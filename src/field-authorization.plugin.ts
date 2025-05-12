import {
  ApolloServerPlugin,
  BaseContext,
  GraphQLRequestListener,
  GraphQLRequestContextDidResolveOperation,
  GraphQLRequestContextWillSendResponse,
} from '@apollo/server';
import { Logger } from '@nestjs/common';
import { verify, Algorithm } from 'jsonwebtoken';
import jwksRsa from 'jwks-rsa';
import { Observable, lastValueFrom } from 'rxjs';

/* -------------------------------------------------------------------------
 * 1) Interfacce e tipi
 * ----------------------------------------------------------------------- */
interface FieldPermission {
  fieldPath: string;
  canView: boolean;
}

interface OperationPermission {
  operationName: string;
  canExecute: boolean;
}

export interface GrantsClientLike {
  send<R = any, D = any>(pattern: any, data: D): Observable<R>;
}

export interface M2MVerificationConfig {
  jwksUri: string;
  issuer: string;
  audience: string | string[];
  allowedAlgos?: string[];  // default: ['RS256']
}

/**
 * Mappa per la field-level security:
 *   __typename => nomeEntityUsatoSuDB
 *
 * Esempio:
 *   entityNameMap: {
 *     User: "User",
 *     Group: "Group",
 *     Permission: "Permission",
 *   }
 */
export interface MultiEntityGrantsOptions {
  grantsClient: GrantsClientLike;

  entityNameMap: Record<string, string>;

  parseGroupIds?: (raw?: string | null) => string[];
  m2mVerificationConfig?: M2MVerificationConfig;

  /**
   * Se true, abilita i log (livello debug).
   * Default = false
   */
  debug?: boolean;
}

/* -------------------------------------------------------------------------
 * 2) Helpers
 * ----------------------------------------------------------------------- */
function defaultParseGroups(raw?: string | null): string[] {
  return raw
    ? raw.split(',').map(s => s.trim()).filter(Boolean)
    : [];
}

async function checkCanExecute(
  client: GrantsClientLike,
  groupId: string,
  opName: string,
  logger: Logger,
  debug: boolean,
): Promise<boolean> {
  if (debug) logger.debug(`checkCanExecute => groupId="${groupId}", opName="${opName}"`);
  try {
    const list = await lastValueFrom(
      client.send<OperationPermission[]>('FIND_OP_PERMISSIONS_BY_GROUP', { groupId }),
    );
    const found = list.some(p => p.operationName === opName && p.canExecute);
    if (debug) logger.debug(`... groupId="${groupId}", opName="${opName}" => canExecute=${found}`);
    return found;
  } catch (err: unknown) {
    if (debug) logger.debug(`... checkCanExecute => catch => ${(err as Error).message || err}`);
    return false;
  }
}

async function fetchViewable(
  client: GrantsClientLike,
  groupId: string,
  entityName: string,
  logger: Logger,
  debug: boolean,
): Promise<Set<string>> {
  if (debug) logger.debug(`fetchViewable => groupId="${groupId}", entityName="${entityName}"`);
  try {
    const list = await lastValueFrom(
      client.send<FieldPermission[]>('FIND_PERMISSIONS_BY_GROUP', { groupId, entityName }),
    );
    const viewable = list.filter(p => p.canView).map(p => p.fieldPath);
    if (debug) logger.debug(`... groupId="${groupId}", entityName="${entityName}" => viewable: [${viewable.join(', ')}]`);
    return new Set(viewable);
  } catch (err: unknown) {
    if (debug) logger.debug(`... fetchViewable => catch => ${(err as Error).message || err}`);
    return new Set<string>();
  }
}

/**
 * Rimuove il “segmento root” se corrisponde a un rootFieldName.
 * Esempio: se subPath = "findAllUsers.authData.name" e `rootFieldNames` contiene "findAllUsers",
 *          restituisce "authData.name".
 */
function stripRootSegment(subPath: string, rootFieldNames: Set<string>): string {
  const parts = subPath.split('.');
  if (parts.length > 1 && rootFieldNames.has(parts[0])) {
    parts.shift(); // rimuove es. "findAllUsers"
  }
  return parts.join('.');
}

/**
 * Rimuove i campi non consentiti, con supporto a fallback di typename e strip del root field.
 */
function removeDisallowedMultiEntity(
  obj: any,
  allowedMap: Record<string, Set<string>>,
  defaultAllowed: Set<string>,
  rootFieldNames: Set<string>,   // e.g. { 'findAllUsers' }
  logger: Logger,
  debug: boolean,
  currentTypename: string | undefined,
  path = '',
) {
  if (!obj || typeof obj !== 'object') return;
  if (Array.isArray(obj)) {
    for (const item of obj) {
      removeDisallowedMultiEntity(item, allowedMap, defaultAllowed, rootFieldNames, logger, debug, currentTypename, path);
    }
    return;
  }

  // se c'è un __typename non mappato => fallback
  let typename: string | undefined = (obj.__typename as string) || currentTypename;
  if (obj.__typename && !(obj.__typename in allowedMap)) {
    // fallback
    typename = currentTypename;
    if (debug && obj.__typename !== currentTypename) {
      logger.debug(`Typename "${obj.__typename}" non è in entityNameMap => fallback a parent="${currentTypename}"`);
    }
  }

  const isKnownEntity = typename && allowedMap[typename];
  const setToUse = isKnownEntity ? allowedMap[typename!] : defaultAllowed;

  for (const k of Object.keys(obj)) {
    if (k === '_id') continue;

    // Costruiamo subPath
    const subPathBase = path ? `${path}.${k}` : k;
    // Rimuoviamo eventuale “root field”
    const finalPath = stripRootSegment(subPathBase, rootFieldNames);

    const val = obj[k];
    if (val && typeof val === 'object') {
      // ricorsione
      removeDisallowedMultiEntity(val, allowedMap, defaultAllowed, rootFieldNames, logger, debug, typename, subPathBase);
      if (Object.keys(val).length === 0) {
        delete obj[k];
      }
    } else {
      if (!setToUse.has(finalPath)) {
        if (debug) {
          logger.debug(`remove => subPath="${subPathBase}" finalPath="${finalPath}" (typename="${typename}" known=${!!isKnownEntity})`);
        }
        delete obj[k];
      }
    }
  }
}

async function verifyM2MToken(token: string, cfg: M2MVerificationConfig, logger: Logger, debug: boolean): Promise<void> {
  if (debug) logger.debug(`verifyM2MToken => issuer="${cfg.issuer}", audience="${cfg.audience}"`);
  const jwksClient = jwksRsa({ jwksUri: cfg.jwksUri, cache: true, cacheMaxAge: 60_000 });

  const getKey = (header: any, callback: (err: any, key?: string) => void) => {
    jwksClient.getSigningKey(header.kid, (err, key) => {
      if (err || !key) return callback(err || new Error(`No key for kid=${header.kid}`));
      callback(null, key.getPublicKey());
    });
  };
  const algos = (cfg.allowedAlgos || ['RS256']) as Algorithm[];

  return new Promise((resolve, reject) => {
    verify(token, getKey, { audience: cfg.audience, issuer: cfg.issuer, algorithms: algos }, (err) => {
      if (err) {
        if (debug) logger.debug(`verifyM2MToken => error: ${err.message}`);
        return reject(err);
      }
      if (debug) logger.debug('verifyM2MToken => success');
      resolve();
    });
  });
}

/* -------------------------------------------------------------------------
 * 3) Plugin “createMultiEntityGrantsPlugin”
 * ----------------------------------------------------------------------- */
export function createMultiEntityGrantsPlugin(opts: MultiEntityGrantsOptions): ApolloServerPlugin<BaseContext> {
  const logger = new Logger('MultiEntityPlugin');
  const debug = !!opts.debug;
  const parseGroups = opts.parseGroupIds ?? defaultParseGroups;
  const m2mConfig = opts.m2mVerificationConfig;

  // Operazioni di Federation
  const FEDERATION_OPS = new Set([ '_service', '__ApolloGetServiceDefinition__', '_entities' ]);

  if (debug) {
    logger.log('createMultiEntityGrantsPlugin => init');
    logger.debug(`entityNameMap => ${JSON.stringify(opts.entityNameMap, null, 2)}`);
  }

  return {
    async requestDidStart() {
      if (debug) logger.debug('requestDidStart');
      // Prepara un set dove salvare i rootFieldNames dell’operazione
      let rootFieldNames = new Set<string>();

      return <GraphQLRequestListener<BaseContext>>{
        async didResolveOperation(rc: GraphQLRequestContextDidResolveOperation<BaseContext>) {
          if (debug) logger.debug('didResolveOperation => start');

          const headers = rc.request.http?.headers;
          if (!headers) return;

          const rawOpName = rc.operationName ?? rc.operation?.name?.value ?? 'UnnamedOperation';
          const opName = rawOpName.replace(/__\w+__\d+$/, '');
          if (debug) logger.debug(`rawOpName="${rawOpName}" => opName="${opName}"`);

          // Raccogli i root fieldName della query
          if (rc.operation?.selectionSet?.selections) {
            const selections = rc.operation.selectionSet.selections;
            // Esempio: se la query è `query { findAllUsers { ... } }` => rootFieldName = "findAllUsers"
            const fieldNames = selections
              .map((s: any) => s.name?.value)
              .filter((n: string) => !!n);
            rootFieldNames = new Set(fieldNames);
            if (debug) logger.debug(`rootFieldNames => [${[...rootFieldNames].join(', ')}]`);
          }

          // Federation?
          if (FEDERATION_OPS.has(rawOpName)) {
            if (debug) logger.debug('didResolveOperation => federation => bypass');
            return;
          }

          // Legge Authorization
          const authHeader = headers.get('authorization') || '';
          if (debug) logger.debug(`authHeader="${authHeader}"`);

          // M2M?
          if (authHeader.toLowerCase().startsWith('bearer ')) {
            if (!m2mConfig) {
              throw new Error('Bearer M2M token presente, ma manca m2mVerificationConfig');
            }
            const token = authHeader.split(' ')[1];
            await verifyM2MToken(token, m2mConfig, logger, debug);
            if (debug) logger.debug('M2M => skip x-user-groups');
            return;
          }

          // Altrimenti => x-user-groups
          const rawGroups = headers.get('x-user-groups');
          if (!rawGroups) {
            throw new Error(`[GrantsPlugin] Nessun M2M e nessun x-user-groups => denied (op=${opName})`);
          }
          const groups = parseGroups(rawGroups);
          if (debug) logger.debug(`groups = [${groups.join(', ')}]`);

          if (!groups.length) {
            throw new Error(`[GrantsPlugin] x-user-groups vuoto => denied`);
          }

          // check canExecute
          let canExe = false;
          try {
            canExe = await Promise.any(
              groups.map(g => checkCanExecute(opts.grantsClient, g, opName, logger, debug)),
            );
          } catch (err) {
            if (debug) logger.debug(`promise.any => catch => ${(err as Error).message || err}`);
            canExe = false;
          }
          if (!canExe) {
            if (debug) logger.debug(`op="${opName}" => denied => groups=${groups.join(',')}`);
            throw new Error(`[GrantsPlugin] Operazione "${opName}" non consentita per i gruppi [${groups.join(',')}]`);
          }
          if (debug) logger.debug(`op="${opName}" => canExe = true => proceed`);
        },

        async willSendResponse(rc: GraphQLRequestContextWillSendResponse<BaseContext>) {
          if (debug) logger.debug('willSendResponse => start');

          if (rc.response.body.kind !== 'single') {
            if (debug) logger.debug('... not single => skip');
            return;
          }
          const data = rc.response.body.singleResult.data;
          if (!data) {
            if (debug) logger.debug('... no data => skip');
            return;
          }

          const headers = rc.request.http?.headers;
          if (!headers) {
            if (debug) logger.debug('... no headers => skip');
            return;
          }

          const rawOpName = rc.operationName ?? rc.operation?.name?.value ?? 'UnnamedOperation';
          if (FEDERATION_OPS.has(rawOpName)) {
            if (debug) logger.debug('... federation => skip field filtering');
            return;
          }

          // Se Bearer M2M => skip
          const authHeader = headers.get('authorization') || '';
          if (authHeader.toLowerCase().startsWith('bearer ')) {
            if (debug) logger.debug('... bearer M2M => skip field filtering');
            return;
          }

          // Altrimenti => x-user-groups
          const rawGroups = headers.get('x-user-groups');
          if (!rawGroups) {
            if (debug) logger.debug('... no x-user-groups => skip');
            return;
          }
          const groups = parseGroups(rawGroups);
          if (!groups.length) {
            if (debug) logger.debug('... groups[] empty => skip');
            return;
          }

          // 1) costruiamo "allowedMap" (typename => fieldPaths unione di tutti i groupIds)
          const allowedMap: Record<string, Set<string>> = {};
          const defaultAllowed = new Set<string>();

          for (const typename of Object.keys(opts.entityNameMap)) {
            const entityName = opts.entityNameMap[typename];
            const unionFields = new Set<string>();
            for (const gId of groups) {
              const partial = await fetchViewable(opts.grantsClient, gId, entityName, logger, debug);
              partial.forEach(f => unionFields.add(f));
            }
            allowedMap[typename] = unionFields;
            if (debug) {
              logger.debug(
                `typename="${typename}" => unionFields= [${[...unionFields].join(', ')}]`
              );
            }
          }

          if (debug) {
            logger.debug(`Data BEFORE filtering:\n${JSON.stringify(data, null, 2)}`);
          }

          // 2) rimuoviamo i campi
          // Creiamo un "rootTypename"? Se la tua root è l’elenco di User, puoi passare "User"
          removeDisallowedMultiEntity(
            data,
            allowedMap,
            defaultAllowed,
            rc.operation?.selectionSet
              ? new Set( /* rootFieldNames che abbiamo memorizzato nel didResolveOperation */ )
              : new Set(),   // se non definito
            logger,
            debug,
            /*currentTypename=*/ 'User',
          );

          if (debug) {
            logger.debug(`Data AFTER filtering:\n${JSON.stringify(data, null, 2)}`);
          }
        },
      };
    },
  };
}