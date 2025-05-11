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

/** parse x-user-groups di default */
function defaultParseGroups(raw?: string | null): string[] {
  return raw
    ? raw.split(',').map(s => s.trim()).filter(Boolean)
    : [];
}

/** Verifica se un gruppo ha canExecute su opName */
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
    if (err instanceof Error) {
      if (debug) logger.debug(`... checkCanExecute => catch error: ${err.message}`);
    } else {
      if (debug) logger.debug(`... checkCanExecute => catch => ${JSON.stringify(err)}`);
    }
    return false;
  }
}

/** Carica i fieldPaths “viewable” (canView) per una data entityName + groupId */
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
    if (err instanceof Error) {
      if (debug) logger.debug(`... fetchViewable => catch error: ${err.message}`);
    } else {
      if (debug) logger.debug(`... fetchViewable => catch => ${JSON.stringify(err)}`);
    }
    return new Set<string>();
  }
}

/**
 * Rimuove i campi non consentiti in un oggetto con possibili __typename multipli.
 * Se l'oggetto figlio **non** ha `__typename`, eredita la `currentTypename` dal genitore.
 */
function removeDisallowedMultiEntity(
  obj: any,
  allowedMap: Record<string, Set<string>>,
  defaultAllowed: Set<string>,
  logger: Logger,
  debug: boolean,
  currentTypename: string | undefined, // <-- se manca, si usa defaultAllowed
  path = ''
) {
  if (!obj || typeof obj !== 'object') return;

  if (Array.isArray(obj)) {
    for (const item of obj) {
      removeDisallowedMultiEntity(item, allowedMap, defaultAllowed, logger, debug, currentTypename, path);
    }
    return;
  }

  // Se l'oggetto ha un __typename, usalo. Altrimenti eredita currentTypename
  const typename = (obj.__typename as string) || currentTypename;
  const isKnownEntity = typename && allowedMap[typename];

  // Scegliamo il set di fieldPaths
  const setToUse = isKnownEntity
    ? allowedMap[typename!]
    : defaultAllowed;

  for (const k of Object.keys(obj)) {
    // Conserviamo _id se vuoi
    if (k === '_id') continue;

    const subPath = path ? `${path}.${k}` : k;
    const val = obj[k];

    if (val && typeof val === 'object') {
      // Ricorsione. Passiamo la stessa `typename` (o none) in caso di sub-objects
      removeDisallowedMultiEntity(val, allowedMap, defaultAllowed, logger, debug, typename, subPath);
      if (Object.keys(val).length === 0) {
        delete obj[k];
      }
    } else {
      // Se subPath NON è presente => cancella
      if (!setToUse.has(subPath)) {
        if (debug) {
          logger.debug(
            `remove => "${subPath}" (typename="${typename}" known=${!!isKnownEntity})`
          );
        }
        delete obj[k];
      }
    }
  }
}

/** Verifica token Bearer M2M */
async function verifyM2MToken(token: string, cfg: M2MVerificationConfig, logger: Logger, debug: boolean): Promise<void> {
  if (debug) logger.debug(`verifyM2MToken => issuer="${cfg.issuer}", audience="${cfg.audience}"`);
  const jwksClient = jwksRsa({
    jwksUri: cfg.jwksUri,
    cache: true,
    cacheMaxAge: 60_000,
  });

  const getKey = (header: any, callback: (err: any, key?: string) => void) => {
    jwksClient.getSigningKey(header.kid, (err, key) => {
      if (err) {
        return callback(err);
      }
      if (!key) {
        return callback(new Error(`No signing key found for kid=${header.kid}`));
      }
      callback(null, key.getPublicKey());
    });
  };

  const algos = (cfg.allowedAlgos || ['RS256']) as Algorithm[];

  return new Promise((resolve, reject) => {
    verify(
      token,
      getKey,
      {
        audience: cfg.audience,
        issuer:   cfg.issuer,
        algorithms: algos,
      },
      (err) => {
        if (err) {
          if (debug) logger.debug(`verifyM2MToken => error: ${err?.message || err}`);
          return reject(err);
        }
        if (debug) logger.debug('verifyM2MToken => success');
        resolve();
      },
    );
  });
}

/* -------------------------------------------------------------------------
 * 3) Plugin “createMultiEntityGrantsPlugin”
 * ----------------------------------------------------------------------- */
export function createMultiEntityGrantsPlugin(
  opts: MultiEntityGrantsOptions,
): ApolloServerPlugin<BaseContext> {
  const logger = new Logger('MultiEntityPlugin');  // puoi cambiare la "context label"
  const debug = !!opts.debug;                      // se non definito => false
  const parseGroups = opts.parseGroupIds ?? defaultParseGroups;
  const m2mConfig   = opts.m2mVerificationConfig;

  // Operazioni "federation"
  const FEDERATION_OPS = new Set([
    '_service',
    '__ApolloGetServiceDefinition__',
    '_entities',
  ]);

  if (debug) {
    logger.log('createMultiEntityGrantsPlugin => init');
    logger.debug(`entityNameMap => ${JSON.stringify(opts.entityNameMap, null, 2)}`);
  }

  return {
    async requestDidStart() {
      if (debug) logger.debug('requestDidStart');
      return <GraphQLRequestListener<BaseContext>>{
        /* ------------------------------------------------------
         * 1) Controllo canExecute => didResolveOperation
         * ------------------------------------------------------*/
        async didResolveOperation(rc: GraphQLRequestContextDidResolveOperation<BaseContext>) {
          if (debug) logger.debug('didResolveOperation => start');

          const headers = rc.request.http?.headers;
          if (!headers) {
            if (debug) logger.debug('didResolveOperation => no headers => skip');
            return;
          }

          // Nome operazione base
          const rawOpName = rc.operationName ?? rc.operation?.name?.value ?? 'UnnamedOperation';
          const opName = rawOpName.replace(/__\w+__\d+$/, '');
          if (debug) logger.debug(`rawOpName="${rawOpName}" => opName="${opName}"`);

          if (FEDERATION_OPS.has(rawOpName)) {
            if (debug) logger.debug('didResolveOperation => federation => bypass');
            return;
          }

          // Legge Authorization
          const authHeader = headers.get('authorization') || '';
          if (debug) logger.debug(`authHeader="${authHeader}"`);

          if (authHeader.toLowerCase().startsWith('bearer ')) {
            // M2M
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
          } catch (err: unknown) {
            if (err instanceof Error) {
              if (debug) logger.debug(`promise.any => catch => ${err.message}`);
            } else {
              if (debug) logger.debug(`promise.any => catch => ${JSON.stringify(err)}`);
            }
            canExe = false;
          }
          if (!canExe) {
            if (debug) logger.debug(`op="${opName}" => denied => groups=${groups.join(',')}`);
            throw new Error(`[GrantsPlugin] Operazione "${opName}" non consentita per i gruppi [${groups.join(',')}]`);
          }
          if (debug) logger.debug(`op="${opName}" => canExe = true => proceed`);
        },

        /* ------------------------------------------------------
         * 2) Field-level => willSendResponse
         * ------------------------------------------------------*/
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
          const defaultAllowed = new Set<string>(); // se non troviamo un typename nella mappa

          for (const typename of Object.keys(opts.entityNameMap)) {
            const entityName = opts.entityNameMap[typename];
            // union per i vari groupIds
            const unionFields = new Set<string>();
            for (const gId of groups) {
              const partial = await fetchViewable(opts.grantsClient, gId, entityName, logger, debug);
              partial.forEach(f => unionFields.add(f));
            }
            allowedMap[typename] = unionFields;
            if (debug) logger.debug(`typename="${typename}" => unionFields= [${[...unionFields].join(', ')}]`);
          }

          // 2) rimuoviamo i campi
          if (debug) {
            logger.debug(`Data BEFORE filtering:\n${JSON.stringify(data, null, 2)}`);
          }

          /**
           * Qui possiamo decidere se passare `undefined` come `currentTypename`,
           * oppure, se volessimo interpretare la root come “User” (ad es. in un findAllUsers),
           * potremmo farlo. Ma in genere si parte con `undefined` e poi i sub-entities
           * di root senza __typename useranno `defaultAllowed`.
           */
          removeDisallowedMultiEntity(
            data,
            allowedMap,
            defaultAllowed,
            logger,
            debug,
            /* currentTypename = */ undefined,
          );

          if (debug) {
            logger.debug(`Data AFTER filtering:\n${JSON.stringify(data, null, 2)}`);
          }
        },
      };
    },
  };
}