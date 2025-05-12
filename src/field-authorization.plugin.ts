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
import { lastValueFrom } from 'rxjs';

/* -------------------------------------------------------------------------
 * 1) Tipi e interfacce di base
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
  send<R = any, D = any>(pattern: any, data: D): import('rxjs').Observable<R>;
}

/** Configurazione per la verifica M2M con Keycloak (o simili) */
export interface M2MVerificationConfig {
  jwksUri: string;
  issuer: string;
  audience: string | string[];
  allowedAlgos?: string[]; // default: ['RS256']
}

/**
 * Mappa: “__typename => nome usato su DB grants”.
 *
 * Esempio tipico:
 * ```ts
 * entityNameMap: {
 *   User: "User",
 *   Group: "Group",
 *   ...
 * }
 * ```
 * Se un child ha `__typename="AuthDataSchema"` e non è in `entityNameMap`, il plugin farà fallback al *typename* del genitore.
 */
export interface MultiEntityGrantsOptions {
  /** Client Proxy per contattare i pattern 'FIND_OP_PERMISSIONS_BY_GROUP', 'FIND_PERMISSIONS_BY_GROUP', ecc. */
  grantsClient: GrantsClientLike;

  /** Mappa i typenames => entityName su DB.  Esempio:  `User => "User"` */
  entityNameMap: Record<string, string>;

  /** Se devi parsare x-user-groups in modo custom */
  parseGroupIds?: (raw?: string | null) => string[];

  /** Se hai Keycloak M2M e vuoi validare i Bearer token “federation”. */
  m2mVerificationConfig?: M2MVerificationConfig;

  /**
   * Se true, abilita i log (livello debug).
   * Default = false
   */
  debug?: boolean;

  /**
   * Mappa opName => rootTypename, per sapere che il risultato di `findAllUsers` è un array di “User”.
   * Ad esempio:
   * ```ts
   * rootTypenameMap: {
   *   findAllUsers: "User",
   *   findOneUser:  "User",
   *   ...
   * }
   * ```
   */
  rootTypenameMap?: Record<string, string>;
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

/** Verifica canExecute su un'operazione */
async function checkCanExecute(
  client: GrantsClientLike,
  groupId: string,
  opName: string,
  logger: Logger,
  debug: boolean,
): Promise<boolean> {
  if (debug) {
    logger.debug(`checkCanExecute => groupId="${groupId}", opName="${opName}"`);
  }
  try {
    const list = await lastValueFrom(
      client.send<OperationPermission[]>('FIND_OP_PERMISSIONS_BY_GROUP', { groupId }),
    );
    const found = list.some(p => p.operationName === opName && p.canExecute);
    if (debug) {
      logger.debug(`... groupId="${groupId}", opName="${opName}" => canExecute=${found}`);
    }
    return found;
  } catch (err) {
    if (debug) {
      logger.debug(`... checkCanExecute => catch => ${err instanceof Error ? err.message : err}`);
    }
    return false;
  }
}

/** Carica i fieldPaths “viewable” da DB grants (groupId, entityName). */
async function fetchViewable(
  client: GrantsClientLike,
  groupId: string,
  entityName: string,
  logger: Logger,
  debug: boolean,
): Promise<Set<string>> {
  if (debug) {
    logger.debug(`fetchViewable => groupId="${groupId}", entityName="${entityName}"`);
  }
  try {
    const list = await lastValueFrom(
      client.send<FieldPermission[]>('FIND_PERMISSIONS_BY_GROUP', { groupId, entityName }),
    );
    const viewable = list.filter(p => p.canView).map(p => p.fieldPath);
    if (debug) {
      logger.debug(`... groupId="${groupId}", entityName="${entityName}" => viewable: [${viewable.join(', ')}]`);
    }
    return new Set(viewable);
  } catch (err) {
    if (debug) {
      logger.debug(`... fetchViewable => catch => ${err instanceof Error ? err.message : err}`);
    }
    return new Set<string>();
  }
}

/**
 * Se la prima parte del path corrisponde a un rootField (es. "findAllUsers"),
 * la rimuove. Esempio: "findAllUsers.authData.email" => "authData.email".
 */
function stripRootSegment(fullPath: string, rootFieldNames: Set<string>): string {
  const parts = fullPath.split('.');
  if (parts.length > 1 && rootFieldNames.has(parts[0])) {
    parts.shift(); // toglie la parte iniziale (es. "findAllUsers")
  }
  return parts.join('.');
}

/**
 * Rimuove i campi non ammessi da `obj`.
 * - fallback: se child ha `__typename` sconosciuto, usiamo `parentTypename`.
 * - stripRootSegment: rimuove la parte "findAllUsers" se presente dal path.
 */
function removeDisallowedMultiEntity(
  obj: any,
  allowedMap: Record<string, Set<string>>,
  defaultAllowed: Set<string>,
  rootFieldNames: Set<string>,
  logger: Logger,
  debug: boolean,
  currentTypename: string | undefined,
  path = '',
) {
  if (!obj || typeof obj !== 'object') return;

  if (Array.isArray(obj)) {
    for (const item of obj) {
      removeDisallowedMultiEntity(
        item,
        allowedMap,
        defaultAllowed,
        rootFieldNames,
        logger,
        debug,
        currentTypename,
        path,
      );
    }
    return;
  }

  // Leggiamo eventuale __typename
  const ownTypename = obj.__typename as string | undefined;

  // Se "ownTypename" non è in mappa => fallback a "currentTypename"
  let finalTypename = ownTypename && allowedMap[ownTypename]
    ? ownTypename
    : currentTypename;

  // Se non c'è, usiamo defaultAllowed
  const isKnownEntity = finalTypename && allowedMap[finalTypename];
  const setToUse = isKnownEntity ? allowedMap[finalTypename!] : defaultAllowed;

  for (const fieldKey of Object.keys(obj)) {
    if (fieldKey === '_id') {
      // tieni _id
      continue;
    }

    const subPath = path ? `${path}.${fieldKey}` : fieldKey;
    const val = obj[fieldKey];

    if (val && typeof val === 'object') {
      removeDisallowedMultiEntity(
        val,
        allowedMap,
        defaultAllowed,
        rootFieldNames,
        logger,
        debug,
        finalTypename, // child eredita il typename dal parent se non ne ha uno suo
        subPath,
      );
      if (Object.keys(val).length === 0) {
        delete obj[fieldKey];
      }
    } else {
      // E' un field "atomico"
      // Rimuovo l'eventuale rootSegment
      const finalPath = stripRootSegment(subPath, rootFieldNames);

      if (!setToUse.has(finalPath)) {
        if (debug) {
          logger.debug(
            `remove => subPath="${subPath}" finalPath="${finalPath}" (typename="${
              finalTypename || 'N/A'
            }" known=${!!isKnownEntity})`,
          );
        }
        delete obj[fieldKey];
      }
    }
  }
}

/**
 * Verifica Bearer M2M (Keycloak) => RS256
 */
async function verifyM2MToken(
  token: string,
  cfg: M2MVerificationConfig,
  logger: Logger,
  debug: boolean,
): Promise<void> {
  if (debug) {
    logger.debug(`verifyM2MToken => issuer="${cfg.issuer}", audience="${cfg.audience}"`);
  }
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
        return callback(new Error(`No signing key for kid=${header.kid}`));
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
          if (debug) {
            logger.debug(`verifyM2MToken => error: ${err.message}`);
          }
          return reject(err);
        }
        if (debug) {
          logger.debug('verifyM2MToken => success');
        }
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
  const logger = new Logger('MultiEntityPlugin');
  const debug = !!opts.debug;
  const parseGroups = opts.parseGroupIds ?? defaultParseGroups;
  const m2mConfig   = opts.m2mVerificationConfig;

  // Federation
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

      // useremo queste var per passare info dal didResolveOperation al willSendResponse
      let rootFieldNames = new Set<string>();
      let rootTypename: string | undefined;

      return <GraphQLRequestListener<BaseContext>>{
        /* ===============================================================
         * A) canExecute => didResolveOperation
         * ============================================================= */
        async didResolveOperation(rc: GraphQLRequestContextDidResolveOperation<BaseContext>) {
          if (debug) logger.debug('didResolveOperation => start');

          const rawOpName = rc.operationName ?? rc.operation?.name?.value ?? 'UnnamedOperation';
          const opName = rawOpName.replace(/__\w+__\d+$/, '');

          if (FEDERATION_OPS.has(rawOpName)) {
            if (debug) logger.debug('federation => bypass canExecute');
            return;
          }

          // rootTypenameMap => se definito, associamo quell'opName a un typename
          if (opts.rootTypenameMap && opts.rootTypenameMap[opName]) {
            rootTypename = opts.rootTypenameMap[opName];
            if (debug) logger.debug(`opName="${opName}" => rootTypename="${rootTypename}"`);
          }

          // estraiamo i rootFieldNames dal selectionSet
          const selectionSet = rc.operation?.selectionSet;
          if (selectionSet && Array.isArray(selectionSet.selections)) {
            const topNames: string[] = [];
            for (const sel of selectionSet.selections) {
              if (sel.kind === 'Field' && sel.name?.value) {
                topNames.push(sel.name.value);
              }
            }
            rootFieldNames = new Set(topNames);
            if (debug && topNames.length) {
              logger.debug(`rootFieldNames=[${topNames.join(', ')}]`);
            }
          }

          const headers = rc.request.http?.headers;
          if (!headers) return;

          const authHeader = headers.get('authorization') || '';
          if (debug) logger.debug(`authHeader="${authHeader}"`);

          // 1) Bearer => M2M?
          if (authHeader.toLowerCase().startsWith('bearer ')) {
            if (!m2mConfig) {
              throw new Error('Bearer M2M token presente, ma manca m2mVerificationConfig');
            }
            const token = authHeader.split(' ')[1];
            await verifyM2MToken(token, m2mConfig, logger, debug);
            if (debug) logger.debug('M2M => skip x-user-groups');
            return;
          }

          // 2) Altrimenti => x-user-groups
          const rawGroups = headers.get('x-user-groups');
          if (!rawGroups) {
            throw new Error(`[GrantsPlugin] No M2M e no x-user-groups => denied (op=${opName})`);
          }
          const groups = parseGroups(rawGroups);
          if (!groups.length) {
            throw new Error(`[GrantsPlugin] x-user-groups vuoto => denied.`);
          }
          if (debug) {
            logger.debug(`groups=[${groups.join(', ')}]`);
          }

          // check canExecute
          let canExe = false;
          try {
            canExe = await Promise.any(
              groups.map(g => checkCanExecute(opts.grantsClient, g, opName, logger, debug)),
            );
          } catch (err) {
            if (debug) {
              logger.debug(`promise.any => catch => ${err instanceof Error ? err.message : err}`);
            }
            canExe = false;
          }
          if (!canExe) {
            if (debug) logger.debug(`op="${opName}" => denied => groups=[${groups.join(',')}]`);
            throw new Error(`[GrantsPlugin] Operazione "${opName}" non consentita per i gruppi [${groups.join(',')}]`);
          }
          if (debug) logger.debug(`op="${opName}" => canExe= true => proceed`);
        },

        /* ===============================================================
         * B) field-level => willSendResponse
         * ============================================================= */
        async willSendResponse(rc: GraphQLRequestContextWillSendResponse<BaseContext>) {
          if (debug) logger.debug('willSendResponse => start');

          if (rc.response.body.kind !== 'single') return;
          const data = rc.response.body.singleResult.data;
          if (!data) return;

          const rawOpName = rc.operationName ?? rc.operation?.name?.value ?? 'UnnamedOperation';
          if (FEDERATION_OPS.has(rawOpName)) {
            if (debug) logger.debug('federation => skip field filtering');
            return;
          }

          // Bearer M2M => skip
          const headers = rc.request.http?.headers;
          if (!headers) return;
          const authHeader = headers.get('authorization') || '';
          if (authHeader.toLowerCase().startsWith('bearer ')) {
            if (debug) logger.debug('M2M => skip field filtering');
            return;
          }

          // parse x-user-groups
          const rawGroups = headers.get('x-user-groups');
          if (!rawGroups) return;
          const groups = parseGroups(rawGroups);
          if (!groups.length) return;

          // Creiamo la mappa “typename => setOf(fieldPaths)”
          const allowedMap: Record<string, Set<string>> = {};
          const defaultAllowed = new Set<string>();

          // Popoliamo i fieldPaths uniti
          for (const typename of Object.keys(opts.entityNameMap)) {
            const entityName = opts.entityNameMap[typename];
            const union = new Set<string>();
            for (const gId of groups) {
              const partial = await fetchViewable(opts.grantsClient, gId, entityName, logger, debug);
              partial.forEach(f => union.add(f));
            }
            allowedMap[typename] = union;
            if (debug) {
              logger.debug(`typename="${typename}" => unionFields=[${[...union].join(', ')}]`);
            }
          }

          if (debug) {
            logger.debug(`Data BEFORE filtering:\n${JSON.stringify(data, null, 2)}`);
          }

          // Se in didResolveOperation abbiamo impostato rootTypename
          // (es. "User" per findAllUsers), lo passiamo
          removeDisallowedMultiEntity(
            data,
            allowedMap,
            defaultAllowed,
            /* rootFieldNames= */ rootFieldNames,
            logger,
            debug,
            /* currentTypename= */ rootTypename,
          );

          if (debug) {
            logger.debug(`Data AFTER filtering:\n${JSON.stringify(data, null, 2)}`);
          }
        },
      };
    },
  };
}