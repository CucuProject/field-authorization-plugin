import {
  ApolloServerPlugin,
  BaseContext,
  GraphQLRequestListener,
  GraphQLRequestContextDidResolveOperation,
  GraphQLRequestContextWillSendResponse,
} from '@apollo/server';

import { Algorithm, verify } from 'jsonwebtoken';
import jwksRsa from 'jwks-rsa';
import { lastValueFrom, Observable } from 'rxjs';

/* -------------------------------------------------------------------------
 * 1) Tipi provenienti dal microservizio "grants"
 * ----------------------------------------------------------------------- */
interface FieldPermission {
  fieldPath: string;
  canView: boolean;
}
interface OperationPermission {
  operationName: string;
  canExecute: boolean;
}

/* -------------------------------------------------------------------------
 * 2) Interfaccia “Client-like” (per GrantsClient)
 * ----------------------------------------------------------------------- */
export interface GrantsClientLike {
  send<R = any, D = any>(pattern: any, data: D): Observable<R>;
}

/* -------------------------------------------------------------------------
 * 3) Configurazione Keycloak M2M
 * ----------------------------------------------------------------------- */
export interface M2MVerificationConfig {
  jwksUri      : string;   // es. "http://keycloak:8080/realms/myrealm/protocol/openid-connect/certs"
  issuer       : string;   // es. "http://keycloak:8080/realms/myrealm"
  audience     : string;   // client_id su Keycloak
  allowedAlgos?: string[]; // default: ['RS256']
}

/* -------------------------------------------------------------------------
 * 4) Opzioni del plugin
 * ----------------------------------------------------------------------- */
export interface GrantsAuthPluginOptions {
  grantsClient : GrantsClientLike;
  entityName   : string;
  parseGroupIds?: (raw?: string | null) => string[];
  m2mVerificationConfig?: M2MVerificationConfig;
}

/* -------------------------------------------------------------------------
 * 5) Helpers
 * ----------------------------------------------------------------------- */
function defaultParseGroups(raw?: string | null): string[] {
  return raw
    ? raw.split(',').map(s => s.trim()).filter(Boolean)
    : [];
}

function removeDisallowed(obj: any, allowedFields: Set<string>, path = ''): void {
  if (!obj || typeof obj !== 'object') return;
  if (Array.isArray(obj)) {
    for (const item of obj) removeDisallowed(item, allowedFields, path);
    return;
  }
  for (const k of Object.keys(obj)) {
    const subPath = path ? `${path}.${k}` : k;
    // Manteniamo _id per convenzione
    if (subPath === '_id') continue;

    const val = obj[k];
    if (val && typeof val === 'object') {
      removeDisallowed(val, allowedFields, subPath);
      if (Object.keys(val).length === 0) {
        delete obj[k];
      }
    } else {
      if (!allowedFields.has(subPath)) {
        delete obj[k];
      }
    }
  }
}

async function checkCanExecute(
  client : GrantsClientLike,
  groupId: string,
  opName : string,
): Promise<boolean> {
  return lastValueFrom(
    client.send<OperationPermission[]>('FIND_OP_PERMISSIONS_BY_GROUP', { groupId }),
  )
    .then(list => list.some(p => p.operationName === opName && p.canExecute))
    .catch(() => false);
}

async function fetchViewable(
  client    : GrantsClientLike,
  groupId   : string,
  entityName: string,
): Promise<Set<string>> {
  return lastValueFrom(
    client.send<FieldPermission[]>('FIND_PERMISSIONS_BY_GROUP', { groupId, entityName }),
  )
    .then(list => new Set(list.filter(p => p.canView).map(p => p.fieldPath)))
    .catch(() => new Set<string>());
}

/** Verifica Bearer M2M via jwks-rsa e jsonwebtoken.verify() */
async function verifyM2MToken(token: string, cfg: M2MVerificationConfig): Promise<void> {
  const jwksClient = jwksRsa({
    jwksUri: cfg.jwksUri,
    cache  : true,
    cacheMaxAge: 60_000,
  });
  const getKey = (header: any, callback: (err: any, key?: string) => void) => {
    jwksClient.getSigningKey(header.kid, (err, key) => {
      if (err) return callback(err);
      if (!key) return callback(new Error(`No signing key for kid=${header.kid}`));
      callback(null, key.getPublicKey());
    });
  };
  const chosenAlgos = (cfg.allowedAlgos || ['RS256']) as Algorithm[];

  return new Promise((resolve, reject) => {
    verify(
      token,
      getKey,
      {
        audience: cfg.audience,
        issuer  : cfg.issuer,
        algorithms: chosenAlgos,
      },
      (err) => {
        if (err) return reject(err);
        resolve();
      },
    );
  });
}

/* -------------------------------------------------------------------------
 * 6) Plugin “createGrantsAuthorizationPlugin”
 * ----------------------------------------------------------------------- */
export function createGrantsAuthorizationPlugin(
  opts: GrantsAuthPluginOptions,
): ApolloServerPlugin<BaseContext> {

  const parseGroups = opts.parseGroupIds ?? defaultParseGroups;
  const m2mConfig   = opts.m2mVerificationConfig;

  return {
    async requestDidStart() {

      return <GraphQLRequestListener<BaseContext>> {
        // ----------------------------------------------
        // A) canExecute => didResolveOperation
        // ----------------------------------------------
        async didResolveOperation(rc: GraphQLRequestContextDidResolveOperation<BaseContext>) {
          const headers = rc.request.http?.headers;
          if (!headers) return;

          const opName =
            rc.operationName ?? rc.operation?.name?.value ?? 'UnnamedOperation';

          /** 1) Check se x-internal-federation-call=1 */
          const fedFlag = headers.get('x-internal-federation-call');
          if (fedFlag === '1') {
            // → DEVE essere presente Bearer M2M e valido
            if (!m2mConfig) {
              throw new Error(
                '[GrantsAuthPlugin] x-internal-federation-call=1 ma manca m2mVerificationConfig',
              );
            }
            const authHeader = headers.get('authorization') || '';
            if (!authHeader.toLowerCase().startsWith('bearer ')) {
              throw new Error(
                '[GrantsAuthPlugin] Missing Bearer in x-internal-federation-call => denied',
              );
            }
            // Verifichiamo M2M
            const token = authHeader.split(' ')[1];
            try {
              await verifyM2MToken(token, m2mConfig);
            } catch (err) {
              throw new Error(
                `[GrantsAuthPlugin] Federation Bearer M2M invalid: ${(err as Error).message}`,
              );
            }
            // se ok => skip i controlli su group
            return;
          }

          /** 2) Se non è federation-call, controlliamo Bearer M2M (facoltativo) */
          const authHeader = headers.get('authorization') || '';
          if (authHeader.toLowerCase().startsWith('bearer ')) {
            if (!m2mConfig) {
              throw new Error(
                '[GrantsAuthPlugin] Bearer found, but no m2mVerificationConfig provided.',
              );
            }
            const token = authHeader.split(' ')[1];
            try {
              await verifyM2MToken(token, m2mConfig);
              return; // skip x-user-groups
            } catch (err) {
              throw new Error(
                `[GrantsAuthPlugin] M2M token invalid: ${(err as Error).message}`,
              );
            }
          }

          /** 3) Altrimenti => parse x-user-groups */
          const rawGroups = headers.get('x-user-groups');
          if (!rawGroups) {
            throw new Error(
              `[GrantsAuthPlugin] No Bearer and no x-user-groups => denied. (opName=${opName})`,
            );
          }
          const groups = parseGroups(rawGroups);
          if (!groups.length) {
            throw new Error('[GrantsAuthPlugin] x-user-groups is empty => denied.');
          }

          // check canExecute
          const allowed = await Promise.any(
            groups.map(g => checkCanExecute(opts.grantsClient, g, opName)),
          ).catch(() => false);

          if (!allowed) {
            throw new Error(
              `[GrantsAuthPlugin] Operation "${opName}" not allowed for groups=${groups.join(',')}`,
            );
          }
        },

        // ----------------------------------------------
        // B) field-level filtering => willSendResponse
        // ----------------------------------------------
        async willSendResponse(rc: GraphQLRequestContextWillSendResponse<BaseContext>) {
          if (rc.response.body.kind !== 'single') return;
          const data = rc.response.body.singleResult.data;
          if (!data) return;

          const headers = rc.request.http?.headers;
          if (!headers) return;

          // 1) Federation call? skip
          if (headers.get('x-internal-federation-call') === '1') {
            // (già verificato Bearer M2M sopra)
            return;
          }

          // 2) M2M Bearer? skip
          const authHeader = headers.get('authorization') || '';
          if (authHeader.toLowerCase().startsWith('bearer ')) {
            return;
          }

          // 3) parse groups
          const rawGroups = headers.get('x-user-groups');
          if (!rawGroups) return; // nessun group => potresti forzare data = {}
          const groups = parseGroups(rawGroups);
          if (!groups.length) return;

          // fetch fieldPaths
          const union = new Set<string>();
          for (const g of groups) {
            const viewable = await fetchViewable(opts.grantsClient, g, opts.entityName);
            viewable.forEach(path => union.add(path));
          }

          // rimuovi i campi non inclusi
          removeDisallowed(data, union);
        },
      };
    },
  };
}