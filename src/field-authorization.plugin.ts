import {
  ApolloServerPlugin,
  BaseContext,
  GraphQLRequestListener,
  GraphQLRequestContextDidResolveOperation,
  GraphQLRequestContextWillSendResponse,
} from '@apollo/server';

import { Algorithm, verify } from 'jsonwebtoken';
import jwksRsa from 'jwks-rsa';
import { Observable, lastValueFrom } from 'rxjs';

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
 *    Qui basta un metodo .send()
 * ----------------------------------------------------------------------- */
export interface GrantsClientLike {
  send<R = any, D = any>(pattern: any, data: D): Observable<R>;
}

/* -------------------------------------------------------------------------
 * 3) Configurazione Keycloak M2M
 * ----------------------------------------------------------------------- */
export interface M2MVerificationConfig {
  jwksUri: string;          // "http://keycloak:8080/realms/myrealm/protocol/openid-connect/certs"
  issuer: string;           // "http://keycloak:8080/realms/myrealm"
  audience: string;         // il client_id registrato su Keycloak
  allowedAlgos?: string[];  // default: ['RS256']
}

/* -------------------------------------------------------------------------
 * 4) Opzioni del plugin
 * ----------------------------------------------------------------------- */
export interface GrantsAuthPluginOptions {
  grantsClient: GrantsClientLike;         // Necessario per send(...) a GRANTS
  entityName  : string;                   // "User", "Project", "Auth", etc.
  parseGroupIds?: (raw?: string | null) => string[];
  m2mVerificationConfig?: M2MVerificationConfig;
}

/* -------------------------------------------------------------------------
 * 5) Helpers
 * ----------------------------------------------------------------------- */

/** Parser di default per x-user-groups */
function defaultParseGroups(raw?: string|null): string[] {
  return raw
    ? raw.split(',').map(s => s.trim()).filter(Boolean)
    : [];
}

/** Rimuove da "obj" i campi non inclusi in “allowedFields” (ricorsivo) */
function removeDisallowed(obj: any, allowedFields: Set<string>, path = ''): void {
  if (!obj || typeof obj !== 'object') return;

  if (Array.isArray(obj)) {
    for (const item of obj) {
      removeDisallowed(item, allowedFields, path);
    }
    return;
  }

  for (const k of Object.keys(obj)) {
    const subPath = path ? `${path}.${k}` : k;

    // Non filtriamo "_id"
    if (subPath === '_id') {
      continue;
    }

    const value = obj[k];
    if (value && typeof value === 'object') {
      removeDisallowed(value, allowedFields, subPath);
      if (Object.keys(value).length === 0) {
        delete obj[k];
      }
    } else {
      if (!allowedFields.has(subPath)) {
        delete obj[k];
      }
    }
  }
}

/** Richiama Grants per check canExecute */
async function checkCanExecute(
  client: GrantsClientLike,
  groupId: string,
  opName: string,
): Promise<boolean> {
  return lastValueFrom(
    client.send<OperationPermission[]>('FIND_OP_PERMISSIONS_BY_GROUP', { groupId }),
  )
    .then(list => list.some(p => p.operationName === opName && p.canExecute))
    .catch(() => false);
}

/** Richiama Grants per ottenere i fieldPaths “viewable” da un gruppo su una certa entity */
async function fetchViewable(
  client: GrantsClientLike,
  groupId: string,
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
  // Crea un client JWKS con caching
  const jwksClient = jwksRsa({
    jwksUri: cfg.jwksUri,
    cache: true,
    cacheMaxAge: 60_000,
  });

  // Sostituisce la chiave “on the fly”
  const getKey = (header: any, callback: (err: any, key?: string) => void) => {
    jwksClient.getSigningKey(header.kid, (err, key) => {
      if (err) return callback(err);
      if (!key) {
        return callback(new Error(`No signing key found for kid=${header.kid}`));
      }
      const signingKey = key.getPublicKey();
      callback(null, signingKey);
    });
  };

  const chosenAlgos = (cfg.allowedAlgos || ['RS256']) as Algorithm[];

  return new Promise((resolve, reject) => {
    verify(
      token,
      getKey,
      {
        audience: cfg.audience,
        issuer: cfg.issuer,
        algorithms: chosenAlgos,
      },
      (err) => {
        if (err) {
          return reject(err);
        }
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
        // ----------------------------------------
        // A) “canExecute” => didResolveOperation
        // ----------------------------------------
        async didResolveOperation(rc: GraphQLRequestContextDidResolveOperation<BaseContext>) {

          const headers = rc.request.http?.headers;
          if (!headers) return;

          const opName =
            rc.operationName ?? rc.operation?.name?.value ?? 'UnnamedOperation';

          /* --- 1) Se abbiamo Bearer => check M2M --- */
          const authHeader = headers.get('authorization') || '';
          if (authHeader.toLowerCase().startsWith('bearer ')) {
            if (!m2mConfig) {
              throw new Error(
                '[GrantsAuthPlugin] Bearer present, but no m2mVerificationConfig provided.',
              );
            }
            const token = authHeader.split(' ')[1];
            try {
              await verifyM2MToken(token, m2mConfig);
              // Se M2M è valido => skip x-user-groups => “canExecute” con token M2M
              return;
            } catch (err) {
              throw new Error(
                `[GrantsAuthPlugin] M2M token invalid: ${(err as Error).message}`,
              );
            }
          }

          /* --- 2) Altrimenti, parse “x-user-groups” --- */
          const rawGroups = headers.get('x-user-groups');
          if (!rawGroups) {
            // Qui blocchiamo se manca Bearer e manca x-user-groups
            // Se desideri bypassare introspezione, potresti fare un check su
            // if (['_service', '_entities'].includes(opName)) { return; }
            // Altrimenti errore
            throw new Error(
              `[GrantsAuthPlugin] No Bearer token and no x-user-groups => Denied (op=${opName}).`,
            );
          }

          // parse groupIds
          const groups = parseGroups(rawGroups);
          if (!groups.length) {
            throw new Error(
              '[GrantsAuthPlugin] “x-user-groups” is empty => denied.',
            );
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

        // ----------------------------------------
        // B) field-level filtering => willSendResponse
        // ----------------------------------------
        async willSendResponse(rc: GraphQLRequestContextWillSendResponse<BaseContext>) {
          // Se la risposta non è “single” => skip
          if (rc.response.body.kind !== 'single') return;
          const data = rc.response.body.singleResult.data;
          if (!data) return; // no data => skip

          const headers = rc.request.http?.headers;
          if (!headers) return;

          // Se c’è Bearer => skip field filtering
          const authHeader = headers.get('authorization') || '';
          if (authHeader.toLowerCase().startsWith('bearer ')) {
            return;
          }

          // Altrimenti => x-user-groups
          const groups = parseGroups(headers.get('x-user-groups'));
          if (!groups.length) {
            // se non c’è => potresti bloccare o azzerare data
            return;
          }

          // fetch “viewable” fieldPaths
          const union = new Set<string>();
          for (const g of groups) {
            const viewable = await fetchViewable(opts.grantsClient, g, opts.entityName);
            viewable.forEach(path => union.add(path));
          }

          // Rimuovi i campi non inclusi in union
          removeDisallowed(data, union);
        },
      };
    },
  };
}