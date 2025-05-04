import {
  ApolloServerPlugin,
  BaseContext,
  GraphQLRequestListener,
  GraphQLRequestContextDidResolveOperation,
  GraphQLRequestContextWillSendResponse,
} from '@apollo/server';

import { Algorithm, JwtPayload, verify } from 'jsonwebtoken';
import jwksRsa, { JwksClient } from 'jwks-rsa';
import { lastValueFrom, Observable } from 'rxjs';

/* -------------------------------------------------------------------------
 * 1) Tipi provenienti dal microservizio "grants" (semplificati)
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
 *    Se vuoi validare la firma RS256 del token M2M
 * ----------------------------------------------------------------------- */
export interface M2MVerificationConfig {
  jwksUri: string;             // es: "http://keycloak:8080/realms/myrealm/protocol/openid-connect/certs"
  issuer: string;              // es: "http://keycloak:8080/realms/myrealm"
  audience: string;            // il client_id registrato su Keycloak
  allowedAlgos?: string[];     // default: ['RS256']
}

/* -------------------------------------------------------------------------
 * 4) Opzioni del plugin
 * ----------------------------------------------------------------------- */
export interface GrantsAuthPluginOptions {
  grantsClient: GrantsClientLike;
  entityName  : string;
  /**
   * Funzione per parsare l’header “x-user-groups” (di default, split su virgola).
   */
  parseGroupIds?: (raw?: string | null) => string[];

  /**
   * Se definito, useremo questi parametri per validare via JWT RS256
   * le richieste con “Authorization: Bearer <token>”.
   */
  m2mVerificationConfig?: M2MVerificationConfig;
}

/* -------------------------------------------------------------------------
 * 5) Utilities
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

/* -------------------------------------------------------------------------
 * 6) Verifica M2M: uso di jwks-rsa e verify() di jsonwebtoken
 * ----------------------------------------------------------------------- */
async function verifyM2MToken(token: string, cfg: M2MVerificationConfig): Promise<void> {
  // Crea client JWKS, con caching
  const jwksClient = jwksRsa({
    jwksUri: cfg.jwksUri,
    cache: true,
    cacheMaxAge: 60000,
  });

  const getKey = (header: any, callback: (err: any, key?: string) => void) => {
    jwksClient.getSigningKey(header.kid, (err, key) => {
      if (err) {
        return callback(err);
      }
      if (!key) {
        return callback(new Error('No signing key found for kid=' + header.kid));
      }
      const signingKey = key.getPublicKey();
      callback(null, signingKey);
    });
  };

  // Prepara la lista di algos
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
      (err, decoded) => {
        if (err) {
          return reject(err);
        }
        // se vuoi controllare che “decoded.client_id” esista
        // (NB: Keycloak a volte mette client_id in "azp" o "clientId", dipende dalla config)
        // a tua scelta:
        resolve();
      },
    );
  });
}

/* -------------------------------------------------------------------------
 * 7) Plugin “createGrantsAuthorizationPlugin”
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
        // A) canExecute => didResolveOperation
        // ----------------------------------------
        async didResolveOperation(rc: GraphQLRequestContextDidResolveOperation<BaseContext>) {
          const headers = rc.request.http?.headers;
          if (!headers) return;

          // Controlla se c’è un token Bearer
          const authHeader = headers.get('authorization') || '';
          if (authHeader.toLowerCase().startsWith('bearer ')) {
            const token = authHeader.split(' ')[1];

            // Se abbiamo config M2M => verifichiamo la firma
            if (m2mConfig) {
              try {
                await verifyM2MToken(token, m2mConfig);
                // => se ok => skip i controlli Grants (return)
                return;
              } catch (err) {
                // se token M2M invalido => blocchiamo
                throw new Error(
                  `[GrantsAuthPlugin] M2M token invalid: ${(err as Error).message}`,
                );
              }
            } else {
              // se non c’è config => skip (fiducia)
              return;
            }
          }

          // Altrimenti, se non Bearer => assumiamo FE => ci servono x-user-groups
          const groups = parseGroups(headers.get('x-user-groups'));
          if (!groups.length) {
            throw new Error('[GrantsAuthPlugin] x-user-groups mancante');
          }

          // Ora, check canExecute
          const opName = rc.operationName ?? rc.operation?.name?.value ?? 'UnnamedOperation';
          const allowed = await Promise.any(
            groups.map(g => checkCanExecute(opts.grantsClient, g, opName)),
          ).catch(() => false);

          if (!allowed) {
            throw new Error(
              `[GrantsAuthPlugin] Operazione "${opName}" negata per gruppi ${groups.join(',')}`,
            );
          }
        },

        // ----------------------------------------
        // B) field-level filtering => willSendResponse
        // ----------------------------------------
        async willSendResponse(rc: GraphQLRequestContextWillSendResponse<BaseContext>) {
          if (rc.response.body.kind !== 'single') return;
          const data = rc.response.body.singleResult.data;
          if (!data) return;

          const headers = rc.request.http?.headers;
          if (!headers) return;

          // Se c’è Bearer => verifichiamo M2M
          const authHeader = headers.get('authorization') || '';
          if (authHeader.toLowerCase().startsWith('bearer ')) {
            const token = authHeader.split(' ')[1];
            if (m2mConfig) {
              try {
                await verifyM2MToken(token, m2mConfig);
                // se ok => skip field filtering
                return;
              } catch (err) {
                throw new Error(`[GrantsAuthPlugin] M2M token invalid: ${(err as Error).message}`);
              }
            } else {
              // no config => skip
              return;
            }
          }

          // Altrimenti => x-user-groups
          const groups = parseGroups(headers.get('x-user-groups'));
          if (!groups.length) return; // se mancano => non filtra (o potresti filtrare tutto)

          // Colleziona tutti i fieldPaths viewable
          const union = new Set<string>();
          for (const g of groups) {
            const viewable = await fetchViewable(opts.grantsClient, g, opts.entityName);
            viewable.forEach(path => union.add(path));
          }

          removeDisallowed(data, union);
        },
      };
    },
  };
}