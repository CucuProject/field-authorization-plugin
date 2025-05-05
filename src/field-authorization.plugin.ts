import {
  ApolloServerPlugin,
  BaseContext,
  GraphQLRequestListener,
  GraphQLRequestContextDidResolveOperation,
  GraphQLRequestContextWillSendResponse,
} from '@apollo/server';
import { verify, Algorithm } from 'jsonwebtoken';
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
 * 2) Interfaccia “Client-like” (per GrantsClient) => .send()
 * ----------------------------------------------------------------------- */
export interface GrantsClientLike {
  send<R = any, D = any>(pattern: any, data: D): Observable<R>;
}

/* -------------------------------------------------------------------------
 * 3) Configurazione Keycloak M2M (audience può essere string o array)
 * ----------------------------------------------------------------------- */
export interface M2MVerificationConfig {
  jwksUri: string;            // es: "http://keycloak:8080/.../certs"
  issuer: string;             // es: "http://keycloak:8080/realms/myrealm"
  audience: string | string[]; // uno o più client_id validi
  allowedAlgos?: string[];    // default: ['RS256']
}

/* -------------------------------------------------------------------------
 * 4) Opzioni del plugin
 * ----------------------------------------------------------------------- */
export interface GrantsAuthPluginOptions {
  grantsClient: GrantsClientLike;
  entityName: string;
  parseGroupIds?: (raw?: string | null) => string[];
  m2mVerificationConfig?: M2MVerificationConfig;
}

/* -------------------------------------------------------------------------
 * 5) Helpers
 * ----------------------------------------------------------------------- */
// Funzione predefinita per parsare x-user-groups
function defaultParseGroups(raw?: string | null): string[] {
  return raw
    ? raw.split(',').map(s => s.trim()).filter(Boolean)
    : [];
}

/** Rimuove da "obj" i campi non presenti in “allowedFields” (ricorsivo) */
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

    // Manteniamo per convenzione "_id"
    if (subPath === '_id') {
      continue;
    }

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

/** Invoca Grants per check canExecute */
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

/** Invoca Grants per ottenere i fieldPath “viewable” */
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

/**
 * Verifica un token Bearer M2M tramite jwks-rsa e jsonwebtoken.verify().
 * Accetta audience singola o array di audience.
 */
async function verifyM2MToken(token: string, cfg: M2MVerificationConfig): Promise<void> {
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
  // Se parseGroupIds non è fornita, usiamo defaultParseGroups
  const parseGroups = opts.parseGroupIds ?? defaultParseGroups;
  const m2mConfig = opts.m2mVerificationConfig;

  // Set di operazioni Federation / introspezione che vogliamo “bypassare”
  const FEDERATION_OPS = new Set([
    '_service',
    '__ApolloGetServiceDefinition__',
    '_entities',
  ]);

  return {
    async requestDidStart() {
      return <GraphQLRequestListener<BaseContext>>{
        // ----------------------------------------------
        // A) canExecute => didResolveOperation
        // ----------------------------------------------
        async didResolveOperation(rc: GraphQLRequestContextDidResolveOperation<BaseContext>) {
          const headers = rc.request.http?.headers;
          if (!headers) return;

          const opName =
            rc.operationName ?? rc.operation?.name?.value ?? 'UnnamedOperation';

          // 1) Se è un'operazione di Federation => bypass
          if (FEDERATION_OPS.has(opName)) {
            return;
          }

          // 2) Se c’è Bearer => M2M check
          const authHeader = headers.get('authorization') || '';
          if (authHeader.toLowerCase().startsWith('bearer ')) {
            if (!m2mConfig) {
              throw new Error('Bearer token presente, ma manca m2mVerificationConfig');
            }
            const token = authHeader.split(' ')[1];
            await verifyM2MToken(token, m2mConfig);
            // => se verifica ok => saltiamo x-user-groups
            return;
          }

          // 3) Altrimenti => x-user-groups
          const rawGroups = headers.get('x-user-groups');
          if (!rawGroups) {
            throw new Error(
              `[GrantsAuthPlugin] Nessun Bearer token e nessun x-user-groups => denied (op=${opName})`,
            );
          }
          const groups = parseGroups(rawGroups);
          if (!groups.length) {
            throw new Error(`[GrantsAuthPlugin] x-user-groups è vuoto => denied.`);
          }

          // check canExecute su almeno un gruppo
          const canExe = await Promise.any(
            groups.map(g => checkCanExecute(opts.grantsClient, g, opName)),
          ).catch(() => false);

          if (!canExe) {
            throw new Error(
              `[GrantsAuthPlugin] Operazione "${opName}" non consentita per i gruppi [${groups.join(',')}]`,
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

          // 1) Se Federation => bypass
          const opName =
            rc.operationName ?? rc.operation?.name?.value ?? 'UnnamedOperation';
          if (FEDERATION_OPS.has(opName)) {
            return;
          }

          // 2) Se Bearer => skip
          const authHeader = headers.get('authorization') || '';
          if (authHeader.toLowerCase().startsWith('bearer ')) {
            return;
          }

          // 3) parse groups
          const rawGroups = headers.get('x-user-groups');
          if (!rawGroups) {
            return; // nessun group => non filtra
          }

          const groups = parseGroups(rawGroups);
          if (!groups.length) {
            return; // se vuoto => nessun filtering
          }

          // fetch fieldPaths “viewable”
          const union = new Set<string>();
          for (const g of groups) {
            const viewable = await fetchViewable(opts.grantsClient, g, opts.entityName);
            viewable.forEach(path => union.add(path));
          }

          // Rimuove i campi non inclusi
          removeDisallowed(data, union);
        },
      };
    },
  };
}