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
          console.log('[GrantsPlugin] didResolveOperation - start, opName=', rc.operationName);

          const headers = rc.request.http?.headers;
          if (!headers) {
            console.log('[GrantsPlugin] didResolveOperation - no headers; skipping');
            return;
          }

          const opName =
            rc.operationName ?? rc.operation?.name?.value ?? 'UnnamedOperation';

          console.log('[GrantsPlugin] opName =', opName);

          // 1) Federation?
          if (FEDERATION_OPS.has(opName)) {
            console.log('[GrantsPlugin] opName is Federation => bypass');
            return;
          }

          // 2) Bearer => M2M
          const authHeader = headers.get('authorization') || '';
          console.log('[GrantsPlugin] authorization=', authHeader);

          if (authHeader.toLowerCase().startsWith('bearer ')) {
            console.log('[GrantsPlugin] Bearer token => verifying as M2M...');
            if (!m2mConfig) {
              throw new Error('Bearer token presente, ma manca m2mVerificationConfig');
            }
            const token = authHeader.split(' ')[1];
            try {
              await verifyM2MToken(token, m2mConfig);
              console.log('[GrantsPlugin] M2M token verify OK => skip x-user-groups check');
              return;
            } catch (err) {
              console.log('[GrantsPlugin] M2M token verify ERROR =>', err);
              throw err;
            }
          }

          // 3) Altrimenti => x-user-groups
          const rawGroups = headers.get('x-user-groups');
          console.log('[GrantsPlugin] x-user-groups=', rawGroups);
          if (!rawGroups) {
            console.log('[GrantsPlugin] => NO x-user-groups => throw error');
            throw new Error(`[GrantsAuthPlugin] Nessun Bearer token e nessun x-user-groups => denied (op=${opName})`);
          }

          // parse
          const groups = parseGroups(rawGroups);
          console.log('[GrantsPlugin] parsed groups=', groups);

          if (!groups.length) {
            console.log('[GrantsPlugin] groups è array vuoto => denied');
            throw new Error(`[GrantsAuthPlugin] x-user-groups è vuoto => denied.`);
          }

          console.log(`[GrantsPlugin] => checking canExecute for op="${opName}"`);
          let canExe = false;
          try {
            // Promise.any => se TUTTI danno false => catch
            canExe = await Promise.any(
              groups.map(g => checkCanExecute(opts.grantsClient, g, opName)),
            );
            console.log('[GrantsPlugin] canExe =>', canExe);
          } catch (err) {
            // se *tutte* le promise rifiutano, o .any() entra qui
            console.log('[GrantsPlugin] promise.any => false =>', err);
            canExe = false;
          }

          if (!canExe) {
            console.log(`[GrantsPlugin] => not allowed to execute "${opName}" => throw error`);
            throw new Error(`[GrantsAuthPlugin] Operazione "${opName}" non consentita per i gruppi [${groups.join(',')}]`);
          }

          console.log('[GrantsPlugin] => didResolveOperation OK => continuing');
        },
        // ----------------------------------------------
        // B) field-level filtering => willSendResponse
        // ----------------------------------------------
        async willSendResponse(rc: GraphQLRequestContextWillSendResponse<BaseContext>) {
          console.log('[GrantsPlugin] willSendResponse - start');

          if (rc.response.body.kind !== 'single') {
            console.log('[GrantsPlugin] willSendResponse => not single => skip');
            return;
          }
          const data = rc.response.body.singleResult.data;
          console.log('[GrantsPlugin] data keys =', data && Object.keys(data));

          if (!data) {
            console.log('[GrantsPlugin] no data => skip');
            return;
          }

          const headers = rc.request.http?.headers;
          if (!headers) {
            console.log('[GrantsPlugin] no headers => skip');
            return;
          }

          const opName =
            rc.operationName ?? rc.operation?.name?.value ?? 'UnnamedOperation';
          console.log('[GrantsPlugin] opName =', opName);

          if (FEDERATION_OPS.has(opName)) {
            console.log('[GrantsPlugin] federation => skip');
            return;
          }

          // check Bearer
          const authHeader = headers.get('authorization') || '';
          console.log('[GrantsPlugin] authHeader =', authHeader);
          if (authHeader.toLowerCase().startsWith('bearer ')) {
            console.log('[GrantsPlugin] Bearer => skip field filtering');
            return;
          }

          // parse x-user-groups
          const rawGroups = headers.get('x-user-groups');
          console.log('[GrantsPlugin] x-user-groups =', rawGroups);
          if (!rawGroups) {
            console.log('[GrantsPlugin] => skip because no groups');
            return;
          }

          const groups = parseGroups(rawGroups);
          if (!groups.length) {
            console.log('[GrantsPlugin] => skip because groups[] is empty');
            return;
          }

          console.log('[GrantsPlugin] => fetching fieldPermissions from grants...');
          const union = new Set<string>();
          for (const g of groups) {
            // potresti loggare g
            const viewable = await fetchViewable(opts.grantsClient, g, opts.entityName);
            console.log('[GrantsPlugin] group=', g, 'viewable =', viewable);
            viewable.forEach(path => union.add(path));
          }

          console.log('[GrantsPlugin] union of fieldPaths =', union);
          removeDisallowed(data, union);
          console.log('[GrantsPlugin] => data post removeDisallowed =', data);
        },
      };
    },
  };
}