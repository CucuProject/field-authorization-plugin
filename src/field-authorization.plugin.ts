import {
  ApolloServerPlugin,
  BaseContext,
  GraphQLRequestListener,
  GraphQLRequestContextDidResolveOperation,
  GraphQLRequestContextWillSendResponse,
} from '@apollo/server';
import { lastValueFrom, Observable } from 'rxjs';

/* ---------- TIPI provenienti da Grants ---------- */
interface FieldPermission   { fieldPath: string; canView: boolean; }
interface OperationPermission { operationName: string; canExecute: boolean; }

/* ---------- “Client-like” : solo ciò che serve al plugin ---------- */
export interface GrantsClientLike {
  send<R = any, D = any>(pattern: any, data: D): Observable<R>;
}

/* ---------- Opzioni esposte al sub-graph ---------- */
export interface GrantsAuthPluginOptions {
  grantsClient : GrantsClientLike;   // <-- NIENTE ClientProxy nominale
  entityName   : string;
  parseGroupIds?: (raw?: string | null) => string[];
}

/* ---------- Utilities ---------- */
const defaultParse = (raw?: string|null): string[] =>
  raw ? raw.split(',').map(s => s.trim()).filter(Boolean) : [];

const removeDisallowed = (obj: any, allowed: Set<string>, p = ''): void => {
  if (!obj || typeof obj !== 'object') return;
  if (Array.isArray(obj)) { obj.forEach(i => removeDisallowed(i, allowed, p)); return; }
  for (const k of Object.keys(obj)) {
    const path = p ? `${p}.${k}` : k;
    if (path === '_id') continue;
    const v = obj[k];
    if (v && typeof v === 'object') {
      removeDisallowed(v, allowed, path);
      if (Object.keys(v).length === 0) delete obj[k];
    } else if (!allowed.has(path)) {
      delete obj[k];
    }
  }
};

const checkCanExecute = async (
  client: GrantsClientLike, g: string, op: string,
): Promise<boolean> =>
  lastValueFrom(
    client.send<OperationPermission[]>('FIND_OP_PERMISSIONS_BY_GROUP', { groupId: g }),
  )
    .then(list => list.some(p => p.operationName === op && p.canExecute))
    .catch(() => false);

const fetchViewable = async (
  client: GrantsClientLike, g: string, entity: string,
): Promise<Set<string>> =>
  lastValueFrom(
    client.send<FieldPermission[]>('FIND_PERMISSIONS_BY_GROUP', { groupId: g, entityName: entity }),
  )
    .then(list => new Set(list.filter(p => p.canView).map(p => p.fieldPath)))
    .catch(() => new Set<string>());

/* ---------- Factory ---------- */
export function createGrantsAuthorizationPlugin(
  opts: GrantsAuthPluginOptions,
): ApolloServerPlugin<BaseContext> {

  const parseGroups = opts.parseGroupIds ?? defaultParse;

  return {
    async requestDidStart() {

      return <GraphQLRequestListener<BaseContext>>{

        /* ---- 1)  canExecute ------------------------------------------------ */
        async didResolveOperation(rc: GraphQLRequestContextDidResolveOperation<BaseContext>) {
          const groups = parseGroups(rc.request.http?.headers.get('x-user-groups'));
          if (groups.length === 0)
            throw new Error('[GrantsAuthPlugin] header "x-user-groups" mancante');

          const opName =
            rc.operationName ?? rc.operation?.name?.value ?? 'UnnamedOperation';

          const allowed = await Promise.any(
            groups.map(g => checkCanExecute(opts.grantsClient, g, opName)),
          ).catch(() => false);

          if (!allowed)
            throw new Error(
              `[GrantsAuthPlugin] operazione "${opName}" non consentita per gruppi ${groups.join(',')}`,
            );
        },

        /* ---- 2)  Field-level filtering ------------------------------------ */
        async willSendResponse(rc: GraphQLRequestContextWillSendResponse<BaseContext>) {
          if (rc.response.body.kind !== 'single') return;
          const data = rc.response.body.singleResult.data;
          if (!data) return;

          const groups = parseGroups(rc.request.http?.headers.get('x-user-groups'));
          if (groups.length === 0) return;

          const union = new Set<string>();
          for (const g of groups) {
            (await fetchViewable(opts.grantsClient, g, opts.entityName))
              .forEach(f => union.add(f));
          }
          removeDisallowed(data, union);
        },
      };
    },
  };
}
