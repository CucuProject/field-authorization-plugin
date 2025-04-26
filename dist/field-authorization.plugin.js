"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createGrantsAuthorizationPlugin = createGrantsAuthorizationPlugin;
const rxjs_1 = require("rxjs");
/* ---------- Utilities ---------- */
const defaultParse = (raw) => raw ? raw.split(',').map(s => s.trim()).filter(Boolean) : [];
const removeDisallowed = (obj, allowed, p = '') => {
    if (!obj || typeof obj !== 'object')
        return;
    if (Array.isArray(obj)) {
        obj.forEach(i => removeDisallowed(i, allowed, p));
        return;
    }
    for (const k of Object.keys(obj)) {
        const path = p ? `${p}.${k}` : k;
        if (path === '_id')
            continue;
        const v = obj[k];
        if (v && typeof v === 'object') {
            removeDisallowed(v, allowed, path);
            if (Object.keys(v).length === 0)
                delete obj[k];
        }
        else if (!allowed.has(path)) {
            delete obj[k];
        }
    }
};
const checkCanExecute = async (client, g, op) => (0, rxjs_1.lastValueFrom)(client.send('FIND_OP_PERMISSIONS_BY_GROUP', { groupId: g }))
    .then(list => list.some(p => p.operationName === op && p.canExecute))
    .catch(() => false);
const fetchViewable = async (client, g, entity) => (0, rxjs_1.lastValueFrom)(client.send('FIND_PERMISSIONS_BY_GROUP', { groupId: g, entityName: entity }))
    .then(list => new Set(list.filter(p => p.canView).map(p => p.fieldPath)))
    .catch(() => new Set());
/* ---------- Factory ---------- */
function createGrantsAuthorizationPlugin(opts) {
    const parseGroups = opts.parseGroupIds ?? defaultParse;
    return {
        async requestDidStart() {
            return {
                /* ---- 1)  canExecute ------------------------------------------------ */
                async didResolveOperation(rc) {
                    const groups = parseGroups(rc.request.http?.headers.get('x-user-groups'));
                    if (groups.length === 0)
                        throw new Error('[GrantsAuthPlugin] header "x-user-groups" mancante');
                    const opName = rc.operationName ?? rc.operation?.name?.value ?? 'UnnamedOperation';
                    const allowed = await Promise.any(groups.map(g => checkCanExecute(opts.grantsClient, g, opName))).catch(() => false);
                    if (!allowed)
                        throw new Error(`[GrantsAuthPlugin] operazione "${opName}" non consentita per gruppi ${groups.join(',')}`);
                },
                /* ---- 2)  Field-level filtering ------------------------------------ */
                async willSendResponse(rc) {
                    if (rc.response.body.kind !== 'single')
                        return;
                    const data = rc.response.body.singleResult.data;
                    if (!data)
                        return;
                    const groups = parseGroups(rc.request.http?.headers.get('x-user-groups'));
                    if (groups.length === 0)
                        return;
                    const union = new Set();
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
