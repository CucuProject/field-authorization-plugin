"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createGrantsAuthorizationPlugin = createGrantsAuthorizationPlugin;
const jsonwebtoken_1 = require("jsonwebtoken");
const jwks_rsa_1 = __importDefault(require("jwks-rsa"));
const rxjs_1 = require("rxjs");
/* -------------------------------------------------------------------------
 * 5) Helpers
 * ----------------------------------------------------------------------- */
function defaultParseGroups(raw) {
    return raw
        ? raw.split(',').map(s => s.trim()).filter(Boolean)
        : [];
}
function removeDisallowed(obj, allowedFields, path = '') {
    if (!obj || typeof obj !== 'object')
        return;
    if (Array.isArray(obj)) {
        for (const item of obj)
            removeDisallowed(item, allowedFields, path);
        return;
    }
    for (const k of Object.keys(obj)) {
        const subPath = path ? `${path}.${k}` : k;
        // Manteniamo _id per convenzione
        if (subPath === '_id')
            continue;
        const val = obj[k];
        if (val && typeof val === 'object') {
            removeDisallowed(val, allowedFields, subPath);
            if (Object.keys(val).length === 0) {
                delete obj[k];
            }
        }
        else {
            if (!allowedFields.has(subPath)) {
                delete obj[k];
            }
        }
    }
}
async function checkCanExecute(client, groupId, opName) {
    return (0, rxjs_1.lastValueFrom)(client.send('FIND_OP_PERMISSIONS_BY_GROUP', { groupId }))
        .then(list => list.some(p => p.operationName === opName && p.canExecute))
        .catch(() => false);
}
async function fetchViewable(client, groupId, entityName) {
    return (0, rxjs_1.lastValueFrom)(client.send('FIND_PERMISSIONS_BY_GROUP', { groupId, entityName }))
        .then(list => new Set(list.filter(p => p.canView).map(p => p.fieldPath)))
        .catch(() => new Set());
}
/** Verifica Bearer M2M via jwks-rsa e jsonwebtoken.verify() */
async function verifyM2MToken(token, cfg) {
    const jwksClient = (0, jwks_rsa_1.default)({
        jwksUri: cfg.jwksUri,
        cache: true,
        cacheMaxAge: 60_000,
    });
    const getKey = (header, callback) => {
        jwksClient.getSigningKey(header.kid, (err, key) => {
            if (err)
                return callback(err);
            if (!key)
                return callback(new Error(`No signing key for kid=${header.kid}`));
            callback(null, key.getPublicKey());
        });
    };
    const chosenAlgos = (cfg.allowedAlgos || ['RS256']);
    return new Promise((resolve, reject) => {
        (0, jsonwebtoken_1.verify)(token, getKey, {
            audience: cfg.audience,
            issuer: cfg.issuer,
            algorithms: chosenAlgos,
        }, (err) => {
            if (err)
                return reject(err);
            resolve();
        });
    });
}
/* -------------------------------------------------------------------------
 * 6) Plugin “createGrantsAuthorizationPlugin”
 * ----------------------------------------------------------------------- */
function createGrantsAuthorizationPlugin(opts) {
    const parseGroups = opts.parseGroupIds ?? defaultParseGroups;
    const m2mConfig = opts.m2mVerificationConfig;
    return {
        async requestDidStart() {
            return {
                // ----------------------------------------------
                // A) canExecute => didResolveOperation
                // ----------------------------------------------
                async didResolveOperation(rc) {
                    const headers = rc.request.http?.headers;
                    if (!headers)
                        return;
                    const opName = rc.operationName ?? rc.operation?.name?.value ?? 'UnnamedOperation';
                    /** 1) Check se x-internal-federation-call=1 */
                    const fedFlag = headers.get('x-internal-federation-call');
                    if (fedFlag === '1') {
                        // → DEVE essere presente Bearer M2M e valido
                        if (!m2mConfig) {
                            throw new Error('[GrantsAuthPlugin] x-internal-federation-call=1 ma manca m2mVerificationConfig');
                        }
                        const authHeader = headers.get('authorization') || '';
                        if (!authHeader.toLowerCase().startsWith('bearer ')) {
                            throw new Error('[GrantsAuthPlugin] Missing Bearer in x-internal-federation-call => denied');
                        }
                        // Verifichiamo M2M
                        const token = authHeader.split(' ')[1];
                        try {
                            await verifyM2MToken(token, m2mConfig);
                        }
                        catch (err) {
                            throw new Error(`[GrantsAuthPlugin] Federation Bearer M2M invalid: ${err.message}`);
                        }
                        // se ok => skip i controlli su group
                        return;
                    }
                    /** 2) Se non è federation-call, controlliamo Bearer M2M (facoltativo) */
                    const authHeader = headers.get('authorization') || '';
                    if (authHeader.toLowerCase().startsWith('bearer ')) {
                        if (!m2mConfig) {
                            throw new Error('[GrantsAuthPlugin] Bearer found, but no m2mVerificationConfig provided.');
                        }
                        const token = authHeader.split(' ')[1];
                        try {
                            await verifyM2MToken(token, m2mConfig);
                            return; // skip x-user-groups
                        }
                        catch (err) {
                            throw new Error(`[GrantsAuthPlugin] M2M token invalid: ${err.message}`);
                        }
                    }
                    /** 3) Altrimenti => parse x-user-groups */
                    const rawGroups = headers.get('x-user-groups');
                    if (!rawGroups) {
                        throw new Error(`[GrantsAuthPlugin] No Bearer and no x-user-groups => denied. (opName=${opName})`);
                    }
                    const groups = parseGroups(rawGroups);
                    if (!groups.length) {
                        throw new Error('[GrantsAuthPlugin] x-user-groups is empty => denied.');
                    }
                    // check canExecute
                    const allowed = await Promise.any(groups.map(g => checkCanExecute(opts.grantsClient, g, opName))).catch(() => false);
                    if (!allowed) {
                        throw new Error(`[GrantsAuthPlugin] Operation "${opName}" not allowed for groups=${groups.join(',')}`);
                    }
                },
                // ----------------------------------------------
                // B) field-level filtering => willSendResponse
                // ----------------------------------------------
                async willSendResponse(rc) {
                    if (rc.response.body.kind !== 'single')
                        return;
                    const data = rc.response.body.singleResult.data;
                    if (!data)
                        return;
                    const headers = rc.request.http?.headers;
                    if (!headers)
                        return;
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
                    if (!rawGroups)
                        return; // nessun group => potresti forzare data = {}
                    const groups = parseGroups(rawGroups);
                    if (!groups.length)
                        return;
                    // fetch fieldPaths
                    const union = new Set();
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
