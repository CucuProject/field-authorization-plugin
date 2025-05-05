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
/**
 * Verifica Bearer M2M via jwks-rsa e jsonwebtoken.verify().
 * Accetta audience come string o come lista.
 */
async function verifyM2MToken(token, cfg) {
    console.log('[GrantsAuthPlugin] verifyM2MToken START');
    console.log(`[GrantsAuthPlugin] Using jwksUri=${cfg.jwksUri}, issuer=${cfg.issuer}, audience=`, cfg.audience);
    const jwksClient = (0, jwks_rsa_1.default)({
        jwksUri: cfg.jwksUri,
        cache: true,
        cacheMaxAge: 60_000,
    });
    const getKey = (header, callback) => {
        jwksClient.getSigningKey(header.kid, (err, key) => {
            if (err) {
                console.error('[GrantsAuthPlugin] getSigningKey error =>', err);
                return callback(err);
            }
            if (!key) {
                console.error(`[GrantsAuthPlugin] No signing key found for kid=${header.kid}`);
                return callback(new Error(`No signing key for kid=${header.kid}`));
            }
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
            if (err) {
                console.error('[GrantsAuthPlugin] verifyM2MToken => jwt.verify error =>', err);
                return reject(err);
            }
            console.log('[GrantsAuthPlugin] verifyM2MToken => OK');
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
    console.log('[GrantsAuthPlugin] createGrantsAuthorizationPlugin => m2mConfig=', m2mConfig);
    return {
        async requestDidStart() {
            console.log('[GrantsAuthPlugin] requestDidStart fired');
            return {
                // ----------------------------------------------
                // A) canExecute => didResolveOperation
                // ----------------------------------------------
                async didResolveOperation(rc) {
                    console.log('[GrantsAuthPlugin] didResolveOperation: START');
                    try {
                        const headers = rc.request.http?.headers;
                        if (!headers) {
                            console.log('[GrantsAuthPlugin] No headers => skip');
                            return;
                        }
                        const opName = rc.operationName ?? rc.operation?.name?.value ?? 'UnnamedOperation';
                        console.log(`[GrantsAuthPlugin] didResolveOperation => opName="${opName}"`);
                        /** 1) Check se x-internal-federation-call=1 */
                        const fedFlag = headers.get('x-internal-federation-call');
                        console.log('[GrantsAuthPlugin] x-internal-federation-call =>', fedFlag);
                        if (fedFlag === '1') {
                            console.log('[GrantsAuthPlugin] Federation internal call => verifying M2M token');
                            if (!m2mConfig) {
                                throw new Error('[GrantsAuthPlugin] x-internal-federation-call=1 ma manca m2mVerificationConfig');
                            }
                            const authHeader = headers.get('authorization') || '';
                            if (!authHeader.toLowerCase().startsWith('bearer ')) {
                                throw new Error('[GrantsAuthPlugin] Missing Bearer in x-internal-federation-call => denied');
                            }
                            const token = authHeader.split(' ')[1];
                            await verifyM2MToken(token, m2mConfig);
                            console.log('[GrantsAuthPlugin] Federation M2M token => OK, skip group checks');
                            return;
                        }
                        /** 2) Se non è federation-call, controlliamo Bearer M2M (facoltativo) */
                        const authHeader = headers.get('authorization') || '';
                        if (authHeader.toLowerCase().startsWith('bearer ')) {
                            console.log('[GrantsAuthPlugin] Found Bearer => verifying M2M token');
                            if (!m2mConfig) {
                                throw new Error('[GrantsAuthPlugin] Bearer found, but no m2mVerificationConfig provided.');
                            }
                            const token = authHeader.split(' ')[1];
                            await verifyM2MToken(token, m2mConfig);
                            console.log('[GrantsAuthPlugin] M2M token => OK => skip x-user-groups checks');
                            return;
                        }
                        /** 3) Altrimenti => parse x-user-groups */
                        console.log('[GrantsAuthPlugin] No bearer => expecting x-user-groups for FE calls');
                        const rawGroups = headers.get('x-user-groups');
                        if (!rawGroups) {
                            throw new Error(`[GrantsAuthPlugin] No Bearer and no x-user-groups => denied. (opName=${opName})`);
                        }
                        const groups = parseGroups(rawGroups);
                        console.log(`[GrantsAuthPlugin] x-user-groups => [${groups.join(', ')}]`);
                        if (!groups.length) {
                            throw new Error('[GrantsAuthPlugin] x-user-groups is empty => denied.');
                        }
                        // check canExecute
                        const allowed = await Promise.any(groups.map(g => checkCanExecute(opts.grantsClient, g, opName))).catch(() => false);
                        console.log('[GrantsAuthPlugin] canExecute =>', allowed);
                        if (!allowed) {
                            throw new Error(`[GrantsAuthPlugin] Operation "${opName}" not allowed for groups=${groups.join(',')}`);
                        }
                        console.log('[GrantsAuthPlugin] didResolveOperation => OK');
                    }
                    catch (err) {
                        console.error('[GrantsAuthPlugin] didResolveOperation => ERROR:', err);
                        throw err;
                    }
                },
                // ----------------------------------------------
                // B) field-level filtering => willSendResponse
                // ----------------------------------------------
                async willSendResponse(rc) {
                    console.log('[GrantsAuthPlugin] willSendResponse: START');
                    try {
                        if (rc.response.body.kind !== 'single') {
                            console.log('[GrantsAuthPlugin] Response is not "single" => skip');
                            return;
                        }
                        const data = rc.response.body.singleResult.data;
                        if (!data) {
                            console.log('[GrantsAuthPlugin] No data => skip');
                            return;
                        }
                        const headers = rc.request.http?.headers;
                        if (!headers) {
                            console.log('[GrantsAuthPlugin] No headers => skip');
                            return;
                        }
                        // 1) Federation call? skip
                        const fedFlag = headers.get('x-internal-federation-call');
                        if (fedFlag === '1') {
                            console.log('[GrantsAuthPlugin] Federation call => skip field filtering');
                            return;
                        }
                        // 2) M2M Bearer? skip
                        const authHeader = headers.get('authorization') || '';
                        if (authHeader.toLowerCase().startsWith('bearer ')) {
                            console.log('[GrantsAuthPlugin] M2M bearer => skip field filtering');
                            return;
                        }
                        // 3) parse groups
                        const rawGroups = headers.get('x-user-groups');
                        if (!rawGroups) {
                            console.log('[GrantsAuthPlugin] No x-user-groups => skip or clear data?');
                            return;
                        }
                        const groups = defaultParseGroups(rawGroups);
                        console.log('[GrantsAuthPlugin] field-level => groups are:', groups);
                        if (!groups.length) {
                            console.log('[GrantsAuthPlugin] groups is empty => skip filtering');
                            return;
                        }
                        // fetch fieldPaths
                        console.log('[GrantsAuthPlugin] fetching fieldPaths => entityName=', opts.entityName);
                        const union = new Set();
                        for (const g of groups) {
                            const viewable = await fetchViewable(opts.grantsClient, g, opts.entityName);
                            viewable.forEach(path => union.add(path));
                        }
                        console.log('[GrantsAuthPlugin] final union =>', union);
                        // rimuovi i campi non inclusi
                        removeDisallowed(data, union);
                        console.log('[GrantsAuthPlugin] removed disallowed fields => done');
                    }
                    catch (err) {
                        console.error('[GrantsAuthPlugin] willSendResponse => ERROR:', err);
                        throw err;
                    }
                },
            };
        },
    };
}
