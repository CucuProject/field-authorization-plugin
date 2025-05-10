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
// Funzione predefinita per parsare x-user-groups
function defaultParseGroups(raw) {
    return raw
        ? raw.split(',').map(s => s.trim()).filter(Boolean)
        : [];
}
/** Rimuove da "obj" i campi non presenti in “allowedFields” (ricorsivo) */
function removeDisallowed(obj, allowedFields, path = '') {
    if (!obj || typeof obj !== 'object')
        return;
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
        }
        else {
            if (!allowedFields.has(subPath)) {
                delete obj[k];
            }
        }
    }
}
/** Invoca Grants per check canExecute */
async function checkCanExecute(client, groupId, opName) {
    return (0, rxjs_1.lastValueFrom)(client.send('FIND_OP_PERMISSIONS_BY_GROUP', { groupId }))
        .then(list => list.some(p => p.operationName === opName && p.canExecute))
        .catch(() => false);
}
/** Invoca Grants per ottenere i fieldPath “viewable” */
async function fetchViewable(client, groupId, entityName) {
    return (0, rxjs_1.lastValueFrom)(client.send('FIND_PERMISSIONS_BY_GROUP', { groupId, entityName }))
        .then(list => new Set(list.filter(p => p.canView).map(p => p.fieldPath)))
        .catch(() => new Set());
}
/**
 * Verifica un token Bearer M2M tramite jwks-rsa e jsonwebtoken.verify().
 * Accetta audience singola o array di audience.
 */
async function verifyM2MToken(token, cfg) {
    const jwksClient = (0, jwks_rsa_1.default)({
        jwksUri: cfg.jwksUri,
        cache: true,
        cacheMaxAge: 60_000,
    });
    const getKey = (header, callback) => {
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
    const chosenAlgos = (cfg.allowedAlgos || ['RS256']);
    return new Promise((resolve, reject) => {
        (0, jsonwebtoken_1.verify)(token, getKey, {
            audience: cfg.audience,
            issuer: cfg.issuer,
            algorithms: chosenAlgos,
        }, (err) => {
            if (err) {
                return reject(err);
            }
            resolve();
        });
    });
}
/* -------------------------------------------------------------------------
 * 6) Plugin “createGrantsAuthorizationPlugin”
 * ----------------------------------------------------------------------- */
function createGrantsAuthorizationPlugin(opts) {
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
            return {
                // ----------------------------------------------
                // A) canExecute => didResolveOperation
                // ----------------------------------------------
                async didResolveOperation(rc) {
                    console.log('[GrantsPlugin] didResolveOperation - start, opName=', rc.operationName);
                    const headers = rc.request.http?.headers;
                    if (!headers) {
                        console.log('[GrantsPlugin] didResolveOperation - no headers; skipping');
                        return;
                    }
                    const opName = rc.operationName ?? rc.operation?.name?.value ?? 'UnnamedOperation';
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
                        }
                        catch (err) {
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
                        canExe = await Promise.any(groups.map(g => checkCanExecute(opts.grantsClient, g, opName)));
                        console.log('[GrantsPlugin] canExe =>', canExe);
                    }
                    catch (err) {
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
                async willSendResponse(rc) {
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
                    const opName = rc.operationName ?? rc.operation?.name?.value ?? 'UnnamedOperation';
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
                    const union = new Set();
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
