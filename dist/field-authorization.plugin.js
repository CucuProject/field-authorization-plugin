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
/** Parser di default per x-user-groups */
function defaultParseGroups(raw) {
    return raw
        ? raw.split(',').map(s => s.trim()).filter(Boolean)
        : [];
}
/** Rimuove da "obj" i campi non inclusi in “allowedFields” (ricorsivo) */
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
        }
        else {
            if (!allowedFields.has(subPath)) {
                delete obj[k];
            }
        }
    }
}
/** Richiama Grants per check canExecute */
async function checkCanExecute(client, groupId, opName) {
    return (0, rxjs_1.lastValueFrom)(client.send('FIND_OP_PERMISSIONS_BY_GROUP', { groupId }))
        .then(list => list.some(p => p.operationName === opName && p.canExecute))
        .catch(() => false);
}
/** Richiama Grants per ottenere i fieldPaths “viewable” da un gruppo su una certa entity */
async function fetchViewable(client, groupId, entityName) {
    return (0, rxjs_1.lastValueFrom)(client.send('FIND_PERMISSIONS_BY_GROUP', { groupId, entityName }))
        .then(list => new Set(list.filter(p => p.canView).map(p => p.fieldPath)))
        .catch(() => new Set());
}
/** Verifica Bearer M2M via jwks-rsa e jsonwebtoken.verify() */
async function verifyM2MToken(token, cfg) {
    // Crea un client JWKS con caching
    const jwksClient = (0, jwks_rsa_1.default)({
        jwksUri: cfg.jwksUri,
        cache: true,
        cacheMaxAge: 60_000,
    });
    // Sostituisce la chiave “on the fly”
    const getKey = (header, callback) => {
        jwksClient.getSigningKey(header.kid, (err, key) => {
            if (err)
                return callback(err);
            if (!key) {
                return callback(new Error(`No signing key found for kid=${header.kid}`));
            }
            const signingKey = key.getPublicKey();
            callback(null, signingKey);
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
    const parseGroups = opts.parseGroupIds ?? defaultParseGroups;
    const m2mConfig = opts.m2mVerificationConfig;
    return {
        async requestDidStart() {
            return {
                // ----------------------------------------
                // A) “canExecute” => didResolveOperation
                // ----------------------------------------
                async didResolveOperation(rc) {
                    const headers = rc.request.http?.headers;
                    if (!headers)
                        return;
                    const opName = rc.operationName ?? rc.operation?.name?.value ?? 'UnnamedOperation';
                    /* --- 1) Se abbiamo Bearer => check M2M --- */
                    const authHeader = headers.get('authorization') || '';
                    if (authHeader.toLowerCase().startsWith('bearer ')) {
                        if (!m2mConfig) {
                            throw new Error('[GrantsAuthPlugin] Bearer present, but no m2mVerificationConfig provided.');
                        }
                        const token = authHeader.split(' ')[1];
                        try {
                            await verifyM2MToken(token, m2mConfig);
                            // Se M2M è valido => skip x-user-groups => “canExecute” con token M2M
                            return;
                        }
                        catch (err) {
                            throw new Error(`[GrantsAuthPlugin] M2M token invalid: ${err.message}`);
                        }
                    }
                    /* --- 2) Altrimenti, parse “x-user-groups” --- */
                    const rawGroups = headers.get('x-user-groups');
                    if (!rawGroups) {
                        // Qui blocchiamo se manca Bearer e manca x-user-groups
                        // Se desideri bypassare introspezione, potresti fare un check su
                        // if (['_service', '_entities'].includes(opName)) { return; }
                        // Altrimenti errore
                        throw new Error(`[GrantsAuthPlugin] No Bearer token and no x-user-groups => Denied (op=${opName}).`);
                    }
                    // parse groupIds
                    const groups = parseGroups(rawGroups);
                    if (!groups.length) {
                        throw new Error('[GrantsAuthPlugin] “x-user-groups” is empty => denied.');
                    }
                    // check canExecute
                    const allowed = await Promise.any(groups.map(g => checkCanExecute(opts.grantsClient, g, opName))).catch(() => false);
                    if (!allowed) {
                        throw new Error(`[GrantsAuthPlugin] Operation "${opName}" not allowed for groups=${groups.join(',')}`);
                    }
                },
                // ----------------------------------------
                // B) field-level filtering => willSendResponse
                // ----------------------------------------
                async willSendResponse(rc) {
                    // Se la risposta non è “single” => skip
                    if (rc.response.body.kind !== 'single')
                        return;
                    const data = rc.response.body.singleResult.data;
                    if (!data)
                        return; // no data => skip
                    const headers = rc.request.http?.headers;
                    if (!headers)
                        return;
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
                    const union = new Set();
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
