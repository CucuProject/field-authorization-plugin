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
 * 5) Utilities
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
/* -------------------------------------------------------------------------
 * 6) Verifica M2M: uso di jwks-rsa e verify() di jsonwebtoken
 * ----------------------------------------------------------------------- */
async function verifyM2MToken(token, cfg) {
    // Crea client JWKS, con caching
    const jwksClient = (0, jwks_rsa_1.default)({
        jwksUri: cfg.jwksUri,
        cache: true,
        cacheMaxAge: 60000,
    });
    const getKey = (header, callback) => {
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
    const chosenAlgos = (cfg.allowedAlgos || ['RS256']);
    return new Promise((resolve, reject) => {
        (0, jsonwebtoken_1.verify)(token, getKey, {
            audience: cfg.audience,
            issuer: cfg.issuer,
            algorithms: chosenAlgos,
        }, (err, decoded) => {
            if (err) {
                return reject(err);
            }
            // se vuoi controllare che “decoded.client_id” esista
            // (NB: Keycloak a volte mette client_id in "azp" o "clientId", dipende dalla config)
            // a tua scelta:
            resolve();
        });
    });
}
/* -------------------------------------------------------------------------
 * 7) Plugin “createGrantsAuthorizationPlugin”
 * ----------------------------------------------------------------------- */
function createGrantsAuthorizationPlugin(opts) {
    const parseGroups = opts.parseGroupIds ?? defaultParseGroups;
    const m2mConfig = opts.m2mVerificationConfig;
    return {
        async requestDidStart() {
            return {
                // ----------------------------------------
                // A) canExecute => didResolveOperation
                // ----------------------------------------
                async didResolveOperation(rc) {
                    const headers = rc.request.http?.headers;
                    if (!headers)
                        return;
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
                            }
                            catch (err) {
                                // se token M2M invalido => blocchiamo
                                throw new Error(`[GrantsAuthPlugin] M2M token invalid: ${err.message}`);
                            }
                        }
                        else {
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
                    const allowed = await Promise.any(groups.map(g => checkCanExecute(opts.grantsClient, g, opName))).catch(() => false);
                    if (!allowed) {
                        throw new Error(`[GrantsAuthPlugin] Operazione "${opName}" negata per gruppi ${groups.join(',')}`);
                    }
                },
                // ----------------------------------------
                // B) field-level filtering => willSendResponse
                // ----------------------------------------
                async willSendResponse(rc) {
                    if (rc.response.body.kind !== 'single')
                        return;
                    const data = rc.response.body.singleResult.data;
                    if (!data)
                        return;
                    const headers = rc.request.http?.headers;
                    if (!headers)
                        return;
                    // Se c’è Bearer => verifichiamo M2M
                    const authHeader = headers.get('authorization') || '';
                    if (authHeader.toLowerCase().startsWith('bearer ')) {
                        const token = authHeader.split(' ')[1];
                        if (m2mConfig) {
                            try {
                                await verifyM2MToken(token, m2mConfig);
                                // se ok => skip field filtering
                                return;
                            }
                            catch (err) {
                                throw new Error(`[GrantsAuthPlugin] M2M token invalid: ${err.message}`);
                            }
                        }
                        else {
                            // no config => skip
                            return;
                        }
                    }
                    // Altrimenti => x-user-groups
                    const groups = parseGroups(headers.get('x-user-groups'));
                    if (!groups.length)
                        return; // se mancano => non filtra (o potresti filtrare tutto)
                    // Colleziona tutti i fieldPaths viewable
                    const union = new Set();
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
