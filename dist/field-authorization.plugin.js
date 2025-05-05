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
                    const headers = rc.request.http?.headers;
                    if (!headers)
                        return;
                    const opName = rc.operationName ?? rc.operation?.name?.value ?? 'UnnamedOperation';
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
                        throw new Error(`[GrantsAuthPlugin] Nessun Bearer token e nessun x-user-groups => denied (op=${opName})`);
                    }
                    const groups = parseGroups(rawGroups);
                    if (!groups.length) {
                        throw new Error(`[GrantsAuthPlugin] x-user-groups è vuoto => denied.`);
                    }
                    // check canExecute su almeno un gruppo
                    const canExe = await Promise.any(groups.map(g => checkCanExecute(opts.grantsClient, g, opName))).catch(() => false);
                    if (!canExe) {
                        throw new Error(`[GrantsAuthPlugin] Operazione "${opName}" non consentita per i gruppi [${groups.join(',')}]`);
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
                    // 1) Se Federation => bypass
                    const opName = rc.operationName ?? rc.operation?.name?.value ?? 'UnnamedOperation';
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
                    const union = new Set();
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
