"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createMultiEntityGrantsPlugin = createMultiEntityGrantsPlugin;
const jsonwebtoken_1 = require("jsonwebtoken");
const jwks_rsa_1 = __importDefault(require("jwks-rsa"));
const rxjs_1 = require("rxjs");
/* -------------------------------------------------------------------------
 * 2) Helpers
 * ----------------------------------------------------------------------- */
// parse x-user-groups di default
function defaultParseGroups(raw) {
    return raw
        ? raw.split(',').map(s => s.trim()).filter(Boolean)
        : [];
}
// check operazione eseguibile
async function checkCanExecute(client, groupId, opName) {
    return (0, rxjs_1.lastValueFrom)(client.send('FIND_OP_PERMISSIONS_BY_GROUP', { groupId }))
        .then(list => list.some(p => p.operationName === opName && p.canExecute))
        .catch(() => false);
}
// Carica i fieldPaths “viewable” (per una data entityName)
async function fetchViewable(client, groupId, entityName) {
    return (0, rxjs_1.lastValueFrom)(client.send('FIND_PERMISSIONS_BY_GROUP', { groupId, entityName }))
        .then(list => new Set(list.filter(p => p.canView).map(p => p.fieldPath)))
        .catch(() => new Set());
}
/** Rimuove i campi *non consentiti*, basandosi su “allowedMap”. */
function removeDisallowedMultiEntity(obj, allowedMap, // es: { "Group": Set(...), "Permission": Set(...) }
defaultAllowed, // fallback se un __typename non esiste
path = '') {
    if (!obj || typeof obj !== 'object')
        return;
    if (Array.isArray(obj)) {
        for (const item of obj) {
            removeDisallowedMultiEntity(item, allowedMap, defaultAllowed, path);
        }
        return;
    }
    // Prova a vedere se esiste un __typename
    const typename = obj.__typename;
    const isKnownEntity = typename && allowedMap[typename];
    for (const k of Object.keys(obj)) {
        // Teniamo i campi speciali se vuoi (es. _id):
        if (k === '_id')
            continue;
        const subPath = path ? `${path}.${k}` : k;
        const val = obj[k];
        // Quale set di fieldPaths usare? se __typename non è conosciuto → fallback
        const setToUse = isKnownEntity ? allowedMap[typename] : defaultAllowed;
        if (val && typeof val === 'object') {
            removeDisallowedMultiEntity(val, allowedMap, defaultAllowed, subPath);
            // se l’oggetto “figlio” è vuoto dopo la pulizia, lo rimuoviamo
            if (Object.keys(val).length === 0) {
                delete obj[k];
            }
        }
        else {
            // se subPath non è nel set → rimuovi
            if (!setToUse.has(subPath)) {
                delete obj[k];
            }
        }
    }
}
/** Verifica un token Bearer M2M tramite jwks-rsa */
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
                return callback(new Error(`No signing key found for kid=${header.kid}`));
            callback(null, key.getPublicKey());
        });
    };
    const algos = (cfg.allowedAlgos || ['RS256']);
    return new Promise((resolve, reject) => {
        (0, jsonwebtoken_1.verify)(token, getKey, {
            audience: cfg.audience,
            issuer: cfg.issuer,
            algorithms: algos,
        }, (err) => {
            if (err)
                return reject(err);
            resolve();
        });
    });
}
/* -------------------------------------------------------------------------
 * 3) Plugin “createMultiEntityGrantsPlugin”
 * ----------------------------------------------------------------------- */
function createMultiEntityGrantsPlugin(opts) {
    const parseGroups = opts.parseGroupIds ?? defaultParseGroups;
    const m2mConfig = opts.m2mVerificationConfig;
    const FEDERATION_OPS = new Set([
        '_service',
        '__ApolloGetServiceDefinition__',
        '_entities',
    ]);
    return {
        async requestDidStart() {
            return {
                // A) Controlla canExecute => didResolveOperation
                async didResolveOperation(rc) {
                    const headers = rc.request.http?.headers;
                    if (!headers)
                        return;
                    const opName = rc.operationName ?? rc.operation?.name?.value ?? 'UnnamedOperation';
                    // Rimuovi “__users__0” e simili
                    const baseOpName = opName.replace(/__\w+__\d+$/, '');
                    // Se Federation => bypass
                    if (FEDERATION_OPS.has(opName))
                        return;
                    const authHeader = headers.get('authorization') || '';
                    if (authHeader.toLowerCase().startsWith('bearer ')) {
                        // => M2M
                        if (!m2mConfig) {
                            throw new Error('Bearer token ma manca m2mVerificationConfig');
                        }
                        const token = authHeader.split(' ')[1];
                        await verifyM2MToken(token, m2mConfig);
                        return;
                    }
                    // Altrimenti => x-user-groups
                    const rawGroups = headers.get('x-user-groups');
                    if (!rawGroups) {
                        throw new Error(`[GrantsPlugin] Nessun token M2M e nessun x-user-groups => denied (op=${opName})`);
                    }
                    const groups = parseGroups(rawGroups);
                    if (!groups.length) {
                        throw new Error(`[GrantsPlugin] x-user-groups vuoto => denied.`);
                    }
                    // check canExecute
                    let canExe = false;
                    try {
                        canExe = await Promise.any(groups.map(g => checkCanExecute(opts.grantsClient, g, baseOpName)));
                    }
                    catch {
                        canExe = false;
                    }
                    if (!canExe) {
                        throw new Error(`[GrantsPlugin] Operazione "${baseOpName}" non consentita per i gruppi [${groups.join(',')}]`);
                    }
                },
                // B) field-level filtering => willSendResponse
                async willSendResponse(rc) {
                    if (rc.response.body.kind !== 'single')
                        return;
                    const data = rc.response.body.singleResult.data;
                    if (!data)
                        return;
                    const headers = rc.request.http?.headers;
                    if (!headers)
                        return;
                    const opName = rc.operationName ?? rc.operation?.name?.value ?? 'UnnamedOperation';
                    if (FEDERATION_OPS.has(opName))
                        return;
                    // Se Bearer M2M => skip filtering
                    const authHeader = headers.get('authorization') || '';
                    if (authHeader.toLowerCase().startsWith('bearer '))
                        return;
                    // Altrimenti => x-user-groups
                    const rawGroups = headers.get('x-user-groups');
                    if (!rawGroups)
                        return; // skip
                    const groups = parseGroups(rawGroups);
                    if (!groups.length)
                        return;
                    // Prepara la "allowedMap" per ogni typename
                    // Ad esempio: { "Group": Set(...) , "Permission": Set(...), ... }
                    // e un "defaultAllowed" vuoto => { }
                    const allowedMap = {};
                    const defaultAllowed = new Set();
                    // 1) Per ogni typename definito in "entityNameMap"
                    //    Carichiamo i fieldPaths in union (tra i groupIds)
                    for (const typename of Object.keys(opts.entityNameMap)) {
                        const entityName = opts.entityNameMap[typename];
                        // costruiamo la union di fieldPaths "viewable" per tutti i groupIds
                        const unionFields = new Set();
                        for (const gId of groups) {
                            const partial = await fetchViewable(opts.grantsClient, gId, entityName);
                            partial.forEach(f => unionFields.add(f));
                        }
                        allowedMap[typename] = unionFields;
                    }
                    // 2) Rimuovi i campi
                    removeDisallowedMultiEntity(data, allowedMap, defaultAllowed);
                },
            };
        },
    };
}
