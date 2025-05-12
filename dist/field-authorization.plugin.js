"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createMultiEntityGrantsPlugin = createMultiEntityGrantsPlugin;
const common_1 = require("@nestjs/common");
const jsonwebtoken_1 = require("jsonwebtoken");
const jwks_rsa_1 = __importDefault(require("jwks-rsa"));
const rxjs_1 = require("rxjs");
/* -------------------------------------------------------------------------
 * 2) Helpers
 * ----------------------------------------------------------------------- */
/** parse x-user-groups di default */
function defaultParseGroups(raw) {
    return raw
        ? raw.split(',').map(s => s.trim()).filter(Boolean)
        : [];
}
/** Verifica se groupId ha `canExecute=true` per operation=opName */
async function checkCanExecute(client, groupId, opName, logger, debug) {
    if (debug)
        logger.debug(`checkCanExecute => groupId="${groupId}", opName="${opName}"`);
    try {
        const list = await (0, rxjs_1.lastValueFrom)(client.send('FIND_OP_PERMISSIONS_BY_GROUP', { groupId }));
        const found = list.some(p => p.operationName === opName && p.canExecute);
        if (debug) {
            logger.debug(`... groupId="${groupId}", opName="${opName}" => canExecute=${found}`);
        }
        return found;
    }
    catch (err) {
        if (debug) {
            logger.debug(`... checkCanExecute => catch => ${err instanceof Error ? err.message : err}`);
        }
        return false;
    }
}
/** Carica i fieldPaths “viewable” da DB grants, per (groupId, entityName). */
async function fetchViewable(client, groupId, entityName, logger, debug) {
    if (debug) {
        logger.debug(`fetchViewable => groupId="${groupId}", entityName="${entityName}"`);
    }
    try {
        const list = await (0, rxjs_1.lastValueFrom)(client.send('FIND_PERMISSIONS_BY_GROUP', { groupId, entityName }));
        const viewable = list.filter(p => p.canView).map(p => p.fieldPath);
        if (debug) {
            logger.debug(`... groupId="${groupId}", entityName="${entityName}" => viewable: [${viewable.join(', ')}]`);
        }
        return new Set(viewable);
    }
    catch (err) {
        if (debug) {
            logger.debug(`... fetchViewable => catch => ${err instanceof Error ? err.message : err}`);
        }
        return new Set();
    }
}
/**
 * Rimuove il root field (es. "findAllUsers") se presente come primo
 * segmento. Esempio: "findAllUsers.authData.name" => "authData.name"
 */
function stripRootSegment(fullPath, rootFieldNames) {
    const parts = fullPath.split('.');
    // se la prima parte è inclusa nel set => rimuovila
    if (parts.length > 1 && rootFieldNames.has(parts[0])) {
        parts.shift();
    }
    return parts.join('.');
}
/**
 * Rimuove i campi non consentiti da `obj`.
 * - allowedMap[typename] = set di fieldPaths (es: "authData.name", "authData.email", ...)
 * - defaultAllowed è un set vuoto (di solito)
 * - rootFieldNames => set dei fieldName top-level (es. "findAllUsers")
 * - currentTypename => se l'oggetto non ha __typename, usiamo questo fallback
 */
function removeDisallowedMultiEntity(obj, allowedMap, defaultAllowed, rootFieldNames, logger, debug, currentTypename, path = '') {
    if (!obj || typeof obj !== 'object')
        return;
    // (A) Se array => ricorsione su each
    if (Array.isArray(obj)) {
        for (const item of obj) {
            removeDisallowedMultiEntity(item, allowedMap, defaultAllowed, rootFieldNames, logger, debug, currentTypename, path);
        }
        return;
    }
    // (B) Leggi (o eredita) il typename
    const ownTypename = obj.__typename;
    const typename = ownTypename || currentTypename;
    // se esiste typename in mappa => usalo, altrimenti => default
    const isKnownEntity = typename && allowedMap[typename];
    const setToUse = isKnownEntity ? allowedMap[typename] : defaultAllowed;
    // (C) Itera i field
    for (const fieldKey of Object.keys(obj)) {
        // mantieni _id
        if (fieldKey === '_id')
            continue;
        const subPath = path ? `${path}.${fieldKey}` : fieldKey;
        const val = obj[fieldKey];
        if (val && typeof val === 'object') {
            // ricorsione => se l'oggetto child non ha __typename, erediterà `typename`
            removeDisallowedMultiEntity(val, allowedMap, defaultAllowed, rootFieldNames, logger, debug, typename, subPath);
            // se il child risulta vuoto => rimuoviamo
            if (Object.keys(val).length === 0) {
                delete obj[fieldKey];
            }
        }
        else {
            // normal field => verifichiamo se è consentito
            // 1) rimuovo root field => "findAllUsers" -> "authData.name"
            const finalPath = stripRootSegment(subPath, rootFieldNames);
            if (!setToUse.has(finalPath)) {
                if (debug) {
                    logger.debug(`remove => subPath="${subPath}" finalPath="${finalPath}" (typename="${typename}" known=${!!isKnownEntity})`);
                }
                delete obj[fieldKey];
            }
        }
    }
}
/** Verifica Bearer M2M, se serve. */
async function verifyM2MToken(token, cfg, logger, debug) {
    if (debug) {
        logger.debug(`verifyM2MToken => issuer="${cfg.issuer}", audience="${cfg.audience}"`);
    }
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
    const algos = (cfg.allowedAlgos || ['RS256']);
    return new Promise((resolve, reject) => {
        (0, jsonwebtoken_1.verify)(token, getKey, {
            audience: cfg.audience,
            issuer: cfg.issuer,
            algorithms: algos,
        }, (err) => {
            if (err) {
                if (debug)
                    logger.debug(`verifyM2MToken => error: ${err.message}`);
                return reject(err);
            }
            if (debug)
                logger.debug('verifyM2MToken => success');
            resolve();
        });
    });
}
/* -------------------------------------------------------------------------
 * 3) Plugin: createMultiEntityGrantsPlugin
 * ----------------------------------------------------------------------- */
function createMultiEntityGrantsPlugin(opts) {
    const logger = new common_1.Logger('MultiEntityPlugin');
    const debug = !!opts.debug;
    const parseGroups = opts.parseGroupIds ?? defaultParseGroups;
    const m2mConfig = opts.m2mVerificationConfig;
    // Per memorizzare i field root, es. "findAllUsers", "findOneUser", ...
    let rootFieldNames = new Set();
    // Se ci sono funzioni federation
    const FEDERATION_OPS = new Set([
        '_service',
        '__ApolloGetServiceDefinition__',
        '_entities',
    ]);
    if (debug) {
        logger.log('createMultiEntityGrantsPlugin => init');
        logger.debug(`entityNameMap => ${JSON.stringify(opts.entityNameMap, null, 2)}`);
    }
    return {
        async requestDidStart() {
            if (debug)
                logger.debug('requestDidStart');
            return {
                // A) Controllo canExecute => didResolveOperation
                async didResolveOperation(rc) {
                    if (debug)
                        logger.debug('didResolveOperation => start');
                    // 1) Estrai root field names
                    const selectionSet = rc.operation?.selectionSet;
                    if (selectionSet && Array.isArray(selectionSet.selections)) {
                        const topNames = [];
                        for (const sel of selectionSet.selections) {
                            if (sel.kind === 'Field' && sel.name?.value) {
                                topNames.push(sel.name.value);
                            }
                        }
                        rootFieldNames = new Set(topNames);
                        if (debug) {
                            logger.debug(`rootFieldNames => [${[...rootFieldNames].join(', ')}]`);
                        }
                    }
                    const rawOpName = rc.operationName ?? rc.operation?.name?.value ?? 'UnnamedOperation';
                    const opName = rawOpName.replace(/__\w+__\d+$/, '');
                    if (debug)
                        logger.debug(`rawOpName="${rawOpName}" => opName="${opName}"`);
                    if (FEDERATION_OPS.has(rawOpName)) {
                        if (debug)
                            logger.debug(`federation => bypass`);
                        return;
                    }
                    // 2) Legge Authorization
                    const headers = rc.request.http?.headers;
                    if (!headers)
                        return;
                    const authHeader = headers.get('authorization') || '';
                    if (debug)
                        logger.debug(`authHeader="${authHeader}"`);
                    if (authHeader.toLowerCase().startsWith('bearer ')) {
                        // => M2M
                        if (!m2mConfig) {
                            throw new Error('Bearer M2M token presente, ma manca m2mVerificationConfig');
                        }
                        const token = authHeader.split(' ')[1];
                        await verifyM2MToken(token, m2mConfig, logger, debug);
                        if (debug)
                            logger.debug('M2M => skip x-user-groups');
                        return;
                    }
                    // 3) Altrimenti => x-user-groups
                    const rawGroups = headers.get('x-user-groups');
                    if (!rawGroups) {
                        throw new Error(`[GrantsPlugin] Nessun M2M e nessun x-user-groups => denied (op=${opName})`);
                    }
                    const groups = parseGroups(rawGroups);
                    if (!groups.length) {
                        throw new Error(`[GrantsPlugin] x-user-groups vuoto => denied`);
                    }
                    if (debug) {
                        logger.debug(`groups => [${groups.join(', ')}]`);
                    }
                    // 4) Check canExecute
                    let canExe = false;
                    try {
                        canExe = await Promise.any(groups.map(g => checkCanExecute(opts.grantsClient, g, opName, logger, debug)));
                    }
                    catch (err) {
                        if (debug) {
                            logger.debug(`promise.any => catch => ${err instanceof Error ? err.message : err}`);
                        }
                        canExe = false;
                    }
                    if (!canExe) {
                        if (debug) {
                            logger.debug(`op="${opName}" => denied => groups=[${groups.join(',')}]`);
                        }
                        throw new Error(`[GrantsPlugin] Operazione "${opName}" non consentita per i gruppi [${groups.join(',')}]`);
                    }
                    if (debug)
                        logger.debug(`op="${opName}" => canExe= true => proceed`);
                },
                // B) Field-level => willSendResponse
                async willSendResponse(rc) {
                    if (debug)
                        logger.debug('willSendResponse => start');
                    if (rc.response.body.kind !== 'single')
                        return;
                    const data = rc.response.body.singleResult.data;
                    if (!data)
                        return;
                    const rawOpName = rc.operationName ?? rc.operation?.name?.value ?? 'UnnamedOperation';
                    if (FEDERATION_OPS.has(rawOpName)) {
                        if (debug)
                            logger.debug('federation => skip field filtering');
                        return;
                    }
                    // Se Bearer M2M => skip
                    const headers = rc.request.http?.headers;
                    if (!headers)
                        return;
                    const authHeader = headers.get('authorization') || '';
                    if (authHeader.toLowerCase().startsWith('bearer ')) {
                        if (debug)
                            logger.debug('M2M => skip field filtering');
                        return;
                    }
                    // x-user-groups
                    const rawGroups = headers.get('x-user-groups');
                    if (!rawGroups)
                        return;
                    const groups = parseGroups(rawGroups);
                    if (!groups.length)
                        return;
                    // 1) Prepara allowedMap
                    const allowedMap = {};
                    const defaultAllowed = new Set();
                    for (const typename of Object.keys(opts.entityNameMap)) {
                        const entityName = opts.entityNameMap[typename];
                        // union dei fieldPaths viewable per questi group
                        const union = new Set();
                        for (const gId of groups) {
                            const partial = await fetchViewable(opts.grantsClient, gId, entityName, logger, debug);
                            partial.forEach(f => union.add(f));
                        }
                        allowedMap[typename] = union;
                        if (debug) {
                            logger.debug(`typename="${typename}" => unionFields=[${[...union].join(', ')}]`);
                        }
                    }
                    // 2) Esegui filtering
                    if (debug) {
                        logger.debug(`Data BEFORE filtering:\n${JSON.stringify(data, null, 2)}`);
                    }
                    removeDisallowedMultiEntity(data, allowedMap, defaultAllowed, rootFieldNames, // passiamo i root fields
                    logger, debug, 
                    /* currentTypename */ undefined);
                    if (debug) {
                        logger.debug(`Data AFTER filtering:\n${JSON.stringify(data, null, 2)}`);
                    }
                },
            };
        },
    };
}
