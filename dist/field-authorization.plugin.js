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
/** Verifica canExecute su un'operazione */
async function checkCanExecute(client, groupId, opName, logger, debug) {
    if (debug) {
        logger.debug(`checkCanExecute => groupId="${groupId}", opName="${opName}"`);
    }
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
/** Carica i fieldPaths “viewable” da DB grants (groupId, entityName). */
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
 * Se la prima parte del path corrisponde a un rootField (es. "findAllUsers"),
 * la rimuove. Esempio: "findAllUsers.authData.email" => "authData.email".
 */
function stripRootSegment(fullPath, rootFieldNames) {
    const parts = fullPath.split('.');
    if (parts.length > 1 && rootFieldNames.has(parts[0])) {
        parts.shift(); // toglie la parte iniziale (es. "findAllUsers")
    }
    return parts.join('.');
}
/**
 * Rimuove i campi non ammessi da `obj`.
 * - fallback: se child ha `__typename` sconosciuto, usiamo `parentTypename`.
 * - stripRootSegment: rimuove la parte "findAllUsers" se presente dal path.
 */
function removeDisallowedMultiEntity(obj, allowedMap, defaultAllowed, rootFieldNames, logger, debug, currentTypename, path = '') {
    if (!obj || typeof obj !== 'object')
        return;
    if (Array.isArray(obj)) {
        for (const item of obj) {
            removeDisallowedMultiEntity(item, allowedMap, defaultAllowed, rootFieldNames, logger, debug, currentTypename, path);
        }
        return;
    }
    // Leggiamo eventuale __typename
    const ownTypename = obj.__typename;
    // Se "ownTypename" non è in mappa => fallback a "currentTypename"
    let finalTypename = ownTypename && allowedMap[ownTypename]
        ? ownTypename
        : currentTypename;
    // Se non c'è, usiamo defaultAllowed
    const isKnownEntity = finalTypename && allowedMap[finalTypename];
    const setToUse = isKnownEntity ? allowedMap[finalTypename] : defaultAllowed;
    for (const fieldKey of Object.keys(obj)) {
        if (fieldKey === '_id') {
            // tieni _id
            continue;
        }
        const subPath = path ? `${path}.${fieldKey}` : fieldKey;
        const val = obj[fieldKey];
        if (val && typeof val === 'object') {
            removeDisallowedMultiEntity(val, allowedMap, defaultAllowed, rootFieldNames, logger, debug, finalTypename, // child eredita il typename dal parent se non ne ha uno suo
            subPath);
            if (Object.keys(val).length === 0) {
                delete obj[fieldKey];
            }
        }
        else {
            // E' un field "atomico"
            // Rimuovo l'eventuale rootSegment
            const finalPath = stripRootSegment(subPath, rootFieldNames);
            if (!setToUse.has(finalPath)) {
                if (debug) {
                    logger.debug(`remove => subPath="${subPath}" finalPath="${finalPath}" (typename="${finalTypename || 'N/A'}" known=${!!isKnownEntity})`);
                }
                delete obj[fieldKey];
            }
        }
    }
}
/**
 * Verifica Bearer M2M (Keycloak) => RS256
 */
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
            if (err) {
                return callback(err);
            }
            if (!key) {
                return callback(new Error(`No signing key for kid=${header.kid}`));
            }
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
                if (debug) {
                    logger.debug(`verifyM2MToken => error: ${err.message}`);
                }
                return reject(err);
            }
            if (debug) {
                logger.debug('verifyM2MToken => success');
            }
            resolve();
        });
    });
}
/* -------------------------------------------------------------------------
 * 3) Plugin “createMultiEntityGrantsPlugin”
 * ----------------------------------------------------------------------- */
function createMultiEntityGrantsPlugin(opts) {
    const logger = new common_1.Logger('MultiEntityPlugin');
    const debug = !!opts.debug;
    const parseGroups = opts.parseGroupIds ?? defaultParseGroups;
    const m2mConfig = opts.m2mVerificationConfig;
    // Federation
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
            // useremo queste var per passare info dal didResolveOperation al willSendResponse
            let rootFieldNames = new Set();
            let rootTypename;
            return {
                /* ===============================================================
                 * A) canExecute => didResolveOperation
                 * ============================================================= */
                async didResolveOperation(rc) {
                    if (debug)
                        logger.debug('didResolveOperation => start');
                    const rawOpName = rc.operationName ?? rc.operation?.name?.value ?? 'UnnamedOperation';
                    const opName = rawOpName.replace(/__\w+__\d+$/, '');
                    if (FEDERATION_OPS.has(rawOpName)) {
                        if (debug)
                            logger.debug('federation => bypass canExecute');
                        return;
                    }
                    // rootTypenameMap => se definito, associamo quell'opName a un typename
                    if (opts.rootTypenameMap && opts.rootTypenameMap[opName]) {
                        rootTypename = opts.rootTypenameMap[opName];
                        if (debug)
                            logger.debug(`opName="${opName}" => rootTypename="${rootTypename}"`);
                    }
                    // estraiamo i rootFieldNames dal selectionSet
                    const selectionSet = rc.operation?.selectionSet;
                    if (selectionSet && Array.isArray(selectionSet.selections)) {
                        const topNames = [];
                        for (const sel of selectionSet.selections) {
                            if (sel.kind === 'Field' && sel.name?.value) {
                                topNames.push(sel.name.value);
                            }
                        }
                        rootFieldNames = new Set(topNames);
                        if (debug && topNames.length) {
                            logger.debug(`rootFieldNames=[${topNames.join(', ')}]`);
                        }
                    }
                    const headers = rc.request.http?.headers;
                    if (!headers)
                        return;
                    const authHeader = headers.get('authorization') || '';
                    if (debug)
                        logger.debug(`authHeader="${authHeader}"`);
                    // 1) Bearer => M2M?
                    if (authHeader.toLowerCase().startsWith('bearer ')) {
                        if (!m2mConfig) {
                            throw new Error('Bearer M2M token presente, ma manca m2mVerificationConfig');
                        }
                        const token = authHeader.split(' ')[1];
                        await verifyM2MToken(token, m2mConfig, logger, debug);
                        if (debug)
                            logger.debug('M2M => skip x-user-groups');
                        return;
                    }
                    // 2) Altrimenti => x-user-groups
                    const rawGroups = headers.get('x-user-groups');
                    if (!rawGroups) {
                        throw new Error(`[GrantsPlugin] No M2M e no x-user-groups => denied (op=${opName})`);
                    }
                    const groups = parseGroups(rawGroups);
                    if (!groups.length) {
                        throw new Error(`[GrantsPlugin] x-user-groups vuoto => denied.`);
                    }
                    if (debug) {
                        logger.debug(`groups=[${groups.join(', ')}]`);
                    }
                    // check canExecute
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
                        if (debug)
                            logger.debug(`op="${opName}" => denied => groups=[${groups.join(',')}]`);
                        throw new Error(`[GrantsPlugin] Operazione "${opName}" non consentita per i gruppi [${groups.join(',')}]`);
                    }
                    if (debug)
                        logger.debug(`op="${opName}" => canExe= true => proceed`);
                },
                /* ===============================================================
                 * B) field-level => willSendResponse
                 * ============================================================= */
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
                    // Bearer M2M => skip
                    const headers = rc.request.http?.headers;
                    if (!headers)
                        return;
                    const authHeader = headers.get('authorization') || '';
                    if (authHeader.toLowerCase().startsWith('bearer ')) {
                        if (debug)
                            logger.debug('M2M => skip field filtering');
                        return;
                    }
                    // parse x-user-groups
                    const rawGroups = headers.get('x-user-groups');
                    if (!rawGroups)
                        return;
                    const groups = parseGroups(rawGroups);
                    if (!groups.length)
                        return;
                    // Creiamo la mappa “typename => setOf(fieldPaths)”
                    const allowedMap = {};
                    const defaultAllowed = new Set();
                    // Popoliamo i fieldPaths uniti
                    for (const typename of Object.keys(opts.entityNameMap)) {
                        const entityName = opts.entityNameMap[typename];
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
                    if (debug) {
                        logger.debug(`Data BEFORE filtering:\n${JSON.stringify(data, null, 2)}`);
                    }
                    // Se in didResolveOperation abbiamo impostato rootTypename
                    // (es. "User" per findAllUsers), lo passiamo
                    removeDisallowedMultiEntity(data, allowedMap, defaultAllowed, 
                    /* rootFieldNames= */ rootFieldNames, logger, debug, 
                    /* currentTypename= */ rootTypename);
                    if (debug) {
                        logger.debug(`Data AFTER filtering:\n${JSON.stringify(data, null, 2)}`);
                    }
                },
            };
        },
    };
}
