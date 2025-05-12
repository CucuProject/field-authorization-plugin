import { ApolloServerPlugin, BaseContext } from '@apollo/server';
export interface GrantsClientLike {
    send<R = any, D = any>(pattern: any, data: D): import('rxjs').Observable<R>;
}
/** Configurazione per la verifica M2M con Keycloak (o simili) */
export interface M2MVerificationConfig {
    jwksUri: string;
    issuer: string;
    audience: string | string[];
    allowedAlgos?: string[];
}
/**
 * Mappa: “__typename => nome usato su DB grants”.
 *
 * Esempio tipico:
 * ```ts
 * entityNameMap: {
 *   User: "User",
 *   Group: "Group",
 *   ...
 * }
 * ```
 * Se un child ha `__typename="AuthDataSchema"` e non è in `entityNameMap`, il plugin farà fallback al *typename* del genitore.
 */
export interface MultiEntityGrantsOptions {
    /** Client Proxy per contattare i pattern 'FIND_OP_PERMISSIONS_BY_GROUP', 'FIND_PERMISSIONS_BY_GROUP', ecc. */
    grantsClient: GrantsClientLike;
    /** Mappa i typenames => entityName su DB.  Esempio:  `User => "User"` */
    entityNameMap: Record<string, string>;
    /** Se devi parsare x-user-groups in modo custom */
    parseGroupIds?: (raw?: string | null) => string[];
    /** Se hai Keycloak M2M e vuoi validare i Bearer token “federation”. */
    m2mVerificationConfig?: M2MVerificationConfig;
    /**
     * Se true, abilita i log (livello debug).
     * Default = false
     */
    debug?: boolean;
    /**
     * Mappa opName => rootTypename, per sapere che il risultato di `findAllUsers` è un array di “User”.
     * Ad esempio:
     * ```ts
     * rootTypenameMap: {
     *   findAllUsers: "User",
     *   findOneUser:  "User",
     *   ...
     * }
     * ```
     */
    rootTypenameMap?: Record<string, string>;
}
export declare function createMultiEntityGrantsPlugin(opts: MultiEntityGrantsOptions): ApolloServerPlugin<BaseContext>;
