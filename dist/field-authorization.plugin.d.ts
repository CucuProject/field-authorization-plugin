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
 * Mappa: “__typename => nome usato su DB grants”
 *
 * Esempio:
 * ```ts
 * entityNameMap: {
 *   User: "User",
 *   Group: "Group",
 *   // ...
 * }
 * ```
 */
export interface MultiEntityGrantsOptions {
    grantsClient: GrantsClientLike;
    entityNameMap: Record<string, string>;
    parseGroupIds?: (raw?: string | null) => string[];
    m2mVerificationConfig?: M2MVerificationConfig;
    /** Se true, logga debug */
    debug?: boolean;
}
export declare function createMultiEntityGrantsPlugin(opts: MultiEntityGrantsOptions): ApolloServerPlugin<BaseContext>;
