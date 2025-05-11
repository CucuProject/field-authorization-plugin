import { ApolloServerPlugin, BaseContext } from '@apollo/server';
import { Observable } from 'rxjs';
export interface GrantsClientLike {
    send<R = any, D = any>(pattern: any, data: D): Observable<R>;
}
export interface M2MVerificationConfig {
    jwksUri: string;
    issuer: string;
    audience: string | string[];
    allowedAlgos?: string[];
}
/**
 * Mappa per la field-level security:
 *   __typename => nomeEntityUsatoSuDB
 *
 * Esempio:
 *   entityNameMap: {
 *     User: "User",
 *     Group: "Group",
 *     Permission: "Permission",
 *   }
 */
export interface MultiEntityGrantsOptions {
    grantsClient: GrantsClientLike;
    entityNameMap: Record<string, string>;
    parseGroupIds?: (raw?: string | null) => string[];
    m2mVerificationConfig?: M2MVerificationConfig;
    /**
     * Se true, abilita i log (livello debug).
     * Default = false
     */
    debug?: boolean;
}
export declare function createMultiEntityGrantsPlugin(opts: MultiEntityGrantsOptions): ApolloServerPlugin<BaseContext>;
