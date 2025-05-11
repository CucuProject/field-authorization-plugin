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
 * L’opzione cruciale: "entityNameMap" => { "Group": "Group", "Permission": "Permission", ... }
 * dove la *chiave* è il __typename e il *valore* è come vogliamo che l’entità si chiami in DB grants.
 */
export interface MultiEntityGrantsOptions {
    grantsClient: GrantsClientLike;
    entityNameMap: Record<string, string>;
    parseGroupIds?: (raw?: string | null) => string[];
    m2mVerificationConfig?: M2MVerificationConfig;
}
export declare function createMultiEntityGrantsPlugin(opts: MultiEntityGrantsOptions): ApolloServerPlugin<BaseContext>;
