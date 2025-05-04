import { ApolloServerPlugin, BaseContext } from '@apollo/server';
import { Observable } from 'rxjs';
export interface GrantsClientLike {
    send<R = any, D = any>(pattern: any, data: D): Observable<R>;
}
export interface M2MVerificationConfig {
    jwksUri: string;
    issuer: string;
    audience: string;
    allowedAlgos?: string[];
}
export interface GrantsAuthPluginOptions {
    grantsClient: GrantsClientLike;
    entityName: string;
    /**
     * Funzione per parsare l’header “x-user-groups” (di default, split su virgola).
     */
    parseGroupIds?: (raw?: string | null) => string[];
    /**
     * Se definito, useremo questi parametri per validare via JWT RS256
     * le richieste con “Authorization: Bearer <token>”.
     */
    m2mVerificationConfig?: M2MVerificationConfig;
}
export declare function createGrantsAuthorizationPlugin(opts: GrantsAuthPluginOptions): ApolloServerPlugin<BaseContext>;
