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
export interface GrantsAuthPluginOptions {
    grantsClient: GrantsClientLike;
    entityName: string;
    parseGroupIds?: (raw?: string | null) => string[];
    m2mVerificationConfig?: M2MVerificationConfig;
}
export declare function createGrantsAuthorizationPlugin(opts: GrantsAuthPluginOptions): ApolloServerPlugin<BaseContext>;
