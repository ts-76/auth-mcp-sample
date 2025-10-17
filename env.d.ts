export {};

declare global {
    interface Env {
        OAUTH_KV: KVNamespace;
        ACCESS_CLIENT_ID: string;
        ACCESS_CLIENT_SECRET: string;
        ACCESS_TOKEN_URL: string;
        ACCESS_AUTHORIZATION_URL: string;
        ACCESS_JWKS_URL: string;
        COOKIE_ENCRYPTION_KEY: string;
        MCP_OBJECT: DurableObjectNamespace;
        MCP_RESOURCE_BUCKET: R2Bucket;
        AI: Ai;
    }
}
