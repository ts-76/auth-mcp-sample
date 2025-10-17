import OAuthProvider from '@cloudflare/workers-oauth-provider';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { McpAgent } from 'agents/mcp';
import { registerTools } from './mcp/tools';
import { handleAccessRequest } from './auth/access-handler';
import type { Props } from './auth/workers-oauth-utils';

export class MyMCP extends McpAgent<Env, Record<string, never>, Props> {
    declare env: Env;
    declare props?: Props;

    server = new McpServer({
        name: 'my-mcp-server',
        version: '1.0.0',
    });

    async init() {
        registerTools(this.server, this.env);
    }
}

async function handleMcpRequest(req: Request, env: Env, ctx: ExecutionContext) {
    const { pathname } = new URL(req.url);
    if (pathname === '/mcp') {
        return MyMCP.serve('/mcp').fetch(req, env, ctx);
    }
    return new Response('Not found', { status: 404 });
}

export default new OAuthProvider({
    apiHandler: { fetch: handleMcpRequest as any },
    apiRoute: ['/mcp'],
    authorizeEndpoint: '/authorize',
    clientRegistrationEndpoint: '/register',
    defaultHandler: { fetch: handleAccessRequest as any },
    tokenEndpoint: '/token',
});
