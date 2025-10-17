import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerListAllObjectsTool } from './list_objects';

export function registerTools(mcpServer: McpServer, env: Env) {
    registerListAllObjectsTool(mcpServer, env);
}
