import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerListObjectsTool } from './list_objects.js';
export function registerTools(mcpServer: McpServer, env: Env) {
    registerListObjectsTool(mcpServer, env);
}
