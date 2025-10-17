import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

export function registerListAllObjectsTool(mcpServer: McpServer, env: Env) {
  mcpServer.registerTool(
    'list_all_objects',
    {
      title: 'List all objects in R2',
      description: 'MCP_RESOURCE_BUCKET から全オブジェクトのキーを列挙します。',
      annotations: { readOnlyHint: true, openWorldHint: false },
      inputSchema: {}, // 入力なし
      outputSchema: {
        keys: z.array(z.string()),
        count: z.number(),
      },
    },
    async () => {
      const { MCP_RESOURCE_BUCKET } = env;

      const keys: string[] = [];
      let cursor: string | undefined = undefined;

      do {
        const res = await MCP_RESOURCE_BUCKET.list({
          cursor,
          limit: 1000, // まとめて取得（API側の上限に依存）
        });

        for (const obj of res.objects) {
          if (obj.key) keys.push(obj.key);
        }

        cursor = res.truncated ? res.cursor : undefined;
      } while (cursor);

      const structuredContent = {
        keys,
        count: keys.length,
      } as const;

      return {
        content: [{ type: 'text', text: JSON.stringify(structuredContent) }],
        structuredContent,
      };
    }
  );
}