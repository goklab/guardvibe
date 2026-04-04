import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ToolDefinition } from "./types.js";

/**
 * Register a new-style ToolDefinition with the MCP server.
 * Adapter layer — new tools use ToolDefinition, old tools stay as-is.
 */
export function registerTool(
  server: McpServer,
  tool: ToolDefinition,
): void {
  server.tool(
    tool.name,
    tool.description,
    tool.schema,
    tool.handler as any,
  );
}
