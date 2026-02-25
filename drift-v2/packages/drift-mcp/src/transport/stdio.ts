/**
 * stdio transport — primary MCP transport.
 *
 * This is how most MCP clients (Claude Desktop, Cursor, Kiro, etc.) connect.
 * Uses stdin/stdout for JSON-RPC communication per MCP specification.
 */

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

/**
 * Create a stdio transport for the MCP server.
 */
export function createStdioTransport(): StdioServerTransport {
  return new StdioServerTransport();
}
