/**
 * Streamable HTTP transport — secondary MCP transport for Docker/containerized deployments.
 *
 * Uses HTTP with Server-Sent Events for streaming responses.
 * This transport is used when the MCP server runs in a container
 * and clients connect over the network.
 */

import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';

export interface HttpTransportOptions {
  /** Path prefix for the MCP endpoint (default: '/mcp'). */
  path?: string;
  /** Session ID header name. */
  sessionIdHeader?: string;
}

/**
 * Create a Streamable HTTP transport for the MCP server.
 */
export function createHttpTransport(
  _options?: HttpTransportOptions,
): StreamableHTTPServerTransport {
  return new StreamableHTTPServerTransport({
    sessionIdGenerator: () => crypto.randomUUID(),
    onsessioninitialized: (_sessionId) => {
      // Session tracking can be added here
    },
  });
}
