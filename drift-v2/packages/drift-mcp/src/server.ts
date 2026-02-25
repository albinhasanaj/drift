/**
 * MCP Server — main server class.
 *
 * Sets up the MCP server with progressive disclosure:
 * - 4 registered tools (drift_status, drift_context, drift_scan, drift_tool)
 * - ~49 internal tools via drift_tool dynamic dispatch
 * - stdio transport (primary) + Streamable HTTP transport (secondary)
 * - MCP protocol compliant via @modelcontextprotocol/sdk
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import { registerTools } from './tools/index.js';
import { loadNapi } from './napi.js';
import { resolveProjectRoot } from '@drift/napi-contracts';
import type { McpConfig, InternalTool } from './types.js';
import { DEFAULT_MCP_CONFIG } from './types.js';
import { InfrastructureLayer } from './infrastructure/index.js';
import { initCortex, shutdownCortex } from './cortex.js';

export interface DriftMcpServer {
  /** The underlying MCP server instance. */
  server: McpServer;
  /** Internal tool catalog for drift_tool dispatch. */
  catalog: Map<string, InternalTool>;
  /** Infrastructure layer (cache, rate limiter, error handler, etc.). */
  infrastructure: InfrastructureLayer;
  /** Connect to a transport and start serving. */
  connect(transport: Transport): Promise<void>;
  /** Graceful shutdown. */
  close(): Promise<void>;
}

/**
 * Create and configure the Drift MCP server.
 *
 * @param config - Server configuration (transport, token limits, etc.)
 * @returns Configured server ready to connect to a transport
 */
export function createDriftMcpServer(
  config: Partial<McpConfig> = {},
): DriftMcpServer {
  const mergedConfig = { ...DEFAULT_MCP_CONFIG, ...config };
  const projectRoot = resolveProjectRoot(mergedConfig.projectRoot);

  // Initialize infrastructure layer
  const infrastructure = new InfrastructureLayer({
    projectRoot,
    maxResponseTokens: mergedConfig.maxResponseTokens,
  });

  // Initialize NAPI bindings
  const napi = loadNapi();
  try {
    napi.driftInitialize(undefined, projectRoot);
  } catch {
    // Non-fatal — NAPI may already be initialized or not available
  }

  // Initialize Cortex if enabled
  if (mergedConfig.cortexEnabled !== false) {
    const cortexDbPath = mergedConfig.cortexDbPath ?? '.cortex/cortex.db';
    initCortex(cortexDbPath).catch(() => {
      // Non-fatal — Cortex may not be available
    });
  }

  // Create MCP server
  const server = new McpServer({
    name: 'drift-analysis',
    version: '2.0.0',
  });

  // Register all tools (progressive disclosure) with infrastructure layer
  const catalog = registerTools(server, infrastructure);

  return {
    server,
    catalog,
    infrastructure,
    async connect(transport: Transport): Promise<void> {
      await server.connect(transport);
    },
    async close(): Promise<void> {
      try {
        await server.close();
      } finally {
        try {
          napi.driftShutdown();
        } catch {
          // Non-fatal
        }
        try {
          await shutdownCortex();
        } catch {
          // Non-fatal
        }
      }
    },
  };
}
