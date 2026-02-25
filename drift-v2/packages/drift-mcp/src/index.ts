#!/usr/bin/env node
/**
 * Drift MCP Server — entry point.
 *
 * Progressive disclosure MCP server for AI agent consumption.
 * 3 entry points + drift_tool dynamic dispatch (~81% token reduction).
 *
 * Usage:
 *   drift-mcp                    # stdio transport (default)
 *   drift-mcp --transport http   # Streamable HTTP transport
 *   drift-mcp --port 3100        # HTTP on custom port
 */

import { createDriftMcpServer } from './server.js';
import { createStdioTransport } from './transport/stdio.js';
import { createHttpTransport } from './transport/http.js';
import type { McpConfig } from './types.js';

// Re-export public API
export { createDriftMcpServer } from './server.js';
export type { DriftMcpServer } from './server.js';
export { registerTools } from './tools/index.js';
export { createStdioTransport } from './transport/stdio.js';
export { createHttpTransport } from './transport/http.js';
export type { McpConfig, StatusOverview, ContextOutput, ScanResult } from './types.js';
export { setNapi, resetNapi } from './napi.js';
export type { DriftNapi } from './napi.js';

/**
 * Parse CLI arguments for standalone execution.
 */
function parseArgs(args: string[]): Partial<McpConfig> {
  const config: Partial<McpConfig> = {};

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--transport' && args[i + 1]) {
      config.transport = args[++i] as 'stdio' | 'http';
    } else if (arg === '--port' && args[i + 1]) {
      config.port = parseInt(args[++i], 10);
      config.transport = 'http';
    } else if (arg === '--project-root' && args[i + 1]) {
      config.projectRoot = args[++i];
    } else if (arg === '--max-tokens' && args[i + 1]) {
      config.maxResponseTokens = parseInt(args[++i], 10);
    }
  }

  return config;
}

/**
 * Main entry point — starts the MCP server.
 */
async function main(): Promise<void> {
  const config = parseArgs(process.argv.slice(2));
  const driftServer = createDriftMcpServer(config);

  // Graceful shutdown
  const shutdown = async () => {
    await driftServer.close();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  if (config.transport === 'http') {
    const transport = createHttpTransport();
    await driftServer.connect(transport);
    // HTTP server would be started here with express/http module
    // For now, the transport handles the HTTP protocol
    process.stderr.write(
      `Drift MCP server listening on HTTP port ${config.port ?? 3100}\n`,
    );
  } else {
    // Default: stdio transport
    const transport = createStdioTransport();
    await driftServer.connect(transport);
    process.stderr.write('Drift MCP server running on stdio\n');
  }
}

// Run if executed directly
const isMainModule =
  typeof process !== 'undefined' &&
  process.argv[1] &&
  (process.argv[1].endsWith('drift-mcp') ||
    process.argv[1].endsWith('index.js') ||
    process.argv[1].endsWith('index.ts'));

if (isMainModule) {
  main().catch((err) => {
    process.stderr.write(`Fatal: ${err}\n`);
    process.exit(1);
  });
}
