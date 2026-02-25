/**
 * drift_memory_search — Hybrid search with session deduplication.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftMemorySearch(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_memory_search",
    description:
      "Search memories using hybrid full-text + semantic search with session deduplication.",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "Search query." },
        limit: { type: "number", description: "Max results. Default 20." },
      },
      required: ["query"],
    },
    handler: async (args) => {
      const results = await client.memorySearch(
        args.query as string,
        args.limit as number | undefined,
      );
      return { count: results.length, memories: results };
    },
  };
}
