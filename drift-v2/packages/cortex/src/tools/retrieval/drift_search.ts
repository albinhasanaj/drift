/**
 * drift_search — Direct hybrid search (no orchestration).
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftSearch(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_search",
    description:
      "Direct hybrid search combining full-text and semantic similarity. " +
      "Returns compressed memories ranked by relevance.",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "Search query." },
        budget: { type: "number", description: "Token budget. Default 4096." },
      },
      required: ["query"],
    },
    handler: async (args) => {
      const results = await client.search(args.query as string, args.budget as number | undefined);
      return { count: results.length, memories: results };
    },
  };
}
