/**
 * drift_cortex_reembed — Trigger re-embedding pipeline.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftCortexReembed(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_cortex_reembed",
    description:
      "Trigger re-embedding for memories whose embeddings may be stale. " +
      "Useful after model upgrades or content changes.",
    inputSchema: {
      type: "object",
      properties: {
        memory_type: {
          type: "string",
          description: "Re-embed only this type. Omit for all.",
        },
      },
    },
    handler: async (args) => {
      // E-01: Call the real reembed NAPI binding which iterates memories,
      // regenerates embeddings via the configured provider chain, and
      // stores them in the embeddings table.
      const result = await client.reembed(args.memory_type as string | undefined);
      return result;
    },
  };
}
