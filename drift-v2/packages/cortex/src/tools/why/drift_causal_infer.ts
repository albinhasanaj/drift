/**
 * drift_causal_infer — Infer causal relationship between two memories.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftCausalInfer(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_causal_infer",
    description:
      "Infer a causal relationship between two memories. Returns strength, " +
      "suggested relation type, and whether it exceeds the threshold.",
    inputSchema: {
      type: "object",
      properties: {
        source_memory_id: {
          type: "string",
          description: "ID of the source memory.",
        },
        target_memory_id: {
          type: "string",
          description: "ID of the target memory.",
        },
      },
      required: ["source_memory_id", "target_memory_id"],
    },
    handler: async (args) => {
      const sourceId = args.source_memory_id as string;
      const targetId = args.target_memory_id as string;
      if (!sourceId || !targetId) {
        throw new Error("Both source_memory_id and target_memory_id are required.");
      }
      const [source, target] = await Promise.all([
        client.memoryGet(sourceId),
        client.memoryGet(targetId),
      ]);
      return client.causalInfer(source, target);
    },
  };
}
