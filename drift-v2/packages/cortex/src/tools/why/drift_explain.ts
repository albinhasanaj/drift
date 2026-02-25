/**
 * drift_explain — Explain a single memory with its causal chain.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftExplain(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_explain",
    description:
      "Explain a single memory with its full causal chain — what caused it, " +
      "what it caused, and the narrative connecting them.",
    inputSchema: {
      type: "object",
      properties: {
        memory_id: { type: "string", description: "Memory UUID to explain." },
      },
      required: ["memory_id"],
    },
    handler: async (args) => {
      const memoryId = args.memory_id as string;
      const [memory, narrative, traversal] = await Promise.all([
        client.memoryGet(memoryId),
        client.causalGetWhy(memoryId),
        client.causalTraverse(memoryId),
      ]);
      return { memory, narrative, causal_graph: traversal };
    },
  };
}
