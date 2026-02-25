/**
 * drift_counterfactual — "What if we hadn't done X?"
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftCounterfactual(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_counterfactual",
    description:
      "Counterfactual analysis: explore what would be different if a memory " +
      "didn't exist. Shows downstream effects and affected memories.",
    inputSchema: {
      type: "object",
      properties: {
        memory_id: {
          type: "string",
          description: "Memory UUID to remove in the counterfactual.",
        },
      },
      required: ["memory_id"],
    },
    handler: async (args) => {
      const result = await client.causalCounterfactual(args.memory_id as string);
      return {
        removed_memory: args.memory_id,
        affected_count: result.nodes.length,
        affected_memories: result.nodes,
      };
    },
  };
}
