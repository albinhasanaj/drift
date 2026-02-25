/**
 * drift_intervention — "If we change X, what needs updating?"
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftIntervention(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_intervention",
    description:
      "Intervention analysis: if a memory is modified, which downstream " +
      "memories need updating? Shows the propagation path.",
    inputSchema: {
      type: "object",
      properties: {
        memory_id: {
          type: "string",
          description: "Memory UUID being modified.",
        },
      },
      required: ["memory_id"],
    },
    handler: async (args) => {
      const result = await client.causalIntervention(args.memory_id as string);
      return {
        modified_memory: args.memory_id,
        needs_update_count: result.nodes.length,
        needs_update: result.nodes,
      };
    },
  };
}
