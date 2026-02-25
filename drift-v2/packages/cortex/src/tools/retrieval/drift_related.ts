/**
 * drift_related — Find related memories by entity links.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftRelated(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_related",
    description:
      "Find memories related to a given memory via causal graph traversal. " +
      "Returns connected memories with path strength scores.",
    inputSchema: {
      type: "object",
      properties: {
        memory_id: { type: "string", description: "Memory UUID to find relations for." },
      },
      required: ["memory_id"],
    },
    handler: async (args) => {
      const result = await client.causalTraverse(args.memory_id as string);
      return {
        origin_id: result.origin_id,
        related_count: result.nodes.length,
        nodes: result.nodes,
      };
    },
  };
}
