/**
 * drift_why — Full "why" context with causal narratives.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftWhy(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_why",
    description:
      "Get a full causal narrative explaining 'why' for a memory. " +
      "Includes causal chains, evidence references, and confidence levels.",
    inputSchema: {
      type: "object",
      properties: {
        memory_id: { type: "string", description: "Memory UUID to explain." },
      },
      required: ["memory_id"],
    },
    handler: async (args) => {
      return client.causalGetWhy(args.memory_id as string);
    },
  };
}
