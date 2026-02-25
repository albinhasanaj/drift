/**
 * drift_temporal_causal — Temporal causal graph traversal.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

const VALID_DIRECTIONS = ["forward", "backward", "both"];

export function driftTemporalCausal(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_temporal_causal",
    description:
      "Traverse the causal graph as it existed at a specific point in time. " +
      "Directions: forward, backward, both.",
    inputSchema: {
      type: "object",
      properties: {
        memory_id: {
          type: "string",
          description: "Starting memory ID.",
        },
        as_of: {
          type: "string",
          description: "ISO 8601 timestamp — causal graph state at this time.",
        },
        direction: {
          type: "string",
          enum: VALID_DIRECTIONS,
          description: "Traversal direction. Default: 'both'.",
        },
        depth: {
          type: "number",
          description: "Maximum traversal depth. Default: 5.",
        },
      },
      required: ["memory_id", "as_of"],
    },
    handler: async (args) => {
      const memoryId = args.memory_id as string;
      const asOf = args.as_of as string;
      const direction = (args.direction as string) ?? "both";
      const depth = (args.depth as number) ?? 5;
      if (!VALID_DIRECTIONS.includes(direction)) {
        throw new Error(`Invalid direction: '${direction}'. Valid: ${VALID_DIRECTIONS.join(", ")}`);
      }
      return client.queryTemporalCausal(memoryId, asOf, direction, depth);
    },
  };
}
