/**
 * drift_time_travel — Point-in-time knowledge query using bitemporal semantics.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftTimeTravel(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_time_travel",
    description:
      "Query memories as they existed at a specific point in time. " +
      "Uses bitemporal semantics: system_time controls what was recorded, " +
      "valid_time controls what was true at that time.",
    inputSchema: {
      type: "object",
      properties: {
        system_time: {
          type: "string",
          description: "ISO 8601 timestamp — what was recorded by this time.",
        },
        valid_time: {
          type: "string",
          description: "ISO 8601 timestamp — what was true at this time.",
        },
        filter: {
          type: "string",
          description:
            "Optional JSON filter: { memory_types?: string[], tags?: string[], linked_files?: string[] }",
        },
      },
      required: ["system_time", "valid_time"],
    },
    handler: async (args) => {
      const start = Date.now();
      const memories = await client.queryAsOf(
        args.system_time as string,
        args.valid_time as string,
        args.filter as string | undefined,
      );
      const elapsed = Date.now() - start;
      return {
        memories,
        count: memories.length,
        query_time_ms: elapsed,
      };
    },
  };
}
