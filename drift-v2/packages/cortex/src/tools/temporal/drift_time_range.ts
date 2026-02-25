/**
 * drift_time_range — Query memories valid during a time range.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

const VALID_MODES = ["overlaps", "contains", "started_during", "ended_during"];

export function driftTimeRange(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_time_range",
    description:
      "Query memories valid during a time range. Modes: overlaps, contains, " +
      "started_during, ended_during.",
    inputSchema: {
      type: "object",
      properties: {
        from: {
          type: "string",
          description: "ISO 8601 start timestamp.",
        },
        to: {
          type: "string",
          description: "ISO 8601 end timestamp.",
        },
        mode: {
          type: "string",
          enum: VALID_MODES,
          description: "Range query mode. Default: 'overlaps'.",
        },
      },
      required: ["from", "to"],
    },
    handler: async (args) => {
      const from = args.from as string;
      const to = args.to as string;
      const mode = (args.mode as string) ?? "overlaps";
      if (!VALID_MODES.includes(mode)) {
        throw new Error(`Invalid mode: '${mode}'. Valid: ${VALID_MODES.join(", ")}`);
      }
      const memories = await client.queryRange(from, to, mode);
      return { memories, count: memories.length };
    },
  };
}
