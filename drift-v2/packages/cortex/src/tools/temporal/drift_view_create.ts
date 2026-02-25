/**
 * drift_view_create — Create a materialized temporal view.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftViewCreate(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_view_create",
    description:
      "Create a materialized view of the knowledge base at a specific point in time. " +
      "Useful for snapshotting before major changes.",
    inputSchema: {
      type: "object",
      properties: {
        label: {
          type: "string",
          description: "Human-readable label for the view (e.g. 'pre-refactor').",
        },
        timestamp: {
          type: "string",
          description: "ISO 8601 timestamp to snapshot at.",
        },
      },
      required: ["label", "timestamp"],
    },
    handler: async (args) => {
      const label = args.label as string;
      const timestamp = args.timestamp as string;
      if (!label) throw new Error("label is required.");
      if (!timestamp) throw new Error("timestamp is required.");
      return client.createMaterializedView(label, timestamp);
    },
  };
}
