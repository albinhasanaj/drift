/**
 * drift_view_get — Get a materialized temporal view by label.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftViewGet(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_view_get",
    description:
      "Get a materialized temporal view by label. Returns null if not found.",
    inputSchema: {
      type: "object",
      properties: {
        label: {
          type: "string",
          description: "Label of the view to retrieve.",
        },
      },
      required: ["label"],
    },
    handler: async (args) => {
      const label = args.label as string;
      if (!label) throw new Error("label is required.");
      const view = await client.getMaterializedView(label);
      return view ?? { found: false, label };
    },
  };
}
