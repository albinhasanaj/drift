/**
 * drift_view_list — List all materialized temporal views.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftViewList(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_view_list",
    description:
      "List all materialized temporal views.",
    inputSchema: {
      type: "object",
      properties: {},
    },
    handler: async () => {
      const views = await client.listMaterializedViews();
      return { views, count: views.length };
    },
  };
}
