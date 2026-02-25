/**
 * drift_cortex_status — Health dashboard.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftCortexStatus(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_cortex_status",
    description:
      "Get a comprehensive health dashboard for the Cortex system. " +
      "Shows overall status, subsystem health, and key metrics.",
    inputSchema: {
      type: "object",
      properties: {},
    },
    handler: async () => {
      const [health, consolidation, degradations] = await Promise.all([
        client.healthReport(),
        client.consolidationStatus(),
        client.degradations(),
      ]);
      return {
        health,
        consolidation,
        degradation_count: degradations.length,
        degradations,
      };
    },
  };
}
