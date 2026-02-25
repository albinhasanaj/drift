/**
 * drift_cortex_metrics — Consolidation quality + retrieval metrics.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftCortexMetrics(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_cortex_metrics",
    description:
      "Get detailed metrics including consolidation quality, retrieval stats, " +
      "cache performance, and system health indicators.",
    inputSchema: {
      type: "object",
      properties: {},
    },
    handler: async () => {
      const [consolidation, health, cache] = await Promise.all([
        client.consolidationMetrics(),
        client.healthMetrics(),
        client.cacheStats(),
      ]);
      return { consolidation, health, prediction_cache: cache };
    },
  };
}
