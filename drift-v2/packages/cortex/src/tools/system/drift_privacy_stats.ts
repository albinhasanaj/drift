/**
 * drift_privacy_stats — Get privacy pattern failure statistics.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftPrivacyStats(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_privacy_stats",
    description:
      "Get privacy pattern failure statistics. Shows which sanitization " +
      "patterns have failed and their error details.",
    inputSchema: {
      type: "object",
      properties: {},
    },
    handler: async () => {
      return client.patternStats();
    },
  };
}
