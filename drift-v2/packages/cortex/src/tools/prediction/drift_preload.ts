/**
 * drift_preload — Manual preload for specific file/pattern.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftPreload(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_preload",
    description:
      "Manually preload predicted memories into cache for specific files. " +
      "Reduces latency for subsequent retrieval.",
    inputSchema: {
      type: "object",
      properties: {
        active_files: {
          type: "array",
          items: { type: "string" },
          description: "Files to preload memories for.",
        },
      },
    },
    handler: async (args) => {
      return client.preload(args.active_files as string[] | undefined);
    },
  };
}
