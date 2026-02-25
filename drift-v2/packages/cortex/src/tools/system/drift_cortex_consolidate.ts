/**
 * drift_cortex_consolidate — Manual consolidation trigger.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition, MemoryType } from "../../bridge/types.js";

export function driftCortexConsolidate(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_cortex_consolidate",
    description:
      "Manually trigger memory consolidation. Clusters episodic memories " +
      "into semantic knowledge with quality metrics.",
    inputSchema: {
      type: "object",
      properties: {
        memory_type: {
          type: "string",
          description: "Memory type to consolidate. Default: episodic.",
        },
      },
    },
    handler: async (args) => {
      return client.consolidate(args.memory_type as MemoryType | undefined);
    },
  };
}
