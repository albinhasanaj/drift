/**
 * drift_memory_get — Get memory by ID with full details.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftMemoryGet(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_memory_get",
    description: "Get a memory by its ID with full details including links and metadata.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Memory UUID." },
      },
      required: ["id"],
    },
    handler: async (args) => {
      return client.memoryGet(args.id as string);
    },
  };
}
