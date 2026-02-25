/**
 * drift_memory_list — List memories with filters (type, importance, date).
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition, MemoryType } from "../../bridge/types.js";

export function driftMemoryList(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_memory_list",
    description:
      "List memories with optional type filter. Returns all memories if no filter specified.",
    inputSchema: {
      type: "object",
      properties: {
        memory_type: {
          type: "string",
          description: "Filter by memory type. Omit to list all.",
        },
      },
    },
    handler: async (args) => {
      const memories = await client.memoryList(args.memory_type as MemoryType | undefined);
      return { count: memories.length, memories };
    },
  };
}
