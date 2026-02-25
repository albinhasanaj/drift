/**
 * drift_cortex_export — Export memories as JSON.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition, MemoryType } from "../../bridge/types.js";

export function driftCortexExport(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_cortex_export",
    description:
      "Export all memories (or filtered by type) as a JSON array. " +
      "Useful for backup, migration, or analysis.",
    inputSchema: {
      type: "object",
      properties: {
        memory_type: {
          type: "string",
          description: "Filter by memory type. Omit to export all.",
        },
      },
    },
    handler: async (args) => {
      const memories = await client.memoryList(args.memory_type as MemoryType | undefined);
      return {
        count: memories.length,
        exported_at: new Date().toISOString(),
        memories,
      };
    },
  };
}
