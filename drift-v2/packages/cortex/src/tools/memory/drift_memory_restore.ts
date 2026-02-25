/**
 * drift_memory_restore — Restore an archived memory.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftMemoryRestore(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_memory_restore",
    description:
      "Restore a previously archived memory back to active status.",
    inputSchema: {
      type: "object",
      properties: {
        memory_id: {
          type: "string",
          description: "ID of the archived memory to restore.",
        },
      },
      required: ["memory_id"],
    },
    handler: async (args) => {
      const memoryId = args.memory_id as string;
      if (!memoryId || memoryId.trim().length === 0) {
        throw new Error("memory_id is required and cannot be empty.");
      }
      await client.memoryRestore(memoryId);
      return { memory_id: memoryId, status: "restored" };
    },
  };
}
