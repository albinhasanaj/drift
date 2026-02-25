/**
 * drift_memory_update — Update memory content or metadata.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { BaseMemory, McpToolDefinition } from "../../bridge/types.js";

export function driftMemoryUpdate(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_memory_update",
    description: "Update an existing memory's content, summary, tags, importance, or other fields.",
    inputSchema: {
      type: "object",
      properties: {
        memory: {
          type: "object",
          description: "Full BaseMemory object with updated fields. Must include 'id'.",
        },
      },
      required: ["memory"],
    },
    handler: async (args) => {
      const memory = args.memory as BaseMemory;
      await client.memoryUpdate(memory);
      return { id: memory.id, status: "updated" };
    },
  };
}
