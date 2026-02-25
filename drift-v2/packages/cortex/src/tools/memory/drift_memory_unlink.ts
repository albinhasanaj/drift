/**
 * drift_memory_unlink — Remove a link from a memory.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { BaseMemory, McpToolDefinition } from "../../bridge/types.js";

export function driftMemoryUnlink(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_memory_unlink",
    description: "Remove a link from a memory by link type and identifier.",
    inputSchema: {
      type: "object",
      properties: {
        memory_id: { type: "string", description: "Memory UUID." },
        link_type: {
          type: "string",
          enum: ["pattern", "constraint", "file", "function"],
          description: "Type of link to remove.",
        },
        identifier: {
          type: "string",
          description:
            "Identifier to match: pattern_id, constraint_id, file_path, or function_name.",
        },
      },
      required: ["memory_id", "link_type", "identifier"],
    },
    handler: async (args) => {
      const memory = await client.memoryGet(args.memory_id as string);
      const id = args.identifier as string;
      const updated: BaseMemory = { ...memory };

      switch (args.link_type as string) {
        case "pattern":
          updated.linked_patterns = memory.linked_patterns.filter((l) => l.pattern_id !== id);
          break;
        case "constraint":
          updated.linked_constraints = memory.linked_constraints.filter(
            (l) => l.constraint_id !== id,
          );
          break;
        case "file":
          updated.linked_files = memory.linked_files.filter((l) => l.file_path !== id);
          break;
        case "function":
          updated.linked_functions = memory.linked_functions.filter((l) => l.function_name !== id);
          break;
        default:
          throw new Error(`Unknown link_type: ${args.link_type}`);
      }

      await client.memoryUpdate(updated);
      return { memory_id: args.memory_id, link_type: args.link_type, status: "unlinked" };
    },
  };
}
