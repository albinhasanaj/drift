/**
 * drift_memory_link — Link memory to pattern, constraint, file, or function.
 */

import type { CortexClient } from "../../bridge/client.js";
import type {
  BaseMemory,
  ConstraintLink,
  FileLink,
  FunctionLink,
  McpToolDefinition,
  PatternLink,
} from "../../bridge/types.js";

export function driftMemoryLink(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_memory_link",
    description:
      "Link a memory to a pattern, constraint, file, or function. " +
      "Specify exactly one of: pattern, constraint, file, or function.",
    inputSchema: {
      type: "object",
      properties: {
        memory_id: { type: "string", description: "Memory UUID to link." },
        link_type: {
          type: "string",
          enum: ["pattern", "constraint", "file", "function"],
          description: "Type of link to create.",
        },
        link_data: {
          type: "object",
          description: "Link data matching the link_type schema.",
        },
      },
      required: ["memory_id", "link_type", "link_data"],
    },
    handler: async (args) => {
      const memory = await client.memoryGet(args.memory_id as string);
      const updated: BaseMemory = { ...memory };

      switch (args.link_type as string) {
        case "pattern":
          updated.linked_patterns = [...memory.linked_patterns, args.link_data as PatternLink];
          break;
        case "constraint":
          updated.linked_constraints = [
            ...memory.linked_constraints,
            args.link_data as ConstraintLink,
          ];
          break;
        case "file":
          updated.linked_files = [...memory.linked_files, args.link_data as FileLink];
          break;
        case "function":
          updated.linked_functions = [...memory.linked_functions, args.link_data as FunctionLink];
          break;
        default:
          throw new Error(`Unknown link_type: ${args.link_type}`);
      }

      await client.memoryUpdate(updated);
      return { memory_id: args.memory_id, link_type: args.link_type, status: "linked" };
    },
  };
}
