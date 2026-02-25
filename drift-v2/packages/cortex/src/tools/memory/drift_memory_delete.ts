/**
 * drift_memory_delete — Soft delete (archive) with audit trail.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftMemoryDelete(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_memory_delete",
    description:
      "Soft-delete a memory by archiving it. The memory is preserved for audit " +
      "but excluded from search results.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Memory UUID to archive." },
        hard_delete: {
          type: "boolean",
          description: "If true, permanently delete instead of archiving. Default false.",
        },
      },
      required: ["id"],
    },
    handler: async (args) => {
      const id = args.id as string;
      if (args.hard_delete) {
        await client.memoryDelete(id);
        return { id, status: "deleted" };
      }
      await client.memoryArchive(id);
      return { id, status: "archived" };
    },
  };
}
