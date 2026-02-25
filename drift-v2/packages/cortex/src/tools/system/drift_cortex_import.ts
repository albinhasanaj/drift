/**
 * drift_cortex_import — Import memories from JSON.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { BaseMemory, McpToolDefinition } from "../../bridge/types.js";

export function driftCortexImport(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_cortex_import",
    description:
      "Import memories from a JSON array. Each memory must be a valid BaseMemory object. " +
      "Skips duplicates by content hash.",
    inputSchema: {
      type: "object",
      properties: {
        memories: {
          type: "array",
          description: "Array of BaseMemory objects to import.",
        },
      },
      required: ["memories"],
    },
    handler: async (args) => {
      const memories = args.memories as BaseMemory[];
      let imported = 0;
      let skipped = 0;
      const errors: { id: string; error: string }[] = [];

      for (const memory of memories) {
        try {
          await client.memoryCreate(memory);
          imported++;
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          if (message.includes("UNIQUE") || message.includes("duplicate")) {
            skipped++;
          } else {
            errors.push({ id: memory.id, error: message });
          }
        }
      }

      return { imported, skipped, errors: errors.length, error_details: errors };
    },
  };
}
