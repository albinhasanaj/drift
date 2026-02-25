/**
 * drift_context — Orchestrated context retrieval with budget allocation.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition, RetrievalContext } from "../../bridge/types.js";

export function driftContext(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_context",
    description:
      "Retrieve memories orchestrated by intent, compressed to fit a token budget. " +
      "Handles session dedup, importance ranking, and budget packing.",
    inputSchema: {
      type: "object",
      properties: {
        focus: { type: "string", description: "Query or focus area." },
        active_files: {
          type: "array",
          items: { type: "string" },
          description: "Currently open files for proximity boosting.",
        },
        sent_ids: {
          type: "array",
          items: { type: "string" },
          description: "Memory IDs already sent this session (for dedup).",
        },
        budget: { type: "number", description: "Token budget. Default 4096." },
      },
      required: ["focus"],
    },
    handler: async (args) => {
      const context: RetrievalContext = {
        focus: args.focus as string,
        intent: null,
        active_files: (args.active_files as string[]) ?? [],
        budget: (args.budget as number) ?? 4096,
        sent_ids: (args.sent_ids as string[]) ?? [],
      };
      const results = await client.retrieve(context, context.budget);
      return { count: results.length, memories: results };
    },
  };
}
