/**
 * drift_gen_context — Build generation context with provenance.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftGenContext(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_gen_context",
    description:
      "Build a generation context with memories organized by budget allocation " +
      "and provenance tracking. Used before LLM generation.",
    inputSchema: {
      type: "object",
      properties: {
        focus: { type: "string", description: "Generation focus or prompt context." },
        active_files: {
          type: "array",
          items: { type: "string" },
          description: "Currently open files.",
        },
        budget: { type: "number", description: "Token budget. Default 4096." },
        sent_ids: {
          type: "array",
          items: { type: "string" },
          description: "Already-sent memory IDs.",
        },
      },
      required: ["focus"],
    },
    handler: async (args) => {
      return client.buildGenerationContext(
        args.focus as string,
        args.active_files as string[] | undefined,
        args.budget as number | undefined,
        args.sent_ids as string[] | undefined,
      );
    },
  };
}
