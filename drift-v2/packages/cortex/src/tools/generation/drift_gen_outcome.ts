/**
 * drift_gen_outcome — Track generation outcome (accepted/rejected).
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftGenOutcome(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_gen_outcome",
    description:
      "Track whether a generation using retrieved memories was useful. " +
      "Feeds into the learning loop to improve future retrieval.",
    inputSchema: {
      type: "object",
      properties: {
        memory_ids: {
          type: "array",
          items: { type: "string" },
          description: "Memory IDs used in the generation.",
        },
        was_useful: {
          type: "boolean",
          description: "Whether the generation was accepted/useful.",
        },
        session_id: { type: "string", description: "Session ID for tracking." },
      },
      required: ["memory_ids", "was_useful"],
    },
    handler: async (args) => {
      await client.trackOutcome(
        args.memory_ids as string[],
        args.was_useful as boolean,
        args.session_id as string | undefined,
      );
      return { status: "tracked", memory_count: (args.memory_ids as string[]).length };
    },
  };
}
