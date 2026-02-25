/**
 * drift_feedback — Process user feedback (confirm/reject/modify).
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftFeedback(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_feedback",
    description:
      "Process user feedback on a memory. Positive feedback boosts confidence; " +
      "negative feedback triggers learning and potential correction.",
    inputSchema: {
      type: "object",
      properties: {
        memory_id: { type: "string", description: "Memory UUID to give feedback on." },
        feedback: { type: "string", description: "Feedback text." },
        is_positive: {
          type: "boolean",
          description: "True for confirmation, false for rejection.",
        },
      },
      required: ["memory_id", "feedback", "is_positive"],
    },
    handler: async (args) => {
      return client.processFeedback(
        args.memory_id as string,
        args.feedback as string,
        args.is_positive as boolean,
      );
    },
  };
}
