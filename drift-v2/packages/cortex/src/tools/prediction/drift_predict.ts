/**
 * drift_predict — Predictive preloading for current context.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftPredict(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_predict",
    description:
      "Predict which memories will be needed next based on active files, " +
      "recent queries, and current intent.",
    inputSchema: {
      type: "object",
      properties: {
        active_files: {
          type: "array",
          items: { type: "string" },
          description: "Currently open files.",
        },
        recent_queries: {
          type: "array",
          items: { type: "string" },
          description: "Recent search queries.",
        },
        current_intent: { type: "string", description: "Current detected intent." },
      },
    },
    handler: async (args) => {
      return client.predict(
        args.active_files as string[] | undefined,
        args.recent_queries as string[] | undefined,
        args.current_intent as string | undefined,
      );
    },
  };
}
