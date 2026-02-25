/**
 * drift_session_analytics — Get session analytics.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftSessionAnalytics(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_session_analytics",
    description:
      "Get analytics for a session — loaded memories, patterns, files, " +
      "tokens sent, and query counts.",
    inputSchema: {
      type: "object",
      properties: {
        session_id: {
          type: "string",
          description: "Session ID to get analytics for.",
        },
      },
      required: ["session_id"],
    },
    handler: async (args) => {
      const sessionId = args.session_id as string;
      if (!sessionId) throw new Error("session_id is required.");
      return client.sessionAnalytics(sessionId);
    },
  };
}
