/**
 * drift_session_get — Get session context.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftSessionGet(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_session_get",
    description:
      "Get a session's context — sent memory IDs, token usage, budget.",
    inputSchema: {
      type: "object",
      properties: {
        session_id: {
          type: "string",
          description: "Session ID to retrieve.",
        },
      },
      required: ["session_id"],
    },
    handler: async (args) => {
      const sessionId = args.session_id as string;
      if (!sessionId) throw new Error("session_id is required.");
      return client.sessionGet(sessionId);
    },
  };
}
