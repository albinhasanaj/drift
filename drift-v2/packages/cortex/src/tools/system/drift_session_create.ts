/**
 * drift_session_create — Create a new session.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftSessionCreate(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_session_create",
    description:
      "Create a new Cortex session for tracking token usage and loaded memories.",
    inputSchema: {
      type: "object",
      properties: {
        session_id: {
          type: "string",
          description: "Optional session ID. Auto-generated if not provided.",
        },
      },
    },
    handler: async (args) => {
      const sessionId = await client.sessionCreate(args.session_id as string | undefined);
      return { session_id: sessionId };
    },
  };
}
