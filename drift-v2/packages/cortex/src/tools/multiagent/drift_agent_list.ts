/**
 * drift_agent_list — List all registered agents.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftAgentList(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_agent_list",
    description:
      "List all registered agents, optionally filtered by status " +
      "(active, idle, deregistered).",
    inputSchema: {
      type: "object",
      properties: {
        status_filter: {
          type: "string",
          enum: ["active", "idle", "deregistered"],
          description: "Optional status filter.",
        },
      },
    },
    handler: async (args) => {
      const agents = await client.listAgents(args.status_filter as string | undefined);
      return { agents, count: agents.length };
    },
  };
}
