/**
 * drift_agent_get — Get an agent by ID.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftAgentGet(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_agent_get",
    description:
      "Get an agent's registration details by ID. Returns null if not found.",
    inputSchema: {
      type: "object",
      properties: {
        agent_id: {
          type: "string",
          description: "ID of the agent to retrieve.",
        },
      },
      required: ["agent_id"],
    },
    handler: async (args) => {
      const agentId = args.agent_id as string;
      if (!agentId) throw new Error("agent_id is required.");
      const agent = await client.getAgent(agentId);
      return agent ?? { found: false, agent_id: agentId };
    },
  };
}
