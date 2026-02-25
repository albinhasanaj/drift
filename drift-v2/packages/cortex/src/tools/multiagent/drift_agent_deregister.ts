/**
 * drift_agent_deregister — Deregister an agent.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftAgentDeregister(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_agent_deregister",
    description:
      "Deregister an agent from the multi-agent memory system.",
    inputSchema: {
      type: "object",
      properties: {
        agent_id: {
          type: "string",
          description: "ID of the agent to deregister.",
        },
      },
      required: ["agent_id"],
    },
    handler: async (args) => {
      const agentId = args.agent_id as string;
      if (!agentId) throw new Error("agent_id is required.");
      await client.deregisterAgent(agentId);
      return { agent_id: agentId, status: "deregistered" };
    },
  };
}
