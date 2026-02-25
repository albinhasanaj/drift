/**
 * drift_agent_trust — Query trust scores between agents.
 *
 * Returns trust scores including overall trust, per-domain trust, and the evidence
 * breakdown (validated, contradicted, useful, total). If target_agent is omitted,
 * returns trust scores for all agents the given agent has interacted with.
 *
 * @example
 *   { "agent_id": "agent-alpha", "target_agent": "agent-beta" }
 *   → { "trust": { "overall_trust": 0.85, "domain_trust": { "code_review": 0.9 }, ... } }
 *
 *   { "agent_id": "agent-alpha" }
 *   → { "trust": [ { "target_agent": "agent-beta", "overall_trust": 0.85, ... }, ... ] }
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftAgentTrust(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_agent_trust",
    description:
      "Query trust scores between agents. Returns overall trust, per-domain trust, " +
      "and evidence breakdown. If target_agent is omitted, returns all trust records " +
      "for the given agent. " +
      "Example: { \"agent_id\": \"agent-alpha\", \"target_agent\": \"agent-beta\" }",
    inputSchema: {
      type: "object",
      properties: {
        agent_id: {
          type: "string",
          description: "ID of the agent whose trust scores to query.",
        },
        target_agent: {
          type: "string",
          description:
            "Optional: specific target agent to get trust for. If omitted, returns all trust records.",
        },
      },
      required: ["agent_id"],
    },
    handler: async (args) => {
      const agentId = args.agent_id as string | undefined;
      if (!agentId || agentId.trim().length === 0) {
        throw new Error(
          "agent_id is required. Use 'drift cortex agents list' to see registered agents.",
        );
      }

      const targetAgent = args.target_agent as string | undefined;

      try {
        const trust = await client.getTrust(agentId, targetAgent ?? undefined);
        return { trust };
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (message.includes("AgentNotFound")) {
          const which = targetAgent
            ? `Agent '${targetAgent}' not found.`
            : `Agent '${agentId}' not found.`;
          throw new Error(
            `${which} Use 'drift cortex agents list' to see registered agents.`,
          );
        }
        throw new Error(`Failed to query trust scores: ${message}`);
      }
    },
  };
}
