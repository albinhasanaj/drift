/**
 * drift_agent_sync — Sync memory state between two agents.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftAgentSync(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_agent_sync",
    description:
      "Synchronize memory state between two agents via delta sync. " +
      "Returns counts of applied and buffered deltas.",
    inputSchema: {
      type: "object",
      properties: {
        source_agent: {
          type: "string",
          description: "Source agent ID.",
        },
        target_agent: {
          type: "string",
          description: "Target agent ID.",
        },
      },
      required: ["source_agent", "target_agent"],
    },
    handler: async (args) => {
      const source = args.source_agent as string;
      const target = args.target_agent as string;
      if (!source) throw new Error("source_agent is required.");
      if (!target) throw new Error("target_agent is required.");
      return client.syncAgents(source, target);
    },
  };
}
