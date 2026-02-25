/**
 * drift_agent_register — Register a new agent in the multi-agent memory system.
 *
 * Creates a new agent with a unique ID, home namespace, and advertised capabilities.
 * The agent can then share memories, create projections, and participate in trust scoring.
 *
 * @example
 *   { "name": "code-reviewer", "capabilities": ["code_review", "testing"] }
 *   → { "agent": { "agent_id": "...", "name": "code-reviewer", "namespace": "agent://code-reviewer/", ... } }
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftAgentRegister(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_agent_register",
    description:
      "Register a new agent in the Cortex multi-agent memory system. " +
      "Each agent gets a unique ID, a home namespace, and can advertise capabilities. " +
      "Example: { \"name\": \"code-reviewer\", \"capabilities\": [\"code_review\"] }",
    inputSchema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description: "Human-readable agent name (e.g. 'code-reviewer', 'test-agent').",
        },
        capabilities: {
          type: "array",
          items: { type: "string" },
          description:
            "Capabilities this agent advertises (e.g. ['code_review', 'testing']). Defaults to [].",
        },
      },
      required: ["name"],
    },
    handler: async (args) => {
      const name = args.name as string | undefined;
      if (!name || name.trim().length === 0) {
        throw new Error("Agent name is required and cannot be empty.");
      }

      const capabilities = (args.capabilities as string[] | undefined) ?? [];
      for (const cap of capabilities) {
        if (typeof cap !== "string" || cap.trim().length === 0) {
          throw new Error(
            "Each capability must be a non-empty string. " +
              "Example: [\"code_review\", \"testing\"]",
          );
        }
      }

      try {
        const agent = await client.registerAgent(name.trim(), capabilities);
        return { agent };
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (message.includes("AlreadyRegistered")) {
          throw new Error(
            `An agent named '${name}' is already registered. ` +
              "Use 'drift cortex agents list' to see existing agents.",
          );
        }
        throw new Error(`Failed to register agent '${name}': ${message}`);
      }
    },
  };
}
