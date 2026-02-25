/**
 * drift_agent_namespace — Create a namespace.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

const VALID_SCOPES = ["agent", "team", "project"];

export function driftAgentNamespace(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_agent_namespace",
    description:
      "Create a new namespace for memory isolation. " +
      "Scopes: agent (private), team (shared), project (wide).",
    inputSchema: {
      type: "object",
      properties: {
        scope: {
          type: "string",
          enum: VALID_SCOPES,
          description: "Namespace scope: agent, team, or project.",
        },
        name: {
          type: "string",
          description: "Human-readable namespace name.",
        },
        owner: {
          type: "string",
          description: "Owner agent ID.",
        },
      },
      required: ["scope", "name", "owner"],
    },
    handler: async (args) => {
      const scope = args.scope as string;
      const name = args.name as string;
      const owner = args.owner as string;
      if (!VALID_SCOPES.includes(scope)) {
        throw new Error(`Invalid scope: '${scope}'. Valid: ${VALID_SCOPES.join(", ")}`);
      }
      if (!name) throw new Error("name is required.");
      if (!owner) throw new Error("owner is required.");
      const uri = await client.createNamespace(scope, name, owner);
      return { namespace_uri: uri };
    },
  };
}
