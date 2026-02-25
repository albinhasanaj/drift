/**
 * drift_agent_share — Share a memory to another namespace.
 *
 * Copies a memory into a target namespace with a provenance hop recording the share action.
 * Requires the sharing agent to have Share permission on the target namespace.
 *
 * @example
 *   { "memory_id": "abc123", "target_namespace": "team://backend/", "agent_id": "agent-alpha" }
 *   → { "success": true, "provenance_hop": { ... } }
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

const NAMESPACE_URI_PATTERN = /^(agent|team|project):\/\/.+\/$/;

export function driftAgentShare(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_agent_share",
    description:
      "Share a memory to another namespace. Creates a copy in the target namespace " +
      "with a provenance hop recording the share action. " +
      "Example: { \"memory_id\": \"abc123\", \"target_namespace\": \"team://backend/\", \"agent_id\": \"agent-1\" }",
    inputSchema: {
      type: "object",
      properties: {
        memory_id: {
          type: "string",
          description: "UUID of the memory to share.",
        },
        target_namespace: {
          type: "string",
          description:
            "Target namespace URI (e.g. 'team://backend/', 'project://myapp/').",
        },
        agent_id: {
          type: "string",
          description: "ID of the agent performing the share.",
        },
      },
      required: ["memory_id", "target_namespace", "agent_id"],
    },
    handler: async (args) => {
      const memoryId = args.memory_id as string | undefined;
      const targetNamespace = args.target_namespace as string | undefined;
      const agentId = args.agent_id as string | undefined;

      if (!memoryId || memoryId.trim().length === 0) {
        throw new Error("memory_id is required. Provide the UUID of the memory to share.");
      }
      if (!targetNamespace || targetNamespace.trim().length === 0) {
        throw new Error(
          "target_namespace is required. Use format: 'team://name/' or 'project://name/'.",
        );
      }
      if (!NAMESPACE_URI_PATTERN.test(targetNamespace)) {
        throw new Error(
          `Invalid namespace URI '${targetNamespace}'. ` +
            "Expected format: '{scope}://{name}/' where scope is agent, team, or project. " +
            "Example: 'team://backend/'",
        );
      }
      if (!agentId || agentId.trim().length === 0) {
        throw new Error("agent_id is required. Provide the ID of the agent performing the share.");
      }

      try {
        const provenanceHop = await client.shareMemory(memoryId, targetNamespace, agentId);
        return { success: true, provenance_hop: provenanceHop };
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (message.includes("PermissionDenied")) {
          throw new Error(
            `Agent '${agentId}' does not have Share permission on '${targetNamespace}'. ` +
              "Use 'drift cortex namespaces permissions' to check or grant permissions.",
          );
        }
        if (message.includes("NotFound")) {
          throw new Error(
            `Memory '${memoryId}' not found. Use 'drift_memory_search' to find valid memory IDs.`,
          );
        }
        throw new Error(`Failed to share memory: ${message}`);
      }
    },
  };
}
