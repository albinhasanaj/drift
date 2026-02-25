/**
 * drift_agent_retract — Retract (tombstone) a memory in a namespace.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftAgentRetract(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_agent_retract",
    description:
      "Retract a memory from a namespace. Adds a tombstone marker " +
      "for CRDT-safe distributed deletion.",
    inputSchema: {
      type: "object",
      properties: {
        memory_id: {
          type: "string",
          description: "ID of the memory to retract.",
        },
        namespace: {
          type: "string",
          description: "Namespace URI to retract from.",
        },
        agent_id: {
          type: "string",
          description: "Agent performing the retraction.",
        },
      },
      required: ["memory_id", "namespace", "agent_id"],
    },
    handler: async (args) => {
      const memoryId = args.memory_id as string;
      const namespace = args.namespace as string;
      const agentId = args.agent_id as string;
      if (!memoryId) throw new Error("memory_id is required.");
      if (!namespace) throw new Error("namespace is required.");
      if (!agentId) throw new Error("agent_id is required.");
      await client.retractMemory(memoryId, namespace, agentId);
      return { memory_id: memoryId, status: "retracted" };
    },
  };
}
