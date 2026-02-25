/**
 * drift_agent_provenance — Query the provenance chain for a memory.
 *
 * Returns the full chain of custody: who created it, who shared it, who validated it,
 * and the cumulative confidence through the chain. Optionally includes cross-agent trace.
 *
 * @example
 *   { "memory_id": "abc123", "max_depth": 5 }
 *   → { "provenance": { "memory_id": "abc123", "origin": { "type": "human" }, "chain": [...], "chain_confidence": 0.95 },
 *       "cross_agent_trace": { "path": [...] } }
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftAgentProvenance(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_agent_provenance",
    description:
      "Query the provenance chain for a memory — who created it, who shared it, " +
      "who validated it, and the cumulative confidence. Includes cross-agent trace " +
      "showing how knowledge flowed between agents. " +
      "Example: { \"memory_id\": \"abc123\", \"max_depth\": 5 }",
    inputSchema: {
      type: "object",
      properties: {
        memory_id: {
          type: "string",
          description: "UUID of the memory to trace.",
        },
        max_depth: {
          type: "number",
          description: "Maximum traversal depth for cross-agent trace. Default: 10.",
        },
      },
      required: ["memory_id"],
    },
    handler: async (args) => {
      const memoryId = args.memory_id as string | undefined;
      if (!memoryId || memoryId.trim().length === 0) {
        throw new Error("memory_id is required. Provide the UUID of the memory to trace.");
      }

      const maxDepth = (args.max_depth as number | undefined) ?? 10;
      if (maxDepth <= 0 || !Number.isInteger(maxDepth)) {
        throw new Error(
          `Invalid max_depth ${maxDepth}. Must be a positive integer. Default is 10.`,
        );
      }

      try {
        const [provenance, crossAgentTrace] = await Promise.all([
          client.getProvenance(memoryId),
          client.traceCrossAgent(memoryId, maxDepth),
        ]);

        if (!provenance) {
          throw new Error(
            `No provenance found for memory '${memoryId}'. ` +
              "The memory may not exist or may not have provenance tracking enabled.",
          );
        }

        return {
          provenance,
          cross_agent_trace:
            crossAgentTrace.path.length > 0 ? crossAgentTrace : undefined,
        };
      } catch (err) {
        if (err instanceof Error && err.message.startsWith("No provenance found")) {
          throw err;
        }
        const message = err instanceof Error ? err.message : String(err);
        if (message.includes("NotFound")) {
          throw new Error(
            `Memory '${memoryId}' not found. Use 'drift_memory_search' to find valid memory IDs.`,
          );
        }
        throw new Error(`Failed to query provenance: ${message}`);
      }
    },
  };
}
