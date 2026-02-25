/**
 * drift_cloud_resolve — Resolve a cloud sync conflict.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

const VALID_RESOLUTIONS = ["local_wins", "remote_wins", "last_write_wins", "crdt_merge", "manual"];

export function driftCloudResolve(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_cloud_resolve",
    description:
      "Resolve a cloud sync conflict for a specific memory. " +
      "Strategies: local_wins, remote_wins, last_write_wins, crdt_merge, manual.",
    inputSchema: {
      type: "object",
      properties: {
        memory_id: {
          type: "string",
          description: "ID of the conflicting memory.",
        },
        resolution: {
          type: "string",
          enum: VALID_RESOLUTIONS,
          description: "Conflict resolution strategy.",
        },
      },
      required: ["memory_id", "resolution"],
    },
    handler: async (args) => {
      const memoryId = args.memory_id as string;
      const resolution = args.resolution as string;
      if (!memoryId) throw new Error("memory_id is required.");
      if (!VALID_RESOLUTIONS.includes(resolution)) {
        throw new Error(`Invalid resolution: '${resolution}'. Valid: ${VALID_RESOLUTIONS.join(", ")}`);
      }
      return client.cloudResolveConflict(memoryId, resolution);
    },
  };
}
