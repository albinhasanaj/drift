/**
 * drift_cloud_status — Get cloud sync status (cortex + data pipeline).
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftCloudStatus(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_cloud_status",
    description:
      "Get cloud sync status — cortex online/offline state plus data pipeline sync status, " +
      "last sync time, row count, and cursor positions.",
    inputSchema: {
      type: "object",
      properties: {},
    },
    handler: async () => {
      const cortexStatus = await client.cloudStatus();

      let pipelineStatus: Record<string, unknown> = { available: false };
      try {
        const { isLoggedIn, CLOUD_CONFIG_PATH } = await import("@drift/core/cloud");
        const { readFile } = await import("node:fs/promises");
        const { join } = await import("node:path");
        const { homedir } = await import("node:os");

        const loggedIn = await isLoggedIn();
        const configPath = join(homedir(), CLOUD_CONFIG_PATH);
        const statePath = join(homedir(), ".drift/cloud-sync-state.json");

        let config = null;
        try { config = JSON.parse(await readFile(configPath, "utf-8")); } catch { /* */ }

        let syncState = null;
        try { syncState = JSON.parse(await readFile(statePath, "utf-8")); } catch { /* */ }

        pipelineStatus = {
          available: true,
          authenticated: loggedIn,
          configured: config !== null,
          projectId: config?.projectId ?? null,
          lastSyncAt: syncState?.lastSyncAt ?? null,
          lastSyncRowCount: syncState?.lastSyncRowCount ?? 0,
          cursors: syncState ? {
            drift: syncState.driftCursor,
            bridge: syncState.bridgeCursor,
            cortex: syncState.cortexCursor,
          } : null,
        };
      } catch {
        // @drift/core/cloud not available
      }

      return { cortex: cortexStatus, dataPipeline: pipelineStatus };
    },
  };
}
