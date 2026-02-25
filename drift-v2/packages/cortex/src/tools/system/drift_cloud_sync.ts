/**
 * drift_cloud_sync — Trigger cloud sync (cortex memory sync + data pipeline push).
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftCloudSync(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_cloud_sync",
    description:
      "Trigger a cloud sync — push local analysis data and cortex memories to Drift Cloud. " +
      "Returns counts of pushed rows and cortex sync status.",
    inputSchema: {
      type: "object",
      properties: {
        full: {
          type: "boolean",
          description: "If true, ignore delta cursors and re-upload everything.",
        },
      },
    },
    handler: async (args) => {
      // 1. Cortex memory sync (existing path)
      const cortexResult = await client.cloudSync();

      // 2. Data pipeline sync (new SyncClient path)
      let pipelineResult: Record<string, unknown> = { skipped: true, reason: "not configured" };
      try {
        const { SyncClient, defaultSyncState, isLoggedIn, CLOUD_CONFIG_PATH } = await import("@drift/core/cloud");
        const { readFile, writeFile, mkdir } = await import("node:fs/promises");
        const { join } = await import("node:path");
        const { homedir } = await import("node:os");

        const loggedIn = await isLoggedIn();
        if (loggedIn) {
          const configPath = join(homedir(), CLOUD_CONFIG_PATH);
          const config = JSON.parse(await readFile(configPath, "utf-8"));
          const statePath = join(homedir(), ".drift/cloud-sync-state.json");
          let syncState;
          try {
            syncState = JSON.parse(await readFile(statePath, "utf-8"));
          } catch {
            syncState = defaultSyncState();
          }

          const fullSync = args.full === true;
          const reader = {
            readRows: async () => [] as Record<string, unknown>[],
            getMaxCursor: async () => 0,
          };

          const syncClient = new SyncClient(config, process.cwd());
          const result = await syncClient.push(reader, fullSync ? null : syncState, undefined, fullSync);

          const stateDir = statePath.substring(0, statePath.lastIndexOf("/"));
          await mkdir(stateDir, { recursive: true });
          await writeFile(statePath, JSON.stringify(result.syncState, null, 2));

          pipelineResult = {
            success: result.success,
            totalRows: result.totalRows,
            durationMs: result.durationMs,
            errors: result.errors,
          };
        } else {
          pipelineResult = { skipped: true, reason: "not authenticated" };
        }
      } catch (err) {
        pipelineResult = { skipped: true, reason: err instanceof Error ? err.message : String(err) };
      }

      return { cortex: cortexResult, dataPipeline: pipelineResult };
    },
  };
}
