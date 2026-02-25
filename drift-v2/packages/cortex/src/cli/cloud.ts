/**
 * cloud — Cloud sync subcommands.
 *
 * Wires the data pipeline SyncClient (Phase 3) into the cortex CLI.
 * `drift cortex cloud sync` triggers both cortex memory sync AND data pipeline push.
 */

import type { CortexClient } from "../bridge/client.js";

export async function cloudCommand(
  client: CortexClient,
  sub: string,
  flags: Record<string, string>,
): Promise<void> {
  switch (sub) {
    case "sync": {
      // 1. Cortex memory sync (existing NAPI path)
      const cortexResult = await client.cloudSync();
      console.log("Cortex memory sync:", JSON.stringify(cortexResult, null, 2));

      // 2. Data pipeline sync (new SyncClient path)
      await runDataPipelineSync(flags);
      break;
    }
    case "status": {
      // Cortex cloud status
      const cortexStatus = await client.cloudStatus();

      // Data pipeline status
      const pipelineStatus = await getDataPipelineStatus();

      console.log(JSON.stringify({
        cortex: cortexStatus,
        dataPipeline: pipelineStatus,
      }, null, 2));
      break;
    }
    case "resolve": {
      const memoryId = flags.memory;
      const resolution = flags.resolution;
      if (!memoryId || !resolution) {
        console.error("  Error: cloud resolve requires --memory <id> --resolution <strategy>");
        process.exit(1);
      }
      const result = await client.cloudResolveConflict(memoryId, resolution);
      console.log(JSON.stringify(result, null, 2));
      break;
    }
    default:
      console.error(`  Unknown cloud subcommand: ${sub}. Valid: sync, status, resolve`);
      process.exit(1);
  }
}

/**
 * Run the data pipeline sync using SyncClient from @drift/core/cloud.
 * Dynamically imports to avoid hard dependency when cloud is not configured.
 */
async function runDataPipelineSync(flags: Record<string, string>): Promise<void> {
  try {
    const { SyncClient, defaultSyncState, isLoggedIn, CLOUD_CONFIG_PATH } = await import("@drift/core/cloud");
    const { readFile, writeFile, mkdir } = await import("node:fs/promises");
    const { join } = await import("node:path");
    const { homedir } = await import("node:os");

    const loggedIn = await isLoggedIn();
    if (!loggedIn) {
      console.log("Data pipeline: skipped (not authenticated — run `drift cloud login`)");
      return;
    }

    const configPath = join(homedir(), CLOUD_CONFIG_PATH);
    let config;
    try {
      config = JSON.parse(await readFile(configPath, "utf-8"));
    } catch {
      console.log("Data pipeline: skipped (no cloud config found)");
      return;
    }

    const statePath = join(homedir(), ".drift/cloud-sync-state.json");
    let syncState;
    try {
      syncState = JSON.parse(await readFile(statePath, "utf-8"));
    } catch {
      syncState = defaultSyncState();
    }

    const fullSync = flags.full === "true";
    const projectRoot = process.cwd();

    // Stub reader — actual NAPI bindings will be wired in Phase 6 Rust work
    const reader = {
      readRows: async (_table: string, _db: string, _afterCursor?: number) => {
        return [] as Record<string, unknown>[];
      },
      getMaxCursor: async (_db: string) => 0,
    };

    const syncClient = new SyncClient(config, projectRoot);
    const result = await syncClient.push(
      reader,
      fullSync ? null : syncState,
      (progress: { currentTableIndex: number; totalTables: number; table: string; rowsUploaded: number; totalRows: number }) => {
        process.stdout.write(
          `  [${progress.currentTableIndex + 1}/${progress.totalTables}] ${progress.table}: ${progress.rowsUploaded}/${progress.totalRows}\r`
        );
      },
      fullSync,
    );

    // Persist sync state
    const stateDir = statePath.substring(0, statePath.lastIndexOf("/"));
    await mkdir(stateDir, { recursive: true });
    await writeFile(statePath, JSON.stringify(result.syncState, null, 2));

    console.log(`\nData pipeline: ${result.success ? "success" : "failed"} — ${result.totalRows} rows in ${result.durationMs}ms`);
    if (result.errors.length > 0) {
      for (const err of result.errors) {
        console.error(`  ${err.table}: ${err.message}`);
      }
    }
  } catch (err) {
    console.log(`Data pipeline: skipped (${err instanceof Error ? err.message : String(err)})`);
  }
}

/**
 * Read data pipeline status from local sync state file.
 */
async function getDataPipelineStatus(): Promise<Record<string, unknown>> {
  try {
    const { isLoggedIn, CLOUD_CONFIG_PATH } = await import("@drift/core/cloud");
    const { readFile } = await import("node:fs/promises");
    const { join } = await import("node:path");
    const { homedir } = await import("node:os");

    const loggedIn = await isLoggedIn();
    const configPath = join(homedir(), CLOUD_CONFIG_PATH);
    const statePath = join(homedir(), ".drift/cloud-sync-state.json");

    let config = null;
    try {
      config = JSON.parse(await readFile(configPath, "utf-8"));
    } catch {
      // Not configured
    }

    let syncState = null;
    try {
      syncState = JSON.parse(await readFile(statePath, "utf-8"));
    } catch {
      // No sync state yet
    }

    return {
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
    return { available: false, reason: "@drift/core/cloud not available" };
  }
}
