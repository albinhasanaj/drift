/**
 * drift cloud — Cloud sync commands: login, push, status, logout.
 */

import type { Command } from 'commander';
import { loadNapi } from '../napi.js';
import { formatOutput, type OutputFormat } from '../output/index.js';

export function registerCloudCommand(program: Command): void {
  const cloud = program
    .command('cloud')
    .description('Cloud sync operations. Run `drift cloud login` to get started.');

  // ── drift cloud login ──
  cloud
    .command('login')
    .description('Authenticate with Drift Cloud using email + password')
    .requiredOption('--url <url>', 'Supabase project URL')
    .requiredOption('--anon-key <key>', 'Supabase anon key')
    .requiredOption('--email <email>', 'Login email')
    .requiredOption('--password <password>', 'Login password')
    .option('--project-id <id>', 'Cloud project UUID')
    .option('--tenant-id <id>', 'Cloud tenant UUID')
    .action(async (opts: {
      url: string;
      anonKey: string;
      email: string;
      password: string;
      projectId?: string;
      tenantId?: string;
    }) => {
      try {
        // Dynamic import to avoid loading cloud module when not needed
        const { saveCredentials } = await import('@drift/core/cloud');
        const { CLOUD_CONFIG_PATH } = await import('@drift/core/cloud');
        const { writeFile, mkdir } = await import('node:fs/promises');
        const { join } = await import('node:path');
        const { homedir } = await import('node:os');

        // Authenticate with Supabase Auth
        const response = await fetch(`${opts.url}/auth/v1/token?grant_type=password`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'apikey': opts.anonKey,
          },
          body: JSON.stringify({
            email: opts.email,
            password: opts.password,
          }),
        });

        if (!response.ok) {
          const body = await response.text().catch(() => '');
          process.stderr.write(`Login failed (${response.status}): ${body}\n`);
          process.exitCode = 1;
          return;
        }

        const data = await response.json() as {
          access_token: string;
          refresh_token: string;
          expires_in: number;
          user: { id: string };
        };

        // Save credentials
        await saveCredentials({
          accessToken: data.access_token,
          refreshToken: data.refresh_token,
          expiresAt: new Date(Date.now() + data.expires_in * 1000).toISOString(),
        });

        // Save cloud config if project/tenant provided
        if (opts.projectId && opts.tenantId) {
          const configPath = join(homedir(), CLOUD_CONFIG_PATH);
          const dir = configPath.substring(0, configPath.lastIndexOf('/'));
          await mkdir(dir, { recursive: true });
          await writeFile(configPath, JSON.stringify({
            supabaseUrl: opts.url,
            supabaseAnonKey: opts.anonKey,
            projectId: opts.projectId,
            tenantId: opts.tenantId,
          }, null, 2), { mode: 0o600 });
        }

        process.stdout.write(`✓ Logged in as ${opts.email}\n`);
        if (opts.projectId) {
          process.stdout.write(`  Project: ${opts.projectId}\n`);
        }
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 2;
      }
    });

  // ── drift cloud push ──
  cloud
    .command('push')
    .description('Sync local analysis data to Drift Cloud')
    .option('-f, --format <format>', 'Output format: table, json', 'table')
    .option('--full', 'Full sync (ignore delta cursors)', false)
    .option('-q, --quiet', 'Suppress progress output')
    .action(async (opts: { format: OutputFormat; full: boolean; quiet?: boolean }) => {
      try {
        const { SyncClient, defaultSyncState } = await import('@drift/core/cloud');
        const { readFile, writeFile, mkdir } = await import('node:fs/promises');
        const { join } = await import('node:path');
        const { homedir } = await import('node:os');
        const { CLOUD_CONFIG_PATH } = await import('@drift/core/cloud');

        // Load cloud config
        const configPath = join(homedir(), CLOUD_CONFIG_PATH);
        let config;
        try {
          const raw = await readFile(configPath, 'utf-8');
          config = JSON.parse(raw);
        } catch {
          process.stderr.write('Not configured. Run `drift cloud login` first.\n');
          process.exitCode = 1;
          return;
        }

        // Load sync state
        const statePath = join(homedir(), '.drift/cloud-sync-state.json');
        let syncState;
        try {
          const raw = await readFile(statePath, 'utf-8');
          syncState = JSON.parse(raw);
        } catch {
          syncState = opts.full ? null : defaultSyncState();
        }

        const napi = loadNapi();
        const projectRoot = process.cwd();

        // Create a LocalRowReader backed by NAPI
        // Note: driftCloudReadRows and driftCloudMaxCursor are Phase 6 stubs
        const napiAny = napi as unknown as Record<string, Function>;
        const reader = {
          readRows: async (table: string, db: string, afterCursor?: number) => {
            try {
              if (typeof napiAny.driftCloudReadRows !== 'function') return [];
              return napiAny.driftCloudReadRows(projectRoot, table, db, afterCursor ?? 0) as Record<string, unknown>[];
            } catch {
              return [];
            }
          },
          getMaxCursor: async (db: string) => {
            try {
              if (typeof napiAny.driftCloudMaxCursor !== 'function') return 0;
              return napiAny.driftCloudMaxCursor(projectRoot, db) as number;
            } catch {
              return 0;
            }
          },
        };

        const client = new SyncClient(config, projectRoot);

        if (!opts.quiet) {
          process.stdout.write('Syncing to Drift Cloud...\n');
        }

        const result = await client.push(
          reader,
          syncState,
          opts.quiet ? undefined : (progress: { currentTableIndex: number; totalTables: number; table: string; rowsUploaded: number; totalRows: number }) => {
            process.stdout.write(
              `  [${progress.currentTableIndex + 1}/${progress.totalTables}] ${progress.table}: ${progress.rowsUploaded}/${progress.totalRows} rows\r`
            );
          },
          opts.full,
        );

        // Save updated sync state
        const stateDir = statePath.substring(0, statePath.lastIndexOf('/'));
        await mkdir(stateDir, { recursive: true });
        await writeFile(statePath, JSON.stringify(result.syncState, null, 2));

        if (!opts.quiet) {
          process.stdout.write('\n');
        }

        if (result.success) {
          const summary = {
            success: true,
            totalRows: result.totalRows,
            durationMs: result.durationMs,
            tableCounts: result.tableCounts,
            cursors: result.syncState,
          };
          if (!opts.quiet) {
            process.stdout.write(formatOutput(summary, opts.format));
          }
        } else {
          process.stderr.write(`Sync completed with ${result.errors.length} error(s):\n`);
          for (const err of result.errors) {
            process.stderr.write(`  ${err.table}: ${err.message}\n`);
          }
          process.exitCode = 1;
        }
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 2;
      }
    });

  // ── drift cloud status ──
  cloud
    .command('status')
    .description('Show cloud sync status — last sync time, cursors, config')
    .option('-f, --format <format>', 'Output format: table, json', 'table')
    .action(async (opts: { format: OutputFormat }) => {
      try {
        const { isLoggedIn } = await import('@drift/core/cloud');
        const { CLOUD_CONFIG_PATH } = await import('@drift/core/cloud');
        const { readFile } = await import('node:fs/promises');
        const { join } = await import('node:path');
        const { homedir } = await import('node:os');

        const loggedIn = await isLoggedIn();
        const configPath = join(homedir(), CLOUD_CONFIG_PATH);
        const statePath = join(homedir(), '.drift/cloud-sync-state.json');

        let config = null;
        try {
          config = JSON.parse(await readFile(configPath, 'utf-8'));
        } catch {
          // Not configured
        }

        if (!config && !loggedIn) {
          process.stderr.write(
            'Cloud sync is not configured.\n\n' +
            'To set up cloud sync:\n' +
            '  1. drift cloud login          — authenticate with your account\n' +
            '  2. drift cloud configure      — set up project sync\n' +
            '  3. drift cloud status         — verify configuration\n\n' +
            'Configuration is stored in:\n' +
            `  Config:      ~/.drift/cloud-config.json\n` +
            `  Credentials: ~/.drift/cloud-credentials.json\n\n` +
            'Note: Cloud features are optional. Drift works fully offline.\n',
          );
          process.exitCode = 1;
          return;
        }

        let syncState = null;
        try {
          syncState = JSON.parse(await readFile(statePath, 'utf-8'));
        } catch {
          // No sync state yet
        }

        const status = {
          authenticated: loggedIn,
          configured: config !== null,
          supabaseUrl: config?.supabaseUrl ?? null,
          projectId: config?.projectId ?? null,
          tenantId: config?.tenantId ?? null,
          lastSyncAt: syncState?.lastSyncAt ?? null,
          lastSyncRowCount: syncState?.lastSyncRowCount ?? 0,
          cursors: syncState ? {
            drift: syncState.driftCursor,
            bridge: syncState.bridgeCursor,
            cortex: syncState.cortexCursor,
          } : null,
        };

        process.stdout.write(formatOutput(status, opts.format));
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 2;
      }
    });

  // ── drift cloud logout ──
  cloud
    .command('logout')
    .description('Remove stored Drift Cloud credentials')
    .action(async () => {
      try {
        const { logout } = await import('@drift/core/cloud');
        await logout();
        process.stdout.write('Logged out from Drift Cloud.\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 2;
      }
    });
}
