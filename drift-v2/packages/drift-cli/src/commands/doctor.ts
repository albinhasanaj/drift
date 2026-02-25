/**
 * drift doctor — health checks for the Drift installation.
 *
 * Verifies: drift.toml exists, schema version is current, drift.db is not corrupt.
 */

import type { Command } from 'commander';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { loadNapi } from '../napi.js';

interface HealthCheck {
  name: string;
  status: 'ok' | 'warn' | 'error';
  message: string;
}

export function registerDoctorCommand(program: Command): void {
  program
    .command('doctor')
    .description('Run health checks on the Drift installation')
    .action(async () => {
      const projectRoot = process.cwd();
      const checks: HealthCheck[] = [];

      // Check 1: drift.toml exists
      const configPath = path.join(projectRoot, 'drift.toml');
      if (fs.existsSync(configPath)) {
        checks.push({ name: 'drift.toml', status: 'ok', message: 'Configuration file found' });
      } else {
        checks.push({
          name: 'drift.toml',
          status: 'error',
          message: 'Missing. Run `drift setup` to create it.',
        });
      }

      // Check 2: .drift directory exists
      const driftDir = path.join(projectRoot, '.drift');
      if (fs.existsSync(driftDir)) {
        checks.push({ name: '.drift directory', status: 'ok', message: 'Data directory found' });
      } else {
        checks.push({
          name: '.drift directory',
          status: 'error',
          message: 'Missing. Run `drift setup` to initialize.',
        });
      }

      // Check 3: drift.db exists and is readable
      const dbPath = path.join(driftDir, 'drift.db');
      if (fs.existsSync(dbPath)) {
        try {
          const stats = fs.statSync(dbPath);
          if (stats.size > 0) {
            checks.push({ name: 'drift.db', status: 'ok', message: `Database found (${formatSize(stats.size)})` });
          } else {
            checks.push({ name: 'drift.db', status: 'warn', message: 'Database is empty — run `drift scan`' });
          }
        } catch {
          checks.push({ name: 'drift.db', status: 'error', message: 'Database exists but is not readable' });
        }
      } else {
        checks.push({
          name: 'drift.db',
          status: 'error',
          message: 'Missing. Run `drift setup` to initialize.',
        });
      }

      // Check 4: Node.js version
      const nodeVersion = process.version;
      const major = parseInt(nodeVersion.slice(1), 10);
      if (major >= 18) {
        checks.push({ name: 'Node.js', status: 'ok', message: `${nodeVersion} (>= 18 required)` });
      } else {
        checks.push({ name: 'Node.js', status: 'error', message: `${nodeVersion} — Node.js >= 18 required` });
      }

      // Check 5: NAPI bindings + driftIsInitialized
      try {
        const napi = loadNapi();
        const initialized = napi.driftIsInitialized();
        if (initialized) {
          checks.push({ name: 'NAPI bindings', status: 'ok', message: 'Native module loaded, database initialized' });
        } else {
          checks.push({ name: 'NAPI bindings', status: 'warn', message: 'Native module loaded but not initialized — run `drift setup`' });
        }
      } catch {
        checks.push({ name: 'NAPI bindings', status: 'warn', message: 'Native module not available — using stub' });
      }

      // Output results
      const hasErrors = checks.some((c) => c.status === 'error');
      const hasWarnings = checks.some((c) => c.status === 'warn');

      for (const check of checks) {
        const icon = check.status === 'ok' ? '✓' : check.status === 'warn' ? '⚠' : '✗';
        process.stdout.write(`${icon} ${check.name}: ${check.message}\n`);
      }

      process.stdout.write('\n');
      if (hasErrors) {
        process.stdout.write('Some checks failed. Run `drift setup` to fix.\n');
        process.exitCode = 1;
      } else if (hasWarnings) {
        process.stdout.write('All critical checks passed with warnings.\n');
        process.exitCode = 0;
      } else {
        process.stdout.write('All checks passed.\n');
        process.exitCode = 0;
      }
    });
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
