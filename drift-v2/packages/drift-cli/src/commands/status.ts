/**
 * drift status — show project overview.
 */

import type { Command } from 'commander';
import { loadNapi } from '../napi.js';
import { formatOutput, type OutputFormat } from '../output/index.js';

export function registerStatusCommand(program: Command): void {
  program
    .command('status')
    .description('Show project overview — file count, patterns, violations, health score')
    .option('-f, --format <format>', 'Output format: table, json, sarif', 'table')
    .option('-q, --quiet', 'Suppress all output except errors')
    .action(async (opts: { format: OutputFormat; quiet?: boolean }) => {
      const napi = loadNapi();
      try {
        const audit = napi.driftAudit('.');
        const violations = napi.driftViolations('.');
        const result = {
          ...audit,
          violationCount: violations.length,
        };
        if (!opts.quiet) {
          process.stdout.write(formatOutput(result, opts.format));
        }
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 2;
      }
    });
}
