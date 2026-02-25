/**
 * drift dismiss — dismiss a violation with reason (Bayesian confidence adjustment).
 */

import type { Command } from 'commander';
import { loadNapi } from '../napi.js';
import { formatOutput, type OutputFormat } from '../output/index.js';

export function registerDismissCommand(program: Command): void {
  program
    .command('dismiss <violationId>')
    .description('Dismiss a violation with a reason. Adjusts Bayesian confidence.')
    .requiredOption('-r, --reason <reason>', 'Reason for dismissal')
    .option('-f, --format <format>', 'Output format: table, json', 'table')
    .option('-q, --quiet', 'Suppress all output except errors')
    .action(async (violationId: string, opts: { reason: string; format: OutputFormat; quiet?: boolean }) => {
      const napi = loadNapi();
      try {
        const result = napi.driftDismissViolation({
          violationId,
          action: 'dismiss',
          reason: opts.reason,
        });
        if (!opts.quiet) {
          process.stdout.write(formatOutput(result, opts.format));
        }
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 2;
      }
    });
}
