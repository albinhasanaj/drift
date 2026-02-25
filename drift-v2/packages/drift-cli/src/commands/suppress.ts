/**
 * drift suppress — suppress a violation for a period with auto-unsuppress.
 */

import type { Command } from 'commander';
import { loadNapi } from '../napi.js';
import { formatOutput, type OutputFormat } from '../output/index.js';

export function registerSuppressCommand(program: Command): void {
  program
    .command('suppress <violationId>')
    .description('Suppress a violation with a reason. Auto-unsuppresses after retention period.')
    .requiredOption('-r, --reason <reason>', 'Reason for suppression')
    .option('-f, --format <format>', 'Output format: table, json', 'table')
    .option('-q, --quiet', 'Suppress all output except errors')
    .action(async (violationId: string, opts: { reason: string; format: OutputFormat; quiet?: boolean }) => {
      const napi = loadNapi();
      try {
        const result = napi.driftSuppressViolation(violationId, opts.reason);
        if (!opts.quiet) {
          process.stdout.write(formatOutput(result, opts.format));
        }
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 2;
      }
    });
}
