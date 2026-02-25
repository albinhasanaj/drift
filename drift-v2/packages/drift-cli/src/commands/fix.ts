/**
 * drift fix — mark a violation as fixed (positive Bayesian signal).
 */

import type { Command } from 'commander';
import { loadNapi } from '../napi.js';
import { formatOutput, type OutputFormat } from '../output/index.js';

export function registerFixCommand(program: Command): void {
  program
    .command('fix <violationId>')
    .description('Mark a violation as fixed. Reports confidence adjustment.')
    .option('-f, --format <format>', 'Output format: table, json', 'table')
    .option('-q, --quiet', 'Suppress all output except errors')
    .action(async (violationId: string, opts: { format: OutputFormat; quiet?: boolean }) => {
      const napi = loadNapi();
      try {
        const result = napi.driftFixViolation(violationId);
        if (!opts.quiet) {
          process.stdout.write(formatOutput(result, opts.format));
        }
        process.exitCode = 0;
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 2;
      }
    });
}
