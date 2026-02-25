/**
 * drift errors — error handling gap analysis.
 */

import type { Command } from 'commander';
import { loadNapi } from '../napi.js';
import { formatOutput, type OutputFormat } from '../output/index.js';

export function registerErrorsCommand(program: Command): void {
  program
    .command('errors [path]')
    .description('Analyze error handling gaps — find unhandled exceptions and missing error paths')
    .option('-f, --format <format>', 'Output format: table, json, sarif', 'table')
    .option('-q, --quiet', 'Suppress all output except errors')
    .action(async (path: string | undefined, opts: { format: OutputFormat; quiet?: boolean }) => {
      const napi = loadNapi();
      try {
        const result = napi.driftErrorHandling(path ?? process.cwd());
        if (!opts.quiet) {
          process.stdout.write(formatOutput(result, opts.format));
        }
        process.exitCode = result.unhandledCount > 0 ? 1 : 0;
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 2;
      }
    });
}
