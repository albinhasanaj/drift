/**
 * drift patterns — list detected patterns.
 */

import type { Command } from 'commander';
import { loadNapi } from '../napi.js';
import { formatOutput, type OutputFormat } from '../output/index.js';

export function registerPatternsCommand(program: Command): void {
  program
    .command('patterns')
    .description('List detected code patterns')
    .option('-f, --format <format>', 'Output format: table, json, sarif', 'table')
    .option('-c, --category <category>', 'Filter by pattern category')
    .option('--after <id>', 'Keyset pagination cursor — show patterns after this ID')
    .option('--limit <n>', 'Maximum number of patterns to return', '100')
    .option('-q, --quiet', 'Suppress all output except errors')
    .action(async (opts: { format: OutputFormat; category?: string; after?: string; limit: string; quiet?: boolean }) => {
      const napi = loadNapi();
      try {
        const result = napi.driftPatterns(opts.category, opts.after, parseInt(opts.limit, 10));
        if (!opts.quiet) {
          process.stdout.write(formatOutput(result, opts.format));
        }
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 2;
      }
    });
}
