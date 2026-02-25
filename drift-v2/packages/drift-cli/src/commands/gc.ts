/**
 * drift gc — garbage collection with tiered retention.
 */

import type { Command } from 'commander';
import { loadNapi } from '../napi.js';
import { formatOutput, type OutputFormat } from '../output/index.js';

export function registerGcCommand(program: Command): void {
  program
    .command('gc')
    .description('Run garbage collection on drift.db with tiered retention')
    .option('--short-days <days>', 'Short-term retention (detections), default 30', '30')
    .option('--medium-days <days>', 'Medium-term retention (trends), default 90', '90')
    .option('--long-days <days>', 'Long-term retention (caches), default 365', '365')
    .option('-f, --format <format>', 'Output format: table, json', 'table')
    .option('-q, --quiet', 'Suppress all output except errors')
    .action(async (opts: { shortDays: string; mediumDays: string; longDays: string; format: OutputFormat; quiet?: boolean }) => {
      const napi = loadNapi();
      try {
        const result = napi.driftGC(
          parseInt(opts.shortDays, 10),
          parseInt(opts.mediumDays, 10),
          parseInt(opts.longDays, 10),
        );
        if (!opts.quiet) {
          process.stdout.write(formatOutput(result, opts.format));
        }
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 2;
      }
    });
}
