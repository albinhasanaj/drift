/**
 * drift simulate — run speculative execution / Monte Carlo simulation.
 */

import type { Command } from 'commander';
import { loadNapi } from '../napi.js';
import { formatOutput, type OutputFormat } from '../output/index.js';

const VALID_CATEGORIES = [
  'add_feature', 'fix_bug', 'refactor', 'migrate_framework', 'add_test',
  'security_fix', 'performance_optimization', 'dependency_update',
  'api_change', 'database_migration', 'config_change', 'documentation', 'infrastructure',
] as const;

export function registerSimulateCommand(program: Command): void {
  program
    .command('simulate <task>')
    .description('Run speculative execution simulation for a task')
    .option('-c, --category <category>', `Task category: ${VALID_CATEGORIES.join(', ')}`, 'refactor')
    .option('-f, --format <format>', 'Output format: table, json, sarif', 'table')
    .option('-q, --quiet', 'Suppress all output except errors')
    .action(async (task: string, opts: { category: string; format: OutputFormat; quiet?: boolean }) => {
      const napi = loadNapi();
      try {
        if (!VALID_CATEGORIES.includes(opts.category as typeof VALID_CATEGORIES[number])) {
          process.stderr.write(`Invalid category '${opts.category}'. Valid: ${VALID_CATEGORIES.join(', ')}\n`);
          process.exitCode = 2;
          return;
        }
        const result = await napi.driftSimulate(opts.category, task, '{}');
        if (!opts.quiet) {
          process.stdout.write(formatOutput(result, opts.format));
        }
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 2;
      }
    });
}
