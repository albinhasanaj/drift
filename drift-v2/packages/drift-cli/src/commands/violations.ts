/**
 * drift violations — list all violations.
 */

import type { Command } from 'commander';
import { loadNapi } from '../napi.js';
import { formatOutput, type OutputFormat } from '../output/index.js';

export function registerViolationsCommand(program: Command): void {
  program
    .command('violations [path]')
    .description('List all violations found in the project')
    .option('-f, --format <format>', 'Output format: table, json, sarif', 'table')
    .option('-q, --quiet', 'Suppress all output except errors')
    .action(async (path: string | undefined, opts: { format: OutputFormat; quiet?: boolean }) => {
      const napi = loadNapi();
      const violationsPath = path ?? process.cwd();
      try {
        const result = napi.driftViolations(violationsPath);

        if ((result as unknown[]).length === 0 && !opts.quiet) {
          process.stderr.write(
            'No violations found. This may mean:\n' +
            '  (a) Your code is fully compliant\n' +
            '  (b) No rules are configured — check drift.toml [rules] section\n' +
            '  (c) Analysis has not been run — try `drift scan && drift analyze`\n\n',
          );
        }

        if (!opts.quiet) {
          process.stdout.write(formatOutput(result, opts.format));
        }
        process.exitCode = (result as unknown[]).length > 0 ? 1 : 0;
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 2;
      }
    });
}
