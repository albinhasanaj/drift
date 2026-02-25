/**
 * drift approve — approve, ignore, or query pattern statuses.
 *
 * Subcommands:
 *   drift approve <patternId>           — approve a pattern
 *   drift approve --ignore <patternId>  — ignore a pattern
 *   drift approve --list [--status <s>] — list pattern statuses
 */

import type { Command } from 'commander';
import { loadNapi } from '../napi.js';
import { formatOutput, type OutputFormat } from '../output/index.js';

export function registerApproveCommand(program: Command): void {
  const cmd = program
    .command('approve [patternId]')
    .description('Approve or manage pattern lifecycle status (discovered → approved / ignored)')
    .option('--ignore', 'Set pattern status to ignored instead of approved')
    .option('--reset', 'Reset pattern status back to discovered')
    .option('-r, --reason <reason>', 'Reason for the status change')
    .option('-l, --list', 'List all pattern statuses (no patternId required)')
    .option('-s, --status <status>', 'Filter by status when listing: discovered, approved, ignored')
    .option('-f, --format <format>', 'Output format: table, json', 'table')
    .option('-q, --quiet', 'Suppress all output except errors')
    .action(
      async (
        patternId: string | undefined,
        opts: {
          ignore?: boolean;
          reset?: boolean;
          reason?: string;
          list?: boolean;
          status?: string;
          format: OutputFormat;
          quiet?: boolean;
        },
      ) => {
        const napi = loadNapi();
        try {
          // List mode
          if (opts.list) {
            const result = napi.driftPatternStatus(opts.status ?? null);
            if (!opts.quiet) {
              process.stdout.write(formatOutput(result, opts.format));
            }
            return;
          }

          // Approve / ignore / reset a specific pattern
          if (!patternId) {
            process.stderr.write(
              'Error: <patternId> is required unless --list is specified.\n' +
                'Usage: drift approve <patternId> [--ignore] [--reset] [-r reason]\n' +
                '       drift approve --list [--status discovered|approved|ignored]\n',
            );
            process.exitCode = 1;
            return;
          }

          const status = opts.reset
            ? 'discovered'
            : opts.ignore
              ? 'ignored'
              : 'approved';

          const result = napi.driftApprovePattern(
            patternId,
            status,
            opts.reason ?? null,
          );

          if (!opts.quiet) {
            process.stdout.write(formatOutput(result, opts.format));
          }
        } catch (err) {
          process.stderr.write(
            `Error: ${err instanceof Error ? err.message : err}\n`,
          );
          process.exitCode = 2;
        }
      },
    );

  return cmd as unknown as void;
}
