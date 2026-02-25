/**
 * drift export — export violations in any supported format.
 */

import type { Command } from 'commander';
import { loadNapi } from '../napi.js';
import { formatOutput, type OutputFormat } from '../output/index.js';
import * as fs from 'node:fs';

const REPORT_FORMATS = ['sarif', 'json', 'html', 'junit', 'sonarqube', 'console', 'github', 'gitlab'] as const;

export function registerExportCommand(program: Command): void {
  program
    .command('export [path]')
    .description('Export violations in the specified format')
    .option(
      '-f, --format <format>',
      `Output format: ${REPORT_FORMATS.join(', ')}`,
      'json',
    )
    .option('-o, --output <file>', 'Write output to file instead of stdout')
    .option('-q, --quiet', 'Suppress all output except errors')
    .action(async (path: string | undefined, opts: { format: string; output?: string; quiet?: boolean }) => {
      const napi = loadNapi();
      try {
        let formatted: string;

        // Use driftReport for rich report formats (sarif, html, junit, sonarqube, github, gitlab)
        if (REPORT_FORMATS.includes(opts.format as typeof REPORT_FORMATS[number])) {
          formatted = napi.driftReport(opts.format);
        } else {
          // Fallback: raw violations with basic formatting
          const violations = napi.driftViolations(path ?? process.cwd());
          formatted = formatOutput(violations, opts.format as OutputFormat);
        }

        if (opts.output) {
          fs.writeFileSync(opts.output, formatted, 'utf-8');
          if (!opts.quiet) {
            process.stdout.write(`Exported to ${opts.output}\n`);
          }
        } else if (!opts.quiet) {
          process.stdout.write(formatted);
        }
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 2;
      }
    });
}
