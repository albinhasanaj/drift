/**
 * drift report — generate reports from stored violations in 8 formats.
 */

import type { Command } from 'commander';
import { loadNapi } from '../napi.js';

const VALID_FORMATS = [
  'sarif', 'json', 'html', 'junit', 'sonarqube', 'console', 'github', 'gitlab',
] as const;

export function registerReportCommand(program: Command): void {
  program
    .command('report')
    .description('Generate a report from stored violations')
    .option('-f, --format <format>', `Report format: ${VALID_FORMATS.join(', ')}`, 'console')
    .option('-r, --report-format <format>', `(alias) Report format: ${VALID_FORMATS.join(', ')}`)
    .option('-o, --output <file>', 'Write output to file instead of stdout')
    .option('-q, --quiet', 'Suppress all output except errors')
    .action(async (opts: { format: string; reportFormat?: string; output?: string; quiet?: boolean }) => {
      const napi = loadNapi();
      // --report-format takes precedence if both provided
      const selectedFormat = opts.reportFormat ?? opts.format;
      try {
        if (!VALID_FORMATS.includes(selectedFormat as typeof VALID_FORMATS[number])) {
          process.stderr.write(`Invalid format '${selectedFormat}'. Valid: ${VALID_FORMATS.join(', ')}\n`);
          process.exitCode = 2;
          return;
        }
        const result = napi.driftReport(selectedFormat);
        if (opts.output) {
          const fs = await import('fs');
          fs.writeFileSync(opts.output, result, 'utf-8');
          if (!opts.quiet) {
            process.stdout.write(`Report written to ${opts.output}\n`);
          }
        } else if (!opts.quiet) {
          process.stdout.write(result);
          process.stdout.write('\n');
        }
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 2;
      }
    });
}
