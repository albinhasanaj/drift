/**
 * drift security — OWASP Top 10 analysis with CWE mapping.
 */

import type { Command } from 'commander';
import { loadNapi } from '../napi.js';
import { formatOutput, type OutputFormat } from '../output/index.js';

export function registerSecurityCommand(program: Command): void {
  program
    .command('security [path]')
    .description('Run OWASP Top 10 analysis with CWE mapping and compliance scoring')
    .option('-f, --format <format>', 'Output format: table, json, sarif', 'table')
    .option('-q, --quiet', 'Suppress all output except errors')
    .action(async (path: string | undefined, opts: { format: OutputFormat; quiet?: boolean }) => {
      const napi = loadNapi();
      try {
        const result = napi.driftOwaspAnalysis(path ?? process.cwd());
        if (!opts.quiet) {
          process.stdout.write(formatOutput(result, opts.format));
        }
        process.exitCode = result.findings.length > 0 ? 1 : 0;
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 2;
      }
    });
}
