/**
 * drift scan — scan project for patterns and violations.
 *
 * Supports --include and --exclude glob flags for folder selection,
 * plus persistent configuration via drift.toml [scan] section.
 */

import type { Command } from 'commander';
import { loadNapi } from '../napi.js';
import { formatOutput, type OutputFormat } from '../output/index.js';

export function registerScanCommand(program: Command): void {
  program
    .command('scan [paths...]')
    .description('Scan project for patterns and violations. Pass one or more folder paths to scan specific directories.')
    .option('-f, --format <format>', 'Output format: table, json, sarif', 'table')
    .option('-i, --incremental', 'Only scan changed files since last scan')
    .option('--include <globs...>', 'Only scan files matching these glob patterns (e.g., "src/**")')
    .option('--exclude <globs...>', 'Exclude files matching these glob patterns (e.g., "drift/**")')
    .option('--follow-symlinks', 'Follow symbolic links during scan')
    .option('--max-file-size <bytes>', 'Maximum file size in bytes (default: 1MB)', parseInt)
    .option('-q, --quiet', 'Suppress all output except errors')
    .action(async (paths: string[], opts: {
      format: OutputFormat;
      incremental?: boolean;
      include?: string[];
      exclude?: string[];
      followSymlinks?: boolean;
      maxFileSize?: number;
      quiet?: boolean;
    }) => {
      const napi = loadNapi();
      const scanPaths = paths.length > 0 ? paths : [process.cwd()];

      // Build scan options from CLI flags
      const options: Record<string, unknown> = {};
      if (opts.incremental === true) {
        options.forceFull = false;
      }
      if (opts.include && opts.include.length > 0) {
        options.include = opts.include;
      }
      if (opts.exclude && opts.exclude.length > 0) {
        options.extraIgnore = opts.exclude;
      }
      if (opts.followSymlinks === true) {
        options.followSymlinks = true;
      }
      if (opts.maxFileSize !== undefined) {
        options.maxFileSize = opts.maxFileSize;
      }

      const scanOptions = Object.keys(options).length > 0 ? options : undefined;

      try {
        // Scan each path and merge results
        let totalFiles = 0;
        let lastResult: Awaited<ReturnType<typeof napi.driftScan>> | undefined;
        for (const scanPath of scanPaths) {
          const result = await napi.driftScan(scanPath, scanOptions as Parameters<typeof napi.driftScan>[1]);
          totalFiles += result.filesTotal;
          lastResult = result;
        }
        if (!opts.quiet && lastResult) {
          if (scanPaths.length > 1) {
            // Multi-path: show merged summary
            const merged = { ...lastResult, filesTotal: totalFiles, paths: scanPaths };
            process.stdout.write(formatOutput(merged, opts.format));
          } else {
            process.stdout.write(formatOutput(lastResult, opts.format));
          }
        }
        process.exitCode = 0;
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 2;
      }
    });
}
