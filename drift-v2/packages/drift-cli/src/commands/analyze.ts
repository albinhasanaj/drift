/**
 * drift analyze — run the full analysis pipeline on the project.
 *
 * This is THE critical command that populates the database with detections,
 * patterns, violations, call graph edges, boundaries, and conventions.
 * Without this, all query commands (check, violations, patterns, etc.) return empty.
 *
 * Pipeline: read tracked files → parse → detect → persist detections →
 * cross-file analysis (boundaries, call graph) → pattern intelligence → flush.
 *
 * Prerequisites: `drift scan` must have been run first to populate file_metadata.
 */

import type { Command } from 'commander';
import { loadNapi } from '../napi.js';
import { formatOutput, type OutputFormat } from '../output/index.js';

export function registerAnalyzeCommand(program: Command): void {
  program
    .command('analyze [path]')
    .description(
      'Run full analysis pipeline — detections, patterns, call graph, boundaries. Requires prior scan.',
    )
    .option(
      '-f, --format <format>',
      'Output format: table, json, sarif',
      'table',
    )
    .option('-q, --quiet', 'Suppress all output except errors')
    .option(
      '--scan',
      'Run scan before analysis (equivalent to drift scan && drift analyze)',
    )
    .option(
      '--phase <n>',
      'Max analysis phase: 1=detect, 2=cross-file, 3=structural, 4=graph, 5=enforce',
      parseInt,
    )
    .option(
      '--no-bridge',
      'Skip bridge grounding after analysis (default: bridge runs)',
    )
    .action(
      async (
        path: string | undefined,
        opts: {
          format: OutputFormat;
          quiet?: boolean;
          scan?: boolean;
          phase?: number;
          bridge?: boolean;
        },
      ) => {
        const napi = loadNapi();
        const scanPath = path ?? process.cwd();

        // Signal Rust NAPI layer to suppress debug logging
        if (opts.quiet) {
          process.env.DRIFT_QUIET = '1';
        } else {
          delete process.env.DRIFT_QUIET;
        }

        try {
          // Optionally run scan first
          if (opts.scan) {
            if (!opts.quiet) {
              process.stdout.write('Scanning files...\n');
            }
            const scanResult = await napi.driftScan(scanPath);
            if (!opts.quiet) {
              process.stdout.write(
                `Scan complete: ${scanResult.filesTotal} files (${scanResult.filesAdded} added, ${scanResult.filesModified} modified, ${scanResult.filesRemoved} removed)\n`,
              );
            }
          }

          // Run analysis
          if (!opts.quiet) {
            process.stdout.write('Running analysis pipeline...\n');
          }
          const results = await napi.driftAnalyze(opts.phase);

          // Bridge grounding — validate bridge memories against drift.db evidence
          const bridgeEnabled = opts.bridge !== false && process.env.DRIFT_BRIDGE_ENABLED !== 'false';
          if (bridgeEnabled) {
            try {
              const snapshot = napi.driftBridgeGroundAfterAnalyze();
              if (!opts.quiet && snapshot.total_checked > 0) {
                process.stdout.write(
                  `Bridge grounding: ${snapshot.total_checked} memories checked, ${snapshot.validated} validated\n`,
                );
              }
            } catch {
              // Non-fatal: grounding failure doesn't affect analyze output
            }
          }

          if (!opts.quiet) {
            // Summary statistics
            const totalMatches = results.reduce(
              (sum, r) => sum + r.matches.length,
              0,
            );
            const totalTime = results.reduce(
              (sum, r) => sum + r.analysisTimeUs,
              0,
            );
            const languages = [
              ...new Set(results.map((r) => r.language)),
            ];

            process.stdout.write(
              `\nAnalysis complete:\n` +
                `  Files analyzed: ${results.length}\n` +
                `  Patterns detected: ${totalMatches}\n` +
                `  Languages: ${languages.join(', ') || 'none'}\n` +
                `  Total time: ${(totalTime / 1000).toFixed(1)}ms\n`,
            );

            if (opts.format !== 'table' || totalMatches > 0) {
              process.stdout.write(
                '\n' + formatOutput(results, opts.format),
              );
            }
          }

          process.exitCode = 0;
        } catch (err) {
          process.stderr.write(
            `Error: ${err instanceof Error ? err.message : err}\n`,
          );
          process.exitCode = 2;
        }
      },
    );
}
