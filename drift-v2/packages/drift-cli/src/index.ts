#!/usr/bin/env node
/**
 * Drift CLI — entry point.
 *
 * 26 commands organized by category:
 * Core: scan, analyze, check, status, report
 * Exploration: patterns, violations, security, contracts, coupling, dna, taint, errors, test-quality, impact
 * Feedback: fix, dismiss, suppress, explain
 * Advanced: simulate, context, audit, export
 * Operational: gc, setup, doctor
 *
 * Exit codes: 0 = clean, 1 = violations found, 2 = error.
 */

import { Command } from 'commander';
import { registerAllCommands } from './commands/index.js';
import { loadNapi } from './napi.js';
import { isNapiStub, resolveProjectRoot } from '@drift/napi-contracts';

// Re-export public API
export { registerAllCommands } from './commands/index.js';
export { formatOutput } from './output/index.js';
export type { OutputFormat } from './output/index.js';
export { setNapi } from './napi.js';
export type { DriftNapi } from './napi.js';

/**
 * Create and configure the CLI program.
 */
export function createProgram(): Command {
  const program = new Command();

  program
    .name('drift')
    .description('Drift — AI-native code analysis and quality enforcement')
    .version('2.0.0')
    .option('-q, --quiet', 'Suppress all output except errors')
    .option('--require-native', 'Error if native binary is unavailable (instead of using stubs)')
    .enablePositionalOptions()
    .passThroughOptions();

  registerAllCommands(program);

  return program;
}

/**
 * Main entry point — parses args and runs the appropriate command.
 */
async function main(): Promise<void> {
  // Initialize NAPI with project root from cwd.
  // The project root determines where .drift/drift.db and .drift/bridge.db live.
  // We use process.cwd() unconditionally — attempting to detect paths from CLI
  // args is fragile because command names ('bridge'), subcommand names ('ground'),
  // and option values ('json') can collide with directory names in the repo.
  // Individual commands (scan, analyze) handle their own path arguments internally.
  const napi = loadNapi();
  const isSetup = process.argv.includes('setup');

  const program = createProgram();

  if (!isSetup) {
    try {
      napi.driftInitialize(undefined, resolveProjectRoot());
    } catch {
      // Non-fatal — may already be initialized or not available yet
    }
  }

  // Check --require-native before executing any command
  const opts = program.opts();
  if (opts.requireNative && isNapiStub()) {
    process.stderr.write(
      'Error: --require-native specified but native binary is unavailable. ' +
      'Install platform-specific binary or run `napi build`.\n',
    );
    process.exitCode = 2;
    return;
  }

  try {
    await program.parseAsync(process.argv);
  } catch (err) {
    process.stderr.write(
      `Error: ${err instanceof Error ? err.message : err}\n`,
    );
    process.exitCode = 2;
  }
}

// Run if executed directly
const isMainModule =
  typeof process !== 'undefined' &&
  process.argv[1] &&
  (process.argv[1].endsWith('drift') ||
    process.argv[1].endsWith('index.js') ||
    process.argv[1].endsWith('index.ts'));

if (isMainModule) {
  main().catch((err) => {
    process.stderr.write(`Fatal: ${err}\n`);
    process.exit(2);
  });
}
