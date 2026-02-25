/**
 * drift validate-pack <file.toml> — validate a framework pack TOML file.
 *
 * Loads the TOML file, parses it through the framework pack loader,
 * and reports any errors or prints a summary of the pack.
 */

import type { Command } from 'commander';
import * as fs from 'node:fs';
import { loadNapi } from '../napi.js';

export function registerValidatePackCommand(program: Command): void {
  program
    .command('validate-pack <file>')
    .description('Validate a framework pack TOML file')
    .action(async (file: string) => {
      // Check file exists
      if (!fs.existsSync(file)) {
        process.stderr.write(`Error: file not found: ${file}\n`);
        process.exitCode = 1;
        return;
      }

      // Read TOML content
      let content: string;
      try {
        content = fs.readFileSync(file, 'utf-8');
      } catch (err) {
        process.stderr.write(
          `Error: could not read file: ${err instanceof Error ? err.message : err}\n`,
        );
        process.exitCode = 1;
        return;
      }

      // Pre-check: detect if this is a project config file instead of a framework pack.
      // Framework packs have [framework] + [[patterns]], project configs have [scan]/[policy]/[gates].
      const isProjectConfig =
        /^\[scan\]/m.test(content) ||
        /^\[policy\]/m.test(content) ||
        /^\[gates\]/m.test(content) ||
        /^\[reporters\]/m.test(content);
      const hasFrameworkSection = /^\[framework\]/m.test(content);

      if (isProjectConfig && !hasFrameworkSection) {
        process.stderr.write(
          `✗ '${file}' is a Drift project configuration file, not a framework pack.\n` +
          `  Framework packs require a [framework] section and [[patterns]] entries.\n` +
          `  To validate project config, use 'drift doctor' instead.\n`,
        );
        process.exitCode = 1;
        return;
      }

      // Validate via NAPI
      const napi = loadNapi();
      const result = napi.driftValidatePack(content);

      if (result.valid) {
        process.stdout.write(`✓ Valid framework pack: ${result.name}\n`);
        if (result.version) {
          process.stdout.write(`  Version: ${result.version}\n`);
        }
        process.stdout.write(`  Languages: ${result.languageCount}\n`);
        process.stdout.write(`  Patterns: ${result.patternCount}\n`);
        process.exitCode = 0;
      } else {
        process.stderr.write(`✗ Invalid framework pack: ${file}\n`);
        if (result.error) {
          process.stderr.write(`  Error: ${result.error}\n`);
        }
        process.exitCode = 1;
      }
    });
}
