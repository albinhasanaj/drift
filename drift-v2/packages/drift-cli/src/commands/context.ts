/**
 * drift context — intent-weighted deep dive context generation.
 */

import type { Command } from 'commander';
import { loadNapi } from '../napi.js';
import { formatOutput, type OutputFormat } from '../output/index.js';

const VALID_INTENTS = [
  'fix_bug', 'add_feature', 'understand_code', 'security_audit', 'generate_spec',
] as const;

const VALID_DEPTHS = ['overview', 'standard', 'deep'] as const;

const INTENT_KEYWORDS: Record<string, typeof VALID_INTENTS[number]> = {
  'fix': 'fix_bug',
  'bug': 'fix_bug',
  'debug': 'fix_bug',
  'repair': 'fix_bug',
  'patch': 'fix_bug',
  'add': 'add_feature',
  'feature': 'add_feature',
  'new': 'add_feature',
  'create': 'add_feature',
  'implement': 'add_feature',
  'build': 'add_feature',
  'understand': 'understand_code',
  'read': 'understand_code',
  'explore': 'understand_code',
  'learn': 'understand_code',
  'how': 'understand_code',
  'what': 'understand_code',
  'security': 'security_audit',
  'audit': 'security_audit',
  'vulnerability': 'security_audit',
  'vuln': 'security_audit',
  'spec': 'generate_spec',
  'specification': 'generate_spec',
  'document': 'generate_spec',
  'docs': 'generate_spec',
};

function resolveIntent(raw: string): typeof VALID_INTENTS[number] | null {
  // Exact match first
  if (VALID_INTENTS.includes(raw as typeof VALID_INTENTS[number])) {
    return raw as typeof VALID_INTENTS[number];
  }

  // Keyword matching — find best match from input words
  const words = raw.toLowerCase().replace(/[^a-z0-9_\s]/g, '').split(/\s+/);
  const matches = new Map<typeof VALID_INTENTS[number], number>();

  for (const word of words) {
    const mapped = INTENT_KEYWORDS[word];
    if (mapped) {
      matches.set(mapped, (matches.get(mapped) ?? 0) + 1);
    }
  }

  if (matches.size === 0) return null;

  // Return intent with most keyword hits
  return [...matches.entries()].sort((a, b) => b[1] - a[1])[0][0];
}

export function registerContextCommand(program: Command): void {
  program
    .command('context <intent>')
    .description('Generate intent-weighted context for a task')
    .option('-d, --depth <depth>', `Context depth: ${VALID_DEPTHS.join(', ')}`, 'standard')
    .option('--data <json>', 'Additional data as JSON string', '{}')
    .option('-f, --format <format>', 'Output format: table, json, sarif', 'json')
    .option('-q, --quiet', 'Suppress all output except errors')
    .action(async (intent: string, opts: { depth: string; data: string; format: OutputFormat; quiet?: boolean }) => {
      const napi = loadNapi();
      try {
        const resolved = resolveIntent(intent);
        if (!resolved) {
          process.stderr.write(
            `Could not resolve intent '${intent}'.\n` +
            `Valid intents: ${VALID_INTENTS.join(', ')}\n` +
            `Tip: Use keywords like "fix", "add", "understand", "security", or "spec".\n`,
          );
          process.exitCode = 2;
          return;
        }

        if (resolved !== intent) {
          process.stderr.write(`Resolved intent: '${intent}' → '${resolved}'\n`);
        }

        if (!VALID_DEPTHS.includes(opts.depth as typeof VALID_DEPTHS[number])) {
          process.stderr.write(`Invalid depth '${opts.depth}'. Valid: ${VALID_DEPTHS.join(', ')}\n`);
          process.exitCode = 2;
          return;
        }
        const result = await napi.driftContext(resolved, opts.depth, opts.data);
        if (!opts.quiet) {
          process.stdout.write(formatOutput(result, opts.format));
        }
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 2;
      }
    });
}
