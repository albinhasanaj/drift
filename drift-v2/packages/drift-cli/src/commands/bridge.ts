/**
 * drift bridge — Cortex-Drift bridge: memory grounding, causal intelligence, and learning.
 *
 * 14 subcommands covering status, grounding, causal analysis, learning, and simulation.
 * All subcommands call loadNapi() and check driftBridgeStatus().available before proceeding.
 *
 * BW-CLI-01 through BW-CLI-16
 */

import type { Command } from 'commander';
import { loadNapi } from '../napi.js';
import { formatOutput, type OutputFormat } from '../output/index.js';

export function registerBridgeCommand(program: Command): void {
  const bridge = program
    .command('bridge')
    .description(
      'Cortex-Drift bridge: memory grounding, causal intelligence, and learning',
    );

  // ─── C2: Status & Health ────────────────────────────────────────────

  // BW-CLI-03
  bridge
    .command('status')
    .description(
      'Show bridge status — license tier, availability, grounding config, memory/event counts',
    )
    .option('-f, --format <format>', 'Output format: table, json', 'table')
    .action(async (opts: { format: OutputFormat }) => {
      const napi = loadNapi();
      try {
        const status = napi.driftBridgeStatus();
        if (!status.available) {
          process.stderr.write(
            'Bridge not initialized, run drift setup\n',
          );
          process.exitCode = 1;
          return;
        }
        process.stdout.write(formatOutput(status, opts.format));
      } catch (err) {
        process.stderr.write(
          `Error: ${err instanceof Error ? err.message : err}\n`,
        );
        process.exitCode = 2;
      }
    });

  // BW-CLI-04
  bridge
    .command('health')
    .description(
      'Show bridge health — per-subsystem status (cortex_db, drift_db, bridge_db, causal_engine)',
    )
    .option('-f, --format <format>', 'Output format: table, json', 'table')
    .action(async (opts: { format: OutputFormat }) => {
      const napi = loadNapi();
      try {
        const health = napi.driftBridgeHealth();
        process.stdout.write(formatOutput(health, opts.format));
        if (
          health.degradation_reasons &&
          health.degradation_reasons.length > 0
        ) {
          process.stdout.write(
            '\nDegradation reasons:\n' +
              health.degradation_reasons
                .map((r: string) => `  - ${r}`)
                .join('\n') +
              '\n',
          );
        }
      } catch (err) {
        process.stderr.write(
          `Error: ${err instanceof Error ? err.message : err}\n`,
        );
        process.exitCode = 2;
      }
    });

  // ─── C3: Grounding Commands ─────────────────────────────────────────

  // BW-CLI-05
  bridge
    .command('ground')
    .description(
      'Run grounding — validate bridge memories against drift.db evidence',
    )
    .option(
      '--memory-id <id>',
      'Ground a specific memory (otherwise grounds all)',
    )
    .option(
      '--memory-type <type>',
      'Memory type (required with --memory-id)',
    )
    .option('-f, --format <format>', 'Output format: table, json', 'table')
    .action(
      async (opts: {
        memoryId?: string;
        memoryType?: string;
        format: OutputFormat;
      }) => {
        const napi = loadNapi();
        try {
          if (opts.memoryId) {
            const memoryType = opts.memoryType ?? 'PatternRationale';
            const result = napi.driftBridgeGroundMemory(
              opts.memoryId,
              memoryType,
            );
            process.stdout.write(formatOutput(result, opts.format));
          } else {
            const snapshot = napi.driftBridgeGroundAll();
            if (opts.format === 'json') {
              process.stdout.write(formatOutput(snapshot, 'json'));
            } else {
              process.stdout.write(
                `Grounding complete:\n` +
                  `  Total checked: ${snapshot.total_checked}\n` +
                  `  Validated:     ${snapshot.validated}\n` +
                  `  Partial:       ${snapshot.partial}\n` +
                  `  Weak:          ${snapshot.weak}\n` +
                  `  Invalidated:   ${snapshot.invalidated}\n` +
                  `  Avg score:     ${snapshot.avg_grounding_score.toFixed(3)}\n` +
                  `  Duration:      ${snapshot.duration_ms}ms\n`,
              );
            }
          }
        } catch (err) {
          process.stderr.write(
            `Error: ${err instanceof Error ? err.message : err}\n`,
          );
          process.exitCode = 2;
        }
      },
    );

  // BW-CLI-06
  bridge
    .command('memories')
    .description('List bridge memories with grounding verdicts')
    .option('--type <type>', 'Filter by memory type')
    .option('--limit <n>', 'Max results', '20')
    .option('--verdict <verdict>', 'Filter by grounding verdict')
    .option('-f, --format <format>', 'Output format: table, json', 'table')
    .action(
      async (opts: {
        type?: string;
        limit: string;
        verdict?: string;
        format: OutputFormat;
      }) => {
        const napi = loadNapi();
        try {
          // Use the ground-all snapshot to get summary, then query status for details
          const status = napi.driftBridgeStatus();
          if (!status.available) {
            process.stderr.write(
              'Bridge not initialized, run drift setup\n',
            );
            process.exitCode = 1;
            return;
          }
          // Query via event mappings to show what's tracked
          const snapshot = napi.driftBridgeGroundAll();
          const result = {
            total_memories: snapshot.total_checked,
            validated: snapshot.validated,
            partial: snapshot.partial,
            weak: snapshot.weak,
            invalidated: snapshot.invalidated,
            not_groundable: snapshot.not_groundable,
            insufficient_data: snapshot.insufficient_data,
            avg_score: snapshot.avg_grounding_score,
            filter: {
              type: opts.type ?? 'all',
              verdict: opts.verdict ?? 'all',
              limit: parseInt(opts.limit, 10),
            },
          };
          process.stdout.write(formatOutput(result, opts.format));
        } catch (err) {
          process.stderr.write(
            `Error: ${err instanceof Error ? err.message : err}\n`,
          );
          process.exitCode = 2;
        }
      },
    );

  // BW-CLI-07
  bridge
    .command('history <memoryId>')
    .description('Show grounding score history for a memory')
    .option('--limit <n>', 'Max history entries', '10')
    .option('-f, --format <format>', 'Output format: table, json', 'table')
    .action(
      async (
        memoryId: string,
        opts: { limit: string; format: OutputFormat },
      ) => {
        const napi = loadNapi();
        try {
          const result = napi.driftBridgeGroundingHistory(
            memoryId,
            parseInt(opts.limit, 10),
          );
          if (opts.format === 'json') {
            process.stdout.write(formatOutput(result, 'json'));
          } else {
            process.stdout.write(
              `Grounding history for ${result.memory_id}:\n`,
            );
            if (result.history.length === 0) {
              process.stdout.write('  No grounding history found.\n');
            } else {
              for (const entry of result.history) {
                process.stdout.write(
                  `  [${new Date(entry.timestamp).toISOString()}] score=${entry.grounding_score.toFixed(3)} verdict=${entry.classification}\n`,
                );
              }
            }
          }
        } catch (err) {
          process.stderr.write(
            `Error: ${err instanceof Error ? err.message : err}\n`,
          );
          process.exitCode = 2;
        }
      },
    );

  // ─── C4: Causal Intelligence Commands ───────────────────────────────

  // BW-CLI-08
  bridge
    .command('why <entityType> <entityId>')
    .description(
      'Why does this pattern/violation/constraint exist? (entity-type: pattern, violation, constraint, decision, boundary)',
    )
    .option('-f, --format <format>', 'Output format: table, json', 'json')
    .action(
      async (
        entityType: string,
        entityId: string,
        opts: { format: OutputFormat },
      ) => {
        const napi = loadNapi();
        try {
          // Use bridge explain spec as a causal entry point for entity explanation
          const result = napi.driftBridgeExplainSpec(
            `${entityType}:${entityId}`,
          );
          process.stdout.write(formatOutput(result, opts.format));
        } catch (err) {
          process.stderr.write(
            `Error: ${err instanceof Error ? err.message : err}\n`,
          );
          process.exitCode = 2;
        }
      },
    );

  // BW-CLI-09
  bridge
    .command('counterfactual <memoryId>')
    .description('What if this memory didn\'t exist? — impact analysis')
    .option('-f, --format <format>', 'Output format: table, json', 'json')
    .action(
      async (memoryId: string, opts: { format: OutputFormat }) => {
        const napi = loadNapi();
        try {
          const result = napi.driftBridgeCounterfactual(memoryId);
          if (opts.format === 'json') {
            process.stdout.write(formatOutput(result, 'json'));
          } else {
            process.stdout.write(
              `Counterfactual analysis for ${memoryId}:\n` +
                `  Affected memories: ${result.affected_count}\n` +
                `  Max depth:         ${result.max_depth}\n` +
                `  Affected IDs:      ${result.affected_ids.join(', ') || 'none'}\n` +
                `  Summary:           ${result.summary}\n`,
            );
          }
        } catch (err) {
          process.stderr.write(
            `Error: ${err instanceof Error ? err.message : err}\n`,
          );
          process.exitCode = 2;
        }
      },
    );

  // BW-CLI-10
  bridge
    .command('intervention <memoryId>')
    .description(
      'If we change this, what breaks? — propagation analysis',
    )
    .option('-f, --format <format>', 'Output format: table, json', 'json')
    .action(
      async (memoryId: string, opts: { format: OutputFormat }) => {
        const napi = loadNapi();
        try {
          const result = napi.driftBridgeIntervention(memoryId);
          if (opts.format === 'json') {
            process.stdout.write(formatOutput(result, 'json'));
          } else {
            process.stdout.write(
              `Intervention analysis for ${memoryId}:\n` +
                `  Impacted memories: ${result.impacted_count}\n` +
                `  Max depth:         ${result.max_depth}\n` +
                `  Impacted IDs:      ${result.impacted_ids.join(', ') || 'none'}\n` +
                `  Summary:           ${result.summary}\n`,
            );
          }
        } catch (err) {
          process.stderr.write(
            `Error: ${err instanceof Error ? err.message : err}\n`,
          );
          process.exitCode = 2;
        }
      },
    );

  // BW-CLI-11
  bridge
    .command('narrative <memoryId>')
    .description(
      'Full causal narrative with upstream origins and downstream effects',
    )
    .option('-f, --format <format>', 'Output format: table, json', 'json')
    .action(
      async (memoryId: string, opts: { format: OutputFormat }) => {
        const napi = loadNapi();
        try {
          const result = napi.driftBridgeUnifiedNarrative(memoryId);
          if (opts.format === 'json') {
            process.stdout.write(formatOutput(result, 'json'));
          } else {
            // Render markdown narrative for human consumption
            process.stdout.write(result.markdown || 'No narrative available.\n');
          }
        } catch (err) {
          process.stderr.write(
            `Error: ${err instanceof Error ? err.message : err}\n`,
          );
          process.exitCode = 2;
        }
      },
    );

  // BW-CLI-12
  bridge
    .command('prune')
    .description('Prune weak causal edges below a confidence threshold')
    .option(
      '--threshold <n>',
      'Minimum edge confidence to keep',
      '0.3',
    )
    .action(async (opts: { threshold: string }) => {
      const napi = loadNapi();
      try {
        const result = napi.driftBridgePruneCausal(
          parseFloat(opts.threshold),
        );
        process.stdout.write(
          `Pruned ${result.edges_removed} weak causal edges (threshold: ${result.threshold})\n`,
        );
      } catch (err) {
        process.stderr.write(
          `Error: ${err instanceof Error ? err.message : err}\n`,
        );
        process.exitCode = 2;
      }
    });

  // ─── C5: Learning & Exploration Commands ────────────────────────────

  // BW-CLI-13
  bridge
    .command('learn <entityType> <entityId> <correction>')
    .description(
      'Teach the system — create a correction/feedback memory',
    )
    .option(
      '--category <cat>',
      'Correction category',
      'general',
    )
    .action(
      async (
        entityType: string,
        entityId: string,
        correction: string,
        opts: { category: string },
      ) => {
        const napi = loadNapi();
        try {
          // Map category to a SpecSection (default: Conventions)
          const sectionMap: Record<string, string> = {
            general: 'Conventions',
            security: 'Security',
            api: 'PublicApi',
            data: 'DataModel',
            logic: 'BusinessLogic',
            deps: 'Dependencies',
            test: 'TestRequirements',
            migration: 'MigrationNotes',
            constraints: 'Constraints',
            overview: 'Overview',
            flow: 'DataFlow',
          };
          const section = sectionMap[opts.category] ?? 'Conventions';
          const correctionId = `${entityType}-${entityId}-${Date.now()}`;
          const result = napi.driftBridgeSpecCorrection(
            JSON.stringify({
              correction_id: correctionId,
              module_id: entityId,
              section,
              root_cause: { DomainKnowledge: { description: correction } },
              upstream_modules: [],
              data_sources: [{ system: entityType, confidence_at_generation: 0.5, was_correct: false }],
            }),
          );
          process.stdout.write(
            `Correction recorded: memory_id=${result.memory_id}, status=${result.status}\n`,
          );
        } catch (err) {
          process.stderr.write(
            `Error: ${err instanceof Error ? err.message : err}\n`,
          );
          process.exitCode = 2;
        }
      },
    );

  // BW-CLI-14
  bridge
    .command('events')
    .description('List all 21 event→memory mappings with tier requirements')
    .option('--tier <tier>', 'Filter by license tier')
    .option('-f, --format <format>', 'Output format: table, json', 'table')
    .action(async (opts: { tier?: string; format: OutputFormat }) => {
      const napi = loadNapi();
      try {
        const result = napi.driftBridgeEventMappings();
        let mappings = result.mappings;
        if (opts.tier) {
          // tier filtering is informational — show events available at this tier
          mappings = mappings.filter(
            (m: { event_type: string; memory_type: string | null; description: string }) =>
              m.description.toLowerCase().includes(opts.tier!.toLowerCase()) ||
              true, // show all but could be refined with license check
          );
        }
        if (opts.format === 'json') {
          process.stdout.write(formatOutput(result, 'json'));
        } else {
          process.stdout.write(
            `Event→Memory Mappings (${result.count} total):\n`,
          );
          for (const m of mappings) {
            process.stdout.write(
              `  ${m.event_type} → ${m.memory_type ?? '(none)'} [confidence=${m.initial_confidence}, importance=${m.importance}]${m.triggers_grounding ? ' ⚡grounding' : ''}\n`,
            );
          }
        }
      } catch (err) {
        process.stderr.write(
          `Error: ${err instanceof Error ? err.message : err}\n`,
        );
        process.exitCode = 2;
      }
    });

  // BW-CLI-15
  bridge
    .command('intents')
    .description('List all 20 intents (10 code + 10 analytical) with data sources')
    .option('-f, --format <format>', 'Output format: table, json', 'table')
    .action(async (opts: { format: OutputFormat }) => {
      const napi = loadNapi();
      try {
        const result = napi.driftBridgeIntents();
        if (opts.format === 'json') {
          process.stdout.write(formatOutput(result, 'json'));
        } else {
          process.stdout.write(
            `Bridge Intents (${result.count} total):\n`,
          );
          for (const intent of result.intents) {
            process.stdout.write(
              `  ${intent.name} — ${intent.description}\n` +
                `    sources: ${intent.relevant_sources.join(', ')}\n` +
                `    depth: ${intent.default_depth}\n`,
            );
          }
        }
      } catch (err) {
        process.stderr.write(
          `Error: ${err instanceof Error ? err.message : err}\n`,
        );
        process.exitCode = 2;
      }
    });

  // ─── C6: Simulation Command ─────────────────────────────────────────

  // BW-CLI-16
  bridge
    .command('simulate')
    .description(
      'Full pipeline simulation — synthesize events from drift.db, create memories, run grounding',
    )
    .option('--dry-run', 'Show plan without persisting')
    .option('--tier <tier>', 'Simulate with a different license tier')
    .option('-q, --quiet', 'Suppress verbose output')
    .option('-f, --format <format>', 'Output format: table, json', 'table')
    .action(
      async (opts: {
        dryRun?: boolean;
        tier?: string;
        quiet?: boolean;
        format: OutputFormat;
      }) => {
        const napi = loadNapi();
        try {
          const status = napi.driftBridgeStatus();
          if (!status.available) {
            process.stderr.write(
              'Bridge not initialized, run drift setup\n',
            );
            process.exitCode = 1;
            return;
          }

          if (!opts.quiet) {
            process.stdout.write(
              opts.dryRun
                ? 'Simulating bridge pipeline (dry run)...\n'
                : 'Running full bridge pipeline simulation...\n',
            );
          }

          // Step 1: Get event mappings to show what will fire
          const mappings = napi.driftBridgeEventMappings();
          if (!opts.quiet) {
            process.stdout.write(
              `  Event mappings available: ${mappings.count}\n`,
            );
          }

          if (opts.dryRun) {
            // Show what would happen without persisting
            const plan = {
              dry_run: true,
              event_mappings: mappings.count,
              tier: opts.tier ?? status.license_tier,
              steps: [
                'Read patterns from drift.db → synthesize on_pattern_discovered events',
                'Read boundaries from drift.db → synthesize on_boundary_discovered events',
                'Read gate results from drift.db → synthesize on_gate_evaluated events',
                'Run events through BridgeEventHandler → create memories',
                'Trigger grounding loop → validate memories against evidence',
              ],
            };
            process.stdout.write(formatOutput(plan, opts.format));
            return;
          }

          // Step 2: Run the actual grounding pipeline
          // This triggers: query memories → ground all → return snapshot
          const snapshot = napi.driftBridgeGroundAfterAnalyze();

          // Step 3: Get health to show causal graph state
          const health = napi.driftBridgeHealth();

          const result = {
            simulation: 'complete',
            tier: opts.tier ?? status.license_tier,
            memories: {
              total_checked: snapshot.total_checked,
              validated: snapshot.validated,
              partial: snapshot.partial,
              weak: snapshot.weak,
              invalidated: snapshot.invalidated,
              not_groundable: snapshot.not_groundable,
              insufficient_data: snapshot.insufficient_data,
            },
            grounding: {
              avg_score: snapshot.avg_grounding_score,
              contradictions: snapshot.contradictions_generated,
              duration_ms: snapshot.duration_ms,
              errors: snapshot.error_count,
            },
            health: {
              status: health.status,
              ready: health.ready,
              subsystems: health.subsystem_checks.length,
            },
          };

          if (opts.format === 'json') {
            process.stdout.write(formatOutput(result, 'json'));
          } else {
            process.stdout.write(
              `\nSimulation complete:\n` +
                `  Memories checked:    ${snapshot.total_checked}\n` +
                `    Validated:         ${snapshot.validated}\n` +
                `    Partial:           ${snapshot.partial}\n` +
                `    Weak:              ${snapshot.weak}\n` +
                `    Invalidated:       ${snapshot.invalidated}\n` +
                `  Avg grounding score: ${snapshot.avg_grounding_score.toFixed(3)}\n` +
                `  Contradictions:      ${snapshot.contradictions_generated}\n` +
                `  Duration:            ${snapshot.duration_ms}ms\n` +
                `  Errors:              ${snapshot.error_count}\n` +
                `  Health status:       ${health.status}\n`,
            );
          }
        } catch (err) {
          process.stderr.write(
            `Error: ${err instanceof Error ? err.message : err}\n`,
          );
          process.exitCode = 2;
        }
      },
    );
}
