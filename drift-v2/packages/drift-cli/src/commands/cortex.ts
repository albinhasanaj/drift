/**
 * drift cortex — umbrella command for Cortex memory system (44 subcommands).
 *
 * Delegates to CortexClient for all memory, causal, learning, temporal,
 * multi-agent, and system operations.
 */

import type { Command } from 'commander';
import { CortexClient } from '@drift/cortex';
import * as fs from 'fs';
import * as path from 'path';
import { formatOutput, type OutputFormat } from '../output/index.js';

let cortexClient: CortexClient | null = null;

async function getCortex(dbPath?: string): Promise<CortexClient> {
  if (cortexClient) return cortexClient;

  const resolvedPath = dbPath ?? '.cortex/cortex.db';
  const dir = path.dirname(resolvedPath);

  // Ensure parent directory exists (mirrors setup.ts:82–84)
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  cortexClient = await CortexClient.initialize({
    dbPath: resolvedPath,
  });
  return cortexClient;
}

export function registerCortexCommand(program: Command): void {
  const cortex = program
    .command('cortex')
    .description('Cortex persistent memory system');

  // ─── Status ────────────────────────────────────────────────────────
  cortex
    .command('status')
    .description('Show Cortex health dashboard')
    .option('--db <path>', 'Cortex database path')
    .option('-f, --format <format>', 'Output format: json, table', 'json')
    .action(async (opts: { db?: string; format: OutputFormat }) => {
      try {
        const client = await getCortex(opts.db);
        const [health, consolidation, degradations] = await Promise.all([
          client.healthReport(),
          client.consolidationStatus(),
          client.degradations(),
        ]);
        const result = {
          health,
          consolidation,
          degradation_count: degradations.length,
          degradations,
        };
        process.stdout.write(formatOutput(result, opts.format));
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Memory CRUD ───────────────────────────────────────────────────
  cortex
    .command('search <query>')
    .description('Search memories (hybrid semantic + keyword)')
    .option('--limit <n>', 'Max results', '10')
    .option('-f, --format <format>', 'Output format: json, table', 'json')
    .option('--db <path>', 'Cortex database path')
    .action(async (query: string, opts: { limit: string; format: OutputFormat; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const results = await client.memorySearch(query, parseInt(opts.limit, 10));
        process.stdout.write(formatOutput(results, opts.format));
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  cortex
    .command('get <id>')
    .description('Get a memory by ID')
    .option('--db <path>', 'Cortex database path')
    .action(async (id: string, opts: { db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const memory = await client.memoryGet(id);
        process.stdout.write(JSON.stringify(memory, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  cortex
    .command('list')
    .description('List memories')
    .option('--type <type>', 'Filter by memory type')
    .option('-f, --format <format>', 'Output format: json, table', 'json')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { type?: string; format: OutputFormat; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const memories = await client.memoryList(opts.type as never);
        process.stdout.write(formatOutput(memories, opts.format));
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  cortex
    .command('delete <id>')
    .description('Delete (archive) a memory')
    .option('--db <path>', 'Cortex database path')
    .action(async (id: string, opts: { db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        await client.memoryDelete(id);
        process.stdout.write(JSON.stringify({ id, status: 'deleted' }) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  cortex
    .command('restore <id>')
    .description('Restore an archived memory')
    .option('--db <path>', 'Cortex database path')
    .action(async (id: string, opts: { db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        await client.memoryRestore(id);
        process.stdout.write(JSON.stringify({ id, status: 'restored' }) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Add ─────────────────────────────────────────────────────────────
  cortex
    .command('add <type>')
    .description('Add a memory to Cortex. Content auto-wrapped with type if needed.')
    .requiredOption('--summary <text>', 'Memory summary')
    .requiredOption(
      '--content <json>',
      'Memory content as JSON. Can be {"type":"episodic","data":{...}} or just the data object.',
    )
    .option('--tags <tags>', 'Comma-separated tags')
    .option('--db <path>', 'Cortex database path')
    .action(async (type: string, opts: { summary: string; content: string; tags?: string; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const { registerTools, callTool } = await import('@drift/cortex');
        const registry = registerTools(client);

        let content = JSON.parse(opts.content);

        // Auto-wrap: if content lacks 'type' field, wrap with the memory type argument
        if (!content.type) {
          content = { type, data: content };
        }

        const result = await callTool(registry, 'drift_memory_add', {
          memory_type: type,
          summary: opts.summary,
          content,
          tags: opts.tags?.split(',') ?? [],
        });
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Why / Causal ──────────────────────────────────────────────────
  cortex
    .command('why <id>')
    .description('Explain why a memory exists (causal narrative)')
    .option('--db <path>', 'Cortex database path')
    .action(async (id: string, opts: { db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const result = await client.causalGetWhy(id);
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  cortex
    .command('explain <id>')
    .description('Full memory explanation with causal chain and context')
    .option('--db <path>', 'Cortex database path')
    .action(async (id: string, opts: { db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const [memory, why, related] = await Promise.all([
          client.memoryGet(id),
          client.causalGetWhy(id),
          client.causalTraverse(id),
        ]);
        process.stdout.write(JSON.stringify({ memory, why, related }, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Learning ──────────────────────────────────────────────────────
  cortex
    .command('learn <correction>')
    .description('Learn from a correction')
    .option('--context <ctx>', 'Context for the correction', '')
    .option('--source <src>', 'Source of the correction', 'cli')
    .option('--db <path>', 'Cortex database path')
    .action(async (correction: string, opts: { context: string; source: string; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const result = await client.learn(correction, opts.context, opts.source);
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Predict ───────────────────────────────────────────────────────
  cortex
    .command('predict')
    .description('Predict needed memories for current task')
    .option('--files <files...>', 'Active file paths')
    .option('--intent <intent>', 'Current intent')
    .option('-f, --format <format>', 'Output format: json, table', 'json')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { files?: string[]; intent?: string; format: OutputFormat; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const result = await client.predict(opts.files, undefined, opts.intent);
        process.stdout.write(formatOutput(result, opts.format));
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Sanitize ──────────────────────────────────────────────────────
  cortex
    .command('sanitize <text>')
    .description('Sanitize text by redacting sensitive data')
    .option('--db <path>', 'Cortex database path')
    .action(async (text: string, opts: { db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const result = await client.sanitize(text);
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Cloud ─────────────────────────────────────────────────────────
  cortex
    .command('cloud-sync')
    .description('Trigger cloud sync')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const result = await client.cloudSync();
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  cortex
    .command('cloud-status')
    .description('Show cloud sync status')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const result = await client.cloudStatus();
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Session ───────────────────────────────────────────────────────
  cortex
    .command('session-create')
    .description('Create a new session')
    .option('--id <id>', 'Optional session ID')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { id?: string; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const sessionId = await client.sessionCreate(opts.id);
        process.stdout.write(JSON.stringify({ session_id: sessionId }) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Temporal ──────────────────────────────────────────────────────
  cortex
    .command('time-travel')
    .description('Query knowledge at a point in time')
    .requiredOption('--system-time <time>', 'ISO 8601 system time')
    .requiredOption('--valid-time <time>', 'ISO 8601 valid time')
    .option('--filter <json>', 'Optional JSON filter')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { systemTime: string; validTime: string; filter?: string; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const result = await client.queryAsOf(opts.systemTime, opts.validTime, opts.filter);
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── GC / Decay ────────────────────────────────────────────────────
  cortex
    .command('gc')
    .description('Garbage collection: decay, session cleanup, archival')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const [decay, sessions] = await Promise.all([
          client.decayRun(),
          client.sessionCleanup(),
        ]);
        process.stdout.write(JSON.stringify({ decay, sessions_cleaned: sessions }, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Consolidate ───────────────────────────────────────────────────
  cortex
    .command('consolidate')
    .description('Run memory consolidation')
    .option('--type <type>', 'Memory type to consolidate')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { type?: string; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const result = await client.consolidate(opts.type as never);
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Export / Import ───────────────────────────────────────────────
  cortex
    .command('export')
    .description('Export all memories as JSON')
    .option('--type <type>', 'Filter by memory type')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { type?: string; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const memories = await client.memoryList(opts.type as never);
        process.stdout.write(JSON.stringify(memories, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Agents ────────────────────────────────────────────────────────
  cortex
    .command('agents')
    .description('List registered agents')
    .option('--status <status>', 'Filter by status: active, idle, deregistered')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { status?: string; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const agents = await client.listAgents(opts.status);
        process.stdout.write(JSON.stringify({ agents, count: agents.length }, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Import ──────────────────────────────────────────────────────────
  cortex
    .command('import <file>')
    .description('Import memories from a JSON file')
    .option('--db <path>', 'Cortex database path')
    .action(async (file: string, opts: { db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const { registerTools, callTool } = await import('@drift/cortex');
        const registry = registerTools(client);
        const fs = await import('fs');
        const data = JSON.parse(fs.readFileSync(file, 'utf-8'));
        const result = await callTool(registry, 'drift_cortex_import', { memories: data });
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Metrics ────────────────────────────────────────────────────────
  cortex
    .command('metrics')
    .description('Show system metrics (consolidation, health, cache)')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const [consolidation, health, cache] = await Promise.all([
          client.consolidationMetrics(),
          client.healthMetrics(),
          client.cacheStats(),
        ]);
        process.stdout.write(JSON.stringify({ consolidation, health, cache }, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Reembed ────────────────────────────────────────────────────────
  cortex
    .command('reembed')
    .description('Re-embed memories using the configured provider')
    .option('--type <type>', 'Memory type to re-embed')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { type?: string; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const result = await client.reembed(opts.type as never);
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Timeline ───────────────────────────────────────────────────────
  cortex
    .command('timeline')
    .description('Knowledge evolution timeline')
    .option('--from <time>', 'Start time (ISO 8601)')
    .option('--to <time>', 'End time (ISO 8601)')
    .option('--type <type>', 'Memory type filter')
    .option('--module <mod>', 'Module filter')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { from?: string; to?: string; type?: string; module?: string; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const { registerTools, callTool } = await import('@drift/cortex');
        const registry = registerTools(client);
        const result = await callTool(registry, 'drift_knowledge_timeline', {
          from: opts.from, to: opts.to, memory_type: opts.type, module: opts.module,
        });
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Diff ───────────────────────────────────────────────────────────
  cortex
    .command('diff')
    .description('Compare knowledge between two points in time')
    .requiredOption('--from <time>', 'First time (ISO 8601)')
    .requiredOption('--to <time>', 'Second time (ISO 8601)')
    .option('--scope <scope>', 'Scope filter')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { from: string; to: string; scope?: string; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const result = await client.queryDiff(opts.from, opts.to, opts.scope);
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Replay ─────────────────────────────────────────────────────────
  cortex
    .command('replay <decision-id>')
    .description('Replay a past decision with historical context')
    .option('--budget <n>', 'Token budget')
    .option('--db <path>', 'Cortex database path')
    .action(async (decisionId: string, opts: { budget?: string; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const result = await client.replayDecision(decisionId, opts.budget ? parseInt(opts.budget, 10) : undefined);
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Namespaces ─────────────────────────────────────────────────────
  cortex
    .command('namespaces')
    .description('List or create namespaces')
    .option('--create', 'Create a new namespace')
    .option('--scope <scope>', 'Scope: agent, team, project')
    .option('--name <name>', 'Namespace name')
    .option('--owner <owner>', 'Owner agent ID')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { create?: boolean; scope?: string; name?: string; owner?: string; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        if (opts.create && opts.scope && opts.name && opts.owner) {
          const { registerTools, callTool } = await import('@drift/cortex');
          const registry = registerTools(client);
          const result = await callTool(registry, 'drift_agent_namespace', {
            scope: opts.scope, name: opts.name, owner: opts.owner,
          });
          process.stdout.write(JSON.stringify(result, null, 2) + '\n');
        } else {
          const agents = await client.listAgents();
          process.stdout.write(JSON.stringify({ agents: agents.length, hint: 'Use --create --scope --name --owner to create' }, null, 2) + '\n');
        }
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Provenance ─────────────────────────────────────────────────────
  cortex
    .command('provenance <memory-id>')
    .description('Show provenance chain for a memory')
    .option('--depth <n>', 'Max trace depth', '5')
    .option('--db <path>', 'Cortex database path')
    .action(async (memoryId: string, opts: { depth: string; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const [provenance, trace] = await Promise.all([
          client.getProvenance(memoryId),
          client.traceCrossAgent(memoryId, parseInt(opts.depth, 10)),
        ]);
        process.stdout.write(JSON.stringify({ provenance, cross_agent_trace: trace }, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Decay ──────────────────────────────────────────────────────────
  cortex
    .command('decay')
    .description('Run confidence decay engine')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const result = await client.decayRun();
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Validate ──────────────────────────────────────────────────────
  cortex
    .command('validate')
    .description('Run 4-dimension validation on candidate memories')
    .option('--min <n>', 'Min confidence threshold')
    .option('--max <n>', 'Max confidence threshold')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { min?: string; max?: string; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const result = await client.validationRun(
          opts.min ? parseFloat(opts.min) : undefined,
          opts.max ? parseFloat(opts.max) : undefined,
        );
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Temporal: time-range (CH-17) ─────────────────────────────────
  cortex
    .command('time-range')
    .description('Query memories valid during a time range')
    .requiredOption('--from <time>', 'Start time (ISO 8601)')
    .requiredOption('--to <time>', 'End time (ISO 8601)')
    .option('--mode <mode>', 'Overlap mode: overlaps, contains, contained_by', 'overlaps')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { from: string; to: string; mode: string; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const result = await client.queryRange(opts.from, opts.to, opts.mode);
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Temporal: temporal-causal (CH-18) ────────────────────────────
  cortex
    .command('temporal-causal')
    .description('Temporal-aware causal traversal from a memory')
    .requiredOption('--memory-id <id>', 'Memory ID to traverse from')
    .requiredOption('--as-of <time>', 'Point-in-time for the traversal (ISO 8601)')
    .option('--direction <dir>', 'Traversal direction: forward, backward, both', 'both')
    .option('--depth <n>', 'Max traversal depth', '5')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { memoryId: string; asOf: string; direction: string; depth: string; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const result = await client.queryTemporalCausal(
          opts.memoryId, opts.asOf, opts.direction, parseInt(opts.depth, 10),
        );
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Temporal: view-create (CH-19) ────────────────────────────────
  cortex
    .command('view-create')
    .description('Create a materialized knowledge snapshot')
    .requiredOption('--label <label>', 'View label')
    .requiredOption('--timestamp <time>', 'Snapshot timestamp (ISO 8601)')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { label: string; timestamp: string; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const result = await client.createMaterializedView(opts.label, opts.timestamp);
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Temporal: view-get (CH-20) ───────────────────────────────────
  cortex
    .command('view-get')
    .description('Get a materialized view by label')
    .requiredOption('--label <label>', 'View label')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { label: string; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const result = await client.getMaterializedView(opts.label);
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Temporal: view-list (CH-21) ──────────────────────────────────
  cortex
    .command('view-list')
    .description('List all materialized views')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const result = await client.listMaterializedViews();
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Temporal: knowledge-health (CH-22) ───────────────────────────
  cortex
    .command('knowledge-health')
    .description('Knowledge drift metrics and alerts')
    .option('--window <hours>', 'Drift window in hours')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { window?: string; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const [metrics, alerts] = await Promise.all([
          client.getDriftMetrics(opts.window ? parseInt(opts.window, 10) : undefined),
          client.getDriftAlerts(),
        ]);
        process.stdout.write(JSON.stringify({ metrics, alerts }, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Multi-Agent: agent-register (CH-23) ──────────────────────────
  cortex
    .command('agent-register')
    .description('Register a new AI agent')
    .requiredOption('--name <name>', 'Agent name')
    .option('--capabilities <caps>', 'Comma-separated capabilities')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { name: string; capabilities?: string; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const caps = opts.capabilities?.split(',') ?? [];
        const result = await client.registerAgent(opts.name, caps);
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Multi-Agent: agent-deregister (CH-24) ────────────────────────
  cortex
    .command('agent-deregister')
    .description('Deregister an agent')
    .requiredOption('--agent-id <id>', 'Agent ID to deregister')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { agentId: string; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        await client.deregisterAgent(opts.agentId);
        process.stdout.write(JSON.stringify({ agent_id: opts.agentId, status: 'deregistered' }) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Multi-Agent: agent-get (CH-25) ───────────────────────────────
  cortex
    .command('agent-get')
    .description('Get agent details')
    .requiredOption('--agent-id <id>', 'Agent ID')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { agentId: string; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const result = await client.getAgent(opts.agentId);
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Multi-Agent: agent-share (CH-26) ─────────────────────────────
  cortex
    .command('agent-share')
    .description('Share a memory to a namespace')
    .requiredOption('--memory-id <id>', 'Memory ID to share')
    .requiredOption('--namespace <ns>', 'Target namespace')
    .requiredOption('--agent-id <id>', 'Sharing agent ID')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { memoryId: string; namespace: string; agentId: string; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const result = await client.shareMemory(opts.memoryId, opts.namespace, opts.agentId);
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Multi-Agent: agent-retract (CH-27) ───────────────────────────
  cortex
    .command('agent-retract')
    .description('Retract a shared memory from a namespace')
    .requiredOption('--memory-id <id>', 'Memory ID to retract')
    .requiredOption('--namespace <ns>', 'Namespace to retract from')
    .requiredOption('--agent-id <id>', 'Agent ID performing retraction')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { memoryId: string; namespace: string; agentId: string; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        await client.retractMemory(opts.memoryId, opts.namespace, opts.agentId);
        process.stdout.write(JSON.stringify({ memory_id: opts.memoryId, status: 'retracted' }) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Multi-Agent: agent-sync (CH-28) ──────────────────────────────
  cortex
    .command('agent-sync')
    .description('Sync memories between two agents')
    .requiredOption('--source <id>', 'Source agent ID')
    .requiredOption('--target <id>', 'Target agent ID')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { source: string; target: string; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const result = await client.syncAgents(opts.source, opts.target);
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Multi-Agent: agent-trust (CH-29) ─────────────────────────────
  cortex
    .command('agent-trust')
    .description('Get trust scores for an agent')
    .requiredOption('--agent-id <id>', 'Agent ID')
    .option('--target <id>', 'Target agent ID for pairwise trust')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { agentId: string; target?: string; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const result = await client.getTrust(opts.agentId, opts.target);
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });

  // ─── Multi-Agent: agent-project (CH-30) ───────────────────────────
  cortex
    .command('agent-project')
    .description('Create a memory projection between namespaces')
    .requiredOption('--source-ns <ns>', 'Source namespace')
    .requiredOption('--target-ns <ns>', 'Target namespace')
    .option('--filter <json>', 'Projection filter as JSON')
    .option('--db <path>', 'Cortex database path')
    .action(async (opts: { sourceNs: string; targetNs: string; filter?: string; db?: string }) => {
      try {
        const client = await getCortex(opts.db);
        const config = {
          source_namespace: opts.sourceNs,
          target_namespace: opts.targetNs,
          filter: opts.filter ? JSON.parse(opts.filter) : undefined,
        };
        const result = await client.createProjection(config as never);
        process.stdout.write(JSON.stringify({ projection_id: result }, null, 2) + '\n');
      } catch (err) {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
        process.exitCode = 1;
      }
    });
}
