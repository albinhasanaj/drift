/**
 * Cortex tool registration for the drift MCP server.
 *
 * Bridges the 63 Cortex MCP tools from @drift/cortex into the drift_tool
 * catalog as "cortex" category entries. Each handler lazily gets the
 * CortexClient via getCortex() and delegates to the tool's handler.
 */

import { getCortex } from '../cortex.js';
import type { InternalTool } from '../types.js';

/**
 * CH-31/CH-32: Best-effort bridge notification after cortex memory mutations.
 * When cortex memories change via MCP, notify the bridge so grounding snapshots
 * stay current. Falls back silently if bridge is unavailable.
 */
async function notifyBridgeOfCortexMutation(): Promise<void> {
  try {
    const { loadNapi } = await import('../napi.js');
    const napi = loadNapi();
    const status = napi.driftBridgeStatus();
    if (status.available) {
      napi.driftBridgeGroundAfterAnalyze();
    }
  } catch {
    // Non-fatal — bridge may not be initialized
  }
}

/**
 * Register all Cortex tools into the drift_tool catalog.
 * Tools are prefixed with "cortex_" to avoid name collisions with drift-analysis tools.
 */
export function registerCortexTools(catalog: Map<string, InternalTool>): void {
  // ─── Memory (8) ──────────────────────────────────────────────────
  register(catalog, {
    name: 'cortex_memory_add',
    description: 'Create a new memory with auto-dedup and causal inference.',
    category: 'cortex',
    estimatedTokens: '~200',
    handler: async (p) => {
      const { registerTools } = await import('@drift/cortex');
      const client = getCortex();
      const registry = registerTools(client);
      const result = await callCortexTool(registry, 'drift_memory_add', p);
      await notifyBridgeOfCortexMutation();
      return result;
    },
  });

  register(catalog, {
    name: 'cortex_memory_search',
    description: 'Hybrid search across all memories (semantic + keyword).',
    category: 'cortex',
    estimatedTokens: '~500-2000',
    handler: async (p) => {
      const client = getCortex();
      return client.memorySearch(p.query as string, p.limit as number | undefined);
    },
  });

  register(catalog, {
    name: 'cortex_memory_get',
    description: 'Get a specific memory by ID with full metadata.',
    category: 'cortex',
    estimatedTokens: '~300',
    handler: async (p) => {
      const client = getCortex();
      return client.memoryGet(p.memory_id as string);
    },
  });

  register(catalog, {
    name: 'cortex_memory_update',
    description: 'Update an existing memory. Re-embeds if content changes.',
    category: 'cortex',
    estimatedTokens: '~200',
    handler: async (p) => {
      const { registerTools } = await import('@drift/cortex');
      const client = getCortex();
      const registry = registerTools(client);
      const result = await callCortexTool(registry, 'drift_memory_update', p);
      await notifyBridgeOfCortexMutation();
      return result;
    },
  });

  register(catalog, {
    name: 'cortex_memory_delete',
    description: 'Soft-delete a memory (marks as archived).',
    category: 'cortex',
    estimatedTokens: '~50',
    handler: async (p) => {
      const client = getCortex();
      await client.memoryDelete(p.memory_id as string);
      await notifyBridgeOfCortexMutation();
      return { memory_id: p.memory_id, status: 'deleted' };
    },
  });

  register(catalog, {
    name: 'cortex_memory_list',
    description: 'List memories, optionally filtered by type.',
    category: 'cortex',
    estimatedTokens: '~500-3000',
    handler: async (p) => {
      const client = getCortex();
      return client.memoryList(p.memory_type as never);
    },
  });

  register(catalog, {
    name: 'cortex_memory_link',
    description: 'Link a memory to a pattern, constraint, file, or function.',
    category: 'cortex',
    estimatedTokens: '~100',
    handler: async (p) => {
      const { registerTools } = await import('@drift/cortex');
      const client = getCortex();
      const registry = registerTools(client);
      return callCortexTool(registry, 'drift_memory_link', p);
    },
  });

  register(catalog, {
    name: 'cortex_memory_unlink',
    description: 'Remove a link from a memory.',
    category: 'cortex',
    estimatedTokens: '~100',
    handler: async (p) => {
      const { registerTools } = await import('@drift/cortex');
      const client = getCortex();
      const registry = registerTools(client);
      return callCortexTool(registry, 'drift_memory_unlink', p);
    },
  });

  // ─── Memory: restore (Phase B) ──────────────────────────────────
  register(catalog, {
    name: 'cortex_memory_restore',
    description: 'Restore an archived memory back to active status.',
    category: 'cortex',
    estimatedTokens: '~50',
    handler: async (p) => {
      const client = getCortex();
      await client.memoryRestore(p.memory_id as string);
      return { memory_id: p.memory_id, status: 'restored' };
    },
  });

  // ─── Retrieval (3) ───────────────────────────────────────────────
  register(catalog, {
    name: 'cortex_context',
    description: 'Get intent-weighted context from Cortex memory system.',
    category: 'cortex',
    estimatedTokens: '~500-3000',
    handler: async (p) => {
      const client = getCortex();
      return client.getContext(
        p.focus as string,
        p.active_files as string[] | undefined,
        p.sent_ids as string[] | undefined,
        p.budget as number | undefined,
      );
    },
  });

  register(catalog, {
    name: 'cortex_search',
    description: 'Search Cortex memories with token-budgeted retrieval.',
    category: 'cortex',
    estimatedTokens: '~500-2000',
    handler: async (p) => {
      const client = getCortex();
      return client.search(p.query as string, p.budget as number | undefined);
    },
  });

  register(catalog, {
    name: 'cortex_related',
    description: 'Find causally related memories via graph traversal.',
    category: 'cortex',
    estimatedTokens: '~300-1000',
    handler: async (p) => {
      const client = getCortex();
      return client.causalTraverse(p.memory_id as string);
    },
  });

  // ─── Why / Causal (4) ────────────────────────────────────────────
  register(catalog, {
    name: 'cortex_why',
    description: 'Get causal narrative explaining why something exists.',
    category: 'cortex',
    estimatedTokens: '~500-2000',
    handler: async (p) => {
      const client = getCortex();
      return client.causalGetWhy(p.memory_id as string);
    },
  });

  register(catalog, {
    name: 'cortex_explain',
    description: 'Full memory explanation with causal chain and context.',
    category: 'cortex',
    estimatedTokens: '~500-3000',
    handler: async (p) => {
      const { registerTools } = await import('@drift/cortex');
      const client = getCortex();
      const registry = registerTools(client);
      return callCortexTool(registry, 'drift_explain', p);
    },
  });

  register(catalog, {
    name: 'cortex_counterfactual',
    description: 'Explore counterfactual scenarios for a memory.',
    category: 'cortex',
    estimatedTokens: '~300-1000',
    handler: async (p) => {
      const client = getCortex();
      return client.causalCounterfactual(p.memory_id as string);
    },
  });

  register(catalog, {
    name: 'cortex_intervention',
    description: 'Compute intervention effects on the causal graph.',
    category: 'cortex',
    estimatedTokens: '~300-1000',
    handler: async (p) => {
      const client = getCortex();
      return client.causalIntervention(p.memory_id as string);
    },
  });

  // ─── Causal: infer (Phase B) ────────────────────────────────────
  register(catalog, {
    name: 'cortex_causal_infer',
    description: 'Infer causal relationship between two memories.',
    category: 'cortex',
    estimatedTokens: '~200',
    handler: async (p) => {
      const { registerTools } = await import('@drift/cortex');
      const client = getCortex();
      const registry = registerTools(client);
      return callCortexTool(registry, 'drift_causal_infer', p);
    },
  });

  // ─── Learning (3) ────────────────────────────────────────────────
  register(catalog, {
    name: 'cortex_learn',
    description: 'Learn from a correction or feedback.',
    category: 'cortex',
    estimatedTokens: '~200',
    handler: async (p) => {
      const client = getCortex();
      const result = await client.learn(
        p.correction as string,
        p.context as string,
        p.source as string ?? 'mcp',
      );
      await notifyBridgeOfCortexMutation();
      return result;
    },
  });

  register(catalog, {
    name: 'cortex_feedback',
    description: 'Provide positive/negative feedback on a memory.',
    category: 'cortex',
    estimatedTokens: '~100',
    handler: async (p) => {
      const client = getCortex();
      return client.processFeedback(
        p.memory_id as string,
        p.feedback as string,
        p.is_positive as boolean ?? true,
      );
    },
  });

  register(catalog, {
    name: 'cortex_validate',
    description: 'Get memories that need human validation.',
    category: 'cortex',
    estimatedTokens: '~300-1500',
    handler: async (p) => {
      const client = getCortex();
      return client.getValidationCandidates(
        p.min_confidence as number | undefined,
        p.max_confidence as number | undefined,
      );
    },
  });

  // ─── Generation (2) ──────────────────────────────────────────────
  register(catalog, {
    name: 'cortex_gen_context',
    description: 'Build token-budgeted generation context for an AI task.',
    category: 'cortex',
    estimatedTokens: '~500-3000',
    handler: async (p) => {
      const client = getCortex();
      return client.buildGenerationContext(
        p.focus as string,
        p.active_files as string[] | undefined,
        p.budget as number | undefined,
        p.sent_ids as string[] | undefined,
      );
    },
  });

  register(catalog, {
    name: 'cortex_gen_outcome',
    description: 'Track whether generated output was useful (feedback loop).',
    category: 'cortex',
    estimatedTokens: '~50',
    handler: async (p) => {
      const client = getCortex();
      await client.trackOutcome(
        p.memory_ids as string[],
        p.was_useful as boolean,
        p.session_id as string | undefined,
      );
      return { status: 'tracked' };
    },
  });

  // ─── System (8) ──────────────────────────────────────────────────
  register(catalog, {
    name: 'cortex_status',
    description: 'Cortex health dashboard — subsystem status, metrics, degradations.',
    category: 'cortex',
    estimatedTokens: '~300',
    handler: async () => {
      const client = getCortex();
      const [health, consolidation, degradations] = await Promise.all([
        client.healthReport(),
        client.consolidationStatus(),
        client.degradations(),
      ]);
      return { health, consolidation, degradation_count: degradations.length, degradations };
    },
  });

  register(catalog, {
    name: 'cortex_metrics',
    description: 'Cortex system metrics — consolidation, health, cache stats.',
    category: 'cortex',
    estimatedTokens: '~300',
    handler: async () => {
      const client = getCortex();
      const [consolidation, health, cache] = await Promise.all([
        client.consolidationMetrics(),
        client.healthMetrics(),
        client.cacheStats(),
      ]);
      return { consolidation, health, cache };
    },
  });

  register(catalog, {
    name: 'cortex_consolidate',
    description: 'Run memory consolidation (merge similar episodic → semantic).',
    category: 'cortex',
    estimatedTokens: '~200',
    handler: async (p) => {
      const client = getCortex();
      return client.consolidate(p.memory_type as never);
    },
  });

  register(catalog, {
    name: 'cortex_validate_system',
    description: 'Run 4-dimension validation on candidate memories.',
    category: 'cortex',
    estimatedTokens: '~300-1000',
    handler: async (p) => {
      const client = getCortex();
      return client.validationRun(
        p.min_confidence as number | undefined,
        p.max_confidence as number | undefined,
      );
    },
  });

  register(catalog, {
    name: 'cortex_gc',
    description: 'Garbage collection: decay → cleanup sessions → archive stale memories.',
    category: 'cortex',
    estimatedTokens: '~100',
    handler: async () => {
      const client = getCortex();
      const [decay, sessions] = await Promise.all([
        client.decayRun(),
        client.sessionCleanup(),
      ]);
      return { decay, sessions_cleaned: sessions };
    },
  });

  register(catalog, {
    name: 'cortex_export',
    description: 'Export all memories as JSON array.',
    category: 'cortex',
    estimatedTokens: '~500-5000',
    handler: async (p) => {
      const client = getCortex();
      return client.memoryList(p.memory_type as never);
    },
  });

  register(catalog, {
    name: 'cortex_import',
    description: 'Import memories from JSON array.',
    category: 'cortex',
    estimatedTokens: '~200',
    handler: async (p) => {
      const { registerTools } = await import('@drift/cortex');
      const client = getCortex();
      const registry = registerTools(client);
      return callCortexTool(registry, 'drift_cortex_import', p);
    },
  });

  register(catalog, {
    name: 'cortex_reembed',
    description: 'Re-embed memories using the configured provider chain.',
    category: 'cortex',
    estimatedTokens: '~100',
    handler: async (p) => {
      const client = getCortex();
      return client.reembed(p.memory_type as never);
    },
  });

  // ─── Privacy (Phase B) ──────────────────────────────────────────
  register(catalog, {
    name: 'cortex_privacy_sanitize',
    description: 'Sanitize text by redacting sensitive data (emails, keys, etc.).',
    category: 'cortex',
    estimatedTokens: '~200',
    handler: async (p) => {
      const client = getCortex();
      return client.sanitize(p.text as string);
    },
  });

  register(catalog, {
    name: 'cortex_privacy_stats',
    description: 'Get privacy pattern failure statistics.',
    category: 'cortex',
    estimatedTokens: '~100',
    handler: async () => {
      const client = getCortex();
      return client.patternStats();
    },
  });

  // ─── Cloud (Phase B + Phase 6 data pipeline) ───────────────────
  register(catalog, {
    name: 'cortex_cloud_sync',
    description: 'Sync local analysis data and cortex memories to Drift Cloud. Returns cortex sync status and data pipeline push results.',
    category: 'cortex',
    estimatedTokens: '~200',
    handler: async (p) => {
      const client = getCortex();
      const cortexResult = await client.cloudSync();

      // Also trigger data pipeline sync if configured
      let pipelineResult: Record<string, unknown> = { skipped: true };
      try {
        const { SyncClient, defaultSyncState, isLoggedIn, CLOUD_CONFIG_PATH } = await import('@drift/core/cloud');
        const { readFile, writeFile, mkdir } = await import('node:fs/promises');
        const { join } = await import('node:path');
        const { homedir } = await import('node:os');

        if (await isLoggedIn()) {
          const configPath = join(homedir(), CLOUD_CONFIG_PATH);
          const config = JSON.parse(await readFile(configPath, 'utf-8'));
          const statePath = join(homedir(), '.drift/cloud-sync-state.json');
          let syncState;
          try { syncState = JSON.parse(await readFile(statePath, 'utf-8')); } catch { syncState = defaultSyncState(); }

          const fullSync = p.full === true;
          const reader = { readRows: async () => [] as Record<string, unknown>[], getMaxCursor: async () => 0 };
          const syncClient = new SyncClient(config, process.cwd());
          const result = await syncClient.push(reader, fullSync ? null : syncState, undefined, fullSync);

          const stateDir = statePath.substring(0, statePath.lastIndexOf('/'));
          await mkdir(stateDir, { recursive: true });
          await writeFile(statePath, JSON.stringify(result.syncState, null, 2));

          pipelineResult = { success: result.success, totalRows: result.totalRows, durationMs: result.durationMs };
        }
      } catch { /* @drift/core/cloud not available */ }

      return { cortex: cortexResult, dataPipeline: pipelineResult };
    },
  });

  register(catalog, {
    name: 'cortex_cloud_status',
    description: 'Get cloud sync status — cortex online/offline state plus data pipeline sync status, last sync time, and cursors.',
    category: 'cortex',
    estimatedTokens: '~150',
    handler: async () => {
      const client = getCortex();
      const cortexStatus = await client.cloudStatus();

      let pipelineStatus: Record<string, unknown> = { available: false };
      try {
        const { isLoggedIn, CLOUD_CONFIG_PATH } = await import('@drift/core/cloud');
        const { readFile } = await import('node:fs/promises');
        const { join } = await import('node:path');
        const { homedir } = await import('node:os');

        const loggedIn = await isLoggedIn();
        const configPath = join(homedir(), CLOUD_CONFIG_PATH);
        const statePath = join(homedir(), '.drift/cloud-sync-state.json');
        let config = null;
        try { config = JSON.parse(await readFile(configPath, 'utf-8')); } catch { /* */ }
        let syncState = null;
        try { syncState = JSON.parse(await readFile(statePath, 'utf-8')); } catch { /* */ }

        pipelineStatus = {
          available: true,
          authenticated: loggedIn,
          configured: config !== null,
          projectId: config?.projectId ?? null,
          lastSyncAt: syncState?.lastSyncAt ?? null,
          lastSyncRowCount: syncState?.lastSyncRowCount ?? 0,
        };
      } catch { /* @drift/core/cloud not available */ }

      return { cortex: cortexStatus, dataPipeline: pipelineStatus };
    },
  });

  register(catalog, {
    name: 'cortex_cloud_resolve',
    description: 'Resolve a cloud sync conflict for a specific memory.',
    category: 'cortex',
    estimatedTokens: '~100',
    handler: async (p) => {
      const client = getCortex();
      return client.cloudResolveConflict(
        p.memory_id as string,
        p.resolution as string,
      );
    },
  });

  // ─── Session (Phase B) ──────────────────────────────────────────
  register(catalog, {
    name: 'cortex_session_create',
    description: 'Create a new Cortex session for tracking memory interactions.',
    category: 'cortex',
    estimatedTokens: '~50',
    handler: async (p) => {
      const client = getCortex();
      const sessionId = await client.sessionCreate(p.session_id as string | undefined);
      return { session_id: sessionId };
    },
  });

  register(catalog, {
    name: 'cortex_session_get',
    description: 'Get session context including loaded memories and patterns.',
    category: 'cortex',
    estimatedTokens: '~300',
    handler: async (p) => {
      const client = getCortex();
      return client.sessionGet(p.session_id as string);
    },
  });

  register(catalog, {
    name: 'cortex_session_analytics',
    description: 'Get session analytics: token counts, query counts, loaded counts.',
    category: 'cortex',
    estimatedTokens: '~200',
    handler: async (p) => {
      const client = getCortex();
      return client.sessionAnalytics(p.session_id as string);
    },
  });

  // ─── Prediction (2) ──────────────────────────────────────────────
  register(catalog, {
    name: 'cortex_predict',
    description: 'Predict which memories will be needed for the current task.',
    category: 'cortex',
    estimatedTokens: '~200',
    handler: async (p) => {
      const client = getCortex();
      return client.predict(
        p.active_files as string[] | undefined,
        p.recent_queries as string[] | undefined,
        p.intent as string | undefined,
      );
    },
  });

  register(catalog, {
    name: 'cortex_preload',
    description: 'Preload predicted memories into cache for faster retrieval.',
    category: 'cortex',
    estimatedTokens: '~100',
    handler: async (p) => {
      const client = getCortex();
      return client.preload(p.active_files as string[] | undefined);
    },
  });

  // ─── Temporal (5) ────────────────────────────────────────────────
  register(catalog, {
    name: 'cortex_time_travel',
    description: 'Query knowledge base as it existed at a specific point in time.',
    category: 'cortex',
    estimatedTokens: '~500-3000',
    handler: async (p) => {
      const client = getCortex();
      return client.queryAsOf(
        p.system_time as string,
        p.valid_time as string,
        p.filter as string | undefined,
      );
    },
  });

  register(catalog, {
    name: 'cortex_time_diff',
    description: 'Compare knowledge between two points in time.',
    category: 'cortex',
    estimatedTokens: '~500-3000',
    handler: async (p) => {
      const client = getCortex();
      return client.queryDiff(
        p.time_a as string,
        p.time_b as string,
        p.scope as string | undefined,
      );
    },
  });

  register(catalog, {
    name: 'cortex_time_replay',
    description: 'Replay a past decision with historical context and hindsight.',
    category: 'cortex',
    estimatedTokens: '~500-3000',
    handler: async (p) => {
      const client = getCortex();
      return client.replayDecision(
        p.decision_id as string,
        p.budget as number | undefined,
      );
    },
  });

  register(catalog, {
    name: 'cortex_knowledge_health',
    description: 'Knowledge drift metrics and alerts.',
    category: 'cortex',
    estimatedTokens: '~300-1000',
    handler: async (p) => {
      const client = getCortex();
      const [metrics, alerts] = await Promise.all([
        client.getDriftMetrics(p.window_hours as number | undefined),
        client.getDriftAlerts(),
      ]);
      return { metrics, alerts };
    },
  });

  register(catalog, {
    name: 'cortex_knowledge_timeline',
    description: 'Knowledge evolution timeline with drift snapshots.',
    category: 'cortex',
    estimatedTokens: '~300-1500',
    handler: async (p) => {
      const { registerTools } = await import('@drift/cortex');
      const client = getCortex();
      const registry = registerTools(client);
      return callCortexTool(registry, 'drift_knowledge_timeline', p);
    },
  });

  // ─── Temporal: range + causal + views (Phase B) ────────────────
  register(catalog, {
    name: 'cortex_time_range',
    description: 'Query memories valid during a time range.',
    category: 'cortex',
    estimatedTokens: '~500-3000',
    handler: async (p) => {
      const client = getCortex();
      return client.queryRange(
        p.from as string,
        p.to as string,
        p.mode as string ?? 'overlaps',
      );
    },
  });

  register(catalog, {
    name: 'cortex_temporal_causal',
    description: 'Temporal-aware causal traversal from a memory at a point in time.',
    category: 'cortex',
    estimatedTokens: '~300-1500',
    handler: async (p) => {
      const client = getCortex();
      return client.queryTemporalCausal(
        p.memory_id as string,
        p.as_of as string,
        p.direction as string ?? 'both',
        (p.depth as number) ?? 5,
      );
    },
  });

  register(catalog, {
    name: 'cortex_view_create',
    description: 'Create a materialized view (snapshot) of the knowledge base.',
    category: 'cortex',
    estimatedTokens: '~100',
    handler: async (p) => {
      const client = getCortex();
      return client.createMaterializedView(
        p.label as string,
        p.timestamp as string,
      );
    },
  });

  register(catalog, {
    name: 'cortex_view_get',
    description: 'Get a materialized view by label.',
    category: 'cortex',
    estimatedTokens: '~200',
    handler: async (p) => {
      const client = getCortex();
      return client.getMaterializedView(p.label as string);
    },
  });

  register(catalog, {
    name: 'cortex_view_list',
    description: 'List all materialized views.',
    category: 'cortex',
    estimatedTokens: '~200-500',
    handler: async () => {
      const client = getCortex();
      return client.listMaterializedViews();
    },
  });

  // ─── Multi-Agent (5 + 6 Phase B) ────────────────────────────────
  register(catalog, {
    name: 'cortex_agent_register',
    description: 'Register a new AI agent with capabilities.',
    category: 'cortex',
    estimatedTokens: '~200',
    handler: async (p) => {
      const client = getCortex();
      return client.registerAgent(
        p.name as string,
        p.capabilities as string[],
      );
    },
  });

  register(catalog, {
    name: 'cortex_agent_share',
    description: 'Share a memory to another agent\'s namespace.',
    category: 'cortex',
    estimatedTokens: '~200',
    handler: async (p) => {
      const client = getCortex();
      return client.shareMemory(
        p.memory_id as string,
        p.target_namespace as string,
        p.agent_id as string,
      );
    },
  });

  register(catalog, {
    name: 'cortex_agent_project',
    description: 'Create a memory projection between namespaces.',
    category: 'cortex',
    estimatedTokens: '~200',
    handler: async (p) => {
      const { registerTools } = await import('@drift/cortex');
      const client = getCortex();
      const registry = registerTools(client);
      return callCortexTool(registry, 'drift_agent_project', p);
    },
  });

  register(catalog, {
    name: 'cortex_agent_provenance',
    description: 'Trace the provenance chain of a memory across agents.',
    category: 'cortex',
    estimatedTokens: '~300-1000',
    handler: async (p) => {
      const client = getCortex();
      const [provenance, trace] = await Promise.all([
        client.getProvenance(p.memory_id as string),
        client.traceCrossAgent(p.memory_id as string, (p.max_depth as number) ?? 5),
      ]);
      return { provenance, cross_agent_trace: trace };
    },
  });

  register(catalog, {
    name: 'cortex_agent_trust',
    description: 'Get trust scores for an agent.',
    category: 'cortex',
    estimatedTokens: '~200',
    handler: async (p) => {
      const client = getCortex();
      return client.getTrust(
        p.agent_id as string,
        p.target_agent as string | undefined,
      );
    },
  });

  // ─── Multi-Agent Phase B additions ──────────────────────────────
  register(catalog, {
    name: 'cortex_agent_deregister',
    description: 'Deregister an agent from the multi-agent system.',
    category: 'cortex',
    estimatedTokens: '~50',
    handler: async (p) => {
      const client = getCortex();
      await client.deregisterAgent(p.agent_id as string);
      return { agent_id: p.agent_id, status: 'deregistered' };
    },
  });

  register(catalog, {
    name: 'cortex_agent_get',
    description: 'Get agent registration details.',
    category: 'cortex',
    estimatedTokens: '~200',
    handler: async (p) => {
      const client = getCortex();
      return client.getAgent(p.agent_id as string);
    },
  });

  register(catalog, {
    name: 'cortex_agent_list',
    description: 'List all registered agents, optionally filtered by status.',
    category: 'cortex',
    estimatedTokens: '~300-1000',
    handler: async (p) => {
      const client = getCortex();
      return client.listAgents(p.status_filter as string | undefined);
    },
  });

  register(catalog, {
    name: 'cortex_agent_namespace',
    description: 'Create a new namespace for agent memory isolation.',
    category: 'cortex',
    estimatedTokens: '~100',
    handler: async (p) => {
      const { registerTools } = await import('@drift/cortex');
      const client = getCortex();
      const registry = registerTools(client);
      return callCortexTool(registry, 'drift_agent_namespace', p);
    },
  });

  register(catalog, {
    name: 'cortex_agent_retract',
    description: 'Retract (unshare) a previously shared memory from a namespace.',
    category: 'cortex',
    estimatedTokens: '~100',
    handler: async (p) => {
      const client = getCortex();
      await client.retractMemory(
        p.memory_id as string,
        p.namespace as string,
        p.agent_id as string,
      );
      return { memory_id: p.memory_id, status: 'retracted' };
    },
  });

  register(catalog, {
    name: 'cortex_agent_sync',
    description: 'Sync memories between two agents.',
    category: 'cortex',
    estimatedTokens: '~100',
    handler: async (p) => {
      const client = getCortex();
      return client.syncAgents(
        p.source_agent as string,
        p.target_agent as string,
      );
    },
  });

  // ─── Missing tools (CH-13/CH-14) ──────────────────────────────
  register(catalog, {
    name: 'cortex_analyze_correction',
    description: 'Analyze a correction for learning insights without applying it.',
    category: 'cortex',
    estimatedTokens: '~200',
    handler: async (p) => {
      const client = getCortex();
      return client.analyzeCorrection(
        p.correction as string,
        p.context as string ?? '',
        p.source as string ?? 'mcp',
      );
    },
  });

  register(catalog, {
    name: 'cortex_configure',
    description: 'Get or update Cortex runtime configuration.',
    category: 'cortex',
    estimatedTokens: '~100',
    handler: async () => {
      const client = getCortex();
      return client.configure();
    },
  });
}

/** Read-only Cortex tools safe to cache. */
export const CORTEX_CACHEABLE_TOOLS = new Set([
  'cortex_status', 'cortex_metrics', 'cortex_search', 'cortex_context',
  'cortex_why', 'cortex_explain', 'cortex_related', 'cortex_counterfactual',
  'cortex_intervention', 'cortex_time_travel', 'cortex_time_diff',
  'cortex_time_replay', 'cortex_knowledge_health', 'cortex_knowledge_timeline',
  'cortex_agent_provenance', 'cortex_agent_trust', 'cortex_validate',
  'cortex_memory_get', 'cortex_memory_list', 'cortex_memory_search',
  'cortex_predict', 'cortex_preload', 'cortex_export',
  'cortex_gen_context', 'cortex_validate_system',
  // Phase B additions — read-only
  'cortex_causal_infer', 'cortex_privacy_stats', 'cortex_cloud_status',
  'cortex_session_get', 'cortex_session_analytics', 'cortex_time_range',
  'cortex_temporal_causal', 'cortex_view_get', 'cortex_view_list',
  'cortex_agent_get', 'cortex_agent_list',
  // CH-15: new read-only tools
  'cortex_analyze_correction', 'cortex_configure',
]);

/** Mutation Cortex tools — cache should be invalidated after these. */
export const CORTEX_MUTATION_TOOLS = new Set([
  'cortex_memory_add', 'cortex_memory_update', 'cortex_memory_delete',
  'cortex_memory_link', 'cortex_memory_unlink', 'cortex_learn',
  'cortex_feedback', 'cortex_consolidate', 'cortex_gc', 'cortex_import',
  'cortex_reembed', 'cortex_agent_register', 'cortex_agent_share',
  'cortex_agent_project', 'cortex_gen_outcome',
  // Phase B additions — mutations
  'cortex_memory_restore', 'cortex_privacy_sanitize', 'cortex_cloud_sync',
  'cortex_cloud_resolve', 'cortex_session_create', 'cortex_view_create',
  'cortex_agent_deregister', 'cortex_agent_namespace',
  'cortex_agent_retract', 'cortex_agent_sync',
]);

function register(catalog: Map<string, InternalTool>, tool: InternalTool): void {
  catalog.set(tool.name, tool);
}

/**
 * Helper to call a tool from the @drift/cortex tool registry by name.
 */
async function callCortexTool(
  registry: ReadonlyMap<string, { handler: (args: Record<string, unknown>) => Promise<unknown> }>,
  name: string,
  params: Record<string, unknown>,
): Promise<unknown> {
  const tool = registry.get(name);
  if (!tool) {
    throw new Error(`Cortex tool "${name}" not found in registry`);
  }
  return tool.handler(params);
}
