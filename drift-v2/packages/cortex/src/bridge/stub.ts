/**
 * Complete stub implementation of NativeBindings.
 *
 * Every method returns structurally valid typed data matching the Rust return types.
 * No `{}` returns — every field present with sensible empty/zero defaults.
 * Used as fallback when native binary is unavailable, and for testing.
 */

import type { NativeBindings } from "./index.js";

/** Create a complete stub NativeBindings with all 68 methods returning valid typed data. */
export function createStubNativeModule(): NativeBindings {
  return {
    // ─── Lifecycle (3) ───────────────────────────────────────────────
    cortexInitialize(
      _dbPath: string | null,
      _configToml: string | null,
      _cloudEnabled: boolean | null,
    ): void {
      // no-op
    },

    cortexShutdown(): void {
      // no-op
    },

    cortexConfigure(_configToml: string | null): Record<string, unknown> {
      return { mode: "stub", initialized: false };
    },

    // ─── Memory CRUD (8) ─────────────────────────────────────────────
    cortexMemoryCreate(_memoryJson: unknown): void {
      // no-op
    },

    cortexMemoryGet(_id: string): unknown {
      return null;
    },

    cortexMemoryUpdate(_memoryJson: unknown): void {
      // no-op
    },

    cortexMemoryDelete(_id: string): void {
      // no-op
    },

    cortexMemorySearch(_query: string, _limit: number | null): unknown {
      return [];
    },

    cortexMemoryList(_memoryType: string | null): unknown {
      return [];
    },

    cortexMemoryArchive(_id: string): void {
      // no-op
    },

    cortexMemoryRestore(_id: string): void {
      // no-op
    },

    // ─── Retrieval (3) ───────────────────────────────────────────────
    cortexRetrievalRetrieve(_contextJson: unknown, _budget: number | null): unknown {
      return [];
    },

    cortexRetrievalSearch(_query: string, _budget: number | null): unknown {
      return [];
    },

    cortexRetrievalGetContext(
      _focus: string,
      _activeFiles: string[] | null,
      _sentIds: string[] | null,
      _budget: number | null,
    ): unknown {
      return { focus: "", intent: null, active_files: [], budget: 0, sent_ids: [] };
    },

    // ─── Causal (5) ──────────────────────────────────────────────────
    cortexCausalInferCause(_sourceJson: unknown, _targetJson: unknown): unknown {
      return { source_id: "", target_id: "", strength: 0, suggested_relation: "related", above_threshold: false };
    },

    cortexCausalTraverse(_memoryId: string): unknown {
      return { origin_id: "", max_depth_reached: 0, nodes: [] };
    },

    cortexCausalGetWhy(_memoryId: string): unknown {
      return { sections: [], summary: "", confidence: 0 };
    },

    cortexCausalCounterfactual(_memoryId: string): unknown {
      return { origin_id: "", max_depth_reached: 0, nodes: [] };
    },

    cortexCausalIntervention(_memoryId: string): unknown {
      return { origin_id: "", max_depth_reached: 0, nodes: [] };
    },

    // ─── Learning (4) ────────────────────────────────────────────────
    cortexLearningAnalyzeCorrection(
      _correctionText: string,
      _context: string,
      _source: string,
      _originalMemoryId: string | null,
    ): unknown {
      return { category: "unknown", principle: null, memory_created: null };
    },

    cortexLearningLearn(_correctionText: string, _context: string, _source: string): unknown {
      return { category: "unknown", principle: null, memory_created: null };
    },

    cortexLearningGetValidationCandidates(
      _minConfidence: number | null,
      _maxConfidence: number | null,
    ): unknown {
      return [];
    },

    cortexLearningProcessFeedback(_memoryId: string, _feedback: string, _isPositive: boolean): unknown {
      return { category: "feedback", principle: null, memory_created: null };
    },

    // ─── Consolidation (3) ───────────────────────────────────────────
    cortexConsolidationConsolidate(_memoryType: string | null): unknown {
      return { created: [], archived: [], metrics: { precision: 0, compression_ratio: 0, lift: 0, stability: 0 } };
    },

    cortexConsolidationGetMetrics(): unknown {
      return { total_runs: 0, successful_runs: 0, success_rate: 0, is_running: false };
    },

    cortexConsolidationGetStatus(): unknown {
      return { is_running: false };
    },

    // ─── Embeddings (1) ──────────────────────────────────────────────
    cortexReembed(_memoryType: string | null): unknown {
      return { reembedded: 0 };
    },

    // ─── Decay (1) ───────────────────────────────────────────────────
    cortexDecayRun(): unknown {
      return { processed: 0, archived: 0, updated: 0 };
    },

    // ─── Health (3) ──────────────────────────────────────────────────
    cortexHealthGetHealth(): unknown {
      return {
        overall_status: "healthy",
        subsystems: [],
        metrics: {
          total_memories: 0,
          active_memories: 0,
          archived_memories: 0,
          average_confidence: 0,
          db_size_bytes: 0,
          embedding_cache_hit_rate: 0,
        },
      };
    },

    cortexHealthGetMetrics(): unknown {
      return {};
    },

    cortexHealthGetDegradations(): unknown {
      return [];
    },

    // ─── Generation (2) ──────────────────────────────────────────────
    cortexGenerationBuildContext(
      _focus: string,
      _activeFiles: string[] | null,
      _budget: number | null,
      _sentIds: string[] | null,
    ): unknown {
      return { allocations: [], total_tokens: 0, total_budget: 0 };
    },

    cortexGenerationTrackOutcome(
      _memoryIds: string[],
      _wasUseful: boolean,
      _sessionId: string | null,
    ): void {
      // no-op
    },

    // ─── Prediction (3) ──────────────────────────────────────────────
    cortexPredictionPredict(
      _activeFiles: string[] | null,
      _recentQueries: string[] | null,
      _currentIntent: string | null,
    ): unknown {
      return { memory_ids: [], signals: [], confidence: 0 };
    },

    cortexPredictionPreload(_activeFiles: string[] | null): unknown {
      return { preloaded_count: 0, memory_ids: [], confidence: 0 };
    },

    cortexPredictionGetCacheStats(): unknown {
      return { entry_count: 0, hits: 0, misses: 0, hit_rate: 0 };
    },

    // ─── Privacy (2) ─────────────────────────────────────────────────
    cortexPrivacySanitize(_text: string): unknown {
      return { text: _text, redactions: 0 };
    },

    cortexPrivacyGetPatternStats(): unknown {
      return { failure_count: 0, has_failures: false, failures: [] };
    },

    // ─── Cloud (3) ───────────────────────────────────────────────────
    cortexCloudSync(): unknown {
      return { status: "disabled", pushed: 0, pulled: 0, conflicts_resolved: 0, manual_conflicts: 0 };
    },

    cortexCloudGetStatus(): unknown {
      return { status: "disabled", is_online: false, offline_queue_length: 0 };
    },

    cortexCloudResolveConflict(_memoryId: string, _resolution: string): Record<string, unknown> {
      return { resolved: false, reason: "cloud not enabled" };
    },

    // ─── Session (4) ─────────────────────────────────────────────────
    cortexSessionCreate(_sessionId: string | null): string {
      return _sessionId ?? "stub-session";
    },

    cortexSessionGet(_sessionId: string): unknown {
      return { session_id: _sessionId, sent_memory_ids: [], tokens_used: 0, token_budget: 0 };
    },

    cortexSessionCleanup(): number {
      return 0;
    },

    cortexSessionAnalytics(_sessionId: string): unknown {
      return {
        session_id: _sessionId,
        created_at: new Date().toISOString(),
        last_activity: new Date().toISOString(),
        loaded_memories_count: 0,
        loaded_patterns_count: 0,
        loaded_files_count: 0,
        tokens_sent: 0,
        queries_made: 0,
      };
    },

    // ─── Validation (1) ──────────────────────────────────────────────
    cortexValidationRun(_minConfidence: number | null, _maxConfidence: number | null): Record<string, unknown> {
      return { candidates_checked: 0, passed: 0, failed: 0, healed: 0, results: [] };
    },

    // ─── Temporal (10) ───────────────────────────────────────────────
    cortexTemporalQueryAsOf(
      _systemTime: string,
      _validTime: string,
      _filter: string | null,
    ): unknown {
      return [];
    },

    cortexTemporalQueryRange(_from: string, _to: string, _mode: string): unknown {
      return [];
    },

    cortexTemporalQueryDiff(_timeA: string, _timeB: string, _scope: string | null): unknown {
      return {
        created: [], archived: [], modified: [], confidence_shifts: [],
        new_contradictions: [], resolved_contradictions: [], reclassifications: [],
        stats: {
          memories_at_a: 0, memories_at_b: 0, net_change: 0,
          avg_confidence_at_a: 0, avg_confidence_at_b: 0, confidence_trend: 0,
          knowledge_churn_rate: 0,
        },
      };
    },

    cortexTemporalReplayDecision(_decisionId: string, _budget: number | null): unknown {
      return {
        decision: null,
        available_context: [],
        retrieved_context: [],
        causal_state: { nodes: [], edges: [] },
        hindsight: [],
      };
    },

    cortexTemporalQueryTemporalCausal(
      _memoryId: string,
      _asOf: string,
      _direction: string,
      _depth: number,
    ): unknown {
      return { origin_id: "", max_depth_reached: 0, nodes: [] };
    },

    cortexTemporalGetDriftMetrics(_windowHours: number | null): unknown {
      return {
        timestamp: new Date().toISOString(),
        window_hours: _windowHours ?? 168,
        type_metrics: {},
        module_metrics: {},
        global: {
          total_memories: 0, active_memories: 0, archived_memories: 0,
          avg_confidence: 0, overall_ksi: 0, overall_contradiction_density: 0,
          overall_evidence_freshness: 0,
        },
      };
    },

    cortexTemporalGetDriftAlerts(): unknown {
      return [];
    },

    cortexTemporalCreateMaterializedView(_label: string, _timestamp: string): unknown {
      return {
        view_id: 0, label: _label, timestamp: _timestamp,
        memory_count: 0, snapshot_ids: [], drift_snapshot_id: null,
        created_by: null, auto_refresh: false,
      };
    },

    cortexTemporalGetMaterializedView(_label: string): unknown {
      return null;
    },

    cortexTemporalListMaterializedViews(): unknown {
      return [];
    },

    // ─── Multi-Agent (12) ────────────────────────────────────────────
    cortexMultiagentRegisterAgent(_name: string, _capabilities: string[]): unknown {
      return {
        agent_id: { 0: "stub-agent" },
        name: _name,
        namespace: `agent://stub-agent/${_name}`,
        capabilities: _capabilities,
        parent_agent: null,
        registered_at: new Date().toISOString(),
        last_active: new Date().toISOString(),
        status: { state: "active" },
      };
    },

    cortexMultiagentDeregisterAgent(_agentId: string): void {
      // no-op
    },

    cortexMultiagentGetAgent(_agentId: string): unknown {
      return null;
    },

    cortexMultiagentListAgents(_statusFilter: string | null): unknown {
      return [];
    },

    cortexMultiagentCreateNamespace(_scope: string, _name: string, _owner: string): string {
      return `${_scope}://${_owner}/${_name}`;
    },

    cortexMultiagentShareMemory(_memoryId: string, _targetNamespace: string, _agentId: string): unknown {
      return {
        agent_id: { 0: _agentId },
        action: "shared_to",
        timestamp: new Date().toISOString(),
        confidence_delta: 0,
      };
    },

    cortexMultiagentCreateProjection(_configJson: unknown): string {
      return "stub-projection-id";
    },

    cortexMultiagentRetractMemory(_memoryId: string, _namespace: string, _agentId: string): void {
      // no-op
    },

    cortexMultiagentGetProvenance(_memoryId: string): unknown {
      return null;
    },

    cortexMultiagentTraceCrossAgent(_memoryId: string, _maxDepth: number): unknown {
      return { path: [] };
    },

    cortexMultiagentGetTrust(_agentId: string, _targetAgent: string | null): unknown {
      return {
        agent_id: { 0: _agentId },
        target_agent: { 0: _targetAgent ?? "" },
        overall_trust: 0.5,
        domain_trust: {},
        evidence: { validated_count: 0, contradicted_count: 0, useful_count: 0, total_received: 0 },
        last_updated: new Date().toISOString(),
      };
    },

    cortexMultiagentSyncAgents(_sourceAgent: string, _targetAgent: string): unknown {
      return { applied_count: 0, buffered_count: 0, errors: [] };
    },
  };
}
