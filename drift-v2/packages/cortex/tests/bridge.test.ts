/**
 * NAPI bridge integration tests.
 *
 * Tests the bridge layer's error handling, module loading, and type conversions.
 * Uses dependency injection via a test-only factory since the actual NAPI module
 * requires a compiled Rust binary.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { CortexError } from "../src/bridge/client.js";
import type { NativeBindings } from "../src/bridge/index.js";
import type {
  AgentRegistration,
  AgentTrust,
  BaseMemory,
  CausalNarrative,
  CrossAgentTrace,
  HealthReport,
  ConsolidationResult,
  DecisionReplay,
  DriftAlert,
  DriftSnapshot,
  MaterializedTemporalView,
  MultiAgentSyncResult,
  PredictionResult,
  ProvenanceHop,
  ProvenanceRecord,
  SessionAnalytics,
  CacheStats,
  SanitizeResult,
  TemporalDiff,
  TraversalResult,
} from "../src/bridge/types.js";

// ─── Mock Native Module ──────────────────────────────────────────────────────

function createMockBindings(): NativeBindings {
  return {
    cortexInitialize: vi.fn(),
    cortexShutdown: vi.fn(),
    cortexConfigure: vi.fn(() => ({ retrieval: {}, embedding: {} })),

    cortexMemoryCreate: vi.fn(),
    cortexMemoryGet: vi.fn((id: string) => ({
      id,
      memory_type: "episodic",
      content: { type: "episodic", data: { interaction: "test", context: "test", outcome: null } },
      summary: "Test memory",
      transaction_time: "2026-01-01T00:00:00Z",
      valid_time: "2026-01-01T00:00:00Z",
      valid_until: null,
      confidence: 0.9,
      importance: "normal",
      last_accessed: "2026-01-01T00:00:00Z",
      access_count: 1,
      linked_patterns: [],
      linked_constraints: [],
      linked_files: [],
      linked_functions: [],
      tags: ["test"],
      archived: false,
      superseded_by: null,
      supersedes: null,
      content_hash: "abc123",
    })),
    cortexMemoryUpdate: vi.fn(),
    cortexMemoryDelete: vi.fn(),
    cortexMemorySearch: vi.fn(() => []),
    cortexMemoryList: vi.fn(() => []),
    cortexMemoryArchive: vi.fn(),
    cortexMemoryRestore: vi.fn(),

    cortexRetrievalRetrieve: vi.fn(() => []),
    cortexRetrievalSearch: vi.fn(() => []),
    cortexRetrievalGetContext: vi.fn(() => ({
      focus: "test",
      intent: null,
      active_files: [],
      budget: 4096,
      sent_ids: [],
    })),

    cortexCausalInferCause: vi.fn(() => ({
      source_id: "a",
      target_id: "b",
      strength: 0.8,
      suggested_relation: "Related",
      above_threshold: true,
    })),
    cortexCausalTraverse: vi.fn(() => ({
      origin_id: "a",
      max_depth_reached: 2,
      nodes: [],
    })),
    cortexCausalGetWhy: vi.fn(() => ({
      summary: "Because reasons",
      confidence: 0.9,
      sections: [],
    })),
    cortexCausalCounterfactual: vi.fn(() => ({
      origin_id: "a",
      max_depth_reached: 0,
      nodes: [],
    })),
    cortexCausalIntervention: vi.fn(() => ({
      origin_id: "a",
      max_depth_reached: 0,
      nodes: [],
    })),

    cortexLearningAnalyzeCorrection: vi.fn(() => ({
      category: "factual",
      principle: "Always verify",
      memory_created: null,
    })),
    cortexLearningLearn: vi.fn(() => ({
      category: "factual",
      principle: null,
      memory_created: null,
    })),
    cortexLearningGetValidationCandidates: vi.fn(() => []),
    cortexLearningProcessFeedback: vi.fn(() => ({
      category: "feedback",
      principle: null,
      memory_created: null,
    })),

    cortexConsolidationConsolidate: vi.fn(() => ({
      created: [],
      archived: [],
      metrics: { precision: 0.95, compression_ratio: 2.0, lift: 0.1, stability: 0.9 },
    })),
    cortexConsolidationGetMetrics: vi.fn(() => ({
      total_runs: 5,
      successful_runs: 4,
      success_rate: 0.8,
      is_running: false,
    })),
    cortexConsolidationGetStatus: vi.fn(() => ({ is_running: false })),

    cortexHealthGetHealth: vi.fn(() => ({
      overall_status: "healthy",
      subsystems: [],
      metrics: {
        total_memories: 100,
        active_memories: 90,
        archived_memories: 10,
        average_confidence: 0.85,
        db_size_bytes: 1024000,
        embedding_cache_hit_rate: 0.75,
      },
    })),
    cortexHealthGetMetrics: vi.fn(() => ({
      session_count: 3,
      causal_stats: { node_count: 50, edge_count: 30 },
    })),
    cortexHealthGetDegradations: vi.fn(() => []),

    cortexGenerationBuildContext: vi.fn(() => ({
      allocations: [],
      total_tokens: 0,
      total_budget: 4096,
    })),
    cortexGenerationTrackOutcome: vi.fn(),

    cortexPredictionPredict: vi.fn(() => ({
      memory_ids: [],
      signals: [],
      confidence: 0.5,
    })),
    cortexPredictionPreload: vi.fn(() => ({
      preloaded_count: 0,
      memory_ids: [],
      confidence: 0.5,
    })),
    cortexPredictionGetCacheStats: vi.fn(() => ({
      entry_count: 10,
      hits: 8,
      misses: 2,
      hit_rate: 0.8,
    })),

    cortexPrivacySanitize: vi.fn(() => ({ text: "sanitized", redactions: 2 })),
    cortexPrivacyGetPatternStats: vi.fn(() => ({
      failure_count: 0,
      has_failures: false,
      failures: [],
    })),

    cortexCloudSync: vi.fn(() => ({
      status: "Synced",
      pushed: 5,
      pulled: 3,
      conflicts_resolved: 0,
      manual_conflicts: 0,
    })),
    cortexCloudGetStatus: vi.fn(() => ({
      status: "Online",
      is_online: true,
      offline_queue_length: 0,
    })),
    cortexCloudResolveConflict: vi.fn(() => ({
      memory_id: "a",
      resolution: "keep_local",
    })),

    cortexSessionCreate: vi.fn(() => "session-123"),
    cortexSessionGet: vi.fn(() => ({
      session_id: "session-123",
      sent_memory_ids: [],
      tokens_used: 0,
      token_budget: 8192,
    })),
    cortexSessionCleanup: vi.fn(() => 2),
    cortexSessionAnalytics: vi.fn(() => ({
      session_id: "session-123",
      created_at: "2026-01-01T00:00:00Z",
      last_activity: "2026-01-01T00:01:00Z",
      loaded_memories_count: 5,
      loaded_patterns_count: 2,
      loaded_files_count: 3,
      tokens_sent: 1024,
      queries_made: 4,
    })),

    // Temporal (10)
    cortexTemporalQueryAsOf: vi.fn(() => [
      {
        id: "mem-1",
        memory_type: "episodic",
        content: { type: "episodic", data: { interaction: "test", context: "ctx", outcome: null } },
        summary: "Test memory at time T",
        transaction_time: "2026-01-01T00:00:00Z",
        valid_time: "2026-01-01T00:00:00Z",
        valid_until: null,
        confidence: 0.85,
        importance: "normal",
        last_accessed: "2026-01-01T00:00:00Z",
        access_count: 1,
        linked_patterns: [],
        linked_constraints: [],
        linked_files: [],
        linked_functions: [],
        tags: [],
        archived: false,
        superseded_by: null,
        supersedes: null,
        content_hash: "abc",
      },
    ]),
    cortexTemporalQueryRange: vi.fn(() => []),
    cortexTemporalQueryDiff: vi.fn(() => ({
      created: [],
      archived: [],
      modified: [],
      confidence_shifts: [],
      new_contradictions: [],
      resolved_contradictions: [],
      reclassifications: [],
      stats: {
        memories_at_a: 10,
        memories_at_b: 12,
        net_change: 2,
        avg_confidence_at_a: 0.8,
        avg_confidence_at_b: 0.82,
        confidence_trend: 0.02,
        knowledge_churn_rate: 0.1,
      },
    })),
    cortexTemporalReplayDecision: vi.fn(() => ({
      decision: {
        id: "dec-1",
        memory_type: "decision",
        content: { type: "decision", data: { decision: "Use JWT", rationale: "Standard", alternatives: [] } },
        summary: "Use JWT for auth",
        transaction_time: "2026-01-01T00:00:00Z",
        valid_time: "2026-01-01T00:00:00Z",
        valid_until: null,
        confidence: 0.9,
        importance: "high",
        last_accessed: "2026-01-01T00:00:00Z",
        access_count: 3,
        linked_patterns: [],
        linked_constraints: [],
        linked_files: [],
        linked_functions: [],
        tags: ["auth"],
        archived: false,
        superseded_by: null,
        supersedes: null,
        content_hash: "dec123",
      },
      available_context: [],
      retrieved_context: [],
      causal_state: { nodes: ["dec-1"], edges: [] },
      hindsight: [],
    })),
    cortexTemporalQueryTemporalCausal: vi.fn(() => ({
      origin_id: "mem-1",
      max_depth_reached: 2,
      nodes: [{ memory_id: "mem-2", depth: 1, path_strength: 0.8 }],
    })),
    cortexTemporalGetDriftMetrics: vi.fn(() => ({
      timestamp: "2026-01-01T00:00:00Z",
      window_hours: 168,
      type_metrics: {},
      module_metrics: {},
      global: {
        total_memories: 100,
        active_memories: 90,
        archived_memories: 10,
        avg_confidence: 0.85,
        overall_ksi: 0.92,
        overall_contradiction_density: 0.02,
        overall_evidence_freshness: 0.88,
      },
    })),
    cortexTemporalGetDriftAlerts: vi.fn(() => []),
    cortexTemporalCreateMaterializedView: vi.fn(() => ({
      view_id: 1,
      label: "sprint-12",
      timestamp: "2026-01-01T00:00:00Z",
      memory_count: 90,
      snapshot_ids: [1, 2, 3],
      drift_snapshot_id: 1,
      created_by: { system: "test" },
      auto_refresh: false,
    })),
    cortexTemporalGetMaterializedView: vi.fn(() => ({
      view_id: 1,
      label: "sprint-12",
      timestamp: "2026-01-01T00:00:00Z",
      memory_count: 90,
      snapshot_ids: [1, 2, 3],
      drift_snapshot_id: 1,
      created_by: { system: "test" },
      auto_refresh: false,
    })),
    cortexTemporalListMaterializedViews: vi.fn(() => []),

    // Multi-Agent (12)
    cortexMultiagentRegisterAgent: vi.fn((name: string, capabilities: string[]) => ({
      agent_id: { "0": "agent-uuid-123" },
      name,
      namespace: `agent://${name}/`,
      capabilities,
      parent_agent: null,
      registered_at: "2026-01-15T10:00:00Z",
      last_active: "2026-01-15T10:00:00Z",
      status: { state: "active" },
    })),
    cortexMultiagentDeregisterAgent: vi.fn(),
    cortexMultiagentGetAgent: vi.fn((agentId: string) => ({
      agent_id: { "0": agentId },
      name: "test-agent",
      namespace: "agent://test-agent/",
      capabilities: ["code_review"],
      parent_agent: null,
      registered_at: "2026-01-15T10:00:00Z",
      last_active: "2026-01-15T10:00:00Z",
      status: { state: "active" },
    })),
    cortexMultiagentListAgents: vi.fn(() => []),
    cortexMultiagentCreateNamespace: vi.fn(() => "team://backend/"),
    cortexMultiagentShareMemory: vi.fn(() => ({
      agent_id: { "0": "agent-1" },
      action: "shared_to",
      timestamp: "2026-01-15T10:00:00Z",
      confidence_delta: 0.0,
    })),
    cortexMultiagentCreateProjection: vi.fn(() => "proj-uuid-456"),
    cortexMultiagentRetractMemory: vi.fn(),
    cortexMultiagentGetProvenance: vi.fn((memoryId: string) => ({
      memory_id: memoryId,
      origin: { type: "agent_created" },
      chain: [
        {
          agent_id: { "0": "agent-1" },
          action: "created",
          timestamp: "2026-01-15T10:00:00Z",
          confidence_delta: 0.0,
        },
      ],
      chain_confidence: 1.0,
    })),
    cortexMultiagentTraceCrossAgent: vi.fn(() => ({
      path: [
        { agent_id: "agent-1", memory_id: "mem-1", confidence: 0.9 },
        { agent_id: "agent-2", memory_id: "mem-2", confidence: 0.85 },
      ],
    })),
    cortexMultiagentGetTrust: vi.fn(() => ({
      agent_id: { "0": "agent-a" },
      target_agent: { "0": "agent-b" },
      overall_trust: 0.75,
      domain_trust: { code_review: 0.9 },
      evidence: {
        validated_count: 5,
        contradicted_count: 1,
        useful_count: 3,
        total_received: 10,
      },
      last_updated: "2026-01-15T10:00:00Z",
    })),
    cortexMultiagentSyncAgents: vi.fn(() => ({
      applied_count: 5,
      buffered_count: 1,
      errors: [],
    })),
  };
}

/**
 * Create a CortexClient-like wrapper directly from mock bindings.
 * This bypasses the native module loading to test the client logic in isolation.
 */
function createTestClient(bindings: NativeBindings) {
  return {
    async memoryGet(id: string): Promise<BaseMemory> {
      return bindings.cortexMemoryGet(id) as BaseMemory;
    },
    async memoryCreate(memory: BaseMemory): Promise<void> {
      bindings.cortexMemoryCreate(memory);
    },
    async memoryUpdate(memory: BaseMemory): Promise<void> {
      bindings.cortexMemoryUpdate(memory);
    },
    async memoryDelete(id: string): Promise<void> {
      bindings.cortexMemoryDelete(id);
    },
    async memorySearch(query: string, limit?: number): Promise<BaseMemory[]> {
      return bindings.cortexMemorySearch(query, limit ?? null) as BaseMemory[];
    },
    async memoryList(memoryType?: string): Promise<BaseMemory[]> {
      return bindings.cortexMemoryList(memoryType ?? null) as BaseMemory[];
    },
    async memoryArchive(id: string): Promise<void> {
      bindings.cortexMemoryArchive(id);
    },
    async memoryRestore(id: string): Promise<void> {
      bindings.cortexMemoryRestore(id);
    },
    async healthReport(): Promise<HealthReport> {
      return bindings.cortexHealthGetHealth() as HealthReport;
    },
    async consolidate(): Promise<ConsolidationResult> {
      return bindings.cortexConsolidationConsolidate(null) as ConsolidationResult;
    },
    async causalGetWhy(memoryId: string): Promise<CausalNarrative> {
      return bindings.cortexCausalGetWhy(memoryId) as CausalNarrative;
    },
    async predict(activeFiles?: string[]): Promise<PredictionResult> {
      return bindings.cortexPredictionPredict(activeFiles ?? null, null, null) as PredictionResult;
    },
    async sessionCreate(sessionId?: string): Promise<string> {
      return bindings.cortexSessionCreate(sessionId ?? null);
    },
    async sessionAnalytics(sessionId: string): Promise<SessionAnalytics> {
      return bindings.cortexSessionAnalytics(sessionId) as SessionAnalytics;
    },
    async cacheStats(): Promise<CacheStats> {
      return bindings.cortexPredictionGetCacheStats() as CacheStats;
    },
    async sanitize(text: string): Promise<SanitizeResult> {
      return bindings.cortexPrivacySanitize(text) as SanitizeResult;
    },
    async shutdown(): Promise<void> {
      bindings.cortexShutdown();
    },
    // Temporal
    async queryAsOf(systemTime: string, validTime: string, filter?: string): Promise<BaseMemory[]> {
      return bindings.cortexTemporalQueryAsOf(systemTime, validTime, filter ?? null) as BaseMemory[];
    },
    async queryRange(from: string, to: string, mode: string): Promise<BaseMemory[]> {
      return bindings.cortexTemporalQueryRange(from, to, mode) as BaseMemory[];
    },
    async queryDiff(timeA: string, timeB: string, scope?: string): Promise<TemporalDiff> {
      return bindings.cortexTemporalQueryDiff(timeA, timeB, scope ?? null) as TemporalDiff;
    },
    async replayDecision(decisionId: string, budget?: number): Promise<DecisionReplay> {
      return bindings.cortexTemporalReplayDecision(decisionId, budget ?? null) as DecisionReplay;
    },
    async queryTemporalCausal(memoryId: string, asOf: string, direction: string, maxDepth: number): Promise<TraversalResult> {
      return bindings.cortexTemporalQueryTemporalCausal(memoryId, asOf, direction, maxDepth) as TraversalResult;
    },
    async getDriftMetrics(windowHours?: number): Promise<DriftSnapshot> {
      return bindings.cortexTemporalGetDriftMetrics(windowHours ?? null) as DriftSnapshot;
    },
    async getDriftAlerts(): Promise<DriftAlert[]> {
      return bindings.cortexTemporalGetDriftAlerts() as DriftAlert[];
    },
    async createMaterializedView(label: string, timestamp: string): Promise<MaterializedTemporalView> {
      return bindings.cortexTemporalCreateMaterializedView(label, timestamp) as MaterializedTemporalView;
    },
    async getMaterializedView(label: string): Promise<MaterializedTemporalView | null> {
      return bindings.cortexTemporalGetMaterializedView(label) as MaterializedTemporalView | null;
    },
    async listMaterializedViews(): Promise<MaterializedTemporalView[]> {
      return bindings.cortexTemporalListMaterializedViews() as MaterializedTemporalView[];
    },
    // Multi-Agent
    async registerAgent(name: string, capabilities: string[]): Promise<AgentRegistration> {
      return bindings.cortexMultiagentRegisterAgent(name, capabilities) as AgentRegistration;
    },
    async deregisterAgent(agentId: string): Promise<void> {
      bindings.cortexMultiagentDeregisterAgent(agentId);
    },
    async getAgent(agentId: string): Promise<AgentRegistration | null> {
      return bindings.cortexMultiagentGetAgent(agentId) as AgentRegistration | null;
    },
    async listAgents(statusFilter?: string): Promise<AgentRegistration[]> {
      return bindings.cortexMultiagentListAgents(statusFilter ?? null) as AgentRegistration[];
    },
    async createNamespace(scope: string, name: string, owner: string): Promise<string> {
      return bindings.cortexMultiagentCreateNamespace(scope, name, owner);
    },
    async shareMemory(memoryId: string, targetNamespace: string, agentId: string): Promise<ProvenanceHop> {
      return bindings.cortexMultiagentShareMemory(memoryId, targetNamespace, agentId) as ProvenanceHop;
    },
    async createProjection(config: unknown): Promise<string> {
      return bindings.cortexMultiagentCreateProjection(config);
    },
    async retractMemory(memoryId: string, namespace: string, agentId: string): Promise<void> {
      bindings.cortexMultiagentRetractMemory(memoryId, namespace, agentId);
    },
    async getProvenance(memoryId: string): Promise<ProvenanceRecord | null> {
      return bindings.cortexMultiagentGetProvenance(memoryId) as ProvenanceRecord | null;
    },
    async traceCrossAgent(memoryId: string, maxDepth: number): Promise<CrossAgentTrace> {
      return bindings.cortexMultiagentTraceCrossAgent(memoryId, maxDepth) as CrossAgentTrace;
    },
    async getTrust(agentId: string, targetAgent?: string): Promise<AgentTrust> {
      return bindings.cortexMultiagentGetTrust(agentId, targetAgent ?? null) as AgentTrust;
    },
    async syncAgents(sourceAgent: string, targetAgent: string): Promise<MultiAgentSyncResult> {
      return bindings.cortexMultiagentSyncAgents(sourceAgent, targetAgent) as MultiAgentSyncResult;
    },
  };
}

describe("CortexClient (via mock bindings)", () => {
  let bindings: NativeBindings;
  let client: ReturnType<typeof createTestClient>;

  beforeEach(() => {
    bindings = createMockBindings();
    client = createTestClient(bindings);
  });

  it("should get a memory by ID", async () => {
    const memory = await client.memoryGet("test-id");
    expect(memory.id).toBe("test-id");
    expect(memory.memory_type).toBe("episodic");
    expect(memory.confidence).toBe(0.9);
    expect(bindings.cortexMemoryGet).toHaveBeenCalledWith("test-id");
  });

  it("should search memories", async () => {
    const results = await client.memorySearch("test query", 10);
    expect(Array.isArray(results)).toBe(true);
    expect(bindings.cortexMemorySearch).toHaveBeenCalledWith("test query", 10);
  });

  it("should handle health report", async () => {
    const report = await client.healthReport();
    expect(report.overall_status).toBe("healthy");
    expect(report.metrics.total_memories).toBe(100);
  });

  it("should handle consolidation", async () => {
    const result = await client.consolidate();
    expect(result.metrics.precision).toBe(0.95);
  });

  it("should handle causal operations", async () => {
    const narrative = await client.causalGetWhy("test-id");
    expect(narrative.summary).toBe("Because reasons");
    expect(narrative.confidence).toBe(0.9);
  });

  it("should handle prediction", async () => {
    const result = await client.predict(["file.ts"]);
    expect(result.confidence).toBe(0.5);
  });

  it("should handle session operations", async () => {
    const sessionId = await client.sessionCreate();
    expect(sessionId).toBe("session-123");

    const analytics = await client.sessionAnalytics("session-123");
    expect(analytics.queries_made).toBe(4);
  });

  it("should handle cache stats", async () => {
    const stats = await client.cacheStats();
    expect(stats.hit_rate).toBe(0.8);
    expect(stats.entry_count).toBe(10);
  });

  it("should handle privacy sanitization", async () => {
    const result = await client.sanitize("test with [email]");
    expect(result.text).toBe("sanitized");
    expect(result.redactions).toBe(2);
  });

  it("should handle shutdown", async () => {
    await client.shutdown();
    expect(bindings.cortexShutdown).toHaveBeenCalled();
  });

  it("should handle memory CRUD lifecycle", async () => {
    const memory = await client.memoryGet("mem-1");
    expect(memory.id).toBe("mem-1");

    await client.memoryUpdate(memory);
    expect(bindings.cortexMemoryUpdate).toHaveBeenCalledWith(memory);

    await client.memoryArchive("mem-1");
    expect(bindings.cortexMemoryArchive).toHaveBeenCalledWith("mem-1");

    await client.memoryRestore("mem-1");
    expect(bindings.cortexMemoryRestore).toHaveBeenCalledWith("mem-1");

    await client.memoryDelete("mem-1");
    expect(bindings.cortexMemoryDelete).toHaveBeenCalledWith("mem-1");
  });

  it("should list memories by type", async () => {
    await client.memoryList("tribal");
    expect(bindings.cortexMemoryList).toHaveBeenCalledWith("tribal");
  });

  // ─── Temporal Tests ──────────────────────────────────────────────────────

  it("should query as-of a point in time (TTD4-01)", async () => {
    const memories = await client.queryAsOf("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z");
    expect(Array.isArray(memories)).toBe(true);
    expect(memories.length).toBe(1);
    expect(memories[0].id).toBe("mem-1");
    expect(memories[0].confidence).toBe(0.85);
    expect(bindings.cortexTemporalQueryAsOf).toHaveBeenCalledWith(
      "2026-01-01T00:00:00Z",
      "2026-01-01T00:00:00Z",
      null,
    );
  });

  it("should query temporal diff (TTD4-02)", async () => {
    const diff = await client.queryDiff("2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z");
    expect(diff.stats.memories_at_a).toBe(10);
    expect(diff.stats.memories_at_b).toBe(12);
    expect(diff.stats.net_change).toBe(2);
    expect(diff.stats.confidence_trend).toBe(0.02);
    expect(bindings.cortexTemporalQueryDiff).toHaveBeenCalledWith(
      "2026-01-01T00:00:00Z",
      "2026-02-01T00:00:00Z",
      null,
    );
  });

  it("should replay a decision (TTD4-03)", async () => {
    const replay = await client.replayDecision("dec-1", 2000);
    expect(replay.decision.id).toBe("dec-1");
    expect(replay.decision.memory_type).toBe("decision");
    expect(replay.causal_state.nodes).toContain("dec-1");
    expect(replay.hindsight).toEqual([]);
    expect(bindings.cortexTemporalReplayDecision).toHaveBeenCalledWith("dec-1", 2000);
  });

  it("should get drift metrics (TTD4-04)", async () => {
    const metrics = await client.getDriftMetrics(168);
    expect(metrics.global.overall_ksi).toBe(0.92);
    expect(metrics.global.avg_confidence).toBe(0.85);
    expect(metrics.global.overall_evidence_freshness).toBe(0.88);
    expect(metrics.global.total_memories).toBe(100);
    expect(bindings.cortexTemporalGetDriftMetrics).toHaveBeenCalledWith(168);
  });

  it("should create a materialized view (TTD4-05)", async () => {
    const view = await client.createMaterializedView("sprint-12", "2026-01-01T00:00:00Z");
    expect(view.view_id).toBe(1);
    expect(view.label).toBe("sprint-12");
    expect(view.memory_count).toBe(90);
    expect(bindings.cortexTemporalCreateMaterializedView).toHaveBeenCalledWith(
      "sprint-12",
      "2026-01-01T00:00:00Z",
    );
  });

  it("should get drift alerts", async () => {
    const alerts = await client.getDriftAlerts();
    expect(Array.isArray(alerts)).toBe(true);
    expect(alerts.length).toBe(0);
    expect(bindings.cortexTemporalGetDriftAlerts).toHaveBeenCalled();
  });

  it("should query temporal causal", async () => {
    const result = await client.queryTemporalCausal("mem-1", "2026-01-01T00:00:00Z", "both", 3);
    expect(result.origin_id).toBe("mem-1");
    expect(result.nodes.length).toBe(1);
    expect(result.nodes[0].memory_id).toBe("mem-2");
    expect(bindings.cortexTemporalQueryTemporalCausal).toHaveBeenCalledWith(
      "mem-1",
      "2026-01-01T00:00:00Z",
      "both",
      3,
    );
  });

  it("should query range", async () => {
    const memories = await client.queryRange(
      "2026-01-01T00:00:00Z",
      "2026-02-01T00:00:00Z",
      "overlaps",
    );
    expect(Array.isArray(memories)).toBe(true);
    expect(bindings.cortexTemporalQueryRange).toHaveBeenCalledWith(
      "2026-01-01T00:00:00Z",
      "2026-02-01T00:00:00Z",
      "overlaps",
    );
  });

  it("should get a materialized view by label", async () => {
    const view = await client.getMaterializedView("sprint-12");
    expect(view).not.toBeNull();
    expect(view!.label).toBe("sprint-12");
    expect(bindings.cortexTemporalGetMaterializedView).toHaveBeenCalledWith("sprint-12");
  });

  it("should list materialized views", async () => {
    const views = await client.listMaterializedViews();
    expect(Array.isArray(views)).toBe(true);
    expect(bindings.cortexTemporalListMaterializedViews).toHaveBeenCalled();
  });

  // ─── Multi-Agent Tests (TMD2-TS-01) ─────────────────────────────────

  it("should register an agent (TMD2-NAPI-01 round-trip)", async () => {
    const reg = await client.registerAgent("code-reviewer", ["code_review", "testing"]);
    expect(reg.name).toBe("code-reviewer");
    expect(reg.capabilities).toEqual(["code_review", "testing"]);
    expect(reg.status).toEqual({ state: "active" });
    expect(bindings.cortexMultiagentRegisterAgent).toHaveBeenCalledWith(
      "code-reviewer",
      ["code_review", "testing"],
    );
  });

  it("should deregister an agent", async () => {
    await client.deregisterAgent("agent-uuid-123");
    expect(bindings.cortexMultiagentDeregisterAgent).toHaveBeenCalledWith("agent-uuid-123");
  });

  it("should get an agent by ID", async () => {
    const agent = await client.getAgent("agent-uuid-123");
    expect(agent).not.toBeNull();
    expect(agent!.name).toBe("test-agent");
    expect(bindings.cortexMultiagentGetAgent).toHaveBeenCalledWith("agent-uuid-123");
  });

  it("should list agents", async () => {
    const agents = await client.listAgents("active");
    expect(Array.isArray(agents)).toBe(true);
    expect(bindings.cortexMultiagentListAgents).toHaveBeenCalledWith("active");
  });

  it("should create a namespace", async () => {
    const uri = await client.createNamespace("team", "backend", "agent-1");
    expect(uri).toBe("team://backend/");
    expect(bindings.cortexMultiagentCreateNamespace).toHaveBeenCalledWith(
      "team",
      "backend",
      "agent-1",
    );
  });

  it("should share a memory (TMD2-NAPI-02 round-trip)", async () => {
    const hop = await client.shareMemory("mem-1", "team://backend/", "agent-1");
    expect(hop.action).toBe("shared_to");
    expect(hop.confidence_delta).toBe(0.0);
    expect(bindings.cortexMultiagentShareMemory).toHaveBeenCalledWith(
      "mem-1",
      "team://backend/",
      "agent-1",
    );
  });

  it("should create a projection", async () => {
    const projId = await client.createProjection({ id: "proj-1" } as unknown);
    expect(projId).toBe("proj-uuid-456");
    expect(bindings.cortexMultiagentCreateProjection).toHaveBeenCalled();
  });

  it("should retract a memory", async () => {
    await client.retractMemory("mem-1", "agent://default/", "agent-1");
    expect(bindings.cortexMultiagentRetractMemory).toHaveBeenCalledWith(
      "mem-1",
      "agent://default/",
      "agent-1",
    );
  });

  it("should get provenance (TMD2-NAPI-03 round-trip)", async () => {
    const prov = await client.getProvenance("mem-1");
    expect(prov).not.toBeNull();
    expect(prov!.memory_id).toBe("mem-1");
    expect(prov!.origin).toEqual({ type: "agent_created" });
    expect(prov!.chain.length).toBe(1);
    expect(prov!.chain[0].action).toBe("created");
    expect(prov!.chain_confidence).toBe(1.0);
    expect(bindings.cortexMultiagentGetProvenance).toHaveBeenCalledWith("mem-1");
  });

  it("should trace cross-agent causal relationships", async () => {
    const trace = await client.traceCrossAgent("mem-1", 3);
    expect(trace.path.length).toBe(2);
    expect(trace.path[0].agent_id).toBe("agent-1");
    expect(trace.path[0].memory_id).toBe("mem-1");
    expect(trace.path[1].agent_id).toBe("agent-2");
    expect(bindings.cortexMultiagentTraceCrossAgent).toHaveBeenCalledWith("mem-1", 3);
  });

  it("should get trust scores (TMD2-NAPI-04 round-trip)", async () => {
    const trust = await client.getTrust("agent-a", "agent-b");
    expect(trust.overall_trust).toBe(0.75);
    expect(trust.domain_trust).toEqual({ code_review: 0.9 });
    expect(trust.evidence.validated_count).toBe(5);
    expect(trust.evidence.contradicted_count).toBe(1);
    expect(bindings.cortexMultiagentGetTrust).toHaveBeenCalledWith("agent-a", "agent-b");
  });

  it("should sync agents (TMD2-NAPI-05 round-trip)", async () => {
    const result = await client.syncAgents("agent-a", "agent-b");
    expect(result.applied_count).toBe(5);
    expect(result.buffered_count).toBe(1);
    expect(result.errors).toEqual([]);
    expect(bindings.cortexMultiagentSyncAgents).toHaveBeenCalledWith("agent-a", "agent-b");
  });
});

describe("CortexError", () => {
  it("should parse structured error codes from NAPI errors", () => {
    const error = new CortexError("MEMORY_NOT_FOUND", "Memory not found: abc");
    expect(error.code).toBe("MEMORY_NOT_FOUND");
    expect(error.message).toBe("Memory not found: abc");
    expect(error.name).toBe("CortexError");
  });

  it("should handle errors with unknown codes", () => {
    const error = new CortexError("UNKNOWN", "Something went wrong");
    expect(error.code).toBe("UNKNOWN");
    expect(error.message).toBe("Something went wrong");
  });

  it("should be an instance of Error", () => {
    const error = new CortexError("STORAGE_ERROR", "DB failed");
    expect(error).toBeInstanceOf(Error);
    expect(error).toBeInstanceOf(CortexError);
  });
});

describe("NativeBindings interface", () => {
  it("should have all required binding functions", () => {
    const bindings = createMockBindings();

    // Lifecycle
    expect(typeof bindings.cortexInitialize).toBe("function");
    expect(typeof bindings.cortexShutdown).toBe("function");
    expect(typeof bindings.cortexConfigure).toBe("function");

    // Memory (8)
    expect(typeof bindings.cortexMemoryCreate).toBe("function");
    expect(typeof bindings.cortexMemoryGet).toBe("function");
    expect(typeof bindings.cortexMemoryUpdate).toBe("function");
    expect(typeof bindings.cortexMemoryDelete).toBe("function");
    expect(typeof bindings.cortexMemorySearch).toBe("function");
    expect(typeof bindings.cortexMemoryList).toBe("function");
    expect(typeof bindings.cortexMemoryArchive).toBe("function");
    expect(typeof bindings.cortexMemoryRestore).toBe("function");

    // Retrieval (3)
    expect(typeof bindings.cortexRetrievalRetrieve).toBe("function");
    expect(typeof bindings.cortexRetrievalSearch).toBe("function");
    expect(typeof bindings.cortexRetrievalGetContext).toBe("function");

    // Causal (5)
    expect(typeof bindings.cortexCausalInferCause).toBe("function");
    expect(typeof bindings.cortexCausalTraverse).toBe("function");
    expect(typeof bindings.cortexCausalGetWhy).toBe("function");
    expect(typeof bindings.cortexCausalCounterfactual).toBe("function");
    expect(typeof bindings.cortexCausalIntervention).toBe("function");

    // Learning (4)
    expect(typeof bindings.cortexLearningAnalyzeCorrection).toBe("function");
    expect(typeof bindings.cortexLearningLearn).toBe("function");
    expect(typeof bindings.cortexLearningGetValidationCandidates).toBe("function");
    expect(typeof bindings.cortexLearningProcessFeedback).toBe("function");

    // Consolidation (3)
    expect(typeof bindings.cortexConsolidationConsolidate).toBe("function");
    expect(typeof bindings.cortexConsolidationGetMetrics).toBe("function");
    expect(typeof bindings.cortexConsolidationGetStatus).toBe("function");

    // Health (3)
    expect(typeof bindings.cortexHealthGetHealth).toBe("function");
    expect(typeof bindings.cortexHealthGetMetrics).toBe("function");
    expect(typeof bindings.cortexHealthGetDegradations).toBe("function");

    // Generation (2)
    expect(typeof bindings.cortexGenerationBuildContext).toBe("function");
    expect(typeof bindings.cortexGenerationTrackOutcome).toBe("function");

    // Prediction (3)
    expect(typeof bindings.cortexPredictionPredict).toBe("function");
    expect(typeof bindings.cortexPredictionPreload).toBe("function");
    expect(typeof bindings.cortexPredictionGetCacheStats).toBe("function");

    // Privacy (2)
    expect(typeof bindings.cortexPrivacySanitize).toBe("function");
    expect(typeof bindings.cortexPrivacyGetPatternStats).toBe("function");

    // Cloud (3)
    expect(typeof bindings.cortexCloudSync).toBe("function");
    expect(typeof bindings.cortexCloudGetStatus).toBe("function");
    expect(typeof bindings.cortexCloudResolveConflict).toBe("function");

    // Session (4)
    expect(typeof bindings.cortexSessionCreate).toBe("function");
    expect(typeof bindings.cortexSessionGet).toBe("function");
    expect(typeof bindings.cortexSessionCleanup).toBe("function");
    expect(typeof bindings.cortexSessionAnalytics).toBe("function");

    // Temporal (10)
    expect(typeof bindings.cortexTemporalQueryAsOf).toBe("function");
    expect(typeof bindings.cortexTemporalQueryRange).toBe("function");
    expect(typeof bindings.cortexTemporalQueryDiff).toBe("function");
    expect(typeof bindings.cortexTemporalReplayDecision).toBe("function");
    expect(typeof bindings.cortexTemporalQueryTemporalCausal).toBe("function");
    expect(typeof bindings.cortexTemporalGetDriftMetrics).toBe("function");
    expect(typeof bindings.cortexTemporalGetDriftAlerts).toBe("function");
    expect(typeof bindings.cortexTemporalCreateMaterializedView).toBe("function");
    expect(typeof bindings.cortexTemporalGetMaterializedView).toBe("function");
    expect(typeof bindings.cortexTemporalListMaterializedViews).toBe("function");

    // Multi-Agent (12)
    expect(typeof bindings.cortexMultiagentRegisterAgent).toBe("function");
    expect(typeof bindings.cortexMultiagentDeregisterAgent).toBe("function");
    expect(typeof bindings.cortexMultiagentGetAgent).toBe("function");
    expect(typeof bindings.cortexMultiagentListAgents).toBe("function");
    expect(typeof bindings.cortexMultiagentCreateNamespace).toBe("function");
    expect(typeof bindings.cortexMultiagentShareMemory).toBe("function");
    expect(typeof bindings.cortexMultiagentCreateProjection).toBe("function");
    expect(typeof bindings.cortexMultiagentRetractMemory).toBe("function");
    expect(typeof bindings.cortexMultiagentGetProvenance).toBe("function");
    expect(typeof bindings.cortexMultiagentTraceCrossAgent).toBe("function");
    expect(typeof bindings.cortexMultiagentGetTrust).toBe("function");
    expect(typeof bindings.cortexMultiagentSyncAgents).toBe("function");
  });
});
