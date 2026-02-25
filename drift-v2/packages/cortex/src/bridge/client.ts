/**
 * CortexClient — typed wrapper over NAPI bindings.
 *
 * Provides a clean async API with proper TypeScript types, error mapping,
 * and structured error codes. All methods delegate to the native Rust module.
 */

import { loadNativeModule, type NativeBindings } from "./index.js";
import type {
  AgentRegistration,
  AgentTrust,
  BaseMemory,
  CausalNarrative,
  CacheStats,
  CloudStatus,
  CompressedMemory,
  ConsolidationDashboard,
  ConsolidationResult,
  ConsolidationStatus,
  CrossAgentTrace,
  DecisionReplay,
  DegradationEvent,
  DriftAlert,
  DriftSnapshot,
  GenerationContext,
  HealthReport,
  InferenceResult,
  LearningResult,
  MaterializedTemporalView,
  MemoryType,
  MultiAgentSyncResult,
  PatternStats,
  PredictionResult,
  PreloadResult,
  ProjectionConfig,
  ProvenanceHop,
  ProvenanceRecord,
  RetrievalContext,
  SanitizeResult,
  SessionAnalytics,
  SyncResult,
  TemporalDiff,
  TraversalResult,
} from "./types.js";

export interface CortexInitOptions {
  /** Path to SQLite database. Null for in-memory. */
  dbPath?: string | null;
  /** TOML configuration string. */
  configToml?: string | null;
  /** Enable cloud sync. */
  cloudEnabled?: boolean;
}

/** Structured error thrown by CortexClient methods. */
export class CortexError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "CortexError";
  }
}

/**
 * Parse a NAPI error message to extract the structured error code.
 * NAPI errors from Rust have the format: "[ERROR_CODE] Human-readable message"
 */
function parseNapiError(err: unknown): CortexError {
  const message = err instanceof Error ? err.message : String(err);
  const match = /^\[([A-Z_]+)\]\s*(.+)$/.exec(message);
  if (match) {
    return new CortexError(match[1], match[2]);
  }
  return new CortexError("UNKNOWN", message);
}

/** Wrap a synchronous NAPI call in a Promise with error mapping. */
async function wrap<T>(fn: () => T): Promise<T> {
  try {
    return fn();
  } catch (err) {
    throw parseNapiError(err);
  }
}

export class CortexClient {
  private native: NativeBindings;

  private constructor(native: NativeBindings) {
    this.native = native;
  }

  /**
   * Initialize the Cortex runtime and return a client instance.
   * Must be called before any other operations.
   */
  static async initialize(opts: CortexInitOptions = {}): Promise<CortexClient> {
    const native = loadNativeModule();
    await wrap(() =>
      native.cortexInitialize(
        opts.dbPath ?? null,
        opts.configToml ?? null,
        opts.cloudEnabled ?? null,
      ),
    );
    return new CortexClient(native);
  }

  /** Graceful shutdown. */
  async shutdown(): Promise<void> {
    await wrap(() => this.native.cortexShutdown());
  }

  /** Get current configuration as JSON. */
  async configure(): Promise<unknown> {
    return wrap(() => this.native.cortexConfigure(null));
  }

  // ─── Memory CRUD ─────────────────────────────────────────────────────────

  async memoryCreate(memory: BaseMemory): Promise<void> {
    await wrap(() => this.native.cortexMemoryCreate(memory));
  }

  async memoryGet(id: string): Promise<BaseMemory> {
    return wrap(() => this.native.cortexMemoryGet(id) as BaseMemory);
  }

  async memoryUpdate(memory: BaseMemory): Promise<void> {
    await wrap(() => this.native.cortexMemoryUpdate(memory));
  }

  async memoryDelete(id: string): Promise<void> {
    await wrap(() => this.native.cortexMemoryDelete(id));
  }

  async memorySearch(query: string, limit?: number): Promise<BaseMemory[]> {
    return wrap(() => this.native.cortexMemorySearch(query, limit ?? null) as BaseMemory[]);
  }

  async memoryList(memoryType?: MemoryType): Promise<BaseMemory[]> {
    return wrap(() => this.native.cortexMemoryList(memoryType ?? null) as BaseMemory[]);
  }

  async memoryArchive(id: string): Promise<void> {
    await wrap(() => this.native.cortexMemoryArchive(id));
  }

  async memoryRestore(id: string): Promise<void> {
    await wrap(() => this.native.cortexMemoryRestore(id));
  }

  // ─── Retrieval ───────────────────────────────────────────────────────────

  async retrieve(context: RetrievalContext, budget?: number): Promise<CompressedMemory[]> {
    return wrap(
      () => this.native.cortexRetrievalRetrieve(context, budget ?? null) as CompressedMemory[],
    );
  }

  async search(query: string, budget?: number): Promise<CompressedMemory[]> {
    return wrap(
      () => this.native.cortexRetrievalSearch(query, budget ?? null) as CompressedMemory[],
    );
  }

  async getContext(
    focus: string,
    activeFiles?: string[],
    sentIds?: string[],
    budget?: number,
  ): Promise<RetrievalContext> {
    return wrap(
      () =>
        this.native.cortexRetrievalGetContext(
          focus,
          activeFiles ?? null,
          sentIds ?? null,
          budget ?? null,
        ) as RetrievalContext,
    );
  }

  // ─── Causal ──────────────────────────────────────────────────────────────

  async causalInfer(source: BaseMemory, target: BaseMemory): Promise<InferenceResult> {
    return wrap(() => this.native.cortexCausalInferCause(source, target) as InferenceResult);
  }

  async causalTraverse(memoryId: string): Promise<TraversalResult> {
    return wrap(() => this.native.cortexCausalTraverse(memoryId) as TraversalResult);
  }

  async causalGetWhy(memoryId: string): Promise<CausalNarrative> {
    return wrap(() => this.native.cortexCausalGetWhy(memoryId) as CausalNarrative);
  }

  async causalCounterfactual(memoryId: string): Promise<TraversalResult> {
    return wrap(() => this.native.cortexCausalCounterfactual(memoryId) as TraversalResult);
  }

  async causalIntervention(memoryId: string): Promise<TraversalResult> {
    return wrap(() => this.native.cortexCausalIntervention(memoryId) as TraversalResult);
  }

  // ─── Learning ────────────────────────────────────────────────────────────

  async analyzeCorrection(
    correctionText: string,
    context: string,
    source: string,
    originalMemoryId?: string,
  ): Promise<LearningResult> {
    return wrap(
      () =>
        this.native.cortexLearningAnalyzeCorrection(
          correctionText,
          context,
          source,
          originalMemoryId ?? null,
        ) as LearningResult,
    );
  }

  async learn(correctionText: string, context: string, source: string): Promise<LearningResult> {
    return wrap(
      () => this.native.cortexLearningLearn(correctionText, context, source) as LearningResult,
    );
  }

  async getValidationCandidates(
    minConfidence?: number,
    maxConfidence?: number,
  ): Promise<BaseMemory[]> {
    return wrap(
      () =>
        this.native.cortexLearningGetValidationCandidates(
          minConfidence ?? null,
          maxConfidence ?? null,
        ) as BaseMemory[],
    );
  }

  async processFeedback(
    memoryId: string,
    feedback: string,
    isPositive: boolean,
  ): Promise<LearningResult> {
    return wrap(
      () =>
        this.native.cortexLearningProcessFeedback(memoryId, feedback, isPositive) as LearningResult,
    );
  }

  // ─── Validation ─────────────────────────────────────────────────────────

  /** E-02: Run 4-dimension validation on candidate memories. */
  async validationRun(
    minConfidence?: number,
    maxConfidence?: number,
  ): Promise<unknown> {
    return wrap(
      () =>
        this.native.cortexValidationRun(
          minConfidence ?? null,
          maxConfidence ?? null,
        ),
    );
  }

  // ─── Consolidation ──────────────────────────────────────────────────────

  async consolidate(memoryType?: MemoryType): Promise<ConsolidationResult> {
    return wrap(
      () => this.native.cortexConsolidationConsolidate(memoryType ?? null) as ConsolidationResult,
    );
  }

  async consolidationMetrics(): Promise<ConsolidationDashboard> {
    return wrap(() => this.native.cortexConsolidationGetMetrics() as ConsolidationDashboard);
  }

  async consolidationStatus(): Promise<ConsolidationStatus> {
    return wrap(() => this.native.cortexConsolidationGetStatus() as ConsolidationStatus);
  }

  // ─── Embeddings ────────────────────────────────────────────────────────

  /** E-01: Re-embed all memories (or a specific type) using the configured provider chain. */
  async reembed(memoryType?: string): Promise<unknown> {
    return wrap(() => this.native.cortexReembed(memoryType ?? null));
  }

  // ─── Decay ────────────────────────────────────────────────────────────

  /** C-07: Run decay on all memories — compute new confidence, archive if needed. */
  async decayRun(): Promise<unknown> {
    return wrap(() => this.native.cortexDecayRun());
  }

  // ─── Health ──────────────────────────────────────────────────────────────

  async healthReport(): Promise<HealthReport> {
    return wrap(() => this.native.cortexHealthGetHealth() as HealthReport);
  }

  async healthMetrics(): Promise<unknown> {
    return wrap(() => this.native.cortexHealthGetMetrics());
  }

  async degradations(): Promise<DegradationEvent[]> {
    return wrap(() => this.native.cortexHealthGetDegradations() as DegradationEvent[]);
  }

  // ─── Generation ──────────────────────────────────────────────────────────

  async buildGenerationContext(
    focus: string,
    activeFiles?: string[],
    budget?: number,
    sentIds?: string[],
  ): Promise<GenerationContext> {
    return wrap(
      () =>
        this.native.cortexGenerationBuildContext(
          focus,
          activeFiles ?? null,
          budget ?? null,
          sentIds ?? null,
        ) as GenerationContext,
    );
  }

  async trackOutcome(memoryIds: string[], wasUseful: boolean, sessionId?: string): Promise<void> {
    await wrap(() =>
      this.native.cortexGenerationTrackOutcome(memoryIds, wasUseful, sessionId ?? null),
    );
  }

  // ─── Prediction ──────────────────────────────────────────────────────────

  async predict(
    activeFiles?: string[],
    recentQueries?: string[],
    currentIntent?: string,
  ): Promise<PredictionResult> {
    return wrap(
      () =>
        this.native.cortexPredictionPredict(
          activeFiles ?? null,
          recentQueries ?? null,
          currentIntent ?? null,
        ) as PredictionResult,
    );
  }

  async preload(activeFiles?: string[]): Promise<PreloadResult> {
    return wrap(() => this.native.cortexPredictionPreload(activeFiles ?? null) as PreloadResult);
  }

  async cacheStats(): Promise<CacheStats> {
    return wrap(() => this.native.cortexPredictionGetCacheStats() as CacheStats);
  }

  // ─── Privacy ─────────────────────────────────────────────────────────────

  async sanitize(text: string): Promise<SanitizeResult> {
    return wrap(() => this.native.cortexPrivacySanitize(text) as SanitizeResult);
  }

  async patternStats(): Promise<PatternStats> {
    return wrap(() => this.native.cortexPrivacyGetPatternStats() as PatternStats);
  }

  // ─── Cloud ───────────────────────────────────────────────────────────────

  async cloudSync(): Promise<SyncResult> {
    return wrap(() => this.native.cortexCloudSync() as SyncResult);
  }

  async cloudStatus(): Promise<CloudStatus> {
    return wrap(() => this.native.cortexCloudGetStatus() as CloudStatus);
  }

  async cloudResolveConflict(memoryId: string, resolution: string): Promise<unknown> {
    return wrap(() => this.native.cortexCloudResolveConflict(memoryId, resolution));
  }

  // ─── Session ─────────────────────────────────────────────────────────────

  async sessionCreate(sessionId?: string): Promise<string> {
    return wrap(() => this.native.cortexSessionCreate(sessionId ?? null));
  }

  async sessionGet(sessionId: string): Promise<unknown> {
    return wrap(() => this.native.cortexSessionGet(sessionId));
  }

  async sessionCleanup(): Promise<number> {
    return wrap(() => this.native.cortexSessionCleanup());
  }

  async sessionAnalytics(sessionId: string): Promise<SessionAnalytics> {
    return wrap(() => this.native.cortexSessionAnalytics(sessionId) as SessionAnalytics);
  }

  // ─── Temporal ──────────────────────────────────────────────────────────────

  async queryAsOf(
    systemTime: string,
    validTime: string,
    filter?: string,
  ): Promise<BaseMemory[]> {
    return wrap(
      () =>
        this.native.cortexTemporalQueryAsOf(systemTime, validTime, filter ?? null) as BaseMemory[],
    );
  }

  async queryRange(from: string, to: string, mode: string): Promise<BaseMemory[]> {
    return wrap(() => this.native.cortexTemporalQueryRange(from, to, mode) as BaseMemory[]);
  }

  async queryDiff(timeA: string, timeB: string, scope?: string): Promise<TemporalDiff> {
    return wrap(
      () => this.native.cortexTemporalQueryDiff(timeA, timeB, scope ?? null) as TemporalDiff,
    );
  }

  async replayDecision(decisionId: string, budget?: number): Promise<DecisionReplay> {
    return wrap(
      () =>
        this.native.cortexTemporalReplayDecision(decisionId, budget ?? null) as DecisionReplay,
    );
  }

  async queryTemporalCausal(
    memoryId: string,
    asOf: string,
    direction: string,
    maxDepth: number,
  ): Promise<TraversalResult> {
    return wrap(
      () =>
        this.native.cortexTemporalQueryTemporalCausal(
          memoryId,
          asOf,
          direction,
          maxDepth,
        ) as TraversalResult,
    );
  }

  async getDriftMetrics(windowHours?: number): Promise<DriftSnapshot> {
    return wrap(
      () => this.native.cortexTemporalGetDriftMetrics(windowHours ?? null) as DriftSnapshot,
    );
  }

  async getDriftAlerts(): Promise<DriftAlert[]> {
    return wrap(() => this.native.cortexTemporalGetDriftAlerts() as DriftAlert[]);
  }

  async createMaterializedView(
    label: string,
    timestamp: string,
  ): Promise<MaterializedTemporalView> {
    return wrap(
      () =>
        this.native.cortexTemporalCreateMaterializedView(
          label,
          timestamp,
        ) as MaterializedTemporalView,
    );
  }

  async getMaterializedView(label: string): Promise<MaterializedTemporalView | null> {
    return wrap(
      () =>
        this.native.cortexTemporalGetMaterializedView(label) as MaterializedTemporalView | null,
    );
  }

  async listMaterializedViews(): Promise<MaterializedTemporalView[]> {
    return wrap(
      () => this.native.cortexTemporalListMaterializedViews() as MaterializedTemporalView[],
    );
  }

  // ─── Multi-Agent ──────────────────────────────────────────────────────

  /** Register a new agent with the given name and capabilities. */
  async registerAgent(name: string, capabilities: string[]): Promise<AgentRegistration> {
    return wrap(() => this.native.cortexMultiagentRegisterAgent(name, capabilities) as AgentRegistration);
  }

  /** Deregister an agent by ID. */
  async deregisterAgent(agentId: string): Promise<void> {
    return wrap(() => this.native.cortexMultiagentDeregisterAgent(agentId));
  }

  /** Get an agent by ID. Returns null if not found. */
  async getAgent(agentId: string): Promise<AgentRegistration | null> {
    return wrap(() => this.native.cortexMultiagentGetAgent(agentId) as AgentRegistration | null);
  }

  /** List agents, optionally filtered by status. */
  async listAgents(statusFilter?: string): Promise<AgentRegistration[]> {
    return wrap(() => this.native.cortexMultiagentListAgents(statusFilter ?? null) as AgentRegistration[]);
  }

  /** Create a new namespace. Returns the namespace URI. */
  async createNamespace(scope: string, name: string, owner: string): Promise<string> {
    return wrap(() => this.native.cortexMultiagentCreateNamespace(scope, name, owner));
  }

  /** Share a memory to a target namespace. Returns the provenance hop. */
  async shareMemory(memoryId: string, targetNamespace: string, agentId: string): Promise<ProvenanceHop> {
    return wrap(() => this.native.cortexMultiagentShareMemory(memoryId, targetNamespace, agentId) as ProvenanceHop);
  }

  /** Create a memory projection between namespaces. Returns the projection ID. */
  async createProjection(config: ProjectionConfig): Promise<string> {
    return wrap(() => this.native.cortexMultiagentCreateProjection(config));
  }

  /** Retract (tombstone) a memory in a namespace. */
  async retractMemory(memoryId: string, namespace: string, agentId: string): Promise<void> {
    return wrap(() => this.native.cortexMultiagentRetractMemory(memoryId, namespace, agentId));
  }

  /** Get the full provenance record for a memory. */
  async getProvenance(memoryId: string): Promise<ProvenanceRecord | null> {
    return wrap(() => this.native.cortexMultiagentGetProvenance(memoryId) as ProvenanceRecord | null);
  }

  /** Trace causal relationships across agent boundaries. */
  async traceCrossAgent(memoryId: string, maxDepth: number): Promise<CrossAgentTrace> {
    return wrap(() => this.native.cortexMultiagentTraceCrossAgent(memoryId, maxDepth) as CrossAgentTrace);
  }

  /** Get trust scores for an agent, optionally toward a specific target. */
  async getTrust(agentId: string, targetAgent?: string): Promise<AgentTrust> {
    return wrap(() => this.native.cortexMultiagentGetTrust(agentId, targetAgent ?? null) as AgentTrust);
  }

  /** Synchronize memory state between two agents via delta sync. */
  async syncAgents(sourceAgent: string, targetAgent: string): Promise<MultiAgentSyncResult> {
    return wrap(() => this.native.cortexMultiagentSyncAgents(sourceAgent, targetAgent) as MultiAgentSyncResult);
  }
}
