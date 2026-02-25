/**
 * NAPI bridge consumer — loads the native Rust module.
 *
 * The native module is built from crates/cortex/cortex-napi via napi-rs.
 * It exports synchronous functions that call into the Rust CortexRuntime.
 */

import { createRequire } from 'node:module';
import { createStubNativeModule } from './stub.js';

// ESM-compatible require for loading native .node addons
const esmRequire = createRequire(import.meta.url);

let nativeModule: NativeBindings | null = null;
let nativeIsStub = false;

/** Raw NAPI function signatures exported by cortex-napi. */
export interface NativeBindings {
  // Lifecycle
  cortexInitialize(
    dbPath: string | null,
    configToml: string | null,
    cloudEnabled: boolean | null,
  ): void;
  cortexShutdown(): void;
  cortexConfigure(configToml: string | null): Record<string, unknown>;

  // Memory CRUD
  cortexMemoryCreate(memoryJson: unknown): void;
  cortexMemoryGet(id: string): unknown;
  cortexMemoryUpdate(memoryJson: unknown): void;
  cortexMemoryDelete(id: string): void;
  cortexMemorySearch(query: string, limit: number | null): unknown;
  cortexMemoryList(memoryType: string | null): unknown;
  cortexMemoryArchive(id: string): void;
  cortexMemoryRestore(id: string): void;

  // Retrieval
  cortexRetrievalRetrieve(contextJson: unknown, budget: number | null): unknown;
  cortexRetrievalSearch(query: string, budget: number | null): unknown;
  cortexRetrievalGetContext(
    focus: string,
    activeFiles: string[] | null,
    sentIds: string[] | null,
    budget: number | null,
  ): unknown;

  // Causal
  cortexCausalInferCause(sourceJson: unknown, targetJson: unknown): unknown;
  cortexCausalTraverse(memoryId: string): unknown;
  cortexCausalGetWhy(memoryId: string): unknown;
  cortexCausalCounterfactual(memoryId: string): unknown;
  cortexCausalIntervention(memoryId: string): unknown;

  // Learning
  cortexLearningAnalyzeCorrection(
    correctionText: string,
    context: string,
    source: string,
    originalMemoryId: string | null,
  ): unknown;
  cortexLearningLearn(correctionText: string, context: string, source: string): unknown;
  cortexLearningGetValidationCandidates(
    minConfidence: number | null,
    maxConfidence: number | null,
  ): unknown;
  cortexLearningProcessFeedback(memoryId: string, feedback: string, isPositive: boolean): unknown;

  // Consolidation
  cortexConsolidationConsolidate(memoryType: string | null): unknown;
  cortexConsolidationGetMetrics(): unknown;
  cortexConsolidationGetStatus(): unknown;

  // Embeddings (E-01)
  cortexReembed(memoryType: string | null): unknown;

  // Decay (C-07)
  cortexDecayRun(): unknown;

  // Health
  cortexHealthGetHealth(): unknown;
  cortexHealthGetMetrics(): unknown;
  cortexHealthGetDegradations(): unknown;

  // Generation
  cortexGenerationBuildContext(
    focus: string,
    activeFiles: string[] | null,
    budget: number | null,
    sentIds: string[] | null,
  ): unknown;
  cortexGenerationTrackOutcome(
    memoryIds: string[],
    wasUseful: boolean,
    sessionId: string | null,
  ): void;

  // Prediction
  cortexPredictionPredict(
    activeFiles: string[] | null,
    recentQueries: string[] | null,
    currentIntent: string | null,
  ): unknown;
  cortexPredictionPreload(activeFiles: string[] | null): unknown;
  cortexPredictionGetCacheStats(): unknown;

  // Privacy
  cortexPrivacySanitize(text: string): unknown;
  cortexPrivacyGetPatternStats(): unknown;

  // Cloud
  cortexCloudSync(): unknown;
  cortexCloudGetStatus(): unknown;
  cortexCloudResolveConflict(memoryId: string, resolution: string): Record<string, unknown>;

  // Session
  cortexSessionCreate(sessionId: string | null): string;
  cortexSessionGet(sessionId: string): unknown;
  cortexSessionCleanup(): number;
  cortexSessionAnalytics(sessionId: string): unknown;

  // Validation (E-02)
  cortexValidationRun(minConfidence: number | null, maxConfidence: number | null): Record<string, unknown>;

  // Temporal
  cortexTemporalQueryAsOf(
    systemTime: string,
    validTime: string,
    filter: string | null,
  ): unknown;
  cortexTemporalQueryRange(from: string, to: string, mode: string): unknown;
  cortexTemporalQueryDiff(timeA: string, timeB: string, scope: string | null): unknown;
  cortexTemporalReplayDecision(decisionId: string, budget: number | null): unknown;
  cortexTemporalQueryTemporalCausal(
    memoryId: string,
    asOf: string,
    direction: string,
    depth: number,
  ): unknown;
  cortexTemporalGetDriftMetrics(windowHours: number | null): unknown;
  cortexTemporalGetDriftAlerts(): unknown;
  cortexTemporalCreateMaterializedView(label: string, timestamp: string): unknown;
  cortexTemporalGetMaterializedView(label: string): unknown;
  cortexTemporalListMaterializedViews(): unknown;

  // Multi-Agent (12)
  cortexMultiagentRegisterAgent(name: string, capabilities: string[]): unknown;
  cortexMultiagentDeregisterAgent(agentId: string): void;
  cortexMultiagentGetAgent(agentId: string): unknown;
  cortexMultiagentListAgents(statusFilter: string | null): unknown;
  cortexMultiagentCreateNamespace(scope: string, name: string, owner: string): string;
  cortexMultiagentShareMemory(memoryId: string, targetNamespace: string, agentId: string): unknown;
  cortexMultiagentCreateProjection(configJson: unknown): string;
  cortexMultiagentRetractMemory(memoryId: string, namespace: string, agentId: string): void;
  cortexMultiagentGetProvenance(memoryId: string): unknown;
  cortexMultiagentTraceCrossAgent(memoryId: string, maxDepth: number): unknown;
  cortexMultiagentGetTrust(agentId: string, targetAgent: string | null): unknown;
  cortexMultiagentSyncAgents(sourceAgent: string, targetAgent: string): unknown;
}

/**
 * Load the native NAPI module.
 * Tries require('drift-cortex-napi') which resolves to the platform-specific binary.
 * Falls back to a structurally valid stub when the native binary is unavailable.
 */
export function loadNativeModule(): NativeBindings {
  if (nativeModule) return nativeModule;

  try {
    // The napi-rs build produces a platform-specific .node file
    // published as drift-cortex-napi with optional dependencies per platform.
    nativeModule = esmRequire("drift-cortex-napi") as NativeBindings;
    nativeIsStub = false;
    return nativeModule;
  } catch {
    // Fall back to stub when native binary is unavailable.
    // This enables development, testing, and graceful degradation.
    console.warn(
      '[cortex] \u26a0 Native binary unavailable \u2014 using stub fallback. ' +
      'All Cortex operations will return empty/no-op results. Build drift-cortex-napi to enable real functionality.',
    );
    nativeModule = createStubNativeModule();
    nativeIsStub = true;
    return nativeModule;
  }
}

/**
 * Get the loaded native module, or throw if not yet loaded.
 */
export function getNativeModule(): NativeBindings {
  if (!nativeModule) {
    throw new Error(
      "Native module not loaded. Call loadNativeModule() or CortexClient.initialize() first.",
    );
  }
  return nativeModule;
}

/**
 * Check if the native module is loaded.
 */
export function isNativeModuleLoaded(): boolean {
  return nativeModule !== null;
}

/** Reset the module reference (for testing). */
export function resetNativeModule(): void {
  nativeModule = null;
  nativeIsStub = false;
}

/**
 * Check if the native module is a stub (native binary unavailable).
 */
export function isNativeStub(): boolean {
  return nativeIsStub;
}
