/**
 * DriftNapi — The single source of truth for all Rust↔TypeScript NAPI function signatures.
 *
 * Every method in this interface corresponds to a `#[napi]` export in
 * `crates/drift/drift-napi/src/bindings/*.rs`. Function names and parameter
 * types MUST match Rust exactly. When Rust disagrees with TypeScript, Rust wins.
 *
 * 66 methods total, grouped by Rust binding module:
 * - Lifecycle (4): lifecycle.rs
 * - Scanner (3): scanner.rs
 * - Analysis (4): analysis.rs
 * - Patterns (4): patterns.rs
 * - Graph (5): graph.rs
 * - Structural (9): structural.rs
 * - Enforcement (7): enforcement.rs
 * - Feedback (3): feedback.rs
 * - Advanced (4): advanced.rs
 * - Bridge (21): bridge.rs
 * - Cloud (2): cloud.rs
 */

import type { ScanOptions, ScanSummary } from './types/scanner.js';
import type { ProgressCallback } from './types/lifecycle.js';
import type {
  JsAnalysisResult,
  JsCallGraphResult,
  JsBoundaryResult,
  JsValidatePackResult,
} from './types/analysis.js';
import type {
  PatternsResult,
  ConfidenceResult,
  OutlierResult,
  ConventionResult,
} from './types/patterns.js';
import type {
  JsReachabilityResult,
  JsTaintResult,
  JsErrorHandlingResult,
  JsImpactResult,
  JsTestTopologyResult,
} from './types/graph.js';
import type {
  JsCouplingResult,
  JsConstraintResult,
  JsContractResult,
  JsConstantsResult,
  JsWrapperResult,
  JsDnaResult,
  JsOwaspResult,
  JsCryptoResult,
  JsDecompositionResult,
} from './types/structural.js';
import type {
  JsCheckResult,
  JsAuditResult,
  JsViolation,
  JsGateResult,
  JsFeedbackInput,
  JsFeedbackResult,
  JsPatternStatusResult,
  JsApprovePatternResult,
  GcResult,
} from './types/enforcement.js';
import type {
  BridgeStatusResult,
  BridgeHealthResult,
  BridgeGroundingResult,
  BridgeGroundingSnapshot,
  BridgeGroundingHistoryResult,
  BridgeEntityLink,
  BridgeEventMappingsResult,
  BridgeGroundabilityResult,
  BridgeLicenseResult,
  BridgeIntentsResult,
  BridgeAdaptiveWeightsResult,
  BridgeSpecCorrectionResult,
  BridgeContractVerifiedResult,
  BridgeDecompositionAdjustedResult,
  BridgeExplainSpecResult,
  BridgeCounterfactualResult,
  BridgeInterventionResult,
  BridgeUnifiedNarrativeResult,
  BridgePruneCausalResult,
} from './types/bridge.js';

export interface DriftNapi {
  // ─── Lifecycle (4) — lifecycle.rs ────────────────────────────────────
  // Rust: driftInitialize(db_path: Option<String>, project_root: Option<String>, config_toml: Option<String>, cortex_db_path: Option<String>)
  driftInitialize(
    dbPath?: string,
    projectRoot?: string,
    configToml?: string,
    cortexDbPath?: string,
  ): void;

  // Rust: driftShutdown()
  driftShutdown(): void;

  // Rust: driftIsInitialized() -> bool
  driftIsInitialized(): boolean;

  // Rust: driftGC(short_days: Option<u32>, medium_days: Option<u32>, long_days: Option<u32>) -> serde_json::Value
  driftGC(
    shortDays?: number,
    mediumDays?: number,
    longDays?: number,
  ): GcResult;

  // ─── Scanner (3) — scanner.rs ────────────────────────────────────────
  // Rust: driftScan(root: String, options: Option<ScanOptions>) -> AsyncTask<ScanTask>
  driftScan(root: string, options?: ScanOptions): Promise<ScanSummary>;

  // Rust: driftScanWithProgress(root: String, options: Option<ScanOptions>, on_progress: ThreadsafeFunction)
  driftScanWithProgress(
    root: string,
    options: ScanOptions | undefined,
    onProgress: ProgressCallback,
  ): Promise<ScanSummary>;

  // Rust: driftCancelScan()
  driftCancelScan(): void;

  // ─── Analysis (3) — analysis.rs ──────────────────────────────────────
  // Rust: drift_analyze(max_phase: Option<u32>) -> Vec<JsAnalysisResult>
  driftAnalyze(maxPhase?: number): Promise<JsAnalysisResult[]>;

  // Rust: drift_call_graph() -> JsCallGraphResult
  driftCallGraph(): Promise<JsCallGraphResult>;

  // Rust: drift_boundaries() -> JsBoundaryResult
  driftBoundaries(): Promise<JsBoundaryResult>;

  // Rust: drift_validate_pack(toml_content: String) -> JsValidatePackResult
  driftValidatePack(tomlContent: string): JsValidatePackResult;

  // ─── Patterns (4) — patterns.rs ──────────────────────────────────────
  // Rust: drift_patterns(category: Option<String>, after_id: Option<String>, limit: Option<u32>)
  driftPatterns(
    category?: string,
    afterId?: string,
    limit?: number,
  ): PatternsResult;

  // Rust: drift_confidence(tier: Option<String>, after_id: Option<String>, limit: Option<u32>)
  driftConfidence(
    tier?: string,
    afterId?: string,
    limit?: number,
  ): ConfidenceResult;

  // Rust: drift_outliers(pattern_id: Option<String>, after_id: Option<u32>, limit: Option<u32>)
  driftOutliers(
    patternId?: string,
    afterId?: number,
    limit?: number,
  ): OutlierResult;

  // Rust: drift_conventions(category: Option<String>, after_id: Option<u32>, limit: Option<u32>)
  driftConventions(
    category?: string,
    afterId?: number,
    limit?: number,
  ): ConventionResult;

  // ─── Graph (5) — graph.rs ────────────────────────────────────────────
  // Rust: drift_reachability(function_key: String, direction: String)
  driftReachability(
    functionKey: string,
    direction: string,
  ): JsReachabilityResult;

  // Rust: drift_taint_analysis(root: String)
  driftTaintAnalysis(root: string): JsTaintResult;

  // Rust: drift_error_handling(root: String)
  driftErrorHandling(root: string): JsErrorHandlingResult;

  // Rust: drift_impact_analysis(root: String)
  driftImpactAnalysis(root: string): JsImpactResult;

  // Rust: drift_test_topology(root: String)
  driftTestTopology(root: string): JsTestTopologyResult;

  // ─── Structural (9) — structural.rs ──────────────────────────────────
  // Rust: drift_coupling_analysis(root: String)
  driftCouplingAnalysis(root: string): JsCouplingResult;

  // Rust: drift_constraint_verification(root: String)
  driftConstraintVerification(root: string): JsConstraintResult;

  // Rust: drift_contract_tracking(root: String)
  driftContractTracking(root: string): JsContractResult;

  // Rust: drift_constants_analysis(root: String)
  driftConstantsAnalysis(root: string): JsConstantsResult;

  // Rust: drift_wrapper_detection(root: String)
  driftWrapperDetection(root: string): JsWrapperResult;

  // Rust: drift_dna_analysis(root: String)
  driftDnaAnalysis(root: string): JsDnaResult;

  // Rust: drift_owasp_analysis(root: String)
  driftOwaspAnalysis(root: string): JsOwaspResult;

  // Rust: drift_crypto_analysis(root: String)
  driftCryptoAnalysis(root: string): JsCryptoResult;

  // Rust: drift_decomposition(root: String)
  driftDecomposition(root: string): JsDecompositionResult;

  // ─── Enforcement (7) — enforcement.rs ────────────────────────────────
  // Rust: drift_check(_root: String)
  driftCheck(root: string): JsCheckResult;

  // Rust: drift_audit(_root: String)
  driftAudit(root: string): JsAuditResult;

  // Rust: drift_violations(_root: String) -> Vec<JsViolation>
  driftViolations(root: string): JsViolation[];

  // Rust: drift_gates(_root: String) -> Vec<JsGateResult>
  driftGates(root: string): JsGateResult[];

  // Rust: drift_report(format: String) -> String
  driftReport(format: string): string;

  // Rust: drift_approve_pattern(pattern_id: String, status: String, reason: Option<String>)
  driftApprovePattern(
    patternId: string,
    status: string,
    reason: string | null,
  ): JsApprovePatternResult;

  // Rust: drift_pattern_status(status_filter: Option<String>)
  driftPatternStatus(
    statusFilter: string | null,
  ): JsPatternStatusResult;

  // ─── Feedback (3) — feedback.rs ──────────────────────────────────────
  // Rust: drift_dismiss_violation(input: JsFeedbackInput)
  driftDismissViolation(input: JsFeedbackInput): JsFeedbackResult;

  // Rust: drift_fix_violation(violation_id: String)
  driftFixViolation(violationId: string): JsFeedbackResult;

  // Rust: drift_suppress_violation(violation_id: String, reason: String)
  driftSuppressViolation(
    violationId: string,
    reason: string,
  ): JsFeedbackResult;

  // ─── Advanced (4) — advanced.rs ──────────────────────────────────────
  // Rust: drift_simulate(task_category: String, task_description: String, context_json: String)
  driftSimulate(
    taskCategory: string,
    taskDescription: string,
    contextJson: string,
  ): Promise<string>;

  // Rust: drift_decisions(repo_path: String)
  driftDecisions(repoPath: string): Promise<string>;

  // Rust: drift_context(intent: String, depth: String, data_json: String)
  driftContext(
    intent: string,
    depth: string,
    dataJson: string,
  ): Promise<string>;

  // Rust: drift_generate_spec(module_json: String, migration_path_json: Option<String>)
  driftGenerateSpec(
    moduleJson: string,
    migrationPathJson?: string,
  ): Promise<string>;

  // ─── Bridge (20) — bridge.rs ────────────────────────────────────────
  // Rust: drift_bridge_status()
  driftBridgeStatus(): BridgeStatusResult;

  // Rust: drift_bridge_ground_memory(memory_id: String, memory_type: String)
  driftBridgeGroundMemory(memoryId: string, memoryType: string): BridgeGroundingResult;

  // Rust: drift_bridge_ground_all()
  driftBridgeGroundAll(): BridgeGroundingSnapshot;

  // Rust: drift_bridge_grounding_history(memory_id: String, limit: Option<u32>)
  driftBridgeGroundingHistory(memoryId: string, limit?: number): BridgeGroundingHistoryResult;

  // Rust: drift_bridge_translate_link(pattern_id: String, pattern_name: String, confidence: f64)
  driftBridgeTranslateLink(patternId: string, patternName: string, confidence: number): BridgeEntityLink;

  // Rust: drift_bridge_translate_constraint_link(constraint_id: String, constraint_name: String)
  driftBridgeTranslateConstraintLink(constraintId: string, constraintName: string): BridgeEntityLink;

  // Rust: drift_bridge_event_mappings()
  driftBridgeEventMappings(): BridgeEventMappingsResult;

  // Rust: drift_bridge_groundability(memory_type: String)
  driftBridgeGroundability(memoryType: string): BridgeGroundabilityResult;

  // Rust: drift_bridge_license_check(feature: String)
  driftBridgeLicenseCheck(feature: string): BridgeLicenseResult;

  // Rust: drift_bridge_intents()
  driftBridgeIntents(): BridgeIntentsResult;

  // Rust: drift_bridge_adaptive_weights(feedback_json: String)
  driftBridgeAdaptiveWeights(feedbackJson: string): BridgeAdaptiveWeightsResult;

  // Rust: drift_bridge_spec_correction(correction_json: String)
  driftBridgeSpecCorrection(correctionJson: string): BridgeSpecCorrectionResult;

  // Rust: drift_bridge_contract_verified(module_id: String, passed: bool, section: String, mismatch_type: Option<String>, severity: Option<f64>)
  driftBridgeContractVerified(moduleId: string, passed: boolean, section: string, mismatchType?: string, severity?: number): BridgeContractVerifiedResult;

  // Rust: drift_bridge_decomposition_adjusted(module_id: String, adjustment_type: String, dna_hash: String)
  driftBridgeDecompositionAdjusted(moduleId: string, adjustmentType: string, dnaHash: string): BridgeDecompositionAdjustedResult;

  // Rust: drift_bridge_explain_spec(memory_id: String)
  driftBridgeExplainSpec(memoryId: string): BridgeExplainSpecResult;

  // Rust: drift_bridge_counterfactual(memory_id: String)
  driftBridgeCounterfactual(memoryId: string): BridgeCounterfactualResult;

  // Rust: drift_bridge_intervention(memory_id: String)
  driftBridgeIntervention(memoryId: string): BridgeInterventionResult;

  // Rust: drift_bridge_health()
  driftBridgeHealth(): BridgeHealthResult;

  // Rust: drift_bridge_unified_narrative(memory_id: String)
  driftBridgeUnifiedNarrative(memoryId: string): BridgeUnifiedNarrativeResult;

  // Rust: drift_bridge_prune_causal(threshold: Option<f64>)
  driftBridgePruneCausal(threshold?: number): BridgePruneCausalResult;

  // Rust: drift_bridge_ground_after_analyze()
  driftBridgeGroundAfterAnalyze(): BridgeGroundingSnapshot;

  // ─── Cloud (2) — cloud.rs ──────────────────────────────────────
  // Rust: drift_cloud_read_rows(table: String, db: String, after_cursor: Option<i64>, limit: Option<u32>) -> serde_json::Value
  driftCloudReadRows(
    table: string,
    db: string,
    afterCursor?: number,
    limit?: number,
  ): unknown[];

  // Rust: drift_cloud_max_cursor(db: String) -> i64
  driftCloudMaxCursor(db: string): number;
}

/** Total number of methods in the DriftNapi interface. */
export const DRIFT_NAPI_METHOD_COUNT = 66;

/** All method names in the DriftNapi interface, for runtime validation. */
export const DRIFT_NAPI_METHOD_NAMES: ReadonlyArray<keyof DriftNapi> = [
  // Lifecycle (4)
  'driftInitialize',
  'driftShutdown',
  'driftIsInitialized',
  'driftGC',
  // Scanner (3)
  'driftScan',
  'driftScanWithProgress',
  'driftCancelScan',
  // Analysis (4)
  'driftAnalyze',
  'driftCallGraph',
  'driftBoundaries',
  'driftValidatePack',
  // Patterns (4)
  'driftPatterns',
  'driftConfidence',
  'driftOutliers',
  'driftConventions',
  // Graph (5)
  'driftReachability',
  'driftTaintAnalysis',
  'driftErrorHandling',
  'driftImpactAnalysis',
  'driftTestTopology',
  // Structural (9)
  'driftCouplingAnalysis',
  'driftConstraintVerification',
  'driftContractTracking',
  'driftConstantsAnalysis',
  'driftWrapperDetection',
  'driftDnaAnalysis',
  'driftOwaspAnalysis',
  'driftCryptoAnalysis',
  'driftDecomposition',
  // Enforcement (7)
  'driftCheck',
  'driftAudit',
  'driftViolations',
  'driftGates',
  'driftReport',
  'driftApprovePattern',
  'driftPatternStatus',
  // Feedback (3)
  'driftDismissViolation',
  'driftFixViolation',
  'driftSuppressViolation',
  // Advanced (4)
  'driftSimulate',
  'driftDecisions',
  'driftContext',
  'driftGenerateSpec',
  // Bridge (20)
  'driftBridgeStatus',
  'driftBridgeGroundMemory',
  'driftBridgeGroundAll',
  'driftBridgeGroundingHistory',
  'driftBridgeTranslateLink',
  'driftBridgeTranslateConstraintLink',
  'driftBridgeEventMappings',
  'driftBridgeGroundability',
  'driftBridgeLicenseCheck',
  'driftBridgeIntents',
  'driftBridgeAdaptiveWeights',
  'driftBridgeSpecCorrection',
  'driftBridgeContractVerified',
  'driftBridgeDecompositionAdjusted',
  'driftBridgeExplainSpec',
  'driftBridgeCounterfactual',
  'driftBridgeIntervention',
  'driftBridgeHealth',
  'driftBridgeUnifiedNarrative',
  'driftBridgePruneCausal',
  'driftBridgeGroundAfterAnalyze',
  // Cloud (2)
  'driftCloudReadRows',
  'driftCloudMaxCursor',
] as const;
