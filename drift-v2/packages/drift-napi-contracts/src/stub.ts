/**
 * Complete stub implementation of DriftNapi.
 *
 * Every method returns structurally valid typed data matching the Rust return types.
 * No `{}` returns — every field present with sensible empty/zero defaults.
 * Used as fallback when native binary is unavailable, and for testing.
 */

import type { DriftNapi } from './interface.js';
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

/** Create a complete stub DriftNapi with all 64 methods returning valid typed data. */
export function createStubNapi(): DriftNapi {
  return {
    // ─── Lifecycle (4) ───────────────────────────────────────────────
    driftInitialize(
      _dbPath?: string,
      _projectRoot?: string,
      _configToml?: string,
      _cortexDbPath?: string,
    ): void {
      // no-op
    },

    driftShutdown(): void {
      // no-op
    },

    driftIsInitialized(): boolean {
      return false;
    },

    driftGC(
      _shortDays?: number,
      _mediumDays?: number,
      _longDays?: number,
    ): GcResult {
      return { totalDeleted: 0, durationMs: 0, perTable: [] };
    },

    // ─── Scanner (3) ─────────────────────────────────────────────────
    async driftScan(
      _root: string,
      _options?: ScanOptions,
    ): Promise<ScanSummary> {
      return {
        filesTotal: 0,
        filesAdded: 0,
        filesModified: 0,
        filesRemoved: 0,
        filesUnchanged: 0,
        errorsCount: 0,
        durationMs: 0,
        status: 'complete',
        languages: {},
      };
    },

    async driftScanWithProgress(
      _root: string,
      _options: ScanOptions | undefined,
      _onProgress: ProgressCallback,
    ): Promise<ScanSummary> {
      return {
        filesTotal: 0,
        filesAdded: 0,
        filesModified: 0,
        filesRemoved: 0,
        filesUnchanged: 0,
        errorsCount: 0,
        durationMs: 0,
        status: 'complete',
        languages: {},
      };
    },

    driftCancelScan(): void {
      // no-op
    },

    // ─── Analysis (4) ────────────────────────────────────────────────
    async driftAnalyze(_maxPhase?: number): Promise<JsAnalysisResult[]> {
      return [];
    },

    async driftCallGraph(): Promise<JsCallGraphResult> {
      return {
        totalFunctions: 0,
        totalEdges: 0,
        entryPoints: 0,
        resolutionRate: 0,
        buildDurationMs: 0,
      };
    },

    async driftBoundaries(): Promise<JsBoundaryResult> {
      return {
        models: [],
        sensitiveFields: [],
        frameworksDetected: [],
      };
    },

    driftValidatePack(_tomlContent: string): JsValidatePackResult {
      return {
        valid: false,
        name: null,
        version: null,
        languageCount: 0,
        patternCount: 0,
        error: 'Stub: native binary not available',
      };
    },

    // ─── Patterns (4) ────────────────────────────────────────────────
    driftPatterns(
      _category?: string,
      _afterId?: string,
      _limit?: number,
    ): PatternsResult {
      return { patterns: [], hasMore: false, nextCursor: null };
    },

    driftConfidence(
      _tier?: string,
      _afterId?: string,
      _limit?: number,
    ): ConfidenceResult {
      return { scores: [], hasMore: false, nextCursor: null };
    },

    driftOutliers(
      _patternId?: string,
      _afterId?: number,
      _limit?: number,
    ): OutlierResult {
      return { outliers: [], hasMore: false, nextCursor: null };
    },

    driftConventions(
      _category?: string,
      _afterId?: number,
      _limit?: number,
    ): ConventionResult {
      return { conventions: [], hasMore: false, nextCursor: null };
    },

    // ─── Graph (5) ───────────────────────────────────────────────────
    driftReachability(
      functionKey: string,
      _direction: string,
    ): JsReachabilityResult {
      return {
        source: functionKey,
        reachableCount: 0,
        sensitivity: 'low',
        maxDepth: 0,
        engine: 'petgraph',
      };
    },

    driftTaintAnalysis(_root: string): JsTaintResult {
      return {
        flows: [],
        vulnerabilityCount: 0,
        sourceCount: 0,
        sinkCount: 0,
      };
    },

    driftErrorHandling(_root: string): JsErrorHandlingResult {
      return {
        gaps: [],
        handlerCount: 0,
        unhandledCount: 0,
      };
    },

    driftImpactAnalysis(_root: string): JsImpactResult {
      return {
        blastRadii: [],
        deadCode: [],
      };
    },

    driftTestTopology(_root: string): JsTestTopologyResult {
      return {
        quality: {
          coverageBreadth: 0,
          coverageDepth: 0,
          assertionDensity: 0,
          mockRatio: 0,
          isolation: 1,
          freshness: 1,
          stability: 1,
          overall: 0,
          smellCount: 0,
        },
        testCount: 0,
        sourceCount: 0,
        coveragePercent: 0,
        minimumTestSetSize: 0,
      };
    },

    // ─── Structural (9) ──────────────────────────────────────────────
    driftCouplingAnalysis(_root: string): JsCouplingResult {
      return { metrics: [], cycles: [], moduleCount: 0 };
    },

    driftConstraintVerification(_root: string): JsConstraintResult {
      return {
        totalConstraints: 0,
        passing: 0,
        failing: 0,
        violations: [],
      };
    },

    driftContractTracking(_root: string): JsContractResult {
      return {
        endpoints: [],
        mismatches: [],
        paradigmCount: 0,
        frameworkCount: 0,
      };
    },

    driftConstantsAnalysis(_root: string): JsConstantsResult {
      return {
        constantCount: 0,
        secrets: [],
        magicNumbers: [],
        missingEnvVars: [],
        deadConstantCount: 0,
      };
    },

    driftWrapperDetection(_root: string): JsWrapperResult {
      return {
        wrappers: [],
        health: {
          consistency: 0,
          coverage: 0,
          abstractionDepth: 0,
          overall: 0,
        },
        frameworkCount: 0,
        categoryCount: 0,
      };
    },

    driftDnaAnalysis(_root: string): JsDnaResult {
      return {
        genes: [],
        mutations: [],
        health: {
          overall: 0,
          consistency: 0,
          confidence: 0,
          mutationScore: 1,
          coverage: 0,
        },
        geneticDiversity: 0,
      };
    },

    driftOwaspAnalysis(_root: string): JsOwaspResult {
      return {
        findings: [],
        compliance: {
          postureScore: 100,
          owaspCoverage: 0,
          cweTop25Coverage: 0,
          criticalCount: 0,
          highCount: 0,
          mediumCount: 0,
          lowCount: 0,
        },
      };
    },

    driftCryptoAnalysis(_root: string): JsCryptoResult {
      return {
        findings: [],
        health: {
          overall: 100,
          criticalCount: 0,
          highCount: 0,
          mediumCount: 0,
        },
      };
    },

    driftDecomposition(_root: string): JsDecompositionResult {
      return {
        modules: [],
        moduleCount: 0,
        totalFiles: 0,
        avgCohesion: 0,
        avgCoupling: 0,
      };
    },

    // ─── Enforcement (5) ─────────────────────────────────────────────
    driftCheck(_root: string): JsCheckResult {
      return {
        overallPassed: true,
        totalViolations: 0,
        gates: [],
        sarif: null,
      };
    },

    driftAudit(_root: string): JsAuditResult {
      return {
        healthScore: 100,
        breakdown: {
          avgConfidence: 0,
          approvalRatio: 0,
          complianceRate: 1,
          crossValidationRate: 0,
          duplicateFreeRate: 1,
        },
        trend: 'stable',
        degradationAlerts: [],
        autoApprovedCount: 0,
        needsReviewCount: 0,
        dataCompleteness: 1,
      };
    },

    driftViolations(_root: string): JsViolation[] {
      return [];
    },

    driftGates(_root: string): JsGateResult[] {
      return [];
    },

    driftReport(_format: string): string {
      return '';
    },

    driftApprovePattern(
      _patternId: string,
      _status: string,
      _reason: string | null,
    ): JsApprovePatternResult {
      return {
        success: true,
        patternId: _patternId,
        previousStatus: 'discovered',
        newStatus: _status,
        message: `Stub: pattern ${_patternId} set to ${_status}`,
      };
    },

    driftPatternStatus(
      _statusFilter: string | null,
    ): JsPatternStatusResult {
      return {
        patterns: [],
        total: 0,
        counts: { discovered: 0, approved: 0, ignored: 0 },
      };
    },

    // ─── Feedback (3) ────────────────────────────────────────────────
    driftDismissViolation(_input: JsFeedbackInput): JsFeedbackResult {
      return { success: true, message: 'Stub: violation dismissed' };
    },

    driftFixViolation(_violationId: string): JsFeedbackResult {
      return { success: true, message: 'Stub: violation marked as fixed' };
    },

    driftSuppressViolation(
      _violationId: string,
      _reason: string,
    ): JsFeedbackResult {
      return { success: true, message: 'Stub: violation suppressed' };
    },

    // ─── Advanced (4) ────────────────────────────────────────────────
    async driftSimulate(
      _taskCategory: string,
      _taskDescription: string,
      _contextJson: string,
    ): Promise<string> {
      return JSON.stringify({
        strategies: [],
        taskCategory: _taskCategory,
        taskDescription: _taskDescription,
      });
    },

    async driftDecisions(_repoPath: string): Promise<string> {
      return JSON.stringify({ decisions: [] });
    },

    async driftContext(
      _intent: string,
      _depth: string,
      _dataJson: string,
    ): Promise<string> {
      return JSON.stringify({
        sections: [],
        tokenCount: 0,
        intent: _intent,
        depth: _depth,
      });
    },

    async driftGenerateSpec(
      _moduleJson: string,
      _migrationPathJson?: string,
    ): Promise<string> {
      return JSON.stringify({
        moduleName: '',
        sections: [],
        totalTokenCount: 0,
        hasAllSections: false,
      });
    },

    // ─── Bridge (20) ──────────────────────────────────────────────────

    driftBridgeStatus() {
      return {
        available: false,
        license_tier: 'Community',
        grounding_enabled: false,
        version: '0.1.0',
      };
    },

    driftBridgeGroundMemory(_memoryId: string, _memoryType: string) {
      return {
        memory_id: _memoryId,
        grounding_score: 0.0,
        classification: 'InsufficientData',
        evidence: [],
      };
    },

    driftBridgeGroundAll() {
      return {
        total_checked: 0,
        validated: 0,
        partial: 0,
        weak: 0,
        invalidated: 0,
        not_groundable: 0,
        insufficient_data: 0,
        avg_grounding_score: 0.0,
        contradictions_generated: 0,
        duration_ms: 0,
        error_count: 0,
        trigger_type: null,
      };
    },

    driftBridgeGroundingHistory(_memoryId: string, _limit?: number) {
      return {
        memory_id: _memoryId,
        history: [],
      };
    },

    driftBridgeTranslateLink(_patternId: string, _patternName: string, _confidence: number) {
      return {
        entity_type: 'pattern',
        entity_id: _patternId,
        entity_name: _patternName,
        confidence: _confidence,
        link_type: 'PatternLink',
      };
    },

    driftBridgeTranslateConstraintLink(_constraintId: string, _constraintName: string) {
      return {
        entity_type: 'constraint',
        entity_id: _constraintId,
        entity_name: _constraintName,
        confidence: 1.0,
        link_type: 'ConstraintLink',
      };
    },

    driftBridgeEventMappings() {
      return {
        mappings: [],
        count: 0,
      };
    },

    driftBridgeGroundability(_memoryType: string) {
      return {
        memory_type: _memoryType,
        groundability: 'Unknown',
      };
    },

    driftBridgeLicenseCheck(_feature: string) {
      return {
        feature: _feature,
        tier: 'Community',
        allowed: false,
      };
    },

    driftBridgeIntents() {
      return {
        intents: [],
        count: 0,
      };
    },

    driftBridgeAdaptiveWeights(_feedbackJson: string) {
      return {
        weights: {},
        failure_distribution: {},
        sample_size: 0,
        last_updated: new Date().toISOString(),
      };
    },

    driftBridgeSpecCorrection(_correctionJson: string) {
      return {
        memory_id: '',
        status: 'stub',
      };
    },

    driftBridgeContractVerified(
      _moduleId: string,
      _passed: boolean,
      _section: string,
      _mismatchType?: string,
      _severity?: number,
    ) {
      return {
        memory_id: '',
        passed: _passed,
      };
    },

    driftBridgeDecompositionAdjusted(
      _moduleId: string,
      _adjustmentType: string,
      _dnaHash: string,
    ) {
      return {
        memory_id: '',
        adjustment_type: _adjustmentType,
      };
    },

    driftBridgeExplainSpec(_memoryId: string) {
      return {
        memory_id: _memoryId,
        explanation: '',
      };
    },

    driftBridgeCounterfactual(_memoryId: string) {
      return {
        affected_count: 0,
        affected_ids: [],
        max_depth: 0,
        summary: '',
      };
    },

    driftBridgeIntervention(_memoryId: string) {
      return {
        impacted_count: 0,
        impacted_ids: [],
        max_depth: 0,
        summary: '',
      };
    },

    driftBridgeHealth() {
      return {
        status: 'unavailable',
        ready: false,
        subsystem_checks: [],
        degradation_reasons: ['Bridge not initialized (stub)'],
      };
    },

    driftBridgeUnifiedNarrative(_memoryId: string) {
      return {
        memory_id: _memoryId,
        sections: [],
        upstream: [],
        downstream: [],
        markdown: '',
      };
    },

    driftBridgePruneCausal(_threshold?: number) {
      return {
        edges_removed: 0,
        threshold: _threshold ?? 0.3,
      };
    },

    driftBridgeGroundAfterAnalyze() {
      return {
        total_checked: 0,
        validated: 0,
        partial: 0,
        weak: 0,
        invalidated: 0,
        not_groundable: 0,
        insufficient_data: 0,
        avg_grounding_score: 0,
        contradictions_generated: 0,
        duration_ms: 0,
        error_count: 0,
        trigger_type: 'manual_after_analyze',
      };
    },

    // ─── Cloud (2) ──────────────────────────────────────────────────

    driftCloudReadRows(
      _table: string,
      _db: string,
      _afterCursor?: number,
      _limit?: number,
    ): unknown[] {
      return [];
    },

    driftCloudMaxCursor(_db: string): number {
      return 0;
    },
  };
}
