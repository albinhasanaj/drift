/**
 * Additional stub coverage tests — exercises every stub method to reach ≥90% coverage.
 * Covers all structural, graph, enforcement, feedback, and advanced stubs.
 */

import { describe, it, expect } from 'vitest';
import { createStubNapi } from '../src/stub.js';

describe('Stub — Full Method Coverage', () => {
  const stub = createStubNapi();

  // Lifecycle
  it('driftInitialize is no-op', () => {
    expect(() => stub.driftInitialize()).not.toThrow();
    expect(() => stub.driftInitialize('db.sqlite', '/root', 'toml')).not.toThrow();
  });

  it('driftShutdown is no-op', () => {
    expect(() => stub.driftShutdown()).not.toThrow();
  });

  it('driftCancelScan is no-op', () => {
    expect(() => stub.driftCancelScan()).not.toThrow();
  });

  // Patterns — all 4
  it('drift_patterns returns valid shape', () => {
    const r = stub.driftPatterns();
    expect(r.patterns).toEqual([]);
    expect(r.hasMore).toBe(false);
    expect(r.nextCursor).toBeNull();

    // With args
    const r2 = stub.driftPatterns('naming', 'cursor-1', 50);
    expect(r2.patterns).toEqual([]);
  });

  it('drift_confidence returns valid shape', () => {
    const r = stub.driftConfidence();
    expect(r.scores).toEqual([]);
    expect(r.hasMore).toBe(false);

    const r2 = stub.driftConfidence('high', 'after', 10);
    expect(r2.scores).toEqual([]);
  });

  it('drift_outliers returns valid shape', () => {
    const r = stub.driftOutliers();
    expect(r.outliers).toEqual([]);

    const r2 = stub.driftOutliers('pat-1', 5, 20);
    expect(r2.outliers).toEqual([]);
  });

  it('drift_conventions returns valid shape', () => {
    const r = stub.driftConventions();
    expect(r.conventions).toEqual([]);

    const r2 = stub.driftConventions('naming', 3, 100);
    expect(r2.conventions).toEqual([]);
  });

  // Graph — all 5
  it('drift_reachability returns valid shape with source echoed', () => {
    const r = stub.driftReachability('myFunc', 'forward');
    expect(r.source).toBe('myFunc');
    expect(r.reachableCount).toBe(0);
    expect(r.sensitivity).toBe('low');
    expect(r.maxDepth).toBe(0);
    expect(r.engine).toBe('petgraph');
  });

  it('drift_taint_analysis returns valid shape', () => {
    const r = stub.driftTaintAnalysis('/src');
    expect(r.flows).toEqual([]);
    expect(r.vulnerabilityCount).toBe(0);
    expect(r.sourceCount).toBe(0);
    expect(r.sinkCount).toBe(0);
  });

  it('drift_error_handling returns valid shape', () => {
    const r = stub.driftErrorHandling('/src');
    expect(r.gaps).toEqual([]);
    expect(r.handlerCount).toBe(0);
    expect(r.unhandledCount).toBe(0);
  });

  it('drift_impact_analysis returns valid shape', () => {
    const r = stub.driftImpactAnalysis('/src');
    expect(r.blastRadii).toEqual([]);
    expect(r.deadCode).toEqual([]);
  });

  it('drift_test_topology returns valid shape with nested quality', () => {
    const r = stub.driftTestTopology('/src');
    expect(r.testCount).toBe(0);
    expect(r.sourceCount).toBe(0);
    expect(r.coveragePercent).toBe(0);
    expect(r.minimumTestSetSize).toBe(0);
    expect(r.quality.coverageBreadth).toBe(0);
    expect(r.quality.isolation).toBe(1);
    expect(r.quality.freshness).toBe(1);
    expect(r.quality.stability).toBe(1);
    expect(r.quality.smellCount).toBe(0);
  });

  // Structural — all 9
  it('drift_coupling_analysis returns valid shape', () => {
    const r = stub.driftCouplingAnalysis('/src');
    expect(r.metrics).toEqual([]);
    expect(r.cycles).toEqual([]);
    expect(r.moduleCount).toBe(0);
  });

  it('drift_constraint_verification returns valid shape', () => {
    const r = stub.driftConstraintVerification('/src');
    expect(r.totalConstraints).toBe(0);
    expect(r.passing).toBe(0);
    expect(r.failing).toBe(0);
    expect(r.violations).toEqual([]);
  });

  it('drift_contract_tracking returns valid shape', () => {
    const r = stub.driftContractTracking('/src');
    expect(r.endpoints).toEqual([]);
    expect(r.mismatches).toEqual([]);
    expect(r.paradigmCount).toBe(0);
    expect(r.frameworkCount).toBe(0);
  });

  it('drift_constants_analysis returns valid shape', () => {
    const r = stub.driftConstantsAnalysis('/src');
    expect(r.constantCount).toBe(0);
    expect(r.secrets).toEqual([]);
    expect(r.magicNumbers).toEqual([]);
    expect(r.missingEnvVars).toEqual([]);
    expect(r.deadConstantCount).toBe(0);
  });

  it('drift_wrapper_detection returns valid shape with nested health', () => {
    const r = stub.driftWrapperDetection('/src');
    expect(r.wrappers).toEqual([]);
    expect(r.frameworkCount).toBe(0);
    expect(r.categoryCount).toBe(0);
    expect(r.health.consistency).toBe(0);
    expect(r.health.coverage).toBe(0);
    expect(r.health.abstractionDepth).toBe(0);
    expect(r.health.overall).toBe(0);
  });

  it('drift_dna_analysis returns valid shape with nested health', () => {
    const r = stub.driftDnaAnalysis('/src');
    expect(r.genes).toEqual([]);
    expect(r.mutations).toEqual([]);
    expect(r.geneticDiversity).toBe(0);
    expect(r.health.overall).toBe(0);
    expect(r.health.consistency).toBe(0);
    expect(r.health.confidence).toBe(0);
    expect(r.health.mutationScore).toBe(1);
    expect(r.health.coverage).toBe(0);
  });

  it('drift_owasp_analysis returns valid shape with nested compliance', () => {
    const r = stub.driftOwaspAnalysis('/src');
    expect(r.findings).toEqual([]);
    expect(r.compliance.postureScore).toBe(100);
    expect(r.compliance.owaspCoverage).toBe(0);
    expect(r.compliance.cweTop25Coverage).toBe(0);
    expect(r.compliance.criticalCount).toBe(0);
    expect(r.compliance.highCount).toBe(0);
    expect(r.compliance.mediumCount).toBe(0);
    expect(r.compliance.lowCount).toBe(0);
  });

  it('drift_crypto_analysis returns valid shape with nested health', () => {
    const r = stub.driftCryptoAnalysis('/src');
    expect(r.findings).toEqual([]);
    expect(r.health.overall).toBe(100);
    expect(r.health.criticalCount).toBe(0);
    expect(r.health.highCount).toBe(0);
    expect(r.health.mediumCount).toBe(0);
  });

  it('drift_decomposition returns valid shape', () => {
    const r = stub.driftDecomposition('/src');
    expect(r.modules).toEqual([]);
    expect(r.moduleCount).toBe(0);
    expect(r.totalFiles).toBe(0);
    expect(r.avgCohesion).toBe(0);
    expect(r.avgCoupling).toBe(0);
  });

  // Enforcement — all 4
  it('drift_check returns valid shape', () => {
    const r = stub.driftCheck('/src');
    expect(r.overallPassed).toBe(true);
    expect(r.totalViolations).toBe(0);
    expect(r.gates).toEqual([]);
    expect(r.sarif).toBeNull();
  });

  it('drift_audit returns valid shape with nested breakdown', () => {
    const r = stub.driftAudit('/src');
    expect(r.healthScore).toBe(100);
    expect(r.trend).toBe('stable');
    expect(r.degradationAlerts).toEqual([]);
    expect(r.breakdown.avgConfidence).toBe(0);
    expect(r.breakdown.complianceRate).toBe(1);
    expect(r.breakdown.duplicateFreeRate).toBe(1);
  });

  it('drift_violations returns empty array', () => {
    const r = stub.driftViolations('/src');
    expect(r).toEqual([]);
  });

  it('drift_gates returns empty array', () => {
    const r = stub.driftGates('/src');
    expect(r).toEqual([]);
  });

  // Feedback — all 3
  it('drift_dismiss_violation returns success', () => {
    const r = stub.driftDismissViolation({ violationId: 'v1', action: 'dismiss' });
    expect(r.success).toBe(true);
    expect(r.message).toBeTruthy();
  });

  it('drift_fix_violation returns success', () => {
    const r = stub.driftFixViolation('v1');
    expect(r.success).toBe(true);
    expect(r.message).toBeTruthy();
  });

  it('drift_suppress_violation returns success', () => {
    const r = stub.driftSuppressViolation('v1', 'false positive');
    expect(r.success).toBe(true);
    expect(r.message).toBeTruthy();
  });

  // Advanced — all 4 (async, parse JSON)
  it('drift_simulate returns valid JSON', async () => {
    const r = await stub.driftSimulate('fix_bug', 'fix auth', '{}');
    const parsed = JSON.parse(r);
    expect(parsed).toHaveProperty('strategies');
    expect(parsed).toHaveProperty('taskCategory');
    expect(parsed).toHaveProperty('taskDescription');
  });

  it('drift_decisions returns valid JSON', async () => {
    const r = await stub.driftDecisions('/repo');
    const parsed = JSON.parse(r);
    expect(parsed).toHaveProperty('decisions');
    expect(parsed.decisions).toEqual([]);
  });

  it('drift_context returns valid JSON', async () => {
    const r = await stub.driftContext('understand_code', 'deep', '{}');
    const parsed = JSON.parse(r);
    expect(parsed).toHaveProperty('sections');
    expect(parsed).toHaveProperty('tokenCount');
    expect(parsed).toHaveProperty('intent');
    expect(parsed).toHaveProperty('depth');
  });

  it('drift_generate_spec returns valid JSON', async () => {
    const r = await stub.driftGenerateSpec('{}');
    const parsed = JSON.parse(r);
    expect(parsed).toHaveProperty('moduleName');
    expect(parsed).toHaveProperty('sections');
    expect(parsed).toHaveProperty('totalTokenCount');
    expect(parsed).toHaveProperty('hasAllSections');

    // With optional migration path
    const r2 = await stub.driftGenerateSpec('{}', '{}');
    expect(JSON.parse(r2)).toHaveProperty('moduleName');
  });
});
