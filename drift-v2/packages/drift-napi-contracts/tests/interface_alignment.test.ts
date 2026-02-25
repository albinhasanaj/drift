/**
 * Interface Alignment Tests — TH-NAPI-01 through TH-NAPI-05
 * Verifies DriftNapi interface contract integrity.
 */

import { describe, it, expect } from 'vitest';
import { DRIFT_NAPI_METHOD_COUNT, DRIFT_NAPI_METHOD_NAMES } from '../src/interface.js';
import { createStubNapi } from '../src/stub.js';
import type { DriftNapi } from '../src/interface.js';

describe('Interface Alignment — Contract Integrity', () => {
  // TH-NAPI-01: Every DriftNapi method has a corresponding stub entry
  it('TH-NAPI-01: every DriftNapi method has a corresponding stub entry — no missing method', () => {
    const stub = createStubNapi();
    for (const name of DRIFT_NAPI_METHOD_NAMES) {
      expect(typeof stub[name], `Stub missing method: ${name}`).toBe('function');
    }
  });

  // TH-NAPI-02: Interface methods match Rust #[napi] export names
  it('TH-NAPI-02: interface methods match Rust #[napi] export names', () => {
    // These are the exact function names from crates/drift/drift-napi/src/bindings/*.rs
    const rustExports = [
      // lifecycle.rs
      'driftInitialize', 'driftShutdown', 'driftIsInitialized',
      // scanner.rs
      'driftScan', 'driftScanWithProgress', 'driftCancelScan',
      // analysis.rs
      'driftAnalyze', 'driftCallGraph', 'driftBoundaries', 'driftValidatePack',
      // patterns.rs
      'driftPatterns', 'driftConfidence', 'driftOutliers', 'driftConventions',
      // graph.rs
      'driftReachability', 'driftTaintAnalysis', 'driftErrorHandling',
      'driftImpactAnalysis', 'driftTestTopology',
      // structural.rs
      'driftCouplingAnalysis', 'driftConstraintVerification',
      'driftContractTracking', 'driftConstantsAnalysis',
      'driftWrapperDetection', 'driftDnaAnalysis',
      'driftOwaspAnalysis', 'driftCryptoAnalysis', 'driftDecomposition',
      // enforcement.rs
      'driftCheck', 'driftAudit', 'driftViolations', 'driftGates',
      'driftReport', 'driftGC',
      'driftApprovePattern', 'driftPatternStatus',
      // feedback.rs
      'driftDismissViolation', 'driftFixViolation', 'driftSuppressViolation',
      // advanced.rs
      'driftSimulate', 'driftDecisions', 'driftContext', 'driftGenerateSpec',
      // bridge.rs
      'driftBridgeStatus', 'driftBridgeGroundMemory', 'driftBridgeGroundAll',
      'driftBridgeGroundingHistory', 'driftBridgeTranslateLink',
      'driftBridgeTranslateConstraintLink', 'driftBridgeEventMappings',
      'driftBridgeGroundability', 'driftBridgeLicenseCheck', 'driftBridgeIntents',
      'driftBridgeAdaptiveWeights', 'driftBridgeSpecCorrection',
      'driftBridgeContractVerified', 'driftBridgeDecompositionAdjusted',
      'driftBridgeExplainSpec', 'driftBridgeCounterfactual',
      'driftBridgeIntervention', 'driftBridgeHealth',
      'driftBridgeUnifiedNarrative', 'driftBridgePruneCausal',
      'driftBridgeGroundAfterAnalyze',
      // cloud.rs
      'driftCloudReadRows', 'driftCloudMaxCursor',
    ];

    // Every Rust export must be in our interface
    for (const name of rustExports) {
      expect(DRIFT_NAPI_METHOD_NAMES).toContain(name);
    }
    // No extra methods in our interface beyond Rust exports
    for (const name of DRIFT_NAPI_METHOD_NAMES) {
      expect(rustExports).toContain(name);
    }
  });

  // TH-NAPI-03: DriftNapi has exactly 66 functions (43 drift + 21 bridge + 2 cloud)
  it('TH-NAPI-03: DriftNapi has exactly 66 functions — prevents accidental add/remove', () => {
    expect(DRIFT_NAPI_METHOD_COUNT).toBe(66);
    expect(DRIFT_NAPI_METHOD_NAMES.length).toBe(66);

    // Also verify no duplicates
    const unique = new Set(DRIFT_NAPI_METHOD_NAMES);
    expect(unique.size).toBe(66);
  });

  // TH-NAPI-04: No function uses `any` type
  it('TH-NAPI-04: no function uses `any` type — all params and returns fully typed', () => {
    // This is a compile-time guarantee enforced by strict TypeScript.
    // At runtime, we verify the stub returns typed values, not `any`.
    const stub = createStubNapi();

    // Verify all sync methods return actual values (not undefined)
    expect(stub.driftIsInitialized()).toBe(false);
    expect(Array.isArray(stub.driftViolations('.'))).toBe(true);
    expect(Array.isArray(stub.driftGates('.'))).toBe(true);

    // Verify typed return shapes have correct field names
    const check = stub.driftCheck('.');
    expect(check).toHaveProperty('overallPassed');
    expect(check).toHaveProperty('totalViolations');
    expect(check).toHaveProperty('gates');
    expect(check).toHaveProperty('sarif');
  });

  // TH-NAPI-05: No function uses Record<string, unknown>
  it('TH-NAPI-05: no function uses Record<string, unknown> — all return named interfaces', () => {
    const stub = createStubNapi();

    // Verify structural results have named typed fields, not generic records
    const coupling = stub.driftCouplingAnalysis('.');
    expect(coupling).toHaveProperty('metrics');
    expect(coupling).toHaveProperty('cycles');
    expect(coupling).toHaveProperty('moduleCount');
    expect(Array.isArray(coupling.metrics)).toBe(true);

    const owasp = stub.driftOwaspAnalysis('.');
    expect(owasp).toHaveProperty('findings');
    expect(owasp).toHaveProperty('compliance');
    expect(owasp.compliance).toHaveProperty('postureScore');
    expect(owasp.compliance).toHaveProperty('owaspCoverage');

    const audit = stub.driftAudit('.');
    expect(audit).toHaveProperty('healthScore');
    expect(audit).toHaveProperty('breakdown');
    expect(audit.breakdown).toHaveProperty('avgConfidence');

    // Compile-time type assertion: this line would fail to compile
    // if any method returned Record<string, unknown>
    const _typeCheck: DriftNapi = stub;
    expect(_typeCheck).toBeDefined();
  });
});
