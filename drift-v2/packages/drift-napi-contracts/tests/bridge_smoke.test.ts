/**
 * Bridge Smoke Tests — BT-NAPI-01 through BT-NAPI-15
 *
 * BT-NAPI-01..10: Bridge NAPI binding smoke tests (via stub)
 * BT-NAPI-11..13: Contract alignment tests
 * BT-NAPI-14..15: Bridge validation tests
 */

import { describe, it, expect } from 'vitest';
import { createStubNapi } from '../src/stub.js';
import { DRIFT_NAPI_METHOD_COUNT, DRIFT_NAPI_METHOD_NAMES } from '../src/interface.js';
import {
  validateBridgeGroundParams,
  validateBridgeCounterfactualParams,
} from '../src/validation.js';
import type {
  BridgeStatusResult,
  BridgeHealthResult,
  BridgeEventMappingsResult,
  BridgeIntentsResult,
  BridgeLicenseResult,
  BridgeGroundabilityResult,
  BridgeEntityLink,
  BridgeGroundingResult,
  BridgeGroundingSnapshot,
  BridgeGroundingHistoryResult,
  BridgeCounterfactualResult,
  BridgeInterventionResult,
  BridgeUnifiedNarrativeResult,
  BridgePruneCausalResult,
  BridgeAdaptiveWeightsResult,
  BridgeSpecCorrectionResult,
  BridgeContractVerifiedResult,
  BridgeDecompositionAdjustedResult,
  BridgeExplainSpecResult,
} from '../src/types/bridge.js';

describe('Bridge NAPI Binding Smoke Tests', () => {
  const stub = createStubNapi();

  // BT-NAPI-01: driftBridgeStatus() returns BridgeStatusResult shape
  it('BT-NAPI-01: driftBridgeStatus() returns BridgeStatusResult shape', () => {
    const result: BridgeStatusResult = stub.driftBridgeStatus();
    expect(result).toHaveProperty('available');
    expect(result).toHaveProperty('license_tier');
    expect(result).toHaveProperty('grounding_enabled');
    expect(result).toHaveProperty('version');
    expect(typeof result.available).toBe('boolean');
    expect(typeof result.license_tier).toBe('string');
    expect(typeof result.grounding_enabled).toBe('boolean');
    expect(typeof result.version).toBe('string');
    // Stub returns available: false (no native binary)
    expect(result.available).toBe(false);
  });

  // BT-NAPI-02: driftBridgeStatus() before init returns stub data (bridge not initialized)
  it('BT-NAPI-02: driftBridgeStatus() stub signals bridge not initialized', () => {
    const result = stub.driftBridgeStatus();
    // Stub always returns available: false — matching "bridge not initialized" behavior
    expect(result.available).toBe(false);
    expect(result.grounding_enabled).toBe(false);
  });

  // BT-NAPI-03: driftBridgeHealth() returns health result with checks array
  it('BT-NAPI-03: driftBridgeHealth() returns BridgeHealthResult with checks and degradation', () => {
    const result: BridgeHealthResult = stub.driftBridgeHealth();
    expect(result).toHaveProperty('status');
    expect(result).toHaveProperty('ready');
    expect(result).toHaveProperty('subsystem_checks');
    expect(result).toHaveProperty('degradation_reasons');
    expect(typeof result.status).toBe('string');
    expect(typeof result.ready).toBe('boolean');
    expect(Array.isArray(result.subsystem_checks)).toBe(true);
    expect(Array.isArray(result.degradation_reasons)).toBe(true);
    // Stub indicates unavailable
    expect(result.status).toBe('unavailable');
    expect(result.ready).toBe(false);
  });

  // BT-NAPI-04: driftBridgeEventMappings() returns event mappings result
  it('BT-NAPI-04: driftBridgeEventMappings() returns BridgeEventMappingsResult shape', () => {
    const result: BridgeEventMappingsResult = stub.driftBridgeEventMappings();
    expect(result).toHaveProperty('mappings');
    expect(result).toHaveProperty('count');
    expect(Array.isArray(result.mappings)).toBe(true);
    expect(typeof result.count).toBe('number');
    // Stub returns empty (real implementation returns 21)
    expect(result.count).toBe(0);
    expect(result.mappings.length).toBe(result.count);
  });

  // BT-NAPI-05: driftBridgeIntents() returns intents result
  it('BT-NAPI-05: driftBridgeIntents() returns BridgeIntentsResult shape', () => {
    const result: BridgeIntentsResult = stub.driftBridgeIntents();
    expect(result).toHaveProperty('intents');
    expect(result).toHaveProperty('count');
    expect(Array.isArray(result.intents)).toBe(true);
    expect(typeof result.count).toBe('number');
    // Stub returns empty (real implementation returns 20)
    expect(result.count).toBe(0);
  });

  // BT-NAPI-06: driftBridgeLicenseCheck returns BridgeLicenseResult shape
  it('BT-NAPI-06: driftBridgeLicenseCheck() returns BridgeLicenseResult shape', () => {
    const result: BridgeLicenseResult = stub.driftBridgeLicenseCheck('grounding_basic');
    expect(result).toHaveProperty('feature');
    expect(result).toHaveProperty('tier');
    expect(result).toHaveProperty('allowed');
    expect(typeof result.feature).toBe('string');
    expect(typeof result.tier).toBe('string');
    expect(typeof result.allowed).toBe('boolean');
    expect(result.feature).toBe('grounding_basic');
  });

  // BT-NAPI-07: driftBridgeLicenseCheck passes through feature name
  it('BT-NAPI-07: driftBridgeLicenseCheck() passes through feature name correctly', () => {
    const result = stub.driftBridgeLicenseCheck('counterfactual');
    expect(result.feature).toBe('counterfactual');
    expect(result.tier).toBe('Community');
    // Stub returns allowed: false for all features
    expect(result.allowed).toBe(false);
  });

  // BT-NAPI-08: driftBridgeGroundability returns result with memory type
  it('BT-NAPI-08: driftBridgeGroundability() returns GroundabilityResult shape', () => {
    const result: BridgeGroundabilityResult = stub.driftBridgeGroundability('PatternRationale');
    expect(result).toHaveProperty('memory_type');
    expect(result).toHaveProperty('groundability');
    expect(typeof result.memory_type).toBe('string');
    expect(typeof result.groundability).toBe('string');
    expect(result.memory_type).toBe('PatternRationale');
  });

  // BT-NAPI-09: driftBridgeGroundability passes through memory type for non-groundable
  it('BT-NAPI-09: driftBridgeGroundability() passes through memory type', () => {
    const result = stub.driftBridgeGroundability('Feedback');
    expect(result.memory_type).toBe('Feedback');
    expect(typeof result.groundability).toBe('string');
  });

  // BT-NAPI-10: driftBridgeTranslateLink returns EntityLink shape
  it('BT-NAPI-10: driftBridgeTranslateLink() returns BridgeEntityLink shape', () => {
    const result: BridgeEntityLink = stub.driftBridgeTranslateLink('pat-001', 'SingletonPattern', 0.8);
    expect(result).toHaveProperty('entity_type');
    expect(result).toHaveProperty('entity_id');
    expect(result).toHaveProperty('entity_name');
    expect(result).toHaveProperty('confidence');
    expect(result).toHaveProperty('link_type');
    expect(typeof result.entity_type).toBe('string');
    expect(result.entity_id).toBe('pat-001');
    expect(result.entity_name).toBe('SingletonPattern');
    expect(result.confidence).toBe(0.8);
  });
});

describe('Bridge Smoke — Return Shape Completeness', () => {
  const stub = createStubNapi();

  it('driftBridgeGroundMemory() returns BridgeGroundingResult shape', () => {
    const result: BridgeGroundingResult = stub.driftBridgeGroundMemory('mem-1', 'Core');
    expect(result).toHaveProperty('memory_id');
    expect(result).toHaveProperty('grounding_score');
    expect(result).toHaveProperty('classification');
    expect(result).toHaveProperty('evidence');
    expect(result.memory_id).toBe('mem-1');
    expect(typeof result.grounding_score).toBe('number');
    expect(Array.isArray(result.evidence)).toBe(true);
  });

  it('driftBridgeGroundAll() returns BridgeGroundingSnapshot shape', () => {
    const result: BridgeGroundingSnapshot = stub.driftBridgeGroundAll();
    expect(result).toHaveProperty('total_checked');
    expect(result).toHaveProperty('validated');
    expect(result).toHaveProperty('partial');
    expect(result).toHaveProperty('weak');
    expect(result).toHaveProperty('invalidated');
    expect(result).toHaveProperty('avg_grounding_score');
    expect(result).toHaveProperty('duration_ms');
    expect(result).toHaveProperty('error_count');
    expect(typeof result.total_checked).toBe('number');
  });

  it('driftBridgeGroundingHistory() returns history shape', () => {
    const result: BridgeGroundingHistoryResult = stub.driftBridgeGroundingHistory('mem-1');
    expect(result.memory_id).toBe('mem-1');
    expect(Array.isArray(result.history)).toBe(true);
  });

  it('driftBridgeTranslateConstraintLink() returns EntityLink shape', () => {
    const result: BridgeEntityLink = stub.driftBridgeTranslateConstraintLink('cst-1', 'MaxRetries');
    expect(result.entity_type).toBe('constraint');
    expect(result.entity_id).toBe('cst-1');
    expect(result.link_type).toBe('ConstraintLink');
  });

  it('driftBridgeCounterfactual() returns counterfactual shape', () => {
    const result: BridgeCounterfactualResult = stub.driftBridgeCounterfactual('mem-1');
    expect(result).toHaveProperty('affected_count');
    expect(result).toHaveProperty('affected_ids');
    expect(result).toHaveProperty('max_depth');
    expect(result).toHaveProperty('summary');
    expect(Array.isArray(result.affected_ids)).toBe(true);
  });

  it('driftBridgeIntervention() returns intervention shape', () => {
    const result: BridgeInterventionResult = stub.driftBridgeIntervention('mem-1');
    expect(result).toHaveProperty('impacted_count');
    expect(result).toHaveProperty('impacted_ids');
    expect(Array.isArray(result.impacted_ids)).toBe(true);
  });

  it('driftBridgeUnifiedNarrative() returns narrative shape', () => {
    const result: BridgeUnifiedNarrativeResult = stub.driftBridgeUnifiedNarrative('mem-1');
    expect(result.memory_id).toBe('mem-1');
    expect(Array.isArray(result.sections)).toBe(true);
    expect(Array.isArray(result.upstream)).toBe(true);
    expect(Array.isArray(result.downstream)).toBe(true);
    expect(typeof result.markdown).toBe('string');
  });

  it('driftBridgePruneCausal() returns prune shape', () => {
    const result: BridgePruneCausalResult = stub.driftBridgePruneCausal(0.5);
    expect(result).toHaveProperty('edges_removed');
    expect(result).toHaveProperty('threshold');
    expect(result.threshold).toBe(0.5);
  });

  it('driftBridgeAdaptiveWeights() returns weights shape', () => {
    const result: BridgeAdaptiveWeightsResult = stub.driftBridgeAdaptiveWeights('{}');
    expect(result).toHaveProperty('weights');
    expect(result).toHaveProperty('failure_distribution');
    expect(result).toHaveProperty('sample_size');
    expect(result).toHaveProperty('last_updated');
    expect(typeof result.sample_size).toBe('number');
  });

  it('driftBridgeSpecCorrection() returns correction shape', () => {
    const result: BridgeSpecCorrectionResult = stub.driftBridgeSpecCorrection('{}');
    expect(result).toHaveProperty('memory_id');
    expect(result).toHaveProperty('status');
  });

  it('driftBridgeContractVerified() returns verified shape', () => {
    const result: BridgeContractVerifiedResult = stub.driftBridgeContractVerified('mod-1', true, 'api');
    expect(result).toHaveProperty('memory_id');
    expect(result).toHaveProperty('passed');
    expect(result.passed).toBe(true);
  });

  it('driftBridgeDecompositionAdjusted() returns adjusted shape', () => {
    const result: BridgeDecompositionAdjustedResult = stub.driftBridgeDecompositionAdjusted('mod-1', 'split', 'abc');
    expect(result).toHaveProperty('memory_id');
    expect(result).toHaveProperty('adjustment_type');
    expect(result.adjustment_type).toBe('split');
  });

  it('driftBridgeExplainSpec() returns explain shape', () => {
    const result: BridgeExplainSpecResult = stub.driftBridgeExplainSpec('mem-1');
    expect(result.memory_id).toBe('mem-1');
    expect(typeof result.explanation).toBe('string');
  });
});

describe('Bridge Contract Alignment Tests', () => {
  // BT-NAPI-11: DriftNapi interface has exactly 66 methods
  it('BT-NAPI-11: DriftNapi has exactly 66 methods — 43 drift + 21 bridge + 2 cloud', () => {
    expect(DRIFT_NAPI_METHOD_COUNT).toBe(66);
    expect(DRIFT_NAPI_METHOD_NAMES.length).toBe(66);
    const unique = new Set(DRIFT_NAPI_METHOD_NAMES);
    expect(unique.size).toBe(66);
  });

  // BT-NAPI-12: Every bridge method has a corresponding stub entry
  it('BT-NAPI-12: every bridge method has a corresponding stub entry', () => {
    const stub = createStubNapi();
    const bridgeMethods = DRIFT_NAPI_METHOD_NAMES.filter((n) => n.startsWith('driftBridge'));
    expect(bridgeMethods.length).toBe(21);
    for (const name of bridgeMethods) {
      expect(typeof stub[name], `Stub missing bridge method: ${name}`).toBe('function');
    }
  });

  // BT-NAPI-13: Every bridge stub returns value matching declared return type (not {})
  it('BT-NAPI-13: every bridge stub returns non-empty typed value', () => {
    const stub = createStubNapi();

    // Status
    const status = stub.driftBridgeStatus();
    expect(Object.keys(status).length).toBeGreaterThan(0);
    expect(status).toHaveProperty('available');

    // Health
    const health = stub.driftBridgeHealth();
    expect(Object.keys(health).length).toBeGreaterThan(0);
    expect(health).toHaveProperty('status');
    expect(health).toHaveProperty('subsystem_checks');

    // Grounding
    const ground = stub.driftBridgeGroundMemory('id', 'Core');
    expect(Object.keys(ground).length).toBeGreaterThan(0);
    expect(ground).toHaveProperty('grounding_score');

    // Snapshot
    const snapshot = stub.driftBridgeGroundAll();
    expect(Object.keys(snapshot).length).toBeGreaterThan(0);
    expect(snapshot).toHaveProperty('total_checked');

    // Counterfactual
    const cf = stub.driftBridgeCounterfactual('id');
    expect(Object.keys(cf).length).toBeGreaterThan(0);
    expect(cf).toHaveProperty('affected_count');

    // Link
    const link = stub.driftBridgeTranslateLink('id', 'name', 0.5);
    expect(Object.keys(link).length).toBeGreaterThan(0);
    expect(link).toHaveProperty('entity_type');
  });
});

describe('Bridge Validation Tests', () => {
  // BT-NAPI-14: validateBridgeGroundParams fails for empty memoryId
  it('BT-NAPI-14: validateBridgeGroundParams({ memoryId: "" }) fails — empty ID', () => {
    const result = validateBridgeGroundParams({ memoryId: '', memoryType: 'Core' });
    expect(result.valid).toBe(false);
    expect(result.field).toBe('memoryId');

    // Also test missing memoryId
    const result2 = validateBridgeGroundParams({ memoryType: 'Core' });
    expect(result2.valid).toBe(false);
    expect(result2.field).toBe('memoryId');

    // Test missing memoryType
    const result3 = validateBridgeGroundParams({ memoryId: 'abc-123' });
    expect(result3.valid).toBe(false);
    expect(result3.field).toBe('memoryType');

    // Test invalid memoryType
    const result4 = validateBridgeGroundParams({ memoryId: 'abc-123', memoryType: 'InvalidType' });
    expect(result4.valid).toBe(false);
    expect(result4.field).toBe('memoryType');
  });

  // BT-NAPI-15: validateBridgeGroundParams passes for valid input
  it('BT-NAPI-15: validateBridgeGroundParams({ memoryId: "abc-123", memoryType: "PatternRationale" }) passes', () => {
    const result = validateBridgeGroundParams({
      memoryId: 'abc-123',
      memoryType: 'PatternRationale',
    });
    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
    expect(result.field).toBeUndefined();

    // Also verify all valid memory types pass
    const validTypes = [
      'PatternRationale', 'ConstraintOverride', 'DecisionContext', 'CodeSmell',
      'Core', 'Tribal', 'Semantic', 'Insight', 'Feedback', 'Episodic',
      'Preference', 'Skill',
    ];
    for (const memoryType of validTypes) {
      const r = validateBridgeGroundParams({ memoryId: 'test-id', memoryType });
      expect(r.valid, `Expected valid for memoryType=${memoryType}`).toBe(true);
    }
  });

  it('validateBridgeCounterfactualParams validates memoryId', () => {
    // Missing
    expect(validateBridgeCounterfactualParams({}).valid).toBe(false);
    // Empty
    expect(validateBridgeCounterfactualParams({ memoryId: '' }).valid).toBe(false);
    // Valid
    expect(validateBridgeCounterfactualParams({ memoryId: 'mem-123' }).valid).toBe(true);
  });
});
