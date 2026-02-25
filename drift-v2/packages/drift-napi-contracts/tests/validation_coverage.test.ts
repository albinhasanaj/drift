/**
 * Additional validation coverage tests — exercises all validator branches.
 */

import { describe, it, expect } from 'vitest';
import {
  validateScanParams,
  validateContextParams,
  validateSimulateParams,
  validateReachabilityParams,
  validateRootParam,
  validateFeedbackParams,
} from '../src/validation.js';

describe('Validation — Full Branch Coverage', () => {
  // Scan params — additional branches
  it('validateScanParams with valid root passes', () => {
    expect(validateScanParams({ root: '/src' }).valid).toBe(true);
  });

  it('validateScanParams with non-string root fails', () => {
    const r = validateScanParams({ root: 123 as unknown as string });
    expect(r.valid).toBe(false);
    expect(r.field).toBe('root');
  });

  it('validateScanParams with valid options passes', () => {
    const r = validateScanParams({
      root: '/src',
      options: { forceFull: true, maxFileSize: 1024, extraIgnore: ['*.log'], followSymlinks: false },
    });
    expect(r.valid).toBe(true);
  });

  it('validateScanParams with non-object options fails', () => {
    const r = validateScanParams({ options: 'bad' as unknown as { forceFull?: boolean } });
    expect(r.valid).toBe(false);
    expect(r.field).toBe('options');
  });

  it('validateScanParams with negative maxFileSize fails', () => {
    const r = validateScanParams({ options: { maxFileSize: -1 } });
    expect(r.valid).toBe(false);
    expect(r.field).toBe('options.maxFileSize');
  });

  it('validateScanParams with non-number maxFileSize fails', () => {
    const r = validateScanParams({ options: { maxFileSize: 'big' as unknown as number } });
    expect(r.valid).toBe(false);
    expect(r.field).toBe('options.maxFileSize');
  });

  it('validateScanParams with null root passes (optional)', () => {
    expect(validateScanParams({ root: undefined }).valid).toBe(true);
  });

  // Context params — additional branches
  it('validateContextParams with all valid intents pass', () => {
    for (const intent of ['fix_bug', 'add_feature', 'understand_code', 'understand', 'security_audit', 'generate_spec']) {
      expect(validateContextParams({ intent }).valid).toBe(true);
    }
  });

  it('validateContextParams with valid depths pass', () => {
    for (const depth of ['overview', 'standard', 'deep']) {
      expect(validateContextParams({ intent: 'fix_bug', depth }).valid).toBe(true);
    }
  });

  it('validateContextParams with null intent fails', () => {
    const r = validateContextParams({ intent: null as unknown as string });
    expect(r.valid).toBe(false);
    expect(r.field).toBe('intent');
  });

  it('validateContextParams with empty intent fails', () => {
    const r = validateContextParams({ intent: '' });
    expect(r.valid).toBe(false);
    expect(r.field).toBe('intent');
  });

  it('validateContextParams with invalid intent fails', () => {
    const r = validateContextParams({ intent: 'invalid_intent' });
    expect(r.valid).toBe(false);
    expect(r.field).toBe('intent');
    expect(r.error).toContain('must be one of');
  });

  // Simulate params — additional branches
  it('validateSimulateParams with all valid categories pass', () => {
    const categories = [
      'add_feature', 'fix_bug', 'refactor', 'migrate_framework', 'add_test',
      'security_fix', 'performance_optimization', 'dependency_update',
      'api_change', 'database_migration', 'config_change', 'documentation', 'infrastructure',
    ];
    for (const category of categories) {
      expect(validateSimulateParams({ category, description: 'test' }).valid).toBe(true);
    }
  });

  it('validateSimulateParams with null category fails', () => {
    const r = validateSimulateParams({ category: null as unknown as string, description: 'x' });
    expect(r.valid).toBe(false);
    expect(r.field).toBe('category');
  });

  it('validateSimulateParams with invalid category fails', () => {
    const r = validateSimulateParams({ category: 'invalid', description: 'x' });
    expect(r.valid).toBe(false);
    expect(r.field).toBe('category');
    expect(r.error).toContain('must be one of');
  });

  it('validateSimulateParams with null description fails', () => {
    const r = validateSimulateParams({ category: 'refactor', description: null as unknown as string });
    expect(r.valid).toBe(false);
    expect(r.field).toBe('description');
  });

  it('validateSimulateParams with empty description fails', () => {
    const r = validateSimulateParams({ category: 'refactor', description: '' });
    expect(r.valid).toBe(false);
    expect(r.field).toBe('description');
  });

  // Reachability params
  it('validateReachabilityParams with valid input passes', () => {
    expect(validateReachabilityParams({ functionKey: 'myFunc', direction: 'forward' }).valid).toBe(true);
    expect(validateReachabilityParams({ functionKey: 'myFunc', direction: 'backward' }).valid).toBe(true);
  });

  it('validateReachabilityParams with missing functionKey fails', () => {
    const r = validateReachabilityParams({ direction: 'forward' });
    expect(r.valid).toBe(false);
    expect(r.field).toBe('functionKey');
  });

  it('validateReachabilityParams with empty functionKey fails', () => {
    const r = validateReachabilityParams({ functionKey: '', direction: 'forward' });
    expect(r.valid).toBe(false);
    expect(r.field).toBe('functionKey');
  });

  it('validateReachabilityParams with missing direction fails', () => {
    const r = validateReachabilityParams({ functionKey: 'fn' });
    expect(r.valid).toBe(false);
    expect(r.field).toBe('direction');
  });

  it('validateReachabilityParams with invalid direction fails', () => {
    const r = validateReachabilityParams({ functionKey: 'fn', direction: 'sideways' });
    expect(r.valid).toBe(false);
    expect(r.field).toBe('direction');
  });

  // Root param
  it('validateRootParam with valid root passes', () => {
    expect(validateRootParam({ root: '/src' }).valid).toBe(true);
  });

  it('validateRootParam with missing root fails', () => {
    const r = validateRootParam({});
    expect(r.valid).toBe(false);
    expect(r.field).toBe('root');
  });

  it('validateRootParam with empty root fails', () => {
    const r = validateRootParam({ root: '' });
    expect(r.valid).toBe(false);
    expect(r.field).toBe('root');
  });

  // Feedback params
  it('validateFeedbackParams with valid input passes', () => {
    expect(validateFeedbackParams({ violationId: 'v-123' }).valid).toBe(true);
  });

  it('validateFeedbackParams with missing violationId fails', () => {
    const r = validateFeedbackParams({});
    expect(r.valid).toBe(false);
    expect(r.field).toBe('violationId');
  });

  it('validateFeedbackParams with empty violationId fails', () => {
    const r = validateFeedbackParams({ violationId: '' });
    expect(r.valid).toBe(false);
    expect(r.field).toBe('violationId');
  });

  it('validateFeedbackParams with null violationId fails', () => {
    const r = validateFeedbackParams({ violationId: null as unknown as string });
    expect(r.valid).toBe(false);
    expect(r.field).toBe('violationId');
  });
});
