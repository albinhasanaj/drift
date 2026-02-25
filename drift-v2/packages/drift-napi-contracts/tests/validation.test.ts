/**
 * Validation Tests — TH-NAPI-18 through TH-NAPI-25
 * Verifies runtime parameter validators catch bad input before NAPI calls.
 */

import { describe, it, expect } from 'vitest';
import {
  validateScanParams,
  validateContextParams,
  validateSimulateParams,
} from '../src/validation.js';

describe('Validation — Reject Bad Input', () => {
  // TH-NAPI-18: validateScanParams({}) passes (all optional)
  it('TH-NAPI-18: validateScanParams({}) passes (all optional)', () => {
    const result = validateScanParams({});
    expect(result.valid).toBe(true);
  });

  // TH-NAPI-19: validateScanParams({ root: '' }) fails — empty path
  it("TH-NAPI-19: validateScanParams({ root: '' }) fails — empty path", () => {
    const result = validateScanParams({ root: '' });
    expect(result.valid).toBe(false);
    expect(result.field).toBe('root');
    expect(result.error).toContain('empty');
  });

  // TH-NAPI-20: validateContextParams({ intent: 'fix_bug' }) passes
  it("TH-NAPI-20: validateContextParams({ intent: 'fix_bug' }) passes", () => {
    const result = validateContextParams({ intent: 'fix_bug' });
    expect(result.valid).toBe(true);
  });

  // TH-NAPI-21: validateContextParams({}) fails — missing required intent
  it('TH-NAPI-21: validateContextParams({}) fails — missing required intent', () => {
    const result = validateContextParams({});
    expect(result.valid).toBe(false);
    expect(result.field).toBe('intent');
    expect(result.error).toContain('required');
  });

  // TH-NAPI-22: validateContextParams({ intent: 'x', depth: 'invalid' }) fails — enum mismatch
  it("TH-NAPI-22: validateContextParams({ intent: 'fix_bug', depth: 'invalid' }) fails — enum mismatch", () => {
    const result = validateContextParams({ intent: 'fix_bug', depth: 'invalid' });
    expect(result.valid).toBe(false);
    expect(result.field).toBe('depth');
    expect(result.error).toContain('must be one of');
  });

  // TH-NAPI-23: validateSimulateParams({ category: 'refactor', description: 'x' }) passes
  it("TH-NAPI-23: validateSimulateParams({ category: 'refactor', description: 'x' }) passes", () => {
    const result = validateSimulateParams({
      category: 'refactor',
      description: 'Refactor the auth module',
    });
    expect(result.valid).toBe(true);
  });

  // TH-NAPI-24: validateSimulateParams({ category: '', description: '' }) fails — empty required
  it("TH-NAPI-24: validateSimulateParams({ category: '', description: '' }) fails — empty required", () => {
    const result = validateSimulateParams({ category: '', description: '' });
    expect(result.valid).toBe(false);
    expect(result.field).toBe('category');
    expect(result.error).toContain('non-empty');
  });

  // TH-NAPI-25: SQL injection string in intent — validator passes (valid string), Rust handles safely
  it('TH-NAPI-25: SQL injection string in intent — validator passes for valid intent values', () => {
    // SQL injection in a field that has enum validation should fail (not a valid intent)
    const sqlInjection = "'; DROP TABLE patterns; --";
    const result = validateContextParams({ intent: sqlInjection });
    expect(result.valid).toBe(false);
    expect(result.field).toBe('intent');

    // But if SQL injection appears in a non-enum string field like description,
    // the validator passes — Rust handles SQL safely via parameterized queries
    const simResult = validateSimulateParams({
      category: 'refactor',
      description: "'; DROP TABLE patterns; --",
    });
    expect(simResult.valid).toBe(true);
  });
});
