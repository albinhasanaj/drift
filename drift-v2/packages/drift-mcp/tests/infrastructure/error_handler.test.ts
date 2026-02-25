/**
 * Error Handler Tests — TH-ERR-01 through TH-ERR-07
 */

import { describe, it, expect } from 'vitest';
import { ErrorHandler } from '../../src/infrastructure/error_handler.js';

describe('Error Handler', () => {
  // TH-ERR-01: [SCAN_ERROR] → "Run drift setup first"
  it('TH-ERR-01: [SCAN_ERROR] → recovery hint "Run drift setup first"', () => {
    const err = new Error('[SCAN_ERROR] Failed to scan project');
    const structured = ErrorHandler.toStructuredError(err);
    expect(structured.code).toBe('SCAN_ERROR');
    expect(structured.recoveryHints).toContain('Run drift setup first');
    expect(structured.retryable).toBe(false);
  });

  // TH-ERR-02: [DB_BUSY] → retryable: true, retryAfterMs: 1000
  it('TH-ERR-02: [DB_BUSY] → retryable: true, retryAfterMs: 1000', () => {
    const err = new Error('[DB_BUSY] Database is locked');
    const structured = ErrorHandler.toStructuredError(err);
    expect(structured.code).toBe('DB_BUSY');
    expect(structured.retryable).toBe(true);
    expect(structured.retryAfterMs).toBe(1000);
  });

  // TH-ERR-03: [UNSUPPORTED_LANGUAGE] → empty alternativeTools
  it('TH-ERR-03: [UNSUPPORTED_LANGUAGE] → empty alternativeTools', () => {
    const err = new Error('[UNSUPPORTED_LANGUAGE] Language not supported');
    const structured = ErrorHandler.toStructuredError(err);
    expect(structured.code).toBe('UNSUPPORTED_LANGUAGE');
    expect(structured.alternativeTools).toEqual([]);
    expect(structured.retryable).toBe(false);
  });

  // TH-ERR-04: [CANCELLED] → retryable: true
  it('TH-ERR-04: [CANCELLED] → retryable: true', () => {
    const err = new Error('[CANCELLED] Operation was cancelled');
    const structured = ErrorHandler.toStructuredError(err);
    expect(structured.code).toBe('CANCELLED');
    expect(structured.retryable).toBe(true);
  });

  // TH-ERR-05: unknown error → generic with retryable: false
  it('TH-ERR-05: unknown error → generic with retryable: false', () => {
    const err = new Error('Something unexpected happened');
    const structured = ErrorHandler.toStructuredError(err);
    expect(structured.code).toBe('UNKNOWN');
    expect(structured.retryable).toBe(false);
    expect(structured.message).toBe('Something unexpected happened');
  });

  // TH-ERR-06: non-Error thrown (string/number/null) — wrapped, not rethrown
  it('TH-ERR-06: non-Error thrown — wrapped, not rethrown', () => {
    // String
    const strErr = ErrorHandler.toStructuredError('string error');
    expect(strErr.code).toBe('UNKNOWN');
    expect(strErr.message).toBe('string error');

    // Number
    const numErr = ErrorHandler.toStructuredError(42);
    expect(numErr.code).toBe('UNKNOWN');
    expect(numErr.message).toBe('42');

    // Null
    const nullErr = ErrorHandler.toStructuredError(null);
    expect(nullErr.code).toBe('UNKNOWN');
    expect(nullErr.message).toBe('null error');

    // Undefined
    const undefErr = ErrorHandler.toStructuredError(undefined);
    expect(undefErr.code).toBe('UNKNOWN');
    expect(undefErr.message).toBe('undefined error');
  });

  // TH-ERR-07: stack trace preserved
  it('TH-ERR-07: stack trace preserved for Error instances', () => {
    const err = new Error('[SCAN_ERROR] test');
    const structured = ErrorHandler.toStructuredError(err);
    expect(structured.stack).toBeDefined();
    expect(structured.stack).toContain('Error');

    // Non-Error has no stack
    const strErr = ErrorHandler.toStructuredError('no stack');
    expect(strErr.stack).toBeUndefined();
  });

  // Test wrap() helper
  it('wrap() catches errors and returns structured error', async () => {
    const result = await ErrorHandler.wrap(async () => {
      throw new Error('[DB_BUSY] locked');
    });
    expect(result).toHaveProperty('code', 'DB_BUSY');
    expect(result).toHaveProperty('retryable', true);
  });

  it('wrap() returns normal result on success', async () => {
    const result = await ErrorHandler.wrap(async () => ({ ok: true }));
    expect(result).toEqual({ ok: true });
  });
});
