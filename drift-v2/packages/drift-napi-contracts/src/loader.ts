/**
 * NAPI loader — singleton with lazy initialization, stub fallback, and test injection.
 *
 * loadNapi() attempts to require('drift-napi') and validates the loaded module
 * has all 40 expected function names. Falls back to createStubNapi() if native
 * binary is unavailable. Thread-safe via synchronous singleton pattern.
 */

import { createRequire } from 'node:module';
import type { DriftNapi } from './interface.js';
import { DRIFT_NAPI_METHOD_NAMES } from './interface.js';
import { createStubNapi } from './stub.js';

// ESM-compatible require for loading native .node addons
const esmRequire = createRequire(import.meta.url);

/** Error thrown when a loaded NAPI module is missing required functions. */
export class NapiLoadError extends Error {
  public readonly missingFunctions: string[];

  constructor(missingFunctions: string[]) {
    super(
      `NAPI module is missing ${missingFunctions.length} required function(s): ${missingFunctions.join(', ')}`,
    );
    this.name = 'NapiLoadError';
    this.missingFunctions = missingFunctions;
  }
}

/** The singleton instance. null = not yet initialized. */
let instance: DriftNapi | null = null;

/** Whether the current instance was set via setNapi() (test injection). */
let isTestOverride = false;

/** Whether the current instance is a stub (native binary unavailable). */
let usingStub = false;

/**
 * Load the NAPI bindings. Returns a singleton — subsequent calls return the same instance.
 *
 * Resolution order:
 * 1. If setNapi() was called, returns the test-injected instance
 * 2. Attempts require('drift-napi') — validates all 40 functions present
 * 3. Falls back to createStubNapi() if native binary unavailable
 *
 * Performance: <1ms after first call (singleton).
 */
export function loadNapi(): DriftNapi {
  if (instance !== null) {
    return instance;
  }

  try {
    // Attempt to load native binary via ESM-compatible require
    const native = esmRequire('drift-napi') as Record<string, unknown>;
    validateNapiModule(native);
    instance = native as unknown as DriftNapi;
    usingStub = false;
  } catch {
    // Native binary unavailable — fall back to stub
    console.warn(
      '[drift] ⚠ Native binary unavailable — using stub fallback. ' +
      'All analysis results will be empty. Run `napi build` or install platform-specific binary to enable real analysis.',
    );
    instance = createStubNapi();
    usingStub = true;
  }

  return instance;
}

/**
 * Override the singleton with a test-provided instance.
 * Validates the provided object has all 40 required functions.
 * Throws NapiLoadError if any functions are missing.
 */
export function setNapi(napi: DriftNapi): void {
  const missing = getMissingFunctions(napi as unknown as Record<string, unknown>);
  if (missing.length > 0) {
    throw new NapiLoadError(missing);
  }
  instance = napi;
  isTestOverride = true;
}

/**
 * Clear the singleton. Next loadNapi() call will re-initialize.
 * Primarily for test cleanup.
 */
export function resetNapi(): void {
  instance = null;
  isTestOverride = false;
  usingStub = false;
}

/**
 * Check if the current instance was injected via setNapi().
 */
export function isNapiOverridden(): boolean {
  return isTestOverride;
}

/**
 * Check if the current NAPI instance is a stub (native binary unavailable).
 * Returns false if loadNapi() has not been called yet.
 */
export function isNapiStub(): boolean {
  return usingStub;
}

/**
 * Validate that a loaded module has all required NAPI function names.
 * Throws NapiLoadError with the list of missing functions.
 */
function validateNapiModule(mod: Record<string, unknown>): void {
  const missing = getMissingFunctions(mod);
  if (missing.length > 0) {
    throw new NapiLoadError(missing);
  }
}

/**
 * Get the list of missing function names from a module.
 */
function getMissingFunctions(mod: Record<string, unknown>): string[] {
  const missing: string[] = [];
  for (const name of DRIFT_NAPI_METHOD_NAMES) {
    if (typeof mod[name] !== 'function') {
      missing.push(name);
    }
  }
  return missing;
}
