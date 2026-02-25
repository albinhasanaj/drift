/**
 * Infrastructure wiring tests — verifies that cache, rate limiter, error handler,
 * and response builder are actually used by tool handlers when InfrastructureLayer
 * is provided.
 *
 * PH-INFRA-WIRE-01 through PH-INFRA-WIRE-08
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { setNapi, resetNapi, loadNapi } from '../../src/napi.js';
import { createStubNapi } from '@drift/napi-contracts';
import { InfrastructureLayer } from '../../src/infrastructure/index.js';
import { handleDriftTool, buildToolCatalog } from '../../src/tools/drift_tool.js';
import { ResponseCache } from '../../src/infrastructure/cache.js';

describe('Infrastructure Wiring', () => {
  let infra: InfrastructureLayer;
  let catalog: ReturnType<typeof buildToolCatalog>;

  beforeEach(() => {
    resetNapi();
    setNapi(createStubNapi());
    infra = new InfrastructureLayer({ projectRoot: '/test' });
    catalog = buildToolCatalog();
  });

  // PH-INFRA-WIRE-01: Cache hit on second call for read-only tool
  it('WIRE-01: second call to cacheable tool returns cached result', async () => {
    const params = { tool: 'drift_audit', params: { root: '.' } };

    // First call — cache miss, executes handler
    const result1 = await handleDriftTool(params, catalog, infra);
    expect(infra.cache.size).toBe(1);

    // Second call — cache hit, returns same object
    const result2 = await handleDriftTool(params, catalog, infra);
    expect(result2).toEqual(result1);
    // Still just 1 entry (not 2)
    expect(infra.cache.size).toBe(1);
  });

  // PH-INFRA-WIRE-02: Mutation tool invalidates cache
  it('WIRE-02: mutation tool clears entire cache', async () => {
    // Populate cache with a read
    await handleDriftTool({ tool: 'drift_audit', params: { root: '.' } }, catalog, infra);
    expect(infra.cache.size).toBe(1);

    // Run mutation tool (analyze)
    await handleDriftTool({ tool: 'drift_analyze', params: {} }, catalog, infra);

    // Cache should be cleared
    expect(infra.cache.size).toBe(0);
  });

  // PH-INFRA-WIRE-03: Different params produce different cache keys
  it('WIRE-03: different params produce different cache entries', async () => {
    await handleDriftTool({ tool: 'drift_owasp', params: { root: '/a' } }, catalog, infra);
    await handleDriftTool({ tool: 'drift_owasp', params: { root: '/b' } }, catalog, infra);
    expect(infra.cache.size).toBe(2);
  });

  // PH-INFRA-WIRE-04: Error handler wraps failures into structured errors
  it('WIRE-04: handler errors become structured errors with recovery hints', async () => {
    // Override stub to throw
    const napi = loadNapi();
    (napi as unknown as Record<string, unknown>).driftAudit = () => {
      throw new Error('[STORAGE_ERROR] Database corrupted');
    };

    const result = await handleDriftTool(
      { tool: 'drift_audit', params: { root: '.' } },
      catalog,
      infra,
    );

    expect(result).toBeDefined();
    const r = result as Record<string, unknown>;
    expect(r.code).toBe('STORAGE_ERROR');
    expect(Array.isArray(r.recoveryHints)).toBe(true);
    expect((r.recoveryHints as string[]).length).toBeGreaterThan(0);
  });

  // PH-INFRA-WIRE-05: Non-cacheable tools bypass cache
  it('WIRE-05: mutation tools do not cache results', async () => {
    await handleDriftTool({ tool: 'drift_dismiss', params: { violationId: 'v1', action: 'dismiss', reason: 'test' } }, catalog, infra);
    // dismiss is a mutation tool — should not be cached, and cache is cleared
    expect(infra.cache.size).toBe(0);
  });

  // PH-INFRA-WIRE-06: Response builder adds _summary and _tokenEstimate
  it('WIRE-06: response builder enriches results with metadata', async () => {
    const result = await handleDriftTool(
      { tool: 'drift_coupling', params: { root: '.' } },
      catalog,
      infra,
    );

    const r = result as Record<string, unknown>;
    expect(r._summary).toBe('drift_coupling result');
    expect(typeof r._tokenEstimate).toBe('number');
  });

  // PH-INFRA-WIRE-07: Cache key is project-isolated
  it('WIRE-07: cache keys include project root for isolation', () => {
    const key1 = ResponseCache.buildKey('/project-a', 'drift_status', {});
    const key2 = ResponseCache.buildKey('/project-b', 'drift_status', {});
    expect(key1).not.toBe(key2);
    expect(key1.startsWith('/project-a:')).toBe(true);
    expect(key2.startsWith('/project-b:')).toBe(true);
  });

  // PH-INFRA-WIRE-08: Without infra, tools still work (backward compatible)
  it('WIRE-08: tools work without infrastructure (no infra = no caching/rate limiting)', async () => {
    const result = await handleDriftTool(
      { tool: 'drift_audit', params: { root: '.' } },
      catalog,
      // no infra
    );
    expect(result).toBeDefined();
    // No _summary because no response builder
    expect((result as Record<string, unknown>)._summary).toBeUndefined();
  });
});
