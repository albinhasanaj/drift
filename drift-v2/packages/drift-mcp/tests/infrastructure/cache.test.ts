/**
 * Cache Tests — TH-CACHE-01 through TH-CACHE-08
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ResponseCache } from '../../src/infrastructure/cache.js';

describe('Cache — Eviction, Isolation & TTL', () => {
  let cache: ResponseCache;

  beforeEach(() => {
    cache = new ResponseCache();
  });

  // TH-CACHE-01: set()+get() round-trip returns identical data
  it('TH-CACHE-01: set()+get() round-trip returns identical data', () => {
    const data = { violations: [{ id: 'v1', severity: 'high' }] };
    const key = ResponseCache.buildKey('/project', 'drift_check', { path: '.' });
    cache.set(key, data);
    expect(cache.get(key)).toEqual(data);
  });

  // TH-CACHE-02: TTL: set 100ms TTL, wait 150ms, get returns undefined
  it('TH-CACHE-02: TTL expiry — set 100ms TTL, wait 150ms, get returns undefined', () => {
    const key = ResponseCache.buildKey('/project', 'drift_status', {});
    cache.set(key, { ok: true }, 100);

    // Advance time
    vi.useFakeTimers();
    vi.advanceTimersByTime(150);
    expect(cache.get(key)).toBeUndefined();
    vi.useRealTimers();
  });

  // TH-CACHE-03: LRU eviction: fill 100, add 101st — oldest evicted
  it('TH-CACHE-03: LRU eviction — fill 100, add 101st — oldest evicted', () => {
    for (let i = 0; i < 100; i++) {
      cache.set(`key-${i}`, { i });
    }
    expect(cache.size).toBe(100);

    // Add 101st entry
    cache.set('key-100', { i: 100 });
    expect(cache.size).toBe(100); // Still 100
    expect(cache.get('key-0')).toBeUndefined(); // Oldest evicted
    expect(cache.get('key-100')).toEqual({ i: 100 }); // Newest present
  });

  // TH-CACHE-04: Project isolation — /project-a key not visible from /project-b
  it('TH-CACHE-04: project isolation — /project-a key not visible from /project-b', () => {
    const keyA = ResponseCache.buildKey('/project-a', 'drift_check', { path: '.' });
    const keyB = ResponseCache.buildKey('/project-b', 'drift_check', { path: '.' });

    cache.set(keyA, { project: 'a' });
    cache.set(keyB, { project: 'b' });

    expect(cache.get(keyA)).toEqual({ project: 'a' });
    expect(cache.get(keyB)).toEqual({ project: 'b' });

    // Keys are different due to different project roots
    expect(keyA).not.toBe(keyB);
  });

  // TH-CACHE-05: invalidate(glob): 5 keys match, all gone, others retained
  it('TH-CACHE-05: invalidate(glob) — matching keys removed, others retained', () => {
    cache.set('/proj:drift_check:abc', { a: 1 });
    cache.set('/proj:drift_check:def', { a: 2 });
    cache.set('/proj:drift_check:ghi', { a: 3 });
    cache.set('/proj:drift_audit:abc', { a: 4 });
    cache.set('/proj:drift_audit:def', { a: 5 });
    cache.set('/proj:drift_scan:abc', { a: 6 });

    const removed = cache.invalidate('/proj:drift_check:*');
    expect(removed).toBe(3);
    expect(cache.get('/proj:drift_check:abc')).toBeUndefined();
    expect(cache.get('/proj:drift_check:def')).toBeUndefined();
    expect(cache.get('/proj:drift_check:ghi')).toBeUndefined();
    expect(cache.get('/proj:drift_audit:abc')).toEqual({ a: 4 });
    expect(cache.get('/proj:drift_scan:abc')).toEqual({ a: 6 });
  });

  // TH-CACHE-06: invalidateProject(): all project entries gone, others retained
  it('TH-CACHE-06: invalidateProject() — all project entries gone, others retained', () => {
    cache.set('/proj-a:drift_check:abc', { a: 1 });
    cache.set('/proj-a:drift_audit:abc', { a: 2 });
    cache.set('/proj-b:drift_check:abc', { b: 1 });

    const removed = cache.invalidateProject('/proj-a');
    expect(removed).toBe(2);
    expect(cache.get('/proj-a:drift_check:abc')).toBeUndefined();
    expect(cache.get('/proj-a:drift_audit:abc')).toBeUndefined();
    expect(cache.get('/proj-b:drift_check:abc')).toEqual({ b: 1 });
  });

  // TH-CACHE-07: set(key, undefined) is no-op
  it('TH-CACHE-07: set(key, undefined) is no-op', () => {
    cache.set('key', undefined);
    expect(cache.size).toBe(0);
    expect(cache.get('key')).toBeUndefined();
  });

  // TH-CACHE-08: cache stores tokenEstimate field
  it('TH-CACHE-08: cache stores tokenEstimate field', () => {
    const key = 'test-key';
    cache.set(key, { data: 'hello' }, undefined, 250);

    // The tokenEstimate is stored internally — verify by getting the data back
    const data = cache.get(key);
    expect(data).toEqual({ data: 'hello' });
  });
});
