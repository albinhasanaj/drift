/**
 * Cursor Manager Tests — TH-CURSOR-01 through TH-CURSOR-06
 */

import { describe, it, expect, vi } from 'vitest';
import { CursorManager } from '../../src/infrastructure/cursor_manager.js';

describe('Cursor Manager', () => {
  const manager = new CursorManager({ secret: 'test-secret' });

  // TH-CURSOR-01: encode→decode round-trip
  it('TH-CURSOR-01: encode→decode round-trip returns original data', () => {
    const data = {
      sortColumn: 'created_at',
      lastValue: '2025-01-01',
      lastId: 'abc-123',
      version: 1,
    };
    const cursor = manager.encodeCursor(data);
    const decoded = manager.decodeCursor(cursor);
    expect(decoded).not.toBeNull();
    expect(decoded!.sortColumn).toBe('created_at');
    expect(decoded!.lastValue).toBe('2025-01-01');
    expect(decoded!.lastId).toBe('abc-123');
    expect(decoded!.version).toBe(1);
  });

  // TH-CURSOR-02: tampered → null
  it('TH-CURSOR-02: tampered cursor returns null', () => {
    const data = {
      sortColumn: 'id',
      lastValue: 42,
      lastId: 'xyz',
      version: 1,
    };
    const cursor = manager.encodeCursor(data);

    // Tamper by decoding, modifying the JSON payload, and re-encoding without valid HMAC
    const decoded = Buffer.from(cursor, 'base64url').toString('utf-8');
    const sepIdx = decoded.lastIndexOf('|');
    const json = decoded.slice(0, sepIdx);
    const sig = decoded.slice(sepIdx + 1);
    // Modify JSON but keep old signature — HMAC should fail
    const tampered = json.replace('"id"', '"ID"') + '|' + sig;
    const tamperedCursor = Buffer.from(tampered).toString('base64url');
    expect(manager.decodeCursor(tamperedCursor)).toBeNull();
  });

  // TH-CURSOR-03: expired → null
  it('TH-CURSOR-03: expired cursor returns null', () => {
    const shortTtlManager = new CursorManager({ secret: 'test', ttlMs: 100 });
    const data = {
      sortColumn: 'id',
      lastValue: 1,
      lastId: 'x',
      version: 1,
    };
    const cursor = shortTtlManager.encodeCursor(data);

    // Advance time past TTL
    vi.useFakeTimers();
    vi.advanceTimersByTime(200);
    expect(shortTtlManager.decodeCursor(cursor)).toBeNull();
    vi.useRealTimers();
  });

  // TH-CURSOR-04: wrong version → null
  it('TH-CURSOR-04: wrong version cursor returns null', () => {
    const v1Manager = new CursorManager({ secret: 'test', currentVersion: 1 });
    const v2Manager = new CursorManager({ secret: 'test', currentVersion: 2 });

    const data = {
      sortColumn: 'id',
      lastValue: 1,
      lastId: 'x',
      version: 1,
    };
    const cursor = v1Manager.encodeCursor(data);
    // v2 manager should reject v1 cursors
    expect(v2Manager.decodeCursor(cursor)).toBeNull();
  });

  // TH-CURSOR-05: empty → null
  it('TH-CURSOR-05: empty string returns null', () => {
    expect(manager.decodeCursor('')).toBeNull();
  });

  // TH-CURSOR-06: invalid base64 → null
  it('TH-CURSOR-06: invalid base64 returns null', () => {
    expect(manager.decodeCursor('not-valid-base64!!!')).toBeNull();
    expect(manager.decodeCursor('aGVsbG8=')).toBeNull(); // valid base64 but not a cursor
  });
});
