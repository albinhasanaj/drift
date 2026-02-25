/**
 * CursorManager — opaque keyset cursors with HMAC integrity and TTL expiry.
 *
 * - encodeCursor({sortColumn, lastValue, lastId, version}) → base64url JSON + HMAC-SHA256
 * - decodeCursor(cursor) → data or null (invalid/tampered/expired/wrong-version)
 * - 1-hour expiry, version field for schema migration compat
 *
 * PH-INFRA-06
 */

import { createHmac } from 'node:crypto';

export interface CursorData {
  sortColumn: string;
  lastValue: string | number;
  lastId: string;
  version: number;
}

export interface CursorConfig {
  /** HMAC secret for cursor signing. */
  secret: string;
  /** Cursor TTL in milliseconds. Default: 1 hour. */
  ttlMs: number;
  /** Current cursor version. Cursors with different versions are rejected. */
  currentVersion: number;
}

const DEFAULT_CURSOR_CONFIG: CursorConfig = {
  secret: 'drift-cursor-secret-change-in-production',
  ttlMs: 60 * 60 * 1000, // 1 hour
  currentVersion: 1,
};

interface CursorPayload extends CursorData {
  createdAt: number;
}

export class CursorManager {
  private readonly config: CursorConfig;

  constructor(config: Partial<CursorConfig> = {}) {
    this.config = { ...DEFAULT_CURSOR_CONFIG, ...config };
  }

  /** Encode cursor data into an opaque string. */
  encodeCursor(data: CursorData): string {
    const payload: CursorPayload = {
      ...data,
      version: this.config.currentVersion,
      createdAt: Date.now(),
    };
    const json = JSON.stringify(payload);
    const signature = this.sign(json);
    const combined = `${json}|${signature}`;
    return Buffer.from(combined).toString('base64url');
  }

  /** Decode and validate a cursor string. Returns null if invalid/tampered/expired/wrong-version. */
  decodeCursor(cursor: string): CursorData | null {
    if (!cursor || cursor.length === 0) return null;

    let decoded: string;
    try {
      decoded = Buffer.from(cursor, 'base64url').toString('utf-8');
    } catch {
      return null;
    }

    const separatorIndex = decoded.lastIndexOf('|');
    if (separatorIndex === -1) return null;

    const json = decoded.slice(0, separatorIndex);
    const signature = decoded.slice(separatorIndex + 1);

    // Verify HMAC
    const expectedSignature = this.sign(json);
    if (signature !== expectedSignature) return null;

    let payload: CursorPayload;
    try {
      payload = JSON.parse(json) as CursorPayload;
    } catch {
      return null;
    }

    // Check version
    if (payload.version !== this.config.currentVersion) return null;

    // Check expiry
    const now = Date.now();
    if (now - payload.createdAt > this.config.ttlMs) return null;

    return {
      sortColumn: payload.sortColumn,
      lastValue: payload.lastValue,
      lastId: payload.lastId,
      version: payload.version,
    };
  }

  private sign(data: string): string {
    return createHmac('sha256', this.config.secret).update(data).digest('hex');
  }
}
