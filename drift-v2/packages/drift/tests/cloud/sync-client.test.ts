import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  SyncClient,
  TIER1_TABLES,
  defaultSyncState,
} from '../../src/cloud/sync-client.js';
import type { LocalRowReader } from '../../src/cloud/sync-client.js';
import type { CloudConfig, SyncState } from '../../src/cloud/config.js';
import { BATCH_SIZE } from '../../src/cloud/config.js';

// ── Mock auth ──

vi.mock('../../src/cloud/auth.js', () => ({
  getToken: vi.fn().mockResolvedValue('mock-jwt-token'),
}));

// ── Mock fetch ──

const fetchMock = vi.fn();
globalThis.fetch = fetchMock;

// ── Helpers ──

const MOCK_CONFIG: CloudConfig = {
  supabaseUrl: 'https://test.supabase.co',
  supabaseAnonKey: 'anon-key-123',
  projectId: 'proj-uuid-1',
  tenantId: 'tenant-uuid-1',
};

function mockReader(tableRows: Record<string, Record<string, unknown>[]> = {}): LocalRowReader {
  return {
    readRows: vi.fn().mockImplementation(async (table: string) => {
      return tableRows[table] ?? [];
    }),
    getMaxCursor: vi.fn().mockResolvedValue(100),
  };
}

function okResponse(): Response {
  return new Response(null, { status: 200 });
}

// ── Tests ──

beforeEach(() => {
  fetchMock.mockReset();
  fetchMock.mockResolvedValue(okResponse());
});

describe('SyncClient', () => {
  describe('push()', () => {
    it('returns success with zero rows when all tables empty', async () => {
      const client = new SyncClient(MOCK_CONFIG, '/project');
      const result = await client.push(mockReader(), null);

      expect(result.success).toBe(true);
      expect(result.totalRows).toBe(0);
      expect(result.errors).toHaveLength(0);
      expect(result.syncState.lastSyncAt).not.toBeNull();
    });

    it('uploads rows with tenant_id and project_id injected', async () => {
      const reader = mockReader({
        violations: [
          { id: 'v-1', file: 'src/a.ts', line: 10, severity: 'error' },
        ],
      });

      const client = new SyncClient(MOCK_CONFIG, '/project');
      await client.push(reader, null);

      // Find the fetch call for cloud_violations
      const violationCall = fetchMock.mock.calls.find(
        (call: unknown[]) => (call[0] as string).includes('cloud_violations')
      );
      expect(violationCall).toBeDefined();

      const body = JSON.parse((violationCall![1] as RequestInit).body as string);
      expect(body[0].tenant_id).toBe('tenant-uuid-1');
      expect(body[0].project_id).toBe('proj-uuid-1');
    });

    it('applies redaction to path fields before upload', async () => {
      const reader = mockReader({
        violations: [
          { id: 'v-1', file: '/project/src/auth.ts', line: 10, severity: 'error' },
        ],
      });

      const client = new SyncClient(MOCK_CONFIG, '/project');
      await client.push(reader, null);

      const violationCall = fetchMock.mock.calls.find(
        (call: unknown[]) => (call[0] as string).includes('cloud_violations')
      );
      const body = JSON.parse((violationCall![1] as RequestInit).body as string);
      expect(body[0].file).toBe('src/auth.ts');
    });

    it('sends upsert headers to PostgREST', async () => {
      const reader = mockReader({
        gate_results: [
          { id: 1, gate_id: 'complexity', passed: true, score: 0.9 },
        ],
      });

      const client = new SyncClient(MOCK_CONFIG, '/project');
      await client.push(reader, null);

      const gateCall = fetchMock.mock.calls.find(
        (call: unknown[]) => (call[0] as string).includes('cloud_gate_results')
      );
      expect(gateCall).toBeDefined();
      const headers = (gateCall![1] as RequestInit).headers as Record<string, string>;
      expect(headers['Prefer']).toContain('resolution=merge-duplicates');
      expect(headers['Authorization']).toBe('Bearer mock-jwt-token');
    });

    it('returns error when not authenticated', async () => {
      const { getToken } = await import('../../src/cloud/auth.js');
      (getToken as ReturnType<typeof vi.fn>).mockResolvedValueOnce(null);

      const client = new SyncClient(MOCK_CONFIG, '/project');
      const result = await client.push(mockReader(), null);

      expect(result.success).toBe(false);
      expect(result.errors[0].message).toContain('Not authenticated');
    });

    it('updates sync cursors after successful push', async () => {
      const reader = mockReader();
      (reader.getMaxCursor as ReturnType<typeof vi.fn>)
        .mockResolvedValueOnce(500)   // drift
        .mockResolvedValueOnce(200)   // bridge
        .mockResolvedValueOnce(50);   // cortex

      const client = new SyncClient(MOCK_CONFIG, '/project');
      const result = await client.push(reader, null);

      expect(result.syncState.driftCursor).toBe(500);
      expect(result.syncState.bridgeCursor).toBe(200);
      expect(result.syncState.cortexCursor).toBe(50);
    });

    it('reports per-table row counts', async () => {
      const reader = mockReader({
        violations: [
          { id: 'v-1', file: 'a.ts', severity: 'error' },
          { id: 'v-2', file: 'b.ts', severity: 'warning' },
        ],
        gate_results: [
          { id: 1, gate_id: 'complexity', passed: true },
        ],
      });

      const client = new SyncClient(MOCK_CONFIG, '/project');
      const result = await client.push(reader, null);

      expect(result.tableCounts['violations']).toBe(2);
      expect(result.tableCounts['gate_results']).toBe(1);
      expect(result.totalRows).toBe(3);
    });

    it('handles PostgREST 4xx error as non-retryable', async () => {
      fetchMock.mockResolvedValue(new Response('Conflict', { status: 409 }));

      const reader = mockReader({
        violations: [{ id: 'v-1', file: 'a.ts', severity: 'error' }],
      });

      const client = new SyncClient(MOCK_CONFIG, '/project');
      const result = await client.push(reader, null);

      // Should have errors but not hang forever retrying
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors[0].retryable).toBe(false);
    });

    it('calls onProgress callback', async () => {
      const reader = mockReader({
        violations: [{ id: 'v-1', file: 'a.ts', severity: 'error' }],
      });
      const progressCalls: unknown[] = [];

      const client = new SyncClient(MOCK_CONFIG, '/project');
      await client.push(reader, null, (p) => progressCalls.push(p));

      expect(progressCalls.length).toBeGreaterThan(0);
    });

    it('respects fullSync flag to ignore cursors', async () => {
      const reader = mockReader();
      const existingState: SyncState = {
        driftCursor: 999,
        bridgeCursor: 999,
        cortexCursor: 999,
        lastSyncAt: '2026-01-01T00:00:00Z',
        lastSyncRowCount: 50,
      };

      const client = new SyncClient(MOCK_CONFIG, '/project');
      await client.push(reader, existingState, undefined, true);

      // readRows should have been called with cursor 0 (not 999) for drift tables
      const readRowsCalls = (reader.readRows as ReturnType<typeof vi.fn>).mock.calls;
      const driftCall = readRowsCalls.find(
        (call: unknown[]) => call[1] === 'drift'
      );
      expect(driftCall).toBeDefined();
      expect(driftCall![2]).toBe(0);
    });
  });
});

describe('TIER1_TABLES', () => {
  it('has 42 table definitions', () => {
    expect(TIER1_TABLES).toHaveLength(42);
  });

  it('all have required fields', () => {
    for (const def of TIER1_TABLES) {
      expect(def.localTable).toBeTruthy();
      expect(def.cloudTable).toBeTruthy();
      expect(['drift', 'bridge', 'cortex']).toContain(def.db);
      expect(def.conflictColumns).toBeTruthy();
    }
  });

  it('cloud table names all start with cloud_', () => {
    for (const def of TIER1_TABLES) {
      expect(def.cloudTable.startsWith('cloud_')).toBe(true);
    }
  });

  it('has 37 drift tables and 5 bridge tables', () => {
    const drift = TIER1_TABLES.filter(t => t.db === 'drift');
    const bridge = TIER1_TABLES.filter(t => t.db === 'bridge');
    expect(drift).toHaveLength(37);
    expect(bridge).toHaveLength(5);
  });
});

describe('defaultSyncState', () => {
  it('returns zeroed cursors', () => {
    const state = defaultSyncState();
    expect(state.driftCursor).toBe(0);
    expect(state.bridgeCursor).toBe(0);
    expect(state.cortexCursor).toBe(0);
    expect(state.lastSyncAt).toBeNull();
    expect(state.lastSyncRowCount).toBe(0);
  });
});
