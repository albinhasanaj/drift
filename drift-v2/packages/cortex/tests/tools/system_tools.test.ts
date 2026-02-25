/**
 * System tool tests — status, metrics, consolidate, validate, gc, export, import, reembed.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { CortexClient } from "../../src/bridge/client.js";
import { driftCortexStatus } from "../../src/tools/system/drift_cortex_status.js";
import { driftCortexMetrics } from "../../src/tools/system/drift_cortex_metrics.js";
import { driftCortexConsolidate } from "../../src/tools/system/drift_cortex_consolidate.js";
import { driftCortexValidate } from "../../src/tools/system/drift_cortex_validate.js";
import { driftCortexGc } from "../../src/tools/system/drift_cortex_gc.js";
import { driftCortexExport } from "../../src/tools/system/drift_cortex_export.js";
import { driftCortexImport } from "../../src/tools/system/drift_cortex_import.js";
import { driftCortexReembed } from "../../src/tools/system/drift_cortex_reembed.js";
import type { BaseMemory } from "../../src/bridge/types.js";

const MOCK_MEMORY: BaseMemory = {
  id: "mem-001",
  memory_type: "episodic",
  content: { type: "episodic", data: { interaction: "test", context: "ctx", outcome: null } },
  summary: "Test memory",
  transaction_time: "2026-01-01T00:00:00Z",
  valid_time: "2026-01-01T00:00:00Z",
  valid_until: null,
  confidence: 0.1,
  importance: "low",
  last_accessed: "2026-01-01T00:00:00Z",
  access_count: 0,
  linked_patterns: [],
  linked_constraints: [],
  linked_files: [],
  linked_functions: [],
  tags: [],
  archived: false,
  superseded_by: null,
  supersedes: null,
  content_hash: "hash",
};

function createMockClient(): CortexClient {
  return {
    healthReport: vi.fn(async () => ({
      overall_status: "healthy",
      subsystems: [{ name: "storage", status: "healthy", message: null }],
      metrics: {
        total_memories: 50,
        active_memories: 45,
        archived_memories: 5,
        average_confidence: 0.82,
        db_size_bytes: 512000,
        embedding_cache_hit_rate: 0.7,
      },
    })),
    consolidationStatus: vi.fn(async () => ({ is_running: false })),
    consolidationMetrics: vi.fn(async () => ({
      total_runs: 10,
      successful_runs: 9,
      success_rate: 0.9,
      is_running: false,
    })),
    degradations: vi.fn(async () => []),
    healthMetrics: vi.fn(async () => ({ session_count: 2 })),
    cacheStats: vi.fn(async () => ({
      entry_count: 20,
      hits: 15,
      misses: 5,
      hit_rate: 0.75,
    })),
    consolidate: vi.fn(async () => ({
      created: ["new-1"],
      archived: ["old-1", "old-2"],
      metrics: { precision: 0.9, compression_ratio: 2.5, lift: 0.15, stability: 0.88 },
    })),
    getValidationCandidates: vi.fn(async (min?: number, max?: number) =>
      max === 0.15 ? [] : [MOCK_MEMORY],
    ),
    validationRun: vi.fn(async () => ({ total_checked: 1 })),
    decayRun: vi.fn(async () => ({ processed: 10, archived: 1, updated: 9 })),
    reembed: vi.fn(async () => ({ total_memories: 1, reembedded: 1 })),
    sessionCleanup: vi.fn(async () => 3),
    memoryArchive: vi.fn(),
    memoryList: vi.fn(async () => [MOCK_MEMORY]),
    memoryCreate: vi.fn(),
    search: vi.fn(async () => []),
  } as unknown as CortexClient;
}

describe("System Tools", () => {
  let client: CortexClient;

  beforeEach(() => {
    client = createMockClient();
  });

  describe("drift_cortex_status", () => {
    it("should return health dashboard", async () => {
      const tool = driftCortexStatus(client);
      expect(tool.name).toBe("drift_cortex_status");

      const result = (await tool.handler({})) as {
        health: { overall_status: string };
        degradation_count: number;
      };
      expect(result.health.overall_status).toBe("healthy");
      expect(result.degradation_count).toBe(0);
    });
  });

  describe("drift_cortex_metrics", () => {
    it("should return combined metrics", async () => {
      const tool = driftCortexMetrics(client);
      const result = (await tool.handler({})) as {
        consolidation: { total_runs: number };
        prediction_cache: { hit_rate: number };
      };
      expect(result.consolidation.total_runs).toBe(10);
      expect(result.prediction_cache.hit_rate).toBe(0.75);
    });
  });

  describe("drift_cortex_consolidate", () => {
    it("should trigger consolidation", async () => {
      const tool = driftCortexConsolidate(client);
      const result = (await tool.handler({})) as {
        created: string[];
        archived: string[];
      };
      expect(result.created).toHaveLength(1);
      expect(result.archived).toHaveLength(2);
    });
  });

  describe("drift_cortex_validate", () => {
    it("should return validation candidates", async () => {
      const tool = driftCortexValidate(client);
      const result = (await tool.handler({})) as { total_checked: number };
      expect(result.total_checked).toBe(1);
    });
  });

  describe("drift_cortex_gc", () => {
    it("should run garbage collection", async () => {
      const tool = driftCortexGc(client);
      const result = (await tool.handler({})) as {
        sessions_removed: number;
        memories_archived: number;
      };
      expect(result.sessions_removed).toBe(3);
      expect(result.memories_archived).toBe(1);
    });
  });

  describe("drift_cortex_export", () => {
    it("should export memories", async () => {
      const tool = driftCortexExport(client);
      const result = (await tool.handler({})) as {
        count: number;
        exported_at: string;
      };
      expect(result.count).toBe(1);
      expect(result.exported_at).toBeDefined();
    });
  });

  describe("drift_cortex_import", () => {
    it("should import memories", async () => {
      const tool = driftCortexImport(client);
      const result = (await tool.handler({
        memories: [MOCK_MEMORY],
      })) as { imported: number };
      expect(result.imported).toBe(1);
    });

    it("should handle duplicate errors gracefully", async () => {
      const mockClient = createMockClient();
      (mockClient.memoryCreate as ReturnType<typeof vi.fn>).mockRejectedValue(
        new Error("UNIQUE constraint failed"),
      );
      const tool = driftCortexImport(mockClient);
      const result = (await tool.handler({
        memories: [MOCK_MEMORY],
      })) as { imported: number; skipped: number };
      expect(result.imported).toBe(0);
      expect(result.skipped).toBe(1);
    });
  });

  describe("drift_cortex_reembed", () => {
    it("should trigger re-embedding", async () => {
      const tool = driftCortexReembed(client);
      const result = (await tool.handler({})) as {
        total_memories: number;
        reembedded: number;
      };
      expect(result.total_memories).toBe(1);
      expect(result.reembedded).toBe(1);
    });
  });
});
