/**
 * CLI command integration tests — all 13 commands.
 *
 * Tests that each CLI command function calls the correct client methods
 * and produces output without errors.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { CortexClient } from "../../src/bridge/client.js";
import { statusCommand } from "../../src/cli/status.js";
import { searchCommand } from "../../src/cli/search.js";
import { whyCommand } from "../../src/cli/why.js";
import { explainCommand } from "../../src/cli/explain.js";
import { consolidateCommand } from "../../src/cli/consolidate.js";
import { validateCommand } from "../../src/cli/validate.js";
import { gcCommand } from "../../src/cli/gc.js";
import { metricsCommand } from "../../src/cli/metrics.js";
import { reembedCommand } from "../../src/cli/reembed.js";
import { exportCommand } from "../../src/cli/export.js";
import { learnCommand } from "../../src/cli/learn.js";
import type { BaseMemory } from "../../src/bridge/types.js";

const MOCK_MEMORY: BaseMemory = {
  id: "mem-001",
  memory_type: "episodic",
  content: { type: "episodic", data: { interaction: "test", context: "ctx", outcome: null } },
  summary: "Test memory",
  transaction_time: "2026-01-01T00:00:00Z",
  valid_time: "2026-01-01T00:00:00Z",
  valid_until: null,
  confidence: 0.9,
  importance: "normal",
  last_accessed: "2026-01-01T00:00:00Z",
  access_count: 5,
  linked_patterns: [],
  linked_constraints: [],
  linked_files: [{ file_path: "src/main.ts", line_start: 1, line_end: 10, content_hash: null }],
  linked_functions: [],
  tags: ["test"],
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
    search: vi.fn(async () => [
      {
        memory_id: "mem-001",
        memory_type: "semantic",
        importance: "high",
        level: 2,
        text: "Important knowledge",
        token_count: 8,
        relevance_score: 0.88,
      },
    ]),
    memorySearch: vi.fn(async () => [MOCK_MEMORY]),
    memoryGet: vi.fn(async () => MOCK_MEMORY),
    causalGetWhy: vi.fn(async () => ({
      summary: "Because of the incident",
      confidence: 0.85,
      sections: [{ title: "Root Cause", entries: ["Missing validation"] }],
    })),
    causalTraverse: vi.fn(async () => ({
      origin_id: "mem-001",
      max_depth_reached: 2,
      nodes: [{ memory_id: "mem-002", depth: 1, path_strength: 0.9 }],
    })),
    consolidate: vi.fn(async () => ({
      created: ["new-1"],
      archived: ["old-1"],
      metrics: { precision: 0.92, compression_ratio: 2.1, lift: 0.12, stability: 0.9 },
    })),
    getValidationCandidates: vi.fn(async () => [
      { ...MOCK_MEMORY, confidence: 0.2 },
    ]),
    sessionCleanup: vi.fn(async () => 2),
    memoryArchive: vi.fn(),
    memoryList: vi.fn(async () => [MOCK_MEMORY]),
    cacheStats: vi.fn(async () => ({
      entry_count: 15,
      hits: 12,
      misses: 3,
      hit_rate: 0.8,
    })),
    learn: vi.fn(async () => ({
      category: "factual",
      principle: "Always validate input",
      memory_created: "mem-new",
    })),
  } as unknown as CortexClient;
}

describe("CLI Commands", () => {
  let client: CortexClient;
  let consoleSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    client = createMockClient();
    consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  it("status — shows health dashboard", async () => {
    await statusCommand(client);
    expect(client.healthReport).toHaveBeenCalled();
    expect(consoleSpy).toHaveBeenCalled();
  });

  it("search — performs hybrid search", async () => {
    await searchCommand(client, "authentication");
    expect(client.search).toHaveBeenCalled();
    expect(consoleSpy).toHaveBeenCalled();
  });

  it("search — handles empty results", async () => {
    (client.search as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    await searchCommand(client, "nonexistent");
    expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining("No memories"));
  });

  it("why — shows causal narrative", async () => {
    await whyCommand(client, "src/auth.ts");
    expect(client.memorySearch).toHaveBeenCalled();
    expect(client.causalGetWhy).toHaveBeenCalled();
  });

  it("explain — shows full memory with causal chain", async () => {
    await explainCommand(client, "mem-001");
    expect(client.memoryGet).toHaveBeenCalledWith("mem-001");
    expect(client.causalGetWhy).toHaveBeenCalledWith("mem-001");
    expect(client.causalTraverse).toHaveBeenCalledWith("mem-001");
  });

  it("consolidate — triggers consolidation", async () => {
    await consolidateCommand(client);
    expect(client.consolidate).toHaveBeenCalled();
  });

  it("validate — runs validation", async () => {
    await validateCommand(client);
    expect(client.getValidationCandidates).toHaveBeenCalled();
  });

  it("gc — runs garbage collection", async () => {
    await gcCommand(client);
    expect(client.sessionCleanup).toHaveBeenCalled();
    expect(client.memoryArchive).toHaveBeenCalled();
  });

  it("metrics — shows system metrics", async () => {
    await metricsCommand(client);
    expect(client.consolidationMetrics).toHaveBeenCalled();
    expect(client.cacheStats).toHaveBeenCalled();
  });

  it("reembed — triggers re-embedding", async () => {
    await reembedCommand(client);
    expect(client.memoryList).toHaveBeenCalled();
  });

  it("export — exports memories as JSON", async () => {
    await exportCommand(client);
    expect(client.memoryList).toHaveBeenCalled();
    expect(consoleSpy).toHaveBeenCalled();
  });

  it("learn — processes correction", async () => {
    await learnCommand(client, "Fix: use async/await", "code review");
    expect(client.learn).toHaveBeenCalled();
  });
});
