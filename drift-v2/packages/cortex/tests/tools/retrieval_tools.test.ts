/**
 * Retrieval tool tests — context, search, related.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { CortexClient } from "../../src/bridge/client.js";
import { driftContext } from "../../src/tools/retrieval/drift_context.js";
import { driftSearch } from "../../src/tools/retrieval/drift_search.js";
import { driftRelated } from "../../src/tools/retrieval/drift_related.js";
import type { CompressedMemory, TraversalResult } from "../../src/bridge/types.js";

const MOCK_COMPRESSED: CompressedMemory = {
  memory_id: "mem-001",
  memory_type: "semantic",
  importance: "high",
  level: 2,
  text: "Important knowledge about the system",
  token_count: 12,
  relevance_score: 0.92,
};

const MOCK_TRAVERSAL: TraversalResult = {
  origin_id: "mem-001",
  max_depth_reached: 3,
  nodes: [
    { memory_id: "mem-002", depth: 1, path_strength: 0.85 },
    { memory_id: "mem-003", depth: 2, path_strength: 0.6 },
  ],
};

function createMockClient(): CortexClient {
  return {
    retrieve: vi.fn(async () => [MOCK_COMPRESSED]),
    search: vi.fn(async () => [MOCK_COMPRESSED]),
    causalTraverse: vi.fn(async () => MOCK_TRAVERSAL),
  } as unknown as CortexClient;
}

describe("Retrieval Tools", () => {
  let client: CortexClient;

  beforeEach(() => {
    client = createMockClient();
  });

  describe("drift_context", () => {
    it("should retrieve context with budget", async () => {
      const tool = driftContext(client);
      expect(tool.name).toBe("drift_context");

      const result = (await tool.handler({
        focus: "authentication flow",
        budget: 2048,
      })) as { count: number; memories: CompressedMemory[] };

      expect(result.count).toBe(1);
      expect(result.memories[0].relevance_score).toBe(0.92);
      expect(client.retrieve).toHaveBeenCalled();
    });

    it("should pass active files and sent IDs", async () => {
      const tool = driftContext(client);
      await tool.handler({
        focus: "test",
        active_files: ["src/auth.ts"],
        sent_ids: ["mem-old"],
        budget: 1024,
      });
      expect(client.retrieve).toHaveBeenCalled();
    });
  });

  describe("drift_search", () => {
    it("should perform direct hybrid search", async () => {
      const tool = driftSearch(client);
      expect(tool.name).toBe("drift_search");

      const result = (await tool.handler({
        query: "database migration",
      })) as { count: number; memories: CompressedMemory[] };

      expect(result.count).toBe(1);
      expect(client.search).toHaveBeenCalledWith("database migration", undefined);
    });
  });

  describe("drift_related", () => {
    it("should find related memories via causal graph", async () => {
      const tool = driftRelated(client);
      expect(tool.name).toBe("drift_related");

      const result = (await tool.handler({
        memory_id: "mem-001",
      })) as { origin_id: string; related_count: number };

      expect(result.origin_id).toBe("mem-001");
      expect(result.related_count).toBe(2);
    });
  });
});
