/**
 * Why/causal tool tests — why, explain, counterfactual, intervention.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { CortexClient } from "../../src/bridge/client.js";
import { driftWhy } from "../../src/tools/why/drift_why.js";
import { driftExplain } from "../../src/tools/why/drift_explain.js";
import { driftCounterfactual } from "../../src/tools/why/drift_counterfactual.js";
import { driftIntervention } from "../../src/tools/why/drift_intervention.js";
import type { BaseMemory, CausalNarrative, TraversalResult } from "../../src/bridge/types.js";

const MOCK_NARRATIVE: CausalNarrative = {
  summary: "This pattern exists because of a performance incident in Q3",
  confidence: 0.88,
  sections: [
    { title: "Root Cause", entries: ["Performance degradation under load"] },
    { title: "Resolution", entries: ["Implemented caching layer"] },
  ],
};

const MOCK_TRAVERSAL: TraversalResult = {
  origin_id: "mem-001",
  max_depth_reached: 2,
  nodes: [
    { memory_id: "mem-002", depth: 1, path_strength: 0.9 },
  ],
};

const MOCK_MEMORY: BaseMemory = {
  id: "mem-001",
  memory_type: "incident",
  content: {
    type: "incident",
    data: {
      title: "Q3 Performance Incident",
      root_cause: "Missing cache",
      impact: "High latency",
      resolution: "Added Redis cache",
      lessons_learned: ["Always cache hot paths"],
    },
  },
  summary: "Q3 performance incident",
  transaction_time: "2026-01-01T00:00:00Z",
  valid_time: "2026-01-01T00:00:00Z",
  valid_until: null,
  confidence: 0.95,
  importance: "critical",
  last_accessed: "2026-02-01T00:00:00Z",
  access_count: 15,
  linked_patterns: [],
  linked_constraints: [],
  linked_files: [],
  linked_functions: [],
  tags: ["incident", "performance"],
  archived: false,
  superseded_by: null,
  supersedes: null,
  content_hash: "hash456",
};

function createMockClient(): CortexClient {
  return {
    causalGetWhy: vi.fn(async () => MOCK_NARRATIVE),
    causalTraverse: vi.fn(async () => MOCK_TRAVERSAL),
    causalCounterfactual: vi.fn(async () => ({
      ...MOCK_TRAVERSAL,
      nodes: [
        { memory_id: "mem-003", depth: 1, path_strength: 0.7 },
        { memory_id: "mem-004", depth: 2, path_strength: 0.4 },
      ],
    })),
    causalIntervention: vi.fn(async () => ({
      ...MOCK_TRAVERSAL,
      nodes: [{ memory_id: "mem-005", depth: 1, path_strength: 0.85 }],
    })),
    memoryGet: vi.fn(async () => MOCK_MEMORY),
  } as unknown as CortexClient;
}

describe("Why/Causal Tools", () => {
  let client: CortexClient;

  beforeEach(() => {
    client = createMockClient();
  });

  describe("drift_why", () => {
    it("should return causal narrative", async () => {
      const tool = driftWhy(client);
      expect(tool.name).toBe("drift_why");

      const result = (await tool.handler({ memory_id: "mem-001" })) as CausalNarrative;
      expect(result.summary).toContain("performance incident");
      expect(result.confidence).toBe(0.88);
      expect(result.sections).toHaveLength(2);
    });
  });

  describe("drift_explain", () => {
    it("should return memory with narrative and causal graph", async () => {
      const tool = driftExplain(client);
      expect(tool.name).toBe("drift_explain");

      const result = (await tool.handler({ memory_id: "mem-001" })) as {
        memory: BaseMemory;
        narrative: CausalNarrative;
        causal_graph: TraversalResult;
      };

      expect(result.memory.id).toBe("mem-001");
      expect(result.narrative.summary).toContain("performance");
      expect(result.causal_graph.nodes).toHaveLength(1);
    });
  });

  describe("drift_counterfactual", () => {
    it("should show affected memories if removed", async () => {
      const tool = driftCounterfactual(client);
      expect(tool.name).toBe("drift_counterfactual");

      const result = (await tool.handler({ memory_id: "mem-001" })) as {
        affected_count: number;
      };
      expect(result.affected_count).toBe(2);
    });
  });

  describe("drift_intervention", () => {
    it("should show what needs updating if modified", async () => {
      const tool = driftIntervention(client);
      expect(tool.name).toBe("drift_intervention");

      const result = (await tool.handler({ memory_id: "mem-001" })) as {
        needs_update_count: number;
      };
      expect(result.needs_update_count).toBe(1);
    });
  });
});
