/**
 * Memory CRUD tool tests — all 8 memory tools.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { CortexClient } from "../../src/bridge/client.js";
import { driftMemoryAdd } from "../../src/tools/memory/drift_memory_add.js";
import { driftMemoryGet } from "../../src/tools/memory/drift_memory_get.js";
import { driftMemorySearch } from "../../src/tools/memory/drift_memory_search.js";
import { driftMemoryUpdate } from "../../src/tools/memory/drift_memory_update.js";
import { driftMemoryDelete } from "../../src/tools/memory/drift_memory_delete.js";
import { driftMemoryList } from "../../src/tools/memory/drift_memory_list.js";
import { driftMemoryLink } from "../../src/tools/memory/drift_memory_link.js";
import { driftMemoryUnlink } from "../../src/tools/memory/drift_memory_unlink.js";
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
  access_count: 0,
  linked_patterns: [{ pattern_id: "p1", pattern_name: "singleton" }],
  linked_constraints: [],
  linked_files: [{ file_path: "src/main.ts", line_start: 1, line_end: 10, content_hash: null }],
  linked_functions: [],
  tags: ["test"],
  archived: false,
  superseded_by: null,
  supersedes: null,
  content_hash: "hash123",
};

function createMockClient(): CortexClient {
  return {
    memoryCreate: vi.fn(),
    memoryGet: vi.fn(async () => ({ ...MOCK_MEMORY })),
    memoryUpdate: vi.fn(),
    memoryDelete: vi.fn(),
    memorySearch: vi.fn(async () => [MOCK_MEMORY]),
    memoryList: vi.fn(async () => [MOCK_MEMORY]),
    memoryArchive: vi.fn(),
    memoryRestore: vi.fn(),
  } as unknown as CortexClient;
}

describe("Memory Tools", () => {
  let client: CortexClient;

  beforeEach(() => {
    client = createMockClient();
  });

  describe("drift_memory_add", () => {
    it("should create a memory and return its ID", async () => {
      const tool = driftMemoryAdd(client);
      expect(tool.name).toBe("drift_memory_add");

      const result = (await tool.handler({
        memory_type: "episodic",
        content: { type: "episodic", data: { interaction: "test", context: "ctx", outcome: null } },
        summary: "Test",
        tags: ["test"],
      })) as { id: string; status: string };

      expect(result.status).toBe("created");
      expect(result.id).toBeDefined();
      expect(client.memoryCreate).toHaveBeenCalled();
    });

    it("should have required fields in schema", () => {
      const tool = driftMemoryAdd(client);
      expect(tool.inputSchema.required).toContain("memory_type");
      expect(tool.inputSchema.required).toContain("content");
      expect(tool.inputSchema.required).toContain("summary");
    });
  });

  describe("drift_memory_get", () => {
    it("should return a memory by ID", async () => {
      const tool = driftMemoryGet(client);
      const result = (await tool.handler({ id: "mem-001" })) as BaseMemory;
      expect(result.id).toBe("mem-001");
      expect(result.memory_type).toBe("episodic");
    });
  });

  describe("drift_memory_search", () => {
    it("should search and return results", async () => {
      const tool = driftMemorySearch(client);
      const result = (await tool.handler({ query: "test" })) as {
        count: number;
        memories: BaseMemory[];
      };
      expect(result.count).toBe(1);
      expect(result.memories[0].id).toBe("mem-001");
    });
  });

  describe("drift_memory_update", () => {
    it("should update a memory", async () => {
      const tool = driftMemoryUpdate(client);
      const result = (await tool.handler({
        memory: { ...MOCK_MEMORY, summary: "Updated" },
      })) as { id: string; status: string };
      expect(result.status).toBe("updated");
      expect(client.memoryUpdate).toHaveBeenCalled();
    });
  });

  describe("drift_memory_delete", () => {
    it("should archive by default (soft delete)", async () => {
      const tool = driftMemoryDelete(client);
      const result = (await tool.handler({ id: "mem-001" })) as {
        id: string;
        status: string;
      };
      expect(result.status).toBe("archived");
      expect(client.memoryArchive).toHaveBeenCalledWith("mem-001");
    });

    it("should hard delete when flag is set", async () => {
      const tool = driftMemoryDelete(client);
      const result = (await tool.handler({
        id: "mem-001",
        hard_delete: true,
      })) as { id: string; status: string };
      expect(result.status).toBe("deleted");
      expect(client.memoryDelete).toHaveBeenCalledWith("mem-001");
    });
  });

  describe("drift_memory_list", () => {
    it("should list memories", async () => {
      const tool = driftMemoryList(client);
      const result = (await tool.handler({})) as {
        count: number;
        memories: BaseMemory[];
      };
      expect(result.count).toBe(1);
    });

    it("should filter by type", async () => {
      const tool = driftMemoryList(client);
      await tool.handler({ memory_type: "tribal" });
      expect(client.memoryList).toHaveBeenCalledWith("tribal");
    });
  });

  describe("drift_memory_link", () => {
    it("should add a pattern link", async () => {
      const tool = driftMemoryLink(client);
      const result = (await tool.handler({
        memory_id: "mem-001",
        link_type: "pattern",
        link_data: { pattern_id: "p2", pattern_name: "factory" },
      })) as { status: string };
      expect(result.status).toBe("linked");
      expect(client.memoryUpdate).toHaveBeenCalled();
    });

    it("should add a file link", async () => {
      const tool = driftMemoryLink(client);
      await tool.handler({
        memory_id: "mem-001",
        link_type: "file",
        link_data: { file_path: "src/utils.ts", line_start: 5, line_end: 20, content_hash: null },
      });
      expect(client.memoryUpdate).toHaveBeenCalled();
    });
  });

  describe("drift_memory_unlink", () => {
    it("should remove a pattern link", async () => {
      const tool = driftMemoryUnlink(client);
      const result = (await tool.handler({
        memory_id: "mem-001",
        link_type: "pattern",
        identifier: "p1",
      })) as { status: string };
      expect(result.status).toBe("unlinked");
      expect(client.memoryUpdate).toHaveBeenCalled();
    });

    it("should remove a file link", async () => {
      const tool = driftMemoryUnlink(client);
      await tool.handler({
        memory_id: "mem-001",
        link_type: "file",
        identifier: "src/main.ts",
      });
      expect(client.memoryUpdate).toHaveBeenCalled();
    });
  });
});
