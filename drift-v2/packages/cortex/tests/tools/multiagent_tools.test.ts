/**
 * Multi-agent MCP tool tests — all 5 multi-agent tools.
 *
 * TMD3-MCP-01: drift_agent_register works
 * TMD3-MCP-02: drift_agent_share works
 * TMD3-MCP-03: drift_agent_provenance works
 * TMD3-MCP-04: drift_agent_trust works
 * (drift_agent_project also tested)
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { CortexClient } from "../../src/bridge/client.js";
import { driftAgentRegister } from "../../src/tools/multiagent/drift_agent_register.js";
import { driftAgentShare } from "../../src/tools/multiagent/drift_agent_share.js";
import { driftAgentProject } from "../../src/tools/multiagent/drift_agent_project.js";
import { driftAgentProvenance } from "../../src/tools/multiagent/drift_agent_provenance.js";
import { driftAgentTrust } from "../../src/tools/multiagent/drift_agent_trust.js";

function createMockClient(): CortexClient {
  return {
    registerAgent: vi.fn(async (name: string, capabilities: string[]) => ({
      agent_id: { "0": "agent-uuid-123" },
      name,
      namespace: `agent://${name}/`,
      capabilities,
      parent_agent: null,
      registered_at: "2026-01-15T10:00:00Z",
      last_active: "2026-01-15T10:00:00Z",
      status: { state: "active" },
    })),
    deregisterAgent: vi.fn(),
    getAgent: vi.fn(),
    listAgents: vi.fn(async () => []),
    createNamespace: vi.fn(async () => "team://backend/"),
    shareMemory: vi.fn(async () => ({
      agent_id: { "0": "agent-1" },
      action: "shared_to",
      timestamp: "2026-01-15T11:00:00Z",
      confidence_delta: 0.0,
    })),
    createProjection: vi.fn(async () => "proj-uuid-456"),
    retractMemory: vi.fn(),
    getProvenance: vi.fn(async (memoryId: string) => ({
      memory_id: memoryId,
      origin: { type: "human" },
      chain: [
        {
          agent_id: { "0": "agent-alpha" },
          action: "created",
          timestamp: "2026-01-15T10:00:00Z",
          confidence_delta: 0.0,
        },
        {
          agent_id: { "0": "agent-alpha" },
          action: "shared_to",
          timestamp: "2026-01-15T11:00:00Z",
          confidence_delta: 0.0,
        },
      ],
      chain_confidence: 0.95,
    })),
    traceCrossAgent: vi.fn(async () => ({
      path: [
        { agent_id: "agent-alpha", memory_id: "mem-1", confidence: 0.9 },
        { agent_id: "agent-beta", memory_id: "mem-2", confidence: 0.85 },
      ],
    })),
    getTrust: vi.fn(async () => ({
      agent_id: { "0": "agent-alpha" },
      target_agent: { "0": "agent-beta" },
      overall_trust: 0.85,
      domain_trust: { code_review: 0.9, testing: 0.8 },
      evidence: {
        validated_count: 5,
        contradicted_count: 1,
        useful_count: 3,
        total_received: 10,
      },
      last_updated: "2026-01-15T10:00:00Z",
    })),
    syncAgents: vi.fn(),
  } as unknown as CortexClient;
}

describe("Multi-Agent MCP Tools", () => {
  let client: CortexClient;

  beforeEach(() => {
    client = createMockClient();
  });

  // ─── TMD3-MCP-01: drift_agent_register ─────────────────────────────────

  describe("drift_agent_register", () => {
    it("should register an agent and return registration (TMD3-MCP-01)", async () => {
      const tool = driftAgentRegister(client);
      expect(tool.name).toBe("drift_agent_register");

      const result = (await tool.handler({
        name: "code-reviewer",
        capabilities: ["code_review", "testing"],
      })) as { agent: { name: string; capabilities: string[]; namespace: string } };

      expect(result.agent.name).toBe("code-reviewer");
      expect(result.agent.capabilities).toEqual(["code_review", "testing"]);
      expect(result.agent.namespace).toBe("agent://code-reviewer/");
      expect(client.registerAgent).toHaveBeenCalledWith("code-reviewer", [
        "code_review",
        "testing",
      ]);
    });

    it("should reject empty agent name", async () => {
      const tool = driftAgentRegister(client);
      await expect(tool.handler({ name: "" })).rejects.toThrow(
        "Agent name is required and cannot be empty",
      );
    });

    it("should reject empty capability strings", async () => {
      const tool = driftAgentRegister(client);
      await expect(
        tool.handler({ name: "test", capabilities: ["valid", ""] }),
      ).rejects.toThrow("Each capability must be a non-empty string");
    });

    it("should default capabilities to empty array", async () => {
      const tool = driftAgentRegister(client);
      await tool.handler({ name: "minimal-agent" });
      expect(client.registerAgent).toHaveBeenCalledWith("minimal-agent", []);
    });

    it("should have required fields in schema", () => {
      const tool = driftAgentRegister(client);
      expect(tool.inputSchema.required).toContain("name");
    });
  });

  // ─── TMD3-MCP-02: drift_agent_share ────────────────────────────────────

  describe("drift_agent_share", () => {
    it("should share a memory and return provenance hop (TMD3-MCP-02)", async () => {
      const tool = driftAgentShare(client);
      expect(tool.name).toBe("drift_agent_share");

      const result = (await tool.handler({
        memory_id: "mem-1",
        target_namespace: "team://backend/",
        agent_id: "agent-1",
      })) as { success: boolean; provenance_hop: { action: string } };

      expect(result.success).toBe(true);
      expect(result.provenance_hop.action).toBe("shared_to");
      expect(client.shareMemory).toHaveBeenCalledWith("mem-1", "team://backend/", "agent-1");
    });

    it("should reject empty memory_id", async () => {
      const tool = driftAgentShare(client);
      await expect(
        tool.handler({ memory_id: "", target_namespace: "team://x/", agent_id: "a" }),
      ).rejects.toThrow("memory_id is required");
    });

    it("should reject invalid namespace URI", async () => {
      const tool = driftAgentShare(client);
      await expect(
        tool.handler({ memory_id: "m1", target_namespace: "invalid", agent_id: "a" }),
      ).rejects.toThrow("Invalid namespace URI");
    });

    it("should reject empty agent_id", async () => {
      const tool = driftAgentShare(client);
      await expect(
        tool.handler({ memory_id: "m1", target_namespace: "team://x/", agent_id: "" }),
      ).rejects.toThrow("agent_id is required");
    });

    it("should have required fields in schema", () => {
      const tool = driftAgentShare(client);
      expect(tool.inputSchema.required).toContain("memory_id");
      expect(tool.inputSchema.required).toContain("target_namespace");
      expect(tool.inputSchema.required).toContain("agent_id");
    });
  });

  // ─── drift_agent_project ───────────────────────────────────────────────

  describe("drift_agent_project", () => {
    it("should create a projection and return projection_id", async () => {
      const tool = driftAgentProject(client);
      expect(tool.name).toBe("drift_agent_project");

      const result = (await tool.handler({
        source_namespace: "agent://alpha/",
        target_namespace: "team://backend/",
        compression_level: 1,
        live: true,
      })) as { projection_id: string };

      expect(result.projection_id).toBeDefined();
      expect(typeof result.projection_id).toBe("string");
      expect(client.createProjection).toHaveBeenCalled();
    });

    it("should reject invalid source namespace", async () => {
      const tool = driftAgentProject(client);
      await expect(
        tool.handler({ source_namespace: "bad", target_namespace: "team://x/" }),
      ).rejects.toThrow("Invalid source_namespace");
    });

    it("should reject invalid target namespace", async () => {
      const tool = driftAgentProject(client);
      await expect(
        tool.handler({ source_namespace: "agent://a/", target_namespace: "bad" }),
      ).rejects.toThrow("Invalid target_namespace");
    });

    it("should reject invalid compression level", async () => {
      const tool = driftAgentProject(client);
      await expect(
        tool.handler({
          source_namespace: "agent://a/",
          target_namespace: "team://b/",
          compression_level: 5,
        }),
      ).rejects.toThrow("Invalid compression_level");
    });

    it("should default compression_level to 0 and live to false", async () => {
      const tool = driftAgentProject(client);
      await tool.handler({
        source_namespace: "agent://alpha/",
        target_namespace: "team://backend/",
      });
      const call = (client.createProjection as ReturnType<typeof vi.fn>).mock.calls[0][0];
      expect(call.compression_level).toBe(0);
      expect(call.live).toBe(false);
    });
  });

  // ─── TMD3-MCP-03: drift_agent_provenance ───────────────────────────────

  describe("drift_agent_provenance", () => {
    it("should return provenance and cross-agent trace (TMD3-MCP-03)", async () => {
      const tool = driftAgentProvenance(client);
      expect(tool.name).toBe("drift_agent_provenance");

      const result = (await tool.handler({
        memory_id: "mem-1",
        max_depth: 5,
      })) as {
        provenance: { memory_id: string; chain: unknown[]; chain_confidence: number };
        cross_agent_trace: { path: unknown[] };
      };

      expect(result.provenance.memory_id).toBe("mem-1");
      expect(result.provenance.chain.length).toBe(2);
      expect(result.provenance.chain_confidence).toBe(0.95);
      expect(result.cross_agent_trace).toBeDefined();
      expect(result.cross_agent_trace.path.length).toBe(2);
      expect(client.getProvenance).toHaveBeenCalledWith("mem-1");
      expect(client.traceCrossAgent).toHaveBeenCalledWith("mem-1", 5);
    });

    it("should reject empty memory_id", async () => {
      const tool = driftAgentProvenance(client);
      await expect(tool.handler({ memory_id: "" })).rejects.toThrow("memory_id is required");
    });

    it("should reject invalid max_depth", async () => {
      const tool = driftAgentProvenance(client);
      await expect(tool.handler({ memory_id: "m1", max_depth: 0 })).rejects.toThrow(
        "Invalid max_depth",
      );
    });

    it("should default max_depth to 10", async () => {
      const tool = driftAgentProvenance(client);
      await tool.handler({ memory_id: "mem-1" });
      expect(client.traceCrossAgent).toHaveBeenCalledWith("mem-1", 10);
    });

    it("should omit cross_agent_trace when path is empty", async () => {
      (client.traceCrossAgent as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ path: [] });
      const tool = driftAgentProvenance(client);
      const result = (await tool.handler({ memory_id: "mem-1" })) as {
        provenance: unknown;
        cross_agent_trace?: unknown;
      };
      expect(result.cross_agent_trace).toBeUndefined();
    });

    it("should throw when no provenance found", async () => {
      (client.getProvenance as ReturnType<typeof vi.fn>).mockResolvedValueOnce(null);
      const tool = driftAgentProvenance(client);
      await expect(tool.handler({ memory_id: "nonexistent" })).rejects.toThrow(
        "No provenance found",
      );
    });
  });

  // ─── TMD3-MCP-04: drift_agent_trust ────────────────────────────────────

  describe("drift_agent_trust", () => {
    it("should return trust scores (TMD3-MCP-04)", async () => {
      const tool = driftAgentTrust(client);
      expect(tool.name).toBe("drift_agent_trust");

      const result = (await tool.handler({
        agent_id: "agent-alpha",
        target_agent: "agent-beta",
      })) as {
        trust: {
          overall_trust: number;
          domain_trust: Record<string, number>;
          evidence: { validated_count: number };
        };
      };

      expect(result.trust.overall_trust).toBe(0.85);
      expect(result.trust.domain_trust.code_review).toBe(0.9);
      expect(result.trust.evidence.validated_count).toBe(5);
      expect(client.getTrust).toHaveBeenCalledWith("agent-alpha", "agent-beta");
    });

    it("should query without target_agent", async () => {
      const tool = driftAgentTrust(client);
      await tool.handler({ agent_id: "agent-alpha" });
      expect(client.getTrust).toHaveBeenCalledWith("agent-alpha", undefined);
    });

    it("should reject empty agent_id", async () => {
      const tool = driftAgentTrust(client);
      await expect(tool.handler({ agent_id: "" })).rejects.toThrow("agent_id is required");
    });

    it("should have required fields in schema", () => {
      const tool = driftAgentTrust(client);
      expect(tool.inputSchema.required).toContain("agent_id");
    });
  });

  // ─── Tool Registration ─────────────────────────────────────────────────

  describe("Tool definitions", () => {
    it("all 5 tools have name, description, inputSchema, and handler", () => {
      const factories = [
        driftAgentRegister,
        driftAgentShare,
        driftAgentProject,
        driftAgentProvenance,
        driftAgentTrust,
      ];

      for (const factory of factories) {
        const tool = factory(client);
        expect(tool.name).toBeTruthy();
        expect(tool.description).toBeTruthy();
        expect(tool.inputSchema).toBeDefined();
        expect(tool.inputSchema.type).toBe("object");
        expect(typeof tool.handler).toBe("function");
      }
    });

    it("all tool names follow drift_agent_ prefix convention", () => {
      const factories = [
        driftAgentRegister,
        driftAgentShare,
        driftAgentProject,
        driftAgentProvenance,
        driftAgentTrust,
      ];

      for (const factory of factories) {
        const tool = factory(client);
        expect(tool.name).toMatch(/^drift_agent_/);
      }
    });
  });
});
