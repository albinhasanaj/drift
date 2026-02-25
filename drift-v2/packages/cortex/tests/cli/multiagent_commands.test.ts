/**
 * Multi-agent CLI command tests — agents, namespaces, provenance.
 *
 * Tests that each CLI command calls the correct client methods and produces
 * formatted output. Covers TMD3-CLI-01 through TMD3-CLI-03.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { CortexClient } from "../../src/bridge/client.js";
import type {
  AgentRegistration,
  ProvenanceRecord,
  CrossAgentTrace,
} from "../../src/bridge/types.js";
import { agentsCommand } from "../../src/cli/agents.js";
import { namespacesCommand } from "../../src/cli/namespaces.js";
import { provenanceCommand } from "../../src/cli/provenance.js";

const MOCK_AGENT: AgentRegistration = {
  agent_id: { 0: "a1b2c3d4-e5f6-7890-abcd-ef1234567890" },
  name: "code-reviewer",
  namespace: "agent://code-reviewer/",
  capabilities: ["code_review", "testing"],
  parent_agent: null,
  registered_at: "2026-01-15T10:00:00Z",
  last_active: "2026-01-15T12:00:00Z",
  status: { state: "active" },
};

const MOCK_AGENT_2: AgentRegistration = {
  agent_id: { 0: "b2c3d4e5-f6a7-8901-bcde-f12345678901" },
  name: "test-runner",
  namespace: "agent://test-runner/",
  capabilities: ["testing"],
  parent_agent: { 0: "a1b2c3d4-e5f6-7890-abcd-ef1234567890" },
  registered_at: "2026-01-15T11:00:00Z",
  last_active: "2026-01-15T11:30:00Z",
  status: { state: "idle", since: "2026-01-15T11:30:00Z" },
};

const MOCK_PROVENANCE: ProvenanceRecord = {
  memory_id: "mem-001",
  origin: { type: "human" },
  chain: [
    {
      agent_id: { 0: "agent-alpha" },
      action: "created",
      timestamp: "2026-01-15T10:00:00Z",
      confidence_delta: 0.0,
    },
    {
      agent_id: { 0: "agent-alpha" },
      action: "shared_to",
      timestamp: "2026-01-15T11:00:00Z",
      confidence_delta: 0.0,
    },
    {
      agent_id: { 0: "agent-beta" },
      action: "validated_by",
      timestamp: "2026-01-16T09:00:00Z",
      confidence_delta: 0.1,
    },
    {
      agent_id: { 0: "agent-gamma" },
      action: "used_in_decision",
      timestamp: "2026-01-17T14:00:00Z",
      confidence_delta: 0.05,
    },
  ],
  chain_confidence: 0.95,
};

const MOCK_CROSS_AGENT_TRACE: CrossAgentTrace = {
  path: [
    { agent_id: "agent-alpha", memory_id: "mem-001", confidence: 0.95 },
    { agent_id: "agent-beta", memory_id: "mem-002", confidence: 0.88 },
  ],
};

function createMockClient(): CortexClient {
  return {
    listAgents: vi.fn(async () => [MOCK_AGENT, MOCK_AGENT_2]),
    registerAgent: vi.fn(async () => MOCK_AGENT),
    deregisterAgent: vi.fn(async () => undefined),
    getAgent: vi.fn(async () => MOCK_AGENT),
    createNamespace: vi.fn(async () => "team://backend/"),
    getProvenance: vi.fn(async () => MOCK_PROVENANCE),
    traceCrossAgent: vi.fn(async () => MOCK_CROSS_AGENT_TRACE),
  } as unknown as CortexClient;
}

describe("Multi-Agent CLI Commands", () => {
  let client: CortexClient;
  let consoleSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    client = createMockClient();
    consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  // ─── TMD3-CLI-01: drift cortex agents ───────────────────────────────

  describe("agents command", () => {
    it("list — shows registered agents in table format", async () => {
      await agentsCommand(client, "list", [], {});
      expect(client.listAgents).toHaveBeenCalled();
      expect(consoleSpy).toHaveBeenCalled();
      // Verify table headers are present
      const output = consoleSpy.mock.calls.map((c) => c[0]).join("\n");
      expect(output).toContain("AGENT ID");
      expect(output).toContain("NAME");
      expect(output).toContain("code-reviewer");
      expect(output).toContain("test-runner");
    });

    it("list — shows agents in JSON format", async () => {
      await agentsCommand(client, "list", [], { format: "json" });
      expect(consoleSpy).toHaveBeenCalled();
      const output = consoleSpy.mock.calls[0][0] as string;
      const parsed = JSON.parse(output);
      expect(parsed).toHaveLength(2);
      expect(parsed[0].name).toBe("code-reviewer");
    });

    it("list — passes status filter", async () => {
      await agentsCommand(client, "list", [], { status: "active" });
      expect(client.listAgents).toHaveBeenCalledWith("active");
    });

    it("register — registers a new agent", async () => {
      await agentsCommand(client, "register", ["my-agent"], {
        capabilities: "code_review,testing",
      });
      expect(client.registerAgent).toHaveBeenCalledWith("my-agent", [
        "code_review",
        "testing",
      ]);
      const output = consoleSpy.mock.calls.map((c) => c[0]).join("\n");
      expect(output).toContain("Agent registered");
    });

    it("deregister — deregisters an agent", async () => {
      await agentsCommand(client, "deregister", ["agent-001"], {});
      expect(client.deregisterAgent).toHaveBeenCalledWith("agent-001");
      const output = consoleSpy.mock.calls.map((c) => c[0]).join("\n");
      expect(output).toContain("deregistered");
    });

    it("info — shows agent details", async () => {
      await agentsCommand(client, "info", ["agent-001"], {});
      expect(client.getAgent).toHaveBeenCalledWith("agent-001");
      const output = consoleSpy.mock.calls.map((c) => c[0]).join("\n");
      expect(output).toContain("code-reviewer");
      expect(output).toContain("agent://code-reviewer/");
    });

    it("info — shows agent details in JSON format", async () => {
      await agentsCommand(client, "info", ["agent-001"], { format: "json" });
      const output = consoleSpy.mock.calls[0][0] as string;
      const parsed = JSON.parse(output);
      expect(parsed.name).toBe("code-reviewer");
    });
  });

  // ─── TMD3-CLI-02: drift cortex namespaces ───────────────────────────

  describe("namespaces command", () => {
    it("list — shows namespaces in table format", async () => {
      await namespacesCommand(client, "list", [], {});
      expect(client.listAgents).toHaveBeenCalled();
      expect(consoleSpy).toHaveBeenCalled();
      const output = consoleSpy.mock.calls.map((c) => c[0]).join("\n");
      expect(output).toContain("NAMESPACE URI");
      expect(output).toContain("agent://code-reviewer/");
    });

    it("list — shows namespaces in JSON format", async () => {
      await namespacesCommand(client, "list", [], { format: "json" });
      const output = consoleSpy.mock.calls[0][0] as string;
      const parsed = JSON.parse(output);
      expect(parsed).toHaveLength(2);
    });

    it("create — creates a new namespace", async () => {
      await namespacesCommand(client, "create", ["team", "backend"], {
        agent: "agent-001",
      });
      expect(client.createNamespace).toHaveBeenCalledWith("team", "backend", "agent-001");
      const output = consoleSpy.mock.calls.map((c) => c[0]).join("\n");
      expect(output).toContain("Namespace created");
    });

    it("permissions — shows permission info", async () => {
      await namespacesCommand(client, "permissions", ["team://backend/"], {});
      const output = consoleSpy.mock.calls.map((c) => c[0]).join("\n");
      expect(output).toContain("team://backend/");
      expect(output).toContain("Default permissions");
    });
  });

  // ─── TMD3-CLI-03: drift cortex provenance ───────────────────────────

  describe("provenance command", () => {
    it("shows provenance chain in text format", async () => {
      await provenanceCommand(client, "mem-001", {});
      expect(client.getProvenance).toHaveBeenCalledWith("mem-001");
      expect(client.traceCrossAgent).toHaveBeenCalledWith("mem-001", 10);

      const output = consoleSpy.mock.calls.map((c) => c[0]).join("\n");
      expect(output).toContain("mem-001");
      expect(output).toContain("Provenance Chain");
      expect(output).toContain("Created by");
      expect(output).toContain("agent-alpha");
      expect(output).toContain("Validated by");
      expect(output).toContain("agent-beta");
      expect(output).toContain("Chain confidence: 0.95");
    });

    it("shows provenance in JSON format", async () => {
      await provenanceCommand(client, "mem-001", { format: "json" });
      const output = consoleSpy.mock.calls[0][0] as string;
      const parsed = JSON.parse(output);
      expect(parsed.provenance.memory_id).toBe("mem-001");
      expect(parsed.provenance.chain_confidence).toBe(0.95);
      expect(parsed.cross_agent_trace).toBeDefined();
    });

    it("uses custom depth", async () => {
      await provenanceCommand(client, "mem-001", { depth: "5" });
      expect(client.traceCrossAgent).toHaveBeenCalledWith("mem-001", 5);
    });

    it("shows cross-agent trace in text output", async () => {
      await provenanceCommand(client, "mem-001", {});
      const output = consoleSpy.mock.calls.map((c) => c[0]).join("\n");
      expect(output).toContain("Cross-Agent Trace");
      expect(output).toContain("agent-alpha");
      expect(output).toContain("agent-beta");
    });

    it("omits cross-agent trace when empty", async () => {
      (client.traceCrossAgent as ReturnType<typeof vi.fn>).mockResolvedValue({
        path: [],
      });
      await provenanceCommand(client, "mem-001", {});
      const output = consoleSpy.mock.calls.map((c) => c[0]).join("\n");
      expect(output).not.toContain("Cross-Agent Trace");
    });

    it("shows confidence deltas in text output", async () => {
      await provenanceCommand(client, "mem-001", {});
      const output = consoleSpy.mock.calls.map((c) => c[0]).join("\n");
      expect(output).toContain("[confidence +0.10]");
      expect(output).toContain("[confidence +0.05]");
    });
  });
});
