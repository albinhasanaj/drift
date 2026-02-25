/**
 * drift cortex agents — Manage registered agents.
 *
 * Subcommands:
 *   list        List all registered agents
 *   register    Register a new agent
 *   deregister  Deregister an agent
 *   info        Show agent details
 *
 * Options:
 *   --status <status>           Filter by status (active/idle/deregistered)
 *   --capabilities <caps...>    Capabilities for registration (comma-separated)
 *   --format <format>           Output format (table/json), default: table
 */

import type { CortexClient } from "../bridge/client.js";
import type { AgentRegistration } from "../bridge/types.js";

function formatStatus(status: AgentRegistration["status"]): string {
  switch (status.state) {
    case "active":
      return "active";
    case "idle":
      return `idle (since ${status.since})`;
    case "deregistered":
      return `deregistered (at ${status.at})`;
  }
}

function printAgentTable(agents: AgentRegistration[]): void {
  if (agents.length === 0) {
    console.log("\n  No agents registered.\n");
    return;
  }

  // Column headers and widths
  const header = { id: "AGENT ID", name: "NAME", status: "STATUS", caps: "CAPABILITIES", ns: "NAMESPACE" };
  const rows = agents.map((a) => ({
    id: a.agent_id[0].slice(0, 12) + "…",
    name: a.name,
    status: formatStatus(a.status),
    caps: a.capabilities.join(", ") || "(none)",
    ns: a.namespace,
  }));

  const colW = {
    id: Math.max(header.id.length, ...rows.map((r) => r.id.length)),
    name: Math.max(header.name.length, ...rows.map((r) => r.name.length)),
    status: Math.max(header.status.length, ...rows.map((r) => r.status.length)),
    caps: Math.max(header.caps.length, ...rows.map((r) => r.caps.length)),
    ns: Math.max(header.ns.length, ...rows.map((r) => r.ns.length)),
  };

  const pad = (s: string, w: number) => s.padEnd(w);
  const line = `  ${pad(header.id, colW.id)}  ${pad(header.name, colW.name)}  ${pad(header.status, colW.status)}  ${pad(header.caps, colW.caps)}  ${pad(header.ns, colW.ns)}`;
  const sep = "  " + "─".repeat(line.length - 2);

  console.log();
  console.log(line);
  console.log(sep);
  for (const r of rows) {
    console.log(`  ${pad(r.id, colW.id)}  ${pad(r.name, colW.name)}  ${pad(r.status, colW.status)}  ${pad(r.caps, colW.caps)}  ${pad(r.ns, colW.ns)}`);
  }
  console.log();
}

function printAgentJson(agents: AgentRegistration[]): void {
  console.log(JSON.stringify(agents, null, 2));
}

export async function agentsCommand(
  client: CortexClient,
  subcommand: string,
  positional: string[],
  flags: Record<string, string>,
): Promise<void> {
  const format = flags.format ?? "table";

  switch (subcommand) {
    case "list": {
      const statusFilter = flags.status ?? undefined;
      const agents = await client.listAgents(statusFilter);
      if (format === "json") {
        printAgentJson(agents);
      } else {
        printAgentTable(agents);
      }
      break;
    }

    case "register": {
      const name = positional[0];
      if (!name) {
        console.error("  Error: register requires an agent name.");
        console.error("  Usage: drift cortex agents register <name> [--capabilities cap1,cap2]");
        process.exit(1);
      }
      const capabilities = flags.capabilities ? flags.capabilities.split(",").map((c) => c.trim()) : [];
      const agent = await client.registerAgent(name, capabilities);
      if (format === "json") {
        console.log(JSON.stringify(agent, null, 2));
      } else {
        console.log(`\n  Agent registered:`);
        console.log(`    ID:           ${agent.agent_id[0]}`);
        console.log(`    Name:         ${agent.name}`);
        console.log(`    Namespace:    ${agent.namespace}`);
        console.log(`    Capabilities: ${agent.capabilities.join(", ") || "(none)"}`);
        console.log();
      }
      break;
    }

    case "deregister": {
      const agentId = positional[0];
      if (!agentId) {
        console.error("  Error: deregister requires an agent ID.");
        console.error("  Usage: drift cortex agents deregister <agent-id>");
        process.exit(1);
      }
      await client.deregisterAgent(agentId);
      console.log(`\n  Agent '${agentId}' deregistered.\n`);
      break;
    }

    case "info": {
      const agentId = positional[0];
      if (!agentId) {
        console.error("  Error: info requires an agent ID.");
        console.error("  Usage: drift cortex agents info <agent-id>");
        process.exit(1);
      }
      const agent = await client.getAgent(agentId);
      if (!agent) {
        console.error(`  Agent '${agentId}' not found. Use 'drift cortex agents list' to see registered agents.`);
        process.exit(1);
      }
      if (format === "json") {
        console.log(JSON.stringify(agent, null, 2));
      } else {
        console.log(`\n  Agent: ${agent.name}`);
        console.log(`  ─────────────────────────────────────`);
        console.log(`  ID:           ${agent.agent_id[0]}`);
        console.log(`  Namespace:    ${agent.namespace}`);
        console.log(`  Status:       ${formatStatus(agent.status)}`);
        console.log(`  Capabilities: ${agent.capabilities.join(", ") || "(none)"}`);
        console.log(`  Registered:   ${agent.registered_at}`);
        console.log(`  Last Active:  ${agent.last_active}`);
        if (agent.parent_agent) {
          console.log(`  Parent Agent: ${agent.parent_agent[0]}`);
        }
        console.log();
      }
      break;
    }

    default:
      console.error(`  Unknown subcommand: ${subcommand}`);
      console.error("  Available: list, register, deregister, info");
      process.exit(1);
  }
}
