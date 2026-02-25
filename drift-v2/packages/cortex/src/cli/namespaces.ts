/**
 * drift cortex namespaces — Manage memory namespaces.
 *
 * Subcommands:
 *   list         List all namespaces
 *   create       Create a new namespace
 *   permissions  Show namespace permissions
 *
 * Options:
 *   --scope <scope>    Filter by scope (agent/team/project)
 *   --agent <agent>    Filter by agent
 *   --format <format>  Output format (table/json), default: table
 */

import type { CortexClient } from "../bridge/client.js";

interface NamespaceInfo {
  uri: string;
  scope: string;
  name: string;
  owner: string;
}

function printNamespaceTable(namespaces: NamespaceInfo[]): void {
  if (namespaces.length === 0) {
    console.log("\n  No namespaces found.\n");
    return;
  }

  const header = { uri: "NAMESPACE URI", scope: "SCOPE", name: "NAME", owner: "OWNER" };
  const rows = namespaces;

  const colW = {
    uri: Math.max(header.uri.length, ...rows.map((r) => r.uri.length)),
    scope: Math.max(header.scope.length, ...rows.map((r) => r.scope.length)),
    name: Math.max(header.name.length, ...rows.map((r) => r.name.length)),
    owner: Math.max(header.owner.length, ...rows.map((r) => r.owner.length)),
  };

  const pad = (s: string, w: number) => s.padEnd(w);
  const line = `  ${pad(header.uri, colW.uri)}  ${pad(header.scope, colW.scope)}  ${pad(header.name, colW.name)}  ${pad(header.owner, colW.owner)}`;
  const sep = "  " + "─".repeat(line.length - 2);

  console.log();
  console.log(line);
  console.log(sep);
  for (const r of rows) {
    console.log(`  ${pad(r.uri, colW.uri)}  ${pad(r.scope, colW.scope)}  ${pad(r.name, colW.name)}  ${pad(r.owner, colW.owner)}`);
  }
  console.log();
}

export async function namespacesCommand(
  client: CortexClient,
  subcommand: string,
  positional: string[],
  flags: Record<string, string>,
): Promise<void> {
  const format = flags.format ?? "table";

  switch (subcommand) {
    case "list": {
      // List agents and derive namespaces from their registrations
      const agents = await client.listAgents();
      let namespaces: NamespaceInfo[] = agents.map((a) => ({
        uri: a.namespace,
        scope: "agent",
        name: a.name,
        owner: a.agent_id[0],
      }));

      // Apply scope filter
      if (flags.scope) {
        namespaces = namespaces.filter((ns) => ns.scope === flags.scope);
      }
      // Apply agent filter
      if (flags.agent) {
        namespaces = namespaces.filter((ns) => ns.owner === flags.agent);
      }

      if (format === "json") {
        console.log(JSON.stringify(namespaces, null, 2));
      } else {
        printNamespaceTable(namespaces);
      }
      break;
    }

    case "create": {
      const scope = positional[0] ?? flags.scope;
      const name = positional[1] ?? flags.name;
      const owner = flags.agent ?? flags.owner ?? "";

      if (!scope || !name) {
        console.error("  Error: create requires a scope and name.");
        console.error("  Usage: drift cortex namespaces create <scope> <name> [--agent <owner>]");
        console.error("  Scopes: agent, team, project");
        process.exit(1);
      }

      if (!["agent", "team", "project"].includes(scope)) {
        console.error(`  Error: invalid scope '${scope}'. Must be agent, team, or project.`);
        process.exit(1);
      }

      const uri = await client.createNamespace(scope, name, owner);
      if (format === "json") {
        console.log(JSON.stringify({ namespace_uri: uri, scope, name, owner }, null, 2));
      } else {
        console.log(`\n  Namespace created: ${uri}\n`);
      }
      break;
    }

    case "permissions": {
      const namespaceUri = positional[0];
      if (!namespaceUri) {
        console.error("  Error: permissions requires a namespace URI.");
        console.error("  Usage: drift cortex namespaces permissions <namespace-uri>");
        process.exit(1);
      }

      // Show namespace info — permissions are managed through the bridge
      console.log(`\n  Namespace: ${namespaceUri}`);
      console.log(`  ─────────────────────────────────────`);
      console.log(`  Permissions are managed through the multi-agent engine.`);
      console.log(`  Default permissions by scope:`);
      console.log(`    agent://   → Owner: all permissions`);
      console.log(`    team://    → Members: read + write`);
      console.log(`    project:// → All agents: read`);
      console.log();
      break;
    }

    default:
      console.error(`  Unknown subcommand: ${subcommand}`);
      console.error("  Available: list, create, permissions");
      process.exit(1);
  }
}
