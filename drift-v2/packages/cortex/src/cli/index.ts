#!/usr/bin/env node
/**
 * CLI command registration — subcommands under `drift cortex`.
 *
 * Usage:
 *   drift-cortex status
 *   drift-cortex search <query>
 *   drift-cortex why <file|pattern>
 *   drift-cortex explain <memory-id>
 *   drift-cortex add <type> --summary "..." --content '{...}'
 *   drift-cortex learn --correction "..." --context "..."
 *   drift-cortex consolidate [--type <memory_type>]
 *   drift-cortex validate
 *   drift-cortex export [--type <memory_type>]
 *   drift-cortex import <file>
 *   drift-cortex gc
 *   drift-cortex metrics
 *   drift-cortex reembed [--type <memory_type>]
 */

import { CortexClient } from "../bridge/client.js";
import { statusCommand } from "./status.js";
import { searchCommand } from "./search.js";
import { whyCommand } from "./why.js";
import { explainCommand } from "./explain.js";
import { addCommand } from "./add.js";
import { learnCommand } from "./learn.js";
import { consolidateCommand } from "./consolidate.js";
import { validateCommand } from "./validate.js";
import { exportCommand } from "./export.js";
import { importCommand } from "./import.js";
import { gcCommand } from "./gc.js";
import { metricsCommand } from "./metrics.js";
import { reembedCommand } from "./reembed.js";
import { timelineCommand } from "./timeline.js";
import { diffCommand } from "./diff.js";
import { replayCommand } from "./replay.js";
import { agentsCommand } from "./agents.js";
import { namespacesCommand } from "./namespaces.js";
import { provenanceCommand } from "./provenance.js";
import { predictCommand } from "./predict.js";
import { sanitizeCommand } from "./sanitize.js";
import { cloudCommand } from "./cloud.js";
import { sessionCommand } from "./session.js";
import { restoreCommand } from "./restore.js";
import { decayCommand } from "./decay.js";
import { timeTravelCommand } from "./time-travel.js";

interface ParsedArgs {
  command: string;
  positional: string[];
  flags: Record<string, string>;
}

function parseArgs(argv: string[]): ParsedArgs {
  const args = argv.slice(2); // skip node + script
  const command = args[0] ?? "help";
  const positional: string[] = [];
  const flags: Record<string, string> = {};

  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith("--")) {
      const key = arg.slice(2);
      const value = args[i + 1] ?? "";
      flags[key] = value;
      i++;
    } else {
      positional.push(arg);
    }
  }

  return { command, positional, flags };
}

function printHelp(): void {
  console.log(`
  drift-cortex — Cortex persistent memory CLI

  Commands:
    status                          Health dashboard
    search <query>                  Hybrid search
    why <file|pattern>              Causal narrative
    explain <memory-id>             Full memory with causal chain
    add <type> --summary --content  Create a memory
    learn --correction --context    Learn from correction
    consolidate [--type <type>]     Manual consolidation
    validate                        Run validation
    export [--type <type>]          Export as JSON
    import <file>                   Import from JSON
    gc                              Garbage collection
    metrics                         System metrics
    reembed [--type <type>]         Re-embed memories
    timeline [--from --to]          Knowledge evolution over time
    diff --from <time> --to <time>  Compare knowledge between times
    replay <decision-id>            Replay decision context
    agents <sub> [opts]             Manage agents (list/register/deregister/info)
    namespaces <sub> [opts]         Manage namespaces (list/create/permissions)
    provenance <memory-id> [opts]   Show provenance chain
    predict [--files --intent]      Predict needed memories
    sanitize <text>                 Redact sensitive data
    cloud <sub>                     Cloud sync (sync/status/resolve)
    session <sub> [opts]            Session management (create/get/analytics/cleanup)
    restore <memory-id>             Restore archived memory
    decay                           Run confidence decay
    time-travel --system-time --valid-time  Point-in-time query
    help                            Show this help
`);
}

async function main(): Promise<void> {
  const { command, positional, flags } = parseArgs(process.argv);

  if (command === "help" || command === "--help" || command === "-h") {
    printHelp();
    return;
  }

  // Initialize client
  const client = await CortexClient.initialize({
    dbPath: flags.db ?? null,
    configToml: flags.config ?? null,
    cloudEnabled: flags.cloud === "true",
  });

  try {
    switch (command) {
      case "status":
        await statusCommand(client);
        break;
      case "search":
        if (!positional[0]) {
          console.error("  Error: search requires a query argument.");
          process.exit(1);
        }
        await searchCommand(client, positional[0], flags.limit ? parseInt(flags.limit) : undefined);
        break;
      case "why":
        if (!positional[0]) {
          console.error("  Error: why requires a file or pattern argument.");
          process.exit(1);
        }
        await whyCommand(client, positional[0]);
        break;
      case "explain":
        if (!positional[0]) {
          console.error("  Error: explain requires a memory-id argument.");
          process.exit(1);
        }
        await explainCommand(client, positional[0]);
        break;
      case "add":
        if (!positional[0] || !flags.summary || !flags.content) {
          console.error("  Error: add requires <type> --summary <text> --content <json>");
          process.exit(1);
        }
        await addCommand(
          client,
          positional[0],
          flags.summary,
          flags.content,
          flags.tags?.split(","),
        );
        break;
      case "learn":
        if (!flags.correction || !flags.context) {
          console.error("  Error: learn requires --correction <text> --context <text>");
          process.exit(1);
        }
        await learnCommand(client, flags.correction, flags.context, flags.source);
        break;
      case "consolidate":
        await consolidateCommand(client, flags.type);
        break;
      case "validate":
        await validateCommand(client);
        break;
      case "export":
        await exportCommand(client, flags.type);
        break;
      case "import":
        if (!positional[0]) {
          console.error("  Error: import requires a file path argument.");
          process.exit(1);
        }
        await importCommand(client, positional[0]);
        break;
      case "gc":
        await gcCommand(client);
        break;
      case "metrics":
        await metricsCommand(client);
        break;
      case "reembed":
        await reembedCommand(client, flags.type);
        break;
      case "timeline":
        await timelineCommand(client, flags.from, flags.to, flags.type, flags.module);
        break;
      case "diff":
        if (!flags.from || !flags.to) {
          console.error("  Error: diff requires --from <time> --to <time>");
          process.exit(1);
        }
        await diffCommand(client, flags.from, flags.to, flags.scope);
        break;
      case "replay":
        if (!positional[0]) {
          console.error("  Error: replay requires a decision-id argument.");
          process.exit(1);
        }
        await replayCommand(
          client,
          positional[0],
          flags.budget ? parseInt(flags.budget) : undefined,
        );
        break;
      case "agents":
        if (!positional[0]) {
          console.error("  Error: agents requires a subcommand (list/register/deregister/info).");
          process.exit(1);
        }
        await agentsCommand(client, positional[0], positional.slice(1), flags);
        break;
      case "namespaces":
        if (!positional[0]) {
          console.error("  Error: namespaces requires a subcommand (list/create/permissions).");
          process.exit(1);
        }
        await namespacesCommand(client, positional[0], positional.slice(1), flags);
        break;
      case "provenance":
        if (!positional[0]) {
          console.error("  Error: provenance requires a memory-id argument.");
          process.exit(1);
        }
        await provenanceCommand(client, positional[0], flags);
        break;
      case "predict":
        await predictCommand(
          client,
          flags.files?.split(","),
          flags.queries?.split(","),
          flags.intent,
        );
        break;
      case "sanitize":
        if (!positional[0]) {
          console.error("  Error: sanitize requires a text argument.");
          process.exit(1);
        }
        await sanitizeCommand(client, positional[0]);
        break;
      case "cloud":
        if (!positional[0]) {
          console.error("  Error: cloud requires a subcommand (sync/status/resolve).");
          process.exit(1);
        }
        await cloudCommand(client, positional[0], flags);
        break;
      case "session":
        if (!positional[0]) {
          console.error("  Error: session requires a subcommand (create/get/analytics/cleanup).");
          process.exit(1);
        }
        await sessionCommand(client, positional[0], positional.slice(1), flags);
        break;
      case "restore":
        if (!positional[0]) {
          console.error("  Error: restore requires a memory-id argument.");
          process.exit(1);
        }
        await restoreCommand(client, positional[0]);
        break;
      case "decay":
        await decayCommand(client);
        break;
      case "time-travel":
        if (!flags["system-time"] || !flags["valid-time"]) {
          console.error("  Error: time-travel requires --system-time <iso> --valid-time <iso>");
          process.exit(1);
        }
        await timeTravelCommand(client, flags["system-time"], flags["valid-time"], flags.filter);
        break;
      default:
        console.error(`  Unknown command: ${command}`);
        printHelp();
        process.exit(1);
    }
  } finally {
    await client.shutdown();
  }
}

main().catch((err) => {
  console.error(`  Fatal: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
