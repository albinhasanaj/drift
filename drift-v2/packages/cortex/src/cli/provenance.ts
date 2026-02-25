/**
 * drift cortex provenance <memory-id> — Show provenance chain for a memory.
 *
 * Options:
 *   --depth <depth>    Max traversal depth, default: 10
 *   --format <format>  Output format (text/json), default: text
 *
 * Text output renders a tree-style provenance chain with Unicode box-drawing characters.
 */

import type { CortexClient } from "../bridge/client.js";
import type { ProvenanceRecord, CrossAgentTrace } from "../bridge/types.js";

function formatAction(action: string): string {
  switch (action) {
    case "created":
      return "Created by";
    case "shared_to":
      return "Shared to";
    case "projected_to":
      return "Projected to";
    case "merged_with":
      return "Merged with";
    case "consolidated_from":
      return "Consolidated from";
    case "validated_by":
      return "Validated by";
    case "used_in_decision":
      return "Used in decision by";
    case "corrected_by":
      return "Corrected by";
    case "reclassified_from":
      return "Reclassified from";
    default:
      return action;
  }
}

function formatOrigin(origin: { type: string }): string {
  switch (origin.type) {
    case "human":
      return "Human";
    case "agent_created":
      return "Agent-Created";
    case "derived":
      return "Derived";
    case "imported":
      return "Imported";
    case "projected":
      return "Projected";
    default:
      return origin.type;
  }
}

function formatConfidenceDelta(delta: number): string {
  if (delta === 0) return "";
  const sign = delta > 0 ? "+" : "";
  return ` [confidence ${sign}${delta.toFixed(2)}]`;
}

function printProvenanceText(
  memoryId: string,
  provenance: ProvenanceRecord,
  crossAgentTrace: CrossAgentTrace | null,
): void {
  console.log(`\n  Memory ${memoryId} — Provenance Chain`);

  const chain = provenance.chain;
  for (let i = 0; i < chain.length; i++) {
    const hop = chain[i];
    const isLast = i === chain.length - 1 && !crossAgentTrace;
    const prefix = isLast ? "└─" : "├─";
    const agentLabel = hop.agent_id[0];
    const originLabel = i === 0 ? ` (${formatOrigin(provenance.origin)})` : "";
    const deltaLabel = formatConfidenceDelta(hop.confidence_delta);

    console.log(
      `  ${prefix} ${formatAction(hop.action)} ${agentLabel}${originLabel} at ${hop.timestamp}${deltaLabel}`,
    );
  }

  if (crossAgentTrace && crossAgentTrace.path.length > 0) {
    console.log(`  │`);
    console.log(`  Cross-Agent Trace:`);
    for (let i = 0; i < crossAgentTrace.path.length; i++) {
      const hop = crossAgentTrace.path[i];
      const isLast = i === crossAgentTrace.path.length - 1;
      const prefix = isLast ? "└─" : "├─";
      console.log(
        `  ${prefix} Agent ${hop.agent_id} → Memory ${hop.memory_id} (confidence: ${hop.confidence.toFixed(2)})`,
      );
    }
  }

  console.log(`  Chain confidence: ${provenance.chain_confidence.toFixed(2)}`);
  console.log();
}

export async function provenanceCommand(
  client: CortexClient,
  memoryId: string,
  flags: Record<string, string>,
): Promise<void> {
  if (!memoryId || memoryId.trim().length === 0) {
    console.error("  Error: provenance requires a memory-id argument.");
    console.error("  Usage: drift cortex provenance <memory-id> [--depth <n>] [--format text|json]");
    process.exit(1);
  }

  const maxDepth = flags.depth ? parseInt(flags.depth, 10) : 10;
  const format = flags.format ?? "text";

  if (maxDepth <= 0 || isNaN(maxDepth)) {
    console.error("  Error: --depth must be a positive integer.");
    process.exit(1);
  }

  const [provenance, crossAgentTrace] = await Promise.all([
    client.getProvenance(memoryId),
    client.traceCrossAgent(memoryId, maxDepth),
  ]);

  if (!provenance) {
    console.error(
      `  No provenance found for memory '${memoryId}'. ` +
        "The memory may not exist or may not have provenance tracking.",
    );
    process.exit(1);
  }

  const trace = crossAgentTrace.path.length > 0 ? crossAgentTrace : null;

  if (format === "json") {
    const output: Record<string, unknown> = { provenance };
    if (trace) {
      output.cross_agent_trace = trace;
    }
    console.log(JSON.stringify(output, null, 2));
  } else {
    printProvenanceText(memoryId, provenance, trace);
  }
}
