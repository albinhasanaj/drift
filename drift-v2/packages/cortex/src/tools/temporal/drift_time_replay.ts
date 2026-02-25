/**
 * drift_time_replay — Replay decision context with hindsight analysis.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { DecisionReplay, McpToolDefinition } from "../../bridge/types.js";

function summarizeReplay(replay: DecisionReplay): string {
  const parts: string[] = [];
  parts.push(`Decision: "${replay.decision.summary}"`);
  parts.push(`Available context at decision time: ${replay.available_context.length} memories`);
  parts.push(`Retrieved context: ${replay.retrieved_context.length} memories`);
  parts.push(
    `Causal graph: ${replay.causal_state.nodes.length} nodes, ${replay.causal_state.edges.length} edges`,
  );

  if (replay.hindsight.length > 0) {
    const contradicts = replay.hindsight.filter((h) => h.relationship === "contradicts").length;
    const informs = replay.hindsight.filter(
      (h) => h.relationship === "would_have_informed",
    ).length;
    const supersedes = replay.hindsight.filter((h) => h.relationship === "supersedes").length;
    const supports = replay.hindsight.filter((h) => h.relationship === "supports").length;

    const hindsightParts: string[] = [];
    if (contradicts > 0) hindsightParts.push(`${contradicts} contradicting`);
    if (informs > 0) hindsightParts.push(`${informs} would-have-informed`);
    if (supersedes > 0) hindsightParts.push(`${supersedes} superseding`);
    if (supports > 0) hindsightParts.push(`${supports} supporting`);

    parts.push(`Hindsight: ${replay.hindsight.length} items (${hindsightParts.join(", ")})`);
  } else {
    parts.push("No hindsight items — decision context appears complete.");
  }

  return parts.join(". ") + ".";
}

export function driftTimeReplay(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_time_replay",
    description:
      "Replay a decision's context as it was at decision time, with hindsight " +
      "analysis showing what we know now that we didn't know then.",
    inputSchema: {
      type: "object",
      properties: {
        decision_memory_id: {
          type: "string",
          description: "UUID of the decision memory to replay.",
        },
        budget: {
          type: "number",
          description: "Token budget for retrieval simulation (default: 2000).",
        },
      },
      required: ["decision_memory_id"],
    },
    handler: async (args) => {
      const replay = await client.replayDecision(
        args.decision_memory_id as string,
        (args.budget as number) ?? 2000,
      );
      return {
        replay,
        hindsight_summary: summarizeReplay(replay),
      };
    },
  };
}
