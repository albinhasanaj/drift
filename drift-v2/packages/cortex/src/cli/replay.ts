/**
 * drift cortex replay <decision-id> — Replay decision context with hindsight.
 */

import type { CortexClient } from "../bridge/client.js";

export async function replayCommand(
  client: CortexClient,
  decisionId: string,
  budget?: number,
): Promise<void> {
  const replay = await client.replayDecision(decisionId, budget ?? 2000);

  console.log("\n  Decision Replay");
  console.log(`  Decision ID: ${decisionId}`);
  console.log(`  Summary: ${replay.decision.summary}`);
  console.log(`  Type: ${replay.decision.memory_type}`);
  console.log(`  Confidence: ${replay.decision.confidence.toFixed(2)}`);
  console.log();

  // Context at decision time
  console.log(`  Available Context: ${replay.available_context.length} memories`);
  console.log(`  Retrieved Context: ${replay.retrieved_context.length} memories`);
  console.log();

  // Causal state
  console.log("  Causal Graph at Decision Time:");
  console.log(`    Nodes: ${replay.causal_state.nodes.length}`);
  console.log(`    Edges: ${replay.causal_state.edges.length}`);
  console.log();

  // Hindsight
  if (replay.hindsight.length > 0) {
    console.log(`  Hindsight (${replay.hindsight.length} items):`);
    for (const item of replay.hindsight) {
      const rel = item.relationship.replace(/_/g, " ");
      console.log(
        `    [${rel}] ${item.memory.summary.slice(0, 80)} (relevance: ${item.relevance.toFixed(2)})`,
      );
    }
  } else {
    console.log("  No hindsight items — decision context appears complete.");
  }

  console.log();
}
