/**
 * drift cortex diff — Compare knowledge between two time points.
 */

import type { CortexClient } from "../bridge/client.js";

export async function diffCommand(
  client: CortexClient,
  from: string,
  to: string,
  scope?: string,
): Promise<void> {
  const diff = await client.queryDiff(from, to, scope);

  console.log("\n  Temporal Diff");
  console.log(`  From: ${from}`);
  console.log(`  To:   ${to}`);
  if (scope) console.log(`  Scope: ${scope}`);
  console.log();

  // Summary counts
  console.log(`  Created:  ${diff.created.length}`);
  console.log(`  Archived: ${diff.archived.length}`);
  console.log(`  Modified: ${diff.modified.length}`);
  console.log();

  // Stats
  const s = diff.stats;
  console.log("  Stats:");
  console.log(`    Memories at A: ${s.memories_at_a}`);
  console.log(`    Memories at B: ${s.memories_at_b}`);
  console.log(`    Net change:    ${s.net_change >= 0 ? "+" : ""}${s.net_change}`);
  console.log(`    Avg conf at A: ${s.avg_confidence_at_a.toFixed(3)}`);
  console.log(`    Avg conf at B: ${s.avg_confidence_at_b.toFixed(3)}`);
  console.log(
    `    Conf trend:    ${s.confidence_trend > 0 ? "↑" : s.confidence_trend < 0 ? "↓" : "→"} ${s.confidence_trend.toFixed(3)}`,
  );
  console.log(`    Churn rate:    ${s.knowledge_churn_rate.toFixed(3)}`);
  console.log();

  // Confidence shifts
  if (diff.confidence_shifts.length > 0) {
    console.log(`  Confidence Shifts (${diff.confidence_shifts.length}):`);
    for (const cs of diff.confidence_shifts.slice(0, 10)) {
      const arrow = cs.delta > 0 ? "↑" : "↓";
      console.log(
        `    ${cs.memory_id.slice(0, 8)}… ${cs.old_confidence.toFixed(2)} → ${cs.new_confidence.toFixed(2)} (${arrow}${Math.abs(cs.delta).toFixed(2)})`,
      );
    }
    if (diff.confidence_shifts.length > 10) {
      console.log(`    … and ${diff.confidence_shifts.length - 10} more`);
    }
    console.log();
  }

  // Contradictions
  if (diff.new_contradictions.length > 0) {
    console.log(`  New Contradictions (${diff.new_contradictions.length}):`);
    for (const c of diff.new_contradictions.slice(0, 5)) {
      console.log(`    ${c.memory_a_id.slice(0, 8)}… ↔ ${c.memory_b_id.slice(0, 8)}… — ${c.description}`);
    }
    console.log();
  }

  if (diff.resolved_contradictions.length > 0) {
    console.log(`  Resolved Contradictions (${diff.resolved_contradictions.length})`);
    console.log();
  }
}
