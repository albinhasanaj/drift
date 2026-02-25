/**
 * drift cortex status — Health dashboard.
 */

import type { CortexClient } from "../bridge/client.js";

export async function statusCommand(client: CortexClient): Promise<void> {
  const [health, consolidation, degradations] = await Promise.all([
    client.healthReport(),
    client.consolidationStatus(),
    client.degradations(),
  ]);

  console.log(`\n  Cortex Status: ${health.overall_status.toUpperCase()}`);
  console.log(`  ─────────────────────────────────────`);
  console.log(
    `  Memories:     ${health.metrics.total_memories} total, ${health.metrics.active_memories} active, ${health.metrics.archived_memories} archived`,
  );
  console.log(`  Confidence:   ${(health.metrics.average_confidence * 100).toFixed(1)}% average`);
  console.log(
    `  Cache:        ${(health.metrics.embedding_cache_hit_rate * 100).toFixed(1)}% hit rate`,
  );
  console.log(`  Consolidation: ${consolidation.is_running ? "running" : "idle"}`);

  if (health.subsystems.length > 0) {
    console.log(`\n  Subsystems:`);
    for (const sub of health.subsystems) {
      const icon = sub.status === "healthy" ? "✓" : sub.status === "degraded" ? "⚠" : "✗";
      console.log(
        `    ${icon} ${sub.name}: ${sub.status}${sub.message ? ` — ${sub.message}` : ""}`,
      );
    }
  }

  if (degradations.length > 0) {
    console.log(`\n  Degradations (${degradations.length}):`);
    for (const d of degradations) {
      console.log(`    ⚠ ${d.component}: ${d.failure} → ${d.fallback_used}`);
    }
  }

  console.log();
}
