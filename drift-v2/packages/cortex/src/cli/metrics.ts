/**
 * drift cortex metrics — Consolidation quality metrics.
 */

import type { CortexClient } from "../bridge/client.js";

export async function metricsCommand(client: CortexClient): Promise<void> {
  const [consolidation, cache] = await Promise.all([
    client.consolidationMetrics(),
    client.cacheStats(),
  ]);

  console.log(`\n  Cortex Metrics`);
  console.log(`  ─────────────────────────────────────`);
  console.log(`  Consolidation:`);
  console.log(`    Total runs:     ${consolidation.total_runs}`);
  console.log(`    Successful:     ${consolidation.successful_runs}`);
  console.log(`    Success rate:   ${(consolidation.success_rate * 100).toFixed(1)}%`);
  console.log(`    Running:        ${consolidation.is_running ? "yes" : "no"}`);
  console.log(`\n  Prediction Cache:`);
  console.log(`    Entries:  ${cache.entry_count}`);
  console.log(`    Hits:     ${cache.hits}`);
  console.log(`    Misses:   ${cache.misses}`);
  console.log(`    Hit rate: ${(cache.hit_rate * 100).toFixed(1)}%`);
  console.log();
}
