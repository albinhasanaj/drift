/**
 * drift cortex search <query> — Hybrid search with RRF.
 */

import type { CortexClient } from "../bridge/client.js";

export async function searchCommand(
  client: CortexClient,
  query: string,
  limit?: number,
): Promise<void> {
  const results = await client.search(query, limit ?? 4096);

  if (results.length === 0) {
    console.log("\n  No memories found.\n");
    return;
  }

  console.log(`\n  Found ${results.length} memories:\n`);
  for (const mem of results) {
    const score = (mem.relevance_score * 100).toFixed(1);
    console.log(`  [${score}%] ${mem.memory_id} (${mem.memory_type}, L${mem.level})`);
    console.log(`         ${mem.text.slice(0, 120)}${mem.text.length > 120 ? "…" : ""}`);
    console.log();
  }
}
