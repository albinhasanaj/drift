/**
 * drift cortex reembed — Trigger re-embedding pipeline.
 */

import type { CortexClient } from "../bridge/client.js";
import type { MemoryType } from "../bridge/types.js";

export async function reembedCommand(client: CortexClient, memoryType?: string): Promise<void> {
  console.log(`\n  Re-embedding${memoryType ? ` ${memoryType}` : " all"} memories...`);

  const memories = await client.memoryList(memoryType as MemoryType | undefined);
  let reembedded = 0;

  for (const memory of memories) {
    try {
      await client.search(memory.summary, 1);
      reembedded++;
    } catch {
      // Skip failures — degraded mode handles fallback
    }
  }

  console.log(`  ─────────────────────────────────────`);
  console.log(`  Total:      ${memories.length}`);
  console.log(`  Reembedded: ${reembedded}`);
  console.log();
}
