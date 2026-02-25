/**
 * drift cortex gc — Run compaction.
 */

import type { CortexClient } from "../bridge/client.js";

export async function gcCommand(client: CortexClient): Promise<void> {
  console.log(`\n  Running garbage collection...`);

  const sessionsRemoved = await client.sessionCleanup();

  // Archive memories below archival threshold
  const archivalCandidates = await client.getValidationCandidates(0.0, 0.15);
  let archived = 0;
  for (const memory of archivalCandidates) {
    if (!memory.archived) {
      await client.memoryArchive(memory.id);
      archived++;
    }
  }

  console.log(`  ─────────────────────────────────────`);
  console.log(`  Sessions removed: ${sessionsRemoved}`);
  console.log(`  Memories archived: ${archived}`);
  console.log(`  Status: compaction complete`);
  console.log();
}
