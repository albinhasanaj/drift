/**
 * drift cortex validate — Run validation across all memories.
 */

import type { CortexClient } from "../bridge/client.js";

export async function validateCommand(client: CortexClient): Promise<void> {
  console.log(`\n  Running validation...`);

  const candidates = await client.getValidationCandidates(0.0, 1.0);

  console.log(`  ─────────────────────────────────────`);
  console.log(`  Total checked: ${candidates.length}`);

  if (candidates.length === 0) {
    console.log(`  All memories are healthy.\n`);
    return;
  }

  const lowConfidence = candidates.filter((m) => m.confidence < 0.3);
  const medConfidence = candidates.filter((m) => m.confidence >= 0.3 && m.confidence < 0.5);

  console.log(`  Low confidence (<30%):  ${lowConfidence.length}`);
  console.log(`  Med confidence (30-50%): ${medConfidence.length}`);

  if (lowConfidence.length > 0) {
    console.log(`\n  Low confidence memories:`);
    for (const m of lowConfidence.slice(0, 10)) {
      console.log(`    ${m.id} (${(m.confidence * 100).toFixed(0)}%) ${m.summary}`);
    }
  }

  console.log();
}
