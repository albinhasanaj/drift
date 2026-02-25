/**
 * drift cortex why <file|pattern> — Causal narrative.
 */

import type { CortexClient } from "../bridge/client.js";

export async function whyCommand(client: CortexClient, target: string): Promise<void> {
  // Search for memories related to the target, then get causal narrative for the top result
  const results = await client.memorySearch(target, 1);

  if (results.length === 0) {
    console.log(`\n  No memories found for "${target}".\n`);
    return;
  }

  const memory = results[0];
  const narrative = await client.causalGetWhy(memory.id);

  console.log(`\n  Why: ${memory.summary}`);
  console.log(`  ─────────────────────────────────────`);
  console.log(`  ${narrative.summary}`);
  console.log(`  Confidence: ${(narrative.confidence * 100).toFixed(1)}%`);

  if (narrative.sections.length > 0) {
    for (const section of narrative.sections) {
      console.log(`\n  ${section.title}:`);
      if (section.content) {
        console.log(`    ${section.content}`);
      }
    }
  }

  console.log();
}
