/**
 * drift cortex learn — Trigger learning from corrections.
 */

import type { CortexClient } from "../bridge/client.js";

export async function learnCommand(
  client: CortexClient,
  correctionText: string,
  context: string,
  source?: string,
): Promise<void> {
  const result = await client.learn(correctionText, context, source ?? "cli");

  console.log(`\n  Learning Result:`);
  console.log(`  ─────────────────────────────────────`);
  console.log(`  Category:  ${result.category}`);
  console.log(`  Principle: ${result.principle ?? "(none extracted)"}`);
  console.log(`  Memory:    ${result.memory_created ?? "(no memory created)"}`);
  console.log();
}
