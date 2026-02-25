/**
 * drift cortex consolidate — Manual consolidation trigger.
 */

import type { CortexClient } from "../bridge/client.js";
import type { MemoryType } from "../bridge/types.js";

export async function consolidateCommand(client: CortexClient, memoryType?: string): Promise<void> {
  console.log(`\n  Running consolidation${memoryType ? ` for ${memoryType}` : ""}...`);

  const result = await client.consolidate(memoryType as MemoryType | undefined);

  console.log(`  ─────────────────────────────────────`);
  console.log(`  Created:    ${result.created.length} consolidated memories`);
  console.log(`  Archived:   ${result.archived.length} source memories`);
  console.log(`  Precision:  ${(result.metrics.precision * 100).toFixed(1)}%`);
  console.log(`  Compression: ${result.metrics.compression_ratio.toFixed(2)}x`);
  console.log(`  Lift:       ${result.metrics.lift.toFixed(3)}`);
  console.log(`  Stability:  ${(result.metrics.stability * 100).toFixed(1)}%`);
  console.log();
}
