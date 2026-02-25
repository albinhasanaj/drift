/**
 * drift cortex export — Export memories as JSON.
 */

import type { CortexClient } from "../bridge/client.js";
import type { MemoryType } from "../bridge/types.js";

export async function exportCommand(client: CortexClient, memoryType?: string): Promise<void> {
  const memories = await client.memoryList(memoryType as MemoryType | undefined);

  const output = {
    exported_at: new Date().toISOString(),
    count: memories.length,
    memories,
  };

  // Output as JSON to stdout for piping
  console.log(JSON.stringify(output, null, 2));
}
