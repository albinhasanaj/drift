/**
 * restore — Restore an archived memory.
 */

import type { CortexClient } from "../bridge/client.js";

export async function restoreCommand(
  client: CortexClient,
  memoryId: string,
): Promise<void> {
  await client.memoryRestore(memoryId);
  console.log(JSON.stringify({ id: memoryId, status: "restored" }));
}
