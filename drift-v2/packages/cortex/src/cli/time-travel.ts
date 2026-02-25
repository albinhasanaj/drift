/**
 * time-travel — Point-in-time knowledge query.
 */

import type { CortexClient } from "../bridge/client.js";

export async function timeTravelCommand(
  client: CortexClient,
  systemTime: string,
  validTime: string,
  filter?: string,
): Promise<void> {
  const memories = await client.queryAsOf(systemTime, validTime, filter);
  console.log(JSON.stringify({ memories, count: memories.length }, null, 2));
}
