/**
 * predict — Predict needed memories for current task.
 */

import type { CortexClient } from "../bridge/client.js";

export async function predictCommand(
  client: CortexClient,
  activeFiles?: string[],
  recentQueries?: string[],
  intent?: string,
): Promise<void> {
  const result = await client.predict(activeFiles, recentQueries, intent);
  console.log(JSON.stringify(result, null, 2));
}
