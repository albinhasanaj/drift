/**
 * decay — Run confidence decay engine.
 */

import type { CortexClient } from "../bridge/client.js";

export async function decayCommand(client: CortexClient): Promise<void> {
  const result = await client.decayRun();
  console.log(JSON.stringify(result, null, 2));
}
