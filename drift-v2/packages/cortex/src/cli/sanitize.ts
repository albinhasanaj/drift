/**
 * sanitize — Sanitize text by redacting sensitive data.
 */

import type { CortexClient } from "../bridge/client.js";

export async function sanitizeCommand(
  client: CortexClient,
  text: string,
): Promise<void> {
  const result = await client.sanitize(text);
  console.log(JSON.stringify(result, null, 2));
}
