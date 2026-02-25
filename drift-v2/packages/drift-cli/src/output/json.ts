/**
 * JSON output format — machine-readable structured output.
 */

/**
 * Format data as pretty-printed JSON.
 */
export function formatJson(data: unknown): string {
  return JSON.stringify(data, null, 2) + '\n';
}
