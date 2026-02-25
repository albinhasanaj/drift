/**
 * Output format registration — table, JSON, SARIF.
 */

import { formatTable } from './table.js';
import { formatJson } from './json.js';
import { formatSarif } from './sarif.js';

export type OutputFormat = 'table' | 'json' | 'sarif';

/**
 * Format data for output in the specified format.
 */
export function formatOutput(
  data: unknown,
  format: OutputFormat,
): string {
  switch (format) {
    case 'json':
      return formatJson(data);
    case 'sarif':
      return formatSarif(data);
    case 'table':
    default:
      return formatTable(data);
  }
}

export { formatTable } from './table.js';
export { formatJson } from './json.js';
export { formatSarif } from './sarif.js';
