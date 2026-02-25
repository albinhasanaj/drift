/**
 * drift_cortex_validate — Run validation across all memories.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftCortexValidate(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_cortex_validate",
    description:
      "Run 4-dimension validation (citation, temporal, contradiction, pattern alignment) " +
      "across all memories. Returns validation results with healing actions.",
    inputSchema: {
      type: "object",
      properties: {
        min_confidence: {
          type: "number",
          description: "Only validate memories below this confidence. Default 1.0.",
        },
      },
    },
    handler: async (args) => {
      // E-02: Run real 4-dimension validation instead of just listing candidates.
      const result = await client.validationRun(
        0.0,
        (args.min_confidence as number) ?? 1.0,
      );
      return result;
    },
  };
}
