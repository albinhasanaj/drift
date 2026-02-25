/**
 * drift_validate — Get validation candidates for active learning.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftValidate(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_validate",
    description:
      "Get memories that are candidates for validation — low-confidence memories " +
      "that would benefit from human review or active learning.",
    inputSchema: {
      type: "object",
      properties: {
        min_confidence: {
          type: "number",
          description: "Minimum confidence threshold. Default 0.0.",
        },
        max_confidence: {
          type: "number",
          description: "Maximum confidence threshold. Default 0.5.",
        },
      },
    },
    handler: async (args) => {
      const candidates = await client.getValidationCandidates(
        args.min_confidence as number | undefined,
        args.max_confidence as number | undefined,
      );
      return { count: candidates.length, candidates };
    },
  };
}
