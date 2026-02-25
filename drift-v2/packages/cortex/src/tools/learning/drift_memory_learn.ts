/**
 * drift_memory_learn — Correction analysis + principle extraction.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftMemoryLearn(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_memory_learn",
    description:
      "Analyze a correction and extract learning principles. Creates new " +
      "memories from corrections and categorizes the learning.",
    inputSchema: {
      type: "object",
      properties: {
        correction_text: {
          type: "string",
          description: "The correction or new information.",
        },
        context: {
          type: "string",
          description: "Context in which the correction was made.",
        },
        source: {
          type: "string",
          description: "Source of the correction (e.g. 'user', 'code_review').",
        },
        original_memory_id: {
          type: "string",
          description: "ID of the memory being corrected, if applicable.",
        },
      },
      required: ["correction_text", "context", "source"],
    },
    handler: async (args) => {
      return client.analyzeCorrection(
        args.correction_text as string,
        args.context as string,
        args.source as string,
        args.original_memory_id as string | undefined,
      );
    },
  };
}
