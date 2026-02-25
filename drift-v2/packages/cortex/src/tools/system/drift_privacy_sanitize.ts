/**
 * drift_privacy_sanitize — Sanitize text by redacting sensitive data.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition } from "../../bridge/types.js";

export function driftPrivacySanitize(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_privacy_sanitize",
    description:
      "Sanitize text by redacting sensitive data (emails, API keys, tokens, etc.). " +
      "Returns sanitized text and redaction count.",
    inputSchema: {
      type: "object",
      properties: {
        text: {
          type: "string",
          description: "Text to sanitize.",
        },
      },
      required: ["text"],
    },
    handler: async (args) => {
      const text = args.text as string;
      if (typeof text !== "string") {
        throw new Error("text is required and must be a string.");
      }
      const result = await client.sanitize(text);
      return {
        sanitized_text: result.text,
        redaction_count: result.redactions,
      };
    },
  };
}
