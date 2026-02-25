/**
 * drift_time_diff — Compare knowledge between two points in time.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition, TemporalDiff } from "../../bridge/types.js";

function summarizeDiff(diff: TemporalDiff): string {
  const parts: string[] = [];
  if (diff.created.length > 0) parts.push(`${diff.created.length} created`);
  if (diff.archived.length > 0) parts.push(`${diff.archived.length} archived`);
  if (diff.modified.length > 0) parts.push(`${diff.modified.length} modified`);
  if (diff.confidence_shifts.length > 0)
    parts.push(`${diff.confidence_shifts.length} confidence shifts`);
  if (diff.new_contradictions.length > 0)
    parts.push(`${diff.new_contradictions.length} new contradictions`);
  if (diff.resolved_contradictions.length > 0)
    parts.push(`${diff.resolved_contradictions.length} resolved contradictions`);
  if (diff.reclassifications.length > 0)
    parts.push(`${diff.reclassifications.length} reclassifications`);

  const trend =
    diff.stats.confidence_trend > 0
      ? "improving"
      : diff.stats.confidence_trend < 0
        ? "declining"
        : "stable";

  return parts.length > 0
    ? `${parts.join(", ")}. Net change: ${diff.stats.net_change >= 0 ? "+" : ""}${diff.stats.net_change}. Confidence trend: ${trend}.`
    : "No changes detected between the two time points.";
}

export function driftTimeDiff(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_time_diff",
    description:
      "Compare knowledge between two points in time. Shows what was created, " +
      "archived, modified, and how confidence shifted.",
    inputSchema: {
      type: "object",
      properties: {
        time_a: {
          type: "string",
          description: "ISO 8601 timestamp — earlier time point.",
        },
        time_b: {
          type: "string",
          description: "ISO 8601 timestamp — later time point.",
        },
        scope: {
          type: "string",
          description: "Scope of diff: 'all' (default), or a namespace string.",
        },
      },
      required: ["time_a", "time_b"],
    },
    handler: async (args) => {
      const diff = await client.queryDiff(
        args.time_a as string,
        args.time_b as string,
        args.scope as string | undefined,
      );
      return {
        diff,
        summary: summarizeDiff(diff),
      };
    },
  };
}
