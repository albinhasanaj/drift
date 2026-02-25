/**
 * drift_knowledge_timeline — Knowledge evolution visualization over time.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { DriftSnapshot, McpToolDefinition } from "../../bridge/types.js";

type Granularity = "hourly" | "daily" | "weekly";

function getIntervalMs(granularity: Granularity): number {
  switch (granularity) {
    case "hourly":
      return 60 * 60 * 1000;
    case "daily":
      return 24 * 60 * 60 * 1000;
    case "weekly":
      return 7 * 24 * 60 * 60 * 1000;
  }
}

function computeTrend(snapshots: DriftSnapshot[]): {
  ksi_trend: string;
  confidence_trend: string;
  freshness_trend: string;
} {
  if (snapshots.length < 2) {
    return { ksi_trend: "insufficient_data", confidence_trend: "insufficient_data", freshness_trend: "insufficient_data" };
  }

  const first = snapshots[0];
  const last = snapshots[snapshots.length - 1];

  const classify = (delta: number): string =>
    delta > 0.05 ? "improving" : delta < -0.05 ? "declining" : "stable";

  return {
    ksi_trend: classify(last.global.overall_ksi - first.global.overall_ksi),
    confidence_trend: classify(last.global.avg_confidence - first.global.avg_confidence),
    freshness_trend: classify(
      last.global.overall_evidence_freshness - first.global.overall_evidence_freshness,
    ),
  };
}

export function driftKnowledgeTimeline(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_knowledge_timeline",
    description:
      "Visualize knowledge evolution over time. Returns a time-series of drift " +
      "snapshots at the specified granularity with trend analysis.",
    inputSchema: {
      type: "object",
      properties: {
        from: {
          type: "string",
          description: "ISO 8601 timestamp — start of timeline.",
        },
        to: {
          type: "string",
          description: "ISO 8601 timestamp — end of timeline.",
        },
        granularity: {
          type: "string",
          enum: ["hourly", "daily", "weekly"],
          description: "Time granularity for snapshots (default: daily).",
        },
      },
      required: ["from", "to"],
    },
    handler: async (args) => {
      const fromTime = new Date(args.from as string).getTime();
      const toTime = new Date(args.to as string).getTime();
      const granularity = ((args.granularity as string) ?? "daily") as Granularity;
      const intervalMs = getIntervalMs(granularity);

      // Compute window hours for each snapshot based on granularity
      const windowHours = Math.ceil(intervalMs / (60 * 60 * 1000));

      const snapshots: DriftSnapshot[] = [];
      for (let t = fromTime; t <= toTime; t += intervalMs) {
        // Use the actual timestamp for each snapshot point so we get
        // historical data, not the same current snapshot repeated.
        const pointTime = new Date(t).toISOString();
        const nextTime = new Date(Math.min(t + intervalMs, toTime)).toISOString();
        // Query memories that existed in each window to derive metrics
        const memories = await client.queryRange(pointTime, nextTime, "overlaps");
        const active = memories.filter((m: { archived?: boolean }) => !m.archived);
        const archived = memories.filter((m: { archived?: boolean }) => m.archived);
        const avgConfidence = active.length > 0
          ? active.reduce((sum: number, m: { confidence?: number }) => sum + (m.confidence ?? 0), 0) / active.length
          : 0;
        snapshots.push({
          timestamp: pointTime,
          window_hours: windowHours,
          type_metrics: {},
          module_metrics: {},
          global: {
            total_memories: memories.length,
            active_memories: active.length,
            archived_memories: archived.length,
            avg_confidence: avgConfidence,
            overall_ksi: 0,
            overall_contradiction_density: 0,
            overall_evidence_freshness: 0,
          },
        } as DriftSnapshot);
      }

      return {
        snapshots,
        trend: computeTrend(snapshots),
      };
    },
  };
}
