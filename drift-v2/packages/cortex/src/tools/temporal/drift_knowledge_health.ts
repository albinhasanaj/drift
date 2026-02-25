/**
 * drift_knowledge_health — Drift metrics dashboard with alerts.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { DriftAlert, DriftSnapshot, McpToolDefinition } from "../../bridge/types.js";

function summarizeHealth(metrics: DriftSnapshot, alerts: DriftAlert[]): string {
  const g = metrics.global;
  const parts: string[] = [];

  parts.push(
    `${g.active_memories} active memories (${g.archived_memories} archived)`,
  );
  parts.push(`Overall KSI: ${g.overall_ksi.toFixed(2)}`);
  parts.push(`Avg confidence: ${g.avg_confidence.toFixed(2)}`);
  parts.push(`Evidence freshness: ${g.overall_evidence_freshness.toFixed(2)}`);
  parts.push(`Contradiction density: ${g.overall_contradiction_density.toFixed(3)}`);

  if (alerts.length > 0) {
    const critical = alerts.filter((a) => a.severity === "critical").length;
    const warning = alerts.filter((a) => a.severity === "warning").length;
    const info = alerts.filter((a) => a.severity === "info").length;
    const alertParts: string[] = [];
    if (critical > 0) alertParts.push(`${critical} critical`);
    if (warning > 0) alertParts.push(`${warning} warning`);
    if (info > 0) alertParts.push(`${info} info`);
    parts.push(`Alerts: ${alertParts.join(", ")}`);
  } else {
    parts.push("No active alerts.");
  }

  return parts.join(". ") + ".";
}

export function driftKnowledgeHealth(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_knowledge_health",
    description:
      "Get a drift metrics dashboard showing knowledge base health: KSI, " +
      "confidence trends, contradiction density, evidence freshness, and active alerts.",
    inputSchema: {
      type: "object",
      properties: {
        window_hours: {
          type: "number",
          description: "Time window in hours for metrics computation (default: 168 = 1 week).",
        },
      },
    },
    handler: async (args) => {
      const windowHours = (args.window_hours as number) ?? 168;
      const [metrics, alerts] = await Promise.all([
        client.getDriftMetrics(windowHours),
        client.getDriftAlerts(),
      ]);
      return {
        metrics,
        alerts,
        summary: summarizeHealth(metrics, alerts),
      };
    },
  };
}
