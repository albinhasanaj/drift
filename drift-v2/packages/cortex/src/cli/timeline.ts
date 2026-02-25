/**
 * drift cortex timeline — Show knowledge evolution over time.
 */

import type { CortexClient } from "../bridge/client.js";

export async function timelineCommand(
  client: CortexClient,
  from?: string,
  to?: string,
  memoryType?: string,
  module?: string,
): Promise<void> {
  const now = new Date();
  const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

  const fromTime = from ? new Date(from) : thirtyDaysAgo;
  const toTime = to ? new Date(to) : now;

  // Compute snapshots at daily intervals
  const intervalMs = 24 * 60 * 60 * 1000;
  const points: Array<{
    date: string;
    ksi: number;
    confidence: number;
    contradiction_density: number;
    efi: number;
  }> = [];

  for (let t = fromTime.getTime(); t <= toTime.getTime(); t += intervalMs) {
    const windowHours = 24;
    const snapshot = await client.getDriftMetrics(windowHours);
    const g = snapshot.global;

    points.push({
      date: new Date(t).toISOString().slice(0, 10),
      ksi: g.overall_ksi,
      confidence: g.avg_confidence,
      contradiction_density: g.overall_contradiction_density,
      efi: g.overall_evidence_freshness,
    });
  }

  if (points.length === 0) {
    console.log("\n  No data points in the specified range.\n");
    return;
  }

  // Print header
  console.log("\n  Knowledge Timeline");
  if (memoryType) console.log(`  Type filter: ${memoryType}`);
  if (module) console.log(`  Module filter: ${module}`);
  console.log(`  Range: ${fromTime.toISOString().slice(0, 10)} → ${toTime.toISOString().slice(0, 10)}`);
  console.log();

  // Table header
  console.log(
    "  Date        │ KSI   │ Conf  │ Contra │ EFI  ",
  );
  console.log(
    "  ────────────┼───────┼───────┼────────┼──────",
  );

  for (const p of points) {
    console.log(
      `  ${p.date} │ ${p.ksi.toFixed(2).padStart(5)} │ ${p.confidence.toFixed(2).padStart(5)} │ ${p.contradiction_density.toFixed(3).padStart(6)} │ ${p.efi.toFixed(2).padStart(4)}`,
    );
  }

  console.log();
}
