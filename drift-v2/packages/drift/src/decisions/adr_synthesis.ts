/**
 * ADR synthesis — generates Architecture Decision Records from mined decisions.
 */

import type { DecisionCategory } from "./categories.js";

/** A mined decision from Rust analysis. */
export interface MinedDecision {
  id: string;
  category: DecisionCategory;
  description: string;
  commitSha?: string;
  timestamp: number;
  confidence: number;
  relatedPatterns: string[];
  author?: string;
  filesChanged: string[];
}

/** ADR status. */
export type AdrStatus = "proposed" | "accepted" | "deprecated" | "superseded";

/** A synthesized ADR. */
export interface SynthesizedAdr {
  title: string;
  status: AdrStatus;
  context: string;
  decision: string;
  consequences: string;
  sourceDecisions: string[];
  confidence: number;
}

/**
 * ADR synthesizer — generates ADR documents from mined decisions.
 *
 * Groups related decisions and synthesizes them into structured ADR format.
 */
export class AdrSynthesizer {
  /**
   * Synthesize ADRs from a set of mined decisions.
   */
  synthesize(decisions: MinedDecision[]): SynthesizedAdr[] {
    // Group decisions by category
    const grouped = new Map<DecisionCategory, MinedDecision[]>();
    for (const decision of decisions) {
      const existing = grouped.get(decision.category) ?? [];
      existing.push(decision);
      grouped.set(decision.category, existing);
    }

    const adrs: SynthesizedAdr[] = [];

    for (const [category, categoryDecisions] of grouped) {
      // Sort by timestamp
      const sorted = categoryDecisions.sort((a, b) => a.timestamp - b.timestamp);

      // Group closely related decisions (within 7 days)
      const clusters = this.clusterDecisions(sorted);

      for (const cluster of clusters) {
        const adr = this.synthesizeCluster(category, cluster);
        if (adr) {
          adrs.push(adr);
        }
      }
    }

    return adrs.sort((a, b) => b.confidence - a.confidence);
  }

  private clusterDecisions(decisions: MinedDecision[]): MinedDecision[][] {
    if (decisions.length === 0) return [];

    const clusters: MinedDecision[][] = [];
    let current: MinedDecision[] = [decisions[0]];

    for (let i = 1; i < decisions.length; i++) {
      const timeDelta = decisions[i].timestamp - decisions[i - 1].timestamp;
      const sevenDays = 7 * 24 * 3600;

      if (timeDelta <= sevenDays) {
        current.push(decisions[i]);
      } else {
        clusters.push(current);
        current = [decisions[i]];
      }
    }
    clusters.push(current);

    return clusters;
  }

  private synthesizeCluster(
    category: DecisionCategory,
    cluster: MinedDecision[],
  ): SynthesizedAdr | null {
    if (cluster.length === 0) return null;

    const primary = cluster[0];
    const avgConfidence =
      cluster.reduce((sum, d) => sum + d.confidence, 0) / cluster.length;

    return {
      title: `${this.categoryTitle(category)}: ${primary.description}`,
      status: avgConfidence >= 0.7 ? "accepted" : "proposed",
      context: `Based on ${cluster.length} related decision(s) found in git history.`,
      decision: primary.description,
      consequences: `Affects ${new Set(cluster.flatMap((d) => d.filesChanged)).size} file(s).`,
      sourceDecisions: cluster.map((d) => d.id),
      confidence: avgConfidence,
    };
  }

  private categoryTitle(category: DecisionCategory): string {
    const titles: Record<DecisionCategory, string> = {
      architecture: "Architecture Decision",
      technology: "Technology Choice",
      pattern: "Design Pattern",
      convention: "Convention",
      security: "Security Decision",
      performance: "Performance Decision",
      testing: "Testing Strategy",
      deployment: "Deployment Decision",
      data_model: "Data Model Decision",
      api_design: "API Design Decision",
      error_handling: "Error Handling Strategy",
      documentation: "Documentation Decision",
    };
    return titles[category] ?? "Decision";
  }
}
