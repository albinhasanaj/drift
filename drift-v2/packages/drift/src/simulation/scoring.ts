/**
 * Composite scoring logic — combines Rust scorer outputs into final ranking.
 */

import type { SimulationApproach } from "./approaches.js";

/** Weights for composite scoring. */
export interface ScorerWeights {
  complexity: number;
  risk: number;
  effort: number;
  confidence: number;
}

/** Default scorer weights. */
const DEFAULT_WEIGHTS: ScorerWeights = {
  complexity: 0.25,
  risk: 0.30,
  effort: 0.25,
  confidence: 0.20,
};

/** Rust scorer output for an approach. */
export interface RustScores {
  complexityScore: number;
  riskScore: number;
  effortScore: number;
  confidenceScore: number;
}

/** Composite scorer — combines 4 Rust scorer outputs into final ranking. */
export class CompositeScorer {
  private weights: ScorerWeights;

  constructor(weights?: Partial<ScorerWeights>) {
    this.weights = { ...DEFAULT_WEIGHTS, ...weights };
  }

  /**
   * Score and rank approaches using Rust scorer outputs.
   * Lower composite score = better approach.
   */
  rank(
    approaches: SimulationApproach[],
    rustScores: RustScores[],
  ): SimulationApproach[] {
    if (approaches.length !== rustScores.length) {
      throw new Error("Approaches and scores arrays must have same length");
    }

    const scored = approaches.map((approach, i) => {
      const scores = rustScores[i];
      const composite =
        scores.complexityScore * this.weights.complexity +
        scores.riskScore * this.weights.risk +
        scores.effortScore * this.weights.effort +
        scores.confidenceScore * this.weights.confidence;

      return { ...approach, compositeScore: composite };
    });

    // Sort by composite score ascending (lower = better)
    return scored.sort((a, b) => a.compositeScore - b.compositeScore);
  }

  /**
   * Generate tradeoff analysis between top approaches.
   */
  generateTradeoffs(
    ranked: SimulationApproach[],
  ): string[] {
    if (ranked.length < 2) return [];

    const best = ranked[0];
    const second = ranked[1];
    const tradeoffs: string[] = [];

    const scoreDiff = second.compositeScore - best.compositeScore;
    if (scoreDiff < 0.05) {
      tradeoffs.push(
        `"${best.name}" and "${second.name}" are very close in score (Δ${scoreDiff.toFixed(3)}). Consider non-quantitative factors.`,
      );
    }

    if (best.riskLevel === "high" && second.riskLevel === "low") {
      tradeoffs.push(
        `"${best.name}" scores better overall but has higher risk. "${second.name}" is safer.`,
      );
    }

    if (best.estimatedEffortHours > second.estimatedEffortHours * 1.5) {
      tradeoffs.push(
        `"${best.name}" requires ${best.estimatedEffortHours}h vs ${second.estimatedEffortHours}h for "${second.name}".`,
      );
    }

    return tradeoffs;
  }
}
