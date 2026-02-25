/**
 * Simulation orchestrator — coordinates Rust computation with TS approach generation.
 */

import { ApproachGenerator, type TaskCategory, type SimulationContext, type SimulationApproach } from "./approaches.js";
import { CompositeScorer, type RustScores, type ScorerWeights } from "./scoring.js";

/** Simulation result from the orchestrator. */
export interface SimulationResult {
  taskCategory: TaskCategory;
  taskDescription: string;
  approaches: SimulationApproach[];
  recommendedApproach: SimulationApproach | null;
  tradeoffs: string[];
  confidenceInterval: {
    p10: number;
    p50: number;
    p90: number;
  };
}

/** Native binding interface (provided by drift-napi). */
export interface NativeBinding {
  driftSimulate(
    taskCategory: string,
    taskDescription: string,
    contextJson: string,
  ): Promise<string>;
}

/**
 * Simulation orchestrator — coordinates Rust computation with TS approach generation.
 *
 * Flow:
 * 1. TS generates candidate approaches
 * 2. Rust scores each approach (complexity, risk, effort, confidence)
 * 3. TS combines scores and generates recommendations
 */
export class SimulationOrchestrator {
  private approachGenerator: ApproachGenerator;
  private scorer: CompositeScorer;
  private native: NativeBinding | null;

  constructor(native?: NativeBinding, weights?: Partial<ScorerWeights>) {
    this.approachGenerator = new ApproachGenerator();
    this.scorer = new CompositeScorer(weights);
    this.native = native ?? null;
  }

  /**
   * Run a full simulation for a task.
   */
  async simulate(
    category: TaskCategory,
    description: string,
    context: SimulationContext,
  ): Promise<SimulationResult> {
    // Generate approaches
    const approaches = this.approachGenerator.generate(category, context);

    // If native binding available, use Rust for scoring
    let rustResult: RustSimulationResult | null = null;
    if (this.native) {
      try {
        const contextJson = JSON.stringify({
          avg_complexity: context.avgComplexity,
          avg_cognitive_complexity: context.avgCognitiveComplexity,
          blast_radius: context.blastRadius,
          sensitivity: context.sensitivity,
          test_coverage: context.testCoverage,
          constraint_violations: context.constraintViolations,
          total_loc: context.totalLoc,
          dependency_count: context.dependencyCount,
          coupling_instability: context.couplingInstability,
        });

        const resultJson = await this.native.driftSimulate(
          category,
          description,
          contextJson,
        );
        rustResult = JSON.parse(resultJson) as RustSimulationResult;
      } catch {
        // Fall back to TS-only scoring
      }
    }

    // Apply Rust scores if available, otherwise use defaults
    const rustScores: RustScores[] = approaches.map((_, i) => {
      if (rustResult?.approaches?.[i]) {
        const ra = rustResult.approaches[i];
        return {
          complexityScore: ra.complexity_score ?? 0.5,
          riskScore: ra.risk_score ?? 0.5,
          effortScore: ra.effort_score ?? 0.5,
          confidenceScore: ra.confidence_score ?? 0.5,
        };
      }
      return { complexityScore: 0.5, riskScore: 0.5, effortScore: 0.5, confidenceScore: 0.5 };
    });

    // Rank approaches
    const ranked = this.scorer.rank(approaches, rustScores);
    const tradeoffs = this.scorer.generateTradeoffs(ranked);

    // Get confidence interval from Rust or estimate
    const ci = rustResult?.effort_estimate ?? {
      p10: (approaches[0]?.estimatedEffortHours ?? 4) * 0.6,
      p50: approaches[0]?.estimatedEffortHours ?? 8,
      p90: (approaches[0]?.estimatedEffortHours ?? 16) * 1.8,
    };

    return {
      taskCategory: category,
      taskDescription: description,
      approaches: ranked,
      recommendedApproach: ranked[0] ?? null,
      tradeoffs,
      confidenceInterval: ci,
    };
  }
}

interface RustSimulationResult {
  approaches?: Array<{
    complexity_score?: number;
    risk_score?: number;
    effort_score?: number;
    confidence_score?: number;
  }>;
  effort_estimate?: {
    p10: number;
    p50: number;
    p90: number;
  };
}
