/**
 * Simulation Engine — TypeScript orchestration layer.
 *
 * Coordinates Rust computation cores (Monte Carlo, scorers) with
 * TypeScript approach generation and composite scoring.
 */

export { SimulationOrchestrator } from "./orchestrator.js";
export { ApproachGenerator, type TaskCategory, type SimulationApproach } from "./approaches.js";
export { CompositeScorer, type ScorerWeights } from "./scoring.js";
