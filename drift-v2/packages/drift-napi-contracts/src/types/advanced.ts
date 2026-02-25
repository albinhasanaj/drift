/**
 * Advanced system types — aligned to crates/drift/drift-napi/src/bindings/advanced.rs
 *
 * Note: Rust advanced bindings return String (JSON-serialized). These interfaces
 * define the JSON structure after deserialization on the TS side.
 */

/** Result from drift_simulate(). JSON structure from Rust StrategyRecommender. */
export interface SimulationResult {
  strategies: SimulationStrategy[];
  taskCategory: string;
  taskDescription: string;
}

export interface SimulationStrategy {
  name: string;
  description: string;
  confidence: number;
  estimatedEffort: string;
  risks: string[];
  steps: string[];
}

/** Result from drift_decisions(). JSON structure from Rust GitAnalyzer. */
export interface DecisionResult {
  decisions: DecisionEntry[];
}

export interface DecisionEntry {
  id: string;
  description: string;
  date: string;
  author: string;
  files: string[];
  confidence: number;
}

/** Result from drift_context(). JSON structure from Rust ContextEngine. */
export interface ContextResult {
  sections: ContextSection[];
  tokenCount: number;
  intent: string;
  depth: string;
}

export interface ContextSection {
  name: string;
  content: string;
}

/** Result from drift_generate_spec(). JSON structure from Rust SpecificationRenderer. */
export interface SpecResult {
  moduleName: string;
  sections: SpecSection[];
  totalTokenCount: number;
  hasAllSections: boolean;
}

export interface SpecSection {
  section: string;
  content: string;
}
