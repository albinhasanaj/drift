/**
 * Approach generation logic for simulation tasks.
 */

/** 13 task categories matching the Rust enum. */
export type TaskCategory =
  | "add_feature"
  | "fix_bug"
  | "refactor"
  | "migrate_framework"
  | "add_test"
  | "security_fix"
  | "performance_optimization"
  | "dependency_update"
  | "api_change"
  | "database_migration"
  | "config_change"
  | "documentation"
  | "infrastructure";

/** A candidate approach for completing a task. */
export interface SimulationApproach {
  name: string;
  description: string;
  estimatedEffortHours: number;
  riskLevel: "low" | "medium" | "high" | "critical";
  affectedFileCount: number;
  tradeoffs: string[];
  compositeScore: number;
}

/** Simulation context from Rust analysis. */
export interface SimulationContext {
  avgComplexity: number;
  avgCognitiveComplexity: number;
  blastRadius: number;
  sensitivity: number;
  testCoverage: number;
  constraintViolations: number;
  totalLoc: number;
  dependencyCount: number;
  couplingInstability: number;
}

/** Approach generator — creates candidate approaches for a task category. */
export class ApproachGenerator {
  /**
   * Generate candidate approaches for a task.
   */
  generate(category: TaskCategory, _context: SimulationContext): SimulationApproach[] {
    const templates = approachTemplates[category] ?? defaultTemplates;
    return templates.map((t) => ({
      ...t,
      affectedFileCount: 0,
      compositeScore: 0,
    }));
  }
}

interface ApproachTemplate {
  name: string;
  description: string;
  estimatedEffortHours: number;
  riskLevel: "low" | "medium" | "high" | "critical";
  tradeoffs: string[];
}

const defaultTemplates: ApproachTemplate[] = [
  {
    name: "standard",
    description: "Standard approach for this task type",
    estimatedEffortHours: 8,
    riskLevel: "medium",
    tradeoffs: ["Predictable", "Well-understood"],
  },
  {
    name: "accelerated",
    description: "Fast-track approach with reduced validation",
    estimatedEffortHours: 5,
    riskLevel: "high",
    tradeoffs: ["Faster delivery", "Higher risk"],
  },
  {
    name: "thorough",
    description: "Comprehensive approach with extra validation",
    estimatedEffortHours: 12,
    riskLevel: "low",
    tradeoffs: ["Lower risk", "More effort"],
  },
];

const approachTemplates: Partial<Record<TaskCategory, ApproachTemplate[]>> = {
  add_feature: [
    {
      name: "incremental",
      description: "Add feature incrementally with feature flags",
      estimatedEffortHours: 16,
      riskLevel: "low",
      tradeoffs: ["Lower risk", "Slower delivery", "Flag cleanup needed"],
    },
    {
      name: "big_bang",
      description: "Implement complete feature in one pass",
      estimatedEffortHours: 12,
      riskLevel: "high",
      tradeoffs: ["Faster delivery", "Higher risk", "Harder to review"],
    },
    {
      name: "prototype_first",
      description: "Build prototype, validate, then productionize",
      estimatedEffortHours: 20,
      riskLevel: "low",
      tradeoffs: ["Better design", "More effort", "Validated approach"],
    },
  ],
  fix_bug: [
    {
      name: "minimal_fix",
      description: "Smallest change that fixes the bug",
      estimatedEffortHours: 4,
      riskLevel: "low",
      tradeoffs: ["Low risk", "May not address root cause"],
    },
    {
      name: "root_cause",
      description: "Fix the root cause with comprehensive testing",
      estimatedEffortHours: 10,
      riskLevel: "medium",
      tradeoffs: ["Prevents recurrence", "More effort"],
    },
    {
      name: "defensive",
      description: "Fix bug and add defensive checks",
      estimatedEffortHours: 8,
      riskLevel: "low",
      tradeoffs: ["Prevents similar bugs", "More code"],
    },
  ],
  security_fix: [
    {
      name: "patch",
      description: "Apply targeted security patch",
      estimatedEffortHours: 5,
      riskLevel: "medium",
      tradeoffs: ["Quick mitigation", "May miss variants"],
    },
    {
      name: "harden",
      description: "Comprehensive hardening of the affected area",
      estimatedEffortHours: 12,
      riskLevel: "low",
      tradeoffs: ["Thorough protection", "More effort"],
    },
    {
      name: "defense_in_depth",
      description: "Add multiple layers of security controls",
      estimatedEffortHours: 18,
      riskLevel: "low",
      tradeoffs: ["Maximum protection", "Significant effort"],
    },
  ],
};
