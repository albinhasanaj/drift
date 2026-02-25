/**
 * Decision category definitions — 12 categories matching the Rust enum.
 */

/** 12 decision categories. */
export type DecisionCategory =
  | "architecture"
  | "technology"
  | "pattern"
  | "convention"
  | "security"
  | "performance"
  | "testing"
  | "deployment"
  | "data_model"
  | "api_design"
  | "error_handling"
  | "documentation";

/** All 12 categories. */
export const ALL_CATEGORIES: DecisionCategory[] = [
  "architecture",
  "technology",
  "pattern",
  "convention",
  "security",
  "performance",
  "testing",
  "deployment",
  "data_model",
  "api_design",
  "error_handling",
  "documentation",
];

/** Category metadata. */
export interface CategoryInfo {
  name: DecisionCategory;
  displayName: string;
  description: string;
  keywords: string[];
}

/** Category metadata for all 12 categories. */
export const CATEGORY_INFO: Record<DecisionCategory, CategoryInfo> = {
  architecture: {
    name: "architecture",
    displayName: "Architecture",
    description: "Structural decisions about system organization",
    keywords: ["microservice", "monolith", "modular", "layer", "decouple"],
  },
  technology: {
    name: "technology",
    displayName: "Technology",
    description: "Technology stack and framework choices",
    keywords: ["migrate", "upgrade", "framework", "library", "runtime"],
  },
  pattern: {
    name: "pattern",
    displayName: "Pattern",
    description: "Design pattern adoption decisions",
    keywords: ["pattern", "singleton", "factory", "observer", "strategy"],
  },
  convention: {
    name: "convention",
    displayName: "Convention",
    description: "Coding convention and style decisions",
    keywords: ["convention", "naming", "style", "lint", "format"],
  },
  security: {
    name: "security",
    displayName: "Security",
    description: "Security-related decisions",
    keywords: ["security", "auth", "csrf", "xss", "encrypt"],
  },
  performance: {
    name: "performance",
    displayName: "Performance",
    description: "Performance optimization decisions",
    keywords: ["performance", "optimize", "cache", "lazy", "bundle"],
  },
  testing: {
    name: "testing",
    displayName: "Testing",
    description: "Testing strategy decisions",
    keywords: ["test", "coverage", "integration", "e2e", "mock"],
  },
  deployment: {
    name: "deployment",
    displayName: "Deployment",
    description: "Deployment and infrastructure decisions",
    keywords: ["deploy", "ci/cd", "docker", "kubernetes", "terraform"],
  },
  data_model: {
    name: "data_model",
    displayName: "Data Model",
    description: "Database and data model decisions",
    keywords: ["schema", "migration", "model", "entity", "table"],
  },
  api_design: {
    name: "api_design",
    displayName: "API Design",
    description: "API design and versioning decisions",
    keywords: ["api", "endpoint", "rest", "graphql", "grpc"],
  },
  error_handling: {
    name: "error_handling",
    displayName: "Error Handling",
    description: "Error handling strategy decisions",
    keywords: ["error", "exception", "retry", "circuit breaker", "fallback"],
  },
  documentation: {
    name: "documentation",
    displayName: "Documentation",
    description: "Documentation strategy decisions",
    keywords: ["document", "readme", "changelog", "api doc"],
  },
};
