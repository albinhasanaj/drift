/**
 * Structural intelligence types — aligned to crates/drift/drift-napi/src/bindings/structural.rs
 * All 9 structural systems: coupling, constraints, contracts, constants, wrappers, DNA, OWASP, crypto, decomposition
 */

// ─── Coupling Analysis ───────────────────────────────────────────────

/** Aligned to Rust JsCouplingMetrics (#[napi(object)]). */
export interface JsCouplingMetrics {
  module: string;
  ce: number;
  ca: number;
  instability: number;
  abstractness: number;
  distance: number;
  zone: string;
}

/** Aligned to Rust JsCycleInfo (#[napi(object)]). */
export interface JsCycleInfo {
  members: string[];
  breakSuggestionCount: number;
}

/** Aligned to Rust JsCouplingResult (#[napi(object)]). */
export interface JsCouplingResult {
  metrics: JsCouplingMetrics[];
  cycles: JsCycleInfo[];
  moduleCount: number;
}

// ─── Constraint System ───────────────────────────────────────────────

/** Aligned to Rust JsConstraintViolation (#[napi(object)]). */
export interface JsConstraintViolation {
  constraintId: string;
  file: string;
  line: number | null;
  message: string;
}

/** Aligned to Rust JsConstraintResult (#[napi(object)]). */
export interface JsConstraintResult {
  totalConstraints: number;
  passing: number;
  failing: number;
  violations: JsConstraintViolation[];
}

// ─── Contract Tracking ───────────────────────────────────────────────

/** Aligned to Rust JsEndpoint (#[napi(object)]). */
export interface JsEndpoint {
  method: string;
  path: string;
  file: string;
  line: number;
  framework: string;
}

/** Aligned to Rust JsContractMismatch (#[napi(object)]). */
export interface JsContractMismatch {
  backendEndpoint: string;
  frontendCall: string;
  mismatchType: string;
  severity: string;
  message: string;
}

/** Aligned to Rust JsContractResult (#[napi(object)]). */
export interface JsContractResult {
  endpoints: JsEndpoint[];
  mismatches: JsContractMismatch[];
  paradigmCount: number;
  frameworkCount: number;
}

// ─── Constants & Secrets ─────────────────────────────────────────────

/** Aligned to Rust JsSecret (#[napi(object)]). */
export interface JsSecret {
  patternName: string;
  file: string;
  line: number;
  severity: string;
  confidence: number;
}

/** Aligned to Rust JsMagicNumber (#[napi(object)]). */
export interface JsMagicNumber {
  value: string;
  file: string;
  line: number;
  suggestedName: string | null;
}

/** Aligned to Rust JsConstantsResult (#[napi(object)]). */
export interface JsConstantsResult {
  constantCount: number;
  secrets: JsSecret[];
  magicNumbers: JsMagicNumber[];
  missingEnvVars: string[];
  deadConstantCount: number;
}

// ─── Wrapper Detection ───────────────────────────────────────────────

/** Aligned to Rust JsWrapper (#[napi(object)]). */
export interface JsWrapper {
  name: string;
  file: string;
  line: number;
  category: string;
  framework: string;
  confidence: number;
  isMultiPrimitive: boolean;
  usageCount: number;
}

/** Aligned to Rust JsWrapperHealth (#[napi(object)]). */
export interface JsWrapperHealth {
  consistency: number;
  coverage: number;
  abstractionDepth: number;
  overall: number;
}

/** Aligned to Rust JsWrapperResult (#[napi(object)]). */
export interface JsWrapperResult {
  wrappers: JsWrapper[];
  health: JsWrapperHealth;
  frameworkCount: number;
  categoryCount: number;
}

// ─── DNA System ──────────────────────────────────────────────────────

/** Aligned to Rust JsGene (#[napi(object)]). */
export interface JsGene {
  id: string;
  name: string;
  dominantAllele: string | null;
  alleleCount: number;
  confidence: number;
  consistency: number;
}

/** Aligned to Rust JsMutation (#[napi(object)]). */
export interface JsMutation {
  id: string;
  file: string;
  line: number;
  gene: string;
  expected: string;
  actual: string;
  impact: string;
}

/** Aligned to Rust JsDnaHealthScore (#[napi(object)]). */
export interface JsDnaHealthScore {
  overall: number;
  consistency: number;
  confidence: number;
  mutationScore: number;
  coverage: number;
}

/** Aligned to Rust JsDnaResult (#[napi(object)]). */
export interface JsDnaResult {
  genes: JsGene[];
  mutations: JsMutation[];
  health: JsDnaHealthScore;
  geneticDiversity: number;
}

// ─── OWASP/CWE Mapping ──────────────────────────────────────────────

/** Aligned to Rust JsSecurityFinding (#[napi(object)]). */
export interface JsSecurityFinding {
  id: string;
  detector: string;
  file: string;
  line: number;
  description: string;
  severity: number;
  cweIds: number[];
  owaspCategories: string[];
  confidence: number;
  remediation: string | null;
}

/** Aligned to Rust JsComplianceReport (#[napi(object)]). */
export interface JsComplianceReport {
  postureScore: number;
  owaspCoverage: number;
  cweTop25Coverage: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
}

/** Aligned to Rust JsOwaspResult (#[napi(object)]). */
export interface JsOwaspResult {
  findings: JsSecurityFinding[];
  compliance: JsComplianceReport;
}

// ─── Cryptographic Failure Detection ─────────────────────────────────

/** Aligned to Rust JsCryptoFinding (#[napi(object)]). */
export interface JsCryptoFinding {
  file: string;
  line: number;
  category: string;
  description: string;
  confidence: number;
  cweId: number;
  remediation: string;
  language: string;
}

/** Aligned to Rust JsCryptoHealthScore (#[napi(object)]). */
export interface JsCryptoHealthScore {
  overall: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
}

/** Aligned to Rust JsCryptoResult (#[napi(object)]). */
export interface JsCryptoResult {
  findings: JsCryptoFinding[];
  health: JsCryptoHealthScore;
}

// ─── Module Decomposition ────────────────────────────────────────────

/** Aligned to Rust JsLogicalModule (#[napi(object)]). */
export interface JsLogicalModule {
  name: string;
  fileCount: number;
  publicInterfaceCount: number;
  internalFunctionCount: number;
  cohesion: number;
  coupling: number;
  estimatedComplexity: number;
  appliedPriorCount: number;
}

/** Aligned to Rust JsDecompositionResult (#[napi(object)]). */
export interface JsDecompositionResult {
  modules: JsLogicalModule[];
  moduleCount: number;
  totalFiles: number;
  avgCohesion: number;
  avgCoupling: number;
}
