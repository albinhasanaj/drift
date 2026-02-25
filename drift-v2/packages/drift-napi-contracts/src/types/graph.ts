/**
 * Graph intelligence types — aligned to crates/drift/drift-napi/src/bindings/graph.rs
 */

/** Aligned to Rust JsReachabilityResult (#[napi(object)]). */
export interface JsReachabilityResult {
  source: string;
  reachableCount: number;
  sensitivity: string;
  maxDepth: number;
  engine: string;
}

/** Aligned to Rust JsTaintFlow (#[napi(object)]). */
export interface JsTaintFlow {
  sourceFile: string;
  sourceLine: number;
  sourceType: string;
  sinkFile: string;
  sinkLine: number;
  sinkType: string;
  cweId: number | null;
  isSanitized: boolean;
  confidence: number;
  pathLength: number;
}

/** Aligned to Rust JsTaintResult (#[napi(object)]). */
export interface JsTaintResult {
  flows: JsTaintFlow[];
  vulnerabilityCount: number;
  sourceCount: number;
  sinkCount: number;
}

/** Aligned to Rust JsErrorGap (#[napi(object)]). */
export interface JsErrorGap {
  file: string;
  functionName: string;
  line: number;
  gapType: string;
  severity: string;
  cweId: number | null;
  remediation: string | null;
}

/** Aligned to Rust JsErrorHandlingResult (#[napi(object)]). */
export interface JsErrorHandlingResult {
  gaps: JsErrorGap[];
  handlerCount: number;
  unhandledCount: number;
}

/** Aligned to Rust JsBlastRadius (#[napi(object)]). */
export interface JsBlastRadius {
  functionId: string;
  callerCount: number;
  riskScore: number;
  maxDepth: number;
}

/** Aligned to Rust JsDeadCode (#[napi(object)]). */
export interface JsDeadCode {
  functionId: string;
  reason: string;
  exclusion: string | null;
}

/** Aligned to Rust JsImpactResult (#[napi(object)]). */
export interface JsImpactResult {
  blastRadii: JsBlastRadius[];
  deadCode: JsDeadCode[];
}

/** Aligned to Rust JsTestQuality (#[napi(object)]). */
export interface JsTestQuality {
  coverageBreadth: number;
  coverageDepth: number;
  assertionDensity: number;
  mockRatio: number;
  isolation: number;
  freshness: number;
  stability: number;
  overall: number;
  smellCount: number;
}

/** Aligned to Rust JsTestTopologyResult (#[napi(object)]). */
export interface JsTestTopologyResult {
  quality: JsTestQuality;
  testCount: number;
  sourceCount: number;
  coveragePercent: number;
  minimumTestSetSize: number;
}
