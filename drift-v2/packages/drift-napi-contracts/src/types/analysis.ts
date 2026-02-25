/**
 * Analysis types — aligned to crates/drift/drift-napi/src/bindings/analysis.rs
 */

/** Aligned to Rust JsAnalysisResult (#[napi(object)]). */
export interface JsAnalysisResult {
  file: string;
  language: string;
  matches: JsPatternMatch[];
  analysisTimeUs: number;
}

/** Aligned to Rust JsPatternMatch (#[napi(object)]). */
export interface JsPatternMatch {
  file: string;
  line: number;
  column: number;
  patternId: string;
  confidence: number;
  category: string;
  detectionMethod: string;
  matchedText: string;
  cweIds: number[];
  owasp: string | null;
}

/** Aligned to Rust JsValidatePackResult (#[napi(object)]). */
export interface JsValidatePackResult {
  valid: boolean;
  name: string | null;
  version: string | null;
  languageCount: number;
  patternCount: number;
  error: string | null;
}

/** Aligned to Rust JsCallGraphResult (#[napi(object)]). */
export interface JsCallGraphResult {
  totalFunctions: number;
  totalEdges: number;
  entryPoints: number;
  resolutionRate: number;
  buildDurationMs: number;
}

/** Aligned to Rust JsBoundaryResult (#[napi(object)]). */
export interface JsBoundaryResult {
  models: JsModelResult[];
  sensitiveFields: JsSensitiveField[];
  frameworksDetected: string[];
}

/** Aligned to Rust JsModelResult (#[napi(object)]). */
export interface JsModelResult {
  name: string;
  tableName: string | null;
  file: string;
  framework: string;
  fieldCount: number;
  confidence: number;
}

/** Aligned to Rust JsSensitiveField (#[napi(object)]). */
export interface JsSensitiveField {
  modelName: string;
  fieldName: string;
  file: string;
  sensitivity: string;
  confidence: number;
}
