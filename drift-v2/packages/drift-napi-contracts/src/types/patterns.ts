/**
 * Pattern types — aligned to crates/drift/drift-napi/src/bindings/patterns.rs
 *
 * Note: Rust returns serde_json::Value for these functions. We define
 * typed interfaces matching the JSON structure returned by the Rust stubs.
 */

/** Result from drift_patterns(). */
export interface PatternsResult {
  patterns: PatternEntry[];
  hasMore: boolean;
  nextCursor: string | null;
}

export interface PatternEntry {
  id: string;
  name: string;
  category: string;
  confidence: number;
  occurrenceCount: number;
}

/** Result from drift_confidence(). */
export interface ConfidenceResult {
  scores: ConfidenceScore[];
  hasMore: boolean;
  nextCursor: string | null;
}

export interface ConfidenceScore {
  patternId: string;
  confidence: number;
  tier: string;
  sampleCount: number;
}

/** Result from drift_outliers(). */
export interface OutlierResult {
  outliers: OutlierEntry[];
  hasMore: boolean;
  nextCursor: string | null;
}

export interface OutlierEntry {
  file: string;
  line: number;
  patternId: string;
  deviation: number;
  severity: string;
}

/** Result from drift_conventions(). */
export interface ConventionResult {
  conventions: ConventionEntry[];
  hasMore: boolean;
  nextCursor: string | null;
}

export interface ConventionEntry {
  name: string;
  category: string;
  adherenceRate: number;
  exampleCount: number;
}
