/**
 * Bridge result types — cortex-drift-bridge NAPI return shapes.
 *
 * Every type here corresponds to a serde_json::Value returned by
 * `crates/cortex-drift-bridge/src/napi/functions.rs`.
 */

// ─── Status & Health ────────────────────────────────────────────────

export interface BridgeStatusResult {
  available: boolean;
  license_tier: string;
  grounding_enabled: boolean;
  version: string;
}

export interface BridgeHealthResult {
  status: string;
  ready: boolean;
  subsystem_checks: BridgeSubsystemCheck[];
  degradation_reasons: string[];
}

export interface BridgeSubsystemCheck {
  name: string;
  healthy: boolean;
  detail: string;
}

// ─── Grounding ──────────────────────────────────────────────────────

export interface BridgeGroundingResult {
  memory_id: string;
  grounding_score: number;
  classification: string;
  evidence: unknown[];
}

export interface BridgeGroundingSnapshot {
  total_checked: number;
  validated: number;
  partial: number;
  weak: number;
  invalidated: number;
  not_groundable: number;
  insufficient_data: number;
  avg_grounding_score: number;
  contradictions_generated: number;
  duration_ms: number;
  error_count: number;
  trigger_type: string | null;
}

export interface BridgeGroundingHistoryEntry {
  grounding_score: number;
  classification: string;
  timestamp: number;
}

export interface BridgeGroundingHistoryResult {
  memory_id: string;
  history: BridgeGroundingHistoryEntry[];
}

// ─── Links ──────────────────────────────────────────────────────────

export interface BridgeEntityLink {
  entity_type: string;
  entity_id: string;
  entity_name: string;
  confidence: number;
  link_type: string;
}

// ─── Events & Intents ───────────────────────────────────────────────

export interface BridgeEventMapping {
  event_type: string;
  memory_type: string | null;
  initial_confidence: number;
  importance: string;
  triggers_grounding: boolean;
  description: string;
}

export interface BridgeEventMappingsResult {
  mappings: BridgeEventMapping[];
  count: number;
}

export interface BridgeGroundabilityResult {
  memory_type: string;
  groundability: string;
  error?: string;
}

export interface BridgeIntentEntry {
  name: string;
  description: string;
  relevant_sources: string[];
  default_depth: number;
}

export interface BridgeIntentsResult {
  intents: BridgeIntentEntry[];
  count: number;
}

// ─── License ────────────────────────────────────────────────────────

export interface BridgeLicenseResult {
  feature: string;
  tier: string;
  allowed: boolean;
}

// ─── Specification ──────────────────────────────────────────────────

export interface BridgeAdaptiveWeightsResult {
  weights: Record<string, number>;
  failure_distribution: Record<string, number>;
  sample_size: number;
  last_updated: string;
}

export interface BridgeSpecCorrectionResult {
  memory_id: string;
  status: string;
}

export interface BridgeContractVerifiedResult {
  memory_id: string;
  passed: boolean;
}

export interface BridgeDecompositionAdjustedResult {
  memory_id: string;
  adjustment_type: string;
}

export interface BridgeExplainSpecResult {
  memory_id: string;
  explanation: string;
}

// ─── Causal Intelligence ────────────────────────────────────────────

export interface BridgeCounterfactualResult {
  affected_count: number;
  affected_ids: string[];
  max_depth: number;
  summary: string;
}

export interface BridgeInterventionResult {
  impacted_count: number;
  impacted_ids: string[];
  max_depth: number;
  summary: string;
}

export interface BridgeUnifiedNarrativeResult {
  memory_id: string;
  sections: unknown[];
  upstream: unknown[];
  downstream: unknown[];
  markdown: string;
}

export interface BridgePruneCausalResult {
  edges_removed: number;
  threshold: number;
}
