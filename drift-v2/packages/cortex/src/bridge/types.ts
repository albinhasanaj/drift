/**
 * TypeScript type definitions for the Cortex NAPI bridge.
 *
 * GENERATED TYPES: All Rust-mirroring types below are validated against ts-rs
 * generated bindings from `cortex-core` Rust structs/enums with `#[derive(TS)]`.
 *
 * To regenerate: `cargo test -p cortex-core export_bindings`
 * Generated files: `crates/cortex/cortex-core/bindings/*.ts`
 *
 * CI enforces sync: `cargo test export_bindings -p cortex-core && git diff --exit-code`
 *
 * The types below are kept in sync with Rust automatically. If a Rust struct
 * changes, `cargo test` regenerates the .ts file and CI catches the diff.
 *
 * TS-only types (error codes, MCP tool definitions) remain at the bottom.
 */

// ─── Enums ───────────────────────────────────────────────────────────────────

/** 23 memory type variants across 3 categories. Generated from Rust `MemoryType`. */
export type MemoryType =
  // Domain-agnostic (9)
  | "core"
  | "tribal"
  | "procedural"
  | "semantic"
  | "episodic"
  | "decision"
  | "insight"
  | "reference"
  | "preference"
  // Code-specific (4)
  | "pattern_rationale"
  | "constraint_override"
  | "decision_context"
  | "code_smell"
  // Universal V2 (10)
  | "agent_spawn"
  | "entity"
  | "goal"
  | "feedback"
  | "workflow"
  | "conversation"
  | "incident"
  | "meeting"
  | "skill"
  | "environment";

export type Importance = "low" | "normal" | "high" | "critical";

export type HealthStatus = "healthy" | "degraded" | "unhealthy";

export type HealingActionType =
  | "confidence_adjust"
  | "citation_update"
  | "embedding_refresh"
  | "archival"
  | "human_review_flag";

export type RelationshipType =
  | "supersedes"
  | "supports"
  | "contradicts"
  | "related"
  | "derived_from"
  | "owns"
  | "affects"
  | "blocks"
  | "requires"
  | "references"
  | "learned_from"
  | "assigned_to"
  | "depends_on";

/** 18 intent types across 3 categories. Generated from Rust `Intent`. */
export type Intent =
  | "create"
  | "investigate"
  | "decide"
  | "recall"
  | "learn"
  | "summarize"
  | "compare"
  | "add_feature"
  | "fix_bug"
  | "refactor"
  | "security_audit"
  | "understand_code"
  | "add_test"
  | "review_code"
  | "deploy_migrate"
  | "spawn_agent"
  | "execute_workflow"
  | "track_progress";

// ─── Link Types ──────────────────────────────────────────────────────────────

export interface PatternLink {
  pattern_id: string;
  pattern_name: string;
}

export interface ConstraintLink {
  constraint_id: string;
  constraint_name: string;
}

export interface FileLink {
  file_path: string;
  line_start: number | null;
  line_end: number | null;
  content_hash: string | null;
}

export interface FunctionLink {
  function_name: string;
  file_path: string;
  signature: string | null;
}

// ─── Typed Content Variants ──────────────────────────────────────────────────

// Domain-agnostic

export interface CoreContent {
  project_name: string;
  description: string;
  metadata: unknown;
}

export interface TribalContent {
  knowledge: string;
  severity: string;
  warnings: string[];
  consequences: string[];
}

export interface ProceduralStep {
  order: number;
  instruction: string;
  completed: boolean;
}

export interface ProceduralContent {
  title: string;
  steps: ProceduralStep[];
  prerequisites: string[];
}

export interface SemanticContent {
  knowledge: string;
  source_episodes: string[];
  consolidation_confidence: number;
}

export interface EpisodicContent {
  interaction: string;
  context: string;
  outcome: string | null;
}

export interface Alternative {
  description: string;
  reason_rejected: string;
}

export interface DecisionContent {
  decision: string;
  rationale: string;
  alternatives: Alternative[];
}

export interface InsightContent {
  observation: string;
  evidence: string[];
}

export interface ReferenceContent {
  title: string;
  url: string | null;
  citation: string;
}

export interface PreferenceContent {
  preference: string;
  scope: string;
  value: unknown;
}

// Code-specific

export interface PatternRationaleContent {
  pattern_name: string;
  rationale: string;
  business_context: string;
  examples: string[];
}

export interface ConstraintOverrideContent {
  constraint_name: string;
  override_reason: string;
  approved_by: string;
  scope: string;
  expiry: string | null;
}

export interface DecisionContextContent {
  decision: string;
  context: string;
  adr_link: string | null;
  trade_offs: string[];
}

export interface CodeSmellContent {
  smell_name: string;
  description: string;
  bad_example: string;
  good_example: string;
  severity: string;
}


// Universal V2

export interface AgentSpawnContent {
  agent_name: string;
  configuration: unknown;
  purpose: string;
}

export interface EntityContent {
  entity_name: string;
  entity_type: string;
  description: string;
  attributes: unknown;
}

export interface GoalContent {
  title: string;
  description: string;
  progress: number;
  milestones: string[];
}

export interface FeedbackContent {
  feedback: string;
  category: string;
  source: string;
}

export interface WorkflowStep {
  order: number;
  action: string;
  condition: string | null;
}

export interface WorkflowContent {
  name: string;
  steps: WorkflowStep[];
  trigger: string | null;
}

export interface ConversationContent {
  summary: string;
  participants: string[];
  key_points: string[];
}

export interface IncidentContent {
  title: string;
  root_cause: string;
  impact: string;
  resolution: string;
  lessons_learned: string[];
}

export interface MeetingContent {
  title: string;
  attendees: string[];
  notes: string;
  action_items: string[];
}

export interface SkillContent {
  skill_name: string;
  proficiency: string;
  domain: string;
  evidence: string[];
}

export interface EnvironmentContent {
  name: string;
  config: unknown;
  platform: string | null;
}

/**
 * Tagged union for TypedContent — matches Rust's #[serde(tag = "type", content = "data")].
 * Each variant is { type: "variant_name", data: VariantContent }.
 */
export type TypedContent =
  | { type: "core"; data: CoreContent }
  | { type: "tribal"; data: TribalContent }
  | { type: "procedural"; data: ProceduralContent }
  | { type: "semantic"; data: SemanticContent }
  | { type: "episodic"; data: EpisodicContent }
  | { type: "decision"; data: DecisionContent }
  | { type: "insight"; data: InsightContent }
  | { type: "reference"; data: ReferenceContent }
  | { type: "preference"; data: PreferenceContent }
  | { type: "pattern_rationale"; data: PatternRationaleContent }
  | { type: "constraint_override"; data: ConstraintOverrideContent }
  | { type: "decision_context"; data: DecisionContextContent }
  | { type: "code_smell"; data: CodeSmellContent }
  | { type: "agent_spawn"; data: AgentSpawnContent }
  | { type: "entity"; data: EntityContent }
  | { type: "goal"; data: GoalContent }
  | { type: "feedback"; data: FeedbackContent }
  | { type: "workflow"; data: WorkflowContent }
  | { type: "conversation"; data: ConversationContent }
  | { type: "incident"; data: IncidentContent }
  | { type: "meeting"; data: MeetingContent }
  | { type: "skill"; data: SkillContent }
  | { type: "environment"; data: EnvironmentContent };

// ─── BaseMemory ──────────────────────────────────────────────────────────────

/** The universal memory struct. Every memory in the system is a BaseMemory. */
export interface BaseMemory {
  id: string;
  memory_type: MemoryType;
  content: TypedContent;
  summary: string;
  transaction_time: string;
  valid_time: string;
  valid_until: string | null;
  confidence: number;
  importance: Importance;
  last_accessed: string;
  access_count: number;
  linked_patterns: PatternLink[];
  linked_constraints: ConstraintLink[];
  linked_files: FileLink[];
  linked_functions: FunctionLink[];
  tags: string[];
  archived: boolean;
  superseded_by: string | null;
  supersedes: string | null;
  content_hash: string;
}

// ─── Retrieval & Compression ─────────────────────────────────────────────────

export interface RetrievalContext {
  focus: string;
  intent: Intent | null;
  active_files: string[];
  budget: number;
  sent_ids: string[];
}

export interface CompressedMemory {
  memory_id: string;
  memory_type: MemoryType;
  importance: Importance;
  level: number;
  text: string;
  token_count: number;
  relevance_score: number;
}

// ─── Causal ──────────────────────────────────────────────────────────────────

export interface NarrativeSection {
  title: string;
  content: string;
  memory_ids: string[];
}

export interface CausalNarrative {
  sections: NarrativeSection[];
  summary: string;
  confidence: number;
}

export interface TraversalNode {
  memory_id: string;
  depth: number;
  path_strength: number;
}

export interface TraversalResult {
  origin_id: string;
  max_depth_reached: number;
  nodes: TraversalNode[];
}

export interface InferenceResult {
  source_id: string;
  target_id: string;
  strength: number;
  suggested_relation: string;
  above_threshold: boolean;
}

// ─── Consolidation ───────────────────────────────────────────────────────────

export interface ConsolidationMetrics {
  precision: number;
  compression_ratio: number;
  lift: number;
  stability: number;
}

export interface ConsolidationResult {
  created: string[];
  archived: string[];
  metrics: ConsolidationMetrics;
}

export interface ConsolidationStatus {
  is_running: boolean;
}

export interface ConsolidationDashboard {
  total_runs: number;
  successful_runs: number;
  success_rate: number;
  is_running: boolean;
}

// ─── Learning ────────────────────────────────────────────────────────────────

export interface LearningResult {
  category: string;
  principle: string | null;
  memory_created: string | null;
}

// ─── Validation ──────────────────────────────────────────────────────────────

export interface DimensionScores {
  citation: number;
  temporal: number;
  contradiction: number;
  pattern_alignment: number;
}

export interface HealingAction {
  action_type: HealingActionType;
  description: string;
  applied: boolean;
}

export interface ValidationResult {
  memory_id: string;
  dimension_scores: DimensionScores;
  overall_score: number;
  healing_actions: HealingAction[];
  passed: boolean;
}

// ─── Health ──────────────────────────────────────────────────────────────────

export interface SubsystemHealth {
  name: string;
  status: HealthStatus;
  message: string | null;
}

export interface HealthMetrics {
  total_memories: number;
  active_memories: number;
  archived_memories: number;
  average_confidence: number;
  db_size_bytes: number;
  embedding_cache_hit_rate: number;
}

export interface HealthReport {
  overall_status: HealthStatus;
  subsystems: SubsystemHealth[];
  metrics: HealthMetrics;
}

// ─── Session ─────────────────────────────────────────────────────────────────

export interface SessionContext {
  session_id: string;
  sent_memory_ids: string[];
  tokens_used: number;
  token_budget: number;
}

export interface SessionAnalytics {
  session_id: string;
  created_at: string;
  last_activity: string;
  loaded_memories_count: number;
  loaded_patterns_count: number;
  loaded_files_count: number;
  tokens_sent: number;
  queries_made: number;
}

// ─── Prediction ──────────────────────────────────────────────────────────────

export interface PredictionResult {
  memory_ids: string[];
  signals: string[];
  confidence: number;
}

export interface PreloadResult {
  preloaded_count: number;
  memory_ids: string[];
  confidence: number;
}

export interface CacheStats {
  entry_count: number;
  hits: number;
  misses: number;
  hit_rate: number;
}

// ─── Generation ──────────────────────────────────────────────────────────────

export interface BudgetAllocation {
  category: string;
  percentage: number;
  memories: CompressedMemory[];
  tokens_used: number;
}

export interface GenerationContext {
  allocations: BudgetAllocation[];
  total_tokens: number;
  total_budget: number;
}

// ─── Privacy ─────────────────────────────────────────────────────────────────

export interface SanitizeResult {
  text: string;
  redactions: number;
}

export interface PatternFailure {
  pattern_name: string;
  category: string;
  error: string;
}

export interface PatternStats {
  failure_count: number;
  has_failures: boolean;
  failures: PatternFailure[];
}

// ─── Cloud ───────────────────────────────────────────────────────────────────

export interface SyncResult {
  status: string;
  pushed: number;
  pulled: number;
  conflicts_resolved: number;
  manual_conflicts: number;
}

export interface CloudStatus {
  status: string;
  is_online: boolean;
  offline_queue_length: number;
}

// ─── Degradation ─────────────────────────────────────────────────────────────

export interface DegradationEvent {
  component: string;
  failure: string;
  fallback_used: string;
  timestamp: string;
}

// ─── Relationships ───────────────────────────────────────────────────────────

export interface RelationshipEdge {
  source_id: string;
  target_id: string;
  relationship_type: RelationshipType;
  strength: number;
  evidence: string[];
}

// ─── WhyContext ──────────────────────────────────────────────────────────────

export interface WhyEntry {
  memory_id: string;
  summary: string;
  confidence: number;
}

export interface WhyContext {
  patterns: WhyEntry[];
  decisions: WhyEntry[];
  tribal: WhyEntry[];
  warnings: string[];
}

// ─── Temporal ─────────────────────────────────────────────────────────────────

/** Epistemic status of a memory — its verification lifecycle state. */
export type EpistemicStatus =
  | { status: "conjecture"; source: string; created_at: string }
  | { status: "provisional"; evidence_count: number; last_validated: string }
  | { status: "verified"; verified_by: string[]; verified_at: string; evidence_refs: string[] }
  | { status: "stale"; was_verified_at: string; staleness_detected_at: string; reason: string };

/** Alert severity levels. */
export type AlertSeverity = "info" | "warning" | "critical";

/** Categories of drift that can trigger alerts. */
export type DriftAlertCategory =
  | "knowledge_churn"
  | "confidence_erosion"
  | "contradiction_spike"
  | "stale_evidence"
  | "knowledge_explosion"
  | "coverage_gap";

/** A drift alert fired when a metric crosses a threshold. */
export interface DriftAlert {
  severity: AlertSeverity;
  category: DriftAlertCategory;
  message: string;
  affected_memories: string[];
  recommended_action: string;
  detected_at: string;
}

/** Per-memory-type drift metrics. */
export interface TypeDriftMetrics {
  count: number;
  avg_confidence: number;
  ksi: number;
  contradiction_density: number;
  consolidation_efficiency: number;
  evidence_freshness_index: number;
}

/** Per-module drift metrics. */
export interface ModuleDriftMetrics {
  memory_count: number;
  coverage_ratio: number;
  avg_confidence: number;
  churn_rate: number;
}

/** Global aggregate drift metrics. */
export interface GlobalDriftMetrics {
  total_memories: number;
  active_memories: number;
  archived_memories: number;
  avg_confidence: number;
  overall_ksi: number;
  overall_contradiction_density: number;
  overall_evidence_freshness: number;
}

/** Point-in-time capture of all drift metrics. */
export interface DriftSnapshot {
  timestamp: string;
  window_hours: number;
  type_metrics: Record<string, TypeDriftMetrics>;
  module_metrics: Record<string, ModuleDriftMetrics>;
  global: GlobalDriftMetrics;
}

/** Summary statistics for a temporal diff. */
export interface DiffStats {
  memories_at_a: number;
  memories_at_b: number;
  net_change: number;
  avg_confidence_at_a: number;
  avg_confidence_at_b: number;
  confidence_trend: number;
  knowledge_churn_rate: number;
}

/** A modification to a specific field of a memory. */
export interface MemoryModification {
  memory_id: string;
  field: string;
  old_value: unknown;
  new_value: unknown;
  modified_at: string;
}

/** A significant confidence change. */
export interface ConfidenceShift {
  memory_id: string;
  old_confidence: number;
  new_confidence: number;
  delta: number;
}

/** A memory type reclassification. */
export interface Reclassification {
  memory_id: string;
  old_type: string;
  new_type: string;
  confidence: number;
  reclassified_at: string;
}

/** Contradiction between memories. */
export interface Contradiction {
  memory_a_id: string;
  memory_b_id: string;
  contradiction_type: string;
  confidence: number;
  description: string;
}

/** Result of comparing two knowledge states at different times. */
export interface TemporalDiff {
  created: BaseMemory[];
  archived: BaseMemory[];
  modified: MemoryModification[];
  confidence_shifts: ConfidenceShift[];
  new_contradictions: Contradiction[];
  resolved_contradictions: Contradiction[];
  reclassifications: Reclassification[];
  stats: DiffStats;
}

/** Snapshot of the causal graph at a specific point in time. */
export interface CausalGraphSnapshot {
  nodes: string[];
  edges: CausalEdgeSnapshot[];
}

/** A single edge in the causal graph snapshot. */
export interface CausalEdgeSnapshot {
  source: string;
  target: string;
  relation_type: string;
  strength: number;
}

/** A piece of knowledge that didn't exist at decision time but is relevant now. */
export interface HindsightItem {
  memory: BaseMemory;
  relevance: number;
  relationship: string;
}

/** Result of replaying a decision with historical context and hindsight. */
export interface DecisionReplay {
  decision: BaseMemory;
  available_context: BaseMemory[];
  retrieved_context: CompressedMemory[];
  causal_state: CausalGraphSnapshot;
  hindsight: HindsightItem[];
}

/** A materialized view of the knowledge base at a specific point in time. */
export interface MaterializedTemporalView {
  view_id: number;
  label: string;
  timestamp: string;
  memory_count: number;
  snapshot_ids: number[];
  drift_snapshot_id: number | null;
  created_by: unknown;
  auto_refresh: boolean;
}

/** Query for memories as they existed at a specific point in time. */
export interface AsOfQuery {
  system_time: string;
  valid_time: string;
  filter?: string;
}

/** Query for memories valid during a time range. */
export interface TemporalRangeQuery {
  from: string;
  to: string;
  mode: "overlaps" | "contains" | "started_during" | "ended_during";
}

/** Query for differences between two knowledge states. */
export interface TemporalDiffQuery {
  time_a: string;
  time_b: string;
  scope?: string;
}

/** Query for replaying a decision with historical context. */
export interface DecisionReplayQuery {
  decision_memory_id: string;
  budget?: number;
}

/** Query for temporal causal graph traversal. */
export interface TemporalCausalQuery {
  memory_id: string;
  as_of: string;
  direction: "forward" | "backward" | "both";
  max_depth: number;
}

// ─── Multi-Agent ─────────────────────────────────────────────────────────────

/** UUID-based agent identifier. */
export interface AgentId {
  /** The agent's unique identifier string (UUID or "default"). */
  0: string;
}

/** Agent lifecycle status. Tagged union discriminated by `state`. */
export type AgentStatus =
  | { state: "active" }
  | { state: "idle"; since: string }
  | { state: "deregistered"; at: string };

/** Full agent metadata stored in the registry. */
export interface AgentRegistration {
  /** Unique agent identifier. */
  agent_id: AgentId;
  /** Human-readable agent name. */
  name: string;
  /** The agent's home namespace URI. */
  namespace: string;
  /** Capabilities this agent advertises (e.g., "code_review", "testing"). */
  capabilities: string[];
  /** Parent agent if this was spawned. */
  parent_agent: AgentId | null;
  /** ISO 8601 timestamp of when this agent was registered. */
  registered_at: string;
  /** ISO 8601 timestamp of last heartbeat. */
  last_active: string;
  /** Current lifecycle status. */
  status: AgentStatus;
}

/** Namespace scope — determines visibility and default permissions. */
export type NamespaceScope =
  | { type: "agent"; value: AgentId }
  | { type: "team"; value: string }
  | { type: "project"; value: string };

/** A namespace identifier composed of a scope and a name. */
export interface NamespaceId {
  /** The scope determines visibility and default permissions. */
  scope: NamespaceScope;
  /** Human-readable namespace name. */
  name: string;
}

/** Permission levels for namespace access. */
export type NamespacePermission = "read" | "write" | "share" | "admin";

/** Access control list for a namespace. */
export interface NamespaceACL {
  /** The namespace this ACL applies to. */
  namespace: NamespaceId;
  /** Permission grants: [agent_id, permissions][]. */
  grants: Array<[AgentId, NamespacePermission[]]>;
}

/** Filter criteria for memory projections. */
export interface ProjectionFilter {
  /** Only include these memory types (empty = all). */
  memory_types: string[];
  /** Minimum confidence threshold. */
  min_confidence: number | null;
  /** Minimum importance level. */
  min_importance: string | null;
  /** Only include memories linked to these files. */
  linked_files: string[];
  /** Only include memories with these tags. */
  tags: string[];
  /** Maximum age in days. */
  max_age_days: number | null;
  /** Custom predicate expression (future use). */
  predicate: string | null;
}

/** A projection from one namespace to another with optional filtering. */
export interface ProjectionConfig {
  /** Unique projection identifier. */
  id: string;
  /** Source namespace to project from. */
  source: NamespaceId;
  /** Target namespace to project into. */
  target: NamespaceId;
  /** Filter criteria for which memories to include. */
  filter: ProjectionFilter;
  /** Compression level for projected memories (0–3). */
  compression_level: number;
  /** Whether this projection is live (auto-syncs on changes). */
  live: boolean;
  /** ISO 8601 timestamp of when this projection was created. */
  created_at: string;
  /** Agent that created this projection. */
  created_by: AgentId;
}

/** How a memory was originally created. */
export type ProvenanceOrigin =
  | { type: "human" }
  | { type: "agent_created" }
  | { type: "derived" }
  | { type: "imported" }
  | { type: "projected" };

/** Actions that can appear in a provenance chain. */
export type ProvenanceAction =
  | "created"
  | "shared_to"
  | "projected_to"
  | "merged_with"
  | "consolidated_from"
  | "validated_by"
  | "used_in_decision"
  | "corrected_by"
  | "reclassified_from"
  | "retracted";

/** A single hop in the provenance chain. */
export interface ProvenanceHop {
  /** The agent that performed this action. */
  agent_id: AgentId;
  /** What action was taken. */
  action: ProvenanceAction;
  /** ISO 8601 timestamp of when this hop occurred. */
  timestamp: string;
  /** Change in confidence at this hop (range: -1.0 to 1.0). */
  confidence_delta: number;
}

/** Full provenance record for a memory. */
export interface ProvenanceRecord {
  /** The memory this provenance record belongs to. */
  memory_id: string;
  /** How this memory was originally created. */
  origin: ProvenanceOrigin;
  /** Chain of custody hops (ordered, oldest first). */
  chain: ProvenanceHop[];
  /** Cumulative confidence through the chain. */
  chain_confidence: number;
}

/** Accumulated evidence for trust computation. */
export interface TrustEvidence {
  /** Number of memories validated as correct. */
  validated_count: number;
  /** Number of memories that contradicted known facts. */
  contradicted_count: number;
  /** Number of memories that were useful in decisions. */
  useful_count: number;
  /** Total memories received from the target agent. */
  total_received: number;
}

/** Trust relationship from one agent toward another. */
export interface AgentTrust {
  /** The agent holding this trust assessment. */
  agent_id: AgentId;
  /** The agent being assessed. */
  target_agent: AgentId;
  /** Overall trust score in [0.0, 1.0]. */
  overall_trust: number;
  /** Per-domain trust scores (domain name → score). */
  domain_trust: Record<string, number>;
  /** Evidence supporting this trust assessment. */
  evidence: TrustEvidence;
  /** ISO 8601 timestamp of when this trust was last updated. */
  last_updated: string;
}

/** How a cross-agent contradiction is resolved. */
export type ContradictionResolution =
  | { strategy: "trust_wins" }
  | { strategy: "needs_human_review" }
  | { strategy: "context_dependent" }
  | { strategy: "temporal_supersession" };

/** A detected contradiction between two agents' memories. */
export interface CrossAgentContradiction {
  /** First memory in the contradiction. */
  memory_a: string;
  /** Agent that owns memory_a. */
  agent_a: AgentId;
  /** Trust score of agent_a. */
  trust_a: number;
  /** Second memory in the contradiction. */
  memory_b: string;
  /** Agent that owns memory_b. */
  agent_b: AgentId;
  /** Trust score of agent_b. */
  trust_b: number;
  /** Type of contradiction. */
  contradiction_type: string;
  /** How this contradiction was or should be resolved. */
  resolution: ContradictionResolution;
}

/** A single hop in a cross-agent causal trace. */
export interface CrossAgentHop {
  /** The agent at this hop. */
  agent_id: string;
  /** The memory at this hop. */
  memory_id: string;
  /** Confidence/strength at this hop. */
  confidence: number;
}

/** Result of a cross-agent causal trace. */
export interface CrossAgentTrace {
  /** Ordered path of agent/memory hops in the trace. */
  path: CrossAgentHop[];
}

/** Result of a multi-agent sync operation. */
export interface MultiAgentSyncResult {
  /** Number of deltas applied during sync. */
  applied_count: number;
  /** Number of deltas buffered (waiting for causal predecessors). */
  buffered_count: number;
  /** Error messages encountered during sync (empty on success). */
  errors: string[];
}

// ─── Error Codes ─────────────────────────────────────────────────────────────

export const CortexErrorCode = {
  MULTI_AGENT_ERROR: "MULTI_AGENT_ERROR",
  MEMORY_NOT_FOUND: "MEMORY_NOT_FOUND",
  INVALID_TYPE: "INVALID_TYPE",
  EMBEDDING_ERROR: "EMBEDDING_ERROR",
  STORAGE_ERROR: "STORAGE_ERROR",
  CAUSAL_CYCLE: "CAUSAL_CYCLE",
  TOKEN_BUDGET_EXCEEDED: "TOKEN_BUDGET_EXCEEDED",
  MIGRATION_ERROR: "MIGRATION_ERROR",
  SANITIZATION_ERROR: "SANITIZATION_ERROR",
  CONSOLIDATION_ERROR: "CONSOLIDATION_ERROR",
  VALIDATION_ERROR: "VALIDATION_ERROR",
  SERIALIZATION_ERROR: "SERIALIZATION_ERROR",
  CONCURRENCY_ERROR: "CONCURRENCY_ERROR",
  CLOUD_SYNC_ERROR: "CLOUD_SYNC_ERROR",
  CONFIG_ERROR: "CONFIG_ERROR",
  DEGRADED_MODE: "DEGRADED_MODE",
  RUNTIME_NOT_INITIALIZED: "RUNTIME_NOT_INITIALIZED",
} as const;

export type CortexErrorCodeType = (typeof CortexErrorCode)[keyof typeof CortexErrorCode];

// ─── MCP Tool Definition ─────────────────────────────────────────────────────

export interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: "object";
    properties: Record<string, unknown>;
    required?: string[];
  };
  handler: (args: Record<string, unknown>) => Promise<unknown>;
}
