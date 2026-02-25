/**
 * @drift/cortex — Public API
 *
 * Cortex persistent memory system: 61 MCP tools + CLI over Rust NAPI bindings.
 */

// Bridge
export { CortexClient, CortexError } from "./bridge/client.js";
export type { CortexInitOptions } from "./bridge/client.js";
export { loadNativeModule, getNativeModule, isNativeModuleLoaded } from "./bridge/index.js";
export type { NativeBindings } from "./bridge/index.js";

// Types — re-export everything
export type {
  // Enums
  MemoryType,
  Importance,
  HealthStatus,
  HealingActionType,
  RelationshipType,
  Intent,
  CortexErrorCodeType,
  // Links
  PatternLink,
  ConstraintLink,
  FileLink,
  FunctionLink,
  // Content variants
  TypedContent,
  CoreContent,
  TribalContent,
  ProceduralStep,
  ProceduralContent,
  SemanticContent,
  EpisodicContent,
  Alternative,
  DecisionContent,
  InsightContent,
  ReferenceContent,
  PreferenceContent,
  PatternRationaleContent,
  ConstraintOverrideContent,
  DecisionContextContent,
  CodeSmellContent,
  AgentSpawnContent,
  EntityContent,
  GoalContent,
  FeedbackContent,
  WorkflowStep,
  WorkflowContent,
  ConversationContent,
  IncidentContent,
  MeetingContent,
  SkillContent,
  EnvironmentContent,
  // Core models
  BaseMemory,
  RetrievalContext,
  CompressedMemory,
  CausalNarrative,
  NarrativeSection,
  TraversalNode,
  TraversalResult,
  InferenceResult,
  ConsolidationMetrics,
  ConsolidationResult,
  ConsolidationStatus,
  ConsolidationDashboard,
  LearningResult,
  DimensionScores,
  HealingAction,
  ValidationResult,
  SubsystemHealth,
  HealthMetrics,
  HealthReport,
  SessionContext,
  SessionAnalytics,
  PredictionResult,
  PreloadResult,
  CacheStats,
  BudgetAllocation,
  GenerationContext,
  SanitizeResult,
  PatternFailure,
  PatternStats,
  SyncResult,
  CloudStatus,
  DegradationEvent,
  RelationshipEdge,
  WhyEntry,
  WhyContext,
  McpToolDefinition,
  // Temporal types (CX-FIX-11)
  MaterializedTemporalView,
  TemporalDiff,
  DriftSnapshot,
  DriftAlert,
  DecisionReplay,
  // Multi-agent types (CX-FIX-12)
  AgentRegistration,
  AgentTrust,
  ProvenanceRecord,
  ProvenanceHop,
  CrossAgentTrace,
  ProjectionConfig,
  ProjectionFilter,
  MultiAgentSyncResult,
  NamespaceScope,
  NamespaceId,
  NamespaceACL,
  NamespacePermission,
  AgentId,
} from "./bridge/types.js";

export { CortexErrorCode } from "./bridge/types.js";

// Tool registry
export { registerTools, listTools, callTool } from "./tools/index.js";
export type { ToolRegistry } from "./tools/index.js";
