# Audit System (Health Scoring, Degradation, Auto-Approve) — V2 Implementation Prep

> Comprehensive build specification for Drift v2's Audit System (System 25).
> Synthesized from: 09-quality-gates/audit.md (AuditEngine pipeline, health score formula,
> duplicate detection, cross-validation, recommendation engine, auto-approve criteria,
> AuditStore persistence, degradation tracking with alerts/trends/history),
> DRIFT-V2-FULL-SYSTEM-AUDIT.md (Cat 09 — Audit System GA3, health scoring weights,
> Jaccard similarity, cross-validation, degradation 90-day history, 7-day rolling averages,
> v2 additions: trend prediction, anomaly detection, per-category health breakdown),
> DRIFT-V2-STACK-HIERARCHY.md (Level 3 — Enforcement, consumes patterns/confidence/outliers,
> produces "your codebase is drifting" signal, D5 event emission for bridge propagation),
> DRIFT-V2-SYSTEMS-REFERENCE.md (Audit System TOC entry),
> PLANNING-DRIFT.md (D1 standalone, D5 event system, D7 Cortex grounding),
> cortex-observability/src/health/ (HealthChecker, HealthReporter, HealthSnapshot,
> SubsystemChecker — 5 subsystem checks, DriftSummary, TrendIndicator, recommendations),
> cortex-observability/src/degradation/ (DegradationTracker, TrackedDegradation,
> RecoveryStatus, alerting with AlertLevel/DegradationAlert, evaluate_alerts),
> cortex-observability/src/engine.rs (ObservabilityEngine orchestrator),
> cortex-observability/src/metrics/ (MetricsCollector — 5 domain collectors),
> cortex-observability/src/tracing_setup/events.rs (degradation_triggered structured event),
> cortex-core/src/models/audit_entry.rs (AuditEntry, AuditOperation — 10 ops, AuditActor — 7),
> cortex-core/src/models/health_report.rs (HealthReport, HealthStatus, SubsystemHealth, HealthMetrics),
> cortex-core/src/models/degradation_event.rs (DegradationEvent — component/failure/fallback),
> cortex-core/src/traits/health_reporter.rs (IHealthReporter trait),
> cortex-storage/src/migrations/v006_audit_tables.rs (memory_audit_log, consolidation_metrics,
> degradation_log — 3 tables, 4 indexes),
> cortex-storage/src/queries/audit_ops.rs (insert_audit_entry, query_by_memory,
> query_by_time_range, query_by_actor — with temporal event emission),
> cortex-storage/tests/integration/audit_test.rs (audit log on create/update/delete),
> cortex-napi/src/bindings/health.rs (cortex_health_get_health, cortex_health_get_metrics,
> cortex_health_get_degradations — 3 NAPI functions),
> cortex-napi/src/conversions/health_types.rs (health_report_to_json, degradation_events_to_json),
> 03-NAPI-BRIDGE-V2-PREP.md (§10.11 run_audit/query_health_trends, §9 batch API,
> §15 bindings/audit.rs, §12 dna_types.rs, §18 v1 feature verification),
> 02-STORAGE-V2-PREP.md (drift.db schema, materialized_status table),
> 09-quality-gates/types.md (GateResult, GateViolation, HealthSnapshot, GateInput),
> 09-quality-gates/store.md (SnapshotStore, GateRunStore, branch-based organization),
> 09-quality-gates/overview.md (6 gates, 4 policies, 4 aggregation modes, scoring system),
> 09-quality-gates/policy.md (progressive enforcement, scope-aware policies),
> 04-INFRASTRUCTURE-V2-PREP.md (thiserror, tracing, DriftEventHandler, FxHashMap),
> 10-BAYESIAN-CONFIDENCE-SCORING-V2-PREP.md (Bayesian posterior, momentum, tiers),
> 11-OUTLIER-DETECTION-V2-PREP.md (Z-Score, IQR, Grubbs, rule-based),
> 12-PATTERN-AGGREGATION-V2-PREP.md (pattern lifecycle, approval workflow),
> 13-LEARNING-SYSTEM-V2-PREP.md (convention learning, dominance thresholds),
> internet research on health scoring algorithms, anomaly detection, and trend prediction.
>
> Purpose: Everything needed to build the Audit System from scratch in Rust.
> Every v1 feature accounted for. Zero feature loss. Every algorithm defined.
> Every type modeled. Every integration point documented. Every threshold preserved.
> The Audit System is the "your codebase is drifting" signal — the core value
> proposition of Drift. It consumes data from nearly every other subsystem and
> produces the single most actionable output: health scores, degradation alerts,
> auto-approve decisions, and trend analysis that tell developers whether their
> codebase conventions are holding or eroding.
> Generated: 2026-02-08

---

## Table of Contents

1. Architectural Position
2. V1 Complete Feature Inventory
3. V2 Architecture — Unified Audit Engine
4. Core Data Model (Rust Types)
5. Phase 1: Audit Pipeline — Pattern Collection & Filtering
6. Phase 2: Duplicate Detection (Jaccard Similarity)
7. Phase 3: Cross-Validation Engine
8. Phase 4: Recommendation Engine (Auto-Approve, Review, Likely-FP)
9. Phase 5: Health Score Calculation (5-Factor Weighted Formula)
10. Phase 6: Per-Category Health Breakdown (V2 Addition)
11. Phase 7: Degradation Detection & Alerting
12. Phase 8: Trend Analysis (7-Day Rolling Averages)
13. Phase 9: Trend Prediction (V2 Addition — Linear Regression)
14. Phase 10: Anomaly Detection (V2 Addition — Statistical Outliers)
15. Phase 11: Snapshot Persistence & History
16. Phase 12: Audit Summary Builder
17. Integration with Quality Gates
18. Integration with Violation Feedback Loop
19. Integration with Cortex Observability (Proven Patterns)
20. Integration with Cortex Grounding (D7 Bridge)
21. Storage Schema (drift.db Audit Tables)
22. NAPI Interface
23. MCP Tool Interface
24. CLI Interface
25. Event Interface (D5 DriftEventHandler)
26. Tracing & Observability
27. Configuration
28. Performance Targets & Benchmarks
29. Build Order & Dependencies
30. V1 → V2 Feature Cross-Reference
31. Inconsistencies & Decisions
32. Risk Register

---

## 1. Architectural Position

The Audit System is **Level 3 — Enforcement** in the Drift v2 stack hierarchy.
It sits alongside Quality Gates, Policy Engine, Rules Engine, and the Violation
Feedback Loop. It is the system that transforms raw analysis data into the
human-readable verdict: "your codebase is drifting."

Per DRIFT-V2-STACK-HIERARCHY.md:

> **Audit System** — Health scoring, degradation detection, auto-approve, snapshots.
> Consumes: Patterns, confidence, outliers.
> Importance: The "your codebase is drifting" signal. Core value prop.

Per DRIFT-V2-FULL-SYSTEM-AUDIT.md (GA3):

> P0. Health scoring weights preserved exactly. Duplicate detection via Jaccard
> similarity. Cross-validation: orphan patterns, high outlier ratio, low confidence
> approved, constraint alignment. Degradation tracking: 90-day history, 7-day
> rolling averages. V2 additions: trend prediction, anomaly detection, per-category
> health breakdown.

### What Lives Here
- AuditEngine: orchestrates the full audit pipeline (filter → dedup → cross-validate → recommend → score → degrade → trend)
- Health score calculation: 5-factor weighted formula producing 0-100 score
- Duplicate detection: Jaccard similarity on pattern location sets
- Cross-validation: 4 validation checks against external data sources
- Recommendation engine: auto-approve / review / likely-false-positive classification
- Degradation tracker: compares audits over time, detects quality regression
- Alert system: warning and critical thresholds for health drops, confidence drops, FP increases
- Trend analysis: 7-day rolling averages with improving/stable/declining classification
- Trend prediction: linear regression on health history (v2 addition)
- Anomaly detection: statistical outlier detection on audit metrics (v2 addition)
- Per-category health breakdown: health scores per pattern category (v2 addition)
- Snapshot persistence: daily snapshots with 90-day retention
- Audit summary builder: human-readable audit reports

### What Does NOT Live Here
- Pattern detection (lives in drift-core detectors — Level 2A)
- Confidence scoring (lives in drift-core Bayesian scorer — Level 2A)
- Outlier detection (lives in drift-core outlier engine — Level 2A)
- Quality gate evaluation (lives in quality gates — Level 3, separate system)
- Policy enforcement (lives in policy engine — Level 3, separate system)
- Violation tracking (lives in rules engine — Level 3, separate system)
- Cortex health reporting (lives in cortex-observability — separate crate)

### Dependency Chain
```
Level 2A (Patterns, Confidence, Outliers)
    ↓
Level 2B (Call Graph, Boundaries)
    ↓
Level 3 — Audit System
    ↓ consumes
    ├── Patterns (with confidence scores, locations, outliers)
    ├── Constraints (for cross-validation alignment)
    ├── Call Graph (for cross-validation: patterns in call graph)
    └── Previous Audit Snapshots (for degradation detection)
    ↓ produces
    ├── Health Score (0-100, consumed by Quality Gates, MCP, CLI, Dashboard)
    ├── Degradation Alerts (consumed by CLI, IDE, MCP)
    ├── Auto-Approve Decisions (consumed by Pattern Aggregation)
    ├── Trend Data (consumed by Dashboard, MCP drift_status)
    └── DriftEventHandler events (consumed by Cortex bridge)
```

### Relationship to Cortex Observability

The existing `cortex-observability` crate provides health reporting for Cortex's
memory system (storage, embeddings, causal graph, privacy, temporal subsystems).
The Drift Audit System is architecturally analogous but domain-different:

| Aspect | Cortex Observability | Drift Audit System |
|--------|---------------------|--------------------|
| Domain | Memory health | Codebase convention health |
| Health inputs | Memory counts, confidence, cache rates | Pattern confidence, compliance, duplicates |
| Subsystems | Storage, embeddings, causal, privacy, temporal | Patterns, constraints, security, test coverage, DNA |
| Degradation | Component failure → fallback tracking | Health score regression over time |
| Alerting | >3 events/hour → warning, >24h → critical | Health drop, confidence drop, FP increase |
| Persistence | In-memory tracker + degradation_log table | drift.db audit tables + daily snapshots |

**Key insight**: Drift's audit system borrows the degradation tracker/alerting
architecture from cortex-observability but applies it to a completely different
domain (codebase conventions vs memory system health). The health score formula,
duplicate detection, cross-validation, and recommendation engine are unique to Drift.

---

## 2. V1 Complete Feature Inventory

Every v1 feature must be accounted for in v2. Zero feature loss.

### 2.1 AuditEngine (audit-engine.ts)

| V1 Feature | Description | V2 Status |
|-----------|-------------|-----------|
| Pattern filtering by category | Optional category filter on audit input | **KEPT** — `AuditOptions.categories: Option<Vec<String>>` |
| Duplicate detection (Jaccard) | Location overlap analysis, threshold 0.85 | **KEPT** — exact algorithm preserved |
| Duplicate merge recommendation | similarity > 0.9 → merge, else review | **KEPT** — thresholds preserved |
| Cross-validation: orphan patterns | Patterns with no locations | **KEPT** |
| Cross-validation: high outlier ratio | Outliers > 50% of total | **KEPT** — threshold preserved |
| Cross-validation: low confidence approved | Approved patterns with confidence < 0.5 | **KEPT** |
| Cross-validation: constraint alignment | 1 - (issue_count / total_patterns) | **KEPT** |
| Per-pattern recommendations | auto-approve / review / likely-false-positive | **KEPT** — exact criteria preserved |
| Health score (5-factor weighted) | avgConf×0.30 + approval×0.20 + compliance×0.20 + crossVal×0.15 + dupFree×0.15 | **KEPT** — exact weights preserved |
| Audit summary generation | Human-readable summary with counts and scores | **KEPT** |

### 2.2 AuditStore (audit-store.ts)

| V1 Feature | Description | V2 Status |
|-----------|-------------|-----------|
| latest.json persistence | Current audit state | **UPGRADED** — drift.db `audit_snapshots` table |
| Snapshot history (30-day) | Daily snapshots in .drift/audit/snapshots/ | **UPGRADED** — drift.db, 90-day retention |
| degradation.json | Quality trend tracking | **UPGRADED** — drift.db `audit_degradation` table |
| Health drop alerts | Warning: -5pts, Critical: -15pts | **KEPT** — exact thresholds preserved |
| Confidence drop alerts | Warning: -5%, Critical: -15% | **KEPT** — exact thresholds preserved |
| New false positive alerts | Warning: >5, Critical: >10 | **KEPT** — exact thresholds preserved |
| Duplicate increase alerts | Warning: >3 groups | **KEPT** |
| 7-day rolling average trends | Health, confidence, pattern growth | **KEPT** — exact algorithm preserved |
| Trend classification | improving / stable / declining (±2 threshold) | **KEPT** — exact thresholds preserved |
| Pattern growth classification | healthy / rapid (>5/day) / stagnant (<0.5/day) | **KEPT** — exact thresholds preserved |
| 90-day history retention | Daily entries for trend analysis | **KEPT** |

### 2.3 Configuration (v1)

| V1 Feature | Description | V2 Status |
|-----------|-------------|-----------|
| autoApproveThreshold: 0.90 | Confidence for auto-approval | **KEPT** |
| reviewThreshold: 0.70 | Confidence for review | **KEPT** |
| duplicateSimilarityThreshold: 0.85 | Jaccard similarity for duplicates | **KEPT** |
| minLocationsForEstablished: 3 | Min locations for established pattern | **KEPT** |
| maxOutlierRatio: 0.5 | Max outlier ratio before flagging | **KEPT** |

### 2.4 V2 Additions (New Features)

| New Feature | Source | Description |
|------------|--------|-------------|
| Trend prediction | GA3, v2 additions | Linear regression on health history for forecasting |
| Anomaly detection | GA3, v2 additions | Statistical outlier detection on audit metrics |
| Per-category health breakdown | GA3, v2 additions | Health scores per pattern category (16 categories) |
| Rust-native duplicate detection | 09-quality-gates/audit.md v2 notes | Move Jaccard to Rust for large pattern sets |
| Auto-merge threshold | GA3 | Jaccard > 0.95 → auto-merge (upgraded from 0.9) |
| Bayesian confidence integration | AD8 | Health score uses Bayesian posterior instead of static confidence |
| DriftEventHandler events | D5 | on_audit_complete, on_health_degraded, on_pattern_auto_approved |
| SQLite-native persistence | 02-STORAGE-V2-PREP | All audit data in drift.db, no JSON files |
| Materialized status integration | 02-STORAGE-V2-PREP | Health score feeds materialized_status singleton |

---

## 3. V2 Architecture — Unified Audit Engine

### Design Philosophy

The v1 audit system was split across two TypeScript files: `audit-engine.ts`
(computation) and `audit-store.ts` (persistence + degradation). In v2, the
entire audit pipeline moves to Rust as a single `AuditEngine` that owns the
full lifecycle: collect → validate → score → degrade → persist → report.

The TypeScript layer becomes a thin orchestration wrapper that calls
`run_audit()` via NAPI and renders the results.

### Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        AuditEngine                               │
│  (drift-core/src/audit/engine.rs — main orchestrator)           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Phase 1: Collect & Filter                                       │
│  ├── Load patterns from drift.db (with confidence, locations)    │
│  ├── Optional category filter                                    │
│  └── Build pattern index (FxHashMap<PatternId, PatternData>)     │
│                                                                  │
│  Phase 2: Duplicate Detection                                    │
│  ├── Jaccard similarity on location sets (same-category only)    │
│  ├── Threshold: 0.85 (configurable)                              │
│  ├── Group duplicates into DuplicateGroup[]                      │
│  └── Classify: merge (>0.95) / review (0.85-0.95)               │
│                                                                  │
│  Phase 3: Cross-Validation                                       │
│  ├── Orphan check: patterns with 0 locations                     │
│  ├── Outlier ratio check: outliers > maxOutlierRatio             │
│  ├── Low confidence approved: approved AND confidence < 0.5      │
│  ├── Constraint alignment: 1 - (issues / total)                  │
│  └── Call graph coverage: patterns in call graph / total          │
│                                                                  │
│  Phase 4: Recommendation Engine                                  │
│  ├── auto-approve: conf≥0.90 ∧ outlier≤0.50 ∧ locs≥3 ∧ no err  │
│  ├── review: conf≥0.70 (but not auto-approve)                   │
│  ├── likely-false-positive: conf<0.70 ∨ outlier>0.50            │
│  └── Duplicate membership downgrades auto-approve → review       │
│                                                                  │
│  Phase 5: Health Score                                           │
│  ├── 5-factor weighted formula → [0, 100]                        │
│  └── Per-category breakdown (v2 addition)                        │
│                                                                  │
│  Phase 6: Degradation Detection                                  │
│  ├── Compare against previous snapshot                           │
│  ├── Generate alerts (warning / critical)                        │
│  ├── Calculate trends (7-day rolling average)                    │
│  ├── Predict future trend (linear regression, v2)                │
│  └── Detect anomalies (statistical outliers, v2)                 │
│                                                                  │
│  Phase 7: Persist & Report                                       │
│  ├── Save snapshot to drift.db                                   │
│  ├── Update materialized_status                                  │
│  ├── Emit DriftEventHandler events                               │
│  └── Build AuditResult summary                                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Module Structure

```
crates/drift-core/src/audit/
├── mod.rs                  # Re-exports, AuditEngine public API
├── engine.rs               # AuditEngine orchestrator (pipeline phases 1-7)
├── config.rs               # AuditConfig with all thresholds
├── types.rs                # AuditResult, AuditSnapshot, PatternAuditData, etc.
├── duplicate_detection.rs  # Jaccard similarity, DuplicateGroup
├── cross_validation.rs     # 4 validation checks + constraint alignment
├── recommendations.rs      # Auto-approve / review / likely-FP classification
├── health_score.rs         # 5-factor weighted formula + per-category breakdown
├── degradation.rs          # DegradationDetector: alerts, trends, prediction, anomaly
├── trend_analysis.rs       # 7-day rolling averages, trend classification
├── trend_prediction.rs     # Linear regression on health history (v2)
├── anomaly_detection.rs    # Statistical outlier detection on metrics (v2)
├── snapshot.rs             # Snapshot persistence, history queries, retention
└── summary.rs              # Human-readable audit summary builder
```


---

## 4. Core Data Model (Rust Types)

### 4.1 Audit Result (Top-Level Output)

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Complete result of an audit run. Returned by `run_audit()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditResult {
    /// Unique audit run identifier.
    pub run_id: String,
    /// When the audit was executed.
    pub timestamp: DateTime<Utc>,
    /// Overall health score [0, 100].
    pub health_score: f64,
    /// Health score breakdown by factor.
    pub health_breakdown: HealthBreakdown,
    /// Per-category health scores (v2 addition).
    pub category_health: FxHashMap<String, CategoryHealth>,
    /// Patterns that qualify for auto-approval.
    pub auto_approved: Vec<PatternRecommendation>,
    /// Patterns that need human review.
    pub needs_review: Vec<PatternRecommendation>,
    /// Patterns likely to be false positives.
    pub likely_false_positives: Vec<PatternRecommendation>,
    /// Duplicate pattern groups detected.
    pub duplicate_groups: Vec<DuplicateGroup>,
    /// Cross-validation issues found.
    pub cross_validation_issues: Vec<CrossValidationIssue>,
    /// Degradation alerts (if previous snapshot exists).
    pub degradation_alerts: Vec<DegradationAlert>,
    /// Current trend indicators.
    pub trends: AuditTrends,
    /// Trend prediction (v2 addition).
    pub prediction: Option<TrendPrediction>,
    /// Anomalies detected (v2 addition).
    pub anomalies: Vec<AuditAnomaly>,
    /// Summary statistics.
    pub summary: AuditSummary,
    /// Duration of the audit run in milliseconds.
    pub duration_ms: u32,
}
```

### 4.2 Health Score Types

```rust
/// Breakdown of the 5-factor health score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthBreakdown {
    /// Average pattern confidence [0.0, 1.0]. Weight: 0.30.
    pub avg_confidence: f64,
    /// Approved patterns / total patterns [0.0, 1.0]. Weight: 0.20.
    pub approval_ratio: f64,
    /// Locations / (locations + outliers) [0.0, 1.0]. Weight: 0.20.
    pub compliance_rate: f64,
    /// Patterns in call graph / total patterns [0.0, 1.0]. Weight: 0.15.
    pub cross_validation_rate: f64,
    /// 1 - (patterns in duplicate groups / total) [0.0, 1.0]. Weight: 0.15.
    pub duplicate_free_rate: f64,
    /// The computed score before scaling to [0, 100].
    pub raw_score: f64,
}

/// Per-category health score (v2 addition).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryHealth {
    /// Category name (one of 16 detection categories).
    pub category: String,
    /// Health score for this category [0, 100].
    pub score: f64,
    /// Number of patterns in this category.
    pub pattern_count: usize,
    /// Average confidence for patterns in this category.
    pub avg_confidence: f64,
    /// Compliance rate for this category.
    pub compliance_rate: f64,
    /// Trend for this category.
    pub trend: TrendDirection,
}
```

### 4.3 Pattern Audit Data (Internal)

```rust
/// Internal representation of a pattern during audit processing.
/// Loaded from drift.db, enriched during the pipeline.
#[derive(Debug, Clone)]
pub struct PatternAuditData {
    pub id: String,
    pub name: String,
    pub category: String,
    pub status: PatternStatus,
    pub confidence: f64,
    /// Bayesian posterior parameters (v2).
    pub alpha: f64,
    pub beta: f64,
    pub locations: Vec<PatternLocation>,
    pub outlier_count: usize,
    pub total_location_count: usize,
    /// Whether this pattern appears in the call graph.
    pub in_call_graph: bool,
    /// Whether this pattern has constraint alignment issues.
    pub constraint_issues: usize,
    /// Whether this pattern has error-level issues.
    pub has_error_issues: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PatternStatus {
    Discovered,
    Approved,
    Ignored,
}

/// A pattern's file:line location for Jaccard comparison.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct PatternLocation {
    pub file: String,
    pub line: u32,
}
```

### 4.4 Duplicate Detection Types

```rust
/// A group of patterns detected as duplicates via Jaccard similarity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateGroup {
    /// IDs of patterns in this group.
    pub pattern_ids: Vec<String>,
    /// Pairwise similarity scores.
    pub similarities: Vec<DuplicatePair>,
    /// Recommended action for the group.
    pub recommendation: DuplicateAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicatePair {
    pub pattern_a: String,
    pub pattern_b: String,
    pub similarity: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DuplicateAction {
    /// Similarity > 0.95 — safe to auto-merge.
    AutoMerge,
    /// Similarity > 0.90 — recommend merge.
    Merge,
    /// Similarity 0.85-0.90 — needs human review.
    Review,
}
```

### 4.5 Cross-Validation Types

```rust
/// An issue found during cross-validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossValidationIssue {
    pub pattern_id: String,
    pub issue_type: CrossValidationIssueType,
    pub message: String,
    pub severity: IssueSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossValidationIssueType {
    /// Pattern has zero locations.
    OrphanPattern,
    /// Outlier ratio exceeds threshold.
    HighOutlierRatio,
    /// Approved pattern with confidence below 0.5.
    LowConfidenceApproved,
    /// Pattern conflicts with architectural constraints.
    ConstraintMisalignment,
    /// Pattern not found in call graph (weak cross-validation).
    NotInCallGraph,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IssueSeverity {
    Info,
    Warning,
    Error,
}
```

### 4.6 Recommendation Types

```rust
/// A recommendation for a specific pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternRecommendation {
    pub pattern_id: String,
    pub pattern_name: String,
    pub category: String,
    pub confidence: f64,
    pub recommendation: RecommendationType,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationType {
    AutoApprove,
    Review,
    LikelyFalsePositive,
}
```

### 4.7 Degradation & Trend Types

```rust
/// Alert generated when audit metrics degrade.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradationAlert {
    pub alert_type: DegradationAlertType,
    pub level: AlertLevel,
    pub message: String,
    pub current_value: f64,
    pub previous_value: f64,
    pub delta: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradationAlertType {
    HealthDrop,
    ConfidenceDrop,
    NewFalsePositives,
    DuplicateIncrease,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertLevel {
    Warning,
    Critical,
}

/// Trend indicators for audit metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTrends {
    /// Health score trend over 7-day rolling average.
    pub health_trend: TrendDirection,
    /// Confidence trend over 7-day rolling average.
    pub confidence_trend: TrendDirection,
    /// Pattern growth classification.
    pub pattern_growth: PatternGrowth,
    /// Per-category trends (v2 addition).
    pub category_trends: FxHashMap<String, TrendDirection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrendDirection {
    Improving,
    Stable,
    Declining,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PatternGrowth {
    /// < 0.5 patterns/day.
    Stagnant,
    /// 0.5-5.0 patterns/day.
    Healthy,
    /// > 5.0 patterns/day.
    Rapid,
}
```

### 4.8 Trend Prediction Types (V2 Addition)

```rust
/// Predicted future trend based on linear regression over health history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendPrediction {
    /// Predicted health score 7 days from now.
    pub predicted_health_7d: f64,
    /// Predicted health score 30 days from now.
    pub predicted_health_30d: f64,
    /// Slope of the regression line (points per day).
    pub slope_per_day: f64,
    /// R² goodness of fit [0.0, 1.0]. Below 0.5 = low confidence.
    pub r_squared: f64,
    /// Confidence in the prediction.
    pub confidence: PredictionConfidence,
    /// Days until health score crosses warning threshold (70), if declining.
    pub days_to_warning: Option<u32>,
    /// Days until health score crosses critical threshold (50), if declining.
    pub days_to_critical: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PredictionConfidence {
    /// R² ≥ 0.7 and ≥ 14 data points.
    High,
    /// R² ≥ 0.5 and ≥ 7 data points.
    Medium,
    /// R² < 0.5 or < 7 data points.
    Low,
}
```

### 4.9 Anomaly Detection Types (V2 Addition)

```rust
/// An anomaly detected in audit metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditAnomaly {
    pub metric: AnomalyMetric,
    pub value: f64,
    pub expected_range: (f64, f64),
    pub z_score: f64,
    pub severity: IssueSeverity,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyMetric {
    HealthScore,
    AvgConfidence,
    ComplianceRate,
    DuplicateCount,
    FalsePositiveCount,
    PatternCount,
    OutlierRatio,
}
```

### 4.10 Audit Snapshot (Persistence)

```rust
/// A point-in-time snapshot of audit state, persisted to drift.db.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSnapshot {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub health_score: f64,
    pub avg_confidence: f64,
    pub total_patterns: usize,
    pub approved_patterns: usize,
    pub discovered_patterns: usize,
    pub ignored_patterns: usize,
    pub total_locations: usize,
    pub total_outliers: usize,
    pub duplicate_group_count: usize,
    pub false_positive_count: usize,
    pub cross_validation_score: f64,
    /// Per-category scores serialized as JSON.
    pub category_scores: serde_json::Value,
    /// Degradation alerts serialized as JSON.
    pub alerts: serde_json::Value,
}

/// Summary statistics for the audit report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSummary {
    pub total_patterns: usize,
    pub patterns_by_status: PatternStatusCounts,
    pub patterns_by_category: FxHashMap<String, usize>,
    pub total_locations: usize,
    pub total_outliers: usize,
    pub compliance_rate: f64,
    pub duplicate_groups: usize,
    pub cross_validation_issues: usize,
    pub auto_approved_count: usize,
    pub needs_review_count: usize,
    pub likely_fp_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternStatusCounts {
    pub discovered: usize,
    pub approved: usize,
    pub ignored: usize,
}
```


---

## 5. Phase 1: Audit Pipeline — Pattern Collection & Filtering

### Input

The audit engine receives patterns from drift.db. It does NOT re-run detection —
it operates on the most recent detection results already persisted.

```rust
impl AuditEngine {
    /// Run a full audit. This is the main entry point.
    pub fn run_audit(
        &self,
        db: &DatabaseManager,
        config: &AuditConfig,
        event_handler: &dyn DriftEventHandler,
    ) -> Result<AuditResult, AuditError> {
        let start = std::time::Instant::now();
        let run_id = generate_run_id();

        // Phase 1: Collect patterns from drift.db.
        let mut patterns = self.load_patterns(db, &config.categories)?;

        // Phase 2: Detect duplicates.
        let duplicate_groups = self.detect_duplicates(&patterns, config)?;

        // Phase 3: Cross-validate.
        let cv_issues = self.cross_validate(&patterns, db, config)?;

        // Phase 4: Generate recommendations.
        let recommendations = self.recommend(&patterns, &duplicate_groups, config)?;

        // Phase 5: Calculate health score.
        let (health_score, breakdown) = self.calculate_health(
            &patterns, &duplicate_groups, &cv_issues, config,
        )?;

        // Phase 5b: Per-category health breakdown (v2).
        let category_health = self.calculate_category_health(&patterns, config)?;

        // Phase 6: Degradation detection.
        let previous = self.load_latest_snapshot(db)?;
        let degradation = self.detect_degradation(
            health_score, &breakdown, &recommendations, &previous, config,
        )?;

        // Phase 6b: Trend analysis.
        let history = self.load_snapshot_history(db, 90)?;
        let trends = self.analyze_trends(&history, config)?;

        // Phase 6c: Trend prediction (v2).
        let prediction = self.predict_trend(&history)?;

        // Phase 6d: Anomaly detection (v2).
        let anomalies = self.detect_anomalies(&history, health_score, &breakdown)?;

        // Phase 7: Persist snapshot.
        let snapshot = self.build_snapshot(
            &run_id, health_score, &breakdown, &patterns,
            &duplicate_groups, &recommendations, &category_health,
            &degradation,
        );
        self.save_snapshot(db, &snapshot)?;
        self.update_materialized_status(db, &snapshot)?;
        self.enforce_retention(db, config.history_retention_days)?;

        // Phase 7b: Emit events.
        event_handler.on_audit_complete(&AuditCompleteEvent {
            run_id: run_id.clone(),
            health_score,
            alert_count: degradation.len(),
            auto_approved_count: recommendations.auto_approved.len(),
        });

        if degradation.iter().any(|a| a.level == AlertLevel::Critical) {
            event_handler.on_health_degraded(&HealthDegradedEvent {
                health_score,
                alerts: degradation.clone(),
            });
        }

        for rec in &recommendations.auto_approved {
            event_handler.on_pattern_auto_approved(&PatternAutoApprovedEvent {
                pattern_id: rec.pattern_id.clone(),
                confidence: rec.confidence,
            });
        }

        // Build result.
        Ok(AuditResult {
            run_id,
            timestamp: Utc::now(),
            health_score,
            health_breakdown: breakdown,
            category_health,
            auto_approved: recommendations.auto_approved,
            needs_review: recommendations.needs_review,
            likely_false_positives: recommendations.likely_fps,
            duplicate_groups,
            cross_validation_issues: cv_issues,
            degradation_alerts: degradation,
            trends,
            prediction,
            anomalies,
            summary: self.build_summary(&patterns, &recommendations, &duplicate_groups, &cv_issues),
            duration_ms: start.elapsed().as_millis() as u32,
        })
    }
}
```

### Pattern Loading

```rust
/// Load patterns from drift.db with optional category filter.
fn load_patterns(
    &self,
    db: &DatabaseManager,
    categories: &Option<Vec<String>>,
) -> Result<Vec<PatternAuditData>, AuditError> {
    db.read(|conn| {
        let mut query = String::from(
            "SELECT p.id, p.name, p.category, p.status, p.confidence,
                    p.alpha, p.beta, p.has_error_issues,
                    COUNT(DISTINCT pl.id) as location_count,
                    COUNT(DISTINCT CASE WHEN pl.is_outlier = 1 THEN pl.id END) as outlier_count,
                    EXISTS(SELECT 1 FROM call_graph_patterns cgp WHERE cgp.pattern_id = p.id) as in_call_graph,
                    (SELECT COUNT(*) FROM constraint_issues ci WHERE ci.pattern_id = p.id) as constraint_issues
             FROM patterns p
             LEFT JOIN pattern_locations pl ON pl.pattern_id = p.id"
        );

        if let Some(cats) = categories {
            let placeholders: Vec<String> = cats.iter().enumerate()
                .map(|(i, _)| format!("?{}", i + 1))
                .collect();
            query.push_str(&format!(" WHERE p.category IN ({})", placeholders.join(",")));
        }

        query.push_str(" GROUP BY p.id ORDER BY p.category, p.name");

        // Execute and map rows to PatternAuditData...
        // (standard rusqlite query_map pattern)
    })
}
```

---

## 6. Phase 2: Duplicate Detection (Jaccard Similarity)

### Algorithm

Jaccard similarity measures the overlap between two sets:

```
J(A, B) = |A ∩ B| / |A ∪ B|
```

For patterns, the sets are file:line location tuples. Two patterns are
considered duplicates if their location sets have Jaccard similarity ≥ 0.85.

### Implementation

```rust
use rustc_hash::FxHashSet;

/// Detect duplicate patterns within the same category.
pub fn detect_duplicates(
    patterns: &[PatternAuditData],
    config: &AuditConfig,
) -> Vec<DuplicateGroup> {
    let mut groups: Vec<DuplicateGroup> = Vec::new();
    let mut assigned: FxHashSet<String> = FxHashSet::default();

    // Group patterns by category (only compare within same category).
    let by_category = group_by_category(patterns);

    for (_category, category_patterns) in &by_category {
        let n = category_patterns.len();
        if n < 2 {
            continue;
        }

        // Pre-compute location sets for O(1) lookup.
        let location_sets: Vec<FxHashSet<(String, u32)>> = category_patterns
            .iter()
            .map(|p| {
                p.locations
                    .iter()
                    .map(|loc| (loc.file.clone(), loc.line))
                    .collect()
            })
            .collect();

        // Pairwise comparison (O(n²) within category — acceptable for <1000 patterns).
        for i in 0..n {
            if assigned.contains(&category_patterns[i].id) {
                continue;
            }

            let mut group_ids = vec![category_patterns[i].id.clone()];
            let mut pairs = Vec::new();

            for j in (i + 1)..n {
                if assigned.contains(&category_patterns[j].id) {
                    continue;
                }

                let similarity = jaccard_similarity(&location_sets[i], &location_sets[j]);

                if similarity >= config.duplicate_similarity_threshold {
                    group_ids.push(category_patterns[j].id.clone());
                    pairs.push(DuplicatePair {
                        pattern_a: category_patterns[i].id.clone(),
                        pattern_b: category_patterns[j].id.clone(),
                        similarity,
                    });
                }
            }

            if group_ids.len() > 1 {
                let max_similarity = pairs.iter().map(|p| p.similarity).fold(0.0_f64, f64::max);
                let recommendation = if max_similarity > config.auto_merge_threshold {
                    DuplicateAction::AutoMerge
                } else if max_similarity > 0.90 {
                    DuplicateAction::Merge
                } else {
                    DuplicateAction::Review
                };

                for id in &group_ids {
                    assigned.insert(id.clone());
                }

                groups.push(DuplicateGroup {
                    pattern_ids: group_ids,
                    similarities: pairs,
                    recommendation,
                });
            }
        }
    }

    groups
}

/// Jaccard similarity between two sets.
fn jaccard_similarity(a: &FxHashSet<(String, u32)>, b: &FxHashSet<(String, u32)>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0; // Both empty = identical.
    }
    let intersection = a.intersection(b).count();
    let union = a.union(b).count();
    if union == 0 {
        return 0.0;
    }
    intersection as f64 / union as f64
}
```

### Performance Note

For N patterns per category, pairwise comparison is O(N²). With typical category
sizes of 10-100 patterns, this is negligible (<1ms). For extreme cases (>1000
patterns in a single category), consider locality-sensitive hashing (MinHash)
as a future optimization. The v1 implementation used the same O(N²) approach
and it was never a bottleneck.

---

## 7. Phase 3: Cross-Validation Engine

Cross-validation checks patterns against external data sources to identify
quality issues that confidence scoring alone cannot detect.

### Four Validation Checks

```rust
/// Run all cross-validation checks.
pub fn cross_validate(
    patterns: &[PatternAuditData],
    db: &DatabaseManager,
    config: &AuditConfig,
) -> Vec<CrossValidationIssue> {
    let mut issues = Vec::new();

    for pattern in patterns {
        // Check 1: Orphan patterns (no locations).
        if pattern.total_location_count == 0 {
            issues.push(CrossValidationIssue {
                pattern_id: pattern.id.clone(),
                issue_type: CrossValidationIssueType::OrphanPattern,
                message: format!(
                    "Pattern '{}' has no locations — may be stale or misconfigured",
                    pattern.name
                ),
                severity: IssueSeverity::Warning,
            });
        }

        // Check 2: High outlier ratio.
        if pattern.total_location_count > 0 {
            let outlier_ratio = pattern.outlier_count as f64 / pattern.total_location_count as f64;
            if outlier_ratio > config.max_outlier_ratio {
                issues.push(CrossValidationIssue {
                    pattern_id: pattern.id.clone(),
                    issue_type: CrossValidationIssueType::HighOutlierRatio,
                    message: format!(
                        "Pattern '{}' has {:.0}% outliers (threshold: {:.0}%)",
                        pattern.name,
                        outlier_ratio * 100.0,
                        config.max_outlier_ratio * 100.0,
                    ),
                    severity: IssueSeverity::Warning,
                });
            }
        }

        // Check 3: Low confidence approved.
        if pattern.status == PatternStatus::Approved && pattern.confidence < 0.5 {
            issues.push(CrossValidationIssue {
                pattern_id: pattern.id.clone(),
                issue_type: CrossValidationIssueType::LowConfidenceApproved,
                message: format!(
                    "Pattern '{}' is approved but confidence is {:.2} (below 0.50)",
                    pattern.name, pattern.confidence,
                ),
                severity: IssueSeverity::Error,
            });
        }

        // Check 4: Constraint misalignment.
        if pattern.constraint_issues > 0 {
            issues.push(CrossValidationIssue {
                pattern_id: pattern.id.clone(),
                issue_type: CrossValidationIssueType::ConstraintMisalignment,
                message: format!(
                    "Pattern '{}' has {} constraint alignment issues",
                    pattern.name, pattern.constraint_issues,
                ),
                severity: IssueSeverity::Warning,
            });
        }

        // Check 5: Not in call graph (weak signal — info only).
        if !pattern.in_call_graph && pattern.total_location_count > 0 {
            issues.push(CrossValidationIssue {
                pattern_id: pattern.id.clone(),
                issue_type: CrossValidationIssueType::NotInCallGraph,
                message: format!(
                    "Pattern '{}' has no call graph coverage — cross-validation limited",
                    pattern.name,
                ),
                severity: IssueSeverity::Info,
            });
        }
    }

    issues
}

/// Calculate the constraint alignment score.
/// Returns 1.0 - (issue_count / total_patterns), clamped to [0.0, 1.0].
pub fn constraint_alignment_score(
    issues: &[CrossValidationIssue],
    total_patterns: usize,
) -> f64 {
    if total_patterns == 0 {
        return 1.0;
    }
    let issue_count = issues
        .iter()
        .filter(|i| i.issue_type == CrossValidationIssueType::ConstraintMisalignment)
        .count();
    (1.0 - (issue_count as f64 / total_patterns as f64)).max(0.0)
}
```


---

## 8. Phase 4: Recommendation Engine (Auto-Approve, Review, Likely-FP)

### Decision Criteria (Preserved from V1)

The recommendation engine classifies each pattern into one of three buckets.
These criteria are the exact v1 thresholds — they are tuned and must be preserved.

| Recommendation | Criteria |
|---|---|
| `auto-approve` | confidence ≥ 0.90 AND outlierRatio ≤ 0.50 AND locations ≥ 3 AND no error-level issues |
| `review` | confidence ≥ 0.70 (but doesn't meet auto-approve criteria) |
| `likely-false-positive` | confidence < 0.70 OR outlierRatio > 0.50 |

**Special rule**: Patterns that are members of a duplicate group have their
`auto-approve` recommendation downgraded to `review`. Rationale: duplicates
indicate potential miscategorization that needs human judgment.

### Implementation

```rust
/// Classify patterns into auto-approve, review, and likely-false-positive.
pub fn recommend(
    patterns: &[PatternAuditData],
    duplicate_groups: &[DuplicateGroup],
    config: &AuditConfig,
) -> RecommendationResult {
    // Build set of pattern IDs that are in duplicate groups.
    let in_duplicate_group: FxHashSet<&str> = duplicate_groups
        .iter()
        .flat_map(|g| g.pattern_ids.iter().map(|s| s.as_str()))
        .collect();

    let mut auto_approved = Vec::new();
    let mut needs_review = Vec::new();
    let mut likely_fps = Vec::new();

    for pattern in patterns {
        // Skip already-approved or ignored patterns.
        if pattern.status != PatternStatus::Discovered {
            continue;
        }

        let outlier_ratio = if pattern.total_location_count > 0 {
            pattern.outlier_count as f64 / pattern.total_location_count as f64
        } else {
            1.0 // No locations = treat as 100% outlier.
        };

        let meets_auto_approve = pattern.confidence >= config.auto_approve_threshold
            && outlier_ratio <= config.max_outlier_ratio
            && pattern.total_location_count >= config.min_locations_for_established
            && !pattern.has_error_issues;

        let recommendation = if meets_auto_approve {
            if in_duplicate_group.contains(pattern.id.as_str()) {
                // Downgrade: duplicate membership → review.
                RecommendationType::Review
            } else {
                RecommendationType::AutoApprove
            }
        } else if pattern.confidence >= config.review_threshold {
            RecommendationType::Review
        } else {
            RecommendationType::LikelyFalsePositive
        };

        let reason = match recommendation {
            RecommendationType::AutoApprove => format!(
                "confidence={:.2}, outlierRatio={:.2}, locations={}, no errors",
                pattern.confidence, outlier_ratio, pattern.total_location_count,
            ),
            RecommendationType::Review => {
                if in_duplicate_group.contains(pattern.id.as_str()) {
                    "auto-approve downgraded: pattern is in a duplicate group".into()
                } else if pattern.confidence >= config.auto_approve_threshold {
                    format!(
                        "high confidence but: outlierRatio={:.2} or locations={} or has errors",
                        outlier_ratio, pattern.total_location_count,
                    )
                } else {
                    format!("confidence={:.2} meets review threshold", pattern.confidence)
                }
            }
            RecommendationType::LikelyFalsePositive => format!(
                "confidence={:.2} below {:.2} or outlierRatio={:.2} above {:.2}",
                pattern.confidence, config.review_threshold,
                outlier_ratio, config.max_outlier_ratio,
            ),
        };

        let rec = PatternRecommendation {
            pattern_id: pattern.id.clone(),
            pattern_name: pattern.name.clone(),
            category: pattern.category.clone(),
            confidence: pattern.confidence,
            recommendation,
            reason,
        };

        match recommendation {
            RecommendationType::AutoApprove => auto_approved.push(rec),
            RecommendationType::Review => needs_review.push(rec),
            RecommendationType::LikelyFalsePositive => likely_fps.push(rec),
        }
    }

    RecommendationResult {
        auto_approved,
        needs_review,
        likely_fps,
    }
}

#[derive(Debug, Clone)]
pub struct RecommendationResult {
    pub auto_approved: Vec<PatternRecommendation>,
    pub needs_review: Vec<PatternRecommendation>,
    pub likely_fps: Vec<PatternRecommendation>,
}
```

---

## 9. Phase 5: Health Score Calculation (5-Factor Weighted Formula)

### The Formula (Preserved Exactly from V1)

```
health_score = (avgConfidence × 0.30
              + approvalRatio × 0.20
              + complianceRate × 0.20
              + crossValidationRate × 0.15
              + duplicateFreeRate × 0.15) × 100
```

All factors are normalized to [0.0, 1.0]. The result is scaled to [0, 100].

**These weights are tuned. Do not change them without A/B testing.**

### Factor Definitions

| Factor | Formula | Weight |
|--------|---------|--------|
| avgConfidence | Mean confidence across all patterns | 0.30 |
| approvalRatio | approved_count / total_patterns | 0.20 |
| complianceRate | total_locations / (total_locations + total_outliers) | 0.20 |
| crossValidationRate | patterns_in_call_graph / total_patterns | 0.15 |
| duplicateFreeRate | 1.0 - (patterns_in_duplicate_groups / total_patterns) | 0.15 |

### Implementation

```rust
/// Calculate the overall health score and its breakdown.
pub fn calculate_health(
    patterns: &[PatternAuditData],
    duplicate_groups: &[DuplicateGroup],
    cv_issues: &[CrossValidationIssue],
    config: &AuditConfig,
) -> (f64, HealthBreakdown) {
    let total = patterns.len();
    if total == 0 {
        return (100.0, HealthBreakdown::perfect());
    }

    // Factor 1: Average confidence.
    let avg_confidence = patterns.iter().map(|p| p.confidence).sum::<f64>() / total as f64;

    // Factor 2: Approval ratio.
    let approved = patterns.iter().filter(|p| p.status == PatternStatus::Approved).count();
    let approval_ratio = approved as f64 / total as f64;

    // Factor 3: Compliance rate.
    let total_locations: usize = patterns.iter().map(|p| p.total_location_count).sum();
    let total_outliers: usize = patterns.iter().map(|p| p.outlier_count).sum();
    let compliance_rate = if total_locations + total_outliers > 0 {
        total_locations as f64 / (total_locations + total_outliers) as f64
    } else {
        1.0
    };

    // Factor 4: Cross-validation rate (patterns in call graph).
    let in_call_graph = patterns.iter().filter(|p| p.in_call_graph).count();
    let cross_validation_rate = in_call_graph as f64 / total as f64;

    // Factor 5: Duplicate-free rate.
    let in_dup_groups: usize = duplicate_groups.iter().map(|g| g.pattern_ids.len()).sum();
    let duplicate_free_rate = 1.0 - (in_dup_groups as f64 / total as f64);

    // Weighted sum.
    let raw_score = avg_confidence * 0.30
        + approval_ratio * 0.20
        + compliance_rate * 0.20
        + cross_validation_rate * 0.15
        + duplicate_free_rate * 0.15;

    let health_score = (raw_score * 100.0).clamp(0.0, 100.0);

    let breakdown = HealthBreakdown {
        avg_confidence,
        approval_ratio,
        compliance_rate,
        cross_validation_rate,
        duplicate_free_rate,
        raw_score,
    };

    (health_score, breakdown)
}

impl HealthBreakdown {
    /// A perfect health breakdown (used when there are no patterns).
    pub fn perfect() -> Self {
        Self {
            avg_confidence: 1.0,
            approval_ratio: 1.0,
            compliance_rate: 1.0,
            cross_validation_rate: 1.0,
            duplicate_free_rate: 1.0,
            raw_score: 1.0,
        }
    }
}
```

---

## 10. Phase 6: Per-Category Health Breakdown (V2 Addition)

### Rationale

V1 produced a single health score. V2 adds per-category breakdown so developers
can see which convention categories are healthy and which are degrading. This
enables targeted remediation: "your security patterns are healthy but your
testing patterns are declining."

### Implementation

```rust
/// Calculate health scores per pattern category.
pub fn calculate_category_health(
    patterns: &[PatternAuditData],
    config: &AuditConfig,
) -> FxHashMap<String, CategoryHealth> {
    let by_category = group_by_category(patterns);
    let mut result = FxHashMap::default();

    for (category, cat_patterns) in &by_category {
        let count = cat_patterns.len();
        if count == 0 {
            continue;
        }

        let avg_confidence = cat_patterns.iter().map(|p| p.confidence).sum::<f64>() / count as f64;

        let total_locs: usize = cat_patterns.iter().map(|p| p.total_location_count).sum();
        let total_outliers: usize = cat_patterns.iter().map(|p| p.outlier_count).sum();
        let compliance_rate = if total_locs + total_outliers > 0 {
            total_locs as f64 / (total_locs + total_outliers) as f64
        } else {
            1.0
        };

        // Simplified score for per-category (confidence × 0.50 + compliance × 0.50).
        let score = ((avg_confidence * 0.50 + compliance_rate * 0.50) * 100.0).clamp(0.0, 100.0);

        result.insert(
            category.clone(),
            CategoryHealth {
                category: category.clone(),
                score,
                pattern_count: count,
                avg_confidence,
                compliance_rate,
                trend: TrendDirection::Stable, // Updated by trend analysis.
            },
        );
    }

    result
}
```

### Category Trend Integration

Per-category trends are calculated in Phase 8 (Trend Analysis) by comparing
the current category scores against the 7-day rolling average of historical
category scores. The `trend` field in `CategoryHealth` is updated after trend
analysis completes.


---

## 11. Phase 7: Degradation Detection & Alerting

### Design (Preserved from V1)

Degradation detection compares the current audit against the most recent
previous snapshot. It generates alerts when metrics cross warning or critical
thresholds. This is the "drift detection" feature — the core value proposition.

### Alert Thresholds (Exact V1 Values)

| Alert Type | Warning Threshold | Critical Threshold |
|-----------|-------------------|-------------------|
| Health score drop | -5 points | -15 points |
| Confidence drop | -5% (-0.05) | -15% (-0.15) |
| New false positives | > 5 | > 10 |
| Duplicate group increase | > 3 new groups | — |

### Implementation

```rust
/// Detect degradation by comparing current audit against previous snapshot.
pub fn detect_degradation(
    current_health: f64,
    current_breakdown: &HealthBreakdown,
    recommendations: &RecommendationResult,
    previous: &Option<AuditSnapshot>,
    config: &AuditConfig,
) -> Vec<DegradationAlert> {
    let previous = match previous {
        Some(p) => p,
        None => return Vec::new(), // No previous snapshot — no degradation possible.
    };

    let mut alerts = Vec::new();

    // Alert 1: Health score drop.
    let health_delta = current_health - previous.health_score;
    if health_delta <= -config.health_drop_critical {
        alerts.push(DegradationAlert {
            alert_type: DegradationAlertType::HealthDrop,
            level: AlertLevel::Critical,
            message: format!(
                "Health score dropped {:.1} points ({:.1} → {:.1})",
                health_delta.abs(),
                previous.health_score,
                current_health,
            ),
            current_value: current_health,
            previous_value: previous.health_score,
            delta: health_delta,
        });
    } else if health_delta <= -config.health_drop_warning {
        alerts.push(DegradationAlert {
            alert_type: DegradationAlertType::HealthDrop,
            level: AlertLevel::Warning,
            message: format!(
                "Health score dropped {:.1} points ({:.1} → {:.1})",
                health_delta.abs(),
                previous.health_score,
                current_health,
            ),
            current_value: current_health,
            previous_value: previous.health_score,
            delta: health_delta,
        });
    }

    // Alert 2: Confidence drop.
    let conf_delta = current_breakdown.avg_confidence - previous.avg_confidence;
    if conf_delta <= -config.confidence_drop_critical {
        alerts.push(DegradationAlert {
            alert_type: DegradationAlertType::ConfidenceDrop,
            level: AlertLevel::Critical,
            message: format!(
                "Average confidence dropped {:.1}% ({:.2} → {:.2})",
                (conf_delta.abs() * 100.0),
                previous.avg_confidence,
                current_breakdown.avg_confidence,
            ),
            current_value: current_breakdown.avg_confidence,
            previous_value: previous.avg_confidence,
            delta: conf_delta,
        });
    } else if conf_delta <= -config.confidence_drop_warning {
        alerts.push(DegradationAlert {
            alert_type: DegradationAlertType::ConfidenceDrop,
            level: AlertLevel::Warning,
            message: format!(
                "Average confidence dropped {:.1}% ({:.2} → {:.2})",
                (conf_delta.abs() * 100.0),
                previous.avg_confidence,
                current_breakdown.avg_confidence,
            ),
            current_value: current_breakdown.avg_confidence,
            previous_value: previous.avg_confidence,
            delta: conf_delta,
        });
    }

    // Alert 3: New false positives.
    let fp_count = recommendations.likely_fps.len();
    let prev_fp = previous.false_positive_count;
    let new_fps = if fp_count > prev_fp { fp_count - prev_fp } else { 0 };
    if new_fps > config.new_fp_critical {
        alerts.push(DegradationAlert {
            alert_type: DegradationAlertType::NewFalsePositives,
            level: AlertLevel::Critical,
            message: format!("{} new likely false positives detected", new_fps),
            current_value: fp_count as f64,
            previous_value: prev_fp as f64,
            delta: new_fps as f64,
        });
    } else if new_fps > config.new_fp_warning {
        alerts.push(DegradationAlert {
            alert_type: DegradationAlertType::NewFalsePositives,
            level: AlertLevel::Warning,
            message: format!("{} new likely false positives detected", new_fps),
            current_value: fp_count as f64,
            previous_value: prev_fp as f64,
            delta: new_fps as f64,
        });
    }

    // Alert 4: Duplicate group increase.
    let dup_delta = recommendations.auto_approved.len() as i64; // placeholder
    let current_dup_groups = 0_usize; // filled from actual data
    let prev_dup_groups = previous.duplicate_group_count;
    if current_dup_groups > prev_dup_groups + config.duplicate_increase_warning {
        alerts.push(DegradationAlert {
            alert_type: DegradationAlertType::DuplicateIncrease,
            level: AlertLevel::Warning,
            message: format!(
                "{} new duplicate groups detected ({} → {})",
                current_dup_groups - prev_dup_groups,
                prev_dup_groups,
                current_dup_groups,
            ),
            current_value: current_dup_groups as f64,
            previous_value: prev_dup_groups as f64,
            delta: (current_dup_groups as f64 - prev_dup_groups as f64),
        });
    }

    alerts
}
```

---

## 12. Phase 8: Trend Analysis (7-Day Rolling Averages)

### Algorithm (Preserved from V1)

Trends are calculated by comparing the 7-day rolling average of the current
period against the 7-day rolling average of the previous period. The threshold
for trend classification is ±2 points (health) or ±2% (confidence).

### Implementation

```rust
/// Analyze trends from snapshot history.
pub fn analyze_trends(
    history: &[AuditSnapshot],
    config: &AuditConfig,
) -> AuditTrends {
    if history.len() < 2 {
        return AuditTrends::default();
    }

    let now = Utc::now();
    let seven_days_ago = now - chrono::Duration::days(7);
    let fourteen_days_ago = now - chrono::Duration::days(14);

    // Split history into current 7-day window and previous 7-day window.
    let current_window: Vec<&AuditSnapshot> = history
        .iter()
        .filter(|s| s.timestamp >= seven_days_ago)
        .collect();
    let previous_window: Vec<&AuditSnapshot> = history
        .iter()
        .filter(|s| s.timestamp >= fourteen_days_ago && s.timestamp < seven_days_ago)
        .collect();

    // Health trend.
    let current_health_avg = rolling_average(&current_window, |s| s.health_score);
    let previous_health_avg = rolling_average(&previous_window, |s| s.health_score);
    let health_trend = classify_trend(
        current_health_avg,
        previous_health_avg,
        config.trend_threshold_points, // ±2.0
    );

    // Confidence trend.
    let current_conf_avg = rolling_average(&current_window, |s| s.avg_confidence);
    let previous_conf_avg = rolling_average(&previous_window, |s| s.avg_confidence);
    let confidence_trend = classify_trend(
        current_conf_avg * 100.0,
        previous_conf_avg * 100.0,
        config.trend_threshold_percent, // ±2.0
    );

    // Pattern growth.
    let pattern_growth = classify_pattern_growth(history, config);

    // Per-category trends (v2 addition).
    let category_trends = calculate_category_trends(history, config);

    AuditTrends {
        health_trend,
        confidence_trend,
        pattern_growth,
        category_trends,
    }
}

fn rolling_average<F>(snapshots: &[&AuditSnapshot], extractor: F) -> f64
where
    F: Fn(&AuditSnapshot) -> f64,
{
    if snapshots.is_empty() {
        return 0.0;
    }
    let sum: f64 = snapshots.iter().map(|s| extractor(s)).sum();
    sum / snapshots.len() as f64
}

fn classify_trend(current: f64, previous: f64, threshold: f64) -> TrendDirection {
    let delta = current - previous;
    if delta > threshold {
        TrendDirection::Improving
    } else if delta < -threshold {
        TrendDirection::Declining
    } else {
        TrendDirection::Stable
    }
}

fn classify_pattern_growth(
    history: &[AuditSnapshot],
    config: &AuditConfig,
) -> PatternGrowth {
    if history.len() < 2 {
        return PatternGrowth::Healthy;
    }

    let oldest = &history[0];
    let newest = history.last().unwrap();
    let days = (newest.timestamp - oldest.timestamp).num_days().max(1) as f64;
    let growth_per_day = (newest.total_patterns as f64 - oldest.total_patterns as f64) / days;

    if growth_per_day > config.rapid_growth_threshold {
        PatternGrowth::Rapid
    } else if growth_per_day < config.stagnant_growth_threshold {
        PatternGrowth::Stagnant
    } else {
        PatternGrowth::Healthy
    }
}
```

---

## 13. Phase 9: Trend Prediction (V2 Addition — Linear Regression)

### Rationale

V1 only reported current trends (improving/stable/declining). V2 adds predictive
capability: "at the current rate, your health score will cross the warning
threshold in 12 days." This enables proactive remediation.

### Algorithm: Simple Linear Regression

We use ordinary least squares (OLS) regression on the health score history.
The independent variable is days since the first snapshot. The dependent
variable is the health score.

```
y = mx + b
where:
  y = predicted health score
  m = slope (points per day)
  x = days from first snapshot
  b = y-intercept
```

### Implementation

```rust
/// Predict future health trend using linear regression on history.
pub fn predict_trend(history: &[AuditSnapshot]) -> Option<TrendPrediction> {
    if history.len() < 3 {
        return None; // Need at least 3 data points for meaningful regression.
    }

    let base_time = history[0].timestamp;
    let points: Vec<(f64, f64)> = history
        .iter()
        .map(|s| {
            let days = (s.timestamp - base_time).num_seconds() as f64 / 86400.0;
            (days, s.health_score)
        })
        .collect();

    let n = points.len() as f64;
    let sum_x: f64 = points.iter().map(|(x, _)| x).sum();
    let sum_y: f64 = points.iter().map(|(_, y)| y).sum();
    let sum_xy: f64 = points.iter().map(|(x, y)| x * y).sum();
    let sum_x2: f64 = points.iter().map(|(x, _)| x * x).sum();

    let denominator = n * sum_x2 - sum_x * sum_x;
    if denominator.abs() < f64::EPSILON {
        return None; // All x values are the same — can't fit a line.
    }

    let slope = (n * sum_xy - sum_x * sum_y) / denominator;
    let intercept = (sum_y - slope * sum_x) / n;

    // R² (coefficient of determination).
    let mean_y = sum_y / n;
    let ss_tot: f64 = points.iter().map(|(_, y)| (y - mean_y).powi(2)).sum();
    let ss_res: f64 = points
        .iter()
        .map(|(x, y)| {
            let predicted = slope * x + intercept;
            (y - predicted).powi(2)
        })
        .sum();
    let r_squared = if ss_tot > 0.0 { 1.0 - ss_res / ss_tot } else { 1.0 };

    // Predict future values.
    let current_x = points.last().unwrap().0;
    let predicted_7d = (slope * (current_x + 7.0) + intercept).clamp(0.0, 100.0);
    let predicted_30d = (slope * (current_x + 30.0) + intercept).clamp(0.0, 100.0);

    // Days to warning/critical thresholds (only if declining).
    let current_health = points.last().unwrap().1;
    let days_to_warning = if slope < 0.0 && current_health > 70.0 {
        Some(((current_health - 70.0) / slope.abs()).ceil() as u32)
    } else {
        None
    };
    let days_to_critical = if slope < 0.0 && current_health > 50.0 {
        Some(((current_health - 50.0) / slope.abs()).ceil() as u32)
    } else {
        None
    };

    let confidence = if r_squared >= 0.7 && points.len() >= 14 {
        PredictionConfidence::High
    } else if r_squared >= 0.5 && points.len() >= 7 {
        PredictionConfidence::Medium
    } else {
        PredictionConfidence::Low
    };

    Some(TrendPrediction {
        predicted_health_7d: predicted_7d,
        predicted_health_30d: predicted_30d,
        slope_per_day: slope,
        r_squared,
        confidence,
        days_to_warning,
        days_to_critical,
    })
}
```

### Prediction Display

The prediction is surfaced in MCP, CLI, and Dashboard:
- "Health score predicted to reach 70 (warning) in ~12 days at current rate"
- "Health trend: declining at -0.8 points/day (R²=0.82, high confidence)"
- "Predicted health in 7 days: 74.4, in 30 days: 56.0"

---

## 14. Phase 10: Anomaly Detection (V2 Addition — Statistical Outliers)

### Rationale

V1 degradation detection only compared against the immediately previous snapshot.
V2 adds anomaly detection that compares against the full historical distribution.
This catches sudden spikes or drops that might not trigger the simple delta-based
alerts but are statistically unusual.

### Algorithm: Z-Score on Historical Distribution

For each metric, compute the mean and standard deviation from the last 30 days
of history. Flag the current value as anomalous if |z-score| > 2.5.

```rust
/// Detect anomalies in current audit metrics against historical distribution.
pub fn detect_anomalies(
    history: &[AuditSnapshot],
    current_health: f64,
    current_breakdown: &HealthBreakdown,
) -> Vec<AuditAnomaly> {
    if history.len() < 7 {
        return Vec::new(); // Need sufficient history for meaningful statistics.
    }

    let mut anomalies = Vec::new();

    // Check each metric against its historical distribution.
    let metrics: Vec<(AnomalyMetric, f64, Vec<f64>)> = vec![
        (
            AnomalyMetric::HealthScore,
            current_health,
            history.iter().map(|s| s.health_score).collect(),
        ),
        (
            AnomalyMetric::AvgConfidence,
            current_breakdown.avg_confidence,
            history.iter().map(|s| s.avg_confidence).collect(),
        ),
        (
            AnomalyMetric::ComplianceRate,
            current_breakdown.compliance_rate,
            history.iter().map(|s| {
                let locs = s.total_locations as f64;
                let outliers = s.total_outliers as f64;
                if locs + outliers > 0.0 { locs / (locs + outliers) } else { 1.0 }
            }).collect(),
        ),
        (
            AnomalyMetric::DuplicateCount,
            current_breakdown.duplicate_free_rate, // inverted
            history.iter().map(|s| s.duplicate_group_count as f64).collect(),
        ),
        (
            AnomalyMetric::PatternCount,
            0.0, // filled from current data
            history.iter().map(|s| s.total_patterns as f64).collect(),
        ),
    ];

    for (metric, current_value, historical_values) in &metrics {
        if historical_values.len() < 7 {
            continue;
        }

        let n = historical_values.len() as f64;
        let mean: f64 = historical_values.iter().sum::<f64>() / n;
        let variance: f64 = historical_values
            .iter()
            .map(|v| (v - mean).powi(2))
            .sum::<f64>()
            / (n - 1.0);
        let std_dev = variance.sqrt();

        if std_dev < f64::EPSILON {
            continue; // No variance — can't compute z-score.
        }

        let z_score = (current_value - mean) / std_dev;

        if z_score.abs() > 2.5 {
            let severity = if z_score.abs() > 3.5 {
                IssueSeverity::Error
            } else {
                IssueSeverity::Warning
            };

            anomalies.push(AuditAnomaly {
                metric: *metric,
                value: *current_value,
                expected_range: (mean - 2.5 * std_dev, mean + 2.5 * std_dev),
                z_score,
                severity,
                message: format!(
                    "{:?} is {:.2} (z-score: {:.2}, expected range: {:.2}-{:.2})",
                    metric,
                    current_value,
                    z_score,
                    mean - 2.5 * std_dev,
                    mean + 2.5 * std_dev,
                ),
            });
        }
    }

    anomalies
}
```


---

## 15. Phase 11: Snapshot Persistence & History

### Storage Design

V1 used JSON files in `.drift/audit/`. V2 uses drift.db tables exclusively.
No JSON files. No file I/O for audit persistence.

### Snapshot Lifecycle

1. After each audit run, save a snapshot to `audit_snapshots` table
2. Update `materialized_status` singleton with latest health score
3. Enforce retention: delete snapshots older than `history_retention_days` (default: 90)
4. Query history for trend analysis and degradation detection

### Implementation

```rust
/// Save an audit snapshot to drift.db.
fn save_snapshot(
    &self,
    db: &DatabaseManager,
    snapshot: &AuditSnapshot,
) -> Result<(), AuditError> {
    db.write(|conn| {
        conn.execute(
            "INSERT INTO audit_snapshots (
                id, timestamp, health_score, avg_confidence,
                total_patterns, approved_patterns, discovered_patterns, ignored_patterns,
                total_locations, total_outliers, duplicate_group_count,
                false_positive_count, cross_validation_score,
                category_scores, alerts
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            rusqlite::params![
                snapshot.id,
                snapshot.timestamp.to_rfc3339(),
                snapshot.health_score,
                snapshot.avg_confidence,
                snapshot.total_patterns,
                snapshot.approved_patterns,
                snapshot.discovered_patterns,
                snapshot.ignored_patterns,
                snapshot.total_locations,
                snapshot.total_outliers,
                snapshot.duplicate_group_count,
                snapshot.false_positive_count,
                snapshot.cross_validation_score,
                snapshot.category_scores.to_string(),
                snapshot.alerts.to_string(),
            ],
        )?;
        Ok(())
    })
}

/// Update the materialized_status singleton with latest audit data.
fn update_materialized_status(
    &self,
    db: &DatabaseManager,
    snapshot: &AuditSnapshot,
) -> Result<(), AuditError> {
    db.write(|conn| {
        conn.execute(
            "UPDATE materialized_status SET
                health_score = ?1,
                health_trend = ?2,
                pattern_total = ?3,
                pattern_approved = ?4,
                pattern_discovered = ?5,
                pattern_ignored = ?6,
                last_audit_at = ?7
            WHERE id = 1",
            rusqlite::params![
                snapshot.health_score,
                "stable", // Updated by trend analysis
                snapshot.total_patterns,
                snapshot.approved_patterns,
                snapshot.discovered_patterns,
                snapshot.ignored_patterns,
                snapshot.timestamp.to_rfc3339(),
            ],
        )?;
        Ok(())
    })
}

/// Load snapshot history for the last N days.
fn load_snapshot_history(
    &self,
    db: &DatabaseManager,
    days: u32,
) -> Result<Vec<AuditSnapshot>, AuditError> {
    let cutoff = Utc::now() - chrono::Duration::days(days as i64);
    db.read(|conn| {
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, health_score, avg_confidence,
                    total_patterns, approved_patterns, discovered_patterns, ignored_patterns,
                    total_locations, total_outliers, duplicate_group_count,
                    false_positive_count, cross_validation_score,
                    category_scores, alerts
             FROM audit_snapshots
             WHERE timestamp >= ?1
             ORDER BY timestamp ASC"
        )?;
        // Map rows to AuditSnapshot...
    })
}

/// Enforce retention policy: delete snapshots older than N days.
fn enforce_retention(
    &self,
    db: &DatabaseManager,
    retention_days: u32,
) -> Result<(), AuditError> {
    let cutoff = Utc::now() - chrono::Duration::days(retention_days as i64);
    db.write(|conn| {
        conn.execute(
            "DELETE FROM audit_snapshots WHERE timestamp < ?1",
            rusqlite::params![cutoff.to_rfc3339()],
        )?;
        Ok(())
    })
}
```

---

## 16. Phase 12: Audit Summary Builder

### Human-Readable Summary

The audit summary is a structured object that CLI, MCP, and Dashboard can
render into human-readable output. It contains all the key metrics and
actionable information from the audit run.

```rust
/// Build the audit summary from computed data.
fn build_summary(
    &self,
    patterns: &[PatternAuditData],
    recommendations: &RecommendationResult,
    duplicate_groups: &[DuplicateGroup],
    cv_issues: &[CrossValidationIssue],
) -> AuditSummary {
    let mut patterns_by_category: FxHashMap<String, usize> = FxHashMap::default();
    for p in patterns {
        *patterns_by_category.entry(p.category.clone()).or_insert(0) += 1;
    }

    let discovered = patterns.iter().filter(|p| p.status == PatternStatus::Discovered).count();
    let approved = patterns.iter().filter(|p| p.status == PatternStatus::Approved).count();
    let ignored = patterns.iter().filter(|p| p.status == PatternStatus::Ignored).count();

    let total_locations: usize = patterns.iter().map(|p| p.total_location_count).sum();
    let total_outliers: usize = patterns.iter().map(|p| p.outlier_count).sum();
    let compliance_rate = if total_locations + total_outliers > 0 {
        total_locations as f64 / (total_locations + total_outliers) as f64
    } else {
        1.0
    };

    AuditSummary {
        total_patterns: patterns.len(),
        patterns_by_status: PatternStatusCounts {
            discovered,
            approved,
            ignored,
        },
        patterns_by_category,
        total_locations,
        total_outliers,
        compliance_rate,
        duplicate_groups: duplicate_groups.len(),
        cross_validation_issues: cv_issues.len(),
        auto_approved_count: recommendations.auto_approved.len(),
        needs_review_count: recommendations.needs_review.len(),
        likely_fp_count: recommendations.likely_fps.len(),
    }
}
```

---

## 17. Integration with Quality Gates

### How the Audit System Feeds Quality Gates

The audit system produces data consumed by multiple quality gates:

| Quality Gate | Audit Data Consumed |
|-------------|-------------------|
| Pattern Compliance | Health score, compliance rate, outlier counts |
| Regression Detection | Previous snapshot comparison, trend data |
| Impact Simulation | Pattern locations, call graph coverage |
| Security Boundary | Cross-validation issues (constraint alignment) |

### Regression Detection Gate

The regression detection gate uses audit snapshots as its baseline:

```rust
/// The regression detection gate queries audit history to compare
/// current state against a baseline snapshot.
pub fn get_baseline_for_regression(
    db: &DatabaseManager,
    branch: &str,
) -> Result<Option<AuditSnapshot>, AuditError> {
    db.read(|conn| {
        let mut stmt = conn.prepare(
            "SELECT * FROM audit_snapshots
             WHERE branch = ?1
             ORDER BY timestamp DESC
             LIMIT 1"
        )?;
        // Map to AuditSnapshot...
    })
}
```

### Health Score in Gate Results

The overall health score is included in the quality gate aggregate result:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityGateAggregate {
    pub passed: bool,
    pub overall_score: f64,
    pub health_score: f64,        // From audit system
    pub health_trend: TrendDirection, // From audit system
    pub gates: Vec<GateResult>,
}
```

---

## 18. Integration with Violation Feedback Loop

### Bidirectional Data Flow

The audit system and violation feedback loop have a bidirectional relationship:

1. **Audit → Feedback**: Auto-approve decisions from the audit system feed into
   the pattern approval workflow. When a pattern is auto-approved, the feedback
   loop records this as a positive signal.

2. **Feedback → Audit**: Violation dismissals and false positive reports feed
   back into the audit system's false positive count, which affects the health
   score (via the `duplicateFreeRate` factor) and triggers degradation alerts
   when FP counts increase.

### Event Flow

```
Audit System                    Violation Feedback Loop
    │                                    │
    ├── on_pattern_auto_approved ──────→ │ (records approval)
    │                                    │
    │ ←── on_violation_dismissed ────────┤ (FP signal)
    │                                    │
    │ ←── on_detector_disabled ──────────┤ (detector health)
    │                                    │
    ├── on_health_degraded ────────────→ │ (triggers review)
    │                                    │
```

### Tricorder-Style Integration

Per DRIFT-V2-FULL-SYSTEM-AUDIT.md: "Developer action (fix, ignore, approve)
feeds back into pattern confidence." The audit system reads the accumulated
feedback data when calculating health scores:

- Patterns with high dismissal rates get lower effective confidence
- Detectors with >20% FP rate for 30+ days are flagged in cross-validation
- Auto-approve decisions are suppressed for patterns from unhealthy detectors

---

## 19. Integration with Cortex Observability (Proven Patterns)

### What We Borrow from Cortex

The existing `cortex-observability` crate provides proven patterns that the
Drift audit system adopts:

| Cortex Pattern | Drift Adoption |
|---------------|----------------|
| `HealthChecker` + `IHealthReporter` trait | `AuditEngine` implements `IAuditReporter` trait |
| `HealthSnapshot` → `HealthReport` pipeline | `PatternAuditData[]` → `AuditResult` pipeline |
| `SubsystemChecker` (5 subsystem checks) | Per-category health checks (16 categories) |
| `DegradationTracker` (record/recover/alert) | `DegradationDetector` (compare/alert/trend) |
| `AlertLevel` (Warning/Critical) | Same enum, same semantics |
| `TrendIndicator` (Improving/Stable/Declining) | `TrendDirection` — same semantics |
| `Recommendation` (severity + message + action) | `PatternRecommendation` (type + reason) |
| `ObservabilityEngine` orchestrator | `AuditEngine` orchestrator |
| Structured tracing events | Same pattern: `tracing::info!(event = "audit_complete", ...)` |

### What We Do NOT Borrow

| Cortex Feature | Why Not |
|---------------|---------|
| Memory-based health metrics (total_memories, etc.) | Drift tracks patterns, not memories |
| Embedding cache hit rate | Drift doesn't use embeddings for audit |
| Causal graph health | Drift uses call graph, not causal graph |
| Privacy subsystem check | Drift has security boundary gate instead |
| Temporal drift (KSI/EFI) | Drift has its own trend analysis |

### Architectural Alignment

Both systems follow the same pattern:
1. Collect snapshot data from subsystems
2. Run health checks against thresholds
3. Generate recommendations
4. Detect degradation against history
5. Emit structured events
6. Persist for trend analysis

This alignment means developers familiar with cortex-observability will
immediately understand the Drift audit system's architecture.


---

## 20. Integration with Cortex Grounding (D7 Bridge)

### Event Propagation to Cortex

Per PLANNING-DRIFT.md D5: "Every enforcement action that changes state should
emit a typed event via DriftEventHandler. In standalone mode these are no-ops.
When the bridge is active, they become Cortex memories."

The audit system emits three events that the bridge can propagate:

| Event | Cortex Memory Type | Content |
|-------|-------------------|---------|
| `on_audit_complete` | `audit_result` | Health score, alert count, auto-approved count |
| `on_health_degraded` | `health_alert` | Health score, degradation alerts |
| `on_pattern_auto_approved` | `pattern_rationale` | Pattern ID, confidence, approval reason |

### Grounding Check

Per D7: "DNA health scores are another grounding signal the bridge can compare
against Cortex memories." The audit health score serves the same purpose:

```rust
/// Compare audit health score against Cortex memory confidence.
/// If Cortex memories claim the codebase is healthy but the audit
/// score is low, flag a grounding mismatch.
pub fn grounding_check(
    audit_health: f64,
    cortex_avg_confidence: f64,
) -> Option<GroundingMismatch> {
    let delta = (audit_health / 100.0 - cortex_avg_confidence).abs();
    if delta > 0.3 {
        Some(GroundingMismatch {
            audit_health,
            cortex_confidence: cortex_avg_confidence,
            delta,
            message: format!(
                "Audit health ({:.0}) and Cortex confidence ({:.2}) diverge by {:.0}%",
                audit_health, cortex_avg_confidence, delta * 100.0,
            ),
        })
    } else {
        None
    }
}
```

---

## 21. Storage Schema (drift.db Audit Tables)

### Table: audit_snapshots

```sql
CREATE TABLE IF NOT EXISTS audit_snapshots (
    id                    TEXT PRIMARY KEY,
    timestamp             TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    health_score          REAL NOT NULL,
    avg_confidence        REAL NOT NULL,
    total_patterns        INTEGER NOT NULL,
    approved_patterns     INTEGER NOT NULL,
    discovered_patterns   INTEGER NOT NULL,
    ignored_patterns      INTEGER NOT NULL,
    total_locations       INTEGER NOT NULL,
    total_outliers        INTEGER NOT NULL,
    duplicate_group_count INTEGER NOT NULL DEFAULT 0,
    false_positive_count  INTEGER NOT NULL DEFAULT 0,
    cross_validation_score REAL NOT NULL DEFAULT 1.0,
    category_scores       TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(category_scores)),
    alerts                TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(alerts)),
    branch                TEXT,
    commit_sha            TEXT
) STRICT;

CREATE INDEX IF NOT EXISTS idx_audit_snapshots_timestamp ON audit_snapshots(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_snapshots_branch ON audit_snapshots(branch);
```

### Table: audit_degradation_log

```sql
CREATE TABLE IF NOT EXISTS audit_degradation_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id     TEXT NOT NULL REFERENCES audit_snapshots(id),
    alert_type      TEXT NOT NULL,
    alert_level     TEXT NOT NULL,
    message         TEXT NOT NULL,
    current_value   REAL NOT NULL,
    previous_value  REAL NOT NULL,
    delta           REAL NOT NULL,
    timestamp       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

CREATE INDEX IF NOT EXISTS idx_audit_degradation_timestamp ON audit_degradation_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_degradation_type ON audit_degradation_log(alert_type);
```

### Table: audit_recommendations

```sql
CREATE TABLE IF NOT EXISTS audit_recommendations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id     TEXT NOT NULL REFERENCES audit_snapshots(id),
    pattern_id      TEXT NOT NULL,
    pattern_name    TEXT NOT NULL,
    category        TEXT NOT NULL,
    confidence      REAL NOT NULL,
    recommendation  TEXT NOT NULL,
    reason          TEXT NOT NULL,
    applied         INTEGER NOT NULL DEFAULT 0,
    applied_at      TEXT,
    timestamp       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

CREATE INDEX IF NOT EXISTS idx_audit_rec_pattern ON audit_recommendations(pattern_id);
CREATE INDEX IF NOT EXISTS idx_audit_rec_type ON audit_recommendations(recommendation);
CREATE INDEX IF NOT EXISTS idx_audit_rec_snapshot ON audit_recommendations(snapshot_id);
```

### Table: audit_duplicate_groups

```sql
CREATE TABLE IF NOT EXISTS audit_duplicate_groups (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id     TEXT NOT NULL REFERENCES audit_snapshots(id),
    pattern_ids     TEXT NOT NULL CHECK(json_valid(pattern_ids)),
    max_similarity  REAL NOT NULL,
    recommendation  TEXT NOT NULL,
    resolved        INTEGER NOT NULL DEFAULT 0,
    resolved_at     TEXT,
    timestamp       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

CREATE INDEX IF NOT EXISTS idx_audit_dup_snapshot ON audit_duplicate_groups(snapshot_id);
```

### Migration

```rust
/// Migration: Create audit system tables.
pub fn migrate_audit_tables(conn: &Connection) -> Result<(), StorageError> {
    conn.execute_batch("
        -- audit_snapshots, audit_degradation_log,
        -- audit_recommendations, audit_duplicate_groups
        -- (full DDL as above)
    ")?;
    Ok(())
}
```

### Relationship to Cortex Audit Tables

The existing cortex-storage has `memory_audit_log`, `consolidation_metrics`,
and `degradation_log` tables (v006 migration). These are for Cortex's memory
system. Drift's audit tables are completely separate and live in drift.db,
not cortex.db. No schema conflicts.

---

## 22. NAPI Interface

### Exported Functions

Per 03-NAPI-BRIDGE-V2-PREP.md §10.11, the audit system exposes 2 NAPI functions:

| Function | Sync/Async | Returns | Description |
|----------|-----------|---------|-------------|
| `run_audit()` | Async | `AuditResult` | Full audit pipeline |
| `query_health_trends(days?)` | Sync | `HealthTrend[]` | Historical health data |

### Additional Functions (V2 Additions)

| Function | Sync/Async | Returns | Description |
|----------|-----------|---------|-------------|
| `query_audit_snapshot(id?)` | Sync | `AuditSnapshot` | Get specific or latest snapshot |
| `query_degradation_alerts(days?)` | Sync | `DegradationAlert[]` | Recent degradation alerts |
| `query_category_health()` | Sync | `CategoryHealth[]` | Per-category health breakdown |
| `query_audit_recommendations(filter?)` | Sync | `PatternRecommendation[]` | Pending recommendations |
| `apply_auto_approvals()` | Async | `ApplyResult` | Apply all auto-approve recommendations |

### NAPI Binding Implementation

```rust
// crates/drift-napi/src/bindings/audit.rs

use napi::bindgen_prelude::*;
use napi_derive::napi;

/// Run a full audit: health scoring, degradation detection, recommendations.
/// Writes snapshot to drift.db, returns lightweight summary.
#[napi]
pub fn run_audit() -> AsyncTask<AuditTask> {
    AsyncTask::new(AuditTask)
}

pub struct AuditTask;

#[napi]
impl Task for AuditTask {
    type Output = serde_json::Value;
    type JsValue = serde_json::Value;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let rt = crate::runtime::get()?;
        let config = &rt.config.audit;
        let result = drift_core::audit::run_audit(&rt.db, config, &rt.event_handler)
            .map_err(crate::conversions::error_types::to_napi_error)?;
        serde_json::to_value(&result)
            .map_err(|e| napi::Error::from_reason(format!("[INTERNAL_ERROR] {e}")))
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(output)
    }
}

/// Query health trend history for the last N days (default: 30).
#[napi]
pub fn query_health_trends(days: Option<u32>) -> napi::Result<serde_json::Value> {
    let rt = crate::runtime::get()?;
    let days = days.unwrap_or(30);
    let history = drift_core::audit::query_snapshot_history(&rt.db, days)
        .map_err(crate::conversions::error_types::to_napi_error)?;

    let trends: Vec<serde_json::Value> = history
        .iter()
        .map(|s| {
            serde_json::json!({
                "date": s.timestamp.format("%Y-%m-%d").to_string(),
                "health_score": s.health_score,
                "avg_confidence": s.avg_confidence,
                "total_patterns": s.total_patterns,
                "approved_patterns": s.approved_patterns,
                "duplicate_groups": s.duplicate_group_count,
                "false_positives": s.false_positive_count,
            })
        })
        .collect();

    serde_json::to_value(&trends)
        .map_err(|e| napi::Error::from_reason(format!("[INTERNAL_ERROR] {e}")))
}

/// Query per-category health breakdown.
#[napi]
pub fn query_category_health() -> napi::Result<serde_json::Value> {
    let rt = crate::runtime::get()?;
    let snapshot = drift_core::audit::query_latest_snapshot(&rt.db)
        .map_err(crate::conversions::error_types::to_napi_error)?;

    match snapshot {
        Some(s) => serde_json::to_value(&s.category_scores)
            .map_err(|e| napi::Error::from_reason(format!("[INTERNAL_ERROR] {e}"))),
        None => Ok(serde_json::json!({})),
    }
}

/// Query pending audit recommendations with optional filter.
#[napi]
pub fn query_audit_recommendations(
    filter: Option<String>,
) -> napi::Result<serde_json::Value> {
    let rt = crate::runtime::get()?;
    let recs = drift_core::audit::query_recommendations(&rt.db, filter.as_deref())
        .map_err(crate::conversions::error_types::to_napi_error)?;
    serde_json::to_value(&recs)
        .map_err(|e| napi::Error::from_reason(format!("[INTERNAL_ERROR] {e}")))
}

/// Apply all auto-approve recommendations from the latest audit.
#[napi]
pub fn apply_auto_approvals() -> AsyncTask<ApplyAutoApprovalsTask> {
    AsyncTask::new(ApplyAutoApprovalsTask)
}
```

### Error Codes

```rust
pub mod audit_codes {
    pub const AUDIT_ERROR: &str = "AUDIT_ERROR";
    pub const NO_PATTERNS: &str = "NO_PATTERNS";
    pub const SNAPSHOT_NOT_FOUND: &str = "SNAPSHOT_NOT_FOUND";
    pub const HISTORY_EMPTY: &str = "HISTORY_EMPTY";
}
```


---

## 23. MCP Tool Interface

### drift_audit Tool (3 Actions)

The audit system is exposed via the `drift_audit` MCP tool with 3 actions,
following the progressive disclosure pattern (3 entry points per server).

```typescript
// MCP tool definition
{
    name: "drift_audit",
    description: "Run codebase health audit, view trends, and manage recommendations",
    inputSchema: {
        type: "object",
        properties: {
            action: {
                type: "string",
                enum: ["run", "trends", "recommendations"],
                description: "Action to perform"
            },
            days: {
                type: "number",
                description: "Number of days for trend history (default: 30)"
            },
            category: {
                type: "string",
                description: "Filter by pattern category"
            },
            apply_auto_approve: {
                type: "boolean",
                description: "Whether to apply auto-approve recommendations"
            }
        },
        required: ["action"]
    }
}
```

### Action: run

Runs a full audit and returns the health score, alerts, and recommendations.
Token budget: ~800-2000 tokens depending on alert count.

```json
{
    "action": "run",
    "result": {
        "health_score": 78.4,
        "health_trend": "stable",
        "prediction": {
            "7d": 77.2,
            "30d": 73.8,
            "confidence": "medium"
        },
        "alerts": [
            {
                "type": "confidence_drop",
                "level": "warning",
                "message": "Average confidence dropped 6.2% (0.84 → 0.79)"
            }
        ],
        "summary": {
            "total_patterns": 142,
            "approved": 98,
            "discovered": 38,
            "ignored": 6,
            "auto_approved": 5,
            "needs_review": 12,
            "likely_fp": 3,
            "duplicate_groups": 2,
            "compliance_rate": 0.87
        },
        "category_health": {
            "security": { "score": 92.1, "trend": "stable" },
            "testing": { "score": 64.3, "trend": "declining" },
            "api": { "score": 81.7, "trend": "improving" }
        }
    }
}
```

### Action: trends

Returns health trend history for dashboard visualization.

### Action: recommendations

Returns pending recommendations with optional category filter.
Supports `apply_auto_approve: true` to batch-apply auto-approvals.

---

## 24. CLI Interface

### drift audit Command (4 Subcommands)

```
drift audit                    # Run full audit, display summary
drift audit --category=security  # Audit specific category
drift audit trends             # Show health trend chart (last 30 days)
drift audit trends --days=90   # Extended trend history
drift audit recommendations    # List pending recommendations
drift audit apply              # Apply all auto-approve recommendations
```

### CLI Output Format

```
╭─────────────────────────────────────────────────╮
│  Codebase Health: 78.4 / 100  (▼ declining)     │
╰─────────────────────────────────────────────────╯

  Breakdown:
    Confidence:      0.79  (weight: 30%)  ▼ -6.2%
    Approval Rate:   0.69  (weight: 20%)  ─ stable
    Compliance:      0.87  (weight: 20%)  ─ stable
    Cross-Validation: 0.72  (weight: 15%)  ▲ +3.1%
    Duplicate-Free:  0.95  (weight: 15%)  ─ stable

  ⚠ Warning: Average confidence dropped 6.2% (0.84 → 0.79)

  Prediction: Health score → 77.2 in 7 days, 73.8 in 30 days
              (medium confidence, R²=0.61)

  Category Health:
    security     92.1  ─ stable     (24 patterns)
    api          81.7  ▲ improving  (31 patterns)
    errors       79.2  ─ stable     (18 patterns)
    testing      64.3  ▼ declining  (22 patterns)  ← needs attention
    styling      58.1  ▼ declining  (15 patterns)  ← needs attention

  Recommendations:
    5 patterns ready for auto-approval
    12 patterns need review
    3 patterns likely false positives
    2 duplicate groups detected

  Run `drift audit apply` to auto-approve 5 patterns.
  Run `drift audit recommendations` for details.
```

---

## 25. Event Interface (D5 DriftEventHandler)

### Audit Events

Per D5: every enforcement action that changes state emits a typed event.
The audit system emits events via the `DriftEventHandler` trait.

```rust
/// Events emitted by the audit system.
pub trait AuditEventHandler: Send + Sync {
    /// Called when an audit run completes.
    fn on_audit_complete(&self, event: &AuditCompleteEvent) {}

    /// Called when health score degrades past a threshold.
    fn on_health_degraded(&self, event: &HealthDegradedEvent) {}

    /// Called when a pattern is auto-approved by the audit system.
    fn on_pattern_auto_approved(&self, event: &PatternAutoApprovedEvent) {}

    /// Called when an anomaly is detected in audit metrics.
    fn on_audit_anomaly(&self, event: &AuditAnomalyEvent) {}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditCompleteEvent {
    pub run_id: String,
    pub health_score: f64,
    pub alert_count: usize,
    pub auto_approved_count: usize,
    pub duration_ms: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthDegradedEvent {
    pub health_score: f64,
    pub alerts: Vec<DegradationAlert>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternAutoApprovedEvent {
    pub pattern_id: String,
    pub pattern_name: String,
    pub category: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditAnomalyEvent {
    pub metric: AnomalyMetric,
    pub value: f64,
    pub z_score: f64,
    pub severity: IssueSeverity,
}
```

### Integration with DriftEventHandler

These events are methods on the main `DriftEventHandler` trait (defined in
infrastructure). Default implementations are no-ops. The bridge crate
overrides them to create Cortex memories.

```rust
// In drift-core/src/events.rs (infrastructure)
pub trait DriftEventHandler: Send + Sync {
    // ... other events ...

    fn on_audit_complete(&self, _event: &AuditCompleteEvent) {}
    fn on_health_degraded(&self, _event: &HealthDegradedEvent) {}
    fn on_pattern_auto_approved(&self, _event: &PatternAutoApprovedEvent) {}
    fn on_audit_anomaly(&self, _event: &AuditAnomalyEvent) {}
}
```

---

## 26. Tracing & Observability

### Structured Tracing Events

Following the cortex-observability pattern, the audit system emits structured
tracing events for every significant operation.

```rust
use tracing::{info, warn, instrument};

#[instrument(skip(db, config, event_handler), fields(run_id))]
pub fn run_audit(
    db: &DatabaseManager,
    config: &AuditConfig,
    event_handler: &dyn DriftEventHandler,
) -> Result<AuditResult, AuditError> {
    let run_id = generate_run_id();
    tracing::Span::current().record("run_id", &run_id.as_str());

    info!(event = "audit_started", "starting audit run");

    // ... pipeline phases ...

    info!(
        event = "audit_complete",
        health_score = result.health_score,
        alert_count = result.degradation_alerts.len(),
        auto_approved = result.auto_approved.len(),
        duration_ms = result.duration_ms,
        "audit complete"
    );

    if !result.degradation_alerts.is_empty() {
        warn!(
            event = "degradation_detected",
            alert_count = result.degradation_alerts.len(),
            worst_level = ?result.degradation_alerts.iter().map(|a| &a.level).max(),
            "degradation alerts generated"
        );
    }

    if !result.anomalies.is_empty() {
        warn!(
            event = "anomalies_detected",
            anomaly_count = result.anomalies.len(),
            "statistical anomalies detected in audit metrics"
        );
    }

    Ok(result)
}
```

### Key Tracing Spans

| Span | Fields | Purpose |
|------|--------|---------|
| `audit_run` | run_id | Top-level audit execution |
| `audit_load_patterns` | count, categories | Pattern loading from drift.db |
| `audit_duplicate_detection` | groups_found, comparisons | Jaccard similarity computation |
| `audit_cross_validation` | issues_found | Cross-validation checks |
| `audit_health_score` | score, breakdown | Health score calculation |
| `audit_degradation` | alerts_generated | Degradation detection |
| `audit_trend_analysis` | health_trend, confidence_trend | Trend computation |
| `audit_prediction` | slope, r_squared | Linear regression |
| `audit_anomaly_detection` | anomalies_found | Statistical anomaly detection |
| `audit_persist` | snapshot_id | Snapshot persistence |


---

## 27. Configuration

### AuditConfig (TOML)

```toml
[audit]
# Recommendation thresholds (preserved from v1 — tuned values)
auto_approve_threshold = 0.90       # Confidence for auto-approval
review_threshold = 0.70             # Confidence for review recommendation
min_locations_for_established = 3   # Min locations for established pattern

# Duplicate detection
duplicate_similarity_threshold = 0.85  # Jaccard similarity for duplicate detection
auto_merge_threshold = 0.95            # Jaccard similarity for auto-merge (v2 upgrade)

# Cross-validation
max_outlier_ratio = 0.50            # Max outlier ratio before flagging

# Degradation alert thresholds (preserved from v1)
health_drop_warning = 5.0           # Points drop for warning
health_drop_critical = 15.0         # Points drop for critical
confidence_drop_warning = 0.05      # Percentage drop for warning
confidence_drop_critical = 0.15     # Percentage drop for critical
new_fp_warning = 5                  # New false positives for warning
new_fp_critical = 10                # New false positives for critical
duplicate_increase_warning = 3      # New duplicate groups for warning

# Trend analysis
trend_threshold_points = 2.0        # ±points for trend classification
trend_threshold_percent = 2.0       # ±percent for trend classification
rapid_growth_threshold = 5.0        # Patterns/day for "rapid" growth
stagnant_growth_threshold = 0.5     # Patterns/day for "stagnant" growth

# History
history_retention_days = 90         # Days to retain audit snapshots
```

### Rust Config Type

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    // Recommendation thresholds.
    pub auto_approve_threshold: f64,
    pub review_threshold: f64,
    pub min_locations_for_established: usize,

    // Duplicate detection.
    pub duplicate_similarity_threshold: f64,
    pub auto_merge_threshold: f64,

    // Cross-validation.
    pub max_outlier_ratio: f64,

    // Degradation alert thresholds.
    pub health_drop_warning: f64,
    pub health_drop_critical: f64,
    pub confidence_drop_warning: f64,
    pub confidence_drop_critical: f64,
    pub new_fp_warning: usize,
    pub new_fp_critical: usize,
    pub duplicate_increase_warning: usize,

    // Trend analysis.
    pub trend_threshold_points: f64,
    pub trend_threshold_percent: f64,
    pub rapid_growth_threshold: f64,
    pub stagnant_growth_threshold: f64,

    // History.
    pub history_retention_days: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            auto_approve_threshold: 0.90,
            review_threshold: 0.70,
            min_locations_for_established: 3,
            duplicate_similarity_threshold: 0.85,
            auto_merge_threshold: 0.95,
            max_outlier_ratio: 0.50,
            health_drop_warning: 5.0,
            health_drop_critical: 15.0,
            confidence_drop_warning: 0.05,
            confidence_drop_critical: 0.15,
            new_fp_warning: 5,
            new_fp_critical: 10,
            duplicate_increase_warning: 3,
            trend_threshold_points: 2.0,
            trend_threshold_percent: 2.0,
            rapid_growth_threshold: 5.0,
            stagnant_growth_threshold: 0.5,
            history_retention_days: 90,
        }
    }
}
```

---

## 28. Performance Targets & Benchmarks

### Target Performance

| Operation | Target | Rationale |
|-----------|--------|-----------|
| Full audit (100 patterns) | < 50ms | Interactive CLI response |
| Full audit (1000 patterns) | < 200ms | Large codebase, still fast |
| Full audit (10K patterns) | < 2s | Enterprise scale |
| Duplicate detection (1000 patterns) | < 100ms | O(N²) within category |
| Health score calculation | < 1ms | Simple arithmetic |
| Trend analysis (90 days) | < 10ms | Linear scan of history |
| Trend prediction (90 days) | < 5ms | Simple linear regression |
| Anomaly detection (30 days) | < 5ms | Z-score computation |
| Snapshot persistence | < 10ms | Single INSERT + UPDATE |
| History query (90 days) | < 5ms | Indexed timestamp query |

### Bottleneck Analysis

The primary bottleneck is duplicate detection (O(N²) pairwise comparison).
For 1000 patterns in a single category, this is 500K comparisons. Each
comparison is a set intersection (O(min(|A|, |B|))) on location sets.

Mitigation strategies (if needed):
1. **Category partitioning**: Already implemented — only compare within category
2. **MinHash approximation**: For categories with >500 patterns, use MinHash
   with 128 hash functions for O(N) approximate Jaccard
3. **Early termination**: Skip comparison if location set sizes differ by >5x
   (Jaccard can't exceed 0.85 if |A| > 5|B|)

### Benchmark Suite

```rust
#[bench]
fn bench_audit_100_patterns(b: &mut Bencher) {
    let patterns = generate_test_patterns(100);
    let config = AuditConfig::default();
    b.iter(|| {
        let _ = run_audit_pipeline(&patterns, &config);
    });
}

#[bench]
fn bench_audit_1000_patterns(b: &mut Bencher) {
    let patterns = generate_test_patterns(1000);
    let config = AuditConfig::default();
    b.iter(|| {
        let _ = run_audit_pipeline(&patterns, &config);
    });
}

#[bench]
fn bench_jaccard_similarity(b: &mut Bencher) {
    let set_a: FxHashSet<(String, u32)> = (0..100).map(|i| (format!("file_{}.ts", i % 10), i)).collect();
    let set_b: FxHashSet<(String, u32)> = (50..150).map(|i| (format!("file_{}.ts", i % 10), i)).collect();
    b.iter(|| {
        let _ = jaccard_similarity(&set_a, &set_b);
    });
}

#[bench]
fn bench_trend_prediction_90_days(b: &mut Bencher) {
    let history = generate_test_history(90);
    b.iter(|| {
        let _ = predict_trend(&history);
    });
}
```

---

## 29. Build Order & Dependencies

### Prerequisites

The audit system depends on:
1. **drift-core storage** (drift.db with pattern tables) — must exist
2. **Pattern detection** (patterns, confidence, locations in drift.db) — must have run
3. **Call graph** (for cross-validation) — optional but recommended
4. **Constraint system** (for constraint alignment) — optional
5. **Infrastructure** (thiserror, tracing, DriftEventHandler) — must exist

### Build Phases

**Phase 1: Core Types & Config (Day 1)**
1. `types.rs` — All type definitions (§4)
2. `config.rs` — AuditConfig with defaults (§27)
3. `mod.rs` — Module declarations and re-exports

**Phase 2: Health Score & Recommendations (Day 2-3)**
4. `health_score.rs` — 5-factor weighted formula (§9)
5. `recommendations.rs` — Auto-approve / review / likely-FP (§8)
6. `duplicate_detection.rs` — Jaccard similarity (§6)
7. `cross_validation.rs` — 4 validation checks (§7)

**Phase 3: Degradation & Trends (Day 4-5)**
8. `degradation.rs` — Alert generation (§11)
9. `trend_analysis.rs` — 7-day rolling averages (§12)
10. `trend_prediction.rs` — Linear regression (§13)
11. `anomaly_detection.rs` — Z-score anomaly detection (§14)

**Phase 4: Persistence & Engine (Day 6-7)**
12. `snapshot.rs` — Snapshot persistence, history queries (§15)
13. `summary.rs` — Audit summary builder (§16)
14. `engine.rs` — AuditEngine orchestrator (§5)

**Phase 5: Integration (Day 8-9)**
15. Storage migration — Create audit tables (§21)
16. NAPI bindings — `bindings/audit.rs` (§22)
17. Event integration — DriftEventHandler methods (§25)
18. Tracing integration — Structured spans (§26)

**Phase 6: Testing & Benchmarks (Day 10)**
19. Unit tests for each module
20. Integration tests (full pipeline)
21. Benchmark suite (§28)
22. Golden tests (known-good audit results)

### Total Estimated Effort: 10 working days

This is a focused, well-scoped system. The algorithms are straightforward
(weighted averages, Jaccard similarity, linear regression, z-scores). The
complexity is in the integration points and ensuring zero feature loss from v1.

---

## 30. V1 → V2 Feature Cross-Reference

Complete mapping of every v1 feature to its v2 location.

| V1 Feature | V1 Location | V2 Location | Status |
|-----------|-------------|-------------|--------|
| AuditEngine.runAudit() | audit-engine.ts | engine.rs::run_audit() | **KEPT** |
| Pattern filtering by category | audit-engine.ts | engine.rs::load_patterns() | **KEPT** |
| Duplicate detection (Jaccard) | audit-engine.ts | duplicate_detection.rs | **KEPT** |
| Jaccard threshold 0.85 | audit-engine.ts | config.rs (default) | **KEPT** |
| Merge recommendation (>0.9) | audit-engine.ts | duplicate_detection.rs | **UPGRADED** (>0.95 auto-merge) |
| Cross-validation: orphan | audit-engine.ts | cross_validation.rs | **KEPT** |
| Cross-validation: outlier ratio | audit-engine.ts | cross_validation.rs | **KEPT** |
| Cross-validation: low conf approved | audit-engine.ts | cross_validation.rs | **KEPT** |
| Cross-validation: constraint align | audit-engine.ts | cross_validation.rs | **KEPT** |
| Auto-approve criteria | audit-engine.ts | recommendations.rs | **KEPT** |
| Review criteria | audit-engine.ts | recommendations.rs | **KEPT** |
| Likely-FP criteria | audit-engine.ts | recommendations.rs | **KEPT** |
| Duplicate downgrade rule | audit-engine.ts | recommendations.rs | **KEPT** |
| Health score formula | audit-engine.ts | health_score.rs | **KEPT** (exact weights) |
| Health score weights | audit-engine.ts | health_score.rs | **KEPT** (0.30/0.20/0.20/0.15/0.15) |
| Audit summary | audit-engine.ts | summary.rs | **KEPT** |
| latest.json | audit-store.ts | drift.db audit_snapshots | **UPGRADED** |
| Snapshot history (30-day) | audit-store.ts | drift.db (90-day retention) | **UPGRADED** |
| degradation.json | audit-store.ts | drift.db audit_degradation_log | **UPGRADED** |
| Health drop alert (-5/-15) | audit-store.ts | degradation.rs | **KEPT** |
| Confidence drop alert (-5%/-15%) | audit-store.ts | degradation.rs | **KEPT** |
| New FP alert (>5/>10) | audit-store.ts | degradation.rs | **KEPT** |
| Duplicate increase alert (>3) | audit-store.ts | degradation.rs | **KEPT** |
| 7-day rolling averages | audit-store.ts | trend_analysis.rs | **KEPT** |
| Trend classification (±2) | audit-store.ts | trend_analysis.rs | **KEPT** |
| Pattern growth (>5/day, <0.5/day) | audit-store.ts | trend_analysis.rs | **KEPT** |
| 90-day history retention | audit-store.ts | config.rs (default) | **KEPT** |
| autoApproveThreshold: 0.90 | config | config.rs | **KEPT** |
| reviewThreshold: 0.70 | config | config.rs | **KEPT** |
| duplicateSimilarityThreshold: 0.85 | config | config.rs | **KEPT** |
| minLocationsForEstablished: 3 | config | config.rs | **KEPT** |
| maxOutlierRatio: 0.5 | config | config.rs | **KEPT** |

### New V2 Features (Not in V1)

| Feature | V2 Location | Source |
|---------|-------------|--------|
| Per-category health breakdown | health_score.rs | GA3 v2 additions |
| Trend prediction (linear regression) | trend_prediction.rs | GA3 v2 additions |
| Anomaly detection (z-score) | anomaly_detection.rs | GA3 v2 additions |
| Auto-merge threshold (0.95) | config.rs | GA3 |
| Bayesian confidence integration | health_score.rs | AD8 |
| DriftEventHandler events | engine.rs | D5 |
| SQLite-native persistence | snapshot.rs | 02-STORAGE-V2-PREP |
| Materialized status integration | snapshot.rs | 02-STORAGE-V2-PREP |
| NAPI async audit | bindings/audit.rs | 03-NAPI-BRIDGE-V2-PREP |
| MCP drift_audit tool | MCP server | 07-mcp |
| CLI drift audit command | CLI | 10-cli |
| Grounding check (D7) | engine.rs | PLANNING-DRIFT D7 |

---

## 31. Inconsistencies & Decisions

### Resolved Inconsistencies

**1. Merge threshold: 0.9 (v1) vs 0.95 (GA3)**
The v1 audit-engine.ts used 0.9 as the merge recommendation threshold.
GA3 mentions auto-merge at >0.95. Resolution: V2 uses a two-tier system:
- Auto-merge: >0.95 (new, safe for automation)
- Merge recommendation: >0.90 (preserved from v1)
- Review: 0.85-0.90 (preserved from v1)

**2. Snapshot retention: 30 days (v1 code) vs 90 days (v1 docs)**
The v1 audit-store.ts had 30-day snapshot retention, but the audit.md docs
say "90 days of daily entries." Resolution: V2 uses 90 days (the documented
value). The 30-day code value was likely a bug or early default.

**3. Health score in Cortex vs Drift**
Cortex's `HealthReport` uses `HealthStatus` (Healthy/Degraded/Unhealthy) as
a categorical assessment. Drift's audit uses a numeric score (0-100). These
are complementary, not conflicting. Drift's numeric score can be mapped to
Cortex's categorical status: ≥70 = Healthy, 50-70 = Degraded, <50 = Unhealthy.

**4. Cross-validation: call graph coverage**
The v1 audit.md mentions "patterns in call graph / total" as a factor, but
the v1 code only checks constraint alignment. Resolution: V2 includes both
call graph coverage AND constraint alignment in cross-validation, with call
graph coverage feeding into the `crossValidationRate` health factor.

**5. Duplicate detection scope**
V1 only compares patterns within the same category. This is correct — patterns
in different categories (e.g., "security" vs "testing") should never be
considered duplicates even if they share locations. V2 preserves this behavior.

### Open Decisions

**1. Should auto-approve be automatic or require confirmation?**
V1 auto-approve was a recommendation only — it didn't actually change pattern
status. V2 adds `apply_auto_approvals()` as an explicit action. The MCP tool
supports `apply_auto_approve: true` for AI-assisted workflows.
Decision: Auto-approve remains a recommendation by default. Explicit action
required to apply. This preserves developer control.

**2. Should anomaly detection use Grubbs' test for small samples?**
The outlier detection V2 prep (11-OUTLIER-DETECTION-V2-PREP.md) specifies
Grubbs' test for 10≤n<30 samples. For audit anomaly detection, we typically
have 7-90 data points. Decision: Use z-score for simplicity. Grubbs' test
adds complexity without significant benefit for this use case (we're not
detecting outliers in a sample — we're comparing a single value against a
distribution).

**3. Should per-category health use the same 5-factor formula?**
The overall health score uses 5 factors. Per-category health can't use all 5
(approval ratio and duplicate-free rate are less meaningful per-category).
Decision: Per-category uses a simplified 2-factor formula:
`score = (avg_confidence × 0.50 + compliance_rate × 0.50) × 100`.
This is sufficient for category-level health assessment.

**4. Should trend prediction use exponential smoothing instead of linear regression?**
Linear regression assumes a linear trend. Exponential smoothing handles
non-linear trends better. Decision: Start with linear regression (simpler,
interpretable, R² provides confidence measure). Add exponential smoothing
as a future enhancement if linear regression proves insufficient.

---

## 32. Risk Register

| Risk | Impact | Likelihood | Mitigation |
|------|--------|-----------|------------|
| Health score formula changes break user expectations | High | Low | Exact v1 weights preserved. Any changes require A/B testing. |
| Duplicate detection O(N²) too slow for large categories | Medium | Low | Category partitioning already limits N. MinHash fallback ready. |
| Trend prediction misleading with insufficient data | Medium | Medium | R² confidence metric + minimum data point requirements. |
| Anomaly detection false alarms | Low | Medium | Conservative z-score threshold (2.5). Minimum 7 data points. |
| Auto-approve applies incorrect recommendations | High | Low | Explicit action required. Recommendations are suggestions only. |
| Snapshot retention fills disk | Low | Low | 90-day retention with automatic cleanup. Each snapshot ~1KB. |
| Cross-validation depends on call graph availability | Medium | Medium | Graceful degradation: if no call graph, cross_validation_rate defaults to 0.5. |
| Per-category trends noisy with few patterns | Low | Medium | Minimum 3 patterns per category for trend calculation. |
| Bayesian confidence integration changes health scores | Medium | Medium | Bayesian posterior mean is close to static confidence for established patterns. Divergence only for new/uncertain patterns. |
| Migration from v1 JSON to v2 SQLite loses history | Medium | Low | Migration script reads v1 JSON files and inserts into drift.db. |

---

## Summary of All Decisions

| Decision | Choice | Confidence | Source |
|----------|--------|------------|--------|
| Health score formula | 5-factor weighted, exact v1 weights | Very High | v1 audit-engine.ts, GA3 |
| Health score weights | 0.30/0.20/0.20/0.15/0.15 | Very High | v1 tuned values |
| Duplicate detection | Jaccard similarity, threshold 0.85 | Very High | v1 preserved |
| Auto-merge threshold | 0.95 (new tier above v1's 0.90 merge) | High | GA3 |
| Auto-approve criteria | conf≥0.90, outlier≤0.50, locs≥3, no errors | Very High | v1 preserved |
| Review threshold | 0.70 | Very High | v1 preserved |
| Degradation thresholds | -5/-15 health, -5%/-15% conf, >5/>10 FP, >3 dup | Very High | v1 preserved |
| Trend classification | ±2 points/percent threshold | Very High | v1 preserved |
| Pattern growth thresholds | >5/day rapid, <0.5/day stagnant | Very High | v1 preserved |
| History retention | 90 days | High | v1 docs (corrected from 30-day code) |
| Persistence | drift.db SQLite (no JSON files) | Very High | 02-STORAGE-V2-PREP |
| Per-category health | 2-factor simplified formula | High | v2 design decision |
| Trend prediction | Linear regression with R² confidence | High | v2 addition |
| Anomaly detection | Z-score, threshold 2.5, min 7 data points | High | v2 addition |
| Event system | DriftEventHandler trait, no-op defaults | Very High | D5 |
| NAPI interface | Async run_audit + sync queries | Very High | 03-NAPI-BRIDGE-V2-PREP |
| Auto-approve behavior | Recommendation only, explicit apply action | High | Developer control |
| Cross-validation scope | 5 checks (orphan, outlier, low-conf, constraint, call graph) | High | v1 + v2 expansion |
| Module structure | 13 files in drift-core/src/audit/ | High | Follows crate conventions |
| Build effort | 10 working days | Medium-High | Based on algorithm complexity |
