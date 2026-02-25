# Violation Feedback Loop (Tricorder-Style FP Tracking) — V2 Implementation Prep

> Comprehensive build specification for Drift v2's Violation Feedback Loop — the self-healing
> system that tracks developer actions on violations, computes per-detector false positive rates,
> auto-disables noisy detectors, and feeds confidence adjustments back into the pattern system.
> Synthesized from: DRIFT-V2-FULL-SYSTEM-AUDIT.md (AD9, Cat 09 Enforcement, P1 #16),
> DRIFT-V2-STACK-HIERARCHY.md (Level 3 Enforcement — "Self-healing loop"),
> PLANNING-DRIFT.md (D1 standalone, D5 DriftEventHandler, D7 grounding feedback loop),
> 09-QUALITY-GATES-V2-PREP.md (§15 Developer Feedback Loop R6, §12 Progressive Enforcement R2,
> violation_feedback table, FeedbackStats, enforcement transitions),
> 25-AUDIT-SYSTEM-V2-PREP.md (§18 Integration with Violation Feedback Loop, bidirectional
> data flow, Tricorder-style integration, health score FP factor),
> 13-LEARNING-SYSTEM-V2-PREP.md (§20 Integration with Feedback Loop AD9,
> ConventionFeedback enum, ConventionEffectiveness, false_positive_rate(), should_disable()),
> 04-INFRASTRUCTURE-V2-PREP.md (§4 DriftEventHandler: on_violation_detected,
> on_violation_dismissed, on_violation_fixed, on_detector_alert, on_detector_disabled),
> .research/09-quality-gates/RESEARCH.md (QG-R5 Google Tricorder <10% FP rate,
> QG-R3 Semgrep three-mode policies, QG-R4 Meta Fix Fast signal aggregation,
> QG-R15 Augment Code enterprise FP management),
> .research/09-quality-gates/RECOMMENDATIONS.md (R2 progressive enforcement,
> R6 developer feedback loop, R11 hotspot-aware scoring),
> Sadowski et al. "Lessons from Building Static Analysis Tools at Google" (CACM 2018),
> Semgrep Assistant Memories (2025 — AI-powered FP triage with organizational memory),
> Semgrep triage/remediation workflow (7 triage statuses, auto-triage, nosemgrep comments),
> cortex-consolidation/src/pipeline/phase3_recall_gate.rs (Rust gate pattern reference),
> cortex-observability (HealthChecker, DegradationTracker proven patterns),
> cortex-learning (process_feedback Cortex memory feedback pattern),
> 03-NAPI-BRIDGE-V2-PREP.md (template pattern for v2 prep documents),
> 26-OWASP-CWE-MAPPING-V2-PREP.md (CWE taxonomy for SARIF suppression metadata),
> 20-CONSTRAINT-SYSTEM-V2-PREP.md (constraint violation feedback integration).
>
> Purpose: Everything needed to build the violation feedback loop from scratch. All v1
> features preserved and upgraded. All architectural decisions resolved. Every algorithm
> specified. Every type defined. Every integration point documented. Every event contract
> defined. Zero feature loss. Tricorder-grade self-healing analysis quality.
> Generated: 2026-02-08

---

## Table of Contents

1. Architectural Position
2. V1 Complete Feature Inventory — Preservation Matrix
3. V2 Architecture — Unified Feedback Engine
4. Core Data Model (Rust Types)
5. Violation Action Taxonomy (5 Actions + Sub-Reasons)
6. False Positive Rate Computation Engine
7. Detector Health Monitoring & Auto-Disable
8. Confidence Adjustment Pipeline
9. Inline Suppression System (drift-ignore)
10. Progressive Enforcement Integration
11. Feedback Persistence — SQLite in drift.db
12. Event System Integration (D5 DriftEventHandler)
13. Feedback Aggregation & Statistics Engine
14. Abuse Detection & Safety Rails
15. MCP Tool Interface
16. CLI Interface
17. IDE / LSP Integration
18. SARIF Suppression Mapping
19. Integration with Upstream Systems
20. Integration with Downstream Consumers
21. NAPI Bridge Interface
22. Cortex Bridge Integration (D7 Grounding)
23. Configuration (drift.toml)
24. License Gating — Tier Mapping
25. Resolved Inconsistencies
26. File / Module Structure
27. Build Order & Dependency Chain
28. V1 Feature Verification — Complete Gap Analysis
29. Algorithms Reference
30. Research Grounding — External Sources

---

## 1. Architectural Position

The Violation Feedback Loop is Level 3 (Enforcement) in Drift's stack hierarchy. It is
the self-healing system that transforms developer actions on violations into signals that
improve analysis quality over time. Without it, Drift's analysis accumulates false positives
until developers ignore all results — the #1 cause of static analysis tool abandonment.

Per PLANNING-DRIFT.md D1: Drift is standalone. The feedback loop lives entirely in drift-core.
Per PLANNING-DRIFT.md D5: Feedback events emit via DriftEventHandler (no-op in standalone).
Per PLANNING-DRIFT.md D7: The bridge consumes feedback events to create Cortex memories.

Per DRIFT-V2-STACK-HIERARCHY.md:
> Violation Feedback Loop (Tricorder-style) — FP tracking per detector, auto-disable >20%
> for 30+ days, action feeds back into confidence. Self-healing loop. Per D5: violation
> feedback events (on_violation_dismissed, on_detector_disabled) should be emitted via
> DriftEventHandler so the bridge can propagate to Cortex.

Per DRIFT-V2-FULL-SYSTEM-AUDIT.md AD9:
> "Not useful" / "Useful" signals on every violation. Track effective false-positive rate
> per detector (<5% target). Detectors with >10% FP rate get alert, >20% for 30+ days
> get auto-disabled. Developer action (fix, ignore, approve) feeds back into pattern
> confidence. Project-level customization, not user-level.

Per DRIFT-V2-FULL-SYSTEM-AUDIT.md P1 #16:
> Violation Feedback Loop → Tricorder-style FP tracking, detector health, auto-disable

### What Lives Here

- Violation action recording (fix, dismiss, ignore, auto-fix, not-seen tracking)
- Per-detector false positive rate computation (Tricorder formula)
- Per-pattern false positive rate computation (for enforcement transitions)
- Detector health monitoring with alert/disable thresholds
- Automatic detector disable at >20% FP rate for 30+ days
- Confidence adjustment pipeline (feedback → Bayesian parameter updates)
- Inline suppression system (`// drift-ignore` with expiration)
- Feedback aggregation and statistics engine
- Abuse detection (dismiss-rate-per-author monitoring)
- SARIF suppression mapping for audit trails
- Event emission via DriftEventHandler (D5)
- Feedback persistence in drift.db (violation_feedback, pattern_suppressions tables)

### What Does NOT Live Here

- Quality gate execution (lives in Quality Gates — gates consume feedback stats)
- Pattern detection (lives in Detector System — detectors produce violations)
- Pattern confidence scoring (lives in Bayesian Confidence — feedback adjusts parameters)
- Enforcement mode transitions (lives in Quality Gates §12 — consumes FP rates from here)
- Audit health scoring (lives in Audit System — consumes FP counts from here)
- Learning system adjustments (lives in Learning System — consumes feedback signals)
- MCP tool routing (lives in MCP Server — calls feedback APIs)
- CLI command parsing (lives in CLI — calls feedback APIs)
- NAPI bridge functions (lives in drift-napi — thin wrappers around feedback APIs)

### Upstream Dependencies (What Feedback Loop Consumes)

| System | What It Provides | How Feedback Uses It |
|--------|-----------------|---------------------|
| Detector System (06) | Violations with pattern IDs, detector IDs | Records actions against violations |
| Rules Engine | Violation IDs, severity, locations | Links feedback to specific violations |
| Quality Gates (09) | Gate results with violations | Tracks which violations were surfaced |
| Bayesian Confidence (10) | Current α/β parameters per pattern | Adjusts parameters based on feedback |
| Scanner (00) | File content hashes | Detects auto-fixed violations (content changed) |

### Downstream Consumers (What Consumes Feedback Data)

| System | What It Consumes | How It Uses It |
|--------|-----------------|---------------|
| Quality Gates (09) | FP rates per pattern | Enforcement mode transitions (§12) |
| Audit System (25) | FP counts, detector health | Health score calculation, degradation alerts |
| Learning System (13) | Convention feedback signals | Bayesian α/β adjustments |
| Bayesian Confidence (10) | Feedback-driven parameter updates | Posterior recalculation |
| Progressive Enforcement | Per-pattern FP rates | Promotion/demotion decisions |
| SARIF Reporter | Suppression records | SARIF suppression objects in output |
| Cortex Bridge (D7) | Feedback events | Memory creation (constraint_override, anti_pattern) |

---

## 2. V1 Complete Feature Inventory — Preservation Matrix

Every v1 feature must be preserved or explicitly upgraded. No silent drops.

### V1 Features from DRIFT-V2-FULL-SYSTEM-AUDIT.md

| # | V1 Feature | V1 Location | V2 Status | V2 Section |
|---|-----------|-------------|-----------|------------|
| 1 | "Not useful" / "Useful" signals on every violation | MCP, CLI, IDE | ✅ Preserved + expanded to 5 actions | §5 |
| 2 | Track violation actions: Fixed, Dismissed, Ignored, AutoFixed, NotSeen | Enforcement layer | ✅ Preserved exactly | §5 |
| 3 | Effective FP rate per detector | Enforcement layer | ✅ Preserved + per-pattern added | §6 |
| 4 | FP formula: (dismissed+ignored)/(fixed+dismissed+ignored+autoFixed) | Enforcement layer | ✅ Preserved exactly | §6 |
| 5 | Detector health alert at >10% FP rate | Enforcement layer | ✅ Preserved | §7 |
| 6 | Auto-disable at >20% FP rate for 30+ days | Enforcement layer | ✅ Preserved | §7 |
| 7 | Developer action feeds back into pattern confidence | Enforcement layer | ✅ Preserved + Bayesian | §8 |
| 8 | Project-level customization, not user-level | Config | ✅ Preserved | §23 |
| 9 | Expose health metrics via MCP | MCP tools | ✅ Preserved + expanded | §15 |
| 10 | Track in IDE (opt-in) | VSCode extension | ✅ Preserved | §17 |
| 11 | Track in CLI | CLI commands | ✅ Preserved | §16 |
| 12 | Track in CI | CI agent | ✅ Preserved | §16 |

### V1 Features from Quality Gates (09-QUALITY-GATES-V2-PREP.md §15)

| # | V1/R6 Feature | V2 Status | V2 Section |
|---|--------------|-----------|------------|
| 13 | Feedback actions: fix, dismiss:false-positive, dismiss:wont-fix, dismiss:not-applicable | ✅ Preserved + expanded | §5 |
| 14 | Confidence adjustment: fix +0.02, dismiss:fp -0.05, dismiss:na -0.02 | ✅ Upgraded to Bayesian | §8 |
| 15 | Automatic demotion at >10% FP (block→comment) | ✅ Preserved | §10 |
| 16 | Automatic demotion at >25% FP (comment→monitor) | ✅ Preserved | §10 |
| 17 | violation_feedback SQLite table | ✅ Preserved + expanded | §11 |
| 18 | Indefinite retention (audit trail) | ✅ Preserved | §11 |
| 19 | Dismissal requires reason | ✅ Preserved | §5 |
| 20 | Abuse detection: author dismiss rate monitoring | ✅ Preserved + expanded | §14 |

### V1 Features from Learning System (13-LEARNING-SYSTEM-V2-PREP.md §20)

| # | V1 Feature | V2 Status | V2 Section |
|---|-----------|-----------|------------|
| 21 | ConventionFeedback enum (ViolationFixed, ViolationDismissed, Approved, Rejected) | ✅ Preserved | §5 |
| 22 | Bayesian α/β adjustment from feedback | ✅ Preserved | §8 |
| 23 | ConventionEffectiveness tracking | ✅ Preserved + expanded | §6 |
| 24 | false_positive_rate() computation | ✅ Preserved exactly | §6 |
| 25 | should_disable() with ≥10 acted-on minimum | ✅ Preserved | §7 |

### V1 Features from Audit System (25-AUDIT-SYSTEM-V2-PREP.md §18)

| # | V1 Feature | V2 Status | V2 Section |
|---|-----------|-----------|------------|
| 26 | Bidirectional data flow (Audit↔Feedback) | ✅ Preserved | §19, §20 |
| 27 | Auto-approve suppression for unhealthy detectors | ✅ Preserved | §7 |
| 28 | Health score FP factor (duplicateFreeRate) | ✅ Preserved | §20 |
| 29 | Degradation alerts on FP count increase | ✅ Preserved | §20 |

### V1 Features from Infrastructure (04-INFRASTRUCTURE-V2-PREP.md §4)

| # | V1 Feature | V2 Status | V2 Section |
|---|-----------|-----------|------------|
| 30 | on_violation_detected event | ✅ Preserved | §12 |
| 31 | on_violation_dismissed event | ✅ Preserved | §12 |
| 32 | on_violation_fixed event | ✅ Preserved | §12 |
| 33 | on_detector_alert event | ✅ Preserved | §12 |
| 34 | on_detector_disabled event | ✅ Preserved | §12 |

### V1 Features from Full System Audit (Pattern Suppression)

| # | V1 Feature | V2 Status | V2 Section |
|---|-----------|-----------|------------|
| 35 | pattern_suppressions table for `// drift-ignore` | ✅ Preserved + expanded | §9 |
| 36 | Inline suppression with reason | ✅ Preserved | §9 |
| 37 | Expiration support for temporary suppressions | ✅ Preserved | §9 |

### V1 Features from MCP Feedback System

| # | V1 Feature | V2 Status | V2 Section |
|---|-----------|-----------|------------|
| 38 | User ratings: good (+0.1), bad (-0.15), irrelevant (-0.05) | ✅ Upgraded to Bayesian | §8 |
| 39 | Directory-level score propagation (30% of file delta) | ✅ Preserved | §8 |
| 40 | File exclusion when confidence > 0.5 and boost < -0.5 | ✅ Preserved | §8 |

**Total v1 features: 40. Total preserved: 40. Total upgraded: 8. Total dropped: 0.**

---

## 3. V2 Architecture — Unified Feedback Engine

### Design Philosophy

The v2 feedback loop is a unified engine that consolidates the scattered v1 feedback
mechanisms (MCP ratings, violation actions, inline suppressions, convention feedback)
into a single coherent system with one source of truth in drift.db.

Key architectural principles:
1. **Single source of truth**: All feedback flows through `FeedbackEngine` and persists
   in `violation_feedback` + `pattern_suppressions` tables in drift.db
2. **Event-driven propagation**: Every feedback action emits a DriftEventHandler event (D5)
3. **Lazy aggregation**: Statistics are computed on-demand or during scheduled audit,
   not on every feedback action (performance)
4. **Conservative adjustments**: Feedback adjustments are small relative to scan-derived
   signals (0.5 per dismissal vs integer counts from scan) — per Learning System §20.2
5. **Project-level scope**: Feedback is project-scoped, not user-scoped (AD9)
6. **Audit trail**: All feedback is immutable and indefinitely retained

### System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         FEEDBACK ENTRY POINTS                               │
│  MCP Tools │ CLI Commands │ IDE Actions │ PR Comments │ Auto-Detection      │
├─────────────────────────────────────────────────────────────────────────────┤
│                         FEEDBACK ENGINE (Rust)                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │ Action       │  │ Suppression  │  │ Statistics   │  │ Health       │   │
│  │ Recorder     │  │ Manager      │  │ Aggregator   │  │ Monitor      │   │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘   │
│         │                 │                 │                 │            │
│  ┌──────┴─────────────────┴─────────────────┴─────────────────┴──────┐    │
│  │                    PERSISTENCE (drift.db)                          │    │
│  │  violation_feedback │ pattern_suppressions │ detector_health       │    │
│  └────────────────────────────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────────────────────┤
│                         EVENT EMISSION (D5)                                 │
│  on_violation_dismissed │ on_violation_fixed │ on_detector_alert │ ...     │
├─────────────────────────────────────────────────────────────────────────────┤
│                         DOWNSTREAM CONSUMERS                                │
│  Quality Gates │ Audit System │ Learning System │ Bayesian Confidence       │
│  Progressive Enforcement │ SARIF Reporter │ Cortex Bridge (D7)             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

| Component | Responsibility | Rust/TS |
|-----------|---------------|---------|
| ActionRecorder | Validates and persists feedback actions | Rust |
| SuppressionManager | Manages inline `// drift-ignore` suppressions | Rust |
| StatisticsAggregator | Computes FP rates, action distributions, trends | Rust |
| HealthMonitor | Monitors detector health, triggers alerts/disables | Rust |
| ConfidenceAdjuster | Applies Bayesian parameter updates from feedback | Rust |
| AbuseDetector | Monitors per-author dismiss rates, flags anomalies | Rust |
| FeedbackEngine | Orchestrator — coordinates all components | Rust |
| FeedbackOrchestrator | TS coordination — resolves context, calls Rust | TS |

### Why Rust-First

The feedback engine is Rust-first because:
1. Statistics computation (FP rates across thousands of patterns) benefits from Rust speed
2. Bayesian parameter updates are numerical computation
3. SQLite access is already in Rust (drift.db owned by Rust)
4. Event emission is via Rust DriftEventHandler trait
5. Health monitoring runs during scan (Rust pipeline)
6. TS orchestrator is thin — resolves git context, calls NAPI functions

---

## 4. Core Data Model (Rust Types)

### Violation Action Types

```rust
use serde::{Deserialize, Serialize};
use std::fmt;

/// The 5 violation actions tracked by the feedback loop.
/// Per DRIFT-V2-FULL-SYSTEM-AUDIT.md: Fixed, Dismissed, Ignored, AutoFixed, NotSeen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationAction {
    /// Developer manually fixed the violation in code.
    Fixed,
    /// Developer explicitly dismissed the violation with a reason.
    Dismissed,
    /// Developer ignored the violation (no explicit action, inferred from behavior).
    Ignored,
    /// Violation was automatically fixed by quick-fix application.
    AutoFixed,
    /// Violation was present in previous scan but not acted upon.
    /// Tracked for denominator accuracy — not counted as positive or negative signal.
    NotSeen,
}

impl ViolationAction {
    /// Whether this action counts as a positive signal (violation was valid).
    pub fn is_positive_signal(&self) -> bool {
        matches!(self, ViolationAction::Fixed | ViolationAction::AutoFixed)
    }

    /// Whether this action counts as a negative signal (violation was noise).
    pub fn is_negative_signal(&self) -> bool {
        matches!(self, ViolationAction::Dismissed | ViolationAction::Ignored)
    }

    /// Whether this action counts toward the FP rate denominator.
    pub fn counts_toward_fp_rate(&self) -> bool {
        !matches!(self, ViolationAction::NotSeen)
    }
}

impl fmt::Display for ViolationAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ViolationAction::Fixed => write!(f, "fixed"),
            ViolationAction::Dismissed => write!(f, "dismissed"),
            ViolationAction::Ignored => write!(f, "ignored"),
            ViolationAction::AutoFixed => write!(f, "auto_fixed"),
            ViolationAction::NotSeen => write!(f, "not_seen"),
        }
    }
}
```

### Dismissal Reasons

```rust
/// Sub-reasons for dismissal actions.
/// Per 09-QUALITY-GATES-V2-PREP.md §15 R6.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DismissalReason {
    /// Pattern incorrectly flagged this code — false positive.
    /// Effect: -0.05 confidence (v1), β += 0.5 (v2 Bayesian).
    FalsePositive,
    /// Valid violation but intentional deviation — create exception.
    /// Effect: no confidence change, creates suppression record.
    WontFix,
    /// Pattern doesn't apply to this context.
    /// Effect: -0.02 confidence (v1), β += 0.25 (v2 Bayesian).
    NotApplicable,
    /// Duplicate of another violation already addressed.
    /// Effect: no confidence change, no FP count.
    Duplicate,
}

impl DismissalReason {
    /// Whether this dismissal counts as a false positive for FP rate calculation.
    pub fn counts_as_false_positive(&self) -> bool {
        matches!(self, DismissalReason::FalsePositive | DismissalReason::NotApplicable)
    }

    /// Bayesian beta adjustment for this dismissal type.
    pub fn beta_adjustment(&self) -> f64 {
        match self {
            DismissalReason::FalsePositive => 0.5,
            DismissalReason::NotApplicable => 0.25,
            DismissalReason::WontFix => 0.0,
            DismissalReason::Duplicate => 0.0,
        }
    }
}
```


### Feedback Record

```rust
/// A single feedback action recorded against a violation.
/// Immutable once created — audit trail requirement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackRecord {
    /// Unique ID (UUID v7 for time-ordered).
    pub id: String,
    /// The violation this feedback is about.
    pub violation_id: String,
    /// The pattern that produced the violation.
    pub pattern_id: String,
    /// The detector that owns the pattern.
    pub detector_id: String,
    /// The action taken.
    pub action: ViolationAction,
    /// Sub-reason for dismissals (required when action == Dismissed).
    pub dismissal_reason: Option<DismissalReason>,
    /// Free-text reason provided by developer.
    pub reason: Option<String>,
    /// Author who took the action (git author or IDE user).
    pub author: Option<String>,
    /// File where the violation was located.
    pub file: String,
    /// Line number of the violation.
    pub line: u32,
    /// Column number of the violation (optional).
    pub column: Option<u32>,
    /// The rule/gate that surfaced this violation.
    pub source_gate: Option<String>,
    /// Git commit SHA at the time of feedback (for audit).
    pub commit_sha: Option<String>,
    /// Branch where feedback was given.
    pub branch: Option<String>,
    /// Timestamp (ISO 8601).
    pub timestamp: String,
    /// Whether this was an automated action (auto-fix, auto-detect).
    pub is_automated: bool,
}
```

### Inline Suppression Record

```rust
/// An inline suppression via `// drift-ignore` comment.
/// Per DRIFT-V2-FULL-SYSTEM-AUDIT.md: pattern_suppressions table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionRecord {
    /// Unique ID.
    pub id: String,
    /// File containing the suppression comment.
    pub file: String,
    /// Line number of the suppression comment.
    pub line: u32,
    /// Pattern ID being suppressed (None = suppress all on this line).
    pub pattern_id: Option<String>,
    /// Detector ID being suppressed (None = suppress all detectors).
    pub detector_id: Option<String>,
    /// Reason for suppression (required).
    pub reason: String,
    /// Expiration date (None = permanent).
    /// Per DRIFT-V2-FULL-SYSTEM-AUDIT.md: "Expiration support for temporary suppressions."
    pub expires_at: Option<String>,
    /// Author who added the suppression.
    pub created_by: Option<String>,
    /// When the suppression was first detected.
    pub created_at: String,
    /// Whether the suppression is currently active.
    pub is_active: bool,
}
```

### Detector Health State

```rust
/// Health state for a single detector, computed from feedback data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorHealthState {
    /// Detector ID.
    pub detector_id: String,
    /// Current effective FP rate (0.0 - 1.0).
    pub fp_rate: f64,
    /// Number of days the FP rate has exceeded the alert threshold.
    pub days_above_alert: u32,
    /// Number of days the FP rate has exceeded the disable threshold.
    pub days_above_disable: u32,
    /// Current health status.
    pub status: DetectorHealthStatus,
    /// Total violations produced by this detector (acted upon).
    pub total_acted_on: u64,
    /// Total violations fixed.
    pub total_fixed: u64,
    /// Total violations dismissed.
    pub total_dismissed: u64,
    /// Total violations ignored.
    pub total_ignored: u64,
    /// Total violations auto-fixed.
    pub total_auto_fixed: u64,
    /// Last time health was evaluated.
    pub last_evaluated: String,
    /// Trend direction over last 30 days.
    pub trend: TrendDirection,
}

/// Detector health status levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorHealthStatus {
    /// FP rate < 5% — healthy.
    Healthy,
    /// FP rate 5-10% — warning, needs attention.
    Warning,
    /// FP rate 10-20% — alert, flagged for review.
    Alert,
    /// FP rate > 20% for < 30 days — critical, approaching disable.
    Critical,
    /// FP rate > 20% for ≥ 30 days — auto-disabled.
    Disabled,
    /// Manually disabled by user override.
    ManuallyDisabled,
    /// Insufficient data (< 10 acted-on violations).
    InsufficientData,
}

/// Trend direction for health metrics.
/// Borrowed from cortex-observability proven pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrendDirection {
    Improving,
    Stable,
    Declining,
}
```

### Feedback Statistics

```rust
/// Aggregated feedback statistics for a pattern or detector.
/// Computed on-demand by StatisticsAggregator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackStats {
    /// Entity ID (pattern_id or detector_id).
    pub entity_id: String,
    /// Entity type.
    pub entity_type: FeedbackEntityType,
    /// Time window for these statistics.
    pub window_days: u32,
    /// Total violations in window.
    pub total_violations: u64,
    /// Violations by action.
    pub fixed: u64,
    pub dismissed: u64,
    pub ignored: u64,
    pub auto_fixed: u64,
    pub not_seen: u64,
    /// Dismissals by reason.
    pub dismissed_false_positive: u64,
    pub dismissed_wont_fix: u64,
    pub dismissed_not_applicable: u64,
    pub dismissed_duplicate: u64,
    /// Computed FP rate.
    pub fp_rate: f64,
    /// Whether this entity should be auto-disabled.
    pub should_disable: bool,
    /// Unique authors who provided feedback.
    pub unique_authors: u32,
    /// Most recent feedback timestamp.
    pub last_feedback: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackEntityType {
    Pattern,
    Detector,
    Convention,
    Gate,
}

impl FeedbackStats {
    /// Compute the effective false positive rate.
    /// Per DRIFT-V2-FULL-SYSTEM-AUDIT.md:
    /// FP rate = (dismissed + ignored) / (fixed + dismissed + ignored + autoFixed)
    ///
    /// Note: NotSeen is excluded from both numerator and denominator.
    /// Note: Only FP-counting dismissals (FalsePositive, NotApplicable) count
    /// in the numerator. WontFix and Duplicate do not.
    pub fn false_positive_rate(
        dismissed_fp: u64,
        dismissed_na: u64,
        ignored: u64,
        fixed: u64,
        auto_fixed: u64,
        dismissed_wf: u64,
    ) -> f64 {
        let negative = dismissed_fp + dismissed_na + ignored;
        let total = fixed + dismissed_fp + dismissed_na + dismissed_wf + ignored + auto_fixed;
        if total == 0 {
            return 0.0;
        }
        negative as f64 / total as f64
    }
}
```

---

## 5. Violation Action Taxonomy (5 Actions + Sub-Reasons)

### The 5 Core Actions

Per DRIFT-V2-FULL-SYSTEM-AUDIT.md, the feedback loop tracks exactly 5 violation actions:

| Action | Signal | FP Rate Impact | Confidence Impact | How Detected |
|--------|--------|---------------|-------------------|-------------|
| `Fixed` | Positive | Denominator only | α += 0.5 | Developer changes code to match pattern |
| `Dismissed` | Negative (varies) | Numerator + denominator | β += 0.0-0.5 (by reason) | Developer explicitly dismisses |
| `Ignored` | Negative | Numerator + denominator | β += 0.25 | Violation present but no action taken (inferred) |
| `AutoFixed` | Positive | Denominator only | α += 0.5 | Quick-fix applied automatically |
| `NotSeen` | Neutral | Excluded | No change | Violation in scan but not surfaced to developer |

### Dismissal Sub-Reasons

| Reason | FP Rate Impact | Confidence Impact | Creates Suppression |
|--------|---------------|-------------------|-------------------|
| `false_positive` | Counts as FP | β += 0.5 | No |
| `wont_fix` | Does NOT count as FP | No change | Yes (permanent exception) |
| `not_applicable` | Counts as FP | β += 0.25 | No |
| `duplicate` | Does NOT count as FP | No change | No |

### Action Detection Methods

```rust
/// How each action is detected/recorded.
pub enum ActionSource {
    /// Developer explicitly clicked "Fix" or "Dismiss" in UI/CLI/MCP.
    Explicit,
    /// Inferred from code changes between scans.
    /// If a violation disappears and the file content changed → Fixed.
    InferredFromScan,
    /// Quick-fix was applied via IDE code action or CLI.
    QuickFixApplied,
    /// Violation was present for N scans without action → Ignored.
    /// Default: 3 consecutive scans without action = Ignored.
    InferredFromInaction { consecutive_scans: u32 },
    /// Auto-detected from inline `// drift-ignore` comment.
    InlineSuppression,
}

/// Infer violation action from scan-to-scan comparison.
/// Called during scan pipeline after violation detection.
pub fn infer_violation_action(
    previous_violations: &[ViolationSnapshot],
    current_violations: &[ViolationSnapshot],
    file_changes: &FileChangeSet,
    config: &FeedbackConfig,
) -> Vec<InferredAction> {
    let mut actions = Vec::new();

    for prev in previous_violations {
        let still_present = current_violations.iter().any(|v| v.matches(prev));

        if !still_present {
            // Violation disappeared
            if file_changes.was_modified(&prev.file) {
                // File was changed → likely fixed
                actions.push(InferredAction {
                    violation_id: prev.id.clone(),
                    action: ViolationAction::Fixed,
                    source: ActionSource::InferredFromScan,
                    confidence: 0.85, // High but not certain
                });
            }
            // If file wasn't changed but violation gone → pattern/detector changed
            // Don't record as Fixed — this is a detection change, not a developer action
        } else {
            // Violation still present
            let has_explicit_feedback = prev.has_feedback();
            if !has_explicit_feedback {
                let consecutive = prev.consecutive_unfixed_scans + 1;
                if consecutive >= config.ignored_after_scans {
                    actions.push(InferredAction {
                        violation_id: prev.id.clone(),
                        action: ViolationAction::Ignored,
                        source: ActionSource::InferredFromInaction {
                            consecutive_scans: consecutive,
                        },
                        confidence: 0.70,
                    });
                }
            }
        }
    }

    actions
}
```

### Validation Rules

```rust
/// Validate a feedback action before recording.
pub fn validate_feedback(record: &FeedbackRecord) -> Result<(), FeedbackError> {
    // Rule 1: Dismissed actions MUST have a dismissal reason
    if record.action == ViolationAction::Dismissed && record.dismissal_reason.is_none() {
        return Err(FeedbackError::MissingDismissalReason {
            violation_id: record.violation_id.clone(),
        });
    }

    // Rule 2: Non-dismissed actions MUST NOT have a dismissal reason
    if record.action != ViolationAction::Dismissed && record.dismissal_reason.is_some() {
        return Err(FeedbackError::UnexpectedDismissalReason {
            action: record.action,
        });
    }

    // Rule 3: WontFix dismissals SHOULD have a reason text
    if record.dismissal_reason == Some(DismissalReason::WontFix) && record.reason.is_none() {
        return Err(FeedbackError::WontFixRequiresReason {
            violation_id: record.violation_id.clone(),
        });
    }

    // Rule 4: File and line must be present
    if record.file.is_empty() {
        return Err(FeedbackError::MissingFile);
    }

    Ok(())
}
```


---

## 6. False Positive Rate Computation Engine

### The Tricorder Formula

Per DRIFT-V2-FULL-SYSTEM-AUDIT.md and Google's Tricorder system (Sadowski et al., CACM 2018):

```
Effective FP Rate = (dismissed_fp + dismissed_na + ignored) / (fixed + dismissed_all + ignored + auto_fixed)
```

Where:
- `dismissed_fp` = dismissals with reason `false_positive`
- `dismissed_na` = dismissals with reason `not_applicable`
- `dismissed_all` = all dismissals (including `wont_fix` and `duplicate`)
- `ignored` = violations inferred as ignored (no action after N scans)
- `fixed` = violations fixed by developer
- `auto_fixed` = violations fixed by quick-fix application
- `not_seen` is EXCLUDED from both numerator and denominator

### Granularity Levels

The FP rate is computed at 4 granularity levels:

| Level | Entity | Use Case | Window |
|-------|--------|----------|--------|
| Per-detector | detector_id | Health monitoring, auto-disable | 30 days (configurable) |
| Per-pattern | pattern_id | Enforcement transitions, confidence adjustment | 30 days (configurable) |
| Per-convention | convention_id | Learning system effectiveness | 30 days (configurable) |
| Per-gate | gate_id | Gate health monitoring | 90 days |

### Computation Algorithm

```rust
/// Compute FP rate for an entity within a time window.
/// Queries violation_feedback table in drift.db.
pub fn compute_fp_rate(
    db: &DatabaseManager,
    entity_id: &str,
    entity_type: FeedbackEntityType,
    window_days: u32,
) -> Result<FpRateResult, FeedbackError> {
    let column = match entity_type {
        FeedbackEntityType::Pattern => "pattern_id",
        FeedbackEntityType::Detector => "detector_id",
        FeedbackEntityType::Convention => "pattern_id", // conventions map to patterns
        FeedbackEntityType::Gate => "source_gate",
    };

    let cutoff = format!("datetime('now', '-{} days')", window_days);

    let stats = db.read(|conn| {
        conn.query_row(
            &format!(
                "SELECT
                    COUNT(*) FILTER (WHERE action = 'fixed') as fixed,
                    COUNT(*) FILTER (WHERE action = 'dismissed'
                        AND dismissal_reason = 'false_positive') as dismissed_fp,
                    COUNT(*) FILTER (WHERE action = 'dismissed'
                        AND dismissal_reason = 'not_applicable') as dismissed_na,
                    COUNT(*) FILTER (WHERE action = 'dismissed'
                        AND dismissal_reason = 'wont_fix') as dismissed_wf,
                    COUNT(*) FILTER (WHERE action = 'dismissed'
                        AND dismissal_reason = 'duplicate') as dismissed_dup,
                    COUNT(*) FILTER (WHERE action = 'ignored') as ignored,
                    COUNT(*) FILTER (WHERE action = 'auto_fixed') as auto_fixed,
                    COUNT(*) FILTER (WHERE action = 'not_seen') as not_seen,
                    COUNT(DISTINCT author) as unique_authors
                FROM violation_feedback
                WHERE {} = ?1 AND timestamp >= {}",
                column, cutoff
            ),
            [entity_id],
            |row| {
                Ok(RawFeedbackCounts {
                    fixed: row.get(0)?,
                    dismissed_fp: row.get(1)?,
                    dismissed_na: row.get(2)?,
                    dismissed_wf: row.get(3)?,
                    dismissed_dup: row.get(4)?,
                    ignored: row.get(5)?,
                    auto_fixed: row.get(6)?,
                    not_seen: row.get(7)?,
                    unique_authors: row.get(8)?,
                })
            },
        )
    })?;

    let negative = stats.dismissed_fp + stats.dismissed_na + stats.ignored;
    let total = stats.fixed + stats.dismissed_fp + stats.dismissed_na
        + stats.dismissed_wf + stats.dismissed_dup + stats.ignored + stats.auto_fixed;

    let fp_rate = if total == 0 { 0.0 } else { negative as f64 / total as f64 };

    Ok(FpRateResult {
        entity_id: entity_id.to_string(),
        entity_type,
        window_days,
        fp_rate,
        total_acted_on: total,
        total_positive: stats.fixed + stats.auto_fixed,
        total_negative: negative,
        total_neutral: stats.dismissed_wf + stats.dismissed_dup,
        total_not_seen: stats.not_seen,
        unique_authors: stats.unique_authors,
        has_sufficient_data: total >= 10, // Per Learning System §20.3
    })
}

/// FP rate computation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FpRateResult {
    pub entity_id: String,
    pub entity_type: FeedbackEntityType,
    pub window_days: u32,
    pub fp_rate: f64,
    pub total_acted_on: u64,
    pub total_positive: u64,
    pub total_negative: u64,
    pub total_neutral: u64,
    pub total_not_seen: u64,
    pub unique_authors: u32,
    /// Per Learning System §20.3: need ≥10 acted-on violations for reliable FP rate.
    pub has_sufficient_data: bool,
}
```

### Thresholds (Per AD9 and Research)

| Metric | Target | Warning | Alert | Critical | Auto-Disable |
|--------|--------|---------|-------|----------|-------------|
| FP Rate (per detector) | <5% | 5-10% | 10-20% | >20% (<30d) | >20% (≥30d) |
| FP Rate (per pattern) | <10% | 10-15% | 15-25% | >25% | N/A (demotion instead) |
| Minimum sample size | 10 | — | — | — | — |
| Window | 30 days | — | — | — | — |

### Comparison with Industry Standards

| Tool | FP Rate Target | Enforcement | Source |
|------|---------------|-------------|--------|
| Google Tricorder | <10% per check | Remove check if exceeded | Sadowski et al., CACM 2018 |
| Semgrep Assistant | 95%+ agreement rate | AI auto-triage + memories | [Semgrep blog, 2025](https://semgrep.dev/blog/2025/making-zero-false-positive-sast-a-reality-with-ai-powered-memory/) |
| Drift v2 | <5% per detector | Alert at 10%, disable at 20% for 30d | AD9 |

Drift's thresholds are more aggressive than Tricorder's 10% because Drift has the advantage
of Bayesian confidence scoring — patterns with low confidence are already filtered before
they produce violations. The 5% target applies to violations that actually reach developers.

---

## 7. Detector Health Monitoring & Auto-Disable

### Health State Machine

```
                    ┌─────────────┐
                    │ Insufficient│
                    │    Data     │ (<10 acted-on violations)
                    └──────┬──────┘
                           │ ≥10 violations
                           ▼
                    ┌─────────────┐
              ┌────→│   Healthy   │ (FP rate < 5%)
              │     └──────┬──────┘
              │            │ FP rate ≥ 5%
              │            ▼
              │     ┌─────────────┐
              │     │   Warning   │ (FP rate 5-10%)
              │     └──────┬──────┘
              │            │ FP rate ≥ 10%
              │            ▼
              │     ┌─────────────┐
              │     │    Alert    │ (FP rate 10-20%)
              │     └──────┬──────┘  → emit on_detector_alert
              │            │ FP rate ≥ 20%
              │            ▼
              │     ┌─────────────┐
              │     │  Critical   │ (FP rate > 20%, < 30 days)
              │     └──────┬──────┘  → emit on_detector_alert (critical)
              │            │ ≥ 30 days above 20%
              │            ▼
              │     ┌─────────────┐
              │     │  Disabled   │ (auto-disabled)
              │     └─────────────┘  → emit on_detector_disabled
              │            │
              │            │ FP rate drops below 20% (manual re-enable)
              └────────────┘
```

### Health Evaluation Algorithm

```rust
/// Evaluate detector health and determine state transitions.
/// Called during scheduled audit or on-demand via MCP/CLI.
pub fn evaluate_detector_health(
    db: &DatabaseManager,
    detector_id: &str,
    config: &DetectorHealthConfig,
    event_handler: &dyn DriftEventHandler,
) -> Result<DetectorHealthState, FeedbackError> {
    // Step 1: Compute current FP rate
    let fp_result = compute_fp_rate(
        db, detector_id, FeedbackEntityType::Detector, config.window_days,
    )?;

    // Step 2: Load previous health state
    let previous = load_detector_health(db, detector_id)?;

    // Step 3: Determine new status
    let new_status = if !fp_result.has_sufficient_data {
        DetectorHealthStatus::InsufficientData
    } else if fp_result.fp_rate < config.healthy_threshold {
        DetectorHealthStatus::Healthy
    } else if fp_result.fp_rate < config.warning_threshold {
        DetectorHealthStatus::Warning
    } else if fp_result.fp_rate < config.alert_threshold {
        DetectorHealthStatus::Alert
    } else {
        // FP rate >= alert_threshold (20%)
        let days_above = previous
            .as_ref()
            .map(|p| {
                if p.status == DetectorHealthStatus::Critical
                    || p.status == DetectorHealthStatus::Disabled
                {
                    p.days_above_disable + 1
                } else {
                    1
                }
            })
            .unwrap_or(1);

        if days_above >= config.disable_after_days {
            DetectorHealthStatus::Disabled
        } else {
            DetectorHealthStatus::Critical
        }
    };

    // Step 4: Compute trend
    let trend = compute_trend(db, detector_id, config.trend_window_days)?;

    // Step 5: Emit events on state transitions
    if let Some(ref prev) = previous {
        match (prev.status, new_status) {
            (s, DetectorHealthStatus::Alert) if s != DetectorHealthStatus::Alert => {
                event_handler.on_detector_alert(detector_id, fp_result.fp_rate);
                tracing::warn!(
                    event = "detector_alert",
                    detector_id = detector_id,
                    fp_rate = fp_result.fp_rate,
                    "Detector FP rate {:.1}% exceeds alert threshold",
                    fp_result.fp_rate * 100.0
                );
            }
            (s, DetectorHealthStatus::Disabled) if s != DetectorHealthStatus::Disabled => {
                event_handler.on_detector_disabled(
                    detector_id,
                    &format!(
                        "FP rate {:.1}% exceeded {:.0}% for {} days",
                        fp_result.fp_rate * 100.0,
                        config.alert_threshold * 100.0,
                        config.disable_after_days
                    ),
                );
                tracing::error!(
                    event = "detector_disabled",
                    detector_id = detector_id,
                    fp_rate = fp_result.fp_rate,
                    days = config.disable_after_days,
                    "Detector auto-disabled due to sustained high FP rate"
                );
            }
            _ => {}
        }
    }

    // Step 6: Build and persist new state
    let state = DetectorHealthState {
        detector_id: detector_id.to_string(),
        fp_rate: fp_result.fp_rate,
        days_above_alert: if fp_result.fp_rate >= config.warning_threshold {
            previous.as_ref().map(|p| p.days_above_alert + 1).unwrap_or(1)
        } else {
            0
        },
        days_above_disable: if fp_result.fp_rate >= config.alert_threshold {
            previous.as_ref().map(|p| p.days_above_disable + 1).unwrap_or(1)
        } else {
            0
        },
        status: new_status,
        total_acted_on: fp_result.total_acted_on,
        total_fixed: fp_result.total_positive - fp_result.total_not_seen, // approximate
        total_dismissed: fp_result.total_negative,
        total_ignored: 0, // broken out in detailed query
        total_auto_fixed: 0,
        last_evaluated: chrono::Utc::now().to_rfc3339(),
        trend,
    };

    persist_detector_health(db, &state)?;

    Ok(state)
}

/// Configuration for detector health monitoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorHealthConfig {
    /// FP rate below this = Healthy. Default: 0.05 (5%).
    pub healthy_threshold: f64,
    /// FP rate above this = Warning. Default: 0.10 (10%).
    pub warning_threshold: f64,
    /// FP rate above this = Alert/Critical. Default: 0.20 (20%).
    pub alert_threshold: f64,
    /// Days above alert_threshold before auto-disable. Default: 30.
    pub disable_after_days: u32,
    /// Window for FP rate computation. Default: 30 days.
    pub window_days: u32,
    /// Window for trend computation. Default: 90 days.
    pub trend_window_days: u32,
    /// Minimum acted-on violations for reliable FP rate. Default: 10.
    pub min_sample_size: u32,
}

impl Default for DetectorHealthConfig {
    fn default() -> Self {
        Self {
            healthy_threshold: 0.05,
            warning_threshold: 0.10,
            alert_threshold: 0.20,
            disable_after_days: 30,
            window_days: 30,
            trend_window_days: 90,
            min_sample_size: 10,
        }
    }
}
```

### Auto-Disable Behavior

When a detector is auto-disabled:

1. All patterns owned by the detector are demoted to `monitor` enforcement mode
2. Violations from the detector are excluded from gate results
3. The detector is excluded from audit health score calculation
4. An `on_detector_disabled` event is emitted (D5)
5. A degradation alert is created in the audit system
6. The detector can be manually re-enabled via CLI (`drift feedback re-enable <detector_id>`)
   or MCP tool (`drift_feedback_reenable`)
7. Re-enabling resets the `days_above_disable` counter but does NOT reset the FP rate
8. If the FP rate is still above threshold after re-enable, the 30-day countdown restarts

### Interaction with Audit System (§18 of 25-AUDIT-SYSTEM-V2-PREP.md)

Per the bidirectional data flow:
- Auto-approve decisions are suppressed for patterns from disabled detectors
- Health score calculation excludes disabled detectors from the `crossValidation` factor
- Degradation alerts include detector health as a contributing factor


---

## 8. Confidence Adjustment Pipeline

### V1 → V2 Upgrade: Static Deltas → Bayesian Parameter Updates

V1 used fixed confidence deltas:
- fix: +0.02, dismiss:fp: -0.05, dismiss:na: -0.02, good: +0.1, bad: -0.15, irrelevant: -0.05

V2 upgrades to Bayesian parameter updates that integrate with the Bayesian Confidence
Scoring system (10-BAYESIAN-CONFIDENCE-SCORING-V2-PREP.md):

| Action | V1 Delta | V2 Bayesian Update | Rationale |
|--------|----------|-------------------|-----------|
| Fixed | +0.02 | α += 0.5 | Positive evidence: pattern correctly identified deviation |
| AutoFixed | +0.02 | α += 0.5 | Same as Fixed — quick-fix confirms pattern validity |
| Dismissed:FP | -0.05 | β += 0.5 | Negative evidence: pattern incorrectly flagged code |
| Dismissed:NA | -0.02 | β += 0.25 | Weak negative: pattern valid but wrong context |
| Dismissed:WontFix | 0 | No change | Intentional deviation — pattern is correct, code is exception |
| Dismissed:Duplicate | 0 | No change | Detection issue, not pattern quality issue |
| Ignored | -0.01 | β += 0.25 | Weak negative: inferred disinterest |
| ConventionApproved | N/A | α += 2.0 | Strong positive: explicit human validation |
| ConventionRejected | N/A | β += 5.0 | Strong negative: explicit human rejection |
| MCP good rating | +0.1 | α += 0.5 | Positive signal on example quality |
| MCP bad rating | -0.15 | β += 0.75 | Negative signal on example quality |
| MCP irrelevant | -0.05 | β += 0.25 | Weak negative signal |

### Conservative Adjustment Principle

Per 13-LEARNING-SYSTEM-V2-PREP.md §20.2:
> "Feedback adjustments are conservative (0.5 per dismissal vs. integer counts from scan)"

This is critical. A single scan can observe 50+ matching files, each contributing α += 1.0
to the Bayesian posterior. A single developer dismissal contributes β += 0.5. This means
scan-derived evidence dominates, and feedback is a correction signal, not a primary signal.

This prevents a single frustrated developer from tanking a well-established pattern's
confidence. It takes sustained negative feedback across multiple developers to meaningfully
reduce confidence.

### Confidence Adjustment Algorithm

```rust
/// Apply feedback to a pattern's Bayesian parameters.
/// Per 13-LEARNING-SYSTEM-V2-PREP.md §20.2.
pub fn apply_feedback_to_confidence(
    pattern: &mut BayesianPattern,
    feedback: &FeedbackRecord,
    config: &ConfidenceAdjustmentConfig,
) {
    match feedback.action {
        ViolationAction::Fixed | ViolationAction::AutoFixed => {
            pattern.alpha += config.positive_alpha_increment; // default: 0.5
        }
        ViolationAction::Dismissed => {
            if let Some(ref reason) = feedback.dismissal_reason {
                pattern.beta += reason.beta_adjustment();
            }
        }
        ViolationAction::Ignored => {
            pattern.beta += config.ignored_beta_increment; // default: 0.25
        }
        ViolationAction::NotSeen => {
            // No adjustment — not a developer signal
        }
    }

    // Recalculate posterior
    pattern.recalculate_posterior();

    tracing::debug!(
        event = "confidence_adjusted",
        pattern_id = %pattern.id,
        action = %feedback.action,
        new_alpha = pattern.alpha,
        new_beta = pattern.beta,
        new_confidence = pattern.posterior_mean(),
        "Pattern confidence adjusted from feedback"
    );
}

/// Configuration for confidence adjustments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceAdjustmentConfig {
    /// Alpha increment for positive signals (Fixed, AutoFixed). Default: 0.5.
    pub positive_alpha_increment: f64,
    /// Beta increment for Ignored violations. Default: 0.25.
    pub ignored_beta_increment: f64,
    /// Alpha increment for convention approval. Default: 2.0.
    pub convention_approved_alpha: f64,
    /// Beta increment for convention rejection. Default: 5.0.
    pub convention_rejected_beta: f64,
    /// Alpha increment for MCP good rating. Default: 0.5.
    pub mcp_good_alpha: f64,
    /// Beta increment for MCP bad rating. Default: 0.75.
    pub mcp_bad_beta: f64,
    /// Beta increment for MCP irrelevant rating. Default: 0.25.
    pub mcp_irrelevant_beta: f64,
}

impl Default for ConfidenceAdjustmentConfig {
    fn default() -> Self {
        Self {
            positive_alpha_increment: 0.5,
            ignored_beta_increment: 0.25,
            convention_approved_alpha: 2.0,
            convention_rejected_beta: 5.0,
            mcp_good_alpha: 0.5,
            mcp_bad_beta: 0.75,
            mcp_irrelevant_beta: 0.25,
        }
    }
}
```

### Directory-Level Score Propagation (V1 Preserved)

Per DRIFT-V2-FULL-SYSTEM-AUDIT.md: "Directory-level score propagation (30% of file delta)"

When feedback is recorded for a file, 30% of the confidence delta propagates to the
directory level. This means if a pattern is consistently dismissed in `src/auth/`, the
pattern's confidence for files in `src/auth/` decreases faster than for files elsewhere.

```rust
/// Propagate feedback signal to directory level.
/// Per v1: 30% of file-level delta propagates to directory.
pub fn propagate_to_directory(
    db: &DatabaseManager,
    pattern_id: &str,
    file_path: &str,
    delta: f64,
    config: &ConfidenceAdjustmentConfig,
) -> Result<(), FeedbackError> {
    let dir = std::path::Path::new(file_path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    let dir_delta = delta * 0.30; // 30% propagation

    db.write(|conn| {
        conn.execute(
            "INSERT INTO pattern_directory_scores (pattern_id, directory, score_delta)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(pattern_id, directory) DO UPDATE SET
                score_delta = score_delta + ?3,
                updated_at = datetime('now')",
            rusqlite::params![pattern_id, dir, dir_delta],
        )
    })?;

    Ok(())
}
```

### File Exclusion (V1 Preserved)

Per DRIFT-V2-FULL-SYSTEM-AUDIT.md: "File exclusion when confidence > 0.5 and boost < -0.5"

When a pattern's accumulated feedback for a specific file results in a negative boost
exceeding -0.5 while the pattern's overall confidence is still above 0.5, the file is
excluded from that pattern's violation detection. This is a per-file suppression that
doesn't affect the pattern's global confidence.

```rust
/// Check if a file should be excluded from a pattern's detection.
pub fn should_exclude_file(
    db: &DatabaseManager,
    pattern_id: &str,
    file_path: &str,
    pattern_confidence: f64,
) -> Result<bool, FeedbackError> {
    let boost: f64 = db.read(|conn| {
        conn.query_row(
            "SELECT COALESCE(SUM(
                CASE
                    WHEN action = 'fixed' OR action = 'auto_fixed' THEN 0.1
                    WHEN action = 'dismissed' AND dismissal_reason = 'false_positive' THEN -0.15
                    WHEN action = 'dismissed' AND dismissal_reason = 'not_applicable' THEN -0.05
                    WHEN action = 'ignored' THEN -0.05
                    ELSE 0
                END
            ), 0.0)
            FROM violation_feedback
            WHERE pattern_id = ?1 AND file = ?2",
            rusqlite::params![pattern_id, file_path],
            |row| row.get(0),
        )
    })?;

    Ok(pattern_confidence > 0.5 && boost < -0.5)
}
```

---

## 9. Inline Suppression System (drift-ignore)

### Comment Syntax

Per DRIFT-V2-FULL-SYSTEM-AUDIT.md: `pattern_suppressions` table for inline `// drift-ignore`.

Supported comment formats across languages:

```
// drift-ignore: reason text                          — suppress all on next line
// drift-ignore[pattern-id]: reason text              — suppress specific pattern
// drift-ignore[pattern-id] expires:2026-06-01: reason — suppress with expiration
// drift-ignore-next-line: reason text                — alias for drift-ignore
/* drift-ignore: reason text */                       — block comment variant
# drift-ignore: reason text                           — Python/Ruby/YAML
<!-- drift-ignore: reason text -->                    — HTML/XML
```

### Suppression Parser

```rust
use regex::Regex;
use once_cell::sync::Lazy;

static DRIFT_IGNORE_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?x)
        drift-ignore(?:-next-line)?
        (?:\[([a-f0-9]{16})\])?          # optional [pattern-id]
        (?:\s+expires:(\d{4}-\d{2}-\d{2}))? # optional expires:YYYY-MM-DD
        :\s*(.+?)                          # required: reason text
        \s*(?:\*/|-->)?$                   # optional closing comment
        "
    ).unwrap()
});

/// Parse a drift-ignore comment from a source line.
pub fn parse_suppression(
    line_content: &str,
    file: &str,
    line_number: u32,
) -> Option<SuppressionRecord> {
    let captures = DRIFT_IGNORE_PATTERN.captures(line_content)?;

    Some(SuppressionRecord {
        id: generate_suppression_id(file, line_number),
        file: file.to_string(),
        line: line_number,
        pattern_id: captures.get(1).map(|m| m.as_str().to_string()),
        detector_id: None,
        reason: captures.get(3).map(|m| m.as_str().trim().to_string())
            .unwrap_or_else(|| "No reason provided".to_string()),
        expires_at: captures.get(2).map(|m| m.as_str().to_string()),
        created_by: None, // populated from git blame
        created_at: chrono::Utc::now().to_rfc3339(),
        is_active: true,
    })
}

/// Scan a file for all drift-ignore comments.
/// Called during the scan pipeline after parsing.
pub fn scan_suppressions(
    file_path: &str,
    content: &str,
) -> Vec<SuppressionRecord> {
    content
        .lines()
        .enumerate()
        .filter_map(|(i, line)| {
            parse_suppression(line, file_path, (i + 1) as u32)
        })
        .collect()
}
```

### Suppression Lifecycle

```
1. Developer adds `// drift-ignore[abc123]: false positive in test context`
2. Next scan detects the comment → creates SuppressionRecord
3. Violations matching the suppression are filtered from gate results
4. Suppression is recorded in pattern_suppressions table
5. SARIF output includes the suppression as a SARIF suppression object
6. If expires_at is set and date has passed → suppression becomes inactive
7. Expired suppressions are flagged in audit reports
8. If the suppressed line is removed → suppression is marked inactive
```

### Expiration Enforcement

```rust
/// Check and deactivate expired suppressions.
/// Called during scan pipeline.
pub fn enforce_suppression_expiration(
    db: &DatabaseManager,
) -> Result<Vec<ExpiredSuppression>, FeedbackError> {
    let expired = db.write(|conn| {
        let mut stmt = conn.prepare(
            "UPDATE pattern_suppressions
             SET is_active = 0
             WHERE is_active = 1
               AND expires_at IS NOT NULL
               AND expires_at < datetime('now')
             RETURNING id, file, line, pattern_id, reason, expires_at"
        )?;

        let results = stmt.query_map([], |row| {
            Ok(ExpiredSuppression {
                id: row.get(0)?,
                file: row.get(1)?,
                line: row.get(2)?,
                pattern_id: row.get(3)?,
                reason: row.get(4)?,
                expired_at: row.get(5)?,
            })
        })?.collect::<Result<Vec<_>, _>>()?;

        Ok(results)
    })?;

    for exp in &expired {
        tracing::info!(
            event = "suppression_expired",
            file = %exp.file,
            line = exp.line,
            pattern_id = ?exp.pattern_id,
            "Inline suppression expired"
        );
    }

    Ok(expired)
}
```

### Suppression in Gate Evaluation

```rust
/// Filter violations against active suppressions.
/// Called by quality gate evaluation before scoring.
pub fn filter_suppressed_violations(
    violations: Vec<GateViolation>,
    suppressions: &[SuppressionRecord],
) -> (Vec<GateViolation>, Vec<SuppressedViolation>) {
    let mut active = Vec::new();
    let mut suppressed = Vec::new();

    for violation in violations {
        let matching_suppression = suppressions.iter().find(|s| {
            s.is_active
                && s.file == violation.file
                && (s.line == violation.line || s.line == violation.line.saturating_sub(1))
                && s.pattern_id.as_ref().map_or(true, |pid| pid == &violation.pattern_id)
        });

        if let Some(supp) = matching_suppression {
            suppressed.push(SuppressedViolation {
                violation,
                suppression_id: supp.id.clone(),
                reason: supp.reason.clone(),
            });
        } else {
            active.push(violation);
        }
    }

    (active, suppressed)
}
```


---

## 10. Progressive Enforcement Integration

### How Feedback Drives Enforcement Transitions

The feedback loop provides the FP rate data that drives enforcement mode transitions
in the Quality Gates system (09-QUALITY-GATES-V2-PREP.md §12).

```
Feedback Loop                    Quality Gates (Progressive Enforcement)
    │                                    │
    ├── compute_fp_rate(pattern) ───────→│ evaluate_enforcement_transition()
    │                                    │
    │                                    ├── FP rate > 10% → Block → Comment
    │                                    │
    │                                    ├── FP rate > 25% → Comment → Monitor
    │                                    │
    │                                    ├── FP rate < 10% + criteria → Comment → Block
    │                                    │
    │                                    └── FP rate < 10% + criteria → Monitor → Comment
    │                                    │
    │ ←── on_enforcement_changed ────────┤ (event for audit trail)
    │                                    │
```

### FeedbackStats Interface for Quality Gates

```rust
/// Interface consumed by Quality Gates §12 for enforcement transitions.
/// The feedback loop provides this; quality gates consume it.
pub trait FeedbackStatsProvider: Send + Sync {
    /// Get the false positive rate for a pattern within a time window.
    fn false_positive_rate(&self, pattern_id: &str, window_days: u32) -> f64;

    /// Get the false positive rate for a detector within a time window.
    fn detector_fp_rate(&self, detector_id: &str, window_days: u32) -> f64;

    /// Check if a detector is currently disabled.
    fn is_detector_disabled(&self, detector_id: &str) -> bool;

    /// Get all patterns with FP rate above a threshold.
    fn patterns_above_fp_threshold(&self, threshold: f64, window_days: u32) -> Vec<String>;

    /// Get feedback summary for a pattern (for enforcement transition logging).
    fn pattern_feedback_summary(&self, pattern_id: &str) -> Option<FeedbackStats>;
}
```

### Enforcement Transition Audit Trail

Every enforcement transition triggered by feedback data is recorded:

```rust
/// Record an enforcement transition in the audit trail.
pub struct EnforcementTransitionRecord {
    pub id: String,
    pub pattern_id: String,
    pub from_mode: EnforcementMode,
    pub to_mode: EnforcementMode,
    pub reason: String,
    pub fp_rate_at_transition: f64,
    pub total_acted_on: u64,
    pub triggered_by: TransitionTrigger,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransitionTrigger {
    /// Automatic transition during scheduled audit.
    ScheduledAudit,
    /// Manual transition via CLI or MCP.
    ManualOverride { author: String },
    /// Triggered by detector disable cascade.
    DetectorDisabled { detector_id: String },
}
```

---

## 11. Feedback Persistence — SQLite in drift.db

### Table: violation_feedback

Per 09-QUALITY-GATES-V2-PREP.md §15 R6, expanded with v2 fields:

```sql
-- Violation feedback (core feedback loop table)
-- Retention: Indefinite (audit trail requirement)
CREATE TABLE violation_feedback (
    id TEXT PRIMARY KEY,
    violation_id TEXT NOT NULL,
    pattern_id TEXT NOT NULL,
    detector_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN (
        'fixed', 'dismissed', 'ignored', 'auto_fixed', 'not_seen'
    )),
    dismissal_reason TEXT CHECK(
        (action != 'dismissed' AND dismissal_reason IS NULL) OR
        (action = 'dismissed' AND dismissal_reason IN (
            'false_positive', 'wont_fix', 'not_applicable', 'duplicate'
        ))
    ),
    reason TEXT,
    author TEXT,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    column_num INTEGER,
    source_gate TEXT,
    commit_sha TEXT,
    branch TEXT,
    is_automated INTEGER NOT NULL DEFAULT 0,
    confidence_before REAL,
    confidence_after REAL,
    timestamp TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_feedback_pattern ON violation_feedback(pattern_id);
CREATE INDEX idx_feedback_detector ON violation_feedback(detector_id);
CREATE INDEX idx_feedback_timestamp ON violation_feedback(timestamp DESC);
CREATE INDEX idx_feedback_action ON violation_feedback(action);
CREATE INDEX idx_feedback_file ON violation_feedback(file);
CREATE INDEX idx_feedback_author ON violation_feedback(author);
-- Composite index for FP rate queries
CREATE INDEX idx_feedback_detector_action_ts
    ON violation_feedback(detector_id, action, timestamp);
CREATE INDEX idx_feedback_pattern_action_ts
    ON violation_feedback(pattern_id, action, timestamp);
```

### Table: pattern_suppressions

Per DRIFT-V2-FULL-SYSTEM-AUDIT.md: `pattern_suppressions` table for `// drift-ignore`.

```sql
-- Inline suppression tracking
-- Retention: Until suppression is removed from code or expires
CREATE TABLE pattern_suppressions (
    id TEXT PRIMARY KEY,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    pattern_id TEXT,           -- NULL = suppress all patterns on this line
    detector_id TEXT,          -- NULL = suppress all detectors
    reason TEXT NOT NULL,
    expires_at TEXT,           -- NULL = permanent
    created_by TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    is_active INTEGER NOT NULL DEFAULT 1,
    deactivated_at TEXT,
    deactivation_reason TEXT   -- 'expired', 'removed', 'manual'
) STRICT;

CREATE INDEX idx_suppressions_file ON pattern_suppressions(file, line);
CREATE INDEX idx_suppressions_pattern ON pattern_suppressions(pattern_id);
CREATE INDEX idx_suppressions_active ON pattern_suppressions(is_active);
CREATE INDEX idx_suppressions_expires ON pattern_suppressions(expires_at)
    WHERE expires_at IS NOT NULL;
```

### Table: detector_health

```sql
-- Detector health state tracking
-- Retention: 90 days (configurable)
CREATE TABLE detector_health (
    id TEXT PRIMARY KEY,
    detector_id TEXT NOT NULL,
    fp_rate REAL NOT NULL,
    status TEXT NOT NULL CHECK(status IN (
        'healthy', 'warning', 'alert', 'critical',
        'disabled', 'manually_disabled', 'insufficient_data'
    )),
    days_above_alert INTEGER NOT NULL DEFAULT 0,
    days_above_disable INTEGER NOT NULL DEFAULT 0,
    total_acted_on INTEGER NOT NULL DEFAULT 0,
    total_fixed INTEGER NOT NULL DEFAULT 0,
    total_dismissed INTEGER NOT NULL DEFAULT 0,
    total_ignored INTEGER NOT NULL DEFAULT 0,
    total_auto_fixed INTEGER NOT NULL DEFAULT 0,
    trend TEXT NOT NULL DEFAULT 'stable' CHECK(trend IN (
        'improving', 'stable', 'declining'
    )),
    evaluated_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_detector_health_detector ON detector_health(detector_id, evaluated_at DESC);
CREATE INDEX idx_detector_health_status ON detector_health(status);
```

### Table: pattern_directory_scores

```sql
-- Directory-level feedback score propagation
-- Per v1: 30% of file-level delta propagates to directory
CREATE TABLE pattern_directory_scores (
    pattern_id TEXT NOT NULL,
    directory TEXT NOT NULL,
    score_delta REAL NOT NULL DEFAULT 0.0,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (pattern_id, directory)
) STRICT;

CREATE INDEX idx_dir_scores_pattern ON pattern_directory_scores(pattern_id);
```

### Table: enforcement_transitions

```sql
-- Audit trail for enforcement mode transitions
-- Retention: Indefinite (audit trail)
CREATE TABLE enforcement_transitions (
    id TEXT PRIMARY KEY,
    pattern_id TEXT NOT NULL,
    from_mode TEXT NOT NULL,
    to_mode TEXT NOT NULL,
    reason TEXT NOT NULL,
    fp_rate_at_transition REAL,
    total_acted_on INTEGER,
    triggered_by TEXT NOT NULL,  -- 'scheduled_audit', 'manual_override', 'detector_disabled'
    triggered_by_detail TEXT,    -- JSON: { author: "..." } or { detector_id: "..." }
    timestamp TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_transitions_pattern ON enforcement_transitions(pattern_id, timestamp DESC);
CREATE INDEX idx_transitions_timestamp ON enforcement_transitions(timestamp DESC);
```

### Retention Policy

| Table | Retention | Cleanup Strategy |
|-------|-----------|-----------------|
| violation_feedback | Indefinite | No auto-deletion (audit trail) |
| pattern_suppressions | Until removed/expired | Deactivate on expiry, keep record |
| detector_health | 90 days | `DELETE WHERE evaluated_at < datetime('now', '-90 days')` |
| pattern_directory_scores | Indefinite | Reset on pattern deletion |
| enforcement_transitions | Indefinite | No auto-deletion (audit trail) |

---

## 12. Event System Integration (D5 DriftEventHandler)

### Events Emitted by the Feedback Loop

Per 04-INFRASTRUCTURE-V2-PREP.md §4, the feedback loop emits these events:

```rust
/// Events emitted by the violation feedback loop.
/// All events have no-op default implementations per D5.
pub trait DriftEventHandler: Send + Sync {
    // ... (other events from other systems) ...

    // ---- Violation Feedback Events ----

    /// A violation was detected during scan.
    fn on_violation_detected(&self, _violation: &Violation) {}

    /// A violation was dismissed by a developer.
    fn on_violation_dismissed(&self, _violation: &Violation, _reason: &str) {}

    /// A violation was fixed (manually or auto-detected from scan diff).
    fn on_violation_fixed(&self, _violation: &Violation) {}

    /// A violation was auto-fixed via quick-fix application.
    fn on_violation_auto_fixed(&self, _violation: &Violation, _fix_strategy: &str) {}

    /// A detector's FP rate exceeded the alert threshold.
    fn on_detector_alert(&self, _detector_id: &str, _fp_rate: f64) {}

    /// A detector was auto-disabled due to sustained high FP rate.
    fn on_detector_disabled(&self, _detector_id: &str, _reason: &str) {}

    /// A detector was manually re-enabled.
    fn on_detector_reenabled(&self, _detector_id: &str, _author: &str) {}

    /// An enforcement mode transition occurred.
    fn on_enforcement_changed(
        &self,
        _pattern_id: &str,
        _from: &str,
        _to: &str,
        _reason: &str,
    ) {}

    /// An inline suppression was detected.
    fn on_suppression_detected(&self, _suppression: &SuppressionRecord) {}

    /// An inline suppression expired.
    fn on_suppression_expired(&self, _suppression_id: &str, _file: &str) {}

    /// Feedback abuse detected (high dismiss rate from single author).
    fn on_feedback_abuse_detected(&self, _author: &str, _dismiss_rate: f64) {}
}
```

### Event Emission Points

| Event | Emission Point | Data Included |
|-------|---------------|---------------|
| `on_violation_detected` | Scan pipeline, after violation detection | Violation with pattern_id, file, line, severity |
| `on_violation_dismissed` | ActionRecorder, after recording dismissal | Violation + dismissal reason |
| `on_violation_fixed` | ActionRecorder, after recording fix (explicit or inferred) | Violation |
| `on_violation_auto_fixed` | ActionRecorder, after quick-fix application | Violation + fix strategy name |
| `on_detector_alert` | HealthMonitor, on state transition to Alert | detector_id, current FP rate |
| `on_detector_disabled` | HealthMonitor, on state transition to Disabled | detector_id, reason string |
| `on_detector_reenabled` | FeedbackEngine, on manual re-enable | detector_id, author |
| `on_enforcement_changed` | Quality Gates promotion engine (consumes our FP data) | pattern_id, from/to modes, reason |
| `on_suppression_detected` | SuppressionManager, during scan | Full SuppressionRecord |
| `on_suppression_expired` | SuppressionManager, during expiration check | suppression_id, file |
| `on_feedback_abuse_detected` | AbuseDetector, during audit | author, dismiss rate |

### Bridge Consumption (D7)

Per 04-INFRASTRUCTURE-V2-PREP.md §4 bridge event mapping:

| Feedback Event | Cortex Memory Type | Memory Content |
|---------------|-------------------|----------------|
| `on_violation_dismissed` | `constraint_override` | "Pattern X dismissed in file Y because Z" |
| `on_detector_disabled` | `anti_pattern` | "Detector X auto-disabled: FP rate too high" |
| `on_enforcement_changed` | `decision_context` | "Pattern X demoted from block to comment" |
| `on_feedback_abuse_detected` | `tribal_knowledge` | "Author X has high dismiss rate — review needed" |

These memory types enable the Cortex grounding loop (D7) to validate its memories against
actual developer behavior. If Cortex believes "this project uses pattern X" but developers
consistently dismiss violations from pattern X, the grounding loop can flag the memory
for review.


---

## 13. Feedback Aggregation & Statistics Engine

### Aggregation Strategy: Lazy with Caching

Statistics are NOT computed on every feedback action (too expensive for high-volume
codebases). Instead:

1. **On-demand**: MCP tools and CLI commands trigger fresh computation
2. **During audit**: Scheduled audit runs compute all statistics
3. **Cached**: Results cached in `detector_health` table with TTL
4. **Incremental**: New feedback invalidates cache for affected entities

### Aggregation Queries

```rust
/// Get feedback distribution for a detector over a time window.
pub fn get_detector_feedback_distribution(
    db: &DatabaseManager,
    detector_id: &str,
    window_days: u32,
) -> Result<FeedbackDistribution, FeedbackError> {
    let cutoff = format!("datetime('now', '-{} days')", window_days);

    db.read(|conn| {
        conn.query_row(
            &format!(
                "SELECT
                    COUNT(*) as total,
                    COUNT(*) FILTER (WHERE action = 'fixed') as fixed,
                    COUNT(*) FILTER (WHERE action = 'dismissed') as dismissed,
                    COUNT(*) FILTER (WHERE action = 'ignored') as ignored,
                    COUNT(*) FILTER (WHERE action = 'auto_fixed') as auto_fixed,
                    COUNT(*) FILTER (WHERE action = 'not_seen') as not_seen,
                    COUNT(DISTINCT pattern_id) as unique_patterns,
                    COUNT(DISTINCT file) as unique_files,
                    COUNT(DISTINCT author) as unique_authors,
                    MIN(timestamp) as earliest,
                    MAX(timestamp) as latest
                FROM violation_feedback
                WHERE detector_id = ?1 AND timestamp >= {}",
                cutoff
            ),
            [detector_id],
            |row| {
                Ok(FeedbackDistribution {
                    total: row.get(0)?,
                    fixed: row.get(1)?,
                    dismissed: row.get(2)?,
                    ignored: row.get(3)?,
                    auto_fixed: row.get(4)?,
                    not_seen: row.get(5)?,
                    unique_patterns: row.get(6)?,
                    unique_files: row.get(7)?,
                    unique_authors: row.get(8)?,
                    earliest: row.get(9)?,
                    latest: row.get(10)?,
                })
            },
        )
    })
}

/// Get top patterns by FP rate (for audit reports).
pub fn get_top_fp_patterns(
    db: &DatabaseManager,
    limit: u32,
    window_days: u32,
    min_sample_size: u32,
) -> Result<Vec<PatternFpSummary>, FeedbackError> {
    let cutoff = format!("datetime('now', '-{} days')", window_days);

    db.read(|conn| {
        let mut stmt = conn.prepare(&format!(
            "WITH pattern_stats AS (
                SELECT
                    pattern_id,
                    COUNT(*) FILTER (WHERE action IN ('fixed', 'auto_fixed')) as positive,
                    COUNT(*) FILTER (WHERE action = 'dismissed'
                        AND dismissal_reason IN ('false_positive', 'not_applicable')) as fp,
                    COUNT(*) FILTER (WHERE action = 'ignored') as ignored,
                    COUNT(*) FILTER (WHERE action != 'not_seen') as total
                FROM violation_feedback
                WHERE timestamp >= {}
                GROUP BY pattern_id
                HAVING total >= ?1
            )
            SELECT
                pattern_id,
                CAST(fp + ignored AS REAL) / total as fp_rate,
                total,
                positive,
                fp,
                ignored
            FROM pattern_stats
            ORDER BY fp_rate DESC
            LIMIT ?2",
            cutoff
        ))?;

        let results = stmt.query_map(
            rusqlite::params![min_sample_size, limit],
            |row| {
                Ok(PatternFpSummary {
                    pattern_id: row.get(0)?,
                    fp_rate: row.get(1)?,
                    total_acted_on: row.get(2)?,
                    total_positive: row.get(3)?,
                    total_fp: row.get(4)?,
                    total_ignored: row.get(5)?,
                })
            },
        )?.collect::<Result<Vec<_>, _>>()?;

        Ok(results)
    })
}

/// Compute trend direction from historical FP rates.
pub fn compute_trend(
    db: &DatabaseManager,
    detector_id: &str,
    window_days: u32,
) -> Result<TrendDirection, FeedbackError> {
    let history: Vec<f64> = db.read(|conn| {
        let mut stmt = conn.prepare(
            "SELECT fp_rate FROM detector_health
             WHERE detector_id = ?1
             ORDER BY evaluated_at DESC
             LIMIT ?2"
        )?;

        stmt.query_map(
            rusqlite::params![detector_id, window_days],
            |row| row.get(0),
        )?.collect::<Result<Vec<_>, _>>()
    })?;

    if history.len() < 3 {
        return Ok(TrendDirection::Stable);
    }

    // Simple linear regression on recent history
    let recent_avg: f64 = history[..3].iter().sum::<f64>() / 3.0;
    let older_avg: f64 = history[3..].iter().sum::<f64>()
        / history[3..].len().max(1) as f64;

    let delta = recent_avg - older_avg;

    if delta < -0.02 {
        Ok(TrendDirection::Improving)
    } else if delta > 0.02 {
        Ok(TrendDirection::Declining)
    } else {
        Ok(TrendDirection::Stable)
    }
}
```

### Feedback Summary for Audit Reports

```rust
/// Complete feedback summary for inclusion in audit reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackAuditSummary {
    /// Total feedback records in the system.
    pub total_feedback_records: u64,
    /// Records in the last 30 days.
    pub records_last_30_days: u64,
    /// Number of detectors by health status.
    pub detectors_healthy: u32,
    pub detectors_warning: u32,
    pub detectors_alert: u32,
    pub detectors_critical: u32,
    pub detectors_disabled: u32,
    /// Overall system FP rate (all detectors combined).
    pub system_fp_rate: f64,
    /// Top 5 patterns by FP rate.
    pub top_fp_patterns: Vec<PatternFpSummary>,
    /// Top 5 detectors by FP rate.
    pub top_fp_detectors: Vec<DetectorFpSummary>,
    /// Active suppressions count.
    pub active_suppressions: u32,
    /// Expired suppressions in last 30 days.
    pub recently_expired_suppressions: u32,
    /// Enforcement transitions in last 30 days.
    pub recent_transitions: Vec<EnforcementTransitionRecord>,
    /// Abuse alerts in last 30 days.
    pub abuse_alerts: Vec<AbuseAlert>,
}
```

---

## 14. Abuse Detection & Safety Rails

### The Problem

Per 09-QUALITY-GATES-V2-PREP.md §15 R6:
> "Developers may dismiss valid violations to unblock PRs"
> "Dismissal abuse detection: if one author dismisses >50% of violations, flag for team review"

### Abuse Detection Algorithm

```rust
/// Detect potential feedback abuse patterns.
/// Called during scheduled audit.
pub fn detect_feedback_abuse(
    db: &DatabaseManager,
    config: &AbuseDetectionConfig,
    event_handler: &dyn DriftEventHandler,
) -> Result<Vec<AbuseAlert>, FeedbackError> {
    let mut alerts = Vec::new();

    // Check 1: Per-author dismiss rate
    let author_stats = db.read(|conn| {
        let mut stmt = conn.prepare(
            "SELECT
                author,
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE action = 'dismissed') as dismissed,
                COUNT(*) FILTER (WHERE action = 'dismissed'
                    AND dismissal_reason = 'false_positive') as dismissed_fp
            FROM violation_feedback
            WHERE author IS NOT NULL
                AND timestamp >= datetime('now', '-30 days')
            GROUP BY author
            HAVING total >= ?1"
        )?;

        stmt.query_map(
            [config.min_actions_for_abuse_check],
            |row| {
                Ok(AuthorFeedbackStats {
                    author: row.get(0)?,
                    total: row.get(1)?,
                    dismissed: row.get(2)?,
                    dismissed_fp: row.get(3)?,
                })
            },
        )?.collect::<Result<Vec<_>, _>>()
    })?;

    for stats in &author_stats {
        let dismiss_rate = stats.dismissed as f64 / stats.total as f64;

        if dismiss_rate > config.author_dismiss_rate_threshold {
            let alert = AbuseAlert {
                alert_type: AbuseAlertType::HighDismissRate,
                author: stats.author.clone(),
                dismiss_rate,
                total_actions: stats.total,
                dismissed_count: stats.dismissed,
                window_days: 30,
                timestamp: chrono::Utc::now().to_rfc3339(),
            };

            event_handler.on_feedback_abuse_detected(&stats.author, dismiss_rate);

            tracing::warn!(
                event = "feedback_abuse_detected",
                author = %stats.author,
                dismiss_rate = dismiss_rate,
                total = stats.total,
                "Author dismiss rate {:.0}% exceeds threshold",
                dismiss_rate * 100.0
            );

            alerts.push(alert);
        }
    }

    // Check 2: Burst dismissals (many dismissals in short time)
    let burst_alerts = detect_burst_dismissals(db, config)?;
    alerts.extend(burst_alerts);

    // Check 3: Pattern-targeted dismissals (one author dismissing all violations
    // from a specific pattern — may indicate disagreement with the pattern)
    let targeted_alerts = detect_targeted_dismissals(db, config)?;
    alerts.extend(targeted_alerts);

    Ok(alerts)
}

/// Detect burst dismissal patterns (many dismissals in a short window).
fn detect_burst_dismissals(
    db: &DatabaseManager,
    config: &AbuseDetectionConfig,
) -> Result<Vec<AbuseAlert>, FeedbackError> {
    db.read(|conn| {
        let mut stmt = conn.prepare(
            "SELECT author, COUNT(*) as burst_count
             FROM violation_feedback
             WHERE action = 'dismissed'
                AND timestamp >= datetime('now', '-1 hour')
             GROUP BY author
             HAVING burst_count >= ?1"
        )?;

        stmt.query_map(
            [config.burst_threshold],
            |row| {
                Ok(AbuseAlert {
                    alert_type: AbuseAlertType::BurstDismissals,
                    author: row.get(0)?,
                    dismiss_rate: 1.0,
                    total_actions: row.get::<_, u64>(1)?,
                    dismissed_count: row.get::<_, u64>(1)?,
                    window_days: 0, // 1 hour window
                    timestamp: chrono::Utc::now().to_rfc3339(),
                })
            },
        )?.collect::<Result<Vec<_>, _>>()
    })
}

/// Detect targeted dismissals (one author dismissing all violations from one pattern).
fn detect_targeted_dismissals(
    db: &DatabaseManager,
    config: &AbuseDetectionConfig,
) -> Result<Vec<AbuseAlert>, FeedbackError> {
    db.read(|conn| {
        let mut stmt = conn.prepare(
            "SELECT author, pattern_id, COUNT(*) as count
             FROM violation_feedback
             WHERE action = 'dismissed'
                AND timestamp >= datetime('now', '-7 days')
             GROUP BY author, pattern_id
             HAVING count >= ?1"
        )?;

        stmt.query_map(
            [config.targeted_threshold],
            |row| {
                Ok(AbuseAlert {
                    alert_type: AbuseAlertType::TargetedDismissals,
                    author: row.get(0)?,
                    dismiss_rate: 1.0,
                    total_actions: row.get::<_, u64>(2)?,
                    dismissed_count: row.get::<_, u64>(2)?,
                    window_days: 7,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                })
            },
        )?.collect::<Result<Vec<_>, _>>()
    })
}

/// Abuse alert types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AbuseAlertType {
    /// Author dismisses >50% of violations they encounter.
    HighDismissRate,
    /// Author dismissed many violations in a short burst (>20 in 1 hour).
    BurstDismissals,
    /// Author dismissed all violations from a specific pattern (>10 in 7 days).
    TargetedDismissals,
}

/// Configuration for abuse detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbuseDetectionConfig {
    /// Minimum actions before checking for abuse. Default: 10.
    pub min_actions_for_abuse_check: u32,
    /// Author dismiss rate threshold. Default: 0.50 (50%).
    pub author_dismiss_rate_threshold: f64,
    /// Burst threshold (dismissals in 1 hour). Default: 20.
    pub burst_threshold: u32,
    /// Targeted threshold (dismissals of one pattern in 7 days). Default: 10.
    pub targeted_threshold: u32,
}

impl Default for AbuseDetectionConfig {
    fn default() -> Self {
        Self {
            min_actions_for_abuse_check: 10,
            author_dismiss_rate_threshold: 0.50,
            burst_threshold: 20,
            targeted_threshold: 10,
        }
    }
}
```

### Safety Rails

| Rail | Purpose | Behavior |
|------|---------|----------|
| Minimum sample size | Prevent premature decisions | No health status change until ≥10 acted-on violations |
| Conservative Bayesian updates | Prevent single-user impact | Feedback adjustments are 0.5 vs scan's 1.0+ per observation |
| Abuse detection | Prevent dismiss-to-unblock | Flag authors with >50% dismiss rate |
| Burst detection | Prevent mass-dismiss scripts | Flag >20 dismissals in 1 hour |
| Targeted detection | Prevent pattern-targeting | Flag >10 dismissals of one pattern in 7 days |
| Manual re-enable required | Prevent permanent disable | Auto-disabled detectors need explicit re-enable |
| WontFix doesn't count as FP | Prevent legitimate exceptions from hurting FP rate | Intentional deviations are neutral |
| Duplicate doesn't count as FP | Prevent dedup issues from hurting FP rate | Detection issues are neutral |


---

## 15. MCP Tool Interface

### drift_feedback_record

Record a feedback action on a violation.

```typescript
// MCP tool: drift_feedback_record
interface DriftFeedbackRecordInput {
    violation_id: string;
    action: 'fixed' | 'dismissed' | 'ignored' | 'auto_fixed';
    dismissal_reason?: 'false_positive' | 'wont_fix' | 'not_applicable' | 'duplicate';
    reason?: string;
}

interface DriftFeedbackRecordOutput {
    success: boolean;
    feedback_id: string;
    confidence_before: number;
    confidence_after: number;
    detector_health_status: string;
    message: string;
}
```

### drift_feedback_stats

Get feedback statistics for a pattern or detector.

```typescript
// MCP tool: drift_feedback_stats
interface DriftFeedbackStatsInput {
    entity_id: string;
    entity_type: 'pattern' | 'detector' | 'convention';
    window_days?: number;  // default: 30
}

interface DriftFeedbackStatsOutput {
    entity_id: string;
    fp_rate: number;
    total_acted_on: number;
    fixed: number;
    dismissed: number;
    ignored: number;
    auto_fixed: number;
    health_status: string;
    trend: 'improving' | 'stable' | 'declining';
    should_disable: boolean;
    has_sufficient_data: boolean;
}
```

### drift_feedback_health

Get detector health overview.

```typescript
// MCP tool: drift_feedback_health
interface DriftFeedbackHealthInput {
    detector_id?: string;  // optional: specific detector, or all
    include_disabled?: boolean;  // default: true
}

interface DriftFeedbackHealthOutput {
    detectors: Array<{
        detector_id: string;
        status: string;
        fp_rate: number;
        trend: string;
        total_acted_on: number;
        days_above_alert: number;
    }>;
    system_fp_rate: number;
    active_suppressions: number;
    recent_transitions: number;
}
```

### drift_feedback_reenable

Re-enable a disabled detector.

```typescript
// MCP tool: drift_feedback_reenable
interface DriftFeedbackReenableInput {
    detector_id: string;
    reason: string;
}

interface DriftFeedbackReenableOutput {
    success: boolean;
    detector_id: string;
    previous_status: string;
    new_status: string;
    fp_rate: number;
    message: string;
}
```

### drift_feedback_suppressions

List active suppressions.

```typescript
// MCP tool: drift_feedback_suppressions
interface DriftFeedbackSuppressionsInput {
    file?: string;         // filter by file
    pattern_id?: string;   // filter by pattern
    include_expired?: boolean;  // default: false
    limit?: number;        // default: 50
}

interface DriftFeedbackSuppressionsOutput {
    suppressions: Array<{
        id: string;
        file: string;
        line: number;
        pattern_id: string | null;
        reason: string;
        expires_at: string | null;
        is_active: boolean;
        created_at: string;
    }>;
    total: number;
    active_count: number;
    expired_count: number;
}
```

### drift_feedback_top_fp

Get patterns/detectors with highest FP rates.

```typescript
// MCP tool: drift_feedback_top_fp
interface DriftFeedbackTopFpInput {
    entity_type: 'pattern' | 'detector';
    limit?: number;        // default: 10
    window_days?: number;  // default: 30
    min_sample?: number;   // default: 10
}

interface DriftFeedbackTopFpOutput {
    entities: Array<{
        entity_id: string;
        fp_rate: number;
        total_acted_on: number;
        total_positive: number;
        total_negative: number;
        trend: string;
    }>;
}
```

---

## 16. CLI Interface

### Commands

```bash
# Record feedback on a violation
drift feedback record <violation-id> --action fix
drift feedback record <violation-id> --action dismiss --reason false-positive
drift feedback record <violation-id> --action dismiss --reason wont-fix --comment "Intentional for legacy compat"
drift feedback record <violation-id> --action dismiss --reason not-applicable

# View feedback statistics
drift feedback stats <pattern-id>
drift feedback stats --detector <detector-id>
drift feedback stats --all --window 30

# View detector health
drift feedback health
drift feedback health <detector-id>
drift feedback health --status alert,critical,disabled

# Re-enable a disabled detector
drift feedback re-enable <detector-id> --reason "FP rate improved after rule update"

# List suppressions
drift feedback suppressions
drift feedback suppressions --file src/auth/login.ts
drift feedback suppressions --expired
drift feedback suppressions --expiring-soon 7  # expiring in next 7 days

# View top FP patterns/detectors
drift feedback top-fp --patterns --limit 10
drift feedback top-fp --detectors --limit 5

# View enforcement transitions
drift feedback transitions --pattern <pattern-id>
drift feedback transitions --last 30  # last 30 days

# View abuse alerts
drift feedback abuse-alerts
drift feedback abuse-alerts --author <author>

# Export feedback data (for external analysis)
drift feedback export --format json --output feedback-export.json
drift feedback export --format csv --output feedback-export.csv
```

### CLI Output Examples

```
$ drift feedback health

Detector Health Summary
═══════════════════════

System FP Rate: 3.2% (target: <5%) ✓

Status      Count  Detectors
──────────  ─────  ─────────────────────────────────────
Healthy     12     auth-patterns, api-routes, error-handling, ...
Warning      2     logging-patterns (7.3%), test-structure (6.1%)
Alert        1     documentation-patterns (14.2%) ⚠
Critical     0
Disabled     1     styling-conventions (23.1%, 45 days) ✗

Active Suppressions: 8
Recent Transitions: 3 (last 30 days)
Abuse Alerts: 0
```

```
$ drift feedback stats auth-middleware-pattern

Pattern: auth-middleware-pattern
Window: 30 days
═══════════════════════════════

FP Rate: 2.1% (target: <10%) ✓
Enforcement: block
Trend: improving ↑

Actions:
  Fixed:       47 (78.3%)
  Dismissed:    3 (5.0%)
    - false_positive: 1
    - wont_fix: 2
  Ignored:      1 (1.7%)
  Auto-Fixed:   9 (15.0%)
  ──────────────────────
  Total:       60

Sufficient data: yes (60 ≥ 10)
Should disable: no
```

---

## 17. IDE / LSP Integration

### Violation Diagnostics with Feedback Actions

The LSP server surfaces violations as diagnostics with code actions for feedback:

```typescript
// LSP diagnostic with feedback code actions
interface ViolationDiagnostic {
    range: Range;
    severity: DiagnosticSeverity;
    code: string;  // violation ID
    source: 'drift';
    message: string;
    // Code actions available:
    // 1. Quick Fix (from rules engine)
    // 2. Dismiss: False Positive
    // 3. Dismiss: Won't Fix
    // 4. Dismiss: Not Applicable
    // 5. Add drift-ignore comment
    // 6. View pattern details
}
```

### Code Actions

```typescript
// Code action: Dismiss violation
{
    title: "Drift: Dismiss as false positive",
    kind: "quickfix.drift.dismiss.fp",
    command: {
        command: "drift.feedback.dismiss",
        arguments: [violationId, "false_positive"]
    }
}

// Code action: Add inline suppression
{
    title: "Drift: Suppress with // drift-ignore",
    kind: "quickfix.drift.suppress",
    edit: {
        // Insert `// drift-ignore[pattern-id]: <reason>` above the line
    }
}

// Code action: View detector health
{
    title: "Drift: View detector health for this pattern",
    kind: "source.drift.health",
    command: {
        command: "drift.feedback.showHealth",
        arguments: [detectorId]
    }
}
```

### Status Bar Integration

The VSCode extension shows feedback health in the status bar:

```
Drift: 3.2% FP | 12 healthy | 1 alert | 8 suppressions
```

Clicking opens the feedback health panel with:
- Detector health table
- Top FP patterns
- Recent enforcement transitions
- Active suppressions with expiration dates

---

## 18. SARIF Suppression Mapping

### SARIF 2.1.0 Suppression Objects

Per 09-QUALITY-GATES-V2-PREP.md §14 R4, dismissed violations and inline suppressions
map to SARIF suppression objects:

```json
{
    "results": [
        {
            "ruleId": "pattern-compliance/auth-middleware",
            "level": "error",
            "message": { "text": "Missing auth middleware on route handler" },
            "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "src/api/users.ts" }, "region": { "startLine": 42 } } }],
            "suppressions": [
                {
                    "kind": "inSource",
                    "status": "accepted",
                    "justification": "Legacy endpoint — auth handled by upstream proxy",
                    "location": {
                        "physicalLocation": {
                            "artifactLocation": { "uri": "src/api/users.ts" },
                            "region": { "startLine": 41 }
                        }
                    },
                    "properties": {
                        "drift:suppressionId": "supp-abc123",
                        "drift:expiresAt": "2026-06-01",
                        "drift:createdBy": "developer@example.com",
                        "drift:dismissalReason": "wont_fix"
                    }
                }
            ]
        }
    ]
}
```

### Suppression Kind Mapping

| Feedback Action | SARIF Suppression Kind | SARIF Status |
|----------------|----------------------|-------------|
| Dismissed:WontFix | `inSource` (if drift-ignore) or `external` | `accepted` |
| Dismissed:FalsePositive | `external` | `accepted` |
| Dismissed:NotApplicable | `external` | `accepted` |
| Inline drift-ignore | `inSource` | `accepted` |
| Expired suppression | `inSource` | `rejected` |

### Baseline State Integration

Suppressed violations interact with SARIF `baselineState`:

| Scenario | baselineState | suppressions |
|----------|--------------|-------------|
| New violation, no suppression | `new` | `[]` |
| New violation, suppressed | `new` | `[{ kind: "inSource", ... }]` |
| Existing violation, newly suppressed | `unchanged` | `[{ kind: "external", ... }]` |
| Previously suppressed, suppression expired | `updated` | `[{ kind: "inSource", status: "rejected" }]` |
| Violation fixed | `absent` | N/A |

---

## 19. Integration with Upstream Systems

### From Detector System (06)

The detector system produces violations that the feedback loop tracks:

```rust
/// When a violation is detected, register it for feedback tracking.
pub fn register_violation_for_tracking(
    engine: &FeedbackEngine,
    violation: &Violation,
    detector_id: &str,
) {
    // Create a ViolationSnapshot for scan-to-scan comparison
    engine.register_violation(ViolationSnapshot {
        id: violation.id.clone(),
        pattern_id: violation.pattern_id.clone(),
        detector_id: detector_id.to_string(),
        file: violation.file.clone(),
        line: violation.line,
        severity: violation.severity,
        scan_id: engine.current_scan_id(),
        consecutive_unfixed_scans: 0,
        has_feedback: false,
    });
}
```

### From Rules Engine

The rules engine provides violation IDs and quick-fix data:

```rust
/// When a quick-fix is applied, record as AutoFixed.
pub fn record_quick_fix_applied(
    engine: &FeedbackEngine,
    violation_id: &str,
    fix_strategy: &str,
) -> Result<(), FeedbackError> {
    engine.record_action(FeedbackRecord {
        violation_id: violation_id.to_string(),
        action: ViolationAction::AutoFixed,
        is_automated: true,
        reason: Some(format!("Quick-fix applied: {}", fix_strategy)),
        // ... other fields populated from context
        ..Default::default()
    })
}
```

### From Quality Gates (09)

Quality gates provide the context for which violations were surfaced to developers:

```rust
/// After gate execution, mark violations as surfaced (not NotSeen).
pub fn mark_violations_surfaced(
    engine: &FeedbackEngine,
    gate_result: &GateResult,
) {
    for violation in &gate_result.violations {
        engine.mark_surfaced(&violation.id, &gate_result.gate_id);
    }
}
```

---

## 20. Integration with Downstream Consumers

### To Quality Gates — Progressive Enforcement (§12)

The feedback loop provides FP rates consumed by the enforcement transition engine:

```rust
impl FeedbackStatsProvider for FeedbackEngine {
    fn false_positive_rate(&self, pattern_id: &str, window_days: u32) -> f64 {
        compute_fp_rate(&self.db, pattern_id, FeedbackEntityType::Pattern, window_days)
            .map(|r| r.fp_rate)
            .unwrap_or(0.0)
    }

    fn detector_fp_rate(&self, detector_id: &str, window_days: u32) -> f64 {
        compute_fp_rate(&self.db, detector_id, FeedbackEntityType::Detector, window_days)
            .map(|r| r.fp_rate)
            .unwrap_or(0.0)
    }

    fn is_detector_disabled(&self, detector_id: &str) -> bool {
        load_detector_health(&self.db, detector_id)
            .map(|h| h.map(|s| s.status == DetectorHealthStatus::Disabled).unwrap_or(false))
            .unwrap_or(false)
    }

    fn patterns_above_fp_threshold(&self, threshold: f64, window_days: u32) -> Vec<String> {
        get_top_fp_patterns(&self.db, 1000, window_days, 10)
            .map(|patterns| {
                patterns.into_iter()
                    .filter(|p| p.fp_rate > threshold)
                    .map(|p| p.pattern_id)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn pattern_feedback_summary(&self, pattern_id: &str) -> Option<FeedbackStats> {
        compute_feedback_stats(&self.db, pattern_id, FeedbackEntityType::Pattern, 30).ok()
    }
}
```

### To Audit System (25) — Health Score Factor

Per 25-AUDIT-SYSTEM-V2-PREP.md §18:

```rust
/// Provide FP data for audit health score calculation.
pub fn get_fp_count_for_audit(
    engine: &FeedbackEngine,
    window_days: u32,
) -> Result<AuditFpData, FeedbackError> {
    let total_fp = engine.db.read(|conn| {
        conn.query_row(
            "SELECT COUNT(*) FROM violation_feedback
             WHERE action = 'dismissed'
                AND dismissal_reason IN ('false_positive', 'not_applicable')
                AND timestamp >= datetime('now', ?1)",
            [format!("-{} days", window_days)],
            |row| row.get::<_, u64>(0),
        )
    })?;

    let disabled_detectors = engine.db.read(|conn| {
        conn.query_row(
            "SELECT COUNT(DISTINCT detector_id) FROM detector_health
             WHERE status = 'disabled'",
            [],
            |row| row.get::<_, u32>(0),
        )
    })?;

    Ok(AuditFpData {
        total_false_positives: total_fp,
        disabled_detector_count: disabled_detectors,
        system_fp_rate: compute_system_fp_rate(&engine.db, window_days)?,
    })
}
```

### To Learning System (13) — Convention Feedback

Per 13-LEARNING-SYSTEM-V2-PREP.md §20:

```rust
/// Convert a feedback record to a ConventionFeedback for the learning system.
pub fn to_convention_feedback(record: &FeedbackRecord) -> Option<ConventionFeedback> {
    match record.action {
        ViolationAction::Fixed => Some(ConventionFeedback::ViolationFixed {
            convention_id: record.pattern_id.clone(),
            file: record.file.clone(),
        }),
        ViolationAction::Dismissed => Some(ConventionFeedback::ViolationDismissed {
            convention_id: record.pattern_id.clone(),
            file: record.file.clone(),
            reason: record.reason.clone(),
        }),
        _ => None,
    }
}
```

### To SARIF Reporter

```rust
/// Convert feedback records to SARIF suppression objects.
pub fn to_sarif_suppressions(
    feedback: &[FeedbackRecord],
    suppressions: &[SuppressionRecord],
    violation_id: &str,
) -> Vec<SarifSuppression> {
    let mut sarif_supps = Vec::new();

    // From explicit feedback (dismissals)
    for record in feedback.iter().filter(|r| {
        r.violation_id == violation_id && r.action == ViolationAction::Dismissed
    }) {
        sarif_supps.push(SarifSuppression {
            kind: "external".to_string(),
            status: "accepted".to_string(),
            justification: record.reason.clone().unwrap_or_default(),
            properties: serde_json::json!({
                "drift:feedbackId": record.id,
                "drift:dismissalReason": record.dismissal_reason,
                "drift:author": record.author,
                "drift:timestamp": record.timestamp,
            }),
        });
    }

    // From inline suppressions
    for supp in suppressions.iter().filter(|s| {
        s.is_active && s.pattern_id.as_deref() == Some(violation_id)
    }) {
        sarif_supps.push(SarifSuppression {
            kind: "inSource".to_string(),
            status: if supp.is_active { "accepted" } else { "rejected" }.to_string(),
            justification: supp.reason.clone(),
            properties: serde_json::json!({
                "drift:suppressionId": supp.id,
                "drift:expiresAt": supp.expires_at,
                "drift:createdBy": supp.created_by,
            }),
        });
    }

    sarif_supps
}
```


---

## 21. NAPI Bridge Interface

### Exported Functions

Per 03-NAPI-BRIDGE-V2-PREP.md pattern: thin wrappers around Rust engine methods.

```rust
use napi_derive::napi;
use napi::Result;

/// Record a feedback action on a violation.
#[napi]
pub async fn drift_feedback_record(
    runtime: &DriftRuntime,
    violation_id: String,
    action: String,
    dismissal_reason: Option<String>,
    reason: Option<String>,
    author: Option<String>,
) -> Result<FeedbackRecordResult> {
    let action = parse_violation_action(&action)
        .map_err(|e| napi::Error::from_reason(format!("INVALID_ACTION: {}", e)))?;

    let dismissal = dismissal_reason
        .map(|r| parse_dismissal_reason(&r))
        .transpose()
        .map_err(|e| napi::Error::from_reason(format!("INVALID_REASON: {}", e)))?;

    runtime.feedback_engine()
        .record_action_async(violation_id, action, dismissal, reason, author)
        .await
        .map_err(|e| napi::Error::from_reason(format!("FEEDBACK_ERROR: {}", e)))
}

/// Get feedback statistics for a pattern or detector.
#[napi]
pub async fn drift_feedback_stats(
    runtime: &DriftRuntime,
    entity_id: String,
    entity_type: String,
    window_days: Option<u32>,
) -> Result<FeedbackStatsResult> {
    let entity_type = parse_entity_type(&entity_type)
        .map_err(|e| napi::Error::from_reason(format!("INVALID_TYPE: {}", e)))?;

    runtime.feedback_engine()
        .get_stats_async(&entity_id, entity_type, window_days.unwrap_or(30))
        .await
        .map_err(|e| napi::Error::from_reason(format!("FEEDBACK_ERROR: {}", e)))
}

/// Get detector health overview.
#[napi]
pub async fn drift_feedback_health(
    runtime: &DriftRuntime,
    detector_id: Option<String>,
) -> Result<DetectorHealthOverview> {
    runtime.feedback_engine()
        .get_health_overview_async(detector_id.as_deref())
        .await
        .map_err(|e| napi::Error::from_reason(format!("FEEDBACK_ERROR: {}", e)))
}

/// Re-enable a disabled detector.
#[napi]
pub async fn drift_feedback_reenable(
    runtime: &DriftRuntime,
    detector_id: String,
    reason: String,
    author: Option<String>,
) -> Result<ReenableResult> {
    runtime.feedback_engine()
        .reenable_detector_async(&detector_id, &reason, author.as_deref())
        .await
        .map_err(|e| napi::Error::from_reason(format!("FEEDBACK_ERROR: {}", e)))
}

/// List active suppressions.
#[napi]
pub async fn drift_feedback_suppressions(
    runtime: &DriftRuntime,
    file: Option<String>,
    pattern_id: Option<String>,
    include_expired: Option<bool>,
    limit: Option<u32>,
) -> Result<SuppressionsResult> {
    runtime.feedback_engine()
        .list_suppressions_async(
            file.as_deref(),
            pattern_id.as_deref(),
            include_expired.unwrap_or(false),
            limit.unwrap_or(50),
        )
        .await
        .map_err(|e| napi::Error::from_reason(format!("FEEDBACK_ERROR: {}", e)))
}

/// Get top FP patterns or detectors.
#[napi]
pub async fn drift_feedback_top_fp(
    runtime: &DriftRuntime,
    entity_type: String,
    limit: Option<u32>,
    window_days: Option<u32>,
    min_sample: Option<u32>,
) -> Result<TopFpResult> {
    let entity_type = parse_entity_type(&entity_type)
        .map_err(|e| napi::Error::from_reason(format!("INVALID_TYPE: {}", e)))?;

    runtime.feedback_engine()
        .get_top_fp_async(
            entity_type,
            limit.unwrap_or(10),
            window_days.unwrap_or(30),
            min_sample.unwrap_or(10),
        )
        .await
        .map_err(|e| napi::Error::from_reason(format!("FEEDBACK_ERROR: {}", e)))
}

/// Infer violation actions from scan-to-scan comparison.
/// Called internally during scan pipeline.
#[napi]
pub async fn drift_feedback_infer_actions(
    runtime: &DriftRuntime,
    scan_id: String,
) -> Result<InferredActionsResult> {
    runtime.feedback_engine()
        .infer_actions_from_scan_async(&scan_id)
        .await
        .map_err(|e| napi::Error::from_reason(format!("FEEDBACK_ERROR: {}", e)))
}

/// Run detector health evaluation (called during audit).
#[napi]
pub async fn drift_feedback_evaluate_health(
    runtime: &DriftRuntime,
) -> Result<HealthEvaluationResult> {
    runtime.feedback_engine()
        .evaluate_all_detector_health_async()
        .await
        .map_err(|e| napi::Error::from_reason(format!("FEEDBACK_ERROR: {}", e)))
}
```

### Error Codes

| Code | Meaning |
|------|---------|
| `INVALID_ACTION` | Unknown violation action string |
| `INVALID_REASON` | Unknown dismissal reason string |
| `INVALID_TYPE` | Unknown entity type string |
| `FEEDBACK_ERROR` | General feedback engine error |
| `VIOLATION_NOT_FOUND` | Violation ID not found |
| `DETECTOR_NOT_FOUND` | Detector ID not found |
| `DETECTOR_NOT_DISABLED` | Attempted re-enable on non-disabled detector |
| `VALIDATION_FAILED` | Feedback record validation failed |

---

## 22. Cortex Bridge Integration (D7 Grounding)

### How Feedback Events Become Cortex Memories

Per PLANNING-DRIFT.md D5 and D7, the bridge crate implements DriftEventHandler to
create Cortex memories from feedback events:

```rust
// In cortex-drift-bridge (NOT in drift-core)
struct BridgeFeedbackHandler {
    cortex_client: CortexClient,
}

impl DriftEventHandler for BridgeFeedbackHandler {
    fn on_violation_dismissed(&self, violation: &Violation, reason: &str) {
        // Create a constraint_override memory in Cortex
        self.cortex_client.create_memory(Memory {
            memory_type: MemoryType::ConstraintOverride,
            content: format!(
                "Pattern '{}' violation dismissed in {} at line {}: {}",
                violation.pattern_id, violation.file, violation.line, reason
            ),
            metadata: json!({
                "pattern_id": violation.pattern_id,
                "file": violation.file,
                "line": violation.line,
                "reason": reason,
                "source": "violation_feedback"
            }),
            confidence: 0.7,
            ..Default::default()
        });
    }

    fn on_detector_disabled(&self, detector_id: &str, reason: &str) {
        // Create an anti_pattern memory in Cortex
        self.cortex_client.create_memory(Memory {
            memory_type: MemoryType::AntiPattern,
            content: format!(
                "Detector '{}' auto-disabled: {}. Patterns from this detector \
                 should be treated with lower confidence.",
                detector_id, reason
            ),
            metadata: json!({
                "detector_id": detector_id,
                "reason": reason,
                "source": "detector_health"
            }),
            confidence: 0.9,
            ..Default::default()
        });
    }

    fn on_enforcement_changed(
        &self,
        pattern_id: &str,
        from: &str,
        to: &str,
        reason: &str,
    ) {
        // Create a decision_context memory in Cortex
        self.cortex_client.create_memory(Memory {
            memory_type: MemoryType::DecisionContext,
            content: format!(
                "Pattern '{}' enforcement changed from {} to {}: {}",
                pattern_id, from, to, reason
            ),
            metadata: json!({
                "pattern_id": pattern_id,
                "from_mode": from,
                "to_mode": to,
                "reason": reason,
                "source": "enforcement_transition"
            }),
            confidence: 0.8,
            ..Default::default()
        });
    }
}
```

### Grounding Loop Consumption

The grounding feedback loop (D7) reads feedback data from drift.db to validate
Cortex memories:

```
Cortex Memory: "This project uses auth middleware on all routes"
Drift Feedback: auth-middleware pattern has 2.1% FP rate, 47 fixes, 3 dismissals
Grounding Result: VALIDATED — high fix rate confirms memory accuracy

Cortex Memory: "This project follows consistent error handling"
Drift Feedback: error-handling pattern has 23% FP rate, auto-disabled
Grounding Result: INVALIDATED — high FP rate suggests memory is inaccurate
```

This is the "killer feature" per PLANNING-DRIFT.md D7 — empirically validated AI memory.
The feedback loop provides the ground truth that makes grounding possible.

---

## 23. Configuration (drift.toml)

### Feedback Configuration Section

```toml
[feedback]
# Enable/disable the feedback loop. Default: true.
enabled = true

# Project-level scope (not user-level). Per AD9.
scope = "project"

# Window for FP rate computation. Default: 30 days.
window_days = 30

# Number of consecutive scans without action before marking as Ignored.
# Default: 3.
ignored_after_scans = 3

[feedback.detector_health]
# FP rate thresholds. Per AD9.
healthy_threshold = 0.05    # <5% = healthy
warning_threshold = 0.10    # 5-10% = warning
alert_threshold = 0.20      # 10-20% = alert, >20% = critical
disable_after_days = 30     # Days above alert_threshold before auto-disable
min_sample_size = 10        # Minimum acted-on violations for reliable FP rate

[feedback.confidence_adjustment]
# Bayesian parameter adjustments. Per Learning System §20.2.
positive_alpha_increment = 0.5
ignored_beta_increment = 0.25
convention_approved_alpha = 2.0
convention_rejected_beta = 5.0
mcp_good_alpha = 0.5
mcp_bad_beta = 0.75
mcp_irrelevant_beta = 0.25

[feedback.directory_propagation]
# Percentage of file-level delta that propagates to directory. Per v1.
propagation_rate = 0.30

[feedback.file_exclusion]
# Thresholds for per-file exclusion. Per v1.
min_confidence = 0.5
max_boost = -0.5

[feedback.abuse_detection]
# Abuse detection thresholds.
min_actions_for_check = 10
author_dismiss_rate_threshold = 0.50
burst_threshold = 20          # dismissals in 1 hour
targeted_threshold = 10       # dismissals of one pattern in 7 days

[feedback.suppression]
# Inline suppression configuration.
# Supported comment prefixes.
prefixes = ["drift-ignore", "drift-ignore-next-line"]
# Whether to require a reason for suppressions. Default: true.
require_reason = true
# Maximum suppression duration (0 = unlimited). Default: 0.
max_duration_days = 0
# Whether to warn on expired suppressions. Default: true.
warn_on_expired = true
```

---

## 24. License Gating — Tier Mapping

| Feature | Community | Team | Enterprise |
|---------|-----------|------|-----------|
| Record feedback (fix/dismiss) | ✅ | ✅ | ✅ |
| View FP rates | ✅ | ✅ | ✅ |
| Inline suppressions (drift-ignore) | ✅ | ✅ | ✅ |
| Detector health monitoring | ✅ | ✅ | ✅ |
| Auto-disable at >20% FP | ✅ | ✅ | ✅ |
| Progressive enforcement integration | ❌ | ✅ | ✅ |
| Abuse detection | ❌ | ✅ | ✅ |
| SARIF suppression mapping | ❌ | ✅ | ✅ |
| Enforcement transition audit trail | ❌ | ✅ | ✅ |
| Feedback export (JSON/CSV) | ❌ | ❌ | ✅ |
| Custom health thresholds | ❌ | ❌ | ✅ |
| Multi-repo feedback aggregation | ❌ | ❌ | ✅ |
| Webhook notifications on health changes | ❌ | ❌ | ✅ |

Rationale: Core feedback (recording, FP rates, health, auto-disable) is free because
it's essential for analysis quality. Progressive enforcement and audit trails are Team
features because they require policy management. Export and custom thresholds are
Enterprise because they serve governance needs.

---

## 25. Resolved Inconsistencies

### Inconsistency 1: FP Rate Formula Variants

**Source A** (DRIFT-V2-FULL-SYSTEM-AUDIT.md):
> `(dismissed + ignored) / (fixed + dismissed + ignored + autoFixed)`

**Source B** (13-LEARNING-SYSTEM-V2-PREP.md §20.3):
> `(dismissed + ignored) / (fixed + dismissed + ignored)` — no autoFixed

**Resolution**: Use Source A. AutoFixed is a positive signal equivalent to Fixed and
must be in the denominator. Source B's ConventionEffectiveness was written before the
AutoFixed action was fully specified. The v2 formula is:
```
FP rate = (dismissed_fp + dismissed_na + ignored) / (fixed + dismissed_all + ignored + auto_fixed)
```

### Inconsistency 2: Dismissal Reason Granularity

**Source A** (09-QUALITY-GATES-V2-PREP.md §15):
> 4 reasons: false-positive, wont-fix, not-applicable (no duplicate)

**Source B** (Semgrep triage model):
> 3 reasons: False positive, Acceptable risk, No time to fix

**Resolution**: Use 4 reasons (Source A + Duplicate). Duplicate is needed because
cross-gate deduplication (per Meta Fix Fast QG-R4) can surface the same violation
from multiple gates. Developers need a way to dismiss duplicates without affecting
FP rate. Map Semgrep's "Acceptable risk" to WontFix, "No time to fix" to WontFix.

### Inconsistency 3: FP Rate Threshold for Enforcement Demotion

**Source A** (09-QUALITY-GATES-V2-PREP.md §12):
> Block→Comment at >10%, Comment→Monitor at >25%

**Source B** (DRIFT-V2-FULL-SYSTEM-AUDIT.md):
> Alert at >10%, auto-disable at >20% for 30+ days

**Resolution**: Both are correct — they operate at different levels.
- **Pattern-level** (Source A): FP rate drives enforcement mode transitions
- **Detector-level** (Source B): FP rate drives detector health status
A detector can be healthy (overall <5% FP) while individual patterns from that
detector have higher FP rates. The pattern-level thresholds are more granular.

### Inconsistency 4: Confidence Adjustment Values

**Source A** (09-QUALITY-GATES-V2-PREP.md §15 R6):
> fix: +0.02, dismiss:fp: -0.05, dismiss:na: -0.02

**Source B** (13-LEARNING-SYSTEM-V2-PREP.md §20.2):
> ViolationFixed: α += 0.5, ViolationDismissed: β += 0.5

**Resolution**: Source A is the v1 static delta model. Source B is the v2 Bayesian
model. V2 uses Bayesian exclusively. The v1 deltas are preserved as documentation
of the migration path but are not used in v2 code.

### Inconsistency 5: MCP Feedback Ratings vs Violation Actions

**Source A** (DRIFT-V2-FULL-SYSTEM-AUDIT.md MCP Feedback System):
> good: +0.1, bad: -0.15, irrelevant: -0.05

**Source B** (This document §5):
> 5 violation actions: Fixed, Dismissed, Ignored, AutoFixed, NotSeen

**Resolution**: MCP ratings and violation actions are different feedback channels.
MCP ratings are about example quality (pattern examples shown to AI agents).
Violation actions are about violation accuracy (violations shown to developers).
Both feed into the same Bayesian confidence system but through different paths.
MCP ratings map to: good → α += 0.5, bad → β += 0.75, irrelevant → β += 0.25.


---

## 26. File / Module Structure

```
drift-core/src/feedback/
├── mod.rs                      # Module exports, FeedbackEngine orchestrator
├── types.rs                    # ViolationAction, DismissalReason, FeedbackRecord,
│                               #   SuppressionRecord, DetectorHealthState, FeedbackStats,
│                               #   FeedbackEntityType, TrendDirection, DetectorHealthStatus
├── action_recorder.rs          # ActionRecorder — validates and persists feedback
├── suppression_manager.rs      # SuppressionManager — parse, track, expire suppressions
├── statistics.rs               # StatisticsAggregator — FP rate computation, distributions,
│                               #   trend analysis, top-FP queries
├── health_monitor.rs           # HealthMonitor — detector health state machine, alerts,
│                               #   auto-disable, re-enable
├── confidence_adjuster.rs      # ConfidenceAdjuster — Bayesian parameter updates,
│                               #   directory propagation, file exclusion
├── abuse_detector.rs           # AbuseDetector — per-author dismiss rate, burst detection,
│                               #   targeted dismissal detection
├── inference.rs                # Scan-to-scan action inference (Fixed, Ignored detection)
├── config.rs                   # FeedbackConfig, DetectorHealthConfig,
│                               #   ConfidenceAdjustmentConfig, AbuseDetectionConfig
├── errors.rs                   # FeedbackError enum (thiserror)
├── persistence.rs              # SQLite read/write for all feedback tables
└── sarif.rs                    # SARIF suppression mapping

drift-core/src/feedback/errors.rs:
├── FeedbackError
│   ├── MissingDismissalReason { violation_id }
│   ├── UnexpectedDismissalReason { action }
│   ├── WontFixRequiresReason { violation_id }
│   ├── MissingFile
│   ├── ViolationNotFound { violation_id }
│   ├── DetectorNotFound { detector_id }
│   ├── DetectorNotDisabled { detector_id }
│   ├── ValidationFailed { message }
│   ├── DatabaseError { source: rusqlite::Error }
│   └── InternalError { message }

drift-napi/src/bindings/
├── feedback.rs                 # NAPI bindings for all feedback functions

packages/drift/src/feedback/
├── index.ts                    # FeedbackOrchestrator (TS coordination layer)
├── types.ts                    # TS type definitions (generated from Rust via napi)
└── cli.ts                      # CLI command handlers for `drift feedback`
```

### Module Dependency Graph

```
                    ┌──────────────┐
                    │  types.rs    │
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
    ┌─────────▼──┐  ┌──────▼─────┐  ┌──▼──────────┐
    │ config.rs  │  │ errors.rs  │  │persistence.rs│
    └─────────┬──┘  └──────┬─────┘  └──┬──────────┘
              │            │            │
    ┌─────────▼────────────▼────────────▼──────────┐
    │              action_recorder.rs               │
    │              suppression_manager.rs            │
    │              statistics.rs                     │
    │              health_monitor.rs                 │
    │              confidence_adjuster.rs            │
    │              abuse_detector.rs                 │
    │              inference.rs                      │
    │              sarif.rs                          │
    └──────────────────────┬───────────────────────┘
                           │
                    ┌──────▼───────┐
                    │   mod.rs     │ (FeedbackEngine)
                    └──────────────┘
```

---

## 27. Build Order & Dependency Chain

### Phase 1: Foundation (Week 1)

1. `types.rs` — All type definitions (ViolationAction, DismissalReason, FeedbackRecord, etc.)
2. `errors.rs` — FeedbackError enum
3. `config.rs` — All configuration structs with defaults
4. `persistence.rs` — SQLite table creation, CRUD operations

**Milestone**: Can create tables and persist/read feedback records.

### Phase 2: Core Engine (Week 2)

5. `action_recorder.rs` — Validate and record feedback actions
6. `statistics.rs` — FP rate computation, distributions, trend analysis
7. `health_monitor.rs` — Detector health state machine, alerts, auto-disable
8. `inference.rs` — Scan-to-scan action inference

**Milestone**: Can record feedback, compute FP rates, monitor detector health.

### Phase 3: Intelligence (Week 3)

9. `confidence_adjuster.rs` — Bayesian parameter updates, directory propagation
10. `suppression_manager.rs` — Parse, track, expire inline suppressions
11. `abuse_detector.rs` — Per-author dismiss rate monitoring
12. `sarif.rs` — SARIF suppression mapping

**Milestone**: Full feedback intelligence pipeline operational.

### Phase 4: Integration (Week 4)

13. `mod.rs` — FeedbackEngine orchestrator, FeedbackStatsProvider implementation
14. NAPI bindings (`drift-napi/src/bindings/feedback.rs`)
15. TS orchestrator (`packages/drift/src/feedback/index.ts`)
16. CLI commands (`packages/drift/src/feedback/cli.ts`)

**Milestone**: Full end-to-end feedback loop operational via MCP, CLI, and IDE.

### Phase 5: Polish (Week 5)

17. MCP tool registration
18. LSP integration (code actions for dismiss/suppress)
19. Integration tests with Quality Gates, Audit System, Learning System
20. Performance testing with large feedback datasets

**Milestone**: Production-ready feedback loop.

### Dependencies on Other Systems

| Dependency | Required By | Phase |
|-----------|------------|-------|
| drift.db schema (02-STORAGE) | persistence.rs | Phase 1 |
| DriftEventHandler (04-INFRASTRUCTURE) | health_monitor.rs, action_recorder.rs | Phase 2 |
| Violation types (06-DETECTOR) | types.rs, inference.rs | Phase 1 |
| BayesianPattern (10-BAYESIAN) | confidence_adjuster.rs | Phase 3 |
| GateViolation (09-QUALITY-GATES) | sarif.rs, statistics.rs | Phase 3 |
| drift-napi runtime (03-NAPI-BRIDGE) | NAPI bindings | Phase 4 |

### Dependencies FROM Other Systems

| Consumer | What It Needs | Available After |
|----------|-------------|----------------|
| Quality Gates §12 (enforcement transitions) | FeedbackStatsProvider trait | Phase 2 |
| Audit System §18 (health score FP factor) | get_fp_count_for_audit() | Phase 2 |
| Learning System §20 (convention feedback) | to_convention_feedback() | Phase 2 |
| SARIF Reporter (suppression objects) | to_sarif_suppressions() | Phase 3 |
| Cortex Bridge D7 (memory creation) | DriftEventHandler events | Phase 2 |

---

## 28. V1 Feature Verification — Complete Gap Analysis

### Verification Checklist

| # | V1 Feature | V2 Implementation | Section | Verified |
|---|-----------|-------------------|---------|----------|
| 1 | "Not useful"/"Useful" signals | 5 actions + sub-reasons | §5 | ✅ |
| 2 | Track Fixed/Dismissed/Ignored/AutoFixed/NotSeen | ViolationAction enum | §4, §5 | ✅ |
| 3 | FP rate per detector | compute_fp_rate() with Detector entity type | §6 | ✅ |
| 4 | FP formula with autoFixed | Tricorder formula preserved exactly | §6 | ✅ |
| 5 | Alert at >10% FP | DetectorHealthStatus::Alert | §7 | ✅ |
| 6 | Auto-disable at >20% for 30+ days | Health state machine | §7 | ✅ |
| 7 | Feedback → pattern confidence | Bayesian α/β adjustments | §8 | ✅ |
| 8 | Project-level scope | config.scope = "project" | §23 | ✅ |
| 9 | MCP health metrics | drift_feedback_health tool | §15 | ✅ |
| 10 | IDE tracking (opt-in) | LSP code actions + status bar | §17 | ✅ |
| 11 | CLI tracking | drift feedback commands | §16 | ✅ |
| 12 | CI tracking | CLI in CI mode | §16 | ✅ |
| 13 | Dismiss sub-reasons | DismissalReason enum (4 reasons) | §4, §5 | ✅ |
| 14 | Confidence deltas | Upgraded to Bayesian | §8 | ✅ |
| 15 | Block→Comment at >10% FP | Progressive enforcement integration | §10 | ✅ |
| 16 | Comment→Monitor at >25% FP | Progressive enforcement integration | §10 | ✅ |
| 17 | violation_feedback table | Expanded with v2 fields | §11 | ✅ |
| 18 | Indefinite retention | Retention policy preserved | §11 | ✅ |
| 19 | Dismissal requires reason | validate_feedback() | §5 | ✅ |
| 20 | Abuse detection | AbuseDetector with 3 checks | §14 | ✅ |
| 21 | ConventionFeedback enum | Preserved, maps to ViolationAction | §5, §20 | ✅ |
| 22 | Bayesian α/β from feedback | ConfidenceAdjuster | §8 | ✅ |
| 23 | ConventionEffectiveness | FeedbackStats with FP rate | §6 | ✅ |
| 24 | false_positive_rate() | FeedbackStats::false_positive_rate() | §6 | ✅ |
| 25 | should_disable() with ≥10 minimum | has_sufficient_data field | §6, §7 | ✅ |
| 26 | Bidirectional Audit↔Feedback | §19 upstream, §20 downstream | §19, §20 | ✅ |
| 27 | Auto-approve suppression for unhealthy detectors | §7 auto-disable behavior | §7 | ✅ |
| 28 | Health score FP factor | get_fp_count_for_audit() | §20 | ✅ |
| 29 | Degradation alerts on FP increase | HealthMonitor events | §7, §12 | ✅ |
| 30 | on_violation_detected | DriftEventHandler | §12 | ✅ |
| 31 | on_violation_dismissed | DriftEventHandler | §12 | ✅ |
| 32 | on_violation_fixed | DriftEventHandler | §12 | ✅ |
| 33 | on_detector_alert | DriftEventHandler | §12 | ✅ |
| 34 | on_detector_disabled | DriftEventHandler | §12 | ✅ |
| 35 | pattern_suppressions table | Expanded with v2 fields | §11 | ✅ |
| 36 | Inline suppression with reason | SuppressionManager parser | §9 | ✅ |
| 37 | Expiration support | enforce_suppression_expiration() | §9 | ✅ |
| 38 | MCP ratings (good/bad/irrelevant) | Mapped to Bayesian updates | §8 | ✅ |
| 39 | Directory-level propagation (30%) | propagate_to_directory() | §8 | ✅ |
| 40 | File exclusion (conf>0.5, boost<-0.5) | should_exclude_file() | §8 | ✅ |

**Result: 40/40 v1 features preserved. 0 features dropped. 8 features upgraded.**

---

## 29. Algorithms Reference

### Algorithm 1: Tricorder FP Rate

```
Input: feedback records for entity E in window W
Output: FP rate ∈ [0.0, 1.0]

negative = count(dismissed:fp) + count(dismissed:na) + count(ignored)
total = count(fixed) + count(dismissed:all) + count(ignored) + count(auto_fixed)
fp_rate = negative / total  (0.0 if total == 0)
```

### Algorithm 2: Detector Health State Machine

```
Input: current FP rate, previous state, config
Output: new DetectorHealthStatus

if acted_on < min_sample_size → InsufficientData
if fp_rate < 0.05 → Healthy
if fp_rate < 0.10 → Warning
if fp_rate < 0.20 → Alert (emit on_detector_alert)
if fp_rate ≥ 0.20:
    days_above = previous.days_above_disable + 1
    if days_above ≥ 30 → Disabled (emit on_detector_disabled)
    else → Critical (emit on_detector_alert with severity=critical)
```

### Algorithm 3: Bayesian Confidence Adjustment

```
Input: feedback record, pattern's (α, β)
Output: updated (α, β)

Fixed/AutoFixed → α += 0.5
Dismissed:FP → β += 0.5
Dismissed:NA → β += 0.25
Dismissed:WontFix → no change
Dismissed:Duplicate → no change
Ignored → β += 0.25
ConventionApproved → α += 2.0
ConventionRejected → β += 5.0

posterior_mean = α / (α + β)
```

### Algorithm 4: Scan-to-Scan Action Inference

```
Input: previous violations V_prev, current violations V_curr, file changes F
Output: inferred actions

for each v in V_prev:
    if v ∉ V_curr:
        if v.file ∈ F.modified → infer Fixed (confidence 0.85)
        else → skip (detection change, not developer action)
    else:
        if v has no explicit feedback:
            v.consecutive_unfixed_scans += 1
            if consecutive ≥ 3 → infer Ignored (confidence 0.70)
```

### Algorithm 5: Abuse Detection

```
Input: feedback records in last 30 days, grouped by author
Output: abuse alerts

for each author A:
    dismiss_rate = A.dismissed / A.total
    if dismiss_rate > 0.50 AND A.total ≥ 10 → HighDismissRate alert

for each author A in last 1 hour:
    if A.dismissed > 20 → BurstDismissals alert

for each (author, pattern) pair in last 7 days:
    if dismissed > 10 → TargetedDismissals alert
```

### Algorithm 6: Directory Propagation

```
Input: feedback on file F for pattern P, confidence delta D
Output: directory-level score update

dir = parent_directory(F)
dir_delta = D × 0.30
UPDATE pattern_directory_scores SET score_delta += dir_delta
    WHERE pattern_id = P AND directory = dir
```

### Algorithm 7: File Exclusion Check

```
Input: pattern P, file F, pattern confidence C
Output: boolean (should exclude)

boost = SUM(
    +0.1 for each Fixed/AutoFixed in F for P,
    -0.15 for each Dismissed:FP in F for P,
    -0.05 for each Dismissed:NA in F for P,
    -0.05 for each Ignored in F for P
)

exclude = (C > 0.5) AND (boost < -0.5)
```

---

## 30. Research Grounding — External Sources

### Primary Sources

| Source | Type | Key Contribution | Confidence |
|--------|------|-----------------|------------|
| Sadowski et al., "Lessons from Building Static Analysis Tools at Google" (CACM 2018) | Tier 1 (Peer-reviewed, ACM) | <10% FP rate enforcement, "Not useful"/"Please fix" feedback, continuous improvement loop | Very High |
| Semgrep Assistant Memories (2025) | Tier 1 (Official product docs) | AI-powered FP triage, organizational memory for false positive context, 95%+ agreement rate | Very High |
| Semgrep Triage & Remediation | Tier 1 (Official docs) | 7 triage statuses (Open, Reviewing, Provisionally Ignored, To Fix, Fixed, Ignored, Closed), nosemgrep comments, auto-triage | Very High |
| SonarQube "Clean as You Code" | Tier 1 (Official docs) | New-code-first philosophy, personal responsibility model | Very High |
| Meta Fix Fast | Tier 2 (Engineering blog) | Signal aggregation, time-to-fix correlation with pipeline stage, noise management | High |
| OPA Policy-as-Code | Tier 1 (CNCF graduated) | Declarative policy principles applied to enforcement configuration | High |
| CodeScene Delta Analysis | Tier 2 (Engineering blog) | Hotspot-aware scoring, behavioral code quality | High |
| SARIF 2.1.0 OASIS Standard | Tier 1 (OASIS standard) | Suppression objects, baselineState, audit trail format | Very High |

### Key Insights Applied

1. **Tricorder's <10% rule** → Drift targets <5% per detector (more aggressive because
   Bayesian confidence pre-filters low-quality patterns before they produce violations)

2. **Semgrep's Memory system** → Drift's feedback loop is the local equivalent — instead
   of cloud-based AI memories, Drift stores feedback in drift.db and uses it to adjust
   Bayesian parameters and enforcement modes locally. Same principle (learn from triage),
   different architecture (local-first vs cloud-first).

3. **Meta's signal aggregation** → Drift's cross-gate deduplication (Duplicate dismissal
   reason) and violation prioritization (R16 in Quality Gates) address the same problem
   of signal overload.

4. **SonarQube's new-code-first** → Drift's PR mode (§11 in Quality Gates) ensures
   feedback is primarily about new violations, not legacy debt. This dramatically reduces
   the volume of violations developers need to triage.

5. **SARIF suppressions** → Drift maps all feedback actions to SARIF suppression objects,
   creating a standards-compliant audit trail that integrates with GitHub Code Scanning
   and enterprise compliance tools.

6. **Semgrep's triage statuses** → Drift's 5 violation actions (Fixed, Dismissed, Ignored,
   AutoFixed, NotSeen) map to Semgrep's model: Fixed=Fixed, Dismissed=Ignored (with reason),
   Ignored=Open (no action), AutoFixed=Fixed, NotSeen=Open (not surfaced). The key
   difference is Drift tracks NotSeen separately for denominator accuracy.

---

## Appendix A: Migration from V1

### Data Migration

If v1 feedback data exists (in any format), migrate to v2 schema:

```sql
-- Migration: v1 feedback records → v2 violation_feedback table
-- v1 may have stored feedback in JSON files or a simpler table structure.
-- This migration handles the common case of a flat feedback table.

INSERT INTO violation_feedback (
    id, violation_id, pattern_id, detector_id, action,
    dismissal_reason, reason, author, file, line,
    timestamp, created_at
)
SELECT
    id,
    violation_id,
    pattern_id,
    COALESCE(detector_id, 'unknown'),
    CASE action
        WHEN 'fix' THEN 'fixed'
        WHEN 'dismiss:false-positive' THEN 'dismissed'
        WHEN 'dismiss:wont-fix' THEN 'dismissed'
        WHEN 'dismiss:not-applicable' THEN 'dismissed'
        ELSE action
    END,
    CASE action
        WHEN 'dismiss:false-positive' THEN 'false_positive'
        WHEN 'dismiss:wont-fix' THEN 'wont_fix'
        WHEN 'dismiss:not-applicable' THEN 'not_applicable'
        ELSE NULL
    END,
    reason,
    author,
    file,
    line,
    timestamp,
    COALESCE(created_at, timestamp)
FROM v1_violation_feedback;
```

### Configuration Migration

V1 feedback configuration (if any) maps to v2 `[feedback]` section in drift.toml.
Default values are chosen to match v1 behavior, so no explicit migration is needed
for projects that used v1 defaults.

---

## Appendix B: Semgrep Comparison Matrix

| Feature | Semgrep | Drift v2 |
|---------|---------|----------|
| Triage statuses | 7 (Open, Reviewing, Provisionally Ignored, To Fix, Fixed, Ignored, Closed) | 5 actions (Fixed, Dismissed, Ignored, AutoFixed, NotSeen) + 4 dismissal reasons |
| AI auto-triage | Yes (Assistant, 95%+ agreement) | No (local-first, no cloud AI dependency) |
| Organizational memory | Yes (Memories — cloud-based, scoped by project/rule/vuln-class) | Yes (drift.db — local, Bayesian parameters + directory scores) |
| FP rate tracking | Implicit (via Assistant metrics) | Explicit (per-detector, per-pattern, Tricorder formula) |
| Auto-disable | No (manual rule management) | Yes (>20% FP for 30+ days) |
| Inline suppression | `nosemgrep` comment | `// drift-ignore` comment with expiration |
| Progressive enforcement | Monitor/Comment/Block per rule | Monitor/Comment/Block per pattern with auto-promotion |
| Feedback persistence | Cloud (Semgrep AppSec Platform) | Local (drift.db SQLite) |
| SARIF suppressions | Yes | Yes |
| Abuse detection | No | Yes (per-author dismiss rate, burst, targeted) |

### Key Architectural Difference

Semgrep's approach is cloud-first: feedback flows to the Semgrep AppSec Platform where
AI (Assistant) processes it. Drift's approach is local-first: feedback stays in drift.db
and is processed by deterministic algorithms (Bayesian updates, threshold-based health
monitoring). This aligns with PLANNING-DRIFT.md D1 (standalone independence) — Drift's
feedback loop works without any cloud service.

The trade-off: Semgrep's AI can catch context-dependent false positives that rule-based
systems miss. Drift compensates with Bayesian confidence scoring (patterns with low
confidence don't produce violations in the first place) and progressive enforcement
(new patterns start in monitor mode, proving themselves before blocking).
