# Constraint System (drift-constraints) — V2 Implementation Prep

> Comprehensive build specification for Drift v2's constraint detection, verification,
> and enforcement subsystem. Synthesized from: 18-constraints RECAP.md, RESEARCH.md,
> RECOMMENDATIONS.md, DRIFT-V2-FULL-SYSTEM-AUDIT.md (Cat 18), DRIFT-V2-STACK-HIERARCHY.md
> (Level 2C), PLANNING-DRIFT.md (D1-D7), 03-NAPI-BRIDGE-V2-PREP.md (§10.10 constraint
> bindings), 02-STORAGE-V2-PREP.md (drift.db schema), 04-INFRASTRUCTURE-V2-PREP.md
> (quality gates integration), 05-CALL-GRAPH-V2-PREP.md (ordering constraint verification),
> 06-UNIFIED-ANALYSIS-ENGINE-V2-PREP.md (Level 4 cross-reference constraints),
> 07-BOUNDARY-DETECTION-V2-PREP.md (data_flow constraint source), existing cortex-core
> constraint types (ConstraintLink, ConstraintOverrideContent, ConstraintGatherer),
> ArchUnit FreezingArchRule pattern, Semgrep YAML rule syntax, SonarQube Architecture as
> Code, OPA Constraint Framework, Google Tricorder feedback loops, Daikon invariant mining,
> and 25+ external research sources.
>
> Purpose: Everything needed to build drift-constraints from scratch. All 12 invariant
> types preserved and upgraded, all v1 features accounted for, decisions resolved,
> inconsistencies flagged, interface contracts defined, build order specified.
> Generated: 2026-02-08

---

## 1. Architectural Position

The constraint system is Level 2C (Structural Intelligence) in Drift's stack hierarchy.
It is the enforcement layer that transforms statistically discovered patterns into
enforceable architectural invariants. Unlike patterns (which describe what IS), constraints
enforce what MUST BE.

Per PLANNING-DRIFT.md D1: Drift is standalone. Constraints live entirely in drift-core.
Per PLANNING-DRIFT.md D6: All constraint data persists in drift.db (standalone, no ATTACH).
Per PLANNING-DRIFT.md D5: Constraint lifecycle events emit via DriftEventHandler.

### What Lives Here
- 12 invariant types (all v1 types preserved + upgraded verification)
- 10 constraint categories spanning the full application stack
- 4-stage pipeline: InvariantDetector → ConstraintSynthesizer → ConstraintStore → ConstraintVerifier
- AST-based verification via Rust ParseResult (replaces v1 regex)
- Call graph integration for ordering constraints (must_precede, must_follow)
- Declarative TOML constraint format (version-controlled, human-readable)
- Baseline management (FreezingArchRule pattern for legacy adoption)
- Developer feedback loop (false-positive tracking, auto-demotion)
- Constraint conflict resolution (specificity-based precedence)
- Constraint templates (10+ built-in reusable patterns)
- SQLite persistence in drift.db (replaces v1 JSON files)
- Incremental verification (file-level + constraint-level)
- Temporal analysis (momentum scoring, trend detection)

### What Does NOT Live Here
- Quality gate evaluation (lives in drift-gates, consumes constraint verification results)
- MCP tool definitions (lives in drift-analysis MCP server, calls constraint APIs)
- CLI commands (lives in drift-cli, calls constraint APIs)
- Cortex memory integration (lives in cortex-drift-bridge, optional)
- Context generation (lives in drift-context, consumes active constraints)
- Pattern detection (lives in drift-detectors, feeds invariant mining)
- Call graph construction (lives in drift-call-graph, feeds ordering verification)
- Taint analysis (lives in drift-taint, feeds data_flow verification)

### Upstream Dependencies (What Constraints Consumes)

| System | What It Provides | How Constraints Uses It |
|--------|-----------------|------------------------|
| Parsers (02) | ParseResult with functions, classes, imports, decorators | AST-based predicate evaluation |
| Call Graph (05) | Function→function edges, path queries | must_precede/must_follow verification |
| Detectors (06) | Approved patterns with confidence scores | Pattern-based invariant mining |
| Boundary Detection (07) | Data access points, sensitive fields | data_flow invariant mining |
| Taint Analysis (15) | Source→sink paths, sanitizer locations | data_flow constraint verification |
| Test Topology (18) | Test-to-source mappings, coverage data | Test coverage invariant mining |
| Error Handling (16) | Error boundaries, propagation chains | Error handling invariant mining |
| Storage (02) | drift.db SQLite with WAL mode | Constraint persistence, baselines, feedback |

### Downstream Consumers (What Depends on Constraints)

| System | What It Consumes | How It Uses Constraints |
|--------|-----------------|------------------------|
| Quality Gates | Active constraints, verification results | constraint-verification gate (blocking) |
| NAPI Bridge (03) | Constraint APIs | detect_constraints(), verify_constraints() |
| MCP Server | Constraint data, verification API | drift_validate_change, drift_prevalidate |
| CLI | Constraint CRUD, verification | drift constraints list/approve/ignore/baseline |
| Context Generation | Active constraints for file/package | Constraint gatherer (20% token budget) |
| DriftEventHandler (D5) | Lifecycle events | on_constraint_approved, on_violation_detected |

---

## 2. V1 Feature Inventory — Complete Preservation Matrix

Every v1 feature is accounted for. Nothing is dropped without replacement.

### 2.1 Core Types (v1 → v2)

| v1 Feature | v1 Implementation | v2 Status | v2 Location |
|-----------|-------------------|-----------|-------------|
| Constraint struct | TypeScript interface, ~15 fields | **UPGRADED** — Rust struct + SQLite row | §3.1 |
| 12 invariant types | TypeScript enum | **KEPT** — Rust enum, all 12 preserved | §3.2 |
| 10 categories | TypeScript string union | **KEPT** — Rust enum, all 10 preserved | §3.3 |
| 4 status states | discovered/approved/ignored/custom | **UPGRADED** — 6 states (+deprecated, +superseded) | §3.4 |
| 9 language targets | TypeScript string union | **UPGRADED** — 10 languages (+go) | §3.5 |
| ConstraintScope | files/directories/functions/classes/entryPoints | **UPGRADED** — +packages, +modules, glob optimization | §3.6 |
| ConstraintConfidence | score/conforming/violating/lastVerified | **UPGRADED** — +momentum, +trend, +history | §3.7 |
| ConstraintEnforcement | level/autoFix/message/suggestion | **UPGRADED** — autoFix implemented, +fix templates | §3.8 |
| ConstraintViolation | constraintId/file/line/message/severity | **UPGRADED** — +snippet, +fix suggestion, +baseline status | §3.9 |
| VerificationResult | file/violations/passed/failed/skipped | **UPGRADED** — +baseline-aware, +incremental stats | §3.10 |
| ConstraintSource | type/sourceIds/evidence | **UPGRADED** — +temporal data, +cross-language | §3.11 |

### 2.2 Pipeline Components (v1 → v2)

| v1 Component | v1 LOC (est.) | v2 Status | v2 Location |
|-------------|---------------|-----------|-------------|
| InvariantDetector | ~400 TS | **UPGRADED** — Rust, +temporal mining, +negative invariants | §5 |
| ConstraintSynthesizer | ~350 TS | **UPGRADED** — Rust, +conflict detection, +template expansion | §6 |
| ConstraintStore | ~500 TS (JSON files) | **REPLACED** — SQLite in drift.db, indexed, versioned | §7 |
| ConstraintVerifier | ~450 TS (regex) | **REPLACED** — Rust AST-based, +call graph, +data flow | §8 |
| Index (exports) | ~30 TS | **KEPT** — Rust mod.rs re-exports | §4 |

### 2.3 Storage (v1 → v2)

| v1 Feature | v1 Implementation | v2 Status | v2 Location |
|-----------|-------------------|-----------|-------------|
| Category-indexed JSON files | .drift/constraints/discovered/*.json | **REPLACED** — SQLite tables | §7.1 |
| index.json for fast lookups | Category → constraint ID mapping | **REPLACED** — SQLite indexes | §7.2 |
| CRUD operations | File read/write per category | **UPGRADED** — SQLite CRUD with transactions | §7.3 |
| Scope matching (getForFile) | Glob pattern matching, O(N×S) | **UPGRADED** — Scope index table, O(1) lookup | §7.4 |
| Lifecycle transitions | approve(id), ignore(id) | **UPGRADED** — +bulk transitions, +audit trail | §7.5 |
| Query with filters | query(options) with sort/paginate | **UPGRADED** — SQL queries with keyset pagination | §7.6 |

### 2.4 Verification (v1 → v2)

| v1 Feature | v1 Implementation | v2 Status | v2 Location |
|-----------|-------------------|-----------|-------------|
| Full-file verification | verifyFile(path, content, constraints) | **UPGRADED** — AST-based, all 12 types | §8.1 |
| Change-aware verification | verifyChange(path, old, new, constraints) | **UPGRADED** — +constraint-level incremental | §8.2 |
| Function extraction | Language-specific regex | **REPLACED** — ParseResult.functions | §8.3 |
| Class extraction | Language-specific regex | **REPLACED** — ParseResult.classes | §8.3 |
| Entry point detection | Route decorator/handler regex | **REPLACED** — ParseResult.decorators + framework detection | §8.3 |
| Import detection | import/require regex | **REPLACED** — ParseResult.imports | §8.3 |
| 8-language support | Per-language regex patterns | **UPGRADED** — 10 languages via tree-sitter AST | §8.4 |

### 2.5 Integration Points (v1 → v2)

| v1 Integration | v1 Implementation | v2 Status | v2 Location |
|---------------|-------------------|-----------|-------------|
| Quality gate (constraint-verification) | TS gate evaluator | **UPGRADED** — Rust, baseline-aware | §12.1 |
| MCP tools (drift_validate_change) | TS MCP handler | **KEPT** — calls Rust via NAPI | §12.2 |
| MCP tools (drift_prevalidate) | TS MCP handler | **KEPT** — calls Rust via NAPI | §12.2 |
| CLI (drift constraints list) | TS CLI command | **UPGRADED** — +pagination, +filters | §12.3 |
| CLI (drift constraints approve) | TS CLI command | **UPGRADED** — +bulk approve, +audit | §12.3 |
| CLI (drift constraints ignore) | TS CLI command | **UPGRADED** — +reason required, +audit | §12.3 |
| Cortex constraint_override memories | TS memory creation | **KEPT** — via bridge crate (D4) | §12.4 |
| Cortex ConstraintLink | Rust struct in cortex-core | **KEPT** — via bridge crate (D4) | §12.4 |
| Context generation (20% budget) | TS constraint gatherer | **UPGRADED** — +predicate context, +rationale | §12.5 |
| Provenance tracking ([drift:constraint]) | TS provenance tags | **KEPT** — via context generation | §12.5 |

### 2.6 New v2 Features NOT in v1

| New Feature | Why | Priority | Location |
|------------|-----|----------|----------|
| Declarative TOML format | Version-controlled constraints, user-defined | P0 | §9 |
| Baseline management | Legacy codebase adoption (FreezingArchRule) | P0 | §10 |
| Developer feedback loop | <5% false-positive rate (Tricorder) | P1 | §11 |
| Constraint conflict resolution | Prevent contradictory constraints | P1 | §6.4 |
| Constraint templates | Reusable patterns, reduce boilerplate | P1 | §9.3 |
| Temporal analysis | Momentum scoring, trend detection | P1 | §5.5 |
| Negative invariant mining | Detect what is consistently AVOIDED | P1 | §5.6 |
| Constraint versioning | History tracking, audit trail | P1 | §7.7 |
| Auto-fix implementation | Automated remediation for deterministic fixes | P2 | §8.5 |
| Constraint visualization | Coverage maps, trend charts, health dashboard | P2 | §12.6 |
| Constraint inheritance | Package-level constraints inherited by sub-packages | P1 | §9.4 |
| Cross-language invariants | Same invariant across multiple languages | P2 | §5.7 |

---

## 3. Core Type System (Rust)

All types live in `crates/drift-core/src/constraints/types.rs`.
Every v1 type is preserved and upgraded.

### 3.1 Constraint (Primary Entity)

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single architectural constraint — the core entity.
/// Persisted in drift.db `constraints` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraint {
    /// Deterministic hash-based ID: SHA256(category + invariant_type + predicate + scope).
    pub id: String,
    /// Human-readable name (e.g., "Authentication must precede data access").
    pub name: String,
    /// What this constraint enforces.
    pub description: String,
    /// 1 of 10 categories.
    pub category: ConstraintCategory,
    /// The actual rule — 1 of 12 invariant types.
    pub invariant: ConstraintInvariant,
    /// Where this constraint applies (files, directories, functions, etc.).
    pub scope: ConstraintScope,
    /// Statistical confidence with temporal tracking.
    pub confidence: ConstraintConfidence,
    /// How violations are reported and fixed.
    pub enforcement: ConstraintEnforcement,
    /// Lifecycle state.
    pub status: ConstraintStatus,
    /// Target language(s).
    pub language: ConstraintLanguage,
    /// What Drift data produced this constraint.
    pub source: ConstraintSource,
    /// Optional rationale (links to ADRs, explanations).
    pub rationale: Option<ConstraintRationale>,
    /// Template ID if instantiated from a template.
    pub template_id: Option<String>,
    /// Schema version for forward compatibility.
    pub version: u32,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp.
    pub updated_at: DateTime<Utc>,
    /// Last verification timestamp.
    pub last_verified: Option<DateTime<Utc>>,
    /// Who approved this constraint (if approved).
    pub approved_by: Option<String>,
    /// When this constraint was approved.
    pub approved_at: Option<DateTime<Utc>>,
}
```


### 3.2 Invariant Types (All 12 Preserved)

```rust
/// The 12 invariant types — the actual rules constraints enforce.
/// Every v1 type is preserved. Verification strategy upgraded from regex to AST/call graph.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum InvariantType {
    /// "X must have Y" — Required element present.
    /// v2 verification: ParseResult.functions/classes/decorators/imports pattern match.
    MustHave,
    /// "X must not have Y" — Forbidden element absent.
    /// v2 verification: Negated ParseResult pattern match.
    MustNotHave,
    /// "X must come before Y" — Ordering (A before B).
    /// v2 verification: Call graph path query (NEW — was unverifiable in v1).
    MustPrecede,
    /// "X must come after Y" — Ordering (A after B).
    /// v2 verification: Call graph path query (NEW — was unverifiable in v1).
    MustFollow,
    /// "X and Y must be in same location" — Colocation.
    /// v2 verification: File path comparison via scanner.
    MustColocate,
    /// "X and Y must be in different locations" — Separation.
    /// v2 verification: File path comparison via scanner.
    MustSeparate,
    /// "X must be wrapped in Y" — Containment (try/catch, if-check).
    /// v2 verification: AST containment check (NEW — was unverifiable in v1).
    MustWrap,
    /// "X must propagate to Y" — Error/event propagation through chain.
    /// v2 verification: Call graph reachability query.
    MustPropagate,
    /// "X must have exactly N of Y" — Count constraints (min/max).
    /// v2 verification: Count query on ParseResult elements.
    Cardinality,
    /// "Data must not flow from X to Y" — Data flow path constraint.
    /// v2 verification: Taint analysis engine (NEW — was unverifiable in v1).
    DataFlow,
    /// "X must match naming pattern" — Naming convention enforcement.
    /// v2 verification: Regex/glob matching on ParseResult names.
    Naming,
    /// "Module must contain X" — File/directory structure requirements.
    /// v2 verification: File system check via scanner.
    Structure,
}

impl InvariantType {
    /// Whether this invariant type requires call graph access for verification.
    pub fn requires_call_graph(&self) -> bool {
        matches!(self, Self::MustPrecede | Self::MustFollow | Self::MustPropagate)
    }

    /// Whether this invariant type requires taint analysis for verification.
    pub fn requires_taint_analysis(&self) -> bool {
        matches!(self, Self::DataFlow)
    }

    /// Whether this invariant type requires AST access for verification.
    pub fn requires_ast(&self) -> bool {
        matches!(
            self,
            Self::MustHave
                | Self::MustNotHave
                | Self::MustWrap
                | Self::Cardinality
                | Self::Naming
        )
    }

    /// Whether this invariant type requires file system access for verification.
    pub fn requires_filesystem(&self) -> bool {
        matches!(
            self,
            Self::MustColocate | Self::MustSeparate | Self::Structure
        )
    }
}
```

### 3.3 Constraint Categories (All 10 Preserved)

```rust
/// The 10 constraint categories spanning the full application stack.
/// All v1 categories preserved.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintCategory {
    /// API endpoint constraints (auth decorators, response formats, versioning).
    Api,
    /// Authentication/authorization constraints (auth-before-data, role checks).
    Auth,
    /// Data access layer constraints (no direct DB from controllers, ORM usage).
    Data,
    /// Error handling constraints (try/catch requirements, propagation rules).
    Error,
    /// Test coverage constraints (exported functions must have tests).
    Test,
    /// Security pattern constraints (input validation, output encoding).
    Security,
    /// Module/file structure constraints (naming, colocation, separation).
    Structural,
    /// Performance pattern constraints (no N+1, caching requirements).
    Performance,
    /// Logging requirement constraints (audit logging, structured logging).
    Logging,
    /// Input validation constraints (sanitization, type checking).
    Validation,
}

impl ConstraintCategory {
    /// All categories for iteration.
    pub const ALL: [Self; 10] = [
        Self::Api,
        Self::Auth,
        Self::Data,
        Self::Error,
        Self::Test,
        Self::Security,
        Self::Structural,
        Self::Performance,
        Self::Logging,
        Self::Validation,
    ];

    /// Priority weight for conflict resolution (higher = wins conflicts).
    /// Security constraints take precedence over naming constraints.
    pub fn priority_weight(&self) -> u32 {
        match self {
            Self::Security => 100,
            Self::Auth => 90,
            Self::Data => 80,
            Self::Error => 70,
            Self::Api => 60,
            Self::Validation => 50,
            Self::Test => 40,
            Self::Performance => 30,
            Self::Logging => 20,
            Self::Structural => 10,
        }
    }
}
```

### 3.4 Constraint Status (Upgraded: 4 → 6 States)

```rust
/// Constraint lifecycle states.
/// v1 had 4 states: discovered, approved, ignored, custom.
/// v2 adds: deprecated (being phased out), superseded (replaced by another).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintStatus {
    /// Auto-detected, pending review. Not enforced.
    Discovered,
    /// User-approved, actively enforced.
    Approved,
    /// User-ignored, not enforced. Reason tracked.
    Ignored,
    /// User-defined (from TOML file). Always enforced.
    Custom,
    /// Being phased out. Enforcement demoted to "info". (NEW in v2)
    Deprecated,
    /// Replaced by another constraint. Links to successor. (NEW in v2)
    Superseded,
}

impl ConstraintStatus {
    /// Whether this status means the constraint is actively enforced.
    pub fn is_enforced(&self) -> bool {
        matches!(self, Self::Approved | Self::Custom)
    }

    /// Whether this status means the constraint is visible in reports.
    pub fn is_visible(&self) -> bool {
        !matches!(self, Self::Ignored | Self::Superseded)
    }
}
```

### 3.5 Constraint Language (Upgraded: 9 → 10 Languages)

```rust
/// Target language for a constraint.
/// v1 had 9 languages. v2 adds Go (matching parser support).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintLanguage {
    TypeScript,
    JavaScript,
    Python,
    Java,
    CSharp,
    Php,
    Rust,
    Cpp,
    Go,  // NEW in v2
    /// Applies to all languages.
    All,
}
```

### 3.6 Constraint Scope (Upgraded)

```rust
/// Where a constraint applies. Determines which files/functions are checked.
/// v2 adds: packages (monorepo support), modules (language-level modules).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConstraintScope {
    /// Glob patterns for files (e.g., "src/api/**/*.ts").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
    /// Directory patterns.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub directories: Vec<String>,
    /// Function name patterns (glob).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub functions: Vec<String>,
    /// Class name patterns (glob).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub classes: Vec<String>,
    /// Only apply to entry points (API handlers, exported functions).
    #[serde(default)]
    pub entry_points: bool,
    /// Package names for monorepo scoping (NEW in v2).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packages: Vec<String>,
    /// Module name patterns for language-level scoping (NEW in v2).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub modules: Vec<String>,
}

impl ConstraintScope {
    /// Calculate specificity score for conflict resolution.
    /// More specific scopes win over less specific ones.
    pub fn specificity(&self) -> u32 {
        let mut score = 0u32;
        // File-specific is most specific
        if !self.files.is_empty() {
            score += 100;
            // Exact paths (no wildcards) are even more specific
            if self.files.iter().any(|f| !f.contains('*')) {
                score += 50;
            }
        }
        if !self.directories.is_empty() { score += 50; }
        if !self.functions.is_empty() { score += 30; }
        if !self.classes.is_empty() { score += 30; }
        if self.entry_points { score += 20; }
        if !self.packages.is_empty() { score += 40; }
        if !self.modules.is_empty() { score += 25; }
        // Empty scope = project-wide = lowest specificity
        if score == 0 { score = 10; }
        score
    }
}
```

### 3.7 Constraint Confidence (Upgraded with Temporal Tracking)

```rust
/// Statistical confidence with temporal tracking.
/// v2 adds: momentum (strengthening/weakening), history snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintConfidence {
    /// Current confidence score (0.0-1.0).
    pub score: f64,
    /// Number of conforming instances.
    pub conforming_count: u32,
    /// Number of violating instances.
    pub violating_count: u32,
    /// Last verification timestamp.
    pub last_verified: Option<DateTime<Utc>>,
    /// Momentum: positive = strengthening, negative = weakening (NEW in v2).
    /// Calculated as: (current_ratio - previous_ratio) / time_delta_days.
    pub momentum: f64,
    /// Trend direction over last 30 days (NEW in v2).
    pub trend: ConfidenceTrend,
    /// Adjusted confidence after feedback (NEW in v2).
    /// adjusted = score × (1.0 - false_positive_rate)
    pub adjusted_score: f64,
}

/// Confidence trend direction.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceTrend {
    /// Conforming ratio increasing.
    Strengthening,
    /// Conforming ratio stable (±0.01 over 30 days).
    Stable,
    /// Conforming ratio decreasing.
    Weakening,
    /// Not enough data points for trend calculation.
    Unknown,
}

impl ConstraintConfidence {
    /// Calculate confidence from conforming/violating counts.
    pub fn calculate(conforming: u32, violating: u32) -> f64 {
        let total = conforming + violating;
        if total == 0 {
            return 0.0;
        }
        conforming as f64 / total as f64
    }

    /// Update momentum from previous confidence snapshot.
    pub fn update_momentum(&mut self, previous_score: f64, days_elapsed: f64) {
        if days_elapsed > 0.0 {
            self.momentum = (self.score - previous_score) / days_elapsed;
        }
        self.trend = if self.momentum > 0.01 {
            ConfidenceTrend::Strengthening
        } else if self.momentum < -0.01 {
            ConfidenceTrend::Weakening
        } else {
            ConfidenceTrend::Stable
        };
    }
}
```


### 3.8 Constraint Enforcement (Upgraded with Auto-Fix)

```rust
/// How violations are reported and fixed.
/// v2 implements autoFix (was a no-op field in v1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintEnforcement {
    /// Severity level: error (blocks CI), warning (reported), info (informational).
    pub level: EnforcementLevel,
    /// Whether auto-fix is available for this constraint type.
    pub auto_fix: bool,
    /// Human-readable violation message template.
    /// Supports placeholders: {file}, {function}, {class}, {line}.
    pub message: String,
    /// Suggested fix description.
    pub suggestion: Option<String>,
    /// Fix template for auto-remediation (NEW in v2).
    /// Uses tree-sitter edit API for AST manipulation.
    pub fix_template: Option<FixTemplate>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementLevel {
    Info,
    Warning,
    Error,
}

/// Auto-fix template for deterministic remediation (NEW in v2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixTemplate {
    /// Fix strategy.
    pub strategy: FixStrategy,
    /// Template code (language-specific).
    pub template: String,
    /// Whether the fix requires user confirmation.
    pub requires_confirmation: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FixStrategy {
    /// Add missing element (decorator, import, wrapper).
    AddElement,
    /// Rename to match convention.
    Rename,
    /// Wrap in error handler (try/catch).
    WrapInHandler,
    /// Create missing file from template.
    CreateFile,
    /// Remove forbidden element.
    RemoveElement,
}
```

### 3.9 Constraint Violation (Upgraded)

```rust
/// A single constraint violation — produced by the verifier.
/// v2 adds: snippet context, fix suggestion, baseline status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintViolation {
    /// ID of the violated constraint.
    pub constraint_id: String,
    /// Human-readable constraint name.
    pub constraint_name: String,
    /// File where the violation occurred.
    pub file: String,
    /// Line number of the violation.
    pub line: u32,
    /// Column number (NEW in v2 — enables precise IDE diagnostics).
    pub column: Option<u32>,
    /// Violation message (from enforcement.message template, interpolated).
    pub message: String,
    /// Severity level.
    pub severity: EnforcementLevel,
    /// Suggested fix description.
    pub suggestion: Option<String>,
    /// Code snippet around the violation (3 lines context).
    pub snippet: Option<String>,
    /// Whether this violation is in the baseline (NEW in v2).
    /// Baseline violations are not reported as new failures.
    pub is_baseline: bool,
    /// Content hash of the violation context for stable baseline matching.
    pub context_hash: String,
}
```

### 3.10 Verification Result (Upgraded with Baseline Awareness)

```rust
/// Per-file verification output.
/// v2 adds: baseline-aware counts, incremental stats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// File that was verified.
    pub file: String,
    /// All violations found (including baseline).
    pub violations: Vec<ConstraintViolation>,
    /// Number of constraints that passed.
    pub passed: u32,
    /// Number of constraints that failed (new violations only).
    pub failed: u32,
    /// Number of constraints skipped (scope mismatch, missing data source).
    pub skipped: u32,
    /// Number of violations in baseline (not counted as failures) (NEW in v2).
    pub baseline_count: u32,
    /// Number of baseline violations that were fixed (ratchet) (NEW in v2).
    pub fixed_baseline_count: u32,
    /// Constraints evaluated (for incremental stats) (NEW in v2).
    pub constraints_evaluated: u32,
    /// Constraints skipped by incremental optimization (NEW in v2).
    pub constraints_skipped_incremental: u32,
    /// Verification duration in microseconds.
    pub duration_us: u64,
}

/// Aggregate verification result across all files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationSummary {
    /// Per-file results.
    pub results: Vec<VerificationResult>,
    /// Total violations (new only — excludes baseline).
    pub total_violations: u32,
    /// Total baseline violations.
    pub total_baseline: u32,
    /// Total fixed baseline violations (ratchet progress).
    pub total_fixed: u32,
    /// Total constraints evaluated.
    pub total_evaluated: u32,
    /// Total constraints skipped.
    pub total_skipped: u32,
    /// Overall pass/fail.
    pub passed: bool,
    /// Total duration in milliseconds.
    pub duration_ms: u64,
}
```

### 3.11 Constraint Source (Upgraded with Temporal Data)

```rust
/// Tracks provenance — what Drift data produced this constraint.
/// v2 adds: temporal snapshots for momentum calculation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintSource {
    /// What type of Drift data produced this constraint.
    pub source_type: SourceType,
    /// IDs of the source entities (pattern IDs, function IDs, etc.).
    pub source_ids: Vec<String>,
    /// Evidence: conforming and violating locations.
    pub evidence: ConstraintEvidence,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceType {
    /// Mined from approved patterns.
    Pattern,
    /// Mined from call graph relationships.
    CallGraph,
    /// Mined from boundary detection.
    Boundary,
    /// Mined from test topology.
    TestTopology,
    /// Mined from error handling analysis.
    ErrorHandling,
    /// User-defined (from TOML file or CLI).
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintEvidence {
    /// Number of conforming instances.
    pub conforming: u32,
    /// Number of violating instances.
    pub violating: u32,
    /// File paths where the invariant holds.
    pub conforming_locations: Vec<String>,
    /// File paths where the invariant is broken.
    pub violating_locations: Vec<String>,
}
```

### 3.12 Constraint Rationale (NEW in v2)

```rust
/// Why a constraint exists — links to ADRs, explanations, business context.
/// Critical for adoption: developers need to understand WHY (Tricorder finding).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintRationale {
    /// Human-readable explanation of why this constraint exists.
    pub text: String,
    /// Link to Architecture Decision Record (if available).
    pub adr_link: Option<String>,
    /// Business context (e.g., "OWASP A01 compliance requirement").
    pub business_context: Option<String>,
    /// Examples of correct usage.
    pub examples: Vec<String>,
}
```

---

## 4. Module Structure

```
crates/drift-core/src/constraints/
├── mod.rs                  # Public API re-exports
├── types.rs                # All types from §3 (Constraint, InvariantType, etc.)
├── extraction/
│   ├── mod.rs              # Extraction pipeline re-exports
│   ├── invariant_detector.rs   # §5 — Mines invariants from 5 data sources
│   ├── constraint_synthesizer.rs # §6 — Converts invariants to Constraints
│   └── mining_strategies/
│       ├── mod.rs          # Strategy trait + registry
│       ├── pattern_mining.rs    # Mine from approved patterns
│       ├── call_graph_mining.rs # Mine from call graph (auth-before-data)
│       ├── boundary_mining.rs   # Mine from boundary detection
│       ├── test_mining.rs       # Mine from test topology
│       ├── error_mining.rs      # Mine from error handling
│       └── negative_mining.rs   # Mine negative invariants (NEW in v2)
├── store/
│   ├── mod.rs              # Store re-exports
│   ├── constraint_store.rs # §7 — SQLite CRUD, lifecycle, querying
│   ├── scope_index.rs      # §7.4 — Fast file→constraint lookup
│   ├── baseline_store.rs   # §10 — Baseline management (FreezingArchRule)
│   └── feedback_store.rs   # §11 — Developer feedback persistence
├── verification/
│   ├── mod.rs              # Verification re-exports
│   ├── constraint_verifier.rs  # §8 — AST-based verification engine
│   ├── predicate_evaluator.rs  # §8.3 — Per-invariant-type evaluation
│   ├── change_detector.rs      # §8.2 — Change-aware verification
│   └── auto_fixer.rs           # §8.5 — Auto-fix implementation (P2)
├── templates/
│   ├── mod.rs              # Template engine
│   ├── template_registry.rs    # §9.3 — Built-in + custom template loading
│   └── builtin/            # 10+ built-in TOML templates
│       ├── layer_separation.toml
│       ├── naming_convention.toml
│       ├── auth_before_access.toml
│       ├── test_coverage.toml
│       ├── error_handling.toml
│       ├── no_direct_db.toml
│       ├── input_validation.toml
│       ├── logging_required.toml
│       ├── no_circular_deps.toml
│       └── api_response_format.toml
├── conflict/
│   ├── mod.rs              # Conflict detection re-exports
│   ├── conflict_detector.rs    # §6.4 — Pairwise comparison, cycle detection
│   └── specificity.rs         # §6.4 — Specificity-based resolution
└── toml_parser.rs          # §9 — TOML constraint file parser
```

### Public API (mod.rs)

```rust
//! Drift Constraint System — architectural invariant detection, verification, and enforcement.
//!
//! Pipeline: InvariantDetector → ConstraintSynthesizer → ConstraintStore → ConstraintVerifier
//!
//! 12 invariant types, 10 categories, baseline management, developer feedback,
//! AST-based verification, declarative TOML format.

pub mod types;
pub mod extraction;
pub mod store;
pub mod verification;
pub mod templates;
pub mod conflict;
pub mod toml_parser;

// Re-export primary types for convenience.
pub use types::*;
pub use store::constraint_store::ConstraintStore;
pub use verification::constraint_verifier::ConstraintVerifier;
pub use extraction::invariant_detector::InvariantDetector;
pub use extraction::constraint_synthesizer::ConstraintSynthesizer;
pub use templates::template_registry::TemplateRegistry;
pub use conflict::conflict_detector::ConflictDetector;
```


---

## 5. Invariant Detector (Extraction Phase 1)

The semantic analysis engine that mines architectural invariants from Drift's existing
data. This is the "learning" component — it discovers what rules the codebase follows.

### 5.1 Architecture

```rust
use crate::constraints::types::*;

/// Configuration for invariant detection.
pub struct InvariantDetectorConfig {
    /// Minimum confidence threshold for detected invariants.
    pub min_confidence: f64,
    /// Minimum conforming instances to consider an invariant.
    pub min_conforming: u32,
    /// Minimum files in scope for negative invariant mining.
    pub min_files_for_negative: u32,
    /// Whether to enable temporal analysis (momentum scoring).
    pub enable_temporal: bool,
    /// Whether to enable negative invariant mining.
    pub enable_negative_mining: bool,
    /// Whether to enable cross-language invariant detection.
    pub enable_cross_language: bool,
}

impl Default for InvariantDetectorConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.7,
            min_conforming: 3,
            min_files_for_negative: 10,
            enable_temporal: true,
            enable_negative_mining: true,
            enable_cross_language: false, // P2 — disabled by default
        }
    }
}

/// A detected invariant — output of the mining phase, input to synthesis.
pub struct DetectedInvariant {
    /// The constraint (without generated ID or metadata).
    pub constraint: PartialConstraint,
    /// Evidence supporting this invariant.
    pub evidence: ConstraintEvidence,
    /// Violations found during detection.
    pub violations: Vec<ViolationDetail>,
}

/// Partial constraint — fields that mining can determine.
/// ID, metadata, and status are added by the synthesizer.
pub struct PartialConstraint {
    pub name: String,
    pub description: String,
    pub category: ConstraintCategory,
    pub invariant_type: InvariantType,
    pub predicate: Predicate,
    pub scope: ConstraintScope,
    pub language: ConstraintLanguage,
    pub source_type: SourceType,
    pub source_ids: Vec<String>,
}
```

### 5.2 Detection Algorithm

```
Input: PatternStore, CallGraphDb, BoundaryStore, TestTopologyDb, ErrorHandlingDb
Output: Vec<DetectedInvariant>

For each mining strategy (registered in priority order):
  1. Query the data source for high-confidence, approved data
  2. Identify recurring invariants (>= min_conforming instances)
  3. Check for violations (instances that break the invariant)
  4. Calculate confidence: conforming / (conforming + violating)
  5. Filter by min_confidence threshold
  6. Produce DetectedInvariant with evidence

If enable_negative_mining:
  7. Scan for patterns with 0 violations across all files in scope
  8. Require min_files_for_negative files to avoid false positives
  9. Produce must_not_have invariants for consistently avoided patterns

If enable_temporal:
  10. Load previous confidence snapshots from constraint_history
  11. Calculate momentum for each invariant
  12. Flag weakening invariants for review

Merge all invariants from all strategies
Sort by confidence (descending)
Return
```

### 5.3 Mining Strategy Trait

```rust
/// Trait for pluggable invariant mining strategies.
/// Each strategy mines from a specific data source.
pub trait MiningStrategy: Send + Sync {
    /// Human-readable name of this strategy.
    fn name(&self) -> &'static str;

    /// The source type this strategy mines from.
    fn source_type(&self) -> SourceType;

    /// Mine invariants from the data source.
    /// Returns detected invariants sorted by confidence (descending).
    fn mine(
        &self,
        db: &DatabaseManager,
        config: &InvariantDetectorConfig,
    ) -> DriftResult<Vec<DetectedInvariant>>;
}
```

### 5.4 Mining Strategies — Per Data Source

| Strategy | Source | Categories Produced | Invariant Types |
|----------|--------|-------------------|-----------------|
| PatternMining | Approved patterns (confidence > 0.7) | api, auth, data, error, test, security, structural | must_have, must_not_have, naming |
| CallGraphMining | Entry points + call relationships | auth, security, data | must_precede, must_follow, must_propagate |
| BoundaryMining | Data access points + sensitive fields | data, security | must_not_have (direct DB access), data_flow |
| TestMining | Test-to-source mappings | test | must_have (test exists), cardinality (min coverage) |
| ErrorMining | Error boundaries + propagation chains | error | must_wrap (try/catch), must_propagate |
| NegativeMining | All files in scope (absence detection) | all | must_not_have (consistently avoided patterns) |

**Pattern Mining Detail**:
```
For each approved pattern with confidence > threshold:
  Group by category
  For each group:
    Identify recurring properties:
      - Decorators present on all functions in scope → must_have(decorator)
      - Return type consistent across scope → naming(return_type_pattern)
      - Error handling present on all async functions → must_wrap(try/catch)
    Calculate conforming/violating ratio
    Produce invariant if ratio > min_confidence
```

**Call Graph Mining Detail**:
```
For each entry point (API handler, exported function):
  Walk call graph forward (BFS, max depth 5):
    If auth check found before data access → conforming
    If data access found without prior auth check → violating
  Calculate ratio
  If ratio > min_confidence:
    Produce must_precede(auth_check, data_access) invariant
```

### 5.5 Temporal Analysis (NEW in v2)

```rust
/// Calculate momentum for a constraint based on historical snapshots.
/// Positive momentum = pattern is strengthening (more conforming over time).
/// Negative momentum = pattern is weakening (more violating over time).
pub fn calculate_momentum(
    current: &ConstraintConfidence,
    history: &[ConfidenceSnapshot],
    window_days: u32,
) -> f64 {
    if history.is_empty() {
        return 0.0;
    }

    // Find snapshot closest to `window_days` ago.
    let cutoff = Utc::now() - chrono::Duration::days(window_days as i64);
    let previous = history
        .iter()
        .filter(|s| s.timestamp >= cutoff)
        .min_by_key(|s| (s.timestamp - cutoff).num_seconds().unsigned_abs());

    match previous {
        Some(prev) => {
            let days_elapsed = (Utc::now() - prev.timestamp).num_days() as f64;
            if days_elapsed > 0.0 {
                (current.score - prev.score) / days_elapsed
            } else {
                0.0
            }
        }
        None => 0.0,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceSnapshot {
    pub score: f64,
    pub conforming_count: u32,
    pub violating_count: u32,
    pub timestamp: DateTime<Utc>,
}
```

### 5.6 Negative Invariant Mining (NEW in v2)

Detects patterns that are consistently AVOIDED — things the codebase never does.
These become `must_not_have` constraints.

```
Algorithm:
  For each file scope (directory, package):
    Collect all import patterns across all files in scope
    Identify imports that appear in 0 files within the scope
      but exist in other scopes (i.e., the import is available but never used here)
    If the scope has >= min_files_for_negative files:
      Produce must_not_have(import_pattern) invariant
      Confidence = 1.0 (100% avoidance)

  Example output:
    "No file in src/services/ imports from src/controllers/"
    → must_not_have, category=structural, confidence=1.0, 47 files in scope
```

### 5.7 Cross-Language Invariant Detection (NEW in v2, P2)

```
Algorithm:
  Group detected invariants by (category, invariant_type, predicate_normalized)
  For each group:
    If invariants exist for 2+ languages:
      Merge into a single cross-language invariant
      Set language = All
      Combine evidence from all languages
      Confidence = min(per_language_confidences)

  Example:
    TS: "All API handlers have error handling" (confidence 0.92)
    Python: "All API handlers have error handling" (confidence 0.88)
    → Cross-language: "All API handlers have error handling" (confidence 0.88, language=All)
```

---

## 6. Constraint Synthesizer (Extraction Phase 2)

Converts detected invariants into full Constraint objects. Handles ID generation,
deduplication, merging, conflict detection, and comparison with existing constraints.

### 6.1 Synthesis Pipeline

```
Input: Vec<DetectedInvariant> from InvariantDetector
       Vec<Constraint> from ConstraintStore (existing)
       Vec<Constraint> from TOML parser (user-defined)

Pipeline:
  1. Convert each DetectedInvariant → Constraint (generate ID, add metadata)
  2. Expand constraint templates (if template_id is set)
  3. Merge similar constraints (Jaccard similarity > 0.8)
  4. Detect conflicts (§6.4)
  5. Diff against existing constraints in store:
     - Same hash → update (refresh confidence, merge evidence)
     - New hash → add as 'discovered'
     - Missing hash → flag for review (not auto-deleted)
  6. Apply auto-approval (confidence > auto_approve_threshold)
  7. Merge with user-defined constraints (TOML takes precedence)
  8. Return SynthesisResult with stats

Output: SynthesisResult {
    new_constraints: Vec<Constraint>,
    updated_constraints: Vec<Constraint>,
    removed_constraints: Vec<String>,  // IDs flagged for review
    conflicts: Vec<ConstraintConflict>,
    stats: SynthesisStats,
}
```

### 6.2 ID Generation (Deterministic)

```rust
use sha2::{Sha256, Digest};

/// Generate a deterministic constraint ID from its defining properties.
/// Same constraint always gets the same ID, enabling deduplication across runs.
pub fn generate_constraint_id(
    category: &ConstraintCategory,
    invariant_type: &InvariantType,
    predicate: &Predicate,
    scope: &ConstraintScope,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_string(category).unwrap_or_default());
    hasher.update(serde_json::to_string(invariant_type).unwrap_or_default());
    hasher.update(serde_json::to_string(predicate).unwrap_or_default());
    hasher.update(serde_json::to_string(scope).unwrap_or_default());
    let hash = hasher.finalize();
    format!("cst_{}", hex::encode(&hash[..12])) // 24-char hex prefix
}
```

### 6.3 Synthesis Configuration

```rust
pub struct SynthesisConfig {
    /// Auto-approve constraints above this confidence threshold.
    /// Default: 0.95 (only very high-confidence constraints auto-approved).
    pub auto_approve_threshold: f64,
    /// Merge similar constraints above this similarity threshold.
    /// Default: 0.8 (Jaccard similarity on category + type + predicate + scope).
    pub similarity_threshold: f64,
    /// Whether to merge similar constraints.
    pub merge_similar: bool,
    /// Whether to detect and report conflicts.
    pub detect_conflicts: bool,
    /// Categories to process (None = all).
    pub categories: Option<Vec<ConstraintCategory>>,
}

impl Default for SynthesisConfig {
    fn default() -> Self {
        Self {
            auto_approve_threshold: 0.95,
            similarity_threshold: 0.8,
            merge_similar: true,
            detect_conflicts: true,
            categories: None,
        }
    }
}
```

### 6.4 Conflict Detection & Resolution (NEW in v2)

```rust
/// A detected conflict between two constraints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintConflict {
    /// First constraint in the conflict.
    pub constraint_a: String, // ID
    /// Second constraint in the conflict.
    pub constraint_b: String, // ID
    /// Type of conflict.
    pub conflict_type: ConflictType,
    /// Suggested resolution.
    pub resolution: ConflictResolution,
    /// Which constraint wins (based on specificity).
    pub winner: Option<String>, // ID
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConflictType {
    /// Opposite invariant types for overlapping scopes
    /// (must_have vs must_not_have for same property).
    Contradiction,
    /// Ordering constraints form a cycle
    /// (A must_precede B, B must_precede A).
    OrderingCycle,
    /// Overlapping scopes with different enforcement levels.
    EnforcementMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictResolution {
    /// Resolution strategy applied.
    pub strategy: ResolutionStrategy,
    /// Explanation of why this resolution was chosen.
    pub explanation: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionStrategy {
    /// Higher specificity wins (scope narrowness + status + confidence).
    SpecificityWins,
    /// Higher category priority wins (security > naming).
    CategoryPriorityWins,
    /// User must resolve manually.
    ManualResolution,
}
```

**Conflict Detection Algorithm**:
```
1. Pairwise comparison of constraints with overlapping scopes:
   For each pair (A, B) where scope_overlaps(A.scope, B.scope):
     If A.invariant_type is opposite of B.invariant_type:
       AND A.predicate targets same property as B.predicate:
         → Contradiction conflict
     If A.enforcement.level != B.enforcement.level:
       → EnforcementMismatch conflict

2. Ordering cycle detection (Tarjan's SCC):
   Build directed graph: constraint → constraint for must_precede/must_follow
   Run Tarjan's SCC algorithm
   Any SCC with size > 1 → OrderingCycle conflict

3. Resolution:
   For each conflict:
     Calculate specificity(A) and specificity(B):
       specificity = scope.specificity() + status_score + (confidence × 10)
       status_score: custom=30, approved=20, discovered=10
     If specificity(A) != specificity(B):
       → SpecificityWins (higher specificity)
     Else if category_priority(A) != category_priority(B):
       → CategoryPriorityWins (higher priority)
     Else:
       → ManualResolution (flag for user)
```

**Scope Overlap Detection**:
```rust
/// Check if two scopes overlap (any file could match both).
pub fn scopes_overlap(a: &ConstraintScope, b: &ConstraintScope) -> bool {
    // If either scope is empty (project-wide), they overlap.
    if a.is_project_wide() || b.is_project_wide() {
        return true;
    }
    // Check file glob overlap.
    for pattern_a in &a.files {
        for pattern_b in &b.files {
            if globs_overlap(pattern_a, pattern_b) {
                return true;
            }
        }
    }
    // Check directory overlap.
    for dir_a in &a.directories {
        for dir_b in &b.directories {
            if dir_a.starts_with(dir_b) || dir_b.starts_with(dir_a) {
                return true;
            }
        }
    }
    false
}
```


---

## 7. Constraint Store (SQLite Persistence)

Replaces v1's JSON file-based storage with SQLite tables in drift.db.
Provides ACID transactions, concurrent read access (WAL mode), efficient indexing,
versioning, and baseline management.

### 7.1 Schema

```sql
-- Core constraint table (replaces .drift/constraints/discovered/*.json)
CREATE TABLE constraints (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL,           -- ConstraintCategory enum value
    invariant_type TEXT NOT NULL,     -- InvariantType enum value
    predicate_json TEXT NOT NULL,     -- Serialized Predicate
    scope_json TEXT NOT NULL,         -- Serialized ConstraintScope
    confidence REAL NOT NULL DEFAULT 0.0,
    adjusted_confidence REAL NOT NULL DEFAULT 0.0,
    momentum REAL NOT NULL DEFAULT 0.0,
    trend TEXT NOT NULL DEFAULT 'unknown',
    conforming_count INTEGER NOT NULL DEFAULT 0,
    violating_count INTEGER NOT NULL DEFAULT 0,
    enforcement_level TEXT NOT NULL DEFAULT 'warning',
    auto_fix INTEGER NOT NULL DEFAULT 0,
    message_template TEXT NOT NULL DEFAULT '',
    suggestion TEXT,
    fix_template_json TEXT,
    status TEXT NOT NULL DEFAULT 'discovered',
    language TEXT NOT NULL DEFAULT 'all',
    source_type TEXT NOT NULL,
    source_ids_json TEXT,
    evidence_json TEXT,
    rationale_json TEXT,
    template_id TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_verified TEXT,
    approved_by TEXT,
    approved_at TEXT,
    superseded_by TEXT              -- ID of replacement constraint (for superseded status)
) STRICT;

-- Indexes for common query patterns
CREATE INDEX idx_constraints_category ON constraints(category);
CREATE INDEX idx_constraints_status ON constraints(status);
CREATE INDEX idx_constraints_language ON constraints(language);
CREATE INDEX idx_constraints_confidence ON constraints(confidence DESC);
CREATE INDEX idx_constraints_enforcement ON constraints(enforcement_level);
CREATE INDEX idx_constraints_invariant_type ON constraints(invariant_type);
CREATE INDEX idx_constraints_source_type ON constraints(source_type);
CREATE INDEX idx_constraints_updated ON constraints(updated_at DESC);
```

### 7.2 Scope Index (Fast File→Constraint Lookup)

```sql
-- Scope index for O(1) file-to-constraint lookup.
-- Replaces v1's O(N×S×G) linear scan.
CREATE TABLE constraint_scope_index (
    constraint_id TEXT NOT NULL REFERENCES constraints(id) ON DELETE CASCADE,
    scope_pattern TEXT NOT NULL,
    scope_type TEXT NOT NULL,       -- 'file', 'directory', 'function', 'class', 'package', 'module'
    language TEXT NOT NULL DEFAULT 'all',
    PRIMARY KEY(constraint_id, scope_pattern, scope_type)
) STRICT;

CREATE INDEX idx_scope_pattern ON constraint_scope_index(scope_pattern);
CREATE INDEX idx_scope_type ON constraint_scope_index(scope_type);
CREATE INDEX idx_scope_language ON constraint_scope_index(language);
```

**Lookup Algorithm**:
```rust
/// Get all constraints applicable to a file path.
/// Uses scope index for O(1) lookup instead of v1's O(N×S) scan.
pub fn get_constraints_for_file(
    conn: &Connection,
    file_path: &str,
    file_language: ConstraintLanguage,
) -> DriftResult<Vec<Constraint>> {
    // Query scope index for matching patterns.
    // Uses GLOB matching in SQLite for file patterns.
    let sql = r#"
        SELECT DISTINCT c.*
        FROM constraints c
        JOIN constraint_scope_index si ON c.id = si.constraint_id
        WHERE c.status IN ('approved', 'custom')
          AND (si.language = 'all' OR si.language = ?1)
          AND (
            (si.scope_type = 'file' AND ?2 GLOB si.scope_pattern)
            OR (si.scope_type = 'directory' AND ?2 LIKE si.scope_pattern || '%')
            OR (si.scope_type = 'package' AND ?3 = si.scope_pattern)
          )
        ORDER BY c.confidence DESC
    "#;
    // Execute and deserialize...
}
```

### 7.3 CRUD Operations

| Operation | v1 Complexity | v2 Complexity | Notes |
|-----------|--------------|---------------|-------|
| add(constraint) | O(1) amortized (file append) | O(1) (INSERT) | Atomic with scope index update |
| get(id) | O(N) linear scan | O(1) (PRIMARY KEY) | Direct lookup |
| update(id, updates) | O(N) find + O(1) update | O(1) (UPDATE by PK) | Version incremented, history recorded |
| delete(id) | O(N) find + O(N) rebuild | O(1) (DELETE by PK) | CASCADE deletes scope index entries |
| approve(id) | O(N) find | O(1) (UPDATE by PK) | Baseline snapshot triggered |
| ignore(id, reason) | O(N) find | O(1) (UPDATE by PK) | Reason stored in history |
| getAll() | O(N) (load all files) | O(N) (SELECT *) | Paginated in v2 |
| getByCategory(cat) | O(1) with index.json | O(1) (indexed) | Same performance |
| getForFile(path) | O(N×S×G) | O(1) via scope index | Major improvement |
| query(options) | O(N) filter + O(N log N) sort | O(log N) (indexed SQL) | Keyset pagination |

### 7.4 Scope Index Maintenance

```rust
/// Rebuild scope index for a constraint.
/// Called on constraint create/update.
fn rebuild_scope_index(conn: &Connection, constraint: &Constraint) -> DriftResult<()> {
    // Delete existing entries.
    conn.execute(
        "DELETE FROM constraint_scope_index WHERE constraint_id = ?1",
        [&constraint.id],
    )?;

    // Insert file patterns.
    for pattern in &constraint.scope.files {
        conn.execute(
            "INSERT INTO constraint_scope_index (constraint_id, scope_pattern, scope_type, language)
             VALUES (?1, ?2, 'file', ?3)",
            params![constraint.id, pattern, constraint.language.as_str()],
        )?;
    }

    // Insert directory patterns.
    for dir in &constraint.scope.directories {
        conn.execute(
            "INSERT INTO constraint_scope_index (constraint_id, scope_pattern, scope_type, language)
             VALUES (?1, ?2, 'directory', ?3)",
            params![constraint.id, dir, constraint.language.as_str()],
        )?;
    }

    // Insert package patterns.
    for pkg in &constraint.scope.packages {
        conn.execute(
            "INSERT INTO constraint_scope_index (constraint_id, scope_pattern, scope_type, language)
             VALUES (?1, ?2, 'package', ?3)",
            params![constraint.id, pkg, constraint.language.as_str()],
        )?;
    }

    Ok(())
}
```

### 7.5 Lifecycle Transitions (Upgraded)

```rust
/// Approve a constraint — transitions to 'approved' status.
/// Triggers baseline snapshot for existing violations.
pub fn approve_constraint(
    conn: &Connection,
    id: &str,
    approved_by: Option<&str>,
    event_handler: &dyn DriftEventHandler,
) -> DriftResult<()> {
    let now = Utc::now().to_rfc3339();

    // Update status.
    conn.execute(
        "UPDATE constraints SET status = 'approved', approved_by = ?1, approved_at = ?2,
         updated_at = ?2 WHERE id = ?3",
        params![approved_by, now, id],
    )?;

    // Record in history.
    conn.execute(
        "INSERT INTO constraint_history (constraint_id, version, change_type, changed_at, changed_by)
         SELECT id, version, 'approved', ?1, ?2 FROM constraints WHERE id = ?3",
        params![now, approved_by, id],
    )?;

    // Snapshot current violations as baseline (FreezingArchRule pattern).
    snapshot_baseline(conn, id)?;

    // Emit event (D5).
    event_handler.on_constraint_approved(id);

    Ok(())
}

/// Bulk approve constraints above a confidence threshold.
/// NEW in v2 — v1 only supported one-at-a-time.
pub fn bulk_approve(
    conn: &Connection,
    min_confidence: f64,
    categories: Option<&[ConstraintCategory]>,
    event_handler: &dyn DriftEventHandler,
) -> DriftResult<u32> {
    let mut count = 0u32;
    let constraints = query_discoverable(conn, min_confidence, categories)?;
    for c in &constraints {
        approve_constraint(conn, &c.id, Some("auto-bulk"), event_handler)?;
        count += 1;
    }
    Ok(count)
}
```

### 7.6 Query with Keyset Pagination

```rust
/// Query constraints with filters and keyset pagination.
/// Consistent with 02-STORAGE-V2-PREP.md §10 pagination pattern.
pub fn query_constraints(
    conn: &Connection,
    filter: &ConstraintFilter,
    cursor: Option<&(String, String)>, // (sort_value, id)
    limit: usize,
) -> DriftResult<PaginatedConstraints> {
    let mut sql = String::from("SELECT * FROM constraints WHERE 1=1");
    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

    if let Some(category) = &filter.category {
        sql.push_str(" AND category = ?");
        params.push(Box::new(category.as_str().to_string()));
    }
    if let Some(status) = &filter.status {
        sql.push_str(" AND status = ?");
        params.push(Box::new(status.as_str().to_string()));
    }
    if let Some(min_confidence) = filter.min_confidence {
        sql.push_str(" AND confidence >= ?");
        params.push(Box::new(min_confidence));
    }
    if let Some(language) = &filter.language {
        sql.push_str(" AND (language = ? OR language = 'all')");
        params.push(Box::new(language.as_str().to_string()));
    }
    if let Some(invariant_type) = &filter.invariant_type {
        sql.push_str(" AND invariant_type = ?");
        params.push(Box::new(invariant_type.as_str().to_string()));
    }

    // Keyset pagination.
    if let Some((sort_val, last_id)) = cursor {
        sql.push_str(" AND (confidence, id) < (?, ?)");
        params.push(Box::new(sort_val.parse::<f64>().unwrap_or(0.0)));
        params.push(Box::new(last_id.clone()));
    }

    sql.push_str(" ORDER BY confidence DESC, id DESC");
    sql.push_str(&format!(" LIMIT {}", limit + 1)); // +1 to detect has_more

    // Execute and build PaginatedConstraints...
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintFilter {
    pub category: Option<ConstraintCategory>,
    pub status: Option<ConstraintStatus>,
    pub min_confidence: Option<f64>,
    pub language: Option<ConstraintLanguage>,
    pub invariant_type: Option<InvariantType>,
    pub source_type: Option<SourceType>,
    pub search: Option<String>, // FTS on name + description
}
```

### 7.7 Constraint Version History (NEW in v2)

```sql
-- Version history for audit trail and temporal analysis.
-- Every status change, confidence update, and edit is recorded.
CREATE TABLE constraint_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    constraint_id TEXT NOT NULL REFERENCES constraints(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    change_type TEXT NOT NULL,       -- 'created', 'updated', 'approved', 'ignored',
                                    -- 'deprecated', 'superseded', 'confidence_update'
    old_values_json TEXT,            -- Previous field values (for diff)
    new_values_json TEXT,            -- New field values
    changed_at TEXT NOT NULL,
    changed_by TEXT                  -- User or 'system' or 'auto-bulk'
) STRICT;

CREATE INDEX idx_history_constraint ON constraint_history(constraint_id);
CREATE INDEX idx_history_changed_at ON constraint_history(changed_at DESC);
CREATE INDEX idx_history_change_type ON constraint_history(change_type);
```


---

## 8. Constraint Verifier (AST-Based — Replaces v1 Regex)

The enforcement engine that validates code against applicable constraints.
v2 replaces v1's regex-based extraction with Rust ParseResult AST access,
enabling accurate verification of all 12 invariant types.

### 8.1 Verification Architecture

```rust
/// The main verification engine.
/// Accepts ParseResult (from Rust parser) instead of raw source code.
pub struct ConstraintVerifier {
    /// Database handle for scope index lookups and baseline checks.
    db: Arc<DatabaseManager>,
    /// Call graph handle for ordering constraint verification.
    call_graph: Option<Arc<CallGraphDb>>,
    /// Taint analysis handle for data_flow constraint verification.
    taint_engine: Option<Arc<TaintEngine>>,
    /// Baseline store for FreezingArchRule filtering.
    baseline_store: BaselineStore,
    /// Feedback store for false-positive rate calculation.
    feedback_store: FeedbackStore,
}

impl ConstraintVerifier {
    /// Verify a file against all applicable constraints.
    /// This is the primary verification entry point.
    pub fn verify_file(
        &self,
        file_path: &str,
        parse_result: &ParseResult,
        language: ConstraintLanguage,
    ) -> DriftResult<VerificationResult> {
        let start = std::time::Instant::now();

        // 1. Get applicable constraints via scope index (O(1) lookup).
        let constraints = self.db.get_constraints_for_file(file_path, language)?;

        let mut violations = Vec::new();
        let mut passed = 0u32;
        let mut failed = 0u32;
        let mut skipped = 0u32;
        let mut baseline_count = 0u32;

        // 2. Evaluate each constraint.
        for constraint in &constraints {
            match self.evaluate_constraint(constraint, file_path, parse_result) {
                Ok(result) => match result {
                    PredicateResult::Pass => passed += 1,
                    PredicateResult::Fail(violation_details) => {
                        for detail in violation_details {
                            let violation = self.build_violation(constraint, file_path, &detail);
                            // Check baseline.
                            if self.baseline_store.is_baseline(&violation)? {
                                violations.push(ConstraintViolation {
                                    is_baseline: true,
                                    ..violation
                                });
                                baseline_count += 1;
                            } else {
                                violations.push(violation);
                                failed += 1;
                            }
                        }
                    }
                    PredicateResult::Skip(reason) => {
                        skipped += 1;
                        tracing::debug!(
                            constraint_id = constraint.id,
                            reason = %reason,
                            "Constraint skipped"
                        );
                    }
                },
                Err(e) => {
                    skipped += 1;
                    tracing::warn!(
                        constraint_id = constraint.id,
                        error = %e,
                        "Constraint evaluation error"
                    );
                }
            }
        }

        Ok(VerificationResult {
            file: file_path.to_string(),
            violations,
            passed,
            failed,
            skipped,
            baseline_count,
            fixed_baseline_count: 0, // Calculated in batch verification
            constraints_evaluated: passed + failed,
            constraints_skipped_incremental: 0,
            duration_us: start.elapsed().as_micros() as u64,
        })
    }

    /// Change-aware verification — only checks changed lines.
    /// v2 adds constraint-level incrementality on top of v1's line-level filtering.
    pub fn verify_change(
        &self,
        file_path: &str,
        old_parse_result: Option<&ParseResult>,
        new_parse_result: &ParseResult,
        changed_lines: &[u32],
        language: ConstraintLanguage,
    ) -> DriftResult<VerificationResult> {
        let mut result = self.verify_file(file_path, new_parse_result, language)?;

        // Filter violations to only those on changed lines.
        result.violations.retain(|v| {
            v.is_baseline || changed_lines.contains(&v.line)
        });

        // Recalculate failed count.
        result.failed = result.violations.iter()
            .filter(|v| !v.is_baseline)
            .count() as u32;

        Ok(result)
    }
}
```

### 8.2 Predicate Evaluation Matrix

The core of the verifier — maps each invariant type to a specific evaluation strategy.

```rust
/// Result of evaluating a single constraint predicate.
pub enum PredicateResult {
    /// Constraint satisfied.
    Pass,
    /// Constraint violated — includes violation details.
    Fail(Vec<ViolationDetail>),
    /// Constraint skipped — missing data source or not applicable.
    Skip(String),
}

/// Evaluate a constraint against a ParseResult.
fn evaluate_constraint(
    &self,
    constraint: &Constraint,
    file_path: &str,
    parse_result: &ParseResult,
) -> DriftResult<PredicateResult> {
    match constraint.invariant.invariant_type {
        // AST-based predicates (use ParseResult directly).
        InvariantType::MustHave => {
            self.eval_must_have(&constraint.invariant.predicate, parse_result)
        }
        InvariantType::MustNotHave => {
            self.eval_must_not_have(&constraint.invariant.predicate, parse_result)
        }
        InvariantType::MustWrap => {
            self.eval_must_wrap(&constraint.invariant.predicate, parse_result)
        }
        InvariantType::Cardinality => {
            self.eval_cardinality(&constraint.invariant.predicate, parse_result)
        }
        InvariantType::Naming => {
            self.eval_naming(&constraint.invariant.predicate, parse_result)
        }

        // Call graph predicates (require call graph access).
        InvariantType::MustPrecede => {
            match &self.call_graph {
                Some(cg) => self.eval_must_precede(&constraint.invariant.predicate, cg, file_path),
                None => Ok(PredicateResult::Skip("Call graph not available".into())),
            }
        }
        InvariantType::MustFollow => {
            match &self.call_graph {
                Some(cg) => self.eval_must_follow(&constraint.invariant.predicate, cg, file_path),
                None => Ok(PredicateResult::Skip("Call graph not available".into())),
            }
        }
        InvariantType::MustPropagate => {
            match &self.call_graph {
                Some(cg) => self.eval_must_propagate(&constraint.invariant.predicate, cg, file_path),
                None => Ok(PredicateResult::Skip("Call graph not available".into())),
            }
        }

        // Taint analysis predicates (require taint engine).
        InvariantType::DataFlow => {
            match &self.taint_engine {
                Some(te) => self.eval_data_flow(&constraint.invariant.predicate, te, file_path),
                None => Ok(PredicateResult::Skip("Taint analysis not available".into())),
            }
        }

        // Filesystem predicates (use scanner data).
        InvariantType::MustColocate => {
            self.eval_must_colocate(&constraint.invariant.predicate, file_path)
        }
        InvariantType::MustSeparate => {
            self.eval_must_separate(&constraint.invariant.predicate, file_path)
        }
        InvariantType::Structure => {
            self.eval_structure(&constraint.invariant.predicate, file_path)
        }
    }
}
```

### 8.3 Predicate Evaluation — Per Invariant Type

**MustHave (AST-based)**:
```rust
/// "X must have Y" — check that required elements are present.
/// Uses ParseResult.functions, .classes, .imports, .decorators.
fn eval_must_have(
    &self,
    predicate: &Predicate,
    parse_result: &ParseResult,
) -> DriftResult<PredicateResult> {
    let mut violations = Vec::new();

    // Check required decorators on functions.
    if let Some(required_decorators) = &predicate.decorators {
        for func in &parse_result.functions {
            if predicate.matches_function_scope(func) {
                for required in required_decorators {
                    if !func.decorators.iter().any(|d| glob_match(required, &d.name)) {
                        violations.push(ViolationDetail {
                            line: func.line,
                            column: Some(func.column),
                            message: format!(
                                "Function '{}' must have decorator matching '{}'",
                                func.name, required
                            ),
                        });
                    }
                }
            }
        }
    }

    // Check required imports.
    if let Some(required_imports) = &predicate.imports {
        for required in required_imports {
            if !parse_result.imports.iter().any(|i| glob_match(&required.pattern, &i.source)) {
                violations.push(ViolationDetail {
                    line: 1, // File-level violation
                    column: None,
                    message: format!("File must import from '{}'", required.pattern),
                });
            }
        }
    }

    if violations.is_empty() {
        Ok(PredicateResult::Pass)
    } else {
        Ok(PredicateResult::Fail(violations))
    }
}
```

**MustPrecede (Call Graph — NEW verification in v2)**:
```rust
/// "X must come before Y" — verify ordering via call graph path query.
/// Was UNVERIFIABLE in v1 (no call graph access). Now uses CallGraphDb.
fn eval_must_precede(
    &self,
    predicate: &Predicate,
    call_graph: &CallGraphDb,
    file_path: &str,
) -> DriftResult<PredicateResult> {
    let before_pattern = predicate.before.as_ref()
        .ok_or_else(|| DriftError::InvalidPredicate("must_precede requires 'before' field"))?;
    let after_pattern = predicate.after.as_ref()
        .ok_or_else(|| DriftError::InvalidPredicate("must_precede requires 'after' field"))?;

    // Find all functions in this file matching the "after" pattern.
    let after_functions = call_graph.functions_in_file(file_path)?
        .into_iter()
        .filter(|f| predicate_matches_function(after_pattern, f))
        .collect::<Vec<_>>();

    let mut violations = Vec::new();

    for after_func in &after_functions {
        // Walk callers backward — check if any caller matching "before" pattern
        // appears on the path from entry point to this function.
        let callers = call_graph.get_callers_transitive(&after_func.id, 10)?;
        let has_before = callers.iter().any(|c| predicate_matches_function(before_pattern, c));

        if !has_before {
            violations.push(ViolationDetail {
                line: after_func.line,
                column: Some(after_func.column),
                message: format!(
                    "'{}' must be preceded by a call matching '{}' in the call chain",
                    after_func.name,
                    before_pattern.description()
                ),
            });
        }
    }

    if violations.is_empty() {
        Ok(PredicateResult::Pass)
    } else {
        Ok(PredicateResult::Fail(violations))
    }
}
```

**MustWrap (AST Containment — NEW verification in v2)**:
```rust
/// "X must be wrapped in Y" — verify AST containment.
/// Was UNVERIFIABLE in v1 (no AST structure). Now uses ParseResult AST.
fn eval_must_wrap(
    &self,
    predicate: &Predicate,
    parse_result: &ParseResult,
) -> DriftResult<PredicateResult> {
    let target_pattern = predicate.target.as_ref()
        .ok_or_else(|| DriftError::InvalidPredicate("must_wrap requires 'target' field"))?;
    let wrapper_type = predicate.wrapper.as_ref()
        .ok_or_else(|| DriftError::InvalidPredicate("must_wrap requires 'wrapper' field"))?;

    let mut violations = Vec::new();

    for func in &parse_result.functions {
        if predicate_matches_target(target_pattern, func) {
            // Check if the function body is wrapped in the required wrapper.
            let is_wrapped = match wrapper_type.as_str() {
                "try_catch" | "try/catch" => func.has_try_catch,
                "if_check" | "if-check" => func.has_guard_clause,
                "error_boundary" => func.has_error_boundary,
                _ => false,
            };

            if !is_wrapped {
                violations.push(ViolationDetail {
                    line: func.line,
                    column: Some(func.column),
                    message: format!(
                        "Function '{}' must be wrapped in '{}'",
                        func.name, wrapper_type
                    ),
                });
            }
        }
    }

    if violations.is_empty() {
        Ok(PredicateResult::Pass)
    } else {
        Ok(PredicateResult::Fail(violations))
    }
}
```

### 8.4 Language Support (10 Languages via Tree-Sitter)

| Language | v1 (Regex) | v2 (AST) | Improvement |
|----------|-----------|----------|-------------|
| TypeScript | ✅ | ✅ | Accurate decorator/generic detection |
| JavaScript | ✅ | ✅ | Arrow function, destructuring support |
| Python | ✅ | ✅ | Decorator, async/await, type hint detection |
| Java | ✅ | ✅ | Annotation, generic, interface detection |
| C# | ✅ | ✅ | Attribute, async, LINQ detection |
| PHP | ✅ | ✅ | Attribute (PHP 8+), namespace detection |
| Rust | ✅ | ✅ | Macro, trait, lifetime detection |
| C++ | ✅ | ✅ | Template, namespace, RAII detection |
| Go | ❌ | ✅ (NEW) | Interface, goroutine, defer detection |
| All | ✅ | ✅ | Cross-language constraints |

### 8.5 Auto-Fix Implementation (NEW in v2, P2)

```rust
/// Apply an auto-fix for a constraint violation.
/// Uses tree-sitter edit API for AST manipulation.
/// Returns the modified source code (does NOT write to disk — caller decides).
pub fn apply_fix(
    violation: &ConstraintViolation,
    constraint: &Constraint,
    source: &str,
    parse_result: &ParseResult,
) -> DriftResult<Option<FixResult>> {
    let fix_template = match &constraint.enforcement.fix_template {
        Some(t) => t,
        None => return Ok(None),
    };

    let fixed_source = match fix_template.strategy {
        FixStrategy::AddElement => {
            add_element(source, violation.line, &fix_template.template)?
        }
        FixStrategy::Rename => {
            rename_element(source, violation.line, violation.column, &fix_template.template)?
        }
        FixStrategy::WrapInHandler => {
            wrap_in_handler(source, violation.line, parse_result, &fix_template.template)?
        }
        FixStrategy::CreateFile => {
            // Returns None — file creation is handled by caller.
            return Ok(Some(FixResult::CreateFile {
                path: fix_template.template.clone(),
                template: fix_template.template.clone(),
            }));
        }
        FixStrategy::RemoveElement => {
            remove_element(source, violation.line, &fix_template.template)?
        }
    };

    Ok(Some(FixResult::Modified {
        source: fixed_source,
        requires_confirmation: fix_template.requires_confirmation,
    }))
}

pub enum FixResult {
    Modified {
        source: String,
        requires_confirmation: bool,
    },
    CreateFile {
        path: String,
        template: String,
    },
}
```


---

## 9. Declarative TOML Constraint Format (NEW in v2)

Version-controlled, human-readable constraint definitions. Replaces v1's internal
JSON format with a user-facing TOML format inspired by Semgrep YAML rules (§3.1),
SonarQube Architecture as Code (§1.3), and OPA Constraint Framework (§6.1).

### 9.1 Format Specification

```toml
# drift-constraints.toml — Version-controlled architectural constraints
# Located at project root or in .drift/constraints.toml
# Can be split: include = ["constraints/security.toml", "constraints/api.toml"]

[settings]
# Auto-approve discovered constraints above this confidence threshold.
auto_approve_threshold = 0.95
# Default enforcement level for new constraints.
enforcement_default = "warning"
# Baseline file location (version-controlled).
baseline_file = ".drift/constraint-baselines.json"
# Feedback auto-demotion thresholds.
feedback_demote_threshold = 0.10    # Demote error→warning at 10% FP rate
feedback_review_threshold = 0.25    # Flag for review at 25% FP rate
# Include additional constraint files.
include = []

# ─── User-Defined Constraints ───────────────────────────────────────

[[constraints]]
id = "auth-before-data"
name = "Authentication must precede data access"
category = "security"
type = "must_precede"
language = "all"
enforcement = "error"
description = "All API endpoints must verify authentication before accessing data stores"

[constraints.scope]
files = ["src/api/**/*", "src/controllers/**/*"]
entry_points = true

[constraints.predicate]
before = { decorators = ["@Auth", "@Authenticated", "@RequiresAuth"] }
after = { calls = ["*.repository.*", "*.service.find*", "*.service.get*", "db.*"] }

[constraints.rationale]
text = "Unauthenticated data access is a critical security vulnerability (OWASP A01)"
adr = "docs/adr/003-auth-middleware.md"

# ─── Layer Separation ────────────────────────────────────────────────

[[constraints]]
id = "no-controller-to-repo"
name = "Controllers must not access repositories directly"
category = "structural"
type = "must_not_have"
language = "all"
enforcement = "error"

[constraints.scope]
files = ["src/controllers/**/*"]

[constraints.predicate]
imports = { pattern = "**/repositories/**" }

[constraints.rationale]
text = "Controllers must go through the service layer for data access"

# ─── Naming Convention ───────────────────────────────────────────────

[[constraints]]
id = "service-naming"
name = "Service classes must end with 'Service'"
category = "structural"
type = "naming"
language = "all"
enforcement = "warning"

[constraints.scope]
directories = ["src/services/"]

[constraints.predicate]
classes = { pattern = "*Service" }

# ─── Template Instantiation ─────────────────────────────────────────

[[constraints]]
template = "error-handling"
params.target_patterns = ["async *Handler", "async *Controller"]
params.wrapper = "try_catch"
enforcement = "error"

[[constraints]]
template = "test-coverage"
params.source_dir = "src/"
params.test_dir = "tests/"
params.min_coverage = 0.8
enforcement = "warning"
```

### 9.2 TOML Parser

```rust
use toml::Value;

/// Parse a drift-constraints.toml file into constraint definitions.
pub fn parse_constraint_toml(content: &str) -> DriftResult<ParsedConstraintFile> {
    let doc: TomlConstraintFile = toml::from_str(content)
        .map_err(|e| DriftError::ConstraintParseError(format!("TOML parse error: {e}")))?;

    let mut constraints = Vec::new();
    let mut errors = Vec::new();

    for (idx, def) in doc.constraints.iter().enumerate() {
        match convert_toml_to_constraint(def) {
            Ok(c) => constraints.push(c),
            Err(e) => errors.push(format!("constraints[{}]: {}", idx, e)),
        }
    }

    // Process includes.
    for include_path in &doc.settings.include {
        let included = std::fs::read_to_string(include_path)
            .map_err(|e| DriftError::ConstraintParseError(
                format!("Cannot read include '{}': {}", include_path, e)
            ))?;
        let included_file = parse_constraint_toml(&included)?;
        constraints.extend(included_file.constraints);
        errors.extend(included_file.errors);
    }

    Ok(ParsedConstraintFile {
        settings: doc.settings,
        constraints,
        errors,
    })
}

#[derive(Debug, Deserialize)]
pub struct TomlConstraintFile {
    #[serde(default)]
    pub settings: ConstraintSettings,
    #[serde(default)]
    pub constraints: Vec<TomlConstraintDef>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ConstraintSettings {
    #[serde(default = "default_auto_approve")]
    pub auto_approve_threshold: f64,
    #[serde(default = "default_enforcement")]
    pub enforcement_default: String,
    pub baseline_file: Option<String>,
    #[serde(default)]
    pub feedback_demote_threshold: f64,
    #[serde(default)]
    pub feedback_review_threshold: f64,
    #[serde(default)]
    pub include: Vec<String>,
}

fn default_auto_approve() -> f64 { 0.95 }
fn default_enforcement() -> String { "warning".to_string() }
```

### 9.3 Constraint Templates (10+ Built-In)

Templates are parameterized constraint definitions that reduce boilerplate.

| Template | Category | Invariant Type | Parameters | Description |
|----------|----------|---------------|------------|-------------|
| `layer-separation` | structural | must_not_have | upper_layer, lower_layer | Prevent direct access between layers |
| `naming-convention` | structural | naming | directory, suffix/prefix, target | Enforce naming patterns |
| `auth-before-access` | security | must_precede | auth_decorators, data_patterns | Auth check before data access |
| `test-coverage` | test | must_have | source_dir, test_dir, min_coverage | Minimum test coverage |
| `error-handling` | error | must_wrap | target_patterns, wrapper | Error handler requirement |
| `no-direct-db` | data | must_not_have | controller_dir, db_patterns | No direct DB from controllers |
| `input-validation` | validation | must_precede | validation_patterns, handler_patterns | Validate before process |
| `logging-required` | logging | must_have | target_functions, log_patterns | Logging in critical paths |
| `no-circular-deps` | structural | must_not_have | (auto-detected) | No circular module dependencies |
| `api-response-format` | api | must_have | endpoint_patterns, response_type | Consistent API responses |

**Template Format**:
```toml
# crates/drift-core/src/constraints/templates/builtin/layer_separation.toml
[template]
id = "layer-separation"
name = "{upper_layer} must not access {lower_layer} directly"
category = "structural"
type = "must_not_have"
description = "Enforces layer separation: {upper_layer} cannot import from {lower_layer}"

[template.params]
upper_layer = { type = "string", required = true, description = "Upper layer directory" }
lower_layer = { type = "string", required = true, description = "Lower layer directory" }

[template.scope]
files = ["src/{upper_layer}/**/*"]

[template.predicate]
imports = { pattern = "**/{lower_layer}/**" }

[template.rationale]
text = "Layer separation prevents tight coupling between {upper_layer} and {lower_layer}"
```

**Template Expansion**:
```rust
/// Expand a template with parameters into a full Constraint.
pub fn expand_template(
    template: &ConstraintTemplate,
    params: &HashMap<String, String>,
    enforcement: Option<EnforcementLevel>,
) -> DriftResult<Constraint> {
    // Validate all required params are provided.
    for (name, param_def) in &template.params {
        if param_def.required && !params.contains_key(name) {
            return Err(DriftError::TemplateMissingParam(
                template.id.clone(),
                name.clone(),
            ));
        }
    }

    // Interpolate {param} placeholders in all string fields.
    let name = interpolate(&template.name, params);
    let description = interpolate(&template.description, params);
    let scope = interpolate_scope(&template.scope, params);
    let predicate = interpolate_predicate(&template.predicate, params);
    let rationale = template.rationale.as_ref()
        .map(|r| ConstraintRationale {
            text: interpolate(&r.text, params),
            ..r.clone()
        });

    Ok(Constraint {
        id: generate_constraint_id(&template.category, &template.invariant_type, &predicate, &scope),
        name,
        description,
        category: template.category,
        invariant: ConstraintInvariant {
            invariant_type: template.invariant_type,
            predicate,
        },
        scope,
        confidence: ConstraintConfidence::default_custom(),
        enforcement: ConstraintEnforcement {
            level: enforcement.unwrap_or(EnforcementLevel::Warning),
            ..Default::default()
        },
        status: ConstraintStatus::Custom,
        language: template.language.unwrap_or(ConstraintLanguage::All),
        source: ConstraintSource::manual(),
        rationale,
        template_id: Some(template.id.clone()),
        version: 1,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_verified: None,
        approved_by: None,
        approved_at: None,
    })
}
```

### 9.4 Constraint Inheritance (NEW in v2)

Hierarchical constraint files — child directories inherit parent constraints.

```
project-root/
├── drift-constraints.toml          # Project-level (inherited by all)
├── src/
│   ├── api/
│   │   └── drift-constraints.toml  # API-specific (overrides project)
│   └── services/
│       └── drift-constraints.toml  # Service-specific (overrides project)
```

**Resolution Rules**:
1. Child constraints inherit all parent constraints.
2. Child constraints can override parent constraints (higher specificity wins).
3. Child constraints can add new constraints.
4. Child constraints CANNOT remove parent constraints (only override enforcement level).
5. Specificity: file-level > directory-level > package-level > project-level.

```rust
/// Resolve constraint inheritance by walking up the directory tree.
pub fn resolve_inheritance(
    project_root: &Path,
    file_path: &Path,
) -> DriftResult<Vec<Constraint>> {
    let mut constraint_files = Vec::new();

    // Walk from project root to file's directory, collecting constraint files.
    let relative = file_path.strip_prefix(project_root)
        .map_err(|_| DriftError::PathError)?;

    let mut current = project_root.to_path_buf();
    for component in relative.parent().unwrap_or(Path::new("")).components() {
        current.push(component);
        let toml_path = current.join("drift-constraints.toml");
        if toml_path.exists() {
            constraint_files.push(toml_path);
        }
    }

    // Also check project root.
    let root_toml = project_root.join("drift-constraints.toml");
    if root_toml.exists() && !constraint_files.contains(&root_toml) {
        constraint_files.insert(0, root_toml);
    }

    // Parse all files, merge with specificity resolution.
    let mut all_constraints = Vec::new();
    for (depth, toml_path) in constraint_files.iter().enumerate() {
        let content = std::fs::read_to_string(toml_path)?;
        let parsed = parse_constraint_toml(&content)?;
        for mut constraint in parsed.constraints {
            // Deeper files get higher specificity bonus.
            constraint.scope.depth_bonus = depth as u32 * 10;
            all_constraints.push(constraint);
        }
    }

    // Resolve conflicts — higher specificity wins.
    resolve_conflicts(&mut all_constraints);

    Ok(all_constraints)
}
```


---

## 10. Baseline Management (FreezingArchRule Pattern — NEW in v2)

The single most important feature for enterprise adoption. Enables incremental
constraint adoption on legacy codebases by freezing existing violations.

Inspired by ArchUnit's FreezingArchRule (§8.2 research), validated by SonarQube's
incremental analysis (§8.1), and Google's Tricorder approach (§10.2).

### 10.1 Schema

```sql
-- Violation baselines — frozen violations that are tolerated.
-- When a baseline violation is fixed, it's removed (ratchet effect).
CREATE TABLE constraint_baselines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    constraint_id TEXT NOT NULL REFERENCES constraints(id) ON DELETE CASCADE,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    -- Content hash of surrounding lines for stable matching across line shifts.
    context_hash TEXT NOT NULL,
    -- Original violation message for display.
    message TEXT NOT NULL,
    -- When this baseline entry was created.
    created_at TEXT NOT NULL,
    -- When this violation was fixed (NULL = still in baseline).
    fixed_at TEXT,
    UNIQUE(constraint_id, file, context_hash)
) STRICT;

CREATE INDEX idx_baselines_constraint ON constraint_baselines(constraint_id);
CREATE INDEX idx_baselines_file ON constraint_baselines(file);
CREATE INDEX idx_baselines_fixed ON constraint_baselines(fixed_at);
```

### 10.2 Baseline Flow

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│ Approve           │────▶│ Verify All Files  │────▶│ Snapshot All     │
│ Constraint        │     │ (full scan)       │     │ Violations as    │
│                   │     │                   │     │ Baseline         │
└──────────────────┘     └──────────────────┘     └────────┬─────────┘
                                                           │
┌──────────────────┐     ┌──────────────────┐     ┌────────▼─────────┐
│ Report ONLY       │◀────│ Filter Out        │◀────│ Verify Code      │
│ New Violations    │     │ Baseline Entries   │     │ Change           │
│ (CI passes)       │     │                   │     │                   │
└──────────────────┘     └──────────────────┘     └────────┬─────────┘
                                                           │
                          ┌──────────────────┐     ┌────────▼─────────┐
                          │ Remove Fixed      │◀────│ Detect Fixed     │
                          │ From Baseline     │     │ Violations       │
                          │ (ratchet — can    │     │ (context_hash    │
                          │  never regress)   │     │  no longer found)│
                          └──────────────────┘     └──────────────────┘
```

### 10.3 Baseline Store Implementation

```rust
pub struct BaselineStore {
    db: Arc<DatabaseManager>,
}

impl BaselineStore {
    /// Snapshot all current violations for a constraint as baseline.
    /// Called when a constraint is first approved.
    pub fn snapshot_baseline(
        &self,
        constraint_id: &str,
        violations: &[ConstraintViolation],
    ) -> DriftResult<u32> {
        let conn = self.db.writer()?;
        let now = Utc::now().to_rfc3339();
        let mut count = 0u32;

        for violation in violations {
            conn.execute(
                "INSERT OR IGNORE INTO constraint_baselines
                 (constraint_id, file, line, context_hash, message, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    constraint_id,
                    violation.file,
                    violation.line,
                    violation.context_hash,
                    violation.message,
                    now,
                ],
            )?;
            count += 1;
        }

        Ok(count)
    }

    /// Check if a violation is in the baseline.
    /// Uses context_hash for stable matching (survives line number changes).
    pub fn is_baseline(&self, violation: &ConstraintViolation) -> DriftResult<bool> {
        let conn = self.db.reader()?;
        let count: u32 = conn.query_row(
            "SELECT COUNT(*) FROM constraint_baselines
             WHERE constraint_id = ?1 AND file = ?2 AND context_hash = ?3
             AND fixed_at IS NULL",
            params![violation.constraint_id, violation.file, violation.context_hash],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Update baseline — remove fixed violations (ratchet effect).
    /// Called after verification to detect violations that no longer exist.
    pub fn ratchet(
        &self,
        constraint_id: &str,
        current_violations: &[ConstraintViolation],
    ) -> DriftResult<u32> {
        let conn = self.db.writer()?;
        let now = Utc::now().to_rfc3339();

        // Get all unfixed baseline entries for this constraint.
        let baseline_hashes: Vec<String> = conn
            .prepare(
                "SELECT context_hash FROM constraint_baselines
                 WHERE constraint_id = ?1 AND fixed_at IS NULL"
            )?
            .query_map([constraint_id], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;

        // Current violation hashes.
        let current_hashes: std::collections::HashSet<&str> = current_violations
            .iter()
            .map(|v| v.context_hash.as_str())
            .collect();

        // Mark fixed: baseline entries whose hash is no longer in current violations.
        let mut fixed_count = 0u32;
        for hash in &baseline_hashes {
            if !current_hashes.contains(hash.as_str()) {
                conn.execute(
                    "UPDATE constraint_baselines SET fixed_at = ?1
                     WHERE constraint_id = ?2 AND context_hash = ?3 AND fixed_at IS NULL",
                    params![now, constraint_id, hash],
                )?;
                fixed_count += 1;
            }
        }

        Ok(fixed_count)
    }

    /// Get baseline statistics for a constraint.
    pub fn baseline_stats(&self, constraint_id: &str) -> DriftResult<BaselineStats> {
        let conn = self.db.reader()?;
        let total: u32 = conn.query_row(
            "SELECT COUNT(*) FROM constraint_baselines WHERE constraint_id = ?1",
            [constraint_id],
            |row| row.get(0),
        )?;
        let remaining: u32 = conn.query_row(
            "SELECT COUNT(*) FROM constraint_baselines
             WHERE constraint_id = ?1 AND fixed_at IS NULL",
            [constraint_id],
            |row| row.get(0),
        )?;
        let fixed: u32 = total - remaining;

        Ok(BaselineStats { total, remaining, fixed })
    }
}

/// Context hash calculation — stable across line number changes.
/// Hashes the violation's surrounding code context (3 lines before + after).
pub fn calculate_context_hash(source: &str, line: u32) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let start = line.saturating_sub(3) as usize;
    let end = (line as usize + 3).min(lines.len());
    let context = lines[start..end].join("\n");
    let hash = blake3::hash(context.as_bytes());
    hash.to_hex()[..16].to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineStats {
    pub total: u32,
    pub remaining: u32,
    pub fixed: u32,
}
```

---

## 11. Developer Feedback Loop (NEW in v2)

Enables <5% effective false-positive rate through developer feedback.
Inspired by Google's Tricorder (§10.2 research): every violation has a
"dismiss" action, high FP rates auto-demote constraints.

### 11.1 Schema

```sql
-- Developer feedback on constraint violations.
-- Aggregated per-constraint for false-positive rate calculation.
CREATE TABLE constraint_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    constraint_id TEXT NOT NULL REFERENCES constraints(id) ON DELETE CASCADE,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    -- Action taken by developer.
    action TEXT NOT NULL,            -- 'false_positive', 'wont_fix', 'not_applicable', 'fixed'
    -- Optional reason for the action.
    reason TEXT,
    -- Timestamp.
    created_at TEXT NOT NULL
) STRICT;

CREATE INDEX idx_feedback_constraint ON constraint_feedback(constraint_id);
CREATE INDEX idx_feedback_action ON constraint_feedback(action);
CREATE INDEX idx_feedback_created ON constraint_feedback(created_at DESC);
```

### 11.2 Feedback Store Implementation

```rust
pub struct FeedbackStore {
    db: Arc<DatabaseManager>,
}

impl FeedbackStore {
    /// Record developer feedback on a violation.
    pub fn record_feedback(
        &self,
        constraint_id: &str,
        file: &str,
        line: u32,
        action: FeedbackAction,
        reason: Option<&str>,
    ) -> DriftResult<()> {
        let conn = self.db.writer()?;
        conn.execute(
            "INSERT INTO constraint_feedback (constraint_id, file, line, action, reason, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                constraint_id,
                file,
                line,
                action.as_str(),
                reason,
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Calculate effective false-positive rate for a constraint.
    /// Rate = dismissals / (dismissals + fixes) over rolling 30-day window.
    pub fn false_positive_rate(
        &self,
        constraint_id: &str,
        window_days: u32,
    ) -> DriftResult<f64> {
        let conn = self.db.reader()?;
        let cutoff = (Utc::now() - chrono::Duration::days(window_days as i64)).to_rfc3339();

        let dismissals: u32 = conn.query_row(
            "SELECT COUNT(*) FROM constraint_feedback
             WHERE constraint_id = ?1 AND action IN ('false_positive', 'not_applicable')
             AND created_at >= ?2",
            params![constraint_id, cutoff],
            |row| row.get(0),
        )?;

        let fixes: u32 = conn.query_row(
            "SELECT COUNT(*) FROM constraint_feedback
             WHERE constraint_id = ?1 AND action = 'fixed'
             AND created_at >= ?2",
            params![constraint_id, cutoff],
            |row| row.get(0),
        )?;

        let total = dismissals + fixes;
        if total == 0 {
            return Ok(0.0); // No feedback yet — assume good.
        }

        Ok(dismissals as f64 / total as f64)
    }

    /// Auto-demote constraints with high false-positive rates.
    /// Called periodically (e.g., after each scan).
    pub fn auto_demote(
        &self,
        demote_threshold: f64,    // e.g., 0.10 (10%)
        review_threshold: f64,    // e.g., 0.25 (25%)
        event_handler: &dyn DriftEventHandler,
    ) -> DriftResult<DemotionReport> {
        let conn = self.db.writer()?;
        let mut demoted = Vec::new();
        let mut flagged = Vec::new();

        // Get all enforced constraints.
        let constraints: Vec<(String, String)> = conn
            .prepare(
                "SELECT id, enforcement_level FROM constraints
                 WHERE status IN ('approved', 'custom')"
            )?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;

        for (id, current_level) in &constraints {
            let fp_rate = self.false_positive_rate(id, 30)?;

            if fp_rate >= review_threshold {
                // Flag for review — very high FP rate.
                flagged.push(id.clone());
                event_handler.on_constraint_flagged(id, fp_rate);
            } else if fp_rate >= demote_threshold && current_level == "error" {
                // Demote error → warning.
                conn.execute(
                    "UPDATE constraints SET enforcement_level = 'warning', updated_at = ?1
                     WHERE id = ?2",
                    params![Utc::now().to_rfc3339(), id],
                )?;
                demoted.push(id.clone());
                event_handler.on_constraint_demoted(id, fp_rate);
            }

            // Update adjusted confidence.
            let adjusted = {
                let base: f64 = conn.query_row(
                    "SELECT confidence FROM constraints WHERE id = ?1",
                    [id],
                    |row| row.get(0),
                )?;
                base * (1.0 - fp_rate)
            };
            conn.execute(
                "UPDATE constraints SET adjusted_confidence = ?1 WHERE id = ?2",
                params![adjusted, id],
            )?;
        }

        Ok(DemotionReport { demoted, flagged })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackAction {
    FalsePositive,
    WontFix,
    NotApplicable,
    Fixed,
}

impl FeedbackAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FalsePositive => "false_positive",
            Self::WontFix => "wont_fix",
            Self::NotApplicable => "not_applicable",
            Self::Fixed => "fixed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemotionReport {
    pub demoted: Vec<String>,
    pub flagged: Vec<String>,
}
```


---

## 12. Integration Points

### 12.1 Quality Gates Integration

The constraint-verification gate is one of 6 quality gates. It consumes
verification results and produces a pass/fail decision.

```rust
/// Quality gate: constraint verification.
/// Baseline-aware — only new violations cause failure.
pub struct ConstraintVerificationGate {
    verifier: Arc<ConstraintVerifier>,
}

impl QualityGate for ConstraintVerificationGate {
    fn name(&self) -> &'static str { "constraint-verification" }

    fn evaluate(
        &self,
        files: &[AnalyzedFile],
        policy: &GatePolicy,
    ) -> DriftResult<GateResult> {
        let mut total_new_violations = 0u32;
        let mut total_baseline = 0u32;
        let mut results = Vec::new();

        for file in files {
            let result = self.verifier.verify_file(
                &file.path,
                &file.parse_result,
                file.language,
            )?;
            total_new_violations += result.failed;
            total_baseline += result.baseline_count;
            results.push(result);
        }

        let passed = match policy.constraint_threshold {
            GateThreshold::Zero => total_new_violations == 0,
            GateThreshold::Max(n) => total_new_violations <= n,
            GateThreshold::ErrorsOnly => {
                results.iter().all(|r| {
                    r.violations.iter()
                        .filter(|v| !v.is_baseline)
                        .all(|v| v.severity != EnforcementLevel::Error)
                })
            }
        };

        Ok(GateResult {
            gate: self.name().to_string(),
            passed,
            score: if total_new_violations == 0 { 100.0 } else {
                (1.0 - (total_new_violations as f64 / (total_new_violations + total_baseline) as f64).min(1.0)) * 100.0
            },
            details: serde_json::to_value(&results)?,
        })
    }
}
```

### 12.2 NAPI Bridge Integration

Per 03-NAPI-BRIDGE-V2-PREP.md §10.10, two NAPI functions expose constraints:

```rust
// In crates/drift-napi/src/bindings/constraints.rs

/// Detect constraints — mine invariants, synthesize, store.
/// Async: runs full detection pipeline.
#[napi]
pub fn detect_constraints(root: String) -> AsyncTask<DetectConstraintsTask> {
    AsyncTask::new(DetectConstraintsTask { root })
}

/// Verify constraints against changed files.
/// Sync for single-file, async for batch.
/// Returns ConstraintVerificationResult (summary + violations).
#[napi]
pub fn verify_constraints(
    changed_files: Option<Vec<String>>,
) -> napi::Result<serde_json::Value> {
    let rt = crate::runtime::get()?;
    let result = if let Some(files) = changed_files {
        rt.constraint_verifier.verify_changed_files(&files)
    } else {
        rt.constraint_verifier.verify_all()
    };
    let summary = result.map_err(to_napi_error)?;
    serde_json::to_value(&summary)
        .map_err(|e| napi::Error::from_reason(format!("[INTERNAL_ERROR] {e}")))
}
```

**NAPI Conversion Types** (in `conversions/constraint_types.rs`):

```rust
#[napi(object)]
pub struct ConstraintsSummary {
    pub total: u32,
    pub by_category: HashMap<String, u32>,
    pub by_status: HashMap<String, u32>,
    pub by_invariant_type: HashMap<String, u32>,
    pub new_discovered: u32,
    pub conflicts: u32,
}

#[napi(object)]
pub struct ConstraintVerificationResult {
    pub total_violations: u32,
    pub total_baseline: u32,
    pub total_fixed: u32,
    pub total_evaluated: u32,
    pub total_skipped: u32,
    pub passed: bool,
    pub duration_ms: u32,
    pub violations: serde_json::Value, // Vec<ConstraintViolation> as JSON
}
```

### 12.3 CLI Integration

New and upgraded CLI commands:

| Command | v1 | v2 | Description |
|---------|-----|-----|-------------|
| `drift constraints list` | ✅ | **UPGRADED** — pagination, filters | List constraints |
| `drift constraints approve <id>` | ✅ | **UPGRADED** — +bulk, +audit | Approve constraint |
| `drift constraints ignore <id>` | ✅ | **UPGRADED** — +reason required | Ignore constraint |
| `drift constraints show <id>` | ❌ | **NEW** | Show constraint details + history |
| `drift constraints explain <id>` | ❌ | **NEW** | Show resolution chain + conflicts |
| `drift constraints baseline create` | ❌ | **NEW** | Snapshot current violations |
| `drift constraints baseline update` | ❌ | **NEW** | Ratchet — remove fixed violations |
| `drift constraints baseline diff` | ❌ | **NEW** | Show baseline changes |
| `drift constraints feedback <id> <action>` | ❌ | **NEW** | Record developer feedback |
| `drift constraints templates list` | ❌ | **NEW** | List available templates |
| `drift constraints templates show <id>` | ❌ | **NEW** | Show template details |
| `drift constraints init` | ❌ | **NEW** | Scaffold drift-constraints.toml |
| `drift constraints verify [files...]` | ❌ | **NEW** | Verify specific files |
| `drift constraints bulk-approve` | ❌ | **NEW** | Approve all above threshold |

### 12.4 Cortex Bridge Integration (Optional, D4)

Per PLANNING-DRIFT.md D4, the bridge crate is a leaf — Drift doesn't know it exists.

```rust
// In cortex-drift-bridge (NOT in drift-core):

/// When a constraint is approved in Drift, create a Cortex memory.
fn on_constraint_approved(constraint: &Constraint) {
    let memory = BaseMemory {
        memory_type: MemoryType::ConstraintOverride,
        content: TypedContent::ConstraintOverride(ConstraintOverrideContent {
            constraint_name: constraint.name.clone(),
            override_reason: format!("Auto-approved: confidence {:.2}", constraint.confidence.score),
            approved_by: constraint.approved_by.clone().unwrap_or_default(),
            scope: serde_json::to_string(&constraint.scope).unwrap_or_default(),
            expiry: None,
        }),
        summary: format!("Constraint: {}", constraint.name),
        linked_constraints: vec![ConstraintLink {
            constraint_id: constraint.id.clone(),
            constraint_name: constraint.name.clone(),
        }],
        ..Default::default()
    };
    cortex_storage.create(&memory).ok();
}

/// When a violation is dismissed, create a feedback memory.
fn on_violation_dismissed(constraint_id: &str, reason: &str) {
    let memory = BaseMemory {
        memory_type: MemoryType::Feedback,
        content: TypedContent::Feedback(FeedbackContent {
            feedback_type: "constraint_dismissal".to_string(),
            content: format!("Constraint {} dismissed: {}", constraint_id, reason),
            source: "drift-constraints".to_string(),
            sentiment: "neutral".to_string(),
        }),
        ..Default::default()
    };
    cortex_storage.create(&memory).ok();
}
```

### 12.5 Context Generation Integration

Per existing cortex-retrieval constraint_gatherer.rs, constraints get 20% of token budget.
v2 enriches the context with predicate details and rationale.

```rust
/// Enhanced constraint gatherer for v2.
/// Includes predicate, rationale, and violation examples in context.
pub struct EnhancedConstraintGatherer {
    db: Arc<DatabaseManager>,
}

impl Gatherer for EnhancedConstraintGatherer {
    fn category(&self) -> &'static str { "constraints" }
    fn default_percentage(&self) -> f64 { 0.20 }

    fn gather(
        &self,
        focus: &str,
        active_files: &[String],
        limit: usize,
    ) -> DriftResult<Vec<ContextEntry>> {
        let mut entries = Vec::new();

        // Get constraints applicable to active files.
        for file in active_files {
            let constraints = self.db.get_constraints_for_file(file, ConstraintLanguage::All)?;
            for constraint in constraints.iter().take(limit) {
                entries.push(ContextEntry {
                    id: constraint.id.clone(),
                    category: "constraints".to_string(),
                    text: format!(
                        "[{:?}] {} — {} (confidence: {:.2})\nPredicate: {:?}\n{}",
                        constraint.category,
                        constraint.name,
                        constraint.description,
                        constraint.confidence.score,
                        constraint.invariant.predicate,
                        constraint.rationale.as_ref()
                            .map(|r| format!("Rationale: {}", r.text))
                            .unwrap_or_default(),
                    ),
                    relevance_score: constraint.confidence.adjusted_score,
                });
            }
        }

        // Sort by relevance, security constraints first.
        entries.sort_by(|a, b| b.relevance_score.partial_cmp(&a.relevance_score).unwrap());
        entries.truncate(limit);

        Ok(entries)
    }
}
```

### 12.6 DriftEventHandler Events (D5)

Per PLANNING-DRIFT.md D5, the constraint system emits typed events via DriftEventHandler.
In standalone mode these are no-ops. When the bridge is active, they become Cortex memories.

```rust
/// Constraint-related events emitted via DriftEventHandler.
pub trait ConstraintEvents {
    /// A constraint was approved (manually or auto-bulk).
    fn on_constraint_approved(&self, constraint_id: &str) {}
    /// A constraint was ignored.
    fn on_constraint_ignored(&self, constraint_id: &str, reason: &str) {}
    /// A constraint was deprecated.
    fn on_constraint_deprecated(&self, constraint_id: &str) {}
    /// A new violation was detected (not in baseline).
    fn on_violation_detected(&self, constraint_id: &str, file: &str, line: u32) {}
    /// A baseline violation was fixed (ratchet progress).
    fn on_baseline_fixed(&self, constraint_id: &str, file: &str) {}
    /// A constraint was auto-demoted due to high FP rate.
    fn on_constraint_demoted(&self, constraint_id: &str, fp_rate: f64) {}
    /// A constraint was flagged for review due to very high FP rate.
    fn on_constraint_flagged(&self, constraint_id: &str, fp_rate: f64) {}
    /// A conflict was detected between two constraints.
    fn on_conflict_detected(&self, constraint_a: &str, constraint_b: &str) {}
}
```

---

## 13. Predicate Type System

The predicate defines WHAT a constraint checks. Each invariant type has a specific
predicate structure.

```rust
/// The predicate — what the constraint actually checks.
/// Serialized as JSON in the `predicate_json` column.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Predicate {
    /// For must_have/must_not_have: required/forbidden decorators.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decorators: Option<Vec<String>>,
    /// For must_have/must_not_have: required/forbidden imports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imports: Option<Vec<ImportPattern>>,
    /// For must_have/must_not_have: required/forbidden calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calls: Option<Vec<String>>,
    /// For must_precede: what must come before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<PredicateTarget>,
    /// For must_precede/must_follow: what must come after.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<PredicateTarget>,
    /// For must_wrap: what must be wrapped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<PredicateTarget>,
    /// For must_wrap: the wrapper type (try_catch, if_check, error_boundary).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapper: Option<String>,
    /// For cardinality: minimum count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_count: Option<u32>,
    /// For cardinality: maximum count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_count: Option<u32>,
    /// For naming: name pattern (glob or regex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// For naming: what to match (classes, functions, files).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub naming_target: Option<NamingTarget>,
    /// For data_flow: source pattern (where data originates).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// For data_flow: sink pattern (where data must not reach).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sink: Option<String>,
    /// For structure: required files/directories.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_files: Option<Vec<String>>,
    /// For must_colocate/must_separate: entity patterns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entities: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportPattern {
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredicateTarget {
    /// Decorator patterns to match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decorators: Option<Vec<String>>,
    /// Call patterns to match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calls: Option<Vec<String>>,
    /// Function name patterns to match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub functions: Option<Vec<String>>,
    /// Description for error messages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NamingTarget {
    Classes,
    Functions,
    Files,
    Variables,
    Modules,
}
```

### Predicate Validation

```rust
/// Validate that a predicate has the required fields for its invariant type.
pub fn validate_predicate(
    invariant_type: &InvariantType,
    predicate: &Predicate,
) -> DriftResult<()> {
    match invariant_type {
        InvariantType::MustHave | InvariantType::MustNotHave => {
            if predicate.decorators.is_none()
                && predicate.imports.is_none()
                && predicate.calls.is_none()
            {
                return Err(DriftError::InvalidPredicate(
                    "must_have/must_not_have requires at least one of: decorators, imports, calls"
                ));
            }
        }
        InvariantType::MustPrecede | InvariantType::MustFollow => {
            if predicate.before.is_none() || predicate.after.is_none() {
                return Err(DriftError::InvalidPredicate(
                    "must_precede/must_follow requires both 'before' and 'after' fields"
                ));
            }
        }
        InvariantType::MustWrap => {
            if predicate.target.is_none() || predicate.wrapper.is_none() {
                return Err(DriftError::InvalidPredicate(
                    "must_wrap requires both 'target' and 'wrapper' fields"
                ));
            }
        }
        InvariantType::Cardinality => {
            if predicate.min_count.is_none() && predicate.max_count.is_none() {
                return Err(DriftError::InvalidPredicate(
                    "cardinality requires at least one of: min_count, max_count"
                ));
            }
        }
        InvariantType::DataFlow => {
            if predicate.source.is_none() || predicate.sink.is_none() {
                return Err(DriftError::InvalidPredicate(
                    "data_flow requires both 'source' and 'sink' fields"
                ));
            }
        }
        InvariantType::Naming => {
            if predicate.pattern.is_none() {
                return Err(DriftError::InvalidPredicate(
                    "naming requires 'pattern' field"
                ));
            }
        }
        InvariantType::Structure => {
            if predicate.required_files.is_none() {
                return Err(DriftError::InvalidPredicate(
                    "structure requires 'required_files' field"
                ));
            }
        }
        InvariantType::MustColocate | InvariantType::MustSeparate => {
            if predicate.entities.is_none() || predicate.entities.as_ref().map_or(true, |e| e.len() < 2) {
                return Err(DriftError::InvalidPredicate(
                    "must_colocate/must_separate requires 'entities' with at least 2 entries"
                ));
            }
        }
        InvariantType::MustPropagate => {
            if predicate.source.is_none() || predicate.sink.is_none() {
                return Err(DriftError::InvalidPredicate(
                    "must_propagate requires both 'source' and 'sink' fields"
                ));
            }
        }
    }
    Ok(())
}
```


---

## 14. Incremental Verification Strategy

Three-level incrementality for CI/CD performance. Verification time proportional
to change size, not codebase size.

### Level 1: File-Level (v1 — Preserved)
- Only verify files that changed (content-hash comparison via scanner).
- Skip unchanged files entirely.
- Already implemented in v1's `verifyChange()`.

### Level 2: Constraint-Level (NEW in v2 — P1)
- Maintain scope index mapping file paths to applicable constraints.
- When a file changes, look up only applicable constraints via scope index.
- Skip constraints whose scope doesn't match the changed file.
- Expected reduction: 80-90% of constraints skipped for typical file changes.

```rust
/// Incremental verification — only evaluates applicable constraints.
pub fn verify_incremental(
    &self,
    changed_files: &[(String, ParseResult)],
) -> DriftResult<VerificationSummary> {
    let mut results = Vec::new();

    for (file_path, parse_result) in changed_files {
        let language = detect_language(file_path);

        // Level 2: Only get constraints applicable to this file.
        let applicable = self.db.get_constraints_for_file(file_path, language)?;
        let total_constraints = self.db.total_active_constraints()?;
        let skipped = total_constraints - applicable.len() as u32;

        let mut result = self.verify_file_with_constraints(
            file_path,
            parse_result,
            &applicable,
        )?;
        result.constraints_skipped_incremental = skipped;

        results.push(result);
    }

    Ok(VerificationSummary::from_results(results))
}
```

### Level 3: Predicate-Level (Future — P2)
- Track which code elements each constraint depends on.
- When a file changes, determine which elements changed (functions added/removed/modified).
- Only re-evaluate predicates that depend on changed elements.
- Expected additional reduction: 50-70% of predicate evaluations skipped.

### Verification Result Cache

```sql
-- Cache verification results per (file_hash, constraint_id) pair.
-- Skip re-verification if both file and constraint are unchanged.
CREATE TABLE verification_cache (
    file_path TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    constraint_id TEXT NOT NULL REFERENCES constraints(id) ON DELETE CASCADE,
    constraint_version INTEGER NOT NULL,
    result TEXT NOT NULL,           -- 'pass', 'fail', 'skip'
    violations_json TEXT,           -- Cached violations (if fail)
    cached_at TEXT NOT NULL,
    PRIMARY KEY(file_path, constraint_id)
) STRICT;

CREATE INDEX idx_vcache_file ON verification_cache(file_path);
CREATE INDEX idx_vcache_constraint ON verification_cache(constraint_id);
```

---

## 15. Error Handling

Per PLANNING-DRIFT.md AD6: thiserror error enums from the first line of code.

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConstraintError {
    #[error("Constraint not found: {0}")]
    NotFound(String),

    #[error("Invalid predicate for {invariant_type}: {reason}")]
    InvalidPredicate {
        invariant_type: String,
        reason: String,
    },

    #[error("Constraint parse error: {0}")]
    ParseError(String),

    #[error("Template not found: {0}")]
    TemplateNotFound(String),

    #[error("Template missing required parameter '{param}' for template '{template}'")]
    TemplateMissingParam {
        template: String,
        param: String,
    },

    #[error("Constraint conflict: {constraint_a} conflicts with {constraint_b}")]
    Conflict {
        constraint_a: String,
        constraint_b: String,
    },

    #[error("Ordering cycle detected: {0}")]
    OrderingCycle(String),

    #[error("Baseline error: {0}")]
    BaselineError(String),

    #[error("Feedback error: {0}")]
    FeedbackError(String),

    #[error("Verification error: {0}")]
    VerificationError(String),

    #[error("Storage error: {0}")]
    StorageError(#[from] rusqlite::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}
```

---

## 16. Tracing Instrumentation

Per PLANNING-DRIFT.md AD10: structured logging + span-based timing from the first line.

```rust
use tracing::{info, warn, debug, instrument, info_span};

#[instrument(skip(db, config), fields(categories = ?config.categories))]
pub fn detect_invariants(
    db: &DatabaseManager,
    config: &InvariantDetectorConfig,
) -> DriftResult<Vec<DetectedInvariant>> {
    let _span = info_span!("constraint_detection").entered();
    info!(min_confidence = config.min_confidence, "Starting invariant detection");

    let mut all_invariants = Vec::new();
    for strategy in &strategies {
        let _strategy_span = info_span!("mining_strategy", name = strategy.name()).entered();
        let invariants = strategy.mine(db, config)?;
        info!(
            strategy = strategy.name(),
            count = invariants.len(),
            "Mining strategy completed"
        );
        all_invariants.extend(invariants);
    }

    info!(total = all_invariants.len(), "Invariant detection complete");
    Ok(all_invariants)
}

#[instrument(skip(verifier, parse_result), fields(file = %file_path))]
pub fn verify_file(
    verifier: &ConstraintVerifier,
    file_path: &str,
    parse_result: &ParseResult,
    language: ConstraintLanguage,
) -> DriftResult<VerificationResult> {
    let start = std::time::Instant::now();
    let result = verifier.verify_file(file_path, parse_result, language)?;
    debug!(
        passed = result.passed,
        failed = result.failed,
        skipped = result.skipped,
        baseline = result.baseline_count,
        duration_us = start.elapsed().as_micros() as u64,
        "File verification complete"
    );
    Ok(result)
}
```

---

## 17. Performance Targets

| Metric | v1 | v2 Target | Strategy |
|--------|-----|-----------|----------|
| Verification per file | ~50ms (regex) | <5ms (AST) | ParseResult direct access, no re-parsing |
| Scope lookup | O(N×S×G) | O(1) | SQLite scope index |
| Constraint query | O(N) linear scan | O(log N) | SQLite indexed queries |
| Full codebase verification (10K files) | ~500s | <50s | Incremental Level 2 + rayon parallelism |
| Invariant detection | ~30s | <10s | Rust, parallel mining strategies |
| Baseline check | N/A | <1ms per violation | SQLite indexed lookup |
| Feedback rate calculation | N/A | <5ms per constraint | SQLite aggregate query |
| TOML parsing | N/A | <10ms for 100 constraints | toml crate, single pass |
| Template expansion | N/A | <1ms per template | String interpolation |
| Conflict detection | N/A | <100ms for 1000 constraints | Scope-partitioned pairwise |

---

## 18. Build Order

The constraint system is built after its upstream dependencies are functional.
It's a consumer of parsers, call graph, boundaries, test topology, and error handling.

### Phase 1: Foundation (Week 1-2)
1. `types.rs` — All types from §3 (Constraint, InvariantType, etc.)
2. `mod.rs` — Module structure and re-exports
3. Error types (§15) and tracing instrumentation (§16)
4. `store/constraint_store.rs` — SQLite CRUD (schema from §7.1)
5. `store/scope_index.rs` — Scope index maintenance (§7.4)
6. Verify: Can create, read, update, delete constraints in drift.db

### Phase 2: TOML Format (Week 2-3)
7. `toml_parser.rs` — Parse drift-constraints.toml (§9.1)
8. `templates/template_registry.rs` — Template loading and expansion (§9.3)
9. `templates/builtin/*.toml` — 10 built-in templates
10. Verify: Can parse TOML files, expand templates, merge with store

### Phase 3: Verification Engine (Week 3-5)
11. `verification/predicate_evaluator.rs` — Per-invariant-type evaluation (§8.3)
12. `verification/constraint_verifier.rs` — Main verification engine (§8.1)
13. `verification/change_detector.rs` — Change-aware verification (§8.2)
14. Verify: Can verify files against constraints using ParseResult

### Phase 4: Invariant Mining (Week 5-7)
15. `extraction/mining_strategies/*.rs` — 6 mining strategies (§5.4)
16. `extraction/invariant_detector.rs` — Detection orchestrator (§5.1)
17. `extraction/constraint_synthesizer.rs` — Synthesis pipeline (§6.1)
18. Verify: Can detect invariants from patterns, call graph, boundaries

### Phase 5: Baseline & Feedback (Week 7-8)
19. `store/baseline_store.rs` — Baseline management (§10)
20. `store/feedback_store.rs` — Feedback persistence (§11)
21. Integrate baseline into verifier (§8.1 baseline check)
22. Integrate feedback into confidence (§11.2 auto-demotion)
23. Verify: Baseline-aware verification, feedback recording

### Phase 6: Conflict Resolution (Week 8-9)
24. `conflict/conflict_detector.rs` — Pairwise comparison + cycle detection (§6.4)
25. `conflict/specificity.rs` — Specificity-based resolution
26. Integrate into synthesizer pipeline
27. Verify: Conflicts detected and resolved

### Phase 7: Integration (Week 9-10)
28. NAPI bindings (§12.2) — detect_constraints(), verify_constraints()
29. Quality gate integration (§12.1)
30. Context generation integration (§12.5)
31. DriftEventHandler events (§12.6)
32. Verify: Full pipeline functional end-to-end

### Phase 8: Advanced Features (Week 10-12)
33. Temporal analysis (§5.5) — momentum scoring
34. Negative invariant mining (§5.6)
35. Constraint inheritance (§9.4)
36. Auto-fix implementation (§8.5)
37. Incremental verification Level 2 (§14)
38. Verify: All advanced features functional

---

## 19. v1 Feature Verification — Complete Gap Analysis

Cross-referenced against all v1 documentation, existing Rust code (cortex-core
ConstraintLink, ConstraintOverrideContent, ConstraintGatherer), and the
DRIFT-V2-FULL-SYSTEM-AUDIT.md Category 18 specification.

### v1 Features — 100% Accounted For

| v1 Feature | v2 Status | Evidence |
|-----------|-----------|----------|
| 12 invariant types | ✅ All preserved | §3.2 — InvariantType enum |
| 10 constraint categories | ✅ All preserved | §3.3 — ConstraintCategory enum |
| 4 status states | ✅ Preserved + 2 new | §3.4 — +deprecated, +superseded |
| 9 language targets | ✅ Preserved + 1 new | §3.5 — +Go |
| InvariantDetector (5 sources) | ✅ Preserved + 2 new | §5 — +negative mining, +temporal |
| ConstraintSynthesizer (dedup, merge) | ✅ Preserved + conflict detection | §6 |
| ConstraintStore (CRUD, lifecycle) | ✅ Upgraded to SQLite | §7 |
| ConstraintVerifier (full + change-aware) | ✅ Upgraded to AST-based | §8 |
| Scope matching (files, dirs, functions, classes, entry_points) | ✅ Preserved + packages, modules | §3.6 |
| Confidence scoring (score, conforming, violating) | ✅ Preserved + momentum, trend | §3.7 |
| Enforcement (level, autoFix, message, suggestion) | ✅ Preserved + fix templates | §3.8 |
| Violation reporting (constraintId, file, line, message, severity) | ✅ Preserved + column, snippet, baseline | §3.9 |
| VerificationResult (passed, failed, skipped) | ✅ Preserved + baseline counts | §3.10 |
| ConstraintSource (type, sourceIds, evidence) | ✅ Preserved + temporal data | §3.11 |
| Auto-approval (configurable threshold) | ✅ Preserved | §6.3 |
| Deduplication (hash-based) | ✅ Preserved | §6.2 |
| Merging (similarity threshold 0.8) | ✅ Preserved | §6.3 |
| Quality gate integration | ✅ Preserved + baseline-aware | §12.1 |
| MCP tools (drift_validate_change, drift_prevalidate) | ✅ Preserved | §12.2 |
| CLI (list, approve, ignore) | ✅ Preserved + 11 new commands | §12.3 |
| Cortex integration (ConstraintOverride, ConstraintLink) | ✅ Preserved via bridge | §12.4 |
| Context generation (20% budget) | ✅ Preserved + enriched | §12.5 |
| Provenance tracking ([drift:constraint]) | ✅ Preserved | §12.5 |
| 8-language verification | ✅ Preserved + Go (10 total) | §8.4 |
| Change-aware verification | ✅ Preserved + constraint-level incremental | §8.2, §14 |

### v1 Gaps — All Addressed

| v1 Gap | v2 Resolution | Section |
|--------|--------------|---------|
| Ordering constraints unverifiable | Call graph path queries | §8.2 (MustPrecede) |
| Data flow constraints unverifiable | Taint analysis integration | §8.2 (DataFlow) |
| MustWrap constraints unverifiable | AST containment check | §8.2 (MustWrap) |
| Regex-based extraction (~70% accuracy) | ParseResult AST (~98% accuracy) | §8.3 |
| No baseline management | FreezingArchRule pattern | §10 |
| No declarative format | TOML constraint files | §9 |
| No feedback loop | Tricorder-style feedback | §11 |
| No conflict detection | Specificity-based resolution | §6.4 |
| No constraint versioning | SQLite history table | §7.7 |
| No auto-fix implementation | Fix templates + tree-sitter edit | §8.5 |
| File-based storage (no ACID) | SQLite in drift.db | §7 |
| No constraint inheritance | Directory-based inheritance | §9.4 |
| No temporal analysis | Momentum scoring + trends | §5.5 |
| No negative invariant mining | Absence detection | §5.6 |
| No cross-language invariants | Cross-language grouping | §5.7 |
| Linear scan for ID lookups O(N) | SQLite PRIMARY KEY O(1) | §7.3 |
| No scope index | SQLite scope index O(1) | §7.2 |

---

## 20. Resolved Inconsistencies

| Inconsistency | Source A | Source B | Resolution |
|---------------|----------|----------|------------|
| Storage format | RECAP.md says JSON files | RECOMMENDATIONS.md says SQLite | **SQLite** — per D6, drift.db is the single source of truth |
| Auto-approve threshold | RECAP.md says "configurable" | RECOMMENDATIONS.md says 0.95 | **0.95 default, configurable** in drift-constraints.toml settings |
| Constraint status count | RECAP.md says 4 states | Audit says 4 states | **6 states** — added deprecated + superseded for lifecycle completeness |
| Language count | RECAP.md says 9 | Parser support says 10 | **10 languages** — added Go to match parser support |
| Verifier data source | RECAP.md says "regex extraction" | RECOMMENDATIONS.md says "ParseResult" | **ParseResult** — regex is replaced entirely |
| TOML vs YAML format | RECOMMENDATIONS.md discusses both | SonarQube uses YAML | **TOML** — no indentation sensitivity, better Rust ecosystem support |
| Constraint store location | v1: .drift/constraints/ | v2: drift.db | **Both** — TOML files are source of truth for user-defined, SQLite for merged/resolved set |
| Feedback window | RECOMMENDATIONS.md says 30 days | Tricorder paper doesn't specify | **30 days rolling window** — configurable |

---

## 21. Summary of All Decisions

| Decision | Choice | Confidence | Source |
|----------|--------|------------|--------|
| Storage backend | SQLite in drift.db | Very High | D6, RECOMMENDATIONS R6 |
| Verification engine | Rust AST via ParseResult | Very High | RECOMMENDATIONS R1 |
| Declarative format | TOML (not YAML) | High | Rust ecosystem, no indent sensitivity |
| Baseline pattern | FreezingArchRule (ArchUnit) | Very High | RESEARCH §8.2 |
| Feedback model | Tricorder-style (<5% FP target) | Very High | RESEARCH §10.2 |
| Conflict resolution | Specificity-based (CSS model) | High | RESEARCH §7.1 |
| Template system | TOML templates with param interpolation | High | RESEARCH §6.1 (OPA) |
| Invariant types | All 12 preserved, all verifiable | Very High | v1 parity requirement |
| Categories | All 10 preserved | Very High | v1 parity requirement |
| Status states | 6 (4 preserved + deprecated + superseded) | High | ADR lifecycle mapping |
| Languages | 10 (9 preserved + Go) | High | Parser support alignment |
| Mining strategies | 6 (5 preserved + negative mining) | High | RESEARCH §4.1 (Daikon) |
| Temporal analysis | Momentum scoring + trend detection | Medium-High | RESEARCH §5.2 |
| Auto-fix | Fix templates + tree-sitter edit | Medium | RESEARCH §3.1 (Semgrep) |
| Inheritance | Directory-based, specificity resolution | Medium-High | RESEARCH §1.3 (SonarQube) |
| Scope index | SQLite table for O(1) lookup | Very High | Performance requirement |
| Event emission | DriftEventHandler trait (D5) | Very High | PLANNING-DRIFT.md D5 |
| Independence | Zero imports from cortex-core | Very High | PLANNING-DRIFT.md D1 |

---

## 22. Cross-Category Impact Matrix

| Category | Impact from Constraints V2 | Action Required |
|----------|---------------------------|-----------------|
| 00-Scanner | Content hashes drive incremental verification | Expose file hash API |
| 01-Parsers | ParseResult consumed by constraint verifier | Ensure stable interface for functions, classes, decorators, imports |
| 02-Storage | New SQLite tables in drift.db | Schema migration (§7.1) |
| 03-NAPI | 2 binding functions + conversion types | Add constraints.rs binding module (§12.2) |
| 04-Infrastructure | Quality gate integration | Update constraint-verification gate (§12.1) |
| 05-Call Graph | Path queries for ordering constraints | Expose get_callers_transitive(), path_exists() APIs |
| 06-Unified Analysis | Level 4 cross-reference constraints | Constraint detection as consumer of analysis results |
| 07-Boundary Detection | data_flow constraint source | Expose boundary data for mining |
| 10-CLI | 14 new/upgraded commands | Add constraint command group (§12.3) |
| 15-Taint Analysis | data_flow constraint verification | Expose taint path query API |
| 16-Error Handling | Error handling invariant mining | Expose error boundary data for mining |
| 18-Test Topology | Test coverage invariant mining | Expose coverage data for mining |
| Context Generation | Enhanced constraint gatherer | Update gatherer with predicate + rationale (§12.5) |
| DriftEventHandler | 8 new event types | Add ConstraintEvents trait methods (§12.6) |

---

## 23. Risk Register

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| ParseResult interface instability | Medium | High | Define stable constraint-facing interface subset |
| Call graph not available at verification time | Medium | High | Graceful degradation — skip ordering constraints (PredicateResult::Skip) |
| Taint analysis not available at verification time | High (P2 system) | Medium | Graceful degradation — skip data_flow constraints |
| TOML format too verbose for complex predicates | Low | Medium | Support tree-sitter query syntax for advanced predicates |
| Baseline gaming by developers | Low | Medium | Team-level aggregation, code review of baseline changes |
| Template proliferation | Low | Low | Curated built-in set, community review for additions |
| SQLite migration data loss | Low | High | Backup JSON before migration, rollback capability |
| Conflict detection O(N²) performance | Low | Medium | Scope-based partitioning reduces effective N |
| Feedback cold start (no data) | Medium | Low | Use confidence score as initial proxy |
| Cross-file constraints (colocate/separate) | Medium | Medium | Special handling — verify at directory level, not file level |

---

## 24. Target Metrics

| Metric | v1 | v2 Target | Evidence |
|--------|-----|-----------|----------|
| Verifiable invariant types | 8/12 | 12/12 | AST + call graph + taint |
| Verification accuracy | ~70% (regex) | ~98% (AST) | ParseResult direct access |
| Verification speed (per file) | ~50ms | <5ms | Rust, no re-parsing |
| Effective false-positive rate | Unknown | <5% | Tricorder feedback loop |
| Constraint format | Internal JSON | TOML (version-controlled) | Declarative format |
| Legacy codebase adoption | Impractical | Baseline-enabled | FreezingArchRule |
| Conflict detection | None | Automatic | Specificity-based |
| Incremental verification | File-level only | Constraint-level | Scope index |
| Auto-fix coverage | 0% | 40% of constraint types | Fix templates |
| Constraint templates | 0 | 10+ built-in | Template registry |
| Scope lookup | O(N×S×G) | O(1) | SQLite scope index |
| ID lookup | O(N) | O(1) | SQLite PRIMARY KEY |
| Languages supported | 9 | 10 | +Go |
| Status states | 4 | 6 | +deprecated, +superseded |
| Mining strategies | 5 | 6 | +negative mining |
| CLI commands | 3 | 14 | Full constraint management |

---

*This specification accounts for 100% of v1 constraint system features. Every type,
every pipeline component, every integration point, and every capability is either
preserved as-is, upgraded with new capabilities, or replaced with a strictly superior
implementation. No feature loss. The constraint system is Drift's enforcement backbone —
it transforms statistical patterns into architectural law.*
