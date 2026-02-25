# Quality Gates (drift-gates) — V2 Implementation Prep

> Comprehensive build specification for Drift v2's Quality Gates subsystem — the CI/CD
> enforcement layer that transforms analysis into actionable pass/fail decisions.
> Synthesized from: 09-quality-gates/overview.md, 09-quality-gates/orchestrator.md,
> 09-quality-gates/gates.md, 09-quality-gates/policy.md, 09-quality-gates/reporters.md,
> 09-quality-gates/store.md, 09-quality-gates/types.md, 09-quality-gates/audit.md,
> .research/09-quality-gates/RECAP.md (840 lines, 20 limitations, 12 open questions),
> .research/09-quality-gates/RESEARCH.md (15 external sources: SonarQube, Semgrep, Meta
> Fix Fast, Google Tricorder, OPA, CodeScene, SARIF 2.1.0, OWASP SPVS, Meta FBDetect,
> GitHub Code Scanning, JUnit XML, DevSecOps frameworks, Augment Code),
> .research/09-quality-gates/RECOMMENDATIONS.md (19 recommendations R1-R19, 6 build phases),
> .research/09-quality-gates/AUDIT.md (coverage audit: 93% after patches, 7 critical gaps
> closed, 15 gaps total identified and resolved),
> DRIFT-V2-FULL-SYSTEM-AUDIT.md (Cat 09, A9),
> DRIFT-V2-STACK-HIERARCHY.md (Level 3 Enforcement),
> PLANNING-DRIFT.md (D1-D7),
> 03-NAPI-BRIDGE-V2-PREP.md (§10.12 gate bindings, §9 batch API QualityGates variant),
> 02-STORAGE-V2-PREP.md (drift.db schema: gate_runs, health_snapshots, audit_history,
> violation_feedback, gate_cache tables),
> 04-INFRASTRUCTURE-V2-PREP.md (thiserror, tracing, DriftEventHandler on_gate_evaluated,
> GateConfig in drift.toml, error codes GATE_FAILED),
> 19-COUPLING-ANALYSIS-V2-PREP.md (§20 CouplingGateInput, coupling quality gate criterion),
> 20-CONSTRAINT-SYSTEM-V2-PREP.md (§12.1 ConstraintVerificationGate, QualityGate trait),
> 22-CONSTANTS-ENVIRONMENT-V2-PREP.md (§22 SecurityGateInput from secrets),
> 23-WRAPPER-DETECTION-V2-PREP.md (WrapperGateInput),
> 24-DNA-SYSTEM-V2-PREP.md (§22 DnaGateInput, DNA health score consumption),
> 26-OWASP-CWE-MAPPING-V2-PREP.md (CWE/OWASP taxonomy for SARIF, security gate enrichment),
> 16-ERROR-HANDLING-ANALYSIS-V2-PREP.md (ErrorHandlingGate),
> 15-TAINT-ANALYSIS-V2-PREP.md (taint sink CWE mappings for security gate),
> cortex-consolidation/src/pipeline/phase3_recall_gate.rs (Rust gate pattern reference),
> cortex-core/src/traits/health_reporter.rs (IHealthReporter trait pattern),
> SonarQube "Clean as You Code" (QG-R1), Semgrep three-mode policies (QG-R3),
> Google Tricorder <10% FP rate (QG-R5), OPA policy-as-code (QG-R6),
> SARIF 2.1.0 OASIS standard (QG-R8), OWASP SPVS maturity levels (QG-R9),
> Meta FBDetect regression detection (QG-R10).
>
> Purpose: Everything needed to build drift-gates from scratch. All 6 gates preserved
> and upgraded. All 20 v1 limitations addressed. All 12 open questions resolved. All 19
> recommendations integrated. Every algorithm specified. Every type defined. Every
> integration point documented. Every architectural decision resolved. Zero feature loss.
> Generated: 2026-02-08

---

## Table of Contents

1. Architectural Position
2. V1 Complete Feature Inventory — Preservation Matrix
3. V2 Architecture — Unified Quality Gates Engine
4. Core Data Model (Rust Types)
5. The 6 Quality Gates — Rust Implementations
6. Gate Orchestrator — TS Coordination Layer
7. Policy Engine — Declarative Policy-as-Code
8. Reporter System — 7 Output Formats + Plugin Architecture
9. Persistence — SQLite in drift.db
10. Audit System — Health Scoring & Degradation Tracking
11. New-Code-First Enforcement (R1)
12. Progressive Enforcement — Monitor/Comment/Block (R2)
13. Incremental Gate Execution with Caching (R3)
14. Rich SARIF 2.1.0 Output (R4)
15. Developer Feedback Loop (R6)
16. Multi-Stage Enforcement (R7)
17. Gate Dependency Graph & Priority Ordering (R9)
18. Violation Prioritization Algorithm (R16)
19. Structured Violation Explanations (R15)
20. Dry-Run / Preview Mode (R17)
21. Hotspot-Aware Scoring (R11)
22. OWASP/CWE Alignment (R12)
23. Gate Timeout & Partial Failure Recovery (R13)
24. Custom Rule Expansion — AST & Call Graph Conditions (R14)
25. Webhook & Notification System (R18)
26. Integration with Upstream Systems
27. Integration with Downstream Consumers
28. NAPI Bridge Interface
29. CLI Interface
30. MCP Tool Interface
31. License Gating — Tier Mapping
32. Resolved Inconsistencies
33. File Module Structure
34. Build Order & Dependency Chain
35. V1 Feature Verification — Complete Gap Analysis

---

## 1. Architectural Position

Quality Gates is Level 3 (Enforcement) in Drift's stack hierarchy. It is the system
that transforms upstream analysis (patterns, constraints, call graph, boundaries,
security, DNA, coupling, error handling) into actionable pass/fail decisions for CI/CD
pipelines, pull requests, and developer workflows.

Per PLANNING-DRIFT.md D1: Drift is standalone. Quality gates live entirely in drift-core.
Per PLANNING-DRIFT.md D5: Gate lifecycle events emit via DriftEventHandler.
Per PLANNING-DRIFT.md D6: All gate data persists in drift.db (standalone, no ATTACH).

Per DRIFT-V2-STACK-HIERARCHY.md:
> Rules Engine · Quality Gates · Policy · Audit · Feedback
> ← All emit DriftEventHandler events (D5) →

Per DRIFT-V2-FULL-SYSTEM-AUDIT.md A9:
> Quality Gates — Missing Details: New-code-first enforcement, progressive enforcement,
> incremental execution, rich SARIF, policy-as-code, developer feedback loop,
> multi-stage enforcement.

### What Lives Here

- 6 quality gates (all v1 gates preserved + upgraded with Rust analysis backends)
- Gate orchestrator (TS coordination — resolves files, loads policy, executes gates)
- Policy engine (4 built-in policies + custom YAML/JSON + inheritance + versioning)
- 7 reporters (text, JSON, SARIF 2.1.0, GitHub, GitLab, JUnit XML, HTML) + plugin system
- Persistence (SQLite: gate_runs, health_snapshots, audit_history, violation_feedback, gate_cache)
- Audit system (health scoring, duplicate detection, cross-validation, degradation tracking)
- New-code-first enforcement mode (R1 — only new violations block)
- Progressive enforcement (R2 — Monitor → Comment → Block per pattern)
- Incremental gate execution with 3-tier caching (R3)
- Developer feedback loop (R6 — dismiss/fix/exception actions)
- Multi-stage enforcement (R7 — pre-commit, PR, post-merge, scheduled)
- Gate dependency graph with priority ordering (R9)
- Violation prioritization algorithm (R16 — multi-factor scoring)
- Structured violation explanations (R15 — WHY/WHAT/HOW/IMPACT)
- Dry-run / preview mode (R17)
- Hotspot-aware scoring (R11 — git history integration)
- OWASP/CWE alignment (R12 — compliance reporting)
- Gate timeout with partial failure recovery (R13)
- Custom rule expansion (R14 — AST, call graph, metric conditions)
- Webhook/notification system (R18)
- Reporter plugin architecture (R19)

### What Does NOT Live Here

- Pattern detection (lives in Detector System — gates consume patterns)
- Constraint mining (lives in Constraint System — gates consume verification results)
- Call graph construction (lives in Call Graph Builder — gates consume reachability)
- Boundary detection (lives in Boundary Detection — gates consume security data)
- Taint analysis (lives in Taint Analysis — gates consume taint paths)
- DNA analysis (lives in DNA System — gates consume health scores)
- Coupling analysis (lives in Coupling Analysis — gates consume coupling metrics)
- Error handling analysis (lives in Error Handling — gates consume error gaps)
- MCP tool routing (lives in MCP Server — calls gate APIs)
- CLI command parsing (lives in CLI — calls gate APIs)
- NAPI bridge functions (lives in drift-napi — thin wrappers around gate APIs)

### Upstream Dependencies (What Gates Consumes)

| System | What It Provides | How Gates Uses It |
|--------|-----------------|-------------------|
| Detector System (06) | Approved patterns with confidence, locations, outliers | Pattern compliance gate, regression detection |
| Constraint System (20) | Active constraints, verification results | Constraint verification gate |
| Call Graph (05) | Function→function edges, reachability, entry points | Impact simulation gate, security boundary gate |
| Boundary Detection (07) | Data access points, sensitive fields, ORM mappings | Security boundary gate |
| Taint Analysis (15) | Source→sink paths, sanitizer locations, CWE mappings | Security boundary gate enrichment |
| DNA System (24) | Health score, mutation count, genetic diversity | DNA gate input (optional 7th gate criterion) |
| Coupling Analysis (19) | Cycle count, health score, hotspot count | Coupling gate input (impact simulation enrichment) |
| Error Handling (16) | Error gaps, propagation chains, boundary coverage | Error handling gate criterion |
| Constants/Secrets (22) | Secret count by severity, magic number count | Security gate input |
| Wrapper Detection (23) | Wrapper health score, thin delegation count | Wrapper gate input |
| OWASP/CWE Mapping (26) | CWE IDs, OWASP categories per violation | SARIF taxonomy enrichment |
| Storage (02) | drift.db SQLite with WAL mode | All persistence |
| Parsers (01) | ParseResult with AST data | Custom rules AST conditions |
| Scanner (00) | File list, content hashes, git diff | Changed file resolution |

### Downstream Consumers (What Depends on Gates)

| Consumer | What It Reads | Interface |
|----------|--------------|-----------|
| CLI | Gate results, policy list, run history | `drift gate run`, `drift policy` |
| MCP Server | Gate results for AI-assisted quality checks | `drift_quality_gate` tool |
| NAPI Bridge | Gate execution, history queries, preview | `run_quality_gates()`, `query_gate_history()` |
| CI Pipelines | Exit codes, SARIF uploads, JUnit XML | Reporter output |
| IDE / LSP | Real-time gate feedback on file save | Pre-commit mode results |
| DriftEventHandler | Gate lifecycle events | `on_gate_evaluated`, `on_regression_detected` |
| Audit System | Gate run data for degradation tracking | `GateRunRecord` |
| Context Generation | Active violations for AI context | Violation summaries |

---

## 2. V1 Complete Feature Inventory — Preservation Matrix

Every v1 feature is accounted for. Nothing is dropped without replacement.

### 2.1 Core Components (v1 → v2)

| v1 Feature | v1 Implementation | v2 Status | v2 Location |
|-----------|-------------------|-----------|-------------|
| GateOrchestrator (9-step pipeline) | TS, ~200 lines | **UPGRADED** — TS with Rust-backed analysis | §6 |
| GateRegistry (singleton, lazy import) | TS, singleton pattern | **KEPT** — TS, same pattern | §6 |
| ParallelExecutor (single group) | TS, Promise.all | **UPGRADED** — DAG with topological execution | §17 |
| ResultAggregator (severity sort) | TS, simple aggregation | **UPGRADED** — priority-sorted with dedup | §18 |
| BaseGate (scoring, fail-safe, violation IDs) | TS abstract class | **UPGRADED** — Rust trait + TS wrapper | §5 |
| 6 gate implementations | TS, ~30 files | **UPGRADED** — Rust analysis + TS coordination | §5 |
| PolicyLoader (5-step resolution) | TS, JSON only | **UPGRADED** — YAML + JSON + inheritance | §7 |
| PolicyEvaluator (4 aggregation modes) | TS, 4 modes | **KEPT** — all 4 modes preserved exactly | §7 |
| 4 built-in policies | TS, hardcoded | **UPGRADED** — 4 built-in + custom + packs | §7 |
| 5 reporters (text/JSON/SARIF/GitHub/GitLab) | TS, 5 files | **UPGRADED** — 7 reporters + plugin system | §8 |
| SnapshotStore (branch-based, 50/branch) | TS, JSON files | **UPGRADED** — SQLite, configurable retention | §9 |
| GateRunStore (100 run history) | TS, JSON files | **UPGRADED** — SQLite, unlimited with retention | §9 |
| Types (~1300 lines, 40+ interfaces) | TS types.ts | **UPGRADED** — Rust types + TS mirrors | §4 |
| AuditEngine (5-step pipeline) | TS, ~300 lines | **UPGRADED** — Rust health scoring | §10 |
| AuditStore (degradation tracking) | TS, JSON files | **UPGRADED** — SQLite, 90-day history | §10 |
| License gating (Community/Team/Enterprise) | TS, feature flags | **KEPT** — same tier mapping | §31 |
| MCP integration (drift_quality_gate) | TS MCP handler | **KEPT** — calls Rust via NAPI | §30 |
| CLI integration (drift gate run) | TS CLI handler | **UPGRADED** — new flags: --mode, --dry-run | §29 |

### 2.2 Gate Algorithms (v1 → v2)

| v1 Algorithm | v1 Complexity | v2 Status | v2 Changes |
|-------------|---------------|-----------|------------|
| Gate scoring (error=10, warning=3, info=1) | O(v) | **KEPT** — same penalty weights | Configurable per-gate |
| Pattern compliance rate | O(p) | **UPGRADED** — new-code-first mode | Only new violations block |
| Regression severity classification | O(p) | **UPGRADED** — statistical significance | Noise filtering added |
| Friction score calculation | O(f×d) | **KEPT** — same formula | Rust implementation |
| Security boundary check | O(a×d) | **UPGRADED** — CWE/OWASP enrichment | Taint integration |
| Policy aggregation (4 modes) | O(g) | **KEPT** — all 4 modes preserved | Required gates always block |
| Health score (5-factor weighted) | O(p) | **KEPT** — same weights (0.30/0.20/0.20/0.15/0.15) | Preserved exactly |
| Duplicate detection (Jaccard) | O(p²×l) | **UPGRADED** — Rust implementation | Same algorithm, faster |
| Degradation tracking (7-day rolling) | O(h) | **KEPT** — same thresholds | SQLite-backed |

### 2.3 V1 Limitations → V2 Resolution

| # | V1 Limitation | V2 Resolution | Section |
|---|--------------|---------------|---------|
| 1 | File-based persistence | SQLite in drift.db | §9 |
| 2 | No gate dependencies | DAG with topological execution | §17 |
| 3 | No incremental gate execution | 3-tier caching strategy | §13 |
| 4 | No caching | Gate-level + per-file + branch caching | §13 |
| 5 | No partial failure recovery | Checkpoint/resume via gate_cache | §23 |
| 6 | No multi-repo support | Enterprise P2 — shared policies via packs | §7 |
| 7 | No policy inheritance | `extends` keyword in YAML policies | §7 |
| 8 | JSON-only custom policies | YAML + JSON support | §7 |
| 9 | No policy versioning | `apiVersion` field with migration | §7 |
| 10 | No gate timeout | Per-gate configurable timeout (30s default) | §23 |
| 11 | No violation dedup across gates | Cross-gate dedup in ResultAggregator | §18 |
| 12 | No historical trend visualization | SQLite queries + materialized views | §9 |
| 13 | No webhook/notification support | Webhook system with template variables | §25 |
| 14 | No dry-run mode | `--dry-run` flag, no persistence | §20 |
| 15 | No gate priority/ordering | Priority field + dependency graph | §17 |
| 16 | Audit O(p²) duplicate detection | Rust implementation (same algorithm, 10-50× faster) | §10 |
| 17 | No custom reporter plugin system | Plugin architecture with discovery | §8 |
| 18 | Security gate is heuristic | CWE/OWASP mapping + taint integration | §22 |
| 19 | Custom rules limited to 6 types | +3 new types: AST, call graph, metric | §24 |
| 20 | No baseline management UI | CLI: `drift gate baseline set/reset/compare` | §29 |

### 2.4 V1 Open Questions → V2 Resolutions

| # | Open Question | Resolution |
|---|--------------|------------|
| 1 | Gate dependencies? | Yes — DAG with topological execution (§17) |
| 2 | Incremental execution via input hashing? | Yes — 3-tier caching (§13) |
| 3 | When to migrate to SQLite? | Day one in v2 — all persistence in drift.db (§9) |
| 4 | Policy YAML support? | Yes — YAML + JSON + inheritance (§7) |
| 5 | Custom reporter plugin system? | Yes — plugin architecture (§8) |
| 6 | Gate timeout defaults? | 30s default, per-gate configurable (§23) |
| 7 | Violation dedup across gates? | Yes — cross-gate dedup by file+line+ruleId (§18) |
| 8 | Webhook integration? | Yes — template-based webhooks (§25) |
| 9 | Dry-run mode? | Yes — `--dry-run` flag (§20) |
| 10 | AST-based custom rules? | Yes — tree-sitter query conditions (§24) |
| 11 | Call-graph-based custom rules? | Yes — source/target path conditions (§24) |
| 12 | Audit health score weights optimal? | Preserved from v1 — configurable per-gate in v2 (§10) |

---

## 3. V2 Architecture — Unified Quality Gates Engine

### Architectural Split: Rust Analysis + TS Orchestration

Quality gates is a hybrid system. Heavy analysis (pattern matching, call graph traversal,
security boundary checking, duplicate detection) runs in Rust for performance. Orchestration
(file resolution, policy loading, gate coordination, reporting) stays in TypeScript for
flexibility and rapid iteration.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PRESENTATION LAYER (TS)                             │
│  CLI (drift gate run)  │  MCP (drift_quality_gate)  │  IDE/LSP  │  CI      │
├─────────────────────────────────────────────────────────────────────────────┤
│                         GATE ORCHESTRATOR (TS)                              │
│  GateOrchestrator → PolicyLoader → GateRegistry → DependencyExecutor       │
│  → PolicyEvaluator → ResultAggregator → PriorityScorer → Reporter          │
├──────────┬──────────┬──────────┬──────────┬──────────┬──────────┬──────────┤
│ Pattern  │Constraint│Regression│ Impact   │ Security │ Custom   │ Audit    │
│Compliance│Verificatn│Detection │Simulation│ Boundary │ Rules    │ Engine   │
│ (Rust)   │ (Rust)   │ (TS)     │ (Rust)   │ (Rust)   │ (Hybrid) │ (Rust)   │
├──────────┴──────────┴──────────┴──────────┴──────────┴──────────┴──────────┤
│                         POLICY ENGINE (TS)                                  │
│  4 Built-in │ Custom YAML/JSON │ Inheritance │ Scope Matching │ Versioning │
├─────────────────────────────────────────────────────────────────────────────┤
│                         ENFORCEMENT MODES (TS + Rust)                       │
│  New-Code-First │ Progressive (Monitor/Comment/Block) │ Multi-Stage        │
├─────────────────────────────────────────────────────────────────────────────┤
│                         REPORTERS (TS)                                      │
│  Text │ JSON │ SARIF 2.1.0 │ GitHub │ GitLab │ JUnit XML │ HTML │ Plugins │
├─────────────────────────────────────────────────────────────────────────────┤
│                         FEEDBACK & INTELLIGENCE (TS + Rust)                 │
│  Feedback Loop │ Violation Prioritization │ Hotspot Scoring │ Explanations │
├─────────────────────────────────────────────────────────────────────────────┤
│                         PERSISTENCE (Rust via drift.db)                     │
│  gate_runs │ health_snapshots │ audit_history │ violation_feedback │ cache  │
├─────────────────────────────────────────────────────────────────────────────┤
│                         NOTIFICATIONS (TS)                                  │
│  Webhooks │ Template Engine │ Slack/PagerDuty/Custom                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

### What Runs in Rust (Performance-Critical)

| Component | Why Rust | Called Via |
|-----------|----------|-----------|
| Pattern compliance analysis | Iterates all patterns × files — hot path | NAPI `run_quality_gates()` |
| Constraint verification | AST-based predicate evaluation | NAPI `verify_constraints()` |
| Impact simulation traversal | Call graph BFS/DFS reachability | NAPI `analyze_impact()` |
| Security boundary checking | Call graph walking + data flow | NAPI `run_quality_gates()` |
| Duplicate detection (audit) | O(p²) Jaccard similarity | NAPI `run_audit()` |
| Health score calculation | Pure math on pattern metrics | NAPI `run_audit()` |
| Gate result caching | SQLite read/write | NAPI `run_quality_gates()` |
| Violation scoring | Multi-factor priority calculation | NAPI `run_quality_gates()` |

### What Stays in TypeScript (Coordination & Formatting)

| Component | Why TS | Rationale |
|-----------|--------|-----------|
| GateOrchestrator | Pure coordination logic | No heavy computation |
| PolicyLoader/Evaluator | Configuration parsing + matching | YAML/JSON handling |
| All Reporters | Output formatting | Template-heavy, format-specific |
| GateRegistry | Registration/instantiation | Simple factory pattern |
| ResultAggregator | Aggregation + dedup | Light computation |
| Webhook/Notification | HTTP calls + templates | I/O-bound, not CPU-bound |
| Custom Rules evaluator (regex/glob) | Regex/glob matching | TS regex is fast enough |
| Feedback UI integration | PR comment actions | GitHub/GitLab API calls |

### Execution Pipeline (V2 — 12 Steps)

```
 1. resolveFiles()         — Resolve file list (changed files for PR mode, all for full)
 2. loadPolicy()           — Load policy via PolicyLoader (YAML/JSON, inheritance, context)
 3. determineGates()       — Filter gates based on policy (enabled, not skipped, licensed)
 4. checkCache()           — Check gate_cache for unchanged inputs (R3)
 5. buildContext()         — Lazy-load only what uncached gates need
 6. executeGates()         — Run gates via DependencyExecutor (DAG ordering, R9)
 7. evaluate()             — Evaluate results against policy via PolicyEvaluator
 8. prioritize()           — Score and sort violations via PriorityScorer (R16)
 9. aggregate()            — Combine into final QualityGateResult via ResultAggregator
10. persist()              — Save snapshot + run history + cache (skip if dry-run)
11. notify()               — Fire webhooks if configured (R18)
12. report()               — Generate output via selected Reporter(s)
```

Steps 4 and 10 are new in v2. Step 8 is new (violation prioritization). Step 11 is new
(webhooks). The core pipeline structure is preserved from v1 with targeted enhancements.

---

## 4. Core Data Model (Rust Types)

### 4.1 Gate Identity & Status

```rust
use serde::{Deserialize, Serialize};
use std::fmt;

/// The 6 quality gate identifiers. All v1 gates preserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GateId {
    PatternCompliance,
    ConstraintVerification,
    RegressionDetection,
    ImpactSimulation,
    SecurityBoundary,
    CustomRules,
}

impl GateId {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PatternCompliance => "pattern-compliance",
            Self::ConstraintVerification => "constraint-verification",
            Self::RegressionDetection => "regression-detection",
            Self::ImpactSimulation => "impact-simulation",
            Self::SecurityBoundary => "security-boundary",
            Self::CustomRules => "custom-rules",
        }
    }

    /// All gate IDs in default execution order.
    pub fn all() -> &'static [GateId] {
        &[
            Self::PatternCompliance,
            Self::ConstraintVerification,
            Self::RegressionDetection,
            Self::ImpactSimulation,
            Self::SecurityBoundary,
            Self::CustomRules,
        ]
    }
}

impl fmt::Display for GateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Gate execution status. All v1 statuses preserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GateStatus {
    Passed,
    Failed,
    Warned,
    Skipped,
    Errored,
}

/// Output format for reporters. V1 formats + JUnit XML + HTML.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Json,
    Text,
    Sarif,
    Github,
    Gitlab,
    Junit,  // NEW: JUnit XML (R8)
    Html,   // NEW: HTML standalone (R8)
}

/// Enforcement mode for progressive enforcement (R2).
/// Patterns progress: Monitor → Comment → Block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnforcementMode {
    /// Tracked internally, not in gate results.
    Monitor,
    /// Appears in PR comments, doesn't block.
    Comment,
    /// Appears in PR comments AND blocks merge.
    Block,
}

/// Gate execution mode (R1, R7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GateMode {
    /// Evaluate only changed files. Only new violations block. Default for PR.
    Pr,
    /// Evaluate all files. All violations reported.
    Full,
    /// Compare current state against baseline. Post-merge checks.
    Regression,
    /// Fast subset — pattern compliance on changed files only. <5s target.
    PreCommit,
}
```

### 4.2 Gate Trait (Rust Interface)

```rust
use crate::errors::DriftResult;

/// The core quality gate trait. All 6 gates implement this.
/// Gates that run heavy analysis in Rust implement evaluate() directly.
/// Gates that stay in TS implement a thin Rust wrapper that delegates.
pub trait QualityGate: Send + Sync {
    /// Unique gate identifier.
    fn id(&self) -> GateId;

    /// Human-readable gate name.
    fn name(&self) -> &'static str;

    /// Human-readable description.
    fn description(&self) -> &'static str;

    /// Execute the gate against the provided input.
    /// Returns a GateResult with pass/fail, score, violations, and details.
    fn evaluate(&self, input: &GateInput) -> DriftResult<GateResult>;

    /// Validate gate-specific configuration.
    fn validate_config(&self, config: &GateConfig) -> ConfigValidation;

    /// Default configuration for this gate.
    fn default_config(&self) -> GateConfig;

    /// Gates this gate depends on (for DAG ordering).
    /// Default: no dependencies.
    fn dependencies(&self) -> &[GateId] {
        &[]
    }

    /// Timeout for this gate in milliseconds.
    /// Default: 30_000 (30 seconds).
    fn timeout_ms(&self) -> u64 {
        30_000
    }
}

/// Configuration validation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigValidation {
    pub valid: bool,
    pub errors: Vec<String>,
}
```

### 4.3 Gate Input & Context

```rust
/// Input provided to each gate by the orchestrator.
#[derive(Debug, Clone)]
pub struct GateInput {
    /// Files to check (changed files in PR mode, all files in full mode).
    pub files: Vec<String>,
    /// All files in the project (for context, even in PR mode).
    pub all_files: Vec<String>,
    /// Gate-specific configuration from the active policy.
    pub config: GateConfig,
    /// Shared context loaded by the orchestrator.
    pub context: GateContext,
    /// Previous health snapshot for regression detection.
    pub previous_snapshot: Option<HealthSnapshot>,
    /// Execution mode (PR, full, regression, pre-commit).
    pub mode: GateMode,
    /// Current branch name.
    pub branch: String,
    /// Current commit SHA (if available).
    pub commit_sha: Option<String>,
    /// Results from predecessor gates (for dependent gates).
    pub predecessor_results: HashMap<GateId, GateResult>,
}

/// Shared context loaded lazily by the orchestrator.
/// Only loads what active gates need.
#[derive(Debug, Clone, Default)]
pub struct GateContext {
    pub project_root: String,
    /// Approved patterns with confidence, locations, outliers.
    pub patterns: Vec<Pattern>,
    /// Active constraints with verification status.
    pub constraints: Vec<Constraint>,
    /// Call graph for impact simulation and security boundary.
    pub call_graph: Option<CallGraphHandle>,
    /// Custom rule definitions.
    pub custom_rules: Vec<CustomRule>,
    /// Git history data for hotspot scoring (R11).
    pub hotspot_data: Option<HotspotData>,
    /// CWE/OWASP mapping registry (R12).
    pub cwe_registry: Option<CweRegistry>,
}

/// Hotspot data from git history analysis (R11).
#[derive(Debug, Clone)]
pub struct HotspotData {
    /// File path → change frequency (commits in last 90 days).
    pub change_frequency: HashMap<String, u32>,
    /// Maximum change frequency across all files (for normalization).
    pub max_frequency: u32,
    /// File path → distinct author count.
    pub author_count: HashMap<String, u32>,
}
```

### 4.4 Gate Result & Violations

```rust
/// Result produced by each gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateResult {
    pub gate_id: GateId,
    pub gate_name: String,
    pub status: GateStatus,
    pub passed: bool,
    pub score: f64,                    // 0-100
    pub summary: String,
    pub violations: Vec<GateViolation>,
    pub warnings: Vec<String>,
    pub execution_time_ms: u64,
    pub details: serde_json::Value,    // Gate-specific details
    pub error: Option<String>,
}

/// Individual violation with structured explanation (R15).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateViolation {
    /// Unique ID: "{gateId}-{file}-{line}-{ruleId}"
    pub id: String,
    pub gate_id: GateId,
    pub rule_id: String,
    pub severity: ViolationSeverity,
    pub message: String,
    pub file: String,
    pub line: u32,
    pub column: Option<u32>,
    pub end_line: Option<u32>,
    pub end_column: Option<u32>,
    pub suggestion: Option<String>,
    /// Whether this violation was introduced by the current change (R1).
    pub is_new: bool,
    /// Author who introduced this violation (via git blame, R16).
    pub author: Option<String>,
    /// Enforcement mode of the pattern that triggered this violation (R2).
    pub enforcement_mode: EnforcementMode,
    /// Structured explanation (R15).
    pub explanation: Option<ViolationExplanation>,
    /// Priority score (0.0-1.0, computed by PriorityScorer, R16).
    pub priority_score: Option<f64>,
    /// CWE ID if applicable (R12).
    pub cwe_id: Option<u32>,
    /// OWASP category if applicable (R12).
    pub owasp_category: Option<String>,
    /// Gate-specific details.
    pub details: Option<serde_json::Value>,
}

/// Violation severity levels. Preserved from v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ViolationSeverity {
    Error,
    Warning,
    Info,
    Hint,
}

impl ViolationSeverity {
    /// Penalty points for gate scoring. Preserved from v1.
    pub fn penalty(&self) -> u32 {
        match self {
            Self::Error => 10,
            Self::Warning => 3,
            Self::Info => 1,
            Self::Hint => 0,
        }
    }
}

/// Structured violation explanation (R15).
/// WHY it's a violation, WHAT's expected, HOW to fix, IMPACT if not fixed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViolationExplanation {
    /// Why this is a violation.
    pub why: String,
    /// What the expected pattern/behavior is.
    pub expected: String,
    /// How to fix the violation.
    pub how_to_fix: String,
    /// Impact of not fixing.
    pub impact: String,
    /// URL to documentation or CWE reference.
    pub learn_more: Option<String>,
    /// Related pattern IDs that define the expected behavior.
    pub related_patterns: Vec<String>,
}
```

### 4.5 Aggregated Result

```rust
/// Final aggregated quality gate result. Preserved from v1 with extensions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityGateResult {
    pub passed: bool,
    pub status: GateStatus,
    pub score: f64,
    pub summary: String,
    pub gates: HashMap<GateId, GateResult>,
    /// All violations sorted by priority score (R16).
    pub violations: Vec<GateViolation>,
    pub warnings: Vec<String>,
    pub policy: PolicySummary,
    pub metadata: GateRunMetadata,
    pub exit_code: i32,
    /// Whether this was a dry-run (R17).
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySummary {
    pub id: String,
    pub name: String,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateRunMetadata {
    pub execution_time_ms: u64,
    pub files_checked: u32,
    pub gates_run: Vec<GateId>,
    pub gates_skipped: Vec<GateId>,
    pub gates_cached: Vec<GateId>,  // NEW: gates served from cache (R3)
    pub timestamp: String,
    pub branch: String,
    pub commit_sha: Option<String>,
    pub ci: bool,
    pub mode: GateMode,             // NEW: execution mode (R1)
    pub new_violations: u32,        // NEW: count of new violations only (R1)
    pub total_violations: u32,
}
```

### 4.6 Per-Gate Configuration Types

```rust
/// Gate-specific configuration. Deserialized from policy YAML/JSON.
/// Each variant preserves all v1 config fields + v2 additions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "gate")]
pub enum GateConfig {
    PatternCompliance(PatternComplianceConfig),
    ConstraintVerification(ConstraintVerificationConfig),
    RegressionDetection(RegressionDetectionConfig),
    ImpactSimulation(ImpactSimulationConfig),
    SecurityBoundary(SecurityBoundaryConfig),
    CustomRules(CustomRulesConfig),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternComplianceConfig {
    pub enabled: bool,
    pub blocking: bool,
    pub min_compliance_rate: f64,       // 0-100, default: 80
    pub max_new_outliers: u32,          // default: 0
    #[serde(default)]
    pub categories: Vec<String>,        // empty = all
    pub min_pattern_confidence: f64,    // default: 0.7
    pub approved_only: bool,            // default: true
    /// Minimum enforcement mode to include (R2). Default: Block.
    pub min_enforcement_mode: EnforcementMode,
    /// Hotspot multiplier for violation scoring (R11). Default: 0.5.
    pub hotspot_multiplier: f64,
    /// Timeout in milliseconds. Default: 15_000.
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintVerificationConfig {
    pub enabled: bool,
    pub blocking: bool,
    pub enforce_approved: bool,         // default: true
    pub enforce_discovered: bool,       // default: false
    pub min_confidence: f64,            // default: 0.9
    #[serde(default)]
    pub categories: Vec<String>,        // empty = all
    /// Baseline-aware: only new violations cause failure (R1).
    pub baseline_aware: bool,           // default: true
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionDetectionConfig {
    pub enabled: bool,
    pub blocking: bool,
    pub max_confidence_drop: f64,       // percentage points, default: 5
    pub max_compliance_drop: f64,       // percentage points, default: 10
    pub max_new_outliers_per_pattern: u32, // default: 3
    #[serde(default)]
    pub critical_categories: Vec<String>, // default: ["auth", "security"]
    pub baseline: BaselineSource,
    /// Statistical significance threshold (R10). Default: 0.05.
    pub significance_threshold: f64,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BaselineSource {
    BranchBase,
    PreviousRun,
    Snapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactSimulationConfig {
    pub enabled: bool,
    pub blocking: bool,
    pub max_files_affected: u32,        // default: 20
    pub max_functions_affected: u32,    // default: 50
    pub max_entry_points_affected: u32, // default: 10
    pub max_friction_score: f64,        // 0-100, default: 60
    pub analyze_sensitive_data: bool,   // default: true
    /// Include coupling depth in blast radius (from 19-COUPLING).
    pub include_coupling: bool,         // default: true
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityBoundaryConfig {
    pub enabled: bool,
    pub blocking: bool,
    pub allow_new_sensitive_access: bool, // default: false
    #[serde(default = "default_protected_tables")]
    pub protected_tables: Vec<String>,
    pub max_data_flow_depth: u32,       // default: 5
    #[serde(default = "default_auth_patterns")]
    pub required_auth_patterns: Vec<String>,
    /// Include taint analysis paths (from 15-TAINT).
    pub include_taint: bool,            // default: true
    /// Include CWE/OWASP mapping (R12).
    pub include_cwe_mapping: bool,      // default: true
    pub timeout_ms: Option<u64>,
}

fn default_protected_tables() -> Vec<String> {
    vec![
        "users".into(), "payments".into(),
        "credentials".into(), "tokens".into(),
    ]
}

fn default_auth_patterns() -> Vec<String> {
    vec![
        "authenticate".into(), "authorize".into(),
        "checkAuth".into(), "requireAuth".into(),
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRulesConfig {
    pub enabled: bool,
    pub blocking: bool,
    #[serde(default)]
    pub rule_files: Vec<String>,        // Paths to rule YAML/JSON files
    #[serde(default)]
    pub inline_rules: Vec<CustomRule>,  // Inline rule definitions
    pub use_built_in_rules: bool,       // default: false
    pub timeout_ms: Option<u64>,
}
```

### 4.7 Per-Gate Detail Types

```rust
/// Pattern compliance gate details. Preserved from v1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternComplianceDetails {
    pub total_patterns: u32,
    pub checked_patterns: u32,
    pub compliance_rate: f64,
    pub new_outliers: u32,
    pub outlier_details: Vec<OutlierDetail>,
    pub by_category: HashMap<String, CategoryCompliance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryCompliance {
    pub patterns: u32,
    pub compliance: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutlierDetail {
    pub pattern_id: String,
    pub pattern_name: String,
    pub file: String,
    pub line: u32,
    pub is_new: bool,
}

/// Regression detection gate details. Preserved from v1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionDetectionDetails {
    pub baseline_source: String,
    pub regressions: Vec<PatternRegression>,
    pub improvements: Vec<PatternImprovement>,
    pub category_deltas: HashMap<String, f64>,
    pub overall_delta: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternRegression {
    pub pattern_id: String,
    pub pattern_name: String,
    pub category: String,
    pub previous_confidence: f64,
    pub current_confidence: f64,
    pub confidence_delta: f64,
    pub previous_compliance: f64,
    pub current_compliance: f64,
    pub compliance_delta: f64,
    pub new_outliers: u32,
    pub severity: RegressionSeverity,
    /// Whether the regression is statistically significant (R10).
    pub statistically_significant: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegressionSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternImprovement {
    pub pattern_id: String,
    pub pattern_name: String,
    pub confidence_delta: f64,
    pub compliance_delta: f64,
}

/// Impact simulation gate details. Preserved from v1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactSimulationDetails {
    pub files_affected: u32,
    pub functions_affected: u32,
    pub entry_points_affected: u32,
    pub sensitive_data_paths: Vec<SensitiveDataPath>,
    pub friction_score: f64,
    pub breaking_risk: BreakingRisk,
    pub affected_files: Vec<AffectedFile>,
    /// Coupling depth from coupling analysis (from 19-COUPLING).
    pub coupling_depth: Option<u32>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BreakingRisk {
    Critical,
    High,
    Medium,
    Low,
}

/// Security boundary gate details. Preserved from v1 + CWE/OWASP (R12).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityBoundaryDetails {
    pub data_access_points: Vec<DataAccessPoint>,
    pub unauthorized_paths: Vec<UnauthorizedPath>,
    pub new_sensitive_access: u32,
    pub protected_tables_accessed: Vec<String>,
    pub auth_coverage: f64,
    /// CWE IDs found in this gate run (R12).
    pub cwe_ids: Vec<u32>,
    /// OWASP categories found (R12).
    pub owasp_categories: Vec<String>,
}

/// Custom rules gate details. Preserved from v1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRulesDetails {
    pub total_rules: u32,
    pub rules_evaluated: u32,
    pub rules_passed: u32,
    pub rules_failed: u32,
    pub results: Vec<RuleResult>,
}

/// Constraint verification gate details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintVerificationDetails {
    pub total_constraints: u32,
    pub checked_constraints: u32,
    pub passed_constraints: u32,
    pub failed_constraints: u32,
    pub new_violations: u32,
    pub baseline_violations: u32,
}
```

### 4.8 Custom Rule Condition Types (V1 6 + V2 3 = 9 Total)

```rust
/// Custom rule condition types. V1's 6 types + 3 new (R14).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum RuleCondition {
    // ── V1 Conditions (all 6 preserved) ──
    /// Files matching glob must/must-not exist.
    FilePattern {
        pattern: String,
        must_exist: bool,
    },
    /// File content must/must-not match regex.
    ContentPattern {
        pattern: String,
        scope: Option<String>,  // glob for files to check
        must_match: bool,
    },
    /// Package must/must-not be in dependencies.
    Dependency {
        package: String,
        version: Option<String>,
        must_exist: bool,
    },
    /// Files/functions must follow naming convention.
    Naming {
        pattern: String,        // regex for names
        scope: String,          // "files" | "functions" | "classes" | "variables"
        target: String,         // glob for files to check
    },
    /// Directory must contain required files.
    Structure {
        directory: String,
        required_files: Vec<String>,
    },
    /// AND/OR/NOT combinations of other conditions.
    Composite {
        operator: CompositeOperator,
        conditions: Vec<RuleCondition>,
    },

    // ── V2 New Conditions (R14) ──
    /// Tree-sitter AST query condition.
    AstQuery {
        query: String,          // tree-sitter query string
        scope: Option<String>,  // glob for files to check
        must_match: bool,       // true = must match, false = must not match
        language: Option<String>, // auto-detect if not specified
    },
    /// Call graph path condition.
    CallGraph {
        source: PathPattern,    // source function/file pattern
        target: PathPattern,    // target function/file pattern
        must_exist: bool,       // true = path must exist, false = must not exist
    },
    /// Metric threshold condition.
    Metric {
        metric: String,         // "cyclomatic-complexity", "coupling", etc.
        threshold: f64,
        operator: MetricOperator,
        scope: Option<String>,  // glob for files to check
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CompositeOperator {
    And,
    Or,
    Not,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathPattern {
    pub pattern: String,        // glob pattern for file paths
    pub function: Option<String>, // regex for function names
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MetricOperator {
    LessThan,
    LessThanOrEqual,
    GreaterThan,
    GreaterThanOrEqual,
    Equal,
}
```

### 4.9 Upstream Gate Input Types (From Other V2 Prep Docs)

These types are defined in their respective subsystems and consumed by quality gates.

```rust
/// From 19-COUPLING-ANALYSIS-V2-PREP.md §20.
/// Input for quality gate coupling checks.
pub struct CouplingGateInput {
    pub health_score: f64,
    pub cycle_count: u32,
    pub hotspot_count: u32,
    pub max_instability: f64,
    pub zone_of_pain_count: u32,
}

/// From 24-DNA-SYSTEM-V2-PREP.md §22.
/// Input to the DNA quality gate.
pub struct DnaGateInput {
    pub health_score: u32,
    pub mutation_count: u32,
    pub high_impact_mutations: u32,
    pub genes_without_dominant: u32,
    pub genetic_diversity: f64,
}

/// From 22-CONSTANTS-ENVIRONMENT-V2-PREP.md §22.
/// Input to the security quality gate from constants analysis.
pub struct SecurityGateInput {
    pub critical_secrets: usize,
    pub high_secrets: usize,
    pub medium_secrets: usize,
    pub magic_number_count: usize,
}

/// From 23-WRAPPER-DETECTION-V2-PREP.md.
/// Input for wrapper-related quality gate checks.
pub struct WrapperGateInput {
    pub health_score: f32,
    pub total_wrappers: u32,
    pub thin_delegation_count: u32,
}
```

---

## 5. The 6 Quality Gates — Rust Implementations

### 5.1 Base Gate Scoring Algorithm

All gates use the same scoring formula. Preserved exactly from v1.

```rust
/// Calculate gate score from violations.
/// Penalty: error=10, warning=3, info=1, hint=0.
/// Score = max(0, 100 - (total_penalty / max_penalty) × 100)
///
/// With hotspot multiplier (R11):
/// adjusted_penalty = base_penalty × (1 + hotspot_score × hotspot_multiplier)
pub fn calculate_score(
    violations: &[GateViolation],
    hotspot_data: Option<&HotspotData>,
    hotspot_multiplier: f64,
) -> f64 {
    if violations.is_empty() {
        return 100.0;
    }

    let max_penalty = violations.len() as f64 * 10.0; // worst case: all errors
    let total_penalty: f64 = violations.iter().map(|v| {
        let base = v.severity.penalty() as f64;
        if let Some(hotspots) = hotspot_data {
            let freq = hotspots.change_frequency
                .get(&v.file)
                .copied()
                .unwrap_or(0) as f64;
            let hotspot_score = if hotspots.max_frequency > 0 {
                freq / hotspots.max_frequency as f64
            } else {
                0.0
            };
            base * (1.0 + hotspot_score * hotspot_multiplier)
        } else {
            base
        }
    }).sum();

    (100.0 - (total_penalty / max_penalty) * 100.0).max(0.0)
}

/// Determine gate status from score and config threshold.
pub fn determine_status(score: f64, threshold: f64, has_errors: bool) -> GateStatus {
    if has_errors || score < threshold {
        GateStatus::Failed
    } else if score < threshold + 10.0 {
        GateStatus::Warned
    } else {
        GateStatus::Passed
    }
}

/// Generate violation ID. Preserved from v1.
/// Format: "{gateId}-{file}-{line}-{ruleId}"
pub fn violation_id(gate_id: GateId, file: &str, line: u32, rule_id: &str) -> String {
    format!("{}-{}-{}-{}", gate_id, file, line, rule_id)
}

/// Fail-safe: errored gates return passed: true.
/// Preserved from v1 — errors don't block.
pub fn error_result(gate_id: GateId, gate_name: &str, error: String) -> GateResult {
    GateResult {
        gate_id,
        gate_name: gate_name.to_string(),
        status: GateStatus::Errored,
        passed: true, // FAIL-SAFE: errors don't block
        score: 0.0,
        summary: format!("Gate errored: {error}"),
        violations: vec![],
        warnings: vec![format!("Gate execution failed: {error}")],
        execution_time_ms: 0,
        details: serde_json::Value::Null,
        error: Some(error),
    }
}
```

### 5.2 Gate 1: Pattern Compliance

```rust
/// Pattern Compliance Gate — Are approved patterns being followed?
///
/// V1 algorithm preserved. V2 additions:
/// - New-code-first mode (R1): only new outliers in changed files block
/// - Progressive enforcement (R2): filter by enforcement mode
/// - Hotspot-aware scoring (R11): violations in hotspots weighted higher
/// - Structured explanations (R15): WHY/WHAT/HOW/IMPACT per violation
pub struct PatternComplianceGate;

impl QualityGate for PatternComplianceGate {
    fn id(&self) -> GateId { GateId::PatternCompliance }
    fn name(&self) -> &'static str { "Pattern Compliance" }
    fn description(&self) -> &'static str {
        "Checks whether approved patterns are being followed and detects new outliers"
    }

    fn evaluate(&self, input: &GateInput) -> DriftResult<GateResult> {
        let config = input.config.as_pattern_compliance()?;
        let start = std::time::Instant::now();

        // 1. Filter patterns by config
        let patterns: Vec<_> = input.context.patterns.iter()
            .filter(|p| config.approved_only && p.status == PatternStatus::Approved)
            .filter(|p| p.confidence >= config.min_pattern_confidence)
            .filter(|p| config.categories.is_empty()
                || config.categories.contains(&p.category))
            .filter(|p| p.enforcement_mode >= config.min_enforcement_mode) // R2
            .collect();

        let mut violations = Vec::new();
        let mut total_locations = 0u64;
        let mut total_outliers = 0u64;
        let mut new_outliers = 0u32;
        let mut by_category: HashMap<String, CategoryCompliance> = HashMap::new();

        // 2. Calculate compliance per pattern
        for pattern in &patterns {
            let locations = pattern.location_count as u64;
            let outliers = pattern.outlier_count as u64;
            total_locations += locations;
            total_outliers += outliers;

            let compliance = if locations + outliers > 0 {
                locations as f64 / (locations + outliers) as f64
            } else {
                1.0
            };

            // Track by category
            let cat = by_category.entry(pattern.category.clone())
                .or_insert(CategoryCompliance { patterns: 0, compliance: 0.0 });
            cat.patterns += 1;
            cat.compliance += compliance;

            // 3. Detect new outliers in changed files (R1)
            for outlier in &pattern.outliers {
                let is_new = input.mode == GateMode::Pr
                    && input.files.contains(&outlier.file);

                if is_new {
                    new_outliers += 1;
                }

                // Only create violations for blocking enforcement mode
                if pattern.enforcement_mode == EnforcementMode::Block
                    || (pattern.enforcement_mode == EnforcementMode::Comment
                        && !config.blocking)
                {
                    violations.push(GateViolation {
                        id: violation_id(GateId::PatternCompliance,
                            &outlier.file, outlier.line, &pattern.id),
                        gate_id: GateId::PatternCompliance,
                        rule_id: pattern.id.clone(),
                        severity: ViolationSeverity::Warning,
                        message: format!(
                            "Outlier: {} deviates from pattern '{}'",
                            outlier.file, pattern.name
                        ),
                        file: outlier.file.clone(),
                        line: outlier.line,
                        column: None,
                        end_line: None,
                        end_column: None,
                        suggestion: pattern.suggestion.clone(),
                        is_new,
                        author: None, // populated by PriorityScorer
                        enforcement_mode: pattern.enforcement_mode,
                        explanation: Some(ViolationExplanation {
                            why: format!(
                                "This code deviates from the '{}' pattern (confidence: {:.0}%)",
                                pattern.name, pattern.confidence * 100.0
                            ),
                            expected: pattern.description.clone(),
                            how_to_fix: pattern.suggestion.clone()
                                .unwrap_or_else(|| "Follow the established pattern".into()),
                            impact: format!(
                                "Inconsistent code increases maintenance cost. {} other locations follow this pattern.",
                                pattern.location_count
                            ),
                            learn_more: None,
                            related_patterns: vec![pattern.id.clone()],
                        }),
                        priority_score: None,
                        cwe_id: None,
                        owasp_category: None,
                        details: None,
                    });
                }
            }
        }

        // 4. Evaluate thresholds
        let overall_compliance = if total_locations + total_outliers > 0 {
            total_locations as f64 / (total_locations + total_outliers) as f64 * 100.0
        } else {
            100.0
        };

        // In PR mode, only new violations can block (R1)
        let blocking_violations = if input.mode == GateMode::Pr {
            violations.iter().filter(|v| v.is_new).count()
        } else {
            violations.len()
        };

        let passed = overall_compliance >= config.min_compliance_rate
            && (input.mode == GateMode::Pr
                ? new_outliers <= config.max_new_outliers
                : true);

        // Normalize category compliance
        for cat in by_category.values_mut() {
            if cat.patterns > 0 {
                cat.compliance /= cat.patterns as f64;
            }
        }

        let score = calculate_score(
            &violations,
            input.context.hotspot_data.as_ref(),
            config.hotspot_multiplier,
        );

        Ok(GateResult {
            gate_id: self.id(),
            gate_name: self.name().to_string(),
            status: determine_status(score, config.min_compliance_rate, !passed),
            passed,
            score,
            summary: format!(
                "Compliance: {:.1}% ({} patterns, {} new outliers)",
                overall_compliance, patterns.len(), new_outliers
            ),
            violations,
            warnings: vec![],
            execution_time_ms: start.elapsed().as_millis() as u64,
            details: serde_json::to_value(PatternComplianceDetails {
                total_patterns: patterns.len() as u32,
                checked_patterns: patterns.len() as u32,
                compliance_rate: overall_compliance,
                new_outliers,
                outlier_details: vec![], // populated from violations
                by_category,
            })?,
            error: None,
        })
    }

    fn default_config(&self) -> GateConfig {
        GateConfig::PatternCompliance(PatternComplianceConfig {
            enabled: true,
            blocking: true,
            min_compliance_rate: 80.0,
            max_new_outliers: 0,
            categories: vec![],
            min_pattern_confidence: 0.7,
            approved_only: true,
            min_enforcement_mode: EnforcementMode::Block,
            hotspot_multiplier: 0.5,
            timeout_ms: Some(15_000),
        })
    }

    fn validate_config(&self, config: &GateConfig) -> ConfigValidation {
        // validation logic
        ConfigValidation { valid: true, errors: vec![] }
    }
}
```

### 5.3 Gate 2: Constraint Verification

```rust
/// Constraint Verification Gate — Do code changes satisfy architectural constraints?
///
/// Delegates to the ConstraintVerifier from 20-CONSTRAINT-SYSTEM-V2-PREP.md §12.1.
/// V2 addition: baseline-aware — only new violations cause failure (R1).
pub struct ConstraintVerificationGate {
    verifier: Arc<ConstraintVerifier>,
}

impl QualityGate for ConstraintVerificationGate {
    fn id(&self) -> GateId { GateId::ConstraintVerification }
    fn name(&self) -> &'static str { "Constraint Verification" }
    fn description(&self) -> &'static str {
        "Verifies that code changes satisfy architectural constraints"
    }

    fn evaluate(&self, input: &GateInput) -> DriftResult<GateResult> {
        let config = input.config.as_constraint_verification()?;
        let start = std::time::Instant::now();

        let files_to_check = if input.mode == GateMode::Pr {
            &input.files
        } else {
            &input.all_files
        };

        let mut total_new = 0u32;
        let mut total_baseline = 0u32;
        let mut violations = Vec::new();

        for file in files_to_check {
            let result = self.verifier.verify_file(file)?;
            for violation in &result.violations {
                let is_new = !violation.is_baseline;
                if is_new { total_new += 1; } else { total_baseline += 1; }

                violations.push(GateViolation {
                    id: violation_id(self.id(), file, violation.line, &violation.constraint_id),
                    gate_id: self.id(),
                    rule_id: violation.constraint_id.clone(),
                    severity: match violation.enforcement_level {
                        EnforcementLevel::Error => ViolationSeverity::Error,
                        EnforcementLevel::Warning => ViolationSeverity::Warning,
                        EnforcementLevel::Info => ViolationSeverity::Info,
                    },
                    message: violation.message.clone(),
                    file: file.clone(),
                    line: violation.line,
                    is_new,
                    enforcement_mode: EnforcementMode::Block,
                    explanation: Some(ViolationExplanation {
                        why: format!("Constraint '{}' violated", violation.constraint_name),
                        expected: violation.expected.clone(),
                        how_to_fix: violation.suggestion.clone()
                            .unwrap_or_else(|| "Fix the constraint violation".into()),
                        impact: "Architectural constraint violations can lead to technical debt".into(),
                        learn_more: None,
                        related_patterns: vec![],
                    }),
                    ..Default::default()
                });
            }
        }

        // Baseline-aware: only new violations cause failure (R1)
        let passed = if config.baseline_aware {
            total_new == 0
        } else {
            total_new + total_baseline == 0
        };

        let score = calculate_score(&violations, None, 0.0);

        Ok(GateResult {
            gate_id: self.id(),
            gate_name: self.name().to_string(),
            status: determine_status(score, 70.0, !passed),
            passed,
            score,
            summary: format!("{} new violations, {} baseline", total_new, total_baseline),
            violations,
            warnings: vec![],
            execution_time_ms: start.elapsed().as_millis() as u64,
            details: serde_json::to_value(ConstraintVerificationDetails {
                total_constraints: input.context.constraints.len() as u32,
                checked_constraints: input.context.constraints.len() as u32,
                passed_constraints: input.context.constraints.len() as u32 - total_new,
                failed_constraints: total_new,
                new_violations: total_new,
                baseline_violations: total_baseline,
            })?,
            error: None,
        })
    }

    fn default_config(&self) -> GateConfig {
        GateConfig::ConstraintVerification(ConstraintVerificationConfig {
            enabled: true,
            blocking: true,
            enforce_approved: true,
            enforce_discovered: false,
            min_confidence: 0.9,
            categories: vec![],
            baseline_aware: true,
            timeout_ms: Some(30_000),
        })
    }

    fn validate_config(&self, _config: &GateConfig) -> ConfigValidation {
        ConfigValidation { valid: true, errors: vec![] }
    }
}
```

### 5.4 Gate 3: Regression Detection

```rust
/// Regression Detection Gate — Has pattern confidence/compliance dropped vs baseline?
///
/// V1 algorithm preserved. V2 additions:
/// - Statistical significance testing (R10/QG-R10)
/// - Noise filtering via standard deviation
/// - Root cause attribution to specific file changes
pub struct RegressionDetectionGate;

impl QualityGate for RegressionDetectionGate {
    fn id(&self) -> GateId { GateId::RegressionDetection }
    fn name(&self) -> &'static str { "Regression Detection" }
    fn description(&self) -> &'static str {
        "Detects drops in pattern confidence or compliance compared to baseline"
    }

    fn dependencies(&self) -> &[GateId] {
        // Can use pattern compliance results for current state
        &[GateId::PatternCompliance]
    }

    fn evaluate(&self, input: &GateInput) -> DriftResult<GateResult> {
        let config = input.config.as_regression_detection()?;
        let start = std::time::Instant::now();

        let baseline = match &input.previous_snapshot {
            Some(snapshot) => snapshot,
            None => {
                return Ok(GateResult {
                    gate_id: self.id(),
                    gate_name: self.name().to_string(),
                    status: GateStatus::Skipped,
                    passed: true,
                    score: 100.0,
                    summary: "No baseline snapshot available — skipping".into(),
                    violations: vec![],
                    warnings: vec!["No baseline snapshot for regression comparison".into()],
                    execution_time_ms: start.elapsed().as_millis() as u64,
                    details: serde_json::Value::Null,
                    error: None,
                });
            }
        };

        let mut regressions = Vec::new();
        let mut improvements = Vec::new();
        let mut violations = Vec::new();

        for pattern in &input.context.patterns {
            if let Some(baseline_pattern) = baseline.find_pattern(&pattern.id) {
                let conf_delta = pattern.confidence - baseline_pattern.confidence;
                let comp_delta = pattern.compliance_rate() - baseline_pattern.compliance_rate();

                // V2: Statistical significance check (R10)
                let significant = is_statistically_significant(
                    conf_delta,
                    pattern.location_count,
                    config.significance_threshold,
                );

                if conf_delta < 0.0 && significant {
                    let severity = classify_regression_severity(
                        conf_delta,
                        comp_delta,
                        &pattern.category,
                        &config,
                    );

                    regressions.push(PatternRegression {
                        pattern_id: pattern.id.clone(),
                        pattern_name: pattern.name.clone(),
                        category: pattern.category.clone(),
                        previous_confidence: baseline_pattern.confidence,
                        current_confidence: pattern.confidence,
                        confidence_delta: conf_delta,
                        previous_compliance: baseline_pattern.compliance_rate(),
                        current_compliance: pattern.compliance_rate(),
                        compliance_delta: comp_delta,
                        new_outliers: pattern.outlier_count
                            .saturating_sub(baseline_pattern.outlier_count),
                        severity,
                        statistically_significant: significant,
                    });

                    violations.push(GateViolation {
                        id: violation_id(self.id(), &pattern.category, 0, &pattern.id),
                        gate_id: self.id(),
                        rule_id: format!("regression-{}", pattern.id),
                        severity: match severity {
                            RegressionSeverity::Critical => ViolationSeverity::Error,
                            RegressionSeverity::High => ViolationSeverity::Error,
                            RegressionSeverity::Medium => ViolationSeverity::Warning,
                            RegressionSeverity::Low => ViolationSeverity::Info,
                        },
                        message: format!(
                            "Pattern '{}' regressed: confidence {:.1}% → {:.1}% (Δ{:.1}%)",
                            pattern.name,
                            baseline_pattern.confidence * 100.0,
                            pattern.confidence * 100.0,
                            conf_delta * 100.0,
                        ),
                        file: String::new(),
                        line: 0,
                        is_new: true,
                        enforcement_mode: EnforcementMode::Block,
                        explanation: Some(ViolationExplanation {
                            why: format!(
                                "Pattern confidence dropped by {:.1}% since the baseline",
                                conf_delta.abs() * 100.0
                            ),
                            expected: format!(
                                "Pattern confidence should remain within {:.0}% of baseline",
                                config.max_confidence_drop
                            ),
                            how_to_fix: "Review recent changes that may have introduced outliers".into(),
                            impact: "Declining pattern confidence indicates codebase drift".into(),
                            learn_more: None,
                            related_patterns: vec![pattern.id.clone()],
                        }),
                        ..Default::default()
                    });
                } else if conf_delta > 0.0 {
                    improvements.push(PatternImprovement {
                        pattern_id: pattern.id.clone(),
                        pattern_name: pattern.name.clone(),
                        confidence_delta: conf_delta,
                        compliance_delta: comp_delta,
                    });
                }
            }
        }

        let overall_delta = if !regressions.is_empty() {
            regressions.iter().map(|r| r.confidence_delta).sum::<f64>()
                / regressions.len() as f64
        } else {
            0.0
        };

        let passed = regressions.iter().all(|r| {
            r.confidence_delta.abs() * 100.0 <= config.max_confidence_drop
        });

        let score = calculate_score(&violations, None, 0.0);

        Ok(GateResult {
            gate_id: self.id(),
            gate_name: self.name().to_string(),
            status: determine_status(score, 70.0, !passed),
            passed,
            score,
            summary: format!(
                "{} regressions, {} improvements (overall Δ{:.1}%)",
                regressions.len(), improvements.len(), overall_delta * 100.0
            ),
            violations,
            warnings: vec![],
            execution_time_ms: start.elapsed().as_millis() as u64,
            details: serde_json::to_value(RegressionDetectionDetails {
                baseline_source: format!("{:?}", config.baseline),
                regressions,
                improvements,
                category_deltas: HashMap::new(), // computed from regressions
                overall_delta,
            })?,
            error: None,
        })
    }

    fn default_config(&self) -> GateConfig {
        GateConfig::RegressionDetection(RegressionDetectionConfig {
            enabled: true,
            blocking: false, // Warning only by default
            max_confidence_drop: 5.0,
            max_compliance_drop: 10.0,
            max_new_outliers_per_pattern: 3,
            critical_categories: vec!["auth".into(), "security".into()],
            baseline: BaselineSource::BranchBase,
            significance_threshold: 0.05,
            timeout_ms: Some(30_000),
        })
    }

    fn validate_config(&self, _config: &GateConfig) -> ConfigValidation {
        ConfigValidation { valid: true, errors: vec![] }
    }
}

/// Classify regression severity. Preserved from v1.
fn classify_regression_severity(
    conf_delta: f64,
    comp_delta: f64,
    category: &str,
    config: &RegressionDetectionConfig,
) -> RegressionSeverity {
    let conf_drop = conf_delta.abs() * 100.0;
    if conf_drop > config.max_confidence_drop * 2.0
        || config.critical_categories.contains(&category.to_string())
    {
        RegressionSeverity::Critical
    } else if conf_drop > config.max_confidence_drop {
        RegressionSeverity::High
    } else if comp_delta.abs() * 100.0 > config.max_compliance_drop {
        RegressionSeverity::Medium
    } else {
        RegressionSeverity::Low
    }
}

/// Statistical significance test for regression detection (R10/QG-R10).
/// Uses a simple z-test approximation for proportion comparison.
fn is_statistically_significant(
    delta: f64,
    sample_size: u32,
    threshold: f64,
) -> bool {
    if sample_size < 5 {
        return delta.abs() > 0.1; // small sample: use fixed threshold
    }
    // z-test for proportion difference
    let se = (0.5 * 0.5 / sample_size as f64).sqrt();
    let z = delta.abs() / se;
    // p-value approximation: z > 1.96 → p < 0.05
    let critical_z = match threshold {
        t if t <= 0.01 => 2.576,
        t if t <= 0.05 => 1.960,
        t if t <= 0.10 => 1.645,
        _ => 1.960,
    };
    z > critical_z
}
```

### 5.5 Gate 4: Impact Simulation

```rust
/// Impact Simulation Gate — How large is the blast radius of the change?
///
/// V1 algorithm preserved. V2: Rust implementation for call graph traversal.
/// Friction score formula preserved exactly from v1.
pub struct ImpactSimulationGate;

impl QualityGate for ImpactSimulationGate {
    fn id(&self) -> GateId { GateId::ImpactSimulation }
    fn name(&self) -> &'static str { "Impact Simulation" }
    fn description(&self) -> &'static str {
        "Analyzes the blast radius of code changes via call graph traversal"
    }

    fn evaluate(&self, input: &GateInput) -> DriftResult<GateResult> {
        let config = input.config.as_impact_simulation()?;
        let start = std::time::Instant::now();

        let call_graph = input.context.call_graph.as_ref()
            .ok_or_else(|| DriftError::gate("Call graph not available for impact simulation"))?;

        let mut files_affected = HashSet::new();
        let mut functions_affected = HashSet::new();
        let mut entry_points_affected = HashSet::new();
        let mut sensitive_data_paths = Vec::new();
        let mut violations = Vec::new();

        // 1. For each changed file, find functions in the call graph
        for file in &input.files {
            let functions = call_graph.functions_in_file(file);

            for func in &functions {
                // 2. Trace callers (reverse reachability)
                let callers = call_graph.reverse_reachability(
                    &func.id,
                    config.max_data_flow_depth as usize,
                );

                for caller in &callers {
                    functions_affected.insert(caller.id.clone());
                    files_affected.insert(caller.file.clone());

                    // 3. Identify affected entry points
                    if caller.is_entry_point {
                        entry_points_affected.insert(caller.id.clone());
                    }
                }

                // 4. Trace sensitive data paths (if enabled)
                if config.analyze_sensitive_data {
                    let paths = call_graph.trace_sensitive_data(&func.id);
                    sensitive_data_paths.extend(paths);
                }
            }
        }

        // 5. Calculate friction score (PRESERVED from v1)
        let friction_score = {
            let f = files_affected.len() as f64 / config.max_files_affected as f64 * 25.0;
            let fn_ = functions_affected.len() as f64 / config.max_functions_affected as f64 * 25.0;
            let ep = entry_points_affected.len() as f64 / config.max_entry_points_affected as f64 * 30.0;
            let sd = sensitive_data_paths.len() as f64 * 20.0;
            (f + fn_ + ep + sd).min(100.0)
        };

        // 6. Classify breaking risk (PRESERVED from v1)
        let breaking_risk = if friction_score > 80.0 {
            BreakingRisk::Critical
        } else if friction_score > 60.0 {
            BreakingRisk::High
        } else if friction_score > 40.0 {
            BreakingRisk::Medium
        } else {
            BreakingRisk::Low
        };

        // Generate violations for threshold breaches
        if files_affected.len() > config.max_files_affected as usize {
            violations.push(GateViolation {
                id: violation_id(self.id(), "project", 0, "max-files-exceeded"),
                gate_id: self.id(),
                rule_id: "max-files-exceeded".into(),
                severity: ViolationSeverity::Warning,
                message: format!(
                    "Change affects {} files (threshold: {})",
                    files_affected.len(), config.max_files_affected
                ),
                file: String::new(),
                line: 0,
                is_new: true,
                enforcement_mode: EnforcementMode::Block,
                explanation: Some(ViolationExplanation {
                    why: "This change has a large blast radius".into(),
                    expected: format!("Changes should affect ≤{} files", config.max_files_affected),
                    how_to_fix: "Consider breaking this change into smaller, focused PRs".into(),
                    impact: "Large blast radius increases risk of unintended side effects".into(),
                    learn_more: None,
                    related_patterns: vec![],
                }),
                ..Default::default()
            });
        }

        if friction_score > config.max_friction_score {
            violations.push(GateViolation {
                id: violation_id(self.id(), "project", 0, "friction-exceeded"),
                gate_id: self.id(),
                rule_id: "friction-exceeded".into(),
                severity: ViolationSeverity::Error,
                message: format!(
                    "Friction score {:.0} exceeds threshold {:.0}",
                    friction_score, config.max_friction_score
                ),
                file: String::new(),
                line: 0,
                is_new: true,
                enforcement_mode: EnforcementMode::Block,
                ..Default::default()
            });
        }

        let passed = friction_score <= config.max_friction_score;
        let score = (100.0 - friction_score).max(0.0);

        Ok(GateResult {
            gate_id: self.id(),
            gate_name: self.name().to_string(),
            status: determine_status(score, 100.0 - config.max_friction_score, !passed),
            passed,
            score,
            summary: format!(
                "Friction: {:.0}, {} files, {} functions, {} entry points affected",
                friction_score, files_affected.len(),
                functions_affected.len(), entry_points_affected.len()
            ),
            violations,
            warnings: vec![],
            execution_time_ms: start.elapsed().as_millis() as u64,
            details: serde_json::to_value(ImpactSimulationDetails {
                files_affected: files_affected.len() as u32,
                functions_affected: functions_affected.len() as u32,
                entry_points_affected: entry_points_affected.len() as u32,
                sensitive_data_paths,
                friction_score,
                breaking_risk,
                affected_files: vec![], // populated from files_affected
                coupling_depth: None,   // populated from coupling analysis
            })?,
            error: None,
        })
    }

    fn default_config(&self) -> GateConfig {
        GateConfig::ImpactSimulation(ImpactSimulationConfig {
            enabled: true,
            blocking: false, // Warning only by default
            max_files_affected: 20,
            max_functions_affected: 50,
            max_entry_points_affected: 10,
            max_friction_score: 60.0,
            analyze_sensitive_data: true,
            include_coupling: true,
            timeout_ms: Some(30_000),
        })
    }

    fn validate_config(&self, _config: &GateConfig) -> ConfigValidation {
        ConfigValidation { valid: true, errors: vec![] }
    }
}
```

### 5.6 Gate 5: Security Boundary

```rust
/// Security Boundary Gate — Is sensitive data accessed without authentication?
///
/// V1 algorithm preserved. V2 additions:
/// - CWE/OWASP mapping (R12) for every violation
/// - Taint analysis integration (from 15-TAINT)
/// - Structured explanations with call chain (R15)
pub struct SecurityBoundaryGate;

impl QualityGate for SecurityBoundaryGate {
    fn id(&self) -> GateId { GateId::SecurityBoundary }
    fn name(&self) -> &'static str { "Security Boundary" }
    fn description(&self) -> &'static str {
        "Detects unauthorized access to sensitive data without authentication"
    }

    fn dependencies(&self) -> &[GateId] {
        &[GateId::ImpactSimulation] // can reuse affected function set
    }

    fn evaluate(&self, input: &GateInput) -> DriftResult<GateResult> {
        let config = input.config.as_security_boundary()?;
        let start = std::time::Instant::now();

        let call_graph = input.context.call_graph.as_ref()
            .ok_or_else(|| DriftError::gate("Call graph not available for security boundary"))?;

        let mut violations = Vec::new();
        let mut data_access_points = Vec::new();
        let mut unauthorized_paths = Vec::new();
        let mut new_sensitive_access = 0u32;
        let mut cwe_ids = HashSet::new();
        let mut owasp_categories = HashSet::new();

        let files_to_check = if input.mode == GateMode::Pr {
            &input.files
        } else {
            &input.all_files
        };

        for file in files_to_check {
            // 1. Detect data access points
            let access_points = call_graph.data_access_points(file);

            for access in &access_points {
                // 2. Filter for protected tables
                if !config.protected_tables.contains(&access.table) {
                    continue;
                }

                data_access_points.push(access.clone());

                // 3. Check if auth exists in the call chain
                let has_auth = call_graph.has_auth_in_chain(
                    &access.function_id,
                    &config.required_auth_patterns,
                    config.max_data_flow_depth as usize,
                );

                if !has_auth {
                    // 4. Unauthorized path found
                    let is_new = input.previous_snapshot
                        .as_ref()
                        .map(|s| !s.has_access_point(&access.id))
                        .unwrap_or(true);

                    if is_new {
                        new_sensitive_access += 1;
                    }

                    unauthorized_paths.push(UnauthorizedPath {
                        access_point: access.clone(),
                        call_chain: call_graph.get_call_chain(&access.function_id),
                        is_new,
                    });

                    // Map to CWE/OWASP (R12)
                    let cwe = CWE_862; // Missing Authorization
                    let owasp = "A01:2025"; // Broken Access Control
                    cwe_ids.insert(cwe);
                    owasp_categories.insert(owasp.to_string());

                    violations.push(GateViolation {
                        id: violation_id(self.id(), file, access.line, "unauthorized-access"),
                        gate_id: self.id(),
                        rule_id: "unauthorized-access".into(),
                        severity: ViolationSeverity::Error,
                        message: format!(
                            "Unauthorized access to protected table '{}' without auth middleware",
                            access.table
                        ),
                        file: file.clone(),
                        line: access.line,
                        is_new,
                        enforcement_mode: EnforcementMode::Block,
                        cwe_id: Some(862),
                        owasp_category: Some(owasp.to_string()),
                        explanation: Some(ViolationExplanation {
                            why: format!(
                                "This endpoint accesses the '{}' table which contains protected data",
                                access.table
                            ),
                            expected: format!(
                                "All routes accessing protected tables must use one of: {}",
                                config.required_auth_patterns.join(", ")
                            ),
                            how_to_fix: format!(
                                "Add authentication middleware (e.g., {}()) before this route handler",
                                config.required_auth_patterns.first().unwrap_or(&"authenticate".into())
                            ),
                            impact: "Without auth, any unauthenticated request can access protected data".into(),
                            learn_more: Some("https://cwe.mitre.org/data/definitions/862.html".into()),
                            related_patterns: vec![],
                        }),
                        ..Default::default()
                    });
                }
            }
        }

        // Check for new sensitive access (R1)
        let passed = if config.allow_new_sensitive_access {
            true
        } else {
            new_sensitive_access == 0
        };

        let auth_coverage = if !data_access_points.is_empty() {
            1.0 - (unauthorized_paths.len() as f64 / data_access_points.len() as f64)
        } else {
            1.0
        };

        let score = calculate_score(&violations, None, 0.0);

        Ok(GateResult {
            gate_id: self.id(),
            gate_name: self.name().to_string(),
            status: determine_status(score, 70.0, !passed),
            passed,
            score,
            summary: format!(
                "{} unauthorized paths, {} new sensitive access, {:.0}% auth coverage",
                unauthorized_paths.len(), new_sensitive_access, auth_coverage * 100.0
            ),
            violations,
            warnings: vec![],
            execution_time_ms: start.elapsed().as_millis() as u64,
            details: serde_json::to_value(SecurityBoundaryDetails {
                data_access_points,
                unauthorized_paths,
                new_sensitive_access,
                protected_tables_accessed: config.protected_tables.clone(),
                auth_coverage,
                cwe_ids: cwe_ids.into_iter().collect(),
                owasp_categories: owasp_categories.into_iter().collect(),
            })?,
            error: None,
        })
    }

    fn default_config(&self) -> GateConfig {
        GateConfig::SecurityBoundary(SecurityBoundaryConfig {
            enabled: true,
            blocking: true,
            allow_new_sensitive_access: false,
            protected_tables: default_protected_tables(),
            max_data_flow_depth: 5,
            required_auth_patterns: default_auth_patterns(),
            include_taint: true,
            include_cwe_mapping: true,
            timeout_ms: Some(60_000),
        })
    }

    fn validate_config(&self, _config: &GateConfig) -> ConfigValidation {
        ConfigValidation { valid: true, errors: vec![] }
    }
}
```

### 5.7 Gate 6: Custom Rules

```rust
/// Custom Rules Gate — User-defined rules with 9 condition types.
///
/// V1's 6 condition types preserved. V2 adds 3 new: AST, call graph, metric (R14).
/// Built-in rules preserved: no console.log, no TODO/FIXME, test files exist,
/// no hardcoded secrets.
pub struct CustomRulesGate;

impl QualityGate for CustomRulesGate {
    fn id(&self) -> GateId { GateId::CustomRules }
    fn name(&self) -> &'static str { "Custom Rules" }
    fn description(&self) -> &'static str {
        "Evaluates user-defined rules with 9 condition types"
    }

    fn evaluate(&self, input: &GateInput) -> DriftResult<GateResult> {
        let config = input.config.as_custom_rules()?;
        let start = std::time::Instant::now();

        let mut rules = Vec::new();

        // Load rules from files
        for rule_file in &config.rule_files {
            let loaded = load_rules_from_file(rule_file)?;
            rules.extend(loaded);
        }

        // Add inline rules
        rules.extend(config.inline_rules.clone());

        // Add built-in rules if enabled
        if config.use_built_in_rules {
            rules.extend(built_in_rules());
        }

        let mut violations = Vec::new();
        let mut rules_passed = 0u32;
        let mut rules_failed = 0u32;
        let mut results = Vec::new();

        for rule in &rules {
            let result = evaluate_condition(
                &rule.condition,
                &input.files,
                &input.context,
            )?;

            if result.matched {
                rules_failed += 1;
                for location in &result.locations {
                    violations.push(GateViolation {
                        id: violation_id(self.id(), &location.file, location.line, &rule.id),
                        gate_id: self.id(),
                        rule_id: rule.id.clone(),
                        severity: rule.severity,
                        message: rule.message.clone(),
                        file: location.file.clone(),
                        line: location.line,
                        suggestion: rule.suggestion.clone(),
                        is_new: true,
                        enforcement_mode: EnforcementMode::Block,
                        ..Default::default()
                    });
                }
            } else {
                rules_passed += 1;
            }

            results.push(RuleResult {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                passed: !result.matched,
                locations: result.locations,
            });
        }

        let score = calculate_score(&violations, None, 0.0);
        let passed = violations.iter()
            .all(|v| v.severity != ViolationSeverity::Error);

        Ok(GateResult {
            gate_id: self.id(),
            gate_name: self.name().to_string(),
            status: determine_status(score, 70.0, !passed),
            passed,
            score,
            summary: format!(
                "{} rules evaluated, {} passed, {} failed",
                rules.len(), rules_passed, rules_failed
            ),
            violations,
            warnings: vec![],
            execution_time_ms: start.elapsed().as_millis() as u64,
            details: serde_json::to_value(CustomRulesDetails {
                total_rules: rules.len() as u32,
                rules_evaluated: rules.len() as u32,
                rules_passed,
                rules_failed,
                results,
            })?,
            error: None,
        })
    }

    fn default_config(&self) -> GateConfig {
        GateConfig::CustomRules(CustomRulesConfig {
            enabled: false, // Disabled by default
            blocking: false,
            rule_files: vec![],
            inline_rules: vec![],
            use_built_in_rules: false,
            timeout_ms: Some(30_000),
        })
    }

    fn validate_config(&self, _config: &GateConfig) -> ConfigValidation {
        ConfigValidation { valid: true, errors: vec![] }
    }
}

/// Built-in rules (when useBuiltInRules: true). Preserved from v1.
fn built_in_rules() -> Vec<CustomRule> {
    vec![
        CustomRule {
            id: "no-console-log".into(),
            name: "No console.log in production code".into(),
            description: "console.log statements should not be committed".into(),
            severity: ViolationSeverity::Warning,
            condition: RuleCondition::ContentPattern {
                pattern: r"console\.log\(".into(),
                scope: Some("src/**/*.{ts,js}".into()),
                must_match: false,
            },
            message: "Remove console.log before committing".into(),
            suggestion: Some("Use a proper logging library instead".into()),
        },
        CustomRule {
            id: "no-todo-fixme".into(),
            name: "No TODO/FIXME in committed code".into(),
            description: "TODO and FIXME comments should be resolved".into(),
            severity: ViolationSeverity::Info,
            condition: RuleCondition::ContentPattern {
                pattern: r"(TODO|FIXME)\b".into(),
                scope: Some("src/**".into()),
                must_match: false,
            },
            message: "Resolve TODO/FIXME before committing".into(),
            suggestion: None,
        },
        CustomRule {
            id: "test-files-exist".into(),
            name: "Test files must exist for source files".into(),
            description: "Every source file should have a corresponding test file".into(),
            severity: ViolationSeverity::Warning,
            condition: RuleCondition::Structure {
                directory: "src".into(),
                required_files: vec!["**/*.test.{ts,js}".into()],
            },
            message: "Missing test file for source file".into(),
            suggestion: Some("Create a test file alongside the source file".into()),
        },
        CustomRule {
            id: "no-hardcoded-secrets".into(),
            name: "No hardcoded secrets".into(),
            description: "API keys and passwords should not be hardcoded".into(),
            severity: ViolationSeverity::Error,
            condition: RuleCondition::ContentPattern {
                pattern: r#"(api[_-]?key|password|secret|token)\s*[:=]\s*["'][^"']{8,}"#.into(),
                scope: Some("src/**".into()),
                must_match: false,
            },
            message: "Hardcoded secret detected — use environment variables".into(),
            suggestion: Some("Move secrets to environment variables or a secrets manager".into()),
        },
    ]
}
```

---

## 6. Gate Orchestrator — TS Coordination Layer

The orchestrator stays in TypeScript. It is pure coordination logic — no heavy computation.

### GateOrchestrator (V2)

```typescript
export class GateOrchestrator {
    private registry: GateRegistry;
    private policyLoader: PolicyLoader;
    private executor: DependencyExecutor;
    private evaluator: PolicyEvaluator;
    private aggregator: ResultAggregator;
    private prioritizer: PriorityScorer;
    private notifier: NotificationEngine;
    private cache: GateCache;

    constructor(private projectRoot: string, private native: NativeBindings) {
        this.registry = getGateRegistry();
        this.policyLoader = new PolicyLoader(projectRoot);
        this.executor = new DependencyExecutor();
        this.evaluator = new PolicyEvaluator();
        this.aggregator = new ResultAggregator();
        this.prioritizer = new PriorityScorer();
        this.notifier = new NotificationEngine();
        this.cache = new GateCache(native);
    }

    async run(options: QualityGateOptions): Promise<QualityGateResult> {
        const start = Date.now();

        // 1. Resolve files
        const { files, allFiles } = await this.resolveFiles(options);

        // 2. Load policy (YAML/JSON, inheritance, context-based)
        const policy = await this.policyLoader.load(options.policy, {
            branch: options.branch,
            paths: files,
            author: options.author,
        });

        // 3. Determine which gates to run
        const gates = this.determineGates(policy);

        // 4. Check cache for unchanged inputs (R3)
        const { cached, uncached } = await this.cache.check(gates, files, policy);

        // 5. Build context (lazy — only what uncached gates need)
        const context = await this.buildContext(uncached, options);

        // 6. Execute uncached gates via DependencyExecutor (R9)
        const gateResults = await this.executor.execute(
            uncached, context, policy, options,
            cached, // pass cached results for dependent gates
        );

        // Merge cached + fresh results
        const allResults = { ...cached, ...gateResults };

        // 7. Evaluate against policy
        const evaluation = this.evaluator.evaluate(allResults, policy);

        // 8. Prioritize violations (R16)
        const prioritized = this.prioritizer.score(
            evaluation.violations, context.hotspotData, options,
        );

        // 9. Aggregate
        const result = this.aggregator.aggregate(
            allResults, evaluation, prioritized, policy, {
                executionTimeMs: Date.now() - start,
                filesChecked: files.length,
                gatesRun: Object.keys(gateResults) as GateId[],
                gatesSkipped: this.getSkippedGates(policy),
                gatesCached: Object.keys(cached) as GateId[],
                branch: options.branch ?? '',
                commitSha: options.commitSha,
                ci: options.ci ?? false,
                mode: options.mode ?? 'pr',
                dryRun: options.dryRun ?? false,
            },
        );

        // 10. Persist (skip if dry-run, R17)
        if (!options.dryRun) {
            await this.persist(result, options);
            await this.cache.save(gateResults, files, policy);
        }

        // 11. Notify (R18)
        if (policy.actions) {
            await this.notifier.fire(result, policy.actions);
        }

        // 12. Report
        // (handled by caller — orchestrator returns the result)

        return result;
    }
}
```

### DependencyExecutor (V2 — Replaces ParallelExecutor)

```typescript
export class DependencyExecutor {
    /**
     * Execute gates respecting dependency DAG (R9).
     *
     * Execution groups (topological order):
     *   Group 1 (parallel): pattern-compliance, constraint-verification,
     *                        impact-simulation, custom-rules
     *   Group 2 (parallel): regression-detection (depends on pattern-compliance),
     *                        security-boundary (depends on impact-simulation)
     *
     * Early termination: if policy.earlyTermination is true and any required
     * gate in Group 1 fails, skip Group 2.
     */
    async execute(
        gates: GateId[],
        context: GateContext,
        policy: QualityPolicy,
        options: QualityGateOptions,
        cachedResults: Record<GateId, GateResult>,
    ): Promise<Record<GateId, GateResult>> {
        const results: Record<string, GateResult> = {};
        const groups = this.buildExecutionGroups(gates);

        for (const group of groups) {
            // Early termination check (R9)
            if (policy.aggregation.earlyTermination) {
                const requiredFailed = Object.entries(results).some(
                    ([id, r]) => policy.aggregation.requiredGates?.includes(id as GateId)
                        && !r.passed
                );
                if (requiredFailed) break;
            }

            // Execute group in parallel with per-gate timeout (R13)
            const groupResults = await Promise.all(
                group.map(gateId => this.executeWithTimeout(
                    gateId, context, policy, options,
                    { ...cachedResults, ...results },
                ))
            );

            for (const result of groupResults) {
                results[result.gateId] = result;
            }
        }

        return results as Record<GateId, GateResult>;
    }

    private async executeWithTimeout(
        gateId: GateId,
        context: GateContext,
        policy: QualityPolicy,
        options: QualityGateOptions,
        predecessorResults: Record<GateId, GateResult>,
    ): Promise<GateResult> {
        const timeout = policy.gates[gateId]?.timeout ?? 30_000;

        try {
            return await Promise.race([
                this.executeGate(gateId, context, policy, options, predecessorResults),
                this.timeoutPromise(timeout, gateId),
            ]);
        } catch (err) {
            // Fail-safe: errored gates return passed: true
            return errorResult(gateId, String(err));
        }
    }

    private buildExecutionGroups(gates: GateId[]): GateId[][] {
        // Topological sort based on gate dependencies
        const deps: Record<string, GateId[]> = {
            'pattern-compliance': [],
            'constraint-verification': [],
            'regression-detection': ['pattern-compliance'],
            'impact-simulation': [],
            'security-boundary': ['impact-simulation'],
            'custom-rules': [],
        };

        // Simple two-group split based on dependencies
        const group1 = gates.filter(g => deps[g]?.length === 0);
        const group2 = gates.filter(g => (deps[g]?.length ?? 0) > 0);

        const groups: GateId[][] = [];
        if (group1.length > 0) groups.push(group1);
        if (group2.length > 0) groups.push(group2);
        return groups;
    }
}
```

---

## 7. Policy Engine — Declarative Policy-as-Code

### PolicyLoader (V2 — YAML + JSON + Inheritance)

```typescript
export class PolicyLoader {
    /**
     * Resolution order (preserved from v1 + v2 additions):
     * 1. Inline QualityPolicy object
     * 2. Built-in policy by ID (default, strict, relaxed, ci-fast)
     * 3. Custom policy from .drift/policies/{id}.yaml or .drift/policies/{id}.json
     * 4. Context-based matching (branch, paths, author)
     * 5. Fallback to 'default' policy
     *
     * V2 additions:
     * - YAML support (R5)
     * - Inheritance via 'extends' keyword (R5)
     * - Policy versioning via 'apiVersion' field (R5)
     * - Policy packs from npm packages (R5)
     */
    async load(
        policyRef: string | QualityPolicy | undefined,
        context?: PolicyContext,
    ): Promise<QualityPolicy> {
        // ... resolution logic
    }

    /**
     * Resolve inheritance chain.
     * extends: "drift:default" → load default, deep merge overrides.
     */
    private resolveInheritance(policy: QualityPolicy): QualityPolicy {
        if (!policy.extends) return policy;

        const parent = this.loadById(policy.extends.replace('drift:', ''));
        return deepMerge(parent, policy);
    }
}
```

### 4 Built-in Policies (All V1 Policies Preserved)

```yaml
# Policy: default — Balanced (preserved from v1)
apiVersion: drift/v1
kind: QualityPolicy
metadata:
  name: default
  description: "Balanced policy for all branches"
gates:
  pattern-compliance:
    enabled: true
    blocking: true
    minComplianceRate: 80
    minPatternConfidence: 0.7
  constraint-verification:
    enabled: true
    blocking: true
    enforceApproved: true
    minConfidence: 0.9
  regression-detection:
    enabled: true
    blocking: false  # Warning only
    maxConfidenceDrop: 5
    maxComplianceDrop: 10
  impact-simulation:
    enabled: true
    blocking: false  # Warning only
    maxFilesAffected: 20
    maxFunctionsAffected: 50
  security-boundary:
    enabled: true
    blocking: true
    allowNewSensitiveAccess: false
    protectedTables: [users, payments, credentials, tokens]
  custom-rules:
    enabled: false
aggregation:
  mode: any  # Any blocking gate failure = overall failure
  requiredGates: [pattern-compliance, security-boundary]

# Policy: strict — Main/Release Branches (preserved from v1)
# Scope: main, master, release/*
# Everything blocking, tighter thresholds:
#   90% compliance, 0.8 confidence, 2% max confidence drop,
#   15 max files, 30 max functions, custom rules enabled

# Policy: relaxed — Feature Branches (preserved from v1)
# Scope: feature/*, fix/*, chore/*
# 70% compliance, 3 outliers allowed, constraints warn,
# regression skipped, impact warns, security still blocks

# Policy: ci-fast — Minimal CI (preserved from v1)
# Only pattern compliance (70%), everything else skipped
```

### 4 Aggregation Modes (All Preserved from V1)

```rust
/// Policy aggregation modes. All 4 preserved exactly from v1.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AggregationMode {
    /// Any blocking gate failure = overall failure. Default.
    Any,
    /// All gates must fail for overall failure. Lenient.
    All,
    /// Weighted average of gate scores vs minScore.
    Weighted,
    /// Average of all gate scores vs minScore.
    Threshold,
}

/// Aggregation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationConfig {
    pub mode: AggregationMode,
    #[serde(default)]
    pub required_gates: Vec<GateId>,
    #[serde(default)]
    pub weights: HashMap<GateId, f64>,
    pub min_score: Option<f64>,         // default: 70
    /// NEW: Early termination if required gate fails (R9).
    pub early_termination: Option<bool>,
}

/// Policy scope for context-based matching. Preserved from v1.
/// Specificity scoring: branch +10, path +5, author +3,
/// include +2, exclude +1. Most specific wins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyScope {
    #[serde(default)]
    pub branches: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub authors: Vec<String>,
    #[serde(default)]
    pub include_files: Vec<String>,
    #[serde(default)]
    pub exclude_files: Vec<String>,
}
```

---

## 8. Reporter System — 7 Output Formats + Plugin Architecture

### Reporter Interface (Preserved from V1, Made Public for Plugins)

```typescript
export interface Reporter {
    readonly id: string;
    readonly format: OutputFormat;
    generate(result: QualityGateResult, options?: ReporterOptions): string;
    write(report: string, options?: ReporterOptions): Promise<void>;
}

export interface ReporterOptions {
    outputPath?: string;
    verbose?: boolean;
    includeDetails?: boolean;
    maxViolations?: number;
}
```

### 7 Built-in Reporters (V1's 5 + 2 New)

| Reporter | Format | Status | Use Case |
|----------|--------|--------|----------|
| TextReporter | `text` | V1 preserved | Terminal-friendly output |
| JsonReporter | `json` | V1 preserved | Machine-readable, API consumption |
| SarifReporter | `sarif` | V1 upgraded (R4) | Rich SARIF 2.1.0 with baselineState, codeFlows, fixes, taxonomies |
| GithubReporter | `github` | V1 preserved | GitHub PR markdown comments with feedback actions (R6) |
| GitlabReporter | `gitlab` | V1 preserved | GitLab MR markdown comments with feedback actions (R6) |
| JunitReporter | `junit` | **NEW** (R8) | JUnit XML for universal CI integration |
| HtmlReporter | `html` | **NEW** (R8) | Standalone HTML report with embedded CSS |

### Plugin Architecture (R19)

```typescript
// Plugin discovery order:
// 1. Built-in reporters (7 above)
// 2. Project-level plugins: .drift/plugins/reporters/*.js
// 3. npm packages: drift-reporter-* (from package.json)

// Usage: drift gate run --format confluence
// Or:    drift gate run --format custom:./my-reporter.js

export class ReporterRegistry {
    private reporters: Map<string, Reporter> = new Map();

    register(reporter: Reporter): void {
        this.reporters.set(reporter.id, reporter);
    }

    async loadPlugins(projectRoot: string): Promise<void> {
        // Load from .drift/plugins/reporters/
        const pluginDir = path.join(projectRoot, '.drift/plugins/reporters');
        if (await fs.pathExists(pluginDir)) {
            const files = await fs.readdir(pluginDir);
            for (const file of files.filter(f => f.endsWith('.js'))) {
                const plugin = require(path.join(pluginDir, file));
                if (this.isValidReporter(plugin)) {
                    this.register(plugin);
                }
            }
        }
    }

    get(format: string): Reporter | undefined {
        return this.reporters.get(format);
    }
}
```

### Multiple Simultaneous Reporters

```bash
# Output both SARIF (for GitHub Code Scanning) and JUnit XML (for CI dashboard)
drift gate run --format sarif,junit --output-dir .drift/reports/
```

---

## 9. Persistence — SQLite in drift.db

All quality gate persistence migrates from JSON files to SQLite tables in drift.db.
Per 02-STORAGE-V2-PREP.md, drift.db uses WAL mode for concurrent read access.

### SQLite Schema

```sql
-- Gate run history (replaces .drift/quality-gates/history/runs/*.json)
CREATE TABLE gate_runs (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    branch TEXT NOT NULL,
    commit_sha TEXT,
    policy_id TEXT NOT NULL,
    passed INTEGER NOT NULL,
    score REAL NOT NULL,
    violation_count INTEGER NOT NULL,
    new_violation_count INTEGER NOT NULL,  -- NEW: R1
    execution_time_ms INTEGER NOT NULL,
    ci INTEGER NOT NULL DEFAULT 0,
    mode TEXT NOT NULL DEFAULT 'pr',       -- NEW: R1
    dry_run INTEGER NOT NULL DEFAULT 0,    -- NEW: R17
    gate_results TEXT NOT NULL,            -- JSON blob of per-gate results
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_gate_runs_branch ON gate_runs(branch, timestamp DESC);
CREATE INDEX idx_gate_runs_timestamp ON gate_runs(timestamp DESC);

-- Health snapshots (replaces .drift/quality-gates/snapshots/{branch}/*.json)
CREATE TABLE health_snapshots (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    branch TEXT NOT NULL,
    commit_sha TEXT,
    patterns_snapshot TEXT NOT NULL,       -- JSON blob
    constraints_snapshot TEXT NOT NULL,    -- JSON blob
    security_snapshot TEXT NOT NULL,       -- JSON blob
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_snapshots_branch ON health_snapshots(branch, timestamp DESC);

-- Audit history (replaces .drift/audit/snapshots/*.json)
CREATE TABLE audit_history (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    health_score REAL NOT NULL,
    avg_confidence REAL NOT NULL,
    approval_ratio REAL NOT NULL,
    compliance_rate REAL NOT NULL,
    cross_validation_rate REAL NOT NULL,
    duplicate_free_rate REAL NOT NULL,
    pattern_count INTEGER NOT NULL,
    duplicate_groups INTEGER NOT NULL,
    false_positive_count INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_audit_timestamp ON audit_history(timestamp DESC);

-- Violation feedback (NEW: R6)
CREATE TABLE violation_feedback (
    id TEXT PRIMARY KEY,
    violation_id TEXT NOT NULL,
    pattern_id TEXT NOT NULL,
    action TEXT NOT NULL,  -- fix, dismiss:false-positive, dismiss:wont-fix, dismiss:not-applicable
    reason TEXT,
    author TEXT,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_feedback_pattern ON violation_feedback(pattern_id);
CREATE INDEX idx_feedback_timestamp ON violation_feedback(timestamp DESC);

-- Gate result cache (NEW: R3)
CREATE TABLE gate_cache (
    cache_key TEXT PRIMARY KEY,
    gate_id TEXT NOT NULL,
    branch TEXT NOT NULL,
    result TEXT NOT NULL,               -- JSON blob of GateResult
    input_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT
);
CREATE INDEX idx_cache_branch ON gate_cache(branch);
CREATE INDEX idx_cache_expires ON gate_cache(expires_at);
```

### Retention Policies

| Table | Retention | Mechanism |
|-------|-----------|-----------|
| gate_runs | 90 days | `DELETE WHERE timestamp < datetime('now', '-90 days')` |
| health_snapshots | 50 per branch (configurable) | Delete oldest when limit exceeded |
| audit_history | 90 days | `DELETE WHERE timestamp < datetime('now', '-90 days')` |
| violation_feedback | Indefinite | No auto-deletion (audit trail) |
| gate_cache | 7 days inactive | `DELETE WHERE expires_at < datetime('now')` |

---

## 10. Audit System — Health Scoring & Degradation Tracking

### Health Score Formula (Preserved Exactly from V1)

```rust
/// Calculate audit health score. Preserved exactly from v1.
/// Weights: avgConfidence × 0.30 + approvalRatio × 0.20 + complianceRate × 0.20
///        + crossValidationRate × 0.15 + duplicateFreeRate × 0.15
pub fn calculate_health_score(
    avg_confidence: f64,
    approval_ratio: f64,
    compliance_rate: f64,
    cross_validation_rate: f64,
    duplicate_free_rate: f64,
) -> f64 {
    let score = (avg_confidence * 0.30
        + approval_ratio * 0.20
        + compliance_rate * 0.20
        + cross_validation_rate * 0.15
        + duplicate_free_rate * 0.15) * 100.0;
    score.clamp(0.0, 100.0)
}
```

### Duplicate Detection (Preserved Algorithm, Rust Implementation)

```rust
/// Detect duplicate patterns using Jaccard similarity.
/// Preserved from v1: threshold 0.85, same-category only.
/// V2: Rust implementation for O(p²) performance.
pub fn detect_duplicates(
    patterns: &[Pattern],
    threshold: f64,  // default: 0.85
) -> Vec<DuplicateGroup> {
    let mut groups = Vec::new();
    let by_category = group_by_category(patterns);

    for (_, category_patterns) in &by_category {
        for i in 0..category_patterns.len() {
            for j in (i + 1)..category_patterns.len() {
                let jaccard = jaccard_similarity(
                    &category_patterns[i].locations,
                    &category_patterns[j].locations,
                );
                if jaccard > threshold {
                    let recommendation = if jaccard > 0.90 {
                        DuplicateRecommendation::Merge
                    } else {
                        DuplicateRecommendation::Review
                    };
                    groups.push(DuplicateGroup {
                        pattern_a: category_patterns[i].id.clone(),
                        pattern_b: category_patterns[j].id.clone(),
                        similarity: jaccard,
                        recommendation,
                    });
                }
            }
        }
    }
    groups
}
```

### Degradation Tracking (Preserved from V1)

```rust
/// Degradation alert thresholds. Preserved exactly from v1.
pub struct DegradationConfig {
    pub health_warning: f64,        // -5 points
    pub health_critical: f64,       // -15 points
    pub confidence_warning: f64,    // -5%
    pub confidence_critical: f64,   // -15%
    pub false_positive_warning: u32, // > 5
    pub false_positive_critical: u32, // > 10
    pub duplicate_warning: u32,     // > 3 groups
}

/// Trend analysis. 7-day rolling average vs previous 7 days.
/// Preserved from v1: ±2 point/percent threshold for stable.
pub fn calculate_trend(
    current_7day_avg: f64,
    previous_7day_avg: f64,
) -> Trend {
    let delta = current_7day_avg - previous_7day_avg;
    if delta > 2.0 {
        Trend::Improving
    } else if delta < -2.0 {
        Trend::Declining
    } else {
        Trend::Stable
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Trend {
    Improving,
    Stable,
    Declining,
}
```

### Recommendation Engine (Preserved from V1)

```rust
/// Auto-approve recommendation criteria. Preserved from v1.
pub fn recommend_action(pattern: &Pattern) -> PatternRecommendation {
    if pattern.confidence >= 0.90
        && pattern.outlier_ratio() <= 0.50
        && pattern.location_count >= 3
        && !pattern.has_error_issues
    {
        PatternRecommendation::AutoApprove
    } else if pattern.confidence >= 0.70 {
        PatternRecommendation::Review
    } else {
        PatternRecommendation::LikelyFalsePositive
    }
}
```


---

## 11. New-Code-First Enforcement (R1)

The single most impactful architectural change in v2. Inspired by SonarQube's "Clean as
You Code" philosophy (QG-R1): developers should never be blocked by pre-existing issues
they didn't introduce.

### Core Principle

In PR mode (default), only violations introduced by the current change can block merge.
Pre-existing violations are reported but do not affect the pass/fail decision.

### Mode Behavior Matrix

| Mode | Files Evaluated | Blocking Violations | Baseline | Use Case |
|------|----------------|--------------------|---------|---------| 
| `pr` (default) | Changed files only | New violations only | Target branch snapshot | Pull request checks |
| `full` | All files | All violations | None | Scheduled audits, baseline establishment |
| `regression` | All files | Regressions only | Previous main snapshot | Post-merge verification |
| `pre-commit` | Staged files only | New violations only | Working tree | Local pre-commit hook |

### New vs Existing Violation Classification

```rust
/// Classify whether a violation is new (introduced by this change) or existing.
/// Uses three signals in priority order:
///   1. File presence in changed file list
///   2. Line-level git blame (if available)
///   3. Baseline snapshot comparison
pub fn classify_violation_novelty(
    violation: &GateViolation,
    changed_files: &[String],
    blame_data: Option<&BlameData>,
    baseline: Option<&HealthSnapshot>,
) -> bool {
    // Signal 1: File not in changed set → existing
    if !changed_files.contains(&violation.file) {
        return false;
    }

    // Signal 2: Git blame shows violation line was changed in this commit
    if let Some(blame) = blame_data {
        if let Some(line_info) = blame.line_info(&violation.file, violation.line) {
            return line_info.is_uncommitted || line_info.commit == blame.head_commit;
        }
    }

    // Signal 3: Violation exists in baseline → existing
    if let Some(snap) = baseline {
        let baseline_key = format!("{}:{}:{}", violation.file, violation.line, violation.rule_id);
        if snap.has_violation(&baseline_key) {
            return false;
        }
    }

    // Default: if file is changed and no contrary evidence, treat as new
    true
}
```

### Author Attribution (via Git Blame)

```rust
/// Populate violation author from git blame data.
/// Used by PriorityScorer (R16) for authorMatch factor.
pub fn attribute_author(
    violation: &mut GateViolation,
    blame_data: Option<&BlameData>,
) {
    if let Some(blame) = blame_data {
        if let Some(line_info) = blame.line_info(&violation.file, violation.line) {
            violation.author = Some(line_info.author.clone());
        }
    }
}
```

### Policy Configuration

```yaml
# Per-gate new-code-first configuration
gates:
  pattern-compliance:
    blockOnNewOnly: true      # Default: true in PR mode
    reportExisting: true      # Show existing violations as info
  constraint-verification:
    baselineAware: true       # Only new constraint violations block
  security-boundary:
    blockOnNewOnly: true      # Even security — only new unauthorized access blocks
    # Exception: critical CWE violations always block regardless of novelty
    alwaysBlockCwe: [798, 89]  # Hardcoded secrets, SQL injection
```

### Interaction with Other Recommendations

- R2 (Progressive Enforcement): enforcement mode is orthogonal to novelty — a `monitor` pattern
  never blocks regardless of novelty; a `block` pattern only blocks if the violation is new
- R3 (Caching): cache key includes mode — PR cache is separate from full-scan cache
- R16 (Prioritization): `isNew` is a 0.25-weight factor in priority score
- R17 (Dry-Run): dry-run respects mode — `--dry-run --mode pr` shows what would block

---

## 12. Progressive Enforcement — Monitor / Comment / Block (R2)

Three-mode enforcement at the per-pattern level. Patterns graduate through modes as
confidence grows and false-positive rate stays low.

### Enforcement Mode Lifecycle

```
  ┌──────────┐    confidence ≥ 0.70    ┌──────────┐    confidence ≥ 0.85    ┌──────────┐
  │ MONITOR  │ ──── locations ≥ 5 ────→│ COMMENT  │ ──── locations ≥ 10 ──→│  BLOCK   │
  │          │      age ≥ 7 days       │          │      age ≥ 30 days     │          │
  └──────────┘                         └──────────┘      FP rate < 10%     └──────────┘
       ↑                                    ↑                                    │
       │         FP rate > 25%              │         FP rate > 10%              │
       └────────────────────────────────────┘←───────────────────────────────────┘
                    AUTOMATIC DEMOTION
```

### Promotion Rules (Configurable)

```yaml
# In drift.toml or policy YAML
enforcement:
  promotion:
    monitorToComment:
      minConfidence: 0.70
      minLocations: 5
      minAge: 7d
    commentToBlock:
      minConfidence: 0.85
      minLocations: 10
      minAge: 30d
      maxFalsePositiveRate: 0.10
      requireManualApproval: false  # true = require human approval for block promotion
  demotion:
    blockToComment:
      falsePositiveRate: 0.10       # >10% FP rate → demote
      windowDays: 30
    commentToMonitor:
      falsePositiveRate: 0.25       # >25% FP rate → suspend
      windowDays: 30
```

### Promotion Engine (Runs During Audit, Not Gate Execution)

```rust
/// Evaluate whether a pattern should be promoted or demoted.
/// Runs during scheduled audit, not during gate execution.
pub fn evaluate_enforcement_transition(
    pattern: &Pattern,
    feedback_stats: &FeedbackStats,
    config: &EnforcementPromotionConfig,
) -> Option<EnforcementTransition> {
    let current = pattern.enforcement_mode;
    let fp_rate = feedback_stats.false_positive_rate(pattern.id(), config.window_days);

    // Check demotion first (safety)
    match current {
        EnforcementMode::Block if fp_rate > config.demotion.block_to_comment.fp_rate => {
            return Some(EnforcementTransition {
                from: EnforcementMode::Block,
                to: EnforcementMode::Comment,
                reason: format!("FP rate {:.0}% exceeds {:.0}% threshold",
                    fp_rate * 100.0, config.demotion.block_to_comment.fp_rate * 100.0),
            });
        }
        EnforcementMode::Comment if fp_rate > config.demotion.comment_to_monitor.fp_rate => {
            return Some(EnforcementTransition {
                from: EnforcementMode::Comment,
                to: EnforcementMode::Monitor,
                reason: format!("FP rate {:.0}% exceeds {:.0}% threshold",
                    fp_rate * 100.0, config.demotion.comment_to_monitor.fp_rate * 100.0),
            });
        }
        _ => {}
    }

    // Check promotion
    let age_days = pattern.age_days();
    match current {
        EnforcementMode::Monitor
            if pattern.confidence >= config.promotion.monitor_to_comment.min_confidence
            && pattern.location_count >= config.promotion.monitor_to_comment.min_locations
            && age_days >= config.promotion.monitor_to_comment.min_age_days =>
        {
            Some(EnforcementTransition {
                from: EnforcementMode::Monitor,
                to: EnforcementMode::Comment,
                reason: format!("Confidence {:.0}%, {} locations, {} days old",
                    pattern.confidence * 100.0, pattern.location_count, age_days),
            })
        }
        EnforcementMode::Comment
            if pattern.confidence >= config.promotion.comment_to_block.min_confidence
            && pattern.location_count >= config.promotion.comment_to_block.min_locations
            && age_days >= config.promotion.comment_to_block.min_age_days
            && fp_rate <= config.promotion.comment_to_block.max_fp_rate =>
        {
            if config.promotion.comment_to_block.require_manual_approval {
                Some(EnforcementTransition {
                    from: EnforcementMode::Comment,
                    to: EnforcementMode::Comment, // stays comment, flagged for review
                    reason: "Eligible for block promotion — awaiting manual approval".into(),
                })
            } else {
                Some(EnforcementTransition {
                    from: EnforcementMode::Comment,
                    to: EnforcementMode::Block,
                    reason: format!("Confidence {:.0}%, FP rate {:.0}%, {} locations",
                        pattern.confidence * 100.0, fp_rate * 100.0, pattern.location_count),
                })
            }
        }
        _ => None,
    }
}
```

### How Gates Filter by Enforcement Mode

Pattern compliance gate (§5.2) filters patterns by `min_enforcement_mode` from policy:
- Policy says `minEnforcementMode: block` → only `block` patterns produce violations
- Policy says `minEnforcementMode: comment` → `comment` + `block` patterns produce violations
- Policy says `minEnforcementMode: monitor` → all patterns produce violations (audit mode)

Violations carry their pattern's enforcement mode in `violation.enforcement_mode`. The
ResultAggregator uses this to determine which violations actually block:
- `block` violations → can block merge (if gate is blocking)
- `comment` violations → appear in PR comments, never block
- `monitor` violations → tracked internally, not in gate results

---

## 13. Incremental Gate Execution with Caching (R3)

Three-tier caching strategy that reduces gate execution time by 80-95% for small changes.

### Tier 1 — Gate-Level Input Hashing

```rust
/// Compute a cache key for an entire gate execution.
/// If the key matches a cached result, skip the gate entirely.
pub fn gate_cache_key(
    gate_id: GateId,
    files: &[String],
    policy_config: &GateConfig,
    context_hash: &str,  // hash of patterns/constraints/call-graph state
    mode: GateMode,
) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(gate_id.as_str().as_bytes());
    hasher.update(mode.as_str().as_bytes());
    for file in files {
        hasher.update(file.as_bytes());
    }
    hasher.update(serde_json::to_string(policy_config).unwrap_or_default().as_bytes());
    hasher.update(context_hash.as_bytes());
    format!("{:x}", hasher.finalize())
}
```

### Tier 2 — Per-File Result Caching

For pattern compliance and custom rules, cache per-file evaluation results:

```rust
/// Per-file cache entry. Stored in gate_cache table.
pub struct FileCacheEntry {
    pub file_path: String,
    pub content_hash: String,       // SHA-256 of file content
    pub applicable_rules_hash: String, // hash of patterns/rules that apply to this file
    pub violations: Vec<GateViolation>,
    pub created_at: String,
}

/// Check if a file's cached result is still valid.
pub fn is_file_cache_valid(
    entry: &FileCacheEntry,
    current_content_hash: &str,
    current_rules_hash: &str,
) -> bool {
    entry.content_hash == current_content_hash
        && entry.applicable_rules_hash == current_rules_hash
}
```

### Tier 3 — Branch-Based Cache Management

```
Branch Cache Lifecycle:
  1. PR opens targeting main → download main's cache as baseline
  2. PR gates execute → only uncached gates run
  3. PR gates complete → upload results to PR branch cache
  4. PR merges → main cache updated with merged results
  5. Branch inactive >7 days → cache pruned

Cache Invalidation Rules:
  - File content changed → invalidate Tier 2 for that file
  - Pattern/constraint state changed → invalidate Tier 1 for affected gates
  - Policy config changed → invalidate Tier 1 for all gates
  - Call graph changed → invalidate Tier 1 for impact-simulation, security-boundary
  - Any doubt → re-execute (conservative invalidation)
```

### Cache Storage (SQLite)

```sql
-- Already defined in §9, repeated here for context
-- gate_cache table with composite key, branch isolation, TTL
SELECT result FROM gate_cache
WHERE cache_key = ?
  AND branch = ?
  AND (expires_at IS NULL OR expires_at > datetime('now'));
```

### Orchestrator Cache Integration

```typescript
// In GateOrchestrator.run() — step 4
const { cached, uncached } = await this.cache.check(gates, files, policy);

// cached: Record<GateId, GateResult> — gates served from cache
// uncached: GateId[] — gates that need fresh execution

// Step 6: only execute uncached gates
const freshResults = await this.executor.execute(uncached, context, policy, options, cached);

// Step 10: save fresh results to cache (skip if dry-run)
if (!options.dryRun) {
    await this.cache.save(freshResults, files, policy);
}
```

### Performance Targets

| Scenario | Without Cache | With Cache | Improvement |
|----------|-------------|-----------|-------------|
| Small PR (5 files, no pattern changes) | ~3s | ~200ms | 93% |
| Medium PR (20 files, no pattern changes) | ~8s | ~500ms | 94% |
| Large PR (100 files, pattern changes) | ~15s | ~5s | 67% |
| Full scan (first run, no cache) | ~30s | ~30s | 0% |
| Full scan (cached, no changes) | ~30s | ~1s | 97% |

---

## 14. Rich SARIF 2.1.0 Output (R4)

Full SARIF 2.1.0 compliance for GitHub Code Scanning, VS Code SARIF Viewer, and
enterprise compliance tools.

### SARIF Schema Structure

```typescript
interface DriftSarifOutput {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json";
    version: "2.1.0";
    runs: [{
        tool: {
            driver: {
                name: "drift";
                version: string;
                informationUri: "https://drift.dev";
                rules: SarifRule[];
                taxonomies: SarifTaxonomy[];
            };
        };
        results: SarifResult[];
        invocations: [SarifInvocation];
        versionControlProvenance: [SarifVersionControl];
    }];
}
```

### Key SARIF Properties (V2 Additions)

| Property | V1 Status | V2 Status | Source |
|----------|-----------|-----------|--------|
| `results[].ruleId` | ✅ Had | ✅ Kept | Gate violation rule_id |
| `results[].level` | ✅ Had | ✅ Kept | Severity mapping |
| `results[].locations` | ✅ Had | ✅ Kept | File + line + column |
| `results[].message` | ✅ Had | ✅ Kept | Violation message |
| `results[].baselineState` | ❌ Missing | ✅ NEW | `new`/`unchanged`/`updated`/`absent` from R1 |
| `results[].codeFlows` | ❌ Missing | ✅ NEW | Security boundary call chains |
| `results[].fixes` | ❌ Missing | ✅ NEW | Quick fix suggestions |
| `results[].suppressions` | ❌ Missing | ✅ NEW | Dismissed violations from R6 |
| `results[].rank` | ❌ Missing | ✅ NEW | Priority score from R16 |
| `tool.driver.taxonomies` | ❌ Missing | ✅ NEW | CWE + OWASP taxonomies from R12 |
| `results[].taxa` | ❌ Missing | ✅ NEW | Per-result CWE/OWASP references |

### baselineState Mapping

```typescript
function mapBaselineState(violation: GateViolation, previousRun?: SarifRun): BaselineState {
    if (!previousRun) return 'new';

    const previousResult = previousRun.results.find(r =>
        r.ruleId === violation.rule_id
        && r.locations?.[0]?.physicalLocation?.artifactLocation?.uri === violation.file
    );

    if (!previousResult) return 'new';
    if (previousResult.message.text === violation.message) return 'unchanged';
    return 'updated';
}
// 'absent' = was in previous run but not in current (violation fixed)
```

### codeFlows for Security Boundary

```json
{
    "codeFlows": [{
        "threadFlows": [{
            "locations": [
                {
                    "location": {
                        "physicalLocation": {
                            "artifactLocation": { "uri": "src/routes/admin.ts" },
                            "region": { "startLine": 23 }
                        },
                        "message": { "text": "Entry point: GET /admin/users" }
                    }
                },
                {
                    "location": {
                        "physicalLocation": {
                            "artifactLocation": { "uri": "src/services/userService.ts" },
                            "region": { "startLine": 45 }
                        },
                        "message": { "text": "Calls userService.getAll()" }
                    }
                },
                {
                    "location": {
                        "physicalLocation": {
                            "artifactLocation": { "uri": "src/db/queries.ts" },
                            "region": { "startLine": 12 }
                        },
                        "message": { "text": "Accesses 'users' table without auth" }
                    }
                }
            ]
        }]
    }]
}
```

### CWE/OWASP Taxonomies

```json
{
    "taxonomies": [
        {
            "name": "CWE",
            "version": "4.14",
            "organization": "MITRE",
            "shortDescription": { "text": "Common Weakness Enumeration" },
            "downloadUri": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
            "informationUri": "https://cwe.mitre.org",
            "taxa": [
                { "id": "862", "name": "Missing Authorization" },
                { "id": "798", "name": "Hard-coded Credentials" },
                { "id": "89", "name": "SQL Injection" }
            ]
        },
        {
            "name": "OWASP Top 10 2021",
            "version": "2021",
            "organization": "OWASP Foundation",
            "taxa": [
                { "id": "A01", "name": "Broken Access Control" },
                { "id": "A02", "name": "Cryptographic Failures" },
                { "id": "A03", "name": "Injection" }
            ]
        }
    ]
}
```

### SARIF Detail Levels (Configurable)

| Level | Size | Content |
|-------|------|---------|
| `basic` | ~50KB | Results with ruleId, level, locations, message |
| `standard` (default) | ~200KB | + baselineState, fixes, suppressions, taxonomies |
| `full` | ~500KB+ | + codeFlows, rank, all taxa references, graphs |

```bash
drift gate run --format sarif --sarif-level full --output drift-results.sarif
```

### GitHub Code Scanning Upload

```yaml
# .github/workflows/drift.yml
- name: Run Drift Quality Gates
  run: drift gate run --format sarif --output results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
    category: drift-quality-gates
```


---

## 15. Developer Feedback Loop (R6)

Closes the loop between violation reporting and pattern quality. Without feedback,
false positives accumulate until developers ignore all results.

### Feedback Actions

| Action | PR Comment Button | CLI Command | Effect on Pattern |
|--------|------------------|-------------|-------------------|
| Fix | "I fixed this" | `drift gate fix <id>` | +0.02 confidence (confirms validity) |
| False Positive | "Not a real issue" | `drift gate dismiss <id> --reason false-positive` | -0.05 confidence, track FP |
| Won't Fix | "Valid but intentional" | `drift gate dismiss <id> --reason wont-fix` | Create exception, no confidence change |
| Not Applicable | "Doesn't apply here" | `drift gate dismiss <id> --reason not-applicable` | -0.02 confidence |

### Feedback in PR Comments (GitHub/GitLab Reporters)

```markdown
### 🚨 Quality Gate: Pattern Compliance — FAILED (score: 72)

| # | File | Line | Violation | Severity | Actions |
|---|------|------|-----------|----------|---------|
| 1 | src/auth/login.ts | 42 | Missing auth middleware | error | [Fix ✅](link) · [Not an issue 🚫](link) · [Won't fix 🔇](link) |
| 2 | src/api/users.ts | 15 | Non-standard route | warning | [Fix ✅](link) · [Not an issue 🚫](link) · [Won't fix 🔇](link) |

> 💡 Your feedback improves pattern accuracy. Patterns with >10% false-positive rate are automatically demoted.
```

### Feedback Aggregation (Runs During Audit)

```rust
/// Calculate false-positive rate for a pattern over a time window.
pub fn false_positive_rate(
    pattern_id: &str,
    feedback: &[ViolationFeedback],
    window_days: u32,
) -> f64 {
    let cutoff = Utc::now() - Duration::days(window_days as i64);
    let recent: Vec<_> = feedback.iter()
        .filter(|f| f.pattern_id == pattern_id && f.timestamp > cutoff)
        .collect();

    if recent.is_empty() {
        return 0.0;
    }

    let fp_count = recent.iter()
        .filter(|f| f.action == "dismiss:false-positive")
        .count();

    fp_count as f64 / recent.len() as f64
}

/// Apply confidence adjustment from feedback.
/// Called during audit phase, not during gate execution.
pub fn apply_feedback_confidence_adjustment(
    pattern: &mut Pattern,
    feedback: &[ViolationFeedback],
) {
    for fb in feedback {
        if fb.pattern_id != pattern.id { continue; }
        match fb.action.as_str() {
            "fix" => pattern.confidence = (pattern.confidence + 0.02).min(1.0),
            "dismiss:false-positive" => pattern.confidence = (pattern.confidence - 0.05).max(0.0),
            "dismiss:not-applicable" => pattern.confidence = (pattern.confidence - 0.02).max(0.0),
            "dismiss:wont-fix" => { /* no confidence change — create exception */ }
            _ => {}
        }
    }
}
```

### Abuse Detection

```rust
/// Flag authors who dismiss an unusually high percentage of violations.
/// Threshold: >50% dismiss rate in 30 days → flag for team review.
pub fn detect_dismiss_abuse(
    feedback: &[ViolationFeedback],
    window_days: u32,
) -> Vec<AbuseAlert> {
    let cutoff = Utc::now() - Duration::days(window_days as i64);
    let by_author: HashMap<String, Vec<&ViolationFeedback>> = feedback.iter()
        .filter(|f| f.timestamp > cutoff)
        .filter(|f| f.author.is_some())
        .fold(HashMap::new(), |mut acc, f| {
            acc.entry(f.author.clone().unwrap()).or_default().push(f);
            acc
        });

    by_author.into_iter()
        .filter_map(|(author, fbs)| {
            let dismiss_count = fbs.iter()
                .filter(|f| f.action.starts_with("dismiss:"))
                .count();
            let rate = dismiss_count as f64 / fbs.len() as f64;
            if rate > 0.50 && fbs.len() >= 5 {
                Some(AbuseAlert {
                    author,
                    dismiss_rate: rate,
                    total_feedback: fbs.len(),
                    window_days,
                })
            } else {
                None
            }
        })
        .collect()
}
```

### SARIF Suppressions (From Feedback)

Dismissed violations map to SARIF `suppressions` for audit trail:

```json
{
    "suppressions": [{
        "kind": "inSource",
        "status": "accepted",
        "justification": "False positive — this pattern doesn't apply to auth middleware",
        "location": {
            "physicalLocation": {
                "artifactLocation": { "uri": "src/auth/middleware.ts" },
                "region": { "startLine": 42 }
            }
        }
    }]
}
```

---

## 16. Multi-Stage Enforcement (R7)

Four enforcement stages with appropriate scope and latency targets.

### Stage Configuration

| Stage | Trigger | Scope | Latency | Gates | Policy |
|-------|---------|-------|---------|-------|--------|
| Pre-commit | `git commit` | Staged files | <5s | Pattern compliance only | `pre-commit` preset |
| PR check | CI push | Changed + affected | <30s | All enabled gates | Branch-appropriate |
| Post-merge | CI merge | Full scan | <2m | All + regression | `default` + regression |
| Scheduled | Cron (daily) | Full + audit | <5m | All + audit + degradation | `strict` + full audit |

### Pre-Commit Hook

```bash
#!/bin/sh
# .drift/hooks/pre-commit (generated by `drift hooks install`)
# Runs pattern compliance on staged files only. <5s target.
# Fail-open: if drift is not installed or times out, allow commit.

STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)
if [ -z "$STAGED_FILES" ]; then
    exit 0
fi

drift gate run \
    --mode pre-commit \
    --files $STAGED_FILES \
    --dry-run \
    --format text \
    --timeout 5000 \
    2>/dev/null

# Fail-open: if drift fails, allow commit
if [ $? -eq 2 ]; then
    echo "⚠️  Drift quality gate timed out — committing anyway"
    exit 0
fi

exit $?
```

### Stage-Specific Gate Presets

```yaml
# Pre-commit preset (built-in)
apiVersion: drift/v1
kind: QualityPolicy
metadata:
  name: pre-commit
  description: "Fast pre-commit check — pattern compliance only"
gates:
  pattern-compliance:
    enabled: true
    blocking: true
    timeout: 3000        # 3s max
  constraint-verification:
    enabled: false
  regression-detection:
    enabled: false
  impact-simulation:
    enabled: false
  security-boundary:
    enabled: false
  custom-rules:
    enabled: false
aggregation:
  mode: any

# Post-merge preset (built-in)
apiVersion: drift/v1
kind: QualityPolicy
metadata:
  name: post-merge
  description: "Full scan with regression detection after merge"
extends: drift:default
overrides:
  gates:
    regression-detection:
      enabled: true
      blocking: true       # Regressions block on main
      baseline: branch-base
```

### Hook Installation

```bash
# Install pre-commit hook
drift hooks install

# This creates:
#   .drift/hooks/pre-commit → symlinked to .git/hooks/pre-commit
#   .drift/hooks/post-merge → symlinked to .git/hooks/post-merge

# Uninstall
drift hooks uninstall
```

### IDE Integration (LSP)

Real-time gate feedback on file save:
- LSP server runs pattern compliance on the saved file
- Results appear as inline diagnostics (warnings/errors)
- Uses dry-run mode — no persistence, no baseline pollution
- Latency target: <1s for single file

---

## 17. Gate Dependency Graph & Priority Ordering (R9)

### Dependency DAG

```
                    ┌─────────────────────┐
                    │   pattern-compliance │ ← Group 1 (no deps)
                    └──────────┬──────────┘
                               │ depends on
                    ┌──────────▼──────────┐
                    │ regression-detection │ ← Group 2
                    └─────────────────────┘

                    ┌─────────────────────┐
                    │  impact-simulation   │ ← Group 1 (no deps)
                    └──────────┬──────────┘
                               │ depends on
                    ┌──────────▼──────────┐
                    │  security-boundary   │ ← Group 2
                    └─────────────────────┘

                    ┌─────────────────────────┐
                    │ constraint-verification  │ ← Group 1 (no deps)
                    └─────────────────────────┘

                    ┌─────────────────────┐
                    │    custom-rules      │ ← Group 1 (no deps)
                    └─────────────────────┘
```

### Execution Groups (Topological Order)

```
Group 1 (parallel): pattern-compliance, constraint-verification,
                    impact-simulation, custom-rules
    ↓ all complete
Group 2 (parallel): regression-detection, security-boundary
```

### Early Termination

```typescript
// If policy.aggregation.earlyTermination is true:
// After Group 1 completes, check if any required gate failed.
// If so, skip Group 2 and return immediately.

// Example: security-boundary is required, pattern-compliance fails
// → skip regression-detection and security-boundary
// → return failed result with only Group 1 results

// Default: earlyTermination = false (all gates run regardless)
```

### Priority Ordering (Within Groups)

Gates within a group execute in parallel, but priority affects:
1. Resource allocation (higher priority gates get more CPU time)
2. Result display order (higher priority violations shown first)
3. Early termination evaluation order

```yaml
# In policy
gates:
  security-boundary:
    priority: 1    # Highest — security first
  pattern-compliance:
    priority: 2
  constraint-verification:
    priority: 3
  impact-simulation:
    priority: 4
  regression-detection:
    priority: 5
  custom-rules:
    priority: 6    # Lowest
```

### Data Sharing Between Groups

Dependent gates receive predecessor results in `GateInput.predecessor_results`:

```rust
// regression-detection receives pattern-compliance results
let pattern_result = input.predecessor_results.get(&GateId::PatternCompliance);
if let Some(result) = pattern_result {
    // Use current compliance data instead of re-computing
    let current_compliance = result.details["compliance_rate"].as_f64();
}

// security-boundary receives impact-simulation results
let impact_result = input.predecessor_results.get(&GateId::ImpactSimulation);
if let Some(result) = impact_result {
    // Reuse affected function set instead of re-traversing call graph
    let affected_functions = &result.details["functions_affected"];
}
```

---

## 18. Violation Prioritization Algorithm (R16)

Multi-factor scoring that surfaces the most actionable violations first.

### Priority Score Formula

```rust
/// Calculate priority score for a violation.
/// Score range: 0.0 (lowest priority) to 1.0 (highest priority).
///
/// Formula:
///   priority = severity × 0.30
///            + isNew × 0.25
///            + patternConfidence × 0.15
///            + hotspotScore × 0.15
///            + fixDifficulty × 0.10
///            + authorMatch × 0.05
pub fn calculate_priority_score(
    violation: &GateViolation,
    context: &PriorityContext,
) -> f64 {
    let severity = match violation.severity {
        ViolationSeverity::Error => 1.0,
        ViolationSeverity::Warning => 0.6,
        ViolationSeverity::Info => 0.3,
        ViolationSeverity::Hint => 0.1,
    };

    let is_new = if violation.is_new { 1.0 } else { 0.3 };

    let pattern_confidence = context.pattern_confidence
        .get(&violation.rule_id)
        .copied()
        .unwrap_or(0.5);

    let hotspot_score = context.hotspot_data
        .as_ref()
        .and_then(|h| h.change_frequency.get(&violation.file))
        .map(|&freq| {
            let max = context.hotspot_data.as_ref().unwrap().max_frequency;
            if max > 0 { freq as f64 / max as f64 } else { 0.0 }
        })
        .unwrap_or(0.0);

    let fix_difficulty = estimate_fix_difficulty(&violation.rule_id);

    let author_match = if context.current_author.is_some()
        && violation.author == context.current_author
    {
        1.0
    } else {
        0.5
    };

    severity * 0.30
        + is_new * 0.25
        + pattern_confidence * 0.15
        + hotspot_score * 0.15
        + fix_difficulty * 0.10
        + author_match * 0.05
}

/// Estimate fix difficulty from violation type.
/// 1.0 = trivial (naming, formatting), 0.2 = complex (architecture).
fn estimate_fix_difficulty(rule_id: &str) -> f64 {
    match rule_id {
        r if r.contains("naming") || r.contains("format") => 1.0,
        r if r.contains("console") || r.contains("todo") => 0.9,
        r if r.contains("import") || r.contains("dependency") => 0.7,
        r if r.contains("pattern") || r.contains("outlier") => 0.5,
        r if r.contains("security") || r.contains("auth") => 0.3,
        r if r.contains("architecture") || r.contains("coupling") => 0.2,
        _ => 0.5,
    }
}
```

### Cross-Gate Deduplication

Before prioritization, deduplicate violations across gates:

```rust
/// Deduplicate violations across gates.
/// Key: (file, line, rule_id). If two gates report the same location,
/// keep the one with higher severity.
pub fn deduplicate_violations(violations: &mut Vec<GateViolation>) {
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut to_remove = Vec::new();

    for (i, v) in violations.iter().enumerate() {
        let key = format!("{}:{}:{}", v.file, v.line, v.rule_id);
        if let Some(&existing_idx) = seen.get(&key) {
            // Keep higher severity
            if v.severity > violations[existing_idx].severity {
                to_remove.push(existing_idx);
                seen.insert(key, i);
            } else {
                to_remove.push(i);
            }
        } else {
            seen.insert(key, i);
        }
    }

    // Remove duplicates (reverse order to preserve indices)
    to_remove.sort_unstable();
    to_remove.dedup();
    for idx in to_remove.into_iter().rev() {
        violations.remove(idx);
    }
}
```

### "Fix These First" Highlighting

```typescript
// Top N violations by priority score highlighted in reporter output
const TOP_N = 5;
const fixTheseFirst = violations
    .sort((a, b) => (b.priorityScore ?? 0) - (a.priorityScore ?? 0))
    .slice(0, TOP_N);

// Text reporter output:
// ┌─────────────────────────────────────────────────┐
// │ 🎯 Fix These First (highest priority)           │
// ├─────────────────────────────────────────────────┤
// │ 1. src/auth/login.ts:42 — Missing auth (0.92)  │
// │ 2. src/api/users.ts:15 — Outlier pattern (0.78) │
// │ 3. src/db/queries.ts:88 — SQL pattern (0.71)   │
// └─────────────────────────────────────────────────┘
```

### Configurable Weights

```yaml
# In policy — override default priority weights
prioritization:
  weights:
    severity: 0.30
    isNew: 0.25
    patternConfidence: 0.15
    hotspotScore: 0.15
    fixDifficulty: 0.10
    authorMatch: 0.05
  topN: 5  # Number of "Fix These First" violations
```


---

## 19. Structured Violation Explanations (R15)

Every violation carries a structured explanation: WHY it's a violation, WHAT's expected,
HOW to fix it, and the IMPACT of not fixing it.

### Explanation Structure (Defined in §4.4)

```rust
pub struct ViolationExplanation {
    pub why: String,
    pub expected: String,
    pub how_to_fix: String,
    pub impact: String,
    pub learn_more: Option<String>,
    pub related_patterns: Vec<String>,
}
```

### Per-Gate Explanation Templates

| Gate | WHY | WHAT | HOW | IMPACT |
|------|-----|------|-----|--------|
| Pattern Compliance | "This code deviates from the '{name}' pattern (confidence: {conf}%)" | Pattern description | Pattern suggestion or "Follow the established pattern" | "{N} other locations follow this pattern" |
| Constraint Verification | "Constraint '{name}' violated" | Constraint expected behavior | Constraint suggestion | "Architectural constraint violations lead to tech debt" |
| Regression Detection | "Pattern confidence dropped by {delta}% since baseline" | "Confidence should remain within {threshold}% of baseline" | "Review recent changes that introduced outliers" | "Declining confidence indicates codebase drift" |
| Impact Simulation | "This change has a large blast radius" | "Changes should affect ≤{N} files" | "Break into smaller, focused PRs" | "Large blast radius increases risk of side effects" |
| Security Boundary | "Endpoint accesses '{table}' without auth" | "All routes accessing protected tables must use {auth}" | "Add {auth}() middleware before route handler" | "Unauthenticated requests can access protected data" |
| Custom Rules | Rule message | Rule description | Rule suggestion | "Custom rule violation" |

### Explanation in Reporter Output

```
❌ src/auth/login.ts:42 — Missing auth middleware [error]

   WHY:    This endpoint accesses the 'users' table which contains PII
   EXPECT: All routes accessing protected tables must use authenticate() middleware
   FIX:    Add authenticate() middleware before the route handler
   IMPACT: Without auth, any unauthenticated request can read user PII
   REF:    https://cwe.mitre.org/data/definitions/862.html
```

### SARIF Mapping

- `why` → `result.message.text`
- `how_to_fix` → `result.fixes[0].description.text`
- `learn_more` → `rule.helpUri`
- `expected` → `rule.fullDescription.text`
- `impact` → appended to `result.message.text`

---

## 20. Dry-Run / Preview Mode (R17)

Preview what gates would check without persisting results or affecting baselines.

### Behavior

| Step | Normal Run | Dry Run |
|------|-----------|---------|
| 1. resolveFiles | ✅ | ✅ |
| 2. loadPolicy | ✅ | ✅ |
| 3. determineGates | ✅ | ✅ |
| 4. checkCache | ✅ | ✅ (reads cache) |
| 5. buildContext | ✅ | ✅ |
| 6. executeGates | ✅ | ✅ |
| 7. evaluate | ✅ | ✅ |
| 8. prioritize | ✅ | ✅ |
| 9. aggregate | ✅ | ✅ |
| 10. persist | ✅ | ❌ SKIPPED |
| 11. notify | ✅ | ❌ SKIPPED |
| 12. report | ✅ | ✅ (with banner) |

### CLI Usage

```bash
# Preview on staged files
drift gate run --dry-run

# Preview with specific policy
drift gate run --dry-run --policy strict

# Preview showing only new violations
drift gate run --dry-run --mode pr --new-only

# Preview with full output
drift gate run --dry-run --format json --verbose
```

### Exit Codes

| Code | Normal Run | Dry Run |
|------|-----------|---------|
| 0 | All gates passed | Always (unless --strict-dry-run) |
| 1 | At least one gate failed | Only with --strict-dry-run |
| 2 | Execution error | Execution error |

### Output Banner

```
╔══════════════════════════════════════════════════════════════╗
║  DRY RUN — Results not persisted. Baselines not affected.   ║
║  Run without --dry-run to persist results.                  ║
╚══════════════════════════════════════════════════════════════╝
```

---

## 21. Hotspot-Aware Scoring (R11)

Violations in frequently-changed files are weighted higher because they have
disproportionate impact on development velocity.

### Hotspot Score Calculation

```rust
/// Calculate hotspot score for a file.
/// Score: 0.0 (rarely changed) to 1.0 (most frequently changed).
pub fn hotspot_score(
    file: &str,
    hotspot_data: &HotspotData,
) -> f64 {
    let freq = hotspot_data.change_frequency
        .get(file)
        .copied()
        .unwrap_or(0);

    if hotspot_data.max_frequency == 0 {
        return 0.0;
    }

    freq as f64 / hotspot_data.max_frequency as f64
}
```

### Hotspot Data Collection

```bash
# Collected during scan phase (not during gate execution)
# Cached in drift.db — refreshed on each full scan

# Change frequency: commits touching file in last 90 days
git log --format='%H' --since='90 days ago' -- <file> | wc -l

# Author count: distinct authors in last 90 days
git log --format='%ae' --since='90 days ago' -- <file> | sort -u | wc -l
```

### Integration with Gate Scoring (§5.1)

```
adjustedPenalty = basePenalty × (1 + hotspotScore × hotspotMultiplier)

Example:
  basePenalty = 10 (error)
  hotspotScore = 0.8 (frequently changed file)
  hotspotMultiplier = 0.5 (default)
  adjustedPenalty = 10 × (1 + 0.8 × 0.5) = 10 × 1.4 = 14

Effect: violations in hotspot files reduce the gate score more aggressively,
making them more likely to trigger warnings or failures.
```

### Integration with Priority Score (§18)

Hotspot score is a 0.15-weight factor in the priority formula. A violation in a
hotspot file with score 0.8 contributes 0.8 × 0.15 = 0.12 to the priority score.

### Configuration

```yaml
gates:
  pattern-compliance:
    hotspotMultiplier: 0.5    # Default: 0.5 (up to 1.5× penalty)
    # Set to 0.0 to disable hotspot scoring
    # Set to 1.0 for aggressive hotspot weighting (up to 2× penalty)
```

---

## 22. OWASP/CWE Alignment (R12)

Map all security-related violations to CWE IDs and OWASP Top 10 categories for
compliance reporting and SARIF taxonomy enrichment.

### CWE Mapping Table

| Drift Security Check | CWE ID | CWE Name | OWASP 2021 |
|---------------------|--------|----------|------------|
| Unauthorized data access | 862 | Missing Authorization | A01 Broken Access Control |
| Missing auth middleware | 306 | Missing Authentication | A07 Identification Failures |
| Unprotected sensitive data | 311 | Missing Encryption | A02 Cryptographic Failures |
| Hardcoded secrets | 798 | Hard-coded Credentials | A07 Identification Failures |
| SQL injection patterns | 89 | SQL Injection | A03 Injection |
| Missing input validation | 20 | Improper Input Validation | A03 Injection |
| Insecure configuration | 16 | Configuration | A05 Security Misconfiguration |
| Path traversal | 22 | Path Traversal | A01 Broken Access Control |
| XSS patterns | 79 | Cross-site Scripting | A03 Injection |
| SSRF patterns | 918 | Server-Side Request Forgery | A10 SSRF |

### CWE Registry (Rust)

```rust
/// CWE registry for mapping Drift violations to CWE/OWASP.
/// Loaded once, shared across all gate executions.
pub struct CweRegistry {
    entries: HashMap<String, CweEntry>,
}

pub struct CweEntry {
    pub cwe_id: u32,
    pub cwe_name: String,
    pub owasp_category: String,
    pub owasp_name: String,
    pub description: String,
    pub reference_url: String,
}

impl CweRegistry {
    /// Map a Drift rule_id to CWE/OWASP.
    pub fn lookup(&self, rule_id: &str) -> Option<&CweEntry> {
        self.entries.get(rule_id)
    }

    /// Enrich a violation with CWE/OWASP data.
    pub fn enrich_violation(&self, violation: &mut GateViolation) {
        if let Some(entry) = self.lookup(&violation.rule_id) {
            violation.cwe_id = Some(entry.cwe_id);
            violation.owasp_category = Some(entry.owasp_category.clone());
            if let Some(ref mut explanation) = violation.explanation {
                explanation.learn_more = Some(entry.reference_url.clone());
            }
        }
    }
}
```

### OWASP Compliance Report

```
OWASP Top 10 2021 Coverage Report
══════════════════════════════════
A01 Broken Access Control      ✅ Covered (3 checks, 0 violations)
A02 Cryptographic Failures     ✅ Covered (2 checks, 1 violation)
A03 Injection                  ✅ Covered (4 checks, 0 violations)
A04 Insecure Design            ⚠️  Partial (1 check — pattern compliance)
A05 Security Misconfiguration  ✅ Covered (3 checks, 0 violations)
A06 Vulnerable Components      ❌ Not covered (use dependency scanner)
A07 Identification Failures    ✅ Covered (2 checks, 0 violations)
A08 Software/Data Integrity    ⚠️  Partial (1 check — constraint verification)
A09 Logging Failures           ✅ Covered (2 checks, 0 violations)
A10 SSRF                       ⚠️  Partial (taint analysis integration)

Coverage: 7/10 fully covered, 3/10 partial
```

---

## 23. Gate Timeout & Partial Failure Recovery (R13)

### Per-Gate Timeout

```rust
/// Default timeout per gate (milliseconds).
pub const DEFAULT_GATE_TIMEOUT_MS: u64 = 30_000;

/// Gate-specific default timeouts.
pub fn default_timeout(gate_id: GateId) -> u64 {
    match gate_id {
        GateId::PatternCompliance => 15_000,      // Fast — pattern iteration
        GateId::ConstraintVerification => 30_000,  // Medium — AST evaluation
        GateId::RegressionDetection => 30_000,     // Medium — snapshot comparison
        GateId::ImpactSimulation => 30_000,        // Medium — call graph traversal
        GateId::SecurityBoundary => 60_000,        // Slow — deep call graph + taint
        GateId::CustomRules => 30_000,             // Variable — depends on rule count
    }
}
```

### Timeout Execution (TS Orchestrator)

```typescript
async function executeWithTimeout(
    gateId: GateId,
    input: GateInput,
    timeoutMs: number,
): Promise<GateResult> {
    return Promise.race([
        executeGate(gateId, input),
        new Promise<GateResult>((_, reject) =>
            setTimeout(() => reject(new Error(`Gate ${gateId} timed out after ${timeoutMs}ms`)),
                timeoutMs)
        ),
    ]).catch(err => ({
        gateId,
        gateName: gateId,
        status: 'errored' as GateStatus,
        passed: true,  // FAIL-SAFE: timeout doesn't block
        score: 0,
        summary: `Gate timed out after ${timeoutMs}ms`,
        violations: [],
        warnings: [`Gate execution timed out: ${err.message}`],
        executionTimeMs: timeoutMs,
        details: {},
        error: err.message,
    }));
}
```

### Partial Failure Recovery (Checkpoint/Resume)

```sql
-- After each gate completes, save checkpoint to gate_cache
INSERT OR REPLACE INTO gate_cache (cache_key, gate_id, branch, result, input_hash, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now', '+1 hour'));
```

```typescript
// On orchestrator startup, check for incomplete runs
async function resumeIncompleteRun(branch: string): Promise<Partial<Record<GateId, GateResult>>> {
    const checkpoints = await db.query(
        `SELECT gate_id, result FROM gate_cache
         WHERE branch = ? AND expires_at > datetime('now')
         ORDER BY created_at DESC`,
        [branch]
    );

    const completed: Partial<Record<GateId, GateResult>> = {};
    for (const cp of checkpoints) {
        completed[cp.gate_id as GateId] = JSON.parse(cp.result);
    }
    return completed;
}
```

### Fail-Safe Hierarchy

1. Gate throws exception → `status: errored`, `passed: true` (v1 behavior preserved)
2. Gate times out → `status: errored`, `passed: true`, warning logged
3. Gate returns invalid result → `status: errored`, `passed: true`, warning logged
4. Orchestrator crashes → next run resumes from checkpoint
5. SQLite unavailable → run all gates without caching (fail-open)

---

## 24. Custom Rule Expansion — AST & Call Graph Conditions (R14)

V1's 6 condition types + 3 new types = 9 total. Types defined in §4.8.

### AST Query Condition (Tree-Sitter)

```yaml
# Example: No direct database access in controllers
- id: no-direct-db-access
  name: "No direct database access in controllers"
  severity: error
  condition:
    type: ast-query
    query: |
      (call_expression
        function: (member_expression
          object: (identifier) @obj
          (#match? @obj "^(db|prisma|sequelize|knex)$")))
    scope: "src/controllers/**"
    mustNot: true
  message: "Controllers must not access the database directly. Use a service layer."
  suggestion: "Move database access to a service class and inject it."

# Example: All exported functions must have JSDoc
- id: require-jsdoc-exports
  name: "Exported functions require JSDoc"
  severity: warning
  condition:
    type: ast-query
    query: |
      (export_statement
        declaration: (function_declaration
          name: (identifier) @name
          !comment))
    scope: "src/**/*.ts"
    mustNot: false  # Must match = must have JSDoc
  message: "Exported function missing JSDoc documentation"
```

### Call Graph Condition

```yaml
# Example: Controllers must not call other controllers
- id: no-controller-to-controller
  name: "No controller-to-controller calls"
  severity: error
  condition:
    type: call-graph
    source:
      pattern: "src/controllers/**"
      function: ".*"
    target:
      pattern: "src/controllers/**"
      function: ".*"
    mustNot: true
  message: "Controllers should not call other controllers. Extract shared logic to a service."

# Example: All database access must go through repository layer
- id: db-through-repository
  name: "Database access via repository only"
  severity: error
  condition:
    type: call-graph
    source:
      pattern: "src/**"
      function: ".*"
    target:
      pattern: "node_modules/prisma/**"
    mustNot: true
    except:
      pattern: "src/repositories/**"
  message: "Database access must go through the repository layer."
```

### Metric Condition

```yaml
# Example: Function complexity limit
- id: max-complexity
  name: "Function cyclomatic complexity limit"
  severity: warning
  condition:
    type: metric
    metric: cyclomatic-complexity
    threshold: 15
    operator: less-than-or-equal
    scope: "src/**"
  message: "Function complexity exceeds 15. Consider refactoring."

# Example: File length limit
- id: max-file-length
  name: "File length limit"
  severity: info
  condition:
    type: metric
    metric: lines-of-code
    threshold: 500
    operator: less-than-or-equal
    scope: "src/**"
  message: "File exceeds 500 lines. Consider splitting."
```

### Condition Evaluation Dispatch

```rust
/// Evaluate a rule condition against the project.
pub fn evaluate_condition(
    condition: &RuleCondition,
    files: &[String],
    context: &GateContext,
) -> DriftResult<ConditionResult> {
    match condition {
        // V1 conditions (all 6 preserved)
        RuleCondition::FilePattern { pattern, must_exist } =>
            evaluate_file_pattern(pattern, must_exist, files),
        RuleCondition::ContentPattern { pattern, scope, must_match } =>
            evaluate_content_pattern(pattern, scope.as_deref(), must_match, files),
        RuleCondition::Dependency { package, version, must_exist } =>
            evaluate_dependency(package, version.as_deref(), must_exist),
        RuleCondition::Naming { pattern, scope, target } =>
            evaluate_naming(pattern, scope, target, files),
        RuleCondition::Structure { directory, required_files } =>
            evaluate_structure(directory, required_files),
        RuleCondition::Composite { operator, conditions } =>
            evaluate_composite(operator, conditions, files, context),

        // V2 new conditions
        RuleCondition::AstQuery { query, scope, must_match, language } =>
            evaluate_ast_query(query, scope.as_deref(), must_match, language.as_deref(), files),
        RuleCondition::CallGraph { source, target, must_exist } =>
            evaluate_call_graph(source, target, must_exist, context),
        RuleCondition::Metric { metric, threshold, operator, scope } =>
            evaluate_metric(metric, *threshold, operator, scope.as_deref(), files, context),
    }
}
```

---

## 25. Webhook & Notification System (R18)

Fire-and-forget notifications triggered by gate results.

### Notification Engine (TS)

```typescript
export class NotificationEngine {
    private templateEngine: TemplateEngine;

    constructor() {
        this.templateEngine = new TemplateEngine();
    }

    async fire(
        result: QualityGateResult,
        actions: PolicyActions,
    ): Promise<void> {
        const hooks = this.selectHooks(result, actions);

        // Fire all webhooks in parallel, fail-open
        await Promise.allSettled(
            hooks.map(hook => this.executeHook(hook, result))
        );
    }

    private selectHooks(result: QualityGateResult, actions: PolicyActions): WebhookAction[] {
        if (!result.passed && actions.onFail) return actions.onFail;
        if (result.passed && result.warnings.length > 0 && actions.onWarn) return actions.onWarn;
        if (result.passed && actions.onPass) return actions.onPass;
        return [];
    }

    private async executeHook(hook: WebhookAction, result: QualityGateResult): Promise<void> {
        const body = this.templateEngine.render(hook.body, {
            branch: result.metadata.branch,
            commitSha: result.metadata.commitSha ?? '',
            score: result.score.toFixed(1),
            status: result.status,
            summary: result.summary,
            violationCount: result.violations.length,
            newViolationCount: result.metadata.newViolations,
            gatesRun: result.metadata.gatesRun.join(', '),
            gatesFailed: Object.entries(result.gates)
                .filter(([_, r]) => !r.passed)
                .map(([id]) => id)
                .join(', '),
            executionTimeMs: result.metadata.executionTimeMs,
        });

        try {
            await fetch(hook.url, {
                method: hook.method ?? 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...hook.headers,
                },
                body,
                signal: AbortSignal.timeout(5000), // 5s timeout
            });
        } catch (err) {
            // Fail-open: notification failure never blocks gate result
            console.warn(`Webhook failed: ${hook.url} — ${err}`);
        }
    }
}
```

### Template Variables

| Variable | Type | Description |
|----------|------|-------------|
| `{{branch}}` | string | Current branch name |
| `{{commitSha}}` | string | Current commit SHA |
| `{{score}}` | string | Overall gate score (e.g., "72.5") |
| `{{status}}` | string | Overall status (passed/failed/warned) |
| `{{summary}}` | string | One-line summary |
| `{{violationCount}}` | number | Total violation count |
| `{{newViolationCount}}` | number | New violations only (R1) |
| `{{gatesRun}}` | string | Comma-separated gate IDs |
| `{{gatesFailed}}` | string | Comma-separated failed gate IDs |
| `{{executionTimeMs}}` | number | Total execution time |
| `{{env.VAR_NAME}}` | string | Environment variable (for secrets) |

### Policy Configuration

```yaml
actions:
  onFail:
    - type: webhook
      url: "{{env.SLACK_WEBHOOK_URL}}"
      body: |
        {
          "text": "🚨 Quality gate FAILED on {{branch}} (score: {{score}})",
          "blocks": [{
            "type": "section",
            "text": {
              "type": "mrkdwn",
              "text": "*Branch:* {{branch}}\n*Score:* {{score}}\n*Failed:* {{gatesFailed}}\n*Violations:* {{violationCount}} ({{newViolationCount}} new)"
            }
          }]
        }
  onPass:
    - type: webhook
      url: "{{env.SLACK_WEBHOOK_URL}}"
      body: |
        { "text": "✅ Quality gate passed on {{branch}} (score: {{score}})" }
```


---

## 26. Integration with Upstream Systems

Quality gates is a pure consumer. It reads from upstream systems but never writes back
(except feedback → pattern confidence, which flows through the audit system).

### Integration Matrix

| Upstream System | Data Consumed | Gate(s) That Use It | Load Strategy |
|----------------|---------------|--------------------|--------------| 
| Detector System (06) | Approved patterns, outliers, confidence, locations | Pattern Compliance, Regression Detection | Lazy — only if gate enabled |
| Constraint System (20) | Active constraints, verification results | Constraint Verification | Lazy — only if gate enabled |
| Call Graph Builder (05) | Function edges, reachability, entry points | Impact Simulation, Security Boundary, Custom Rules (call-graph condition) | Lazy — only if impact/security/call-graph-rules enabled |
| Boundary Detection (07) | Data access points, sensitive fields, ORM mappings | Security Boundary | Lazy — loaded with call graph |
| Taint Analysis (15) | Source→sink paths, sanitizer locations, CWE mappings | Security Boundary (enrichment) | Lazy — only if `include_taint: true` |
| DNA System (24) | Health score, mutation count, genetic diversity | Optional gate criterion (via custom rules) | Lazy — only if DNA rules configured |
| Coupling Analysis (19) | Cycle count, health score, hotspot count | Impact Simulation (coupling depth enrichment) | Lazy — only if `include_coupling: true` |
| Error Handling (16) | Error gaps, propagation chains, boundary coverage | Optional gate criterion (via custom rules) | Lazy — only if error handling rules configured |
| Constants/Secrets (22) | Secret count by severity, magic number count | Security Boundary (enrichment) | Lazy — loaded with security gate |
| Wrapper Detection (23) | Wrapper health score, thin delegation count | Optional gate criterion (via custom rules) | Lazy — only if wrapper rules configured |
| OWASP/CWE Mapping (26) | CWE IDs, OWASP categories per violation | Security Boundary, SARIF Reporter | Loaded once at startup, shared |
| Storage (02) | drift.db SQLite with WAL mode | All persistence | Always available |
| Parsers (01) | ParseResult with AST data | Custom Rules (AST condition) | Lazy — only if AST rules configured |
| Scanner (00) | File list, content hashes, git diff | File resolution, cache invalidation | Always loaded (step 1) |

### Lazy Context Loading

The orchestrator only loads what active gates need:

```typescript
async buildContext(gates: GateId[], options: QualityGateOptions): Promise<GateContext> {
    const context: GateContext = { projectRoot: this.projectRoot };

    // Only load patterns if pattern-compliance or regression-detection is active
    if (gates.includes('pattern-compliance') || gates.includes('regression-detection')) {
        context.patterns = await this.native.queryPatterns({ status: 'approved' });
    }

    // Only load constraints if constraint-verification is active
    if (gates.includes('constraint-verification')) {
        context.constraints = await this.native.queryConstraints({ status: 'active' });
    }

    // Only load call graph if impact-simulation or security-boundary is active
    if (gates.includes('impact-simulation') || gates.includes('security-boundary')) {
        context.callGraph = await this.native.getCallGraph();
    }

    // Only load custom rules if custom-rules gate is active
    if (gates.includes('custom-rules')) {
        context.customRules = await this.loadCustomRules(options);
    }

    // Only load hotspot data if any gate uses hotspot scoring
    if (options.mode !== 'pre-commit') {
        context.hotspotData = await this.native.getHotspotData();
    }

    // CWE registry loaded once, shared
    context.cweRegistry = await this.native.getCweRegistry();

    return context;
}
```

---

## 27. Integration with Downstream Consumers

### Consumer Interface Matrix

| Consumer | Interface | Data Format | Latency Requirement |
|----------|-----------|-------------|--------------------| 
| CLI | `drift gate run` → `QualityGateResult` | Formatted by reporter | <30s for PR, <5m for full |
| MCP Server | `drift_quality_gate` tool | JSON `QualityGateResult` | <30s |
| NAPI Bridge | `run_quality_gates()` | Rust `QualityGateResult` → serde_json | <30s |
| CI Pipelines | Exit code + reporter output | SARIF, JUnit XML, text | <2m |
| IDE / LSP | Diagnostics on file save | LSP Diagnostic[] | <1s |
| DriftEventHandler | `on_gate_evaluated` event | `GateEvaluatedEvent` | Fire-and-forget |
| Audit System | Gate run data | `GateRunRecord` in drift.db | Async (post-run) |
| Context Generation | Active violations for AI | Violation summaries | On-demand query |

### DriftEventHandler Events

```rust
/// Events emitted by quality gates via DriftEventHandler (D5).
pub enum GateEvent {
    /// Emitted when a gate completes evaluation.
    GateEvaluated {
        gate_id: GateId,
        status: GateStatus,
        score: f64,
        violation_count: u32,
        execution_time_ms: u64,
    },
    /// Emitted when a regression is detected.
    RegressionDetected {
        pattern_id: String,
        pattern_name: String,
        confidence_delta: f64,
        severity: RegressionSeverity,
    },
    /// Emitted when overall gate run completes.
    GateRunCompleted {
        passed: bool,
        score: f64,
        total_violations: u32,
        new_violations: u32,
        execution_time_ms: u64,
    },
    /// Emitted when a pattern is promoted/demoted (R2).
    EnforcementModeChanged {
        pattern_id: String,
        from: EnforcementMode,
        to: EnforcementMode,
        reason: String,
    },
    /// Emitted when health score degrades (audit).
    HealthDegradation {
        current_score: f64,
        previous_score: f64,
        delta: f64,
        severity: DegradationSeverity,
    },
}
```

---

## 28. NAPI Bridge Interface

Thin NAPI wrappers that expose Rust gate analysis to the TS orchestrator.
Per 03-NAPI-BRIDGE-V2-PREP.md §10.12.

### NAPI Functions

```rust
// ── Gate Execution ──

/// Run all quality gates. The primary entry point.
/// Called by TS GateOrchestrator.
#[napi]
pub fn run_quality_gates(input: JsGateInput) -> napi::Result<JsQualityGateResult> {
    // Delegates to Rust gate implementations
    // Returns full QualityGateResult as JSON
}

/// Run a single gate (for incremental execution).
#[napi]
pub fn run_single_gate(gate_id: String, input: JsGateInput) -> napi::Result<JsGateResult> {
    // Delegates to specific gate implementation
}

// ── History & Queries ──

/// Query gate run history with keyset pagination.
#[napi]
pub fn query_gate_history(
    branch: Option<String>,
    limit: Option<u32>,
    cursor: Option<String>,
) -> napi::Result<JsPagedGateRuns> {
    // SELECT from gate_runs with pagination
}

/// Get the latest health snapshot for a branch.
#[napi]
pub fn get_health_snapshot(branch: String) -> napi::Result<Option<JsHealthSnapshot>> {
    // SELECT from health_snapshots ORDER BY timestamp DESC LIMIT 1
}

// ── Audit ──

/// Run the audit engine (health score, duplicates, degradation).
#[napi]
pub fn run_audit() -> napi::Result<JsAuditResult> {
    // Delegates to Rust audit implementation
}

// ── Cache ──

/// Check gate cache for a given cache key.
#[napi]
pub fn check_gate_cache(cache_key: String, branch: String) -> napi::Result<Option<JsGateResult>> {
    // SELECT from gate_cache WHERE cache_key = ? AND branch = ?
}

/// Save gate result to cache.
#[napi]
pub fn save_gate_cache(
    cache_key: String,
    gate_id: String,
    branch: String,
    result: JsGateResult,
    input_hash: String,
) -> napi::Result<()> {
    // INSERT OR REPLACE INTO gate_cache
}

// ── Feedback ──

/// Record violation feedback.
#[napi]
pub fn record_violation_feedback(feedback: JsViolationFeedback) -> napi::Result<()> {
    // INSERT INTO violation_feedback
}

/// Query feedback for a pattern.
#[napi]
pub fn query_violation_feedback(
    pattern_id: String,
    limit: Option<u32>,
) -> napi::Result<Vec<JsViolationFeedback>> {
    // SELECT from violation_feedback WHERE pattern_id = ?
}

// ── Hotspot Data ──

/// Get hotspot data (file change frequencies).
#[napi]
pub fn get_hotspot_data() -> napi::Result<JsHotspotData> {
    // Computed from git log, cached in drift.db
}

// ── CWE Registry ──

/// Get the CWE/OWASP mapping registry.
#[napi]
pub fn get_cwe_registry() -> napi::Result<JsCweRegistry> {
    // Static data, loaded once
}
```

### Batch API Integration

Per 03-NAPI-BRIDGE-V2-PREP.md §9, quality gates can be included in batch analysis:

```rust
#[napi]
pub fn analyze_batch(root: String, analyses: Vec<AnalysisType>) -> napi::Result<JsBatchResult> {
    // If analyses includes AnalysisType::QualityGates:
    //   run_quality_gates() as part of the batch
}
```

---

## 29. CLI Interface

### Commands

```bash
# ── Gate Execution ──
drift gate run                          # Run gates with default policy, PR mode
drift gate run --policy strict          # Run with specific policy
drift gate run --mode full              # Full scan (all files)
drift gate run --mode pre-commit        # Pre-commit mode (staged files, <5s)
drift gate run --mode regression        # Post-merge regression check
drift gate run --dry-run                # Preview without persisting
drift gate run --format sarif,junit     # Multiple output formats
drift gate run --output-dir ./reports   # Output directory for reports
drift gate run --new-only               # Show only new violations
drift gate run --verbose                # Detailed output
drift gate run --timeout 60000          # Override global timeout (ms)
drift gate run --gate pattern-compliance # Run single gate only
drift gate run --sarif-level full       # SARIF detail level

# ── Policy Management ──
drift policy list                       # List available policies
drift policy show <id>                  # Show resolved policy
drift policy diff <a> <b>               # Diff two policies
drift policy validate <path>            # Validate policy file
drift policy resolve <id>               # Show fully resolved policy (with inheritance)

# ── Baseline Management ──
drift gate baseline set                 # Set current state as baseline
drift gate baseline reset               # Reset baseline to empty
drift gate baseline compare             # Compare current vs baseline
drift gate baseline show                # Show current baseline info

# ── History & Audit ──
drift gate history                      # Show recent gate runs
drift gate history --branch main        # Filter by branch
drift gate audit                        # Run audit (health score, duplicates)
drift gate audit --verbose              # Detailed audit output

# ── Feedback ──
drift gate dismiss <violation-id> --reason false-positive
drift gate dismiss <violation-id> --reason wont-fix --comment "Intentional"
drift gate dismiss <violation-id> --reason not-applicable

# ── Hooks ──
drift hooks install                     # Install pre-commit/post-merge hooks
drift hooks uninstall                   # Remove hooks
drift hooks status                      # Show installed hooks
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All gates passed |
| 1 | At least one blocking gate failed |
| 2 | Execution error (config, timeout, crash) |

---

## 30. MCP Tool Interface

### drift_quality_gate Tool

```typescript
// MCP tool definition
{
    name: "drift_quality_gate",
    description: "Run quality gates on the current project",
    inputSchema: {
        type: "object",
        properties: {
            mode: {
                type: "string",
                enum: ["pr", "full", "regression", "pre-commit"],
                default: "pr",
                description: "Execution mode"
            },
            policy: {
                type: "string",
                description: "Policy ID or path"
            },
            files: {
                type: "array",
                items: { type: "string" },
                description: "Specific files to check (optional)"
            },
            dryRun: {
                type: "boolean",
                default: false,
                description: "Preview without persisting"
            },
            gate: {
                type: "string",
                description: "Run single gate only (optional)"
            },
            format: {
                type: "string",
                enum: ["json", "text", "sarif"],
                default: "json",
                description: "Output format"
            }
        }
    }
}
```

### Additional MCP Tools

```typescript
// Query gate history
{
    name: "drift_gate_history",
    description: "Query quality gate run history",
    inputSchema: {
        type: "object",
        properties: {
            branch: { type: "string" },
            limit: { type: "number", default: 10 }
        }
    }
}

// Dismiss violation
{
    name: "drift_gate_dismiss",
    description: "Dismiss a quality gate violation",
    inputSchema: {
        type: "object",
        properties: {
            violationId: { type: "string" },
            reason: {
                type: "string",
                enum: ["false-positive", "wont-fix", "not-applicable"]
            },
            comment: { type: "string" }
        },
        required: ["violationId", "reason"]
    }
}

// Run audit
{
    name: "drift_gate_audit",
    description: "Run quality gate audit (health score, duplicates, degradation)",
    inputSchema: {
        type: "object",
        properties: {
            verbose: { type: "boolean", default: false }
        }
    }
}
```

---

## 31. License Gating — Tier Mapping

Preserved from v1. Quality gate features are gated by license tier.

### Feature → Tier Matrix

| Feature | Community (Free) | Team | Enterprise |
|---------|-----------------|------|-----------|
| Pattern compliance gate | ✅ | ✅ | ✅ |
| Constraint verification gate | ✅ | ✅ | ✅ |
| Regression detection gate | ✅ | ✅ | ✅ |
| Impact simulation gate | ❌ | ✅ | ✅ |
| Security boundary gate | ❌ | ✅ | ✅ |
| Custom rules gate (6 v1 types) | ❌ | ✅ | ✅ |
| Custom rules (AST/call-graph/metric) | ❌ | ❌ | ✅ |
| Built-in policies (4) | ✅ | ✅ | ✅ |
| Custom policies (YAML/JSON) | ❌ | ✅ | ✅ |
| Policy inheritance | ❌ | ❌ | ✅ |
| Policy packs | ❌ | ❌ | ✅ |
| Text reporter | ✅ | ✅ | ✅ |
| JSON reporter | ✅ | ✅ | ✅ |
| SARIF reporter (basic) | ✅ | ✅ | ✅ |
| SARIF reporter (full — codeFlows, fixes) | ❌ | ✅ | ✅ |
| GitHub/GitLab reporters | ❌ | ✅ | ✅ |
| JUnit XML reporter | ✅ | ✅ | ✅ |
| HTML reporter | ❌ | ✅ | ✅ |
| Reporter plugins | ❌ | ❌ | ✅ |
| Gate history (last 10 runs) | ✅ | ✅ | ✅ |
| Gate history (unlimited) | ❌ | ✅ | ✅ |
| Audit (health score) | ✅ | ✅ | ✅ |
| Audit (degradation tracking) | ❌ | ✅ | ✅ |
| Developer feedback loop | ❌ | ✅ | ✅ |
| Webhooks/notifications | ❌ | ❌ | ✅ |
| Multi-stage enforcement | ❌ | ✅ | ✅ |
| Incremental caching | ✅ | ✅ | ✅ |
| Hotspot-aware scoring | ❌ | ✅ | ✅ |
| OWASP/CWE compliance report | ❌ | ❌ | ✅ |
| Dry-run mode | ✅ | ✅ | ✅ |

### Tier Check Implementation

```typescript
function isFeatureAvailable(feature: GateFeature, tier: LicenseTier): boolean {
    const tierLevel = { community: 0, team: 1, enterprise: 2 };
    const requiredTier = FEATURE_TIER_MAP[feature];
    return tierLevel[tier] >= tierLevel[requiredTier];
}

// Used in orchestrator:
// if (!isFeatureAvailable('impact-simulation', license.tier)) {
//     skip gate, add to gatesSkipped
// }
```


---

## 32. Resolved Inconsistencies

Issues found across v1 source documents and research that are resolved in this spec.

| # | Inconsistency | Source | Resolution |
|---|--------------|--------|------------|
| 1 | overview.md says "ParallelExecutor runs all gates in parallel" but gates.md says "regression-detection needs pattern-compliance results" | overview.md vs gates.md | Resolved: DependencyExecutor replaces ParallelExecutor. Gates declare dependencies. Topological execution in groups (§17). |
| 2 | types.md defines `OutputFormat` with 5 values but reporters.md describes 5 reporters with different naming | types.md vs reporters.md | Resolved: OutputFormat enum has 7 values (§4.1). Reporter IDs match format names exactly. |
| 3 | policy.md says "4 built-in policies" but overview.md says "3 built-in policies" | policy.md vs overview.md | Resolved: 4 built-in policies (default, strict, relaxed, ci-fast) as documented in policy.md (§7). |
| 4 | store.md says "50 snapshots per branch" but audit.md says "90-day retention" | store.md vs audit.md | Resolved: Both apply. Snapshots: 50 per branch. Audit history: 90-day retention. Gate runs: 90-day retention. Different tables, different policies (§9). |
| 5 | RECOMMENDATIONS R10 proposes SQLite migration but RECAP says "stores stay TS" | RECOMMENDATIONS vs RECAP | Resolved: Persistence layer is Rust (SQLite via drift.db). Store logic (queries, retention) is Rust. TS orchestrator calls NAPI for all persistence (§9, §28). |
| 6 | gates.md says "custom rules: 6 condition types" but types.md lists only 5 in the enum | gates.md vs types.md | Resolved: 6 v1 types (FilePattern, ContentPattern, Dependency, Naming, Structure, Composite) + 3 v2 types = 9 total (§4.8). |
| 7 | AUDIT.md GAP-1 says "gate scoring weights not validated" | AUDIT.md | Resolved: Weights preserved from v1 (error=10, warning=3, info=1, hint=0) but now configurable per-gate in policy. Teams can tune. Hotspot multiplier adds context-aware weighting (§21). |
| 8 | AUDIT.md GAP-2 says "audit health score weights not validated" | AUDIT.md | Resolved: Weights preserved exactly (0.30/0.20/0.20/0.15/0.15). Working well in v1. Configurable in v2 if teams want to tune (§10). |
| 9 | AUDIT.md GAP-7 says "O(p²) duplicate detection not improved algorithmically" | AUDIT.md | Resolved: Algorithm preserved (Jaccard similarity, same-category). Rust implementation provides 10-50× speedup. For expected scale (<10K patterns), O(p²) in Rust is fast enough. LSH/MinHash deferred to P3 if needed (§10). |
| 10 | AUDIT.md GAP-8 says "security auth detection remains heuristic" | AUDIT.md | Resolved: Auth detection still uses function name matching (v1 preserved) but enriched with: (a) CWE/OWASP mapping (§22), (b) taint analysis integration for data flow (§5.6), (c) AST-based custom rules can express auth patterns (§24). Full AST-based auth flow analysis deferred to P3. |
| 11 | AUDIT.md GAP-14 says "no cross-repo strategy" | AUDIT.md | Resolved: Enterprise P2 feature. Shared policies via policy packs (npm packages). Cross-repo quality dashboards via SARIF aggregation. Full multi-repo gate orchestration deferred to post-v2. |
| 12 | AUDIT.md GAP-16 says "Cortex integration not fully explored" | AUDIT.md | Resolved: Feedback loop (§15) creates tribal knowledge: "Pattern X doesn't apply to auth modules" → stored as violation_feedback → consumed by audit for confidence adjustment. Deep Cortex memory integration deferred to P3. |
| 13 | AUDIT.md GAP-17 says "data lake / materialized views not addressed" | AUDIT.md | Resolved: SQLite views replace data lake. Gate trend data queryable via: `SELECT branch, date(timestamp), avg(score) FROM gate_runs GROUP BY branch, date(timestamp)`. Materialized views are a Storage (02) responsibility. |
| 14 | AUDIT.md GAP-18 says "services layer integration not addressed" | AUDIT.md | Resolved: The CLI orchestrates both scanning and gate execution. `drift gate run` calls scanner first (if needed), then gates. The scan pipeline (25) triggers gates as a post-scan step. Gate orchestrator is independent — it receives pre-computed context. |

---

## 33. File Module Structure

```
drift-core/
├── src/
│   ├── gates/
│   │   ├── mod.rs                      # pub mod declarations, GateId, QualityGate trait
│   │   ├── scoring.rs                  # calculate_score, determine_status, violation_id, error_result
│   │   ├── pattern_compliance.rs       # PatternComplianceGate
│   │   ├── constraint_verification.rs  # ConstraintVerificationGate
│   │   ├── regression_detection.rs     # RegressionDetectionGate, statistical significance
│   │   ├── impact_simulation.rs        # ImpactSimulationGate, friction score
│   │   ├── security_boundary.rs        # SecurityBoundaryGate, CWE enrichment
│   │   ├── custom_rules.rs             # CustomRulesGate, condition evaluation
│   │   ├── conditions/
│   │   │   ├── mod.rs                  # evaluate_condition dispatch
│   │   │   ├── file_pattern.rs         # FilePattern condition
│   │   │   ├── content_pattern.rs      # ContentPattern condition
│   │   │   ├── dependency.rs           # Dependency condition
│   │   │   ├── naming.rs              # Naming condition
│   │   │   ├── structure.rs           # Structure condition
│   │   │   ├── composite.rs           # Composite (AND/OR/NOT) condition
│   │   │   ├── ast_query.rs           # AstQuery condition (tree-sitter)
│   │   │   ├── call_graph.rs          # CallGraph condition
│   │   │   └── metric.rs             # Metric condition
│   │   ├── cache.rs                    # Gate cache (3-tier caching)
│   │   ├── priority.rs                 # PriorityScorer, deduplication
│   │   ├── hotspot.rs                  # Hotspot data collection and scoring
│   │   ├── cwe_registry.rs            # CWE/OWASP mapping registry
│   │   ├── enforcement.rs             # Progressive enforcement (promotion/demotion)
│   │   └── types.rs                    # All gate types (§4)
│   ├── audit/
│   │   ├── mod.rs                      # AuditEngine
│   │   ├── health_score.rs            # Health score calculation (5-factor)
│   │   ├── duplicates.rs              # Duplicate detection (Jaccard)
│   │   ├── degradation.rs            # Degradation tracking, trend analysis
│   │   └── recommendations.rs        # Pattern recommendation engine
│   └── persistence/
│       ├── gate_runs.rs               # gate_runs table CRUD
│       ├── health_snapshots.rs        # health_snapshots table CRUD
│       ├── audit_history.rs           # audit_history table CRUD
│       ├── violation_feedback.rs      # violation_feedback table CRUD
│       └── gate_cache.rs             # gate_cache table CRUD

drift-napi/
├── src/
│   ├── gates.rs                       # NAPI bindings for gate execution
│   ├── audit.rs                       # NAPI bindings for audit
│   ├── cache.rs                       # NAPI bindings for cache operations
│   └── feedback.rs                    # NAPI bindings for feedback

packages/drift/
├── src/
│   ├── gates/
│   │   ├── orchestrator.ts            # GateOrchestrator (12-step pipeline)
│   │   ├── registry.ts                # GateRegistry (singleton, lazy import)
│   │   ├── executor.ts                # DependencyExecutor (DAG, timeout, early termination)
│   │   ├── evaluator.ts               # PolicyEvaluator (4 aggregation modes)
│   │   ├── aggregator.ts              # ResultAggregator (dedup, merge)
│   │   └── types.ts                   # TS mirror types (generated from Rust)
│   ├── policy/
│   │   ├── loader.ts                  # PolicyLoader (YAML/JSON, inheritance, context)
│   │   ├── built-in/
│   │   │   ├── default.yaml           # Default policy
│   │   │   ├── strict.yaml            # Strict policy
│   │   │   ├── relaxed.yaml           # Relaxed policy
│   │   │   ├── ci-fast.yaml           # CI-fast policy
│   │   │   ├── pre-commit.yaml        # Pre-commit preset
│   │   │   └── post-merge.yaml        # Post-merge preset
│   │   └── schema.json                # Policy JSON Schema for validation
│   ├── reporters/
│   │   ├── registry.ts                # ReporterRegistry (built-in + plugins)
│   │   ├── text.ts                    # TextReporter
│   │   ├── json.ts                    # JsonReporter
│   │   ├── sarif.ts                   # SarifReporter (full 2.1.0)
│   │   ├── github.ts                  # GithubReporter (with feedback actions)
│   │   ├── gitlab.ts                  # GitlabReporter (with feedback actions)
│   │   ├── junit.ts                   # JunitReporter (NEW)
│   │   └── html.ts                    # HtmlReporter (NEW)
│   └── notifications/
│       ├── engine.ts                  # NotificationEngine
│       └── templates.ts               # Template variable resolution
```

---

## 34. Build Order & Dependency Chain

Quality gates is Level 3 (Enforcement). It depends on Level 1 (Analysis) and Level 2
(Intelligence) systems being built first.

### Build Phases (Internal to Quality Gates)

```
Phase 1 — Rust Foundation:
  drift-core/src/gates/mod.rs          (GateId, QualityGate trait)
  drift-core/src/gates/types.rs        (all type definitions)
  drift-core/src/gates/scoring.rs      (base scoring algorithm)
  drift-core/src/persistence/*.rs      (SQLite table CRUD)
  drift-core/src/gates/cache.rs        (3-tier caching)
  drift-core/src/gates/cwe_registry.rs (CWE/OWASP mapping)
  drift-core/src/gates/enforcement.rs  (progressive enforcement types)

Phase 2 — Gate Implementations (Rust):
  drift-core/src/gates/pattern_compliance.rs
  drift-core/src/gates/constraint_verification.rs
  drift-core/src/gates/regression_detection.rs
  drift-core/src/gates/impact_simulation.rs
  drift-core/src/gates/security_boundary.rs
  drift-core/src/gates/custom_rules.rs
  drift-core/src/gates/conditions/*.rs  (all 9 condition types)

Phase 3 — Audit (Rust):
  drift-core/src/audit/health_score.rs
  drift-core/src/audit/duplicates.rs
  drift-core/src/audit/degradation.rs
  drift-core/src/audit/recommendations.rs

Phase 4 — NAPI Bridge:
  drift-napi/src/gates.rs
  drift-napi/src/audit.rs
  drift-napi/src/cache.rs
  drift-napi/src/feedback.rs

Phase 5 — TS Orchestration:
  packages/drift/src/gates/orchestrator.ts
  packages/drift/src/gates/registry.ts
  packages/drift/src/gates/executor.ts
  packages/drift/src/gates/evaluator.ts
  packages/drift/src/gates/aggregator.ts

Phase 6 — Policy Engine:
  packages/drift/src/policy/loader.ts
  packages/drift/src/policy/built-in/*.yaml
  packages/drift/src/policy/schema.json

Phase 7 — Reporters:
  packages/drift/src/reporters/*.ts     (all 7 + registry)

Phase 8 — Notifications & Feedback:
  packages/drift/src/notifications/engine.ts
  packages/drift/src/notifications/templates.ts
```

### External Dependencies (Must Be Built First)

| Dependency | Required By | Phase |
|-----------|-------------|-------|
| Storage (02) — drift.db schema | All persistence | Before Phase 1 |
| Parsers (01) — ParseResult | AST conditions | Before Phase 2 |
| Detector System (06) — Pattern types | Pattern compliance, regression | Before Phase 2 |
| Constraint System (20) — Constraint types | Constraint verification | Before Phase 2 |
| Call Graph (05) — CallGraph handle | Impact simulation, security boundary | Before Phase 2 |
| Taint Analysis (15) — Taint paths | Security boundary enrichment | Before Phase 2 |
| OWASP/CWE Mapping (26) — CWE registry | CWE enrichment | Before Phase 1 |
| NAPI Bridge (03) — napi-rs setup | All NAPI bindings | Before Phase 4 |
| Infrastructure (04) — DriftEventHandler | Event emission | Before Phase 5 |
| Scanner (00) — File resolution | Orchestrator step 1 | Before Phase 5 |

---

## 35. V1 Feature Verification — Complete Gap Analysis

Cross-referenced against all v1 documentation, the RECAP (20 limitations, 12 open
questions), the AUDIT (15 gaps), and every recommendation (R1-R19).

### V1 Core Components — All Accounted For

| V1 Component | Lines in V1 | V2 Section | Status |
|-------------|-------------|-----------|--------|
| GateOrchestrator (9-step pipeline) | ~200 | §6 | ✅ Upgraded to 12-step |
| GateRegistry (singleton) | ~50 | §6 | ✅ Preserved |
| ParallelExecutor | ~80 | §17 | ✅ Replaced by DependencyExecutor |
| ResultAggregator | ~60 | §18 | ✅ Upgraded with dedup + priority |
| BaseGate (scoring, fail-safe) | ~100 | §5.1 | ✅ Preserved as Rust functions |
| PatternComplianceGate | ~150 | §5.2 | ✅ Upgraded with R1, R2, R11, R15 |
| ConstraintVerificationGate | ~120 | §5.3 | ✅ Upgraded with baseline-aware R1 |
| RegressionDetectionGate | ~180 | §5.4 | ✅ Upgraded with statistical significance R10 |
| ImpactSimulationGate | ~200 | §5.5 | ✅ Upgraded with Rust call graph traversal |
| SecurityBoundaryGate | ~250 | §5.6 | ✅ Upgraded with CWE/OWASP R12, taint |
| CustomRulesGate | ~300 | §5.7 | ✅ Upgraded with 3 new condition types R14 |
| PolicyLoader (5-step resolution) | ~150 | §7 | ✅ Upgraded with YAML, inheritance R5 |
| PolicyEvaluator (4 modes) | ~100 | §7 | ✅ All 4 modes preserved exactly |
| 4 built-in policies | ~200 | §7 | ✅ All 4 preserved + 2 new presets |
| TextReporter | ~80 | §8 | ✅ Preserved |
| JsonReporter | ~40 | §8 | ✅ Preserved |
| SarifReporter | ~120 | §8, §14 | ✅ Upgraded to full SARIF 2.1.0 |
| GithubReporter | ~100 | §8 | ✅ Upgraded with feedback actions R6 |
| GitlabReporter | ~100 | §8 | ✅ Upgraded with feedback actions R6 |
| SnapshotStore | ~80 | §9 | ✅ Migrated to SQLite |
| GateRunStore | ~60 | §9 | ✅ Migrated to SQLite |
| AuditEngine (5-step) | ~300 | §10 | ✅ Preserved, Rust implementation |
| AuditStore | ~50 | §9 | ✅ Migrated to SQLite |
| Types (~1300 lines) | ~1300 | §4 | ✅ All types preserved + extended |
| License gating | ~30 | §31 | ✅ Preserved, expanded |
| MCP integration | ~50 | §30 | ✅ Preserved, expanded |
| CLI integration | ~40 | §29 | ✅ Preserved, expanded |

### V1 Algorithms — All Preserved

| Algorithm | V1 Formula | V2 Status | V2 Section |
|-----------|-----------|-----------|-----------|
| Gate scoring (error=10, warning=3, info=1) | `100 - (penalty/maxPenalty) × 100` | ✅ Preserved exactly + hotspot multiplier | §5.1 |
| Pattern compliance rate | `locations / (locations + outliers)` | ✅ Preserved + new-code-first | §5.2 |
| Regression severity classification | confidence drop × category | ✅ Preserved + statistical significance | §5.4 |
| Friction score | `f×25 + fn×25 + ep×30 + sd×20` | ✅ Preserved exactly | §5.5 |
| Policy aggregation (4 modes: any/all/weighted/threshold) | Mode-specific formulas | ✅ All 4 preserved exactly | §7 |
| Health score (5-factor weighted) | `conf×0.30 + appr×0.20 + comp×0.20 + xval×0.15 + dup×0.15` | ✅ Preserved exactly | §10 |
| Duplicate detection (Jaccard) | `|A∩B| / |A∪B|`, threshold 0.85 | ✅ Preserved, Rust implementation | §10 |
| Degradation tracking (7-day rolling) | ±2 point threshold | ✅ Preserved exactly | §10 |
| Policy specificity scoring | branch+10, path+5, author+3, include+2, exclude+1 | ✅ Preserved exactly | §7 |
| Recommendation engine (auto-approve criteria) | conf≥0.90, outlier≤0.50, locations≥3 | ✅ Preserved exactly | §10 |

### V1 Limitations — All 20 Addressed

| # | Limitation | Resolution | Section |
|---|-----------|-----------|---------|
| 1 | File-based persistence | ✅ SQLite in drift.db | §9 |
| 2 | No gate dependencies | ✅ DAG with topological execution | §17 |
| 3 | No incremental execution | ✅ 3-tier caching | §13 |
| 4 | No caching | ✅ Gate + file + branch caching | §13 |
| 5 | No partial failure recovery | ✅ Checkpoint/resume | §23 |
| 6 | No multi-repo support | ✅ Policy packs (Enterprise P2) | §7 |
| 7 | No policy inheritance | ✅ `extends` keyword | §7 |
| 8 | JSON-only policies | ✅ YAML + JSON | §7 |
| 9 | No policy versioning | ✅ `apiVersion` field | §7 |
| 10 | No gate timeout | ✅ Per-gate configurable (30s default) | §23 |
| 11 | No violation dedup | ✅ Cross-gate dedup by file+line+ruleId | §18 |
| 12 | No historical trends | ✅ SQLite queries + retention | §9 |
| 13 | No webhooks | ✅ Template-based webhook system | §25 |
| 14 | No dry-run mode | ✅ `--dry-run` flag | §20 |
| 15 | No gate priority | ✅ Priority field + dependency graph | §17 |
| 16 | Audit O(p²) slow | ✅ Rust implementation (10-50× faster) | §10 |
| 17 | No reporter plugins | ✅ Plugin architecture | §8 |
| 18 | Security gate heuristic | ✅ CWE/OWASP + taint integration | §22 |
| 19 | Custom rules limited | ✅ +3 new types (AST, call graph, metric) | §24 |
| 20 | No baseline management | ✅ CLI: `drift gate baseline set/reset/compare` | §29 |

### V1 Open Questions — All 12 Resolved

| # | Question | Resolution | Section |
|---|---------|-----------|---------|
| 1 | Gate dependencies? | ✅ DAG with topological execution | §17 |
| 2 | Incremental execution? | ✅ 3-tier caching | §13 |
| 3 | When to migrate to SQLite? | ✅ Day one in v2 | §9 |
| 4 | Policy YAML support? | ✅ YAML + JSON + inheritance | §7 |
| 5 | Custom reporter plugins? | ✅ Plugin architecture | §8 |
| 6 | Gate timeout defaults? | ✅ 30s default, per-gate configurable | §23 |
| 7 | Violation dedup across gates? | ✅ Cross-gate dedup | §18 |
| 8 | Webhook integration? | ✅ Template-based webhooks | §25 |
| 9 | Dry-run mode? | ✅ `--dry-run` flag | §20 |
| 10 | AST-based custom rules? | ✅ Tree-sitter query conditions | §24 |
| 11 | Call-graph-based custom rules? | ✅ Source/target path conditions | §24 |
| 12 | Audit health score weights? | ✅ Preserved, configurable in v2 | §10 |

### AUDIT Gaps — All 18 Addressed

| # | Gap | Resolution | Section |
|---|-----|-----------|---------|
| GAP-1 | Gate scoring weights not validated | ✅ Preserved + configurable per-gate | §5.1, §32 |
| GAP-2 | Audit health score weights not validated | ✅ Preserved + configurable | §10, §32 |
| GAP-3 | No webhook/notification research | ✅ Full webhook system | §25 |
| GAP-4 | No dry-run/preview mode | ✅ Full dry-run implementation | §20 |
| GAP-5 | No reporter plugin/extensibility | ✅ Plugin architecture | §8 |
| GAP-6 | No baseline management | ✅ CLI baseline commands | §29 |
| GAP-7 | Audit O(p²) not improved | ✅ Rust perf sufficient; LSH deferred | §10, §32 |
| GAP-8 | Security auth detection heuristic | ✅ CWE + taint + AST rules | §22, §24, §32 |
| GAP-9 | No violation prioritization | ✅ Multi-factor priority algorithm | §18 |
| GAP-10 | No author attribution | ✅ Git blame integration | §11 |
| GAP-11 | No analysis depth tradeoffs | ✅ Multi-stage with depth per stage | §16 |
| GAP-12 | No SARIF graph support | ✅ codeFlows covers primary use case | §14, §32 |
| GAP-13 | Statistical significance not formalized | ✅ Z-test implementation | §5.4 |
| GAP-14 | No cross-repo strategy | ✅ Policy packs (Enterprise P2) | §7, §32 |
| GAP-15 | No violation explanation format | ✅ Structured WHY/WHAT/HOW/IMPACT | §19 |
| GAP-16 | Cortex integration shallow | ✅ Feedback → tribal knowledge | §15, §32 |
| GAP-17 | Data lake replacement not detailed | ✅ SQLite views | §9, §32 |
| GAP-18 | Services layer handoff not documented | ✅ CLI orchestrates scan → gates | §32 |

### Recommendations — All 19 Integrated

| # | Recommendation | Integrated | Section(s) |
|---|---------------|-----------|-----------|
| R1 | New-code-first enforcement | ✅ | §11, §5.2, §5.3, §5.6 |
| R2 | Progressive enforcement | ✅ | §12, §5.2, §4.1 |
| R3 | Incremental caching | ✅ | §13, §6, §9 |
| R4 | Rich SARIF 2.1.0 | ✅ | §14, §8 |
| R5 | Policy-as-code | ✅ | §7 |
| R6 | Developer feedback loop | ✅ | §15, §8, §9 |
| R7 | Multi-stage enforcement | ✅ | §16 |
| R8 | JUnit XML + HTML reporters | ✅ | §8 |
| R9 | Gate dependency graph | ✅ | §17, §6 |
| R10 | SQLite persistence | ✅ | §9 |
| R11 | Hotspot-aware scoring | ✅ | §21, §5.1 |
| R12 | OWASP/CWE alignment | ✅ | §22, §5.6, §14 |
| R13 | Gate timeout + recovery | ✅ | §23 |
| R14 | Custom rule expansion | ✅ | §24, §4.8 |
| R15 | Structured explanations | ✅ | §19, §4.4, §5.2-§5.7 |
| R16 | Violation prioritization | ✅ | §18 |
| R17 | Dry-run mode | ✅ | §20 |
| R18 | Webhook notifications | ✅ | §25 |
| R19 | Reporter plugins | ✅ | §8 |

### Final Verification

- **V1 features preserved**: 27/27 core components (100%)
- **V1 algorithms preserved**: 10/10 (100%)
- **V1 limitations addressed**: 20/20 (100%)
- **V1 open questions resolved**: 12/12 (100%)
- **AUDIT gaps closed**: 18/18 (100%)
- **Recommendations integrated**: 19/19 (100%)
- **Feature loss**: Zero. Every v1 capability has a v2 equivalent or upgrade.
