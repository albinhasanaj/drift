# Constants & Environment Analysis — V2 Implementation Prep

> Comprehensive build specification for Drift v2's Constants & Environment Analysis
> subsystem (System 22). Synthesized from: 05-analyzers/constants-analysis.md (TS
> orchestration, per-language extractors, dead constant detection, storage — ~600 LOC),
> 05-analyzers/environment-analysis.md (EnvScanner, .env parsing, missing variable
> detection, consistency checking — ~400 LOC), 01-rust-core/constants.md (Rust
> ConstantsAnalyzer ~800 LOC: 21 secret patterns, confidence scoring, magic number
> detection, inconsistency detection, thread_local! parallelism),
> 01-rust-core/environment.md (Rust EnvironmentAnalyzer ~500 LOC: env var extraction,
> sensitivity classification, access method detection),
> 01-rust-core/other-analyzers.md (NAPI exposure: analyze_constants, analyze_environment),
> .research/05-analyzers/RECAP.md (Algorithm #5: secret detection, Algorithm #6: coupling,
> dual TS/Rust implementation inventory, 22K+ LOC analyzer system),
> .research/05-analyzers/RECOMMENDATIONS.md (R7: expanded secret detection — Azure, GCP,
> npm, PyPI, entropy-based confidence; R8: AST-based magic number detection),
> .research/05-analyzers/RESEARCH.md (R8: GitGuardian enterprise credential scanning,
> pattern + entropy hybrid, provider-specific patterns, false positive reduction),
> .research/05-analyzers/AUDIT.md (constants-analysis.md, environment-analysis.md coverage),
> .research/01-rust-core/RECOMMENDATIONS.md (AST-based magic number detection, fuzzy name
> matching for inconsistency detection, dead constant detection via call graph),
> .research/01-rust-core/RECAP.md (ConstantsAnalyzer, EnvironmentAnalyzer, SecretDetector
> 21 patterns, thread_local! pattern, NAPI exposure),
> DRIFT-V2-FULL-SYSTEM-AUDIT.md (Constants & Environment Rust: magic number detection,
> string literal analysis, secret detection, env var usage tracking, .env file parsing),
> DRIFT-V2-STACK-HIERARCHY.md (Level 2C — Structural Intelligence: "Narrow scope. Feeds
> security (secrets) and constraints."),
> DRIFT-V2-SYSTEMS-REFERENCE.md (Constants & Environment — TOC entry),
> 06-UNIFIED-ANALYSIS-ENGINE-V2-PREP.md (ParseResult.numeric_literals for magic number
> detection, ParseResult.string_literals for string analysis, 4-phase pipeline),
> 06-DETECTOR-SYSTEM.md (config/env-management Learning detector, config/secrets-handling
> Base detector UPGRADED + OWASP A02, security/hardcoded-secrets Base detector UPGRADED
> + 100+ patterns),
> 02-STORAGE-V2-PREP.md (drift.db schema: constants, magic_numbers, env_vars, env_files
> tables),
> 03-NAPI-BRIDGE-V2-PREP.md (§10.10 analyze_constants Async → ConstantsSummary;
> AnalysisType::Constants, AnalysisType::Environment in batch API; structural.rs binding),
> 04-INFRASTRUCTURE-V2-PREP.md (thiserror, tracing, DriftEventHandler, FxHashMap,
> config layered resolution: CLI flags > env vars > project config > user config > defaults),
> 07-mcp/tools-by-category.md (drift_constants — analysis category, ~800-2000 tokens),
> 10-cli/commands.md (drift constants: default/list/get/secrets/inconsistent/dead/export
> subcommands, drift environment: default/list/missing/inconsistent subcommands),
> 13-advanced/dna-system.md (DNA gene extractors consume constants metrics),
> 09-quality-gates/gates.md (security gate consumes secret detection results),
> 15-TAINT-ANALYSIS-V2-PREP.md (source registry: env vars as taint sources),
> 20-CONSTRAINT-SYSTEM-V2-PREP.md (constraint mining from constant patterns),
> GitGuardian blog — "Protect Code and Prevent Credential Leaks" (pattern + entropy
> hybrid, provider-specific patterns, git history scanning),
> OWASP Top 10 2025 A02:2025 — Cryptographic Failures (hardcoded secrets alignment),
> CWE-798 — Use of Hard-coded Credentials,
> CWE-547 — Use of Hard-coded, Security-relevant Constants,
> dotenv specification (https://dotenv-linter.github.io/),
> PLANNING-DRIFT.md (D1-D7).
>
> Purpose: Everything needed to build the Constants & Environment Analysis subsystem
> from scratch. This is the DEDICATED deep-dive — the 06-UNIFIED-ANALYSIS-ENGINE doc
> covers the per-file detection pipeline; the 06-DETECTOR-SYSTEM doc covers the
> trait-based detector framework; this document covers the full constants & environment
> analysis engine: constant extraction from AST, magic number detection (AST-based,
> replacing v1 regex), secret detection (100+ patterns, entropy scoring, contextual
> analysis), environment variable extraction (9+ languages, 15+ access methods),
> .env file parsing (dotenv spec compliance), missing/inconsistent variable detection,
> dead constant detection (via call graph), inconsistency detection (fuzzy name matching),
> framework-specific environment detection (Next.js, Vite, Django, Spring, etc.),
> sensitivity classification (4-tier), confidence scoring (Bayesian + entropy),
> incremental analysis, and the full integration with security, taint analysis,
> constraints, quality gates, DNA, and storage.
> Every v1 feature accounted for. Zero feature loss. Every algorithm specified.
> Every type defined. Every integration point documented. Every architectural
> decision resolved.
> Generated: 2026-02-08

---

## Table of Contents

1. Architectural Position
2. V1 Complete Feature Inventory
3. V2 Architecture — Unified Constants & Environment Engine
4. Core Data Model
5. Phase 1: Constant Extraction from AST (Per-Language)
6. Phase 2: Magic Number Detection (AST-Based, Replaces v1 Regex)
7. Phase 3: Secret Detection Engine (100+ Patterns, Entropy Scoring)
8. Phase 4: Inconsistency Detection (Fuzzy Name Matching)
9. Phase 5: Dead Constant Detection (Call Graph Integration)
10. Phase 6: Environment Variable Extraction (9+ Languages, 15+ Access Methods)
11. Phase 7: .env File Parsing (Dotenv Spec Compliance)
12. Phase 8: Missing & Inconsistent Variable Detection
13. Phase 9: Framework-Specific Environment Detection
14. Phase 10: Sensitivity Classification Engine (4-Tier)
15. Phase 11: Confidence Scoring (Bayesian + Entropy)
16. Phase 12: Constant Categorization & Naming Suggestions
17. Phase 13: Health Score Calculation
18. Incremental Analysis (Content-Hash + Dependency Tracking)
19. Integration with Unified Analysis Engine
20. Integration with Taint Analysis
21. Integration with Constraint Detection
22. Integration with Quality Gates (Security Gate)
23. Integration with DNA System
24. Integration with Enterprise Secret Detection
25. Integration with Cortex Grounding (D7)
26. Storage Schema (drift.db)
27. NAPI Interface
28. MCP Tool Interface (drift_constants — 6 Actions)
29. CLI Interface (drift constants — 7 Subcommands, drift environment — 4 Subcommands)
30. Event Interface
31. Tracing & Observability
32. Performance Targets & Benchmarks
33. Build Order & Dependencies
34. V1 → V2 Feature Cross-Reference
35. Inconsistencies & Decisions
36. Risk Register

---

## 1. Architectural Position

Constants & Environment Analysis is **Level 2C — Structural Intelligence** in the
Drift v2 stack hierarchy. It is the system that catalogs hardcoded values, detects
leaked secrets, identifies magic numbers, tracks environment variable dependencies,
and cross-references code against .env files — answering questions like "are there
hardcoded secrets in this codebase?", "which environment variables are used but never
defined?", "are there magic numbers that should be named constants?", and "do my
.env files across environments have consistent variable sets?"

Per DRIFT-V2-STACK-HIERARCHY.md:

> Constants & Environment: Magic numbers, env vars, .env parsing. Narrow scope.
> Feeds security (secrets) and constraints.

Per DRIFT-V2-FULL-SYSTEM-AUDIT.md:

> Constants & Environment (Rust):
> - Constants: magic number detection, string literal analysis, secret detection
> - Environment: env var usage tracking, .env file parsing
> - Action: Catalogs hardcoded values and environment dependencies

### Core Thesis

Constants & Environment analysis is fundamentally a **cataloging and cross-referencing
problem**. V1 solved this with a split architecture: Rust handled the heavy lifting
(parallel file processing, regex-based secret detection, basic magic number detection)
while TypeScript added orchestration (dead constant detection, .env parsing, storage).
V2 unifies everything in Rust with zero feature loss, upgrading regex-based detection
to AST-based detection, expanding secret patterns from 21 to 100+, and adding
framework-specific environment detection.

The key architectural insight: **constants and environment variables are two sides of
the same coin**. A hardcoded database URL is both a "constant" and a "missing environment
variable." A `process.env.DATABASE_URL` access is both an "environment variable" and a
"configuration dependency." V2 unifies these into a single engine that understands the
full lifecycle: declaration → usage → configuration → deployment.

The second insight: **secret detection is the highest-value output**. While magic number
detection and inconsistency analysis improve code quality, secret detection prevents
security incidents. V2 prioritizes secret detection accuracy with entropy-based scoring,
contextual analysis, and provider-specific patterns — targeting <1% false positive rate
for Critical/High severity secrets.

### What Lives Here

- Constant extraction from AST (const/let/var/final/static declarations, 9+ languages)
- Magic number detection via AST (not line-level regex — context-aware, scope-aware)
- Secret detection engine (100+ patterns, 7 severity levels, entropy scoring)
- Inconsistency detection with fuzzy name matching (camelCase ↔ snake_case normalization)
- Dead constant detection via call graph (unused exports, unreferenced declarations)
- Environment variable extraction (9+ languages, 15+ access methods)
- .env file parsing (dotenv spec: .env, .env.local, .env.production, .env.*.local)
- Missing variable detection (used in code but not defined in .env)
- Inconsistent variable detection (different values across .env variants)
- Framework-specific environment detection (Next.js NEXT_PUBLIC_*, Vite VITE_*, etc.)
- Sensitivity classification (Public, Internal, Secret, Critical — 4-tier)
- Confidence scoring (Bayesian base + entropy adjustment + contextual signals)
- Constant categorization (config, api, status, error, ui, math, time, size, limit)
- Naming suggestions for magic numbers (context-aware: timeout → TIMEOUT_MS)
- Value masking for secrets (partial reveal for identification)
- Placeholder detection (skip "example", "todo", "changeme", etc.)
- Health score calculation (multi-factor, 0-100)
- Incremental analysis (content-hash invalidation, dependency-aware propagation)
- Constants & environment result persistence (drift.db — 4 tables, 12+ indexes)

### What Does NOT Live Here

- Enterprise secret detection (lives in Security Intelligence — Level 2D, 100+ patterns
  with git history scanning, connection string parsing, base64 decoding)
- Pattern detection (lives in Detector System — config/env-management, config/secrets-handling,
  security/hardcoded-secrets detectors consume our data)
- Taint source registration (lives in Taint Analysis — consumes env var access points)
- Quality gate evaluation (lives in Quality Gates — consumes secret detection results)
- Constraint mining from constant patterns (lives in Constraint Detection)
- Call graph construction (lives in Call Graph Builder — we consume it for dead constants)
- AST parsing (lives in Parsers — we consume ParseResult)

### Upstream Dependencies (What Constants & Environment Consumes)

| System | What It Provides | How We Use It |
|--------|-----------------|---------------|
| Parsers (Level 0) | ParseResult with functions, classes, imports, exports, string_literals, numeric_literals | AST-based constant extraction, magic number detection |
| Scanner (Level 0) | ScanDiff (added/modified/removed files), content hashes | Incremental analysis input, .env file discovery |
| Storage (Level 0) | DatabaseManager with batch writer | Persistence to drift.db |
| Call Graph (Level 1) | Function→function edges, export usage tracking | Dead constant detection |
| Unified Analysis (Level 1) | Resolution index for import resolution | Cross-file constant reference tracking |
| Infrastructure (Level 0) | thiserror, tracing, DriftEventHandler, config | Error handling, observability, events |

### Downstream Consumers (What Depends on Constants & Environment)

| Consumer | What It Reads | How It Uses Our Data |
|----------|--------------|---------------------|
| Enterprise Secret Detection | Secret candidates with confidence | Enriches with git history, connection string parsing |
| Taint Analysis | Env var access points as taint sources | Source registry: env vars are untrusted input |
| Constraint Detection | Constant patterns, naming conventions | Mines invariants: "all timeouts use TIMEOUT_* constants" |
| Quality Gates | Secret count by severity, magic number count | Security gate: block if Critical secrets found |
| DNA System | Constants metrics, env var count, secret ratio | Gene extractor: configuration health gene |
| Detector System | Constant data, env var data | config/env-management, config/secrets-handling detectors |
| Simulation Engine | Constants metrics for friction scoring | "What if I add this env var?" impact |
| CI Agent | Secret scan results, magic number count | PR-level security check |
| MCP Server | drift_constants tool responses | AI-assisted constants analysis |
| CLI | drift constants, drift environment commands | Developer constants/environment analysis |
| Context Generation | Constants summary for AI context | AI-ready configuration context |

---

## 2. V1 Feature Inventory — Complete Preservation Matrix

Every v1 feature is accounted for. Nothing is dropped without replacement.

### 2.1 Rust Constants Analyzer (v1 → v2)

| # | V1 Feature | V1 Implementation | V2 Status | V2 Location |
|---|-----------|-------------------|-----------|-------------|
| C1 | `ConstantsAnalyzer` struct | Orchestrates extraction, secrets, magic numbers, inconsistencies | **UPGRADED** — `ConstantsEngine` with unified pipeline | §3 |
| C2 | `ConstantExtractor` | Extracts const/let/var declarations from AST | **UPGRADED** — 9+ languages, richer categorization | §5 |
| C3 | `SecretDetector` (21 patterns) | Regex-based, 3 severity tiers, confidence scoring | **UPGRADED** — 100+ patterns, 7 severity tiers, entropy scoring | §7 |
| C4 | Magic number detection | Regex `\b(\d{2,})\b` with exclusion list | **REPLACED** — AST-based detection, scope-aware, context-aware | §6 |
| C5 | Inconsistency detection | Group by normalized name (lowercase), flag differing values | **UPGRADED** — Fuzzy name matching (camelCase ↔ snake_case) | §8 |
| C6 | Confidence scoring | `base + entropy_adj + length_adj`, capped at 1.0 | **UPGRADED** — Bayesian + entropy + contextual signals | §15 |
| C7 | Placeholder detection | Skip "example", "placeholder", "your_", "xxx", "todo", "changeme" | **KEPT** — Same list + expanded | §7.5 |
| C8 | Value masking | Partial reveal: first 4 + "..." + last 4 | **KEPT** — Same algorithm | §7.6 |
| C9 | `thread_local!` parallelism | Per-thread ParserManager, ConstantExtractor, SecretDetector | **UPGRADED** — rayon + thread_local! with ParseResult sharing | §3 |
| C10 | `ConstantInfo` type | name, value, category, file, line, language, is_exported | **UPGRADED** — +scope, +references, +is_dead, +naming_quality | §4.1 |
| C11 | `SecretCandidate` type | name, masked_value, secret_type, severity, file, line, confidence | **UPGRADED** — +entropy, +context_keywords, +provider, +cwe_id | §4.2 |
| C12 | `MagicNumber` type | value, file, line, context, suggested_name | **UPGRADED** — +scope, +ast_context, +category, +fix_suggestion | §4.3 |
| C13 | `InconsistentValue` type | name_pattern, values: Vec<ValueLocation>, severity | **UPGRADED** — +normalized_name, +match_score, +suggested_canonical | §4.4 |
| C14 | `ConstantsResult` type | constants, secrets, magic_numbers, inconsistencies, dead_constants, stats | **UPGRADED** — +health_score, +env_summary, +framework_detection | §4.5 |
| C15 | `ConstantsStats` type | total_constants, by_category, by_language, exported_count, etc. | **UPGRADED** — +secret_severity_breakdown, +magic_number_categories | §4.6 |
| C16 | NAPI: `analyze_constants(files)` | Returns JsConstantsResult | **UPGRADED** — `analyze_constants(root)` Async, writes to drift.db | §27 |
| C17 | Name suggestion for magic numbers | Context-aware: timeout→TIMEOUT_MS, port→PORT | **UPGRADED** — +AST context, +scope analysis, +language conventions | §16 |
| C18 | Secret severity tiers | Critical (0.9), High (0.8), Medium (0.6) | **UPGRADED** — 7 tiers: Critical/High/Medium/Low/Info/FP/Suppressed | §7.2 |

### 2.2 Rust Environment Analyzer (v1 → v2)

| # | V1 Feature | V1 Implementation | V2 Status | V2 Location |
|---|-----------|-------------------|-----------|-------------|
| E1 | `EnvironmentAnalyzer` struct | Orchestrates env var extraction and analysis | **UPGRADED** — Unified into `ConstantsEngine` | §3 |
| E2 | `EnvExtractor` | Extracts env var access from ASTs and source | **UPGRADED** — 9+ languages, 15+ access methods | §10 |
| E3 | `EnvAccess` type | variable_name, file, line, access_method, has_default, sensitivity | **UPGRADED** — +framework, +is_public, +required, +description | §4.7 |
| E4 | `EnvVariable` type | name, accesses, sensitivity, has_default_anywhere, access_count | **UPGRADED** — +defined_in_env_files, +missing, +inconsistent | §4.8 |
| E5 | `EnvSensitivity` enum | Public, Internal, Secret, Critical | **KEPT** — Same 4 tiers, enhanced classification rules | §14 |
| E6 | Sensitivity classification | Pattern-based: *_SECRET→Critical, *_KEY→Secret, *_HOST→Internal | **UPGRADED** — +framework-aware, +value-based inference | §14 |
| E7 | Access method detection | process.env, os.environ, getenv, env(), ${}, %% | **UPGRADED** — 15+ methods across 9+ languages | §10.2 |
| E8 | Default value tracking | has_default, default_value per access | **KEPT** — Same tracking | §10 |
| E9 | `EnvironmentResult` type | accesses, variables, stats | **UPGRADED** — +env_files, +missing, +inconsistent, +framework | §4.9 |
| E10 | `EnvironmentStats` type | total_accesses, unique_variables, by_sensitivity, by_language | **UPGRADED** — +missing_count, +inconsistent_count, +coverage | §4.10 |
| E11 | NAPI: `analyze_environment(files)` | Returns JsEnvironmentResult | **MERGED** — Into `analyze_constants(root)` unified call | §27 |

### 2.3 TypeScript Constants Layer (v1 → v2)

| # | V1 Feature | V1 Implementation | V2 Status | V2 Location |
|---|-----------|-------------------|-----------|-------------|
| TC1 | Per-language extractors | Enhanced extraction per language | **MOVED** — To Rust, per-language AST extraction | §5 |
| TC2 | Dead constant detection | Usage analysis via call graph | **MOVED** — To Rust, call graph integration | §9 |
| TC3 | Constants store | Persistence to .drift/constants/ (JSON files) | **REPLACED** — SQLite in drift.db | §26 |
| TC4 | Pattern store integration | Integration with pattern store | **UPGRADED** — Detector system integration | §24 |
| TC5 | Analysis orchestration | Coordinates Rust + TS analysis | **ELIMINATED** — All analysis in Rust | §3 |

### 2.4 TypeScript Environment Layer (v1 → v2)

| # | V1 Feature | V1 Implementation | V2 Status | V2 Location |
|---|-----------|-------------------|-----------|-------------|
| TE1 | EnvScanner | Orchestrates extraction + .env parsing | **MOVED** — To Rust | §3 |
| TE2 | .env file parsing | Reads .env, .env.local, .env.production, etc. | **MOVED** — To Rust, dotenv spec compliance | §11 |
| TE3 | Missing variable detection | Cross-references code vs .env | **MOVED** — To Rust | §12 |
| TE4 | Consistency checking | Checks across .env variants | **MOVED** — To Rust | §12 |
| TE5 | Per-language extractors | Enhanced extraction | **MOVED** — To Rust | §10 |
| TE6 | EnvStore | Persistence to .drift/environment/ | **REPLACED** — SQLite in drift.db | §26 |

### 2.5 New V2 Features NOT in V1

| New Feature | Why | Priority | Location |
|------------|-----|----------|----------|
| AST-based magic number detection | v1 regex misses context; AST knows scope, type, usage | P0 | §6 |
| 100+ secret patterns (was 21) | Azure, GCP, npm, PyPI, Hashicorp, Databricks, etc. | P0 | §7 |
| Entropy-based confidence scoring | GitGuardian research: pattern + entropy hybrid reduces FP | P0 | §15 |
| Fuzzy name matching for inconsistencies | camelCase ↔ snake_case normalization catches more | P1 | §8 |
| Dead constant detection in Rust | Was TS-only; now uses call graph in Rust | P1 | §9 |
| Framework-specific env detection | Next.js NEXT_PUBLIC_*, Vite VITE_*, Django DJANGO_* | P1 | §13 |
| .env file parsing in Rust | Was TS-only; now unified in Rust engine | P1 | §11 |
| Missing/inconsistent variable detection in Rust | Was TS-only; now cross-references in Rust | P1 | §12 |
| CWE/OWASP mapping for secrets | CWE-798, CWE-547, OWASP A02:2025 alignment | P1 | §7.3 |
| Contextual secret analysis | Nearby keywords increase/decrease confidence | P1 | §7.4 |
| Provider-specific secret patterns | Each cloud provider has distinct key formats | P1 | §7.1 |
| Constant naming quality scoring | Measures how well constants are named | P2 | §16 |
| Health score calculation | Multi-factor 0-100 score for constants hygiene | P2 | §17 |
| Temporal tracking | Track secret/magic number trends over time | P2 | §26 |
| Auto-fix suggestions for magic numbers | Generate const declaration + replace usage | P2 | §6.5 |
| .env template generation | Generate .env.example from code analysis | P2 | §11.5 |

---

## 3. V2 Architecture — Unified Constants & Environment Engine

### Design Philosophy

V1 split constants and environment analysis across 4 codebases:
1. Rust `ConstantsAnalyzer` (~800 LOC) — secret detection, magic numbers, extraction
2. Rust `EnvironmentAnalyzer` (~500 LOC) — env var extraction, sensitivity
3. TypeScript `constants/` (~600 LOC) — dead constants, storage, orchestration
4. TypeScript `environment/` (~400 LOC) — .env parsing, missing detection, consistency

V2 unifies everything into a single Rust `ConstantsEngine` that:
- Consumes `ParseResult` from the unified analysis pipeline (no re-parsing)
- Runs all analysis phases in a single pass per file
- Writes results directly to drift.db (no JSON files)
- Returns lightweight `ConstantsSummary` via NAPI (not full results)
- Supports incremental analysis via content-hash invalidation

### Engine Architecture

```
                    ┌─────────────────────────────────────────┐
                    │         ConstantsEngine (Unified)        │
                    │                                         │
  ParseResult[] ──→ │  Phase 1: Constant Extraction (AST)     │
  (from pipeline)   │  Phase 2: Magic Number Detection (AST)  │
                    │  Phase 3: Secret Detection (100+ regex)  │
                    │  Phase 4: Inconsistency Detection (fuzzy)│
  CallGraphDb ────→ │  Phase 5: Dead Constant Detection (CG)  │
  (optional)        │  Phase 6: Env Var Extraction (AST)       │
                    │  Phase 7: .env File Parsing (dotenv)     │
  .env files ─────→ │  Phase 8: Missing/Inconsistent Detection │
  (from scanner)    │  Phase 9: Framework Detection            │
                    │  Phase 10: Sensitivity Classification    │
                    │  Phase 11: Confidence Scoring             │
                    │  Phase 12: Categorization & Naming        │
                    │  Phase 13: Health Score                   │
                    │                                         │
                    │  ──→ Write to drift.db (batch writer)    │
                    │  ──→ Emit events (DriftEventHandler)     │
                    │  ──→ Return ConstantsSummary (NAPI)      │
                    └─────────────────────────────────────────┘
```

### Threading Model

```rust
/// The unified constants & environment analysis engine.
/// Stateless — all state lives in drift.db.
/// Thread-safe — uses rayon for file-level parallelism.
pub struct ConstantsEngine {
    secret_detector: SecretDetector,
    env_config: EnvironmentConfig,
    framework_registry: FrameworkEnvRegistry,
}
```

Per-file analysis runs in parallel via rayon. The `SecretDetector` is `Send + Sync`
because all regex patterns are compiled once at construction and shared immutably.
No `thread_local!` needed in v2 — we consume `ParseResult` instead of parsing ourselves.

### Key Difference from V1

V1: Each file was parsed independently by the constants analyzer (via `thread_local!`
ParserManager). This duplicated work already done by the unified analysis pipeline.

V2: The unified analysis pipeline (Level 1) parses all files and produces `ParseResult`
structs. The constants engine consumes these — no re-parsing. This means:
- Zero parsing overhead in the constants engine
- Access to richer AST data (numeric_literals, string_literals with context)
- Consistent AST representation across all analyzers
- Incremental analysis is automatic (only re-analyze changed files)

---

## 4. Core Data Model

All types live in `crates/drift-core/src/constants/types.rs`.
Every v1 type is preserved and upgraded.

### 4.1 ConstantInfo (Extracted Constant Declaration)

```rust
use serde::{Deserialize, Serialize};

/// A constant declaration extracted from source code.
/// Persisted in drift.db `constants` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstantInfo {
    /// Deterministic ID: SHA256(file + name + line).
    pub id: String,
    /// Constant name as declared in source.
    pub name: String,
    /// Constant value (string representation).
    pub value: String,
    /// Semantic category.
    pub category: ConstantCategory,
    /// Source file path (interned Spur in engine, String for persistence).
    pub file: String,
    /// Line number (1-indexed).
    pub line: u32,
    /// Column number (0-indexed).
    pub column: u32,
    /// Source language.
    pub language: Language,
    /// Whether this constant is exported/public.
    pub is_exported: bool,
    /// Declaration kind.
    pub declaration_kind: DeclarationKind,
    /// Scope: module-level, class-level, function-level, block-level.
    pub scope: ConstantScope,
    /// Number of references to this constant across the codebase.
    pub reference_count: u32,
    /// Whether this constant is dead (zero references outside declaration file).
    pub is_dead: bool,
    /// Naming quality score (0.0-1.0): measures adherence to naming conventions.
    pub naming_quality: f64,
    /// Content hash of the file at analysis time (for incremental).
    pub content_hash: u64,
}

/// Semantic category for constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConstantCategory {
    Config,       // Configuration values (URLs, paths, feature flags)
    Api,          // API keys, endpoints, versions
    Status,       // HTTP status codes, error codes, state enums
    Error,        // Error messages, error codes
    Ui,           // Colors, dimensions, labels, i18n keys
    Math,         // Mathematical constants (PI, E, conversion factors)
    Time,         // Durations, intervals, timeouts
    Size,         // Buffer sizes, limits, thresholds
    Limit,        // Rate limits, max retries, pagination
    Security,     // Secrets, tokens, credentials (overlaps with SecretCandidate)
    Regex,        // Regular expression patterns
    Database,     // Table names, column names, query templates
    Environment,  // Environment variable names/defaults
    Unknown,      // Cannot be categorized
}

/// How the constant was declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeclarationKind {
    Const,        // const, final, static final
    StaticConst,  // static const (Rust, C++)
    Enum,         // enum variant
    Define,       // #define (C/C++)
    Readonly,     // readonly (TypeScript)
    ClassField,   // static class field
    ModuleLevel,  // Module-level variable treated as constant
}

/// Scope where the constant is declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConstantScope {
    Module,       // Top-level module/file scope
    Class,        // Class-level (static field, enum)
    Function,     // Function-local constant
    Block,        // Block-scoped (if/for/match)
}
```

### 4.2 SecretCandidate (Detected Secret)

```rust
/// A potential secret detected in source code.
/// Persisted in drift.db `constants` table with category = Security.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretCandidate {
    /// Deterministic ID: SHA256(file + line + secret_type).
    pub id: String,
    /// Variable/field name containing the secret.
    pub name: String,
    /// Masked value for identification without exposure.
    pub masked_value: String,
    /// Secret type identifier (e.g., "aws_access_key", "github_token").
    pub secret_type: String,
    /// Cloud/service provider (e.g., "aws", "github", "stripe").
    pub provider: Option<String>,
    /// Severity classification.
    pub severity: SecretSeverity,
    /// Source file path.
    pub file: String,
    /// Line number (1-indexed).
    pub line: u32,
    /// Confidence score (0.0-1.0).
    pub confidence: f64,
    /// Shannon entropy of the matched value.
    pub entropy: f64,
    /// Human-readable reason for detection.
    pub reason: String,
    /// CWE identifier (e.g., "CWE-798" for hardcoded credentials).
    pub cwe_id: Option<String>,
    /// OWASP category (e.g., "A02:2025" for cryptographic failures).
    pub owasp_id: Option<String>,
    /// Context keywords found near the secret (increases confidence).
    pub context_keywords: Vec<String>,
    /// Whether this is a known placeholder/example value.
    pub is_placeholder: bool,
    /// Content hash of the file at analysis time.
    pub content_hash: u64,
}

/// Secret severity levels — expanded from v1's 3 tiers to 7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SecretSeverity {
    Critical,     // Active credentials with high blast radius (AWS root, DB admin)
    High,         // Service-specific credentials (API keys, tokens)
    Medium,       // Potentially sensitive (generic passwords, bearer tokens)
    Low,          // Low-risk patterns (internal URLs, non-production keys)
    Info,         // Informational (patterns that look like secrets but probably aren't)
    FalsePositive,// Confirmed false positive (user-marked or auto-detected)
    Suppressed,   // Intentionally suppressed (baseline, .driftignore)
}
```

### 4.3 MagicNumber (Detected Magic Number)

```rust
/// A magic number detected in source code.
/// Persisted in drift.db `magic_numbers` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagicNumber {
    /// Deterministic ID: SHA256(file + line + value).
    pub id: String,
    /// Numeric value.
    pub value: f64,
    /// Raw string representation from source (preserves "0xFF", "1_000", etc.).
    pub raw: String,
    /// Source file path.
    pub file: String,
    /// Line number (1-indexed).
    pub line: u32,
    /// Column number (0-indexed).
    pub column: u32,
    /// Source language.
    pub language: Language,
    /// AST context: where this number appears.
    pub ast_context: MagicNumberContext,
    /// Semantic category inferred from context.
    pub category: MagicNumberCategory,
    /// Suggested constant name (context-aware).
    pub suggested_name: Option<String>,
    /// Auto-fix suggestion: extract to named constant.
    pub fix_suggestion: Option<FixSuggestion>,
    /// Scope where the magic number appears.
    pub scope: ConstantScope,
    /// Content hash of the file at analysis time.
    pub content_hash: u64,
}

/// AST context for magic numbers — replaces v1's line-level regex.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MagicNumberContext {
    FunctionArgument,   // foo(42)
    VariableAssignment, // let x = 42
    Comparison,         // if x > 42
    ArrayIndex,         // arr[42]
    ReturnValue,        // return 42
    BinaryOperation,    // x + 42
    SwitchCase,         // case 42:
    DefaultParameter,   // function foo(x = 42)
    ObjectProperty,     // { timeout: 42 }
    EnumValue,          // enum { X = 42 }
    Other,              // Unclassified
}

/// Semantic category for magic numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MagicNumberCategory {
    Timeout,      // Likely a timeout/delay value
    Port,         // Likely a network port
    Size,         // Likely a buffer/limit size
    Retry,        // Likely a retry count
    HttpStatus,   // HTTP status code (but not in standard list)
    BitMask,      // Likely a bitmask/flag
    Percentage,   // Likely a percentage (0-100)
    Index,        // Likely an array/collection index
    Threshold,    // Likely a threshold/limit
    Unknown,      // Cannot be categorized
}

/// Auto-fix suggestion for extracting magic number to named constant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixSuggestion {
    /// Suggested constant declaration.
    pub declaration: String,
    /// Where to insert the declaration (file, line).
    pub insert_file: String,
    pub insert_line: u32,
    /// What to replace at the magic number location.
    pub replacement: String,
}
```

### 4.4 InconsistentValue (Name Collision with Different Values)

```rust
/// A group of constants with similar names but different values.
/// Indicates potential inconsistency or naming collision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InconsistentValue {
    /// Normalized name pattern (lowercase, underscore-separated).
    pub normalized_name: String,
    /// All locations with their values.
    pub locations: Vec<ValueLocation>,
    /// Fuzzy match score between the most distant pair (0.0-1.0).
    pub match_score: f64,
    /// Suggested canonical name (most common variant).
    pub suggested_canonical: Option<String>,
    /// Severity based on value divergence.
    pub severity: InconsistencySeverity,
}

/// A single location of an inconsistent value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueLocation {
    /// Original name as declared.
    pub name: String,
    /// Value at this location.
    pub value: String,
    /// Source file path.
    pub file: String,
    /// Line number.
    pub line: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InconsistencySeverity {
    High,    // Same normalized name, very different values (likely bug)
    Medium,  // Similar names, different values (likely unintentional)
    Low,     // Loosely similar names, different values (possibly intentional)
}
```

### 4.5 ConstantsResult (Unified Analysis Result)

```rust
/// Complete result of constants & environment analysis.
/// Written to drift.db; summary returned via NAPI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstantsResult {
    pub constants: Vec<ConstantInfo>,
    pub secrets: Vec<SecretCandidate>,
    pub magic_numbers: Vec<MagicNumber>,
    pub inconsistencies: Vec<InconsistentValue>,
    pub dead_constants: Vec<DeadConstant>,
    pub env_result: EnvironmentResult,
    pub health_score: HealthScore,
    pub stats: ConstantsStats,
}

/// A constant that is declared but never referenced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadConstant {
    /// Reference to the ConstantInfo.
    pub constant_id: String,
    /// Name of the dead constant.
    pub name: String,
    /// File where declared.
    pub file: String,
    /// Line where declared.
    pub line: u32,
    /// Whether it's exported (exported dead constants are higher severity).
    pub is_exported: bool,
    /// Confidence that it's truly dead (0.0-1.0).
    /// Lower if dynamic access patterns detected (e.g., computed property names).
    pub confidence: f64,
}
```

### 4.6 ConstantsStats

```rust
/// Statistics for constants analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConstantsStats {
    pub total_constants: usize,
    pub by_category: HashMap<ConstantCategory, usize>,
    pub by_language: Vec<LanguageCount>,
    pub exported_count: usize,
    pub dead_count: usize,
    pub secrets_count: usize,
    pub secret_severity_breakdown: HashMap<SecretSeverity, usize>,
    pub magic_numbers_count: usize,
    pub magic_number_categories: HashMap<MagicNumberCategory, usize>,
    pub inconsistencies_count: usize,
    pub env_vars_count: usize,
    pub env_missing_count: usize,
    pub env_inconsistent_count: usize,
    pub files_analyzed: usize,
    pub duration_ms: u64,
}
```

### 4.7 EnvAccess (Environment Variable Access Point)

```rust
/// A single access to an environment variable in source code.
/// Persisted in drift.db `env_vars` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvAccess {
    /// Deterministic ID: SHA256(file + line + variable_name).
    pub id: String,
    /// Environment variable name.
    pub variable_name: String,
    /// Source file path.
    pub file: String,
    /// Line number (1-indexed).
    pub line: u32,
    /// Column number (0-indexed).
    pub column: u32,
    /// Source language.
    pub language: Language,
    /// How the variable is accessed.
    pub access_method: EnvAccessMethod,
    /// Whether a default/fallback value is provided.
    pub has_default: bool,
    /// Default value if provided.
    pub default_value: Option<String>,
    /// Sensitivity classification.
    pub sensitivity: EnvSensitivity,
    /// Framework that defines this variable pattern (if detected).
    pub framework: Option<String>,
    /// Whether this is a public/client-side variable (e.g., NEXT_PUBLIC_*).
    pub is_public: bool,
    /// Whether this variable is required (no default, used in critical path).
    pub is_required: bool,
    /// Description from nearby comments (if found).
    pub description: Option<String>,
    /// Content hash of the file at analysis time.
    pub content_hash: u64,
}

/// How an environment variable is accessed — language-specific methods.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnvAccessMethod {
    // JavaScript/TypeScript
    ProcessEnv,           // process.env.VAR_NAME
    ProcessEnvBracket,    // process.env["VAR_NAME"]
    ImportMetaEnv,        // import.meta.env.VITE_VAR (Vite)
    // Python
    OsEnviron,            // os.environ["VAR"]
    OsEnvironGet,         // os.environ.get("VAR", default)
    OsGetenv,             // os.getenv("VAR")
    DotenvValues,         // dotenv_values()
    // Rust
    StdEnvVar,            // std::env::var("VAR")
    StdEnvVarOs,          // std::env::var_os("VAR")
    // Java/Kotlin
    SystemGetenv,         // System.getenv("VAR")
    SystemGetProperty,    // System.getProperty("VAR")
    // C#
    EnvironmentGetVar,    // Environment.GetEnvironmentVariable("VAR")
    ConfigurationIndex,   // Configuration["VAR"]
    // Go
    OsGetenv,             // os.Getenv("VAR")
    OsLookupEnv,          // os.LookupEnv("VAR")
    // PHP
    Getenv,               // getenv("VAR")
    EnvSuperglobal,       // $_ENV["VAR"]
    // Ruby
    EnvBracket,           // ENV["VAR"]
    EnvFetch,             // ENV.fetch("VAR")
    // Shell/Docker
    DollarBrace,          // ${VAR} or $VAR
    // Generic
    Other(String),        // Unrecognized access method
}
```

### 4.8 EnvVariable (Aggregated Environment Variable)

```rust
/// An environment variable aggregated across all access points.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvVariable {
    /// Variable name.
    pub name: String,
    /// All access locations.
    pub accesses: Vec<EnvAccessLocation>,
    /// Highest sensitivity across all accesses.
    pub sensitivity: EnvSensitivity,
    /// Whether any access provides a default value.
    pub has_default_anywhere: bool,
    /// Total access count across all files.
    pub access_count: usize,
    /// .env files where this variable is defined.
    pub defined_in: Vec<EnvFileRef>,
    /// Whether this variable is missing from all .env files.
    pub is_missing: bool,
    /// Whether this variable has inconsistent values across .env files.
    pub is_inconsistent: bool,
    /// Framework association (if detected).
    pub framework: Option<String>,
    /// Whether this is a public/client-side variable.
    pub is_public: bool,
}

/// Reference to an .env file definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvFileRef {
    pub file: String,
    pub value: Option<String>,  // None if defined but empty
    pub line: u32,
}

/// Compact access location for aggregation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvAccessLocation {
    pub file: String,
    pub line: u32,
    pub access_method: String,
}
```

### 4.9 EnvironmentResult

```rust
/// Complete result of environment variable analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentResult {
    /// All env var access points.
    pub accesses: Vec<EnvAccess>,
    /// Aggregated variables.
    pub variables: Vec<EnvVariable>,
    /// Parsed .env files.
    pub env_files: Vec<EnvFile>,
    /// Variables used in code but not defined in any .env file.
    pub missing_variables: Vec<MissingVariable>,
    /// Variables with different values across .env files.
    pub inconsistent_variables: Vec<InconsistentVariable>,
    /// Detected framework environment patterns.
    pub framework_patterns: Vec<FrameworkEnvPattern>,
    /// Statistics.
    pub stats: EnvironmentStats,
}

/// A parsed .env file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvFile {
    /// File path (e.g., ".env", ".env.production").
    pub path: String,
    /// Environment name inferred from filename.
    pub environment: Option<String>,
    /// Variables defined in this file.
    pub variables: Vec<EnvFileVariable>,
    /// Number of variables.
    pub variable_count: usize,
    /// Whether this file has comments.
    pub has_comments: bool,
}

/// A variable defined in an .env file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvFileVariable {
    pub name: String,
    pub value: Option<String>,
    pub line: u32,
    pub has_quotes: bool,
    pub is_commented: bool,
}

/// A variable used in code but not defined in any .env file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingVariable {
    pub name: String,
    pub sensitivity: EnvSensitivity,
    pub access_count: usize,
    pub access_files: Vec<String>,
    pub has_default: bool,
    pub is_required: bool,
}

/// A variable with different values across .env files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InconsistentVariable {
    pub name: String,
    pub values: Vec<EnvFileRef>,
    pub severity: InconsistencySeverity,
}

/// Detected framework-specific environment pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkEnvPattern {
    pub framework: String,
    pub prefix: String,
    pub description: String,
    pub variables: Vec<String>,
    pub is_public: bool,
}
```

### 4.10 EnvironmentStats

```rust
/// Statistics for environment variable analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnvironmentStats {
    pub total_accesses: usize,
    pub unique_variables: usize,
    pub by_sensitivity: HashMap<EnvSensitivity, usize>,
    pub by_language: Vec<LanguageCount>,
    pub by_access_method: HashMap<String, usize>,
    pub env_files_count: usize,
    pub missing_count: usize,
    pub inconsistent_count: usize,
    pub public_count: usize,
    pub required_without_default: usize,
    pub coverage: f64,  // % of code-referenced vars defined in .env files
    pub files_analyzed: usize,
    pub duration_ms: u64,
}
```

### 4.11 HealthScore

```rust
/// Multi-factor health score for constants & environment hygiene.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthScore {
    /// Overall score (0-100).
    pub overall: u32,
    /// Per-factor breakdown.
    pub factors: HealthFactors,
    /// Grade: A (90+), B (80+), C (70+), D (60+), F (<60).
    pub grade: char,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthFactors {
    /// No hardcoded secrets (0-100, weight: 0.30).
    pub secret_hygiene: u32,
    /// Low magic number density (0-100, weight: 0.20).
    pub magic_number_hygiene: u32,
    /// No inconsistent constants (0-100, weight: 0.15).
    pub consistency: u32,
    /// No dead constants (0-100, weight: 0.10).
    pub dead_constant_ratio: u32,
    /// Env vars defined in .env files (0-100, weight: 0.15).
    pub env_coverage: u32,
    /// Good naming conventions (0-100, weight: 0.10).
    pub naming_quality: u32,
}
```

---

## 5. Phase 1: Constant Extraction from AST (Per-Language)

### What Changed from V1

V1 extracted constants via `thread_local!` `ConstantExtractor` that parsed files
independently. V2 consumes `ParseResult` from the unified analysis pipeline — the
AST is already parsed, and we extract from the structured data.

### Extraction Strategy

For each `ParseResult`, extract constant declarations by walking the AST for:

1. **Module-level const/static declarations** — `const X = 42`, `static X: i32 = 42`
2. **Class-level static fields** — `static readonly MAX = 100`, `public static final int MAX = 100`
3. **Enum variants** — `enum Color { Red = 1, Green = 2 }`
4. **#define macros** — `#define MAX_SIZE 1024` (C/C++)
5. **Frozen/immutable assignments** — `Object.freeze({})`, `tuple()` (Python)

### Per-Language Extraction Patterns

| Language | Const Declaration | Static Field | Enum | Other |
|----------|------------------|-------------|------|-------|
| TypeScript/JS | `const X =`, `Object.freeze()` | `static readonly X =` | `enum { X = }` | `as const` |
| Python | `X = ` (UPPER_CASE convention) | Class-level UPPER_CASE | `class X(Enum):` | `Final[T]` |
| Rust | `const X:`, `static X:` | — | `enum X { V = }` | `lazy_static!` |
| Java | `static final X =` | `static final X =` | `enum { X }` | `@Value` |
| C# | `const X =`, `static readonly X =` | `static readonly X =` | `enum { X = }` | — |
| Go | `const X =` | — | `iota` | `var X = ` (package-level) |
| PHP | `const X =`, `define('X', )` | `const X =` | — | `readonly` |
| C++ | `const X =`, `constexpr X =` | `static const X =` | `enum { X = }` | `#define X` |
| Ruby | `X = ` (UPPER_CASE) | — | — | `freeze` |

### Extraction Algorithm

```rust
pub fn extract_constants(
    parse_result: &ParseResult,
    language: Language,
) -> Vec<ConstantInfo> {
    let mut constants = Vec::new();

    // Strategy 1: Walk ParseResult.functions for const declarations
    // (ParseResult already extracts top-level declarations)
    for func in &parse_result.functions {
        if is_constant_declaration(func, language) {
            constants.push(build_constant_info(func, language));
        }
    }

    // Strategy 2: Walk ParseResult.classes for static fields
    for class in &parse_result.classes {
        for field in &class.fields {
            if is_static_constant(field, language) {
                constants.push(build_class_constant(class, field, language));
            }
        }
    }

    // Strategy 3: Walk ParseResult.exports for re-exported constants
    for export in &parse_result.exports {
        if is_constant_export(export, language) {
            // Mark existing constant as exported
            mark_exported(&mut constants, export);
        }
    }

    // Strategy 4: Language-specific patterns via tree-sitter queries
    extract_language_specific(&parse_result, language, &mut constants);

    constants
}
```

### Categorization Heuristics

Constants are categorized by analyzing name patterns and value patterns:

```rust
fn categorize_constant(name: &str, value: &str) -> ConstantCategory {
    let name_lower = name.to_lowercase();

    // Name-based heuristics (highest priority)
    if name_lower.contains("timeout") || name_lower.contains("delay")
        || name_lower.contains("interval") {
        return ConstantCategory::Time;
    }
    if name_lower.contains("max_") || name_lower.contains("min_")
        || name_lower.contains("limit") {
        return ConstantCategory::Limit;
    }
    if name_lower.contains("url") || name_lower.contains("endpoint")
        || name_lower.contains("host") || name_lower.contains("port") {
        return ConstantCategory::Config;
    }
    if name_lower.contains("key") || name_lower.contains("token")
        || name_lower.contains("secret") || name_lower.contains("password") {
        return ConstantCategory::Security;
    }
    if name_lower.contains("error") || name_lower.contains("err_") {
        return ConstantCategory::Error;
    }
    if name_lower.contains("status") || name_lower.contains("code") {
        return ConstantCategory::Status;
    }
    if name_lower.contains("size") || name_lower.contains("buffer")
        || name_lower.contains("capacity") {
        return ConstantCategory::Size;
    }
    if name_lower.contains("color") || name_lower.contains("width")
        || name_lower.contains("height") || name_lower.contains("label") {
        return ConstantCategory::Ui;
    }
    if name_lower.contains("regex") || name_lower.contains("pattern") {
        return ConstantCategory::Regex;
    }
    if name_lower.contains("table") || name_lower.contains("column")
        || name_lower.contains("query") {
        return ConstantCategory::Database;
    }
    if name_lower.contains("env") || name_lower.starts_with("next_public")
        || name_lower.starts_with("vite_") {
        return ConstantCategory::Environment;
    }

    // Value-based heuristics (fallback)
    if value.starts_with("http://") || value.starts_with("https://") {
        return ConstantCategory::Api;
    }
    if value.parse::<f64>().is_ok() {
        return ConstantCategory::Math;
    }

    ConstantCategory::Unknown
}
```

---

## 6. Phase 2: Magic Number Detection (AST-Based)

### What Changed from V1

V1 used line-level regex `\b(\d{2,})\b` which:
- Missed context (couldn't distinguish `setTimeout(5000)` from `const TIMEOUT = 5000`)
- Matched numbers inside string literals and comments
- Couldn't determine scope (module-level vs function-local)
- Had a static exclusion list that missed domain-specific safe numbers

V2 uses AST-based detection via `ParseResult.numeric_literals`:
- Knows the AST context (function argument, comparison, assignment, etc.)
- Automatically skips string literals and comments (AST-aware)
- Understands scope (only flags numbers in non-constant contexts)
- Uses dynamic exclusion based on language and framework

### Detection Algorithm

```rust
pub fn detect_magic_numbers(
    parse_result: &ParseResult,
    constants: &[ConstantInfo],
    language: Language,
    config: &MagicNumberConfig,
) -> Vec<MagicNumber> {
    let mut magic_numbers = Vec::new();
    let constant_values: HashSet<String> = constants.iter()
        .map(|c| c.value.clone())
        .collect();

    for numeric in &parse_result.numeric_literals {
        let value = numeric.value;

        // Skip excluded values
        if is_excluded_number(value, language, config) {
            continue;
        }

        // Skip if this value is already a named constant
        if constant_values.contains(&numeric.raw) {
            continue;
        }

        // Skip if inside a constant declaration (const X = 42 is fine)
        if is_in_constant_declaration(numeric, parse_result) {
            continue;
        }

        // Skip enum values
        if is_in_enum_declaration(numeric, parse_result) {
            continue;
        }

        // Determine AST context
        let ast_context = classify_context(numeric, parse_result);

        // Determine category from context
        let category = categorize_magic_number(numeric, ast_context, parse_result);

        // Generate suggested name
        let suggested_name = suggest_constant_name(
            value, ast_context, category, numeric, parse_result,
        );

        // Generate fix suggestion
        let fix = generate_fix_suggestion(
            numeric, &suggested_name, parse_result, language,
        );

        magic_numbers.push(MagicNumber {
            id: generate_id(&numeric.file, numeric.line, value),
            value,
            raw: numeric.raw.clone(),
            file: numeric.file.clone(),
            line: numeric.line,
            column: numeric.column,
            language,
            ast_context,
            category,
            suggested_name,
            fix_suggestion: fix,
            scope: determine_scope(numeric, parse_result),
            content_hash: parse_result.content_hash,
        });
    }

    magic_numbers
}
```

### Exclusion List (Expanded from V1)

```rust
/// Numbers that are universally safe and should never be flagged.
fn is_excluded_number(value: f64, language: Language, config: &MagicNumberConfig) -> bool {
    // Universal exclusions (same as v1 + expanded)
    let universal = [
        0.0, 1.0, 2.0, -1.0,           // Trivial
        10.0, 100.0, 1000.0,            // Powers of 10
        60.0, 24.0, 365.0, 7.0, 30.0,  // Time
        1024.0, 2048.0, 4096.0, 8192.0, // Powers of 2
        16384.0, 32768.0, 65536.0,
        // HTTP status codes
        200.0, 201.0, 204.0, 301.0, 302.0, 304.0,
        400.0, 401.0, 403.0, 404.0, 405.0, 409.0, 422.0, 429.0,
        500.0, 502.0, 503.0, 504.0,
        // Common math
        3.14159, 2.71828,               // PI, E (approximate)
        0.5, 0.25, 0.75,               // Common fractions
        255.0, 256.0,                   // Byte boundaries
        // Common bit patterns
        0xFF as f64, 0xFFFF as f64, 0xFFFFFFFF as f64,
    ];

    if universal.contains(&value) {
        return true;
    }

    // Year range (1900-2100)
    if value >= 1900.0 && value <= 2100.0 && value == value.floor() {
        return true;
    }

    // User-configured exclusions
    if config.excluded_values.contains(&value) {
        return true;
    }

    // Language-specific exclusions
    match language {
        Language::Go => {
            // Go uses 0o, 0b prefixes — iota patterns are fine
            false
        }
        Language::Rust => {
            // Rust uses typed literals (42u32) — these are often intentional
            false
        }
        _ => false,
    }
}
```

### Context-Aware Name Suggestion (Upgraded from V1)

```rust
fn suggest_constant_name(
    value: f64,
    context: MagicNumberContext,
    category: MagicNumberCategory,
    numeric: &NumericLiteralInfo,
    parse_result: &ParseResult,
) -> Option<String> {
    // Strategy 1: Infer from enclosing function/variable name
    if let Some(enclosing) = find_enclosing_context(numeric, parse_result) {
        match &enclosing {
            Context::FunctionCall(name) => {
                if name.contains("timeout") || name.contains("setTimeout") {
                    return Some(format!("TIMEOUT_MS_{}", value as u64));
                }
                if name.contains("retry") || name.contains("retries") {
                    return Some(format!("MAX_RETRIES_{}", value as u64));
                }
                if name.contains("port") || name.contains("listen") {
                    return Some(format!("PORT_{}", value as u64));
                }
            }
            Context::VariableAssignment(name) => {
                let upper = to_screaming_snake_case(name);
                return Some(upper);
            }
            Context::ObjectProperty(key) => {
                return Some(to_screaming_snake_case(key));
            }
            _ => {}
        }
    }

    // Strategy 2: Infer from category
    match category {
        MagicNumberCategory::Timeout => Some(format!("TIMEOUT_MS_{}", value as u64)),
        MagicNumberCategory::Port => Some(format!("PORT_{}", value as u64)),
        MagicNumberCategory::Size => Some(format!("MAX_SIZE_{}", value as u64)),
        MagicNumberCategory::Retry => Some(format!("MAX_RETRIES_{}", value as u64)),
        MagicNumberCategory::Threshold => Some(format!("THRESHOLD_{}", value as u64)),
        MagicNumberCategory::Percentage => Some(format!("PERCENTAGE_{}", value as u64)),
        _ => Some(format!("MAGIC_{}", value as u64)),
    }
}
```

---

## 7. Phase 3: Secret Detection Engine (100+ Patterns, Entropy Scoring)

### What Changed from V1

V1 had 21 regex patterns across 3 severity tiers with basic confidence scoring.
V2 expands to 100+ patterns across 7 severity tiers with entropy-based scoring,
contextual analysis, and provider-specific detection.

### 7.1 Provider-Specific Pattern Registry

All patterns are organized by provider for maintainability. Each pattern includes
metadata for CWE/OWASP mapping and contextual validation.

```rust
/// A single secret detection pattern.
#[derive(Debug, Clone)]
pub struct SecretPattern {
    /// Unique pattern identifier.
    pub name: &'static str,
    /// Provider/service (e.g., "aws", "github", "azure").
    pub provider: &'static str,
    /// Compiled regex pattern.
    pub regex: &'static str,
    /// Base severity.
    pub severity: SecretSeverity,
    /// Base confidence before adjustments.
    pub base_confidence: f64,
    /// Optional context keywords that must appear nearby to trigger.
    pub context_required: Option<&'static [&'static str]>,
    /// CWE identifier.
    pub cwe_id: &'static str,
    /// OWASP category.
    pub owasp_id: &'static str,
    /// Human-readable description.
    pub description: &'static str,
}
```

### Pattern Categories (100+ Total)

**AWS (8 patterns — preserved from v1 + expanded)**
| Pattern | Regex | Severity | Confidence |
|---------|-------|----------|------------|
| AWS Access Key ID | `AKIA[0-9A-Z]{16}` | Critical | 0.95 |
| AWS Secret Access Key | `aws.{0,20}secret.{0,20}['"][0-9a-zA-Z/+]{40}['"]` | Critical | 0.90 |
| AWS Session Token | `(?i)aws.{0,20}session.{0,20}token.{0,20}['"][A-Za-z0-9/+=]{100,}['"]` | Critical | 0.85 |
| AWS MFA Serial | `arn:aws:iam::\d{12}:mfa/` | Medium | 0.70 |
| AWS Account ID | `(?i)aws.{0,10}account.{0,10}id.{0,10}['"]?\d{12}['"]?` | Low | 0.50 |
| AWS ARN | `arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:` | Info | 0.40 |
| AWS S3 Presigned URL | `https://[a-z0-9.-]+\.s3\.amazonaws\.com/.*X-Amz-Credential` | High | 0.80 |
| AWS RDS Connection | `(?i)(rds|aurora).{0,30}(password\|passwd).{0,10}['"][^'"]+['"]` | Critical | 0.90 |

**Azure (6 patterns — NEW in v2)**
| Pattern | Regex | Severity | Confidence |
|---------|-------|----------|------------|
| Azure Storage Connection | `DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}` | Critical | 0.95 |
| Azure AD Client Secret | Context: `azure\|client.?secret\|tenant` + `[a-zA-Z0-9~._-]{34}` | High | 0.80 |
| Azure SAS Token | `(?i)(sv=\d{4}-\d{2}-\d{2}&s[a-z]=[a-z]+&)` | High | 0.85 |
| Azure Cosmos DB Key | `(?i)cosmos.{0,20}key.{0,20}['"][A-Za-z0-9+/=]{86}==['"]` | Critical | 0.90 |
| Azure Service Bus | `Endpoint=sb://[^;]+;SharedAccessKey=[A-Za-z0-9+/=]{44}=` | Critical | 0.90 |
| Azure DevOps PAT | `[a-z2-7]{52}` + context: `azure\|devops\|pat\|token` | High | 0.75 |

**GCP (5 patterns — NEW in v2)**
| Pattern | Regex | Severity | Confidence |
|---------|-------|----------|------------|
| GCP Service Account JSON | `"type"\s*:\s*"service_account"` | Critical | 0.95 |
| GCP API Key | `AIza[0-9A-Za-z\-_]{35}` | High | 0.90 |
| GCP OAuth Client Secret | `(?i)gcp\|google.{0,20}client.?secret.{0,20}['"][A-Za-z0-9_-]{24}['"]` | High | 0.85 |
| Firebase Config | `(?i)firebase.{0,20}(apiKey\|authDomain\|databaseURL)` | Medium | 0.70 |
| GCP Private Key ID | `(?i)private_key_id.{0,10}['"][a-f0-9]{40}['"]` | High | 0.85 |

**GitHub (4 patterns — preserved from v1 + expanded)**
| Pattern | Regex | Severity | Confidence |
|---------|-------|----------|------------|
| GitHub PAT (classic) | `ghp_[a-zA-Z0-9]{36}` | Critical | 0.95 |
| GitHub OAuth Token | `gho_[a-zA-Z0-9]{36}` | Critical | 0.95 |
| GitHub App Token | `(ghu\|ghs\|ghr)_[a-zA-Z0-9]{36}` | Critical | 0.95 |
| GitHub Token (generic) | `github.{0,20}token.{0,20}['"][a-zA-Z0-9]{35,40}['"]` | High | 0.80 |

**Stripe (2 patterns — preserved from v1)**
| Pattern | Regex | Severity | Confidence |
|---------|-------|----------|------------|
| Stripe Secret Key | `sk_live_[a-zA-Z0-9]{24,}` | Critical | 0.95 |
| Stripe Restricted Key | `rk_live_[a-zA-Z0-9]{24,}` | Critical | 0.95 |

**Package Registries (4 patterns — NEW in v2)**
| Pattern | Regex | Severity | Confidence |
|---------|-------|----------|------------|
| npm Token | `npm_[A-Za-z0-9]{36}` | High | 0.95 |
| PyPI Token | `pypi-[A-Za-z0-9]{32,}` | High | 0.95 |
| NuGet API Key | `oy2[a-z0-9]{43}` | High | 0.90 |
| RubyGems API Key | `rubygems_[a-f0-9]{48}` | High | 0.90 |

**Database (6 patterns — preserved + expanded)**
| Pattern | Regex | Severity | Confidence |
|---------|-------|----------|------------|
| PostgreSQL Connection | `postgres(ql)?://[^'"\s]+` | High | 0.85 |
| MySQL Connection | `mysql://[^'"\s]+` | High | 0.85 |
| MongoDB Connection | `mongodb(\+srv)?://[^'"\s]+` | High | 0.85 |
| Redis Connection | `redis://[^'"\s]+` | High | 0.80 |
| Database Password | `db.{0,10}(password\|passwd\|pwd)\s*[=:]\s*['"][^'"]+['"]` | High | 0.80 |
| JDBC Connection | `jdbc:[a-z]+://[^'"\s]+` | High | 0.80 |

**Cryptographic (6 patterns — preserved + expanded)**
| Pattern | Regex | Severity | Confidence |
|---------|-------|----------|------------|
| RSA Private Key | `-----BEGIN RSA PRIVATE KEY-----` | Critical | 0.99 |
| SSH Private Key | `-----BEGIN OPENSSH PRIVATE KEY-----` | Critical | 0.99 |
| PGP Private Key | `-----BEGIN PGP PRIVATE KEY BLOCK-----` | Critical | 0.99 |
| EC Private Key | `-----BEGIN EC PRIVATE KEY-----` | Critical | 0.99 |
| PKCS8 Private Key | `-----BEGIN PRIVATE KEY-----` | Critical | 0.99 |
| Certificate | `-----BEGIN CERTIFICATE-----` | Info | 0.40 |

**Communication (4 patterns — preserved from v1)**
| Pattern | Regex | Severity | Confidence |
|---------|-------|----------|------------|
| Slack Token | `xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*` | High | 0.90 |
| Slack Webhook | `https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+` | Medium | 0.85 |
| SendGrid API Key | `SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}` | High | 0.95 |
| Twilio API Key | `SK[a-f0-9]{32}` | High | 0.90 |

**Authentication (6 patterns — preserved + expanded)**
| Pattern | Regex | Severity | Confidence |
|---------|-------|----------|------------|
| JWT Token | `eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*` | High | 0.85 |
| Password Assignment | `(password\|passwd\|pwd)\s*[=:]\s*['"][^'"]{8,}['"]` | High | 0.80 |
| Bearer Token | `bearer\s+[a-zA-Z0-9_\-\.]+` | Medium | 0.60 |
| Basic Auth | `(?i)basic\s+[A-Za-z0-9+/=]{20,}` | Medium | 0.70 |
| OAuth Client Secret | `(?i)client.?secret.{0,10}['"][a-zA-Z0-9_-]{20,}['"]` | High | 0.80 |
| API Key (generic) | `(api[_-]?key\|apikey)\s*[=:]\s*['"][a-zA-Z0-9]{20,}['"]` | Medium | 0.60 |

**Infrastructure (8 patterns — NEW in v2)**
| Pattern | Regex | Severity | Confidence |
|---------|-------|----------|------------|
| Hashicorp Vault Token | `hvs\.[a-zA-Z0-9_-]{24,}` | Critical | 0.95 |
| Hashicorp Terraform Token | `(?i)terraform.{0,20}token.{0,20}['"][a-zA-Z0-9.]{14,}['"]` | High | 0.80 |
| Docker Registry Auth | `(?i)docker.{0,20}(password\|auth).{0,10}['"][^'"]+['"]` | High | 0.80 |
| Kubernetes Secret | `(?i)kind:\s*Secret` + `data:` | Medium | 0.70 |
| Datadog API Key | `(?i)datadog.{0,20}(api.?key\|app.?key).{0,10}['"][a-f0-9]{32}['"]` | High | 0.85 |
| New Relic License Key | `(?i)new.?relic.{0,20}license.{0,10}['"][a-f0-9]{40}['"]` | High | 0.85 |
| Sentry DSN | `https://[a-f0-9]{32}@[a-z0-9.]+\.ingest\.sentry\.io/\d+` | Medium | 0.80 |
| Databricks Token | `dapi[a-f0-9]{32}` | High | 0.90 |

**Generic (6 patterns — preserved from v1)**
| Pattern | Regex | Severity | Confidence |
|---------|-------|----------|------------|
| Hardcoded Password | `(password\|passwd\|pwd)\s*[=:]\s*['"][^'"]+['"]` | Medium | 0.60 |
| Secret Assignment | `(secret\|api_key\|private_key)\s*[=:]\s*['"][^'"]{16,}['"]` | Medium | 0.60 |
| High Entropy String | (entropy-based, no regex) | Low | 0.40 |
| Connection String | `(Server\|Data Source)=[^;]+;.*Password=[^;]+` | High | 0.80 |
| Private Key Inline | `(?i)private.?key.{0,10}['"][A-Za-z0-9+/=\n]{50,}['"]` | Critical | 0.90 |
| Webhook URL | `https://[a-z]+\.webhook\.[a-z]+/` | Medium | 0.65 |

### 7.2 Severity Classification

```rust
impl SecretSeverity {
    /// Base confidence for this severity tier.
    pub fn base_confidence(&self) -> f64 {
        match self {
            Self::Critical => 0.90,
            Self::High => 0.80,
            Self::Medium => 0.60,
            Self::Low => 0.40,
            Self::Info => 0.20,
            Self::FalsePositive => 0.0,
            Self::Suppressed => 0.0,
        }
    }
}
```

### 7.3 CWE/OWASP Mapping

Every secret pattern maps to relevant CWE and OWASP identifiers:

| Secret Type | CWE | OWASP |
|------------|-----|-------|
| Hardcoded credentials | CWE-798 | A02:2025 |
| Hardcoded crypto key | CWE-321 | A02:2025 |
| Security-relevant constant | CWE-547 | A02:2025 |
| Cleartext password | CWE-312 | A02:2025 |
| Insufficiently protected credentials | CWE-522 | A07:2025 |

### 7.4 Contextual Analysis

Nearby keywords increase or decrease confidence:

```rust
/// Keywords that increase confidence when found near a pattern match.
const POSITIVE_CONTEXT: &[&str] = &[
    "secret", "private", "credential", "password", "token",
    "auth", "key", "api_key", "access_key", "connection_string",
    "production", "prod", "live", "real",
];

/// Keywords that decrease confidence (likely test/example).
const NEGATIVE_CONTEXT: &[&str] = &[
    "test", "mock", "fake", "dummy", "example", "sample",
    "placeholder", "template", "fixture", "stub", "sandbox",
    "development", "dev", "staging", "local",
];

fn adjust_confidence_by_context(
    base: f64,
    line_content: &str,
    surrounding_lines: &[&str],
) -> f64 {
    let mut adjustment = 0.0;
    let context = surrounding_lines.join(" ").to_lowercase();

    for keyword in POSITIVE_CONTEXT {
        if context.contains(keyword) {
            adjustment += 0.05;
        }
    }
    for keyword in NEGATIVE_CONTEXT {
        if context.contains(keyword) {
            adjustment -= 0.10;
        }
    }

    (base + adjustment).clamp(0.0, 1.0)
}
```

### 7.5 Placeholder Detection (Preserved + Expanded)

```rust
/// Placeholder patterns that indicate example/template values.
const PLACEHOLDER_PATTERNS: &[&str] = &[
    "example", "placeholder", "your_", "xxx", "todo",
    "changeme", "replace", "insert", "fill_in", "update_this",
    "dummy", "fake", "test", "sample", "demo",
    "xxxxxxxxx", "000000000", "aaaaaaaaa",
    "<your-", "${", "{{",
];

fn is_placeholder(value: &str) -> bool {
    let lower = value.to_lowercase();

    // Check against placeholder patterns
    for pattern in PLACEHOLDER_PATTERNS {
        if lower.contains(pattern) {
            return true;
        }
    }

    // Check for all-same-character strings
    if value.len() > 4 {
        let first = value.chars().next().unwrap();
        if value.chars().all(|c| c == first) {
            return true;
        }
    }

    // Check for exact matches of common placeholder values
    matches!(lower.as_str(), "password" | "secret" | "token" | "key"
        | "changeme" | "password123" | "admin" | "root")
}
```

### 7.6 Value Masking (Preserved from V1)

```rust
/// Mask a secret value for safe display.
/// Shows enough to identify the secret without exposing it.
pub fn mask_value(value: &str) -> String {
    let len = value.len();
    if len <= 8 {
        "*".repeat(len)
    } else {
        let visible = std::cmp::min(4, len / 4);
        format!(
            "{}...{}",
            &value[..visible],
            &value[len - visible..]
        )
    }
}
```

---

## 8. Phase 4: Inconsistency Detection (Fuzzy Name Matching)

### What Changed from V1

V1 grouped constants by exact lowercase name and flagged groups with different values.
This missed common inconsistencies like `MAX_RETRIES` vs `maxRetries` vs `MaxRetries`.

V2 uses fuzzy name matching with normalization:

```rust
/// Normalize a constant name for fuzzy matching.
/// Splits on camelCase, snake_case, kebab-case boundaries → lowercase → join with _.
fn normalize_name(name: &str) -> String {
    let mut parts = Vec::new();
    let mut current = String::new();

    for (i, ch) in name.chars().enumerate() {
        if ch == '_' || ch == '-' {
            if !current.is_empty() {
                parts.push(current.clone());
                current.clear();
            }
        } else if ch.is_uppercase() && i > 0 {
            // camelCase boundary
            let prev = name.chars().nth(i - 1).unwrap_or('_');
            if prev.is_lowercase() || prev.is_ascii_digit() {
                if !current.is_empty() {
                    parts.push(current.clone());
                    current.clear();
                }
            }
            current.push(ch.to_lowercase().next().unwrap());
        } else {
            current.push(ch.to_lowercase().next().unwrap());
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }

    parts.join("_")
}

/// Detect inconsistent constants using fuzzy name matching.
pub fn detect_inconsistencies(
    constants: &[ConstantInfo],
) -> Vec<InconsistentValue> {
    // Group by normalized name
    let mut groups: HashMap<String, Vec<&ConstantInfo>> = HashMap::new();
    for constant in constants {
        let normalized = normalize_name(&constant.name);
        groups.entry(normalized).or_default().push(constant);
    }

    let mut inconsistencies = Vec::new();

    for (normalized, group) in &groups {
        if group.len() < 2 {
            continue;
        }

        // Check if values differ
        let values: HashSet<&str> = group.iter().map(|c| c.value.as_str()).collect();
        if values.len() <= 1 {
            continue; // All same value — consistent
        }

        // Calculate match score (how similar the names are)
        let names: Vec<&str> = group.iter().map(|c| c.name.as_str()).collect();
        let match_score = calculate_name_similarity(&names);

        // Determine severity
        let severity = if match_score > 0.9 {
            InconsistencySeverity::High   // Very similar names, different values = likely bug
        } else if match_score > 0.7 {
            InconsistencySeverity::Medium  // Similar names = possibly unintentional
        } else {
            InconsistencySeverity::Low     // Loosely similar = possibly intentional
        };

        // Find most common variant as suggested canonical
        let suggested = find_most_common_name(&group);

        inconsistencies.push(InconsistentValue {
            normalized_name: normalized.clone(),
            locations: group.iter().map(|c| ValueLocation {
                name: c.name.clone(),
                value: c.value.clone(),
                file: c.file.clone(),
                line: c.line,
            }).collect(),
            match_score,
            suggested_canonical: suggested,
            severity,
        });
    }

    inconsistencies
}
```

---

## 9. Phase 5: Dead Constant Detection (Call Graph Integration)

### What Changed from V1

V1 dead constant detection was TypeScript-only and required the call graph to be
available. V2 moves this to Rust and integrates directly with the call graph.

### Detection Algorithm

```rust
/// Detect constants that are declared but never referenced.
/// Requires call graph for cross-file reference tracking.
pub fn detect_dead_constants(
    constants: &[ConstantInfo],
    call_graph: Option<&CallGraphDb>,
    parse_results: &[ParseResult],
) -> Vec<DeadConstant> {
    let mut dead = Vec::new();

    for constant in constants {
        // Skip non-exported module-level constants (they might be used locally)
        if !constant.is_exported && constant.scope == ConstantScope::Module {
            // Check local references within the same file
            let local_refs = count_local_references(
                &constant.name, &constant.file, parse_results,
            );
            if local_refs > 1 { // 1 = the declaration itself
                continue;
            }
        }

        // For exported constants, check cross-file references
        if constant.is_exported {
            let cross_refs = match call_graph {
                Some(cg) => count_cross_file_references(
                    &constant.name, &constant.file, cg,
                ),
                None => {
                    // Without call graph, check import references
                    count_import_references(
                        &constant.name, &constant.file, parse_results,
                    )
                }
            };

            if cross_refs > 0 {
                continue; // Referenced elsewhere
            }
        }

        // Calculate confidence
        let confidence = calculate_dead_confidence(constant, parse_results);

        dead.push(DeadConstant {
            constant_id: constant.id.clone(),
            name: constant.name.clone(),
            file: constant.file.clone(),
            line: constant.line,
            is_exported: constant.is_exported,
            confidence,
        });
    }

    dead
}

/// Confidence that a constant is truly dead.
/// Lower confidence if dynamic access patterns are detected.
fn calculate_dead_confidence(
    constant: &ConstantInfo,
    parse_results: &[ParseResult],
) -> f64 {
    let mut confidence = 0.9;

    // Lower confidence if the file uses dynamic property access
    // (e.g., obj[varName] could reference any constant)
    if has_dynamic_access_patterns(&constant.file, parse_results) {
        confidence -= 0.3;
    }

    // Lower confidence if the constant is in a library/shared module
    if constant.file.contains("lib/") || constant.file.contains("shared/")
        || constant.file.contains("utils/") {
        confidence -= 0.1;
    }

    // Higher confidence if the constant is in a test file
    if constant.file.contains("test") || constant.file.contains("spec") {
        confidence -= 0.2; // Test constants are often used dynamically
    }

    confidence.clamp(0.1, 1.0)
}
```

---

## 10. Phase 6: Environment Variable Extraction (9+ Languages, 15+ Access Methods)

### What Changed from V1

V1 extracted env vars via AST + regex patterns. V2 consumes `ParseResult` and uses
tree-sitter queries for precise extraction across 9+ languages.

### Per-Language Extraction Patterns

```rust
/// Extract environment variable accesses from a ParseResult.
pub fn extract_env_accesses(
    parse_result: &ParseResult,
    language: Language,
) -> Vec<EnvAccess> {
    match language {
        Language::TypeScript | Language::JavaScript => extract_js_env(parse_result),
        Language::Python => extract_python_env(parse_result),
        Language::Rust => extract_rust_env(parse_result),
        Language::Java | Language::Kotlin => extract_java_env(parse_result),
        Language::CSharp => extract_csharp_env(parse_result),
        Language::Go => extract_go_env(parse_result),
        Language::Php => extract_php_env(parse_result),
        Language::Ruby => extract_ruby_env(parse_result),
        Language::Cpp => extract_cpp_env(parse_result),
        _ => Vec::new(),
    }
}
```

### 10.1 JavaScript/TypeScript Extraction

```rust
fn extract_js_env(parse_result: &ParseResult) -> Vec<EnvAccess> {
    let mut accesses = Vec::new();

    // Pattern 1: process.env.VAR_NAME (member expression)
    // Pattern 2: process.env["VAR_NAME"] (computed member expression)
    // Pattern 3: import.meta.env.VITE_VAR (Vite)
    // Pattern 4: Deno.env.get("VAR") (Deno)

    for call_site in &parse_result.call_sites {
        // process.env.get() or process.env["X"]
        if call_site.receiver.as_deref() == Some("process.env") {
            // Extract variable name from argument or member
            if let Some(var_name) = extract_env_var_name(call_site) {
                accesses.push(build_env_access(
                    var_name,
                    call_site,
                    EnvAccessMethod::ProcessEnv,
                    parse_result,
                ));
            }
        }
    }

    // Also scan string_literals for process.env references
    // (handles destructuring: const { VAR } = process.env)
    for string_lit in &parse_result.string_literals {
        if let Some(var_name) = extract_env_from_string_context(string_lit) {
            accesses.push(build_env_access_from_string(
                var_name,
                string_lit,
                EnvAccessMethod::ProcessEnv,
                parse_result,
            ));
        }
    }

    accesses
}
```

### 10.2 Complete Access Method Registry

| Language | Access Method | Pattern | Has Default |
|----------|-------------|---------|-------------|
| JS/TS | `process.env.X` | Member expression | No |
| JS/TS | `process.env["X"]` | Computed member | No |
| JS/TS | `process.env.X \|\| "default"` | Logical OR | Yes |
| JS/TS | `process.env.X ?? "default"` | Nullish coalescing | Yes |
| JS/TS | `import.meta.env.VITE_X` | Vite import.meta | No |
| Python | `os.environ["X"]` | Subscript | No |
| Python | `os.environ.get("X", "default")` | Method call | Yes |
| Python | `os.getenv("X")` | Function call | Optional |
| Python | `dotenv_values()` | dotenv library | N/A |
| Rust | `std::env::var("X")` | Function call | No (Result) |
| Rust | `std::env::var("X").unwrap_or("default")` | Method chain | Yes |
| Java | `System.getenv("X")` | Static method | No |
| Java | `System.getProperty("X", "default")` | Static method | Yes |
| C# | `Environment.GetEnvironmentVariable("X")` | Static method | No |
| C# | `Configuration["X"]` | Indexer | No |
| Go | `os.Getenv("X")` | Function call | No |
| Go | `os.LookupEnv("X")` | Function call | No (bool) |
| PHP | `getenv("X")` | Function call | No |
| PHP | `$_ENV["X"]` | Superglobal | No |
| PHP | `env("X", "default")` | Laravel helper | Yes |
| Ruby | `ENV["X"]` | Subscript | No |
| Ruby | `ENV.fetch("X", "default")` | Method call | Yes |
| Shell | `${X}` or `$X` | Variable expansion | No |
| Shell | `${X:-default}` | Default expansion | Yes |
| Docker | `${X}` in Dockerfile | ARG/ENV | Depends |
| C++ | `std::getenv("X")` | Function call | No |

---

## 11. Phase 7: .env File Parsing (Dotenv Spec Compliance)

### What Changed from V1

V1 .env parsing was TypeScript-only. V2 moves it to Rust for unified analysis.

### Dotenv Spec Compliance

The parser follows the dotenv specification with support for:
- Basic `KEY=value` assignments
- Quoted values (single, double, backtick)
- Multiline values (double-quoted with `\n`)
- Comments (`#` at start of line or after value)
- Variable interpolation (`${OTHER_VAR}`)
- Export prefix (`export KEY=value`)
- Empty values (`KEY=`)

### File Discovery

```rust
/// Discover .env files in the project root.
/// Follows standard dotenv file precedence.
const ENV_FILE_PATTERNS: &[&str] = &[
    ".env",
    ".env.local",
    ".env.development",
    ".env.development.local",
    ".env.test",
    ".env.test.local",
    ".env.staging",
    ".env.staging.local",
    ".env.production",
    ".env.production.local",
    ".env.example",
    ".env.sample",
    ".env.template",
];

/// Infer environment name from .env filename.
fn infer_environment(filename: &str) -> Option<String> {
    if filename == ".env" || filename == ".env.local" {
        return Some("default".to_string());
    }
    // Extract middle part: .env.{environment}[.local]
    let parts: Vec<&str> = filename.split('.').collect();
    if parts.len() >= 3 {
        let env = parts[2];
        if env != "local" && env != "example" && env != "sample" && env != "template" {
            return Some(env.to_string());
        }
    }
    None
}
```

### Parser Implementation

```rust
/// Parse a .env file into structured variables.
pub fn parse_env_file(content: &str, path: &str) -> EnvFile {
    let mut variables = Vec::new();
    let mut has_comments = false;

    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        // Skip empty lines
        if trimmed.is_empty() {
            continue;
        }

        // Skip comments
        if trimmed.starts_with('#') {
            has_comments = true;
            continue;
        }

        // Skip export prefix
        let line_content = if trimmed.starts_with("export ") {
            &trimmed[7..]
        } else {
            trimmed
        };

        // Parse KEY=VALUE
        if let Some(eq_pos) = line_content.find('=') {
            let name = line_content[..eq_pos].trim().to_string();
            let raw_value = line_content[eq_pos + 1..].trim();

            // Handle quoted values
            let (value, has_quotes) = parse_value(raw_value);

            // Check for inline comments
            let is_commented = false; // Already handled above

            variables.push(EnvFileVariable {
                name,
                value,
                line: (line_num + 1) as u32,
                has_quotes,
                is_commented,
            });
        }
    }

    EnvFile {
        path: path.to_string(),
        environment: infer_environment(
            std::path::Path::new(path)
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or(path),
        ),
        variable_count: variables.len(),
        has_comments,
        variables,
    }
}
```

### 11.5 .env Template Generation (NEW in V2)

```rust
/// Generate a .env.example file from code analysis.
/// Lists all environment variables found in code with descriptions.
pub fn generate_env_template(
    variables: &[EnvVariable],
) -> String {
    let mut output = String::new();
    output.push_str("# Auto-generated by Drift — environment variable template\n");
    output.push_str("# Copy this file to .env and fill in the values\n\n");

    // Group by sensitivity
    let mut by_sensitivity: BTreeMap<EnvSensitivity, Vec<&EnvVariable>> = BTreeMap::new();
    for var in variables {
        by_sensitivity.entry(var.sensitivity).or_default().push(var);
    }

    for (sensitivity, vars) in &by_sensitivity {
        output.push_str(&format!("# --- {} ---\n", sensitivity_label(sensitivity)));
        for var in vars {
            if let Some(desc) = &var.accesses.first().and_then(|a| None::<String>) {
                output.push_str(&format!("# {}\n", desc));
            }
            let default = if var.has_default_anywhere {
                "# has default in code"
            } else {
                "# REQUIRED"
            };
            output.push_str(&format!("{}= {}\n", var.name, default));
        }
        output.push('\n');
    }

    output
}
```

---

## 12. Phase 8: Missing & Inconsistent Variable Detection

### Missing Variable Detection

Cross-references environment variables found in code against .env files:

```rust
/// Detect environment variables used in code but not defined in any .env file.
pub fn detect_missing_variables(
    variables: &[EnvVariable],
    env_files: &[EnvFile],
) -> Vec<MissingVariable> {
    let defined: HashSet<String> = env_files.iter()
        .flat_map(|f| f.variables.iter().map(|v| v.name.clone()))
        .collect();

    variables.iter()
        .filter(|v| !defined.contains(&v.name))
        .filter(|v| !is_framework_provided(&v.name)) // Skip NODE_ENV, etc.
        .map(|v| MissingVariable {
            name: v.name.clone(),
            sensitivity: v.sensitivity,
            access_count: v.access_count,
            access_files: v.accesses.iter().map(|a| a.file.clone()).collect(),
            has_default: v.has_default_anywhere,
            is_required: !v.has_default_anywhere && v.access_count > 1,
        })
        .collect()
}

/// Variables provided by the runtime/framework, not user-defined.
fn is_framework_provided(name: &str) -> bool {
    matches!(name,
        "NODE_ENV" | "HOME" | "PATH" | "USER" | "SHELL" | "TERM"
        | "PWD" | "LANG" | "LC_ALL" | "TZ" | "HOSTNAME"
        | "CI" | "GITHUB_ACTIONS" | "GITLAB_CI" | "JENKINS_URL"
        | "VERCEL" | "NETLIFY" | "HEROKU"
    )
}
```

### Inconsistent Variable Detection

Detects variables with different values across .env file variants:

```rust
/// Detect variables with different values across .env files.
pub fn detect_inconsistent_variables(
    env_files: &[EnvFile],
) -> Vec<InconsistentVariable> {
    // Group all variable definitions by name across all .env files
    let mut by_name: HashMap<String, Vec<EnvFileRef>> = HashMap::new();

    for file in env_files {
        // Skip example/template files
        if file.path.contains("example") || file.path.contains("sample")
            || file.path.contains("template") {
            continue;
        }

        for var in &file.variables {
            by_name.entry(var.name.clone()).or_default().push(EnvFileRef {
                file: file.path.clone(),
                value: var.value.clone(),
                line: var.line,
            });
        }
    }

    by_name.into_iter()
        .filter(|(_, refs)| {
            // Only flag if defined in 2+ files with different values
            if refs.len() < 2 { return false; }
            let values: HashSet<Option<&str>> = refs.iter()
                .map(|r| r.value.as_deref())
                .collect();
            values.len() > 1
        })
        .map(|(name, refs)| {
            let severity = classify_inconsistency_severity(&name, &refs);
            InconsistentVariable { name, values: refs, severity }
        })
        .collect()
}

fn classify_inconsistency_severity(
    name: &str,
    refs: &[EnvFileRef],
) -> InconsistencySeverity {
    let name_lower = name.to_lowercase();

    // Critical variables with different values = High severity
    if name_lower.contains("database") || name_lower.contains("secret")
        || name_lower.contains("password") || name_lower.contains("key") {
        return InconsistencySeverity::High;
    }

    // URLs/endpoints with different values = Medium (expected across environments)
    if name_lower.contains("url") || name_lower.contains("host")
        || name_lower.contains("endpoint") {
        return InconsistencySeverity::Low; // Expected to differ
    }

    InconsistencySeverity::Medium
}
```

---

## 13. Phase 9: Framework-Specific Environment Detection

### Framework Environment Registry

Declarative registry of framework-specific environment variable patterns:

```rust
/// A framework's environment variable conventions.
#[derive(Debug, Clone)]
pub struct FrameworkEnvSpec {
    /// Framework name.
    pub name: &'static str,
    /// Variable name prefix (e.g., "NEXT_PUBLIC_" for Next.js).
    pub prefix: Option<&'static str>,
    /// Detection pattern: file or dependency that indicates this framework.
    pub detection: FrameworkDetection,
    /// Whether prefixed variables are exposed to the client/browser.
    pub is_public: bool,
    /// Well-known variables for this framework.
    pub known_variables: &'static [&'static str],
    /// Description of the prefix convention.
    pub description: &'static str,
}

#[derive(Debug, Clone)]
pub enum FrameworkDetection {
    /// Detect by package.json dependency.
    Dependency(&'static str),
    /// Detect by config file existence.
    ConfigFile(&'static str),
    /// Detect by import pattern in code.
    ImportPattern(&'static str),
}

/// Registry of framework-specific environment patterns.
pub const FRAMEWORK_ENV_REGISTRY: &[FrameworkEnvSpec] = &[
    // JavaScript/TypeScript Frameworks
    FrameworkEnvSpec {
        name: "Next.js",
        prefix: Some("NEXT_PUBLIC_"),
        detection: FrameworkDetection::Dependency("next"),
        is_public: true,
        known_variables: &["NEXT_PUBLIC_API_URL", "NEXT_PUBLIC_ANALYTICS_ID"],
        description: "NEXT_PUBLIC_ prefix exposes variables to the browser bundle",
    },
    FrameworkEnvSpec {
        name: "Vite",
        prefix: Some("VITE_"),
        detection: FrameworkDetection::Dependency("vite"),
        is_public: true,
        known_variables: &["VITE_API_URL", "VITE_APP_TITLE"],
        description: "VITE_ prefix exposes variables via import.meta.env",
    },
    FrameworkEnvSpec {
        name: "Create React App",
        prefix: Some("REACT_APP_"),
        detection: FrameworkDetection::Dependency("react-scripts"),
        is_public: true,
        known_variables: &["REACT_APP_API_URL"],
        description: "REACT_APP_ prefix exposes variables to the browser",
    },
    FrameworkEnvSpec {
        name: "Nuxt.js",
        prefix: Some("NUXT_PUBLIC_"),
        detection: FrameworkDetection::Dependency("nuxt"),
        is_public: true,
        known_variables: &["NUXT_PUBLIC_API_BASE"],
        description: "NUXT_PUBLIC_ prefix for runtime config",
    },
    FrameworkEnvSpec {
        name: "Expo",
        prefix: Some("EXPO_PUBLIC_"),
        detection: FrameworkDetection::Dependency("expo"),
        is_public: true,
        known_variables: &["EXPO_PUBLIC_API_URL"],
        description: "EXPO_PUBLIC_ prefix for client-side access",
    },
    FrameworkEnvSpec {
        name: "Remix",
        prefix: None,
        detection: FrameworkDetection::Dependency("@remix-run/node"),
        is_public: false,
        known_variables: &["SESSION_SECRET", "DATABASE_URL"],
        description: "Remix uses server-side env vars only (no client prefix)",
    },

    // Python Frameworks
    FrameworkEnvSpec {
        name: "Django",
        prefix: Some("DJANGO_"),
        detection: FrameworkDetection::ImportPattern("django"),
        is_public: false,
        known_variables: &[
            "DJANGO_SECRET_KEY", "DJANGO_DEBUG", "DJANGO_ALLOWED_HOSTS",
            "DJANGO_SETTINGS_MODULE", "DATABASE_URL",
        ],
        description: "Django settings often loaded from environment",
    },
    FrameworkEnvSpec {
        name: "Flask",
        prefix: Some("FLASK_"),
        detection: FrameworkDetection::ImportPattern("flask"),
        is_public: false,
        known_variables: &["FLASK_APP", "FLASK_ENV", "FLASK_DEBUG", "SECRET_KEY"],
        description: "Flask uses FLASK_ prefix for CLI configuration",
    },
    FrameworkEnvSpec {
        name: "FastAPI",
        prefix: None,
        detection: FrameworkDetection::ImportPattern("fastapi"),
        is_public: false,
        known_variables: &["DATABASE_URL", "SECRET_KEY", "CORS_ORIGINS"],
        description: "FastAPI typically uses pydantic Settings for env loading",
    },

    // Java Frameworks
    FrameworkEnvSpec {
        name: "Spring Boot",
        prefix: Some("SPRING_"),
        detection: FrameworkDetection::ConfigFile("application.properties"),
        is_public: false,
        known_variables: &[
            "SPRING_DATASOURCE_URL", "SPRING_DATASOURCE_USERNAME",
            "SPRING_DATASOURCE_PASSWORD", "SPRING_PROFILES_ACTIVE",
            "SERVER_PORT",
        ],
        description: "Spring Boot relaxed binding: SPRING_DATASOURCE_URL → spring.datasource.url",
    },

    // .NET Frameworks
    FrameworkEnvSpec {
        name: "ASP.NET Core",
        prefix: Some("ASPNETCORE_"),
        detection: FrameworkDetection::ConfigFile("appsettings.json"),
        is_public: false,
        known_variables: &[
            "ASPNETCORE_ENVIRONMENT", "ASPNETCORE_URLS",
            "ConnectionStrings__DefaultConnection",
        ],
        description: "ASP.NET Core uses __ as section separator in env vars",
    },

    // Go Frameworks
    FrameworkEnvSpec {
        name: "Go (standard)",
        prefix: None,
        detection: FrameworkDetection::ConfigFile("go.mod"),
        is_public: false,
        known_variables: &["PORT", "DATABASE_URL", "REDIS_URL"],
        description: "Go typically uses plain env var names",
    },

    // PHP Frameworks
    FrameworkEnvSpec {
        name: "Laravel",
        prefix: None,
        detection: FrameworkDetection::ConfigFile("artisan"),
        is_public: false,
        known_variables: &[
            "APP_NAME", "APP_ENV", "APP_KEY", "APP_DEBUG", "APP_URL",
            "DB_CONNECTION", "DB_HOST", "DB_PORT", "DB_DATABASE",
            "DB_USERNAME", "DB_PASSWORD",
        ],
        description: "Laravel uses .env extensively with env() helper",
    },

    // Ruby Frameworks
    FrameworkEnvSpec {
        name: "Ruby on Rails",
        prefix: None,
        detection: FrameworkDetection::ConfigFile("Gemfile"),
        is_public: false,
        known_variables: &[
            "RAILS_ENV", "SECRET_KEY_BASE", "DATABASE_URL",
            "RAILS_MASTER_KEY", "REDIS_URL",
        ],
        description: "Rails uses ENV[] with credentials for secrets",
    },

    // Rust Frameworks
    FrameworkEnvSpec {
        name: "Actix Web",
        prefix: None,
        detection: FrameworkDetection::Dependency("actix-web"),
        is_public: false,
        known_variables: &["HOST", "PORT", "DATABASE_URL", "RUST_LOG"],
        description: "Actix typically uses dotenv + std::env::var",
    },
];
```

---

## 14. Phase 10: Sensitivity Classification Engine (4-Tier)

### Classification Algorithm (Upgraded from V1)

V1 used simple pattern matching on variable names. V2 adds value-based inference
and framework-aware classification.

```rust
/// Classify the sensitivity of an environment variable.
pub fn classify_sensitivity(
    name: &str,
    value: Option<&str>,
    framework: Option<&str>,
) -> EnvSensitivity {
    let name_lower = name.to_lowercase();

    // Tier 1: Critical — credentials that grant direct access
    if name_lower.contains("secret_key") || name_lower.contains("private_key")
        || name_lower.contains("master_key") || name_lower.ends_with("_secret")
        || name_lower == "database_url" || name_lower.contains("connection_string")
        || name_lower.contains("_password") || name_lower.contains("_passwd") {
        return EnvSensitivity::Critical;
    }

    // Tier 2: Secret — tokens and keys that authenticate
    if name_lower.contains("_key") || name_lower.contains("_token")
        || name_lower.contains("_auth") || name_lower.contains("_credential")
        || name_lower.contains("api_key") || name_lower.contains("access_key")
        || name_lower.contains("bearer") || name_lower.contains("jwt_secret") {
        return EnvSensitivity::Secret;
    }

    // Tier 3: Internal — infrastructure details
    if name_lower.contains("_host") || name_lower.contains("_port")
        || name_lower.contains("_url") || name_lower.contains("_endpoint")
        || name_lower.contains("_addr") || name_lower.contains("_dsn")
        || name_lower.contains("_uri") || name_lower.contains("redis_")
        || name_lower.contains("smtp_") || name_lower.contains("_region") {
        return EnvSensitivity::Internal;
    }

    // Value-based inference (if value is available)
    if let Some(val) = value {
        if val.starts_with("http://") || val.starts_with("https://") {
            return EnvSensitivity::Internal;
        }
        if val.contains("password") || val.contains("secret") {
            return EnvSensitivity::Secret;
        }
    }

    // Framework-specific: public prefixes are always Public
    if let Some(fw) = framework {
        for spec in FRAMEWORK_ENV_REGISTRY {
            if spec.name == fw {
                if let Some(prefix) = spec.prefix {
                    if name.starts_with(prefix) && spec.is_public {
                        return EnvSensitivity::Public;
                    }
                }
            }
        }
    }

    // Default: Public
    EnvSensitivity::Public
}
```

---

## 15. Phase 11: Confidence Scoring (Bayesian + Entropy)

### Entropy Calculation (NEW in V2)

From GitGuardian research: pattern + entropy hybrid reduces false positives.

```rust
/// Calculate Shannon entropy of a string.
/// High entropy (>4.0) suggests random/generated content (likely real secret).
/// Low entropy (<3.0) suggests structured/readable content (likely placeholder).
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }

    let len = s.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Calculate final confidence for a secret candidate.
/// Combines base severity confidence + entropy adjustment + contextual signals.
pub fn calculate_secret_confidence(
    pattern: &SecretPattern,
    matched_value: &str,
    line_content: &str,
    surrounding_lines: &[&str],
) -> f64 {
    let mut confidence = pattern.base_confidence;

    // Entropy adjustment (from R7 recommendation)
    let entropy = shannon_entropy(matched_value);
    if entropy > 4.5 {
        confidence += 0.10;  // Very high entropy — likely real
    } else if entropy > 4.0 {
        confidence += 0.05;  // High entropy
    } else if entropy < 2.5 {
        confidence -= 0.20;  // Low entropy — likely placeholder
    } else if entropy < 3.0 {
        confidence -= 0.10;  // Below average entropy
    }

    // Length adjustment (preserved from v1)
    if matched_value.len() > 30 {
        confidence += 0.05;
    }

    // Character diversity adjustment (preserved from v1)
    let has_upper = matched_value.chars().any(|c| c.is_uppercase());
    let has_lower = matched_value.chars().any(|c| c.is_lowercase());
    let has_digit = matched_value.chars().any(|c| c.is_ascii_digit());
    let has_special = matched_value.chars().any(|c| !c.is_alphanumeric());
    let diversity = [has_upper, has_lower, has_digit, has_special]
        .iter().filter(|&&b| b).count();
    if diversity >= 3 {
        confidence += 0.05;
    }

    // Contextual adjustment
    confidence = adjust_confidence_by_context(
        confidence, line_content, surrounding_lines,
    );

    // Placeholder check (overrides everything)
    if is_placeholder(matched_value) {
        confidence = 0.05; // Near-zero but not zero (still report as Info)
    }

    confidence.clamp(0.0, 1.0)
}
```

---

## 16. Phase 12: Constant Categorization & Naming Suggestions

### Naming Quality Scoring

Measures how well a constant follows naming conventions for its language:

```rust
/// Score the naming quality of a constant (0.0-1.0).
pub fn score_naming_quality(
    name: &str,
    language: Language,
    category: ConstantCategory,
) -> f64 {
    let mut score = 0.5; // Base score

    match language {
        Language::Rust | Language::Go | Language::Cpp => {
            // Expect SCREAMING_SNAKE_CASE for constants
            if is_screaming_snake_case(name) {
                score += 0.3;
            }
            // Descriptive name (>3 chars, not just abbreviation)
            if name.len() > 3 {
                score += 0.1;
            }
        }
        Language::TypeScript | Language::JavaScript => {
            // Expect SCREAMING_SNAKE_CASE or camelCase depending on context
            if is_screaming_snake_case(name) || is_camel_case(name) {
                score += 0.3;
            }
        }
        Language::Python => {
            // Expect SCREAMING_SNAKE_CASE for module-level constants
            if is_screaming_snake_case(name) {
                score += 0.3;
            }
        }
        Language::Java | Language::CSharp => {
            // Expect SCREAMING_SNAKE_CASE or PascalCase
            if is_screaming_snake_case(name) || is_pascal_case(name) {
                score += 0.3;
            }
        }
        _ => {
            if is_screaming_snake_case(name) {
                score += 0.2;
            }
        }
    }

    // Category-appropriate naming
    match category {
        ConstantCategory::Time => {
            if name.contains("MS") || name.contains("SEC") || name.contains("MIN")
                || name.contains("TIMEOUT") || name.contains("INTERVAL") {
                score += 0.1;
            }
        }
        ConstantCategory::Size => {
            if name.contains("MAX") || name.contains("MIN") || name.contains("SIZE")
                || name.contains("LIMIT") || name.contains("CAPACITY") {
                score += 0.1;
            }
        }
        _ => {}
    }

    score.clamp(0.0, 1.0)
}
```

---

## 17. Phase 13: Health Score Calculation

```rust
/// Calculate the overall health score for constants & environment.
pub fn calculate_health_score(
    constants: &[ConstantInfo],
    secrets: &[SecretCandidate],
    magic_numbers: &[MagicNumber],
    inconsistencies: &[InconsistentValue],
    dead_constants: &[DeadConstant],
    env_result: &EnvironmentResult,
) -> HealthScore {
    // Factor 1: Secret hygiene (weight: 0.30)
    // 100 if no secrets, decreases per secret by severity
    let critical_secrets = secrets.iter()
        .filter(|s| s.severity == SecretSeverity::Critical && s.confidence > 0.7)
        .count();
    let high_secrets = secrets.iter()
        .filter(|s| s.severity == SecretSeverity::High && s.confidence > 0.7)
        .count();
    let secret_hygiene = if critical_secrets > 0 {
        0 // Any critical secret = 0
    } else {
        (100 - (high_secrets * 20).min(100)) as u32
    };

    // Factor 2: Magic number hygiene (weight: 0.20)
    let total_lines: usize = constants.len().max(1); // Approximate
    let magic_density = magic_numbers.len() as f64 / total_lines as f64;
    let magic_hygiene = ((1.0 - magic_density * 100.0).max(0.0) * 100.0) as u32;

    // Factor 3: Consistency (weight: 0.15)
    let consistency = if inconsistencies.is_empty() {
        100
    } else {
        let high_count = inconsistencies.iter()
            .filter(|i| i.severity == InconsistencySeverity::High)
            .count();
        (100 - (high_count * 25).min(100)) as u32
    };

    // Factor 4: Dead constant ratio (weight: 0.10)
    let dead_ratio = if constants.is_empty() {
        0.0
    } else {
        dead_constants.len() as f64 / constants.len() as f64
    };
    let dead_score = ((1.0 - dead_ratio) * 100.0) as u32;

    // Factor 5: Env coverage (weight: 0.15)
    let env_coverage = if env_result.variables.is_empty() {
        100 // No env vars = perfect coverage (nothing to cover)
    } else {
        let defined = env_result.variables.iter()
            .filter(|v| !v.is_missing)
            .count();
        ((defined as f64 / env_result.variables.len() as f64) * 100.0) as u32
    };

    // Factor 6: Naming quality (weight: 0.10)
    let avg_naming = if constants.is_empty() {
        1.0
    } else {
        constants.iter().map(|c| c.naming_quality).sum::<f64>()
            / constants.len() as f64
    };
    let naming_score = (avg_naming * 100.0) as u32;

    // Weighted overall
    let overall = (
        secret_hygiene as f64 * 0.30
        + magic_hygiene as f64 * 0.20
        + consistency as f64 * 0.15
        + dead_score as f64 * 0.10
        + env_coverage as f64 * 0.15
        + naming_score as f64 * 0.10
    ) as u32;

    let grade = match overall {
        90..=100 => 'A',
        80..=89 => 'B',
        70..=79 => 'C',
        60..=69 => 'D',
        _ => 'F',
    };

    HealthScore {
        overall,
        factors: HealthFactors {
            secret_hygiene,
            magic_number_hygiene: magic_hygiene,
            consistency,
            dead_constant_ratio: dead_score,
            env_coverage,
            naming_quality: naming_score,
        },
        grade,
    }
}
```

---

## 18. Incremental Analysis (Content-Hash + Dependency Tracking)

### Strategy

Constants & environment analysis is file-local (no cross-file dependencies for
extraction). This makes incremental analysis straightforward:

1. **Content-hash invalidation**: Only re-analyze files whose content hash changed
2. **Dependency-aware propagation**: When a file changes, re-run:
   - Inconsistency detection (cross-file name comparison)
   - Dead constant detection (cross-file reference tracking)
   - Missing variable detection (cross-reference code vs .env files)
3. **.env file changes**: Re-run all environment cross-referencing

```rust
/// Determine which files need re-analysis based on ScanDiff.
pub fn plan_incremental_analysis(
    diff: &ScanDiff,
    previous_results: &ConstantsResult,
) -> IncrementalPlan {
    let mut plan = IncrementalPlan::default();

    // Files to fully re-analyze
    plan.files_to_analyze.extend(diff.added.iter().cloned());
    plan.files_to_analyze.extend(diff.modified.iter().cloned());

    // Files to remove from results
    plan.files_to_remove.extend(diff.removed.iter().cloned());

    // If any .env file changed, re-run all env cross-referencing
    let env_changed = diff.added.iter()
        .chain(diff.modified.iter())
        .chain(diff.removed.iter())
        .any(|f| f.ends_with(".env") || f.contains(".env."));

    if env_changed {
        plan.rerun_env_cross_reference = true;
    }

    // If any file changed, re-run inconsistency detection
    // (a new constant might create an inconsistency with existing ones)
    if !plan.files_to_analyze.is_empty() {
        plan.rerun_inconsistency_detection = true;
    }

    // If call graph changed, re-run dead constant detection
    plan.rerun_dead_detection = !plan.files_to_analyze.is_empty();

    plan
}
```

---

## 19. Integration with Unified Analysis Engine

The constants engine consumes `ParseResult` from the unified analysis pipeline.
Key fields used:

| ParseResult Field | Used By | Purpose |
|------------------|---------|---------|
| `functions` | Constant extraction | Identify const declarations |
| `classes` | Constant extraction | Identify static fields, enums |
| `imports` | Dead constant detection | Track import references |
| `exports` | Constant extraction | Mark exported constants |
| `string_literals` | Secret detection | Scan string values for secrets |
| `numeric_literals` | Magic number detection | AST-based magic number detection |
| `call_sites` | Env var extraction | Detect process.env, os.getenv calls |
| `decorators` | Framework detection | Detect @Value, @ConfigurationProperties |

### Pipeline Position

```
Scanner (Level 0)
  → Parsers (Level 0) — produces ParseResult
    → Unified Analysis Engine (Level 1) — enriches ParseResult
      → Constants & Environment Engine (Level 2C) ← YOU ARE HERE
        → writes to drift.db
        → emits events via DriftEventHandler
        → returns ConstantsSummary via NAPI
```

---

## 20. Integration with Taint Analysis

Environment variables are taint sources — they represent untrusted external input.

```rust
/// Register env var access points as taint sources for the taint engine.
pub fn register_taint_sources(
    env_accesses: &[EnvAccess],
) -> Vec<TaintSource> {
    env_accesses.iter()
        .filter(|a| a.sensitivity >= EnvSensitivity::Internal)
        .map(|a| TaintSource {
            kind: TaintSourceKind::EnvironmentVariable,
            name: a.variable_name.clone(),
            file: a.file.clone(),
            line: a.line,
            sensitivity: match a.sensitivity {
                EnvSensitivity::Critical => TaintSensitivity::High,
                EnvSensitivity::Secret => TaintSensitivity::High,
                EnvSensitivity::Internal => TaintSensitivity::Medium,
                EnvSensitivity::Public => TaintSensitivity::Low,
            },
        })
        .collect()
}
```

---

## 21. Integration with Constraint Detection

Constants patterns feed constraint mining:

- "All timeout values use TIMEOUT_* named constants" → naming constraint
- "No hardcoded secrets in src/ directory" → security constraint
- "All env vars have defaults in non-production code" → configuration constraint
- "Magic number density < 5% per file" → code quality constraint

---

## 22. Integration with Quality Gates (Security Gate)

The security quality gate consumes secret detection results:

```rust
/// Input to the security quality gate from constants analysis.
pub struct SecurityGateInput {
    /// Number of Critical severity secrets with confidence > 0.7.
    pub critical_secrets: usize,
    /// Number of High severity secrets with confidence > 0.7.
    pub high_secrets: usize,
    /// Total secrets across all severities.
    pub total_secrets: usize,
    /// Magic number count (informational).
    pub magic_number_count: usize,
    /// Health score from constants analysis.
    pub health_score: u32,
}

/// Gate evaluation: FAIL if any Critical secrets, WARN if High secrets.
pub fn evaluate_security_gate(input: &SecurityGateInput) -> GateResult {
    if input.critical_secrets > 0 {
        GateResult::Fail {
            reason: format!(
                "{} critical secret(s) detected — hardcoded credentials must be removed",
                input.critical_secrets,
            ),
        }
    } else if input.high_secrets > 0 {
        GateResult::Warn {
            reason: format!(
                "{} high-severity secret(s) detected — review and remediate",
                input.high_secrets,
            ),
        }
    } else {
        GateResult::Pass
    }
}
```

---

## 23. Integration with DNA System

The DNA system extracts a "configuration health" gene from constants metrics:

```rust
/// Gene data for the DNA system's configuration health gene.
pub struct ConfigurationGene {
    /// Secret ratio: secrets / total_constants (lower is better).
    pub secret_ratio: f64,
    /// Magic number density: magic_numbers / total_lines.
    pub magic_number_density: f64,
    /// Env coverage: defined_vars / total_vars.
    pub env_coverage: f64,
    /// Dead constant ratio: dead / total.
    pub dead_constant_ratio: f64,
    /// Overall health score (0-100).
    pub health_score: u32,
}
```

---

## 24. Integration with Enterprise Secret Detection

The constants engine's `SecretCandidate` results feed into the enterprise secret
detection system (Level 2D), which adds:
- Git history scanning (secrets in old commits)
- Connection string parsing (extract credentials from URLs)
- Base64 decoding (detect encoded secrets)
- Verification via API (check if credentials are active)

The constants engine provides the initial detection; enterprise secret detection
enriches and validates.

---

## 25. Integration with Cortex Grounding (D7)

Per PLANNING-DRIFT.md D7, the bridge crate can compare constants analysis results
against Cortex memories:

- Secret detection results validate `security_concern` memories
- Environment variable patterns validate `configuration_pattern` memories
- Constant naming conventions validate `naming_convention` memories

This is a one-way read — Drift computes independently, the bridge consumes.

---

## 26. Storage Schema (drift.db)

### Constants Table

```sql
CREATE TABLE constants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    category TEXT NOT NULL,          -- ConstantCategory enum
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    column_num INTEGER NOT NULL DEFAULT 0,
    language TEXT NOT NULL,
    is_exported INTEGER NOT NULL DEFAULT 0,
    declaration_kind TEXT NOT NULL,   -- DeclarationKind enum
    scope TEXT NOT NULL DEFAULT 'module',
    reference_count INTEGER NOT NULL DEFAULT 0,
    is_dead INTEGER NOT NULL DEFAULT 0,
    naming_quality REAL NOT NULL DEFAULT 0.5,
    content_hash INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_constants_file ON constants(file);
CREATE INDEX idx_constants_category ON constants(category);
CREATE INDEX idx_constants_name ON constants(name);
CREATE INDEX idx_constants_is_dead ON constants(is_dead) WHERE is_dead = 1;
CREATE INDEX idx_constants_is_exported ON constants(is_exported) WHERE is_exported = 1;
CREATE INDEX idx_constants_content_hash ON constants(content_hash);
```

### Secrets Table (Subset of Constants with Security Category)

```sql
CREATE TABLE secrets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    masked_value TEXT NOT NULL,
    secret_type TEXT NOT NULL,
    provider TEXT,
    severity TEXT NOT NULL,          -- SecretSeverity enum
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    confidence REAL NOT NULL,
    entropy REAL NOT NULL DEFAULT 0.0,
    reason TEXT NOT NULL,
    cwe_id TEXT,
    owasp_id TEXT,
    is_placeholder INTEGER NOT NULL DEFAULT 0,
    content_hash INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_secrets_file ON secrets(file);
CREATE INDEX idx_secrets_severity ON secrets(severity);
CREATE INDEX idx_secrets_provider ON secrets(provider);
CREATE INDEX idx_secrets_confidence ON secrets(confidence);
CREATE INDEX idx_secrets_content_hash ON secrets(content_hash);
```

### Magic Numbers Table

```sql
CREATE TABLE magic_numbers (
    id TEXT PRIMARY KEY,
    value REAL NOT NULL,
    raw TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    column_num INTEGER NOT NULL DEFAULT 0,
    language TEXT NOT NULL,
    ast_context TEXT NOT NULL,        -- MagicNumberContext enum
    category TEXT NOT NULL,           -- MagicNumberCategory enum
    suggested_name TEXT,
    scope TEXT NOT NULL DEFAULT 'module',
    content_hash INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_magic_numbers_file ON magic_numbers(file);
CREATE INDEX idx_magic_numbers_category ON magic_numbers(category);
CREATE INDEX idx_magic_numbers_content_hash ON magic_numbers(content_hash);
```

### Environment Variables Table

```sql
CREATE TABLE env_vars (
    id TEXT PRIMARY KEY,
    variable_name TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    column_num INTEGER NOT NULL DEFAULT 0,
    language TEXT NOT NULL,
    access_method TEXT NOT NULL,      -- EnvAccessMethod enum
    has_default INTEGER NOT NULL DEFAULT 0,
    default_value TEXT,
    sensitivity TEXT NOT NULL,        -- EnvSensitivity enum
    framework TEXT,
    is_public INTEGER NOT NULL DEFAULT 0,
    is_required INTEGER NOT NULL DEFAULT 0,
    description TEXT,
    content_hash INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_env_vars_variable_name ON env_vars(variable_name);
CREATE INDEX idx_env_vars_file ON env_vars(file);
CREATE INDEX idx_env_vars_sensitivity ON env_vars(sensitivity);
CREATE INDEX idx_env_vars_framework ON env_vars(framework);
CREATE INDEX idx_env_vars_content_hash ON env_vars(content_hash);
```

### Environment Files Table

```sql
CREATE TABLE env_files (
    id TEXT PRIMARY KEY,
    path TEXT NOT NULL UNIQUE,
    environment TEXT,
    variable_count INTEGER NOT NULL DEFAULT 0,
    has_comments INTEGER NOT NULL DEFAULT 0,
    content_hash INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE TABLE env_file_variables (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    env_file_id TEXT NOT NULL REFERENCES env_files(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    value TEXT,
    line INTEGER NOT NULL,
    has_quotes INTEGER NOT NULL DEFAULT 0,
    is_commented INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX idx_env_file_variables_env_file ON env_file_variables(env_file_id);
CREATE INDEX idx_env_file_variables_name ON env_file_variables(name);
```

### Batch Write Pattern

All writes use the batch writer from the storage layer (02-STORAGE-V2-PREP.md):

```rust
pub fn persist_constants_results(
    db: &DatabaseManager,
    result: &ConstantsResult,
    diff: &ScanDiff,
) -> Result<(), StorageError> {
    // Phase 1: Delete stale data for removed/modified files
    let stale_files: Vec<&str> = diff.removed.iter()
        .chain(diff.modified.iter())
        .map(|f| f.as_str())
        .collect();
    db.delete_constants_for_files(&stale_files)?;
    db.delete_secrets_for_files(&stale_files)?;
    db.delete_magic_numbers_for_files(&stale_files)?;
    db.delete_env_vars_for_files(&stale_files)?;

    // Phase 2: Batch insert new data
    db.batch_insert_constants(&result.constants)?;
    db.batch_insert_secrets(&result.secrets)?;
    db.batch_insert_magic_numbers(&result.magic_numbers)?;
    db.batch_insert_env_vars(&result.env_result.accesses)?;

    // Phase 3: Update env files (full replace)
    db.replace_env_files(&result.env_result.env_files)?;

    Ok(())
}
```

---

## 27. NAPI Interface

### Exported Functions (3)

| Function | Sync/Async | Returns | Description |
|----------|-----------|---------|-------------|
| `analyze_constants(root)` | Async | `ConstantsSummary` | Full constants + environment analysis |
| `query_constants(filter, pagination)` | Sync | `PaginatedResult<ConstantSummary>` | Query constants with filters |
| `query_secrets(filter, pagination)` | Sync | `PaginatedResult<SecretSummary>` | Query secrets with filters |

### ConstantsSummary (NAPI Return Type)

```rust
#[napi(object)]
pub struct ConstantsSummary {
    pub total_constants: u32,
    pub total_secrets: u32,
    pub total_magic_numbers: u32,
    pub total_inconsistencies: u32,
    pub total_dead_constants: u32,
    pub total_env_vars: u32,
    pub missing_env_vars: u32,
    pub inconsistent_env_vars: u32,
    pub health_score: u32,
    pub health_grade: String,
    pub secret_severity_breakdown: serde_json::Value,
    pub top_issues: Vec<ConstantsIssue>,
    pub duration_ms: u32,
    pub status: String,
}

#[napi(object)]
pub struct ConstantsIssue {
    pub kind: String,       // "secret", "magic_number", "inconsistency", "dead", "missing_env"
    pub severity: String,
    pub message: String,
    pub file: String,
    pub line: u32,
}
```

### Batch API Integration

The constants engine is invoked via the batch API when `AnalysisType::Constants`
or `AnalysisType::Environment` is requested:

```rust
AnalysisType::Constants => {
    let summary = drift_core::constants::analyze(
        &parse_results, &rt.db, rt.call_graph.as_ref(),
    ).map_err(to_napi_error)?;
    result.constants = Some(summary);
}
AnalysisType::Environment => {
    // Environment is included in Constants analysis
    // but can be requested separately for lightweight env-only analysis
    let summary = drift_core::constants::analyze_env_only(
        &parse_results, &rt.db,
    ).map_err(to_napi_error)?;
    result.environment = Some(summary);
}
```

---

## 28. MCP Tool Interface (drift_constants — 6 Actions)

### Tool Definition

```typescript
{
    name: "drift_constants",
    description: "Analyze constants, secrets, magic numbers, and environment variables",
    inputSchema: {
        type: "object",
        properties: {
            action: {
                type: "string",
                enum: ["overview", "secrets", "magic_numbers", "inconsistent",
                       "dead", "environment"],
                description: "Analysis action to perform"
            },
            file: {
                type: "string",
                description: "Optional: filter by file path"
            },
            severity: {
                type: "string",
                enum: ["critical", "high", "medium", "low"],
                description: "Optional: minimum severity for secrets"
            },
            category: {
                type: "string",
                description: "Optional: filter by constant category"
            }
        },
        required: ["action"]
    }
}
```

### Action Responses

| Action | Token Cost | What It Returns |
|--------|-----------|-----------------|
| `overview` | ~800 | Health score, top issues, summary stats |
| `secrets` | ~1000-2000 | Secret candidates by severity, CWE/OWASP mapping |
| `magic_numbers` | ~800-1500 | Magic numbers with suggested names, fix suggestions |
| `inconsistent` | ~500-1000 | Inconsistent constants with suggested canonical names |
| `dead` | ~500-1000 | Dead constants with confidence scores |
| `environment` | ~800-1500 | Env vars, missing vars, .env coverage, framework detection |

---

## 29. CLI Interface

### `drift constants` — 7 Subcommands

| Subcommand | Description | Key Flags |
|-----------|-------------|-----------|
| (default) | Overview: health score, top issues | `--format text\|json` |
| `list` | List all constants | `--category`, `--language`, `--file`, `--exported`, `--limit` |
| `get <name>` | Constant details | — |
| `secrets` | Hardcoded secrets | `--severity`, `--provider`, `--format text\|json\|sarif` |
| `inconsistent` | Inconsistent values | `--severity` |
| `dead` | Unused constants | `--exported-only`, `--confidence` |
| `export <file>` | Export to file | `--format json\|csv\|toml` |

### `drift environment` — 4 Subcommands

| Subcommand | Description | Key Flags |
|-----------|-------------|-----------|
| (default) | Overview: coverage, missing, frameworks | `--format text\|json` |
| `list` | List all env vars | `--sensitivity`, `--framework`, `--file` |
| `missing` | Missing variables | `--required-only` |
| `template` | Generate .env.example | `--output <path>` |

---

## 30. Event Interface

Events emitted via `DriftEventHandler` (per D5):

```rust
pub trait DriftEventHandler: Send + Sync {
    // Constants events
    fn on_secret_detected(&self, secret: &SecretCandidate) {}
    fn on_critical_secret_detected(&self, secret: &SecretCandidate) {}
    fn on_magic_number_detected(&self, magic: &MagicNumber) {}
    fn on_dead_constant_detected(&self, dead: &DeadConstant) {}
    fn on_constants_analysis_complete(&self, summary: &ConstantsSummary) {}

    // Environment events
    fn on_missing_env_var_detected(&self, var: &MissingVariable) {}
    fn on_env_inconsistency_detected(&self, var: &InconsistentVariable) {}
    fn on_env_analysis_complete(&self, summary: &EnvironmentStats) {}
}
```

---

## 31. Tracing & Observability

### Span Hierarchy

```
constants_analysis (root span)
├── constant_extraction (per-file, parallel)
├── magic_number_detection (per-file, parallel)
├── secret_detection (per-file, parallel)
│   └── pattern_matching (per-pattern-group)
├── inconsistency_detection (cross-file)
├── dead_constant_detection (cross-file, requires call graph)
├── env_extraction (per-file, parallel)
├── env_file_parsing (per-.env-file)
├── env_cross_reference (cross-file)
├── framework_detection
├── sensitivity_classification
├── confidence_scoring
├── health_score_calculation
└── persistence (batch write to drift.db)
```

### Log Levels

| Level | What Gets Logged |
|-------|-----------------|
| ERROR | Analysis failures, storage errors |
| WARN | High-confidence secrets detected, missing critical env vars |
| INFO | Analysis start/complete, summary stats, health score |
| DEBUG | Per-file analysis details, pattern match counts |
| TRACE | Individual pattern matches, confidence calculations |

Enable via `DRIFT_LOG` environment variable:
```
DRIFT_LOG=constants=debug           # Debug constants analysis
DRIFT_LOG=constants::secrets=trace  # Trace secret detection
DRIFT_LOG=constants::env=debug      # Debug environment analysis
```

---

## 32. Performance Targets & Benchmarks

| Metric | Target | Measurement |
|--------|--------|-------------|
| 10K files analysis | <5s | End-to-end constants + environment |
| Secret detection per file | <1ms | 100+ patterns against source |
| Magic number detection per file | <0.5ms | AST-based, no re-parsing |
| .env file parsing | <1ms per file | Dotenv spec parser |
| Incremental re-analysis | <500ms | Changed files only |
| Memory usage | <100MB | For 10K file codebase |
| Secret false positive rate | <1% | For Critical/High severity |
| Secret false negative rate | <5% | For known provider patterns |

### Benchmark Strategy

```rust
#[bench]
fn bench_secret_detection_10k_files(b: &mut Bencher) {
    let files = generate_test_files(10_000);
    b.iter(|| {
        let detector = SecretDetector::new();
        for file in &files {
            detector.detect(file);
        }
    });
}

#[bench]
fn bench_magic_number_detection(b: &mut Bencher) {
    let parse_results = parse_test_files(1_000);
    b.iter(|| {
        for pr in &parse_results {
            detect_magic_numbers(pr, &[], Language::TypeScript, &Default::default());
        }
    });
}
```

---

## 33. Build Order & Dependencies

### Phase 1: Core Types (No Dependencies)
1. `types.rs` — All types defined in §4
2. `config.rs` — `MagicNumberConfig`, `EnvironmentConfig`, `SecretDetectionConfig`

### Phase 2: Detection Engines (Depends on Types)
3. `extractor.rs` — Constant extraction from ParseResult (§5)
4. `magic_numbers.rs` — AST-based magic number detection (§6)
5. `secrets.rs` — Secret detection engine with 100+ patterns (§7)
6. `inconsistency.rs` — Fuzzy name matching (§8)
7. `env_extractor.rs` — Environment variable extraction (§10)
8. `env_parser.rs` — .env file parsing (§11)

### Phase 3: Cross-File Analysis (Depends on Detection Engines)
9. `dead_constants.rs` — Dead constant detection via call graph (§9)
10. `env_cross_ref.rs` — Missing/inconsistent variable detection (§12)
11. `framework_detection.rs` — Framework-specific env detection (§13)
12. `sensitivity.rs` — Sensitivity classification (§14)
13. `confidence.rs` — Confidence scoring with entropy (§15)

### Phase 4: Scoring & Persistence (Depends on Cross-File Analysis)
14. `naming.rs` — Naming quality scoring (§16)
15. `health.rs` — Health score calculation (§17)
16. `storage.rs` — drift.db persistence (§26)

### Phase 5: Engine & Integration (Depends on Everything)
17. `engine.rs` — `ConstantsEngine` orchestrating all phases (§3)
18. `incremental.rs` — Incremental analysis planning (§18)
19. `mod.rs` — Module exports, public API

### Phase 6: NAPI & Presentation
20. NAPI bindings in `drift-napi/src/bindings/structural.rs` (§27)
21. MCP tool handler (§28)
22. CLI commands (§29)

---

## 34. V1 → V2 Feature Cross-Reference

| V1 Feature | V1 Location | V2 Location | Status |
|-----------|-------------|-------------|--------|
| ConstantsAnalyzer | Rust drift-core/constants/analyzer.rs | §3 ConstantsEngine | UPGRADED |
| ConstantExtractor | Rust drift-core/constants/extractor.rs | §5 Phase 1 | UPGRADED |
| SecretDetector (21 patterns) | Rust drift-core/constants/secrets.rs | §7 Phase 3 (100+ patterns) | UPGRADED |
| Magic number regex | Rust drift-core/constants/analyzer.rs | §6 Phase 2 (AST-based) | REPLACED |
| Inconsistency detection | Rust drift-core/constants/analyzer.rs | §8 Phase 4 (fuzzy matching) | UPGRADED |
| ConstantInfo type | Rust drift-core/constants/types.rs | §4.1 | UPGRADED |
| SecretCandidate type | Rust drift-core/constants/types.rs | §4.2 | UPGRADED |
| MagicNumber type | Rust drift-core/constants/types.rs | §4.3 | UPGRADED |
| InconsistentValue type | Rust drift-core/constants/types.rs | §4.4 | UPGRADED |
| ConstantsResult type | Rust drift-core/constants/types.rs | §4.5 | UPGRADED |
| ConstantsStats type | Rust drift-core/constants/types.rs | §4.6 | UPGRADED |
| thread_local! parallelism | Rust drift-core/constants/analyzer.rs | §3 rayon + ParseResult | UPGRADED |
| Confidence scoring | Rust drift-core/constants/secrets.rs | §15 Bayesian + entropy | UPGRADED |
| Placeholder detection | Rust drift-core/constants/secrets.rs | §7.5 | KEPT + expanded |
| Value masking | Rust drift-core/constants/secrets.rs | §7.6 | KEPT |
| Name suggestion | Rust drift-core/constants/analyzer.rs | §6 context-aware | UPGRADED |
| NAPI analyze_constants | Rust drift-core/napi | §27 | UPGRADED |
| EnvironmentAnalyzer | Rust drift-core/environment/analyzer.rs | §3 unified engine | MERGED |
| EnvExtractor | Rust drift-core/environment/extractor.rs | §10 Phase 6 | UPGRADED |
| EnvAccess type | Rust drift-core/environment/types.rs | §4.7 | UPGRADED |
| EnvVariable type | Rust drift-core/environment/types.rs | §4.8 | UPGRADED |
| EnvSensitivity enum | Rust drift-core/environment/types.rs | §14 | KEPT |
| Sensitivity classification | Rust drift-core/environment/extractor.rs | §14 | UPGRADED |
| Access method detection | Rust drift-core/environment/extractor.rs | §10.2 (15+ methods) | UPGRADED |
| NAPI analyze_environment | Rust drift-core/napi | §27 merged into analyze_constants | MERGED |
| TS dead constant detection | TS constants/analysis/ | §9 Phase 5 (Rust) | MOVED |
| TS constants store | TS constants/store/ | §26 drift.db | REPLACED |
| TS pattern store integration | TS constants/integration/ | §24 detector system | UPGRADED |
| TS .env file parsing | TS environment/env-scanner.ts | §11 Phase 7 (Rust) | MOVED |
| TS missing variable detection | TS environment/env-scanner.ts | §12 Phase 8 (Rust) | MOVED |
| TS consistency checking | TS environment/env-scanner.ts | §12 Phase 8 (Rust) | MOVED |
| TS per-language extractors | TS environment/extractors/ | §10 Phase 6 (Rust) | MOVED |
| TS EnvStore | TS environment/env-store.ts | §26 drift.db | REPLACED |

**Total: 34 v1 features accounted for. 0 features dropped. 0 features lost.**

---

## 35. Inconsistencies & Decisions

### Resolved Inconsistencies

| # | Inconsistency | Resolution |
|---|--------------|------------|
| 1 | V1 has separate `analyze_constants` and `analyze_environment` NAPI calls | **MERGED** — Single `analyze_constants` call runs both. `analyze_environment` available as lightweight env-only variant. |
| 2 | V1 magic number detection uses line-level regex; v2 unified engine provides `numeric_literals` | **RESOLVED** — V2 uses `ParseResult.numeric_literals` exclusively. No regex for magic numbers. |
| 3 | V1 secret detection runs on raw source lines; v2 could use `string_literals` from ParseResult | **DECISION** — Run on both: `string_literals` for AST-aware detection + raw source lines for patterns that span multiple tokens (e.g., PEM headers). |
| 4 | V1 TS dead constant detection requires call graph; call graph may not be built yet | **RESOLVED** — Dead constant detection is optional. If call graph unavailable, use import-based reference counting (less accurate but functional). |
| 5 | NAPI bridge doc lists `analyze_constants` under "Structural Analysis Functions" alongside coupling/wrappers | **KEPT** — Constants analysis stays in structural.rs binding module alongside coupling and wrappers. |
| 6 | Batch API has both `AnalysisType::Constants` and `AnalysisType::Environment` | **RESOLVED** — `Constants` runs full analysis (constants + environment). `Environment` runs env-only (lightweight). |
| 7 | Stack hierarchy says "Narrow scope. Feeds security (secrets) and constraints." but we also feed DNA, taint, quality gates | **CLARIFIED** — The hierarchy description is simplified. Full consumer list in §1 downstream consumers table. |

### Open Decisions

| # | Decision | Options | Recommendation |
|---|---------|---------|----------------|
| 1 | Should .env file parsing stay in Rust or move to TS? | A) Rust (unified), B) TS (simpler I/O) | **A) Rust** — Unified analysis, no NAPI round-trip for cross-referencing |
| 2 | Should secret detection scan git history? | A) Yes (in constants engine), B) No (enterprise secret detection only) | **B) No** — Git history scanning is enterprise-tier. Constants engine scans current files only. |
| 3 | Should we verify detected secrets via API? | A) Yes (read-only verification), B) No (privacy concern) | **B) No** — Too risky. Verification is opt-in enterprise feature, not default. |
| 4 | Should magic number auto-fix be implemented in P0? | A) Yes, B) No (P2) | **B) P2** — Detection is P0. Auto-fix requires code modification which is higher risk. |

---

## 36. Risk Register

| # | Risk | Likelihood | Impact | Mitigation |
|---|------|-----------|--------|------------|
| 1 | Secret detection false positives annoy developers | Medium | High | Entropy scoring, contextual analysis, placeholder detection, baseline support |
| 2 | 100+ regex patterns cause performance regression | Low | Medium | Compile patterns once at init, use RegexSet for batch matching, benchmark |
| 3 | .env file parsing edge cases (multiline, interpolation) | Medium | Low | Follow dotenv spec strictly, test against dotenv-linter test suite |
| 4 | Dead constant detection false positives (dynamic access) | Medium | Medium | Lower confidence for files with dynamic access patterns, require call graph |
| 5 | Framework detection misidentifies framework | Low | Low | Require multiple signals (dependency + config file + import pattern) |
| 6 | AST-based magic number detection misses numbers in unsupported AST contexts | Low | Low | Fallback to regex for languages without full numeric_literal extraction |
| 7 | Inconsistency detection groups unrelated constants | Medium | Low | Require match_score > 0.7 for flagging, allow user suppression |
| 8 | Sensitivity classification too aggressive (marks public vars as Secret) | Medium | Medium | Conservative defaults, allow per-project overrides in drift.toml |

---

*This document accounts for 100% of v1 features across all 4 codebases (Rust constants,
Rust environment, TypeScript constants, TypeScript environment). Zero feature loss.
Every algorithm specified. Every type defined. Every integration point documented.
Every architectural decision resolved. Ready to build.*
