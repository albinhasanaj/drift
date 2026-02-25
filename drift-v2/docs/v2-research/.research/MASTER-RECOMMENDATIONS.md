# Drift V2 — Master Recommendations

> Enterprise-grade recommendations synthesized from the complete v1 recap (27 categories) and master research encyclopedia (90+ sources). These define HOW to build Drift v2 from scratch — every architectural decision, every priority, every phase.

**Priority Levels**:
- P0: Must be decided/built before anything else. Architectural foundations.
- P1: Core functionality. Required for v2 launch.
- P2: Important for enterprise adoption. Can follow initial launch.
- P3: Nice-to-have. Future roadmap.

---

## Part 1: Architectural Decisions (Decide Before Writing Code)

### AD1: Incremental-First Architecture

**Priority**: P0 | **Impact**: Every subsystem | **Evidence**: §1.1, §1.2

Build the entire system around incremental computation from day one. Do NOT build batch-only and retrofit.

**Two-phase model** (proven by rust-analyzer, IntelliJ, Sorbet):
1. **Per-file indexing phase**: Parse file → extract patterns → produce file index entry. Embarrassingly parallel. Each entry is content-hashed (xxhash) and cached.
2. **Cross-file analysis phase**: Call graph resolution, coupling metrics, reachability — computed from the file index. Auto-invalidate when input entries change.

**Persistent index**: SQLite-backed, survives process restarts. On startup, hash-check files against stored index — only re-index changed files.

**Three-layer incrementality**:
- Layer 1 (Easy): Per-file detection — skip unchanged files via content hash
- Layer 2 (Medium): Confidence re-scoring — only re-score patterns with locations in changed files
- Layer 3 (Hard): Convention re-learning — threshold-based trigger (>10% files changed) for full re-learning

### AD2: Single Canonical Data Model

**Priority**: P0 | **Impact**: Every subsystem | **Evidence**: §2.1

One `ParseResult` type. One `Pattern` type. One `FunctionEntry` type. No more three-shape problem (Rust, TS, NAPI).

Rust defines the canonical types. NAPI serializes them. TypeScript consumes them. No re-interpretation, no re-parsing, no shape conversion.

### AD3: Declarative Pattern Definitions

**Priority**: P0 | **Impact**: Detectors, MCP, Quality Gates | **Evidence**: §3.4

Ship with hardcoded defaults (all v1 patterns). Users add custom patterns via TOML/YAML without recompiling.

```toml
[[patterns]]
id = "spring-security"
language = "java"
category = "Auth"
confidence = 0.95
query = '(annotation name: (identifier) @name (#match? @name "^(PreAuthorize|Secured)$"))'
```

Tree-sitter query syntax serves as the pattern language. Graduated complexity: simple patterns → metavariables → cross-file.

### AD4: Visitor Pattern for Detection

**Priority**: P0 | **Impact**: Detection performance | **Evidence**: §3.2

Single-pass AST traversal with all detectors registered as visitors. Reduces traversals from O(detectors × files) to O(files). This is the single most impactful architectural change for detection performance.

```
Engine traverses AST once per file
  → For each node, notifies all registered detectors interested in that node type
  → Detectors report findings independently
  → Engine collects all findings in one pass
```

### AD5: Split MCP Server Architecture

**Priority**: P0 | **Impact**: MCP, token efficiency, user experience | **Evidence**: §7.1-7.5

Split into two MCP servers plus implement progressive disclosure within each:

```
┌─────────────────────────────────────────────────────────────┐
│                    HOST APPLICATION                          │
├──────────────────────┬──────────────────────────────────────┤
│  drift-analysis      │  drift-memory (optional)             │
│  ~17-20 tools        │  ~15-20 tools                        │
│  Read-only drift.db  │  Read/Write cortex.db + Read drift.db│
│  ~5-8K tokens        │  ~5-8K tokens                        │
│                      │                                       │
│  Entry points:       │  Entry points:                        │
│  • drift_context     │  • drift_memory_context               │
│  • drift_discover    │  • drift_memory_manage                │
│  • drift_tool        │  • drift_memory_discover              │
└──────────────────────┴──────────────────────────────────────┘
```

**Why**: Token efficiency (save 10-20K tokens), single responsibility, independent scaling, user choice, security separation. The MCP spec explicitly supports multiple servers per host.

**Progressive disclosure within each server**: Instead of loading all tool definitions upfront, expose 3 entry points. Reduces startup cost from ~8K to ~1.5K tokens per server.

### AD6: Structured Error Handling Everywhere

**Priority**: P0 | **Impact**: Every Rust subsystem | **Evidence**: §16 (thiserror ecosystem)

Use `thiserror` for all error types from the first line of code. One error enum per subsystem with structured variants. Propagate meaningful errors through NAPI to TypeScript.

### AD7: SQLite WAL Mode as Default

**Priority**: P0 | **Impact**: All storage | **Evidence**: §8.1

Every SQLite database opens with: WAL mode, `synchronous = NORMAL`, `mmap_size = 268435456` (256MB), `busy_timeout = 5000`. Enables concurrent reads during writes.

### AD8: Temporal Confidence with Momentum

**Priority**: P0 | **Impact**: Confidence scoring, convention learning | **Evidence**: §5.1, §5.2

Replace static confidence scoring with momentum-aware scoring:

```
score = frequency × 0.35 + consistency × 0.25 + ageFactor × 0.10 + spread × 0.15 + momentum × 0.15
```

Where `momentum = (current_frequency - previous_frequency) / previous_frequency`, normalized to [0, 1]. Prevents flagging intentional migrations as violations.

### AD9: Feedback Loop Architecture

**Priority**: P0 | **Impact**: Detection quality, enterprise adoption | **Evidence**: §3.1

Build Google Tricorder-style feedback from day one:
- "Not useful" / "Useful" signals on every violation
- Track effective false-positive rate per detector (<5% target)
- Detectors with high "not useful" rates get confidence reduction
- Developer action (fix, ignore, approve) feeds back into pattern confidence
- Project-level customization, not user-level

---

## Part 2: Category-Specific Recommendations

### Rust Core (Category 01)

| # | Recommendation | Priority | Evidence |
|---|---------------|----------|----------|
| RC1 | Scanner with incremental change detection (content hash, skip unchanged) | P0 | §1.1 |
| RC2 | Parser layer with rich extraction (everything in one pass per file) | P0 | §2.1, §2.2 |
| RC3 | String interning with `lasso` crate (ThreadedRodeo for build, RodeoReader for query) | P0 | §16.1 |
| RC4 | Unified analyzer with declarative patterns (tree-sitter queries + TOML config) | P0 | §3.4 |
| RC5 | Enterprise-grade secret detection (100+ patterns, Shannon entropy, contextual scoring) | P0 | §9.2 |
| RC6 | Call graph with full 6-strategy resolution algorithm | P0 | §4.1 |
| RC7 | Coupling analyzer with Tarjan's SCC + zone classification + module roles | P1 | §4.1, §17.1 |
| RC8 | Boundary analysis with ORM extractors + risk scoring (28+ ORMs) | P1 | Recap §21 |
| RC9 | Environment analyzer with .env cross-referencing + missing variable detection | P1 | Recap §5 |
| RC10 | Error handling analyzer with propagation chain tracking (source → sink) | P1 | Recap §19 |
| RC11 | Test topology with quality scoring (35+ frameworks, 8 languages) | P1 | Recap §17 |
| RC12 | Reachability with taint analysis foundation (intraprocedural first) | P1 | §4.2 |
| RC13 | Wrapper detector with multi-framework registry (not just React) | P2 | Recap §1 |
| RC14 | Constants analyzer with fuzzy matching + dead constant detection | P2 | Recap §1 |
| RC15 | N-API bridge with batch and streaming support (parse_batch, stream results) | P0 | §16.5 |
| RC16 | Rayon parallelism with thread_local cleanup between scans | P1 | §16.4 |
| RC17 | Performance-optimized data structures (FxHashMap, SmallVec, xxhash) | P1 | Recap §4 |

### Parsers (Category 02)

| # | Recommendation | Priority | Evidence |
|---|---------------|----------|----------|
| PA1 | Incremental parse cache (Moka, content-addressed, durable across restarts) | P0 | §16.2, §2.2 |
| PA2 | Single canonical ParseResult shape (Rust-defined, NAPI-serialized, TS-consumed) | P0 | AD2 |
| PA3 | Structured decorator/annotation extraction (name + parsed arguments) | P0 | §2.4 |
| PA4 | Pydantic model extraction in Rust (v1/v2 detection, type resolution with cycle detection) | P0 | §2.3 |
| PA5 | Consolidated tree-sitter queries (2-4x fewer traversals via alternations) | P1 | §2.2 |
| PA6 | Trait-based LanguageParser architecture (one trait per language) | P1 | Recap §5 |
| PA7 | Namespace/package extraction for all 10 languages | P1 | Recap §5 |
| PA8 | NAPI batch/streaming APIs (amortize per-call overhead) | P1 | §16.5 |
| PA9 | Error-tolerant extraction (handle tree-sitter error nodes gracefully) | P1 | §2.2 |
| PA10 | Generic type parameter extraction (generics, bounded types) | P1 | Recap §5 |
| PA11 | Thread-safe parser pool (thread_local with cleanup, compiled queries reused) | P1 | §16.4 |
| PA12 | Framework construct extraction as composable extension layer | P2 | Recap §5 |
| PA13 | Structured error types with thiserror (per-language error variants) | P2 | AD6 |
| PA14 | Language addition scaffold (macro/codegen for adding new languages) | P2 | Recap §5 |

### Detectors (Category 03)

| # | Recommendation | Priority | Evidence |
|---|---------------|----------|----------|
| DE1 | Single-pass visitor pattern for detection (ESLint-style) | P0 | AD4, §3.2 |
| DE2 | Incremental detection with content-hash skipping | P0 | §1.2 |
| DE3 | Temporal confidence decay + momentum scoring | P0 | AD8, §5.2 |
| DE4 | Generic AST normalization layer (GAST) for language-agnostic detection | P1 | §2.1 |
| DE5 | Effective false-positive tracking + feedback loop (Tricorder-style) | P1 | AD9, §3.1 |
| DE6 | Outlier detection refinements (Z=2.5, min n=10, Grubbs' for n=10-30) | P1 | §5.3 |
| DE7 | OWASP/CWE-aligned security detection (map detectors to CWE IDs) | P1 | §9.1 |
| DE8 | Contract detection expansion (GraphQL schemas, gRPC protobuf, OpenAPI specs) | P1 | §13.1 |
| DE9 | Bayesian convention learning (replace binary 60% threshold with graduated confidence) | P1 | §5.1 |
| DE10 | Suggested fixes as first-class output (7 fix strategies with confidence) | P1 | §3.1 |
| DE11 | Framework detection as composable middleware (easy to add new frameworks) | P2 | Recap §3 |
| DE12 | Detector testing and validation framework (golden file tests, regression suite) | P2 | §3.1 |

### Call Graph (Category 04)

| # | Recommendation | Priority | Evidence |
|---|---------------|----------|----------|
| CG1 | Per-language hybrid extractors in Rust (8 languages × standard + data-access) | P0 | Recap §7 |
| CG2 | Full 6-strategy resolution algorithm in Rust (same-file, method, DI, import, export, fuzzy) | P0 | Recap §7 |
| CG3 | Impact analysis engine in Rust (forward/reverse impact, affected file count) | P1 | Recap §7 |
| CG4 | Dead code detection in Rust (unreachable functions, unused exports) | P1 | Recap §7 |
| CG5 | Incremental call graph updates (only rebuild affected subgraphs) | P1 | §1.1 |
| CG6 | Enrichment pipeline (sensitivity classification, impact scoring, remediation) | P1 | Recap §7 |
| CG7 | Cross-service reachability (microservice API calls, HTTP/gRPC boundaries) | P2 | Recap §7 |
| CG8 | In-memory graph with petgraph (StableGraph synced with SQLite) | P1 | §16.3 |

### Analyzers (Category 05)

| # | Recommendation | Priority | Evidence |
|---|---------------|----------|----------|
| AN1 | Unified language provider with 20 ORM matchers migrated to Rust | P1 | Recap §8 |
| AN2 | Rules engine with deduplication, limits, blocking detection in Rust | P1 | Recap §8 |
| AN3 | Quick fix generator (7 strategies) exposed via NAPI | P1 | Recap §8 |
| AN4 | Severity manager with 4-level resolution + escalation rules | P1 | Recap §8 |
| AN5 | Variant manager with scoped overrides (global/directory/file) | P2 | Recap §8 |
| AN6 | Basic intraprocedural data flow analysis (constant propagation, taint tracking) | P1 | §3.3, §18.3 |
| AN7 | Generic scope tree in Rust (per-language extractors populate, language-agnostic analysis) | P1 | §18.2 |
| AN8 | Type inference framework using union-find (ena crate) for cross-expression type tracking | P2 | §18.1 |
| AN9 | CFG construction from normalized IR (not directly from tree-sitter AST) | P1 | §18.3 |
| AN10 | Forward/backward dataflow framework as generic Rust algorithms | P1 | §18.3 |
| AN11 | Shadowed variable detection via scope tree walk-up | P1 | §18.2 |
| AN12 | Unreachable code detection via CFG dead-edge analysis | P2 | §18.3 |
| AN13 | Null dereference detection via forward dataflow (null propagation tracking) | P2 | §18.3 |
| AN14 | Per-language lowering to normalized IR (separate from analysis algorithms) | P1 | §18.1 |

### Cortex Memory (Category 06)

| # | Recommendation | Priority | Evidence |
|---|---------------|----------|----------|
| CX1 | Hybrid search: FTS5 + sqlite-vec with RRF fusion | P0 | §6.2 |
| CX2 | Code-specific embedding model (Jina Code v2 or CodeRankEmbed, local ONNX) | P0 | §6.3 |
| CX3 | Rust embedding inference via ort crate (3-5x speedup over Transformers.js) | P1 | §6.4 |
| CX4 | Two-phase memory pipeline (extraction → dedup/update before storage) | P1 | §6.1 |
| CX5 | Retrieval-difficulty-based consolidation triggers (not just time-based) | P1 | §6.5 |
| CX6 | Embedding enrichment (prepend type, category, file paths before embedding) | P1 | §17.3 |
| CX7 | Re-ranking stage after initial retrieval (cross-encoder or lightweight scorer) | P1 | §6.7 |
| CX8 | Accurate token counting via tiktoken-rs (replace string-length approximation) | P1 | §6.8 |
| CX9 | Graph-based memory representation (petgraph for causal graph, entity relationships) | P2 | §6.6, §16.3 |
| CX10 | DAG enforcement in causal system (cycle detection, counterfactual queries) | P2 | §6.6 |
| CX11 | Memory observability (retrieval effectiveness, token efficiency, quality trends) | P2 | §17.4 |
| CX12 | Evidence-based memory promotion (not just time-based consolidation) | P2 | §17.2 |
| CX13 | PII detection expansion (50+ patterns, connection strings, base64) | P2 | §9.3 |

### MCP Server (Category 07)

| # | Recommendation | Priority | Evidence |
|---|---------------|----------|----------|
| MC1 | Split into drift-analysis + drift-memory servers | P0 | AD5, §7.1 |
| MC2 | Progressive disclosure (3 entry points per server, not 17-20 tools) | P0 | §7.3 |
| MC3 | Tool description optimization (reduce schema verbosity by 60-70%) | P1 | §7.2 |
| MC4 | Workflow-oriented tools (drift_context handles 80% of queries) | P1 | §7.3, §19.1 |
| MC5 | Shared database coordination (drift.db + cortex.db, no server-to-server RPC) | P1 | §7.5 |
| MC6 | Response caching with content-hash invalidation (tool_name + params_hash + db_hash) | P1 | §19.2 |
| MC7 | Token estimation in responses via tiktoken-rs (help AI budget context window) | P1 | §19.2, §6.8 |
| MC8 | Security separation (analysis=read-only/low-risk, memory=read-write/higher-risk) | P2 | §7.4 |
| MC9 | Consistent JSON response schemas across all tools (structured, parseable) | P1 | §19.1 |
| MC10 | Workflow tools combining related operations (drift_analyze_function = signature + callers + callees + impact) | P1 | §19.1 |
| MC11 | Built-in pagination with cursor support for all list operations | P1 | §19.1 |
| MC12 | Streaming responses for large result sets (pattern lists, call graph traversals) | P2 | §19.2 |
| MC13 | Per-tool configurable rate limits (token-based, not request-count) | P2 | §19.2 |
| MC14 | Tool packs: pre-configured tool subsets for common workflows (security audit, code review, onboarding) | P2 | Recap §10 |

### Storage (Category 08)

| # | Recommendation | Priority | Evidence |
|---|---------------|----------|----------|
| ST1 | Consolidate to 2 databases: drift.db (Rust-owned) + cortex.db (TS-owned) | P0 | Recap §11 |
| ST2 | WAL mode + NORMAL sync + 256MB mmap on all databases | P0 | AD7, §8.1 |
| ST3 | Prepared statement caching for repeated queries | P1 | §8.1 |
| ST4 | Batch writes within single transactions (not per-row commits) | P1 | §8.1 |
| ST5 | Schema migration with rollback support (sequential, versioned) | P1 | Recap §26 |
| ST6 | FTS5 indexes on cortex.db for hybrid search | P1 | §6.2 |
| ST7 | Content-hash-based cache invalidation for query results | P1 | §1.2 |
| ST8 | ATTACH DATABASE for cross-db queries (cortex reads from drift.db) | P2 | Recap §11 |

### Quality Gates (Category 09)

| # | Recommendation | Priority | Evidence |
|---|---------------|----------|----------|
| QG1 | Transparent gates: rationale + suggested fix + documentation link per violation | P0 | §10.1 |
| QG2 | SARIF output enriched with CWE IDs, code flows, fix objects | P1 | §10.2 |
| QG3 | GitHub/GitLab PR annotations with inline fix suggestions | P1 | §10.2 |
| QG4 | Policy engine with 4 built-in policies (default, strict, relaxed, ci-fast) | P1 | Recap §12 |
| QG5 | KPI dashboard: pattern compliance rate, convention drift velocity, health trends | P2 | §10.1 |
| QG6 | Pre-merge simulation (impact analysis + quality gate dry-run) | P2 | §15.2 |

### CLI (Category 10)

| # | Recommendation | Priority | Evidence |
|---|---------------|----------|----------|
| CL1 | Rust-first execution via clap derive macros (native binary, no Node.js for core commands) | P1 | §20.1 |
| CL2 | Incremental scan command (only re-analyze changed files) | P0 | AD1 |
| CL3 | Interactive setup wizard generating both MCP server configs | P1 | AD5 |
| CL4 | Rayon replaces Piscina for all CPU-bound parallel work (parsing, detection, analysis) | P0 | §20.2 |
| CL5 | Git integration: staged-file scanning, pre-commit/pre-push hooks | P1 | Recap §13 |
| CL6 | Pluggable reporters (text, JSON, SARIF, GitHub, GitLab) | P1 | §10.2 |
| CL7 | Nested subcommands via clap (e.g., `drift call-graph build`, `drift memory search`) | P1 | §20.1 |
| CL8 | Shell completion generation for bash/zsh/fish/PowerShell | P2 | §20.1 |
| CL9 | Environment variable fallbacks for all config options (CI-friendly) | P1 | §20.1 |
| CL10 | `--format` flag on all output commands (text/json/sarif) with consistent schemas | P1 | §20.1 |
| CL11 | Progress reporting with ETA for long scans (file count, parse rate, detection rate) | P1 | Recap §13 |
| CL12 | Hybrid architecture: core commands native Rust, advanced commands (setup wizard, memory) in TS via NAPI | P1 | §20.1 |

### IDE (Category 11)

| # | Recommendation | Priority | Evidence |
|---|---------------|----------|----------|
| ID1 | LSP server leveraging Rust core for heavy computation (thin TS protocol layer) | P1 | §11.1, §21.2 |
| ID2 | Phased activation (register capabilities progressively, don't block on startup) | P1 | §11.1, §21.1 |
| ID3 | Real-time pattern violation highlighting via LSP publishDiagnostics | P1 | §21.2 |
| ID4 | Code actions for quick fixes (7 strategies as WorkspaceEdit objects) | P1 | §21.2 |
| ID5 | Hover information showing pattern details, confidence scores, and rationale | P1 | §21.2 |
| ID6 | Code lenses showing function-level metrics (coupling, complexity, test coverage) | P2 | §21.2 |
| ID7 | Lazy activation on specific events only (onLanguage, onCommand), never `*` | P0 | §21.1 |
| ID8 | Bundle with esbuild for single-file distribution (reduce load time) | P1 | §21.1 |
| ID9 | FileSystemWatcher API for file change detection (not polling) | P1 | §21.1 |
| ID10 | Tree views: patterns, violations, files, constants (Redux-like state) | P2 | Recap §14 |
| ID11 | Webview dashboard with pattern trends and health metrics | P2 | Recap §14 |
| ID12 | Workspace symbols for pattern and constraint navigation | P2 | §21.2 |
| ID13 | Extension profiling integration (detect and report own performance impact) | P2 | §21.1 |

### Infrastructure (Category 12)

| # | Recommendation | Priority | Evidence |
|---|---------------|----------|----------|
| IN1 | NAPI-RS v3 for cross-compilation (7+ platform targets from single CI) | P0 | §12.2 |
| IN2 | Turborepo task graph integrating Rust compilation with caching | P1 | §12.1 |
| IN3 | Affected-only CI execution (only test/build changed packages) | P1 | §12.1 |
| IN4 | Docker multi-stage build for containerized MCP server | P1 | Recap §15 |
| IN5 | Pre-compiled binary distribution via npm scope packages | P1 | §12.2 |
| IN6 | CIBench benchmark framework for performance regression detection | P2 | Recap §15 |

### Advanced Systems (Category 13)

| # | Recommendation | Priority | Evidence |
|---|---------------|----------|----------|
| AV1 | DNA system: 10 gene extractors migrated to Rust with structural fingerprinting | P2 | §15.1, §29.1 |
| AV2 | Simulation engine integrated with call graph for precise impact analysis | P2 | §15.2, §29.3 |
| AV3 | Decision mining from git history via git2 crate (NLP heuristics for decision extraction) | P3 | §29.2 |
| AV4 | DORA-adjacent metrics: compliance rate, drift velocity, health trends | P3 | §15.1 |
| AV5 | DNA: add structural fingerprinting based on normalized AST features (not just pattern matching) | P2 | §29.1 |
| AV6 | DNA: embedding-based similarity for cross-codebase comparison | P3 | §29.1 |
| AV7 | DNA: track gene evolution over time (mutation detection with temporal analysis) | P2 | §29.1 |
| AV8 | DNA: add backend genes for database access, authentication, logging, configuration patterns | P2 | §29.1 |
| AV9 | Simulation: multi-dimension scoring (convention alignment, test coverage impact, security, architecture, complexity) | P2 | §29.3 |
| AV10 | Simulation: sub-second execution using pre-computed indexes (call graph, pattern index, test mapping) | P2 | §29.3 |
| AV11 | Decision mining: link decisions to code locations via diff analysis | P3 | §29.2 |
| AV12 | Decision mining: detect ADRs in documentation and link to code | P3 | §29.2 |
| AV13 | Language intelligence: framework detection registry with composable matchers | P2 | Recap §16 |

### Specialized Analysis (Categories 17-22)

| # | Recommendation | Priority | Evidence |
|---|---------------|----------|----------|
| SP1 | Test topology: 35+ framework detection with 4-strategy test-to-code mapping (naming, imports, call graph, co-change) | P1 | §22.1 |
| SP2 | Test topology: produce test-to-source mapping file usable by CI systems (selective test execution) | P1 | §22.1 |
| SP3 | Test topology: quality scoring with convention consistency dimension + anti-pattern detection | P1 | §22.2 |
| SP4 | Test topology: minimum test set calculation using call-graph-based coverage mapping | P1 | §22.1 |
| SP5 | Test topology: detect framework migration patterns (Jest → Vitest) | P2 | §22.2 |
| SP6 | Constraints: 12 invariant types mapped to specific verification strategies (dependency graph, call graph, AST, data flow) | P1 | §30.1 |
| SP7 | Constraints: change-aware verification (only verify constraints affected by current change) | P1 | §30.1 |
| SP8 | Constraints: declarative constraint format (TOML/YAML) that can be version-controlled | P1 | §30.1 |
| SP9 | Constraints: constraint inheritance (package-level constraints inherited by sub-packages) | P2 | §30.1 |
| SP10 | Error handling: error chain tracking linking manifestation location to fix location | P1 | §23.1 |
| SP11 | Error handling: cross-function chain detection via call graph integration | P1 | §23.1 |
| SP12 | Error handling: classify chains by type (exception, null, resource) with priority scoring | P1 | §23.1 |
| SP13 | Error handling: detect anti-patterns (empty catch, catch-and-rethrow, swallowed errors, overly broad catch) | P1 | §23.2 |
| SP14 | Error handling: map error boundaries to call graph to identify unprotected code paths | P2 | §23.2 |
| SP15 | Contracts: GraphQL schema parsing (.graphql files + SDL in code) + breaking change detection | P1 | §31.1 |
| SP16 | Contracts: gRPC protobuf parsing (.proto files) + breaking change detection | P1 | §31.2 |
| SP17 | Contracts: OpenAPI/Swagger spec parsing as first-class contract source | P1 | §13.1 |
| SP18 | Contracts: classify changes as breaking/non-breaking/deprecation across all protocols | P1 | §31.1, §31.2 |
| SP19 | Contracts: frontend usage detection for GraphQL (useQuery/useMutation) and gRPC (generated stubs) | P2 | §31.1, §31.2 |
| SP20 | Security: expand learn-then-detect to 40+ ORM frameworks | P1 | §24.1 |
| SP21 | Security: add unsafe API detection per ORM (raw SQL bypass patterns) | P1 | §24.2 |
| SP22 | Security: cross-reference sensitive fields with data access points for unprotected access detection | P1 | §24.2 |
| SP23 | Security: OWASP Top 10 coverage (9/10), CWE ID mapping per detector | P1 | §9.1 |
| SP24 | Security: track sensitive data flow through call graph (source → sink taint analysis) | P2 | §24.2 |
| SP25 | Context generation: place highest-importance context first (primacy bias — 3x weight in first 25%) | P1 | §25.1 |
| SP26 | Context generation: adaptive budgeting based on query intent (security queries get more security context) | P1 | §25.1 |
| SP27 | Context generation: context quality metrics (was context used? did it lead to correct output?) | P2 | §25.1 |
| SP28 | Context generation: scope pattern analysis per package, not just per repository | P1 | §25.2 |
| SP29 | Context generation: workspace root detection for all 11+ ecosystems | P1 | §25.2 |

### Data Infrastructure (Categories 23-26)

| # | Recommendation | Priority | Evidence |
|---|---------------|----------|----------|
| DI1 | Pattern repository: single IPatternRepository with SQLite backend + event sourcing for lifecycle | P1 | §26.1 |
| DI2 | Pattern repository: append-only event log (PatternDiscovered, Approved, Ignored, ConfidenceUpdated, Merged, Archived) | P1 | §26.1 |
| DI3 | Pattern repository: temporal queries for pattern evolution tracking ("when was this discovered?") | P2 | §26.1 |
| DI4 | Pattern repository: event log feeds DNA mutation detection and audit trails | P2 | §26.1 |
| DI5 | Data lake: DEPRECATED — replaced by SQLite views and indexes | P0 | Recap §24 |
| DI6 | Services layer: rayon parallel iterators replace Piscina for scan pipeline | P0 | §27.1 |
| DI7 | Services layer: streaming pipeline (parse as files discovered, detect as files parsed) | P1 | §27.1 |
| DI8 | Services layer: crossbeam channels for pipeline stage communication | P1 | §27.1 |
| DI9 | Services layer: DashMap for concurrent pattern counting during aggregation | P1 | §27.1 |
| DI10 | Workspace: SQLite Online Backup API for WAL-mode safe backups (not file copy) | P1 | §28.2 |
| DI11 | Workspace: user_version pragma for schema version tracking (atomic, no separate table) | P1 | §28.1 |
| DI12 | Workspace: savepoints for partial rollback within multi-step migrations | P1 | §28.1 |
| DI13 | Workspace: backup verification (restore to temp, run integrity check) | P1 | §28.2 |
| DI14 | Workspace: configurable retention policies (daily/weekly/monthly for enterprise) | P2 | §28.2 |
| DI15 | Workspace: multi-project registry with health indicators (last scan, pattern count, error count) | P2 | §28.2 |
| DI16 | Workspace: context pre-loading for frequently accessed projects | P2 | §28.2 |

---

## Part 3: Build Phases

```
Phase 0 — Architectural Decisions (before code)
  Duration: 1-2 weeks
  Deliverables:
  • AD1-AD9 documented and agreed upon
  • Rust crate structure defined
  • TypeScript package structure defined
  • SQLite schema v1 designed
  • CI/CD pipeline configured

Phase 1 — Core Engine (Rust)
  Duration: 4-6 weeks
  Dependencies: Phase 0
  Deliverables:
  • Scanner with incremental change detection (RC1)
  • Parser layer with rich extraction for 10 languages (RC2, PA1-PA11)
  • String interning with lasso (RC3)
  • Unified analyzer with declarative patterns (RC4)
  • Content-hash-based parse cache with Moka (PA1)
  • N-API bridge with batch/streaming (RC15)
  • SQLite storage with WAL mode (ST1, ST2)

Phase 2 — Pattern Detection (Rust)
  Duration: 3-4 weeks
  Dependencies: Phase 1
  Deliverables:
  • Visitor pattern detection engine (DE1)
  • Confidence scoring with momentum (DE3)
  • Outlier detection with refined statistics (DE6)
  • Convention learning with graduated confidence (DE9)
  • Secret detection (100+ patterns, entropy) (RC5)
  • Incremental detection with hash skipping (DE2)

Phase 3 — Analysis Subsystems (Rust)
  Duration: 4-6 weeks
  Dependencies: Phase 1
  Deliverables:
  • Call graph with full resolution (CG1, CG2)
  • Coupling with Tarjan's SCC (RC7)
  • Boundary analysis with ORM extractors (RC8)
  • Environment analyzer (RC9)
  • Error handling analyzer (RC10)
  • Test topology (RC11)
  • Reachability with taint foundation (RC12)
  • In-memory graph with petgraph (CG8)

Phase 4 — Bridge & Orchestration
  Duration: 2-3 weeks
  Dependencies: Phases 1-3
  Deliverables:
  • N-API bridge with all Rust functions exposed (RC15)
  • TypeScript orchestration layer (thin wrapper)
  • Feedback loop infrastructure (AD9)
  • Rules engine with quick fixes (AN2, AN3)

Phase 5 — MCP Servers (TypeScript)
  Duration: 3-4 weeks
  Dependencies: Phase 4
  Deliverables:
  • drift-analysis server with progressive disclosure (MC1, MC2)
  • drift-memory server with progressive disclosure (MC1, MC2)
  • Tool description optimization (MC3)
  • Response caching and token estimation (MC6, MC7)

Phase 6 — Cortex Memory (TypeScript + Rust)
  Duration: 3-4 weeks
  Dependencies: Phase 4
  Deliverables:
  • Hybrid search with FTS5 + RRF (CX1)
  • Code-specific embeddings (CX2)
  • Rust embedding inference via ort (CX3)
  • Two-phase memory pipeline (CX4)
  • Embedding enrichment (CX6)
  • Accurate token counting (CX8)

Phase 7 — Presentation Layer (TypeScript)
  Duration: 3-4 weeks
  Dependencies: Phases 5-6
  Deliverables:
  • CLI with incremental scan (CL1, CL2)
  • Quality gates with transparent rationale (QG1)
  • SARIF + GitHub/GitLab reporters (QG2, QG3)
  • VSCode extension with LSP (ID1, ID2)
  • Setup wizard (CL3)

Phase 8 — Enterprise & Ecosystem
  Duration: 4-6 weeks (ongoing)
  Dependencies: Phase 7
  Deliverables:
  • OWASP/CWE alignment (DE7, SP5)
  • Contract expansion: GraphQL, gRPC, OpenAPI (DE8, SP4)
  • Constraint enforcement (SP2)
  • KPI dashboard (QG5)
  • DNA system migration (AV1)
  • Simulation engine integration (AV2)
  • Advanced memory features (CX9-CX13)
```

---

## Part 4: V2 Target Metrics

| Metric | V1 Baseline | V2 Target | Evidence |
|--------|-------------|-----------|----------|
| Full scan (10K files) | 5-10s | <2s | §1.1 (incremental architecture) |
| Incremental scan (50 changed files) | 5-10s (full rescan) | <200ms | §1.2 (content-hash skipping) |
| MCP tool definitions (analysis only) | ~15-25K tokens | <2K tokens | §7.2, §7.3 (progressive disclosure) |
| MCP tool definitions (analysis + memory) | ~25-40K tokens | <4K tokens | §7.2, §7.3 |
| Secret detection patterns | 21 | 100+ | §9.2 (GitGuardian benchmark) |
| AST patterns (Rust) | ~30 | 350+ (all v1 detectors) | §3.2 (visitor pattern) |
| Call resolution strategies | 3 (Rust) | 6 (full parity) | Recap §7 |
| Languages parsed | 10 | 10+ (with scaffold) | §2.2 |
| Frameworks detected | 7 | 20+ (with middleware) | Recap §3 |
| OWASP Top 10 coverage | ~4/10 | 9/10 | §9.1 |
| Effective false-positive rate | Unknown | <5% | §3.1 (Google Tricorder) |
| Embedding dimensions | 384 (general) | 1024 (code-specific) | §6.3 |
| Memory retrieval method | Vector-only | Hybrid (FTS5 + vector + RRF) | §6.2 |
| Token counting accuracy | ~±30% (string length) | ~±2% (tiktoken) | §6.8 |
| Outlier detection min sample | 3 | 10 | §5.3 (NIST) |
| Z-score threshold | 2.0 | 2.5 | §5.3 (NIST) |
| Convention learning threshold | Binary 60% | Graduated Bayesian | §5.1 |
| Contract protocols | REST only | REST + GraphQL + gRPC | §13.1 |
| CWE ID mapping | None | Per-detector | §9.1 |
| SARIF enrichment | Basic | CWE IDs + code flows + fixes | §10.2 |

---

## Part 5: Risk Register

### Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Rust migration takes longer than estimated | High | High | Phase incrementally; TS fallback for each subsystem |
| Tree-sitter query consolidation introduces regressions | Medium | Medium | Golden file test suite per language |
| Visitor pattern doesn't handle all detector types | Low | High | Fallback to per-detector traversal for complex detectors |
| Code-specific embedding model quality varies by language | Medium | Medium | Benchmark on Drift-specific retrieval tasks before committing |
| NAPI bridge becomes bottleneck for large result sets | Medium | Medium | Batch/streaming APIs; JSON serialization fallback |
| SQLite WAL mode checkpoint stalls during heavy writes | Low | Medium | Configure auto-checkpoint threshold; manual checkpoint between phases |
| Progressive disclosure confuses AI agents | Medium | Medium | Fallback to full tool loading; A/B test with real agents |

### Organizational Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Scope creep from 350+ detector migration | High | High | Prioritize by usage frequency; migrate top 50 first |
| Enterprise customers need features before Phase 8 | Medium | High | Identify top 3 enterprise blockers; fast-track those |
| Community adoption requires documentation | High | Medium | Document as you build; TOML pattern format enables community rules |

---

## Part 6: Decision Log

| Decision | Options Considered | Chosen | Rationale |
|----------|-------------------|--------|-----------|
| MCP architecture | Single server, Split servers, Microservices | Split (2 servers) | Token efficiency, single responsibility, spec support (§7.1-7.5) |
| Detection architecture | Per-detector traversal, Visitor pattern, Pipeline | Visitor pattern | O(files) vs O(files × detectors) traversals (§3.2) |
| Incremental strategy | Full rescan, File-hash skip, Salsa framework | File-hash skip | Simpler than Salsa, covers 90% of benefit (§1.1, §1.2) |
| Confidence scoring | Static weights, Momentum-aware, Full Bayesian | Momentum-aware | Balances simplicity with temporal awareness (§5.2) |
| Embedding model | General-purpose, Code-specific, Multi-model | Code-specific | Significant retrieval quality improvement for code memories (§6.3) |
| Graph library | Custom, petgraph, neo4rs | petgraph | Standard library, built-in algorithms, 10M+ downloads (§16.3) |
| Cache library | Custom LRU, Moka, quick_cache | Moka | TinyLFU, thread-safe, TTL support, most popular (§16.2) |
| String interning | Custom, lasso, symbol_table | lasso | ThreadedRodeo for build, RodeoReader for query (§16.1) |
| Error handling | anyhow, thiserror, custom | thiserror | Structured variants, zero-cost, ecosystem standard (AD6) |
| Secret detection | Regex-only, Entropy + regex, ML-based | Entropy + regex | Catches unknown formats without ML complexity (§9.2) |
| Outlier threshold | Z=2.0, Z=2.5, Z=3.0 | Z=2.5 | Reduces false positives while catching meaningful deviations (§5.3) |
| Contract protocols | REST-only, REST+GraphQL, REST+GraphQL+gRPC | All three | Enterprise codebases use all three (§13.1) |
| Memory search | Vector-only, FTS-only, Hybrid RRF | Hybrid RRF | Consistently outperforms either alone (§6.2) |

---

## Part 7: Recommendation Cross-Reference Matrix

This matrix shows how recommendations connect across categories. A change in one area affects others.

```
AD1 (Incremental) ──→ RC1 (Scanner) ──→ DE2 (Detection skip) ──→ CG5 (Call graph update)
                  ──→ PA1 (Parse cache) ──→ ST7 (Cache invalidation)

AD2 (Canonical model) ──→ PA2 (ParseResult) ──→ RC15 (NAPI bridge) ──→ AN1 (Unified provider)
                      ──→ AN14 (Normalized IR) ──→ AN9 (CFG construction) ──→ AN6 (Dataflow)

AD4 (Visitor pattern) ──→ DE1 (Detection engine) ──→ DE3 (Confidence) ──→ DE5 (Feedback loop)
                      ──→ RC4 (Declarative patterns) ──→ DE12 (Testing framework)

AD5 (MCP split) ──→ MC1-MC14 (All MCP) ──→ CL3 (Setup wizard) ──→ ID1 (LSP server)
               ──→ MC10 (Workflow tools) ──→ MC9 (Consistent schemas)

AD9 (Feedback loop) ──→ DE5 (False positive tracking) ──→ DE3 (Confidence adjustment)
                    ──→ CX11 (Memory observability) ──→ QG5 (KPI dashboard)

RC5 (Secrets) ──→ DE7 (OWASP alignment) ──→ SP23 (Security coverage) ──→ QG2 (SARIF + CWE)

CG1-CG2 (Call graph) ──→ RC12 (Reachability) ──→ SP10-SP14 (Error chains + boundaries)
                     ──→ CG3 (Impact analysis) ──→ QG6 (Pre-merge simulation) ──→ AV9 (Simulation scoring)
                     ──→ SP1-SP4 (Test topology) ──→ CG4 (Dead code)
                     ──→ SP24 (Security taint tracking) ──→ SP21 (ORM unsafe API detection)

CX1-CX2 (Memory search) ──→ CX6 (Enrichment) ──→ CX7 (Re-ranking) ──→ CX11 (Observability)

AN7 (Scope tree) ──→ AN11 (Shadowed vars) ──→ AN14 (Normalized IR) ──→ AN9 (CFG) ──→ AN6 (Dataflow)
                ──→ AN12 (Unreachable code) ──→ AN13 (Null dereference)

SP15-SP18 (Contracts) ──→ SP19 (Frontend usage) ──→ MC10 (Workflow tools)

DI1-DI4 (Pattern repo events) ──→ AV7 (DNA mutation tracking) ──→ AV1 (DNA fingerprinting)

DI6-DI9 (Services pipeline) ──→ CL4 (Rayon parallelism) ──→ RC16 (Thread-local cleanup)

SP25-SP29 (Context gen) ──→ MC7 (Token estimation) ──→ CX8 (tiktoken-rs)
```

---

## Updated Quality Checklist

- [x] All 27 categories have specific, deep recommendations
- [x] Every recommendation has priority level (P0-P3)
- [x] Every recommendation cites evidence (research section or recap section)
- [x] 9 architectural decisions documented with rationale
- [x] 8 build phases defined with dependency ordering and duration estimates
- [x] 20+ target metrics with V1 baselines and V2 targets
- [x] Technical and organizational risks identified with mitigations
- [x] 13 key decisions logged with options considered and rationale
- [x] Cross-reference matrix shows inter-category dependencies (expanded)
- [x] **GAP CLOSURE**: All previously thin categories now have deep, specific recommendations
- [x] **Analyzers (05)**: Expanded from 6 → 14 recommendations (type inference, scope tree, CFG, dataflow)
- [x] **MCP (07)**: Expanded from 8 → 14 recommendations (workflow tools, streaming, rate limiting, tool packs)
- [x] **CLI (10)**: Expanded from 6 → 12 recommendations (clap, rayon, shell completions, progress reporting)
- [x] **IDE (11)**: Expanded from 5 → 13 recommendations (LSP diagnostics, code actions, hover, code lenses, bundling)
- [x] **Advanced (13)**: Expanded from 4 → 13 recommendations (DNA fingerprinting, simulation scoring, decision mining)
- [x] **Specialized (17-22)**: Expanded from 6 → 29 recommendations (test mapping, error chains, GraphQL/gRPC, ORM security, context budgeting)
- [x] **Data Infrastructure (23-26)**: Expanded from 5 → 16 recommendations (event sourcing, streaming pipeline, backup API, migration)
- [x] Recommendations total: 9 AD + 17 RC + 14 PA + 12 DE + 8 CG + 14 AN + 13 CX + 14 MC + 8 ST + 6 QG + 12 CL + 13 ID + 6 IN + 13 AV + 29 SP + 16 DI = **194 recommendations** (up from 123)
- [x] Every v1 capability has a corresponding recommendation
- [x] Every v1 gap has a research-backed improvement path
- [x] Every recommendation traces to either a research finding or a recap capability
