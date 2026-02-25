# Drift V2 — Complete Stack Hierarchy (Dependency-Ordered Importance)

> Every system in Drift V2, ranked by structural importance.
> "Importance" = how many other systems break if this one doesn't exist.
> Nothing at Level N can function without Level N-1 being complete.
>
> Rebuilt from all 35+ V2-PREP system documents + PLANNING-DRIFT.md (D1-D7).
> This is a dependency truth map, not a build schedule.
>
> Cross-referenced against every V2-PREP document for completeness.
> All spec numbers, algorithm choices, crate versions, and framework counts
> verified against their source V2-PREP documents.
>
> Generated: 2026-02-08
> Last verified: 2026-02-08

---

## How PLANNING-DRIFT.md (D1-D7) Shapes This Hierarchy

| Decision | Structural Impact |
|----------|------------------|
| **D1: Standalone Independence** | No system in Drift imports from cortex-core. The entire hierarchy is self-contained. Context generation, grounding, and memory-linked tools are strictly optional branches, never on the critical path. |
| **D4: Bridge Crate is a Leaf** | cortex-drift-bridge depends on both drift-core and cortex-core, but nothing in Drift depends on it. The grounding loop (D7) is Level 5B — high value, zero structural importance to Drift. |
| **D5: DriftEventHandler is Bedrock** | Trait-based event bus with no-op defaults is Level 0 infrastructure. Every subsystem emits typed events from day one. Retrofitting later touches every function signature. |
| **D6: Separate Databases** | drift.db is fully self-contained. ATTACH cortex.db is optional read-only overlay. Every query works without it. Cross-DB queries are presentation-layer concerns. |
| **D7: Grounding Loop is a Leaf** | The killer integration feature, but architecturally the last thing that needs to work — it only consumes what the core stack produces. |

---

## Level 0 — Bedrock (Everything Dies Without These)

These are the gravity systems. Every feature in Drift traces back to one of these.
**8 systems. 0 optional.**

| # | System | Key Specs | Why Bedrock | Downstream Consumers |
|---|--------|-----------|-------------|---------------------|
| — | **Configuration System** | TOML (drift.toml), 4-layer resolution (CLI > env > project > user > defaults), `DriftConfig` with `ScanConfig`, `AnalysisConfig`, `GateConfig`, `McpConfig`, `BackupConfig`, `TelemetryConfig`, `LicenseConfig`. Validation at load time. Config loading: `load_config()` merges layers via `merge_toml_config()`. Env vars: `DRIFT_SCAN_MAX_FILE_SIZE`, etc. | Everything reads config. Scanner needs ignore patterns, detectors need thresholds, storage needs pragma settings, quality gates need fail levels. Must exist before first scan. | Every system (~35+) |
| — | **thiserror Error Enums** | Per-subsystem structured error types: `ScanError`, `ParseError`, `StorageError`, `DetectionError`, `CallGraphError`, `PipelineError`, `TaintError`, `ConstraintError`, `BoundaryError`. `DriftErrorCode` trait for NAPI conversion. Non-fatal error collection pattern (`PipelineResult.errors: Vec<PipelineError>`). 14+ NAPI error codes: `SCAN_ERROR`, `PARSE_ERROR`, `DB_BUSY`, `DB_CORRUPT`, `CANCELLED`, `UNSUPPORTED_LANGUAGE`, `DETECTION_ERROR`, `CALL_GRAPH_ERROR`, `CONFIG_ERROR`, `LICENSE_ERROR`, `GATE_FAILED`, `STORAGE_ERROR`, `DISK_FULL`, `MIGRATION_FAILED`. Format: `[ERROR_CODE] message`. | Per AD6: from the first line of code. Every Rust function returns typed errors. Retrofitting touches every function signature. Enables programmatic error handling in TS via `DriftError` class with code parsing. | Every system (~35+) |
| — | **tracing Instrumentation** | `tracing` crate with `EnvFilter`, per-subsystem spans, structured fields. `DRIFT_LOG=scanner=debug,parser=info`. 12+ key metrics: scan throughput (`scan_files_per_second`), cache hit rate, parse time per language, NAPI serialization time, detection time per category, batch write time, call graph build time, confidence compute time, gate evaluation time, MCP response time, discovery duration, hashing duration. Optional OpenTelemetry layer behind `otel` feature flag. `pino` for TS layer. `tracing-subscriber` with `env-filter` feature. | Per AD10: from the first line of code. Without it, you're debugging blind and can't measure performance targets (10K files <3s). Span-based timing is how you find bottlenecks. | Every system (~35+) |
| — | **DriftEventHandler Trait** | Trait with no-op defaults, `Vec<Arc<dyn DriftEventHandler>>`, synchronous dispatch via `emit()` helper. 16+ event methods: scan lifecycle (`on_scan_started`, `on_scan_progress`, `on_scan_complete`, `on_scan_error`), pattern lifecycle (`on_pattern_discovered`, `on_pattern_approved`, `on_pattern_ignored`, `on_pattern_merged`), violations (`on_violation_detected`, `on_violation_dismissed`, `on_violation_fixed`), enforcement (`on_gate_evaluated`, `on_regression_detected`), detector health (`on_detector_alert`, `on_detector_disabled`), errors (`on_error`). Zero overhead when no handlers registered (empty Vec iteration). | Per D5: the hook point the bridge crate latches onto. If subsystems don't emit events from day one, you retrofit every subsystem later. In standalone mode these are no-ops. When bridge is active, they become Cortex memories. | Bridge crate, NAPI progress callbacks, future telemetry, future webhooks |
| 01 | **Tree-Sitter Parsers** | 10 languages (TS, JS, Python, Java, C#, Go, Rust, Ruby, PHP, Kotlin). Per-language tree-sitter grammars compiled via `build.rs`. `thread_local!` parser instances (tree-sitter is not `Send`). Moka LRU parse cache (in-memory) + SQLite `parse_cache` table. Extracts: functions, classes, imports, exports, calls, decorators, inheritance, access modifiers, type annotations. `tree-sitter` v0.24. | Every analysis path starts here. Zero detectors, zero call graph, zero boundaries, zero taint, zero contracts, zero test topology, zero error handling, zero DNA, zero constraints without parsed ASTs. The single most critical system. | Every Level 1+ system (~30+) |
| 00 | **Scanner** | `ignore` crate v0.4 (parallel walker from ripgrep) for Phase 1 discovery via `WalkParallel`. `rayon` v1.10 for Phase 2 processing. xxh3 content hashing via `xxhash-rust` v0.8 (optional `blake3` behind config flag for enterprise audit trails). Two-level incrementality: mtime comparison (catches ~95% unchanged) → content hash for mtime-changed files. `.driftignore` (gitignore syntax, hierarchical via `add_custom_ignore_filename`). 18 default ignores (node_modules, .git, dist, build, target, .next, .nuxt, __pycache__, .pytest_cache, coverage, .nyc_output, vendor, .venv, venv, .tox, .mypy_cache, bin, obj). `ScanDiff` output: added/modified/removed/unchanged + `ScanStats` (total_files, total_size_bytes, discovery_ms, hashing_ms, diff_ms, cache_hit_rate, files_skipped_large, files_skipped_ignored, languages_found). `ScanEntry` includes `language: Option<Language>` (detected from extension). Language detection from extension. Performance: 10K files <300ms, 100K files <1.5s, incremental (1 file) <100ms. Cancellation via `AtomicBool`. `ScanConfig`: max_file_size (1MB default), threads (0=auto), extra_ignore, follow_symlinks (false), compute_hashes (true), force_full_scan (false), skip_binary (true), hash_algorithm ("xxh3"\|"blake3"). | The entry point to the entire pipeline. No scanner = no files = no parsing = nothing. Owns incremental detection — content hashes determine what gets re-analyzed. Three-layer incrementality: L1 file-level skip (scanner), L2 pattern re-scoring (detectors), L3 re-learning threshold (conventions). | Parsers, call graph, every detector, every analyzer, storage (file_metadata) |
| 02 | **SQLite Storage (drift.db)** | `rusqlite` v0.32+ with `bundled` feature (guarantees SQLite 3.45+ across 7 NAPI targets). WAL mode, `PRAGMA synchronous=NORMAL`, 64MB page cache (`cache_size=-64000`), 256MB mmap, `busy_timeout=5000`, `temp_store=MEMORY`, `auto_vacuum=INCREMENTAL`, `foreign_keys=ON`. Write-serialized + read-pooled (`Mutex<Connection>` writer, round-robin `ReadPool` with `AtomicUsize` index, read connections with `SQLITE_OPEN_READ_ONLY | SQLITE_OPEN_NO_MUTEX` + `PRAGMA query_only=ON`). 40+ STRICT tables. Medallion architecture: Bronze (staging, ephemeral) → Silver (normalized, source of truth, schema-enforced) → Gold (materialized: `materialized_status`, `materialized_security`, `health_trends`). CQRS read/write separation. Batch writer via `crossbeam-channel` bounded(1024) with dedicated writer thread, `BEGIN IMMEDIATE` transactions, `prepare_cached()`, batch size 500, `recv_timeout(100ms)` for partial flush. Keyset pagination (not OFFSET/LIMIT) with composite cursor `(sort_column, id)`, Base64-encoded opaque cursors. `rusqlite_migration` + `PRAGMA user_version` (forward-only, no down migrations). JSONB via `jsonb()` for frequently-queried JSON columns. Covering indexes (replaces v1 PatternIndexView), partial indexes (3-10x smaller), expression indexes on JSON, dimension-replacement indexes (replaces v1's 4 JSON index files). WAL checkpoint: 3-tier (auto PASSIVE at 1000 pages, explicit TRUNCATE post-scan, emergency at 100MB). Per D6: fully self-contained, ATTACH cortex.db is optional read-only overlay. Silver tables by domain: Patterns (7 tables), Call Graph (3), Security (3), Contracts (4), Constraints (2), Test Topology (6), DNA (3), Error Handling (3), Audit (3), Environment (2), Constants (2), Coupling (2), Learning (1), Quality Gates (3), Infrastructure (6). Gold layer refresh via `RefreshPipeline::refresh_all()` in single `BEGIN IMMEDIATE` transaction. | Nothing persists without this. No patterns survive a restart, no call graph is queryable, no incremental analysis is possible. Replaces v1's entire Data Lake (~4,870 lines TS across 10 stores) with ~800 lines Rust. | Every system that reads or writes data (~30+) |
| 03 | **NAPI Bridge (drift-napi)** | napi-rs v3 (July 2025), no `compat-mode` — v3 APIs exclusively. Singleton `DriftRuntime` via `OnceLock` (lock-free after init). ~40+ exported functions across ~15 binding modules. Two function categories: Command (write-heavy, return summary via `#[napi(object)]` structs) and Query (read-only, paginated, keyset cursors). `AsyncTask` for >10ms operations (runs on libuv thread pool, not tokio). v3 `ThreadsafeFunction` with ownership-based lifecycle (no manual ref/unref) for progress callbacks, shared via `Arc<ThreadsafeFunction>`. Batch API: `analyze_batch(options: BatchOptions)` — multiple analyses in one NAPI call with shared parse results (15 analysis types: Scan, Patterns, CallGraph, Boundaries, TestTopology, ErrorHandling, Constants, Environment, Wrappers, Taint, Coupling, Constraints, Contracts, Dna, Secrets). Structured error codes (`[ERROR_CODE] message`) via `DriftErrorCode` trait + `to_napi_error()`. Cancellation via global `AtomicBool` (`SCAN_CANCELLED`) + future per-operation `CancellationToken`. 8 platform targets (7 native: x86_64/aarch64 macOS, x86_64/aarch64 Linux gnu/musl, x86_64 Windows + wasm32-wasip1-threads fallback). Core principle: Rust does ALL computation + writes to drift.db, NAPI returns lightweight summaries. `NapiProgressHandler` bridges `DriftEventHandler` → `ThreadsafeFunction` (reports every 100 files). Lifecycle: `drift_initialize()`, `drift_shutdown()`, `drift_configure()`. | The only door between Rust analysis and TS presentation. Without it, Rust computation is trapped. No MCP, no CLI, no VSCode, no LSP. | MCP server, CLI, VSCode extension, LSP, dashboard, CI agent |

**Dependency truth**: `Config + thiserror + tracing + DriftEventHandler → Scanner → Parsers → Storage → NAPI → everything else`

**What changed from previous hierarchy**: Bedrock expanded from 4 → 8 systems. The event trait, error handling, tracing, and config are load-bearing infrastructure that D5/AD6/AD10 explicitly require from line one.

---

## Level 1 — Structural Skeleton (Core Analysis That Most Systems Consume)

These produce the foundational data structures. They don't depend on each other (mostly), but almost everything above depends on at least one.
**6 systems.**

| # | System | Key Specs | Upstream Dependencies | Downstream Consumers (count) |
|---|--------|-----------|----------------------|------------------------------|
| 06 | **Unified Analysis Engine** | 4-phase per-file pipeline: (1) AST pattern detection via visitor pattern, (2) string extraction, (3) regex on strings, (4) resolution index building. Processes `ScanDiff.added + modified` files. Shared parse results across all detectors per file (single-pass). GAST normalization (~30 node types) for cross-language analysis. Declarative TOML pattern definitions (user-extensible without code changes). `CompiledQuery` with `cwe_ids: SmallVec<[u32; 2]>` and `owasp: Option<Spur>` fields. | Parsers, scanner, string interning | Detectors, patterns, confidence, outliers, violations, DNA, constraints, constants/environment, crypto detection (~10) |
| 05 | **Call Graph Builder** | petgraph `StableGraph` in-memory + SQLite persistence. 6 resolution strategies: direct (exact name match), method (class.method qualified), constructor (new/init), callback (closure/lambda), dynamic (string-based/reflection), external (cross-module). Parallel extraction via rayon. `functions` + `call_edges` + `data_access` tables. Incremental: re-extract only changed files (O(edges_in_changed_file)), remove edges for deleted files. | Parsers, storage | Reachability, impact, dead code, taint, error handling propagation, test topology coverage, N+1, contracts (cross-service), simulation, constraints (must_precede/must_follow), coupling (~12) |
| 06 | **Detector System** | 16 categories × 3 variants (Base/Learning/Semantic) = 350+ detectors total. Trait-based: `Detector` trait with `detect(&self, ctx: &DetectionContext) -> Vec<PatternMatch>`. Registry with category filtering, critical-only mode. Categories: api, auth, components, config, contracts, data-access, documentation, errors, logging, performance, security, structural, styling, testing, types, accessibility. Security category: 18 detectors. Each detector carries `cwe_ids` and `owasp` fields populated from the OWASP/CWE mapping registry at detection time. | Parsers, unified analysis engine | Patterns, violations, confidence, outliers, DNA, constraints, quality gates, audit (~10) |
| 07 | **Boundary Detection** | 33+ ORM frameworks across 9 languages (28 from v1 + 5 new: MikroORM, Kysely, sqlc, SQLBoiler, Qt SQL). 10 field extractors (7 from v1 + 3 new: EfCoreExtractor, HibernateExtractor, EloquentExtractor — per OR5 recommendation). Two-phase learn-then-detect architecture. Sensitive field classification: 4 categories (PII, Credentials, Financial, Health) with ~100+ patterns (3x v1's ~30). 6 formal false-positive filters (v1 had ad-hoc). Confidence scoring: 5 weighted factors. `FieldExtractor` trait in Rust. `boundaries`, `sensitive_fields`, `boundary_rules` tables. Field-level data flow tracking. | Parsers, unified language provider | Security analysis, taint (sinks), reachability (sensitivity classification), constraints (data_flow), quality gates (security gate), OWASP mapping (~7) |
| 08 | **Unified Language Provider** | 9 language normalizers (TS, JS, Python, Java, C#, PHP, Go, Rust, C++). 22 ORM/framework matchers (20 from v1 + 2 new: MikroORM, Kysely + 2 detection-only: sqlc, SQLBoiler). Cross-language type mapping. `UnifiedCallChain` universal representation. 12 semantic categories. Framework detection: 5 framework pattern sets (Express, Django, Spring, Rails, ASP.NET, etc.). `LanguageNormalizer` + `OrmMatcher` traits. Entry point detection: `EntryPointKind` with Cron, WebSocket, GraphQL variants. N+1 query detection module (`n_plus_one.rs`). Taint sink extraction module (`taint_integration.rs`). | Parsers | Boundary detection, N+1, contract extraction, language intelligence, wrapper detection, taint integration (~6) |
| — | **String Interning (lasso)** | `lasso` v0.7 with `multi-threaded` + `serialize` features. `ThreadedRodeo` for build/scan phase (thread-safe, mutable), `RodeoReader` for query phase (immutable, zero-contention). `PathInterner` (normalizes path separators before interning), `FunctionInterner` (supports qualified name interning: `Class.method`). 60-80% memory reduction for file paths and function names. `Spur` keys for integer-based comparisons. | None (utility) | Unified analysis, call graph, all identifier-heavy systems (~15) |

**Key insight**: Call graph feeds ~12 downstream systems — the highest-leverage "second branch" after the core detection pipeline. Detector system feeds ~10. Per D1, neither assumes Cortex exists — they write to drift.db only.

---

## Level 2 — Intelligence Layer (Derived Analysis)

### Tier 2A — Pattern Intelligence (4 systems — Core Value Proposition)

These are what make Drift *Drift*. Without them, you have a scanner that finds things but can't rank, learn, or flag deviations.

| # | System | Key Specs | Upstream Dependencies | Downstream Consumers (count) |
|---|--------|-----------|----------------------|------------------------------|
| 10 | **Bayesian Confidence Scoring** | Beta distribution: `Beta(1+k, 1+n-k)` posterior. 5-factor model: frequency (how often), consistency (how uniformly), age (how long established), spread (how many files), momentum (trend direction). Graduated tiers: Established (≥0.85), Emerging (≥0.70), Tentative (≥0.50), Uncertain (<0.50). Momentum tracking for trend detection (rising/falling/stable). | Detector system, pattern aggregation | Outlier detection, quality gates, audit, learning system, grounding loop (D7 — bridge reads these), rules engine (~7) |
| 11 | **Outlier Detection** | 6 methods: Z-Score (n≥30), Grubbs' test (10≤n<30), Generalized ESD (multiple outliers in same dataset), IQR (n<30), MAD (robust to extreme outliers), rule-based (always, for structural rules). Auto-selects method based on sample size. Deviation scoring per location. 4 significance tiers for classification. | Confidence scoring, pattern aggregation | Violations, rules engine, quality gates, audit, feedback loop (~6) |
| 12 | **Pattern Aggregation & Deduplication** | 7-phase pipeline: (1) group by pattern ID, (2) cross-file merging, (3) Jaccard similarity (0.85 threshold flags for review, 0.95 auto-merge), (4) MinHash LSH for approximate near-duplicate detection at scale, (5) hierarchy building (parent-child pattern relationships), (6) counter reconciliation (location_count, outlier_count caches), (7) Gold layer refresh. Exact + semantic deduplication. | Detector system, unified analysis engine | Confidence scoring, outlier detection, learning system, rules engine, DNA (~6) |
| 13 | **Learning System** | Bayesian convention discovery. 5 categories of learnable conventions: Universal (cross-project norms), ProjectSpecific (local conventions), Emerging (gaining adoption), Legacy (declining usage), Contested (inconsistent adoption). Thresholds: minOccurrences=3, dominance=0.60, minFiles=2. Automatic pattern promotion: discovered → approved when thresholds met. Re-learning trigger: >10% files changed → full re-learn. `learned_conventions` table. | Detector system, pattern aggregation, confidence scoring | Pattern lifecycle, quality gates, audit, DNA (~5) |

**D7 impact on 2A**: The grounding feedback loop reads confidence scores and pattern data from drift.db to validate Cortex memories. Drift computes confidence independently; the bridge consumes it. Confidence scoring quality directly affects grounding quality — get this right and the grounding loop is powerful.

### Tier 2B — Graph-Derived Analysis (5 systems)

These all depend on the call graph. They represent the security and structural intelligence that makes Drift enterprise-grade.

| # | System | Key Specs | Upstream Dependencies | Downstream Consumers (count) |
|---|--------|-----------|----------------------|------------------------------|
| 14 | **Reachability Analysis** | Forward/inverse BFS traversal. Sensitivity classification (can user input reach this SQL query?). Auto-select engine: petgraph for small graphs (<10K nodes), SQLite recursive CTE for large graphs (>10K nodes). Caching of reachability results. Reachability matrix for frequently-queried pairs. | Call graph, boundaries | Taint analysis, impact analysis, security analysis, constraints, quality gates (~6) |
| 15 | **Taint Analysis** ⚡NEW | Source/sink/sanitizer model. TOML-driven registry (extensible without code changes — add new sources/sinks/sanitizers via config, not code). Phase 1: intraprocedural (within-function dataflow tracking). Phase 2: interprocedural via function summaries (cross-function taint propagation). 9 CWE mappings: CWE-89 SQL injection, CWE-79 XSS, CWE-22 path traversal, CWE-78 command injection, CWE-918 SSRF, CWE-117 log injection, CWE-601 open redirect, CWE-90 LDAP injection, CWE-643 XPath injection. Taint label propagation with sanitizer tracking. Framework-specific taint specifications. SARIF code flow generation for taint paths. | Call graph, reachability, boundaries, OWASP/CWE mapping | Quality gates (security gate), violations, SARIF output, CI agent (~5) |
| 16 | **Error Handling Analysis** | 8-phase topology engine: (1) error type profiling (catalog all error/exception types), (2) handler detection (try/catch/rescue/recover patterns), (3) propagation chain tracing via call graph (which functions propagate which errors), (4) unhandled path identification (functions that can throw but callers don't catch), (5) gap analysis (empty catch, swallowed errors, generic catches), (6) framework-specific analysis (Express error middleware, Django exception handlers, Spring @ExceptionHandler, etc.), (7) CWE/OWASP A10:2025 mapping (Mishandling of Exceptional Conditions), (8) remediation suggestions. 20+ framework support (Express, Koa, Hapi, Fastify, Django, Flask, Spring, ASP.NET, Rails, Sinatra, Laravel, Phoenix, Gin, Echo, Actix, Rocket, NestJS, Next.js, Nuxt, SvelteKit). `error_boundaries`, `error_gaps`, `error_types` tables. | Call graph, parsers, OWASP/CWE mapping | Quality gates (error handling gate), constraints, violations, DNA (~5) |
| 17 | **Impact Analysis** | Blast radius computation (transitive caller analysis via call graph BFS). Dead code detection with 10 false-positive categories: entry points, event handlers, reflection targets, dependency injection, test utilities, framework hooks, decorators/annotations, interface implementations, conditional compilation, dynamic imports. Dijkstra shortest path + K-shortest paths for impact visualization. Risk scoring per function (5 factors: blast radius, sensitivity, test coverage, complexity, change frequency — weighted composite). | Call graph, reachability, test topology | Simulation engine, CI agent (`drift_impact`), quality gates, constraints (~5) |
| 18 | **Test Topology** | 45+ test frameworks (up from 35 in previous hierarchy). 7-dimension quality scoring: coverage breadth (% functions tested), coverage depth (avg call depth tested), assertion density (assertions per test), mock ratio (mocked vs real dependencies), test isolation (shared state detection), test freshness (time since last update), test stability (flakiness detection). 24 test smell detectors (e.g., mystery guest, eager test, lazy test, assertion roulette, test code duplication). Coverage mapping via call graph BFS (test function → tested functions). Minimum test set computation via greedy set cover algorithm. `test_files`, `test_cases`, `test_coverage`, `mock_statements`, `test_smells`, `uncovered_functions` tables. | Call graph, parsers, unified language provider | Quality gates (test coverage gate), simulation (test coverage scorer), CI agent, DNA (~5) |

### Tier 2C — Structural Intelligence (7 systems)

Architecture health, contracts, and the capstone DNA metric.

| # | System | Key Specs | Upstream Dependencies | Downstream Consumers (count) |
|---|--------|-----------|----------------------|------------------------------|
| 19 | **Coupling Analysis** | Tarjan's SCC via petgraph for cycle detection. Robert C. Martin instability metrics: Ce (efferent coupling), Ca (afferent coupling), I (instability = Ce/(Ce+Ca)), A (abstractness), D (distance from main sequence = |A+I-1|). 10-phase pipeline: (1) module boundary detection, (2) import graph construction, (3) afferent/efferent counting, (4) instability calculation, (5) abstractness calculation, (6) distance from main sequence, (7) SCC detection, (8) zone classification (Zone of Pain, Zone of Uselessness, Main Sequence), (9) cycle break suggestions, (10) trend tracking. `module_coupling`, `coupling_metrics` tables. | Call graph, parsers | DNA, simulation, quality gates, constraints (~5) |
| 20 | **Constraint System** | 12 invariant types: must_exist, must_not_exist, must_precede, must_follow, must_colocate, must_separate, data_flow, naming_convention, dependency_direction, layer_boundary, size_limit, complexity_limit. 10 categories. 4-stage pipeline: InvariantDetector → ConstraintSynthesizer → ConstraintStore → ConstraintVerifier. AST-based verification (not regex — replaces v1's regex approach). `FreezingArchRule` baseline: snapshot constraints at a point in time, fail on regression. Constraint mining from existing code patterns. `constraints`, `constraint_violations` tables. | Nearly everything in 2A and 2B as data sources, parsers, call graph | Quality gates (constraint gate), violations, audit, CI agent (~4) |
| 21 | **Contract Tracking** | REST + GraphQL + gRPC + AsyncAPI protocol support. 20+ framework extractors (Express, FastAPI, Spring, ASP.NET, Django REST, NestJS, Flask, Rails, Laravel, Gin, Echo, Actix, Rocket, Koa, Hapi, Phoenix, Fiber, Chi, Gorilla, Mux). BE↔FE matching via path similarity + schema compatibility scoring. Breaking change classifier: field removal, type change, required field addition, endpoint removal, method change, response shape change. GraphQL N+1 resolver detection. `contracts`, `contract_endpoints`, `contract_schemas`, `contract_mismatches` tables. | Parsers, unified language provider, boundaries | Quality gates, CI agent (breaking change detection), violations (~3) |
| 22 | **Constants & Environment** | 100+ secret patterns (API keys, tokens, connection strings, private keys, certificates, OAuth secrets, webhook secrets). Shannon entropy scoring for high-entropy string detection (flag even without pattern match). Magic number detection with AST-based contextual analysis (replaces v1 regex). `.env` file parsing with cross-reference to code usage (detect unused env vars, missing env vars). Contextual scoring: variable name weight, file path weight, proximity to auth code. Base64 decoding for encoded secrets. CWE-798 (hardcoded credentials), CWE-321 (hardcoded crypto key), CWE-547 (hardcoded security-relevant constant) mappings. `env_vars`, `env_files`, `constants`, `magic_numbers` tables. | Parsers, unified analysis engine | Security analysis, constraints, quality gates, OWASP mapping (~4) |
| 23 | **Wrapper Detection** | 8 framework detection patterns: logging wrappers, HTTP client wrappers, DB wrappers, cache wrappers, auth wrappers, validation wrappers, serialization wrappers, event wrappers. 150+ primitive function signatures (known library functions that wrappers delegate to). Thin delegation pattern detection (function that just calls another function with minor transformation). Clustering for wrapper family identification (group related wrappers). Security wrapper categories: auth, sanitization, crypto, CSRF, headers. | Call graph, parsers, unified language provider | Call graph accuracy improvement (collapse wrapper chains), DNA, coupling analysis (~3) |
| 24 | **DNA System** | 10 gene extractors: naming conventions (casing, prefixes, suffixes), error handling patterns (try/catch density, error propagation style), test patterns (test-to-code ratio, assertion style), import patterns (barrel files, deep imports, circular), type usage (any/unknown ratio, generics usage), documentation density (JSDoc/docstring coverage), complexity distribution (cyclomatic complexity histogram), coupling profile (instability, abstractness), security posture (vulnerability density, secret exposure), framework usage (framework-specific idiom adherence). Health scoring (0-100) per gene and aggregate. Mutation detection (gene drift between snapshots — which genes changed and by how much). Capstone metric — synthesizes all other analyses into a single codebase fingerprint. `dna_profiles`, `dna_genes`, `dna_comparisons` tables. | Coupling, constraints, test topology, error handling, patterns, confidence, boundaries | Simulation, audit, quality gates, MCP tools (~4) |
| 26 | **OWASP/CWE Mapping** | Every security detector → CWE IDs. OWASP 2025 Top 10 coverage: **10/10 categories** (upgraded from 9/10 conservative estimate — A03 Supply Chain has shallow coverage via dependency-audit only, all others have deep coverage). CWE Top 25 2025 coverage target: 25/25. SARIF taxonomy integration (CWE + OWASP tool components). Metadata enrichment layer — doesn't change what gets detected, adds compliance classification. Unified mapping registry (source of truth — other subsystems populate their CWE/OWASP fields from this registry). Finding enrichment pipeline. Security posture score (composite 0-100, multi-factor). Compliance report generator (OWASP summary, CWE summary, gap analysis). Maps to: A01 Broken Access Control, A02 Security Misconfiguration, A03 Supply Chain (shallow), A04 Cryptographic Failures, A05 Injection, A06 Vulnerable Components, A07 Auth Failures, A08 Data Integrity, A09 Logging Failures, A10 Mishandling of Exceptional Conditions. | Taint analysis, error handling, boundary detection, constants/environment, cryptographic failures | SARIF output, quality gates (security gate), CI agent, enterprise compliance (~4) |

### Tier 2D — Security Intelligence (2 systems)

Leaf security systems with high standalone value but minimal downstream consumers.

| # | System | Key Specs | Upstream Dependencies | Downstream Consumers (count) |
|---|--------|-----------|----------------------|------------------------------|
| 22* | **Enterprise Secret Detection** | 100+ regex patterns (API keys, tokens, connection strings, private keys, certificates). Shannon entropy scoring (flag high-entropy strings even without pattern match). Contextual scoring (variable name, file path, proximity to auth code). Base64 decoding for encoded secrets. 22 overlap with constants/environment system (shared pattern library). CWE-798, CWE-321, CWE-547 mappings. | Parsers, unified analysis engine | Violations, quality gates (security gate), SARIF output, OWASP mapping (~4) |
| 27 | **Cryptographic Failure Detection** ⚡NEW | 10 detection categories: weak hash detection (MD5, SHA1 in security contexts), deprecated cipher detection (DES, 3DES, RC4, Blowfish), ECB mode detection, static IV/nonce detection, hardcoded cryptographic keys, short key length detection (<2048 RSA, <256 ECC), disabled TLS verification, JWT alg=none, plaintext password storage, insufficient PRNG. Per-language patterns for Python, JS/TS, Java, C#, Go. OWASP A04:2025 (Cryptographic Failures) coverage. CWE-1439 category mapping (30+ member CWEs including CWE-261, CWE-296, CWE-319, CWE-321, CWE-326, CWE-327, CWE-328, CWE-329, CWE-330). | Parsers, unified analysis engine | Violations, quality gates, OWASP mapping, SARIF output (~4) |

---

## Level 3 — Enforcement (Consumes Intelligence, Produces Decisions)

These systems turn analysis into action. Without them, Drift is informational only.
**5 systems.**

| # | System | Key Specs | What It Consumes | Downstream Consumers (count) |
|---|--------|-----------|-----------------|------------------------------|
| — | **Rules Engine Evaluator** | Pattern matcher → violations → severity assignment → quick fixes (7 fix strategies: add import, rename, extract function, wrap in try/catch, add type annotation, add test, add documentation). Maps detected patterns + outliers to actionable violations with file/line/column locations, severity levels (error/warning/info/hint), and auto-fix suggestions. | Patterns, outliers, confidence | Quality gates, violations output, MCP tools, CLI, CI agent (~5) |
| 09 | **Quality Gates** | 6 gates: pattern compliance (are approved patterns followed?), constraint verification (are architectural constraints met?), security boundaries (are sensitive fields protected?), test coverage (is coverage above threshold?), error handling (are errors properly handled?), regression detection (has health score declined?). DAG-based gate orchestrator (gates can depend on other gates — security gate runs before compliance gate). 7 reporters: SARIF 2.1.0 (GitHub Code Scanning integration), GitHub Code Quality, GitLab Code Quality, JUnit XML (CI test frameworks), HTML (standalone reports), JSON (programmatic), console (human-readable). Progressive enforcement (warn → error over time, configurable ramp-up). `gate_snapshots`, `gate_runs` tables. | Nearly everything from Level 2 | CI agent, CLI (`drift check`), MCP tools, policy engine, audit (~6) |
| — | **Policy Engine** | 4 built-in policies: strict (all gates must pass at error level), standard (all gates must pass at warning level), lenient (only security + regression gates required), custom (user-defined gate selection + thresholds). 4 aggregation modes: all-must-pass, any-must-pass, weighted (per-gate weights), threshold (composite score ≥ N). Progressive enforcement ramp-up for new projects (start lenient, tighten over time). Per-gate override capability. | Quality gates | CI agent, CLI, MCP tools (~3) |
| 25 | **Audit System** | 5-factor health scoring: pattern compliance rate (% approved patterns followed), security posture (vulnerability density + exposure), test coverage (% functions with tests), error handling completeness (% error paths handled), constraint satisfaction (% constraints passing). Degradation detection: health score declining over time, ±0.02 threshold to avoid noise from minor fluctuations. Trend prediction via linear regression on `health_trends` table. Auto-approve patterns meeting stability criteria (high confidence + consistent for N scans). `audit_snapshots`, `audit_health`, `audit_degradation` tables. | Patterns, confidence, outliers, quality gates, DNA | MCP tools (`drift_status`), CLI, dashboard, CI agent (~4) |
| 31 | **Violation Feedback Loop** | Tricorder-style false-positive tracking per detector (inspired by Google's Tricorder paper, Sadowski et al. CACM 2018). Metrics: FP rate (% violations dismissed as false positive), dismissal rate (% violations dismissed for any reason), action rate (% violations that led to code changes). Auto-disable rule: >20% FP rate sustained for 30+ days → detector disabled with notification via `on_detector_disabled` event. Feeds back into confidence scoring (dismissed violations reduce pattern confidence by adjusting Beta distribution parameters). Per D5: violation feedback events (`on_violation_dismissed`, `on_detector_disabled`) emitted via DriftEventHandler. `violation_feedback` table. | Violations, patterns, confidence, detector system | Confidence scoring (feedback), detector health, audit, bridge (via events) (~4) |

**D5 impact on L3**: Every enforcement action that changes state (pattern approved, violation dismissed, gate failed, detector disabled) emits a typed event via DriftEventHandler. In standalone mode these are no-ops. When the bridge is active, they become Cortex memories.

---

## Level 4 — Advanced / Capstone Systems (4 systems)

High-value features built on top of the full stack. Impressive but they're leaves — nothing else depends on them.

| # | System | Key Specs | Why Level 4 |
|---|--------|-----------|-------------|
| 28 | **Simulation Engine** | 13 task categories: add feature, fix bug, refactor, migrate framework, add test, security fix, performance optimization, dependency update, API change, database migration, config change, documentation, infrastructure. 4 scorers: complexity (cyclomatic + cognitive), risk (blast radius + sensitivity), effort (LOC estimate + dependency count), confidence (test coverage + constraint satisfaction). Monte Carlo simulation for effort estimation with confidence intervals (P10/P50/P90). 15 strategy recommendations (e.g., "start with tests", "refactor first", "feature flag rollout"). | Pure consumer of call graph + patterns + constraints + test topology + DNA + impact analysis. Produces recommendations, doesn't feed core analysis. |
| 29 | **Decision Mining** | `git2` crate integration for commit history analysis. ADR (Architecture Decision Record) detection in markdown files. 12 decision categories: technology choice, pattern adoption, pattern abandonment, dependency addition, dependency removal, API design, schema change, security policy, test strategy, deployment strategy, configuration change, refactoring approach. Temporal correlation with pattern changes (did a decision precede a pattern shift?). | Consumes patterns + git history + DNA. Doesn't feed core analysis. Enrichment system. |
| 30 | **Context Generation** | Unified context engine for AI consumption. 15 package manager support: npm, yarn, pnpm, pip, poetry, pipenv, cargo, go mod, maven, gradle, nuget, composer, bundler, cocoapods, swift PM. Token budgeting with model-aware limits (different budgets for Claude, GPT-4, Gemini, local models). Intent-weighted context selection (different context for "fix bug" vs "add feature" vs "understand code" vs "security audit"). 3 output formats: markdown (human-readable), JSON (programmatic), SARIF (compliance). Per D3: feeds drift-analysis MCP server only — no Cortex dependency. | Pure consumer. Powers MCP tools (`drift_context`). Doesn't feed other analysis systems. |
| — | **N+1 Query Detection** | Call graph + ORM pattern matching → loop-query anti-pattern detection. Detects: N+1 SELECT in loops, missing eager loading, lazy loading in serialization contexts. Framework-specific: ActiveRecord (includes/preload), Django ORM (select_related/prefetch_related), SQLAlchemy (joinedload/subqueryload), Hibernate (FetchType.EAGER/@BatchSize), Entity Framework (Include/ThenInclude), Prisma (include/select), Sequelize (include with model), TypeORM (relations/eager). Implementation split: detection logic in `08-UNIFIED-LANGUAGE-PROVIDER` (`n_plus_one.rs`), GraphQL N+1 resolver detection in `21-CONTRACT-TRACKING`. Event: `on_n_plus_one_detected` via DriftEventHandler. | High value, narrow scope. Leaf system. |

---

## Level 5 — Presentation (Pure Consumers)

### 5A — Drift Standalone (No Cortex Dependency)

Per D1 and D3, these work with drift.db alone. This is the complete Drift product.

| # | System | Key Specs | Priority | Rationale |
|---|--------|-----------|----------|-----------|
| 32 | **drift-analysis MCP Server** | ~20-25 tools with `drift_*` namespace. Progressive disclosure with 3 entry points: `drift_status` (overview — reads `materialized_status` singleton, <1ms), `drift_context` (deep dive, replaces 3-5 calls, intent-weighted), `drift_scan` (trigger analysis). Read-only drift.db access via ReadPool. stdio transport (primary) + HTTP/SSE transport (Docker/containerized). Cache TTL configurable via `McpConfig.cache_ttl_seconds` (default 300s). Token budgeting for AI context windows via `McpConfig.max_response_tokens` (default 8000). Split architecture: drift-analysis (standalone) vs drift-memory (bridge-dependent, separate registration). | #1 | How AI agents consume Drift. The primary interface for Claude, Cursor, Copilot, and any MCP-compatible client. |
| — | **CLI** | 48-65+ commands across subcommands: `drift scan`, `drift check`, `drift status`, `drift patterns`, `drift violations`, `drift impact`, `drift simulate`, `drift audit`, `drift setup`, `drift doctor`, `drift export`, `drift explain`, `drift fix`. Setup wizard for first-time configuration (`drift setup` creates drift.toml + .driftignore). `drift doctor` health checks (db integrity, config validation, grammar availability). Git integration. Multiple output formats (table, JSON, SARIF). | #2 | How developers and CI consume Drift directly. The human interface. |
| 09* | **Quality Gate Reporters** | 7 output formats: SARIF 2.1.0 (GitHub Code Scanning integration — critical for GitHub Advanced Security), GitHub Code Quality, GitLab Code Quality, JUnit XML (CI test frameworks), HTML (standalone reports), JSON (programmatic), console (human-readable). SARIF includes CWE + OWASP taxonomies from the mapping registry. | #3 | Output formatting. Makes quality gates useful in CI/CD pipelines. |
| 34 | **CI Agent & GitHub Action** | 9 parallel analysis passes: scan, patterns, call graph, boundaries, security, tests, errors, contracts, constraints. PR-level incremental analysis (only changed files + transitive dependents via impact analysis). SARIF upload to GitHub Code Scanning. Comment generation for PR reviews (summary of findings, breaking changes, new violations). GitHub Action v2 with split MCP server support (drift-analysis only in CI, no drift-memory). Configurable fail conditions via policy engine. | #4 | Automated enforcement in CI/CD. Makes Drift useful without human intervention. |
| — | **VSCode Extension** | Inline violation highlighting. Quick fix suggestions (from rules engine's 7 fix strategies). Pattern explorer sidebar. Health score status bar. Go-to-definition for patterns. Violation hover tooltips. | #5 | Editor integration for real-time feedback. |
| — | **LSP Server** | Language Server Protocol implementation. IDE-agnostic (works with any LSP client: Neovim, Emacs, Sublime, etc.). Diagnostics (violations as LSP diagnostics), code actions (quick fixes), hover information (pattern details, confidence scores). | #6 | IDE-agnostic integration beyond VSCode. |
| — | **Dashboard** | Web visualization (Vite + React + Tailwind). Health score trends (from `health_trends` table). Pattern explorer. Violation browser. Call graph visualization. Security posture overview (from `materialized_security`). | #7 | Visual exploration for non-CLI users. |
| — | **Galaxy** | 3D codebase visualization (Three.js). Module clustering. Coupling visualization (zones of pain/uselessness from coupling analysis). Stays TS/React. | #8 | Impressive demo, lowest structural priority. |

### 5B — Bridge-Dependent Presentation (Requires Cortex + Drift)

Per D1/D3/D4, these only exist when both systems are detected. They are structurally optional — Drift is complete without them.

| System | Key Specs | Why 5B |
|--------|-----------|--------|
| **drift-memory MCP Server** | ~15-20 tools with `drift_memory_*` namespace. Read/write cortex.db + read drift.db. Only registers when Cortex detected at startup. | Per D3: separate from drift-analysis. Requires cortex.db to exist. |
| **Bridge MCP Tools** | `drift_why` (synthesizes pattern data + causal memory), `drift_memory_learn` (create memory from Drift analysis), `drift_grounding_check` (verify memory against codebase reality). Registered conditionally by drift-analysis server when Cortex available. | Per D4: bridge crate is a leaf. These tools need both systems. |
| **Grounding Feedback Loop** | Drift scan results validate Cortex memories. Confidence adjustment based on codebase reality. Memory flagged for review when grounding drops below threshold. Per D7: the killer integration feature — first AI memory system with empirically validated memory. | Drift doesn't know or care that grounding is happening. It computes accurate data; the bridge consumes it. |
| **Event-Driven Memory Creation** | Drift events → Cortex memories via bridge's DriftEventHandler implementation. 6 bridge responsibilities: event mapping, link translation (PatternLink → EntityLink per D2), grounding logic, grounding feedback loop, intent extensions, combined MCP tools. `pattern:approved` → `pattern_rationale` memory. `regression:detected` → `decision_context` memory. `violation:dismissed` → `constraint_override` memory. `detector:disabled` → `anti_pattern` memory. Additional event sources: decision mining (`on_decision_mined`, `on_decision_reversed`, `on_adr_detected`), boundary detection (`on_boundary_discovered`), error handling (via pipeline error events), coupling analysis (coupling snapshot at scan complete), DNA system (DNA health score at scan complete). | Per D5: Drift emits events; what happens to them is not Drift's concern. The bridge implements the handler. |

**Key structural insight from D4/D7**: The grounding loop is the most valuable feature of the *product*, but it's a leaf in Drift's hierarchy. Drift's job is to compute accurate confidence scores, emit events, and write clean data to drift.db. The bridge's job is to consume that data and make Cortex memories empirically validated. Drift doesn't need to know the bridge exists.

---

## Level 6 — Infrastructure / Cross-Cutting

These systems run parallel to the analysis stack. They don't block analysis but are required for a shippable product.

| # | System | Key Specs | When Needed | Criticality |
|---|--------|-----------|-------------|-------------|
| 33 | **Workspace Management** | First thing that runs. drift.db lifecycle (create, open, migrate, backup, vacuum). Workspace detection (find project root). `drift setup` wizard (creates drift.toml + .driftignore). `drift doctor` health checks (db integrity via `PRAGMA integrity_check`, config validation, grammar availability, disk space). Per D6: handles ATTACH cortex.db when bridge is active. Backup via SQLite Backup API (hot backup, no downtime, copies db while readers/writer active). Process-level locking via `fd-lock` (prevents two Drift instances from writing to same drift.db). | Before first user interaction | High |
| — | **Licensing & Feature Gating** | 3 tiers: Community (free, core analysis — scanner, parsers, detectors, patterns, basic gates), Professional (advanced analysis + CI — taint, coupling, contracts, simulation, CI agent, all reporters), Enterprise (full stack + OWASP compliance reports + telemetry + blake3 hashing + OpenTelemetry). 16 gated features. JWT validation for license keys. Graceful degradation (features disabled, not errored — gated features return "upgrade required" message). | Before public release | Medium |
| 34 | **GitHub Action** | Reusable GitHub Action for CI integration. SARIF upload to GitHub Code Scanning. PR comment generation (findings summary, breaking changes, new violations). Configurable analysis passes (select which of the 9 passes to run). Split MCP server support (drift-analysis only in CI, no drift-memory). | When CI ships | Medium |
| — | **Docker Deployment** | Multi-arch Alpine images (amd64 + arm64). Pre-built native binaries (no compilation in container). HTTP/SSE MCP transport for containerized deployment (stdio doesn't work in Docker). Per D3: containerize drift-analysis and drift-memory servers independently. | When HTTP MCP transport ships | Medium |
| — | **Telemetry** | Cloudflare Worker + D1 backend. Anonymous usage metrics: scan count, file count, language distribution, gate pass/fail rates, analysis duration, feature usage. Opt-in only (default: disabled). Rust-side event emission via DriftEventHandler. TS-side collection + batched upload. | Post-launch | Low |
| — | **AI Providers** | Anthropic, OpenAI, Ollama abstraction layer. Powers `drift explain` (explain a pattern/violation in natural language) and `drift fix` (suggest code fix for a violation). Stays in TS (packages/ai). Model-agnostic interface. | When explain/fix ships | Low |
| — | **CIBench** | 4-level benchmark framework: micro (criterion — individual function benchmarks), component (integration — subsystem benchmarks), system (end-to-end — full pipeline benchmarks), regression (CI — track performance over time, fail on regression). Isolated in `drift-bench` crate to keep benchmark dependencies out of production. | When benchmarking | Low |

---

## Cargo Workspace Structure (from 04-INFRASTRUCTURE-V2-PREP)

v1 had 2 crates. v2 expands to 5-6 crates with feature flags:

| Crate | Responsibility | Why Separate |
|-------|---------------|--------------|
| `drift-core` | Types, traits, errors, config, event system, data structures | Foundation — everything depends on this |
| `drift-analysis` | Parsers, detectors, call graph, boundaries, coupling, all analysis | Separates parsing (fast, stateless) from persistence |
| `drift-storage` | SQLite persistence, migrations, batch writer, CQRS, refresh pipeline | Schema changes don't recompile parsers |
| `drift-napi` | NAPI-RS v3 bindings, singleton runtime, async tasks | Bridge layer — depends on all above |
| `drift-bench` | Benchmarks (criterion) — isolated from production | Benchmark deps don't pollute production |

Feature flags: `default = ["cortex", "mcp"]`, `cortex` (bridge support), `mcp`, `wasm`, `benchmark`, `otel` (OpenTelemetry), `lang-python`, `lang-java`, `lang-rust`, `full`.

Key workspace dependencies: `tree-sitter` v0.24, `rusqlite` v0.32 (bundled), `napi` v3, `thiserror` v2, `tracing` v0.1, `rustc-hash` v2, `smallvec` v1.13, `lasso` v0.7, `rayon` v1.10, `xxhash-rust` v0.8, `petgraph` v0.6, `moka` v0.12, `ignore` v0.4, `crossbeam-channel` v0.5.

Release profile: `lto = true`, `codegen-units = 1`, `opt-level = 3`, `strip = "symbols"`.

TS workspace (pnpm + Turborepo): `packages/mcp`, `packages/cli`, `packages/ci`, `packages/ai`, `packages/vscode`, `packages/lsp`, `packages/dashboard`, `packages/galaxy`, `packages/cibench`.

---

## The Critical Path (15 Systems)

The minimum stack to deliver Drift's core value, incorporating all planning decisions:

```
Level 0 — Bedrock:
  Config + thiserror + tracing + DriftEventHandler (scaffolded, no-op defaults)
    │
Level 0 — Entry:
    ├→ Scanner (file walking via ignore crate, xxh3 hashing, .driftignore)
    │    │
    │    ├→ Parsers (10 langs, tree-sitter, thread_local!, Moka cache)
    │    │    │
Level 1 — Skeleton:
    │    │    ├→ String Interning (lasso — ThreadedRodeo → RodeoReader)
    │    │    │    │
    │    │    │    ├→ Unified Analysis Engine (4-phase AST+regex pipeline)
    │    │    │    │    │
    │    │    │    │    ├→ Detector System (16 categories × 3 variants, 350+ detectors)
    │    │    │    │    │    │
Level 2A — Pattern Intelligence:
    │    │    │    │    │    ├→ Learning System (Bayesian convention discovery)
    │    │    │    │    │    │    │
    │    │    │    │    │    │    ├→ Confidence Scoring (Beta posterior + momentum)
    │    │    │    │    │    │    │    │
    │    │    │    │    │    │    │    ├→ Outlier Detection (Z-Score/Grubbs'/ESD/IQR/MAD)
    │    │    │    │    │    │    │    │    │
    │    │    │    │    │    │    │    │    ├→ Pattern Aggregation (Jaccard + MinHash LSH)
    │    │    │    │    │    │    │    │    │    │
Level 3 — Enforcement:
    │    │    │    │    │    │    │    │    │    ├→ Rules Engine (violations + severity + quick fixes)
    │    │    │    │    │    │    │    │    │    │    │
Level 0 — Persistence + Bridge:
    │    │    │    │    │    │    │    │    │    │    ├→ Storage (drift.db — standalone, no ATTACH)
    │    │    │    │    │    │    │    │    │    │    │    │
    │    │    │    │    │    │    │    │    │    │    │    ├→ NAPI Bridge (drift-napi, napi-rs v3)
    │    │    │    │    │    │    │    │    │    │    │    │    │
Level 5A — Presentation:
    │    │    │    │    │    │    │    │    │    │    │    │    └→ CLI (drift scan + drift check)
```

That's **15 systems** on the critical path (was 12 before planning doc added infrastructure requirements).

### Branch Points Off the Spine

```
Branch 1 (from Call Graph — highest leverage, unlocks 7 systems):
  Call Graph → Reachability → Taint Analysis (⚡NEW, 9 CWE mappings)
                            → Impact Analysis → Dead Code (10 FP categories)
                            → Error Handling Analysis (8-phase, 20+ frameworks)
                            → Test Topology (45+ frameworks, 24 smell detectors)
                            → Coupling Analysis (Tarjan SCC, Martin metrics)
  Unlocks: 7 Level 2B/2C systems, ~12 downstream consumers

Branch 2 (from Rules Engine — enforcement chain):
  Rules Engine → Quality Gates (6 gates, DAG orchestrator) → Policy Engine (4 modes) → Audit System (5-factor health)
  Unlocks: CI enforcement, progressive adoption, health monitoring

Branch 3 (from Unified Language Provider — ORM intelligence):
  ULP → Boundary Detection (33+ ORMs, 10 extractors) → N+1 Detection (8 frameworks)
      → Contract Tracking (4 protocols, 20+ extractors)
  Unlocks: Security boundaries, API contract verification

Branch 4 (optional, bridge-dependent):
  DriftEventHandler consumers → Bridge Crate (6 responsibilities) → Cortex Memory Creation → Grounding Loop
  Unlocks: D7's killer feature, but architecturally the last thing that needs to work
```

---

## Visual Dependency Map

```
  ┌──────────────────────────────────────────────────────────────────┐
  │                    BRIDGE-DEPENDENT (L5B) — Optional              │
  │  drift-memory MCP · Bridge Tools · Grounding Loop                 │
  │  Event→Memory (6 responsibilities) · drift_why · drift_grounding  │
  │  ← Requires Cortex + Drift both present (D1/D4) →                │
  └──────────────────────────────┬───────────────────────────────────┘
                                 │ (consumes drift.db via ATTACH, D6)
  ┌──────────────────────────────┴───────────────────────────────────┐
  │                    DRIFT STANDALONE (L5A)                          │
  │  drift-analysis MCP (~25 tools) · CLI (48-65+ cmds)               │
  │  VSCode · LSP · CI Agent (9 passes) · Dashboard · Galaxy          │
  │  Reporters: SARIF 2.1.0 · GitHub · GitLab · JUnit · HTML · JSON   │
  └──────────────────────────────┬───────────────────────────────────┘
                                 │
  ┌──────────────────────────────┴───────────────────────────────────┐
  │                    ADVANCED / CAPSTONE (L4)                        │
  │  Simulation (13 tasks, Monte Carlo, P10/P50/P90)                   │
  │  Decision Mining (git2, ADR, 12 categories)                        │
  │  Context Generation (15 pkg mgrs, token budgets, intent-weighted)  │
  │  N+1 Detection (8 ORM frameworks, GraphQL resolvers)               │
  └──────────────────────────────┬───────────────────────────────────┘
                                 │
  ┌──────────────────────────────┴───────────────────────────────────┐
  │                    ENFORCEMENT (L3)                                │
  │  Rules Engine (7 fix strategies)                                   │
  │  Quality Gates (6 gates, 7 reporters, DAG orchestrator)            │
  │  Policy Engine (4 modes, progressive ramp-up)                      │
  │  Audit (5-factor health, degradation ±0.02, linear regression)     │
  │  Violation Feedback Loop (Tricorder-style, auto-disable >20%/30d)  │
  │  ← All emit DriftEventHandler events (D5) →                       │
  └──────────────────────────────┬───────────────────────────────────┘
                                 │
     ┌───────────────────────────┼───────────────────────────────────┐
     │                           │                                   │
  ┌──┴──────────────┐  ┌───────┴──────────┐  ┌────────────────────┴──┐
  │ PATTERN (2A)     │  │ GRAPH (2B)        │  │ STRUCTURAL (2C)       │
  │ Confidence (β)   │  │ Reachability      │  │ Coupling (Tarjan SCC) │
  │ Outlier (6 meth) │  │ Taint ⚡NEW       │  │ Constraints (12 inv)  │
  │ Aggregation      │  │  (9 CWE, TOML)   │  │ Contracts (4 proto)   │
  │  (Jaccard+LSH)   │  │ Impact + Dead Code│  │ Constants + Env       │
  │ Learning (Bayes) │  │  (10 FP cats)     │  │  (100+ secrets)       │
  │  (5 categories)  │  │ Error Handling    │  │ Wrapper Detection     │
  │                  │  │  (8-phase, 20+ fw)│  │  (150+ primitives)    │
  │                  │  │ Test Topology     │  │ DNA (10 genes)        │
  │                  │  │  (45+ fw, 24 smls)│  │ OWASP/CWE (10/10)    │
  └──────┬──────────┘  └───────┬───────────┘  └──────────┬───────────┘
         │                     │                          │
  ┌──────┴─────────────────────┴──────────────────────────┘
  │                                                    ┌──────────────┐
  │              SKELETON (L1)                         │ SECURITY (2D) │
  │  Unified Analysis Engine (4-phase, GAST ~30 nodes) │ Secrets (100+)│
  │  Call Graph (petgraph, 6 strategies, incremental)  │ Crypto ⚡NEW  │
  │  Detector System (16 cat × 3 var, 350+)            │  (10 cats)    │
  │  Boundary Detection (33+ ORMs, 10 extractors)      └──────────────┘
  │  Unified Language Provider (9 normalizers, 22 matchers)
  │  String Interning (lasso, 60-80% mem reduction)
  └──────────────────────┬──────────────────────────────┘
                         │
  ┌──────────────────────┴──────────────────────────────┐
  │              BEDROCK (L0) — 8 Systems                 │
  │  Parsers (10 langs, tree-sitter v0.24)                │
  │  Scanner (ignore v0.4, xxh3, 2-level incremental)     │
  │  SQLite Storage (drift.db, WAL, 40+ STRICT, CQRS)    │
  │  NAPI Bridge (napi-rs v3, 8 targets, ~40+ functions)  │
  │  thiserror (per-subsystem enums, 14+ NAPI codes)      │
  │  tracing (structured spans, EnvFilter, 12+ metrics)   │
  │  DriftEventHandler (16+ events, no-op defaults, D5)   │
  │  Configuration (TOML, 4-layer resolution)             │
  └──────────────────────────────────────────────────────┘
```

---

## Consumer Count Summary (Systems Ranked by Downstream Impact)

How many other systems break or lose capability if this system doesn't exist:

| Rank | System | Downstream Consumers | Level |
|------|--------|---------------------|-------|
| 1 | Config + thiserror + tracing + Events | ~35+ (everything) | L0 |
| 2 | Tree-Sitter Parsers | ~30+ (every analysis) | L0 |
| 3 | Scanner | ~30+ (transitively) | L0 |
| 4 | SQLite Storage (drift.db) | ~30+ (everything persisted) | L0 |
| 5 | NAPI Bridge | ~8 (all presentation) | L0 |
| 6 | String Interning | ~15 (all identifier-heavy systems) | L1 |
| 7 | Call Graph Builder | ~12 (reachability, taint, impact, errors, tests, coupling, constraints, simulation, N+1, contracts, wrappers, DNA) | L1 |
| 8 | Detector System | ~10 (patterns, violations, confidence, outliers, DNA, constraints, gates, audit, learning, feedback) | L1 |
| 9 | Unified Analysis Engine | ~10 (detectors, patterns, confidence, outliers, violations, DNA, constraints, constants, crypto) | L1 |
| 10 | Bayesian Confidence Scoring | ~7 (outliers, gates, audit, learning, rules, grounding, feedback) | L2A |
| 11 | Boundary Detection | ~7 (security, taint, reachability, constraints, gates, OWASP, N+1) | L1 |
| 12 | Quality Gates | ~6 (CI agent, CLI, MCP, policy, audit, reporters) | L3 |
| 13 | Reachability Analysis | ~6 (taint, impact, security, constraints, gates) | L2B |
| 14 | Pattern Aggregation | ~6 (confidence, outliers, learning, rules, DNA) | L2A |
| 15 | Unified Language Provider | ~6 (boundaries, N+1, contracts, language intel, wrappers, taint integration) | L1 |
| 16 | Outlier Detection | ~6 (violations, rules, gates, audit, feedback) | L2A |
| 17 | OWASP/CWE Mapping | ~5 (SARIF, gates, CI agent, taint, error handling) | L2C |
| 18 | Learning System | ~5 (pattern lifecycle, gates, audit, DNA) | L2A |
| 19 | Test Topology | ~5 (gates, simulation, CI agent, DNA, impact) | L2B |
| 20 | Impact Analysis | ~5 (simulation, CI agent, gates, constraints) | L2B |
| 21 | Error Handling Analysis | ~5 (gates, constraints, violations, DNA, OWASP A10) | L2B |
| 22 | Taint Analysis | ~5 (gates, violations, SARIF, CI agent, OWASP) | L2B |
| 23 | Coupling Analysis | ~5 (DNA, simulation, gates, constraints) | L2C |
| 24-60 | All remaining systems | 0-4 each | L2C-L6 |

---

## V2-PREP Document Coverage Matrix

Cross-reference of every system against its V2-PREP document status:

| System | V2-PREP Document | Status |
|--------|-----------------|--------|
| Configuration System | 04-INFRASTRUCTURE-V2-PREP.md §5 | ✅ Fully specified |
| thiserror Error Enums | 04-INFRASTRUCTURE-V2-PREP.md §2 | ✅ Fully specified |
| tracing Instrumentation | 04-INFRASTRUCTURE-V2-PREP.md §3 | ✅ Fully specified |
| DriftEventHandler Trait | 04-INFRASTRUCTURE-V2-PREP.md §4 | ✅ Fully specified |
| Tree-Sitter Parsers | 01-PARSERS.md (v1 reference) | ⚠️ No dedicated V2-PREP (covered in scanner + infrastructure) |
| Scanner | 00-SCANNER-V2-PREP.md | ✅ Fully specified |
| SQLite Storage | 02-STORAGE-V2-PREP.md | ✅ Fully specified |
| NAPI Bridge | 03-NAPI-BRIDGE-V2-PREP.md | ✅ Fully specified |
| Unified Analysis Engine | 06-UNIFIED-ANALYSIS-ENGINE-V2-PREP.md | ✅ Fully specified |
| Call Graph Builder | 05-CALL-GRAPH-V2-PREP.md | ✅ Fully specified |
| Detector System | 06-DETECTOR-SYSTEM.md (v1 reference) | ⚠️ No dedicated V2-PREP (covered in unified analysis engine) |
| Boundary Detection | 07-BOUNDARY-DETECTION-V2-PREP.md | ✅ Fully specified |
| Unified Language Provider | 08-UNIFIED-LANGUAGE-PROVIDER-V2-PREP.md | ✅ Fully specified |
| String Interning | 04-INFRASTRUCTURE-V2-PREP.md §6 | ✅ Fully specified |
| Bayesian Confidence Scoring | 10-BAYESIAN-CONFIDENCE-SCORING-V2-PREP.md | ✅ Fully specified |
| Outlier Detection | 11-OUTLIER-DETECTION-V2-PREP.md | ✅ Fully specified |
| Pattern Aggregation | 12-PATTERN-AGGREGATION-V2-PREP.md | ✅ Fully specified |
| Learning System | 13-LEARNING-SYSTEM-V2-PREP.md | ✅ Fully specified |
| Reachability Analysis | 14-REACHABILITY-ANALYSIS-V2-PREP.md | ✅ Fully specified |
| Taint Analysis ⚡ | 15-TAINT-ANALYSIS-V2-PREP.md | ✅ Fully specified |
| Error Handling Analysis | 16-ERROR-HANDLING-ANALYSIS-V2-PREP.md | ✅ Fully specified |
| Impact Analysis | 16-IMPACT-ANALYSIS-V2-PREP.md + 17-IMPACT-ANALYSIS-V2-PREP.md | ✅ Fully specified (note: duplicate numbering — both 16 and 17 exist) |
| Test Topology | 18-TEST-TOPOLOGY-V2-PREP.md | ✅ Fully specified |
| Coupling Analysis | 19-COUPLING-ANALYSIS-V2-PREP.md | ✅ Fully specified |
| Constraint System | 20-CONSTRAINT-SYSTEM-V2-PREP.md | ✅ Fully specified |
| Contract Tracking | 21-CONTRACT-TRACKING-V2-PREP.md | ✅ Fully specified |
| Constants & Environment | 22-CONSTANTS-ENVIRONMENT-V2-PREP.md | ✅ Fully specified |
| Wrapper Detection | 23-WRAPPER-DETECTION-V2-PREP.md | ✅ Fully specified |
| DNA System | 24-DNA-SYSTEM-V2-PREP.md | ✅ Fully specified |
| Audit System | 25-AUDIT-SYSTEM-V2-PREP.md | ✅ Fully specified |
| OWASP/CWE Mapping | 26-OWASP-CWE-MAPPING-V2-PREP.md | ✅ Fully specified |
| Cryptographic Failure Detection ⚡ | 27-CRYPTOGRAPHIC-FAILURE-DETECTION-V2-PREP.md | ✅ Fully specified |
| Simulation Engine | 28-SIMULATION-ENGINE-V2-PREP.md | ✅ Fully specified |
| Decision Mining | 29-DECISION-MINING-V2-PREP.md | ✅ Fully specified |
| Context Generation | 30-CONTEXT-GENERATION-V2-PREP.md | ✅ Fully specified |
| Violation Feedback Loop | 31-VIOLATION-FEEDBACK-LOOP-V2-PREP.md | ✅ Fully specified |
| MCP Server | 32-MCP-SERVER-V2-PREP.md | ✅ Fully specified |
| Workspace Management | 33-WORKSPACE-MANAGEMENT-V2-PREP.md | ✅ Fully specified |
| CI Agent & GitHub Action | 34-CI-AGENT-GITHUB-ACTION-V2-PREP.md | ✅ Fully specified |
| Cortex-Drift Bridge | 34-CORTEX-DRIFT-BRIDGE-V2-PREP.md | ✅ Fully specified |
| Rules Engine | 09-QUALITY-GATES-V2-PREP.md (subsection) | ⚠️ No dedicated V2-PREP |
| Policy Engine | 09-QUALITY-GATES-V2-PREP.md (subsection) | ⚠️ No dedicated V2-PREP |
| N+1 Query Detection | 08-UNIFIED-LANGUAGE-PROVIDER-V2-PREP.md + 21-CONTRACT-TRACKING-V2-PREP.md | ⚠️ No dedicated V2-PREP (split across two docs) |
| Licensing & Feature Gating | 04-INFRASTRUCTURE-V2-PREP.md (subsection) | ⚠️ No dedicated V2-PREP |
| AI Providers | — | ❌ No V2-PREP document |
| CIBench | — | ❌ No V2-PREP document |
| Galaxy | — | ❌ No V2-PREP document |
| VSCode Extension | — | ❌ No V2-PREP document |
| LSP Server | — | ❌ No V2-PREP document |
| Dashboard | — | ❌ No V2-PREP document |
| CLI | — | ❌ No V2-PREP document |
| Docker Deployment | — | ❌ No V2-PREP document |
| Telemetry | — | ❌ No V2-PREP document |

---

## What's New Since the Previous Hierarchy

| Change | Details | Source |
|--------|---------|--------|
| **Taint Analysis (#15) is NET NEW** | Source/sink/sanitizer model, TOML-driven registry, intraprocedural + interprocedural via summaries, 9 CWE mappings. Didn't exist in previous hierarchy. | 15-TAINT-ANALYSIS-V2-PREP |
| **Cryptographic Failure Detection (#27) is NET NEW** | 10 detection categories, weak hashes, deprecated ciphers, ECB mode, static IV, OWASP A04, CWE-1439 (30+ member CWEs). Per-language patterns for 5 languages. Didn't exist in previous hierarchy. | 27-CRYPTOGRAPHIC-FAILURE-DETECTION-V2-PREP |
| **OWASP coverage upgraded 9/10 → 10/10** | V2-PREP resolved: all 10 OWASP 2025 categories have at least one detector. A03 (Supply Chain) has shallow coverage (dependency-audit only). The "9/10" was a conservative estimate. | 26-OWASP-CWE-MAPPING-V2-PREP §inconsistency #5 |
| **Boundary Detection field extractors: 7 → 10** | 7 from v1 + 3 new (EfCoreExtractor, HibernateExtractor, EloquentExtractor per OR5 recommendation). Previous hierarchy said "7 field extractors". | 07-BOUNDARY-DETECTION-V2-PREP §6 |
| **Error Handling expanded to 8-phase engine** | Was 4-phase in previous hierarchy. Now: profiling → handler detection → propagation → unhandled paths → gap analysis → framework-specific → CWE/OWASP A10 → remediation. 20+ frameworks. | 16-ERROR-HANDLING-ANALYSIS-V2-PREP |
| **Test Topology expanded to 45+ frameworks** | Was 35+ in previous hierarchy. Added 7-dimension quality scoring, 24 test smell detectors, greedy set cover for minimum test set. | 18-TEST-TOPOLOGY-V2-PREP |
| **Boundary Detection expanded to 33+ ORMs** | Was 28+ in previous hierarchy. +5 new: MikroORM, Kysely, sqlc, SQLBoiler, Qt SQL. | 07-BOUNDARY-DETECTION-V2-PREP |
| **Scanner uses `ignore` crate v0.4** | Previous hierarchy said `walkdir + rayon`. V2-PREP resolved this: `ignore` crate (from ripgrep) for parallel walking + native gitignore, `rayon` for post-discovery processing. | 00-SCANNER-V2-PREP |
| **NAPI Bridge uses napi-rs v3** | Previous hierarchy didn't specify version. V2-PREP specifies v3 (July 2025) with wasm32 fallback, redesigned ThreadsafeFunction, lifetime safety. 8 platform targets. No `compat-mode`. | 03-NAPI-BRIDGE-V2-PREP |
| **Storage fully specified** | Previous hierarchy said "40+ tables". V2-PREP specifies: Medallion architecture (Bronze/Silver/Gold), CQRS, batch writer via crossbeam bounded(1024), keyset pagination with composite cursors, covering/partial/expression indexes, JSONB, `rusqlite_migration`, WAL 3-tier checkpoint, Silver tables by domain (15 domains, 50+ tables). | 02-STORAGE-V2-PREP |
| **Infrastructure fully specified** | Previous hierarchy listed 4 bedrock items. V2-PREP specifies: per-subsystem error enums with 14+ NAPI error codes, tracing with 12+ named metrics, full DriftEventHandler trait (16+ events with method signatures), TOML config with 4-layer resolution and 7 config sections, data structures (FxHashMap via rustc-hash v2, SmallVec v1.13, BTreeMap, lasso v0.7). Cargo workspace expanded to 5-6 crates with feature flags. | 04-INFRASTRUCTURE-V2-PREP |
| **Simulation Engine expanded** | Was "13 task categories, 15 strategies, 4 scorers". V2-PREP adds Monte Carlo simulation for effort estimation with confidence intervals (P10/P50/P90). | 28-SIMULATION-ENGINE-V2-PREP |
| **Quality Gates expanded to 7 reporters** | Was "SARIF + GitHub + GitLab + JUnit + HTML". V2-PREP adds JSON and console reporters, DAG-based gate orchestrator, progressive enforcement. | 09-QUALITY-GATES-V2-PREP |
| **Violation Feedback Loop fully specified** | Was mentioned but not detailed. V2-PREP specifies Tricorder-style FP tracking (Sadowski et al. CACM 2018), auto-disable threshold (>20% for 30+ days), feedback into confidence scoring via Beta distribution parameter adjustment. | 31-VIOLATION-FEEDBACK-LOOP-V2-PREP |
| **Context Generation expanded** | Was "11 package managers". V2-PREP specifies 15 package managers, token budgeting with model-aware limits, intent-weighted context selection (different context per intent type). | 30-CONTEXT-GENERATION-V2-PREP |
| **Workspace Management fully specified** | Was a brief mention. V2-PREP specifies: drift.db lifecycle, workspace detection, `drift setup` wizard, `drift doctor` (db integrity, config validation, grammar availability, disk space), backup via SQLite Backup API (hot backup), process-level locking via `fd-lock`. | 33-WORKSPACE-MANAGEMENT-V2-PREP |
| **CI Agent fully specified** | Was "9 analysis passes". V2-PREP specifies: PR-level incremental analysis (changed files + transitive dependents), SARIF upload, comment generation, split MCP server support, configurable fail conditions via policy engine. | 34-CI-AGENT-GITHUB-ACTION-V2-PREP |
| **Cargo workspace expanded** | Was 2 crates (drift-core, drift-napi). V2-PREP specifies 5-6 crates: drift-core, drift-analysis, drift-storage, drift-napi, drift-bench. Feature flags for conditional compilation. Release profile with LTO + single codegen unit. | 04-INFRASTRUCTURE-V2-PREP |
| **N+1 Detection implementation clarified** | Was listed as standalone leaf. V2-PREP reveals split implementation: ORM N+1 in `08-UNIFIED-LANGUAGE-PROVIDER` (`n_plus_one.rs`), GraphQL N+1 in `21-CONTRACT-TRACKING`. Event: `on_n_plus_one_detected`. | 08-ULP-V2-PREP, 21-CONTRACT-TRACKING-V2-PREP |
| **Bridge crate fully specified** | Was brief mention. V2-PREP specifies 6 bridge responsibilities: event mapping, link translation (PatternLink → EntityLink), grounding logic, grounding feedback loop, intent extensions, combined MCP tools. Additional event sources from decision mining, boundary detection, error handling, coupling, DNA. | 34-CORTEX-DRIFT-BRIDGE-V2-PREP |
| **Unified Analysis Engine GAST specified** | Was "4-phase pipeline". V2-PREP specifies GAST normalization (~30 node types), declarative TOML pattern definitions (user-extensible), `CompiledQuery` with CWE/OWASP fields, visitor pattern for single-pass detection. | 06-UNIFIED-ANALYSIS-ENGINE-V2-PREP |
| **Unified Language Provider expanded** | Was "9 normalizers, 20+ matchers". V2-PREP specifies 22 ORM matchers (20 v1 + 2 new), `UnifiedCallChain` representation, 12 semantic categories, N+1 module, taint integration module, `EntryPointKind` with Cron/WebSocket/GraphQL variants. | 08-UNIFIED-LANGUAGE-PROVIDER-V2-PREP |
| **Numbering discrepancy noted** | Both Error Handling Analysis and Impact Analysis have V2-PREP docs numbered "16". Error Handling is System 16 in its doc, Impact Analysis is also labeled System 16 in `16-IMPACT-ANALYSIS-V2-PREP.md` but correctly numbered 17 in the hierarchy and in `17-IMPACT-ANALYSIS-V2-PREP.md`. | 16-ERROR-HANDLING-ANALYSIS-V2-PREP, 16-IMPACT-ANALYSIS-V2-PREP, 17-IMPACT-ANALYSIS-V2-PREP |

---

## Complete System Count

| Level | Systems | Count |
|-------|---------|-------|
| L0 — Bedrock | Config, thiserror, tracing, DriftEventHandler, Parsers, Scanner, Storage, NAPI | **8** |
| L1 — Skeleton | Unified Analysis Engine, Call Graph, Detector System, Boundary Detection, Unified Language Provider, String Interning | **6** |
| L2A — Pattern Intelligence | Confidence Scoring, Outlier Detection, Pattern Aggregation, Learning System | **4** |
| L2B — Graph-Derived | Reachability, Taint ⚡, Error Handling, Impact, Test Topology | **5** |
| L2C — Structural Intelligence | Coupling, Constraints, Contracts, Constants/Environment, Wrapper Detection, DNA, OWASP/CWE Mapping | **7** |
| L2D — Security Intelligence | Enterprise Secret Detection, Cryptographic Failure Detection ⚡ | **2** |
| L3 — Enforcement | Rules Engine, Quality Gates, Policy Engine, Audit System, Violation Feedback Loop | **5** |
| L4 — Advanced/Capstone | Simulation Engine, Decision Mining, Context Generation, N+1 Detection | **4** |
| L5A — Drift Standalone | MCP Server, CLI, Reporters, CI Agent, VSCode, LSP, Dashboard, Galaxy | **8** |
| L5B — Bridge-Dependent | drift-memory MCP, Bridge Tools, Grounding Loop, Event→Memory | **4** |
| L6 — Cross-Cutting | Workspace Management, Licensing, GitHub Action, Docker, Telemetry, AI Providers, CIBench | **7** |
| **Total** | | **60** |

⚡ = NET NEW in V2 (not in previous hierarchy)

---

## V2-PREP Document Gap Summary

**35 V2-PREP documents exist** covering the core analysis stack comprehensively.

**Systems with dedicated V2-PREP docs**: 35 (all core + advanced analysis systems)
**Systems covered as subsections of other V2-PREP docs**: 5 (Rules Engine, Policy Engine, N+1, Licensing, String Interning)
**Systems without any V2-PREP coverage**: 9 (CLI, VSCode, LSP, Dashboard, Galaxy, AI Providers, Docker, Telemetry, CIBench)

The 9 undocumented systems are all Level 5A presentation or Level 6 cross-cutting — none are on the critical analysis path. They can be specified when their build phase approaches.

---

*This hierarchy reflects both structural dependency truth and the architectural constraints from PLANNING-DRIFT.md.*
*Drift is self-contained. The bridge is a leaf. The grounding loop is the killer feature that Drift enables but doesn't own.*
*Every system has been verified against its V2-PREP document. Consumer counts are derived from actual dependency analysis across all 35+ specs.*
*All spec numbers (framework counts, algorithm names, crate versions, table counts, CWE mappings) verified against source V2-PREP documents as of 2026-02-08.*