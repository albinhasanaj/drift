# Drift v2 — Full System Audit (Hierarchical Build Reference)

> Complete inventory of every system to build for Drift v2 — a ground-up rewrite.
> v1 is erased. This is what v2 IS, based on all v2-research recommendations.
> Organized by category (00-26, excluding 06-cortex — already built).
> Not verbose — what it is, what it does, its action.
>
> Key principle: Rust does all analysis. TypeScript is thin orchestration only.
> Storage: drift.db (SQLite) only. No JSON shards, no data lake, no hybrid stores.
>
> Generated: 2026-02-07

---

## Category 00 — Architecture & Foundations

### Foundational Architectural Decisions (P0 — Decide Before Writing Code)

These are load-bearing decisions from the v2 research. They constrain every subsystem.

1. **AD1: Incremental-First Architecture** — Build the entire system around incremental computation from day one. NOT batch-first with incrementality bolted on.
   - Two-phase model: (1) per-file indexing (embarrassingly parallel, content-hashed, cached), (2) cross-file analysis (call graph, coupling, reachability — auto-invalidate when inputs change)
   - Persistent SQLite-backed index survives restarts. On startup, hash-check files → only re-index changed files
   - Three-layer incrementality: Layer 1 (file-level skip via content hash), Layer 2 (pattern re-scoring only for changed files), Layer 3 (convention re-learning threshold-based: >10% files changed triggers full re-learn)
   - Cancellation pattern: global revision counter, long-running queries check and panic with `Cancelled`, caught at API boundary

2. **AD2: Single Canonical Data Model** — One `ParseResult` type. One `Pattern` type. One `FunctionEntry` type. Rust defines canonical types. NAPI serializes. TS consumes. No three-shape problem.

3. **AD3: Declarative Pattern Definitions (TOML)** — Ship with hardcoded defaults (all v1 patterns). Users add custom patterns via TOML without recompiling. Tree-sitter query syntax as the pattern language. Graduated complexity: simple node match → structural parent-child → predicate matching → cross-reference constraints.
   ```toml
   [[patterns]]
   id = "spring-security"
   language = "java"
   category = "Auth"
   confidence = 0.95
   query = '(annotation name: (identifier) @name (#match? @name "^(PreAuthorize|Secured)$"))'
   ```

4. **AD4: Visitor Pattern for Detection** — Single-pass AST traversal with all detectors registered as visitors. Reduces traversals from O(detectors × files) to O(files). The single most impactful architectural change for detection performance.

5. **AD5: Split MCP Server Architecture** — Split into two MCP servers: `drift-analysis` (~17-20 tools, read-only drift.db, ~5-8K tokens) + `drift-memory` (optional, ~15-20 tools, read/write cortex.db + read drift.db). Progressive disclosure: 3 entry points per server, not all tools upfront. Reduces startup cost from ~8K to ~1.5K tokens per server.

6. **AD6: Structured Error Handling (thiserror)** — Use `thiserror` for all Rust error types from the first line of code. One error enum per subsystem with structured variants. Propagate meaningful errors through NAPI to TypeScript with error codes.

7. **AD7: SQLite WAL Mode as Default** — Every SQLite database opens with: WAL mode, `synchronous = NORMAL`, `mmap_size = 268435456` (256MB), `busy_timeout = 5000`.

8. **AD8: Bayesian Confidence with Momentum** — Replace static confidence scoring with Bayesian posterior + momentum:
   - Beta distribution: prior Beta(1,1), posterior Beta(1+k, 1+n-k) where k=successes, n=trials
   - `final_score = posterior_mean × 0.70 + consistency × 0.15 + momentum × 0.15`
   - Graduated tiers by credible interval width: Established (mean>0.7, CI<0.15), Emerging (mean>0.5, CI<0.25), Tentative (mean>0.3, CI<0.40), Uncertain (else)
   - Store posterior parameters (α, β) per pattern in SQLite for incremental updates
   - Note: The static formula (frequency×0.40 + consistency×0.30 + age×0.15 + spread×0.15) is the v1 baseline; Bayesian is the v2 target

9. **AD9: Feedback Loop Architecture (Tricorder-style)** — "Not useful" / "Useful" signals on every violation. Track effective false-positive rate per detector (<5% target). Detectors with >10% FP rate get alert, >20% for 30+ days get auto-disabled. Developer action (fix, ignore, approve) feeds back into pattern confidence. Project-level customization, not user-level.

10. **AD10: Observability-First (tracing crate)** — Use the `tracing` crate for structured logging and span-based instrumentation from the first line of code. Every subsystem emits structured events with timing, counts, error context. Key metrics: parse_time_per_language, detection_time_per_category, cache_hit_rate, napi_serialization_time, mcp_response_time. Configurable log levels per subsystem (`DRIFT_LOG=parser=debug,detector=info`). Optional OpenTelemetry integration for enterprise distributed tracing.

11. **AD11: Taint Analysis as First-Class Subsystem** — Not an afterthought. Source/sink/sanitizer registry (TOML-configurable, per-framework defaults). Phase 1: intraprocedural taint tracking in Rust. Phase 2: interprocedural via call graph taint summaries.

12. **AD12: Performance-Optimized Data Structures** — `FxHashMap` for all internal hash maps, `SmallVec<[T; 4]>` for usually-small collections, `BTreeMap` for ordered lookups, `xxhash` (xxh3) for content hashing, `lasso` crate for string interning (`ThreadedRodeo` for build, `RodeoReader` for query), `petgraph` (`StableGraph`) for in-memory call graph synced with SQLite, `Moka` cache (TinyLFU + LRU) for parse cache (content-addressed, durable across restarts). Release profile: `lto = true`, `codegen-units = 1`, `opt-level = 3`.

### Architecture Layers (strict dependency, no circular)
1. **Foundation** → Rust parsers, Rust scanner, SQLite storage
2. **Analysis** → Rust detectors, call graph, boundaries, constants, environment, DNA
3. **Intelligence** → Patterns (aggregated), constraints, test topology
4. **Enforcement** → Rules engine, quality gates, audit
5. **Presentation** → MCP server (TS), CLI (TS), VSCode (TS), Dashboard (TS)

### v2 Package Map
- `crates/drift-core` → ALL analysis in Rust: parsers, scanner, call graph, detectors, boundaries, coupling, reachability, constants, environment, wrappers, test topology, error handling, DNA, constraints, unified analysis
- `crates/drift-napi` → Full NAPI bridge (Rust → Node.js)
- `packages/mcp` → MCP server (TS): tool routing, caching, rate limiting, packs
- `packages/cli` → CLI (TS): commands, reporters, UI — calls Rust via NAPI
- `packages/lsp` → LSP server (TS): diagnostics, code actions — calls Rust via NAPI
- `packages/vscode` → VSCode extension (TS): commands, views, diagnostics
- `packages/dashboard` → Web dashboard (TS): Vite + React + Tailwind
- `packages/ai` → AI provider abstraction (TS): Anthropic, OpenAI, Ollama
- `packages/ci` → CI agent (TS): PR analysis, GitHub/GitLab integration
- `packages/galaxy` → 3D visualization (TS/React): Three.js data viz

### Core Data Models
- `Pattern` → 16-char hex ID, 16 categories, 3 statuses (discovered/approved/ignored), confidence, locations[]
- `Violation` → Deviation from pattern: patternId, file, line, severity, quickFix
- `ConfidenceScore` → frequency×0.40 + consistency×0.30 + age×0.15 + spread×0.15
- `PatternLocation` → file, line, column, isOutlier, confidence, outlierReason
- `PatternMatch` → per-detector per-file match result

### Storage: Single SQLite Database
- `drift.db` → ALL Drift data (40+ tables, WAL mode, mmap)
- `cortex.db` → Cortex memory (separate, already built)
- Cross-DB: SQLite ATTACH for read-only cross-queries when both present
- No JSON shards. No data lake. No hybrid stores.


---

## Category 01 — Rust Core (crates/drift-core)

### Scanner (Rust)
- Parallel file walking → `rayon` + `walkdir`
- Respects `.gitignore` + `.driftignore`
- Content hashing → `xxhash-rust` (xxh3) for incremental detection
- Config: root, patterns[], extraIgnores, computeHashes, maxFileSize (1MB), threads
- **Action**: Walks filesystem, hashes files, returns file list for parsing

### Parsers (Rust) — 10 Languages
- TypeScript, JavaScript, Python, Java, C#, PHP, Go, Rust, C, C++
- Tree-sitter primary with S-expression queries per language
- Extracts per file: functions, classes, imports, exports, call sites, decorators, generic types, inheritance chains, access modifiers, framework constructs
- Output types: FunctionInfo, ClassInfo, ImportInfo, CallSite
- **Action**: Parses source → structured AST extraction per language

### Unified Analysis Engine (Rust) — Core Pattern Detection
- 4-phase per-file pipeline:
  1. AST pattern detection via pre-compiled tree-sitter queries (per language)
  2. String extraction from AST (strings >3 chars)
  3. Regex on extracted strings only (SQL 9 patterns, routes 6, sensitive data 8, environment 6)
  4. Resolution index building (cross-file function resolution)
- AstPatternDetector: compiled queries for TS, JS, Python, Java, C#, PHP, Go, Rust, C++
- StringLiteralAnalyzer: RegexSet applied to extracted strings, never raw source
- ResolutionIndex: BTreeMap + FxHashMap + SmallVec, same-file → exported → ambiguous resolution
- String interning via `lasso` crate: `ThreadedRodeo` during build/scan (mutable), `RodeoReader` for query (immutable, contention-free). Domain wrappers: `PathInterner` (normalizes `\` → `/`), `FunctionInterner` (supports `intern_qualified(class, method)`). 60-80% memory reduction.
- NAPI: `analyze_unified(root, options) → UnifiedResult`
- **Action**: Single-pass AST+regex pattern detection with cross-file resolution

### Call Graph Builder (Rust)
- Universal extractor → language-agnostic via normalized ParseResult
- Parallel: rayon file walk → parse → extract → MPSC channel → batch writer
- SQLite storage: tables `functions`, `call_edges`, `data_access`, `metadata` (6 indexes)
- Config: batch_size=100, WAL mode, 64MB cache, 256MB mmap
- 6 resolution strategies: same-file (high) → method call (high) → DI injection (med-high) → import-based (med) → export-based (med) → fuzzy (low)
- Entry point detection: route decorators, controllers, exported handlers, main
- **Action**: Builds function→function call edges across entire codebase

### Reachability (Rust)
- In-memory BFS engine (fast, small-medium codebases)
- SQLite-backed BFS engine (scalable, O(1) memory, recursive CTEs)
- Forward: function → what data can it reach?
- Inverse: data → who can reach it?
- Sensitivity classification: PII, credentials, financial, health
- Taint analysis: track data transformations along paths
- **Action**: Traces data flow paths through call graph

### Taint Analysis (Rust) — First-Class Subsystem
- Source/sink/sanitizer registry as TOML configuration with per-framework defaults for all 28+ ORMs and 10 languages
- **Phase 1 — Intraprocedural**: For each function, build mini data-flow graph, track taint through assignments and calls within a single function
- **Phase 2 — Interprocedural**: Produce taint summaries per function (which parameters taint which return values), propagate across function boundaries via call graph
- Sources: function parameters, request objects, env vars, user input APIs
- Sinks: SQL query construction, command execution, HTML rendering, file writes, URL redirects, deserialization
- Sanitizer recognition: escapeHtml, parameterize, DOMPurify, express-validator (reduces false positives)
- 4 vulnerability detectors: SQL injection (HTTP params → ORM raw methods), XSS (user input → innerHTML/template rendering), SSRF (user input → HTTP client URL), Path traversal (user input → filesystem path)
- Field-level data flow: track individual fields through call paths (`users.password_hash` vs `users.display_name`), detect transformations (DirectAccess, Aggregation, Hashing, Encryption, Masking, Concatenation, Filtering)
- **Action**: Transforms structural analysis into security analysis — the single most impactful security improvement

### Impact Analysis (Rust)
- Transitive caller analysis via call graph
- Risk scoring: affected functions × entry points × sensitive data × depth
- Dead code detection with false positive filtering (entry points, framework hooks, dynamic dispatch, exported)
- Path finding: BFS with path tracking between any two functions
- **Action**: Calculates blast radius of changes, finds dead code

### Boundary Detection (Rust)
- 28+ ORM frameworks across 8 languages
- 7 dedicated field extractors: Prisma, Django, SQLAlchemy, Supabase, GORM, Diesel, Raw SQL
- Sensitive field detection: PII (0.5-0.95), Credentials (0.7-0.95), Financial (0.8-0.95), Health (0.9-0.95)
- False positive filtering: function names, imports, comments, mock/test prefixes
- Confidence: tableNameFound(0.3) + fieldsFound(0.2) + operationClear(0.2) + frameworkMatched(0.2) + fromLiteral(0.1)
- Boundary rules: per-table allowed/denied files, allowed operations, requireAuth
- **Action**: Discovers data access points, classifies sensitivity, enforces boundary rules

### Unified Language Provider (Rust)
- 9 language normalizers: TypeScript, JavaScript, Python, Java, C#, PHP, Go, Rust, C++
- Language AST → universal UnifiedCallChain representation
- 20 ORM/framework matchers: Supabase, Prisma, TypeORM, Sequelize, Drizzle, Knex, Mongoose, Django, SQLAlchemy, EF Core, Eloquent, Spring Data, GORM, Diesel, SeaORM, SQLx, Raw SQL, database/sql, + base + registry
- Normalizer pattern maps to Rust traits, matcher pattern is pure data transformation
- **Action**: Cross-language ORM/framework pattern detection from normalized call chains

### Coupling Analysis (Rust)
- Module-level coupling metrics
- Import/export dependency tracking
- Afferent (Ca) / efferent (Ce) coupling calculation, Instability (I), Abstractness (A), Distance (D)
- Tarjan's SCC for cycle detection (guarantees completeness, same O(V+E))
- Condensation graph generation (DAG of SCCs for architecture visualization)
- Zone detection: Zone of Pain (low I, low A), Zone of Uselessness (high I, high A)
- Module role classification: hub, authority, balanced, isolated
- Cycle break suggestions: score by `(Ce of source / Ca of target)`, suggest approach (ExtractInterface, DependencyInversion, MergeModules, IntroduceMediator)
- **Action**: Measures inter-module dependency strength, detects cycles, classifies zones

### Constants & Environment (Rust)
- Constants: magic number detection, string literal analysis, secret detection
- Environment: env var usage tracking, .env file parsing
- **Action**: Catalogs hardcoded values and environment dependencies

### Wrappers (Rust)
- Wrapper function detection (thin delegation patterns)
- Wrapper clustering (related wrappers grouped)
- **Action**: Identifies functions that just delegate to another function

### NAPI Bridge (crates/drift-napi) — Full Coverage
- All Rust analysis exposed to Node.js via NAPI-RS (v3 for cross-compilation, 7+ platform targets)
- Individual analysis functions (~25, covering all capabilities)
- Batch API: `analyze_batch(root, analyses: Vec<AnalysisType>)` — multiple analyses in one NAPI call, shared parsed results
- Streaming support via napi-rs `AsyncTask` + chunked results for large result sets
- Async variants for long-running operations
- Structured error propagation: Rust error enums → meaningful NAPI error objects
- Platform targets: darwin-arm64, darwin-x64, linux-arm64-gnu, linux-arm64-musl, linux-x64-gnu, linux-x64-musl, win32-x64-msvc
- parse, scan, analyze_unified, build_call_graph, analyze_reachability, analyze_boundaries, analyze_test_topology, analyze_error_handling, analyze_constants, analyze_environment, analyze_wrappers, analyze_taint, + all query functions
- **Action**: Complete Rust→Node.js interface for TS orchestration layer


---

## Category 02 — Parsers (Rust-Only)

### Tree-Sitter Parsers — 10 Languages
- TypeScript, JavaScript, Python, Java, C#, PHP, Go, Rust, C, C++
- S-expression queries per language for structural extraction
- Full extraction: functions, classes, imports, exports, calls, decorators/annotations, generic types, inheritance chains, access modifiers, framework constructs, doc comments
- **Action**: Unified parsing interface — all languages, all constructs, Rust-only

### Pydantic Model Extraction
- Pydantic v1 and v2 model detection
- Field extraction with types, defaults, validators
- **Action**: Extracts Python data model definitions for boundary analysis

### PHP Extraction Utilities
- Class extractor, method extractor, PHP 8 attribute extractor, docblock extractor
- Comprehensive PHP type system (classes, interfaces, traits, enums, methods, properties, attributes, namespaces)
- **Action**: Structured PHP parsing for Laravel and other PHP detectors

### Generic AST Normalization Layer (GAST) — Language-Agnostic Detection
- ~30 normalized node types covering 80% of detection needs: Function, Class, TryCatch, Call, Import, Route, etc.
- Per-language normalizers (10 languages): Language-Specific CST → GAST Normalizer → Generic AST → Detectors
- Language-specific detectors kept for truly unique patterns (PHP attributes, Rust lifetimes)
- Adding a new language requires only a normalizer (~500-1000 lines) — all existing detectors work automatically
- Reduces detector codebase by 50-70%
- **Action**: Cross-language pattern detection from a single normalized AST representation

---

## Category 03 — Detector System (Rust Trait-Based)

### 16 Detection Categories
1. **security** → SQL injection, XSS, CSRF, secrets, auth bypass
2. **auth** → Authentication patterns, session management, token handling
3. **errors** → Error handling conventions, try/catch patterns, error types
4. **api** → REST conventions, endpoint patterns, response formats
5. **components** → UI component patterns, prop conventions, lifecycle
6. **config** → Configuration management, env vars, feature flags
7. **contracts** → API contracts, request/response schemas, validation
8. **data-access** → ORM patterns, query conventions, repository patterns
9. **documentation** → JSDoc, docstrings, README conventions
10. **logging** → Log levels, structured logging, log formatting
11. **performance** → Caching, lazy loading, memoization, bundle optimization
12. **structural** → File organization, naming conventions, module boundaries
13. **styling** → CSS conventions, theme patterns, responsive design
14. **testing** → Test patterns, assertion styles, mock conventions
15. **types** → Type annotation patterns, interface conventions, generics usage
16. **accessibility** → ARIA patterns, semantic HTML, keyboard navigation

### Rust Trait Hierarchy (3 Variants Per Category)
- **BaseDetector trait** → Fast regex/AST matching, deterministic
- **LearningDetector trait** → Adapts to codebase conventions, learns dominant pattern, flags deviations
- **SemanticDetector trait** → Deep AST analysis with context awareness
- All regex patterns ported as data (static config), not logic

### Detector Registry (Rust)
- Central registry with category mapping
- Language filtering (only run relevant detectors per file type)
- Critical-only mode for fast scans
- **Action**: Routes files to applicable detectors, collects PatternMatch[] results

### Framework-Specific Detector Suites (Rust)
- **Spring Boot** (Java): 12 categories × learning + semantic (api, async, auth, config, data, di, errors, logging, structural, testing, transaction, validation)
- **ASP.NET** (C#): 11 categories (auth, config, contracts, data-access, docs, errors, logging, performance, security, structural, testing)
- **Laravel** (PHP): 12 categories + aggregator
- **Django** (Python): URL extractor, ViewSet extractor, Serializer extractor
- **Go**: 5 web frameworks (Gin, Echo, Fiber, Chi, net/http) + auth middleware + error patterns
- **Rust**: 4 web frameworks (Actix, Axum, Rocket, Warp) + auth middleware + error patterns
- **C++**: 3 web frameworks (Crow, Boost.Beast, Qt Network) + auth + errors
- **Action**: Framework-aware convention detection beyond generic category detectors

### Detector Contracts
- Input: DetectionContext (file, content, ast, imports, exports, projectContext)
- Output: DetectionResult (patterns[], violations[], confidence)
- Lifecycle: register → learnFromProject → detect → onFileChange → unload
- ValueDistribution algorithm: tracks value frequency, dominant at >60% (configurable)
- **Action**: Defines the contract every detector must fulfill

### Learning System (Rust)
- Min occurrences: 3, dominance threshold: 0.60, min files: 2
- Max files to analyze: 1000
- Learned patterns stored in drift.db (not JSON files)
- **Action**: Discovers dominant conventions, flags deviations as outliers

### Confidence Scoring (Rust)
- v1 baseline: `score = frequency×0.40 + consistency×0.30 + age×0.15 + spread×0.15`
- v2 target (Bayesian): `final_score = posterior_mean × 0.70 + consistency × 0.15 + momentum × 0.15` where posterior = Beta(1+k, 1+n-k), momentum = (current_freq - prev_freq) / prev_freq normalized [0,1]
- Graduated tiers: Established (mean>0.7, CI<0.15), Emerging (mean>0.5, CI<0.25), Tentative (mean>0.3, CI<0.40), Uncertain (else)
- Store posterior parameters (α, β) per pattern in drift.db for incremental updates without full recalculation
- Levels (v1 compat): high (≥0.85), medium (≥0.70), low (≥0.50), uncertain (<0.50)
- All factors normalized [0,1], weights sum to 1.0 (±0.001)
- **Action**: Quantifies how established each detected convention is

### Outlier Detection (Rust) — 3 Methods
1. **Z-Score** (n≥30): threshold=2.5 (v1 used 2.0; 2.5 balances sensitivity/precision per NIST), significance tiers: |z|>3.5=critical, >3.0=high, >2.5=moderate
2. **IQR** (n<30): multiplier=1.5, significance by normalized distance
3. **Grubbs' test** (10≤n<30): for small samples, iterative detection with 3-iteration cap (addresses masking effects)
4. **Rule-based**: Custom rules per detector
- Minimum sample size: 10 (not 3)
- Types: structural, syntactic, semantic, stylistic, missing, extra, inconsistent
- Consider SIMD for batch scoring
- **Action**: Identifies statistical deviations from conventions


---

## Category 04 — Call Graph (Rust)

### Per-Language Hybrid Extractors (Rust)
- 9 languages: TypeScript, JavaScript, Python, Java, C#, PHP, Go, Rust, C++
- Tree-sitter primary + regex fallback for robustness
- ORM-aware extraction (tracks DB queries alongside calls)
- **Action**: Extracts function definitions + call sites per file per language

### Call Resolution (Rust) — 6 Strategies
1. **Same-file** (High) → Function defined in same file
2. **Method call** (High) → Resolved via class/receiver type
3. **DI injection** (Medium-High) → FastAPI Depends, Spring @Autowired, NestJS @Inject
4. **Import-based** (Medium) → Follow import chains
5. **Export-based** (Medium) → Match exported names
6. **Fuzzy** (Low) → Name similarity for dynamic calls
- Unified resolution algorithm (not per-language variants)
- Resolution rate target: 60-85%

### Analysis Engines (Rust)
- **ReachabilityEngine** → Forward BFS, inverse BFS, path finding
- **ImpactAnalyzer** → Transitive caller analysis, risk scoring
- **DeadCodeDetector** → Unreachable functions with false positive filtering
- **CoverageAnalyzer** → Call graph × test topology for function-level coverage
- **PathFinder** → BFS with path tracking between any two functions
- **Action**: Answers reachability, impact, dead code, coverage, and path queries

### Storage (SQLite only)
- Tables: functions, call_edges, data_access, metadata (6 indexes)
- All in drift.db — no separate callgraph.db
- **Action**: Persists call graph for online querying

---

## Category 05 — Analyzers (Rust)

### AST Analyzer (Rust)
- Structural pattern matching via tree-sitter queries
- Subtree comparison with similarity scoring (0-1)
- Depth-first traversal with visitor pattern
- **Action**: Structural pattern matching and subtree comparison on ASTs

### Type Analyzer (Rust)
- Per-language type extraction from AST
- Structural subtype checking, compatibility checking
- Type coverage calculation (% of typed locations)
- Handles: primitives, references, unions, intersections, arrays, tuples, functions, objects, literals, generics
- **Action**: Type system analysis from AST

### Semantic Analyzer (Rust)
- Scope tree: global → module → function → method → class → block
- Symbol table: all declarations with type, visibility, mutability, references
- Reference resolution: links identifier uses to declarations via scope chain
- Shadowed variable detection
- Critical for call resolution accuracy
- **Action**: Scope analysis, symbol resolution, reference tracking

### Flow Analyzer (Rust)
- CFG construction: entry/exit, statements, branches, loops, exception handling
- Edge types: normal, true-branch, false-branch, exception, break, continue, return, throw
- Data flow: variable definitions/uses, reaching definitions, null dereference detection
- Issue detection: unreachable code, infinite loops, missing returns, null dereferences
- Forward/backward dataflow framework as generic Rust algorithms
- Per-language lowering to normalized IR (separate from analysis algorithms)
- **Action**: Control flow graph construction and data flow analysis

### N+1 Query Detection (Rust)
- Combines call graph analysis with ORM pattern detection
- Finds loops containing ORM queries that depend on loop variables without a preceding bulk query
- Framework-specific fix suggestions: Prisma (`include`/`select`), Django (`select_related`/`prefetch_related`), SQLAlchemy (`joinedload`/`subqueryload`)
- **Action**: Detects N+1 query anti-patterns with actionable fix suggestions

### Rules Engine
- **Evaluator** (Rust) → Pattern matcher → find violations from outliers → severity → quick fixes
- **Rule Engine** (TS) → Orchestration: violation tracking, dedup, limits (100/pattern, 50/file)
- **Severity Manager** (TS) → Resolution: pattern-specific → category → config → default. Defaults: security/auth=error, errors/api/data-access=warning, testing/logging=info, documentation/styling=hint
- **Quick Fix Generator** (TS) → 7 strategies: replace (pattern-based), wrap (0.6), extract (0.5), import (0.7), rename (0.7), move (0.4), delete (0.5)
- **Variant Manager** (TS) → Scoped overrides (global/directory/file), lifecycle, expiration
- **Action**: Determines "what SHOULD be" and generates actionable violations

---

## Category 06 — Cortex (EXCLUDED — Already Built)

> 19-crate Rust workspace. See `crates/cortex/` for implementation.

---

## Category 07 — MCP Server (TS — 56+ Tools)

### Tool Categories
1. **Discovery** → `drift_status`, `drift_patterns_list`, `drift_pattern_get`, `drift_categories`
2. **Context** → `drift_context` (meta-tool, replaces 3-5 calls), `drift_package_context`
3. **Code Examples** → `drift_code_examples`, `drift_code_examples_batch`
4. **Validation** → `drift_prevalidate`, `drift_validate_change`
5. **Security** → `drift_security_summary`, `drift_security_boundaries`, `drift_security_reachability`
6. **Analysis** → `drift_call_graph`, `drift_impact`, `drift_dead_code`, `drift_test_topology`
7. **Constraints** → `drift_constraints`, `drift_constraint_verify`
8. **Error Handling** → `drift_errors` (types, gaps, boundaries)
9. **DNA** → `drift_dna_profile`, `drift_dna_compare`
10. **Memory** → `drift_memory_*` tools (Cortex integration, conditional on Cortex availability)

### Server Architecture (TS) — Split into Two Servers
- **drift-analysis** (~17-20 tools): read-only drift.db, ~5-8K tokens. Entry points: `drift_context`, `drift_discover`, `drift_tool`
- **drift-memory** (optional, ~15-20 tools): read/write cortex.db + read drift.db, ~5-8K tokens. Entry points: `drift_memory_context`, `drift_memory_manage`, `drift_memory_discover`
- Progressive disclosure: 3 entry points per server (not all tools upfront), reduces startup cost from ~8K to ~1.5K tokens per server
- Separate `drift_*` namespace (Cortex gets `cortex_*`)
- Tool routing, caching with TTL per category, rate limiting, token estimation
- All tools call Rust via NAPI — TS is routing + formatting only
- Bridge tools (`drift_why`, `drift_memory_learn`) registered conditionally when Cortex detected
- Consistent JSON response schemas across all tools (structured, parseable)
- Workflow tools combining related operations (e.g., `drift_analyze_function` = signature + callers + callees + impact)
- Built-in pagination with cursor support for all list operations
- Cortex facade pattern: MCP tools call facade, not internal APIs directly

### Pack Manager (TS)
- Custom tool packs (subsets for specific workflows)
- Pack suggestion engine (infers from project structure)
- Staleness detection, usage tracking
- **Action**: Reduces context window cost by serving only relevant tools

### Feedback System (TS)
- User ratings on pattern examples: good (+0.1), bad (-0.15), irrelevant (-0.05)
- Directory-level score propagation (30% of file delta)
- File exclusion when confidence > 0.5 and boost < -0.5
- **Action**: Reinforcement learning loop for example quality

### Curation System (TS) — Anti-Hallucination Verification
- Pattern approval workflow requiring verifiable evidence before AI can approve patterns
- Evidence requirements scale with confidence: High (≥0.85) = 1 verified file; Medium (≥0.70) = 2 files + snippets + reasoning; Low (≥0.50) = 3 files + snippets + detailed reasoning
- Verifier reads actual files from disk, checks claimed evidence against real code
- Verification score: verifiedChecks / totalChecks. ≥0.80 = verified, ≥0.50 = partial, <0.50 = failed
- Approval blocked if: verified files < minimum, snippets required but missing, score below threshold, reasoning < 20 chars
- Audit trail for all curation decisions
- **Action**: Prevents AI from approving patterns based on hallucinated evidence


---

## Category 08 — Storage (SQLite Only)

### Single Database: drift.db
- WAL mode, mmap, all Drift data in one file
- 40+ tables organized by domain:
  - **Patterns**: patterns, pattern_locations, pattern_variants, pattern_examples, pattern_history (7 indexes)
  - **Call Graph**: functions, call_edges, data_access, metadata (6 indexes)
  - **Security**: boundaries, sensitive_fields, boundary_rules
  - **Contracts**: contracts, contract_endpoints, contract_schemas
  - **Constraints**: constraints, constraint_violations
  - **Test Topology**: test_files, test_cases, test_coverage
  - **DNA**: dna_profiles, dna_genes, dna_comparisons
  - **Error Handling**: error_boundaries, error_gaps, error_types
  - **Audit**: audit_snapshots, audit_health, audit_degradation
  - **Environment**: env_vars, env_files
  - **Constants**: constants, magic_numbers
  - **Coupling**: module_coupling, coupling_metrics
  - **Learning**: learned_conventions (replaces .drift/learned/ JSON)
  - **Quality Gates**: gate_snapshots, gate_runs
- **Action**: Single source of truth for all Drift data

### Cross-DB Queries (When Cortex Present)
- SQLite ATTACH `cortex.db` as read-only
- Cross-DB reads for grounding, memory-linked patterns
- Writes always go to owning database only
- Graceful degradation if cortex.db doesn't exist

---

## Category 09 — Quality Gates

### 6 Gates
1. **Pattern Compliance** → Checks approved patterns are followed, flags outliers
2. **Constraint Verification** → Runs ConstraintVerifier, change-aware mode (only checks changed lines)
3. **Security Boundaries** → Validates data access rules, unauthorized access, missing auth
4. **Test Coverage** → Minimum thresholds per module, function-level via test topology
5. **Error Handling** → Minimum quality scores, flags critical unhandled paths
6. **Regression Detection** → Compares against previous baseline, detects score changes

### Orchestrator (TS)
- Runs gates in dependency order
- Aggregates pass/fail/skip per gate
- Configurable: which gates required vs advisory
- CI integration: exit code 1 on failure
- **Action**: Coordinates gate execution, produces aggregate result

### Policy Engine (TS)
- **PolicyLoader**: 5-source resolution (inline → built-in → custom → context-based → default)
- **Context-based selection**: branch patterns (+10), path patterns (+5), author patterns (+3) — most specific wins
- **PolicyEvaluator**: 4 aggregation modes — `any` (default), `all`, `weighted`, `threshold`
- **4 built-in policies**: `default` (balanced), `strict` (main/release), `relaxed` (feature branches), `ci-fast` (minimal)
- Required gates always block regardless of aggregation mode
- Custom policies in drift.db
- **Action**: Controls which gates run, thresholds, blocking behavior

### Persistence
- **SnapshotStore**: Health snapshots per branch (max 50/branch) — patterns + constraints + security state
- **GateRunStore**: Run history (max 100 runs) — lightweight summaries for trend analysis
- All stored in drift.db (not filesystem)
- **Action**: Enables regression detection and trend analysis

### Reporters (TS)
- 5 output formats: Text (terminal), JSON (machine), SARIF 2.1.0 (GitHub Code Scanning), GitHub (PR comments), GitLab (MR comments)
- SARIF maps violations to results with ruleId, level, locations
- **Action**: Transforms gate results into CI-consumable output

---

## Category 10 — CLI (TS — 48-65+ Commands)

### Command Groups
- **scan** → full scan, incremental, watch
- **patterns** → list, get, approve, ignore, export, import
- **check** → run quality gates, --fix, --staged
- **callgraph** → build, stats, entry-points, reachability, impact, dead-code
- **security** → summary, boundaries, reachability, sensitive-fields
- **secrets** → standalone secret scanning with entropy analysis
- **taint** → on-demand taint analysis of specific functions
- **constraints** → list, approve, ignore, verify, synthesize
- **test-topology** → analyze, coverage, minimum-set, mocks
- **errors** → analyze, gaps, boundaries, types
- **dna** → profile, compare, history
- **contracts** → list, verify, diff
- **audit** → run, history, health
- **context** → generate, package
- **config** → init, show, set, reset
- **memory** → Cortex memory subcommands
- **setup** → guided onboarding wizard

### Setup Wizard (TS)
- 8-phase guided onboarding: prerequisites → init → pattern approval → core features → deep analysis → derived features → memory → finalize
- 13 modular runners: Boundaries, Contracts, Environment, Constants, CallGraph, TestTopology, Coupling, DNA, ErrorHandling, Constraints, Audit, Memory, SqliteSync
- SourceOfTruth generation: baseline checksums, feature configs
- Resume capability, quick mode (`-y`)
- **Action**: Guided project onboarding

### Git Integration (TS)
- Staged file detection (`git diff --cached`) for `drift check --staged`
- Changed file detection for incremental checking
- Git hook management: pre-commit (`drift check --staged`), pre-push (`drift check`)
- Husky auto-detection and integration
- **Action**: Git-aware file filtering and hook installation

### Reporters (TS)
- 4 formats: Text (colored terminal), JSON (machine), GitHub (Actions annotations), GitLab (Code Quality)
- Selection via `--format` flag, `--ci` auto-selects JSON
- **Action**: Pluggable violation output formatting

### All Commands Call Rust via NAPI
- TS is routing + formatting only
- No analysis logic in TS layer


---

## Category 11 — IDE Integration (TS)

### VSCode Extension
- Commands: scan, check, approve/ignore patterns, show call graph
- Views: pattern explorer, violation list, security boundaries
- Diagnostics: inline violation markers with severity
- Code actions: quick fixes from rules engine
- **Action**: Surfaces Drift analysis in the editor

### LSP Server
- Language Server Protocol implementation
- Diagnostics on file save, code actions for violations, hover info for patterns
- Calls Rust via NAPI for all analysis
- **Action**: IDE-agnostic integration via LSP

---

## Category 12 — Infrastructure

### Build System
- Cargo workspace for Rust crates
- pnpm + Turborepo for TS packages
- NAPI-RS for Rust→Node.js bridge
- Turborepo pipeline: build → typecheck → lint → test (with caching)

### Configuration System
- Config files: `drift.config.json` / `.driftrc.json` / `.driftrc`
- Config loading: file → merge defaults → env var overrides → validate
- Env overrides: `DRIFT_AI_PROVIDER`, `DRIFT_CI_FAIL_ON`, etc.
- `.driftignore`: Gitignore-compatible pattern file
- **Action**: Project-level configuration management

### Docker Deployment
- Multi-stage build: Node 20, pnpm, Rust native compilation
- Production: non-root user, 4GB memory limit, health checks
- Docker Compose: SSE at `/sse`, message at `/message`
- **Action**: Containerized MCP HTTP server deployment

### Telemetry (TS)
- Client: opt-in, event batching, privacy controls
- Server: Cloudflare Worker + D1 database
- Endpoints: POST /v1/events, GET /v1/health, GET /v1/stats
- 30-day rolling window, daily aggregates
- **Action**: Anonymous usage tracking for product decisions

### GitHub Action
- Composite action: `driftdetect-ci@latest`
- Inputs: github-token, fail-on-violation, post-comment, create-check, pattern-check, impact-analysis, constraint-verification, security-boundaries, memory-enabled
- Outputs: status, summary, violations-count, drift-score, result-json
- **Action**: PR-level drift analysis in CI/CD

### CI Agent / PR Analyzer (TS)
- Orchestrates 9 analysis passes in parallel: patterns, constraints, impact, security, tests, coupling, errors, contracts, constants
- 12 pluggable interfaces: IPatternMatcher, IConstraintVerifier, IImpactAnalyzer, IBoundaryScanner, ITestTopology, IModuleCoupling, IErrorHandling, IContractChecker, IConstantsAnalyzer, IQualityGates, ITrendAnalyzer, ICortex
- Scoring: patternScore(30%) + constraintScore(25%) + securityScore(20%) + testScore(15%) + couplingScore(10%)
- Providers: GitHub (Octokit), GitLab
- Reporters: GitHub comment (markdown), SARIF 2.1.0
- **Action**: Full PR-level drift analysis with CI integration

### AI Provider Package (TS)
- 3 providers: Anthropic (Claude), OpenAI, Ollama (local)
- 2 capabilities: explain(violation) → explanation + suggested action, generateFix(violation) → fixed code + confidence
- Context building: CodeExtractor, ContextBuilder, Sanitizer
- Prompt templates: ExplainPrompt, FixPrompt
- **Action**: AI-powered violation explanation and auto-fix generation

### Licensing & Feature Gating (TS)
- 3 tiers: Community (free) / Team / Enterprise
- 16 enterprise features gated at runtime
- LicenseManager → loading, validation, caching
- LicenseValidator → JWT/key validation, expiration
- FeatureGuard → Runtime tier check before feature use (6 patterns: requireFeature, checkFeature, guardFeature, withFeatureGate, @RequiresFeature decorator, guardMCPTool)
- Sources: env var (`DRIFT_LICENSE_KEY`), file (`.drift/license.key`), config
- Community: scanning, detection, analysis, CI, MCP, VSCode
- Team: policy engine, regression, custom rules, trends, exports
- Enterprise: multi-repo, simulation, security boundaries, audit trails, integrations, REST API
- **Action**: Gates features by license tier — the monetization boundary

### Dual Licensing Model
- Apache 2.0 for open-source core
- BSL 1.1 for enterprise features (converts to Apache 2.0 after 4 years)
- Per-file license headers (`@license Apache-2.0` or `@license BSL-1.1`)
- **Action**: Legal framework for open-core business model

### CIBench — Codebase Intelligence Benchmark (TS)
- 4-level evaluation: Perception (30%), Understanding (35%), Application (25%), Validation (10%)
- Novel features: counterfactual evaluation, calibration measurement (ECE/MCE), generative probes, adversarial robustness, negative knowledge
- Test corpus with ground truth
- **Action**: Measures how well tools understand codebases

### Galaxy Visualization (TS/React)
- Three.js + react-three-fiber + Zustand
- Tables as planets, fields as moons, entry points as stations, data flows as lanes
- Force-directed layout engine, real-time access animation
- **Action**: Interactive 3D visualization of database schemas and data access patterns


---

## Category 13 — Advanced Systems

### DNA System (Rust) — 10 Gene Extractors
- Extracts "genetic fingerprint" of codebase conventions
- Gene extractors: naming conventions, file structure, import patterns, error handling style, test patterns, documentation style, type usage, API conventions, security patterns, logging patterns
- Each gene: name, value (dominant convention), confidence, evidence count
- DNA Profile: collection of all genes for a project
- DNA Comparison: diff two profiles to measure convention drift
- **Action**: Quantifies codebase identity for drift detection and cross-project comparison

### DNA Health & Mutations (Rust)
- Health score: consistency(40%) + confidence(30%) + mutations(20%) + coverage(10%) → [0,100]
- Genetic diversity metric: distinct alleles across genes, normalized
- Mutation detector: non-dominant allele occurrences → Mutation records
- Impact classification: high (frequency<10% ∧ dominant>80%), medium (frequency<30%), low (else)
- Thresholds: dominantMinFrequency=0.6, healthScoreWarning=70, healthScoreCritical=50
- **Action**: Identifies files deviating from dominant conventions, scores codebase health

### Decision Mining (Rust) — 12 Categories
- Categories: framework choice, ORM selection, auth strategy, error handling approach, test framework, logging strategy, API style, state management, deployment pattern, caching strategy, messaging pattern, database choice
- Evidence: code patterns + frequency + consistency
- **Action**: Discovers implicit architectural decisions from codebase conventions

### Decision Mining — Git Integration (TS)
- GitWalker: traverses git history (max 1000 commits, configurable)
- CommitParser: parses conventional commits (feat/fix/refactor/perf/etc.), extracts semantic signals
- DiffAnalyzer: architectural signals from diffs, dependency change detection (package.json, requirements.txt, pom.xml)
- **Action**: Extracts architectural decision evidence from git history

### Simulation Engine (TS) — 13 Task Categories, 15 Approach Strategies
- Task categories: add_feature, fix_bug, refactor, optimize, add_test, add_docs, security_fix, dependency_update, config_change, migration, integration, monitoring, deployment
- 15 approach strategies per task type
- Uses call graph + patterns + constraints to predict affected areas
- **Action**: "What if" analysis — predicts impact of proposed changes

### Simulation Scorers (TS) — 4 Dimensions
- **FrictionScorer**: 5 factors (code churn, pattern deviation, testing effort, refactoring, learning curve) → 0-100
- **ImpactScorer**: Call graph blast radius → risk score 0-100, levels (low<25, medium<50, high<75, critical≥75)
- **PatternAlignmentScorer**: Alignment with established patterns, outlier risk detection
- **SecurityScorer**: Data access implications, auth implications, security warnings
- **Action**: Multi-dimensional scoring of proposed change approaches

### Language Intelligence (Rust) — 5 Normalizers, 5 Framework Patterns
- Normalizers: TypeScript, Python, Java, C#, PHP
- Framework patterns: Spring (Java), FastAPI (Python), NestJS (TypeScript), Laravel (PHP), ASP.NET (C#)
- Pipeline: extractRaw → detectFrameworks → normalizeFunction → deriveFileSemantics
- Function semantics: isEntryPoint, isInjectable, isAuthHandler, isTestCase, isDataAccessor, requiresAuth
- File semantics: isController, isService, isModel, isTestFile, primaryFramework
- Cross-language queries: findEntryPoints, findDataAccessors, findInjectables, findAuthHandlers, findByCategory (12 categories)
- **Action**: Cross-language semantic normalization for unified analysis

---

## Category 14 — Directory Map

### v2 Crate Structure
```
crates/
├── drift/
│   ├── drift-core/        # ALL analysis: parsers, scanner, call graph, detectors,
│   │                      # boundaries, coupling, reachability, constants, environment,
│   │                      # wrappers, test topology, error handling, DNA, constraints,
│   │                      # unified analysis, language intelligence, taint analysis,
│   │                      # secret detection, GAST normalization
│   └── drift-napi/        # Full NAPI bridge (all Rust → Node.js, batch/streaming)
├── cortex/                # Already built — 19 crates
└── cortex-drift/          # Bridge (optional, when both present)
    ├── cortex-drift-bridge/   # Event mapping, link translation, grounding
    ├── cortex-drift-napi/     # Combined NAPI bindings
    └── cortex-drift-mcp/      # Combined MCP tools
```

---

## Category 15 — Build Strategy (Ground-Up)

### Not a Migration — A Rewrite
- v1 is erased. No migration path, no dual-path, no legacy compatibility
- Build each system from scratch in Rust, guided by v2 research specs
- TS layer built fresh as thin orchestration over NAPI

### Build Phases
1. Rust foundation: parsers (10 langs), scanner, SQLite schema
2. Rust analysis: call graph, detectors (trait-based), boundaries
3. Rust intelligence: confidence scoring, outlier detection, pattern aggregation, reachability, test topology, error handling, constraints, contracts, DNA, language intelligence
4. Rust enforcement: rules engine evaluator, quality gate evaluation
5. TS presentation: MCP server, CLI, VSCode, LSP, Dashboard
6. TS infrastructure: licensing, workspace management, telemetry, CI agent

---

## Category 16 — Gap Analysis (Critical Items for v2)

### P0 — Must Build
1. **Licensing & Feature Gating** → 3 tiers, 16 features, JWT + simple keys, runtime gating
2. **Workspace Management** → Project lifecycle: init, switch, backup, migrate
3. **Confidence Scorer + Pattern Matcher** → v1 baseline weights (0.40/0.30/0.15/0.15), v2 Bayesian target (Beta posterior + momentum), thresholds (0.85/0.70/0.50)
4. **Context Generation** → AI-ready context from Drift data, 11 package managers, token budgeting
5. **Audit System** → Health scoring (5 weighted factors), degradation detection
6. **Configuration System** → Config loading, env overrides, .driftignore, validation
7. **Taint Analysis Foundation** → Source/sink/sanitizer TOML registry, intraprocedural tracking, taint summaries
8. **Observability Infrastructure** → `tracing` crate instrumentation, per-subsystem metrics, configurable log levels
9. **Declarative Pattern Definitions** → TOML format, graduated complexity, user custom patterns without recompiling
10. **Dual Licensing** → Apache 2.0 + BSL 1.1, per-file headers

### P1 — Important
7. **Telemetry** → Client + Cloudflare Worker backend
8. **MCP Feedback System** → Reinforcement learning for example quality
9. **MCP Pack Manager** → Custom packs, suggestion engine
10. **MCP Curation System** → Anti-hallucination verification for pattern approval
11. **CI Agent** → 9 parallel analysis passes, GitHub/GitLab integration
12. **AI Providers** → Anthropic, OpenAI, Ollama for explain + fix
13. **OWASP 2025 Alignment** → CWE mapping per detector, 9/10 coverage
14. **Enterprise Secret Detection** → 100+ patterns, Shannon entropy, connection string parsing
15. **Contract Expansion** → GraphQL, gRPC, OpenAPI support
16. **Violation Feedback Loop** → Tricorder-style FP tracking, detector health, auto-disable

### Deep Algorithm Values (Must Match Exactly)
- **Confidence (v1 baseline)**: frequency×0.40 + consistency×0.30 + age×0.15 + spread×0.15
- **Confidence (v2 Bayesian target)**: posterior_mean × 0.70 + consistency × 0.15 + momentum × 0.15, where posterior = Beta(1+k, 1+n-k), momentum = (current_freq - prev_freq) / prev_freq normalized [0,1]
- **Bayesian Tiers**: Established (mean>0.7, CI<0.15), Emerging (mean>0.5, CI<0.25), Tentative (mean>0.3, CI<0.40), Uncertain (else)
- **Health Score (Audit)**: avgConfidence×0.30 + approvalRatio×0.20 + complianceRate×0.20 + crossValidation×0.15 + duplicateFree×0.15 → ×100 → [0,100]
- **Health Score (DNA)**: consistency×0.40 + confidence×0.30 + mutations×0.20 + coverage×0.10 → [0,100]
- **Audit Auto-Approve**: confidence≥0.90, outlierRatio≤0.50, locations≥3, no error-severity
- **Learning**: minOccurrences=3, dominance=0.60, minFiles=2, maxFiles=1000
- **Feedback**: good=+0.1, bad=-0.15, irrelevant=-0.05, dirPropagation=30%
- **Duplicate Detection**: Jaccard similarity on location sets, threshold=0.85, merge>0.9
- **Outlier Z-Score** (n≥30): threshold=2.5 (v2, was 2.0 in v1), significance tiers: |z|>3.5=critical, >3.0=high, >2.5=moderate
- **Outlier Grubbs'** (10≤n<30): iterative with 3-iteration cap
- **Outlier IQR** (n<30): multiplier=1.5
- **Outlier Minimum Sample**: 10 (not 3)
- **Error Quality Score**: Base 50, +20 try/catch, +15 recover, -25 swallowed, -20 unhandled async → [0,100]
- **Error Risk Score**: Base 50, +30 swallowed, +25 unhandled-async, +20 entry point → min(100)
- **Impact Risk**: files(25) + entry points(30) + sensitive paths(30) + strategy risk(15) → [0,100]
- **Shannon Entropy**: base64 > 4.5, hex > 3.0, general > 4.0
- **Secret Contextual Scoring**: variable name sensitivity (+0.10), test file (-0.20), comment (-0.30), .env file (+0.10), placeholder (-1.00)
- **Violation FP Rate**: (dismissed + ignored) / (fixed + dismissed + ignored + autoFixed), alert >10%, auto-disable >20% for 30+ days


---

## Category 17 — Test Topology (Rust — 35+ Frameworks, 9 Languages)

### Framework Coverage
- **TypeScript/JS**: Jest, Vitest, Mocha, Ava, Tape
- **Python**: Pytest, Unittest, Nose
- **Java**: JUnit4, JUnit5, TestNG
- **C#**: xUnit, NUnit, MSTest
- **PHP**: PHPUnit, Pest, Codeception
- **Go**: go-testing, Testify, Ginkgo, Gomega
- **Rust**: rust-test, tokio-test, proptest, criterion, rstest
- **C++**: GTest, Catch2, Boost.Test, doctest, CppUnit

### Per-Language Extractors (Rust)
- Framework detection, test case extraction, mock extraction, setup block extraction
- Tree-sitter primary + regex fallback
- **Action**: Extracts test cases, mocks, fixtures per file per framework

### Coverage Mapping (Rust)
1. Resolve direct function calls → function IDs
2. Transitive calls via call graph BFS
3. Record test → function mapping with reach type (direct/transitive/mocked)
4. Per source file: coverage %
- **Action**: Maps which tests cover which production functions

### Minimum Test Set (Rust)
- Given changed files → find functions → find covering tests → deduplicate
- Returns: selected tests, total vs selected, time savings, coverage %
- **Action**: "Which tests should I run after this change?"

### Uncovered Function Detection (Rust)
- Risk score (0-100): entry point (+30), sensitive data (+25), call graph centrality
- Inferred reasons: dead-code, framework-hook, generated, trivial, test-only, deprecated
- **Action**: Identifies untested high-risk functions

### Mock Analysis (Rust)
- Classify external (good) vs internal (suspicious)
- Per-test mock ratio, high-mock-ratio threshold (>0.7)
- **Action**: Identifies brittle tests with excessive mocking

### Test Quality Signals (Rust)
- assertionCount, hasErrorCases, hasEdgeCases, mockRatio, setupRatio, score (0-100)
- **Action**: Quantifies individual test quality

---

## Category 18 — Constraints System (Rust — 12 Invariant Types, 10 Categories)

### 10 Categories
api, auth, data, error, test, security, structural, performance, logging, validation

### 12 Invariant Types
1. `must_have` — Required element present
2. `must_not_have` — Forbidden element absent
3. `must_precede` — Ordering (A before B)
4. `must_follow` — Ordering (A after B)
5. `must_colocate` — Same module
6. `must_separate` — Different modules
7. `must_wrap` — Wrapped (try/catch, if-check)
8. `must_propagate` — Error/event propagates through chain
9. `cardinality` — Count constraints (min/max)
10. `data_flow` — Data flows through specific path
11. `naming` — Naming convention enforcement
12. `structure` — File/directory structure requirements

### Pipeline (Rust)
1. **InvariantDetector** → Mines from 5 sources (patterns, call graph, boundaries, test topology, error handling)
2. **ConstraintSynthesizer** → Converts to Constraint objects, merges similar (threshold 0.8)
3. **ConstraintStore** → SQLite persistence in drift.db
4. **ConstraintVerifier** → AST-based predicate evaluation (full file or change-aware mode)

### Verification (Rust)
- Full file: all applicable constraints
- Change-aware: only checks changed lines (reduces noise)
- Predicate types: function, class, entry point, naming, structure
- **Action**: Enforces architectural invariants learned from codebase

### Status Lifecycle
`discovered` → `approved` (enforced) | `ignored` (not enforced) | `custom` (user-defined)

---

## Category 19 — Error Handling Analysis (Rust — 4 Phases)

### Phase 1 — Function Profiling (Rust)
- Per function: detect try/catch, throw capability, catch clauses (type, action, preservesError), async handling, quality score (0-100)

### Phase 2 — Propagation Chain Building (Rust)
- Walk up call graph from throwers, find catch boundaries, max depth 20, cycle detection

### Phase 3 — Unhandled Path Detection (Rust)
- Chains where sink=null → severity by entry point type (exported=critical, entry point file=critical, else=medium)

### Phase 4 — Gap Detection (Rust)
- no-try-catch, swallowed-error, unhandled-async, bare-catch, missing-boundary

### Quality Score: Base 50, +20 try/catch, +15 recover, +10 transform, +5 preserves error, -25 swallowed, -20 unhandled async → [0,100]
### Risk Score: Base 50, +30 swallowed, +25 unhandled-async, +20 entry point, +15 exported → min(100)

### Framework Boundary Detection (Rust)
- React ErrorBoundary, Express middleware (4 params), NestJS filter, Spring @ExceptionHandler, Laravel handler

### Rust-Specific Gap Detection
- `.unwrap()` → High severity
- `.expect()` → Medium severity
- `.then()` without `.catch()` → UnhandledPromise

---

## Category 20 — Contracts (Rust — BE↔FE Matching)

### Contract Tracking (Rust)
- Discovers API contracts between backend and frontend
- Matches: endpoint definitions (BE) ↔ API calls (FE)
- Tracks: URL, HTTP method, request/response schemas, auth requirements

### Backend Framework Support (Rust)
- Express, NestJS, FastAPI, Flask, Spring Boot, Laravel, Django, ASP.NET

### Frontend Library Support (Rust)
- fetch, axios, React Query, SWR, Angular HttpClient

### Path Similarity Algorithm (Rust)
- Multi-factor weighted: segment names (Jaccard), segment count, suffix match, resource name, parameter positions

### Verification (Rust)
- Schema compatibility checking
- Breaking change detection (field removed, type changed)
- Unused endpoint detection (BE with no FE consumer)
- Orphaned call detection (FE with no BE endpoint)

### Contract Protocol Expansion (Rust) — REST + GraphQL + gRPC
- **GraphQL**: Schema extraction (.graphql files, code-first SDL, introspection), schema↔resolver mismatch detection, frontend query↔schema mismatch (useQuery/useMutation), N+1 resolver detection, breaking change detection
- **gRPC/Protobuf**: .proto file parsing, service/message definitions, client↔server mismatch, breaking change detection, frontend usage via generated stubs
- **OpenAPI/Swagger**: Spec parsing as first-class contract source, endpoint↔spec validation
- Change classification across all protocols: breaking / non-breaking / deprecation
- **Action**: Full API contract coverage across REST, GraphQL, and gRPC

---

## Category 21 — Security & Data Boundaries (Rust)

### Two-Phase: Learn-Then-Detect (Rust)
1. DataAccessLearner → Discovers frameworks, table names, naming conventions
2. BoundaryScanner → Uses learned patterns + regex fallback

### 28+ ORM Frameworks, 8 Languages (Rust)
- C#: EF Core, Dapper
- Python: Django, SQLAlchemy, Tortoise, Peewee
- TypeScript/JS: Prisma, TypeORM, Sequelize, Drizzle, Knex, Mongoose, Supabase
- Java: Spring Data, Hibernate, jOOQ, MyBatis
- PHP: Eloquent, Doctrine
- Go: GORM, sqlx, Ent, Bun
- Rust: Diesel, SeaORM, tokio-postgres, rusqlite
- Generic: Raw SQL

### 4 Sensitivity Categories (Rust)
- PII (0.5-0.95), Credentials (0.7-0.95), Financial (0.8-0.95), Health (0.9-0.95)

### 4 Security Tiers
- Critical: credentials, financial
- High: PII, health
- Medium: general data with sensitive fields
- Low: standard data access

### Secret Detection — Enterprise-Grade (Rust)
- 100+ regex patterns organized by provider: Cloud (AWS 5, GCP 4, Azure 4, DigitalOcean 2, Heroku 2), Code platforms (GitHub 3, GitLab 2, Bitbucket 2, npm 2, PyPI 2), Payment (Stripe 3, Square 2, PayPal 2), Communication (Slack 3, Twilio 2, SendGrid 2), Database (connection strings 4, passwords 3), Auth (JWT 2, OAuth 2, bearer tokens 2), Crypto (RSA/SSH/PGP private keys 3), Generic (password/secret/API key assignments)
- Shannon entropy calculator: per-charset thresholds (base64 > 4.5, hex > 3.0, general > 4.0)
- Contextual confidence scoring: variable name sensitivity (+0.10), test file (-0.20), comment (-0.30), .env file (+0.10), placeholder detected (-1.00)
- Connection string parsing for embedded credentials (MongoDB, PostgreSQL, MySQL, Redis, MSSQL)
- Base64-encoded secret detection: decode candidates, check decoded content against patterns
- Declarative TOML format for pattern maintenance
- **Action**: Catches both known secret formats (regex) and unknown formats (entropy)

### OWASP 2025 Alignment & CWE Mapping (Rust)
- Every security detector maps to specific CWE ID(s) in detector definition metadata
- OWASP Top 10 2025 coverage target: 9/10
  - A01 (Broken Access Control): permission-checks, rbac-patterns, path-traversal, cors-misconfiguration
  - A02 (Cryptographic Failures): weak-crypto-algorithms (MD5, SHA1), insecure cipher modes (ECB), hardcoded IVs/keys
  - A03 (Software Supply Chain): dependency file analysis, lockfile integrity checks
  - A04 (Insecure Design): missing-rate-limiting, missing-input-validation, trust-boundary-violations
  - A05 (Security Misconfiguration): debug-mode-enabled, default-credentials, missing-security-headers
  - A07 (Auth Failures): weak-password-policy, missing-mfa-check, session-fixation
  - A08 (Integrity Failures): insecure-deserialization, unsigned-data-acceptance
  - A09 (Logging Failures): missing-security-logging, pii-in-logs
  - A10 (SSRF): ssrf-detection, url-from-user-input
- SARIF output enriched with CWE IDs, code flows, fix objects
- **Action**: Enterprise compliance readiness with traceable security findings

---

## Category 22 — Context Generation

### Context Generator (Rust + TS)
- Generates AI-ready context from Drift data (~2000 tokens vs 50,000 raw)
- Powers `drift_context` and `drift_package_context` MCP tools
- Package detection (Rust), token budgeting (Rust), context assembly (TS)

### Package Detector (Rust) — 11 Package Managers
npm, pnpm, yarn, Python (pyproject.toml/setup.py/setup.cfg), Go (go.mod/go.work), Maven, Gradle, Composer, .NET (.csproj/.sln), Cargo, Ruby (Gemfile)

### Token Management (Rust)
- Token budgeting per context section
- Priority-based inclusion (most relevant first)
- Truncation with summary when over budget

---

## Category 23 — Pattern Repository (TS)

### Architecture
- `IPatternRepository` → Full CRUD, querying, filtering, sorting, pagination, events
- `IPatternService` → Consumer API for MCP/CLI/Dashboard
- SQLite-backed (drift.db) — no file-based repositories
- **Action**: Clean data access layer for pattern CRUD

---

## Category 24 — Data Lake (ELIMINATED)

> Fully removed in v2. All functionality replaced by SQLite queries/views over drift.db.

---

## Category 25 — Services Layer (TS)

### ScannerService (TS)
- Coordinates: calls Rust scanner via NAPI → Rust does all analysis → TS stores results
- No worker threads (Rust rayon handles parallelism)
- Incremental scanning via content hash comparison
- **Action**: Top-level scan orchestration from CLI/MCP entry points

---

## Category 26 — Workspace Management (TS)

### WorkspaceManager → Workspace initialization, project root detection, .drift/ creation
### ProjectSwitcher → Multi-project switching, cache invalidation, store reloading
### ContextLoader → Hydrates all stores from drift.db on project load
### BackupManager → Backup creation/restoration, retention policy
### SchemaMigrator → drift.db schema migrations across versions
### Configuration → drift.config.json loading, env overrides, .driftignore


---

## Cross-Cutting: Pattern System (Central Entity)

### Pattern (Rust)
- 16 categories × 3 statuses × 3 detection methods
- Pattern definition: ASTMatchConfig, RegexMatchConfig, StructuralMatchConfig
- Pattern matching engine: multi-strategy (AST, regex, structural), LRU cache (1000 entries, 60s TTL)
- Detection pipeline (8 phases): scan → parse → detect → aggregate → score → outlier detect → store → violations
- **Action**: The core loop — discover conventions, score confidence, flag deviations

### Audit System (Rust + TS)
- AuditEngine → Pattern validation, health scoring, degradation detection
- Health Score: avgConfidence×0.30 + approvalRatio×0.20 + complianceRate×0.20 + crossValidation×0.15 + duplicateFree×0.15 → ×100 → [0,100]
- Auto-approve: confidence≥0.90, outlierRatio≤0.50, locations≥3, no error-severity
- **Action**: Tells users "your codebase is drifting" — core value proposition

### Violation Feedback Loop (Tricorder-style)
- "Not useful" / "Useful" signals on every violation (MCP, CLI, IDE)
- Track violation actions: Fixed, Dismissed, Ignored, AutoFixed, NotSeen
- Effective FP rate per detector: `(dismissed + ignored) / (fixed + dismissed + ignored + autoFixed)`
- Detector health: alert at >10% FP rate, auto-disable at >20% for 30+ days
- Developer action (fix, ignore, approve) feeds back into pattern confidence
- Project-level customization, not user-level
- Expose health metrics via MCP, track in IDE (opt-in), CLI, and CI
- **Action**: Continuous improvement loop — builds developer trust, reduces noise over time

### Event System (Rust traits)
- Trait-based event bus with typed events (not EventEmitter)
- Default method implementations are no-ops
- DriftEventHandler: on_pattern_approved, on_scan_complete, on_regression_detected
- Zero overhead when no handlers registered
- **Action**: System-wide typed pub/sub for reactive updates

---

## Cross-Cutting: Bridge (Optional — Cortex + Drift)

### cortex-drift-bridge (Rust)
- Event mapping: Drift events → Cortex memories (pattern:approved → pattern_rationale memory)
- Link translation: Drift PatternLink → Cortex EntityLink
- Grounding logic: Compare Cortex memories against Drift scan results
- **Action**: Connects Drift scanning to Cortex memory

### cortex-drift-mcp (TS)
- Combined MCP tools: drift_why (synthesizes pattern data + causal memory), drift_memory_learn
- Registered conditionally when both systems detected
- **Action**: Tools that need both Drift + Cortex

### Grounding Feedback Loop (The Killer Feature)
1. Cortex stores memory: "Team uses repository pattern"
2. Drift scans: 87% repository pattern → memory is 87% grounded
3. Team refactors away → Drift scan: 45% → memory confidence decreases
4. Cortex validation engine heals or creates contradiction
- **Action**: Empirically validated AI memory — beliefs checked against ground truth

---

## Master Build Order (v2 Ground-Up)

### Tier 0 — Foundation (No Dependencies)
- [ ] Rust parsers (10 languages) — tree-sitter extraction with full construct support
- [ ] Rust scanner — parallel file walking, hashing, filtering
- [ ] SQLite schema — drift.db with 40+ tables (including posterior parameters for Bayesian scoring)
- [ ] NAPI bridge — Rust↔Node.js interface with batch/streaming support
- [ ] `thiserror` error enums per subsystem — structured error handling from day one
- [ ] `tracing` crate instrumentation scaffolded — observability from day one
- [ ] TOML pattern definition format finalized — declarative patterns
- [ ] Source/sink/sanitizer registry format defined (TOML) — taint analysis foundation
- [ ] String interning with `lasso` — ThreadedRodeo for build, RodeoReader for query

### Tier 1 — Core Analysis (Depends on Tier 0)
- [ ] Unified analysis engine — 4-phase AST+regex pipeline with string interning
- [ ] Visitor pattern detection engine — single-pass AST traversal, all detectors as visitors
- [ ] Generic AST Normalization Layer (GAST) — ~30 normalized node types, per-language normalizers
- [ ] Call graph builder — function→function edges, 6 resolution strategies, `petgraph` in-memory graph
- [ ] Detector system — trait-based (Base→Learning→Semantic), 16 categories
- [ ] Detector registry — category mapping, language filtering
- [ ] Framework-specific detectors — Spring, ASP.NET, Laravel, Django, Go, Rust, C++
- [ ] Boundary detection — 28+ ORMs, sensitive field classification
- [ ] Constants & environment extraction
- [ ] Wrapper detection + clustering
- [ ] Declarative pattern loading from TOML — hardcoded defaults + user custom patterns

### Tier 2 — Intelligence (Depends on Tier 1)
- [ ] Bayesian confidence scoring — Beta distribution posterior + momentum, graduated tiers
- [ ] Outlier detection — Z-Score (2.5), Grubbs' (10≤n<30), IQR, rule-based
- [ ] Pattern aggregation — group by ID, deduplicate, merge across files
- [ ] Pattern matching engine — AST, regex, structural strategies + LRU cache (`Moka`)
- [ ] Incremental detection — content-hash skipping (3 layers: file, pattern, convention)
- [ ] Reachability analysis — forward/inverse BFS, taint analysis, sensitivity classification
- [ ] Taint analysis foundation — source/sink TOML registry + intraprocedural tracking + taint summaries
- [ ] Impact analysis — blast radius, dead code, path finding
- [ ] Test topology — 35+ frameworks, coverage mapping, minimum test set, quality signals
- [ ] Error handling — 4-phase topology, quality scoring, gap detection, framework boundaries
- [ ] Constraint detection — 12 invariant types from 5 data sources
- [ ] Constraint verification — AST-based predicate evaluation, change-aware mode
- [ ] Contract tracking — BE↔FE matching, path similarity, schema compatibility
- [ ] DNA system — 10 gene extractors, health scoring, mutation detection
- [ ] Language intelligence — 5 normalizers, 5 framework patterns, cross-language queries
- [ ] Unified language provider — 9 normalizers, 20 ORM matchers
- [ ] Module coupling — afferent/efferent metrics, Tarjan's SCC, zone classification
- [ ] N+1 query detection — call graph + ORM pattern analysis
- [ ] Enterprise secret detection — 100+ patterns, Shannon entropy, contextual scoring, connection strings
- [ ] Feedback loop infrastructure — violation-level "useful"/"not useful" tracking

### Tier 3 — Enforcement (Depends on Tier 2)
- [ ] Rules engine evaluator — pattern matcher → violations → severity
- [ ] Quality gates — 6 gates + orchestrator + policy engine (4 modes, 4 built-in policies)
- [ ] Audit system — health scoring, degradation detection, snapshots
- [ ] Quality gate persistence — snapshots + run history in drift.db

### Tier 4 — Advanced (Depends on Tier 2-3)
- [ ] Decision mining — 12 categories + git integration
- [ ] Simulation engine — 13 task categories, 15 strategies, 4 scorers
- [ ] Context generation — 11 package managers, token budgeting
- [ ] OWASP 2025 alignment — CWE mapping per detector, 9/10 coverage, cryptographic failure detection
- [ ] Taint-based vulnerability detection — SQLi, XSS, SSRF, path traversal (interprocedural via call graph)
- [ ] Contract expansion — GraphQL schema parsing, gRPC protobuf parsing, OpenAPI spec parsing

### Tier 5 — Presentation (Depends on All Above)
- [ ] MCP server — split: drift-analysis + drift-memory, progressive disclosure, 3 entry points each, packs, feedback, curation
- [ ] CLI — 48-65+ commands, setup wizard, git integration, reporters, `drift secrets`, `drift taint`
- [ ] VSCode extension — commands, views, diagnostics, code actions
- [ ] LSP server — diagnostics, code actions, hover
- [ ] Dashboard — Vite + React + Tailwind
- [ ] Galaxy — 3D visualization

### Tier 6 — Infrastructure (Parallel with All)
- [ ] Configuration system — config loading, env overrides, .driftignore
- [ ] Licensing & feature gating — 3 tiers, 16 features, JWT validation
- [ ] Dual licensing — Apache 2.0 + BSL 1.1, per-file headers
- [ ] Workspace management — init, switch, backup, migrate
- [ ] Telemetry — client + Cloudflare Worker
- [ ] CI agent — 9 analysis passes, GitHub/GitLab, SARIF
- [ ] AI providers — Anthropic, OpenAI, Ollama
- [ ] GitHub Action — composite action
- [ ] Docker deployment — multi-stage build, SSE transport
- [ ] CIBench — 4-level benchmark framework
- [ ] Observability — `tracing` instrumentation, per-subsystem metrics, configurable log levels, optional OpenTelemetry

### Bridge (Optional — When Cortex + Drift Both Present)
- [ ] cortex-drift-bridge — event mapping, link translation, grounding logic
- [ ] cortex-drift-napi — combined NAPI bindings
- [ ] cortex-drift-mcp — combined MCP tools
- [ ] Grounding feedback loop — empirically validated memory

---

## Numeric Summary

| System | Count |
|--------|-------|
| Languages parsed (Rust) | 10 |
| Detector categories | 16 |
| Detector trait variants | 3 per category |
| Framework-specific detector suites | 7 |
| Call graph languages | 9 |
| Call resolution strategies | 6 |
| ORM frameworks supported | 28+ |
| ORM/framework matchers (unified provider) | 20 |
| Language normalizers (unified provider) | 9 |
| Language normalizers (intelligence) | 5 |
| Framework patterns (intelligence) | 5 |
| Field extractors | 7 |
| Sensitivity categories | 4 |
| Analyzers (AST/Type/Semantic/Flow) | 4 |
| Test frameworks | 35+ |
| Constraint categories | 10 |
| Invariant types | 12 |
| Error handling phases | 4 |
| Quality gates | 6 |
| Quality gate policies (built-in) | 4 |
| Quality gate aggregation modes | 4 |
| Quality gate reporters | 5 |
| MCP servers | 2 (drift-analysis + drift-memory) |
| MCP tools | 56+ |
| MCP entry points per server | 3 (progressive disclosure) |
| CLI commands | 48-65+ |
| CLI setup runners | 13 |
| CLI reporters | 4 (+SARIF) |
| DNA gene extractors | 10 |
| DNA health factors | 4 |
| Decision mining categories | 12 |
| Simulation task categories | 13 |
| Simulation approach strategies | 15 |
| Simulation scorers | 4 |
| Package managers detected | 11 |
| SQLite tables (drift.db) | 40+ |
| Rust unified analysis AST query sets | 9 per language |
| Rust string analysis regex sets | 4 (SQL, routes, sensitive, env) |
| Enterprise features gated | 16 |
| Licensing tiers | 3 |
| Quick fix strategies | 7 |
| Outlier detection methods | 3 (+Grubbs') |
| Confidence scoring factors | 4 (v1) / Bayesian posterior + momentum (v2) |
| Confidence tiers (v2 Bayesian) | 4 (Established/Emerging/Tentative/Uncertain) |
| Health scoring factors (audit) | 5 |
| Health scoring factors (DNA) | 4 |
| AI providers | 3 |
| CI analysis passes | 9 |
| CI pluggable interfaces | 12 |
| CIBench evaluation levels | 4 |
| Secret detection patterns | 100+ |
| Secret detection cloud providers | 25+ |
| Shannon entropy thresholds | 3 (base64>4.5, hex>3.0, general>4.0) |
| OWASP Top 10 2025 coverage | 9/10 |
| Taint vulnerability classes | 4 (SQLi, XSS, SSRF, Path Traversal) |
| Contract protocols | 3 (REST, GraphQL, gRPC) |
| GAST normalized node types | ~30 |
| Architectural decisions (P0) | 12 (AD1-AD12) |
| NAPI platform targets | 7 |

---

## What's NOT in v2 (Eliminated from v1)

- JSON shard storage (.drift/patterns/, .drift/contracts/, etc.)
- Data lake (.drift/lake/)
- Hybrid stores (JSON + SQLite sync)
- JSON↔SQLite sync service
- TS parsers (BaseParser, ParserManager, tree-sitter loaders)
- TS detectors (all 350+ files — replaced by Rust trait-based system)
- TS call graph extractors (replaced by Rust universal extractor)
- TS analyzers (AST/Type/Semantic/Flow — replaced by Rust)
- Worker threads / Piscina (replaced by Rust rayon)
- Dual-path MCP architecture (SQLite-only, no legacy JSON path)
- Store factory auto-detection (no JSON to detect)
- Legacy compatibility layers (legacy-extractors.ts, legacy-scanner.ts)
- Separate callgraph.db (merged into drift.db)

---

*End of audit. Every v2 system from categories 00-26 (excluding 06-cortex) is accounted for above.*
*All v2-research recommendations (AD1-AD12, NR1-NR32, RC/PA/DE/CG/AN/MC/ST/QG/CL/ID/IN/AV/SP/DI series) are incorporated.*
*This is a ground-up build plan. v1 is erased.*


---

## Appendix A — V1 Research Cross-Reference: Missing Context & Key References

> This appendix captures features, algorithms, specific values, and architectural details from the v1 research documents (`.research/*/RECOMMENDATIONS.md`) that are NOT already specified in the audit above. These are the gaps that, if forgotten, would cause v2 feature degradation. No source code — only references and key context needed for recreation.

---

### A1. Pipelines — End-to-End Operational References (Cat 00)

The audit defines subsystems but does not include the 7 end-to-end pipeline definitions from `00-overview/pipelines.md`. These are critical operational references for how subsystems compose:

1. **Full Scan Pipeline** (`drift scan`): 12-step sequence — resolve project → file discovery → parsing → detection → aggregation → confidence scoring → pattern storage → optional call graph → optional boundary scan → optional contract scan → optional manifest → finalization. Duration target: 2-30s typical, 5min large monorepos. Health monitoring warns at 30s, kills at 300s timeout.
2. **Violation Check Pipeline** (`drift check`): 5-step — resolve files (supports `--staged` for pre-commit) → load approved patterns → evaluate via rules engine → report (text/json/github/gitlab) → exit code (0=clean, 1=violations).
3. **MCP Context Query Pipeline** (`drift_context`): 7-step — pattern retrieval by relevance → code examples (prefer same-directory) → Cortex retrieval with intent weighting → call graph context (1-2 hops) → boundary context → synthesis with token budget → response with metadata.
4. **Quality Gate Pipeline** (`drift gate`): 5-step — load policy → execute gates in parallel (pattern compliance, constraint verification, regression detection, impact analysis, security boundary, custom rules) → aggregate (4 modes: all-pass, any-pass, weighted, custom) → report → exit code.
5. **Memory Retrieval Pipeline** (`drift_why`): 7-step — gather candidates (topic + pattern + file + function search) → score → intent weighting → session deduplication → causal narrative traversal → hierarchical compression (4 levels) → response.
6. **Setup Wizard Pipeline** (`drift setup`): 8 phases — prerequisites → init (30+ subdirectories) → scan + approval → core features → deep analysis → derived features → memory init → finalize. Supports `--resume` via persisted SetupState.
7. **Learning Pipeline** (`drift_memory_learn`): 7-step — correction analysis (10 categories) → diff analysis → principle extraction → memory creation → causal inference → contradiction check → persistence.


### A2. Data Models — Missing Type Details (Cat 00)

The audit references data models but omits several key type definitions from `00-overview/data-models.md`:

- **Contract type**: `{ id, method (GET/POST/PUT/PATCH/DELETE), endpoint, backend: BackendEndpoint { method, path, file, line, responseFields, framework }, frontend: FrontendApiCall[] { method, path, file, line, responseFields, library }, mismatches: FieldMismatch[] { fieldPath, mismatchType, description, severity }, status (discovered/verified/mismatch/ignored), confidence: ContractConfidence { score, level, matchConfidence, fieldExtractionConfidence } }`
- **DriftConfig type**: `{ severity?: Record<string, Severity>, ignore?: string[], ai?: { provider, model }, ci?: { failOn, reportFormat }, learning?: { autoApproveThreshold, minOccurrences }, performance?: { maxWorkers, cacheEnabled, incrementalAnalysis } }`. Config file: `drift.config.json`. Env overrides: `DRIFT_AI_PROVIDER`, `DRIFT_AI_MODEL`, `DRIFT_CI_FAIL_ON`.
- **Pattern categories**: The audit lists 15 categories but the data model defines 15 explicitly: api, auth, components, config, data-access, documentation, errors, logging, performance, security, structural, styling, testing, types, validation. Ensure "validation" is not dropped.
- **Confidence scoring weights** (canonical from code): frequency 0.40, consistency 0.30, age 0.15, spread 0.15. Levels: high ≥0.85, medium ≥0.70, low ≥0.50, uncertain <0.50.


### A3. Parsers — Missing Details (Cat 02)

From `.research/02-parsers/RECOMMENDATIONS.md`:

- **Moka cache specifics**: TinyLFU admission + LRU eviction, 10K entry capacity, durable persistence via bincode serialization to SQLite blob column. Cache key: `(file_path, content_hash)`. Cache value: full `ParseResult`.
- **Error-tolerant extraction**: When tree-sitter produces ERROR nodes, extract partial results from valid subtrees rather than failing the entire file. Track error recovery rate per language.
- **Thread-safe parser pool**: Use `thread_local!` storage for tree-sitter parsers (they are not Send). Each rayon worker gets its own parser instance. Explicit cleanup on thread exit.
- **Framework construct extraction**: `FrameworkExtractor` trait as an extension layer on top of base parsing. Extracts framework-specific constructs (route decorators, DI annotations, ORM model definitions) without polluting the core parser.
- **Language parser scaffold macro**: `define_parser!` macro for adding new language support with minimal boilerplate — auto-generates the tree-sitter query loading, node visitor, and NAPI bindings.
- **Consolidated tree-sitter queries**: Reduce from 4-5 AST traversals per file to 2 (one for structure extraction, one for call site extraction) by combining queries.
- **Body hash on FunctionInfo**: Add `body_hash: u64` field to `FunctionInfo` for function-level change detection. When only a function body changes (not its signature), only that function's analysis is invalidated — cross-file analysis is preserved.


### A4. Detectors — Missing Details (Cat 03)

From `.research/03-detectors/RECOMMENDATIONS.md`:

- **Fix generation as first-class output**: Every detector should produce optional `Fix` alongside violations. `FixKind` enum: TextEdit, MultiEdit, Rename, ImportChange, Structural, Suggestion. Fix safety levels: Level 1 (auto-apply safe), Level 2 (review required), Level 3 (suggestion only).
- **Batch fix CLI**: `drift fix --auto` (apply Level 1 fixes), `drift fix --review` (interactive Level 2), `drift fix --category <cat>` (scope by category), `drift fix --detector <id>` (scope by detector).
- **Framework detection as composable middleware**: `FrameworkMiddleware` trait with plugin system. Framework detection runs as a pre-pass, enriching the `ProjectContext` with detected frameworks. Detectors then use framework context to select appropriate patterns.
- **Detector testing framework**: Snapshot testing with annotated fixture files (expected violations marked in comments). Cross-language parity tests (same pattern detected in equivalent TS/Python/Java code). False-positive regression corpus (known FP cases that must not regress). Confidence calibration tests (verify confidence scores are within expected ranges). Performance benchmarks per detector.
- **Contested convention handling**: When two conventions are close in frequency (e.g., 45% vs 55%), report both as "contested" rather than picking the 55% as dominant and flagging the 45% as violations. Threshold: if the gap between top two alleles is <20%, mark as contested.


### A5. Call Graph — Missing Details (Cat 04)

From `.research/04-call-graph/RECOMMENDATIONS.md`:

- **Namespace-based attribute resolution**: Follow PyCG's approach — resolve method calls via class hierarchy MRO (Method Resolution Order). When `obj.method()` is called, walk the MRO chain to find the actual implementation.
- **Call graph accuracy benchmarking**: Micro-benchmarks (per-language, per-pattern precision/recall) and macro-benchmarks (full-project resolution rate) following PyCG methodology. Metrics: precision, recall, resolution-rate (% of call sites resolved to at least one target).
- **Cross-service reachability**: For microservice architectures, extend reachability analysis across service boundaries via contract matching (HTTP endpoint → handler function). Requires contract detection (Cat 20) data.
- **Reachability result caching**: LRU cache for reachability queries. Cache key: `(source_function, target_function)`. Invalidate on call graph rebuild. Critical for MCP tools that repeatedly query reachability.


### A6. Analyzers — Missing Details (Cat 05)

From `.research/05-analyzers/RECOMMENDATIONS.md` (14 recommendations, R1-R14):

- **Salsa-based incremental query system**: Adopt Salsa's "evaluate vs build-first" model from rust-analyzer. Queries are memoized; when inputs change, only dependent queries re-execute. Target: <100ms incremental scan for single-file changes (down from ~10s full rescan).
- **Layered architecture with explicit API boundaries**: Follow rust-analyzer's layer model: syntax → hir-def/hir-ty → hir → ide. Each layer has a public API; no layer reaches into another's internals. This enables independent testing and evolution of each layer.
- **Compilation abstraction for cross-file analysis**: Roslyn-inspired `Compilation` object that represents the entire project's semantic model. Enables cross-file type resolution, import resolution, and symbol lookup without re-parsing.
- **Generalized semantic analysis traits**: `TypeSystem` and `ScopeResolver` traits that all language analyzers implement. Enables language-agnostic analysis passes (e.g., "find all unused imports" works the same for TS, Python, Java).
- **Interprocedural data flow via function summaries**: Per-function summaries (inputs → outputs, side effects, exceptions) composed along call graph edges. Enables cross-function taint analysis and data flow tracking without re-analyzing callee bodies.
- **Quick fix coverage target**: 80%+ of violations should have auto-fix suggestions. Track fix application rate for feedback. Batch fix support ("Fix all in file", "Fix all of type").
- **Analyzer feedback loop**: Track violation actions (Fixed, Dismissed, Ignored, AutoFixed, NotSeen). Compute per-analyzer health: effective FP rate = (dismissed + ignored) / total. Auto-disable analyzers with >20% effective FP rate and >100 total violations.
- **Coupling analyzer Rust parity**: Port Tarjan's SCC algorithm (more efficient than DFS for cycle detection), module roles (Hub/Authority/Balanced/Isolated), zone detection (MainSequence/ZoneOfPain/ZoneOfUselessness), break point suggestions (ExtractInterface/DependencyInversion/MergeModules/IntroduceMediator), refactor impact analysis.
- **Cancellation support**: rust-analyzer's revision counter pattern. Global `AtomicU64` revision; each analysis checks if revision changed. On cancellation, panic with special `Cancelled` value caught at API boundary. Ensures responsiveness during typing.
- **Unified Provider Rust migration**: Port 9 language normalizers and 20 ORM matchers to Rust. `LanguageNormalizer` trait + `OrmMatcher` trait. Enables single-pass analysis (parse + extract call graph + detect ORM patterns simultaneously). Start with most-used ORMs (Prisma, Django, SQLAlchemy).


### A7. MCP Server — Missing Details (Cat 07)

From `.research/07-mcp/RECOMMENDATIONS.md` (18 recommendations):

- **MCP 2025-11-25 spec compliance**: Resources primitive with `drift://` URIs (e.g., `drift://patterns/{id}`, `drift://context/{scope}`). Prompts primitive for workflow templates: `security-audit`, `code-review`, `refactor-plan`. Elicitation for interactive curation workflows. Streamable HTTP transport replacing SSE. Tool Annotations: `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint` on every tool.
- **Tool consolidation target**: ~16 core tools (down from 56+ routed tools). Composition framework for workflow tools: `drift_security_audit`, `drift_refactor_plan`, `drift_code_review`, `drift_debug_context` — each composes multiple internal queries into a single rich response.
- **OAuth 2.1 authorization**: Scope hierarchy for enterprise multi-tenant. Scopes: `drift:read`, `drift:write`, `drift:admin`. Token validation in Rust for performance.
- **OpenTelemetry observability**: Replace custom metrics with OTel spans and metrics. Trace every MCP request end-to-end. Export to Jaeger/Prometheus/OTLP.
- **TinyLFU caching with semantic keys**: Moka cache with TinyLFU admission policy. Cache key includes intent + scope + file hashes. Invalidate on scan completion. Target: <50ms for cached MCP responses.
- **Enhanced anti-hallucination**: 5 verification types — symbol verification (does this function exist?), relationship verification (does A call B?), convention verification (is this the dominant pattern?), security verification (is this endpoint protected?), freshness verification (is this data from the latest scan?).
- **Batch tool execution**: JSON-RPC batching support. Client sends array of tool calls, server executes in parallel, returns array of results. Reduces round-trip overhead for multi-tool workflows.
- **Multi-project connection pooling**: For monorepo/multi-project setups, maintain a pool of database connections per project. Lazy initialization — only connect when a project is first queried.
- **Tool versioning/deprecation workflow**: Semantic versioning on tool schemas. Deprecation notices in tool annotations. Grace period before removal. Migration guides in tool descriptions.


### A8. Storage — Missing Details (Cat 08)

From `.research/08-storage/RECOMMENDATIONS.md` (29 recommendations across 8 phases):

- **DatabaseManager architecture**: Single Rust-owned `drift.db` with write-serialized (`Mutex<Connection>`) + read-pooled (N read connections) strategy. Connection pragmas: `journal_mode=WAL`, `synchronous=NORMAL`, `foreign_keys=ON`, `cache_size=-64000` (64MB), `mmap_size=268435456` (256MB), `busy_timeout=5000`. Close pragmas: `PRAGMA optimize` with `analysis_limit=400`.
- **Schema migration via `rusqlite_migration`**: `PRAGMA user_version` tracking. Migrations as `const` slice of SQL strings via `include_str!()`. Rules: never remove migrations, never backwards-incompatible changes, auto-backup before migration, CI validation test.
- **STRICT tables**: All tables use `STRICT` keyword (SQLite 3.37+). JSON columns use `TEXT` with `CHECK(json_valid(column))` constraints.
- **New tables for v2**: `file_metadata` (content_hash for incremental), `packages` (monorepo registry), `pattern_suppressions` (inline `// drift-ignore`), `migration_history`, `cache_entries`, `project_registry`, `materialized_status`, `materialized_security`.
- **Materialized status tables**: Singleton-row tables refreshed after each scan. Replace Data Lake views for instant `drift_status` responses. `materialized_status` (health_score, trend, pattern counts, scan info) and `materialized_security` (risk_level, violations, sensitive fields).
- **Batch writer with crossbeam channel**: Generalized from call-graph-only to all domains. Bounded channel (`bounded(1024)`) prevents OOM. `BEGIN IMMEDIATE` transactions prevent SQLITE_BUSY. Returns `WriteStats` for telemetry.
- **Incremental file index**: `file_metadata` table with two-level change detection: Level 1 mtime comparison (instant), Level 2 content hash (catches mtime-only changes from git operations). xxhash for content hashing.
- **Keyset pagination**: All list queries use `(sort_column, id)` composite cursor. Base64-encoded opaque cursors. Constant-time regardless of page depth.
- **Expression indexes on JSON columns**: `CREATE INDEX idx ON table(json_extract(column, '$.field'))` for frequently-queried JSON fields. Normalize `mismatches` JSON into `contract_mismatches` table.
- **Hot backup via SQLite Backup API**: `rusqlite::backup::Backup` with chunked transfer (1000 pages, 10ms sleep). Integrity verification after backup. Triggers: before migrations, before `drift upgrade`, before destructive ops, on user request. Retention: last 5 backups.
- **VACUUM strategy**: Conditional — only when freelist > 20% of total pages. Checkpoint WAL first. Run after retention enforcement.
- **WAL checkpoint strategy**: Automatic PASSIVE during normal operation. Explicit TRUNCATE after scans. Emergency checkpoint if WAL exceeds 100MB.
- **Concurrent process safety**: Process-level lock file via `flock()` (Unix) / `LockFileEx` (Windows). Read operations don't acquire lock (WAL handles read concurrency). Only scan operations acquire exclusive lock. PID + timestamp in lock file for diagnostics. `--force` flag for stuck processes.
- **Graceful error handling**: Map all SQLite error codes to actionable `StorageError` variants: Busy (retry), DiskFull (run `drift doctor`), Corrupt (auto-restore from backup), IoError (surface OS details), MigrationFailed (version + detail).
- **v1→v2 upgrade path**: `drift upgrade` command. Detect v1 state (JsonOnly/Hybrid/SqliteOnly/Fresh). Create backup → create/migrate schema → migrate JSON data → migrate quality gates → migrate constraints → archive v1 files → verify.
- **Monorepo support**: `packages` table with auto-detection of package managers. Per-package pattern/function counts. Per-package filtering on all queries.
- **Retention policies**: scan_history 100 entries, pattern_history 365 days, audit_snapshots 50 entries, health_trends 180 days, backups 5, cache_entries 24 hours. Enforced after each scan.
- **Lock file generation**: `drift.lock` in TOML format — deterministic snapshot of approved patterns. `drift lock validate` returns exit code 1 if out of sync. CI integration for enforcing lock file freshness.
- **ATTACH DATABASE for Cortex**: On-demand `ATTACH DATABASE cortex.db AS cortex` for cross-domain queries (e.g., pattern-linked memories). Keep drift.db and cortex.db separate for independent schema migration and backup.
- **Storage telemetry**: `StorageTelemetry` struct tracking query_count, write_count, cache_hits/misses, total_query_time, slowest_query. Exposed via NAPI as `drift_storage_stats`.
- **SARIF export from storage**: SARIF 2.1.0 exporter generating standards-compliant output from patterns/violations in drift.db.


### A9. Quality Gates — Missing Details (Cat 09)

From `.research/09-quality-gates/RECOMMENDATIONS.md` (19 recommendations, R1-R19):

- **New-code-first enforcement**: SonarQube "Clean as You Code" philosophy. Only new violations block — pre-existing violations are baselined. `isNew` field on every violation via baseline comparison. Modes: `full` (all violations), `pr` (only changed files), `new-only` (only new violations).
- **Progressive enforcement**: Three modes per pattern — Monitor (log only) → Comment (PR comment, non-blocking) → Block (fail CI). Automatic promotion rules: Monitor→Comment after 14 days with <5% FP rate, Comment→Block after 30 days with <2% FP rate. `enforcementMode` field on Pattern model.
- **Incremental gate execution with 3-tier caching**: File-level (skip unchanged files), pattern-level (skip unchanged patterns), gate-level (skip gates whose inputs haven't changed). Cache stored in SQLite `gate_cache` table.
- **Rich SARIF 2.1.0**: Full spec compliance including `baselineState` (new/unchanged/updated/absent), `codeFlows` (for taint/reachability paths), `fixes` (from QuickFix system), `suppressions` (for baselined violations), CWE taxonomies in `taxonomies` section.
- **Policy-as-code with YAML**: Inheritance via `extends: drift:default`. Versioning with `version` field. Policy packs (named collections: `drift:security-strict`, `drift:startup-fast`). Per-gate configuration with thresholds, enforcement mode, timeout.
- **Multi-stage enforcement**: Pre-commit (<5s, pattern compliance only), PR (<30s, all gates), Post-merge (<2min, full analysis + trend), Scheduled (<5min, deep analysis + regression). Each stage has different gate sets and time budgets.
- **JUnit XML and HTML reporters**: JUnit XML for universal CI compatibility (Jenkins, GitLab, Azure DevOps). HTML for human-readable reports with charts and trend data.
- **Gate dependency graph**: Topological execution order. Early termination — if a dependency gate fails and the dependent gate requires it, skip the dependent. Parallel execution of independent gates.
- **Hotspot-aware violation scoring**: Weight violations by file change frequency (from git log analysis). Formula: `violation_weight = base_severity × (1 + hotspot_multiplier × change_frequency)`. Configurable multiplier, disabled by default in `ci-fast` policy.
- **Violation author tracking**: Git blame integration to determine if the current author introduced the violation. `authorMatch` factor in prioritization score.
- **Violation prioritization algorithm**: `priorityScore = severity×0.30 + isNew×0.25 + patternConfidence×0.15 + hotspotScore×0.15 + fixDifficulty×0.10 + authorMatch×0.05`. Top N violations highlighted as "Fix These First."
- **Structured violation explanations**: `ViolationExplanation { why, expected, howToFix, impact, learnMore?, relatedPatterns? }` on every `GateViolation`. Maps to SARIF `fixes` and `helpUri`.
- **Dry-run / preview mode**: `drift gate run --dry-run` — executes gates but does NOT persist results or affect baselines. Cache IS populated. Exit code always 0 unless `--strict-dry-run`.
- **Webhook and notification system**: `PolicyActions.onPass/onFail/onWarn` with webhook support. Template variables: `{{branch}}`, `{{commitSha}}`, `{{score}}`, `{{status}}`, `{{summary}}`, `{{env.VAR_NAME}}`. Fire-and-forget with 5s timeout.
- **Reporter plugin architecture**: Public `Reporter` interface. Plugin discovery: built-in → `.drift/plugins/reporters/*.js` → npm `drift-reporter-*` packages. Usage: `drift gate run --format confluence`.
- **Custom rule expansion**: 3 new condition types — AST condition (tree-sitter query), Call graph condition (source/target path patterns), Metric condition (cyclomatic complexity threshold). All work within existing composite condition system (AND/OR/NOT).
- **Gate timeout and recovery**: Per-gate timeout (default 30s, configurable). Timeout returns `status: 'errored'`. Checkpoint/resume for interrupted runs via `gate_cache` table.
- **OWASP/CWE alignment**: Map all security violations to CWE IDs and OWASP Top 10 categories. Compliance reporter producing OWASP coverage summary (covered/partial/not covered per category).
- **Developer feedback loop for gates**: Track violation display/fix/dismiss events. Compute per-gate effective FP rate. Auto-disable gates with >20% FP rate.


### A10. CLI — Missing Details (Cat 10)

From `.research/10-cli/RECOMMENDATIONS.md`:

- **Structured exit codes**: 0=clean, 1=violations found, 2=tool error (crash/timeout), 3=invalid arguments/config. All commands must use these consistently.
- **Structured error taxonomy**: Machine-readable error codes — E1xx (project errors: not found, not initialized), E2xx (config errors: invalid, missing), E3xx (scan errors: timeout, parse failure), E4xx (storage errors: corrupt, locked), E5xx (git errors: not a repo, dirty state). Each error includes code, message, and suggestion.
- **Lazy-loading command architecture**: Commands loaded on-demand, not at startup. Reduces CLI startup time from ~500ms to ~100ms. Only the invoked command's dependencies are loaded.
- **Shell completion support**: Generate completions for bash, zsh, fish, PowerShell via `drift completions <shell>`. Includes subcommand, flag, and argument completion.
- **Configuration hierarchy**: CLI flags > env vars (`DRIFT_*` prefix) > project config (`.driftrc.json`/`.driftrc.yaml`/`drift.config.ts`) > user config (`~/.config/drift/`) > system defaults. `drift config show` to display resolved config.
- **SARIF as first-class output**: Available on ALL violation-producing commands (`drift check`, `drift scan`, `drift gate`, `drift report`), not just `drift gate`. Include `codeFlows`, `fixes`, CWE/OWASP tags. `drift upload-sarif` for GitHub Code Scanning integration.
- **Stable fingerprints**: Content-based (not line-number-based) fingerprints for diff-based reporting. Use semantic location (function/class name) when available. Stable across code reformatting.
- **Reporter architecture**: `ReportResult { formatted, data, metadata }` — structured data always available alongside formatted output. Custom formatters via npm packages or local files: `drift check --format ./my-formatter.js`.


### A11. Infrastructure — Missing Details (Cat 12)

From `.research/12-infrastructure/RECOMMENDATIONS.md` (25 recommendations):

- **Rust CI pipeline**: `cargo fmt --all -- --check` + `cargo clippy --all-targets --all-features -- -D warnings` + `cargo nextest run` as blocking gates. Remove `continue-on-error: true` from build/test steps.
- **Supply chain security**: `cargo-deny` config for license checking and vulnerability scanning. SBOM generation in SPDX and CycloneDX formats (via `cargo-sbom` + `@cyclonedx/bom`). SLSA Level 2-3 provenance attestation via Sigstore. Signed releases for npm packages and native binaries.
- **EU CRA compliance**: SBOM generation required by Dec 2027 for EU Cyber Resilience Act. Start generating now to establish the pipeline.
- **Cargo workspace expansion**: Target 5-6 crates with feature flags for optional subsystems. Workspace-level dependency management.
- **NAPI-RS v3 migration**: Enables WebAssembly support alongside native binaries. Broader platform reach.
- **Turborepo remote caching**: Shared build cache across CI runs and developers. Reduces CI time for unchanged packages.
- **sccache for Rust compilation**: Shared compilation cache. Reduces Rust build times by 50-80% on cache hits.
- **cargo-zigbuild for cross-compilation**: Build musl targets for Alpine Linux without complex cross-compilation toolchains. Targets: `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`.
- **cargo-nextest for testing**: 3x faster test execution than `cargo test`. Better output formatting. Per-test timeout support.
- **Performance regression detection**: Run `criterion` benchmarks in CI on every PR. Compare against main branch baseline with statistical significance (p < 0.05). Fail PR if any benchmark regresses >10%.
- **E2E integration test suite**: Full pipeline test: scan → detect → analyze → store → query via MCP. Use demo applications as test fixtures. Snapshot testing against known-good baselines.
- **Changesets for npm versioning**: Coordinated monorepo versioning across npm packages.
- **release-plz for Cargo publishing**: Automated Cargo.toml version bumps and crates.io publishing.
- **Coordinated cross-registry release**: npm + crates.io releases in a single pipeline. Version bump → build → test → SBOM → sign → publish.
- **Justfile task runner**: Replace complex npm scripts with Justfile for cross-platform task running.
- **Pre-commit hooks via husky**: `drift check --staged` as pre-commit hook. `drift gate run --dry-run` as pre-push hook.
- **Multi-architecture Docker builds**: `docker buildx` with `linux/amd64,linux/arm64`. Alpine-based image variant.


### A12. Advanced Systems — Missing Details (Cat 13)

From `.research/13-advanced/RECOMMENDATIONS.md` (16 recommendations, R1-R16):

**DNA System**:
- **Declarative gene definitions via TOML**: Genes defined as data files, not hardcoded extractors. Each gene TOML specifies: id, name, category, extraction patterns (regex + tree-sitter queries), allele classification rules, dominance thresholds.
- **Structural gene extraction via tree-sitter**: Ensemble scoring combining regex pattern matching + structural AST queries. Tree-sitter queries for precise extraction (e.g., "find all function declarations with async keyword").
- **Graduated dominance tiers**: Weak 30-59%, Moderate 60-79%, Strong 80-94%, Dominant 95%+. Replaces binary dominant/non-dominant classification.
- **Cross-gene consistency score**: Measures how well genes agree with each other. High consistency = coherent codebase. Low consistency = fragmented conventions.
- **Revised DNA health score formula**: `health = geneHealth×0.35 + consistency×0.25 + stability×0.20 + coverage×0.20`. Adds cross-gene consistency factor (missing from v1).

**Decision Mining**:
- **Knowledge graph-backed decision storage**: SQLite with adjacency lists for decision relationships. Temporal queries (decisions in time range). ADR lifecycle tracking (proposed → accepted → deprecated → superseded).
- **Enhanced NLP extraction**: Decision reversal detection via revert commits and rollback patterns. ADR document detection (scan `docs/adr/`, `docs/decisions/`, `architecture/decisions/` directories, parse markdown for decision metadata).
- **git2 integration**: Rust `git2` crate (libgit2 binding) for 5-10x faster commit walking. Parallel commit analysis via rayon (open Repository per thread). Performance: 10K commits in ~0.5-1s (vs 5-10s with simple-git).

**Simulation**:
- **Six-dimensional simulation scoring**: Add test coverage impact + complexity change to existing 4 dimensions (friction, impact, alignment, security). Rebalanced weights: friction 0.20, impact 0.20, alignment 0.25, security 0.15, test_coverage 0.10, complexity 0.10.
- **Architectural fitness function framework**: Declarative fitness functions in TOML. Check types: pattern-alignment, convention-compliance, security, test-coverage. Threshold-based pass/fail. Trend tracking over time (direction + velocity). Quality gate integration for merge blocking.
- **Learned strategy templates**: Learn simulation templates from the codebase's actual patterns (not hardcoded). Use DNA genes + detected patterns to build codebase-specific templates. Priority: learned > builtin > fallback.

**Language Intelligence**:
- **Generic AST (GAST) normalization layer**: Language-agnostic representation covering 6 construct types: Function, Class, Import, Decorator, ErrorHandling, TypeDefinition. Per-language `GastTranslator` trait. Extends normalization beyond decorators to function signatures, class hierarchies, module structures.
- **Declarative framework mappings in TOML**: Framework definitions as data files. Detection signals: imports, config files, build files. Decorator patterns with semantic classification. Plugin loading from `.drift/frameworks/`. Target: expand from 5 to 20+ frameworks.
- **Expanded language coverage**: Go (struct tags as decorators, Gin/Echo/Fiber/Chi frameworks), Rust (derive macros and attributes, Actix/Axum/Rocket frameworks), C++ (C++11 attributes, minimal support). New decision mining extractors per language.

**Cross-Subsystem**:
- **Event bus**: Lightweight pub/sub for cross-subsystem data flow. Events: DnaAnalysisComplete, MutationDetected, DecisionMined, SimulationComplete, FrameworkDetected, etc. Synchronous dispatch, no persistence, no replay.
- **Unified cross-language query API**: Single API composing results from all 4 subsystems. `UnifiedQuery { scope, include (semantics/conventions/decisions/simulation/metrics), filters }`. Returns `FileIntelligence` per file with data from all subsystems.
- **DORA-adjacent convention health metrics**: 4 metrics — Drift Velocity (dominant allele changes/month), Compliance Rate (files matching dominant alleles / total), Health Trend (slope of health score over time), Mutation Resolution Rate (median days to resolve detected mutations). Assessments: Stable/Evolving/Volatile, Improving/Stable/Degrading/Critical.
- **Incremental analysis with content-hash caching**: 3-layer cache — file-level skip (content hash), gene-level re-aggregation (only re-aggregate if files changed), simulation result caching (task hash + file hashes). Performance: 100x for no-change, 25x for 10 files changed, 10x for 100 files changed.


### A13. Gap Analysis — Missing Systems (Cat 16)

From `.research/16-gap-analysis/RECOMMENDATIONS.md` — systems that exist in v1 but are NOT covered elsewhere in the audit:

- **Licensing & Feature Gating (GA1)**: P0. LicenseManager with JWT + simple key validation. 3 tiers (Community/Team/Enterprise), 16 gated features, 6 guard patterns (`requireFeature`, `checkFeature`, `guardFeature`, `withFeatureGate`, `@RequiresFeature`, `guardMCPTool`). License sources: env var → file → config → community fallback. V2: JWT validation in Rust (`jsonwebtoken` crate), feature registry as Rust enum, license caching with 1hr TTL, offline validation with periodic online refresh.
- **Audit System (GA3)**: P0. Health scoring weights: avgConfidence×0.30 + approvalRatio×0.20 + complianceRate×0.20 + crossValidationRate×0.15 + duplicateFreeRate×0.15. Duplicate detection via Jaccard similarity (threshold 0.85, auto-merge >0.95). Cross-validation: orphan patterns, high outlier ratio, low confidence approved, constraint alignment. Degradation tracking: 90-day history, 7-day rolling averages. V2 additions: trend prediction, anomaly detection, per-category health breakdown.
- **Telemetry System (GA4)**: P1. Opt-in, anonymous, privacy-preserving. Rust telemetry client with event batching. Cloudflare Worker backend with D1 storage. V2 additions: differential privacy, GDPR-compliant deletion, gated feature attempt tracking.
- **MCP Feedback System (GA5)**: P1. Rating system: good (+0.1), bad (-0.15), irrelevant (-0.05). Directory propagation at 30%. Exclusion threshold: boost < -0.5 AND confidence > 0.5. V2: move to Rust, per-pattern feedback, team aggregation (enterprise), feedback-driven confidence adjustment.
- **MCP Pack Manager (GA6)**: P2. Custom pack creation, staleness detection, usage tracking, suggestion engine. Stays in TypeScript. V2 additions: pack versioning, sharing, marketplace.
- **Skills Library**: 73 skill templates. V2: catalog with categories, TOML-based schema, cross-reference to detectors, skill marketplace for enterprise.


### A14. Test Topology — Missing Details (Cat 17)

From `.research/17-test-topology/RECOMMENDATIONS.md` (12 recommendations):

- **Unified Rust extraction engine**: Single `TestExtractor` trait for all 9 languages. Extraction result includes: test cases, mock statements, setup blocks, fixtures, imports, file hash. New fields: `is_parameterized`, `parameter_count`, `mock_category` (External/Internal/Http/Database/FileSystem), `is_deep_mock` (mock returning mock), `FixtureScope` (Function/Class/Module/Session expanded beyond Python).
- **Framework coverage expansion**: V1 detects 35+ frameworks. V2 target additions: Playwright, Cypress, Testing Library (TS/JS); Hypothesis, Behave (Python); Cucumber, Spock, Arquillian (Java); SpecFlow, FluentAssertions (C#); Behat (PHP); GoConvey, rapid (Go); nextest runner (Rust); GoogleMock (C++); Kotest, MockK (Kotlin — new language); Quick/Nimble (Swift — new language).
- **Incremental analysis**: Content-hash-based invalidation with dependency-aware propagation. When source file changes, re-map all tests covering it. When test file changes, re-extract. Cache in SQLite `test_extraction_cache` table with MessagePack-serialized extraction results. Target: <500ms incremental for 10 changed files.
- **Test smell detection engine**: 19 canonical smells (from testsmells.org) + 5 flakiness-inducing smells. Detected during extraction (zero additional AST traversal). Key smells: AssertionRoulette, ConditionalTestLogic, EmptyTest, MagicNumberTest, MysteryGuest, SleepyTest, UnknownTest (no assertions), IndirectTesting, TestRunWar, FireAndForget. Each smell has severity, line, suggestion, auto_fixable flag.
- **Multi-dimensional quality scoring**: 7 dimensions — assertion_quality, error_coverage, edge_coverage, mock_health, smell_penalty, isolation, mutation_score (optional from external tools). Configurable weights. Grade system: A/B/C/D/F. Default weights shift when mutation data is available.
- **Test-to-source mapping**: Bidirectional maps (source→tests, test→sources). Mapping strategies: import analysis, naming convention, directory convention, call graph, explicit annotations. Used by simulation (R6 test coverage scorer) and quality gates.


### A15. Constraints — Missing Details (Cat 18)

From `.research/18-constraints/RECOMMENDATIONS.md`:

- **AST-based constraint verification in Rust**: Replace regex-based code element extraction with Rust parser AST. Predicate-to-verification mapping: Function/Class/EntryPoint/Naming → ParseResult, must_precede/must_follow → call graph path query, data_flow → taint analysis, must_wrap → AST containment, must_colocate/must_separate → file path comparison, cardinality → count query on AST. Accuracy improvement: ~70% (regex) → ~98% (AST).
- **Declarative constraint format (TOML)**: `drift-constraints.toml` at project root. Supports auto-discovered + user-defined constraints. Sections: `[settings]` (auto_approve_threshold, enforcement_default, baseline_file), `[[constraints]]` (id, name, category, type, language, enforcement, scope, predicate, rationale). Support `include` directives for splitting large files.
- **Baseline management (FreezingArchRule)**: Snapshot all current violations when constraint is first approved. Only report NEW violations on subsequent runs. Ratchet effect — fixed violations removed from baseline, can never regress. Content-hash-based matching for stability across line number changes. CLI: `drift constraints baseline create/update/diff`.
- **Developer feedback loop**: Dismiss actions with reason categories (false_positive, wont_fix, not_applicable, already_fixed). Per-constraint effective FP rate = dismissals / (dismissals + fixes) over 30-day window. Auto-demotion: >10% FP → demote error to warning, >25% FP → flag for review. Adjusted confidence: `base_confidence × (1 - false_positive_rate)`.
- **Constraint conflict resolution & inheritance**: Specificity-based precedence: scope_score (file-specific 100, directory 50, project-wide 10) + status_score (custom 30, approved 20, discovered 10) + confidence_score (confidence × 10). Pairwise conflict detection at load time. Inheritance: child constraints inherit parent, can override enforcement but cannot remove parent constraints. `drift constraints explain <id>` for resolution chain debugging.
- **Constraint storage migration to SQLite**: Full schema with `constraints`, `constraint_violations`, `constraint_baselines`, `constraint_feedback` tables. Indexes on status, language, category, confidence. Event log for audit trail.


### A16. Error Handling — Missing Details (Cat 19)

From `.research/19-error-handling/RECOMMENDATIONS.md` (12 recommendations):

- **Unified error handling analyzer in Rust**: Three-phase architecture — Phase 1: per-file AST analysis (parallel via rayon, extract boundaries/gaps/error types, compute per-function throws sets), Phase 2: cross-file topology (compose throws sets along call graph, build propagation chains, detect unhandled paths), Phase 3: quality assessment (multi-dimensional scoring, CWE mapping, risk scoring).
- **Interprocedural error propagation engine**: Compositional per-function error summaries (`FunctionErrorSummary { throws_set, catches_set, has_catch_all, rethrows, async_handling, content_hash }`). Propagation computed by composing summaries along call graph edges. Incremental: when function changes, only its summary and direct callers need re-analysis.
- **Expanded error type system**: `ErrorTypeRegistry` with full inheritance hierarchy, usage tracking (throw/catch locations), dead catch detection (caught but never thrown), uncaught type detection (thrown but never caught), cross-file resolution.
- **Multi-dimensional quality scoring**: 4 categories — Coverage (handling_coverage, boundary_coverage, async_coverage, framework_coverage), Depth (avg/max propagation depth, catch-to-throw ratio, type specificity), Quality (swallowed_error_rate, context_preservation_rate, stack_preservation_rate, recovery_rate), Security (information_disclosure_risk, fail_open_risk, cwe_violation_count). Composite: coverage×0.30 + depth×0.20 + quality×0.30 + security×0.20.
- **CWE/OWASP security-mapped gap detection**: Expanded from 7 to 24+ gap types. New security-focused: InformationDisclosure (CWE-209), FailOpenAuth (CWE-755), GenericCatch (CWE-396), GenericThrows (CWE-397), MissingErrorLogging (CWE-392), SensitiveDataInLog (CWE-532). New quality-focused: NestedTryCatch, RethrowWithoutContext, MixedErrorParadigms, DeadErrorHandling, CatchingProgrammingError. New language-specific: RustUnwrapInLibrary, RustExpectWithoutMessage, RustPanicInNonTest, GoIgnoredErrorReturn.
- **Framework boundary detection expansion**: From 5 to 20+ frameworks. Detect framework-specific error handling patterns (Express error middleware, FastAPI exception handlers, Spring @ExceptionHandler, Django middleware, NestJS exception filters, etc.).


### A17. Contracts — Missing Details (Cat 20)

From `.research/20-contracts/RECOMMENDATIONS.md`:

- **Unified contract model — multi-paradigm**: `ApiContract` supporting 6 paradigms: REST, GraphQL, gRPC, WebSocket, EventDriven (Kafka/RabbitMQ/SNS/SQS), tRPC. Unified `ApiOperation` with `OperationType` enum covering all paradigms (HttpGet/Post/Put/Patch/Delete, GraphQLQuery/Mutation/Subscription, GrpcUnary/ServerStream/ClientStream/BidiStream, EventPublish/EventSubscribe, WsMessage, TrpcQuery/Mutation/Subscription). Unified type system: `ApiType { name, kind (Object/Enum/Union/Array/Map/Scalar/Reference), fields }` with `FieldConstraint` (MinLength, MaxLength, Pattern, Format, etc.).
- **Schema-first contract detection**: Parsers for OpenAPI 3.0/3.1 (YAML/JSON), GraphQL SDL (via tree-sitter-graphql), Protobuf (via protox-parse, no protoc dependency), AsyncAPI 2.x/3.0. Spec file discovery in standard locations (api/, specs/, proto/, schemas/).
- **Code-first contract extraction expansion**: REST: add Go (Gin, Echo, Fiber, Chi), Rust (Actix, Axum, Rocket), Ruby (Rails, Sinatra), Kotlin (Ktor). Frontend: add SWR, react-query v5, Apollo REST Link, Ky, Got, Superagent. GraphQL code-first: type-graphql, nexus, pothos, Strawberry, Ariadne, Graphene, juniper, async-graphql, gqlgen, DGS Framework. gRPC: grpc-js, nice-grpc, grpcio, io.grpc, tonic. Event-driven: kafkajs, confluent-kafka, sarama, amqplib, pika, lapin, AWS SNS/SQS SDK. tRPC: router definitions, Zod input schemas, client-router matching.
- **Breaking change classifier**: Categorize changes as breaking/non-breaking/deprecation per paradigm. REST: removed endpoint, removed required field, type change. GraphQL: removed field, changed type, removed enum value. gRPC: changed field number, removed field, changed type. Severity levels for CI gate integration.
- **Contract source tracking**: `ContractSource` enum — CodeExtraction (file, line, framework, confidence), SpecFile (file, spec_type, version), ContractTest (file, framework, test_name), Both (spec + code). Enables spec-vs-code drift detection.


### A18. Security — Missing Details (Cat 21)

From `.research/21-security/RECOMMENDATIONS.md`:

- **Security-integrated pipeline (not separate phase)**: Security analysis woven into every pipeline stage — SCAN (secret detection), PARSE (crypto/deserialization extraction), DETECT (security patterns via visitor), ANALYZE (taint, reachability, access control), REPORT (CWE/OWASP/SARIF). No separate security phase — avoids duplicate AST traversal.
- **Unified SecurityFinding data model**: Every security finding carries: `finding_type`, `severity`, `confidence`, `cwe_ids[]`, `owasp_categories[]`, `location`, `code_flow?: FlowStep[]`, `description`, `remediation`, `evidence`, `framework?`, `related_locations[]`.
- **Taint analysis as first-class engine**: Rust intraprocedural taint engine with declarative registries (TOML). Source registry (user input, env vars, file reads, HTTP params — per-framework). Sink registry (SQL queries, exec(), file writes, HTTP responses — per-CWE). Sanitizer registry (encoding functions, validation functions). Propagator registry (string ops, collection ops). Interprocedural expansion via call graph summaries (P2).
- **Secret detection expansion**: From 21 to 150+ provider-specific patterns. True Shannon entropy calculation (replace character diversity check). Threshold: entropy > 4.5 for 20+ char strings in sensitive contexts. Contextual scoring (variable name, file path, surrounding code). New providers: Azure (5+ types), GCP (4+), DigitalOcean, Heroku, Linode, CircleCI, Travis, Jenkins, GitHub Actions, OpenAI, Anthropic, HuggingFace, Cohere. Connection string parsing (Postgres, MySQL, MongoDB, Redis). Base64-encoded secret detection. .env file parsing with cross-reference to code usage.
- **Cryptographic failure detection (NEW)**: Weak hash for passwords (MD5, SHA1), hardcoded encryption keys/IVs, deprecated algorithms (DES, 3DES, RC4), disabled TLS verification, ECB mode, insufficient key lengths (<2048 RSA, <256 AES), JWT alg=none, plaintext password storage. CWE-326/327/328/329/295/321/256 mapping. Per-language pattern library.
- **Broken access control detection (enhanced)**: Route-auth middleware cross-reference, IDOR via taint analysis, path traversal via taint, CORS wildcard misconfiguration, missing CSRF protection, horizontal privilege escalation, SSRF detection.
- **Security misconfiguration detection**: Missing security headers (CSP, HSTS, X-Frame-Options), debug mode in production, default credentials, insecure cookie settings, exposed error details, missing rate limiting on auth endpoints.
- **Insecure deserialization detection (NEW)**: Per-language dangerous deserialization functions. Taint integration (user input → deserialization). CWE-502 mapping.
- **Unsafe ORM API patterns**: Prisma ($queryRaw, $executeRaw), Django (.extra(), .raw(), RawSQL()), SQLAlchemy (text(), execute() with string), Eloquent (DB::raw(), whereRaw()), Spring Data (@Query nativeQuery + string concat), Hibernate (createSQLQuery() + string concat), GORM (db.Raw(), db.Exec()), Knex (.raw()), Sequelize (.query()), TypeORM (.query(), createQueryBuilder().where(string)).
- **SARIF security output**: Full SARIF 2.1 with codeFlows for taint results, CWE/OWASP in properties, fix suggestions, GitHub Code Scanning upload format, GitLab SAST report format.
- **Security MCP tools**: `drift_security_findings` (query by CWE/OWASP/severity), `drift_taint_paths`, `drift_secrets`, `drift_owasp_coverage`, enhanced `drift_security_summary`.
- **Success metrics**: OWASP Top 10 coverage from ~5/10 to 9/10. CWE Top 25 coverage from ~6.5/25 to 17/25. Secret patterns from 21 to 150+. FP rate target <10%. Security finding types from 3 to 6+.


### A19. Context Generation — Missing Details (Cat 22)

From `.research/22-context-generation/RECOMMENDATIONS.md`:

- **Unified context engine**: Merge the dual-path architecture (intent-aware `drift_context` + package-scoped `drift_package_context`) into a single engine. 8-step pipeline: resolve scope → gather candidates → retrieve Cortex memories → score by relevance → rank → budget allocation → format → session tracking.
- **Intent-weighted scoring**: Per-intent weight multipliers on context sections. Example: `security_review` intent boosts constraints and data_accessors, reduces key_files. `add_feature` intent boosts patterns and examples. `fix_bug` intent boosts call graph context and error handling.
- **Semantic relevance scoring**: 2-stage — fast candidate scoring (keyword + file proximity + pattern alignment) → semantic re-ranking with embeddings for top candidates. Embeddings from Cortex's existing embedding infrastructure.
- **Layered context depth**: Overview (~2K tokens: pattern summary, top constraints, entry point count, health score), Standard (~6K tokens: patterns with examples, constraints, entry points, key files, guidance, top 5 memories), Deep (~12K tokens: everything in standard + code examples, data accessor details, dependency patterns, full entry point list up to 50, extended memories top 15, file-level detail). Invariant: overview ⊂ standard ⊂ deep.
- **Accurate BPE token counting**: Replace `length × 0.25` approximation with actual BPE tokenization via `tiktoken-rs` (exact for OpenAI models) or `splintr` (111 MB/s batch throughput). Model-aware counting (OpenAI cl100k_base/o200k_base, Anthropic, Generic fallback). Cache token counts per `(content_hash, model_family)`.
- **Intelligent budget allocation**: Proportional allocation across sections (patterns 40%, constraints 15%, entry_points 10%, key_files 10%, guidance 10%, memories 5%, system_prompt 10%). Intent modifies allocation. Within-section trimming by relevance score. Surplus redistribution to highest-demand section.
- **Session-aware context deduplication**: Track delivered content per session via content hash. On subsequent requests, replace already-delivered items with compact references. 30-50% token reduction on requests 2+. Sessions expire after 30 minutes. In-memory only.
- **Cortex memory integration**: Memory retrieval step between "gather candidates" and "score". Query by scope + intent + memory types (semantic, tribal, decision). Limit by depth (overview=3, standard=5, deep=15). Min confidence 0.5.


### A20. Pattern Repository — Missing Details (Cat 23)

From `.research/23-pattern-repository/RECOMMENDATIONS.md` (18 recommendations):

- **Single Rust-owned SQLite for all pattern data**: Eliminates 6-backend fragmentation (JSON files, SQLite unified store, Data Lake shards, Rust SQLite, Cortex SQLite, hybrid bridge stores). Eliminates 3 sync paths. ~7,500 lines of storage code removed. TypeScript gets read-only access for presentation.
- **Connection pool architecture**: `PatternDb { writer: Mutex<Connection>, readers: Vec<Mutex<Connection>> }`. WAL mode pragmas. Prepared statement caching via `prepare_cached()`.
- **Rust pattern repository with NAPI bindings**: Single implementation replacing 3 TS implementations (~2,418 LOC). Full CRUD, lifecycle (approve/ignore/merge), batch operations (upsert_batch for scan pipeline), incremental operations (get_patterns_for_files, invalidate_file).
- **Write batching via MPSC channel**: Generalized ParallelWriter pattern. 500 patterns per transaction batch. Dedicated writer thread. Bounded channel for backpressure. 100x write throughput improvement.
- **Event log / audit trail**: `pattern_events` table with structured event types: Discovered, ConfidenceUpdated, StatusChanged, LocationsUpdated, Merged, SecurityMapped, Archived, Restored, FalsePositiveReported. Actor tracking (system/user/detector). Composite indexes for time-range and actor queries.
- **Bayesian confidence scoring**: Replace weighted average with Bayesian update model. Prior from category-level statistics. Likelihood from observation data (frequency, consistency, spread). Posterior updated incrementally on each scan. Temporal decay factor: `confidence × e^(-λt)` where λ is per-category decay rate.
- **Pattern deduplication**: Jaccard similarity on location sets. Threshold 0.85 for flagging, 0.95 for auto-merge. Merge strategy: keep higher-confidence pattern, combine locations, preserve both names as aliases.
- **OWASP/CWE mapping on security patterns**: `security_mapping` table linking pattern_id to CWE IDs and OWASP categories. Populated by security detectors. Queryable for compliance reporting.
- **Pattern suppression tracking**: `pattern_suppressions` table for inline `// drift-ignore` comments. Fields: file, line, pattern_id, reason, expires_at, created_by. Expiration support for temporary suppressions.


### A21. Services Layer — Missing Details (Cat 25)

From `.research/25-services-layer/RECOMMENDATIONS.md` (25 recommendations):

- **Two-phase pipeline architecture**: Phase 1 (per-file indexing, embarrassingly parallel via rayon) → Phase 2 (cross-file analysis, dependency-driven). Key invariant from rust-analyzer: "Editing a function body never invalidates cross-file derived data." Most edits trigger only Phase 1 re-indexing.
- **Unified service contract**: Single `IScanService` interface for all consumers (CLI, MCP, Quality Gates, IDE). Methods: `scan()`, `scanIncremental()`, `cancel()`, `query()`, `health()`. Consumers adapt via thin wrappers adding consumer-specific concerns (CLI: spinner/reporters, MCP: caching/rate-limiting, Gates: policy evaluation).
- **NAPI bridge API surface**: Primary: `native_scan()` and `native_scan_with_progress()` (single NAPI call owns entire computation). Write to SQLite from Rust (only summary crosses NAPI boundary). `AsyncTask` for all >10ms operations. `ThreadsafeFunction` with `NonBlocking` mode for progress callbacks.
- **Rust scan engine**: Rayon + MPSC pipeline. Custom rayon pool (`num_cpus - 1`). Bounded crossbeam channel (`4 × num_threads`) between workers and writer. Batched SQLite writes (500 results per transaction). Cancellation via shared `AtomicBool`. Progress via `AtomicU64` counter + ThreadsafeFunction every 100 files. Error tolerance: parse errors produce partial results, detector errors skip detector for that file.
- **Performance targets**: 10K files <3s, 100K files <15s, 500K files <60s, incremental 1-file-changed <100ms.
- **Content-hash cache for incremental skipping**: `file_cache` SQLite table with `(path, content_hash, last_indexed_at)`. `diff()` method returns added/modified/removed/unchanged files. Cache invalidation: file-level (content hash), pattern-level (only re-aggregate changed files), convention-level (<10% changed → skip, 10-30% → incremental, >30% → full).
- **Cancellation bridge**: TypeScript calls `cancel_scan(scan_id)` → sets `AtomicBool` in Rust → rayon workers check between files → partial results returned with `status: 'partial'`. Graceful: already-processed files persisted, in-progress file discarded.
- **TypeScript ScanService**: ~100-200 LOC replacing ~5,500 LOC. Thin wrapper over NAPI calls. Adds: timeout management, progress callbacks, consumer-specific adaptation.
- **Consumer adapters**: CLI adapter (spinner, reporters, persistence triggers), MCP adapter (caching, rate limiting, response envelope), Gate adapter (policy evaluation, threshold checking), IDE adapter (file-level incremental, diagnostics formatting).


### A22. Workspace — Missing Details (Cat 26)

From `.research/26-workspace/RECOMMENDATIONS.md`:

- **SQLite as single source of truth**: All workspace state in `drift.db` — config, backup registry, migration history, context cache. Replaces scattered JSON files (config.json, source-of-truth.json, registry.json, context-cache.json).
- **Schema migration via `rusqlite_migration`**: `PRAGMA user_version` tracking. Forward-only migrations. Auto-backup before migration via SQLite Backup API.
- **Hot backup via SQLite Backup API**: `rusqlite::backup::Backup` with chunked transfer (1000 pages, 10ms sleep). Integrity verification post-backup. Tiered retention: max_operational=5, max_daily=7, max_weekly=4, max_total_size_mb=500.
- **Workspace locking**: `fd-lock` crate for cross-platform advisory locks. Shared read locks (MCP queries, CLI reads, backup) — concurrent OK. Exclusive write locks (scan, migrate, reset) — fail with "another operation in progress". RAII-based release (auto-released on process exit, even crash).
- **Event-driven context refresh**: Replace 2-tier cache (in-memory + JSON, 5-min TTL) with SQLite `workspace_context` table refreshed as final scan step. Zero staleness. For MCP long-running process: in-memory cache invalidated by SQLite `update_hook` callback.
- **Monorepo workspace support**: Auto-detect packages via ecosystem-specific markers (package.json workspaces, Cargo.toml workspace members, pyproject.toml, go.work, pom.xml modules, .csproj in solution). Per-package analysis with workspace-level defaults. Package dependency graph.
- **TOML configuration with layering**: `drift.toml` at project root. Sections: `[scan]`, `[analysis]`, `[quality-gates]`, `[mcp]`, `[backup]`, `[telemetry]`. Layering: CLI flags > env vars > project config > user config > defaults.


### A23. Event System — Specific Events

The audit mentions Rust trait-based events but doesn't enumerate the specific events and their producers/consumers from the v1 research:

| Event | Producer | Consumers |
|-------|----------|-----------|
| `pattern:added` | Detection pipeline | Pattern repository, Cortex, Audit |
| `pattern:approved` | CLI/MCP user action | Quality gates, Constraints, Cortex |
| `pattern:removed` | Retention/manual | Pattern repository, Constraints |
| `patterns:loaded` | Storage layer | Detection pipeline, MCP tools |
| `scan:complete` | Services layer | Materialized views, Context refresh, Telemetry |
| `memory:created` | Cortex | Causal graph, Embedding pipeline |
| `memory:accessed` | MCP tools | Decay engine, Access tracking |
| `constraint:violated` | Constraint verifier | Quality gates, Feedback system |
| `gate:evaluated` | Quality gate engine | Notification system, History |
| `file:changed` | File watcher / Scanner | Incremental cache, Test topology |

---

### A24. Documentation Corrections

From `.research/16-gap-analysis/RECOMMENDATIONS.md` (GD1):

- CLI command count: "~45" in some docs → actual is 65+
- MCP tool count: "90+" in some docs → actual is ~56 routed tools
- Confidence weights: Standardize on code values (0.40/0.30/0.15/0.15), remove incorrect documentation values that differ
- .drift/ directory: Ensure documentation includes `learned/`, `feedback/`, `packs/`, `license.key`, `backups/` subdirectories
- Package detector scope: Document all 11 package ecosystems (npm, yarn, pnpm, pip, poetry, cargo, go, maven, gradle, nuget, composer)

---

---


### A25. Category 24 — Data Lake Replacement Architecture (CRITICAL)

The audit body says "ELIMINATED" with a one-liner, but `.research/24-data-lake/RECOMMENDATIONS.md` contains **30 recommendations across 9 phases** (2,703 lines) defining HOW the SQLite replacement actually works. This is the architectural blueprint for the entire read/query layer. While A8 (Storage) covers some primitives (materialized tables, file_metadata, batch writer), Category 24 defines the complete data flow architecture, index strategy, materialization pipeline, and consumer migration. Without this, the audit says "eliminated" but doesn't explain what replaces it.

**Phase 0 — Architectural Decisions (AD1-AD3)**:

- **AD1 — Medallion Architecture (Bronze/Silver/Gold)**: Formally classify every table in `drift.db` into three layers:
  - **Bronze**: Raw scan ingestion. Ephemeral staging tables cleared at scan start. Write-optimized, minimal indexes. Tables: `scan_results` (temporary staging), `raw_pattern_matches` (append-only during detection). Bronze may be implicit in v2.0 — detectors can write directly to Silver if no staging needed.
  - **Silver**: Normalized analysis data. Schema-enforced (STRICT + CHECK), foreign keys, referential integrity. Standard B-tree indexes. Tables: `patterns`, `pattern_locations`, `pattern_examples`, `functions`, `call_edges`, `data_access`, `sensitive_fields`, `data_models`, `data_access_points`, `contracts`, `contract_frontends`, `constraints`, `env_variables`, `file_metadata`.
  - **Gold**: Pre-computed consumption layer. Refreshed explicitly after scans (not during). Covering indexes, partial indexes, materialized tables. Tables: `materialized_status`, `materialized_security`, `health_trends`, covering indexes on Silver tables, generated columns.
  - **Key rules**: Bronze→Silver during scan (detectors write to Silver via batch writer). Silver→Gold after scan completion (explicit refresh call). Gold is read-only from consumer perspective. Silver is source of truth — Gold can always be rebuilt from Silver.

- **AD2 — Explicit CQRS Pattern (Read/Write Separation)**: Three paths through `DatabaseManager`:
  - **Write path** (`drift scan`): Detectors/parsers → `writer()` → Silver tables → `refresh_read_model()` → Gold tables. Uses `BEGIN IMMEDIATE` transactions.
  - **Read path** (MCP/CLI): Consumer → `reader()` → Gold tables (materialized) + Silver tables (indexed). Read connections use `PRAGMA query_only = ON` to prevent accidental writes.
  - **Refresh path** (post-scan): `refresh_read_model()` → rebuilds `materialized_status`, `materialized_security`, updates `health_trends`. Acquires write connection because it INSERT/REPLACE into Gold tables.
  - WAL mode enables readers to continue during write transactions without blocking.

- **AD3 — Ownership-Based Invalidation Model**: Every derived fact (pattern, function, call edge, data access point) is linked to the source file that produced it via `file_metadata`. When a file changes, only its owned facts are invalidated and re-derived.
  - **Incremental scan flow**: (1) Walk filesystem → collect (path, mtime, size). (2) Compare against `file_metadata`: mtime unchanged → SKIP (~95% of files); mtime changed → compute xxhash64; content_hash unchanged → UPDATE mtime only; content_hash changed → MARK for re-scan; file not in table → NEW; file in table but not on disk → DELETED. (3) For DELETED files: DELETE owned facts from `pattern_locations`, `functions`, `call_edges`, `data_access`, `file_metadata`. (4) For re-scan files: DELETE owned facts, re-scan, INSERT new facts, UPDATE `file_metadata`. (5) Refresh Gold layer only if any files changed.
  - Counter caches on `file_metadata`: `pattern_count`, `function_count` — instant per-file stats without JOINs. Maintained by triggers on Silver tables (disabled during bulk scan, reconciled after).
  - Based on Meta's Glean ownership-based invalidation and Google's Kythe storage model.

**Phase 1 — Gold Layer Schema (GL1-GL3)**:

- **GL1 — Materialized Status Table**: Singleton (`CHECK (id = 1)`) with pre-computed: `health_score`, `health_trend` (improving/stable/declining), pattern counts (total/approved/discovered/ignored), `category_counts` (JSON), issue counts (critical/warning), `top_issues` (JSON), `security_risk_level`, `security_violations`, `sensitive_exposures`, last scan info (at/duration_ms/files/patterns/incremental/changed_files), `refreshed_at`. Refresh is a single `INSERT OR REPLACE` with subqueries against Silver tables. Health trend uses ±0.02 threshold to avoid noise. Query: `SELECT * FROM materialized_status WHERE id = 1` — guaranteed <1ms.

- **GL2 — Materialized Security Table**: Singleton with: `risk_level` (low/medium/high/critical), `overall_risk_score`, counts (tables/access_points/sensitive_fields/violations), breakdowns as JSON (`sensitivity_breakdown`, `violation_breakdown`, `top_risk_tables`, `top_violations`), `unprotected_access_points`, `raw_sql_access_points`. Risk level derived from max table risk score (≥0.8=critical, ≥0.6=high, ≥0.3=medium, else low). Refresh order matters: security before status (status reads `security_risk_level` from security).

- **GL3 — File Metadata Table**: Defined in AD3. Additional indexes: `idx_file_metadata_language` (for `drift stats --by-language`), `idx_file_metadata_errors` (partial, WHERE error IS NOT NULL, for `drift doctor`), `idx_file_metadata_scanned` (for recently scanned files). Counter cache triggers: `trg_file_pattern_count_insert/delete` on `pattern_locations`, `trg_file_function_count_insert/delete` on `functions`.

**Phase 2 — Index Strategy (IX1-IX4)**:

- **IX1 — Covering Indexes for Pattern Listing**: Replaces v1's PatternIndexView. Index on `patterns(category, status, confidence_score DESC, id, name, subcategory, severity, location_count, outlier_count)`. Column order matters: filter columns first, sort column next, output columns last. Query planner uses as covering index — never touches patterns table. Visible in EXPLAIN QUERY PLAN as `USING COVERING INDEX`. ~50-100 bytes per pattern overhead.

- **IX2 — Partial Indexes for Skewed Distributions**: 3-10x smaller and faster indexes for frequently queried subsets:
  - `idx_approved_patterns ON patterns(category, confidence_score DESC) WHERE status = 'approved'` — typically 10-30% of patterns
  - `idx_entry_points ON functions(file, name, return_type) WHERE is_entry_point = 1` — typically <5% of functions
  - `idx_high_confidence ON patterns(category, status) WHERE confidence_score >= 0.85`
  - `idx_sensitive_pii ON sensitive_fields(table_name, field_name) WHERE sensitivity = 'PII'`
  - `idx_sensitive_credentials ON sensitive_fields(...) WHERE sensitivity = 'credentials'`
  - `idx_active_patterns ON patterns(category, name) WHERE status != 'ignored'`
  - `idx_files_with_errors ON file_metadata(path) WHERE error IS NOT NULL`
  - `idx_patterns_with_outliers ON patterns(category, id) WHERE outlier_count > 0`
  - Query must include matching WHERE clause to use partial index.

- **IX3 — Expression Indexes on JSON Columns + Tag Normalization**: For multi-tag filtering, normalize into junction table `pattern_tags(pattern_id, tag)` with index `idx_pattern_tags_tag ON pattern_tags(tag, pattern_id)`. Dual storage: JSON column for full retrieval, junction table for indexed queries. Both updated in same transaction. Reconciliation check in `drift doctor`. Expression index on `contracts(json_extract(mismatches, '$[0].type'))` for mismatch type filtering.

- **IX4 — Dimension-Replacement Indexes**: Replaces v1's four JSON index files (FileIndex, CategoryIndex, TableIndex, EntryPointIndex) with SQL indexes:
  - `idx_pattern_locations_file ON pattern_locations(file, pattern_id)` — replaces FileIndex
  - `idx_patterns_category ON patterns(category, id)` — replaces CategoryIndex
  - `idx_data_access_table ON data_access_points(table_name, id)` + `idx_data_access_function ON data_access_points(function_id)` — replaces TableIndex
  - `idx_functions_entry ON functions(is_entry_point, id) WHERE is_entry_point = 1` + `idx_call_edges_caller/callee` — replaces EntryPointIndex (via recursive CTE for reachability)
  - Eliminates ~440 lines of IndexStore code and entire index rebuild step.

**Phase 3 — Materialization Pipeline (MP1-MP3)**:

- **MP1 — Explicit Post-Scan Refresh Pipeline**: Replaces v1's ViewMaterializer (590 lines). `RefreshPipeline` runs after scan completion. Steps in order: (1) `refresh_materialized_security`, (2) `refresh_materialized_status`, (3) `append_health_trend`, (4) `reconcile_counter_caches`. Entire refresh in single `BEGIN IMMEDIATE` transaction. Errors in individual steps logged but don't abort pipeline — partial refresh better than none. Returns `RefreshReport` with per-step timing and rows affected. Also supports `refresh_selective(changed_domains)` for incremental scans.

- **MP2 — Delta-Aware Refresh for Incremental Scans**: Tracks which Silver-layer rows changed via `ScanDelta` (in-memory set of changed domains, not per-row). If only patterns changed, skip security refresh. If only security data changed, skip pattern count refresh. Always refresh `materialized_status` (aggregates everything). Always update last scan info. Falls back to full refresh (MP1) if delta tracking fails. Based on Salsa's minimal recomputation principle.

- **MP3 — Health Trend Tracking**: `health_trends` table — append-only Gold layer. Columns: `recorded_at`, `scan_id`, `health_score`, pattern counts, security metrics, call graph metrics (total_functions, total_call_edges, entry_points), contract metrics (verified, mismatched), computed `trend` (improving/stable/declining with ±0.02 threshold). Indexes: `idx_health_trends_time(recorded_at DESC)`, `idx_health_trends_scan(scan_id)`. Subject to retention policies (OP1).

**Phase 4 — Generated Columns (GC1-GC2)**:

- **GC1 — Virtual Generated Columns for Confidence Classification**: Centralize derived field computation in schema:
  - `confidence_level`: high (≥0.85), medium (≥0.70), low (≥0.50), uncertain (<0.50)
  - `age_days`: `CAST(julianday('now') - julianday(first_seen) AS INTEGER)` — don't index (non-deterministic)
  - `is_actionable`: 1 if status='approved' AND confidence_score≥0.70, else 0
  - `severity_rank`: critical=0, warning=1, info=2, else 3
  - Indexes on generated columns: `idx_patterns_confidence_level`, `idx_patterns_actionable` (partial, WHERE is_actionable=1), `idx_patterns_severity`

- **GC2 — Risk Score View**: SQL view `v_table_risk_scores` computing per-table risk using v1's exact formula: `baseSensitivity × (0.5 + accessFactor×0.3 + rawSqlPenalty + violationPenalty)`. Sensitivity weights: credentials=1.0, PII=0.9, health=0.9, financial=0.85, else=0.5. Access factor: `MIN(access_count/10, 1.0)`. Raw SQL penalty: 0.2 if any raw SQL. Violation penalty: `MIN(violation_count×0.1, 0.3)`. Used by GL2 refresh to populate `top_risk_tables`.

**Phase 5 — Cache Warming (CW1)**:

- **CW1 — Startup Cache Warming**: On MCP server startup (before accepting first request), execute lightweight warming queries: (1) `materialized_status WHERE id=1`, (2) `materialized_security WHERE id=1`, (3) patterns covering index touch (LIMIT 1 with ORDER BY matching IX1), (4) functions entry point index touch, (5) recent health trends (LIMIT 5). Total <10ms. Also warm after database restore. CLI warming optional (only for `drift status`/`drift patterns`).

**Phase 6 — Incremental Invalidation (II1-II2)**:

- **II1 — File-Based Dependency Tracking**: `DependencyTracker` maps files to affected domains. Created at scan start, populated as scanner processes files. After scan, `compute_affected_domains()` checks which Silver tables have rows from changed files. Domain-level tracking (Patterns, CallGraph, Security, Contracts, DNA) — not per-table. Feeds into `refresh_selective()` (MP1). If no domains affected, skip refresh entirely.

- **II2 — Reconciliation Checks for Data Integrity**: 8 checks exposed via `drift doctor`: (1) `location_count` counter cache vs actual COUNT, (2) `outlier_count` counter cache, (3) `file_metadata.pattern_count` counter cache, (4) `materialized_status` fields vs computed values, (5) orphaned `pattern_locations` without patterns, (6) foreign key integrity (`PRAGMA foreign_key_check`), (7) file metadata staleness (files on disk not in table), (8) `pattern_tags` junction table vs `patterns.tags` JSON. `drift doctor --fix` auto-fixes inconsistencies. Also runs after database restore and schema migrations.

**Phase 7 — Operational Safety (OP1-OP3)**:

- **OP1 — Retention Policies**: Configurable per append-only table. Defaults: `health_trends` 180 days/500 entries, `scan_history` 365 days/1000 entries, `pattern_history` 90 days, `query_telemetry` 30 days/10K entries. Enforced after refresh pipeline and via `drift maintenance`. Age-based + count-based pruning. `PRAGMA incremental_vacuum` after pruning.

- **OP2 — Query Telemetry Persistence**: `query_telemetry` table with sampling (10% default, always record slow queries >10ms). Columns: `query_type`, `source` (mcp/cli/quality_gate), `execution_time_us`, `rows_returned`, `filters` (JSON), `used_index`, `was_cache_hit`, `was_slow`. Indexes: `idx_telemetry_time`, `idx_telemetry_slow` (partial). Analyzed by `drift doctor --performance`.

- **OP3 — Data Integrity Validation on Startup**: Three levels: Quick (<1ms, schema version + materialized table existence), Normal (<100ms, Quick + `PRAGMA foreign_key_check`), Full (seconds, Normal + `PRAGMA integrity_check` + reconciliation). Quick runs on every database open. Normal after migrations. Full on `drift doctor` and after crash recovery.

**Phase 8 — Consumer Migration (CM1-CM3)**:

- **CM1 — MCP Tool Query Layer**: Every MCP tool maps to specific SQL queries:
  - `drift_status` → `SELECT * FROM materialized_status WHERE id = 1`
  - `drift_patterns_list` → covering index IX1 query with category/status filters
  - `drift_file_patterns` → JOIN via `idx_pattern_locations_file` (IX4)
  - `drift_security_summary` → `SELECT * FROM materialized_security WHERE id = 1`
  - `drift_code_examples` → `SELECT * FROM pattern_examples WHERE pattern_id = ? ORDER BY quality_score DESC`
  - `drift_pattern_detail` → patterns + pattern_locations by id
  - `drift_impact_analysis` → recursive CTE on `call_edges`
  - `drift_health_trends` → `SELECT * FROM health_trends ORDER BY recorded_at DESC LIMIT ?`
  - All queries via `reader()` connections with `PRAGMA query_only = ON`. Use `prepare_cached()`. Keyset pagination (not OFFSET).

- **CM2 — CLI Command Query Updates**: CLI shares same NAPI query bindings as MCP. `drift status` → `get_status()`, `drift patterns` → `query_patterns(opts)`, `drift security` → `get_security_summary()`, `drift doctor` → `validate_database(Full)` + `run_reconciliation()`, `drift maintenance` → `enforce_retention_policies()`. All support `--json` flag.

- **CM3 — Quality Gate Integration**: Quality gates read from `materialized_status` directly. `get_quality_gate_input()` returns health_score, approved_ratio, security_risk_level, security_violations. Pattern compliance checked against baseline. Gates fail gracefully if materialized tables empty (first run). Check `refreshed_at` timestamp to warn if data stale.

**Phase 9 — Advanced Optimizations (AO1-AO3)**:

- **AO1 — SQLite Performance Pragmas**: Already covered in A8 (Storage). Critical for data lake: `cache_size=64MB` keeps Gold-layer pages in memory, `mmap_size=256MB` for covering index scans, WAL for concurrent read/write, `PRAGMA optimize` on close updates query planner statistics.

- **AO2 — EXPLAIN QUERY PLAN Validation Suite**: Test suite asserting critical queries use intended indexes. Tests: patterns list uses covering index IX1, file patterns uses IX4, approved patterns uses partial index IX2, status query uses PRIMARY KEY SEARCH (not SCAN). Run in CI to catch query plan regressions. Needs representative test data (not empty tables).

- **AO3 — VACUUM and Checkpoint Strategy**: Auto-checkpoint every 1000 WAL pages (SQLite default). Explicit `PRAGMA wal_checkpoint(TRUNCATE)` after scan completion. `PRAGMA incremental_vacuum(1000)` after retention pruning. Full `VACUUM` only on explicit `drift maintenance --vacuum`. Enable `PRAGMA auto_vacuum = INCREMENTAL` in initial schema.

**V1 Elimination Summary**: ~4,870 lines of v1 Data Lake TypeScript (QueryEngine ~400, ViewStore ~430, IndexStore ~440, PatternShardStore ~430, CallGraphShardStore ~650, SecurityShardStore ~660, ExamplesStore ~550, ViewMaterializer ~590, ManifestStore ~420, Types ~300) replaced by ~800 lines Rust (refresh pipeline + queries + reconciliation).

---

### A26. Category 01 — Rust Core Supplemental Details

The audit body's Category 01 section is thorough (scanner, parsers, unified analysis, call graph, reachability, taint, impact, boundary, coupling, constants, wrappers, NAPI). The following items from `.research/01-rust-core/RECOMMENDATIONS.md` (18 recommendations, FA1-FA3 + R1-R18) are either missing or under-specified in the audit body:

- **FA2 — Structured Error Handling**: `thiserror` for ALL error types from the first line of code. One error enum per subsystem: `ScanError`, `ParseError`, `CallGraphError`, `AnalysisError`, `CouplingError`, `BoundaryError`, etc. Each variant has structured fields (not just strings). `#[from]` for automatic conversion from std errors. This is a foundational decision — impossible to retrofit cleanly.

- **FA1 — Incremental-First Architecture**: The audit mentions incremental scanning but doesn't fully describe the two-phase model: (1) Per-file indexing phase — embarrassingly parallel, no cross-file dependencies, each file's index entry content-hashed and cached. (2) Cross-file analysis phase — call graph, coupling, reachability computed from file index as "derived queries" that auto-invalidate when input index entries change. Key principle: separate "dumb indexes" (per-file, incrementally updated) from "smart caches" (cross-file, rebuilt from indexes). Based on rust-analyzer's architecture and Salsa incremental framework.

- **R3 — String Interning Details**: The audit mentions `lasso` crate but not the phase separation: `Rodeo` during build/scan (mutable, single-threaded per task), `RodeoReader` for query/read (immutable, contention-free), `ThreadedRodeo` if concurrent interning needed during parallel scanning.

- **R16 — Rayon Thread Pool Configuration**: Custom `ThreadPoolBuilder` with configured thread count, stack size, and panic handling. Parser pool pattern: bounded crossbeam channel as parser pool (checkout/return) instead of `thread_local!` (which leaks memory for pool lifetime). `Arc<RwLock<ResolutionIndex>>` for shared cross-file state during parallel analysis. Batch processing with `par_iter()` + `flat_map_iter()` to avoid unnecessary intermediate allocations.

- **R17 — Performance Data Structures**: Use from the start (not retrofit): `FxHashMap` (rustc-hash) for all internal hash maps, `SmallVec<[T; 4]>` for usually-small collections, `BTreeMap` for ordered lookups (resolution index), `lasso` for interning, `xxhash` (xxh3) for content hashing. Release profile: `lto = true`, `codegen-units = 1`, `opt-level = 3`.

- **R18 — 15-Category Pattern Coverage**: All 15 categories must have AST queries AND string patterns from day one. v1 had gaps in Components, Documentation, Logging, Performance, Structural, Styling, Testing, Types. Specifically: Logging patterns were compiled in v1 but never wired up. The Violation system type was defined but never populated. v2 builds both from the start.

- **R4 — Declarative Pattern Definitions**: Patterns loaded from TOML files at startup (not just hardcoded). Ship with hardcoded defaults (all v1 patterns). Users can add custom patterns without recompiling. Format: `[[patterns]]` with id, language, category, confidence, tree-sitter query. `[[string_patterns]]` with id, category, confidence, regex.

- **R5 — Secret Detection Scale**: v2 ships with 100+ patterns (v1 had 21). Organized by provider: Cloud (AWS 5, GCP 4, Azure 4, DigitalOcean 2, Heroku 2), Code platforms (GitHub 3, GitLab 2, Bitbucket 2, npm 2, PyPI 2), Payment (Stripe 3, Square 2, PayPal 2), Communication (Slack 3, Twilio 2, SendGrid 2), Database (connection strings 4, passwords 3), Auth (JWT 2, OAuth 2, bearer 2), Crypto (RSA/SSH/PGP 3), Generic. Shannon entropy threshold: H > 4.5 for strings assigned to sensitive variables. Contextual confidence scoring: +0.05 high char diversity, +0.05 length>30, +0.10 sensitive var name, -0.20 test file, -0.30 comment, +0.10 .env file, -1.00 placeholder detected.

- **R15 — NAPI Bridge Design**: Consider JSON-over-stdio as secondary interface for MCP server flexibility (not just NAPI). This enables the Rust core to serve as a standalone analysis server, not just a Node.js addon.

- **Build Order**: Phase 0 (FA1+FA2+FA3 decisions) → Phase 1 (R1 Scanner → R2 Parsers → R3 Interning) → Phase 2 (R4 Unified Analyzer → R5 Secrets) → Phase 3 (R6-R14 all analyzers) → Phase 4 (R15 NAPI) → Phase 5 (R16-R18 performance, applied during Phases 1-4).

---

*End of Appendix A (A1-A26). This cross-reference now covers ALL category research documents (00-05, 07-10, 12-13, 16-26) against the audit. Category 06 (Cortex) excluded — already built as 19-crate Rust workspace. Every gap identified represents context that would be lost without this appendix.*

*End of audit. Every v2 system from categories 00-26 (excluding 06-cortex) is accounted for above.*
*All v2-research recommendations are incorporated.*
*Appendix A cross-references all v1 research documents to ensure no feature degradation.*
*This is a ground-up build plan. v1 is erased.*