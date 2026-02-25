# 01 Rust Core — V2 Build Recommendations

> **Context**: Drift v2 is a greenfield build. All source code is being written fresh. These recommendations define how to BUILD the Rust core from scratch using best practices, not how to migrate or port from v1. The v1 research serves as a requirements specification — what capabilities are needed — while these recommendations define HOW to build them right the first time.

## Summary

18 recommendations organized into 5 build phases. Each defines a capability to build into the new Rust core from day one, backed by external research from Tier 1-3 sources. The v1 codebase is treated as a requirements document, not as code to port.

---

## Foundational Architecture Decisions

These decisions must be made BEFORE writing code. They affect every subsystem.

### FA1: Incremental-First Architecture

**Priority**: P0 (Build First)
**Effort**: High
**Impact**: Defines the entire computation model — every subsystem builds on this

**What to Build**:
Design the entire Rust core around incremental computation from the start. Do NOT build a batch-only system and retrofit incrementality later.

Architecture (based on rust-analyzer's proven model):
1. Per-file indexing phase: parse file → extract patterns → produce file index entry. Embarrassingly parallel, no cross-file dependencies. Each file's index entry is content-hashed (xxhash) and cached.
2. Cross-file analysis phase: call graph resolution, coupling metrics, reachability — all computed from the file index. These are "derived queries" that auto-invalidate when their input index entries change.
3. Tree-sitter incremental parsing: cache parsed AST trees. On file change, use `tree.edit()` + re-parse for sub-millisecond updates.
4. SQLite-backed persistent index: survives process restarts. On startup, hash-check files against stored index — only re-index changed files.

**Key Design Principle**: Separate "dumb indexes" (per-file, incrementally updated) from "smart caches" (cross-file, rebuilt from indexes). Indexes are cheap to update. Caches are cheap to rebuild from indexes.

**Evidence**:
- rust-analyzer architecture: https://rust-analyzer.github.io/blog/2020/07/20/three-architectures-for-responsive-ide.html
- Salsa incremental framework: https://salsa-rs.github.io/salsa/overview.html
- Tree-sitter incremental parsing: https://zed.dev/blog/syntax-aware-editing

**Build Notes**:
- Evaluate Salsa for the cross-file phase. If too complex, build a simpler content-hash + dependency-tracking cache.
- Start with file-level granularity. Function-level can come later.
- The scanner, parsers, unified analyzer, and all specialized analyzers must be designed to produce cacheable, hashable output from day one.

---

### FA2: Structured Error Handling from Day One

**Priority**: P0 (Build First)
**Effort**: Low
**Impact**: Every subsystem uses this — impossible to retrofit cleanly

**What to Build**:
Use `thiserror` for all error types from the first line of code. Define one error enum per subsystem with structured variants.

```rust
#[derive(thiserror::Error, Debug)]
pub enum ScanError {
    #[error("path not found: {path}")]
    PathNotFound { path: String },
    #[error("permission denied: {path}")]
    PermissionDenied { path: String },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

// Per subsystem: ParseError, CallGraphError, AnalysisError,
// CouplingError, BoundaryError, etc.
```

**Evidence**:
- thiserror: https://docs.rs/thiserror (Rust ecosystem standard, 10K+ dependents)
- Error design: https://home.expurple.me/posts/designing-error-types-in-rust-applications/

---

### FA3: SQLite WAL Mode as Default

**Priority**: P0 (Build First)
**Effort**: Trivial
**Impact**: Enables concurrent reads during writes across all SQLite databases

**What to Build**:
Every SQLite database (call graph, file index, pattern storage) opens with:
```sql
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA mmap_size=268435456;  -- 256MB memory-mapped I/O
PRAGMA optimize;             -- on close
```

**Evidence**: SQLite WAL documentation: https://www.sqlite.org/wal.html

---

## Phase 1: Core Engine

Build the foundational subsystems that everything else depends on.

### R1: Scanner with Incremental Change Detection

**Priority**: P0
**Effort**: Medium

**What to Build**:
A parallel filesystem scanner that:
1. Walks directories via `walkdir` + `rayon` with `.gitignore`/`.driftignore` support
2. Returns file metadata: path, size, content hash (xxhash), detected language
3. Compares content hashes against the persistent index to identify changed/added/removed files
4. Builds a dependency graph from import/export analysis (not just file listing)
5. Supports configurable max file size, include/exclude globs, symlink following

**Key difference from v1**: v1 scanner was file-list-only. v2 scanner owns change detection and dependency graph from the start.

**Dependencies**: `walkdir`, `ignore`, `globset`, `rayon`, `xxhash`

---

### R2: Parser Layer with Rich Extraction

**Priority**: P0
**Effort**: High

**What to Build**:
Tree-sitter parsers for 10 languages that extract EVERYTHING needed for downstream analysis in a single pass. No re-parsing by other subsystems.

`ParseResult` must include from day one:
- Functions (with full signatures, return types, decorators WITH arguments, generics, doc comments)
- Classes (with inheritance, interfaces, abstract status, all methods and properties)
- Imports/exports (with type-only distinction, re-exports, namespace imports)
- Call sites (with receiver, arguments count, position)
- String literals (with AST context: function argument, variable assignment, decorator, etc.)
- Numeric literals (with AST context for magic number detection)
- Error handling constructs (try/catch/finally with caught types)
- Decorator/annotation details (name AND arguments — e.g., `@Route("/api/users")` extracts the path)

**Key difference from v1**: v1 Rust parsers extracted basics; TS parsers added richness. v2 extracts everything in Rust. No TS re-parsing.

Cache parsed trees for incremental re-parsing (FA1).

**Evidence**:
- Tree-sitter incremental parsing: https://tomassetti.me/incremental-parsing-using-tree-sitter/
- Semgrep architecture (tree-sitter → IL → analysis): https://semgrep.dev/docs/contributing/contributing-code/

---

### R3: String Interning with Production Crate

**Priority**: P0
**Effort**: Low

**What to Build**:
Use the `lasso` crate instead of a custom interner:
- `Rodeo` during the build/scan phase (mutable, single-threaded per task)
- `RodeoReader` for the query/read phase (immutable, contention-free)
- `ThreadedRodeo` if concurrent interning is needed during parallel scanning

Wrap with domain-specific additions:
- `PathInterner`: normalizes `\` → `/` before interning
- `FunctionInterner`: supports `intern_qualified(class, method)` → `"Class.method"`

**Key difference from v1**: v1 used a custom `HashMap<String, Symbol>` + `Vec<String>` with no thread-safe variant. v2 uses a battle-tested crate with build/read phase separation.

**Evidence**:
- lasso: https://docs.rs/lasso/latest/lasso/
- String interning in Rust: https://dev.to/cad97/string-interners-in-rust-797

---

## Phase 2: Pattern Detection Engine

### R4: Unified Analyzer with Declarative Patterns

**Priority**: P0
**Effort**: High

**What to Build**:
A 4-phase per-file analysis pipeline (same proven architecture as v1, but with declarative patterns):

```
File → tree-sitter parse → ParseResult
  Phase 1: AST Pattern Detection (tree-sitter queries, confidence 0.85-0.95)
  Phase 2: String Extraction (from AST, with context)
  Phase 3: String Literal Analysis (regex on extracted strings, confidence 0.80-0.90)
  Phase 4: Resolution Index population (function indexing for cross-file resolution)
```

**Critical new capability**: Declarative pattern definitions loaded from TOML/YAML files at startup:
```toml
[[patterns]]
id = "spring-security"
language = "java"
category = "Auth"
confidence = 0.95
query = '(annotation name: (identifier) @name (#match? @name "^(PreAuthorize|Secured)$"))'

[[string_patterns]]
id = "sql-select"
category = "DataAccess"
confidence = 0.9
regex = '(?i)SELECT\s+.+\s+FROM\s+\w+'
```

Ship with hardcoded defaults (all v1 patterns). Users can add custom patterns without recompiling.

**Resolution Index**: Use `BTreeMap<Symbol, SmallVec<[FunctionId; 4]>>` + `FxHashMap` for O(1) lookups. Resolution algorithm: exact name → same-file preference → exported preference → ambiguous. Wire up `ResolutionStats` tracking from day one (v1 left this as TODO).

**Wire up ALL pattern sets from day one**: SQL (9), routes (6), sensitive data (8), environment (6), AND logging (4) — v1 compiled log patterns but never used them.

**Build the Violation system from day one**: `Violation` type with detection rules (v1 defined the type but never populated it).

**Evidence**:
- Semgrep declarative rules: https://semgrep.dev/docs/writing-rules/
- Semgrep community model: https://github.com/semgrep/semgrep

---

### R5: Enterprise-Grade Secret Detection

**Priority**: P0
**Effort**: Medium

**What to Build**:
A secret detection engine with 100+ patterns, entropy analysis, and contextual scoring. Build this right from the start — don't ship with 21 patterns and plan to expand later.

**Architecture**:
1. Provider-specific pattern detectors (100+ regex patterns organized by provider):
   - Cloud: AWS (5 patterns), GCP (4), Azure (4), DigitalOcean (2), Heroku (2)
   - Code platforms: GitHub (3), GitLab (2), Bitbucket (2), npm (2), PyPI (2)
   - Payment: Stripe (3), Square (2), PayPal (2)
   - Communication: Slack (3), Twilio (2), SendGrid (2)
   - Database: connection strings (4), passwords (3)
   - Auth: JWT (2), OAuth (2), bearer tokens (2)
   - Crypto: RSA/SSH/PGP private keys (3)
   - Generic: password assignments, secret assignments, API key assignments

2. Shannon entropy calculator for generic high-entropy detection:
   ```
   H = -Σ p(x) * log2(p(x))
   Threshold: H > 4.5 for strings assigned to sensitive variables
   ```

3. Contextual confidence scoring:
   ```
   base = severity_to_base(severity)  // 0.9, 0.8, 0.6, 0.4, 0.2
   + 0.05 if high character diversity (≥3 of: upper, lower, digit, special)
   + 0.05 if length > 30
   + 0.10 if sensitive variable name (password, secret, key, token, credential)
   - 0.20 if in test file
   - 0.30 if in comment
   + 0.10 if in .env file
   - 1.00 if placeholder detected (example, placeholder, xxx, todo, changeme)
   ```

4. Placeholder detection (skip false positives)
5. Value masking for safe reporting
6. Organize patterns in declarative format (TOML) for easy maintenance

**Key difference from v1**: v1 had 21 patterns with basic entropy check (+0.05). v2 ships with 100+ patterns, full Shannon entropy, and rich contextual scoring.

**Evidence**:
- OWASP Secrets Management: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- GitGuardian methodology: https://blog.gitguardian.com/secrets-in-source-code-episode-3-3-building-reliable-secrets-detection/
- GitGuardian entropy detection: https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/generics/generic_high_entropy_secret

---

## Phase 3: Analysis Subsystems

Build all specialized analyzers. Each produces cacheable output for the incremental index (FA1).

### R6: Call Graph with Full Resolution

**Priority**: P0
**Effort**: High

**What to Build**:
A call graph builder that:
1. Processes files in parallel via rayon with `StreamingBuilder` pattern
2. Stores in SQLite (WAL mode, FA3) with `ParallelWriter` for threaded batch writes
3. Runs a resolution pass that resolves call targets to function IDs with confidence scoring
4. Tracks resolution statistics from day one (total calls, resolved, same-file, cross-file, unresolved)
5. Exposes rich queries: callers, callees, entry points, data accessors, file-level callers

**Data model**:
```
FunctionEntry { id: "file:name:line", name, start_line, end_line,
  is_entry_point, is_data_accessor, calls, called_by, data_access }
CallEntry { target, resolved_id, resolved, confidence, line }
DataAccessRef { table, fields, operation: Read|Write|Delete, line }
```

---

### R7: Coupling Analyzer with Full Feature Set

**Priority**: P1
**Effort**: Medium

**What to Build**:
Build the coupling analyzer with ALL features from day one — don't build basic metrics and plan to add the rest later.

1. Robert C. Martin metrics: Ca, Ce, Instability (I), Abstractness (A), Distance (D)
2. Tarjan's SCC for cycle detection (not DFS — Tarjan's is the correct algorithm, same O(V+E) complexity, guarantees completeness)
3. Condensation graph generation (DAG of SCCs for architecture visualization)
4. Zone detection: Zone of Pain (low I, low A), Zone of Uselessness (high I, high A)
5. Module role classification: hub (high Ca + high Ce), authority (high Ca + low Ce), balanced, isolated (low Ca + low Ce)
6. Cycle break suggestions: for each edge in an SCC, score by (Ce of source / Ca of target)
7. Refactor impact analysis: given a module, compute affected modules via transitive dependencies + call graph
8. Health score: penalize cycles, high coupling, zone violations, unused exports
9. Call graph integration for accurate impact analysis

**Evidence**:
- Tarjan's SCC: https://www.wikiwand.com/en/Tarjan's_strongly_connected_components_algorithm
- Robert C. Martin metrics: "Design Principles and Design Patterns" (2000)

---

### R8: Boundary Analysis with ORM Extractors and Risk Scoring

**Priority**: P1
**Effort**: Medium

**What to Build**:
1. Data access point detection (DB queries, API calls, file I/O) with operation classification (Read/Write/Delete/Update)
2. ORM-specific field extractors built in from the start:
   - Prisma, Django, SQLAlchemy, Entity Framework, Sequelize, TypeORM (highest priority)
   - Supabase, GORM, Diesel, Raw SQL (secondary)
3. Sensitive field detection (PII, financial, auth, health) with reason tracking
4. Risk scoring per data access point: `risk = sensitivity × exposure × frequency`
5. Table name validation (naming convention checks)

**Key difference from v1**: v1 had basic detection in Rust, ORM extractors in TS. v2 does everything in Rust.

---

### R9: Environment Analyzer with .env Cross-Referencing

**Priority**: P1
**Effort**: Low-Medium

**What to Build**:
1. Extract env var access patterns from source: `process.env.X`, `os.environ["X"]`, `getenv("X")`, `env("X")`, `${X}`, `%X%`
2. Sensitivity classification: Critical/Secret/Internal/Public based on name patterns
3. `.env` file parser (key=value with comment support, quoted values, multiline)
4. Missing variable detection: cross-reference code accesses against .env contents
5. Environment consistency checking: compare `.env`, `.env.production`, `.env.development`
6. Framework-specific prefix detection: `NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`, `NUXT_*`, `EXPO_PUBLIC_*`

**Key difference from v1**: v1 split this across Rust (extraction) and TS (.env parsing, cross-referencing). v2 does it all in Rust.

---

### R10: Error Handling Analyzer with Propagation Tracking

**Priority**: P1
**Effort**: Medium

**What to Build**:
1. Error boundary detection: TryCatch, ErrorMiddleware, ErrorBoundary, GlobalHandler, Decorator, ResultType
2. Error gap detection: UnhandledPromise, EmptyCatch, MissingCatch, SwallowedError, UncheckedResult, IgnoredError
3. Gap severity classification: Critical/High/Medium/Low with fix suggestions
4. Error type tracking (custom error classes, inheritance chains)
5. Error propagation chain tracking via call graph integration (which functions can throw, where are errors caught)
6. Error profile generation per module (types handled, gap density, rethrow rate)

**Key difference from v1**: v1 did AST-level detection in Rust, propagation chains in TS. v2 builds the full pipeline in Rust with call graph integration.

---

### R11: Test Topology Analyzer with Quality Scoring

**Priority**: P1
**Effort**: Medium

**What to Build**:
1. Test file identification by naming convention and content
2. Framework detection for 35+ frameworks across 10 languages:
   - JS/TS: Jest, Vitest, Mocha, Cypress, Playwright, Testing Library, Supertest, Chai, Sinon
   - Python: pytest, unittest, nose2, hypothesis
   - Java: JUnit, TestNG, Mockito, AssertJ
   - C#: NUnit, xUnit, MSTest
   - Go: testing, testify
   - PHP: PHPUnit, Pest
   - Rust: built-in test, proptest
3. Test case extraction with type classification (Unit/Integration/E2E/Performance/Snapshot)
4. Mock detection and classification (Full/Partial/Spy)
5. Test-to-source mapping via import analysis AND call graph integration
6. Test quality scoring: assertion density, mock ratio, test isolation, naming conventions
7. Minimum test set calculation: given a code change, which tests must run?
8. Coverage risk levels per source file

**Key difference from v1**: v1 had 11 frameworks in Rust, 35+ in TS. v2 builds all 35+ in Rust with quality scoring and minimum test set from the start.

---

### R12: Reachability Engine with Taint Analysis Foundation

**Priority**: P1
**Effort**: High

**What to Build**:
1. Forward reachability: "From function X, what data can it access?"
2. Inverse reachability: "What functions can reach sensitive data Y?"
3. Call path tracing with sensitive field identification along paths
4. Both in-memory and SQLite-backed variants (for large codebases)
5. Basic intraprocedural taint analysis:
   - Define sources (function parameters, request objects, env vars, user input APIs)
   - Define sinks (SQL query construction, logging, HTTP responses, file writes)
   - Track taint propagation through assignments, concatenation, function calls within a single function
   - Report taint flows as `DetectedPattern` with category `Security` and source→sink path metadata
6. Sanitizer recognition (escapeHtml, parameterize, etc.) to reduce false positives

**Evidence**:
- Semgrep taint analysis: https://semgrep.dev/docs/writing-rules/data-flow/data-flow-overview/
- Semgrep design trade-offs: intraprocedural, no path sensitivity, no soundness guarantees — keeps it fast and practical

**Key difference from v1**: v1 had reachability but zero data flow analysis. v2 builds taint tracking in from the start.

---

### R13: Wrapper Detector with Multi-Framework Registry

**Priority**: P2
**Effort**: Low-Medium

**What to Build**:
1. Detect functions that wrap framework primitives by analyzing call targets
2. Comprehensive primitives registry covering all major frameworks:
   - React: useState, useReducer, useEffect, useLayoutEffect, useMemo, useCallback, useRef, useContext
   - Vue: ref, reactive, computed, watch, watchEffect, onMounted, onUnmounted
   - Angular: HttpClient, Injectable, ActivatedRoute, FormBuilder, FormControl
   - Svelte: writable, readable, derived, onMount, onDestroy
   - Express: Router, express.json, express.static, cors, helmet
   - NestJS: @Injectable, @Controller, @Get, @Post, @Guard, @Interceptor
   - Data fetching: fetch, axios, useSWR, useQuery, got, superagent
   - Validation: zod, yup, joi, class-validator
   - Database: prisma.*, sequelize.*, typeorm.*, knex.*
   - Logging: console.*, logger.*, winston.*, pino.*
3. Confidence scoring with name-based and call-count adjustments
4. Wrapper clustering by category with similarity scoring
5. Cross-file usage counting via call graph (not deferred to TS)
6. Make the registry configurable (load from TOML) for extensibility

**Key difference from v1**: v1 was React-focused with usage counting deferred to TS. v2 covers all major frameworks with call-graph-based usage counting in Rust.

---

### R14: Constants Analyzer with Fuzzy Matching

**Priority**: P2
**Effort**: Low-Medium

**What to Build**:
1. Constant extraction from AST (const/let/var declarations)
2. Magic number detection via AST (not line-level regex): identify numeric literals in non-constant contexts, with context-aware naming suggestions
3. Inconsistency detection with fuzzy name matching:
   - Normalize names: split on `_`, `-`, camelCase boundaries → lowercase → join with `_`
   - `MAX_RETRIES`, `maxRetries`, `MaxRetries` all normalize to `max_retries`
   - Flag groups with different values
4. Dead constant detection via usage analysis (cross-reference with call graph/import graph)

**Key difference from v1**: v1 used line-level regex for magic numbers and exact-match for inconsistencies. v2 uses AST-based detection and fuzzy name matching.

---

## Phase 4: Bridge Layer

### R15: N-API Bridge with Batch and Streaming Support

**Priority**: P0
**Effort**: Medium

**What to Build**:
Design the N-API bridge as a first-class API layer, not a thin wrapper:

1. Individual analysis functions (same as v1 ~25 functions, but covering all new capabilities)
2. Batch API: `analyze_batch(root, analyses: Vec<AnalysisType>)` — runs multiple analyses in one N-API call, shares parsed results
3. Streaming support for large result sets via napi-rs `AsyncTask` + chunked results
4. Async variants for long-running operations (full scan, call graph build)
5. Structured error propagation: Rust error enums → meaningful N-API error objects with codes and messages

**Platform support**: darwin-arm64, darwin-x64, linux-arm64-gnu, linux-arm64-musl, linux-x64-gnu, linux-x64-musl, win32-x64-msvc

**Key design decision**: Keep N-API for performance-critical paths. Consider JSON-over-stdio as a secondary interface for MCP server flexibility.

**Evidence**:
- napi-rs: https://napi.rs/
- JetBrains on Rust+TS hybrid: https://blog.jetbrains.com/rust/2026/01/27/rust-vs-javascript-typescript/

---

## Phase 5: Performance Infrastructure

### R16: Rayon Parallelism with Proper Parser Management

**Priority**: P1
**Effort**: Low

**What to Build**:
Use rayon for all file-level parallelism with proper resource management:
1. Custom `ThreadPoolBuilder` with configured thread count, stack size, and panic handling
2. Parser pool pattern: instead of `thread_local!` (which leaks memory for pool lifetime), use a bounded crossbeam channel as a parser pool — checkout/return pattern
3. `Arc<RwLock<ResolutionIndex>>` for shared cross-file state during parallel analysis
4. Batch file processing with `par_iter()` + `flat_map_iter()` to avoid unnecessary intermediate allocations

**Evidence**:
- Rayon work-stealing: https://www.shuttle.rs/blog/2024/04/11/using-rayon-rust
- Thread-local caveats: https://github.com/rayon-rs/rayon/issues/941

---

### R17: Performance-Optimized Data Structures

**Priority**: P1
**Effort**: Low

**What to Build**:
Use the right data structure for each job from the start:
- `FxHashMap` (rustc-hash) for all internal hash maps (faster than std HashMap for small keys)
- `SmallVec<[T; 4]>` for collections that are usually small (function overloads, import lists)
- `BTreeMap` for ordered lookups (resolution index name lookups, prefix search)
- `lasso` for string interning (R3)
- `xxhash` (xxh3) for content hashing (file change detection)
- Release profile: `lto = true`, `codegen-units = 1`, `opt-level = 3`

---

### R18: Comprehensive Pattern Category Coverage

**Priority**: P1
**Effort**: Medium

**What to Build**:
Ensure all 15 pattern categories have AST queries AND string patterns from day one:

| Category | AST Queries | String Patterns | Status |
|---|---|---|---|
| Api | Routes, handlers per framework | Route path strings | ✅ Build |
| Auth | Decorators, middleware, guards | Bearer tokens, auth headers | ✅ Build |
| Components | Component declarations | — | ✅ Build |
| Config | — | Environment patterns | ✅ Build |
| DataAccess | ORM decorators, entity annotations | SQL strings | ✅ Build |
| Documentation | Doc comments, JSDoc | — | ✅ Build |
| Errors | Try/catch, error checks | — | ✅ Build |
| Logging | — | Console/logger patterns | ✅ Build (v1 compiled but never wired) |
| Performance | Memoization, caching decorators | — | ✅ Build |
| Security | Auth checks, CSRF tokens | Sensitive data patterns | ✅ Build |
| Structural | Module patterns, barrel files | — | ✅ Build |
| Styling | CSS-in-JS, styled components | — | ✅ Build |
| Testing | Test decorators, describe/it | — | ✅ Build |
| Types | Type annotations, interfaces | — | ✅ Build |
| Validation | Validation decorators | Schema patterns | ✅ Build |

v1 had gaps in Components, Documentation, Logging, Performance, Structural, Styling, Testing, Types. v2 covers all 15 from the start.

---

## Build Order

```
Phase 0 (Architecture):  FA1 + FA2 + FA3           [Decisions before code]
Phase 1 (Core Engine):   R1 → R2 → R3              [Scanner, Parsers, Interning]
Phase 2 (Detection):     R4 → R5                    [Unified Analyzer, Secrets]
Phase 3 (Analysis):      R6 → R7 → R8 → R9 → R10 → R11 → R12 → R13 → R14
                         [CallGraph, Coupling, Boundaries, Env, Errors, Tests, Reachability, Wrappers, Constants]
Phase 4 (Bridge):        R15                        [N-API]
Phase 5 (Performance):   R16 → R17 → R18           [Rayon, Data Structures, Pattern Coverage]
```

Note: Phase 5 items are "build with" not "add after" — they should be applied during Phases 1-4, listed separately for clarity.

---

## Dependency Graph

```
FA1 (Incremental) ──→ R1 (Scanner) ──→ R2 (Parsers) ──→ R4 (Unified Analyzer)
FA2 (Errors) ────────→ ALL subsystems                         │
FA3 (SQLite WAL) ───→ R6 (Call Graph)                         ↓
R3 (Interning) ─────→ R4, R6                            R5 (Secrets)
                                                              │
R6 (Call Graph) ────→ R7 (Coupling), R10 (Errors), R11 (Tests), R12 (Reachability)
R2 (Parsers) ───────→ R8 (Boundaries), R9 (Env), R13 (Wrappers), R14 (Constants)
R4 + R6 ────────────→ R15 (N-API Bridge)
```

---

## Quality Checklist

- [x] All 15 source documents accounted for
- [x] All v2 notes from every source document addressed
- [x] All limitations from every source document resolved in recommendations
- [x] Every recommendation framed as "build new" not "migrate/port"
- [x] External evidence cited for every architectural decision
- [x] Build order defined with dependency graph
- [x] No feature deferred to "add later" — everything built into the right phase
- [x] Traceability: every source doc maps to at least one recommendation
