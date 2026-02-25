# 16 Gap Analysis — Research Recap

> A comprehensive, cross-cutting synthesis of every gap, limitation, missing capability, and architectural debt identified across the entire Drift v1 codebase. This document consolidates findings from all 11 category RECAPs (01-rust-core through 13-advanced), the primary gap inventory (16-gap-analysis/README.md), the Rust core audit, and the MASTER_RECAP — producing the definitive gap registry for the v2 greenfield rebuild.
>
> **Scope**: 25 primary gaps from the gap inventory + 100+ cross-category gaps from all research categories + deep algorithm gaps + architectural debt + security gaps + coverage gaps + infrastructure gaps + corrections to existing documentation.
>
> **Date**: February 2026

---

## Executive Summary

Drift v1 is a ~51,000-line codebase (40K+ TypeScript, 11K Rust) that successfully proves the core thesis — offline convention discovery exposed to AI agents via MCP. But it was built iteratively, and the gaps compound. This document catalogs every known gap organized into 10 dimensions: architectural, algorithmic, security, coverage, performance, infrastructure, feature parity, data integrity, operational, and documentation. The gap count is not 25 (as the primary inventory suggests) — it is closer to 150 discrete gaps when cross-category findings are included.

The gaps cluster into three severity tiers:
- **Tier 1 — Structural** (38 gaps): Architectural decisions that cannot be patched — they must be rebuilt. Three ParseResult shapes, dual-layer architecture, no incremental anything, 6 fragmented storage backends, no structured error handling in Rust.
- **Tier 2 — Capability** (62 gaps): Missing features that limit enterprise viability. No taint analysis, only 21 secret patterns, no OWASP/CWE mapping, no GraphQL/gRPC contracts, incomplete language coverage, no temporal confidence decay, no Bayesian learning.
- **Tier 3 — Operational** (50+ gaps): Infrastructure, tooling, and quality-of-life gaps. No Rust CI, no multi-arch Docker, no SBOM, no performance regression CI, no E2E tests, no canary releases.

V2 must close all Tier 1 gaps by design (they are architectural). Tier 2 gaps define the feature roadmap. Tier 3 gaps define the operational maturity target.

---

## 1. Primary Gap Inventory (25 Gaps from README.md)

### 1.1 Critical Gaps (P0) — Will Break V2 If Missed

#### GAP-01: Licensing & Feature Gating System — COMPLETELY UNDOCUMENTED
- **Location**: `packages/core/src/licensing/`
- **Impact**: Business model — 3 tiers (community/team/enterprise), 16 gated features, JWT + simple key validation
- **Components**: LicenseManager, LicenseValidator, FeatureGuard, types
- **Guard patterns**: `requireFeature()`, `checkFeature()`, `guardFeature()`, `withFeatureGate()`, `@RequiresFeature()`, `guardMCPTool()`, `requireTier()`
- **License sources**: env var (`DRIFT_LICENSE_KEY`), file (`.drift/license.key`), config
- **Why critical**: The entire monetization model is encoded here. Every gated feature checks this system. Without it, v2 loses the open-core boundary.
- **Cross-ref**: 12-infrastructure RECAP §6 (full licensing deep dive)

#### GAP-02: Workspace Management System — UNDOCUMENTED
- **Location**: `packages/core/src/workspace/`
- **Impact**: Project lifecycle orchestrator — the glue that ties everything together
- **Components**: WorkspaceManager, ProjectSwitcher, ContextLoader, BackupManager, SchemaMigrator, SourceOfTruth
- **Why critical**: Without understanding how projects are initialized, switched, backed up, and migrated, v2 won't have a coherent lifecycle.

#### GAP-03: Audit System — UNDOCUMENTED
- **Location**: `packages/core/src/audit/`
- **Impact**: Pattern validation, health scoring, degradation detection — the core value proposition feedback loop
- **Components**: AuditEngine, AuditStore, types
- **Health score algorithm**: avgConfidence×0.30 + approvalRatio×0.20 + complianceRate×0.20 + crossValidationRate×0.15 + duplicateFreeRate×0.15, ×100, clamped [0,100]
- **Cross-ref**: 09-quality-gates RECAP §6 (full audit system deep dive)

#### GAP-04: Pattern Matcher & Confidence Scorer — UNDER-DOCUMENTED
- **Location**: `packages/core/src/matcher/`
- **Impact**: The heart of Drift's learning system
- **Missing from docs**: `confidence-scorer.ts` (the actual algorithm), `pattern-matcher.ts` (the core matching engine)
- **Confidence weights**: frequency×0.40 + consistency×0.30 + ageFactor×0.15 + spread×0.15
- **Cross-ref**: 03-detectors RECAP §Key Algorithms (full algorithm documentation)

#### GAP-05: Context Generation System — NOW DOCUMENTED
- **Location**: `packages/core/src/context/`
- **Status**: ✅ Documented in `22-context-generation/`
- **Components**: ContextGenerator, PackageDetector (11 package ecosystems), types

#### GAP-06: Storage Backend Auto-Detection — UNDOCUMENTED
- **Location**: `packages/core/src/storage/store-factory.ts`
- **Impact**: Transparent JSON↔SQLite switching based on what exists on disk
- **Functions**: `detectStorageBackend()`, `hasSqliteDatabase()`, `hasJsonPatterns()`, `getStorageInfo()`
- **Cross-ref**: 08-storage RECAP §Backend 2 (StoreFactory deep dive)

### 1.2 High-Priority Gaps (P1) — Important for Feature Parity

#### GAP-07: Skills Library — 73 Architectural Templates — UNDOCUMENTED
- **Location**: `skills/` directory
- **Impact**: Knowledge base for code generation guidance — significant domain expertise
- **Categories**: AI coaching, API patterns, caching, circuit breakers, database migrations, distributed locks, error handling, feature flags, health checks, idempotency, JWT auth, leader election, logging, metrics, multi-tenancy, OAuth, pagination, rate limiting, retry/fallback, row-level security, SSE, Stripe, Supabase, webhooks, websockets, worker orchestration, and more

#### GAP-08: Wiki — 58 User Documentation Pages — UNDOCUMENTED
- **Location**: `wiki/` directory
- **Impact**: User-facing documentation revealing intended behavior not captured in code-level docs
- **Key pages**: Architecture, Audit System, Call Graph, CI Integration, CLI Reference, Configuration, Cortex (7 pages), Dashboard, Detectors Deep Dive, FAQ, Getting Started, MCP (3 pages), Quality Gates, Security Analysis, Skills, Troubleshooting, Watch Mode

#### GAP-09: Demo Applications — 8 Reference Implementations — UNDOCUMENTED
- **Location**: `demo/` directory
- **Impact**: Integration test fixtures validating Drift works across all supported languages/frameworks
- **Apps**: Node.js/TS backend, C# backend, Spring Boot backend, Laravel backend, Go backend, Rust backend, WPF/XAML sample, React frontend

#### GAP-10: GitHub Action — CI/CD Integration — UNDER-DOCUMENTED
- **Location**: `actions/drift-action/action.yml`
- **Impact**: Composite action for PR analysis with 8 inputs, 5 outputs
- **Cross-ref**: 12-infrastructure RECAP §10 (full GitHub Action documentation)

#### GAP-11: Services Layer — NOW DOCUMENTED
- **Status**: ✅ Documented in `25-services-layer/overview.md`

#### GAP-12: Learning System — UNDER-DOCUMENTED
- **Location**: `packages/core/src/learning/`
- **Impact**: Convention persistence across sessions — `.drift/learned/{detector-id}.json`
- **Defaults**: minOccurrences=3, dominanceThreshold=0.60, minFiles=2, maxFiles=1000, 24-hour expiry

### 1.3 Medium-Priority Gaps (P2) — Behavioral Details

#### GAP-13: Unified Provider Internal Details — UNDER-DOCUMENTED
- Parser registry, legacy extractors, legacy scanner wrapper, unified scanner, unified data access adapter, internal migration guide

#### GAP-14: Speculative Execution — Split Across Two Directories
- `packages/core/src/simulation/` (documented) and `packages/core/src/speculative/` (undocumented)
- Separate approach generator and template types in the speculative directory

#### GAP-15: Dual Licensing Model — UNDOCUMENTED
- Apache 2.0 (open source) + BSL 1.1 (enterprise features)
- Per-file license headers, BSL converts to Apache 2.0 after 4 years
- **Cross-ref**: 12-infrastructure RECAP §6

#### GAP-16: MCP Feedback System — UNDOCUMENTED
- `packages/mcp/src/feedback.ts` — FeedbackManager with file/directory-level scoring
- Rating system: good (+0.1), bad (-0.15), irrelevant (-0.05)
- Directory propagation: 30% of file delta
- Exclusion threshold: boost < -0.5 AND confidence > 0.5
- Score→multiplier: `1 + (boost × 0.7)` (range 0.3 to 1.7)
- Persists to `.drift/feedback/examples.json` and `.drift/feedback/scores.json`
- Keeps last 5000 entries
- **This is a reinforcement learning loop for example quality — completely undocumented**

#### GAP-17: MCP Pack Manager — UNDER-DOCUMENTED
- `packages/mcp/src/packs.ts` — PackManager with custom pack creation, staleness detection, usage tracking
- Pack suggestion engine inferring packs from project structure
- Custom packs stored in `.drift/packs/`
- Usage analytics tracking per pack

#### GAP-18: Storage Backend Auto-Detection — UNDOCUMENTED
- (Covered under GAP-06)

#### GAP-19: JSON↔SQLite Sync Service — UNDER-DOCUMENTED
- `packages/core/src/storage/sync-service.ts` — 1142 lines, 11 sync methods
- Bidirectional sync across patterns, contracts, constraints, boundaries, environment, call graph, audit, DNA, test topology, scan history, quality gates
- **Cross-ref**: 08-storage RECAP §SyncService

#### GAP-20: Docker Deployment — UNDOCUMENTED
- Multi-stage build, non-root user, 4GB memory limit, health checks
- SSE endpoint at `/sse`, message endpoint at `/message`
- **Cross-ref**: 12-infrastructure RECAP §4

#### GAP-21: Husky Git Hooks — UNDOCUMENTED
#### GAP-22: Build Scripts — UNDER-DOCUMENTED
#### GAP-23: Turborepo Pipeline — UNDOCUMENTED
#### GAP-24: Pattern System Consolidation — NOW DOCUMENTED (see `23-pattern-repository/`)
#### GAP-25: Pervasive EventEmitter Architecture — UNDOCUMENTED
- Nearly every store and manager extends EventEmitter
- Events like `pattern:added`, `pattern:approved`, `patterns:loaded` propagate through the system
- This pub/sub architecture must be preserved in v2

---

## 2. Deep Algorithm Gaps

These are the exact values, weights, and thresholds that must be preserved or deliberately improved in v2. Getting these wrong means v2 produces different results than v1 for the same codebase.

### 2.1 Confidence Scoring Algorithm
```
score = frequency × 0.40 + consistency × 0.30 + ageFactor × 0.15 + spread × 0.15
```
- Frequency: occurrences / totalLocations [0.0, 1.0]
- Consistency: 1 - variance (clamped) [0.0, 1.0]
- Age Factor: Linear 0.1 → 1.0 over 30 days, then flat forever
- Spread: fileCount / totalFiles [0.0, 1.0]
- Classification: high (≥0.85), medium (≥0.70), low (≥0.50), uncertain (<0.50)

**Known gaps**:
- No temporal decay — once high confidence, stays there forever even if convention changes
- No momentum signal — cannot detect conventions that are growing or declining
- No Bayesian uncertainty — binary threshold (60%) for convention learning
- Weight validation enforces sum = 1.0 (±0.001 tolerance) — good, preserve this

### 2.2 Health Score Algorithm
```
score = (avgConfidence × 0.30 + approvalRatio × 0.20 + complianceRate × 0.20
       + crossValidationRate × 0.15 + duplicateFreeRate × 0.15) × 100
```
- Clamped to [0, 100]
- **Known gap**: No temporal component — health score is a snapshot, not a trend

### 2.3 Audit Recommendation Thresholds
- Auto-approve: confidence ≥ 0.90, outlierRatio ≤ 0.50, locations ≥ 3, no error-severity issues
- Review: confidence ≥ 0.70
- Likely false positive: confidence < 0.70
- Duplicate group membership downgrades auto-approve to review

### 2.4 Learning System Defaults
- Min occurrences: 3
- Dominance threshold: 0.60 (60% must use same convention)
- Min files: 2
- Max files to analyze: 1000
- Learned patterns expire after 24 hours
- Stored in `.drift/learned/{detector-id}.json`
- **Known gap**: Binary threshold with no Bayesian uncertainty modeling

### 2.5 Feedback Scoring (MCP)
- Good example: +0.1 boost
- Bad example: -0.15 penalty
- Irrelevant: -0.05 penalty
- Directory propagation: 30% of file delta
- Exclusion threshold: boost < -0.5 AND confidence > 0.5
- Score → multiplier: `1 + (boost × 0.7)` (range: 0.3 to 1.7)

### 2.6 Duplicate Detection
- Jaccard similarity on location sets (file:line pairs)
- Threshold: 0.85 similarity
- Only compares within same category
- Recommendation: merge if > 0.9, review if > 0.85

### 2.7 Outlier Detection
- n ≥ 30: Z-Score with |z| > 2.0 threshold (flags ~4.6% — too aggressive per NIST)
- n < 30: IQR with 1.5× multiplier
- Sensitivity adjustment: both scale by `(1 + (1 - sensitivity))`
- **Known gaps**: No Grubbs' test for small samples, no iterative detection, threshold too low

### 2.8 Gate Scoring
```
penalty = Σ(error_violations × 10) + Σ(warning_violations × 3) + Σ(info_violations × 1)
score = max(0, 100 - (penalty / maxPenalty) × 100)
```

### 2.9 Friction Score (Impact Simulation)
```
frictionScore = (filesAffected/maxFiles × 25) + (functionsAffected/maxFunctions × 25)
              + (entryPointsAffected/maxEntryPoints × 30) + (sensitiveDataPaths × 20)
```
- Breaking risk: critical (>80), high (>60), medium (>40), low

### 2.10 CI Agent Scoring
```
overallScore = patternScore × 0.30 + constraintScore × 0.25
             + securityScore × 0.20 + testScore × 0.15
             + couplingScore × 0.10
```

### 2.11 Wrapper Detection Confidence
```
base = 0.6
+ 0.15 naming patterns (use*, with*, create*, make*)
+ 0.15 wrapper/hook/helper in name
+ 0.10 custom hook pattern (useXxx)
- 0.10 complex functions (>10 calls)
+ 0.10 focused functions (≤3 calls)
threshold = 0.5
```

### 2.12 Secret Detection Confidence
- Critical (0.9 base): AWS keys, GitHub tokens, Stripe keys, RSA/SSH/PGP private keys
- High (0.8 base): Google API keys, passwords, JWTs, DB connections, Slack/SendGrid/Twilio
- Medium (0.6 base): Hardcoded passwords, bearer tokens, generic API keys, webhooks
- Adjustments: +0.05 high entropy, +0.05 length >30
- Placeholder skip: "example", "placeholder", "your_", "xxx", "todo", "changeme"

---

## 3. Architectural Gaps

These are structural problems that cannot be patched — they must be redesigned in v2.

### 3.1 Three ParseResult Shapes
| Shape | Source | Structure |
|-------|--------|-----------|
| Rust `ParseResult` | `crates/drift-core/` | Extracted metadata (functions, classes, imports, exports, calls) |
| TS `ParseResult` | `packages/core/` | Raw AST tree (fundamentally different) |
| NAPI `JsParseResult` | `crates/drift-napi/` | Bridge conversion of Rust shape with manual field-by-field mapping |

**Impact**: Type confusion, maintenance burden, impossible to guarantee consistent behavior across layers.
**V2 fix**: One canonical `ParseResult` type owned by Rust, consumed everywhere.

### 3.2 Dual-Layer Architecture (Feature Parity Drift)
- Rust: ~30 AST patterns, 3 call resolution strategies, basic coupling metrics
- TypeScript: 350+ detectors, 6 call resolution strategies, full coupling with Tarjan's SCC, module roles, zone detection
- **Impact**: Double maintenance, feature parity drift, inconsistent results depending on which layer runs

### 3.3 Six Fragmented Storage Backends
1. JSON File Storage (deprecated)
2. SQLite Unified Store (keep — becomes foundation)
3. Data Lake with materialized views/shards/indexes (deprecated)
4. Rust SQLite for call graphs (keep — expand)
5. Cortex SQLite with vector embeddings (keep — consolidate)
6. Hybrid bridge stores (deprecated)

**Impact**: ~12,000 lines of storage code, 50+ JSON files in `.drift/`, three separate sync paths, no transactional guarantees across domains.
**V2 fix**: 2 Rust-managed SQLite databases: `drift.db` (all analysis) + `cortex.db` (AI memory + vectors).

### 3.4 No Structured Error Handling in Rust
- String-based errors throughout `drift-core`
- Poor NAPI error propagation — errors become opaque strings in TypeScript
- **V2 fix**: `thiserror` for all error types, one error enum per subsystem

### 3.5 Thread-Local Parser Management
- `thread_local!` for `ParserManager` in rayon threads
- No explicit cleanup between scan operations
- **Impact**: Unbounded memory growth across long-running processes

### 3.6 Dead Code in Unified Analyzer
- `log_patterns` RegexSet compiled but never called in `analyze()`
- `Violation` type defined but `violations` always `Vec::new()`
- `ResolutionStats` fields all initialized to 0 with TODO comments
- **Impact**: Wasted compilation, missing detection capabilities, no resolution quality tracking

### 3.7 JSON Shard Duplication
- Patterns stored in both SQLite and JSON shards
- Dual-write overhead on every scan
- No single source of truth during hybrid phase
- **V2 fix**: SQLite-only, eliminate all JSON persistence

### 3.8 No Incremental Anything
| Subsystem | Current | Impact |
|-----------|---------|--------|
| Scanner | Full rescan every time | Wasted I/O |
| Parser | Re-parse all files on every scan | Wasted CPU |
| Detectors | Re-detect all files on every scan | Wasted CPU |
| Call Graph | Full rebuild required | Wasted CPU + I/O |
| Analyzers | Full re-analysis every time | Wasted CPU |
| Views | Manual rebuild, not auto-refreshed | Stale data risk |

**V2 fix**: Content-hash based file-level skipping, tree-sitter `tree.edit()` for IDE mode, Salsa-based derived queries for cross-file analysis.

### 3.9 No Pattern Decay
- Once a pattern reaches high confidence, it stays there forever
- Even if the convention changes, old patterns are enforced
- **Impact**: Drift fights intentional convention migrations

### 3.10 No Pattern Merging
- Multiple detectors can discover the same convention independently
- No consolidation mechanism — duplicate patterns accumulate
- Jaccard similarity detection exists but only flags, doesn't auto-merge

### 3.11 Pervasive EventEmitter Without Backpressure
- Nearly every store/manager extends EventEmitter
- No backpressure mechanism for high-frequency events
- No event ordering guarantees across async boundaries
- **V2 consideration**: Preserve pub/sub architecture but add structured event bus with ordering guarantees

---

## 4. Security Gaps

### 4.1 Secret Detection Coverage
- **Current**: 21 regex patterns
- **Missing providers**: Azure (4+ key types), GCP (service account keys, API keys), DigitalOcean, Heroku, npm tokens, PyPI tokens, NuGet API keys, Bitbucket, GitLab tokens, Square, PayPal
- **Missing techniques**: Shannon entropy calculator (H > 4.5 threshold), contextual confidence scoring (variable name sensitivity, test file discount, comment discount, .env file boost)
- **V2 target**: 100+ patterns organized by provider

### 4.2 No OWASP/CWE Mapping
- Security findings have no CWE IDs
- No OWASP Top 10 category references
- Cannot produce compliance reports
- **Impact**: Enterprise customers require compliance mapping for audit purposes

### 4.3 No Taint Analysis
- Cannot track untrusted data from sources to sinks
- Cannot distinguish sanitized from unsanitized data
- No source-sink-sanitizer model
- **Impact**: Cannot detect SQL injection, XSS, command injection, SSRF with confidence
- **V2 approach**: Intraprocedural first (within single function), then interprocedural via call graph

### 4.4 Missing OWASP Coverage
| OWASP Category | Current Coverage | Gap |
|----------------|-----------------|-----|
| A01: Broken Access Control | Partial (auth detectors) | No permission checks, RBAC patterns, path traversal, CORS |
| A02: Cryptographic Failures | Partial (secret detection) | No weak crypto, insecure random, weak hashing |
| A03: Injection | Partial (SQL injection, XSS) | No command injection, LDAP injection, template injection |
| A04: Insecure Design | None | No rate limiting checks, input validation, trust boundaries |
| A05: Security Misconfiguration | None | No debug mode, default credentials, missing headers |
| A07: Auth Failures | Partial (auth detectors) | No weak password policy, missing MFA, session fixation |
| A08: Integrity Failures | None | No insecure deserialization, unsigned data |
| A09: Logging Failures | Partial (logging detectors) | No security logging checks, PII-in-logs detection |
| A10: SSRF | None | No URL-from-user-input detection |

### 4.5 No Field-Level Data Flow
- Reachability is table-level only (`users` table, not `users.password_hash`)
- Cannot distinguish sensitive fields from non-sensitive fields in data flow
- **Impact**: High false positive rate in security analysis — accessing `users.display_name` flagged same as `users.password_hash`

### 4.6 No Cross-File Data Flow
- All analysis is intraprocedural (within a single function)
- No tracking of data transformations across function boundaries
- **Impact**: Cannot detect security vulnerabilities that span multiple functions

---

## 5. Coverage Gaps

### 5.1 Language Coverage Gaps

| Language | Parsing | Detection | Call Graph | Semantic Analysis |
|----------|---------|-----------|------------|-------------------|
| TypeScript | ✅ Full | ✅ Full (350+ detectors) | ✅ Full (6 strategies) | ✅ Type + Scope |
| JavaScript | ✅ Full | ✅ Full | ✅ Full | ✅ Scope only |
| Python | ✅ Full | ⚠️ Partial (Django contracts only) | ✅ Full | ❌ None |
| Java | ✅ Full | ⚠️ Partial (Spring 12 categories) | ✅ Full | ❌ None |
| C# | ✅ Full | ⚠️ Partial (ASP.NET 11 categories) | ✅ Full | ❌ None |
| PHP | ✅ Full | ⚠️ Partial (Laravel 12 categories) | ✅ Full | ❌ None |
| Go | ✅ Full | ⚠️ Minimal (api+auth+errors only) | ✅ Full | ❌ None |
| Rust | ✅ Full | ⚠️ Minimal (api+auth+errors only) | ✅ Full | ❌ None |
| C++ | ✅ Full | ⚠️ Minimal (api+auth+errors only) | ✅ Full | ❌ None |
| C | ✅ Full | ❌ None | ✅ Basic | ❌ None |

### 5.2 Framework Coverage Gaps

| Framework | Current | Missing |
|-----------|---------|---------|
| Django | Contracts only | Learning, semantic, config, logging, testing, structural, security |
| Go frameworks (Gin, Echo, Fiber, Chi) | api+auth+errors | config, logging, testing, structural, data-access, performance |
| Rust frameworks (Actix, Axum, Rocket, Warp) | api+auth+errors | Same as Go |
| C++ frameworks (Crow, Boost.Beast, Qt) | api+auth+errors | Same as Go |
| Vue.js | ❌ None | All categories |
| Angular | ❌ None | All categories |
| Svelte | ❌ None | All categories |
| Next.js | ❌ None | All categories (SSR, ISR, API routes, middleware) |
| NestJS | ❌ None | All categories (DI, guards, interceptors, pipes) |
| FastAPI | Partial (route detection) | Full framework support |
| Ruby on Rails | ❌ None | All categories |
| Phoenix (Elixir) | ❌ None | All categories |

### 5.3 API Paradigm Gaps
- **GraphQL**: No schema extraction, no resolver detection, no query↔schema mismatch, no N+1 resolver detection
- **gRPC/Protobuf**: No .proto parsing, no service/message definitions, no client↔server mismatch
- **WebSocket**: No contract detection for WebSocket APIs
- **REST**: Covered but missing OpenAPI/Swagger spec parsing and breaking change classification

### 5.4 Detector Stub/Placeholder Gaps
- `SemanticLearningDetector`: Stub — not implemented
- `Custom match strategy`: Defined in types but not implemented
- `Violation` type in Rust: Defined but never populated
- `log_patterns` in Rust: Compiled but never used
- `ResolutionStats` in Rust: Fields all TODO

### 5.5 Rust Feature Parity Gaps (vs TypeScript)

| Feature | Rust | TypeScript | Priority |
|---------|------|------------|----------|
| Generic type parameters | ❌ | ✅ | P0 |
| Pydantic model extraction | ❌ | ✅ (9 files) | P0 |
| Structured annotations | Partial (strings) | ✅ (objects) | P0 |
| Full inheritance chains | Partial (direct) | ✅ (multi-level) | P1 |
| Namespace/package extraction | ❌ | ✅ | P1 |
| Incremental parsing | ❌ | ✅ (tree.edit()) | P2 |
| AST caching | ❌ | ✅ (LRU, 100) | P2 |
| Per-language call extractors | 1 universal | 8 × 3 variants | P0 |
| 6-strategy call resolution | 3 strategies | 6 strategies | P0 |
| DI injection resolution | ❌ | ✅ | P0 |
| Impact analysis | ❌ | ✅ | P1 |
| Dead code detection | ❌ | ✅ | P1 |
| Tarjan's SCC | ❌ (DFS) | ✅ | P1 |
| Module roles/zones | ❌ | ✅ | P1 |
| Type analysis | ❌ | ✅ (TS-only) | P0 |
| Scope/symbol resolution | ❌ | ✅ (TS/JS-only) | P0 |
| CFG construction | ❌ | ✅ | P1 |
| Rules engine | ❌ | ✅ (4,900 LOC) | P1 |
| Quick fix generation | ❌ | ✅ (7 strategies) | P2 |

---

## 6. Performance Gaps

### 6.1 Detection Performance
- 350+ TypeScript detectors run sequentially per file
- Each detector traverses the AST independently — 100+ traversals per file
- Current: ~5ms per file per detector → 5-10s for 10K files
- Target: <0.5ms per file total via single-pass visitor pattern
- **V2 fix**: ESLint-style visitor pattern — traverse once, dispatch to all interested handlers

### 6.2 No Parallel Detection in TypeScript
- Single-threaded execution for all detectors
- No worker thread utilization
- **V2 fix**: Rust-native detection with rayon parallelism

### 6.3 No Caching Strategy
- No parse result caching between scans
- No detection result caching
- No call graph query caching
- **V2 fix**: Moka concurrent cache (TinyLFU + LRU), content-hash keyed

### 6.4 Storage Performance
- No connection pooling (single connection per backend)
- No prepared statement caching (each query re-parsed)
- No keyset pagination (OFFSET/LIMIT degrades at scale)
- No write batching for patterns (individual inserts)
- **V2 fix**: Connection pool (1 writer + N readers), prepared statements, keyset pagination, batch transactions

### 6.5 Scale Targets
| Metric | V1 Actual | V2 Target |
|--------|-----------|-----------|
| Incremental scan (1 file, 10K codebase) | ~10s (full rescan) | <100ms |
| Full scan (10K files) | ~30s | <5s |
| Full scan (500K files) | Untested/infeasible | <60s |
| Detection per file | ~5ms (100+ traversals) | <0.5ms (single pass) |
| Parse cache hit rate | 0% (no cache) | >95% |

---

## 7. Infrastructure Gaps

### 7.1 CI/CD Gaps
- No Rust CI integration: no `cargo clippy`, `cargo fmt`, `cargo test` in pipeline
- `continue-on-error: true` on build and test (debt)
- Lint disabled (debt)
- No performance regression CI (no benchmark comparison in PRs)
- No E2E integration tests (CI tests core/detectors/mcp only, not full pipeline)

### 7.2 Build & Release Gaps
- No automated cross-publish (npm and cargo publish are separate manual processes)
- No monorepo version management (no Changesets or similar)
- No canary/staged releases (all-or-nothing npm publish)
- No reproducible builds (no build hash verification)
- Missing Linux musl target (only gnu targets, no Alpine Linux support)
- No WASM target (no browser-based analysis capability)

### 7.3 Supply Chain Security Gaps
- No SBOM generation (Software Bill of Materials)
- No dependency scanning (no Dependabot/Snyk)
- No provenance attestation (npm provenance exists but no SLSA)
- No signed releases

### 7.4 Operational Gaps
- No infrastructure-as-code (Docker/Cloudflare configs are manual)
- No observability stack (no structured logging, no distributed tracing, no metrics beyond telemetry)
- No multi-arch Docker builds (single architecture only)
- No license server (JWT validation is local-only, no revocation capability)

### 7.5 Rust Build Gaps
- No Rust workspace feature flags (no conditional compilation for optional analyzers)
- No schema versioning in Rust (only TS has migration support)
- No Rust-side benchmarks in CI

---

## 8. Data Integrity Gaps

### 8.1 No Single Source of Truth
- 6 storage backends with 3 sync paths create inconsistency risk
- `source-of-truth.json` tracks which backend is authoritative per domain — fragile

### 8.2 No Transactional Guarantees Across Domains
- JSON writes can partially fail
- No atomic operations spanning patterns + call graph + audit

### 8.3 No Data Integrity Validation
- No periodic consistency checks between backends
- No checksum verification on read
- No corruption detection

### 8.4 No Retention Policies
- Pattern history grows unbounded
- Audit snapshots: 30-day retention (good)
- Gate run history: max 100 runs (good)
- Telemetry: 90-day raw events (good)
- But: learned patterns, feedback scores, pack usage — no retention

### 8.5 No Schema Versioning in Rust
- Only TypeScript has migration support for SQLite schema changes
- Rust `CallGraphDb` creates schema on open with no version tracking

---

## 9. Documentation Corrections

These are factual errors in existing documentation that must be corrected.

### 9.1 CLI Command Count
- **Documented**: "~45 commands"
- **Actual**: `commands/index.ts` exports 48 named commands, plus `dna/` subcommands, plus `setup/` has 13 runners. Real count is closer to 65+.

### 9.2 MCP Tool Count
- **Documented**: "90+ tools"
- **Actual**: 56 unique tool names in `routeToolCall()` switch statements. With 17 memory tools routed via `executeMemoryTool` wrapper + 33 memory tool files, total is ~56 routed tools.

### 9.3 Matcher Directory Contents
- **Documented**: `types.ts`, `outlier-detector.ts`
- **Actual**: `types.ts`, `outlier-detector.ts`, `confidence-scorer.ts`, `pattern-matcher.ts`, `index.ts` + 3 test files

### 9.4 .drift/ Directory Structure
Missing from configuration docs:
- `.drift/learned/` — Learned pattern conventions (per-detector JSON files)
- `.drift/feedback/` — Example quality feedback (examples.json, scores.json)
- `.drift/packs/` — Custom MCP tool packs
- `.drift/license.key` — License key file
- `.drift/backups/` — Backup storage with retention policy

### 9.5 Package Detector Scope
Supports 11 package ecosystems (far more comprehensive than documented):
npm workspaces, pnpm workspaces, yarn workspaces, Python (pyproject.toml, setup.py, setup.cfg), Go modules (go.mod, go.work), Maven (pom.xml), Gradle (settings.gradle), Composer (composer.json), .NET (.csproj, .sln), Cargo workspaces (Cargo.toml)

### 9.6 Confidence Weight Discrepancy
- **Documentation**: 0.35/0.25/0.15/0.25
- **Code**: 0.40/0.30/0.15/0.15
- **Authoritative**: The code. V2 should use the code values as baseline.

### 9.7 MCP Server Dual-Path Architecture
Undocumented dual-path in enterprise server:
- Legacy path: `PatternStore` (JSON-based) directly
- New path: `IPatternService` (SQLite-backed) when available
- Tools with dual implementations: `drift_status`, `drift_patterns_list`, `drift_pattern_get`, `drift_code_examples`, `drift_prevalidate`, `drift_security_summary`, `drift_contracts_list`, `drift_env`, `drift_dna_profile`, `drift_constraints`

---

## 10. Cross-Category Gap Synthesis

### 10.1 Gaps That Appear in Multiple Categories

| Gap | Categories Where It Appears | Impact |
|-----|---------------------------|--------|
| No incremental computation | 01, 02, 03, 04, 05, 08 | Every subsystem is batch-only |
| No taint analysis | 01, 03, 04, 05 | Cannot do meaningful security analysis |
| No structured errors in Rust | 01, 02 | Poor error propagation across NAPI |
| No pattern decay | 03, 05, 09 | Stale conventions enforced forever |
| No feedback loop | 03, 05, 07 | Unknown false-positive rate |
| Dual-layer feature parity | 01, 02, 03, 04, 05 | Double maintenance, inconsistent results |
| No OWASP/CWE mapping | 03, 04, 05 | Cannot produce compliance reports |
| No GraphQL/gRPC contracts | 03, 07 | Missing modern API paradigms |
| Framework coverage gaps | 02, 03 | Django, Go, Rust, C++ incomplete |
| Storage fragmentation | 08, 07, 09, 10 | 6 backends, no single source of truth |

### 10.2 Gaps That Block Other Gaps

```
No incremental computation ──blocks──→ IDE integration (sub-second response)
                           ──blocks──→ 500K+ file support
                           ──blocks──→ Watch mode performance

No taint analysis ──blocks──→ OWASP A01, A03, A10 coverage
                  ──blocks──→ Field-level security analysis
                  ──blocks──→ Enterprise compliance reporting

No canonical ParseResult ──blocks──→ Consistent detection across layers
                         ──blocks──→ GAST normalization layer
                         ──blocks──→ Cross-language detector reuse

No call graph in Rust (full) ──blocks──→ Taint analysis in Rust
                              ──blocks──→ Impact analysis in Rust
                              ──blocks──→ Dead code detection in Rust
                              ──blocks──→ Security boundary analysis in Rust
```

### 10.3 Gap Closure Ordering (Critical Path)

```
Phase 0: Architectural decisions (M1-M4)
  ↓
Phase 1: Canonical ParseResult + Parser trait + Scanner with change detection
  ↓
Phase 2: Single-pass visitor pattern + Unified analyzer + Secret detection (100+)
  ↓
Phase 3: Full call graph (6 strategies) + Taint analysis + Coupling (Tarjan's)
  ↓
Phase 4: Temporal decay + Bayesian learning + Outlier refinements
  ↓
Phase 5: OWASP/CWE mapping + N+1 detection
  ↓
Phase 6: N-API bridge + Fixes + Feedback loop + Contracts (REST/GraphQL/gRPC)
  ↓
Phase 7: Infrastructure (Rust CI, multi-arch Docker, SBOM, E2E tests)
```

---

## 11. Undocumented Systems Inventory

Systems that exist in v1 but have no research documentation:

| System | Location | Lines (est.) | Status |
|--------|----------|-------------|--------|
| Licensing & Feature Gating | `packages/core/src/licensing/` | ~800 | ✅ Documented in 12-infrastructure RECAP |
| Workspace Management | `packages/core/src/workspace/` | ~1500 | ❌ No dedicated research doc |
| Telemetry (client + server) | `packages/core/src/telemetry/` + `infrastructure/telemetry-worker/` | ~600 | ✅ Documented in 12-infrastructure RECAP |
| Skills Library | `skills/` (73 templates) | ~7000 | ❌ No research doc |
| Wiki | `wiki/` (58 pages) | ~15000 | ❌ No research doc |
| Demo Applications | `demo/` (8 apps) | ~5000 | ❌ No research doc |
| MCP Feedback System | `packages/mcp/src/feedback.ts` | ~300 | ❌ No research doc |
| MCP Pack Manager | `packages/mcp/src/packs.ts` | ~400 | ❌ No research doc |
| Galaxy Visualization | `packages/galaxy/` | ~2500 | ✅ Documented in 12-infrastructure RECAP |
| CIBench | `packages/cibench/` | ~3000 | ✅ Documented in 12-infrastructure RECAP |
| AI Providers | `packages/ai/` | ~1000 | ✅ Documented in 12-infrastructure RECAP |
| Dashboard | `packages/dashboard/` | ~2000 | ❌ No dedicated research doc |
| LSP Server | `packages/lsp/` | ~500 | ❌ No dedicated research doc |

---

## 12. V2 Gap Closure Priority Matrix

| Priority | Gap Count | Examples | Build Phase |
|----------|-----------|---------|-------------|
| P0 — Must have for launch | 18 | Canonical ParseResult, incremental computation, single-pass detection, full call graph, taint analysis, 100+ secrets, OWASP mapping, temporal decay, licensing, workspace management | Phases 0-3 |
| P1 — Must have within 3 months | 24 | Bayesian learning, GAST normalization, framework middleware, GraphQL/gRPC contracts, impact analysis, dead code, Tarjan's SCC, N+1 detection, feedback loop, fix generation | Phases 3-6 |
| P2 — Must have within 6 months | 20 | Cross-service reachability, abstract interpretation, WASM target, multi-arch Docker, canary releases, CIBench v2, Galaxy v2 | Phase 7+ |
| P3 — Nice to have | 10+ | Speculative execution, advanced visualization, custom detector marketplace | Future |

---

## Quality Checklist

- [x] All 25 primary gaps from README.md documented with cross-references
- [x] All 12 deep algorithm gaps documented with exact values and thresholds
- [x] All 11 architectural gaps documented with v2 fix strategies
- [x] All 6 security gap categories documented with OWASP mapping
- [x] All 5 coverage gap dimensions documented (language, framework, API paradigm, stubs, Rust parity)
- [x] All 5 performance gap areas documented with v1 baselines and v2 targets
- [x] All 5 infrastructure gap categories documented
- [x] All 5 data integrity gaps documented
- [x] All 7 documentation corrections cataloged
- [x] Cross-category gap synthesis with blocking dependencies
- [x] Gap closure ordering aligned with MASTER_RECOMMENDATIONS build phases
- [x] Undocumented systems inventory with documentation status
- [x] Priority matrix with gap counts per tier
- [x] Every gap cross-referenced to source category RECAP where applicable
