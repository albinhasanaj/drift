# 23 Pattern Repository — Comprehensive Audit

> **Purpose**: Exhaustive audit of every pattern, design decision, architectural convention, anti-pattern, and cross-cutting concern identified across all 16 Drift v1 research categories. This document is the forensic foundation for the RECAP — nothing is inferred, everything is traced to source.
>
> **Scope**: All 16 category RECAPs, 3 master documents, 8 overview documents, gap analysis, and cross-category connections.
>
> **Date**: February 2026

---

## 1. Architectural Patterns Inventory

### 1.1 Layered Architecture (6 Layers)

**Source**: SYSTEM_BRIEF.md, MASTER_RECAP.md, 00-overview/architecture.md

Drift v1 implements a strict 6-layer architecture with unidirectional dependency flow:

| Layer | Name | Components | Responsibility |
|-------|------|-----------|----------------|
| 1 | Presentation | CLI, MCP Server, VSCode, Dashboard | User/AI-facing interfaces |
| 2 | Orchestration | Commands, Services, Quality Gates, Workspace | Pipeline coordination |
| 3 | Intelligence | Detectors (350+), Analyzers, Cortex Memory | Pattern discovery, semantic analysis |
| 4 | Analysis | Call Graph, Boundaries, Reachability | Relationship mapping |
| 5 | Parsing | Tree-sitter (10 langs), Regex fallback | AST extraction |
| 6 | Storage | drift.db (SQLite), cortex.db (SQLite + vectors) | Persistence |
| 7 | Rust Core | Native parsers, Scanner, Call graph, NAPI | Performance engine |

**Dependency Rule**: Each layer may only depend on layers below it. Presentation → Orchestration → Intelligence → Analysis → Parsing → Storage → Rust Core.

**Violations Found**:
- Detectors (Layer 3) sometimes directly access storage (Layer 6), bypassing Analysis (Layer 4)
- MCP Server (Layer 1) directly queries storage via 9 store objects, bypassing orchestration
- Quality Gates (Layer 2) directly consume call graph (Layer 4), which is correct, but also directly read pattern storage (Layer 6)

### 1.2 Dual-Layer Architecture (Rust + TypeScript)

**Source**: 01-rust-core/RECAP.md, 02-parsers/RECAP.md, MASTER_RECAP.md

The most fundamental architectural pattern. Every compute-intensive subsystem has two implementations:

| Subsystem | Rust Implementation | TypeScript Implementation | Feature Parity |
|-----------|-------------------|--------------------------|----------------|
| Parsers | 10 languages, ~8K LOC | 14 languages, ~10K LOC | TS has richer extraction |
| Call Graph | StreamingBuilder, ParallelWriter | GraphBuilder, 8 extractors | TS has 6-strategy resolution |
| Unified Analyzer | AST + string + regex pipeline | Full rules engine | TS has quick fixes |
| Boundaries | ORM detection, PII patterns | Full boundary scanner | TS has learning |
| Coupling | Martin's metrics, DFS cycles | Cycle detection, refactor suggestions | TS has richer output |
| Constants | 21 regex patterns, entropy | Orchestration, per-language | Complementary |
| Environment | Multi-lang extraction | .env parsing, consistency | Complementary |
| Error Handling | AST boundary/gap detection | Call-graph-aware propagation | Complementary |
| Test Topology | 13 framework detection | 35+ frameworks, quality scoring | TS far richer |
| Wrappers | Primitive registry, clustering | Cross-file usage, docs export | Complementary |

**Anti-Pattern**: Three ParseResult shapes (Rust, TS, NAPI bridge) create type confusion at every boundary crossing.

### 1.3 Pipeline Architecture

**Source**: 00-overview/pipelines.md, 10-cli/RECAP.md, 25-services-layer

Drift's core operations are modeled as sequential pipelines:

**Scan Pipeline** (12 phases):
```
File Discovery → Parsing → Detection → Aggregation → Confidence Scoring →
Pattern Storage → [Call Graph Build] → [Boundary Scan] → [Contract Scan] →
[Manifest Generation] → History Snapshot → Finalization
```

**Check Pipeline** (5 phases):
```
File Resolution → Pattern Loading → Rule Evaluation → Reporting → Exit Code
```

**MCP Context Pipeline** (7 phases):
```
Pattern Retrieval → Code Examples → Cortex Retrieval → Call Graph Context →
Boundary Context → Synthesis → Response
```

**Quality Gate Pipeline** (9 phases):
```
File Resolution → Policy Loading → Gate Determination → Context Building →
Gate Execution → Evaluation → Aggregation → Snapshot Save → Report Generation
```

---

## 2. Design Patterns Inventory

### 2.1 Factory Pattern

**Instances Found**:

| Factory | Location | Creates | Detection Method |
|---------|----------|---------|-----------------|
| `createErrorHandlingAnalyzer()` | 19-error-handling | ErrorHandlingAnalyzer | Options-based |
| `createPatternServiceAsync()` | 23-pattern-repository | IPatternService | Auto-detect backend |
| `createCortex()` | 06-cortex | CortexV2 | Config-based |
| `StoreFactory.create()` | 08-storage | UnifiedStore or JSON stores | Backend auto-detection |
| `DetectorLoader` | 03-detectors | Detector instances | Lazy loading with factory functions |
| `GateRegistry` | 09-quality-gates | Gate instances | Lazy instantiation, singleton |
| `PatternServiceFactory` | 10-cli | PatternService | Config-based |

### 2.2 Repository Pattern

**Instances Found**:

| Repository | Domain | Interface | Storage |
|-----------|--------|-----------|---------|
| PatternRepository | Patterns | IPatternService | SQLite |
| ContractRepository | Contracts | IContractRepository | SQLite |
| ConstraintRepository | Constraints | typed access | SQLite |
| BoundaryRepository | Boundaries | typed access | SQLite |
| EnvironmentRepository | Environment | typed access | SQLite |
| CallgraphRepository | Call Graph | typed access | SQLite |
| AuditRepository | Audit | typed access | SQLite |
| DNARepository | DNA | typed access | SQLite |
| TestTopologyRepository | Test Topology | typed access | SQLite |
| IMemoryStorage | Cortex Memory | Full CRUD + vector | SQLite + sqlite-vec |

### 2.3 Strategy Pattern

**Instances Found**:

| Strategy Set | Count | Context | Selection Method |
|-------------|-------|---------|-----------------|
| Call Resolution Strategies | 6 | Call graph building | Priority cascade |
| Quick Fix Strategies | 7 | Rules engine | Pattern-based |
| Aggregation Modes | 4 | Quality gates | Policy config |
| Embedding Providers | 4 | Cortex | Auto-detection priority |
| Outlier Detection Methods | 2 | Confidence scoring | Sample size (n≥30 → Z-score, else IQR) |
| Pattern Matching Strategies | 3 | Detector system | AST, Regex, Structural |
| Retrieval Intent Strategies | 15 | Cortex retrieval | Intent classification |

### 2.4 Observer / EventEmitter Pattern

**Source**: 16-gap-analysis/RECAP.md (GAP-25), 08-storage/RECAP.md

Nearly every store and manager extends Node.js EventEmitter:

| Emitter | Events | Consumers |
|---------|--------|-----------|
| PatternStore | `pattern:added`, `pattern:approved`, `pattern:ignored`, `patterns:loaded` | MCP, CLI, Quality Gates |
| ContractStore | `contract:discovered`, `contract:verified`, `contract:mismatch` | MCP, CLI |
| CallGraphStore | `callgraph:built`, `callgraph:updated` | Analysis engines |
| AuditStore | `audit:completed`, `degradation:detected` | CLI, Quality Gates |
| DetectorRegistry | `detector:registered`, `detector:enabled`, `detector:disabled` | Loader, CLI |
| WorkspaceManager | `project:switched`, `project:initialized` | All consumers |

**Anti-Pattern**: No backpressure mechanism. No ordering guarantees. No error propagation through event chains. Events are fire-and-forget.

### 2.5 Adapter Pattern

**Instances Found**:

| Adapter | From | To | Purpose |
|---------|------|-----|---------|
| Native Adapter | Rust ParseResult | TS ParseResult | Fallback chain |
| NAPI Bridge | Rust types | JS types | Field-by-field conversion |
| HybridPatternStore | SQLite + JSON | Unified API | Migration bridge |
| HybridContractStore | SQLite + JSON | Unified API | Migration bridge |
| Language Normalizers (9) | Per-language AST | Unified semantic model | Cross-language comparison |
| UnifiedCallGraphProvider | Rust + TS call graphs | Unified query API | Storage abstraction |

### 2.6 Builder Pattern

**Instances Found**:

| Builder | Product | Steps |
|---------|---------|-------|
| ResponseBuilder | MCP Response | summary → details → examples → pagination |
| StreamingBuilder | Call Graph | parallel parse → extract → resolve → persist |
| SetupState | Project Setup | 8-phase wizard with 13 runners |
| ViewMaterializer | Data Lake Views | status → patterns → security → trends → indexes |
| GraphBuilder | In-memory Call Graph | register functions → imports → classes → calls → resolve |

### 2.7 Visitor Pattern (Proposed, Not Implemented)

**Source**: MASTER_RECOMMENDATIONS.md (M5), 03-detectors/RECOMMENDATIONS.md

V1 runs 100+ separate AST traversals per file (one per detector). V2 proposes a single-pass visitor pattern where the AST is traversed once and each node is dispatched to interested handlers.

**Current anti-pattern**: O(d × n) where d = detectors, n = AST nodes. Target: O(n) with visitor dispatch.

### 2.8 Decorator Pattern

**Instances Found**:

| Decorator | Purpose | Location |
|-----------|---------|----------|
| `@RequiresFeature()` | License tier gating | Licensing system |
| `guardMCPTool()` | MCP tool access control | MCP server |
| `requireTier()` | Tier enforcement | Feature guard |
| `withFeatureGate()` | Feature flag wrapping | Feature guard |

### 2.9 Singleton Pattern

**Instances Found**:

| Singleton | Scope | Purpose |
|-----------|-------|---------|
| GateRegistry | Process | Gate registration and lazy instantiation |
| FrameworkRegistry | Process | Framework pattern definitions |
| DetectorRegistry | Process | Detector registration and querying |
| ProjectRegistry | Global (~/.drift) | Multi-project management |

---

## 3. Data Patterns Inventory

### 3.1 Confidence Scoring (Weighted Composite)

**Source**: 03-detectors/RECAP.md, 00-overview/data-models.md

The heart of Drift's learning system:

```
score = frequency × 0.40 + consistency × 0.30 + ageFactor × 0.15 + spread × 0.15
```

| Factor | Calculation | Range | Weight |
|--------|------------|-------|--------|
| Frequency | occurrences / totalLocations | [0.0, 1.0] | 0.40 |
| Consistency | 1 - variance (clamped) | [0.0, 1.0] | 0.30 |
| Age Factor | Linear scale: 0.1 → 1.0 over 30 days | [0.1, 1.0] | 0.15 |
| Spread | fileCount / totalFiles | [0.0, 1.0] | 0.15 |

**Classification**: high (≥0.85), medium (≥0.70), low (≥0.50), uncertain (<0.50)

**Weight validation**: Constructor enforces sum = 1.0 (±0.001 tolerance).

**Known Issue**: Gap analysis documents list weights as 0.35/0.25/0.15/0.25 but actual code uses 0.4/0.3/0.15/0.15. Code is authoritative.

### 3.2 Health Scoring (Multiple Variants)

**Variant 1 — Audit Health Score** (09-quality-gates):
```
score = avgConfidence×0.30 + approvalRatio×0.20 + complianceRate×0.20
      + crossValidationRate×0.15 + duplicateFreeRate×0.15
```

**Variant 2 — DNA Health Score** (13-advanced):
```
score = consistency×0.40 + confidence×0.30 + mutations×0.20 + coverage×0.10
```

**Variant 3 — Error Handling Quality Score** (19-error-handling):
```
Base: 50, +20 try/catch, +15 recover, +10 transform, +5 preserves error,
-20 no try/catch, -25 swallowed error, -5 bare catch
```

**Variant 4 — Gate Scoring** (09-quality-gates):
```
penalty = errors×10 + warnings×3 + info×1
score = max(0, 100 - (penalty / maxPenalty) × 100)
```

### 3.3 Bitemporal Tracking

**Source**: 06-cortex/RECAP.md

Every Cortex memory tracks two time dimensions:
- **Transaction time**: When we learned it (immutable)
- **Valid time**: When it was/is true (can be updated)

Enables temporal queries: "What did we know about X as of last Tuesday?"

### 3.4 Content-Hash Change Detection

**Source**: 08-storage/RECAP.md, MASTER_RECOMMENDATIONS.md

SHA-256 hashing of file contents for incremental scan support. Used in ManifestStore for skip-unchanged-files optimization. V2 upgrades to xxhash for speed.

### 3.5 Sharded Storage

**Source**: 08-storage/RECAP.md (Data Lake)

Data partitioned by dimension for selective loading:
- Patterns by category: `.drift/lake/patterns/{category}.json`
- Call graph by file: `.drift/lake/callgraph/{fileHash}.json`
- Security by table: `.drift/lake/security/{table}.json`
- Examples by pattern: `.drift/lake/examples/{patternId}.json`

### 3.6 Hierarchical Compression (Cortex)

**Source**: 06-cortex/RECAP.md

4 compression levels for token budget management:
| Level | Tokens | Content |
|-------|--------|---------|
| 1 | ~IDs only | Memory IDs |
| 2 | ~20 per memory | One-liner summaries |
| 3 | ~200 per memory | With examples |
| 4 | Unlimited | Full context |

Greedy bin-packing sorted by importance.

---

## 4. Anti-Patterns Inventory

### 4.1 Three ParseResult Shapes

**Source**: 02-parsers/RECAP.md, MASTER_RECAP.md

| Shape | Origin | Structure | Problem |
|-------|--------|-----------|---------|
| Rust `ParseResult` | `crates/drift-core/src/parsers/types.rs` | Extracted metadata (functions, classes, imports, exports, calls) | Canonical |
| TS `ParseResult` | `packages/core/src/parsers/` | Raw AST tree (fundamentally different) | Incompatible |
| NAPI `JsParseResult` | `crates/drift-napi/src/lib.rs` | Bridge conversion of Rust shape | Lossy conversion |

**Impact**: Every consumer must handle shape ambiguity. Field-by-field manual conversion in NAPI bridge is error-prone and lossy.

### 4.2 Six Fragmented Storage Backends

**Source**: 08-storage/RECAP.md

| Backend | Technology | Lines | Status |
|---------|-----------|-------|--------|
| JSON File Storage | JSON files in .drift/ | ~3,868 | DEPRECATED |
| SQLite Unified Store | better-sqlite3 | ~2,542 | KEEP (foundation) |
| Data Lake | JSON views/shards/indexes | ~4,520 | DEPRECATED |
| Rust SQLite | rusqlite | ~1,200 | KEEP (expand) |
| Cortex Memory | better-sqlite3 + sqlite-vec | ~1,500 | KEEP (consolidate) |
| Hybrid Stores | Bridge layers | ~800 | DEPRECATED |

**Impact**: ~12,000 lines of storage code, 50+ JSON files, 3 sync paths, no transactional guarantees across domains.

### 4.3 No Incremental Computation

**Source**: MASTER_RECOMMENDATIONS.md (M1), 16-gap-analysis/RECAP.md

Every subsystem is batch-only:
- Full filesystem rescan every time
- Full re-parse of all files
- Full re-detection across all detectors
- Full call graph rebuild
- Full view materialization

**Impact**: Scan times scale linearly with codebase size. No sub-second response for single-file changes.

### 4.4 No Pattern Decay

**Source**: 16-gap-analysis/RECAP.md, MASTER_RECOMMENDATIONS.md

Patterns never lose confidence over time. A pattern discovered 2 years ago with no recent occurrences has the same confidence as one discovered yesterday. Stale conventions are enforced forever.

### 4.5 No Pattern Merging

**Source**: 09-quality-gates/RECAP.md (Audit System)

Duplicate patterns accumulate. The audit system detects duplicates (Jaccard similarity > 0.85) but doesn't auto-merge them. Manual review required.

### 4.6 Thread-Local Parser Management

**Source**: 01-rust-core/RECAP.md

Rust parsers use `thread_local!` for parser instances. Each rayon thread gets its own parser set. No upper bound on memory growth as thread count increases.

### 4.7 Dead Code in Rust

**Source**: 01-rust-core/RECAP.md

`log_patterns` function compiled but never called. Indicates incomplete cleanup during development.

### 4.8 Pervasive EventEmitter Without Backpressure

**Source**: 16-gap-analysis/RECAP.md (GAP-25)

Fire-and-forget events with no ordering guarantees, no error propagation, no backpressure. Can cause cascading failures in high-throughput scenarios.

---

## 5. Cross-Cutting Concerns Inventory

### 5.1 Error Handling Patterns

**Rust**: `anyhow::Result` used pervasively. No structured error types. No `thiserror` enums. Errors are opaque strings at NAPI boundary.

**TypeScript**: Mix of thrown exceptions, Result-like patterns, and silent failures. No consistent error hierarchy.

**NAPI Bridge**: Errors converted to generic JS exceptions. No structured error codes. No error categorization.

### 5.2 Parallelism Patterns

| Pattern | Technology | Used By |
|---------|-----------|---------|
| Rayon thread pool | Rust | Scanner, Call Graph Builder, Unified Analyzer |
| Piscina worker threads | Node.js | ScannerService (CLI) |
| MPSC channel | Rust | ParallelWriter (call graph persistence) |
| Promise.all | TypeScript | Quality gate parallel execution |
| thread_local! | Rust | Parser instances per thread |

### 5.3 Caching Patterns

| Cache | Technology | Strategy | Location |
|-------|-----------|----------|----------|
| MCP ResponseCache | LRU + file | L1 in-memory + L2 file | 07-mcp |
| Cortex Embedding Cache | 3-tier | L1 Map + L2 SQLite + L3 precomputed | 06-cortex |
| Parser LRU Cache | LRU | TS ParserManager | 02-parsers |
| Moka (proposed) | TinyLFU + LRU | Content-hash keyed | MASTER_RESEARCH |
| ManifestStore | Content-hash | SHA-256 file hashes | 08-storage |

### 5.4 Configuration Patterns

| Config Source | Format | Priority | Location |
|--------------|--------|----------|----------|
| drift.config.json | JSON | Base | Project root |
| .driftrc.json / .driftrc | JSON | Alternative | Project root |
| Environment variables | DRIFT_* | Override | Process env |
| CLI flags | Various | Highest | Command line |
| .drift/config.json | JSON | Project-specific | .drift/ directory |
| Policy files | JSON | Gate-specific | .drift/quality-gates/policies/ |

### 5.5 Licensing / Feature Gating

**Source**: 16-gap-analysis/RECAP.md (GAP-01), 12-infrastructure/RECAP.md

3 tiers: Community, Team, Enterprise. 16 gated features. JWT + simple key validation.

Guard patterns: `requireFeature()`, `checkFeature()`, `guardFeature()`, `withFeatureGate()`, `@RequiresFeature()`, `guardMCPTool()`, `requireTier()`.

License sources: env var (`DRIFT_LICENSE_KEY`), file (`.drift/license.key`), config.

### 5.6 Telemetry Patterns

**Source**: 12-infrastructure/RECAP.md

Cloudflare Workers-based anonymous telemetry. Opt-in. Records scan duration, file count, pattern count, language distribution. No PII.

---

## 6. Algorithm Patterns Inventory

### 6.1 Statistical Methods

| Algorithm | Used By | Complexity | Selection Criteria |
|-----------|---------|-----------|-------------------|
| Z-Score outlier detection | Detectors | O(n) | n ≥ 30 samples |
| IQR outlier detection | Detectors | O(n log n) | n < 30 samples |
| Jaccard similarity | Audit (duplicate detection) | O(l) per pair | Same-category patterns |
| TF-IDF embeddings | Cortex (lexical) | O(v × d) | Keyword matching |
| BFS traversal | Call graph reachability | O(V + E) | Forward/inverse reach |
| DFS cycle detection | Coupling analyzer | O(V + E) | Module dependency cycles |
| Weighted composite scoring | Confidence, health, friction | O(1) per entity | Universal |
| Set cover (greedy) | Test topology (min test set) | O(t × f) | CI optimization |
| Martin's metrics (Ca/Ce/I/A/D) | Coupling analyzer | O(m) per module | Module coupling |

### 6.2 Resolution Strategies (Call Graph)

**Source**: 04-call-graph/RECAP.md

6-strategy cascade for resolving call targets:

| Priority | Strategy | Confidence | Method |
|----------|----------|-----------|--------|
| 1 | Same-file | High | Match function name within same file |
| 2 | Method resolution | High | Match class.method via class registry |
| 3 | DI resolution | Medium-High | Match injected dependency types |
| 4 | Import resolution | Medium | Follow import chains |
| 5 | Export resolution | Medium | Match exported names |
| 6 | Fuzzy matching | Low | Name similarity across all functions |

### 6.3 Confidence Propagation

Confidence scores ripple through relationships:
- Pattern confidence → violation severity
- Call graph edge confidence → reachability confidence
- Contract match confidence → mismatch severity
- Memory confidence → retrieval ranking
- Embedding similarity → memory relevance

---

## 7. Integration Patterns Inventory

### 7.1 NAPI Bridge Pattern

**Source**: 01-rust-core/RECAP.md, 02-parsers/RECAP.md

~25 N-API functions expose Rust to TypeScript. Manual field-by-field conversion. No automatic serialization. Each function has a `Js*` wrapper type.

### 7.2 Fallback Chain Pattern

**Source**: 02-parsers/RECAP.md

```
Rust native → TS tree-sitter → TS regex → null
```

Used in parsers, call graph extractors, test topology extractors. Each level has decreasing confidence.

### 7.3 Hybrid Extraction Pattern

**Source**: 04-call-graph/RECAP.md

Tree-sitter primary extraction with regex fallback. Results merged, preferring tree-sitter when available. Confidence tagged by extraction method.

### 7.4 Query Routing Pattern (Data Lake)

**Source**: 08-storage/RECAP.md

```
Query → Views (pre-computed) → Indexes (O(1)) → Shards (partitioned) → Raw (full load)
```

Each result includes `source` field. Stats tracking records hit counts and response times.

### 7.5 Token Budget Pattern (MCP/Cortex)

**Source**: 07-mcp/RECAP.md, 06-cortex/RECAP.md

All MCP responses and Cortex retrievals are compressed to fit within a token budget (default 2000). Higher-importance items get more allocation. Hierarchical compression with 4 levels.

---

## 8. Testing Patterns Inventory

### 8.1 Test Framework Coverage

| Framework | Languages | Detection Method |
|-----------|----------|-----------------|
| Jest | TS/JS | Import detection, describe/it/test blocks |
| Vitest | TS/JS | Import detection, describe/it/test blocks |
| Mocha | TS/JS | Import detection, describe/it blocks |
| Pytest | Python | Function prefix `test_`, class prefix `Test` |
| JUnit 4/5 | Java | @Test annotation |
| TestNG | Java | @Test annotation |
| xUnit | C# | [Fact], [Theory] attributes |
| NUnit | C# | [Test], [TestCase] attributes |
| PHPUnit | PHP | Method prefix `test`, @test annotation |
| go-testing | Go | Function prefix `Test`, `*testing.T` parameter |
| rust-test | Rust | #[test] attribute, #[cfg(test)] module |
| GTest | C++ | TEST(), TEST_F() macros |
| Catch2 | C++ | TEST_CASE(), SECTION() macros |

### 8.2 Property-Based Testing

**Source**: 10-cli/RECAP.md

CLI `check` command has property-based tests. Limited adoption elsewhere.

### 8.3 Test Coverage Gaps

**Source**: 16-gap-analysis/RECAP.md

- No E2E tests
- No performance regression tests in CI
- No Rust-specific tests in CI (no `cargo clippy`, `cargo fmt`, `cargo test`)
- Coverage thresholds set at 80% but `continue-on-error: true` in CI (debt)

---

## 9. Security Patterns Inventory

### 9.1 Secret Detection

**Source**: 05-analyzers/RECAP.md (Constants Analyzer)

21 regex patterns for secret detection with entropy scoring and placeholder filtering.

### 9.2 Sensitive Data Classification

**Source**: 04-call-graph/RECAP.md (Reachability)

Categories: PII, financial, health, credentials. Used in reachability analysis and security boundary gates.

### 9.3 Auth Pattern Detection

**Source**: 09-quality-gates/RECAP.md (Security Boundary Gate)

Required auth patterns: `authenticate`, `authorize`, `checkAuth`, `requireAuth`. Walks call graph to verify auth exists in call chain before data access.

### 9.4 Path Security

**Source**: 07-mcp/RECAP.md

MCP server validates file paths to prevent directory traversal attacks.

---

## 10. Deployment Patterns Inventory

### 10.1 Transport Patterns

| Transport | Protocol | Use Case |
|-----------|----------|----------|
| stdio | stdin/stdout | IDE integration (Claude Desktop, Cursor, Kiro) |
| HTTP/SSE | HTTP + Server-Sent Events | Containerized deployments (Docker) |

### 10.2 Platform Targets

7 native binary targets: darwin-arm64, darwin-x64, linux-arm64-gnu, linux-arm64-musl, linux-x64-gnu, linux-x64-musl, win32-x64-msvc.

### 10.3 Build Pipeline

pnpm 8 + Turborepo + NAPI-RS cross-compilation. Publish order: core → detectors → galaxy → dashboard → CLI → MCP.

---

## Audit Completeness Checklist

- [x] All 16 category RECAPs reviewed
- [x] 3 master documents reviewed (RECAP, RESEARCH, RECOMMENDATIONS)
- [x] 8 overview documents reviewed
- [x] Gap analysis (150+ gaps) cross-referenced
- [x] Category connections mapped
- [x] Research methodology understood
- [x] All architectural patterns cataloged
- [x] All design patterns cataloged
- [x] All data patterns cataloged
- [x] All anti-patterns cataloged
- [x] All cross-cutting concerns cataloged
- [x] All algorithm patterns cataloged
- [x] All integration patterns cataloged
- [x] All testing patterns cataloged
- [x] All security patterns cataloged
- [x] All deployment patterns cataloged
