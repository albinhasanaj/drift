# Drift V1 → V2 Master Audit

> Enterprise-grade traceability audit of the complete Drift v1 system across all 27 categories. This document captures every architectural gap, every cross-cutting risk, every unresolved dependency, and every decision that must be made before v2 code is written. It is the single source of truth for what v1 IS, what it CANNOT do, and what v2 MUST address.

**Audit Date**: 2026-02-06
**Scope**: All 27 categories (00-26), ~1,200+ source files, ~65 Rust files, ~500+ TypeScript files
**Methodology**: Full document review of all category RECAPs, RESEARCH files, RECOMMENDATIONS, and source documentation

---

## Table of Contents

1. [System Identity & Core Thesis](#1-system-identity--core-thesis)
2. [Architecture Audit](#2-architecture-audit)
3. [Category-by-Category Gap Analysis](#3-category-by-category-gap-analysis)
4. [Cross-Cutting Concerns](#4-cross-cutting-concerns)
5. [Data Model Inconsistencies](#5-data-model-inconsistencies)
6. [Performance Bottlenecks](#6-performance-bottlenecks)
7. [Security Audit](#7-security-audit)
8. [Reliability & Error Handling Audit](#8-reliability--error-handling-audit)
9. [Scalability Constraints](#9-scalability-constraints)
10. [Integration Contract Risks](#10-integration-contract-risks)
11. [Missing Enterprise Features](#11-missing-enterprise-features)
12. [Technical Debt Inventory](#12-technical-debt-inventory)
13. [Decision Register](#13-decision-register)
14. [Risk Matrix](#14-risk-matrix)
15. [V2 Non-Negotiables](#15-v2-non-negotiables)

---

## 1. System Identity & Core Thesis

### What Drift Is
Drift is a codebase convention discovery and indexing tool. It scans codebases to automatically discover patterns (how the team actually writes code), indexes them in SQLite, and exposes them to AI agents via MCP (Model Context Protocol).

### Core Thesis (Validated)
> If you can discover and index a codebase's conventions offline (no AI), you can expose them to AI at query time, giving it exactly the context it needs without wasting tokens on discovery.

### Four-Phase Operation
1. **SCAN** — Parse codebase with tree-sitter (10 languages), discover conventions across 16 categories, score statistically
2. **INDEX** — Store everything in SQLite (patterns, call graph, boundaries). No AI involved — pure static analysis
3. **EXPOSE** — MCP server with 87+ tools lets AI query what it needs
4. **LEARN** — Cortex memory system replaces static AGENTS.md with living memory

### What Makes Drift Unique (Audit Confirmed)
- Learns, doesn't prescribe — discovers YOUR conventions
- Statistical, not binary — confidence scores, not pass/fail
- Offline indexing — no AI needed for scanning
- MCP-native — built for AI consumption from day one
- Living memory — Cortex replaces static docs
- Multi-language — 10 languages, 28+ ORMs, 21+ frameworks
- Call graph aware — understands function relationships
- 100% local — no code leaves the machine

### Business Model
Open core with 3 tiers:
- **Community** (free, Apache 2.0): All scanning, detection, analysis, CI, MCP, VSCode
- **Team** (BSL 1.1): Policy engine, regression detection, custom rules, trends, exports
- **Enterprise** (BSL 1.1): Multi-repo governance, impact simulation, security boundaries, audit trails

---

## 2. Architecture Audit

### Layer Model (6 Layers — Strictly Ordered)

```
Layer 6 (Advanced):     Simulation Engine, Decision Mining, Context Generation
Layer 5 (Presentation): MCP Server, CLI, VSCode Extension, Dashboard
Layer 4 (Enforcement):  Rules Engine, Quality Gates, Audit, DNA System
Layer 3 (Intelligence): Patterns (aggregated), Cortex, Constraints, Wrappers, Coupling
Layer 2 (Analysis):     Detectors, Call Graph, Boundaries, Constants, Environment, Errors, Tests
Layer 1 (Foundation):   Parsers, Storage, Scanner
```

### AUDIT FINDING A1: Circular Dependency Risk
**Severity**: Medium
**Finding**: While the layer model is strictly ordered in documentation, the actual implementation has bidirectional dependencies:
- Analyzers (Layer 2) consume from Call Graph (Layer 2) — peer dependency, acceptable
- Detectors (Layer 2) consume from Analyzers (Layer 2) — peer dependency, acceptable
- Context Generation (Layer 6) depends on Cortex (Layer 3), Detectors (Layer 2), Call Graph (Layer 2), Security (Layer 2) — deep cross-layer dependency
- Quality Gates (Layer 4) depend on Call Graph (Layer 2) for impact simulation — acceptable skip
**Risk**: Context Generation's 4-layer dependency chain makes it fragile to changes in any upstream layer
**V2 Action**: Define explicit interface contracts at each layer boundary. Context Generation should consume from a unified query API, not directly from 4+ subsystems.

### AUDIT FINDING A2: Language Split Creates Maintenance Burden
**Severity**: High
**Finding**: ~65 Rust files (performance-critical) + ~500+ TypeScript files (orchestration, UI, memory). Many subsystems exist in BOTH languages with feature gaps:
- Parsers: Rust extracts basic metadata, TS extracts rich framework-aware data
- Call Graph: Rust has 3 resolution strategies, TS has 6
- Coupling: Rust uses DFS, TS uses Tarjan's SCC
- Detectors: Rust has ~30 AST patterns, TS has 350+
- Analyzers: Rust has basic metrics, TS has full analysis
**Risk**: Every feature must be implemented twice. Bugs fixed in one layer may not be fixed in the other. Feature parity is never achieved.
**V2 Action**: Rust becomes the single source of truth for all computation. TS becomes thin orchestration/presentation only.

### AUDIT FINDING A3: Three ParseResult Shapes
**Severity**: Critical
**Finding**: Three different ParseResult types exist:
1. Rust `ParseResult` — contains extracted metadata (functions, classes, imports, exports, calls)
2. TS `ParseResult` — contains raw AST tree (not extracted metadata)
3. NAPI `JsParseResult` — third shape consumed by TS callers
**Risk**: Data loss during conversion, semantic drift between shapes, maintenance nightmare
**V2 Action**: Single canonical ParseResult defined in Rust, serialized via NAPI, consumed by TS. No re-interpretation.


### AUDIT FINDING A4: Storage Fragmentation
**Severity**: Critical
**Finding**: 6 separate storage backends in v1:
1. JSON files (.drift/patterns/*.json) — 50+ files, O(n) reads, no concurrency
2. SQLite unified (drift.db) — 40+ tables, 50+ indexes
3. Data Lake (materialized views, indexes, shards) — JSON-based
4. Rust SQLite (callgraph.db) — separate database
5. Cortex SQLite (cortex.db + sqlite-vec) — separate database
6. Hybrid stores — transitional bridges
**Risk**: No transactional guarantees across domains. Partial writes corrupt data. Three separate sync paths. ~12,000 lines of storage code.
**V2 Action**: Consolidate to 2 databases: drift.db (Rust-owned, all analysis) + cortex.db (TS-owned, memory + vectors)

### AUDIT FINDING A5: MCP Tool Explosion
**Severity**: High
**Finding**: 87+ MCP tools across 10 categories. Tool definitions alone consume ~15-20K tokens. Most AI agents can only effectively use 10-20 tools.
**Risk**: Token waste, tool selection confusion, poor AI agent performance
**V2 Action**: Split into 2 servers (drift-analysis ~17-20 tools, drift-memory ~15-20 tools). Implement progressive disclosure (3 entry points per server).

---

## 3. Category-by-Category Gap Analysis

### Category 00: Overview (Documentation)
**Status**: Complete. 8 documentation files covering architecture, pipelines, data models, configuration.
**Gaps**: None — documentation category.
**V2 Action**: Regenerate from v2 implementation.

### Category 01: Rust Core (~65 files)
**Status**: Solid foundation with 12 subsystems.
**Critical Gaps**:
| ID | Gap | Severity | Impact |
|----|-----|----------|--------|
| RC-G1 | No incremental scanning (full rescan every time) | Critical | Performance on large codebases |
| RC-G2 | No dependency graph building (done in TS) | High | Cross-file analysis |
| RC-G3 | Parsers extract significantly less detail than TS | Critical | Feature parity |
| RC-G4 | Only ~30 AST patterns vs 350+ TS detectors | Critical | Detection coverage |
| RC-G5 | Log patterns compiled but never used | Low | Dead code |
| RC-G6 | Violation system defined but never populated | Medium | Enforcement |
| RC-G7 | Resolution stats fields are TODO | Low | Observability |
| RC-G8 | Coupling uses DFS instead of Tarjan's SCC | Medium | Correctness |
| RC-G9 | Missing cloud provider secrets (Azure, GCP, npm, PyPI) | High | Security |
| RC-G10 | No .env file parsing, no missing variable detection | Medium | Config analysis |
| RC-G11 | No error propagation chain tracking | Medium | Error analysis |
| RC-G12 | Wrapper registry is React-focused only | Medium | Framework coverage |
| RC-G13 | No cross-service reachability | High | Microservice support |
| RC-G14 | No taint analysis | High | Security analysis |

### Category 02: Parsers (~58 files)
**Status**: Dual-layer (Rust ~8K lines + TS ~10K+ lines). Functional but fragmented.
**Critical Gaps**:
| ID | Gap | Severity | Impact |
|----|-----|----------|--------|
| PA-G1 | No generic type parameter extraction in Rust | Critical | Type analysis, contracts |
| PA-G2 | No Pydantic model support in Rust | Critical | FastAPI contract detection |
| PA-G3 | Annotations extracted as strings, not structured objects | Critical | Framework pattern detection |
| PA-G4 | No full inheritance chain resolution in Rust | High | Component hierarchy |
| PA-G5 | No namespace/package extraction in Rust | High | Java, C#, PHP analysis |
| PA-G6 | No incremental parsing in Rust | Medium | IDE integration |
| PA-G7 | No AST caching in Rust | Medium | Repeated parse avoidance |
| PA-G8 | Three different ParseResult shapes | Critical | Data integrity |

### Category 03: Detectors (~350 files)
**Status**: Comprehensive coverage (350+ detectors, 16 categories, 7 framework extensions). 100% TypeScript.
**Critical Gaps**:
| ID | Gap | Severity | Impact |
|----|-----|----------|--------|
| DE-G1 | 350+ TS detectors running sequentially per file | Critical | Performance |
| DE-G2 | No incremental detection | Critical | Scan time |
| DE-G3 | Rust parity gap (~30 vs 350+ patterns) | Critical | Migration |
| DE-G4 | SemanticLearningDetector is a stub | Medium | Learning capability |
| DE-G5 | No pattern decay (old patterns never lose confidence) | High | Accuracy |
| DE-G6 | No pattern merging (similar patterns not consolidated) | Medium | Noise |
| DE-G7 | No call graph integration for cross-function analysis | High | Detection depth |
| DE-G8 | No data flow analysis | High | Security detection |
| DE-G9 | No effective false-positive tracking | Critical | Enterprise adoption |
| DE-G10 | Django only has contracts — no learning/semantic | Medium | Framework coverage |
| DE-G11 | Go/Rust/C++ only have api+auth+errors | Medium | Framework coverage |
| DE-G12 | No GraphQL/gRPC contract detection | High | Modern API support |

### Category 04: Call Graph (~53 files)
**Status**: Dual-layer. TS has rich extraction, Rust has high-performance building.
**Critical Gaps**:
| ID | Gap | Severity | Impact |
|----|-----|----------|--------|
| CG-G1 | Rust has only UniversalExtractor — no per-language extractors | Critical | Extraction quality |
| CG-G2 | Impact analysis, dead code, coverage not in Rust | High | Analysis capability |
| CG-G3 | Rust has 3 resolution strategies vs 6 in TS | High | Resolution rate |
| CG-G4 | No incremental builds (full rebuild every time) | Critical | Performance |
| CG-G5 | No taint analysis | High | Security |
| CG-G6 | No cross-service reachability | High | Microservices |
| CG-G7 | No polymorphism support in Rust | Medium | OOP languages |
| CG-G8 | No DI resolution in Rust | High | Framework support |
| CG-G9 | Resolution rate only 60-85% | Medium | Accuracy |
| CG-G10 | Duplicate type definitions between call_graph and reachability modules | Medium | Maintenance |

### Category 05: Analyzers (~22K lines)
**Status**: Fragmented dual implementation. TS has full features, Rust has basic metrics.
**Critical Gaps**:
| ID | Gap | Severity | Impact |
|----|-----|----------|--------|
| AN-G1 | Core analyzers (AST, Type, Semantic, Flow) are 100% TS | High | Performance |
| AN-G2 | No incremental analysis | Critical | Scan time |
| AN-G3 | Type Analyzer is TS-only — no Rust implementation | Medium | Cross-language types |
| AN-G4 | Semantic Analyzer only handles TS/JS | Medium | Language coverage |
| AN-G5 | Flow Analyzer has no interprocedural analysis | High | Data flow depth |
| AN-G6 | Secret detection missing Azure, GCP, npm, PyPI tokens | High | Security |
| AN-G7 | Wrapper detection React-focused only | Medium | Framework coverage |
| AN-G8 | Coupling analysis feature gap (Rust missing refactor impact, zones) | Medium | Analysis depth |
| AN-G9 | Unified Provider 20 ORM matchers are TS-only | High | Data access detection |
| AN-G10 | Rules Engine not parallelized | Medium | Performance |
| AN-G11 | No cross-file data flow | High | Security analysis |
| AN-G12 | No taint tracking | High | Vulnerability detection |

### Category 06: Cortex Memory (~150 files)
**Status**: Comprehensive AI memory system. 100% TypeScript. 23 memory types, 18 subsystems.
**Critical Gaps**:
| ID | Gap | Severity | Impact |
|----|-----|----------|--------|
| CX-G1 | 384-dim vectors from Transformers.js — not code-optimized | High | Retrieval quality |
| CX-G2 | No hybrid search (vector-only, no FTS + RRF) | High | Retrieval precision |
| CX-G3 | Consolidation is LLM-dependent — no air-gapped fallback | Medium | Offline operation |
| CX-G4 | Token estimation is approximate (string length, not tokenizer) | Medium | Budget accuracy |
| CX-G5 | Only 10 PII/secret patterns | High | Privacy compliance |
| CX-G6 | No graph-based memory representation | Medium | Multi-hop reasoning |
| CX-G7 | Causal inference is heuristic — no formal causal model | Medium | Reasoning quality |
| CX-G8 | No memory versioning (updated in-place) | Medium | Audit trail |
| CX-G9 | Prediction cache TTL is static (5 min) | Low | Efficiency |
| CX-G10 | Single-node only — no distributed memory | High | Team collaboration |
| CX-G11 | No memory importance auto-reclassification | Low | Memory quality |
| CX-G12 | Fixed 384-dim embeddings — cannot leverage higher-dim models | Medium | Future-proofing |

### Category 07: MCP Server (~90 files)
**Status**: Functional with 87+ tools. Monolithic architecture.
**Critical Gaps**: See AUDIT FINDING A5 above.
**Additional**:
| ID | Gap | Severity | Impact |
|----|-----|----------|--------|
| MC-G1 | Tool definitions consume ~15-20K tokens | Critical | Token efficiency |
| MC-G2 | No progressive disclosure | High | AI agent usability |
| MC-G3 | Monolithic server (analysis + memory in one) | High | Separation of concerns |
| MC-G4 | No streaming responses for large result sets | Medium | Large codebase support |

### Category 08: Storage (~35 files)
**Status**: 6 fragmented backends. See AUDIT FINDING A4 above.
**Additional**:
| ID | Gap | Severity | Impact |
|----|-----|----------|--------|
| ST-G1 | No connection pooling | Medium | Concurrent access |
| ST-G2 | No prepared statement caching | Medium | Query performance |
| ST-G3 | No keyset pagination (uses OFFSET/LIMIT) | Medium | Scale |
| ST-G4 | No schema versioning in Rust | High | Migration safety |
| ST-G5 | No cross-database queries (drift.db ↔ cortex.db isolated) | Medium | Unified queries |
| ST-G6 | No retention policies (history grows unbounded) | Medium | Disk usage |
| ST-G7 | No data integrity validation | High | Reliability |

### Category 09: Quality Gates (~30 files)
**Status**: Comprehensive 6-gate system with policy engine. 100% TypeScript.
**Critical Gaps**:
| ID | Gap | Severity | Impact |
|----|-----|----------|--------|
| QG-G1 | JSON-based snapshot storage (not SQLite) | Medium | Consistency |
| QG-G2 | No CWE ID mapping in SARIF output | High | Compliance |
| QG-G3 | No inline fix suggestions in PR annotations | Medium | Developer experience |
| QG-G4 | No KPI dashboard (compliance rate, drift velocity) | Medium | Enterprise visibility |
| QG-G5 | Parallel executor has no dependency ordering | Low | Gate dependencies |

### Category 10: CLI (~50 files)
**Status**: Comprehensive 50+ commands via Commander.js.
**Critical Gaps**:
| ID | Gap | Severity | Impact |
|----|-----|----------|--------|
| CL-G1 | Node.js required for all commands | Medium | Distribution |
| CL-G2 | Piscina worker threads instead of rayon | Medium | Performance |
| CL-G3 | No incremental scan command | Critical | Developer workflow |

### Category 11: IDE (~40 files)
**Status**: VSCode extension with phased activation, LSP, decorations.
**Critical Gaps**:
| ID | Gap | Severity | Impact |
|----|-----|----------|--------|
| ID-G1 | Heavy computation in TS (not leveraging Rust core) | High | Performance |
| ID-G2 | No real-time pattern violation highlighting | Medium | Developer experience |

### Category 12: Infrastructure (~30 files)
**Status**: Monorepo with pnpm + Turborepo. NAPI-RS cross-compilation.
**Gaps**: Mostly operational — CI/CD, Docker, telemetry are functional.

### Category 13: Advanced Systems (~45 files)
**Status**: DNA (10 genes), Simulation Engine, Decision Mining, Language Intelligence. 100% TypeScript.
**Critical Gaps**:
| ID | Gap | Severity | Impact |
|----|-----|----------|--------|
| AV-G1 | DNA gene extractors are regex-based (not AST) | Medium | Accuracy |
| AV-G2 | Simulation Engine is enterprise-only but core to value prop | Medium | Adoption |
| AV-G3 | Decision Mining requires git history (slow for large repos) | Medium | Performance |
| AV-G4 | Language Intelligence covers only 5 frameworks | Medium | Coverage |

### Categories 14-16: Documentation
**Status**: Directory maps, migration strategy, gap analysis. Documentation only.
**V2 Action**: Regenerate from v2 implementation.

### Category 17: Test Topology (~15 files)
**Status**: Dual-layer. Rust detects 10 frameworks, TS detects 35+.
**Critical Gaps**: No quality scoring in Rust, no minimum test set calculation, no call-graph-based coverage.

### Category 18: Constraints (~8 files)
**Status**: 12 invariant types, 10 categories. 100% TypeScript.
**Critical Gaps**:
| ID | Gap | Severity | Impact |
|----|-----|----------|--------|
| CN-G1 | Regex-based verification (duplicates parser work) | High | Performance, accuracy |
| CN-G2 | No AST-based verification | Critical | Structural checks |
| CN-G3 | No call graph integration in verifier | Critical | Ordering constraints |
| CN-G4 | No data flow integration | High | Data flow constraints |
| CN-G5 | No cross-file verification | High | Module-level invariants |
| CN-G6 | JSON file storage (no ACID) | Medium | Reliability |

### Categories 19-22: Specialized Analysis
**Error Handling (19)**: 4-phase analysis, boundary detection. Gap: no propagation chains in Rust.
**Contracts (20)**: REST-only. Gap: no GraphQL, no gRPC, no OpenAPI spec parsing.
**Security (21)**: 28+ ORMs, sensitive data detection. Gap: no taint analysis, limited PII patterns.
**Context Generation (22)**: Powers drift_context. Gap: no adaptive budgeting, no quality metrics.

### Categories 23-26: Data Infrastructure
**Pattern Repository (23)**: Repository + Service pattern. 5 implementations. Gap: no event sourcing.
**Data Lake (24)**: DEPRECATED for v2. Concepts preserved as SQLite views.
**Services Layer (25)**: Piscina worker pools. Gap: should be rayon in v2.
**Workspace (26)**: Project lifecycle. Gap: no SQLite backup API usage, no retention policies.


---

## 4. Cross-Cutting Concerns

### CC1: Incrementality Is Missing Everywhere
**Severity**: Critical
**Affected Categories**: 01, 02, 03, 04, 05, 08, 09, 17, 18, 19, 20, 21
**Finding**: Every subsystem performs full re-analysis on every scan. No content-hash-based change detection, no dependency tracking for selective re-analysis, no cached intermediate results.
**Impact**: Scan times scale linearly with codebase size. A 100K-file codebase takes 10-30x longer than necessary.
**V2 Action**: Incremental-first architecture (AD1). Content-hash-based file index. Dependency graph for selective re-analysis. Persistent cache across restarts.

### CC2: No Unified Error Handling Strategy
**Severity**: High
**Affected Categories**: All Rust subsystems
**Finding**: Error handling in Rust code is inconsistent. Some subsystems use `Result<T, String>`, others use custom error types, some use `anyhow`. No structured error propagation through NAPI to TypeScript.
**V2 Action**: `thiserror` for all error types. One error enum per subsystem. Structured error propagation through NAPI.

### CC3: No Observability Infrastructure
**Severity**: High
**Affected Categories**: All
**Finding**: No structured logging, no metrics collection, no performance tracing. Cannot answer: "How long does parsing take per language?", "What's the cache hit rate?", "Which detectors are slowest?"
**V2 Action**: `tracing` crate for structured logging. Metrics collection for key operations. Performance counters exposed via NAPI.

### CC4: No Configuration Validation
**Severity**: Medium
**Affected Categories**: 01, 03, 06, 09, 13
**Finding**: Configuration is scattered across JSON files, environment variables, and hardcoded defaults. No schema validation, no type safety, no migration path for config changes.
**V2 Action**: Single configuration schema (TOML). Validated at startup. Versioned with migration support.

### CC5: Testing Strategy Is Inconsistent
**Severity**: Medium
**Affected Categories**: All
**Finding**: Rust has inline `#[cfg(test)]` tests. TS has Jest/Vitest tests in `__tests__/` directories. No integration tests spanning Rust ↔ TS boundary. No property-based tests for statistical algorithms. No benchmark tests for performance regression.
**V2 Action**: Rust unit tests + integration tests. Property-based tests for confidence scoring, outlier detection. Benchmark tests for parser, detector, call graph performance. NAPI bridge integration tests.

### CC6: No Telemetry or Usage Analytics
**Severity**: Low (but important for enterprise)
**Affected Categories**: 07, 10, 12
**Finding**: Cloudflare Workers telemetry exists but is minimal. No usage analytics for MCP tools (which tools are used most?), no scan performance tracking, no error rate monitoring.
**V2 Action**: Optional telemetry with clear opt-in. Track: scan duration, file count, pattern count, MCP tool usage, error rates.

---

## 5. Data Model Inconsistencies

### DM1: Pattern Type Has Multiple Definitions
**Locations**: Rust `DetectedPattern`, TS `Pattern`, NAPI `JsDetectedPattern`, SQLite `patterns` table
**Issue**: 4 different representations of the same concept. Fields differ across representations.
**V2 Action**: Single canonical `Pattern` type in Rust. All other representations derived from it.

### DM2: FunctionNode Has Duplicate Definitions
**Locations**: TS `FunctionNode` (call graph), Rust `FunctionEntry` (call graph), Rust `FunctionNode` (reachability)
**Issue**: 3 different representations. Reachability module has its own types separate from call graph module.
**V2 Action**: Single `FunctionEntry` type in Rust. Reachability operates on the same type.

### DM3: Confidence Scoring Weights Disagree
**Locations**: Documentation says 0.35/0.25/0.15/0.25, code uses 0.4/0.3/0.15/0.15
**Issue**: Documentation and implementation disagree. No single source of truth.
**V2 Action**: Code is authoritative. Document the actual weights. Add momentum factor (0.15) for v2.

### DM4: Violation Type Is Underspecified
**Locations**: Rust `Violation` (defined but never populated), TS `Violation` (fully implemented), TS `GateViolation` (quality gates)
**Issue**: Rust violation system is dead code. TS has two different violation types for different contexts.
**V2 Action**: Single `Violation` type in Rust. Quality gate violations extend base violation with gate-specific fields.

### DM5: Memory Types Are Overengineered
**Finding**: 23 memory types across 3 categories. Many types overlap (decision vs decision_context, insight vs semantic, preference vs tribal).
**V2 Action**: Consolidate to ~15 types. Merge overlapping types. Keep extensibility via metadata fields.

---

## 6. Performance Bottlenecks

### PB1: Sequential Detection (Critical)
**Category**: 03 (Detectors)
**Finding**: 350+ TypeScript detectors run sequentially per file. Each detector traverses the AST independently.
**Impact**: O(detectors × files × AST_size). For 10K files with 350 detectors, this is ~3.5M AST traversals.
**V2 Fix**: Single-pass visitor pattern (ESLint-style). O(files × AST_size) with O(detectors) callbacks per node.

### PB2: Full Rescan Every Time (Critical)
**Category**: 01, 03, 04, 05
**Finding**: No incremental scanning. Every scan re-parses, re-detects, re-analyzes all files.
**Impact**: Scan time proportional to total codebase size, not change size.
**V2 Fix**: Content-hash-based change detection. Only re-process changed files. Dependency graph for cascading invalidation.

### PB3: NAPI Per-Call Overhead (Medium)
**Category**: 01 (Rust Core)
**Finding**: Each NAPI call has ~0.1-1ms overhead for serialization/deserialization. With 25+ functions called per file, this adds up.
**V2 Fix**: Batch APIs (parse_batch, analyze_batch). Streaming results. Reduce round-trips.

### PB4: JSON Storage I/O (Medium)
**Category**: 08 (Storage)
**Finding**: JSON file reads are O(n) — must parse entire file to find one pattern. 50+ JSON files in .drift/.
**V2 Fix**: SQLite-only storage. O(1) index lookups. No JSON files.

### PB5: No Query Caching (Medium)
**Category**: 07, 08
**Finding**: MCP tool responses are not cached. Same query re-executes full analysis.
**V2 Fix**: Content-hash-based response cache. Invalidate on scan completion.

### PB6: Embedding Generation Bottleneck (Medium)
**Category**: 06 (Cortex)
**Finding**: Transformers.js embedding generation is slow (~50-200ms per text). Blocks memory operations.
**V2 Fix**: Rust ort crate for ONNX inference (3-5x speedup). Async generation. 3-tier cache.

---

## 7. Security Audit

### SA1: Secret Detection Coverage Gaps
**Finding**: 21 regex patterns in Rust. Missing:
- Azure keys (SharedAccessSignature, AccountKey)
- GCP service account keys (JSON with private_key)
- npm tokens (npm_*)
- PyPI tokens (pypi-*)
- Databricks tokens
- Snowflake credentials
- MongoDB connection strings with credentials
- Redis AUTH passwords
- Elasticsearch API keys
- Vault tokens
**V2 Target**: 100+ patterns with Shannon entropy scoring and contextual analysis.

### SA2: No Taint Analysis
**Finding**: Cannot track data flow from user input to security-sensitive operations (SQL queries, file operations, network calls).
**Impact**: Cannot detect SQL injection, XSS, SSRF, path traversal at the data flow level.
**V2 Target**: Intraprocedural taint tracking in Rust. Interprocedural via call graph.

### SA3: Limited PII Detection
**Finding**: Cortex privacy system has only 10 PII/secret patterns. Missing: Slack tokens, GitHub tokens, Azure keys, GCP service accounts, npm tokens, PyPI tokens, connection strings, base64-encoded secrets.
**V2 Target**: 50+ PII patterns. Connection string parsing. Base64 detection.

### SA4: No OWASP/CWE Alignment
**Finding**: Security detectors are not mapped to OWASP Top 10 or CWE IDs. SARIF output lacks CWE references.
**V2 Target**: Map all security detectors to CWE IDs. SARIF output includes CWE references. Cover 9/10 OWASP Top 10.

### SA5: No Authentication on MCP Server
**Finding**: MCP server has no authentication mechanism. Any process that can connect can query all data.
**V2 Target**: Optional authentication for MCP server. Token-based access control. Read-only vs read-write separation.

---

## 8. Reliability & Error Handling Audit

### RE1: No Transactional Guarantees Across Domains
**Finding**: JSON writes can partially fail. A crash during scan can leave patterns in SQLite but not in JSON, or vice versa.
**V2 Fix**: Single SQLite database with transactions. All-or-nothing writes.

### RE2: No Graceful Degradation for Missing Dependencies
**Finding**: If tree-sitter grammar fails to load, parser returns None. But callers don't always handle None gracefully.
**V2 Fix**: Structured error types. Explicit fallback paths. Partial results with error annotations.

### RE3: No Crash Recovery
**Finding**: If Drift crashes mid-scan, there's no recovery mechanism. Next scan starts from scratch.
**V2 Fix**: WAL mode SQLite survives crashes. Incremental index means only the interrupted file needs re-processing.

### RE4: No Data Integrity Validation
**Finding**: No periodic consistency checks between storage backends. No checksum validation on read.
**V2 Fix**: Single storage backend eliminates consistency issues. SQLite integrity_check on startup (optional).

---

## 9. Scalability Constraints

### SC1: In-Memory Call Graph Doesn't Scale
**Finding**: TS call graph loads entire graph into memory. For 100K+ function codebases, this can exceed available RAM.
**V2 Fix**: SQLite-backed graph with in-memory cache for hot paths. petgraph for analysis, SQLite for persistence.

### SC2: Single-Node Cortex
**Finding**: Cortex memory is local to one machine. Cannot share memories across team members or CI environments.
**V2 Fix**: Phase 1: local-only (same as v1). Phase 2: optional sync to shared storage (SQLite replication or export/import).

### SC3: No Pagination for Large Result Sets
**Finding**: MCP tools return all results at once. For codebases with 10K+ patterns, responses can be enormous.
**V2 Fix**: Cursor-based pagination on all list operations. Configurable page size.

### SC4: No Streaming for Long Operations
**Finding**: Scan results are returned only after full completion. No progress reporting, no partial results.
**V2 Fix**: Streaming pipeline (parse as files discovered, detect as files parsed). Progress callbacks via NAPI.

---

## 10. Integration Contract Risks

### IC1: Parser → Everything (Highest Risk)
**Finding**: Every subsystem depends on parser output. Any change to ParseResult breaks all downstream consumers.
**Risk**: Highest. A parser regression affects detectors, call graph, analyzers, boundaries, security, contracts, test topology, constraints, context generation.
**V2 Mitigation**: Versioned ParseResult. Backward-compatible additions only. Comprehensive parser regression tests.

### IC2: Detectors → Pattern Repository → MCP/Quality Gates
**Finding**: Detector output format changes cascade through pattern storage to MCP tools and quality gates.
**Risk**: High. Pattern schema changes affect 5+ downstream categories.
**V2 Mitigation**: Stable Pattern type with versioned schema. Event-sourced pattern lifecycle.

### IC3: Call Graph → Security/Test Topology/Quality Gates/Constraints
**Finding**: Call graph is consumed by 6+ downstream categories. Resolution rate changes affect all consumers.
**Risk**: High. A call graph regression affects security analysis, test coverage, impact simulation, constraint verification.
**V2 Mitigation**: Call graph API contract with guaranteed minimum resolution rate. Regression tests on resolution quality.

### IC4: Cortex → MCP (33 tools)
**Finding**: 33 MCP tools expose Cortex functionality. Any Cortex API change requires updating 33 tool implementations.
**Risk**: Medium. Cortex is relatively stable but has many consumers.
**V2 Mitigation**: Cortex facade pattern. MCP tools call facade, not internal APIs directly.

---

## 11. Missing Enterprise Features

### EF1: Multi-Repository Governance
**Status**: Not implemented
**Need**: Enterprise customers manage 100+ repositories. Need cross-repo pattern comparison, unified dashboards, centralized policy management.
**V2 Phase**: Phase 3 (post-launch)

### EF2: Team Memory Sharing
**Status**: Not implemented (Cortex is single-node)
**Need**: Team members should share institutional knowledge. CI should access the same memory as developers.
**V2 Phase**: Phase 2

### EF3: Audit Trail
**Status**: Partial (pattern history exists, but no comprehensive audit log)
**Need**: Enterprise compliance requires knowing who approved what pattern, when, and why.
**V2 Phase**: Phase 2

### EF4: Role-Based Access Control
**Status**: Not implemented
**Need**: Different team members should have different permissions (approve patterns, configure policies, view security data).
**V2 Phase**: Phase 3

### EF5: Custom Detector SDK
**Status**: Not implemented
**Need**: Enterprise customers want to write custom detectors for proprietary patterns.
**V2 Phase**: Phase 2 (declarative TOML patterns), Phase 3 (programmatic SDK)

### EF6: Compliance Reporting
**Status**: Partial (SARIF output exists)
**Need**: SOC 2, ISO 27001, HIPAA compliance reports showing security posture over time.
**V2 Phase**: Phase 3

---

## 12. Technical Debt Inventory

| ID | Debt | Category | Severity | Effort to Fix |
|----|------|----------|----------|---------------|
| TD1 | Log patterns compiled but never used | 01 | Low | 1 hour |
| TD2 | Violation system defined but never populated | 01 | Medium | 1 day |
| TD3 | Resolution stats fields are TODO | 01 | Low | 2 hours |
| TD4 | SemanticLearningDetector is a stub | 03 | Medium | 1 week |
| TD5 | Custom match strategy defined but not implemented | 03 | Low | 2 days |
| TD6 | Confidence weight discrepancy (docs vs code) | 03 | Low | 1 hour |
| TD7 | Duplicate type definitions (call graph vs reachability) | 04 | Medium | 1 day |
| TD8 | JSON shard duplication (patterns in SQLite AND JSON) | 08 | High | 1 week |
| TD9 | Hybrid stores (transitional bridges) | 08 | High | 3 days |
| TD10 | SyncService 11-domain bidirectional sync | 08 | High | Remove entirely |
| TD11 | Data Lake JSON implementation | 08 | High | Replace with SQLite views |
| TD12 | 50+ JSON files in .drift/ | 08 | Medium | Consolidate to SQLite |
| TD13 | category-connections.md duplicate file | Meta | Low | Delete one |

---

## 13. Decision Register

Decisions that MUST be made before v2 code is written:

| ID | Decision | Options | Recommendation | Impact |
|----|----------|---------|----------------|--------|
| D1 | FFI approach | NAPI (thicker) vs Rust CLI with JSON IPC | NAPI — lower latency, richer types | All subsystems |
| D2 | Incremental strategy | Salsa framework vs custom content-hash | Custom content-hash (simpler, sufficient) | All subsystems |
| D3 | Pattern definition format | TOML vs YAML vs JSON | TOML (Rust-native, readable, typed) | Detectors, MCP |
| D4 | Cortex ownership | Rust vs TypeScript | TypeScript (LLM-dependent features) | Memory system |
| D5 | MCP server split | 2 servers vs 1 with namespaces | 2 servers (token efficiency, security) | MCP, IDE |
| D6 | Embedding model | Transformers.js vs ort (ONNX) vs API | ort for local, API optional | Cortex |
| D7 | Graph library | petgraph vs custom | petgraph (mature, well-tested) | Call graph, Cortex |
| D8 | String interning | Custom vs lasso crate | lasso (ThreadedRodeo for build, RodeoReader for query) | All Rust |
| D9 | Error handling | anyhow vs thiserror | thiserror (structured, typed) | All Rust |
| D10 | Configuration format | TOML vs YAML | TOML (Rust-native) | All subsystems |
| D11 | Cache library | Custom vs moka | moka (production-proven, async) | Parser, MCP |
| D12 | Parallel execution | rayon vs tokio | rayon for CPU-bound, tokio for I/O-bound | All Rust |

---

## 14. Risk Matrix

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| Parser regression breaks all downstream | Medium | Critical | Versioned ParseResult, comprehensive tests |
| Rust migration takes longer than estimated | High | High | Prioritize P0 features, keep TS fallback |
| MCP spec changes break tool definitions | Low | High | Abstract MCP layer, version tool schemas |
| SQLite performance insufficient for 1M+ files | Low | High | Benchmark early, have PostgreSQL escape hatch |
| Embedding model quality insufficient | Medium | Medium | Pluggable provider, benchmark on code retrieval |
| Enterprise customers need features not in Phase 1 | High | Medium | Clear roadmap, Phase 2/3 planning |
| Cross-platform build failures (7 targets) | Medium | Medium | CI matrix testing, NAPI-RS handles most |
| Memory usage exceeds limits on large codebases | Medium | High | SQLite-backed everything, streaming pipelines |

---

## 15. V2 Non-Negotiables

These are the absolute minimum requirements for v2 to be considered enterprise-grade:

1. **Incremental scanning** — Must not re-analyze unchanged files
2. **Single canonical data model** — One ParseResult, one Pattern, one FunctionEntry
3. **100+ secret detection patterns** — With Shannon entropy and contextual scoring
4. **Visitor pattern detection** — Single-pass AST traversal, not per-detector
5. **Feedback loop** — Effective false-positive tracking, developer action → confidence adjustment
6. **Split MCP servers** — Analysis + Memory, progressive disclosure
7. **SQLite-only storage** — No JSON files, no hybrid stores, no sync services
8. **Structured error handling** — thiserror everywhere, meaningful errors through NAPI
9. **OWASP/CWE alignment** — Security detectors mapped to standards
10. **Temporal confidence** — Momentum scoring, pattern decay, evolution tracking
11. **Hybrid search in Cortex** — FTS5 + sqlite-vec with RRF fusion
12. **Code-specific embeddings** — Not general-purpose 384-dim vectors
13. **Declarative pattern definitions** — TOML/YAML, not hardcoded
14. **GraphQL + gRPC contracts** — Not REST-only
15. **Taint analysis foundation** — At minimum intraprocedural

---

## Audit Completeness Checklist

- [x] All 27 categories inventoried
- [x] Architecture audit with 5 critical findings
- [x] Category-by-category gap analysis with 80+ identified gaps
- [x] 6 cross-cutting concerns documented
- [x] 5 data model inconsistencies identified
- [x] 6 performance bottlenecks cataloged
- [x] 5 security audit findings
- [x] 4 reliability concerns
- [x] 4 scalability constraints
- [x] 4 integration contract risks assessed
- [x] 6 missing enterprise features
- [x] 13 technical debt items inventoried
- [x] 12 architectural decisions requiring resolution
- [x] 8 risks in risk matrix
- [x] 15 v2 non-negotiables defined
