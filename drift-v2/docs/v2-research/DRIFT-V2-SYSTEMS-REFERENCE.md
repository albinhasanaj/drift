# Drift v2 — Complete Systems Reference

> Single-source reference of every system, algorithm, data model, and infrastructure detail across all 26 v2-research categories.
> No source code — just what exists, how it works, and what v2 needs.
> Generated from 165+ documentation files across the full v2-research audit.

---

## Table of Contents

1. [Core Architecture](#1-core-architecture)
2. [Parsing Layer](#2-parsing-layer)
3. [Scanner](#3-scanner)
4. [Detector System](#4-detector-system)
5. [Pattern System](#5-pattern-system)
6. [Confidence Scoring & Outlier Detection](#6-confidence-scoring--outlier-detection)
7. [Call Graph](#7-call-graph)
8. [Security & Boundaries](#8-security--boundaries)
9. [Reachability Analysis](#9-reachability-analysis)
10. [Analyzers (AST, Type, Semantic, Flow)](#10-analyzers)
11. [Language Intelligence](#11-language-intelligence)
12. [Rules Engine](#12-rules-engine)
13. [Constraints System](#13-constraints-system)
14. [Error Handling Analysis](#14-error-handling-analysis)
15. [Test Topology](#15-test-topology)
16. [Gap Analysis — What's Missing from v2-Research Docs](#16-gap-analysis--whats-missing-from-v2-research-docs)
17. [Contract Tracking](#17-contract-tracking)
18. [DNA System](#18-dna-system)
19. [Decision Mining](#19-decision-mining)
20. [Simulation Engine](#20-simulation-engine)
21. [Module Coupling](#21-module-coupling)
22. [Constants & Environment](#22-constants--environment)
23. [Cortex Memory System](#23-cortex-memory-system)
24. [MCP Server](#24-mcp-server)
25. [Context Generation](#25-context-generation)
26. [Quality Gates](#26-quality-gates)
27. [Storage](#27-storage)
28. [Data Lake (Deprecated → SQLite)](#28-data-lake)
29. [Pattern Repository](#29-pattern-repository)
30. [Services Layer](#30-services-layer)
31. [CLI](#31-cli)
32. [IDE Integration](#32-ide-integration)
33. [Workspace Management](#33-workspace-management)
34. [Infrastructure & Build](#34-infrastructure--build)
35. [Licensing & Feature Gating](#35-licensing--feature-gating)
36. [Telemetry](#36-telemetry)
37. [v2 Migration Strategy](#37-v2-migration-strategy)
38. [Critical Algorithms Reference](#38-critical-algorithms-reference)

---

## 1. Core Architecture

**Thesis**: Offline indexing + online querying. Scan once with tree-sitter AST + regex, store in SQLite, expose via MCP. AI gets curated context in ~2000 tokens instead of 50,000.

**Layers** (strict dependency — no circular):
1. **Foundation**: Parsers, Storage
2. **Analysis**: Detectors, Call Graph, Boundaries, Constants, Environment, DNA, etc.
3. **Intelligence**: Patterns (aggregated), Cortex, Constraints, Test Topology
4. **Enforcement**: Rules Engine, Quality Gates, Audit
5. **Presentation**: MCP, CLI, VSCode, Dashboard

**Current Implementation**:
- Rust (~65 files): Scanner, parsers (10 languages), call graph builder, boundary detection, coupling, reachability, constants, environment, wrappers, test topology, error handling
- TypeScript (~500+ files): Detectors (350+), TS-side parsers, call graph extractors, core analyzers, pattern matching, storage orchestration, language intelligence
- Stays TS forever: CLI, MCP server, VSCode extension, Dashboard, Cortex AI orchestration, Simulation engine

**Monorepo**: pnpm 8 + Turborepo. 2 Rust crates + 12 TypeScript packages.

---

## 2. Parsing Layer

**Location**: `crates/drift-core/src/parsers/` (Rust), `packages/core/src/parsers/` (TS)

**Languages**: TypeScript, JavaScript, Python, Java, C#, PHP, Go, Rust, C, C++ (10 total)

**Extraction per file**: Functions, classes, imports, exports, call sites, decorators, type annotations, doc comments.

**Rust parsers** (9 files): tree-sitter primary. Each parser has S-expression queries for function/class/import/export/call extraction. Missing vs TS: decorator/annotation extraction, generic type parameters, inheritance chains, access modifiers, namespace/package info, framework-specific constructs.

**TS parsers**: `BaseParser` abstract class (20+ methods), `ParserManager` with LRU cache + incremental parsing + language detection. Tree-sitter loaders for 7 languages. Pydantic v1/v2 model extraction (9 files).

**NAPI bridge**: `parse(filePath, content, language)` → `JsParseResult` with functions[], classes[], imports[], exports[], calls[], errors[].

**Key types**:
- `JsFunctionInfo`: name, qualifiedName, parameters[], returnType, isExported, isAsync, startLine, endLine, decorators[], docComment
- `JsClassInfo`: name, extends, implements[], isExported, startLine, endLine, decorators[], properties[]
- `JsImportInfo`: source, named[], default, namespace, isTypeOnly, line
- `JsCallSite`: callerName, calleeName, line, column, isAsync, isDynamic

**v2**: Consolidate to Rust-only. Add decorator/annotation extraction, generic types, inheritance chains, framework constructs.

---

## 3. Scanner

**Location**: `crates/drift-core/src/scanner/` (Rust), `packages/core/src/scanner/` (TS)

**Rust scanner**: Parallel file walking via `rayon` + `walkdir`. Respects `.gitignore` + `.driftignore`. Content hashing via `xxhash-rust` (xxh3). Returns `JsScanResult` with files[], stats, errors[].

**Config**: root, patterns[], extraIgnores, computeHashes, maxFileSize (default 1MB), threads.

**TS scanner**: `FileWalker` (sequential), `NativeScanner` (wraps Rust NAPI), `ChangeDetector` (incremental via content hash), `WorkerPool`/`ThreadedWorkerPool` (Piscina).

**Default ignores**: node_modules, .git, dist, build, coverage, __pycache__, .venv, target, vendor, etc.

**v2**: Rust scanner becomes the only scanner. TS worker pool eliminated (Rust rayon handles parallelism).

---

## 4. Detector System

**Location**: `packages/detectors/` — 350+ files, 100% TypeScript

**16 Categories**: security, auth, errors, api, components, config, contracts, data-access, documentation, logging, performance, structural, styling, testing, types, accessibility.

**3 Variants per category**:
- **Base** — Fast regex/AST matching. Deterministic.
- **Learning** — Adapts to codebase conventions. Learns dominant pattern, flags deviations.
- **Semantic** — Deep AST analysis with context awareness.

**7 Base classes**: `BaseDetector`, `BaseLearningDetector`, `BaseSemanticDetector`, `BaseASTDetector`, `BaseRegexDetector`, `BaseStructuralDetector`, `BaseCompositeDetector`.

**Registry**: Central detector registry with category mapping, language filtering, critical-only mode.

**Learning system defaults**:
- Min occurrences: 3
- Dominance threshold: 0.60 (60% must use same convention)
- Min files: 2
- Max files to analyze: 1000
- Learned patterns expire after 24 hours
- Stored in `.drift/learned/{detector-id}.json`

**Detection output**: `PatternMatch[]` per detector per file, with patternId, detectorId, category, confidence, location (file, line, column, endLine, endColumn), isOutlier, matchedText, metadata.

**v2**: All detectors move to Rust. Trait-based detector system (base → learning → semantic). Port all regex patterns (data, not logic). Create Rust detector registry.

---

## 5. Pattern System

**The central entity**. A Pattern represents a discovered convention.

**Unified type** (15 categories, 3 statuses):

- **Categories**: security, auth, errors, api, components, config, contracts, data-access, documentation, logging, performance, structural, styling, testing, types, accessibility
- **Statuses**: `discovered` → `approved` | `ignored`
- **Detection methods**: ast, regex, semantic, structural, custom

**Pattern data model**:
- Identity: 16-char hex ID (hash of detectorId + patternId), subcategory, name, description
- Scoring: `ConfidenceScore` (frequency, consistency, age, spread, composite score, level)
- Locations: `PatternLocation[]` — file, line, column, isOutlier, confidence, outlierReason
- Classification: severity (error/warning/info/hint), autoFixable
- Metadata: firstSeen, lastSeen, source (auto-detected/user-defined/learned), tags[]
- Detector reference: detectorId (e.g. "security/sql-injection"), patternId with context suffix (/unknown, /assignment, /conditional, /property_access, /import, /call)

**Pattern definition** (matching config):
- `ASTMatchConfig`: nodeType, query (tree-sitter syntax), properties, children[], matchDescendants, minDepth, maxDepth
- `RegexMatchConfig`: pattern, flags, captureGroups, multiline, contextLines
- `StructuralMatchConfig`: pathPattern, directoryPattern, namingPattern (PascalCase/camelCase/kebab-case/snake_case/SCREAMING_SNAKE), requiredSiblings, parentStructure, extension

**Pattern matching engine** (`PatternMatcher`):
- Multi-strategy: routes to AST, regex, or structural matching based on `matchType`
- LRU cache (1000 entries, 60s TTL, keyed by `file:patternId`, validated by content hash)
- AST matching: depth-first traversal, confidence = matchedChecks / totalChecks × childConfidence
- Regex matching: global regex.exec() loop, confidence always 1.0 (binary match)
- Structural matching: all checks AND'd (path, directory, naming, extension, siblings, parents), confidence 1.0 or 0.0
- Batch matching: `matchAll(context, patterns[])` runs all patterns against one file

**Detection pipeline** (8 phases):
1. File scanning — parallel walk, .gitignore + .driftignore, content hashing for incremental
2. Parsing — tree-sitter per language, extract functions/classes/imports/exports/calls/decorators/types
3. Detection — per file × per detector, filtered by language + categories, parallelizable
4. Aggregation — group by pattern ID, deduplicate by location key (file:line:column), merge across files
5. Confidence scoring — weighted composite (see Section 6)
6. Outlier detection — statistical deviation analysis (see Section 6)
7. Storage — SQLite transaction + JSON shards (v1), SQLite-only (v2)
8. Violation generation — outlier locations → violations, missing patterns → info violations, quick fixes

**Storage**: SQLite tables (`patterns`, `pattern_locations`, `pattern_variants`, `pattern_examples`, `pattern_history`) + JSON shards (one per category in `.drift/patterns/`). 7 indexes. Integrity checksums per shard. v2 drops JSON entirely.

**v2**: All detectors move to Rust. Trait-based system. Port regex patterns as data. Create Rust detector registry. SQLite-only storage.

---

## 6. Confidence Scoring & Outlier Detection

### Confidence Scoring

**Algorithm**: `score = frequency × 0.40 + consistency × 0.30 + ageFactor × 0.15 + spread × 0.15`

All factors normalized to [0.0, 1.0]. Weighted sum clamped to [0.0, 1.0]. Weights must sum to 1.0 (±0.001 tolerance).

**Factor calculations**:
- **Frequency** (weight 0.40): `occurrences / totalLocations`. Clamped [0, 1].
- **Consistency** (weight 0.30): `1 - variance`. Inverted variance — higher = more uniform.
- **Age factor** (weight 0.15): Linear scale from `minAgeFactor` (0.1) to 1.0 over `maxAgeDays` (30). Brand new = 0.1, ≥30 days = 1.0. Formula: `minAgeFactor + (daysSinceFirstSeen / maxAgeDays) × (1.0 - minAgeFactor)`.
- **Spread** (weight 0.15): `fileCount / totalFiles`. Clamped [0, 1].

**Confidence levels**:

| Level | Threshold | Meaning |
|-------|-----------|---------|
| high | ≥ 0.85 | Well-established, safe to enforce |
| medium | ≥ 0.70 | Likely pattern, worth flagging |
| low | ≥ 0.50 | Emerging, informational |
| uncertain | < 0.50 | Not enough evidence |

### Outlier Detection

**Detection flow**: Receive matches → convert to numeric data points → select method by sample size → run statistical + rule-based detection → merge, deduplicate → return result.

**Configuration defaults**: minSampleSize=3, zScoreThreshold=2.0, iqrMultiplier=1.5, sensitivity=0.7.

**Sensitivity adjustment**: `adjustedThreshold = baseThreshold × (1 + (1 - sensitivity))`. Sensitivity 1.0 = strictest, 0.0 = most lenient.

**Method 1 — Z-Score** (n ≥ 30):
- `zScore = (value - mean) / stdDev`
- Outlier if `|zScore| > adjustedThreshold`
- Significance: |z| > 3.0 = high, > 2.5 = medium, > 2.0 = low
- Deviation score: `min(1.0, (|zScore| - threshold) / threshold)`

**Method 2 — IQR** (n < 30):
- `IQR = Q3 - Q1`, `lowerBound = Q1 - multiplier × IQR`, `upperBound = Q3 + multiplier × IQR`
- Outlier if value outside bounds
- Significance by normalized distance from bound: > 3.0 = high, > 2.0 = medium, > 1.0 = low
- Deviation score: `clamp(normalizedDistance / 3, 0, 1)`

**Method 3 — Rule-based**: Custom rules registered with the detector. Each rule has an ID, check function, reason, and significance level.

**Outlier types**: structural, syntactic, semantic, stylistic, missing, extra, inconsistent.

**v2**: Pure math — trivially portable to Rust. Consider SIMD for batch scoring.

---

## 7. Call Graph

**Scope**: Maps every function call relationship in the codebase. Backbone of reachability, impact, dead code, and test coverage analysis.

**Languages**: TypeScript, JavaScript, Python, Java, C#, PHP, Go, Rust, C++ (9 total).

**Hybrid extraction**: Tree-sitter primary, regex fallback for robustness. Per-language extractors (8 languages × 3 variants in TS: standard, hybrid, data-access). Rust has a single `UniversalExtractor` (language-agnostic via normalized `ParseResult`).

**Extraction output per file**: `FileExtractionResult` — functions[], calls[], imports[], classes[]. Each function has: name, qualifiedName, startLine, endLine, parameters, returnType, className, isExported, isConstructor, isAsync, decorators[].

**Call resolution** (6 strategies, in order):

| Strategy | Confidence | Description |
|----------|-----------|-------------|
| Same-file | High | Function defined in same file |
| Method call | High | Resolved via class/receiver type |
| DI injection | Medium-High | FastAPI Depends, Spring @Autowired (TS only) |
| Import-based | Medium | Follow import chains |
| Export-based | Medium | Match exported names |
| Fuzzy | Low | Name similarity for dynamic calls |

Resolution rate: typically 60-85%.

**Dual storage**:
- Legacy JSON: `.drift/lake/callgraph/` — entire graph serialized. Deprecated.
- SQLite (current): `callgraph.db` with tables `functions`, `call_edges`, `data_access`, `metadata`. 6 indexes.

**Rust streaming builder**: Parallel file walking via rayon → parse with tree-sitter → extract via UniversalExtractor → send FunctionBatch to ParallelWriter (dedicated writer thread via MPSC channel) → batch inserts in transactions → resolution pass. Config: `batch_size=100`, WAL mode, 64MB cache, 256MB mmap.

**Analysis engines** (TS):
- **GraphBuilder**: 6-strategy resolution, entry point detection (route decorators, controllers, exported handlers, main), data accessor identification
- **ReachabilityEngine**: Forward BFS ("what data can this code reach?"), inverse BFS ("who can reach this data?"), path finding between any two functions
- **ImpactAnalyzer**: Transitive caller analysis, risk scoring (affected functions × entry points × sensitive data × depth)
- **DeadCodeDetector**: Functions never called, with false positive filtering (entry points, framework hooks, dynamic dispatch, event handlers, exported)
- **CoverageAnalyzer**: Integrates call graph with test topology for field-level coverage
- **PathFinder**: BFS with path tracking between any two functions

**Rust reachability**: Two engines — `ReachabilityEngine` (in-memory BFS, fast) and `SqliteReachabilityEngine` (SQL-backed, scalable). Both support forward/inverse reachability with sensitivity classification (PII, credentials, financial, health).

**NAPI bridge**: 10 functions — build_call_graph, is_call_graph_available, get_stats, get_entry_points, get_data_accessors, get_callers, get_file_callers, analyze_reachability (×2 for in-memory/SQLite), analyze_inverse_reachability (×2).

**Consumers**: Test topology, error handling, constraints, quality gates, module coupling, security boundaries, MCP tools.

**v2**: Per-language hybrid extractors in Rust. Impact/dead code/coverage analysis in Rust. Deprecate JSON storage. Unified resolution algorithm.

---

## 8. Security & Boundaries

**Core question**: "What sensitive data can this code reach?"

**Two-phase approach**: Learn-then-detect. `DataAccessLearner` scans codebase first to discover frameworks, table names, naming conventions, variable-to-table mappings. Then `BoundaryScanner` uses learned patterns + regex fallback for detection.

**ORM support** (28+ frameworks across 8 languages):
- C#: EF Core, Dapper
- Python: Django, SQLAlchemy, Tortoise, Peewee
- TypeScript/JS: Prisma, TypeORM, Sequelize, Drizzle, Knex, Mongoose, Supabase
- Java: Spring Data, Hibernate, jOOQ, MyBatis
- PHP: Eloquent, Doctrine
- Go: GORM, sqlx, Ent, Bun
- Rust: Diesel, SeaORM, tokio-postgres, rusqlite
- Generic: Raw SQL

**Dedicated field extractors** (7): Prisma, Django, SQLAlchemy, Supabase, GORM, Diesel, Raw SQL.

**Sensitive field detection** (Rust implementation):

| Category | Examples | Specificity Range |
|----------|---------|-------------------|
| PII | ssn (0.95), social_security (0.95), date_of_birth (0.9), email (0.65) | 0.5–0.95 |
| Credentials | password_hash (0.95), api_key (0.9), access_token (0.85) | 0.7–0.95 |
| Financial | credit_card (0.95), cvv (0.95), bank_account (0.9), salary (0.85) | 0.8–0.95 |
| Health | medical_record (0.95), diagnosis (0.9), prescription (0.9) | 0.9–0.95 |

**False positive filtering**: Reduces confidence for function names containing sensitive words, import statements, comments, mock/test/dummy prefixed names, health_check/health_endpoint.

**Confidence breakdown** (5 weighted factors):
- tableNameFound (0.3), fieldsFound (0.2), operationClear (0.2), frameworkMatched (0.2), fromLiteral (0.1)

**Security prioritization** (4 tiers): Critical (credentials, financial), High (PII, health), Medium (general data with sensitive fields), Low (standard data access).

**Boundary rules**: Per-table allowed/denied files (glob patterns), allowed operations, requireAuth flag. Violations: unauthorized_file, unauthorized_operation, missing_auth.

**v2**: Boundary scanning to Rust (10-50x speedup). Sensitive field detection already in Rust — expand. Reachability via Rust with SQLite CTEs. Field extractors to Rust tree-sitter.

---

## 9. Reachability Analysis

**Two engines** (Rust):

**In-memory** (`ReachabilityEngine`): BFS through `CallGraph` HashMap. Fast for small-medium codebases.
- Forward: find containing function → BFS through calls → collect data_access points → classify sensitive fields → build call paths
- Inverse: find all functions accessing target table/field → reverse BFS to find entry points
- Path finding: BFS with path tracking between any two functions

**SQLite-backed** (`SqliteReachabilityEngine`): Same API, queries SQLite directly. Trades latency per lookup for memory efficiency. O(1) memory regardless of codebase size.

**Key types**:
- `ReachabilityResult`: origin, reachable_access[], tables[], sensitive_fields[], max_depth, functions_traversed
- `InverseReachabilityResult`: target, access_paths[], entry_points[], total_accessors
- `ReachabilityOptions`: max_depth, sensitive_only, tables filter, include_unresolved

**v2 needs**: Taint analysis (track data transformations), field-level tracking, cross-service reachability, recursive CTEs for better performance, caching frequently-queried results.

---

## 10. Analyzers (AST, Type, Semantic, Flow)

Four foundational analysis engines operating on tree-sitter ASTs. Every scanned file passes through one or more.

### AST Analyzer (~800 lines)
Structural pattern matching and subtree comparison.
- `findPattern(ast, pattern)` — find nodes matching structural pattern
- `compareSubtrees(node1, node2)` — similarity score (0-1) between subtrees
- `traverse(ast, visitor)` — depth-first walk with callback
- `ASTPattern`: nodeType (required), text (string/regex), children[], minChildren, maxChildren, hasChild, notHasChild, depth

### Type Analyzer (~1600 lines)
Full TypeScript type system analysis.
- `extractType(node)` — extract TypeInfo from AST node
- `isSubtypeOf(type1, type2)` — structural subtype check
- `areTypesCompatible(type1, type2)` — compatibility check (looser)
- `getTypeCoverage(ast)` — percentage of typed locations
- Handles: primitives, references, unions, intersections, arrays, tuples, functions, objects, literals, generics
- `TypeInfo`: kind, text, name, members[], parameters[], returnType, elementType, types[], typeArguments[], constraint, isOptional, isReadonly, isExported

### Semantic Analyzer (~1350 lines)
Scope analysis, symbol resolution, reference tracking.
- Builds scope tree (global → module → function → method → class → block → etc.)
- Symbol table: all declarations with type, visibility, mutability, references
- Reference resolution: links identifier uses to declarations via scope chain
- Shadowed variable detection
- Collects from: function/arrow/method declarations, class/field definitions, variable declarations (const/let/var with mutability), destructuring, imports, exports, interfaces, type aliases, enums

### Flow Analyzer (~1600 lines)
Control flow graph construction and data flow analysis.
- Builds CFG with nodes for: entry/exit, statements, branches, loops, exception handling, returns/throws/breaks/continues
- Edge types: normal, true-branch, false-branch, exception, break, continue, return, throw
- Data flow: variable definitions/uses, reaching definitions, null dereference detection
- Issue detection: unreachable code, infinite loops, missing returns, null dereferences

**v2**: All four move to Rust. AST analyzer maps to tree-sitter queries. Type analyzer needs per-language variants. Semantic analyzer critical for call resolution accuracy. Flow analyzer needed for error handling and data flow.

---

## 11. Language Intelligence

Cross-language semantic normalization layer. Wraps raw call graph extractions with decorator normalization and semantic classification.

**5 normalizers**: TypeScript, Python, Java, C#, PHP. Each implements `extractRaw()` by calling the existing call graph extractor.

**Normalization pipeline**: extractRaw → detectFrameworks → normalizeFunction (per function: normalize decorators, derive semantics) → deriveFileSemantics.

**Decorator normalization**: Try FrameworkRegistry for known decorators (with semantic info + confidence + argument extraction). If no match: category='unknown', confidence=0.

**Function semantics** (derived from decorators): isEntryPoint, isInjectable, isAuthHandler, isTestCase, isDataAccessor, requiresAuth, entryPoint (HTTP path + methods), dependencies, auth (required roles).

**File semantics**: isController (has entry points), isService (has injectables, no entry points), isModel (has data accessors), isTestFile, primaryFramework.

**5 framework patterns**: Spring (Java), FastAPI (Python), NestJS (TypeScript), Laravel (PHP), ASP.NET (C#). Each defines `detectionPatterns` (imports, decorators) and `decoratorMappings` (pattern → semantic meaning).

**Cross-language queries** (`LanguageIntelligence` class): findEntryPoints, findDataAccessors, findInjectables, findAuthHandlers, findByCategory (12 categories: routing, di, orm, auth, validation, test, logging, caching, scheduling, messaging, middleware, unknown).

**v2**: Normalization is pure data transformation — excellent Rust candidate. Framework patterns are static config — zero-cost Rust structs.

---

## 12. Rules Engine

Enforcement layer. Patterns describe "what IS", rules engine determines "what SHOULD be" and flags deviations.

**Evaluator** (~900 lines): Core pipeline — checkMatch → getMatchDetails → evaluate (run pattern matcher, find violations from outliers, determine severity, generate quick fixes) → evaluateAll → evaluateFiles.

**Violation sources**: (1) Outlier locations — statistical deviations, (2) Missing patterns — file should have pattern but doesn't, (3) Outlier location details — specific code deviating from expected form.

**Rule Engine** (~900 lines): Higher-level orchestration wrapping Evaluator. Adds violation tracking (dedup by `patternId:file:range`), violation limits (100/pattern, 50/file), blocking detection, file filtering.

**Severity Manager** (~760 lines): Resolution order: pattern-specific override → category override → config-level → default. Defaults: security/auth=error, errors/api/data-access=warning, testing/logging=info, documentation/styling=hint. Escalation system: count/category/pattern/file-based rules.

**Quick Fix Generator** (~1320 lines): 7 strategies:

| Strategy | Confidence | What It Does |
|----------|-----------|-------------|
| Replace | Pattern-based | Replace code at violation range |
| Wrap | 0.6 | Wrap in try/catch, if-check, or function |
| Extract | 0.5 | Extract into named function/variable |
| Import | 0.7 | Add missing import |
| Rename | 0.7 | Rename to match convention |
| Move | 0.4 | Move code to different location |
| Delete | 0.5 | Remove unnecessary code |

**Variant Manager** (~1100 lines): Scoped pattern overrides (global/directory/file). Lifecycle: create → activate/deactivate → query → expire → delete. Stored in `.drift/variants/` as JSON. Auto-save with 30s interval. Expiration support.

**v2**: Evaluator core to Rust. Quick fix generation stays TS (presentation). Severity/variant managers stay TS (configuration).

---

## 13. Constraints System

**Location**: `packages/core/src/constraints/` (TS ~8 files)

Discovers and enforces architectural invariants learned from the codebase. Unlike patterns (what IS), constraints enforce what MUST BE.

**Architecture**: InvariantDetector (mines from data sources) → ConstraintSynthesizer (converts to Constraint objects) → ConstraintStore (persistence) → ConstraintVerifier (validates code). Integrates with Quality Gates via `constraint-verification` gate.

**10 categories**: api, auth, data, error, test, security, structural, performance, logging, validation.

**12 invariant types**: must_have, must_not_have, must_precede, must_follow, must_colocate, must_separate, must_wrap, must_propagate, cardinality, data_flow, naming, structure.

**Core type** (`Constraint`): id, name, description, category, derivedFrom (source type + IDs + evidence), invariant (type + predicate + description), scope (files/directories/functions/classes/entryPoints globs), confidence (score 0-1, conforming/violating counts, lastVerified), enforcement (level error/warning/info, autoFix, message, suggestion), status (discovered/approved/ignored/custom), language (typescript/javascript/python/java/csharp/php/rust/cpp/all), metadata.

**Status lifecycle**: `discovered` (auto-discovered, pending review) → `approved` (user-approved, actively enforced) | `ignored` (user-ignored, not enforced). Also `custom` for user-defined constraints.

**Detection from 5 data sources**:

| Source | What It Detects | Categories |
|--------|----------------|------------|
| Patterns | High-confidence approved patterns → invariants | api, auth, data, error, test, security, structural |
| Call Graph | Auth-before-data-access, validation patterns | auth, security, data |
| Boundaries | Data access layer invariants, sensitive data rules | data, security |
| Test Topology | Coverage requirements, test patterns | test |
| Error Handling | Error boundary patterns, propagation rules | error |

**Detection algorithm** (`InvariantDetector`): For each source → query high-confidence approved data → identify recurring invariants (≥ threshold conforming) → check violations → confidence = conforming / (conforming + violating) → produce `DetectedInvariant` with evidence (conforming count, violating count, conformingLocations[], violatingLocations[], sources[]). Merge invariants from all sources. Return sorted by confidence.

**Synthesis pipeline** (`ConstraintSynthesizer`): Detect invariants → convert to Constraint objects (with generated ID, metadata) → merge similar (if enabled, similarity threshold 0.8) → diff against existing (hash by category + invariant type + predicate + scope) → save new/updated. Auto-approval when confidence > threshold (e.g. 0.95). Existing constraints with same hash get confidence refreshed. Constraints no longer detected are flagged for review.

**Synthesis config**: categories filter, minConfidence, autoApproveThreshold, mergeSimilar (bool), similarityThreshold (0-1, default 0.8).

**Verification** (`ConstraintVerifier`): Two modes:
- `verifyFile(filePath, content, constraints)` — Full file verification
- `verifyChange(filePath, oldContent, newContent, constraints)` — Change-aware, only checks changed lines (diffs old vs new to find changed line numbers, only evaluates constraints where violations fall on changed lines — reduces noise, existing violations don't block new changes)

**Verification flow**: Determine file language → filter applicable constraints (scope glob matching on files/directories, language matching by extension) → for each constraint: extract code elements → evaluate predicate → record pass/fail with violation details → build summary (pass/fail/skip counts).

**Predicate types**:
- **Function**: Functions matching pattern must have/not have properties (error handling, decorators, return types)
- **Class**: Classes matching pattern must contain certain methods/properties
- **Entry Point**: API endpoints must have authentication, validation, etc.
- **Naming**: Files/functions/classes must match naming conventions
- **File Structure**: Modules must contain certain files (index.ts, types.ts, etc.)

**Code element extraction**: Language-aware patterns for function detection (def, func, fn, function, etc.), class detection (class, struct, interface), error handling detection (try/catch, try/except, defer, etc.), import detection (import/require). Supports all 8 languages.

**Violation output** (`ConstraintViolation`): constraintId, constraintName, file, line, message, severity (error/warning/info), suggestion, snippet.

**Store** (`ConstraintStore`): File-based persistence in `.drift/constraints/` organized by category (discovered/, custom). JSON format. `index.json` for fast category-based lookups without loading all files. Full CRUD + query with filters (categories, status, language, minConfidence, search), sorting, pagination. Lifecycle methods: approve(id), ignore(id, reason). `getForFile(filePath)` checks scope globs. `getActive(minConfidence)` returns approved constraints above threshold.

**Storage layout**:
```
.drift/constraints/
├── discovered/
│   ├── api.json
│   ├── auth.json
│   ├── security.json
│   └── structural.json
├── index.json
└── (custom constraints)
```

**Integration points**: Quality Gates (`constraint-verification` gate), MCP Tools (`drift_validate_change`, `drift_prevalidate`, `drift_constraints`), CLI (`drift constraints list/approve/ignore`).

**Lifecycle**: Detect → Synthesize → Store → Review → Enforce → Verify.

**v2**: Invariant detection to Rust (graph traversal). Constraint verification (predicate evaluation) ideal for Rust — currently regex-heavy, should use AST from Rust parsers. Change-aware verification (diffing) lightweight — can stay TS. Synthesis/merging stays TS. Store not performance-critical — stays TS or migrates to SQLite. Consider: AST-based verification (replace regex), call graph integration in verifier, data flow integration for data flow constraints, cross-file verification for module-level invariants.

---

## 14. Error Handling Analysis

**Location**: `packages/core/src/error-handling/` (TS ~3 files, ~600 lines analyzer), `crates/drift-core/src/error_handling/` (Rust ~3 files, ~300 lines analyzer)

Builds a complete topology of how errors flow through a codebase. Detects try/catch blocks, error boundaries, unhandled error paths, error propagation chains, and async error handling gaps. Integrates with the call graph to trace error flow across function boundaries.

**Core design principles**: (1) Error handling analyzed as a topology — not just per-function, but across call chains. (2) Unhandled error paths severity-ranked (critical for entry points, lower for internal). (3) Framework boundaries detected (React ErrorBoundary, Express middleware, NestJS filters, etc.). (4) Async error handling tracked separately (unhandled promises are a distinct bug class). (5) Error transformations along propagation chains tracked (stack trace preservation).

**Architecture**:
```
┌─────────────────────────────────────────────────────────┐
│              ErrorHandlingAnalyzer                       │
│  (error-handling-analyzer.ts — main analysis engine)    │
├──────────┬──────────┬──────────┬────────────────────────┤
│ Profile  │ Boundary │ Propag.  │   Gap                  │
│ Building │ Detection│ Chains   │   Detection            │
├──────────┴──────────┴──────────┴────────────────────────┤
│              Call Graph Integration                      │
│  Caller lookup │ Path traversal │ Native SQLite queries  │
├─────────────────────────────────────────────────────────┤
│              Rust Core (crates/drift-core)               │
│  ErrorPattern │ CatchBlock │ ErrorPropagation            │
└─────────────────────────────────────────────────────────┘
```

### TypeScript Analyzer API

```
ErrorHandlingAnalyzer:
  constructor(options: ErrorHandlingOptions)
  setCallGraph(callGraph): void
  build(): ErrorHandlingTopology
  getTopology(): ErrorHandlingTopology | null
  getMetrics(): ErrorHandlingMetrics | null
  getSummary(): ErrorHandlingSummary | null
  analyzeFunction(funcId, func?): ErrorHandlingProfile
  getFunctionAnalysis(funcId): FunctionErrorAnalysis | null
  getGaps(options?: GapDetectionOptions): ErrorHandlingGap[]
  getBoundaries(options?: BoundaryAnalysisOptions): ErrorBoundary[]
  getUnhandledPaths(minSeverity?): UnhandledErrorPath[]
```

Factory: `createErrorHandlingAnalyzer(options) → ErrorHandlingAnalyzer`

### Build Algorithm (3 phases)

**Phase 1 — Function Profiling**: For each function in the call graph: detect try/catch presence (`hasTryCatch`) → detect throw capability (`canThrow` — conservative: any function with calls can throw) → find throw locations → extract catch clauses (type, action, preservesError) → check for rethrows → analyze async handling (if async) → calculate quality score (0-100) → if function has try/catch, check if it's a boundary.

**Phase 2 — Propagation Chain Building**: For each function that can throw: start at thrower → walk up call graph via `calledBy` → at each level check if any caller has try/catch → if found, chain terminates at that boundary (sink) → if not found and no more callers, chain escapes (sink = null). Max depth: 20 levels (configurable). Cycle detection: skip already-visited functions.

**Phase 3 — Unhandled Path Detection**: For each propagation chain where `sink === null`: identify entry point (last function in path) → calculate severity based on entry point type (exported function → `critical`, entry point file → `critical`, otherwise → `medium`) → suggest boundary location (middle of chain).

**Phase 4 — Gap Detection**: Find error handling gaps: `no-try-catch` (function can throw but no handling), `swallowed-error` (catch block silently swallows), `unhandled-async` (async function with unhandled promise chains), `bare-catch` (catches `any` without type checking), `missing-boundary` (entry point without error boundary protection).

### Quality Score Algorithm

```
Base score: 50

Positive factors:
  +20  has try/catch
  +15  catch action is 'recover'
  +10  catch action is 'transform'
  +5   catch preserves original error
  +10  async function has try/catch with await
  +5   async function has .catch()

Negative factors:
  -20  can throw but no try/catch
  -25  catch swallows error (empty catch)
  -5   bare catch (catches 'any')
  -20  async with unhandled promises

Result: clamp(0, 100)
```

Quality mapping: ≥80 = excellent, ≥60 = good, ≥40 = fair, <40 = poor.

### Risk Score Algorithm (for gaps)

```
Base score: 50

Gap type weights:
  +20  no-try-catch
  +30  swallowed-error
  +25  unhandled-async
  +5   bare-catch

Function importance:
  +15  exported function
  +20  entry point file
  +10  called by >5 functions

Result: min(100, score)
```

### Framework Boundary Detection

| Framework | Detection Signal |
|-----------|-----------------|
| React ErrorBoundary | `componentDidCatch` method or class name contains "ErrorBoundary" |
| Express middleware | Function with exactly 4 parameters (err, req, res, next) |
| NestJS filter | Class name contains "filter" + method named "catch" |
| Spring handler | `@ExceptionHandler` or `@ControllerAdvice` annotations |
| Laravel handler | Detected via class hierarchy |

### Call Graph Integration
- Uses `setCallGraph()` to receive the call graph
- Checks for native SQLite call graph availability
- Falls back to in-memory `calledBy` arrays
- `getFunctionCallers()` tries: calledBy array → native SQLite query

### TypeScript Types

**Core enums**: `CatchAction` = log | rethrow | swallow | transform | recover. `ErrorSeverity` = critical | high | medium | low. `ErrorHandlingQuality` = excellent | good | fair | poor.

**ErrorHandlingProfile** (per-function): functionId, file, name, qualifiedName ("ClassName.methodName"), line, hasTryCatch, canThrow, throwLocations[], catchClauses[] (errorType, action, line, preservesError), rethrows, asyncHandling (hasCatch, hasAsyncTryCatch, hasUnhandledPromises, unhandledLocations[]), isAsync, qualityScore (0-100).

**ErrorBoundary**: functionId, file, name, catchesFrom[] (function IDs caught from), handledTypes[], isFrameworkBoundary, frameworkType (react-error-boundary | express-middleware | nestjs-filter | spring-handler | laravel-handler), coverage (% of callers protected), line.

**UnhandledErrorPath**: entryPoint, path[] (function IDs), errorType, severity, suggestedBoundary (where to add handling), reason.

**ErrorTransformation**: location (function ID), fromType, toType, preservesStack, line.

**ErrorPropagationChain**: source (functionId + throwLine), sink (functionId + catchLine, or null if uncaught), propagationPath[], transformations[], depth.

**ErrorHandlingTopology** (complete result): functions (Map<string, ErrorHandlingProfile>), boundaries[], unhandledPaths[], propagationChains[], generatedAt, projectRoot.

**ErrorHandlingMetrics**: totalFunctions, functionsWithTryCatch, functionsThatThrow, boundaryCount, unhandledCount, unhandledBySeverity (Record<ErrorSeverity, number>), avgQualityScore, swallowedErrorCount, unhandledAsyncCount, frameworkBoundaries.

**ErrorHandlingSummary**: totalFunctions, coveragePercent (functions with handling / total), unhandledPaths, criticalUnhandled, avgQuality, qualityDistribution (Record<ErrorHandlingQuality, number>), topIssues[] (type + count + severity).

**FunctionErrorAnalysis** (detailed per-function): profile, incomingErrors[] (from + errorType), outgoingErrors[] (to + caught), isProtected, protectingBoundary?, issues[] (type + message + severity + line), suggestions[].

**ErrorHandlingGap**: functionId, file, name, line, gapType (no-try-catch | swallowed-error | unhandled-async | bare-catch | missing-boundary), severity, description, suggestion, riskScore (0-100).

**AsyncErrorHandling**: hasCatch, hasAsyncTryCatch, hasUnhandledPromises, unhandledLocations[] (line + expression).

**Options**: `ErrorHandlingOptions` — rootDir, includeAsync (default true), detectFrameworkBoundaries (default true), maxPropagationDepth (default 20). `GapDetectionOptions` — minSeverity (default 'low'), limit (default 20), includeSuggestions (default true), files[] (focus on specific files). `BoundaryAnalysisOptions` — includeFramework, minCoverage.

### Rust Analyzer

**Fundamentally different approach** — works directly on source files without a call graph (AST-first):

```
ErrorHandlingAnalyzer:
  pub fn new() -> Self
  pub fn analyze(&mut self, files: &[String]) -> ErrorHandlingResult
```

**Boundary extraction algorithm**: For each line in source → detect "try" keyword (mark try_start) → detect "catch"/"except" keyword (create ErrorBoundary — check if catch is empty/swallowed, if it logs error, if it rethrows, extract caught types from catch signature) → detect `.catch()` calls from AST call sites (PromiseCatch boundary).

**Gap detection algorithm**: For each function in ParseResult: if async → check if function body contains try/catch → check if function has .catch() calls within its range → if neither and contains "await" → UnhandledAsync gap. For all call sites: `.then()` without nearby `.catch()` → UnhandledPromise gap. `.unwrap()` → UnwrapWithoutCheck gap (High severity). `.expect()` → UnwrapWithoutCheck gap (Medium severity).

**Error type extraction**: For each class in ParseResult: if class.extends contains "Error" or "Exception" or "Throwable" OR class.name ends with "Error" or "Exception" → extract as ErrorType.

**Caught type extraction** (multi-language): JavaScript/TypeScript: `catch (e: Error)` → extract type after ':'. Python: `except ValueError as e` → extract word after "except". Java/C#: `catch (IOException e)` → extract first word in parens.

**Helper methods**: `is_empty_catch(lines, line)` — checks for `{}`, `{ }`, or `pass`. `check_logs_error(lines, line)` — scans next 10 lines for console.error, logger.error, etc. `check_rethrows(lines, line)` — scans next 10 lines for `throw`, `raise`, `rethrow`. `get_function_source(lines, func)` — extracts function body text. `function_has_try_catch(lines, func)` — checks if function contains try+catch.

### Rust Types

**BoundaryType** (enum): TryCatch, TryExcept, TryFinally, ErrorHandler, PromiseCatch, AsyncAwait, ResultMatch, PanicHandler.

**ErrorBoundary** (Rust): file, start_line (u32), end_line (u32), boundary_type (BoundaryType), caught_types (Vec<String>), rethrows (bool), logs_error (bool), is_swallowed (bool).

**GapType** (enum): UnhandledPromise, UnhandledAsync, MissingCatch, SwallowedError, UnwrapWithoutCheck, UncheckedResult, MissingErrorBoundary.

**GapSeverity** (enum): Low, Medium, High, Critical.

**ErrorGap** (Rust): file, line (u32), function, gap_type (GapType), severity (GapSeverity), description.

**ErrorType** (Rust): name, file, line (u32), extends (Option<String>), is_exported (bool).

**ErrorHandlingResult** (Rust aggregate): boundaries (Vec<ErrorBoundary>), gaps (Vec<ErrorGap>), error_types (Vec<ErrorType>), files_analyzed (usize), duration_ms (u64).

### Type Mapping: Rust ↔ TypeScript

| Concept | Rust | TypeScript |
|---------|------|------------|
| Boundary | `ErrorBoundary` (file-level) | `ErrorBoundary` (function-level, with call graph) |
| Gap | `ErrorGap` (AST-detected) | `ErrorHandlingGap` (call-graph-aware, with risk score) |
| Error type | `ErrorType` | Extracted via `FunctionErrorAnalysis` |
| Propagation | Not implemented | `ErrorPropagationChain` (call graph traversal) |
| Topology | Not implemented | `ErrorHandlingTopology` (complete graph) |
| Quality | Not implemented | `qualityScore` (0-100) per function |

### MCP Integration — `drift_error_handling` / `drift_errors`

**Location**: `packages/mcp/src/tools/surgical/errors.ts` (~350 lines). Surgical layer — low token cost (300 target, 800 max).

**Purpose**: Returns custom error classes, error handling gaps, and error boundaries. Solves: AI needs to know existing error types when adding error handling.

**Actions**:
- `types` — List custom error classes. Returns: name, file, line, extends, properties[], usages (throw count).
- `gaps` — Find error handling gaps with severity filtering (default: "medium"). Returns: function, file, line, gapType, severity, suggestion.
- `boundaries` — List error boundaries. Returns: function, file, line, handledTypes[], coverage (%), isFramework.

**Arguments**: action (types | gaps | boundaries, default: types), severity filter, limit (default: 20).

**Stats response**: All actions include stats — totalTypes, totalGaps, totalBoundaries, criticalGaps, avgCoverage.

**Prerequisites**: Call graph must be built (`drift callgraph build`). Throws `CALLGRAPH_NOT_BUILT` error if missing.

**Integration**: Uses `createErrorHandlingAnalyzer()` factory → sets call graph from `CallGraphStore` → builds topology → queries based on action.

### v2 Merge Strategy

The two implementations are complementary — Rust is AST-first (pattern detection), TypeScript is call-graph-first (topology analysis). v2 should:
1. Keep Rust for AST-level extraction (boundaries, gaps, error types)
2. Move propagation chain analysis to Rust (graph traversal is ideal)
3. Move quality scoring to Rust (pure math)
4. Keep framework boundary detection in Rust (pattern matching)
5. Expose topology via NAPI for MCP tools

---

## 15. Test Topology

**Location**: `packages/core/src/test-topology/` (TS ~15 files), `crates/drift-core/src/test_topology/` (Rust 3 files)

Maps tests to production code they exercise. Answers: "Which tests cover this function?", "What's untested?", "Which tests should I run after changing this file?"

**Architecture**: `TestTopologyAnalyzer` (main API) → Per-Language Extractors (8 languages) → Call Graph Integration (direct + transitive + native SQLite) → Coverage/Mock/Quality analysis. Hybrid analyzer (`HybridTestTopologyAnalyzer`) combines tree-sitter primary with regex fallback for robustness.

**35+ frameworks across 8 languages**:
- TypeScript/JS: Jest, Vitest, Mocha, Ava, Tape
- Python: Pytest, Unittest, Nose
- Java: JUnit4, JUnit5, TestNG
- C#: xUnit, NUnit, MSTest
- PHP: PHPUnit, Pest, Codeception
- Go: go-testing, Testify, Ginkgo, Gomega
- Rust: rust-test, tokio-test, proptest, criterion, rstest
- C++: GTest, Catch2, Boost.Test, doctest, CppUnit

**Per-language extractors**: Each inherits from `BaseTestExtractor` (abstract base with framework detection, test case extraction, mock extraction, setup block extraction interfaces). Regex fallback extractors in `extractors/regex/` for when tree-sitter parsing fails.

**Extraction output per file** (`TestExtraction`): file, framework, language, testCases[], mocks[], setupBlocks[], fixtures[] (Pytest-specific).

**Per test case** (`TestCase`): id (`file:name:line`), name, parentBlock (describe/context), qualifiedName (`describe > it`), file, line, directCalls[], transitiveCalls[], assertions[] (with details), quality signals.

**Test quality signals** (`TestQualitySignals`): assertionCount, hasErrorCases, hasEdgeCases (null/empty/boundary), mockRatio (high = brittle), setupRatio (setup lines vs test lines), score (0-100).

**Coverage mapping algorithm**:
1. For each test case: resolve direct function calls → function IDs
2. If call graph available: find transitive calls (BFS through call graph)
3. Record test → function mapping with reach type (direct/transitive/mocked)
4. Per source file: collect all functions, find covering tests, calculate coverage %
5. Mock-only coverage tracked separately — not real coverage

**Reach types**: `direct` (test calls function), `transitive` (test reaches via call chain), `mocked` (only reached via mocked paths). Confidence: direct=high, transitive-shallow=medium-high, transitive-deep=lower, mocked=lowest.

**Minimum test set**: Given changed files → find all functions → find covering tests → deduplicate → calculate coverage → estimate time savings. Returns: selected tests with reasons, total vs selected count, estimated time savings, changed code coverage percentage.

**Uncovered function detection**: Risk score (0-100) based on: entry point (+30), sensitive data access (+25), call graph centrality. Inferred reasons: dead-code (no callers), framework-hook (lifecycle method), generated (in generated file), trivial (getter/setter/constructor), test-only (only called from tests), deprecated (marked deprecated).

**Mock analysis**: Aggregate all mocks → classify external (good) vs internal (suspicious) → per-test mock ratio → identify high-mock-ratio tests (>0.7) → rank most-mocked modules. Output: totalMocks, externalMocks, internalMocks, avgMockRatio, highMockRatioTests[], topMockedModules[].

**Mock statement types** (`MockStatement`): target, mockType (jest.mock, sinon.stub, @patch, etc.), line, isExternal (external deps vs internal code), hasImplementation.

**Summary statistics**: test files/cases count, covered vs total source files and functions, coverage percentages (file-level and function-level), average mock ratio and quality score, breakdown by framework.

**Rust implementation** (`crates/drift-core/src/test_topology/`): `TestFile`, `TestCase`, `TestFramework` (enum: Jest, Vitest, Mocha, Pytest, JUnit, NUnit, XUnit, PHPUnit, GoTest, RustTest, Catch2, GoogleTest, Unknown), `MockUsage`, `MockType` (Function, Module, Class, Http), `TestType` (Unit, Integration, E2E, Unknown). Framework detection for 13 frameworks. Simpler than TS — no quality scoring or transitive analysis yet.

**MCP integration**: Exposed via `drift_test_topology` MCP tool for AI-assisted test analysis.

**v2**: Per-language extractors to Rust. Coverage mapping with call graph traversal to Rust (main bottleneck). Quality scoring to Rust. Minimum test set (set-cover problem) benefits from Rust performance at scale. Mock analysis can stay TS (presentation). Fixture detection should expand beyond Python (JUnit @Rule, C# [SetUp]).


---

## 16. Gap Analysis — What's Missing from v2-Research Docs

> Systematic audit of the Drift codebase vs the 49 existing v2-research documents. Organized by severity. Source: `docs/v2-research/16-gap-analysis/`.

### Rust Core Documentation Audit

**Coverage grade: A-** — All P0 items complete. Call graph, reachability, unified analysis, and NAPI bridge are at Cortex-level depth. 10 docs covering 12 modules (61 source files) + 8 comprehensive call graph docs. Can you recreate v2 from these docs alone? Yes, for all major subsystems — right architecture, module boundaries, algorithm details, type definitions, regex patterns, confidence scores, and the complete Rust↔TypeScript API contract. Remaining work is P1 (data-models.md secondary types, benchmarks.md) and P2 (flow diagrams, build configuration).

### Critical Gaps (P0 — Will break v2 if missed)

#### 1. Licensing & Feature Gating System — COMPLETELY UNDOCUMENTED
`packages/core/src/licensing/` — 4 files: license-manager.ts, license-validator.ts, feature-guard.ts, types.ts.

**Business-critical system** that gates enterprise features at runtime.

**3 tiers**:
- **Community** (free): All scanning, detection, analysis, CI, MCP, VSCode
- **Team**: Policy engine, regression detection, custom rules, trends, exports
- **Enterprise**: Multi-repo governance, impact simulation, security boundaries, audit trails, Jira/Slack/webhooks, self-hosted models, custom detectors, REST API

**16 enterprise features** gated at runtime. License sources: env var (`DRIFT_LICENSE_KEY`), file (`.drift/license.key`), config. Validation: JWT/key validation, expiration checks. `FeatureGuard` checks tier before allowing feature use.

**Why critical**: The entire monetization model is encoded here. Every gated feature in quality-gates, dashboard, and integrations checks this system. Rebuild without it = lose the open-core boundary.

#### 2. Workspace Management System — UNDOCUMENTED
`packages/core/src/workspace/` — 6 files: workspace-manager.ts, project-switcher.ts, context-loader.ts, backup-manager.ts, schema-migrator.ts, source-of-truth.ts.

**Project lifecycle orchestrator** — the glue that ties everything together.

- `WorkspaceManager` — Top-level workspace initialization and management
- `ProjectSwitcher` — Multi-project switching (invalidates caches, reloads stores)
- `ContextLoader` — Loads all context for a project (patterns, contracts, boundaries, etc.)
- `BackupManager` — Backup creation and restoration
- `SchemaMigrator` — Database schema migrations across versions
- `SourceOfTruth` — Source of truth management (which store is authoritative)

**Why critical**: Without understanding how projects are initialized, switched, backed up, and migrated, v2 won't have a coherent lifecycle.

#### 3. Audit System — UNDOCUMENTED
`packages/core/src/audit/` — 3 files: audit-engine.ts, audit-store.ts, types.ts.

- `AuditEngine` — Pattern validation, health scoring, degradation detection
- `AuditStore` — Audit snapshot persistence
- Types: Audit snapshots, health scores, degradation metrics

**Why critical**: The audit system tells users "your codebase is drifting." It's the core value proposition feedback loop.

#### 4. Pattern Matcher & Confidence Scorer — UNDER-DOCUMENTED
`packages/core/src/matcher/` — Docs mention `outlier-detector.ts` and `types.ts` but miss:
- `confidence-scorer.ts` — The confidence scoring algorithm (frequency, consistency, age, spread)
- `pattern-matcher.ts` — The core pattern matching engine that evaluates patterns against files
- Actually contains: types.ts, outlier-detector.ts, confidence-scorer.ts, pattern-matcher.ts, index.ts + 3 test files

**Why critical**: Confidence scoring is the heart of Drift's learning system. Without the exact algorithm, v2 patterns won't score the same way.

#### 5. Context Generation System — ✅ NOW DOCUMENTED
`packages/core/src/context/` — context-generator.ts, package-detector.ts, types.ts. Powers `drift_context` and `drift_package_context` MCP tools. See `22-context-generation/` (overview, types, package-detector, token-management).

#### 6. Storage Backend Auto-Detection — UNDOCUMENTED
`packages/core/src/storage/store-factory.ts` — The store factory automatically detects whether to use SQLite or JSON:
- `detectStorageBackend()` checks for `drift.db` (SQLite) vs `.drift/patterns/` (JSON)
- `hasSqliteDatabase()` and `hasJsonPatterns()` detection functions
- `getStorageInfo()` returns current backend, file counts, database size
- Transparent switching between backends based on what exists on disk

### High-Priority Gaps (P1 — Important for feature parity)

#### 7. Skills Library — 73 Architectural Templates — UNDOCUMENTED
`skills/` directory with 73 skill templates, each containing a `SKILL.md`. Categories: AI coaching, API patterns, caching strategies, circuit breakers, database migrations, distributed locks, error handling, feature flags, health checks, idempotency, JWT auth, leader election, logging/observability, metrics collection, multi-tenancy, OAuth, pagination, rate limiting, retry/fallback, row-level security, SSE streaming, Stripe integration, Supabase auth, webhook security, websocket management, worker orchestration, and more. These are the "knowledge base" for code generation guidance — significant domain expertise.

#### 8. Wiki — 58 User Documentation Pages — UNDOCUMENTED
`wiki/` directory. Key pages: Architecture, Audit System, Call Graph Analysis, CI Integration, CLI Reference, Configuration, Cortex (7 pages), Dashboard, Data Boundaries, Decision Mining, Detectors Deep Dive, FAQ, Getting Started, Git Hooks, Impact Analysis, Incremental Scans, Language Support, MCP (3 pages), Memory CLI, Monorepo Support, Pattern Categories, Quality Gates, Security Analysis, Skills, Speculative Execution, Styling DNA, Troubleshooting, Watch Mode, Wrappers Detection. Contains usage patterns, examples, and explanations revealing intended behavior not captured in code-level docs.

#### 9. Demo Applications — 8 Reference Implementations — UNDOCUMENTED
`demo/` directory: backend/ (Node.js/TS), csharp-backend/ (C#), spring-backend/ (Spring Boot), laravel-backend/ (Laravel), go-backend/ (Go), rust-backend/ (Rust), wpf-sample/ (WPF/XAML), frontend/ (React). These are the test fixtures validating Drift works across all supported languages/frameworks — the integration test suite.

#### 10. GitHub Action — CI/CD Integration — UNDER-DOCUMENTED
`actions/drift-action/action.yml` — Composite action installing `driftdetect-ci@latest`. Inputs: github-token, fail-on-violation, post-comment, create-check, pattern-check, impact-analysis, constraint-verification, security-boundaries, memory-enabled. Outputs: status, summary, violations-count, drift-score, result-json. Runs `drift-ci analyze --pr <number>`.

#### 11. Telemetry System — UNDOCUMENTED
**Client** (`packages/core/src/telemetry/`): telemetry-client.ts (opt-in collection, event batching, privacy controls), types.ts (event types, configuration). **Server** (`infrastructure/telemetry-worker/`): Cloudflare Worker (D1 database). Endpoints: `POST /v1/events`, `GET /v1/health`, `GET /v1/stats`. Tracks: event types, language usage, category usage, unique installations. Daily aggregate stats with 30-day rolling window.

#### 12. Learning Store — UNDER-DOCUMENTED
`packages/core/src/learning/` — learning-store.ts, types.ts. Standalone learning store that persists learned conventions across sessions. Docs mention learning in detector context but don't document the persistence layer (`.drift/learned/`).

#### 13. MCP Feedback System — UNDOCUMENTED
`packages/mcp/src/feedback.ts` — Full example quality feedback system tracking user ratings on pattern examples. `FeedbackManager` class with file/directory-level scoring. Rating system: good (+0.1 boost), bad (-0.15 penalty), irrelevant (-0.05). Directory-level score propagation (30% of file-level delta). File exclusion when confidence > 0.5 and boost < -0.5. Persists to `.drift/feedback/examples.json` and `.drift/feedback/scores.json`. Keeps last 5000 feedback entries. This is a reinforcement learning loop for example quality.

#### 14. MCP Pack Manager — UNDER-DOCUMENTED
`packages/mcp/src/packs.ts` — Much more than "tool subsets." `PackManager` class with custom pack creation, staleness detection, usage tracking. Pack suggestion engine infers packs from project structure. Custom packs stored in `.drift/packs/`. Pack content generation with pattern filtering, scoring, and caching. Usage analytics tracking per pack.

#### 15. JSON↔SQLite Sync Service — UNDER-DOCUMENTED
`packages/core/src/storage/sync-service.ts` — Comprehensive bidirectional sync service with 11 sync methods: syncAll() (full sync), plus individual syncs for boundaries, environment, call graph, audit, DNA, test topology, contracts, constraints, history, coupling, error handling. Each reads from JSON files and writes to SQLite repositories.

#### 16. MCP Dual-Path Architecture — UNDOCUMENTED
The enterprise server has a dual-path architecture: Legacy path uses `PatternStore` (JSON-based) directly. New path uses `IPatternService` (SQLite-backed) when available. Tools with dual implementations: `drift_status`, `drift_patterns_list`, `drift_pattern_get`, `drift_code_examples`, `drift_prevalidate`, `drift_security_summary`, `drift_contracts_list`, `drift_env`, `drift_dna_profile`, `drift_constraints`. All prefer SQLite (`UnifiedStore`) when available.

### Medium-Priority Gaps (P2 — Behavioral details)

#### 17. Unified Provider Internal Details — UNDER-DOCUMENTED
Missing internal files: parsing/parser-registry.ts (parser selection/registration), compat/legacy-extractors.ts (backward compatibility), compat/legacy-scanner.ts (legacy scanner wrapper), integration/unified-scanner.ts (drop-in replacement), integration/unified-data-access-adapter.ts (bridge to existing format), docs/MIGRATION.md (internal migration guide).

#### 18. Speculative Execution — Split Across Two Directories
Docs cover `packages/core/src/simulation/` but miss: `packages/core/src/speculative/approach-generator.ts` (separate approach generator), `packages/core/src/speculative/templates/types.ts` (template type definitions). Appears to be an older or parallel implementation.

#### 19. Dual Licensing Model — UNDOCUMENTED
`licenses/` directory: Apache-2.0.txt, BSL-1.1.txt, LICENSING.md (comprehensive FAQ and tier explanation). Each source file has a license header (`@license Apache-2.0` or `@license BSL-1.1`). BSL code converts to Apache 2.0 after 4 years.

#### 20. Docker Deployment — UNDOCUMENTED
Multi-stage Docker build for MCP HTTP server. Builder stage: Node 20, pnpm, native module compilation (tree-sitter). Production stage: Non-root user, 4GB memory limit, health checks. Docker Compose: SSE endpoint at `/sse`, message endpoint at `/message`. Volume mounting for project analysis and `.drift` cache persistence. Environment: `NODE_OPTIONS=--max-old-space-size=4096`.

#### 21. Husky Git Hooks — UNDOCUMENTED
Root `package.json` includes `"prepare": "husky install"`, indicating pre-commit hooks configured.

#### 22. Build Scripts — UNDER-DOCUMENTED
`scripts/` directory: generate-large-codebase.ts (synthetic codebases for benchmarking), publish.sh (package publishing), transform-detector.ts (detector transformation utility), validate-docs.sh / validate-docs.ts (documentation validation).

#### 23. Turborepo Pipeline — UNDOCUMENTED
`turbo.json` defines build pipeline: `build` → `typecheck` → `lint` → `test` dependency chain. `^build` dependencies (build deps first). Caching enabled for build, typecheck, lint, test. `test:watch` and `dev` marked as persistent (no cache). Coverage output tracking.

#### 24. Pervasive EventEmitter Architecture — UNDOCUMENTED
Nearly every store and manager extends `EventEmitter`: PatternStore, ContractStore, HistoryStore, ConstraintStore, HybridPatternStore, HybridContractStore, all Data Lake stores (IndexStore, QueryEngine, ViewStore, ViewMaterializer, PatternShardStore, CallGraphShardStore, SecurityShardStore, ExamplesStore, ManifestStore), WorkerPool, ThreadedWorkerPool, ProjectRegistry, VariantManager, PackageDetector, PackageContextGenerator, CachedPatternRepository, PatternStoreAdapter. Events like `pattern:added`, `pattern:approved`, `patterns:loaded` propagate through the system. This event-driven pub/sub architecture must be preserved in v2.

### Deep Algorithm Gaps (Exact values needed for v2 recreation)

#### Confidence Scoring Algorithm
**Weights** (must sum to 1.0): Frequency 0.40 (occurrences / totalLocations), Consistency 0.30 (1 - variance), Age 0.15 (linear scale, 0→30 days maps to minAgeFactor 0.1→1.0), Spread 0.15 (fileCount / totalFiles).

**Thresholds**: High ≥ 0.85, Medium ≥ 0.70, Low ≥ 0.50, Uncertain < 0.50.

#### Health Score Algorithm
**Weights** (must sum to 1.0): Average Confidence 0.30, Approval Ratio 0.20, Compliance Rate 0.20 (locations / (locations + outliers)), Cross-Validation Rate 0.15, Duplicate-Free Rate 0.15. Score = weighted sum × 100, clamped [0, 100].

#### Audit Recommendation Thresholds
- Auto-approve: confidence ≥ 0.90, outlierRatio ≤ 0.50, locations ≥ 3, no error-severity issues
- Review: confidence ≥ 0.70
- Likely false positive: confidence < 0.70

#### Learning System Defaults
- Min occurrences: 3
- Dominance threshold: 0.60 (60% must use same convention)
- Min files: 2
- Max files to analyze: 1000
- Learned patterns expire after 24 hours (re-learn on next scan)
- Stored in `.drift/learned/{detector-id}.json`

#### Feedback Scoring
- Good example: +0.1 boost
- Bad example: -0.15 penalty
- Irrelevant: -0.05 penalty
- Directory propagation: 30% of file delta
- Exclusion threshold: boost < -0.5 AND confidence > 0.5
- Score → multiplier: `1 + (boost × 0.7)` (range: 0.3 to 1.7)

#### Duplicate Detection
- Jaccard similarity on location sets (file:line pairs)
- Threshold: 0.85 similarity
- Only compares within same category
- Recommendation: merge if > 0.9, review if > 0.85

### Corrections to Existing Docs

**CLI Command Count**: Documented as "~45 commands." Actual: `commands/index.ts` exports 48 named commands, plus `dna/` subcommands, plus `setup/` has 13 runners. Real count closer to 65+.

**MCP Tool Count**: Documented as "90+ tools." Actual: 56 unique tool names in `routeToolCall()` switch statements. With 17 memory tools routed via `executeMemoryTool` wrapper + 33 memory tool files, total is ~56 routed tools.

**Matcher Directory**: Documented as containing types.ts, outlier-detector.ts. Actually contains: types.ts, outlier-detector.ts, confidence-scorer.ts, pattern-matcher.ts, index.ts + 3 test files.

**.drift/ Directory Structure**: Config doc lists `.drift/` structure but misses: `.drift/learned/` (learned pattern conventions per-detector), `.drift/feedback/` (example quality feedback — examples.json, scores.json), `.drift/packs/` (custom MCP tool packs), `.drift/license.key` (license key file), `.drift/backups/` (backup storage with retention policy).

**Package Detector Scope**: Context generation supports monorepo detection for: npm/pnpm/yarn workspaces, Python packages (pyproject.toml, setup.py, setup.cfg), Go modules (go.mod, go.work), Maven modules (pom.xml), Gradle modules (settings.gradle), Composer packages (composer.json), .NET projects (.csproj, .sln), Cargo workspaces (Cargo.toml). Far more comprehensive than documented.

### Priority Summary for v2 Recreation

| Priority | Gap | Impact |
|----------|-----|--------|
| P0 | Licensing/Feature Gating | Business model — 3 tiers, 16 features, JWT + simple keys |
| P0 | Workspace Management | Project lifecycle — init, switch, backup, migrate, source-of-truth |
| P0 | Confidence Scorer + Pattern Matcher | Core algorithm — exact weights and thresholds |
| P0 | Context Generation | ✅ DOCUMENTED — see `22-context-generation/` |
| P0 | Audit System | Health scoring — exact weights documented above |
| P0 | Storage Backend Auto-Detection | Transparent JSON↔SQLite switching |
| P1 | Skills Library (73 templates) | Knowledge base for code generation |
| P1 | Telemetry System | Client + Cloudflare Worker backend |
| P1 | Learning Store + Types | Convention persistence — `.drift/learned/` |
| P1 | MCP Feedback System | Reinforcement learning for example quality |
| P1 | MCP Pack Manager | Custom packs, suggestion engine, usage tracking |
| P1 | JSON↔SQLite Sync Service | 11 sync methods for migration |
| P1 | MCP Dual-Path Architecture | Legacy JSON vs new SQLite tool implementations |
| P2 | Wiki (58 pages) | User documentation |
| P2 | Demo Apps (8 apps) | Integration test fixtures |
| P2 | GitHub Action | CI/CD — composite action with 8 inputs, 5 outputs |
| P2 | Docker Deployment | Multi-stage build, SSE/message endpoints |
| P2 | Dual Licensing (Apache 2.0 + BSL 1.1) | Legal/compliance |
| P2 | Turborepo Pipeline | Build dependency chain |
| P2 | EventEmitter Architecture | Pervasive pub/sub — must preserve in v2 |
| P3 | Build scripts | Developer tooling |
| P3 | Husky hooks | Dev workflow |
| P3 | Speculative split | Code organization quirk |