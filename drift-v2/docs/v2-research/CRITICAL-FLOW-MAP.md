# Drift V2 — Complete Critical Flow Map

> Generated: 2025-02-10 | Comprehensive mapping of every critical flow in the system

## Table of Contents

1. [System Architecture Overview](#1-system-architecture-overview)
2. [Flow 1: Scanner](#2-flow-1-scanner)
3. [Flow 2: Parser](#3-flow-2-parser)
4. [Flow 3: Detection Engine](#4-flow-3-detection-engine)
5. [Flow 4: Analysis Pipeline (Orchestrator)](#5-flow-4-analysis-pipeline)
6. [Flow 5: Pattern Intelligence](#6-flow-5-pattern-intelligence)
7. [Flow 6: Structural Analysis (10 subsystems)](#7-flow-6-structural-analysis)
8. [Flow 7: Graph Intelligence (5 subsystems)](#8-flow-7-graph-intelligence)
9. [Flow 8: Enforcement Engine](#9-flow-8-enforcement-engine)
10. [Flow 9: Storage Layer](#10-flow-9-storage-layer)
11. [Flow 10: NAPI Bindings](#11-flow-10-napi-bindings)
12. [Flow 11: Presentation Layer (MCP, CLI, CI)](#12-flow-11-presentation-layer)
13. [Flow 12: Cortex Memory System](#13-flow-12-cortex-memory-system)
14. [Flow 13: Cortex-Drift Bridge](#14-flow-13-cortex-drift-bridge)
15. [Flow 14: Advanced Systems](#15-flow-14-advanced-systems)
16. [Master Data Flow Diagram](#16-master-data-flow-diagram)
17. [Database Schema Map](#17-database-schema-map)

---

## 1. System Architecture Overview

Drift V2 is a **3-workspace Rust monorepo** with a TypeScript presentation layer:

```
┌─────────────────────────────────────────────────────────────────┐
│                    PRESENTATION LAYER (TS)                       │
│  drift-mcp (MCP server) │ drift-cli (CLI) │ drift-ci (CI agent) │
│  drift-napi-contracts (shared types) │ drift │ cortex            │
└──────────────────────────┬──────────────────────────────────────┘
                           │ NAPI-RS v3 (41 drift + 68 cortex = 109 bindings)
┌──────────────────────────┴──────────────────────────────────────┐
│                      RUST ENGINE LAYER                          │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │ drift-napi  │  │ cortex-napi  │  │ cortex-drift-bridge    │ │
│  │ (9 modules) │  │ (17 modules) │  │ (15 subsystems)        │ │
│  └──────┬──────┘  └──────┬───────┘  └────────────────────────┘ │
│  ┌──────┴──────┐  ┌──────┴───────┐                              │
│  │drift-analysis│  │cortex-*     │  (21 crates)                 │
│  │drift-storage │  │cortex-storage│                              │
│  │drift-context │  └─────────────┘                              │
│  │drift-core    │                                               │
│  │drift-bench   │                                               │
│  └──────────────┘                                               │
└─────────────────────────────────────────────────────────────────┘
                           │
              ┌────────────┴────────────┐
              │     drift.db (SQLite)   │    cortex.db (SQLite)
              │     45 tables, WAL mode │    20+ tables, WAL mode
              └─────────────────────────┘
```

**3 Rust workspaces:**
- `crates/drift/` — analysis engine (5 crates: drift-analysis, drift-storage, drift-context, drift-core, drift-bench)
- `crates/cortex/` — memory system (21 crates: 20 cortex-* crates + test-fixtures)
- `crates/cortex-drift-bridge/` — bridge between the two (15 subsystems)

**6 TS packages:**
- `packages/drift-mcp/` — MCP server (6 entry points, ~41 internal tools, 61 cortex tools)
- `packages/drift-cli/` — CLI (27 commands + cortex umbrella with 30 subcommands)
- `packages/drift-ci/` — CI agent (10 analysis passes)
- `packages/drift-napi-contracts/` — shared NAPI type definitions (interface.ts, stub.ts, loader.ts)
- `packages/drift/` — core drift TS package
- `packages/cortex/` — cortex TS package (61 tools, bridge client, CortexClient)

---

## 2. Flow 1: Scanner

**Purpose:** Discover files, compute hashes, detect changes incrementally.

**Entry point:** `driftScan(root, options)` → `scanner.rs` NAPI binding

```
User calls driftScan(root)
  │
  ├─► Phase 1: DISCOVERY
  │   walker.rs::walk_directory()
  │   ├─ Uses `ignore` crate's WalkParallel
  │   ├─ Respects .gitignore + .driftignore + 18 default ignores
  │   ├─ Filters: node_modules, .git, dist, build, target, __pycache__, etc.
  │   ├─ Detects language from file extension
  │   └─ Returns Vec<DiscoveredFile> sorted by path
  │
  ├─► Phase 2: CLASSIFICATION (parallel via rayon)
  │   incremental.rs::classify_file()
  │   ├─ Level 1: mtime comparison (catches ~95% unchanged)
  │   ├─ Level 2: content hash via xxhash (for mtime-changed files)
  │   └─ Returns (FileStatus, ScanEntry) per file
  │
  ├─► Phase 3: DIFF COMPUTATION
  │   incremental.rs::compute_diff()
  │   ├─ Classifies: Added / Modified / Unchanged (per-file via FileStatus enum)
  │   ├─ Removed = cached paths absent from disk (set difference, not a FileStatus value)
  │   ├─ Computes language stats, cache hit rate
  │   └─ Returns ScanDiff { added, modified, removed, unchanged, errors, stats, entries }
  │
  └─► Phase 4: PERSISTENCE
      scanner.rs::persist_scan_diff()
      ├─ BatchCommand::UpsertFileMetadata → file_metadata table
      ├─ BatchCommand::DeleteFileMetadata → removes deleted files
      ├─ Records scan in scan_history table
      └─ Flushes BatchWriter
```

**Key files:**
- `drift-analysis/src/scanner/scanner.rs` — orchestrator
- `drift-analysis/src/scanner/walker.rs` — parallel file walker
- `drift-analysis/src/scanner/incremental.rs` — 2-level change detection
- `drift-analysis/src/scanner/hasher.rs` — xxhash content hashing
- `drift-analysis/src/scanner/language_detect.rs` — 14 languages, extension-based
- `drift-analysis/src/scanner/cancellation.rs` — cross-thread scan cancellation (AtomicBool)
- `drift-analysis/src/scanner/types.rs` — ScanDiff, ScanEntry, ScanStats, DiscoveredFile, FileStatus
- `drift-napi/src/bindings/scanner.rs` — NAPI binding + persistence

**14 supported languages:**
TypeScript, JavaScript, Python, Java, C#, Go, Rust, Ruby, PHP, Kotlin, C++, C, Swift, Scala

**Storage tables touched:** `file_metadata`, `scan_history`

---

## 3. Flow 2: Parser

**Purpose:** Parse source files into a canonical `ParseResult` struct via tree-sitter AST.

**Entry point:** `ParserManager::parse()` or `parse_returning_tree()`

```
ParserManager.parse(source, path)
  │
  ├─► Language detection (extension-based)
  ├─► Cache check (content_hash → ParseCache, moka-based)
  ├─► Route to language-specific parser (10 parsers)
  │   └─ tree-sitter AST parse → visitor extraction
  └─► Return ParseResult
```

**ParseResult contains (canonical struct, 18 fields):**
- `file: String` — source file path
- `language: Language` — detected language enum
- `content_hash: u64` — xxh3 hash of source content
- `functions: Vec<FunctionInfo>` — 18 fields: name, qualified_name, file, line, column, end_line, parameters (SmallVec<ParameterInfo>), return_type, generic_params, visibility, is_exported, is_async, is_generator, is_abstract, range, decorators, doc_comment, body_hash, signature_hash
- `classes: Vec<ClassInfo>` — 13 fields: name, namespace, extends, implements, generic_params, is_exported, is_abstract, class_kind (Class/Interface/Struct/Enum/Trait/Record/Union/TypeAlias), methods, properties, range, decorators
- `imports: Vec<ImportInfo>` — 5 fields: source, specifiers (SmallVec<ImportSpecifier {name, alias}>), is_type_only, file, line
- `exports: Vec<ExportInfo>` — 6 fields: name (Option), is_default, is_type_only, source (Option), file, line
- `call_sites: Vec<CallSite>` — 7 fields: callee_name, receiver, file, line, column, argument_count (u8), is_await
- `decorators: Vec<DecoratorInfo>` — 4 fields: name, arguments (SmallVec<DecoratorArgument {key, value}>), raw_text, range
- `string_literals`, `numeric_literals`, `error_handling`, `doc_comments`
- `namespace`, `parse_time_us`, `error_count`, `error_ranges`
- `has_errors: bool` — whether tree-sitter reported parse errors

**10 language parsers (each implements `LanguageParser` trait):**

| Parser | File | Tree-sitter Grammar |
|--------|------|-------------------|
| TypeScript | `typescript.rs` | `tree_sitter_typescript` (TS + TSX) |
| JavaScript | `javascript.rs` | `tree_sitter_javascript` |
| Python | `python.rs` | `tree_sitter_python` |
| Java | `java.rs` | `tree_sitter_java` |
| C# | `csharp.rs` | `tree_sitter_c_sharp` |
| Go | `go.rs` | `tree_sitter_go` |
| Rust | `rust_lang.rs` | `tree_sitter_rust` |
| Ruby | `ruby.rs` | `tree_sitter_ruby` |
| PHP | `php.rs` | `tree_sitter_php` |
| Kotlin | `kotlin.rs` | `tree_sitter_kotlin_sg` |

**Fallback grammars:** C/C++ → C# grammar, Swift/Scala → Java grammar

**Key files:**
- `drift-analysis/src/parsers/manager.rs` — ParserManager (routes + caches)
- `drift-analysis/src/parsers/types.rs` — ParseResult canonical struct
- `drift-analysis/src/parsers/traits.rs` — LanguageParser trait
- `drift-analysis/src/parsers/languages/mod.rs` — shared visitor logic (69KB)
- `drift-analysis/src/parsers/cache.rs` — moka-based parse cache

---

## 4. Flow 3: Detection Engine

**Purpose:** Run pattern detectors across parsed files to find code patterns, security issues, anti-patterns.

```
DetectorRegistry.run_all(ctx: &DetectionContext)
  │
  ├─► For each registered detector:
  │   ├─ Check enabled (not disabled, not critical-only filtered)
  │   ├─ catch_unwind() for panic safety
  │   └─ detector.detect(ctx) → Vec<PatternMatch>
  │
  └─► Return all matches
```

**16 detector categories (each implements `Detector` trait):**

| # | Category | File | Status |
|---|----------|------|--------|
| 1 | Security | `security/` | Priority — eval, cmd injection, XSS, secrets (120 lines) |
| 2 | DataAccess | `data_access/` | Priority — ORM methods, raw SQL, repository pattern (112 lines) |
| 3 | Errors | `errors/` | Priority — empty catch, generic catch-all, error patterns (81 lines) |
| 4 | Testing | `testing/` | Priority — test frameworks, mocks, assertions, naming (150 lines) |
| 5 | Structural | `structural/` | Priority — naming conventions, class naming, export patterns (86 lines) |
| 6 | Api | `api/` | Real impl — REST endpoints, route strings, framework imports (109 lines) |
| 7 | Auth | `auth/` | Real impl — auth functions, JWT/token imports, auth calls (107 lines) |
| 8 | Components | `components/` | Real impl — component patterns |
| 9 | Config | `config/` | Real impl — config patterns |
| 10 | Contracts | `contracts/` | Real impl — contract patterns |
| 11 | Documentation | `documentation/` | Real impl — doc patterns |
| 12 | Logging | `logging/` | Real impl — console/logger calls, framework imports, bare prints (132 lines) |
| 13 | Performance | `performance/` | Real impl — performance patterns |
| 14 | Styling | `styling/` | Real impl — styling patterns |
| 15 | Types | `types/` | Real impl — type patterns |
| 16 | Accessibility | `accessibility/` | Real impl — accessibility patterns |

> **DD-03 Correction:** The code comment in `registry.rs` and `mod.rs` labels categories 6-16 as "skeleton" but this is **stale**. Every detector has real detection logic (80-150 lines) using call sites, imports, function names, and string literals. The "priority 5" distinction is about hardening depth, not implementation existence.

**3 detector variants:** Base (pattern matching), Learning (2-pass), Semantic

**PatternMatch output:** file, line, column, pattern_id, confidence, category, detection_method, matched_text, cwe_ids, owasp

**Key files:**
- `drift-analysis/src/detectors/registry.rs` — DetectorRegistry + create_default_registry()
- `drift-analysis/src/detectors/traits.rs` — Detector trait, DetectorCategory enum
- `drift-analysis/src/engine/visitor.rs` — DetectionContext
- `drift-analysis/src/engine/pipeline.rs` — AnalysisPipeline (4-phase per-file)
- `drift-analysis/src/engine/regex_engine.rs` — regex-based pattern matching
- `drift-analysis/src/engine/resolution.rs` — cross-reference resolution

---

## 5. Flow 4: Analysis Pipeline (The Master Orchestrator)

**Purpose:** `drift_analyze()` is the single NAPI entry point that orchestrates ALL analysis.

**Entry point:** `driftAnalyze()` → `analysis.rs` (1,350 lines)

This is the **most critical flow** — it chains 8 major steps:

```
drift_analyze()
  │
  ├─► Step 1: READ TRACKED FILES from file_metadata table
  │
  ├─► Step 2: PARSE + DETECT (per file)
  │   ├─ ParserManager.parse_returning_tree() → (ParseResult, Tree)
  │   ├─ AnalysisPipeline.analyze_file() → 4-phase detection
  │   ├─ Collect: all_matches, detection_rows, function_rows, all_parse_results
  │   └─ BatchCommand::InsertDetections + InsertFunctions
  │
  ├─► Step 3: CROSS-FILE ANALYSIS
  │   ├─ 3a: BoundaryDetector.detect() → InsertBoundaries
  │   └─ 3b: CallGraphBuilder.build() → InsertCallEdges
  │
  ├─► Step 4: PATTERN INTELLIGENCE
  │   ├─ PatternIntelligencePipeline.run() with DbFeedbackStore
  │   ├─ InsertPatternConfidence (Bayesian scores)
  │   ├─ InsertOutliers (statistical outliers)
  │   └─ InsertConventions (discovered conventions)
  │
  ├─► Step 5: STRUCTURAL ANALYSIS (12 sub-steps, 10 subsystems)
  │   ├─ 5a: Coupling → InsertCouplingMetrics + InsertCouplingCycles
  │   ├─ 5b: Wrappers → InsertWrappers
  │   ├─ 5c: Crypto → InsertCryptoFindings
  │   ├─ 5d: DNA → InsertDnaGenes + InsertDnaMutations
  │   ├─ 5e: Secrets → InsertSecrets
  │   ├─ 5f: Constants → InsertConstants
  │   ├─ 5g: Constraints → insert_constraint_verification (direct write)
  │   ├─ 5h: Env Variables → InsertEnvVariables
  │   ├─ 5i: Data Access → InsertDataAccess
  │   ├─ 5j: OWASP → InsertOwaspFindings
  │   ├─ 5k: Decomposition → InsertDecompositionDecisions
  │   └─ 5l: Contracts → InsertContracts + InsertContractMismatches
  │
  ├─► Step 6: GRAPH INTELLIGENCE (5 sub-steps)
  │   ├─ 6a: Taint analysis → InsertTaintFlows
  │   ├─ 6b: Error handling → InsertErrorGaps
  │   ├─ 6c: Impact analysis → InsertImpactScores
  │   ├─ 6d: Test topology → InsertTestQuality
  │   └─ 6e: Reachability → InsertReachabilityCache
  │
  ├─► Step 7: ENFORCEMENT
  │   ├─ GateInputBuilder + GateOrchestrator.execute()
  │   ├─ InsertViolations
  │   └─ InsertGateResults
  │
  └─► Step 8: DEGRADATION ALERTS
      ├─ Compare current vs previous gate results
      ├─ InsertDegradationAlerts
      └─ Flush BatchWriter
```

**Storage tables written (32 tables via 33 data-carrying BatchCommand variants):**
`file_metadata` (upsert+delete), `detections`, `functions`, `boundaries`, `call_edges`, `pattern_confidence`, `outliers`, `conventions`, `scan_history`, `coupling_metrics`, `coupling_cycles`, `wrappers`, `crypto_findings`, `dna_genes`, `dna_mutations`, `secrets`, `constants`, `constraint_verifications` (direct write), `env_variables`, `data_access`, `owasp_findings`, `decomposition_decisions`, `contracts`, `contract_mismatches`, `taint_flows`, `error_gaps`, `impact_scores`, `test_quality`, `reachability_cache`, `violations`, `gate_results`, `degradation_alerts`

**Note:** The BatchCommand enum has 35 total variants (33 data-carrying + 2 control: `Flush`, `Shutdown`). `InsertParseCache` is data-carrying.

---

## 6. Flow 5: Pattern Intelligence

**Purpose:** Bayesian confidence scoring, outlier detection, convention learning.

```
PatternIntelligencePipeline.run(matches, total_files, now, store)
  │
  ├─► 1. Confidence Scoring (Bayesian)
  │   ├─ 7 factors: frequency, consistency, feedback, data_quality, temporal_decay, category_relative, momentum
  │   ├─ Beta distribution: alpha/beta → posterior_mean
  │   ├─ Credible intervals (95% HDI)
  │   └─ Tier classification: Established / Emerging / Contested / Declining
  │
  ├─► 2. Aggregation
  │   ├─ Group matches by pattern_id
  │   ├─ MinHash similarity (universal hashing)
  │   └─ Incremental aggregation (no full recompute)
  │
  ├─► 3. Outlier Detection
  │   ├─ Normality check (skewness/kurtosis)
  │   ├─ Ensemble: IQR + ESD + Z-score
  │   ├─ confidence_cliff + file_isolation rules
  │   └─ Consensus scoring across methods
  │
  ├─► 4. Convention Learning
  │   ├─ ConventionStore trait (persistence abstraction)
  │   ├─ Dirichlet-based contested detection
  │   ├─ file_spread promotion, directory scope detection
  │   └─ Convergence scoring
  │
  └─► Output: PipelineResult { scores, outliers, conventions, diagnostics }
```

**Key files:**
- `patterns/pipeline.rs` — PatternIntelligencePipeline orchestrator
- `patterns/confidence/scorer.rs` — Bayesian confidence scoring
- `patterns/confidence/factors.rs` — 7 scoring factors
- `patterns/confidence/momentum.rs` — trend momentum tracking
- `patterns/aggregation/pipeline.rs` — aggregation pipeline
- `patterns/aggregation/similarity.rs` — MinHash similarity
- `patterns/outliers/selector.rs` — ensemble outlier detection
- `patterns/outliers/rule_based.rs` — rule-based outlier rules
- `patterns/learning/discovery.rs` — convention discovery
- `patterns/learning/promotion.rs` — convention promotion logic
- `patterns/learning/types.rs` — ConventionStore trait

---

## 7. Flow 6: Structural Analysis (10 Subsystems)

### 6a. Coupling Analysis
```
ImportGraphBuilder::from_parse_results() → compute_martin_metrics() → detect_cycles()
```
- **Martin metrics:** Ce (efferent), Ca (afferent), instability, abstractness, distance-from-main-sequence
- **Cycle detection:** strongly connected components
- **Tables:** `coupling_metrics`, `coupling_cycles`
- **Files:** `structural/coupling/`

### 6b. Wrapper Detection
```
WrapperDetector::detect(content, file) → compute_confidence() → analyze_multi_primitive()
```
- Detects SDK/library wrappers around primitives
- Multi-primitive composite analysis
- **Table:** `wrappers`
- **Files:** `structural/wrappers/`

### 6c. Cryptography Analysis
```
CryptoDetector::detect(content, file, lang) → compute_confidence_batch()
```
- Detects weak crypto, hardcoded keys, deprecated algorithms
- CWE + OWASP mapping per finding
- **Table:** `crypto_findings`
- **Files:** `structural/crypto/`

### 6d. DNA Profiling
```
GeneExtractorRegistry::with_all_extractors()
  → extract_from_file() per file per extractor
  → build_gene() per extractor
  → detect_mutations() across genes
```
- **Gene extractors** (11): naming, error_handling, testing, logging, typing, async, imports, state_management, documentation, security, architecture
- Genes have alleles (variants), dominant allele, consistency score
- Mutations = deviations from dominant pattern
- **Tables:** `dna_genes`, `dna_mutations`
- **Files:** `structural/dna/`

### 6e. Secrets Detection
```
detect_secrets(content, file) → SecretFinding { pattern_name, redacted_value, entropy, confidence }
```
- Shannon entropy-based filtering
- Known token patterns (AWS, GitHub, Slack, etc.)
- **Table:** `secrets`
- **Files:** `structural/constants/secrets.rs`

### 6f. Constants & Magic Numbers
```
detect_magic_numbers(content, file, lang) → MagicNumber { value, suggested_name }
```
- **Table:** `constants`
- **Files:** `structural/constants/magic_numbers.rs`

### 6g. Constraint Verification
```
InvariantDetector → ConstraintStore → ConstraintVerifier::verify_all()
```
- **Invariant types:** MustExist, MustNotExist, MaxCount, MinCount, Pattern
- User-defined constraints stored in DB, verified against parsed code
- **Table:** `constraint_verifications`
- **Files:** `structural/constraints/`

### 6h. Environment Variables
```
extract_env_references(content, file, lang) → EnvReference { name, access_method, has_default }
```
- 8 languages supported
- **Table:** `env_variables`
- **Files:** `structural/constants/env_extraction.rs`

### 6i. Contract Extraction & Matching
```
ExtractorRegistry::extract_all_with_context(content, file, parse_result)
  → match_contracts(backend_eps, frontend_eps)
  → ContractMatch { mismatches }
```
- **14 endpoint extractors:** Express, Fastify, NestJS, Next.js, tRPC, Django, Rails, Flask, Spring, Gin, Actix, ASP.NET, Laravel, Frontend
- **4 schema parsers:** OpenAPI, GraphQL, Protobuf, AsyncAPI
- **7 mismatch types** detected between BE↔FE
- **19 breaking change types** for version comparison
- **Tables:** `contracts`, `contract_mismatches`
- **Files:** `structural/contracts/`

### 6j. Decomposition Analysis
```
decompose_with_priors(input, priors) → Vec<Module> with applied_priors
```
- Service boundary suggestion based on coupling, data access, call patterns
- **Table:** `decomposition_decisions`
- **Files:** `structural/decomposition/`

---

## 8. Flow 7: Graph Intelligence (5 Subsystems)

All 5 depend on the **call graph** built in Step 3b.

### 7a. Call Graph
```
CallGraphBuilder::build(parse_results) → (CallGraph, CallGraphStats)
```
- **petgraph** stable directed graph
- **6 resolution strategies:** SameFile (0.95), Fuzzy (0.40), Import-based, Export-based, DI, Method
- **Files:** `call_graph/builder.rs`, `call_graph/resolution.rs`
- **Table:** `call_edges`

### 7b. Taint Analysis
```
Phase 1: analyze_intraprocedural(parse_result, registry) — per-file
Phase 2: analyze_interprocedural(call_graph, parse_results, registry) — cross-function
```
- TaintRegistry with configurable sources/sinks/sanitizers
- CWE mapping per taint flow
- **Table:** `taint_flows`
- **Files:** `graph/taint/`

### 7c. Error Handling Analysis
```
detect_handlers() → trace_propagation() → analyze_gaps() → map_to_cwe()
```
- Detects error handling patterns and gaps
- Propagation tracing through call graph
- CWE mapping for each gap type
- **Table:** `error_gaps`
- **Files:** `graph/error_handling/`

### 7d. Impact Analysis
```
compute_all_blast_radii(call_graph) + detect_dead_code(call_graph)
```
- Blast radius = transitive caller count + risk score
- Dead code detection with exclusion categories (test, config, etc.)
- **Table:** `impact_scores`
- **Files:** `graph/impact/`

### 7e. Test Topology
```
compute_quality_score(call_graph, parse_results) + detect_all_smells(parse_results, call_graph)
```
- 7 quality dimensions: coverage_breadth, coverage_depth, assertion_density, mock_ratio, isolation, freshness, stability
- Test smell detection
- **Table:** `test_quality`
- **Files:** `graph/test_topology/`

### 7f. Reachability
```
reachability_forward(call_graph, node, max_depth) → classify_sensitivity()
```
- BFS forward reachability with depth limit
- Sensitivity classification per node
- **Table:** `reachability_cache`
- **Files:** `graph/reachability/`

---

## 9. Flow 8: Enforcement Engine

**Purpose:** Quality gates, violations, policies, reports.

```
GateInputBuilder::new()
  .files(file_list)
  .patterns(pattern_info)
  .security_findings_from_taint_flows(taint_flows)
  .error_gaps_from_analysis(error_gaps)
  .test_coverage_from_mapping(total, covered, uncovered, threshold)
  .previous_health_score(prev)
  .current_health_score(curr)
  .baseline_violations(baseline_set)
  .build()
  │
  └─► GateOrchestrator::execute(gate_input)
      │
      ├─► Topological sort (Kahn's algorithm, cycle detection)
      ├─► 6 Quality Gates (dependency-ordered, 30s per-gate timeout):
      │   ├─ Gate 1: PatternCompliance   (no deps)
      │   ├─ Gate 2: ConstraintVerification (deps: [PatternCompliance])
      │   ├─ Gate 3: SecurityBoundaries    (deps: [PatternCompliance])
      │   ├─ Gate 4: TestCoverage          (no deps)
      │   ├─ Gate 5: ErrorHandling         (no deps)
      │   └─ Gate 6: Regression            (no deps, reads predecessor_results)
      │
      ├─► Progressive enforcement (4-phase ramp-up over configurable days)
      ├─► is_new marking (baseline_violations HashSet, key="file:line:rule_id")
      ├─► Policy engine evaluation
      └─► Output: Vec<GateResult> { gate_id, status, passed, score, violations, warnings, execution_time_ms, details, error }
```

### 9a. Gate Threshold Logic (per gate)

| Gate | Empty-Input Behavior | Score Formula | Pass/Fail Threshold |
|------|---------------------|---------------|--------------------|
| **PatternCompliance** | Empty patterns → score=100%, **silently passes** | `locations/(locations+outliers) × 100` | FAIL if any Error-severity outlier (confidence≥0.9); WARN if Warning (≥0.7); else PASS |
| **ConstraintVerification** | Empty constraints → **Skipped** | `passing/total_constraints × 100` | FAIL if any constraint has violations |
| **SecurityBoundaries** | Empty findings → **Skipped** | `(total-error_count)/total × 100` | FAIL if any critical/high finding; WARN if medium; else PASS |
| **TestCoverage** | No coverage data → **Skipped** | `overall_coverage` (direct) | FAIL if `score < threshold`; else PASS |
| **ErrorHandling** | Empty gaps → **Skipped** | `(total-error_count)/total × 100` | FAIL if any swallowed/unhandled gap; WARN if generic/empty_catch; else PASS |
| **Regression** | No previous score → **Skipped** | `current_health_score` (direct) | FAIL if new Error violations OR delta ≤ -15; WARN if delta ≤ -5; else PASS |

**⚠ Critical:** PatternCompliance is the **only** gate that silently passes on empty input (compliance_rate defaults to 1.0). Gates 2-6 skip. This means PatternCompliance always provides a result, and since Gates 2-3 depend on it, they will always evaluate (not skip due to unmet deps) if their own input data exists.

### 9b. Policy Engine (4 aggregation modes, 3 presets)

**4 Aggregation modes:** AllMustPass, AnyMustPass, Weighted, Threshold

| Preset | Mode | Threshold | Required Gates | Weights | Progressive |
|--------|------|-----------|---------------|---------|-------------|
| **Strict** | AllMustPass | 80.0 | All 6 gates | N/A | No |
| **Standard** | Threshold | 70.0 | SecurityBoundaries only | PC:0.25, CV:0.20, SB:0.25, TC:0.15, EH:0.10, R:0.05 | Yes (30d) |
| **Lenient** | AnyMustPass | 50.0 | None | N/A | Yes (60d) |

**Missing required gate = FAIL** (`is_some_and()` — if a required gate's result is absent from results, `check_required_gates()` returns false).

### 9c. Reporter Output Format Details

| Format | Key Implementation Details |
|--------|---------------------------|
| **SARIF 2.1.0** | Taxonomies at `runs[0].taxonomies` (CWE 4.13 + OWASP 2021). Rule relationships at `rules[N].relationships`. Properties include `isNew`. Quick fixes as `fixes[0].description`. |
| **JUnit XML** | `errors` = Error severity count, `failures` = Warning severity count. Each gate = `<testsuite>`, each violation = `<testcase>` with `<failure>`. Skipped gates emit `<skipped />`. |
| **SonarQube** | Has `rules` array (required since SonarQube 10.3). `cleanCodeAttribute: "CONVENTIONAL"`. `impacts` with `softwareQuality` (SECURITY if CWE, else MAINTAINABILITY). Issue types: VULNERABILITY/BUG/CODE_SMELL. |
| **GitHub** | Code Quality annotations. Severity: Error→failure, Warning→warning, Info/Hint→notice. `raw_details` contains CWE+OWASP. |
| **GitLab** | Code Quality format. Fingerprint = hash(rule_id + file + line) for dedup. Categories inferred from rule_id prefix. |
| **JSON** | Direct serde serialization of Vec<GateResult>. |
| **Console** | Human-readable, color-coded output. |
| **HTML** | Full HTML report with styling. |

### 9d. Feedback Types & Bayesian Deltas

**4 FeedbackActions:** Fix, Dismiss, Suppress, Escalate
**4 DismissalReasons:** FalsePositive, WontFix, NotApplicable, Duplicate

| Action | Dismissal Reason | Alpha Delta | Beta Delta | Effect |
|--------|-----------------|-------------|------------|--------|
| Fix | N/A | +1.0 | 0.0 | Strong positive signal |
| Dismiss | FalsePositive | 0.0 | +0.5 | Strong negative signal |
| Dismiss | NotApplicable | 0.0 | +0.25 | Moderate negative |
| Dismiss | WontFix/Duplicate | 0.0 | 0.0 | No change |
| Suppress | N/A | 0.0 | +0.1 | Mild negative |
| Escalate | N/A | +0.5 | 0.0 | Positive signal |

**FeedbackTracker thresholds:** alert at 10% FP rate, auto-disable at 20% FP rate sustained 30+ days, min 10 findings before FP rate is meaningful.

**FeedbackStatsProvider trait** (resolves circular dep between gates↔feedback):
`fp_rate_for_detector()`, `fp_rate_for_pattern()`, `is_detector_disabled()`, `total_actions_for_detector()`
— FeedbackTracker implements this trait. NoOpFeedbackStats returns zeros.

**RulesEvaluator FP integration:** If FP rate > 20% for a pattern_id → severity downgraded one level (Error→Warning→Info→Hint).

**Abuse detection:** FeedbackTracker tracks per-author dismiss timestamps; flags authors exceeding threshold dismissals within a time window.

### 9e. Suppression Formats (4 formats)

| Format | Syntax | Scope |
|--------|--------|-------|
| **drift-ignore** | `// drift-ignore` or `// drift-ignore rule1, rule2` | Universal (requires comment prefix: `//`, `#`, `--`, `/*`) |
| **noqa** | `# noqa` or `# noqa: rule1, rule2` | Python/flake8 |
| **eslint-disable** | `// eslint-disable-next-line` or `// eslint-disable-next-line rule1, rule2` | JS/TS |
| **SuppressWarnings** | `@SuppressWarnings("all")` or `@SuppressWarnings("rule")` | Java/Kotlin |

Checks **both** the current line (inline suppression) and the line immediately above (next-line directive).

### 9f. Quick-Fix Strategies (8 strategies, language-aware)

| Strategy | Triggered By Category | Languages with Templates |
|----------|----------------------|-------------------------|
| Rename | naming, convention | N/A |
| WrapInTryCatch | error_handling, crypto | Python, Rust, Go, Java/Kotlin, Ruby, C#, JS |
| AddImport | import, dependency | N/A |
| AddTypeAnnotation | type_safety | Python, Rust, Go, Java/Kotlin, TS |
| AddDocumentation | documentation | Python, Rust, Go, Ruby, JS |
| AddTest | test_coverage | N/A |
| ExtractFunction | complexity, decomposition | N/A |
| UseParameterizedQuery | security, taint | Python, Rust, Go, Java, Ruby, C#, PHP, JS |

### 9g. Progressive Enforcement (4-phase ramp-up)

```
progress = project_age_days / ramp_up_days
  < 25%:  All violations → Info
  < 50%:  Error → Warning, Warning → Info
  < 75%:  Error stays Error, Warning → Warning
  ≥100%:  Full enforcement
New files always get full enforcement regardless of ramp-up phase.
```

**Key files:**
- `enforcement/gates/orchestrator.rs` — GateOrchestrator (DAG topo-sort, 30s timeout, progressive, is_new)
- `enforcement/gates/types.rs` — GateInput (14 fields), GateResult (10 fields), GateInputBuilder (12 builder methods), QualityGate trait
- `enforcement/gates/pattern_compliance.rs` — Gate 1
- `enforcement/gates/constraint_verification.rs` — Gate 2 (deps: PatternCompliance)
- `enforcement/gates/security_boundaries.rs` — Gate 3 (deps: PatternCompliance)
- `enforcement/gates/test_coverage.rs` — Gate 4
- `enforcement/gates/error_handling.rs` — Gate 5
- `enforcement/gates/regression.rs` — Gate 6 (reads predecessor_results)
- `enforcement/gates/progressive.rs` — ProgressiveEnforcement + ProgressiveConfig
- `enforcement/rules/evaluator.rs` — RulesEvaluator (severity assignment, dedup, FP downgrade)
- `enforcement/rules/types.rs` — Violation (14 fields), Severity (4 levels with penalties: E=10, W=3, I=1, H=0), QuickFix, PatternInfo, OutlierLocation
- `enforcement/rules/quick_fixes.rs` — QuickFixGenerator (8 strategies, 7 languages)
- `enforcement/rules/suppression.rs` — SuppressionChecker (4 formats, bidirectional line check)
- `enforcement/policy/engine.rs` — PolicyEngine (4 aggregation modes)
- `enforcement/policy/types.rs` — Policy (3 presets), PolicyResult, AggregationMode
- `enforcement/reporters/` — 8 reporters (Reporter trait: `name()`, `generate()`)
- `enforcement/audit/` — HealthScorer, DegradationDetector, TrendAnalyzer, DuplicateDetector, AutoApprover
- `enforcement/feedback/types.rs` — FeedbackAction (4), DismissalReason (4), FeedbackMetrics, FeedbackRecord
- `enforcement/feedback/tracker.rs` — FeedbackTracker (implements FeedbackStatsProvider)
- `enforcement/feedback/confidence_feedback.rs` — ConfidenceFeedback (Bayesian alpha/beta adjustment)
- `enforcement/feedback/stats_provider.rs` — FeedbackStatsProvider trait + NoOpFeedbackStats
- **Tables:** `violations`, `gate_results`, `policy_results`, `degradation_alerts`, `feedback`, `audit_snapshots`, `health_trends`

---

## 10. Flow 9: Storage Layer

### drift-storage (45 tables across 7 migrations)

### 10a. DatabaseManager Reader/Writer Pool Architecture

```
DatabaseManager
  ├─ Writer: Mutex<Connection> (serialized writes via mutex lock)
  │   └─ with_writer(|conn| ...) — acquires mutex, passes &Connection
  ├─ Readers: ReadPool (round-robin parallel reads)
  │   ├─ DEFAULT_POOL_SIZE = 4, MAX_POOL_SIZE = 8
  │   ├─ Connections opened with SQLITE_OPEN_READ_ONLY | SQLITE_OPEN_NO_MUTEX
  │   ├─ Read pragmas: query_only=ON, cache_size=-64000, mmap_size=256MB, busy_timeout=5s
  │   └─ with_reader(|conn| ...) — round-robin via AtomicUsize
  ├─ BatchWriter: separate connection via open_batch_connection()
  │   └─ ⚠ In-memory mode: batch connection is ISOLATED (separate DB, writes invisible to main writer)
  └─ Pragmas (writer): WAL, synchronous=NORMAL, foreign_keys=ON, cache_size=-64000 (64MB),
                        mmap_size=256MB, busy_timeout=5s, temp_store=MEMORY, auto_vacuum=INCREMENTAL
```

**Write transaction helper:** `with_immediate_transaction()` — issues `BEGIN IMMEDIATE` then wraps with `unchecked_transaction()` for auto-rollback on drop. Prevents SQLITE_BUSY by acquiring write lock at transaction start.

### 10b. 7 Migration SQL Files (column-level)

| Version | Tables (count) | Columns |
|---------|---------------|----------|
| **v001** | `file_metadata` (1) | path\*, language, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at, scan_duration_us, pattern_count, function_count, error_count, error |
| | `parse_cache` (2) | content_hash\*, language, parse_result_json, created_at |
| | `functions` (3) | id\*, file, name, qualified_name, language, line, end_line, parameter_count, return_type, is_exported, is_async, body_hash, signature_hash |
| | `scan_history` (4) | id\*, started_at, completed_at, root_path, total_files, added_files, modified_files, removed_files, unchanged_files, duration_ms, status, error |
| **v002** | `call_edges` (5) | caller_id, callee_id, resolution, confidence, call_site_line (composite PK) |
| | `data_access` (6) | function_id, table_name, operation, framework, line, confidence (composite PK) |
| | `detections` (7) | id\*, file, line, column_num, pattern_id, category, confidence, detection_method, cwe_ids, owasp, matched_text, created_at |
| | `boundaries` (8) | id\*, file, framework, model_name, table_name, field_name, sensitivity, confidence, created_at |
| **v003** | `pattern_confidence` (9) | pattern_id\*, alpha, beta, posterior_mean, credible_interval_low, credible_interval_high, tier, momentum, last_updated |
| | `outliers` (10) | id\*, pattern_id, file, line, deviation_score, significance, method, created_at |
| | `conventions` (11) | id\*, pattern_id, category, scope, dominance_ratio, promotion_status, discovered_at, last_seen, expires_at |
| **v004** | `reachability_cache` (12) | source_node, direction (composite PK), reachable_set, sensitivity, computed_at |
| | `taint_flows` (13) | id\*, source_file, source_line, source_type, sink_file, sink_line, sink_type, cwe_id, is_sanitized, path, confidence, created_at |
| | `error_gaps` (14) | id\*, file, function_id, gap_type, error_type, propagation_chain, framework, cwe_id, severity, created_at |
| | `impact_scores` (15) | function_id\*, blast_radius, risk_score, is_dead_code, dead_code_reason, exclusion_category, updated_at |
| | `test_coverage` (16) | test_function_id, source_function_id (composite PK), coverage_type |
| | `test_quality` (17) | function_id\*, coverage_breadth, coverage_depth, assertion_density, mock_ratio, isolation, freshness, stability, overall_score, smells, updated_at |
| **v005** | `coupling_metrics` (18) | module\*, ce, ca, instability, abstractness, distance, zone, updated_at |
| | `coupling_cycles` (19) | id\*, members, break_suggestions, created_at |
| | `constraints` (20) | id\*, description, invariant_type, target, scope, source, enabled, created_at, updated_at |
| | `constraint_verifications` (21) | id\*, constraint_id (FK→constraints), passed, violations, verified_at |
| | `contracts` (22) | id\*, paradigm, source_file, framework, confidence, endpoints, created_at, updated_at |
| | `contract_mismatches` (23) | id\*, backend_endpoint, frontend_call, mismatch_type, severity, message, created_at |
| | `constants` (24) | id\*, name, value, file, line, is_used, language, is_named, created_at |
| | `secrets` (25) | id\*, pattern_name, redacted_value, file, line, severity, entropy, confidence, cwe_ids, created_at |
| | `env_variables` (26) | id\*, name, file, line, access_method, has_default, defined_in_env, framework_prefix, created_at |
| | `wrappers` (27) | id\*, name, file, line, category, wrapped_primitives, framework, confidence, is_multi_primitive, is_exported, usage_count, created_at |
| | `dna_genes` (28) | gene_id\*, name, description, dominant_allele, alleles, confidence, consistency, exemplars, updated_at |
| | `dna_mutations` (29) | id\*, file, line, gene_id, expected, actual, impact, code, suggestion, detected_at, resolved, resolved_at |
| | `crypto_findings` (30) | id\*, file, line, category, description, code, confidence, cwe_id, owasp, remediation, language, created_at |
| | `owasp_findings` (31) | id\*, detector, file, line, description, severity, cwes, owasp_categories, confidence, remediation, created_at |
| | `decomposition_decisions` (32) | id\*, dna_profile_hash, adjustment, confidence, dna_similarity, narrative, source_dna_hash, applied_weight, created_at |
| **v006** | ⚠ v006 has **MIGRATION_SQL_PART2** — separate execution after main SQL | |
| *(Part 1)* | `violations` (33) | id\*, file, line, column_num, end_line, end_column, severity, pattern_id, rule_id, message, quick_fix_strategy, quick_fix_description, cwe_id, owasp_category, suppressed, is_new, created_at |
| | `gate_results` (34) | id\*, gate_id, status, passed, score, summary, violation_count, warning_count, execution_time_ms, details, error, run_at |
| *(Part 2)* | `audit_snapshots` (35) | id\*, health_score, avg_confidence, approval_ratio, compliance_rate, cross_validation_rate, duplicate_free_rate, pattern_count, category_scores, created_at |
| | `health_trends` (36) | id\*, metric_name, metric_value, recorded_at |
| | `feedback` (37) | id\*, violation_id, pattern_id, detector_id, action, dismissal_reason, reason, author, created_at |
| | `policy_results` (38) | id\*, policy_name, aggregation_mode, overall_passed, overall_score, gate_count, gates_passed, gates_failed, details, run_at |
| | `degradation_alerts` (39) | id\*, alert_type, severity, message, current_value, previous_value, delta, created_at |
| **v007** | `simulations` (40) | id\*, task_category, task_description, approach_count, recommended_approach, p10_effort, p50_effort, p90_effort, created_at |
| | `decisions` (41) | id\*, category, description, commit_sha, confidence, related_patterns, author, files_changed, created_at |
| | `context_cache` (42) | id\*, session_id, intent, depth, token_count, content_hash, created_at |
| | `migration_projects` (43) | id\*, name, source_language, target_language, source_framework, target_framework, status, created_at |
| | `migration_modules` (44) | id\*, project_id (FK→migration_projects), module_name, status, spec_content, created_at, updated_at |
| | `migration_corrections` (45) | id\*, module_id (FK→migration_modules), section, original_text, corrected_text, reason, created_at |

\* = PRIMARY KEY

### 10c. 16 Query Modules (function domains)

| Module | Domain | Key Tables Served |
|--------|--------|-------------------|
| `files` | File metadata CRUD | file_metadata |
| `parse_cache` | Parse result cache | parse_cache |
| `functions` | Function registry | functions |
| `call_edges` | Call graph edges | call_edges |
| `detections` | Detection results | detections |
| `boundaries` | ORM boundary detection | boundaries |
| `patterns` | Pattern intelligence | pattern_confidence, outliers, conventions |
| `graph` | Graph intelligence | taint_flows, error_gaps, impact_scores, test_coverage, test_quality, reachability_cache |
| `structural` | Structural intelligence | coupling_metrics, coupling_cycles, constraints, constraint_verifications, contracts, contract_mismatches, constants, secrets, env_variables, wrappers, dna_genes, dna_mutations, crypto_findings, owasp_findings, decomposition_decisions |
| `enforcement` | Enforcement engine | violations, gate_results, audit_snapshots, health_trends, feedback, policy_results, degradation_alerts |
| `constants` | Named constants | constants |
| `data_access` | Data access patterns | data_access |
| `env_variables` | Environment variables | env_variables |
| `scan_history` | Scan lifecycle | scan_history |
| `advanced` | Simulations/decisions | simulations, decisions, context_cache, migration_projects, migration_modules, migration_corrections |
| `util` | Shared SQL helpers | N/A |

**35 BatchCommand variants** (33 data-carrying + 2 control):

*Data commands (used by drift_analyze + scan):*
`UpsertFileMetadata`, `DeleteFileMetadata`, `InsertParseCache`, `InsertDetections`, `InsertFunctions`, `InsertBoundaries`, `InsertCallEdges`, `InsertPatternConfidence`, `InsertOutliers`, `InsertConventions`, `InsertScanHistory`, `InsertDataAccess`, `InsertCouplingMetrics`, `InsertCouplingCycles`, `InsertWrappers`, `InsertCryptoFindings`, `InsertDnaGenes`, `InsertDnaMutations`, `InsertSecrets`, `InsertConstants`, `InsertEnvVariables`, `InsertOwaspFindings`, `InsertDecompositionDecisions`, `InsertContracts`, `InsertContractMismatches`, `InsertTaintFlows`, `InsertErrorGaps`, `InsertImpactScores`, `InsertTestQuality`, `InsertReachabilityCache`, `InsertViolations`, `InsertGateResults`, `InsertDegradationAlerts`

*Control commands:*
`Flush`, `Shutdown`

### 10d. Retention Tier Assignments (4 tiers)

**Tier 0 — Current (orphan cleanup):** Removes rows referencing files no longer in `file_metadata`.
- `detections`, `functions`, `boundaries`, `constants`, `secrets`, `env_variables`, `wrappers`, `crypto_findings`, `owasp_findings`

**Tier 1 — Short (30 days):**
- `detections`\*, `outliers`, `violations`, `gate_results`, `error_gaps`, `taint_flows`, `crypto_findings`\*, `owasp_findings`\*, `secrets`\*, `degradation_alerts`, `policy_results`
- \*Tables marked with \* also have orphan cleanup (double cleanup path)

**Tier 2 — Medium (90 days):**
- `scan_history`, `audit_snapshots`, `health_trends`, `feedback`, `constraint_verifications`, `contract_mismatches`, `dna_mutations`, `coupling_cycles`, `decomposition_decisions`

**Tier 3 — Long (365 days):**
- `parse_cache`, `context_cache`, `simulations`, `decisions`, `migration_corrections`, `migration_modules`, `migration_projects`

**Self-bounding (UPSERT, no retention needed):** `file_metadata`, `pattern_confidence`, `impact_scores`, `coupling_metrics`, `constraints`, `contracts`, `dna_genes`, `reachability_cache`, `test_coverage`, `test_quality`, `data_access`, `call_edges`

**Not covered by retention:** `migration_projects`, `migration_modules` FK cascade from projects (Long tier deletes projects, ON DELETE CASCADE would handle modules — but no FK CASCADE defined, so modules/corrections cleaned independently)

### cortex-storage (20+ tables, 15 migrations)

**19 query modules:** `memory_crud`, `link_ops`, `causal_ops`, `vector_search`, `version_ops`, `rollback`, `audit_ops`, `event_ops`, `session_ops`, `drift_ops`, `snapshot_ops`, `temporal_ops`, `multiagent_ops`, `view_ops`, `maintenance`, `compaction`, `recovery`, `aggregation`

### cortex-drift-bridge storage (6 files)
Shared schema between drift.db and cortex.db for grounding, licensing, and link translation.

---

## 11. Flow 10: NAPI Bindings (109 total)

### Drift NAPI (41 Rust exports across 9 modules — 40 in TS contract)

> **Audit finding:** Rust exports 41 `#[napi]` functions. The TS `DriftNapi` interface (`packages/drift-napi-contracts/src/interface.ts`) exposes 40.
> **Gap:** `driftScanHistory(limit?: u32) → Vec<JsScanHistoryEntry>` exists in Rust (`scanner.rs:412`) but is missing from TS contract.

#### lifecycle.rs (4 functions)

| JS Name | Rust Signature | Return Type | Async |
|---------|---------------|-------------|-------|
| `driftInitialize` | `(db_path: Option<String>, project_root: Option<String>, config_toml: Option<String>)` | `napi::Result<()>` → `void` | No |
| `driftShutdown` | `()` | `napi::Result<()>` → `void` | No |
| `driftIsInitialized` | `()` | `bool` → `boolean` | No |
| `driftGC` | `(short_days: Option<u32>, medium_days: Option<u32>, long_days: Option<u32>)` | `napi::Result<serde_json::Value>` → `GcResult` | No |

#### scanner.rs (4 functions — 3 in TS)

| JS Name | Rust Signature | Return Type | Async | TS? |
|---------|---------------|-------------|-------|-----|
| `driftScan` | `(root: String, options: Option<ScanOptions>)` | `AsyncTask<ScanTask>` → `Promise<ScanSummary>` | Yes | ✓ |
| `driftScanWithProgress` | `(root: String, options: Option<ScanOptions>, on_progress: ThreadsafeFunction<ProgressUpdate, ()>)` | `AsyncTask<ScanWithProgressTask>` → `Promise<ScanSummary>` | Yes | ✓ |
| `driftCancelScan` | `()` | `napi::Result<()>` → `void` | No | ✓ |
| `driftScanHistory` | `(limit: Option<u32>)` | `napi::Result<Vec<JsScanHistoryEntry>>` | No | **⚠ MISSING** |

#### analysis.rs (3 functions)

| JS Name | Rust Signature | Return Type | Async |
|---------|---------------|-------------|-------|
| `driftAnalyze` | `()` | `napi::Result<Vec<JsAnalysisResult>>` → `Promise<JsAnalysisResult[]>` | Yes |
| `driftCallGraph` | `()` | `napi::Result<JsCallGraphResult>` → `Promise<JsCallGraphResult>` | Yes |
| `driftBoundaries` | `()` | `napi::Result<JsBoundaryResult>` → `Promise<JsBoundaryResult>` | Yes |

**Key types:** `JsAnalysisResult { file, language, matches: Vec<JsPatternMatch>, analysis_time_us }`, `JsPatternMatch { file, line, column, pattern_id, confidence, category, detection_method, matched_text, cwe_ids, owasp }`, `JsCallGraphResult { total_functions, total_edges, entry_points, resolution_rate, build_duration_ms }`, `JsBoundaryResult { models, sensitive_fields, frameworks_detected }`

#### patterns.rs (4 functions)

| JS Name | Rust Signature | Return Type | Async |
|---------|---------------|-------------|-------|
| `driftPatterns` | `(category: Option<String>, after_id: Option<String>, limit: Option<u32>)` | `Result<serde_json::Value>` → `PatternsResult` | No |
| `driftConfidence` | `(tier: Option<String>, after_id: Option<String>, limit: Option<u32>)` | `Result<serde_json::Value>` → `ConfidenceResult` | No |
| `driftOutliers` | `(pattern_id: Option<String>, after_id: Option<u32>, limit: Option<u32>)` | `Result<serde_json::Value>` → `OutlierResult` | No |
| `driftConventions` | `(category: Option<String>, after_id: Option<u32>, limit: Option<u32>)` | `Result<serde_json::Value>` → `ConventionResult` | No |

> Note: Rust returns `serde_json::Value` (dynamic JSON); TS types (`PatternsResult`, etc.) provide stricter typing over the JSON shape. All support keyset pagination via `after_id`/`limit`.

#### graph.rs (5 functions)

| JS Name | Rust Signature | Return Type | Async |
|---------|---------------|-------------|-------|
| `driftReachability` | `(function_key: String, direction: String)` | `napi::Result<JsReachabilityResult>` | No |
| `driftTaintAnalysis` | `(root: String)` | `napi::Result<JsTaintResult>` | No |
| `driftErrorHandling` | `(root: String)` | `napi::Result<JsErrorHandlingResult>` | No |
| `driftImpactAnalysis` | `(root: String)` | `napi::Result<JsImpactResult>` | No |
| `driftTestTopology` | `(root: String)` | `napi::Result<JsTestTopologyResult>` | No |

#### structural.rs (9 functions)

| JS Name | Rust Signature | Return Type | Async |
|---------|---------------|-------------|-------|
| `driftCouplingAnalysis` | `(root: String)` | `napi::Result<JsCouplingResult>` | No |
| `driftConstraintVerification` | `(root: String)` | `napi::Result<JsConstraintResult>` | No |
| `driftContractTracking` | `(root: String)` | `napi::Result<JsContractResult>` | No |
| `driftConstantsAnalysis` | `(root: String)` | `napi::Result<JsConstantsResult>` | No |
| `driftWrapperDetection` | `(root: String)` | `napi::Result<JsWrapperResult>` | No |
| `driftDnaAnalysis` | `(root: String)` | `napi::Result<JsDnaResult>` | No |
| `driftOwaspAnalysis` | `(root: String)` | `napi::Result<JsOwaspResult>` | No |
| `driftCryptoAnalysis` | `(root: String)` | `napi::Result<JsCryptoResult>` | No |
| `driftDecomposition` | `(root: String)` | `napi::Result<JsDecompositionResult>` | No |

#### enforcement.rs (5 functions)

| JS Name | Rust Signature | Return Type | Async |
|---------|---------------|-------------|-------|
| `driftCheck` | `(_root: String)` | `napi::Result<JsCheckResult>` | No |
| `driftAudit` | `(_root: String)` | `napi::Result<JsAuditResult>` | No |
| `driftViolations` | `(_root: String)` | `napi::Result<Vec<JsViolation>>` | No |
| `driftReport` | `(format: String)` | `napi::Result<String>` | No |
| `driftGates` | `(_root: String)` | `napi::Result<Vec<JsGateResult>>` | No |

**Key types:** `JsCheckResult { overall_passed, total_violations, gates, sarif }`, `JsViolation { id, file, line, column, end_line, end_column, severity, pattern_id, rule_id, message, quick_fix_strategy, quick_fix_description, cwe_id, owasp_category, suppressed, is_new }` (16 fields), `JsGateResult { gate_id, status, passed, score, summary, violation_count, warning_count, execution_time_ms, details, error }` (10 fields), `JsAuditResult { health_score, breakdown, trend, degradation_alerts, auto_approved_count, needs_review_count }`

#### feedback.rs (3 functions)

| JS Name | Rust Signature | Return Type | Async |
|---------|---------------|-------------|-------|
| `driftDismissViolation` | `(input: JsFeedbackInput)` | `napi::Result<JsFeedbackResult>` | No |
| `driftFixViolation` | `(violation_id: String)` | `napi::Result<JsFeedbackResult>` | No |
| `driftSuppressViolation` | `(violation_id: String, reason: String)` | `napi::Result<JsFeedbackResult>` | No |

**Key types:** `JsFeedbackInput { violation_id, action, reason? }`, `JsFeedbackResult { success, message }`

#### advanced.rs (4 functions)

| JS Name | Rust Signature | Return Type | Async |
|---------|---------------|-------------|-------|
| `driftSimulate` | `(task_category: String, task_description: String, context_json: String)` | `Result<String>` → `Promise<string>` | Yes |
| `driftDecisions` | `(repo_path: String)` | `Result<String>` → `Promise<string>` | Yes |
| `driftContext` | `(intent: String, depth: String, data_json: String)` | `Result<String>` → `Promise<string>` | Yes |
| `driftGenerateSpec` | `(module_json: String, migration_path_json: Option<String>)` | `Result<String>` → `Promise<string>` | Yes |

### TS Contract Package (`packages/drift-napi-contracts/`)

**Single source of truth** for Rust↔TypeScript signatures: `DriftNapi` interface (40 methods), `createStubNapi()` fallback, `loadNapi()` singleton loader with validation of all 40 method names, `setNapi()` test injection, `NapiLoadError` for missing functions.

### Cortex NAPI (68 functions across 17 modules)

| Module | Functions | Purpose |
|--------|-----------|---------|
| `lifecycle.rs` | configure, shutdown, isInitialized | Runtime lifecycle |
| `memory.rs` | create, get, update, delete, search, list, bulkInsert | Memory CRUD |
| `causal.rs` | addEdge, getGraph, infer | Causal reasoning |
| `cloud.rs` | sync, resolveConflict, getStatus | Cloud sync |
| `consolidation.rs` | run, getStats | Memory consolidation |
| `decay.rs` | run, getSchedule, preview | Time-based decay |
| `embeddings.rs` | embed, reembed, search, reembedMemory | Vector embeddings |
| `generation.rs` | summarize, generateInsights | AI generation |
| `health.rs` | getSnapshot, getDashboard | System health |
| `learning.rs` | recordInteraction, getPatterns | Learning from usage |
| `multiagent.rs` | register, deregister, sync, namespace, permissions, trust, projections, provenance, deltaQueue | Multi-agent coordination |
| `prediction.rs` | predict, getAccuracy | Usage prediction |
| `privacy.rs` | sanitize, getReport | Privacy/PII protection |
| `retrieval.rs` | retrieve, getRelevant | Memory retrieval |
| `session.rs` | create, end, getAnalytics | Session management |
| `temporal.rs` | getTimeline, getDiff, getAlerts, timeTravel, getCausal, getViews | Temporal intelligence |
| `validation.rs` | run (4-dimension validation) | Memory validation |

---

## 12. Flow 11: Presentation Layer

### MCP Server (`packages/drift-mcp/`)
```
MCP Server (stdio/SSE transport)
  ├─► 6 registered entry points:
  │   drift_status   — project overview (<1ms, reads materialized view)
  │   drift_context   — intent-weighted deep dive (replaces 3-5 tool calls)
  │   drift_scan      — trigger scan + analysis (mutates DB)
  │   drift_tool      — dynamic dispatch to 40 drift + 61 cortex internal tools
  │   drift_discover  — intent-guided tool recommendation
  │   drift_workflow  — composite multi-tool workflows (pre_commit, security_audit, etc.)
  │
  ├─► 40 drift internal tools (via drift_tool dispatch):
  │   See full catalog below
  │
  ├─► 61 cortex internal tools (via cortex_tools.ts):
  │   See full catalog below
  │
  └─► Infrastructure layer (7 modules):
      cache, rate_limiter, token_estimator, error_handler,
      cursor_manager, response_builder, tool_filter
```

#### Drift Internal Tool Catalog (40 tools)

| # | Tool Name | Category | NAPI Method Called |
|---|-----------|----------|-------------------|
| 1 | `drift_status` | discovery | `driftIsInitialized`, `driftViolations`, `driftAudit`, `driftCheck` (composite) |
| 2 | `drift_capabilities` | discovery | (lists catalog — no NAPI) |
| 3 | `drift_callers` | surgical | `driftCallGraph` |
| 4 | `drift_reachability` | surgical | `driftReachability(functionKey, direction)` |
| 5 | `drift_prevalidate` | surgical | `driftCheck(path)` |
| 6 | `drift_similar` | surgical | `driftPatterns(category, afterId, limit)` |
| 7 | `drift_patterns_list` | exploration | `driftPatterns(category, afterId, limit)` |
| 8 | `drift_security_summary` | exploration | `driftOwaspAnalysis(path)` |
| 9 | `drift_trends` | exploration | `driftAudit(root)` |
| 10 | `drift_impact_analysis` | detail | `driftImpactAnalysis(root)` |
| 11 | `drift_taint` | detail | `driftTaintAnalysis(root)` |
| 12 | `drift_dna_profile` | detail | `driftDnaAnalysis(root)` |
| 13 | `drift_wrappers` | detail | `driftWrapperDetection(root)` |
| 14 | `drift_coupling` | analysis | `driftCouplingAnalysis(root)` |
| 15 | `drift_test_topology` | analysis | `driftTestTopology(root)` |
| 16 | `drift_error_handling` | analysis | `driftErrorHandling(root)` |
| 17 | `drift_quality_gate` | analysis | `driftGates(root)` |
| 18 | `drift_constants` | analysis | `driftConstantsAnalysis(root)` |
| 19 | `drift_constraints` | analysis | `driftConstraintVerification(root)` |
| 20 | `drift_audit` | analysis | `driftAudit(root)` |
| 21 | `drift_decisions` | analysis | `driftDecisions(repoPath)` |
| 22 | `drift_simulate` | analysis | `driftSimulate(category, description, contextJson)` |
| 23 | `drift_explain` | generation | `driftContext(query, 'deep', '{}')` |
| 24 | `drift_validate_change` | generation | `driftCheck(root)` |
| 25 | `drift_suggest_changes` | generation | `driftViolations(root)` |
| 26 | `drift_generate_spec` | generation | `driftGenerateSpec(moduleJson, migrationPathJson)` |
| 27 | `drift_outliers` | exploration | `driftOutliers(patternId, afterId, limit)` |
| 28 | `drift_conventions` | exploration | `driftConventions(category, afterId, limit)` |
| 29 | `drift_owasp` | analysis | `driftOwaspAnalysis(root)` |
| 30 | `drift_crypto` | analysis | `driftCryptoAnalysis(root)` |
| 31 | `drift_decomposition` | analysis | `driftDecomposition(root)` |
| 32 | `drift_contracts` | exploration | `driftContractTracking(root)` |
| 33 | `drift_dismiss` | feedback | `driftDismissViolation(input)` |
| 34 | `drift_fix` | feedback | `driftFixViolation(violationId)` |
| 35 | `drift_suppress` | feedback | `driftSuppressViolation(violationId, reason)` |
| 36 | `drift_scan_progress` | operational | `driftScanWithProgress(path, options, callback)` |
| 37 | `drift_cancel_scan` | operational | `driftCancelScan()` |
| 38 | `drift_analyze` | operational | `driftAnalyze()` |
| 39 | `drift_report` | generation | `driftReport(format)` |
| 40 | `drift_gc` | operational | `driftGC(shortDays, mediumDays, longDays)` |

#### Cortex Internal Tool Catalog (61 tools)

| Category | Tools | Count |
|----------|-------|-------|
| Memory | `cortex_memory_add`, `_search`, `_get`, `_update`, `_delete`, `_list`, `_link`, `_unlink`, `_restore` | 9 |
| Retrieval | `cortex_context`, `cortex_search`, `cortex_related` | 3 |
| Why/Causal | `cortex_why`, `cortex_explain`, `cortex_counterfactual`, `cortex_intervention`, `cortex_causal_infer` | 5 |
| Learning | `cortex_learn`, `cortex_feedback`, `cortex_validate` | 3 |
| Generation | `cortex_gen_context`, `cortex_gen_outcome` | 2 |
| System | `cortex_status`, `_metrics`, `_consolidate`, `_validate_system`, `_gc`, `_export`, `_import`, `_reembed` | 8 |
| Privacy | `cortex_privacy_sanitize`, `cortex_privacy_stats` | 2 |
| Cloud | `cortex_cloud_sync`, `_status`, `_resolve` | 3 |
| Session | `cortex_session_create`, `_get`, `_analytics` | 3 |
| Prediction | `cortex_predict`, `cortex_preload` | 2 |
| Temporal | `cortex_time_travel`, `_diff`, `_replay`, `_range`, `cortex_temporal_causal`, `cortex_knowledge_health`, `_timeline`, `cortex_view_create`, `_get`, `_list` | 10 |
| Multi-Agent | `cortex_agent_register`, `_share`, `_project`, `_provenance`, `_trust`, `_deregister`, `_get`, `_list`, `_namespace`, `_retract`, `_sync` | 11 |

> **Note:** `cortex_tools.ts` line 414 comment says "Cortex tools (40)" — this is stale; actual count is 61.

### CLI (`packages/drift-cli/`)

**27 commands** (+ cortex umbrella with subcommands):

| # | Command | NAPI Method(s) Called | Category |
|---|---------|----------------------|----------|
| 1 | `scan` | `driftScan(path, options)` | Core |
| 2 | `analyze` | `driftAnalyze()` | Core |
| 3 | `check` | `driftCheck(path)`, `driftReport('sarif')` (for `--format sarif`) | Core |
| 4 | `status` | `driftIsInitialized()`, `driftViolations('.')`, `driftAudit('.')`, `driftCheck('.')` | Core |
| 5 | `report` | `driftReport(format)` | Core |
| 6 | `patterns` | `driftPatterns(category, afterId, limit)` | Exploration |
| 7 | `violations` | `driftViolations(root)` | Exploration |
| 8 | `security` | `driftOwaspAnalysis(path)` | Exploration |
| 9 | `contracts` | `driftContractTracking(path)` | Exploration |
| 10 | `coupling` | `driftCouplingAnalysis(path)` | Exploration |
| 11 | `dna` | `driftDnaAnalysis(path)` | Exploration |
| 12 | `taint` | `driftTaintAnalysis(path)` | Exploration |
| 13 | `errors` | `driftErrorHandling(path)` | Exploration |
| 14 | `test-quality` | `driftTestTopology(path)` | Exploration |
| 15 | `impact` | `driftImpactAnalysis(path)` | Exploration |
| 16 | `fix` | `driftFixViolation(violationId)` | Feedback |
| 17 | `dismiss` | `driftDismissViolation(input)` | Feedback |
| 18 | `suppress` | `driftSuppressViolation(violationId, reason)` | Feedback |
| 19 | `explain` | `driftContext(intent, depth, dataJson)` | Feedback |
| 20 | `simulate` | `driftSimulate(category, description, contextJson)` | Advanced |
| 21 | `context` | `driftContext(intent, depth, dataJson)` | Advanced |
| 22 | `audit` | `driftAudit(root)` | Advanced |
| 23 | `export` | `driftReport(format)` / `driftViolations(root)` | Advanced |
| 24 | `gc` | `driftGC(shortDays, mediumDays, longDays)` | Operational |
| 25 | `setup` | `driftInitialize(dbPath, projectRoot)` | Operational |
| 26 | `doctor` | `driftIsInitialized()` + diagnostic checks | Operational |
| 27 | `cortex` | Cortex NAPI functions via `@drift/cortex` | Operational |

> **Note:** `index.ts` header comment says "26 commands" — this is stale; actual count is 27 (cortex added in Phase B).

### CI Agent (`packages/drift-ci/`)

**10 analysis passes** (run in parallel with timeout + error handling):

| # | Pass Name | NAPI Method(s) Called | Pass/Fail Logic |
|---|-----------|----------------------|-----------------|
| 1 | `scan` | `driftScan(path, options)` → `driftAnalyze()` | Always passes (populates DB) |
| 2 | `patterns` | `driftPatterns()` | Always passes (informational) |
| 3 | `call_graph` | `driftCallGraph()` | Always passes (informational) |
| 4 | `boundaries` | `driftBoundaries()` | Always passes (informational) |
| 5 | `security` | `driftOwaspAnalysis(path)` | Fails if `findings.length > 0` |
| 6 | `tests` | `driftTestTopology(path)` | Always passes (informational) |
| 7 | `errors` | `driftErrorHandling(path)` | Always passes (informational) |
| 8 | `contracts` | `driftContractTracking(path)` | Fails if `mismatches.length > 0` |
| 9 | `constraints` | `driftConstraintVerification(path)` | Fails if `failing > 0` |
| 10 | `enforcement` | `driftCheck(path)` | Fails if `!overallPassed` |

#### CI Weighted Scoring Formula

```
Score = Σ(pass_score × weight) / Σ(weight)    where weight > 0

Pass scores: passed = 100, failed = 50, error = 0

Weights (sum to 1.0):
  scan:         0.15    (15%)
  patterns:     0.10    (10%)
  call_graph:   0.00    (informational — excluded from score)
  boundaries:   0.00    (informational — excluded from score)
  security:     0.20    (20%)  ← highest weight
  tests:        0.15    (15%)
  errors:       0.10    (10%)
  contracts:    0.10    (10%)
  constraints:  0.05    ( 5%)
  enforcement:  0.15    (15%)

Final score: round(weighted_average), range 0-100
Overall status: FAIL if score < threshold OR (failOn='error' AND any failed/error) OR (failOn='warning' AND totalViolations > 0)
```

**Post-analysis outputs:** PR comment generation (markdown), SARIF file export, JSON output

---

## 13. Flow 12: Cortex Memory System

**21 Rust crates** (20 cortex-* crates + test-fixtures) forming a complete memory management system:

```
cortex-napi (68 NAPI bindings)
  └─► CortexRuntime (OnceLock singleton)
      ├─ StorageEngine (writer mutex + read pool)
      ├─ EmbeddingEngine (3-tier cache: L1 HashMap → L2 SQLite → L3 provider)
      ├─ ConsolidationEngine (episodic + procedural consolidation)
      ├─ DecayEngine (time-based memory decay)
      ├─ LearningEngine (interaction-based learning)
      ├─ TemporalEngine (timeline, drift detection, time travel)
      ├─ CausalEngine (causal graph, inference)
      ├─ PredictionEngine (usage prediction)
      ├─ PrivacyEngine (PII sanitization)
      ├─ RetrievalEngine (ranked retrieval, RRF)
      ├─ ValidationEngine (4-dimension validation)
      ├─ MultiAgentEngine (agents, namespaces, permissions, trust, deltas)
      ├─ CloudEngine (sync, conflict resolution, quota)
      ├─ SessionEngine (session lifecycle)
      ├─ ObservabilityEngine (metrics, health)
      └─ GenerationEngine (summarization, insights)
```

**Memory lifecycle:**
```
Create → Embed → Store → Retrieve → Update (re-embed) → Consolidate → Decay → Archive
```

**Key subsystems:**
- **Embeddings:** TF-IDF fallback → ONNX → API provider, with degradation chain
- **Consolidation:** Episodic + Procedural memories, phase1 selection → phase2 merge
- **Causal:** Directed graph with inference, stored in SQLite, sync from storage
- **Multi-agent:** Agent registry, namespaces (Agent/Team/Project scope), RBAC permissions, trust scoring, CRDT delta queue, projections, provenance
- **Temporal:** Bitemporal storage (valid_at + transaction_time), drift alerts, time travel queries

---

## 14. Flow 13: Cortex-Drift Bridge

**Purpose:** Connects Cortex memories to Drift analysis data for grounding.

```
cortex-drift-bridge (15 subsystems)
  ├─ grounding/ — evidence collection from drift.db to ground memories
  │   ├─ evidence/collector.rs — 10 evidence types
  │   ├─ evidence/types.rs — EvidenceType enum
  │   ├─ loop_runner.rs — grounding loop (single + batch)
  │   └─ scoring/ — grounding score computation
  │
  ├─ causal/ — causal narrative generation from analysis
  ├─ config/ — shared configuration
  ├─ errors/ — unified error types
  ├─ event_mapping/ — drift events → cortex temporal events
  ├─ health/ — cross-system health monitoring
  ├─ intents/ — intent classification
  ├─ license/ — licensing integration
  ├─ link_translation/ — cross-DB link resolution
  ├─ napi/ — 20 NAPI-ready functions
  ├─ query/ — cross-DB queries
  ├─ specification/ — spec generation from analysis
  ├─ storage/ — shared schema DDL
  ├─ tools/ — 6 MCP tool handlers
  └─ types/ — shared types
```

**10 evidence types for grounding:**
pattern_confidence, occurrence_rate, temporal_stability, cross_validation, file_coverage, detection_method_agreement, outlier_status, convention_alignment, enforcement_status, community_signal

---

## 15. Flow 14: Advanced Systems

### Simulation Engine
```
driftSimulate(category, description, context)
  └─► StrategyRecommender::recommend(task)
      ├─ 13 task categories (add_feature, fix_bug, refactor, etc.)
      ├─ Monte Carlo confidence intervals
      └─ Strategy recommendations with risk assessment
```

### Decision Mining
```
driftDecisions(repo_path)
  └─► GitAnalyzer::analyze(path)
      ├─ Parses git log (up to 500 commits)
      └─ Extracts architectural decisions from commit patterns
```

### Context Generation
```
driftContext(intent, depth, data)
  └─► ContextEngine::generate(intent, depth, analysis_data)
      ├─ 5 intents: FixBug, AddFeature, UnderstandCode, SecurityAudit, GenerateSpec
      ├─ 3 depths: Overview, Standard, Deep
      └─ Token-counted sectioned output
```

### Specification Generation
```
driftGenerateSpec(module, migration_path)
  └─► SpecificationRenderer::render(module, migration)
      └─ Generates migration specs with source→target language/framework
```

---

## 16. Master Data Flow Diagram

```
                         USER / AGENT
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
         drift-cli       drift-mcp       drift-ci
              │               │               │
              └───────┬───────┘               │
                      ▼                       │
              drift-napi-contracts             │
                      │                       │
         ┌────────────┼───────────────────────┘
         ▼            ▼
    drift-napi    cortex-napi
         │            │
         ▼            ▼
    DriftRuntime  CortexRuntime
         │            │
         │    ┌───────┘
         │    │   cortex-drift-bridge
         │    │       │
         ▼    ▼       ▼
    ┌─────────────────────────────────────────────┐
    │              drift_analyze()                  │
    │                                              │
    │  Scanner → Parser → Detector → PatternIntel  │
    │     │         │        │            │        │
    │     ▼         ▼        ▼            ▼        │
    │  Structural Analysis (10 subsystems)          │
    │     │                                        │
    │     ▼                                        │
    │  Graph Intelligence (5 subsystems)            │
    │     │                                        │
    │     ▼                                        │
    │  Enforcement Engine (6 gates)                 │
    │     │                                        │
    │     ▼                                        │
    │  Degradation Alerts                          │
    └──────────────────┬──────────────────────────┘
                       │
                       ▼
                   drift.db
              (45 tables, WAL mode)
                       │
              ┌────────┼────────┐
              ▼        ▼        ▼
          Queries   Reports   Feedback
           (16       (8         loop
          modules)  formats)
```

---

## 17. Database Schema Map

### drift.db — 45 tables

**Tier 1: Source Data (v001)**
- `file_metadata` — tracked files (path, hash, mtime, language, size)
- `parse_cache` — parse result cache keyed by content_hash
- `functions` — extracted functions (name, params, return_type, hashes)
- `scan_history` — scan runs (start, end, counts, duration, status)

**Tier 2: Cross-File Analysis (v002)**
- `call_edges` — function call relationships (caller→callee with resolution strategy)
- `data_access` — function→table access patterns (ORM/query detection)
- `detections` — pattern matches (file, line, pattern_id, confidence, category)
- `boundaries` — ORM models + sensitive fields

**Tier 3: Pattern Intelligence (v003)**
- `pattern_confidence` — Bayesian scores (alpha, beta, posterior_mean, tier)
- `outliers` — statistical outliers (⚠ table name is `outliers`, NOT `outlier_detections`)
- `conventions` — discovered conventions

**Tier 4: Graph Intelligence (v004)**
- `reachability_cache` — forward reachability cache
- `taint_flows` — taint analysis flows (source→sink)
- `error_gaps` — error handling gaps
- `impact_scores` — blast radius + dead code
- `test_coverage` — test→source function mapping
- `test_quality` — test quality scores + smells

**Tier 5: Structural (v005, 15 tables)**
- `coupling_metrics` — Martin metrics per module
- `coupling_cycles` — dependency cycles
- `constraints` — user-defined invariants
- `constraint_verifications` — verification results
- `contracts` — API endpoint contracts
- `contract_mismatches` — BE↔FE contract mismatches
- `constants` — magic numbers
- `secrets` — detected secrets/tokens
- `env_variables` — environment variable references
- `wrappers` — wrapper/SDK detection
- `dna_genes` — codebase DNA genes
- `dna_mutations` — DNA mutations/deviations
- `crypto_findings` — cryptographic issues
- `owasp_findings` — OWASP/CWE enriched findings
- `decomposition_decisions` — service boundary suggestions

**Tier 6: Enforcement (v006, 7 tables in 2 parts)**
- `violations` — quality gate violations
- `gate_results` — gate execution results
- `audit_snapshots` — periodic audit snapshots
- `health_trends` — health score trends
- `feedback` — user feedback on patterns
- `policy_results` — policy evaluation results
- `degradation_alerts` — quality degradation alerts

**Tier 7: Advanced (v007, 6 tables)**
- `simulations` — simulation results
- `decisions` — mined architectural decisions
- `context_cache` — generated context cache
- `migration_projects` — language/framework migration projects
- `migration_modules` — per-module migration tracking
- `migration_corrections` — spec corrections during migration

---

*This document maps every critical flow, every database table, every NAPI binding, and every subsystem in Drift V2. Total: 109 NAPI bindings (41 drift + 68 cortex), 45 drift.db tables, 14 languages, 16 detector categories, 14 endpoint extractors, 4 schema parsers, 6 quality gates, 8 report formats (SARIF/JSON/Console/HTML/JUnit/SonarQube/GitHub/GitLab), 10 structural subsystems, 5 graph intelligence subsystems, 21 Cortex crates, 15 bridge subsystems, 6 TS packages, 35 BatchCommand variants, 16 query modules, and 7 storage migrations.*

---

## Appendix A: Production Hardening Gaps

> Identified during source code audit. These are not bugs but areas requiring attention for production readiness.

### A1. Call graph built twice in `drift_analyze()`
Step 3b calls `CallGraphBuilder::build()` and Step 6 rebuilds it from scratch (line 923 of `analysis.rs`). For large repos this doubles the graph construction cost. **Fix:** Cache the call graph result from Step 3b and reuse in Step 6.

### A2. File content read from disk multiple times
Steps 5b–5l each call `std::fs::read_to_string()` per file, even though Step 2 already read all file content. Contract extraction (Step 5l) re-reads every file. **Fix:** Pass source content through the pipeline or cache in a HashMap.

### A3. No pipeline timeout
`drift_analyze()` has no time limit. A 100K-file repo could run for hours. **Fix:** Add configurable timeout with graceful partial-result return.

### A4. No memory pressure monitoring
`all_parse_results: Vec<ParseResult>` grows unbounded. A large repo with complex files could cause OOM. **Fix:** Stream-based processing or memory budget with spill-to-disk.

### A5. Per-file errors silently swallowed
File read/parse failures in ~15 locations use `continue` with no error aggregation. The NAPI return type (`Vec<JsAnalysisResult>`) has no error summary field. **Fix:** Add an `errors: Vec<FileError>` field to the return type and collect all per-file failures.

### A6. Degradation alerts logic is simplistic
Step 8 only checks absolute thresholds (score < 0.5, violations > 50), not actual delta from the previous run. **Fix:** Load previous run's gate results and compute real deltas.

### A7. BatchWriter failure mid-pipeline has no rollback
If the writer fails on Step 5, Steps 6–8 still run but earlier data may be lost. No transactional boundary across the pipeline. **Fix:** Consider checkpoint-and-resume or at minimum aggregate writer errors into the return.

### A8. `data_access` function_id uses line number as proxy
Step 5i sets `function_id = m.line as i64` which is not a real FK to the functions table. Joins on `function_id` will produce incorrect results. **Fix:** Resolve the enclosing function from the functions table by file + line range.

### A9. CI agent internal pass count inconsistency
Code comments alternate between "9 parallel passes" (`index.ts:6`, `agent.ts:2`) and "10" (`agent.ts:87`, `agent.ts:251`). The actual count is 10. **Fix:** Align all comments to 10.

---

## Appendix B: Audit Trail

**Audited:** 2025-02-10 (initial), 2025-02-10 (DD deep dive §2–§5), 2025-02-10 (DD deep dive §9–§10), 2025-02-10 (DD-15/DD-16 schema + cross-ref)
**Method:** Line-by-line verification of every claim in this document against source code in `crates/drift/`, `crates/cortex/`, `crates/cortex-drift-bridge/`, and `packages/`.
**Corrections applied:** 16 factual errors fixed + 10 DD-01–04 errors + 7 DD-08/09 errors + 1 DD-15 error (34 total), 11 omissions addressed + 21 DD-01–04 omissions + 14 DD-08/09 omissions + 1 DD-15 omission (47 total), 7 stale cross-references fixed (DD-16), 9 production hardening gaps documented. See Appendix C for DD-01–04. See Appendix D for DD-08/DD-09. See Appendix E for DD-15/DD-16.

| ID | Type | Section | Finding | Resolution |
|----|------|---------|---------|------------|
| E1 | Error | §3 Parser | ParseResult has 18 fields, not 15 | Fixed: added file, language, content_hash, has_errors |
| E2 | Error | §11 NAPI | Drift has 41 NAPI functions, not 40 | Fixed count |
| E3 | Error | §11 NAPI | 5 wrong structural function names | Fixed: driftDnaAnalysis, driftDecomposition, etc. |
| E4 | Error | §11 NAPI | driftTestQuality → driftTestTopology | Fixed |
| E5 | Error | §11 NAPI | Feedback module: 3 functions, not 4; wrong names | Fixed: driftDismissViolation, driftFixViolation, driftSuppressViolation |
| E6 | Error | §9 Enforcement | CSV/Markdown reporters don't exist | Fixed: GitHub/GitLab |
| E7 | Error | §10 Storage | BatchCommand count was "21", actual 35 | Fixed: 35 total (33 data + 2 control) |
| E8 | Error | §13 Cortex | 24 crates → 21 (includes scripts/target/test-fixtures) | Fixed |
| E9 | Error | §11 NAPI | Cortex has 17 modules, not 18 | Fixed |
| E10 | Error | §12 MCP | "8 drift tools" → 6 entry points + ~41 internal | Fixed |
| E11 | Error | §12 CLI | 28 commands → 27 + cortex umbrella | Fixed |
| E12 | Error | §12 CI | Pass names didn't match code | Fixed: actual 10 pass names |
| E13 | Error | §7 Structural | "9 Subsystems" → 10 | Fixed |
| E14 | Error | §1 Architecture | "4 TS packages" → 6 | Fixed: added drift, cortex |
| E15 | Error | §1 Architecture | "40 drift + 68 cortex = 108" → 41 + 68 = 109 | Fixed |
| E16 | Verified | §10 Storage | Query module count | Confirmed: 16 modules + mod.rs |
| O1 | Omission | §1 | packages/drift/ and packages/cortex/ missing | Added to package list |
| O2 | Omission | §10 | InsertParseCache BatchCommand missing | Added to variant list |
| O3 | Omission | §2 | cancellation.rs and types.rs missing from key files | Added |
| O4 | Gap | Appendix A | Call graph built twice | Documented in A1 |
| O5 | Gap | Appendix A | File content re-read from disk | Documented in A2 |
| O6 | Gap | Appendix A | No pipeline timeout | Documented in A3 |
| O7 | Gap | Appendix A | Per-file errors silently swallowed | Documented in A5 |
| O8 | Omission | §1 | drift-core crate role undocumented | Noted in architecture |
| O9 | Gap | Appendix A | data_access FK proxy | Documented in A8 |
| O10 | Gap | Appendix A | CI pass count inconsistency | Documented in A9 |
| O11 | Gap | Appendix A | BatchWriter failure mid-pipeline | Documented in A7 |

---

## Appendix C: Deep Dive Corrections (DD-01 through DD-04)

> **Deep-dive audit performed: 2025-02-10** — Line-by-line verification of §2–§5 against source files in `crates/drift/drift-analysis/src/` and `crates/drift/drift-napi/src/bindings/`.

### DD-01: §2 Scanner — 2 Errors, 6 Omissions

**Errors:**

| ID | Location | Finding | Impact |
|----|----------|---------|--------|
| DD01-E1 | §2 line 99 | `FileStatus` enum has **3** variants (`Added`, `Modified`, `Unchanged`), not 4. "Removed" is computed via set difference in `compute_diff()` — cached paths absent from disk. It is NOT a `FileStatus` value. | Audit may incorrectly assume Removed flows through the same per-file classification path |
| DD01-E2 | §2 line 101 | `ScanDiff` was missing `errors: Vec<String>` field. **Fixed inline.** | Missing error aggregation path |

**Omissions:**

| ID | What's missing | Actual content (line-verified) |
|----|----------------|-------------------------------|
| DD01-O1 | `ScanEntry` field list | 7 fields: `path: PathBuf`, `content_hash: u64`, `mtime_secs: i64`, `mtime_nanos: u32`, `file_size: u64`, `language: Option<Language>`, `scan_duration_us: u64` — (`types.rs:13-21`) |
| DD01-O2 | `ScanStats` field list | 10 fields: `total_files`, `total_size_bytes`, `discovery_ms`, `hashing_ms`, `diff_ms`, `cache_hit_rate`, `files_skipped_large`, `files_skipped_ignored`, `files_skipped_binary`, `languages_found: FxHashMap<Language, usize>` — (`types.rs:37-48`) |
| DD01-O3 | `DiscoveredFile` field list | 4 fields: `path: PathBuf`, `file_size: u64`, `mtime: SystemTime`, `language: Option<Language>` — (`types.rs:52-57`) |
| DD01-O4 | `CachedFileMetadata` field list | 6 fields: `path`, `content_hash`, `mtime_secs`, `mtime_nanos`, `file_size`, `language` — (`types.rs:69-76`) |
| DD01-O5 | `DriftEventHandler` trait | 24 event methods with no-op defaults in `drift-core/src/events/handler.rs`. Scanner uses 4: `on_scan_started`, `on_scan_progress`, `on_scan_complete`, `on_scan_error`. Trait requires `Send + Sync`. `EventDispatcher` wraps `Vec<Arc<dyn DriftEventHandler>>` with `catch_unwind` per handler. |
| DD01-O6 | Scanner NAPI has 4 functions | `driftScan` (async task), `driftScanWithProgress` (async + ThreadsafeFunction progress), `driftCancelScan` (AtomicBool), `driftScanHistory` (query recent). §2 only mentions `driftScan` in the flow. |

**Verified correct:** 18 default ignore patterns (exact list), all file paths, Phase 1-4 flow, 14 languages, storage tables, xxh3 hashing, `ignore` crate WalkParallel, .gitignore + .driftignore, sorted output.

---

### DD-02: §3 Parser — 6 Errors, 3 Omissions

**Errors (field count mismatches):**

| ID | Struct | Claimed | Actual | Missing fields |
|----|--------|---------|--------|----------------|
| DD02-E1 | `FunctionInfo` | "12+ fields", 7 named | **18 fields** | `qualified_name`, `file`, `line`, `column`, `end_line`, `generic_params` (SmallVec<GenericParam>), `is_exported`, `is_async`, `is_generator`, `is_abstract`, `range` (Range), `doc_comment` — (`types.rs:68-88`) |
| DD02-E2 | `ClassInfo` | 6 named | **13 fields** | `namespace`, `generic_params`, `is_exported`, `is_abstract`, `class_kind` (8 variants: Class/Interface/Struct/Enum/Trait/Record/Union/TypeAlias), `range` — (`types.rs:91-104`) |
| DD02-E3 | `CallSite` | 4 named | **7 fields** | `file`, `line`, `column` — (`types.rs:133-141`) |
| DD02-E4 | `ImportInfo` | 3 named | **5 fields** | `file`, `line` — (`types.rs:143-150`) |
| DD02-E5 | `ExportInfo` | 3 named | **6 fields** | `source: Option<String>`, `file`, `line`. Also `name` is `Option<String>` not `String` — (`types.rs:158-166`) |
| DD02-E6 | `DecoratorInfo` | 3 named | **4 fields** | `range`. Sub-struct `DecoratorArgument { key: Option<String>, value: String }` undocumented — (`types.rs:118-130`) |

**All 6 inline field descriptions fixed above.**

**Omissions:**

| ID | What's missing | Details |
|----|----------------|---------|
| DD02-O1 | 10+ supporting types | `StringLiteralInfo` (6 fields + `StringContext` enum, 7 variants), `NumericLiteralInfo` (7 fields + `NumericContext` enum, 10 variants), `ErrorHandlingInfo` (8 fields + `ErrorHandlingKind` enum, 12 variants: TryCatch/TryExcept/TryFinally/Throw/ResultMatch/QuestionMark/Unwrap/PromiseCatch/AsyncAwaitTry/Rescue/Defer/DeferRecover/WithStatement), `DocCommentInfo` (5 fields + `DocCommentStyle` enum, 7 variants: JsDoc/TripleSlash/Docstring/Pound/KDoc/PhpDoc/GoDoc), `ParameterInfo` (4 fields: name, type_annotation, default_value, is_rest), `PropertyInfo` (5 fields: name, type_annotation, is_static, is_readonly, visibility), `GenericParam` (2 fields: name, bounds), `Visibility` enum (Public/Private/Protected), `Range` { start: Position, end: Position }, `Position` { line: u32, column: u32 } |
| DD02-O2 | `LanguageParser` trait methods | `language() -> Language`, `extensions() -> &[&str]`, `parse(source, path) -> Result<ParseResult, ParseError>` — (`traits.rs:11-20`) |
| DD02-O3 | `ParserManager` full API | `parse()`, `parse_with_language()`, `parse_returning_tree()` (returns `(ParseResult, Tree)` — avoids double-parse), `cache_entry_count()`, `invalidate_cache()` — (`manager.rs:90-177`) |

**Verified correct:** 18 ParseResult fields, 10 parser file names, all tree-sitter grammar mappings, fallback grammars (C/C++→C#, Swift/Scala→Java), moka-based parse cache, all key file paths.

---

### DD-03: §4 Detection Engine — 1 Error, 5 Omissions

**Error:**

| ID | Finding | Impact |
|----|---------|--------|
| DD03-E1 | **"Skeleton" classification is stale/misleading.** All 16 detectors have real detection logic (80-150 lines each). The code comments in `registry.rs:146` and `mod.rs:4-5` label 11 detectors as "skeleton" but each has real pattern detection using call sites, imports, function names, and string literals. Verified: ApiDetector (109 lines, REST + routes + frameworks), AuthDetector (107 lines, auth functions + JWT + auth calls), LoggingDetector (132 lines, logger calls + framework imports + bare prints). **Fixed inline.** | Audit may incorrectly conclude 11 detectors produce no output |

**Omissions:**

| ID | What's missing | Details |
|----|----------------|---------|
| DD03-O1 | `DetectionContext` field list | 9 fields: `file: &str`, `language: Language`, `source: &[u8]`, `imports: &[ImportInfo]`, `exports: &[ExportInfo]`, `functions: &[FunctionInfo]`, `classes: &[ClassInfo]`, `call_sites: &[CallSite]`, `parse_result: &ParseResult` — (`visitor.rs:20-30`) |
| DD03-O2 | Visitor architecture details | **3 handler traits:** `DetectorHandler` (7 methods: id, node_types, languages, on_enter, on_exit, results, reset — AST visitor), `FileDetectorHandler` (5 methods — full-file analysis after traversal), `LearningDetectorHandler` (6 methods: learn + detect two-pass). **`VisitorRegistry`**: 5 internal structures (handlers vec, node_handlers FxHashMap for O(1) dispatch, wildcard_handlers, file_handlers, learning_handlers). **`DetectionEngine`**: wraps VisitorRegistry, runs depth-first traversal dispatching on_enter/on_exit per node type — (`visitor.rs:54-338`) |
| DD03-O3 | `DetectionMethod` enum | 5 variants: `AstVisitor`, `StringRegex`, `TomlPattern`, `LearningDeviation`, `Semantic` — (`types.rs:38-50`) |
| DD03-O4 | `Detector` trait methods | `id() -> &str`, `category() -> DetectorCategory`, `variant() -> DetectorVariant`, `detect(ctx) -> Vec<PatternMatch>`, `is_critical() -> bool` (default false) — (`traits.rs:7-24`) |
| DD03-O5 | Missing key files | `engine/types.rs` (PatternMatch, PatternCategory, DetectionMethod, AnalysisResult, AnalysisPhase), `engine/string_extraction.rs` (ExtractedString with StringKind enum: Literal/Template/Raw/Regex/DocComment), `engine/toml_patterns.rs` (TomlPatternLoader, CompiledQuery), `engine/gast/` (Generic AST normalization — see DD04-O3) |

**Verified correct:** 16 detector categories, all 16 .rs files exist, 3 detector variants (Base/Learning/Semantic), PatternMatch 10 fields, catch_unwind() panic safety, key file paths.

---

### DD-04: §5 Analysis Pipeline — 1 Error, 7 Omissions

**Error:**

| ID | Finding | Impact |
|----|---------|--------|
| DD04-E1 | **Two separate resolution systems conflated.** §7a documents the call graph with "6 strategies: SameFile (0.95), Fuzzy (0.40), Import-based, Export-based, DI, Method". But `engine/resolution.rs` (Phase 4 of per-file pipeline) has its own **distinct** `ResolutionIndex` with 6 different strategies: Direct (0.95), Method (0.90), Constructor (0.85), Callback (0.75), Dynamic (0.50), External (0.68). These are **two completely separate systems** — the pipeline's Phase 4 builds a `ResolutionIndex` using `engine/resolution.rs`, the call graph builder uses `call_graph/resolution.rs`. | Audit may incorrectly assume single resolution system |

**Omissions:**

| ID | What's missing | Details |
|----|----------------|---------|
| DD04-O1 | `AnalysisPipeline` composition | `AnalysisPipeline { engine: DetectionEngine, regex_engine: RegexEngine }`. Chain: AnalysisPipeline → {DetectionEngine + RegexEngine}. DetectionEngine → VisitorRegistry → handlers. Methods: `new()`, `with_engine()`, `analyze_file()`, `analyze_files()` — (`pipeline.rs:20-122`) |
| DD04-O2 | `AnalysisResult` struct | 8 fields: `file: String`, `language: Language`, `matches: Vec<PatternMatch>`, `strings_extracted: usize`, `regex_matches: usize`, `resolution_entries: usize`, `analysis_time_us: u64`, `phase_times_us: [u64; 4]` — (`types.rs:10-20`) |
| DD04-O3 | **`engine/gast/` — Generic AST normalization** | Completely undocumented subsystem. Normalizes language-specific tree-sitter ASTs into ~40-50 common node types + `Other` catch-all. Files: `types.rs` (231 lines, GASTNode enum with Program/Module/Namespace/Function/Class/Interface/Enum/TypeAlias/Method/... variants), `base_normalizer.rs` (18KB), 10 language-specific normalizers in `normalizers/` (typescript 10KB, python 7KB, rust 6KB, java 4KB, go 4KB, php 4KB, csharp 4KB, cpp 4KB, ruby 4KB + mod.rs) |
| DD04-O4 | `engine/incremental.rs` | `IncrementalAnalyzer` — determines which files need re-analysis. Content-hash skip for unchanged files. Methods: `files_to_analyze(diff)` (returns added + modified), `needs_analysis(file, hash)` (L2 incremental) — (`incremental.rs:1-84`) |
| DD04-O5 | `engine/toml_patterns.rs` | `TomlPatternLoader` + `CompiledQuery` — TOML-defined declarative pattern definitions loaded at startup |
| DD04-O6 | `engine/string_extraction.rs` | Phase 2 string extraction. `ExtractedString` { value, file, line, column, kind, context }. `StringKind` enum: Literal/Template/Raw/Regex/DocComment. Per-language string node kinds for correct extraction across all 10 languages — (`string_extraction.rs:1-199`) |
| DD04-O7 | `ResolutionIndex.resolve()` method | 6-strategy fallback chain: (1) Direct — same file function match (0.95), (2) Method — qualified class.method (0.90), (3) Constructor — class match (0.85), (4) Callback — imported symbol in same file (0.75), (5) External — exported from another file (0.68), (6) Dynamic — any match, low confidence (0.50). Uses BTreeMap for name index, FxHashMap for file index, SmallVec for strategies — (`resolution.rs:225-278`) |

**Verified correct:** 4-phase per-file flow (AST detection → String extraction → Regex matching → Resolution building), AnalysisPipeline in pipeline.rs, ResolutionIndex in resolution.rs, DetectionContext.from_parse_result().

---

### DD Summary

| Section | Errors Found | Omissions Found | Items Verified Correct |
|---------|-------------|-----------------|----------------------|
| DD-01 Scanner | 2 | 6 | 10 |
| DD-02 Parser | 6 | 3 | 6 |
| DD-03 Detection Engine | 1 | 5 | 6 |
| DD-04 Analysis Pipeline | 1 | 7 | 4 |
| DD-08 Enforcement | 3 | 12 | 8 |
| DD-09 Storage | 4 | 2 | 6 |
| DD-15 Schema Columns | 1 | 1 | 45 tables (398 cols) |
| DD-16 Cross-References | 0 | 0 | 7 stale refs fixed |
| **Total** | **18** | **36** | **40 + 45 tables + 7 refs** |

**Most critical for audit:**
1. **DD02-E1:** FunctionInfo has 18 fields, not "12+" — the 11 undocumented fields (`is_exported`, `is_async`, `qualified_name`, etc.) are exactly what downstream systems (call graph, contracts, DNA) depend on
2. **DD03-E1:** ALL 16 detectors have real implementations — the "skeleton" label is stale
3. **DD04-E1:** Two separate resolution systems exist — pipeline Phase 4 (`engine/resolution.rs`) vs call graph (`call_graph/resolution.rs`) have different strategies and confidences
4. **DD04-O3:** GAST (Generic AST) normalization layer is completely undocumented — 10 language-specific normalizers totaling ~50KB of code
5. **DD01-O5:** `DriftEventHandler` trait (24 event methods) is the cross-cutting event system for the entire engine — not mentioned anywhere in the document
6. **DD08-E1:** PatternCompliance is the ONLY gate that silently passes on empty input — other 5 skip. Wrong claims about empty-input = wrong hardening
7. **DD09-E1:** Table count was 39, actual is 45 — 6 tables missing from all prior audits (parse_cache, test_coverage, migration_projects/modules/corrections)
8. **DD09-E2:** Table name `outlier_detections` doesn't exist — actual name is `outliers`

---

## Appendix D: Deep Dive Corrections (DD-08 and DD-09)

> **Deep-dive audit performed: 2025-02-10** — Line-by-line verification of §9 Enforcement and §10 Storage against source files in `crates/drift/drift-analysis/src/enforcement/` and `crates/drift/drift-storage/src/`.

### DD-08: §9 Enforcement — 3 Errors, 12 Omissions

**Errors:**

| ID | Finding | Impact |
|----|---------|--------|
| DD08-E1 | PatternCompliance **silently passes** on empty input (compliance_rate defaults to 1.0). Document implied all gates skip on empty data. | Wrong empty-input claims = wrong hardening assumptions. Only Gates 2-6 skip. |
| DD08-E2 | Document listed "17 query modules" but actual count is **16** (queries/mod.rs lists 16 pub mod statements). | Minor count error but propagated to summary and data flow diagram. |
| DD08-E3 | Document said "17 query modules" in summary and data flow diagram. | Fixed to 16 throughout. |

**Omissions (all added to §9):**

| ID | What was missing | Now documented in |
|----|-----------------|-------------------|
| DD08-O1 | Exact gate threshold values per gate (score formulas, severity thresholds) | §9a table |
| DD08-O2 | Empty-input behavior per gate (skip vs silent pass) | §9a table + warning |
| DD08-O3 | Gate dependency graph (Gates 2-3 depend on PatternCompliance) | §9 flow diagram |
| DD08-O4 | 4 policy aggregation modes + 3 presets with exact configs | §9b |
| DD08-O5 | Standard policy weights (PC:0.25, CV:0.20, SB:0.25, TC:0.15, EH:0.10, R:0.05) | §9b table |
| DD08-O6 | Missing required gate = FAIL behavior | §9b |
| DD08-O7 | Reporter-specific format details (SARIF taxonomy placement, JUnit errors/failures, SonarQube rules array) | §9c table |
| DD08-O8 | Bayesian delta values per feedback action type | §9d table |
| DD08-O9 | FeedbackTracker thresholds (10% alert, 20% disable, 30d sustained, min 10 findings) | §9d |
| DD08-O10 | FeedbackStatsProvider trait interface + FP rate severity downgrade in RulesEvaluator | §9d |
| DD08-O11 | 4 suppression format syntaxes with bidirectional line checking | §9e table |
| DD08-O12 | 8 quick-fix strategies with language-aware templates | §9f table |

**Verified correct:** 6 gate IDs, GateOrchestrator topo-sort, 30s timeout, GateResult 10 fields, GateInput 14 fields, 8 reporter names, Reporter trait interface.

---

### DD-09: §10 Storage — 4 Errors, 2 Omissions

**Errors:**

| ID | Finding | Impact |
|----|---------|--------|
| DD09-E1 | Total table count was **39**, actual is **45**. Missing tables: `parse_cache` (v001), `test_coverage` (v004), `migration_projects` (v007), `migration_modules` (v007), `migration_corrections` (v007). | 6 tables invisible to audit = 6 tables with no verification |
| DD09-E2 | Table name `outlier_detections` does not exist. Actual table name is **`outliers`** (v003). | Any SQL referencing `outlier_detections` will fail |
| DD09-E3 | `functions` table was listed under v002, but it's actually in **v001**. v002 has `data_access` instead. | Incorrect migration ordering in audit |
| DD09-E4 | v007 listed only 3 tables (`simulations`, `decisions`, `context_cache`). Actual count is **6** (also `migration_projects`, `migration_modules`, `migration_corrections`). | 3 tables completely missing from all documentation |

**Omissions (all added to §10):**

| ID | What was missing | Now documented in |
|----|-----------------|-------------------|
| DD09-O1 | DatabaseManager pool specifics: ReadPool DEFAULT=4/MAX=8, round-robin AtomicUsize, SQLITE_OPEN_READ_ONLY flags, read vs write pragmas, in-memory BatchWriter isolation caveat, with_immediate_transaction helper | §10a |
| DD09-O2 | Full retention tier assignments: 4 tiers (Current/orphan cleanup, Short 30d, Medium 90d, Long 365d), exact table-to-tier mapping, self-bounding tables, double-cleanup paths | §10d |

---

## Appendix E: Deep Dive Corrections (DD-15 and DD-16)

> **Deep-dive audit performed: 2025-02-10** — Column-level verification of all 45 tables against migration SQL (ground truth), plus cross-reference consistency check across all sections.

### DD-15: §10b Schema — 1 Error, 1 Omission

**Error:**

| ID | Finding | Impact |
|----|---------|--------|
| DD15-E1 | §5 line 298 claimed "30 tables via 32 data-carrying BatchCommand variants". Actual: **32 tables via 33 data-carrying** variants (verified against `commands.rs`). Line 301 misclassified `InsertParseCache` as non-data (it carries `Vec<ParseCacheRow>`). | Pipeline write coverage understated; `InsertParseCache` wrongly grouped with control commands |

**Omission:**

| ID | What was missing | Now documented in |
|----|-----------------|-------------------|
| DD15-O1 | §10b had column-level detail for v001–v004 only (17 tables, 147 columns). **28 tables across v005–v007 (251 columns) had NO column-level detail** — only table names were listed. This is 63% of all schema columns invisible to audit. | §10b — all 45 tables now have full column listings verified against migration SQL |

**Column-level verification results (all 45 tables, 398 total columns):**

| Migration | Tables | Columns | Status |
|-----------|--------|---------|--------|
| v001 | 4 | 41 | ✅ All match SQL (was already documented) |
| v002 | 4 | 32 | ✅ All match SQL (was already documented) |
| v003 | 3 | 26 | ✅ All match SQL (was already documented) |
| v004 | 6 | 48 | ✅ All match SQL (was already documented) |
| v005 | 15 | 134 | ✅ All match SQL (**newly documented**) |
| v006 | 7 | 70 | ✅ All match SQL (**newly documented**) |
| v007 | 6 | 47 | ✅ All match SQL (**newly documented**) |
| **Total** | **45** | **398** | **100% verified against CREATE TABLE statements** |

**Foreign key relationships verified:**
- `constraint_verifications.constraint_id` → `constraints(id)` (v005)
- `migration_modules.project_id` → `migration_projects(id)` (v007)
- `migration_corrections.module_id` → `migration_modules(id)` (v007)

**Tables with NO BatchCommand wiring (13 tables — written directly or not yet wired):**
`constraints`, `constraint_verifications` (direct write), `test_coverage`, `audit_snapshots`, `health_trends`, `feedback`, `policy_results`, `simulations`, `decisions`, `context_cache`, `migration_projects`, `migration_modules`, `migration_corrections`

---

### DD-16: Cross-Reference Consistency — 7 Stale References Fixed

| ID | Location | Stale Value | Correct Value | Root Cause |
|----|----------|-------------|---------------|------------|
| DD16-S1 | §1 ASCII diagram (line 55) | "39 tables" | **45 tables** | DD09-E1 correction not propagated to ASCII art |
| DD16-S2 | ToC (line 13) | "(9 subsystems)" | **(10 subsystems)** | E13 correction not propagated to ToC |
| DD16-S3 | §16 Master diagram (line 1214) | "(9 subsystems)" | **(10 subsystems)** | E13 correction not propagated to summary diagram |
| DD16-S4 | §5 table list (line 299) | `outlier_detections` | **`outliers`** | DD09-E2 correction not propagated to §5 |
| DD16-S5 | §5 line 298 | "30 tables via 32 data-carrying" | **32 tables via 33 data-carrying** | BatchCommand count wrong + InsertParseCache misclassified |
| DD16-S6 | §5 line 301 | "32 data + Flush, Shutdown, InsertParseCache" | **33 data + 2 control (Flush, Shutdown)** | InsertParseCache is data-carrying, not control |
| DD16-S7 | Appendix B E7 | "32 data + 3 control" | **33 data + 2 control** | Original correction itself was wrong |

**Pattern observed:** 5 of 7 stale references are corrections from prior deep dives (DD09-E1, DD09-E2, E13, E7) that were applied to the primary section but **not propagated to all secondary references** (ToC, ASCII diagrams, summary diagrams, cross-reference lists). This is a systemic issue — future corrections should grep for all occurrences before marking as fixed.

**All 7 stale references have been fixed inline.**

---

### DD-15/DD-16 Summary

| Audit Item | Errors | Omissions | Stale Refs Fixed | Items Verified |
|------------|--------|-----------|------------------|----------------|
| DD-15 Schema | 1 | 1 | — | 45 tables, 398 columns |
| DD-16 Cross-Ref | — | — | 7 | All sections cross-checked |
| **Total** | **1** | **1** | **7** | **45 tables + full doc** |
