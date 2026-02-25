# Drift V2 — Complete Scaffold Directory Map

> The definitive file-by-file directory structure for the entire Drift V2 codebase.
> Every directory, every file, every `mod.rs`, every `Cargo.toml`, every test file.
> Source truth: DRIFT-V2-IMPLEMENTATION-ORCHESTRATION.md (all 20 sections, all ~55 systems).
>
> This document IS the deliverable. Hand this to a scaffold agent and every file gets created.
> No ambiguity. No interpretation needed. Every path is absolute from workspace root.
>
> Generated: 2026-02-08

---

## Table of Contents

1. Workspace Root (`crates/drift/`)
2. drift-core (Phase 0 — Infrastructure Primitives)
3. drift-storage (Phase 1 — SQLite Persistence)
4. drift-analysis (Phases 1-7 — All Analysis Systems)
5. drift-context (Phase 7 — Context Generation)
6. drift-napi (Phases 1-8 — NAPI Bridge)
7. drift-bench (Benchmarks)
8. TypeScript Packages (`packages/`)
9. Bridge Crate (`crates/cortex-drift-bridge/`)
10. Cross-Reference Verification Matrix

---

## 1. Workspace Root

**Source**: Orchestration §3.1

```
crates/drift/
├── Cargo.toml                          # Workspace manifest (6 members)
├── Cargo.lock                          # Lockfile (generated)
├── .cargo/
│   └── config.toml                     # Shared build settings (linker, env, incremental)
├── rustfmt.toml                        # max_width=100, edition="2021"
├── clippy.toml                         # Strict linting config
├── deny.toml                           # cargo-deny: license + advisory auditing
├── rust-toolchain.toml                 # Pin Rust edition
├── drift-core/                         # §2 below
├── drift-storage/                      # §3 below
├── drift-analysis/                     # §4 below
├── drift-context/                      # §5 below
├── drift-napi/                         # §6 below
└── drift-bench/                        # §7 below
```

### Workspace Cargo.toml Members

```toml
[workspace]
members = [
    "drift-core",
    "drift-analysis",
    "drift-storage",
    "drift-context",
    "drift-napi",
    "drift-bench",
]
```

### Crate Dependency Direction (R6 — No Circular Dependencies)

```
drift-napi    → drift-analysis, drift-storage, drift-context, drift-core
drift-bench   → drift-analysis, drift-storage, drift-core
drift-analysis → drift-core
drift-storage  → drift-core
drift-context  → drift-core
drift-core    → (no internal dependencies)
```

---

## 2. drift-core (Phase 0 — Infrastructure Primitives)

**Source**: Orchestration §3.2–§3.6
**Depends on**: Nothing (leaf crate)
**Systems**: Configuration, thiserror Error Enums, tracing Instrumentation,
DriftEventHandler Trait, String Interning, Data Structures

```
crates/drift/drift-core/
├── Cargo.toml
└── src/
    ├── lib.rs                          # pub mod declarations + crate-level re-exports
    │
    ├── config/                         # §3.2 — Configuration System (DriftConfig)
    │   ├── mod.rs                      # pub mod: drift_config, scan_config, analysis_config,
    │   │                               #   gate_config, mcp_config, backup_config,
    │   │                               #   telemetry_config, license_config
    │   ├── drift_config.rs             # DriftConfig — 4-layer resolution
    │   │                               #   (CLI > env > project drift.toml > user ~/.drift/config.toml > defaults)
    │   ├── scan_config.rs              # ScanConfig — ignore patterns, max file size, parallelism
    │   ├── analysis_config.rs          # AnalysisConfig — detector thresholds, feature flags
    │   ├── gate_config.rs              # GateConfig — quality gate thresholds, fail levels
    │   ├── mcp_config.rs               # McpConfig — max_response_tokens, transport settings
    │   ├── backup_config.rs            # BackupConfig — backup intervals, retention
    │   ├── telemetry_config.rs         # TelemetryConfig — opt-in metrics, endpoint
    │   └── license_config.rs           # LicenseConfig — 3-tier gating (Community/Team/Enterprise)
    │
    ├── errors/                         # §3.3 — Error Handling (thiserror)
    │   ├── mod.rs                      # pub mod: error_code, scan_error, parse_error,
    │   │                               #   storage_error, detection_error, call_graph_error,
    │   │                               #   pipeline_error, taint_error, constraint_error,
    │   │                               #   boundary_error, gate_error, config_error, napi_error
    │   ├── error_code.rs               # DriftErrorCode trait — every error enum implements this
    │   │                               #   Produces structured "[ERROR_CODE] message" strings
    │   ├── scan_error.rs               # ScanError enum
    │   ├── parse_error.rs              # ParseError enum
    │   ├── storage_error.rs            # StorageError enum
    │   ├── detection_error.rs          # DetectionError enum
    │   ├── call_graph_error.rs         # CallGraphError enum
    │   ├── pipeline_error.rs           # PipelineError enum + PipelineResult (non-fatal collection)
    │   ├── taint_error.rs              # TaintError enum
    │   ├── constraint_error.rs         # ConstraintError enum
    │   ├── boundary_error.rs           # BoundaryError enum
    │   ├── gate_error.rs               # GateError enum
    │   ├── config_error.rs             # ConfigError enum
    │   └── napi_error.rs               # NapiError enum + 14 NAPI error codes:
    │                                   #   SCAN_ERROR, PARSE_ERROR, DB_BUSY, DB_CORRUPT,
    │                                   #   CANCELLED, UNSUPPORTED_LANGUAGE, DETECTION_ERROR,
    │                                   #   CALL_GRAPH_ERROR, CONFIG_ERROR, LICENSE_ERROR,
    │                                   #   GATE_FAILED, STORAGE_ERROR, DISK_FULL, MIGRATION_FAILED
    │
    ├── events/                         # §3.5 — Event System (DriftEventHandler)
    │   ├── mod.rs                      # pub mod: handler, dispatcher, types
    │   ├── handler.rs                  # DriftEventHandler trait — 24 methods with no-op defaults:
    │   │                               #   Scan: on_scan_started, on_scan_progress,
    │   │                               #         on_scan_complete, on_scan_error
    │   │                               #   Patterns: on_pattern_discovered, on_pattern_approved,
    │   │                               #             on_pattern_ignored, on_pattern_merged
    │   │                               #   Violations: on_violation_detected, on_violation_dismissed,
    │   │                               #               on_violation_fixed
    │   │                               #   Enforcement: on_gate_evaluated, on_regression_detected,
    │   │                               #                on_enforcement_changed
    │   │                               #   Constraints: on_constraint_approved, on_constraint_violated
    │   │                               #   Decisions: on_decision_mined, on_decision_reversed,
    │   │                               #              on_adr_detected
    │   │                               #   Boundaries: on_boundary_discovered
    │   │                               #   Detector health: on_detector_alert, on_detector_disabled
    │   │                               #   Feedback: on_feedback_abuse_detected
    │   │                               #   Errors: on_error
    │   ├── dispatcher.rs               # EventDispatcher — Vec<Arc<dyn DriftEventHandler>>
    │   │                               #   emit() helper, synchronous dispatch
    │   └── types.rs                    # Event payload types for all 24 event methods
    │
    ├── tracing/                        # §3.4 — Observability (tracing)
    │   ├── mod.rs                      # pub mod: setup, metrics
    │   ├── setup.rs                    # init_tracing(), EnvFilter setup
    │   │                               #   DRIFT_LOG=scanner=debug,parser=info,storage=warn
    │   └── metrics.rs                  # 12+ structured span field definitions:
    │                                   #   scan_files_per_second, cache_hit_rate,
    │                                   #   parse_time_per_language, napi_serialization_time,
    │                                   #   detection_time_per_category, batch_write_time,
    │                                   #   call_graph_build_time, confidence_compute_time,
    │                                   #   gate_evaluation_time, mcp_response_time,
    │                                   #   discovery_duration, hashing_duration
    │
    ├── types/                          # §3.6 — Data Structures & String Interning
    │   ├── mod.rs                      # pub mod: interning, collections, identifiers
    │   ├── interning.rs               # PathInterner (normalizes path separators before interning),
    │   │                               #   FunctionInterner (qualified name: Class.method),
    │   │                               #   ThreadedRodeo wrappers (build/scan phase),
    │   │                               #   RodeoReader wrappers (query phase, zero-contention)
    │   ├── collections.rs              # FxHashMap, FxHashSet (from rustc-hash) re-exports,
    │   │                               #   SmallVec re-exports, BTreeMap type aliases
    │   └── identifiers.rs             # Spur-based ID types: FileId, FunctionId, PatternId,
    │                                   #   ClassId, ModuleId, DetectorId, ConstraintId, etc.
    │
    └── traits/                         # Shared traits used across crates
        ├── mod.rs                      # pub mod declarations for shared traits
        └── incremental.rs              # Incremental processing trait (content-hash skip)


### drift-core Tests

```
crates/drift/drift-core/
└── tests/
    ├── config_test.rs                  # DriftConfig 4-layer resolution tests
    ├── errors_test.rs                  # Error enum + DriftErrorCode trait tests
    ├── events_test.rs                  # DriftEventHandler dispatch + no-op default tests
    └── types_test.rs                   # Interning, collections, identifier tests
```

---

## 3. drift-storage (Phase 1 — SQLite Persistence)

**Source**: Orchestration §4.3, §18.2
**Depends on**: drift-core
**Systems**: SQLite Storage (System 02)

```
crates/drift/drift-storage/
├── Cargo.toml
└── src/
    ├── lib.rs                          # pub mod declarations + crate-level re-exports
    │
    ├── connection/                     # Connection architecture
    │   ├── mod.rs                      # pub mod: pool, writer, pragmas
    │   ├── pool.rs                     # ReadPool — round-robin AtomicUsize index,
    │   │                               #   SQLITE_OPEN_READ_ONLY connections
    │   ├── writer.rs                   # Mutex<Connection> write serialization
    │   │                               #   (std::sync::Mutex, NOT tokio — Drift has no async runtime)
    │   └── pragmas.rs                  # WAL mode, synchronous=NORMAL, 64MB page_cache,
    │                                   #   256MB mmap, busy_timeout=5000, temp_store=MEMORY,
    │                                   #   auto_vacuum=INCREMENTAL, foreign_keys=ON
    │
    ├── batch/                          # Batch writer system
    │   ├── mod.rs                      # pub mod: writer, commands
    │   ├── writer.rs                   # crossbeam-channel bounded(1024), dedicated writer thread,
    │   │                               #   BEGIN IMMEDIATE transactions, prepare_cached(),
    │   │                               #   batch size 500, recv_timeout(100ms)
    │   └── commands.rs                 # BatchCommand enum — all write operations as variants
    │
    ├── migrations/                     # Schema migration system
    │   ├── mod.rs                      # pub mod + migration registry
    │   │                               #   rusqlite_migration + PRAGMA user_version
    │   ├── v001_core_schema.rs         # Phase 1: file_metadata, parse_cache, functions
    │   ├── v002_analysis_schema.rs     # Phase 2: call_edges, data_access, detections,
    │   │                               #   boundaries, patterns
    │   ├── v003_pattern_schema.rs      # Phase 3: pattern_confidence (α, β, score),
    │   │                               #   outliers, conventions
    │   ├── v004_graph_schema.rs        # Phase 4: reachability_cache, taint_flows,
    │   │                               #   error_gaps, impact_scores, test_coverage
    │   ├── v005_structural_schema.rs   # Phase 5: coupling_metrics, constraints, contracts,
    │   │                               #   constants, secrets, wrappers, dna_genes,
    │   │                               #   crypto_findings, owasp_findings
    │   ├── v006_enforcement_schema.rs  # Phase 6: violations, gate_results,
    │   │                               #   audit_snapshots, health_trends, feedback
    │   └── v007_advanced_schema.rs     # Phase 7: simulations, decisions, context_cache
    │
    ├── queries/                        # Query modules by domain
    │   ├── mod.rs                      # pub mod: files, parse_cache, functions, call_edges,
    │   │                               #   patterns, detections, boundaries, graph,
    │   │                               #   structural, enforcement, advanced
    │   ├── files.rs                    # file_metadata table queries
    │   ├── parse_cache.rs              # parse_cache table queries
    │   ├── functions.rs                # functions table queries
    │   ├── call_edges.rs               # call_edges table queries
    │   ├── patterns.rs                 # patterns + confidence queries (α, β, score columns)
    │   ├── detections.rs               # detections table queries
    │   ├── boundaries.rs               # boundaries table queries
    │   ├── graph.rs                    # reachability, taint, impact, test queries
    │   ├── structural.rs               # coupling, constraints, contracts, constants,
    │   │                               #   wrappers, dna, owasp, crypto queries
    │   ├── enforcement.rs              # violations, gates, audit, feedback queries
    │   └── advanced.rs                 # simulations, decisions, context queries
    │
    ├── pagination/                     # Keyset cursor pagination (NOT OFFSET/LIMIT)
    │   ├── mod.rs                      # pub mod: keyset
    │   └── keyset.rs                   # Composite cursor (sort_column, id)
    │
    └── materialized/                   # Materialized views
        ├── mod.rs                      # pub mod: status, security, trends
        ├── status.rs                   # materialized_status view
        ├── security.rs                 # materialized_security view
        └── trends.rs                   # health_trends view
```

### drift-storage Tests & Benches

```
crates/drift/drift-storage/
├── tests/
│   ├── connection_test.rs              # Pool, writer, pragma tests
│   ├── batch_test.rs                   # Batch writer throughput + correctness tests
│   ├── migration_test.rs              # Schema migration + user_version tests
│   └── queries_test.rs                # Per-domain query correctness tests
└── benches/
    ├── batch_bench.rs                  # Batch writer throughput benchmarks
    └── query_bench.rs                  # Query performance benchmarks
```

---

## 4. drift-analysis (Phases 1-7 — All Analysis Systems)

**Source**: Orchestration §4.1, §4.2, §5–§10
**Depends on**: drift-core
**Systems**: Scanner, Parsers, Engine, Detectors, Call Graph, Boundaries,
Language Provider, Patterns, Graph, Structural, Enforcement, Advanced

This is the largest crate. Each top-level subdirectory maps to a system or phase.

```
crates/drift/drift-analysis/
├── Cargo.toml
└── src/
    ├── lib.rs                          # pub mod declarations for all 12 top-level modules
    │                                   #   scanner, parsers, engine, detectors, call_graph,
    │                                   #   boundaries, language_provider, patterns, graph,
    │                                   #   structural, enforcement, advanced
    │
    ├── scanner/                        # System 00 — §4.1 (Phase 1)
    ├── parsers/                        # System 01 — §4.2 (Phase 1)
    ├── engine/                         # System 06 — §5.2 (Phase 2)
    ├── detectors/                      # System 06 — §5.3 (Phase 2)
    ├── call_graph/                     # System 05 — §5.4 (Phase 2)
    ├── boundaries/                     # System 07 — §5.5 (Phase 2)
    ├── language_provider/              # System 08 — §5.6 (Phase 2)
    ├── patterns/                       # Phase 3 — §6 (Aggregation, Confidence, Outliers, Learning)
    ├── graph/                          # Phase 4 — §7 (Reachability, Taint, Error Handling, Impact, Test Topology)
    ├── structural/                     # Phase 5 — §8 (Coupling, Constraints, Contracts, Constants, Wrappers, DNA, OWASP/CWE, Crypto)
    ├── enforcement/                    # Phase 6 — §9 (Rules, Gates, Policy, Audit, Feedback, Reporters)
    └── advanced/                       # Phase 7 — §10 (Simulation, Decisions, Context, N+1)
```

I will now expand every subdirectory in full.


### 4.1 scanner/ — System 00 (Phase 1)

**Source**: Orchestration §4.1, 00-SCANNER-V2-PREP
**Lives in**: `drift-analysis/src/scanner/`

```
crates/drift/drift-analysis/src/scanner/
├── mod.rs                              # pub mod: walker, hasher, diff, stats, ignore_rules,
│                                       #   entry, cancellation
├── walker.rs                           # ignore crate v0.4 WalkParallel integration,
│                                       #   rayon v1.10 Phase 2 processing
├── hasher.rs                           # xxh3 content hashing via xxhash-rust v0.8,
│                                       #   two-level incremental: mtime → content hash
├── diff.rs                             # ScanDiff (added/modified/removed/unchanged)
├── stats.rs                            # ScanStats (timing, throughput, file counts)
├── ignore_rules.rs                     # .driftignore support (gitignore syntax, hierarchical),
│                                       #   18 default ignores (node_modules, .git, dist, build,
│                                       #   target, .next, .nuxt, __pycache__, .pytest_cache,
│                                       #   coverage, .nyc_output, vendor, .venv, venv, .tox,
│                                       #   .mypy_cache, bin, obj)
├── entry.rs                            # ScanEntry: path, content_hash, mtime, size, language
└── cancellation.rs                     # AtomicBool cancellation token
```

### 4.2 parsers/ — System 01 (Phase 1)

**Source**: Orchestration §4.2, 01-PARSERS-V2-PREP
**Lives in**: `drift-analysis/src/parsers/`

```
crates/drift/drift-analysis/src/parsers/
├── mod.rs                              # pub mod: types, traits, manager, cache, macros, languages
├── types.rs                            # ParseResult — canonical fields reconciled across 30+ docs:
│                                       #   functions, classes, imports, exports, call_sites,
│                                       #   decorators, inheritance, access_modifiers,
│                                       #   type_annotations, string_literals, numeric_literals,
│                                       #   error_handling_constructs, namespace/package info
│                                       #   Body hash + signature hash for function-level change detection
├── traits.rs                           # LanguageParser trait
├── manager.rs                          # ParserManager dispatcher
│                                       #   thread_local! parser instances (tree-sitter Parser is not Send)
├── cache.rs                            # Moka LRU parse cache (in-memory, TinyLFU admission)
│                                       #   + SQLite parse_cache table for persistence
├── macros.rs                           # define_parser! macro for mechanical language addition
└── languages/                          # 10 language parsers
    ├── mod.rs                          # pub mod: typescript, javascript, python, java, csharp,
    │                                   #   go, rust_lang, ruby, php, kotlin
    ├── typescript.rs                   # TypeScript tree-sitter parser
    ├── javascript.rs                   # JavaScript tree-sitter parser
    ├── python.rs                       # Python tree-sitter parser
    ├── java.rs                         # Java tree-sitter parser
    ├── csharp.rs                       # C# tree-sitter parser
    ├── go.rs                           # Go tree-sitter parser
    ├── rust_lang.rs                    # Rust tree-sitter parser (rust_lang to avoid keyword collision)
    ├── ruby.rs                         # Ruby tree-sitter parser
    ├── php.rs                          # PHP tree-sitter parser
    └── kotlin.rs                       # Kotlin tree-sitter parser
```

### 4.3 engine/ — System 06 (Phase 2)

**Source**: Orchestration §5.2, 06-UNIFIED-ANALYSIS-ENGINE-V2-PREP
**Lives in**: `drift-analysis/src/engine/`

```
crates/drift/drift-analysis/src/engine/
├── mod.rs                              # pub mod: pipeline, visitor, gast, resolution,
│                                       #   pattern_defs, incremental
├── pipeline.rs                         # 4-phase per-file pipeline:
│                                       #   1. AST pattern detection via visitor (single-pass)
│                                       #   2. String extraction (literals, templates, interpolations)
│                                       #   3. Regex on extracted strings (URL, SQL, secret patterns)
│                                       #   4. Resolution index building (6 strategies)
├── visitor.rs                          # Visitor trait — all detectors implement this
│                                       #   Single AST traversal, all detectors as visitors (AD4)
├── gast/                               # GAST normalization layer
│   ├── mod.rs                          # pub mod: node_types, normalizers
│   ├── node_types.rs                   # ~40-50 GAST node types
│   │                                   #   GASTNode::Other { kind, children } catch-all variant
│   └── normalizers/                    # Per-language GAST normalizers
│       ├── mod.rs                      # pub mod: base, typescript, javascript, python, java,
│       │                               #   csharp, php, go, rust_lang, cpp
│       ├── base.rs                     # Base normalizer (shared logic)
│       ├── typescript.rs               # TS normalizer
│       ├── javascript.rs               # JS normalizer
│       ├── python.rs                   # Python normalizer
│       ├── java.rs                     # Java normalizer
│       ├── csharp.rs                   # C# normalizer
│       ├── php.rs                      # PHP normalizer
│       ├── go.rs                       # Go normalizer
│       ├── rust_lang.rs                # Rust normalizer
│       └── cpp.rs                      # C++ normalizer
├── resolution.rs                       # 6 resolution strategies for cross-file symbol resolution:
│                                       #   Direct, Method, Constructor, Callback, Dynamic, External
├── pattern_defs.rs                     # Declarative TOML pattern definitions (user-extensible)
│                                       #   CompiledQuery carries cwe_ids: SmallVec<[u32; 2]>
│                                       #   and owasp: Option<Spur>
└── incremental.rs                      # Processes only ScanDiff.added + modified files
                                        #   Content-hash skip for unchanged files
```

### 4.4 detectors/ — System 06 Detectors (Phase 2)

**Source**: Orchestration §5.3, 06-DETECTOR-SYSTEM
**Lives in**: `drift-analysis/src/detectors/`
**16 categories**, 3 variants each (Base, Learning, Semantic), 350+ total detectors

```
crates/drift/drift-analysis/src/detectors/
├── mod.rs                              # pub mod: traits, registry, api, auth, components,
│                                       #   config, contracts, data_access, documentation,
│                                       #   errors, logging, performance, security, structural,
│                                       #   styling, testing, types, accessibility
├── traits.rs                           # Detector trait: detect(&self, ctx: &DetectionContext) -> Vec<PatternMatch>
│                                       #   DetectionContext struct
│                                       #   Each detector carries cwe_ids and owasp fields
├── registry.rs                         # DetectorRegistry — category filtering, critical-only mode
│
├── api/                                # Category 1: API detectors
│   └── mod.rs                          # Base + Learning + Semantic variants
├── auth/                               # Category 2: Authentication detectors
│   └── mod.rs
├── components/                         # Category 3: Component detectors
│   └── mod.rs
├── config/                             # Category 4: Configuration detectors
│   └── mod.rs
├── contracts/                          # Category 5: Contract detectors
│   └── mod.rs
├── data_access/                        # Category 6: Data access detectors
│   └── mod.rs
├── documentation/                      # Category 7: Documentation detectors
│   └── mod.rs
├── errors/                             # Category 8: Error handling detectors
│   └── mod.rs
├── logging/                            # Category 9: Logging detectors
│   └── mod.rs
├── performance/                        # Category 10: Performance detectors
│   └── mod.rs
├── security/                           # Category 11: Security detectors
│   └── mod.rs
├── structural/                         # Category 12: Structural detectors
│   └── mod.rs
├── styling/                            # Category 13: Styling detectors
│   └── mod.rs
├── testing/                            # Category 14: Testing detectors
│   └── mod.rs
├── types/                              # Category 15: Type system detectors
│   └── mod.rs
└── accessibility/                      # Category 16: Accessibility detectors
    └── mod.rs
```


### 4.5 call_graph/ — System 05 (Phase 2)

**Source**: Orchestration §5.4, 05-CALL-GRAPH-V2-PREP
**Lives in**: `drift-analysis/src/call_graph/`

```
crates/drift/drift-analysis/src/call_graph/
├── mod.rs                              # pub mod: builder, resolution, graph, cte_fallback,
│                                       #   entry_points, incremental, types
├── builder.rs                          # Call graph construction — petgraph StableGraph in-memory
│                                       #   + SQLite persistence. Parallel extraction via rayon.
├── resolution.rs                       # 6 resolution strategies:
│                                       #   1. Direct (exact name match within same file)
│                                       #   2. Method (class.method qualified lookup)
│                                       #   3. Constructor (new/init patterns)
│                                       #   4. Callback (closure/lambda parameter tracking)
│                                       #   5. Dynamic (string-based/reflection — lower confidence)
│                                       #   6. External (cross-module via import/export resolution)
├── graph.rs                            # StableGraph wrapper, BFS traversal, node/edge types
├── cte_fallback.rs                     # SQLite recursive CTE fallback for >500K functions
│                                       #   Temp table for visited set, max_depth=5
│                                       #   in_memory_threshold config (default 500K functions)
├── entry_points.rs                     # 5 heuristic categories: exported functions, main/index,
│                                       #   route handlers, test functions, CLI entry points
├── incremental.rs                      # Re-extract only changed files O(edges_in_changed_file),
│                                       #   remove edges for deleted files, re-resolve affected
└── types.rs                            # CallNode, CallEdge, ResolutionStrategy, DI framework support
                                        #   5 frameworks: FastAPI, Spring, NestJS, Laravel, ASP.NET
                                        #   at confidence 0.80
```

### 4.6 boundaries/ — System 07 (Phase 2)

**Source**: Orchestration §5.5, 07-BOUNDARY-DETECTION-V2-PREP
**Lives in**: `drift-analysis/src/boundaries/`

```
crates/drift/drift-analysis/src/boundaries/
├── mod.rs                              # pub mod: detector, frameworks, extractors,
│                                       #   sensitive_fields, confidence, types
├── detector.rs                         # Two-phase learn-then-detect architecture
├── frameworks.rs                       # 33+ ORM framework detection across 9 languages
│                                       #   (28 from v1 + 5 new: MikroORM, Kysely, sqlc,
│                                       #   SQLBoiler, Qt SQL)
├── extractors.rs                       # 10 dedicated field extractors
│                                       #   (7 from v1 + 3 new: EfCoreExtractor,
│                                       #   HibernateExtractor, EloquentExtractor)
├── sensitive_fields.rs                 # 4 categories: PII, Credentials, Financial, Health
│                                       #   ~100+ patterns (3x v1's ~30)
│                                       #   6 formal false-positive filters
├── confidence.rs                       # Confidence scoring with 5 weighted factors
└── types.rs                            # Boundary, BoundaryField, SensitivityCategory types
```

### 4.7 language_provider/ — System 08 (Phase 2)

**Source**: Orchestration §5.6, 08-UNIFIED-LANGUAGE-PROVIDER-V2-PREP
**Lives in**: `drift-analysis/src/language_provider/`

```
crates/drift/drift-analysis/src/language_provider/
├── mod.rs                              # pub mod: provider, normalizers, orm_matchers,
│                                       #   call_chain, categories, framework_detection,
│                                       #   n_plus_one, taint_sinks
├── provider.rs                         # UnifiedLanguageProvider — semantic bridge between
│                                       #   raw parsing and language-agnostic detection
├── normalizers.rs                      # 9 language normalizers (TS/JS, Python, Java, C#,
│                                       #   PHP, Go, Rust, C++, base)
├── orm_matchers.rs                     # 22 ORM/framework matchers
├── call_chain.rs                       # UnifiedCallChain universal representation
├── categories.rs                       # 12 semantic categories
├── framework_detection.rs              # 5+ framework pattern sets
├── n_plus_one.rs                       # N+1 query detection module — §10.4
│                                       #   8 ORM frameworks: ActiveRecord, Django ORM,
│                                       #   SQLAlchemy, Hibernate, Entity Framework,
│                                       #   Prisma, Sequelize, TypeORM
│                                       #   GraphQL N+1 resolver detection
└── taint_sinks.rs                      # Taint sink extraction module
```

### 4.8 patterns/ — Phase 3 (Pattern Intelligence)

**Source**: Orchestration §6.2–§6.5
**Lives in**: `drift-analysis/src/patterns/`
**Systems**: Pattern Aggregation (12), Bayesian Confidence (10), Outlier Detection (11), Learning (13)

```
crates/drift/drift-analysis/src/patterns/
├── mod.rs                              # pub mod: aggregation, confidence, outliers, learning
│
├── aggregation/                        # System 12 — §6.2 Pattern Aggregation & Deduplication
│   ├── mod.rs                          # pub mod: pipeline, grouping, merging, similarity,
│   │                                   #   hierarchy, counters, gold_layer
│   ├── pipeline.rs                     # 7-phase aggregation pipeline orchestrator
│   ├── grouping.rs                     # Phase 1: Group by pattern ID (bucket per-file matches)
│   ├── merging.rs                      # Phase 2: Cross-file merging (same pattern across files)
│   ├── similarity.rs                   # Phase 3-4: Jaccard similarity (0.85 threshold flags,
│   │                                   #   0.95 auto-merge) + MinHash LSH for approximate
│   │                                   #   near-duplicate detection at scale (n > 50K)
│   ├── hierarchy.rs                    # Phase 5: Parent-child pattern relationships
│   ├── counters.rs                     # Phase 6: Counter reconciliation
│   │                                   #   (location_count, outlier_count caches)
│   └── gold_layer.rs                   # Phase 7: Gold layer refresh (materialized views)
│
├── confidence/                         # System 10 — §6.3 Bayesian Confidence Scoring
│   ├── mod.rs                          # pub mod: scorer, beta, factors, tiers, momentum
│   ├── scorer.rs                       # Bayesian confidence scorer orchestrator
│   ├── beta.rs                         # Beta distribution: Beta(1+k, 1+n-k) posterior
│   ├── factors.rs                      # 5-factor model: frequency, consistency, age, spread, momentum
│   ├── tiers.rs                        # Graduated tiers by credible interval width:
│   │                                   #   Established (≥0.85), Emerging (≥0.70),
│   │                                   #   Tentative (≥0.50), Uncertain (<0.50)
│   └── momentum.rs                     # Temporal decay + momentum tracking (rising/falling/stable)
│
├── outliers/                           # System 11 — §6.4 Outlier Detection
│   ├── mod.rs                          # pub mod: detector, z_score, grubbs, esd, iqr,
│   │                                   #   mad, rule_based, tiers, scoring
│   ├── detector.rs                     # Auto-selection based on sample size
│   ├── z_score.rs                      # Z-Score with iterative masking (n ≥ 30), 3-iteration cap
│   ├── grubbs.rs                       # Grubbs' test (10 ≤ n < 30), single outlier
│   ├── esd.rs                          # Generalized ESD / Rosner test (n ≥ 25, multiple outliers)
│   ├── iqr.rs                          # IQR with Tukey fences (supplementary, non-normal data)
│   ├── mad.rs                          # Modified Z-Score / MAD (robust to extreme outliers)
│   ├── rule_based.rs                   # Rule-based (always, for structural rules)
│   ├── tiers.rs                        # 4 significance tiers: Critical, High, Moderate, Low
│   └── scoring.rs                      # Deviation scoring (normalized 0.0-1.0 severity)
│                                       #   Outlier-to-violation conversion pipeline
│                                       #   T-distribution critical values via statrs crate
│
└── learning/                           # System 13 — §6.5 Learning System
    ├── mod.rs                          # pub mod: discoverer, categories, thresholds,
    │                                   #   promotion, dirichlet, scope, retention
    ├── discoverer.rs                   # Bayesian convention discovery engine
    ├── categories.rs                   # 5 categories: Universal, ProjectSpecific, Emerging,
    │                                   #   Legacy, Contested (within 15% frequency)
    ├── thresholds.rs                   # minOccurrences=3, dominance=0.60, minFiles=2
    ├── promotion.rs                    # Automatic pattern promotion: discovered → approved
    │                                   #   Re-learning trigger: >10% files changed → full re-learn
    ├── dirichlet.rs                    # Dirichlet-Multinomial extension for multi-value conventions
    ├── scope.rs                        # Convention scope system (project / directory / package)
    └── retention.rs                    # Convention expiry & retention policies
```


### 4.9 graph/ — Phase 4 (Graph Intelligence)

**Source**: Orchestration §7.2–§7.6
**Lives in**: `drift-analysis/src/graph/`
**Systems**: Reachability (14), Taint (15), Error Handling (16), Impact (17), Test Topology (18)

```
crates/drift/drift-analysis/src/graph/
├── mod.rs                              # pub mod: reachability, taint, error_handling,
│                                       #   impact, test_topology
│
├── reachability/                       # System 14 — §7.2 Reachability Analysis
│   ├── mod.rs                          # pub mod: engine, sensitivity, cache, cross_service,
│   │                                   #   field_flow
│   ├── engine.rs                       # Forward/inverse BFS traversal on petgraph
│   │                                   #   Auto-select: petgraph for <10K nodes,
│   │                                   #   SQLite recursive CTE for >10K nodes
│   ├── sensitivity.rs                  # Sensitivity classification: 4 categories
│   │                                   #   (Critical, High, Medium, Low)
│   │                                   #   "Can user input reach this SQL query?"
│   ├── cache.rs                        # Reachability caching with LRU + invalidation on graph changes
│   ├── cross_service.rs                # Cross-service reachability for microservice boundaries
│   └── field_flow.rs                   # Field-level data flow tracking
│
├── taint/                              # System 15 — §7.3 Taint Analysis (NET NEW)
│   ├── mod.rs                          # pub mod: engine, registry, sources, sinks,
│   │                                   #   sanitizers, labels, summaries, sarif, types
│   ├── engine.rs                       # Taint analysis engine
│   │                                   #   Phase 1: Intraprocedural (within-function dataflow)
│   │                                   #   Phase 2: Interprocedural via function summaries
│   ├── registry.rs                     # TOML-driven source/sink/sanitizer registry
│   │                                   #   (extensible without code changes)
│   ├── sources.rs                      # Taint source definitions
│   ├── sinks.rs                        # 17 sink types with CWE mappings:
│   │                                   #   SqlQuery (CWE-89), OsCommand (CWE-78),
│   │                                   #   CodeExecution (CWE-94), FileWrite (CWE-22),
│   │                                   #   FileRead (CWE-22), HtmlOutput (CWE-79),
│   │                                   #   HttpRedirect (CWE-601), HttpRequest (CWE-918),
│   │                                   #   Deserialization (CWE-502), LdapQuery (CWE-90),
│   │                                   #   XpathQuery (CWE-643), TemplateRender (CWE-1336),
│   │                                   #   LogOutput (CWE-117), HeaderInjection (CWE-113),
│   │                                   #   RegexConstruction (CWE-1333), XmlParsing (CWE-611),
│   │                                   #   FileUpload (CWE-434), Custom(u32)
│   ├── sanitizers.rs                   # Sanitizer definitions + tracking
│   ├── labels.rs                       # Taint label propagation
│   ├── summaries.rs                    # Function summaries for interprocedural analysis
│   ├── sarif.rs                        # SARIF code flow generation for taint paths
│   └── types.rs                        # TaintFlow, TaintPath, TaintLabel types
│
├── error_handling/                     # System 16 — §7.4 Error Handling Analysis
│   ├── mod.rs                          # pub mod: topology, profiler, handler_detection,
│   │                                   #   propagation, gap_analysis, frameworks, cwe_mapping,
│   │                                   #   remediation
│   ├── topology.rs                     # 8-phase topology engine orchestrator
│   ├── profiler.rs                     # Phase 1: Error type profiling
│   ├── handler_detection.rs            # Phase 2: Handler detection
│   ├── propagation.rs                  # Phase 3: Propagation chain tracing via call graph
│   ├── gap_analysis.rs                 # Phase 4-5: Unhandled path identification + gap analysis
│   │                                   #   (empty catch, swallowed errors, generic catches)
│   ├── frameworks.rs                   # Phase 6: Framework-specific analysis (20+ frameworks):
│   │                                   #   Express, Koa, Hapi, Fastify, Django, Flask, Spring,
│   │                                   #   ASP.NET, Rails, Sinatra, Laravel, Phoenix, Gin, Echo,
│   │                                   #   Actix, Rocket, NestJS, Next.js, Nuxt, SvelteKit
│   ├── cwe_mapping.rs                  # Phase 7: CWE/OWASP A10:2025 mapping
│   └── remediation.rs                  # Phase 8: Remediation suggestions
│
├── impact/                             # System 17 — §7.5 Impact Analysis
│   ├── mod.rs                          # pub mod: blast_radius, risk_scoring, dead_code,
│   │                                   #   path_finding, types
│   ├── blast_radius.rs                 # Transitive caller analysis via call graph BFS
│   ├── risk_scoring.rs                 # Risk scoring per function — 5 factors:
│   │                                   #   blast radius, sensitivity, test coverage,
│   │                                   #   complexity, change frequency
│   ├── dead_code.rs                    # Dead code detection with 10 false-positive categories:
│   │                                   #   entry points, event handlers, reflection targets,
│   │                                   #   dependency injection, test utilities, framework hooks,
│   │                                   #   decorators/annotations, interface implementations,
│   │                                   #   conditional compilation, dynamic imports
│   ├── path_finding.rs                 # Dijkstra shortest path + K-shortest paths
│   │                                   #   for impact visualization
│   └── types.rs                        # ImpactResult, BlastRadius, RiskScore types
│
└── test_topology/                      # System 18 — §7.6 Test Topology
    ├── mod.rs                          # pub mod: scorer, smells, coverage_mapping,
    │                                   #   minimum_set, frameworks, types
    ├── scorer.rs                       # 7-dimension quality scoring:
    │                                   #   coverage breadth, coverage depth, assertion density,
    │                                   #   mock ratio, test isolation, test freshness, test stability
    ├── smells.rs                       # 24 test smell detectors:
    │                                   #   mystery guest, eager test, lazy test,
    │                                   #   assertion roulette, etc.
    ├── coverage_mapping.rs             # Coverage mapping via call graph BFS
    │                                   #   (test function → tested functions)
    ├── minimum_set.rs                  # Minimum test set computation via greedy set cover
    ├── frameworks.rs                   # 45+ test framework support
    └── types.rs                        # TestQualityScore, TestSmell, CoverageMap types
```

### 4.10 structural/ — Phase 5 (Structural Intelligence)

**Source**: Orchestration §8.2–§8.9
**Lives in**: `drift-analysis/src/structural/`
**Systems**: Coupling (19), Constraints (20), Contracts (21), Constants (22),
Wrappers (23), DNA (24), OWASP/CWE (26), Crypto (27)

```
crates/drift/drift-analysis/src/structural/
├── mod.rs                              # pub mod: coupling, constraints, contracts, constants,
│                                       #   wrappers, dna, owasp_cwe, crypto
│
├── coupling/                           # System 19 — §8.2 Coupling Analysis
│   ├── mod.rs                          # pub mod: pipeline, import_graph, martin_metrics,
│   │                                   #   cycle_detection, zones, suggestions, trends
│   ├── pipeline.rs                     # 10-phase pipeline orchestrator
│   ├── import_graph.rs                 # Module boundary detection + import graph construction
│   ├── martin_metrics.rs               # Robert C. Martin metrics:
│   │                                   #   Ce (efferent), Ca (afferent),
│   │                                   #   I (instability = Ce/(Ce+Ca)),
│   │                                   #   A (abstractness),
│   │                                   #   D (distance from main sequence = |A+I-1|)
│   ├── cycle_detection.rs              # Tarjan's SCC via petgraph::algo::tarjan_scc
│   │                                   #   + condensation graph
│   ├── zones.rs                        # Zone classification: Zone of Pain,
│   │                                   #   Zone of Uselessness, Main Sequence
│   ├── suggestions.rs                  # Cycle break suggestions
│   └── trends.rs                       # Trend tracking over time
│
├── constraints/                        # System 20 — §8.3 Constraint System
│   ├── mod.rs                          # pub mod: detector, synthesizer, store, verifier,
│   │                                   #   invariant_types, freezing, mining
│   ├── detector.rs                     # InvariantDetector — AST-based (not regex)
│   ├── synthesizer.rs                  # ConstraintSynthesizer
│   ├── store.rs                        # ConstraintStore
│   ├── verifier.rs                     # ConstraintVerifier — 4-stage pipeline
│   ├── invariant_types.rs              # 12 invariant types: must_exist, must_not_exist,
│   │                                   #   must_precede, must_follow, must_colocate,
│   │                                   #   must_separate, data_flow, naming_convention,
│   │                                   #   dependency_direction, layer_boundary,
│   │                                   #   size_limit, complexity_limit
│   ├── freezing.rs                     # FreezingArchRule baseline — snapshot constraints,
│   │                                   #   fail on regression
│   └── mining.rs                       # Constraint mining from existing code patterns
│
├── contracts/                          # System 21 — §8.4 Contract Tracking
│   ├── mod.rs                          # pub mod: tracker, schema_parsing, code_extraction,
│   │                                   #   matching, breaking_changes, mismatches,
│   │                                   #   confidence, paradigms
│   ├── tracker.rs                      # Multi-protocol API contract verification orchestrator
│   ├── schema_parsing.rs               # Schema-first parsing: OpenAPI 3.0/3.1, GraphQL SDL,
│   │                                   #   Protobuf, AsyncAPI 2.x/3.0
│   ├── code_extraction.rs              # Code-first extraction — 20+ backend framework extractors,
│   │                                   #   15+ frontend/consumer libraries
│   ├── matching.rs                     # BE↔FE matching via path similarity + schema compatibility
│   ├── breaking_changes.rs             # Breaking change classifier: 20+ change types across
│   │                                   #   4 severity levels (breaking, deprecation, compatible, cosmetic)
│   ├── mismatches.rs                   # 7 mismatch types: field missing, type mismatch,
│   │                                   #   required/optional, enum value, nested shape,
│   │                                   #   array/scalar, nullable
│   ├── confidence.rs                   # Bayesian 7-signal confidence model:
│   │                                   #   path similarity, field overlap, type compatibility,
│   │                                   #   response shape match, temporal stability,
│   │                                   #   cross-validation, consumer agreement
│   └── paradigms/                      # 7 paradigms
│       ├── mod.rs                      # pub mod: rest, graphql, grpc, asyncapi, trpc,
│       │                               #   websocket, event_driven
│       ├── rest.rs                     # REST paradigm
│       ├── graphql.rs                  # GraphQL paradigm
│       ├── grpc.rs                     # gRPC paradigm
│       ├── asyncapi.rs                 # AsyncAPI paradigm
│       ├── trpc.rs                     # tRPC paradigm (TypeScript-only)
│       ├── websocket.rs                # WebSocket paradigm
│       └── event_driven.rs             # Event-driven paradigm (Kafka, RabbitMQ, SNS/SQS, Redis pub/sub)

│
├── constants/                          # System 22 — §8.5 Constants & Environment
│   ├── mod.rs                          # pub mod: pipeline, extraction, magic_numbers,
│   │                                   #   secrets, inconsistency, dead_constants,
│   │                                   #   env_vars, dotenv, missing_vars, framework_env,
│   │                                   #   sensitivity, entropy, health, types
│   ├── pipeline.rs                     # 13-phase unified pipeline orchestrator
│   ├── extraction.rs                   # Phase 1: Constant extraction from AST (9+ languages)
│   ├── magic_numbers.rs                # Phase 2: Magic number detection via AST
│   │                                   #   (scope-aware, context-aware — replaces v1 regex)
│   ├── secrets.rs                      # Phase 3: Secret detection engine
│   │                                   #   150+ patterns, 7 severity tiers:
│   │                                   #   Critical/High/Medium/Low/Info/FP/Suppressed
│   │                                   #   Format validation as 3rd confidence signal
│   │                                   #   (AWS AKIA*, GitHub ghp_*)
│   ├── inconsistency.rs               # Phase 4: Inconsistency detection
│   │                                   #   (fuzzy name matching, camelCase ↔ snake_case)
│   ├── dead_constants.rs               # Phase 5: Dead constant detection via call graph
│   ├── env_vars.rs                     # Phase 6: Environment variable extraction
│   │                                   #   (9+ languages, 15+ access methods)
│   ├── dotenv.rs                       # Phase 7: .env file parsing
│   │                                   #   (.env, .env.local, .env.production, .env.*.local)
│   ├── missing_vars.rs                 # Phase 8: Missing variable detection
│   │                                   #   (referenced in code but not in .env)
│   ├── framework_env.rs                # Phase 9: Framework-specific env detection
│   │                                   #   (Next.js NEXT_PUBLIC_*, Vite VITE_*,
│   │                                   #   Django DJANGO_*, Spring)
│   ├── sensitivity.rs                  # Phase 10: Sensitivity classification (4-tier)
│   ├── entropy.rs                      # Phase 11: Shannon entropy scoring
│   │                                   #   (hybrid pattern + entropy reduces FP)
│   │                                   #   CWE-798, CWE-321, CWE-547 mappings
│   ├── health.rs                       # Phase 12: Health score calculation
│   └── types.rs                        # Constant, Secret, EnvVar, MagicNumber types
│
├── wrappers/                           # System 23 — §8.6 Wrapper Detection
│   ├── mod.rs                          # pub mod: detector, categories, framework_patterns,
│   │                                   #   confidence, multi_primitive, health,
│   │                                   #   regex_set, clustering, security_bridge
│   ├── detector.rs                     # Thin delegation pattern detection engine
│   ├── categories.rs                   # 16 WrapperCategory variants:
│   │                                   #   StateManagement, DataFetching, FormHandling, Routing,
│   │                                   #   Authentication, ErrorBoundary, Caching, Styling,
│   │                                   #   Animation, Accessibility, Logging, ApiClient,
│   │                                   #   Middleware, Testing, Internationalization, Other
│   ├── framework_patterns.rs           # 8 framework detection patterns with 150+ primitive
│   │                                   #   function signatures across 8 frameworks:
│   │                                   #   React, Vue, Angular, Svelte, SolidJS, Express,
│   │                                   #   Next.js, TanStack Query
│   ├── confidence.rs                   # Enhanced 7-signal confidence model:
│   │                                   #   import match, name match, call-site match,
│   │                                   #   export status, usage count, depth analysis,
│   │                                   #   framework specificity
│   ├── multi_primitive.rs              # Multi-primitive detection (single function wrapping
│   │                                   #   multiple primitives from same category)
│   ├── health.rs                       # Wrapper health scoring: consistency, coverage,
│   │                                   #   abstraction depth → 0-100 score
│   ├── regex_set.rs                    # RegexSet optimization for single-pass multi-pattern
│   │                                   #   primitive matching
│   ├── clustering.rs                   # Clustering for wrapper family identification
│   └── security_bridge.rs              # Security wrapper categories (auth, validation,
│                                       #   sanitization, encryption, access control) →
│                                       #   taint analysis sanitizer registry
│
├── dna/                                # System 24 — §8.7 DNA System
│   ├── mod.rs                          # pub mod: extractor, genes, health, mutations,
│   │                                   #   context_builder, regex_set, types
│   ├── extractor.rs                    # Gene extractor framework
│   ├── genes/                          # 10 gene extractors
│   │   ├── mod.rs                      # pub mod: variant_handling, responsive_approach,
│   │   │                               #   state_styling, theming, spacing_philosophy,
│   │   │                               #   animation_approach, api_response_format,
│   │   │                               #   error_response_format, logging_format, config_pattern
│   │   ├── variant_handling.rs         # Frontend gene: variant-handling
│   │   ├── responsive_approach.rs      # Frontend gene: responsive-approach
│   │   ├── state_styling.rs            # Frontend gene: state-styling
│   │   ├── theming.rs                  # Frontend gene: theming
│   │   ├── spacing_philosophy.rs       # Frontend gene: spacing-philosophy
│   │   ├── animation_approach.rs       # Frontend gene: animation-approach
│   │   ├── api_response_format.rs      # Backend gene: api-response-format
│   │   ├── error_response_format.rs    # Backend gene: error-response-format
│   │   ├── logging_format.rs           # Backend gene: logging-format
│   │   └── config_pattern.rs           # Backend gene: config-pattern
│   ├── health.rs                       # Health scoring formula:
│   │                                   #   healthScore = consistency(40%) + confidence(30%)
│   │                                   #   + mutations(20%) + coverage(10%)
│   │                                   #   Output: 0-100 score, clamped
│   ├── mutations.rs                    # Mutation detection between snapshots (SHA-256 IDs)
│   │                                   #   Impact classification: high/medium/low
│   ├── context_builder.rs              # 4-level AI context builder:
│   │                                   #   overview (~2K tokens), standard (~6K),
│   │                                   #   deep (~12K), full (unlimited)
│   ├── regex_set.rs                    # RegexSet optimization: 10 genes × ~4 alleles × ~3 patterns
│   │                                   #   = ~120 patterns matched in single pass per file
│   └── types.rs                        # Gene, Allele, DnaProfile, Mutation types
│
├── owasp_cwe/                          # System 26 — §8.8 OWASP/CWE Mapping
│   ├── mod.rs                          # pub mod: registry, enrichment, coverage, security_finding,
│   │                                   #   posture, compliance, sarif_taxonomy, wrapper_bridge
│   ├── registry.rs                     # 173 detector → CWE/OWASP mapping matrix
│   │                                   #   Compile-time const registries in Rust
│   │                                   #   User extensions via TOML
│   ├── enrichment.rs                   # FindingEnrichmentPipeline:
│   │                                   #   enrich_detector_violation(), enrich_taint_flow(),
│   │                                   #   enrich_secret(), enrich_error_gap(),
│   │                                   #   enrich_boundary_violation()
│   ├── coverage.rs                     # OWASP 2025 Top 10 coverage: 10/10 categories
│   │                                   #   CWE Top 25 2025: 20/25 fully + 5/25 partially
│   │                                   #   Gap reporting for CWEs without upstream detectors
│   ├── security_finding.rs             # SecurityFinding unified type — raw findings from all
│   │                                   #   upstream subsystems enriched with CWE IDs,
│   │                                   #   OWASP categories, severity, compliance metadata
│   ├── posture.rs                      # Security posture score (composite 0-100)
│   ├── compliance.rs                   # Compliance report generator
│   ├── sarif_taxonomy.rs               # SARIF taxonomy integration
│   └── wrapper_bridge.rs               # Wrapper → sanitizer bridge:
│                                       #   security wrappers mapped to taint sanitizer registry
│                                       #   Wrapper bypass detection
│
└── crypto/                             # System 27 — §8.9 Cryptographic Failure Detection (NET NEW)
    ├── mod.rs                          # pub mod: detector, categories, patterns, confidence,
    │                                   #   health, remediation, types
    ├── detector.rs                     # Crypto failure detection engine
    ├── categories.rs                   # 14 detection categories:
    │                                   #   WeakHash (MD5, SHA1), DeprecatedCipher (DES, 3DES, RC4),
    │                                   #   HardcodedKey, EcbMode, StaticIv,
    │                                   #   InsufficientKeyLen (<2048 RSA, <256 ECC),
    │                                   #   DisabledTls, InsecureRandom, JwtConfusion (alg=none),
    │                                   #   PlaintextPassword, WeakKdf, MissingEncryption,
    │                                   #   CertPinningBypass, NonceReuse
    ├── patterns.rs                     # 261 patterns across 12 languages
    │                                   #   (Python, JS/TS, Java, C#, Go, Ruby, PHP, Kotlin,
    │                                   #   Swift, Rust, C/C++, Scala)
    │                                   #   TOML-based pattern definitions (user-customizable)
    ├── confidence.rs                   # 4-factor crypto-specific confidence scoring
    ├── health.rs                       # Crypto health score calculator
    │                                   #   OWASP A04:2025 (Cryptographic Failures) coverage
    │                                   #   CWE-1439 category mapping (30+ member CWEs)
    ├── remediation.rs                  # Remediation suggestion engine
    └── types.rs                        # CryptoFinding, CryptoCategory, CryptoSeverity types
```


### 4.11 enforcement/ — Phase 6 (Enforcement)

**Source**: Orchestration §9.2–§9.6
**Lives in**: `drift-analysis/src/enforcement/`
**Systems**: Rules Engine, Quality Gates (09), Policy Engine, Audit (25),
Violation Feedback Loop (31), Reporters

```
crates/drift/drift-analysis/src/enforcement/
├── mod.rs                              # pub mod: rules, gates, policy, audit, feedback, reporters
│
├── rules/                              # §9.2 Rules Engine Evaluator
│   ├── mod.rs                          # pub mod: evaluator, violations, severity, quick_fixes
│   ├── evaluator.rs                    # Pattern matcher → violations → severity assignment
│   ├── violations.rs                   # Violation type: file/line/column locations,
│   │                                   #   severity levels (error/warning/info/hint)
│   ├── severity.rs                     # Severity assignment logic
│   └── quick_fixes.rs                  # 7 fix strategies: add import, rename,
│                                       #   extract function, wrap in try/catch,
│                                       #   add type annotation, add test, add documentation
│
├── gates/                              # System 09 — §9.3 Quality Gates
│   ├── mod.rs                          # pub mod: orchestrator, pattern_compliance,
│   │                                   #   constraint_verification, security_boundaries,
│   │                                   #   test_coverage, error_handling, regression_detection
│   ├── orchestrator.rs                 # DAG-based gate orchestrator
│   │                                   #   (gates can depend on other gates)
│   ├── pattern_compliance.rs           # Gate 1: Are approved patterns followed?
│   ├── constraint_verification.rs      # Gate 2: Are architectural constraints met?
│   ├── security_boundaries.rs          # Gate 3: Are sensitive fields protected?
│   ├── test_coverage.rs                # Gate 4: Is coverage above threshold?
│   ├── error_handling.rs               # Gate 5: Are errors properly handled?
│   └── regression_detection.rs         # Gate 6: Has health score declined?
│
├── policy/                             # §9.4 Policy Engine
│   ├── mod.rs                          # pub mod: engine, policies, aggregation, progressive
│   ├── engine.rs                       # Policy engine orchestrator
│   ├── policies.rs                     # 4 built-in policies: strict, standard, lenient, custom
│   ├── aggregation.rs                  # 4 aggregation modes: all-must-pass, any-must-pass,
│   │                                   #   weighted, threshold
│   └── progressive.rs                  # Progressive enforcement ramp-up for new projects
│                                       #   New-code-first enforcement (SonarQube "Clean as You Code")
│
├── audit/                              # System 25 — §9.5 Audit System
│   ├── mod.rs                          # pub mod: scorer, degradation, duplicates,
│   │                                   #   trends, anomaly, categories, auto_approve
│   ├── scorer.rs                       # 5-factor health scoring:
│   │                                   #   health_score = (avgConfidence × 0.30 +
│   │                                   #   approvalRatio × 0.20 + complianceRate × 0.20 +
│   │                                   #   crossValidationRate × 0.15 +
│   │                                   #   duplicateFreeRate × 0.15) × 100
│   ├── degradation.rs                  # Degradation detection:
│   │                                   #   warning at -5 points / -5% confidence,
│   │                                   #   critical at -15 points / -15% confidence
│   ├── duplicates.rs                   # Three-tier Jaccard duplicate detection:
│   │                                   #   >0.95 auto-merge, >0.90 recommend, 0.85-0.90 review
│   ├── trends.rs                       # Trend prediction via linear regression on health_trends
│   ├── anomaly.rs                      # Anomaly detection via Z-score on audit metrics
│   ├── categories.rs                   # Per-category health breakdown (16 categories)
│   └── auto_approve.rs                 # Auto-approve: confidence ≥ 0.90, outlierRatio ≤ 0.50,
│                                       #   locations ≥ 3, no error-level issues
│
├── feedback/                           # System 31 — §9.6 Violation Feedback Loop
│   ├── mod.rs                          # pub mod: tracker, metrics, auto_disable,
│   │                                   #   suppression, confidence_feedback
│   ├── tracker.rs                      # Tricorder-style false-positive tracking per detector
│   ├── metrics.rs                      # FP rate, dismissal rate, action rate per detector
│   ├── auto_disable.rs                 # Auto-disable rule: >20% FP rate sustained 30+ days
│   │                                   #   → detector disabled
│   ├── suppression.rs                  # Inline suppression system (drift-ignore comments)
│   └── confidence_feedback.rs          # Feeds back into confidence scoring
│                                       #   (dismissed violations reduce pattern confidence)
│
└── reporters/                          # §11.4 Quality Gate Reporters
    ├── mod.rs                          # pub mod: sarif, github, gitlab, junit, html,
    │                                   #   json, console, sonarqube
    ├── sarif.rs                        # SARIF 2.1.0 reporter — CWE + OWASP taxonomies
    │                                   #   (built in Phase 6, key to GitHub Code Scanning)
    ├── github.rs                       # GitHub Code Quality reporter
    ├── gitlab.rs                       # GitLab Code Quality reporter
    ├── junit.rs                        # JUnit XML reporter
    ├── html.rs                         # HTML reporter
    ├── json.rs                         # JSON reporter
    ├── console.rs                      # Console reporter
    └── sonarqube.rs                    # SonarQube Generic Issue Format (P2, post-launch)
```

### 4.12 advanced/ — Phase 7 (Advanced & Capstone)

**Source**: Orchestration §10.1–§10.4
**Lives in**: `drift-analysis/src/advanced/`
**Systems**: Simulation Engine (28), Decision Mining (29), Context Generation (30)
**Note**: N+1 detection lives in `language_provider/n_plus_one.rs` (§4.7 above)

```
crates/drift/drift-analysis/src/advanced/
├── mod.rs                              # pub mod: simulation, decisions, context
│
├── simulation/                         # System 28 — §10.1 Simulation Engine (Rust side)
│   ├── mod.rs                          # pub mod: engine, categories, scorers, monte_carlo,
│   │                                   #   strategies, types
│   ├── engine.rs                       # Simulation engine — Rust heavy computation:
│   │                                   #   impact analysis, pattern matching, call graph
│   │                                   #   traversal, coupling friction
│   ├── categories.rs                   # 13 task categories: add feature, fix bug, refactor,
│   │                                   #   migrate framework, add test, security fix,
│   │                                   #   performance optimization, dependency update,
│   │                                   #   API change, database migration, config change,
│   │                                   #   documentation, infrastructure
│   ├── scorers.rs                      # 4 scorers: complexity, risk (blast radius + sensitivity),
│   │                                   #   effort (LOC + dependency count),
│   │                                   #   confidence (test coverage + constraint satisfaction)
│   ├── monte_carlo.rs                  # Monte Carlo simulation for effort estimation
│   │                                   #   with confidence intervals (P10/P50/P90)
│   ├── strategies.rs                   # 15 strategy recommendations
│   └── types.rs                        # SimulationResult, Approach, Score types
│
├── decisions/                          # System 29 — §10.2 Decision Mining (Rust side)
│   ├── mod.rs                          # pub mod: miner, git_analysis, adr_detection,
│   │                                   #   categories, correlation, types
│   ├── miner.rs                        # Decision mining engine — Rust git2 high-performance pipeline
│   ├── git_analysis.rs                 # git2 crate integration for commit history analysis
│   ├── adr_detection.rs                # ADR detection in markdown files
│   ├── categories.rs                   # 12 decision categories
│   ├── correlation.rs                  # Temporal correlation with pattern changes
│   └── types.rs                        # Decision, ADR, DecisionCategory types
│
└── context/                            # System 30 — §10.3 Context Generation (analysis-side)
    ├── mod.rs                          # pub mod: analyzer, intent_scoring, types
    ├── analyzer.rs                     # Analysis-side context data extraction
    ├── intent_scoring.rs               # Intent-weighted scoring for context selection
    └── types.rs                        # ContextData, IntentWeight types
```

### drift-analysis Tests & Benches

```
crates/drift/drift-analysis/
├── tests/
│   ├── scanner_test.rs                 # Scanner integration tests
│   ├── parsers_test.rs                 # Parser integration tests (all 10 languages)
│   ├── engine_test.rs                  # Unified Analysis Engine tests
│   ├── detectors_test.rs              # Detector system tests (16 categories)
│   ├── call_graph_test.rs             # Call graph builder tests (6 resolution strategies)
│   ├── boundaries_test.rs             # Boundary detection tests (33+ ORMs)
│   ├── language_provider_test.rs      # ULP tests (9 normalizers)
│   ├── aggregation_test.rs            # Pattern aggregation tests
│   ├── confidence_test.rs             # Bayesian confidence tests
│   ├── outliers_test.rs               # Outlier detection tests (6 methods)
│   ├── learning_test.rs               # Learning system tests
│   ├── reachability_test.rs           # Reachability analysis tests
│   ├── taint_test.rs                  # Taint analysis tests (17 sink types)
│   ├── error_handling_test.rs         # Error handling analysis tests
│   ├── impact_test.rs                 # Impact analysis tests
│   ├── test_topology_test.rs          # Test topology tests
│   ├── coupling_test.rs               # Coupling analysis tests
│   ├── constraints_test.rs            # Constraint system tests (12 invariant types)
│   ├── contracts_test.rs              # Contract tracking tests (7 paradigms)
│   ├── constants_test.rs              # Constants & environment tests
│   ├── wrappers_test.rs               # Wrapper detection tests
│   ├── dna_test.rs                    # DNA system tests (10 genes)
│   ├── owasp_cwe_test.rs             # OWASP/CWE mapping tests
│   ├── crypto_test.rs                 # Crypto failure detection tests (14 categories)
│   ├── rules_test.rs                  # Rules engine tests
│   ├── gates_test.rs                  # Quality gates tests (6 gates)
│   ├── policy_test.rs                 # Policy engine tests
│   ├── audit_test.rs                  # Audit system tests
│   ├── feedback_test.rs               # Violation feedback loop tests
│   ├── reporters_test.rs              # Reporter format tests (8 formats)
│   ├── simulation_test.rs             # Simulation engine tests
│   ├── decisions_test.rs              # Decision mining tests
│   └── context_test.rs                # Context generation tests
└── benches/
    ├── scanner_bench.rs                # Scanner throughput benchmarks
    ├── parser_bench.rs                 # Parser throughput benchmarks
    ├── engine_bench.rs                 # Analysis engine benchmarks
    ├── call_graph_bench.rs            # Call graph build + BFS benchmarks
    ├── confidence_bench.rs            # Confidence scoring benchmarks
    ├── taint_bench.rs                 # Taint analysis benchmarks
    └── coupling_bench.rs              # Coupling analysis benchmarks
```


---

## 5. drift-context (Phase 7 — Context Generation)

**Source**: Orchestration §10.3, 30-CONTEXT-GENERATION-V2-PREP
**Depends on**: drift-core
**Systems**: Context Generation (System 30) — 6th crate, isolates tiktoken-rs,
quick-xml, serde_yaml, glob, base64 dependencies

```
crates/drift/drift-context/
├── Cargo.toml
└── src/
    ├── lib.rs                          # pub mod declarations + crate-level re-exports
    │
    ├── generation/                     # Context generation core
    │   ├── mod.rs                      # pub mod: builder, intent, deduplication
    │   ├── builder.rs                  # Context builder — 3 depth levels:
    │   │                               #   overview (~2K tokens), standard (~6K), deep (~12K)
    │   ├── intent.rs                   # Intent-weighted selection
    │   │                               #   Different context for: fix bug, add feature,
    │   │                               #   understand code, security audit
    │   └── deduplication.rs            # Session-aware dedup (30-50% token savings on follow-ups)
    │
    ├── tokenization/                   # Token budgeting
    │   ├── mod.rs                      # pub mod: budget, counter
    │   ├── budget.rs                   # Token budgeting, model-aware limits
    │   │                               #   Strategic content ordering (primacy-recency
    │   │                               #   for transformer attention)
    │   └── counter.rs                  # tiktoken-rs wrapper
    │
    ├── formats/                        # Output format serializers
    │   ├── mod.rs                      # pub mod: xml, yaml, markdown
    │   ├── xml.rs                      # quick-xml output
    │   ├── yaml.rs                     # serde_yaml output
    │   └── markdown.rs                 # Markdown output
    │
    └── packages/                       # Package manager support
        ├── mod.rs                      # pub mod: manager
        └── manager.rs                  # 15 package manager support
```

### drift-context Tests

```
crates/drift/drift-context/
└── tests/
    └── context_test.rs                 # Context generation integration tests
```

---

## 6. drift-napi (Phases 1-8 — NAPI Bridge)

**Source**: Orchestration §4.4, §18.3, 03-NAPI-BRIDGE-V2-PREP
**Depends on**: drift-analysis, drift-storage, drift-context, drift-core
**Systems**: NAPI Bridge (System 03)
**Total**: ~55 top-level exports across ~14 modules

```
crates/drift/drift-napi/
├── Cargo.toml
├── build.rs                            # napi-build
└── src/
    ├── lib.rs                          # pub mod declarations + #[napi] re-exports
    │                                   #   #[allow(dead_code)] #[allow(unused)] at crate level
    │
    ├── runtime.rs                      # DriftRuntime singleton via OnceLock (lock-free after init)
    │                                   #   Two function categories:
    │                                   #   Command (write-heavy, return summary)
    │                                   #   Query (read-only, paginated, keyset cursors)
    │                                   #   AsyncTask for >10ms operations (libuv thread pool)
    │
    ├── conversions/                    # Type conversions at NAPI boundary
    │   ├── mod.rs                      # pub mod: error_codes, types
    │   ├── error_codes.rs              # DriftErrorCode → NAPI error conversion
    │   │                               #   14+ NAPI error codes
    │   └── types.rs                    # Rust ↔ JS type conversions
    │
    └── bindings/                       # NAPI binding modules (~14 modules, ~55 functions)
        ├── mod.rs                      # pub mod: lifecycle, scanner, analysis, patterns,
        │                               #   graph, structural, enforcement, advanced,
        │                               #   workspace, feedback
        │
        ├── lifecycle.rs                # Phase 1 (3 functions):
        │                               #   drift_initialize, drift_shutdown
        │
        ├── scanner.rs                  # Phase 1 (1 function):
        │                               #   drift_scan
        │
        ├── analysis.rs                 # Phase 2 (2-3 functions):
        │                               #   drift_analyze, drift_call_graph, drift_boundaries
        │
        ├── patterns.rs                 # Phase 3 (3-4 functions):
        │                               #   drift_patterns, drift_confidence,
        │                               #   drift_outliers, drift_conventions
        │
        ├── graph.rs                    # Phase 4 (per-system query functions):
        │                               #   reachability, taint, error_handling,
        │                               #   impact, test topology queries
        │
        ├── structural.rs               # Phase 5 (per-system query functions):
        │                               #   coupling, constraints, contracts, constants,
        │                               #   wrappers, dna, owasp, crypto queries
        │
        ├── enforcement.rs              # Phase 6 (3-4 functions):
        │                               #   drift_check, drift_audit,
        │                               #   drift_violations, drift_gates
        │
        ├── advanced.rs                 # Phase 7 (3-4 functions):
        │                               #   drift_simulate, drift_decisions, drift_context
        │
        ├── workspace.rs                # Phase 10 (16 functions):
        │                               #   Workspace management functions
        │
        └── feedback.rs                 # Phase 6 (violation feedback functions):
                                        #   Violation feedback + suppression functions
```

### drift-napi Tests

```
crates/drift/drift-napi/
└── tests/
    └── napi_test.rs                    # NAPI binding integration tests
```

---

## 7. drift-bench (Benchmarks)

**Source**: Orchestration §13.7
**Depends on**: drift-analysis, drift-storage, drift-core

```
crates/drift/drift-bench/
├── Cargo.toml
├── src/
│   ├── lib.rs                          # Shared benchmark utilities
│   └── fixtures.rs                     # Shared test fixtures and generators
└── benches/
    ├── scanner_bench.rs                # Scanner throughput benchmarks
    ├── parser_bench.rs                 # Parser throughput benchmarks
    ├── call_graph_bench.rs            # Call graph build + traversal benchmarks
    ├── confidence_bench.rs            # Confidence scoring benchmarks
    ├── storage_bench.rs               # Storage batch write + query benchmarks
    └── end_to_end_bench.rs            # Full pipeline end-to-end benchmarks
```

---

## 8. TypeScript Packages

**Source**: Orchestration §10.1, §10.2, §11.1–§11.3
**Lives in**: `packages/`

### 8.1 packages/drift-mcp/ — MCP Server (System 32, Phase 8)

**Source**: Orchestration §11.1, 32-MCP-SERVER-V2-PREP

```
packages/drift-mcp/
├── package.json
├── tsconfig.json
└── src/
    ├── index.ts                        # Package entry point
    ├── server.ts                       # MCP server setup — MCP spec 2025-11-25
    │                                   #   stdio transport (primary) + Streamable HTTP (Docker)
    │                                   #   Token budgeting via McpConfig.max_response_tokens (default 8000)
    ├── tools/
    │   ├── index.ts                    # Tool registry
    │   ├── drift_status.ts             # Entry point 1: overview, reads materialized_status, <1ms
    │   ├── drift_context.ts            # Entry point 2: deep dive, intent-weighted, replaces 3-5 calls
    │   ├── drift_scan.ts               # Entry point 3: trigger analysis
    │   └── drift_tool.ts              # Dynamic dispatch for ~49 internal analysis tools
    │                                   #   Progressive disclosure reduces token overhead ~81%
    └── transport/
        ├── index.ts                    # Transport registry
        ├── stdio.ts                    # stdio transport (primary)
        └── http.ts                     # Streamable HTTP transport (Docker/containerized)
```

### 8.2 packages/drift-cli/ — CLI (Phase 8)

**Source**: Orchestration §11.2

```
packages/drift-cli/
├── package.json
├── tsconfig.json
└── src/
    ├── index.ts                        # CLI entry point
    ├── commands/
    │   ├── index.ts                    # Command registry
    │   ├── scan.ts                     # drift scan
    │   ├── check.ts                    # drift check
    │   ├── status.ts                   # drift status
    │   ├── patterns.ts                 # drift patterns
    │   ├── violations.ts               # drift violations
    │   ├── impact.ts                   # drift impact
    │   ├── simulate.ts                 # drift simulate
    │   ├── audit.ts                    # drift audit
    │   ├── setup.ts                    # drift setup (first-time wizard)
    │   ├── doctor.ts                   # drift doctor (health checks)
    │   ├── export.ts                   # drift export
    │   ├── explain.ts                  # drift explain (AI-powered)
    │   └── fix.ts                      # drift fix (AI-powered)
    └── output/
        ├── index.ts                    # Output format registry
        ├── table.ts                    # Table output formatter
        ├── json.ts                     # JSON output formatter
        └── sarif.ts                    # SARIF output formatter
```

### 8.3 packages/drift-ci/ — CI Agent & GitHub Action (System 34, Phase 8)

**Source**: Orchestration §11.3, 34-CI-AGENT-GITHUB-ACTION-V2-PREP

```
packages/drift-ci/
├── package.json
├── tsconfig.json
├── action.yml                          # GitHub Action definition
└── src/
    ├── index.ts                        # CI agent entry point
    ├── agent.ts                        # 9 parallel analysis passes:
    │                                   #   scan, patterns, call graph, boundaries, security,
    │                                   #   tests, errors, contracts, constraints
    │                                   #   PR-level incremental analysis (changed files + transitive dependents)
    ├── pr_comment.ts                   # PR comment generation
    └── sarif_upload.ts                 # GitHub Code Scanning SARIF upload
```

### 8.4 packages/drift/ — Shared TS Orchestration Layer

**Source**: Orchestration §10.1, §10.2
**Purpose**: TypeScript orchestration for hybrid Rust/TS systems

```
packages/drift/
├── package.json
├── tsconfig.json
└── src/
    ├── index.ts                        # Package entry point
    │
    ├── simulation/                     # TS orchestration for Simulation Engine — §10.1
    │   ├── index.ts                    # Simulation module entry
    │   ├── orchestrator.ts             # Approach generation, composite scoring,
    │   │                               #   tradeoff generation, recommendation
    │   ├── approaches.ts               # Approach definitions for 13 task categories
    │   └── scoring.ts                  # Composite scoring logic
    │
    └── decisions/                      # TS orchestration for Decision Mining — §10.2
        ├── index.ts                    # Decisions module entry
        ├── adr_synthesis.ts            # ADR synthesis (AI-assisted)
        └── categories.ts              # 12 decision category definitions
```


---

## 9. Bridge Crate (Phase 9)

**Source**: Orchestration §12, 34-CORTEX-DRIFT-BRIDGE-V2-PREP
**Lives in**: `crates/cortex-drift-bridge/` (separate from drift workspace —
depends on both drift-core and cortex-core)
**Systems**: Cortex-Drift Bridge (System 34), Grounding Feedback Loop (D7)

```
crates/cortex-drift-bridge/
├── Cargo.toml                          # Dependencies: drift-core, cortex-core, rusqlite, thiserror
│                                       #   NOT a member of crates/drift/ workspace
│                                       #   (depends on both drift-core AND cortex-core)
└── src/
    ├── lib.rs                          # pub mod declarations + crate-level re-exports
    │
    ├── event_mapping/                  # Responsibility 1: Drift events → Cortex memories
    │   ├── mod.rs                      # pub mod: mapper, memory_types
    │   ├── mapper.rs                   # 21 event types → Cortex memory types:
    │   │                               #   on_pattern_approved → PatternRationale (0.8)
    │   │                               #   on_pattern_discovered → Insight (0.5)
    │   │                               #   on_pattern_ignored → Feedback (0.6)
    │   │                               #   on_pattern_merged → DecisionContext (0.7)
    │   │                               #   on_scan_complete → triggers grounding loop (no memory)
    │   │                               #   on_regression_detected → DecisionContext (0.9)
    │   │                               #   on_violation_detected → no memory (too noisy)
    │   │                               #   on_violation_dismissed → ConstraintOverride (0.7)
    │   │                               #   on_violation_fixed → Feedback (0.8)
    │   │                               #   on_gate_evaluated → DecisionContext (0.6)
    │   │                               #   on_detector_alert → Tribal (0.6)
    │   │                               #   on_detector_disabled → CodeSmell (0.9)
    │   │                               #   on_constraint_approved → ConstraintOverride (0.8)
    │   │                               #   on_constraint_violated → Feedback (0.7)
    │   │                               #   on_decision_mined → DecisionContext (0.7)
    │   │                               #   on_decision_reversed → DecisionContext (0.8)
    │   │                               #   on_adr_detected → DecisionContext (0.9)
    │   │                               #   on_boundary_discovered → Tribal (0.6)
    │   │                               #   on_enforcement_changed → DecisionContext (0.8)
    │   │                               #   on_feedback_abuse_detected → Tribal (0.7)
    │   │                               #   on_error → no memory (logged only)
    │   └── memory_types.rs             # Memory type + confidence mappings
    │
    ├── link_translation/               # Responsibility 2: PatternLink → EntityLink
    │   ├── mod.rs                      # pub mod: translator
    │   └── translator.rs               # 5 EntityLink constructors:
    │                                   #   from_pattern, from_constraint, from_detector,
    │                                   #   from_module, from_decision
    │
    ├── grounding/                      # Responsibilities 3-4: Grounding logic + feedback loop (D7)
    │   ├── mod.rs                      # pub mod: loop_runner, scorer, evidence,
    │   │                               #   scheduler, classification
    │   ├── loop_runner.rs              # Grounding loop orchestration
    │   │                               #   Max 500 memories per grounding loop
    │   │                               #   Thresholds: Validated ≥0.7, Partial ≥0.4,
    │   │                               #   Weak ≥0.2, Invalidated <0.2
    │   ├── scorer.rs                   # Grounding score computation
    │   │                               #   Confidence adjustment: boost_delta=0.05,
    │   │                               #   partial_penalty=0.05, weak_penalty=0.15,
    │   │                               #   invalidated_floor=0.1, contradiction_drop=0.3
    │   ├── evidence.rs                 # 10 evidence types with weights:
    │   │                               #   PatternConfidence, PatternOccurrence, FalsePositiveRate,
    │   │                               #   ConstraintVerification, CouplingMetric, DnaHealth,
    │   │                               #   TestCoverage, ErrorHandlingGaps, DecisionEvidence,
    │   │                               #   BoundaryData
    │   ├── scheduler.rs                # 6 trigger types:
    │   │                               #   Post-scan incremental (every scan, affected only),
    │   │                               #   Post-scan full (every 10th scan, all groundable),
    │   │                               #   Scheduled (daily, configurable),
    │   │                               #   On-demand MCP (user-triggered),
    │   │                               #   Memory creation (on creation),
    │   │                               #   Memory update (on update)
    │   └── classification.rs           # 13 groundable memory types (of 23 total):
    │                                   #   Fully groundable (6): PatternRationale,
    │                                   #     ConstraintOverride, DecisionContext, CodeSmell,
    │                                   #     Core, Semantic
    │                                   #   Partially groundable (7): Tribal, Decision,
    │                                   #     Insight, Entity, Feedback, Incident, Environment
    │                                   #   Not groundable (10): Procedural, Episodic, Reference,
    │                                   #     Preference, AgentSpawn, Goal, Workflow,
    │                                   #     Conversation, Meeting, Skill
    │
    ├── storage/                        # Bridge-specific SQLite tables
    │   ├── mod.rs                      # pub mod: tables
    │   └── tables.rs                   # 4 bridge-specific tables:
    │                                   #   bridge_grounding_results (90d Community, unlimited Enterprise)
    │                                   #   bridge_grounding_snapshots (365d retention)
    │                                   #   bridge_event_log (30d retention)
    │                                   #   bridge_metrics (7d rolling window)
    │
    ├── license/                        # License gating for bridge features
    │   ├── mod.rs                      # pub mod: gating
    │   └── gating.rs                   # 3-tier feature gating:
    │                                   #   Community: 5 event types, manual grounding only
    │                                   #   Team: all 21 event types, scheduled grounding, MCP tools
    │                                   #   Enterprise: full grounding loop, contradiction generation,
    │                                   #     cross-DB analytics
    │
    └── intents/                        # Responsibility 5: Code-specific intent extensions
        ├── mod.rs                      # pub mod: extensions
        └── extensions.rs               # 10 code-specific intent extensions registered as Cortex extensions:
                                        #   add_feature, fix_bug, refactor, review_code, debug,
                                        #   understand_code, security_audit, performance_audit,
                                        #   test_coverage, documentation
```

### Bridge Tests

```
crates/cortex-drift-bridge/
└── tests/
    ├── event_mapping_test.rs           # Event → memory type mapping tests (21 events)
    ├── grounding_test.rs               # Grounding loop + scorer + evidence tests
    └── link_translation_test.rs        # PatternLink → EntityLink translation tests
```

---

## 10. Cross-Reference Verification Matrix

This matrix verifies every system from the orchestration plan has a home directory,
every requirement from the scaffold prompt is met, and every dependency direction is honored.

### 10.1 System → Directory Mapping (All ~55 Systems)

| # | System | Phase | Directory |
|---|--------|-------|-----------|
| — | Configuration System | 0 | `drift-core/src/config/` |
| — | thiserror Error Enums | 0 | `drift-core/src/errors/` |
| — | tracing Instrumentation | 0 | `drift-core/src/tracing/` |
| — | DriftEventHandler Trait | 0 | `drift-core/src/events/` |
| — | String Interning (lasso) | 0 | `drift-core/src/types/` |
| 00 | Scanner | 1 | `drift-analysis/src/scanner/` |
| 01 | Tree-Sitter Parsers | 1 | `drift-analysis/src/parsers/` |
| 02 | SQLite Storage | 1 | `drift-storage/src/` |
| 03 | NAPI Bridge | 1 | `drift-napi/src/` |
| 05 | Call Graph Builder | 2 | `drift-analysis/src/call_graph/` |
| 06 | Unified Analysis Engine | 2 | `drift-analysis/src/engine/` |
| 06 | Detector System | 2 | `drift-analysis/src/detectors/` |
| 07 | Boundary Detection | 2 | `drift-analysis/src/boundaries/` |
| 08 | Unified Language Provider | 2 | `drift-analysis/src/language_provider/` |
| 09 | Quality Gates | 6 | `drift-analysis/src/enforcement/gates/` |
| 10 | Bayesian Confidence | 3 | `drift-analysis/src/patterns/confidence/` |
| 11 | Outlier Detection | 3 | `drift-analysis/src/patterns/outliers/` |
| 12 | Pattern Aggregation | 3 | `drift-analysis/src/patterns/aggregation/` |
| 13 | Learning System | 3 | `drift-analysis/src/patterns/learning/` |
| 14 | Reachability Analysis | 4 | `drift-analysis/src/graph/reachability/` |
| 15 | Taint Analysis | 4 | `drift-analysis/src/graph/taint/` |
| 16 | Error Handling Analysis | 4 | `drift-analysis/src/graph/error_handling/` |
| 17 | Impact Analysis | 4 | `drift-analysis/src/graph/impact/` |
| 18 | Test Topology | 4 | `drift-analysis/src/graph/test_topology/` |
| 19 | Coupling Analysis | 5 | `drift-analysis/src/structural/coupling/` |
| 20 | Constraint System | 5 | `drift-analysis/src/structural/constraints/` |
| 21 | Contract Tracking | 5 | `drift-analysis/src/structural/contracts/` |
| 22 | Constants & Environment | 5 | `drift-analysis/src/structural/constants/` |
| 23 | Wrapper Detection | 5 | `drift-analysis/src/structural/wrappers/` |
| 24 | DNA System | 5 | `drift-analysis/src/structural/dna/` |
| 25 | Audit System | 6 | `drift-analysis/src/enforcement/audit/` |
| 26 | OWASP/CWE Mapping | 5 | `drift-analysis/src/structural/owasp_cwe/` |
| 27 | Crypto Failure Detection | 5 | `drift-analysis/src/structural/crypto/` |
| 28 | Simulation Engine | 7 | `drift-analysis/src/advanced/simulation/` + `packages/drift/src/simulation/` |
| 29 | Decision Mining | 7 | `drift-analysis/src/advanced/decisions/` + `packages/drift/src/decisions/` |
| 30 | Context Generation | 7 | `drift-context/src/` + `drift-analysis/src/advanced/context/` |
| 31 | Violation Feedback Loop | 6 | `drift-analysis/src/enforcement/feedback/` |
| 32 | MCP Server | 8 | `packages/drift-mcp/` |
| 33 | Workspace Management | 10 | `drift-napi/src/bindings/workspace.rs` |
| 34 | CI Agent & GitHub Action | 8 | `packages/drift-ci/` |
| 34 | Cortex-Drift Bridge | 9 | `crates/cortex-drift-bridge/` |
| — | CLI | 8 | `packages/drift-cli/` |
| — | Rules Engine | 6 | `drift-analysis/src/enforcement/rules/` |
| — | Policy Engine | 6 | `drift-analysis/src/enforcement/policy/` |
| — | Reporters | 8 | `drift-analysis/src/enforcement/reporters/` |
| — | N+1 Query Detection | 7 | `drift-analysis/src/language_provider/n_plus_one.rs` |

### 10.1.1 Phase 10 Systems — Intentionally Excluded

The following 9 systems are Phase 10 (Polish & Ship) with no V2-PREP specs.
Per orchestration §2 and §17, none block the analysis pipeline. All are Level 5/6
presentation or cross-cutting concerns that consume the analysis stack.
They are excluded from this scaffold by design:

- VSCode Extension (Presentation, Phase 10)
- LSP Server (Presentation, Phase 10)
- Dashboard (Presentation, Phase 10)
- Galaxy (Presentation, Phase 10)
- AI Providers (Cross-Cutting, Phase 10)
- Docker Deployment (Cross-Cutting, Phase 10)
- Telemetry (Cross-Cutting, Phase 10)
- CIBench (Cross-Cutting, Phase 10)
- Licensing & Feature Gating (Cross-Cutting, Phase 10)

These will be scaffolded when their respective V2-PREP specs are written,
per the "When to Spec" timeline in orchestration §17.


### 10.2 Scaffold Prompt Requirements Checklist

| Requirement | Status | Evidence |
|-------------|--------|----------|
| R1: Single Responsibility Per File | ✅ | Every file contains one struct/trait/enum/concept. No god files. No utils.rs. |
| R2: Modular Subdirectories | ✅ | Every system has its own subdirectory. Every subdirectory has mod.rs. |
| R3: Predictable Naming | ✅ | All directories snake_case. All files snake_case.rs. No abbreviations except universally understood (config, db, ast, cwe, owasp). No numbered prefixes. |
| R4: Navigability | ✅ | Any system findable in <10s by scanning directory names. File names describe contents. |
| R5: Scalable | ✅ | New detector category = add subdirectory under detectors/. New language parser = add file under parsers/languages/. New quality gate = add file under enforcement/gates/. New reporter = add file under enforcement/reporters/. |
| R6: Clean Crate Boundaries | ✅ | Dependency directions verified: drift-core has zero internal deps. No circular dependencies. |
| R7: Production-Grade | ✅ | Every crate has tests/. Performance-critical crates have benches/. Cargo.toml dependencies specified. Workspace config files present. |

### 10.3 Quantitative Verification

| Check | Expected | Mapped |
|-------|----------|--------|
| Rust crates | 6 | 6 (drift-core, drift-analysis, drift-storage, drift-context, drift-napi, drift-bench) |
| Bridge crate | 1 | 1 (cortex-drift-bridge) |
| TypeScript packages | 4 | 4 (drift-mcp, drift-cli, drift-ci, drift) |
| Detector categories | 16 | 16 (api, auth, components, config, contracts, data_access, documentation, errors, logging, performance, security, structural, styling, testing, types, accessibility) |
| Language parsers | 10 | 10 (typescript, javascript, python, java, csharp, go, rust_lang, ruby, php, kotlin) |
| GAST normalizers | 10 | 10 (base, typescript, javascript, python, java, csharp, php, go, rust_lang, cpp) |
| Error enums | 12 | 12 (scan, parse, storage, detection, call_graph, pipeline, taint, constraint, boundary, gate, config, napi) |
| Event methods | 24 | 24 (4 Scan + 4 Patterns + 3 Violations + 3 Enforcement + 2 Constraints + 3 Decisions + 1 Boundaries + 2 Detector health + 1 Feedback + 1 Errors). Orchestration §3.5 prose says "21" but the actual enumeration yields 24 — our map includes every one. |
| Config sections | 8 | 8 (drift, scan, analysis, gate, mcp, backup, telemetry, license) |
| Quality gates | 6 | 6 (pattern_compliance, constraint_verification, security_boundaries, test_coverage, error_handling, regression_detection) |
| Reporter formats | 8 | 8 (sarif, github, gitlab, junit, html, json, console, sonarqube) |
| Taint sink types | 17+1 | 18 (17 named + Custom(u32)) |
| Crypto categories | 14 | 14 (WeakHash, DeprecatedCipher, HardcodedKey, EcbMode, StaticIv, InsufficientKeyLen, DisabledTls, InsecureRandom, JwtConfusion, PlaintextPassword, WeakKdf, MissingEncryption, CertPinningBypass, NonceReuse) |
| Contract paradigms | 7 | 7 (rest, graphql, grpc, asyncapi, trpc, websocket, event_driven) |
| DNA genes | 10 | 10 (6 frontend + 4 backend) |
| Outlier methods | 6 | 6 (z_score, grubbs, esd, iqr, mad, rule_based) |
| Constraint invariant types | 12 | 12 (must_exist, must_not_exist, must_precede, must_follow, must_colocate, must_separate, data_flow, naming_convention, dependency_direction, layer_boundary, size_limit, complexity_limit) |
| Bridge evidence types | 10 | 10 |
| Bridge grounding triggers | 6 | 6 |
| Bridge groundable memory types | 13 | 13 (6 fully + 7 partially) |
| Bridge storage tables | 4 | 4 |
| Bridge intent extensions | 10 | 10 |
| Wrapper categories | 16 | 16 |
| Migration files | 7 | 7 (v001–v007) |
| Storage query modules | 11 | 11 (files, parse_cache, functions, call_edges, patterns, detections, boundaries, graph, structural, enforcement, advanced) |
| CLI commands | 13 | 13 (scan, check, status, patterns, violations, impact, simulate, audit, setup, doctor, export, explain, fix) |
| MCP tools | 3 entry + ~49 dispatch | 4 files (drift_status, drift_context, drift_scan, drift_tool) |
| CI analysis passes | 9 | 9 (scan, patterns, call graph, boundaries, security, tests, errors, contracts, constraints) |

### 10.4 File Count Summary

| Location | Directories | Files | Total |
|----------|-------------|-------|-------|
| crates/drift/ (workspace root) | 1 | 6 | 7 |
| drift-core/ | 8 | 24 | 32 |
| drift-storage/ | 9 | 26 | 35 |
| drift-analysis/ | 72 | 168 | 240 |
| drift-context/ | 6 | 12 | 18 |
| drift-napi/ | 4 | 14 | 18 |
| drift-bench/ | 2 | 8 | 10 |
| packages/drift-mcp/ | 3 | 9 | 12 |
| packages/drift-cli/ | 3 | 18 | 21 |
| packages/drift-ci/ | 1 | 6 | 7 |
| packages/drift/ | 3 | 9 | 12 |
| cortex-drift-bridge/ | 8 | 19 | 27 |
| **TOTAL** | **~120** | **~319** | **~439** |

### 10.5 Scaffold Verification Checklist

```
## Scaffold Verification
- [ ] Every `pub mod` declaration has a corresponding file or directory with mod.rs
- [ ] Every system from the orchestration plan has a home directory (§10.1 verified)
- [ ] Every detector category (16) has a subdirectory under detectors/
- [ ] Every language parser (10) has a file under parsers/languages/
- [ ] Every GAST normalizer (10) has a file under engine/gast/normalizers/
- [ ] Every error enum from §3.3 (12) has a file under errors/
- [ ] Every event method from §3.5 (24) is declared in handler.rs
- [ ] Every config section from §3.2 (8) has a file under config/
- [ ] Every quality gate (6) has a file under enforcement/gates/
- [ ] Every reporter format (8) has a file under enforcement/reporters/
- [ ] Every taint sink type (17+1) is documented in graph/taint/sinks.rs
- [ ] Every crypto category (14) is documented in structural/crypto/categories.rs
- [ ] Every contract paradigm (7) has a file under structural/contracts/paradigms/
- [ ] Every DNA gene (10) has a file under structural/dna/genes/
- [ ] Every outlier method (6) has a file under patterns/outliers/
- [ ] Every constraint invariant type (12) is documented in structural/constraints/invariant_types.rs
- [ ] drift-core has zero dependencies on other drift crates
- [ ] drift-analysis depends only on drift-core
- [ ] drift-storage depends only on drift-core
- [ ] drift-context depends only on drift-core
- [ ] drift-napi depends on drift-analysis, drift-storage, drift-context, drift-core
- [ ] drift-bench depends on drift-analysis, drift-storage, drift-core
- [ ] cortex-drift-bridge depends on drift-core and cortex-core (NOT a workspace member)
- [ ] TypeScript packages/ structure matches §11 presentation systems
- [ ] Bridge crate structure matches §12 bridge system
- [ ] No file contains more than one primary public type (R1 enforced)
- [ ] No directory is missing a mod.rs (R2 enforced)
- [ ] All file names are snake_case (R3 enforced)
- [ ] All workspace config files present (Cargo.toml, .cargo/config.toml, rustfmt.toml, clippy.toml, deny.toml)
- [ ] Migration files cover all 7 phases of schema progression (§18.2)
- [ ] NAPI binding modules cover all phase progressions (§18.3)
```

---

## Appendix A: Build Order for Scaffold Agent

The scaffold agent should create files in this exact order to ensure every `pub mod`
declaration has a corresponding file before the next crate begins:

1. **Workspace root**: `crates/drift/Cargo.toml`, `.cargo/config.toml`, `rustfmt.toml`, `clippy.toml`, `deny.toml`, `rust-toolchain.toml`
2. **drift-core**: All files (§2) — this is the leaf dependency, must exist first
3. **drift-storage**: All files (§3) — depends only on drift-core
4. **drift-analysis**: All files (§4) — depends only on drift-core, largest crate
5. **drift-context**: All files (§5) — depends only on drift-core
6. **drift-napi**: All files (§6) — depends on drift-analysis, drift-storage, drift-context, drift-core
7. **drift-bench**: All files (§7) — depends on drift-analysis, drift-storage, drift-core
8. **TypeScript packages**: All files (§8) — no Rust dependency ordering
9. **cortex-drift-bridge**: All files (§9) — separate from workspace, depends on drift-core + cortex-core

This order mirrors the orchestration plan's Phase 0 → Phase 9 progression and ensures
upstream crates exist before downstream crates reference them.

---

*End of scaffold directory map. Every file accounted for. Every system housed.
Every dependency direction honored. Build it in order.*
