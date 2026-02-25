# Scaffold Full Directory Structure — Agent Prompt

> Copy everything below the line into a fresh agent context window.
> Provide the orchestration plan as context reference.

---

## YOUR TASK

You are a principal engineer scaffolding the complete file and directory structure for the Drift V2 Rust/TypeScript codebase. You will read the implementation orchestration plan, then produce every directory, every file, every `mod.rs` — the full tree that a team builds into.

You are not writing implementation code. You are creating the skeleton: empty files with module declarations, `mod.rs` files with `pub mod` statements, `Cargo.toml` files with correct dependencies, and `lib.rs` files with correct re-exports. Every file you create must compile (even if the structs/functions inside are just `todo!()`). The structure itself is the deliverable.

## INPUT FILE

Read this file fully before creating anything:

**The orchestration plan (your single source of truth):**
#File docs/v2-research/DRIFT-V2-IMPLEMENTATION-ORCHESTRATION.md

This document contains everything you need: all ~55 systems, all 11 phases, all 6 crates, all subsystem locations, all dependency relationships, all trait names, all error enum names, all event method names, and all storage table names.

Do NOT audit, question, or revise any architectural decision. The orchestration plan has been validated by 16 research sections and 4 audit passes. Your job is structural execution.

## STRICT STRUCTURAL REQUIREMENTS

These are non-negotiable. Every directory and file must satisfy ALL of these:

### R1: Single Responsibility Per File
One struct, one trait, one enum, or one tightly-coupled pair per file. No god files. No "utils.rs" dumping grounds. If a file would contain two unrelated types, split it.

Exceptions:
- `mod.rs` files contain only `pub mod` declarations and re-exports
- `lib.rs` files contain only `pub mod` declarations, re-exports, and crate-level doc comments
- Test files can test multiple related items from the same module

### R2: Modular Subdirectories With Explicit Boundaries
Every system gets its own subdirectory. Every subsystem within a system gets its own subdirectory or file depending on complexity. The directory name IS the module name. No ambiguity.

Pattern:
```
system_name/
├── mod.rs              (pub mod declarations + re-exports only)
├── types.rs            (public types for this system)
├── traits.rs           (public traits for this system, if any)
├── errors.rs           (system-specific error enum, if not in drift-core)
├── subsystem_a/
│   ├── mod.rs
│   ├── ...
└── subsystem_b/
    ├── mod.rs
    └── ...
```

### R3: Predictable Naming Conventions
- Directories: `snake_case`, matching the Rust module name exactly
- Files: `snake_case.rs`, matching the primary type or concept inside
- No abbreviations unless universally understood (`config`, `db`, `ast`, `cwe`, `owasp`)
- No numbered prefixes on directories (use alphabetical or dependency order)
- Test files: `{module}_test.rs` in a sibling `tests/` directory, or `#[cfg(test)] mod tests` inline for unit tests

### R4: Navigability — Any Skill Level
A junior developer opening this repo for the first time must be able to:
1. Find any system in <10 seconds by scanning directory names
2. Understand what a file contains from its name alone
3. Know where to add new code without asking anyone
4. Trace a dependency by following `mod.rs` → `pub mod` → file

### R5: Scalable — No Refactoring to Add Systems
The structure must accommodate:
- Adding a new detector category (just add a subdirectory under `detectors/`)
- Adding a new language parser (just add a file under `parsers/languages/`)
- Adding a new quality gate (just add a file under `enforcement/gates/`)
- Adding a new NAPI module (just add a file under `bindings/`)
- Adding a new reporter format (just add a file under `enforcement/reporters/`)

No existing file needs modification to add a new instance of any extensible system.

### R6: Clean Crate Boundaries
The 6 crates have strict dependency directions:
```
drift-napi → drift-analysis → drift-core
drift-napi → drift-storage  → drift-core
drift-napi → drift-context  → drift-core
drift-bench → drift-analysis, drift-storage, drift-core
```
No circular dependencies. No crate reaches into another crate's internals. Public APIs only at crate boundaries.

### R7: Production-Grade From Day One
- Every crate has a `tests/` directory with at least a placeholder integration test file per system
- Every crate has a `benches/` directory if performance-critical (drift-analysis, drift-storage)
- `Cargo.toml` files have correct `[dependencies]`, `[dev-dependencies]`, and `[features]`
- `.cargo/config.toml` at workspace root for shared build settings
- `rustfmt.toml` and `clippy.toml` at workspace root

## HOW TO EXECUTE

### Step 1: Create the workspace root
```
crates/drift/
├── Cargo.toml                 (workspace manifest — copy from orchestration §3.1)
├── .cargo/config.toml
├── rustfmt.toml
├── clippy.toml
├── drift-core/
├── drift-analysis/
├── drift-storage/
├── drift-context/
├── drift-napi/
└── drift-bench/
```

### Step 2: Scaffold drift-core (Phase 0 infrastructure)
This crate contains: config, errors, tracing, events, types, traits, constants.
Every other crate depends on this. Read orchestration §3.2–§3.6 for the full list of types.

Expected structure:
```
drift-core/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── config/
│   │   ├── mod.rs
│   │   ├── drift_config.rs       (DriftConfig, 4-layer resolution)
│   │   ├── scan_config.rs        (ScanConfig)
│   │   ├── analysis_config.rs    (AnalysisConfig)
│   │   ├── gate_config.rs        (GateConfig)
│   │   ├── mcp_config.rs         (McpConfig)
│   │   ├── backup_config.rs      (BackupConfig)
│   │   ├── telemetry_config.rs   (TelemetryConfig)
│   │   └── license_config.rs     (LicenseConfig)
│   ├── errors/
│   │   ├── mod.rs
│   │   ├── error_code.rs         (DriftErrorCode trait)
│   │   ├── scan_error.rs         (ScanError enum)
│   │   ├── parse_error.rs        (ParseError enum)
│   │   ├── storage_error.rs      (StorageError enum)
│   │   ├── detection_error.rs    (DetectionError enum)
│   │   ├── call_graph_error.rs   (CallGraphError enum)
│   │   ├── pipeline_error.rs     (PipelineError enum + PipelineResult)
│   │   ├── taint_error.rs        (TaintError enum)
│   │   ├── constraint_error.rs   (ConstraintError enum)
│   │   ├── boundary_error.rs     (BoundaryError enum)
│   │   ├── gate_error.rs         (GateError enum)
│   │   ├── config_error.rs       (ConfigError enum)
│   │   └── napi_error.rs         (NapiError enum + 14 NAPI error codes)
│   ├── events/
│   │   ├── mod.rs
│   │   ├── handler.rs            (DriftEventHandler trait — 21 methods)
│   │   ├── dispatcher.rs         (EventDispatcher — Vec<Arc<dyn DriftEventHandler>>)
│   │   └── types.rs              (event payload types)
│   ├── tracing/
│   │   ├── mod.rs
│   │   ├── setup.rs              (init_tracing, EnvFilter setup)
│   │   └── metrics.rs            (12+ structured span field definitions)
│   ├── types/
│   │   ├── mod.rs
│   │   ├── interning.rs          (PathInterner, FunctionInterner, ThreadedRodeo wrappers)
│   │   ├── collections.rs        (FxHashMap, FxHashSet, SmallVec re-exports + type aliases)
│   │   └── identifiers.rs        (Spur-based ID types: FileId, FunctionId, PatternId, etc.)
│   └── traits/
│       ├── mod.rs
│       └── ... (shared traits used across crates)
└── tests/
    ├── config_test.rs
    ├── errors_test.rs
    ├── events_test.rs
    └── types_test.rs
```

### Step 3: Scaffold drift-analysis (Phases 1-7 analysis systems)
This is the largest crate. It contains: scanner, parsers, engine, detectors, call graph, boundaries, language provider, patterns, graph analysis, structural analysis, enforcement, and advanced systems.

Read orchestration §4–§10 for every system. Each system's "Lives in" field tells you the subdirectory.

Expected top-level structure:
```
drift-analysis/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── scanner/           (System 00 — §4.1)
│   ├── parsers/           (System 01 — §4.2)
│   ├── engine/            (System 06 — §5.2, Unified Analysis Engine)
│   ├── detectors/         (System 06 — §5.3, 16 categories)
│   ├── call_graph/        (System 05 — §5.4)
│   ├── boundaries/        (System 07 — §5.5)
│   ├── language_provider/ (System 08 — §5.6)
│   ├── patterns/          (Phase 3 — §6, aggregation + confidence + outliers + learning)
│   ├── graph/             (Phase 4 — §7, reachability + taint + error_handling + impact + test_topology)
│   ├── structural/        (Phase 5 — §8, coupling + constraints + contracts + constants + wrappers + dna + owasp_cwe + crypto)
│   ├── enforcement/       (Phase 6 — §9, rules + gates + policy + audit + feedback + reporters)
│   └── advanced/          (Phase 7 — §10, simulation + decisions + context + n_plus_one)
├── tests/
│   ├── scanner_test.rs
│   ├── parsers_test.rs
│   ├── engine_test.rs
│   ├── ... (one per system)
└── benches/
    ├── scanner_bench.rs
    ├── parser_bench.rs
    └── ... (performance-critical systems)
```

Each subdirectory must be fully expanded. For example, `parsers/` must contain:
```
parsers/
├── mod.rs
├── types.rs              (ParseResult, canonical fields from §4.2)
├── traits.rs             (LanguageParser trait)
├── manager.rs            (ParserManager dispatcher)
├── cache.rs              (Moka LRU + SQLite parse cache)
├── macros.rs             (define_parser! macro)
└── languages/
    ├── mod.rs
    ├── typescript.rs
    ├── javascript.rs
    ├── python.rs
    ├── java.rs
    ├── csharp.rs
    ├── go.rs
    ├── rust.rs
    ├── ruby.rs
    ├── php.rs
    └── kotlin.rs
```

And `detectors/` must contain one subdirectory per category:
```
detectors/
├── mod.rs
├── traits.rs             (Detector trait, DetectionContext)
├── registry.rs           (DetectorRegistry)
├── api/
│   └── mod.rs
├── auth/
│   └── mod.rs
├── components/
│   └── mod.rs
├── config/
│   └── mod.rs
├── contracts/
│   └── mod.rs
├── data_access/
│   └── mod.rs
├── documentation/
│   └── mod.rs
├── errors/
│   └── mod.rs
├── logging/
│   └── mod.rs
├── performance/
│   └── mod.rs
├── security/
│   └── mod.rs
├── structural/
│   └── mod.rs
├── styling/
│   └── mod.rs
├── testing/
│   └── mod.rs
├── types/
│   └── mod.rs
└── accessibility/
    └── mod.rs
```

### Step 4: Scaffold drift-storage (Phase 1 persistence)
Read orchestration §4.3 for the full storage architecture.

```
drift-storage/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── connection/
│   │   ├── mod.rs
│   │   ├── pool.rs           (ReadPool, round-robin AtomicUsize)
│   │   ├── writer.rs         (Mutex<Connection> write serialization)
│   │   └── pragmas.rs        (WAL, synchronous, page_cache, mmap settings)
│   ├── batch/
│   │   ├── mod.rs
│   │   ├── writer.rs         (crossbeam-channel bounded(1024), dedicated thread)
│   │   └── commands.rs       (BatchCommand enum)
│   ├── migrations/
│   │   ├── mod.rs
│   │   └── ... (one file per migration version)
│   ├── queries/
│   │   ├── mod.rs
│   │   ├── files.rs          (file_metadata queries)
│   │   ├── parse_cache.rs    (parse_cache queries)
│   │   ├── functions.rs      (functions table queries)
│   │   ├── call_edges.rs     (call_edges table queries)
│   │   ├── patterns.rs       (patterns + confidence queries)
│   │   ├── detections.rs     (detections table queries)
│   │   ├── boundaries.rs     (boundaries table queries)
│   │   ├── graph.rs          (reachability, taint, impact, test queries)
│   │   ├── structural.rs     (coupling, constraints, contracts, constants, wrappers, dna, owasp, crypto queries)
│   │   ├── enforcement.rs    (violations, gates, audit, feedback queries)
│   │   └── advanced.rs       (simulations, decisions, context queries)
│   ├── pagination/
│   │   ├── mod.rs
│   │   └── keyset.rs         (keyset cursor pagination)
│   └── materialized/
│       ├── mod.rs
│       ├── status.rs         (materialized_status view)
│       ├── security.rs       (materialized_security view)
│       └── trends.rs         (health_trends view)
├── tests/
│   ├── connection_test.rs
│   ├── batch_test.rs
│   ├── migration_test.rs
│   └── queries_test.rs
└── benches/
    ├── batch_bench.rs
    └── query_bench.rs
```

### Step 5: Scaffold drift-context (Phase 7 context generation)
Read orchestration §10.3 for the context generation system.

```
drift-context/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── generation/
│   │   ├── mod.rs
│   │   ├── builder.rs        (context builder, 3 depth levels)
│   │   ├── intent.rs         (intent-weighted selection)
│   │   └── deduplication.rs  (session-aware dedup)
│   ├── tokenization/
│   │   ├── mod.rs
│   │   ├── budget.rs         (token budgeting, model-aware limits)
│   │   └── counter.rs        (tiktoken-rs wrapper)
│   ├── formats/
│   │   ├── mod.rs
│   │   ├── xml.rs            (quick-xml output)
│   │   ├── yaml.rs           (serde_yaml output)
│   │   └── markdown.rs       (markdown output)
│   └── packages/
│       ├── mod.rs
│       └── manager.rs        (15 package manager support)
├── tests/
│   └── context_test.rs
```

### Step 6: Scaffold drift-napi (Phase 1+ NAPI bridge)
Read orchestration §4.4 and §18.3 for the NAPI function progression.

```
drift-napi/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── runtime.rs            (DriftRuntime singleton via OnceLock)
│   ├── conversions/
│   │   ├── mod.rs
│   │   ├── error_codes.rs    (DriftErrorCode → NAPI error conversion)
│   │   └── types.rs          (Rust ↔ JS type conversions)
│   └── bindings/
│       ├── mod.rs
│       ├── lifecycle.rs      (drift_initialize, drift_shutdown)
│       ├── scanner.rs        (drift_scan)
│       ├── analysis.rs       (drift_analyze, drift_call_graph, drift_boundaries)
│       ├── patterns.rs       (drift_patterns, drift_confidence, drift_outliers, drift_conventions)
│       ├── graph.rs          (reachability, taint, error_handling, impact, test queries)
│       ├── structural.rs     (coupling, constraints, contracts, constants, wrappers, dna, owasp, crypto queries)
│       ├── enforcement.rs    (drift_check, drift_audit, drift_violations, drift_gates)
│       ├── advanced.rs       (drift_simulate, drift_decisions, drift_context)
│       ├── workspace.rs      (workspace management — 16 functions)
│       └── feedback.rs       (violation feedback functions)
├── build.rs                  (napi-build)
└── tests/
    └── napi_test.rs
```

### Step 7: Scaffold drift-bench (benchmarks)
```
drift-bench/
├── Cargo.toml
├── benches/
│   ├── scanner_bench.rs
│   ├── parser_bench.rs
│   ├── call_graph_bench.rs
│   ├── confidence_bench.rs
│   ├── storage_bench.rs
│   └── end_to_end_bench.rs
└── src/
    ├── lib.rs
    └── fixtures.rs           (shared test fixtures and generators)
```

### Step 8: Scaffold TypeScript packages (Phases 7-8 presentation)
Read orchestration §10.1, §10.2, §11.1–§11.3 for the TS-side systems.

```
packages/
├── drift-mcp/               (MCP Server — §11.1)
│   ├── package.json
│   ├── tsconfig.json
│   └── src/
│       ├── index.ts
│       ├── server.ts         (MCP server setup, stdio + HTTP transport)
│       ├── tools/
│       │   ├── index.ts
│       │   ├── drift_status.ts
│       │   ├── drift_context.ts
│       │   ├── drift_scan.ts
│       │   └── drift_tool.ts (dynamic dispatch for ~49 internal tools)
│       └── transport/
│           ├── index.ts
│           ├── stdio.ts
│           └── http.ts
├── drift-cli/                (CLI — §11.2)
│   ├── package.json
│   ├── tsconfig.json
│   └── src/
│       ├── index.ts
│       ├── commands/
│       │   ├── index.ts
│       │   ├── scan.ts
│       │   ├── check.ts
│       │   ├── status.ts
│       │   ├── patterns.ts
│       │   ├── violations.ts
│       │   ├── impact.ts
│       │   ├── simulate.ts
│       │   ├── audit.ts
│       │   ├── setup.ts
│       │   ├── doctor.ts
│       │   ├── export.ts
│       │   ├── explain.ts
│       │   └── fix.ts
│       └── output/
│           ├── index.ts
│           ├── table.ts
│           ├── json.ts
│           └── sarif.ts
├── drift-ci/                 (CI Agent — §11.3)
│   ├── package.json
│   ├── tsconfig.json
│   ├── action.yml            (GitHub Action definition)
│   └── src/
│       ├── index.ts
│       ├── agent.ts          (9 parallel analysis passes)
│       ├── pr_comment.ts     (PR comment generation)
│       └── sarif_upload.ts   (GitHub Code Scanning upload)
└── drift/                    (shared TS orchestration layer)
    ├── package.json
    ├── tsconfig.json
    └── src/
        ├── index.ts
        ├── simulation/       (TS orchestration for Simulation Engine — §10.1)
        │   ├── index.ts
        │   ├── orchestrator.ts
        │   ├── approaches.ts
        │   └── scoring.ts
        └── decisions/        (TS orchestration for Decision Mining — §10.2)
            ├── index.ts
            ├── adr_synthesis.ts
            └── categories.ts
```

### Step 9: Scaffold the bridge crate (Phase 9)
Read orchestration §12 for the bridge system. This is a separate crate outside the drift workspace because it depends on both drift-core and cortex-core.

```
crates/cortex-drift-bridge/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── event_mapping/
│   │   ├── mod.rs
│   │   ├── mapper.rs         (21 event types → Cortex memory types)
│   │   └── memory_types.rs   (memory type + confidence mappings)
│   ├── link_translation/
│   │   ├── mod.rs
│   │   └── translator.rs     (PatternLink → EntityLink, 5 constructors)
│   ├── grounding/
│   │   ├── mod.rs
│   │   ├── loop_runner.rs    (grounding loop orchestration)
│   │   ├── scorer.rs         (grounding score computation)
│   │   ├── evidence.rs       (10 evidence types with weights)
│   │   ├── scheduler.rs      (6 trigger types, max 500 memories)
│   │   └── classification.rs (13 groundable memory types)
│   ├── storage/
│   │   ├── mod.rs
│   │   └── tables.rs         (4 bridge-specific SQLite tables)
│   ├── license/
│   │   ├── mod.rs
│   │   └── gating.rs         (3-tier feature gating)
│   └── intents/
│       ├── mod.rs
│       └── extensions.rs     (10 code-specific intent extensions)
├── tests/
│   ├── event_mapping_test.rs
│   ├── grounding_test.rs
│   └── link_translation_test.rs
```

### Step 10: Create workspace-level config files

Create these at the workspace root (`crates/drift/`):
- `rustfmt.toml` — standard formatting (max_width = 100, edition = "2021")
- `clippy.toml` — strict linting
- `.cargo/config.toml` — shared build settings, target-specific flags
- `deny.toml` — cargo-deny config for license and advisory auditing

## RULES

1. **Create every file.** Every `.rs` file must exist, even if the body is just `//! Module description` + `todo!()` stubs. Every `mod.rs` must have correct `pub mod` declarations. Every `Cargo.toml` must have correct dependencies.

2. **No empty directories.** Every directory must contain at least a `mod.rs`.

3. **Follow the orchestration plan exactly.** If the plan says "Lives in: `drift-analysis/src/scanner/`", that's where it goes. If the plan lists 16 detector categories, create 16 subdirectories. If the plan lists 10 language parsers, create 10 files.

4. **Compile-ready stubs.** Every file should contain the minimum to compile:
   - Structs: `pub struct TypeName;` or `pub struct TypeName { /* TODO */ }`
   - Traits: `pub trait TraitName { /* TODO */ }`
   - Enums: `pub enum EnumName { /* TODO */ }`
   - Functions: `pub fn function_name() { todo!() }`
   - Use `#[allow(dead_code)]` and `#[allow(unused)]` at the crate level during scaffolding

5. **Module doc comments.** Every `mod.rs` and every `lib.rs` must have a `//!` doc comment explaining what this module contains and which orchestration plan section it implements.

6. **No implementation logic.** Zero algorithms, zero business logic, zero SQL queries. Only type definitions, trait signatures, function signatures, and `todo!()` bodies. The structure is the deliverable.

7. **Work crate by crate.** Complete one crate fully before moving to the next. Order: drift-core → drift-storage → drift-analysis → drift-context → drift-napi → drift-bench → packages/ → cortex-drift-bridge.

8. **Verify as you go.** After completing each crate, confirm `mod.rs` declarations match the files that exist. Every `pub mod foo;` must have a corresponding `foo.rs` or `foo/mod.rs`.

## OUTPUT

Your output is the complete file tree created in the workspace. No summary document. No changelog. Just the files.

After all files are created, produce a single verification block:

```
## Scaffold Verification
- [ ] `cargo build --workspace` succeeds (with todo!() stubs and #[allow(unused)])
- [ ] Every `pub mod` declaration has a corresponding file
- [ ] Every system from the orchestration plan has a home directory
- [ ] Every detector category (16) has a subdirectory
- [ ] Every language parser (10) has a file
- [ ] Every error enum from §3.3 has a file
- [ ] Every event method from §3.5 is declared in handler.rs
- [ ] Every config section from §3.2 has a file
- [ ] drift-core has zero dependencies on other drift crates
- [ ] drift-analysis depends only on drift-core
- [ ] drift-storage depends only on drift-core
- [ ] drift-context depends only on drift-core
- [ ] drift-napi depends on drift-analysis, drift-storage, drift-context, drift-core
- [ ] drift-bench depends on drift-analysis, drift-storage, drift-core
- [ ] TypeScript packages/ structure matches §11 presentation systems
- [ ] Bridge crate structure matches §12 bridge system
- [ ] No file contains more than one primary public type (R1 enforced)
- [ ] No directory is missing a mod.rs (R2 enforced)
- [ ] All file names are snake_case (R3 enforced)
```

If any check fails, fix it before finishing.
