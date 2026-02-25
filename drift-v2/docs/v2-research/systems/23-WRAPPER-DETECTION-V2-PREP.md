# Wrapper Detection (Primitives, Clustering, Cross-File Usage, Framework Expansion) — V2 Implementation Prep

> Comprehensive build specification for Drift v2's Wrapper Detection subsystem (System 23).
> Synthesized from: 01-rust-core/wrappers.md (Rust WrapperDetector, 6 primitive categories,
> ~20 primitives, confidence scoring formula, WrapperInfo/WrapperCluster/WrappersResult types,
> call extraction strategy, name-based category fallback, WrapperCategory 12-variant enum),
> 05-analyzers/wrappers-analysis.md (TS orchestration layer, 8 source files across 5
> subdirectories, detection/clustering/primitives/export/integration, cross-file usage
> counting, expanded per-framework registries, pattern store persistence),
> .research/05-analyzers/RECAP.md (Algorithm #8 — wrapper detection flow, confidence formula,
> known primitives registry, ~700 LOC Rust core + ~600 LOC TS orchestration),
> .research/05-analyzers/AUDIT.md (wrappers-analysis.md ✅, wrappers.md ✅, confidence
> formula reproduced, all types documented),
> .research/01-rust-core/RECAP.md (§12 Wrappers Analyzer — detection, clustering,
> NAPI: analyze_wrappers(files), undocumented clustering algorithm),
> .research/MASTER-AUDIT.md (Layer 3 Intelligence — Wrappers, RC-G12 wrapper registry
> React-focused only, AN-G7 wrapper detection React-focused only),
> DRIFT-V2-FULL-SYSTEM-AUDIT.md (Cat 05 — Wrappers Rust: thin delegation patterns,
> wrapper clustering, analyze_wrappers NAPI endpoint, supplemental A26 wrapper registry
> expansion question, 8 pending architectural decisions including wrapper registry),
> DRIFT-V2-STACK-HIERARCHY.md (Level 2C — Structural Intelligence, "Wrapper Detection:
> Thin delegation patterns, clustering. Lowest-impact analysis. Feeds call graph accuracy."),
> DRIFT-V2-SYSTEMS-REFERENCE.md (Rust ~65 files includes wrappers, wiki Wrappers Detection
> page, MCP tool count includes wrapper tools),
> 03-NAPI-BRIDGE-V2-PREP.md (§9 batch API AnalysisType::Wrappers, §10.10 analyze_wrappers
> Async → WrappersSummary, §15 bindings/structural.rs, §12 conversion modules,
> NativeBindings.analyzeWrappers, DriftClient typed wrapper),
> 02-STORAGE-V2-PREP.md (drift.db schema: wrappers + wrapper_clusters tables),
> 08-storage/sqlite-schema.md (wrappers, wrapper_clusters — 2 tables),
> 06-UNIFIED-ANALYSIS-ENGINE-V2-PREP.md (ParseResult contract, call extraction,
> function line ranges, Domain Wrappers preserved from v1),
> 05-CALL-GRAPH-V2-PREP.md (petgraph StableGraph, CallGraphDb, callers/callees queries),
> 04-INFRASTRUCTURE-V2-PREP.md (thiserror, tracing, FxHashMap, rayon, regex),
> 07-mcp/tools-by-category.md (drift_wrappers — analysis category, ~500-1500 tokens),
> 07-mcp/tools-inventory.md (wrappers.ts — Wrapper detection tool),
> 10-cli/commands.md (drift wrappers: --json, -v/--verbose flags),
> 22-DNA-SYSTEM-V2-PREP.md (DNA gene extractors consume wrapper data for convention analysis),
> 19-COUPLING-ANALYSIS-V2-PREP.md (downstream consumer pattern reference),
> 20-CONSTRAINT-SYSTEM-V2-PREP.md (constraint mining from wrapper patterns),
> PLANNING-DRIFT.md (D1 standalone, D5 event system, D7 Cortex grounding),
> React Hooks documentation (useState, useReducer, useEffect, useLayoutEffect, useMemo,
> useCallback, useRef, useContext, useId, useDeferredValue, useTransition, useSyncExternalStore),
> Vue 3 Composition API (ref, reactive, computed, watch, watchEffect, onMounted, provide/inject,
> useSlots, useAttrs, defineProps, defineEmits, toRef, toRefs, shallowRef, triggerRef),
> Angular injectable services (HttpClient, FormBuilder, ActivatedRoute, Router, Renderer2,
> ChangeDetectorRef, NgZone, Injector, ElementRef, ViewContainerRef, TemplateRef),
> Svelte stores (writable, readable, derived, get, $store syntax),
> SolidJS primitives (createSignal, createEffect, createMemo, createResource, createStore),
> Express middleware patterns (app.use, router.use, express.Router, middleware chaining),
> Next.js patterns (useRouter, useSearchParams, usePathname, getServerSideProps, getStaticProps),
> Zustand/Jotai/Recoil state management primitives,
> TanStack Query (useQuery, useMutation, useInfiniteQuery, useQueryClient),
> tRPC client hooks (trpc.useQuery, trpc.useMutation),
> Prisma client patterns (prisma.model.findMany, prisma.model.create),
> Drizzle ORM patterns (db.select, db.insert, db.update, db.delete),
> arxiv.org/html/2509.22530v1 (hybrid value-flow + LLM wrapper detection for allocation
> functions — applicable heuristic: "straightforward wrappers" via value-flow analysis),
> Rust regex crate RegexSet (single-pass multi-pattern matching for primitive detection),
> Rust sha2 crate (SHA-256 for deterministic wrapper IDs).
>
> Purpose: Everything needed to build the Wrapper Detection subsystem from scratch in Rust.
> Every v1 feature accounted for. Zero feature loss. Every algorithm specified.
> Every type defined. Every integration point documented. Every architectural decision
> resolved. The wrapper detection system is the lowest-impact Level 2C analysis — but
> it feeds call graph accuracy, DNA convention analysis, and provides critical insight
> into how teams abstract framework primitives. V2 expands the React-only primitive
> registry to 8 frameworks, adds cross-file usage counting via call graph integration,
> moves clustering entirely to Rust, adds wrapper documentation export, and introduces
> wrapper health scoring for quality gate integration.
> Generated: 2026-02-08

---

## Table of Contents

1. Architectural Position
2. V1 Complete Feature Inventory
3. V2 Architecture — Unified Wrapper Engine
4. Core Data Model (Rust Types)
5. Phase 1: Primitive Registry (8 Frameworks, 150+ Primitives)
6. Phase 2: Per-File Wrapper Detection (Call-Site Analysis)
7. Phase 3: Confidence Scoring (Enhanced 7-Signal Model)
8. Phase 4: Category Classification (Name + Import + Call-Site Hybrid)
9. Phase 5: Cross-File Usage Counting (Call Graph Integration)
10. Phase 6: Wrapper Clustering (Category + Primitive + Similarity)
11. Phase 7: Wrapper Documentation Export (Markdown + JSON)
12. Phase 8: Wrapper Health Scoring
13. Phase 9: Incremental Wrapper Analysis (Content-Hash Aware)
14. RegexSet Optimization — Single-Pass Primitive Matching
15. Integration with Unified Analysis Engine
16. Integration with Call Graph Builder
17. Integration with DNA System
18. Integration with Quality Gates
19. Integration with Constraint System
20. Integration with Context Generation
21. Integration with Cortex Grounding (D7)
22. Storage Schema (drift.db Wrapper Tables)
23. NAPI Interface
24. MCP Tool Interface (drift_wrappers — 4 Actions)
25. CLI Interface (drift wrappers — 4 Subcommands)
26. Event Interface
27. Tracing & Observability
28. Performance Targets & Benchmarks
29. Build Order & Dependencies
30. V1 → V2 Feature Cross-Reference
31. Inconsistencies & Decisions
32. Risk Register

---

## 1. Architectural Position

Wrapper Detection is **Level 2C — Structural Intelligence** in the Drift v2 stack
hierarchy. It is the lowest-impact analysis at this level, but it provides unique
insight that no other subsystem captures: how teams abstract framework primitives
into project-specific APIs.

Per DRIFT-V2-STACK-HIERARCHY.md:

> Wrapper Detection: Thin delegation patterns, clustering. Lowest-impact analysis.
> Feeds call graph accuracy.

Per DRIFT-V2-FULL-SYSTEM-AUDIT.md Category 05:

> Wrappers (Rust) — Wrapper function detection (thin delegation patterns).
> Wrapper clustering (related wrappers grouped).
> Action: Identifies functions that just delegate to another function.

Per .research/MASTER-AUDIT.md:

> Layer 3 (Intelligence): Patterns (aggregated), Cortex, Constraints, Wrappers, Coupling

### Core Thesis

A "wrapper" is a function whose primary purpose is to delegate to a known framework
primitive while adding project-specific concerns (naming, defaults, error handling,
logging, type narrowing). Wrappers are the team's abstraction layer over external APIs.

Detecting wrappers matters because:
1. **Call graph accuracy** — Wrappers create indirection. Knowing `useAuth()` wraps
   `useState()` + `useEffect()` lets the call graph resolve through the abstraction.
2. **Convention analysis** — Wrapper patterns reveal team conventions (e.g., "we always
   wrap fetch with error handling" → convention gene for DNA system).
3. **Refactoring safety** — When a framework primitive changes (React 18→19, Vue 2→3),
   knowing which wrappers depend on it quantifies migration scope.
4. **Code review intelligence** — "This function wraps useState but doesn't follow the
   team's established useAuth/useForm pattern" → actionable review feedback.
5. **Documentation generation** — Auto-generated wrapper docs show teams their own
   abstraction layer, which is often undocumented.

### What Lives Here

- Primitive registry (8 frameworks, 150+ primitives, extensible via TOML config)
- Per-file wrapper detection (call-site analysis against primitive registry)
- Confidence scoring (7-signal enhanced model, 0.0–1.0)
- Category classification (12 categories + name/import/call-site hybrid)
- Cross-file usage counting (call graph integration)
- Wrapper clustering (category + primitive + similarity grouping)
- Wrapper documentation export (Markdown + JSON)
- Wrapper health scoring (consistency, coverage, abstraction depth)
- Incremental analysis (content-hash aware, skip unchanged files)
- RegexSet optimization (single-pass multi-pattern primitive matching)
- Wrapper result persistence (drift.db wrappers + wrapper_clusters tables)

### What Does NOT Live Here

- Source file parsing (lives in Parsers / Unified Analysis Engine)
- Call graph construction (lives in Call Graph Builder — wrappers consume it)
- Pattern detection (lives in Detector System — separate concern)
- DNA gene extraction (lives in DNA System — consumes wrapper data)
- Quality gate evaluation (lives in Quality Gates — consumes wrapper health)
- Constraint mining (lives in Constraint System — consumes wrapper patterns)
- MCP tool routing (lives in MCP Server)
- CLI command parsing (lives in CLI)

### Downstream Consumers

| Consumer | What It Reads | Interface |
|----------|--------------|-----------|
| Call Graph Builder | Wrapper→primitive mappings for resolution | `WrapperResolutionIndex` |
| DNA System | Wrapper patterns as convention signals | `WrapperConventionData` |
| Quality Gates | Wrapper health score, abstraction consistency | `WrapperHealthInput` |
| Constraint System | Wrapper patterns for invariant mining | `WrapperConstraintData` |
| Context Generation | Wrapper summary for AI context | `WrapperContextData` |
| Cortex Bridge (D7) | Wrapper patterns as grounding signal | `WrapperGroundingData` |
| MCP Server | drift_wrappers tool responses | `WrappersResult` |
| CLI | drift wrappers command output | `WrappersResult` |

### Upstream Dependencies

| Dependency | What It Provides | Contract |
|-----------|-----------------|----------|
| Scanner (Level 0) | File list, content hashes | `ScanDiff`, `ContentHash` |
| Parsers (Level 0) | ParseResult with functions, calls, imports | `ParseResult` |
| Storage (Level 0) | DatabaseManager for persistence | `batch_writer`, `keyset_pagination` |
| Call Graph (Level 1) | Function→function edges, callers/callees | `CallGraphDb` (optional) |
| Infrastructure (Level 0) | thiserror, tracing, FxHashMap, rayon, regex | Error enums, spans, handlers |



---

## 2. V1 Complete Feature Inventory

Every feature from the v1 implementation (Rust core ~700 LOC + TypeScript orchestration
~600 LOC) must be preserved in v2. This is the zero-feature-loss guarantee.

### 2.1 Rust Core Features (crates/drift-core/src/wrappers/)

| # | Feature | V1 Location | V2 Action |
|---|---------|-------------|-----------|
| R1 | `WrapperDetector` — per-file call-site analysis against primitives | `detector.rs` | **UPGRADED** — enhanced confidence, RegexSet matching |
| R2 | `WrapperClusterer` — groups related wrappers | `clusterer.rs` | **UPGRADED** — similarity scoring, cross-file awareness |
| R3 | `WrappersAnalyzer` — orchestrates detection + clustering | `analyzer.rs` | **UPGRADED** — unified engine with call graph integration |
| R4 | Known primitives registry (6 categories, ~20 primitives) | `detector.rs` | **EXPANDED** — 8 frameworks, 150+ primitives, TOML extensible |
| R5 | Confidence scoring (base 0.6 + 5 adjustments) | `detector.rs` | **UPGRADED** — 7-signal model with import/export awareness |
| R6 | `WrapperCategory` enum (12 variants) | `types.rs` | **EXPANDED** — 16 variants (+Middleware, +StateManagement split, +Testing, +Internationalization) |
| R7 | `WrapperInfo` struct (8 fields) | `types.rs` | **UPGRADED** — 14 fields (+id, +imports, +depth, +framework, +hash, +updated_at) |
| R8 | `WrapperCluster` struct (4 fields) | `types.rs` | **UPGRADED** — 8 fields (+id, +similarity_score, +health, +description) |
| R9 | `WrappersResult` struct (3 fields) | `types.rs` | **UPGRADED** — 5 fields (+health_score, +framework_breakdown) |
| R10 | `WrappersStats` struct (6 fields) | `types.rs` | **UPGRADED** — 10 fields (+framework stats, +depth distribution, +health) |
| R11 | Call extraction via ParseResult.calls filtered by function line range | `detector.rs` | **PRESERVED** — same strategy, optimized with pre-sorted calls |
| R12 | Primitive matching: exact OR ends_with OR contains | `detector.rs` | **UPGRADED** — RegexSet single-pass + import-aware resolution |
| R13 | Name-based category fallback (10 name→category rules) | `detector.rs` | **EXPANDED** — 16 name→category rules + import-based classification |
| R14 | Minimum confidence threshold: 0.5 | `detector.rs` | **PRESERVED** — configurable via WrapperConfig |
| R15 | One wrapper per function (first match wins) | `detector.rs` | **UPGRADED** — multi-primitive wrappers (function can wrap multiple) |
| R16 | NAPI: `analyze_wrappers(files)` | NAPI binding | **UPGRADED** — `analyze_wrappers(root)` + query functions |

### 2.2 TypeScript Orchestration Features (packages/core/src/wrappers/)

| # | Feature | V1 Location | V2 Action |
|---|---------|-------------|-----------|
| T1 | Expanded per-framework primitive registries | `primitives/` | **MOVED TO RUST** — 8 framework registries in Rust |
| T2 | Enhanced detection with call graph integration | `detection/` | **MOVED TO RUST** — call graph callers/callees queries |
| T3 | Cross-file usage counting from call graph | `detection/` | **MOVED TO RUST** — CallGraphDb integration |
| T4 | Full clustering with similarity scoring | `clustering/` | **MOVED TO RUST** — Jaccard + category + primitive similarity |
| T5 | Wrapper documentation generation | `export/` | **MOVED TO RUST** — Markdown + JSON export |
| T6 | Pattern store persistence | `integration/` | **REPLACED** — SQLite persistence (drift.db) |
| T7 | Wrapper types (WrapperInfo, WrapperCluster, etc.) | `types.ts` | **MOVED TO RUST** — all types in Rust, NAPI-exposed |
| T8 | Module exports and public API | `index.ts` | **REPLACED** — NAPI function exports |

### 2.3 NAPI Interface (v1 → v2)

| # | Feature | V1 | V2 |
|---|---------|----|----|
| N1 | Wrapper analysis entry point | `analyze_wrappers(files: Vec<String>)` | `analyze_wrappers(root: String, options?: WrapperOptions)` |
| N2 | Wrapper query | None (TS-side only) | `query_wrappers(filter: WrapperFilter)` |
| N3 | Wrapper cluster query | None (TS-side only) | `query_wrapper_clusters(filter: ClusterFilter)` |
| N4 | Wrapper detail | None | `query_wrapper_detail(id: String)` |
| N5 | Batch integration | `AnalysisType::Wrappers` in batch | **PRESERVED** — same batch API integration |

### 2.4 MCP Tool (v1 → v2)

| # | Feature | V1 | V2 |
|---|---------|----|----|
| M1 | `drift_wrappers` tool | ~500-1500 tokens, basic listing | **UPGRADED** — 4 actions (list, detail, clusters, health) |
| M2 | Token estimation | ~500-1500 | ~500-2000 (richer data) |

### 2.5 CLI Command (v1 → v2)

| # | Feature | V1 | V2 |
|---|---------|----|----|
| C1 | `drift wrappers` | Basic listing, --json, -v | **UPGRADED** — 4 subcommands |
| C2 | `drift wrappers list` | Implicit default | Explicit subcommand with filters |
| C3 | `drift wrappers clusters` | None | New: cluster listing |
| C4 | `drift wrappers detail <name>` | None | New: wrapper detail view |
| C5 | `drift wrappers health` | None | New: wrapper health report |

### 2.6 Known Gaps Addressed in V2

| # | V1 Gap | Source | V2 Resolution |
|---|--------|--------|---------------|
| G1 | Primitive registry React-focused only | MASTER-AUDIT RC-G12, AN-G7 | 8 frameworks, 150+ primitives |
| G2 | Usage counting always 0 in Rust | 01-rust-core/wrappers.md | Call graph integration fills usage |
| G3 | Clustering algorithm undocumented | 01-rust-core/RECAP.md §12 | Fully specified algorithm (§10) |
| G4 | No cross-file wrapper detection | 05-analyzers/wrappers-analysis.md | Call graph + import resolution |
| G5 | No wrapper documentation export | 05-analyzers/wrappers-analysis.md | Markdown + JSON export (§11) |
| G6 | No wrapper health scoring | New requirement | Health score for quality gates (§12) |
| G7 | One wrapper per function limitation | 01-rust-core/wrappers.md | Multi-primitive detection |
| G8 | No incremental analysis | New requirement | Content-hash aware (§13) |
| G9 | No TOML-configurable primitives | Audit question #8 | Custom primitive registry via TOML |
| G10 | No framework auto-detection | New requirement | Import-based framework detection |

---

## 3. V2 Architecture — Unified Wrapper Engine

### Design Philosophy

The v1 wrapper detection is split: Rust handles per-file detection (~700 LOC), TypeScript
handles orchestration (~600 LOC). V2 unifies everything in Rust. The TypeScript layer
becomes a thin NAPI caller — no wrapper logic remains in TS.

The key architectural upgrade is **call graph integration**. V1 Rust detection is
single-file: it sees calls within a function but can't count how many other files
call that wrapper. V2 uses the call graph (built by the Call Graph Builder at Level 1)
to resolve cross-file usage, enabling accurate usage counts and richer clustering.

### Engine Architecture

```
                    ┌─────────────────────────────────────┐
                    │        WrapperEngine (pub)           │
                    │                                     │
                    │  analyze(root, config, db, cg?)     │
                    │  analyze_incremental(diff, ...)     │
                    │  query_wrappers(filter, db)         │
                    │  query_clusters(filter, db)         │
                    │  export_docs(format, db)            │
                    │  health_score(db)                   │
                    └──────────────┬──────────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
    ┌─────────▼──────────┐ ┌──────▼───────┐ ┌─────────▼──────────┐
    │  PrimitiveRegistry │ │  Detector    │ │  Clusterer         │
    │                    │ │              │ │                    │
    │  8 framework regs  │ │  per-file    │ │  category+prim    │
    │  150+ primitives   │ │  call-site   │ │  similarity        │
    │  RegexSet compiled │ │  confidence  │ │  cross-file        │
    │  TOML extensible   │ │  multi-prim  │ │  health scoring    │
    └────────────────────┘ └──────────────┘ └────────────────────┘
              │                    │                    │
              │            ┌──────▼───────┐            │
              │            │  UsageCounter│            │
              │            │              │            │
              │            │  call graph  │            │
              │            │  callers()   │            │
              │            │  cross-file  │            │
              │            └──────────────┘            │
              │                    │                    │
              └────────────────────┼────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────┐
                    │        Storage (drift.db)            │
                    │                                     │
                    │  wrappers table                     │
                    │  wrapper_clusters table             │
                    │  wrapper_primitives table           │
                    │  wrapper_usage table                │
                    └─────────────────────────────────────┘
```

### Module Layout

```
drift-core/src/wrappers/
├── mod.rs              # Module exports
├── engine.rs           # WrapperEngine — public API, orchestration
├── registry.rs         # PrimitiveRegistry — 8 frameworks, RegexSet
├── detector.rs         # WrapperDetector — per-file call-site analysis
├── confidence.rs       # ConfidenceScorer — 7-signal model
├── classifier.rs       # CategoryClassifier — name + import + call hybrid
├── usage.rs            # UsageCounter — call graph integration
├── clusterer.rs        # WrapperClusterer — similarity-based grouping
├── health.rs           # HealthCalculator — wrapper health scoring
├── export.rs           # DocExporter — Markdown + JSON output
├── types.rs            # All types: WrapperInfo, WrapperCluster, etc.
├── config.rs           # WrapperConfig — TOML-configurable settings
├── storage.rs          # WrapperStorage — drift.db read/write
└── errors.rs           # WrapperError enum (thiserror)
```

14 files, estimated ~1,800 LOC total (vs v1: ~1,300 LOC across Rust + TS).
The increase is justified by: 8× larger primitive registry, cross-file usage,
enhanced clustering, documentation export, health scoring, and incremental analysis.


---

## 4. Core Data Model (Rust Types)

### 4.1 WrapperCategory Enum (16 Variants)

V1 has 12 variants. V2 adds 4 to cover expanded framework support.

```rust
use serde::{Deserialize, Serialize};

/// Category of framework primitive being wrapped.
/// V2 expands from 12 → 16 variants to cover multi-framework detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub enum WrapperCategory {
    // --- Preserved from v1 (12) ---
    StateManagement,
    SideEffects,
    DataFetching,
    Validation,
    Logging,
    Authentication,
    Caching,
    ErrorHandling,
    FormHandling,
    Routing,
    Factory,
    Other,
    // --- New in v2 (4) ---
    Middleware,          // Express/Koa/Hono middleware wrappers
    Testing,            // Test utility wrappers (render, act, waitFor)
    Internationalization, // i18n wrappers (useTranslation, formatMessage)
    Rendering,          // SSR/hydration wrappers (getServerSideProps, loader)
}
```

### 4.2 Framework Enum

```rust
/// Framework that a primitive belongs to.
/// Used for framework-specific detection and reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub enum Framework {
    React,
    Vue,
    Angular,
    Svelte,
    SolidJS,
    Express,
    NextJS,
    Generic,    // Framework-agnostic primitives (fetch, console, etc.)
}
```

### 4.3 WrapperInfo Struct (14 Fields)

V1 has 8 fields. V2 adds 6 for richer analysis.

```rust
/// A detected wrapper function.
/// V2 expands from 8 → 14 fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub struct WrapperInfo {
    // --- Preserved from v1 (8) ---
    pub name: String,               // Function name
    pub file: String,               // File path (relative to project root)
    pub line: u32,                  // Line number (1-indexed)
    pub wraps: Vec<String>,         // Wrapped primitive names (v2: multi-primitive)
    pub category: WrapperCategory,  // Primary category
    pub is_exported: bool,          // Whether the function is exported
    pub usage_count: u32,           // Cross-file usage count (v1: always 0 in Rust)
    pub confidence: f32,            // Detection confidence (0.0–1.0)
    // --- New in v2 (6) ---
    pub id: String,                 // Deterministic ID: SHA-256(file + name + line)[..16]
    pub framework: Framework,       // Detected framework
    pub imports: Vec<String>,       // Import sources for wrapped primitives
    pub depth: u8,                  // Wrapper depth (1 = direct, 2+ = wrapper-of-wrapper)
    pub content_hash: String,       // Content hash for incremental analysis
    pub updated_at: i64,            // Unix timestamp of last analysis
}
```

### 4.4 WrapperCluster Struct (8 Fields)

V1 has 4 fields. V2 adds 4 for richer clustering.

```rust
/// A group of related wrappers.
/// V2 expands from 4 → 8 fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub struct WrapperCluster {
    // --- Preserved from v1 (4) ---
    pub name: String,                   // Cluster name (auto-generated or user-defined)
    pub category: WrapperCategory,      // Primary category
    pub wrappers: Vec<WrapperInfo>,     // Member wrappers
    pub total_usage: u32,               // Sum of all member usage counts
    // --- New in v2 (4) ---
    pub id: String,                     // Deterministic cluster ID
    pub similarity_score: f32,          // Intra-cluster similarity (0.0–1.0)
    pub health: f32,                    // Cluster health score (0.0–100.0)
    pub description: String,            // Auto-generated description
}
```

### 4.5 WrappersResult Struct (5 Fields)

```rust
/// Complete wrapper analysis result.
/// V2 expands from 3 → 5 fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub struct WrappersResult {
    // --- Preserved from v1 (3) ---
    pub wrappers: Vec<WrapperInfo>,
    pub clusters: Vec<WrapperCluster>,
    pub stats: WrappersStats,
    // --- New in v2 (2) ---
    pub health_score: f32,              // Overall wrapper health (0.0–100.0)
    pub framework_breakdown: Vec<FrameworkCount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub struct FrameworkCount {
    pub framework: Framework,
    pub count: u32,
    pub percentage: f32,
}
```

### 4.6 WrappersStats Struct (10 Fields)

```rust
/// Wrapper analysis statistics.
/// V2 expands from 6 → 10 fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub struct WrappersStats {
    // --- Preserved from v1 (6) ---
    pub total_wrappers: u32,
    pub by_category: Vec<CategoryCount>,
    pub by_primitive: Vec<PrimitiveCount>,
    pub exported_count: u32,
    pub files_analyzed: u32,
    pub duration_ms: u64,
    // --- New in v2 (4) ---
    pub by_framework: Vec<FrameworkCount>,
    pub avg_confidence: f32,
    pub avg_depth: f32,
    pub cluster_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub struct CategoryCount {
    pub category: WrapperCategory,
    pub count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub struct PrimitiveCount {
    pub primitive: String,
    pub count: u32,
    pub framework: Framework,
}
```

### 4.7 WrappersSummary (NAPI Return Type)

Lightweight summary that crosses the NAPI boundary. Full data stays in drift.db.

```rust
/// Lightweight summary returned from analyze_wrappers().
/// Full data persisted to drift.db, queried via query_wrappers().
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub struct WrappersSummary {
    pub total_wrappers: u32,
    pub total_clusters: u32,
    pub health_score: f32,
    pub top_categories: Vec<CategoryCount>,
    pub top_frameworks: Vec<FrameworkCount>,
    pub files_analyzed: u32,
    pub files_with_wrappers: u32,
    pub duration_ms: u32,
    pub status: String,
}
```

### 4.8 Configuration Types

```rust
/// Wrapper detection configuration.
/// Loaded from drift.toml [wrappers] section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapperConfig {
    /// Minimum confidence threshold (default: 0.5)
    pub min_confidence: f32,
    /// Maximum calls in a function before it's considered "complex" (default: 10)
    pub max_calls_for_simple: u32,
    /// Minimum calls for "focused wrapper" bonus (default: 3)
    pub min_calls_for_focused: u32,
    /// Enable cross-file usage counting (requires call graph)
    pub enable_usage_counting: bool,
    /// Enable wrapper clustering
    pub enable_clustering: bool,
    /// Custom primitive definitions (from TOML)
    pub custom_primitives: Vec<CustomPrimitive>,
    /// Frameworks to detect (empty = all)
    pub frameworks: Vec<Framework>,
    /// File patterns to include (glob)
    pub include_patterns: Vec<String>,
    /// File patterns to exclude (glob)
    pub exclude_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomPrimitive {
    pub name: String,
    pub category: WrapperCategory,
    pub framework: Framework,
    pub import_source: Option<String>,
}

impl Default for WrapperConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.5,
            max_calls_for_simple: 10,
            min_calls_for_focused: 3,
            enable_usage_counting: true,
            enable_clustering: true,
            custom_primitives: Vec::new(),
            frameworks: Vec::new(), // empty = all
            include_patterns: vec!["**/*.{ts,tsx,js,jsx,vue,svelte}".into()],
            exclude_patterns: vec![
                "**/node_modules/**".into(),
                "**/*.test.*".into(),
                "**/*.spec.*".into(),
                "**/__tests__/**".into(),
            ],
        }
    }
}
```

### 4.9 Error Types

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WrapperError {
    #[error("Registry error: {0}")]
    Registry(String),

    #[error("Detection failed for {file}: {reason}")]
    Detection { file: String, reason: String },

    #[error("Clustering failed: {0}")]
    Clustering(String),

    #[error("Call graph unavailable: {0}")]
    CallGraphUnavailable(String),

    #[error("Storage error: {0}")]
    Storage(#[from] crate::errors::StorageError),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Export error: {0}")]
    Export(String),
}
```


---

## 5. Phase 1: Primitive Registry (8 Frameworks, 150+ Primitives)

The primitive registry is the foundation of wrapper detection. V1 has 6 categories with
~20 React-focused primitives. V2 expands to 8 frameworks with 150+ primitives.

### Registry Architecture

```rust
use regex::RegexSet;
use rustc_hash::FxHashMap;

/// Compiled primitive registry with RegexSet for single-pass matching.
pub struct PrimitiveRegistry {
    /// All registered primitives indexed by name
    primitives: FxHashMap<String, PrimitiveEntry>,
    /// RegexSet for single-pass matching against call targets
    regex_set: RegexSet,
    /// Ordered list of patterns (index matches RegexSet)
    patterns: Vec<String>,
    /// Import source → framework mapping for framework auto-detection
    import_framework_map: FxHashMap<String, Framework>,
}

#[derive(Debug, Clone)]
pub struct PrimitiveEntry {
    pub name: String,
    pub category: WrapperCategory,
    pub framework: Framework,
    pub import_sources: Vec<String>,    // e.g., ["react", "@tanstack/react-query"]
    pub match_mode: MatchMode,
}

#[derive(Debug, Clone, Copy)]
pub enum MatchMode {
    Exact,          // Call must exactly match primitive name
    EndsWith,       // Call must end with primitive name (e.g., "React.useState")
    Contains,       // Call must contain primitive name
    Prefix,         // Call must start with primitive name (e.g., "console.log")
}
```

### Framework Registries

#### 5.1 React (40 primitives)

| Category | Primitives |
|----------|-----------|
| StateManagement | `useState`, `useReducer`, `useSyncExternalStore`, `useOptimistic`, `useActionState` |
| SideEffects | `useEffect`, `useLayoutEffect`, `useInsertionEffect` |
| DataFetching | `use` (React 19 resource), `useSWR`, `useQuery`, `useMutation`, `useInfiniteQuery`, `useSuspenseQuery` |
| Rendering | `useMemo`, `useCallback`, `useRef`, `useId`, `useDeferredValue`, `useTransition`, `startTransition`, `memo`, `forwardRef`, `lazy` |
| Routing | `useRouter`, `useSearchParams`, `usePathname`, `useParams`, `useNavigate`, `useLocation`, `useMatch` |
| FormHandling | `useForm`, `useFormState`, `useFormStatus`, `useFieldArray`, `useWatch`, `useController` |
| ErrorHandling | `useErrorBoundary`, `ErrorBoundary` |
| Testing | `render`, `act`, `waitFor`, `screen`, `fireEvent`, `userEvent` |
| Internationalization | `useTranslation`, `useIntl`, `formatMessage`, `Trans` |

Import sources: `react`, `react-dom`, `react-router`, `react-router-dom`, `@tanstack/react-query`,
`swr`, `react-hook-form`, `@hookform/resolvers`, `react-i18next`, `react-intl`,
`@testing-library/react`, `next/navigation`, `next/router`

#### 5.2 Vue 3 (30 primitives)

| Category | Primitives |
|----------|-----------|
| StateManagement | `ref`, `reactive`, `shallowRef`, `shallowReactive`, `readonly`, `shallowReadonly`, `toRef`, `toRefs`, `triggerRef`, `customRef` |
| SideEffects | `watch`, `watchEffect`, `watchPostEffect`, `watchSyncEffect` |
| Rendering | `computed`, `h`, `defineComponent`, `defineAsyncComponent`, `nextTick`, `useSlots`, `useAttrs` |
| SideEffects | `onMounted`, `onUnmounted`, `onBeforeMount`, `onBeforeUnmount`, `onUpdated`, `onBeforeUpdate`, `onActivated`, `onDeactivated`, `onErrorCaptured` |
| DataFetching | `useFetch`, `useAsyncData` (Nuxt) |
| Routing | `useRouter`, `useRoute` |

Import sources: `vue`, `@vue/reactivity`, `@vue/runtime-core`, `nuxt/app`, `vue-router`

#### 5.3 Angular (25 primitives)

| Category | Primitives |
|----------|-----------|
| DataFetching | `HttpClient.get`, `HttpClient.post`, `HttpClient.put`, `HttpClient.delete`, `HttpClient.patch`, `HttpClient.request` |
| FormHandling | `FormBuilder.group`, `FormBuilder.control`, `FormBuilder.array`, `FormControl`, `FormGroup`, `FormArray`, `Validators` |
| Routing | `Router.navigate`, `Router.navigateByUrl`, `ActivatedRoute.params`, `ActivatedRoute.queryParams`, `ActivatedRoute.data` |
| Rendering | `ChangeDetectorRef.detectChanges`, `ChangeDetectorRef.markForCheck`, `Renderer2.createElement`, `Renderer2.setAttribute`, `NgZone.run`, `NgZone.runOutsideAngular` |
| StateManagement | `signal`, `computed`, `effect` (Angular 16+ signals) |

Import sources: `@angular/common/http`, `@angular/forms`, `@angular/router`,
`@angular/core`, `@angular/platform-browser`

#### 5.4 Svelte (15 primitives)

| Category | Primitives |
|----------|-----------|
| StateManagement | `writable`, `readable`, `derived`, `get` (Svelte 4 stores), `$state`, `$derived`, `$effect` (Svelte 5 runes) |
| SideEffects | `onMount`, `onDestroy`, `beforeUpdate`, `afterUpdate`, `tick` |
| Rendering | `createEventDispatcher`, `setContext`, `getContext`, `hasContext` |

Import sources: `svelte`, `svelte/store`, `svelte/motion`, `svelte/transition`

#### 5.5 SolidJS (15 primitives)

| Category | Primitives |
|----------|-----------|
| StateManagement | `createSignal`, `createStore`, `createMutable`, `produce`, `reconcile` |
| SideEffects | `createEffect`, `createRenderEffect`, `createComputed`, `onMount`, `onCleanup` |
| Rendering | `createMemo`, `createResource`, `lazy`, `createRoot`, `batch` |

Import sources: `solid-js`, `solid-js/store`, `solid-js/web`

#### 5.6 Express/Koa/Hono (15 primitives)

| Category | Primitives |
|----------|-----------|
| Middleware | `app.use`, `router.use`, `express.Router`, `app.get`, `app.post`, `app.put`, `app.delete`, `app.patch` |
| Middleware | `Hono.get`, `Hono.post`, `Hono.use`, `Koa.use` |
| ErrorHandling | `app.use` (4-arg error middleware) |

Import sources: `express`, `koa`, `hono`, `@hono/zod-validator`

#### 5.7 Next.js (15 primitives)

| Category | Primitives |
|----------|-----------|
| Rendering | `getServerSideProps`, `getStaticProps`, `getStaticPaths`, `generateStaticParams`, `generateMetadata` |
| DataFetching | `fetch` (extended), `unstable_cache`, `revalidatePath`, `revalidateTag` |
| Routing | `useRouter`, `useSearchParams`, `usePathname`, `useParams`, `redirect`, `notFound` |

Import sources: `next/navigation`, `next/router`, `next/cache`, `next/headers`

#### 5.8 Generic / Framework-Agnostic (20 primitives)

| Category | Primitives |
|----------|-----------|
| DataFetching | `fetch`, `axios`, `axios.get`, `axios.post`, `axios.put`, `axios.delete` |
| Validation | `z.object`, `z.string`, `z.number`, `z.array`, `z.enum` (Zod), `yup.object`, `yup.string` (Yup), `Joi.object` (Joi) |
| Logging | `console.log`, `console.error`, `console.warn`, `console.info`, `console.debug`, `logger.info`, `logger.error`, `logger.warn`, `logger.debug` |
| Authentication | `signIn`, `signOut`, `getSession`, `useSession`, `getServerSession` |
| Caching | `cache`, `memoize`, `lru-cache` |

Import sources: `axios`, `zod`, `yup`, `joi`, `next-auth`, `@auth/core`, `winston`, `pino`

### Registry Compilation

```rust
impl PrimitiveRegistry {
    /// Build the registry from built-in + custom primitives.
    /// Compiles a RegexSet for single-pass matching.
    pub fn new(config: &WrapperConfig) -> Result<Self, WrapperError> {
        let mut primitives = FxHashMap::default();
        let mut patterns = Vec::new();
        let mut import_map = FxHashMap::default();

        // Register built-in primitives for each framework
        Self::register_react(&mut primitives, &mut patterns, &mut import_map);
        Self::register_vue(&mut primitives, &mut patterns, &mut import_map);
        Self::register_angular(&mut primitives, &mut patterns, &mut import_map);
        Self::register_svelte(&mut primitives, &mut patterns, &mut import_map);
        Self::register_solid(&mut primitives, &mut patterns, &mut import_map);
        Self::register_express(&mut primitives, &mut patterns, &mut import_map);
        Self::register_nextjs(&mut primitives, &mut patterns, &mut import_map);
        Self::register_generic(&mut primitives, &mut patterns, &mut import_map);

        // Register custom primitives from TOML config
        for custom in &config.custom_primitives {
            let entry = PrimitiveEntry {
                name: custom.name.clone(),
                category: custom.category,
                framework: custom.framework,
                import_sources: custom.import_source.iter().cloned().collect(),
                match_mode: MatchMode::Exact,
            };
            patterns.push(regex::escape(&custom.name));
            primitives.insert(custom.name.clone(), entry);
        }

        // Filter by configured frameworks (if specified)
        if !config.frameworks.is_empty() {
            primitives.retain(|_, v| config.frameworks.contains(&v.framework)
                || v.framework == Framework::Generic);
        }

        let regex_set = RegexSet::new(&patterns)
            .map_err(|e| WrapperError::Registry(format!("RegexSet compilation: {e}")))?;

        Ok(Self { primitives, regex_set, patterns, import_framework_map: import_map })
    }

    /// Single-pass match: returns all primitives that match the call target.
    pub fn match_call(&self, call_target: &str) -> Vec<&PrimitiveEntry> {
        self.regex_set
            .matches(call_target)
            .into_iter()
            .filter_map(|idx| {
                let pattern_name = &self.patterns[idx];
                self.primitives.get(pattern_name)
            })
            .collect()
    }

    /// Detect framework from import sources.
    pub fn detect_framework(&self, imports: &[String]) -> Framework {
        let mut framework_counts: FxHashMap<Framework, u32> = FxHashMap::default();
        for import in imports {
            if let Some(fw) = self.import_framework_map.get(import.as_str()) {
                *framework_counts.entry(*fw).or_default() += 1;
            }
        }
        framework_counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(fw, _)| fw)
            .unwrap_or(Framework::Generic)
    }
}
```


---

## 6. Phase 2: Per-File Wrapper Detection (Call-Site Analysis)

This is the core detection algorithm. V1's approach is preserved and enhanced.

### Algorithm (V2 Enhanced)

```
For each file in scan results:
  1. Get ParseResult (functions, calls, imports, exports)
  2. Detect framework from imports (§5 registry)
  3. Pre-sort calls by line number (optimization)
  4. For each function in ParseResult.functions:
     a. Extract calls within function's line range (binary search on sorted calls)
     b. Extract import sources for those calls
     c. For each call:
        - Match against PrimitiveRegistry (RegexSet single-pass)
        - If match(es) found:
          - Calculate confidence (§7)
          - Classify category (§8)
          - Record ALL matched primitives (v2: multi-primitive)
     d. If any primitives matched AND confidence ≥ threshold:
        - Create WrapperInfo
        - Determine wrapper depth (§6.2)
        - Generate deterministic ID
  5. Persist results to drift.db via batch writer
```

### Key Differences from V1

| Aspect | V1 | V2 |
|--------|----|----|
| Primitives per function | First match wins (1) | All matches recorded (multi-primitive) |
| Call extraction | Linear scan of all calls | Binary search on pre-sorted calls |
| Primitive matching | Sequential check per call | RegexSet single-pass per call |
| Framework detection | None | Import-based auto-detection |
| Wrapper depth | Not tracked | Recursive depth calculation |
| Incremental | Full re-analysis | Content-hash skip unchanged |

### 6.1 Call Extraction (Optimized)

V1 filters `ParseResult.calls` with a linear scan. V2 pre-sorts calls by start line
and uses binary search for O(log n) lookup per function.

```rust
/// Extract calls within a function's line range using binary search.
fn extract_calls_for_function<'a>(
    sorted_calls: &'a [CallInfo],
    func_start: u32,
    func_end: u32,
) -> &'a [CallInfo] {
    let start_idx = sorted_calls
        .partition_point(|c| c.range.start.line < func_start);
    let end_idx = sorted_calls
        .partition_point(|c| c.range.start.line <= func_end);
    &sorted_calls[start_idx..end_idx]
}
```

### 6.2 Wrapper Depth Calculation

A wrapper that wraps another wrapper has depth > 1. This is new in v2 and requires
a second pass after initial detection.

```
Depth calculation (post-detection pass):
  Build wrapper_name_set from all detected wrappers in project
  For each wrapper W:
    depth = 1
    For each call C in W's calls:
      If C.target ∈ wrapper_name_set:
        depth = max(depth, lookup_depth(C.target) + 1)
    W.depth = depth
```

This is bounded: maximum depth is capped at 5 to prevent pathological cases.
Circular wrapper chains (A wraps B wraps A) are detected and broken at depth 1.

### 6.3 Deterministic ID Generation

```rust
use sha2::{Sha256, Digest};

/// Generate deterministic wrapper ID from file + name + line.
/// Same as v1 mutation ID pattern (DNA system).
fn generate_wrapper_id(file: &str, name: &str, line: u32) -> String {
    let mut hasher = Sha256::new();
    hasher.update(file.as_bytes());
    hasher.update(b":");
    hasher.update(name.as_bytes());
    hasher.update(b":");
    hasher.update(line.to_string().as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..8]) // 16 hex chars
}
```

### 6.4 Multi-Primitive Detection

V1 breaks after the first primitive match per function. V2 records all matches.
This is important for functions like `useAuthForm()` that wrap both `useState` and
`useForm` — both primitives should be recorded.

```rust
fn detect_wrappers_in_function(
    func: &FunctionInfo,
    calls: &[CallInfo],
    registry: &PrimitiveRegistry,
    imports: &[ImportInfo],
) -> Option<WrapperInfo> {
    let mut matched_primitives: Vec<String> = Vec::new();
    let mut primary_category = WrapperCategory::Other;
    let mut primary_framework = Framework::Generic;
    let mut matched_entries: Vec<&PrimitiveEntry> = Vec::new();

    for call in calls {
        let call_target = resolve_call_target(call, imports);
        let matches = registry.match_call(&call_target);
        for entry in matches {
            if !matched_primitives.contains(&entry.name) {
                matched_primitives.push(entry.name.clone());
                matched_entries.push(entry);
            }
        }
    }

    if matched_primitives.is_empty() {
        return None;
    }

    // Primary category = most specific match (not Other)
    primary_category = matched_entries.iter()
        .map(|e| e.category)
        .find(|c| *c != WrapperCategory::Other)
        .unwrap_or(WrapperCategory::Other);

    // Primary framework = most common framework among matches
    primary_framework = most_common_framework(&matched_entries);

    let confidence = calculate_confidence(func, calls, &matched_primitives);
    if confidence < config.min_confidence {
        return None;
    }

    Some(WrapperInfo {
        name: func.name.clone(),
        file: file_path.to_string(),
        line: func.range.start.line,
        wraps: matched_primitives,
        category: primary_category,
        is_exported: func.is_exported,
        usage_count: 0, // Filled in Phase 5
        confidence,
        id: generate_wrapper_id(file_path, &func.name, func.range.start.line),
        framework: primary_framework,
        imports: extract_import_sources(imports, &matched_entries),
        depth: 1, // Filled in post-detection pass
        content_hash: String::new(), // Filled by caller
        updated_at: now_unix(),
    })
}
```

---

## 7. Phase 3: Confidence Scoring (Enhanced 7-Signal Model)

V1 uses a 5-signal model (base 0.6 + 5 adjustments). V2 enhances to 7 signals
with import-awareness and export-awareness.

### V1 Confidence Formula (Preserved)

```
base = 0.6
+ 0.15 if name starts with: use, with, create, make
+ 0.15 if name contains: wrapper, hook, helper
+ 0.10 if custom hook pattern (useXxx where X is uppercase)
- 0.10 if total_calls > max_calls_for_simple (default: 10)
+ 0.10 if total_calls ≤ min_calls_for_focused (default: 3)
confidence = clamp(base + adjustments, 0.0, 1.0)
```

### V2 Enhanced Formula (7 Signals)

```
base = 0.6

Signal 1 — Name prefix (preserved):
  + 0.15 if name starts with: use, with, create, make, wrap, get, set

Signal 2 — Name contains (preserved):
  + 0.15 if name contains: wrapper, hook, helper, util, adapter, proxy, facade

Signal 3 — Custom hook pattern (preserved):
  + 0.10 if custom hook pattern (useXxx where X is uppercase)

Signal 4 — Call complexity (preserved):
  - 0.10 if total_calls > max_calls_for_simple
  + 0.10 if total_calls ≤ min_calls_for_focused

Signal 5 — Import awareness (NEW):
  + 0.10 if wrapped primitive is explicitly imported (not global)
  This confirms the function intentionally uses the framework API.

Signal 6 — Export awareness (NEW):
  + 0.05 if function is exported
  Exported wrappers are more likely intentional abstractions.

Signal 7 — Primitive ratio (NEW):
  + 0.05 if primitive_calls / total_calls ≥ 0.5
  Functions where most calls are to primitives are more likely wrappers.

confidence = clamp(base + signals, 0.0, 1.0)
```

### Implementation

```rust
pub fn calculate_confidence(
    func: &FunctionInfo,
    calls: &[CallInfo],
    matched_primitives: &[String],
    imports: &[ImportInfo],
    config: &WrapperConfig,
) -> f32 {
    let mut score: f32 = 0.6;
    let name = &func.name;
    let total_calls = calls.len() as u32;
    let primitive_calls = matched_primitives.len() as u32;

    // Signal 1: Name prefix
    let prefixes = ["use", "with", "create", "make", "wrap", "get", "set"];
    if prefixes.iter().any(|p| name.starts_with(p)) {
        score += 0.15;
    }

    // Signal 2: Name contains
    let keywords = ["wrapper", "hook", "helper", "util", "adapter", "proxy", "facade"];
    if keywords.iter().any(|k| name.to_lowercase().contains(k)) {
        score += 0.15;
    }

    // Signal 3: Custom hook pattern (useXxx)
    if name.starts_with("use") && name.len() > 3 {
        let fourth_char = name.chars().nth(3).unwrap_or('a');
        if fourth_char.is_uppercase() {
            score += 0.10;
        }
    }

    // Signal 4: Call complexity
    if total_calls > config.max_calls_for_simple {
        score -= 0.10;
    } else if total_calls <= config.min_calls_for_focused {
        score += 0.10;
    }

    // Signal 5: Import awareness (NEW)
    let has_explicit_import = matched_primitives.iter().any(|prim| {
        imports.iter().any(|imp| imp.specifiers.contains(prim))
    });
    if has_explicit_import {
        score += 0.10;
    }

    // Signal 6: Export awareness (NEW)
    if func.is_exported {
        score += 0.05;
    }

    // Signal 7: Primitive ratio (NEW)
    if total_calls > 0 && (primitive_calls as f32 / total_calls as f32) >= 0.5 {
        score += 0.05;
    }

    score.clamp(0.0, 1.0)
}
```

### Confidence Thresholds

| Range | Interpretation |
|-------|---------------|
| 0.90–1.00 | Very high confidence — obvious wrapper (name + import + focused) |
| 0.75–0.89 | High confidence — strong signals |
| 0.60–0.74 | Medium confidence — base + some signals |
| 0.50–0.59 | Low confidence — barely above threshold |
| < 0.50 | Rejected — not recorded as wrapper |


---

## 8. Phase 4: Category Classification (Name + Import + Call-Site Hybrid)

V1 uses a two-step approach: (1) primitive registry category, (2) name-based fallback.
V2 adds import-based classification as a third signal for higher accuracy.

### Classification Priority

```
1. Primitive registry match → use registry category (highest priority)
2. Import source analysis → infer category from import path
3. Name-based fallback → pattern match on function name (lowest priority)
```

### Import-Based Classification (NEW)

```rust
fn classify_from_imports(imports: &[ImportInfo]) -> Option<WrapperCategory> {
    for import in imports {
        let source = import.source.to_lowercase();
        if source.contains("auth") || source.contains("session") {
            return Some(WrapperCategory::Authentication);
        }
        if source.contains("form") || source.contains("formik") {
            return Some(WrapperCategory::FormHandling);
        }
        if source.contains("router") || source.contains("navigation") {
            return Some(WrapperCategory::Routing);
        }
        if source.contains("i18n") || source.contains("intl") || source.contains("locale") {
            return Some(WrapperCategory::Internationalization);
        }
        if source.contains("test") || source.contains("jest") || source.contains("vitest") {
            return Some(WrapperCategory::Testing);
        }
        if source.contains("cache") || source.contains("memo") {
            return Some(WrapperCategory::Caching);
        }
        if source.contains("middleware") {
            return Some(WrapperCategory::Middleware);
        }
    }
    None
}
```

### Name-Based Fallback (V2 Expanded — 16 Rules)

V1 has 10 name→category rules. V2 expands to 16.

| # | Name Pattern | Category |
|---|-------------|----------|
| 1 | auth, login, session, signIn, signOut | Authentication |
| 2 | fetch, api, request, http, query, mutate | DataFetching |
| 3 | valid, schema, parse, safeParse | Validation |
| 4 | log, trace, debug, logger, telemetry | Logging |
| 5 | cache, memo, memoize, lru | Caching |
| 6 | error, catch, handle, boundary, fallback | ErrorHandling |
| 7 | form, input, field, submit | FormHandling |
| 8 | route, navigate, link, redirect, path | Routing |
| 9 | create, factory, build, make, construct | Factory |
| 10 | state, store, atom, signal, reducer | StateManagement |
| 11 | effect, watch, subscribe, listen, observe | SideEffects |
| 12 | middleware, intercept, guard, pipe | Middleware |
| 13 | test, mock, stub, spy, fixture | Testing |
| 14 | translate, i18n, intl, locale, format | Internationalization |
| 15 | render, hydrate, ssr, server, loader | Rendering |
| 16 | (none of above) | Other |

---

## 9. Phase 5: Cross-File Usage Counting (Call Graph Integration)

This is the biggest upgrade from v1. V1 Rust always sets `usage_count = 0` because
it has no cross-file visibility. The TS layer fills it from the call graph. V2 does
this entirely in Rust.

### Algorithm

```
Prerequisites: Call graph must be built (Level 1 dependency)

For each detected wrapper W:
  1. Look up W in call graph by qualified name (file:function_name)
  2. Query callers: cg.callers(W.qualified_name)
  3. Filter callers to exclude:
     - Same-file callers (intra-file usage doesn't count)
     - Test file callers (test usage is separate metric)
     - Node_modules callers (external usage doesn't count)
  4. W.usage_count = filtered_callers.len()
```

### Implementation

```rust
use crate::call_graph::CallGraphDb;

pub struct UsageCounter<'a> {
    call_graph: Option<&'a CallGraphDb>,
}

impl<'a> UsageCounter<'a> {
    pub fn new(call_graph: Option<&'a CallGraphDb>) -> Self {
        Self { call_graph }
    }

    /// Count cross-file usage for a wrapper.
    /// Returns 0 if call graph is unavailable (graceful degradation).
    pub fn count_usage(&self, wrapper: &WrapperInfo) -> u32 {
        let Some(cg) = self.call_graph else {
            return 0;
        };

        let qualified_name = format!("{}:{}", wrapper.file, wrapper.name);
        let callers = match cg.callers(&qualified_name) {
            Ok(callers) => callers,
            Err(_) => return 0,
        };

        callers
            .iter()
            .filter(|caller| {
                // Exclude same-file callers
                caller.file != wrapper.file
                // Exclude test files
                && !is_test_file(&caller.file)
                // Exclude node_modules
                && !caller.file.contains("node_modules")
            })
            .count() as u32
    }

    /// Batch count usage for all wrappers (more efficient than per-wrapper).
    pub fn count_usage_batch(&self, wrappers: &mut [WrapperInfo]) {
        let Some(cg) = self.call_graph else {
            return; // All usage_count stays 0
        };

        for wrapper in wrappers.iter_mut() {
            wrapper.usage_count = self.count_usage(wrapper);
        }
    }
}

fn is_test_file(path: &str) -> bool {
    path.contains(".test.") || path.contains(".spec.")
        || path.contains("__tests__") || path.contains("__test__")
}
```

### Graceful Degradation

If the call graph hasn't been built yet (e.g., first scan, or call graph disabled),
usage counting silently returns 0 for all wrappers. This matches v1 Rust behavior
and ensures wrapper detection works independently of call graph availability.

The `WrappersSummary` includes a `usage_counting_available: bool` field so the
TS layer knows whether usage counts are meaningful.

---

## 10. Phase 6: Wrapper Clustering (Category + Primitive + Similarity)

V1 has clustering in Rust (`clusterer.rs`) but the algorithm is undocumented.
V2 fully specifies the clustering algorithm.

### Clustering Algorithm

```
Input: Vec<WrapperInfo> (all detected wrappers)
Output: Vec<WrapperCluster>

Phase 1 — Category Grouping:
  Group wrappers by (category, primary_primitive)
  Each group becomes a candidate cluster

Phase 2 — Similarity Refinement:
  For each candidate cluster with > 1 member:
    Calculate pairwise Jaccard similarity on wrapped primitives
    If avg similarity < 0.3: split into sub-clusters
    If avg similarity ≥ 0.3: keep as single cluster

Phase 3 — Naming:
  Cluster name = "{category} wrappers ({primary_primitive})"
  e.g., "DataFetching wrappers (useQuery)"

Phase 4 — Health Scoring:
  Per-cluster health = consistency × confidence × usage
  (See §12 for formula)

Phase 5 — Description Generation:
  Auto-generate description from cluster members
  e.g., "3 data fetching wrappers around useQuery, used 47 times across 12 files"
```

### Jaccard Similarity

```rust
/// Jaccard similarity between two sets of wrapped primitives.
fn jaccard_similarity(a: &[String], b: &[String]) -> f32 {
    let set_a: FxHashSet<&str> = a.iter().map(|s| s.as_str()).collect();
    let set_b: FxHashSet<&str> = b.iter().map(|s| s.as_str()).collect();
    let intersection = set_a.intersection(&set_b).count();
    let union = set_a.union(&set_b).count();
    if union == 0 {
        return 0.0;
    }
    intersection as f32 / union as f32
}
```

### Cluster ID Generation

```rust
/// Deterministic cluster ID from sorted member IDs.
fn generate_cluster_id(members: &[WrapperInfo]) -> String {
    let mut hasher = Sha256::new();
    let mut ids: Vec<&str> = members.iter().map(|w| w.id.as_str()).collect();
    ids.sort();
    for id in ids {
        hasher.update(id.as_bytes());
        hasher.update(b":");
    }
    let result = hasher.finalize();
    hex::encode(&result[..8])
}
```

### Implementation

```rust
pub struct WrapperClusterer;

impl WrapperClusterer {
    pub fn cluster(wrappers: &[WrapperInfo]) -> Vec<WrapperCluster> {
        let mut clusters = Vec::new();

        // Phase 1: Group by (category, primary_primitive)
        let mut groups: FxHashMap<(WrapperCategory, String), Vec<&WrapperInfo>> =
            FxHashMap::default();
        for wrapper in wrappers {
            let primary = wrapper.wraps.first()
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            groups.entry((wrapper.category, primary))
                .or_default()
                .push(wrapper);
        }

        // Phase 2: Similarity refinement
        for ((category, primary), members) in &groups {
            if members.len() == 1 {
                // Single-member cluster
                clusters.push(Self::build_cluster(
                    category, primary, members, 1.0,
                ));
                continue;
            }

            let avg_sim = Self::avg_pairwise_similarity(members);
            if avg_sim >= 0.3 {
                clusters.push(Self::build_cluster(
                    category, primary, members, avg_sim,
                ));
            } else {
                // Split: each member becomes its own cluster
                for member in members {
                    clusters.push(Self::build_cluster(
                        category, primary, &[member], 1.0,
                    ));
                }
            }
        }

        // Sort clusters by total_usage descending
        clusters.sort_by(|a, b| b.total_usage.cmp(&a.total_usage));
        clusters
    }

    fn avg_pairwise_similarity(members: &[&WrapperInfo]) -> f32 {
        if members.len() < 2 {
            return 1.0;
        }
        let mut total = 0.0;
        let mut count = 0;
        for i in 0..members.len() {
            for j in (i + 1)..members.len() {
                total += jaccard_similarity(&members[i].wraps, &members[j].wraps);
                count += 1;
            }
        }
        if count == 0 { 1.0 } else { total / count as f32 }
    }

    fn build_cluster(
        category: &WrapperCategory,
        primary: &str,
        members: &[&WrapperInfo],
        similarity: f32,
    ) -> WrapperCluster {
        let total_usage: u32 = members.iter().map(|w| w.usage_count).sum();
        let avg_confidence: f32 = members.iter().map(|w| w.confidence).sum::<f32>()
            / members.len() as f32;
        let member_count = members.len();
        let file_count = members.iter()
            .map(|w| w.file.as_str())
            .collect::<FxHashSet<_>>()
            .len();

        WrapperCluster {
            id: generate_cluster_id_from_refs(members),
            name: format!("{:?} wrappers ({})", category, primary),
            category: *category,
            wrappers: members.iter().map(|w| (*w).clone()).collect(),
            total_usage,
            similarity_score: similarity,
            health: avg_confidence * 100.0, // Simplified; full formula in §12
            description: format!(
                "{} {} wrapper{} around {}, used {} time{} across {} file{}",
                member_count,
                format!("{:?}", category).to_lowercase(),
                if member_count != 1 { "s" } else { "" },
                primary,
                total_usage,
                if total_usage != 1 { "s" } else { "" },
                file_count,
                if file_count != 1 { "s" } else { "" },
            ),
        }
    }
}
```


---

## 11. Phase 7: Wrapper Documentation Export (Markdown + JSON)

V1 TS layer has documentation export. V2 moves this to Rust.

### Markdown Export

```rust
pub struct DocExporter;

impl DocExporter {
    /// Generate Markdown documentation for all wrappers.
    pub fn export_markdown(result: &WrappersResult) -> String {
        let mut md = String::with_capacity(4096);

        // Header
        md.push_str("# Project Wrapper Documentation\n\n");
        md.push_str(&format!(
            "> Auto-generated by Drift. {} wrappers detected across {} clusters.\n",
            result.stats.total_wrappers, result.stats.cluster_count,
        ));
        md.push_str(&format!("> Health Score: {:.0}/100\n\n", result.health_score));

        // Quick Reference Table
        md.push_str("## Quick Reference\n\n");
        md.push_str("| Wrapper | Category | Wraps | Usage | Confidence |\n");
        md.push_str("|---------|----------|-------|-------|------------|\n");
        for w in &result.wrappers {
            md.push_str(&format!(
                "| `{}` | {:?} | {} | {} | {:.0}% |\n",
                w.name,
                w.category,
                w.wraps.join(", "),
                w.usage_count,
                w.confidence * 100.0,
            ));
        }

        // Framework Breakdown
        md.push_str("\n## Framework Breakdown\n\n");
        for fc in &result.framework_breakdown {
            md.push_str(&format!(
                "- **{:?}**: {} wrappers ({:.0}%)\n",
                fc.framework, fc.count, fc.percentage,
            ));
        }

        // Clusters
        md.push_str("\n## Wrapper Clusters\n\n");
        for cluster in &result.clusters {
            md.push_str(&format!("### {}\n\n", cluster.name));
            md.push_str(&format!("{}\n\n", cluster.description));
            md.push_str("| Wrapper | File | Line | Usage |\n");
            md.push_str("|---------|------|------|-------|\n");
            for w in &cluster.wrappers {
                md.push_str(&format!(
                    "| `{}` | `{}` | {} | {} |\n",
                    w.name, w.file, w.line, w.usage_count,
                ));
            }
            md.push_str("\n");
        }

        md
    }

    /// Generate JSON documentation for all wrappers.
    pub fn export_json(result: &WrappersResult) -> Result<String, WrapperError> {
        serde_json::to_string_pretty(result)
            .map_err(|e| WrapperError::Export(format!("JSON serialization: {e}")))
    }
}
```

---

## 12. Phase 8: Wrapper Health Scoring

New in v2. Provides a single 0–100 score for quality gate integration.

### Health Formula (4-Factor Weighted Composite)

Inspired by the DNA system's health formula (§H1 in DNA V2 Prep).

```
health = consistency(35%) + confidence(30%) + coverage(20%) + abstraction(15%)

consistency = 1 - (category_entropy / max_entropy)
  Where category_entropy = -Σ(p_i × log2(p_i)) for each category proportion
  High consistency = wrappers concentrated in few categories (team has clear patterns)
  Low consistency = wrappers scattered across many categories (no clear pattern)

confidence = average confidence across all wrappers
  High confidence = strong naming/import signals
  Low confidence = ambiguous detection

coverage = exported_wrappers / total_wrappers
  High coverage = team exports their wrappers (intentional abstractions)
  Low coverage = many private wrappers (ad-hoc, not shared)

abstraction = 1 - (avg_depth - 1) / max_depth
  High abstraction = shallow wrappers (direct primitive access)
  Low abstraction = deep wrapper chains (over-abstraction)

health = clamp(
    consistency * 0.35 + confidence * 0.30 + coverage * 0.20 + abstraction * 0.15,
    0.0, 1.0
) * 100.0
```

### Implementation

```rust
pub struct HealthCalculator;

impl HealthCalculator {
    pub fn calculate(wrappers: &[WrapperInfo]) -> f32 {
        if wrappers.is_empty() {
            return 100.0; // No wrappers = no problems
        }

        let consistency = Self::consistency_score(wrappers);
        let confidence = Self::avg_confidence(wrappers);
        let coverage = Self::coverage_score(wrappers);
        let abstraction = Self::abstraction_score(wrappers);

        let health = consistency * 0.35
            + confidence * 0.30
            + coverage * 0.20
            + abstraction * 0.15;

        (health * 100.0).clamp(0.0, 100.0)
    }

    fn consistency_score(wrappers: &[WrapperInfo]) -> f32 {
        let mut category_counts: FxHashMap<WrapperCategory, u32> = FxHashMap::default();
        for w in wrappers {
            *category_counts.entry(w.category).or_default() += 1;
        }
        let total = wrappers.len() as f32;
        let entropy: f32 = category_counts.values()
            .map(|&count| {
                let p = count as f32 / total;
                if p > 0.0 { -p * p.log2() } else { 0.0 }
            })
            .sum();
        let max_entropy = (category_counts.len() as f32).log2().max(1.0);
        1.0 - (entropy / max_entropy).min(1.0)
    }

    fn avg_confidence(wrappers: &[WrapperInfo]) -> f32 {
        wrappers.iter().map(|w| w.confidence).sum::<f32>() / wrappers.len() as f32
    }

    fn coverage_score(wrappers: &[WrapperInfo]) -> f32 {
        let exported = wrappers.iter().filter(|w| w.is_exported).count() as f32;
        exported / wrappers.len() as f32
    }

    fn abstraction_score(wrappers: &[WrapperInfo]) -> f32 {
        let avg_depth = wrappers.iter().map(|w| w.depth as f32).sum::<f32>()
            / wrappers.len() as f32;
        let max_depth = 5.0;
        1.0 - ((avg_depth - 1.0) / max_depth).clamp(0.0, 1.0)
    }
}
```

### Health Thresholds

| Score | Status | Meaning |
|-------|--------|---------|
| 80–100 | Healthy | Consistent wrapper patterns, good abstractions |
| 60–79 | Warning | Some inconsistency or low confidence |
| 40–59 | Degraded | Significant wrapper sprawl or over-abstraction |
| 0–39 | Critical | No clear wrapper patterns, deep chains |

---

## 13. Phase 9: Incremental Wrapper Analysis (Content-Hash Aware)

New in v2. Avoids re-analyzing unchanged files.

### Algorithm

```
Input: ScanDiff (added, modified, removed, unchanged files)

1. For removed files:
   DELETE FROM wrappers WHERE file IN (removed_files)
   DELETE FROM wrapper_clusters (will be rebuilt)

2. For added + modified files:
   Run full detection pipeline (§6–§8)
   UPSERT results into wrappers table

3. For unchanged files:
   Skip detection — existing results in drift.db are still valid

4. Rebuild clusters from all wrappers (full + incremental)
   Clustering is cheap (in-memory, no I/O) so always runs on full set

5. Recalculate health score
```

### Content-Hash Validation

```rust
/// Check if a file's wrappers need re-analysis.
fn needs_reanalysis(
    file: &str,
    current_hash: &str,
    db: &DatabaseManager,
) -> bool {
    match db.query_row(
        "SELECT content_hash FROM wrappers WHERE file = ?1 LIMIT 1",
        [file],
        |row| row.get::<_, String>(0),
    ) {
        Ok(stored_hash) => stored_hash != current_hash,
        Err(_) => true, // No existing data → needs analysis
    }
}
```


---

## 14. RegexSet Optimization — Single-Pass Primitive Matching

V1 checks each call against each primitive sequentially. V2 uses Rust's `regex::RegexSet`
for single-pass matching — one pass over the call target string matches against all 150+
primitive patterns simultaneously.

### Why RegexSet

From the Rust regex crate documentation: RegexSet compiles multiple patterns into a single
automaton. A single scan of the input string determines which patterns match. For 150+
patterns, this is dramatically faster than 150+ sequential regex matches.

This is the same optimization used by the DNA system's gene extractors (§18 in DNA V2 Prep).

### Pattern Compilation Strategy

```rust
/// Build regex patterns for each primitive.
/// Uses anchored patterns for exact/endswith/contains modes.
fn build_patterns(primitives: &[PrimitiveEntry]) -> Vec<String> {
    primitives.iter().map(|p| {
        let escaped = regex::escape(&p.name);
        match p.match_mode {
            MatchMode::Exact => format!("^{}$", escaped),
            MatchMode::EndsWith => format!("(?:^|\\.){}$", escaped),
            MatchMode::Contains => escaped,
            MatchMode::Prefix => format!("^{}", escaped),
        }
    }).collect()
}
```

### Performance Impact

| Metric | V1 (Sequential) | V2 (RegexSet) |
|--------|-----------------|---------------|
| Patterns | ~20 | 150+ |
| Match time per call | O(n) where n = patterns | O(1) amortized |
| 10K functions × 5 calls | ~1M comparisons | ~50K regex scans |
| Estimated speedup | Baseline | 5-10× for primitive matching |

---

## 15. Integration with Unified Analysis Engine

Wrapper detection consumes `ParseResult` from the Unified Analysis Engine (Level 1).

### ParseResult Contract

Wrapper detection requires these fields from `ParseResult`:

```rust
// From drift-core unified analysis
pub struct ParseResult {
    pub functions: Vec<FunctionInfo>,   // All functions in file
    pub calls: Vec<CallInfo>,           // All call sites in file
    pub imports: Vec<ImportInfo>,       // All import statements
    pub exports: Vec<ExportInfo>,       // All export statements
    // ... other fields not used by wrapper detection
}
```

### Integration Point

```rust
/// Wrapper detection entry point from unified analysis pipeline.
/// Called during Phase 2 (cross-file analysis) of the unified pipeline.
pub fn analyze_wrappers_from_parse_results(
    parse_results: &[(PathBuf, ParseResult)],
    config: &WrapperConfig,
    db: &DatabaseManager,
    call_graph: Option<&CallGraphDb>,
) -> Result<WrappersSummary, WrapperError> {
    let engine = WrapperEngine::new(config)?;
    engine.analyze_from_parse_results(parse_results, db, call_graph)
}
```

---

## 16. Integration with Call Graph Builder

Wrapper detection both consumes and enriches the call graph.

### Consuming Call Graph (Usage Counting)

As described in §9, wrapper detection queries the call graph for cross-file callers
of each detected wrapper function.

### Enriching Call Graph (Wrapper Resolution Index)

Wrapper detection produces a `WrapperResolutionIndex` that the call graph can use
to resolve through wrapper indirection:

```rust
/// Index mapping wrapper functions to their wrapped primitives.
/// Used by call graph builder to resolve through wrappers.
pub struct WrapperResolutionIndex {
    /// wrapper_qualified_name → wrapped primitive names
    wrapper_to_primitives: FxHashMap<String, Vec<String>>,
}

impl WrapperResolutionIndex {
    pub fn from_wrappers(wrappers: &[WrapperInfo]) -> Self {
        let mut map = FxHashMap::default();
        for w in wrappers {
            let qualified = format!("{}:{}", w.file, w.name);
            map.insert(qualified, w.wraps.clone());
        }
        Self { wrapper_to_primitives: map }
    }

    /// Resolve a call through wrapper indirection.
    /// Returns the underlying primitives if the target is a known wrapper.
    pub fn resolve(&self, call_target: &str) -> Option<&[String]> {
        self.wrapper_to_primitives.get(call_target).map(|v| v.as_slice())
    }
}
```

### Dependency Order

Call graph is built at Level 1. Wrapper detection runs at Level 2C.
This means the call graph is available when wrapper detection runs.
The wrapper resolution index is produced as output and can be consumed
by subsequent call graph refinement passes.

---

## 17. Integration with DNA System

The DNA system (System 22) consumes wrapper data as a convention signal.

### What DNA Reads

| DNA Gene | Wrapper Data Used | How |
|----------|------------------|-----|
| Variant Handling | Wrapper patterns around state management | Convention signal |
| API Response Format | Wrapper patterns around data fetching | Convention signal |
| Error Response Format | Wrapper patterns around error handling | Convention signal |

### Interface

```rust
/// Data provided to DNA system for convention analysis.
pub struct WrapperConventionData {
    pub dominant_framework: Framework,
    pub category_distribution: Vec<CategoryCount>,
    pub top_wrappers: Vec<WrapperInfo>,  // Top 10 by usage
    pub health_score: f32,
}
```

---

## 18. Integration with Quality Gates

Wrapper health feeds into quality gate evaluation.

### Gate Input

```rust
/// Input for wrapper-related quality gate checks.
pub struct WrapperGateInput {
    pub health_score: f32,
    pub total_wrappers: u32,
    pub low_confidence_count: u32,      // Wrappers with confidence < 0.6
    pub deep_wrapper_count: u32,        // Wrappers with depth > 2
    pub unclustered_count: u32,         // Wrappers not in any cluster
    pub unused_exported_count: u32,     // Exported wrappers with 0 usage
}
```

### Gate Rules

| Rule | Threshold | Severity |
|------|-----------|----------|
| Wrapper health below warning | health < 60 | Warning |
| Wrapper health below critical | health < 40 | Error |
| Deep wrapper chains | depth > 3 | Warning |
| Unused exported wrappers | usage = 0 AND exported | Info |
| Low confidence wrappers | confidence < 0.6 | Info |

---

## 19. Integration with Constraint System

Wrapper patterns can be mined as architectural constraints.

### Constraint Types from Wrappers

| Constraint | Example | Invariant Type |
|-----------|---------|----------------|
| "All data fetching must use useApi wrapper" | `must_use_wrapper("useApi", DataFetching)` | `must_use` |
| "No direct useState in components" | `must_not_call("useState", "components/**")` | `must_not_use` |
| "All auth calls must go through useAuth" | `must_use_wrapper("useAuth", Authentication)` | `must_use` |

### Interface

```rust
/// Wrapper patterns available for constraint mining.
pub struct WrapperConstraintData {
    pub dominant_wrappers: Vec<WrapperInfo>,     // High-usage, high-confidence
    pub wrapper_categories: Vec<WrapperCategory>, // Categories with wrappers
    pub framework: Framework,
}
```

---

## 20. Integration with Context Generation

Wrapper data is included in AI context at multiple detail levels.

### Context Levels (Matching DNA System Pattern)

| Level | Tokens | Content |
|-------|--------|---------|
| 1 | ~20 | "Project uses 15 React wrappers (health: 82/100)" |
| 2 | ~200 | Table: category, count, top wrapper, usage |
| 3 | ~500-1500 | Full wrapper list with clusters and code examples |
| 4 | Unlimited | Raw JSON (WrappersResult) |

### Interface

```rust
/// Wrapper context data for AI context generation.
pub struct WrapperContextData {
    pub level: u8,
    pub content: String,
}

impl WrapperContextData {
    pub fn generate(result: &WrappersResult, level: u8) -> Self {
        let content = match level {
            1 => format!(
                "Project uses {} {:?} wrappers (health: {:.0}/100)",
                result.stats.total_wrappers,
                result.framework_breakdown.first()
                    .map(|f| f.framework)
                    .unwrap_or(Framework::Generic),
                result.health_score,
            ),
            2 => Self::generate_table(result),
            3 => DocExporter::export_markdown(result),
            4 => DocExporter::export_json(result).unwrap_or_default(),
            _ => String::new(),
        };
        Self { level, content }
    }

    fn generate_table(result: &WrappersResult) -> String {
        let mut table = String::from("| Category | Count | Top Wrapper | Usage |\n");
        table.push_str("|----------|-------|-------------|-------|\n");
        // Group by category, show top wrapper per category
        for cat_count in &result.stats.by_category {
            let top = result.wrappers.iter()
                .filter(|w| w.category == cat_count.category)
                .max_by_key(|w| w.usage_count);
            if let Some(top_w) = top {
                table.push_str(&format!(
                    "| {:?} | {} | {} | {} |\n",
                    cat_count.category, cat_count.count,
                    top_w.name, top_w.usage_count,
                ));
            }
        }
        table
    }
}
```

---

## 21. Integration with Cortex Grounding (D7)

Per PLANNING-DRIFT.md D7, Drift analysis results serve as grounding signals for
Cortex memories. Wrapper patterns are a lightweight grounding signal.

### Grounding Data

```rust
/// Wrapper data for Cortex grounding (D7).
pub struct WrapperGroundingData {
    pub framework: Framework,
    pub health_score: f32,
    pub wrapper_count: u32,
    pub top_patterns: Vec<String>,  // e.g., ["useAuth wraps useState+useEffect", ...]
}
```

This is consumed by the cortex-drift-bridge crate (optional, per D4).


---

## 22. Storage Schema (drift.db Wrapper Tables)

Per 02-STORAGE-V2-PREP.md and 08-storage/sqlite-schema.md, wrapper data persists
in drift.db with 4 STRICT tables.

### Table: wrappers

```sql
CREATE TABLE wrappers (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    file        TEXT NOT NULL,
    line        INTEGER NOT NULL,
    wraps       TEXT NOT NULL,          -- JSON array of primitive names
    category    TEXT NOT NULL,          -- WrapperCategory enum value
    framework   TEXT NOT NULL,          -- Framework enum value
    is_exported INTEGER NOT NULL DEFAULT 0,
    usage_count INTEGER NOT NULL DEFAULT 0,
    confidence  REAL NOT NULL,
    imports     TEXT NOT NULL DEFAULT '[]',  -- JSON array of import sources
    depth       INTEGER NOT NULL DEFAULT 1,
    content_hash TEXT NOT NULL,
    updated_at  INTEGER NOT NULL,
    UNIQUE(file, name, line)
) STRICT;

CREATE INDEX idx_wrappers_file ON wrappers(file);
CREATE INDEX idx_wrappers_category ON wrappers(category);
CREATE INDEX idx_wrappers_framework ON wrappers(framework);
CREATE INDEX idx_wrappers_confidence ON wrappers(confidence);
CREATE INDEX idx_wrappers_usage ON wrappers(usage_count DESC);
CREATE INDEX idx_wrappers_updated ON wrappers(updated_at);
```

### Table: wrapper_clusters

```sql
CREATE TABLE wrapper_clusters (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    category        TEXT NOT NULL,
    total_usage     INTEGER NOT NULL DEFAULT 0,
    similarity_score REAL NOT NULL DEFAULT 0.0,
    health          REAL NOT NULL DEFAULT 0.0,
    description     TEXT NOT NULL DEFAULT '',
    updated_at      INTEGER NOT NULL
) STRICT;

CREATE INDEX idx_wrapper_clusters_category ON wrapper_clusters(category);
CREATE INDEX idx_wrapper_clusters_usage ON wrapper_clusters(total_usage DESC);
```

### Table: wrapper_cluster_members

```sql
CREATE TABLE wrapper_cluster_members (
    cluster_id  TEXT NOT NULL REFERENCES wrapper_clusters(id) ON DELETE CASCADE,
    wrapper_id  TEXT NOT NULL REFERENCES wrappers(id) ON DELETE CASCADE,
    PRIMARY KEY (cluster_id, wrapper_id)
) STRICT;

CREATE INDEX idx_wcm_wrapper ON wrapper_cluster_members(wrapper_id);
```

### Table: wrapper_analysis_runs

```sql
CREATE TABLE wrapper_analysis_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at      INTEGER NOT NULL,
    completed_at    INTEGER,
    files_analyzed  INTEGER NOT NULL DEFAULT 0,
    wrappers_found  INTEGER NOT NULL DEFAULT 0,
    clusters_found  INTEGER NOT NULL DEFAULT 0,
    health_score    REAL,
    duration_ms     INTEGER,
    incremental     INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'running'
) STRICT;

CREATE INDEX idx_war_started ON wrapper_analysis_runs(started_at DESC);
```

### Storage Implementation

```rust
pub struct WrapperStorage;

impl WrapperStorage {
    /// Batch upsert wrappers using the batch writer pattern.
    pub fn upsert_wrappers(
        db: &DatabaseManager,
        wrappers: &[WrapperInfo],
    ) -> Result<(), WrapperError> {
        db.batch_write(|tx| {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO wrappers (id, name, file, line, wraps, category, framework,
                 is_exported, usage_count, confidence, imports, depth, content_hash, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                 ON CONFLICT(file, name, line) DO UPDATE SET
                 wraps = excluded.wraps, category = excluded.category,
                 framework = excluded.framework, is_exported = excluded.is_exported,
                 usage_count = excluded.usage_count, confidence = excluded.confidence,
                 imports = excluded.imports, depth = excluded.depth,
                 content_hash = excluded.content_hash, updated_at = excluded.updated_at"
            )?;

            for w in wrappers {
                stmt.execute(rusqlite::params![
                    w.id, w.name, w.file, w.line,
                    serde_json::to_string(&w.wraps).unwrap_or_default(),
                    format!("{:?}", w.category),
                    format!("{:?}", w.framework),
                    w.is_exported as i32,
                    w.usage_count,
                    w.confidence,
                    serde_json::to_string(&w.imports).unwrap_or_default(),
                    w.depth,
                    w.content_hash,
                    w.updated_at,
                ])?;
            }
            Ok(())
        })?;
        Ok(())
    }

    /// Delete wrappers for removed files.
    pub fn delete_wrappers_for_files(
        db: &DatabaseManager,
        files: &[String],
    ) -> Result<(), WrapperError> {
        if files.is_empty() {
            return Ok(());
        }
        db.batch_write(|tx| {
            let placeholders: String = files.iter()
                .enumerate()
                .map(|(i, _)| format!("?{}", i + 1))
                .collect::<Vec<_>>()
                .join(",");
            tx.execute(
                &format!("DELETE FROM wrappers WHERE file IN ({})", placeholders),
                rusqlite::params_from_iter(files),
            )?;
            Ok(())
        })?;
        Ok(())
    }

    /// Query wrappers with filters and keyset pagination.
    pub fn query_wrappers(
        db: &DatabaseManager,
        filter: &WrapperFilter,
    ) -> Result<PaginatedResult<WrapperInfo>, WrapperError> {
        // Build WHERE clause from filter
        let mut conditions = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(ref category) = filter.category {
            conditions.push("category = ?");
            params.push(Box::new(format!("{:?}", category)));
        }
        if let Some(ref framework) = filter.framework {
            conditions.push("framework = ?");
            params.push(Box::new(format!("{:?}", framework)));
        }
        if let Some(min_confidence) = filter.min_confidence {
            conditions.push("confidence >= ?");
            params.push(Box::new(min_confidence));
        }
        if let Some(ref file_pattern) = filter.file_pattern {
            conditions.push("file GLOB ?");
            params.push(Box::new(file_pattern.clone()));
        }
        if let Some(ref cursor) = filter.cursor {
            conditions.push("id > ?");
            params.push(Box::new(cursor.clone()));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let limit = filter.limit.unwrap_or(50).min(100);
        let sql = format!(
            "SELECT * FROM wrappers {} ORDER BY id LIMIT {}",
            where_clause, limit + 1,
        );

        // Execute and build paginated result
        // ... (standard keyset pagination pattern from 02-STORAGE-V2-PREP.md)
        todo!("Implementation follows standard keyset pagination pattern")
    }
}

/// Filter for wrapper queries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub struct WrapperFilter {
    pub category: Option<WrapperCategory>,
    pub framework: Option<Framework>,
    pub min_confidence: Option<f32>,
    pub file_pattern: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}

/// Filter for cluster queries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub struct ClusterFilter {
    pub category: Option<WrapperCategory>,
    pub min_usage: Option<u32>,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}
```

---

## 23. NAPI Interface

Per 03-NAPI-BRIDGE-V2-PREP.md §10.10, wrapper detection is exposed via the
`bindings/structural.rs` module alongside coupling and constants analysis.

### Exported Functions (4)

| Function | Sync/Async | Returns | Description |
|----------|-----------|---------|-------------|
| `analyze_wrappers(root, options?)` | Async | `WrappersSummary` | Full wrapper analysis |
| `query_wrappers(filter)` | Sync | `PaginatedResult<WrapperInfo>` | Query wrappers with filters |
| `query_wrapper_clusters(filter)` | Sync | `PaginatedResult<WrapperCluster>` | Query clusters |
| `query_wrapper_detail(id)` | Sync | `WrapperDetail` | Full wrapper with usage data |

### Implementation

```rust
use napi::bindgen_prelude::*;
use napi_derive::napi;

#[napi(object)]
pub struct WrapperOptions {
    pub incremental: Option<bool>,
    pub enable_usage_counting: Option<bool>,
    pub enable_clustering: Option<bool>,
    pub frameworks: Option<Vec<String>>,
    pub min_confidence: Option<f64>,
}

pub struct AnalyzeWrappersTask {
    root: String,
    options: Option<WrapperOptions>,
}

#[napi]
impl Task for AnalyzeWrappersTask {
    type Output = WrappersSummary;
    type JsValue = WrappersSummary;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let rt = crate::runtime::get()?;
        let root = PathBuf::from(&self.root);

        let config = self.build_config(&rt.config);
        let call_graph = rt.call_graph_db.as_ref();

        drift_core::wrappers::analyze(&root, &config, &rt.db, call_graph)
            .map_err(crate::errors::to_napi_error)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(output)
    }
}

#[napi]
pub fn analyze_wrappers(
    root: String,
    options: Option<WrapperOptions>,
) -> AsyncTask<AnalyzeWrappersTask> {
    AsyncTask::new(AnalyzeWrappersTask { root, options })
}

#[napi]
pub fn query_wrappers(filter: WrapperFilter) -> napi::Result<serde_json::Value> {
    let rt = crate::runtime::get()?;
    let result = drift_core::wrappers::query_wrappers(&filter, &rt.db)
        .map_err(crate::errors::to_napi_error)?;
    serde_json::to_value(&result)
        .map_err(|e| napi::Error::from_reason(format!("[INTERNAL_ERROR] {e}")))
}

#[napi]
pub fn query_wrapper_clusters(filter: ClusterFilter) -> napi::Result<serde_json::Value> {
    let rt = crate::runtime::get()?;
    let result = drift_core::wrappers::query_clusters(&filter, &rt.db)
        .map_err(crate::errors::to_napi_error)?;
    serde_json::to_value(&result)
        .map_err(|e| napi::Error::from_reason(format!("[INTERNAL_ERROR] {e}")))
}

#[napi]
pub fn query_wrapper_detail(id: String) -> napi::Result<serde_json::Value> {
    let rt = crate::runtime::get()?;
    let result = drift_core::wrappers::query_detail(&id, &rt.db)
        .map_err(crate::errors::to_napi_error)?;
    serde_json::to_value(&result)
        .map_err(|e| napi::Error::from_reason(format!("[INTERNAL_ERROR] {e}")))
}
```

### Error Code Integration

```rust
impl DriftErrorCode for WrapperError {
    fn error_code(&self) -> &'static str {
        match self {
            WrapperError::Registry(_) => codes::ANALYSIS_ERROR,
            WrapperError::Detection { .. } => codes::DETECTION_ERROR,
            WrapperError::Clustering(_) => codes::ANALYSIS_ERROR,
            WrapperError::CallGraphUnavailable(_) => codes::CALL_GRAPH_ERROR,
            WrapperError::Storage(_) => codes::STORAGE_ERROR,
            WrapperError::Config(_) => codes::CONFIG_ERROR,
            WrapperError::Export(_) => codes::ANALYSIS_ERROR,
        }
    }
}
```


---

## 24. MCP Tool Interface (drift_wrappers — 4 Actions)

Per 07-mcp/tools-by-category.md, `drift_wrappers` is in the analysis category
with ~500-1500 tokens. V2 expands to 4 actions.

### Tool Definition

```json
{
  "name": "drift_wrappers",
  "description": "Analyze framework wrapper functions — thin delegation patterns around React hooks, Vue composables, Angular services, Express middleware, and other framework primitives. Detects wrappers, clusters related ones, counts cross-file usage, and scores wrapper health.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "action": {
        "type": "string",
        "enum": ["list", "detail", "clusters", "health"],
        "description": "Action to perform"
      },
      "category": {
        "type": "string",
        "enum": ["StateManagement", "SideEffects", "DataFetching", "Validation", "Logging", "Authentication", "Caching", "ErrorHandling", "FormHandling", "Routing", "Factory", "Middleware", "Testing", "Internationalization", "Rendering", "Other"],
        "description": "Filter by wrapper category"
      },
      "framework": {
        "type": "string",
        "enum": ["React", "Vue", "Angular", "Svelte", "SolidJS", "Express", "NextJS", "Generic"],
        "description": "Filter by framework"
      },
      "name": {
        "type": "string",
        "description": "Wrapper name for detail action"
      },
      "limit": {
        "type": "number",
        "description": "Max results (default: 20, max: 50)"
      }
    },
    "required": ["action"]
  }
}
```

### Action Responses

**list** (~500-1500 tokens):
```json
{
  "wrappers": [
    {
      "name": "useAuth",
      "file": "src/hooks/useAuth.ts",
      "wraps": ["useState", "useEffect"],
      "category": "Authentication",
      "framework": "React",
      "usage": 23,
      "confidence": 0.92
    }
  ],
  "total": 15,
  "health_score": 82
}
```

**detail** (~200-500 tokens):
```json
{
  "name": "useAuth",
  "file": "src/hooks/useAuth.ts",
  "line": 5,
  "wraps": ["useState", "useEffect"],
  "category": "Authentication",
  "framework": "React",
  "is_exported": true,
  "usage_count": 23,
  "confidence": 0.92,
  "depth": 1,
  "callers": ["LoginPage", "ProtectedRoute", "Header"],
  "cluster": "Authentication wrappers (useState)"
}
```

**clusters** (~300-800 tokens):
```json
{
  "clusters": [
    {
      "name": "DataFetching wrappers (useQuery)",
      "category": "DataFetching",
      "members": 4,
      "total_usage": 47,
      "health": 88,
      "description": "4 data fetching wrappers around useQuery, used 47 times across 12 files"
    }
  ],
  "total": 6
}
```

**health** (~200-400 tokens):
```json
{
  "health_score": 82,
  "consistency": 0.85,
  "confidence": 0.78,
  "coverage": 0.73,
  "abstraction": 0.91,
  "total_wrappers": 15,
  "framework": "React",
  "recommendations": [
    "Consider consolidating 3 low-usage DataFetching wrappers",
    "2 exported wrappers have 0 cross-file usage"
  ]
}
```

---

## 25. CLI Interface (drift wrappers — 4 Subcommands)

V1 has a single `drift wrappers` command with `--json` and `-v` flags.
V2 expands to 4 subcommands.

### Command Structure

```
drift wrappers                    # List wrappers (default action)
drift wrappers list               # List wrappers with filters
drift wrappers clusters           # Show wrapper clusters
drift wrappers detail <name>      # Wrapper detail view
drift wrappers health             # Wrapper health report
```

### Flags

| Subcommand | Flag | Type | Default | Description |
|-----------|------|------|---------|-------------|
| list | `--category` | string | all | Filter by category |
| list | `--framework` | string | all | Filter by framework |
| list | `--min-confidence` | number | 0.5 | Minimum confidence |
| list | `--sort` | string | usage | Sort: usage, confidence, name |
| list | `--json` | boolean | false | JSON output |
| list | `-v, --verbose` | boolean | false | Verbose output |
| clusters | `--category` | string | all | Filter by category |
| clusters | `--json` | boolean | false | JSON output |
| detail | `<name>` | argument | required | Wrapper function name |
| detail | `--json` | boolean | false | JSON output |
| health | `--json` | boolean | false | JSON output |

### Example Output

```
$ drift wrappers

  Wrapper Detection — 15 wrappers across 8 files

  Framework: React (12) | Next.js (3)
  Health Score: 82/100

  ┌──────────────────┬────────────────┬──────────────────┬───────┬────────────┐
  │ Wrapper          │ Category       │ Wraps            │ Usage │ Confidence │
  ├──────────────────┼────────────────┼──────────────────┼───────┼────────────┤
  │ useAuth          │ Authentication │ useState, useEff │    23 │       92%  │
  │ useApi           │ DataFetching   │ useQuery         │    18 │       88%  │
  │ useForm          │ FormHandling   │ useForm          │    15 │       95%  │
  │ useToast         │ SideEffects    │ useState, useEff │    12 │       85%  │
  │ withErrorBound   │ ErrorHandling  │ ErrorBoundary    │     8 │       78%  │
  └──────────────────┴────────────────┴──────────────────┴───────┴────────────┘

  6 clusters detected. Run `drift wrappers clusters` for details.
```

---

## 26. Event Interface

Per PLANNING-DRIFT.md D5, wrapper lifecycle events emit via `DriftEventHandler`.

### Events

```rust
/// Wrapper-related events emitted during analysis.
pub enum WrapperEvent {
    /// Analysis started
    AnalysisStarted {
        files_to_analyze: u32,
        incremental: bool,
    },
    /// Analysis completed
    AnalysisCompleted {
        wrappers_found: u32,
        clusters_found: u32,
        health_score: f32,
        duration_ms: u64,
    },
    /// New wrapper detected (not seen before)
    WrapperDetected {
        name: String,
        file: String,
        category: WrapperCategory,
        framework: Framework,
        confidence: f32,
    },
    /// Wrapper removed (file deleted or function removed)
    WrapperRemoved {
        name: String,
        file: String,
    },
    /// Health score changed significantly (>5 points)
    HealthChanged {
        previous: f32,
        current: f32,
        delta: f32,
    },
}
```

### Event Handler Integration

```rust
impl WrapperEngine {
    fn emit_event(&self, event: WrapperEvent, handlers: &[Arc<dyn DriftEventHandler>]) {
        for handler in handlers {
            handler.on_wrapper_event(&event);
        }
    }
}
```

---

## 27. Tracing & Observability

Per 04-INFRASTRUCTURE-V2-PREP.md, all subsystems use the `tracing` crate.

### Spans

```rust
use tracing::{info_span, instrument, debug, info, warn};

#[instrument(skip(config, db, call_graph), fields(root = %root.display()))]
pub fn analyze(
    root: &Path,
    config: &WrapperConfig,
    db: &DatabaseManager,
    call_graph: Option<&CallGraphDb>,
) -> Result<WrappersSummary, WrapperError> {
    let _span = info_span!("wrapper_analysis").entered();

    // Phase 1: Registry compilation
    let _reg_span = info_span!("registry_compilation").entered();
    let registry = PrimitiveRegistry::new(config)?;
    debug!(primitives = registry.len(), "Registry compiled");
    drop(_reg_span);

    // Phase 2: Detection
    let _det_span = info_span!("wrapper_detection").entered();
    // ... detection logic
    info!(wrappers = count, "Detection complete");
    drop(_det_span);

    // Phase 3: Usage counting
    let _usage_span = info_span!("usage_counting").entered();
    // ... usage counting
    drop(_usage_span);

    // Phase 4: Clustering
    let _cluster_span = info_span!("wrapper_clustering").entered();
    // ... clustering
    drop(_cluster_span);

    // Phase 5: Health scoring
    let _health_span = info_span!("health_scoring").entered();
    // ... health calculation
    drop(_health_span);

    // Phase 6: Persistence
    let _persist_span = info_span!("wrapper_persistence").entered();
    // ... write to drift.db
    drop(_persist_span);

    Ok(summary)
}
```

### Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `wrapper.analysis.duration_ms` | Histogram | Total analysis time |
| `wrapper.detection.duration_ms` | Histogram | Detection phase time |
| `wrapper.clustering.duration_ms` | Histogram | Clustering phase time |
| `wrapper.count` | Gauge | Total wrappers detected |
| `wrapper.cluster_count` | Gauge | Total clusters |
| `wrapper.health_score` | Gauge | Current health score |
| `wrapper.files_analyzed` | Counter | Files processed |
| `wrapper.cache_hits` | Counter | Incremental cache hits |


---

## 28. Performance Targets & Benchmarks

### Targets

| Metric | Target | Rationale |
|--------|--------|-----------|
| Detection (1K files) | < 200ms | Per-file detection is lightweight |
| Detection (10K files) | < 1.5s | Rayon parallelism + RegexSet |
| Detection (50K files) | < 5s | Incremental skips unchanged |
| Usage counting (1K wrappers) | < 100ms | Call graph queries are indexed |
| Clustering (500 wrappers) | < 50ms | In-memory, no I/O |
| Health scoring | < 5ms | Pure computation |
| Full pipeline (10K files) | < 2s | All phases combined |
| Incremental (100 changed) | < 200ms | Only re-analyze changed files |
| Memory (10K files) | < 50MB | ParseResults are shared, not copied |

### Benchmark Strategy

```rust
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_detection(c: &mut Criterion) {
    let registry = PrimitiveRegistry::new(&WrapperConfig::default()).unwrap();
    let parse_results = load_test_parse_results(); // 1K files

    c.bench_function("detect_1k_files", |b| {
        b.iter(|| {
            for (path, result) in &parse_results {
                detect_wrappers_in_file(path, result, &registry, &config);
            }
        })
    });
}

fn bench_clustering(c: &mut Criterion) {
    let wrappers = generate_test_wrappers(500);

    c.bench_function("cluster_500_wrappers", |b| {
        b.iter(|| WrapperClusterer::cluster(&wrappers))
    });
}

fn bench_regex_set(c: &mut Criterion) {
    let registry = PrimitiveRegistry::new(&WrapperConfig::default()).unwrap();
    let call_targets: Vec<String> = generate_test_call_targets(10_000);

    c.bench_function("regex_set_10k_calls", |b| {
        b.iter(|| {
            for target in &call_targets {
                registry.match_call(target);
            }
        })
    });
}

criterion_group!(benches, bench_detection, bench_clustering, bench_regex_set);
criterion_main!(benches);
```

---

## 29. Build Order & Dependencies

### Dependency Graph

```
drift-core/src/wrappers/ depends on:
├── drift-core/src/errors/          # WrapperError, StorageError
├── drift-core/src/config/          # WrapperConfig from drift.toml
├── drift-core/src/unified/         # ParseResult (functions, calls, imports)
├── drift-core/src/call_graph/      # CallGraphDb (optional, for usage counting)
├── drift-core/src/storage/         # DatabaseManager (drift.db)
└── drift-core/src/infrastructure/  # tracing, events, FxHashMap
```

### Build Order (Within Wrapper Module)

```
Phase 1 (no internal deps):
  1. types.rs       — All types (WrapperInfo, WrapperCluster, etc.)
  2. errors.rs      — WrapperError enum
  3. config.rs      — WrapperConfig

Phase 2 (depends on Phase 1):
  4. registry.rs    — PrimitiveRegistry (depends on types, config)
  5. confidence.rs  — ConfidenceScorer (depends on types)
  6. classifier.rs  — CategoryClassifier (depends on types)

Phase 3 (depends on Phase 2):
  7. detector.rs    — WrapperDetector (depends on registry, confidence, classifier)
  8. usage.rs       — UsageCounter (depends on types, call_graph)
  9. storage.rs     — WrapperStorage (depends on types, errors)

Phase 4 (depends on Phase 3):
  10. clusterer.rs  — WrapperClusterer (depends on types)
  11. health.rs     — HealthCalculator (depends on types)
  12. export.rs     — DocExporter (depends on types)

Phase 5 (depends on all):
  13. engine.rs     — WrapperEngine (orchestrates everything)
  14. mod.rs        — Module exports
```

### External Crate Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `regex` | 1.x | RegexSet for primitive matching |
| `sha2` | 0.10 | SHA-256 for deterministic IDs |
| `hex` | 0.4 | Hex encoding for IDs |
| `serde` | 1.x | Serialization (derive) |
| `serde_json` | 1.x | JSON for NAPI + storage |
| `thiserror` | 1.x | Error enum derivation |
| `tracing` | 0.1 | Observability spans |
| `rustc-hash` | 1.x | FxHashMap/FxHashSet |
| `rayon` | 1.x | Parallel file processing |

All crates are already dependencies of drift-core (no new additions needed).

---

## 30. V1 → V2 Feature Cross-Reference

Complete mapping ensuring zero feature loss.

| V1 Feature | V1 Location | V2 Location | Status |
|-----------|-------------|-------------|--------|
| WrapperDetector | Rust detector.rs | Rust detector.rs | UPGRADED |
| WrapperClusterer | Rust clusterer.rs | Rust clusterer.rs | UPGRADED |
| WrappersAnalyzer | Rust analyzer.rs | Rust engine.rs | UPGRADED |
| WrapperInfo (8 fields) | Rust types.rs | Rust types.rs (14 fields) | EXPANDED |
| WrapperCluster (4 fields) | Rust types.rs | Rust types.rs (8 fields) | EXPANDED |
| WrappersResult (3 fields) | Rust types.rs | Rust types.rs (5 fields) | EXPANDED |
| WrappersStats (6 fields) | Rust types.rs | Rust types.rs (10 fields) | EXPANDED |
| WrapperCategory (12 variants) | Rust types.rs | Rust types.rs (16 variants) | EXPANDED |
| Confidence scoring (5 signals) | Rust detector.rs | Rust confidence.rs (7 signals) | UPGRADED |
| Primitive registry (6 cat, ~20) | Rust detector.rs | Rust registry.rs (8 fw, 150+) | EXPANDED |
| Name-based fallback (10 rules) | Rust detector.rs | Rust classifier.rs (16 rules) | EXPANDED |
| Call extraction (linear) | Rust detector.rs | Rust detector.rs (binary search) | OPTIMIZED |
| Primitive matching (sequential) | Rust detector.rs | Rust registry.rs (RegexSet) | OPTIMIZED |
| NAPI analyze_wrappers | NAPI binding | NAPI structural.rs | UPGRADED |
| TS cross-file usage | TS detection/ | Rust usage.rs | MOVED TO RUST |
| TS clustering | TS clustering/ | Rust clusterer.rs | MOVED TO RUST |
| TS primitive registries | TS primitives/ | Rust registry.rs | MOVED TO RUST |
| TS documentation export | TS export/ | Rust export.rs | MOVED TO RUST |
| TS pattern store integration | TS integration/ | Rust storage.rs (SQLite) | REPLACED |
| MCP drift_wrappers | TS wrappers.ts | TS wrappers.ts (thin NAPI caller) | UPGRADED |
| CLI drift wrappers | TS wrappers.ts | TS wrappers.ts (thin NAPI caller) | UPGRADED |

**Zero features dropped. All v1 capabilities preserved or upgraded.**

---

## 31. Inconsistencies & Decisions

### I1: One Wrapper Per Function vs Multi-Primitive

**Source**: V1 `detector.rs` breaks after first primitive match. V1 `WrapperInfo.wraps`
is `Vec<String>` (supports multiple) but only ever has one entry.

**Resolution**: V2 records all matched primitives. The `wraps` field genuinely contains
multiple entries. This is more accurate — `useAuthForm()` wrapping both `useState` and
`useForm` should record both.

### I2: Clustering Algorithm Undocumented

**Source**: V1 `clusterer.rs` exists but the algorithm is not documented in any
research doc. The RECAP notes "Clustering algorithm undocumented."

**Resolution**: V2 fully specifies the algorithm in §10. Category + primitive grouping
with Jaccard similarity refinement. This is a clean design that matches the v1 intent
(group related wrappers) while being fully specified.

### I3: Usage Count Always 0 in Rust

**Source**: V1 Rust sets `usage_count = 0` for all wrappers. TS layer fills it.

**Resolution**: V2 Rust fills usage_count via call graph integration (§9). Graceful
degradation to 0 if call graph unavailable. The `WrappersSummary` includes a
`usage_counting_available` flag.

### I4: Primitive Registry Expansion Priority

**Source**: MASTER-AUDIT RC-G12 and AN-G7 flag React-only registry. Audit question #8
asks "What's the priority order for Vue/Angular/Svelte/Express primitives?"

**Resolution**: V2 includes all 8 frameworks from day one. Priority order for
implementation: React (largest user base) → Vue → Next.js → Express → Angular →
Svelte → SolidJS → Generic. But all are specified in §5 and should be implemented
together since they're just data (primitive entries), not logic.

### I5: TOML-Configurable Primitives

**Source**: Audit question #8 asks "Should the primitive registry be configurable/extensible?"

**Resolution**: Yes. V2 supports `custom_primitives` in `WrapperConfig` loaded from
`drift.toml` `[wrappers]` section. Teams can add project-specific primitives without
modifying Drift source code.

### I6: Wrapper Detection vs Pattern Detection Overlap

**Source**: Both wrapper detection and pattern detection analyze function behavior.
Could they overlap?

**Resolution**: They serve different purposes. Pattern detection identifies recurring
code patterns (naming conventions, import patterns, etc.). Wrapper detection specifically
identifies delegation to known framework primitives. They are complementary — a wrapper
IS a pattern, but not all patterns are wrappers. Wrapper detection feeds into pattern
detection as a signal, not a replacement.

### I7: WrapperCategory Expansion

**Source**: V1 has 12 categories. V2 needs to cover Express middleware, testing utilities,
i18n, and SSR patterns.

**Resolution**: V2 adds 4 categories: Middleware, Testing, Internationalization, Rendering.
The `Other` category remains as catch-all. Total: 16 categories.

### I8: Batch API Integration

**Source**: 03-NAPI-BRIDGE-V2-PREP.md §9 includes `AnalysisType::Wrappers` in the batch
API but `BatchResult` doesn't have a `wrappers` field.

**Resolution**: Add `wrappers: Option<WrappersSummary>` to `BatchResult`. The batch API
runs wrapper detection after parsing (Phase 3), sharing the same `parse_results`.

---

## 32. Risk Register

| # | Risk | Likelihood | Impact | Mitigation |
|---|------|-----------|--------|------------|
| R1 | RegexSet compilation slow for 150+ patterns | Low | Medium | Compile once at registry creation, cache in `PrimitiveRegistry` |
| R2 | False positives from expanded registry | Medium | Low | Configurable min_confidence, framework filtering |
| R3 | Call graph unavailable during first scan | High | Low | Graceful degradation (usage_count = 0), flag in summary |
| R4 | Wrapper depth calculation cycles | Low | Medium | Cycle detection + depth cap at 5 |
| R5 | Large projects (50K+ files) slow detection | Low | Medium | Rayon parallelism + incremental analysis |
| R6 | Custom TOML primitives conflict with built-in | Low | Low | Custom primitives override built-in (last wins) |
| R7 | Framework auto-detection incorrect | Medium | Low | Fallback to Generic, user can override in config |
| R8 | Clustering produces too many single-member clusters | Medium | Low | Minimum cluster size configurable, merge small clusters |
| R9 | Health score not meaningful for small projects | Medium | Low | Minimum wrapper count threshold (< 3 wrappers → skip health) |
| R10 | Vue/Svelte template syntax not parsed by tree-sitter | Medium | Medium | Rely on `<script>` block parsing; template wrappers are rare |

---

## End of Document

This document contains everything needed to build the Wrapper Detection subsystem
from scratch. Every v1 feature is accounted for. Every algorithm is specified.
Every type is defined. Every integration point is documented. Every architectural
decision is resolved.

The wrapper detection system is the lowest-impact Level 2C analysis, but it provides
unique value: understanding how teams abstract framework primitives. V2 transforms it
from a React-only, single-file detector into a multi-framework, cross-file, health-scored
analysis engine that feeds call graph accuracy, DNA convention analysis, quality gates,
and AI context generation.

Build order: types → errors → config → registry → confidence → classifier → detector →
usage → storage → clusterer → health → export → engine → mod.
