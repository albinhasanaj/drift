# cortex-drift-bridge — Buildout Agent

> Precise gap analysis, phased task inventory, and execution playbook for
> bringing the bridge from its current ~40% implementation to the 100%
> architecture defined in `BRIDGE-100-PERCENT-ARCHITECTURE.md`.
>
> Generated: 2026-02-09 · Source of truth until superseded.

---

## Table of Contents

1. [Current State Audit](#1-current-state-audit)
2. [Gap Analysis Matrix](#2-gap-analysis-matrix)
3. [Phase Plan](#3-phase-plan)
4. [Phase 0 — Foundation Hardening](#4-phase-0--foundation-hardening)
5. [Phase 1 — Data Access Layer](#5-phase-1--data-access-layer)
6. [Phase 2 — Core Logic Completion](#6-phase-2--core-logic-completion)
7. [Phase 3 — Causal Intelligence Layer](#7-phase-3--causal-intelligence-layer)
8. [Phase 4 — Presentation Layer](#8-phase-4--presentation-layer)
9. [Phase 5 — Resilience & Observability](#9-phase-5--resilience--observability)
10. [Phase 6 — Test Buildout](#10-phase-6--test-buildout)
11. [Dependency Graph & Critical Path](#11-dependency-graph--critical-path)
12. [Verification Gates](#12-verification-gates)
13. [Risk Register](#13-risk-register)

---

## 1. Current State Audit

### What Exists (15 source files)

| Module | Files | Status | Notes |
|--------|-------|--------|-------|
| `lib.rs` | 1 | **Functional** | `BridgeRuntime` with init/shutdown, missing PRAGMAs |
| `errors.rs` | 1 | **Functional** | 12 variants, flat file (not errors/ directory) |
| `event_mapping/` | 3 | **Functional** | `mod.rs`, `mapper.rs` (21 handlers), `memory_types.rs` (21 mappings) |
| `link_translation/` | 2 | **Functional** | `mod.rs`, `translator.rs` (5 constructors + round-trip) |
| `grounding/` | 6 | **Functional** | `mod.rs`, `classification.rs`, `evidence.rs`, `loop_runner.rs`, `scheduler.rs`, `scorer.rs` |
| `specification/` | 7 | **Functional** | `mod.rs`, `corrections.rs`, `events.rs`, `narrative.rs`, `attribution.rs`, `weight_provider.rs`, `decomposition_provider.rs` |
| `intents/` | 2 | **Functional** | `mod.rs`, `extensions.rs` (10 intents) |
| `license/` | 2 | **Functional** | `mod.rs`, `gating.rs` (3-tier) |
| `storage/` | 2 | **Functional** | `mod.rs`, `tables.rs` (5 tables, CRUD, retention) |
| `tools/` | 4 | **Functional** | `drift_why`, `drift_memory_learn`, `drift_grounding_check` |
| `napi/` | 2 | **Functional** | `mod.rs`, `functions.rs` (15 functions) |

### What Exists (7 test files)

| File | Lines | Coverage |
|------|-------|----------|
| `event_mapping_test.rs` | 8487 | 21 event handlers |
| `grounding_test.rs` | 16623 | Loop runner, scorer, evidence |
| `hardening_test.rs` | 23962 | SQL injection, NaN, adversarial |
| `link_translation_test.rs` | 5785 | 5 constructors, round-trip |
| `spec_bridge_test.rs` | 17568 | Corrections, contracts, decomposition |
| `spec_integration_test.rs` | 16516 | Causal engine integration |
| `stress_test.rs` | 41339 | 100 modules, 500 corrections |

**Total existing**: 15 src files, 7 test files, ~32 files  
**Target**: ~128 src files, ~30 test files, 4 bench files = ~162 files  
**Gap**: ~96 src files, ~23 test files, 4 bench files = ~123 files to create

---

## 2. Gap Analysis Matrix

### Layer 0: Foundation

| Target Module | Current State | Gap | Priority |
|---------------|---------------|-----|----------|
| `errors/mod.rs` | Flat `errors.rs` (12 variants) | Refactor into directory: `bridge_error.rs`, `context.rs`, `recovery.rs`, `chain.rs` | P1 |
| `config/` (6 files) | Inline in `BridgeConfig` struct in `lib.rs` | **Entirely missing**: `bridge_config.rs`, `event_config.rs`, `grounding_config.rs`, `evidence_config.rs`, `validation.rs` | P1 |
| `types/` (7 files) | Inline in `grounding/mod.rs` | **Entirely missing**: separate files for `GroundingResult`, `GroundingSnapshot`, `ConfidenceAdjustment`, `GroundingVerdict`, `DataSource`, `EventProcessingResult` | P2 |
| `health/` (5 files) | Single `is_available()` bool | **Entirely missing**: `status.rs`, `checks.rs`, `readiness.rs`, `degradation.rs` | P2 |

### Layer 1: Data Access

| Target Module | Current State | Gap | Priority |
|---------------|---------------|-----|----------|
| `storage/schema.rs` | Inline SQL in `tables.rs` | Extract CREATE TABLE statements | P2 |
| `storage/migrations.rs` | None | **Missing**: PRAGMA user_version versioning | P1 |
| `storage/cortex_writer.rs` | Direct `store_memory()` to `bridge_memories` | **Missing**: Write through `IMemoryStorage` trait | P1 |
| `storage/retention.rs` | `apply_retention()` exists in `tables.rs` | Extract to own file | P3 |
| `storage/pragmas.rs` | **ZERO PRAGMAs set** | **CRITICAL**: `journal_mode=WAL`, `busy_timeout=5000`, etc. | P0 |
| `query/` (5 files) | None | **Entirely missing**: `attach.rs`, `drift_queries.rs`, `cortex_queries.rs`, `cross_db.rs` | P1 |

### Layer 2: Core Logic

| Target Module | Current State | Gap | Priority |
|---------------|---------------|-----|----------|
| `event_mapping/enrichment.rs` | None — events use only payload fields | **Missing**: Query drift.db at event time for full metadata | P1 |
| `event_mapping/dedup.rs` | None — no idempotency | **Missing**: Content-hash dedup with TTL | P1 |
| `event_mapping/cortex_handler.rs` | Not implemented | **Missing**: `BridgeCortexEventHandler` (bidirectional flow) | P2 |
| `event_mapping/memory_builder.rs` | Inline in `mapper.rs` (repetitive `BaseMemory{}`) | **Missing**: Builder pattern with `linked_files`, `linked_functions` | P2 |
| `link_translation/batch.rs` | Exists in `translator.rs::translate_all()` | Extract to own file | P3 |
| `link_translation/round_trip.rs` | Exists in `translator.rs` | Extract to own file | P3 |
| `grounding/evidence/` (13 files) | **Passive** — pre-populated `MemoryForGrounding` fields | **Missing**: 10 active collectors that query drift.db directly | P1 |
| `grounding/contradiction.rs` | `generates_contradiction` flag only — no memory created | **Missing**: Actual contradiction memory creation via cortex-core | P1 |
| `specification/weights/` (5 files) | Single `weight_provider.rs` | **Missing**: `decay.rs` (365-day half-life), `bounds.rs` (NaN/overflow), `persistence.rs` | P1 |
| `specification/decomposition/` (5 files) | Single `decomposition_provider.rs` with `LIKE '%boundary%'` | **Missing**: `dna_similarity.rs`, `structured_priors.rs`, `feedback_loop.rs` | P1 |
| `intents/resolver.rs` | Not implemented | **Missing**: Intent → data source mapping for context generation | P3 |

### Layer 3: Causal Intelligence

| Target Module | Current State | Gap | Priority |
|---------------|---------------|-----|----------|
| `causal/` (7 files) | `on_spec_corrected` uses `add_edge` + `narrative()` directly | **Entirely missing**: `edge_builder.rs`, `inference.rs`, `counterfactual.rs`, `intervention.rs`, `pruning.rs`, `narrative_builder.rs` | P1 |

### Layer 4: Presentation

| Target Module | Current State | Gap | Priority |
|---------------|---------------|-----|----------|
| `tools/drift_counterfactual.rs` | None | **Missing** | P2 |
| `tools/drift_intervention.rs` | None | **Missing** | P2 |
| `tools/drift_bridge_status.rs` | None | **Missing** | P2 |
| `tools/drift_grounding_report.rs` | None | **Missing** | P2 |
| `napi/` (11 files) | Single `functions.rs` (15 functions) | **Missing**: Split into domain files, add 5 new functions (total 20) | P2 |
| `metrics/` (7 files) | None | **Entirely missing**: counters, gauges, histograms, persistence, snapshot | P2 |
| `tracing/` (3 files) | Ad-hoc `info!`/`warn!` calls | **Entirely missing**: structured span definitions | P3 |

### Layer 5: Resilience

| Target Module | Current State | Gap | Priority |
|---------------|---------------|-----|----------|
| `resilience/` (5 files) | None | **Entirely missing**: `error_budget.rs`, `retry.rs`, `fallback.rs`, `recovery.rs`, `busy_timeout.rs` | P2 |

---

## 3. Phase Plan

```
Phase 0: Foundation Hardening ─────── 2-3 days ──► Gate: cargo check + existing tests pass
    │
Phase 1: Data Access Layer ────────── 3-4 days ──► Gate: PRAGMA verification + query tests
    │
Phase 2: Core Logic Completion ────── 5-7 days ──► Gate: active evidence + dedup + weights
    │                                                     (longest phase — grounding + spec)
Phase 3: Causal Intelligence ──────── 3-4 days ──► Gate: counterfactual + intervention tests
    │
Phase 4: Presentation ─────────────── 3-4 days ──► Gate: all 20 NAPI functions + 7 tools
    │
Phase 5: Resilience & Observability ─ 2-3 days ──► Gate: error budget + metrics + spans
    │
Phase 6: Test Buildout ────────────── 4-5 days ──► Gate: all test categories green
    │
    ▼
    DONE (22-30 working days total)
```

**Parallelization opportunities:**
- Phase 3 (causal) can start after Phase 2 grounding is done, overlapping with Phase 2 spec work
- Phase 4 (presentation) can start as Phase 3 wraps up
- Phase 5 (resilience) is fully parallelizable with Phase 4
- Phase 6 (tests) runs throughout but has a dedicated polish phase at the end

---

## 4. Phase 0 — Foundation Hardening

> **Goal**: Fix critical infrastructure gaps. Zero new features, just correctness.

### P0-01: Add SQLite PRAGMAs (CRITICAL)

**File**: Create `src/storage/pragmas.rs`

```rust
pub fn configure_connection(conn: &Connection) -> BridgeResult<()> {
    conn.execute_batch("
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA foreign_keys = ON;
        PRAGMA busy_timeout = 5000;
        PRAGMA cache_size = -8000;
        PRAGMA mmap_size = 268435456;
        PRAGMA temp_store = MEMORY;
    ")?;
    Ok(())
}
```

**Wire into**: `BridgeRuntime::initialize()` — call for every `Connection::open()`.

**Verification**: Query `PRAGMA journal_mode` after init → expect `"wal"`.

### P0-02: Refactor errors.rs → errors/ directory

- `errors/mod.rs` — re-exports
- `errors/bridge_error.rs` — move existing 12 variants
- `errors/context.rs` — `ErrorContext` struct (file, line, span attachment)
- `errors/recovery.rs` — `RecoveryAction` enum: `Retry`, `Fallback`, `Escalate`, `Ignore`
- `errors/chain.rs` — error chain builder for multi-step operations

**Constraint**: All existing `crate::errors::BridgeError` imports must keep working.

### P0-03: Extract config/ from lib.rs

- `config/mod.rs` — re-exports
- `config/bridge_config.rs` — move `BridgeConfig` from `lib.rs`
- `config/event_config.rs` — per-event enable/disable toggles (21 booleans)
- `config/grounding_config.rs` — move `GroundingConfig` from `grounding/mod.rs`
- `config/evidence_config.rs` — per-evidence-type weight overrides
- `config/validation.rs` — reject invalid config combos at startup

**Constraint**: `BridgeConfig` keeps same public API. `GroundingConfig` re-exported from both old and new location.

### P0-04: Extract types/ from grounding/mod.rs

- `types/mod.rs` — re-exports
- `types/grounding_result.rs` — move `GroundingResult`
- `types/grounding_snapshot.rs` — move `GroundingSnapshot`
- `types/confidence_adjustment.rs` — move `ConfidenceAdjustment` + `AdjustmentMode` (add `Set` variant)
- `types/grounding_verdict.rs` — move `GroundingVerdict` (add `Error` variant)
- `types/data_source.rs` — new `GroundingDataSource` enum (12 Drift subsystems)
- `types/event_processing_result.rs` — move from `event_mapping/memory_types.rs`

**Constraint**: Re-export from `grounding/mod.rs` for backward compatibility.

### P0-05: Create health/ module

- `health/mod.rs` — re-exports
- `health/status.rs` — `BridgeHealth` enum: `Available`, `Degraded(Vec<String>)`, `Unavailable`
- `health/checks.rs` — per-subsystem checks: cortex_db, drift_db, causal_engine
- `health/readiness.rs` — readiness probe: all subsystems initialized?
- `health/degradation.rs` — `DegradationTracker`: which features are degraded and why

### P0 Verification Gate

```bash
cargo check -p cortex-drift-bridge
cargo test -p cortex-drift-bridge -- --test-threads=1
```

All existing tests must pass. No new tests required in Phase 0.

---

## 5. Phase 1 — Data Access Layer

> **Goal**: Proper database access patterns. PRAGMAs on every connection, parameterized queries, ATTACH lifecycle.

### P1-01: storage/pragmas.rs integration

Wire `configure_connection()` into `BridgeRuntime::initialize()` for all three connections (cortex_db, drift_db, bridge_db).

### P1-02: storage/migrations.rs

Follow drift-core's `PRAGMA user_version` pattern:
- `BRIDGE_SCHEMA_V1` — current 5 tables
- `migrate()` — version check + apply
- Call in `BridgeRuntime::initialize()` after PRAGMAs

### P1-03: storage/cortex_writer.rs

Bridge opens its own `SqliteMemoryStorage` instance pointing at cortex.db.
- Wraps `IMemoryStorage::create()` / `update()` / `get()`
- Replaces direct `store_memory()` calls in `mapper.rs`, `events.rs`, `drift_memory_learn.rs`

### P1-04: query/ module (5 files)

- `query/mod.rs` — re-exports
- `query/attach.rs` — ATTACH/DETACH lifecycle with RAII guard (auto-detach on drop)
  - Read-only ATTACH for drift.db
  - Read-then-DETACH-then-write pattern (WAL atomicity caveat)
- `query/drift_queries.rs` — 10 parameterized read-only queries:
  1. Pattern confidence by pattern_id
  2. Occurrence rate by pattern_id
  3. False positive rate by pattern_id
  4. Constraint verification status
  5. Coupling metrics by module path
  6. DNA health by project
  7. Test coverage by module
  8. Error handling gaps by module
  9. Decision evidence score
  10. Boundary data score
- `query/cortex_queries.rs` — memory lookup, search, related-memory queries
- `query/cross_db.rs` — joined queries (ATTACH + read drift + read cortex)

### P1-05: Refactor storage/tables.rs

- Extract schema SQL to `storage/schema.rs`
- Extract retention to `storage/retention.rs`
- Keep `tables.rs` as CRUD-only operations

### P1 Verification Gate

```bash
# Test PRAGMA verification
cargo test -p cortex-drift-bridge pragma
# Test query module
cargo test -p cortex-drift-bridge query
# Test migration
cargo test -p cortex-drift-bridge migration
# All existing tests
cargo test -p cortex-drift-bridge -- --test-threads=1
```

---

## 6. Phase 2 — Core Logic Completion

> **Goal**: Active evidence collection, idempotency, weight decay, structured priors, contradiction generation. This is the largest phase.

### P2-01: event_mapping/dedup.rs — Content-hash deduplication

```rust
/// In-memory HashMap<[u8; 32], Instant> with TTL eviction.
/// blake3 hash of (event_type + entity_id + key fields).
/// TTL: 60 seconds. Capacity: 10,000 entries with LRU eviction.
pub struct EventDeduplicator { ... }
```

Wire into `BridgeEventHandler` — check before `create_memory()`.

### P2-02: event_mapping/enrichment.rs — Drift.db enrichment at event time

For each event type that creates a memory, query drift.db for full metadata:
- `PatternApproved` → fetch confidence, file_count, locations
- `RegressionDetected` → fetch affected_files, delta details
- `ViolationDismissed` → fetch severity, file, line
- `BoundaryDiscovered` → fetch full boundary metadata

Uses `query/drift_queries.rs` from Phase 1.

### P2-03: event_mapping/memory_builder.rs — BaseMemory construction helper

Extract repetitive `BaseMemory { ... }` construction from `mapper.rs` into:
```rust
pub struct MemoryBuilder { ... }
impl MemoryBuilder {
    pub fn new(event_type: &str, memory_type: MemoryType) -> Self;
    pub fn content(self, content: TypedContent) -> Self;
    pub fn summary(self, summary: impl Into<String>) -> Self;
    pub fn confidence(self, c: f64) -> Self;
    pub fn importance(self, i: Importance) -> Self;
    pub fn tags(self, t: Vec<String>) -> Self;
    pub fn linked_patterns(self, p: Vec<PatternLink>) -> Self;
    pub fn linked_files(self, f: Vec<FileLink>) -> Self;       // NEW
    pub fn linked_functions(self, f: Vec<FunctionLink>) -> Self; // NEW
    pub fn build(self) -> BaseMemory;
}
```

Refactor all 18 `create_memory()` calls in `mapper.rs` to use the builder.

### P2-04: event_mapping/cortex_handler.rs — Bidirectional event flow

```rust
pub struct BridgeCortexEventHandler { ... }
impl CortexEventHandler for BridgeCortexEventHandler {
    fn on_memory_created(&self, memory: &BaseMemory);      // schedule grounding
    fn on_memory_updated(&self, memory: &BaseMemory);      // re-ground
    fn on_contradiction_detected(&self, c: &Contradiction); // cross-ref drift
    fn on_consolidation_complete(&self, ids: &[String]);    // re-ground consolidated
}
```

### P2-05: grounding/evidence/ — 10 Active Evidence Collectors

**Architecture**: Enum dispatch (not trait objects):

```rust
pub enum EvidenceCollector {
    PatternConfidence,
    PatternOccurrence,
    FalsePositiveRate,
    ConstraintVerification,
    CouplingMetric,
    DnaHealth,
    TestCoverage,
    ErrorHandlingGaps,
    DecisionEvidence,
    BoundaryData,
}
```

Create 13 files in `grounding/evidence/`:
- `mod.rs` — re-exports
- `types.rs` — move `EvidenceType`, `GroundingEvidence` from `evidence.rs`
- `collector.rs` — `EvidenceCollector` enum + dispatch
- `pattern_confidence.rs` — `SELECT confidence FROM drift_patterns WHERE id = ?`
- `pattern_occurrence.rs` — `SELECT occurrence_rate FROM drift_patterns WHERE id = ?`
- `false_positive_rate.rs` — `SELECT fp_rate FROM drift_violation_feedback WHERE pattern_id = ?`
- `constraint_verification.rs` — `SELECT verified FROM drift_constraints WHERE id = ?`
- `coupling_metric.rs` — `SELECT instability FROM drift_coupling WHERE module = ?`
- `dna_health.rs` — `SELECT health_score FROM drift_dna WHERE project = ?`
- `test_coverage.rs` — `SELECT coverage FROM drift_test_topology WHERE module = ?`
- `error_handling_gaps.rs` — `SELECT gap_count FROM drift_error_handling WHERE module = ?`
- `decision_evidence.rs` — `SELECT evidence_score FROM drift_decisions WHERE id = ?`
- `boundary_data.rs` — `SELECT boundary_score FROM drift_boundaries WHERE id = ?`
- `composite.rs` — `CompositeCollector`: runs all 10, merges results

**Key change**: `GroundingLoopRunner::collect_evidence()` switches from reading pre-populated `MemoryForGrounding` fields to calling `CompositeCollector::collect(memory, drift_db)`.

### P2-06: grounding/contradiction.rs — Actual contradiction generation

When `generates_contradiction == true`, create a Cortex contradiction memory:
```rust
pub fn generate_contradiction(
    memory: &MemoryForGrounding,
    grounding_result: &GroundingResult,
    cortex_writer: &CortexWriter,
) -> BridgeResult<String>;
```

### P2-07: specification/weights/ — Refactor into sub-module

- `weights/mod.rs` — re-exports
- `weights/provider.rs` — move `BridgeWeightProvider` (impl `WeightProvider`)
- `weights/computation.rs` — extract `compute_adaptive_weights()` pure function
- `weights/decay.rs` — 365-day half-life:
  ```rust
  fn decay_weight(stored: f64, static_default: f64, elapsed_days: f64) -> f64 {
      let half_life = 365.0;
      let decay_factor = 0.5_f64.powf(elapsed_days / half_life);
      static_default + (stored - static_default) * decay_factor
  }
  ```
- `weights/bounds.rs` — invariants: `0.0 ≤ w ≤ 5.0`, `sum ∈ [5.0, 30.0]`, NaN → default
- `weights/persistence.rs` — store/load adaptive weights as `Skill` memories

### P2-08: specification/decomposition/ — Refactor into sub-module

- `decomposition/mod.rs` — re-exports
- `decomposition/provider.rs` — move `BridgeDecompositionPriorProvider`
- `decomposition/dna_similarity.rs` — real DNA similarity computation (replace `LIKE '%boundary%'`)
- `decomposition/structured_priors.rs` — structured `PriorAdjustmentType` parsing (replace string matching)
- `decomposition/feedback_loop.rs` — confirm → boost confidence, reject → penalize; updates ORIGINAL prior

### P2-09: intents/resolver.rs

Map intent to relevant Drift data sources for MCP context generation:
```rust
pub fn resolve_intent(intent: &str) -> IntentResolution {
    // Returns which drift.db tables to query, depth, token budget
}
```

### P2 Verification Gate

```bash
# Active evidence collectors with real drift.db fixture
cargo test -p cortex-drift-bridge evidence_collector
# Dedup idempotency
cargo test -p cortex-drift-bridge dedup
# Weight decay
cargo test -p cortex-drift-bridge weight_decay
# All existing + new tests
cargo test -p cortex-drift-bridge -- --test-threads=1
```

---

## 7. Phase 3 — Causal Intelligence Layer

> **Goal**: Full CausalEngine wrapper operations. 7 files in `causal/`.

### P3-01: causal/mod.rs

Re-exports all causal bridge operations.

### P3-02: causal/edge_builder.rs

Typed edge creation with bridge-specific defaults:
```rust
pub fn add_correction_edge(engine: &CausalEngine, upstream: &BaseMemory, correction: &BaseMemory, root_cause: &CorrectionRootCause) -> BridgeResult<()>;
pub fn add_grounding_edge(engine: &CausalEngine, memory: &BaseMemory, evidence: &GroundingResult) -> BridgeResult<()>;
```

### P3-03: causal/inference.rs

Auto-discovery: `CausalEngine.infer_and_connect` for bridge memories. Run after batch event processing.

### P3-04: causal/counterfactual.rs

"What if pattern X didn't exist?" — wraps `CausalEngine.counterfactual`:
```rust
pub fn what_if_removed(engine: &CausalEngine, memory_id: &str) -> BridgeResult<CounterfactualResult>;
```
Returns impact assessment: affected memories + confidence deltas.

### P3-05: causal/intervention.rs

"If we change convention X, what breaks?" — wraps `CausalEngine.intervention`:
```rust
pub fn what_if_changed(engine: &CausalEngine, memory_id: &str, change: &str) -> BridgeResult<InterventionResult>;
```
Returns downstream propagation graph with severity scores.

### P3-06: causal/pruning.rs

Prune weak/invalidated causal edges after grounding:
```rust
pub fn prune_weak_edges(engine: &CausalEngine, threshold: f64) -> BridgeResult<PruningReport>;
```

### P3-07: causal/narrative_builder.rs

Rich narrative combining all traversal ops:
- `bidirectional` + `trace_origins` + `trace_effects` → unified explanation
- Replaces current `specification/narrative.rs` ad-hoc implementation

### P3 Verification Gate

```bash
cargo test -p cortex-drift-bridge causal
cargo test -p cortex-drift-bridge counterfactual
cargo test -p cortex-drift-bridge intervention
```

---

## 8. Phase 4 — Presentation Layer

> **Goal**: 7 MCP tools, 20 NAPI functions, metrics module.

### P4-01: 4 New MCP Tools

- `tools/drift_counterfactual.rs` — "What if X didn't exist?"
- `tools/drift_intervention.rs` — "What breaks if we change X?"
- `tools/drift_bridge_status.rs` — bridge health report (subsystem status, degradation, metrics)
- `tools/drift_grounding_report.rs` — full grounding report (snapshot + trends + contradictions)

### P4-02: Split napi/functions.rs → domain files

Split the monolithic 15-function file into domain-organized files:
- `napi/status.rs` — `bridge_status` (1)
- `napi/grounding.rs` — `bridge_ground_memory`, `bridge_ground_all`, `bridge_grounding_history` (3)
- `napi/links.rs` — `bridge_translate_link`, `bridge_translate_constraint_link` (2)
- `napi/mappings.rs` — `bridge_event_mappings`, `bridge_groundability` (2)
- `napi/license.rs` — `bridge_license_check` (1)
- `napi/intents.rs` — `bridge_intents` (1)
- `napi/specification.rs` — 5 spec functions (5)
- `napi/causal.rs` — `bridge_counterfactual`, `bridge_intervention` (2) **NEW**
- `napi/health.rs` — `bridge_health_check`, `bridge_degradation_status` (2) **NEW**
- `napi/metrics.rs` — `bridge_metrics_snapshot` (1) **NEW**

**Total**: 20 NAPI functions (15 existing + 5 new).

### P4-03: metrics/ module (7 files)

- `metrics/mod.rs` — re-exports
- `metrics/collector.rs` — `MetricsCollector`: thread-safe `AtomicU64` counters + `Mutex<f64>` gauges
- `metrics/counters.rs` — `events_processed`, `memories_created`, `errors`, `groundings_run`
- `metrics/gauges.rs` — `grounding_score_avg`, `memories_groundable`, `bridge_available`
- `metrics/histograms.rs` — `grounding_duration_ms`, `event_processing_us`
- `metrics/persistence.rs` — flush to `bridge_metrics` table on configurable interval
- `metrics/snapshot.rs` — `MetricsSnapshot`: point-in-time export for NAPI/MCP

### P4-04: tracing/ module (3 files)

- `tracing/mod.rs` — re-exports
- `tracing/spans.rs` — pre-built `#[instrument]` span definitions
  - Use `#[instrument]` on event handlers, MCP tool handlers, grounding loop top-level
  - Use level-guarded `debug!` on evidence collectors (hot path)
- `tracing/fields.rs` — structured field extractors for consistent span attributes

### P4 Verification Gate

```bash
cargo test -p cortex-drift-bridge tools
cargo test -p cortex-drift-bridge napi
cargo test -p cortex-drift-bridge metrics
```

---

## 9. Phase 5 — Resilience & Observability

> **Goal**: Error budgets, retry, fallback, corruption recovery.

### P5-01: resilience/ module (5 files)

- `resilience/mod.rs` — re-exports
- `resilience/error_budget.rs` — per-subsystem consecutive error tracking
  - After N errors, mark subsystem as degraded (not "tripped")
  - Re-check on next access attempt
  - Integrates with `health/degradation.rs`
- `resilience/retry.rs` — exponential backoff for `SQLITE_BUSY`
  - Max 3 attempts, jitter, base delay 10ms
  - `busy_timeout` PRAGMA is primary; this is application-level backup
- `resilience/fallback.rs` — typed fallback strategies:
  - Grounding fails → `InsufficientData` verdict
  - Cortex write fails → queue to `bridge_memories` buffer
  - Causal edge fails → store correction without edge
  - Weight query fails → static defaults
  - Prior query fails → empty vec
- `resilience/recovery.rs` — corruption recovery:
  - Detect orphaned memories (no causal edges)
  - Detect dangling edges (referencing missing nodes)
  - Rebuild bridge tables from cortex.db + drift.db
  - Validate schema version on startup

### P5 Verification Gate

```bash
cargo test -p cortex-drift-bridge resilience
cargo test -p cortex-drift-bridge recovery
```

---

## 10. Phase 6 — Test Buildout

> **Goal**: Comprehensive test coverage across all categories.

### Existing tests to keep and extend

| File | Keep | Extend With |
|------|------|-------------|
| `event_mapping_test.rs` | ✅ | Enrichment, dedup, builder tests |
| `grounding_test.rs` | ✅ | Active evidence collector tests |
| `hardening_test.rs` | ✅ | Circuit breaker → error budget tests |
| `link_translation_test.rs` | ✅ | Batch, file/function link tests |
| `spec_bridge_test.rs` | ✅ | Weight decay, DNA similarity tests |
| `spec_integration_test.rs` | ✅ | Counterfactual, intervention tests |
| `stress_test.rs` | ✅ | Memory usage tracking |

### New test files to create

| Category | File | Tests |
|----------|------|-------|
| **Common** | `tests/common/mod.rs` | Shared fixtures, builders, assertions |
| **Common** | `tests/common/fixtures.rs` | Fresh drift.db + cortex.db setup |
| **Common** | `tests/common/builders.rs` | Builder pattern for test objects |
| **Unit** | `tests/unit/enrichment_test.rs` | Event enrichment from drift.db |
| **Unit** | `tests/unit/dedup_test.rs` | Idempotency: same event → same memory |
| **Unit** | `tests/unit/evidence_collector_test.rs` | Each of 10 collectors independently |
| **Unit** | `tests/unit/contradiction_test.rs` | Contradiction generation from invalidation |
| **Unit** | `tests/unit/weight_decay_test.rs` | 365-day half-life decay |
| **Unit** | `tests/unit/weight_bounds_test.rs` | NaN, negative, overflow protection |
| **Unit** | `tests/unit/dna_similarity_test.rs` | Similarity computation + 0.6 threshold |
| **Unit** | `tests/unit/prior_feedback_test.rs` | Confirm → boost, reject → penalize |
| **Unit** | `tests/unit/config_validation_test.rs` | Invalid config rejection |
| **Unit** | `tests/unit/metrics_test.rs` | Counter increment, gauge set, histogram |
| **Integration** | `tests/integration/active_evidence_test.rs` | Evidence collectors vs real drift.db |
| **Integration** | `tests/integration/cortex_writer_test.rs` | Write through IMemoryStorage |
| **Integration** | `tests/integration/causal_graph_test.rs` | Corrections → edges → narrative |
| **Integration** | `tests/integration/counterfactual_test.rs` | "What if" end-to-end |
| **Integration** | `tests/integration/intervention_test.rs` | "What breaks" end-to-end |
| **Integration** | `tests/integration/scan_triggers_grounding_test.rs` | on_scan_complete → grounding |
| **Integration** | `tests/integration/bidirectional_events_test.rs` | Drift↔Cortex event flow |
| **Adversarial** | `tests/adversarial/feedback_amplification_test.rs` | Weight oscillation attack |
| **Adversarial** | `tests/adversarial/poisoned_priors_test.rs` | Malicious project poisoning |
| **Concurrency** | `tests/concurrency/parallel_grounding_test.rs` | 4 threads grounding |
| **Concurrency** | `tests/concurrency/cross_db_attach_test.rs` | Concurrent ATTACH |
| **Recovery** | `tests/recovery/corruption_test.rs` | Corrupted tables, invalid JSON |
| **Recovery** | `tests/recovery/missing_db_test.rs` | cortex.db missing → degradation |
| **Recovery** | `tests/recovery/schema_migration_test.rs` | v1→v2 migration |

### Benchmarks (4 files)

| File | What It Measures |
|------|-----------------|
| `benches/grounding_bench.rs` | 500 memories, wall time |
| `benches/evidence_collection_bench.rs` | 10 collectors against drift.db |
| `benches/event_mapping_bench.rs` | 1000 events/second throughput |
| `benches/causal_traversal_bench.rs` | Narrative generation depth=20 |

### P6 Verification Gate

```bash
cargo test -p cortex-drift-bridge -- --test-threads=1
cargo bench -p cortex-drift-bridge
```

---

## 11. Dependency Graph & Critical Path

```
                    ┌─────────────────────────────────────────────────────────┐
                    │                     PHASE 0                             │
                    │  P0-01 PRAGMAs  P0-02 errors/  P0-03 config/           │
                    │  P0-04 types/   P0-05 health/                          │
                    └──────────────────────┬──────────────────────────────────┘
                                           │
                    ┌──────────────────────▼──────────────────────────────────┐
                    │                     PHASE 1                             │
                    │  P1-01 pragmas wire  P1-02 migrations  P1-03 writer    │
                    │  P1-04 query/        P1-05 storage refactor            │
                    └──────────────────────┬──────────────────────────────────┘
                                           │
          ┌────────────────────────────────▼────────────────────────────────┐
          │                          PHASE 2                                │
          │  ┌──────────────┐  ┌─────────────────┐  ┌───────────────────┐  │
          │  │ P2-01 dedup  │  │ P2-05 evidence/ │  │ P2-07 weights/   │  │
          │  │ P2-02 enrich │  │ (10 collectors) │  │ P2-08 decomp/    │  │
          │  │ P2-03 builder│  │ P2-06 contradict│  │ P2-09 resolver   │  │
          │  │ P2-04 cortex │  └────────┬────────┘  └────────┬─────────┘  │
          │  │   handler    │           │                     │            │
          │  └──────────────┘           │                     │            │
          └─────────────────────────────┼─────────────────────┼────────────┘
                                        │                     │
          ┌─────────────────────────────▼─────────────────────┘
          │                     PHASE 3
          │  P3-02 edge_builder  P3-03 inference  P3-04 counterfactual
          │  P3-05 intervention  P3-06 pruning    P3-07 narrative_builder
          └──────────────────────┬────────────────────────────────────────┐
                                 │                                        │
          ┌──────────────────────▼──────────┐  ┌──────────────────────────▼──┐
          │          PHASE 4                │  │        PHASE 5              │
          │  P4-01 4 new tools              │  │  P5-01 resilience/          │
          │  P4-02 napi split + 5 new       │  │  (error_budget, retry,      │
          │  P4-03 metrics/                 │  │   fallback, recovery)       │
          │  P4-04 tracing/                 │  │                             │
          └──────────────┬──────────────────┘  └──────────────┬──────────────┘
                         │                                    │
                         └────────────────┬───────────────────┘
                                          │
          ┌───────────────────────────────▼───────────────────────────────┐
          │                        PHASE 6                                │
          │  Test buildout: unit, integration, adversarial, concurrency,  │
          │  recovery, stress, benchmarks                                  │
          └───────────────────────────────────────────────────────────────┘
```

**Critical path**: P0 → P1 → P2 (evidence/) → P3 → P4 → P6

**Total estimated duration**: 22–30 working days

---

## 12. Verification Gates

| Gate | Trigger | Pass Criteria |
|------|---------|---------------|
| G0 | After Phase 0 | `cargo check` clean, all 7 existing test files pass |
| G1 | After Phase 1 | PRAGMA verification test, query module compiles, migrations run |
| G2 | After Phase 2 | Active evidence collectors return data from drift.db fixture, dedup prevents duplicates, weight decay formula correct |
| G3 | After Phase 3 | Counterfactual returns impact assessment, intervention returns propagation graph |
| G4 | After Phase 4 | All 20 NAPI functions callable, all 7 MCP tools return valid JSON, metrics snapshot non-empty |
| G5 | After Phase 5 | Error budget degrades subsystem after N failures, retry handles SQLITE_BUSY, recovery rebuilds tables |
| G6 | After Phase 6 | All test categories pass, benchmarks run, no regressions |

**Continuous gate (every PR)**:
```bash
cargo check -p cortex-drift-bridge
cargo clippy -p cortex-drift-bridge -- -D warnings
cargo test -p cortex-drift-bridge -- --test-threads=1
```

---

## 13. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| drift.db schema doesn't match expected table names in evidence collectors | High | P2 blocked | Verify actual drift.db schema before writing queries; use `PRAGMA table_info()` |
| `cortex-core::IMemoryStorage` trait doesn't exist or has different API | Medium | P1-03 blocked | Check cortex-core exports first; fall back to current direct SQL if needed |
| `CausalEngine` doesn't expose `counterfactual()` / `intervention()` methods | Medium | P3 blocked | Check cortex-causal API; stub methods if needed |
| Refactoring `errors.rs` → `errors/` breaks downstream imports | Low | P0 blocked | Use `pub use` re-exports, run full test suite after each refactor |
| 10 evidence collector SQL queries are slow against large drift.db | Medium | Performance | Add `LIMIT` clauses, use indexed columns, benchmark with realistic data |
| `MemoryForGrounding` struct changes break existing tests | High | Test failures | Keep backward-compatible fields, add new fields as `Option<T>` |
| ATTACH across WAL databases has unexpected locking | Low | P1-04 deadlock | Follow read-DETACH-write pattern documented in architecture |

---

## Quick Reference: File Creation Checklist

```
Phase 0 (18 files):
  □ src/storage/pragmas.rs
  □ src/errors/mod.rs
  □ src/errors/bridge_error.rs
  □ src/errors/context.rs
  □ src/errors/recovery.rs
  □ src/errors/chain.rs
  □ src/config/mod.rs
  □ src/config/bridge_config.rs
  □ src/config/event_config.rs
  □ src/config/grounding_config.rs
  □ src/config/evidence_config.rs
  □ src/config/validation.rs
  □ src/types/mod.rs
  □ src/types/grounding_result.rs
  □ src/types/grounding_snapshot.rs
  □ src/types/confidence_adjustment.rs
  □ src/types/grounding_verdict.rs
  □ src/types/data_source.rs
  □ src/types/event_processing_result.rs
  □ src/health/mod.rs
  □ src/health/status.rs
  □ src/health/checks.rs
  □ src/health/readiness.rs
  □ src/health/degradation.rs

Phase 1 (8 files):
  □ src/storage/schema.rs
  □ src/storage/migrations.rs
  □ src/storage/cortex_writer.rs
  □ src/storage/retention.rs (extract)
  □ src/query/mod.rs
  □ src/query/attach.rs
  □ src/query/drift_queries.rs
  □ src/query/cortex_queries.rs
  □ src/query/cross_db.rs

Phase 2 (25 files):
  □ src/event_mapping/dedup.rs
  □ src/event_mapping/enrichment.rs
  □ src/event_mapping/memory_builder.rs
  □ src/event_mapping/cortex_handler.rs
  □ src/grounding/evidence/mod.rs
  □ src/grounding/evidence/types.rs
  □ src/grounding/evidence/collector.rs
  □ src/grounding/evidence/pattern_confidence.rs
  □ src/grounding/evidence/pattern_occurrence.rs
  □ src/grounding/evidence/false_positive_rate.rs
  □ src/grounding/evidence/constraint_verification.rs
  □ src/grounding/evidence/coupling_metric.rs
  □ src/grounding/evidence/dna_health.rs
  □ src/grounding/evidence/test_coverage.rs
  □ src/grounding/evidence/error_handling_gaps.rs
  □ src/grounding/evidence/decision_evidence.rs
  □ src/grounding/evidence/boundary_data.rs
  □ src/grounding/evidence/composite.rs
  □ src/grounding/contradiction.rs
  □ src/specification/weights/mod.rs
  □ src/specification/weights/provider.rs
  □ src/specification/weights/computation.rs
  □ src/specification/weights/decay.rs
  □ src/specification/weights/bounds.rs
  □ src/specification/weights/persistence.rs
  □ src/specification/decomposition/mod.rs
  □ src/specification/decomposition/provider.rs
  □ src/specification/decomposition/dna_similarity.rs
  □ src/specification/decomposition/structured_priors.rs
  □ src/specification/decomposition/feedback_loop.rs
  □ src/intents/resolver.rs

Phase 3 (7 files):
  □ src/causal/mod.rs
  □ src/causal/edge_builder.rs
  □ src/causal/inference.rs
  □ src/causal/counterfactual.rs
  □ src/causal/intervention.rs
  □ src/causal/pruning.rs
  □ src/causal/narrative_builder.rs

Phase 4 (18 files):
  □ src/tools/drift_counterfactual.rs
  □ src/tools/drift_intervention.rs
  □ src/tools/drift_bridge_status.rs
  □ src/tools/drift_grounding_report.rs
  □ src/napi/status.rs
  □ src/napi/grounding.rs
  □ src/napi/links.rs
  □ src/napi/mappings.rs
  □ src/napi/license.rs
  □ src/napi/intents.rs
  □ src/napi/specification.rs
  □ src/napi/causal.rs
  □ src/napi/health.rs
  □ src/napi/metrics_napi.rs
  □ src/metrics/mod.rs
  □ src/metrics/collector.rs
  □ src/metrics/counters.rs
  □ src/metrics/gauges.rs
  □ src/metrics/histograms.rs
  □ src/metrics/persistence.rs
  □ src/metrics/snapshot.rs
  □ src/tracing/mod.rs
  □ src/tracing/spans.rs
  □ src/tracing/fields.rs

Phase 5 (5 files):
  □ src/resilience/mod.rs
  □ src/resilience/error_budget.rs
  □ src/resilience/retry.rs
  □ src/resilience/fallback.rs
  □ src/resilience/recovery.rs

Phase 6 (~30 test files + 4 bench files):
  □ tests/common/mod.rs
  □ tests/common/fixtures.rs
  □ tests/common/builders.rs
  □ tests/unit/enrichment_test.rs
  □ tests/unit/dedup_test.rs
  □ tests/unit/evidence_collector_test.rs
  □ tests/unit/contradiction_test.rs
  □ tests/unit/weight_decay_test.rs
  □ tests/unit/weight_bounds_test.rs
  □ tests/unit/dna_similarity_test.rs
  □ tests/unit/prior_feedback_test.rs
  □ tests/unit/config_validation_test.rs
  □ tests/unit/metrics_test.rs
  □ tests/integration/active_evidence_test.rs
  □ tests/integration/cortex_writer_test.rs
  □ tests/integration/causal_graph_test.rs
  □ tests/integration/counterfactual_test.rs
  □ tests/integration/intervention_test.rs
  □ tests/integration/scan_triggers_grounding_test.rs
  □ tests/integration/bidirectional_events_test.rs
  □ tests/adversarial/feedback_amplification_test.rs
  □ tests/adversarial/poisoned_priors_test.rs
  □ tests/concurrency/parallel_grounding_test.rs
  □ tests/concurrency/cross_db_attach_test.rs
  □ tests/recovery/corruption_test.rs
  □ tests/recovery/missing_db_test.rs
  □ tests/recovery/schema_migration_test.rs
  □ benches/grounding_bench.rs
  □ benches/evidence_collection_bench.rs
  □ benches/event_mapping_bench.rs
  □ benches/causal_traversal_bench.rs
```

**Grand total**: ~115 new files (81 src + 30 test + 4 bench)
