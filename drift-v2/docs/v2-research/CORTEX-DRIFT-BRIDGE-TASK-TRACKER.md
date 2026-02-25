# Drift V2 — Cortex-Drift Bridge Task Tracker (Phase 9)

> **Source of Truth:** 34-CORTEX-DRIFT-BRIDGE-V2-PREP.md, SPECIFICATION-ENGINE-NOVEL-LOOP-ENHANCEMENT.md, BRIDGE-100-PERCENT-ARCHITECTURE.md
> **Target Coverage:** ≥80% test coverage per Rust module (`cargo tarpaulin --workspace`)
> **Crate:** `crates/cortex-drift-bridge/` (leaf crate — depends on `drift-core` + `cortex-core` + `cortex-causal`)
> **Total Phases:** 6 (A–F)
> **Quality Gates:** 6 (QG-A through QG-F)
> **Architectural Decision:** Extend, not rewrite. Existing event mapping, grounding, spec engine are sound — fill gaps, connect live data, add missing capabilities.
> **Rule:** No Phase N+1 begins until Phase N quality gate passes.
> **Rule:** You do NOT modify any Drift crate or Cortex crate in this tracker. Bridge only.
> **Verification:** This tracker accounts for 100% of gaps identified in the senior-engineer audit.
> **Upstream Dependency:** Phases 0–8 (Drift + Cortex) must be complete before this begins.

---

## How To Use This Document

- Agents: check off `[ ]` → `[x]` as you complete each task
- Every implementation task has a unique ID: `BR-{system}-{number}` (BR = Bridge)
- Every test task has a unique ID: `BT-{system}-{number}` (BT = Bridge Test)
- Quality gates are pass/fail — all criteria must pass before proceeding
- For bridge types → cross-reference `34-CORTEX-DRIFT-BRIDGE-V2-PREP.md` §Data Model
- For Drift events → cross-reference `crates/drift/drift-core/src/events/`
- For Cortex types → cross-reference `crates/cortex/cortex-core/src/memory/`

---

## Progress Summary

| Phase | Description | Impl Tasks | Test Tasks | Status |
|-------|-------------|-----------|-----------|--------|
| A | Foundation (PRAGMAs, Config, Types, Health) | 18 | 28 | Not Started |
| B | Active Evidence & Grounding (The D7 Fix) | 25 | 35 | Not Started |
| C | Specification Engine Completion | 13 | 24 | Not Started |
| D | Causal Intelligence & MCP Tools | 14 | 26 | Not Started |
| E | Observability, Resilience & Hardening | 13 | 23 | Not Started |
| F | Integration, Parity & Regression | 8 | 30 | Not Started |
| **TOTAL** | | **91** | **166** | |

---

## Phase A: Foundation (PRAGMAs, Config, Types, Health)

> **Goal:** Fix critical SQLite PRAGMA gap, add per-event config, complete missing spec types, add health tracking, establish schema migrations.
> **Estimated effort:** 2–3 days
> **Rationale:** Audit found bridge sets ZERO SQLite PRAGMAs. drift-core sets 8. Without this, all subsequent phases hit SQLITE_BUSY.
> **Performance targets:** Connection open + PRAGMAs < 5ms. Schema migration < 50ms.

### A1 — SQLite PRAGMAs — `src/storage/`

- [ ] `BR-STORE-01` — Create `storage/pragmas.rs` — `configure_connection()` sets 8 PRAGMAs matching drift-core: `journal_mode=WAL`, `synchronous=NORMAL`, `foreign_keys=ON`, `busy_timeout=5000`, `cache_size=-8000`, `mmap_size=268435456`, `temp_store=MEMORY`, `auto_vacuum=INCREMENTAL`
- [ ] `BR-STORE-02` — Refactor `lib.rs` `BridgeRuntime::initialize()` — Call `configure_connection()` on every opened connection. drift_db must use `SQLITE_OPEN_READ_ONLY`
- [ ] `BR-STORE-03` — Create `storage/migrations.rs` — `PRAGMA user_version` tracking (matching drift-core pattern). `migrate()` with version-matched SQL. V1 = current 5 tables

### A2 — Configuration — `src/config/`

- [ ] `BR-CFG-01` — Create `config/mod.rs` — Re-exports `BridgeConfig`, `EventConfig`, `GroundingConfig`, `EvidenceConfig`
- [ ] `BR-CFG-02` — Create `config/bridge_config.rs` — Move `BridgeConfig` from `lib.rs`. Add `event_config`, `evidence_weights`. Add `from_toml()` for drift.toml `[bridge]` parsing
- [ ] `BR-CFG-03` — Create `config/event_config.rs` — Per-event `HashMap<String, bool>` toggles for 21 events. `is_enabled()` checks both toggle AND license tier
- [ ] `BR-CFG-04` — Create `config/evidence_config.rs` — Per-evidence-type weight overrides. `get_weight(evidence_type) -> f64`
- [ ] `BR-CFG-05` — Create `config/validation.rs` — Reject invalid combos: grounding enabled + no drift_db_path, weight outside [0.0, 1.0], unknown event names
- [ ] `BR-CFG-06` — Refactor `lib.rs` — Replace inline `BridgeConfig` with import from `config/`

### A3 — Missing Spec Types — `src/types/`

- [ ] `BR-TYPE-01` — Create `types/mod.rs` — Move `GroundingResult`, `GroundingSnapshot`, `ConfidenceAdjustment`, `GroundingVerdict` here
- [ ] `BR-TYPE-02` — Create `types/data_source.rs` — `GroundingDataSource` enum: 12 variants (PatternConfidence, PatternOccurrence, FalsePositiveRate, ConstraintVerification, CouplingMetric, DnaHealth, TestCoverage, ErrorHandlingGaps, DecisionEvidence, BoundaryData, CallGraph, Manual)
- [ ] `BR-TYPE-03` — Refactor `GroundingResult` — Add: `memory_type`, `data_sources: Vec<GroundingDataSource>`, `checked_at: String`
- [ ] `BR-TYPE-04` — Refactor `GroundingSnapshot` — Add: `flagged_for_review: u32`, `checked_at: String`
- [ ] `BR-TYPE-05` — Refactor `ConfidenceAdjustment` — Add `AdjustmentMode::Set` variant
- [ ] `BR-TYPE-06` — Refactor `GroundingVerdict` — Add `Error` variant

### A4 — Health & Degradation — `src/health/`

- [ ] `BR-HEALTH-01` — Create `health/mod.rs` — Re-exports `BridgeHealth`, `SubsystemStatus`, `DegradationTracker`
- [ ] `BR-HEALTH-02` — Create `health/status.rs` — `BridgeHealth` enum: `Available`, `Degraded { reasons }`, `Unavailable { reason }`. Per-subsystem: cortex_db, drift_db, causal_engine
- [ ] `BR-HEALTH-03` — Create `health/tracker.rs` — Thread-safe `DegradationTracker`: `mark_degraded()`, `mark_available()`, `health_report()`

### Phase A Tests

#### PRAGMAs
- [ ] `BT-STORE-01` — Test `configure_connection()` → `PRAGMA journal_mode` returns `wal`
- [ ] `BT-STORE-02` — Test busy_timeout set to 5000
- [ ] `BT-STORE-03` — Test cache_size set to -8000
- [ ] `BT-STORE-04` — Test foreign_keys ON
- [ ] `BT-STORE-05` — Test `BridgeRuntime::initialize()` calls `configure_connection()` on all connections
- [ ] `BT-STORE-06` — Test drift_db opened read-only — INSERT → error

#### Schema Migration
- [ ] `BT-MIG-01` — Test fresh db: `migrate()` creates 5 tables, sets `user_version = 1`
- [ ] `BT-MIG-02` — Test already-at-v1: `migrate()` idempotent
- [ ] `BT-MIG-03` — Test `get_bridge_schema_version()` returns 0 on fresh db
- [ ] `BT-MIG-04` — Test returns 1 after migration

#### Configuration
- [ ] `BT-CFG-01` — Test `EventConfig` default: all 21 events enabled
- [ ] `BT-CFG-02` — Test `is_enabled("pattern_approved")` → true by default
- [ ] `BT-CFG-03` — Test disabled event → false
- [ ] `BT-CFG-04` — Test Community tier caps at 5 events
- [ ] `BT-CFG-05` — Test `EvidenceConfig` default weights valid
- [ ] `BT-CFG-06` — Test weight override applied
- [ ] `BT-CFG-07` — Test `validate()` rejects weight > 1.0
- [ ] `BT-CFG-08` — Test rejects grounding enabled + no drift_db_path
- [ ] `BT-CFG-09` — Test valid config passes validation

#### Types & Health
- [ ] `BT-TYPE-01` — Test `GroundingDataSource` has 12 variants
- [ ] `BT-TYPE-02` — Test `GroundingResult` serde with new fields
- [ ] `BT-TYPE-03` — Test `GroundingSnapshot` serde with new fields
- [ ] `BT-TYPE-04` — Test `AdjustmentMode::Set` serde round-trip
- [ ] `BT-TYPE-05` — Test `GroundingVerdict::Error` serde round-trip
- [ ] `BT-HEALTH-01` — Test tracker starts `Available`
- [ ] `BT-HEALTH-02` — Test `mark_degraded()` → `Degraded`
- [ ] `BT-HEALTH-03` — Test `mark_available()` → `Available`
- [ ] `BT-HEALTH-04` — Test multiple subsystems degraded → all reasons reported

### QG-A: Phase A Quality Gate

- [ ] `cargo build` — zero errors, zero warnings
- [ ] Every connection has 8 PRAGMAs set. drift_db opened read-only
- [ ] Schema migration idempotent
- [ ] Per-event toggles + license tier filtering work together
- [ ] All 7 missing spec type fields present and serde round-trip
- [ ] Health tracker reports Degraded when cortex_db unavailable
- [ ] `cargo tarpaulin` ≥80% for `storage/`, `config/`, `types/`, `health/`

---

## Phase B: Active Evidence & Grounding (The D7 Fix)

> **Goal:** Make the grounding loop actually query drift.db. Wire `on_scan_complete` to trigger grounding. Add idempotent dedup. Enrich event memories. Write through IMemoryStorage.
> **Estimated effort:** 3–4 days
> **Prerequisite:** Phase A complete
> **Rationale:** `collect_evidence()` has `_drift_db` (unused). The bridge cannot independently ground memories. THIS is the D7 fix.
> **Performance targets:** 500 memories evidenced < 2s. Single query < 1ms.

### B1 — Active Evidence Collectors — `src/grounding/evidence/`

> **IMPORTANT:** Existing `src/grounding/evidence.rs` must be renamed to `src/grounding/evidence/types.rs` (or its contents absorbed into `evidence/mod.rs`) before creating the `evidence/` directory. Rust does not allow both `evidence.rs` and `evidence/` for the same module. Handle this rename in BR-EVID-01.

- [ ] `BR-EVID-01` — Create `grounding/evidence/mod.rs` — Rename existing `evidence.rs` → `evidence/types.rs`, create `mod.rs` re-exporting types + enum + all collectors
- [ ] `BR-EVID-02` — Create `grounding/evidence/collector.rs` — `EvidenceCollector` enum (10 variants, enum dispatch per research §7). `collect()` + `all()`
- [ ] `BR-EVID-03` — Create `evidence/pattern_confidence.rs` — `SELECT confidence FROM drift_patterns WHERE id = ?1`
- [ ] `BR-EVID-04` — Create `evidence/pattern_occurrence.rs` — `SELECT occurrence_rate FROM drift_patterns WHERE id = ?1`
- [ ] `BR-EVID-05` — Create `evidence/false_positive_rate.rs` — `SELECT fp_rate FROM drift_violation_feedback WHERE pattern_id = ?1`
- [ ] `BR-EVID-06` — Create `evidence/constraint_verification.rs` — `SELECT verified FROM drift_constraints WHERE id = ?1`
- [ ] `BR-EVID-07` — Create `evidence/coupling_metric.rs` — `SELECT instability FROM drift_coupling WHERE module = ?1`
- [ ] `BR-EVID-08` — Create `evidence/dna_health.rs` — `SELECT health_score FROM drift_dna WHERE project = ?1`
- [ ] `BR-EVID-09` — Create `evidence/test_coverage.rs` — `SELECT coverage FROM drift_test_topology WHERE module = ?1`
- [ ] `BR-EVID-10` — Create `evidence/decision_evidence.rs` — `SELECT evidence_count FROM drift_decisions WHERE id = ?1`
- [ ] `BR-EVID-11` — Create `evidence/error_handling_gaps.rs` — `SELECT gap_count FROM drift_error_handling WHERE module = ?1`. Returns `EvidenceType::ErrorHandlingGaps`
- [ ] `BR-EVID-12` — Create `evidence/boundary_data.rs` — `SELECT boundary_score FROM drift_boundaries WHERE id = ?1`. Returns `EvidenceType::BoundaryData`
- [ ] `BR-EVID-13` — Create `evidence/composite.rs` — `collect_all()` iterates all 10, filters None, applies config weights, records `GroundingDataSource`

### B2 — Grounding Loop Fix

- [ ] `BR-GRND-01` — Refactor `loop_runner.rs` `collect_evidence()` — Remove underscore from `_drift_db`. Call `composite::collect_all()`. Fall back to pre-populated when drift_db is None
- [ ] `BR-GRND-02` — Refactor `loop_runner.rs` — `GroundingResult` includes `data_sources`, `memory_type`, `checked_at`
- [ ] `BR-GRND-03` — Refactor `scorer.rs` — `GroundingVerdict::Error` when all collectors fail
- [ ] `BR-GRND-04` — Create `grounding/contradiction.rs` — Generate contradiction memory when score < 0.1

### B3 — Scan-Triggered Grounding

- [ ] `BR-GRND-05` — Refactor `mapper.rs` `on_scan_complete()` — Call `GroundingScheduler::should_trigger()` and invoke `GroundingLoopRunner::run()` if true
- [ ] `BR-GRND-06` — Refactor `scheduler.rs` — Add `ScanComplete` trigger. Every 3rd scan, min 5-min interval

### B4 — Event Deduplication

- [ ] `BR-DEDUP-01` — Create `event_mapping/dedup.rs` — `DedupCache`: in-memory blake3 hash map. TTL 60s, cap 10K entries
- [ ] `BR-DEDUP-02` — Refactor `mapper.rs` — Check `DedupCache::is_duplicate()` before `create_memory()` in every handler

### B5 — Event Enrichment

- [ ] `BR-ENRICH-01` — Create `event_mapping/enrichment.rs` — `enrich_pattern_memory()` queries drift.db for file_count, conforming_count, detector_ids, locations
- [ ] `BR-ENRICH-02` — Refactor `mapper.rs` `on_pattern_approved()` — Call enrichment, populate `examples`, `metadata`, `linked_files`

### B6 — Cortex Storage Integration

- [ ] `BR-CORTEX-01` — Create `storage/cortex_writer.rs` — Wraps `IMemoryStorage::create()`. Falls back to `bridge_memories` if unavailable
- [ ] `BR-CORTEX-02` — Refactor `mapper.rs` — Replace `store_memory()` calls with `CortexWriter::write_memory()`

### Phase B Tests

#### Evidence Collectors
- [ ] `BT-EVID-01` — Test pattern_confidence: drift.db has confidence=0.85 → returns evidence
- [ ] `BT-EVID-02` — Test pattern_confidence: pattern missing → returns None
- [ ] `BT-EVID-03` — Test false_positive_rate: fp_rate=0.05 → returns evidence
- [ ] `BT-EVID-04` — Test constraint_verification: verified=true → positive evidence
- [ ] `BT-EVID-05` — Test coupling_metric: instability=0.3 → evidence
- [ ] `BT-EVID-06` — Test dna_health: health=0.9 → evidence
- [ ] `BT-EVID-07` — Test test_coverage: coverage=0.75 → evidence
- [ ] `BT-EVID-08` — Test decision_evidence: count=5 → evidence
- [ ] `BT-EVID-09` — Test error_handling_gaps: gap_count=3 → evidence
- [ ] `BT-EVID-10` — Test boundary_data: boundary_score=0.8 → evidence
- [ ] `BT-EVID-11` — Test composite with full drift.db → 5+ items
- [ ] `BT-EVID-12` — Test composite with empty drift.db → empty vec
- [ ] `BT-EVID-13` — Test composite populates data_sources
- [ ] `BT-EVID-14` — Test config weight=0.0 → excluded

#### Grounding Loop
- [ ] `BT-GRND-01` — Test `collect_evidence()` with live drift_db → evidence returned
- [ ] `BT-GRND-02` — Test with drift_db=None → falls back to pre-populated
- [ ] `BT-GRND-03` — Test result includes data_sources, memory_type, checked_at
- [ ] `BT-GRND-04` — Test all collectors fail → Verdict::Error
- [ ] `BT-GRND-05` — Test contradiction generated when score < 0.1
- [ ] `BT-GRND-06` — Test no contradiction when score >= 0.1

#### Scan Trigger
- [ ] `BT-GRND-07` — Test scan_complete triggers grounding when should_trigger=true
- [ ] `BT-GRND-08` — Test triggers every 3rd scan
- [ ] `BT-GRND-09` — Test 5-minute minimum interval
- [ ] `BT-GRND-10` — Test skipped when drift_db unavailable

#### Dedup
- [ ] `BT-DEDUP-01` — Test same event within 60s → skipped
- [ ] `BT-DEDUP-02` — Test same event after 60s → NOT skipped
- [ ] `BT-DEDUP-03` — Test different events same entity → both processed
- [ ] `BT-DEDUP-04` — Test 10,001 entries → oldest evicted
- [ ] `BT-DEDUP-05` — Test thread safety

#### Enrichment & Cortex Writer
- [ ] `BT-ENRICH-01` — Test enrichment with full drift.db → file_count, locations populated
- [ ] `BT-ENRICH-02` — Test enrichment drift_db unavailable → defaults (no crash)
- [ ] `BT-ENRICH-03` — Test enriched memory has non-empty examples/metadata
- [ ] `BT-CORTEX-01` — Test CortexWriter with IMemoryStorage → memory in cortex.db
- [ ] `BT-CORTEX-02` — Test CortexWriter without IMemoryStorage → falls back to bridge_memories
- [ ] `BT-CORTEX-03` — Test memory written via CortexWriter retrievable via IMemoryStorage::get()

### QG-B: Phase B Quality Gate

- [ ] `_drift_db` parameter no longer has underscore
- [ ] All 10 evidence collectors tested with populated drift.db
- [ ] GroundingResult includes data_sources
- [ ] on_scan_complete triggers grounding (not just logs)
- [ ] Dedup: same event 2x within 60s → 1 memory
- [ ] Enriched memories have file_count, metadata
- [ ] CortexWriter writes through IMemoryStorage
- [ ] Contradiction generated when score < 0.1
- [ ] `cargo tarpaulin` ≥80% for `grounding/`, `event_mapping/`, `storage/cortex_writer`

---

## Known Deferred Items

> Items identified in the blueprint that are **intentionally deferred** from this tracker due to upstream dependencies or lower priority. These should be tracked in a follow-up.

| Item | Blueprint Location | Reason Deferred |
|------|-------------------|----------------|
| `event_mapping/cortex_handler.rs` — `BridgeCortexEventHandler` implementing bidirectional Cortex→Bridge event flow (on_memory_created, on_memory_updated, on_contradiction_detected, on_consolidation_complete) | Blueprint L113–L117 | Requires a `CortexEventHandler` trait in `cortex-core` that does not yet exist. Rule: bridge tracker does NOT modify upstream crates. Create trait in a separate cortex-core tracker first. |
| `storage/retention.rs` — Retention policies (7d metrics, 30d events, 90d/∞ grounding) | Blueprint L79 | Functional without it — data grows slowly. Add when bridge reaches production usage levels. |
| `errors/` expansion — `context.rs`, `recovery.rs`, `chain.rs` (error taxonomy) | Blueprint L40–L44 | Existing `errors.rs` is sufficient for all phases. Expansion is polish, not blocking. |
| `query/` module — `attach.rs`, `drift_queries.rs`, `cortex_queries.rs`, `cross_db.rs` | Blueprint L83–L97 | Evidence collectors embed their own queries. Centralizing into `query/` is a refactor-for-organization, not a functional gap. |
| `link_translation/` expansion — `entity_link.rs`, `batch.rs`, `round_trip.rs` | Blueprint L126–L132 | Existing translator works. Batch and round-trip are optimization. |
| `intents/resolver.rs` — Intent → Drift data source mapping | Blueprint L194 | Intents work without resolver. Add when MCP context tool needs richer intent handling. |
| `health/checks.rs`, `health/readiness.rs` — Individual subsystem check implementations, readiness probe | Blueprint L65–L67 | `DegradationTracker` covers the core need. Individual checks and readiness probes are operational extras. |

---

## Phase C: Specification Engine Completion

> **Goal:** Complete feedback loops: prior confidence adjustment, weight decay, structured decomposition queries, attribution persistence.
> **Estimated effort:** 2–3 days
> **Prerequisite:** Phase B complete (Cortex writer, evidence collectors)
> **Rationale:** Audit found: decomposition uses hardcoded LIKE '%boundary%', prior confidence never updated, no weight decay, attribution stats not persisted.
> **Performance targets:** Weight lookup < 1ms. Prior query < 5ms. Decay < 0.1ms.

### C1 — Weight Decay — `src/specification/weights/`

- [ ] `BR-WEIGHT-01` — Create `specification/weights/mod.rs` — Re-exports `BridgeWeightProvider`, `decay_weight()`
- [ ] `BR-WEIGHT-02` — Refactor `weight_provider.rs` → `weights/provider.rs` — Move existing impl
- [ ] `BR-WEIGHT-03` — Create `weights/decay.rs` — `decay_weight(stored, static_default, elapsed_days) -> f64` using `static_default + (stored - static_default) * 0.5_f64.powf(elapsed_days / 365.0)`. Clamp to [0.0, 5.0]
- [ ] `BR-WEIGHT-04` — Refactor `weights/provider.rs` — Apply `decay_weight()` to each section weight using `last_updated` timestamp before returning
- [ ] `BR-WEIGHT-05` — Create `weights/bounds.rs` — `validate_weight_table()`: each weight ∈ [0.0, 5.0], NaN → static default, sum ∈ [5.0, 30.0]

### C2 — Decomposition Prior Fix — `src/specification/decomposition/`

- [ ] `BR-DECOMP-01` — Create `specification/decomposition/mod.rs` — Re-exports provider + DNA similarity
- [ ] `BR-DECOMP-02` — Refactor `decomposition_provider.rs` → `decomposition/provider.rs`
- [ ] `BR-DECOMP-03` — Create `decomposition/dna_similarity.rs` — `compute_similarity(project_a, project_b, drift_db) -> f64` via Jaccard on DNA tables. Returns 0.0 if missing
- [ ] `BR-DECOMP-04` — Refactor `decomposition/provider.rs` — Replace LIKE '%boundary%' with `dna_similarity ≥ 0.6`. Replace string-matching with `json_extract(content, '$.data.adjustment_type')`
- [ ] `BR-DECOMP-05` — Create `decomposition/feedback_loop.rs` — `update_prior_confidence(memory_id, confirmed, storage) -> BridgeResult<f64>`. Confirm: +0.15 (max 0.99). Reject: -0.2 (min 0.1). Updates ORIGINAL memory via `storage.update()`
- [ ] `BR-DECOMP-06` — Refactor `specification/events.rs` `on_decomposition_adjusted()` — Call `update_prior_confidence()` on the original prior

### C3 — Attribution Persistence

- [ ] `BR-ATTR-01` — Refactor `attribution.rs` — Add `persist(conn) -> BridgeResult<()>`. Stores in `bridge_metrics` as "attribution_{source}"
- [ ] `BR-ATTR-02` — Refactor `events.rs` `on_spec_corrected()` — Call `attribution.persist()`

### Phase C Tests

#### Weight Decay
- [ ] `BT-DECAY-01` — Test `decay_weight(1.0, 0.5, 0.0)` = 1.0 (zero elapsed)
- [ ] `BT-DECAY-02` — Test `decay_weight(1.0, 0.5, 365.0)` = 0.75 (half-life)
- [ ] `BT-DECAY-03` — Test `decay_weight(1.0, 0.5, 730.0)` = 0.625 (2 half-lives)
- [ ] `BT-DECAY-04` — Test `decay_weight(1.0, 0.5, 3650.0)` ≈ 0.5 (10 half-lives)
- [ ] `BT-DECAY-05` — Test provider applies decay to stored weights
- [ ] `BT-DECAY-06` — Test 0-day-old weights → no decay
- [ ] `BT-DECAY-07` — Test NaN → static default
- [ ] `BT-DECAY-08` — Test negative → clamped to 0.0
- [ ] `BT-DECAY-09` — Test > 5.0 → clamped to 5.0

#### Decomposition Priors
- [ ] `BT-DECOMP-01` — Test identical projects → similarity 1.0
- [ ] `BT-DECOMP-02` — Test completely different → 0.0
- [ ] `BT-DECOMP-03` — Test no DNA data → 0.0 (graceful)
- [ ] `BT-DECOMP-04` — Test provider uses DNA similarity ≥ 0.6 (not LIKE '%boundary%')
- [ ] `BT-DECOMP-05` — Test structured json_extract parsing
- [ ] `BT-DECOMP-06` — Test confirm → +0.15
- [ ] `BT-DECOMP-07` — Test reject → -0.2
- [ ] `BT-DECOMP-08` — Test clamp to [0.1, 0.99]
- [ ] `BT-DECOMP-09` — Test updates ORIGINAL memory (not new)
- [ ] `BT-DECOMP-10` — Test `on_decomposition_adjusted()` calls `update_prior_confidence()`

#### Attribution
- [ ] `BT-ATTR-01` — Test `persist()` writes to bridge_metrics
- [ ] `BT-ATTR-02` — Test `on_spec_corrected()` calls `persist()`
- [ ] `BT-ATTR-03` — Test stats survive restart (persisted)
- [ ] `BT-ATTR-04` — Test all DataSourceAttribution variants
- [ ] `BT-ATTR-05` — Test zero corrections → all counts zero

### QG-C: Phase C Quality Gate

- [ ] Weight decay: 365 days → halfway to static default
- [ ] NaN, negative, overflow → clamped
- [ ] Decomposition uses DNA similarity (no LIKE '%boundary%')
- [ ] Prior confidence updated on ORIGINAL memory
- [ ] Confirm +0.15, Reject -0.2, clamped [0.1, 0.99]
- [ ] Attribution persisted to bridge_metrics
- [ ] `cargo tarpaulin` ≥80% for `specification/`

---

## Phase D: Causal Intelligence & MCP Tools

> **Goal:** Unlock CausalEngine's full power. Add counterfactual, intervention, infer_and_connect, pruning. Expand MCP tools from 3 → 7, NAPI from 15 → 20. Make `drift_why` dramatically richer.
> **Estimated effort:** 2–3 days
> **Prerequisite:** Phase C complete (causal edges exist from spec corrections)
> **Rationale:** Bridge uses 3 of 8 CausalEngine operations. Counterfactual and intervention are the most valuable unused — they power "what if" and "what breaks" analysis.
> **Performance targets:** Counterfactual < 50ms. Narrative < 100ms. Pruning < 200ms.

### D1 — Causal Bridge Layer — `src/causal/`

- [ ] `BR-CAUSAL-01` — Create `causal/mod.rs` — Re-exports all causal bridge operations
- [ ] `BR-CAUSAL-02` — Create `causal/edge_builder.rs` — `build_correction_edge()` maps 7 `CorrectionRootCause` variants to `CausalRelation` + strength + evidence. Wraps `engine.add_edge()`
- [ ] `BR-CAUSAL-03` — Create `causal/inference.rs` — `infer_connections(memory_ids, engine) -> BridgeResult<u32>`. Calls `engine.infer_and_connect()` for batch of bridge memories. Returns new edge count
- [ ] `BR-CAUSAL-04` — Create `causal/counterfactual.rs` — `what_if_removed(memory_id, engine) -> BridgeResult<CounterfactualReport>` with affected_memories, total_impact, narrative
- [ ] `BR-CAUSAL-05` — Create `causal/intervention.rs` — `what_breaks(memory_id, engine) -> BridgeResult<InterventionReport>` with downstream, severity, narrative
- [ ] `BR-CAUSAL-06` — Create `causal/pruning.rs` — `prune_weak_edges(engine, min_strength) -> BridgeResult<u32>`. Called after grounding invalidates memories. Returns pruned count
- [ ] `BR-CAUSAL-07` — Create `causal/narrative_builder.rs` — `full_narrative(memory_id, engine) -> BridgeResult<FullNarrative>`. Combines bidirectional + trace_origins + trace_effects + narrative into sections

### D2 — MCP Tool Expansion — `src/tools/`

- [ ] `BR-TOOL-01` — Refactor `tools/drift_why.rs` — Replace LIKE query with: (1) CortexWriter related memories, (2) `full_narrative()`, (3) `what_if_removed()`, (4) grounding status. Rich JSON response
- [ ] `BR-TOOL-02` — Create `tools/drift_counterfactual.rs` — Exposes `what_if_removed()`. Schema: `{ memory_id: String }`
- [ ] `BR-TOOL-03` — Create `tools/drift_intervention.rs` — Exposes `what_breaks()`. Schema: `{ memory_id: String }`
- [ ] `BR-TOOL-04` — Create `tools/drift_bridge_status.rs` — Returns health per subsystem, event counts, grounding stats, degradation reasons
- [ ] `BR-TOOL-05` — Create `tools/drift_grounding_report.rs` — Returns latest snapshot, trends (10 snapshots), contradictions, per-verdict breakdown

### D3 — NAPI Expansion

- [ ] `BR-NAPI-01` — Refactor `napi/functions.rs` — Add 5 functions: `bridge_counterfactual`, `bridge_intervention`, `bridge_health_check`, `bridge_grounding_report`, `bridge_metrics_snapshot`. Total: 15 → 20
- [ ] `BR-NAPI-02` — Refactor `napi/mod.rs` — Update re-exports

### Phase D Tests

#### Causal Operations
- [ ] `BT-CAUSAL-01` — Test `build_correction_edge()` creates edge in CausalEngine
- [ ] `BT-CAUSAL-02` — Test all 7 root causes map to correct CausalRelation
- [ ] `BT-CAUSAL-03` — Test `infer_connections()` discovers implicit edges
- [ ] `BT-CAUSAL-04` — Test infer with no related memories → 0 edges
- [ ] `BT-CAUSAL-05` — Test `what_if_removed()` returns affected with impact scores
- [ ] `BT-CAUSAL-06` — Test what_if on isolated memory → 0 affected
- [ ] `BT-CAUSAL-07` — Test `what_breaks()` returns downstream with severity
- [ ] `BT-CAUSAL-08` — Test what_breaks on leaf → 0 downstream
- [ ] `BT-CAUSAL-09` — Test `prune_weak_edges()` removes below threshold
- [ ] `BT-CAUSAL-10` — Test prune preserves above threshold
- [ ] `BT-CAUSAL-11` — Test `full_narrative()` includes origins + effects + text
- [ ] `BT-CAUSAL-12` — Test full_narrative on edgeless memory → valid empty narrative

#### MCP Tools
- [ ] `BT-TOOL-01` — Test `drift_why` returns rich JSON (narrative, counterfactual, grounding)
- [ ] `BT-TOOL-02` — Test `drift_why` nonexistent entity → empty result
- [ ] `BT-TOOL-03` — Test `drift_counterfactual` returns CounterfactualReport JSON
- [ ] `BT-TOOL-04` — Test counterfactual invalid memory_id → structured error
- [ ] `BT-TOOL-05` — Test `drift_intervention` returns InterventionReport JSON
- [ ] `BT-TOOL-06` — Test intervention invalid memory_id → structured error
- [ ] `BT-TOOL-07` — Test `drift_bridge_status` returns all subsystem statuses
- [ ] `BT-TOOL-08` — Test status with degraded bridge → reasons present
- [ ] `BT-TOOL-09` — Test `drift_grounding_report` returns snapshot + trends
- [ ] `BT-TOOL-10` — Test grounding_report empty db → valid empty report

#### NAPI
- [ ] `BT-NAPI-01` — Test all 20 NAPI functions return valid `serde_json::Value`
- [ ] `BT-NAPI-02` — Test `bridge_counterfactual` round-trips
- [ ] `BT-NAPI-03` — Test `bridge_health_check` returns health JSON
- [ ] `BT-NAPI-04` — Test `bridge_metrics_snapshot` returns metrics JSON

### QG-D: Phase D Quality Gate

- [ ] CausalEngine ops used: 8 of 8 (add_edge, infer_and_connect, counterfactual, intervention, prune, narrative, trace_origins, trace_effects)
- [ ] `drift_why` returns rich response (not LIKE query)
- [ ] Counterfactual and intervention work end-to-end
- [ ] `drift_bridge_status` reports per-subsystem health
- [ ] 20 NAPI functions, all valid JSON
- [ ] 7 MCP tools (up from 3)
- [ ] `cargo tarpaulin` ≥80% for `causal/`, `tools/`, `napi/`

---

## Phase E: Observability, Resilience & Hardening

> **Goal:** Wire metrics pipeline, add structured tracing spans, implement error budget resilience, harden all inputs against adversarial data.
> **Estimated effort:** 2–3 days
> **Prerequisite:** Phase D complete (all tools and NAPI functions exist)
> **Rationale:** Metrics pipeline plumbed but empty. No `#[instrument]` spans. No resilience for connection failures.
> **Performance targets:** Metric recording < 0.01ms. Tracing overhead < 2.5ms per grounding run.

### E1 — Metrics — `src/metrics/`

- [ ] `BR-METRICS-01` — Create `metrics/mod.rs` — Re-exports `MetricsCollector`, `MetricsSnapshot`
- [ ] `BR-METRICS-02` — Create `metrics/collector.rs` — Thread-safe counters (`AtomicU64`): `events_processed`, `events_skipped_dedup`, `events_skipped_license`, `memories_created`, `grounding_runs`, `grounding_verdicts_{validated,partial,weak,invalidated,error}`, `causal_edges_created`, `causal_edges_pruned`, `errors_total`. Methods: `increment()`, `snapshot()`
- [ ] `BR-METRICS-03` — Create `metrics/persistence.rs` — `flush_to_db(snapshot, conn)` writes to `bridge_metrics` table. Called every 60s or on shutdown
- [ ] `BR-METRICS-04` — Wire metrics: Add `MetricsCollector` to `BridgeRuntime`. Call `increment()` in event handlers, dedup, grounding loop, CortexWriter, causal ops

### E2 — Structured Tracing — `src/tracing/`

- [ ] `BR-TRACE-01` — Create `tracing/mod.rs` — Re-exports span helpers
- [ ] `BR-TRACE-02` — Create `tracing/spans.rs` — Add `#[instrument]` to: all 21 `DriftEventHandler` methods, `GroundingLoopRunner::run()`, all 7 MCP tool handlers, `CortexWriter::write_memory()`. Use level-guarded `debug!()` (not `#[instrument]`) in evidence collectors, score computation, dedup checks (hot paths per research §5)

### E3 — Resilience — `src/resilience/`

- [ ] `BR-RESIL-01` — Create `resilience/mod.rs` — Re-exports error budget, retry, fallback
- [ ] `BR-RESIL-02` — Create `resilience/error_budget.rs` — Per-subsystem consecutive error counter (`AtomicU32`). `record_success()` resets. `record_failure()` increments. `is_degraded()` if count > 5. NOT a circuit breaker (per research §1: wrong pattern for SQLite). Re-checks every access
- [ ] `BR-RESIL-03` — Create `resilience/retry.rs` — `retry_on_busy<F, T>(f, max=3) -> BridgeResult<T>`. Exponential backoff: 10ms, 50ms, 200ms. WARN on each retry. Only for write ops
- [ ] `BR-RESIL-04` — Create `resilience/fallback.rs` — Typed strategies: `grounding_fallback() → Verdict::Error`, `weight_fallback() → static_defaults()`, `prior_fallback() → vec![]`, `cortex_write_fallback() → store_in_bridge_memories()`. Each logs reason

### E4 — Input Hardening

- [ ] `BR-HARD-01` — Refactor `mapper.rs` — Validate string fields: truncate to 10KB, reject null bytes, sanitize (defense in depth)
- [ ] `BR-HARD-02` — Refactor `loop_runner.rs` — Validate `MemoryForGrounding`: confidence/importance ∈ [0.0, 1.0], reject NaN/Infinity. Log + skip invalid
- [ ] `BR-HARD-03` — Refactor `napi/functions.rs` — Validate all NAPI inputs: non-empty strings, valid JSON, numeric ranges. Return structured error JSON (not panic)

### Phase E Tests

#### Metrics
- [ ] `BT-METRICS-01` — Test `increment("events_processed")` increases by 1
- [ ] `BT-METRICS-02` — Test `snapshot()` returns all counters
- [ ] `BT-METRICS-03` — Test `flush_to_db()` writes to bridge_metrics
- [ ] `BT-METRICS-04` — Test concurrent increments from 4 threads → final count = 4
- [ ] `BT-METRICS-05` — Test events_processed incremented on each `on_pattern_approved()`
- [ ] `BT-METRICS-06` — Test grounding_verdicts_validated incremented on Validated

#### Tracing
- [ ] `BT-TRACE-01` — Test `on_pattern_approved` emits span with event_type field
- [ ] `BT-TRACE-02` — Test `GroundingLoopRunner::run()` emits span with memory_count
- [ ] `BT-TRACE-03` — Test evidence collectors use `debug!` not `#[instrument]`

#### Resilience
- [ ] `BT-RESIL-01` — Test error budget starts not degraded
- [ ] `BT-RESIL-02` — Test 5 consecutive failures → degraded
- [ ] `BT-RESIL-03` — Test 1 success after 5 failures → resets
- [ ] `BT-RESIL-04` — Test retry_on_busy retries 3x with backoff
- [ ] `BT-RESIL-05` — Test retry succeeds on 2nd attempt → Ok
- [ ] `BT-RESIL-06` — Test all 3 retries fail → returns last error
- [ ] `BT-RESIL-07` — Test `weight_fallback()` returns static_defaults
- [ ] `BT-RESIL-08` — Test `prior_fallback()` returns empty vec

#### Hardening
- [ ] `BT-HARD-01` — Test 1MB string → truncated to 10KB
- [ ] `BT-HARD-02` — Test null bytes → removed
- [ ] `BT-HARD-03` — Test NaN confidence → skipped, logged
- [ ] `BT-HARD-04` — Test Infinity importance → skipped, logged
- [ ] `BT-HARD-05` — Test SQL injection in NAPI input → safe
- [ ] `BT-HARD-06` — Test empty required NAPI field → structured error (not panic)

### QG-E: Phase E Quality Gate

- [ ] `record_metric()` called from handlers, grounding, causal ops
- [ ] MetricsSnapshot has non-zero counters after processing events
- [ ] `#[instrument]` on handlers + tools. `debug!` on evidence collectors
- [ ] Error budget per-subsystem — no circuit breaker timers
- [ ] retry_on_busy: 10ms, 50ms, 200ms exponential backoff
- [ ] All fallbacks return valid typed defaults
- [ ] 1MB input → truncated. NaN/Infinity → skipped. SQL injection → safe
- [ ] `cargo tarpaulin` ≥80% for `metrics/`, `resilience/`, hardening paths

---

## Phase F: Integration, Parity & Regression

> **Goal:** End-to-end validation. Full D7 loop. Concurrency. Adversarial. Stress at scale. Verify complete feedback loop: scan → evidence → grounding → confidence adjustment → contradiction.
> **Estimated effort:** 2–3 days
> **Prerequisite:** Phases A–E all complete
> **Rationale:** Individual modules tested in isolation — must verify full data flow end-to-end and under stress.

### F1 — End-to-End Pipeline Tests

- [ ] `BR-E2E-01` — Create `tests/e2e/full_loop_test.rs` — Full D7 loop: create pattern in drift.db → emit PatternApproved → bridge creates enriched memory in cortex.db → scan_complete → grounding loop → evidence from drift.db → verdict → confidence adjusted → verify final confidence changed
- [ ] `BR-E2E-02` — Create `tests/e2e/spec_correction_flow.rs` — SpecCorrected → Feedback memory → causal edge → weight update → decay after simulated time → narrative → attribution persisted
- [ ] `BR-E2E-03` — Create `tests/e2e/contradiction_flow.rs` — Memory with high confidence → zero evidence in drift.db → Invalidated → contradiction generated → original confidence penalized
- [ ] `BR-E2E-04` — Create `tests/e2e/decomposition_flow.rs` — Store priors → DNA similarity query → priors returned → human confirms → original prior confidence boosted

### F2 — Cross-DB & Degradation

- [ ] `BR-E2E-05` — Create `tests/e2e/cross_db_test.rs` — ATTACH drift.db → read → DETACH → write to cortex.db in separate transaction. Verify WAL non-atomic caveat handled correctly
- [ ] `BR-E2E-06` — Create `tests/e2e/degradation_test.rs` — Remove drift.db after init → bridge continues cortex-only → grounding returns Verdict::Error → metrics record degradation → health shows Degraded → restore drift.db → next operation succeeds

### F3 — Scale & Stress

- [ ] `BR-E2E-07` — Create `tests/stress/scale_test.rs` — 100 modules, 500 memories, 10,000 evidence queries. Wall time < 5s, RSS < 200MB, zero SQLITE_BUSY, all verdicts valid
- [ ] `BR-E2E-08` — Create `tests/stress/concurrent_test.rs` — 4 threads: T1 emits 100 events, T2 runs grounding, T3 does spec corrections, T4 queries MCP tools. No deadlocks, no corruption

### Phase F Tests

#### Full D7 Loop
- [ ] `BT-E2E-01` — Test PatternApproved → enriched memory in cortex.db (not just bridge_memories)
- [ ] `BT-E2E-02` — Test enriched memory has file_count > 0 from drift.db
- [ ] `BT-E2E-03` — Test scan_complete triggers grounding loop
- [ ] `BT-E2E-04` — Test evidence collected from drift.db (data_sources non-empty)
- [ ] `BT-E2E-05` — Test Validated verdict when drift.db confirms pattern (confidence ≥ 0.7)
- [ ] `BT-E2E-06` — Test memory confidence boosted after Validated
- [ ] `BT-E2E-07` — Test dedup: same event 2x → 1 memory
- [ ] `BT-E2E-08` — Test full loop: event → memory → grounding → adjustment (all 4 steps)

#### Spec Correction Loop
- [ ] `BT-E2E-09` — Test SpecCorrected → Feedback memory + causal edge + weight update
- [ ] `BT-E2E-10` — Test weight decay: 365 simulated days → halfway to default
- [ ] `BT-E2E-11` — Test narrative for correction → non-empty text
- [ ] `BT-E2E-12` — Test attribution persisted after correction

#### Contradiction Flow
- [ ] `BT-E2E-13` — Test zero evidence → Invalidated → contradiction created
- [ ] `BT-E2E-14` — Test contradiction references original memory
- [ ] `BT-E2E-15` — Test original confidence decreased

#### Decomposition Flow
- [ ] `BT-E2E-16` — Test DNA similarity ≥ 0.6 → priors returned
- [ ] `BT-E2E-17` — Test similarity < 0.6 → empty
- [ ] `BT-E2E-18` — Test confirm → original confidence increased
- [ ] `BT-E2E-19` — Test reject → original confidence decreased

#### Cross-DB & Degradation
- [ ] `BT-E2E-20` — Test ATTACH+read+DETACH+write doesn't leave drift.db attached
- [ ] `BT-E2E-21` — Test drift.db removed → graceful degradation
- [ ] `BT-E2E-22` — Test drift.db restored → next grounding succeeds
- [ ] `BT-E2E-23` — Test without cortex.db → Unavailable
- [ ] `BT-E2E-24` — Test without drift.db → Degraded, event mapping still works
- [ ] `BT-E2E-25` — Test all MCP tools → structured error when unavailable (not panic)

#### Stress
- [ ] `BT-STRESS-01` — Test 500 memories grounded < 5s
- [ ] `BT-STRESS-02` — Test 1000 events with dedup → < 1000 memories
- [ ] `BT-STRESS-03` — Test 4 threads → no deadlocks (< 30s)
- [ ] `BT-STRESS-04` — Test 4 threads → no SQLITE_BUSY (WAL working)
- [ ] `BT-STRESS-05` — Test RSS < 200MB after 500 memories + 10K queries

### QG-F: Phase F Quality Gate (Final Gate)

- [ ] Full D7 loop: event → enriched memory → grounding with live queries → confidence adjusted
- [ ] Spec correction: correction → causal edge → weight decay → narrative → attribution
- [ ] Contradiction generated when grounding invalidates
- [ ] Decomposition priors use DNA similarity, confidence updated on confirm/reject
- [ ] Cross-DB ATTACH safe under WAL
- [ ] Graceful degradation: continues without drift.db, recovers when restored
- [ ] 500 memories < 5s
- [ ] 4 concurrent threads: no deadlocks, no SQLITE_BUSY, no corruption
- [ ] All 7 MCP tools handle unavailable gracefully
- [ ] All 20 NAPI functions handle invalid input → structured error
- [ ] `cargo tarpaulin` ≥80% across entire crate

---

## Milestone Summary

| Milestone | Phase | Description | Estimated Timeline |
|-----------|-------|-------------|-------------------|
| M-A: "Foundation Solid" | End of A | PRAGMAs, config, types, health, migrations | Day 2–3 |
| M-B: "D7 Lives" | End of B | Active evidence, scan-triggered grounding, dedup, enrichment, Cortex writer | Day 5–7 |
| M-C: "Loops Closed" | End of C | Weight decay, DNA similarity, prior feedback, attribution | Day 8–9 |
| M-D: "Full Intelligence" | End of D | 8/8 CausalEngine ops, 7 MCP tools, 20 NAPI functions | Day 10–12 |
| M-E: "Production Hardened" | End of E | Metrics, tracing, error budget, input hardening | Day 13–14 |
| M-F: "Bridge Certified" | End of F | Full D7 loop, stress tested, concurrency safe | Day 15–17 |

## Critical Path

```
Phase A (2-3d) → Phase B (3-4d) → Phase C (2-3d) → Phase D (2-3d) → Phase E (2-3d) → Phase F (2-3d)
= 13-19 working days (strictly sequential — each phase depends on the previous)
```

## Risk Register

| Risk | Severity | Mitigation |
|------|----------|------------|
| R1: drift.db schema doesn't have expected tables for evidence queries | High | Collectors return `None` when table/column missing. Each query is individually try/catch |
| R2: SQLITE_BUSY under concurrent grounding + event processing | Medium | WAL + busy_timeout=5000 + retry_on_busy exponential backoff |
| R3: CortexWriter contends with Cortex's own writes on cortex.db | Medium | Both use WAL + busy_timeout. Bridge uses BEGIN IMMEDIATE for writes |
| R4: Weight decay too aggressive or conservative | Low | Configurable half-life (365d default), bounds [0.0, 5.0], NaN → static default |
| R5: DNA similarity expensive for large projects | Medium | Cache scores per project pair, invalidate on scan_complete |
| R6: Dedup cache memory growth under burst | Low | Hard cap 10K + 60s TTL + oldest-eviction |
| R7: CausalEngine graph too large for traversal | Low | prune_weak_edges after grounding keeps graph bounded |
| R8: Metrics flush fails during shutdown | Low | Flush every 60s, not just shutdown. Accept minor loss on crash |
| R9: ATTACH drift.db non-atomic with WAL | Medium | Read-DETACH-write pattern: never write while drift.db attached |
| R10: Existing tests break after refactoring | High | Run existing tests after every phase. No test removals without justification |

## Dependency Map

| Phase | External Dependencies | Internal Dependencies |
|-------|----------------------|----------------------|
| A | drift-core `workspace/migration.rs` pattern, cortex-core types | — |
| B | drift.db schema (8 tables: drift_patterns, drift_constraints, drift_coupling, drift_dna, drift_test_topology, drift_decisions, drift_boundaries, drift_violation_feedback) | Phase A |
| C | cortex-core `IMemoryStorage`, cortex-causal `CausalEngine` | Phase B |
| D | cortex-causal full API (counterfactual, intervention, infer_and_connect, prune) | Phase C |
| E | — | Phase D |
| F | — | All of A–E |

---

> **Generated:** 2026-02-09
> **Source documents:** 34-CORTEX-DRIFT-BRIDGE-V2-PREP.md, SPECIFICATION-ENGINE-NOVEL-LOOP-ENHANCEMENT.md, BRIDGE-100-PERCENT-ARCHITECTURE.md, Research Verification Appendix
> **Format reference:** PRESENTATION-LAYER-HARDENING-TASKS.md
> **Total:** 91 implementation tasks + 166 test tasks + 49 quality gate criteria = 306 checkboxes
