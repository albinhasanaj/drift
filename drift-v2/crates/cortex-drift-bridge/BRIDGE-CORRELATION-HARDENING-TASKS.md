# Bridge Correlation Hardening Tasks

> Deep audit of the `cortex-drift-bridge` crate — correlation, grounding, evidence, causal, specification, event mapping, query, storage, NAPI, tools, licensing, health, and link translation subsystems.

## Executive Summary

The `cortex-drift-bridge` crate (15 modules, ~60 source files) is the **only** crate that imports both `cortex-core` and `drift-core`. It is architecturally complete — all 15 modules compile, 656 tests pass, clippy clean. However, a line-by-line audit reveals **34 findings** across 6 severity levels that affect correctness, data integrity, and production readiness.

**Core finding:** The bridge's grounding system is the most mature subsystem (~70% production-ready), but the **correlation pipeline has 3 critical gaps**: (1) drift.db query table names don't match actual drift-storage schema, (2) confidence adjustments are computed but never applied back to cortex.db, and (3) the event→memory pipeline writes to `bridge_memories` but never to the real `cortex-storage` tables. The specification and causal subsystems are structurally complete but contain hardcoded placeholders and fragile string-matching logic.

**Severity breakdown:** P0=4, P1=10, P2=14, P3=6 = 34 total

---

## Findings by Severity

### P0 — Critical (blocks correctness)

#### P0-1: drift_queries.rs table names don't match drift-storage schema
- **File:** `src/query/drift_queries.rs:13-148`
- **Issue:** All 10 drift query functions reference tables like `drift_patterns`, `drift_violation_feedback`, `drift_constraints`, `drift_coupling`, `drift_dna`, `drift_test_topology`, `drift_error_handling`, `drift_decisions`, `drift_boundaries`, `drift_scans`. **None of these tables exist** in the actual drift-storage migration schema. The real tables are `detections`, `pattern_confidence`, `violations`, `constraint_verifications`, `coupling_metrics`, `dna_genes`, `test_quality`, `error_gaps`, `boundaries`, `scan_history`. Every query will return `QueryReturnedNoRows` or `no such table` errors.
- **Impact:** Active evidence collection from drift.db is 100% broken. The `collect_one()` fallback path in `loop_runner.rs` always fails silently, making the grounding system rely entirely on pre-populated `MemoryForGrounding` fields.
- **Fix:** Rewrite all 10 queries to match the actual drift-storage schema (column names and table names).

#### P0-2: Confidence adjustments computed but never applied
- **File:** `src/grounding/loop_runner.rs:130-160`, `src/grounding/scorer.rs:66-110`
- **Issue:** `GroundingLoopRunner::run()` computes `ConfidenceAdjustment` for each memory (boost/penalize/flag) and includes it in `GroundingResult`, but **never writes the adjusted confidence back** to either `bridge_memories` or `cortex.db`. The adjustment is returned in the result struct and persisted as JSON in `bridge_grounding_results.evidence`, but the memory's actual confidence value is never updated.
- **Impact:** Grounding verdicts are computed correctly but have zero effect on memory retrieval ranking. A memory grounded as `Invalidated` retains its original confidence forever.
- **Fix:** After computing the adjustment, execute `UPDATE bridge_memories SET confidence = MIN(MAX(confidence + ?, 0.0), 1.0) WHERE id = ?` (and optionally update cortex.db via the cortex-storage API).

#### P0-3: Event mapper writes to bridge_memories, not cortex-storage
- **File:** `src/event_mapping/mapper.rs:138-142`, `src/storage/tables.rs:23-43`
- **Issue:** `BridgeEventHandler::create_memory()` calls `storage::store_memory()` which INSERTs into `bridge_memories` — a bridge-local table. It never calls `cortex-storage`'s `create_memory()`. The `bridge_memories` table has a simplified schema (9 columns) compared to cortex-storage's full memory table (20+ columns). Memories created by the bridge are invisible to the Cortex retrieval engine, embedding pipeline, and all NAPI bindings that query cortex-storage.
- **Impact:** All 18 memory-creating event handlers produce memories that exist only in the bridge's local table. They cannot be searched, embedded, consolidated, or retrieved by Cortex tools.
- **Fix:** Either (a) call `cortex-storage::create_memory()` directly (requires adding cortex-storage as a dependency), or (b) expose a NAPI callback that the TS layer uses to persist to cortex.db after receiving the bridge result.

#### P0-4: EventProcessingResult type duplicated with conflicting definitions
- **File:** `src/types/event_processing_result.rs:1-23` vs `src/event_mapping/memory_types.rs:24-40`
- **Issue:** Two separate `EventProcessingResult` structs exist with identical field names but different module paths. `mapper.rs` imports from `memory_types`, while `types/mod.rs` re-exports from `types/event_processing_result.rs`. The `types` version is never used by any production code — it's dead code that will confuse future maintainers.
- **Impact:** Potential for import confusion and silent type mismatch if a consumer imports the wrong one.
- **Fix:** Delete `src/types/event_processing_result.rs`, remove from `types/mod.rs`, and re-export from `event_mapping::memory_types` if needed at the crate root.

---

### P1 — High (incorrect behavior under specific conditions)

#### P1-1: Grounding edge relation logic has dead zone
- **File:** `src/causal/edge_builder.rs:33-39`
- **Issue:** `add_grounding_edge()` maps score >= 0.7 → `Supports`, score < 0.2 → `Contradicts`, but scores in [0.2, 0.7) also map to `Supports`. This means a `Weak` verdict (score 0.2-0.4) creates a `Supports` edge, which is semantically wrong — weak grounding should not create a positive causal relationship.
- **Fix:** Add `Weakens` or use `Supports` only for >= 0.4, and `Contradicts` for < 0.4 (matching the Partial/Weak threshold).

#### P1-2: schema_version stored in bridge_metrics subject to retention cleanup
- **File:** `src/storage/migrations.rs:57-63`, `src/storage/retention.rs:31-33`
- **Issue:** `set_schema_version()` INSERTs into `bridge_metrics` with `metric_name = 'schema_version'`. Retention policy in `retention.rs:31-33` excludes `schema_version` from cleanup (`AND metric_name != 'schema_version'`), but this protection is fragile — any future retention refactor could accidentally delete the version marker, causing re-migration on next startup.
- **Fix:** Store schema version in a dedicated single-row table or use `PRAGMA user_version` with a bridge-specific offset.

#### P1-3: MemoryBuilder not used by mapper.rs
- **File:** `src/event_mapping/memory_builder.rs:1-241` vs `src/event_mapping/mapper.rs:92-163`
- **Issue:** `MemoryBuilder` was created to "eliminate repetitive `BaseMemory { ... }` blocks across mapper.rs" (per its doc comment), but `mapper.rs` still constructs `BaseMemory` manually in `create_memory()`. The builder is only used in tests. All 18 event handlers go through the manual path.
- **Impact:** Code duplication, higher maintenance burden, and inconsistency risk (builder clamps confidence, manual path doesn't).
- **Fix:** Refactor `create_memory()` to use `MemoryBuilder`.

#### P1-4: Decomposition provider uses fragile string matching for adjustment type
- **File:** `src/specification/decomposition_provider.rs:77-92`
- **Issue:** `query_priors_with_similarity()` determines `PriorAdjustmentType` by checking if the summary string contains "split", "merge", etc. This is extremely fragile — a summary like "We decided not to split the module" would incorrectly produce a `Split` adjustment. The hardcoded module names ("unknown", "part_a", "part_b", "a", "b", "merged") are placeholders that provide no useful information.
- **Fix:** Store the adjustment type as a structured JSON field in the memory content, and parse it from there instead of string-matching the summary.

#### P1-5: Weight provider queries bridge_memories for Skill type that's never created
- **File:** `src/specification/weight_provider.rs:145-151`
- **Issue:** `BridgeWeightProvider::get_weights()` queries `bridge_memories WHERE memory_type = 'Skill'`, but no code path in the bridge ever creates a memory with type `Skill`. The `MemoryType` enum in cortex-core includes `Skill`, but the bridge's event handlers only create `PatternRationale`, `Insight`, `Feedback`, `DecisionContext`, `ConstraintOverride`, `Tribal`, and `CodeSmell`. This query always returns 0 rows.
- **Impact:** Adaptive weights always fall back to static defaults. The entire weight persistence feature is non-functional.
- **Fix:** Create a `Skill` memory when adaptive weights are computed (in `compute_adaptive_weights()`), or change the query to read from a dedicated weights table.

#### P1-6: cortex_queries.rs tag search uses LIKE with incomplete pattern
- **File:** `src/query/cortex_queries.rs:76`
- **Issue:** `get_memories_by_tag()` constructs `format!("%\"{}%", tag)` for the LIKE pattern. This is missing the closing quote — it should be `%"tag"% ` to match a JSON array element. The current pattern `%"tag%` would match `"tag_extra"` and other partial matches. Also vulnerable to LIKE wildcards in the tag value itself (e.g., tag containing `%` or `_`).
- **Fix:** Use `json_each()` for proper JSON array membership testing, or at minimum fix the pattern to `%"{}"%`.

#### P1-7: Contradiction memory created but never persisted to bridge_memories
- **File:** `src/grounding/contradiction.rs:23-105`
- **Issue:** `generate_contradiction()` constructs a `BaseMemory` and returns its ID, but only persists it if `bridge_db` is `Some`. The caller in `loop_runner.rs:run()` does not pass `bridge_db` to the contradiction generator — it only calls `storage::record_grounding_result()`. The contradiction memory itself is constructed but dropped.
- **Fix:** Wire `bridge_db` through to `generate_contradiction()` in the grounding loop, or persist contradictions as part of `record_grounding_result()`.

#### P1-8: Event dedup hash doesn't include content-varying fields
- **File:** `src/event_mapping/dedup.rs:117-119`
- **Issue:** `compute_dedup_hash()` hashes `event_type:entity_id:extra`. For most event handlers in `mapper.rs`, the `extra` field is empty string `""` (dedup is called via `BridgeRuntime::is_duplicate_event()` in `lib.rs`). This means two `on_regression_detected` events for the same pattern but with different scores would be deduplicated as identical.
- **Impact:** Legitimate distinct events with the same entity_id but different payloads are silently dropped within the 60s TTL window.
- **Fix:** Include score/severity/reason in the dedup hash computation.

#### P1-9: NAPI mod.rs claims 15 functions but functions.rs has 20
- **File:** `src/napi/mod.rs:1` vs `src/napi/functions.rs`
- **Issue:** Module doc comment says "15 functions" but there are actually 20 NAPI-ready functions. Stale documentation.
- **Fix:** Update comment to "20 NAPI-ready bridge functions".

#### P1-10: configure_readonly_connection identical to configure_connection
- **File:** `src/storage/pragmas.rs:17-46`
- **Issue:** `configure_readonly_connection()` and `configure_connection()` execute the exact same PRAGMA set. The doc comment says "Same PRAGMAs except no auto_vacuum" but neither function sets auto_vacuum. This is dead code duplication.
- **Fix:** Either differentiate (e.g., set `query_only = ON` for readonly) or remove the duplicate and use a single function.

---

### P2 — Medium (suboptimal behavior, data quality issues)

#### P2-1: Grounding scorer doesn't use EvidenceConfig weight overrides
- **File:** `src/grounding/scorer.rs:25-50` vs `src/config/evidence_config.rs`
- **Issue:** `GroundingScorer::compute_score()` uses `evidence.weight` directly from the `GroundingEvidence` struct. The `EvidenceConfig` type exists with `weight_for()` method for operator-configurable weight overrides, but it's never wired into the scorer. The scorer has no reference to `EvidenceConfig`.
- **Fix:** Pass `EvidenceConfig` to `GroundingScorer::new()` and use `config.weight_for(&evidence.evidence_type)` instead of `evidence.weight`.

#### P2-2: EventConfig not wired into BridgeEventHandler
- **File:** `src/config/event_config.rs` vs `src/event_mapping/mapper.rs`
- **Issue:** `EventConfig` provides per-event enable/disable toggles, but `BridgeEventHandler` only checks `is_event_allowed()` which uses license tier filtering. The `EventConfig` is never consulted. Operators cannot disable specific noisy events without changing license tier.
- **Fix:** Add `EventConfig` to `BridgeEventHandler` and check `event_config.is_enabled(event_type)` in `is_event_allowed()`.

#### P2-3: Grounding loop doesn't use ErrorChain for batch error collection
- **File:** `src/grounding/loop_runner.rs:60-130` vs `src/errors/chain.rs`
- **Issue:** `GroundingLoopRunner::run()` processes memories in a loop and logs individual errors via `tracing::warn!`, but doesn't use the `ErrorChain` type that was specifically designed for "processing a batch (e.g., grounding 500 memories) where individual failures should not abort the entire batch." Error details are lost after logging.
- **Fix:** Accumulate errors in an `ErrorChain` and include it in the `GroundingSnapshot` return value.

#### P2-4: cross_db.rs count_matching_patterns builds dynamic SQL
- **File:** `src/query/cross_db.rs:40-55`
- **Issue:** `count_matching_patterns()` builds a dynamic IN clause with `format!("?{}", i)` placeholders. While the values are parameterized (safe from injection), the number of placeholders is unbounded. SQLite has a default `SQLITE_MAX_VARIABLE_NUMBER` of 999. Passing >999 pattern_ids will cause a runtime error.
- **Fix:** Chunk the query into batches of 500 IDs, or use a temp table approach.

#### P2-5: Specification events.rs creates placeholder memories for causal edges
- **File:** `src/specification/events.rs:284-318`
- **Issue:** `create_placeholder_memory()` creates a full `BaseMemory` with type `Insight` and content "Placeholder for module X" just to satisfy `CausalEngine::add_edge()` signature. These placeholders are never persisted but pollute the in-memory causal graph with fake nodes.
- **Fix:** Either persist the placeholder (making it a real node) or modify the causal edge API to accept IDs instead of full `BaseMemory` references.

#### P2-6: Retention not called automatically
- **File:** `src/storage/retention.rs:21-51`
- **Issue:** `apply_retention()` exists but is never called from `BridgeRuntime` or any scheduled task. Data accumulates indefinitely in all 5 bridge tables.
- **Fix:** Call `apply_retention()` during `BridgeRuntime::initialize()` and/or after each grounding loop completion.

#### P2-7: Usage tracker not persisted across restarts
- **File:** `src/license/usage_tracking.rs:34-45`
- **Issue:** `UsageTracker` is purely in-memory with `Instant`-based period tracking. On process restart, all usage counts reset to zero. A user could exceed daily limits by restarting the process.
- **Fix:** Persist usage counts to `bridge_metrics` table and load on startup. Use wall-clock time (chrono) instead of `Instant` for period tracking.

#### P2-8: Health check doesn't verify bridge_db
- **File:** `src/health/checks.rs:34-72`
- **Issue:** Health checks verify `cortex_db`, `drift_db`, and `causal_engine`, but not `bridge_db`. The bridge has 3 database connections (`drift_db`, `cortex_db`, `bridge_db`) but only 2 are health-checked. A corrupted or locked `bridge_db` would not be detected.
- **Fix:** Add `check_bridge_db()` health check.

#### P2-9: drift_why tool uses LIKE for memory search
- **File:** `src/tools/drift_why.rs:31-46`
- **Issue:** `handle_drift_why()` searches memories with `WHERE summary LIKE ?1 OR tags LIKE ?1` using `%entity_id%`. This is a full table scan with no index support, and will match partial strings (searching for pattern "auth" matches "authentication", "authorization", "oauth", etc.).
- **Fix:** Use FTS5 if available, or at minimum add an index on `bridge_memories(summary)` and use more specific matching.

#### P2-10: Grounding snapshot doesn't record trigger type
- **File:** `src/storage/tables.rs:77-93`, `src/grounding/scheduler.rs`
- **Issue:** `record_grounding_snapshot()` persists verdict counts and avg score, but doesn't record which `TriggerType` caused the grounding loop (PostScanIncremental, PostScanFull, Scheduled, OnDemand, etc.). This makes it impossible to analyze grounding performance by trigger type.
- **Fix:** Add `trigger_type TEXT` column to `bridge_grounding_snapshots` and pass it through.

#### P2-11: Intent resolver has 10 intents but extensions.rs defines different 10
- **File:** `src/intents/resolver.rs:24-116` vs `src/intents/extensions.rs:17-78`
- **Issue:** `resolver.rs` resolves intents like `explain_pattern`, `explain_violation`, `suggest_fix`, etc. `extensions.rs` defines intents like `add_feature`, `fix_bug`, `refactor`, `review_code`, etc. These are **completely disjoint sets** — no intent name appears in both. The resolver never resolves any of the 10 registered code intents.
- **Impact:** The intent system has two disconnected halves. `CODE_INTENTS` are never resolved, and the resolver's 10 intents are never registered.
- **Fix:** Unify the intent names, or create a mapping layer between the two.

#### P2-12: BridgeConfig doesn't include EventConfig or EvidenceConfig
- **File:** `src/config/bridge_config.rs:7-19`
- **Issue:** `BridgeConfig` contains `cortex_db_path`, `drift_db_path`, `enabled`, `license_tier`, and `grounding: GroundingConfig`. It does not include `EventConfig` or `EvidenceConfig`, even though both exist and are designed to be operator-configurable. They are unreachable from the runtime.
- **Fix:** Add `event_config: EventConfig` and `evidence_config: EvidenceConfig` fields to `BridgeConfig`.

#### P2-13: Feature matrix has 25 features but gating.rs has separate hardcoded check
- **File:** `src/license/feature_matrix.rs:22-179` vs `src/license/gating.rs:27-53`
- **Issue:** `LicenseTier::check()` in `gating.rs` uses hardcoded string matching for ~10 features. `feature_matrix.rs` has a comprehensive 25-entry `FEATURE_MATRIX` with `is_allowed()`. Both exist, neither calls the other. `BridgeEventHandler` uses `LicenseTier` directly (via `gating.rs`), not the feature matrix.
- **Impact:** Two parallel license-checking systems that can diverge. Adding a feature to one doesn't add it to the other.
- **Fix:** Deprecate `gating.rs::check()` and route all license checks through `feature_matrix::is_allowed()`.

#### P2-14: Grounding result ID is not a UUID
- **File:** `src/storage/schema.rs:7` vs `src/types/grounding_result.rs:13`
- **Issue:** `GroundingResult.id` is typed as `String` and set to a UUID in `loop_runner.rs`, but `bridge_grounding_results` uses `INTEGER PRIMARY KEY AUTOINCREMENT` for its `id` column. The UUID `id` from `GroundingResult` is never stored — the DB generates its own integer ID. The `GroundingResult.id` field is effectively dead.
- **Fix:** Either store the UUID in a separate column, or remove the `id` field from `GroundingResult` and use the DB-generated ID.

---

### P3 — Low (code quality, documentation, minor issues)

#### P3-1: lib.rs module count comment says 15 but lists 15 correctly
- **File:** `src/lib.rs:6`
- **Issue:** Comment says "Modules (15)" which is correct. No fix needed — noting for completeness.

#### P3-2: MemoryBuilder panics on missing content
- **File:** `src/event_mapping/memory_builder.rs:126-128`
- **Issue:** `build()` calls `expect("content must be set")` which panics. In a library crate, this should return `Result<BaseMemory, BridgeError>` instead of panicking.
- **Fix:** Return `BridgeResult<BaseMemory>` with a descriptive error.

#### P3-3: Causal error mapping uses BridgeError::Config for non-config errors
- **File:** `src/causal/edge_builder.rs:21`, `src/causal/counterfactual.rs:32`, `src/causal/intervention.rs:31`, `src/causal/pruning.rs:27`
- **Issue:** All causal module functions map errors with `BridgeError::Config(format!("... failed: {}", e))`. These are not configuration errors — they're runtime causal engine errors. Using `Config` variant obscures the actual error category.
- **Fix:** Add a `BridgeError::Causal { operation: String, source: String }` variant.

#### P3-4: DataSourceAttribution stats not persisted or used
- **File:** `src/specification/attribution.rs:28-55`
- **Issue:** `AttributionStats` tracks per-system accuracy rates but is never instantiated or persisted anywhere in the crate. It's a useful type with no consumers.
- **Fix:** Wire into the spec correction flow to track which Drift subsystems produce incorrect data most frequently.

#### P3-5: Duplicate EventProcessingResult import paths
- **File:** `src/event_mapping/memory_types.rs:24-40` vs `src/types/event_processing_result.rs:1-23`
- **Issue:** Same as P0-4 — the types module version is dead code.
- **Fix:** Covered by P0-4.

#### P3-6: GroundingDataSource lists 12 sources but evidence system uses 10
- **File:** `src/types/data_source.rs:6-32` vs `src/grounding/evidence/types.rs:33-44`
- **Issue:** `GroundingDataSource` has 12 variants (Patterns, Conventions, Constraints, Coupling, Dna, TestTopology, ErrorHandling, Decisions, Boundaries, Taint, CallGraph, Security). `EvidenceType` has 10 variants. The 2 extra sources (Taint, CallGraph) have no corresponding evidence collectors. The mapping between the two enums is implicit and undocumented.
- **Fix:** Either add evidence collectors for Taint and CallGraph, or document why they're excluded.

---

## Phase Plan

### Phase A: Correlation Pipeline Correctness (P0, 4-5 days)

| ID | Task | File(s) | Type |
|---|---|---|---|
| COR-01 | Rewrite all 10 drift queries to match actual drift-storage schema | `query/drift_queries.rs` | impl |
| COR-02 | Verify each rewritten query against drift-storage migrations | `query/drift_queries.rs` | impl |
| COR-03 | Wire confidence adjustment write-back after grounding | `grounding/loop_runner.rs`, `storage/tables.rs` | impl |
| COR-04 | Add UPDATE bridge_memories SET confidence for boost/penalize | `storage/tables.rs` | impl |
| COR-05 | Route event-created memories to cortex-storage (or NAPI callback) | `event_mapping/mapper.rs` | impl |
| COR-06 | Delete duplicate EventProcessingResult from types/ | `types/event_processing_result.rs`, `types/mod.rs` | impl |
| COR-07 | Wire bridge_db to contradiction generator in grounding loop | `grounding/loop_runner.rs`, `grounding/contradiction.rs` | impl |
| COR-T01 | Test: drift query returns real data from migrated drift.db | `tests/` | test |
| COR-T02 | Test: grounding loop updates memory confidence in bridge_memories | `tests/` | test |
| COR-T03 | Test: confidence never goes below 0.0 or above 1.0 after adjustment | `tests/` | test |
| COR-T04 | Test: contradiction memory persisted to bridge_memories | `tests/` | test |
| COR-T05 | Test: event-created memory visible to cortex retrieval | `tests/` | test |
| COR-T06 | Test: all 10 evidence types return data from real drift.db schema | `tests/` | test |

### Phase B: Grounding & Evidence Hardening (P1, 3-4 days)

| ID | Task | File(s) | Type |
|---|---|---|---|
| GRD-01 | Fix grounding edge relation dead zone (Weak → Supports bug) | `causal/edge_builder.rs` | impl |
| GRD-02 | Wire EvidenceConfig weight overrides into GroundingScorer | `grounding/scorer.rs`, `config/evidence_config.rs` | impl |
| GRD-03 | Use ErrorChain in grounding loop for batch error collection | `grounding/loop_runner.rs` | impl |
| GRD-04 | Add trigger_type to grounding snapshot persistence | `storage/tables.rs`, `storage/schema.rs` | impl |
| GRD-05 | Fix dedup hash to include content-varying fields | `event_mapping/dedup.rs` | impl |
| GRD-06 | Fix tag search LIKE pattern (missing closing quote) | `query/cortex_queries.rs` | impl |
| GRD-07 | Store GroundingResult UUID or remove dead id field | `types/grounding_result.rs`, `storage/tables.rs` | impl |
| GRD-T01 | Test: Weak verdict creates correct causal relation (not Supports) | `tests/` | test |
| GRD-T02 | Test: EvidenceConfig overrides change grounding score | `tests/` | test |
| GRD-T03 | Test: ErrorChain collects all failures in 500-memory batch | `tests/` | test |
| GRD-T04 | Test: dedup allows same entity_id with different scores | `tests/` | test |
| GRD-T05 | Test: tag search matches exact tag, not partial | `tests/` | test |
| GRD-T06 | Test: grounding snapshot records trigger type | `tests/` | test |

### Phase C: Specification & Causal Hardening (P1-P2, 2-3 days)

| ID | Task | File(s) | Type |
|---|---|---|---|
| SPC-01 | Replace string-matching decomposition type detection with structured JSON | `specification/decomposition_provider.rs` | impl |
| SPC-02 | Create Skill memory when adaptive weights are computed | `specification/weight_provider.rs` | impl |
| SPC-03 | Eliminate placeholder memories for causal edges | `specification/events.rs` | impl |
| SPC-04 | Add BridgeError::Causal variant for causal engine errors | `errors/bridge_error.rs`, `causal/*.rs` | impl |
| SPC-05 | Wire AttributionStats into spec correction flow | `specification/attribution.rs`, `specification/events.rs` | impl |
| SPC-06 | Unify intent names between resolver.rs and extensions.rs | `intents/resolver.rs`, `intents/extensions.rs` | impl |
| SPC-T01 | Test: decomposition prior type parsed from structured content | `tests/` | test |
| SPC-T02 | Test: adaptive weights persisted as Skill memory and retrieved | `tests/` | test |
| SPC-T03 | Test: causal edge created without placeholder memory | `tests/` | test |
| SPC-T04 | Test: all 10 code intents resolve to non-default data sources | `tests/` | test |
| SPC-T05 | Test: attribution stats track per-system accuracy | `tests/` | test |

### Phase D: Configuration & Infrastructure (P2, 2-3 days)

| ID | Task | File(s) | Type |
|---|---|---|---|
| INF-01 | Add EventConfig and EvidenceConfig to BridgeConfig | `config/bridge_config.rs` | impl |
| INF-02 | Wire EventConfig into BridgeEventHandler | `event_mapping/mapper.rs` | impl |
| INF-03 | Deprecate gating.rs::check(), route through feature_matrix | `license/gating.rs`, `license/feature_matrix.rs` | impl |
| INF-04 | Call apply_retention() from BridgeRuntime::initialize() | `lib.rs`, `storage/retention.rs` | impl |
| INF-05 | Persist UsageTracker counts to bridge_metrics | `license/usage_tracking.rs` | impl |
| INF-06 | Add check_bridge_db() health check | `health/checks.rs` | impl |
| INF-07 | Move schema_version to dedicated table or PRAGMA offset | `storage/migrations.rs` | impl |
| INF-08 | Chunk cross_db count_matching_patterns for >999 IDs | `query/cross_db.rs` | impl |
| INF-09 | Remove duplicate configure_readonly_connection or differentiate | `storage/pragmas.rs` | impl |
| INF-10 | Refactor mapper.rs to use MemoryBuilder | `event_mapping/mapper.rs` | impl |
| INF-T01 | Test: EventConfig disables specific events | `tests/` | test |
| INF-T02 | Test: EvidenceConfig overrides propagate to scorer | `tests/` | test |
| INF-T03 | Test: retention deletes old records on initialize | `tests/` | test |
| INF-T04 | Test: usage tracker survives process restart | `tests/` | test |
| INF-T05 | Test: bridge_db health check detects corruption | `tests/` | test |
| INF-T06 | Test: >999 pattern IDs handled without error | `tests/` | test |
| INF-T07 | Test: feature_matrix and gating.rs agree on all features | `tests/` | test |

### Phase E: Code Quality & Documentation (P3, 1-2 days)

| ID | Task | File(s) | Type |
|---|---|---|---|
| CQ-01 | Change MemoryBuilder::build() to return Result | `event_mapping/memory_builder.rs` | impl |
| CQ-02 | Update NAPI mod.rs comment (15 → 20 functions) | `napi/mod.rs` | impl |
| CQ-03 | Add evidence collectors for Taint and CallGraph or document exclusion | `grounding/evidence/` | impl |
| CQ-04 | Wire DataSourceAttribution into correction flow | `specification/attribution.rs` | impl |
| CQ-T01 | Test: MemoryBuilder returns error on missing content (no panic) | `tests/` | test |
| CQ-T02 | Test: all 12 GroundingDataSources have corresponding evidence type or documented exclusion | `tests/` | test |

---

## Dependency Graph

```
Phase A (P0, Correlation Pipeline)
  ├── COR-01..02 (drift query rewrite) — independent
  ├── COR-03..04 (confidence write-back) — depends on grounding loop
  ├── COR-05 (event→cortex routing) — independent
  ├── COR-06 (dedup type) — independent
  └── COR-07 (contradiction persistence) — depends on COR-03

Phase B (P1, Grounding & Evidence) — depends on Phase A (COR-01..02)
  ├── GRD-01 (edge relation) — independent
  ├── GRD-02 (evidence config) — independent
  ├── GRD-03 (error chain) — independent
  ├── GRD-04 (trigger type) — independent
  ├── GRD-05 (dedup hash) — independent
  ├── GRD-06 (tag search) — independent
  └── GRD-07 (result ID) — independent

Phase C (P1-P2, Specification & Causal) — parallelizable with Phase B
  ├── SPC-01..02 (decomposition + weights) — independent
  ├── SPC-03..04 (causal cleanup) — independent
  └── SPC-05..06 (attribution + intents) — independent

Phase D (P2, Infrastructure) — parallelizable with Phase B/C
  └── All tasks independent of each other

Phase E (P3, Code Quality) — after all other phases
```

**Critical path:** A(4-5d) → B(3-4d) → E(1-2d) = **8-11 working days**
**With 2 engineers:** A + {B,C,D parallel} + E = **6-8 working days**

---

## Summary Stats

| Metric | Count |
|---|---|
| Total findings | 34 |
| P0 (critical) | 4 |
| P1 (high) | 10 |
| P2 (medium) | 14 |
| P3 (low) | 6 |
| Implementation tasks | 39 |
| Test tasks | 30 |
| Total tasks | 69 |
| Estimated days (1 engineer) | 12-17 |
| Estimated days (2 engineers) | 8-11 |

---

## Key File Reference

| File | Lines | Role | Findings |
|---|---|---|---|
| `src/grounding/loop_runner.rs` | 470 | Grounding orchestrator | P0-2, P1-7, P2-3 |
| `src/query/drift_queries.rs` | 149 | Drift DB queries | P0-1 |
| `src/event_mapping/mapper.rs` | 564 | Event→memory handler | P0-3, P1-3, P2-2 |
| `src/storage/tables.rs` | 163 | Bridge table CRUD | P0-2, P2-10, P2-14 |
| `src/specification/decomposition_provider.rs` | 163 | Decomposition priors | P1-4 |
| `src/specification/weight_provider.rs` | 192 | Adaptive weights | P1-5 |
| `src/causal/edge_builder.rs` | 77 | Causal edge creation | P1-1 |
| `src/query/cortex_queries.rs` | 134 | Cortex DB queries | P1-6 |
| `src/intents/resolver.rs` | 159 | Intent resolution | P2-11 |
| `src/license/feature_matrix.rs` | 266 | Feature gating | P2-13 |
| `src/config/bridge_config.rs` | 32 | Bridge configuration | P2-12 |
| `src/storage/migrations.rs` | 164 | Schema versioning | P1-2 |
| `src/errors/bridge_error.rs` | 70 | Error types | P3-3 |
| `src/types/event_processing_result.rs` | 23 | Dead code | P0-4 |
