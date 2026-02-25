# 02 Temporal Reasoning — Complete File Map

> Every new and modified file required to implement TR1-TR18 + CR1-CR11.
> Follows existing Cortex conventions exactly: single-responsibility modules,
> per-subsystem `mod.rs` re-exports, `{name}_config.rs` configs,
> `{name}_error.rs` errors, per-subsystem NAPI bindings, per-subsystem
> MCP tools, per-subsystem golden fixtures.
>
> **Convention reference**: Patterns derived from cortex-causal (graph/sync,
> inference/strategies, traversal/*), cortex-consolidation (pipeline/phase*,
> monitoring/*, scheduling/*), cortex-validation (dimensions/*, healing/*),
> cortex-storage (migrations/v0*, queries/*), cortex-napi (bindings/*,
> conversions/*), packages/cortex (tools/*, cli/*).

---

## 1. Workspace Registration

### Modified: `crates/cortex/Cargo.toml`
- Add `"cortex-temporal"` to `[workspace.members]`
- Add `cortex-temporal = { path = "cortex-temporal" }` to `[workspace.dependencies]`
- **Covers**: TR14 (crate architecture)

---

## 2. New Crate: `cortex-temporal`

### `crates/cortex/cortex-temporal/Cargo.toml`
- Package metadata (name, version.workspace, edition.workspace, etc.)
- Dependencies: cortex-core, cortex-storage, chrono, serde, serde_json, tokio
- Dev-dependencies: proptest, criterion, test-fixtures, chrono, serde_json
- Bench target: `temporal_bench`
- **Covers**: TR14

### `crates/cortex/cortex-temporal/src/lib.rs`
- Crate root: module declarations, re-exports of public API
- Re-exports: TemporalEngine, EventStore, SnapshotEngine, all query types,
  drift types, epistemic types
- **Covers**: TR14

### `crates/cortex/cortex-temporal/src/engine.rs`
- `TemporalEngine` struct: implements `ITemporalEngine` trait
- Holds references to WriteConnection (writes) and ReadPool (reads) per CR5
- Orchestrates event_store, snapshot_engine, query modules, drift modules
- Single entry point for all temporal operations
- **Covers**: TR14, CR5

---

### Event Store Module (`src/event_store/`)

### `crates/cortex/cortex-temporal/src/event_store/mod.rs`
- Module declarations, re-exports
- **Covers**: TR1

### `crates/cortex/cortex-temporal/src/event_store/append.rs`
- `append(conn, event) -> Result<u64>` — append a single event
- `append_batch(conn, events) -> Result<Vec<u64>>` — batch append
- Idempotent write via single-transaction with audit_log (CR3, Strategy 1)
- **Covers**: TR1, CR3

### `crates/cortex/cortex-temporal/src/event_store/query.rs`
- `get_events(conn, memory_id, before) -> Vec<MemoryEvent>`
- `get_events_in_range(conn, memory_id, after, before) -> Vec<MemoryEvent>`
- `get_events_by_type(conn, event_type, before) -> Vec<MemoryEvent>`
- `get_all_events_in_range(conn, from, to) -> Vec<MemoryEvent>` (for diff)
- All reads use ReadPool per CR5
- **Covers**: TR1, CR5

### `crates/cortex/cortex-temporal/src/event_store/replay.rs`
- `replay_events(events, initial_state) -> BaseMemory` — apply events to state
- `apply_event(state, event) -> BaseMemory` — single event application
- Event type dispatch: 16 variants + Accessed (CR11)
- **Covers**: TR1, CR11

### `crates/cortex/cortex-temporal/src/event_store/upcaster.rs`
- `EventUpcaster` trait definition
- `UpcasterRegistry` — ordered list of upcasters, applied on read
- `upcast_event(raw_event) -> MemoryEvent` — schema version check + transform
- Default upcasters for v1 schema (identity — no-op for initial version)
- **Covers**: CR2

### `crates/cortex/cortex-temporal/src/event_store/compaction.rs`
- `compact_events(conn, before_date, verified_snapshot_id) -> CompactionResult`
- Moves old events to `memory_events_archive` table
- `CompactionResult` — count moved, space reclaimed
- Respects 6-month retention window
- **Covers**: CR4

---

### Snapshot Module (`src/snapshot/`)

### `crates/cortex/cortex-temporal/src/snapshot/mod.rs`
- Module declarations, re-exports
- **Covers**: TR2

### `crates/cortex/cortex-temporal/src/snapshot/create.rs`
- `create_snapshot(conn, memory_id, reason) -> Result<u64>`
- `create_batch_snapshots(conn, memory_ids, reason) -> Result<Vec<u64>>`
- Compresses state with zstd before storage
- **Covers**: TR2

### `crates/cortex/cortex-temporal/src/snapshot/lookup.rs`
- `get_nearest_snapshot(conn, memory_id, before) -> Option<MemorySnapshot>`
- `get_snapshots_for_memory(conn, memory_id) -> Vec<MemorySnapshot>`
- **Covers**: TR2

### `crates/cortex/cortex-temporal/src/snapshot/reconstruct.rs`
- `reconstruct_at(conn, memory_id, target_time) -> Option<BaseMemory>`
- `reconstruct_all_at(conn, target_time, filter) -> Vec<BaseMemory>`
- Core algorithm: find nearest snapshot → replay events since snapshot
- **Covers**: TR2, TR3 (Query Type 1 implementation)

### `crates/cortex/cortex-temporal/src/snapshot/retention.rs`
- `apply_retention_policy(conn, config) -> RetentionResult`
- Rules: 6 months full, then monthly, then quarterly
- Runs as background task alongside compaction
- **Covers**: TR2, CR4

### `crates/cortex/cortex-temporal/src/snapshot/triggers.rs`
- `AdaptiveSnapshotTrigger` — evaluates when to snapshot
- Trigger conditions: event threshold (50), periodic (weekly),
  pre-consolidation, on-demand (materialized view)
- **Covers**: TR2

---

### Query Module (`src/query/`)

### `crates/cortex/cortex-temporal/src/query/mod.rs`
- Module declarations, re-exports of all 5 query types
- `TemporalQueryDispatcher` — routes TemporalQuery enum to correct handler
- **Covers**: TR3

### `crates/cortex/cortex-temporal/src/query/as_of.rs`
- `execute_as_of(conn, query: AsOfQuery) -> Vec<BaseMemory>`
- Bitemporal filter: transaction_time <= S AND valid_time <= V AND
  (valid_until IS NULL OR valid_until > V)
- Uses reconstruct_all_at for full state reconstruction
- **Covers**: TR3 (Query Type 1)

### `crates/cortex/cortex-temporal/src/query/range.rs`
- `execute_range(conn, query: TemporalRangeQuery) -> Vec<BaseMemory>`
- 4 modes: Overlaps, Contains, StartedDuring, EndedDuring
- Optimized: uses existing memories table indexes for common case,
  falls back to event store for modified-during-range detection
- **Covers**: TR3 (Query Type 2)

### `crates/cortex/cortex-temporal/src/query/diff.rs`
- `execute_diff(conn, query: TemporalDiffQuery) -> TemporalDiff`
- Event-range optimization: query events between time_a and time_b,
  group by memory_id, classify as created/archived/modified
- Computes DiffStats (net change, confidence trend, churn rate)
- **Covers**: TR3 (Query Type 3)

### `crates/cortex/cortex-temporal/src/query/replay.rs`
- `execute_replay(conn, query: DecisionReplayQuery) -> DecisionReplay`
- Reconstructs decision memory at creation time
- Reconstructs available context at decision time
- Simulates retrieval at decision time (calls into retrieval scoring)
- Computes hindsight items (current knowledge - decision-time knowledge)
- **Covers**: TR3 (Query Type 4)

### `crates/cortex/cortex-temporal/src/query/temporal_causal.rs`
- `execute_temporal_causal(conn, query: TemporalCausalQuery) -> TraversalResult`
- Delegates to cortex-causal's temporal_graph module (TR10)
- Passes reconstructed graph + traversal parameters
- **Covers**: TR3 (Query Type 5)

### `crates/cortex/cortex-temporal/src/query/integrity.rs`
- `enforce_temporal_integrity(memories, relationships, query_time) -> Vec<BaseMemory>`
- Temporal join constraint: both endpoints valid at query time
- Causal edge temporal validity: exclude edges where either endpoint invalid
- Link temporal validity: filter stale file/pattern/function links
- Applied automatically by all query types
- **Covers**: TR5

---

### Dual-Time Module (`src/dual_time/`)

### `crates/cortex/cortex-temporal/src/dual_time/mod.rs`
- Module declarations, re-exports
- **Covers**: TR4

### `crates/cortex/cortex-temporal/src/dual_time/validation.rs`
- `validate_transaction_time_immutability(old, new) -> Result<()>`
- Rejects updates that modify transaction_time
- `validate_temporal_bounds(memory) -> Result<()>` — valid_time <= valid_until
- **Covers**: TR4

### `crates/cortex/cortex-temporal/src/dual_time/correction.rs`
- `apply_temporal_correction(conn, memory_id, corrected_valid_time) -> Result<()>`
- Closes old record's system_until, creates new record with corrected range
- Old record remains queryable at original system_time
- **Covers**: TR4

### `crates/cortex/cortex-temporal/src/dual_time/late_arrival.rs`
- `handle_late_arriving_fact(memory, actual_valid_time) -> BaseMemory`
- Sets transaction_time = now, valid_time = actual_valid_time
- Validates that valid_time < transaction_time (late discovery quadrant)
- **Covers**: TR4

---

### Drift Detection Module (`src/drift/`)

### `crates/cortex/cortex-temporal/src/drift/mod.rs`
- Module declarations, re-exports
- **Covers**: TR6, TR7, TR8, TR12

### `crates/cortex/cortex-temporal/src/drift/metrics.rs`
- `compute_ksi(conn, memory_type, window) -> f64` — Knowledge Stability Index
- `compute_confidence_trajectory(conn, memory_type, window) -> Vec<f64>`
- `compute_contradiction_density(conn, memory_type, window) -> f64`
- `compute_consolidation_efficiency(conn, window) -> f64`
- `compute_evidence_freshness(conn, memory) -> f64` — novel metric (TR6.5)
- `compute_evidence_freshness_index(conn) -> f64` — aggregate EFI
- `compute_all_metrics(conn, window) -> DriftSnapshot`
- **Covers**: TR6

### `crates/cortex/cortex-temporal/src/drift/evidence_freshness.rs`
- `freshness_factor(evidence) -> f64` — per-evidence-type freshness
- File link freshness: content_hash match → 1.0, mismatch → 0.5
- Pattern link freshness: active → 1.0, inactive → 0.3
- Supporting memory freshness: supporting_memory.confidence
- User validation freshness: decay(time_since_validation, half_life=90d)
- Product aggregation: Π(freshness_factor_i)
- **Covers**: TR6 (Metric 5)

### `crates/cortex/cortex-temporal/src/drift/alerting.rs`
- `evaluate_drift_alerts(snapshot: &DriftSnapshot, config) -> Vec<DriftAlert>`
- 6 alert categories: KnowledgeChurn, ConfidenceErosion, ContradictionSpike,
  StaleEvidence, KnowledgeExplosion, CoverageGap
- Configurable thresholds from TemporalConfig
- Alert dampening: cooldown per category + affected entity dedup
- **Covers**: TR7

### `crates/cortex/cortex-temporal/src/drift/snapshots.rs`
- `store_drift_snapshot(conn, snapshot) -> Result<u64>`
- `get_drift_snapshots(conn, from, to) -> Vec<DriftSnapshot>`
- `get_latest_drift_snapshot(conn) -> Option<DriftSnapshot>`
- Snapshot frequency: hourly (lightweight), daily (full), weekly (comprehensive)
- **Covers**: TR8

### `crates/cortex/cortex-temporal/src/drift/patterns.rs`
- `detect_crystallization(conn, topic_cluster) -> Option<CrystallizationPattern>`
- `detect_erosion(conn, memory_cluster) -> Option<ErosionPattern>`
- `detect_explosion(conn, module, baseline_window) -> Option<ExplosionPattern>`
- `detect_conflict_wave(conn, window) -> Option<ConflictWavePattern>`
- Each returns detection result + recommended action
- **Covers**: TR12

---

### Epistemic Module (`src/epistemic/`)

### `crates/cortex/cortex-temporal/src/epistemic/mod.rs`
- Module declarations, re-exports
- **Covers**: TR11

### `crates/cortex/cortex-temporal/src/epistemic/status.rs`
- `EpistemicStatus` enum: Conjecture, Provisional, Verified, Stale
- `determine_initial_status(source: &EventActor) -> EpistemicStatus`
- All new memories start as Conjecture
- **Covers**: TR11

### `crates/cortex/cortex-temporal/src/epistemic/transitions.rs`
- `promote_to_provisional(memory, evidence_count) -> EpistemicStatus`
- `promote_to_verified(memory, verified_by, evidence_refs) -> EpistemicStatus`
- `demote_to_stale(memory, reason) -> EpistemicStatus`
- Validation: Conjecture → Provisional → Verified is the only promotion path
- Stale can only come from Verified (evidence decay)
- **Covers**: TR11

### `crates/cortex/cortex-temporal/src/epistemic/aggregation.rs`
- `aggregate_confidence_weighted_avg(evidences) -> f64` — existing approach
- `aggregate_confidence_godel(evidences) -> f64` — Gödel t-norm (min operator)
- `aggregate_confidence(evidences, strategy) -> f64` — configurable dispatch
- **Covers**: TR11 (conservative confidence aggregation from TS11)

---

### Materialized Views Module (`src/views/`)

### `crates/cortex/cortex-temporal/src/views/mod.rs`
- Module declarations, re-exports
- **Covers**: TR9

### `crates/cortex/cortex-temporal/src/views/create.rs`
- `create_materialized_view(conn, label, timestamp) -> Result<MaterializedTemporalView>`
- Snapshots all active memories at timestamp
- Associates drift snapshot at that point
- **Covers**: TR9

### `crates/cortex/cortex-temporal/src/views/query.rs`
- `get_view(conn, label) -> Option<MaterializedTemporalView>`
- `list_views(conn) -> Vec<MaterializedTemporalView>`
- `diff_views(conn, label_a, label_b) -> TemporalDiff` — instant diff
- **Covers**: TR9

### `crates/cortex/cortex-temporal/src/views/auto_refresh.rs`
- `AutoRefreshScheduler` — auto-creates views at configurable intervals
- Default: every 2 weeks (sprint boundaries)
- Checks for new events since last view, skips if no changes
- **Covers**: TR9

---

### Tests & Benchmarks

### `crates/cortex/cortex-temporal/tests/temporal_test.rs`
- Unit/integration tests for event store, snapshot, reconstruction
- Event append + query round-trip
- Snapshot creation + lookup
- State reconstruction accuracy
- **Covers**: TR17

### `crates/cortex/cortex-temporal/tests/query_test.rs`
- Tests for all 5 query types
- AS OF current time = current state
- Range query with all 4 modes
- Diff identity (diff(T,T) = empty)
- Decision replay with known fixtures
- Temporal causal traversal
- **Covers**: TR17

### `crates/cortex/cortex-temporal/tests/drift_test.rs`
- Tests for all 5 drift metrics
- KSI bounds [0.0, 1.0]
- Evidence freshness bounds [0.0, 1.0]
- Alert threshold triggering
- Alert dampening (cooldown)
- **Covers**: TR17

### `crates/cortex/cortex-temporal/tests/epistemic_test.rs`
- Epistemic status transitions
- Promotion path validation (Conjecture → Provisional → Verified only)
- Stale detection from evidence decay
- Gödel t-norm vs weighted average aggregation
- **Covers**: TR17

### `crates/cortex/cortex-temporal/tests/golden_test.rs`
- Golden dataset tests against JSON fixtures
- 5 temporal reconstruction scenarios
- 3 temporal diff scenarios
- 2 decision replay scenarios
- 3 drift detection scenarios
- **Covers**: TR17

### `crates/cortex/cortex-temporal/tests/property_tests.rs`
- Entry point for proptest module
- **Covers**: TR17

### `crates/cortex/cortex-temporal/tests/property/mod.rs`
- Module declarations for property test files
- **Covers**: TR17

### `crates/cortex/cortex-temporal/tests/property/temporal_properties.rs`
- Replay consistency: replay(all_events) == current_state
- Snapshot + replay = full replay
- Temporal monotonicity: event_ids strictly increasing
- Diff symmetry: diff(A,B).created == diff(B,A).archived
- Diff identity: diff(T,T) == empty
- AS OF current == current state
- KSI bounds: 0.0 ≤ KSI ≤ 1.0
- Evidence freshness bounds: 0.0 ≤ freshness ≤ 1.0
- Epistemic ordering: only valid promotion paths
- Temporal referential integrity: no dangling references at any time T
- **Covers**: TR17

### `crates/cortex/cortex-temporal/tests/stress_test.rs`
- High-volume event append (100K events)
- Reconstruction under load (10K memories with snapshots)
- Concurrent temporal reads during writes
- Drift computation on large datasets
- **Covers**: TR17

### `crates/cortex/cortex-temporal/tests/coverage_test.rs`
- Ensures all public API surface is exercised
- Follows pattern from cortex-causal/tests/coverage_test.rs
- **Covers**: TR17

### `crates/cortex/cortex-temporal/benches/temporal_bench.rs`
- Event append latency (target: < 0.1ms)
- Single memory reconstruction, 50 events (target: < 5ms)
- Single memory reconstruction, snapshot + 10 events (target: < 1ms)
- Full state reconstruction, 10K memories (target: < 50ms)
- Temporal diff, two points, 10K memories (target: < 100ms)
- Decision replay (target: < 200ms)
- Drift metric computation, 10K memories (target: < 500ms)
- **Covers**: TR17

---

## 3. Golden Test Fixtures

### `crates/cortex/test-fixtures/golden/temporal/`
Directory for temporal golden test data.

### `crates/cortex/test-fixtures/golden/temporal/reconstruction_simple.json`
- 10 events for 1 memory, expected state at 3 time points
- **Covers**: TR17

### `crates/cortex/test-fixtures/golden/temporal/reconstruction_with_snapshot.json`
- 50 events + 1 snapshot, expected state at 5 time points
- **Covers**: TR17

### `crates/cortex/test-fixtures/golden/temporal/reconstruction_branching.json`
- Memory with consolidation + reclassification events, expected states
- **Covers**: TR17

### `crates/cortex/test-fixtures/golden/temporal/reconstruction_late_arrival.json`
- Late-arriving fact (valid_time < transaction_time), expected bitemporal state
- **Covers**: TR17

### `crates/cortex/test-fixtures/golden/temporal/reconstruction_correction.json`
- Temporal correction (old record closed, new record created), expected states
- **Covers**: TR17

### `crates/cortex/test-fixtures/golden/temporal/diff_sprint_boundary.json`
- Known state at sprint-12 and sprint-14, expected diff
- **Covers**: TR17

### `crates/cortex/test-fixtures/golden/temporal/diff_empty.json`
- Same time point, expected empty diff
- **Covers**: TR17

### `crates/cortex/test-fixtures/golden/temporal/diff_major_refactor.json`
- Before/after a major refactor, expected created/archived/modified counts
- **Covers**: TR17

### `crates/cortex/test-fixtures/golden/temporal/replay_auth_decision.json`
- Decision memory about auth, known context at decision time, expected replay
- **Covers**: TR17

### `crates/cortex/test-fixtures/golden/temporal/replay_with_hindsight.json`
- Decision + later knowledge that contradicts it, expected hindsight items
- **Covers**: TR17

### `crates/cortex/test-fixtures/golden/temporal/drift_stable.json`
- Stable knowledge base, expected KSI ≈ 1.0, no alerts
- **Covers**: TR17

### `crates/cortex/test-fixtures/golden/temporal/drift_erosion.json`
- Declining confidence trajectory, expected ConfidenceErosion alert
- **Covers**: TR17

### `crates/cortex/test-fixtures/golden/temporal/drift_explosion.json`
- Sudden memory creation spike, expected KnowledgeExplosion alert
- **Covers**: TR17

---

## 4. Modifications to `cortex-core`

### Modified: `crates/cortex/cortex-core/src/models/mod.rs`
- Add `pub mod temporal_event;`
- Add `pub mod drift_snapshot;`
- Add `pub mod drift_alert;`
- Add `pub mod temporal_query;`
- Add `pub mod epistemic_status;`
- Add `pub mod materialized_view;`
- Add `pub mod temporal_diff;`
- Add `pub mod decision_replay;`
- Re-export all new types
- **Covers**: TR15 (cortex-core additions)

### New: `crates/cortex/cortex-core/src/models/temporal_event.rs`
- `MemoryEvent` struct (event_id, memory_id, recorded_at, event_type,
  delta, actor, caused_by, schema_version)
- `MemoryEventType` enum (16 variants + Accessed)
- `EventActor` enum (User, Agent, System)
- `MemorySnapshot` struct (snapshot_id, memory_id, snapshot_at, state,
  event_id, snapshot_reason)
- `SnapshotReason` enum (EventThreshold, Periodic, PreOperation, OnDemand)
- **Covers**: TR1, TR2, CR2 (schema_version), CR11 (Accessed variant)

### New: `crates/cortex/cortex-core/src/models/drift_snapshot.rs`
- `DriftSnapshot` struct (timestamp, window, type_metrics, module_metrics, global)
- `TypeDriftMetrics` struct (count, avg_confidence, ksi, contradiction_density,
  consolidation_efficiency, evidence_freshness_index)
- `ModuleDriftMetrics` struct (memory_count, coverage_ratio, avg_confidence, churn_rate)
- `GlobalDriftMetrics` struct (total/active/archived memories, avg_confidence,
  overall_ksi, overall_contradiction_density, overall_evidence_freshness)
- **Covers**: TR8

### New: `crates/cortex/cortex-core/src/models/drift_alert.rs`
- `DriftAlert` struct (severity, category, message, affected_memories,
  recommended_action, detected_at)
- `AlertSeverity` enum (Info, Warning, Critical)
- `DriftAlertCategory` enum (KnowledgeChurn, ConfidenceErosion,
  ContradictionSpike, StaleEvidence, KnowledgeExplosion, CoverageGap)
- **Covers**: TR7

### New: `crates/cortex/cortex-core/src/models/temporal_query.rs`
- `AsOfQuery` struct (system_time, valid_time, filter)
- `TemporalRangeQuery` struct (from, to, mode)
- `TemporalRangeMode` enum (Overlaps, Contains, StartedDuring, EndedDuring)
- `TemporalDiffQuery` struct (time_a, time_b, scope)
- `DiffScope` enum (All, Types, Files, Namespace)
- `DecisionReplayQuery` struct (decision_memory_id, budget_override)
- `TemporalCausalQuery` struct (memory_id, as_of, direction, max_depth)
- **Covers**: TR3

### New: `crates/cortex/cortex-core/src/models/epistemic_status.rs`
- `EpistemicStatus` enum (Conjecture, Provisional, Verified, Stale)
- Each variant carries its own metadata (source, evidence_count, verified_by, etc.)
- `AggregationStrategy` enum (WeightedAverage, GodelTNorm)
- **Covers**: TR11

### New: `crates/cortex/cortex-core/src/models/materialized_view.rs`
- `MaterializedTemporalView` struct (view_id, label, timestamp, memory_count,
  snapshot_ids, drift_snapshot_id, created_by, auto_refresh)
- **Covers**: TR9

### New: `crates/cortex/cortex-core/src/models/temporal_diff.rs`
- `TemporalDiff` struct (created, archived, modified, confidence_shifts,
  new_contradictions, resolved_contradictions, reclassifications, stats)
- `MemoryModification` struct (memory_id, field, old_value, new_value)
- `ConfidenceShift` struct (memory_id, old_confidence, new_confidence, delta)
- `DiffStats` struct (memories_at_a, memories_at_b, net_change,
  avg_confidence_at_a, avg_confidence_at_b, confidence_trend, knowledge_churn_rate)
- **Covers**: TR3 (Query Type 3)

### New: `crates/cortex/cortex-core/src/models/decision_replay.rs`
- `DecisionReplay` struct (decision, available_context, retrieved_context,
  causal_state, hindsight)
- `HindsightItem` struct (memory, relevance, relationship)
- `CausalGraphSnapshot` — serializable snapshot of petgraph state at a time
- **Covers**: TR3 (Query Type 4)

---

### Modified: `crates/cortex/cortex-core/src/errors/mod.rs`
- Add `pub mod temporal_error;`
- Re-export `TemporalError`
- **Covers**: TR15

### New: `crates/cortex/cortex-core/src/errors/temporal_error.rs`
- `TemporalError` enum:
  - `EventAppendFailed(String)`
  - `SnapshotCreationFailed(String)`
  - `ReconstructionFailed(String)`
  - `QueryFailed(String)`
  - `InvalidTemporalBounds(String)` — valid_time > valid_until
  - `ImmutableFieldViolation(String)` — transaction_time modification attempt
  - `SchemaVersionMismatch { expected: u16, found: u16 }`
  - `CompactionFailed(String)`
  - `InvalidEpistemicTransition { from: String, to: String }`
- Implements `From<TemporalError> for CortexError`
- **Covers**: TR15, CR2

---

### Modified: `crates/cortex/cortex-core/src/traits/mod.rs`
- Add `pub mod temporal_engine;`
- Re-export `ITemporalEngine`
- **Covers**: TR15

### New: `crates/cortex/cortex-core/src/traits/temporal_engine.rs`
- `ITemporalEngine` trait (async_trait):
  - `record_event(&self, event) -> Result<u64>`
  - `get_events(&self, memory_id, before) -> Result<Vec<MemoryEvent>>`
  - `reconstruct_at(&self, memory_id, as_of) -> Result<Option<BaseMemory>>`
  - `reconstruct_all_at(&self, as_of, filter) -> Result<Vec<BaseMemory>>`
  - `query_as_of(&self, query) -> Result<Vec<BaseMemory>>`
  - `query_range(&self, query) -> Result<Vec<BaseMemory>>`
  - `query_diff(&self, query) -> Result<TemporalDiff>`
  - `replay_decision(&self, query) -> Result<DecisionReplay>`
  - `query_temporal_causal(&self, query) -> Result<TraversalResult>`
  - `compute_drift_metrics(&self, window) -> Result<DriftSnapshot>`
  - `get_drift_alerts(&self) -> Result<Vec<DriftAlert>>`
  - `create_view(&self, label, timestamp) -> Result<MaterializedTemporalView>`
  - `get_view(&self, label) -> Result<Option<MaterializedTemporalView>>`
- **Covers**: TR14

---

### Modified: `crates/cortex/cortex-core/src/config/mod.rs`
- Add `pub mod temporal_config;`
- Re-export `TemporalConfig`
- **Covers**: TR15

### New: `crates/cortex/cortex-core/src/config/temporal_config.rs`
- `TemporalConfig` struct:
  - `snapshot_event_threshold: u64` (default: 50)
  - `snapshot_periodic_interval_hours: u64` (default: 168 = weekly)
  - `snapshot_retention_full_days: u64` (default: 180 = 6 months)
  - `snapshot_retention_monthly_days: u64` (default: 730 = 2 years)
  - `event_compaction_age_days: u64` (default: 180)
  - `drift_hourly_enabled: bool` (default: true)
  - `drift_daily_enabled: bool` (default: true)
  - `drift_weekly_enabled: bool` (default: true)
  - `alert_ksi_threshold: f64` (default: 0.3)
  - `alert_confidence_erosion_windows: u32` (default: 2)
  - `alert_contradiction_density_threshold: f64` (default: 0.10)
  - `alert_evidence_freshness_threshold: f64` (default: 0.5)
  - `alert_explosion_sigma: f64` (default: 3.0)
  - `alert_cooldown_warning_hours: u64` (default: 24)
  - `alert_cooldown_critical_hours: u64` (default: 1)
  - `epistemic_auto_promote: bool` (default: true)
  - `confidence_aggregation: AggregationStrategy` (default: WeightedAverage)
  - `materialized_view_auto_interval_days: u64` (default: 14)
- `impl Default for TemporalConfig`
- **Covers**: TR7 (thresholds), TR8 (frequencies), TR9 (auto-refresh),
  TR11 (epistemic config), CR4 (compaction age)

---

## 5. Modifications to `cortex-storage`

### Modified: `crates/cortex/cortex-storage/src/migrations/mod.rs`
- Add `pub mod v014_temporal_tables;`
- Register v014 in migration runner
- **Covers**: TR15

### New: `crates/cortex/cortex-storage/src/migrations/v014_temporal_tables.rs`
- `memory_events` table + 3 indexes (memory_time, time, type)
  - Includes `schema_version INTEGER NOT NULL DEFAULT 1` (CR2)
- `memory_events_archive` table (same schema + archived_at) (CR4)
- `memory_snapshots` table + 1 index (memory_time)
  - Includes `reason TEXT NOT NULL` column
- `drift_snapshots` table + 1 index (timestamp)
- `materialized_views` table
- Temporal indexes on existing `memories` table:
  - `idx_memories_valid_range ON memories(valid_time, valid_until) WHERE archived = 0`
  - `idx_memories_transaction_range ON memories(transaction_time)`
- **Covers**: TR1, TR2, TR8, TR9, CR2, CR4

### Modified: `crates/cortex/cortex-storage/src/queries/mod.rs`
- Add `pub mod temporal_ops;`
- Add `pub mod event_ops;`
- Add `pub mod snapshot_ops;`
- Add `pub mod drift_ops;`
- Add `pub mod view_ops;`
- **Covers**: TR15

### New: `crates/cortex/cortex-storage/src/queries/event_ops.rs`
- `insert_event(conn, event) -> Result<u64>`
- `insert_event_batch(conn, events) -> Result<Vec<u64>>`
- `get_events_for_memory(conn, memory_id, before) -> Result<Vec<RawEvent>>`
- `get_events_in_range(conn, from, to) -> Result<Vec<RawEvent>>`
- `get_events_by_type(conn, event_type, before) -> Result<Vec<RawEvent>>`
- `get_event_count(conn, memory_id) -> Result<u64>`
- `move_events_to_archive(conn, before_date, snapshot_id) -> Result<u64>`
- Raw SQL operations, no business logic
- **Covers**: TR1, CR4

### New: `crates/cortex/cortex-storage/src/queries/snapshot_ops.rs`
- `insert_snapshot(conn, snapshot) -> Result<u64>`
- `get_nearest_snapshot(conn, memory_id, before) -> Result<Option<RawSnapshot>>`
- `get_snapshots_for_memory(conn, memory_id) -> Result<Vec<RawSnapshot>>`
- `delete_old_snapshots(conn, retention_policy) -> Result<u64>`
- Raw SQL operations
- **Covers**: TR2

### New: `crates/cortex/cortex-storage/src/queries/temporal_ops.rs`
- `get_memories_valid_at(conn, valid_time, system_time) -> Result<Vec<BaseMemory>>`
- `get_memories_in_range(conn, from, to, mode) -> Result<Vec<BaseMemory>>`
- `get_memories_modified_between(conn, from, to) -> Result<Vec<String>>` (memory_ids)
- Temporal join queries with referential integrity (TR5)
- **Covers**: TR3, TR5

### New: `crates/cortex/cortex-storage/src/queries/drift_ops.rs`
- `insert_drift_snapshot(conn, snapshot) -> Result<u64>`
- `get_drift_snapshots(conn, from, to) -> Result<Vec<RawDriftSnapshot>>`
- `get_latest_drift_snapshot(conn) -> Result<Option<RawDriftSnapshot>>`
- **Covers**: TR8

### New: `crates/cortex/cortex-storage/src/queries/view_ops.rs`
- `insert_materialized_view(conn, view) -> Result<u64>`
- `get_view_by_label(conn, label) -> Result<Option<RawView>>`
- `list_views(conn) -> Result<Vec<RawView>>`
- `delete_view(conn, label) -> Result<()>`
- **Covers**: TR9

---

## 6. Modifications to `cortex-causal`

### Modified: `crates/cortex/cortex-causal/src/graph/mod.rs`
- Add `pub mod temporal_graph;`
- **Covers**: TR10, TR15

### New: `crates/cortex/cortex-causal/src/graph/temporal_graph.rs`
- `reconstruct_graph_at(event_store, as_of) -> StableGraph<MemoryId, CausalEdge>`
  - Gets all RelationshipAdded events before as_of
  - Gets all RelationshipRemoved events before as_of
  - Builds graph with edges added but not yet removed
  - Uses edge strengths as they were at as_of
- `temporal_traversal(memory_id, as_of, direction, max_depth) -> TraversalResult`
  - Reconstructs historical graph, runs existing traversal on it
- **Covers**: TR10

### Modified: `crates/cortex/cortex-causal/src/graph/sync.rs`
- Extend `persist_edge()` to also emit RelationshipAdded event
- Extend `remove_persisted_edge()` to also emit RelationshipRemoved event
- Extend `update_persisted_strength()` to also emit StrengthUpdated event
- Uses single-transaction pattern (CR3) for atomicity
- **Covers**: TR10, TR15, CR3

---

## 7. Modifications to `cortex-validation`

### Modified: `crates/cortex/cortex-validation/src/engine.rs`
- After validation pass/fail, trigger epistemic status transition:
  - Pass all 4 dimensions → promote to Provisional (if Conjecture)
  - Pass all 4 dimensions + user confirmation → promote to Verified
  - Fail → no demotion (epistemic status only degrades via evidence decay)
- **Covers**: TR11, TR15

### Modified: `crates/cortex/cortex-validation/src/dimensions/temporal.rs`
- Add temporal consistency check: memory references should be temporally
  consistent (referenced memories must have existed when the referencing
  memory was created)
- **Covers**: TR5, TR15

---

## 8. Modifications to `cortex-observability`

### Modified: `crates/cortex/cortex-observability/src/health/reporter.rs`
- Add `drift_summary: Option<DriftSummary>` to `HealthSnapshot`
- `DriftSummary` struct: active_alerts count, overall_ksi, overall_efi,
  trend indicators (improving/stable/declining)
- **Covers**: TR7, TR15

### Modified: `crates/cortex/cortex-observability/src/health/subsystem_checks.rs`
- Add `check_temporal(snapshot) -> SubsystemHealth`
- Checks: event store health, snapshot freshness, drift alert count
- **Covers**: TR15

### Modified: `crates/cortex/cortex-observability/src/health/recommendations.rs`
- Add temporal-specific recommendations:
  - "Run snapshot compaction" if events > threshold
  - "Review stale evidence" if EFI < 0.5
  - "Investigate knowledge churn" if KSI < 0.3
- **Covers**: TR7, TR15

---

## 9. Modifications to `cortex-consolidation`

### Modified: `crates/cortex/cortex-consolidation/src/engine.rs`
- After consolidation completes, emit Consolidated events for all
  participating memories (merged, created, archived)
- Uses single-transaction pattern (CR3)
- **Covers**: TR15, CR3

### Modified: `crates/cortex/cortex-consolidation/src/pipeline/phase6_pruning.rs`
- Before archiving memories during pruning, emit Archived events
- **Covers**: TR15

---

## 10. Modifications to `cortex-decay`

### Modified: `crates/cortex/cortex-decay/src/engine.rs`
- After applying decay to a memory's confidence, emit Decayed event
  with { old_confidence, new_confidence, decay_factor }
- **Covers**: TR15

---

## 11. Modifications to `cortex-reclassification`

### Modified: `crates/cortex/cortex-reclassification/src/engine.rs`
- After reclassifying a memory, emit Reclassified event
  with { old_type, new_type, reason, confidence }
- **Covers**: TR15

---

## 12. Modifications to `cortex-retrieval`

### Modified: `crates/cortex/cortex-retrieval/src/ranking/scorer.rs`
- Add 2 new scoring factors: evidence_freshness (0.06), epistemic_status (0.05)
- Redistribute existing weights to accommodate (per CR8)
- `evidence_freshness_score(memory) -> f64` — from temporal engine
- `epistemic_status_score(memory) -> f64` — Verified=1.0, Provisional=0.7,
  Conjecture=0.4, Stale=0.2
- **Covers**: TR13, CR8

### Modified: `crates/cortex/cortex-retrieval/src/ranking/mod.rs`
- Update ScorerWeights default to include new temporal factors
- **Covers**: TR13, CR8

---

## 13. Modifications to `cortex-napi`

### Modified: `crates/cortex/cortex-napi/src/bindings/mod.rs`
- Add `pub mod temporal;`
- **Covers**: TR15

### New: `crates/cortex/cortex-napi/src/bindings/temporal.rs`
- `query_as_of(system_time, valid_time, filter) -> Vec<NapiBaseMemory>`
- `query_range(from, to, mode) -> Vec<NapiBaseMemory>`
- `query_diff(time_a, time_b, scope) -> NapiTemporalDiff`
- `replay_decision(decision_id, budget) -> NapiDecisionReplay`
- `query_temporal_causal(memory_id, as_of, direction, depth) -> NapiTraversalResult`
- `get_drift_metrics(window_hours) -> NapiDriftSnapshot`
- `get_drift_alerts() -> Vec<NapiDriftAlert>`
- `create_materialized_view(label, timestamp) -> NapiMaterializedView`
- `get_materialized_view(label) -> Option<NapiMaterializedView>`
- `list_materialized_views() -> Vec<NapiMaterializedView>`
- All functions are `#[napi]` annotated
- **Covers**: TR15

### Modified: `crates/cortex/cortex-napi/src/conversions/mod.rs`
- Add `pub mod temporal_types;`
- **Covers**: TR15

### New: `crates/cortex/cortex-napi/src/conversions/temporal_types.rs`
- `NapiMemoryEvent` — JS-friendly MemoryEvent
- `NapiDriftSnapshot` — JS-friendly DriftSnapshot
- `NapiDriftAlert` — JS-friendly DriftAlert
- `NapiTemporalDiff` — JS-friendly TemporalDiff
- `NapiDecisionReplay` — JS-friendly DecisionReplay
- `NapiMaterializedView` — JS-friendly MaterializedTemporalView
- `NapiHindsightItem` — JS-friendly HindsightItem
- `NapiDiffStats` — JS-friendly DiffStats
- From/Into conversions between Rust and NAPI types
- **Covers**: TR15

---

## 14. Modifications to TypeScript Package (`packages/cortex`)

### Modified: `packages/cortex/src/bridge/types.ts`
- Add TypeScript interfaces:
  - `TemporalDiff`, `DiffStats`, `MemoryModification`, `ConfidenceShift`
  - `DecisionReplay`, `HindsightItem`, `CausalGraphSnapshot`
  - `DriftSnapshot`, `TypeDriftMetrics`, `ModuleDriftMetrics`, `GlobalDriftMetrics`
  - `DriftAlert`, `AlertSeverity`, `DriftAlertCategory`
  - `MaterializedTemporalView`
  - `EpistemicStatus`
  - `AsOfQuery`, `TemporalRangeQuery`, `TemporalDiffQuery`
  - `DecisionReplayQuery`, `TemporalCausalQuery`
- **Covers**: TR15

### Modified: `packages/cortex/src/bridge/client.ts`
- Add temporal methods:
  - `queryAsOf(systemTime, validTime, filter?)`
  - `queryRange(from, to, mode)`
  - `queryDiff(timeA, timeB, scope?)`
  - `replayDecision(decisionId, budget?)`
  - `queryTemporalCausal(memoryId, asOf, direction, maxDepth)`
  - `getDriftMetrics(windowHours)`
  - `getDriftAlerts()`
  - `createMaterializedView(label, timestamp)`
  - `getMaterializedView(label)`
  - `listMaterializedViews()`
- **Covers**: TR15

---

### MCP Tools (new directory)

### `packages/cortex/src/tools/temporal/`
Directory for temporal MCP tools.

### `packages/cortex/src/tools/temporal/drift_time_travel.ts`
- MCP tool: `drift_time_travel`
- Input: system_time, valid_time, filter (optional)
- Output: memories as they existed at that point in time
- Calls bridge.queryAsOf()
- **Covers**: TR15

### `packages/cortex/src/tools/temporal/drift_time_diff.ts`
- MCP tool: `drift_time_diff`
- Input: time_a, time_b, scope (optional)
- Output: structured diff (created, archived, modified, stats)
- Calls bridge.queryDiff()
- **Covers**: TR15

### `packages/cortex/src/tools/temporal/drift_time_replay.ts`
- MCP tool: `drift_time_replay`
- Input: decision_memory_id, budget (optional)
- Output: decision replay with hindsight items
- Calls bridge.replayDecision()
- **Covers**: TR15

### `packages/cortex/src/tools/temporal/drift_knowledge_health.ts`
- MCP tool: `drift_knowledge_health`
- Input: window_hours (optional, default 168 = 1 week)
- Output: drift metrics dashboard (KSI per type, confidence trajectories,
  contradiction density, consolidation efficiency, EFI, active alerts)
- Calls bridge.getDriftMetrics() + bridge.getDriftAlerts()
- **Covers**: TR15

### `packages/cortex/src/tools/temporal/drift_knowledge_timeline.ts`
- MCP tool: `drift_knowledge_timeline`
- Input: from, to, granularity (optional: hourly/daily/weekly)
- Output: time-series of drift snapshots for visualization
- Calls bridge.getDriftMetrics() for each time point
- **Covers**: TR15

### Modified: `packages/cortex/src/tools/index.ts`
- Register all 5 new temporal tools
- **Covers**: TR15

---

### CLI Commands (new files)

### `packages/cortex/src/cli/timeline.ts`
- CLI command: `drift cortex timeline`
- Shows knowledge evolution over time
- Options: --from, --to, --type, --module
- Calls bridge.getDriftMetrics() for time range
- **Covers**: TR15

### `packages/cortex/src/cli/diff.ts`
- CLI command: `drift cortex diff`
- Compares knowledge between two time points
- Options: --from (required), --to (required), --scope
- Calls bridge.queryDiff()
- **Covers**: TR15

### `packages/cortex/src/cli/replay.ts`
- CLI command: `drift cortex replay`
- Replays decision context
- Options: <decision-id> (required), --budget
- Calls bridge.replayDecision()
- **Covers**: TR15

### Modified: `packages/cortex/src/cli/index.ts`
- Register timeline, diff, replay commands
- **Covers**: TR15

---

### TypeScript Tests

### Modified: `packages/cortex/tests/bridge.test.ts`
- Add test cases for all temporal bridge methods
- queryAsOf, queryRange, queryDiff, replayDecision, queryTemporalCausal
- getDriftMetrics, getDriftAlerts
- createMaterializedView, getMaterializedView, listMaterializedViews
- **Covers**: TR17

---

## 15. Modifications to `cortex-storage` (Mutation Path Wiring)

These are the existing files where event emission must be added.
Each modification is a small addition (emit event alongside existing operation).

### Modified: `crates/cortex/cortex-storage/src/queries/memory_crud.rs`
- `create_memory()`: emit Created event in same transaction
- `update_memory()`: emit ContentUpdated/TagsModified/etc. based on changed fields
- `archive_memory()`: emit Archived event
- `restore_memory()`: emit Restored event
- **Covers**: TR1, CR3

### Modified: `crates/cortex/cortex-storage/src/queries/audit_ops.rs`
- `record_audit()`: also call event_ops::insert_event() in same transaction
- **Covers**: TR1, CR3

### Modified: `crates/cortex/cortex-storage/src/queries/link_ops.rs`
- `add_link()`: emit LinkAdded event
- `remove_link()`: emit LinkRemoved event
- **Covers**: TR1

### Modified: `crates/cortex/cortex-storage/src/queries/version_ops.rs`
- `create_version()`: emit ContentUpdated event with version delta
- **Covers**: TR1

---

## Summary

### File Counts

| Category | New Files | Modified Files |
|----------|-----------|----------------|
| cortex-temporal crate (src/) | 40 | 0 |
| cortex-temporal crate (tests/) | 10 | 0 |
| cortex-temporal crate (benches/) | 1 | 0 |
| cortex-core models | 7 | 1 |
| cortex-core errors | 1 | 1 |
| cortex-core traits | 1 | 1 |
| cortex-core config | 1 | 1 |
| cortex-storage migrations | 1 | 1 |
| cortex-storage queries | 5 | 4 |
| cortex-causal | 1 | 2 |
| cortex-validation | 0 | 2 |
| cortex-observability | 0 | 3 |
| cortex-consolidation | 0 | 2 |
| cortex-decay | 0 | 1 |
| cortex-reclassification | 0 | 1 |
| cortex-retrieval | 0 | 2 |
| cortex-napi | 2 | 2 |
| Golden test fixtures | 13 | 0 |
| TypeScript bridge | 0 | 2 |
| TypeScript MCP tools | 5 | 1 |
| TypeScript CLI | 3 | 1 |
| TypeScript tests | 0 | 1 |
| Workspace config | 0 | 1 |
| **TOTAL** | **91** | **31** |

### Recommendation Coverage Matrix

| Recommendation | Files That Cover It |
|---|---|
| TR1 (Event Store) | event_store/*.rs, event_ops.rs, v014, temporal_event.rs, memory_crud.rs, audit_ops.rs, link_ops.rs, version_ops.rs |
| TR2 (Snapshots) | snapshot/*.rs, snapshot_ops.rs, v014, temporal_event.rs |
| TR3 (Query Algebra) | query/*.rs, temporal_ops.rs, temporal_query.rs, temporal_diff.rs, decision_replay.rs |
| TR4 (Dual-Time) | dual_time/*.rs |
| TR5 (Temporal Integrity) | query/integrity.rs, temporal_ops.rs, validation/temporal.rs |
| TR6 (Drift Metrics) | drift/metrics.rs, drift/evidence_freshness.rs |
| TR7 (Drift Alerting) | drift/alerting.rs, drift_alert.rs, reporter.rs, recommendations.rs |
| TR8 (Drift Snapshots) | drift/snapshots.rs, drift_ops.rs, drift_snapshot.rs, v014 |
| TR9 (Materialized Views) | views/*.rs, view_ops.rs, materialized_view.rs, v014 |
| TR10 (Temporal Causal) | temporal_graph.rs, sync.rs (modified) |
| TR11 (Epistemic) | epistemic/*.rs, epistemic_status.rs, validation/engine.rs |
| TR12 (Evolution Patterns) | drift/patterns.rs |
| TR13 (Retrieval Boosting) | scorer.rs (modified), ranking/mod.rs (modified) |
| TR14 (Crate Architecture) | Cargo.toml, lib.rs, engine.rs |
| TR15 (Existing Crate Changes) | All modified files across 9 crates + NAPI + TypeScript |
| TR16 (Migration Path) | Covered by phase ordering of all files |
| TR17 (Testing) | All test files, golden fixtures, benchmarks |
| TR18 (Backward Compat) | Enforced by additive-only design across all files |
| CR2 (Schema Versioning) | upcaster.rs, temporal_event.rs (schema_version), temporal_error.rs |
| CR3 (Idempotent Recording) | append.rs, memory_crud.rs, audit_ops.rs, sync.rs |
| CR4 (Compaction) | compaction.rs, retention.rs, event_ops.rs, v014 (archive table) |
| CR5 (Concurrency) | engine.rs (TemporalEngine holds writer + readers) |
| CR8 (Scorer Correction) | scorer.rs, ranking/mod.rs |
| CR10 (Event Ordering) | append.rs (AUTOINCREMENT + Mutex guarantees) |
| CR11 (Replay Verification) | replay.rs (Accessed variant), temporal_event.rs |
