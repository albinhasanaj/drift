# Mapping Temporal Reasoning to Existing Cortex Architecture

## New Crate

### cortex-temporal
Owns: event store, snapshot engine, temporal query engine, state reconstruction,
temporal diff engine, drift detection, drift alerting, materialized temporal views.

Dependencies: cortex-core, cortex-storage, cortex-causal, cortex-observability

---

## Changes to Existing Crates

### cortex-storage
- New migration: `v014_temporal_tables.rs`
  - `memory_events` table (event sourcing log)
  - `memory_snapshots` table (periodic state snapshots)
  - `drift_snapshots` table (time-series drift metrics)
  - `materialized_views` table (pre-computed temporal views)
  - Indexes for temporal range queries on existing `memories` table
- New query module: `queries/temporal_ops.rs`
  - `get_events_for_memory(id, before)` — event replay
  - `get_nearest_snapshot(id, before)` — snapshot lookup
  - `get_memories_valid_at(valid_time, system_time)` — point-in-time
  - `get_memories_in_range(from, to, mode)` — temporal range

### cortex-core
- Add `MemoryEvent`, `MemoryEventType`, `EventActor` to models
- Add `DriftSnapshot`, `DriftAlert`, `DriftAlertCategory` to models
- Add `TemporalQuery` enum (AsOf, Range, Diff, Replay, TemporalCausal) to models
- Add `ITemporalEngine` trait to traits module
- Add `TemporalConfig` to config module (snapshot frequency, retention, alert thresholds)

### cortex-causal
- New module: `temporal_graph.rs`
  - `reconstruct_graph_at(timestamp)` — rebuild causal graph as it was at time T
  - `temporal_traversal(memory_id, as_of, direction)` — traverse historical graph
- Extend `graph/sync.rs` to log edge mutations as events

### cortex-validation
- Extend validation to use temporal context: "was this memory valid when it was created?"
- Temporal consistency check: memory references should be temporally consistent

### cortex-observability
- New metrics module: `metrics/drift_metrics.rs`
  - KSI per type, confidence trajectories, contradiction density, coverage ratios
- Extend health report with drift summary
- Drift alerts feed into existing alerting system

### cortex-consolidation
- Log consolidation events to event store (which memories were merged, what was created)
- Enable temporal replay of consolidation decisions

### cortex-napi
- New binding module: `bindings/temporal.rs`
  - queryAsOf, queryRange, queryDiff, replayDecision, temporalCausal
  - getDriftMetrics, getDriftAlerts, createMaterializedView

### packages/cortex (TypeScript)
- New MCP tools:
  - `drift_time_travel` — point-in-time knowledge query
  - `drift_time_diff` — compare knowledge between two times
  - `drift_time_replay` — replay decision context
  - `drift_knowledge_health` — drift metrics dashboard
  - `drift_knowledge_timeline` — visualize knowledge evolution
- New CLI commands:
  - `drift cortex timeline` — show knowledge evolution
  - `drift cortex diff --from <date> --to <date>` — temporal diff
  - `drift cortex replay <decision-id>` — decision replay

---

## Integration with Existing Event Sources

### Events We Already Generate (just need to route to event store)

| Source | Events | Current Destination | New Destination |
|--------|--------|--------------------|-----------------| 
| audit/logger.rs | All mutations | audit_log table | audit_log + memory_events |
| versioning/tracker.rs | Content updates | memory_versions table | memory_versions + memory_events |
| decay engine | Confidence changes | Direct update | memory_events + direct update |
| validation engine | Validation results | validation_history | validation_history + memory_events |
| consolidation engine | Merge/archive | audit_log | audit_log + memory_events |
| reclassification | Type changes | reclassification_history | reclassification_history + memory_events |

The key insight: we're not creating new events, we're routing existing events to an
additional destination (the event store) for temporal reconstruction.

---

## Migration Path

### Phase A: Event Store Foundation
1. Create `memory_events` and `memory_snapshots` tables (migration v014)
2. Implement event recording in cortex-temporal
3. Wire existing mutation paths to also emit events
4. Implement snapshot creation (periodic background task)

### Phase B: Temporal Queries
1. Implement state reconstruction (snapshot + replay)
2. Implement point-in-time queries (AS OF)
3. Implement temporal range queries (BETWEEN)
4. Implement temporal diff engine

### Phase C: Decision Replay + Temporal Causal
1. Implement decision replay (reconstruct retrieval context at past time)
2. Implement temporal causal graph reconstruction
3. Implement temporal causal traversal

### Phase D: Drift Detection + Alerting
1. Implement drift metric calculation
2. Implement drift snapshot storage (time-series)
3. Implement drift alerting rules
4. Wire into observability health report
5. Create materialized temporal views for sprint boundaries

---

## Backward Compatibility

- All existing queries continue to work (they implicitly query "as of now")
- Event recording adds ~0.1ms per mutation (append-only write)
- Snapshot creation runs in background, no impact on foreground operations
- Temporal queries are a new capability, not a change to existing behavior
- Storage overhead: ~330MB for 10K memories over 6 months (see EVENT-SOURCING.md)
