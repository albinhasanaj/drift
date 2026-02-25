# Phase C Prompt — Decision Replay + Temporal Causal

You are implementing Phase C of the cortex temporal reasoning addition. Read these files first:

- `TEMPORAL-TASK-TRACKER.md` (Phase C section, tasks `PTC-*` and tests `TTC-*`)
- `TEMPORAL-IMPLEMENTATION-SPEC.md`
- `FILE-MAP.md`

**Prerequisite:** QG-T1 has passed — Phase B's temporal query algebra and dual-time enforcement are fully operational. All `TTB-*` tests pass, `cargo test --workspace` is green, and coverage ≥80% on all Phase B modules. The AS OF, range, diff, and dual-time modules are working.

## What This Phase Builds

This phase adds decision replay (Query Type 4) and temporal causal graph reconstruction (Query Type 5). 7 impl tasks, 16 tests. Specifically:

1. **cortex-core**: 1 new model file (`decision_replay.rs`) + modify `models/mod.rs` — defines `DecisionReplay` struct (decision, available_context, retrieved_context, causal_state, hindsight), `HindsightItem` struct (memory, relevance, relationship), `CausalGraphSnapshot` struct (nodes, edges), `CausalEdgeSnapshot` struct
2. **cortex-causal**: 1 new file (`graph/temporal_graph.rs`) + modify `graph/mod.rs`:
   - `reconstruct_graph_at(event_store, as_of)` → builds `StableGraph` from RelationshipAdded/Removed/StrengthUpdated events before `as_of`. Process: collect added events → build edge set → apply removals → apply strength updates → build StableGraph
   - `temporal_traversal(memory_id, as_of, direction, max_depth)` → reconstructs historical graph, then reuses existing traversal logic on it
3. **cortex-temporal**: 2 new query files + engine update:
   - `query/replay.rs` — `execute_replay()`: the 10-step algorithm:
     1. Load decision memory
     2. Verify it's a decision type (error if not)
     3. Get decision creation time
     4. Reconstruct decision state at creation time
     5. Reconstruct all available context at decision time via `reconstruct_all_at`
     6. Simulate retrieval at decision time (call retrieval scoring on historical context)
     7. Reconstruct causal graph at decision time via `cortex_causal::temporal_graph`
     8. Get all memories created AFTER decision time
     9. Filter to those with embedding similarity > 0.7 to decision topic
     10. Classify each as "contradicts" / "would_have_informed" / "supersedes" / "supports"
   - `query/temporal_causal.rs` — `execute_temporal_causal()`: delegates to cortex-causal's `temporal_graph` module, passes reconstructed graph + traversal parameters
   - Modify `engine.rs` — implement `replay_decision` and `query_temporal_causal` methods on `TemporalEngine` (previously returned not-yet-implemented error)

## Critical Implementation Details

- **Decision replay is novel** — no existing AI memory system offers this. It requires the intersection of temporal state reconstruction + retrieval simulation + causal graph reconstruction. All three are available from Phases A and B.
- **Hindsight computation** answers: "Was this a good decision given what we knew? Would we make the same decision with what we know now?" Filter post-decision memories by similarity > 0.7 to the decision topic.
- **`classify_relationship`** determines how a hindsight item relates to the decision:
  - `"contradicts"` — the new memory contradicts the decision's reasoning
  - `"would_have_informed"` — the new memory is relevant and would have changed the context
  - `"supersedes"` — the new memory directly supersedes knowledge used in the decision
  - `"supports"` — the new memory reinforces the decision
- **Replay on a non-decision memory must error** — return an appropriate `TemporalError`.
- **Temporal causal at current time must equal current graph traversal** — this is the correctness invariant, same pattern as AS OF current == current state from Phase B.
- **Graph reconstruction from events**: added events build edges, removed events delete them, strength events update them. All ordered by event_id. Performance target: 1K edges < 10ms cold, < 2ms warm.
- **Edge removal is permanent at that point in time** — if an edge is added at T1 and removed at T2, temporal causal at T3 (T3 > T2) must NOT include that edge.
- **Strength updates apply to existing edges only** — if the edge was already removed, the strength update is a no-op.

## Reference Crate Patterns

For `temporal_graph.rs` in cortex-causal, match the existing patterns in `cortex-causal/src/graph/sync.rs` for how edges are persisted and queried. The traversal reuse should call into the existing `cortex-causal/src/traversal/` module with the reconstructed historical graph instead of the current graph.

For `query/replay.rs`, this is the most complex query handler. Look at how `cortex-consolidation/src/pipeline/` chains multiple phases together — the replay algorithm is similarly a multi-step pipeline.

## Task Checklist

Check off tasks in `TEMPORAL-TASK-TRACKER.md` as you complete them: `PTC-CORE-01` through `PTC-CORE-02`, `PTC-CAUSAL-01` through `PTC-CAUSAL-02`, `PTC-TEMP-01` through `PTC-TEMP-03`, and all `TTC-*` tests.

## Quality Gate QG-T2 Must Pass

- All `TTC-*` tests pass
- `cargo test -p cortex-temporal` — zero failures
- `cargo test -p cortex-causal` — zero failures (including new temporal_graph tests)
- `cargo test --workspace` — zero regressions
- Coverage ≥80% for cortex-temporal query/replay.rs
- Coverage ≥80% for cortex-temporal query/temporal_causal.rs
- Coverage ≥80% for cortex-causal graph/temporal_graph.rs
- Benchmark baselines established: decision replay < 200ms warm, temporal causal traversal < 20ms warm, graph reconstruction 1K edges < 10ms cold / < 2ms warm
