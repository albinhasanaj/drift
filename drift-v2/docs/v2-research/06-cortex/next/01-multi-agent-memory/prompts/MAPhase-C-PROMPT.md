# MAPhase C — Delta Sync + Trust + Provenance

> **ULTRA THINK. Quality over speed. No shortcuts. Enterprise-grade perfection.**
> Your boss audits every line through Codex. Make him stop needing to.

You are implementing Phase C of the Cortex multi-agent memory addition. This phase adds the intelligence layer — provenance tracking, trust scoring, and delta-state synchronization. Read these files first:

- `MULTIAGENT-TASK-TRACKER.md` (Phase C section, tasks `PMC-*` and tests `TMC-*`)
- `MULTIAGENT-IMPLEMENTATION-SPEC.md` (full behavioral spec)
- `FILE-MAP.md` (complete file inventory with per-file details)

**Prerequisite:** QG-MA1 has passed — Phase B's storage, namespaces, and projections are fully operational. The `cortex-multiagent` crate exists with working AgentRegistry, NamespaceManager, NamespacePermissionManager, ProjectionEngine, and share/promote/retract operations. Migration v015 is in place. All `TMB-*` tests pass, `cargo test --workspace` is green, and coverage ≥80% on all Phase B modules.

---

## What This Phase Builds

Phase C adds the three pillars of multi-agent intelligence: provenance (where knowledge came from), trust (how much to believe it), and sync (keeping agents converged). 14 impl tasks, 24 tests, 5 property tests. Specifically:

### 1. Provenance Module (`cortex-multiagent/src/provenance/`) — 4 files

**tracker.rs** — `ProvenanceTracker`:
- `record_hop(writer, memory_id, hop)` — append a provenance hop (append-only, never modify)
- `get_provenance(reader, memory_id)` — full provenance record
- `get_chain(reader, memory_id)` — hop chain only
- `get_origin(reader, memory_id)` — origin only
- `chain_confidence(reader, memory_id)` — product of `(1.0 + hop.confidence_delta)`, clamped [0.0, 1.0]

**Chain Confidence Example:**
```
Created by Agent A (delta=0.0) → Shared to B (delta=0.0) → Validated by C (delta=+0.1) → Used by D (delta=+0.05)
chain = 1.0 × 1.0 × 1.1 × 1.05 = 1.155 → clamped to 1.0
```

**correction.rs** — `CorrectionPropagator`:
- `propagate_correction(writer, reader, memory_id, correction)` — propagate through chain
- Dampening: `strength = base × 0.7^hop_distance`
- Stop when `strength < 0.05`

**cross_agent.rs** — `CrossAgentTracer`:
- `trace_cross_agent(reader, memory_id, max_depth)` — follow provenance across agent boundaries
- Returns `CrossAgentTrace` with full path and confidence at each hop

### 2. Trust Module (`cortex-multiagent/src/trust/`) — 5 files

**scorer.rs** — `TrustScorer`:
- `compute_overall_trust(evidence)`:
  ```rust
  overall_trust = (validated + useful) / (total + 1) × (1 - contradicted / (total + 1))
  // Clamp to [0.0, 1.0]
  ```
- `effective_confidence(memory_confidence, trust_score)` — modulates confidence by trust
- Domain-specific trust uses same formula scoped to domain

**Example:**
```
validated=5, contradicted=1, useful=3, total=10
trust = (5+3)/(10+1) × (1 - 1/(10+1)) = 8/11 × 10/11 = 0.727 × 0.909 = 0.661
```

**evidence.rs** — `TrustEvidenceTracker`:
- `record_validation()`, `record_contradiction()`, `record_usage()` — increment counters
- All evidence updates in transactions (atomic)

**decay.rs** — Trust decay toward neutral (0.5):
```rust
trust_new = trust + (0.5 - trust) × (1 - 0.99^days_since_evidence)
```
Why 0.5? Neutral, not zero. Without evidence, trust regresses to "I don't know" not "I don't trust."

**bootstrap.rs** — Initial trust:
- New agents: 0.5 (neutral)
- Spawned agents: parent_trust × discount (default 0.8)

### 3. Sync Module (`cortex-multiagent/src/sync/`) — 5 files

**protocol.rs** — `DeltaSyncEngine`:
Three-phase protocol:
```
1. Request:  Agent A → B: "Give me deltas since clock X"
2. Response: Agent B → A: "Here are N deltas, my clock is Y"
3. Ack:      Agent A → B: "I applied deltas [1..N]"
```

**delta_queue.rs** — `DeltaQueue`:
- SQLite-backed persistent queue
- `enqueue()` → `dequeue()` → `mark_applied()` → `purge_applied()`

**causal_delivery.rs** — `CausalDeliveryManager`:
- `can_apply(delta, local_clock)` — check if all causal predecessors applied
- `buffer_delta(delta)` — buffer out-of-order deltas
- `drain_applicable(local_clock)` — drain buffered deltas that are now ready

**Causal Delivery Example:**
```
Local clock: {A:5, B:3, C:2}
Delta D1 clock {A:6, B:3, C:2} → apply (A incremented by 1)
Delta D2 clock {A:7, B:3, C:2} → buffer (missing A:6)
Delta D3 clock {A:5, B:4, C:2} → apply (B incremented by 1)
After D1 applied → clock {A:6, B:3, C:2} → drain buffer → D2 now ready → apply
```

**cloud_integration.rs** — `CloudSyncAdapter`:
- Local transport (same SQLite DB) vs Cloud transport (HTTP)
- `detect_sync_mode()` chooses transport based on target agent location

---

## Critical Implementation Details

### Provenance is Append-Only
Never modify existing hops. Never delete hops. Even on agent deregistration, provenance is preserved. This is the audit trail.

### Trust Division by Zero
Always use `(total + 1)` in the denominator. When total_received = 0, trust = 0/1 × 1/1 = 0.0. This is correct — no evidence means no trust (but bootstrap sets initial to 0.5).

### Causal Delivery Correctness
The causal delivery guarantee: regardless of delta arrival order, the final materialized state is identical. This is what `TMC-PROP-03` and `TMC-PROP-04` verify. If you get this wrong, agents will diverge.

### Vector Clock Update After Apply
After applying a delta, you MUST update the local vector clock:
```rust
local_clock.merge(&delta.clock);
local_clock.increment(&self_agent_id);
```
Forgetting this breaks causal ordering for all subsequent operations.

---

## Reference Crate Patterns

- **Provenance storage**: Follow `cortex-storage/src/queries/` pattern — raw SQL, parameterized queries
- **Trust computation**: Follow `cortex-decay/src/formula.rs` — mathematical computation with bounds checking
- **Sync protocol**: Follow `cortex-cloud/src/sync/protocol.rs` — request/response/ack pattern
- **Causal delivery**: This is novel — no existing pattern. Implement carefully with thorough property tests.

---

## Task Checklist

Check off tasks in `MULTIAGENT-TASK-TRACKER.md` as you complete them:

**Provenance**: `PMC-MA-01` through `PMC-MA-04`
**Trust**: `PMC-MA-05` through `PMC-MA-09`
**Sync**: `PMC-MA-10` through `PMC-MA-14`
**Tests**: All `TMC-PROV-*` (6), `TMC-TRUST-*` (8), `TMC-SYNC-*` (8), `TMC-PROP-*` (5), `TMC-TEST-*` (3)

---

## Quality Gate: QG-MA2

Before proceeding to Phase D, ALL of these must pass:

### Tests
- [ ] All 24 `TMC-*` unit tests pass
- [ ] All 5 `TMC-PROP-*` property tests pass
- [ ] `cargo test -p cortex-multiagent` — zero failures
- [ ] `cargo test --workspace` — zero regressions

### Coverage
- [ ] Coverage ≥80% for cortex-multiagent provenance modules
- [ ] Coverage ≥80% for cortex-multiagent trust modules
- [ ] Coverage ≥80% for cortex-multiagent sync modules

### Build Quality
- [ ] `cargo clippy -p cortex-multiagent` — zero warnings
- [ ] All public APIs have doc comments with examples
- [ ] All error paths return clear, actionable errors

### Performance
- [ ] Trust computation < 0.01ms per agent pair
- [ ] Provenance chain retrieval < 10ms for 10-hop chain
- [ ] Delta sync < 50ms for 100 deltas

---

## Common Pitfalls to Avoid

### Provenance
- ❌ **Don't modify existing hops** — provenance is append-only
- ❌ **Don't forget to clamp chain_confidence** — product can exceed 1.0
- ✅ **Do log all provenance operations** — critical for debugging

### Trust
- ❌ **Don't let trust go negative** — clamp to [0.0, 1.0]
- ❌ **Don't decay toward 0.0** — decay toward 0.5 (neutral)
- ❌ **Don't divide by zero** — use (total + 1) in denominator
- ✅ **Do update trust atomically** — use transactions

### Delta Sync
- ❌ **Don't apply out-of-order deltas** — buffer until causal predecessors present
- ❌ **Don't forget to update vector clock** — increment after applying delta
- ❌ **Don't purge unapplied deltas** — only purge after mark_applied
- ✅ **Do log all sync operations** — essential for debugging convergence issues

---

## Success Criteria

Phase C is complete when:

1. ✅ All 14 implementation tasks completed
2. ✅ All 24 unit tests pass
3. ✅ All 5 property tests pass
4. ✅ Coverage ≥80% on all Phase C modules
5. ✅ QG-MA2 quality gate passes
6. ✅ Zero regressions in existing tests
7. ✅ All public APIs documented
8. ✅ Performance targets met

**You'll know it works when:** Two agents can diverge (make different edits to the same memory), sync via delta exchange, converge to identical state, and you can trace the full provenance chain showing who did what and how much to trust each contribution.

---

## Next Steps After Phase C

Once QG-MA2 passes, proceed to **MAPhase D1: Cross-Crate Integration**, which integrates multi-agent features into existing Cortex crates (retrieval, validation, consolidation, causal, cloud, session).
