# Phase C: Delta Sync + Trust + Provenance — Implementation Prompt

> **Phase:** C (Delta Sync + Trust + Provenance)
> **Prerequisites:** QG-MA1 passed (Phase B complete with ≥80% coverage)
> **Target:** Implement provenance tracking, trust scoring, and delta-state CRDT synchronization
> **New Files:** ~25 | **Modified Files:** ~5
> **Quality Gate:** QG-MA2 (≥80% coverage on all Phase C modules)
> **Estimated Duration:** ~1.5 weeks

---

## What You're Building

Phase C adds the **intelligence layer** to multi-agent memory: tracking where knowledge came from (provenance), how much to trust it (trust scoring), and keeping agents synchronized without coordination overhead (delta sync).

### The Three Pillars

1. **Provenance** — Every memory has a chain showing its origin and every transformation across agents
2. **Trust** — Agents build evidence-based trust scores for each other, modulating confidence in shared knowledge
3. **Delta Sync** — Agents exchange only what changed (deltas), with causal delivery guarantees

### Why This Matters

Without provenance, you can't answer "why does Agent B believe X?" Without trust, all agents are treated equally even when some are consistently wrong. Without delta sync, agents must exchange full memory snapshots, wasting bandwidth and creating race conditions.

Phase C solves all three with:
- **Append-only provenance log** with dampened correction propagation
- **Evidence-based trust scoring** with domain-specific granularity
- **Causal delivery** using vector clocks to prevent out-of-order application

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    cortex-multiagent                        │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │  Provenance  │  │    Trust     │  │     Sync     │    │
│  │              │  │              │  │              │    │
│  │  • Tracker   │  │  • Scorer    │  │  • Protocol  │    │
│  │  • Correction│  │  • Evidence  │  │  • Queue     │    │
│  │  • Cross-Ag  │  │  • Decay     │  │  • Causal    │    │
│  │              │  │  • Bootstrap │  │  • Cloud     │    │
│  └──────────────┘  └──────────────┘  └──────────────┘    │
│         │                  │                  │            │
│         └──────────────────┴──────────────────┘            │
│                            │                               │
└────────────────────────────┼───────────────────────────────┘
                             │
                    ┌────────▼────────┐
                    │ cortex-storage  │
                    │                 │
                    │ • provenance_log│
                    │ • agent_trust   │
                    │ • delta_queue   │
                    └─────────────────┘
```

---

## Module 1: Provenance Tracking

### What It Does

Tracks the complete history of every memory: who created it, who shared it, who refined it, who corrected it. Each action is a "hop" in the provenance chain.

### Key Files

**`cortex-multiagent/src/provenance/tracker.rs`**
- `ProvenanceTracker` struct (stateless)
- `record_hop(writer, memory_id, hop)` — append a provenance hop
- `get_provenance(reader, memory_id)` — retrieve full provenance record
- `get_chain(reader, memory_id)` — retrieve hop chain
- `get_origin(reader, memory_id)` — retrieve origin only
- `chain_confidence(reader, memory_id)` — compute confidence product

**Chain Confidence Formula:**
```rust
chain_confidence = product of (1.0 + hop.confidence_delta) for all hops
                 = clamp to [0.0, 1.0]
```

**Example:**
```
Memory M1 created by Agent A (confidence_delta = 0.0)
→ Shared to Agent B (confidence_delta = 0.0)
→ Validated by Agent C (confidence_delta = +0.1)
→ Used in decision by Agent D (confidence_delta = +0.05)

chain_confidence = 1.0 × 1.0 × 1.1 × 1.05 = 1.155 → clamped to 1.0
```

**`cortex-multiagent/src/provenance/correction.rs`**
- `CorrectionPropagator` struct
- `propagate_correction(writer, reader, memory_id, correction)` — propagate correction through provenance chain
- `correction_strength(hop_distance)` — compute dampened strength

**Dampening Formula:**
```rust
strength = base_strength × 0.7^hop_distance
stop when strength < 0.05 (threshold)
```

**Example:**
```
Agent A corrects Memory M1 (base_strength = 1.0)
→ M2 derived from M1 (hop_distance = 1): strength = 0.7
→ M3 derived from M2 (hop_distance = 2): strength = 0.49
→ M4 derived from M3 (hop_distance = 3): strength = 0.343
→ M5 derived from M4 (hop_distance = 4): strength = 0.24
→ M6 derived from M5 (hop_distance = 5): strength = 0.168
→ M7 derived from M6 (hop_distance = 6): strength = 0.118
→ M8 derived from M7 (hop_distance = 7): strength = 0.083
→ M9 derived from M8 (hop_distance = 8): strength = 0.058
→ M10 derived from M9 (hop_distance = 9): strength = 0.041 → STOP (< 0.05)
```

**Why dampening?** Prevents cascading invalidation. A correction to a root memory shouldn't invalidate all downstream knowledge with equal force.

**`cortex-multiagent/src/provenance/cross_agent.rs`**
- `CrossAgentTracer` struct
- `trace_cross_agent(reader, memory_id, max_depth)` — follow provenance across agent boundaries
- Returns `CrossAgentTrace` with full path and confidence at each hop

**Example:**
```
Memory M1 (Agent A, confidence 0.8)
→ Shared to Agent B (confidence 0.8)
→ Refined by Agent B (confidence 0.85)
→ Shared to Agent C (confidence 0.85)
→ Validated by Agent C (confidence 0.9)

Trace: [
  (Agent A, M1, 0.8),
  (Agent B, M1_copy, 0.8),
  (Agent B, M1_refined, 0.85),
  (Agent C, M1_refined_copy, 0.85),
  (Agent C, M1_validated, 0.9)
]
```

### Implementation Checklist

- [ ] `PMC-MA-01` — Create `cortex-multiagent/src/provenance/mod.rs`
- [ ] `PMC-MA-02` — Create `cortex-multiagent/src/provenance/tracker.rs`
- [ ] `PMC-MA-03` — Create `cortex-multiagent/src/provenance/correction.rs`
- [ ] `PMC-MA-04` — Create `cortex-multiagent/src/provenance/cross_agent.rs`

### Tests

- [ ] `TMC-PROV-01` — Provenance hop recording and chain retrieval
- [ ] `TMC-PROV-02` — Chain confidence computation correct
- [ ] `TMC-PROV-03` — Correction propagation with dampening (0.7^hop)
- [ ] `TMC-PROV-04` — Correction stops at threshold (strength < 0.05)
- [ ] `TMC-PROV-05` — Cross-agent trace across 3 agents
- [ ] `TMC-PROV-06` — Provenance origin detection correct

---

## Module 2: Trust Scoring

### What It Does

Builds evidence-based trust scores between agents. When Agent A receives memories from Agent B, it tracks:
- How many were later validated as correct
- How many were contradicted
- How many were useful (accessed and used in decisions)

Trust score modulates confidence: `effective_confidence = memory_confidence × trust_score`

### Key Files

**`cortex-multiagent/src/trust/scorer.rs`**
- `TrustScorer` struct (stateless)
- `get_trust(reader, agent_id, target_agent)` — retrieve trust record
- `compute_overall_trust(evidence)` — compute trust from evidence
- `compute_domain_trust(domain, evidence)` — compute domain-specific trust
- `effective_confidence(memory_confidence, trust_score)` — modulate confidence
- `update_trust(writer, agent_id, target_agent, trust)` — persist trust update

**Trust Formula:**
```rust
overall_trust = (validated + useful) / (total + 1)
              × (1 - contradicted / (total + 1))
              
Bounds: clamp to [0.0, 1.0]
```

**Example:**
```
Agent A's trust in Agent B:
- validated_count = 5
- contradicted_count = 1
- useful_count = 3
- total_received = 10

overall_trust = (5 + 3) / (10 + 1) × (1 - 1 / (10 + 1))
              = 8/11 × 10/11
              = 0.727 × 0.909
              = 0.661
```

**Domain-Specific Trust:**
```rust
domain_trust["auth"] = (validated_in_auth + useful_in_auth) / (total_in_auth + 1)
                     × (1 - contradicted_in_auth / (total_in_auth + 1))
```

**`cortex-multiagent/src/trust/evidence.rs`**
- `TrustEvidenceTracker` struct
- `record_validation(writer, agent_id, target_agent, memory_id)` — increment validated_count
- `record_contradiction(writer, agent_id, target_agent, memory_id)` — increment contradicted_count
- `record_usage(writer, agent_id, target_agent, memory_id)` — increment useful_count
- `get_evidence(reader, agent_id, target_agent)` — retrieve evidence

**`cortex-multiagent/src/trust/decay.rs`**
- `apply_trust_decay(trust, days_since_evidence, decay_rate)` — decay toward neutral (0.5)

**Decay Formula:**
```rust
trust_new = trust + (0.5 - trust) × (1 - 0.99^days_since_evidence)
```

**Why decay toward 0.5?** Neutral is 0.5 (neither trusted nor distrusted). Without recent evidence, trust should regress to neutral, not to zero.

**Example:**
```
Initial trust = 0.8
After 50 days: 0.8 + (0.5 - 0.8) × (1 - 0.99^50) = 0.8 + (-0.3) × 0.395 = 0.681
After 100 days: 0.8 + (0.5 - 0.8) × (1 - 0.99^100) = 0.8 + (-0.3) × 0.634 = 0.610
```

**`cortex-multiagent/src/trust/bootstrap.rs`**
- `bootstrap_trust(agent_id, target_agent)` — initialize trust at 0.5
- `bootstrap_from_parent(parent_trust, discount)` — inherit trust from parent agent

**Bootstrap Rules:**
- New agents start at 0.5 (neutral)
- Spawned agents inherit parent's trust × discount (default 0.8)

**Example:**
```
Parent Agent A trusts Agent B at 0.9
Spawned Agent A' inherits: 0.9 × 0.8 = 0.72
```

### Implementation Checklist

- [ ] `PMC-MA-05` — Create `cortex-multiagent/src/trust/mod.rs`
- [ ] `PMC-MA-06` — Create `cortex-multiagent/src/trust/scorer.rs`
- [ ] `PMC-MA-07` — Create `cortex-multiagent/src/trust/evidence.rs`
- [ ] `PMC-MA-08` — Create `cortex-multiagent/src/trust/decay.rs`
- [ ] `PMC-MA-09` — Create `cortex-multiagent/src/trust/bootstrap.rs`

### Tests

- [ ] `TMC-TRUST-01` — Trust bootstrap at 0.5 for new agents
- [ ] `TMC-TRUST-02` — Trust increase from validation (+0.05)
- [ ] `TMC-TRUST-03` — Trust decrease from contradiction (-0.10)
- [ ] `TMC-TRUST-04` — Domain-specific trust computation
- [ ] `TMC-TRUST-05` — Effective confidence modulation (memory × trust)
- [ ] `TMC-TRUST-06` — Trust decay toward neutral over time
- [ ] `TMC-TRUST-07` — Spawned agent trust inheritance with discount
- [ ] `TMC-TRUST-08` — Trust bounds [0.0, 1.0] maintained

---

## Module 3: Delta Sync

### What It Does

Synchronizes agents by exchanging only what changed (deltas), not full memory snapshots. Uses vector clocks for causal delivery: deltas are buffered if they arrive out-of-order, then applied when all predecessors are present.

### Key Files

**`cortex-multiagent/src/sync/protocol.rs`**
- `DeltaSyncEngine` struct
- `SyncRequest` struct (source_agent, target_agent, since_clock)
- `SyncResponse` struct (deltas, current_clock)
- `SyncAck` struct (applied_delta_ids)
- `SyncResult` struct (applied_count, buffered_count, errors)

**Three-Phase Protocol:**
```
1. Request:  Agent A → Agent B: "Give me deltas since clock X"
2. Response: Agent B → Agent A: "Here are 50 deltas, my clock is Y"
3. Ack:      Agent A → Agent B: "I applied deltas [1,2,3,...,50]"
```

**Methods:**
- `initiate_sync(writer, reader, source_agent, target_agent)` — start sync
- `handle_sync_request(reader, request)` — respond with deltas
- `acknowledge_sync(writer, ack)` — mark deltas as applied

**`cortex-multiagent/src/sync/delta_queue.rs`**
- `DeltaQueue` struct (backed by SQLite `delta_queue` table)
- `enqueue(writer, delta, target_agent)` — add delta to queue
- `dequeue(reader, target_agent, limit)` — fetch pending deltas
- `mark_applied(writer, delta_ids)` — mark deltas as applied
- `pending_count(reader, target_agent)` — count pending deltas
- `purge_applied(writer, older_than)` — cleanup old applied deltas

**Queue Lifecycle:**
```
1. Agent A modifies memory M1 → generates delta D1
2. enqueue(D1, target=Agent B)
3. Agent B syncs → dequeue(Agent B, limit=100) → [D1, ...]
4. Agent B applies D1 → mark_applied([D1.id])
5. Periodic cleanup → purge_applied(older_than=7 days)
```

**`cortex-multiagent/src/sync/causal_delivery.rs`**
- `CausalDeliveryManager` struct
- `can_apply(delta, local_clock)` — check if delta is causally ready
- `buffer_delta(delta)` — buffer out-of-order delta
- `drain_applicable(local_clock)` — drain buffered deltas that are now ready

**Causal Delivery Logic:**
```rust
fn can_apply(delta: &MemoryDelta, local_clock: &VectorClock) -> bool {
    // Delta is ready if all its causal predecessors have been applied
    delta.clock.happens_before(local_clock) || delta.clock == local_clock
}
```

**Example:**
```
Local clock: {A:5, B:3, C:2}

Delta D1 with clock {A:6, B:3, C:2} → can_apply = true (A incremented by 1)
Delta D2 with clock {A:7, B:3, C:2} → can_apply = false (A:7 > A:5+1, missing A:6)
Delta D3 with clock {A:5, B:4, C:2} → can_apply = true (B incremented by 1)

Apply D1 → local clock becomes {A:6, B:3, C:2}
Buffer D2 (waiting for A:6)
Apply D3 → local clock becomes {A:6, B:4, C:2}
Drain buffer → D2 now ready (A:7 = A:6+1) → apply D2 → {A:7, B:4, C:2}
```

**`cortex-multiagent/src/sync/cloud_integration.rs`**
- `CloudSyncAdapter` struct
- `SyncTransport` enum (Local, Cloud)
- `sync_via_cloud(source_agent, target_agent)` — sync over HTTP
- `sync_via_local(source_agent, target_agent)` — sync via SQLite
- `detect_sync_mode(target_agent)` — choose transport

**Transport Selection:**
```
If target_agent is local (same SQLite DB) → Local transport
If target_agent is remote (different machine) → Cloud transport
```

### Implementation Checklist

- [ ] `PMC-MA-10` — Create `cortex-multiagent/src/sync/mod.rs`
- [ ] `PMC-MA-11` — Create `cortex-multiagent/src/sync/protocol.rs`
- [ ] `PMC-MA-12` — Create `cortex-multiagent/src/sync/delta_queue.rs`
- [ ] `PMC-MA-13` — Create `cortex-multiagent/src/sync/causal_delivery.rs`
- [ ] `PMC-MA-14` — Create `cortex-multiagent/src/sync/cloud_integration.rs`

### Tests

- [ ] `TMC-SYNC-01` — Delta sync protocol: request → response → ack
- [ ] `TMC-SYNC-02` — Causal delivery: in-order deltas applied immediately
- [ ] `TMC-SYNC-03` — Causal delivery: out-of-order deltas buffered
- [ ] `TMC-SYNC-04` — Causal delivery: drain after unblock
- [ ] `TMC-SYNC-05` — Delta queue: enqueue + dequeue round-trip
- [ ] `TMC-SYNC-06` — Delta queue: mark_applied excludes from dequeue
- [ ] `TMC-SYNC-07` — Cloud vs local sync mode detection
- [ ] `TMC-SYNC-08` — Sync convergence: both agents have identical state

---

## Property-Based Tests (Critical!)

These tests use `proptest` to verify mathematical properties hold for all inputs.

**`cortex-multiagent/tests/property/phase_c_properties.rs`**

- [ ] `TMC-PROP-01` — **Trust bounds**: For any evidence, trust ∈ [0.0, 1.0]
- [ ] `TMC-PROP-02` — **Trust decay monotonicity**: Trust always moves toward 0.5, never away
- [ ] `TMC-PROP-03` — **Causal delivery correctness**: Regardless of arrival order, final state is identical
- [ ] `TMC-PROP-04` — **Delta sync convergence**: After sync, both agents have same materialized state
- [ ] `TMC-PROP-05` — **Correction dampening monotonicity**: Strength decreases with hop distance

**Example Property Test:**
```rust
proptest! {
    #[test]
    fn trust_always_in_bounds(
        validated in 0u64..1000,
        contradicted in 0u64..1000,
        useful in 0u64..1000,
        total in 0u64..1000
    ) {
        let evidence = TrustEvidence {
            validated_count: validated,
            contradicted_count: contradicted,
            useful_count: useful,
            total_received: total,
        };
        let trust = compute_overall_trust(&evidence);
        prop_assert!(trust >= 0.0 && trust <= 1.0);
    }
}
```

---

## Test File Creation

- [ ] `TMC-TEST-01` — Create `cortex-multiagent/tests/provenance_test.rs`
- [ ] `TMC-TEST-02` — Create `cortex-multiagent/tests/trust_test.rs`
- [ ] `TMC-TEST-03` — Create `cortex-multiagent/tests/sync_test.rs`
- [ ] `TMC-TEST-04` — Create `cortex-multiagent/tests/property/phase_c_properties.rs`

---

## Quality Gate: QG-MA2

Before proceeding to Phase D, all of these must pass:

### Test Coverage
- [ ] All 24 Phase C tests pass (`TMC-*`)
- [ ] All 5 property tests pass (`TMC-PROP-*`)
- [ ] `cargo test -p cortex-multiagent` — zero failures
- [ ] `cargo test --workspace` — zero regressions

### Coverage Metrics
- [ ] Coverage ≥80% for `cortex-multiagent/src/provenance/`
- [ ] Coverage ≥80% for `cortex-multiagent/src/trust/`
- [ ] Coverage ≥80% for `cortex-multiagent/src/sync/`

### Code Quality
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

## Integration Points

### With Phase A (CRDT Foundation)
- Provenance uses `VectorClock` for causal ordering
- Delta sync uses `MemoryDelta` and `MergeEngine`
- Trust modulates `base_confidence` (MaxRegister)

### With Phase B (Storage + Namespaces)
- Provenance writes to `provenance_log` table
- Trust writes to `agent_trust` table
- Delta queue writes to `delta_queue` table

### With Phase D (Cross-Crate Integration)
- Trust scores feed into `cortex-retrieval` ranking
- Provenance chains feed into `cortex-validation` contradiction resolution
- Delta sync integrates with `cortex-cloud` sync protocol

---

## Success Criteria

Phase C is complete when:

1. ✅ All 25 new files created
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

Once QG-MA2 passes, proceed to **Phase D: Cross-Crate Integration + NAPI + TypeScript**, which integrates multi-agent features into existing Cortex crates (retrieval, validation, consolidation, causal, cloud, session) and exposes everything via TypeScript MCP tools and CLI commands.

---

**Let's cook! 🔥**
