# CRDT Foundations for Conflict-Free Memory Convergence

## Why CRDTs?

When two agents independently modify memories about the same topic, we need a merge
strategy that:
1. Never requires coordination (agents work offline/independently)
2. Always converges to the same state regardless of message ordering
3. Preserves all information (no silent data loss)

CRDTs (Conflict-free Replicated Data Types) provide exactly these guarantees through
mathematical properties of join-semilattices.

---

## Core CRDT Theory

### The Three Approaches

**State-based CRDTs (CvRDTs)**
- Each replica maintains full state
- Replicas periodically send their entire state to peers
- States are merged using a join operation (least upper bound)
- Requires: state forms a join-semilattice (commutative, associative, idempotent merge)
- Pro: works over unreliable channels (messages can be lost, duplicated, reordered)
- Con: sending full state is expensive for large datasets

**Operation-based CRDTs (CmRDTs)**
- Replicas broadcast operations (small deltas)
- Operations must be commutative (order doesn't matter)
- Requires: exactly-once reliable delivery with causal ordering
- Pro: small message size
- Con: requires reliable delivery infrastructure

**Delta-state CRDTs (best of both worlds)**
- Send only the delta (change) since last sync, not full state
- Deltas are joined to both local and remote states
- Achieves small messages (like op-based) over unreliable channels (like state-based)
- This is what we should use for Cortex

Sources:
- [Approaches to CRDTs — ACM](https://dl.acm.org/doi/10.1145/3695249) — Shapiro et al.
- [Delta State Replicated Data Types](https://www.researchgate.net/publication/301854947) — Almeida et al.
- [arXiv:1806.10254](https://ar5iv.labs.arxiv.org/html/1806.10254) — Shapiro et al.

---

## CRDT Primitives We Need for Memory

### G-Counter (Grow-only Counter)
For: access_count, retrieval_count
Each agent maintains its own counter. Merge = take max per agent. Value = sum of all.
Guarantees: monotonically increasing, no lost increments.

### LWW-Register (Last-Writer-Wins Register)
For: content, summary, confidence (when explicitly updated by user)
Each update carries a timestamp. Merge = keep the one with the highest timestamp.
Simple but loses concurrent updates. Acceptable for user-initiated edits.

### MV-Register (Multi-Value Register)
For: content when concurrent edits must be preserved
Merge = keep all concurrent values, present to user for resolution.
Maps to our existing conflict resolution in cortex-cloud.

### OR-Set (Observed-Remove Set)
For: tags, linked_patterns, linked_files, linked_functions
Add and remove operations. Concurrent add + remove = element is present (add wins).
No tombstone accumulation with optimized implementations.

### LWW-Map (Last-Writer-Wins Map)
For: metadata fields, config overrides per memory
Each key has an LWW-Register. Merge = per-key LWW merge.

### Causal Graph CRDT (Custom)
For: causal_edges, relationships
This is the novel piece. We need a CRDT for DAG structures where:
- Adding an edge is commutative (order doesn't matter)
- Removing an edge uses OR-Set semantics (add wins over concurrent remove)
- Cycle detection is local (each replica validates independently)
- Strength updates use max-wins semantics

---

## Delta-State Approach for Cortex

### How It Works

```
Agent A                          Agent B
   |                                |
   |-- create memory M1 ---------->|  (delta: {add M1, full content})
   |                                |
   |<-- update M1.tags ["auth"] ---|  (delta: {M1.tags: OR-Set add "auth"})
   |                                |
   |-- update M1.confidence 0.9 -->|  (delta: {M1.confidence: LWW 0.9 @t3})
   |                                |
   |   [merge: both have M1 with   |
   |    tags=["auth"], conf=0.9]    |
```

### Delta Encoding for BaseMemory

Each field of BaseMemory maps to a CRDT type:

| Field | CRDT Type | Merge Semantics |
|-------|-----------|-----------------|
| id | Immutable | First-write wins (UUID, never changes) |
| memory_type | LWW-Register | Reclassification = explicit update |
| content | LWW-Register | Last explicit edit wins |
| summary | LWW-Register | Last explicit edit wins |
| transaction_time | Immutable | Set at creation, never changes |
| valid_time | LWW-Register | Can be corrected |
| valid_until | LWW-Register | Can be extended/shortened |
| confidence | Max-Register | Confidence only goes up via explicit boost; decay is local |
| importance | LWW-Register | Reclassification updates |
| last_accessed | Max-Register | Most recent access wins |
| access_count | G-Counter | Per-agent counters, sum for total |
| linked_patterns | OR-Set | Add wins over concurrent remove |
| linked_constraints | OR-Set | Add wins over concurrent remove |
| linked_files | OR-Set | Add wins over concurrent remove |
| linked_functions | OR-Set | Add wins over concurrent remove |
| tags | OR-Set | Add wins over concurrent remove |
| archived | LWW-Register | Explicit archive/restore |
| superseded_by | LWW-Register | Explicit supersession |
| supersedes | OR-Set | Can supersede multiple |
| content_hash | Derived | Recomputed from content after merge |

### Confidence: Special Case

Confidence is tricky because it's modified by both:
1. Explicit user/agent actions (boost, set) — should propagate
2. Automatic decay (time-based) — should be local only

Solution: Store `base_confidence` (CRDT, propagates) and `decay_factor` (local only).
Effective confidence = base_confidence × decay_factor. Each agent decays independently
based on its own access patterns.

---

## Causal Consistency

Delta-state CRDTs don't require causal delivery, but for memory systems we want it
because:
- If Agent A creates memory M1, then creates M2 referencing M1, Agent B should
  receive M1 before M2
- Vector clocks per agent provide causal ordering cheaply

### Vector Clock Design

```rust
type VectorClock = HashMap<AgentId, u64>;

struct MemoryDelta {
    memory_id: MemoryId,
    clock: VectorClock,      // causal ordering
    field_deltas: Vec<FieldDelta>,
}
```

Each agent increments its own clock entry on every mutation. Deltas are applied
only when all causally preceding deltas have been applied (standard causal delivery).

---

## Storage Overhead Analysis

For a typical Cortex deployment with 10K memories and 3 agents:

- Vector clocks: 3 agents × 8 bytes = 24 bytes per memory = 240KB total
- OR-Set metadata (tags): ~50 bytes per tag per memory = ~500KB total
- G-Counter (access_count): 3 agents × 8 bytes = 24 bytes per memory = 240KB total
- Delta log (last 1000 deltas): ~200 bytes per delta = 200KB

Total CRDT overhead: ~1.2MB for 10K memories across 3 agents. Negligible.

---

## Key Design Decisions

1. **Delta-state over pure state-based**: Full state sync of 10K memories is too expensive
2. **Causal delivery**: Vector clocks are cheap and prevent reference-before-creation bugs
3. **OR-Set for collections**: Add-wins semantics match developer expectations
4. **Max-Register for confidence**: Prevents accidental confidence loss from stale replicas
5. **Local-only decay**: Each agent's decay is independent; only explicit boosts propagate
