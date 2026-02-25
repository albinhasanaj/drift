# MAPhase A — CRDT Foundation + Core Types

> **ULTRA THINK. Quality over speed. No shortcuts. Enterprise-grade perfection.**
> Your boss audits every line through Codex. Make him stop needing to.

You are implementing Phase A of the Cortex multi-agent memory addition. This is the mathematical foundation — every subsequent phase depends on the correctness of what you build here. Read these files first:

- `MULTIAGENT-TASK-TRACKER.md` (Phase A section, tasks `PMA-*` and tests `TMA-*`)
- `MULTIAGENT-IMPLEMENTATION-SPEC.md` (full behavioral spec)
- `FILE-MAP.md` (complete file inventory with per-file details)

**Prerequisite:** None — this is Phase A, the first phase. The Cortex workspace already exists with 20+ crates. You are adding 2 new crates (`cortex-crdt`, `cortex-multiagent`) and extending `cortex-core` with new types.

---

## What This Phase Builds

Phase A establishes the CRDT (Conflict-free Replicated Data Type) foundation and all core types needed for multi-agent memory. 35 impl tasks, 31 unit tests, 19 property tests, 3 stress tests, 10 benchmarks. Specifically:

### 1. cortex-core Extensions (~14 tasks)

New model files + error types + trait + config for multi-agent support:

**Agent Types** (`cortex-core/src/models/agent.rs`):
- `AgentId` — UUID-based String wrapper with `new()` and `default_agent()` for backward compat
- `AgentRegistration` — full agent metadata (id, name, namespace, capabilities, parent, timestamps, status)
- `AgentStatus` enum — Active, Idle { since }, Deregistered { at }
- `SpawnConfig` — parent_agent, projection, trust_discount, auto_promote, ttl

**Namespace Types** (`cortex-core/src/models/namespace.rs`):
- `NamespaceId` — scope + name, URI format `{scope}://{name}/`
- `NamespaceScope` enum — Agent(AgentId), Team(String), Project(String)
- `NamespacePermission` enum — Read, Write, Share, Admin
- `NamespaceACL`, `MemoryProjection`, `ProjectionFilter`

**Provenance Types** (`cortex-core/src/models/provenance.rs`):
- `ProvenanceRecord`, `ProvenanceOrigin` (5 variants), `ProvenanceHop`, `ProvenanceAction` (9 variants)

**Cross-Agent Types** (`cortex-core/src/models/cross_agent.rs`):
- `CrossAgentRelation` (5 variants), `CrossAgentContradiction`, `ContradictionResolution` (4 variants)
- `AgentTrust`, `TrustEvidence`

**Memory Extensions** (`cortex-core/src/memory/base.rs`):
- Add `namespace: NamespaceId` field (default: `agent://default/`)
- Add `source_agent: AgentId` field (default: `AgentId::default_agent()`)

**Relationship Extension** (`cortex-core/src/memory/relationships.rs`):
- Add `CrossAgent(CrossAgentRelation)` variant to existing enum

**Error Types** (`cortex-core/src/errors/multiagent_error.rs`):
- `MultiAgentError` enum with 10 variants: AgentNotFound, AgentAlreadyRegistered, NamespaceNotFound, PermissionDenied, ProjectionNotFound, InvalidNamespaceUri, CausalOrderViolation, CyclicDependency, SyncFailed, TrustComputationFailed
- Add `MultiAgentError(#[from] MultiAgentError)` to `CortexError`

**Trait** (`cortex-core/src/traits/multiagent_engine.rs`):
- `IMultiAgentEngine` async_trait with 12 methods

**Config** (`cortex-core/src/config/multiagent_config.rs`):
- `MultiAgentConfig` with 17 fields, all with documented defaults

### 2. cortex-crdt: New Crate (~15 tasks)

A complete CRDT primitives library with 5 data structures, memory-level CRDT wrapper, and a DAG CRDT for the causal graph.

**Vector Clock** (`cortex-crdt/src/clock.rs`):
- `VectorClock` — HashMap<String, u64> with increment, merge, happens_before, concurrent_with, dominates
- Merge is component-wise max. happens_before: all A ≤ B, at least one A < B.

**5 CRDT Primitives** (`cortex-crdt/src/primitives/`):
- `GCounter` — grow-only counter. Per-agent counts, value = sum, merge = per-agent max. Used for access_count.
- `LWWRegister<T>` — last-writer-wins register. Timestamp + agent_id tie-breaking (lexicographic). Used for content, summary, importance, archived.
- `MVRegister<T>` — multi-value register. Preserves all concurrent values. `is_conflicted()` when >1 value. Manual `resolve()`.
- `ORSet<T>` — observed-remove set. Add-wins semantics (concurrent add + remove → present). Unique tags per add. Used for tags, linked_patterns, linked_files.
- `MaxRegister<T: Ord>` — max-wins register. Value only increases. Used for confidence, last_accessed.

**Memory CRDT** (`cortex-crdt/src/memory/`):
- `MemoryCRDT` — wraps every BaseMemory field in the appropriate CRDT type:
  - id: immutable, memory_type: LWW, content: LWW, summary: LWW
  - transaction_time: immutable, valid_time: LWW, valid_until: LWW
  - base_confidence: MaxRegister, importance: LWW, last_accessed: MaxRegister
  - access_count: GCounter, tags: ORSet, linked_*: ORSet (×4)
  - archived: LWW, superseded_by: LWW, supersedes: ORSet
  - namespace: LWW, provenance: Vec<ProvenanceHop>, clock: VectorClock
- `from_base_memory(memory, agent_id)` and `to_base_memory()` round-trip
- `merge(other)` — field-by-field CRDT merge

- `FieldDelta` enum — 13 variants representing individual field changes
- `MergeEngine` — stateless merge orchestrator with causal ordering validation

**DAG CRDT** (`cortex-crdt/src/graph/`):
- `CausalGraphCRDT` — edges as ORSet<CausalEdge>, strengths as HashMap<(String,String), MaxRegister<f64>>
- Cycle prevention: local check before add, global resolution after merge
- `resolve_cycles()` — remove weakest edge in each cycle (deterministic)
- `would_create_cycle(edge)` — pre-add check

---

## Critical Implementation Details

### CRDT Mathematical Properties (MUST hold for ALL primitives)

Every CRDT merge operation MUST satisfy these three properties. The property tests will verify them:

1. **Commutativity**: `merge(A, B) == merge(B, A)` — order doesn't matter
2. **Associativity**: `merge(A, merge(B, C)) == merge(merge(A, B), C)` — grouping doesn't matter
3. **Idempotency**: `merge(A, A) == A` — merging with self is a no-op

If any of these fail, agents will diverge and never converge. This is the mathematical foundation.

### LWW Tie-Breaking

When two LWWRegister values have identical timestamps, tie-break by lexicographic comparison of agent_id. This ensures deterministic merge regardless of which agent merges first.

```rust
fn merge(&mut self, other: &Self) {
    if other.timestamp > self.timestamp
        || (other.timestamp == self.timestamp && other.agent_id > self.agent_id)
    {
        self.value = other.value.clone();
        self.timestamp = other.timestamp;
        self.agent_id = other.agent_id.clone();
    }
}
```

### ORSet Add-Wins Semantics

Concurrent add + remove of the same element → element is PRESENT. This is the defining property of ORSet. The remove only tombstones tags that existed at the time of removal. A concurrent add creates a new tag that isn't tombstoned.

### DAG CRDT Cycle Resolution

After merging two DAG CRDTs, cycles may be introduced (Agent A adds A→B, Agent B adds B→A). Resolution:
1. Detect all cycles using DFS
2. For each cycle, find the edge with the lowest strength (MaxRegister value)
3. Remove that edge (deterministic — same weakest edge regardless of merge order)
4. Repeat until acyclic

### BaseMemory Field Additions

Adding `namespace` and `source_agent` to `BaseMemory` is a breaking change. Use `#[serde(default)]` with default values:
- `namespace` defaults to `NamespaceId { scope: NamespaceScope::Agent(AgentId::default_agent()), name: "default".into() }` → URI `agent://default/`
- `source_agent` defaults to `AgentId::default_agent()`

This ensures existing serialized memories deserialize correctly.

---

## Reference Crate Patterns

Match existing Cortex patterns exactly:

- **Crate structure**: Follow `cortex-causal` — `src/lib.rs` with module declarations, `src/engine.rs` for the main struct, submodules for each concern
- **Error types**: Follow `cortex-core/src/errors/` — enum with `thiserror::Error` derive, `Display` impl, `From` impl for `CortexError`
- **Config types**: Follow `cortex-core/src/config/` — struct with `#[derive(Debug, Clone, Serialize, Deserialize)]`, `impl Default`
- **Trait types**: Follow `cortex-core/src/traits/` — `#[async_trait]` with `CortexResult<T>` return types
- **Test structure**: Follow `cortex-causal/tests/` — separate test files per concern, `property/` subdir for proptest
- **Benchmark structure**: Follow `cortex-causal/benches/` — criterion groups with descriptive names

---

## Task Checklist

Check off tasks in `MULTIAGENT-TASK-TRACKER.md` as you complete them:

**Workspace**: `PMA-WS-01`
**Core Models**: `PMA-CORE-01` through `PMA-CORE-07`
**Core Errors**: `PMA-CORE-08` through `PMA-CORE-10`
**Core Trait**: `PMA-CORE-11`, `PMA-CORE-12`
**Core Config**: `PMA-CORE-13`, `PMA-CORE-14`
**CRDT Crate**: `PMA-CRDT-01` through `PMA-CRDT-15`
**Tests**: All `TMA-CRDT-*` (31), `TMA-PROP-*` (19), `TMA-STRESS-*` (3), `TMA-BENCH-*` (10), `TMA-TEST-*` (8)

---

## Quality Gate: QG-MA0

Before proceeding to Phase B, ALL of these must pass:

### Tests
- [ ] All 31 `TMA-CRDT-*` unit tests pass
- [ ] All 19 `TMA-PROP-*` property tests pass
- [ ] All 3 `TMA-STRESS-*` stress tests pass
- [ ] All 10 `TMA-BENCH-*` benchmarks meet targets

### Build
- [ ] `cargo check -p cortex-crdt` exits 0
- [ ] `cargo check -p cortex-core` exits 0
- [ ] `cargo clippy -p cortex-crdt` — zero warnings
- [ ] `cargo clippy -p cortex-core` — zero warnings (for changed code)
- [ ] `cargo test -p cortex-crdt` — zero failures
- [ ] `cargo test -p cortex-core` — zero failures (zero regressions)
- [ ] `cargo test --workspace` — zero regressions

### Coverage
- [ ] Coverage ≥80% for cortex-crdt primitives modules
- [ ] Coverage ≥80% for cortex-crdt memory modules
- [ ] Coverage ≥80% for cortex-crdt graph modules
- [ ] Coverage ≥80% for cortex-core models (agent, namespace, provenance, cross_agent)

### Performance
- [ ] GCounter merge (5 agents) < 0.01ms
- [ ] LWWRegister merge < 0.001ms
- [ ] ORSet merge (100 elements) < 0.1ms
- [ ] ORSet merge (1000 elements) < 1ms
- [ ] MaxRegister merge < 0.001ms
- [ ] VectorClock merge (20 agents) < 0.01ms
- [ ] MemoryCRDT full merge < 0.5ms
- [ ] Delta computation (50 changed fields) < 0.2ms
- [ ] DAG CRDT merge (500 edges) < 5ms
- [ ] DAG CRDT cycle detection (1K edges) < 10ms

### Enterprise
- [ ] All public APIs have doc comments
- [ ] All errors use CortexResult<T> with specific variants
- [ ] All performance-critical paths instrumented with tracing
- [ ] CRDT storage overhead: 10K memories, 5 agents → < 10MB overhead

---

## Common Pitfalls to Avoid

- ❌ **Don't forget VectorClock update after merge** — the merged clock must be the component-wise max of both
- ❌ **Don't use f64 equality in tests** — use `(a - b).abs() < EPSILON` for floating point comparisons
- ❌ **Don't let ORSet tombstones grow unbounded** — tombstones only need to track tags, not full values
- ❌ **Don't skip the `#[serde(default)]` on new BaseMemory fields** — existing serialized data will fail to deserialize
- ❌ **Don't implement MVRegister resolve as "pick first"** — it must be an explicit user action that collapses to a single value
- ✅ **Do test all three CRDT properties** (commutativity, associativity, idempotency) for every primitive
- ✅ **Do use `proptest` with at least 256 iterations** for property tests
- ✅ **Do clamp all bounded values** — trust [0.0, 1.0], confidence [0.0, 1.0], KSI [0.0, 1.0]

---

## Success Criteria

Phase A is complete when:

1. ✅ All 35 implementation tasks completed
2. ✅ All 31 unit tests pass
3. ✅ All 19 property tests pass (CRDT mathematical guarantees verified)
4. ✅ All 3 stress tests pass (10K memories, 5 agents, full merge < 5s)
5. ✅ All 10 benchmarks meet targets
6. ✅ Coverage ≥80% on all Phase A modules
7. ✅ QG-MA0 quality gate passes
8. ✅ Zero regressions in existing workspace tests
9. ✅ All public APIs documented with examples

**You'll know it works when:** Two agents can independently modify the same memory (different fields), merge their states, and arrive at the exact same result regardless of merge order. The property tests prove this mathematically.

---

## Next Steps After Phase A

Once QG-MA0 passes, proceed to **MAPhase B: Storage + Namespaces + Projections**, which adds SQLite persistence, namespace isolation, memory projections, and sharing operations.
