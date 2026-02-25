# 01 Multi-Agent Memory — Complete File Map

> Every new and modified file required to implement MA-R1 through MA-R14.
> Follows existing Cortex conventions exactly: single-responsibility modules,
> per-subsystem `mod.rs` re-exports, `{name}_config.rs` configs,
> `{name}_error.rs` errors, per-subsystem NAPI bindings, per-subsystem
> MCP tools, per-subsystem golden fixtures.
>
> **Convention reference**: Patterns derived from cortex-temporal (event_store/*,
> snapshot/*, drift/*, epistemic/*), cortex-causal (graph/sync,
> inference/strategies, traversal/*), cortex-consolidation (pipeline/phase*,
> monitoring/*, scheduling/*), cortex-storage (migrations/v0*, queries/*),
> cortex-napi (bindings/*, conversions/*), packages/cortex (tools/*, cli/*).
>
> **Migration numbering note**: Temporal reasoning uses v014. This feature
> uses v015 to avoid collision. Adjust if implementation order changes.

---

## 1. Workspace Registration

### Modified: `crates/cortex/Cargo.toml`
- Add `"cortex-crdt"` and `"cortex-multiagent"` to `[workspace.members]`
- Add `cortex-crdt = { path = "cortex-crdt" }` to `[workspace.dependencies]`
- Add `cortex-multiagent = { path = "cortex-multiagent" }` to `[workspace.dependencies]`
- **Covers**: MA-R1, MA-R12

---

## 2. New Crate: `cortex-crdt`

### `crates/cortex/cortex-crdt/Cargo.toml`
- Package metadata (name, version.workspace, edition.workspace, etc.)
- Dependencies: cortex-core, chrono, serde, serde_json
- Dev-dependencies: proptest, criterion, test-fixtures
- Bench target: `crdt_bench`
- **Covers**: MA-R1

### `crates/cortex/cortex-crdt/src/lib.rs`
- Crate root: module declarations, re-exports of public API
- Re-exports: GCounter, LWWRegister, MVRegister, ORSet, MaxRegister,
  VectorClock, MemoryCRDT, FieldDelta, MergeEngine
- **Covers**: MA-R1

### `crates/cortex/cortex-crdt/src/clock.rs`
- `VectorClock` struct: `HashMap<AgentId, u64>`
- `increment(agent_id)` — increment agent's logical clock
- `merge(other)` — component-wise max
- `happens_before(other) -> bool` — causal ordering check
- `concurrent_with(other) -> bool` — neither happens-before
- `dominates(other) -> bool` — all components >=, at least one >
- **Covers**: MA-R1, MA-R7

---

### Primitives Module (`src/primitives/`)

### `crates/cortex/cortex-crdt/src/primitives/mod.rs`
- Module declarations, re-exports
- **Covers**: MA-R1

### `crates/cortex/cortex-crdt/src/primitives/gcounter.rs`
- `GCounter` struct: `HashMap<AgentId, u64>`
- `increment(agent_id)` — increment agent's counter
- `value() -> u64` — sum of all agent counters
- `merge(other)` — per-agent max
- `delta_since(other) -> GCounterDelta` — entries where self > other
- Serde: Serialize + Deserialize
- **Covers**: MA-R1 (access_count, retrieval_count)

### `crates/cortex/cortex-crdt/src/primitives/lww_register.rs`
- `LWWRegister<T>` struct: `{ value: T, timestamp: DateTime<Utc>, agent_id: AgentId }`
- `set(value, timestamp, agent_id)` — update if timestamp is newer
- `get() -> &T` — current value
- `merge(other)` — keep higher timestamp; tie-break on agent_id lexicographic
- `delta_since(other) -> Option<LWWDelta<T>>` — self if newer than other
- Serde: Serialize + Deserialize where T: Serialize + Deserialize
- **Covers**: MA-R1 (content, summary, memory_type, importance, archived, etc.)

### `crates/cortex/cortex-crdt/src/primitives/mv_register.rs`
- `MVRegister<T>` struct: `Vec<(T, VectorClock)>`
- `set(value, clock)` — add value, prune dominated entries
- `get() -> Vec<&T>` — all concurrent values
- `is_conflicted() -> bool` — more than one value
- `resolve(value)` — collapse to single value (manual resolution)
- `merge(other)` — keep all non-dominated entries from both
- Serde: Serialize + Deserialize where T: Serialize + Deserialize
- **Covers**: MA-R1 (content when concurrent edits must be preserved)

### `crates/cortex/cortex-crdt/src/primitives/or_set.rs`
- `ORSet<T>` struct: add-set + tombstone-set with unique tags
- `add(value, agent_id, seq) -> UniqueTag` — add with unique tag
- `remove(value)` — tombstone all current tags for value
- `contains(value) -> bool` — in add-set and not fully tombstoned
- `elements() -> Vec<&T>` — all present elements
- `merge(other)` — union of add-sets, union of tombstone-sets
- `delta_since(other) -> ORSetDelta<T>` — new adds and removes since other
- Serde: Serialize + Deserialize where T: Serialize + Deserialize + Eq + Hash
- **Covers**: MA-R1 (tags, linked_patterns, linked_constraints, linked_files, etc.)

### `crates/cortex/cortex-crdt/src/primitives/max_register.rs`
- `MaxRegister<T: Ord>` struct: `{ value: T, timestamp: DateTime<Utc> }`
- `set(value)` — update only if value > current
- `get() -> &T` — current max value
- `merge(other)` — keep greater value
- `delta_since(other) -> Option<MaxDelta<T>>` — self if greater
- Serde: Serialize + Deserialize where T: Serialize + Deserialize + Ord
- **Covers**: MA-R1 (confidence boosts, last_accessed)

---

### Memory CRDT Module (`src/memory/`)

### `crates/cortex/cortex-crdt/src/memory/mod.rs`
- Module declarations, re-exports
- **Covers**: MA-R1

### `crates/cortex/cortex-crdt/src/memory/memory_crdt.rs`
- `MemoryCRDT` struct: wraps all per-field CRDTs for a single BaseMemory
- Fields: id (immutable), memory_type (LWWRegister), content (LWWRegister),
  summary (LWWRegister), transaction_time (immutable), valid_time (LWWRegister),
  valid_until (LWWRegister), base_confidence (MaxRegister), importance (LWWRegister),
  last_accessed (MaxRegister), access_count (GCounter), linked_patterns (ORSet),
  linked_constraints (ORSet), linked_files (ORSet), linked_functions (ORSet),
  tags (ORSet), archived (LWWRegister), superseded_by (LWWRegister),
  supersedes (ORSet), namespace (LWWRegister), provenance (append-only Vec)
- `merge(other) -> MemoryCRDT` — per-field merge
- `to_base_memory() -> BaseMemory` — materialize current state
- `from_base_memory(memory, agent_id) -> MemoryCRDT` — wrap existing memory
- `content_hash() -> String` — recompute blake3 from materialized content
- **Covers**: MA-R1

### `crates/cortex/cortex-crdt/src/memory/field_delta.rs`
- `FieldDelta` enum: one variant per field type
  - `ContentUpdated { value: String, lww_timestamp: DateTime<Utc>, agent_id: AgentId }`
  - `SummaryUpdated { value: String, lww_timestamp: DateTime<Utc>, agent_id: AgentId }`
  - `ConfidenceBoosted { value: f64, max_timestamp: DateTime<Utc> }`
  - `TagAdded { tag: String, unique_tag: UniqueTag }`
  - `TagRemoved { tag: String, removed_tags: HashSet<UniqueTag> }`
  - `LinkAdded { link_type: String, target: String, unique_tag: UniqueTag }`
  - `LinkRemoved { link_type: String, target: String, removed_tags: HashSet<UniqueTag> }`
  - `AccessCountIncremented { agent: AgentId, new_count: u64 }`
  - `ImportanceChanged { value: Importance, lww_timestamp: DateTime<Utc>, agent_id: AgentId }`
  - `ArchivedChanged { value: bool, lww_timestamp: DateTime<Utc>, agent_id: AgentId }`
  - `ProvenanceHopAdded { hop: ProvenanceHop }`
  - `MemoryCreated { full_state: BaseMemory }`
  - `NamespaceChanged { namespace: NamespaceId, lww_timestamp: DateTime<Utc>, agent_id: AgentId }`
- Serde: Serialize + Deserialize
- **Covers**: MA-R1, MA-R7

### `crates/cortex/cortex-crdt/src/memory/merge_engine.rs`
- `MergeEngine` — stateless merge orchestrator
- `merge_memories(local: &MemoryCRDT, remote: &MemoryCRDT) -> MemoryCRDT`
- `apply_delta(local: &mut MemoryCRDT, delta: &MemoryDelta) -> Result<()>`
- `compute_delta(local: &MemoryCRDT, remote_clock: &VectorClock) -> MemoryDelta`
- Validates causal ordering before applying deltas
- **Covers**: MA-R1, MA-R7

---

### Causal Graph CRDT Module (`src/graph/`)

### `crates/cortex/cortex-crdt/src/graph/mod.rs`
- Module declarations, re-exports
- **Covers**: MA-R11

### `crates/cortex/cortex-crdt/src/graph/dag_crdt.rs`
- `CausalGraphCRDT` struct: edges (ORSet<CausalEdge>),
  strengths (HashMap<(MemoryId, MemoryId), MaxRegister<f64>>)
- `add_edge(edge, agent_id, seq) -> Result<()>` — local cycle check, then add
- `remove_edge(source, target)` — OR-Set remove
- `update_strength(source, target, strength)` — max-wins update
- `merge(other) -> Result<()>` — merge edges + strengths, then resolve_cycles
- `resolve_cycles()` — detect cycles, remove weakest-link edge
- `detect_cycle() -> Option<Vec<CausalEdge>>` — DFS-based cycle detection
- `would_create_cycle(edge) -> bool` — check before adding
- `to_petgraph() -> StableGraph<MemoryId, CausalEdge>` — materialize
- **Covers**: MA-R11

---

### Tests & Benchmarks (cortex-crdt)

### `crates/cortex/cortex-crdt/tests/crdt_test.rs`
- Unit tests for all CRDT primitives
- GCounter: increment, merge, value correctness
- LWWRegister: set, merge, tie-breaking by agent_id
- MVRegister: concurrent values, conflict detection, resolution
- ORSet: add, remove, add-wins semantics, merge
- MaxRegister: set, merge, only-up semantics
- VectorClock: increment, merge, happens-before, concurrent
- **Covers**: MA-R1

### `crates/cortex/cortex-crdt/tests/memory_crdt_test.rs`
- MemoryCRDT: from_base_memory round-trip
- MemoryCRDT: merge two divergent copies → convergence
- MemoryCRDT: delta computation and application
- MergeEngine: causal ordering enforcement
- **Covers**: MA-R1, MA-R7

### `crates/cortex/cortex-crdt/tests/dag_crdt_test.rs`
- CausalGraphCRDT: add edge, remove edge, merge
- Cycle detection: single edge self-loop rejected
- Cycle detection: multi-hop cycle rejected
- Merge-introduced cycle: weakest-link removed
- Strength: max-wins across agents
- **Covers**: MA-R11

### `crates/cortex/cortex-crdt/tests/property_tests.rs`
- Entry point for proptest module
- **Covers**: MA-R1, MA-R11

### `crates/cortex/cortex-crdt/tests/property/mod.rs`
- Module declarations for property test files
- **Covers**: MA-R1, MA-R11

### `crates/cortex/cortex-crdt/tests/property/crdt_properties.rs`
- GCounter: merge(A,B) == merge(B,A) (commutativity)
- GCounter: merge(A, merge(B,C)) == merge(merge(A,B), C) (associativity)
- GCounter: merge(A,A) == A (idempotency)
- LWWRegister: merge commutativity, associativity, idempotency
- ORSet: merge commutativity, associativity, idempotency
- ORSet: concurrent add + remove → element present (add-wins)
- ORSet: size bounded by unique adds
- MaxRegister: merge commutativity, value monotonically non-decreasing
- VectorClock: causal delivery never applies future deltas
- MemoryCRDT: merge(A,B) == merge(B,A) for all field types
- MemoryCRDT: after sync, both agents have same materialized state
- CausalGraphCRDT: graph is always acyclic after merge
- CausalGraphCRDT: edge add is commutative
- Trust score: always in [0.0, 1.0]
- **Covers**: MA-R1, MA-R11

### `crates/cortex/cortex-crdt/tests/stress_test.rs`
- High-volume merge: 10K memories across 5 agents
- Delta computation under load: 100K field deltas
- DAG CRDT merge with 1K edges across 3 agents
- **Covers**: MA-R1, MA-R11

### `crates/cortex/cortex-crdt/benches/crdt_bench.rs`
- GCounter merge latency (target: < 0.01ms)
- ORSet merge, 100 elements (target: < 0.1ms)
- MemoryCRDT full merge (target: < 0.5ms)
- Delta computation, 50 changed fields (target: < 0.2ms)
- DAG CRDT merge, 500 edges (target: < 5ms)
- VectorClock merge, 20 agents (target: < 0.01ms)
- **Covers**: MA-R1, MA-R11

---

## 3. New Crate: `cortex-multiagent`

### `crates/cortex/cortex-multiagent/Cargo.toml`
- Package metadata (name, version.workspace, edition.workspace, etc.)
- Dependencies: cortex-core, cortex-crdt, cortex-storage, chrono, serde,
  serde_json, tokio, uuid, dashmap
- Dev-dependencies: proptest, test-fixtures
- **Covers**: MA-R2, MA-R3, MA-R4, MA-R5, MA-R6, MA-R7

### `crates/cortex/cortex-multiagent/src/lib.rs`
- Crate root: module declarations, re-exports of public API
- Re-exports: MultiAgentEngine, AgentRegistry, NamespaceManager,
  ProjectionEngine, ProvenanceTracker, TrustScorer, DeltaSyncEngine
- **Covers**: MA-R2 through MA-R7

### `crates/cortex/cortex-multiagent/src/engine.rs`
- `MultiAgentEngine` struct: implements `IMultiAgentEngine` trait
- Holds references to WriteConnection (writes) and ReadPool (reads)
- Orchestrates registry, namespace, projection, provenance, trust, sync modules
- Single entry point for all multi-agent operations
- **Covers**: MA-R12

---

### Agent Registry Module (`src/registry/`)

### `crates/cortex/cortex-multiagent/src/registry/mod.rs`
- Module declarations, re-exports
- **Covers**: MA-R6

### `crates/cortex/cortex-multiagent/src/registry/agent_registry.rs`
- `AgentRegistry` struct: manages agent lifecycle
- `register(name, capabilities) -> Result<AgentRegistration>` — create agent + namespace
- `deregister(agent_id) -> Result<()>` — archive namespace, preserve provenance
- `get_agent(agent_id) -> Result<Option<AgentRegistration>>` — lookup
- `list_agents(filter: Option<AgentStatus>) -> Result<Vec<AgentRegistration>>`
- `update_last_active(agent_id) -> Result<()>` — heartbeat
- `mark_idle(agent_id) -> Result<()>` — status transition
- **Covers**: MA-R6

### `crates/cortex/cortex-multiagent/src/registry/spawn.rs`
- `spawn_agent(config: SpawnConfig) -> Result<AgentRegistration>`
- Creates sub-agent with parent reference
- Optionally creates projection from parent namespace
- Inherits parent trust scores (discounted by `trust_discount`)
- `deregister_spawned(agent_id, auto_promote: bool) -> Result<()>`
  — optionally promotes sub-agent memories to parent namespace
- **Covers**: MA-R6

---

### Namespace Module (`src/namespace/`)

### `crates/cortex/cortex-multiagent/src/namespace/mod.rs`
- Module declarations, re-exports
- **Covers**: MA-R2

### `crates/cortex/cortex-multiagent/src/namespace/manager.rs`
- `NamespaceManager` struct: manages namespace CRUD and permissions
- `create_namespace(scope, owner) -> Result<NamespaceId>` — create with defaults
- `get_namespace(id) -> Result<Option<NamespaceMetadata>>`
- `list_namespaces(scope_filter: Option<NamespaceScope>) -> Result<Vec<NamespaceMetadata>>`
- `delete_namespace(id) -> Result<()>` — only if empty, otherwise archive
- **Covers**: MA-R2

### `crates/cortex/cortex-multiagent/src/namespace/permissions.rs`
- `NamespacePermissionManager` struct: manages ACLs
- `grant(namespace_id, agent_id, permissions, granted_by) -> Result<()>`
- `revoke(namespace_id, agent_id, permissions) -> Result<()>`
- `check(namespace_id, agent_id, permission) -> Result<bool>`
- `get_acl(namespace_id) -> Result<NamespaceACL>`
- Default permission logic: agent=all for owner, team=read+write for members,
  project=read for all
- **Covers**: MA-R2

### `crates/cortex/cortex-multiagent/src/namespace/addressing.rs`
- `NamespaceId` parsing and formatting utilities
- `parse(uri: &str) -> Result<NamespaceId>` — parse `agent://`, `team://`, `project://`
- `to_uri() -> String` — format back to URI
- `is_agent() -> bool`, `is_team() -> bool`, `is_project() -> bool`
- `is_shared() -> bool` — team or project
- `default_namespace() -> NamespaceId` — `agent://default/`
- **Covers**: MA-R2, MA-R13

---

### Projection Module (`src/projection/`)

### `crates/cortex/cortex-multiagent/src/projection/mod.rs`
- Module declarations, re-exports
- **Covers**: MA-R3

### `crates/cortex/cortex-multiagent/src/projection/engine.rs`
- `ProjectionEngine` struct: manages projections and subscriptions
- `create_projection(projection: MemoryProjection) -> Result<ProjectionId>`
- `delete_projection(id: ProjectionId) -> Result<()>`
- `get_projection(id: ProjectionId) -> Result<Option<MemoryProjection>>`
- `list_projections(namespace: &NamespaceId) -> Result<Vec<MemoryProjection>>`
- `evaluate_filter(memory: &BaseMemory, filter: &ProjectionFilter) -> bool`
- **Covers**: MA-R3

### `crates/cortex/cortex-multiagent/src/projection/subscription.rs`
- `SubscriptionManager` struct: manages live projection subscriptions
- `subscribe(projection_id) -> Result<SubscriptionState>`
- `unsubscribe(projection_id) -> Result<()>`
- `push_delta(projection_id, delta: MemoryDelta) -> Result<()>`
  — evaluates filter, compresses to projection level, queues delta
- `drain_queue(projection_id) -> Result<Vec<MemoryDelta>>`
  — returns pending deltas for target agent
- **Covers**: MA-R3

### `crates/cortex/cortex-multiagent/src/projection/backpressure.rs`
- `BackpressureController` struct: manages sync mode transitions
- `SubscriptionState` struct: projection_id, delta_queue (bounded),
  last_sync, mode (Streaming/Batched/CatchUp), queue_high_watermark
- `SyncMode` enum: Streaming, Batched { interval }, CatchUp
- `check_backpressure(state) -> SyncMode` — transition logic
- Queue overflow → switch to Batched; catch-up request → CatchUp mode
- **Covers**: MA-R3

### `crates/cortex/cortex-multiagent/src/projection/compression.rs`
- `compress_for_projection(memory: &BaseMemory, level: CompressionLevel) -> BaseMemory`
- Delegates to cortex-compression's existing L0-L3 system
- L0: full memory, L1: summary + metadata, L2: summary + key examples,
  L3: one-line essence
- **Covers**: MA-R3

---

### Share Module (`src/share/`)

### `crates/cortex/cortex-multiagent/src/share/mod.rs`
- Module declarations, re-exports
- **Covers**: MA-R2, MA-R3

### `crates/cortex/cortex-multiagent/src/share/actions.rs`
- `share(memory_id, target_namespace, agent_id) -> Result<()>`
  — one-time copy with provenance hop
- `promote(memory_id, target_namespace, agent_id) -> Result<()>`
  — move from agent → team/project namespace
- `retract(memory_id, namespace, agent_id) -> Result<()>`
  — tombstone in target namespace via OR-Set
- Permission checks before each action
- **Covers**: MA-R2, MA-R3

---

### Provenance Module (`src/provenance/`)

### `crates/cortex/cortex-multiagent/src/provenance/mod.rs`
- Module declarations, re-exports
- **Covers**: MA-R4

### `crates/cortex/cortex-multiagent/src/provenance/tracker.rs`
- `ProvenanceTracker` struct: records and queries provenance chains
- `record_hop(memory_id, hop: ProvenanceHop) -> Result<()>` — append to chain
- `get_provenance(memory_id) -> Result<Option<ProvenanceRecord>>`
- `get_chain(memory_id) -> Result<Vec<ProvenanceHop>>` — full chain
- `get_origin(memory_id) -> Result<ProvenanceOrigin>`
- `chain_confidence(memory_id) -> Result<f64>` — product of hop confidences
- **Covers**: MA-R4

### `crates/cortex/cortex-multiagent/src/provenance/correction.rs`
- `CorrectionPropagator` struct: propagates corrections through provenance chains
- `propagate_correction(memory_id, correction: MemoryId) -> Result<Vec<CorrectionResult>>`
- Traces provenance chain, applies dampened correction at each hop
- `correction_strength(hop_distance) -> f64` — `base_strength * 0.7^hop`
- Stops propagation when strength < 0.05 threshold
- Returns list of affected memories with applied correction strengths
- **Covers**: MA-R4

### `crates/cortex/cortex-multiagent/src/provenance/cross_agent.rs`
- `CrossAgentTracer` struct: traces knowledge across agent boundaries
- `trace_cross_agent(memory_id, max_depth) -> Result<CrossAgentTrace>`
- `CrossAgentTrace` struct: agents involved, hop count, confidence chain
- Extends cortex-causal traversal with cross-agent relation types
- **Covers**: MA-R4

---

### Trust Module (`src/trust/`)

### `crates/cortex/cortex-multiagent/src/trust/mod.rs`
- Module declarations, re-exports
- **Covers**: MA-R5

### `crates/cortex/cortex-multiagent/src/trust/scorer.rs`
- `TrustScorer` struct: computes and manages agent trust scores
- `get_trust(agent_id, target_agent) -> Result<AgentTrust>`
- `compute_overall_trust(evidence: &TrustEvidence) -> f64`
  — `(validated + useful) / (total + 1) * (1 - contradicted / (total + 1))`
- `compute_domain_trust(domain, evidence) -> f64` — per-domain variant
- `effective_confidence(memory_confidence, trust_score) -> f64`
  — `memory.confidence * domain_trust`
- **Covers**: MA-R5

### `crates/cortex/cortex-multiagent/src/trust/evidence.rs`
- `TrustEvidenceTracker` struct: accumulates trust evidence
- `record_validation(agent_id, target_agent, memory_id) -> Result<()>` — +validated
- `record_contradiction(agent_id, target_agent, memory_id) -> Result<()>` — +contradicted
- `record_usage(agent_id, target_agent, memory_id) -> Result<()>` — +useful
- `get_evidence(agent_id, target_agent) -> Result<TrustEvidence>`
- **Covers**: MA-R5

### `crates/cortex/cortex-multiagent/src/trust/decay.rs`
- `apply_trust_decay(trust: &mut AgentTrust, days_since_evidence: f64)`
- Formula: `trust + (0.5 - trust) * (1 - 0.99^days)`
- Drifts toward 0.5 (neutral) when no new evidence arrives
- **Covers**: MA-R5

### `crates/cortex/cortex-multiagent/src/trust/bootstrap.rs`
- `bootstrap_trust(agent_id, target_agent) -> AgentTrust`
- New agents start at `overall_trust = 0.5`
- `bootstrap_from_parent(parent_trust, discount: f64) -> AgentTrust`
  — spawned agents inherit parent trust * discount (default 0.8)
- **Covers**: MA-R5, MA-R6

---

### Delta Sync Module (`src/sync/`)

### `crates/cortex/cortex-multiagent/src/sync/mod.rs`
- Module declarations, re-exports
- **Covers**: MA-R7

### `crates/cortex/cortex-multiagent/src/sync/protocol.rs`
- `DeltaSyncEngine` struct: orchestrates delta sync between agents
- `initiate_sync(source_agent, target_agent) -> Result<SyncResponse>`
  — sends SyncRequest with local clock, receives deltas
- `handle_sync_request(request: SyncRequest) -> Result<SyncResponse>`
  — computes deltas since requester's clock, returns with own clock
- `acknowledge_sync(ack: SyncAck) -> Result<()>` — update peer clock state
- **Covers**: MA-R7

### `crates/cortex/cortex-multiagent/src/sync/delta_queue.rs`
- `DeltaQueue` struct: persistent queue for pending deltas
- `enqueue(delta: MemoryDelta, target_agent: AgentId) -> Result<()>`
- `dequeue(target_agent: AgentId, limit: usize) -> Result<Vec<MemoryDelta>>`
- `mark_applied(delta_ids: &[u64]) -> Result<()>`
- `pending_count(target_agent: AgentId) -> Result<usize>`
- Backed by `delta_queue` table in SQLite
- **Covers**: MA-R7

### `crates/cortex/cortex-multiagent/src/sync/causal_delivery.rs`
- `CausalDeliveryManager` struct: ensures causal ordering of deltas
- `can_apply(delta: &MemoryDelta, local_clock: &VectorClock) -> bool`
  — checks all causal predecessors have been applied
- `buffer_delta(delta: MemoryDelta)` — store for later if can't apply yet
- `drain_applicable(local_clock: &VectorClock) -> Vec<MemoryDelta>`
  — return all buffered deltas that can now be applied
- **Covers**: MA-R7

### `crates/cortex/cortex-multiagent/src/sync/cloud_integration.rs`
- `CloudSyncAdapter` struct: bridges delta sync with cortex-cloud transport
- `sync_via_cloud(source_agent, target_agent) -> Result<()>`
  — uses cortex-cloud HTTP transport for remote agents
- `sync_via_local(source_agent, target_agent) -> Result<()>`
  — uses SQLite delta_queue for local agents
- `detect_sync_mode(target_agent) -> SyncTransport` — local vs cloud
- **Covers**: MA-R7

---

### Consolidation Module (`src/consolidation/`)

### `crates/cortex/cortex-multiagent/src/consolidation/mod.rs`
- Module declarations, re-exports
- **Covers**: MA-R8

### `crates/cortex/cortex-multiagent/src/consolidation/consensus.rs`
- `ConsensusDetector` struct: finds independently corroborated knowledge
- `detect_consensus(memories_by_namespace, embedding_engine, threshold) -> Vec<ConsensusCandidate>`
  — cross-namespace embedding similarity search, groups by cluster
- `ConsensusCandidate` struct: memories, similarity, agent_count, confidence_boost
- Threshold: embedding similarity > 0.9, agent_count >= 2
- Confidence boost: +0.2 for consensus (matches existing contradiction/consensus system)
- **Covers**: MA-R8

### `crates/cortex/cortex-multiagent/src/consolidation/cross_namespace.rs`
- `CrossNamespaceConsolidator` struct: extends consolidation pipeline
- Phase 0 (new): gather candidates from all team/project namespaces
- Phases 1-3: delegate to existing cortex-consolidation HDBSCAN pipeline
- Phase 4 (extended): apply consensus boost for multi-agent clusters
- Phase 5: existing pruning with cross-namespace provenance preservation
- Consolidated memory placed in team/project namespace
- **Covers**: MA-R8

---

### Validation Module (`src/validation/`)

### `crates/cortex/cortex-multiagent/src/validation/mod.rs`
- Module declarations, re-exports
- **Covers**: MA-R9

### `crates/cortex/cortex-multiagent/src/validation/cross_agent.rs`
- `CrossAgentValidator` struct: detects cross-agent contradictions
- `detect_contradictions(namespace) -> Result<Vec<CrossAgentContradiction>>`
  — checks shared namespace memories against agent namespace memories
- `resolve_contradiction(contradiction) -> Result<ContradictionResolution>`
  — trust difference > 0.3: trust wins; ≤ 0.3: human review;
    context-dependent if different scope tags; temporal supersession if newer + validated
- **Covers**: MA-R9

---

### Tests & Benchmarks (cortex-multiagent)

### `crates/cortex/cortex-multiagent/tests/registry_test.rs`
- Agent registration, deregistration, lifecycle transitions
- Spawned agent creation with parent reference
- Spawned agent deregistration with memory promotion
- Agent status transitions: Active → Idle → Deregistered
- **Covers**: MA-R6

### `crates/cortex/cortex-multiagent/tests/namespace_test.rs`
- Namespace creation for all three scopes
- Permission grant/revoke/check
- Default permissions per scope
- Namespace addressing: parse + format round-trip
- Default namespace backward compatibility
- **Covers**: MA-R2

### `crates/cortex/cortex-multiagent/tests/projection_test.rs`
- Projection creation with filter
- Filter evaluation: memory_types, min_confidence, tags, linked_files
- Live projection subscription + delta push
- Projection compression: L0 through L3
- Backpressure: queue overflow → Batched mode transition
- **Covers**: MA-R3

### `crates/cortex/cortex-multiagent/tests/provenance_test.rs`
- Provenance hop recording and chain retrieval
- Chain confidence computation
- Correction propagation with dampening
- Correction stops at threshold (depth 4+)
- Cross-agent trace across 3 agents
- **Covers**: MA-R4

### `crates/cortex/cortex-multiagent/tests/trust_test.rs`
- Trust bootstrap at 0.5
- Trust increase from validation (+0.05)
- Trust decrease from contradiction (-0.10)
- Domain-specific trust computation
- Effective confidence modulation
- Trust decay toward neutral over time
- Spawned agent trust inheritance with discount
- **Covers**: MA-R5

### `crates/cortex/cortex-multiagent/tests/sync_test.rs`
- Delta sync protocol: request → response → ack
- Causal delivery: out-of-order deltas buffered correctly
- Delta queue: enqueue, dequeue, mark_applied
- Cloud vs local sync mode detection
- **Covers**: MA-R7

### `crates/cortex/cortex-multiagent/tests/consolidation_test.rs`
- Consensus detection: 2 agents with similar memories → candidate
- Consensus detection: dissimilar memories → no candidate
- Cross-namespace consolidation pipeline
- Confidence boost applied correctly
- **Covers**: MA-R8

### `crates/cortex/cortex-multiagent/tests/validation_test.rs`
- Cross-agent contradiction detection
- Trust-weighted resolution: high trust difference → auto-resolve
- Trust-weighted resolution: low trust difference → human review
- Context-dependent resolution
- Temporal supersession resolution
- **Covers**: MA-R9

### `crates/cortex/cortex-multiagent/tests/coverage_test.rs`
- Ensures all public API surface is exercised
- Follows pattern from cortex-causal/tests/coverage_test.rs
- **Covers**: MA-R1 through MA-R14

### `crates/cortex/cortex-multiagent/tests/golden_test.rs`
- Golden dataset tests against JSON fixtures
- 3 CRDT merge scenarios
- 2 namespace permission scenarios
- 2 provenance chain scenarios
- 2 trust scoring scenarios
- 1 consensus detection scenario
- **Covers**: MA-R1 through MA-R9

### `crates/cortex/cortex-multiagent/tests/stress_test.rs`
- 5 agents, 10K memories, full sync cycle
- Concurrent delta application from 3 agents
- Projection with 1K matching memories, live updates
- Trust computation with 10K evidence records
- **Covers**: MA-R1 through MA-R7

---

## 4. Golden Test Fixtures

### `crates/cortex/test-fixtures/golden/multiagent/`
Directory for multi-agent golden test data.

### `crates/cortex/test-fixtures/golden/multiagent/crdt_merge_simple.json`
- 2 agents, 1 memory, divergent tag edits, expected merged state
- **Covers**: MA-R1

### `crates/cortex/test-fixtures/golden/multiagent/crdt_merge_conflict.json`
- 2 agents, concurrent content edits (LWW), expected winner by timestamp
- **Covers**: MA-R1

### `crates/cortex/test-fixtures/golden/multiagent/crdt_merge_confidence.json`
- 3 agents, confidence boosts via MaxRegister, expected max value
- **Covers**: MA-R1

### `crates/cortex/test-fixtures/golden/multiagent/namespace_permissions.json`
- Agent, team, project namespaces with various permission grants, expected access results
- **Covers**: MA-R2

### `crates/cortex/test-fixtures/golden/multiagent/namespace_default_compat.json`
- Single-agent scenario with default namespace, expected identical behavior to v1
- **Covers**: MA-R2, MA-R13

### `crates/cortex/test-fixtures/golden/multiagent/provenance_chain.json`
- 3-agent provenance chain (create → share → refine), expected chain + confidence
- **Covers**: MA-R4

### `crates/cortex/test-fixtures/golden/multiagent/provenance_correction.json`
- Correction at depth 0, expected dampened propagation at depths 1-3
- **Covers**: MA-R4

### `crates/cortex/test-fixtures/golden/multiagent/trust_scoring.json`
- Agent with known evidence (5 validated, 1 contradicted, 3 useful, 10 total),
  expected overall trust and domain trust values
- **Covers**: MA-R5

### `crates/cortex/test-fixtures/golden/multiagent/trust_decay.json`
- Trust score after 50 days and 100 days without evidence, expected decayed values
- **Covers**: MA-R5

### `crates/cortex/test-fixtures/golden/multiagent/consensus_detection.json`
- 3 agents with similar memories about same topic, expected consensus candidate
- **Covers**: MA-R8

---

## 5. Modifications to `cortex-core`

### Modified: `crates/cortex/cortex-core/src/models/mod.rs`
- Add `pub mod agent;`
- Add `pub mod namespace;`
- Add `pub mod provenance;`
- Add `pub mod cross_agent;`
- Re-export all new types
- **Covers**: MA-R12 (cortex-core)

### New: `crates/cortex/cortex-core/src/models/agent.rs`
- `AgentId` struct (UUID-based String wrapper)
- `AgentId::new() -> Self` — UUID v4
- `AgentId::default_agent() -> Self` — `"default"` for backward compat
- `AgentRegistration` struct (agent_id, name, namespace, capabilities,
  parent_agent, registered_at, last_active, status)
- `AgentStatus` enum (Active, Idle { since }, Deregistered { at })
- `SpawnConfig` struct (parent_agent, projection, trust_discount,
  auto_promote_on_deregister, ttl)
- **Covers**: MA-R6, MA-R12

### New: `crates/cortex/cortex-core/src/models/namespace.rs`
- `NamespaceId` struct (scope, name)
- `NamespaceScope` enum (Agent(AgentId), Team(String), Project(String))
- `NamespacePermission` enum (Read, Write, Share, Admin)
- `NamespaceACL` struct (namespace, grants)
- `MemoryProjection` struct (id, source, target, filter, compression_level,
  live, created_at, created_by)
- `ProjectionFilter` struct (memory_types, min_confidence, min_importance,
  linked_files, tags, max_age_days, predicate)
- **Covers**: MA-R2, MA-R3, MA-R12

### New: `crates/cortex/cortex-core/src/models/provenance.rs`
- `ProvenanceRecord` struct (memory_id, origin, chain, chain_confidence)
- `ProvenanceOrigin` enum (Human, AgentCreated, Derived, Imported, Projected)
- `ProvenanceHop` struct (agent_id, action, timestamp, confidence_delta)
- `ProvenanceAction` enum (Created, SharedTo, ProjectedTo, MergedWith,
  ConsolidatedFrom, ValidatedBy, UsedInDecision, CorrectedBy, ReclassifiedFrom)
- **Covers**: MA-R4, MA-R12

### New: `crates/cortex/cortex-core/src/models/cross_agent.rs`
- `CrossAgentRelation` enum (InformedBy, DecisionBasedOn,
  IndependentCorroboration, CrossAgentContradiction, Refinement)
- `CrossAgentContradiction` struct (memory_a, agent_a, trust_a,
  memory_b, agent_b, trust_b, contradiction_type, resolution)
- `ContradictionResolution` enum (TrustWins, NeedsHumanReview,
  ContextDependent, TemporalSupersession)
- `AgentTrust` struct (agent_id, target_agent, overall_trust,
  domain_trust, evidence, last_updated)
- `TrustEvidence` struct (validated_count, contradicted_count,
  useful_count, total_received)
- **Covers**: MA-R5, MA-R9, MA-R12

---

### Modified: `crates/cortex/cortex-core/src/memory/base.rs`
- Add `namespace: NamespaceId` field to `BaseMemory` (default: `agent://default/`)
- Add `source_agent: AgentId` field to `BaseMemory` (default: `AgentId::default_agent()`)
- Update `empty_memory_shell` in cortex-temporal to include new fields
- **Covers**: MA-R12, MA-R13

### Modified: `crates/cortex/cortex-core/src/memory/relationships.rs`
- Add `CrossAgent(CrossAgentRelation)` variant to existing relationship enum
- **Covers**: MA-R4, MA-R12

---

### Modified: `crates/cortex/cortex-core/src/errors/mod.rs`
- Add `pub mod multiagent_error;`
- Re-export `MultiAgentError`
- **Covers**: MA-R12

### New: `crates/cortex/cortex-core/src/errors/multiagent_error.rs`
- `MultiAgentError` enum:
  - `AgentNotFound(String)`
  - `AgentAlreadyRegistered(String)`
  - `NamespaceNotFound(String)`
  - `PermissionDenied { agent: String, namespace: String, permission: String }`
  - `ProjectionNotFound(String)`
  - `InvalidNamespaceUri(String)`
  - `CausalOrderViolation { expected: String, found: String }`
  - `CyclicDependency(String)`
  - `SyncFailed(String)`
  - `TrustComputationFailed(String)`
- Implements `From<MultiAgentError> for CortexError`
- **Covers**: MA-R12

---

### Modified: `crates/cortex/cortex-core/src/traits/mod.rs`
- Add `pub mod multiagent_engine;`
- Re-export `IMultiAgentEngine`
- **Covers**: MA-R12

### New: `crates/cortex/cortex-core/src/traits/multiagent_engine.rs`
- `IMultiAgentEngine` trait (async_trait):
  - `register_agent(&self, name, capabilities) -> Result<AgentRegistration>`
  - `deregister_agent(&self, agent_id) -> Result<()>`
  - `get_agent(&self, agent_id) -> Result<Option<AgentRegistration>>`
  - `list_agents(&self) -> Result<Vec<AgentRegistration>>`
  - `create_namespace(&self, scope, owner) -> Result<NamespaceId>`
  - `check_permission(&self, namespace, agent, permission) -> Result<bool>`
  - `share_memory(&self, memory_id, target_namespace, agent_id) -> Result<()>`
  - `create_projection(&self, projection) -> Result<ProjectionId>`
  - `sync_with(&self, target_agent) -> Result<SyncResult>`
  - `get_provenance(&self, memory_id) -> Result<Option<ProvenanceRecord>>`
  - `get_trust(&self, agent_id, target_agent) -> Result<AgentTrust>`
  - `detect_consensus(&self, namespace) -> Result<Vec<ConsensusCandidate>>`
- **Covers**: MA-R12

---

### Modified: `crates/cortex/cortex-core/src/config/mod.rs`
- Add `pub mod multiagent_config;`
- Re-export `MultiAgentConfig`
- **Covers**: MA-R12

### New: `crates/cortex/cortex-core/src/config/multiagent_config.rs`
- `MultiAgentConfig` struct:
  - `enabled: bool` (default: false — opt-in activation)
  - `default_namespace: String` (default: `"agent://default/"`)
  - `agent_idle_timeout_hours: u64` (default: 24)
  - `delta_queue_max_size: usize` (default: 1000)
  - `backpressure_batch_interval_secs: u64` (default: 60)
  - `trust_bootstrap_score: f64` (default: 0.5)
  - `trust_decay_rate: f64` (default: 0.99)
  - `trust_contradiction_penalty: f64` (default: 0.10)
  - `trust_validation_bonus: f64` (default: 0.05)
  - `trust_usage_bonus: f64` (default: 0.02)
  - `spawn_trust_discount: f64` (default: 0.8)
  - `correction_dampening_factor: f64` (default: 0.7)
  - `correction_min_threshold: f64` (default: 0.05)
  - `consensus_similarity_threshold: f64` (default: 0.9)
  - `consensus_min_agents: usize` (default: 2)
  - `consensus_confidence_boost: f64` (default: 0.2)
  - `contradiction_trust_auto_resolve_threshold: f64` (default: 0.3)
- `impl Default for MultiAgentConfig`
- **Covers**: MA-R1 through MA-R9

---

## 6. Modifications to `cortex-storage`

### Modified: `crates/cortex/cortex-storage/src/migrations/mod.rs`
- Add `pub mod v015_multiagent_tables;`
- Register v015 in migration runner
- **Covers**: MA-R10

### New: `crates/cortex/cortex-storage/src/migrations/v015_multiagent_tables.rs`
- `agent_registry` table + 2 indexes (status, parent)
- `memory_namespaces` table
- `namespace_permissions` table (composite PK: namespace_id + agent_id)
- `memory_projections` table + 2 indexes (source, target)
- `provenance_log` table + 2 indexes (memory, agent)
- `agent_trust` table (composite PK: agent_id + target_agent)
- `delta_queue` table + 2 indexes (target+applied, created_at)
- ALTER TABLE memories ADD COLUMN namespace_id (default `'agent://default/'`)
- ALTER TABLE memories ADD COLUMN source_agent (default `'default'`)
- 2 new indexes on memories (namespace_id, source_agent)
- **Covers**: MA-R10

### Modified: `crates/cortex/cortex-storage/src/queries/mod.rs`
- Add `pub mod multiagent_ops;`
- **Covers**: MA-R10

### New: `crates/cortex/cortex-storage/src/queries/multiagent_ops.rs`
- Agent registry CRUD: insert_agent, get_agent, list_agents, update_agent_status,
  update_last_active, delete_agent
- Namespace CRUD: insert_namespace, get_namespace, list_namespaces, delete_namespace
- Permission CRUD: insert_permission, get_permissions, check_permission,
  delete_permission
- Projection CRUD: insert_projection, get_projection, list_projections,
  delete_projection
- Provenance: insert_provenance_hop, get_provenance_chain, get_provenance_origin
- Trust: insert_trust, get_trust, update_trust, list_trust_for_agent
- Delta queue: enqueue_delta, dequeue_deltas, mark_deltas_applied,
  pending_delta_count, purge_applied_deltas
- Raw SQL operations, no business logic
- **Covers**: MA-R10

### Modified: `crates/cortex/cortex-storage/src/queries/memory_crud.rs`
- Extend `create_memory()` to include namespace_id and source_agent columns
- Extend `get_memory()` to return namespace_id and source_agent
- Add `get_memories_by_namespace(namespace_id) -> Vec<BaseMemory>`
- Add `get_memories_by_agent(agent_id) -> Vec<BaseMemory>`
- **Covers**: MA-R10, MA-R12

### Modified: `crates/cortex/cortex-storage/src/queries/memory_query.rs`
- Add optional `namespace_filter: Option<NamespaceId>` parameter to search queries
- When namespace_filter is Some, add `WHERE namespace_id = ?` clause
- When namespace_filter is None, search all namespaces (backward compat)
- **Covers**: MA-R10, MA-R12, MA-R13

---

## 7. Modifications to `cortex-cloud`

### Modified: `crates/cortex/cortex-cloud/src/sync/protocol.rs`
- Extend sync request/response to include `agent_id: AgentId` field
- When multi-agent is enabled, sync carries agent provenance metadata
- **Covers**: MA-R7, MA-R12

### Modified: `crates/cortex/cortex-cloud/src/conflict/resolver.rs`
- When multi-agent is enabled, use CRDT merge instead of LWW/local-wins/remote-wins
- Existing conflict resolution strategies remain for single-agent scenarios
- **Covers**: MA-R1, MA-R12

---

## 8. Modifications to `cortex-session`

### Modified: `crates/cortex/cortex-session/src/context.rs`
- Add `agent_id: AgentId` field to `SessionContext` (default: `AgentId::default_agent()`)
- **Covers**: MA-R12

### Modified: `crates/cortex/cortex-session/src/dedup.rs`
- Session dedup is now per-agent within a namespace
- Dedup key changes from `(session_id, content_hash)` to
  `(session_id, agent_id, namespace_id, content_hash)`
- **Covers**: MA-R12

---

## 9. Modifications to `cortex-causal`

### Modified: `crates/cortex/cortex-causal/src/relations.rs`
- Add `CrossAgent(CrossAgentRelation)` variant to `CausalRelation` enum
- **Covers**: MA-R4, MA-R12

### Modified: `crates/cortex/cortex-causal/src/graph/sync.rs`
- Extend `CausalEdge` with optional `source_agent: Option<AgentId>` field
- **Covers**: MA-R4, MA-R12

### New: `crates/cortex/cortex-causal/src/graph/cross_agent.rs`
- `trace_cross_agent(memory_id, max_depth) -> TraversalResult`
  — follows provenance across agent boundaries
- `cross_agent_narrative(trace) -> String` — narrative template for
  cross-agent causal chains
- **Covers**: MA-R4, MA-R12

---

## 10. Modifications to `cortex-consolidation`

### Modified: `crates/cortex/cortex-consolidation/src/engine.rs`
- When multi-agent is enabled, extend consolidation to work across namespaces
- Delegates cross-namespace logic to cortex-multiagent's consolidation module
- **Covers**: MA-R8, MA-R12

### Modified: `crates/cortex/cortex-consolidation/src/pipeline/phase6_pruning.rs`
- When archiving consolidated memories, preserve cross-agent provenance
- Consolidated memory placed in team/project namespace with all contributing agents
- **Covers**: MA-R8, MA-R12

---

## 11. Modifications to `cortex-validation`

### Modified: `crates/cortex/cortex-validation/src/engine.rs`
- When multi-agent is enabled, extend contradiction detection across namespaces
- Delegates cross-agent logic to cortex-multiagent's validation module
- After validation, update trust evidence for source agents
- **Covers**: MA-R9, MA-R12

---

## 12. Modifications to `cortex-retrieval`

### Modified: `crates/cortex/cortex-retrieval/src/ranking/scorer.rs`
- When multi-agent is enabled, add trust-weighted scoring factor
- `trust_score(memory, agent_trust) -> f64` — modulates ranking by source trust
- Memories from higher-trust agents rank higher in retrieval results
- **Covers**: MA-R5, MA-R12

### Modified: `crates/cortex/cortex-retrieval/src/engine.rs`
- Add optional `namespace_filter: Option<NamespaceId>` to retrieval queries
- Respect projection compression levels when retrieving projected memories
- **Covers**: MA-R3, MA-R12

---

## 13. Modifications to `cortex-napi`

### Modified: `crates/cortex/cortex-napi/src/bindings/mod.rs`
- Add `pub mod multiagent;`
- **Covers**: MA-R12

### New: `crates/cortex/cortex-napi/src/bindings/multiagent.rs`
- `register_agent(name, capabilities) -> NapiAgentRegistration`
- `deregister_agent(agent_id) -> ()`
- `get_agent(agent_id) -> Option<NapiAgentRegistration>`
- `list_agents() -> Vec<NapiAgentRegistration>`
- `create_namespace(scope, name, owner) -> String` (namespace_id)
- `share_memory(memory_id, target_namespace, agent_id) -> ()`
- `create_projection(source, target, filter_json, compression, live) -> String`
- `retract_memory(memory_id, namespace, agent_id) -> ()`
- `get_provenance(memory_id) -> Option<NapiProvenanceRecord>`
- `trace_cross_agent(memory_id, max_depth) -> NapiCrossAgentTrace`
- `get_trust(agent_id, target_agent) -> NapiAgentTrust`
- `sync_agents(source_agent, target_agent) -> NapiSyncResult`
- All functions are `#[napi]` annotated
- **Covers**: MA-R12

### Modified: `crates/cortex/cortex-napi/src/conversions/mod.rs`
- Add `pub mod multiagent_types;`
- **Covers**: MA-R12

### New: `crates/cortex/cortex-napi/src/conversions/multiagent_types.rs`
- `NapiAgentRegistration` — JS-friendly AgentRegistration
- `NapiProvenanceRecord` — JS-friendly ProvenanceRecord
- `NapiProvenanceHop` — JS-friendly ProvenanceHop
- `NapiCrossAgentTrace` — JS-friendly CrossAgentTrace
- `NapiAgentTrust` — JS-friendly AgentTrust
- `NapiSyncResult` — JS-friendly SyncResult
- `NapiNamespaceACL` — JS-friendly NamespaceACL
- From/Into conversions between Rust and NAPI types
- **Covers**: MA-R12

---

## 14. Modifications to TypeScript Package (`packages/cortex`)

### Modified: `packages/cortex/src/bridge/types.ts`
- Add TypeScript interfaces:
  - `AgentRegistration`, `AgentStatus`, `AgentId`
  - `NamespaceId`, `NamespaceScope`, `NamespacePermission`, `NamespaceACL`
  - `MemoryProjection`, `ProjectionFilter`
  - `ProvenanceRecord`, `ProvenanceHop`, `ProvenanceOrigin`, `ProvenanceAction`
  - `AgentTrust`, `TrustEvidence`
  - `CrossAgentContradiction`, `ContradictionResolution`
  - `SyncResult`, `CrossAgentTrace`
- **Covers**: MA-R12

### Modified: `packages/cortex/src/bridge/client.ts`
- Add multi-agent methods:
  - `registerAgent(name, capabilities)`
  - `deregisterAgent(agentId)`
  - `getAgent(agentId)`, `listAgents()`
  - `createNamespace(scope, name, owner?)`
  - `shareMemory(memoryId, targetNamespace, agentId)`
  - `createProjection(source, target, filter, compression?, live?)`
  - `retractMemory(memoryId, namespace, agentId)`
  - `getProvenance(memoryId)`
  - `traceCrossAgent(memoryId, maxDepth?)`
  - `getTrust(agentId, targetAgent)`
  - `syncAgents(sourceAgent, targetAgent)`
- **Covers**: MA-R12

---

### MCP Tools (new directory)

### `packages/cortex/src/tools/multiagent/`
Directory for multi-agent MCP tools.

### `packages/cortex/src/tools/multiagent/drift_agent_register.ts`
- MCP tool: `drift_agent_register`
- Input: name, capabilities (optional array)
- Output: AgentRegistration with agent_id and namespace
- Calls bridge.registerAgent()
- **Covers**: MA-R6, MA-R12

### `packages/cortex/src/tools/multiagent/drift_agent_share.ts`
- MCP tool: `drift_agent_share`
- Input: memory_id, target_namespace, agent_id
- Output: success confirmation with provenance hop
- Calls bridge.shareMemory()
- **Covers**: MA-R2, MA-R3, MA-R12

### `packages/cortex/src/tools/multiagent/drift_agent_project.ts`
- MCP tool: `drift_agent_project`
- Input: source_namespace, target_namespace, filter (optional),
  compression_level (optional), live (optional)
- Output: projection_id
- Calls bridge.createProjection()
- **Covers**: MA-R3, MA-R12

### `packages/cortex/src/tools/multiagent/drift_agent_provenance.ts`
- MCP tool: `drift_agent_provenance`
- Input: memory_id, max_depth (optional)
- Output: provenance chain with all hops, origin, chain_confidence
- Calls bridge.getProvenance() + bridge.traceCrossAgent()
- **Covers**: MA-R4, MA-R12

### `packages/cortex/src/tools/multiagent/drift_agent_trust.ts`
- MCP tool: `drift_agent_trust`
- Input: agent_id, target_agent (optional — if omitted, returns all trust scores)
- Output: trust scores (overall + per-domain) with evidence breakdown
- Calls bridge.getTrust()
- **Covers**: MA-R5, MA-R12

### Modified: `packages/cortex/src/tools/index.ts`
- Register all 5 new multi-agent tools
- **Covers**: MA-R12

---

### CLI Commands (new files)

### `packages/cortex/src/cli/agents.ts`
- CLI command: `drift cortex agents`
- Subcommands: list, register, deregister, info
- Options: --status (filter by status), --capabilities (filter by capability)
- Calls bridge.listAgents(), bridge.registerAgent(), etc.
- **Covers**: MA-R6, MA-R12

### `packages/cortex/src/cli/namespaces.ts`
- CLI command: `drift cortex namespaces`
- Subcommands: list, create, permissions
- Options: --scope (agent/team/project), --agent (filter by agent)
- Calls bridge.createNamespace(), etc.
- **Covers**: MA-R2, MA-R12

### `packages/cortex/src/cli/provenance.ts`
- CLI command: `drift cortex provenance`
- Input: <memory-id>
- Options: --depth (max trace depth), --format (text/json)
- Calls bridge.getProvenance() + bridge.traceCrossAgent()
- **Covers**: MA-R4, MA-R12

### Modified: `packages/cortex/src/cli/index.ts`
- Register agents, namespaces, provenance commands
- **Covers**: MA-R12

---

### TypeScript Tests

### Modified: `packages/cortex/tests/bridge.test.ts`
- Add test cases for all multi-agent bridge methods
- registerAgent, deregisterAgent, getAgent, listAgents
- createNamespace, shareMemory, createProjection, retractMemory
- getProvenance, traceCrossAgent, getTrust, syncAgents
- **Covers**: MA-R12

---

## Summary

### File Counts

| Category | New Files | Modified Files |
|----------|-----------|----------------|
| cortex-crdt crate (src/) | 14 | 0 |
| cortex-crdt crate (tests/) | 8 | 0 |
| cortex-crdt crate (benches/) | 1 | 0 |
| cortex-multiagent crate (src/) | 25 | 0 |
| cortex-multiagent crate (tests/) | 10 | 0 |
| cortex-core models | 4 | 2 |
| cortex-core errors | 1 | 1 |
| cortex-core traits | 1 | 1 |
| cortex-core config | 1 | 1 |
| cortex-storage migrations | 1 | 1 |
| cortex-storage queries | 1 | 3 |
| cortex-cloud | 0 | 2 |
| cortex-session | 0 | 2 |
| cortex-causal | 1 | 2 |
| cortex-consolidation | 0 | 2 |
| cortex-validation | 0 | 1 |
| cortex-retrieval | 0 | 2 |
| cortex-napi | 2 | 2 |
| Golden test fixtures | 10 | 0 |
| TypeScript bridge | 0 | 2 |
| TypeScript MCP tools | 5 | 1 |
| TypeScript CLI | 3 | 1 |
| TypeScript tests | 0 | 1 |
| Workspace config | 0 | 1 |
| **TOTAL** | **88** | **28** |

### Recommendation Coverage Matrix

| Recommendation | Files That Cover It |
|---|---|
| MA-R1 (CRDT Foundation) | primitives/*.rs, memory/*.rs, crdt_test.rs, crdt_properties.rs, crdt_bench.rs, memory_crdt_test.rs |
| MA-R2 (Namespaces) | namespace/*.rs, share/actions.rs, namespace.rs (model), namespace_test.rs, v015 migration, multiagent_ops.rs |
| MA-R3 (Projections) | projection/*.rs, share/actions.rs, compression.rs, projection_test.rs, namespace.rs (model) |
| MA-R4 (Provenance) | provenance/*.rs, provenance.rs (model), cross_agent.rs (model), provenance_test.rs, relations.rs, graph/cross_agent.rs |
| MA-R5 (Trust) | trust/*.rs, cross_agent.rs (model), trust_test.rs, scorer.rs (retrieval) |
| MA-R6 (Registry) | registry/*.rs, agent.rs (model), registry_test.rs, drift_agent_register.ts, agents.ts (CLI) |
| MA-R7 (Delta Sync) | sync/*.rs, field_delta.rs, clock.rs, sync_test.rs, cloud_integration.rs, protocol.rs (cloud) |
| MA-R8 (Consolidation) | consolidation/*.rs, consolidation_test.rs, engine.rs + phase6 (cortex-consolidation) |
| MA-R9 (Validation) | validation/*.rs, validation_test.rs, engine.rs (cortex-validation), cross_agent.rs (model) |
| MA-R10 (Storage) | v015_multiagent_tables.rs, multiagent_ops.rs, memory_crud.rs, memory_query.rs |
| MA-R11 (DAG CRDT) | graph/*.rs, dag_crdt_test.rs, crdt_properties.rs (graph properties) |
| MA-R12 (Integration) | All modified files across 9 crates + NAPI + TypeScript |
| MA-R13 (Backward Compat) | Enforced by default namespace, opt-in activation, additive-only design |
| MA-R14 (Novelty) | Validated by gap analysis; no file changes needed (context only) |
