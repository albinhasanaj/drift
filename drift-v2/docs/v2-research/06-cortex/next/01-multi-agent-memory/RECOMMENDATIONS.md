# 01 Multi-Agent Memory — Recommendations

> Concrete implementation recommendations for adding multi-agent memory sharing,
> CRDT-based convergence, namespace isolation, cross-agent provenance, and trust
> scoring to Cortex. Derived from 5 research documents (01-PRIOR-ART through
> 05-CORTEX-MAPPING), validated against 16 external sources spanning multi-agent
> memory architectures, CRDT theory, distributed systems, collaborative memory
> frameworks, and trust/provenance research.
>
> **Key insight**: The multi-agent memory problem is fundamentally a distributed
> systems problem disguised as an AI problem. Every agent is a replica. Every
> memory mutation is an operation. Convergence without coordination is the
> requirement. CRDTs provide the mathematical guarantee. What's novel is applying
> CRDT theory to a typed, confidence-scored, causally-linked memory system with
> 23 memory types, hierarchical compression, and cross-agent provenance — something
> no existing system has attempted.

---

## Research Sources (Verified)

| ID | Source | Year | Relevance |
|----|--------|------|-----------|
| MA1 | [BMAM — Brain-inspired Multi-Agent Memory](https://arxiv.org/abs/2601.20465) — Li et al. | 2026 | Functionally specialized memory subsystems; 78.45% LoCoMo; validates type decomposition |
| MA2 | [LatentMem — Customizable Agent-Specific Memory](https://huggingface.co/papers/2602.03036) | 2026 | Learnable latent projections for per-agent memory views; validates projection concept |
| MA3 | [MIRIX — Six-Type Multi-Agent Memory](https://arxiv.org/abs/2507.07957) — Wang, Chen | 2025 | 6 memory types with multi-agent coordination; closest competitor architecture |
| MA4 | [Mem0 — Production Long-Term Memory with Graph](https://arxiv.org/abs/2504.19413) — Chhikara et al. | 2025 | 26% improvement over OpenAI memory; graph consolidation; single-agent only |
| MA5 | [MemOS — Memory Operating System](https://arxiv.org/html/2507.03724) | 2025 | Memory-as-OS framing; unified write/search/merge/revise API; single-agent |
| MA6 | [AMA — Adaptive Memory via Multi-Agent Collaboration](https://arxiv.org/abs/2601.20352) | 2026 | Multi-agent memory adaptation; task-aligned memory construction |
| MA7 | [Collaborative Memory — Dynamic Access Control](https://openreview.net/forum?id=pJUQ5YA98Z) | 2026 | Provable asymmetric time-varying policies; full auditability |
| MA8 | [Emergent Collective Memory in Decentralized MAS](https://arxiv.org/html/2512.10166v1) | 2025 | Collective memory emergence without centralized control |
| MA9 | [CRDT Theory — Approaches to CRDTs](https://dl.acm.org/doi/10.1145/3695249) — Shapiro et al. | 2024 | Definitive CRDT taxonomy: state-based, op-based, delta-state |
| MA10 | [Delta-State CRDTs](https://arxiv.org/abs/1410.2803) — Almeida et al. | 2018 | Delta-state: small messages over unreliable channels |
| MA11 | [EverMemOS — SOTA Memory OS](https://www.prnewswire.com/news-releases/end-agentic-amnesia-evermind-launches-a-memory-platform-and-an-80-000-global-competition-as-evermemos-sets-new-sota-results-across-multiple-benchmarks-302678025.html) | 2026 | 93.05% LoCoMo SOTA; 3-phase engram lifecycle; single-agent |
| MA12 | [BMAS — PFC-Guided Multi-Agent Coordination](https://openreview.net/forum?id=YqFLsI44vN) | 2026 | PFC-inspired task coordination + hippocampus-neocortex dual memory |
| MA13 | [Rust `crdts` crate](https://docs.rs/crdts) | 2024 | Production Rust CRDTs: GCounter, PNCounter, MVReg, ORSwot, LWWReg, VClock |
| MA14 | [Datacake — Distributed Systems Framework](https://docs.rs/datacake) | 2023 | ORSWOT CRDT + eventually consistent storage in Rust |
| MA15 | [Cost/Accuracy of LTM in Distributed MAS](https://arxiv.org/html/2601.07978v2) | 2026 | Mem0 vs Graphiti: mem0 faster, lower resources; accuracy not significant |
| MA16 | [Formal Trust Verification in MAS](https://www.mdpi.com/2227-7390/14/3/456) | 2026 | Formal trust verification under generalized possibility theory |

---

## MA-R1: CRDT Crate Foundation — Conflict-Free Primitives for Memory Fields

**Priority**: P0 — Every multi-agent feature depends on deterministic merge semantics
**Evidence**: MA9, MA10, MA13, MA14, 02-CRDT-FOUNDATIONS.md

The fundamental insight from CRDT theory (MA9, Shapiro et al.) is that if every
field of a data structure has a mathematically defined merge operation that is
commutative, associative, and idempotent, then replicas will converge to the same
state regardless of message ordering, duplication, or loss. This is exactly what
we need for multi-agent memory: agents work independently, sync when convenient,
and always converge.

**Why delta-state over pure state-based (MA10)**: Full state sync of 10K memories
is prohibitively expensive. Delta-state CRDTs send only the change since last sync,
achieving the small message size of operation-based CRDTs while retaining the
unreliable-channel tolerance of state-based CRDTs. Almeida et al. prove that
delta-state CRDTs maintain all convergence guarantees while reducing bandwidth
by orders of magnitude.

**Why a dedicated crate**: CRDT primitives are pure data structures with no
Cortex-specific logic. They belong in `cortex-crdt` so they can be tested in
isolation, potentially reused, and don't pollute cortex-core with merge logic.
The Rust `crdts` crate (MA13) provides reference implementations but is too
general — we need Cortex-specific optimizations (e.g., confidence as Max-Register
with local-only decay).

### CRDT Primitives Required

**G-Counter (Grow-only Counter)** — For: `access_count`, `retrieval_count`

Each agent maintains its own counter. Merge = take max per agent. Value = sum.
Guarantees: monotonically increasing, no lost increments, commutative merge.

**LWW-Register (Last-Writer-Wins Register)** — For: `content`, `summary`,
`memory_type`, `importance`, `archived`, `superseded_by`, `valid_time`, `valid_until`

Each update carries a timestamp + agent_id. Merge = keep highest timestamp.
Tie-breaking: timestamp first, then agent_id lexicographic. Deterministic
convergence even with synchronized clocks.

**MV-Register (Multi-Value Register)** — For: `content` when concurrent edits
must be preserved for manual resolution

Merge = keep all concurrent values (vector clock comparison). When
`is_conflicted()` returns true, surface to user via cortex-cloud's existing
conflict resolution UI.

**OR-Set (Observed-Remove Set)** — For: `tags`, `linked_patterns`,
`linked_constraints`, `linked_files`, `linked_functions`, `supersedes`

Add-wins semantics: concurrent add + remove = element is present. This matches
developer expectations — if Agent A adds a tag while Agent B removes it, the
tag stays (the add had information the remove didn't).

**Max-Register** — For: `confidence` (explicit boosts only), `last_accessed`

Only values greater than current propagate. Prevents accidental confidence loss
from stale replicas.

**Vector Clock** — For: causal ordering of deltas between agents

Each agent increments its own clock entry on every mutation. Deltas are applied
only when all causally preceding deltas have been applied.

### Per-Field CRDT Type Mapping for BaseMemory

| Field | CRDT Type | Merge Semantics |
|-------|-----------|-----------------|
| `id` | Immutable | First-write wins (UUID, never changes) |
| `memory_type` | LWW-Register | Last reclassification wins |
| `content` | LWW-Register / MV-Register (opt-in) | Last edit wins / preserve conflicts |
| `summary` | LWW-Register | Last edit wins |
| `transaction_time` | Immutable | Set at creation, never changes |
| `valid_time` | LWW-Register | Can be corrected |
| `valid_until` | LWW-Register | Can be extended/shortened |
| `confidence` | Max-Register | Only explicit boosts propagate |
| `importance` | LWW-Register | Last reclassification wins |
| `last_accessed` | Max-Register | Most recent access wins |
| `access_count` | G-Counter | Per-agent counters, sum for total |
| `linked_patterns` | OR-Set | Add wins over concurrent remove |
| `linked_constraints` | OR-Set | Add wins over concurrent remove |
| `linked_files` | OR-Set | Add wins over concurrent remove |
| `linked_functions` | OR-Set | Add wins over concurrent remove |
| `tags` | OR-Set | Add wins over concurrent remove |
| `archived` | LWW-Register | Explicit archive/restore |
| `superseded_by` | LWW-Register | Explicit supersession |
| `supersedes` | OR-Set | Can supersede multiple |
| `content_hash` | Derived | Recomputed from content after merge |
| `namespace` | LWW-Register | Explicit promote/move |
| `provenance` | Append-only log | Union of all provenance hops |

### Confidence: The Special Case

Confidence is modified by two fundamentally different mechanisms:

1. **Explicit actions** (user boost, validation pass, consensus) — propagate via Max-Register
2. **Automatic decay** (time-based, per-agent) — local only

Solution: decompose into `base_confidence` (CRDT, propagates) and `decay_factor`
(local, per-agent). Effective confidence = `base_confidence * decay_factor`.

This means if Agent A hasn't accessed a memory in months (low local_decay) but
Agent B just validated it (high base_confidence), Agent A sees the boost but
retains its own decay factor. Cognitively correct — relevance is personal,
truth is shared.

### Storage Overhead Analysis

For 10K memories across 5 agents:

| Component | Per-Memory | Total (10K) |
|-----------|-----------|-------------|
| Vector clocks (5 agents x 8 bytes) | 40 bytes | 400 KB |
| OR-Set metadata (tags, ~5 x 50 bytes) | 250 bytes | 2.5 MB |
| OR-Set metadata (links, ~3 x 50 bytes) | 150 bytes | 1.5 MB |
| G-Counter (access_count, 5 x 8 bytes) | 40 bytes | 400 KB |
| LWW timestamps (10 fields x 16 bytes) | 160 bytes | 1.6 MB |
| Delta log (last 1000 deltas x ~200 bytes) | — | 200 KB |
| **Total CRDT overhead** | **~640 bytes** | **~6.6 MB** |

Negligible. Embedding vectors alone consume ~40MB (10K x 1024 dims x 4 bytes).

---

## MA-R2: Namespace Architecture — Three-Level Memory Isolation

**Priority**: P0 — Isolation is the prerequisite for safe sharing
**Evidence**: MA2, MA3, MA7, MA8, 03-NAMESPACE-DESIGN.md

Every multi-agent memory system that works in production has some form of isolation.
LatentMem (MA2) uses learned latent projections. MIRIX (MA3) uses agent-specific
memory managers. The Collaborative Memory paper (MA7) proves that dynamic access
control with asymmetric policies is necessary for safe cross-agent sharing.

Cortex uses explicit namespaces — more interpretable, auditable, and controllable
than learned representations. Three levels:

### Level 1: Agent Namespace (Private)
- URI: `agent://{agent_id}/`
- Default home for all memories created by an agent
- Only the owning agent can read/write
- Decay, consolidation, validation run independently per namespace
- Created automatically when an agent registers

### Level 2: Team Namespace (Shared)
- URI: `team://{team_id}/`
- Explicitly shared memories visible to all agents in a team
- CRDT-based convergence for concurrent modifications
- All team members have Read + Write; creator has Admin

### Level 3: Project Namespace (Global)
- URI: `project://{project_id}/`
- Project-wide knowledge: patterns, constraints, tribal knowledge
- All agents can read; write requires explicit share action
- Highest trust level — knowledge here is considered authoritative

### Namespace Addressing

```
namespace://scope/path

Examples:
  agent://code-reviewer-1/memories/m-abc123
  team://backend-squad/patterns/auth-pattern
  project://my-app/tribal/never-use-orm-x
```

### NamespaceId Type

```rust
struct NamespaceId {
    scope: NamespaceScope,
    name: String,
}

enum NamespaceScope {
    Agent(AgentId),
    Team(String),
    Project(String),
}

impl NamespaceId {
    fn parse(uri: &str) -> Result<Self, CortexError> { /* ... */ }
    fn to_uri(&self) -> String { /* ... */ }
    fn is_agent(&self) -> bool { /* ... */ }
    fn is_shared(&self) -> bool { /* ... */ }
}
```

### Default Namespace for Backward Compatibility

All existing memories get `namespace: agent://default/`. Single-agent deployments
work exactly as before. Multi-agent features activate only when a second agent
registers. Zero performance overhead for single-agent: namespace checks are O(1)
string comparison against the default.

### Permission Model

```rust
enum NamespacePermission {
    Read,       // Can read memories in this namespace
    Write,      // Can write/update memories
    Share,      // Can share memories from this namespace to others
    Admin,      // Can manage permissions
}

struct NamespaceACL {
    namespace: NamespaceId,
    grants: Vec<(AgentId, Vec<NamespacePermission>)>,
}
```

Default permissions:
- Agent namespace: owner has all, others have none
- Team namespace: all members have Read + Write, creator has Admin
- Project namespace: all agents have Read, explicit grant for Write

**Evidence from MA7**: The Collaborative Memory paper proves that asymmetric,
time-varying access policies are necessary for safe sharing. Our ACL model
supports this — permissions can be granted and revoked per-agent, per-namespace,
at any time. The audit trail (extending v006 audit tables) records every
permission change.


---

## MA-R3: Memory Projection Engine — Filtered, Compressed Views Across Namespaces

**Priority**: P0 — Projections are how agents share knowledge without oversharing
**Evidence**: MA2, MA3, 03-NAMESPACE-DESIGN.md

A projection is a filtered, compressed, optionally live view of one namespace
exposed to another. Think database view — read-only, filtered, potentially
compressed to a different level.

**Why projections instead of full sharing**: LatentMem (MA2) demonstrates that
agents perform better with personalized views of shared knowledge, not copies
of everything. Full sharing creates noise — a security reviewer doesn't need
the developer's episodic memories about CSS debugging. Projections let each
agent see exactly what's relevant.

### Projection Definition

```rust
struct MemoryProjection {
    id: ProjectionId,
    source: NamespaceId,
    target: NamespaceId,
    filter: ProjectionFilter,
    compression_level: CompressionLevel,
    live: bool,                    // auto-update on source changes
    created_at: DateTime<Utc>,
    created_by: AgentId,
}

struct ProjectionFilter {
    memory_types: Option<Vec<MemoryType>>,
    min_confidence: Option<f64>,
    min_importance: Option<Importance>,
    linked_files: Option<Vec<String>>,
    tags: Option<Vec<String>>,
    max_age_days: Option<u64>,
    predicate: Option<String>,     // advanced: custom filter expression
}
```

### Share Semantics

| Action | Semantics | CRDT Behavior |
|--------|-----------|---------------|
| `share(memory, namespace)` | One-time copy to target | Delta sent, no further updates |
| `project(filter, namespace)` | Live filtered view | Subscription established |
| `promote(memory)` | Move from agent → team/project | Memory gets new namespace |
| `retract(memory, namespace)` | Remove from shared namespace | Tombstone in OR-Set |

### Subscription Model for Live Projections

When a projection is `live: true`, the source namespace pushes deltas to the
target whenever matching memories change:

1. Agent A creates memory M1 (tagged "auth")
2. M1 matches Agent B's subscription filter (tags contains "auth")
3. Delta for M1 sent to Agent B's namespace (compressed to projection level)
4. Agent B's retrieval engine can now find M1
5. Agent A updates M1 → delta sent to Agent B → CRDT merge

### Subscription Backpressure

If the target agent is busy and can't process deltas fast enough:

1. Deltas are queued (bounded queue, configurable size, default 1000)
2. If queue fills, switch to periodic full-state sync (less frequent, larger)
3. Target agent can request a "catch-up" sync at any time
4. Queue overflow is logged to observability — indicates capacity mismatch

```rust
struct SubscriptionState {
    projection_id: ProjectionId,
    delta_queue: BoundedQueue<MemoryDelta>,
    last_sync: DateTime<Utc>,
    mode: SyncMode,
    queue_high_watermark: usize,
}

enum SyncMode {
    Streaming,           // normal: deltas flow as they happen
    Batched { interval: Duration },  // backpressure: periodic batch sync
    CatchUp,             // recovering: full state transfer in progress
}
```

### Projection Compression

Projections can compress memories to a different level than the source. This
is critical for spawned sub-agents that need context but not full detail:

- L0 (full): complete memory with all fields
- L1 (summary): summary + metadata only (~20 tokens)
- L2 (compressed): summary + key examples (~100 tokens)
- L3 (ultra): one-line essence (~10 tokens)

A developer agent might project L0 to a team namespace but L2 to a spawned
sub-agent. This reuses cortex-compression's existing 4-level system.

---

## MA-R4: Cross-Agent Provenance — Tracing Knowledge Through Agent Chains

**Priority**: P1 — Critical for debugging, trust, and accountability
**Evidence**: MA7, MA8, 04-PROVENANCE-CHAINS.md

When Agent B makes a decision based on knowledge from Agent A, we need to trace
that lineage. The Collaborative Memory paper (MA7) proves that full auditability
of memory operations is necessary for trustworthy multi-agent systems. The
Emergent Collective Memory paper (MA8) shows that without provenance, collective
knowledge degrades unpredictably.

### ProvenanceRecord

Every memory carries its provenance — where it came from and how it got here:

```rust
struct ProvenanceRecord {
    memory_id: MemoryId,
    origin: ProvenanceOrigin,
    chain: Vec<ProvenanceHop>,
    chain_confidence: f64,
}

enum ProvenanceOrigin {
    Human { user_id: String },
    AgentCreated { agent_id: AgentId, session_id: String },
    Derived { source_memories: Vec<MemoryId> },
    Imported { source: String },
    Projected { source_agent: AgentId, source_memory: MemoryId },
}

struct ProvenanceHop {
    agent_id: AgentId,
    action: ProvenanceAction,
    timestamp: DateTime<Utc>,
    confidence_delta: f64,
}

enum ProvenanceAction {
    Created,
    SharedTo { target: NamespaceId },
    ProjectedTo { target: NamespaceId, compression: CompressionLevel },
    MergedWith { other_memory: MemoryId },
    ConsolidatedFrom { source_memories: Vec<MemoryId> },
    ValidatedBy { result: ValidationOutcome },
    UsedInDecision { decision_memory: MemoryId },
    CorrectedBy { correction: MemoryId },
    ReclassifiedFrom { old_type: MemoryType },
}
```

### Cross-Agent Causal Graph Extension

Our existing causal graph (cortex-causal) tracks relationships within a single
agent. We extend across agent boundaries with new relation types:

```rust
enum CrossAgentRelation {
    InformedBy { source_agent: AgentId },
    DecisionBasedOn { source_agent: AgentId },
    IndependentCorroboration { agents: Vec<AgentId> },
    CrossAgentContradiction { contradicting_agent: AgentId },
    Refinement { original_agent: AgentId },
}
```

These extend the existing 13 relationship types (cortex-core/memory/relationships.rs)
with cross-agent variants. The causal graph stores them as edges with an additional
`source_agent` field.

### Correction Propagation with Dampening

When a memory is corrected, the correction propagates through the provenance chain
with exponential dampening:

```
correction_strength(hop) = base_strength * 0.7^hop
```

- Direct correction: 100% strength
- 1 hop away: 70% strength
- 2 hops away: 49% strength
- 3+ hops: below threshold (5%), logged but not auto-applied

This prevents a single correction from cascading through the entire knowledge
graph while still propagating important corrections to nearby dependents.

### Audit Trail Extension

Every cross-agent interaction is logged to the existing audit system (v006):

```rust
struct CrossAgentAuditEntry {
    timestamp: DateTime<Utc>,
    source_agent: AgentId,
    target_agent: AgentId,
    action: CrossAgentAction,
    memories_involved: Vec<MemoryId>,
    provenance_chain_length: usize,
    trust_score_at_time: f64,
}
```

Stored in the existing `memory_audit_log` table with additional `source_agent`
and `target_agent` columns (added in v013 migration).

---

## MA-R5: Agent Trust Scoring — Domain-Specific Trust with Evidence Tracking

**Priority**: P1 — Trust modulates the confidence of shared knowledge
**Evidence**: MA7, MA16, 04-PROVENANCE-CHAINS.md

Each agent maintains a trust score for every other agent it interacts with.
The Formal Trust Verification paper (MA16) provides the theoretical foundation
for trust computation in multi-agent systems under uncertainty.

### Trust Model

```rust
struct AgentTrust {
    agent_id: AgentId,
    target_agent: AgentId,
    overall_trust: f64,                    // 0.0 - 1.0
    domain_trust: HashMap<String, f64>,    // per-domain trust
    evidence: TrustEvidence,
    last_updated: DateTime<Utc>,
}

struct TrustEvidence {
    validated_count: u64,      // memories later validated as correct
    contradicted_count: u64,   // memories later contradicted
    useful_count: u64,         // memories accessed and used in decisions
    total_received: u64,       // total memories received from this agent
}
```

### Trust Calculation

```
overall_trust = (validated + useful) / (total_received + 1)
              * (1 - contradicted / (total_received + 1))
```

The `+1` in denominators prevents division by zero and provides a slight
optimistic prior (new agents start with moderate trust, not zero).

### Domain-Specific Trust

An agent might be excellent at auth knowledge but unreliable about performance.
Domain trust is computed per-tag cluster:

```
domain_trust(domain) = domain_validated / (domain_total + 1)
                     * (1 - domain_contradicted / (domain_total + 1))
```

When Agent A shares a memory tagged "auth" with Agent B, the effective confidence
is modulated by Agent A's auth-domain trust:

```
effective_confidence = memory.confidence * domain_trust("auth")
```

If Agent A has auth trust 0.9 and shares a memory with confidence 0.85, Agent B
sees effective confidence of 0.765.

### Trust Decay

Trust scores decay slowly toward 0.5 (neutral) when no new evidence arrives:

```
trust_decay(days_since_evidence) = trust + (0.5 - trust) * (1 - 0.99^days)
```

After 100 days without interaction, trust drifts ~63% toward neutral. This
prevents stale trust scores from permanently biasing an agent's view of another.

### Trust Bootstrap

New agents start with `overall_trust = 0.5` (neutral). Trust is earned through:
1. Sharing memories that are later validated (+0.05 per validation)
2. Sharing memories that are used in decisions (+0.02 per use)
3. Sharing memories that are later contradicted (-0.10 per contradiction)

The asymmetric penalty (contradictions hurt 2x more than validations help)
creates a conservative trust model — it's harder to build trust than to lose it.
This is intentional for a code-aware system where bad knowledge can cause bugs.


---

## MA-R6: Agent Registry & Lifecycle — Identity, Registration, Discovery

**Priority**: P0 — Agents must be identifiable before they can share
**Evidence**: MA3, MA6, MA12, 05-CORTEX-MAPPING.md

Every agent in the system needs a stable identity. MIRIX (MA3) uses agent-specific
memory managers. BMAS (MA12) uses PFC-inspired coordination with explicit agent
roles. Cortex needs a lightweight registry that tracks who's in the system.

### AgentId Type

```rust
struct AgentId(String);  // UUID v4, stable across sessions

impl AgentId {
    fn new() -> Self { Self(uuid::Uuid::new_v4().to_string()) }
    fn default_agent() -> Self { Self("default".to_string()) }
}
```

### Agent Registry

```rust
struct AgentRegistration {
    agent_id: AgentId,
    name: String,                          // human-readable: "code-reviewer-1"
    namespace: NamespaceId,                // primary namespace
    capabilities: Vec<String>,             // ["code-review", "security-audit"]
    registered_at: DateTime<Utc>,
    last_active: DateTime<Utc>,
    status: AgentStatus,
}

enum AgentStatus {
    Active,
    Idle { since: DateTime<Utc> },
    Deregistered { at: DateTime<Utc> },
}
```

### Agent Lifecycle

1. **Register**: Agent calls `register(name, capabilities)` → gets AgentId + namespace
2. **Active**: Agent creates/reads/shares memories within its namespace
3. **Idle**: After configurable inactivity (default 24h), status → Idle
4. **Deregister**: Agent explicitly deregisters or admin removes
   - Agent's private namespace is archived (not deleted)
   - Shared memories in team/project namespaces remain
   - Provenance records preserved permanently

### Spawned Agent Inheritance

When an orchestrator spawns a sub-agent:

1. Sub-agent registers with parent reference: `parent_agent: Option<AgentId>`
2. Parent can create a projection from its namespace to the sub-agent
3. Sub-agent inherits parent's trust scores (discounted by 0.8)
4. When sub-agent deregisters, its memories can be promoted to parent's namespace

```rust
struct SpawnConfig {
    parent_agent: AgentId,
    projection: Option<MemoryProjection>,  // context to inherit
    trust_discount: f64,                   // default 0.8
    auto_promote_on_deregister: bool,      // default true
    ttl: Option<Duration>,                 // auto-deregister after TTL
}
```

---

## MA-R7: Delta Sync Protocol — Efficient Cross-Agent State Transfer

**Priority**: P0 — The wire protocol for multi-agent convergence
**Evidence**: MA9, MA10, MA14, 02-CRDT-FOUNDATIONS.md

Delta sync is how agents exchange state changes. Each agent maintains a vector
clock and sends only the deltas since the recipient's last known state.

### Delta Encoding

```rust
struct MemoryDelta {
    memory_id: MemoryId,
    source_agent: AgentId,
    clock: VectorClock,
    field_deltas: Vec<FieldDelta>,
    timestamp: DateTime<Utc>,
}

enum FieldDelta {
    ContentUpdated { value: String, lww_timestamp: DateTime<Utc> },
    SummaryUpdated { value: String, lww_timestamp: DateTime<Utc> },
    ConfidenceBoosted { value: f64, max_timestamp: DateTime<Utc> },
    TagAdded { tag: String, unique_tag: UniqueTag },
    TagRemoved { tag: String, removed_tags: HashSet<UniqueTag> },
    LinkAdded { link_type: String, target: String, unique_tag: UniqueTag },
    LinkRemoved { link_type: String, target: String, removed_tags: HashSet<UniqueTag> },
    AccessCountIncremented { agent: AgentId, new_count: u64 },
    ImportanceChanged { value: Importance, lww_timestamp: DateTime<Utc> },
    ArchivedChanged { value: bool, lww_timestamp: DateTime<Utc> },
    ProvenanceHopAdded { hop: ProvenanceHop },
    MemoryCreated { full_state: BaseMemory },
}
```

### Sync Protocol

```
Agent A                              Agent B
   |                                    |
   |-- SyncRequest { my_clock } ------->|
   |                                    |
   |<-- SyncResponse { deltas,          |
   |       your_missing_deltas,         |
   |       their_clock }                |
   |                                    |
   |-- apply deltas, update clock       |
   |                                    |
   |-- SyncAck { new_clock } ---------->|
   |                                    |
```

### Causal Delivery

Deltas are applied only when all causally preceding deltas have been applied.
The vector clock ensures this:

```rust
fn can_apply(delta: &MemoryDelta, local_clock: &VectorClock) -> bool {
    for (agent, &count) in &delta.clock.clocks {
        if agent == &delta.source_agent {
            // Source agent's clock should be exactly one ahead
            let local = local_clock.clocks.get(agent).copied().unwrap_or(0);
            if count != local + 1 { return false; }
        } else {
            // All other agents' clocks should be <= local
            let local = local_clock.clocks.get(agent).copied().unwrap_or(0);
            if count > local { return false; }
        }
    }
    true
}
```

If a delta can't be applied yet (missing causal predecessor), it's buffered
in a pending queue and retried when new deltas arrive.

### Integration with cortex-cloud

The delta sync protocol extends cortex-cloud's existing sync mechanism:

- **Local multi-agent**: Deltas flow through SQLite (delta_queue table)
- **Cloud multi-agent**: Deltas flow through cortex-cloud's HTTP transport
- **Hybrid**: Local agents sync via SQLite; remote agents sync via cloud

cortex-cloud's existing conflict resolution strategies (LWW, local-wins,
remote-wins, manual) are replaced by CRDT merge for multi-agent scenarios.
CRDTs make conflict resolution deterministic — no strategy selection needed.

---

## MA-R8: Cross-Namespace Consolidation — Consensus Detection Across Agents

**Priority**: P2 — Builds on MA-R2 (namespaces) and MA-R1 (CRDTs)
**Evidence**: MA1, MA4, MA6, 05-CORTEX-MAPPING.md

When multiple agents independently learn the same thing, that's a strong signal.
BMAM (MA1) validates that specialized memory subsystems benefit from cross-system
consolidation. Mem0 (MA4) demonstrates that graph-based consolidation improves
accuracy by 26%.

### Consensus Detection

When the same logical knowledge exists in multiple agent namespaces:

1. **Dedup detection**: Embedding similarity > 0.9 across namespaces → candidate
2. **Merge strategy**: If both are in the same team/project namespace, CRDT merge
3. **Confidence boost**: Multiple agents independently learning the same thing →
   consensus boost (+0.2, matching existing contradiction/consensus system)
4. **Provenance preservation**: Merged memory retains provenance from all agents

```rust
struct ConsensusCandidate {
    memories: Vec<(AgentId, MemoryId)>,
    similarity: f64,
    agent_count: usize,
    confidence_boost: f64,
}

fn detect_consensus(
    memories_by_namespace: &HashMap<NamespaceId, Vec<BaseMemory>>,
    embedding_engine: &dyn IEmbeddingProvider,
    threshold: f64,  // default 0.9
) -> Vec<ConsensusCandidate> {
    // Cross-namespace embedding similarity search
    // Group by similarity clusters
    // Return candidates with 2+ agents
}
```

### Cross-Namespace Consolidation Pipeline

Extends cortex-consolidation's existing HDBSCAN pipeline:

1. **Phase 0 (new)**: Gather candidate memories from all team/project namespaces
2. **Phase 1**: Existing HDBSCAN clustering (now cross-namespace)
3. **Phase 2**: Existing recall gate (quality filter)
4. **Phase 3**: Existing merge + abstraction
5. **Phase 4 (extended)**: Consensus boost for multi-agent clusters
6. **Phase 5**: Existing pruning (archive source memories)

The consolidated memory is placed in the team/project namespace with provenance
recording all contributing agents.

---

## MA-R9: Cross-Agent Validation — Trust-Weighted Contradiction Detection

**Priority**: P2 — Extends cortex-validation across agent boundaries
**Evidence**: MA7, MA16, 04-PROVENANCE-CHAINS.md

When Agent A says "we use bcrypt for auth" and Agent B says "we use argon2 for
auth", that's a cross-agent contradiction. The resolution should consider trust:

### Cross-Agent Contradiction Detection

Extend cortex-validation's existing contradiction detection to work across
namespaces:

1. For each memory in a shared namespace, check for contradictions against
   memories in other agent namespaces that are projected to the same target
2. Use embedding similarity + semantic analysis (existing validation dimensions)
3. Flag contradictions with both agents' trust scores

### Trust-Weighted Resolution

```rust
struct CrossAgentContradiction {
    memory_a: MemoryId,
    agent_a: AgentId,
    trust_a: f64,
    memory_b: MemoryId,
    agent_b: AgentId,
    trust_b: f64,
    contradiction_type: ContradictionType,
    resolution: ContradictionResolution,
}

enum ContradictionResolution {
    /// Higher-trust agent's memory wins automatically
    TrustWins { winner: AgentId },
    /// Trust difference too small — flag for human review
    NeedsHumanReview,
    /// Both memories are valid in different contexts
    ContextDependent { context_a: String, context_b: String },
    /// Newer memory supersedes older (temporal resolution)
    TemporalSupersession { newer: MemoryId },
}
```

Resolution strategy:
- Trust difference > 0.3: higher-trust agent wins automatically
- Trust difference ≤ 0.3: flag for human review
- Both memories have context tags suggesting different scopes: context-dependent
- One memory is significantly newer and from a validated source: temporal supersession

---

## MA-R10: Storage Schema — Migration v013_multiagent_tables

**Priority**: P0 — Database foundation for all multi-agent features
**Evidence**: 05-CORTEX-MAPPING.md, all recommendations above

Migration v013 creates the storage foundation. Follows existing conventions:
TEXT for ISO 8601 dates, TEXT for JSON blobs, INTEGER PRIMARY KEY AUTOINCREMENT.

### Table 1: agent_registry

```sql
CREATE TABLE agent_registry (
    agent_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    namespace_id TEXT NOT NULL,
    capabilities TEXT,              -- JSON array
    parent_agent TEXT,              -- nullable, for spawned agents
    registered_at TEXT NOT NULL,
    last_active TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    FOREIGN KEY (parent_agent) REFERENCES agent_registry(agent_id)
);

CREATE INDEX idx_agent_status ON agent_registry(status);
CREATE INDEX idx_agent_parent ON agent_registry(parent_agent);
```

### Table 2: memory_namespaces

```sql
CREATE TABLE memory_namespaces (
    namespace_id TEXT PRIMARY KEY,
    scope TEXT NOT NULL,            -- 'agent', 'team', 'project'
    owner_agent TEXT,               -- nullable for team/project
    created_at TEXT NOT NULL,
    metadata TEXT,                  -- JSON
    FOREIGN KEY (owner_agent) REFERENCES agent_registry(agent_id)
);
```

### Table 3: namespace_permissions

```sql
CREATE TABLE namespace_permissions (
    namespace_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    permissions TEXT NOT NULL,       -- JSON array: ["read","write","share","admin"]
    granted_at TEXT NOT NULL,
    granted_by TEXT NOT NULL,
    PRIMARY KEY (namespace_id, agent_id),
    FOREIGN KEY (namespace_id) REFERENCES memory_namespaces(namespace_id),
    FOREIGN KEY (agent_id) REFERENCES agent_registry(agent_id)
);
```

### Table 4: memory_projections

```sql
CREATE TABLE memory_projections (
    projection_id TEXT PRIMARY KEY,
    source_namespace TEXT NOT NULL,
    target_namespace TEXT NOT NULL,
    filter_json TEXT NOT NULL,
    compression_level INTEGER NOT NULL DEFAULT 0,
    live INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    FOREIGN KEY (source_namespace) REFERENCES memory_namespaces(namespace_id),
    FOREIGN KEY (target_namespace) REFERENCES memory_namespaces(namespace_id),
    FOREIGN KEY (created_by) REFERENCES agent_registry(agent_id)
);

CREATE INDEX idx_proj_source ON memory_projections(source_namespace);
CREATE INDEX idx_proj_target ON memory_projections(target_namespace);
```

### Table 5: provenance_log

```sql
CREATE TABLE provenance_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    memory_id TEXT NOT NULL,
    hop_index INTEGER NOT NULL,
    agent_id TEXT NOT NULL,
    action TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    confidence_delta REAL DEFAULT 0.0,
    details TEXT,                    -- JSON
    FOREIGN KEY (memory_id) REFERENCES memories(id),
    FOREIGN KEY (agent_id) REFERENCES agent_registry(agent_id)
);

CREATE INDEX idx_prov_memory ON provenance_log(memory_id, hop_index);
CREATE INDEX idx_prov_agent ON provenance_log(agent_id);
```

### Table 6: agent_trust

```sql
CREATE TABLE agent_trust (
    agent_id TEXT NOT NULL,
    target_agent TEXT NOT NULL,
    overall_trust REAL NOT NULL DEFAULT 0.5,
    domain_trust TEXT,               -- JSON: {"auth": 0.9, "perf": 0.3}
    evidence TEXT NOT NULL,          -- JSON: TrustEvidence
    last_updated TEXT NOT NULL,
    PRIMARY KEY (agent_id, target_agent),
    FOREIGN KEY (agent_id) REFERENCES agent_registry(agent_id),
    FOREIGN KEY (target_agent) REFERENCES agent_registry(agent_id)
);
```

### Table 7: delta_queue

```sql
CREATE TABLE delta_queue (
    delta_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_agent TEXT NOT NULL,
    target_agent TEXT NOT NULL,
    memory_id TEXT NOT NULL,
    delta_json TEXT NOT NULL,
    vector_clock TEXT NOT NULL,      -- JSON
    created_at TEXT NOT NULL,
    applied INTEGER NOT NULL DEFAULT 0,
    applied_at TEXT,
    FOREIGN KEY (source_agent) REFERENCES agent_registry(agent_id),
    FOREIGN KEY (target_agent) REFERENCES agent_registry(agent_id)
);

CREATE INDEX idx_delta_target ON delta_queue(target_agent, applied);
CREATE INDEX idx_delta_created ON delta_queue(created_at);
```

### Modification to existing memories table

```sql
ALTER TABLE memories ADD COLUMN namespace_id TEXT DEFAULT 'agent://default/';
ALTER TABLE memories ADD COLUMN source_agent TEXT DEFAULT 'default';

CREATE INDEX idx_memories_namespace ON memories(namespace_id);
CREATE INDEX idx_memories_agent ON memories(source_agent);
```

### Total Storage Overhead

| Component | 10K memories, 5 agents | 10K memories, 20 agents |
|-----------|----------------------|------------------------|
| agent_registry | ~2 KB | ~8 KB |
| memory_namespaces | ~1 KB | ~4 KB |
| namespace_permissions | ~5 KB | ~80 KB |
| memory_projections | ~10 KB | ~100 KB |
| provenance_log | ~5 MB | ~20 MB |
| agent_trust | ~1 KB | ~16 KB |
| delta_queue (active) | ~200 KB | ~2 MB |
| namespace/agent columns on memories | ~200 KB | ~200 KB |
| **Total** | **~5.4 MB** | **~22.4 MB** |

Negligible compared to the base memory storage (~500MB for 10K memories with
embeddings and version history).


---

## MA-R11: Causal Graph CRDT — Novel Contribution for DAG Convergence

**Priority**: P1 — Required for cross-agent causal reasoning
**Evidence**: MA9, 02-CRDT-FOUNDATIONS.md, 04-PROVENANCE-CHAINS.md

This is the most novel piece of the multi-agent system. No existing CRDT library
provides a DAG-specific CRDT. We need one because Cortex's causal graph (petgraph
StableGraph) must converge across agents without cycles.

### Requirements

1. Adding an edge is commutative (order doesn't matter)
2. Removing an edge uses OR-Set semantics (add wins over concurrent remove)
3. Cycle detection is local (each replica validates independently)
4. Strength updates use max-wins semantics

### Design

```rust
struct CausalGraphCRDT {
    edges: ORSet<CausalEdge>,
    strengths: HashMap<(MemoryId, MemoryId), MaxRegister<f64>>,
}

impl CausalGraphCRDT {
    fn add_edge(&mut self, edge: CausalEdge, agent: &AgentId, seq: u64) -> Result<()> {
        // Local cycle detection before adding
        if self.would_create_cycle(&edge) {
            return Err(CortexError::CausalCycle { path: format_cycle_path(&edge) });
        }
        self.edges.add(edge.clone(), agent, seq);
        self.strengths.insert(
            (edge.source.clone(), edge.target.clone()),
            MaxRegister::new(edge.strength, Utc::now()),
        );
        Ok(())
    }

    fn merge(&mut self, other: &CausalGraphCRDT) -> Result<()> {
        self.edges.merge(&other.edges);
        for ((src, tgt), strength) in &other.strengths {
            self.strengths
                .entry((src.clone(), tgt.clone()))
                .or_insert_with(|| MaxRegister::new(0.0, DateTime::UNIX_EPOCH))
                .merge(strength);
        }
        // Post-merge cycle detection and resolution
        self.resolve_cycles();
        Ok(())
    }

    fn resolve_cycles(&mut self) {
        // If merge introduced a cycle (possible when two agents add edges
        // that individually don't create cycles but together do):
        // Remove the edge with the lowest strength (weakest link)
        while let Some(cycle) = self.detect_cycle() {
            let weakest = cycle.iter()
                .min_by(|a, b| {
                    let sa = self.strengths.get(&(a.source.clone(), a.target.clone()));
                    let sb = self.strengths.get(&(b.source.clone(), b.target.clone()));
                    sa.map(|s| s.value).unwrap_or(0.0)
                        .partial_cmp(&sb.map(|s| s.value).unwrap_or(0.0))
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
            if let Some(edge) = weakest {
                self.edges.remove(edge);
            }
        }
    }
}
```

### Why This Is Novel

Existing CRDT literature (MA9) covers sets, registers, counters, and maps.
Graph CRDTs exist for general graphs (add/remove nodes and edges) but not for
DAGs with cycle prevention. Our contribution is a DAG-CRDT that:

1. Maintains the DAG invariant across concurrent modifications
2. Resolves merge-introduced cycles deterministically (weakest-link removal)
3. Preserves OR-Set semantics for edge add/remove
4. Tracks edge strengths with max-wins convergence

This is publishable research — no existing system has a CRDT for causally-ordered
knowledge graphs.

---

## MA-R12: Integration with Existing Crates — 9 Crate Modifications

**Priority**: P0-P2 (varies by crate)
**Evidence**: 05-CORTEX-MAPPING.md, all recommendations above

### cortex-core (P0)
- Add `AgentId` type (UUID-based, with `default_agent()` for backward compat)
- Add `NamespaceId` type (URI-based with parse/format)
- Add `ProvenanceRecord`, `ProvenanceHop`, `ProvenanceAction` to models
- Add `CrossAgentRelation` to memory/relationships.rs
- Add `namespace: NamespaceId` field to BaseMemory (default: `agent://default/`)
- Add `source_agent: AgentId` field to BaseMemory (default: `AgentId::default_agent()`)
- Add `IMultiAgentEngine` trait to traits module
- Add `MultiAgentConfig` to config module
- Add `MultiAgentError` to errors module

### cortex-storage (P0)
- New migration: `v013_multiagent_tables.rs` (MA-R10)
- New query module: `queries/multiagent_ops.rs`
- Extend `memory_crud.rs` with namespace-aware queries
- Extend `memory_query.rs` with namespace filter parameter

### cortex-cloud (P1)
- Extend sync protocol to include agent identity in sync requests
- Delta sync carries agent provenance metadata
- Conflict resolution uses CRDT merge for multi-agent scenarios
- Existing LWW/local-wins/remote-wins strategies remain for single-agent

### cortex-session (P1)
- `SessionContext` gains `agent_id: AgentId` field
- Session dedup is now per-agent within a namespace
- Session cleanup respects namespace boundaries

### cortex-causal (P1)
- Extend `CausalEdge` with optional `source_agent: Option<AgentId>` field
- New traversal: `trace_cross_agent()` — follows provenance across boundaries
- New narrative template: cross-agent causal chains
- New module: `graph/cross_agent.rs`

### cortex-consolidation (P2)
- Cross-namespace consolidation (MA-R8)
- Consensus detection: 3+ agents with similar memories → confidence boost
- Consolidated memories placed in team/project namespace

### cortex-validation (P2)
- Cross-agent contradiction detection (MA-R9)
- Trust-weighted contradiction resolution
- New validation dimension: cross-agent consistency

### cortex-retrieval (P2)
- Namespace-aware search: search within namespace, optionally across
- Trust-weighted ranking: memories from higher-trust agents rank higher
- Projection-aware retrieval: respect compression levels in projections

### cortex-napi (P2)
- New binding module: `bindings/multiagent.rs`
- Functions: registerAgent, getAgentInfo, listAgents, createNamespace,
  shareMemory, projectMemories, retractMemory, getProvenance,
  traceCrossAgent, getTrust, updateTrust

---

## MA-R13: Backward Compatibility — Zero Breaking Changes

**Priority**: P0 — Non-negotiable
**Evidence**: All recommendations, CORTEX-IMPLEMENTATION-SPEC.md

The multi-agent system must be fully backward compatible:

1. **Single-agent works unchanged**: Default namespace `agent://default/` is
   created automatically. All existing APIs work without namespace parameter.
2. **No performance overhead for single-agent**: Namespace checks are O(1)
   string comparison against the default. CRDT overhead is zero when there's
   only one agent (no merges needed).
3. **Opt-in activation**: Multi-agent features activate only when a second
   agent registers. Until then, the system behaves identically to v1.
4. **Migration is additive**: v013 adds new tables and columns. No existing
   tables are modified destructively. The `ALTER TABLE` adds nullable columns
   with defaults.
5. **API surface is additive**: New MCP tools and CLI commands are added.
   Existing tools continue to work with implicit default namespace.

---

## MA-R14: What Makes This Novel — Gap Analysis

**Priority**: Context — justifies the investment
**Evidence**: MA1-MA16, 01-PRIOR-ART.md

| Capability | Blackboard | BMAM | LatentMem | MIRIX | Mem0 | MemOS | EverMemOS | Bedrock AgentCore | **Cortex** |
|---|---|---|---|---|---|---|---|---|---|
| Typed memory (>6 types) | ✗ | ✗ | ✗ | ✓ (6) | ✗ | ✗ | ✗ | ✗ | **✓ (23)** |
| Multi-agent sharing | ✓ (central) | ✗ | ✓ (latent) | ✓ (basic) | ✗ | ✗ | ✗ | ✓ (managed) | **✓ (CRDT)** |
| Conflict-free convergence | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | **✓** |
| Causal provenance | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | **✓ (cross-agent)** |
| Memory projection/filtering | ✗ | ✗ | ✓ (learned) | ✗ | ✗ | ✗ | ✗ | ✗ | **✓ (explicit)** |
| Namespace isolation | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ (session) | **✓ (3-level)** |
| Trust scoring | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | **✓ (domain-specific)** |
| DAG CRDT | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | **✓ (novel)** |
| Code-aware memory | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | **✓** |
| Correction propagation | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | **✓ (dampened)** |
| Temporal integration | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | **✓ (bitemporal)** |

The combination of CRDT-based convergence + 23 typed memories + causal provenance
+ namespace isolation + domain-specific trust + DAG CRDT + code awareness is
completely novel. No existing system — academic or commercial — has this combination.

**Three publishable contributions**:
1. DAG-CRDT with cycle prevention for knowledge graphs
2. Domain-specific trust scoring with dampened correction propagation
3. CRDT-based convergence for typed, confidence-scored memory systems

---

## Implementation Phases — Four Phases with Quality Gates

### Phase Overview

| Phase | Name | Recommendations | New Files | Modified Files | Duration |
|-------|------|----------------|-----------|----------------|----------|
| A | CRDT Foundation + Core Types | MA-R1, MA-R6, MA-R12 (core) | ~35 | ~8 | ~1.5 weeks |
| B | Storage + Namespaces + Projections | MA-R2, MA-R3, MA-R10, MA-R12 (storage) | ~20 | ~6 | ~1.5 weeks |
| C | Delta Sync + Trust + Provenance | MA-R4, MA-R5, MA-R7, MA-R11 | ~25 | ~5 | ~1.5 weeks |
| D | Cross-Crate Integration | MA-R8, MA-R9, MA-R12 (remaining), MA-R13 | ~15 | ~12 | ~1 week |

### Phase Gate Protocol

Before advancing from Phase N to Phase N+1:

1. **Coverage check**: `cargo tarpaulin -p cortex-crdt --ignore-tests` and
   `cargo tarpaulin -p cortex-multiagent --ignore-tests` report >= 80% line coverage
2. **All tests pass**: `cargo test -p cortex-crdt -p cortex-multiagent` exits 0
3. **Property tests pass**: proptest for CRDT convergence properties
4. **No regressions**: `cargo test --workspace` exits 0
5. **Benchmark baselines**: `cargo bench` establishes performance baselines
6. **Diagnostics clean**: No compiler warnings in new or modified crates

### Silent Failure Detection Strategy (Multi-Agent-Specific)

| Module | Silent Failure Risk | Detection Test |
|--------|-------------------|----------------|
| CRDT merge | Non-convergent merge → agents diverge | Property: merge(A,B) == merge(B,A) for all inputs |
| OR-Set | Tombstone leak → unbounded memory growth | Property: OR-Set size bounded by unique adds |
| Vector clock | Missed causal dependency → out-of-order apply | Property: causal delivery never applies future deltas |
| Namespace ACL | Permission bypass → unauthorized read/write | Test: agent without Read permission → query returns empty |
| Projection filter | Filter miss → private memories leak | Test: memory not matching filter → not in projection |
| Trust calculation | Division by zero → NaN trust score | Property: trust always in [0.0, 1.0] |
| Delta sync | Lost delta → permanent divergence | Property: after sync, both agents have same state |
| Cycle detection | Merge introduces cycle → infinite traversal | Property: graph is always acyclic after merge |
| Correction propagation | Undampened cascade → mass invalidation | Test: correction at depth 4 → strength < threshold |
| Consensus detection | False positive → incorrect confidence boost | Test: dissimilar memories → no consensus |
