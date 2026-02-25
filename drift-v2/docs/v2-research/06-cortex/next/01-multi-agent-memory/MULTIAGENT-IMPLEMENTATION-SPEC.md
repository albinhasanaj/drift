# Cortex Multi-Agent Memory — Unified Implementation Specification

> **Version:** 1.0.0
> **Status:** APPROVED FOR IMPLEMENTATION
> **Workspace:** `crates/cortex/cortex-crdt/` + `crates/cortex/cortex-multiagent/` (Rust) + modifications to 9 existing crates + `packages/cortex/` (TypeScript MCP layer)
> **Last Updated:** 2026-02-07
> **Research Corpus:** 5 research documents (01-PRIOR-ART through 05-CORTEX-MAPPING), 16 external sources (MA1-MA16), 14 recommendations (MA-R1 through MA-R14), RECOMMENDATIONS.md, FILE-MAP.md
> **Supersedes:** Individual multi-agent research documents as implementation authority
> **Parent Spec:** CORTEX-IMPLEMENTATION-SPEC.md v2.0.0 (this spec extends, never contradicts)
> **Sibling Spec:** TEMPORAL-IMPLEMENTATION-SPEC.md v1.0.0 (temporal reasoning — this spec depends on temporal's event store for provenance event emission)
> **New Files:** 88 | **Modified Files:** 28 | **Total Touched:** 116
> **New Crates:** cortex-crdt (21st), cortex-multiagent (22nd Rust crate in workspace)
> **New Migration:** v015_multiagent_tables
> **New MCP Tools:** 5 | **New CLI Commands:** 3

## What This Document Is

This is the single source of truth for adding multi-agent memory sharing, CRDT-based convergence, namespace isolation, cross-agent provenance, trust scoring, and delta sync to Drift's Cortex memory system. An agent reading this document should be able to implement every new file, every modification to existing crates, every migration, every test — and understand why every decision was made.

This document synthesizes:
- The RECOMMENDATIONS.md (MA-R1 through MA-R14) — what to build and why
- The FILE-MAP.md (88 new + 28 modified files) — where every line of code goes
- The existing CORTEX-IMPLEMENTATION-SPEC.md — patterns, conventions, and constraints to follow
- The TEMPORAL-IMPLEMENTATION-SPEC.md — sibling spec whose event store we extend with provenance events
- The live codebase (20 crates including cortex-temporal, 13 migrations, 13 query modules, 13 traits, 16+ models) — verified integration points

This document does NOT repeat the parent spec. It references it. If you need BaseMemory fields, memory types, the error hierarchy, or existing crate specs — read CORTEX-IMPLEMENTATION-SPEC.md.

## Why Multi-Agent Memory Exists

Cortex is currently a single-agent brain. One agent, one memory store, one namespace. But the future of AI is multi-agent: agents spawning agents, teams of specialized agents collaborating on the same codebase, orchestrators coordinating swarms.

Without shared memory:
- Agent A learns a pattern, Agent B repeats the same mistake
- Two agents working on the same module create contradictory memories
- No provenance chain when Agent B acts on knowledge from Agent A
- Spawned sub-agents start from zero context every time

Multi-agent memory adds four new capabilities to Cortex:

1. **"Who knows what?"** — Namespace isolation with selective sharing via projections
2. **"Where did this knowledge come from?"** — Cross-agent provenance chains with dampened correction propagation
3. **"How much should I trust this?"** — Domain-specific trust scoring with evidence tracking
4. **"How do agents stay in sync?"** — Delta-state CRDT convergence without coordination overhead

**The core insight**: The multi-agent memory problem is fundamentally a distributed systems problem disguised as an AI problem. Every agent is a replica. Every memory mutation is an operation. Convergence without coordination is the requirement. CRDTs provide the mathematical guarantee. What's novel is applying CRDT theory to a typed, confidence-scored, causally-linked memory system with 23 memory types, hierarchical compression, and cross-agent provenance — something no existing system has attempted.

**Evidence for urgency**: Amazon Bedrock AgentCore (MA19/TS19) launched managed multi-agent memory in 2025. MIRIX (MA3) demonstrated 6-type multi-agent coordination. The market is moving fast — but none of these systems offer CRDT convergence, causal provenance, or domain-specific trust. Cortex's window of differentiation is open but closing.

## What Makes This Novel

No existing system — academic or commercial — offers this combination:

| Capability | Blackboard | BMAM | LatentMem | MIRIX | Mem0 | MemOS | EverMemOS | Bedrock AgentCore | **Cortex (this spec)** |
|---|---|---|---|---|---|---|---|---|---|
| Typed memory (>6 types) | ✗ | ✗ | ✗ | ✓ (6) | ✗ | ✗ | ✗ | ✗ | **✓ (23)** |
| Multi-agent sharing | ✓ (central) | ✗ | ✓ (latent) | ✓ (basic) | ✗ | ✗ | ✗ | ✓ (managed) | **✓ (CRDT)** |
| Conflict-free convergence | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | **✓ (novel)** |
| Causal provenance | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | **✓ (cross-agent)** |
| Memory projection/filtering | ✗ | ✗ | ✓ (learned) | ✗ | ✗ | ✗ | ✗ | ✗ | **✓ (explicit)** |
| Namespace isolation | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ (session) | **✓ (3-level)** |
| Trust scoring | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | **✓ (domain-specific)** |
| DAG CRDT | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | **✓ (novel)** |
| Code-aware memory | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | **✓** |
| Correction propagation | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | **✓ (dampened)** |
| Temporal integration | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | **✓ (bitemporal)** |

**Three publishable contributions**:
1. DAG-CRDT with cycle prevention for knowledge graphs — no existing CRDT library provides this
2. Domain-specific trust scoring with dampened correction propagation across agent boundaries
3. Delta-state CRDT convergence for typed, confidence-scored memory systems with 23 memory types

---

## Research Sources (16 Verified)

| ID | Source | Year | Key Contribution |
|----|--------|------|-----------------|
| MA1 | BMAM — Brain-inspired Multi-Agent Memory (Li et al.) | 2026 | Functionally specialized memory subsystems; 78.45% LoCoMo; validates type decomposition |
| MA2 | LatentMem — Customizable Agent-Specific Memory | 2026 | Learnable latent projections for per-agent memory views; validates projection concept |
| MA3 | MIRIX — Six-Type Multi-Agent Memory (Wang, Chen) | 2025 | 6 memory types with multi-agent coordination; closest competitor architecture |
| MA4 | Mem0 — Production Long-Term Memory with Graph (Chhikara et al.) | 2025 | 26% improvement over OpenAI memory; graph consolidation; single-agent only |
| MA5 | MemOS — Memory Operating System | 2025 | Memory-as-OS framing; unified write/search/merge/revise API; single-agent |
| MA6 | AMA — Adaptive Memory via Multi-Agent Collaboration | 2026 | Multi-agent memory adaptation; task-aligned memory construction |
| MA7 | Collaborative Memory — Dynamic Access Control | 2026 | Provable asymmetric time-varying policies; full auditability |
| MA8 | Emergent Collective Memory in Decentralized MAS | 2025 | Collective memory emergence without centralized control |
| MA9 | CRDT Theory — Approaches to CRDTs (Shapiro et al.) | 2024 | Definitive CRDT taxonomy: state-based, op-based, delta-state |
| MA10 | Delta-State CRDTs (Almeida et al.) | 2018 | Delta-state: small messages over unreliable channels |
| MA11 | EverMemOS — SOTA Memory OS | 2026 | 93.05% LoCoMo SOTA; 3-phase engram lifecycle; single-agent |
| MA12 | BMAS — PFC-Guided Multi-Agent Coordination | 2026 | PFC-inspired task coordination + hippocampus-neocortex dual memory |
| MA13 | Rust `crdts` crate | 2024 | Production Rust CRDTs: GCounter, PNCounter, MVReg, ORSwot, LWWReg, VClock |
| MA14 | Datacake — Distributed Systems Framework | 2023 | ORSWOT CRDT + eventually consistent storage in Rust |
| MA15 | Cost/Accuracy of LTM in Distributed MAS | 2026 | Mem0 vs Graphiti: mem0 faster, lower resources; accuracy not significant |
| MA16 | Formal Trust Verification in MAS | 2026 | Formal trust verification under generalized possibility theory |

---

## Architecture: Two New Crates (21st and 22nd)

Multi-agent memory introduces two new crates: `cortex-crdt` (pure CRDT data structures) and `cortex-multiagent` (multi-agent orchestration). This separation follows the cortex-core/cortex-temporal pattern: pure types in one crate, behavior in another.

**Why two crates instead of one**: CRDT primitives are pure data structures with no Cortex-specific logic. They belong in `cortex-crdt` so they can be tested in isolation with property-based tests for commutativity/associativity/idempotency, potentially reused outside Cortex, and don't pollute cortex-multiagent with merge algebra. The Rust `crdts` crate (MA13) provides reference implementations but is too general — we need Cortex-specific optimizations (e.g., confidence as Max-Register with local-only decay, DAG-CRDT with cycle prevention).

### Dependency Position in Workspace

```
                    cortex-core (foundation — types, traits, errors, config)
                         │
              ┌──────────┼──────────────────────┐
              │          │                      │
        cortex-storage   │               cortex-embeddings
              │          │                      │
              ├──────────┤                      │
              │          │                      │
        cortex-temporal  │               cortex-compression
              │          │                      │
        cortex-crdt ─────┤               cortex-retrieval ←── cortex-multiagent (trust-weighted scoring)
              │          │                      │
        cortex-multiagent┤               cortex-consolidation ←── cortex-multiagent (cross-namespace)
              │          │                      │
              │    cortex-causal ←── cortex-multiagent (cross-agent relations)
              │          │
              │    cortex-validation ←── cortex-multiagent (cross-agent contradictions)
              │          │
              │    cortex-cloud ←── cortex-multiagent (CRDT merge for sync)
              │          │
              │    cortex-session ←── cortex-multiagent (agent_id in context)
              │          │
              │    cortex-napi ←── cortex-multiagent (bindings)
              │
              └── packages/cortex (TypeScript MCP tools + CLI)
```

### Upstream Dependencies

**cortex-crdt reads from:**
- **cortex-core**: All types (BaseMemory, MemoryType, Importance, etc.)

**cortex-multiagent reads from:**
- **cortex-core**: All types, traits, errors, config
- **cortex-crdt**: CRDT primitives, MemoryCRDT, MergeEngine, CausalGraphCRDT
- **cortex-storage**: ReadPool (queries), WriteConnection (writes)

### Downstream Consumers (other crates read from cortex-multiagent)

- **cortex-causal**: Cross-agent relation types, cross-agent traversal
- **cortex-retrieval**: Trust-weighted scoring factor, namespace-aware search
- **cortex-validation**: Cross-agent contradiction detection, trust evidence updates
- **cortex-consolidation**: Cross-namespace consolidation, consensus detection
- **cortex-cloud**: CRDT merge replaces LWW for multi-agent sync
- **cortex-session**: Agent identity in session context
- **cortex-napi**: Multi-agent bindings module
- **packages/cortex**: 5 MCP tools + 3 CLI commands

### Backward Compatibility Strategy (MA-R13)

Multi-agent is fully opt-in. Zero breaking changes:

1. **Default namespace**: All existing memories get `namespace: agent://default/`. Single-agent deployments work identically to v1.
2. **Default agent**: All existing memories get `source_agent: default`. The `AgentId::default_agent()` sentinel means "single-agent mode."
3. **Opt-in activation**: Multi-agent features activate only when `MultiAgentConfig.enabled = true` AND a second agent registers. Until then, the system behaves identically to v1.
4. **Zero overhead for single-agent**: Namespace checks are O(1) string comparison against the default. CRDT overhead is zero when there's only one agent (no merges needed).
5. **Migration is additive**: v015 adds new tables and columns. No existing tables are modified destructively. `ALTER TABLE` adds nullable columns with defaults.
6. **API surface is additive**: New MCP tools and CLI commands are added. Existing tools continue to work with implicit default namespace.

---

## Implementation Phases — Four Phases with Quality Gates

Each phase has an 80% test coverage requirement before the next phase begins. Coverage is measured per-module using `cargo tarpaulin` with the `--ignore-tests` flag (test code itself doesn't count toward coverage).

### Phase Overview

| Phase | Name | Recommendations | New Files | Modified Files | Duration |
|-------|------|----------------|-----------|----------------|----------|
| A | CRDT Foundation + Core Types | MA-R1, MA-R6, MA-R11, MA-R12 (core) | ~35 | ~8 | ~1.5 weeks |
| B | Storage + Namespaces + Projections | MA-R2, MA-R3, MA-R10, MA-R12 (storage) | ~20 | ~6 | ~1.5 weeks |
| C | Delta Sync + Trust + Provenance | MA-R4, MA-R5, MA-R7 | ~25 | ~5 | ~1.5 weeks |
| D | Cross-Crate Integration + NAPI + TypeScript | MA-R8, MA-R9, MA-R12 (remaining), MA-R13 | ~15 | ~12 | ~1 week |

### Phase Gate Protocol

Before advancing from Phase N to Phase N+1:

1. **Coverage check**: `cargo tarpaulin -p cortex-crdt --ignore-tests` and `cargo tarpaulin -p cortex-multiagent --ignore-tests` report ≥ 80% line coverage for all Phase N modules
2. **All tests pass**: `cargo test -p cortex-crdt -p cortex-multiagent` exits 0 with zero failures
3. **Property tests pass**: `cargo test -p cortex-crdt -- property` exits 0 (proptest for CRDT convergence)
4. **No regressions**: `cargo test --workspace` exits 0 — no existing crate broken
5. **Benchmark baselines**: `cargo bench -p cortex-crdt` establishes performance baselines for Phase N features
6. **Diagnostics clean**: No compiler warnings in cortex-crdt, cortex-multiagent, or modified crates

### Silent Failure Detection Strategy (Multi-Agent-Specific)

| Module | Silent Failure Risk | Detection Test |
|--------|-------------------|----------------|
| CRDT merge | Non-convergent merge → agents diverge permanently | Property: merge(A,B) == merge(B,A) for all inputs |
| OR-Set | Tombstone leak → unbounded memory growth | Property: OR-Set size bounded by unique adds |
| Vector clock | Missed causal dependency → out-of-order delta apply | Property: causal delivery never applies future deltas |
| Namespace ACL | Permission bypass → unauthorized read/write | Test: agent without Read permission → query returns empty |
| Projection filter | Filter miss → private memories leak to other agents | Test: memory not matching filter → not in projection |
| Trust calculation | Division by zero → NaN trust score | Property: trust always in [0.0, 1.0] |
| Delta sync | Lost delta → permanent divergence between agents | Property: after sync, both agents have same materialized state |
| DAG CRDT cycle detection | Merge introduces cycle → infinite traversal loop | Property: graph is always acyclic after any merge |
| Correction propagation | Undampened cascade → mass invalidation of knowledge | Test: correction at depth 4 → strength < 0.05 threshold |
| Consensus detection | False positive → incorrect confidence boost | Test: dissimilar memories (similarity < 0.9) → no consensus candidate |
| MemoryCRDT materialization | Field mismatch → BaseMemory diverges from CRDT state | Property: to_base_memory(from_base_memory(m)) == m for all fields |

---

## Storage Schema — Migration v015_multiagent_tables

**File**: `crates/cortex/cortex-storage/src/migrations/v015_multiagent_tables.rs`
**Registered in**: `crates/cortex/cortex-storage/src/migrations/mod.rs`
**Follows**: v014_temporal_tables (temporal reasoning)

This migration creates 7 new tables, adds 2 columns to the existing `memories` table, and creates 4 new indexes. All tables use the same conventions as v001-v014: TEXT for ISO 8601 dates, TEXT for JSON blobs, INTEGER PRIMARY KEY AUTOINCREMENT for IDs.

### Table 1: agent_registry (MA-R6)

The agent identity store. Every agent in the system has a row here. Spawned agents reference their parent.

```sql
CREATE TABLE agent_registry (
    agent_id    TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    namespace_id TEXT NOT NULL,
    capabilities TEXT,                   -- JSON array of capability strings
    parent_agent TEXT,                   -- nullable, for spawned sub-agents
    registered_at TEXT NOT NULL,         -- ISO 8601
    last_active TEXT NOT NULL,           -- ISO 8601, updated on heartbeat
    status      TEXT NOT NULL DEFAULT 'active',  -- 'active' | 'idle' | 'deregistered'
    FOREIGN KEY (parent_agent) REFERENCES agent_registry(agent_id)
);

CREATE INDEX idx_agent_status ON agent_registry(status);
CREATE INDEX idx_agent_parent ON agent_registry(parent_agent);
```

**Size estimate**: ~200 bytes/agent. At 20 agents: ~4KB. Negligible.

### Table 2: memory_namespaces (MA-R2)

Namespace metadata. Three scopes: agent (private), team (shared), project (global).

```sql
CREATE TABLE memory_namespaces (
    namespace_id TEXT PRIMARY KEY,       -- URI: agent://id/, team://name/, project://name/
    scope       TEXT NOT NULL,           -- 'agent' | 'team' | 'project'
    owner_agent TEXT,                    -- nullable for team/project namespaces
    created_at  TEXT NOT NULL,
    metadata    TEXT,                    -- JSON for extensibility
    FOREIGN KEY (owner_agent) REFERENCES agent_registry(agent_id)
);
```

### Table 3: namespace_permissions (MA-R2)

ACL entries. Composite primary key: one row per (namespace, agent) pair.

```sql
CREATE TABLE namespace_permissions (
    namespace_id TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    permissions TEXT NOT NULL,            -- JSON array: ["read","write","share","admin"]
    granted_at  TEXT NOT NULL,
    granted_by  TEXT NOT NULL,
    PRIMARY KEY (namespace_id, agent_id),
    FOREIGN KEY (namespace_id) REFERENCES memory_namespaces(namespace_id),
    FOREIGN KEY (agent_id) REFERENCES agent_registry(agent_id)
);
```

### Table 4: memory_projections (MA-R3)

Projection definitions. Each projection is a filtered, compressed view from one namespace to another.

```sql
CREATE TABLE memory_projections (
    projection_id TEXT PRIMARY KEY,
    source_namespace TEXT NOT NULL,
    target_namespace TEXT NOT NULL,
    filter_json TEXT NOT NULL,            -- JSON: ProjectionFilter
    compression_level INTEGER NOT NULL DEFAULT 0,  -- 0=L0 full, 1=L1 summary, 2=L2 compressed, 3=L3 ultra
    live        INTEGER NOT NULL DEFAULT 0,  -- 1 = auto-update on source changes
    created_at  TEXT NOT NULL,
    created_by  TEXT NOT NULL,
    FOREIGN KEY (source_namespace) REFERENCES memory_namespaces(namespace_id),
    FOREIGN KEY (target_namespace) REFERENCES memory_namespaces(namespace_id),
    FOREIGN KEY (created_by) REFERENCES agent_registry(agent_id)
);

CREATE INDEX idx_proj_source ON memory_projections(source_namespace);
CREATE INDEX idx_proj_target ON memory_projections(target_namespace);
```

### Table 5: provenance_log (MA-R4)

Append-only provenance chain. Each row is one hop in a memory's provenance history.

```sql
CREATE TABLE provenance_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    memory_id   TEXT NOT NULL,
    hop_index   INTEGER NOT NULL,        -- 0 = origin, 1 = first hop, etc.
    agent_id    TEXT NOT NULL,
    action      TEXT NOT NULL,           -- ProvenanceAction variant name
    timestamp   TEXT NOT NULL,
    confidence_delta REAL DEFAULT 0.0,
    details     TEXT,                    -- JSON for action-specific data
    FOREIGN KEY (memory_id) REFERENCES memories(id),
    FOREIGN KEY (agent_id) REFERENCES agent_registry(agent_id)
);

CREATE INDEX idx_prov_memory ON provenance_log(memory_id, hop_index);
CREATE INDEX idx_prov_agent ON provenance_log(agent_id);
```

**Size estimate**: ~150 bytes/hop. At 3 hops/memory average for 10K memories: ~4.5MB.

### Table 6: agent_trust (MA-R5)

Per-agent trust scores. Composite primary key: one row per (agent, target_agent) pair.

```sql
CREATE TABLE agent_trust (
    agent_id     TEXT NOT NULL,
    target_agent TEXT NOT NULL,
    overall_trust REAL NOT NULL DEFAULT 0.5,
    domain_trust TEXT,                   -- JSON: {"auth": 0.9, "perf": 0.3}
    evidence     TEXT NOT NULL,          -- JSON: TrustEvidence struct
    last_updated TEXT NOT NULL,
    PRIMARY KEY (agent_id, target_agent),
    FOREIGN KEY (agent_id) REFERENCES agent_registry(agent_id),
    FOREIGN KEY (target_agent) REFERENCES agent_registry(agent_id)
);
```

### Table 7: delta_queue (MA-R7)

Persistent queue for pending CRDT deltas between agents. Deltas are enqueued by the source agent and dequeued by the target agent during sync.

```sql
CREATE TABLE delta_queue (
    delta_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    source_agent TEXT NOT NULL,
    target_agent TEXT NOT NULL,
    memory_id   TEXT NOT NULL,
    delta_json  TEXT NOT NULL,           -- JSON: MemoryDelta with field deltas
    vector_clock TEXT NOT NULL,          -- JSON: VectorClock state
    created_at  TEXT NOT NULL,
    applied     INTEGER NOT NULL DEFAULT 0,
    applied_at  TEXT,                    -- nullable, set when applied
    FOREIGN KEY (source_agent) REFERENCES agent_registry(agent_id),
    FOREIGN KEY (target_agent) REFERENCES agent_registry(agent_id)
);

CREATE INDEX idx_delta_target ON delta_queue(target_agent, applied);
CREATE INDEX idx_delta_created ON delta_queue(created_at);
```

**Size estimate**: ~300 bytes/delta. Active queue of 1000 deltas: ~300KB. Applied deltas are purged periodically.

### Modifications to Existing memories Table

```sql
ALTER TABLE memories ADD COLUMN namespace_id TEXT DEFAULT 'agent://default/';
ALTER TABLE memories ADD COLUMN source_agent TEXT DEFAULT 'default';

CREATE INDEX idx_memories_namespace ON memories(namespace_id);
CREATE INDEX idx_memories_agent ON memories(source_agent);
```

The defaults ensure all existing memories are assigned to the default single-agent namespace. Zero disruption.

### Total Storage Overhead

| Component | 10K memories, 5 agents | 10K memories, 20 agents |
|-----------|----------------------|------------------------|
| agent_registry | ~1 KB | ~4 KB |
| memory_namespaces | ~1 KB | ~4 KB |
| namespace_permissions | ~5 KB | ~80 KB |
| memory_projections | ~10 KB | ~100 KB |
| provenance_log | ~5 MB | ~20 MB |
| agent_trust | ~1 KB | ~16 KB |
| delta_queue (active) | ~300 KB | ~2 MB |
| namespace/agent columns on memories | ~200 KB | ~200 KB |
| CRDT metadata (vector clocks, OR-Set tags, etc.) | ~6.6 MB | ~26 MB |
| **Total** | **~12.1 MB** | **~48.4 MB** |

Negligible. Embedding vectors alone consume ~40MB for 10K memories (1024 dims × 4 bytes each). The CRDT overhead is bounded and predictable.

### Backward Compatibility (MA-R13)

1. All existing queries continue unchanged — they implicitly operate on `agent://default/` namespace
2. The `ALTER TABLE` adds columns with defaults — no data migration needed
3. New tables are empty until multi-agent features are activated
4. Pre-migration data: memories created before v015 have `namespace_id = 'agent://default/'` and `source_agent = 'default'`. All multi-agent queries treat these as single-agent memories. Graceful degradation, not errors.

---

## Data Models — cortex-core Additions (6 New Files)

All multi-agent data models live in cortex-core so every crate can reference them without depending on cortex-crdt or cortex-multiagent directly. This follows the existing pattern: cortex-core owns types, behavior crates own logic.

### Model 1: AgentId + AgentRegistration + AgentStatus + SpawnConfig (MA-R6)

**File**: `crates/cortex/cortex-core/src/models/agent.rs`

```
AgentId:
    inner: String                           -- UUID v4, stable across sessions

    fn new() -> Self                        -- UUID v4 generation
    fn default_agent() -> Self              -- "default" sentinel for single-agent mode
    fn as_str() -> &str                     -- borrow inner string

AgentRegistration:
    agent_id: AgentId
    name: String                            -- human-readable: "code-reviewer-1"
    namespace: NamespaceId                  -- primary namespace (auto-created on register)
    capabilities: Vec<String>               -- ["code-review", "security-audit"]
    parent_agent: Option<AgentId>           -- for spawned sub-agents
    registered_at: DateTime<Utc>
    last_active: DateTime<Utc>
    status: AgentStatus

AgentStatus:
    Active
    Idle { since: DateTime<Utc> }
    Deregistered { at: DateTime<Utc> }

SpawnConfig:
    parent_agent: AgentId
    projection: Option<MemoryProjection>    -- context to inherit from parent
    trust_discount: f64                     -- default 0.8, multiplied against parent trust
    auto_promote_on_deregister: bool        -- default true, promote sub-agent memories to parent
    ttl: Option<Duration>                   -- auto-deregister after TTL expires
```

**Serde**: All types derive `Serialize, Deserialize, Debug, Clone`. AgentStatus uses `#[serde(rename_all = "snake_case")]` for SQLite TEXT storage.

### Model 2: NamespaceId + NamespaceScope + NamespacePermission + NamespaceACL + MemoryProjection + ProjectionFilter (MA-R2, MA-R3)

**File**: `crates/cortex/cortex-core/src/models/namespace.rs`

```
NamespaceId:
    scope: NamespaceScope
    name: String

    fn parse(uri: &str) -> Result<Self>     -- parse "agent://id/", "team://name/", "project://name/"
    fn to_uri() -> String                   -- format back to URI
    fn is_agent() -> bool
    fn is_team() -> bool
    fn is_project() -> bool
    fn is_shared() -> bool                  -- team or project
    fn default_namespace() -> Self          -- agent://default/

NamespaceScope:
    Agent(AgentId)
    Team(String)
    Project(String)

NamespacePermission:
    Read                                    -- can read memories in this namespace
    Write                                   -- can write/update memories
    Share                                   -- can share memories from this namespace to others
    Admin                                   -- can manage permissions

NamespaceACL:
    namespace: NamespaceId
    grants: Vec<(AgentId, Vec<NamespacePermission>)>

MemoryProjection:
    id: String                              -- ProjectionId (UUID)
    source: NamespaceId
    target: NamespaceId
    filter: ProjectionFilter
    compression_level: u8                   -- 0=L0 full, 1=L1 summary, 2=L2 compressed, 3=L3 ultra
    live: bool                              -- auto-update on source changes
    created_at: DateTime<Utc>
    created_by: AgentId

ProjectionFilter:
    memory_types: Option<Vec<MemoryType>>
    min_confidence: Option<f64>
    min_importance: Option<Importance>
    linked_files: Option<Vec<String>>
    tags: Option<Vec<String>>
    max_age_days: Option<u64>
    predicate: Option<String>               -- advanced: custom filter expression
```

**Namespace addressing convention**: URIs follow the pattern `scope://name/`. The trailing slash is canonical. Parsing is case-insensitive for the scope prefix, case-preserving for the name.

### Model 3: ProvenanceRecord + ProvenanceOrigin + ProvenanceHop + ProvenanceAction (MA-R4)

**File**: `crates/cortex/cortex-core/src/models/provenance.rs`

```
ProvenanceRecord:
    memory_id: String
    origin: ProvenanceOrigin
    chain: Vec<ProvenanceHop>
    chain_confidence: f64                   -- product of hop confidences

ProvenanceOrigin:
    Human { user_id: String }
    AgentCreated { agent_id: AgentId, session_id: String }
    Derived { source_memories: Vec<String> }
    Imported { source: String }
    Projected { source_agent: AgentId, source_memory: String }

ProvenanceHop:
    agent_id: AgentId
    action: ProvenanceAction
    timestamp: DateTime<Utc>
    confidence_delta: f64                   -- how this hop affected confidence

ProvenanceAction:
    Created
    SharedTo { target: NamespaceId }
    ProjectedTo { target: NamespaceId, compression: u8 }
    MergedWith { other_memory: String }
    ConsolidatedFrom { source_memories: Vec<String> }
    ValidatedBy { result: String }          -- validation outcome summary
    UsedInDecision { decision_memory: String }
    CorrectedBy { correction: String }
    ReclassifiedFrom { old_type: MemoryType }
```

### Model 4: CrossAgentRelation + CrossAgentContradiction + ContradictionResolution + AgentTrust + TrustEvidence (MA-R5, MA-R9)

**File**: `crates/cortex/cortex-core/src/models/cross_agent.rs`

```
CrossAgentRelation:
    InformedBy { source_agent: AgentId }
    DecisionBasedOn { source_agent: AgentId }
    IndependentCorroboration { agents: Vec<AgentId> }
    CrossAgentContradiction { contradicting_agent: AgentId }
    Refinement { original_agent: AgentId }

CrossAgentContradiction:
    memory_a: String
    agent_a: AgentId
    trust_a: f64
    memory_b: String
    agent_b: AgentId
    trust_b: f64
    contradiction_type: String              -- reuses existing ContradictionType
    resolution: ContradictionResolution

ContradictionResolution:
    TrustWins { winner: AgentId }           -- higher-trust agent's memory wins automatically
    NeedsHumanReview                        -- trust difference too small for auto-resolve
    ContextDependent { context_a: String, context_b: String }  -- both valid in different scopes
    TemporalSupersession { newer: String }  -- newer + validated memory supersedes

AgentTrust:
    agent_id: AgentId
    target_agent: AgentId
    overall_trust: f64                      -- [0.0, 1.0]
    domain_trust: HashMap<String, f64>      -- per-domain: {"auth": 0.9, "perf": 0.3}
    evidence: TrustEvidence
    last_updated: DateTime<Utc>

TrustEvidence:
    validated_count: u64                    -- memories later validated as correct
    contradicted_count: u64                 -- memories later contradicted
    useful_count: u64                       -- memories accessed and used in decisions
    total_received: u64                     -- total memories received from this agent
```

**Trust calculation formula**:
```
overall_trust = (validated + useful) / (total_received + 1)
              × (1 - contradicted / (total_received + 1))
```

The `+1` in denominators prevents division by zero and provides a slight optimistic prior (new agents start with moderate trust, not zero).

**Trust decay formula** (toward 0.5 neutral when no new evidence):
```
trust_decay(days) = trust + (0.5 - trust) × (1 - 0.99^days)
```

After 100 days without interaction, trust drifts ~63% toward neutral.

### Model Registration

**Modified file**: `crates/cortex/cortex-core/src/models/mod.rs`

Add 4 new module declarations and re-exports:

```rust
mod agent;           // AgentId, AgentRegistration, AgentStatus, SpawnConfig
mod namespace;       // NamespaceId, NamespaceScope, NamespacePermission, NamespaceACL, MemoryProjection, ProjectionFilter
mod provenance;      // ProvenanceRecord, ProvenanceOrigin, ProvenanceHop, ProvenanceAction
mod cross_agent;     // CrossAgentRelation, CrossAgentContradiction, ContradictionResolution, AgentTrust, TrustEvidence
```

All types re-exported via `pub use` following the existing pattern in mod.rs.

### BaseMemory Modifications

**Modified file**: `crates/cortex/cortex-core/src/memory/base.rs`

Add 2 new fields to `BaseMemory`:

```rust
/// Namespace this memory belongs to. Default: agent://default/
pub namespace: NamespaceId,
/// Agent that created this memory. Default: AgentId::default_agent()
pub source_agent: AgentId,
```

Both fields have defaults that preserve backward compatibility. The `empty_memory_shell` function in cortex-temporal is updated to include these fields with their defaults.

### Relationship Extension

**Modified file**: `crates/cortex/cortex-core/src/memory/relationships.rs`

Add `CrossAgent(CrossAgentRelation)` variant to the existing `RelationshipType` enum. This extends the existing 13 relationship types with 5 cross-agent variants.

---

## Error Type — MultiAgentError (MA-R12)

**New file**: `crates/cortex/cortex-core/src/errors/multiagent_error.rs`
**Modified file**: `crates/cortex/cortex-core/src/errors/mod.rs` — add `mod multiagent_error;` + `pub use`

```
MultiAgentError:
    AgentNotFound(String)
    AgentAlreadyRegistered(String)
    NamespaceNotFound(String)
    PermissionDenied { agent: String, namespace: String, permission: String }
    ProjectionNotFound(String)
    InvalidNamespaceUri(String)
    CausalOrderViolation { expected: String, found: String }
    CyclicDependency(String)
    SyncFailed(String)
    TrustComputationFailed(String)
```

Implements `From<MultiAgentError> for CortexError` via a new `MultiAgentError` variant added to the existing `CortexError` enum in `cortex_error.rs`:

```rust
#[error("multi-agent error: {0}")]
MultiAgentError(#[from] MultiAgentError),
```

---

## Trait — IMultiAgentEngine (MA-R12)

**New file**: `crates/cortex/cortex-core/src/traits/multiagent_engine.rs`
**Modified file**: `crates/cortex/cortex-core/src/traits/mod.rs` — add `mod multiagent_engine;` + `pub use`

The 14th trait in cortex-core. Defines the complete multi-agent interface:

```
#[allow(async_fn_in_trait)]
trait IMultiAgentEngine: Send + Sync {
    // Agent registry (MA-R6)
    async fn register_agent(&self, name: &str, capabilities: Vec<String>) -> CortexResult<AgentRegistration>;
    async fn deregister_agent(&self, agent_id: &AgentId) -> CortexResult<()>;
    async fn get_agent(&self, agent_id: &AgentId) -> CortexResult<Option<AgentRegistration>>;
    async fn list_agents(&self) -> CortexResult<Vec<AgentRegistration>>;

    // Namespaces (MA-R2)
    async fn create_namespace(&self, scope: NamespaceScope, owner: &AgentId) -> CortexResult<NamespaceId>;
    async fn check_permission(&self, namespace: &NamespaceId, agent: &AgentId, permission: NamespacePermission) -> CortexResult<bool>;

    // Sharing (MA-R2, MA-R3)
    async fn share_memory(&self, memory_id: &str, target_namespace: &NamespaceId, agent_id: &AgentId) -> CortexResult<()>;
    async fn create_projection(&self, projection: MemoryProjection) -> CortexResult<String>;

    // Sync (MA-R7)
    async fn sync_with(&self, target_agent: &AgentId) -> CortexResult<SyncResult>;

    // Provenance (MA-R4)
    async fn get_provenance(&self, memory_id: &str) -> CortexResult<Option<ProvenanceRecord>>;

    // Trust (MA-R5)
    async fn get_trust(&self, agent_id: &AgentId, target_agent: &AgentId) -> CortexResult<AgentTrust>;

    // Consensus (MA-R8)
    async fn detect_consensus(&self, namespace: &NamespaceId) -> CortexResult<Vec<ConsensusCandidate>>;
}
```

This trait is the contract. cortex-multiagent's `MultiAgentEngine` struct is the implementation. Other crates depend on the trait (in cortex-core), not the implementation (in cortex-multiagent).

---

## Config — MultiAgentConfig (MA-R1 through MA-R9)

**New file**: `crates/cortex/cortex-core/src/config/multiagent_config.rs`
**Modified file**: `crates/cortex/cortex-core/src/config/mod.rs` — add `pub mod multiagent_config;` + `pub use` + add `multiagent: MultiAgentConfig` field to `CortexConfig`

```
MultiAgentConfig:
    // Feature gate
    enabled: bool                               = false     -- opt-in activation

    // Namespace defaults
    default_namespace: String                   = "agent://default/"

    // Agent lifecycle
    agent_idle_timeout_hours: u64               = 24        -- status → Idle after this

    // Delta sync (MA-R7)
    delta_queue_max_size: usize                 = 1000      -- bounded queue per target agent
    backpressure_batch_interval_secs: u64       = 60        -- batch sync interval under backpressure

    // Trust scoring (MA-R5)
    trust_bootstrap_score: f64                  = 0.5       -- new agents start here
    trust_decay_rate: f64                       = 0.99      -- daily decay toward neutral
    trust_contradiction_penalty: f64            = 0.10      -- per contradiction
    trust_validation_bonus: f64                 = 0.05      -- per validation
    trust_usage_bonus: f64                      = 0.02      -- per usage in decision
    spawn_trust_discount: f64                   = 0.8       -- spawned agent inherits parent × this

    // Correction propagation (MA-R4)
    correction_dampening_factor: f64            = 0.7       -- strength × 0.7^hop
    correction_min_threshold: f64               = 0.05      -- stop propagation below this

    // Consensus detection (MA-R8)
    consensus_similarity_threshold: f64         = 0.9       -- embedding similarity for consensus
    consensus_min_agents: usize                 = 2         -- minimum agents for consensus
    consensus_confidence_boost: f64             = 0.2       -- confidence boost on consensus

    // Contradiction resolution (MA-R9)
    contradiction_trust_auto_resolve_threshold: f64 = 0.3   -- trust diff > this → auto-resolve
```

All fields have defaults via `impl Default for MultiAgentConfig`. Configurable via TOML under `[multiagent]` section in CortexConfig.

---

## Phase A: CRDT Foundation + Core Types (~35 new files, ~8 modified)

Phase A builds the mathematical foundation that every subsequent phase depends on. No networking, no storage — just pure CRDT data structures with proven convergence properties, plus the core types in cortex-core.

### Phase A — cortex-core Changes

**Files created** (Phase A subset):
- `src/models/agent.rs` — AgentId, AgentRegistration, AgentStatus, SpawnConfig
- `src/models/namespace.rs` — NamespaceId, NamespaceScope, NamespacePermission, NamespaceACL, MemoryProjection, ProjectionFilter
- `src/models/provenance.rs` — ProvenanceRecord, ProvenanceOrigin, ProvenanceHop, ProvenanceAction
- `src/models/cross_agent.rs` — CrossAgentRelation, CrossAgentContradiction, ContradictionResolution, AgentTrust, TrustEvidence
- `src/errors/multiagent_error.rs` — MultiAgentError enum
- `src/traits/multiagent_engine.rs` — IMultiAgentEngine trait
- `src/config/multiagent_config.rs` — MultiAgentConfig

**Files modified**:
- `src/models/mod.rs` — add 4 new module declarations + re-exports
- `src/memory/base.rs` — add `namespace: NamespaceId` and `source_agent: AgentId` fields
- `src/memory/relationships.rs` — add `CrossAgent(CrossAgentRelation)` variant
- `src/errors/mod.rs` — add multiagent_error module + re-export
- `src/errors/cortex_error.rs` — add MultiAgentError variant to CortexError
- `src/traits/mod.rs` — add multiagent_engine module + re-export
- `src/config/mod.rs` — add multiagent_config module + re-export + add field to CortexConfig

### Phase A — cortex-crdt Crate (New)

**File**: `crates/cortex/cortex-crdt/Cargo.toml`

```toml
[package]
name = "cortex-crdt"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
description = "CRDT primitives for conflict-free multi-agent memory convergence"

[dependencies]
cortex-core = { workspace = true }
chrono = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }

[dev-dependencies]
proptest = { workspace = true }
criterion = { workspace = true }
test-fixtures = { workspace = true }

[[bench]]
name = "crdt_bench"
harness = false
```

**Workspace registration**: Add `"cortex-crdt"` to `[workspace.members]` and `cortex-crdt = { path = "cortex-crdt" }` to `[workspace.dependencies]` in `crates/cortex/Cargo.toml`.

### Phase A — cortex-crdt Source Files

```
crates/cortex/cortex-crdt/
├── Cargo.toml
├── src/
│   ├── lib.rs                              # Module declarations + re-exports
│   ├── clock.rs                            # VectorClock
│   ├── primitives/
│   │   ├── mod.rs                          # Module declarations + re-exports
│   │   ├── gcounter.rs                     # GCounter (grow-only counter)
│   │   ├── lww_register.rs                 # LWWRegister (last-writer-wins)
│   │   ├── mv_register.rs                  # MVRegister (multi-value)
│   │   ├── or_set.rs                       # ORSet (observed-remove set)
│   │   └── max_register.rs                 # MaxRegister (max-wins)
│   ├── memory/
│   │   ├── mod.rs                          # Module declarations + re-exports
│   │   ├── memory_crdt.rs                  # MemoryCRDT (per-field CRDT wrapper for BaseMemory)
│   │   ├── field_delta.rs                  # FieldDelta enum (per-field change descriptors)
│   │   └── merge_engine.rs                 # MergeEngine (stateless merge orchestrator)
│   └── graph/
│       ├── mod.rs                          # Module declarations + re-exports
│       └── dag_crdt.rs                     # CausalGraphCRDT (novel DAG CRDT)
├── tests/
│   ├── crdt_test.rs                        # Unit tests for all CRDT primitives
│   ├── memory_crdt_test.rs                 # MemoryCRDT merge + delta tests
│   ├── dag_crdt_test.rs                    # CausalGraphCRDT tests
│   ├── property_tests.rs                   # Entry point for proptest module
│   ├── property/
│   │   ├── mod.rs
│   │   └── crdt_properties.rs             # All CRDT property-based tests
│   └── stress_test.rs                      # High-volume merge tests
└── benches/
    └── crdt_bench.rs                       # Criterion benchmarks
```

### Phase A — Module Specifications

#### `src/lib.rs`

Crate root. Module declarations for all submodules (clock, primitives, memory, graph). Re-exports the public API: VectorClock, all CRDT primitives, MemoryCRDT, FieldDelta, MergeEngine, CausalGraphCRDT.

#### `src/clock.rs` — VectorClock (MA-R1, MA-R7)

The causal ordering primitive. Each agent maintains its own logical clock entry. Used by delta sync to ensure causal delivery.

```
VectorClock:
    clocks: HashMap<String, u64>            -- AgentId → logical clock value

    fn new() -> Self                        -- empty clock
    fn increment(&mut self, agent_id: &str) -- increment agent's entry by 1
    fn get(&self, agent_id: &str) -> u64    -- get agent's current value (0 if absent)
    fn merge(&mut self, other: &Self)       -- component-wise max
    fn happens_before(&self, other: &Self) -> bool
        -- all self entries <= other entries, at least one strictly less
    fn concurrent_with(&self, other: &Self) -> bool
        -- neither happens_before the other
    fn dominates(&self, other: &Self) -> bool
        -- all self entries >= other entries, at least one strictly greater
```

**Key properties** (verified by property tests):
- `merge(A, B) == merge(B, A)` — commutativity
- `merge(A, merge(B, C)) == merge(merge(A, B), C)` — associativity
- `merge(A, A) == A` — idempotency
- `happens_before` is a strict partial order (irreflexive, transitive, antisymmetric)

#### `src/primitives/gcounter.rs` — GCounter (MA-R1)

Grow-only counter. Each agent maintains its own counter. Merge = per-agent max. Value = sum.

Used for: `access_count`, `retrieval_count` — fields that only ever increase.

```
GCounter:
    counts: HashMap<String, u64>            -- AgentId → agent's counter

    fn new() -> Self
    fn increment(&mut self, agent_id: &str) -- increment agent's counter by 1
    fn value(&self) -> u64                  -- sum of all agent counters
    fn merge(&mut self, other: &Self)       -- per-agent max
    fn delta_since(&self, other: &Self) -> GCounterDelta
        -- entries where self > other (for delta sync)
```

**Convergence guarantee**: Monotonically increasing. No lost increments. `merge(A, B).value() >= max(A.value(), B.value())`.

#### `src/primitives/lww_register.rs` — LWWRegister (MA-R1)

Last-writer-wins register. Each update carries a timestamp + agent_id. Merge = keep highest timestamp. Tie-break: agent_id lexicographic (deterministic).

Used for: `content`, `summary`, `memory_type`, `importance`, `archived`, `superseded_by`, `valid_time`, `valid_until`, `namespace`.

```
LWWRegister<T>:
    value: T
    timestamp: DateTime<Utc>
    agent_id: String

    fn new(value: T, timestamp: DateTime<Utc>, agent_id: String) -> Self
    fn set(&mut self, value: T, timestamp: DateTime<Utc>, agent_id: String)
        -- update only if (timestamp, agent_id) > current (timestamp, agent_id)
    fn get(&self) -> &T
    fn merge(&mut self, other: &Self)
        -- keep higher (timestamp, agent_id) pair
    fn delta_since(&self, other: &Self) -> Option<LWWDelta<T>>
        -- self if newer than other
```

**Tie-breaking rule**: When timestamps are equal, the lexicographically greater agent_id wins. This ensures deterministic convergence even with synchronized clocks. The choice of "greater wins" is arbitrary but must be consistent across all replicas.

#### `src/primitives/mv_register.rs` — MVRegister (MA-R1)

Multi-value register. Preserves all concurrent values for manual resolution. Used when concurrent edits to `content` must be preserved rather than silently discarded.

```
MVRegister<T>:
    values: Vec<(T, VectorClock)>           -- concurrent values with their causal context

    fn new() -> Self
    fn set(&mut self, value: T, clock: &VectorClock)
        -- add value, prune entries dominated by this clock
    fn get(&self) -> Vec<&T>                -- all concurrent values
    fn is_conflicted(&self) -> bool         -- more than one value
    fn resolve(&mut self, value: T)         -- collapse to single value (manual resolution)
    fn merge(&mut self, other: &Self)
        -- keep all non-dominated entries from both registers
```

**When to use MV vs LWW**: LWW is the default for all fields. MV-Register is opt-in for `content` when the agent explicitly wants to preserve concurrent edits (e.g., two agents editing the same memory simultaneously). The `is_conflicted()` flag surfaces to cortex-cloud's existing conflict resolution UI.

#### `src/primitives/or_set.rs` — ORSet (MA-R1)

Observed-Remove Set with add-wins semantics. Concurrent add + remove = element is present. This matches developer expectations — if Agent A adds a tag while Agent B removes it, the tag stays (the add had information the remove didn't).

Used for: `tags`, `linked_patterns`, `linked_constraints`, `linked_files`, `linked_functions`, `supersedes`.

```
UniqueTag:
    agent_id: String
    seq: u64                                -- monotonically increasing per agent

ORSet<T>:
    adds: HashMap<T, HashSet<UniqueTag>>    -- element → set of unique tags
    tombstones: HashSet<UniqueTag>          -- removed tags

    fn new() -> Self
    fn add(&mut self, value: T, agent_id: &str, seq: u64) -> UniqueTag
        -- add with unique tag, returns the tag
    fn remove(&mut self, value: &T)
        -- tombstone all current tags for this value
    fn contains(&self, value: &T) -> bool
        -- in adds and not fully tombstoned
    fn elements(&self) -> Vec<&T>           -- all present elements
    fn len(&self) -> usize
    fn merge(&mut self, other: &Self)
        -- union of add-sets, union of tombstone-sets
    fn delta_since(&self, other: &Self) -> ORSetDelta<T>
        -- new adds and removes since other's state
```

**Add-wins semantics**: When Agent A adds tag "auth" (creating tag-1) and Agent B concurrently removes tag "auth" (tombstoning tag-0), the merge result contains "auth" because tag-1 is not tombstoned. This is the correct behavior for collaborative tagging.

**Tombstone management**: Tombstones accumulate but are bounded by the total number of unique adds ever performed. Periodic compaction (during delta sync) can prune tombstones for elements that have been re-added.

#### `src/primitives/max_register.rs` — MaxRegister (MA-R1)

Max-wins register. Only values greater than the current propagate. Prevents accidental regression from stale replicas.

Used for: `confidence` (explicit boosts only), `last_accessed`.

```
MaxRegister<T: Ord>:
    value: T
    timestamp: DateTime<Utc>

    fn new(value: T, timestamp: DateTime<Utc>) -> Self
    fn set(&mut self, value: T)
        -- update only if value > current
    fn get(&self) -> &T
    fn merge(&mut self, other: &Self)
        -- keep greater value
    fn delta_since(&self, other: &Self) -> Option<MaxDelta<T>>
        -- self if greater than other
```

**Confidence: The Special Case**: Confidence is modified by two fundamentally different mechanisms:
1. **Explicit actions** (user boost, validation pass, consensus) — propagate via MaxRegister
2. **Automatic decay** (time-based, per-agent) — local only, NOT propagated

Solution: decompose into `base_confidence` (CRDT, propagates via MaxRegister) and `decay_factor` (local, per-agent). Effective confidence = `base_confidence × decay_factor`. This means if Agent A hasn't accessed a memory in months (low local decay) but Agent B just validated it (high base_confidence), Agent A sees the boost but retains its own decay factor. Cognitively correct — relevance is personal, truth is shared.

#### `src/memory/memory_crdt.rs` — MemoryCRDT (MA-R1)

The per-field CRDT wrapper for a single BaseMemory. Every field of BaseMemory is wrapped in the appropriate CRDT type. This is the central data structure of the multi-agent system.

```
MemoryCRDT:
    // Immutable fields (set once, never change)
    id: String
    transaction_time: DateTime<Utc>

    // LWW-Register fields
    memory_type: LWWRegister<String>
    content: LWWRegister<String>            -- serialized TypedContent
    summary: LWWRegister<String>
    valid_time: LWWRegister<DateTime<Utc>>
    valid_until: LWWRegister<Option<DateTime<Utc>>>
    importance: LWWRegister<String>         -- serialized Importance
    archived: LWWRegister<bool>
    superseded_by: LWWRegister<Option<String>>
    namespace: LWWRegister<String>          -- serialized NamespaceId

    // MaxRegister fields
    base_confidence: MaxRegister<f64>
    last_accessed: MaxRegister<DateTime<Utc>>

    // GCounter fields
    access_count: GCounter

    // ORSet fields
    linked_patterns: ORSet<String>          -- serialized PatternLink
    linked_constraints: ORSet<String>       -- serialized ConstraintLink
    linked_files: ORSet<String>             -- serialized FileLink
    linked_functions: ORSet<String>         -- serialized FunctionLink
    tags: ORSet<String>
    supersedes: ORSet<String>

    // Append-only
    provenance: Vec<ProvenanceHop>

    // Causal context
    clock: VectorClock

    fn merge(&mut self, other: &Self)
        -- per-field merge using each field's CRDT merge
    fn to_base_memory(&self) -> BaseMemory
        -- materialize current CRDT state into a BaseMemory
    fn from_base_memory(memory: &BaseMemory, agent_id: &str) -> Self
        -- wrap existing BaseMemory fields in CRDT wrappers
    fn content_hash(&self) -> String
        -- recompute blake3 from materialized content
```

**Per-field CRDT type mapping** (complete):

| BaseMemory Field | CRDT Type | Merge Semantics |
|-----------------|-----------|-----------------|
| `id` | Immutable | First-write wins (UUID, never changes) |
| `memory_type` | LWW-Register | Last reclassification wins |
| `content` | LWW-Register | Last edit wins (MV-Register opt-in for conflict preservation) |
| `summary` | LWW-Register | Last edit wins |
| `transaction_time` | Immutable | Set at creation, never changes |
| `valid_time` | LWW-Register | Can be corrected (temporal correction semantics) |
| `valid_until` | LWW-Register | Can be extended/shortened |
| `confidence` | MaxRegister | Only explicit boosts propagate; decay is local |
| `importance` | LWW-Register | Last reclassification wins |
| `last_accessed` | MaxRegister | Most recent access wins |
| `access_count` | GCounter | Per-agent counters, sum for total |
| `linked_patterns` | ORSet | Add wins over concurrent remove |
| `linked_constraints` | ORSet | Add wins over concurrent remove |
| `linked_files` | ORSet | Add wins over concurrent remove |
| `linked_functions` | ORSet | Add wins over concurrent remove |
| `tags` | ORSet | Add wins over concurrent remove |
| `archived` | LWW-Register | Explicit archive/restore |
| `superseded_by` | LWW-Register | Explicit supersession |
| `supersedes` | ORSet | Can supersede multiple memories |
| `content_hash` | Derived | Recomputed from content after merge |
| `namespace` | LWW-Register | Explicit promote/move |
| `source_agent` | Immutable | Set at creation |
| `provenance` | Append-only | Union of all provenance hops |

#### `src/memory/field_delta.rs` — FieldDelta (MA-R1, MA-R7)

Per-field change descriptors for delta sync. Each variant describes a single field change that can be applied to a MemoryCRDT.

```
FieldDelta:
    ContentUpdated { value: String, lww_timestamp: DateTime<Utc>, agent_id: String }
    SummaryUpdated { value: String, lww_timestamp: DateTime<Utc>, agent_id: String }
    ConfidenceBoosted { value: f64, max_timestamp: DateTime<Utc> }
    TagAdded { tag: String, unique_tag: UniqueTag }
    TagRemoved { tag: String, removed_tags: HashSet<UniqueTag> }
    LinkAdded { link_type: String, target: String, unique_tag: UniqueTag }
    LinkRemoved { link_type: String, target: String, removed_tags: HashSet<UniqueTag> }
    AccessCountIncremented { agent: String, new_count: u64 }
    ImportanceChanged { value: String, lww_timestamp: DateTime<Utc>, agent_id: String }
    ArchivedChanged { value: bool, lww_timestamp: DateTime<Utc>, agent_id: String }
    ProvenanceHopAdded { hop: ProvenanceHop }
    MemoryCreated { full_state: serde_json::Value }
    NamespaceChanged { namespace: String, lww_timestamp: DateTime<Utc>, agent_id: String }
```

**Serde**: All variants derive `Serialize, Deserialize`. The `FieldDelta` enum uses `#[serde(tag = "type", content = "data")]` for clean JSON representation in the delta_queue table.

#### `src/memory/merge_engine.rs` — MergeEngine (MA-R1, MA-R7)

Stateless merge orchestrator. Coordinates merging two MemoryCRDT instances and computing/applying deltas.

```
MergeEngine:
    fn merge_memories(local: &MemoryCRDT, remote: &MemoryCRDT) -> MemoryCRDT
        -- per-field merge, returns new merged state
    fn apply_delta(local: &mut MemoryCRDT, delta: &MemoryDelta) -> CortexResult<()>
        -- apply a set of field deltas to local state
        -- validates causal ordering before applying
    fn compute_delta(local: &MemoryCRDT, remote_clock: &VectorClock) -> MemoryDelta
        -- compute field deltas that remote is missing based on clock comparison

MemoryDelta:
    memory_id: String
    source_agent: String
    clock: VectorClock
    field_deltas: Vec<FieldDelta>
    timestamp: DateTime<Utc>
```

**Causal ordering validation**: Before applying a delta, the MergeEngine checks that all causal predecessors have been applied (via VectorClock comparison). If a delta arrives out of order, it's buffered for later application.

#### `src/graph/dag_crdt.rs` — CausalGraphCRDT (MA-R11)

The most novel piece. A CRDT for directed acyclic graphs with cycle prevention. No existing CRDT library provides this.

```
CausalGraphCRDT:
    edges: ORSet<CausalEdge>                -- edges with add-wins semantics
    strengths: HashMap<(String, String), MaxRegister<f64>>  -- (source, target) → strength

    fn new() -> Self
    fn add_edge(&mut self, edge: CausalEdge, agent_id: &str, seq: u64) -> CortexResult<()>
        -- local cycle check via would_create_cycle(), then add to ORSet
        -- initialize strength in MaxRegister
    fn remove_edge(&mut self, source: &str, target: &str)
        -- OR-Set remove (tombstone all tags for this edge)
    fn update_strength(&mut self, source: &str, target: &str, strength: f64)
        -- MaxRegister update (only if strength > current)
    fn merge(&mut self, other: &Self) -> CortexResult<()>
        -- merge edges (ORSet merge) + strengths (per-edge MaxRegister merge)
        -- then resolve_cycles() to handle merge-introduced cycles
    fn resolve_cycles(&mut self)
        -- while detect_cycle() returns Some:
        --   find weakest edge in cycle (lowest strength)
        --   remove it from ORSet
    fn detect_cycle(&self) -> Option<Vec<CausalEdge>>
        -- DFS-based cycle detection on current edge set
    fn would_create_cycle(&self, edge: &CausalEdge) -> bool
        -- check if adding this edge would create a cycle (DFS from target to source)
    fn to_petgraph(&self) -> StableGraph<String, CausalEdge>
        -- materialize current state into petgraph for traversal
    fn edges(&self) -> Vec<&CausalEdge>
        -- all present edges
```

**Why this is novel**: Existing CRDT literature (MA9, Shapiro et al.) covers sets, registers, counters, and maps. Graph CRDTs exist for general graphs but not for DAGs with cycle prevention. Our contribution:
1. Maintains the DAG invariant across concurrent modifications from multiple agents
2. Resolves merge-introduced cycles deterministically (weakest-link removal — the edge with the lowest MaxRegister strength is removed)
3. Preserves OR-Set semantics for edge add/remove (add wins over concurrent remove)
4. Tracks edge strengths with max-wins convergence

**Cycle resolution determinism**: When a merge introduces a cycle (Agent A adds edge X→Y, Agent B adds edge Y→X, both individually acyclic), the `resolve_cycles()` function removes the weakest edge. If strengths are equal, the edge with the lexicographically smaller `(source, target)` pair is removed. This ensures all replicas converge to the same acyclic graph.

### Phase A — CRDT Storage Overhead Analysis

For 10K memories across 5 agents:

| Component | Per-Memory | Total (10K) |
|-----------|-----------|-------------|
| Vector clocks (5 agents × 8 bytes) | 40 bytes | 400 KB |
| OR-Set metadata (tags, ~5 × 50 bytes) | 250 bytes | 2.5 MB |
| OR-Set metadata (links, ~3 × 50 bytes) | 150 bytes | 1.5 MB |
| G-Counter (access_count, 5 × 8 bytes) | 40 bytes | 400 KB |
| LWW timestamps (10 fields × 16 bytes) | 160 bytes | 1.6 MB |
| Delta log (last 1000 deltas × ~200 bytes) | — | 200 KB |
| **Total CRDT overhead** | **~640 bytes** | **~6.6 MB** |

Negligible. Embedding vectors alone consume ~40MB (10K × 1024 dims × 4 bytes).

### Phase A — Quality Gate (QG-MA0)

| Test | Pass Criteria | Coverage Target |
|------|---------------|-----------------|
| GCounter increment + value | Increment 3 agents → value = sum | primitives/gcounter.rs ≥ 80% |
| GCounter merge commutativity | merge(A,B) == merge(B,A) | primitives/gcounter.rs ≥ 80% |
| GCounter merge associativity | merge(A, merge(B,C)) == merge(merge(A,B), C) | primitives/gcounter.rs ≥ 80% |
| GCounter merge idempotency | merge(A,A) == A | primitives/gcounter.rs ≥ 80% |
| LWWRegister set + get | Set value → get returns it | primitives/lww_register.rs ≥ 80% |
| LWWRegister merge keeps newer | Two timestamps → merge keeps higher | primitives/lww_register.rs ≥ 80% |
| LWWRegister tie-break by agent_id | Same timestamp → lexicographic agent_id wins | primitives/lww_register.rs ≥ 80% |
| LWWRegister merge commutativity | merge(A,B) == merge(B,A) | primitives/lww_register.rs ≥ 80% |
| MVRegister concurrent values | Two concurrent sets → both values present | primitives/mv_register.rs ≥ 80% |
| MVRegister is_conflicted | Concurrent values → true; single value → false | primitives/mv_register.rs ≥ 80% |
| MVRegister resolve collapses | Resolve → single value, is_conflicted = false | primitives/mv_register.rs ≥ 80% |
| ORSet add + contains | Add element → contains returns true | primitives/or_set.rs ≥ 80% |
| ORSet remove + contains | Add then remove → contains returns false | primitives/or_set.rs ≥ 80% |
| ORSet add-wins semantics | Concurrent add + remove → element present | primitives/or_set.rs ≥ 80% |
| ORSet merge commutativity | merge(A,B) == merge(B,A) | primitives/or_set.rs ≥ 80% |
| ORSet size bounded | Property: size ≤ unique adds | primitives/or_set.rs ≥ 80% |
| MaxRegister only-up | Set lower value → unchanged | primitives/max_register.rs ≥ 80% |
| MaxRegister merge keeps max | Two values → merge keeps greater | primitives/max_register.rs ≥ 80% |
| VectorClock increment | Increment agent → that entry +1 | clock.rs ≥ 80% |
| VectorClock merge component-wise max | merge(A,B) → per-agent max | clock.rs ≥ 80% |
| VectorClock happens_before | A < B when all A entries ≤ B, at least one < | clock.rs ≥ 80% |
| VectorClock concurrent | Neither happens_before → concurrent | clock.rs ≥ 80% |
| MemoryCRDT from_base_memory round-trip | from_base_memory → to_base_memory == original | memory/memory_crdt.rs ≥ 80% |
| MemoryCRDT merge convergence | Two divergent copies → merge → identical state | memory/memory_crdt.rs ≥ 80% |
| MemoryCRDT delta computation | Compute delta → apply delta → states converge | memory/memory_crdt.rs ≥ 80% |
| MergeEngine causal ordering | Apply delta with missing predecessor → error | memory/merge_engine.rs ≥ 80% |
| CausalGraphCRDT add edge | Add edge → edge present | graph/dag_crdt.rs ≥ 80% |
| CausalGraphCRDT self-loop rejected | Add A→A → error | graph/dag_crdt.rs ≥ 80% |
| CausalGraphCRDT multi-hop cycle rejected | Add A→B, B→C, C→A → last add fails | graph/dag_crdt.rs ≥ 80% |
| CausalGraphCRDT merge-introduced cycle resolved | Agent 1 adds A→B, Agent 2 adds B→A → merge → weakest removed | graph/dag_crdt.rs ≥ 80% |
| CausalGraphCRDT strength max-wins | Two agents update strength → max wins | graph/dag_crdt.rs ≥ 80% |
| No existing test regressions | `cargo test --workspace` passes | Workspace-wide |

**Property-based tests** (proptest, Phase A):
1. **GCounter**: merge(A,B) == merge(B,A) for random counters (commutativity)
2. **GCounter**: merge(A, merge(B,C)) == merge(merge(A,B), C) (associativity)
3. **GCounter**: merge(A,A) == A (idempotency)
4. **LWWRegister**: merge commutativity, associativity, idempotency
5. **ORSet**: merge commutativity, associativity, idempotency
6. **ORSet**: concurrent add + remove → element present (add-wins)
7. **ORSet**: size bounded by unique adds
8. **MaxRegister**: merge commutativity, value monotonically non-decreasing
9. **VectorClock**: causal delivery never applies future deltas
10. **MemoryCRDT**: merge(A,B) == merge(B,A) for all field types
11. **MemoryCRDT**: after sync, both agents have same materialized state
12. **CausalGraphCRDT**: graph is always acyclic after any merge
13. **CausalGraphCRDT**: edge add is commutative
14. **Trust score**: always in [0.0, 1.0] for any evidence values

**Benchmark baselines** (criterion, Phase A):
- GCounter merge latency (target: < 0.01ms)
- ORSet merge, 100 elements (target: < 0.1ms)
- MemoryCRDT full merge (target: < 0.5ms)
- Delta computation, 50 changed fields (target: < 0.2ms)
- DAG CRDT merge, 500 edges (target: < 5ms)
- VectorClock merge, 20 agents (target: < 0.01ms)

---

## Phase B: Storage + Namespaces + Projections (~20 new files, ~6 modified)

Phase B builds the storage layer (migration v015), the namespace system, and the projection engine. Depends on Phase A's CRDT primitives and core types being fully operational.

### Phase B — cortex-storage Changes

**New file**: `src/migrations/v015_multiagent_tables.rs`
- Creates all 7 tables + 2 new columns on memories + 4 new indexes
- Registered in `src/migrations/mod.rs`

**New file**: `src/queries/multiagent_ops.rs` — raw SQL for all multi-agent CRUD
- Agent registry: insert_agent, get_agent, list_agents, update_agent_status, update_last_active, delete_agent
- Namespace: insert_namespace, get_namespace, list_namespaces, delete_namespace
- Permission: insert_permission, get_permissions, check_permission, delete_permission
- Projection: insert_projection, get_projection, list_projections, delete_projection
- Provenance: insert_provenance_hop, get_provenance_chain, get_provenance_origin
- Trust: insert_trust, get_trust, update_trust, list_trust_for_agent
- Delta queue: enqueue_delta, dequeue_deltas, mark_deltas_applied, pending_delta_count, purge_applied_deltas
- Raw SQL operations, no business logic

**Modified files**:
- `src/queries/mod.rs` — add `pub mod multiagent_ops;`
- `src/queries/memory_crud.rs` — extend create/get with namespace_id and source_agent columns; add `get_memories_by_namespace()` and `get_memories_by_agent()`
- `src/queries/memory_query.rs` — add optional `namespace_filter: Option<NamespaceId>` parameter to search queries
- `src/migrations/mod.rs` — register v015

### Phase B — cortex-multiagent Crate (New)

**File**: `crates/cortex/cortex-multiagent/Cargo.toml`

```toml
[package]
name = "cortex-multiagent"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
description = "Multi-agent memory sharing, namespace isolation, provenance, trust, and delta sync"

[dependencies]
cortex-core = { workspace = true }
cortex-crdt = { workspace = true }
cortex-storage = { workspace = true }
chrono = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
tokio = { workspace = true }
uuid = { workspace = true }
dashmap = { workspace = true }
thiserror = { workspace = true }
tracing = { workspace = true }
rusqlite = { workspace = true }

[dev-dependencies]
proptest = { workspace = true }
test-fixtures = { workspace = true }
tokio = { workspace = true, features = ["test-util"] }
tempfile = "3"
```

**Workspace registration**: Add `"cortex-multiagent"` to `[workspace.members]` and `cortex-multiagent = { path = "cortex-multiagent" }` to `[workspace.dependencies]` in `crates/cortex/Cargo.toml`.

### Phase B — cortex-multiagent Source Files (Phase B subset)

```
crates/cortex/cortex-multiagent/
├── Cargo.toml
├── src/
│   ├── lib.rs                              # Module declarations + re-exports
│   ├── engine.rs                           # MultiAgentEngine struct (Phase B: partial impl)
│   ├── registry/
│   │   ├── mod.rs                          # Module declarations + re-exports
│   │   ├── agent_registry.rs              # AgentRegistry — agent lifecycle management
│   │   └── spawn.rs                        # Spawned agent creation + deregistration
│   ├── namespace/
│   │   ├── mod.rs                          # Module declarations + re-exports
│   │   ├── manager.rs                      # NamespaceManager — CRUD + defaults
│   │   ├── permissions.rs                  # NamespacePermissionManager — ACL management
│   │   └── addressing.rs                   # NamespaceId parsing + formatting utilities
│   ├── projection/
│   │   ├── mod.rs                          # Module declarations + re-exports
│   │   ├── engine.rs                       # ProjectionEngine — projection CRUD + filter evaluation
│   │   ├── subscription.rs                 # SubscriptionManager — live projection subscriptions
│   │   ├── backpressure.rs                 # BackpressureController — sync mode transitions
│   │   └── compression.rs                  # Projection compression (delegates to cortex-compression)
│   └── share/
│       ├── mod.rs                          # Module declarations + re-exports
│       └── actions.rs                      # share(), promote(), retract() operations
```

### Phase B — Module Specifications

#### `src/lib.rs`

Crate root. Module declarations for all submodules (registry, namespace, projection, share, provenance, trust, sync, consolidation, validation). Re-exports the public API. Phase B exposes registry, namespace, projection, share. Other modules are declared but empty until their respective phases.

#### `src/engine.rs` — MultiAgentEngine

The central orchestrator. Implements `IMultiAgentEngine` trait. Holds references to WriteConnection and ReadPool per the existing CR5 pattern.

```
MultiAgentEngine:
    writer: Arc<WriteConnection>
    readers: Arc<ReadPool>
    config: MultiAgentConfig
```

Phase B implements: register_agent, deregister_agent, get_agent, list_agents, create_namespace, check_permission, share_memory, create_projection. Other trait methods return `Err(CortexError::MultiAgentError(MultiAgentError::SyncFailed("not yet implemented")))` until their respective phases.

#### `src/registry/agent_registry.rs` — AgentRegistry (MA-R6)

```
AgentRegistry:
    fn register(&self, writer, name, capabilities) -> CortexResult<AgentRegistration>
        -- generate AgentId, create agent namespace, insert into agent_registry table
        -- grant Admin permission on agent namespace to new agent
    fn deregister(&self, writer, agent_id) -> CortexResult<()>
        -- set status = 'deregistered', archive agent namespace
        -- preserve provenance records permanently
    fn get_agent(&self, reader, agent_id) -> CortexResult<Option<AgentRegistration>>
    fn list_agents(&self, reader, filter: Option<AgentStatus>) -> CortexResult<Vec<AgentRegistration>>
    fn update_last_active(&self, writer, agent_id) -> CortexResult<()>
        -- heartbeat: update last_active timestamp
    fn mark_idle(&self, writer, agent_id) -> CortexResult<()>
        -- status transition: Active → Idle
```

#### `src/registry/spawn.rs` — Spawned Agent Management (MA-R6)

```
fn spawn_agent(writer, reader, config: SpawnConfig) -> CortexResult<AgentRegistration>
    -- register sub-agent with parent_agent reference
    -- optionally create projection from parent namespace to sub-agent
    -- inherit parent trust scores × trust_discount (default 0.8)
    -- if ttl is set, schedule auto-deregister

fn deregister_spawned(writer, reader, agent_id, auto_promote: bool) -> CortexResult<()>
    -- if auto_promote: move sub-agent memories to parent namespace
    -- deregister the sub-agent
```

#### `src/namespace/manager.rs` — NamespaceManager (MA-R2)

```
NamespaceManager:
    fn create_namespace(&self, writer, scope, owner) -> CortexResult<NamespaceId>
        -- validate scope, generate namespace_id URI, insert into memory_namespaces
        -- grant default permissions based on scope:
        --   Agent: owner gets all permissions
        --   Team: all members get Read + Write, creator gets Admin
        --   Project: all agents get Read, explicit grant for Write
    fn get_namespace(&self, reader, id) -> CortexResult<Option<NamespaceMetadata>>
    fn list_namespaces(&self, reader, scope_filter) -> CortexResult<Vec<NamespaceMetadata>>
    fn delete_namespace(&self, writer, id) -> CortexResult<()>
        -- only if empty; otherwise archive
```

#### `src/namespace/permissions.rs` — NamespacePermissionManager (MA-R2)

```
NamespacePermissionManager:
    fn grant(&self, writer, namespace_id, agent_id, permissions, granted_by) -> CortexResult<()>
    fn revoke(&self, writer, namespace_id, agent_id, permissions) -> CortexResult<()>
    fn check(&self, reader, namespace_id, agent_id, permission) -> CortexResult<bool>
        -- returns true if agent has the specified permission on namespace
    fn get_acl(&self, reader, namespace_id) -> CortexResult<NamespaceACL>
```

**Default permission logic**:
- Agent namespace: owner has all (Read, Write, Share, Admin), others have none
- Team namespace: all team members have Read + Write, creator has Admin
- Project namespace: all agents have Read, Write requires explicit grant

#### `src/namespace/addressing.rs` — NamespaceId Utilities (MA-R2, MA-R13)

```
fn parse(uri: &str) -> CortexResult<NamespaceId>
    -- parse "agent://code-reviewer-1/", "team://backend-squad/", "project://my-app/"
    -- case-insensitive scope prefix, case-preserving name
fn to_uri(namespace: &NamespaceId) -> String
fn is_agent(namespace: &NamespaceId) -> bool
fn is_team(namespace: &NamespaceId) -> bool
fn is_project(namespace: &NamespaceId) -> bool
fn is_shared(namespace: &NamespaceId) -> bool
fn default_namespace() -> NamespaceId
    -- agent://default/
```

#### `src/projection/engine.rs` — ProjectionEngine (MA-R3)

```
ProjectionEngine:
    fn create_projection(&self, writer, projection: MemoryProjection) -> CortexResult<String>
        -- validate source/target namespaces exist
        -- validate creator has Share permission on source
        -- insert into memory_projections table
    fn delete_projection(&self, writer, id) -> CortexResult<()>
    fn get_projection(&self, reader, id) -> CortexResult<Option<MemoryProjection>>
    fn list_projections(&self, reader, namespace) -> CortexResult<Vec<MemoryProjection>>
    fn evaluate_filter(&self, memory: &BaseMemory, filter: &ProjectionFilter) -> bool
        -- check memory_types, min_confidence, min_importance, tags, linked_files, max_age_days
        -- all conditions are AND (all must match)
```

#### `src/projection/subscription.rs` — SubscriptionManager (MA-R3)

```
SubscriptionManager:
    fn subscribe(&self, projection_id) -> CortexResult<SubscriptionState>
        -- create subscription with Streaming mode, empty delta queue
    fn unsubscribe(&self, projection_id) -> CortexResult<()>
    fn push_delta(&self, projection_id, delta: MemoryDelta) -> CortexResult<()>
        -- evaluate filter against delta's memory
        -- if matches: compress to projection level, enqueue
        -- if queue full: trigger backpressure mode transition
    fn drain_queue(&self, projection_id) -> CortexResult<Vec<MemoryDelta>>
        -- return all pending deltas, clear queue
```

#### `src/projection/backpressure.rs` — BackpressureController (MA-R3)

```
SubscriptionState:
    projection_id: String
    delta_queue: Vec<MemoryDelta>           -- bounded by config.delta_queue_max_size
    last_sync: DateTime<Utc>
    mode: SyncMode
    queue_high_watermark: usize

SyncMode:
    Streaming                               -- normal: deltas flow as they happen
    Batched { interval: Duration }          -- backpressure: periodic batch sync
    CatchUp                                 -- recovering: full state transfer in progress

BackpressureController:
    fn check_backpressure(state: &SubscriptionState) -> SyncMode
        -- queue > 80% capacity → Batched
        -- catch-up requested → CatchUp
        -- queue < 50% capacity → Streaming (recover)
```

#### `src/projection/compression.rs` — Projection Compression (MA-R3)

```
fn compress_for_projection(memory: &BaseMemory, level: u8) -> BaseMemory
    -- delegates to cortex-compression's existing L0-L3 system
    -- L0: full memory (no compression)
    -- L1: summary + metadata only (~20 tokens)
    -- L2: summary + key examples (~100 tokens)
    -- L3: one-line essence (~10 tokens)
```

#### `src/share/actions.rs` — Share/Promote/Retract (MA-R2, MA-R3)

```
fn share(writer, reader, memory_id, target_namespace, agent_id) -> CortexResult<()>
    -- check agent has Read on source namespace + Write on target namespace
    -- copy memory to target namespace with provenance hop (SharedTo)
    -- one-time copy, no further updates

fn promote(writer, reader, memory_id, target_namespace, agent_id) -> CortexResult<()>
    -- check agent has Share on source namespace + Write on target namespace
    -- move memory from agent → team/project namespace
    -- update namespace field on memory
    -- record provenance hop

fn retract(writer, reader, memory_id, namespace, agent_id) -> CortexResult<()>
    -- check agent has Write on namespace
    -- tombstone memory in target namespace via OR-Set semantics
    -- record provenance hop
```

### Phase B — Quality Gate (QG-MA1)

**Prerequisite**: Phase A QG-MA0 passed with ≥ 80% coverage on all Phase A modules.

| Test | Pass Criteria | Coverage Target |
|------|---------------|-----------------|
| Agent registration creates agent + namespace | Register → agent exists, namespace exists | registry/agent_registry.rs ≥ 80% |
| Agent deregistration archives namespace | Deregister → status = deregistered, namespace archived | registry/agent_registry.rs ≥ 80% |
| Agent lifecycle transitions | Active → Idle → Deregistered (valid); Deregistered → Active (invalid) | registry/agent_registry.rs ≥ 80% |
| Spawned agent creation with parent | Spawn → parent reference set, projection created | registry/spawn.rs ≥ 80% |
| Spawned agent deregister with promotion | Deregister spawned → memories promoted to parent | registry/spawn.rs ≥ 80% |
| Namespace creation for all 3 scopes | Create agent/team/project → all exist with correct scope | namespace/manager.rs ≥ 80% |
| Permission grant/revoke/check | Grant Read → check returns true; revoke → check returns false | namespace/permissions.rs ≥ 80% |
| Default permissions per scope | Agent: owner=all; Team: members=Read+Write; Project: all=Read | namespace/permissions.rs ≥ 80% |
| NamespaceId parse + format round-trip | parse(to_uri(ns)) == ns for all scopes | namespace/addressing.rs ≥ 80% |
| Default namespace backward compat | default_namespace() == agent://default/ | namespace/addressing.rs ≥ 80% |
| Projection creation with filter | Create projection → exists with correct filter | projection/engine.rs ≥ 80% |
| Filter evaluation: matching memory | Memory matches all filter criteria → true | projection/engine.rs ≥ 80% |
| Filter evaluation: non-matching memory | Memory fails one criterion → false | projection/engine.rs ≥ 80% |
| Live projection subscription + delta push | Subscribe → push delta → drain returns delta | projection/subscription.rs ≥ 80% |
| Backpressure mode transition | Queue > 80% → Batched; < 50% → Streaming | projection/backpressure.rs ≥ 80% |
| Projection compression L0-L3 | Compress at each level → correct content reduction | projection/compression.rs ≥ 80% |
| Share copies memory with provenance | Share → memory in target namespace, provenance hop recorded | share/actions.rs ≥ 80% |
| Promote moves memory | Promote → memory namespace changed, provenance recorded | share/actions.rs ≥ 80% |
| Retract tombstones memory | Retract → memory not visible in target namespace | share/actions.rs ≥ 80% |
| Permission denied on unauthorized share | Agent without Share permission → error | share/actions.rs ≥ 80% |
| Migration v015 runs cleanly | Fresh DB → run all migrations → v015 tables exist | Migration test |
| Namespace-aware memory queries | Create memories in different namespaces → filter by namespace → correct results | memory_crud.rs changes ≥ 80% |
| No existing test regressions | `cargo test --workspace` passes | Workspace-wide |

---

## Phase C: Delta Sync + Trust + Provenance (~25 new files, ~5 modified)

Phase C builds the three most critical multi-agent subsystems: delta sync (how agents exchange state), trust scoring (how agents evaluate each other), and provenance tracking (how knowledge lineage is recorded). Depends on Phase B's storage layer and namespace system.

### Phase C — cortex-multiagent New Files

```
crates/cortex/cortex-multiagent/src/
├── provenance/
│   ├── mod.rs                              # Module declarations + re-exports
│   ├── tracker.rs                          # ProvenanceTracker — record + query provenance chains
│   ├── correction.rs                       # CorrectionPropagator — dampened correction propagation
│   └── cross_agent.rs                      # CrossAgentTracer — trace knowledge across agent boundaries
├── trust/
│   ├── mod.rs                              # Module declarations + re-exports
│   ├── scorer.rs                           # TrustScorer — compute + manage trust scores
│   ├── evidence.rs                         # TrustEvidenceTracker — accumulate trust evidence
│   ├── decay.rs                            # Trust decay toward neutral
│   └── bootstrap.rs                        # Trust bootstrap for new + spawned agents
└── sync/
    ├── mod.rs                              # Module declarations + re-exports
    ├── protocol.rs                         # DeltaSyncEngine — sync protocol orchestration
    ├── delta_queue.rs                      # DeltaQueue — persistent queue for pending deltas
    ├── causal_delivery.rs                  # CausalDeliveryManager — causal ordering enforcement
    └── cloud_integration.rs               # CloudSyncAdapter — bridge to cortex-cloud transport
```

### Phase C — Module Specifications

#### `src/provenance/tracker.rs` — ProvenanceTracker (MA-R4)

Records and queries provenance chains. Every cross-agent interaction appends a hop.

```
ProvenanceTracker:
    fn record_hop(&self, writer, memory_id, hop: ProvenanceHop) -> CortexResult<()>
        -- append to provenance_log table
        -- hop_index = current chain length
    fn get_provenance(&self, reader, memory_id) -> CortexResult<Option<ProvenanceRecord>>
        -- query provenance_log, assemble ProvenanceRecord
    fn get_chain(&self, reader, memory_id) -> CortexResult<Vec<ProvenanceHop>>
        -- full chain ordered by hop_index
    fn get_origin(&self, reader, memory_id) -> CortexResult<ProvenanceOrigin>
        -- first hop determines origin type
    fn chain_confidence(&self, reader, memory_id) -> CortexResult<f64>
        -- product of (1.0 + confidence_delta) for each hop
        -- clamped to [0.0, 1.0]
```

#### `src/provenance/correction.rs` — CorrectionPropagator (MA-R4)

Propagates corrections through provenance chains with exponential dampening.

```
CorrectionPropagator:
    config: MultiAgentConfig

    fn propagate_correction(&self, writer, reader, memory_id, correction: String) -> CortexResult<Vec<CorrectionResult>>
        -- trace provenance chain from memory_id
        -- for each hop at distance d:
        --   strength = config.correction_dampening_factor ^ d  (default: 0.7^d)
        --   if strength < config.correction_min_threshold (default: 0.05): stop
        --   apply correction with dampened strength
        --   record CorrectedBy provenance hop
        -- return list of affected memories with applied strengths

CorrectionResult:
    memory_id: String
    hop_distance: usize
    correction_strength: f64
    applied: bool                           -- false if strength below threshold

    fn correction_strength(hop_distance: usize, dampening: f64) -> f64
        -- dampening ^ hop_distance
        -- 0.7^0 = 1.0, 0.7^1 = 0.7, 0.7^2 = 0.49, 0.7^3 = 0.343, 0.7^4 = 0.24, 0.7^5 = 0.168
        -- at hop 5+, strength is below 0.2 — corrections are logged but not auto-applied
```

**Dampening rationale**: A correction at the source should have full effect. One hop away, 70% effect. Two hops, 49%. This prevents a single correction from cascading through the entire knowledge graph while still propagating important corrections to nearby dependents. The threshold (default 0.05) ensures propagation terminates.

#### `src/provenance/cross_agent.rs` — CrossAgentTracer (MA-R4)

Traces knowledge across agent boundaries, extending cortex-causal's traversal.

```
CrossAgentTracer:
    fn trace_cross_agent(&self, reader, memory_id, max_depth: usize) -> CortexResult<CrossAgentTrace>
        -- follow provenance chain across agent boundaries
        -- for each hop that crosses an agent boundary:
        --   record the agent transition
        --   accumulate confidence chain

CrossAgentTrace:
    memory_id: String
    agents_involved: Vec<AgentId>           -- ordered by first involvement
    hop_count: usize
    confidence_chain: Vec<f64>              -- confidence at each hop
    total_confidence: f64                   -- product of chain
```

#### `src/trust/scorer.rs` — TrustScorer (MA-R5)

Computes and manages agent trust scores.

```
TrustScorer:
    config: MultiAgentConfig

    fn get_trust(&self, reader, agent_id, target_agent) -> CortexResult<AgentTrust>
        -- query agent_trust table
    fn compute_overall_trust(&self, evidence: &TrustEvidence) -> f64
        -- (validated + useful) / (total_received + 1) × (1 - contradicted / (total_received + 1))
        -- clamped to [0.0, 1.0]
    fn compute_domain_trust(&self, domain: &str, evidence: &TrustEvidence) -> f64
        -- per-domain variant of overall_trust formula
    fn effective_confidence(&self, memory_confidence: f64, trust_score: f64) -> f64
        -- memory_confidence × domain_trust
        -- if Agent A has auth trust 0.9 and shares memory with confidence 0.85:
        --   effective = 0.85 × 0.9 = 0.765
    fn update_trust(&self, writer, agent_id, target_agent, trust: &AgentTrust) -> CortexResult<()>
```

**Trust calculation deep dive**:

The formula `(validated + useful) / (total + 1) × (1 - contradicted / (total + 1))` has two components:
1. **Positive signal**: What fraction of received memories were validated or useful?
2. **Negative signal**: What fraction were contradicted?

The multiplication means contradictions have outsized impact. An agent with 10 validated, 2 contradicted, 3 useful, 20 total:
- Positive: (10 + 3) / 21 = 0.619
- Negative: 1 - 2/21 = 0.905
- Overall: 0.619 × 0.905 = 0.560

The asymmetric penalty (contradictions hurt 2× more than validations help) creates a conservative trust model — appropriate for a code-aware system where bad knowledge can cause bugs.

#### `src/trust/evidence.rs` — TrustEvidenceTracker (MA-R5)

Accumulates trust evidence from cross-agent interactions.

```
TrustEvidenceTracker:
    fn record_validation(&self, writer, agent_id, target_agent, memory_id) -> CortexResult<()>
        -- increment validated_count in agent_trust table
    fn record_contradiction(&self, writer, agent_id, target_agent, memory_id) -> CortexResult<()>
        -- increment contradicted_count
    fn record_usage(&self, writer, agent_id, target_agent, memory_id) -> CortexResult<()>
        -- increment useful_count
    fn get_evidence(&self, reader, agent_id, target_agent) -> CortexResult<TrustEvidence>
```

#### `src/trust/decay.rs` — Trust Decay (MA-R5)

```
fn apply_trust_decay(trust: &mut AgentTrust, days_since_evidence: f64, decay_rate: f64)
    -- trust.overall_trust += (0.5 - trust.overall_trust) × (1 - decay_rate^days)
    -- default decay_rate = 0.99
    -- after 100 days: drifts ~63% toward 0.5 (neutral)
    -- after 200 days: drifts ~86% toward 0.5
    -- prevents stale trust scores from permanently biasing agent interactions
```

**Why decay toward 0.5 (not 0.0)**: Zero trust means "actively distrusted." Neutral (0.5) means "no opinion." An agent that hasn't interacted in months should be treated as unknown, not hostile.

#### `src/trust/bootstrap.rs` — Trust Bootstrap (MA-R5, MA-R6)

```
fn bootstrap_trust(agent_id, target_agent) -> AgentTrust
    -- new agents start at overall_trust = config.trust_bootstrap_score (default 0.5)
    -- empty domain_trust, empty evidence

fn bootstrap_from_parent(parent_trust: &AgentTrust, discount: f64) -> AgentTrust
    -- spawned agents inherit parent trust × discount (default 0.8)
    -- overall_trust = parent.overall_trust × discount
    -- domain_trust = parent.domain_trust.map(|v| v × discount)
    -- evidence starts empty (spawned agent must earn its own)
```

#### `src/sync/protocol.rs` — DeltaSyncEngine (MA-R7)

The wire protocol for multi-agent convergence. Agents exchange deltas based on vector clock comparison.

```
DeltaSyncEngine:
    fn initiate_sync(&self, writer, reader, source_agent, target_agent) -> CortexResult<SyncResponse>
        -- 1. Get local vector clock for source_agent
        -- 2. Send SyncRequest { my_clock } to target
        -- 3. Receive SyncResponse { deltas, their_clock }
        -- 4. Apply received deltas via MergeEngine (causal ordering enforced)
        -- 5. Send SyncAck { new_clock }

    fn handle_sync_request(&self, reader, request: SyncRequest) -> CortexResult<SyncResponse>
        -- compute deltas since requester's clock
        -- return deltas + own clock

    fn acknowledge_sync(&self, writer, ack: SyncAck) -> CortexResult<()>
        -- update peer clock state

SyncRequest:
    source_agent: AgentId
    clock: VectorClock

SyncResponse:
    deltas: Vec<MemoryDelta>
    clock: VectorClock

SyncAck:
    agent_id: AgentId
    clock: VectorClock

SyncResult:
    deltas_sent: usize
    deltas_received: usize
    deltas_applied: usize
    deltas_buffered: usize                  -- couldn't apply yet (causal ordering)
```

**Sync protocol flow**:
```
Agent A                              Agent B
   |                                    |
   |-- SyncRequest { my_clock } ------->|
   |                                    |
   |<-- SyncResponse { deltas,          |
   |       their_clock }                |
   |                                    |
   |-- apply deltas, update clock       |
   |                                    |
   |-- SyncAck { new_clock } ---------->|
   |                                    |
```

#### `src/sync/delta_queue.rs` — DeltaQueue (MA-R7)

Persistent queue backed by the `delta_queue` SQLite table.

```
DeltaQueue:
    fn enqueue(&self, writer, delta: MemoryDelta, target_agent: &AgentId) -> CortexResult<()>
        -- insert into delta_queue table
    fn dequeue(&self, reader, target_agent: &AgentId, limit: usize) -> CortexResult<Vec<MemoryDelta>>
        -- select unapplied deltas for target, ordered by created_at, limited
    fn mark_applied(&self, writer, delta_ids: &[u64]) -> CortexResult<()>
        -- set applied = 1, applied_at = now()
    fn pending_count(&self, reader, target_agent: &AgentId) -> CortexResult<usize>
    fn purge_applied(&self, writer, older_than: DateTime<Utc>) -> CortexResult<u64>
        -- delete applied deltas older than threshold
```

#### `src/sync/causal_delivery.rs` — CausalDeliveryManager (MA-R7)

Ensures deltas are applied in causal order. Out-of-order deltas are buffered.

```
CausalDeliveryManager:
    buffer: Vec<MemoryDelta>                -- deltas waiting for causal predecessors

    fn can_apply(&self, delta: &MemoryDelta, local_clock: &VectorClock) -> bool
        -- for source agent's clock entry: must be exactly local + 1
        -- for all other agents' entries: must be <= local
        -- this ensures all causal predecessors have been applied

    fn buffer_delta(&mut self, delta: MemoryDelta)
        -- store for later if can't apply yet

    fn drain_applicable(&mut self, local_clock: &VectorClock) -> Vec<MemoryDelta>
        -- return all buffered deltas that can now be applied
        -- remove them from buffer
        -- may return multiple deltas if applying one unblocks others
```

**Causal delivery guarantee**: A delta from Agent A with clock {A:5, B:3} can only be applied if the local clock has A ≥ 4 (all previous A deltas applied) and B ≥ 3 (all B deltas that A depended on are applied). This prevents applying a delta that references state the local replica hasn't seen yet.

#### `src/sync/cloud_integration.rs` — CloudSyncAdapter (MA-R7)

Bridges delta sync with cortex-cloud's existing transport layer.

```
CloudSyncAdapter:
    fn sync_via_cloud(&self, source_agent, target_agent) -> CortexResult<()>
        -- use cortex-cloud HTTP transport for remote agents
    fn sync_via_local(&self, source_agent, target_agent) -> CortexResult<()>
        -- use SQLite delta_queue for local agents (same process)
    fn detect_sync_mode(&self, target_agent) -> SyncTransport
        -- Local: target agent is in same Cortex instance
        -- Cloud: target agent is remote (different instance)

SyncTransport:
    Local                                   -- SQLite delta_queue
    Cloud                                   -- cortex-cloud HTTP transport
```

### Phase C — Quality Gate (QG-MA2)

**Prerequisite**: Phase B QG-MA1 passed with ≥ 80% coverage on all Phase B modules.

| Test | Pass Criteria | Coverage Target |
|------|---------------|-----------------|
| Provenance hop recording | Record hop → chain contains hop | provenance/tracker.rs ≥ 80% |
| Provenance chain retrieval | Record 3 hops → get_chain returns all 3 in order | provenance/tracker.rs ≥ 80% |
| Chain confidence computation | Known hops → chain_confidence matches expected | provenance/tracker.rs ≥ 80% |
| Correction propagation with dampening | Correct at depth 0 → depth 1 gets 0.7, depth 2 gets 0.49 | provenance/correction.rs ≥ 80% |
| Correction stops at threshold | Correction at depth 5+ → strength < 0.05 → not applied | provenance/correction.rs ≥ 80% |
| Cross-agent trace across 3 agents | Memory shared A→B→C → trace shows all 3 agents | provenance/cross_agent.rs ≥ 80% |
| Trust bootstrap at 0.5 | New agent → overall_trust = 0.5 | trust/bootstrap.rs ≥ 80% |
| Trust increase from validation | Record validation → trust increases by ~0.05 | trust/scorer.rs ≥ 80% |
| Trust decrease from contradiction | Record contradiction → trust decreases by ~0.10 | trust/scorer.rs ≥ 80% |
| Domain-specific trust | Auth validation → auth domain trust increases | trust/scorer.rs ≥ 80% |
| Effective confidence modulation | Memory confidence 0.85, trust 0.9 → effective 0.765 | trust/scorer.rs ≥ 80% |
| Trust decay toward neutral | 100 days no evidence → trust drifts ~63% toward 0.5 | trust/decay.rs ≥ 80% |
| Spawned agent trust inheritance | Parent trust 0.8, discount 0.8 → spawned trust 0.64 | trust/bootstrap.rs ≥ 80% |
| Delta sync protocol round-trip | Request → response → ack → both agents converged | sync/protocol.rs ≥ 80% |
| Causal delivery: in-order | Deltas in causal order → all applied immediately | sync/causal_delivery.rs ≥ 80% |
| Causal delivery: out-of-order buffered | Delta with missing predecessor → buffered, not applied | sync/causal_delivery.rs ≥ 80% |
| Causal delivery: drain after unblock | Apply missing predecessor → buffered delta now applicable | sync/causal_delivery.rs ≥ 80% |
| Delta queue: enqueue + dequeue | Enqueue 10 deltas → dequeue returns all 10 | sync/delta_queue.rs ≥ 80% |
| Delta queue: mark_applied | Mark applied → not returned by dequeue | sync/delta_queue.rs ≥ 80% |
| Cloud vs local sync detection | Local agent → Local; remote → Cloud | sync/cloud_integration.rs ≥ 80% |
| No existing test regressions | `cargo test --workspace` passes | Workspace-wide |

**Property-based tests** (proptest, Phase C):
1. **Trust bounds**: For any evidence values, `0.0 ≤ overall_trust ≤ 1.0`
2. **Trust decay monotonicity**: Trust always moves toward 0.5, never away
3. **Causal delivery correctness**: For any delta sequence, causal delivery produces the same final state regardless of arrival order
4. **Delta sync convergence**: After sync, both agents have identical materialized state for all shared memories
5. **Correction dampening**: correction_strength is monotonically decreasing with hop distance

---

## Phase D: Cross-Crate Integration + NAPI + TypeScript (~15 new files, ~12 modified)

Phase D is the integration phase. It wires multi-agent capabilities into 7 existing crates, adds NAPI bindings for TypeScript, creates 5 MCP tools, and adds 3 CLI commands. Phase D is subdivided into 3 sub-phases:

- D1: Cross-crate integration (consolidation, validation, retrieval, causal, cloud, session)
- D2: NAPI bindings + TypeScript bridge
- D3: MCP tools + CLI commands

### Phase D1: Cross-Crate Integration

#### `cortex-multiagent/src/consolidation/` — Cross-Namespace Consolidation (MA-R8)

**New files**:
```
src/consolidation/
├── mod.rs
├── consensus.rs                        # ConsensusDetector — find independently corroborated knowledge
└── cross_namespace.rs                  # CrossNamespaceConsolidator — extend consolidation pipeline
```

##### `src/consolidation/consensus.rs` — ConsensusDetector

```
ConsensusDetector:
    config: MultiAgentConfig

    fn detect_consensus(&self, reader, memories_by_namespace, embedding_engine, threshold) -> Vec<ConsensusCandidate>
        -- cross-namespace embedding similarity search
        -- group by similarity cluster (threshold default: 0.9)
        -- filter: agent_count >= config.consensus_min_agents (default: 2)
        -- compute confidence_boost = config.consensus_confidence_boost (default: 0.2)

ConsensusCandidate:
    memories: Vec<(AgentId, String)>        -- (agent, memory_id) pairs
    similarity: f64
    agent_count: usize
    confidence_boost: f64
```

**Consensus semantics**: When 2+ agents independently learn the same thing (embedding similarity > 0.9), that's strong evidence. The confidence boost (+0.2) matches the existing contradiction/consensus system in cortex-validation.

##### `src/consolidation/cross_namespace.rs` — CrossNamespaceConsolidator

Extends cortex-consolidation's existing HDBSCAN pipeline:

```
CrossNamespaceConsolidator:
    fn consolidate_cross_namespace(&self, writer, reader) -> CortexResult<ConsolidationResult>
        -- Phase 0 (new): gather candidates from all team/project namespaces
        -- Phase 1-3: delegate to existing cortex-consolidation HDBSCAN pipeline
        -- Phase 4 (extended): apply consensus boost for multi-agent clusters
        -- Phase 5: existing pruning with cross-namespace provenance preservation
        -- consolidated memory placed in team/project namespace
```

#### `cortex-multiagent/src/validation/` — Cross-Agent Validation (MA-R9)

**New files**:
```
src/validation/
├── mod.rs
└── cross_agent.rs                      # CrossAgentValidator — cross-agent contradiction detection
```

##### `src/validation/cross_agent.rs` — CrossAgentValidator

```
CrossAgentValidator:
    config: MultiAgentConfig

    fn detect_contradictions(&self, reader, namespace) -> CortexResult<Vec<CrossAgentContradiction>>
        -- for each memory in shared namespace:
        --   check against memories in other agent namespaces projected to same target
        --   use embedding similarity + semantic analysis (existing validation dimensions)
        --   flag contradictions with both agents' trust scores

    fn resolve_contradiction(&self, contradiction: &CrossAgentContradiction) -> CortexResult<ContradictionResolution>
        -- trust_diff = |trust_a - trust_b|
        -- if trust_diff > config.contradiction_trust_auto_resolve_threshold (default: 0.3):
        --   TrustWins { winner: higher-trust agent }
        -- elif both memories have different scope tags:
        --   ContextDependent { context_a, context_b }
        -- elif one memory is significantly newer AND from validated source:
        --   TemporalSupersession { newer }
        -- else:
        --   NeedsHumanReview
```

**Resolution strategy rationale**:
- Trust difference > 0.3: The higher-trust agent has demonstrated significantly more reliability. Auto-resolve is safe.
- Trust difference ≤ 0.3: Both agents are similarly trusted. Human judgment needed.
- Context-dependent: Both memories are valid in different scopes (e.g., "use bcrypt for auth" vs "use argon2 for auth" — one for legacy, one for new code).
- Temporal supersession: Newer knowledge from a validated source supersedes older knowledge.

#### Modifications to Existing Crates (Phase D1)

**cortex-causal** (MA-R4, MA-R12):
- `src/relations.rs` — add `CrossAgent(CrossAgentRelation)` variant to `CausalRelation` enum
- `src/graph/sync.rs` — extend `CausalEdge` with optional `source_agent: Option<AgentId>` field
- `src/graph/cross_agent.rs` (new) — `trace_cross_agent()` follows provenance across agent boundaries; `cross_agent_narrative()` generates narrative for cross-agent causal chains
- `src/graph/mod.rs` — add `pub mod cross_agent;`

**cortex-consolidation** (MA-R8, MA-R12):
- `src/engine.rs` — when multi-agent enabled, extend consolidation to work across namespaces; delegate cross-namespace logic to cortex-multiagent's consolidation module
- `src/pipeline/phase6_pruning.rs` — when archiving consolidated memories, preserve cross-agent provenance; consolidated memory placed in team/project namespace

**cortex-validation** (MA-R9, MA-R12):
- `src/engine.rs` — when multi-agent enabled, extend contradiction detection across namespaces; delegate cross-agent logic to cortex-multiagent's validation module; after validation, update trust evidence for source agents

**cortex-retrieval** (MA-R5, MA-R12):
- `src/ranking/scorer.rs` — when multi-agent enabled, add trust-weighted scoring factor: `trust_score(memory, agent_trust) -> f64` modulates ranking by source trust; memories from higher-trust agents rank higher
- `src/engine.rs` — add optional `namespace_filter: Option<NamespaceId>` to retrieval queries; respect projection compression levels when retrieving projected memories

**cortex-cloud** (MA-R1, MA-R7, MA-R12):
- `src/sync/protocol.rs` — extend sync request/response to include `agent_id: AgentId` field
- `src/conflict/resolver.rs` — when multi-agent enabled, use CRDT merge instead of LWW/local-wins/remote-wins; existing strategies remain for single-agent

**cortex-session** (MA-R12):
- `src/context.rs` — add `agent_id: AgentId` field to `SessionContext` (default: `AgentId::default_agent()`)
- `src/dedup.rs` — session dedup now per-agent within namespace; key changes from `(session_id, content_hash)` to `(session_id, agent_id, namespace_id, content_hash)`

### Phase D1 — Quality Gate (QG-MA3a)

| Test | Pass Criteria | Coverage Target |
|------|---------------|-----------------|
| Consensus detection: 2 agents similar | 2 agents with similar memories → candidate found | consolidation/consensus.rs ≥ 80% |
| Consensus detection: dissimilar | Dissimilar memories → no candidate | consolidation/consensus.rs ≥ 80% |
| Cross-namespace consolidation pipeline | 3 agents, overlapping knowledge → consolidated in team namespace | consolidation/cross_namespace.rs ≥ 80% |
| Confidence boost applied | Consensus candidate → confidence boosted by 0.2 | consolidation/consensus.rs ≥ 80% |
| Cross-agent contradiction detection | Agent A says X, Agent B says not-X → contradiction detected | validation/cross_agent.rs ≥ 80% |
| Trust-weighted resolution: high diff | Trust diff > 0.3 → TrustWins | validation/cross_agent.rs ≥ 80% |
| Trust-weighted resolution: low diff | Trust diff ≤ 0.3 → NeedsHumanReview | validation/cross_agent.rs ≥ 80% |
| Context-dependent resolution | Different scope tags → ContextDependent | validation/cross_agent.rs ≥ 80% |
| Temporal supersession | Newer + validated → TemporalSupersession | validation/cross_agent.rs ≥ 80% |
| Trust-weighted retrieval scoring | Higher-trust agent's memory ranks higher | scorer.rs changes ≥ 80% |
| Namespace-aware retrieval | Search with namespace filter → only matching namespace results | engine.rs changes ≥ 80% |
| CRDT merge in cloud sync | Multi-agent cloud sync → CRDT merge used | conflict/resolver.rs changes ≥ 80% |
| Session context includes agent_id | New session → agent_id present | context.rs changes ≥ 80% |
| Cross-agent causal traversal | Traverse across agent boundary → cross-agent relation found | graph/cross_agent.rs ≥ 80% |
| No existing test regressions | `cargo test --workspace` passes | Workspace-wide |

### Phase D2: NAPI Bindings + TypeScript Bridge

#### New cortex-napi Files

```
crates/cortex/cortex-napi/src/bindings/
└── multiagent.rs                       # NAPI bindings for multi-agent operations

crates/cortex/cortex-napi/src/conversions/
└── multiagent_types.rs                 # Rust ↔ JS type conversions
```

**Modified**:
- `src/bindings/mod.rs` — add `pub mod multiagent;`
- `src/conversions/mod.rs` — add `pub mod multiagent_types;`

##### `cortex-napi/src/bindings/multiagent.rs`

12 `#[napi]` functions exposing the full multi-agent API to TypeScript:

```
#[napi] register_agent(name: String, capabilities: Option<Vec<String>>) -> NapiAgentRegistration
#[napi] deregister_agent(agent_id: String) -> ()
#[napi] get_agent(agent_id: String) -> Option<NapiAgentRegistration>
#[napi] list_agents() -> Vec<NapiAgentRegistration>
#[napi] create_namespace(scope: String, name: String, owner: Option<String>) -> String
#[napi] share_memory(memory_id: String, target_namespace: String, agent_id: String) -> ()
#[napi] create_projection(source: String, target: String, filter_json: String, compression: Option<u32>, live: Option<bool>) -> String
#[napi] retract_memory(memory_id: String, namespace: String, agent_id: String) -> ()
#[napi] get_provenance(memory_id: String) -> Option<NapiProvenanceRecord>
#[napi] trace_cross_agent(memory_id: String, max_depth: Option<u32>) -> NapiCrossAgentTrace
#[napi] get_trust(agent_id: String, target_agent: String) -> NapiAgentTrust
#[napi] sync_agents(source_agent: String, target_agent: String) -> NapiSyncResult
```

##### `cortex-napi/src/conversions/multiagent_types.rs`

NAPI-friendly versions of all multi-agent types:

- `NapiAgentRegistration` — JS-friendly AgentRegistration
- `NapiProvenanceRecord` — JS-friendly ProvenanceRecord
- `NapiProvenanceHop` — JS-friendly ProvenanceHop
- `NapiCrossAgentTrace` — JS-friendly CrossAgentTrace
- `NapiAgentTrust` — JS-friendly AgentTrust
- `NapiSyncResult` — JS-friendly SyncResult
- `NapiNamespaceACL` — JS-friendly NamespaceACL

Each has `From<RustType>` and `Into<RustType>` implementations.

#### TypeScript Bridge Modifications

**Modified**: `packages/cortex/src/bridge/types.ts`

Add TypeScript interfaces:
```typescript
interface AgentRegistration { agentId: string; name: string; namespace: string; capabilities: string[]; ... }
interface AgentStatus { type: 'active' | 'idle' | 'deregistered'; ... }
interface NamespaceId { scope: string; name: string; }
interface NamespacePermission { type: 'read' | 'write' | 'share' | 'admin'; }
interface MemoryProjection { id: string; source: string; target: string; filter: ProjectionFilter; ... }
interface ProjectionFilter { memoryTypes?: string[]; minConfidence?: number; tags?: string[]; ... }
interface ProvenanceRecord { memoryId: string; origin: ProvenanceOrigin; chain: ProvenanceHop[]; chainConfidence: number; }
interface ProvenanceHop { agentId: string; action: string; timestamp: string; confidenceDelta: number; }
interface AgentTrust { agentId: string; targetAgent: string; overallTrust: number; domainTrust: Record<string, number>; ... }
interface TrustEvidence { validatedCount: number; contradictedCount: number; usefulCount: number; totalReceived: number; }
interface CrossAgentTrace { memoryId: string; agentsInvolved: string[]; hopCount: number; totalConfidence: number; }
interface SyncResult { deltasSent: number; deltasReceived: number; deltasApplied: number; deltasBuffered: number; }
```

**Modified**: `packages/cortex/src/bridge/client.ts`

Add 12 multi-agent methods to the bridge client matching the NAPI functions.

### Phase D3: MCP Tools + CLI Commands

#### New MCP Tools (5 tools)

```
packages/cortex/src/tools/multiagent/
├── drift_agent_register.ts             # Register a new agent
├── drift_agent_share.ts                # Share memory to another namespace
├── drift_agent_project.ts              # Create a memory projection
├── drift_agent_provenance.ts           # Query provenance chain
└── drift_agent_trust.ts                # Query trust scores
```

**Modified**: `packages/cortex/src/tools/index.ts` — register all 5 new tools

##### `drift_agent_register` — Register Agent

```
Tool: drift_agent_register
Input:
    name: string                        -- human-readable agent name
    capabilities?: string[]             -- optional capability tags
Output:
    registration: AgentRegistration     -- includes agent_id and namespace
```

##### `drift_agent_share` — Share Memory

```
Tool: drift_agent_share
Input:
    memory_id: string
    target_namespace: string            -- URI: team://name/ or project://name/
    agent_id: string                    -- sharing agent
Output:
    success: boolean
    provenance_hop: ProvenanceHop       -- the recorded hop
```

##### `drift_agent_project` — Create Projection

```
Tool: drift_agent_project
Input:
    source_namespace: string
    target_namespace: string
    filter?: ProjectionFilter
    compression_level?: number          -- 0-3, default 0
    live?: boolean                      -- default false
Output:
    projection_id: string
```

##### `drift_agent_provenance` — Query Provenance

```
Tool: drift_agent_provenance
Input:
    memory_id: string
    max_depth?: number                  -- default 10
Output:
    provenance: ProvenanceRecord
    cross_agent_trace?: CrossAgentTrace -- if memory crossed agent boundaries
```

##### `drift_agent_trust` — Query Trust

```
Tool: drift_agent_trust
Input:
    agent_id: string
    target_agent?: string               -- if omitted, returns all trust scores for agent
Output:
    trust: AgentTrust | AgentTrust[]
```

#### New CLI Commands (3 commands)

```
packages/cortex/src/cli/
├── agents.ts                           # drift cortex agents
├── namespaces.ts                       # drift cortex namespaces
└── provenance.ts                       # drift cortex provenance
```

**Modified**: `packages/cortex/src/cli/index.ts` — register all 3 new commands

##### `drift cortex agents`

```
Usage: drift cortex agents [subcommand] [options]
Subcommands:
    list                                -- list all registered agents
    register <name>                     -- register a new agent
    deregister <agent-id>               -- deregister an agent
    info <agent-id>                     -- show agent details
Options:
    --status <status>                   -- filter by status (active/idle/deregistered)
    --capabilities <caps>               -- filter by capability
```

##### `drift cortex namespaces`

```
Usage: drift cortex namespaces [subcommand] [options]
Subcommands:
    list                                -- list all namespaces
    create <scope> <name>               -- create a namespace (scope: agent/team/project)
    permissions <namespace-id>          -- show permissions for a namespace
Options:
    --scope <scope>                     -- filter by scope
    --agent <agent-id>                  -- filter by agent
```

##### `drift cortex provenance`

```
Usage: drift cortex provenance <memory-id> [options]
Options:
    --depth <n>                         -- max trace depth (default: 10)
    --format <fmt>                      -- output format: text/json (default: text)
```

#### TypeScript Test Modifications

**Modified**: `packages/cortex/tests/bridge.test.ts`

Add test cases for all 12 multi-agent bridge methods. Each test verifies the NAPI round-trip.

### Phase D2+D3 — Quality Gate (QG-MA3b)

| Test | Pass Criteria | Coverage Target |
|------|---------------|-----------------|
| NAPI register_agent round-trip | TS → Rust → TS with correct shape | bindings/multiagent.rs ≥ 80% |
| NAPI share_memory round-trip | TS → Rust → TS with correct shape | bindings/multiagent.rs ≥ 80% |
| NAPI get_provenance round-trip | TS → Rust → TS with correct shape | bindings/multiagent.rs ≥ 80% |
| NAPI get_trust round-trip | TS → Rust → TS with correct shape | bindings/multiagent.rs ≥ 80% |
| NAPI sync_agents round-trip | TS → Rust → TS with correct shape | bindings/multiagent.rs ≥ 80% |
| All 12 NAPI functions compile | `cargo check -p cortex-napi` exits 0 | — |
| Type conversions lossless | Rust → NAPI → Rust round-trip preserves all fields | conversions/multiagent_types.rs ≥ 80% |
| MCP tool drift_agent_register works | Tool call → returns registration | TS integration test |
| MCP tool drift_agent_share works | Tool call → memory shared | TS integration test |
| MCP tool drift_agent_provenance works | Tool call → returns provenance | TS integration test |
| MCP tool drift_agent_trust works | Tool call → returns trust scores | TS integration test |
| CLI agents command runs | `drift cortex agents list` → output | Manual verification |
| CLI namespaces command runs | `drift cortex namespaces list` → output | Manual verification |
| CLI provenance command runs | `drift cortex provenance <id>` → output | Manual verification |
| Bridge test suite passes | `vitest run` in packages/cortex → all multi-agent tests pass | TS tests |

---

## Test Infrastructure — Golden Fixtures + Property Tests + Stress Tests + Benchmarks

### Golden Test Fixtures (10 files)

All fixtures live in `crates/cortex/test-fixtures/golden/multiagent/`. Each is a JSON file with known inputs and expected outputs, following the pattern established by `test-fixtures/golden/consolidation/` and `test-fixtures/golden/temporal/`.

**CRDT Merge Fixtures** (3):

| Fixture | Scenario | Validates |
|---------|----------|-----------|
| `crdt_merge_simple.json` | 2 agents, 1 memory, divergent tag edits, expected merged state | Basic OR-Set merge, add-wins semantics |
| `crdt_merge_conflict.json` | 2 agents, concurrent content edits (LWW), expected winner by timestamp | LWW-Register tie-breaking |
| `crdt_merge_confidence.json` | 3 agents, confidence boosts via MaxRegister, expected max value | MaxRegister convergence |

**Namespace Permission Fixtures** (2):

| Fixture | Scenario | Validates |
|---------|----------|-----------|
| `namespace_permissions.json` | Agent, team, project namespaces with various grants, expected access results | ACL enforcement |
| `namespace_default_compat.json` | Single-agent with default namespace, expected identical behavior to v1 | Backward compatibility |

**Provenance Chain Fixtures** (2):

| Fixture | Scenario | Validates |
|---------|----------|-----------|
| `provenance_chain.json` | 3-agent chain (create → share → refine), expected chain + confidence | Provenance tracking |
| `provenance_correction.json` | Correction at depth 0, expected dampened propagation at depths 1-3 | Correction dampening |

**Trust Scoring Fixtures** (2):

| Fixture | Scenario | Validates |
|---------|----------|-----------|
| `trust_scoring.json` | Agent with known evidence (5 validated, 1 contradicted, 3 useful, 10 total), expected trust values | Trust formula |
| `trust_decay.json` | Trust score after 50 days and 100 days without evidence, expected decayed values | Trust decay |

**Consensus Detection Fixture** (1):

| Fixture | Scenario | Validates |
|---------|----------|-----------|
| `consensus_detection.json` | 3 agents with similar memories about same topic, expected consensus candidate | Consensus detection |

### Test Files (10)

```
crates/cortex/cortex-crdt/tests/
├── crdt_test.rs                        # All CRDT primitive unit tests
├── memory_crdt_test.rs                 # MemoryCRDT merge + delta tests
├── dag_crdt_test.rs                    # CausalGraphCRDT tests
├── property_tests.rs                   # Entry point for proptest module
├── property/
│   ├── mod.rs
│   └── crdt_properties.rs             # All CRDT property-based tests
└── stress_test.rs                      # High-volume merge tests

crates/cortex/cortex-multiagent/tests/
├── registry_test.rs                    # Agent registration + lifecycle tests
├── namespace_test.rs                   # Namespace + permission tests
├── projection_test.rs                  # Projection + subscription tests
├── provenance_test.rs                  # Provenance chain + correction tests
├── trust_test.rs                       # Trust scoring + decay tests
├── sync_test.rs                        # Delta sync protocol tests
├── consolidation_test.rs               # Consensus + cross-namespace tests
├── validation_test.rs                  # Cross-agent contradiction tests
├── coverage_test.rs                    # Public API surface coverage
├── golden_test.rs                      # Golden fixture validation
└── stress_test.rs                      # High-volume + concurrent tests
```

### Property-Based Tests (Complete List)

All property tests use `proptest` with configurable iteration counts. Default: 256 iterations per property. CI: 1024 iterations.

| # | Property | Generator | Assertion |
|---|----------|-----------|-----------|
| 1 | GCounter commutativity | Random counters (1-20 agents, 0-1000 counts) | `merge(A,B) == merge(B,A)` |
| 2 | GCounter associativity | Random counters | `merge(A, merge(B,C)) == merge(merge(A,B), C)` |
| 3 | GCounter idempotency | Random counter | `merge(A,A) == A` |
| 4 | LWWRegister commutativity | Random registers with timestamps | `merge(A,B) == merge(B,A)` |
| 5 | LWWRegister associativity | Random registers | `merge(A, merge(B,C)) == merge(merge(A,B), C)` |
| 6 | LWWRegister idempotency | Random register | `merge(A,A) == A` |
| 7 | ORSet commutativity | Random sets (1-50 elements, 1-10 agents) | `merge(A,B) == merge(B,A)` |
| 8 | ORSet associativity | Random sets | `merge(A, merge(B,C)) == merge(merge(A,B), C)` |
| 9 | ORSet idempotency | Random set | `merge(A,A) == A` |
| 10 | ORSet add-wins | Concurrent add + remove on same element | Element is present after merge |
| 11 | ORSet size bounded | Random operations | `size ≤ unique_adds` |
| 12 | MaxRegister commutativity | Random registers | `merge(A,B) == merge(B,A)` |
| 13 | MaxRegister monotonicity | Random operations | Value never decreases |
| 14 | VectorClock causal delivery | Random delta sequences | Causal delivery never applies future deltas |
| 15 | MemoryCRDT commutativity | Random MemoryCRDTs (all field types) | `merge(A,B).to_base_memory() == merge(B,A).to_base_memory()` |
| 16 | MemoryCRDT convergence | Two divergent copies with random mutations | After sync, both have same materialized state |
| 17 | CausalGraphCRDT acyclicity | Random edge additions + merges | Graph is always acyclic after any operation |
| 18 | CausalGraphCRDT edge commutativity | Random edge additions | `merge(A,B).edges() == merge(B,A).edges()` (modulo cycle resolution) |
| 19 | Trust bounds | Random evidence values (0-10000 each) | `0.0 ≤ overall_trust ≤ 1.0` |
| 20 | Trust decay monotonicity | Random trust + random days | Trust always moves toward 0.5 |
| 21 | Correction dampening | Random hop distances (0-20) | `correction_strength` monotonically decreasing |

### Stress Tests

| Test | Scale | Target |
|------|-------|--------|
| High-volume CRDT merge | 10K memories across 5 agents, full merge | < 5s total |
| Delta computation under load | 100K field deltas | < 10s |
| DAG CRDT merge with many edges | 1K edges across 3 agents | < 1s |
| Concurrent delta application | 3 agents, 1K deltas each, concurrent apply | No deadlocks, no data corruption |
| Projection with live updates | 1K matching memories, continuous delta push | < 100ms per delta |
| Trust computation at scale | 10K evidence records | < 500ms |
| Full sync cycle | 5 agents, 10K memories, complete sync | < 30s |

### Benchmark Targets (Complete)

```
crates/cortex/cortex-crdt/benches/crdt_bench.rs
```

| Benchmark | Target | Phase |
|-----------|--------|-------|
| GCounter merge (5 agents) | < 0.01ms | A |
| LWWRegister merge | < 0.001ms | A |
| ORSet merge (100 elements) | < 0.1ms | A |
| ORSet merge (1000 elements) | < 1ms | A |
| MaxRegister merge | < 0.001ms | A |
| VectorClock merge (20 agents) | < 0.01ms | A |
| MemoryCRDT full merge | < 0.5ms | A |
| Delta computation (50 changed fields) | < 0.2ms | A |
| DAG CRDT merge (500 edges) | < 5ms | A |
| DAG CRDT cycle detection (1K edges) | < 10ms | A |
| Namespace permission check | < 0.01ms | B |
| Projection filter evaluation | < 0.05ms | B |
| Trust computation (single pair) | < 0.01ms | C |
| Delta sync (100 deltas) | < 50ms | C |
| Causal delivery check | < 0.01ms | C |
| Consensus detection (100 memories, 5 agents) | < 100ms | D |

---

## Complete File Inventory

### New Files by Crate (88 total)

#### cortex-crdt (23 files)

```
Cargo.toml
src/lib.rs
src/clock.rs
src/primitives/mod.rs
src/primitives/gcounter.rs
src/primitives/lww_register.rs
src/primitives/mv_register.rs
src/primitives/or_set.rs
src/primitives/max_register.rs
src/memory/mod.rs
src/memory/memory_crdt.rs
src/memory/field_delta.rs
src/memory/merge_engine.rs
src/graph/mod.rs
src/graph/dag_crdt.rs
tests/crdt_test.rs
tests/memory_crdt_test.rs
tests/dag_crdt_test.rs
tests/property_tests.rs
tests/property/mod.rs
tests/property/crdt_properties.rs
tests/stress_test.rs
benches/crdt_bench.rs
```

#### cortex-multiagent (35 files)

```
Cargo.toml
src/lib.rs
src/engine.rs
src/registry/mod.rs
src/registry/agent_registry.rs
src/registry/spawn.rs
src/namespace/mod.rs
src/namespace/manager.rs
src/namespace/permissions.rs
src/namespace/addressing.rs
src/projection/mod.rs
src/projection/engine.rs
src/projection/subscription.rs
src/projection/backpressure.rs
src/projection/compression.rs
src/share/mod.rs
src/share/actions.rs
src/provenance/mod.rs
src/provenance/tracker.rs
src/provenance/correction.rs
src/provenance/cross_agent.rs
src/trust/mod.rs
src/trust/scorer.rs
src/trust/evidence.rs
src/trust/decay.rs
src/trust/bootstrap.rs
src/sync/mod.rs
src/sync/protocol.rs
src/sync/delta_queue.rs
src/sync/causal_delivery.rs
src/sync/cloud_integration.rs
src/consolidation/mod.rs
src/consolidation/consensus.rs
src/consolidation/cross_namespace.rs
src/validation/mod.rs
src/validation/cross_agent.rs
tests/registry_test.rs
tests/namespace_test.rs
tests/projection_test.rs
tests/provenance_test.rs
tests/trust_test.rs
tests/sync_test.rs
tests/consolidation_test.rs
tests/validation_test.rs
tests/coverage_test.rs
tests/golden_test.rs
tests/stress_test.rs
```

Note: 35 src files + 11 test files = 46 files total for cortex-multiagent. The 35 count above is src only; tests are listed separately.

#### cortex-core (7 files)

```
src/models/agent.rs
src/models/namespace.rs
src/models/provenance.rs
src/models/cross_agent.rs
src/errors/multiagent_error.rs
src/traits/multiagent_engine.rs
src/config/multiagent_config.rs
```

#### cortex-storage (2 files)

```
src/migrations/v015_multiagent_tables.rs
src/queries/multiagent_ops.rs
```

#### cortex-causal (1 file)

```
src/graph/cross_agent.rs
```

#### cortex-napi (2 files)

```
src/bindings/multiagent.rs
src/conversions/multiagent_types.rs
```

#### test-fixtures (10 files)

```
golden/multiagent/crdt_merge_simple.json
golden/multiagent/crdt_merge_conflict.json
golden/multiagent/crdt_merge_confidence.json
golden/multiagent/namespace_permissions.json
golden/multiagent/namespace_default_compat.json
golden/multiagent/provenance_chain.json
golden/multiagent/provenance_correction.json
golden/multiagent/trust_scoring.json
golden/multiagent/trust_decay.json
golden/multiagent/consensus_detection.json
```

#### TypeScript — packages/cortex (8 files)

```
src/tools/multiagent/drift_agent_register.ts
src/tools/multiagent/drift_agent_share.ts
src/tools/multiagent/drift_agent_project.ts
src/tools/multiagent/drift_agent_provenance.ts
src/tools/multiagent/drift_agent_trust.ts
src/cli/agents.ts
src/cli/namespaces.ts
src/cli/provenance.ts
```

### Modified Files by Crate (28 total)

#### cortex-core (7 files)

```
src/models/mod.rs
src/memory/base.rs
src/memory/relationships.rs
src/errors/mod.rs
src/errors/cortex_error.rs
src/traits/mod.rs
src/config/mod.rs
```

#### cortex-storage (4 files)

```
src/migrations/mod.rs
src/queries/mod.rs
src/queries/memory_crud.rs
src/queries/memory_query.rs
```

#### cortex-causal (2 files)

```
src/graph/mod.rs
src/graph/sync.rs
```

#### cortex-consolidation (2 files)

```
src/engine.rs
src/pipeline/phase6_pruning.rs
```

#### cortex-validation (1 file)

```
src/engine.rs
```

#### cortex-retrieval (2 files)

```
src/ranking/scorer.rs
src/engine.rs
```

#### cortex-cloud (2 files)

```
src/sync/protocol.rs
src/conflict/resolver.rs
```

#### cortex-session (2 files)

```
src/context.rs
src/dedup.rs
```

#### cortex-napi (2 files)

```
src/bindings/mod.rs
src/conversions/mod.rs
```

#### Workspace (1 file)

```
Cargo.toml (workspace members + dependencies)
```

#### TypeScript — packages/cortex (4 files)

```
src/bridge/types.ts
src/bridge/client.ts
src/tools/index.ts
src/cli/index.ts
tests/bridge.test.ts
```

Note: bridge.test.ts is the 5th modified TS file.

---

## Recommendation Coverage Matrix

Every recommendation from RECOMMENDATIONS.md (MA-R1 through MA-R14) is accounted for in this spec.

| Recommendation | Phase | Key Files | Quality Gate |
|---|---|---|---|
| MA-R1 CRDT Foundation | A | primitives/*.rs, memory/*.rs, clock.rs, crdt_test.rs, crdt_properties.rs, crdt_bench.rs, memory_crdt_test.rs | QG-MA0 |
| MA-R2 Namespaces | B | namespace/*.rs, share/actions.rs, namespace.rs (model), namespace_test.rs, v015 migration, multiagent_ops.rs | QG-MA1 |
| MA-R3 Projections | B | projection/*.rs, share/actions.rs, compression.rs, projection_test.rs, namespace.rs (model) | QG-MA1 |
| MA-R4 Provenance | C | provenance/*.rs, provenance.rs (model), cross_agent.rs (model), provenance_test.rs, graph/cross_agent.rs | QG-MA2 |
| MA-R5 Trust | C | trust/*.rs, cross_agent.rs (model), trust_test.rs, scorer.rs (retrieval) | QG-MA2 |
| MA-R6 Registry | A+B | registry/*.rs, agent.rs (model), registry_test.rs, drift_agent_register.ts, agents.ts (CLI) | QG-MA0, QG-MA1 |
| MA-R7 Delta Sync | C | sync/*.rs, field_delta.rs, clock.rs, sync_test.rs, cloud_integration.rs, protocol.rs (cloud) | QG-MA2 |
| MA-R8 Consolidation | D1 | consolidation/*.rs, consolidation_test.rs, engine.rs + phase6 (cortex-consolidation) | QG-MA3a |
| MA-R9 Validation | D1 | validation/*.rs, validation_test.rs, engine.rs (cortex-validation), cross_agent.rs (model) | QG-MA3a |
| MA-R10 Storage | B | v015_multiagent_tables.rs, multiagent_ops.rs, memory_crud.rs, memory_query.rs | QG-MA1 |
| MA-R11 DAG CRDT | A | graph/*.rs, dag_crdt_test.rs, crdt_properties.rs (graph properties) | QG-MA0 |
| MA-R12 Integration | A-D | All modified files across 9 crates + NAPI + TypeScript | All gates |
| MA-R13 Backward Compat | A-D | Enforced by default namespace, opt-in activation, additive-only design | All gates |
| MA-R14 Novelty | — | Validated by gap analysis; no file changes needed (context only) | Documentation |

---

## Final Quality Gate — Full Integration (QG-MA4)

After all four phases are complete, the final integration gate validates the entire multi-agent system end-to-end.

| Test | Pass Criteria |
|------|---------------|
| Full agent lifecycle | Register → create memories → share → sync → deregister → memories preserved |
| CRDT convergence end-to-end | 3 agents, divergent edits → sync → all agents have identical state |
| Namespace isolation | Agent A's private memories invisible to Agent B without projection |
| Projection filtering | Create projection with filter → only matching memories visible to target |
| Provenance chain end-to-end | Create → share → refine → trace → full chain with correct confidence |
| Correction propagation end-to-end | Correct memory → propagation through 3-hop chain → dampened correctly |
| Trust scoring end-to-end | Share memories → validate some → contradict some → trust scores correct |
| Trust-weighted retrieval | Higher-trust agent's memory ranks above lower-trust agent's memory |
| Cross-agent contradiction detection | Two agents contradict → detected → resolved by trust |
| Consensus detection end-to-end | 3 agents independently learn same thing → consensus detected → confidence boosted |
| Delta sync with causal delivery | Out-of-order deltas → buffered → applied in correct order → convergence |
| Cloud sync with CRDT merge | Remote agents sync via cloud → CRDT merge → convergence |
| Backward compatibility | Single-agent mode → all existing tests pass unchanged |
| NAPI round-trip all 12 functions | TypeScript → Rust → TypeScript for every multi-agent function |
| MCP tools all 5 functional | Each MCP tool returns valid response |
| CLI commands all 3 functional | Each CLI command produces output |
| No workspace regressions | `cargo test --workspace` passes with zero failures |
| Coverage ≥ 80% overall | `cargo tarpaulin -p cortex-crdt -p cortex-multiagent --ignore-tests` reports ≥ 80% |
| All benchmarks meet targets | `cargo bench -p cortex-crdt` — all benchmarks within target |
| CRDT storage overhead within bounds | 10K memories, 5 agents → total CRDT overhead < 10MB |

---

## Interaction with Temporal Reasoning (Sibling Spec)

Multi-agent memory and temporal reasoning are complementary features that share infrastructure:

### Shared Infrastructure
- **Event store**: Multi-agent provenance events (SharedTo, ProjectedTo, MergedWith, etc.) are emitted to the same `memory_events` table used by temporal reasoning. This means temporal queries can reconstruct the provenance state at any past time.
- **BaseMemory fields**: Both specs add fields to BaseMemory. Temporal adds none (uses existing `transaction_time`, `valid_time`, `valid_until`). Multi-agent adds `namespace` and `source_agent`. No conflicts.
- **CortexError**: Both specs add error variants. Temporal adds `TemporalError`. Multi-agent adds `MultiAgentError`. No conflicts.
- **CortexConfig**: Both specs add config sections. Temporal adds `[temporal]`. Multi-agent adds `[multiagent]`. No conflicts.

### Migration Ordering
- Temporal: v014_temporal_tables
- Multi-agent: v015_multiagent_tables
- No cross-dependencies between migrations. Either can be applied first, but v015 is numbered after v014 by convention.

### Cross-Feature Queries
With both features active, powerful cross-feature queries become possible:
- "What did Agent A know at time T?" — temporal AS OF + namespace filter
- "When did Agent B first learn about this pattern?" — temporal event query + provenance chain
- "How has trust between Agent A and Agent B evolved?" — temporal diff on trust evidence
- "At the time this decision was made, which agents had contributed to the context?" — decision replay + provenance trace

These cross-feature queries are not implemented in either spec — they emerge naturally from the shared event store and are available to future features.

---

## Estimated Timeline

| Phase | Duration | Cumulative |
|-------|----------|------------|
| A: CRDT Foundation + Core Types | ~1.5 weeks | 1.5 weeks |
| B: Storage + Namespaces + Projections | ~1.5 weeks | 3 weeks |
| C: Delta Sync + Trust + Provenance | ~1.5 weeks | 4.5 weeks |
| D1: Cross-Crate Integration | ~3 days | 5 weeks |
| D2: NAPI Bindings + TypeScript Bridge | ~2 days | 5.5 weeks |
| D3: MCP Tools + CLI Commands | ~2 days | 6 weeks |
| QG-MA4: Final Integration | ~2 days | ~6.5 weeks |

Total: ~5-7 weeks for a senior engineer working full-time.

**Dependency on temporal reasoning**: Multi-agent can be implemented independently of temporal reasoning. The only dependency is the migration numbering (v015 after v014). If temporal reasoning is implemented first, multi-agent provenance events automatically flow into the temporal event store. If multi-agent is implemented first, provenance events are stored in the provenance_log table and can be retroactively emitted to the event store when temporal reasoning is added.
