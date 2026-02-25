# Cortex Temporal Reasoning — Unified Implementation Specification

> **Version:** 1.0.0
> **Status:** APPROVED FOR IMPLEMENTATION
> **Workspace:** `crates/cortex/cortex-temporal/` (Rust) + modifications to 9 existing crates + `packages/cortex/` (TypeScript MCP layer)
> **Last Updated:** 2026-02-07
> **Research Corpus:** 5 research documents (01-BITEMPORAL-THEORY through 05-CORTEX-MAPPING), 21 external sources (TS1-TS21), 18 recommendations (TR1-TR18), 11 cross-reference corrections (CR1-CR11), RECOMMENDATIONS.md, FILE-MAP.md
> **Supersedes:** Individual temporal research documents as implementation authority
> **Parent Spec:** CORTEX-IMPLEMENTATION-SPEC.md v2.0.0 (this spec extends, never contradicts)
> **New Files:** 91 | **Modified Files:** 31 | **Total Touched:** 122
> **New Crate:** cortex-temporal (20th Rust crate in workspace)
> **New Migration:** v014_temporal_tables
> **New MCP Tools:** 5 | **New CLI Commands:** 3

## What This Document Is

This is the single source of truth for adding temporal reasoning, knowledge time-travel, drift detection, and epistemic status tracking to Drift's Cortex memory system. An agent reading this document should be able to implement every new file, every modification to existing crates, every migration, every test — and understand why every decision was made.

This document synthesizes:
- The RECOMMENDATIONS.md (TR1-TR18 + CR1-CR11) — what to build and why
- The FILE-MAP.md (91 new + 31 modified files) — where every line of code goes
- The existing CORTEX-IMPLEMENTATION-SPEC.md — patterns, conventions, and constraints to follow
- The live codebase (19 crates, 12 migrations, 13 query modules, 12 traits, 16 models) — verified integration points

This document does NOT repeat the parent spec. It references it. If you need BaseMemory fields, memory types, the error hierarchy, or existing crate specs — read CORTEX-IMPLEMENTATION-SPEC.md.

## Why Temporal Reasoning Exists

Cortex already answers five questions (see parent spec). Temporal reasoning adds three more:

6. **"What did we know then?"** — Point-in-time reconstruction of knowledge state at any past moment
7. **"How has our understanding changed?"** — Temporal diffs, decision replay, knowledge evolution tracking
8. **"Is our knowledge healthy?"** — Drift detection, evidence freshness, epistemic status, proactive alerting

**The core insight**: Cortex already has 80% of the temporal infrastructure. BaseMemory carries `transaction_time`, `valid_time`, `valid_until`. The audit log (v006) records every mutation. The versioning system (v008) stores content snapshots. What's missing is a **projection engine** that reconstructs state at arbitrary time points, a **temporal query algebra** that makes this queryable, and a **drift detection system** that turns temporal data into actionable health signals.

**Evidence for urgency** (TS11, FPF paper): 20-25% of architectural decisions have stale evidence within 2 months. Without temporal accountability, roughly a quarter of the knowledge base silently becomes unreliable every 60 days.

## What Makes This Novel

No existing system — academic or commercial — offers this combination:

| Capability | Zep/Graphiti | T-GRAG | EverMemOS | Mem0 | XTDB | Bedrock AgentCore | **Cortex (this spec)** |
|---|---|---|---|---|---|---|---|
| Bitemporal tracking | ✓ edges only | Timestamps | ✗ | ✗ | ✓ (gold) | ✗ | **✓ memories + edges** |
| Event sourcing | ✗ | ✗ | ✗ | ✗ | ✓ | ✗ | **✓** |
| Point-in-time queries | ✗ | ✗ | ✗ | ✗ | ✓ | ✗ | **✓** |
| Temporal diff | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | **✓ (novel)** |
| Decision replay | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | **✓ (novel)** |
| Temporal causal graph | ✗ | Partial | ✗ | ✗ | ✗ | ✗ | **✓ (novel)** |
| Knowledge drift detection | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | **✓ (novel)** |
| Epistemic status tracking | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | **✓ (novel)** |
| Evidence freshness scoring | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | **✓ (novel)** |
| Code-aware temporal | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | **✓** |

---

## Research Sources (21 Verified)

| ID | Source | Year | Key Contribution |
|----|--------|------|-----------------|
| TS1 | XTDB v2 — Bitemporal SQL | 2024 | Gold standard: 4-bound temporal records, immutable transaction time |
| TS2 | XTDB Taxonomy of Bitemporal Data | 2025 | Bitemporal indexing strategies |
| TS3 | SQL:2011 Temporal Tables Standard | 2012 | ISO standard: application-time + system-versioned tables |
| TS4 | Temporal Referential Integrity Patterns | 2025 | Referential integrity across time dimensions |
| TS5 | Event Sourcing with SQLite | 2025 | SQLite as event store: append-only, WAL-friendly |
| TS6 | CQRS Snapshots & Performance | 2025 | Snapshot strategies: fixed-interval, time-based, on-demand |
| TS7 | T-GRAG — Temporal GraphRAG (Li et al.) | 2025 | Temporal query decomposition, 3-layer retrieval |
| TS8 | Zep/Graphiti — Temporal KG (Rasmussen et al.) | 2025 | 94.8% DMR accuracy, 90% latency reduction |
| TS9 | ATOM — Dual-Time TKG (Lairgi et al.) | 2025/2026 | Dual-time modeling, 18% higher exhaustivity |
| TS10 | Agent Drift — Behavioral Degradation (Rath et al.) | 2026 | Agent Stability Index, 12-dimension drift |
| TS11 | FPF — Epistemic Status & Temporal Validity (Gilda et al.) | 2026 | 20-25% stale decisions in 2 months; Gödel t-norm |
| TS12 | EverMemOS — Memory Operating System | 2025/2026 | 93.05% LoCoMo, 3-phase lifecycle |
| TS13 | MemoriesDB — Temporal-Semantic-Relational | 2025 | Unified time-semantic-relational architecture |
| TS14 | EvoReasoner — Temporal Multi-Hop Reasoning | 2025 | Global-local entity grounding |
| TS15 | Azure Event Sourcing Pattern | 2025 | Event versioning, idempotency, ordering |
| TS16 | Rust CQRS Event Upcasters | 2025 | EventUpcaster trait for schema evolution |
| TS17 | Graphiti Bi-Temporal Edge Model | 2024 | 4-field bitemporal on edges |
| TS18 | EverMemOS Cloud + SOTA Benchmarks | 2026 | Dual-layer memory, SOTA on 4 benchmarks |
| TS19 | Amazon Bedrock AgentCore Episodic Memory | 2025 | Managed episodic memory |
| TS20 | Event Sourcing Best Practices — Schema Evolution | 2025 | Versioned events, upcaster patterns |
| TS21 | CQRS Deduplication Strategies | 2019 | Idempotent projections via event_id tracking |

---

## Architecture: cortex-temporal as 20th Crate

cortex-temporal slots into the existing workspace as a peer crate. It depends on cortex-core and cortex-storage (reads/writes), and is consumed by cortex-causal (temporal graph reconstruction), cortex-observability (drift metrics in health reports), and cortex-napi (TypeScript bindings).

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
        cortex-temporal ─┤               cortex-compression
              │          │                      │
              │    cortex-causal         cortex-retrieval ←── cortex-temporal (TR13: scoring factors)
              │          │                      │
              │    cortex-validation      cortex-consolidation
              │          │                      │
              │    cortex-observability ←── cortex-temporal (TR7: drift in health reports)
              │          │
              │    cortex-napi ←── cortex-temporal (bindings)
              │
              └── packages/cortex (TypeScript MCP tools + CLI)
```

### Upstream Dependencies (cortex-temporal reads from)
- **cortex-core**: All types, traits, errors, config
- **cortex-storage**: ReadPool (temporal queries), WriteConnection (event appends, snapshots)

### Downstream Consumers (other crates read from cortex-temporal)
- **cortex-causal**: `temporal_graph.rs` calls temporal event store for graph reconstruction
- **cortex-retrieval**: Scorer uses evidence freshness + epistemic status factors (TR13)
- **cortex-validation**: Epistemic status transitions on validation pass/fail (TR11)
- **cortex-observability**: Drift summary in health reports (TR7)
- **cortex-consolidation**: Emits Consolidated events to event store (TR15)
- **cortex-decay**: Emits Decayed events to event store (TR15)
- **cortex-reclassification**: Emits Reclassified events to event store (TR15)
- **cortex-napi**: Temporal bindings module (TR15)
- **packages/cortex**: 5 MCP tools + 3 CLI commands (TR15)

### Event Emission Wiring (Existing Mutation Paths → Event Store)

Every existing mutation path that currently writes to audit_log or directly updates memories must additionally emit a MemoryEvent. This is the zero-new-event-generation strategy — we route existing mutations, not create new ones.

| Existing Source | File | Events Generated | Current Destination | Additional Destination |
|---|---|---|---|---|
| Memory CRUD | `cortex-storage/queries/memory_crud.rs` | Created, ContentUpdated, TagsModified, Archived, Restored | `memories` table | `memory_events` table |
| Audit logging | `cortex-storage/queries/audit_ops.rs` | All CRUD mutations | `memory_audit_log` table | `memory_events` table |
| Link operations | `cortex-storage/queries/link_ops.rs` | LinkAdded, LinkRemoved | `memories` table (JSON) | `memory_events` table |
| Version tracking | `cortex-storage/queries/version_ops.rs` | ContentUpdated | `memory_versions` table | `memory_events` table |
| Decay engine | `cortex-decay/src/engine.rs` | Decayed | Direct `UPDATE` | `memory_events` table |
| Validation engine | `cortex-validation/src/engine.rs` | Validated | `memory_validation_history` | `memory_events` table |
| Consolidation pipeline | `cortex-consolidation/src/engine.rs` | Consolidated | `memory_audit_log` | `memory_events` table |
| Consolidation pruning | `cortex-consolidation/pipeline/phase6_pruning.rs` | Archived | `memory_audit_log` | `memory_events` table |
| Reclassification | `cortex-reclassification/src/engine.rs` | Reclassified | `reclassification_history` | `memory_events` table |
| Causal graph sync | `cortex-causal/src/graph/sync.rs` | RelationshipAdded, RelationshipRemoved, StrengthUpdated | `causal_edges` table | `memory_events` table |

All event emissions use the single-transaction pattern (CR3): both the existing write and the event append happen in the same SQLite transaction via the WriteConnection Mutex. Both succeed or both fail. No inconsistency possible.

---

## Implementation Phases — Four Phases with Quality Gates

Each phase has an 80% test coverage requirement before the next phase begins. Coverage is measured per-module using `cargo tarpaulin` with the `--ignore-tests` flag (test code itself doesn't count toward coverage).

### Phase Overview

| Phase | Name | Recommendations | New Files | Modified Files | Duration |
|-------|------|----------------|-----------|----------------|----------|
| A | Event Store Foundation | TR1, TR2, TR14, TR15 (partial), CR2, CR3, CR4, CR5, CR10, CR11 | 32 | 12 | ~1.5 weeks |
| B | Temporal Queries | TR3, TR4, TR5, TR15 (partial) | 14 | 3 | ~1 week |
| C | Decision Replay + Temporal Causal | TR3.4, TR3.5, TR10, TR15 (partial) | 6 | 3 | ~1 week |
| D | Drift Detection + Epistemic + Views | TR6-TR9, TR11-TR13, TR15 (remaining) | 39 | 13 | ~1.5 weeks |

### Phase Gate Protocol

Before advancing from Phase N to Phase N+1:

1. **Coverage check**: `cargo tarpaulin -p cortex-temporal --ignore-tests` reports ≥ 80% line coverage for all Phase N modules
2. **All tests pass**: `cargo test -p cortex-temporal` exits 0 with zero failures
3. **Property tests pass**: `cargo test -p cortex-temporal -- property` exits 0 (proptest)
4. **No regressions**: `cargo test --workspace` exits 0 — no existing crate broken
5. **Benchmark baselines**: `cargo bench -p cortex-temporal` establishes performance baselines for Phase N features
6. **Diagnostics clean**: No compiler warnings in cortex-temporal or modified crates

### Silent Failure Detection Strategy (Temporal-Specific)

| Module | Silent Failure Risk | Detection Test |
|--------|-------------------|----------------|
| event_store/append | Event not recorded → temporal queries miss mutations | Mutate memory → query events → event must exist |
| event_store/replay | Wrong field applied → reconstructed state diverges | Replay all events → must equal current state (property test) |
| event_store/upcaster | Old schema not upcasted → deserialization fails silently | Store v1 event → read with v2 upcaster → fields correct |
| snapshot/reconstruct | Snapshot + replay diverges from full replay | snapshot_replay == full_replay (property test) |
| snapshot/triggers | Threshold never fires → snapshots never created | Insert 51 events → snapshot must exist |
| query/as_of | Bitemporal filter wrong → future memories leak into past | Create memory at T2 → AS OF T1 → must not appear |
| query/diff | Modified memories miscounted → diff stats wrong | Known fixture → diff must match expected |
| query/integrity | Dangling reference at past time → temporal anomaly | Memory A refs B (created later) → AS OF before B → ref must not resolve |
| drift/metrics | KSI computation wrong → false alerts or missed alerts | Known stable dataset → KSI must be ~1.0 |
| drift/alerting | Alert dampening too aggressive → alerts never fire | Exceed threshold → alert must fire within cooldown window |
| epistemic/transitions | Invalid promotion path → Conjecture jumps to Verified | Attempt Conjecture→Verified → must error |
| dual_time/validation | transaction_time modified → temporal integrity violated | Attempt update of transaction_time → must reject |

---

## Storage Schema — Migration v014_temporal_tables

**File**: `crates/cortex/cortex-storage/src/migrations/v014_temporal_tables.rs`
**Registered in**: `crates/cortex/cortex-storage/src/migrations/mod.rs`
**Follows**: v012_observability (v013 reserved for multi-agent)

This migration creates 5 new tables, 1 archive table, and 2 new indexes on the existing `memories` table. All tables use the same conventions as v001-v012: TEXT for ISO 8601 dates, TEXT for JSON blobs, INTEGER PRIMARY KEY AUTOINCREMENT for IDs.

### Table 1: memory_events (TR1)

The append-only event log. Every mutation to any memory is recorded here as a structured event with a field-level delta. This is the foundation for all temporal reconstruction.

```sql
CREATE TABLE memory_events (
    event_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    memory_id   TEXT NOT NULL,
    recorded_at TEXT NOT NULL,           -- ISO 8601, immutable once written
    event_type  TEXT NOT NULL,           -- one of 17 MemoryEventType variants
    delta       TEXT NOT NULL,           -- JSON field-level diff (not full state)
    actor_type  TEXT NOT NULL,           -- 'user' | 'agent' | 'system'
    actor_id    TEXT NOT NULL,
    caused_by   TEXT,                    -- JSON array of event_ids, nullable
    schema_version INTEGER NOT NULL DEFAULT 1,  -- CR2: event schema versioning
    FOREIGN KEY (memory_id) REFERENCES memories(id)
);

CREATE INDEX idx_events_memory_time ON memory_events(memory_id, recorded_at);
CREATE INDEX idx_events_time ON memory_events(recorded_at);
CREATE INDEX idx_events_type ON memory_events(event_type);
```

**Size estimate**: ~200 bytes/event. At 10 events/memory/month for 10K memories: ~24MB/year.
**Write pattern**: Append-only, WAL-friendly. Sequential event_id via AUTOINCREMENT.
**Ordering guarantee** (CR10): Single WriteConnection Mutex serializes all writes. event_id is monotonically increasing and gap-free within a single Cortex instance.

### Table 2: memory_events_archive (CR4)

Cold storage for compacted events. Same schema as memory_events plus an archived_at timestamp. Events older than 6 months with a verified snapshot after them are moved here during monthly compaction.

```sql
CREATE TABLE memory_events_archive (
    event_id       INTEGER PRIMARY KEY,
    memory_id      TEXT NOT NULL,
    recorded_at    TEXT NOT NULL,
    event_type     TEXT NOT NULL,
    delta          TEXT NOT NULL,
    actor_type     TEXT NOT NULL,
    actor_id       TEXT NOT NULL,
    caused_by      TEXT,
    schema_version INTEGER NOT NULL DEFAULT 1,
    archived_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
```

**Not indexed for replay** — saves index space. Queryable for deep historical analysis but not on the hot path.

### Table 3: memory_snapshots (TR2)

Periodic state captures for O(k) reconstruction. Each snapshot is a zstd-compressed JSON of the full BaseMemory state, valid up to a specific event_id.

```sql
CREATE TABLE memory_snapshots (
    snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
    memory_id   TEXT NOT NULL,
    snapshot_at TEXT NOT NULL,
    state       BLOB NOT NULL,           -- zstd-compressed JSON of BaseMemory
    event_id    INTEGER NOT NULL,        -- snapshot valid up to this event
    reason      TEXT NOT NULL,           -- 'event_threshold' | 'periodic' | 'pre_operation' | 'on_demand'
    FOREIGN KEY (memory_id) REFERENCES memories(id)
);

CREATE INDEX idx_snapshots_memory_time ON memory_snapshots(memory_id, snapshot_at);
```

**Size estimate**: ~500 bytes/snapshot (zstd compressed). Weekly snapshots for 10K memories over 6 months: ~130MB.

### Table 4: drift_snapshots (TR8)

Time-series storage for drift metrics. Each row is a JSON blob of the full DriftSnapshot struct at a point in time.

```sql
CREATE TABLE drift_snapshots (
    snapshot_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      TEXT NOT NULL,
    window_seconds INTEGER NOT NULL,
    metrics        TEXT NOT NULL,          -- JSON blob of DriftSnapshot
    UNIQUE(timestamp, window_seconds)
);

CREATE INDEX idx_drift_time ON drift_snapshots(timestamp);
```

**Size estimate**: Daily snapshots for 1 year: ~730KB. Weekly comprehensive: ~520KB. Total: ~1.3MB/year.

### Table 5: materialized_views (TR9)

Pre-computed knowledge snapshots at significant time points (sprint boundaries, releases).

```sql
CREATE TABLE materialized_views (
    view_id           INTEGER PRIMARY KEY AUTOINCREMENT,
    label             TEXT NOT NULL UNIQUE,
    timestamp         TEXT NOT NULL,
    memory_count      INTEGER NOT NULL,
    snapshot_ids      TEXT NOT NULL,     -- JSON array of snapshot_ids
    drift_snapshot_id INTEGER,
    created_by        TEXT NOT NULL,
    auto_refresh      INTEGER DEFAULT 0,
    FOREIGN KEY (drift_snapshot_id) REFERENCES drift_snapshots(snapshot_id)
);
```

### New Indexes on Existing memories Table

```sql
CREATE INDEX idx_memories_valid_range
ON memories(valid_time, valid_until) WHERE archived = 0;

CREATE INDEX idx_memories_transaction_range
ON memories(transaction_time);
```

These indexes accelerate temporal range queries (TR3, Query Type 2) without affecting existing query performance.

### Total Storage Overhead

| Component | 10K memories, 6 months | 10K memories, 1 year |
|-----------|----------------------|---------------------|
| memory_events | ~120MB | ~240MB |
| memory_events_archive | 0 (compaction starts at 6mo) | ~120MB |
| memory_snapshots | ~130MB | ~260MB |
| drift_snapshots | ~0.7MB | ~1.3MB |
| materialized_views | ~0.1MB | ~0.2MB |
| New indexes on memories | ~5MB | ~5MB |
| **Total** | **~256MB** | **~627MB** |

All within SQLite's operational comfort zone. Bounded by the same retention policies as existing audit log rotation.

### Backward Compatibility (TR18)

1. All existing queries continue unchanged — they implicitly query "as of now"
2. Event recording adds ~0.1ms per mutation (append-only WAL write)
3. Snapshot creation runs in background — no foreground impact
4. Pre-migration data: memories created before v014 have no event history. Temporal queries for pre-migration time ranges return "no temporal data available." Graceful degradation, not errors.
5. New temporal queries are additive API surface — no changes to existing MCP tools or CLI commands



---

## Data Models — cortex-core Additions (10 New Files)

All temporal data models live in cortex-core so every crate can reference them without depending on cortex-temporal directly. This follows the existing pattern: cortex-core owns types, cortex-temporal owns behavior.

### Model 1: MemoryEvent + MemoryEventType + EventActor (TR1, CR2, CR11)

**File**: `crates/cortex/cortex-core/src/models/temporal_event.rs`

The atomic unit of temporal tracking. Every mutation to any memory produces exactly one MemoryEvent. Events are immutable once written — the event store is append-only.

```
MemoryEvent:
    event_id: u64                       -- monotonically increasing, gap-free
    memory_id: String                   -- which memory was affected
    recorded_at: DateTime<Utc>          -- transaction time — immutable once written
    event_type: MemoryEventType         -- 17 variants (see below)
    delta: serde_json::Value            -- field-level diff, NOT full state
    actor: EventActor                   -- who caused this mutation
    caused_by: Vec<u64>                 -- causal predecessors for ordering
    schema_version: u16                 -- starts at 1, incremented on schema changes (CR2)
```

**MemoryEventType** — 17 variants covering every mutation path in Cortex:

| Variant | Source | Delta Shape |
|---------|--------|-------------|
| `Created` | memory_crud::create | Full initial BaseMemory state |
| `ContentUpdated` | memory_crud::update, version_ops | `{ old_summary, new_summary, old_content_hash, new_content_hash }` |
| `ConfidenceChanged` | decay engine, validation | `{ old: f64, new: f64, reason: String }` |
| `ImportanceChanged` | reclassification | `{ old: Importance, new: Importance, reason: String }` |
| `TagsModified` | memory_crud::update | `{ added: Vec<String>, removed: Vec<String> }` |
| `LinkAdded` | link_ops::add | `{ link_type: String, target: String }` |
| `LinkRemoved` | link_ops::remove | `{ link_type: String, target: String }` |
| `RelationshipAdded` | causal graph sync | `{ source: String, target: String, relation_type: String, strength: f64 }` |
| `RelationshipRemoved` | causal graph sync | `{ source: String, target: String }` |
| `StrengthUpdated` | causal graph sync | `{ source: String, target: String, old_strength: f64, new_strength: f64 }` |
| `Archived` | memory_crud::archive, consolidation pruning | `{ reason: String }` |
| `Restored` | memory_crud::restore | `{}` |
| `Decayed` | decay engine | `{ old_confidence: f64, new_confidence: f64, decay_factor: f64 }` |
| `Validated` | validation engine | `{ dimension_scores: DimensionScores, healing_actions: Vec<String> }` |
| `Consolidated` | consolidation pipeline | `{ merged_from: Vec<String>, merged_into: Option<String> }` |
| `Reclassified` | reclassification engine | `{ old_type: String, new_type: String, confidence: f64 }` |
| `Superseded` | memory_crud::update | `{ superseded_by: String }` |

Note: The original 16 variants from RECOMMENDATIONS.md are preserved. `StrengthUpdated` is added for causal edge strength changes (TR10). The `Accessed` event type from CR11 is deliberately excluded from default event sourcing to avoid write amplification on the hot retrieval path. Access patterns are tracked via the existing `last_accessed` / `access_count` fields which are NOT event-sourced.

**EventActor** — who caused the mutation:

```
EventActor:
    User(String)                        -- human user identifier
    Agent(String)                       -- agent identifier
    System(String)                      -- "decay_engine", "consolidation_pipeline", "validation_engine", etc.
```

**Serde**: All types derive `Serialize, Deserialize, Debug, Clone`. MemoryEventType uses `#[serde(rename_all = "snake_case")]` for SQLite TEXT storage.

### Model 2: MemorySnapshot + SnapshotReason (TR2)

**File**: `crates/cortex/cortex-core/src/models/temporal_event.rs` (same file — closely related)

```
MemorySnapshot:
    snapshot_id: u64
    memory_id: String
    snapshot_at: DateTime<Utc>
    state: Vec<u8>                      -- zstd-compressed JSON of full BaseMemory
    event_id: u64                       -- snapshot is valid up to this event
    snapshot_reason: SnapshotReason

SnapshotReason:
    EventThreshold                      -- memory exceeded 50 events since last snapshot
    Periodic                            -- weekly full-database snapshot
    PreOperation                        -- before consolidation or major mutation
    OnDemand                            -- user requested materialized view
```

### Model 3: Temporal Query Types (TR3)

**File**: `crates/cortex/cortex-core/src/models/temporal_query.rs`

Five query types, each with its own request struct:

```
AsOfQuery:
    system_time: DateTime<Utc>          -- "what was recorded by this time"
    valid_time: DateTime<Utc>           -- "what was true at this time"
    filter: Option<MemoryFilter>        -- optional type/tag/file filter

TemporalRangeQuery:
    from: DateTime<Utc>
    to: DateTime<Utc>
    mode: TemporalRangeMode            -- Overlaps | Contains | StartedDuring | EndedDuring

TemporalDiffQuery:
    time_a: DateTime<Utc>
    time_b: DateTime<Utc>
    scope: DiffScope                    -- All | Types(Vec<MemoryType>) | Files(Vec<String>) | Namespace(String)

DecisionReplayQuery:
    decision_memory_id: String
    budget_override: Option<usize>

TemporalCausalQuery:
    memory_id: String
    as_of: DateTime<Utc>
    direction: TraversalDirection        -- reuses cortex-causal's enum
    max_depth: usize
```

**TemporalRangeMode** — four Allen's interval algebra modes:
- `Overlaps`: memory was valid at any point in [from, to]
- `Contains`: memory was valid for the entire [from, to]
- `StartedDuring`: memory became valid during [from, to]
- `EndedDuring`: memory stopped being valid during [from, to]

### Model 4: TemporalDiff + DiffStats (TR3, Query Type 3)

**File**: `crates/cortex/cortex-core/src/models/temporal_diff.rs`

The structured result of comparing two knowledge states:

```
TemporalDiff:
    created: Vec<BaseMemory>                    -- exist at time_b but not time_a
    archived: Vec<BaseMemory>                   -- exist at time_a but not time_b
    modified: Vec<MemoryModification>           -- exist at both, changed
    confidence_shifts: Vec<ConfidenceShift>     -- confidence delta > 0.2
    new_contradictions: Vec<Contradiction>      -- detected between time_a and time_b
    resolved_contradictions: Vec<Contradiction>
    reclassifications: Vec<Reclassification>
    stats: DiffStats

MemoryModification:
    memory_id: String
    field: String                               -- which field changed
    old_value: serde_json::Value
    new_value: serde_json::Value

ConfidenceShift:
    memory_id: String
    old_confidence: f64
    new_confidence: f64
    delta: f64                                  -- new - old

DiffStats:
    memories_at_a: usize
    memories_at_b: usize
    net_change: i64                             -- memories_at_b - memories_at_a
    avg_confidence_at_a: f64
    avg_confidence_at_b: f64
    confidence_trend: f64                       -- positive = improving
    knowledge_churn_rate: f64                   -- (created + archived) / total
```

### Model 5: DecisionReplay + HindsightItem (TR3, Query Type 4)

**File**: `crates/cortex/cortex-core/src/models/decision_replay.rs`

```
DecisionReplay:
    decision: BaseMemory                        -- the decision as it was at creation time
    available_context: Vec<BaseMemory>          -- all memories that existed at decision time
    retrieved_context: Vec<CompressedMemory>    -- what retrieval would have returned
    causal_state: CausalGraphSnapshot           -- causal graph at decision time
    hindsight: Vec<HindsightItem>               -- what we know NOW but didn't THEN

HindsightItem:
    memory: BaseMemory                          -- the memory that didn't exist at decision time
    relevance: f64                              -- embedding similarity to decision topic
    relationship: String                        -- "contradicts" | "would_have_informed" | "supersedes" | "supports"

CausalGraphSnapshot:
    nodes: Vec<String>                          -- memory_ids in the graph at that time
    edges: Vec<CausalEdgeSnapshot>              -- edges with strengths at that time
    
CausalEdgeSnapshot:
    source: String
    target: String
    relation_type: String
    strength: f64
```

### Model 6: DriftSnapshot + Metrics (TR8)

**File**: `crates/cortex/cortex-core/src/models/drift_snapshot.rs`

```
DriftSnapshot:
    timestamp: DateTime<Utc>
    window: Duration
    type_metrics: HashMap<MemoryType, TypeDriftMetrics>
    module_metrics: HashMap<String, ModuleDriftMetrics>
    global: GlobalDriftMetrics

TypeDriftMetrics:
    count: usize
    avg_confidence: f64
    ksi: f64                                    -- Knowledge Stability Index [0.0, 1.0]
    contradiction_density: f64
    consolidation_efficiency: f64
    evidence_freshness_index: f64

ModuleDriftMetrics:
    memory_count: usize
    coverage_ratio: f64
    avg_confidence: f64
    churn_rate: f64

GlobalDriftMetrics:
    total_memories: usize
    active_memories: usize
    archived_memories: usize
    avg_confidence: f64
    overall_ksi: f64
    overall_contradiction_density: f64
    overall_evidence_freshness: f64
```

### Model 7: DriftAlert + AlertSeverity + DriftAlertCategory (TR7)

**File**: `crates/cortex/cortex-core/src/models/drift_alert.rs`

```
DriftAlert:
    severity: AlertSeverity                     -- Info | Warning | Critical
    category: DriftAlertCategory
    message: String
    affected_memories: Vec<String>              -- memory_ids
    recommended_action: String
    detected_at: DateTime<Utc>

AlertSeverity: Info | Warning | Critical

DriftAlertCategory:
    KnowledgeChurn { memory_type: MemoryType, ksi: f64, threshold: f64 }
    ConfidenceErosion { memory_type: MemoryType, trend: f64, windows_declining: u32 }
    ContradictionSpike { density: f64, threshold: f64, hotspot: Option<String> }
    StaleEvidence { memory_id: String, freshness: f64, stale_links: Vec<String> }
    KnowledgeExplosion { module: String, rate: f64, baseline: f64 }
    CoverageGap { module: String, coverage: f64, expected: f64 }
```

### Model 8: EpistemicStatus + AggregationStrategy (TR11)

**File**: `crates/cortex/cortex-core/src/models/epistemic_status.rs`

```
EpistemicStatus:
    Conjecture { source: String, created_at: DateTime<Utc> }
    Provisional { evidence_count: u32, last_validated: DateTime<Utc> }
    Verified { verified_by: Vec<String>, verified_at: DateTime<Utc>, evidence_refs: Vec<String> }
    Stale { was_verified_at: DateTime<Utc>, staleness_detected_at: DateTime<Utc>, reason: String }

AggregationStrategy:
    WeightedAverage                             -- existing approach (default)
    GodelTNorm                                  -- min operator (conservative, from TS11)
```

**Epistemic status is orthogonal to confidence.** A memory can have high confidence (0.9) but be a Conjecture (no one verified it). A memory can have moderate confidence (0.6) but be Verified (multiple people confirmed it, but it's in a contested domain).

**Valid promotion paths**: Conjecture → Provisional → Verified (only forward). Stale can only come from Verified (evidence decay). No skipping steps. No backward transitions except Verified → Stale.

### Model 9: MaterializedTemporalView (TR9)

**File**: `crates/cortex/cortex-core/src/models/materialized_view.rs`

```
MaterializedTemporalView:
    view_id: u64
    label: String                               -- "sprint-12", "v2.0-release", "Q1-2026"
    timestamp: DateTime<Utc>
    memory_count: usize
    snapshot_ids: Vec<u64>                      -- references to memory_snapshots
    drift_snapshot_id: Option<u64>              -- associated drift metrics
    created_by: EventActor
    auto_refresh: bool
```

### Model Registration

**Modified file**: `crates/cortex/cortex-core/src/models/mod.rs`

Add 7 new module declarations and re-exports:

```rust
mod temporal_event;      // MemoryEvent, MemoryEventType, EventActor, MemorySnapshot, SnapshotReason
mod temporal_query;      // AsOfQuery, TemporalRangeQuery, TemporalDiffQuery, DecisionReplayQuery, TemporalCausalQuery, TemporalRangeMode, DiffScope
mod temporal_diff;       // TemporalDiff, MemoryModification, ConfidenceShift, DiffStats
mod decision_replay;     // DecisionReplay, HindsightItem, CausalGraphSnapshot, CausalEdgeSnapshot
mod drift_snapshot;      // DriftSnapshot, TypeDriftMetrics, ModuleDriftMetrics, GlobalDriftMetrics
mod drift_alert;         // DriftAlert, AlertSeverity, DriftAlertCategory
mod epistemic_status;    // EpistemicStatus, AggregationStrategy
mod materialized_view;   // MaterializedTemporalView
```

All types re-exported via `pub use` following the existing pattern in mod.rs.

---

## Error Type — TemporalError (TR15, CR2)

**New file**: `crates/cortex/cortex-core/src/errors/temporal_error.rs`
**Modified file**: `crates/cortex/cortex-core/src/errors/mod.rs` — add `mod temporal_error;` + `pub use`

```
TemporalError:
    EventAppendFailed(String)
    SnapshotCreationFailed(String)
    ReconstructionFailed(String)
    QueryFailed(String)
    InvalidTemporalBounds(String)               -- valid_time > valid_until
    ImmutableFieldViolation(String)             -- transaction_time modification attempt
    SchemaVersionMismatch { expected: u16, found: u16 }
    CompactionFailed(String)
    InvalidEpistemicTransition { from: String, to: String }
```

Implements `From<TemporalError> for CortexError` via a new `TemporalError` variant added to the existing `CortexError` enum in `cortex_error.rs`:

```rust
#[error("temporal error: {0}")]
TemporalError(#[from] TemporalError),
```

---

## Trait — ITemporalEngine (TR14)

**New file**: `crates/cortex/cortex-core/src/traits/temporal_engine.rs`
**Modified file**: `crates/cortex/cortex-core/src/traits/mod.rs` — add `mod temporal_engine;` + `pub use`

The 13th trait in cortex-core. Defines the complete temporal reasoning interface:

```
#[async_trait]
trait ITemporalEngine: Send + Sync {
    // Event store (TR1)
    async fn record_event(&self, event: MemoryEvent) -> Result<u64, CortexError>;
    async fn get_events(&self, memory_id: &str, before: Option<DateTime<Utc>>) -> Result<Vec<MemoryEvent>, CortexError>;

    // State reconstruction (TR2)
    async fn reconstruct_at(&self, memory_id: &str, as_of: DateTime<Utc>) -> Result<Option<BaseMemory>, CortexError>;
    async fn reconstruct_all_at(&self, as_of: DateTime<Utc>, filter: Option<MemoryFilter>) -> Result<Vec<BaseMemory>, CortexError>;

    // Temporal queries (TR3)
    async fn query_as_of(&self, query: AsOfQuery) -> Result<Vec<BaseMemory>, CortexError>;
    async fn query_range(&self, query: TemporalRangeQuery) -> Result<Vec<BaseMemory>, CortexError>;
    async fn query_diff(&self, query: TemporalDiffQuery) -> Result<TemporalDiff, CortexError>;
    async fn replay_decision(&self, query: DecisionReplayQuery) -> Result<DecisionReplay, CortexError>;
    async fn query_temporal_causal(&self, query: TemporalCausalQuery) -> Result<TraversalResult, CortexError>;

    // Drift detection (TR6, TR7)
    async fn compute_drift_metrics(&self, window: Duration) -> Result<DriftSnapshot, CortexError>;
    async fn get_drift_alerts(&self) -> Result<Vec<DriftAlert>, CortexError>;

    // Materialized views (TR9)
    async fn create_view(&self, label: &str, timestamp: DateTime<Utc>) -> Result<MaterializedTemporalView, CortexError>;
    async fn get_view(&self, label: &str) -> Result<Option<MaterializedTemporalView>, CortexError>;
}
```

This trait is the contract. cortex-temporal's `TemporalEngine` struct is the implementation. Other crates depend on the trait (in cortex-core), not the implementation (in cortex-temporal).



---

## Config — TemporalConfig (TR7, TR8, TR9, TR11, CR4)

**New file**: `crates/cortex/cortex-core/src/config/temporal_config.rs`
**Modified file**: `crates/cortex/cortex-core/src/config/mod.rs` — add `pub mod temporal_config;` + `pub use` + add `temporal: TemporalConfig` field to `CortexConfig`

```
TemporalConfig:
    // Snapshot settings (TR2)
    snapshot_event_threshold: u64           = 50        -- snapshot when memory exceeds N events since last snapshot
    snapshot_periodic_interval_hours: u64   = 168       -- weekly periodic snapshots
    snapshot_retention_full_days: u64       = 180       -- keep all snapshots for 6 months
    snapshot_retention_monthly_days: u64    = 730       -- keep monthly snapshots for 2 years

    // Event compaction (CR4)
    event_compaction_age_days: u64          = 180       -- compact events older than 6 months

    // Drift snapshot frequency (TR8)
    drift_hourly_enabled: bool              = true
    drift_daily_enabled: bool               = true
    drift_weekly_enabled: bool              = true

    // Alert thresholds (TR7)
    alert_ksi_threshold: f64                = 0.3       -- KSI below this triggers warning
    alert_confidence_erosion_windows: u32   = 2         -- consecutive declining windows before alert
    alert_contradiction_density_threshold: f64 = 0.10   -- density above this triggers critical
    alert_evidence_freshness_threshold: f64 = 0.5       -- freshness below this triggers warning
    alert_explosion_sigma: f64              = 3.0       -- creation rate > Nσ above baseline
    alert_cooldown_warning_hours: u64       = 24        -- don't re-fire same warning for 24h
    alert_cooldown_critical_hours: u64      = 1         -- don't re-fire same critical for 1h

    // Epistemic settings (TR11)
    epistemic_auto_promote: bool            = true      -- auto-promote on validation pass
    confidence_aggregation: AggregationStrategy = WeightedAverage

    // Materialized views (TR9)
    materialized_view_auto_interval_days: u64 = 14      -- auto-create views every 2 weeks
```

All fields have defaults via `impl Default for TemporalConfig`. Configurable via TOML under `[temporal]` section in CortexConfig.

---

## Phase A: Event Store Foundation (~32 new files, ~12 modified)

Phase A builds the temporal infrastructure that every subsequent phase depends on. No temporal queries, no drift detection — just the ability to record events, create snapshots, and reconstruct state.

### Phase A — cortex-core Changes

**Files created** (Phase A subset):
- `src/models/temporal_event.rs` — MemoryEvent, MemoryEventType, EventActor, MemorySnapshot, SnapshotReason
- `src/errors/temporal_error.rs` — TemporalError enum
- `src/traits/temporal_engine.rs` — ITemporalEngine trait
- `src/config/temporal_config.rs` — TemporalConfig

**Files modified**:
- `src/models/mod.rs` — add temporal_event module + re-exports
- `src/errors/mod.rs` — add temporal_error module + re-export
- `src/errors/cortex_error.rs` — add TemporalError variant to CortexError
- `src/traits/mod.rs` — add temporal_engine module + re-export
- `src/config/mod.rs` — add temporal_config module + re-export + add field to CortexConfig

### Phase A — cortex-storage Changes

**New file**: `src/migrations/v014_temporal_tables.rs`
- Creates all 5 tables + archive table + 2 new indexes on memories table
- Registered in `src/migrations/mod.rs`

**New files** (query modules):
- `src/queries/event_ops.rs` — raw SQL for event CRUD
  - `insert_event(conn, event) -> Result<u64>`
  - `insert_event_batch(conn, events) -> Result<Vec<u64>>`
  - `get_events_for_memory(conn, memory_id, before) -> Result<Vec<RawEvent>>`
  - `get_events_in_range(conn, from, to) -> Result<Vec<RawEvent>>`
  - `get_events_by_type(conn, event_type, before) -> Result<Vec<RawEvent>>`
  - `get_event_count(conn, memory_id) -> Result<u64>`
  - `move_events_to_archive(conn, before_date, snapshot_id) -> Result<u64>`
- `src/queries/snapshot_ops.rs` — raw SQL for snapshot CRUD
  - `insert_snapshot(conn, snapshot) -> Result<u64>`
  - `get_nearest_snapshot(conn, memory_id, before) -> Result<Option<RawSnapshot>>`
  - `get_snapshots_for_memory(conn, memory_id) -> Result<Vec<RawSnapshot>>`
  - `delete_old_snapshots(conn, retention_policy) -> Result<u64>`

**Modified files** (event emission wiring):
- `src/queries/memory_crud.rs` — emit Created/ContentUpdated/TagsModified/Archived/Restored events in same transaction (CR3)
- `src/queries/audit_ops.rs` — emit corresponding event alongside audit record in same transaction (CR3)
- `src/queries/link_ops.rs` — emit LinkAdded/LinkRemoved events
- `src/queries/version_ops.rs` — emit ContentUpdated event with version delta
- `src/queries/mod.rs` — add `pub mod event_ops;` + `pub mod snapshot_ops;`
- `src/migrations/mod.rs` — register v014

### Phase A — cortex-temporal Crate (New)

**File**: `crates/cortex/cortex-temporal/Cargo.toml`

```toml
[package]
name = "cortex-temporal"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[dependencies]
cortex-core = { workspace = true }
cortex-storage = { workspace = true }
chrono = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
tokio = { workspace = true }
thiserror = { workspace = true }
tracing = { workspace = true }
zstd = "0.13"

[dev-dependencies]
proptest = { workspace = true }
criterion = { workspace = true }
test-fixtures = { workspace = true }
tokio = { workspace = true, features = ["test-util"] }

[[bench]]
name = "temporal_bench"
harness = false
```

**Workspace registration**: Add `"cortex-temporal"` to `[workspace.members]` and `cortex-temporal = { path = "cortex-temporal" }` to `[workspace.dependencies]` in `crates/cortex/Cargo.toml`.

### Phase A — cortex-temporal Source Files

```
crates/cortex/cortex-temporal/
├── Cargo.toml
├── src/
│   ├── lib.rs                              # Module declarations + re-exports
│   ├── engine.rs                           # TemporalEngine struct (Phase A: partial impl)
│   ├── event_store/
│   │   ├── mod.rs                          # Module declarations + re-exports
│   │   ├── append.rs                       # Event append (single + batch)
│   │   ├── query.rs                        # Event query (by memory, by range, by type)
│   │   ├── replay.rs                       # Event replay (apply events to state)
│   │   ├── upcaster.rs                     # Schema versioning (CR2)
│   │   └── compaction.rs                   # Event archival (CR4)
│   └── snapshot/
│       ├── mod.rs                          # Module declarations + re-exports
│       ├── create.rs                       # Snapshot creation (single + batch)
│       ├── lookup.rs                       # Snapshot query (nearest, by memory)
│       ├── reconstruct.rs                  # State reconstruction (snapshot + replay)
│       ├── retention.rs                    # Snapshot retention policy
│       └── triggers.rs                     # Adaptive snapshot trigger evaluation
```

### Phase A — Module Specifications

#### `src/lib.rs`

Crate root. Module declarations for all submodules (event_store, snapshot, query, drift, epistemic, dual_time, views). Re-exports the public API: TemporalEngine, EventStore types, SnapshotEngine types. Phase A only exposes event_store and snapshot modules — query, drift, epistemic, dual_time, views are declared but empty (compiled behind `#[cfg(feature = "...")]` or simply as empty modules that will be filled in later phases).

#### `src/engine.rs` — TemporalEngine

The central orchestrator. Implements `ITemporalEngine` trait. Holds references to both WriteConnection (for event appends, snapshot creation) and ReadPool (for all temporal queries) per CR5.

```
TemporalEngine:
    writer: Arc<WriteConnection>        -- for event_store.append(), snapshot.create()
    readers: Arc<ReadPool>              -- for all temporal queries
    config: TemporalConfig
```

**Concurrency model** (CR5): All temporal read queries use ReadPool. All writes use WriteConnection. SQLite WAL mode allows concurrent readers with a single writer. Temporal queries are read-heavy — the only writes are event appends (~0.1ms) and snapshot creation (~5ms per batch).

Phase A implements: `record_event`, `get_events`, `reconstruct_at`, `reconstruct_all_at`. Other trait methods return `Err(CortexError::TemporalError(TemporalError::QueryFailed("not yet implemented")))` until their respective phases.

#### `src/event_store/append.rs`

- `append(writer, event) -> Result<u64>` — single event append via WriteConnection
- `append_batch(writer, events) -> Result<Vec<u64>>` — batch append in single transaction
- Uses `event_ops::insert_event` from cortex-storage
- Returns the assigned event_id
- **Idempotency** (CR3): When called from mutation paths, the event append is in the same SQLite transaction as the original mutation. No dual-write risk.

#### `src/event_store/query.rs`

- `get_events(reader, memory_id, before) -> Vec<MemoryEvent>` — all events for a memory, optionally before a timestamp
- `get_events_in_range(reader, memory_id, after_event_id, before_time) -> Vec<MemoryEvent>` — events between a snapshot and a time point (for reconstruction)
- `get_events_by_type(reader, event_type, before) -> Vec<MemoryEvent>` — all events of a type (for drift metrics)
- `get_all_events_in_range(reader, from, to) -> Vec<MemoryEvent>` — all events in a time range across all memories (for temporal diff)
- All reads use ReadPool — concurrent with writes

#### `src/event_store/replay.rs`

The core state reconstruction logic. Takes a sequence of events and an initial state, applies each event to produce the final state.

- `replay_events(events, initial_state) -> BaseMemory` — apply all events to initial state
- `apply_event(state, event) -> BaseMemory` — single event application

**Event type dispatch** — 17 variants, each modifying specific BaseMemory fields:

| Event Type | Fields Modified |
|-----------|----------------|
| Created | All fields (full initial state) |
| ContentUpdated | content, summary, content_hash |
| ConfidenceChanged | confidence |
| ImportanceChanged | importance |
| TagsModified | tags (add/remove) |
| LinkAdded | linked_patterns / linked_constraints / linked_files / linked_functions (based on link_type) |
| LinkRemoved | linked_patterns / linked_constraints / linked_files / linked_functions |
| RelationshipAdded | (no BaseMemory field — graph-level event) |
| RelationshipRemoved | (no BaseMemory field — graph-level event) |
| StrengthUpdated | (no BaseMemory field — graph-level event) |
| Archived | archived = true |
| Restored | archived = false |
| Decayed | confidence |
| Validated | (no direct field change — validation metadata) |
| Consolidated | superseded_by, supersedes |
| Reclassified | memory_type |
| Superseded | superseded_by |

**Critical property**: `replay_events(all_events_for_memory, empty_shell) == current_state(memory)` — this is the fundamental correctness property tested by property-based tests.

#### `src/event_store/upcaster.rs` (CR2)

Schema evolution for events. Events are immutable — we never modify persisted events. When the schema changes, upcasters transform old events on read.

```
trait EventUpcaster: Send + Sync {
    fn can_upcast(&self, event_type: &str, schema_version: u16) -> bool;
    fn upcast(&self, event: RawEvent) -> RawEvent;
}

UpcasterRegistry:
    upcasters: Vec<Box<dyn EventUpcaster>>
    
    fn upcast_event(&self, raw_event: RawEvent) -> MemoryEvent
        -- checks schema_version, applies matching upcasters in order
        -- if schema_version == current, no-op (fast path)
```

**Three rules for event evolution**:
1. Additive only: new fields are always optional with defaults. Never remove or rename fields in delta JSON.
2. New event types are free: adding a new MemoryEventType variant doesn't affect existing events.
3. Upcasters for breaking changes: if a field must be restructured, write an upcaster. The persisted event is never modified.

Phase A ships with a v1 identity upcaster (no-op). Future schema changes add new upcasters to the registry.

#### `src/event_store/compaction.rs` (CR4)

Moves old events to the archive table. Runs monthly as a background task.

- `compact_events(writer, before_date, verified_snapshot_id) -> CompactionResult`
  - Finds events older than `before_date` where a verified snapshot exists after them
  - Moves matching events to `memory_events_archive` via `event_ops::move_events_to_archive`
  - Returns `CompactionResult { events_moved: u64, space_reclaimed_bytes: u64 }`
- Respects `config.event_compaction_age_days` (default: 180 days)

#### `src/snapshot/create.rs`

- `create_snapshot(writer, memory_id, current_state, reason) -> Result<u64>`
  - Serializes BaseMemory to JSON, compresses with zstd, stores via `snapshot_ops::insert_snapshot`
  - Records the current max event_id for this memory as the snapshot's validity bound
- `create_batch_snapshots(writer, memories, reason) -> Result<Vec<u64>>`
  - Batch creation in single transaction for efficiency (weekly sweep)

#### `src/snapshot/lookup.rs`

- `get_nearest_snapshot(reader, memory_id, before) -> Option<MemorySnapshot>`
  - Finds the most recent snapshot for a memory before a given time
  - Used by reconstruction to minimize replay length
- `get_snapshots_for_memory(reader, memory_id) -> Vec<MemorySnapshot>`

#### `src/snapshot/reconstruct.rs`

The core reconstruction algorithm. This is the most critical module in the entire temporal system.

```
reconstruct_at(reader, memory_id, target_time) -> Option<BaseMemory>:
    1. snapshot = get_nearest_snapshot(memory_id, before=target_time)
    2. if snapshot exists:
           events = get_events_in_range(memory_id, after=snapshot.event_id, before=target_time)
           state = decompress(snapshot.state)  // zstd decompress → JSON → BaseMemory
       else:
           events = get_events(memory_id, before=target_time)
           state = empty_memory_shell(memory_id)
    3. for event in events:
           state = apply_event(state, event)  // from replay.rs
    4. return Some(state)  // or None if no events exist

reconstruct_all_at(reader, target_time, filter) -> Vec<BaseMemory>:
    1. Get all memory_ids that had events before target_time
    2. For each memory_id (optionally filtered by type/tag):
           state = reconstruct_at(memory_id, target_time)
    3. Filter out archived memories (at target_time)
    4. Return all reconstructed states
```

**Performance**:
- Cold (no snapshots): O(n) where n = total events for memory. ~5ms for 50 events.
- Warm (with snapshots): O(k) where k = events since last snapshot. ~1ms for 10 events.
- Full state (10K memories, with weekly snapshots): ~50ms.

#### `src/snapshot/retention.rs`

- `apply_retention_policy(writer, config) -> RetentionResult`
  - Keep all snapshots for `snapshot_retention_full_days` (default: 180 days)
  - After that, keep only monthly snapshots until `snapshot_retention_monthly_days` (default: 730 days)
  - After that, keep only quarterly snapshots
  - Deletes excess snapshots via `snapshot_ops::delete_old_snapshots`
  - Returns `RetentionResult { snapshots_deleted: u64, space_reclaimed_bytes: u64 }`

#### `src/snapshot/triggers.rs`

Evaluates whether a memory needs a new snapshot. Called after event appends.

```
AdaptiveSnapshotTrigger:
    config: TemporalConfig

    fn should_snapshot(reader, memory_id) -> Option<SnapshotReason>:
        event_count = get_event_count_since_last_snapshot(memory_id)
        if event_count >= config.snapshot_event_threshold:
            return Some(SnapshotReason::EventThreshold)
        return None

    fn should_periodic_snapshot(last_snapshot_time) -> bool:
        elapsed = now() - last_snapshot_time
        return elapsed >= Duration::hours(config.snapshot_periodic_interval_hours)
```

The periodic sweep runs as a background task (not blocking foreground operations). The event threshold check runs inline after event appends but is a single COUNT query (~0.01ms).

### Phase A — Modifications to Existing Mutation Paths

These are the critical wiring changes that make the event store actually receive events. Each modification is small — emit an event alongside the existing operation, in the same SQLite transaction.

#### `cortex-storage/src/queries/memory_crud.rs`

```
create_memory():
    existing: INSERT INTO memories ...
    new: ALSO INSERT INTO memory_events (event_type='created', delta=full_state)
    both in same transaction

update_memory():
    existing: UPDATE memories SET ...
    new: ALSO INSERT INTO memory_events (event_type based on changed fields)
    if content changed → ContentUpdated
    if tags changed → TagsModified
    if confidence changed → ConfidenceChanged
    if importance changed → ImportanceChanged
    both in same transaction

archive_memory():
    existing: UPDATE memories SET archived=1
    new: ALSO INSERT INTO memory_events (event_type='archived')
    both in same transaction

restore_memory():
    existing: UPDATE memories SET archived=0
    new: ALSO INSERT INTO memory_events (event_type='restored')
    both in same transaction
```

#### `cortex-storage/src/queries/link_ops.rs`

```
add_link():
    existing: UPDATE memories SET linked_* = ...
    new: ALSO INSERT INTO memory_events (event_type='link_added', delta={link_type, target})

remove_link():
    existing: UPDATE memories SET linked_* = ...
    new: ALSO INSERT INTO memory_events (event_type='link_removed', delta={link_type, target})
```

#### `cortex-storage/src/queries/version_ops.rs`

```
create_version():
    existing: INSERT INTO memory_versions ...
    new: ALSO INSERT INTO memory_events (event_type='content_updated', delta=version_diff)
```

#### `cortex-decay/src/engine.rs`

```
apply_decay():
    existing: UPDATE memories SET confidence = new_confidence
    new: ALSO INSERT INTO memory_events (event_type='decayed', delta={old, new, factor})
```

#### `cortex-validation/src/engine.rs`

```
apply_validation_result():
    existing: INSERT INTO memory_validation_history ...
    new: ALSO INSERT INTO memory_events (event_type='validated', delta={scores, actions})
```

#### `cortex-consolidation/src/engine.rs`

```
complete_consolidation():
    existing: audit_log entries for merged/created/archived
    new: ALSO INSERT INTO memory_events (event_type='consolidated') for each participant
```

#### `cortex-consolidation/src/pipeline/phase6_pruning.rs`

```
prune_memory():
    existing: archive memory
    new: ALSO INSERT INTO memory_events (event_type='archived', delta={reason: 'consolidation_pruning'})
```

#### `cortex-reclassification/src/engine.rs`

```
reclassify():
    existing: INSERT INTO reclassification_history ...
    new: ALSO INSERT INTO memory_events (event_type='reclassified', delta={old_type, new_type, confidence})
```

#### `cortex-causal/src/graph/sync.rs`

```
persist_edge():
    existing: INSERT INTO causal_edges ...
    new: ALSO INSERT INTO memory_events (event_type='relationship_added', delta={source, target, type, strength})

remove_persisted_edge():
    existing: DELETE FROM causal_edges ...
    new: ALSO INSERT INTO memory_events (event_type='relationship_removed', delta={source, target})

update_persisted_strength():
    existing: UPDATE causal_edges SET strength = ...
    new: ALSO INSERT INTO memory_events (event_type='strength_updated', delta={source, target, old, new})
```

### Phase A — Quality Gate (QG-T0)

| Test | Pass Criteria | Coverage Target |
|------|---------------|-----------------|
| Event append round-trip | Append event → query by memory_id → event exists with correct fields | event_store/append.rs ≥ 80% |
| Event batch append | Append 100 events in batch → all 100 queryable | event_store/append.rs ≥ 80% |
| Event query by time range | Append events at T1, T2, T3 → query before T2 → only T1 events | event_store/query.rs ≥ 80% |
| Event query by type | Append mixed types → query by type → only matching type | event_store/query.rs ≥ 80% |
| Event replay produces current state | Create memory → mutate 10 times → replay all events → equals current state | event_store/replay.rs ≥ 80% |
| Event replay handles all 17 types | One test per event type → correct field modified | event_store/replay.rs ≥ 80% |
| Upcaster registry no-op for current version | v1 event → upcast → unchanged | event_store/upcaster.rs ≥ 80% |
| Compaction moves old events | Insert events → create snapshot → compact → events in archive table | event_store/compaction.rs ≥ 80% |
| Snapshot creation + lookup | Create snapshot → lookup by memory_id → found with correct state | snapshot/create.rs + lookup.rs ≥ 80% |
| Snapshot zstd round-trip | Compress → decompress → equals original BaseMemory | snapshot/create.rs ≥ 80% |
| Reconstruction from events only | No snapshots → reconstruct → equals current state | snapshot/reconstruct.rs ≥ 80% |
| Reconstruction from snapshot + events | Snapshot at T1 → events after T1 → reconstruct at T2 → correct state | snapshot/reconstruct.rs ≥ 80% |
| Reconstruction snapshot+replay == full replay | Property test: both paths produce identical state | snapshot/reconstruct.rs ≥ 80% |
| Retention policy deletes old snapshots | Create snapshots at various ages → apply retention → only recent remain | snapshot/retention.rs ≥ 80% |
| Adaptive trigger fires at threshold | Insert 50 events → trigger evaluates → should_snapshot returns true | snapshot/triggers.rs ≥ 80% |
| Mutation paths emit events | Create/update/archive memory → events table has corresponding entries | Integration test |
| Migration v014 runs cleanly | Fresh DB → run all migrations → v014 tables exist | Migration test |
| No existing test regressions | `cargo test --workspace` passes | Workspace-wide |

**Property-based tests** (proptest, Phase A):
1. **Replay consistency**: For any sequence of events, `replay(events) == apply_events_one_by_one(events)`
2. **Snapshot + replay == full replay**: For any memory with events and a snapshot, reconstruction from snapshot + remaining events equals reconstruction from all events
3. **Temporal monotonicity**: event_ids are strictly increasing; recorded_at is monotonically non-decreasing
4. **Event count conservation**: events appended == events queryable (no silent drops)

**Benchmark baselines** (criterion, Phase A):
- Event append: target < 0.1ms
- Single memory reconstruction (50 events, no snapshot): target < 5ms
- Single memory reconstruction (snapshot + 10 events): target < 1ms
- Snapshot creation (single memory): target < 2ms
- Snapshot batch creation (100 memories): target < 200ms



---

## Phase B: Temporal Queries (~14 new files, ~3 modified)

Phase B builds the five temporal query types and the dual-time enforcement layer. Depends on Phase A's event store and snapshot engine being fully operational.

### Phase B — cortex-temporal New Files

```
crates/cortex/cortex-temporal/src/
├── query/
│   ├── mod.rs                          # Module declarations + TemporalQueryDispatcher
│   ├── as_of.rs                        # Point-in-time queries (TR3, Query Type 1)
│   ├── range.rs                        # Temporal range queries (TR3, Query Type 2)
│   ├── diff.rs                         # Temporal diff engine (TR3, Query Type 3)
│   └── integrity.rs                    # Temporal referential integrity (TR5)
└── dual_time/
    ├── mod.rs                          # Module declarations
    ├── validation.rs                   # Immutability enforcement (TR4)
    ├── correction.rs                   # Temporal correction semantics (TR4)
    └── late_arrival.rs                 # Late-arriving fact handling (TR4)
```

Note: `query/replay.rs` (Decision Replay, Query Type 4) and `query/temporal_causal.rs` (Temporal Causal, Query Type 5) are deferred to Phase C because they depend on cortex-causal integration.

### Phase B — cortex-storage New Files

```
crates/cortex/cortex-storage/src/queries/
├── temporal_ops.rs                     # Temporal SQL queries
```

**Modified**: `src/queries/mod.rs` — add `pub mod temporal_ops;`

### Phase B — Module Specifications

#### `src/query/mod.rs`

Module declarations and the `TemporalQueryDispatcher` — a convenience struct that routes `TemporalQuery` enum variants to the correct handler:

```
TemporalQueryDispatcher:
    engine: &TemporalEngine

    async fn dispatch(query: TemporalQuery) -> Result<TemporalQueryResult>:
        match query:
            AsOf(q) => engine.query_as_of(q)
            Range(q) => engine.query_range(q)
            Diff(q) => engine.query_diff(q)
            Replay(q) => engine.replay_decision(q)      // Phase C
            TemporalCausal(q) => engine.query_temporal_causal(q)  // Phase C
```

#### `src/query/as_of.rs` — Point-in-Time Queries (TR3, Query Type 1)

"What did we know at time T?"

The most fundamental temporal query. Reconstructs the complete knowledge state as it existed at a specific (system_time, valid_time) pair.

```
execute_as_of(reader, query: AsOfQuery) -> Result<Vec<BaseMemory>>:
    1. Get all memory_ids that existed at query.system_time
       (transaction_time <= system_time)
    2. For each memory_id:
           state = reconstruct_at(memory_id, query.system_time)
    3. Apply valid_time filter:
           keep only where state.valid_time <= query.valid_time
           AND (state.valid_until IS NULL OR state.valid_until > query.valid_time)
    4. Apply optional MemoryFilter (type, tags, files)
    5. Apply temporal referential integrity (integrity.rs)
    6. Return filtered states
```

**Bitemporal semantics** (TS1, TS3): A memory is visible at (system_time S, valid_time V) if and only if:
- `transaction_time <= S` (we had learned about it by time S)
- `valid_time <= V` (it was true at or before time V)
- `valid_until IS NULL OR valid_until > V` (it hadn't expired by time V)
- The memory was not archived at system_time S

**Optimization**: For the common case of "AS OF now" (current state), short-circuit to the existing query path — no reconstruction needed. This ensures zero overhead for non-temporal queries.

**SQL acceleration** (via `temporal_ops.rs`):
```sql
-- Fast path: get candidate memory_ids without full reconstruction
SELECT DISTINCT memory_id FROM memory_events
WHERE recorded_at <= @system_time
INTERSECT
SELECT id FROM memories
WHERE transaction_time <= @system_time
  AND valid_time <= @valid_time
  AND (valid_until IS NULL OR valid_until > @valid_time);
```

Then reconstruct only the candidate memories, not all 10K.

#### `src/query/range.rs` — Temporal Range Queries (TR3, Query Type 2)

"What memories were active during this period?"

```
execute_range(reader, query: TemporalRangeQuery) -> Result<Vec<BaseMemory>>:
    match query.mode:
        Overlaps:
            -- memory was valid at any point in [from, to]
            SELECT * FROM memories
            WHERE valid_time <= @to
              AND (valid_until IS NULL OR valid_until >= @from)
              AND transaction_time <= @to
              AND archived = 0;

        Contains:
            -- memory was valid for the entire [from, to]
            SELECT * FROM memories
            WHERE valid_time <= @from
              AND (valid_until IS NULL OR valid_until >= @to)
              AND transaction_time <= @from;

        StartedDuring:
            -- memory became valid during [from, to]
            SELECT * FROM memories
            WHERE valid_time >= @from AND valid_time <= @to
              AND transaction_time <= @to;

        EndedDuring:
            -- memory stopped being valid during [from, to]
            SELECT * FROM memories
            WHERE valid_until >= @from AND valid_until <= @to
              AND transaction_time <= @to;
```

**Optimization**: Range queries can often be answered directly from the `memories` table using the new temporal indexes (`idx_memories_valid_range`, `idx_memories_transaction_range`) without event replay. Only memories that were modified during the range need reconstruction to determine their exact state at the range boundaries.

#### `src/query/diff.rs` — Temporal Diff Engine (TR3, Query Type 3)

"What changed between time A and time B?"

The most powerful query type. Compares two knowledge states and returns a structured delta.

```
execute_diff(reader, query: TemporalDiffQuery) -> Result<TemporalDiff>:
    // Optimization: event-range diff instead of full state reconstruction
    1. events = get_all_events_in_range(query.time_a, query.time_b)
    2. Group events by memory_id
    3. For each memory_id with events in range:
           first_event = earliest event in range
           last_event = latest event in range
           if first_event.type == Created:
               → memory was created in this range → add to diff.created
           if last_event.type == Archived:
               → memory was archived in this range → add to diff.archived
           else:
               → memory was modified → reconstruct state at time_a and time_b
               → compute field-level diff → add to diff.modified
    4. Compute confidence_shifts: memories where |confidence_b - confidence_a| > 0.2
    5. Compute contradiction changes: contradictions at time_b minus contradictions at time_a
    6. Compute DiffStats:
           memories_at_a = count of active memories at time_a
           memories_at_b = count of active memories at time_b
           net_change = memories_at_b - memories_at_a
           avg_confidence_at_a = mean confidence at time_a
           avg_confidence_at_b = mean confidence at time_b
           confidence_trend = avg_confidence_at_b - avg_confidence_at_a
           knowledge_churn_rate = (created.len() + archived.len()) as f64 / memories_at_a as f64
    7. Apply scope filter (DiffScope::All, Types, Files, Namespace)
    8. Return TemporalDiff
```

**Performance**: O(events_in_range) instead of O(total_memories × 2). For a 2-week sprint diff with ~500 events across 10K memories, this is ~100ms with snapshots.

**Key property**: `diff(T, T) == empty diff` for any time T. This is a property test.
**Key property**: `diff(A, B).created == diff(B, A).archived` — symmetry.

#### `src/query/integrity.rs` — Temporal Referential Integrity (TR5)

Ensures that when querying memories at a past point in time, all references also resolve at that same point in time. Prevents temporal anomalies.

```
enforce_temporal_integrity(memories, query_time) -> Vec<BaseMemory>:
    for each memory in memories:
        // Filter linked_patterns: keep only patterns that existed at query_time
        memory.linked_patterns.retain(|p| pattern_existed_at(p, query_time))
        
        // Filter linked_files: keep only file links where content_hash was valid at query_time
        memory.linked_files.retain(|f| file_link_valid_at(f, query_time))
        
        // Filter linked_functions: keep only function links that existed at query_time
        memory.linked_functions.retain(|f| function_existed_at(f, query_time))
        
        // Filter superseded_by/supersedes: only if the referenced memory existed at query_time
        if memory.superseded_by is Some(id) and !memory_existed_at(id, query_time):
            memory.superseded_by = None
    
    return memories
```

**Temporal join constraint** for relationships:
```sql
-- Two memories are "related at time T" only if both were valid at T and both were known at T
SELECT m1.*, m2.*
FROM memories m1
JOIN memory_relationships mr ON m1.id = mr.source_id
JOIN memories m2 ON mr.target_id = m2.id
WHERE m1.valid_time <= @query_valid_time
  AND (m1.valid_until IS NULL OR m1.valid_until > @query_valid_time)
  AND m1.transaction_time <= @query_system_time
  AND m2.valid_time <= @query_valid_time
  AND (m2.valid_until IS NULL OR m2.valid_until > @query_valid_time)
  AND m2.transaction_time <= @query_system_time;
```

Applied automatically by all query types. The developer never sees a temporally inconsistent result.

#### `src/dual_time/validation.rs` — Immutability Enforcement (TR4)

```
validate_transaction_time_immutability(old_memory, new_memory) -> Result<()>:
    if old_memory.transaction_time != new_memory.transaction_time:
        return Err(TemporalError::ImmutableFieldViolation(
            "transaction_time cannot be modified after creation"
        ))
    Ok(())

validate_temporal_bounds(memory) -> Result<()>:
    if let Some(valid_until) = memory.valid_until:
        if memory.valid_time > valid_until:
            return Err(TemporalError::InvalidTemporalBounds(
                "valid_time must be <= valid_until"
            ))
    Ok(())
```

**Integration point**: Called from `memory_crud.rs` update path. Rejects any update that attempts to modify `transaction_time`.

#### `src/dual_time/correction.rs` — Temporal Correction Semantics (TR4)

When we discover a fact was wrong, we don't delete the old record. We close it and create a corrected version.

```
apply_temporal_correction(writer, memory_id, corrected_valid_time, corrected_valid_until) -> Result<()>:
    1. old_memory = get_memory(memory_id)
    2. Set old_memory.system_until = now()  // close the old version
    3. Create new memory with:
           transaction_time = now()  // when we learned the correction
           valid_time = corrected_valid_time  // corrected real-world time
           valid_until = corrected_valid_until
           // all other fields copied from old_memory
    4. Set new_memory.supersedes = old_memory.id
    5. Set old_memory.superseded_by = new_memory.id
    6. Emit TemporalCorrection events for both memories
```

The old record remains queryable at its original system_time. The new record is the "current truth."

#### `src/dual_time/late_arrival.rs` — Late-Arriving Facts (TR4)

When we learn about something that happened in the past:

```
handle_late_arriving_fact(memory, actual_valid_time) -> BaseMemory:
    // "We discovered yesterday that the auth module was refactored last month"
    memory.transaction_time = Utc::now()      // when we learned it
    memory.valid_time = actual_valid_time      // when it actually happened
    // Validate: valid_time < transaction_time (late discovery quadrant)
    assert!(memory.valid_time < memory.transaction_time)
    return memory
```

**The four temporal quadrants** (from TS1):
- Known history: both times in the past (standard memories)
- Predicted: valid_time in the future (e.g., "this constraint applies starting next sprint")
- Late discovery: valid_time < transaction_time (we learned about it after it happened)
- Unknown future: not yet created

#### `cortex-storage/src/queries/temporal_ops.rs`

Raw SQL operations for temporal queries. No business logic — just data access.

```
get_memories_valid_at(conn, valid_time, system_time) -> Result<Vec<BaseMemory>>:
    SELECT * FROM memories
    WHERE transaction_time <= @system_time
      AND valid_time <= @valid_time
      AND (valid_until IS NULL OR valid_until > @valid_time)
      AND archived = 0;

get_memories_in_range(conn, from, to, mode) -> Result<Vec<BaseMemory>>:
    // SQL varies by TemporalRangeMode (see range.rs above)

get_memories_modified_between(conn, from, to) -> Result<Vec<String>>:
    SELECT DISTINCT memory_id FROM memory_events
    WHERE recorded_at >= @from AND recorded_at <= @to;
```

### Phase B — Quality Gate (QG-T1)

**Prerequisite**: Phase A QG-T0 passed with ≥ 80% coverage on all Phase A modules.

| Test | Pass Criteria | Coverage Target |
|------|---------------|-----------------|
| AS OF current time == current state | query_as_of(now()) returns same results as normal query | query/as_of.rs ≥ 80% |
| AS OF past time excludes future memories | Create memory at T2 → AS OF T1 → memory not in results | query/as_of.rs ≥ 80% |
| AS OF respects valid_time | Memory valid_time=March, valid_until=April → AS OF May → not visible | query/as_of.rs ≥ 80% |
| AS OF respects transaction_time | Memory created at T2 → AS OF T1 → not visible (not yet known) | query/as_of.rs ≥ 80% |
| Range Overlaps mode | Memory valid March-May → range April-June → visible | query/range.rs ≥ 80% |
| Range Contains mode | Memory valid March-May → range April-April → visible; range Feb-June → not visible | query/range.rs ≥ 80% |
| Range StartedDuring mode | Memory valid_time=April → range March-May → visible | query/range.rs ≥ 80% |
| Range EndedDuring mode | Memory valid_until=April → range March-May → visible | query/range.rs ≥ 80% |
| Diff identity | diff(T, T) == empty diff for any T | query/diff.rs ≥ 80% |
| Diff symmetry | diff(A,B).created == diff(B,A).archived | query/diff.rs ≥ 80% |
| Diff detects created memories | Create memory between A and B → appears in diff.created | query/diff.rs ≥ 80% |
| Diff detects archived memories | Archive memory between A and B → appears in diff.archived | query/diff.rs ≥ 80% |
| Diff detects modifications | Update memory between A and B → appears in diff.modified | query/diff.rs ≥ 80% |
| Diff stats are correct | Known fixture → stats match expected values | query/diff.rs ≥ 80% |
| Temporal integrity filters dangling refs | Memory A refs B (created later) → AS OF before B → ref removed | query/integrity.rs ≥ 80% |
| Temporal integrity preserves valid refs | Memory A refs B (both exist at T) → AS OF T → ref preserved | query/integrity.rs ≥ 80% |
| transaction_time immutability | Attempt to update transaction_time → error | dual_time/validation.rs ≥ 80% |
| Temporal bounds validation | valid_time > valid_until → error | dual_time/validation.rs ≥ 80% |
| Temporal correction creates new version | Correct memory → old version closed, new version created | dual_time/correction.rs ≥ 80% |
| Late-arriving fact sets correct times | Late fact → transaction_time=now, valid_time=past | dual_time/late_arrival.rs ≥ 80% |
| No existing test regressions | `cargo test --workspace` passes | Workspace-wide |

**Property-based tests** (proptest, Phase B):
1. **AS OF current == current**: For any set of memories, `query_as_of(now()) == get_all_active_memories()`
2. **Diff identity**: For any time T, `diff(T, T) == TemporalDiff::empty()`
3. **Diff symmetry**: For any times A, B: `diff(A,B).created.len() == diff(B,A).archived.len()`
4. **Temporal referential integrity**: For any AS OF query result, no memory references a non-existent memory at that time
5. **Temporal bounds**: For any memory, `valid_time <= valid_until` (when valid_until is Some)

**Benchmark additions** (criterion, Phase B):
- Point-in-time query (single memory): target < 5ms cold, < 1ms warm
- Point-in-time query (all 10K memories): target < 500ms cold, < 50ms warm
- Temporal diff (two points, 10K memories): target < 1s cold, < 100ms warm
- Range query (Overlaps mode, 10K memories): target < 50ms



---

## Phase C: Decision Replay + Temporal Causal (~6 new files, ~3 modified)

Phase C builds the two most novel query types — Decision Replay and Temporal Causal — plus the temporal graph reconstruction in cortex-causal. These are the features that no other system offers.

### Phase C — cortex-temporal New Files

```
crates/cortex/cortex-temporal/src/query/
├── replay.rs                           # Decision replay (TR3, Query Type 4)
└── temporal_causal.rs                  # Temporal causal queries (TR3, Query Type 5)
```

### Phase C — cortex-causal New Files

```
crates/cortex/cortex-causal/src/graph/
└── temporal_graph.rs                   # Historical graph reconstruction (TR10)
```

### Phase C — cortex-causal Modified Files

- `src/graph/mod.rs` — add `pub mod temporal_graph;`
- `src/graph/sync.rs` — already modified in Phase A for event emission; Phase C adds the reconstruction consumer

### Phase C — Module Specifications

#### `cortex-temporal/src/query/replay.rs` — Decision Replay (TR3, Query Type 4)

"Reconstruct the exact context available when Decision X was made."

This is the "audit" query. Given a decision memory, it reconstructs what the retrieval engine would have returned at the time that decision was recorded.

```
execute_replay(reader, query: DecisionReplayQuery) -> Result<DecisionReplay>:
    1. decision_memory = get_memory(query.decision_memory_id)
    2. decision_time = decision_memory.transaction_time
    
    // Reconstruct the world as it was when the decision was made
    3. available_context = reconstruct_all_at(decision_time, None)
    
    // Simulate what retrieval would have returned
    4. decision_topic = decision_memory.content.summary()
    5. retrieved_context = simulate_retrieval(
           available_context,
           decision_topic,
           budget=query.budget_override.unwrap_or(2000)
       )
    
    // Reconstruct the causal graph at decision time
    6. causal_state = reconstruct_causal_graph_at(decision_time)
    
    // Compute hindsight: what we know NOW but didn't THEN
    7. current_memories = get_all_active_memories()
    8. new_since_decision = current_memories.filter(|m| m.transaction_time > decision_time)
    9. hindsight = new_since_decision
           .filter(|m| embedding_similarity(m, decision_memory) > 0.7)
           .map(|m| HindsightItem {
               memory: m,
               relevance: embedding_similarity(m, decision_memory),
               relationship: classify_relationship(m, decision_memory),
           })
           .sorted_by(|a, b| b.relevance.cmp(&a.relevance))
    
    10. return DecisionReplay {
            decision: reconstruct_at(decision_memory.id, decision_time),
            available_context,
            retrieved_context,
            causal_state,
            hindsight,
        }
```

**Why this is novel**: No existing AI memory system offers decision replay. Zep/Graphiti (TS8) tracks temporal relationships but can't reconstruct past retrieval contexts. T-GRAG (TS7) handles temporal queries but operates on static document corpora. Decision replay requires the intersection of temporal state reconstruction + retrieval simulation + causal graph reconstruction — all three of which Cortex uniquely has.

**The hindsight computation** answers: "Was this a good decision given what we knew? Would we make the same decision with what we know now?"

**Evidence from TS11**: 20-25% of architectural decisions had stale evidence within two months. Decision replay makes this discoverable.

**`classify_relationship`** determines how a hindsight item relates to the decision:
- `"contradicts"` — the new memory contradicts the decision's reasoning
- `"would_have_informed"` — the new memory is relevant and would have changed the context
- `"supersedes"` — the new memory directly supersedes knowledge used in the decision
- `"supports"` — the new memory reinforces the decision

#### `cortex-temporal/src/query/temporal_causal.rs` — Temporal Causal Queries (TR3, Query Type 5)

"At the time we adopted Pattern X, what was the causal chain?"

Delegates to cortex-causal's temporal graph reconstruction, then runs traversal on the historical graph.

```
execute_temporal_causal(reader, query: TemporalCausalQuery) -> Result<TraversalResult>:
    1. historical_graph = cortex_causal::temporal_graph::reconstruct_graph_at(
           event_store, query.as_of
       )
    2. result = cortex_causal::traversal::traverse(
           &historical_graph,
           query.memory_id,
           query.direction,
           query.max_depth,
       )
    3. return result
```

This reuses cortex-causal's existing traversal and narrative generation, just on a reconstructed historical graph instead of the current one.

#### `cortex-causal/src/graph/temporal_graph.rs` — Historical Graph Reconstruction (TR10)

```
reconstruct_graph_at(event_store, as_of: DateTime<Utc>) -> StableGraph<MemoryId, CausalEdge>:
    1. added_events = get_events_by_type('relationship_added', before=as_of)
    2. removed_events = get_events_by_type('relationship_removed', before=as_of)
    3. strength_events = get_events_by_type('strength_updated', before=as_of)
    
    4. Build edge set:
       edges = {}
       for event in added_events (ordered by event_id):
           edges[(event.source, event.target)] = CausalEdge {
               relation_type: event.delta.relation_type,
               strength: event.delta.strength,
           }
       for event in removed_events (ordered by event_id):
           edges.remove((event.source, event.target))
       for event in strength_events (ordered by event_id):
           if (event.source, event.target) in edges:
               edges[(event.source, event.target)].strength = event.delta.new_strength
    
    5. Build StableGraph from edge set
    6. return graph

temporal_traversal(
    event_store,
    memory_id: MemoryId,
    as_of: DateTime<Utc>,
    direction: TraversalDirection,
    max_depth: usize,
) -> TraversalResult:
    graph = reconstruct_graph_at(event_store, as_of)
    // Reuse existing traversal logic on the historical graph
    traverse(&graph, memory_id, direction, max_depth)
```

**Performance**: Reconstructing a graph with 1K edges from events takes ~10ms. With weekly graph snapshots, reconstruction from snapshot + replay takes ~2ms.

### Phase C — Quality Gate (QG-T2)

**Prerequisite**: Phase B QG-T1 passed with ≥ 80% coverage on all Phase B modules.

| Test | Pass Criteria | Coverage Target |
|------|---------------|-----------------|
| Decision replay returns correct decision state | Known decision → replay → decision matches expected state | query/replay.rs ≥ 80% |
| Decision replay returns correct available context | Known decision at T → replay → context matches AS OF T | query/replay.rs ≥ 80% |
| Decision replay computes hindsight | Decision at T1, new contradicting memory at T2 → hindsight contains it | query/replay.rs ≥ 80% |
| Decision replay hindsight relevance threshold | Irrelevant memory (similarity < 0.7) → not in hindsight | query/replay.rs ≥ 80% |
| Decision replay for non-decision memory → error | Replay on episodic memory → appropriate error | query/replay.rs ≥ 80% |
| Temporal causal at current time == current graph | Temporal traversal at now() matches current traversal | query/temporal_causal.rs ≥ 80% |
| Temporal causal excludes future edges | Edge added at T2 → temporal causal at T1 → edge not in graph | query/temporal_causal.rs ≥ 80% |
| Temporal causal respects edge removal | Edge added at T1, removed at T2 → temporal causal at T3 → edge not in graph | query/temporal_causal.rs ≥ 80% |
| Temporal causal respects strength updates | Edge strength changed at T2 → temporal causal at T1 → old strength | temporal_graph.rs ≥ 80% |
| Graph reconstruction from events | Known edge sequence → reconstruct → graph matches expected | temporal_graph.rs ≥ 80% |
| No existing test regressions | `cargo test --workspace` passes | Workspace-wide |

**Property-based tests** (proptest, Phase C):
1. **Temporal causal at current == current**: For any memory, temporal causal traversal at now() produces the same result as current causal traversal
2. **Graph reconstruction monotonicity**: Adding an edge then removing it results in the edge not being in the graph at any time after removal
3. **Hindsight completeness**: Every memory created after a decision with similarity > 0.7 appears in hindsight

**Benchmark additions** (criterion, Phase C):
- Decision replay: target < 200ms warm
- Temporal causal traversal: target < 20ms warm
- Graph reconstruction (1K edges): target < 10ms cold, < 2ms warm



---

## Phase D: Drift Detection + Epistemic + Views + Integration (~39 new files, ~13 modified)

Phase D is the largest phase. It builds the drift detection system (5 metrics + alerting + time-series + evolution patterns), the epistemic status model, materialized views, retrieval boosting integration, observability integration, NAPI bindings, TypeScript MCP tools, and CLI commands.

Phase D is subdivided into 4 sub-phases for manageability:
- D1: Drift metrics + alerting (core drift engine)
- D2: Epistemic status + views (knowledge quality layer)
- D3: Integration with existing crates (retrieval, observability, validation)
- D4: NAPI bindings + TypeScript MCP tools + CLI commands (developer-facing layer)

### Phase D1: Drift Metrics + Alerting

#### New Files

```
crates/cortex/cortex-temporal/src/drift/
├── mod.rs                              # Module declarations + re-exports
├── metrics.rs                          # 5 drift metrics (TR6)
├── evidence_freshness.rs               # Evidence freshness scoring (TR6, Metric 5)
├── alerting.rs                         # Drift alert evaluation (TR7)
├── snapshots.rs                        # Drift time-series storage (TR8)
└── patterns.rs                         # Evolution pattern detection (TR12)
```

#### New cortex-storage Files

```
crates/cortex/cortex-storage/src/queries/
├── drift_ops.rs                        # Drift snapshot SQL operations
```

**Modified**: `src/queries/mod.rs` — add `pub mod drift_ops;`

#### Module Specifications

##### `src/drift/metrics.rs` — Five Drift Metrics (TR6)

**Metric 1: Knowledge Stability Index (KSI)**

Measures how stable the knowledge base is over a time window.

```
compute_ksi(reader, memory_type: Option<MemoryType>, window: Duration) -> f64:
    start = now() - window
    created = count memories of type created since start
    archived = count memories of type archived since start
    modified = count memories of type with events since start (excluding created/archived)
    total_at_start = count active memories of type at start
    
    if total_at_start == 0: return 1.0  // no memories = perfectly stable
    
    ksi = 1.0 - (created + archived + modified) as f64 / (2.0 * total_at_start as f64)
    return ksi.clamp(0.0, 1.0)
```

- KSI = 1.0: perfectly stable, nothing changed
- KSI = 0.5: moderate churn, half the knowledge base changed
- KSI < 0.3: high churn, knowledge is unstable

Per-type KSI is critical: Episodic KSI is naturally low (episodes are transient). Core KSI should be high. If Tribal KSI drops below 0.5, team norms are shifting.

**Metric 2: Confidence Trajectory**

```
compute_confidence_trajectory(reader, memory_type: Option<MemoryType>, window: Duration, points: usize) -> Vec<f64>:
    interval = window / points
    for i in 0..points:
        t = now() - window + (interval * i)
        avg = average confidence of active memories of type at time t
        trajectory.push(avg)
    return trajectory
```

- Rising: knowledge is being validated and reinforced
- Falling: knowledge is decaying or being contradicted
- Flat: stable but possibly stagnant

**Metric 3: Contradiction Density**

```
compute_contradiction_density(reader, memory_type: Option<MemoryType>, window: Duration) -> f64:
    start = now() - window
    new_contradictions = count contradictions detected since start (from validation events)
    total_memories = count active memories of type
    
    if total_memories == 0: return 0.0
    return new_contradictions as f64 / total_memories as f64
```

- < 0.02: healthy
- 0.02 - 0.10: some disagreement, worth monitoring
- > 0.10: internally inconsistent, needs attention

**Metric 4: Consolidation Efficiency**

```
compute_consolidation_efficiency(reader, window: Duration) -> f64:
    start = now() - window
    semantic_created = count semantic memories created since start (from consolidation)
    episodic_archived = count episodic memories archived since start
    
    if episodic_archived == 0: return 1.0  // nothing to consolidate
    return semantic_created as f64 / episodic_archived as f64
```

- Ratio > 0.5: good — most episodes consolidated into lasting knowledge
- Ratio < 0.2: poor — episodes archived without extracting value
- Ratio > 1.0: excellent — consolidation creating more knowledge than it consumes

**Metric 5: Evidence Freshness Score (Novel — inspired by TS11)**

```
compute_evidence_freshness(reader, memory: &BaseMemory) -> f64:
    factors = []
    for link in memory.linked_files:
        if current_content_hash(link.path) == link.content_hash:
            factors.push(1.0)
        else:
            factors.push(0.5)  // file changed since link was created
    
    for link in memory.linked_patterns:
        if pattern_still_active(link):
            factors.push(1.0)
        else:
            factors.push(0.3)  // pattern no longer active
    
    // Supporting memory freshness = that memory's confidence
    for ref_id in get_supporting_memories(memory):
        ref_memory = get_memory(ref_id)
        factors.push(ref_memory.confidence)
    
    // User validation freshness decays with half-life of 90 days
    if let Some(last_validated) = memory.last_validated:
        days_since = (now() - last_validated).num_days()
        factors.push((-days_since as f64 / 90.0 * 0.693).exp())  // exponential decay
    
    if factors.is_empty(): return 1.0  // no evidence = assume fresh
    return factors.iter().product()  // product aggregation
```

**Aggregate**: Evidence Freshness Index (EFI) = average evidence freshness across all active memories.

**`compute_all_metrics`** — computes all 5 metrics and assembles a `DriftSnapshot`:

```
compute_all_metrics(reader, window: Duration) -> DriftSnapshot:
    type_metrics = for each MemoryType:
        TypeDriftMetrics {
            count, avg_confidence,
            ksi: compute_ksi(type, window),
            contradiction_density: compute_contradiction_density(type, window),
            consolidation_efficiency: compute_consolidation_efficiency(window),
            evidence_freshness_index: avg evidence_freshness for type,
        }
    
    module_metrics = for each file module:
        ModuleDriftMetrics { memory_count, coverage_ratio, avg_confidence, churn_rate }
    
    global = GlobalDriftMetrics {
        total_memories, active_memories, archived_memories,
        avg_confidence, overall_ksi, overall_contradiction_density,
        overall_evidence_freshness,
    }
    
    return DriftSnapshot { timestamp: now(), window, type_metrics, module_metrics, global }
```

##### `src/drift/alerting.rs` — Drift Alert Evaluation (TR7)

```
evaluate_drift_alerts(snapshot: &DriftSnapshot, config: &TemporalConfig, recent_alerts: &[DriftAlert]) -> Vec<DriftAlert>:
    alerts = []
    
    // KSI alerts
    for (type, metrics) in snapshot.type_metrics:
        threshold = match type:
            Core | Tribal => config.alert_ksi_threshold  // 0.3
            Semantic => 0.5
            _ => 0.2  // episodic types have naturally low KSI
        if metrics.ksi < threshold:
            if not dampened(KnowledgeChurn, type, recent_alerts, config):
                alerts.push(DriftAlert {
                    severity: Warning,
                    category: KnowledgeChurn { memory_type: type, ksi: metrics.ksi, threshold },
                    message: format!("{type} knowledge stability dropped to {:.2}", metrics.ksi),
                    recommended_action: "Review recent changes to {type} memories",
                })
    
    // Confidence erosion alerts
    for (type, trajectory) in confidence_trajectories:
        declining_windows = count consecutive declining points at end of trajectory
        if declining_windows >= config.alert_confidence_erosion_windows:
            if not dampened(ConfidenceErosion, type, recent_alerts, config):
                alerts.push(...)
    
    // Contradiction spike alerts
    for (type, metrics) in snapshot.type_metrics:
        if metrics.contradiction_density > config.alert_contradiction_density_threshold:
            alerts.push(DriftAlert { severity: Critical, ... })
    
    // Stale evidence alerts
    for memory in high_importance_memories:
        freshness = compute_evidence_freshness(memory)
        if freshness < config.alert_evidence_freshness_threshold:
            alerts.push(DriftAlert { severity: Warning, ... })
    
    // Knowledge explosion alerts
    for (module, metrics) in snapshot.module_metrics:
        if metrics.churn_rate > baseline + config.alert_explosion_sigma * stddev:
            alerts.push(DriftAlert { severity: Info, ... })
    
    return alerts
```

**Alert dampening**: Each alert category has a cooldown period. Before firing an alert, check if the same category + affected entity was alerted within the cooldown window. Default: 24 hours for warnings, 1 hour for critical.

##### `src/drift/snapshots.rs` — Drift Time-Series Storage (TR8)

```
store_drift_snapshot(writer, snapshot: &DriftSnapshot) -> Result<u64>:
    serialized = serde_json::to_string(snapshot)
    drift_ops::insert_drift_snapshot(writer, timestamp, window_seconds, serialized)

get_drift_snapshots(reader, from: DateTime<Utc>, to: DateTime<Utc>) -> Vec<DriftSnapshot>:
    raw = drift_ops::get_drift_snapshots(reader, from, to)
    raw.map(|r| serde_json::from_str(&r.metrics))

get_latest_drift_snapshot(reader) -> Option<DriftSnapshot>:
    raw = drift_ops::get_latest_drift_snapshot(reader)
    raw.map(|r| serde_json::from_str(&r.metrics))
```

**Snapshot frequency**:
- Hourly: lightweight counters only (memory count, avg confidence) — if `drift_hourly_enabled`
- Daily: full drift metrics per type and module — if `drift_daily_enabled`
- Weekly: comprehensive snapshot with trend analysis — if `drift_weekly_enabled`

##### `src/drift/patterns.rs` — Evolution Pattern Detection (TR12)

Four higher-order patterns in how knowledge evolves:

```
detect_crystallization(reader, topic_cluster: &[MemoryId]) -> Option<CrystallizationPattern>:
    // Track lifecycle: episodic → semantic → validated → stable confidence
    // Healthy clusters show this progression
    // Return time-to-crystallization and current stage

detect_erosion(reader, memory_cluster: &[MemoryId]) -> Option<ErosionPattern>:
    // Confidence trajectory turned negative for 2+ consecutive windows
    // Citations going stale, patterns no longer followed
    // Return affected memories and recommended action

detect_explosion(reader, module: &str, baseline_window: Duration) -> Option<ExplosionPattern>:
    // Memory creation rate exceeds 3σ above rolling average
    // New feature development, major refactor, or incident response
    // Return rate, baseline, and recommendation to trigger consolidation

detect_conflict_wave(reader, window: Duration) -> Option<ConflictWavePattern>:
    // Contradiction density spikes > 2× baseline, concentrated in specific area
    // Convention change creating wave of contradictions
    // Return hotspot and recommendation for targeted validation
```

Each pattern returns a detection result + recommended action string.

### Phase D1 — Quality Gate (QG-T3a)

| Test | Pass Criteria | Coverage Target |
|------|---------------|-----------------|
| KSI = 1.0 for stable dataset | No changes in window → KSI = 1.0 | drift/metrics.rs ≥ 80% |
| KSI bounds [0.0, 1.0] | Property test: any input → 0.0 ≤ KSI ≤ 1.0 | drift/metrics.rs ≥ 80% |
| KSI per type is independent | Change only episodic → core KSI unchanged | drift/metrics.rs ≥ 80% |
| Confidence trajectory tracks correctly | Known confidence changes → trajectory matches | drift/metrics.rs ≥ 80% |
| Contradiction density = 0 for clean dataset | No contradictions → density = 0.0 | drift/metrics.rs ≥ 80% |
| Consolidation efficiency computes correctly | Known consolidation → ratio matches | drift/metrics.rs ≥ 80% |
| Evidence freshness = 1.0 for fresh evidence | All links valid → freshness = 1.0 | drift/evidence_freshness.rs ≥ 80% |
| Evidence freshness < 1.0 for stale links | File changed → freshness drops | drift/evidence_freshness.rs ≥ 80% |
| Evidence freshness bounds [0.0, 1.0] | Property test | drift/evidence_freshness.rs ≥ 80% |
| Alert fires when KSI below threshold | KSI = 0.2, threshold = 0.3 → alert generated | drift/alerting.rs ≥ 80% |
| Alert dampening works | Same alert within cooldown → not re-fired | drift/alerting.rs ≥ 80% |
| Critical alert has shorter cooldown | Critical alert re-fires after 1h, not 24h | drift/alerting.rs ≥ 80% |
| Drift snapshot round-trip | Store → retrieve → equals original | drift/snapshots.rs ≥ 80% |
| Crystallization detection | Known lifecycle progression → detected | drift/patterns.rs ≥ 80% |
| Erosion detection | Declining confidence cluster → detected | drift/patterns.rs ≥ 80% |
| Explosion detection | Spike above 3σ → detected | drift/patterns.rs ≥ 80% |
| Conflict wave detection | Contradiction spike in module → detected | drift/patterns.rs ≥ 80% |



### Phase D2: Epistemic Status + Materialized Views

#### New Files

```
crates/cortex/cortex-temporal/src/epistemic/
├── mod.rs                              # Module declarations + re-exports
├── status.rs                           # EpistemicStatus determination
├── transitions.rs                      # Status promotion/demotion logic
└── aggregation.rs                      # Confidence aggregation strategies

crates/cortex/cortex-temporal/src/views/
├── mod.rs                              # Module declarations + re-exports
├── create.rs                           # Materialized view creation
├── query.rs                            # View lookup + diff between views
└── auto_refresh.rs                     # Auto-creation scheduler
```

#### New cortex-storage Files

```
crates/cortex/cortex-storage/src/queries/
└── view_ops.rs                         # Materialized view SQL operations
```

**Modified**: `src/queries/mod.rs` — add `pub mod view_ops;`

#### Module Specifications

##### `src/epistemic/status.rs` — Epistemic Status Determination (TR11)

```
determine_initial_status(source: &EventActor) -> EpistemicStatus:
    // All new memories start as Conjecture
    EpistemicStatus::Conjecture {
        source: match source {
            EventActor::User(id) => format!("user:{}", id),
            EventActor::Agent(id) => format!("agent:{}", id),
            EventActor::System(name) => format!("system:{}", name),
        },
        created_at: Utc::now(),
    }
```

##### `src/epistemic/transitions.rs` — Status Promotion/Demotion (TR11)

```
promote_to_provisional(current: &EpistemicStatus, evidence_count: u32) -> Result<EpistemicStatus>:
    match current:
        Conjecture { .. } => Ok(EpistemicStatus::Provisional {
            evidence_count,
            last_validated: Utc::now(),
        })
        _ => Err(TemporalError::InvalidEpistemicTransition {
            from: current.variant_name(),
            to: "provisional",
        })

promote_to_verified(current: &EpistemicStatus, verified_by: Vec<String>, evidence_refs: Vec<String>) -> Result<EpistemicStatus>:
    match current:
        Provisional { .. } => Ok(EpistemicStatus::Verified {
            verified_by,
            verified_at: Utc::now(),
            evidence_refs,
        })
        _ => Err(TemporalError::InvalidEpistemicTransition {
            from: current.variant_name(),
            to: "verified",
        })

demote_to_stale(current: &EpistemicStatus, reason: String) -> Result<EpistemicStatus>:
    match current:
        Verified { verified_at, .. } => Ok(EpistemicStatus::Stale {
            was_verified_at: *verified_at,
            staleness_detected_at: Utc::now(),
            reason,
        })
        _ => Err(TemporalError::InvalidEpistemicTransition {
            from: current.variant_name(),
            to: "stale",
        })
```

**Valid transitions**:
- Conjecture → Provisional (on validation pass with evidence)
- Provisional → Verified (on user confirmation or multi-agent corroboration)
- Verified → Stale (on evidence freshness drop below threshold)
- No skipping: Conjecture cannot jump to Verified
- No backward: Verified cannot go back to Provisional (only to Stale)

##### `src/epistemic/aggregation.rs` — Confidence Aggregation (TR11)

```
aggregate_confidence(evidences: &[f64], strategy: AggregationStrategy) -> f64:
    match strategy:
        WeightedAverage =>
            // Existing approach: weighted mean
            evidences.iter().sum::<f64>() / evidences.len() as f64
        
        GodelTNorm =>
            // Conservative: min operator (from TS11, FPF paper)
            // Prevents "many weak signals = strong signal" fallacy
            evidences.iter().cloned().fold(1.0, f64::min)
```

The Gödel t-norm is more conservative than weighted average. A single weak evidence source (0.3) drags the aggregate to 0.3 regardless of how many strong sources exist. This is appropriate for high-stakes contexts (security audit, deployment decisions).

Configurable via `TemporalConfig.confidence_aggregation`. Default: WeightedAverage (backward compatible).

##### `src/views/create.rs` — Materialized View Creation (TR9)

```
create_materialized_view(writer, reader, label: &str, timestamp: DateTime<Utc>) -> Result<MaterializedTemporalView>:
    1. memories = reconstruct_all_at(timestamp, None)
    2. snapshot_ids = for each memory:
           create_snapshot(memory, SnapshotReason::OnDemand)
    3. drift_snapshot = compute_all_metrics(window=Duration::weeks(2))
    4. drift_snapshot_id = store_drift_snapshot(drift_snapshot)
    5. view = MaterializedTemporalView {
           label, timestamp,
           memory_count: memories.len(),
           snapshot_ids,
           drift_snapshot_id: Some(drift_snapshot_id),
           created_by: EventActor::System("materialized_view_engine"),
           auto_refresh: false,
       }
    6. view_ops::insert_materialized_view(writer, &view)
    7. return view
```

##### `src/views/query.rs` — View Lookup + Diff (TR9)

```
get_view(reader, label: &str) -> Option<MaterializedTemporalView>:
    view_ops::get_view_by_label(reader, label)

list_views(reader) -> Vec<MaterializedTemporalView>:
    view_ops::list_views(reader)

diff_views(reader, label_a: &str, label_b: &str) -> Result<TemporalDiff>:
    view_a = get_view(label_a)?
    view_b = get_view(label_b)?
    // Instant diff between two pre-computed views
    query_diff(TemporalDiffQuery {
        time_a: view_a.timestamp,
        time_b: view_b.timestamp,
        scope: DiffScope::All,
    })
```

##### `src/views/auto_refresh.rs` — Auto-Creation Scheduler (TR9)

```
AutoRefreshScheduler:
    config: TemporalConfig

    fn should_create_view() -> Option<String>:
        last_view = get_latest_auto_view()
        if last_view is None or elapsed > config.materialized_view_auto_interval_days:
            label = generate_label()  // e.g., "auto-2026-02-07"
            return Some(label)
        return None

    fn has_changes_since_last_view(reader) -> bool:
        last_view = get_latest_auto_view()
        if last_view is None: return true
        event_count = count events since last_view.timestamp
        return event_count > 0
```

Default interval: 14 days (sprint boundaries). Skips creation if no events since last view.

### Phase D2 — Quality Gate (QG-T3b)

| Test | Pass Criteria | Coverage Target |
|------|---------------|-----------------|
| New memory starts as Conjecture | Create memory → epistemic status = Conjecture | epistemic/status.rs ≥ 80% |
| Conjecture → Provisional on validation | Validate memory → status = Provisional | epistemic/transitions.rs ≥ 80% |
| Provisional → Verified on confirmation | Confirm memory → status = Verified | epistemic/transitions.rs ≥ 80% |
| Verified → Stale on evidence decay | Evidence freshness drops → status = Stale | epistemic/transitions.rs ≥ 80% |
| Conjecture → Verified rejected | Attempt skip → InvalidEpistemicTransition error | epistemic/transitions.rs ≥ 80% |
| Verified → Provisional rejected | Attempt backward → InvalidEpistemicTransition error | epistemic/transitions.rs ≥ 80% |
| WeightedAverage aggregation correct | Known inputs → expected output | epistemic/aggregation.rs ≥ 80% |
| GodelTNorm aggregation = min | [0.9, 0.3, 0.8] → 0.3 | epistemic/aggregation.rs ≥ 80% |
| Materialized view creation | Create view → view exists with correct memory count | views/create.rs ≥ 80% |
| Materialized view lookup | Create → lookup by label → found | views/query.rs ≥ 80% |
| Diff between views | Create view A, create view B → diff returns correct delta | views/query.rs ≥ 80% |
| Auto-refresh scheduler fires | Elapsed > interval → should_create_view returns label | views/auto_refresh.rs ≥ 80% |
| Auto-refresh skips when no changes | No events since last view → should_create_view returns None | views/auto_refresh.rs ≥ 80% |

### Phase D3: Integration with Existing Crates

#### Modified Files

**cortex-retrieval** (TR13, CR8):
- `src/ranking/scorer.rs` — add 2 new scoring factors
- `src/ranking/mod.rs` — update ScorerWeights default

The existing 8-factor additive scorer gains 2 temporal factors. Weights are redistributed to maintain sum = 1.0:

```
Existing weights (redistributed):
    semantic_similarity:  0.22  (was 0.25)
    keyword_match:        0.13  (was 0.15)
    file_proximity:       0.10  (unchanged)
    pattern_alignment:    0.08  (was 0.10)
    recency:              0.10  (unchanged)
    confidence:           0.10  (unchanged)
    importance:           0.08  (was 0.10)
    intent_type_match:    0.08  (was 0.10)

New temporal weights:
    evidence_freshness:   0.06  (new)
    epistemic_status:     0.05  (new)

Total: 1.00
```

**Epistemic status scoring**:
- Verified: 1.0
- Provisional: 0.7
- Conjecture: 0.4
- Stale: 0.2

**Evidence freshness scoring**: Direct value from `compute_evidence_freshness()` [0.0, 1.0].

**cortex-validation** (TR11):
- `src/engine.rs` — after validation pass/fail, trigger epistemic status transition
  - Pass all 4 dimensions → promote to Provisional (if currently Conjecture)
  - Pass all 4 dimensions + user confirmation → promote to Verified
  - Fail → no demotion (epistemic status only degrades via evidence decay, not validation failure)
- `src/dimensions/temporal.rs` — add temporal consistency check
  - Memory references should be temporally consistent (referenced memories must have existed when the referencing memory was created)

**cortex-observability** (TR7):
- `src/health/reporter.rs` — add `drift_summary: Option<DriftSummary>` to `HealthSnapshot`
  - `DriftSummary`: active_alerts count, overall_ksi, overall_efi, trend indicators
- `src/health/subsystem_checks.rs` — add `check_temporal(snapshot) -> SubsystemHealth`
  - Checks: event store health, snapshot freshness, drift alert count
- `src/health/recommendations.rs` — add temporal-specific recommendations
  - "Run snapshot compaction" if events > threshold
  - "Review stale evidence" if EFI < 0.5
  - "Investigate knowledge churn" if KSI < 0.3

### Phase D3 — Quality Gate (QG-T3c)

| Test | Pass Criteria | Coverage Target |
|------|---------------|-----------------|
| Retrieval scorer includes temporal factors | Score with temporal factors ≠ score without | scorer.rs changes ≥ 80% |
| Verified memory scores higher than Conjecture | Same memory, different epistemic status → Verified scores higher | scorer.rs changes ≥ 80% |
| Evidence freshness affects retrieval ranking | Fresh evidence memory ranks above stale evidence memory | scorer.rs changes ≥ 80% |
| Weights sum to 1.0 | Assert all 10 weights sum to 1.0 | scorer.rs changes ≥ 80% |
| Validation promotes epistemic status | Validate Conjecture memory → becomes Provisional | validation engine changes ≥ 80% |
| Validation does not demote on failure | Fail validation on Provisional → stays Provisional | validation engine changes ≥ 80% |
| Health report includes drift summary | Generate health report → drift_summary present | reporter.rs changes ≥ 80% |
| Subsystem check reports temporal health | check_temporal → returns SubsystemHealth | subsystem_checks.rs changes ≥ 80% |
| Temporal recommendations generated | Low KSI → recommendation includes "investigate churn" | recommendations.rs changes ≥ 80% |
| No existing retrieval test regressions | `cargo test -p cortex-retrieval` passes | Existing tests |
| No existing validation test regressions | `cargo test -p cortex-validation` passes | Existing tests |
| No existing observability test regressions | `cargo test -p cortex-observability` passes | Existing tests |



### Phase D4: NAPI Bindings + TypeScript MCP Tools + CLI Commands

#### New cortex-napi Files

```
crates/cortex/cortex-napi/src/bindings/
└── temporal.rs                         # NAPI bindings for temporal operations

crates/cortex/cortex-napi/src/conversions/
└── temporal_types.rs                   # Rust ↔ JS type conversions
```

**Modified**:
- `src/bindings/mod.rs` — add `pub mod temporal;`
- `src/conversions/mod.rs` — add `pub mod temporal_types;`

##### `cortex-napi/src/bindings/temporal.rs`

10 `#[napi]` functions exposing the full temporal API to TypeScript:

```
#[napi] query_as_of(system_time: String, valid_time: String, filter: Option<String>) -> Vec<NapiBaseMemory>
#[napi] query_range(from: String, to: String, mode: String) -> Vec<NapiBaseMemory>
#[napi] query_diff(time_a: String, time_b: String, scope: Option<String>) -> NapiTemporalDiff
#[napi] replay_decision(decision_id: String, budget: Option<u32>) -> NapiDecisionReplay
#[napi] query_temporal_causal(memory_id: String, as_of: String, direction: String, depth: u32) -> NapiTraversalResult
#[napi] get_drift_metrics(window_hours: Option<u32>) -> NapiDriftSnapshot
#[napi] get_drift_alerts() -> Vec<NapiDriftAlert>
#[napi] create_materialized_view(label: String, timestamp: String) -> NapiMaterializedView
#[napi] get_materialized_view(label: String) -> Option<NapiMaterializedView>
#[napi] list_materialized_views() -> Vec<NapiMaterializedView>
```

All time parameters are ISO 8601 strings (parsed to `DateTime<Utc>` in Rust). This matches the existing NAPI pattern where complex types are serialized as JSON strings.

##### `cortex-napi/src/conversions/temporal_types.rs`

NAPI-friendly versions of all temporal types. Each has `From<RustType>` and `Into<RustType>` implementations:

- `NapiMemoryEvent` — JS-friendly MemoryEvent
- `NapiDriftSnapshot` — JS-friendly DriftSnapshot (nested metrics flattened for JS consumption)
- `NapiDriftAlert` — JS-friendly DriftAlert
- `NapiTemporalDiff` — JS-friendly TemporalDiff
- `NapiDecisionReplay` — JS-friendly DecisionReplay
- `NapiMaterializedView` — JS-friendly MaterializedTemporalView
- `NapiHindsightItem` — JS-friendly HindsightItem
- `NapiDiffStats` — JS-friendly DiffStats

#### TypeScript Bridge Modifications

**Modified**: `packages/cortex/src/bridge/types.ts`

Add TypeScript interfaces matching every NAPI type:

```typescript
interface TemporalDiff { created: BaseMemory[]; archived: BaseMemory[]; modified: MemoryModification[]; stats: DiffStats; ... }
interface DiffStats { memoriesAtA: number; memoriesAtB: number; netChange: number; ... }
interface DecisionReplay { decision: BaseMemory; availableContext: BaseMemory[]; hindsight: HindsightItem[]; ... }
interface HindsightItem { memory: BaseMemory; relevance: number; relationship: string; }
interface DriftSnapshot { timestamp: string; global: GlobalDriftMetrics; typeMetrics: Record<string, TypeDriftMetrics>; ... }
interface DriftAlert { severity: 'info' | 'warning' | 'critical'; category: string; message: string; ... }
interface MaterializedTemporalView { viewId: number; label: string; timestamp: string; memoryCount: number; ... }
interface EpistemicStatus { type: 'conjecture' | 'provisional' | 'verified' | 'stale'; ... }
interface AsOfQuery { systemTime: string; validTime: string; filter?: MemoryFilter; }
interface TemporalRangeQuery { from: string; to: string; mode: 'overlaps' | 'contains' | 'started_during' | 'ended_during'; }
interface TemporalDiffQuery { timeA: string; timeB: string; scope?: string; }
interface DecisionReplayQuery { decisionMemoryId: string; budgetOverride?: number; }
interface TemporalCausalQuery { memoryId: string; asOf: string; direction: string; maxDepth: number; }
```

**Modified**: `packages/cortex/src/bridge/client.ts`

Add 10 temporal methods to the bridge client:

```typescript
async queryAsOf(systemTime: string, validTime: string, filter?: MemoryFilter): Promise<BaseMemory[]>
async queryRange(from: string, to: string, mode: TemporalRangeMode): Promise<BaseMemory[]>
async queryDiff(timeA: string, timeB: string, scope?: DiffScope): Promise<TemporalDiff>
async replayDecision(decisionId: string, budget?: number): Promise<DecisionReplay>
async queryTemporalCausal(memoryId: string, asOf: string, direction: string, maxDepth: number): Promise<TraversalResult>
async getDriftMetrics(windowHours?: number): Promise<DriftSnapshot>
async getDriftAlerts(): Promise<DriftAlert[]>
async createMaterializedView(label: string, timestamp: string): Promise<MaterializedTemporalView>
async getMaterializedView(label: string): Promise<MaterializedTemporalView | null>
async listMaterializedViews(): Promise<MaterializedTemporalView[]>
```

#### New MCP Tools (5 tools)

```
packages/cortex/src/tools/temporal/
├── drift_time_travel.ts                # Point-in-time knowledge query
├── drift_time_diff.ts                  # Compare knowledge between two times
├── drift_time_replay.ts                # Replay decision context
├── drift_knowledge_health.ts           # Drift metrics dashboard
└── drift_knowledge_timeline.ts         # Visualize knowledge evolution
```

**Modified**: `packages/cortex/src/tools/index.ts` — register all 5 new tools

##### `drift_time_travel` — Point-in-Time Knowledge Query

```
Tool: drift_time_travel
Input:
    system_time: string (ISO 8601) — "what was recorded by this time"
    valid_time: string (ISO 8601) — "what was true at this time"
    filter?: { types?: string[], tags?: string[], files?: string[] }
Output:
    memories: BaseMemory[] — memories as they existed at that point in time
    count: number
    query_time_ms: number
```

Calls `bridge.queryAsOf()`. The primary developer-facing temporal query.

##### `drift_time_diff` — Compare Knowledge Between Two Times

```
Tool: drift_time_diff
Input:
    time_a: string (ISO 8601)
    time_b: string (ISO 8601)
    scope?: 'all' | 'types' | 'files' | 'namespace'
Output:
    diff: TemporalDiff — structured delta
    summary: string — human-readable summary
```

Calls `bridge.queryDiff()`. The "sprint retrospective" tool.

##### `drift_time_replay` — Replay Decision Context

```
Tool: drift_time_replay
Input:
    decision_memory_id: string
    budget?: number (default: 2000 tokens)
Output:
    replay: DecisionReplay — full decision context reconstruction
    hindsight_summary: string — human-readable hindsight analysis
```

Calls `bridge.replayDecision()`. The "audit" tool.

##### `drift_knowledge_health` — Drift Metrics Dashboard

```
Tool: drift_knowledge_health
Input:
    window_hours?: number (default: 168 = 1 week)
Output:
    metrics: DriftSnapshot — full drift metrics
    alerts: DriftAlert[] — active alerts
    summary: string — human-readable health summary
```

Calls `bridge.getDriftMetrics()` + `bridge.getDriftAlerts()`.

##### `drift_knowledge_timeline` — Visualize Knowledge Evolution

```
Tool: drift_knowledge_timeline
Input:
    from: string (ISO 8601)
    to: string (ISO 8601)
    granularity?: 'hourly' | 'daily' | 'weekly' (default: 'daily')
Output:
    snapshots: DriftSnapshot[] — time-series of drift snapshots
    trend: { ksi_trend: string, confidence_trend: string, freshness_trend: string }
```

Calls `bridge.getDriftMetrics()` for each time point in the range.

#### New CLI Commands (3 commands)

```
packages/cortex/src/cli/
├── timeline.ts                         # drift cortex timeline
├── diff.ts (new)                       # drift cortex diff
└── replay.ts                           # drift cortex replay
```

Note: `diff.ts` is a new file. The existing `packages/cortex/src/cli/` directory already has commands like `status.ts`, `validate.ts`, etc.

**Modified**: `packages/cortex/src/cli/index.ts` — register timeline, diff, replay commands

##### `drift cortex timeline`

```
Usage: drift cortex timeline [options]
Options:
    --from <date>       Start date (ISO 8601, default: 30 days ago)
    --to <date>         End date (ISO 8601, default: now)
    --type <type>       Filter by memory type
    --module <module>   Filter by file module
Output: Table showing KSI, confidence, contradiction density, EFI over time
```

##### `drift cortex diff`

```
Usage: drift cortex diff --from <date> --to <date> [options]
Options:
    --from <date>       Start date (required)
    --to <date>         End date (required)
    --scope <scope>     Diff scope: all | types | files | namespace
Output: Structured diff with created/archived/modified counts + stats
```

##### `drift cortex replay`

```
Usage: drift cortex replay <decision-id> [options]
Options:
    <decision-id>       Memory ID of the decision to replay (required)
    --budget <tokens>   Token budget for retrieval simulation (default: 2000)
Output: Decision context reconstruction + hindsight analysis
```

#### TypeScript Test Modifications

**Modified**: `packages/cortex/tests/bridge.test.ts`

Add test cases for all 10 temporal bridge methods. Each test verifies the NAPI round-trip: TypeScript → Rust → TypeScript with correct type shapes.

### Phase D4 — Quality Gate (QG-T3d)

| Test | Pass Criteria | Coverage Target |
|------|---------------|-----------------|
| NAPI query_as_of round-trip | TS call → Rust → TS response with correct shape | bindings/temporal.rs ≥ 80% |
| NAPI query_diff round-trip | TS call → Rust → TS response with correct shape | bindings/temporal.rs ≥ 80% |
| NAPI replay_decision round-trip | TS call → Rust → TS response with correct shape | bindings/temporal.rs ≥ 80% |
| NAPI get_drift_metrics round-trip | TS call → Rust → TS response with correct shape | bindings/temporal.rs ≥ 80% |
| NAPI create_materialized_view round-trip | TS call → Rust → TS response with correct shape | bindings/temporal.rs ≥ 80% |
| All 10 NAPI functions compile | `cargo check -p cortex-napi` exits 0 | — |
| Type conversions are lossless | Rust → NAPI → Rust round-trip preserves all fields | conversions/temporal_types.rs ≥ 80% |
| MCP tool drift_time_travel works | Tool call → returns memories | TS integration test |
| MCP tool drift_time_diff works | Tool call → returns diff | TS integration test |
| MCP tool drift_knowledge_health works | Tool call → returns metrics + alerts | TS integration test |
| CLI timeline command runs | `drift cortex timeline` → output table | Manual verification |
| CLI diff command runs | `drift cortex diff --from ... --to ...` → output diff | Manual verification |
| CLI replay command runs | `drift cortex replay <id>` → output replay | Manual verification |
| Bridge test suite passes | `vitest run` in packages/cortex → all temporal tests pass | TS tests |



---

## Test Infrastructure — Golden Fixtures + Property Tests + Stress Tests + Benchmarks

### Golden Test Fixtures (13 files)

All fixtures live in `crates/cortex/test-fixtures/golden/temporal/`. Each is a JSON file with known inputs and expected outputs, following the pattern established by `test-fixtures/golden/consolidation/`.

**Temporal Reconstruction Fixtures** (5):

| Fixture | Scenario | Validates |
|---------|----------|-----------|
| `reconstruction_simple.json` | 10 events for 1 memory, expected state at 3 time points | Basic replay correctness |
| `reconstruction_with_snapshot.json` | 50 events + 1 snapshot, expected state at 5 time points | Snapshot + replay path |
| `reconstruction_branching.json` | Memory with consolidation + reclassification events | Complex event type handling |
| `reconstruction_late_arrival.json` | Late-arriving fact (valid_time < transaction_time) | Bitemporal correctness |
| `reconstruction_correction.json` | Temporal correction (old record closed, new created) | Correction semantics |

**Temporal Diff Fixtures** (3):

| Fixture | Scenario | Validates |
|---------|----------|-----------|
| `diff_sprint_boundary.json` | Known state at sprint-12 and sprint-14, expected diff | Diff accuracy |
| `diff_empty.json` | Same time point, expected empty diff | Diff identity property |
| `diff_major_refactor.json` | Before/after major refactor, expected counts | Large-scale diff |

**Decision Replay Fixtures** (2):

| Fixture | Scenario | Validates |
|---------|----------|-----------|
| `replay_auth_decision.json` | Decision about auth, known context at decision time | Replay accuracy |
| `replay_with_hindsight.json` | Decision + later contradicting knowledge | Hindsight computation |

**Drift Detection Fixtures** (3):

| Fixture | Scenario | Validates |
|---------|----------|-----------|
| `drift_stable.json` | Stable knowledge base, expected KSI ≈ 1.0, no alerts | Metric baseline |
| `drift_erosion.json` | Declining confidence trajectory, expected alert | Erosion detection |
| `drift_explosion.json` | Sudden memory creation spike, expected alert | Explosion detection |

### Test Files (7)

```
crates/cortex/cortex-temporal/tests/
├── temporal_test.rs                    # Event store + snapshot + reconstruction tests
├── query_test.rs                       # All 5 query type tests
├── drift_test.rs                       # Drift metrics + alerting tests
├── epistemic_test.rs                   # Epistemic status transition tests
├── golden_test.rs                      # Golden fixture validation
├── stress_test.rs                      # High-volume + concurrent tests
├── coverage_test.rs                    # Public API surface coverage
├── property_tests.rs                   # Entry point for proptest module
└── property/
    ├── mod.rs
    └── temporal_properties.rs          # All property-based tests
```

### Property-Based Tests (Complete List)

All property tests use `proptest` with configurable iteration counts. Default: 256 iterations per property. CI: 1024 iterations.

| # | Property | Generator | Assertion |
|---|----------|-----------|-----------|
| 1 | Replay consistency | Random event sequences (1-100 events, all 17 types) | `replay(events) == apply_one_by_one(events)` |
| 2 | Snapshot + replay == full replay | Random memory with 10-200 events + snapshot at random point | `reconstruct_from_snapshot(snap, remaining) == reconstruct_from_all(all_events)` |
| 3 | Temporal monotonicity | Random event sequence | `event_ids strictly increasing AND recorded_at monotonically non-decreasing` |
| 4 | Diff symmetry | Two random time points A, B | `diff(A,B).created.len() == diff(B,A).archived.len()` |
| 5 | Diff identity | Random time point T | `diff(T,T) == TemporalDiff::empty()` |
| 6 | AS OF current == current | Random set of memories | `query_as_of(now()) == get_all_active_memories()` |
| 7 | KSI bounds | Random memory mutations over random window | `0.0 <= KSI <= 1.0` |
| 8 | Evidence freshness bounds | Random memory with random links | `0.0 <= freshness <= 1.0` |
| 9 | Epistemic ordering | Random transition attempts | Only valid paths succeed: Conjecture→Provisional→Verified, Verified→Stale |
| 10 | Temporal referential integrity | Random AS OF query | No returned memory references a non-existent memory at that time |
| 11 | Event count conservation | Append N events | Query returns exactly N events |
| 12 | Confidence aggregation bounds | Random evidence values [0.0, 1.0] | `0.0 <= aggregate <= 1.0` for both strategies |

### Stress Tests

| Test | Scale | Target |
|------|-------|--------|
| High-volume event append | 100K events, sequential | < 10s total, < 0.1ms/event |
| Reconstruction under load | 10K memories with snapshots, reconstruct all | < 50ms |
| Concurrent temporal reads during writes | 10 reader threads + 1 writer thread, 10K operations | No deadlocks, no data corruption |
| Drift computation on large dataset | 10K memories, 100K events, full drift metrics | < 500ms |
| Compaction under load | 500K events, compact 6-month-old events | < 30s, no data loss |

### Benchmark Targets (Complete)

```
crates/cortex/cortex-temporal/benches/temporal_bench.rs
```

| Benchmark | Target | Phase |
|-----------|--------|-------|
| Event append (single) | < 0.1ms | A |
| Event append (batch of 100) | < 5ms | A |
| Single memory reconstruction (50 events, no snapshot) | < 5ms | A |
| Single memory reconstruction (snapshot + 10 events) | < 1ms | A |
| Snapshot creation (single memory) | < 2ms | A |
| Snapshot batch creation (100 memories) | < 200ms | A |
| Point-in-time query (single memory) | < 5ms cold, < 1ms warm | B |
| Point-in-time query (all 10K memories) | < 500ms cold, < 50ms warm | B |
| Temporal range query (Overlaps, 10K memories) | < 50ms | B |
| Temporal diff (two points, 10K memories) | < 1s cold, < 100ms warm | B |
| Decision replay | < 200ms warm | C |
| Temporal causal traversal | < 20ms warm | C |
| Graph reconstruction (1K edges) | < 10ms cold, < 2ms warm | C |
| KSI computation (10K memories) | < 100ms | D |
| Full drift metrics (10K memories) | < 500ms | D |
| Evidence freshness (single memory) | < 1ms | D |
| Alert evaluation (100 metrics) | < 10ms | D |

---

## Complete File Inventory

### New Files by Crate (91 total)

#### cortex-temporal (51 files)

```
Cargo.toml
src/lib.rs
src/engine.rs
src/event_store/mod.rs
src/event_store/append.rs
src/event_store/query.rs
src/event_store/replay.rs
src/event_store/upcaster.rs
src/event_store/compaction.rs
src/snapshot/mod.rs
src/snapshot/create.rs
src/snapshot/lookup.rs
src/snapshot/reconstruct.rs
src/snapshot/retention.rs
src/snapshot/triggers.rs
src/query/mod.rs
src/query/as_of.rs
src/query/range.rs
src/query/diff.rs
src/query/replay.rs
src/query/temporal_causal.rs
src/query/integrity.rs
src/dual_time/mod.rs
src/dual_time/validation.rs
src/dual_time/correction.rs
src/dual_time/late_arrival.rs
src/drift/mod.rs
src/drift/metrics.rs
src/drift/evidence_freshness.rs
src/drift/alerting.rs
src/drift/snapshots.rs
src/drift/patterns.rs
src/epistemic/mod.rs
src/epistemic/status.rs
src/epistemic/transitions.rs
src/epistemic/aggregation.rs
src/views/mod.rs
src/views/create.rs
src/views/query.rs
src/views/auto_refresh.rs
tests/temporal_test.rs
tests/query_test.rs
tests/drift_test.rs
tests/epistemic_test.rs
tests/golden_test.rs
tests/stress_test.rs
tests/coverage_test.rs
tests/property_tests.rs
tests/property/mod.rs
tests/property/temporal_properties.rs
benches/temporal_bench.rs
```

#### cortex-core (10 files)

```
src/models/temporal_event.rs
src/models/temporal_query.rs
src/models/temporal_diff.rs
src/models/decision_replay.rs
src/models/drift_snapshot.rs
src/models/drift_alert.rs
src/models/epistemic_status.rs
src/models/materialized_view.rs
src/errors/temporal_error.rs
src/traits/temporal_engine.rs
src/config/temporal_config.rs
```

Note: temporal_config.rs is the 11th file but listed under config section above.

#### cortex-storage (7 files)

```
src/migrations/v014_temporal_tables.rs
src/queries/event_ops.rs
src/queries/snapshot_ops.rs
src/queries/temporal_ops.rs
src/queries/drift_ops.rs
src/queries/view_ops.rs
```

#### cortex-causal (1 file)

```
src/graph/temporal_graph.rs
```

#### cortex-napi (2 files)

```
src/bindings/temporal.rs
src/conversions/temporal_types.rs
```

#### test-fixtures (13 files)

```
golden/temporal/reconstruction_simple.json
golden/temporal/reconstruction_with_snapshot.json
golden/temporal/reconstruction_branching.json
golden/temporal/reconstruction_late_arrival.json
golden/temporal/reconstruction_correction.json
golden/temporal/diff_sprint_boundary.json
golden/temporal/diff_empty.json
golden/temporal/diff_major_refactor.json
golden/temporal/replay_auth_decision.json
golden/temporal/replay_with_hindsight.json
golden/temporal/drift_stable.json
golden/temporal/drift_erosion.json
golden/temporal/drift_explosion.json
```

#### TypeScript — packages/cortex (8 files)

```
src/tools/temporal/drift_time_travel.ts
src/tools/temporal/drift_time_diff.ts
src/tools/temporal/drift_time_replay.ts
src/tools/temporal/drift_knowledge_health.ts
src/tools/temporal/drift_knowledge_timeline.ts
src/cli/timeline.ts
src/cli/diff.ts
src/cli/replay.ts
```

### Modified Files by Crate (31 total)

#### cortex-core (5 files)

```
src/models/mod.rs
src/errors/mod.rs
src/errors/cortex_error.rs
src/traits/mod.rs
src/config/mod.rs
```

#### cortex-storage (7 files)

```
src/migrations/mod.rs
src/queries/mod.rs
src/queries/memory_crud.rs
src/queries/audit_ops.rs
src/queries/link_ops.rs
src/queries/version_ops.rs
```

#### cortex-causal (2 files)

```
src/graph/mod.rs
src/graph/sync.rs
```

#### cortex-validation (2 files)

```
src/engine.rs
src/dimensions/temporal.rs
```

#### cortex-observability (3 files)

```
src/health/reporter.rs
src/health/subsystem_checks.rs
src/health/recommendations.rs
```

#### cortex-consolidation (2 files)

```
src/engine.rs
src/pipeline/phase6_pruning.rs
```

#### cortex-decay (1 file)

```
src/engine.rs
```

#### cortex-reclassification (1 file)

```
src/engine.rs
```

#### cortex-retrieval (2 files)

```
src/ranking/scorer.rs
src/ranking/mod.rs
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

Every recommendation from RECOMMENDATIONS.md (TR1-TR18) and every cross-reference correction (CR1-CR11) is accounted for in this spec.

| Recommendation | Phase | Key Files | Quality Gate |
|---|---|---|---|
| TR1 Event Store Foundation | A | event_store/*.rs, event_ops.rs, v014, temporal_event.rs, mutation path wiring | QG-T0 |
| TR2 Snapshot Engine | A | snapshot/*.rs, snapshot_ops.rs, v014 | QG-T0 |
| TR3 Temporal Query Algebra (5 types) | B+C | query/*.rs, temporal_ops.rs, temporal_query.rs, temporal_diff.rs, decision_replay.rs | QG-T1, QG-T2 |
| TR4 Dual-Time Modeling | B | dual_time/*.rs | QG-T1 |
| TR5 Temporal Referential Integrity | B | query/integrity.rs, temporal_ops.rs | QG-T1 |
| TR6 Knowledge Drift Detection (5 metrics) | D1 | drift/metrics.rs, drift/evidence_freshness.rs | QG-T3a |
| TR7 Drift Alerting System | D1 | drift/alerting.rs, drift_alert.rs, reporter.rs | QG-T3a |
| TR8 Drift Snapshot Time-Series | D1 | drift/snapshots.rs, drift_ops.rs, drift_snapshot.rs | QG-T3a |
| TR9 Materialized Temporal Views | D2 | views/*.rs, view_ops.rs, materialized_view.rs | QG-T3b |
| TR10 Temporal Causal Graph Reconstruction | C | temporal_graph.rs, sync.rs | QG-T2 |
| TR11 Epistemic Layers | D2 | epistemic/*.rs, epistemic_status.rs, validation/engine.rs | QG-T3b |
| TR12 Evolution Pattern Detection | D1 | drift/patterns.rs | QG-T3a |
| TR13 Temporal-Aware Retrieval Boosting | D3 | scorer.rs, ranking/mod.rs | QG-T3c |
| TR14 cortex-temporal Crate Architecture | A | Cargo.toml, lib.rs, engine.rs | QG-T0 |
| TR15 Changes to Existing Crates | A-D | All modified files across 9 crates + NAPI + TypeScript | All gates |
| TR16 Migration Path (4 phases) | A-D | Phase structure of this spec | All gates |
| TR17 Testing Strategy | A-D | All test files, golden fixtures, benchmarks | All gates |
| TR18 Backward Compatibility | A-D | Enforced by additive-only design | All gates |
| CR1 Graphiti Correction | — | Gap analysis table in this spec (corrected) | Documentation |
| CR2 Event Schema Versioning | A | upcaster.rs, temporal_event.rs (schema_version) | QG-T0 |
| CR3 Idempotent Event Recording | A | append.rs, memory_crud.rs, audit_ops.rs, sync.rs | QG-T0 |
| CR4 Event Compaction & Archival | A | compaction.rs, retention.rs, event_ops.rs, v014 (archive table) | QG-T0 |
| CR5 Temporal Query Concurrency | A | engine.rs (writer + readers) | QG-T0 |
| CR6 Coverage Ratio Deferred | — | Deferred to cortex-topology | Documentation |
| CR7 New Competitors Update | — | Gap analysis table in this spec (updated) | Documentation |
| CR8 Scorer Correction | D3 | scorer.rs, ranking/mod.rs (additive, not multiplicative) | QG-T3c |
| CR9 Codebase Verification | — | All integration points verified in this spec | Documentation |
| CR10 Event Ordering Guarantees | A | append.rs (AUTOINCREMENT + Mutex) | QG-T0 |
| CR11 Replay Verification Enhancement | A | replay.rs (excluded last_accessed/access_count) | QG-T0 |

---

## Final Quality Gate — Full Integration (QG-T4)

After all four phases are complete, the final integration gate validates the entire temporal system end-to-end.

| Test | Pass Criteria |
|------|---------------|
| Full lifecycle | Create memory → mutate 20 times → reconstruct at 5 time points → all correct |
| Cross-crate event flow | Decay engine decays memory → event recorded → temporal query sees decay |
| Consolidation temporal trail | Consolidate 3 memories → events for all 3 → replay shows consolidation |
| Validation → epistemic promotion | Validate memory → epistemic status promoted → retrieval score changes |
| Drift metrics end-to-end | Create/archive/modify memories → drift metrics reflect changes → alerts fire |
| Decision replay end-to-end | Create decision → add context → replay → context matches |
| NAPI round-trip all 10 functions | TypeScript → Rust → TypeScript for every temporal function |
| MCP tools all 5 functional | Each MCP tool returns valid response |
| CLI commands all 3 functional | Each CLI command produces output |
| No workspace regressions | `cargo test --workspace` passes with zero failures |
| Coverage ≥ 80% overall | `cargo tarpaulin -p cortex-temporal --ignore-tests` reports ≥ 80% |
| All benchmarks meet targets | `cargo bench -p cortex-temporal` — all benchmarks within target |
| Storage overhead within bounds | 10K memories, 6 months of events → total temporal storage < 500MB |

---

## Estimated Timeline

| Phase | Duration | Cumulative |
|-------|----------|------------|
| A: Event Store Foundation | ~1.5 weeks | 1.5 weeks |
| B: Temporal Queries | ~1 week | 2.5 weeks |
| C: Decision Replay + Temporal Causal | ~1 week | 3.5 weeks |
| D1: Drift Metrics + Alerting | ~3 days | 4 weeks |
| D2: Epistemic + Views | ~3 days | 4.5 weeks |
| D3: Existing Crate Integration | ~2 days | 5 weeks |
| D4: NAPI + TypeScript + CLI | ~3 days | 5.5 weeks |
| QG-T4: Final Integration | ~2 days | ~6 weeks |

Total: ~4-6 weeks for a senior engineer working full-time.

