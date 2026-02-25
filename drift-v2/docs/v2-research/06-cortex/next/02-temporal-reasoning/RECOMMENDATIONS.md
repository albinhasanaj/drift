# 02 Temporal Reasoning — Recommendations

> Concrete implementation recommendations for adding temporal reasoning, knowledge
> time-travel, and drift detection to Cortex. Derived from 5 research documents
> (01-BITEMPORAL-THEORY through 05-CORTEX-MAPPING), validated against 14 external
> sources spanning bitemporal database theory, event sourcing, temporal knowledge
> graphs, agent drift research, and epistemic tracking frameworks.
>
> **Key insight**: Cortex already has 80% of the temporal infrastructure — BaseMemory
> carries `transaction_time`, `valid_time`, `valid_until`; the audit log records every
> mutation; the versioning system stores content snapshots. What's missing is a
> **projection engine** that can reconstruct state at arbitrary time points, a
> **temporal query algebra** that makes this queryable, and a **drift detection
> system** that turns temporal data into actionable health signals.

---

## Research Sources (Verified)

| ID | Source | Year | Relevance |
|----|--------|------|-----------|
| TS1 | [XTDB v2 — Bitemporal SQL](https://www.xtdb.com/blog/launching-xtdb-v2) | 2024 | Gold standard for bitemporal design: 4-bound temporal records, immutable transaction time |
| TS2 | [XTDB Taxonomy of Bitemporal Data](https://xtdb.com/blog/building-a-bitemp-index-1-taxonomy) | 2025 | Bitemporal indexing strategies, time-series optimization |
| TS3 | [SQL:2011 Temporal Tables Standard](https://www.waterstechnology.com/inside-reference-data/news/2136305/iso-makes-sql-standard-bi-temporal) | 2012 | ISO standard: application-time period tables + system-versioned tables |
| TS4 | [Temporal Referential Integrity](https://softwarepatternslexicon.com/bitemporal-modeling/bi-temporal-consistency-patterns/temporal-referential-integrity/) | 2025 | Patterns for maintaining referential integrity across time dimensions |
| TS5 | [Event Sourcing with SQLite](https://www.sqliteforum.com/p/building-event-sourcing-systems-with) | 2025 | SQLite as event store: append-only, WAL-friendly, transactional ordering |
| TS6 | [CQRS Snapshots & Performance](https://www.cqrs.com/deeper-insights/snapshots-and-performance/) | 2025 | Snapshot strategies: fixed-interval, time-based, on-demand; O(k) reconstruction |
| TS7 | [T-GRAG — Temporal GraphRAG](https://arxiv.org/abs/2508.01680) — Li et al. | 2025 | Temporal query decomposition, 3-layer interactive retrieval, time-stamped graph structures |
| TS8 | [Zep/Graphiti — Temporal KG for Agent Memory](https://arxiv.org/abs/2501.13956) — Rasmussen et al. | 2025 | Temporally-aware KG engine, 94.8% DMR accuracy, 90% latency reduction vs baselines |
| TS9 | [ATOM — Dual-Time TKG Construction](https://arxiv.org/abs/2510.22590) — Lairgi et al. | 2025/2026 | Dual-time modeling (observed vs valid), atomic fact extraction, 18% higher exhaustivity |
| TS10 | [Agent Drift — Behavioral Degradation](https://arxiv.org/abs/2601.04170) — Rath et al. | 2026 | Agent Stability Index (ASI), 12-dimension drift quantification, episodic memory consolidation as mitigation |
| TS11 | [FPF — Epistemic Status & Temporal Validity](https://arxiv.org/abs/2601.21116) — Gilda et al. | 2026 | 20-25% of architectural decisions have stale evidence within 2 months; Gödel t-norm for confidence aggregation |
| TS12 | [EverMemOS — Memory Operating System](https://www.prnewswire.com/news-releases/ai-infrastructure-company-everminds-evermemos-aims-to-give-ai-agents-durable-coherent-and-continuously-evolving-souls-302636316.html) | 2025/2026 | 93.05% LoCoMo accuracy, 3-phase memory lifecycle, categorical memory extraction |
| TS13 | [MemoriesDB — Temporal-Semantic-Relational](https://arxiv.org/abs/2511.06179) | 2025 | Unified time-semantic-relational entity architecture, decoherence prevention |
| TS14 | [EvoReasoner — Temporal Multi-Hop Reasoning](https://arxiv.org/abs/2509.15464) | 2025 | Global-local entity grounding, temporally grounded scoring for evolving KGs |

---

## TR1: Event Store Foundation — Append-Only Memory Event Log

**Priority**: P0 — Every other temporal feature depends on this
**Evidence**: TS5, TS6, 02-EVENT-SOURCING.md

Cortex already generates every event we need. The audit_log (v006 migration) records
all mutations. The versioning system (v008 migration) stores content snapshots. The
missing piece is a unified, replay-optimized event store that enables state
reconstruction at arbitrary time points.

**The critical insight from CQRS literature (TS6)**: You don't need snapshots for
every entity. Only create them when streams grow long. For Cortex, most memories
have <50 lifetime events — full replay is fast. Snapshots become valuable for
memories with high mutation rates (frequently accessed episodic memories, actively
contested knowledge).

**Event Schema**:

```rust
struct MemoryEvent {
    event_id: u64,                    // monotonically increasing, gap-free
    memory_id: MemoryId,
    recorded_at: DateTime<Utc>,       // transaction time — immutable once written
    event_type: MemoryEventType,      // 16 variants
    delta: serde_json::Value,         // field-level diff, not full state
    actor: EventActor,                // who caused this
    caused_by: Vec<u64>,              // causal predecessors for ordering
}

enum MemoryEventType {
    Created,              // full initial state in delta
    ContentUpdated,       // content field diff
    ConfidenceChanged,    // { old: f64, new: f64, reason: String }
    ImportanceChanged,    // reclassification event
    TagsModified,         // { added: [], removed: [] }
    LinkAdded,            // { link_type, target }
    LinkRemoved,          // { link_type, target }
    RelationshipAdded,    // causal edge creation
    RelationshipRemoved,  // causal edge removal
    Archived,             // memory archived
    Restored,             // memory restored from archive
    Decayed,              // periodic decay application
    Validated,            // validation result applied
    Consolidated,         // merged into/from other memories
    Reclassified,         // memory type changed
    Superseded,           // superseded by another memory
}

enum EventActor {
    User(String),
    Agent(AgentId),
    System(String),       // "decay_engine", "consolidation_pipeline", etc.
}
```

**Routing strategy — zero new event generation**: We don't create new events. We
route existing mutation paths to also emit events. Every place that currently calls
`audit_log.record()` additionally calls `event_store.append()`. The event store
is the temporal projection of mutations that already happen.

| Existing Source | Events Generated | Current Destination | Additional Destination |
|-----------------|-----------------|--------------------|-----------------------|
| `audit/logger.rs` | All CRUD mutations | `memory_audit_log` table | `memory_events` table |
| `versioning/tracker.rs` | Content updates | `memory_versions` table | `memory_events` (ContentUpdated) |
| `cortex-decay/engine.rs` | Confidence changes | Direct `UPDATE` | `memory_events` (Decayed) |
| `cortex-validation/engine.rs` | Validation results | `memory_validation_history` | `memory_events` (Validated) |
| `cortex-consolidation/pipeline` | Merge/archive | `memory_audit_log` | `memory_events` (Consolidated) |
| `cortex-reclassification` | Type changes | `reclassification_history` | `memory_events` (Reclassified) |

**Storage schema** (migration v014):

```sql
CREATE TABLE memory_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    memory_id TEXT NOT NULL,
    recorded_at TEXT NOT NULL,       -- ISO 8601, indexed
    event_type TEXT NOT NULL,
    delta TEXT NOT NULL,             -- JSON, field-level diff
    actor_type TEXT NOT NULL,        -- 'user' | 'agent' | 'system'
    actor_id TEXT NOT NULL,
    caused_by TEXT,                  -- JSON array of event_ids, nullable
    FOREIGN KEY (memory_id) REFERENCES memories(id)
);

CREATE INDEX idx_events_memory_time ON memory_events(memory_id, recorded_at);
CREATE INDEX idx_events_time ON memory_events(recorded_at);
CREATE INDEX idx_events_type ON memory_events(event_type);
```

**Performance**: Append-only writes are WAL-friendly (our existing WAL mode).
Sequential reads for replay are cache-friendly. Each event is ~200 bytes.
At 10 events/memory/month for 10K memories: ~24MB/year. Negligible.

**Backward compatibility**: The event store is additive. All existing queries
continue to work. Events are recorded alongside existing audit entries, not
instead of them. If the event store is empty (fresh install or pre-migration
data), temporal queries gracefully return "no temporal data available before
migration date."

---

## TR2: Snapshot Engine — Periodic State Captures for O(k) Reconstruction

**Priority**: P0
**Evidence**: TS6, 02-EVENT-SOURCING.md

Full event replay from genesis is O(n) where n = total events for a memory.
For most memories this is fine (<50 events). But for high-churn memories
(frequently updated episodic memories, contested knowledge with many validation
cycles), n can grow large. Snapshots reduce reconstruction to O(k) where
k = events since last snapshot.

**Snapshot strategy — adaptive, not fixed-interval**:

Unlike traditional CQRS systems that snapshot every N events, Cortex should
snapshot adaptively based on memory activity patterns:

```rust
struct MemorySnapshot {
    snapshot_id: u64,
    memory_id: MemoryId,
    snapshot_at: DateTime<Utc>,
    state: Vec<u8>,              // zstd-compressed JSON of full BaseMemory
    event_id: u64,               // snapshot is valid up to this event
    snapshot_reason: SnapshotReason,
}

enum SnapshotReason {
    EventThreshold,    // memory exceeded 50 events since last snapshot
    Periodic,          // weekly full-database snapshot
    PreOperation,      // before consolidation or major mutation
    OnDemand,          // user requested materialized view
}
```

**Adaptive snapshot triggers**:
1. **Event threshold**: Snapshot when a memory accumulates 50 events since its
   last snapshot. Most memories never hit this — only high-churn ones get snapshots.
2. **Weekly sweep**: Background task snapshots all active memories weekly. This
   bounds worst-case reconstruction to ~10 events (typical weekly mutation rate).
3. **Pre-consolidation**: Before consolidation merges memories, snapshot all
   participants. This enables "undo consolidation" by replaying from snapshot.
4. **Materialized views**: When a user creates a sprint-boundary or release-date
   view, snapshot all memories at that point.

**Storage schema**:

```sql
CREATE TABLE memory_snapshots (
    snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
    memory_id TEXT NOT NULL,
    snapshot_at TEXT NOT NULL,
    state BLOB NOT NULL,           -- zstd-compressed JSON
    event_id INTEGER NOT NULL,     -- valid up to this event
    reason TEXT NOT NULL,
    FOREIGN KEY (memory_id) REFERENCES memories(id)
);

CREATE INDEX idx_snapshots_memory_time
ON memory_snapshots(memory_id, snapshot_at);
```

**Reconstruction algorithm**:

```
state_at(memory_id, target_time):
    snapshot = get_nearest_snapshot(memory_id, before=target_time)
    if snapshot exists:
        events = get_events(memory_id, after=snapshot.event_id, before=target_time)
        state = decompress(snapshot.state)
    else:
        events = get_events(memory_id, before=target_time)
        state = empty_memory_shell(memory_id)
    for event in events:
        state = apply_event(state, event)
    return state
```

**Storage overhead**: With zstd compression, a BaseMemory snapshot is ~500 bytes.
Weekly snapshots for 10K memories over 6 months (26 weeks): 260K snapshots ×
500 bytes = ~130MB. Combined with events (~200MB), total temporal overhead is
~330MB for 10K memories over 6 months — well within SQLite's comfort zone.

**Snapshot retention**: Keep all snapshots for 6 months. After 6 months, keep
only monthly snapshots. After 2 years, keep only quarterly snapshots. This
matches our existing audit rotation policy.


---

## TR3: Temporal Query Algebra — Five Query Types for Knowledge Time-Travel

**Priority**: P0
**Evidence**: TS1, TS3, TS4, TS7, 03-TEMPORAL-QUERIES.md

The query algebra is the developer-facing API for temporal reasoning. Five query
types, ordered by implementation complexity and user value.

**Novel contribution**: Existing temporal databases (XTDB, SQL:2011 temporal tables)
operate on flat records. Cortex's temporal queries must also reconstruct the
**causal graph** and **relationship network** at past time points — something no
existing system does. This is the intersection of bitemporal databases and
temporal knowledge graphs, and it's what makes Cortex's temporal reasoning unique.

### Query Type 1: Point-in-Time (AS OF)

"What did we know at time T?"

The most fundamental temporal query. Reconstructs the complete knowledge state
as it existed at a specific (system_time, valid_time) pair.

```rust
struct AsOfQuery {
    system_time: DateTime<Utc>,     // "what was recorded by this time"
    valid_time: DateTime<Utc>,      // "what was true at this time"
    filter: Option<MemoryFilter>,   // optional type/tag/file filter
}
```

**Bitemporal semantics (from TS1, TS3)**: A memory is visible at (system_time S,
valid_time V) if and only if:
- `transaction_time <= S` (we had learned about it by time S)
- `valid_time <= V` (it was true at or before time V)
- `valid_until IS NULL OR valid_until > V` (it hadn't expired by time V)
- The memory was not archived at system_time S

This is the SQL:2011 `AS OF SYSTEM TIME S AND VALID TIME V` semantics,
adapted for Cortex's memory model.

**Implementation**: Use the snapshot + replay algorithm from TR2. For bulk
reconstruction (all memories at time T), the weekly snapshot makes this
efficient — replay only events since the nearest weekly snapshot.

**Why this matters for developers**: "Show me what we knew about auth when we
made the decision to switch to OAuth" is a question that currently requires
manual archaeology through git blame and Slack history. With AS OF queries,
it's a single API call.

### Query Type 2: Temporal Range (BETWEEN)

"What memories were active during this period?"

```rust
struct TemporalRangeQuery {
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    mode: TemporalRangeMode,
}

enum TemporalRangeMode {
    Overlaps,       // valid at any point in [from, to]
    Contains,       // valid for the entire [from, to]
    StartedDuring,  // became valid during [from, to]
    EndedDuring,    // stopped being valid during [from, to]
}
```

**Implementation**: This can be answered directly from the `memories` table
using the existing `valid_time` and `valid_until` columns, plus the event
store for memories that were modified during the range. No reconstruction
needed for the common case.

```sql
-- Overlaps mode: memory was valid at any point in [from, to]
SELECT * FROM memories
WHERE valid_time <= @to
  AND (valid_until IS NULL OR valid_until >= @from)
  AND transaction_time <= @to
  AND archived = 0;
```

**Temporal indexes** (added in migration v014):

```sql
CREATE INDEX idx_memories_valid_range
ON memories(valid_time, valid_until)
WHERE archived = 0;

CREATE INDEX idx_memories_transaction_range
ON memories(transaction_time);
```

### Query Type 3: Temporal Diff

"What changed between time A and time B?"

The most powerful query type. Compares two knowledge states and returns a
structured delta. This is the "sprint retrospective" query — show me how
our understanding evolved over the last two weeks.

```rust
struct TemporalDiffQuery {
    time_a: DateTime<Utc>,
    time_b: DateTime<Utc>,
    scope: DiffScope,
}

struct TemporalDiff {
    created: Vec<MemorySnapshot>,           // exist at B but not A
    archived: Vec<MemorySnapshot>,          // exist at A but not B
    modified: Vec<MemoryModification>,      // exist at both, changed
    confidence_shifts: Vec<ConfidenceShift>,// confidence delta > 0.2
    new_contradictions: Vec<Contradiction>, // detected between A and B
    resolved_contradictions: Vec<Contradiction>,
    reclassifications: Vec<Reclassification>,
    stats: DiffStats,
}

struct DiffStats {
    memories_at_a: usize,
    memories_at_b: usize,
    net_change: i64,
    avg_confidence_at_a: f64,
    avg_confidence_at_b: f64,
    confidence_trend: f64,        // positive = improving
    knowledge_churn_rate: f64,    // (created + archived) / total
}
```

**Implementation**: Reconstruct state at time_a and time_b using AS OF queries.
Diff the two states. For large knowledge bases, optimize by only reconstructing
memories that had events between time_a and time_b (the event store's time
index makes this efficient).

**Novel optimization — event-range diff**: Instead of reconstructing two full
states and diffing, query the event store for all events between time_a and
time_b. Group by memory_id. For each memory with events in the range, determine
if it was created, archived, or modified. This is O(events_in_range) instead
of O(total_memories × 2).

### Query Type 4: Decision Replay

"Reconstruct the exact context available when Decision X was made."

Given a decision memory, reconstructs what the retrieval engine would have
returned at the time that decision was recorded. This is the "audit" query —
critical for regulated environments and for learning from past decisions.

```rust
struct DecisionReplayQuery {
    decision_memory_id: MemoryId,
    budget_override: Option<usize>,
}

struct DecisionReplay {
    decision: MemorySnapshot,                // the decision as it was
    available_context: Vec<MemorySnapshot>,   // all memories at decision time
    retrieved_context: Vec<CompressedMemory>, // what retrieval would have returned
    causal_state: CausalGraphSnapshot,        // causal graph at decision time
    hindsight: Vec<HindsightItem>,            // what we know NOW but didn't THEN
}

struct HindsightItem {
    memory: MemorySnapshot,
    relevance: f64,              // how relevant to the decision
    relationship: String,        // "contradicts", "would have informed", etc.
}
```

**Why this is novel**: No existing AI memory system offers decision replay.
Zep/Graphiti (TS8) tracks temporal relationships but can't reconstruct past
retrieval contexts. T-GRAG (TS7) handles temporal queries but operates on
static document corpora, not evolving agent memory. Decision replay requires
the intersection of temporal state reconstruction + retrieval simulation +
causal graph reconstruction — all three of which Cortex uniquely has.

**The hindsight computation**: After reconstructing the decision-time context,
compare it against current knowledge. Memories that exist now but didn't then,
and are relevant to the decision topic (embedding similarity > 0.7), become
hindsight items. This answers: "Was this a good decision given what we knew?
Would we make the same decision with what we know now?"

**Evidence from TS11 (FPF paper)**: The First Principles Framework found that
20-25% of architectural decisions had stale evidence within two months. Decision
replay makes this discoverable — you can systematically audit past decisions
against current knowledge and flag those that may need revisiting.

### Query Type 5: Temporal Causal

"At the time we adopted Pattern X, what was the causal chain?"

Reconstructs the causal graph as it existed at a specific point in time, then
runs traversal on that historical graph.

```rust
struct TemporalCausalQuery {
    memory_id: MemoryId,
    as_of: DateTime<Utc>,
    direction: TraversalDirection,
    max_depth: usize,
}
```

**Implementation**: Reconstruct the causal graph at `as_of` by:
1. Get all causal edges that existed at `as_of` (from event store)
2. Build a temporary petgraph with only those edges
3. Use edge strengths as they were at `as_of`
4. Run standard traversal on the historical graph

This reuses cortex-causal's existing traversal and narrative generation,
just on a reconstructed historical graph instead of the current one.

### Query Cost Estimates

| Query Type | Cold (no snapshots) | Warm (with snapshots) |
|---|---|---|
| Point-in-time (single memory) | ~5ms | ~1ms |
| Point-in-time (all memories) | ~500ms | ~50ms |
| Temporal diff (two points) | ~1s | ~100ms |
| Decision replay | ~2s | ~200ms |
| Temporal causal traversal | ~100ms | ~20ms |

These are acceptable for developer-facing exploratory queries. None of these
are on the hot path for real-time retrieval.


---

## TR4: Dual-Time Modeling — Observed Time vs. Valid Time Separation

**Priority**: P1
**Evidence**: TS1, TS3, TS9, 01-BITEMPORAL-THEORY.md

Cortex already has the two temporal dimensions in BaseMemory:
- `transaction_time`: when the system learned about this fact
- `valid_time`: when this fact was/is true in the real world
- `valid_until`: when this fact stopped being true

But the system doesn't enforce or leverage the distinction rigorously. The
ATOM paper (TS9) demonstrates that explicitly separating "observed time" from
"valid time" yields 18% higher exhaustivity in knowledge extraction. XTDB (TS1)
makes this the core architectural principle — every record has four temporal
bounds: `valid_from`, `valid_to`, `system_from`, `system_to`.

**What needs to change**:

1. **Enforce immutability of transaction_time**: Once a memory is created, its
   `transaction_time` must never change. Currently nothing prevents an update
   from modifying it. Add a validation check in `memory_crud.rs` that rejects
   updates to `transaction_time`.

2. **Add `system_until` for soft-delete tracking**: When a memory is archived
   or superseded, record the system time of that event. Currently `archived`
   is a boolean — we lose the "when was it archived" information.

   ```rust
   // Add to BaseMemory (or as a storage-layer field)
   pub system_until: Option<DateTime<Utc>>,  // when this version was superseded
   ```

3. **Temporal correction semantics**: When we discover a fact was wrong, we
   don't delete the old record. We:
   - Close the old record's `system_until` (it's no longer current)
   - Create a new record with corrected `valid_time` range
   - The old record remains queryable at its original `system_time`

   This is exactly what our versioning system already does, but we need to
   make it queryable through the temporal API.

4. **Late-arriving facts**: When we learn about something that happened in the
   past (e.g., "we discovered yesterday that the auth module was refactored
   last month"), the memory should have:
   - `transaction_time` = now (when we learned it)
   - `valid_time` = last month (when it actually happened)

   This is already supported by BaseMemory's fields but isn't surfaced in
   the creation API. Make `valid_time` an explicit, required parameter in
   memory creation (defaulting to `now` if not specified).

**The four temporal states** (from TS1):

```
                    Valid Time
                Past    |    Future
           ┌────────────┼────────────┐
    Past   │  Known     │  Predicted │
Trans.     │  history   │  (was      │
Time       │            │  expected) │
           ├────────────┼────────────┤
    Future │  Late      │  Unknown   │
           │  discovery │  future    │
           │  (backfill)│            │
           └────────────┴────────────┘
```

Cortex should handle all four quadrants:
- **Known history**: Standard memories with both times in the past
- **Predicted**: Memories with `valid_time` in the future (e.g., "this
  constraint will apply starting next sprint")
- **Late discovery**: Memories where `valid_time < transaction_time` (we
  learned about it after it happened)
- **Unknown future**: Not yet created — but the prediction engine (cortex-prediction)
  could generate speculative memories in this quadrant

---

## TR5: Temporal Referential Integrity — Consistency Across Time

**Priority**: P1
**Evidence**: TS4, 01-BITEMPORAL-THEORY.md

When querying memories at a past point in time, all references must also resolve
at that same point in time. This prevents temporal anomalies.

**The problem**: Memory A (created March 1) references Pattern B (created March 15).
If we query "what did we know on March 10?", Memory A should be visible but its
reference to Pattern B should not resolve — Pattern B didn't exist yet.

**Temporal referential integrity rules**:

1. **Temporal join constraint**: When retrieving related memories at time T, the
   join condition must include temporal overlap. Two memories are "related at
   time T" only if both were valid at T and both were known at T.

   ```sql
   -- Temporal join: find related memories at time T
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

2. **Causal edge temporal validity**: Causal edges in the graph should carry
   their own temporal bounds. An edge between Memory A and Memory B is only
   valid during the period when both A and B are valid. When reconstructing
   the causal graph at time T, exclude edges where either endpoint wasn't
   valid at T.

3. **Link temporal validity**: File links, pattern links, and function links
   should be temporally scoped. A file link is valid only while the file
   exists at the referenced path with the referenced content hash. This
   connects to cortex-validation's citation checking — stale citations are
   a temporal integrity violation.

**Implementation**: The temporal query engine (TR3) must enforce these rules
automatically. When an AS OF query returns memories, their links and
relationships are filtered through temporal validity checks. The developer
never sees a temporally inconsistent result.

---

## TR6: Knowledge Drift Detection — Five Metrics for Knowledge Health

**Priority**: P0
**Evidence**: TS10, TS11, TS12, 04-DRIFT-DETECTION.md

Knowledge drift is the phenomenon where a team's understanding changes over
time — patterns emerge, conventions shift, tribal knowledge evolves, old
assumptions become invalid. The Agent Drift paper (TS10) formalizes this as
"progressive degradation of agent behavior and decision quality over extended
interaction sequences" and proposes the Agent Stability Index (ASI) as a
composite metric across 12 dimensions.

The FPF paper (TS11) provides the most striking evidence: **20-25% of
architectural decisions had stale evidence within two months**. This means
that without temporal accountability, roughly a quarter of your knowledge
base is silently becoming unreliable every 60 days.

Cortex should compute five drift metrics, each targeting a different aspect
of knowledge health:

### Metric 1: Knowledge Stability Index (KSI)

Measures how stable the knowledge base is over a time window.

```
KSI(type, window) = 1 - (created + archived + modified) / (2 × total_at_start)
```

- KSI = 1.0: perfectly stable, nothing changed
- KSI = 0.5: moderate churn, half the knowledge base changed
- KSI < 0.3: high churn, knowledge is unstable

**Per-type KSI is critical**: Episodic KSI is naturally low (episodes are
transient by design). Core KSI should be high (core knowledge is stable).
If Tribal KSI drops below 0.5, team norms are shifting — worth investigating.

**Inspired by TS10's ASI**: The Agent Stability Index uses 12 dimensions.
For Cortex, KSI per memory type gives us 23 dimensions of stability tracking,
which is more granular than ASI and directly actionable (you know which
knowledge category is churning).

### Metric 2: Confidence Trajectory

Track average confidence over time, per memory type:

```
confidence_trajectory(type, window) = [
    avg_confidence(type, t0),
    avg_confidence(type, t1),
    ...
    avg_confidence(type, tn),
]
```

- Rising: knowledge is being validated and reinforced
- Falling: knowledge is decaying or being contradicted
- Flat: stable but possibly stagnant

**Connection to TS11**: The FPF paper's "evidence decay tracking" maps directly
to confidence trajectory. When confidence for a memory type trends downward,
it signals that the evidence supporting those memories is going stale.

### Metric 3: Contradiction Density

```
contradiction_density(type, window) = new_contradictions / total_memories
```

- < 0.02: healthy, few conflicts
- 0.02 - 0.10: some disagreement, worth monitoring
- > 0.10: internally inconsistent, needs attention

### Metric 4: Consolidation Efficiency

```
consolidation_efficiency(window) = semantic_created / episodic_archived
```

- Ratio > 0.5: good — most episodes are being consolidated into lasting knowledge
- Ratio < 0.2: poor — episodes are being archived without extracting value
- Ratio > 1.0: excellent — consolidation is creating more knowledge than it consumes

This metric directly measures whether the hippocampus-to-neocortex transfer
(episodic → semantic consolidation) is working effectively.

### Metric 5: Evidence Freshness Score (Novel — inspired by TS11)

This is a new metric not in the existing research documents, inspired by the
FPF paper's finding that 20-25% of decisions go stale within 2 months.

```
evidence_freshness(memory) = Π(freshness_factor(evidence_i))

freshness_factor(evidence) =
    if evidence.type == "file_link":
        1.0 if content_hash matches current file, else 0.5
    if evidence.type == "pattern_link":
        1.0 if pattern still active, else 0.3
    if evidence.type == "supporting_memory":
        supporting_memory.confidence
    if evidence.type == "user_validation":
        decay(time_since_validation, half_life=90d)
```

A memory's evidence freshness is the product of all its evidence factors.
When evidence freshness drops below 0.5, the memory should be flagged for
re-validation. This catches the "stale evidence" problem that TS11 identified.

**Aggregate metric**: Evidence Freshness Index (EFI) = average evidence
freshness across all active memories. Track EFI over time as a leading
indicator of knowledge base health.


---

## TR7: Drift Alerting System — Proactive Knowledge Health Signals

**Priority**: P1
**Evidence**: TS10, TS11, 04-DRIFT-DETECTION.md

Metrics are useless without alerting. The drift detection system should
proactively surface knowledge health issues before they cause problems.

**Alert categories**:

```rust
struct DriftAlert {
    severity: AlertSeverity,          // info, warning, critical
    category: DriftAlertCategory,
    message: String,
    affected_memories: Vec<MemoryId>,
    recommended_action: String,
    detected_at: DateTime<Utc>,
}

enum DriftAlertCategory {
    /// KSI dropped below threshold for a memory type
    KnowledgeChurn {
        memory_type: MemoryType,
        ksi: f64,
        threshold: f64,
    },
    /// Confidence trajectory turned negative for 2+ consecutive windows
    ConfidenceErosion {
        memory_type: MemoryType,
        trend: f64,           // negative = eroding
        windows_declining: u32,
    },
    /// Contradiction density exceeded threshold
    ContradictionSpike {
        density: f64,
        threshold: f64,
        hotspot: Option<String>,  // file/module with most contradictions
    },
    /// Evidence freshness dropped below threshold
    StaleEvidence {
        memory_id: MemoryId,
        freshness: f64,
        stale_links: Vec<String>,
    },
    /// Memory creation rate anomaly (3σ above rolling average)
    KnowledgeExplosion {
        module: String,
        rate: f64,
        baseline: f64,
    },
    /// Knowledge coverage dropped for a module
    CoverageGap {
        module: String,
        coverage: f64,
        expected: f64,
    },
}
```

**Alert thresholds** (configurable via TemporalConfig):

| Alert | Default Threshold | Severity |
|-------|-------------------|----------|
| KSI < threshold | 0.3 for core/tribal, 0.5 for semantic | Warning |
| Confidence erosion | 2+ consecutive declining windows | Warning |
| Contradiction density | > 0.10 | Critical |
| Evidence freshness | < 0.5 for high-importance memories | Warning |
| Knowledge explosion | > 3σ above 30-day rolling average | Info |
| Coverage gap | < 0.3 for modules with >500 LOC | Warning |

**Integration with cortex-observability**: Alerts feed into the existing
health report system. The `HealthReport` struct gains a `drift_summary`
field with active alerts, trend indicators, and recommended actions.

**Alert dampening**: Don't fire the same alert repeatedly. Each alert
category has a cooldown period (default: 24 hours for warnings, 1 hour
for critical). Alerts are deduplicated by category + affected entity.

---

## TR8: Drift Snapshot Time-Series — Metrics Over Time

**Priority**: P1
**Evidence**: TS10, 04-DRIFT-DETECTION.md

Store drift metrics at regular intervals for trend analysis and dashboarding.

```rust
struct DriftSnapshot {
    timestamp: DateTime<Utc>,
    window: Duration,
    type_metrics: HashMap<MemoryType, TypeDriftMetrics>,
    module_metrics: HashMap<String, ModuleDriftMetrics>,
    global: GlobalDriftMetrics,
}

struct TypeDriftMetrics {
    count: usize,
    avg_confidence: f64,
    ksi: f64,
    contradiction_density: f64,
    consolidation_efficiency: f64,
    evidence_freshness_index: f64,  // new: from TR6
}

struct ModuleDriftMetrics {
    memory_count: usize,
    coverage_ratio: f64,
    avg_confidence: f64,
    churn_rate: f64,
}

struct GlobalDriftMetrics {
    total_memories: usize,
    active_memories: usize,
    archived_memories: usize,
    avg_confidence: f64,
    overall_ksi: f64,
    overall_contradiction_density: f64,
    overall_evidence_freshness: f64,  // new: from TR6
}
```

**Snapshot frequency**:
- Hourly: lightweight counters only (memory count, avg confidence)
- Daily: full drift metrics per type and module
- Weekly: comprehensive snapshot with trend analysis
- Sprint boundary: materialized temporal view (pre-computed for fast queries)

**Storage schema**:

```sql
CREATE TABLE drift_snapshots (
    snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    window_seconds INTEGER NOT NULL,
    metrics TEXT NOT NULL,          -- JSON blob of DriftSnapshot
    UNIQUE(timestamp, window_seconds)
);

CREATE INDEX idx_drift_time ON drift_snapshots(timestamp);
```

**Storage overhead**: Daily snapshots for 1 year: 365 × ~2KB = ~730KB.
Weekly comprehensive: 52 × ~10KB = ~520KB. Total: ~1.3MB/year. Negligible.

---

## TR9: Materialized Temporal Views — Pre-Computed Knowledge Snapshots

**Priority**: P2
**Evidence**: TS1, 03-TEMPORAL-QUERIES.md

For frequently-queried time points (sprint boundaries, release dates, quarterly
reviews), pre-compute and cache the complete knowledge state. This turns
expensive temporal reconstruction into instant lookups.

```rust
struct MaterializedTemporalView {
    view_id: u64,
    label: String,                // "sprint-12", "v2.0-release", "Q1-2026"
    timestamp: DateTime<Utc>,
    memory_count: usize,
    snapshot_ids: Vec<u64>,       // references to memory_snapshots
    drift_snapshot_id: u64,       // associated drift metrics
    created_by: EventActor,
    auto_refresh: bool,           // auto-update on new events
}
```

**Auto-creation**: The system can automatically create materialized views at
configurable intervals (e.g., every 2 weeks for sprint boundaries). Users
can also create them manually for significant milestones.

**Storage schema**:

```sql
CREATE TABLE materialized_views (
    view_id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    memory_count INTEGER NOT NULL,
    snapshot_ids TEXT NOT NULL,     -- JSON array
    drift_snapshot_id INTEGER,
    created_by TEXT NOT NULL,
    auto_refresh INTEGER DEFAULT 0,
    FOREIGN KEY (drift_snapshot_id) REFERENCES drift_snapshots(snapshot_id)
);
```

**Use cases**:
- "Compare our knowledge at sprint-12 vs sprint-14" → instant diff between
  two materialized views
- "What was our knowledge health at the v2.0 release?" → instant lookup
- "Show me the knowledge timeline for the auth module" → sequence of
  materialized views filtered by module

---

## TR10: Temporal Causal Graph Reconstruction

**Priority**: P2
**Evidence**: TS7, TS14, 03-TEMPORAL-QUERIES.md, 05-CORTEX-MAPPING.md

Reconstruct the causal graph as it existed at any past point in time. This
enables temporal causal queries (TR3, Query Type 5) and is essential for
decision replay (TR3, Query Type 4).

**Why this is novel**: T-GRAG (TS7) handles temporal queries over knowledge
graphs but operates on static document corpora with timestamped relations.
EvoReasoner (TS14) performs temporal multi-hop reasoning but on external
knowledge graphs, not evolving agent memory. Cortex's temporal causal
reconstruction operates on a **living, self-modifying** causal graph that
the system itself builds and maintains — a fundamentally different challenge.

**Implementation in cortex-causal**:

```rust
// New module: cortex-causal/src/temporal_graph.rs

/// Reconstruct the causal graph as it existed at a specific time.
/// Uses the event store to determine which edges existed at `as_of`.
fn reconstruct_graph_at(
    event_store: &EventStore,
    as_of: DateTime<Utc>,
) -> StableGraph<MemoryId, CausalEdge> {
    // 1. Get all RelationshipAdded events before as_of
    // 2. Get all RelationshipRemoved events before as_of
    // 3. Build graph with edges that were added but not yet removed
    // 4. Use edge strengths as they were at as_of (from ConfidenceChanged events)
}

/// Traverse the historical causal graph.
fn temporal_traversal(
    memory_id: MemoryId,
    as_of: DateTime<Utc>,
    direction: TraversalDirection,
    max_depth: usize,
) -> TraversalResult {
    let historical_graph = reconstruct_graph_at(event_store, as_of);
    // Reuse existing traversal logic on the historical graph
    traverse(&historical_graph, memory_id, direction, max_depth)
}
```

**Edge event tracking**: Extend the event store to record causal edge
mutations. Currently, cortex-causal modifies the in-memory petgraph and
syncs to the `causal_edges` SQLite table. Add event emission for:
- `RelationshipAdded { source, target, relation_type, strength }`
- `RelationshipRemoved { source, target }`
- `StrengthUpdated { source, target, old_strength, new_strength }`

**Performance**: Reconstructing a graph with 1K edges from events takes
~10ms. With snapshots of the graph state (weekly), reconstruction from
snapshot + replay takes ~2ms. Acceptable for exploratory queries.

---

## TR11: Epistemic Layers — Separating Conjecture from Verified Knowledge

**Priority**: P1 — Novel contribution, high differentiation
**Evidence**: TS11, TS10

This is a novel recommendation not present in the existing research documents,
directly inspired by the First Principles Framework paper (TS11).

**The problem**: LLM coding assistants generate decisions faster than teams
can validate them. Cortex currently treats all memories equally — a memory
created from a quick chat interaction has the same epistemic status as one
validated by three team members over six months. The FPF paper argues this
is fundamentally unsafe: "no widely-adopted framework distinguishes conjecture
from verified knowledge."

**Epistemic status model**:

```rust
enum EpistemicStatus {
    /// Unverified hypothesis — created by agent, not yet validated
    Conjecture {
        source: String,           // which agent/interaction created this
        created_at: DateTime<Utc>,
    },
    /// Partially validated — some evidence supports it
    Provisional {
        evidence_count: u32,
        last_validated: DateTime<Utc>,
    },
    /// Fully validated — confirmed by multiple sources or explicit user approval
    Verified {
        verified_by: Vec<String>, // agents or users who verified
        verified_at: DateTime<Utc>,
        evidence_refs: Vec<MemoryId>,
    },
    /// Deprecated — was verified but evidence has since expired
    Stale {
        was_verified_at: DateTime<Utc>,
        staleness_detected_at: DateTime<Utc>,
        reason: String,
    },
}
```

**How it integrates with existing Cortex**:

1. **New memories start as Conjecture**: When an agent creates a memory from
   a conversation, it's a conjecture. Confidence is set but epistemic status
   is explicitly "unverified."

2. **Validation promotes to Provisional/Verified**: When cortex-validation
   runs and a memory passes all 4 dimensions (citation, temporal, contradiction,
   pattern alignment), it promotes to Provisional. When a user explicitly
   confirms or multiple agents independently corroborate, it promotes to Verified.

3. **Evidence decay triggers Stale**: When a Verified memory's evidence
   freshness (TR6, Metric 5) drops below 0.5, it transitions to Stale.
   This is the automated "evidence expiry" that TS11 calls for.

4. **Retrieval uses epistemic status**: The retrieval engine can weight
   Verified memories higher than Conjectures. In high-stakes contexts
   (security audit, deployment decisions), filter to Verified-only.

**Connection to confidence**: Epistemic status is orthogonal to confidence.
A memory can have high confidence (0.9) but be a Conjecture (no one verified
it). A memory can have moderate confidence (0.6) but be Verified (multiple
people confirmed it, but it's in a contested domain). The two dimensions
together give a much richer picture of knowledge reliability.

**Conservative confidence aggregation (from TS11)**: The FPF paper proposes
using the Gödel t-norm (min operator) for aggregating confidence across
evidence sources, preventing weak evidence from inflating confidence. For
Cortex, this means:

```
aggregated_confidence = min(evidence_1.confidence, evidence_2.confidence, ...)
```

This is more conservative than our current weighted average approach but
prevents the "many weak signals = strong signal" fallacy. Consider offering
this as a configurable aggregation strategy alongside the existing approach.


---

## TR12: Evolution Pattern Detection — Recognizing Knowledge Lifecycle Stages

**Priority**: P2
**Evidence**: TS10, TS12, 04-DRIFT-DETECTION.md

Beyond raw metrics, the drift detection system should recognize higher-order
patterns in how knowledge evolves. Four patterns, each with detection logic
and recommended actions.

### Pattern 1: Knowledge Crystallization

Episodic memories about a topic accumulate → consolidation creates semantic
memories → semantic memories get validated → confidence rises → knowledge
"crystallizes" into stable, high-confidence understanding.

**Detection**: Track the lifecycle of knowledge clusters. Healthy clusters show:
episodic → semantic → validated → stable confidence. Measure time-to-crystallization
per topic area.

**Signal**: A topic that crystallizes quickly (< 2 weeks from first episodic to
stable semantic) indicates the team has strong understanding. A topic that takes
> 2 months suggests the area is complex or contested.

### Pattern 2: Knowledge Erosion

A once-stable area of knowledge starts losing confidence. Citations go stale,
patterns are no longer followed, tribal knowledge contradicts new practices.

**Detection**: Confidence trajectory turns negative for a cluster of related
memories over 2+ consecutive measurement windows.

**Alert**: "Knowledge about [auth module] has been eroding for 3 weeks.
5 memories have declining confidence. 2 file citations are stale."

**Recommended action**: Trigger targeted validation + re-embedding for the
affected area. Surface to the developer as a proactive health check.

### Pattern 3: Knowledge Explosion

A new area of the codebase suddenly generates many memories — new feature
development, major refactor, or incident response.

**Detection**: Memory creation rate for a file/module exceeds 3σ above the
30-day rolling average.

**Opportunity**: Proactively trigger consolidation for the affected area to
prevent knowledge fragmentation. The explosion phase generates many episodic
memories that should be consolidated into semantic knowledge before they decay.

### Pattern 4: Knowledge Conflict Wave

A change in convention or architecture creates a wave of contradictions as
old knowledge conflicts with new practices.

**Detection**: Contradiction density spikes (> 2× baseline), concentrated in
a specific memory type or file cluster.

**Action**: Trigger targeted validation + consolidation for the affected area.
Flag old memories that contradict the new convention for archival review.
This is the temporal equivalent of a "migration" — the knowledge base needs
to be updated to reflect the new reality.

**Connection to TS10 (Agent Drift)**: The Agent Drift paper identifies
"coordination drift" as a breakdown in multi-agent consensus. Knowledge
conflict waves are the single-agent equivalent — internal inconsistency
that degrades decision quality over time.

---

## TR13: Temporal-Aware Retrieval Boosting

**Priority**: P2
**Evidence**: TS7, TS8, TS14

Integrate temporal signals into the retrieval ranking pipeline. Currently,
cortex-retrieval ranks by a combination of embedding similarity, FTS5 score,
importance, and intent weights. Add temporal relevance as an additional signal.

**Temporal relevance factors**:

1. **Recency boost**: More recently validated memories get a small boost.
   Not recency of creation (that would penalize stable knowledge), but
   recency of last validation or access.

   ```
   recency_boost = 1.0 + 0.1 × exp(-days_since_last_validation / 30)
   ```

2. **Temporal alignment**: When the query has temporal context ("what did we
   decide about auth last sprint?"), boost memories whose valid_time falls
   within the implied time range.

3. **Epistemic status boost**: Verified memories get a 1.2× boost over
   Conjectures in the retrieval ranking. Stale memories get a 0.8× penalty.

4. **Evidence freshness**: Memories with high evidence freshness (TR6) rank
   higher than those with stale evidence, all else being equal.

**Integration point**: These factors multiply into the existing RRF score
in cortex-retrieval's ranking pipeline:

```
final_score = rrf_score × recency_boost × epistemic_boost × freshness_factor
```

**Connection to T-GRAG (TS7)**: T-GRAG's "Three-layer Interactive Retriever"
progressively filters retrieval across temporal subgraphs. Cortex's approach
is simpler (multiplicative boosting rather than subgraph filtering) but
achieves a similar effect — temporally relevant knowledge surfaces higher.

**Connection to Zep/Graphiti (TS8)**: Zep achieves 90% latency reduction
partly through temporal indexing that narrows the search space. Cortex's
temporal indexes (TR3) provide the same benefit — temporal range queries
can pre-filter candidates before embedding similarity is computed.

---

## TR14: cortex-temporal Crate Architecture

**Priority**: P0 (structural)
**Evidence**: 05-CORTEX-MAPPING.md

All temporal reasoning logic lives in a new `cortex-temporal` crate.

**Crate structure**:

```
crates/cortex/cortex-temporal/
├── Cargo.toml
├── src/
│   ├── lib.rs                    # re-exports
│   ├── engine.rs                 # TemporalEngine: implements ITemporalEngine
│   ├── event_store.rs            # append, query, replay (TR1)
│   ├── snapshot_engine.rs        # create, query, reconstruct (TR2)
│   ├── query/
│   │   ├── mod.rs
│   │   ├── as_of.rs              # point-in-time queries (TR3.1)
│   │   ├── range.rs              # temporal range queries (TR3.2)
│   │   ├── diff.rs               # temporal diff engine (TR3.3)
│   │   ├── replay.rs             # decision replay (TR3.4)
│   │   └── temporal_causal.rs    # temporal causal queries (TR3.5)
│   ├── drift/
│   │   ├── mod.rs
│   │   ├── metrics.rs            # KSI, confidence trajectory, etc. (TR6)
│   │   ├── alerting.rs           # drift alerts (TR7)
│   │   ├── snapshots.rs          # drift time-series storage (TR8)
│   │   └── patterns.rs           # evolution pattern detection (TR12)
│   ├── epistemic.rs              # epistemic status model (TR11)
│   └── views.rs                  # materialized temporal views (TR9)
├── tests/
│   ├── temporal_test.rs
│   ├── drift_test.rs
│   ├── property/
│   │   └── temporal_properties.rs
│   └── golden_test.rs
└── benches/
    └── temporal_bench.rs
```

**Dependencies**: cortex-core, cortex-storage, cortex-causal, cortex-observability

**Trait definition** (added to cortex-core):

```rust
#[async_trait]
pub trait ITemporalEngine: Send + Sync {
    // Event store
    async fn record_event(&self, event: MemoryEvent) -> Result<u64, CortexError>;
    async fn get_events(&self, memory_id: &str, before: Option<DateTime<Utc>>)
        -> Result<Vec<MemoryEvent>, CortexError>;

    // State reconstruction
    async fn reconstruct_at(&self, memory_id: &str, as_of: DateTime<Utc>)
        -> Result<Option<BaseMemory>, CortexError>;
    async fn reconstruct_all_at(&self, as_of: DateTime<Utc>, filter: Option<MemoryFilter>)
        -> Result<Vec<BaseMemory>, CortexError>;

    // Temporal queries
    async fn query_as_of(&self, query: AsOfQuery) -> Result<Vec<BaseMemory>, CortexError>;
    async fn query_range(&self, query: TemporalRangeQuery) -> Result<Vec<BaseMemory>, CortexError>;
    async fn query_diff(&self, query: TemporalDiffQuery) -> Result<TemporalDiff, CortexError>;
    async fn replay_decision(&self, query: DecisionReplayQuery)
        -> Result<DecisionReplay, CortexError>;
    async fn query_temporal_causal(&self, query: TemporalCausalQuery)
        -> Result<TraversalResult, CortexError>;

    // Drift detection
    async fn compute_drift_metrics(&self, window: Duration)
        -> Result<DriftSnapshot, CortexError>;
    async fn get_drift_alerts(&self) -> Result<Vec<DriftAlert>, CortexError>;

    // Materialized views
    async fn create_view(&self, label: &str, timestamp: DateTime<Utc>)
        -> Result<MaterializedTemporalView, CortexError>;
    async fn get_view(&self, label: &str)
        -> Result<Option<MaterializedTemporalView>, CortexError>;
}
```

---

## TR15: Changes to Existing Crates

**Priority**: P0 (structural)
**Evidence**: 05-CORTEX-MAPPING.md

### cortex-core additions:
- `MemoryEvent`, `MemoryEventType`, `EventActor` models
- `DriftSnapshot`, `DriftAlert`, `DriftAlertCategory` models
- `TemporalQuery` enum (AsOf, Range, Diff, Replay, TemporalCausal)
- `EpistemicStatus` enum (Conjecture, Provisional, Verified, Stale)
- `ITemporalEngine` trait
- `TemporalConfig` in config module (snapshot frequency, retention,
  alert thresholds, epistemic promotion rules)

### cortex-storage additions:
- Migration `v014_temporal_tables.rs`:
  - `memory_events` table + indexes
  - `memory_snapshots` table + indexes
  - `drift_snapshots` table + index
  - `materialized_views` table
  - Temporal indexes on existing `memories` table
- New query module: `queries/temporal_ops.rs`

### cortex-causal additions:
- New module: `temporal_graph.rs` (TR10)
  - `reconstruct_graph_at(timestamp)`
  - `temporal_traversal(memory_id, as_of, direction)`
- Extend `graph/sync.rs` to emit events for edge mutations

### cortex-validation additions:
- Temporal consistency check: memory references should be temporally consistent
- Epistemic status transitions on validation pass/fail

### cortex-observability additions:
- Drift metrics in health report
- Drift alerts in alerting system
- New metrics: KSI per type, confidence trajectories, EFI

### cortex-consolidation additions:
- Log consolidation events to event store
- Enable temporal replay of consolidation decisions

### cortex-napi additions:
- New binding module: `bindings/temporal.rs`
  - queryAsOf, queryRange, queryDiff, replayDecision, temporalCausal
  - getDriftMetrics, getDriftAlerts, createMaterializedView

### packages/cortex (TypeScript) additions:
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

## TR16: Migration Path — Four Phases

**Priority**: P0 (planning)
**Evidence**: 05-CORTEX-MAPPING.md

### Phase A: Event Store Foundation (TR1, TR2, TR14)
1. Add temporal models and trait to cortex-core
2. Create `memory_events` and `memory_snapshots` tables (migration v014)
3. Implement event recording in cortex-temporal
4. Wire existing mutation paths to also emit events
5. Implement snapshot creation (periodic background task)
6. **Quality gate**: Events are recorded for all mutation types. Snapshot
   creation runs without errors. Event replay reconstructs current state
   correctly (property test: replay all events = current state).

### Phase B: Temporal Queries (TR3, TR4, TR5)
1. Implement state reconstruction (snapshot + replay)
2. Implement point-in-time queries (AS OF)
3. Implement temporal range queries (BETWEEN)
4. Implement temporal diff engine
5. Enforce dual-time semantics and temporal referential integrity
6. **Quality gate**: AS OF query for current time returns same results as
   normal query. Diff between time T and T returns empty diff. Temporal
   joins respect referential integrity.

### Phase C: Decision Replay + Temporal Causal (TR3.4, TR3.5, TR10)
1. Implement decision replay (reconstruct retrieval context at past time)
2. Implement temporal causal graph reconstruction
3. Implement temporal causal traversal
4. Implement hindsight computation
5. **Quality gate**: Decision replay for a recent decision returns the same
   context that was actually used. Temporal causal traversal at current time
   matches current causal traversal.

### Phase D: Drift Detection + Alerting + Epistemic (TR6-TR9, TR11-TR13)
1. Implement drift metric calculation (5 metrics)
2. Implement drift snapshot storage (time-series)
3. Implement drift alerting rules
4. Implement epistemic status model
5. Implement evolution pattern detection
6. Implement materialized temporal views
7. Wire into observability health report
8. Wire NAPI bindings and TypeScript MCP tools
9. **Quality gate**: Drift metrics compute correctly for test fixtures.
   Alerts fire when thresholds are exceeded. Epistemic status transitions
   work correctly through the validation pipeline.

---

## TR17: Testing Strategy

**Priority**: P0

### Property-Based Tests (proptest)

| Property | Description |
|----------|-------------|
| Replay consistency | Replaying all events for a memory produces the current state |
| Snapshot + replay = full replay | Reconstructing from snapshot + events = reconstructing from all events |
| Temporal monotonicity | Events are ordered by event_id; recorded_at is monotonically non-decreasing |
| Diff symmetry | diff(A, B).created = diff(B, A).archived |
| Diff identity | diff(T, T) = empty diff for any time T |
| AS OF current = current | AS OF query for now() returns same results as normal query |
| KSI bounds | 0.0 ≤ KSI ≤ 1.0 for any window and memory type |
| Evidence freshness bounds | 0.0 ≤ freshness ≤ 1.0 for any memory |
| Epistemic ordering | Conjecture → Provisional → Verified is the only valid promotion path |
| Temporal referential integrity | No AS OF query returns a memory referencing a non-existent memory at that time |

### Golden Dataset Tests

- 5 temporal reconstruction scenarios: known event sequences with expected
  state at various time points
- 3 temporal diff scenarios: known before/after states with expected diffs
- 2 decision replay scenarios: known decisions with expected historical context
- 3 drift detection scenarios: known metric trajectories with expected alerts

### Performance Benchmarks

| Benchmark | Target |
|-----------|--------|
| Event append | < 0.1ms |
| Single memory reconstruction (50 events) | < 5ms |
| Single memory reconstruction (snapshot + 10 events) | < 1ms |
| Full state reconstruction (10K memories, with snapshots) | < 50ms |
| Temporal diff (two points, 10K memories) | < 100ms |
| Decision replay | < 200ms |
| Drift metric computation (10K memories) | < 500ms |

---

## TR18: Backward Compatibility Guarantees

**Priority**: P0

1. **All existing queries continue to work unchanged**. They implicitly query
   "as of now" — the temporal engine is an additional capability, not a
   replacement for current behavior.

2. **Event recording adds ~0.1ms per mutation**. This is an append-only write
   to a WAL-mode SQLite table — negligible overhead.

3. **Snapshot creation runs in background**. No impact on foreground operations.
   Uses the write connection via Mutex, yielding between batches.

4. **Temporal queries are new API surface**. No changes to existing MCP tools
   or CLI commands. New tools are additive.

5. **Pre-migration data**: Memories created before the temporal migration have
   no event history. Temporal queries for pre-migration time ranges return
   "no temporal data available." The system gracefully degrades — it doesn't
   error, it just has less history to work with.

6. **Storage overhead**: ~330MB for 10K memories over 6 months (events +
   snapshots). Well within SQLite's operational range. Bounded by the same
   retention policies as existing audit log rotation.

---

## Gap Analysis: What This Gives Cortex That Nobody Else Has

| Capability | Zep/Graphiti | T-GRAG | EverMemOS | Mem0 | XTDB | Cortex (proposed) |
|---|---|---|---|---|---|---|
| Bitemporal tracking | Partial (timestamps on edges) | Timestamps on facts | Timestamps on MemCells | ✗ | ✓ (gold standard) | ✓ (BaseMemory fields) |
| Event sourcing | ✗ | ✗ | ✗ | ✗ | ✓ (append-only log) | ✓ (memory_events) |
| Point-in-time queries | ✗ | ✗ | ✗ | ✗ | ✓ | ✓ |
| Temporal diff | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ (novel) |
| Decision replay | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ (novel) |
| Temporal causal graph | ✗ | Temporal subgraphs | ✗ | ✗ | ✗ | ✓ (novel) |
| Knowledge drift detection | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ (novel) |
| Epistemic status tracking | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ (novel, from FPF) |
| Evidence freshness scoring | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ (novel) |
| Typed memory (23 types) | ✗ | ✗ | Partial (MemCell) | ✗ | ✗ | ✓ |
| Code-aware temporal | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |

The combination of **bitemporal event sourcing + temporal causal graph
reconstruction + decision replay + knowledge drift detection + epistemic
status tracking** is completely novel. No existing system — academic or
commercial — offers this combination.

XTDB comes closest on the database layer but has no concept of causal graphs,
drift detection, or epistemic status. Zep/Graphiti has temporal awareness in
its knowledge graph but no event sourcing, no point-in-time queries, and no
drift metrics. T-GRAG handles temporal queries but on static document corpora,
not evolving agent memory.

Cortex's unique position: it already has the richest memory type system (23
types), the deepest causal graph (petgraph with inference, traversal, narrative),
and the most sophisticated validation pipeline (4-dimension with healing).
Adding temporal reasoning on top of this existing infrastructure creates a
system that is qualitatively different from anything else in the space.

---

## Summary of Recommendations

| ID | Recommendation | Priority | New Code | Touches |
|----|---------------|----------|----------|---------|
| TR1 | Event Store Foundation | P0 | cortex-temporal/event_store.rs | cortex-storage (v014), all mutation paths |
| TR2 | Snapshot Engine | P0 | cortex-temporal/snapshot_engine.rs | cortex-storage (v014) |
| TR3 | Temporal Query Algebra (5 types) | P0 | cortex-temporal/query/*.rs | cortex-core (models) |
| TR4 | Dual-Time Modeling | P1 | cortex-core/memory/base.rs | cortex-storage/queries |
| TR5 | Temporal Referential Integrity | P1 | cortex-temporal/query/*.rs | cortex-causal |
| TR6 | Knowledge Drift Detection (5 metrics) | P0 | cortex-temporal/drift/metrics.rs | cortex-observability |
| TR7 | Drift Alerting System | P1 | cortex-temporal/drift/alerting.rs | cortex-observability |
| TR8 | Drift Snapshot Time-Series | P1 | cortex-temporal/drift/snapshots.rs | cortex-storage (v014) |
| TR9 | Materialized Temporal Views | P2 | cortex-temporal/views.rs | cortex-storage (v014) |
| TR10 | Temporal Causal Graph Reconstruction | P2 | cortex-causal/temporal_graph.rs | cortex-causal |
| TR11 | Epistemic Layers | P1 | cortex-temporal/epistemic.rs | cortex-core, cortex-validation |
| TR12 | Evolution Pattern Detection | P2 | cortex-temporal/drift/patterns.rs | cortex-observability |
| TR13 | Temporal-Aware Retrieval Boosting | P2 | cortex-retrieval integration | cortex-retrieval |
| TR14 | cortex-temporal Crate Architecture | P0 | New crate | — |
| TR15 | Changes to Existing Crates | P0 | Multiple crates | 9 existing crates |
| TR16 | Migration Path (4 phases) | P0 | — | Planning |
| TR17 | Testing Strategy | P0 | Tests + benchmarks | cortex-temporal |
| TR18 | Backward Compatibility | P0 | — | Guarantees |

**Total new files**: ~20 (cortex-temporal crate + additions to existing crates)
**Total new migrations**: 1 (v014_temporal_tables.rs)
**Total new MCP tools**: 5
**Total new CLI commands**: 3
**Estimated implementation**: 4 phases, ~4-6 weeks

---

## Cross-Reference Addendum — Verified Against Research & Codebase

> Added after thorough cross-referencing of all 5 research documents
> (01-BITEMPORAL-THEORY through 05-CORTEX-MAPPING), the full Cortex codebase
> (19 crates, storage layer, NAPI bindings, TypeScript bridge), and fresh
> external research (February 2026). This addendum corrects inaccuracies,
> fills gaps, and adds implementation-critical details that the original
> recommendations missed.

### Additional Sources (Verified)

| ID | Source | Year | Relevance |
|----|--------|------|-----------|
| TS15 | [Azure Event Sourcing Pattern — Issues & Considerations](https://learn.microsoft.com/en-us/azure/architecture/patterns/event-sourcing) | 2025 | Microsoft's canonical reference: event versioning, idempotency, ordering, snapshot cost |
| TS16 | [Rust CQRS Event Upcasters](https://doc.rust-cqrs.org/advanced_event_upcasters.html) | 2025 | EventUpcaster trait pattern for Rust event schema evolution |
| TS17 | [Graphiti Bi-Temporal Edge Model](https://www.getzep.com/blog/beyond-static-knowledge-graphs/) | 2024 | Full bi-temporal implementation: created_at, expired_at, valid_at, invalid_at on edges |
| TS18 | [EverMemOS Cloud + SOTA Benchmarks](https://www.prnewswire.com/news-releases/end-agentic-amnesia-evermind-launches-a-memory-platform-and-an-80-000-global-competition-as-evermemos-sets-new-sota-results-across-multiple-benchmarks-302678025.html) | 2026 | Dual-layer memory (working + long-term), SOTA on 4 benchmarks, 100-300ms latency |
| TS19 | [Amazon Bedrock AgentCore Episodic Memory](https://aws.amazon.com/blogs/machine-learning/build-agents-to-learn-from-experiences-using-amazon-bedrock-agentcore-episodic-memory/) | 2025 | Managed episodic memory: situation/intent/assessment/justification/reflection per episode |
| TS20 | [Event Sourcing Best Practices — Schema Evolution](https://brettsblog.hashnode.dev/part-3-event-sourcing-best-practices) | 2025 | Versioned events, weak schema handling, upcaster patterns for production systems |
| TS21 | [CQRS Deduplication Strategies](https://domaincentric.net/blog/event-sourcing-projection-patterns-deduplication-strategies) | 2019 | At-least-once delivery requires deduplication; idempotent projections via event_id tracking |

---

### CR1: Gap Analysis Correction — Graphiti Bi-Temporal Model

**Issue**: The gap analysis table states Graphiti has "Partial (timestamps on
edges)" for bitemporal tracking. This understates their capability.

**Correction**: Graphiti implements a full bi-temporal model on edges with four
temporal fields (TS17):
- `created_at`: when the edge was added to the database (transaction time)
- `expired_at`: when the edge was invalidated in the database (transaction time)
- `valid_at`: when the relationship started in real-world time (valid time)
- `invalid_at`: when the relationship stopped being true in real-world time

This is proper bi-temporal tracking on edges, with LLM-driven temporal extraction
from natural language. However, Graphiti's bi-temporality is limited to edges
(relationships), not nodes (entities). Nodes don't carry temporal bounds. And
Graphiti doesn't offer event sourcing, temporal diff, decision replay, drift
detection, or epistemic status — those remain novel to Cortex.

**Updated gap analysis row for Graphiti**:

| Capability | Zep/Graphiti (corrected) |
|---|---|
| Bitemporal tracking | ✓ on edges (4-field model), ✗ on nodes |
| Point-in-time queries | Planned (temporal filtering on search API) |
| Event sourcing | ✗ |
| Temporal diff | ✗ |
| Decision replay | ✗ |

**Impact on Cortex differentiation**: Cortex's advantage over Graphiti is NOT
in basic bitemporal tracking (Graphiti has this on edges). It's in:
1. Bitemporal tracking on both memories AND relationships (full coverage)
2. Event sourcing with state reconstruction (Graphiti has no event store)
3. Temporal diff, decision replay, temporal causal graph (all novel)
4. Drift detection and epistemic status (all novel)
5. Code-aware temporal reasoning (file links, pattern links, function links)

---

### CR2: Missing — Event Schema Versioning Strategy

**Issue**: TR1 defines 16 `MemoryEventType` variants and a JSON `delta` field.
The Azure Event Sourcing pattern (TS15) identifies event schema evolution as
one of the hardest operational challenges: "If the schema of the persisted
events needs to change, it can be difficult to combine existing events in the
store with the new version."

The Rust CQRS library (TS16) provides an `EventUpcaster` trait specifically
for this problem. The RECOMMENDATIONS.md has no strategy for schema evolution.

**Addition to TR1 — Event Schema Versioning**:

Events are immutable — we never modify persisted events. When the schema
changes, we use upcasting (TS16, TS20):

```rust
/// Version stamp on every event.
struct MemoryEvent {
    // ... existing fields ...
    schema_version: u16,          // starts at 1, incremented on schema changes
}

/// Upcaster trait — converts old event schemas to current on read.
trait EventUpcaster: Send + Sync {
    fn can_upcast(&self, event_type: &str, schema_version: u16) -> bool;
    fn upcast(&self, event: RawEvent) -> RawEvent;
}
```

**Three rules for event evolution**:
1. **Additive only**: New fields are always optional with defaults. Never
   remove or rename fields in the delta JSON.
2. **New event types are free**: Adding a new `MemoryEventType` variant
   doesn't affect existing events. Old events with old types replay fine.
3. **Upcasters for breaking changes**: If a field must be restructured,
   write an upcaster that transforms old events on read. The persisted
   event is never modified. The upcaster runs in the replay pipeline
   between "read from SQLite" and "apply to state."

**Practical example**: If we later split `ContentUpdated` into
`ContentTextUpdated` and `ContentMetadataUpdated`, the upcaster converts
old `ContentUpdated` events into the appropriate new type based on which
fields are present in the delta JSON.

**Storage**: Add `schema_version INTEGER NOT NULL DEFAULT 1` to the
`memory_events` table schema in TR1.

---

### CR3: Missing — Idempotent Event Recording (Dual-Write Safety)

**Issue**: TR1's routing strategy writes to both the existing destination
(e.g., `memory_audit_log`) and the new `memory_events` table. This dual-write
creates a consistency risk: if the audit_log write succeeds but the event_store
write fails (or vice versa), the two stores diverge.

The Azure pattern (TS15) warns: "Event publication might be at least once,
and so consumers of the events must be idempotent." The CQRS deduplication
literature (TS21) emphasizes that at-least-once delivery requires explicit
deduplication.

**Addition to TR1 — Idempotent Event Recording**:

**Strategy 1 — Single transaction**: Wrap both writes in the same SQLite
transaction. Since both `memory_audit_log` and `memory_events` are in the
same database, this is straightforward:

```rust
async fn record_mutation(
    writer: &WriteConnection,
    audit_entry: &AuditEntry,
    event: &MemoryEvent,
) -> CortexResult<()> {
    writer.with_conn(|conn| {
        let tx = conn.transaction()
            .map_err(|e| to_storage_err(e.to_string()))?;
        // Both writes in same transaction — atomic
        audit::insert(&tx, audit_entry)?;
        event_store::append(&tx, event)?;
        tx.commit().map_err(|e| to_storage_err(e.to_string()))?;
        Ok(())
    }).await
}
```

This is the preferred approach. Both writes succeed or both fail. No
inconsistency possible.

**Strategy 2 — Idempotency key (fallback)**: If for any reason the writes
must be separate (e.g., different databases in a future multi-agent setup),
use the `event_id` as an idempotency key. Before appending, check if an
event with the same `memory_id + event_type + recorded_at` already exists.
Skip if duplicate.

**Recommendation**: Use Strategy 1 (single transaction). It's simpler,
leverages SQLite's ACID guarantees, and has zero overhead since both tables
are in the same database file. This aligns with the existing pattern in
`cortex-storage` where all mutations go through the single `WriteConnection`
Mutex.

---

### CR4: Missing — Event Store Compaction & Archival Strategy

**Issue**: TR2 defines snapshot retention (6 months full, then monthly, then
quarterly) but doesn't address event compaction. The event store grows
unbounded. At 10 events/memory/month for 10K memories, that's 1.2M events/year.
Over 3 years: 3.6M events, ~720MB. Still within SQLite's range, but the
growth is linear and unbounded.

**Addition to TR2 — Event Compaction**:

After a snapshot is created and verified, events before that snapshot are
candidates for compaction. Compaction does NOT delete events — it moves
them to a cold archive table:

```sql
CREATE TABLE memory_events_archive (
    -- same schema as memory_events
    event_id INTEGER PRIMARY KEY,
    memory_id TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    delta TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    caused_by TEXT,
    schema_version INTEGER NOT NULL DEFAULT 1,
    archived_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
```

**Compaction rules**:
1. Events older than 6 months with a verified snapshot after them → move
   to archive table
2. Archive table is queryable but not indexed for replay (saves index space)
3. For temporal queries older than 6 months, use snapshot + archive events
4. Archive table can be periodically exported to a separate SQLite file
   for long-term storage (matching existing backup/rotation patterns in
   `cortex-storage/recovery/backup.rs`)

**Compaction frequency**: Monthly, as a background task alongside the
existing audit log rotation.

**Storage impact**: With compaction, the active `memory_events` table stays
bounded at ~6 months of events (~600K rows for 10K memories). The archive
table grows but is not indexed, so it has minimal impact on query performance.

---

### CR5: Missing — Temporal Query Concurrency Model

**Issue**: The `WriteConnection` uses a `tokio::sync::Mutex` (verified in
`cortex-storage/src/pool/write_connection.rs`). Temporal reconstruction
queries (especially full-state reconstruction for 10K memories) could take
50-500ms. If these run on the write connection, they block all writes.

**Addition to TR3 — Concurrency Model**:

All temporal read queries MUST use the `ReadPool`, not the `WriteConnection`.
This is critical for performance:

- **Event replay** (read): Uses `ReadPool` — concurrent with writes
- **Snapshot lookup** (read): Uses `ReadPool` — concurrent with writes
- **State reconstruction** (read): Uses `ReadPool` — concurrent with writes
- **Event append** (write): Uses `WriteConnection` — serialized via Mutex
- **Snapshot creation** (write): Uses `WriteConnection` — serialized via Mutex

The `ReadPool` (verified in `cortex-storage/src/pool/read_pool.rs`) maintains
multiple read connections. SQLite WAL mode allows concurrent readers with a
single writer. Temporal queries are read-heavy by nature — they reconstruct
past state from immutable events. The only writes are event appends and
snapshot creation, which are fast (< 0.1ms per event, < 5ms per snapshot batch).

**Implication for cortex-temporal**: The `TemporalEngine` must accept both
a `WriteConnection` reference (for event appends) and a `ReadPool` reference
(for temporal queries). This matches the existing pattern in `StorageEngine`.

```rust
pub struct TemporalEngine {
    writer: &WriteConnection,    // for event_store.append(), snapshot.create()
    readers: &ReadPool,          // for all temporal queries
    config: TemporalConfig,
}
```

---

### CR6: Research Doc Coverage Verification — Knowledge Coverage Ratio

**Issue**: Research document 04-DRIFT-DETECTION.md defines 5 drift metrics:
1. Knowledge Stability Index (KSI) ✓ in TR6
2. Confidence Trajectory ✓ in TR6
3. Contradiction Density ✓ in TR6
4. Consolidation Efficiency ✓ in TR6
5. **Knowledge Coverage Ratio** — NOT in TR6

TR6 replaced the Coverage Ratio with Evidence Freshness Score (a novel metric).
This is a valid design choice — Evidence Freshness is more actionable and novel.
But the Coverage Ratio from the research should be acknowledged.

**Addition to TR6 — Coverage Ratio (Deferred)**:

The research document proposes a Knowledge Coverage Ratio:
```
coverage(module) = memories_linked_to(module) / code_complexity(module)
```

This metric is deferred to Phase D+ because:
1. It requires integration with code analysis (file-level complexity metrics)
   that cortex-temporal doesn't own
2. It overlaps with cortex-topology's gap detection (03-adaptive-topology,
   which will have its own coverage analysis)
3. Evidence Freshness Score (TR6, Metric 5) provides more immediate value
   for temporal reasoning specifically

When cortex-topology is implemented, Coverage Ratio should be computed there
and fed into the drift detection system as a 6th metric.

---

### CR7: Gap Analysis Update — New Competitors (Feb 2026)

**Issue**: The gap analysis table was compiled from research done in early 2026.
Two significant developments have occurred:

**1. EverMemOS Cloud Launch (Feb 2026, TS18)**:
EverMemOS launched its Cloud Service with SOTA results across 4 major memory
benchmarks. Key capabilities:
- Dual-layer memory: Working Memory (real-time) + Long-Term Memory (knowledge graphs)
- 93.05% LoCoMo accuracy (SOTA)
- 100-300ms latency for agentic loops
- Engram-inspired lifecycle: Episodic Trace → Semantic Consolidation → Adaptive Retrieval

EverMemOS still has NO temporal queries, NO event sourcing, NO drift detection,
and NO epistemic status tracking. Its strength is in the consolidation pipeline
(episodic → semantic), which Cortex already has via cortex-consolidation.

**2. Amazon Bedrock AgentCore Episodic Memory (June 2025, TS19)**:
Amazon launched managed episodic memory for AI agents. Key capabilities:
- Structured episodes: situation, intent, assessment, justification, reflection
- Cross-session learning from past experiences
- Managed infrastructure (no self-hosting)

AgentCore has NO bitemporal tracking, NO temporal queries, NO drift detection,
NO causal graphs, and NO epistemic status. It's a managed episodic memory
service, not a temporal reasoning engine.

**Updated gap analysis rows**:

| Capability | EverMemOS (updated) | Bedrock AgentCore |
|---|---|---|
| Bitemporal tracking | ✗ | ✗ |
| Event sourcing | ✗ | ✗ |
| Point-in-time queries | ✗ | ✗ |
| Temporal diff | ✗ | ✗ |
| Decision replay | ✗ | ✗ |
| Temporal causal graph | ✗ | ✗ |
| Knowledge drift detection | ✗ | ✗ |
| Epistemic status tracking | ✗ | ✗ |
| Evidence freshness scoring | ✗ | ✗ |
| Episodic → Semantic consolidation | ✓ (SOTA) | Partial (episodic only) |
| Managed/Cloud | ✓ (new) | ✓ |

**Impact on Cortex differentiation**: The competitive landscape has shifted
toward managed cloud services (EverMemOS Cloud, Bedrock AgentCore). Cortex's
differentiation is increasingly in the depth of temporal reasoning — no
competitor, managed or self-hosted, offers event sourcing + temporal queries +
drift detection + epistemic status. This is a durable moat.

---

### CR8: TR13 Integration Point Correction — Additive vs. Multiplicative Scoring

**Issue**: TR13 states:
```
final_score = rrf_score × recency_boost × epistemic_boost × freshness_factor
```

But the actual scorer in `cortex-retrieval/src/ranking/scorer.rs` (verified)
uses an **additive weighted model**:
```
score = Σ(weight_i × factor_i)  // 8 factors, weights sum to 1.0
```

The existing 8 factors are: semantic_similarity (0.25), keyword_match (0.15),
file_proximity (0.10), pattern_alignment (0.10), recency (0.10),
confidence (0.10), importance (0.10), intent_type_match (0.10).

A multiplicative boost on top of an additive score would create scaling
issues — a 1.2× epistemic boost would have outsized impact on the final
ranking compared to the individual factor weights.

**Corrected TR13 integration**:

Add temporal factors as additional weighted terms in the existing additive
model, not as multiplicative boosts:

```rust
// New weights (redistribute from existing factors)
pub struct ScorerWeights {
    pub semantic_similarity: f64,    // 0.22 (was 0.25)
    pub keyword_match: f64,          // 0.13 (was 0.15)
    pub file_proximity: f64,         // 0.10
    pub pattern_alignment: f64,      // 0.08 (was 0.10)
    pub recency: f64,                // 0.10
    pub confidence: f64,             // 0.10
    pub importance: f64,             // 0.08 (was 0.10)
    pub intent_type_match: f64,      // 0.08 (was 0.10)
    // New temporal factors
    pub evidence_freshness: f64,     // 0.06 (new)
    pub epistemic_status: f64,       // 0.05 (new)
}
```

This keeps the total weight at 1.0 and integrates temporal signals as
first-class scoring factors rather than post-hoc multipliers. The existing
`recency` factor (0.10) already captures temporal recency — the new factors
add evidence freshness and epistemic status as orthogonal signals.

**Alternative**: If we don't want to change existing weights (backward
compatibility concern), add temporal factors as a secondary re-ranking
pass after the primary 8-factor score. This is less elegant but preserves
existing ranking behavior exactly.

---

### CR9: Codebase Verification — All Integration Points Confirmed

Cross-referenced every integration point claimed in TR15 against the actual
codebase. Results:

| Claimed Integration | File Verified | Status |
|---|---|---|
| audit_log table (v006) | `migrations/v006_audit_tables.rs` | ✓ Schema matches |
| memory_versions table (v008) | `migrations/v008_versioning_tables.rs` | ✓ Schema matches |
| reclassification_history (v011) | `migrations/v011_reclassification.rs` | ✓ Schema matches |
| WAL mode enabled | `pool/pragmas.rs` | ✓ `PRAGMA journal_mode = WAL` |
| Single writer Mutex | `pool/write_connection.rs` | ✓ `tokio::sync::Mutex<Connection>` |
| Read pool for concurrent reads | `pool/mod.rs` | ✓ `ReadPool` + `WriteConnection` |
| Causal graph sync | `cortex-causal/src/graph/sync.rs` | ✓ `persist_edge`, `remove_persisted_edge` |
| 8-factor scorer | `cortex-retrieval/src/ranking/scorer.rs` | ✓ Additive weighted model (see CR8) |
| 4-dimension validation | `cortex-validation/src/engine.rs` | ✓ citation, temporal, contradiction, pattern |
| Health report | `cortex-observability/src/health/reporter.rs` | ✓ `HealthSnapshot` → `HealthReport` |
| NAPI bindings pattern | `cortex-napi/src/bindings/` | ✓ Per-subsystem modules |
| Config pattern | `cortex-core/src/config/` | ✓ Per-subsystem `{name}_config.rs` |
| Traits pattern | `cortex-core/src/traits/` | ✓ Per-subsystem trait files |
| Migration numbering | v001-v012 exist | ✓ v014 is correct (v013 = multi-agent) |
| BaseMemory temporal fields | `cortex-core/src/memory/base.rs` | ✓ `transaction_time`, `valid_time`, `valid_until` |

All 15 integration points verified. No discrepancies found.

---

### CR10: Missing — Temporal Event Ordering Guarantees

**Issue**: The Azure Event Sourcing pattern (TS15) warns: "Multi-threaded
applications and multiple instances of applications might be storing events
in the event store. The consistency of events in the event store is vital,
as is the order of events that affect a specific entity."

Cortex uses a single `WriteConnection` behind a Mutex, which serializes all
writes. This guarantees event ordering within a single process. But the
document should explicitly state this guarantee and its implications.

**Addition to TR1 — Ordering Guarantees**:

**Guaranteed**: Events for a single memory are strictly ordered by `event_id`
(monotonically increasing via `AUTOINCREMENT`). The `WriteConnection` Mutex
serializes all writes, so no two events can have the same `event_id` and
no events can be recorded out of order within a single Cortex instance.

**Not guaranteed across instances**: If multiple Cortex instances write to
the same database (future multi-agent scenario with cortex-multiagent), event
ordering requires additional coordination. The `caused_by` field in
`MemoryEvent` provides causal ordering (vector-clock-like), but total ordering
across instances would require a distributed sequence generator.

**For now**: Single-instance Cortex has perfect event ordering by construction.
The multi-agent scenario (cortex-multiagent, v013) should address cross-instance
ordering as part of its CRDT-based conflict resolution — temporal events from
different agents can be merged using the `caused_by` causal chain rather than
relying on wall-clock ordering.

---

### CR11: Phase A Quality Gate Enhancement — Replay Verification

**Issue**: TR16 Phase A's quality gate says "Event replay reconstructs current
state correctly (property test: replay all events = current state)." This is
the right property test, but the implementation needs more specificity.

**Addition to TR16 Phase A — Replay Verification Protocol**:

The replay verification should run as part of the migration itself:

1. After creating the `memory_events` table and wiring event emission
2. Run the system for a test period (or in test fixtures)
3. For each memory with events, verify:
   ```
   reconstruct_from_events(memory_id) == current_state(memory_id)
   ```
4. This property must hold for ALL fields in BaseMemory:
   - content (TypedContent)
   - summary
   - confidence
   - importance
   - tags
   - linked_patterns, linked_constraints, linked_files, linked_functions
   - archived, superseded_by, supersedes

**Edge case**: The `last_accessed` and `access_count` fields are updated on
every retrieval. These are NOT event-sourced (they're hot-path counters).
The replay verification should exclude these fields, or they should be
tracked via a lightweight `Accessed` event type (not in the original 16
variants). Recommendation: Add an `Accessed` event type but make it
optional — only record it if temporal access pattern analysis is needed.
Default: exclude from event sourcing to avoid write amplification on the
hot retrieval path.
