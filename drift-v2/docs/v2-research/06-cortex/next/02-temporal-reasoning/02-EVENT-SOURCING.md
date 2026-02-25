# Event Sourcing for Knowledge State Reconstruction

## Why Event Sourcing?

Event sourcing stores every state change as an immutable event. Instead of storing only
the current state, we store the complete history of changes. This enables:

1. Reconstruct any past state by replaying events up to a point in time
2. Complete audit trail for free
3. Temporal queries ("what did the state look like at time T?")
4. Debug by replaying the exact sequence of events that led to a state

Source: [Event Sourcing with SQLite](https://www.sqliteforum.com/p/building-event-sourcing-systems-with)

---

## Cortex Already Has the Events

Our audit_log table (Phase 2, `audit/logger.rs`) already records every mutation:

```
memory_id | operation | details (JSON) | actor | timestamp
```

Operations logged: create, update, archive, restore, link, unlink, decay, validate,
consolidate, reclassify.

And our versioning system stores full content snapshots on every update.

The missing piece is a **projection engine** that can replay these events to reconstruct
state at any point in time.

---

## Event Store Design

### Event Schema

```rust
struct MemoryEvent {
    /// Monotonically increasing event ID
    event_id: u64,
    /// The memory this event affects
    memory_id: MemoryId,
    /// When this event was recorded (transaction time)
    recorded_at: DateTime<Utc>,
    /// The type of event
    event_type: MemoryEventType,
    /// The full delta (what changed)
    delta: serde_json::Value,
    /// Who caused this event
    actor: EventActor,
    /// Causal predecessor events (for ordering)
    caused_by: Vec<u64>,
}

enum MemoryEventType {
    Created,
    ContentUpdated,
    ConfidenceChanged,
    ImportanceChanged,
    TagsModified,
    LinkAdded,
    LinkRemoved,
    RelationshipAdded,
    RelationshipRemoved,
    Archived,
    Restored,
    Decayed,
    Validated,
    Consolidated,
    Reclassified,
    Superseded,
}

enum EventActor {
    User(String),
    Agent(AgentId),
    System(String), // "decay_engine", "consolidation_engine", etc.
}
```

---

## State Reconstruction Algorithm

### Naive Approach: Full Replay

```
state_at(memory_id, target_time):
    events = get_events(memory_id, before=target_time)
    state = empty_memory()
    for event in events:
        state = apply_event(state, event)
    return state
```

Cost: O(n) where n = number of events for that memory. Fine for single memories,
expensive for bulk reconstruction.

### Optimized: Snapshot + Replay

Periodically create snapshots (full state captures). To reconstruct:

```
state_at(memory_id, target_time):
    snapshot = get_nearest_snapshot(memory_id, before=target_time)
    events = get_events(memory_id, after=snapshot.time, before=target_time)
    state = snapshot.state
    for event in events:
        state = apply_event(state, event)
    return state
```

Cost: O(k) where k = events since last snapshot. With weekly snapshots and ~10
events/week per memory, k ≈ 10.

### Snapshot Strategy

- **Automatic**: Snapshot every 50 events per memory
- **Periodic**: Weekly full-database snapshot (all active memories)
- **On-demand**: Snapshot before major operations (consolidation, migration)
- **Storage**: Snapshots stored in `memory_snapshots` table, compressed with zstd

---

## CQRS Separation

Command Query Responsibility Segregation naturally fits here:

**Command side** (writes):
- All mutations go through the event store
- Events are appended (never modified)
- Current state is updated as a projection of events

**Query side** (reads):
- Current state queries hit the existing `memories` table (fast, indexed)
- Historical queries hit the event store + snapshots (slower, but rare)
- Temporal queries use the reconstruction algorithm above

This means zero performance impact on current read paths. Historical queries are
an additional capability, not a replacement.

---

## SQLite as Event Store

SQLite is well-suited for event sourcing because:

1. Append-only writes are WAL-friendly (our existing WAL mode)
2. Sequential reads for replay are cache-friendly
3. Transactions guarantee event ordering
4. No external infrastructure needed

### Event Table Schema

```sql
CREATE TABLE memory_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    memory_id TEXT NOT NULL,
    recorded_at TEXT NOT NULL,  -- ISO 8601
    event_type TEXT NOT NULL,
    delta TEXT NOT NULL,        -- JSON
    actor_type TEXT NOT NULL,   -- 'user', 'agent', 'system'
    actor_id TEXT NOT NULL,
    caused_by TEXT,             -- JSON array of event_ids
    FOREIGN KEY (memory_id) REFERENCES memories(id)
);

CREATE INDEX idx_events_memory_time ON memory_events(memory_id, recorded_at);
CREATE INDEX idx_events_time ON memory_events(recorded_at);

CREATE TABLE memory_snapshots (
    snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
    memory_id TEXT NOT NULL,
    snapshot_at TEXT NOT NULL,
    state BLOB NOT NULL,       -- zstd-compressed JSON
    event_id INTEGER NOT NULL, -- snapshot is valid up to this event
    FOREIGN KEY (memory_id) REFERENCES memories(id)
);

CREATE INDEX idx_snapshots_memory_time ON memory_snapshots(memory_id, snapshot_at);
```

### Storage Overhead Estimate

For 10K memories with ~100 events each over 6 months:
- Events: 1M rows × ~200 bytes = ~200MB
- Snapshots (weekly, 26 weeks): 260K rows × ~500 bytes = ~130MB
- Total: ~330MB — well within SQLite's comfort zone

With monthly rotation of events older than 1 year (matching our existing audit rotation),
this stays bounded.
