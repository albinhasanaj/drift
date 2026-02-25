# Query Algebra for Temporal Memory Operations

## Core Temporal Query Types

### 1. Point-in-Time Query (AS OF)

"What did we know at time T?"

Reconstructs the complete memory state as it existed at a specific moment.
Both system_time and valid_time must be satisfied.

```rust
struct AsOfQuery {
    /// System time: "what was recorded by this time"
    system_time: DateTime<Utc>,
    /// Valid time: "what was true at this time"
    valid_time: DateTime<Utc>,
    /// Optional: filter to specific memories
    filter: Option<MemoryFilter>,
}

// Example: "What patterns did we know about on March 1st?"
let query = AsOfQuery {
    system_time: parse("2026-03-01T00:00:00Z"),
    valid_time: parse("2026-03-01T00:00:00Z"),
    filter: Some(MemoryFilter::by_type(MemoryType::PatternRationale)),
};
```

Implementation: Use version history + event replay to reconstruct each memory's
state at the target time. Filter out memories that didn't exist yet or were archived.

### 2. Temporal Range Query (BETWEEN)

"What memories were active during this period?"

Returns all memories that were valid at any point within a time range.

```rust
struct TemporalRangeQuery {
    /// Start of the range
    from: DateTime<Utc>,
    /// End of the range
    to: DateTime<Utc>,
    /// Include memories that were valid at any point in range (OVERLAPS)
    /// vs. memories that were valid for the entire range (CONTAINS)
    mode: TemporalRangeMode,
}

enum TemporalRangeMode {
    /// Memory was valid at any point in [from, to]
    Overlaps,
    /// Memory was valid for the entire [from, to] range
    Contains,
    /// Memory became valid during [from, to]
    StartedDuring,
    /// Memory stopped being valid during [from, to]
    EndedDuring,
}
```

### 3. Temporal Diff Query

"What changed between time A and time B?"

The most powerful query type. Compares two knowledge states and returns the delta.

```rust
struct TemporalDiffQuery {
    /// First snapshot time
    time_a: DateTime<Utc>,
    /// Second snapshot time
    time_b: DateTime<Utc>,
    /// What to diff
    scope: DiffScope,
}

enum DiffScope {
    /// All memories
    All,
    /// Specific memory types
    Types(Vec<MemoryType>),
    /// Memories linked to specific files
    Files(Vec<String>),
    /// Specific namespace
    Namespace(NamespaceId),
}

struct TemporalDiff {
    /// Memories that exist at time_b but not time_a
    created: Vec<MemorySnapshot>,
    /// Memories that exist at time_a but not time_b
    archived: Vec<MemorySnapshot>,
    /// Memories that exist at both but changed
    modified: Vec<MemoryModification>,
    /// Memories whose confidence changed significantly (>0.2 delta)
    confidence_shifts: Vec<ConfidenceShift>,
    /// New contradictions detected between time_a and time_b
    new_contradictions: Vec<Contradiction>,
    /// Contradictions resolved between time_a and time_b
    resolved_contradictions: Vec<Contradiction>,
    /// Memories reclassified between time_a and time_b
    reclassifications: Vec<Reclassification>,
    /// Summary statistics
    stats: DiffStats,
}

struct DiffStats {
    pub memories_at_a: usize,
    pub memories_at_b: usize,
    pub net_change: i64,
    pub avg_confidence_at_a: f64,
    pub avg_confidence_at_b: f64,
    pub confidence_trend: f64, // positive = improving
    pub knowledge_churn_rate: f64, // created + archived / total
}
```

### 4. Decision Replay Query

"Reconstruct the exact context available when Decision X was made."

Given a decision memory, reconstructs what the retrieval engine would have returned
at the time that decision was recorded.

```rust
struct DecisionReplayQuery {
    /// The decision memory to replay
    decision_memory_id: MemoryId,
    /// Optional: override the retrieval budget
    budget_override: Option<usize>,
}

struct DecisionReplay {
    /// The decision memory as it was at creation time
    decision: MemorySnapshot,
    /// All memories that were available at decision time
    available_context: Vec<MemorySnapshot>,
    /// What the retrieval engine would have returned
    retrieved_context: Vec<CompressedMemory>,
    /// Causal graph as it existed at decision time
    causal_state: CausalGraphSnapshot,
    /// What we know NOW that we didn't know THEN
    hindsight: Vec<HindsightItem>,
}

struct HindsightItem {
    /// Memory that exists now but didn't at decision time
    memory: MemorySnapshot,
    /// Would this have changed the decision?
    relevance: f64,
    /// How it relates to the decision
    relationship: String,
}
```

### 5. Temporal Causal Query

"At the time we adopted Pattern X, what was the causal chain?"

Reconstructs the causal graph as it existed at a specific point in time, then
runs traversal on that historical graph.

```rust
struct TemporalCausalQuery {
    /// The memory to trace causality for
    memory_id: MemoryId,
    /// The point in time to evaluate the causal graph
    as_of: DateTime<Utc>,
    /// Traversal direction
    direction: TraversalDirection,
    /// Max depth
    max_depth: usize,
}
```

This requires reconstructing the causal graph state at `as_of`, which means:
- Only include edges that existed at `as_of`
- Use edge strengths as they were at `as_of`
- Exclude edges that were pruned before `as_of`

---

## Query Optimization

### Materialized Temporal Views

For frequently-queried time points (sprint boundaries, release dates), pre-compute
and cache the knowledge state:

```rust
struct MaterializedTemporalView {
    label: String,           // "sprint-12", "v2.0-release"
    timestamp: DateTime<Utc>,
    memory_count: usize,
    snapshot_id: u64,        // reference to pre-computed snapshot
}
```

### Temporal Indexes

Add indexes optimized for temporal queries:

```sql
-- Fast lookup: "what memories were valid at time T?"
CREATE INDEX idx_memories_valid_range
ON memories(valid_time, valid_until)
WHERE archived = 0;

-- Fast lookup: "what memories were created between A and B?"
CREATE INDEX idx_memories_transaction_range
ON memories(transaction_time);

-- Fast event replay
CREATE INDEX idx_events_memory_time
ON memory_events(memory_id, recorded_at);
```

### Query Cost Estimates

| Query Type | Cold (no cache) | Warm (with snapshots) |
|---|---|---|
| Point-in-time (single memory) | ~5ms | ~1ms |
| Point-in-time (all memories) | ~500ms | ~50ms |
| Temporal diff (two points) | ~1s | ~100ms |
| Decision replay | ~2s | ~200ms |
| Temporal causal traversal | ~100ms | ~20ms |

These are acceptable for developer-facing queries that are inherently exploratory.
