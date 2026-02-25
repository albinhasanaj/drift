# Agent A Prompt — Bug Fixes (Issues 2-5) + Concurrency Stress Tests

You are fixing 4 silent-data-corruption bugs in the cortex temporal reasoning system, then writing concurrency stress tests. Read these files first:

- `STRESS-TEST-PLAN.md` (Known Issues section, Issues 2-5)
- `TEMPORAL-IMPLEMENTATION-SPEC.md`
- `FILE-MAP.md`

**Context:** This system is about to ship to 10K+ users. Issues 1, 6, 7, 8 have already been fixed. Issues 2-5 are all "returns wrong data silently" bugs — the most dangerous kind. After fixing them, you'll write concurrency tests because 10K users means concurrent SQLite access.

**Current state:** 204 tests pass, 0 clippy warnings, 0 compile errors. Do NOT break any existing tests.

---

## Part 1: Bug Fixes (do these FIRST)

### Issue 2: `diff` uses current DB state instead of reconstructed historical state

**File:** `crates/cortex/cortex-temporal/src/query/diff.rs`

**The bug:** Lines ~56-57 call `temporal_ops::get_memories_valid_at(conn, earlier, earlier)` and `get_memories_valid_at(conn, later, later)`. This queries the CURRENT database rows filtered by time, NOT the reconstructed state at those times. If a memory's confidence was 0.8 at time A, then changed to 0.3 at time B, and then changed to 0.9 at time C — a diff between A and B will see confidence 0.9 (the current DB value), not 0.8 and 0.3.

**The fix:** The `execute_diff` function currently takes a `&Connection`. It needs access to `ReadPool` to call `reconstruct_all_at`. You have two options:

1. Change the signature to accept `&Arc<ReadPool>` instead of `&Connection`, then call `snapshot::reconstruct::reconstruct_all_at(readers, earlier)` and `reconstruct_all_at(readers, later)` to get true historical state. This requires updating all callers (engine.rs line ~107 where `query_diff` calls `readers.with_conn(|conn| query::diff::execute_diff(conn, query))`).

2. Keep the `&Connection` signature but add a second function `execute_diff_with_reconstruction` that takes `&Arc<ReadPool>` and uses reconstruction. The engine calls the new function; the old one remains for backward compatibility.

Option 1 is cleaner. The callers are:
- `crates/cortex/cortex-temporal/src/engine.rs` — `query_diff` method
- `crates/cortex/cortex-temporal/tests/query_test.rs` — multiple test functions
- `crates/cortex/cortex-temporal/tests/stress_test.rs` — diff tests
- `crates/cortex/cortex-temporal/tests/property/temporal_properties.rs` — `prop_diff_identity` and `prop_diff_symmetry_invariant`

**Important:** The `get_memories_modified_between` call on line ~54 should stay — it's the event-range optimization for finding WHICH memories changed. The fix is only about how we get the state of those memories at each time point.

**Test to add:** Create a memory, change its confidence at T1, change it again at T2. Diff between T0 and T1 should show the T1 confidence, not the T2 (current) confidence.

### Issue 3: `reconstruct_all_at` uses raw SQL instead of `temporal_ops`

**File:** `crates/cortex/cortex-temporal/src/snapshot/reconstruct.rs`

**The bug:** Lines ~72-84 use a raw `SELECT DISTINCT memory_id FROM memory_events WHERE recorded_at <= ?1`. This bypasses any filtering that `temporal_ops` provides and could return memory IDs for events that don't correspond to actual memories (e.g., if a memory was deleted from the `memories` table but events remain as orphans).

**The fix:** Add a validation step. After collecting memory_ids from events, cross-reference against the `memories` table to confirm each ID exists. Alternatively, use a JOIN:

```sql
SELECT DISTINCT me.memory_id 
FROM memory_events me
INNER JOIN memories m ON me.memory_id = m.id
WHERE me.recorded_at <= ?1
```

This ensures we only reconstruct memories that actually exist in the memories table. The `INNER JOIN` is the minimal fix.

**Test to add:** Insert events for a memory_id that doesn't exist in the `memories` table. Call `reconstruct_all_at`. Verify the orphaned memory_id is NOT in the results.

### Issue 4: `confidence_trajectory` queries current confidence, not historical

**File:** `crates/cortex/cortex-temporal/src/drift/metrics.rs`

**The bug:** `compute_confidence_trajectory` (lines ~113-160) queries `AVG(confidence) FROM memories WHERE transaction_time <= ?`. This returns the CURRENT confidence column of memories that existed at that time — not the confidence they HAD at that time. If a memory was created at T1 with confidence 0.9, then updated to 0.3 at T2, querying at T1 returns 0.3 (the current DB value), not 0.9.

**The fix:** This is the hardest of the four. True historical confidence requires reconstructing state at each sample point, which is expensive. Two approaches:

1. **Accurate but slow:** For each sample point, call `reconstruct_all_at(readers, sample_time)` and compute the average confidence from the reconstructed states. This is O(sample_points × memories × events) — potentially very slow for large datasets.

2. **Approximate but fast (recommended):** Use the `memory_events` table to compute confidence at each sample point. For each sample point, find the most recent `confidence_changed` or `created` event before that time for each memory, and use that confidence value. This is a SQL-only approach:

```sql
SELECT AVG(latest_conf) FROM (
    SELECT me.memory_id, 
           (SELECT COALESCE(
               JSON_EXTRACT(me2.delta, '$.new'),
               JSON_EXTRACT(me2.delta, '$.confidence')
           )
           FROM memory_events me2 
           WHERE me2.memory_id = me.memory_id 
             AND me2.recorded_at <= ?1
             AND me2.event_type IN ('confidence_changed', 'created')
           ORDER BY me2.recorded_at DESC LIMIT 1
           ) as latest_conf
    FROM (SELECT DISTINCT memory_id FROM memory_events WHERE recorded_at <= ?1) me
)
```

If the SQL approach is too complex or SQLite's JSON functions aren't reliable enough, fall back to approach 1 but add a comment documenting the performance implications.

**Test to add:** Create a memory with confidence 0.9. Change confidence to 0.3. Compute trajectory with a sample point between the two events. The sample should show ~0.9, not 0.3.

### Issue 5: `consolidation_efficiency` JOIN misses deleted/consolidated memories

**File:** `crates/cortex/cortex-temporal/src/drift/metrics.rs`

**The bug:** `compute_consolidation_efficiency` (lines ~230-270) JOINs `memory_events me JOIN memories m ON me.memory_id = m.id`. If a memory was consolidated (merged into another) and the original row was deleted from the `memories` table, the JOIN fails silently — the event is not counted. This means the metric underreports both semantic creations and episodic archivals.

**The fix:** Use a LEFT JOIN or remove the JOIN entirely. The `memory_events` table already has the `event_type` field. We only need the JOIN to filter by `memory_type`. Instead, store the memory_type in the event delta, or query the memory_type from the event's delta JSON.

Simplest fix: query events directly and extract the memory type from the delta or from a subquery that tolerates missing rows:

```sql
SELECT COUNT(*) FROM memory_events me
LEFT JOIN memories m ON me.memory_id = m.id
WHERE COALESCE(m.memory_type, 
    (SELECT JSON_EXTRACT(me2.delta, '$.memory_type') 
     FROM memory_events me2 
     WHERE me2.memory_id = me.memory_id 
       AND me2.event_type = 'created' 
     LIMIT 1)
) = 'semantic'
AND me.event_type = 'created'
AND me.recorded_at >= ?1
AND me.recorded_at <= ?2
```

Or the simpler approach: just remove the type filter from the JOIN and count ALL created/archived events, then use the `memory_type` from the `Created` event's delta. If this is too complex, document the limitation and add a `-- KNOWN LIMITATION` comment.

**Test to add:** Create an episodic memory, archive it, then DELETE the row from the `memories` table (simulating consolidation cleanup). Compute consolidation efficiency. The archived event should still be counted.

---

## Part 2: Concurrency Stress Tests (do AFTER Part 1)

**File to create:** Add tests to `crates/cortex/cortex-temporal/tests/stress_test.rs`

These tests verify the system handles concurrent access correctly. SQLite uses WAL mode with `IMMEDIATE` transactions. With 10K users, we need to verify:

### Test 1: `concurrent_append_and_read`
- Spawn 5 tokio tasks that each append 100 events
- Spawn 5 tokio tasks that each read events for the same memory
- All tasks run simultaneously
- After all complete: verify total event count == 500
- Verify no panics, no data corruption, no `SQLITE_BUSY` errors bubbling up

### Test 2: `concurrent_reconstruct_during_append`
- Spawn a writer task that appends 200 events over time
- Spawn 3 reader tasks that continuously call `reconstruct_at` for the same memory
- Each reconstruction should return a valid state (not None, not corrupted)
- The confidence value should be monotonically related to the events applied

### Test 3: `concurrent_diff_during_mutation`
- Spawn a writer task that creates and archives memories
- Spawn 2 reader tasks that continuously compute diffs
- Diffs should never panic and should always satisfy the symmetry invariant

### Test 4: `concurrent_drift_metrics`
- Spawn a writer task that creates events
- Spawn a reader task that computes `compute_all_metrics` repeatedly
- Metrics should always be valid (KSI in [0,1], no NaN, no panic)

### Test 5: `concurrent_batch_append_contention`
- Spawn 3 tasks that each call `append_batch` with 100 events simultaneously
- After all complete: verify total event count == 300
- Verify all returned IDs are unique and strictly increasing within each batch

**Implementation notes:**
- Use `tokio::spawn` for concurrency
- Use `Arc<WriteConnection>` and `Arc<ReadPool>` shared across tasks
- Use `tokio::time::sleep` with small durations to create realistic interleaving
- Wrap assertions in the spawned tasks and collect `JoinHandle` results
- The `setup()` function from the existing stress_test.rs creates the DB — reuse it
- Mark tests with `#[tokio::test(flavor = "multi_thread", worker_threads = 4)]`

---

## Verification Checklist

After completing all work:

- [ ] `cargo check -p cortex-temporal` exits 0
- [ ] `cargo clippy -p cortex-temporal` — zero warnings
- [ ] `cargo test -p cortex-temporal` — ALL tests pass (should be 204+ existing + your new ones)
- [ ] `cargo test -p cortex-temporal --test stress_test` — all stress tests pass
- [ ] `cargo test -p cortex-temporal --test query_test` — all query tests pass (diff signature may have changed)
- [ ] `cargo test -p cortex-temporal --test property_tests` — all property tests pass
- [ ] No existing test was deleted or had its assertion weakened

## Files You Will Modify

- `crates/cortex/cortex-temporal/src/query/diff.rs` (Issue 2)
- `crates/cortex/cortex-temporal/src/snapshot/reconstruct.rs` (Issue 3)
- `crates/cortex/cortex-temporal/src/drift/metrics.rs` (Issues 4, 5)
- `crates/cortex/cortex-temporal/src/engine.rs` (if diff signature changes)
- `crates/cortex/cortex-temporal/tests/stress_test.rs` (new concurrency tests + bug verification tests)
- `crates/cortex/cortex-temporal/tests/query_test.rs` (if diff signature changes)
- `crates/cortex/cortex-temporal/tests/property/temporal_properties.rs` (if diff signature changes)
