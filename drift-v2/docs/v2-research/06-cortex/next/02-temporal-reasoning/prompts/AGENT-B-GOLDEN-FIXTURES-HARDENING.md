# Agent B Prompt — Golden Fixtures + Resource Limits + Error Audit

You are hardening the cortex temporal reasoning system for a 10K+ user launch. Your work is independent of Agent A (who is fixing bugs in diff.rs, reconstruct.rs, and metrics.rs — do NOT touch those files). Read these files first:

- `STRESS-TEST-PLAN.md`
- `TEMPORAL-IMPLEMENTATION-SPEC.md`
- `FILE-MAP.md`
- `TEMPORAL-TASK-TRACKER.md` (Golden Fixtures section)

**Context:** 204 tests pass, 0 clippy warnings. The system works but has no golden fixtures (format regression protection), no resource limits (could OOM on large datasets), and generic error messages (will generate support tickets). You're fixing all three.

**Current state:** Do NOT modify these files (Agent A is working on them):
- `crates/cortex/cortex-temporal/src/query/diff.rs`
- `crates/cortex/cortex-temporal/src/snapshot/reconstruct.rs`
- `crates/cortex/cortex-temporal/src/drift/metrics.rs`
- `crates/cortex/cortex-temporal/src/engine.rs`

---

## Part 1: Golden Test Fixtures

Golden fixtures are known-good JSON snapshots that catch serialization format drift. If a serde attribute changes, a field is renamed, or a type conversion silently drops data — golden tests catch it because they compare against a frozen expected output.

### Fixture Files to Create

Create these in `crates/cortex/test-fixtures/golden/temporal/`:

#### 1. `reconstruction_simple.json`
A fixture with:
- 1 memory ("golden-mem-1")
- 10 events: Created, 3× ConfidenceChanged, 2× TagsModified, ContentUpdated, ImportanceChanged, Archived, Restored
- Expected state at 3 time points (after event 3, after event 6, after event 10)
- Each expected state is a full serialized `BaseMemory` JSON

Format:
```json
{
  "description": "Simple reconstruction: 1 memory, 10 events, 3 checkpoints",
  "memory_id": "golden-mem-1",
  "events": [ ... ],
  "checkpoints": [
    { "after_event_index": 3, "expected_state": { ... } },
    { "after_event_index": 6, "expected_state": { ... } },
    { "after_event_index": 10, "expected_state": { ... } }
  ]
}
```

To generate the expected states: write the events, replay them using `cortex_temporal::event_store::replay::replay_events`, serialize the result, and paste it into the fixture. The test then replays the same events and asserts the output matches the fixture exactly.

#### 2. `reconstruction_with_snapshot.json`
- 1 memory, 50 events, 1 snapshot at event 25
- Expected state at 5 time points (events 10, 25, 30, 40, 50)
- Tests that snapshot + replay produces the same result as full replay

#### 3. `diff_empty.json`
- A diff query where time_a == time_b
- Expected output: empty TemporalDiff with all zero stats

#### 4. `drift_stable.json`
- 10 memories, no changes in window
- Expected KSI = 1.0, contradiction_density = 0.0
- Full expected DriftSnapshot JSON

#### 5. `epistemic_lifecycle.json`
- One memory going through Conjecture → Provisional → Verified → Stale
- Expected EpistemicStatus JSON at each stage

### Golden Test File

**File to create:** `crates/cortex/cortex-temporal/tests/golden_test.rs`

Structure:
```rust
//! Golden fixture tests — frozen expected outputs for format regression detection.

use std::fs;
use serde_json::Value;

fn load_fixture(name: &str) -> Value {
    let path = format!(
        "{}/test-fixtures/golden/temporal/{}.json",
        env!("CARGO_MANIFEST_DIR").replace("/cortex-temporal", ""),
        name
    );
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to load fixture {}: {}", name, e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse fixture {}: {}", name, e))
}
```

Each test loads the fixture, replays the events, and asserts the output matches the expected state field-by-field. Use `assert_eq!` on the serialized JSON (not the Rust structs) so that serde format changes are caught.

---

## Part 2: Resource Limits and Graceful Degradation

These are additive changes — you're adding guards, not changing logic.

### 2.1 Reconstruction Event Limit

**File:** `crates/cortex/cortex-temporal/src/snapshot/reconstruct.rs` — but Agent A is modifying this file. Instead, add the limit in the calling code or create a new wrapper.

**Alternative file:** `crates/cortex/cortex-temporal/src/event_store/query.rs`

Add a constant and a check:
```rust
/// Maximum events to replay without a snapshot. Beyond this, reconstruction
/// is too expensive and the caller should create a snapshot first.
pub const MAX_REPLAY_EVENTS: usize = 10_000;
```

In `get_events` and `get_events_after_id`, if the result exceeds `MAX_REPLAY_EVENTS`, log a warning via `tracing::warn!` but still return the events (don't error — that would break existing behavior). The warning gives operators visibility into expensive reconstructions.

### 2.2 Drift Computation Timeout Guard

**File:** `crates/cortex/cortex-temporal/src/drift/alerting.rs`

Add a timing guard around `evaluate_drift_alerts`:
```rust
let start = std::time::Instant::now();
// ... existing alert evaluation ...
if start.elapsed() > std::time::Duration::from_secs(30) {
    tracing::warn!(
        elapsed_ms = start.elapsed().as_millis(),
        "Drift alert evaluation exceeded 30s budget"
    );
}
```

### 2.3 Batch Size Limit

**File:** `crates/cortex/cortex-temporal/src/event_store/append.rs`

Add a constant and validation at the top of `append_batch`:
```rust
/// Maximum batch size for event appends. Larger batches should be chunked by the caller.
pub const MAX_BATCH_SIZE: usize = 5_000;

// In append_batch:
if events.len() > MAX_BATCH_SIZE {
    return Err(CortexError::TemporalError(
        TemporalError::EventAppendFailed(format!(
            "Batch size {} exceeds maximum {}. Split into smaller batches.",
            events.len(), MAX_BATCH_SIZE
        )),
    ));
}
```

### 2.4 Query Result Size Warning

**File:** `crates/cortex/cortex-temporal/src/query/as_of.rs`

After the query returns results, add:
```rust
if results.len() > 10_000 {
    tracing::warn!(
        count = results.len(),
        "AS OF query returned >10K memories — consider adding a filter"
    );
}
```

Do the same in `range.rs`.

---

## Part 3: Error Message Audit

Every error path should produce a message that tells the user WHAT failed, WHY, and WHAT TO DO. Audit these files and improve error messages:

### 3.1 `crates/cortex/cortex-temporal/src/event_store/append.rs`

Current: errors from `event_ops::insert_event` bubble up as generic storage errors.
Improve: wrap with context about which memory_id and event_type failed.

```rust
// Before:
event_ops::insert_event(conn, ...)?;

// After:
event_ops::insert_event(conn, ...).map_err(|e| {
    CortexError::TemporalError(TemporalError::EventAppendFailed(format!(
        "Failed to append {} event for memory '{}': {}",
        event_type, memory_id, e
    )))
})?;
```

### 3.2 `crates/cortex/cortex-temporal/src/snapshot/create.rs`

Improve snapshot creation errors to include the memory_id and the reason (threshold, periodic, manual).

### 3.3 `crates/cortex/cortex-temporal/src/event_store/compaction.rs`

Improve compaction errors to include the date range being compacted and the snapshot_id being used as the safety boundary.

### 3.4 `crates/cortex/cortex-temporal/src/epistemic/transitions.rs`

The `InvalidEpistemicTransition` error already has `from` and `to` fields. Verify that the error messages include the memory_id when available (it may need to be threaded through from the caller).

### 3.5 NAPI Error Boundary

**File:** `crates/cortex/cortex-napi/src/bindings/temporal.rs`

The NAPI bindings convert `CortexError` to `napi::Error` via `error_types::to_napi_error`. Verify that the conversion preserves the full error chain (not just the top-level message). If a user passes an invalid ISO 8601 string, the error should say `"Invalid ISO 8601 time 'not-a-date': ..."` not just `"parse error"`.

Check: the `parse_time` function already has good error messages. Verify the same quality for `parse_range_mode`, `parse_direction`, and `parse_filter`.

---

## Part 4: Tests for Resource Limits

Add these to `crates/cortex/cortex-temporal/tests/stress_test.rs`:

```rust
#[tokio::test]
async fn batch_append_exceeds_max_size() {
    // Create a batch larger than MAX_BATCH_SIZE
    // Verify it returns an error with a helpful message
    // Verify no events were partially committed
}

#[test]
fn error_messages_include_context() {
    // Verify that error messages from various paths include
    // the memory_id, event_type, or other context
    // This is a documentation test — it ensures error quality
}
```

---

## Verification Checklist

After completing all work:

- [ ] `cargo check -p cortex-temporal` exits 0
- [ ] `cargo clippy -p cortex-temporal` — zero warnings
- [ ] `cargo test -p cortex-temporal` — ALL tests pass (204+ existing + your new ones)
- [ ] `cargo test -p cortex-temporal --test golden_test` — all golden tests pass
- [ ] `cargo test -p cortex-temporal --test stress_test` — all stress tests pass
- [ ] Golden fixture JSON files exist and are valid JSON
- [ ] No existing test was deleted or had its assertion weakened
- [ ] You did NOT modify: `diff.rs`, `reconstruct.rs`, `metrics.rs`, `engine.rs`

## Files You Will Create

- `crates/cortex/test-fixtures/golden/temporal/reconstruction_simple.json`
- `crates/cortex/test-fixtures/golden/temporal/reconstruction_with_snapshot.json`
- `crates/cortex/test-fixtures/golden/temporal/diff_empty.json`
- `crates/cortex/test-fixtures/golden/temporal/drift_stable.json`
- `crates/cortex/test-fixtures/golden/temporal/epistemic_lifecycle.json`
- `crates/cortex/cortex-temporal/tests/golden_test.rs`

## Files You Will Modify

- `crates/cortex/cortex-temporal/src/event_store/query.rs` (replay event limit warning)
- `crates/cortex/cortex-temporal/src/event_store/append.rs` (batch size limit + error context)
- `crates/cortex/cortex-temporal/src/drift/alerting.rs` (timing guard)
- `crates/cortex/cortex-temporal/src/query/as_of.rs` (result size warning)
- `crates/cortex/cortex-temporal/src/query/range.rs` (result size warning)
- `crates/cortex/cortex-temporal/src/snapshot/create.rs` (error context)
- `crates/cortex/cortex-temporal/src/event_store/compaction.rs` (error context)
- `crates/cortex/cortex-temporal/src/epistemic/transitions.rs` (verify error context)
- `crates/cortex/cortex-napi/src/bindings/temporal.rs` (verify error chain preservation)
- `crates/cortex/cortex-temporal/tests/stress_test.rs` (resource limit tests)
