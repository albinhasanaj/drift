# Cortex Temporal Reasoning — Stress Test & Silent Failure Exposure Plan

> **Date:** 2026-02-07
> **Goal:** Enterprise-grade verification — expose silent failures, edge cases, data corruption, and performance regressions
> **Approach:** Ultra-thorough. Every module gets adversarial testing. We're not checking if it works — we're trying to break it.

---

## Philosophy

The existing 129 tests prove the happy path works. This plan targets:

1. **Silent data corruption** — replay produces wrong state but doesn't error
2. **Edge case explosions** — boundary values, empty inputs, overflow, NaN propagation
3. **Concurrency hazards** — race conditions between readers and writers
4. **SQL injection / malformed data** — bad inputs that bypass validation
5. **Performance cliffs** — operations that degrade non-linearly at scale
6. **State machine violations** — impossible states that shouldn't exist but might
7. **Cross-module integration gaps** — modules that work alone but fail together

---

## Tier 1: Replay Correctness (HIGHEST PRIORITY)

Replay is the foundation. If replay is wrong, every temporal query returns garbage.

### 1.1 Replay Fidelity — Field-by-Field Exhaustive

**What could silently fail:** `apply_event` silently drops a field update because the delta JSON key doesn't match what the code expects.

| Test | Attack Vector | What Breaks |
|------|--------------|-------------|
| `replay_created_with_all_fields` | Created event with every BaseMemory field populated | Fields silently dropped during deserialization |
| `replay_content_updated_partial_delta` | ContentUpdated with only `new_summary` (no `new_content_hash`) | Code assumes both keys present, panics or silently skips |
| `replay_confidence_changed_boundary_values` | ConfidenceChanged with `new: 0.0`, `new: 1.0`, `new: -0.1`, `new: 1.5` | Confidence not clamped, negative/overflow values leak |
| `replay_tags_modified_duplicates` | TagsModified with `added: ["a", "a", "a"]` | Duplicate tags accumulate |
| `replay_tags_modified_remove_nonexistent` | TagsModified with `removed: ["nonexistent"]` | Panic on missing tag |
| `replay_tags_modified_add_then_remove_same` | TagsModified with `added: ["x"]` then `removed: ["x"]` in same event | Order-dependent behavior |
| `replay_importance_changed_invalid_variant` | ImportanceChanged with `new: "InvalidVariant"` | Silent deserialization failure, importance unchanged |
| `replay_reclassified_invalid_type` | Reclassified with `new_type: "NotAType"` | Silent deserialization failure |
| `replay_consolidated_null_merged_into` | Consolidated with `merged_into: null` | superseded_by set to None vs not set |
| `replay_archived_then_restored_then_archived` | Archive → Restore → Archive sequence | Final state must be archived=true |
| `replay_superseded_empty_string` | Superseded with `superseded_by: ""` | Empty string vs None confusion |
| `replay_unknown_event_type` | Event with type not in the 17 variants | Deserialization panic or silent skip |
| `replay_malformed_delta_json` | Event with `delta: "not json"` or `delta: null` | Panic on unwrap |
| `replay_created_then_created` | Two Created events for same memory | Second Created overwrites first — is this correct? |

### 1.2 Replay Ordering Attacks

| Test | Attack Vector | What Breaks |
|------|--------------|-------------|
| `replay_events_out_of_chronological_order` | Events with recorded_at timestamps out of order | Replay applies in array order, not time order — is this intentional? |
| `replay_interleaved_memories` | Events for memory A and B interleaved | Replay should only apply events matching the target memory |
| `replay_empty_event_list` | `replay_events([], shell)` | Returns shell unchanged — verify |
| `replay_single_event` | One Created event | Minimal path |
| `replay_1000_events` | 1000 sequential confidence changes | Floating point drift accumulation |

### 1.3 Reconstruction Correctness

| Test | Attack Vector | What Breaks |
|------|--------------|-------------|
| `reconstruct_at_exact_event_time` | target_time == event.recorded_at | Off-by-one: event included or excluded? |
| `reconstruct_at_between_events` | target_time between two events | Only earlier events should apply |
| `reconstruct_at_before_first_event` | target_time before any events exist | Should return None |
| `reconstruct_at_far_future` | target_time = year 3000 | Should return current state |
| `reconstruct_snapshot_at_exact_snapshot_time` | target_time == snapshot.snapshot_at | Snapshot included, no replay needed |
| `reconstruct_stale_snapshot` | Snapshot exists but events after it were compacted | Reconstruction gap — data loss |
| `reconstruct_corrupted_snapshot_zstd` | Snapshot with invalid zstd bytes | Should error, not panic |
| `reconstruct_all_at_with_10k_memories` | 10K memories, reconstruct all | Performance: must be < 50ms |
| `reconstruct_all_at_excludes_archived` | Mix of active and archived memories | Only active returned |

---

## Tier 2: Query Correctness

### 2.1 AS OF Query Edge Cases

| Test | Attack Vector | What Breaks |
|------|--------------|-------------|
| `as_of_epoch_zero` | system_time = 1970-01-01T00:00:00Z | No memories should exist |
| `as_of_future_time` | system_time = 2030-01-01 | Should return current state |
| `as_of_null_valid_time` | Memory with valid_until = None | Should be visible at all times |
| `as_of_memory_created_and_archived_same_second` | Created and Archived in same second | Depends on event ordering |
| `as_of_with_filter_no_matches` | Filter for type that doesn't exist | Empty result, not error |

### 2.2 Diff Edge Cases

| Test | Attack Vector | What Breaks |
|------|--------------|-------------|
| `diff_reversed_times` | time_a > time_b | Should swap created/archived per symmetry invariant |
| `diff_very_large_range` | time_a = epoch, time_b = now | All memories are "created" |
| `diff_with_only_modifications` | No creates/archives, only updates | modified list populated, created/archived empty |
| `diff_confidence_shift_exactly_0.2` | Confidence delta = exactly 0.2 | Boundary: > 0.2 triggers shift, == 0.2 does not |
| `diff_churn_rate_division_by_zero` | memories_at_a = 0 | churn_rate should be 0.0, not NaN/Infinity |
| `diff_scope_files_empty_list` | DiffScope::Files(vec![]) | Should return empty or all? |
| `diff_scope_namespace_unimplemented` | DiffScope::Namespace("test") | Currently returns all — document this |

### 2.3 Temporal Integrity

| Test | Attack Vector | What Breaks |
|------|--------------|-------------|
| `integrity_circular_superseded_by` | A superseded_by B, B superseded_by A | Infinite loop in integrity check? |
| `integrity_self_reference` | A superseded_by A | Should be stripped |
| `integrity_deep_chain` | A → B → C → D → E (5-deep superseded chain) | All refs valid, none stripped |
| `integrity_empty_memory_list` | enforce_temporal_integrity(vec![], now) | Should return empty vec |

---

## Tier 3: Dual-Time Correctness

| Test | Attack Vector | What Breaks |
|------|--------------|-------------|
| `correction_nonexistent_memory` | apply_temporal_correction for memory that doesn't exist | Should error gracefully |
| `correction_already_closed_memory` | Correct a memory that already has valid_until set | Double-close? |
| `late_arrival_valid_time_equals_transaction_time` | valid_time == transaction_time (not strictly "late") | Boundary: should this be allowed? |
| `late_arrival_valid_time_in_future` | valid_time > transaction_time | Should be rejected |
| `bounds_valid_time_equals_valid_until` | valid_time == valid_until (zero-duration validity) | Edge case: is this valid? |
| `bounds_valid_until_none` | valid_until = None (open-ended) | Should always pass bounds check |

---

## Tier 4: Drift Metrics Adversarial

### 4.1 KSI Edge Cases

| Test | Attack Vector | What Breaks |
|------|--------------|-------------|
| `ksi_window_with_zero_duration` | window_start == window_end | Division by zero or empty result |
| `ksi_window_in_future` | Both times in the future | Should return 1.0 (no events) |
| `ksi_massive_change_count` | 100K events in window with 10 memories | KSI should clamp to 0.0, not go negative |
| `ksi_single_memory_single_event` | 1 memory, 1 event | KSI = 1.0 - 1/(2*1) = 0.5 |
| `ksi_type_filter_nonexistent_type` | Filter for type with 0 memories | Should return 1.0 |

### 4.2 Evidence Freshness Edge Cases

| Test | Attack Vector | What Breaks |
|------|--------------|-------------|
| `freshness_user_validation_at_epoch` | validated_at = 1970-01-01 | Extremely stale, freshness ≈ 0.0 |
| `freshness_user_validation_in_future` | validated_at > now | freshness > 1.0? Should clamp |
| `freshness_product_of_zeros` | All factors = 0.0 | Product = 0.0, not NaN |
| `freshness_product_of_ones` | All factors = 1.0 | Product = 1.0 |
| `freshness_single_very_small_factor` | One factor = 0.001 | Product dominated by weakest link |
| `freshness_nan_factor` | Factor = NaN | NaN propagation through product |

### 4.3 Alerting Edge Cases

| Test | Attack Vector | What Breaks |
|------|--------------|-------------|
| `alert_empty_snapshot` | DriftSnapshot with all zeros | No alerts should fire |
| `alert_all_thresholds_exceeded` | Every metric exceeds every threshold | All 6 categories fire |
| `alert_dampening_exact_cooldown_boundary` | Alert at exactly cooldown_hours ago | Boundary: dampened or not? |
| `alert_dampening_different_severity_same_category` | Warning then Critical for same category | Critical should NOT be dampened by Warning |
| `alert_ksi_threshold_exactly_at_threshold` | KSI == threshold exactly | Should NOT fire (< threshold, not <=) |

---

## Tier 5: Epistemic State Machine

| Test | Attack Vector | What Breaks |
|------|--------------|-------------|
| `epistemic_stale_to_conjecture` | Attempt Stale → Conjecture | Should be rejected |
| `epistemic_stale_to_provisional` | Attempt Stale → Provisional | Should be rejected |
| `epistemic_double_promote` | Conjecture → Provisional → Provisional | Second promotion should fail |
| `epistemic_aggregation_empty_evidences` | aggregate_confidence([], strategy) | Should return 0.0 or 1.0? |
| `epistemic_aggregation_single_evidence` | aggregate_confidence([0.5], strategy) | Both strategies should return 0.5 |
| `epistemic_godel_all_high_one_zero` | GodelTNorm([0.9, 0.9, 0.0]) | Must return 0.0 |

---

## Tier 6: Concurrency & Performance

| Test | Attack Vector | What Breaks |
|------|--------------|-------------|
| `concurrent_append_and_read` | 10 threads appending, 10 threads reading | Data corruption, partial reads |
| `concurrent_snapshot_and_reconstruct` | Snapshot creation during reconstruction | Stale snapshot used |
| `concurrent_compaction_and_query` | Compaction running while queries execute | Events disappear mid-query |
| `append_100k_events_sequential` | 100K events one at a time | Must complete < 10s |
| `append_100k_events_batch` | 100K events in batches of 1000 | Must complete < 5s |
| `reconstruct_10k_memories` | 10K memories with 50 events each | Must complete < 50ms |
| `drift_metrics_10k_memories` | Full drift computation on 10K memories | Must complete < 500ms |
| `diff_10k_memories_2_week_window` | Diff across 10K memories | Must complete < 1s cold |

---

## Tier 7: SQL Injection & Malformed Data

| Test | Attack Vector | What Breaks |
|------|--------------|-------------|
| `memory_id_with_sql_injection` | memory_id = `"'; DROP TABLE memories; --"` | SQL injection |
| `memory_id_with_unicode` | memory_id = `"🔥temporal🔥"` | Unicode handling |
| `memory_id_empty_string` | memory_id = `""` | Empty string as ID |
| `memory_id_very_long` | memory_id = 10KB string | Buffer overflow |
| `event_delta_very_large` | delta = 1MB JSON blob | Storage limits |
| `event_delta_deeply_nested` | delta = 100-level nested JSON | Stack overflow on parse |
| `tag_with_special_characters` | tag = `"tag with spaces & 'quotes'"` | SQL escaping |
| `summary_with_null_bytes` | summary = `"hello\0world"` | Null byte handling |

---

## Tier 8: Cross-Module Integration

| Test | Attack Vector | What Breaks |
|------|--------------|-------------|
| `full_lifecycle_create_mutate_reconstruct` | Create → 20 mutations → reconstruct at 5 points | End-to-end correctness |
| `drift_after_mass_archival` | Archive 90% of memories → compute drift | KSI should reflect massive change |
| `epistemic_promotion_affects_retrieval_score` | Promote Conjecture → Verified → check score | Score should increase |
| `view_creation_then_diff` | Create view A → mutate → create view B → diff | Diff should show mutations |
| `compaction_then_reconstruct` | Compact old events → reconstruct at compacted time | Should still work via snapshot |
| `late_arrival_then_as_of` | Insert late-arriving fact → AS OF before arrival | Fact visible at valid_time, not transaction_time |

---

## Tier 9: Patterns Module

| Test | Attack Vector | What Breaks |
|------|--------------|-------------|
| `crystallization_no_data` | Empty database | Should return None, not error |
| `erosion_single_memory` | One memory with declining confidence | Should detect or return None gracefully |
| `explosion_zero_baseline` | No historical data for baseline | Division by zero in stddev |
| `conflict_wave_no_contradictions` | Clean database | Should return None |

---

## Tier 10: NAPI Bindings Verification

| Test | Attack Vector | What Breaks |
|------|--------------|-------------|
| `napi_invalid_iso8601_string` | system_time = "not a date" | Should return error, not panic |
| `napi_empty_string_params` | All string params = "" | Graceful handling |
| `napi_null_optional_params` | All optional params = None | Defaults applied correctly |
| `napi_type_conversion_round_trip` | Rust → NAPI → Rust for every type | Lossless conversion |

---

## Execution Priority

1. **Tier 1** (Replay) — If this is wrong, everything is wrong
2. **Tier 2** (Queries) — User-facing correctness
3. **Tier 4** (Drift) — Silent metric corruption
4. **Tier 5** (Epistemic) — State machine violations
5. **Tier 3** (Dual-Time) — Temporal integrity
6. **Tier 7** (SQL/Malformed) — Security
7. **Tier 8** (Integration) — Cross-module gaps
8. **Tier 6** (Concurrency) — Race conditions
9. **Tier 9** (Patterns) — Edge cases
10. **Tier 10** (NAPI) — Binding correctness

---

## Known Issues Found During Code Review

### Issue 1: `user_validation_freshness` uses wrong decay formula
```rust
let freshness = (-days / 90.0 * 0.693_f64.ln().abs()).exp();
```
The spec says `exp(-days/90 * 0.693)`. The code computes `0.693_f64.ln().abs()` which is `ln(0.693).abs() ≈ 0.366`. This means the decay is SLOWER than specified. The correct code should be:
```rust
let freshness = (-days / 90.0 * 0.693).exp();
```

### Issue 2: `diff` falls back to `get_memories_valid_at` instead of `reconstruct_all_at`
The diff module has a TODO comment: "Integrate with reconstruct_all_at when ReadPool is available." It currently uses `temporal_ops::get_memories_valid_at` which queries the current DB state, NOT the reconstructed state at that time. This means diff results may be incorrect for memories that were modified after the query time — the diff sees the current DB row, not the historical state.

### Issue 3: `reconstruct_all_at` uses raw SQL instead of `temporal_ops`
The `reconstruct_all_at` function directly queries `memory_events` with a raw SQL `SELECT DISTINCT memory_id`. This bypasses any filtering that `temporal_ops` might provide and could return memory IDs for events that don't correspond to actual memories (e.g., if a memory was deleted from the memories table but events remain).

### Issue 4: `confidence_trajectory` queries current DB state, not historical
`compute_confidence_trajectory` queries `AVG(confidence) FROM memories WHERE transaction_time <= ?`. This returns the CURRENT confidence of memories that existed at that time, not the confidence they HAD at that time. To get historical confidence, it would need to reconstruct state at each sample point.

### Issue 5: `consolidation_efficiency` JOIN may miss memories
The query JOINs `memory_events` with `memories` on `memory_id = id`. If a memory was consolidated (merged into another) and the original was deleted, the JOIN fails and the event is not counted.

### Issue 6: Property tests TTB-22, TTB-23, TTB-24 are stubs
These property tests contain `prop_assert!(true)` — they don't actually test the property. They defer to integration tests. This means the property-based guarantees for AS OF current, diff identity, and diff symmetry are NOT actually verified by proptest with random inputs.

### Issue 7: `append_batch` is not truly atomic
The batch append iterates and calls `insert_event` one at a time inside `with_conn`. If one insert fails mid-batch, the earlier inserts are committed (since each `insert_event` is a separate SQL statement). The batch should use an explicit `BEGIN TRANSACTION` / `COMMIT`.

### Issue 8: `empty_memory_shell` uses `Utc::now()` for timestamps
When reconstructing from events only (no snapshot), the shell's `transaction_time`, `valid_time`, and `last_accessed` are set to `Utc::now()`. If the Created event doesn't overwrite these (e.g., partial delta), the reconstructed memory has wrong timestamps.
