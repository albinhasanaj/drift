# Agent Prompt: Cortex Memory System Hardening

## Your Mission

You are performing a phased hardening of **the entire Cortex memory system** — 23 Rust sub-crates (`crates/cortex/*`), 1 bridge crate (`crates/cortex-drift-bridge/`), 1 TypeScript package (`packages/cortex/`), and the NAPI runtime that binds them. This is Drift V2's persistent memory layer: temporal event sourcing, HDBSCAN consolidation, CRDT-based multi-agent convergence, 5-factor decay, hybrid FTS5+vector retrieval, 3-tier embedding cache, and 43 MCP tools.

A comprehensive audit has already been completed. **You are not auditing. You are implementing fixes and writing tests.** The audit found 45 issues (4 P0, 14 P1, 22 P2, 5 P3). The systemic theme is: **engines compute results but never persist them.** The algorithms are correct. The storage works. The wiring between them is missing.

**Your job is to wire them together and prove it works with tests that expose real bugs — not happy-path confirmation.**

**Speed does not matter. Correctness does. Every test must target a specific failure mode. Do not write tests that only confirm the happy path.**

---

## Documents You MUST Read Before Writing Any Code

Read these in order. Do not skip any. They are your ground truth.

1. **`docs/v2-research/CORTEX-DEEP-AUDIT-FINDINGS.md`** — The full audit: 45 findings across 14 sections (A–N) with line-verified evidence, code snippets, and root cause analysis. This is your bug list.

2. **`docs/v2-research/CORTEX-HARDENING-TASKS.md`** — The implementation spec: 144 tasks (62 impl + 82 test) across 6 phases (A–F) with exact file paths, line numbers, audit cross-references, dependency graph, and critical path. This is your work order.

3. **`crates/cortex/cortex-napi/src/runtime.rs`** — The singleton runtime that owns all engines. Every fix touches this file or something it creates. Understand the ownership graph before changing anything.

After reading all three, you should be able to answer:
- Which 4 bugs are P0 (production-breaking)?
- Why does learning generate a UUID but never create a memory?
- Why does consolidation run 6 phases but persist nothing?
- Why is multi-agent completely broken in in-memory mode?
- How many duplicate connection pools exist and where?

If you cannot answer all 5, re-read the documents.

---

## Phase Execution Order

Execute phases in this exact order. Do not skip ahead. Each phase has a **gate** — you must pass the gate before moving to the next phase.

### Phase A: Persistence Gap (P0 — start here)

**Goal:** Make learning and consolidation actually persist their results.

**Files you will modify:**
- `crates/cortex/cortex-learning/src/engine.rs` — Add `storage` field, build real `BaseMemory`, call `storage.insert()`
- `crates/cortex/cortex-consolidation/src/engine.rs` — Add `storage` field, persist created memories, archive source episodes
- `crates/cortex/cortex-consolidation/src/pipeline/mod.rs` — Replace hardcoded metrics, fix token estimation
- `crates/cortex/cortex-napi/src/runtime.rs` — Pass storage references to learning and consolidation engines
- `crates/cortex/cortex-napi/src/bindings/generation.rs` — Wire `_was_useful` to learning

**Implementation tasks:** A-01 through A-08 in the spec.

**Tests you will write (10 tests):** A-09 through A-18 in the spec.

**Testing philosophy for this phase:**
- A-09: Verify a real `BaseMemory` exists in storage after learning — not just that a UUID was returned. Query storage by ID, assert all fields (type, summary, confidence, content_hash) are populated.
- A-10: Insert the same correction twice. The second MUST NOT create a new memory. Verify dedup returns `Noop` or `Update`.
- A-11: **Mock `IMemoryStorage` that returns `Err` on insert.** Verify `learn()` propagates the error cleanly — no panic, no silent swallow.
- A-12: Run consolidation with 5 episodic memories. Verify a new `Semantic` memory exists in storage with `source_episodes` containing all 5 IDs.
- A-13: After consolidation, verify source episodes have `archived=true` and `superseded_by` set to the new semantic memory ID.
- A-14: **Mock storage that fails on the 3rd insert.** Verify no partial state — either all memories created or none. This tests atomicity.
- A-15: Run pipeline and verify `precision` is computed from actual recall gate scores, NOT the hardcoded `0.8`.
- A-16: Compare `len()/4` vs `TokenCounter::count()` on 100 real summaries. Assert max 10% deviation. This is a regression gate.
- A-17: Start consolidation in a background thread, attempt a second concurrent consolidation. Verify the second gets `MergeFailed`, the first completes normally.
- A-18: Call `track_outcome(ids, was_useful=false)`. Verify the learning engine receives the negative signal.

**Gate:** `cargo test -p cortex-learning -p cortex-consolidation` — all new tests pass. Run `cargo clippy -p cortex-learning -p cortex-consolidation` — zero warnings.

---

### Phase B: Connection Lifecycle (P0)

**Goal:** Eliminate 3 duplicate connection pools. Fix multi-agent per-call connection creation.

**Files you will modify:**
- `crates/cortex/cortex-napi/src/runtime.rs` — Remove duplicate `StorageEngine` for prediction, duplicate connections for temporal, duplicate `EmbeddingEngine` for consolidation. Add `multiagent: Option<Mutex<MultiAgentEngine>>`.
- `crates/cortex/cortex-napi/src/bindings/multiagent.rs` — Replace `get_engine()` per-call creation with `rt.multiagent` access. Fix `retract_memory` raw connection. Fix sync result hardcoded zeros.

**Implementation tasks:** B-01 through B-07 in the spec.

**Tests you will write (8 tests):** B-08 through B-15 in the spec.

**Testing philosophy for this phase:**
- B-08: **This is the critical in-memory test.** `register_agent("test")` → `get_agent("test")` → assert NOT null. This test FAILS today because each call gets an isolated in-memory DB. Your fix must make it pass.
- B-09: Insert a memory via main storage → call prediction → verify prediction finds it. Tests that prediction shares the storage connection.
- B-10: Emit a temporal event via main storage → query via temporal engine → verify event found. Tests temporal shares connections.
- B-11: File-backed mode: assert only 1 `WriteConnection` exists (not 3).
- B-12: Call `register_agent` 100 times. Assert no connection leak.
- B-13: Register 2 agents, create memories in agent A's namespace, sync A→B. Verify `applied_count > 0` (not hardcoded 0).
- B-14: Spawn 10 threads each calling different multi-agent functions. All must complete within 5 seconds. No deadlock.
- B-15: Share memory → retract → get → verify tombstoned. Tests retract uses shared DB.

**Gate:** `cargo test -p cortex-napi` — all new tests pass, including the in-memory multi-agent test (B-08) that currently fails. Zero clippy warnings.

---

### Phase C: Engine Wiring (P1)

**Goal:** Wire engines that exist but are never called, never hydrated, or never scheduled.

**Files you will modify:**
- `crates/cortex/cortex-core/src/traits.rs` (or equivalent) — Add `list_all_node_ids()` to `ICausalStorage`
- `crates/cortex/cortex-storage/src/engine.rs` — Implement `list_all_node_ids()`, route reads through read pool
- `crates/cortex/cortex-causal/src/graph/sync.rs` — Implement real `rebuild_from_storage`
- `crates/cortex/cortex-causal/src/engine.rs` — Call rebuild on init
- `crates/cortex/cortex-napi/src/runtime.rs` — Add decay scheduling, fix cloud API key, call causal hydration
- `crates/cortex/cortex-napi/src/bindings/health.rs` — Wire real data into health snapshot
- `crates/cortex/cortex-napi/src/bindings/lifecycle.rs` — Implement real shutdown
- `crates/cortex/cortex-cloud/src/quota` — Fix `secs_since_last_sync`

**Implementation tasks:** C-01 through C-13 in the spec.

**Tests you will write (13 tests):** C-14 through C-26 in the spec.

**Testing philosophy for this phase:**
- C-14: **Restart survival test.** Insert causal edges → drop engine → create new engine with same DB → verify all edges present. This is the core test for hydration.
- C-15: Insert 100 edges across 50 nodes → rebuild → verify graph has all 100 edges and correct node types (not "unknown").
- C-17: Create memory with `last_accessed` 90 days ago → run decay → verify confidence DECREASED. Not stayed the same.
- C-18: Memory with confidence 0.16, `last_accessed` 180 days ago → decay → verify confidence < 0.15 → verify archival decision is `Archive`.
- C-19: Run decay → verify `Decayed` event in temporal store with correct old/new confidence delta.
- C-20: **Performance gate.** Decay 1000 memories in under 1 second.
- C-23: Insert 10 memories (3 archived) → get health → verify `total_memories=10`, `archived_memories=3`. Not zeros.
- C-26: **Cloud conflict test.** Create local + remote change for same memory → sync → verify merge (not blind accept-remote).

**Gate:** `cargo test -p cortex-causal -p cortex-decay -p cortex-cloud -p cortex-storage -p cortex-napi` — all pass. Health snapshot returns real values.

---

### Phase D: Embedding Pipeline (P1)

**Goal:** Fix the embedding cache, vector search, and stale embedding problem.

**Files you will modify:**
- `crates/cortex/cortex-embeddings/src/cache/l2_sqlite.rs` — Wire to real SQLite connection
- `crates/cortex/cortex-embeddings/src/engine.rs` — Fix `IEmbeddingProvider` trait impl to use provider chain
- `crates/cortex/cortex-storage/src/queries/memory_crud.rs` — Add re-embed on update, batch bulk_insert
- `crates/cortex/cortex-storage/src/queries/vector_search.rs` — Optimize brute-force path

**Implementation tasks:** D-01 through D-06 in the spec.

**Tests you will write (10 tests):** D-07 through D-16 in the spec.

**Testing philosophy for this phase:**
- D-07: **Restart survival.** Embed text → drop engine → new engine same DB → lookup → cache hit. Tests L2 is actually SQLite.
- D-10: Configure a mock provider → run consolidation → verify mock was called, NOT TF-IDF fallback. Tests the trait bypass fix.
- D-11: Insert memory → embed → update summary → verify NEW embedding differs from old.
- D-13: **Performance gate.** `bulk_insert` 1000 memories under 2 seconds. Verify single transaction.
- D-14: **Atomicity.** Insert 100 memories where #50 has invalid data → verify 0 inserted (all-or-nothing).
- D-15: **Performance gate.** Vector search with 10K embeddings under 500ms.
- D-16: Insert 100 memories with known embeddings → search with known query → verify top-5 are the expected 5 most similar (correctness, not just performance).

**Gate:** `cargo test -p cortex-embeddings -p cortex-storage` — all pass. L2 cache survives restart. Bulk insert is atomic.

---

### Phase E: TypeScript Tools & NAPI Correctness (P1)

**Goal:** Fix tools that claim to do things they don't. Harden the NAPI boundary.

**Files you will modify:**
- `packages/cortex/src/tools/system/drift_cortex_reembed.ts` — Actually re-embed via embedding engine
- `packages/cortex/src/tools/system/drift_cortex_validate.ts` — Actually run validation engine
- `packages/cortex/src/tools/system/drift_cortex_gc.ts` — Wire to decay engine
- `packages/cortex/src/tools/memory/drift_memory_link.ts` — Fix read-modify-write race
- `packages/cortex/src/tools/memory/drift_memory_unlink.ts` — Fix read-modify-write race
- `crates/cortex/cortex-privacy/src/engine.rs` — Fix sort assumption, add comment detection

**Implementation tasks:** E-01 through E-08 in the spec.

**Tests you will write (12 tests):** E-09 through E-20 in the spec.

**Testing philosophy for this phase:**
- E-09: Reembed with modified provider → verify stored embedding CHANGED. Not the same.
- E-11: Validate → verify result contains 4 dimensions (temporal, semantic, structural, confidence) with non-zero scores.
- E-13: Insert old memory → decay → GC → verify archived. Tests the decay→GC chain.
- E-15: **Concurrency test.** 10 concurrent `link` calls on same memory → verify all 10 patterns present. This tests the race fix.
- E-16: Concurrent unlink + link → verify consistent final state (never fewer patterns than expected).
- E-17: Text with 5 PII matches → `apply_replacements` → verify all 5 replaced, no offset corruption.
- E-18: Feed matches in ascending order → verify correct (tests the sort fix).

**Gate:** All TS tests pass. Privacy tests pass with ascending-order input. Concurrent link test passes.

---

### Phase F: Observability & Diagnostics (P2)

**Goal:** Persist metrics, fix migration gap, fix timestamps, make configs configurable.

**Files you will modify:**
- `crates/cortex/cortex-observability/src/metrics/mod.rs` — Add persistence
- `crates/cortex/cortex-observability/src/query_log.rs` — Add persistence
- `crates/cortex/cortex-storage/src/migrations/mod.rs` — Fix v013 gap
- `crates/cortex/cortex-storage/src/temporal_events.rs` — Use DB time
- `crates/cortex/cortex-temporal/src/engine.rs` — Make drift window configurable
- `crates/cortex/cortex-prediction/src/engine.rs` — Fix cache key collision

**Implementation tasks:** F-01 through F-07 in the spec.

**Tests you will write (7 tests):** F-08 through F-14 in the spec.

**Testing philosophy for this phase:**
- F-08: **Restart survival.** Record 100 metrics → restart → verify loaded from DB.
- F-09: Log 60K queries → verify only 50K retained → restart → verify persisted.
- F-11: Insert event → verify timestamp matches DB `strftime('now')`, not Rust `Utc::now()`.
- F-13: Predict with file=None, query="A" → predict with file=None, query="B" → verify DIFFERENT results.

**Gate:** `cargo test -p cortex-observability -p cortex-storage -p cortex-temporal -p cortex-prediction` — all pass. Metrics survive restart.

---

## Architecture Constraints

These are non-negotiable. Violating any of these will break the system.

1. **`CortexRuntime` is a `OnceLock<Arc<CortexRuntime>>` singleton.** You cannot make it mutable after init. Engines that need `&mut self` are wrapped in `Mutex`. Do not add more mutexes than necessary.

2. **`StorageEngine` owns the connection pool.** All reads and writes MUST go through `StorageEngine` (or its `WriteConnection`/`ReadPool`). Do NOT open raw `rusqlite::Connection` instances.

3. **In-memory mode must work.** Many tests and dev workflows use `StorageEngine::open_in_memory()`. In-memory SQLite connections are isolated — each `open_in_memory()` call creates a separate database. All engines MUST share the same `StorageEngine` instance.

4. **The `IMemoryStorage` trait is the storage interface.** Engines should depend on `&dyn IMemoryStorage`, not on `StorageEngine` directly. This enables testing with mocks.

5. **Temporal events are append-only.** Never update or delete events. Use the existing `emit_event()` function in `cortex-storage/src/temporal_events.rs`.

6. **The NAPI boundary is synchronous.** NAPI functions are `#[napi]` sync functions. For async engines (temporal, multi-agent), use `Handle::try_current().block_on()` or the existing `block_on` helper.

7. **Do not change public trait signatures unless absolutely necessary.** Adding methods to traits (like `list_all_node_ids()` to `ICausalStorage`) is fine. Changing existing method signatures breaks all implementors.

---

## Testing Standards

Every test you write must meet ALL of these criteria:

### What Makes a Good Test
- **Targets a specific failure mode** — not "does it work?" but "does it fail correctly when X happens?"
- **Has a clear assertion** — not `assert!(result.is_ok())` but `assert_eq!(memory.summary, "expected text")`
- **Tests the boundary, not the interior** — call the public API, verify the observable output
- **Includes negative cases** — what happens with empty input? Null? Concurrent access? Storage failure?

### What Makes a Bad Test (do NOT write these)
- Tests that only verify the happy path with perfect input
- Tests that assert `is_ok()` without checking the actual value
- Tests that mock so much they're testing the mock, not the code
- Tests that are flaky due to timing (use deterministic assertions, not `sleep`)

### Specific Test Patterns Required
- **Storage failure propagation:** Create a mock `IMemoryStorage` that returns `Err(CortexError::StorageError(...))` on specific methods. Verify the caller propagates the error, doesn't panic, doesn't silently swallow.
- **Restart survival:** Create engine → do work → drop engine → create new engine with same DB path → verify state persisted.
- **Concurrency:** Use `std::thread::spawn` with `Arc` barriers. Verify no data loss, no deadlock (with timeout).
- **Atomicity:** Trigger failure mid-batch. Verify zero partial state.
- **Performance regression:** Use `std::time::Instant` with hard time limits. These catch O(n²) regressions.

---

## Subsystems That Are Clean (do NOT modify)

The audit confirmed these subsystems are correctly implemented. Do not change their internals:

- **cortex-compression** — 4-level hierarchical compression with priority-weighted bin-packing
- **cortex-crdt** — All 6 CRDT primitives with correct mathematical properties
- **cortex-reclassification** — 5-signal weighted scoring with proper normalization
- **cortex-tokens** — Accurate tiktoken cl100k_base tokenizer with blake3 caching
- **cortex-retrieval** (ranking, search, engine, budget, intent, entity expansion) — Proper 5-step pipeline
- **cortex-session** — DashMap concurrency, dedup, cleanup
- **cortex-temporal event store** (append, replay, compaction) — Proper async with transactions

You will USE these subsystems (e.g., `TokenCounter` in Phase A, `RetrievalEngine` in Phase E) but do not modify their internals.

---

## How to Verify Your Work

After each phase, run:

```bash
# Rust tests for modified crates
cargo test -p cortex-learning -p cortex-consolidation -p cortex-napi -p cortex-causal -p cortex-decay -p cortex-storage -p cortex-embeddings -p cortex-cloud -p cortex-observability -p cortex-prediction -p cortex-privacy

# Clippy (zero warnings required)
cargo clippy -p cortex-learning -p cortex-consolidation -p cortex-napi -p cortex-causal -p cortex-decay -p cortex-storage -p cortex-embeddings -p cortex-cloud -p cortex-observability -p cortex-prediction -p cortex-privacy -- -D warnings

# TypeScript tests (Phase E)
cd packages/cortex && npm test
```

If any test fails, fix it before moving to the next phase. Do not accumulate broken tests.

---

## Critical Questions You Must Be Able to Answer After Each Phase

### After Phase A:
- Does `LearningEngine::learn()` create a real `BaseMemory` in storage?
- Does `ConsolidationEngine::consolidate_with_context()` persist created semantic memories AND archive source episodes?
- Are consolidation metrics computed from real pipeline data?

### After Phase B:
- How many `WriteConnection` instances exist at runtime? (Answer must be: 1)
- Does `cortex_multiagent_register_agent` → `cortex_multiagent_get_agent` work in in-memory mode?
- Does `sync_agents` return real counts?

### After Phase C:
- Does the causal graph survive a process restart?
- Is decay scheduled and does it actually reduce confidence?
- Does the health snapshot contain real values for all 12 fields?

### After Phase D:
- Does the L2 embedding cache survive a restart?
- Does `update_memory` trigger re-embedding?
- Is `bulk_insert` wrapped in a single transaction?

### After Phase E:
- Does `drift_cortex_reembed` actually change stored embeddings?
- Does `drift_cortex_validate` return real validation scores?
- Can 10 concurrent `link` operations complete without data loss?

### After Phase F:
- Do metrics survive a restart?
- Does the drift detection window respect configuration?
- Do temporal events use DB time, not Rust time?
