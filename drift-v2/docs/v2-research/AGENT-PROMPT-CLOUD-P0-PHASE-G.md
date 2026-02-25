# Agent Prompt: Cloud P0 Phase G — Integration Testing & P0 Parity Verification

## Your Mission

You are the **final gate** before Phase 1 (Cloud Infrastructure) begins. Every previous phase (A–F) built individual subsystems. Your job is to verify they all work **together** — end-to-end, cross-subsystem, under stress, and with zero regressions.

This phase produces **no new features**. It produces **proof that everything works**.

When this phase is done:
- **Full pipeline test** — scan → store → ground → evidence → verdict, all through trait-based engines
- **Cloud-swap simulation** — mock storage implementations prove trait boundaries are sufficient for Postgres
- **Zero raw `&Connection` in production code** — grep-verified, no exceptions
- **Zero `ATTACH DATABASE`** — eliminated
- **All engines are `Send + Sync + Arc`-compatible** — compile-time verified
- **Enterprise feature integration** — SCIM → webhook → audit → team → IP allowlist, full cross-feature flow
- **Zero regressions** — `cargo test --workspace`, `npm test`, `cargo clippy -D warnings`, `tsc --noEmit` all pass
- **Performance parity** — trait dispatch overhead < 1% vs direct function calls
- **Trait surface area audit** — ≥172 total trait methods across all storage traits

**This phase spans both Rust crates AND Supabase/TypeScript.** It is the only phase that touches every subsystem.

---

## Documents You MUST Read Before Writing Any Code

1. **`docs/v2-research/CLOUD-P0-IMPLEMENTATION-PLAN.md`** — Phase G (lines ~510-600). 6 impl tasks (CP0-G-01 to G-06) + 18 tests (CT0-G-01 to G-18) + Quality Gate.
2. **`docs/v2-research/BRIDGE-CLOUD-READINESS-TRACKER.md`** — Sections 3-5 (storage abstraction strategy, trait design, sync protocol). Understand what "cloud-ready" means for each subsystem.
3. **Phase A-C prompts** — `AGENT-PROMPT-CLOUD-P0-PHASE-B.md`, `PHASE-C.md`. Understand what traits exist and where engines live.
4. **Phase D-F prompts** — `AGENT-PROMPT-CLOUD-P0-PHASE-D.md`, `PHASE-E.md`, `PHASE-F.md`. Understand enterprise features to integrate-test.
5. **Existing test suites** — Run `cargo test --workspace` in `crates/drift/` and `crates/cortex-drift-bridge/` to establish baseline before writing new tests.

After reading, you should answer:
- What are the 7 drift storage traits? (`IDriftFiles`, `IDriftAnalysis`, `IDriftStructural`, `IDriftEnforcement`, `IDriftAdvanced`, `IDriftBatchWriter`, `IDriftReader`)
- What are the 2 bridge traits? (`IBridgeStorage`, `IDriftReader`)
- What workspace trait exists? (`IWorkspaceStorage`)
- How many total trait methods should exist? (≥172: ≥149 drift + ≥23 bridge)
- What enterprise features need cross-integration testing? (SCIM + webhooks + audit log + teams + IP allowlist)
- What grep patterns prove production code is clean? (No raw `&Connection`, no `ATTACH DATABASE`, no `Mutex<Connection>` outside engines)

---

## Phase Execution Order

Phase G has two parallel tracks: **G1 (Rust integration)** and **G2 (Enterprise integration)**. G3 (regression + parity) runs last.

### Sub-Phase G1: Cross-Subsystem Rust Integration (CP0-G-01 through CP0-G-06)

#### Full Pipeline Integration Test (CP0-G-01)

**File:** `crates/drift/drift-napi/tests/integration/full_pipeline_test.rs` (NEW)

This is the most important test in the entire Cloud P0 plan. It proves all three storage engines work together through trait-based interfaces.

```rust
#[test]
fn full_pipeline_scan_ground_evidence_verdict() {
    // 1. Initialize DriftStorageEngine (drift.db)
    //    - Verify implements IDriftFiles + IDriftAnalysis + IDriftStructural
    //      + IDriftEnforcement + IDriftAdvanced + IDriftBatchWriter
    // 2. Initialize BridgeStorageEngine (bridge.db)
    //    - Verify implements IBridgeStorage
    // 3. Run drift_scan() through DriftStorageEngine
    //    - Verify scan results persisted to drift.db via engine
    //    - Verify file metadata, patterns, violations stored
    // 4. Run bridge_ground_all() through BridgeStorageEngine
    //    - Evidence read from drift.db via IDriftReader
    //    - Grounding results written to bridge.db via IBridgeStorage
    //    - Verify grounding verdicts stored
    // 5. Query grounding results through BridgeStorageEngine
    //    - Verify round-trip: write → read produces same data
    // 6. Verify all operations used trait methods, not raw connections
}
```

**Key assertion:** At no point in the pipeline does any code touch a raw `&Connection`. Every DB operation goes through a trait method.

#### Cloud-Swap Simulation — Drift (CP0-G-02)

**File:** `crates/drift/drift-napi/tests/integration/cloud_swap_test.rs` (NEW)

```rust
/// MockDriftStorage: In-memory HashMap implementing all 7 drift traits.
/// Proves the trait boundary is sufficient for a Postgres backend.
struct MockDriftStorage {
    files: HashMap<String, FileMetadata>,
    patterns: HashMap<String, Pattern>,
    violations: Vec<Violation>,
    // ... one HashMap/Vec per trait method's return type
}

impl IDriftFiles for MockDriftStorage { /* HashMap ops */ }
impl IDriftAnalysis for MockDriftStorage { /* HashMap ops */ }
impl IDriftStructural for MockDriftStorage { /* HashMap ops */ }
impl IDriftEnforcement for MockDriftStorage { /* HashMap ops */ }
impl IDriftAdvanced for MockDriftStorage { /* HashMap ops */ }
impl IDriftBatchWriter for MockDriftStorage { /* HashMap ops */ }
impl IDriftReader for MockDriftStorage { /* HashMap ops */ }

#[test]
fn cloud_swap_drift_mock_produces_identical_output() {
    // 1. Run drift_analyze() with real DriftStorageEngine
    // 2. Run drift_analyze() with MockDriftStorage
    // 3. Compare output structures (same fields, same types)
    //    Exact values may differ (timestamps, UUIDs) but structure must match
}
```

**What this proves:** A future `PostgresDriftStorage` implementing the same traits will work without any changes to the analysis pipeline.

#### Cloud-Swap Simulation — Bridge (CP0-G-03)

**File:** `crates/cortex-drift-bridge/tests/integration/cloud_swap_test.rs` (NEW)

```rust
struct MockBridgeStorage { /* in-memory */ }
impl IBridgeStorage for MockBridgeStorage { /* ... */ }

struct MockDriftReader { /* in-memory */ }
impl IDriftReader for MockDriftReader { /* ... */ }

#[test]
fn cloud_swap_bridge_mock_works() {
    // 1. Run driftBridgeGroundAll() with MockBridgeStorage + MockDriftReader
    // 2. Verify grounding produces verdicts
    // 3. Verify evidence collection works through MockDriftReader
}
```

#### Trait Completeness Audit (CP0-G-04)

**File:** `crates/drift/drift-core/tests/trait_completeness_test.rs` (NEW)

Automated test that prevents trait drift — every public query function must have a corresponding trait method.

```rust
#[test]
fn every_drift_storage_query_has_trait_method() {
    // Use compile-time or runtime reflection to verify:
    // 1. Every pub fn in drift-storage/src/queries/*.rs
    //    has a corresponding method in one of the 7 drift traits
    // 2. Every pub fn in cortex-drift-bridge/src/storage/tables.rs
    //    has a corresponding IBridgeStorage method
    // 3. Every pub fn in drift-core/src/workspace/*.rs
    //    has a corresponding IWorkspaceStorage method
    //
    // Implementation approach: grep source files for pub fn signatures,
    // grep trait definitions for method signatures, compare.
    // OR: use a build script that parses both and asserts coverage.
}
```

**Practical implementation:** Since Rust doesn't have runtime reflection, implement as:
1. A `#[test]` that calls every trait method via the engine (proves they compile and link)
2. A shell script or build script that greps `pub fn` in query modules and `fn` in trait definitions, then diffs

#### Connection Leak Test (CP0-G-05)

**File:** `crates/drift/drift-napi/tests/integration/connection_leak_test.rs` (NEW)

```rust
#[test]
fn no_connection_leaks_after_1000_operations() {
    let dir = tempdir().unwrap();
    {
        let engine = DriftStorageEngine::new(dir.path()).unwrap();
        // Run 1000 mixed operations
        for i in 0..1000 {
            engine.get_file_metadata(&format!("file_{}.ts", i));
            engine.insert_detection(/* ... */);
            engine.pattern_confidence(/* ... */);
        }
        // Engine drops here
    }
    // Verify: no .db-wal, .db-shm files remain (clean shutdown)
    // Verify: database file is not locked (can be opened by another process)
    let _verify = Connection::open(dir.path().join("drift.db")).unwrap();
}
```

#### Performance Regression Gate (CP0-G-06)

**File:** `crates/drift/drift-storage/benches/engine_benchmark.rs` (NEW)

```rust
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_trait_vs_direct(c: &mut Criterion) {
    let engine = DriftStorageEngine::new(/* temp */);

    // Direct function call (baseline)
    c.bench_function("direct_get_file_metadata", |b| {
        b.iter(|| engine.inner_get_file_metadata("test.ts"))
    });

    // Trait method call (via &dyn IDriftFiles)
    let trait_ref: &dyn IDriftFiles = &engine;
    c.bench_function("trait_get_file_metadata", |b| {
        b.iter(|| trait_ref.get_file_metadata("test.ts"))
    });

    // Benchmark: 10,000 get_file_metadata, 1,000 insert_detection, 100 pattern_confidence
}

criterion_group!(benches, bench_trait_vs_direct);
criterion_main!(benches);
```

**Pass criteria:** Trait dispatch overhead < 1% (function pointer indirection is ~1ns per call).

**Gate:** All Rust integration tests pass. Mock storage proves trait sufficiency. No leaks. Performance parity.

---

### Sub-Phase G2: Enterprise Feature Integration (CT0-G-11 through CT0-G-13)

These tests verify that Phase D (SCIM), Phase E (Webhooks), and Phase F (Audit/Teams/IP) work together as a coherent enterprise platform.

#### SCIM + Webhook + Audit Integration (CT0-G-11)

**File:** `supabase/tests/enterprise-integration.test.ts` (NEW)

```typescript
Deno.test("SCIM deprovision → webhook fires → audit log entry", async () => {
  // 1. Register webhook for "user.deprovisioned" event (or appropriate event)
  // 2. SCIM DELETE /scim/v2/Users/:id (deprovisioning)
  // 3. Verify webhook delivery received with correct payload
  // 4. Verify cloud_audit_log entry with action "scim.user_deprovisioned"
  // 5. Verify deprovisioned user cannot authenticate
});
```

#### Team + IP Allowlist Integration (CT0-G-12)

```typescript
Deno.test("team member from allowed IP succeeds, blocked IP fails", async () => {
  // 1. Create team, assign project
  // 2. Add team member
  // 3. Add IP allowlist entry: 10.0.0.0/8
  // 4. Request from 10.1.2.3 (mock X-Forwarded-For) → 200
  // 5. Request from 192.168.1.1 → 403
});
```

#### Full Enterprise Flow (CT0-G-13)

```typescript
Deno.test("full enterprise lifecycle", async () => {
  // 1. Create tenant
  // 2. Invite member by email → accept → verify joined
  // 3. Create team → add member → assign project
  // 4. Configure webhook for scan.completed
  // 5. Push scan results → webhook fires → verify payload
  // 6. Query audit log → all events recorded
  // 7. Add IP allowlist → verify enforcement
  // 8. Transfer ownership → verify roles swapped
  // 9. Verify all audit entries in chronological order
});
```

**Gate:** Cross-feature integration tests pass. Enterprise flow is coherent.

---

### Sub-Phase G3: Regression & Parity Verification (CT0-G-04 through CT0-G-18)

#### Static Analysis (CT0-G-04, G-05, G-06)

These are grep-based checks, not runtime tests. They verify code hygiene.

```bash
# CT0-G-04: Zero raw &Connection in production code
grep -r "&Connection" crates/drift/drift-napi/src/ crates/cortex-drift-bridge/src/ \
  --include="*.rs" | grep -v "test" | grep -v "impl " | grep -v "mod test"
# Expected: 0 matches (only trait impl internals and test code)

# CT0-G-05: Zero ATTACH DATABASE
grep -r "ATTACH DATABASE" crates/ --include="*.rs" | grep -v "test"
# Expected: 0 matches

# CT0-G-06: Zero Mutex<Connection> outside engines
grep -r "Mutex<Connection>" crates/ --include="*.rs" \
  | grep -v "ConnectionPool\|engine\|runtime\|test"
# Expected: 0 matches
```

#### Compile-Time Assertions (CT0-G-07, G-08)

```rust
#[test]
fn engines_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<DriftStorageEngine>();
    assert_send_sync::<BridgeStorageEngine>();
    // cortex StorageEngine if applicable
}

#[test]
fn engines_work_behind_arc() {
    let drift = Arc::new(DriftStorageEngine::new(/* temp */));
    let bridge = Arc::new(BridgeStorageEngine::new(/* temp */));
    // Verify trait methods callable through Arc
    let _: &dyn IDriftFiles = drift.as_ref();
    let _: &dyn IBridgeStorage = bridge.as_ref();
}
```

#### Regression Suites (CT0-G-14 through CT0-G-17)

```bash
# CT0-G-14: All Rust tests pass
cd crates/drift && cargo test --workspace
cd crates/cortex && cargo test --workspace
cd crates/cortex-drift-bridge && cargo test

# CT0-G-15: All TS tests pass
cd packages/drift-cli && npm test
cd packages/drift-mcp && npm test
cd packages/drift-ci && npm test
cd packages/drift-napi-contracts && npm test

# CT0-G-16: Clippy clean
cd crates/drift && cargo clippy --all-targets -- -D warnings
cd crates/cortex && cargo clippy --all-targets -- -D warnings
cd crates/cortex-drift-bridge && cargo clippy --all-targets -- -D warnings

# CT0-G-17: TypeScript clean
npx tsc --noEmit  # from repo root

# Supabase tests (Phase D + E + F + G)
cd supabase && deno test tests/ --allow-net --allow-env
```

#### Trait Surface Area Audit (CT0-G-18)

```rust
#[test]
fn trait_surface_area_meets_minimum() {
    // Count methods on each trait:
    // IDriftFiles ≥ 5
    // IDriftAnalysis ≥ 25
    // IDriftStructural ≥ 37
    // IDriftEnforcement ≥ 21
    // IDriftAdvanced ≥ 9
    // IDriftBatchWriter ≥ 5
    // IDriftReader = 14
    // IWorkspaceStorage ≥ 10
    // IBridgeStorage ≥ 23
    // Total ≥ 149 drift + 23 bridge = ≥ 172

    // Implementation: count trait methods by listing them
    // or use a build-time script that parses trait definitions
}
```

---

## Tests (18 tests)

| ID | Test | Type | Proves |
|----|------|------|--------|
| CT0-G-01 | Full pipeline: scan → store → ground → evidence → verdict | e2e | All engines work together |
| CT0-G-02 | MockDriftStorage produces identical analysis output | integration | Drift traits sufficient for cloud |
| CT0-G-03 | MockBridgeStorage + MockDriftReader grounding works | integration | Bridge traits sufficient for cloud |
| CT0-G-04 | Zero raw `&Connection` in production code | static | Clean abstraction |
| CT0-G-05 | Zero `ATTACH DATABASE` in production code | static | Pattern eliminated |
| CT0-G-06 | Zero `Mutex<Connection>` outside engines | static | Encapsulation verified |
| CT0-G-07 | All 3 engines `Send + Sync` | compile | Thread-safe |
| CT0-G-08 | All engines work behind `Arc` | compile | Shareable |
| CT0-G-09 | 1000 ops → shutdown → no file locks | stress | No leaks |
| CT0-G-10 | Trait dispatch overhead < 1% | benchmark | Performance parity |
| CT0-G-11 | SCIM + webhook + audit cross-feature | e2e | Enterprise integration |
| CT0-G-12 | Team + IP allowlist cross-feature | e2e | Access control integration |
| CT0-G-13 | Full enterprise lifecycle flow | e2e | All features coherent |
| CT0-G-14 | `cargo test --workspace` all pass | regression | Zero Rust regressions |
| CT0-G-15 | `npm test` all TS packages pass | regression | Zero TS regressions |
| CT0-G-16 | `cargo clippy -D warnings` clean | compilation | Code quality |
| CT0-G-17 | `tsc --noEmit` clean | compilation | Type safety |
| CT0-G-18 | Trait surface area ≥ 172 methods | audit | Completeness |

---

## Testing Standards

### What Makes a Good Phase G Test
- **Tests the seams between subsystems** — not individual features, but how they interact
- **Uses real engines and real databases** — no mocking the storage layer itself (only mock for cloud-swap simulation)
- **Verifies invariants via grep** — static analysis tests are cheap and catch regressions instantly
- **Measures, doesn't guess** — performance tests use `criterion` benchmarks with statistical significance
- **Is reproducible** — every test uses `tempdir()` for isolation, no shared state

### What Makes a Bad Test
- Tests that duplicate existing unit tests from Phases A-F
- Tests that only verify one subsystem in isolation (that's Phases A-F's job)
- Performance tests without a baseline comparison
- Static analysis tests with overly broad grep patterns that produce false positives
- Enterprise integration tests that skip RLS or use service_role for all operations

### Required Patterns
- **Full pipeline:** CT0-G-01 must exercise all 3 engines in sequence with real data
- **Mock fidelity:** CT0-G-02/03 mock implementations must cover ALL trait methods (not partial)
- **Grep precision:** CT0-G-04/05/06 grep patterns must exclude test files and trait impl internals
- **Enterprise flow:** CT0-G-13 must be a single test that exercises the entire lifecycle — not broken into separate tests
- **Regression breadth:** CT0-G-14/15 must run the FULL test suite, not a subset

---

## Architecture Constraints

1. **Phase G creates no new tables, no new APIs, no new traits.** It only creates test files and benchmark files.
2. **Mock storage must implement ALL methods.** Partial mocks that `unimplemented!()` most methods don't prove trait sufficiency.
3. **Static analysis tests must be deterministic.** Same grep, same result, every time.
4. **Performance benchmarks must use `criterion`** (not wall-clock timing) for statistical rigor.
5. **Enterprise integration tests run against real Supabase local dev.** `supabase start` + `supabase db reset` + `supabase functions serve`.
6. **All existing tests must continue passing.** Phase G must not break anything.

---

## Forbidden Actions

1. **Do NOT create new features.** Phase G is testing only.
2. **Do NOT modify existing source code** (except test files). If a test reveals a bug, document it — don't fix it in Phase G (file an issue for the owning phase).
3. **Do NOT weaken existing tests.** Do not change assertions, skip tests, or increase tolerances.
4. **Do NOT use `#[ignore]` on any test.** Every test must run in CI.
5. **Do NOT hardcode paths or credentials.** Use `tempdir()`, env vars, and Supabase local dev defaults.
6. **Do NOT skip Supabase enterprise integration tests.** They are as important as Rust tests.

---

## Effort Estimate

| Sub-Phase | Tasks | Effort | Key Risk |
|-----------|-------|--------|----------|
| G1: Rust Integration | CP0-G-01 to G-06 | 1-1.5d | Mock storage completeness |
| G2: Enterprise Integration | CT0-G-11 to G-13 | 0.5-1d | Cross-service coordination |
| G3: Regression + Parity | CT0-G-04 to G-18 | 0.5d | Unexpected failures |
| **Total** | **6 impl + 18 test** | **2-3 days** | |

**Dependencies:** ALL previous phases (A-F) must be complete. Phase G is the final gate.

---

## Subsystems That Are Clean (do NOT modify)

- **ALL production source files** — Phase G modifies only test files, benchmark files, and scripts
- **ALL migrations** — no schema changes
- **ALL Edge Functions** — no API changes
- **ALL shared helpers** — no modifications

You MAY create:
- `crates/drift/drift-napi/tests/integration/*.rs` — Rust integration tests
- `crates/drift/drift-core/tests/*.rs` — Trait completeness tests
- `crates/drift/drift-storage/benches/*.rs` — Benchmarks
- `crates/cortex-drift-bridge/tests/integration/*.rs` — Bridge integration tests
- `supabase/tests/enterprise-integration.test.ts` — Enterprise e2e tests

---

## Verification Commands

```bash
# ── G1: Rust Integration ──

# Full pipeline test:
cd crates/drift && cargo test full_pipeline --test full_pipeline_test -- --nocapture
# Expected: 1 test, 0 failures

# Cloud-swap drift:
cd crates/drift && cargo test cloud_swap --test cloud_swap_test -- --nocapture
# Expected: 1+ tests, 0 failures

# Cloud-swap bridge:
cd crates/cortex-drift-bridge && cargo test cloud_swap --test cloud_swap_test -- --nocapture
# Expected: 1+ tests, 0 failures

# Connection leak:
cd crates/drift && cargo test connection_leak --test connection_leak_test -- --nocapture
# Expected: 1 test, 0 failures

# Benchmarks (not in CI — run manually):
cd crates/drift/drift-storage && cargo bench
# Expected: trait overhead < 1%

# ── G2: Enterprise Integration ──

# Enterprise tests:
cd supabase && deno test tests/enterprise-integration.test.ts --allow-net --allow-env
# Expected: 3+ tests, 0 failures

# ── G3: Static Analysis ──

# Zero raw &Connection:
grep -rn "&Connection" crates/drift/drift-napi/src/ crates/cortex-drift-bridge/src/ \
  --include="*.rs" | grep -v "test\|#\[cfg(test)\|mod tests\|impl.*for.*Engine"
# Expected: 0 matches

# Zero ATTACH DATABASE:
grep -rn "ATTACH DATABASE" crates/ --include="*.rs" | grep -v test
# Expected: 0 matches

# Zero Mutex<Connection> outside engines:
grep -rn "Mutex<Connection>" crates/ --include="*.rs" \
  | grep -v "pool\|engine\|runtime\|test"
# Expected: 0 matches

# ── G3: Regression ──

# All Rust:
cd crates/drift && cargo test --workspace
cd crates/cortex-drift-bridge && cargo test
# Expected: 0 failures

# All TS:
npm test --workspaces
# Expected: 0 failures

# Clippy:
cd crates/drift && cargo clippy --all-targets -- -D warnings
cd crates/cortex-drift-bridge && cargo clippy --all-targets -- -D warnings
# Expected: 0 warnings

# TypeScript:
npx tsc --noEmit
# Expected: 0 errors

# All Supabase tests:
cd supabase && deno test tests/ --allow-net --allow-env
# Expected: 0 failures
```

---

## Critical Questions After Phase G

### After G1:
- Do all 3 engines work together in a single pipeline? (Yes — CT0-G-01)
- Can you swap DriftStorageEngine for a mock without changing the pipeline? (Yes — CT0-G-02)
- Can you swap BridgeStorageEngine for a mock without changing grounding? (Yes — CT0-G-03)
- Is trait dispatch overhead measurable? (< 1% — CT0-G-10)

### After G2:
- Does SCIM deprovisioning trigger a webhook and audit entry? (Yes — CT0-G-11)
- Does IP allowlisting work with team-scoped access? (Yes — CT0-G-12)
- Can you run the full enterprise lifecycle in a single test? (Yes — CT0-G-13)

### After G3:
- Are there any raw `&Connection` references in production code? (Zero — CT0-G-04)
- Are there any `ATTACH DATABASE` calls? (Zero — CT0-G-05)
- Do all existing Rust + TS tests still pass? (Yes — CT0-G-14/15)
- Is clippy + tsc clean? (Yes — CT0-G-16/17)
- How many total trait methods exist? (≥ 172 — CT0-G-18)

### Final Sign-Off Question:
**Is the codebase ready for Phase 1 (Cloud Infrastructure)?**
Answer: Yes, if ALL of the following are true:
- [ ] All 18 Phase G tests pass
- [ ] All pre-existing Rust tests pass (cargo test --workspace)
- [ ] All pre-existing TS tests pass (npm test)
- [ ] Clippy clean (0 warnings with -D warnings)
- [ ] tsc clean (0 errors)
- [ ] All Supabase tests pass (Phases D + E + F + G)
- [ ] Trait surface area ≥ 172 methods
- [ ] Performance overhead < 1%

---

## Quality Gate (QG-G) — All Must Pass

- [ ] Full pipeline test passes (scan → ground → evidence → verdict)
- [ ] Cloud-swap simulation proves trait sufficiency (drift + bridge)
- [ ] Zero raw `&Connection` in production code
- [ ] Zero `ATTACH DATABASE` in production code
- [ ] Zero `Mutex<Connection>` outside engine internals
- [ ] All engines `Send + Sync` (compile-time verified)
- [ ] All engines work behind `Arc` (compile-time verified)
- [ ] No connection leaks after 1000 operations
- [ ] Trait dispatch overhead < 1%
- [ ] SCIM + webhook + audit integration test passes
- [ ] Team + IP allowlist integration test passes
- [ ] Full enterprise lifecycle test passes
- [ ] All Rust tests pass (`cargo test --workspace`)
- [ ] All TS tests pass (`npm test`)
- [ ] Clippy clean (`-D warnings`)
- [ ] TypeScript clean (`tsc --noEmit`)
- [ ] Trait surface area ≥ 172 methods
- [ ] All Supabase tests pass (D + E + F + G combined)

---

## Appendix A: Cross-Phase Dependency Map

```
Phase G (Integration Testing & P0 Parity Verification)
│
├── HARD DEPENDS ON (ALL previous phases) ───────────────────────────
│   ├── Phase A — Drift storage traits defined in drift-core
│   │   └── IDriftFiles, IDriftAnalysis, IDriftStructural,
│   │       IDriftEnforcement, IDriftAdvanced, IDriftBatchWriter,
│   │       IDriftReader, IWorkspaceStorage
│   │
│   ├── Phase B — DriftStorageEngine implements all 7 traits
│   │   └── drift-storage/src/engine.rs, drift-napi/src/runtime.rs
│   │       107 NAPI call sites rewired
│   │
│   ├── Phase C — BridgeStorageEngine implements IBridgeStorage
│   │   └── cortex-drift-bridge/src/storage/engine.rs
│   │       IDriftReader replaces ATTACH DATABASE
│   │       ~15 evidence collectors rewired
│   │
│   ├── Phase D — SCIM provisioning (Supabase Edge Functions)
│   │   └── scim-users, scim-groups, scim-admin endpoints
│   │       deprovision.ts, scim-auth.ts, audit.ts
│   │       4 SQL migrations (000-003)
│   │
│   ├── Phase E — Webhook infrastructure
│   │   └── webhook CRUD, dispatch engine, HMAC signatures
│   │       7 event types, retry + dead letter
│   │       1 SQL migration (004)
│   │
│   └── Phase F — Audit + Teams + IP allowlisting
│       └── audit query/export, team CRUD, invitations
│           IP enforcement middleware, CLI escape hatch
│           3 SQL migrations (005-008)
│
├── PRODUCES ────────────────────────────────────────────────────────
│   └── PROOF that Phase 1 (Cloud Infrastructure) can begin:
│       ├── Trait boundaries verified via mock storage
│       ├── No raw connections in production code
│       ├── Enterprise features work end-to-end
│       ├── Zero regressions across all subsystems
│       └── Performance parity confirmed
│
└── INDEPENDENT OF ──────────────────────────────────────────────────
    └── Nothing — Phase G depends on everything
```

---

## Appendix B: Test File Inventory

### New Rust Test Files

| File | Tests | What It Proves |
|------|-------|----------------|
| `drift-napi/tests/integration/full_pipeline_test.rs` | CT0-G-01 | All 3 engines work together |
| `drift-napi/tests/integration/cloud_swap_test.rs` | CT0-G-02 | Drift traits sufficient for cloud |
| `cortex-drift-bridge/tests/integration/cloud_swap_test.rs` | CT0-G-03 | Bridge traits sufficient for cloud |
| `drift-core/tests/trait_completeness_test.rs` | CT0-G-04, G-18 | No trait drift, surface area ≥172 |
| `drift-napi/tests/integration/connection_leak_test.rs` | CT0-G-05, G-09 | No leaks after 1000 ops |
| `drift-storage/benches/engine_benchmark.rs` | CT0-G-06, G-10 | Trait overhead < 1% |
| `drift-napi/tests/integration/send_sync_test.rs` | CT0-G-07, G-08 | Thread safety + Arc compatibility |

### New Supabase Test Files

| File | Tests | What It Proves |
|------|-------|----------------|
| `supabase/tests/enterprise-integration.test.ts` | CT0-G-11, G-12, G-13 | Cross-feature enterprise flow |

### Static Analysis (scripts, not test files)

| Check | Command | Proves |
|-------|---------|--------|
| CT0-G-04 | `grep -r "&Connection" ...` | Zero raw connections |
| CT0-G-05 | `grep -r "ATTACH DATABASE" ...` | Pattern eliminated |
| CT0-G-06 | `grep -r "Mutex<Connection>" ...` | Encapsulation verified |

### Regression (existing test suites)

| Check | Command | Proves |
|-------|---------|--------|
| CT0-G-14 | `cargo test --workspace` (drift, cortex, bridge) | Zero Rust regressions |
| CT0-G-15 | `npm test` (cli, mcp, ci, contracts) | Zero TS regressions |
| CT0-G-16 | `cargo clippy -D warnings` (all workspaces) | Code quality |
| CT0-G-17 | `tsc --noEmit` | Type safety |

---

## Appendix C: Implementation Plan Cross-Reference

### Implementation Tasks

| Plan ID | Task | Prompt Section | Status |
|---------|------|----------------|--------|
| CP0-G-01 | Full pipeline integration test | Sub-Phase G1: Full Pipeline | Covered |
| CP0-G-02 | Cloud-swap simulation (drift) | Sub-Phase G1: Cloud-Swap Drift | Covered |
| CP0-G-03 | Cloud-swap simulation (bridge) | Sub-Phase G1: Cloud-Swap Bridge | Covered |
| CP0-G-04 | Trait completeness audit | Sub-Phase G1: Trait Completeness | Covered |
| CP0-G-05 | Connection leak test | Sub-Phase G1: Connection Leak | Covered |
| CP0-G-06 | Performance regression gate | Sub-Phase G1: Performance | Covered |

### Test Tasks

| Plan ID | Test | Prompt Section | Status |
|---------|------|----------------|--------|
| CT0-G-01 | Full pipeline e2e | Tests: CT0-G-01 | Covered |
| CT0-G-02 | Mock drift storage | Tests: CT0-G-02 | Covered |
| CT0-G-03 | Mock bridge storage | Tests: CT0-G-03 | Covered |
| CT0-G-04 | Zero raw `&Connection` | Sub-Phase G3: Static Analysis | Covered |
| CT0-G-05 | Zero `ATTACH DATABASE` | Sub-Phase G3: Static Analysis | Covered |
| CT0-G-06 | Zero `Mutex<Connection>` outside engines | Sub-Phase G3: Static Analysis | Covered |
| CT0-G-07 | Engines `Send + Sync` | Sub-Phase G3: Compile-Time | Covered |
| CT0-G-08 | Engines behind `Arc` | Sub-Phase G3: Compile-Time | Covered |
| CT0-G-09 | Connection leak 1000 ops | Tests: CT0-G-09 | Covered |
| CT0-G-10 | Performance < 1% overhead | Tests: CT0-G-10 | Covered |
| CT0-G-11 | SCIM + webhook + audit | Sub-Phase G2: Enterprise | Covered |
| CT0-G-12 | Team + IP allowlist | Sub-Phase G2: Enterprise | Covered |
| CT0-G-13 | Full enterprise lifecycle | Sub-Phase G2: Enterprise | Covered |
| CT0-G-14 | Rust regression suite | Sub-Phase G3: Regression | Covered |
| CT0-G-15 | TS regression suite | Sub-Phase G3: Regression | Covered |
| CT0-G-16 | Clippy clean | Sub-Phase G3: Regression | Covered |
| CT0-G-17 | tsc clean | Sub-Phase G3: Regression | Covered |
| CT0-G-18 | Trait surface area ≥ 172 | Tests: CT0-G-18 | Covered |

### Quality Gate Items

| QG Item | Prompt Coverage |
|---------|-----------------|
| Full pipeline passes | CP0-G-01 + CT0-G-01 |
| Cloud-swap proves traits | CP0-G-02/03 + CT0-G-02/03 |
| Zero raw `&Connection` | CT0-G-04 |
| Zero `ATTACH DATABASE` | CT0-G-05 |
| Zero leaked `Mutex<Connection>` | CT0-G-06 |
| `Send + Sync` | CT0-G-07 |
| `Arc` compatible | CT0-G-08 |
| No connection leaks | CP0-G-05 + CT0-G-09 |
| Performance < 1% | CP0-G-06 + CT0-G-10 |
| Enterprise integration | CT0-G-11/12/13 |
| Rust regression | CT0-G-14 |
| TS regression | CT0-G-15 |
| Clippy clean | CT0-G-16 |
| tsc clean | CT0-G-17 |
| Trait surface ≥ 172 | CT0-G-18 |
| Supabase tests pass | All supabase/tests/ |

### Tracker Cross-Reference

| Tracker Ref | Tracker Section | Plan Phase |
|-------------|-----------------|------------|
| P0-01 | §3 Storage Abstraction | CP0-G-02 (trait sufficiency) |
| P0-03 | §3 Performance | CP0-G-06 (benchmarks) |
| P0-07 | §3 Bridge Abstraction | CP0-G-03 (bridge mock) |
| P0-09 | §3 Connection Management | CP0-G-05 (leak test) |
| P0-10 | §3 Mutex Encapsulation | CT0-G-06 (grep check) |
| P0-12 | §3 ATTACH elimination | CT0-G-05 (grep check) |
| P0-15 | §3 Workspace Trait | CP0-G-04 (completeness audit) |
| GAP-01 | §11a SCIM | CT0-G-11 (cross-feature) |
| GAP-02 | §11a Webhooks | CT0-G-11 (cross-feature) |
| GAP-03 | §11a Audit | CT0-G-11/13 (cross-feature) |
| GAP-04 | §11a Teams | CT0-G-12/13 (cross-feature) |
| GAP-05 | §11a IP Allowlist | CT0-G-12 (cross-feature) |

**Coverage: 6/6 impl tasks + 18/18 test tasks + 16/16 QG items + 12/12 tracker refs = 100%**

---

## Final Summary: Cloud P0 Complete

When Phase G passes, the Cloud P0 plan is **complete**:

| Phase | Focus | Tasks | Tests | Status |
|-------|-------|-------|-------|--------|
| A | Drift Storage Traits | 14 | — | Architecture |
| B | DriftStorageEngine + NAPI | 16 | 8 | Rust |
| C | BridgeStorageEngine | 16 | 8 | Rust |
| D | SCIM Provisioning | 10 | 8 | Supabase |
| E | Webhooks | 12 | 10 | Supabase |
| F | Audit + Teams + IP | 18 | 14 | Supabase + CLI |
| G | Integration + Parity | 6 | 18 | Cross-cutting |
| **Total** | | **92** | **66** | **158 tasks** |

**Phase 1 (Cloud Infrastructure) can begin.**
