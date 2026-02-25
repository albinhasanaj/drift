# MAPhase Final — Golden Fixtures + End-to-End Integration + QG-MA4

> **ULTRA THINK. Quality over speed. No shortcuts. Enterprise-grade perfection.**
> Your boss audits every line through Codex. Make him stop needing to.

You are running the final integration quality gate (QG-MA4) for the Cortex multi-agent memory addition. This is the capstone — no new features, only validation, fixtures, and proof of correctness. Read these files first:

- `MULTIAGENT-TASK-TRACKER.md` (Golden Fixtures section `PMF-*`, QG-MA4 section `TMA-INT-*` and `TMA-FINAL-*`)
- `MULTIAGENT-IMPLEMENTATION-SPEC.md` (full behavioral spec)
- `FILE-MAP.md` (complete file inventory)

**Prerequisite:** QG-MA3c has passed — all phases A through D3 are complete. CRDT foundation (A), storage + namespaces (B), provenance + trust + sync (C), cross-crate integration (D1), NAPI + TypeScript (D2), and MCP tools + CLI (D3) are all operational. All `TMA-*`, `TMB-*`, `TMC-*`, `TMD1-*`, `TMD2-*`, `TMD3-*` tests pass. `cargo test --workspace` is green.

---

## What This Phase Builds

No new feature code. Only golden test fixtures, integration tests, and final validation. 13 fixture tasks + 16 final check tasks + 3 test file tasks.

### 1. Golden Test Fixtures (10 JSON files)

Create all fixtures in `crates/cortex/test-fixtures/golden/multiagent/`. Each is a JSON file with known inputs and expected outputs, following the pattern established by `test-fixtures/golden/consolidation/`.

**CRDT Merge Fixtures** (3):
- `crdt_merge_simple.json` — 2 agents, 1 memory, divergent tag edits, expected merged state
  - Agent A adds tag "auth", Agent B adds tag "security" → merged has both tags (ORSet add-wins)
  - Agent A increments access_count 3×, Agent B increments 2× → merged access_count = 5 (GCounter)

- `crdt_merge_conflict.json` — 2 agents, concurrent content edits (LWW), expected winner by timestamp
  - Agent A sets summary at T1, Agent B sets summary at T2 (T2 > T1) → Agent B's summary wins
  - Same timestamp tie-break: Agent A (id "aaa") vs Agent B (id "bbb") → Agent B wins (lexicographic)

- `crdt_merge_confidence.json` — 3 agents, confidence boosts via MaxRegister, expected max value
  - Agent A: confidence 0.7, Agent B: confidence 0.85, Agent C: confidence 0.6 → merged = 0.85

**Namespace Permission Fixtures** (2):
- `namespace_permissions.json` — agent, team, project namespaces with various grants, expected access results
  - Agent scope: owner has all permissions, others have none by default
  - Team scope: members have Read+Write, non-members have none
  - Project scope: members have Read, non-members have none

- `namespace_default_compat.json` — single-agent with default namespace, expected identical behavior to v1
  - All memories in `agent://default/`, source_agent = "default"
  - All existing queries return same results as pre-multi-agent

**Provenance Chain Fixtures** (2):
- `provenance_chain.json` — 3-agent chain (create → share → refine), expected chain + confidence
  - Agent A creates M1 (delta=0.0) → shares to B (delta=0.0) → B refines (delta=+0.05) → shares to C (delta=0.0) → C validates (delta=+0.1)
  - Expected chain_confidence = 1.0 × 1.0 × 1.05 × 1.0 × 1.1 = 1.155 → clamped to 1.0

- `provenance_correction.json` — correction at depth 0, expected dampened propagation at depths 1-3
  - Base correction strength 1.0 → depth 1: 0.7 → depth 2: 0.49 → depth 3: 0.343

**Trust Scoring Fixtures** (2):
- `trust_scoring.json` — agent with known evidence, expected trust values
  - validated=5, contradicted=1, useful=3, total=10
  - Expected: (5+3)/(10+1) × (1 - 1/(10+1)) = 0.727 × 0.909 = 0.661

- `trust_decay.json` — trust score after 50 and 100 days without evidence, expected decayed values
  - Initial trust = 0.8
  - After 50 days: 0.8 + (0.5 - 0.8) × (1 - 0.99^50) = 0.681
  - After 100 days: 0.8 + (0.5 - 0.8) × (1 - 0.99^100) = 0.610

**Consensus Detection Fixture** (1):
- `consensus_detection.json` — 3 agents with similar memories about same topic, expected consensus candidate
  - Agent A, B, C each independently create a memory about "auth uses JWT tokens"
  - Embedding similarity > 0.9 between all three
  - Expected: consensus detected, confidence boost +0.2

### 2. Test Entry Points (3 files)

- `cortex-multiagent/tests/coverage_test.rs` — public API surface coverage (follows cortex-causal pattern)
- `cortex-multiagent/tests/golden_test.rs` — loads each JSON fixture, runs scenario, asserts expected output
- `cortex-multiagent/tests/stress_test.rs` — high-volume + concurrent tests:
  - 5 agents, 10K memories, full sync cycle < 30s
  - Concurrent delta application from 3 agents (no deadlocks)
  - Projection with 1K matching memories
  - Trust computation with 10K evidence records

### 3. End-to-End Integration Tests (16 tests)

These test cross-phase flows spanning the entire multi-agent system:

**`TMA-INT-01`** — Full agent lifecycle: register → create memories → share → sync → deregister → memories preserved
**`TMA-INT-02`** — CRDT convergence: 3 agents, divergent edits → sync → all agents have identical state
**`TMA-INT-03`** — Namespace isolation: Agent A's private memories invisible to Agent B without projection
**`TMA-INT-04`** — Projection filtering: create projection with filter → only matching memories visible
**`TMA-INT-05`** — Provenance chain: create → share → refine → trace → full chain with correct confidence
**`TMA-INT-06`** — Correction propagation: correct memory → propagation through 3-hop chain → dampened correctly
**`TMA-INT-07`** — Trust scoring: share memories → validate some → contradict some → trust scores correct
**`TMA-INT-08`** — Trust-weighted retrieval: higher-trust agent's memory ranks above lower-trust
**`TMA-INT-09`** — Cross-agent contradiction: two agents contradict → detected → resolved by trust
**`TMA-INT-10`** — Consensus detection: 3 agents independently learn same thing → consensus → confidence boosted
**`TMA-INT-11`** — Delta sync with causal delivery: out-of-order deltas → buffered → applied correctly → convergence
**`TMA-INT-12`** — Cloud sync with CRDT merge: remote agents sync → CRDT merge → convergence
**`TMA-INT-13`** — Backward compatibility: single-agent mode → ALL existing tests pass unchanged
**`TMA-INT-14`** — NAPI round-trip: TypeScript → Rust → TypeScript for all 12 multi-agent functions
**`TMA-INT-15`** — MCP tools: all 5 tools return valid responses
**`TMA-INT-16`** — CLI commands: all 3 commands produce output

### 4. Final Checks (15 checks)

```
TMA-FINAL-01  cargo test --workspace                              → zero failures
TMA-FINAL-02  cargo tarpaulin -p cortex-crdt --ignore-tests       → ≥80% coverage
TMA-FINAL-03  cargo tarpaulin -p cortex-multiagent --ignore-tests → ≥80% coverage
TMA-FINAL-04  cargo bench -p cortex-crdt                          → all 10 benchmarks within target
TMA-FINAL-05  cargo clippy -p cortex-crdt                         → zero warnings
TMA-FINAL-06  cargo clippy -p cortex-multiagent                   → zero warnings
TMA-FINAL-07  cargo clippy --workspace                            → zero NEW warnings
TMA-FINAL-08  CRDT storage overhead                               → 10K memories, 5 agents < 10MB
TMA-FINAL-09  vitest run in packages/cortex                       → all tests pass
TMA-FINAL-10  All 10 golden fixtures validate correctly
TMA-FINAL-11  Stress tests pass                                   → 5 agents, 10K memories, sync < 30s
TMA-FINAL-12  No memory leaks in long-running sync
TMA-FINAL-13  All critical paths instrumented with tracing
TMA-FINAL-14  All error messages clear and actionable
TMA-FINAL-15  All public API documentation complete
```

---

## Critical Implementation Details

### Golden Fixtures Must Be Deterministic

Use fixed timestamps, fixed UUIDs, fixed content. No randomness. Expected outputs must be exactly reproducible:
```json
{
  "description": "CRDT merge: 2 agents, divergent tag edits",
  "agents": ["agent-alpha", "agent-beta"],
  "initial_memory": { "id": "mem-001", "tags": ["rust"], ... },
  "operations": [
    { "agent": "agent-alpha", "action": "add_tag", "value": "auth" },
    { "agent": "agent-beta", "action": "add_tag", "value": "security" }
  ],
  "expected_merged": { "tags": ["auth", "rust", "security"] }
}
```

### Stress Test Scale Targets

- 5 agents, 10K memories, full sync cycle < 30s
- Concurrent delta application from 3 agents must not deadlock
- Projection with 1K matching memories must complete
- Trust computation with 10K evidence records must complete

### Backward Compatibility Test (TMA-INT-13)

This is the most critical integration test. It verifies that with `MultiAgentConfig.enabled = false`:
1. All existing tests pass unchanged
2. No performance regression
3. No behavioral change
4. Default namespace/agent values are transparent

### Coverage Measurement

Coverage is per-module, not per-crate:
- `cargo tarpaulin -p cortex-crdt --ignore-tests` — test code doesn't count
- `cargo tarpaulin -p cortex-multiagent --ignore-tests` — test code doesn't count
- Both must report ≥80% line coverage

---

## Task Checklist

Check off tasks in `MULTIAGENT-TASK-TRACKER.md` as you complete them:

**Golden Fixtures**: `PMF-GOLD-01` through `PMF-GOLD-10`
**Test Files**: `PMF-TEST-01` through `PMF-TEST-03`
**Integration Tests**: `TMA-INT-01` through `TMA-INT-16`
**Final Checks**: `TMA-FINAL-01` through `TMA-FINAL-15`

---

## Quality Gate: QG-MA4 (FINAL)

This is the final gate. When QG-MA4 passes, the multi-agent memory system is complete.

### All Tests Pass
- [ ] All 16 `TMA-INT-*` integration tests pass
- [ ] All 15 `TMA-FINAL-*` checks pass
- [ ] All 10 golden fixtures validate correctly
- [ ] `cargo test --workspace` — zero failures
- [ ] `vitest run` — zero failures

### Coverage
- [ ] cortex-crdt ≥80% line coverage
- [ ] cortex-multiagent ≥80% line coverage

### Performance
- [ ] All 10 CRDT benchmarks within target
- [ ] Stress tests pass within time limits
- [ ] CRDT storage overhead < 10MB for 10K memories × 5 agents

### Code Quality
- [ ] Zero clippy warnings in cortex-crdt
- [ ] Zero clippy warnings in cortex-multiagent
- [ ] Zero new clippy warnings workspace-wide
- [ ] All public APIs documented
- [ ] All error messages actionable
- [ ] All critical paths instrumented

### Backward Compatibility
- [ ] Single-agent mode completely unaffected
- [ ] All pre-existing tests pass unchanged
- [ ] Default namespace/agent values transparent

---

## Completion Criteria

The multi-agent memory system is complete when:

1. ✅ All 120 implementation tasks completed (Phases A-D3)
2. ✅ All 151 test tasks pass
3. ✅ All 10 golden fixtures validate
4. ✅ All 7 quality gates pass (QG-MA0 through QG-MA4)
5. ✅ Coverage ≥80% for cortex-crdt and cortex-multiagent
6. ✅ All benchmarks meet targets
7. ✅ Zero clippy warnings
8. ✅ Zero test regressions
9. ✅ All enterprise requirements met (logging, metrics, errors, performance, security)
10. ✅ Documentation complete for all public APIs

**Success Metric:** Multiple AI agents can share, sync, and collaborate on knowledge with provenance tracking, trust scoring, namespace isolation, and conflict-free convergence — all while maintaining perfect backward compatibility with single-agent mode.
