# MAPhase D1 — Cross-Crate Integration (Consolidation + Validation + Retrieval + Causal + Cloud + Session)

> **ULTRA THINK. Quality over speed. No shortcuts. Enterprise-grade perfection.**
> Your boss audits every line through Codex. Make him stop needing to.

You are implementing Phase D1 of the Cortex multi-agent memory addition. This is the integration phase — threading multi-agent awareness through 6 existing crates without breaking anything. Read these files first:

- `MULTIAGENT-TASK-TRACKER.md` (Phase D1 section, tasks `PMD1-*` and tests `TMD1-*`)
- `MULTIAGENT-IMPLEMENTATION-SPEC.md` (full behavioral spec)
- `FILE-MAP.md` (complete file inventory with per-file details)

**Prerequisite:** QG-MA2 has passed — Phase C's provenance tracking, trust scoring, and delta sync are fully operational. All `TMC-*` tests pass, all 5 property tests pass, `cargo test --workspace` is green, and coverage ≥80% on all Phase C modules. The full multi-agent stack is working: CRDT foundation (Phase A), storage + namespaces + projections (Phase B), and provenance + trust + sync (Phase C).

---

## What This Phase Builds

Phase D1 integrates multi-agent features into 6 existing Cortex crates. 18 impl tasks, 20 tests. The key principle: **feature-gated integration** — all changes check `MultiAgentConfig.enabled` and fall back to existing behavior when disabled. Single-agent mode MUST be completely unaffected.

### 1. cortex-multiagent: Consolidation + Validation (~5 tasks)

**Consensus Detection** (`cortex-multiagent/src/consolidation/consensus.rs`):
- `ConsensusDetector` — finds memories from multiple agents that say the same thing
- Threshold: embedding similarity > 0.9, agent_count >= 2
- Confidence boost: +0.2 for consensus (multiple independent sources agree)
- Returns `ConsensusCandidate` with contributing agents and similarity score

**Cross-Namespace Consolidation** (`cortex-multiagent/src/consolidation/cross_namespace.rs`):
- `CrossNamespaceConsolidator` — extends consolidation pipeline across namespaces
- Pipeline: Phase 0 (gather from all namespaces) → Phases 1-3 (HDBSCAN clustering) → Phase 4 (consensus boost) → Phase 5 (pruning)
- Consolidated memory placed in team/project namespace (not agent namespace)

**Cross-Agent Validation** (`cortex-multiagent/src/validation/cross_agent.rs`):
- `CrossAgentValidator` — detects contradictions between agents
- Resolution strategy:
  - Trust diff > 0.3 → `TrustWins` (higher-trust agent's memory wins)
  - Trust diff ≤ 0.3 → `NeedsHumanReview`
  - Different scope tags → `ContextDependent`
  - Newer + validated → `TemporalSupersession`

### 2. cortex-causal: Cross-Agent Relations (~4 tasks)

**Relations Extension** (`cortex-causal/src/relations.rs`):
- Add `CrossAgent(CrossAgentRelation)` variant to `CausalRelation` enum

**Edge Extension** (`cortex-causal/src/graph/sync.rs`):
- Add optional `source_agent: Option<AgentId>` to `CausalEdge`
- `None` for single-agent edges (backward compat)

**Cross-Agent Traversal** (`cortex-causal/src/graph/cross_agent.rs`):
- `trace_cross_agent(memory_id, max_depth)` — traverse causal graph across agent boundaries
- `cross_agent_narrative(trace)` — generate narrative from cross-agent trace

### 3. cortex-consolidation: Multi-Agent Extension (~2 tasks)

**Engine Extension** (`cortex-consolidation/src/engine.rs`):
- When `MultiAgentConfig.enabled` → extend consolidation to work across namespaces
- Delegates to `cortex-multiagent::consolidation::CrossNamespaceConsolidator`
- When disabled → existing behavior unchanged

**Pruning Extension** (`cortex-consolidation/src/pipeline/phase6_pruning.rs`):
- Preserve cross-agent provenance when archiving
- Place consolidated memory in team/project namespace

### 4. cortex-validation: Multi-Agent Extension (~1 task)

**Engine Extension** (`cortex-validation/src/engine.rs`):
- When `MultiAgentConfig.enabled` → extend contradiction detection across namespaces
- Delegates to `cortex-multiagent::validation::CrossAgentValidator`
- Update trust evidence after validation (record_validation / record_contradiction)

### 5. cortex-retrieval: Trust-Weighted Ranking (~2 tasks)

**Scorer Extension** (`cortex-retrieval/src/ranking/scorer.rs`):
- When `MultiAgentConfig.enabled` → add trust-weighted scoring factor
- Memories from higher-trust agents rank higher
- Trust score modulates the ranking weight

**Engine Extension** (`cortex-retrieval/src/engine.rs`):
- Add optional `namespace_filter: Option<NamespaceId>` to retrieval queries
- Respect projection compression levels when retrieving

### 6. cortex-cloud: CRDT Merge (~2 tasks)

**Sync Protocol Extension** (`cortex-cloud/src/sync/protocol.rs`):
- Add `agent_id: AgentId` field to sync request/response
- Default to `AgentId::default_agent()` for backward compat

**Conflict Resolver Extension** (`cortex-cloud/src/conflict/resolver.rs`):
- When `MultiAgentConfig.enabled` → use CRDT merge instead of LWW/local-wins/remote-wins
- When disabled → existing conflict resolution strategies unchanged

### 7. cortex-session: Agent-Aware Sessions (~2 tasks)

**Context Extension** (`cortex-session/src/context.rs`):
- Add `agent_id: AgentId` to `SessionContext` (default: `AgentId::default_agent()`)

**Dedup Extension** (`cortex-session/src/dedup.rs`):
- Dedup key changes from `(session_id, content_hash)` to `(session_id, agent_id, namespace_id, content_hash)`
- Different agents can have the same content in different namespaces without dedup

---

## Critical Implementation Details

### Feature Flag Pattern

Every integration point MUST follow this pattern:

```rust
if self.config.multiagent.enabled {
    // Multi-agent behavior
    let result = multiagent_engine.do_thing()?;
    // ...
} else {
    // Existing single-agent behavior — UNCHANGED
    let result = existing_behavior()?;
    // ...
}
```

This ensures:
1. Single-agent mode is completely unaffected
2. Multi-agent features can be enabled/disabled at runtime
3. No performance overhead when disabled (branch prediction eliminates the check)

### Zero Regressions Rule

This phase modifies 12 existing files across 6 crates. The absolute rule: **every existing test must continue to pass unchanged**. If a test fails, the integration is wrong — fix the integration, not the test.

Run `cargo test --workspace` frequently. Run it after every file modification.

### Trust-Weighted Ranking

The trust score modulates ranking, not replaces it:
```rust
let trust_factor = if config.multiagent.enabled {
    trust_scorer.get_trust(current_agent, memory.source_agent)
        .map(|t| t.overall_trust)
        .unwrap_or(0.5) // neutral if no trust data
} else {
    1.0 // no modulation in single-agent mode
};

candidate.score *= trust_factor;
```

### Cross-Agent Contradiction Resolution

Resolution is deterministic:
1. Compute trust diff: `|trust_a - trust_b|`
2. If diff > 0.3 → higher-trust agent wins (`TrustWins`)
3. If diff ≤ 0.3 AND different scope tags → `ContextDependent` (both valid in their context)
4. If diff ≤ 0.3 AND newer memory is validated → `TemporalSupersession`
5. Otherwise → `NeedsHumanReview`

### Session Dedup Key Change

The dedup key expansion is backward compatible:
- Old key: `(session_id, content_hash)` — still works when all memories have default agent/namespace
- New key: `(session_id, agent_id, namespace_id, content_hash)` — allows same content from different agents

---

## Reference Crate Patterns

- **Feature-gated integration**: Follow how `cortex-retrieval` uses the `reranker` feature flag — `#[cfg(feature = "reranker")]` for compile-time, runtime config check for behavior
- **Cross-crate delegation**: Follow how `cortex-consolidation/src/engine.rs` delegates to pipeline phases — the engine orchestrates, submodules do the work
- **Existing test preservation**: Run `cargo test -p {crate}` after each modification to catch regressions immediately

---

## Task Checklist

Check off tasks in `MULTIAGENT-TASK-TRACKER.md` as you complete them:

**Multi-Agent Consolidation**: `PMD1-MA-01` through `PMD1-MA-05`
**Causal**: `PMD1-CAUSAL-01` through `PMD1-CAUSAL-04`
**Consolidation**: `PMD1-CONS-01`, `PMD1-CONS-02`
**Validation**: `PMD1-VALID-01`
**Retrieval**: `PMD1-RET-01`, `PMD1-RET-02`
**Cloud**: `PMD1-CLOUD-01`, `PMD1-CLOUD-02`
**Session**: `PMD1-SESS-01`, `PMD1-SESS-02`
**Tests**: All `TMD1-CONS-*` (4), `TMD1-VALID-*` (5), `TMD1-INT-*` (11), `TMD1-TEST-*` (2)

---

## Quality Gate: QG-MA3a

Before proceeding to Phase D2, ALL of these must pass:

### Tests
- [ ] All 20 `TMD1-*` tests pass
- [ ] `cargo test -p cortex-multiagent` — zero failures
- [ ] `cargo test -p cortex-causal` — zero failures
- [ ] `cargo test -p cortex-consolidation` — zero failures
- [ ] `cargo test -p cortex-validation` — zero failures
- [ ] `cargo test -p cortex-retrieval` — zero failures
- [ ] `cargo test -p cortex-cloud` — zero failures
- [ ] `cargo test -p cortex-session` — zero failures
- [ ] `cargo test --workspace` — zero regressions

### Coverage
- [ ] Coverage ≥80% for cortex-multiagent consolidation modules
- [ ] Coverage ≥80% for cortex-multiagent validation modules
- [ ] Coverage ≥80% for all modified existing crate code

### Enterprise
- [ ] All feature-gated code has both enabled and disabled paths tested
- [ ] All cross-crate integrations logged at appropriate levels
- [ ] All error paths return clear, actionable errors

---

## Common Pitfalls to Avoid

- ❌ **Don't modify existing test assertions** — if a test fails, the integration is wrong
- ❌ **Don't add multi-agent deps to crates that don't need them** — use optional deps or runtime config
- ❌ **Don't forget the feature flag check** — every integration point must check `config.multiagent.enabled`
- ❌ **Don't break the dedup key silently** — the new key must produce the same results for single-agent mode
- ✅ **Do run `cargo test --workspace` after every file change** — catch regressions immediately
- ✅ **Do test both enabled and disabled paths** — single-agent mode must be unaffected
- ✅ **Do use `Option<AgentId>` for backward-compatible fields** — None = single-agent mode

---

## Success Criteria

Phase D1 is complete when:

1. ✅ All 18 implementation tasks completed
2. ✅ All 20 tests pass
3. ✅ Coverage ≥80% on all modified code
4. ✅ QG-MA3a quality gate passes
5. ✅ Zero regressions across all 6 modified crates
6. ✅ Feature flag works correctly (enabled = multi-agent, disabled = unchanged)

**You'll know it works when:** With multi-agent enabled, retrieval ranks higher-trust agents' memories above lower-trust agents', validation detects cross-agent contradictions and resolves them by trust, and consolidation finds consensus across namespaces. With multi-agent disabled, everything behaves exactly as before.

---

## Next Steps After Phase D1

Once QG-MA3a passes, proceed to **MAPhase D2: NAPI + TypeScript Bridge**, which exposes all multi-agent functionality to TypeScript via NAPI bindings.
