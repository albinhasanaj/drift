# Bridge Correlation Hardening Tasks

> Deep audit of the drift→cortex-drift-bridge→cortex grounding correlation pipeline.
>
> **Audit date:** 2026-02-10
> **Files audited:** ~50 source files across `crates/cortex-drift-bridge/src/` (15 modules), `crates/drift/drift-storage/src/migrations/` (7 migration files, 39 tables), `packages/cortex/src/` (TS exposure layer)
> **Source findings:** `DRIFT-CORTEX-CORRELATION-AUDIT.md` — 10 findings (1 P0, 4 P1, 5 P2)
> **Auditor:** Cascade deep-dive (full schema cross-reference)

---

## Executive Summary

The cortex-drift-bridge is architecturally novel — the only system that empirically grounds AI memory against static analysis evidence with weighted scoring, contradiction generation, and causal graph integration. The 10-evidence-type system, 21 event mappings, 6 trigger types, and 13 groundability classifications are all well-designed.

**However, the entire grounding pipeline is disconnected from drift.db.** All 10 queries in `drift_queries.rs` target phantom table names that don't exist in the real schema. Event mapping creates memories but never pre-populates evidence fields. The grounding scheduler is never instantiated. 12 of 39 drift.db tables (including all security findings) are never correlated into Cortex. The intent resolver maps 10 intents that don't match the 10 extension intents.

**Bottom line:** The engine is built correctly. The fuel lines are disconnected. This spec reconnects them.

**Severity:** P0=1, P1=4, P2=5 → **10 findings total**

---

## Findings by Severity

### P0 — CRITICAL: Production-Breaking (1 finding)

#### P0-1. All 10 drift_queries.rs Queries Target Phantom Tables (Audit #1)
**File:** `cortex-drift-bridge/src/query/drift_queries.rs:1-149`

Every query uses `drift_`-prefixed table names and idealized column names that don't exist in drift.db:

```
Bridge queries:                          Actual drift.db:
─────────────────────────────────────    ─────────────────────────────────────
drift_patterns.confidence                pattern_confidence.posterior_mean
drift_patterns.occurrence_rate           (no such column — needs COUNT query)
drift_violation_feedback.fp_rate         feedback (no fp_rate column — needs ratio)
drift_constraints.verified               constraint_verifications.passed
drift_coupling.instability               coupling_metrics.instability
drift_dna.health_score                   dna_genes (no health_score — needs AVG)
drift_test_topology.coverage             test_quality.overall_score
drift_error_handling.gap_count           error_gaps (no gap_count — needs COUNT)
drift_decisions.evidence_score           decisions.confidence
drift_boundaries.boundary_score          boundaries.confidence
```

**Impact:** When `MemoryForGrounding` fields are `None` and the system falls back to drift.db queries, every query returns `Err(no such table)`, caught at `debug` level. Grounding reports `InsufficientData` for all memories.

---

### P1 — HIGH: Silent Functional Failure (4 findings)

#### P1-1. Event Mapping Creates Memories But Never Populates Evidence Fields (Audit #5)
**File:** `cortex-drift-bridge/src/event_mapping/mapper.rs:1-564`

`BridgeEventHandler::create_memory()` creates `BaseMemory` with tags and linked_patterns, but the `MemoryForGrounding` evidence fields (`pattern_confidence`, `occurrence_rate`, etc.) are never pre-populated. The dual-path fallback in `collect_evidence()` (lines 325-343 of `loop_runner.rs`) already exists and will query drift.db when `evidence_context` is present — **but no production code path populates `evidence_context` either.** Flow:
1. Memory created with initial confidence from mapping table
2. Grounding runs → `MemoryForGrounding` has all `None` fields AND `evidence_context: None`
3. Dual-path fallback skipped (no evidence_context) → drift.db queries never attempted
4. Even if evidence_context were populated, drift.db queries are all broken (P0-1)
5. Result: `InsufficientData` for every memory

**Key nuance:** The `evidence_context` field and dual-path strategy were added in a prior bug fix, but the upstream code that should populate `evidence_context` from memory tags (via `context_from_tags()`) is never called in any production path.

#### P1-2. 12 drift.db Tables Have Zero Cortex Correlation (Audit #2)
**Tables:** `taint_flows`, `crypto_findings`, `secrets`, `owasp_findings`, `env_variables`, `wrappers`, `contracts`, `contract_mismatches`, `coupling_cycles`, `dna_mutations`, `decomposition_decisions`, `constants`

These 12 tables contain high-value analysis data (especially the 4 security tables) that is never correlated into Cortex — not via evidence collection, not via event mapping, not via any bridge path. This leaves ~30% of Drift's intelligence on the table.

#### P1-3. Intent Resolver Maps 10 Intents That Don't Match Extension Intents (Audit #3)
**Files:** `cortex-drift-bridge/src/intents/extensions.rs`, `cortex-drift-bridge/src/intents/resolver.rs`

Extensions define: `add_feature`, `fix_bug`, `refactor`, `review_code`, `debug`, `understand_code`, `security_audit`, `performance_audit`, `test_coverage`, `documentation`

Resolver handles: `explain_pattern`, `explain_violation`, `explain_decision`, `suggest_fix`, `assess_risk`, `review_boundary`, `trace_dependency`, `check_convention`, `analyze_test_coverage`, `security_audit`

Only 1/10 overlaps (`security_audit`). The other 9 extension intents fall through to the default resolver (all 12 sources at depth 1), defeating intent-specific targeting.

#### P1-4. 3 of 12 GroundingDataSources Are Phantom (Audit #4)
**File:** `cortex-drift-bridge/src/types/data_source.rs`

`GroundingDataSource` declares 12 variants including `Taint`, `CallGraph`, `Security`. But the evidence collection system has only 10 evidence types and doesn't use `GroundingDataSource` at all. These 3 data sources have zero evidence collectors — no way to collect grounding evidence from `taint_flows`, `call_edges`, or security findings.

---

### P2 — MEDIUM: Degraded Functionality (5 findings)

| ID | Finding | File | Impact |
|----|---------|------|--------|
| P2-1 | `generate_contradiction()` is dead code + not linked to causal graph | `contradiction.rs`, `loop_runner.rs:120-122` | Loop runner sets `generates_contradiction` flag but never calls `generate_contradiction()`. Even if called, it doesn't invoke `add_grounding_edge()` (which requires 4 params: engine, memory, result, grounding_memory) |
| P2-2 | 20 NAPI + 6 MCP bridge functions have zero TS exposure | `napi/functions.rs`, `tools/*.rs` | Bridge is a working engine with no ignition key |
| P2-3 | Cross-DB ATTACH infrastructure unused | `query/cross_db.rs`, `query/attach.rs` | RAII guards built but never called from production |
| P2-4 | GroundingScheduler never instantiated | `grounding/scheduler.rs` | `on_scan_complete` triggers_grounding=true but scheduler not wired |
| P2-5 | 6 subsystems referenced by intents but not queryable | `intents/resolver.rs` | `n_plus_one`, `reachability`, `impact`, `call_graph`, `taint`, `security` have no data retrieval path |

---

## Phase Plan

### Phase A: Fix Phantom Queries — Reconnect Grounding to drift.db (CRITICAL PATH)

Rewrite all 10 `drift_queries.rs` functions to match the real drift.db schema. This is the single highest-impact change — it makes the entire grounding fallback path functional.

| ID | Task | File(s) | Type | Audit Ref |
|----|------|---------|------|-----------|
| A-01 | Rewrite `pattern_confidence()` — `SELECT posterior_mean FROM pattern_confidence WHERE pattern_id = ?1` | `query/drift_queries.rs:11-22` | impl | P0-1 |
| A-02 | Rewrite `pattern_occurrence_rate()` — `SELECT COUNT(DISTINCT file) * 1.0 / (SELECT COUNT(DISTINCT file) FROM detections) FROM detections WHERE pattern_id = ?1` (file-level occurrence, not pattern count ratio) | `query/drift_queries.rs:24-36` | impl | P0-1 |
| A-03 | Rewrite `false_positive_rate()` — `SELECT COALESCE(SUM(CASE WHEN action = 'dismiss' THEN 1 ELSE 0 END) * 1.0 / NULLIF(COUNT(*), 0), 0.0) FROM feedback WHERE pattern_id = ?1` | `query/drift_queries.rs:38-50` | impl | P0-1 |
| A-04 | Rewrite `constraint_verified()` — `SELECT passed FROM constraint_verifications WHERE constraint_id = ?1 ORDER BY verified_at DESC LIMIT 1` (returns `bool` from `INTEGER`) | `query/drift_queries.rs:52-64` | impl | P0-1 |
| A-05 | Rewrite `coupling_metric()` — `SELECT instability FROM coupling_metrics WHERE module = ?1` (table name fix only, column was correct) | `query/drift_queries.rs:66-78` | impl | P0-1 |
| A-06 | Rewrite `dna_health()` — `SELECT AVG(confidence * consistency) FROM dna_genes` (project-level aggregate; drop `project` param, use global health) | `query/drift_queries.rs:80-92` | impl | P0-1 |
| A-07 | Rewrite `test_coverage()` — `SELECT overall_score FROM test_quality WHERE function_id = ?1` (change param from `module_path` to `function_id`) | `query/drift_queries.rs:94-106` | impl | P0-1 |
| A-08 | Rewrite `error_handling_gaps()` — `SELECT COUNT(*) FROM error_gaps WHERE file LIKE ?1 || '%'` (module_path prefix match on `file` column) | `query/drift_queries.rs:108-120` | impl | P0-1 |
| A-09 | Rewrite `decision_evidence()` — `SELECT confidence FROM decisions WHERE id = CAST(?1 AS INTEGER)` (table `decisions`, column `confidence`; **NOTE:** `id` is `INTEGER AUTOINCREMENT`, bridge passes `&str` — must CAST or change `EvidenceContext.decision_id` to `Option<i64>`) | `query/drift_queries.rs:122-134` | impl | P0-1 |
| A-10 | Rewrite `boundary_data()` — `SELECT confidence FROM boundaries WHERE id = CAST(?1 AS INTEGER)` (table `boundaries`, column `confidence`; **NOTE:** same INTEGER PK issue as decisions) | `query/drift_queries.rs:136-149` | impl | P0-1 |
| A-11 | Update `EvidenceContext` — `project` is already `Option<String>` (will become unused after DNA health goes global); add `function_id: Option<String>` for test_quality queries; add `file_path: Option<String>` for future security queries (Phase C) | `grounding/evidence/collector.rs:15-30` | impl | P0-1 |
| A-12 | Update `context_from_tags()` — parse `function:xxx` tags into `EvidenceContext.function_id` | `grounding/evidence/composite.rs` | impl | P0-1 |
| A-13 | **Test: pattern_confidence returns real data** — create in-memory drift.db with `pattern_confidence` table, insert row, query via `drift_queries::pattern_confidence()` → verify `posterior_mean` returned | new test | test | P0-1 |
| A-14 | **Test: all 10 queries return data from real schema** — create drift.db with all 7 migrations, insert sample data into all 10 queried tables, run all 10 query functions → verify all return `Some(value)` | new test | test | P0-1 |
| A-15 | **Test: queries return None for missing data** — empty drift.db with schema → all 10 queries return `Ok(None)`, not `Err` | new test | test | P0-1 |
| A-16 | **Test: false_positive_rate handles zero feedback** — no rows in `feedback` → returns `Some(0.0)` not division-by-zero | new test | test | P0-1 |
| A-17 | **Test: constraint_verified returns latest** — insert 3 verifications (pass, fail, pass) → returns `true` (latest) | new test | test | P0-1 |
| A-18 | **Test: error_handling_gaps counts by prefix** — insert gaps for `src/auth.rs` and `src/api.rs` → query `src/auth` → returns 1 | new test | test | P0-1 |
| A-19 | **Test: end-to-end grounding with real drift.db** — create drift.db with sample data, create `MemoryForGrounding` with `evidence_context` but all `None` fields → run `ground_single()` with drift_db → verify evidence collected from all 10 types, verdict is not `InsufficientData` | new test | test | P0-1 |

**Estimated effort:** 3-4 hours (SQL rewrites) + 2-3 hours (tests) = **1 day**

---

### Phase B: Wire Evidence Context Population + Grounding Scheduler

The dual-path fallback in `collect_evidence()` already exists (lines 325-343 of `loop_runner.rs`), and `MemoryForGrounding` already has an `evidence_context` field. **The gap is that no production code populates `evidence_context`.** This phase wires that up and instantiates the scheduler.

| ID | Task | File(s) | Type | Audit Ref |
|----|------|---------|------|-----------|
| B-01 | In `BridgeEventHandler::create_memory()`, after creating `BaseMemory`, call `context_from_tags()` with the memory's tags and linked_patterns to build an `EvidenceContext`, and store it alongside the memory in bridge_memories (add `evidence_context_json TEXT` column) | `event_mapping/mapper.rs`, `storage/schema.rs` | impl | P1-1 |
| B-02 | When loading memories for grounding (in `cortex_queries.rs` or wherever `MemoryForGrounding` is constructed), deserialize `evidence_context_json` into `MemoryForGrounding.evidence_context` | `query/cortex_queries.rs` or grounding orchestration code | impl | P1-1 |
| B-03 | Add `evidence_context_json TEXT` column to `bridge_memories` table in bridge schema migration | `storage/schema.rs`, `storage/migrations.rs` | impl | P1-1 |
| B-04 | Ensure `context_from_tags()` correctly parses all tag formats used by `BridgeEventHandler` — `pattern:xxx`, `constraint:xxx`, `module:xxx`, `file:xxx`, `function:xxx`, `decision:xxx`, `boundary:xxx` | `grounding/evidence/composite.rs` | impl | P1-1 |
| B-05 | Instantiate `GroundingScheduler` in `BridgeRuntime` — store as field, call `scheduler.on_scan_complete()` from `on_scan_complete` event handler | `lib.rs`, `event_mapping/mapper.rs` | impl | P2-4 |
| B-06 | Wire scheduler trigger type to `GroundingLoopRunner::run()` — when `on_scan_complete` fires, load all groundable memories from bridge_memories, run grounding loop with the scheduler-determined trigger type | `event_mapping/mapper.rs` or new `grounding/orchestrator.rs` | impl | P2-4 |
| B-07 | **Test: event creates memory with evidence_context** — fire `on_pattern_approved` with a pattern_id → verify `bridge_memories` row has non-null `evidence_context_json` containing the pattern_id | new test | test | P1-1 |
| B-08 | **Test: grounding uses evidence_context for drift.db fallback** — insert memory with evidence_context (pattern_id set) + real drift.db with pattern_confidence data → run grounding → verify PatternConfidence evidence collected, verdict is not `InsufficientData` | new test | test | P1-1 |
| B-09 | **Test: grounding without evidence_context returns InsufficientData** — insert memory with `evidence_context: None` and all `None` fields → run grounding → verify `InsufficientData` (confirms the gap this phase fixes) | new test | test | P1-1 |
| B-10 | **Test: scheduler triggers grounding on scan_complete** — fire `on_scan_complete` → verify grounding loop ran (check snapshot recorded) | new test | test | P2-4 |
| B-11 | **Test: scheduler alternates incremental/full** — fire 10 `on_scan_complete` events → verify 9 incremental + 1 full (at interval=10) | new test | test | P2-4 |
| B-12 | **Test: full end-to-end: scan → event → memory → grounding → verdict** — create drift.db with pattern data, fire `on_pattern_approved`, run grounding → verify memory exists with non-InsufficientData verdict | new test | test | P1-1, P2-4 |

**Estimated effort:** 2-3 days

---

### Phase C: Expand Evidence Coverage — Security + Structural Tables

Add evidence types and event mappings for the 12 uncorrelated drift.db tables, prioritizing the 4 security tables.

| ID | Task | File(s) | Type | Audit Ref |
|----|------|---------|------|-----------|
| C-01 | Add `EvidenceType::SecurityTaint` — queries `taint_flows` for unsanitized flow count by file | `grounding/evidence/types.rs` | impl | P1-2 |
| C-02 | Add `EvidenceType::SecurityCrypto` — queries `crypto_findings` for finding count/severity by file | `grounding/evidence/types.rs` | impl | P1-2 |
| C-03 | Add `EvidenceType::SecuritySecrets` — queries `secrets` for secret count by file | `grounding/evidence/types.rs` | impl | P1-2 |
| C-04 | Add `EvidenceType::SecurityOwasp` — queries `owasp_findings` for finding count/avg severity by file | `grounding/evidence/types.rs` | impl | P1-2 |
| C-05 | Add default weights for 4 new evidence types (suggest: Taint=0.15, Crypto=0.12, Secrets=0.15, OWASP=0.12) | `grounding/evidence/types.rs` | impl | P1-2 |
| C-06 | Add 4 new query functions in `drift_queries.rs` — `taint_flow_count(conn, file)`, `crypto_finding_count(conn, file)`, `secret_count(conn, file)`, `owasp_severity(conn, file)` | `query/drift_queries.rs` | impl | P1-2 |
| C-07 | Add 4 new collector functions in `collector.rs` — `collect_security_taint()`, `collect_security_crypto()`, `collect_security_secrets()`, `collect_security_owasp()` | `grounding/evidence/collector.rs` | impl | P1-2 |
| C-08 | Update `EvidenceType::ALL` array to include 4 new types (10 → 14) | `grounding/evidence/types.rs` | impl | P1-2 |
| C-09 | Update `EvidenceContext` — add `file_path: Option<String>` for security queries (security tables are file-scoped) | `grounding/evidence/collector.rs` | impl | P1-2 |
| C-10 | Update `context_from_tags()` — parse `file:xxx` tags into `EvidenceContext.file_path` | `grounding/evidence/composite.rs` | impl | P1-2 |
| C-11 | Add `MemoryForGrounding` fields — `security_taint: Option<u32>`, `security_crypto: Option<u32>`, `security_secrets: Option<u32>`, `security_owasp: Option<f64>` | `grounding/loop_runner.rs` | impl | P1-2 |
| C-12 | Add pre-populated field handling in `collect_evidence()` for 4 new types | `grounding/loop_runner.rs` | impl | P1-2 |
| C-13 | Add 4 new event mappings for security events — `on_taint_detected` → Insight (0.7), `on_crypto_finding` → CodeSmell (0.8), `on_secret_detected` → CodeSmell (0.9, Critical), `on_owasp_finding` → Insight (0.7) | `event_mapping/memory_types.rs` | impl | P1-2 |
| C-14 | Add event handlers for 4 new security events in `BridgeEventHandler` | `event_mapping/mapper.rs` | impl | P1-2 |
| C-15 | Add event mappings for structural tables — `on_coupling_cycle_detected` → CodeSmell (0.8), `on_dna_mutation_detected` → CodeSmell (0.6), `on_contract_mismatch_detected` → Feedback (0.7), `on_wrapper_detected` → Insight (0.5) | `event_mapping/memory_types.rs` | impl | P1-2 |
| C-16 | Add event handlers for 4 structural events in `BridgeEventHandler` | `event_mapping/mapper.rs` | impl | P1-2 |
| C-17 | **Test: security taint evidence collected** — insert taint_flows rows → collect SecurityTaint evidence → verify count and support score | new test | test | P1-2 |
| C-18 | **Test: security evidence weights sum correctly** — verify 14 evidence type weights still produce valid weighted average (no >1.0 scores) | new test | test | P1-2 |
| C-19 | **Test: all 14 evidence types collected from full drift.db** — create drift.db with all tables populated → collect_all → verify 14 evidence items | new test | test | P1-2 |
| C-20 | **Test: security event creates memory** — fire `on_secret_detected` → verify CodeSmell memory created with `security_secrets` tag and Critical importance | new test | test | P1-2 |
| C-21 | **Test: structural event creates memory** — fire `on_coupling_cycle_detected` → verify CodeSmell memory with cycle members in content | new test | test | P1-2 |
| C-22 | **Test: grounding with security evidence changes verdict** — memory with only pattern evidence = Partial → add security evidence → verify score changes | new test | test | P1-2 |

**Estimated effort:** 3-4 days

---

### Phase D: Fix Intent System + Wire Phantom Data Sources

Align the intent resolver with extension intents and add data retrieval for referenced subsystems.

| ID | Task | File(s) | Type | Audit Ref |
|----|------|---------|------|-----------|
| D-01 | Merge extension intents and resolver intents into unified 15-intent system — keep all 10 extensions + add 5 resolver-only intents (`explain_pattern`, `explain_violation`, `explain_decision`, `suggest_fix`, `assess_risk`) | `intents/extensions.rs` | impl | P1-3 |
| D-02 | Rewrite `resolve_intent()` to handle all 15 intents with targeted data sources | `intents/resolver.rs` | impl | P1-3 |
| D-03 | Add resolver mappings for the 9 previously-unresolved extension intents: `add_feature` → Patterns+Conventions+Boundaries+CallGraph, `fix_bug` → ErrorHandling+Taint+TestTopology+CallGraph, `refactor` → Coupling+Patterns+Dna, `review_code` → Patterns+Constraints+Security, `debug` → CallGraph+ErrorHandling+Taint+Boundaries, `understand_code` → Patterns+CallGraph+Boundaries+Dna, `performance_audit` → Coupling+CallGraph+Boundaries, `test_coverage` → TestTopology+CallGraph, `documentation` → Patterns+Conventions+Boundaries | `intents/resolver.rs` | impl | P1-3 |
| D-04 | Add drift.db query functions for 3 phantom data sources — `query_taint_flows(conn, file)` → Vec of taint flow summaries, `query_call_graph_neighbors(conn, function_id)` → Vec of callers/callees, `query_security_findings(conn, file)` → combined secrets+crypto+owasp | `query/drift_queries.rs` | impl | P1-4 |
| D-05 | Add drift.db query functions for 3 additional referenced subsystems — `query_reachability(conn, node)`, `query_impact_scores(conn, function_id)`, `query_n_plus_one(conn, file)` (from data_access table, detect repeated table access patterns) | `query/drift_queries.rs` | impl | P2-5 |
| D-06 | Wire `GroundingDataSource` enum to actual query dispatch — add `fn query_source(source: GroundingDataSource, conn: &Connection, ctx: &EvidenceContext) -> BridgeResult<Vec<serde_json::Value>>` | new file `query/source_dispatch.rs` | impl | P1-4 |
| D-07 | Update intent resolver to use `query_source()` for data retrieval instead of just returning source names | `intents/resolver.rs` | impl | P1-4, P2-5 |
| D-08 | Update resolver test — `test_all_10_intents_resolve` → `test_all_15_intents_resolve` | `intents/resolver.rs` (inline tests) | impl | P1-3 |
| D-09 | **Test: all 15 intents resolve with targeted sources** — verify each intent maps to 2-4 specific sources, not the default 12 | new test | test | P1-3 |
| D-10 | **Test: extension intents match resolver intents** — verify every intent in `CODE_INTENTS` has a non-default resolution in `resolve_intent()` | new test | test | P1-3 |
| D-11 | **Test: taint data source returns real data** — insert taint_flows → query via `query_source(Taint, ...)` → verify non-empty result | new test | test | P1-4 |
| D-12 | **Test: call_graph data source returns neighbors** — insert call_edges → query via `query_source(CallGraph, ...)` → verify callers and callees | new test | test | P1-4 |
| D-13 | **Test: security data source aggregates all 3 tables** — insert secrets + crypto + owasp → query via `query_source(Security, ...)` → verify combined results | new test | test | P1-4 |
| D-14 | **Test: unknown intent still gets default resolution** — `resolve_intent("nonexistent")` → verify all 12 sources at depth 1 | new test | test | P1-3 |

**Estimated effort:** 2-3 days

---

### Phase E: Causal Graph + Contradiction Wiring

Wire contradiction generation to the causal graph and fix the cross-db infrastructure.

| ID | Task | File(s) | Type | Audit Ref |
|----|------|---------|------|-----------|
| E-01 | In `GroundingLoopRunner::run()` — after `if generates_contradiction` (line 120), call `generate_contradiction(&result, bridge_db)` to actually create the contradiction memory (currently dead code — only increments counter) | `grounding/loop_runner.rs:120-122` | impl | P2-1 |
| E-02 | In `GroundingLoopRunner::ground_single()` — same wiring: when `generates_contradiction` is true, call `generate_contradiction()` | `grounding/loop_runner.rs` | impl | P2-1 |
| E-03 | In `generate_contradiction()`, after creating and storing the contradiction memory, call `add_grounding_edge(engine, original_memory, grounding_result, &contradiction_memory)` — note: `add_grounding_edge()` takes 4 params (engine, memory, result, grounding_memory) | `grounding/contradiction.rs` | impl | P2-1 |
| E-04 | Update `generate_contradiction()` signature — add `causal_engine: Option<&CausalEngine>` and `original_memory: &BaseMemory` params (needed for `add_grounding_edge`) | `grounding/contradiction.rs` | impl | P2-1 |
| E-05 | Add `causal_engine: Option<&CausalEngine>` to `GroundingLoopRunner::new()` or pass per-call, and thread it through to `generate_contradiction()` calls | `grounding/loop_runner.rs` | impl | P2-1 |
| E-06 | Wire cross-db ATTACH for complex evidence queries — use `with_drift_attached()` in a new `collect_cross_db_evidence()` function that JOINs pattern_confidence with detections for richer evidence | `query/cross_db.rs`, `grounding/evidence/collector.rs` | impl | P2-3 |
| E-07 | **Test: contradiction creates causal edge** — ground a memory with Invalidated verdict → verify causal edge exists from original memory to contradiction with `Contradicts` relation | new test | test | P2-1 |
| E-08 | **Test: contradiction with Weak verdict creates Supports edge** — ground a memory with Weak verdict and score drop → verify causal edge with `Supports` relation (low strength) | new test | test | P2-1 |
| E-09 | **Test: contradiction without causal_engine still works** — pass `None` for causal_engine → verify contradiction memory created, no panic, warning logged | new test | test | P2-1 |
| E-10 | **Test: cross-db ATTACH query returns joined data** — attach drift.db → query pattern_confidence JOIN detections → verify combined result | new test | test | P2-3 |
| E-11 | **Test: cross-db DETACH is automatic** — use `with_drift_attached()` → verify drift.db is detached after scope exit (query drift.db alias → error) | new test | test | P2-3 |

**Estimated effort:** 1-2 days

---

### Phase F: TS Exposure — Bridge NAPI + MCP Accessibility

Expose the 20 NAPI-ready bridge functions and 6 MCP tool handlers to the TypeScript layer.

| ID | Task | File(s) | Type | Audit Ref |
|----|------|---------|------|-----------|
| F-01 | Create `packages/cortex/src/bridge/drift-bridge.ts` — TS wrapper for all 20 bridge NAPI functions with typed interfaces | new file | impl | P2-2 |
| F-02 | Add `BridgeClient` class with methods: `status()`, `groundMemory()`, `groundAll()`, `groundingHistory()`, `translateLink()`, `translateConstraintLink()`, `eventMappings()`, `groundability()`, `licenseCheck()`, `intents()`, `adaptiveWeights()`, `specCorrection()`, `contractVerified()`, `decompositionAdjusted()`, `explainSpec()`, `counterfactual()`, `intervention()`, `health()`, `unifiedNarrative()`, `pruneCausal()` | `packages/cortex/src/bridge/drift-bridge.ts` | impl | P2-2 |
| F-03 | Add `NativeBindings` entries for all 20 bridge functions | `packages/cortex/src/bridge/index.ts` | impl | P2-2 |
| F-04 | Create 6 MCP tool wrappers for bridge tools — `drift_grounding_check`, `drift_counterfactual`, `drift_intervention`, `drift_health`, `drift_why`, `drift_memory_learn` (these are the actual 6 `handle_*` functions in `tools/`) | `packages/cortex/src/tools/bridge/` (new directory, 6 files) | impl | P2-2 |
| F-05 | Register 6 new bridge tools in tool index | `packages/cortex/src/tools/index.ts` | impl | P2-2 |
| F-06 | Add bridge tools to MCP server tool registry (when Cortex MCP integration lands) | `packages/drift-mcp/src/tools/` or `packages/cortex/src/tools/` | impl | P2-2 |
| F-07 | **Test: BridgeClient.status() returns valid JSON** — call status → verify `available`, `license_tier`, `grounding_enabled`, `version` fields present | new test | test | P2-2 |
| F-08 | **Test: BridgeClient.groundMemory() returns grounding result** — construct MemoryForGrounding → ground → verify `verdict`, `grounding_score`, `evidence` array | new test | test | P2-2 |
| F-09 | **Test: BridgeClient.eventMappings() returns 21+ mappings** — call → verify array length ≥ 21 (original) + 8 (new from Phase C) | new test | test | P2-2 |
| F-10 | **Test: MCP drift_grounding_check tool returns structured result** — call tool with memory_id → verify JSON schema matches expected format | new test | test | P2-2 |
| F-11 | **Test: MCP drift_health tool returns health status** — call tool → verify `cortex_db`, `drift_db`, `causal_engine` status fields | new test | test | P2-2 |
| F-12 | **Test: all 20 bridge functions callable from TS** — iterate all BridgeClient methods → verify no `undefined` or `not a function` errors | new test | test | P2-2 |

**Estimated effort:** 2-3 days

---

## Dependency Graph

```
Phase A (Fix Phantom Queries)              ← CRITICAL PATH, start here
    │
    ├──→ Phase B (Wire Evidence Pre-Population) ← depends on A (queries must work first)
    │        │
    │        ├──→ Phase C (Expand Evidence Coverage) ← depends on A+B (pattern established)
    │        │
    │        └──→ Phase E (Causal + Contradiction) ← depends on B (grounding must work)
    │
    ├──→ Phase D (Intent System)            ← parallelizable with B after A
    │
    └──→ Phase F (TS Exposure)              ← parallelizable with B/D after A
```

**Critical path:** A(1d) → B(2-3d) → C(3-4d) → E(1-2d) = **7-10 working days**

**With parallelism:**
```
Day 1:     A (fix phantom queries)
Day 2-3:   B (evidence pre-population) + D (intent system, parallel)
Day 4-6:   C (expand evidence coverage) + F (TS exposure, parallel)
Day 7-8:   E (causal wiring) + integration testing
```
**With parallelism: 8-10 working days** (2 engineers: 5-6 days)

---

## Summary Statistics

| Metric | Count |
|--------|-------|
| **Bridge modules audited** | 15 |
| **drift.db tables cross-referenced** | 39 |
| **Total audit findings** | 10 |
| **P0 (production-breaking)** | 1 |
| **P1 (silent functional failure)** | 4 |
| **P2 (degraded functionality)** | 5 |
| **Implementation tasks** | 52 |
| **Test tasks** | 40 |
| **Total tasks** | 92 |
| **Evidence types (current → target)** | 10 → 14 |
| **Event mappings (current → target)** | 21 → 29 |
| **Intents (current → target)** | 10 (mismatched) → 15 (unified) |
| **GroundingDataSources wired (current → target)** | 9/12 → 12/12 |
| **drift.db tables correlated (current → target)** | 10/39 (all broken) → 22/39 (all working) |

---

## Key File Reference

| Component | Path | Key Lines |
|-----------|------|-----------|
| **drift_queries.rs (10 phantom queries)** | `crates/cortex-drift-bridge/src/query/drift_queries.rs` | 1-149 (ALL wrong) |
| **Evidence types (10 types)** | `crates/cortex-drift-bridge/src/grounding/evidence/types.rs` | 1-98 |
| **Evidence collector (enum dispatch)** | `crates/cortex-drift-bridge/src/grounding/evidence/collector.rs` | 1-258 |
| **Evidence composite (collect_all)** | `crates/cortex-drift-bridge/src/grounding/evidence/composite.rs` | 1-122 |
| **Loop runner (grounding orchestration)** | `crates/cortex-drift-bridge/src/grounding/loop_runner.rs` | 1-470 |
| **Scorer (weighted average + verdicts)** | `crates/cortex-drift-bridge/src/grounding/scorer.rs` | 1-143 |
| **Scheduler (6 trigger types)** | `crates/cortex-drift-bridge/src/grounding/scheduler.rs` | 1-72 |
| **Contradiction generator** | `crates/cortex-drift-bridge/src/grounding/contradiction.rs` | 1-105 |
| **Classification (13 groundable types)** | `crates/cortex-drift-bridge/src/grounding/classification.rs` | 1-80 |
| **Event mapper (21 events → memories)** | `crates/cortex-drift-bridge/src/event_mapping/mapper.rs` | 1-564 |
| **Event mappings table (21 entries)** | `crates/cortex-drift-bridge/src/event_mapping/memory_types.rs` | 1-259 |
| **Intent extensions (10 intents)** | `crates/cortex-drift-bridge/src/intents/extensions.rs` | 1-89 |
| **Intent resolver (10 different intents)** | `crates/cortex-drift-bridge/src/intents/resolver.rs` | 1-159 |
| **Link translator (5 constructors)** | `crates/cortex-drift-bridge/src/link_translation/translator.rs` | 1-162 |
| **NAPI functions (20 bridge functions)** | `crates/cortex-drift-bridge/src/napi/functions.rs` | 1-313 |
| **MCP grounding check tool** | `crates/cortex-drift-bridge/src/tools/drift_grounding_check.rs` | 1-72 |
| **Causal edge builder** | `crates/cortex-drift-bridge/src/causal/edge_builder.rs` | 1-77 |
| **Causal narrative builder** | `crates/cortex-drift-bridge/src/causal/narrative_builder.rs` | 1-155 |
| **Spec correction events** | `crates/cortex-drift-bridge/src/specification/events.rs` | 1-319 |
| **Cross-DB ATTACH** | `crates/cortex-drift-bridge/src/query/cross_db.rs` | 1-74 |
| **ATTACH guard (RAII)** | `crates/cortex-drift-bridge/src/query/attach.rs` | 1-109 |
| **Data source enum (12 variants)** | `crates/cortex-drift-bridge/src/types/data_source.rs` | 1-69 |
| **Bridge runtime** | `crates/cortex-drift-bridge/src/lib.rs` | 1-188 |
| **drift.db v001 (file_metadata, functions)** | `crates/drift/drift-storage/src/migrations/v001_initial.rs` | 1-80 |
| **drift.db v002 (call_edges, boundaries)** | `crates/drift/drift-storage/src/migrations/v002_analysis.rs` | 1-71 |
| **drift.db v003 (pattern_confidence)** | `crates/drift/drift-storage/src/migrations/v003_patterns.rs` | 1-51 |
| **drift.db v004 (error_gaps, test_quality)** | `crates/drift/drift-storage/src/migrations/v004_graph.rs` | 1-91 |
| **drift.db v005 (coupling_metrics, constraints, dna_genes, secrets, crypto, owasp)** | `crates/drift/drift-storage/src/migrations/v005_structural.rs` | 1-245 |
| **drift.db v006 (violations, feedback)** | `crates/drift/drift-storage/src/migrations/v006_enforcement.rs` | 1-125 |
| **drift.db v007 (decisions, simulations)** | `crates/drift/drift-storage/src/migrations/v007_advanced.rs` | 1-95 |

---

## Verification Commands

After each phase, run:

```bash
# Bridge crate tests
cargo test -p cortex-drift-bridge -- --nocapture

# Bridge clippy
cargo clippy -p cortex-drift-bridge -- -D warnings

# Full bridge test suite (includes enterprise hardening)
cargo test -p cortex-drift-bridge --test '*' -- --nocapture

# Verify drift.db schema alignment (Phase A)
cargo test -p cortex-drift-bridge --test '*' -- drift_queries --nocapture
```
