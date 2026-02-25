# Drift → Cortex Correlation Audit

> **Date:** 2026-02-10
> **Scope:** Full pipeline from `drift.db` → `cortex-drift-bridge` → `cortex.db`
> **Verdict:** Architecture is sound and novel. **1 P0 blocker, 4 P1 gaps, 6 P2 opportunities.**

---

## Executive Summary

The cortex-drift-bridge is architecturally excellent — a genuine frontier feature that empirically grounds AI memory against static analysis evidence. The 10-evidence-type weighted scoring system, 6 trigger types, contradiction generation, causal edge creation, and 21-event mapping are all well-designed and internally consistent.

**However, the entire grounding slow-path (drift.db fallback queries) is dead code.** All 10 queries in `drift_queries.rs` reference phantom table names that don't exist in drift.db. This means grounding only works via pre-populated `MemoryForGrounding` fields — the automatic evidence collection from drift.db never fires. Additionally, 12 of 39 drift.db tables produce data that is never correlated into Cortex.

---

## Finding #1 (P0): ALL 10 drift_queries.rs Queries Target Phantom Tables

**Severity:** P0 — The entire drift.db fallback evidence collection path is dead code.

### What the bridge queries expect vs what drift.db actually has:

| # | Evidence Type | Bridge Query Table | Bridge Query Column | Actual drift.db Table | Actual Column | Status |
|---|---|---|---|---|---|---|
| 1 | PatternConfidence | `drift_patterns` | `confidence` | `pattern_confidence` | `posterior_mean` | **WRONG TABLE + COLUMN** |
| 2 | PatternOccurrence | `drift_patterns` | `occurrence_rate` | `pattern_confidence` | *(no such column)* | **WRONG TABLE, NO COLUMN** |
| 3 | FalsePositiveRate | `drift_violation_feedback` | `fp_rate` | `feedback` | *(no fp_rate column)* | **WRONG TABLE + COLUMN** |
| 4 | ConstraintVerification | `drift_constraints` | `verified` | `constraint_verifications` | `passed` | **WRONG TABLE + COLUMN** |
| 5 | CouplingMetric | `drift_coupling` | `instability` | `coupling_metrics` | `instability` | **WRONG TABLE** (column correct) |
| 6 | DnaHealth | `drift_dna` | `health_score` | `dna_genes` | `confidence` / `consistency` | **WRONG TABLE + COLUMN** |
| 7 | TestCoverage | `drift_test_topology` | `coverage` | `test_coverage` / `test_quality` | `overall_score` | **WRONG TABLE + COLUMN** |
| 8 | ErrorHandlingGaps | `drift_error_handling` | `gap_count` | `error_gaps` | *(COUNT query needed)* | **WRONG TABLE + COLUMN** |
| 9 | DecisionEvidence | `drift_decisions` | `evidence_score` | `decisions` | `confidence` | **WRONG TABLE + COLUMN** |
| 10 | BoundaryData | `drift_boundaries` | `boundary_score` | `boundaries` | `confidence` | **WRONG TABLE + COLUMN** |

**Root cause:** `drift_queries.rs` was written against a speculative schema (prefixed with `drift_` and using idealized column names). The actual drift.db schema uses unprefixed table names with different column semantics.

**Impact:** When `MemoryForGrounding` fields are `None` and the system falls back to querying drift.db directly, every query returns `Err(SqliteError: no such table)`, which is caught and silently logged at `debug` level. The grounding loop then reports `InsufficientData` for those memories.

**Fix:** Rewrite all 10 queries in `drift_queries.rs` to match the real drift.db schema. Corrected queries:

```
1. PatternConfidence:  SELECT posterior_mean FROM pattern_confidence WHERE pattern_id = ?1
2. PatternOccurrence:  SELECT COUNT(DISTINCT file) * 1.0 / (SELECT COUNT(DISTINCT file) FROM detections) FROM detections WHERE pattern_id = ?1
3. FalsePositiveRate:  SELECT COALESCE(SUM(CASE WHEN action='dismiss' THEN 1 ELSE 0 END)*1.0/NULLIF(COUNT(*),0), 0.0) FROM feedback WHERE pattern_id = ?1
4. ConstraintVerified:  SELECT passed FROM constraint_verifications WHERE constraint_id = ?1 ORDER BY verified_at DESC LIMIT 1
5. CouplingMetric:  SELECT instability FROM coupling_metrics WHERE module = ?1
6. DnaHealth:  SELECT AVG(confidence * consistency) FROM dna_genes  (global aggregate — no project column exists)
7. TestCoverage:  SELECT overall_score FROM test_quality WHERE function_id = ?1
8. ErrorHandlingGaps:  SELECT COUNT(*) FROM error_gaps WHERE file LIKE ?1 || '%'
9. DecisionEvidence:  SELECT confidence FROM decisions WHERE id = CAST(?1 AS INTEGER)  (NOTE: id is INTEGER AUTOINCREMENT, bridge passes string)
10. BoundaryData:  SELECT confidence FROM boundaries WHERE id = CAST(?1 AS INTEGER)  (NOTE: id is INTEGER AUTOINCREMENT, bridge passes string)
```

**Additional type mismatch:** The bridge's `EvidenceContext` uses `decision_id: Option<String>` and `boundary_id: Option<String>`, but the actual `decisions` and `boundaries` tables use `INTEGER PRIMARY KEY AUTOINCREMENT`. The corrected queries must CAST, or the `EvidenceContext` fields should be changed to `Option<i64>`.

**Effort:** ~2 hours. Straightforward SQL rewrites + update tests.

---

## Finding #2 (P1): 12 drift.db Tables Have Zero Cortex Correlation

The bridge maps 10 evidence types and 21 events, but drift.db has **39 tables**. The following 12 tables produce analysis data that is **never correlated into Cortex** — not via evidence collection, not via event mapping, and not via any other bridge path:

| # | drift.db Table | What It Contains | Potential Cortex Value |
|---|---|---|---|
| 1 | `taint_flows` | Source→sink data flow paths with CWE IDs | **Security memory** — "this function has unsanitized data flow to SQL sink" |
| 2 | `crypto_findings` | Cryptographic failures (weak algos, hardcoded keys) | **Security memory** — "this file uses MD5 for password hashing" |
| 3 | `secrets` | Hardcoded credentials with entropy scores | **Security memory** — "hardcoded API key detected in config.ts" |
| 4 | `owasp_findings` | Enriched security findings with CWE/OWASP mapping | **Security memory** — "SQL injection risk (CWE-89, OWASP A03)" |
| 5 | `env_variables` | Environment variable usage patterns | **Environment memory** — "12 env vars used without defaults" |
| 6 | `wrappers` | Detected wrapper functions | **Pattern memory** — "fetchWrapper wraps 3 HTTP primitives" |
| 7 | `contracts` | API endpoint contracts | **Tribal memory** — "POST /api/users expects {name, email}" |
| 8 | `contract_mismatches` | BE↔FE contract mismatches | **Feedback memory** — "frontend calls /api/user but backend has /api/users" |
| 9 | `constants` | Named constants and magic numbers | Low value for grounding |
| 10 | `coupling_cycles` | Detected strongly-connected components | **CodeSmell memory** — "circular dependency: A→B→C→A" |
| 11 | `dna_mutations` | Deviations from dominant coding conventions | **CodeSmell memory** — "camelCase in snake_case codebase" |
| 12 | `decomposition_decisions` | Module boundary adjustments | **DecisionContext memory** — already partially handled via `on_decomposition_adjusted` |

**Impact:** The bridge is leaving ~30% of Drift's analysis intelligence on the table. The most impactful gaps are **security findings** (taint, crypto, secrets, OWASP) — these are high-value signals that should absolutely ground Cortex memories.

**Recommendation:** Add 4 new evidence types (SecurityTaint, SecurityCrypto, SecuritySecrets, SecurityOwasp) or create new event mappings for these tables. Priority: taint_flows and owasp_findings first.

---

## Finding #3 (P1): Intent Resolver Maps 10 Intents But Doesn't Match Extension Intents

The `intents/extensions.rs` defines 10 code intents:
`add_feature`, `fix_bug`, `refactor`, `review_code`, `debug`, `understand_code`, `security_audit`, `performance_audit`, `test_coverage`, `documentation`

The `intents/resolver.rs` resolves 10 **different** intents:
`explain_pattern`, `explain_violation`, `explain_decision`, `suggest_fix`, `assess_risk`, `review_boundary`, `trace_dependency`, `check_convention`, `analyze_test_coverage`, `security_audit`

Only **1 of 10** (`security_audit`) overlaps. The other 9 extension intents all fall through to the default resolver (all 12 sources at depth 1), which defeats the purpose of intent-specific targeting.

**Fix:** Either align the resolver to the extension intents, or merge both sets into a unified 15-20 intent system.

---

## Finding #4 (P1): GroundingDataSource Enum (12 Sources) Not Wired to Evidence Collection

`types/data_source.rs` defines 12 `GroundingDataSource` variants: Patterns, Conventions, Constraints, Coupling, Dna, TestTopology, ErrorHandling, Decisions, Boundaries, Taint, CallGraph, Security.

But the evidence collection system only has **10 evidence types** and doesn't use `GroundingDataSource` at all. The `Taint`, `CallGraph`, and `Security` data sources are declared but have **zero evidence collectors** — there's no way to collect grounding evidence from taint_flows, call_edges, or security findings.

This means 3 of 12 declared data sources are phantom capabilities.

---

## Finding #5 (P1): Event Mapping Creates Memories But Doesn't Populate Evidence Fields

When `BridgeEventHandler` creates a Cortex memory from a Drift event (e.g., `on_pattern_approved` → `PatternRationale`), the created `BaseMemory` has:
- `linked_patterns` populated ✓
- `tags` populated ✓
- `confidence` set from mapping table ✓

But the `MemoryForGrounding` evidence fields (`pattern_confidence`, `occurrence_rate`, etc.) are **never pre-populated** during event handling. This means:

1. Memory is created with initial confidence from the mapping table
2. When grounding runs, `MemoryForGrounding` has all `None` fields
3. System falls back to drift.db queries (Finding #1 — all broken)
4. Result: `InsufficientData` for every memory

The only way grounding currently works is if an external caller manually constructs `MemoryForGrounding` with pre-populated fields. No production code path does this.

**Fix:** In `BridgeEventHandler::create_memory()`, query drift.db for the relevant evidence fields and attach them to the memory's tags or a side-channel that `MemoryForGrounding` can read during grounding.

---

## Finding #6 (P2): Contradiction Generation Is Dead Code + Not Linked to Causal Graph

**Two issues:**

1. `generate_contradiction()` in `contradiction.rs` is **never called** from the grounding loop. `loop_runner.rs` computes `generates_contradiction` as a boolean flag on `GroundingResult` (lines 109-110, 412-413) but never invokes `generate_contradiction()` to actually create the contradiction memory. The function is dead code.

2. Even if it were called, `generate_contradiction()` creates a Feedback memory with `supersedes: Some(original_memory_id)` but **never calls** `causal::edge_builder::add_grounding_edge()` to create a causal edge. The `add_grounding_edge()` function exists and is tested (in `enterprise_data_integrity_test.rs`) but is never wired into the contradiction path.

---

## Finding #7 (P2): 20 NAPI-Ready Functions + 6 MCP Tools Have Zero TS Exposure

(Previously documented in CORTEX-ACCESSIBILITY-HARDENING-TASKS.md)

The bridge's 20 NAPI functions in `napi/functions.rs` and 6 MCP tool handlers in `tools/` are fully functional Rust code, but:
- No TS wrapper calls them
- No MCP server exposes them
- No CLI command triggers them

The bridge is a complete, working engine with no ignition key.

---

## Finding #8 (P2): Cross-DB Query Infrastructure Unused in Production

`query/cross_db.rs` implements ATTACH/DETACH lifecycle with RAII guards for cross-database queries. `query/attach.rs` has a sanitized `AttachGuard`. These are well-engineered but **never called from any production code path**. The evidence collectors in `collector.rs` use direct `Connection` references passed as parameters, not the ATTACH mechanism.

The cross-db infrastructure was built for a future where the bridge needs to JOIN across drift.db and cortex.db tables. This is a valid architectural investment but currently unused.

---

## Finding #9 (P2): Grounding Scheduler Never Instantiated

`scheduler.rs` defines `GroundingScheduler` with `on_scan_complete()` that determines whether to run incremental or full grounding. But no production code instantiates it. The `on_scan_complete` event mapping says `triggers_grounding: true`, but the `BridgeEventHandler` doesn't actually call the scheduler — it just logs the event.

---

## Finding #10 (P2): 6 Drift Analysis Subsystems Referenced by Intents But Not Queryable

The intent system references these Drift subsystems as `relevant_sources`:
- `n_plus_one` — no table, no query
- `reachability` — table exists (`reachability_cache`) but no bridge query
- `impact` — table exists (`impact_scores`) but no bridge query
- `call_graph` — table exists (`call_edges`) but no bridge query
- `taint` — table exists (`taint_flows`) but no bridge query
- `security` — tables exist (secrets, crypto_findings, owasp_findings) but no bridge query

These are referenced in intent resolution but there's no actual data retrieval path.

---

## What's Working Well (No Changes Needed)

| Component | Status | Notes |
|---|---|---|
| **10 Evidence Types + Weights** | ✅ Sound | Well-calibrated default weights, proper weighted average |
| **Grounding Scorer** | ✅ Sound | Thresholds (0.7/0.4/0.2) are reasonable, contradiction logic correct |
| **21 Event Mappings** | ✅ Sound | Confidence values well-chosen, grounding triggers appropriate |
| **6 Trigger Types** | ✅ Sound | Good coverage of all grounding scenarios |
| **13 Groundability Classifications** | ✅ Sound | 6 full, 7 partial, rest not-groundable — correct taxonomy |
| **Link Translation** | ✅ Sound | 5 constructors, round-trip fidelity, proper error handling |
| **Contradiction Generation** | ✅ Sound | Creates Feedback memory with supersedes link |
| **Causal Edge Builder** | ✅ Sound | Supports/Contradicts based on score thresholds |
| **Unified Narrative** | ✅ Sound | Combines narrative + origins + effects |
| **Spec Correction Events** | ✅ Sound | Creates memory + causal edges per upstream module |
| **License Tiering** | ✅ Sound | Community/Pro/Enterprise gating on events |
| **Storage Layer** | ✅ Sound | Grounding history, snapshots, metrics, retention |
| **NaN/Infinity Guards** | ✅ Sound | All evidence collection checks `is_finite()` |
| **Batch Capping** | ✅ Sound | 500 memory cap with deferred overflow |

---

## Priority Fix Order

| Priority | Finding | Effort | Impact |
|---|---|---|---|
| **P0** | #1: Rewrite 10 drift_queries.rs to match real schema | 2h | Unblocks ALL automatic grounding |
| **P1** | #5: Pre-populate evidence fields during event handling | 4h | Makes grounding work end-to-end |
| **P1** | #2: Add event mappings for 8 high-value uncorrelated tables | 6h | +30% intelligence utilization |
| **P1** | #3: Align intent resolver with extension intents | 2h | Intent system actually works |
| **P1** | #4: Add evidence collectors for Taint/CallGraph/Security | 4h | 3 phantom data sources become real |
| **P2** | #6: Wire contradiction → causal graph | 1h | Causal completeness |
| **P2** | #7: TS exposure of 20 NAPI + 6 MCP functions | 8h | Users can access bridge |
| **P2** | #8: Wire cross-db ATTACH for complex queries | 2h | Enables JOIN-based evidence |
| **P2** | #9: Instantiate GroundingScheduler from runtime | 1h | Automatic grounding triggers |
| **P2** | #10: Add queries for 6 referenced subsystems | 4h | Intent resolution has data |

**Critical path:** Fix #1 (2h) → Fix #5 (4h) = **6 hours to working grounding pipeline.**

---

## Architectural Assessment

The cortex-drift-bridge is **genuinely novel**. No existing tool empirically grounds AI memory against static analysis evidence with weighted scoring, contradiction generation, and causal graph integration. The architecture is clean:

- **Separation of concerns:** Evidence types, collectors, scorer, loop runner, scheduler — each has a single responsibility
- **Dual-path evidence:** Pre-populated fields (fast) + drift.db queries (comprehensive) — correct design, just needs the queries fixed
- **D6 compliance:** Bridge never writes to drift.db — enforced at query level
- **Degraded mode:** Works without cortex.db, works without drift.db (reduced capability)
- **Observability:** Grounding snapshots, history, metrics all persisted

The 10 findings above are **wiring issues**, not architectural flaws. The engine is built correctly — it just needs its fuel lines connected.

---

## Appendix: Complete drift.db Table Inventory (39 Tables)

### Correlated into Cortex (via evidence or events): 10/39
- `pattern_confidence` → EvidenceType::PatternConfidence (query broken)
- `detections` → EvidenceType::PatternOccurrence (query broken)
- `feedback` → EvidenceType::FalsePositiveRate (query broken)
- `constraint_verifications` → EvidenceType::ConstraintVerification (query broken)
- `coupling_metrics` → EvidenceType::CouplingMetric (query broken)
- `dna_genes` → EvidenceType::DnaHealth (query broken)
- `test_quality` → EvidenceType::TestCoverage (query broken)
- `error_gaps` → EvidenceType::ErrorHandlingGaps (query broken)
- `decisions` → EvidenceType::DecisionEvidence (query broken)
- `boundaries` → EvidenceType::BoundaryData (query broken)

### High-value, uncorrelated: 12/39
- `taint_flows`, `crypto_findings`, `secrets`, `owasp_findings` (security)
- `env_variables`, `wrappers`, `contracts`, `contract_mismatches` (structural)
- `coupling_cycles`, `dna_mutations`, `decomposition_decisions`, `constants`

### Infrastructure/low-value for grounding: 16/39
- `file_metadata`, `parse_cache`, `functions`, `scan_history` (Phase 1)
- `call_edges`, `data_access` (Phase 2)
- `outliers`, `conventions` (Phase 3)
- `reachability_cache`, `test_coverage`, `impact_scores` (Phase 4)
- `violations`, `gate_results`, `audit_snapshots`, `health_trends`, `policy_results`, `degradation_alerts` (Phase 6)
- `simulations`, `context_cache`, `migration_projects`, `migration_modules`, `migration_corrections` (Phase 7)

*Note: `constraints` table is used indirectly via `constraint_verifications` (correlated above). `test_coverage` (function-to-function mapping) is distinct from `test_quality` (scores) — only `test_quality` is queried by the bridge.*
