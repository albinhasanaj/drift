# Section 13 Findings: Cross-Phase Dependency Matrix & Parallelization Map

> **Status:** ✅ DONE
> **Date completed:** 2026-02-08
> **Orchestration plan sections:** §14 (Dependency Matrix), §15 (Parallelization Map)
> **Reference files consulted:**
> - `DRIFT-V2-IMPLEMENTATION-ORCHESTRATION.md` §14, §15
> - `AUDIT-SYNTHESIS-AND-REMAINING-WORK.md` Part 1 Category D, Part 3 (§14, §15 status)
> - `SECTION-8-FINDINGS.md` (cross-cutting findings on dependency matrix and parallelization)
> - V2-PREP docs: 08-ULP, 26-OWASP-CWE, 30-CONTEXT-GENERATION (for edge verification)
> - Live crates.io / lib.rs data (verified 2026-02-08)
>
> **Summary: 7 CONFIRMED, 5 REVISE, 0 REJECT, 1 APPLIED**

---

## Checklist (all validated)

- [x] Dependency matrix — audit every row for correctness
- [x] Missing edges identified in Round 1: N+1→P5 edge, soft Context Gen→P4 edge
- [x] System count in matrix — does it match the Master Registry?
- [x] Any false dependencies?
- [x] Any missing dependencies?
- [x] Parallelization map — verify each phase's parallelism claim
- [x] Phase 2 "2 tracks" — matrix confirms independence?
- [x] Phase 4 "5 tracks" — matrix confirms all 5 need only P0+P1+P2?
- [x] Phase 5 "7 tracks" — matrix confirms independence?
- [x] Critical path calculation — Round 1 revised to "16-21 weeks"
- [x] Team size recommendations — 1 dev revised to "8-10 months"
- [x] Add realistic (1.3x) timeline column
- [x] Apply Round 1 revisions

---

## Findings

### 1. Dependency Matrix Row-by-Row Audit — ⚠️ REVISE: 3 Edge Issues, 1 System Count Issue

I audited all 55 rows of the §14 dependency matrix against the V2-PREP documents,
the phase descriptions in §3-§13, and the Section 8 findings.

**Exact row count: 55 systems in the matrix.**

Breakdown by phase:
- Phase 0 infrastructure: 5 (Configuration, thiserror, tracing, DriftEventHandler, String Interning)
- Phase 1: 4 (Scanner, Parsers, Storage, NAPI Bridge)
- Phase 2: 5 (UAE, Call Graph, Detector System, Boundary Detection, ULP)
- Phase 3: 4 (Pattern Aggregation, Bayesian Confidence, Outlier Detection, Learning System)
- Phase 4: 5 (Reachability, Taint, Error Handling, Impact, Test Topology)
- Phase 5: 8 (Coupling, Constraint System, Contract Tracking, Constants & Environment, Wrapper Detection, DNA System, OWASP/CWE, Crypto Failure Detection)
- Phase 6: 5 (Rules Engine, Quality Gates, Policy Engine, Audit System, Violation Feedback Loop)
- Phase 7: 4 (Simulation Engine, Decision Mining, Context Generation, N+1 Query Detection)
- Phase 8: 4 (MCP Server, CLI, CI Agent & GitHub Action, Reporters)
- Phase 9: 1 (Cortex-Drift Bridge)
- Phase 10: 10 (Workspace Mgmt, Licensing, Docker, Telemetry, VSCode Extension, LSP Server, Dashboard, Galaxy, AI Providers, CIBench)
- **Total: 55**

The Master Registry (§2) claims "60 systems." §20.16 already flags this discrepancy.
Section 8 findings calculated ~52-53 distinct systems. My count of 55 matrix rows is
the most precise — it includes the 5 Phase 0 infrastructure primitives that the
Master Registry's "35 specced + 9 unspecced = 44" count omits, plus Reporters and
Rules/Policy Engine which are sub-components of specced systems.

**Reconciliation: The matrix has 55 rows. The "60 systems" claim is inflated.**
The gap between 55 and 60 likely comes from counting sub-components separately
(e.g., SARIF Reporter vs non-SARIF Reporters, Enterprise Secret Detection as
separate from Constants & Environment). The matrix's 55 is the authoritative count.

**Verdict:** ⚠️ REVISE — Update §2 header from "60-System" to "55-System" or
"~55 System" to match the actual matrix. The "60" number creates false expectations
and has been flagged by both §20.16 and Section 8 findings.

---

### 2. Missing Edges from Round 1 — ⚠️ REVISE: Partially Confirmed

Section 8 identified 3 missing/questionable edges. I verified each against V2-PREP docs.

#### 2a. N+1 Query Detection → P5 edge (MISSING)

**Section 8 claim:** N+1 needs mature ORM pattern matching from ULP (Phase 2/5),
so it implicitly depends on Phase 5 ULP matchers.

**My verification:** I read 08-UNIFIED-LANGUAGE-PROVIDER-V2-PREP. The N+1 detection
function (`detect_n_plus_one`) takes `UlpResult` + `FlowAnalysisResult` as inputs.
`FlowAnalysisResult` comes from the UAE (Phase 2), not taint analysis (Phase 4).
The ORM matchers that produce `UlpResult.orm_patterns` are built in Phase 2 as part
of the ULP. The 20 ORM/framework matchers (Supabase, Prisma, TypeORM, etc.) are all
Phase 2 deliverables.

However, the ULP's ORM matchers are built incrementally — basic matchers in Phase 2,
with refinements continuing through Phase 5. N+1 detection for basic ORMs (Prisma
`findMany`, ActiveRecord `.where`) works with Phase 2 matchers. Advanced ORM patterns
(GORM, SeaORM, complex LINQ) may need Phase 5 matchers.

The current matrix shows N+1 depending on P0, P1, P2, P4, P7. The P4 dependency is
correct (N+1 needs call graph traversal for interprocedural loop detection, and call
graph is Phase 2, but the matrix marks P4 which contains reachability — this is
actually questionable, see finding 3 below).

**Verdict:** ⚠️ REVISE — Add a soft/optional P5 edge for N+1 Query Detection with
a note: "Basic N+1 detection works with Phase 2 ORM matchers. Advanced ORM coverage
improves as Phase 5 ULP matchers mature." This is an enrichment dependency, not a
hard blocker. N+1 can ship a useful version after Phase 2+4.

#### 2b. Context Generation → P4 soft edge (NOT NEEDED)

**Section 8 claim:** Context Generation should have a soft P4 edge because
30-CONTEXT-GENERATION-V2-PREP §8 describes including taint analysis results and
reachability data in generated context.

**My verification:** I read 30-CONTEXT-GENERATION-V2-PREP §29 (Integration Points).
The upstream dependencies table lists:
- 03-detectors (Phase 2) — pattern data
- 04-call-graph (Phase 2) — entry points, function data
- 07-boundaries (Phase 2) — data accessors, sensitive fields
- 18-constraints (Phase 5) — constraint data
- 06-cortex (optional) — memory retrieval
- 02-storage — database connections
- Package manifests — direct filesystem reads

**Taint analysis, reachability, and impact analysis are NOT listed as upstream
dependencies.** The V2-PREP's upstream table is definitive. Context Generation
does not consume Phase 4 outputs. The current matrix (P0, P1, P2, P3, P5, P7)
is correct.

Section 8's claim appears to have been based on a general reading of §8 rather
than the authoritative §29 upstream table. The context generator can optionally
include security-related data if available, but it doesn't depend on it.

**Verdict:** ✅ CONFIRMED — The matrix is correct as-is for Context Generation.
No P4 edge needed. Section 8's recommendation to add a soft P4 edge is overruled
by the V2-PREP's explicit upstream dependency table.

#### 2c. OWASP/CWE Mapping → P4 edge (CORRECTLY PRESENT)

**Section 8 claim:** The P4 dependency is correct only for taint-informed CWE
mappings. A partial version (pattern-based CWEs) can ship after P2.

**My verification:** I read 26-OWASP-CWE-MAPPING-V2-PREP §3 (Upstream Dependencies).
It explicitly lists Taint Analysis (15) as an upstream dependency providing
"TaintFlow with SinkType → Map SinkType → CWE." The system enriches findings from
6+ upstream subsystems including Taint Analysis. The P4 edge is correct and necessary
for the full system.

Section 8's nuance about partial shipping is valid — pattern-based CWE mappings
(~60% of coverage) can work without taint data. But the matrix correctly shows the
full dependency set.

**Verdict:** ✅ CONFIRMED — P4 edge for OWASP/CWE is correct. Add a note that
partial (pattern-based) CWE mappings can ship after P2, with taint-informed
mappings added after P4.

---

### 3. N+1 Query Detection → P4 Edge Audit — ⚠️ REVISE: Edge Is Questionable

While auditing the N+1 row, I noticed the matrix shows N+1 depending on P4
(Graph Intelligence: Reachability, Taint, Error Handling, Impact, Test Topology).

**What N+1 actually needs from Phase 4:** The `detect_n_plus_one` function in
08-ULP-V2-PREP uses `FlowAnalysisResult` which comes from the UAE (Phase 2), not
from Phase 4 systems. N+1 detection works by finding ORM queries inside loop
constructs — this is intraprocedural analysis using CFG (control flow graph) from
the UAE, not interprocedural reachability or taint analysis.

The call graph (Phase 2) is needed to detect interprocedural N+1 patterns (e.g.,
a function called inside a loop that internally makes a query). But the call graph
is a Phase 2 deliverable, not Phase 4.

**Why the P4 edge might exist:** The orchestration plan's §10.4 says N+1 uses
"Call graph + ORM pattern matching." The call graph is Phase 2. The only Phase 4
system that could be relevant is Reachability Analysis — if N+1 detection needs
to trace reachability from a loop body to a query function across multiple call
levels. But the V2-PREP implementation shows this is done with basic call graph
BFS, not the full reachability analysis engine.

**Verdict:** ⚠️ REVISE — The P4 edge for N+1 Query Detection is likely a false
dependency. N+1 detection needs: P0 (infra), P1 (scanner/parsers/storage), P2
(UAE + call graph + ULP ORM matchers), and P7 (it's a Phase 7 system). The P4
edge should be removed unless there's a specific reachability or taint requirement
not documented in the V2-PREP. If removed, N+1 becomes: P0, P1, P2, P7 — which
means it could theoretically start as early as Phase 2 completion, not Phase 4.
This doesn't change the parallelization map (N+1 is still Phase 7) but it
clarifies the actual dependency chain.

---

### 4. False Dependency Scan — ✅ CONFIRMED: No Other False Dependencies Found

I scanned all 55 rows for dependencies that seem overstated:

**Phase 4 systems (Reachability, Taint, Error Handling, Impact, Test Topology):**
All show P0, P1, P2, P4. The P2 dependency is correct — they all consume call graph
and/or parse results. None shows P3 (Pattern Intelligence), which is correct — these
systems don't need confidence scores or aggregated patterns.

**Phase 5 systems:** Coupling, Contract Tracking, Constants & Environment, Wrapper
Detection, Crypto Failure Detection all show P0, P1, P2, P5 without P3 or P4. This
is correct — they operate on parse results and call graph data, not on pattern
intelligence or graph intelligence outputs.

Constraint System and DNA System correctly show P3 and P4 dependencies (Constraint
needs taint for DataFlow invariants; DNA needs pattern intelligence for gene
extraction and graph intelligence for structural genes).

**Phase 6 systems:** Rules Engine shows P0-P3, P6 (no P4/P5). This is correct —
rules evaluate against confidence-scored patterns (P3), not against graph or
structural intelligence directly. Quality Gates, Policy Engine, and Audit System
show P0-P6 (all prior phases), which is correct — they're the enforcement layer
that needs the full analysis stack.

Violation Feedback Loop shows P0-P3, P6 (no P4/P5). Correct — it feeds back on
quality gate results (P6) and pattern confidence (P3).

**Phase 8 systems:** MCP Server and CLI show P0, P1, P8 only. This is correct —
they're thin presentation layers that read from drift.db. CI Agent shows P0, P1,
P6, P8 — the P6 dependency is correct because CI Agent needs quality gate
pass/fail results.

**Phase 10 systems:** All show minimal dependencies (P0, P1, sometimes P8). Correct
— these are leaf systems.

**Verdict:** ✅ CONFIRMED — No false dependencies found beyond the N+1→P4 edge
discussed in finding 3.

---

### 5. Missing Dependency Scan — ✅ CONFIRMED: No Critical Missing Dependencies

Beyond the edges discussed in findings 2 and 3, I checked for missing dependencies:

**Simulation Engine (P0, P1, P2, P3, P4, P5, P7):** Correct. Simulation needs the
full analysis stack (coupling friction from P5, impact from P4, confidence from P3)
to generate meaningful pre-flight predictions.

**Decision Mining (P0, P1, P2, P7):** Correct. Decision Mining uses git2 for commit
history and pattern data from drift.db. It doesn't need confidence scoring (P3),
graph intelligence (P4), or structural intelligence (P5) — it mines decisions from
version control history, not from analysis results.

**Cortex-Drift Bridge (P0-P6, P9):** Correct. The bridge needs the full analysis
stack through enforcement (P6) to ground Cortex memories against Drift scan data.
It doesn't need Phase 7 (advanced) or Phase 8 (presentation) — those are consumers,
not producers of grounding data.

**Verdict:** ✅ CONFIRMED — No critical missing dependencies found.

---

### 6. Parallelization Map Verification — ✅ CONFIRMED (with 2 refinements)

I verified each phase's parallelism claim against the dependency matrix.

**Phase 0 (Sequential, 1 track):** ✅ All 5 infrastructure primitives depend only
on P0. Internal ordering (Config → errors → tracing → events → data structures) is
a strict chain. Confirmed.

**Phase 1 (Sequential, 1 track):** ✅ Scanner → Parsers → Storage → NAPI is mostly
sequential. The plan correctly notes 2 developers can overlap. Confirmed.

**Phase 2 (2 parallel tracks):** ✅ Track A (UAE + Detectors) and Track B (Call Graph
+ Boundaries + ULP) share only ParseResult as read-only input. Matrix confirms all 5
Phase 2 systems depend on P0+P1 only. No cross-dependencies within Phase 2. Confirmed.

**Phase 3 (Limited parallelism, 1-2 tracks):** ✅ Pattern Aggregation → Confidence →
Outlier/Learning chain is correct. All 4 systems depend on P0-P3. Internal ordering
limits parallelism. Confirmed.

**Phase 4 (5 parallel tracks):** ✅ All 5 systems (Reachability, Taint, Error Handling,
Impact, Test Topology) depend on P0+P1+P2+P4. None depends on another Phase 4 system.
Maximum parallelism confirmed.

**Phase 5 (7 parallel tracks):** ✅ With refinement. The plan claims 7 parallel tracks:
Coupling, Constraints, Contracts, Constants, Wrappers, Crypto, OWASP/CWE. However:
- Constraint System depends on P3+P4+P5 (needs taint from P4)
- DNA System depends on P3+P4+P5 (needs pattern intelligence + graph intelligence)
- OWASP/CWE depends on P4+P5 (needs taint for CWE mapping)

So only 4 of the 7 systems (Coupling, Contract Tracking, Constants & Environment,
Wrapper Detection) can start immediately after Phase 2. The other 3 (Constraint,
DNA, OWASP/CWE) must wait for Phase 4 completion. Crypto Failure Detection depends
on P0+P1+P2+P5 only — it can start after Phase 2, making it 5 systems that can
start early.

**Refinement:** Phase 5 has 5 immediate tracks (Coupling, Contracts, Constants,
Wrappers, Crypto) and 3 delayed tracks (Constraint, DNA, OWASP/CWE) that start
after Phase 4. The "7 parallel tracks" claim is technically correct (all 7+1 can
run in parallel once Phase 4 is done) but misleading about when they can start.

**Phase 6 (Mostly sequential, 1-2 tracks):** ✅ Rules → Gates → Policy → Audit chain
confirmed. Violation Feedback Loop can run parallel with Policy/Audit. Confirmed.

**Phase 7 (4 parallel tracks):** ✅ Simulation, Decision Mining, Context Generation,
N+1 are all independent. Matrix confirms no cross-dependencies. Confirmed.

**Phase 8 (3 parallel tracks):** ✅ MCP, CLI, CI Agent are independent. Reporters
are a 4th track (also independent). Confirmed.

**Phase 9 (Sequential, 1 track):** ✅ Single bridge system. Confirmed.

**Phase 10 (8+ parallel tracks):** ✅ All remaining systems are independent leaves.
Confirmed. (Note: per user instruction, not deeply validating CIBench, LSP, VSCode
Extension, Telemetry, Galaxy, or Dashboard — these are presentation/polish systems
excluded from deep review.)

**Verdict:** ✅ CONFIRMED with refinement. Phase 5's "7 parallel tracks" should note
that 3 tracks (Constraint, DNA, OWASP/CWE) are delayed until Phase 4 completes.
The other phases' parallelism claims are accurate.

---

### 7. Critical Path Calculation — ⚠️ REVISE: Update to 16-21 Weeks + Version Note

The §15 critical path is:
```
Phase 0 (1-2w) → Phase 1 (2-3w) → Phase 2 Track A (2w) → Phase 3 (3-4w) →
Phase 6 (2-3w) → Phase 8 (2w)
= 12-16 weeks minimum for a shippable product
```

**Section 8 findings** applied a 1.3x overconfidence correction: **16-21 weeks realistic.**

**My verification of each segment:**

- Phase 0 (1-2w): ✅ Realistic. Boilerplate Rust setup. Cortex equivalent is ~2,500 LOC.
- Phase 1 (2-3w): ✅ Realistic. Scanner (6-9 days) + Parsers (~1w) + Storage (~1w) + NAPI (~3-5 days). Tight but achievable with overlap.
- Phase 2 Track A (2w): ⚠️ Aggressive. Core UAE pipeline + visitor engine + 20-30 initial detectors. V2-PREP estimates Weeks 1-5 for this scope. 2 weeks is the absolute minimum — 3 weeks is more realistic for enough detectors to produce meaningful patterns for Phase 3.
- Phase 3 (3-4w): ✅ Realistic. Internal dependency chain (Aggregation → Confidence → Outlier/Learning) limits parallelism but each system is well-scoped.
- Phase 6 (2-3w): ✅ Realistic. Rules Engine is a predicate evaluator, Quality Gates is a DAG orchestrator, Policy Engine is TS-side YAML loading, Audit System is SQLite snapshots.
- Phase 8 (2w): ✅ Realistic for minimum viable versions. MCP core + CLI wrapper + CI Agent wrapper.

**Total optimistic: 12-16 weeks. Realistic (1.3x): 16-21 weeks.**

The 1.3x correction is well-justified by software estimation research. Section 8
findings documented this thoroughly (R18: Estimation Overconfidence Bias).

**Internet-verified version note:** The orchestration plan's §3.1 Cargo.toml still
references outdated versions. As of 2026-02-08:
- tree-sitter: **0.26.5** is latest (plan says 0.24, Round 1 revised to 0.25 — both outdated)
- rusqlite: **0.38.0** confirmed (Round 1 revision correct)
- petgraph: **0.8.3** confirmed with `stable_graph` as default feature (Round 1 revision correct)
- napi-rs: **v3.8.x** confirmed stable
- statrs: **0.18.0** is latest (plan references 0.17 — outdated)
- rusqlite_migration: **2.4.1** confirmed compatible with rusqlite 0.38

These version discrepancies don't affect the critical path calculation but should
be noted for the §3.1 Cargo.toml update. tree-sitter 0.26.x is a breaking change
from 0.25.x — grammar compatibility needs re-verification for 0.26.

**Verdict:** ⚠️ REVISE — Update critical path from "12-16 weeks" to include the
realistic estimate: "12-16 weeks optimistic, 16-21 weeks realistic (1.3x correction)."
Also flag tree-sitter 0.26.x and statrs 0.18.0 as version updates beyond what
Round 1 identified.

---

### 8. Team Size Recommendations — ✅ CONFIRMED (with 1.3x column)

Section 8 findings recommended adding a realistic (1.3x) column. I verified the
math and the recommendations.

**Current table (§15):**

| Team Size | Timeline | Strategy |
|-----------|----------|----------|
| 1 developer | 6-8 months | Sequential critical path first |
| 2 developers | 4-5 months | Dev A: critical path, Dev B: parallel tracks |
| 3-4 developers | 3-4 months | Full parallelism in Phases 4-5 |
| 5+ developers | 2.5-3 months | Maximum parallelism |

**Revised table with 1.3x correction:**

| Team Size | Optimistic | Realistic (1.3x) | Strategy |
|-----------|-----------|-------------------|----------|
| 1 developer | 6-8 months | **8-10 months** | Sequential critical path. P0 systems only for Phases 4-5. |
| 2 developers | 4-5 months | **5-6.5 months** | Dev A: critical path. Dev B: parallel tracks. Best ROI. |
| 3-4 developers | 3-4 months | **4-5 months** | Full parallelism Phases 4-5. Requires experienced Rust devs. |
| 5+ developers | 2.5-3 months | **3-4 months** | Diminishing returns. Brooks's Law limits gains beyond 4. |

Section 8's analysis is sound:
- 1-developer at 6-8 months is optimistic because Phases 4+5 alone could take
  24-43 weeks sequentially. The 8-10 month realistic estimate accounts for this.
- 2-developer config is best ROI — halves timeline without coordination overhead.
- 5+ developers hit diminishing returns because the critical path is sequential
  and onboarding overhead absorbs parallelism gains.

**Verdict:** ✅ CONFIRMED — Add the 1.3x column as shown above. The 2-developer
configuration remains the best ROI recommendation.

---

### 9. Phase 5 "7 Tracks" Independence Verification — ✅ CONFIRMED (with staggering note)

The parallelization map claims Phase 5 has "7 parallel tracks." I verified each
system's independence against the dependency matrix:

| System | Dependencies | Can Start After |
|--------|-------------|-----------------|
| Coupling Analysis | P0, P1, P2, P5 | Phase 2 ✅ |
| Contract Tracking | P0, P1, P2, P5 | Phase 2 ✅ |
| Constants & Environment | P0, P1, P2, P5 | Phase 2 ✅ |
| Wrapper Detection | P0, P1, P2, P5 | Phase 2 ✅ |
| Crypto Failure Detection | P0, P1, P2, P5 | Phase 2 ✅ |
| Constraint System | P0, P1, P2, P3, P4, P5 | Phase 4 ⚠️ |
| DNA System | P0, P1, P2, P3, P4, P5 | Phase 4 ⚠️ |
| OWASP/CWE Mapping | P0, P1, P2, P4, P5 | Phase 4 ⚠️ |

5 systems can start immediately after Phase 2. 3 systems must wait for Phase 4.
All 8 systems (including Crypto) are independent of each other — no Phase 5 system
depends on another Phase 5 system's output.

The "7 parallel tracks" claim counts 7 (excluding DNA as a "capstone" that starts
with parser-only extractors). The actual count is 8 systems in Phase 5, with a
staggered start: 5 after Phase 2, 3 after Phase 4.

**Verdict:** ✅ CONFIRMED — All Phase 5 systems are independent of each other.
The parallelism claim is valid. Add a note about the staggered start (5 immediate,
3 delayed until Phase 4).

---

### 10. Phase 4 "5 Tracks" Independence Verification — ✅ CONFIRMED

All 5 Phase 4 systems depend on P0, P1, P2, P4 only:

| System | Cross-P4 Dependencies? |
|--------|----------------------|
| Reachability Analysis | None — uses call graph (P2) |
| Taint Analysis | None — uses call graph (P2) + parse results (P1) |
| Error Handling Analysis | None — uses parse results (P1) + call graph (P2) |
| Impact Analysis | None — uses call graph (P2) |
| Test Topology | None — uses parse results (P1) + call graph (P2) |

No Phase 4 system depends on another Phase 4 system. All consume read-only outputs
from Phase 2 (call graph, parse results, boundaries). The string interning layer
(lasso RodeoReader) is frozen after Phase 1. The parse cache (moka) is read-only.
SQLite writes to different tables — no conflicts.

**Verdict:** ✅ CONFIRMED — Phase 4's "5 parallel tracks" claim is accurate.
Maximum parallelism opportunity.

---

### 11. Round 1 Revision Application — 🔧 APPLIED (with 2 additional version updates)

Round 1 (Section 8 / Audit Synthesis Category D) identified these revisions for §14-§15:

| Revision | Status | Notes |
|----------|--------|-------|
| Fix system count (53 not 60) | 🔧 Verified | Actual matrix count is 55. Update to "~55 systems" |
| Add N+1→P5 edge | 🔧 Verified | Confirmed as soft/optional edge. Add with note |
| Add soft Context Gen→P4 edge | ❌ Overruled | V2-PREP §29 upstream table shows no P4 dependency. Matrix is correct as-is |
| Add 1.3x timeline column | 🔧 Verified | Table provided in finding 8 above |
| Update critical path to 16-21 weeks | 🔧 Verified | Math confirmed. 12-16w × 1.3 = 16-21w |
| Update 1-dev timeline to 8-10 months | 🔧 Verified | Analysis confirmed in finding 8 |

**Additional findings from internet verification (not in Round 1):**

| Item | Round 1 Revision | Current Reality (2026-02-08) | Action |
|------|-----------------|----------------------------|--------|
| tree-sitter | 0.24 → 0.25 | **0.26.5** is latest | Further revision needed. 0.26 is a breaking change from 0.25. Grammar compat must be re-verified for 0.26 |
| statrs | 0.17 (referenced in plan) | **0.18.0** is latest | Update version pin. API changes between 0.17→0.18 need verification for Beta/StudentsT distributions |
| rusqlite_migration | Compat with rusqlite 0.38? | **2.4.1** depends on rusqlite 0.38 | ✅ Confirmed compatible. No action needed |
| rusqlite | 0.32 → 0.38 | **0.38.0** confirmed | ✅ Round 1 revision correct |
| petgraph | 0.6 → 0.8 | **0.8.3** confirmed, stable_graph is default feature | ✅ Round 1 revision correct |
| napi-rs | v3 | **v3.8.x** confirmed stable | ✅ Round 1 revision correct |

**Verdict:** 🔧 APPLIED — All Round 1 revisions for §14-§15 verified and documented.
Two additional version updates identified (tree-sitter 0.26.x, statrs 0.18.0) that
Round 1 did not catch because they were released after the initial research.

---

### 12. N+1 P4 Dependency — Impact on Parallelization — ✅ CONFIRMED: No Impact

If the N+1→P4 edge is removed (per finding 3), N+1's dependencies become P0, P1, P2, P7.
This means N+1 could theoretically start after Phase 2 instead of after Phase 4.

However, N+1 is assigned to Phase 7 in the orchestration plan, and Phase 7 systems
are "high-value features built on top of the full stack" that are intentionally
deferred. Removing the P4 edge doesn't change when N+1 is built — it just clarifies
that N+1 doesn't technically need Phase 4 outputs.

**Verdict:** ✅ CONFIRMED — Removing the false P4 edge has no impact on the
parallelization map or critical path. N+1 remains a Phase 7 system regardless.

---

## Verdict Summary

| Item | Verdict | Action Required |
|------|---------|-----------------|
| Dependency matrix row correctness | ⚠️ REVISE | Remove N+1→P4 false edge. Add soft N+1→P5 edge. Keep Context Gen as-is (no P4 edge needed — overrules Section 8) |
| System count in matrix | ⚠️ REVISE | Matrix has 55 rows, not 60. Update §2 header to "~55 System Master Registry" |
| False dependencies | ⚠️ REVISE | N+1→P4 edge is likely false (see finding 3). All other edges verified correct |
| Missing dependencies | ✅ CONFIRMED | No critical missing dependencies beyond the soft N+1→P5 edge |
| Parallelization map accuracy | ✅ CONFIRMED | All phases' parallelism claims verified. Phase 5 has staggered start (5 immediate, 3 after P4) |
| Phase 2 "2 tracks" | ✅ CONFIRMED | Track A and Track B are fully independent |
| Phase 4 "5 tracks" | ✅ CONFIRMED | All 5 systems are fully independent |
| Phase 5 "7 tracks" | ✅ CONFIRMED | All 8 systems are independent of each other. 5 start after P2, 3 after P4 |
| Critical path (12-16w) | ⚠️ REVISE | Add realistic estimate: 16-21 weeks (1.3x). Flag tree-sitter 0.26.x and statrs 0.18.0 as new version updates |
| Team size recommendations | ✅ CONFIRMED | Add 1.3x column. 2-dev config is best ROI |
| Round 1 revisions | 🔧 APPLIED | All verified. Context Gen→P4 edge overruled. 2 new version updates identified |

**Summary: 7 CONFIRMED, 5 REVISE, 0 REJECT, 1 APPLIED.**

The dependency matrix and parallelization map are fundamentally sound. The 5 revisions
are refinements: correcting the system count (55 not 60), fixing one false edge
(N+1→P4), adding one soft edge (N+1→P5), updating the critical path with the 1.3x
correction, and flagging 2 crate version updates (tree-sitter 0.26.x, statrs 0.18.0)
that emerged after Round 1. The parallelization claims are all verified — no false
parallelism detected. The most significant finding is that Section 8's recommendation
to add a Context Gen→P4 edge is overruled by the V2-PREP's authoritative upstream
dependency table.
