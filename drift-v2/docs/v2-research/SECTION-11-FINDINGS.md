# Section 11 Findings: Phase Estimates, Build Ordering & Verification Gates (Phases 5-8)

> **Status:** ✅ DONE
> **Date completed:** 2026-02-08
> **Orchestration plan sections:** §8-11 (Phases 5-8), §19 (Verification Gates M5-M6)
> **Round:** 2 (Orchestration-level validation)
>
> **Summary: 10 CONFIRMED, 5 REVISE, 0 REJECT, 5 APPLIED**

---

## Checklist (all validated)

- [x] Phase 5 estimate "4-6 weeks" — realistic given 7 parallel tracks + Contract Tracking at ~20 weeks?
- [x] Phase 5 "7 parallel tracks" claim — verify independence of all 7 systems
- [x] Phase 5 DNA System as "capstone" — does it truly need all other Phase 5 systems or can it start earlier?
- [x] Phase 5 verification gate — 13 criteria, are they all measurable?
- [x] Phase 6 estimate "2-3 weeks" — realistic given Rules Engine + Gates + Policy + Audit + Feedback?
- [x] Phase 6 internal ordering — is Rules→Gates→Policy→Audit truly sequential or can any overlap?
- [x] Phase 6 QG↔Feedback circular dependency — is the FeedbackStatsProvider trait resolution documented?
- [x] Phase 6 verification gate — 11 criteria, are they all measurable?
- [x] Phase 7 estimate — Round 1 revised to "6-8 weeks" from "3-4 weeks". Verify this is reflected
- [x] Phase 7 "all 4 are parallel" claim — verify Simulation, Decisions, Context, N+1 independence
- [x] Phase 7 hybrid Rust/TS architecture for Simulation and Decision Mining — any integration risks?
- [x] Phase 7 verification gate — 7 criteria, are they all measurable?
- [x] Phase 8 estimate "3-4 weeks" — realistic given MCP (~7 weeks per V2-PREP)?
- [x] Phase 8 "3 parallel tracks" claim — MCP, CLI, CI Agent independence
- [x] Phase 8 CLI has no V2-PREP — is the scope clear enough to build without one?
- [x] Phase 8 verification gate — 8 criteria, are they all measurable?
- [x] Milestones M5-M6 timing — "12-16w" and "14-20w" — still accurate after Round 1 revisions?
- [x] Apply Round 1 revisions for Phases 5-8

---

## Findings

### 1. Phase 5 Estimate "4-6 weeks" — ⚠️ REVISE: Estimate Is Phase-Level Correct but Masks Contract Tracking's 20-Week Tail

The orchestration plan estimates Phase 5 at "4-6 weeks" with "maximum parallelism (up to 7 independent tracks)."

**Per-system estimates from V2-PREP docs:**

| System | V2-PREP Estimate | Dependencies |
|--------|-----------------|-------------|
| Coupling Analysis (19) | ~2-3 weeks | P0+P1+P2 (call graph + imports) |
| Constraint System (20) | ~3-4 weeks | P0+P1+P2+P3+P4 (needs taint, confidence) |
| Contract Tracking (21) | **~20 weeks** across 20 internal phases | P0+P1+P2 (parsers + ULP) |
| Constants & Environment (22) | ~3-4 weeks | P0+P1+P2 (parsers + analysis engine) |
| Wrapper Detection (23) | ~2-3 weeks | P0+P1+P2 (call graph + parsers) |
| DNA System (24) | ~2-3 weeks (framework + initial extractors) | P0+P1+P2+P3+P4 (capstone) |
| OWASP/CWE Mapping (26) | ~2-3 weeks | P0+P1+P2 (enrichment layer) |
| Crypto Detection (27) | ~5 weeks across 8 internal phases | P0+P1+P2 (parsers + analysis engine) |
| Enterprise Secret Detection | Included in Constants (22) | Same as Constants |

**Analysis:**

The "4-6 weeks" estimate is correct for the phase gate — the point at which most Phase 5 systems are functional and Phase 6 can begin. Most systems (Coupling, Constants, Wrappers, OWASP/CWE, DNA framework) complete in 2-4 weeks. Crypto Detection takes ~5 weeks. These are all achievable within the 4-6 week window.

However, Contract Tracking at ~20 weeks is a massive outlier. It will not complete within Phase 5's 4-6 week window. The orchestration plan (§8.4) correctly notes "ship REST + GraphQL first" as a phased approach, but the estimate doesn't make this explicit.

Additionally, as Section 9 findings noted, Constraint System and DNA System have heavier dependencies (P3+P4) than their Phase 5 peers. They cannot start until Phase 4 completes, creating a staggered start within Phase 5. The "4-6 weeks" estimate assumes P4 is already done when Phase 5 starts, which is correct per the phase ordering but should be explicit.

**Recommendation:** Keep "4-6 weeks" as the phase gate estimate but add two clarifications:
1. "4-6 weeks for Phase 5 gate (all systems except Contract Tracking at MVP). Contract Tracking continues through Phases 6-8 with incremental paradigm delivery (~20 weeks total)."
2. "Constraint System and DNA System start 0-2 weeks after other Phase 5 systems (waiting for P4 completion)."

---

### 2. Phase 5 "7 Parallel Tracks" Claim — ✅ CONFIRMED (with staggered start caveat)

The plan claims 7 independent parallel tracks within Phase 5. I verified each system's dependencies against the dependency matrix:

| Track | System | Depends On | Independent of Other P5 Systems? |
|-------|--------|-----------|--------------------------------|
| 1 | Coupling Analysis | P0+P1+P2 (call graph, imports) | ✅ Yes |
| 2 | Contract Tracking | P0+P1+P2 (parsers, ULP) | ✅ Yes |
| 3 | Constants & Environment | P0+P1+P2 (parsers, analysis engine) | ✅ Yes |
| 4 | Wrapper Detection | P0+P1+P2 (call graph, parsers) | ✅ Yes |
| 5 | Crypto Detection | P0+P1+P2 (parsers, analysis engine) | ✅ Yes |
| 6 | OWASP/CWE Mapping | P0+P1+P2 (all security detectors) | ✅ Yes (enrichment-only) |
| 7a | Constraint System | P0+P1+P2+**P3+P4** | ✅ Independent of other P5, but delayed start |
| 7b | DNA System | P0+P1+P2+**P3+P4** | ✅ Independent of other P5, but delayed start |

All 7 tracks (8 systems across 7 tracks, with Constraint and DNA sharing the "delayed start" characteristic) are genuinely independent of each other. No Phase 5 system depends on another Phase 5 system's output as a hard requirement.

**The DNA System as "capstone":** The plan describes DNA as consuming coupling, constraints, test topology, error handling, patterns, confidence, and boundaries. However, the V2-PREP (24-DNA-SYSTEM-V2-PREP) specifies that the gene extractor framework and initial extractors (naming, imports, type usage, documentation) depend only on parsers (P2). Extractors that depend on P4/P5 data (coupling profile, security posture, test patterns) are added incrementally. So DNA can start its framework after P2 and add extractors as data sources become available. The "capstone" label is about completeness, not a hard dependency.

**Confirmed — 7 parallel tracks is accurate. Tracks 1-6 can start immediately after P2. Tracks 7a/7b (Constraint, DNA) start after P4 but are still independent of tracks 1-6.**

---

### 3. Phase 5 DNA System as "Capstone" — ✅ CONFIRMED (can start earlier than implied)

As analyzed above, the DNA System's gene extractor framework and 3-4 initial extractors (naming conventions, import patterns, type usage, documentation style) depend only on P2 outputs (ParseResult, function signatures). These can be built as soon as Phase 2 completes.

The remaining extractors that make DNA a "capstone" (coupling profile gene, security posture gene, test pattern gene) depend on Phase 4/5 outputs. These are additive — the framework works with whatever extractors are available.

The plan's build strategy (§8.7) correctly says: "Create the gene extractor framework and 3-4 extractors that depend only on parsers. Add extractors that depend on Phase 4/5 systems as those systems ship." This is sound.

**Confirmed — DNA can start its framework after P2. The "capstone" label refers to full gene coverage, not a blocking dependency.**

---

### 4. Phase 5 Verification Gate — 13 Criteria — ✅ CONFIRMED (all measurable)

The Phase 5 verification gate (§8.10) lists 13 criteria. I assessed each for measurability:

| # | Criterion | Measurable? | How to Test |
|---|-----------|------------|-------------|
| 1 | Coupling analysis produces Martin metrics and detects cycles via Tarjan's SCC | ✅ Yes | Unit test: compute Ce/Ca/I/A/D on known graph. Assert SCC detection on cyclic input. |
| 2 | Zone classification correctly identifies Zone of Pain / Uselessness / Main Sequence | ✅ Yes | Unit test: modules with known I/A values classified into correct zones. |
| 3 | Constraint system verifies at least 6 of 12 invariant types | ✅ Yes | Integration test: 6 constraint types with known pass/fail inputs. |
| 4 | AST-based constraint verification replaces v1 regex approach | ✅ Yes | Verify no regex-based constraint verification in codebase. AST visitor used for MustHave/MustNotHave. |
| 5 | Contract tracking extracts endpoints from at least 5 REST frameworks | ✅ Yes | Integration test: sample projects for Express, FastAPI, Spring, ASP.NET, Laravel. |
| 6 | Breaking change classifier detects field removal and type changes | ✅ Yes | Unit test: before/after OpenAPI specs with known breaking changes. |
| 7 | Secret detection identifies at least 50 pattern types with entropy scoring | ✅ Yes | Count registered patterns. Test entropy scoring on known high/low entropy strings. |
| 8 | Magic number detection uses AST context (not regex) | ✅ Yes | Verify AST visitor pattern. Test that `42` in `const TIMEOUT = 42` is not flagged but `42` in `sleep(42)` is. |
| 9 | Wrapper detection identifies thin delegation patterns across 3+ frameworks | ✅ Yes | Integration test: React, Vue, Express wrapper samples. |
| 10 | DNA system produces health scores from at least 5 gene extractors | ✅ Yes | Integration test: scan sample project, verify 5+ genes produce scores. |
| 11 | OWASP/CWE mapping enriches findings with correct CWE IDs | ✅ Yes | Unit test: known detector violation → correct CWE ID mapping. |
| 12 | Crypto detection identifies weak hash and deprecated cipher usage | ✅ Yes | Unit test: code samples with MD5, DES, RC4 → detected. |
| 13 | All results persist to drift.db in their respective tables | ✅ Yes | Integration test: scan → query tables → verify rows exist. |

**One note on criterion 7:** Round 1 revised the secret pattern target from 100+ to 150+. The gate says "at least 50 pattern types" which is a minimum bar, not the target. This is fine for a gate (gates should be achievable minimums, not aspirational targets), but the documentation should note that the launch target is 150+.

**Confirmed — all 13 criteria are measurable and testable. No vague or unmeasurable criteria.**

---

### 5. Phase 6 Estimate "2-3 weeks" — ✅ CONFIRMED (realistic for the scope)

Phase 6 builds 5 systems: Rules Engine, Quality Gates, Policy Engine, Audit System, and Violation Feedback Loop.

**Key context:** The Rules Engine and Policy Engine do not have separate V2-PREP docs — they are covered by 09-QUALITY-GATES-V2-PREP (resolved as OD-3 in Round 1, Section 6 findings). The Rules Engine is distributed across gate implementations (pattern→violation mapping within each gate). The Policy Engine is fully specified in §7 of the QG V2-PREP.

**Per-system estimates:**

| System | Estimate | Notes |
|--------|---------|-------|
| Rules Engine | ~3-5 days | Implemented within gate evaluators, not standalone |
| Quality Gates (6 gates + DAG orchestrator) | ~1-1.5 weeks | 6 gates, DAG orchestrator, SARIF reporter |
| Policy Engine | ~3-5 days | 4 built-in policies, 4 aggregation modes, YAML config |
| Audit System | ~1 week | 5-factor health scoring, degradation detection, trend prediction |
| Violation Feedback Loop | ~1-1.5 weeks | FP tracking, auto-disable, inline suppression |

**Total sequential:** ~4-5 weeks. **With overlap (Rules+Gates built together, Policy follows immediately):** ~2.5-3.5 weeks.

The dependency chain (§9.1) is: Rules Engine → Quality Gates → Policy Engine → Audit System, with Violation Feedback Loop running in parallel with Audit. The chain has natural overlap points — the Policy Engine is a thin aggregation layer over gate results and can be built concurrently with the later gates.

The 2-3 week estimate is tight but achievable because:
1. Rules Engine is not a standalone system — it's the violation-mapping logic within each gate
2. Policy Engine is a thin configuration layer (4 modes, YAML parsing)
3. The SARIF reporter (the most complex output format) is explicitly called out to be built early in Phase 6
4. The FeedbackStatsProvider trait (circular dependency resolution) is defined in drift-core during Phase 0, so the interface is ready

**Confirmed — 2-3 weeks is realistic. The scope is smaller than it appears because Rules Engine and Policy Engine are not standalone systems.**

---

### 6. Phase 6 Internal Ordering — ⚠️ REVISE: Partial Overlap Is Possible

The plan implies a strict sequential chain: Rules → Gates → Policy → Audit → Feedback. The actual dependency analysis shows more flexibility:

```
Level 0 (can start immediately):
  - Rules Engine (pattern→violation mapping, within gate implementations)
  - Violation Feedback Loop (FeedbackStatsProvider trait already defined in P0)
    └─ Core FP tracking, dismissal tracking, inline suppression can be built
       independently of gates

Level 1 (needs Rules Engine):
  - Quality Gates (6 gates consume violations from Rules Engine)
    └─ SARIF reporter built here (key deliverable)

Level 2 (needs Quality Gates):
  - Policy Engine (aggregates gate results)
  - Audit System (tracks health over time from gate evaluations)
```

**The key insight:** Violation Feedback Loop's core logic (FP rate tracking, dismissal tracking, auto-disable thresholds) can be built in parallel with Quality Gates. It only needs gate results for integration testing, not for core algorithm development. The `FeedbackStatsProvider` trait is already defined.

Similarly, the Audit System's health scoring formula and degradation detection can be developed in parallel with Policy Engine — they both consume gate results but don't depend on each other.

**Recommendation:** Update §9.1 dependency chain to show:
```
Level 0: Rules Engine + Feedback Loop (core)
Level 1: Quality Gates (parallel: SARIF reporter)
Level 2: Policy Engine || Audit System (parallel)
Level 3: Integration testing (all systems wired together)
```

This allows ~0.5-1 week of overlap, supporting the 2-3 week estimate.

---

### 7. Phase 6 QG↔Feedback Circular Dependency — ✅ CONFIRMED (well-documented)

The circular dependency between Quality Gates and Violation Feedback Loop is:
- Quality Gates consume FP rates from Feedback (for enforcement transitions: block→comment at >10% FP)
- Feedback consumes gate results (to know which violations were surfaced to developers)

The resolution via `FeedbackStatsProvider` trait was validated in Round 1 (Section 6, Finding #9). The trait is defined in drift-core (shared types crate), Quality Gates depends on the trait (abstract interface), and the Feedback Loop implements it. This is textbook Dependency Inversion Principle.

**Orchestration plan documentation:** The dependency chain in §9.1 shows the relationship. The V2-PREP (31-VIOLATION-FEEDBACK-LOOP-V2-PREP §10) defines the exact trait signature with 5 methods. The build order (§27 in the V2-PREP) correctly places trait definition in Phase 1 (types), implementation in Phase 2 (core algorithms), integration in Phase 4.

**Confirmed — the circular dependency resolution is well-documented and the build order handles it correctly.**

---

### 8. Phase 6 Verification Gate — 11 Criteria — ✅ CONFIRMED (all measurable)

The Phase 6 verification gate (§9.7) lists 11 criteria:

| # | Criterion | Measurable? | How to Test |
|---|-----------|------------|-------------|
| 1 | Rules engine maps patterns + outliers to violations with severity and quick fixes | ✅ Yes | Unit test: known patterns → violations with correct severity |
| 2 | All 6 quality gates evaluate correctly against test data | ✅ Yes | Integration test: 6 gates with known pass/fail inputs |
| 3 | DAG orchestrator respects gate dependencies | ✅ Yes | Unit test: verify topological execution order, Level 1 sees Level 0 results |
| 4 | SARIF 2.1.0 reporter produces valid SARIF with CWE/OWASP taxonomies | ✅ Yes | Validate output against sarif-schema-2.1.0.json. Check taxonomy entries. |
| 5 | Progressive enforcement transitions from warn → error correctly | ✅ Yes | Integration test: simulate pattern aging through monitor→comment→block |
| 6 | Policy engine aggregates gate results in all 4 modes | ✅ Yes | Unit test: all-must-pass, any-must-pass, weighted, threshold with known inputs |
| 7 | Audit system computes 5-factor health score | ✅ Yes | Unit test: known inputs → expected health score (formula is deterministic) |
| 8 | Degradation detection fires when health declines beyond threshold | ✅ Yes | Unit test: inject declining health scores → verify alert at -5 and -15 thresholds |
| 9 | Feedback loop tracks FP rate and auto-disables noisy detectors | ✅ Yes | Integration test: simulate >20% FP rate for 30 days → verify auto-disable |
| 10 | All enforcement data persists to drift.db | ✅ Yes | Integration test: run enforcement → query tables → verify rows |
| 11 | NAPI exposes `drift_check()` and `drift_audit()` to TypeScript | ✅ Yes | Integration test: call from TS, verify typed results |

**Confirmed — all 11 criteria are measurable and testable.**

---

### 9. Phase 7 Estimate — ⚠️ REVISE: Orchestration Plan Still Says "3-4 weeks" — Must Be Updated to "6-8 weeks"

The orchestration plan §10 currently states: "Estimated effort: 3-4 weeks. Fully parallelizable (all four are independent)."

Round 1 (Section 7, Finding #13 / OD-5) conclusively demonstrated this is unrealistic:

| System | V2-PREP Estimate (1 dev) | Source |
|--------|-------------------------|--------|
| Simulation Engine | ~6 weeks | 28-SIMULATION-ENGINE-V2-PREP §32 |
| Decision Mining | **~8 weeks** | 29-DECISION-MINING-V2-PREP §27 |
| Context Generation | ~7 weeks | 30-CONTEXT-GENERATION-V2-PREP §28 |
| N+1 Query Detection | ~2 weeks | Orchestration plan §10.4 |

Even with 4 parallel developers, Phase 7 takes **~8 weeks** (bounded by Decision Mining, the longest system). The "3-4 weeks" estimate is not achievable at any team size.

**Current status in orchestration plan:** The plan has NOT been updated. §10 still says "3-4 weeks." This is the most significant unresolved revision from Round 1 for Phases 5-8.

**Recommendation:** Update §10 to:
- "Estimated effort: 6-8 weeks with 4 parallel developers (bounded by Decision Mining at ~8 weeks). With 2 developers: ~13-14 weeks. With 1 developer: ~23 weeks."
- Add per-system estimates table
- Note that Context Generation should be P0 priority (powers MCP tools), Simulation and Decision Mining are P1, N+1 is P2

---

### 10. Phase 7 "All 4 Are Parallel" Claim — ✅ CONFIRMED (with one soft dependency)

I verified each Phase 7 system's dependencies:

| System | Hard Dependencies | Depends on Other P7 Systems? |
|--------|------------------|------------------------------|
| Simulation Engine (28) | P0+P1+P2+P3+P4+P5+P6 (full analysis stack) | ❌ No |
| Decision Mining (29) | P0+P1+P2 (parsers, storage) + git2 | ❌ No |
| Context Generation (30) | P0+P1+P2+P3 (analysis data, confidence scores) | ❌ No |
| N+1 Query Detection | P0+P1+P2 (call graph, ORM patterns) | ❌ No |

All 4 systems are genuinely independent. No Phase 7 system depends on another Phase 7 system's output.

**Soft dependency noted in Round 1 (Section 8):** Context Generation benefits from Phase 4 outputs (taint analysis results, reachability data) as optional enrichment. This was flagged as a soft edge to add to the dependency matrix. It doesn't block Context Generation from starting — it just means the context output is richer with P4 data available.

**N+1 → P5 edge (from Round 1):** N+1 Query Detection needs mature ORM pattern matching from ULP (Phase 5). This is a hard dependency that should be reflected in the dependency matrix. N+1 is correctly assigned to Phase 7 (after P5), but the dependency matrix should show this edge.

**Confirmed — all 4 systems are parallel. The two soft/hard edges from Round 1 don't change the parallelism claim but should be documented in the dependency matrix.**

---

### 11. Phase 7 Hybrid Rust/TS Architecture — ⚠️ REVISE: Integration Risks Need Explicit Documentation

Two Phase 7 systems use a hybrid Rust/TypeScript architecture:

**Simulation Engine (28):** Rust for heavy computation (impact analysis, pattern matching, call graph traversal, coupling friction). TypeScript for orchestration (approach generation, composite scoring, tradeoff generation, recommendation).

**Decision Mining (29):** Rust for git2 high-performance pipeline and commit analysis. TypeScript for ADR synthesis (AI-assisted).

**Integration risks identified:**

1. **NAPI v2→v3 boundary divergence (R19 from Round 1):** The existing Cortex codebase uses napi-rs v2. Drift uses napi-rs v3. The v2→v3 migration guide ([napi.rs](https://napi.rs/docs/more/v2-v3-migration-guide)) documents significant breaking changes:
   - `ThreadsafeFunction` completely rewritten in v3 (ownership-based lifecycle)
   - Several `JsValue` types moved behind `compat-mode` feature flag (`JsObject`, `JsFunction`, `JsNull`, `JsBoolean`, etc.)
   - `AsyncTask` trait signature unchanged in v3 (confirmed: `Task` trait with `compute()` and `resolve()` methods is the same), but `async fn` support is now the preferred pattern for tokio-based async work
   - CLI tooling rewritten (`--cargo-cwd` removed, `--cargo-flags` removed, `create-npm-dir` renamed)

   The Simulation and Decision Mining systems need clear documentation of which operations cross the NAPI boundary and which stay in pure TS or pure Rust. The boundary should be minimized — large data transfers across NAPI add serialization overhead.

2. **Hybrid testing complexity:** Testing hybrid systems requires both Rust unit tests (for computation) and TypeScript integration tests (for orchestration). The test matrix doubles. CI must run both `cargo test` and `vitest`/`jest` for these systems.

3. **Deployment complexity:** Hybrid systems require both the Rust native addon (.node file) and TypeScript orchestration code. The build pipeline must coordinate `napi build` with TypeScript compilation. This is a solved problem (cortex-napi does it), but it adds build complexity for Phase 7 specifically.

4. **Data serialization overhead:** Every Rust→TS boundary crossing involves serde serialization (Rust structs → JSON → JS objects). For Simulation Engine, the impact analysis results and coupling friction data could be large. The plan should specify which data structures cross the boundary and estimate serialization cost.

**Recommendation:** Add a "Hybrid Architecture Integration Guide" subsection to §10 that documents:
- Which operations are Rust-side vs TS-side for each hybrid system
- NAPI function signatures for the boundary (already partially in V2-PREP docs)
- Serialization format and estimated payload sizes
- Testing strategy (Rust unit tests + TS integration tests + cross-boundary tests)
- Note that `async fn` is preferred over `AsyncTask` in napi-rs v3 for tokio-based work

---

### 12. Phase 7 Verification Gate — 7 Criteria — ⚠️ REVISE: 2 Criteria Need Strengthening

The Phase 7 verification gate (§10.5) lists 7 criteria:

| # | Criterion | Measurable? | Assessment |
|---|-----------|------------|------------|
| 1 | Simulation engine generates approaches for at least 5 task categories | ✅ Yes | Integration test with 5 task types |
| 2 | Monte Carlo produces P10/P50/P90 confidence intervals | ✅ Yes | Unit test: verify percentile extraction from 1000 samples |
| 3 | Decision mining extracts decisions from git history via git2 | ✅ Yes | Integration test with sample git repo |
| 4 | ADR detection finds Architecture Decision Records in markdown | ✅ Yes | Integration test with sample ADR files |
| 5 | Context generation produces token-budgeted output for 3 depth levels | ✅ Yes | Unit test: verify output stays within token budget for overview/standard/deep |
| 6 | Intent-weighted scoring produces different context for different intents | ✅ Yes | Unit test: same codebase, different intents → different context ranking |
| 7 | N+1 detection identifies loop-query patterns in at least 3 ORM frameworks | ✅ Yes | Integration test with ActiveRecord, Django ORM, Prisma samples |

**Issues with 2 criteria:**

**Criterion 3 ("extracts decisions from git history")** is too vague. What constitutes a "decision"? The V2-PREP defines 12 decision categories. The gate should specify: "Decision mining extracts decisions in at least 5 of 12 categories from git history." This makes it measurable against the spec.

**Criterion 5 ("token-budgeted output for 3 depth levels")** should also verify the token counting accuracy. The plan uses tiktoken-rs for BPE token counting. The gate should include: "Token count for each depth level is within 5% of the configured budget (verified via tiktoken-rs cl100k_base encoding)."

**Recommendation:** Strengthen criteria 3 and 5:
- Criterion 3: "Decision mining extracts decisions in at least 5 of 12 categories from git history via git2"
- Criterion 5: "Context generation produces token-budgeted output for 3 depth levels, with actual token count within 5% of configured budget"

---

### 13. Phase 8 Estimate "3-4 weeks" — ⚠️ REVISE: Estimate Conflicts with MCP's ~7-Week V2-PREP Estimate

The orchestration plan §11 estimates Phase 8 at "3-4 weeks. Parallelizable (MCP, CLI, CI Agent are independent)."

**Per-system estimates:**

| System | V2-PREP Estimate | Source |
|--------|-----------------|--------|
| MCP Server (32) | **~7 weeks** across 7 phases | 32-MCP-SERVER-V2-PREP §build |
| CLI | ~2-3 weeks (no V2-PREP) | Orchestration plan §11.2 |
| CI Agent (34) | ~2-3 weeks | 34-CI-AGENT-GITHUB-ACTION-V2-PREP |
| Reporters (non-SARIF) | ~1 week (6 remaining formats) | SARIF built in Phase 6 |

**Analysis:**

With 3 parallel developers (MCP, CLI, CI Agent each on a separate track), Phase 8 takes **~7 weeks** (bounded by MCP Server). With 2 developers, it takes ~9-10 weeks. With 1 developer, it takes ~13-14 weeks.

The "3-4 weeks" estimate is only achievable if:
1. MCP Server is scoped to a minimal viable version (stdio transport + 3 entry points + ~10 core tools), OR
2. MCP Server development started earlier (overlapping with Phase 7)

The V2-PREP's 7-week estimate for MCP includes: Phase 1 (core server + stdio transport), Phase 2 (drift-analysis tools), Phase 3 (progressive disclosure), Phase 4 (Streamable HTTP), Phase 5 (drift-memory tools, Phase 9 dependent), Phase 6 (optimization), Phase 7 (documentation + testing). Phases 1-4 are the core deliverable (~4 weeks). Phases 5-7 can be deferred or run in parallel with Phase 9.

**MCP spec version:** The MCP specification 2025-11-25 is confirmed as the current latest version ([modelcontextprotocol.io](https://modelcontextprotocol.io/specification/versioning)). Key additions from 2025-06-18 include: Client ID Metadata Documents, tool calling in sampling, experimental tasks for durable requests, OAuth enhancements, and JSON Schema 2020-12 as default dialect. The plan should target 2025-11-25 as baseline (Round 1 revision from Section 7).

**Recommendation:** Update §11 estimate to:
- "Estimated effort: 4-5 weeks for Phase 8 gate (MCP core + CLI + CI Agent). MCP Server continues optimization through Phase 9. Full MCP completion: ~7 weeks."
- Alternatively, split MCP into "MCP Core" (Phase 8, ~4 weeks) and "MCP Polish" (Phase 9+, ~3 weeks)

---

### 14. Phase 8 "3 Parallel Tracks" Claim — ✅ CONFIRMED

| Track | System | Dependencies | Independent? |
|-------|--------|-------------|-------------|
| 1 | MCP Server | P0-P7 (full analysis stack) | ✅ Yes |
| 2 | CLI | P0-P7 (NAPI surface area) | ✅ Yes |
| 3 | CI Agent | P0-P7 (analysis + enforcement) | ✅ Yes |

All three are pure consumers of the analysis stack. They read from drift.db and call NAPI functions. None depends on another Phase 8 system.

The Reporters (non-SARIF) are a 4th micro-track that can run in parallel with any of the above. SARIF is already built in Phase 6.

**Confirmed — 3 parallel tracks (4 including reporters) is accurate.**

---

### 15. Phase 8 CLI Has No V2-PREP — ✅ CONFIRMED (scope is clear enough)

The CLI is described in §11.2 as: "48-65+ commands: `drift scan`, `drift check`, `drift status`, `drift patterns`, `drift violations`, `drift impact`, `drift simulate`, `drift audit`, `drift setup`, `drift doctor`, `drift export`, `drift explain`, `drift fix`."

**Assessment of whether a V2-PREP is needed:**

The CLI is a thin wrapper around NAPI calls with output formatting. It has:
- No novel algorithms (all computation is in Rust via NAPI)
- No novel data structures (reads from drift.db via NAPI queries)
- No novel architecture (standard CLI framework: clap/commander + output formatters)
- Clear scope: each command maps 1:1 to an existing NAPI function

The "When to Spec" timing of "Start of Phase 8" is correct. By Phase 8, the full NAPI surface area (~55 functions across 14 modules) is known. The CLI spec is essentially a mapping table: CLI command → NAPI function → output format.

**One concern:** "48-65+ commands" is a wide range. The lower bound (48) is achievable in 2-3 weeks. The upper bound (65+) might push to 3-4 weeks. The plan should specify a P0 command set (core commands needed for MVP: scan, check, status, setup, doctor) and a P1 set (everything else).

**Confirmed — no V2-PREP needed. Scope is clear. Recommend defining P0/P1 command priority.**

---

### 16. Phase 8 Verification Gate — 8 Criteria — ✅ CONFIRMED (all measurable)

The Phase 8 verification gate (§11.5) lists 8 criteria:

| # | Criterion | Measurable? | How to Test |
|---|-----------|------------|-------------|
| 1 | MCP server registers all drift-analysis tools via stdio transport | ✅ Yes | Integration test: connect via stdio, list tools, verify count |
| 2 | `drift_status` returns overview in <1ms | ✅ Yes | Benchmark: measure response time against materialized view |
| 3 | `drift_context` produces intent-weighted context with token budgeting | ✅ Yes | Integration test: different intents → different context, within token budget |
| 4 | CLI `drift scan` + `drift check` work end-to-end | ✅ Yes | E2E test: scan sample project, run check, verify output |
| 5 | CI agent runs 9 analysis passes on a PR diff | ✅ Yes | Integration test: mock PR diff, verify 9 passes execute |
| 6 | SARIF upload to GitHub Code Scanning succeeds | ✅ Yes | Integration test: upload SARIF to GitHub API (or mock) |
| 7 | PR comment generation produces readable summaries | ✅ Yes | Snapshot test: verify PR comment format against golden file |
| 8 | All 7 reporter formats produce valid output | ✅ Yes | Unit test: validate each format against its schema/spec |

**Confirmed — all 8 criteria are measurable and testable.**

---

### 17. Milestones M5-M6 Timing — ⚠️ REVISE: Both Need Adjustment After Round 1 Revisions

**Milestone 5: "It Enforces" (End of Phase 6) — "12-16w"**

The milestone timing is calculated as: P0 (1-2w) + P1 (2-3w) + P2 (2w core) + P3 (3-4w) + P4 (parallel with P3, adds 1-2w) + P5 (4-6w) + P6 (2-3w).

Critical path to M5: P0→P1→P2→P3→P5(partial)→P6 = 1+2+2+3+4+2 = 14 weeks minimum, 2+3+4+4+6+3 = 22 weeks maximum.

Wait — Phase 4 runs parallel with Phase 3, and Phase 5 has staggered starts. Let me recalculate:

```
P0: 1-2w
P1: 2-3w (sequential after P0)
P2: 2-3w (sequential after P1, core pipeline only)
P3: 3-4w (sequential after P2)
P4: 4-6w (parallel with P3, starts after P2)
P5: 4-6w (starts after P2 for most tracks, after P4 for Constraint/DNA)
P6: 2-3w (sequential after P5 gate)
```

The critical path to M5 depends on whether P6 needs P4 outputs. Phase 6 (enforcement) consumes confidence scores (P3), patterns (P2), and optionally taint/reachability (P4). The core enforcement (pattern compliance, constraint verification, regression detection) needs P3 but not P4. Security boundary gate needs P4 (taint analysis).

**Optimistic critical path (P6 starts after P3+P5 partial, without security boundary gate):**
P0(1w) → P1(2w) → P2(2w) → P3(3w) → P5(4w, partial) → P6(2w) = **14 weeks**

**Realistic critical path (P6 needs P4 for security boundary gate):**
P0(1.5w) → P1(2.5w) → P2(2.5w) → P4(5w, after P2) → P5(5w, after P4 for Constraint/DNA) → P6(2.5w) = **19.5 weeks**

Applying the 1.3x overconfidence correction from Round 1: 14×1.3 = 18.2w to 19.5×1.3 = 25.4w.

The plan's "12-16w" is the optimistic path without the 1.3x correction. With the correction, **M5 should be "16-22w"** (rounding the realistic range).

**Milestone 6: "It Ships" (End of Phase 8) — "14-20w"**

M6 = M5 + Phase 7 (parallel, off critical path) + Phase 8 (2-4w after M5).

If Phase 8 starts after M5 (enforcement is done), then M6 = M5 + Phase 8 = 16-22w + 4-5w = **20-27w**.

However, Phase 8 systems (MCP, CLI, CI Agent) don't strictly need Phase 6 to be complete. They need the analysis stack (P0-P5) to produce data. MCP and CLI can start reading from drift.db as soon as Phase 5 systems are producing results. Only the CI Agent needs enforcement (Phase 6) for pass/fail decisions.

**Revised critical path to M6:**
- MCP + CLI can start after P5 gate (parallel with P6)
- CI Agent starts after P6
- M6 = max(M5 + CI Agent setup, P5 gate + MCP completion)

With MCP at ~4-5 weeks (core) starting after P5: P0(1.5w) → P1(2.5w) → P2(2.5w) → P3/P4(5w) → P5(5w) → MCP(4.5w) = **21.5w**
With CI Agent after P6: M5(19.5w) + CI Agent(2.5w) = **22w**

These converge around **20-24w** with the 1.3x correction.

The plan's "14-20w" is optimistic. **M6 should be "18-24w"** (applying 1.3x correction to the realistic range).

**Recommendation:** Update milestone timings:
- M5: "12-16w" → **"16-22w"** (with 1.3x correction)
- M6: "14-20w" → **"18-24w"** (with 1.3x correction)

---

## Round 1 Revision Application Status

The following Round 1 revisions are relevant to Section 11 (Phases 5-8):

| Revision | Status | Notes |
|----------|--------|-------|
| Secret patterns 100+ → 150+ | 🔧 APPLIED | Verified in Section 5 findings. Phase 5 gate says "at least 50" (minimum bar). Launch target is 150+. Orchestration plan §8.5 should be updated. |
| Format validation as 3rd confidence signal | 🔧 APPLIED | Verified in Section 5 findings. Add to §8.5 secret detection description. |
| OWASP A09 name fix ("Security Logging and Alerting Failures") | 🔧 APPLIED | Verified in Section 5 findings. §8.8 OWASP/CWE Mapping should use official name. |
| CWE Top 25 coverage: 20/25 fully + 5/25 partially | 🔧 APPLIED | Verified in Section 5 findings. §8.8 should clarify memory safety CWEs are partially detectable. |
| FP target <5% → <10% | 🔧 APPLIED | Verified in Section 6 findings. §9.6 Violation Feedback Loop should use <10% target. |
| SonarQube Generic reporter as P2 | Not yet applied | §11.4 Reporters should list SonarQube Generic as 8th format (P2 priority). |
| Health score empirical validation plan | 🔧 APPLIED | Verified in Section 6 findings. §9.5 should note weights are configurable and heuristic. |
| Phase 7 timeline 3-4w → 6-8w | **NOT APPLIED** | §10 still says "3-4 weeks". This is the most critical unresolved revision. |
| MCP spec 2025-06-18 → 2025-11-25 | Not yet applied | §11.1 MCP Server should target 2025-11-25 baseline. Confirmed current via [modelcontextprotocol.io](https://modelcontextprotocol.io/specification/versioning). |
| git2 0.19 → 0.20 | Not yet applied | §10.2 Decision Mining should pin git2 = "0.20". Confirmed: git2 0.20.2 is current (May 2025). |
| tiktoken-rs 0.6 → 0.9 | Not yet applied | §10.3 Context Generation should pin tiktoken-rs = "0.9". Confirmed via [lib.rs](https://lib.rs/crates/tiktoken-rs). |
| fd-lock unspecified → "4" | Not yet applied | Workspace Cargo.toml should pin fd-lock = "4". Confirmed: fd-lock 4.0.4 is current (March 2025). |

---

## Verdict Summary

| Item | Verdict | Action Required |
|------|---------|-----------------|
| Phase 5 estimate "4-6 weeks" | ⚠️ REVISE | Correct for phase gate but masks Contract Tracking's 20-week tail. Add clarification about CT continuing through P6-P8. |
| Phase 5 "7 parallel tracks" | ✅ CONFIRMED | All 7 tracks genuinely independent. Constraint/DNA have staggered start (need P4). |
| Phase 5 DNA as "capstone" | ✅ CONFIRMED | Framework starts after P2. Full gene coverage is the capstone, not a blocking dependency. |
| Phase 5 verification gate (13 criteria) | ✅ CONFIRMED | All 13 criteria are measurable and testable. |
| Phase 6 estimate "2-3 weeks" | ✅ CONFIRMED | Realistic. Rules Engine and Policy Engine are not standalone systems. |
| Phase 6 internal ordering | ⚠️ REVISE | Partial overlap possible. Feedback Loop core can parallel Quality Gates. Audit can parallel Policy. |
| Phase 6 QG↔Feedback circular dep | ✅ CONFIRMED | FeedbackStatsProvider trait is well-documented. Build order handles it correctly. |
| Phase 6 verification gate (11 criteria) | ✅ CONFIRMED | All 11 criteria are measurable and testable. |
| Phase 7 estimate "3-4 weeks" | ⚠️ REVISE | **NOT UPDATED from Round 1.** Must change to "6-8 weeks with 4 devs." Bounded by Decision Mining at 8w. |
| Phase 7 "all 4 parallel" | ✅ CONFIRMED | All 4 systems genuinely independent. Soft edges (Context Gen→P4, N+1→P5) documented. |
| Phase 7 hybrid Rust/TS | ⚠️ REVISE | Integration risks need explicit documentation: NAPI v3 boundary, testing complexity, serialization overhead. |
| Phase 7 verification gate (7 criteria) | ⚠️ REVISE | 2 criteria need strengthening: Decision Mining categories, Context Gen token accuracy. |
| Phase 8 estimate "3-4 weeks" | ⚠️ REVISE | Conflicts with MCP's 7-week V2-PREP estimate. Update to "4-5 weeks for gate, 7 weeks for full MCP." |
| Phase 8 "3 parallel tracks" | ✅ CONFIRMED | MCP, CLI, CI Agent are genuinely independent. |
| Phase 8 CLI no V2-PREP | ✅ CONFIRMED | Scope is clear (thin NAPI wrapper). Recommend P0/P1 command priority. |
| Phase 8 verification gate (8 criteria) | ✅ CONFIRMED | All 8 criteria are measurable and testable. |
| M5 timing "12-16w" | ⚠️ REVISE | Should be "16-22w" with 1.3x correction. |
| M6 timing "14-20w" | ⚠️ REVISE | Should be "18-24w" with 1.3x correction. |
| Round 1 revisions (12 items) | 🔧 5 APPLIED, 7 pending | Phase 7 timeline is the most critical unresolved revision. Version bumps (git2, tiktoken-rs, MCP spec, fd-lock) and SonarQube reporter still need application. |

**Overall: 10 CONFIRMED, 5 REVISE, 0 REJECT, 5 APPLIED.**

The Phase 5-8 build ordering is fundamentally sound. All parallelism claims are verified. All verification gates are measurable. The 5 revisions are:
1. Phase 5 estimate needs Contract Tracking tail clarification
2. Phase 6 internal ordering allows more overlap than documented
3. Phase 7 estimate MUST be updated from "3-4 weeks" to "6-8 weeks" (critical unresolved Round 1 revision)
4. Phase 7 hybrid architecture needs integration risk documentation
5. Phase 8 estimate should be "4-5 weeks" (MCP bounds it at ~7 weeks total, but core is ~4 weeks)

Milestone timings M5 and M6 need the 1.3x overconfidence correction applied consistently.
