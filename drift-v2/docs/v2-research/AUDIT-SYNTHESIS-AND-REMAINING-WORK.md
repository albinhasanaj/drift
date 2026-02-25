# Drift V2 — Full Audit Synthesis & Remaining Work

> Generated: 2026-02-08
> Source: Sections 1-8 Findings + DRIFT-V2-IMPLEMENTATION-ORCHESTRATION.md
> Purpose: Final synthesis for one last round of review before implementation plan

---

## Part 1: Cross-Section Audit Synthesis

### Aggregate Verdicts Across All 8 Sections

| Section | Scope | Confirmed | Revise | Reject | Resolved |
|---------|-------|-----------|--------|--------|----------|
| 1 | Phase 0 — Infrastructure & Crate Scaffold | 11 | 4 | 0 | 0 |
| 2 | Phase 1 — Scanner, Parsers, Storage, NAPI | 14 | 4 | 0 | 0 |
| 3 | Phase 2 — Analysis Engine, Call Graph, Detectors | 7 | 3 | 0 | 0 |
| 4 | Phases 3-4 — Pattern Intelligence & Graph Intelligence | 13 | 2 | 0 | 0 |
| 5 | Phase 5 — Structural Intelligence | 8 | 4 | 0 | 0 |
| 6 | Phase 6 — Enforcement (Quality Gates, Audit, Feedback) | 7 | 3 | 0 | 2 |
| 7 | Phases 7-10 — Advanced, Presentation, Bridge, Polish | 8 | 4 | 0 | 1 |
| 8 | Cross-Cutting Concerns | 5 | 5 | 0 | 0 |
| **TOTAL** | **All Phases** | **73** | **29** | **0** | **3** |

Zero rejections across 105 validated decisions. The architecture is fundamentally sound.

---

### All 29 Revisions Consolidated (Grouped by Category)

#### A. Version Bumps (10 items — mechanical, no design change)

| Item | From | To | Section | Impact |
|------|------|----|---------|--------|
| tree-sitter | 0.24 | **0.25** | S1, S2 | Verify all 10 grammar compat |
| rusqlite | 0.32 | **0.38** | S1, S2 | Greenfield, no migration cost |
| petgraph | 0.6 | **0.8** | S1 | Greenfield, stable_graph feature flag |
| smallvec | "1.13" | **"1"** | S1 | Resolves to 1.15.x automatically |
| git2 | 0.19 | **0.20** | S7 | Bundles libgit2 1.9 |
| tiktoken-rs | 0.6 | **0.9** | S7 | Adds o200k_harmony, GPT-5 support |
| MCP spec baseline | 2025-06-18 | **2025-11-25** | S7 | Adds CIMD, XAA, mandatory PKCE |
| rayon | 1.10 | 1.10 (→1.11) | S1 | No action, Cargo resolves automatically |
| lasso | 0.7 | 0.7 (confirmed) | S1 | lasso2 0.8 as fallback if needed |
| fd-lock | unspecified | **"4"** | S7 | Pin version in workspace Cargo.toml |

#### B. Architecture Refinements (11 items — design adjustments, not rewrites)

| Item | Revision | Section | Impact |
|------|----------|---------|--------|
| GAST node types | 26 → plan for **~40-50**, add `GASTNode::Other` catch-all | S3 | More normalization work per language |
| SQLite CTE fallback | Document limitations, use temp table for visited set, lower max_depth to 5 | S3 | Performance documentation + minor impl change |
| Taint sink types | Add **XmlParsing** (CWE-611) and **FileUpload** (CWE-434) → 17 built-in | S4 | 2 new enum variants |
| Secret detection | Add **format validation** as 3rd confidence signal (AWS AKIA*, GitHub ghp_*) | S5 | Additional validation layer |
| Secret pattern count | 100+ → target **150+** for launch | S5 | ~50 more TOML pattern definitions |
| OWASP A09 naming | "Logging & Alerting Failures" → **"Security Logging and Alerting Failures"** | S5 | Cosmetic string fix |
| CWE Top 25 coverage | 25/25 aspirational → **20/25 fully + 5/25 partially** (memory safety) | S5 | Documentation clarification |
| SonarQube reporter | Add **SonarQube Generic Issue Format** as P2 reporter | S6 | 8th reporter format, post-launch |
| Health score weights | Keep current, make configurable, plan **empirical validation** | S6 | Config + telemetry, not code change |
| FP rate target | <5% → **<10%** overall, with category-specific sub-targets | S6 | Threshold adjustment |
| Medallion terminology | Bronze/Silver/Gold → **staging/normalized/materialized** | S2 | Rename in code comments/docs |

#### C. Timeline & Estimation Corrections (4 items)

| Item | Original | Revised | Section |
|------|----------|---------|---------|
| 22-week UAE estimate | 22 weeks | **22-27 weeks** (add 20% buffer) | S3 |
| Phase 7 estimate | 3-4 weeks | **6-8 weeks** (bounded by Decision Mining at 8w) | S7 |
| Critical path | 12-16 weeks | **16-21 weeks** realistic (1.3x overconfidence correction) | S8 |
| 1-developer timeline | 6-8 months | **8-10 months** realistic | S8 |

#### D. Missing Items to Add (4 items)

| Item | What to Add | Section |
|------|-------------|---------|
| Risk register | R17 (SQLite schema complexity), R18 (estimation overconfidence), R19 (NAPI v2→v3 divergence), R20 (parallel dev coordination) | S8 |
| Dependency matrix | N+1→P5 edge, soft Context Gen→P4 edge, fix system count (53 not 60) | S8 |
| Cortex reuse guide | Fix 3 factual errors: 14 NAPI modules (not 12), tokio::sync::Mutex (not std), 21 crates (not 19). Note: similarity.rs is cosine only, not Jaccard | S8 |
| Release profile | Add `panic = "abort"` (matches Cortex) | S1 |

---

### 3 Resolved Open Decisions

| OD | Decision | Resolution | Section |
|----|----------|------------|---------|
| OD-2 | "Professional" vs "Team" tier | **"Team"** — matches SonarQube, Semgrep, Snyk, GitHub convention | S6 |
| OD-3 | Rules/Policy Engine separate specs | **Not needed** — covered by 09-QG-V2-PREP §5 and §7 | S6 |
| OD-5 | Phase 7 + Phase 10 timeline | **Resolved** — estimates updated, critical path unaffected | S7 |

---

## Part 2: Key Validated Architectural Decisions

These are the highest-impact decisions confirmed across all sections:

1. **6-crate workspace** (drift-core, drift-analysis, drift-storage, drift-context, drift-napi, drift-bench) — confirmed with drift-context as 6th crate for tiktoken-rs isolation
2. **Single-pass visitor pattern** for all detectors — validated by ast-grep and Semgrep
3. **Beta-Binomial Bayesian confidence** with 5-factor blending — textbook correct, O(1) updates
4. **Intraprocedural-first taint analysis** with interprocedural via function summaries — matches Semgrep, SonarSource, FlowDroid
5. **Progressive enforcement** (monitor→comment→block with auto-demotion) — more sophisticated than SonarQube, validated by Google Tricorder
6. **Progressive disclosure MCP** (3 entry points, ~81% token reduction) — validated by 4+ production MCP servers
7. **Grounding feedback loop** — first AI memory system with empirically validated memory
8. **petgraph 0.8 StableGraph** for call graph — stable indices critical for incremental updates
9. **WAL mode + synchronous=NORMAL** SQLite — standard high-performance local config
10. **OnceLock singleton** for NAPI runtime — lock-free after init, proven by cortex-napi

---

## Part 3: Orchestration Plan — What Sections Remain for Final Review

The orchestration plan (DRIFT-V2-IMPLEMENTATION-ORCHESTRATION.md) has 20 sections. Here's the status of each against the research findings:

| § | Section | Research Status | Revisions Needed |
|---|---------|----------------|------------------|
| 1 | Governing Principles (D1-D7, AD1-AD12) | ✅ Fully validated | None |
| 2 | 60-System Master Registry | ⚠️ Needs update | System count is ~53, not 60. Add drift-context crate |
| 3 | Phase 0 — Crate Scaffold | ⚠️ Needs update | 6 crates (not 5). Version bumps (tree-sitter 0.25, rusqlite 0.38, petgraph 0.8). Add `panic = "abort"`. Fix feature flag inconsistency |
| 4 | Phase 1 — Entry Pipeline | ⚠️ Needs update | Version bumps. Medallion terminology. macOS scan target 500ms. Separate cold/incremental 100K targets |
| 5 | Phase 2 — Structural Skeleton | ⚠️ Needs update | GAST expansion to ~40-50 types. Add GASTNode::Other. CTE fallback documentation |
| 6 | Phase 3 — Pattern Intelligence | ✅ Fully validated | Minor: UAE estimate buffer |
| 7 | Phase 4 — Graph Intelligence | ⚠️ Needs update | Add 2 taint sink types (XmlParsing, FileUpload) |
| 8 | Phase 5 — Structural Intelligence | ⚠️ Needs update | Secret pattern target 150+. Format validation. OWASP A09 name fix. CWE coverage clarification |
| 9 | Phase 6 — Enforcement | ⚠️ Needs update | FP target <10%. SonarQube reporter P2. Health score empirical validation plan |
| 10 | Phase 7 — Advanced & Capstone | ⚠️ Needs update | Timeline: 6-8 weeks (not 3-4). Per-system estimates needed |
| 11 | Phase 8 — Presentation | ✅ Validated | Minor: MCP spec version update |
| 12 | Phase 9 — Bridge & Integration | ✅ Validated | None |
| 13 | Phase 10 — Polish & Ship | ⚠️ Needs update | Timeline requires 3+ devs for 4-6 weeks |
| 14 | Cross-Phase Dependency Matrix | ⚠️ Needs update | 4 missing/incorrect edges. System count fix |
| 15 | Parallelization Map | ✅ Validated | Add realistic (1.3x) timeline column |
| 16 | Risk Register | ⚠️ Needs update | Add R17-R20. Update R1, R6, R11 |
| 17 | Unspecced Systems | ✅ Validated | None |
| 18 | Cortex Pattern Reuse Guide | ⚠️ Needs update | 3 factual corrections + NAPI v2→v3 note |
| 19 | Verification Gates | ⚠️ Minor update | Add concrete criteria for M3/M7. Add Phase 5→6 gate |
| 20 | Gap Analysis | ⚠️ Needs update | Schema counts, NAPI function counts, performance targets |

**Summary: 8 sections fully validated, 12 sections need updates (all refinements, no rewrites)**

---

## Part 4: Remaining Work Before Final Implementation Plan

### Round 1: Orchestration Plan Updates (apply the 29 revisions)

These are the concrete edits needed to bring the orchestration plan in sync with research:

1. **§2 Master Registry**: Update system count to ~53. Add drift-context as 6th crate.
2. **§3.1 Cargo.toml**: Apply all 10 version bumps. Add `panic = "abort"` to release profile. Fix `default = ["full"]` inconsistency. Add drift-context deps (tiktoken-rs, quick-xml, serde_yaml, glob, base64).
3. **§5.2 GAST**: Change "~30 node types" to "~40-50 node types". Add `GASTNode::Other { kind, children }` catch-all. Make `coverage_report()` mandatory.
4. **§7.3 Taint**: Add `XmlParsing` (CWE-611) and `FileUpload` (CWE-434) to SinkType enum.
5. **§8.5 Constants**: Target 150+ secret patterns. Add format validation signal.
6. **§8.8 OWASP**: Fix A09 name to "Security Logging and Alerting Failures".
7. **§9 Phase 6**: Change FP target from <5% to <10%. Add SonarQube Generic as P2 reporter.
8. **§10 Phase 7**: Update estimate from "3-4 weeks" to "6-8 weeks with 4 devs". Add per-system estimates.
9. **§14 Dependency Matrix**: Add N+1→P5 edge, soft Context Gen→P4 edge. Fix system count.
10. **§15 Parallelization**: Add realistic (1.3x) timeline column. Critical path: 16-21 weeks realistic.
11. **§16 Risk Register**: Add R17 (schema complexity), R18 (estimation overconfidence), R19 (NAPI v2→v3), R20 (parallel coordination). Update R1/R6/R11.
12. **§18 Cortex Reuse**: Fix 3 factual errors. Add NAPI v2→v3 adaptation note. Add conversions/ module pattern.
13. **§19 Verification Gates**: Add concrete criteria for M3 and M7. Add Phase 5→6 precondition.
14. **§20 Gap Analysis**: Update schema counts (Phase 5: ~48-56, not ~40-45). Update NAPI counts (~55 top-level, not 42-53). Add missing performance targets.

### Round 2: Pre-Implementation Verification Checklist

Before writing the final implementation plan, verify these items:

- [ ] All 10 tree-sitter 0.25 grammar crates exist and compile (especially Kotlin community grammar)
- [ ] rusqlite 0.38 is actually released on crates.io (Section 1 recommended it but Section 2 noted lib.rs showed 0.36.x-0.37.x — verify exact latest)
- [ ] petgraph 0.8 `stable_graph` feature flag API — confirm StableGraph is available
- [ ] napi-rs v3 `AsyncTask` API — confirm the exact trait signature for v3 (differs from v2)
- [ ] MCP SDK 2025-11-25 spec support — confirm `@modelcontextprotocol/sdk` version that supports it
- [ ] tiktoken-rs 0.9 `cl100k_base()` and `o200k_base()` API stability
- [ ] `statrs` 0.17 `Beta` and `StudentsT` distribution APIs
- [ ] `fd-lock` 4.x `RwLock<File>` API for process locking
- [ ] `rusqlite_migration` compatibility with rusqlite 0.38
- [ ] crossbeam-channel 0.5.x latest patch (RUSTSEC-2025-0024 fix)

### Round 3: Implementation Plan Structure

After applying revisions and verifying dependencies, the final implementation plan should cover:

1. **Phase 0 Sprint Plan** — exact files to create, exact Cargo.toml contents with verified versions
2. **Phase 1 Sprint Plan** — scanner, parsers, storage, NAPI with test fixtures
3. **Phase 2 Sprint Plan** — two-track allocation, minimum viable detector set, GAST P0 languages
4. **Phase 3-6 Sprint Plans** — critical path items with milestone gates
5. **Phase 4-5 Parallel Track Assignments** — which systems to which developers
6. **Phase 7-10 Prioritized Backlog** — P0/P1/P2 within each phase
7. **Dependency Verification Results** — crate version confirmations
8. **Risk Mitigation Actions** — specific actions for R1-R20

---

## Part 5: Confidence Assessment

| Area | Confidence | Notes |
|------|-----------|-------|
| Architecture (crate structure, data flow, dependency graph) | **Very High** | 73 confirmations, 0 rejections |
| Algorithm choices (Bayesian, Tarjan, MinHash, taint) | **Very High** | All backed by academic literature and production systems |
| Dependency versions | **High** | 10 version bumps identified, all straightforward |
| Timeline estimates | **Medium** | 1.3x overconfidence correction applied. Critical path 16-21 weeks realistic |
| Team scaling | **Medium** | 2-developer config is best ROI. 5+ hits diminishing returns |
| Feature completeness | **High** | 35 V2-PREP specs cover all core systems. 9 unspecced are all presentation/polish |
| Security coverage | **High** | OWASP 2025 10/10, CWE 2025 20/25 fully detectable, taint analysis closes biggest gap |

The research is thorough and the architecture is validated. The remaining work is applying the 29 revisions to the orchestration plan, verifying the 10 dependency versions, and structuring the implementation sprints.
