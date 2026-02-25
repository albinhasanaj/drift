# DRIFT V2 — Diff Manifest

> Generated: 2026-02-08
> Sources: Sections 1–16 Findings + AUDIT-SYNTHESIS-AND-REMAINING-WORK.md
> Purpose: Every actionable delta from 192 validated decisions across 12 completed audit sections.
> Zero rejections. 52 revisions. All refinements — no architectural changes.
> S1–S4 audit pass (2026-02-08): +2 corrections recovered (Changes 7a, 9a), +1 blocker, 1 source fix. Total changes: 63.
> S13–S16 audit pass (2026-02-08): +3 gaps recovered (Changes 54a, 60 expanded, 60a). Total changes: 66.

---

## Agent Instructions

**Target document:** `docs/v2-research/DRIFT-V2-IMPLEMENTATION-ORCHESTRATION.md`

**How to read each Change entry:**
- `§X` = section X of the target document. Navigate there before editing.
- `Op: replace` = find the **Current value** text in that section, swap it for **New value**.
- `Op: insert` = no existing text to find. Add **New value** as new content in that section, matching the format of adjacent entries.
- `Op: delete` = remove the **Current value** from that section.
- `Op: replace-block` = replace an entire subsection or block (e.g., the full Cargo.toml).

**Conflict resolution:**
- The **Corrected §3.1 Cargo.toml** block at the bottom of this manifest is the final, authoritative version. It supersedes Change 5's individual line items. Use it verbatim for §3.1.
- If a Change says "No change" (e.g., Change 37), skip it — it's documented to prevent a previously-suggested edit from being applied.

**Ordering:** Apply changes in section order (§1 → §20). Within a section, apply in change-number order. Changes are independent — no change depends on another change's output.

**Scope:** Only modify sections referenced in this manifest. Do not touch any section not listed here.

---

## §1 — Governing Principles

No changes. All 7 governing decisions (D1–D7) and 12 architectural decisions (AD1–AD12) confirmed structurally enforced by build order.

---

## §2 — Master Registry

### Change 1: System count
- **Source:** S9 Finding #3, S13 Finding #1
- **Op:** replace
- **Current value:** "60-System Master Registry"
- **New value:** "~55-System Master Registry" (55 rows in dependency matrix)
- **Type:** correction

### Change 2: Add Simulation Engine as Net New
- **Source:** S9 Finding #5
- **Op:** insert
- **Current value:** Only Taint (15) and Crypto (27) flagged ⚡ Net New
- **New value:** Add Simulation Engine (28) as ⚡ Net New — genuinely novel, no v1 code to port, hybrid Rust/TS
- **Type:** missing-item

### Change 3: Downstream consumer counts
- **Source:** S9 Finding #6
- **Op:** replace
- **Current value:** Call Graph ~12, Bayesian Confidence ~7, Taint ~5
- **New value:** Call Graph ~20, Bayesian Confidence ~9-10, Taint ~6-7
- **Type:** correction

---

## §3 — Phase 0: Crate Scaffold

### Change 4: Add drift-context as 6th crate
- **Source:** S1 (OD-1 resolution), S9 Finding #3
- **Op:** replace
- **Current value:** 5 workspace members
- **New value:** 6 workspace members — add `drift-context` (isolates tiktoken-rs, quick-xml, serde_yaml, glob, base64)
- **Type:** architecture

### Change 5: Version bumps in §3.1 Cargo.toml (10 items)
- **Source:** S1, S2, S7, S13, S14, S16
- **Op:** replace-block
- **NOTE:** The **Corrected §3.1 Cargo.toml** at the bottom of this manifest is the authoritative version. Use it verbatim to replace the existing §3.1 Cargo.toml block. The individual line items below are for traceability only:
  - `tree-sitter`: "0.24" → "0.25"
  - `rusqlite`: "0.32" → "0.38" (bundles SQLite 3.51.1)
  - `petgraph`: "0.6" → "0.8" (stable_graph is default feature)
  - `smallvec`: "1.13" → "1" (resolves to 1.15.x)
  - `git2`: not pinned → "0.20" (bundles libgit2 1.9)
  - `tiktoken-rs`: not pinned → "0.9" (adds o200k_harmony, GPT-5)
  - `fd-lock`: not pinned → "4"
  - `statrs`: "0.17" (implicit) → "0.18" (Dec 2024 release, non-breaking) [S14]
  - `rayon`: "1.10" → no change (Cargo resolves to 1.11.x)
  - `lasso`: "0.7" → no change (confirmed correct)
- **Type:** version-bump

### Change 6: Add panic=abort to release profile
- **Source:** S1 Finding, S10 Finding #14
- **Op:** insert
- **Current value:** No `panic` setting in `[profile.release]`
- **New value:** `panic = "abort"` (matches Cortex workspace, prevents UB at NAPI FFI boundary)
- **Type:** architecture

### Change 7: Phase 0 verification gate — add 2 criteria
- **Source:** S10 Finding #2, S15 Finding #18
- **Op:** insert
- **Current value:** 8 criteria
- **New value:** 10 criteria — add: (9) `panic = "abort"` set in release profile, (10) drift-context crate compiles and exports public types
- **Type:** missing-item

### Change 7a: Fix feature flag default inconsistency
- **Source:** S1 Finding #15
- **Op:** replace
- **Current value:** Stack hierarchy says `default = ["cortex", "mcp"]`; orchestration plan says `default = ["full"]`
- **New value:** Resolve: `default = ["full"]` for drift-analysis crate. `cortex` and `mcp` flags are optional, not default.
- **Type:** correction

---

## §4 — Phase 1: Entry Pipeline

### Change 8: Medallion terminology rename
- **Source:** S2 Finding
- **Op:** replace
- **Current value:** Bronze / Silver / Gold
- **New value:** staging / normalized / materialized (in code comments and docs)
- **Type:** rename

### Change 9: Phase 1 parallelism claim
- **Source:** S10 Finding #4
- **Op:** replace
- **Current value:** "No parallelism possible here — it's a strict pipeline"
- **New value:** "Integration testing is sequential (Scanner→Parsers→Storage→NAPI), but development of Storage and NAPI infrastructure can overlap with Scanner and Parsers"
- **Type:** correction

### Change 9a: Platform-specific scan performance targets
- **Source:** S2 Finding #18
- **Op:** replace
- **Current value:** 10K files <300ms scan; 100K files <1.5s scan (no platform distinction, no cold/incremental split)
- **New value:** 10K scan: <300ms Linux, <500ms macOS (APFS getdirentries64 bottleneck). 100K scan: <3s cold, <1.5s incremental (1% changed). Add platform-specific target table.
- **Type:** correction

---

## §5 — Phase 2: Structural Skeleton

### Change 10a: GAST node type count
- **Source:** S3 Finding, S14 Finding A6
- **Op:** replace
- **Current value:** "~30 node types"
- **New value:** "~40-50 node types"
- **Type:** architecture

### Change 10b: GAST catch-all variant
- **Source:** S3 Finding, S14 Finding A6
- **Op:** insert
- **Current value:** No catch-all variant in GASTNode enum
- **New value:** Add `GASTNode::Other { kind: String, children: Vec<GASTNode> }` catch-all so normalizers can pass through unrecognized constructs
- **Type:** architecture

### Change 10c: GAST coverage_report() mandatory
- **Source:** S3 Finding, S14 Finding A6
- **Op:** replace
- **Current value:** `coverage_report()` per language (optional)
- **New value:** `coverage_report()` per language (mandatory). Target ≥85% node coverage for P0 languages (TS, JS, Python)
- **Type:** architecture

### Change 11a: CTE fallback — temp table for visited set
- **Source:** S3 Finding
- **Op:** insert
- **Current value:** CTE uses string-based cycle detection (`path NOT LIKE '%' || id || '%'`)
- **New value:** Document: use temp table for visited set instead of string-based cycle detection (~5x faster for dense graphs)
- **Type:** architecture

### Change 11b: CTE fallback — lower max_depth
- **Source:** S3 Finding
- **Op:** replace
- **Current value:** CTE max_depth default (10 or unspecified)
- **New value:** CTE max_depth default = 5 (bounds combinatorial explosion for dense graphs)
- **Type:** architecture

### Change 11c: CTE fallback — document performance characteristics
- **Source:** S3 Finding
- **Op:** insert
- **Current value:** No documented CTE performance limitations
- **New value:** Add note: CTE fallback is ~10x slower than in-memory BFS for sparse graphs, up to 50-100x for highly connected graphs with many cycles. No global visited set in SQLite recursive CTEs.
- **Type:** architecture

### Change 12: UAE estimate buffer
- **Source:** S3 Finding, S14 Finding A8
- **Op:** replace
- **Current value:** "22 weeks" across 7 internal phases
- **New value:** "22-27 weeks" (add 20% risk buffer)
- **Type:** timeline

---

## §6 — Phase 3: Pattern Intelligence

### Change 13: Phase 3 verification gate criterion 6
- **Source:** S10 Finding #11, S15 Finding #21
- **Op:** replace
- **Current value:** "Z-Score, Grubbs', and IQR methods produce statistically valid results"
- **New value:** "Z-Score, Grubbs', and IQR methods produce correct outlier classifications on a reference dataset with known outliers (≥90% precision, ≥80% recall)"
- **Type:** correction

---

## §7 — Phase 4: Graph Intelligence

### Change 14: Add 2 taint sink types
- **Source:** S4 Finding
- **Op:** insert
- **Current value:** 15 built-in SinkType variants
- **New value:** 17 built-in — add `XmlParsing` (CWE-611) and `FileUpload` (CWE-434)
- **Type:** architecture

### Change 15: Phase 4 verification gate — add performance criterion
- **Source:** S10 Finding #12, S15 Finding #22
- **Op:** insert
- **Current value:** 12 criteria
- **New value:** 13 criteria — add: "All 5 systems complete on 10K-file codebase in <15s total"
- **Type:** missing-item

---

## §8 — Phase 5: Structural Intelligence

### Change 16: Secret pattern target
- **Source:** S5 Finding
- **Op:** replace
- **Current value:** 100+ secret patterns
- **New value:** 150+ secret patterns for launch, with format validation as 3rd confidence signal (AWS AKIA*, GitHub ghp_*)
- **Type:** architecture

### Change 17: OWASP A09 name fix
- **Source:** S5 Finding
- **Op:** replace
- **Current value:** "Logging & Alerting Failures"
- **New value:** "Security Logging and Alerting Failures"
- **Type:** rename

### Change 18: CWE Top 25 coverage clarification
- **Source:** S5 Finding
- **Op:** replace
- **Current value:** 25/25 (aspirational)
- **New value:** 20/25 fully detectable + 5/25 partially (memory safety CWEs — Rust mitigates)
- **Type:** correction

### Change 19: Phase 5 Contract Tracking tail
- **Source:** S11 Finding #1
- **Op:** replace
- **Current value:** Phase 5 estimate "4-6 weeks" with no caveat
- **New value:** "4-6 weeks for Phase 5 gate (all systems except Contract Tracking at MVP). Contract Tracking continues through Phases 6-8 (~20 weeks total). Constraint System and DNA System start 0-2 weeks after other P5 systems (waiting for P4)."
- **Type:** timeline

### Change 20: Phase 5 staggered start
- **Source:** S9 Finding #4, S13 Finding #9
- **Op:** replace
- **Current value:** "7 parallel tracks"
- **New value:** 5 immediate tracks (Coupling, Contracts, Constants, Wrappers, Crypto) + 3 delayed tracks (Constraint, DNA, OWASP/CWE) starting after Phase 4
- **Type:** correction

---

## §9 — Phase 6: Enforcement

### Change 21: FP rate target
- **Source:** S6 Finding
- **Op:** replace
- **Current value:** <5% false positive rate
- **New value:** <10% overall, with category-specific sub-targets
- **Type:** architecture

### Change 22: SonarQube reporter
- **Source:** S6 Finding
- **Op:** insert
- **Current value:** 7 reporter formats
- **New value:** 8 reporter formats — add SonarQube Generic Issue Format (P2, post-launch)
- **Type:** missing-item

### Change 23: Health score empirical validation
- **Source:** S6 Finding
- **Op:** replace
- **Current value:** Fixed health score weights
- **New value:** Weights are configurable + plan empirical validation via telemetry post-launch
- **Type:** architecture

### Change 24: Phase 6 internal ordering
- **Source:** S11 Finding #6
- **Op:** replace
- **Current value:** Strict sequential: Rules → Gates → Policy → Audit → Feedback
- **New value:** Partial overlap: Level 0 (Rules Engine + Feedback Loop core), Level 1 (Quality Gates + SARIF), Level 2 (Policy Engine ∥ Audit System), Level 3 (integration)
- **Type:** correction

---

## §10 — Phase 7: Advanced & Capstone

### Change 25: Phase 7 estimate
- **Source:** S7 Finding #13 (OD-5), S11 Finding #9
- **Op:** replace
- **Current value:** "3-4 weeks"
- **New value:** "6-8 weeks with 4 parallel developers" (bounded by Decision Mining at ~8 weeks). Per-system: Simulation ~6w, Decision Mining ~8w, Context Gen ~7w, N+1 ~2w
- **Type:** timeline

### Change 26: Phase 7 hybrid architecture risks
- **Source:** S11 Finding #11
- **Op:** insert
- **Current value:** No integration risk documentation
- **New value:** Add subsection documenting: NAPI v3 boundary for Simulation/Decision Mining, testing strategy (Rust unit + TS integration + cross-boundary), serialization overhead estimates, `async fn` preferred over `AsyncTask` in napi-rs v3
- **Type:** missing-item

### Change 27a: Phase 7 verification gate — strengthen criterion 3
- **Source:** S11 Finding #12, S15 Finding #25
- **Op:** replace
- **Current value:** Criterion 3 (current wording for decision extraction)
- **New value:** "extracts decisions in at least 5 of 12 categories"
- **Type:** missing-item

### Change 27b: Phase 7 verification gate — strengthen criterion 5
- **Source:** S11 Finding #12, S15 Finding #25
- **Op:** replace
- **Current value:** Criterion 5 (current wording for token budget)
- **New value:** "token count within 5% of configured budget"
- **Type:** missing-item

### Change 27c: Phase 7 verification gate — add 3 new criteria
- **Source:** S11 Finding #12, S15 Finding #25
- **Op:** insert
- **Current value:** 7 criteria
- **New value:** Add 3 new criteria: (8) Context gen <100ms full pipeline, (9) NAPI exposes Phase 7 functions, (10) All results persist to drift.db
- **Type:** missing-item

---

## §11 — Phase 8: Presentation

### Change 28: MCP spec version
- **Source:** S7 Finding, S11 Finding #13
- **Op:** replace
- **Current value:** MCP spec 2025-06-18
- **New value:** MCP spec 2025-11-25 (adds CIMD, XAA, mandatory PKCE)
- **Type:** version-bump

### Change 29: Phase 8 estimate
- **Source:** S11 Finding #13
- **Op:** replace
- **Current value:** "3-4 weeks"
- **New value:** "4-5 weeks for Phase 8 gate (MCP core + CLI + CI Agent). Full MCP completion: ~7 weeks per V2-PREP."
- **Type:** timeline

---

## §12 — Phase 9: Bridge & Integration

### Change 30: Phase 9 estimate
- **Source:** S12 Finding #1
- **Op:** replace
- **Current value:** "2-3 weeks"
- **New value:** "3-5 weeks (1 dev), 2-3 weeks (2 devs)" — V2-PREP shows 8 internal phases totaling ~21-26 working days
- **Type:** timeline

### Change 31: License tier naming
- **Source:** S6 (OD-2), S12 Finding #6
- **Op:** replace
- **Current value:** "Professional" / "Pro" in §12.2.6 and §13.2
- **New value:** "Team" — matches SonarQube, Semgrep, Snyk, GitHub convention. Standardize Community / Team / Enterprise everywhere
- **Type:** rename

---

## §13 — Phase 10: Polish & Ship

### Change 32: Phase 10 estimate — team size qualification
- **Source:** S12 Finding #8
- **Op:** replace
- **Current value:** "4-6 weeks"
- **New value:** "4-6 weeks (5+ devs), 8-10 weeks (3 devs), 22-28 weeks (1 dev)". Add P0/P1/P2 prioritization tiers.
- **Type:** timeline

### Change 33: Phase 10 parallelism correction
- **Source:** S12 Finding #9
- **Op:** replace
- **Current value:** "8+ parallel tracks"
- **New value:** 6 immediate tracks + 3 delayed tracks (Docker, VSCode, LSP require P8). VSCode↔LSP share interface dependency.
- **Type:** correction

### Change 34: Add Phase 10 verification gate
- **Source:** S12 Finding #18, S15 Finding #28
- **Op:** insert
- **Current value:** No verification gate for Phase 10
- **New value:** Add §13.8 with 8-12 criteria covering: drift setup, drift doctor, backup, fd-lock, license validation, Docker, VSCode, CIBench
- **Type:** missing-item

---

## §14 — Cross-Phase Dependency Matrix

### Change 35: Remove false N+1→P4 edge
- **Source:** S13 Finding #3
- **Op:** delete
- **Current value:** N+1 Query Detection depends on P4
- **New value:** Remove P4 edge. N+1 needs P0, P1, P2, P7 only. Call graph BFS (P2) suffices; full reachability analysis (P4) not required.
- **Type:** correction

### Change 36: Add soft N+1→P5 edge
- **Source:** S8 Finding, S13 Finding #2a
- **Op:** insert
- **Current value:** No P5 edge for N+1
- **New value:** Add soft/optional P5 edge with note: "Basic N+1 works with P2 ORM matchers. Advanced ORM coverage improves with P5 ULP matchers."
- **Type:** missing-item

### Change 37: Do NOT add Context Gen→P4 edge
- **Source:** S13 Finding #2b (overrules S8)
- **Op:** skip (no edit — this documents a rejected suggestion)
- **Current value:** No P4 edge for Context Generation
- **New value:** No change. V2-PREP §29 upstream table shows no P4 dependency. S8's recommendation overruled.
- **Type:** correction

### Change 38: System count in matrix
- **Source:** S13 Finding #1
- **Op:** replace
- **Current value:** Claims "60 systems"
- **New value:** Matrix has 55 rows. Update all references.
- **Type:** correction

---

## §15 — Parallelization Map

### Change 39: Add 1.3x realistic timeline column
- **Source:** S8 Finding, S13 Finding #8
- **Op:** insert
- **Current value:** Single optimistic timeline per team size
- **New value:** Add column: 1-dev 8-10mo, 2-dev 5-6.5mo, 3-4 dev 4-5mo, 5+ dev 3-4mo
- **Type:** timeline

### Change 40: Critical path correction
- **Source:** S8 Finding, S13 Finding #7
- **Op:** replace
- **Current value:** "12-16 weeks"
- **New value:** "12-16 weeks optimistic, 16-21 weeks realistic (1.3x overconfidence correction)"
- **Type:** timeline

---

## §16 — Risk Register

### Change 41: Update R1
- **Source:** S14 Finding A1
- **Op:** replace
- **Current value:** "tree-sitter v0.24"
- **New value:** "tree-sitter v0.25" in heading and body. Severity unchanged (Medium).
- **Type:** version-bump

### Change 42: Update R6
- **Source:** S14 Finding A6
- **Op:** replace
- **Current value:** "~30 GAST node types", severity Medium
- **New value:** "~40-50 GAST node types", severity Medium-High. Add coverage_report() requirement.
- **Type:** architecture

### Change 43: Update R11
- **Source:** S14 Finding A10
- **Op:** replace
- **Current value:** References rusqlite 0.32, petgraph 0.6
- **New value:** References rusqlite 0.38, petgraph 0.8, tree-sitter 0.25. Downgrade severity Medium → Low (workspace dependency inheritance resolves conflicts).
- **Type:** version-bump

### Change 44: Add R17 — SQLite Schema Complexity
- **Source:** S8 Finding, S14 Finding A12
- **Op:** insert
- **Current value:** No R17
- **New value:** "drift.db grows to 55-65 tables with 180+ total objects. Mitigation: rusqlite_migration uses user_version (fast), cache schema version, skip full validation on match."
- **Type:** missing-item

### Change 45: Add R18 — Estimation Overconfidence
- **Source:** S8 Finding, S14 Finding A13
- **Op:** insert
- **Current value:** No R18
- **New value:** "~30% average overrun. Apply 1.3x for planning. Critical path 12-16w → 16-21w. 1-dev 6-8mo → 8-10mo."
- **Type:** missing-item

### Change 46: Add R19 — NAPI v2→v3 Divergence
- **Source:** S8 Finding, S14 Finding A14
- **Op:** insert
- **Current value:** No R19
- **New value:** "Cortex uses napi v2; Drift targets v3 (3.8.x). ThreadsafeFunction, AsyncTask, Function/FunctionRef differ. Mitigation: v2→v3 cheat sheet before Phase 1."
- **Type:** missing-item

### Change 47: Add R20 — Parallel Dev Coordination
- **Source:** S8 Finding, S14 Finding A15
- **Op:** insert
- **Current value:** No R20
- **New value:** "Phases 4-5 offer 5+7 parallel tracks. Communication overhead scales quadratically. Mitigation: freeze drift-core types before parallel tracks, assign integration lead, cap at 3-4 devs."
- **Type:** missing-item

---

## §18 — Cortex Pattern Reuse Guide

### Change 48: Fix NAPI module count
- **Source:** S8 Finding, S14 Finding B2
- **Op:** replace
- **Current value:** "12 modules"
- **New value:** "14 modules" (causal, cloud, consolidation, generation, health, learning, lifecycle, memory, multiagent, prediction, privacy, retrieval, session, temporal)
- **Type:** correction

### Change 49: Fix Mutex type
- **Source:** S8 Finding, S14 Finding B3
- **Op:** replace
- **Current value:** "`Mutex<Connection>` writer" (implies std::sync)
- **New value:** "`tokio::sync::Mutex<Connection>` writer" — Drift should use `std::sync::Mutex` since Drift has no async runtime
- **Type:** correction

### Change 50: Fix crate count
- **Source:** S8 Finding, S14 Finding B4
- **Op:** replace
- **Current value:** "19 crates"
- **New value:** "21 crates (plus test-fixtures)" — cortex-crdt and cortex-multiagent added since original count
- **Type:** correction

### Change 51: Fix similarity description
- **Source:** S8 Finding, S14 Finding B5
- **Op:** replace
- **Current value:** "Cosine similarity, Jaccard similarity"
- **New value:** "Cosine similarity only" — no Jaccard in Cortex. Drift must implement Jaccard from scratch or use a crate.
- **Type:** correction

### Change 52: Add conversions/ pattern (#13)
- **Source:** S8 Finding, S14 Finding B6
- **Op:** insert
- **Current value:** 12 reuse patterns
- **New value:** 13 patterns — add `cortex-napi/src/conversions/` (7 per-domain conversion files)
- **Type:** missing-item

### Change 53: Add NAPI v2→v3 adaptation note
- **Source:** S8 Finding, S14 Finding B7
- **Op:** insert
- **Current value:** No version adaptation guidance
- **New value:** Add section: ThreadsafeFunction (ownership-based in v3), AsyncTask (prefer `async fn` in v3), Function/FunctionRef (new types), error handling differences
- **Type:** missing-item

---

## §18.1 — Performance Targets

### Change 54: Add 7 missing performance targets
- **Source:** S8 Finding, S14 Finding C2, S15 Finding #7
- **Op:** insert
- **Current value:** ~12 targets
- **New value:** ~19 targets. Add:
  - Error Handling: <5ms per file topology construction
  - Coupling: <1s for 5K-module Tarjan SCC + Martin metrics
  - Wrapper Detection: <2ms per file for 150+ pattern RegexSet
  - Violation Feedback: FP rate <10% overall
  - Context Generation: <50ms standard, <100ms full pipeline
  - N+1 Detection: <10ms per query site
  - Workspace: init <500ms, backup <5s for 100MB db
- **Type:** missing-item

### Change 54a: Add fallback thresholds for 5 tight existing targets
- **Source:** S14 Finding C1 (5 targets marked ⚠️ in performance audit)
- **Op:** replace
- **Current value:** Targets have single threshold only
- **New value:** Add "target / acceptable fallback" pairs: UAE 10K files <10s / <15s, CTE query <50ms / <100ms, taint interprocedural <100ms/fn / <200ms/fn, MCP drift_context <100ms / <200ms. Replace qualitative "parsers single-pass shared" with measurable "Parse 10K files <5s".
- **Type:** missing-item

---

## §18.2 — Schema Progression

### Change 55: Revise cumulative table counts
- **Source:** S8 Finding, S14 Finding D1
- **Op:** replace
- **Current value → New value:**
  - Phase 5: ~40-45 → ~48-56
  - Phase 6: ~48-52 → ~55-62
  - Phase 7: ~55 → ~58-65
- **Type:** correction

---

## §18.3 — NAPI Function Counts

### Change 56: Revise cumulative NAPI counts
- **Source:** S8 Finding, S14 Finding E1, S15 Finding #3
- **Op:** replace
- **Current value:** Phase 9 cumulative: 42-53
- **New value:** ~55 top-level exports. Add note distinguishing top-level exports (~55) from total per-system functions (~70-85).
- **Type:** correction

---

## §19 — Verification Gates & Milestones

### Change 57: M3 "It Learns" — add concrete criteria
- **Source:** S8 Finding, S15 Milestone Audit
- **Op:** replace
- **Current value:** "Patterns are scored, ranked, and learned. Drift is now self-configuring."
- **New value:** "Run on 3 test repos. Verify: (a) conventions discovered without config, (b) confidence scores non-trivial, (c) ≥1 convention reaches 'Universal' per repo, (d) ≥1 genuine outlier flagged per repo."
- **Type:** correction

### Change 58: M7 "It Grounds" — add concrete criteria
- **Source:** S8 Finding, S15 Milestone Audit
- **Op:** replace
- **Current value:** "The Cortex-Drift bridge enables empirically validated AI memory."
- **New value:** "Create Cortex memory via bridge. Verify: (a) confidence updated from scan data, (b) ≥1 grounding result per groundable type (13/23), (c) threshold tiers classify correctly (≥0.7/≥0.4/≥0.2/<0.2)."
- **Type:** correction

### Change 59: Add Phase 5→6 precondition gate
- **Source:** S8 Finding, S15 Finding #30
- **Op:** insert
- **Current value:** No precondition between Phase 5 and Phase 6
- **New value:** 4 criteria: (1) coupling metrics for ≥3 modules, (2) ≥1 constraint passing, (3) ≥1 API contract tracked, (4) DNA profile for ≥1 gene
- **Type:** missing-item

### Change 60: Milestone timing corrections (all 8 milestones)
- **Source:** S11 Finding #17, S12 Finding #14, S15 Milestone Audit
- **Op:** replace
- **Current value → New value:**
  - M1 "It Scans": ~3-5w → ~4-6.5w (with 1.3x)
  - M2 "It Detects": ~6-9w → ~8-12w (with 1.3x)
  - M3 "It Learns": ~9-13w → ~12-17w (with 1.3x)
  - M4 "It Secures": ~10-15w → ~13-19.5w (with 1.3x)
  - M5 "It Enforces": ~12-16w → ~16-22w (with 1.3x)
  - M6 "It Ships": ~14-20w → ~18-24w (with 1.3x)
  - M7 "It Grounds": ~16-22w → ~17-25w (Phase 9 underestimate)
  - M8 "It's Complete": ~20-28w → ~18-26w (5+ devs), ~22-30w (3 devs)
- **Type:** timeline

---

### Change 60a: §9.2/§9.4 QG spec coverage annotations
- **Source:** S15 §20.6 (OD-3 resolution requires plan annotations)
- **Op:** insert
- **Current value:** §9.2 (Rules Engine) and §9.4 (Policy Engine) have no spec coverage note
- **New value:** §9.2 annotate: "Implemented within each gate's evaluate() method. See 09-QG-V2-PREP §5, §18, §24." §9.4 annotate: "Fully specified in 09-QG-V2-PREP §7. No separate spec needed."
- **Type:** correction

---

## §20 — Gap Analysis

### Change 61: MCP tool counts
- **Source:** S15 Finding #9
- **Op:** replace
- **Current value:** §11.1 says "~20-25 tools" analysis, "~15-20 tools" memory
- **New value:** ~52 analysis tools (3 MCP entry points + 49 via dispatch), ~33 memory tools (3 entry points + 30 via dispatch). Progressive disclosure reduces token overhead ~81%.
- **Type:** correction

---

---

## Audit Metadata (informational — do not apply as edits)

### Aggregate Statistics

| Type | Count | Examples |
|------|-------|---------|
| version-bump | 13 | tree-sitter 0.25, rusqlite 0.38, petgraph 0.8, statrs 0.18, MCP 2025-11-25, R1/R11 updates |
| architecture | 8 | GAST ~40-50, taint +2 sinks, FP <10%, health score config, secret 150+, panic=abort, CTE fallback, drift-context |
| timeline | 9 | Phase 7 6-8w, Phase 8 4-5w, Phase 9 3-5w, Phase 10 team-qualified, critical path 16-21w, M1-M8 corrections (all 8 milestones), UAE 22-27w |
| missing-item | 15 | R17-R20, Phase 10 gate, Phase 5→6 gate, 7 perf targets, fallback thresholds, N+1→P5 edge, conversions pattern, v2→v3 note, hybrid arch risks, gate criteria additions |
| correction | 16 | System count 55, NAPI counts, schema counts, consumer counts, Phase 5 stagger, Phase 1 parallelism, N+1→P4 false edge, MCP tool counts, M3/M7 criteria, feature flag default, scan perf targets, §9.2/§9.4 annotations |
| rename | 4 | Medallion terminology, OWASP A09, tier Professional→Team, similarity cosine-only |
| **Total** | **66** | |

### Verdict Counts

| Metric | Round 1 (S1-S8) | Round 2 (S9-S16) | Combined |
|--------|----------------|-----------------|----------|
| CONFIRMED | 73 | 45 | **118** |
| REVISE | 29 | 23 | **52** |
| REJECT | 0 | 0 | **0** |
| RESOLVED (ODs) | 3 | 0 | **3** |
| APPLIED | 0 | 19 | **19** |
| **Total decisions** | **105** | **87** | **192** |

---

## Resolved Open Decisions

| OD | Question | Resolution | Source |
|----|----------|------------|--------|
| OD-1 | drift-context as separate crate? | Yes — 6th crate isolating tiktoken-rs, quick-xml, serde_yaml, glob, base64 | S1 |
| OD-2 | "Professional" vs "Team" tier? | "Team" — matches SonarQube, Semgrep, Snyk, GitHub convention | S6 |
| OD-3 | Rules/Policy Engine need separate specs? | No — covered by 09-QG-V2-PREP §5 and §7 | S6 |
| OD-4 | File numbering conflict (16-IMPACT)? | Filesystem cleanup — rename to 17-IMPACT. No orchestration impact | S15 |
| OD-5 | Phase 7 + Phase 10 timeline? | Resolved — Phase 7 revised to 6-8w, Phase 10 team-size-qualified | S7 |

---

## Pre-Implementation Blockers

**Zero hard blockers.** Phase 0 can start immediately.

Soft blockers (address before or during Phase 0):

| # | Item | Severity | When |
|---|------|----------|------|
| 1 | Apply version bumps to §3.1 Cargo.toml | Low | Before Phase 0 |
| 2 | Sections 9, 10, 11, 15 were not completed in original audit plan — all 4 were subsequently completed and findings are incorporated in this manifest | Resolved | N/A |
| 3 | tree-sitter 0.25 vs 0.26 grammar compat | Low | Phase 0 (pin 0.25, evaluate 0.26 post-Phase 1) |
| 4 | statrs 0.17 → 0.18 | Low | Phase 0 (use 0.18) |
| 5 | Tier naming standardization (Professional→Team) | Low | Before Phase 5 |
| 6 | Phase 10 verification gate missing | Low | Before Phase 10 |
| 7 | N+1→P4 false edge in dependency matrix | Low | Before Phase 7 |
| 8 | System count "60" → "~55" in §2 header | Low | Before implementation |
| 9 | Verify rusqlite 0.38 exists on crates.io (S2 noted lib.rs showed 0.36.x–0.37.x) | Low | Phase 0 |

---

## Corrected §3.1 Cargo.toml

Verbatim from S16 Part E, Section E3 — all Round 1 + Round 2 version bumps applied:

```toml
[workspace]
members = [
    "drift-core",
    "drift-analysis",
    "drift-storage",
    "drift-context",      # 6th crate (OD-1 resolution)
    "drift-napi",
    "drift-bench",
]

[workspace.dependencies]
tree-sitter = "0.25"          # Was "0.24". 0.26.x exists but 0.25 safer for grammar compat
rusqlite = { version = "0.38", features = ["bundled", "backup", "blob"] }  # Was "0.32"
napi = { version = "3", features = ["async", "serde-json"] }
thiserror = "2"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
rustc-hash = "2"
smallvec = "1"                # Was "1.13". "1" resolves to latest 1.x
lasso = { version = "0.7", features = ["multi-threaded", "serialize"] }
rayon = "1.10"
xxhash-rust = { version = "0.8", features = ["xxh3"] }
petgraph = "0.8"              # Was "0.6". stable_graph is default feature
moka = { version = "0.12", features = ["sync"] }
ignore = "0.4"
crossbeam-channel = "0.5"     # Resolves to ≥0.5.15 (RUSTSEC-2025-0024 patched)
serde = { version = "1", features = ["derive"] }
serde_json = "1"
statrs = "0.18"               # Was "0.17" (implicit). 0.18.0 released Dec 2024
git2 = "0.20"                 # Was "0.19". Bundles libgit2 1.9
tiktoken-rs = "0.9"           # Was "0.6". Adds o200k_harmony, GPT-5 support
fd-lock = "4"                 # Was unspecified. Pin for workspace management

# drift-context dependencies (6th crate)
quick-xml = "0.37"
serde_yaml = "0.9"
glob = "0.3"
base64 = "0.22"

[profile.release]
lto = true
codegen-units = 1
opt-level = 3
strip = "symbols"
panic = "abort"               # Added per S1. Matches Cortex workspace
```


---

## Verification Checklist (agent must confirm after all edits)

- [ ] Every §section referenced in this manifest was modified
- [ ] No §section NOT referenced in this manifest was modified
- [ ] §3.1 Cargo.toml matches the Corrected block above verbatim
- [ ] All `Op: insert` items have content matching the format of adjacent entries in their section
- [ ] All `Op: replace` items had their old value found and swapped
- [ ] All `Op: delete` items had their target removed
- [ ] Change 37 (`Op: skip`) was NOT applied — it documents a rejected suggestion
- [ ] System count references updated globally ("60" → "~55") per Changes 1 and 38
- [ ] License tier naming updated globally ("Professional"/"Pro" → "Team") per Change 31
- [ ] Total edits applied: 66 changes (excluding Change 37 skip)
