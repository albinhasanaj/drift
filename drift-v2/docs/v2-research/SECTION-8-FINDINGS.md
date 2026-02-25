# Section 8 Findings: Cross-Cutting Concerns

> **Status:** ✅ DONE
> **Date completed:** 2026-02-08
> **Orchestration plan:** §14-19 (matrices, parallelization, risks, cortex patterns, gates)
>
> **Summary: 5 CONFIRMED, 5 REVISE, 0 REJECT**
>
> This document contains the full research findings for Section 8 of DRIFT-V2-FINAL-RESEARCH-TRACKER.md.
> The tracker file itself should be updated to mark Section 8 as ✅ DONE and reference this file.

---

## Checklist (all validated)

- [x] Cross-phase dependency matrix — any missing edges?
- [x] Parallelization map — any false parallelism (hidden dependencies)?
- [x] Risk register R1-R16 — any missing risks?
- [x] Cortex pattern reuse guide — patterns still valid against current cortex codebase?
- [x] Performance target summary — all targets realistic and measurable?
- [x] Storage schema progression — cumulative counts accurate?
- [x] NAPI function count progression — accurate after per-system reconciliation?
- [x] Verification gates — are they testable and sufficient?
- [x] Team size recommendations — realistic given per-system estimates?
- [x] Critical path calculation (12-16 weeks) — still accurate?

---

## Findings

### 1. Cross-Phase Dependency Matrix — ⚠️ REVISE: 4 Missing Edges, 2 Incorrect Entries

The §14 dependency matrix maps 55 systems against 10 phases (P0-P9). I audited every row against the V2-PREP documents and the phase descriptions in §3-§13.

**Missing edges identified:**

1. **OWASP/CWE Mapping → Phase 4 (P4) dependency is questionable.** The matrix marks OWASP/CWE as depending on P4 (Graph Intelligence). However, 26-OWASP-CWE-MAPPING-V2-PREP describes a pattern-to-CWE mapping system that operates on detected patterns (Phase 2 output) and taint flows (Phase 4 output). The P4 dependency is correct only for taint-informed CWE mappings (e.g., CWE-89 SQL injection requires taint paths). For the majority of CWE mappings (pattern-based), only P2 is needed. **Recommendation**: Keep the P4 edge but add a note that OWASP/CWE can ship a partial version (pattern-based mappings) after P2, with taint-informed mappings added after P4.

2. **N+1 Query Detection → Phase 5 (P5) dependency is missing.** The matrix shows N+1 depending on P0, P1, P2, P4, P7. However, N+1 detection requires ORM boundary information from the Boundary Detection system (Phase 2) AND the Unified Language Provider's ORM pattern matching (Phase 2/5). The ULP's ORM matchers are built incrementally through Phase 5. If N+1 detection needs mature ORM pattern matching (e.g., Prisma's `findMany` inside a loop), it implicitly depends on Phase 5 ULP matchers being available. **Recommendation**: Add a P5 edge for N+1 Query Detection, or document that N+1 ships with basic ORM detection (Phase 2 level) and improves as ULP matchers mature.

3. **Context Generation → Phase 4 (P4) dependency may be understated.** The matrix shows Context Generation depending on P0-P3, P5, P7. However, 30-CONTEXT-GENERATION-V2-PREP §8 describes including taint analysis results and reachability data in generated context. These come from Phase 4. The context generator can function without P4 data (it's optional enrichment), but the dependency should be noted as a soft edge. **Recommendation**: Add a soft/optional P4 edge for Context Generation.

4. **Constraint System → Phase 4 (P4) dependency is already marked but the reason should be documented.** The matrix correctly shows Constraints depending on P4. This is because the `DataFlow` invariant type (one of the 12 constraint types) requires taint analysis results. The `MustPrecede` and `MustFollow` invariants require call graph reachability (also P4). This edge is correct and well-justified.

**Incorrect entries identified:**

1. **The matrix lists 55 rows but the Summary (§20) claims 60 systems.** The gap analysis (§20.16) already flags this. After auditing, the actual count is: 35 specced systems + 9 unspecced systems + ~6 Phase 0 infrastructure primitives (Config, thiserror, tracing, DriftEventHandler, String Interning, data structures) + Rules Engine + Policy Engine = ~52-53 distinct systems. The "60 systems" claim includes sub-components counted as separate systems (e.g., SARIF Reporter counted separately from other reporters). **Recommendation**: Clarify the system count. Use "~53 systems" for the distinct count, or "60 systems including sub-components" if the broader definition is intended.

2. **CIBench row shows dependencies on P0, P1, P2 only.** This is correct for the benchmark framework itself, but CIBench's value comes from benchmarking systems across all phases. It should be noted that CIBench is useful from Phase 1 onward but gains benchmarks incrementally as each phase ships. This isn't a missing dependency edge — CIBench doesn't *require* later phases to build — but the matrix could mislead someone into thinking CIBench is "done" after Phase 2.

**Overall assessment**: The dependency matrix is fundamentally sound. The 4 issues above are refinements, not structural errors. The matrix correctly captures the critical path dependencies and the parallelization opportunities. The most important edges (Phase 2 → Phase 3, Phase 3 → Phase 6, Phase 6 → Phase 8) are all correct.

---

### 2. Parallelization Map — ✅ CONFIRMED (with 2 notes)

The §15 parallelization map describes maximum parallelism per phase. I validated each phase's parallelism claims against the dependency matrix and V2-PREP documents.

**Phase-by-phase validation:**

**Phase 0 (Sequential, 1 track)**: ✅ Correct. Config → errors → tracing → events → data structures is a strict dependency chain. Each primitive is consumed by the next.

**Phase 1 (Sequential, 1 track)**: ✅ Correct with nuance. The plan says "Scanner → Parsers → Storage → NAPI. Each system's output is the next system's input." This is mostly true: Scanner produces `FileMetadata`, Parsers consume it and produce `ParseResult`, Storage persists both. However, Storage and NAPI don't have a strict sequential dependency — Storage needs Scanner+Parser output schemas (to define tables), and NAPI needs Storage (to expose query functions). A developer could start NAPI binding stubs while Storage is being built, as long as the Rust types are defined. The plan already notes "Two developers can overlap (one on scanner+parsers, one on storage+NAPI)." This is correct.

**Phase 2 (2 parallel tracks)**: ✅ Correct. Track A (UAE + Detectors) and Track B (Call Graph + Boundaries + ULP) share only `ParseResult` as a read-only input. Validated in Section 3 findings — zero cross-dependencies.

**Phase 3 (Limited parallelism, 1-2 tracks)**: ✅ Correct. Pattern Aggregation → Confidence Scoring is a strict chain (confidence scoring needs aggregated patterns). Outlier Detection and Learning System can run in parallel after Confidence Scoring. The internal dependency chain limits parallelism to 1-2 tracks.

**Phase 4 (5 parallel tracks)**: ✅ Correct. Reachability, Taint, Error Handling, Impact, and Test Topology are all independent. Each consumes the call graph (Phase 2 output) but none depends on another Phase 4 system's output. This is the widest parallelization opportunity.

**Phase 5 (7 parallel tracks)**: ✅ Correct with one note. Coupling, Constraints, Contracts, Constants, Wrappers, Crypto, and OWASP/CWE are mostly independent. **Note 1**: The Constraint System depends on Phase 4 (taint analysis for DataFlow invariants), so it can't start until Phase 4 completes. The other 6 systems can start as soon as Phase 2 is done. The DNA System is listed as starting with "parser-only extractors" and adding others incrementally — this is correct, DNA's gene extractors can run on ParseResult alone. **Note 2**: OWASP/CWE Mapping depends on Phase 4 for taint-informed CWE mappings (per finding #1 above). A partial version (pattern-based CWEs) can ship without Phase 4.

**Phase 6 (Mostly sequential, 1-2 tracks)**: ✅ Correct. Rules Engine → Quality Gates → Policy Engine → Audit System is a dependency chain. Violation Feedback Loop can run in parallel with Policy/Audit (it depends on Quality Gates output, not Policy/Audit output). The circular dependency between QG and Feedback is resolved via the `FeedbackStatsProvider` trait (validated in Section 6 findings).

**Phase 7 (4 parallel tracks)**: ✅ Correct. Simulation, Decision Mining, Context Generation, and N+1 are all independent leaf systems.

**Phase 8 (3 parallel tracks)**: ✅ Correct. MCP Server, CLI, and CI Agent are all independent presentation consumers.

**Phase 9 (Sequential, 1 track)**: ✅ Correct. The bridge is a single system.

**Phase 10 (8+ parallel tracks)**: ✅ Correct. All remaining systems are independent.

**Hidden dependency check**: I specifically looked for cases where two "parallel" systems might share mutable state or require coordination. Found none — all parallel systems within each phase consume read-only outputs from prior phases. The string interning layer (lasso `RodeoReader`) is frozen after Phase 1. The parse cache (moka) is read-only during analysis phases. The SQLite write connection is serialized by design, so parallel systems writing to different tables don't conflict.

**Verdict**: The parallelization map is accurate. No false parallelism detected. The two notes above (Constraint System's P4 dependency, OWASP/CWE's partial P4 dependency) are already captured in the dependency matrix — they don't invalidate the parallelization claims, they just mean those specific systems start slightly later within their phase.

---

### 3. Risk Register R1-R16 — ⚠️ REVISE: 4 Missing Risks, 2 Severity Adjustments

The risk register covers R1-R11 in §16 and R12-R16 in §20.13 (gap analysis). I audited all 16 risks for completeness, accuracy, and missing risks.

**Existing risks — severity assessment:**

| Risk | Current Assessment | My Assessment | Notes |
|------|-------------------|---------------|-------|
| R1: tree-sitter grammar compat | Correct | ⚠️ Upgrade to 0.25 (per Section 1) changes the risk profile | Section 1 revised tree-sitter from 0.24→0.25. R1 should reference 0.25, not 0.24. Grammar compatibility for 0.25 is better than 0.24 (more grammars have updated). Risk is lower than originally stated. |
| R2: napi-rs v3 maturity | Correct | ✅ Risk is lower than stated | NAPI-RS v3 has been stable since Jul 2025 (7+ months). Rolldown, Rspack, and Oxc are production users. The "newer than v2" framing understates v3's maturity. |
| R3: Taint analysis complexity | Correct | ✅ Accurate | Still the largest net-new system. Intraprocedural-first mitigation is sound. |
| R4: SQLite performance at scale | Correct | ✅ Accurate | WAL mode + covering indexes + keyset pagination is the standard approach. |
| R5: Detector count (350+) | Correct | ✅ Accurate | Mechanical but time-consuming. 50-80 high-value first is the right strategy. |
| R6: Cross-language GAST | Correct | ⚠️ Severity should be HIGHER | Section 3 findings revised GAST from 26 to ~40-50 node types. This increases the normalization effort per language. The risk of edge cases producing incorrect cross-language analysis is higher with more node types. |
| R7: Build time | Correct | ✅ Accurate | Standard mitigations (nextest, sccache, feature flags). |
| R8: UAE 22-week timeline | Correct | ✅ Accurate | Section 3 findings added 20% risk buffer (22-27 weeks realistic). |
| R9: Contract tracking scope | Correct | ✅ Accurate | REST + GraphQL first is the right phased approach. |
| R10: macOS APFS scanner | Correct | ✅ Accurate | Platform constraint, not a bug. |
| R11: Cargo version inconsistencies | Correct | ⚠️ Partially resolved | Section 1 revised several versions (rusqlite 0.32→0.38, petgraph 0.6→0.8, tree-sitter 0.24→0.25). R11 should be updated to reflect the new version pins. The bridge doc's thiserror=1 and rusqlite=0.31 are even more outdated now. |
| R12: tiktoken-rs platform | Correct | ✅ Accurate | Fallback chain is well-designed. |
| R13: Violation feedback retention | Correct | ✅ Accurate | Archival strategy needed for large projects. |
| R14: MCP progressive disclosure UX | Correct | ✅ Accurate | 3-tier pattern may confuse some AI clients. |
| R15: Simulation hybrid architecture | Correct | ✅ Accurate | Rust/TS split adds complexity. |
| R16: Workspace 16 NAPI functions | Correct | ✅ Accurate | Largest single-system NAPI surface. |

**Missing risks identified:**

**R17: SQLite Schema Complexity at 50+ Tables**

The §18.2 schema progression shows drift.db growing to 48-52 tables by Phase 6, plus 4 bridge tables. A [Turso blog post](https://turso.tech/blog/faster-schema-changes-for-sqlite-databases) documents that SQLite schema changes become slow with hundreds of tables because SQLite re-parses the entire schema on every connection open and every DDL statement. At 50+ tables, this is unlikely to be a problem (the threshold is typically 200+ tables), but the incremental migration approach means every `rusqlite_migration` run re-validates the full schema.

**Risk**: Schema migration time increases as table count grows. At 50+ tables with covering indexes, partial indexes, and triggers, the migration validation on startup could take 100-500ms.
**Impact**: Slower `drift_initialize()` cold start.
**Mitigation**: Cache the schema version in a lightweight file alongside drift.db. Skip migration validation if the cached version matches the expected version. Only run full migration on version mismatch. This is a standard pattern used by Django and Rails.

**R18: Estimation Overconfidence Bias**

Research on software effort estimation consistently shows that developers are overconfident in their estimates. A well-documented finding shows that when professionals are "90% confident" their estimate range includes the actual effort, the observed frequency is only 60-70%. The average overrun across software projects is approximately 30%.

The orchestration plan contains per-system estimates from V2-PREP documents (Scanner: 6-9 days, Context Generation: ~7 weeks, Contract Tracking: ~20 weeks, etc.) and phase-level estimates (Phase 2: 3-4 weeks, Phase 7: 3-4 weeks). These estimates are point estimates or narrow ranges, not probability distributions.

**Risk**: Systematic underestimation across all phases. If each phase overruns by the industry-average 30%, the critical path extends from 12-16 weeks to 16-21 weeks.
**Impact**: Timeline slippage, especially on the critical path.
**Mitigation**: Apply a 1.3x multiplier to all estimates for planning purposes (not for developer communication — that creates Parkinson's Law effects). Use the V2-PREP per-system estimates as the "optimistic" bound and 1.5x as the "pessimistic" bound. Track actual vs estimated at each milestone gate. The Section 3 findings already recommended a 20% risk buffer for the UAE — extend this practice to all phases.

**R19: Cortex NAPI v2 → Drift NAPI v3 Pattern Divergence**

The Cortex workspace currently uses `napi = "2"` and `napi-derive = "2"` (confirmed from `crates/cortex/Cargo.toml`). The Drift plan specifies `napi = "3"` (confirmed and validated in Section 1). The Cortex Pattern Reuse Guide (§18) recommends copying patterns from Cortex's NAPI bindings.

**Risk**: NAPI v2 patterns from Cortex may not translate directly to v3. Key v3 changes include: redesigned `ThreadsafeFunction` with ownership-based lifecycle, new `Function`/`FunctionRef` types, changed `AsyncTask` API, and different error handling patterns. Developers copying Cortex patterns verbatim will hit compilation errors.
**Impact**: Slower development velocity in Phase 1 (NAPI bridge) as developers adapt v2 patterns to v3.
**Mitigation**: Create a "v2→v3 migration cheat sheet" before Phase 1 starts. Document the specific API changes for each pattern in the reuse guide. The NAPI-RS v3 announcement blog and migration guide cover the key differences. Alternatively, update the Cortex workspace to NAPI v3 first (separate effort) so patterns are directly reusable.

**R20: Phase 4+5 Parallel Developer Coordination**

Phases 4 and 5 offer 5 and 7 parallel tracks respectively — the widest parallelism in the build. The team size recommendations (§15) suggest 5+ developers for maximum parallelism. However, Brooks's Law ("adding manpower to a late software project makes it later") applies even to parallel tracks because:
- All parallel tracks write to the same drift.db (serialized writer, but schema coordination needed)
- All parallel tracks consume shared types from drift-core (type changes require coordination)
- All parallel tracks need code review, CI resources, and merge coordination
- Onboarding new developers to the codebase takes time even with good documentation

**Risk**: Communication overhead scales quadratically with team size. 5 developers on 5 parallel tracks need 10 communication channels; 7 developers on 7 tracks need 21 channels.
**Impact**: Phases 4-5 take longer than the parallelization map suggests if the team scales up specifically for these phases.
**Mitigation**: The plan's architecture already mitigates this well — each parallel track has its own V2-PREP spec, its own SQLite tables, its own NAPI functions, and its own test suite. The shared surface area (drift-core types, storage schema) should be frozen before parallel tracks begin. Assign one developer as "integration lead" during Phases 4-5 to handle merge conflicts and schema coordination. Don't scale beyond 3-4 developers unless they're already familiar with the codebase.

---

### 4. Cortex Pattern Reuse Guide — ⚠️ REVISE: All 12 Patterns Valid, But 3 Corrections Needed

I validated all 12 patterns in §18 against the current Cortex codebase. Every file and directory referenced in the guide exists and contains the described pattern. However, 3 factual corrections are needed.

**Pattern-by-pattern validation:**

| # | Pattern | File/Dir | Status | Notes |
|---|---------|----------|--------|-------|
| 1 | OnceLock Singleton | `cortex-napi/src/runtime.rs` | ✅ Valid | `static RUNTIME: OnceLock<Arc<CortexRuntime>>` confirmed. Owns 14 engines. |
| 2 | NAPI Bindings | `cortex-napi/src/bindings/` | ⚠️ Count wrong | Guide says "12 modules" — actual count is **14 modules** (causal, cloud, consolidation, generation, health, learning, lifecycle, memory, multiagent, prediction, privacy, retrieval, session, temporal). |
| 3 | Write-Serialized + Read-Pooled | `cortex-storage/src/pool/` | ⚠️ Implementation detail | Guide says `Mutex<Connection>` writer. Actual: `tokio::sync::Mutex<Connection>` (async mutex, not std). Drift uses sync Rust (rayon, not tokio), so the pattern needs adaptation: use `std::sync::Mutex<Connection>` instead. |
| 4 | Batch Writer | `cortex-storage/src/queries/` | ✅ Valid | 18 query modules confirmed. Domain-organized query builders with `prepare_cached()`. |
| 5 | Health Monitoring | `cortex-observability/src/health/` | ✅ Valid | `HealthChecker` implements `IHealthReporter` trait. `HealthReporter` builds snapshots. |
| 6 | Degradation Tracking | `cortex-observability/src/degradation/` | ✅ Valid | `DegradationTracker` with `RecoveryStatus` (Active/Recovered). `record()`, `mark_recovered()`, `active_degradations()`. |
| 7 | Tarjan's SCC | `cortex-causal/src/graph/dag_enforcement.rs` | ✅ Valid | `petgraph::algo::tarjan_scc` imported and used. `would_create_cycle()` + `has_path()` DFS. |
| 8 | Similarity Scoring | `cortex-consolidation/src/algorithms/similarity.rs` | ✅ Valid | `cosine_similarity()` with `NOVELTY_THRESHOLD=0.85` and `OVERLAP_THRESHOLD=0.90`. Note: Jaccard similarity is NOT in this file — it's cosine only. Drift's pattern aggregation uses Jaccard (validated in Section 4), which is a different algorithm. |
| 9 | Deduplication | `cortex-retrieval/src/ranking/deduplication.rs` | ✅ Valid | Session-aware dedup with `HashSet<&str>` for sent IDs. Pre-sorted by score, first wins. |
| 10 | Error Types | `cortex-core/src/errors/cortex_error.rs` | ✅ Valid | `#[derive(Debug, thiserror::Error)]` with 16+ variants. `#[from]` for subsystem error conversion. 10 error files total. |
| 11 | Audit Logging | `cortex-storage/src/migrations/v006_audit_tables.rs` | ✅ Valid | `memory_audit_log` table with id, memory_id, operation, details, actor, timestamp. Indexes on memory_id, operation, timestamp, actor. |
| 12 | NAPI Error Codes | `cortex-napi/src/conversions/error_types.rs` | ✅ Valid | 18 error code constants. `to_napi_error()` maps `CortexError` → `napi::Error` with structured codes. |

**Corrections needed:**

1. **§18 says "12 modules" for NAPI bindings — actual is 14.** Update the guide to say "14 modules" and list them. This matters because Drift's NAPI module count (~14 modules per §18.3) is directly informed by the Cortex reference.

2. **§18 says `Mutex<Connection>` for write connection — actual is `tokio::sync::Mutex<Connection>`.** Cortex uses tokio's async mutex because Cortex is an async system (tokio runtime). Drift is a sync system (rayon for parallelism, no tokio). The pattern needs adaptation: Drift should use `std::sync::Mutex<Connection>` for the write connection. The read pool already uses `std::sync::Mutex<Connection>` in Cortex (confirmed in `read_pool.rs`), so the asymmetry is Cortex-specific. **Add a note to the reuse guide**: "Drift uses `std::sync::Mutex` (not `tokio::sync::Mutex`) because Drift doesn't use an async runtime."

3. **§18 says Cortex has "19 crates" — actual workspace has 22 members** (21 crates + test-fixtures). The Cargo.toml `[workspace] members` list includes: cortex-core, cortex-tokens, cortex-storage, cortex-embeddings, cortex-privacy, cortex-compression, cortex-decay, cortex-causal, cortex-retrieval, cortex-validation, cortex-learning, cortex-consolidation, cortex-prediction, cortex-session, cortex-reclassification, cortex-observability, cortex-cloud, cortex-temporal, cortex-napi, cortex-crdt, cortex-multiagent, test-fixtures. That's 21 crates + 1 test fixture = 22 members. Update the reference from "19 crates" to "21 crates."

4. **§18 Similarity Scoring says "Cosine similarity, Jaccard similarity" — actual file only has cosine.** The `similarity.rs` file implements `cosine_similarity()`, `is_novel()`, and `is_overlap()`. There is no Jaccard implementation in this file. Drift's pattern aggregation system uses Jaccard similarity (validated in Section 4), but this is a different algorithm that Drift will need to implement from scratch (or use a crate). The reuse guide should say "Cosine similarity" only, and note that Jaccard is not available in Cortex.

**The "copy patterns, not code" rule is sound.** The guide correctly warns against creating a shared utility crate between Cortex and Drift (violates D1: standalone independence). The patterns are architectural — OnceLock singleton, write-serialized/read-pooled, domain-organized query modules, trait-based health reporting — and translate cleanly to Drift's type system.

**One additional pattern worth adding to the guide:**

The Cortex workspace's `cortex-napi/src/conversions/` directory contains not just error conversion but also type conversion patterns (Rust types → NAPI types). Drift will need similar conversions for its analysis result types. The pattern of a dedicated `conversions/` module with per-domain conversion files is worth calling out explicitly.

---

### 5. Performance Target Summary — ✅ CONFIRMED (with measurability notes)

The §18.1 performance target table lists 12 key targets across phases. I validated each for realism and measurability.

| Phase | System | Target | Realistic? | Measurable? | Notes |
|-------|--------|--------|-----------|-------------|-------|
| 1 | Scanner | 10K files <300ms | ✅ Yes | ✅ Yes | ripgrep scans 10K files in ~100ms. Drift adds hashing overhead but 300ms is achievable. Benchmark with `criterion`. |
| 1 | Scanner | 100K files <1.5s | ✅ Yes | ✅ Yes | Linear scaling from 10K target. macOS APFS may be slower (R10). |
| 1 | Scanner | Incremental <100ms | ✅ Yes | ✅ Yes | mtime check + xxh3 hash on changed files only. Realistic for <1% file change rate. |
| 1 | Parsers | Single-pass shared results | ✅ Yes | ⚠️ Qualitative | "Single-pass" is a design property, not a measurable target. Add: "Parse 10K files <5s" or similar. |
| 1 | Storage | Batch write 500 rows/tx | ✅ Yes | ✅ Yes | SQLite can handle 10K+ inserts/tx. 500 is conservative. |
| 1 | NAPI | AsyncTask for >10ms ops | ✅ Yes | ✅ Yes | 10ms threshold is measurable via `std::time::Instant`. |
| 1 | NAPI | <1ms for sync queries | ✅ Yes | ✅ Yes | SQLite `prepare_cached` + indexed queries return in <1ms for single-row lookups. |
| 2 | UAE | 10K files <10s end-to-end | ⚠️ Tight | ✅ Yes | 10s for full analysis (scan + parse + detect + score) is ambitious. Depends on detector count and GAST normalization overhead. Achievable with 50-80 detectors, may need relaxing to <15s with 200+ detectors. |
| 2 | Call Graph | Build <5s for 10K files | ✅ Yes | ✅ Yes | petgraph StableGraph construction is fast. 10K files ≈ 50K functions ≈ 150K edges. Graph construction is O(V+E). |
| 2 | Call Graph | BFS <5ms | ✅ Yes | ✅ Yes | In-memory BFS on petgraph is sub-millisecond for typical depths. 5ms is conservative. |
| 2 | Call Graph | SQLite CTE <50ms | ⚠️ Depends | ✅ Yes | Section 3 findings noted CTE performance degrades for dense graphs. 50ms is achievable for sparse graphs (depth ≤5) but may exceed for highly connected graphs. |
| 3 | Confidence | 10K patterns <500ms | ✅ Yes | ✅ Yes | Beta distribution computation is O(1) per pattern. 10K × O(1) = trivial. 500ms is very conservative. |
| 4 | Taint | Intraprocedural <1ms/fn | ✅ Yes | ✅ Yes | Single-function taint propagation is a small fixed-point computation. <1ms is realistic. |
| 4 | Taint | Interprocedural <100ms/fn | ⚠️ Depends | ✅ Yes | Depends on call graph depth and summary cache hit rate. 100ms is achievable for typical functions but may exceed for deeply nested call chains. |
| 5 | Crypto | 261 patterns/file | ✅ Yes | ✅ Yes | RegexSet single-pass matching. Per-language subset (~22-25 patterns) is fast. |
| 5 | Contracts | Endpoint matching <1ms | ✅ Yes | ✅ Yes | String comparison + hash lookup. Trivial. |
| 5 | Contracts | Schema comparison <5ms | ✅ Yes | ✅ Yes | JSON Schema structural diff is bounded by schema size. <5ms for typical API schemas. |
| 8 | MCP | drift_status <1ms | ✅ Yes | ✅ Yes | In-memory status query. Trivial. |
| 8 | MCP | drift_context <100ms | ⚠️ Tight | ✅ Yes | Context generation involves token counting (tiktoken-rs), template rendering, and data aggregation. 100ms is achievable but tight for large contexts. |
| 9 | Bridge | Event mapping <5ms | ✅ Yes | ✅ Yes | Enum-to-enum mapping. Trivial. |
| 9 | Bridge | Grounding single <50ms | ✅ Yes | ✅ Yes | Single memory grounding = 1 SQLite query + comparison. |
| 9 | Bridge | Grounding loop 500 <10s | ✅ Yes | ✅ Yes | 500 × 50ms = 25s sequential. With batching and parallel queries, <10s is achievable. |

**Missing targets from V2-PREP docs** (per §20.7):

The §18.1 table is incomplete. Additional targets that should be added:
- Error Handling (Phase 4): 8-phase topology per file — no time target specified. Add: "<5ms per file for topology construction."
- Coupling (Phase 5): Tarjan SCC + Martin metrics — no time target. Add: "<1s for 5,000-module graph."
- Wrapper Detection (Phase 5): RegexSet single-pass — no time target. Add: "<2ms per file for 150+ pattern matching."
- Context Generation (Phase 7): <50ms standard, <100ms full pipeline (25x improvement over v1) — this IS in the V2-PREP doc but missing from §18.1.
- Violation Feedback (Phase 6): FP rate <5% — this is a quality target, not a performance target, but should be tracked.

**Overall assessment**: All performance targets are measurable (can be benchmarked with `criterion` or `std::time::Instant`). Most are realistic. The 3 targets marked "tight" or "depends" (UAE 10s, CTE 50ms, MCP context 100ms) should have documented fallback thresholds (e.g., "target <10s, acceptable <15s"). The missing targets from V2-PREP docs should be added to §18.1 for completeness.

---

### 6. Storage Schema Progression — ⚠️ REVISE: Cumulative Counts Are Low by ~10-15%

The §18.2 table gives approximate cumulative table counts per phase. I cross-referenced against the per-system table counts from §20.5 and the V2-PREP documents.

**Revised table count audit:**

| Phase | §18.2 Estimate | Actual (from V2-PREP) | Delta | Details |
|-------|---------------|----------------------|-------|---------|
| 1 | ~5-8 | 6-8 | ✅ Close | file_metadata, parse_cache, functions, scan_history, config_cache, migration_version. Possibly file_hashes and parse_errors. |
| 2 | ~15-20 | 18-22 | ✅ Close | Phase 1 tables + call_edges, data_access, detections, boundaries, patterns, file_patterns, orm_patterns (ULP: 4 tables per §20.5), function_semantics, decorator_cache. |
| 3 | ~22-25 | 24-28 | ⚠️ Slightly low | Phase 2 + pattern_confidence, outliers, conventions, learned_conventions, convention_scan_history, contested_conventions, convention_feedback (Learning: 4 tables per §20.5). |
| 4 | ~30-35 | 32-38 | ⚠️ Slightly low | Phase 3 + reachability_cache, taint_flows, taint_summaries, error_gaps, error_topology, impact_scores, impact_paths, test_coverage, test_mapping. |
| 5 | ~40-45 | 48-56 | ❌ Significantly low | Phase 4 + coupling (6 tables) + contracts (9 tables) + DNA (6 tables) + crypto (3 tables) + constants + secrets + wrappers + OWASP findings. The §20.5 gap analysis already flagged this: coupling alone adds 6 tables, contracts add 9, DNA adds 6. That's 21 tables from just 3 systems. |
| 6 | ~48-52 | 55-62 | ⚠️ Low | Phase 5 + violations, gate_results, gate_history, audit_snapshots (4 tables per §20.5), audit_degradation_log, audit_recommendations, audit_duplicate_groups, health_trends, feedback (violation_feedback: 5 tables per §20.5), enforcement_transitions, pattern_suppressions, detector_health, pattern_directory_scores. |
| 7 | ~55 | 58-65 | ⚠️ Low | Phase 6 + simulations, simulation_results, decisions, decision_evidence, context_cache, context_templates. |
| 9 | +4 bridge | +4 bridge | ✅ Correct | bridge_grounding_results, bridge_grounding_snapshots, bridge_event_log, bridge_metrics in bridge.db. |

**Key discrepancy**: Phase 5 is the most underestimated. The §18.2 estimate of "~40-45" should be "~48-56". This is because the gap analysis (§20.5) identified that coupling (6), contracts (9), and DNA (6) alone add 21 tables — more than the §18.2 estimate accounts for.

**Impact of higher table count**: At 55-65 tables in drift.db, SQLite performance is not a concern — SQLite handles hundreds of tables without issues. The concern is migration complexity: `rusqlite_migration` must apply all migrations sequentially on first run. With 30+ migration files, cold start time increases. The mitigation from R17 (schema version caching) applies here.

**Recommendation**: Update §18.2 with the revised counts. The most important correction is Phase 5: change "~40-45" to "~48-56". Also add a note that the total table count (including indexes) will be significantly higher — each table typically has 2-4 indexes, so 60 tables × 3 indexes = ~180 database objects total.

---

### 7. NAPI Function Count Progression — ⚠️ REVISE: §18.3 Underestimates by ~10-15%

The §18.3 table gives approximate NAPI function counts per phase. The gap analysis (§20.3) already flagged that the cumulative total of "42-53" at Phase 9 is low — the actual total from V2-PREP docs is ~55 (per 03-NAPI-BRIDGE-V2-PREP §10 master registry).

**Revised NAPI function count audit:**

| Phase | §18.3 Estimate | Actual (from V2-PREP) | Delta | Key Functions |
|-------|---------------|----------------------|-------|---------------|
| 1 | 3 | 3-5 | ⚠️ Slightly low | drift_initialize, drift_shutdown, drift_scan + possibly drift_parse, drift_migrate |
| 2 | 2-3 (cum: 5-6) | 4-6 (cum: 7-11) | ⚠️ Low | drift_analyze, drift_call_graph, drift_boundaries + drift_detect, drift_patterns, drift_language_info |
| 3 | 3-4 (cum: 8-10) | 4-5 (cum: 11-16) | ⚠️ Low | drift_patterns, drift_confidence, drift_outliers, drift_conventions + drift_learn |
| 4-5 | 8-12 (cum: 16-22) | 12-18 (cum: 23-34) | ⚠️ Low | Per-system query functions. Error Handling: 8, Impact: 8, Coupling: 8, Constants: 3, DNA: 4, Audit: 2 = 33 from just these 6 systems. |
| 6 | 3-4 (cum: 19-26) | 4-6 (cum: 27-40) | ⚠️ Low | drift_check, drift_audit, drift_violations, drift_gates + Violation Feedback: 8 functions |
| 7 | 3-4 (cum: 22-30) | 6-8 (cum: 33-48) | ⚠️ Low | Simulation: 11, Context Gen: 3, Decision Mining: ~3 |
| 8 | 5-8 (cum: 27-38) | 5-8 (cum: 38-56) | ✅ Close | MCP tool handlers, CI agent functions |
| 9 | 15 (cum: 42-53) | 15 (cum: 53-71) | ⚠️ Low | bridge_* functions |

**The core issue**: §18.3 uses conservative ranges that don't account for the per-system NAPI function counts documented in the V2-PREP files. The gap analysis (§20.3) lists specific counts: Error Handling (8), Impact (8), Coupling (8), Constants (3), DNA (4), Audit (2), Simulation (11), Context Gen (3), Violation Feedback (8), Workspace (16), Bridge (15). These alone sum to 86 — far more than the §18.3 cumulative of 42-53.

**However**, many of these per-system functions are internal helpers, not top-level NAPI exports. The 03-NAPI-BRIDGE-V2-PREP §10 master registry lists ~55 top-level NAPI functions. The per-system counts include both top-level exports and internal query functions that are called by the top-level exports.

**Recommendation**: Clarify the distinction between "top-level NAPI exports" (~55, matching the master registry) and "total NAPI-accessible functions" (~70-85, including per-system query functions). Update §18.3 to show ~55 as the cumulative top-level export count at Phase 9, with a note that the internal function count is higher.

**Comparison with Cortex**: The Cortex workspace has 14 NAPI binding modules with an estimated 40-60 top-level exports (based on module count and typical functions per module). Drift's ~55 top-level exports is comparable, which validates the scale.

---

### 8. Verification Gates — ✅ CONFIRMED

The §19 verification gates define 8 milestones with qualitative descriptions. I assessed each for testability and sufficiency.

| Milestone | Gate | Testable? | Sufficient? | Notes |
|-----------|------|-----------|-------------|-------|
| M1: "It Scans" (Phase 1) | Scan real codebase, parse every file, persist results, call from TS | ✅ Yes | ✅ Yes | Concrete: run `drift_scan()` on a 1K-file repo, verify all files in drift.db, verify NAPI round-trip. Add: verify scan time <300ms for 1K files. |
| M2: "It Detects" (Phase 2) | Detect patterns across 16 categories, build call graph, identify boundaries | ✅ Yes | ✅ Yes | Concrete: run `drift_analyze()` on test repo, verify ≥1 detection per category, verify call graph has edges, verify boundary results. Add: verify 50+ detectors passing. |
| M3: "It Learns" (Phase 3) | Patterns scored, ranked, learned. Self-configuring conventions. | ⚠️ Partially | ✅ Yes | "Self-configuring" is qualitative. Make concrete: run on 3 different repos, verify conventions are discovered without manual config, verify confidence scores are non-trivial (not all 0.5). |
| M4: "It Secures" (Phase 4) | Taint, reachability, impact, test topology working | ✅ Yes | ✅ Yes | Concrete: inject a known SQL injection pattern, verify taint analysis detects it. Verify reachability from entry point to vulnerable function. |
| M5: "It Enforces" (Phase 6) | Quality gates pass/fail. SARIF uploads to GitHub Code Scanning. | ✅ Yes | ✅ Yes | Concrete: configure a gate with a threshold, verify pass/fail. Upload SARIF to a test GitHub repo, verify findings appear in Code Scanning tab. |
| M6: "It Ships" (Phase 8) | MCP server, CLI, CI agent working | ✅ Yes | ✅ Yes | Concrete: run `drift` CLI on a repo, verify output. Start MCP server, send a tool call, verify response. Run CI agent in a GitHub Action, verify it produces a report. |
| M7: "It Grounds" (Phase 9) | Bridge enables empirically validated AI memory | ⚠️ Partially | ✅ Yes | "Empirically validated" is qualitative. Make concrete: create a Cortex memory, run bridge grounding, verify the memory's confidence is updated based on Drift scan data. Verify ≥1 grounding result per memory type. |
| M8: "It's Complete" (Phase 10) | All 60 systems built. IDE integration, Docker, telemetry, licensing, benchmarking. | ✅ Yes | ✅ Yes | Concrete: run the full test suite, verify all systems have passing tests. Verify VSCode extension loads and shows diagnostics. Verify Docker image builds and runs. |

**Assessment**: The 8 milestones provide a clear progression from "minimal viable" (M1) to "enterprise-ready" (M8). Each milestone is testable with concrete acceptance criteria. The qualitative descriptions ("It Learns", "It Grounds") need concrete test scenarios to be truly verifiable — I've suggested specific tests above.

**One structural observation**: The milestones map cleanly to the critical path:
- M1 (Phase 1) → M2 (Phase 2) → M3 (Phase 3) → M5 (Phase 6) → M6 (Phase 8) is the critical path.
- M4 (Phase 4) runs in parallel with M3 and doesn't block M5.
- M7 (Phase 9) and M8 (Phase 10) are post-ship milestones.

This means a "shippable product" is achieved at M6 (Phase 8), which aligns with the critical path calculation of 14-20 weeks. M4 (security features) adds depth but doesn't block shipping. This is the correct prioritization — ship a useful tool first, add security depth incrementally.

**Missing gate**: There's no explicit gate between Phase 5 (Structural Intelligence) and Phase 6 (Enforcement). Phase 5 produces the structural data that Phase 6 enforces. A "M4.5: It Understands Structure" gate would verify that coupling metrics, constraints, contracts, and DNA profiles are computed correctly before enforcement begins. Without this gate, Phase 6 could start on incomplete structural data.

**Recommendation**: Add a gate between Phase 5 and Phase 6: "Verify coupling metrics for ≥3 modules, ≥1 constraint passing, ≥1 contract detected, DNA profile computed for ≥1 gene." This doesn't need to be a formal milestone — it can be a Phase 6 precondition check.

---

### 9. Team Size Recommendations — ✅ CONFIRMED (with realism adjustment)

The §15 team size table recommends:

| Team Size | Timeline | Strategy |
|-----------|----------|----------|
| 1 developer | 6-8 months | Sequential critical path first |
| 2 developers | 4-5 months | Dev A: critical path, Dev B: parallel tracks |
| 3-4 developers | 3-4 months | Full parallelism in Phases 4-5 |
| 5+ developers | 2.5-3 months | Maximum parallelism |

**Validation against per-system estimates:**

The V2-PREP documents provide per-system build estimates (§20.4):
- Scanner: 6-9 days
- UAE full pipeline: 22 weeks (core: 5 weeks)
- Contract Tracking: ~20 weeks
- Context Generation: ~7 weeks
- Simulation Engine: ~6 weeks
- Cryptographic Detection: ~5 weeks
- Violation Feedback: ~5 weeks
- Workspace Management: ~5 weeks
- MCP Server: ~7 weeks
- Coupling Analysis: ~4 phases

**Critical path calculation check:**

The critical path is: Phase 0 (1-2w) → Phase 1 (2-3w) → Phase 2 Track A (2w) → Phase 3 (3-4w) → Phase 6 (2-3w) → Phase 8 (2w) = **12-16 weeks**.

This assumes:
- Phase 2 Track A delivers only the core pipeline + visitor engine (Weeks 1-5 of the 22-week UAE plan, but only Weeks 1-2 are on the critical path since Phase 3 needs aggregated patterns, not the full detector suite)
- Phase 3 delivers pattern aggregation + confidence scoring (the minimum for Phase 6 quality gates)
- Phase 6 delivers rules engine + quality gates (the minimum for Phase 8 CI agent)
- Phase 8 delivers MCP server + CLI (the minimum shippable product)

**For 1 developer (6-8 months):**

6 months = 26 weeks. The critical path is 12-16 weeks, leaving 10-14 weeks for Phases 4, 5, 7, 9, 10. This is tight but achievable if:
- Phase 4 systems are built sequentially (5 systems × 2-3 weeks each = 10-15 weeks)
- Phase 5 systems are built sequentially (7 systems × 2-4 weeks each = 14-28 weeks)

At 1 developer, Phases 4+5 alone could take 24-43 weeks — far more than the 10-14 weeks available after the critical path. **The 6-8 month estimate for 1 developer is only achievable if Phases 4+5 are scoped to P0 systems only** (e.g., Reachability + Taint from Phase 4, Coupling + Crypto from Phase 5). The full Phase 4+5 scope requires 8+ months for 1 developer.

**Applying the estimation overconfidence correction (R18):** With a 1.3x multiplier, the 1-developer timeline becomes 8-10 months for a reasonably complete product. The 6-8 month estimate is the optimistic bound.

**For 2 developers (4-5 months):**

Dev A on critical path (12-16 weeks = 3-4 months). Dev B on Phase 2 Track B + Phase 4 + Phase 5 parallel systems. Dev B has ~16-20 weeks of work (Track B: 3-4w, Phase 4 subset: 6-8w, Phase 5 subset: 6-8w). This fits in 4-5 months. **Realistic and achievable.**

**For 3-4 developers (3-4 months):**

The critical path is still 12-16 weeks regardless of team size (it's sequential). 3-4 developers allow full parallelism in Phases 4-5, which run alongside the critical path. The 3-4 month estimate assumes Phases 4+5 complete within the same 12-16 week window as the critical path. With 3-4 developers on 5-7 parallel tracks, each developer handles 1-2 systems — achievable if they're already familiar with the codebase. **Realistic but requires experienced Rust developers.**

**For 5+ developers (2.5-3 months):**

Brooks's Law applies here (R20). 5+ developers on a codebase that doesn't exist yet means significant onboarding overhead. The first 2-4 weeks would be spent on Phase 0-1 (sequential, 1-2 developers productive), with the remaining developers idle or doing prep work. Maximum parallelism doesn't kick in until Phase 4 (week 8+). **The 2.5-3 month estimate is optimistic for a team that hasn't worked together before.** Realistic estimate for 5+ developers: 3-4 months (same as 3-4 developers, because the critical path dominates and onboarding overhead absorbs the parallelism gains).

**Recommendation**: Adjust the team size table:

| Team Size | Optimistic | Realistic (1.3x) | Strategy |
|-----------|-----------|-------------------|----------|
| 1 developer | 6-8 months | 8-10 months | Sequential critical path. P0 systems only for Phases 4-5. |
| 2 developers | 4-5 months | 5-6.5 months | Dev A: critical path. Dev B: parallel tracks. Best ROI. |
| 3-4 developers | 3-4 months | 4-5 months | Full parallelism Phases 4-5. Requires experienced Rust devs. |
| 5+ developers | 2.5-3 months | 3-4 months | Diminishing returns. Brooks's Law limits gains beyond 4. |

The 2-developer configuration offers the best ROI: it halves the timeline from 1-developer without the coordination overhead of larger teams.

---

### 10. Critical Path Calculation (12-16 weeks) — ✅ CONFIRMED (with caveats)

The §15 critical path is:

```
Phase 0 (1-2w) → Phase 1 (2-3w) → Phase 2 Track A (2w) → Phase 3 (3-4w) →
Phase 6 (2-3w) → Phase 8 (2w)
= 12-16 weeks minimum for a shippable product
```

**Validation of each segment:**

**Phase 0 (1-2 weeks)**: Config, errors, tracing, events, data structures. This is boilerplate Rust setup — `thiserror` enums, `tracing` subscriber, `DriftConfig` TOML parsing, `FxHashMap`/`SmallVec` type aliases. 1-2 weeks is realistic for an experienced Rust developer. The Cortex workspace's equivalent setup (cortex-core) is ~2,500 LOC — achievable in 1 week.

**Phase 1 (2-3 weeks)**: Scanner, Parsers, Storage, NAPI. The Scanner V2-PREP estimates 6-9 days (~1,700 LOC). Parsers are tree-sitter wrappers (~1 week). Storage is rusqlite setup with migrations (~1 week). NAPI bridge is 3 initial functions (~3-5 days). Total: 3-4 weeks if sequential, 2-3 weeks with overlap. **The 2-3 week estimate is achievable but at the low end.**

**Phase 2 Track A (2 weeks)**: Core UAE pipeline + visitor engine (Weeks 1-5 of the 22-week UAE plan, but only the minimum needed for Phase 3). This means: the `AnalysisEngine` struct, the `DetectorHandler` trait, the visitor dispatch loop, and 20-30 initial detectors. The V2-PREP estimates Weeks 1-5 for this scope. **2 weeks is aggressive — 3-4 weeks is more realistic for the core pipeline + enough detectors to produce meaningful patterns.** However, the critical path only needs the pipeline to produce *some* patterns for Phase 3 to start. If Phase 3 can start with 10-20 detectors producing patterns, 2 weeks is achievable.

**Phase 3 (3-4 weeks)**: Pattern Aggregation → Confidence Scoring → Outlier Detection → Learning System. The internal dependency chain (aggregation must come first, then confidence, then outlier/learning in parallel) limits parallelism. Pattern Aggregation is the most complex (Jaccard dedup, MinHash LSH, hierarchical grouping). Confidence Scoring is the Bayesian Beta distribution computation (relatively straightforward). **3-4 weeks is realistic.**

**Phase 6 (2-3 weeks)**: Rules Engine → Quality Gates → Policy Engine → Audit System. The Section 6 findings validated this scope. Rules Engine is a predicate evaluator. Quality Gates is a DAG-based orchestrator. Policy Engine is TypeScript-side YAML loading. Audit System is SQLite snapshots. **2-3 weeks is realistic for the minimum viable enforcement.**

**Phase 8 (2 weeks)**: MCP Server + CLI + CI Agent. The MCP Server V2-PREP estimates ~7 weeks for the full system, but the critical path only needs the core MCP server with basic tool registration. CLI is a thin wrapper around NAPI calls. CI Agent is a GitHub Action wrapper. **2 weeks is achievable for minimum viable versions of all three.**

**Total: 12-16 weeks.**

The range is wide (12 to 16) because each segment has a 1-week variance. The optimistic path (12 weeks) assumes everything goes smoothly and each phase hits its low estimate. The pessimistic path (16 weeks) assumes each phase hits its high estimate.

**Applying the estimation overconfidence correction (R18):** With a 1.3x multiplier, the critical path becomes **16-21 weeks**. This is the realistic planning estimate.

**One structural risk**: The critical path assumes Phase 3 can start as soon as Phase 2 Track A produces *any* patterns. If Phase 3 requires a minimum pattern count or diversity to be meaningful (e.g., patterns from ≥5 detector categories), then Phase 2 Track A may need to run longer before Phase 3 can start. This would extend the critical path by 1-2 weeks.

**Recommendation**: Keep the 12-16 week estimate as the "target" but use 16-21 weeks for planning. Define a concrete Phase 2→Phase 3 handoff criterion: "Phase 3 can start when ≥100 patterns from ≥5 categories are detected on the test corpus." This makes the handoff testable and prevents Phase 3 from starting on insufficient data.

---

## Verdict

| Item | Verdict | Action Required |
|------|---------|-----------------|
| Cross-phase dependency matrix | ⚠️ REVISE | Add N+1→P5 edge, add soft Context Gen→P4 edge, clarify OWASP/CWE partial P4 dependency, fix system count (53 not 60) |
| Parallelization map | ✅ CONFIRMED | Sound. No false parallelism. Note Constraint System and OWASP/CWE start later within Phase 5 due to P4 dependency |
| Risk register R1-R16 | ⚠️ REVISE | Add R17 (SQLite schema complexity), R18 (estimation overconfidence), R19 (NAPI v2→v3 pattern divergence), R20 (parallel developer coordination). Update R1 for tree-sitter 0.25, R6 severity higher for expanded GAST, R11 for revised version pins |
| Cortex pattern reuse guide | ⚠️ REVISE | Fix 3 factual errors: NAPI modules 14 not 12, write connection uses tokio::sync::Mutex not std::sync::Mutex (Drift needs std), workspace has 21 crates not 19. Note similarity.rs has cosine only, not Jaccard. Add NAPI v2→v3 adaptation note |
| Performance target summary | ✅ CONFIRMED | All targets measurable. 3 targets (UAE 10s, CTE 50ms, MCP context 100ms) need fallback thresholds. Add missing targets from V2-PREP docs (error handling, coupling, wrapper detection, context generation) |
| Storage schema progression | ⚠️ REVISE | Phase 5 cumulative is ~48-56, not ~40-45. Phase 6 is ~55-62, not ~48-52. Total drift.db objects (tables + indexes) will be ~180+. Add schema version caching for cold start optimization |
| NAPI function count progression | ⚠️ REVISE | Cumulative at Phase 9 is ~55 top-level exports (not 42-53). Clarify distinction between top-level NAPI exports (~55) and total per-system functions (~70-85). Update §18.3 ranges |
| Verification gates | ✅ CONFIRMED | 8 milestones are testable and sufficient. Add concrete acceptance criteria for qualitative gates (M3 "It Learns", M7 "It Grounds"). Add Phase 5→6 precondition gate |
| Team size recommendations | ✅ CONFIRMED | Fundamentally sound. Add realistic (1.3x) column. 2-developer config is best ROI. 5+ developers hit diminishing returns from Brooks's Law. 1-developer realistic timeline is 8-10 months, not 6-8 |
| Critical path (12-16 weeks) | ✅ CONFIRMED | Calculation is correct. Realistic planning estimate with overconfidence correction: 16-21 weeks. Define concrete Phase 2→3 handoff criterion (≥100 patterns from ≥5 categories) |

**Summary: 5 CONFIRMED, 5 REVISE, 0 REJECT.**

The cross-cutting concerns are well-structured and internally consistent. The dependency matrix, parallelization map, and verification gates form a coherent project management framework. The 5 revisions are all refinements — correcting underestimates in table/function counts, adding missing risks, fixing factual errors in the Cortex reuse guide, and applying estimation overconfidence corrections to timeline projections. No architectural decisions need to change. The critical path calculation of 12-16 weeks is confirmed as the target, with 16-21 weeks as the realistic planning estimate.

The most impactful finding is R18 (estimation overconfidence): applying the well-documented 1.3x correction factor to all estimates shifts the 1-developer timeline from 6-8 months to 8-10 months and the critical path from 12-16 weeks to 16-21 weeks. This doesn't change the architecture or build order — it changes the expectations communicated to stakeholders.
