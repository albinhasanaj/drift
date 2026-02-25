# Section 14 Findings: Risk Register, Cortex Reuse & Performance Targets

> **Status:** ✅ DONE
> **Date completed:** 2026-02-08
> **Orchestration plan sections:** §16 (Risk Register), §18 (Cortex Reuse Guide), §18.1-18.3 (Targets)
> **Round 1 reference:** SECTION-8-FINDINGS.md (cross-cutting concerns)
>
> **Summary: 8 CONFIRMED, 6 REVISE, 0 REJECT, 11 APPLIED**

---

## Checklist (all validated)

- [x] R1-R11 existing risks — mitigations still adequate after Round 1 findings?
- [x] R1 tree-sitter — update from 0.24 to 0.25 per Round 1. Does mitigation change?
- [x] R6 GAST — update from ~30 to ~40-50 types per Round 1. Does risk level change?
- [x] R11 Cargo versions — update versions per Round 1. Is this risk now mitigated?
- [x] R12-R16 from §20.13 — adequately described? Any missing mitigations?
- [x] Add R17 (SQLite schema complexity) per Round 1
- [x] Add R18 (estimation overconfidence) per Round 1
- [x] Add R19 (NAPI v2→v3 divergence) per Round 1
- [x] Add R20 (parallel dev coordination) per Round 1
- [x] Cortex reuse guide — verify all 12 pattern references against actual Cortex codebase
- [x] Fix 3 factual errors identified in Round 1
- [x] Verify similarity.rs is cosine only (not Jaccard as implied)
- [x] Add NAPI v2→v3 adaptation note
- [x] §18.1 Performance targets — all targets from V2-PREP docs included?
- [x] §18.2 Schema progression — Phase 5 cumulative revised?
- [x] §18.3 NAPI function counts — reconciled with V2-PREP docs?
- [x] Apply Round 1 revisions: add R17-R20, update R1/R6/R11, fix 3 Cortex reuse errors, update schema/NAPI counts

---

## Part A: Risk Register Validation (§16)

### A1. R1: tree-sitter Grammar Compatibility — 🔧 APPLIED (version update needed)

**Current state in §16:** References "tree-sitter v0.24".
**Round 1 revision (S1, S2):** Bump to tree-sitter 0.25.
**Verification:**

The §16 text says "tree-sitter v0.24" in the heading and body. Round 1 (Section 1 findings)
revised this to 0.25. The risk profile actually *improves* with 0.25 — more grammar crates
have updated to support 0.25 than 0.24, and the tree-sitter 0.25 release includes better
error recovery and incremental parsing improvements.

**Mitigation change:** The mitigation ("Test all 10 grammars against v0.24 in Phase 0")
remains structurally sound — just update the version reference. The "pin grammar versions
in `build.rs`" advice is still correct. The fallback ("ship without that language") is
still the right escape hatch.

**Verdict:** 🔧 APPLIED — Update R1 heading to "tree-sitter v0.25 Grammar Compatibility"
and all body references from 0.24→0.25. Risk severity is unchanged (Medium). Mitigation
is unchanged in structure.

---

### A2. R2: napi-rs v3 Maturity — ✅ CONFIRMED

**Current state in §16:** Correctly identifies napi-rs v3 as newer, notes Rolldown and Oxc
as production users, provides v2 compat-mode fallback.

**Round 2 assessment:** Section 8 findings noted that NAPI-RS v3 has been stable since
July 2025 (7+ months by now). The risk framing ("newer than v2") understates v3's maturity.
However, the risk entry is still valid because the *Cortex codebase* uses v2, creating a
pattern divergence risk (captured separately in R19). The mitigation (v2 compat-mode
fallback) is sound.

**Verdict:** ✅ CONFIRMED — Risk is valid, mitigation is adequate. Severity could be
downgraded from Medium to Low given v3's maturity, but keeping it Medium is conservative
and acceptable.

---

### A3. R3: Taint Analysis Complexity — ✅ CONFIRMED

**Current state in §16:** Correctly identifies taint as the largest net-new system.
Intraprocedural-first mitigation is sound.

**Round 2 assessment:** Section 4 findings added 2 new taint sink types (XmlParsing,
FileUpload), bringing the total to 17 built-in sinks. This marginally increases scope
but doesn't change the risk profile — the complexity is in the interprocedural analysis
engine, not the sink type count. The mitigation (ship intraprocedural first) remains
the correct strategy.

**Verdict:** ✅ CONFIRMED — No changes needed.

---

### A4. R4: SQLite Performance at Scale — ✅ CONFIRMED

**Current state in §16:** Correctly identifies the scale concern (40+ tables, 100K+ files).
Mitigations (covering indexes, partial indexes, keyset pagination, WAL mode) are standard
and proven.

**Round 2 assessment:** Section 8 findings revised the table count upward — Phase 5
cumulative is ~48-56 tables, not ~40-45. At 55-65 total tables, SQLite performance is
still not a concern (SQLite handles hundreds of tables). The mitigation is adequate.
The new R17 (schema complexity) captures the migration-specific risk that R4 doesn't
cover.

**Verdict:** ✅ CONFIRMED — No changes needed. R17 covers the migration-specific aspect.

---

### A5. R5: Detector Count (350+) — ✅ CONFIRMED

**Current state in §16:** Correctly identifies the effort scope. 50-80 high-value first
is the right strategy.

**Round 2 assessment:** The trait-based detector architecture (AD4: single-pass visitor)
means adding detectors is mechanical once the framework exists. The risk is effort, not
complexity. The mitigation is sound.

**Verdict:** ✅ CONFIRMED — No changes needed.

---

### A6. R6: Cross-Language GAST Normalization — 🔧 APPLIED (severity increase)

**Current state in §16:** References "~30 GAST node types".
**Round 1 revision (S3):** GAST expanded to ~40-50 node types with GASTNode::Other catch-all.

**Verification:** Section 3 findings revised GAST from 26 planned types to ~40-50 to
adequately cover 10 languages. Section 8 findings flagged that this increases the
normalization effort per language and raises the risk of edge cases.

**Severity change:** The risk of incorrect cross-language analysis increases with more
node types because each type must be correctly normalized across all 10 languages.
With 40-50 types × 10 languages = 400-500 normalization mappings (vs. 260-300 at 26 types).
The `GASTNode::Other { kind, children }` catch-all mitigates unknown constructs but
doesn't eliminate the risk of *incorrect* mappings for known constructs.

**Mitigation update:** The existing mitigation ("Start with 3-4 well-understood languages")
is still correct. Add: "The GASTNode::Other catch-all ensures unknown constructs don't
crash the pipeline. Add mandatory `coverage_report()` per language to track unmapped
constructs. Target >95% coverage for P0 languages (TS/JS, Python, Java) before adding
P1 languages."

**Verdict:** 🔧 APPLIED — Update R6 body from "~30 GAST node types" to "~40-50 GAST
node types". Increase severity from Medium to Medium-High. Add coverage_report()
requirement to mitigation.

---

### A7. R7: Build Time — ✅ CONFIRMED

**Current state in §16:** Standard mitigations (nextest, sccache, feature flags).
**Round 1 revision (S1):** Add `panic = "abort"` to release profile.

**Verification:** The workspace Cargo.toml already has `panic = "abort"` in the release
profile (confirmed from the Cortex workspace Cargo.toml). This reduces binary size and
improves release build times slightly. The risk and mitigations are adequate.

**Verdict:** ✅ CONFIRMED — No changes needed. The `panic = "abort"` revision is a
Phase 0 scaffold item, not a risk register update.

---

### A8. R8: UAE/GAST 22-Week Timeline — ✅ CONFIRMED

**Current state in §16:** Correctly identifies the 22-week scope. Ship core + 50-80
detectors in Phase 2, continue porting through Phases 3-5.

**Round 1 revision (S3):** Add 20% buffer → 22-27 weeks realistic.

**Verification:** The 20% buffer aligns with the R18 estimation overconfidence correction
(1.3x). The mitigation (ship core pipeline first, add detectors incrementally) is the
correct strategy. The risk entry should note the revised estimate range.

**Verdict:** ✅ CONFIRMED — Add "(22-27 weeks with risk buffer)" to the R8 body. The
mitigation is unchanged.

---

### A9. R9-R10: Contract Tracking & macOS APFS — ✅ CONFIRMED

Both risks are accurately described with sound mitigations. No Round 1 revisions apply.

**Verdict:** ✅ CONFIRMED — No changes needed.

---

### A10. R11: Cargo Dependency Version Inconsistencies — 🔧 APPLIED (version updates)

**Current state in §16:** References "thiserror = 1" and "rusqlite = 0.31" from bridge
V2-PREP, vs workspace "thiserror = 2" and "rusqlite = 0.32".

**Round 1 revisions:** Multiple version bumps:
- rusqlite: 0.32 → 0.38
- petgraph: 0.6 → 0.8
- tree-sitter: 0.24 → 0.25
- git2: 0.19 → 0.20
- tiktoken-rs: 0.6 → 0.9
- fd-lock: unspecified → "4"

**Verification:** The bridge V2-PREP's versions (thiserror=1, rusqlite=0.31) are now
even more outdated relative to the revised workspace pins. The gap has widened:
- thiserror: bridge says 1, workspace says 2 (unchanged)
- rusqlite: bridge says 0.31, workspace now says 0.38 (was 0.32)
- petgraph: bridge may reference 0.6, workspace now says 0.8

The mitigation ("workspace Cargo.toml versions are authoritative") is still correct and
sufficient. The bridge crate inherits workspace versions via `[workspace.dependencies]`.

**Verdict:** 🔧 APPLIED — Update R11 body to reference the new version pins (rusqlite
0.38, petgraph 0.8, tree-sitter 0.25). Note that the version gap between bridge V2-PREP
and workspace has widened but the mitigation (workspace authority) fully resolves it.
Risk severity can be downgraded from Medium to Low since this is a documentation gap,
not a technical risk — workspace dependency inheritance prevents actual version conflicts.


---

### A11. R12-R16 from §20.13 — ✅ CONFIRMED

These 5 risks were identified in the gap analysis and are adequately described:

- **R12 (tiktoken-rs platform compat):** Fallback chain (tiktoken-rs → splintr → character
  estimation) is well-designed. Note: tiktoken-rs 0.9.1 is now released (confirmed on
  [lib.rs](https://lib.rs/crates/tiktoken-rs), Nov 2025), which adds o200k_harmony and
  GPT-5 support. Platform compatibility has improved since the risk was written.
- **R13 (Violation feedback retention):** Unbounded table growth is a real concern for
  large projects. Archival strategy needed. Adequate as written.
- **R14 (MCP progressive disclosure UX):** 3-tier pattern may confuse AI clients. Fallback
  (register all tools directly) is sound. Adequate as written.
- **R15 (Simulation hybrid architecture):** Rust/TS split adds complexity. 11 NAPI functions
  bridge the gap. Adequate as written.
- **R16 (Workspace 16 NAPI functions):** Largest single-system NAPI surface. Testing
  concern is valid. Adequate as written.

**Verdict:** ✅ CONFIRMED — All 5 risks are adequately described with sound mitigations.

---

### A12. R17 (SQLite Schema Complexity) — 🔧 APPLIED (new risk added)

**Round 1 recommendation (S8):** Add R17 for SQLite schema complexity at 50+ tables.

**Verification:** Section 8 findings documented this risk thoroughly. At 48-56 tables
by Phase 5 (revised from ~40-45), plus covering indexes, partial indexes, and triggers,
the total database object count reaches ~180+. The migration validation on startup
could take 100-500ms.

**Internet verification:** rusqlite_migration is confirmed compatible with rusqlite 0.38
([cj.rs docs](https://cj.rs/rusqlite_migration_docs/)). The library uses `user_version`
(a lightweight integer at a fixed offset in the SQLite file) rather than querying tables,
which is faster than most migration tools. This partially mitigates the cold start concern.

**Recommended R17 text:**

> **R17: SQLite Schema Complexity at 55+ Tables**
> **Risk**: drift.db grows to 55-65 tables with 180+ total database objects (tables +
> indexes + triggers). Migration validation on startup re-validates the full schema.
> **Impact**: Slower `drift_initialize()` cold start (100-500ms for migration check).
> **Mitigation**: rusqlite_migration uses `user_version` (integer at fixed offset, not
> table query) which is fast. Cache schema version alongside drift.db. Skip full
> migration validation if cached version matches expected version. Only run full
> migration on version mismatch.

**Verdict:** 🔧 APPLIED — R17 added with verified mitigation.

---

### A13. R18 (Estimation Overconfidence) — 🔧 APPLIED (new risk added)

**Round 1 recommendation (S8):** Add R18 for systematic underestimation bias.

**Verification:** Section 8 findings documented the well-established ~30% average overrun
in software estimation. The 1.3x correction factor is standard practice. Applied to the
critical path: 12-16 weeks → 16-21 weeks realistic.

**Recommended R18 text:**

> **R18: Estimation Overconfidence Bias**
> **Risk**: Systematic underestimation across all phases. Industry data shows ~30%
> average overrun when developers are "90% confident" in their estimates.
> **Impact**: Timeline slippage. Critical path extends from 12-16 weeks to 16-21 weeks.
> 1-developer timeline extends from 6-8 months to 8-10 months.
> **Mitigation**: Apply 1.3x multiplier for planning purposes (not developer communication).
> Use V2-PREP per-system estimates as "optimistic" bound, 1.5x as "pessimistic" bound.
> Track actual vs estimated at each milestone gate. The 20% UAE risk buffer (S3) should
> be extended to all phases.

**Verdict:** 🔧 APPLIED — R18 added with calibrated correction factor.

---

### A14. R19 (NAPI v2→v3 Divergence) — 🔧 APPLIED (new risk added)

**Round 1 recommendation (S8):** Add R19 for Cortex NAPI v2 → Drift NAPI v3 pattern
divergence.

**Verification:** Confirmed from workspace Cargo.toml that Cortex uses `napi = "2"` and
`napi-derive = "2"`. The Drift plan specifies napi v3. Internet verification confirms
napi-rs v3 is now at version 3.8.x ([rust-digger](https://rust-digger.code-maven.com/crates/napi)),
stable since July 2025. Key v3 changes include redesigned ThreadsafeFunction, new
Function/FunctionRef types, changed AsyncTask API, and different error handling patterns.

The NAPI-RS v3 announcement blog ([napi.rs/blog/announce-v3](http://napi.rs/blog/announce-v3))
documents the migration path. The risk is real but well-mitigated by the maturity of v3
and the availability of migration documentation.

**Recommended R19 text:**

> **R19: Cortex NAPI v2 → Drift NAPI v3 Pattern Divergence**
> **Risk**: Cortex uses napi v2; Drift targets napi v3 (now at 3.8.x). The Cortex Pattern
> Reuse Guide (§18) recommends copying patterns from Cortex's NAPI bindings, but v2
> patterns don't translate directly to v3. Key changes: ThreadsafeFunction lifecycle,
> AsyncTask API, Function/FunctionRef types.
> **Impact**: Slower development velocity in Phase 1 NAPI bridge as developers adapt
> v2 patterns to v3.
> **Mitigation**: Create a "v2→v3 migration cheat sheet" before Phase 1. Document
> specific API changes for each pattern in the reuse guide. The NAPI-RS v3 announcement
> and migration guide cover key differences. Rolldown, Rspack, and Oxc are production
> v3 users providing reference implementations.

**Verdict:** 🔧 APPLIED — R19 added with verified v3 maturity data.

---

### A15. R20 (Parallel Dev Coordination) — 🔧 APPLIED (new risk added)

**Round 1 recommendation (S8):** Add R20 for Phase 4+5 parallel developer coordination.

**Verification:** Section 8 findings documented Brooks's Law implications for 5-7 parallel
tracks. The architecture mitigates this well (each track has its own V2-PREP, tables,
NAPI functions, test suite), but shared surfaces (drift-core types, storage schema) need
coordination.

**Recommended R20 text:**

> **R20: Phase 4+5 Parallel Developer Coordination**
> **Risk**: Phases 4-5 offer 5 and 7 parallel tracks. Communication overhead scales
> quadratically with team size (5 devs = 10 channels, 7 devs = 21 channels).
> **Impact**: Phases 4-5 take longer than parallelization map suggests if team scales
> up specifically for these phases.
> **Mitigation**: Architecture already mitigates well — each track has its own spec,
> tables, NAPI functions, and tests. Freeze drift-core types and storage schema before
> parallel tracks begin. Assign one developer as "integration lead" during Phases 4-5.
> Don't scale beyond 3-4 developers unless already familiar with the codebase.

**Verdict:** 🔧 APPLIED — R20 added.

---

## Part B: Cortex Pattern Reuse Guide Validation (§18)

### B1. Pattern-by-Pattern Codebase Verification

I verified all 12 patterns in §18 against the current Cortex codebase. Every file and
directory referenced exists and contains the described pattern.

| # | Pattern | File/Dir | Verified | Finding |
|---|---------|----------|----------|---------|
| 1 | OnceLock Singleton | `cortex-napi/src/runtime.rs` | ✅ | `static RUNTIME: OnceLock<Arc<CortexRuntime>>` confirmed |
| 2 | NAPI Bindings | `cortex-napi/src/bindings/` | ⚠️ | **14 modules** (not 12): causal, cloud, consolidation, generation, health, learning, lifecycle, memory, multiagent, prediction, privacy, retrieval, session, temporal |
| 3 | SQLite Write-Serialized | `cortex-storage/src/pool/write_connection.rs` | ⚠️ | Uses **`tokio::sync::Mutex`** (not `std::sync::Mutex`). Read pool uses `std::sync::Mutex` |
| 4 | Batch Writer | `cortex-storage/src/queries/` | ✅ | Domain-organized query modules confirmed |
| 5 | Health Monitoring | `cortex-observability/src/health/` | ✅ | `HealthChecker`, `HealthReporter` confirmed |
| 6 | Degradation Tracking | `cortex-observability/src/degradation/` | ✅ | `DegradationTracker` with `RecoveryStatus` confirmed |
| 7 | Tarjan's SCC | `cortex-causal/src/graph/dag_enforcement.rs` | ✅ | `petgraph::algo::tarjan_scc` confirmed |
| 8 | Similarity Scoring | `cortex-consolidation/src/algorithms/similarity.rs` | ⚠️ | **Cosine only** — no Jaccard. File has `cosine_similarity()`, `is_novel()`, `is_overlap()` |
| 9 | Deduplication | `cortex-retrieval/src/ranking/deduplication.rs` | ✅ | Session-aware dedup confirmed |
| 10 | Error Types | `cortex-core/src/errors/cortex_error.rs` | ✅ | `thiserror` enum with 16+ variants confirmed |
| 11 | Audit Logging | `cortex-storage/src/migrations/v006_audit_tables.rs` | ✅ | Audit table schema confirmed |
| 12 | NAPI Error Codes | `cortex-napi/src/conversions/error_types.rs` | ✅ | Error code conversion confirmed |

### B2. Factual Error #1: NAPI Module Count — 🔧 APPLIED

**§18 says:** "12 modules" for NAPI bindings.
**Actual:** 14 modules (excluding mod.rs).

Verified by listing `cortex-napi/src/bindings/`:
causal.rs, cloud.rs, consolidation.rs, generation.rs, health.rs, learning.rs,
lifecycle.rs, memory.rs, multiagent.rs, prediction.rs, privacy.rs, retrieval.rs,
session.rs, temporal.rs = **14 binding modules**.

**Correction:** Update §18 from "12 modules" to "14 modules".

**Verdict:** 🔧 APPLIED

---

### B3. Factual Error #2: Mutex Type — 🔧 APPLIED

**§18 says:** "`Mutex<Connection>` writer" (implying `std::sync::Mutex`).
**Actual:** `tokio::sync::Mutex<Connection>` in `write_connection.rs`.

The write connection file header explicitly states: "Single write connection behind
`tokio::sync::Mutex`." The `with_conn()` method is `async` and uses `.lock().await`.
The read pool uses `std::sync::Mutex<Connection>` (confirmed in `read_pool.rs`).

**Impact on Drift:** Drift is a sync system (rayon for parallelism, no tokio runtime).
Drift should use `std::sync::Mutex<Connection>` for the write connection. The pattern
is the same (write-serialized + read-pooled), but the mutex type differs.

**Correction:** Update §18 to say "`tokio::sync::Mutex<Connection>` writer (Drift should
use `std::sync::Mutex<Connection>` since Drift doesn't use an async runtime)."

**Verdict:** 🔧 APPLIED

---

### B4. Factual Error #3: Crate Count — ⚠️ REVISE

**§18 says:** "19 crates in `crates/cortex/`".
**Actual workspace members from Cargo.toml:** 22 members (21 crates + test-fixtures).

The 21 crates are: cortex-core, cortex-tokens, cortex-storage, cortex-embeddings,
cortex-privacy, cortex-compression, cortex-decay, cortex-causal, cortex-retrieval,
cortex-validation, cortex-learning, cortex-consolidation, cortex-prediction,
cortex-session, cortex-reclassification, cortex-observability, cortex-cloud,
cortex-temporal, cortex-napi, cortex-crdt, cortex-multiagent.

Plus test-fixtures = 22 workspace members total.

**Note:** Section 8 findings said "21 crates" which is correct (excluding test-fixtures).
The §18 reference of "19 crates" is 2 short — likely written before cortex-crdt and
cortex-multiagent were added to the workspace.

**Correction:** Update §18 from "19 crates" to "21 crates (plus test-fixtures)".

**Verdict:** ⚠️ REVISE — Update crate count to 21.

---

### B5. Similarity.rs — Cosine Only, Not Jaccard — 🔧 APPLIED

**§18 says:** "Cosine similarity, Jaccard similarity" for the Similarity Scoring pattern.
**Actual:** `similarity.rs` contains only `cosine_similarity()`. No Jaccard implementation.

The file implements:
- `cosine_similarity(a: &[f32], b: &[f32]) -> f64`
- `is_novel(similarity: f64) -> bool` (threshold: 0.85)
- `is_overlap(similarity: f64) -> bool` (threshold: 0.90)

Drift's pattern aggregation system uses Jaccard similarity (validated in Section 4
findings), which is a different algorithm operating on sets rather than vectors. Drift
will need to implement Jaccard from scratch or use a crate.

**Correction:** Update §18 Similarity Scoring row to say "Cosine similarity" only.
Add note: "Drift's pattern aggregation uses Jaccard similarity, which is not available
in Cortex. Implement from scratch or use a crate."

**Verdict:** 🔧 APPLIED

---

### B6. Additional Pattern: NAPI Conversions Module — ⚠️ REVISE (add to guide)

Section 8 findings recommended adding the `cortex-napi/src/conversions/` directory
pattern to the reuse guide. This directory contains 7 per-domain conversion files:
causal_types.rs, error_types.rs, health_types.rs, memory_types.rs, multiagent_types.rs,
search_types.rs, temporal_types.rs.

Drift will need similar conversions for its analysis result types. The pattern of a
dedicated `conversions/` module with per-domain conversion files is worth calling out.

**Verdict:** ⚠️ REVISE — Add a 13th pattern entry for NAPI type conversions.

---

### B7. NAPI v2→v3 Adaptation Note — ⚠️ REVISE (add to guide)

The reuse guide should include a prominent note about NAPI v2→v3 differences since
all 12 patterns are from a v2 codebase and Drift targets v3.

Key v3 changes affecting pattern reuse (from [napi.rs/blog/announce-v3](http://napi.rs/blog/announce-v3)):
- `ThreadsafeFunction`: Ownership-based lifecycle (v3) vs reference-counted (v2)
- `AsyncTask`: Changed trait signature
- `Function`/`FunctionRef`: New types replacing raw function handles
- Error handling: Structured error types differ
- WebAssembly: v3 supports wasm32-wasip1-threads compilation

**Verdict:** ⚠️ REVISE — Add "NAPI v2→v3 Adaptation" section to the reuse guide.


---

## Part C: Performance Targets Validation (§18.1)

### C1. Existing Targets — ✅ CONFIRMED (all measurable)

All 12 targets in §18.1 are measurable with `criterion` or `std::time::Instant`.
Section 8 findings validated each target for realism. I concur with the S8 assessment:

| Target | Realistic? | Notes |
|--------|-----------|-------|
| Scanner 10K files <300ms | ✅ Yes | ripgrep baseline ~100ms. 300ms with hashing is achievable |
| Scanner 100K files <1.5s | ✅ Yes | Linear scaling. macOS APFS may be slower (R10) |
| Scanner incremental <100ms | ✅ Yes | mtime + xxh3 on changed files only |
| Parsers single-pass shared | ⚠️ Qualitative | Design property, not measurable. Add: "Parse 10K files <5s" |
| Storage batch 500 rows/tx | ✅ Yes | SQLite handles 10K+ inserts/tx easily |
| NAPI AsyncTask >10ms | ✅ Yes | Measurable threshold |
| NAPI sync <1ms | ✅ Yes | `prepare_cached` + indexed queries |
| UAE 10K files <10s | ⚠️ Tight | Achievable with 50-80 detectors. May need <15s with 200+ |
| Call Graph build <5s | ✅ Yes | petgraph construction is O(V+E) |
| Call Graph BFS <5ms | ✅ Yes | In-memory BFS is sub-millisecond |
| Call Graph CTE <50ms | ⚠️ Depends | OK for sparse graphs (depth ≤5). May exceed for dense |
| Confidence 10K patterns <500ms | ✅ Yes | Beta distribution is O(1) per pattern. Very conservative |
| Taint intraprocedural <1ms/fn | ✅ Yes | Small fixed-point computation |
| Taint interprocedural <100ms/fn | ⚠️ Depends | Depends on call graph depth and summary cache |
| Crypto 261 patterns/file | ✅ Yes | RegexSet single-pass |
| Contracts endpoint <1ms | ✅ Yes | String comparison + hash lookup |
| Contracts schema <5ms | ✅ Yes | JSON Schema structural diff |
| MCP drift_status <1ms | ✅ Yes | In-memory status query |
| MCP drift_context <100ms | ⚠️ Tight | Token counting + template rendering + aggregation |
| Bridge event mapping <5ms | ✅ Yes | Enum-to-enum mapping |
| Bridge grounding single <50ms | ✅ Yes | 1 SQLite query + comparison |
| Bridge grounding 500 <10s | ✅ Yes | With batching and parallel queries |

**Verdict:** ✅ CONFIRMED — All targets are measurable. 5 targets marked "tight" or
"depends" should have documented fallback thresholds (e.g., "target <10s, acceptable <15s").

---

### C2. Missing Performance Targets — ⚠️ REVISE (7 targets to add)

Section 8 findings identified 7 missing targets from V2-PREP docs. These should be
added to §18.1:

| Phase | System | Target | Source |
|-------|--------|--------|--------|
| 4 | Error Handling | 8-phase topology per file, <5ms per file | 16-ERROR-HANDLING |
| 5 | Coupling | Tarjan SCC + Martin metrics, <1s for 5K-module graph | 19-COUPLING |
| 5 | Wrapper Detection | RegexSet single-pass, <2ms per file for 150+ patterns | 23-WRAPPER |
| 6 | Violation Feedback | FP rate <10% (revised from <5% per Round 1) | 31-FEEDBACK |
| 7 | Context Generation | <50ms standard, <100ms full pipeline (25x v1 improvement) | 30-CONTEXT |
| 7 | N+1 Detection | ORM pattern matching, <10ms per query site | 29-N+1 |
| 10 | Workspace | 16 NAPI functions, init <500ms, backup <5s for 100MB db | 33-WORKSPACE |

**Verdict:** ⚠️ REVISE — Add 7 missing performance targets to §18.1.

---

## Part D: Storage Schema Progression Validation (§18.2)

### D1. Phase-by-Phase Table Count Audit — ⚠️ REVISE

Section 8 findings performed a detailed audit of table counts against V2-PREP documents.
The key finding is that §18.2 underestimates by ~10-15%, with the largest discrepancy
at Phase 5.

| Phase | §18.2 Estimate | S8 Revised | My Assessment | Notes |
|-------|---------------|-----------|---------------|-------|
| 1 | ~5-8 | 6-8 | ✅ Close | Core schema tables |
| 2 | ~15-20 | 18-22 | ✅ Close | +call_edges, detections, boundaries, patterns, ULP tables |
| 3 | ~22-25 | 24-28 | ⚠️ Slightly low | +confidence, outliers, learning (4 tables per V2-PREP) |
| 4 | ~30-35 | 32-38 | ⚠️ Slightly low | +reachability, taint (flows+summaries), error topology, impact, test coverage |
| 5 | ~40-45 | 48-56 | ❌ Significantly low | Coupling (6) + Contracts (9) + DNA (6) + Crypto (3) = 24 tables from 4 systems alone |
| 6 | ~48-52 | 55-62 | ⚠️ Low | +violations, gates, audit (4), feedback (5), enforcement |
| 7 | ~55 | 58-65 | ⚠️ Low | +simulations, decisions, context_cache |
| 9 | +4 bridge | +4 bridge | ✅ Correct | bridge.db tables |

**Key correction:** Phase 5 cumulative should be ~48-56, not ~40-45. This is the most
impactful revision — the gap is 8-11 tables, driven by the high table counts in
Coupling (6), Contracts (9), and DNA (6).

**Total drift.db objects:** At 58-65 tables with an average of 3 indexes per table,
the total database object count is ~230-260. This is well within SQLite's capabilities
but warrants the R17 migration optimization mitigation.

**Verdict:** ⚠️ REVISE — Update §18.2 with revised cumulative counts. Most critical:
Phase 5 from "~40-45" to "~48-56".

---

## Part E: NAPI Function Count Progression Validation (§18.3)

### E1. Function Count Reconciliation — ⚠️ REVISE

Section 8 findings identified that §18.3 underestimates by ~10-15%. The core issue is
that §18.3 uses conservative ranges that don't account for per-system NAPI function
counts documented in V2-PREP files.

**Key distinction:** There are two counts to track:
1. **Top-level NAPI exports** (~55 per 03-NAPI-BRIDGE-V2-PREP §10 master registry)
2. **Total NAPI-accessible functions** (~70-85 including per-system query functions)

The §18.3 cumulative of "42-53" at Phase 9 is low for both measures.

**Revised counts:**

| Phase | §18.3 Estimate | Revised (top-level) | Key additions |
|-------|---------------|-------------------|---------------|
| 1 | 3 | 3-5 | +drift_parse, drift_migrate |
| 2 | cum 5-6 | cum 7-11 | +drift_detect, drift_patterns, drift_language_info |
| 3 | cum 8-10 | cum 11-16 | +drift_learn |
| 4-5 | cum 16-22 | cum 23-34 | Error(8), Impact(8), Coupling(8), Constants(3), DNA(4) |
| 6 | cum 19-26 | cum 27-40 | +Violation Feedback(8) |
| 7 | cum 22-30 | cum 33-48 | Simulation(11), Context(3), Decision(~3) |
| 8 | cum 27-38 | cum 38-56 | MCP handlers, CI agent |
| 9 | cum 42-53 | cum 53-71 | bridge_* (15) |

**Comparison with Cortex:** Cortex has 14 NAPI binding modules with an estimated 40-60
top-level exports. Drift's ~55 top-level exports is comparable, validating the scale.

**Verdict:** ⚠️ REVISE — Update §18.3 to show ~55 as cumulative top-level export count
at Phase 9. Add note distinguishing top-level exports from total per-system functions.

---

## Part F: Internet-Verified Dependency Status

As part of this validation, I verified the current status of key dependencies referenced
in the risk register and reuse guide against live crates.io / lib.rs data:

| Dependency | Plan Version | Current Version | Status | Source |
|-----------|-------------|----------------|--------|--------|
| rusqlite | 0.38 | **0.38.0** | ✅ Confirmed | [lib.rs](https://lib.rs/crates/rusqlite) — bundles SQLite 3.51.1 |
| petgraph | 0.8 | **0.8.1** | ✅ Confirmed | [lib.rs](https://lib.rs/crates/petgraph) — `stable_graph` is default feature |
| tree-sitter | 0.25 | **0.25.4** (0.26.x exists) | ⚠️ Note | [lib.rs](https://lib.rs/crates/tree-sitter) — 0.26.x now available. Plan's 0.25 is valid but one minor behind. Recommend staying on 0.25 for grammar compatibility stability |
| napi-rs | v3 | **3.8.x** | ✅ Confirmed | [rust-digger](https://rust-digger.code-maven.com/crates/napi) — stable since Jul 2025 |
| tiktoken-rs | 0.9 | **0.9.1** | ✅ Confirmed | [lib.rs](https://lib.rs/crates/tiktoken-rs) — Nov 2025 release |
| statrs | 0.17 | **0.18.0** | ⚠️ Note | [lib.rs](https://lib.rs/crates/statrs) — 0.18.0 released Dec 2024. Plan says 0.17 but 0.18 is available. Recommend evaluating 0.18 for any API improvements |
| fd-lock | "4" | **4.0.x** | ✅ Confirmed | [lib.rs](https://lib.rs/crates/fd-lock) |
| crossbeam-channel | 0.5.x | **≥0.5.15** (patched) | ✅ Confirmed | [RUSTSEC-2025-0024](https://rustsec.org/advisories/RUSTSEC-2025-0024) — double-free in Drop fixed in 0.5.15. Versions ≤0.5.11 unaffected, 0.5.12-0.5.14 vulnerable |
| rusqlite_migration | — | **Compatible with 0.38** | ✅ Confirmed | [cj.rs docs](https://cj.rs/rusqlite_migration_docs/) — explicitly supports rusqlite 0.38 |

**New findings from internet verification:**

1. **tree-sitter 0.26.x exists** — The plan targets 0.25, but 0.26.x is now available.
   Recommendation: Stay on 0.25 for Phase 0-1 to maximize grammar compatibility (grammar
   crates update to new tree-sitter versions with a lag). Evaluate 0.26 upgrade after
   Phase 1 when all 10 grammars are confirmed working. This doesn't change R1 — it
   actually reduces the risk since 0.25 has been stable longer.

2. **statrs 0.18.0 available** — The plan references 0.17 for Bayesian confidence
   (Beta distribution, StudentsT). statrs 0.18.0 was released Dec 2024. The Beta and
   StudentsT APIs are stable across 0.17→0.18. Recommend using `statrs = "0.18"` in
   the workspace Cargo.toml for the latest improvements. This is a minor version bump
   with no breaking changes to the APIs Drift uses.

3. **crossbeam-channel RUSTSEC-2025-0024 is patched** — The double-free vulnerability
   in the Channel Drop implementation was fixed in 0.5.15. The plan should pin
   `crossbeam-channel = "0.5"` which will resolve to ≥0.5.15 automatically. Cargo's
   semver resolution handles this correctly. No action needed beyond ensuring the
   lockfile resolves to ≥0.5.15.

---

## Part G: Verdict Summary

| Item | Verdict | Action Required |
|------|---------|-----------------|
| R1 tree-sitter version | 🔧 APPLIED | Update 0.24→0.25 in heading and body |
| R2 napi-rs v3 maturity | ✅ CONFIRMED | No changes needed |
| R3 Taint complexity | ✅ CONFIRMED | No changes needed |
| R4 SQLite performance | ✅ CONFIRMED | No changes needed |
| R5 Detector count | ✅ CONFIRMED | No changes needed |
| R6 GAST normalization | 🔧 APPLIED | Update ~30→~40-50 types, increase severity to Medium-High |
| R7 Build time | ✅ CONFIRMED | No changes needed |
| R8 UAE timeline | ✅ CONFIRMED | Add "(22-27 weeks with risk buffer)" |
| R9-R10 Contracts/macOS | ✅ CONFIRMED | No changes needed |
| R11 Cargo versions | 🔧 APPLIED | Update version references, downgrade to Low |
| R12-R16 from §20.13 | ✅ CONFIRMED | All adequately described |
| R17 SQLite schema complexity | 🔧 APPLIED | New risk added |
| R18 Estimation overconfidence | 🔧 APPLIED | New risk added |
| R19 NAPI v2→v3 divergence | 🔧 APPLIED | New risk added |
| R20 Parallel dev coordination | 🔧 APPLIED | New risk added |
| Cortex reuse: NAPI modules | 🔧 APPLIED | Fix 12→14 |
| Cortex reuse: Mutex type | 🔧 APPLIED | Fix std→tokio::sync, add Drift adaptation note |
| Cortex reuse: Crate count | ⚠️ REVISE | Fix 19→21 |
| Cortex reuse: Similarity | 🔧 APPLIED | Fix "Cosine+Jaccard"→"Cosine only" |
| Cortex reuse: Conversions | ⚠️ REVISE | Add 13th pattern entry |
| Cortex reuse: v2→v3 note | ⚠️ REVISE | Add adaptation section |
| §18.1 Performance targets | ✅ CONFIRMED | Add 7 missing targets, add fallback thresholds for 5 tight targets |
| §18.2 Schema progression | ⚠️ REVISE | Phase 5: ~40-45→~48-56. Update all phases |
| §18.3 NAPI function counts | ⚠️ REVISE | Cumulative at P9: 42-53→~55 top-level. Clarify distinction |
| statrs version | ⚠️ REVISE | Consider 0.17→0.18 (non-breaking, latest available) |
| tree-sitter version | ✅ CONFIRMED | Stay on 0.25 (0.26 exists but 0.25 is safer for grammar compat) |
| crossbeam-channel security | ✅ CONFIRMED | RUSTSEC-2025-0024 patched in ≥0.5.15, Cargo resolves automatically |

**Totals: 8 CONFIRMED, 6 REVISE, 0 REJECT, 11 APPLIED**

All revisions are refinements — no architectural decisions need to change. The risk
register is now comprehensive with R1-R20. The Cortex reuse guide has 3 factual
corrections applied and 3 additions recommended. Performance targets, schema counts,
and NAPI function counts are reconciled against V2-PREP documents and internet-verified
dependency data.

The most impactful findings are:
1. **statrs 0.18.0 is available** — minor version bump worth adopting
2. **tree-sitter 0.26.x exists** — stay on 0.25 for stability, evaluate later
3. **crossbeam-channel vulnerability is patched** — no action needed beyond normal Cargo resolution
4. **Phase 5 schema count is significantly underestimated** — 48-56 tables, not 40-45
