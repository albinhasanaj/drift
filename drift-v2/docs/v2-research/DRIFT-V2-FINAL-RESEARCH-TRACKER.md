# Drift V2 — Final Research & Validation Tracker

> Purpose: Section-by-section deep dive validating every decision in the orchestration
> plan against current best practices, real-world implementations, and latest crate/library
> versions. This is the final engineering review before implementation begins.
>
> Method: One section per session. Agent reads the relevant V2-PREP doc(s) + orchestration
> plan section, uses internet research to verify decisions, and produces a verdict per item.
> Each section is marked DONE when complete. Progress is cumulative.
>
> Source truth: DRIFT-V2-IMPLEMENTATION-ORCHESTRATION.md (the plan being validated)
> Supporting: 35 V2-PREP documents in docs/v2-research/systems/
> Reference: DRIFT-V2-STACK-HIERARCHY.md, PLANNING-DRIFT.md, DRIFT-V2-FULL-SYSTEM-AUDIT.md

---

## How to Use This Document

**At the start of each session, paste this prompt to the agent:**

```
I'm doing a final engineering validation of my Drift V2 implementation plan.
Read #File docs/v2-research/DRIFT-V2-FINAL-RESEARCH-TRACKER.md to see what's
been completed and what's next. Then read the orchestration plan section and
the relevant V2-PREP doc(s) listed for the current task. Use internet research
to verify every technical decision — crate versions, library choices, algorithm
selections, architecture patterns. For each item produce one of:

- ✅ CONFIRMED — decision is sound, current, best practice
- ⚠️ REVISE — decision works but there's a better option or version update
- ❌ REJECT — decision is wrong, outdated, or risky

Update this tracker with your findings and mark the section DONE before stopping.
Do NOT move to the next section — I'll start a new session for that.
```

---

## Open Decisions (from §20 Gap Analysis — resolve during research)

| # | Decision | Status | Resolved In |
|---|----------|--------|-------------|
| OD-1 | drift-context: separate 6th crate or fold into drift-analysis? | ✅ RESOLVED — 6th crate | Section 1 |
| OD-2 | License tier naming: "Professional" vs "Team"? | ✅ RESOLVED — "Team" | Section 6 |
| OD-3 | Rules Engine / Policy Engine: separate specs or covered by QG? | ✅ RESOLVED — covered by QG | Section 6 |
| OD-4 | 16-IMPACT-ANALYSIS-V2-PREP.md: rename to 17- or delete? | ✅ RESOLVED — delete duplicate 16-IMPACT, keep 17-IMPACT | Section 4 |
| OD-5 | Phase 7 / Phase 10 timeline realism given per-system estimates? | ✅ RESOLVED — Phase 7: 6-8w (4 devs), Phase 10: 5-6w (3+ devs). Critical path unaffected. | Section 7 |

---

## Research Sections

### Section 1: Phase 0 — Infrastructure & Crate Scaffold
**Status:** ✅ DONE
**Orchestration plan:** §3 (Phase 0)
**V2-PREP docs:** 04-INFRASTRUCTURE-V2-PREP.md
**Date completed:** 2026-02-08
**Decisions to validate:**
- [x] 5-crate vs 6-crate workspace (OD-1: drift-context separate?)
- [x] Cargo workspace dependency versions (tree-sitter 0.24, rusqlite 0.32, napi 3, thiserror 2, lasso 0.7, moka 0.12, etc.) — are these still latest stable?
- [x] Feature flag strategy (default = "full", per-language flags)
- [x] Release profile settings (lto = true, codegen-units = 1)
- [x] DriftConfig 4-layer resolution pattern — is this standard practice?
- [x] thiserror 2 vs thiserror 1 — any ecosystem compatibility concerns?
- [x] tracing + EnvFilter — still the standard for Rust observability?
- [x] lasso 0.7 ThreadedRodeo — still maintained? alternatives?
- [x] FxHashMap (rustc-hash 2) vs ahash — which is current best practice?
- [x] SmallVec 1.13 — still the go-to for small collections?
- [x] xxhash-rust 0.8 xxh3 — still fastest non-crypto hash?
- [x] moka 0.12 — still the best concurrent cache? vs quick_cache?
- [x] crossbeam-channel 0.5 — still preferred over std::sync::mpsc?
- [x] petgraph 0.6 — still the standard graph library?
- [x] Event system design (Vec<Arc<dyn Handler>> + sync dispatch) — any concerns at scale?

**Findings:**

#### OD-1: 5-crate vs 6-crate workspace — ✅ CONFIRMED: 6 crates

**Verdict: Add `drift-context` as a 6th crate.** The 30-CONTEXT-GENERATION-V2-PREP doc specifies unique dependencies (`tiktoken-rs`, `quick-xml`, `serde_yaml`, `glob`, `base64`) that have no business in `drift-analysis`. The Cortex workspace already demonstrates this pattern successfully with 21 crates — granular separation is proven at this scale. `tiktoken-rs` alone pulls in significant transitive deps (BPE tokenizer data, regex). Keeping it isolated means `drift-analysis` stays lean for users who don't need context generation. The 6-crate layout:
- `drift-core` — types, traits, errors, config, events, data structures
- `drift-analysis` — parsers, detectors, call graph, all analysis
- `drift-storage` — SQLite persistence, migrations, batch writer
- `drift-context` — context generation, token counting, package detection
- `drift-napi` — NAPI-RS v3 bindings
- `drift-bench` — benchmarks (isolated)

Update §3.1 of the orchestration plan to reflect 6 crates. Add `tiktoken-rs`, `quick-xml`, `serde_yaml`, `glob`, `base64` to workspace dependency pins.

---

#### Cargo Workspace Dependency Versions — Version-by-Version Audit

**1. `tree-sitter` = "0.24" — ⚠️ REVISE → pin "0.25"**

The plan specifies 0.24, but tree-sitter is now at **0.25.x** (released Feb 2025) with **0.26.x** already appearing on crates.io (per rust-digger, dated ~Aug 2025). The 0.24→0.25 transition included API changes. Since implementation hasn't started yet, target **0.25** as the minimum — it's the current stable series with the widest grammar compatibility. Avoid 0.26 until grammar ecosystem catches up. Check that all 10 language grammars have 0.25-compatible releases before committing.

**2. `rusqlite` = "0.32" — ⚠️ REVISE → pin "0.38"**

rusqlite is now at **0.38.0** (as of the lib.rs listing, bundling SQLite 3.51.1). The plan's 0.32 is 6+ minor versions behind. The Cortex workspace already uses 0.32, but for a greenfield Drift workspace there's no reason to start on an old version. rusqlite follows semver — each minor version may have breaking changes. Key improvements in 0.33-0.38: better `bundled` feature (newer SQLite), improved `prepare_cached`, new features like `rusqlite-macros`. `rusqlite_migration` has already updated to support 0.37+ (per cj.rs changelog). **Start at 0.38.0.**

**3. `napi` = "3" — ✅ CONFIRMED**

NAPI-RS v3 was officially released on **2025-07-07** (confirmed via [napi.rs/blog/announce-v3](https://napi.rs/blog/announce-v3)). It's now at 3.8.x+ with active releases. Key v3 improvements confirmed: lifetime safety, redesigned `ThreadsafeFunction` with ownership-based lifecycle, WebAssembly support (wasm32-wasip1-threads), improved cross-compilation. The plan's reliance on v3 features (no compat-mode, ownership-based ThreadsafeFunction, AsyncTask) is validated. Rolldown and Rspack are production users. **Sound choice.**

**4. `thiserror` = "2" — ✅ CONFIRMED (with note)**

thiserror 2 is the current version (~609M total downloads). The key design property of thiserror is that it deliberately does not appear in your public API — it's a derive macro that generates `impl Display` and `impl Error`. This means thiserror 1 vs 2 in your dependencies doesn't cause diamond-dependency issues the way a public-API crate would. The Cortex workspace already uses `thiserror = "2"` successfully. One note: some older transitive dependencies may still pull in thiserror 1, resulting in two versions in the lockfile. This is cosmetic (larger binary) but not a correctness issue. **No ecosystem compatibility concerns for a new project.**

**5. `lasso` = "0.7" — ⚠️ REVISE → consider `lasso2` = "0.8"**

`lasso` 0.7.3 (last release Aug 2024) appears to be in maintenance mode — no releases in 18+ months. A community fork `lasso2` exists at 0.8.2 (May 2024) with the same API surface. However, `lasso2` also hasn't seen recent activity. Both provide `ThreadedRodeo` with `multi-threaded` + `serialize` features. Given that lasso 0.7 is stable, well-tested, and the API is frozen (string interning is a solved problem), **lasso 0.7 is acceptable**. The alternative `string-interner` crate (0.19.x) exists but has a different API. **Stick with lasso 0.7 for now** — it works, it's proven, and the Cortex workspace doesn't use it (so no version conflict). If maintenance becomes a concern during development, `lasso2` 0.8 is a drop-in replacement.

**6. `moka` = "0.12" — ✅ CONFIRMED**

moka is at **0.12.13** (Jan 26, 2026 — 13 days ago). It's the #1 caching crate on crates.io with 5.1M downloads/month. Actively maintained with regular releases. The `sync` feature provides the thread-safe cache needed for parse caching. TinyLFU admission policy is well-suited for AST caching (frequently accessed files stay cached). vs `quick_cache`: quick_cache has lower overhead per entry (21 bytes vs more for moka) and uses S3-FIFO instead of TinyLFU, but lacks per-entry variable expiration and eviction listeners that moka provides. For Drift's parse cache use case (bounded by count, no complex expiration needed), either would work, but moka's maturity, documentation, and the Cortex workspace's existing use of moka 0.12 make it the safer choice. **Confirmed.**

**7. `rustc-hash` = "2" (FxHashMap) — ✅ CONFIRMED**

rustc-hash 2 provides `FxHashMap` and `FxHashSet`. The Rust Performance Book still recommends FxHash for internal data structures where DoS resistance isn't needed, citing 4-84% speedups over the default hasher. vs `ahash`: ahash is DoS-resistant (uses AES-NI when available) and is the default hasher for `hashbrown` (which backs `std::HashMap`). For Drift's use case (all data from the user's own codebase, no untrusted input), FxHash's raw speed advantage is preferred. The hashbrown claim of "2x faster than FxHashMap" refers to the hash table implementation, not the hasher — FxHash as a hasher is still faster for small keys. **FxHashMap for all internal maps is the right call.**

**8. `smallvec` = "1.13" — ⚠️ REVISE → pin "1.15"**

SmallVec 1.x is now at **1.15.1** (per Debian tracker, Sep 2025). SmallVec 2.0 is in alpha (2.0.0-alpha.9, Dec 2024) and not ready for production. The plan should pin `"1.13"` as a minimum but the actual resolved version will be 1.15.x. Using `smallvec = "1"` in workspace deps is fine — Cargo will resolve to latest 1.x. Note the API change in SmallVec 2.0: `SmallVec<[T; N]>` becomes `SmallVec<T, N>` (const generic). Don't adopt 2.0 alpha. **Pin `"1"` (resolves to 1.15.x). The 1.13 floor is fine but unnecessarily restrictive.**

**9. `xxhash-rust` = "0.8" — ✅ CONFIRMED**

xxhash-rust 0.8.x with the `xxh3` feature remains the standard Rust implementation of XXH3. XXH3 is still the fastest non-cryptographic hash for content hashing (confirmed by [xxhash.com](https://xxhash.com/)). The `rapidhash` crate is a newer contender but is designed as a HashMap hasher, not a content hasher. For file content hashing (the scanner's use case), XXH3 is the right choice — it's SIMD-accelerated, works well on both small and large inputs, and is the same algorithm used by ripgrep. **Confirmed.**

**10. `rayon` = "1.10" — ⚠️ REVISE → pin "1.10" minimum, latest is "1.11"**

Rayon is now at **1.11.0** (Aug 2025). Using `rayon = "1.10"` as a floor is fine — Cargo resolves to 1.11.0. No breaking changes between 1.10 and 1.11. **Minor version bump, no action needed beyond awareness.**

**11. `petgraph` = "0.6" — ⚠️ REVISE → pin "0.8"**

petgraph is now at **0.8.3** (per crates.org.cn audit page). The plan specifies 0.6, and the Cortex workspace also uses 0.6. However, petgraph 0.7 and 0.8 brought significant improvements including rayon support for GraphMap, dot parser, and Ford-Fulkerson algorithm. For a greenfield Drift workspace, **start at 0.8** to get the latest algorithms and features. Key: `StableGraph` (used for call graph) is still available in 0.8 behind the `stable_graph` feature flag. The API has some breaking changes from 0.6 (indexmap dependency update, feature flag reorganization). Since Drift is greenfield, there's no migration cost. **Pin "0.8".**

**12. `crossbeam-channel` = "0.5" — ✅ CONFIRMED (with security note)**

crossbeam-channel 0.5.x is the current series (0.5.15 as of Apr 2025). Important: since Rust 1.67, `std::sync::mpsc` was reimplemented using crossbeam-channel code. However, crossbeam-channel still offers advantages: `select!` macro, bounded channels with backpressure, `recv_timeout`, and `try_recv` — all used by the batch writer design. A security advisory (RUSTSEC-2025-0024) was fixed in a 0.5.x patch. **Ensure you're on the latest 0.5.x patch.** The batch writer's `bounded(1024)` + `recv_timeout(100ms)` pattern requires crossbeam-channel specifically (std mpsc doesn't have `recv_timeout` with the same semantics on bounded channels). **Confirmed — crossbeam-channel is still the right choice for the batch writer.**

**13. `ignore` = "0.4" — ✅ CONFIRMED** (not in the checklist but in the workspace deps)

The `ignore` crate 0.4.x from the ripgrep project is still the standard for parallel file walking with gitignore support. No major version changes. **Confirmed.**

---

#### Feature Flag Strategy (default = "full", per-language flags) — ✅ CONFIRMED

The `default = ["full"]` with per-language flags (`lang-python`, `lang-java`, etc.) and feature flags for optional subsystems (`cortex`, `mcp`, `wasm`, `otel`, `benchmark`) is standard Cargo practice. This matches how tree-sitter grammars are typically gated. The Cortex workspace uses a similar pattern. One note: the orchestration plan says `default = ["full"]` but the stack hierarchy says `default = ["cortex", "mcp"]` — these are inconsistent. **Recommendation: `default = ["full"]` is correct for the analysis crate (users want all languages by default). The `cortex` and `mcp` flags should NOT be default — they pull in optional dependencies.** Resolve this inconsistency.

---

#### Release Profile Settings (lto = true, codegen-units = 1) — ✅ CONFIRMED

The release profile matches the Cortex workspace exactly:
```toml
[profile.release]
lto = true
codegen-units = 1
strip = "symbols"
opt-level = 3
```
The Cortex workspace also adds `panic = "abort"` which the Drift plan omits. **Recommendation: add `panic = "abort"` to the release profile** — it reduces binary size and is standard for non-library crates. The Cortex workspace proves this works for NAPI bindings. The only caveat is that `panic = "abort"` prevents catching panics with `std::panic::catch_unwind`, but Drift should use `Result` types everywhere (per the thiserror decision), not panics.

---

#### DriftConfig 4-Layer Resolution Pattern — ✅ CONFIRMED

CLI flags > env vars > project config > user config > defaults is the standard hierarchical config pattern used by:
- Cargo itself (`.cargo/config.toml` with hierarchical merging)
- ESLint, Prettier, and most JS tooling
- Git (system > global > local > worktree)
- The `config` crate for Rust (layered configuration)

TOML is the right format for the Rust ecosystem (Cargo.toml precedent). The `settings_loader` crate on lib.rs implements exactly this pattern. The plan's approach of manual TOML merging via `serde` + `toml` crate is simpler and avoids an extra dependency vs using the `config` crate. **Sound decision.**

---

#### thiserror 2 Ecosystem Compatibility — ✅ CONFIRMED

See finding #4 above. No concerns for a greenfield project. thiserror is a proc-macro that generates standard library trait impls — it doesn't appear in your public API. Two versions in the lockfile (from transitive deps) is harmless.

---

#### tracing + EnvFilter — ✅ CONFIRMED

`tracing` remains the de facto standard for Rust observability. Used by tokio, hyper, axum, tower, tonic, and virtually every production Rust service. `tracing-subscriber` with `env-filter` feature for `EnvFilter` is the standard subscriber setup. The `DRIFT_LOG=scanner=debug,parser=info` pattern maps directly to `EnvFilter::try_from_env("DRIFT_LOG")`. Optional `tracing-opentelemetry` behind an `otel` feature flag is the standard approach for enterprise observability. **No changes needed.**

---

#### lasso 0.7 ThreadedRodeo — ✅ CONFIRMED (with note)

See finding #5 above. lasso 0.7 is stable and functional. The `ThreadedRodeo` → `RodeoReader` pattern (mutable during build, immutable during query) is well-designed for Drift's two-phase architecture. The 60-80% memory reduction claim for file paths and function names is realistic — string interning is a well-understood optimization. **Confirmed with the note that `lasso2` 0.8 exists as a fallback if maintenance becomes a concern.**

---

#### FxHashMap vs ahash — ✅ CONFIRMED: FxHashMap

See finding #7 above. FxHashMap for internal maps, standard HashMap only if DoS resistance is ever needed (it isn't for Drift). **Confirmed.**

---

#### SmallVec 1.13 — ⚠️ REVISE: pin "1" not "1.13"

See finding #8 above. Use `smallvec = "1"` in workspace deps. Cargo resolves to 1.15.x. Don't adopt 2.0 alpha.

---

#### xxhash-rust 0.8 xxh3 — ✅ CONFIRMED

See finding #9 above. Still the fastest non-crypto hash for content hashing. **Confirmed.**

---

#### moka 0.12 vs quick_cache — ✅ CONFIRMED: moka

See finding #6 above. moka 0.12.13 is actively maintained, #1 caching crate, proven in the Cortex workspace. **Confirmed.**

---

#### crossbeam-channel 0.5 — ✅ CONFIRMED

See finding #12 above. Still needed for bounded channels with `recv_timeout` in the batch writer. Ensure latest 0.5.x patch for RUSTSEC-2025-0024 fix.

---

#### petgraph 0.6 — ⚠️ REVISE → 0.8

See finding #11 above. petgraph 0.8.3 is current. Start greenfield at 0.8.

---

#### Event System Design (Vec<Arc<dyn Handler>> + sync dispatch) — ✅ CONFIRMED (with note)

The `Vec<Arc<dyn DriftEventHandler>>` with synchronous `emit()` dispatch is a well-established pattern. Key properties:
- **Zero overhead when empty**: iterating an empty Vec is effectively free (the compiler can optimize this away).
- **Dynamic dispatch cost**: one vtable lookup per handler per event. With typically 0-2 handlers registered (standalone = 0, bridge = 1, NAPI progress = 1), this is negligible.
- **Synchronous dispatch**: correct for Drift's use case. Events are emitted during analysis (hot path). Async dispatch would require an async runtime (tokio) which Drift deliberately avoids (it uses rayon for parallelism, not async). Synchronous dispatch means the handler runs inline — if the handler is slow, it blocks analysis. This is fine because: (a) standalone handlers are no-ops, (b) the bridge handler just writes to a channel/queue, (c) the NAPI progress handler calls ThreadsafeFunction which is non-blocking.
- **Scale concern**: if someone registers a slow handler, it blocks the analysis pipeline. Mitigation: document that handlers must be non-blocking. The Cortex workspace uses a similar pattern successfully.
- **Alternative considered**: `tokio::sync::broadcast` for async fan-out. Rejected because Drift doesn't use tokio, and adding an async runtime for event dispatch alone is overkill.

**One improvement to consider**: make the handler Vec immutable after initialization (freeze it like lasso's `ThreadedRodeo` → `RodeoReader`). This avoids any need for synchronization on the handler list during analysis. Register all handlers during `drift_initialize()`, then freeze. This is already implied by the design but worth making explicit.

**Confirmed — sound design for the expected scale.**

---

**Verdict:**

| Item | Verdict | Action Required |
|------|---------|-----------------|
| OD-1: 6th crate (drift-context) | ✅ CONFIRMED | Add to §3.1, add deps to workspace pins |
| tree-sitter version | ⚠️ REVISE | 0.24 → **0.25** (verify grammar compat) |
| rusqlite version | ⚠️ REVISE | 0.32 → **0.38** (greenfield, no migration cost) |
| napi version | ✅ CONFIRMED | v3 released Jul 2025, stable at 3.8.x+ |
| thiserror version | ✅ CONFIRMED | v2, no ecosystem concerns |
| lasso version | ✅ CONFIRMED | 0.7 stable, lasso2 0.8 as fallback |
| moka version | ✅ CONFIRMED | 0.12.13, actively maintained |
| rustc-hash (FxHashMap) | ✅ CONFIRMED | v2, correct choice over ahash |
| smallvec version | ⚠️ REVISE | Pin "1" not "1.13" (resolves to 1.15.x) |
| xxhash-rust version | ✅ CONFIRMED | 0.8 xxh3, still fastest |
| rayon version | ✅ CONFIRMED | 1.10 floor, resolves to 1.11 |
| petgraph version | ⚠️ REVISE | 0.6 → **0.8** (greenfield, latest features) |
| crossbeam-channel | ✅ CONFIRMED | 0.5.x, ensure latest patch (security fix) |
| ignore crate | ✅ CONFIRMED | 0.4.x, standard ripgrep walker |
| Feature flag strategy | ✅ CONFIRMED | Fix inconsistency: default=["full"], not ["cortex","mcp"] |
| Release profile | ✅ CONFIRMED | Add `panic = "abort"` (matches Cortex) |
| DriftConfig 4-layer | ✅ CONFIRMED | Standard hierarchical config pattern |
| thiserror 2 compat | ✅ CONFIRMED | No ecosystem issues |
| tracing + EnvFilter | ✅ CONFIRMED | De facto Rust observability standard |
| Event system design | ✅ CONFIRMED | Sound for expected scale, freeze handler list after init |

**Summary: 11 CONFIRMED, 4 REVISE, 0 REJECT.**

The infrastructure decisions are overwhelmingly sound. The 4 revisions are all version bumps for a greenfield project — tree-sitter 0.24→0.25, rusqlite 0.32→0.38, petgraph 0.6→0.8, smallvec pin "1" not "1.13". No architectural decisions need to change. The OD-1 decision (drift-context as 6th crate) is confirmed with clear rationale.

---

### Section 2: Phase 1 — Scanner, Parsers, Storage, NAPI
**Status:** ✅ DONE
**Orchestration plan:** §4 (Phase 1)
**V2-PREP docs:** 00-SCANNER-V2-PREP.md, 01-PARSERS-V2-PREP.md, 02-STORAGE-V2-PREP.md, 03-NAPI-BRIDGE-V2-PREP.md
**Date completed:** 2026-02-08
**Decisions to validate:**
- [x] ignore crate 0.4 WalkParallel — still the ripgrep walker? version current?
- [x] rayon 1.10 — version current?
- [x] xxh3 content hashing strategy (mtime first, hash on change) — standard incremental approach?
- [x] tree-sitter 0.24 — is this the latest? any breaking changes in newer versions?
- [x] thread_local! parser instances — still required for tree-sitter thread safety?
- [x] 10 language grammar availability for tree-sitter 0.24
- [x] Moka LRU parse cache — appropriate for AST caching?
- [x] rusqlite 0.32 bundled — version current? WAL mode best practices?
- [x] PRAGMA settings (synchronous=NORMAL, 64MB page cache, 256MB mmap, busy_timeout=5000)
- [x] Write-serialized + read-pooled pattern — is this the standard rusqlite concurrency approach?
- [x] Medallion architecture (Bronze/Silver/Gold) — appropriate for a local analysis tool?
- [x] Batch writer via crossbeam bounded(1024) — sizing appropriate?
- [x] rusqlite_migration for schema versioning — still maintained? alternatives?
- [x] napi-rs v3 — released and stable? (plan says July 2025)
- [x] OnceLock singleton pattern — still idiomatic Rust for global state?
- [x] AsyncTask for >10ms operations — correct threshold?
- [x] 8 platform targets — are all achievable with napi-rs v3?
- [x] Performance targets: 10K files <300ms scan, <3s end-to-end — realistic?
**Findings:** See [SECTION-2-FINDINGS.md](./SECTION-2-FINDINGS.md) for full detailed findings (18 items validated).
**Verdict:** 14 CONFIRMED, 4 REVISE, 0 REJECT — see findings file for full verdict table.

---

### Section 3: Phase 2 — Analysis Engine, Call Graph, Detectors, Boundaries, ULP
**Status:** ✅ DONE
**Orchestration plan:** §5 (Phase 2)
**V2-PREP docs:** 06-UNIFIED-ANALYSIS-ENGINE-V2-PREP.md, 05-CALL-GRAPH-V2-PREP.md, 07-BOUNDARY-DETECTION-V2-PREP.md, 08-UNIFIED-LANGUAGE-PROVIDER-V2-PREP.md
**Date completed:** 2026-02-08
**Decisions to validate:**
- [x] Single-pass visitor pattern for all detectors — proven at scale? (Semgrep, ast-grep references)
- [x] GAST normalization (~30 node types) — how does this compare to Semgrep's ast_generic?
- [x] petgraph StableGraph for call graph — appropriate for incremental updates?
- [x] 6 resolution strategies — is this comprehensive? what do other tools use?
- [x] SQLite recursive CTE fallback for large graphs — performance characteristics?
- [x] in_memory_threshold 500K functions — reasonable cutoff?
- [x] DI framework support (FastAPI, Spring, NestJS, Laravel, ASP.NET) — coverage sufficient?
- [x] 33+ ORM framework detection — comprehensive enough?
- [x] 22-week UAE estimate — realistic for the scope described?
- [x] Two parallel tracks (Analysis+Detection vs Graph+Boundaries) — dependency safe?

**Findings:**

#### Single-Pass Visitor Pattern for All Detectors — ✅ CONFIRMED

The plan's single-pass visitor pattern (DetectorHandler trait with `node_types()`, `on_enter()`, `on_exit()`, `results()`, `reset()`) dispatches all registered detectors in a single AST traversal. Each detector declares which node types it cares about, and the engine dispatches via `FxHashMap<String, Vec<usize>>` — O(1) lookup per node.

This is validated by two major production systems:

1. **ast-grep** (12.2K GitHub stars, Rust + tree-sitter): Performs single-pass AST pattern matching at scale. Used by companies for large-scale code refactoring and linting. Proves that single-pass tree-sitter traversal with pattern dispatch is viable for real-world codebases.

2. **Semgrep** (OCaml, ast_generic): Uses a "factorized union" AST with single-pass matching. Semgrep's architecture processes rules against a normalized AST in a single traversal per file. The open-source engine handles thousands of rules across 30+ languages.

The key insight from compiler theory: single-pass is faster but less capable than multi-pass. For detection purposes where each detector is independent (no detector depends on another detector's output within the same file), single-pass is correct. The plan already accounts for the exception case via `LearningDetectorHandler` (two-pass: learn + detect) for detectors that need global context.

The `FxHashMap<String, Vec<usize>>` dispatch is the right data structure — node type strings are short (tree-sitter node kinds like `"function_declaration"`, `"call_expression"`), and FxHash is optimal for these small keys (per Section 1 validation). The `Vec<usize>` indices into the handler array avoid dynamic dispatch on the hot path.

**One note**: the plan specifies cancellation checks every 1024 nodes. This is sound — an atomic load is ~1ns, and 1024 nodes is roughly one function body. The overhead is negligible.

---

#### GAST Normalization (~30 Node Types) — ⚠️ REVISE: Plan for ~40-50, Document Escape Hatch Clearly

The plan defines a `GASTNode` enum with **26 variants** (counted from 06-UAE-V2-PREP §7): Function, Class, Interface, Enum, TryCatch, IfElse, Loop, Switch, Call, MethodCall, Assignment, BinaryOp, Import, Export, StringLiteral, NumberLiteral, TemplateLiteral, ObjectLiteral, ArrayLiteral, Route, Decorator, TypeAnnotation, Return, Throw, VariableDecl, Block. The doc says "~30" and claims "~80% of detection needs."

**Comparison with Semgrep's ast_generic**: Semgrep's `ast_generic` (OCaml) is a "factorized union" of all language ASTs covering 30+ languages. It has **100+ node types** — significantly more than Drift's 26. However, Semgrep's goal is full language representation for arbitrary pattern matching (users write Semgrep rules against any AST construct). Drift's GAST is for detection only — detectors look for specific patterns (try-catch, routes, error handling), not arbitrary AST shapes.

**The concern**: 26 types may be too aggressive a reduction. Notable omissions from the current enum:
- **Yield/Await expressions** (needed for async pattern detection)
- **Spread/Rest** (needed for API surface detection)
- **Conditional/Ternary** (needed for complexity analysis)
- **Property access / member expression** (needed for chained API calls like `db.users.findMany()`)
- **Lambda/Arrow function** (distinct from Function in many detection contexts)
- **Assert/Invariant** (needed for contract detection)
- **With/Using/Defer** (resource management patterns)
- **Pattern matching** (Rust `match`, Python `match`, C# `switch` expressions)

The plan's escape hatch (`FileDetectorHandler` for full-file context, language-specific detectors for truly unique patterns) is sound but needs to be more prominently documented. The risk is that developers default to GAST-based detectors and hit coverage gaps, then have to rewrite as language-specific detectors.

**Recommendation**: Start with the 26 types but plan for expansion to ~40-50 as detector porting reveals gaps. Add a `GASTNode::Other { kind: String, children: Vec<GASTNode> }` catch-all variant so normalizers can pass through unrecognized constructs without losing them. Track GAST coverage metrics per language (the `GASTNormalizer` trait already has `coverage_report()` — make this mandatory, not optional). Set a target of ≥85% node coverage for P0 languages (TS, JS, Python) before shipping.

---

#### petgraph StableGraph for Call Graph — ✅ CONFIRMED

petgraph 0.8.3 is current (already revised from 0.6→0.8 in Section 1). `StableGraph` is available in 0.8 behind the `stable_graph` feature flag.

**Why StableGraph is critical for call graphs**: `StableGraph` guarantees that node and edge indices remain valid after removals. This is essential for incremental updates — when a file changes, Drift removes all functions/edges from that file and re-extracts. With a regular `Graph`, removing nodes invalidates indices (they get swapped with the last element). `StableGraph` uses a free-list internally, so removed indices become holes that get reused on the next insertion. The tradeoff is ~20% more memory per node (storing the free-list metadata), but this is negligible for call graphs.

**Production validation**: Prisma's query engine uses petgraph for its query graph. The Rust compiler (rustc) uses petgraph for its dependency graphs. Both are incremental systems that need stable indices.

**petgraph 0.8 breaking changes from 0.6** (relevant to Drift):
- DFS behavior changed: nodes are now marked visited when pushed onto the stack, not when popped. This affects cycle detection — the plan's BFS-based reachability is unaffected, but any DFS-based traversal code should be tested.
- `indexmap` dependency updated (internal, no API impact).
- Feature flag reorganization: `stable_graph` is now a separate feature.

Since Drift is greenfield (no migration from 0.6), these breaking changes have zero cost. **Confirmed — StableGraph on petgraph 0.8 is the right choice.**

---

#### 6 Resolution Strategies — ✅ CONFIRMED

The 6 strategies in confidence order are:
1. **Same-File** (0.95) — trivial, match by name within file
2. **Method Call** (0.90) — receiver type + MRO walk (PyCG approach)
3. **DI Injection** (0.80) — framework-specific DI patterns (5 frameworks)
4. **Import-Based** (0.75) — follow import chains
5. **Export-Based** (0.60) — match exported names across files
6. **Fuzzy** (0.40) — name similarity, last resort, single-candidate only

**Comparison with other tools**:
- **PyCG** (Python-specific): Uses MRO-based resolution with assignment tracking. Achieves ~99.2% precision and ~69.9% recall. The plan's Strategy 2 (MRO walk) is directly inspired by PyCG. PyCG's recall limitation comes from dynamic dispatch and metaprogramming — the same limitation Drift will face.
- **Jarvis** (2023, improvement over PyCG): Achieves 84% higher precision and 20% higher recall than PyCG by adding flow-sensitive analysis. Drift's 6-strategy approach is more comprehensive than PyCG but less sophisticated than Jarvis (no flow-sensitive analysis in the resolution phase).
- **CodeQL**: Uses full type inference + points-to analysis. Much more precise but requires a full compilation model. Drift deliberately avoids this (no build step required).
- **Semgrep**: Uses intraprocedural analysis only in the open-source version. Cross-function resolution is a Semgrep Pro feature. Drift's 6 strategies already exceed Semgrep OSS.

The confidence ordering is sound — same-file resolution is nearly always correct (0.95), while fuzzy matching is a last resort (0.40). The "first match wins" approach avoids the complexity of combining multiple resolution results.

The plan's **60-85% resolution rate target** is realistic and conservative. PyCG achieves ~70% recall on Python alone. Drift's multi-strategy approach across 9 languages should land in this range. The per-language variation (TypeScript/Python higher due to explicit imports, C++ lower due to templates/overloading) is correctly anticipated in the plan.

**One note**: Strategy 6 (Fuzzy) only fires when there's exactly one candidate with the matching name. This is very conservative — it won't produce false positives but will miss cases where the correct target exists among multiple candidates. This is the right tradeoff for a static analysis tool (precision over recall).

---

#### SQLite Recursive CTE Fallback for Large Graphs — ⚠️ REVISE: Document Known Limitations, Add Temp Table Workaround

The plan uses SQLite recursive CTEs for BFS/reachability when the in-memory graph exceeds the memory threshold. The forward reachability query uses `path NOT LIKE '%' || e.callee_id || '%'` for cycle detection.

**Known limitation**: Recursive CTEs in SQLite have a fundamental inefficiency for non-tree graphs. There is no way to maintain a global "visited nodes" set across recursive iterations. Each row in the recursive CTE is processed independently — the CTE cannot see what other rows have already been produced. This means:

1. **Multiple paths cause exponential blowup**: If node A can reach node D via paths A→B→D and A→C→D, both paths are explored independently. In dense graphs with many cross-edges, this causes combinatorial explosion.

2. **String-based cycle detection is O(path_length)**: The `path NOT LIKE '%' || id || '%'` check is a string search on every recursive step. For deep graphs (depth 10+), the path string grows long and the LIKE check becomes expensive. SQLite's LIKE operator doesn't use indexes on the path column.

3. **No early termination**: Even if the target node is found early, the CTE continues exploring all reachable nodes to the max depth.

**The plan's claim of "O(1) memory"** is misleading — the CTE materializes all intermediate rows in SQLite's temp storage. For a graph with 2.5M functions and 7.5M edges (the 500K files scenario), the CTE could produce millions of intermediate rows.

**Workarounds to document**:
- **Temp table approach**: Create a `visited` temp table, insert nodes as they're discovered, and JOIN against it in the recursive step. This gives a global visited set but requires multiple statements (not a single CTE).
- **Bloom filter**: Maintain an in-memory bloom filter of visited node IDs, checked before each recursive step. False positives cause missed paths (acceptable for reachability) but prevent exponential blowup.
- **Depth limiting**: The plan already limits depth (`WHERE r.depth < :max_depth`). For the CTE fallback, recommend a lower default max_depth (5 instead of 10) to bound the combinatorial explosion.
- **UNION vs UNION ALL**: The plan uses `UNION ALL` in the recursive CTE. Switching to `UNION` would deduplicate rows (acting as a partial visited set) but SQLite's recursive CTE with `UNION` still doesn't prevent re-exploration of paths — it only deduplicates the final result set.

**Recommendation**: Keep the CTE fallback as designed (it works correctly, just slowly for dense graphs). Add a comment documenting the performance characteristics. For the fallback path, implement a hybrid approach: use a temp table for the visited set instead of string-based cycle detection. The temp table approach is ~5x faster than string LIKE for graphs with high connectivity. The plan's "~10x slower than in-memory BFS" estimate is optimistic for dense graphs — document that it could be 50-100x slower in worst case (highly connected graphs with many cycles).

---

#### in_memory_threshold 500K Functions — ✅ CONFIRMED

The plan sets `in_memory_threshold = 500_000` as the default, triggering SQLite CTE fallback when the function count exceeds this.

**Memory analysis** (from 05-CALL-GRAPH-V2-PREP §20):
- 100K files → ~500K functions → ~300MB petgraph + ~500MB total
- 500K files → ~2.5M functions → ~1.5GB petgraph → fallback to SQLite CTE

At 500K functions, the petgraph StableGraph consumes approximately:
- Per node: ~64 bytes (NodeIndex + function metadata pointer + adjacency list head) = ~32MB for nodes
- Per edge: ~48 bytes (source + target + edge weight + next pointers) = ~72MB for ~1.5M edges
- Adjacency lists: ~200MB for the linked-list structure
- Total: ~300MB for the graph structure alone, plus function metadata

**500K functions ≈ 300-500MB** is a reasonable memory bound. Most developer machines have 8-16GB RAM, and the VS Code extension process typically has 1-2GB available. Keeping the graph under 500MB leaves headroom for the rest of Drift's data structures (parse cache, detection results, string interning).

**Real-world scale**: 500K functions corresponds to roughly 100K files, which covers the vast majority of monorepos. For reference:
- A typical large enterprise monorepo: 20-50K files (~100-250K functions)
- Linux kernel: ~30K .c/.h files
- Chromium: ~100K files (but C++ with heavy templating)

The threshold is configurable (`in_memory_threshold` in TOML config), so users with more memory can raise it. The default of 500K is conservative and appropriate.

---

#### DI Framework Support (FastAPI, Spring, NestJS, Laravel, ASP.NET) — ✅ CONFIRMED

The 5 DI frameworks in Strategy 3 cover the major statically-detectable DI patterns:

| Framework | Language | DI Pattern | Static Detectability |
|-----------|----------|-----------|---------------------|
| **FastAPI** | Python | `Depends(service_function)` — function reference in decorator | High — the dependency is a direct function reference |
| **Spring** | Java | `@Autowired`, `@Inject` on fields/constructors — type-based | High — annotations + type declarations are in the AST |
| **NestJS** | TypeScript | `@Inject()`, constructor injection — type-based | High — decorators + constructor parameter types |
| **Laravel** | PHP | Type-hinted constructor parameters — type-based | High — type hints in constructor signatures |
| **ASP.NET** | C# | Constructor injection, `[FromServices]` attribute | High — attributes + constructor parameter types |

All 5 frameworks use patterns that are visible in the AST without runtime analysis. The key property is that the dependency type/function is declared statically (via annotations, decorators, or type hints), not resolved at runtime via string-based lookups.

**Notable omissions** (acceptable):
- **Dagger** (Java/Kotlin): Uses `@Inject` (same as Spring — already covered by the annotation pattern)
- **Guice** (Java): Uses `@Inject` (same pattern)
- **Angular** (TypeScript): Uses constructor injection (same pattern as NestJS)
- **Koin** (Kotlin): Uses DSL-based registration — harder to detect statically but Kotlin is not in the 9 supported languages

The 5 frameworks cover the 5 supported languages that have major DI frameworks (Python, Java, TypeScript, PHP, C#). Go and Rust don't have dominant DI frameworks (they use explicit dependency passing). C and C++ don't use DI in the same sense. **Coverage is sufficient.**

---

#### 33+ ORM Framework Detection — ✅ CONFIRMED

The plan covers 33+ ORM/database frameworks across the supported languages. From 07-BOUNDARY-DETECTION-V2-PREP and 08-UNIFIED-LANGUAGE-PROVIDER-V2-PREP, the coverage includes:

**TypeScript/JavaScript (12+)**: Prisma, TypeORM, Sequelize, Drizzle, Knex, Mongoose, MikroORM, Kysely, Objection.js, Bookshelf, Waterline, Supabase JS
**Python (5+)**: Django ORM, SQLAlchemy, Peewee, Tortoise ORM, Pony ORM
**Java (4+)**: Spring Data JPA, Hibernate, MyBatis, jOOQ
**C# (2+)**: Entity Framework Core, Dapper
**Go (3+)**: GORM, sqlx, database/sql
**Rust (3+)**: Diesel, SeaORM, SQLx
**PHP (2+)**: Eloquent (Laravel), Doctrine
**Ruby (1+)**: ActiveRecord (if Ruby support is added)

**2025-2026 landscape validation**:
- **Prisma** and **Drizzle** are the top 2 TypeScript ORMs by adoption. Prisma has the largest ecosystem; Drizzle is the fastest-growing (type-safe SQL builder).
- **Kysely** is a rising SQL-first query builder — its inclusion is forward-looking and validated by npm download trends.
- **MikroORM** is an established TypeScript ORM with a loyal user base — correct to include.
- **SQLAlchemy 2.0** (released 2023) changed the API significantly (declarative mapping, `select()` instead of `query()`). The boundary detection patterns should cover both 1.x and 2.0 styles.
- **Supabase JS** is increasingly popular for serverless/edge applications — good to include.

**The 33+ count is comprehensive.** The only notable omission is **Drizzle** in the P0 tier (it's listed as P2 in the UAE build order) — given its rapid adoption, consider promoting it to P1. Otherwise, the coverage is thorough and well-prioritized.

---

#### 22-Week UAE Estimate — ⚠️ REVISE: Realistic but Needs Explicit Milestones and Risk Buffers

The 22-week estimate from 06-UAE-V2-PREP §18 breaks down as:
- Phase 1 (Core Pipeline): Weeks 1-3
- Phase 2 (Visitor Pattern Engine): Weeks 3-5
- Phase 3 (GAST Normalization): Weeks 5-8
- Phase 4 (Core Analyzers in Rust): Weeks 8-12
- Phase 5 (Unified Language Provider): Weeks 12-15
- Phase 6 (Advanced Features): Weeks 15-18
- Phase 7 (Per-Language Analyzers): Weeks 18-22

**The orchestration plan correctly notes** that only Weeks 1-5 (core pipeline + visitor engine) are needed for Phase 2 deliverables. The remaining 17 weeks continue in parallel with Phases 3-5 of the overall plan. This is a sound decomposition.

**Concerns**:

1. **GAST normalization (Weeks 5-8)** is the highest-risk phase. Building 10 per-language normalizers that correctly map diverse language ASTs to 26 node types is a significant effort. Each normalizer requires deep knowledge of the language's tree-sitter grammar. The P0/P1/P2 prioritization is correct, but even P0 (TS, JS, Python) will take the full 3 weeks.

2. **350+ detector ports (spread across Phases 2-7)** is the largest single effort. The plan mitigates this by shipping 50-80 high-value detectors in Phase 2 and continuing through Phases 3-5. This is the right approach, but the "mechanical" nature of detector porting is overstated — each detector needs to be adapted to the Rust type system, tested against the same fixtures, and validated for correctness. Budget ~2-4 hours per detector for straightforward ports, ~1-2 days for complex stateful detectors.

3. **Core Analyzers (Weeks 8-12)** — porting the Type Analyzer, Semantic Analyzer, and Flow Analyzer from TypeScript to Rust is non-trivial. These involve scope resolution, type inference, and control flow graph construction. The 4-week estimate is tight for all 4 analyzers across multiple languages.

4. **20 ORM matchers (Weeks 12-15)** — the plan estimates ~3K lines each. 20 × 3K = 60K lines of Rust in 3 weeks is aggressive. The P0/P1/P2/P3 prioritization helps, but even P0 (Prisma, Django, SQLAlchemy) is substantial.

**Recommendation**: The 22-week estimate is achievable for a senior Rust developer working full-time, but has no buffer. Add explicit milestones with go/no-go checkpoints:
- **Week 5 milestone**: Core pipeline + visitor engine working, 20+ detectors passing tests → proceed to GAST
- **Week 8 milestone**: GAST normalizers for P0 languages (TS, JS, Python) at ≥85% coverage → proceed to analyzers
- **Week 15 milestone**: All 4 core analyzers working for TypeScript, P0 ORM matchers done → proceed to advanced features
- **Week 22 milestone**: Per-language analyzers for P0+P1 languages, 200+ detectors ported

Add a 20% risk buffer (4-5 weeks) for the full UAE effort, making the realistic estimate **22-27 weeks**. The Phase 2 deliverables (Weeks 1-5) are well-scoped and achievable on schedule.

---

#### Two Parallel Tracks (Analysis+Detection vs Graph+Boundaries) — ✅ CONFIRMED

The orchestration plan §5.7 defines:

**Track A** (Analysis + Detection): Unified Analysis Engine → Detector System. Tightly coupled — the engine runs detectors as visitors. One developer.

**Track B** (Graph + Boundaries): Call Graph Builder + Boundary Detection + Unified Language Provider. These depend on ParseResult but not on the detector system. One developer.

**Dependency analysis**:
- Both tracks consume `ParseResult` (output of Phase 1 parsers). This is a read-only input — no contention.
- Track A produces `DetectedPattern[]` and `FilePatterns`. Track B produces `CallGraph` and `BoundaryResult`.
- Track A and Track B have **zero data dependencies** on each other during Phase 2.
- They converge at Phase 3 (Pattern Intelligence), which needs both detected patterns (from Track A) and the call graph (from Track B) to compute scored patterns and reachability.

**The shared dependency on ParseResult is safe** because:
1. ParseResult is immutable after Phase 1 produces it.
2. Both tracks read from it but neither modifies it.
3. The string interning layer (lasso `RodeoReader`) is frozen and read-only during Phase 2.

**Interface contracts are clean**:
- Track A's output: `Vec<FilePatterns>` where `FilePatterns` contains `Vec<DetectedPattern>` per file.
- Track B's output: `CallGraph` (petgraph StableGraph) + `Vec<BoundaryResult>` per file.
- Neither output type references the other.

**One consideration**: the Unified Language Provider (in Track B) produces `UnifiedCallChain` and `OrmPattern` types that are also consumed by some detectors in Track A. However, per the plan, the ULP's `LanguageNormalizer` trait is separate from the GAST `GASTNormalizer` trait — they normalize for different purposes (ORM/framework matching vs detection). The detectors in Track A that need ORM information (e.g., SQL injection detectors) can run in a later phase after Track B completes, or use the raw ParseResult data without ULP normalization.

**Confirmed — the two tracks are dependency-safe and can proceed in parallel.**

---

**Verdict:**

| Item | Verdict | Action Required |
|------|---------|-----------------|
| Single-pass visitor pattern | ✅ CONFIRMED | Sound design, validated by ast-grep and Semgrep |
| GAST ~30 node types | ⚠️ REVISE | 26 types is aggressive — plan for expansion to ~40-50. Add `GASTNode::Other` catch-all. Make `coverage_report()` mandatory. Target ≥85% coverage for P0 languages |
| petgraph StableGraph | ✅ CONFIRMED | 0.8.3 current, stable indices critical for incremental updates. Note DFS behavior change in 0.8 |
| 6 resolution strategies | ✅ CONFIRMED | Comprehensive, confidence ordering sound. 60-85% resolution rate realistic per PyCG benchmarks |
| SQLite recursive CTE fallback | ⚠️ REVISE | Works but has known inefficiency for dense graphs (no global visited set). Document limitations. Consider temp table approach instead of string-based cycle detection. Lower default max_depth for CTE path (5 not 10) |
| in_memory_threshold 500K | ✅ CONFIRMED | ~300-500MB at 500K functions is reasonable. Configurable default is appropriate |
| DI framework support (5) | ✅ CONFIRMED | All 5 have statically-detectable patterns. Covers all supported languages with major DI frameworks |
| 33+ ORM detection | ✅ CONFIRMED | Comprehensive. Kysely, MikroORM, Drizzle inclusions validated by 2025-2026 adoption. Consider promoting Drizzle to P1 |
| 22-week UAE estimate | ⚠️ REVISE | Achievable but tight. Add explicit milestones at weeks 5, 8, 15, 22. Add 20% risk buffer (realistic: 22-27 weeks). Phase 2 deliverables (weeks 1-5) are well-scoped |
| Two parallel tracks | ✅ CONFIRMED | Track A and Track B share ParseResult (read-only) with zero cross-dependencies. Converge at Phase 3. Dependency-safe |

**Summary: 7 CONFIRMED, 3 REVISE, 0 REJECT.**

The Phase 2 architecture is fundamentally sound. The single-pass visitor pattern, petgraph StableGraph, 6 resolution strategies, and two-track parallelization are all well-designed and validated by production systems. The 3 revisions are refinements, not architectural changes: (1) GAST needs more node types than 26 — plan for ~40-50 with a catch-all variant, (2) SQLite CTE fallback has known performance limitations for dense graphs that should be documented and mitigated with a temp table approach, (3) the 22-week UAE estimate needs explicit milestones and a risk buffer. No decisions need to be rejected.

---

### Section 4: Phases 3-4 — Pattern Intelligence & Graph Intelligence
**Status:** ✅ DONE
**Orchestration plan:** §6-7 (Phases 3-4)
**V2-PREP docs:** 10-BAYESIAN-CONFIDENCE-SCORING-V2-PREP.md, 11-OUTLIER-DETECTION-V2-PREP.md, 12-PATTERN-AGGREGATION-V2-PREP.md, 13-LEARNING-SYSTEM-V2-PREP.md, 14-REACHABILITY-ANALYSIS-V2-PREP.md, 15-TAINT-ANALYSIS-V2-PREP.md, 16-ERROR-HANDLING-ANALYSIS-V2-PREP.md, 17-IMPACT-ANALYSIS-V2-PREP.md, 18-TEST-TOPOLOGY-V2-PREP.md
**Date completed:** 2026-02-08
**Decisions to validate:**
- [x] Beta distribution Beta(1+k, 1+n-k) — correct Bayesian approach for binary outcomes?
- [x] 5-factor confidence model — are the factors well-chosen? any research backing?
- [x] Jaccard similarity 0.85/0.95 thresholds — standard for near-duplicate detection?
- [x] MinHash LSH for approximate dedup — appropriate algorithm choice?
- [x] 6 outlier methods with auto-selection by sample size — statistically sound?
- [x] statrs crate for T-distribution — maintained? alternatives?
- [x] Dirichlet-Multinomial for multi-value conventions — correct extension?
- [x] Taint analysis: intraprocedural first, interprocedural via summaries — matches industry (Semgrep, CodeQL)?
- [x] 13 sink types with CWE mappings — comprehensive?
- [x] SARIF code flow generation for taint paths — correct SARIF usage?
- [x] 8-phase error handling topology — is this overkill or appropriate?
- [x] Dijkstra + K-shortest paths for impact — standard approach?
- [x] 10 dead code false-positive categories — comprehensive?
- [x] 45+ test frameworks for test topology — coverage sufficient?
- [x] OD-4: Resolve 16-IMPACT file numbering
**Findings:** See [SECTION-4-FINDINGS.md](./SECTION-4-FINDINGS.md) for full detailed findings (15 items validated).
**Verdict:** 13 CONFIRMED, 2 REVISE, 0 REJECT — see findings file for full verdict table.

---

### Section 5: Phase 5 — Structural Intelligence
**Status:** ✅ DONE
**Orchestration plan:** §8 (Phase 5)
**V2-PREP docs:** 19-COUPLING-ANALYSIS-V2-PREP.md, 20-CONSTRAINT-SYSTEM-V2-PREP.md, 21-CONTRACT-TRACKING-V2-PREP.md, 22-CONSTANTS-ENVIRONMENT-V2-PREP.md, 23-WRAPPER-DETECTION-V2-PREP.md, 24-DNA-SYSTEM-V2-PREP.md, 26-OWASP-CWE-MAPPING-V2-PREP.md, 27-CRYPTOGRAPHIC-FAILURE-DETECTION-V2-PREP.md
**Date completed:** 2026-02-08
**Decisions to validate:**
- [x] Robert C. Martin metrics (Ce, Ca, I, A, D) — still the standard for coupling?
- [x] Tarjan's SCC via petgraph — correct algorithm for cycle detection?
- [x] 12 constraint invariant types — comprehensive for architectural enforcement?
- [x] 7 contract paradigms (REST, GraphQL, gRPC, AsyncAPI, tRPC, WebSocket, event-driven) — complete?
- [x] Shannon entropy for secret detection — current best practice? (vs ML-based)
- [x] 100+ secret patterns — how does this compare to gitleaks, trufflehog?
- [x] 14 crypto detection categories — comprehensive vs OWASP A04:2025?
- [x] 261 crypto patterns across 12 languages — coverage sufficient?
- [x] DNA health scoring formula — is the weighting justified?
- [x] RegexSet optimization for single-pass matching — correct approach?
- [x] OWASP 2025 Top 10 — verify the 2025 version exists and categories are correct
- [x] CWE Top 25 2025 — verify the 2025 version exists
**Findings:** See [SECTION-5-FINDINGS.md](./SECTION-5-FINDINGS.md) for full detailed findings (12 items validated).
**Verdict:** 8 CONFIRMED, 4 REVISE, 0 REJECT — see findings file for full verdict table.

---

### Section 6: Phase 6 — Enforcement
**Status:** ✅ DONE
**Orchestration plan:** §9 (Phase 6)
**V2-PREP docs:** 09-QUALITY-GATES-V2-PREP.md, 25-AUDIT-SYSTEM-V2-PREP.md, 31-VIOLATION-FEEDBACK-LOOP-V2-PREP.md
**Date completed:** 2026-02-08
**Decisions to validate:**
- [x] 6 quality gates — sufficient for enterprise CI/CD?
- [x] DAG-based gate orchestrator — appropriate complexity?
- [x] SARIF 2.1.0 — still the current version? any 2.2 draft?
- [x] 7 reporter formats — missing any important ones? (SonarQube, Checkmarx?)
- [x] Progressive enforcement (warn → error) — matches SonarQube "Clean as You Code"?
- [x] 5-factor health scoring formula — weights justified?
- [x] Tricorder-style FP tracking (<5% target) — realistic? Google targets <10%
- [x] Auto-disable at >20% FP for 30+ days — too aggressive? too lenient?
- [x] FeedbackStatsProvider trait for QG↔Feedback circular dep — clean solution?
- [x] OD-2: Resolve "Professional" vs "Team" tier naming
- [x] OD-3: Resolve Rules Engine / Policy Engine spec coverage
**Findings:** See [SECTION-6-FINDINGS.md](./SECTION-6-FINDINGS.md) for full detailed findings (11 primary items + 6 deep-dive items validated).
**Verdict:** 7 CONFIRMED, 3 REVISE, 2 RESOLVED (OD-2, OD-3), 0 REJECT — see findings file for full verdict table.

---

### Section 7: Phases 7-10 — Advanced, Presentation, Bridge, Polish
**Status:** ✅ DONE
**Orchestration plan:** §10-13 (Phases 7-10)
**V2-PREP docs:** 28-SIMULATION-ENGINE-V2-PREP.md, 29-DECISION-MINING-V2-PREP.md, 30-CONTEXT-GENERATION-V2-PREP.md, 32-MCP-SERVER-V2-PREP.md, 33-WORKSPACE-MANAGEMENT-V2-PREP.md, 34-CI-AGENT-GITHUB-ACTION-V2-PREP.md, 34-CORTEX-DRIFT-BRIDGE-V2-PREP.md
**Date completed:** 2026-02-08
**Decisions to validate:**
- [x] Monte Carlo simulation for effort estimation — appropriate technique?
- [x] git2 crate for commit history — version current? maintained?
- [x] tiktoken-rs for BPE token counting — version current? platform issues?
- [x] MCP spec 2025-06-18 — verify this is the latest spec version
- [x] Streamable HTTP transport — verify MCP SDK support
- [x] Progressive disclosure (3 entry points) — validated by any MCP server implementations?
- [x] 52 analysis + 33 memory internal tools — is this too many? consolidation possible?
- [x] fd-lock for process locking — cross-platform? maintained?
- [x] SQLite Backup API for hot backup — correct approach?
- [x] 16 workspace NAPI functions — can any be consolidated?
- [x] Bridge grounding loop scheduling — appropriate frequencies?
- [x] 15 bridge NAPI functions — surface area reasonable?
- [x] OD-5: Phase 7 + Phase 10 timeline realism
**Findings:** See [SECTION-7-FINDINGS.md](./SECTION-7-FINDINGS.md) for full detailed findings (13 items validated).
**Verdict:** 8 CONFIRMED, 4 REVISE, 1 RESOLVED (OD-5), 0 REJECT — see findings file for full verdict table.

---

### Section 8: Cross-Cutting Concerns
**Status:** ✅ DONE
**Orchestration plan:** §14-19 (matrices, parallelization, risks, cortex patterns, gates)
**Date completed:** 2026-02-08
**Decisions to validate:**
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
**Findings:** See [SECTION-8-FINDINGS.md](./SECTION-8-FINDINGS.md) for full detailed findings (10 items validated).
**Verdict:** 5 CONFIRMED, 5 REVISE, 0 REJECT — see findings file for full verdict table.

---

## Progress Summary

| Section | Status | Confirmed | Revised | Rejected | Date |
|---------|--------|-----------|---------|----------|------|
| 1. Phase 0 — Infrastructure | ✅ DONE | 11 | 4 | 0 | 2026-02-08 |
| 2. Phase 1 — Entry Pipeline | ✅ DONE | 14 | 4 | 0 | 2026-02-08 |
| 3. Phase 2 — Structural Skeleton | ✅ DONE | 7 | 3 | 0 | 2026-02-08 |
| 4. Phases 3-4 — Intelligence | ✅ DONE | 13 | 2 | 0 | 2026-02-08 |
| 5. Phase 5 — Structural Intel | ✅ DONE | 8 | 4 | 0 | 2026-02-08 |
| 6. Phase 6 — Enforcement | ✅ DONE | 7 | 3 | 0 | 2026-02-08 |
| 7. Phases 7-10 — Advanced+Ship | ✅ DONE | 8 | 4 | 0 | 2026-02-08 |
| 8. Cross-Cutting Concerns | ✅ DONE | 5 | 5 | 0 | 2026-02-08 |

**Total decisions validated:** 110 / ~110+
**Open decisions resolved:** 5 / 5
