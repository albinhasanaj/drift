# Section 1 Findings: Phase 0 — Infrastructure & Crate Scaffold

> **Status:** ✅ DONE
> **Date completed:** 2026-02-08
> **Orchestration plan:** §3 (Phase 0)
> **V2-PREP docs:** 04-INFRASTRUCTURE-V2-PREP.md
>
> **Summary: 11 CONFIRMED, 4 REVISE, 0 REJECT**
>
> This document contains the full research findings for Section 1 of DRIFT-V2-FINAL-RESEARCH-TRACKER.md.
> The tracker file itself should be updated to mark Section 1 as ✅ DONE and reference this file.

---

## Checklist (all validated)

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

---

## Findings

### OD-1: 5-crate vs 6-crate workspace — ✅ CONFIRMED: 6 crates

**Verdict: Add `drift-context` as a 6th crate.** The 30-CONTEXT-GENERATION-V2-PREP doc specifies unique dependencies (`tiktoken-rs`, `quick-xml`, `serde_yaml`, `glob`, `base64`) that have no business in `drift-analysis`. The Cortex workspace already demonstrates this pattern successfully with 21 crates — granular separation is proven at this scale. `tiktoken-rs` alone pulls in significant transitive deps (BPE tokenizer data, regex). Keeping it isolated means `drift-analysis` stays lean for users who don't need context generation. The 6-crate layout:
- `drift-core` — types, traits, errors, config, events, data structures
- `drift-analysis` — parsers, detectors, call graph, all analysis
- `drift-storage` — SQLite persistence, migrations, batch writer
- `drift-context` — context generation, token counting, package detection
- `drift-napi` — NAPI-RS v3 bindings
- `drift-bench` — benchmarks (isolated)

Update §3.1 of the orchestration plan to reflect 6 crates. Add `tiktoken-rs`, `quick-xml`, `serde_yaml`, `glob`, `base64` to workspace dependency pins.

---

### Cargo Workspace Dependency Versions — Version-by-Version Audit

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

### Feature Flag Strategy (default = "full", per-language flags) — ✅ CONFIRMED

The `default = ["full"]` with per-language flags (`lang-python`, `lang-java`, etc.) and feature flags for optional subsystems (`cortex`, `mcp`, `wasm`, `otel`, `benchmark`) is standard Cargo practice. This matches how tree-sitter grammars are typically gated. The Cortex workspace uses a similar pattern. One note: the orchestration plan says `default = ["full"]` but the stack hierarchy says `default = ["cortex", "mcp"]` — these are inconsistent. **Recommendation: `default = ["full"]` is correct for the analysis crate (users want all languages by default). The `cortex` and `mcp` flags should NOT be default — they pull in optional dependencies.** Resolve this inconsistency.

---

### Release Profile Settings (lto = true, codegen-units = 1) — ✅ CONFIRMED

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

### DriftConfig 4-Layer Resolution Pattern — ✅ CONFIRMED

CLI flags > env vars > project config > user config > defaults is the standard hierarchical config pattern used by:
- Cargo itself (`.cargo/config.toml` with hierarchical merging)
- ESLint, Prettier, and most JS tooling
- Git (system > global > local > worktree)
- The `config` crate for Rust (layered configuration)

TOML is the right format for the Rust ecosystem (Cargo.toml precedent). The `settings_loader` crate on lib.rs implements exactly this pattern. The plan's approach of manual TOML merging via `serde` + `toml` crate is simpler and avoids an extra dependency vs using the `config` crate. **Sound decision.**

---

### thiserror 2 Ecosystem Compatibility — ✅ CONFIRMED

See finding #4 above. No concerns for a greenfield project. thiserror is a proc-macro that generates standard library trait impls — it doesn't appear in your public API. Two versions in the lockfile (from transitive deps) is harmless.

---

### tracing + EnvFilter — ✅ CONFIRMED

`tracing` remains the de facto standard for Rust observability. Used by tokio, hyper, axum, tower, tonic, and virtually every production Rust service. `tracing-subscriber` with `env-filter` feature for `EnvFilter` is the standard subscriber setup. The `DRIFT_LOG=scanner=debug,parser=info` pattern maps directly to `EnvFilter::try_from_env("DRIFT_LOG")`. Optional `tracing-opentelemetry` behind an `otel` feature flag is the standard approach for enterprise observability. **No changes needed.**

---

### lasso 0.7 ThreadedRodeo — ✅ CONFIRMED (with note)

See finding #5 above. lasso 0.7 is stable and functional. The `ThreadedRodeo` → `RodeoReader` pattern (mutable during build, immutable during query) is well-designed for Drift's two-phase architecture. The 60-80% memory reduction claim for file paths and function names is realistic — string interning is a well-understood optimization. **Confirmed with the note that `lasso2` 0.8 exists as a fallback if maintenance becomes a concern.**

---

### FxHashMap vs ahash — ✅ CONFIRMED: FxHashMap

See finding #7 above. FxHashMap for internal maps, standard HashMap only if DoS resistance is ever needed (it isn't for Drift). **Confirmed.**

---

### SmallVec 1.13 — ⚠️ REVISE: pin "1" not "1.13"

See finding #8 above. Use `smallvec = "1"` in workspace deps. Cargo resolves to 1.15.x. Don't adopt 2.0 alpha.

---

### xxhash-rust 0.8 xxh3 — ✅ CONFIRMED

See finding #9 above. Still the fastest non-crypto hash for content hashing. **Confirmed.**

---

### moka 0.12 vs quick_cache — ✅ CONFIRMED: moka

See finding #6 above. moka 0.12.13 is actively maintained, #1 caching crate, proven in the Cortex workspace. **Confirmed.**

---

### crossbeam-channel 0.5 — ✅ CONFIRMED

See finding #12 above. Still needed for bounded channels with `recv_timeout` in the batch writer. Ensure latest 0.5.x patch for RUSTSEC-2025-0024 fix.

---

### petgraph 0.6 — ⚠️ REVISE → 0.8

See finding #11 above. petgraph 0.8.3 is current. Start greenfield at 0.8.

---

### Event System Design (Vec<Arc<dyn Handler>> + sync dispatch) — ✅ CONFIRMED (with note)

The `Vec<Arc<dyn DriftEventHandler>>` with synchronous `emit()` dispatch is a well-established pattern. Key properties:
- **Zero overhead when empty**: iterating an empty Vec is effectively free (the compiler can optimize this away).
- **Dynamic dispatch cost**: one vtable lookup per handler per event. With typically 0-2 handlers registered (standalone = 0, bridge = 1, NAPI progress = 1), this is negligible.
- **Synchronous dispatch**: correct for Drift's use case. Events are emitted during analysis (hot path). Async dispatch would require an async runtime (tokio) which Drift deliberately avoids (it uses rayon for parallelism, not async). Synchronous dispatch means the handler runs inline — if the handler is slow, it blocks analysis. This is fine because: (a) standalone handlers are no-ops, (b) the bridge handler just writes to a channel/queue, (c) the NAPI progress handler calls ThreadsafeFunction which is non-blocking.
- **Scale concern**: if someone registers a slow handler, it blocks the analysis pipeline. Mitigation: document that handlers must be non-blocking. The Cortex workspace uses a similar pattern successfully.
- **Alternative considered**: `tokio::sync::broadcast` for async fan-out. Rejected because Drift doesn't use tokio, and adding an async runtime for event dispatch alone is overkill.

**One improvement to consider**: make the handler Vec immutable after initialization (freeze it like lasso's `ThreadedRodeo` → `RodeoReader`). This avoids any need for synchronization on the handler list during analysis. Register all handlers during `drift_initialize()`, then freeze. This is already implied by the design but worth making explicit.

**Confirmed — sound design for the expected scale.**

---

## Verdict Table

| # | Item | Verdict | Action Required |
|---|------|---------|-----------------|
| 1 | OD-1: 6th crate (drift-context) | ✅ CONFIRMED | Add to §3.1, add deps to workspace pins |
| 2 | tree-sitter version | ⚠️ REVISE | 0.24 → **0.25** (verify grammar compat) |
| 3 | rusqlite version | ⚠️ REVISE | 0.32 → **0.38** (greenfield, no migration cost) |
| 4 | napi version | ✅ CONFIRMED | v3 released Jul 2025, stable at 3.8.x+ |
| 5 | thiserror version | ✅ CONFIRMED | v2, no ecosystem concerns |
| 6 | lasso version | ✅ CONFIRMED | 0.7 stable, lasso2 0.8 as fallback |
| 7 | moka version | ✅ CONFIRMED | 0.12.13, actively maintained |
| 8 | rustc-hash (FxHashMap) | ✅ CONFIRMED | v2, correct choice over ahash |
| 9 | smallvec version | ⚠️ REVISE | Pin "1" not "1.13" (resolves to 1.15.x) |
| 10 | xxhash-rust version | ✅ CONFIRMED | 0.8 xxh3, still fastest |
| 11 | rayon version | ✅ CONFIRMED | 1.10 floor, resolves to 1.11 |
| 12 | petgraph version | ⚠️ REVISE | 0.6 → **0.8** (greenfield, latest features) |
| 13 | crossbeam-channel | ✅ CONFIRMED | 0.5.x, ensure latest patch (security fix) |
| 14 | ignore crate | ✅ CONFIRMED | 0.4.x, standard ripgrep walker |
| 15 | Feature flag strategy | ✅ CONFIRMED | Fix inconsistency: default=["full"], not ["cortex","mcp"] |
| 16 | Release profile | ✅ CONFIRMED | Add `panic = "abort"` (matches Cortex) |
| 17 | DriftConfig 4-layer | ✅ CONFIRMED | Standard hierarchical config pattern |
| 18 | thiserror 2 compat | ✅ CONFIRMED | No ecosystem issues |
| 19 | tracing + EnvFilter | ✅ CONFIRMED | De facto Rust observability standard |
| 20 | Event system design | ✅ CONFIRMED | Sound for expected scale, freeze handler list after init |

**Summary: 11 CONFIRMED, 4 REVISE, 0 REJECT.**

The infrastructure decisions are overwhelmingly sound. The 4 revisions are all version bumps for a greenfield project — tree-sitter 0.24→0.25, rusqlite 0.32→0.38, petgraph 0.6→0.8, smallvec pin "1" not "1.13". No architectural decisions need to change. The OD-1 decision (drift-context as 6th crate) is confirmed with clear rationale.
