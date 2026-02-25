# 01 Rust Core — External Research

> Phase 3: Verifiable best practices from trusted sources, applied to Drift's Rust core.

---

## R1: Incremental Computation Architecture (Salsa / Map-Reduce Indexing)

**Source**: https://rust-analyzer.github.io/blog/2020/07/20/three-architectures-for-responsive-ide.html
**Type**: Tier 2 (Industry Expert — rust-analyzer core team)
**Accessed**: 2026-02-06

**Key Findings**:
- rust-analyzer describes three architectures for responsive IDE tooling. The first (and most performant) splits analysis into an embarrassingly parallel indexing phase (per-file, no cross-file dependencies) and a separate full analysis phase that leverages the index.
- The indexing phase produces "stubs" — top-level declarations with unresolved types. These stubs are merged into a single index. Index updates are incremental: when a file changes, only that file's contribution is removed and re-added.
- "Smart" caches built on top of "dumb" indexes are invalidated completely on change, but reconstruction from the index is cheap.
- This approach combines simplicity with stellar performance and is used by IntelliJ and Sorbet.

**Source**: https://salsa-rs.github.io/salsa/overview.html
**Type**: Tier 1 (Official documentation — Salsa framework)
**Accessed**: 2026-02-06

**Key Findings**:
- Salsa is a Rust framework for incremental recomputation used by rust-analyzer and the Rust compiler. It models programs as sets of queries (K -> V functions) and automatically tracks dependencies to recompute only what changed.
- The key insight: separate "inputs" (things that change externally) from "derived queries" (computed from inputs). When an input changes, only dependent derived queries are re-executed.

**Applicability to Drift**:
Drift currently does full re-analysis on every scan. The rust-analyzer architecture directly maps to Drift's needs: per-file indexing (parsing + pattern extraction) is embarrassingly parallel, and cross-file analysis (call graph resolution, coupling) can leverage the index. Adopting an incremental model would dramatically improve performance for large codebases where only a few files change between scans.

**Confidence**: High — rust-analyzer is the gold standard for Rust-based incremental analysis tooling.

---

## R2: Cycle Detection — Tarjan's SCC vs DFS

**Source**: https://www.wikiwand.com/en/Tarjan's_strongly_connected_components_algorithm
**Type**: Tier 1 (Academic reference — based on Tarjan's 1972 paper)
**Accessed**: 2026-02-06

**Source**: https://www.geeksforgeeks.org/dsa/comparision-between-tarjans-and-kosarajus-algorithm/
**Type**: Tier 3 (Community validated — well-known CS reference)
**Accessed**: 2026-02-06

**Source**: https://www.baeldung.com/cs/scc-tarjans-algorithm
**Type**: Tier 3 (Community validated — established CS education site)
**Accessed**: 2026-02-06

**Key Findings**:
- Tarjan's algorithm finds all strongly connected components in O(V + E) time using a single DFS traversal. It is optimal for this problem class.
- Kosaraju's algorithm also achieves O(V + E) but requires two DFS passes, roughly doubling overhead.
- Plain DFS cycle detection (what Drift's Rust coupling analyzer uses) can find cycles but does not find ALL strongly connected components. It may miss cycles or report incomplete cycle membership.
- Tarjan's produces a complete partition of the graph into SCCs, which enables downstream analysis like condensation graphs (DAG of SCCs) for architectural visualization.

**Applicability to Drift**:
Drift's Rust coupling analyzer uses DFS with recursion stack for cycle detection. The TS implementation already uses Tarjan's SCC. Switching the Rust implementation to Tarjan's would: (1) guarantee finding all cycles, (2) enable condensation graph generation for architecture visualization, (3) align Rust and TS implementations. The performance difference is negligible for typical module graphs, but correctness and completeness improve.

**Confidence**: High — this is established computer science with decades of validation.

---

## R3: Secret Detection Best Practices

**Source**: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
**Type**: Tier 1 (OWASP — authoritative security standard)
**Accessed**: 2026-02-06

**Key Findings**:
- OWASP classifies hardcoded secrets as a critical vulnerability (A07:2025 Authentication Failures).
- Secrets should never be hardcoded, stored unencrypted, or committed to source code.
- Detection should cover: API keys, database credentials, IAM permissions, SSH keys, certificates, and tokens.
- Organizations need centralized secrets management with rotation, auditing, and access control.

**Source**: https://blog.gitguardian.com/secrets-in-source-code-episode-3-3-building-reliable-secrets-detection/
**Type**: Tier 2 (Industry Expert — GitGuardian engineering blog, based on scanning billions of commits)
**Accessed**: 2026-02-06

**Key Findings**:
- Secret detection is probabilistic — not always possible to determine true positives with certainty.
- Effective detection requires combining: (1) pattern recognition for known formats, (2) entropy analysis for unknown formats, (3) context analysis (variable names, file paths, surrounding code), and (4) API validation where possible.
- GitGuardian detects 500+ secret types using specialized detectors per provider.
- Generic high-entropy detection catches secrets that don't match known patterns by looking for high-randomness strings assigned to sensitive variables.
- False positive reduction requires contextual analysis: checking what surrounds a potential secret (variable name, file type, comment vs code).

**Source**: https://github.com/GitGuardian/ggshield
**Type**: Tier 2 (Industry Expert — 500+ secret types, production-proven)
**Accessed**: 2026-02-06

**Applicability to Drift**:
Drift currently has 21 secret detection patterns. Industry leaders like GitGuardian support 500+. Key gaps: (1) no entropy-based generic detection, (2) no contextual analysis beyond placeholder filtering, (3) missing cloud provider patterns (Azure, GCP, DigitalOcean), (4) no API validation for confirming live secrets. Adding Shannon entropy calculation and contextual scoring would significantly reduce false positives and increase detection coverage.

**Confidence**: High — OWASP is the definitive security authority; GitGuardian's approach is validated against billions of real commits.

---

## R4: Static Analysis Architecture — Semgrep's Approach

**Source**: https://semgrep.dev/docs/writing-rules/data-flow/data-flow-overview/
**Type**: Tier 1 (Official documentation — Semgrep)
**Accessed**: 2026-02-06

**Source**: https://semgrep.dev/blog/2022/static-analysis-speed/
**Type**: Tier 2 (Industry Expert — Semgrep engineering blog)
**Accessed**: 2026-02-06

**Source**: https://semgrep.dev/docs/contributing/contributing-code/
**Type**: Tier 1 (Official documentation — Semgrep architecture)
**Accessed**: 2026-02-06

**Key Findings**:
- Semgrep uses an OCaml core engine with tree-sitter for parsing, supporting 30+ languages.
- Architecture: source code → tree-sitter AST → intermediate language (IL) → language-agnostic analysis on IL.
- Data flow analysis capabilities: constant propagation, taint tracking (taint analysis), symbolic propagation.
- Taint tracking enables catching complex injection bugs (XSS, SQLi) by tracking data flow from sources to sinks.
- Design trade-offs: intraprocedural (within single function), no path sensitivity, no pointer/shape analysis, no soundness guarantees. This keeps analysis fast and practical.
- Cross-file (interfile) analysis is supported for taint tracking.
- Semgrep achieved fast scan times through taint summaries and tree matching optimizations.

**Applicability to Drift**:
Drift's unified analyzer currently does pattern matching (AST queries + regex on strings) but lacks data flow analysis entirely. Adding even basic intraprocedural taint tracking would enable: (1) detecting SQL injection patterns where user input flows to query construction, (2) tracking sensitive data flow from input to logging/output, (3) identifying unvalidated data reaching security-critical functions. The Semgrep approach of translating to an intermediate language before analysis is worth considering for Drift's multi-language support.

**Confidence**: High — Semgrep is a widely-adopted, production-proven static analysis tool.

---

## R5: String Interning — Production Crates

**Source**: https://docs.rs/lasso/latest/lasso/
**Type**: Tier 1 (Official crate documentation)
**Accessed**: 2026-02-06

**Source**: https://dev.to/cad97/string-interners-in-rust-797
**Type**: Tier 3 (Community validated — author of the `lasso` crate)
**Accessed**: 2026-02-06

**Source**: https://users.rust-lang.org/t/new-string-interning-crate-symbol-table/75300
**Type**: Tier 2 (Rust community forum — crate author announcement with benchmarks)
**Accessed**: 2026-02-06

**Key Findings**:
- `lasso` provides both single-threaded (`Rodeo`) and multi-threaded (`ThreadedRodeo`) interners with O(1) internment and resolution. It can be converted to `RodeoReader` for contention-free reads or `RodeoResolver` for minimum memory usage.
- `symbol_table` crate uses sharding to reduce lock contention and is fastest under medium/high contention scenarios. It provides stable `&'a str` references.
- Production interners typically provide: thread-safe variants, read-only modes for post-build phase, memory statistics, and configurable backends.
- Key design consideration: separate the "build" phase (mutable, intern new strings) from the "read" phase (immutable, resolve symbols) for maximum performance.

**Applicability to Drift**:
Drift uses a custom `StringInterner` with `HashMap<String, Symbol>` + `Vec<String>`. This works but lacks: (1) thread-safe variant for rayon parallelism (currently using `thread_local!` workaround), (2) read-only mode for post-analysis queries, (3) sharding for reduced contention. Evaluating `lasso` or `symbol_table` could provide better concurrent performance and reduce maintenance burden of custom code.

**Confidence**: Medium-High — these are well-maintained crates with benchmarks, but Drift's custom interner may have domain-specific optimizations worth keeping.

---

## R6: Rayon Parallelism Best Practices

**Source**: https://www.shuttle.rs/blog/2024/04/11/using-rayon-rust
**Type**: Tier 3 (Community validated — Shuttle engineering blog)
**Accessed**: 2026-02-06

**Source**: https://github.com/rayon-rs/rayon/issues/941
**Type**: Tier 2 (Official rayon repository — core maintainer discussion)
**Accessed**: 2026-02-06

**Source**: https://users.rust-lang.org/t/rayon-and-work-locality-over-large-buffers-with-large-thread-pools/114770
**Type**: Tier 2 (Rust community forum — performance discussion)
**Accessed**: 2026-02-06

**Key Findings**:
- Rayon uses work-stealing: idle threads steal tasks from busy threads' local queues. This provides automatic load balancing.
- `thread_local!` storage with rayon is a common pattern but has caveats: thread-local values persist for the lifetime of the thread pool, not the lifetime of the task. This can cause memory accumulation.
- For CPU-bound work (like parsing), rayon's `par_iter()` is ideal. For mixed I/O + CPU, consider separating concerns.
- Data locality matters for large datasets: keeping related data together reduces cache misses. Rayon's work-stealing can hurt locality.
- Custom thread pool configuration (`ThreadPoolBuilder`) allows controlling thread count, stack size, and panic handling.

**Applicability to Drift**:
Drift uses `thread_local!` for `ParserManager` instances in the unified analyzer and constants analyzer. This is noted as a TODO for optimization. The concern is valid: each rayon thread creates its own parser, and these persist for the pool's lifetime. A better approach would be a parser pool with bounded size, or using rayon's `ThreadPoolBuilder` with explicit initialization hooks.

**Confidence**: Medium-High — rayon is well-documented, but optimal patterns depend on workload characteristics.

---

## R7: N-API Bridge Architecture

**Source**: https://napi.rs/
**Type**: Tier 1 (Official napi-rs documentation)
**Accessed**: 2026-02-06

**Source**: https://blog.logrocket.com/building-nodejs-modules-rust-napi-rs/
**Type**: Tier 3 (Community validated — LogRocket engineering blog)
**Accessed**: 2026-02-06

**Source**: https://blog.jetbrains.com/rust/2026/01/27/rust-vs-javascript-typescript/
**Type**: Tier 2 (Industry Expert — JetBrains engineering blog)
**Accessed**: 2026-02-06

**Key Findings**:
- napi-rs v3 introduces WebAssembly integration, safer API designs with lifetime management, and simplified cross-compilation.
- The Rust + TypeScript hybrid pattern is an established industry trend: Rust handles performance-critical logic, TypeScript manages orchestration and presentation.
- Key performance consideration: minimize data serialization across the N-API boundary. Large result sets should be streamed or paginated rather than serialized all at once.
- For async operations, napi-rs supports `AsyncTask` trait for offloading work to libuv's thread pool, keeping the Node.js event loop responsive.

**Applicability to Drift**:
Drift's N-API bridge is described as "functional but thin" with ~25 functions. For v2, the bridge needs to grow significantly to expose pattern detection, storage operations, and richer queries. Key considerations: (1) batch APIs to reduce N-API call overhead, (2) streaming results for large analyses, (3) async variants for long-running operations, (4) consider whether some operations should use JSON IPC instead of N-API for flexibility.

**Confidence**: Medium — the hybrid Rust/TS pattern is well-established, but the specific FFI approach depends on Drift's performance requirements.

---

## R8: Tree-sitter Incremental Parsing

**Source**: https://tomassetti.me/incremental-parsing-using-tree-sitter/
**Type**: Tier 3 (Community validated — established parsing/language engineering blog)
**Accessed**: 2026-02-06

**Source**: https://zed.dev/blog/syntax-aware-editing
**Type**: Tier 2 (Industry Expert — Zed editor engineering blog)
**Accessed**: 2026-02-06

**Key Findings**:
- Tree-sitter's incremental parsing allows efficient re-parsing after edits by reusing unchanged portions of the syntax tree. The `edit()` API informs the parser about what changed, and subsequent `parse()` calls reuse the old tree.
- Zed editor leverages this for low-latency syntax-aware editing, achieving sub-millisecond re-parse times for typical edits.
- Tree-sitter's error recovery produces useful partial results even for syntactically invalid code, which is critical for IDE-like tooling.
- Query cursors (`QueryCursor`) do not cache state between runs — they always traverse the full tree. For incremental query results, the application must implement its own caching layer.

**Applicability to Drift**:
Drift currently parses files from scratch on every scan. For IDE integration and incremental scanning, tree-sitter's `edit()` + incremental `parse()` API should be leveraged. This requires: (1) caching parsed trees between scans, (2) tracking file edits to apply `tree.edit()`, (3) implementing a query result cache since `QueryCursor` doesn't cache. The Zed approach of maintaining a tree cache per open file is directly applicable.

**Confidence**: High — tree-sitter's incremental parsing is its core design feature, well-documented and battle-tested.

---

## R9: Enterprise Static Analysis Best Practices

**Source**: https://www.augmentcode.com/guides/static-code-analysis-best-practices
**Type**: Tier 3 (Community validated — enterprise-focused guide)
**Accessed**: 2026-02-06

**Key Findings**:
- Enterprise static analysis should support codebase indexing for up to 500,000+ files.
- Semantic analysis rules should align with architecture patterns and organizational coding standards.
- Integration into IDE workflows and CI/CD pipelines is essential for adoption.
- Quality gates using contextual risk scoring with automated PR analysis drive enforcement.
- Context-aware feedback (understanding the codebase's conventions) produces more relevant results than generic rules.

**Applicability to Drift**:
This directly validates Drift's core thesis: discovering conventions offline and exposing them to AI at query time. The emphasis on contextual risk scoring aligns with Drift's confidence scoring system. The scale requirement (500K+ files) validates the need for Rust-level performance and incremental analysis.

**Confidence**: Medium — general best practices, but validates Drift's architectural direction.

---

## R10: Module Coupling Metrics — Robert C. Martin

**Source**: Robert C. Martin, "Design Principles and Design Patterns" (2000) — referenced via https://en.wikipedia.org/wiki/Robert_C._Martin
**Type**: Tier 1 (Academic — foundational paper by the originator of the metrics)
**Accessed**: 2026-02-06

**Key Findings**:
- The Stable Dependencies Principle (SDP): depend in the direction of stability. Packages that are hard to change should not depend on packages that are easy to change.
- The Stable Abstractions Principle (SAP): stable packages should be abstract. Abstractness increases with stability.
- The Main Sequence: the ideal relationship between abstractness and instability is A + I = 1. Distance from this line indicates architectural problems.
- Zone of Pain: stable + concrete (low I, low A). Hard to change because many things depend on it, but not abstract enough to extend.
- Zone of Uselessness: unstable + abstract (high I, high A). Too abstract for something nothing depends on.

**Applicability to Drift**:
Drift's Rust coupling analyzer implements Ca, Ce, I, A, D correctly but lacks Zone of Pain/Uselessness detection (only in TS). These zones are critical for actionable architectural feedback. The Rust implementation should add zone classification and module role detection (hub/authority/balanced/isolated) to match the TS feature set.

**Confidence**: High — these are the foundational metrics by their creator, universally accepted in software architecture.
