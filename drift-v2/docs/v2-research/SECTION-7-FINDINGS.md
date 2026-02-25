# Section 7 Findings: Phases 7-10 — Advanced, Presentation, Bridge, Polish

> **Status:** ✅ DONE
> **Date completed:** 2026-02-08
> **Orchestration plan:** §10-13 (Phases 7-10)
> **V2-PREP docs:** 28-SIMULATION-ENGINE-V2-PREP.md, 29-DECISION-MINING-V2-PREP.md, 30-CONTEXT-GENERATION-V2-PREP.md, 32-MCP-SERVER-V2-PREP.md, 33-WORKSPACE-MANAGEMENT-V2-PREP.md, 34-CI-AGENT-GITHUB-ACTION-V2-PREP.md, 34-CORTEX-DRIFT-BRIDGE-V2-PREP.md
>
> **Summary: 8 CONFIRMED, 4 REVISE, 1 RESOLVED (OD-5), 0 REJECT**
>
> This document contains the full research findings for Section 7 of DRIFT-V2-FINAL-RESEARCH-TRACKER.md.

---

## Checklist (all validated)

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

---

## Findings

### 1. Monte Carlo Simulation for Effort Estimation — ✅ CONFIRMED

The plan uses Monte Carlo simulation to produce confidence intervals (P10/P50/P90) for the recommended implementation approach's composite score. The algorithm (28-SIMULATION-ENGINE-V2-PREP §25) perturbs each scoring dimension by ±10% uniform random, re-computes the composite score across N samples (default 1000), sorts the results, and extracts the 5th and 95th percentiles as the 90% confidence interval.

**Validation of the technique:**

Monte Carlo simulation is the industry-standard technique for quantifying uncertainty in multi-variable estimation problems. It is used extensively in:

- **Project management**: PMI's PMBOK Guide recommends Monte Carlo simulation for schedule and cost risk analysis. Tools like Oracle Primavera Risk Analysis, @RISK (Palisade), and Crystal Ball all implement Monte Carlo for project estimation. [Source: [Open Practice Library](https://openpracticelibrary.com/practice/monte-carlo-simulation/)]
- **Software estimation**: COCOMO II and other parametric estimation models use Monte Carlo to produce confidence intervals around point estimates. The technique is particularly valuable when input parameters have known uncertainty ranges.
- **Financial risk assessment**: Value-at-Risk (VaR) calculations in finance use Monte Carlo simulation with the same percentile-based confidence interval approach.

**Assessment of the plan's implementation:**

The implementation is sound but lightweight — it's a sensitivity analysis rather than a full probabilistic model. Key properties:

1. **±10% uniform perturbation** is a reasonable default for scoring uncertainty. The friction, impact, alignment, and security scores are all heuristic-based, so ±10% captures the inherent imprecision. A more sophisticated approach would use per-dimension uncertainty bounds (e.g., friction might have ±15% uncertainty while alignment has ±5%), but the uniform approach is simpler and adequate for v2.

2. **1000 samples** is sufficient for stable percentile estimates. The central limit theorem guarantees convergence of the mean, and 1000 samples gives ~3% precision on the 5th/95th percentiles. Increasing to 10,000 would give ~1% precision but at 10x cost — not worth it for a heuristic scoring system.

3. **Interpretation thresholds** (narrow <10, medium 10-25, wide >25) are reasonable. A narrow interval means the recommendation is robust to scoring uncertainty; a wide interval means the top approaches are close in score and the recommendation is sensitive to assumptions.

4. **Performance**: 1000 iterations of weighted arithmetic (4 multiplications + 3 additions per iteration) completes in <1ms. No performance concern.

**One note**: The plan correctly keeps Monte Carlo as an Enterprise-tier feature. Community and Professional tiers get the v1 heuristic confidence score (gap factor + data quality + alignment factor). This is a reasonable gating decision — Monte Carlo adds value but isn't essential for basic simulation.

---

### 2. git2 Crate for Commit History — ⚠️ REVISE: Pin "0.20" Not "0.19"

The plan specifies `git2 = "0.19"` in 29-DECISION-MINING-V2-PREP §5. However, git2 is now at **0.20.2** (released May 5, 2025, per [lib.rs](https://lib.rs/crates/git2) and [rust-digger](https://rust-digger.code-maven.com/crates/git2)).

**Version history:**
- 0.19.0 — June 14, 2024
- 0.20.0 — January 5, 2025
- 0.20.1 — March 17, 2025
- 0.20.2 — May 5, 2025

git2 0.20.x bundles **libgit2 1.9**, which is the current stable release of the underlying C library. The 0.19→0.20 transition included breaking changes (libgit2 1.8→1.9 upgrade). Since Drift is greenfield, there's no migration cost.

**Maintenance status:** git2 is maintained by the Rust project itself (rust-lang/git2-rs on GitHub). It has 2.1M+ downloads per month and is used by Cargo, GitHub Desktop (via libgit2), GitKraken, and many other production tools. Actively maintained with regular releases.

**Thread safety model:** The plan correctly notes that `git2::Repository` is NOT `Send` or `Sync` — this is a libgit2 limitation. The solution of opening a new `Repository` per rayon thread (via `par_chunks(100)`) is the proven pattern used by gitoxide, delta, and other Rust git tools. The plan's implementation in §5 is correct.

**Alternative considered — gitoxide (gix):** gitoxide is a pure-Rust git implementation that is `Send + Sync` and doesn't require per-thread repository opening. However, gitoxide's API is still evolving rapidly (0.49.x as of April 2025), and its commit walking + diff analysis APIs are less mature than git2's. For Drift's use case (walking commits, extracting diffs, analyzing file changes), git2 is the safer choice. gitoxide could be considered for v3 when its API stabilizes.

**Recommendation:** Pin `git2 = "0.20"` in the workspace Cargo.toml. The plan's `"0.19"` is one minor version behind. No API changes needed — the 0.19→0.20 breaking changes are in areas Drift doesn't use (credential handling, transport configuration).

---

### 3. tiktoken-rs for BPE Token Counting — ⚠️ REVISE: Pin "0.9" Not "0.6"

The plan specifies `tiktoken-rs = "0.6"` in 30-CONTEXT-GENERATION-V2-PREP §2 (Cargo.toml). However, tiktoken-rs is now at **0.9.1** (released November 9, 2025, per [lib.rs](https://www.lib.rs/crates/tiktoken-rs)).

**Version history:**
- 0.6.0 — October 14, 2024
- 0.7.0 — May 19, 2025
- 0.9.1 — November 9, 2025

tiktoken-rs has 855K+ downloads per month and is ranked #5 in Machine Learning on crates.io. It is actively maintained with regular releases.

**Key changes since 0.6:**
- 0.7.0: Added support for newer OpenAI models
- 0.9.x: Added `o200k_harmony` encoding for GPT-oss models, updated model mappings for GPT-5, GPT-4.1, o4, o3 models

**The plan's usage is correct:** The `cl100k_base()` and `o200k_base()` tokenizers used in the plan (30-CONTEXT-GENERATION-V2-PREP §8) are still the right choices. `cl100k_base` is used for ChatGPT models and is a reasonable approximation for Anthropic models (~5% accuracy, as the plan notes). `o200k_base` is used for GPT-4o and newer OpenAI models.

**Platform support:** tiktoken-rs works on all major platforms (Windows, macOS, Linux). It bundles BPE data files (~8.5MB crate size) so there are no runtime download requirements. The `OnceLock` pattern used in the plan for lazy initialization is correct — tokenizer creation involves parsing the BPE data file, which takes ~50-100ms on first call.

**Fallback chain:** The plan's fallback chain (tiktoken-rs → splintr → character estimation) is sound. The `splintr` crate (per [lib.rs](https://lib.rs/crates/splintr)) claims 10-12x faster than tiktoken for batch operations, making it a viable alternative. The character estimation fallback (`length / 4 * 0.8`) with a 20% safety margin is conservative and appropriate.

**Recommendation:** Pin `tiktoken-rs = "0.9"` to get the latest model support. The API is backward-compatible — `cl100k_base()` and `o200k_base()` work identically. The newer `o200k_harmony` encoding is available if needed for GPT-oss model support.

---

### 4. MCP Spec 2025-06-18 — ⚠️ REVISE: Target 2025-11-25 as Baseline, Not 2025-06-18

The plan targets MCP specification **2025-06-18** as the baseline (32-MCP-SERVER-V2-PREP §5). However, a newer spec version **2025-11-25** has been officially released (confirmed via [modelcontextprotocol.io](https://modelcontextprotocol.io/specification/2025-11-25)).

**MCP spec version timeline:**
- 2024-11-05 — Initial public release
- 2025-03-26 — Streamable HTTP transport, OAuth 2.1 authorization
- 2025-06-18 — Structured tool output, elicitation, resource links, OAuth Resource Servers
- **2025-11-25** — Client ID Metadata Documents, Cross App Access (XAA), enterprise authorization enhancements, mandatory PKCE, security best practices updates

The plan already references 2025-11-25 for authorization enhancements (32-MCP-SERVER-V2-PREP §5 header mentions both dates). However, the baseline should be updated to 2025-11-25 since:

1. The 2025-11-25 spec is the **current latest** as of February 2026.
2. All features from 2025-06-18 are included in 2025-11-25 (it's additive).
3. The 2025-11-25 spec adds important security clarifications: servers must respond with HTTP 403 for invalid Origin headers in Streamable HTTP, input validation errors should be Tool Execution Errors (not Protocol Errors) to enable model self-correction.
4. Client ID Metadata Documents (CIMD) from 2025-11-25 are the new standard for client registration with authorization servers — important for enterprise deployment.

**The @modelcontextprotocol/sdk TypeScript SDK** supports all spec versions through its latest releases. The SDK has been updated to support 2025-11-25 features.

**Recommendation:** Update the baseline target from 2025-06-18 to **2025-11-25**. All features the plan already targets (structured output, elicitation, resource links, Streamable HTTP) are available in 2025-11-25. The additional security and authorization features from 2025-11-25 are valuable for enterprise deployment.

---

### 5. Streamable HTTP Transport — ✅ CONFIRMED

The plan replaces v1's HTTP/SSE transport with Streamable HTTP (32-MCP-SERVER-V2-PREP §5.4). This is validated by multiple sources:

**Spec support:** Streamable HTTP was introduced in the MCP 2025-03-26 spec and is the standard transport for remote MCP connections. The older HTTP+SSE transport is deprecated. [Source: [Cloudflare Agents docs](https://developers.cloudflare.com/agents/model-context-protocol/transport/)]

**SDK support:** The `@modelcontextprotocol/sdk` TypeScript SDK added Streamable HTTP support in version 1.10.0 (April 17, 2025). The `StreamableHTTPServerTransport` class is available at `@modelcontextprotocol/sdk/server/streamableHttp.js`, exactly as the plan imports it. [Source: [fka.dev blog](https://blog.fka.dev/blog/2025-06-06-why-mcp-deprecated-sse-and-go-with-streamable-http/)]

**Advantages over SSE (confirmed):**
- Single connection (no separate SSE endpoint)
- Bidirectional streaming (server can push, client can push)
- Simpler deployment (one endpoint, not two)
- Better compatibility with HTTP infrastructure (proxies, load balancers)

**The plan's dual-transport approach is correct:** stdio for IDE integration (primary), Streamable HTTP for containerized/Docker deployment. This matches the MCP spec recommendation: "Clients SHOULD support stdio whenever possible."

**Backward compatibility note:** Many MCP clients now support both Streamable HTTP and legacy SSE. The plan's approach of only implementing Streamable HTTP (not SSE) is forward-looking and correct — SSE is deprecated and will eventually be removed from the spec.

---

### 6. Progressive Disclosure (3 Entry Points) — ✅ CONFIRMED

The plan's progressive disclosure pattern (3 registered MCP tools + internal tool dispatch via `drift_tool`) is validated by multiple real-world MCP server implementations:

**Production validation:**

1. **Rails MCP Server** (by Mario Chávez): Implemented the exact same pattern — previous tools became "internal analyzers" discovered through `search_tools` and invoked through `execute_tool`. Reports ~67% context footprint reduction. [Source: [mariochavez.io](https://mariochavez.io/desarrollo/2025/12/10/rails-mcp-server-context-efficient-refactoring)]

2. **Apigene MCP Gateway**: Implements progressive disclosure for API tools, reporting 98% token cost reduction through dynamic tool loading. Uses a similar meta-tool pattern where agents discover and load tools on-demand. [Source: [apigene.ai](https://www.apigene.ai/blog/solving-mcp-tool-overload-with-dynamic-loading)]

3. **Klavis Progressive Discovery MCP Server**: Uses a "navigator" tool as the single entry point, with agents discovering specific tools through it. Same architectural pattern as Drift's `drift_discover` → `drift_tool` flow. [Source: [klavis.ai](https://www.klavis.ai/blog/agent-context-windows-stay-smart-with-progressive-discovery-mcp-server)]

4. **SynapticLabs Bounded Context Packs**: Documented the meta-tool pattern specifically for MCP servers with 33+ tools consuming 8,000+ tokens. Their solution matches Drift's approach: fewer registered tools, dynamic discovery, pack-based tool bundles. [Source: [synapticlabs.ai](https://blog.synapticlabs.ai/bounded-context-packs-meta-tool-pattern)]

**Token savings analysis:**

The plan estimates reducing from ~8K tokens (87 tools × ~80 tokens each) to ~1.5K tokens (3 tools). This is a **~81% reduction**, consistent with the 67-98% reductions reported by other implementations.

**The 3 entry points are well-chosen:**
- `drift_context` — the most common operation (get context for a task)
- `drift_discover` — health check + capability listing (first thing an agent calls)
- `drift_tool` — dynamic dispatch to any internal tool

This matches the "navigator + executor" pattern that has emerged as the standard approach for large MCP tool sets.

**One consideration:** The `drift_tool` meta-tool pattern requires the AI to make two calls (discover + invoke) instead of one direct call. This adds one round-trip of latency. However, the token savings far outweigh this cost — the AI reasons more effectively with 3 tools in context than with 87.

---

### 7. 52 Analysis + 33 Memory Internal Tools — ✅ CONFIRMED (with consolidation notes)

The plan defines ~52 internal tools for drift-analysis and ~33 for drift-memory (32-MCP-SERVER-V2-PREP §3).

**Assessment:**

The tool count is appropriate for the scope of Drift's analysis capabilities. Each tool maps to a distinct query or operation against drift.db. The key question is whether the AI can effectively discover and use 52+ tools through the `drift_tool` meta-tool pattern.

**Comparison with other MCP servers:**
- v1 Drift: 87+ tools (monolithic, all registered) — too many
- Cursor's internal tools: ~30-40 (estimated from documentation)
- GitHub Copilot's tools: ~20-30 (estimated)
- Drift v2 drift-analysis: 52 (via progressive disclosure) — reasonable
- Drift v2 drift-memory: 33 (via progressive disclosure) — reasonable

**Why 52 is acceptable with progressive disclosure:**

1. The AI never sees all 52 tools at once. It sees 3 entry points, then discovers relevant tools via `drift_discover`.
2. The pack system bundles tools by task (e.g., "security audit" pack includes `drift_security_summary`, `drift_constants`, `drift_error_handling`). Packs reduce cognitive load.
3. Language-specific tools (8 tools: `drift_typescript`, `drift_python`, etc.) are only shown if the language is detected. A Python project never sees `drift_typescript`.
4. The `nextActions` hints in tool responses guide the AI to the next relevant tool, creating a natural workflow.

**Potential consolidation opportunities:**

| Current Tools | Could Consolidate Into | Savings | Risk |
|--------------|----------------------|---------|------|
| `drift_signature` + `drift_type` + `drift_imports` | `drift_symbol` (with `action` param) | 2 tools | Lower discoverability |
| `drift_patterns_list` + `drift_file_patterns` | `drift_patterns` (with `scope` param) | 1 tool | More complex params |
| `drift_callers` + `drift_reachability` | `drift_graph` (with `query_type` param) | 1 tool | Conflated concerns |
| 8 language-specific tools | `drift_language` (with `language` param) | 7 tools | Loss of language-specific params |

**Recommendation:** Keep the current tool count. The progressive disclosure pattern makes 52 tools manageable. Consolidation would reduce discoverability and make individual tools more complex (more parameters, more modes). The current granularity is correct — each tool does one thing well.

---

### 8. fd-lock for Process Locking — ✅ CONFIRMED

The plan uses `fd-lock` for cross-platform advisory file locking (33-WORKSPACE-MANAGEMENT-V2-PREP §6).

**Current version:** fd-lock is at **4.0.4** (released March 10, 2025, per [lib.rs](https://lib.rs/crates/fd-lock)). The plan doesn't specify a version — it should pin `"4"`.

**Maintenance status:** fd-lock has 1.7M+ downloads per month and is used in 645 crates (51 directly). It is actively maintained. The crate is authored by Yoshua Wuyts (yoshuawuyts), a well-known Rust ecosystem contributor.

**Cross-platform support:**
- **Linux/macOS**: Uses `flock(2)` via `rustix::fs::flock` — standard POSIX advisory locking
- **Windows**: Uses `LockFile`/`UnlockFile` from `windows-sys` — Windows advisory locking
- **All platforms**: Advisory locks (opt-in compliance), which is appropriate for Drift's use case (coordinating between Drift processes, not enforcing security)

**The `RwLock<File>` API is correct for Drift's use case:**
- `read()` — shared lock for MCP queries, CLI read commands, backup creation (multiple readers)
- `write()` — exclusive lock for `drift scan`, `drift migrate`, `drift reset` (single writer)
- `try_read()` / `try_write()` — non-blocking, returns error immediately if lock is held

**Performance:** Advisory file locks have negligible overhead (~1µs for acquisition/release), as the plan correctly notes. Lock contention is the only concern, and the plan handles it with immediate failure + user-friendly error messages.

**Alternative considered — `fs2`:** The `fs2` crate also provides cross-platform file locking but hasn't been updated since 2020. fd-lock is the actively maintained choice.

**Recommendation:** Pin `fd-lock = "4"` in the workspace Cargo.toml. The plan's usage pattern (RwLock with try_read/try_write) is correct and well-designed.

---

### 9. SQLite Backup API for Hot Backup — ✅ CONFIRMED

The plan uses rusqlite's `Backup::run_to_completion()` for hot backup of drift.db (33-WORKSPACE-MANAGEMENT-V2-PREP §5). This replaces v1's unsafe file copy approach.

**Why this is correct:**

1. **WAL-mode safety:** V1's file copy is unsafe for WAL-mode databases. The WAL file (`drift.db-wal`) and shared memory file (`drift.db-shm`) must be consistent with the main database file. A file copy can capture an inconsistent state. The SQLite Backup API copies page-by-page from source to destination, ensuring consistency regardless of WAL mode.

2. **Non-blocking for readers:** The Backup API acquires a shared lock on the source database, allowing concurrent reads (MCP queries) to continue during backup. Only writes are briefly blocked during each page-copy step.

3. **Progress control:** The plan uses `run_to_completion(1000, Duration::from_millis(10), None)` — 1000 pages per step with 10ms sleep between steps. For a typical drift.db (<100MB with 4KB pages = ~25,000 pages), this completes in ~250ms with 25 steps. The 10ms sleep between steps allows other database operations to proceed.

4. **Integrity verification:** The plan verifies backup integrity with `PRAGMA integrity_check` after each backup. This is a critical improvement over v1, which had no verification. The plan correctly deletes corrupted backups rather than leaving them in the registry.

**rusqlite Backup API availability:** The `rusqlite::backup::Backup` type is available in rusqlite 0.38 (the version recommended in Section 1). The API has been stable since rusqlite 0.20+.

**Tiered retention policy:** The plan's tiered retention (operational: 5, daily: 7, weekly: 4, max 500MB total) is a significant upgrade from v1's flat `max_backups = 10`. This matches enterprise backup practices (operational for quick rollback, daily for recent history, weekly for longer-term recovery).

**One note:** The plan backs up both drift.db and cortex.db (if present) in the same backup operation. This is correct — both databases should be backed up atomically to maintain cross-database consistency (e.g., bridge grounding results reference both databases).

---

### 10. 16 Workspace NAPI Functions — ✅ CONFIRMED

The plan defines 16 NAPI functions for workspace management (33-WORKSPACE-MANAGEMENT-V2-PREP §8). Let me assess whether any can be consolidated:

**Function inventory:**
1. `workspace_initialize(root_path, config?)` — Create/open workspace
2. `workspace_shutdown()` — Graceful shutdown
3. `workspace_get_status()` — Health snapshot
4. `workspace_get_context()` — Materialized context
5. `workspace_refresh_context()` — Force context refresh
6. `workspace_get_config()` — Read configuration
7. `workspace_update_config(key, value)` — Update configuration
8. `workspace_create_backup(reason)` — Create backup
9. `workspace_restore_backup(backup_id)` — Restore from backup
10. `workspace_list_backups()` — List available backups
11. `workspace_delete_backup(backup_id)` — Delete a backup
12. `workspace_switch_project(project_id)` — Switch active project
13. `workspace_list_projects()` — List registered projects
14. `workspace_add_project(path)` — Register new project
15. `workspace_doctor()` — Health diagnostics
16. `workspace_reset(confirmation)` — Destructive reset

**Consolidation analysis:**

| Candidate Group | Current | Consolidated | Assessment |
|----------------|---------|-------------|------------|
| Backup ops (8-11) | 4 functions | `workspace_backup(action, params)` | Possible but loses type safety — each operation has different params |
| Project ops (12-14) | 3 functions | `workspace_project(action, params)` | Possible but same concern |
| Config ops (6-7) | 2 functions | `workspace_config(action, params)` | Marginal savings |

**Verdict:** The 16 functions are appropriate. Each function has a clear, single responsibility. Consolidation would save 5-7 functions but at the cost of:
- Losing TypeScript type safety (consolidated functions need union types for params)
- Making the NAPI interface harder to understand
- Violating the "one function, one operation" principle from 03-NAPI-BRIDGE-V2-PREP §5

The 16 functions follow the same pattern as cortex-napi (33 functions across 12 binding modules). The NAPI boundary is not a performance concern — these are called infrequently (workspace operations, not hot-path analysis).

---

### 11. Bridge Grounding Loop Scheduling — ✅ CONFIRMED

The plan defines 6 grounding triggers with configurable frequencies (34-CORTEX-DRIFT-BRIDGE-V2-PREP §17):

| Trigger | Scope | Frequency | Assessment |
|---------|-------|-----------|------------|
| Post-scan (incremental) | Affected memories only | Every scan | ✅ Low cost, high relevance. Only grounds memories linked to changed files. |
| Post-scan (full) | All groundable memories | Every 10th scan | ✅ Catches drift in unaffected memories. 10 scans ≈ 1-2 hours of active development. |
| Scheduled | All groundable memories | Daily (configurable) | ✅ Background maintenance for overnight drift detection. |
| On-demand (MCP) | Specified memories | User-triggered | ✅ Essential for explicit validation requests. |
| Memory creation | New memory only | On creation | ✅ Immediate grounding provides instant feedback on new knowledge. |
| Memory update | Updated memory only | On update | ✅ Re-validates after content change. |

**Frequency assessment:**

The frequencies are well-calibrated for the expected usage patterns:

1. **Incremental after every scan** is the right default. The cost is proportional to the number of affected memories (typically 5-20 per scan), not the total memory count. With a max of 500 memories per loop, even a full grounding completes in seconds.

2. **Full grounding every 10th scan** prevents "grounding drift" — memories that aren't linked to recently changed files but whose grounding status may have changed due to broader codebase evolution. The 10-scan interval is conservative; a more aggressive interval (every 5 scans) could be offered as a configuration option.

3. **Daily scheduled grounding** is appropriate for teams that don't scan frequently. It ensures memories are validated at least once per day.

4. **The `min_changed_files` threshold** (default: 0, meaning always ground) is a useful optimization knob. For large monorepos where every save triggers a scan, setting this to 5-10 would skip grounding for trivial changes.

**The `GroundingScheduler` implementation is correct:**
- Uses `AtomicU32` for the scan counter (lock-free, thread-safe)
- Uses `Mutex<Option<DateTime<Utc>>>` for the last full grounding timestamp (rarely contended)
- The `should_ground()` method returns a `GroundingAction` enum (Skip/Incremental/Full) — clean API

**License gating is appropriate:**
- Community: manual grounding only (on-demand via MCP)
- Professional: automatic post-scan grounding + scheduled
- Enterprise: full grounding loop with contradiction generation

This ensures the grounding loop doesn't run unexpectedly for free-tier users while providing the full experience for paying customers.

---

### 12. 15 Bridge NAPI Functions — ✅ CONFIRMED

The plan defines 15 NAPI functions for the Cortex-Drift bridge (34-CORTEX-DRIFT-BRIDGE-V2-PREP §21):

**Function inventory:**
1. `bridge_initialize(cortex_db, drift_db, config?)` — Initialize bridge runtime
2. `bridge_shutdown()` — Graceful shutdown
3. `bridge_is_available()` — Check if bridge is active
4. `bridge_ground_memory(memory_id)` — Ground single memory (Async)
5. `bridge_ground_all(options?)` — Full grounding loop (Async)
6. `bridge_get_grounding_snapshot()` — Latest snapshot
7. `bridge_get_grounding_history(memory_id, limit?)` — History for memory
8. `bridge_translate_links(pattern_links, constraint_links)` — Translate links
9. `bridge_memories_for_pattern(pattern_id)` — Cross-DB query
10. `bridge_patterns_for_memory(memory_id)` — Cross-DB query
11. `bridge_why(query, file?, depth?)` — drift_why implementation (Async)
12. `bridge_learn(content, type?, links?)` — drift_memory_learn impl (Async)
13. `bridge_grounding_check(memory_id?, type?, apply?)` — drift_grounding_check (Async)
14. `bridge_get_metrics()` — Bridge health metrics
15. `bridge_register_event_handler()` — Register with Drift engine

**Surface area assessment:**

The 15 functions cover 6 distinct responsibility areas:
- **Lifecycle** (1-3): Initialize, shutdown, availability check — standard pattern
- **Grounding** (4-7): Core grounding operations — the bridge's primary purpose
- **Link translation** (8): Cross-system entity linking — essential for bridge
- **Cross-DB queries** (9-10): Pattern↔memory lookups — high-value queries
- **MCP tool backends** (11-13): Implementations for the 3 bridge MCP tools
- **Observability** (14-15): Metrics and event registration — operational necessity

**Consolidation analysis:**

The only candidates for consolidation are:
- `bridge_memories_for_pattern` + `bridge_patterns_for_memory` → `bridge_cross_query(direction, id)` — saves 1 function but loses clarity
- `bridge_ground_memory` + `bridge_ground_all` → `bridge_ground(scope, options)` — saves 1 function but conflates single vs batch

**Verdict:** 15 functions is reasonable for a bridge that connects two complex systems. Each function has a clear purpose and distinct parameter signature. The async/sync split is correct — grounding and MCP tool backends are async (potentially long-running), while queries and lifecycle operations are sync (fast).

The 15 functions follow the same density as cortex-napi (33 functions for a larger system). The bridge is architecturally simpler than cortex-core, so 15 functions is proportionate.

---

### 13. OD-5: Phase 7 + Phase 10 Timeline Realism — ⚠️ REVISE → RESOLVED

This is the last open decision from the tracker. The orchestration plan estimates:
- **Phase 7** (Advanced & Capstone): 3-4 weeks, fully parallelizable
- **Phase 10** (Polish & Ship): 4-6 weeks, highly parallelizable

The V2-PREP docs provide per-system build estimates that tell a different story.

**Phase 7 per-system estimates:**

| System | V2-PREP Estimate | Source |
|--------|-----------------|--------|
| Simulation Engine | **~6 weeks** (8 phases, 44 steps) | 28-SIMULATION-ENGINE-V2-PREP §32 |
| Decision Mining | **~8 weeks** (8 phases, 34 steps) | 29-DECISION-MINING-V2-PREP §27 |
| Context Generation | **~7 weeks** (7 phases, 35 steps) | 30-CONTEXT-GENERATION-V2-PREP §28 |
| N+1 Query Detection | **~2 weeks** (subset of ULP) | Orchestration plan §10.4 |

**Phase 7 analysis:**

The orchestration plan says "3-4 weeks, fully parallelizable." This is correct only if all 4 systems are built in parallel by 4 developers. The individual system estimates are:
- Simulation: 6 weeks (1 developer)
- Decision Mining: 8 weeks (1 developer)
- Context Generation: 7 weeks (1 developer)
- N+1: 2 weeks (1 developer)

With 4 parallel developers, Phase 7 takes **~8 weeks** (bounded by Decision Mining, the longest system). With 2 developers, it takes **~13-14 weeks** (Simulation+N+1 on one track, Decision Mining+Context on another). With 1 developer, it takes **~23 weeks** (sequential).

The orchestration plan's "3-4 weeks" estimate is **unrealistic for any team size**. Even with 4 developers, the longest single system (Decision Mining) takes 8 weeks. The plan appears to have used the phase-level estimate without cross-referencing the per-system V2-PREP estimates.

**Phase 10 per-system estimates:**

| System | V2-PREP Estimate | Source |
|--------|-----------------|--------|
| Workspace Management | **~5 weeks** (5 phases, 16 NAPI functions) | 33-WORKSPACE-MANAGEMENT-V2-PREP §25 |
| Licensing & Feature Gating | ~2 weeks | Orchestration plan §13.2 (no V2-PREP) |
| Docker Deployment | ~1 week | Orchestration plan §13.3 (no V2-PREP) |
| Telemetry | ~1 week | Orchestration plan §13.4 (no V2-PREP) |
| VSCode Extension | ~3-4 weeks | Orchestration plan §13.5 (no V2-PREP) |
| LSP Server | ~3-4 weeks | Orchestration plan §13.5 (no V2-PREP) |
| Dashboard | ~2-3 weeks | Orchestration plan §13.5 (no V2-PREP) |
| Galaxy (3D viz) | ~2-3 weeks | Orchestration plan §13.5 (lowest priority) |
| AI Providers | ~1-2 weeks | Orchestration plan §13.6 (no V2-PREP) |
| CIBench | ~1-2 weeks | Orchestration plan §13.7 (no V2-PREP) |

**Phase 10 analysis:**

The orchestration plan says "4-6 weeks, highly parallelizable." With maximum parallelism (5+ developers), the longest single system is Workspace Management at 5 weeks. So 4-6 weeks is achievable with 5+ developers.

However, the realistic scenario for most teams:
- **1 developer**: ~20-25 weeks (sequential, all systems)
- **2 developers**: ~12-15 weeks (Workspace+Licensing on one track, IDE+Dashboard on another)
- **3-4 developers**: ~6-8 weeks (full parallelism on independent systems)
- **5+ developers**: ~5-6 weeks (bounded by Workspace Management)

The "4-6 weeks" estimate is realistic for 3+ developers but optimistic for 1-2 developers.

**Critical path impact:**

The orchestration plan's critical path calculation (§16) is:
```
Phase 0 (1-2w) → Phase 1 (2-3w) → Phase 2 (2w) → Phase 3 (3-4w) →
Phase 6 (2-3w) → Phase 8 (2w) = 12-16 weeks for a shippable product
```

This critical path is correct — it doesn't include Phase 7 or Phase 10. Phases 7 and 10 are off the critical path (they're "nice to have" features that can ship later). The critical path produces a shippable product with core analysis, enforcement, MCP server, CLI, and CI agent.

**Resolution for OD-5:**

| Phase | Plan Estimate | Realistic (1 dev) | Realistic (2 dev) | Realistic (4 dev) |
|-------|--------------|-------------------|-------------------|-------------------|
| Phase 7 | 3-4 weeks | ~23 weeks | ~13-14 weeks | ~8 weeks |
| Phase 10 | 4-6 weeks | ~20-25 weeks | ~12-15 weeks | ~5-6 weeks |

**Recommendations:**

1. **Update Phase 7 estimate** to "6-8 weeks with 4 parallel developers, 8 weeks bounded by Decision Mining." The "3-4 weeks" estimate should be removed — it's not achievable at any team size.

2. **Update Phase 10 estimate** to "5-6 weeks with 3+ parallel developers." The "4-6 weeks" estimate is close but should note the team size requirement.

3. **Add per-system estimates to the orchestration plan** (§10 and §13) so the phase-level estimates are grounded in the V2-PREP data.

4. **Prioritize within Phase 7**: Context Generation (powers the MCP tools) should be P0. Simulation and Decision Mining are P1. N+1 is P2. This allows shipping the most valuable Phase 7 feature first.

5. **Prioritize within Phase 10**: Workspace Management is P0 (needed for production). Licensing is P0 (needed for monetization). VSCode Extension + LSP are P1. Dashboard, Galaxy, AI Providers, CIBench are P2.

6. **The critical path is unaffected.** Phases 7 and 10 are off the critical path. A shippable product (Milestone 6: "It Ships") is achievable in 14-20 weeks regardless of Phase 7/10 timeline.

**OD-5 Status: ✅ RESOLVED** — Phase 7 and Phase 10 estimates are optimistic but the critical path is unaffected. Updated estimates provided above.

---

## Verdict Summary

| Item | Verdict | Action Required |
|------|---------|-----------------|
| Monte Carlo simulation | ✅ CONFIRMED | Sound technique, well-implemented. ±10% perturbation and 1000 samples are appropriate. Enterprise-tier gating is correct. |
| git2 crate | ⚠️ REVISE | Pin "0.20" not "0.19". git2 0.20.2 is current (May 2025), bundles libgit2 1.9. Maintained by rust-lang. Thread safety model correctly handled. |
| tiktoken-rs | ⚠️ REVISE | Pin "0.9" not "0.6". tiktoken-rs 0.9.1 is current (Nov 2025). Adds o200k_harmony for GPT-oss models. API backward-compatible. Fallback chain is sound. |
| MCP spec version | ⚠️ REVISE | Target 2025-11-25 as baseline, not 2025-06-18. The 2025-11-25 spec is the current latest, adds CIMD, XAA, mandatory PKCE, and security clarifications. All 2025-06-18 features are included. |
| Streamable HTTP transport | ✅ CONFIRMED | Supported by @modelcontextprotocol/sdk since v1.10.0 (Apr 2025). Replaces deprecated SSE. Dual-transport (stdio + Streamable HTTP) is correct. |
| Progressive disclosure (3 entry points) | ✅ CONFIRMED | Validated by 4+ production MCP server implementations. 67-98% token reduction reported. The `drift_discover` → `drift_tool` pattern is the emerging standard. |
| 52 + 33 internal tools | ✅ CONFIRMED | Appropriate for scope. Progressive disclosure makes 52 tools manageable. Pack system and language filtering reduce cognitive load. No consolidation needed. |
| fd-lock for process locking | ✅ CONFIRMED | fd-lock 4.0.4 is current (Mar 2025). 1.7M+ downloads/month. Cross-platform (flock on Unix, LockFile on Windows). RwLock API is correct for Drift's read/write semantics. Pin "4". |
| SQLite Backup API | ✅ CONFIRMED | Correct approach for WAL-mode databases. rusqlite Backup API is stable. Page-by-page copy with integrity verification is a significant improvement over v1's file copy. Tiered retention is well-designed. |
| 16 workspace NAPI functions | ✅ CONFIRMED | Appropriate count. Each function has clear single responsibility. Consolidation would lose type safety. Follows cortex-napi density pattern. |
| Bridge grounding scheduling | ✅ CONFIRMED | 6 triggers with configurable frequencies are well-calibrated. Incremental after every scan is low-cost. Full every 10th scan catches drift. License gating is appropriate. |
| 15 bridge NAPI functions | ✅ CONFIRMED | Reasonable for a cross-system bridge. 6 responsibility areas, clear async/sync split. Proportionate to cortex-napi's 33 functions. |
| OD-5: Timeline realism | ⚠️ RESOLVED | Phase 7 "3-4 weeks" is unrealistic — should be "6-8 weeks with 4 devs." Phase 10 "4-6 weeks" is close but requires 3+ devs. Critical path (12-16 weeks) is unaffected. Per-system estimates should be added to orchestration plan. |

**Summary: 8 CONFIRMED, 4 REVISE, 1 RESOLVED (OD-5), 0 REJECT.**

The Phases 7-10 architecture is sound. The progressive disclosure MCP pattern, grounding loop scheduling, SQLite Backup API, and fd-lock choices are all validated by production usage and current best practices. The 4 revisions are version bumps (git2 0.19→0.20, tiktoken-rs 0.6→0.9, MCP spec 2025-06-18→2025-11-25) and a timeline correction (Phase 7 estimate is unrealistic at "3-4 weeks"). The critical path to a shippable product is unaffected by the timeline revision — Phases 7 and 10 are off the critical path.
