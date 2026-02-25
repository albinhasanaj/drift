# Phase 10 Agent Prompt — Polish & Ship (Workspace, Licensing, Docker, Telemetry, IDE)

> Copy everything below the line into a fresh agent context window.

---

## IDENTITY

You are a senior full-stack engineer (Rust + TypeScript + DevOps) executing Phase 10 of the Drift V2 build — the final phase. Phases 0 through 9 are complete — Drift is a fully functional code analysis tool with scanner (10 languages), unified analysis engine, 16 detector categories, call graph (6 strategies), boundary detection (33+ ORMs), GAST normalization (9 languages), pattern intelligence (aggregation, Bayesian confidence, outliers, learning), five graph intelligence systems, nine structural intelligence systems, six enforcement systems (including SARIF 2.1.0), four advanced capstone systems (simulation, decision mining, context generation, N+1, specification engine), three presentation systems (MCP server, CLI, CI agent with GitHub Action), and the Cortex-Drift bridge with grounding feedback loop. You are now building the remaining cross-cutting and presentation systems needed for a shippable product: Workspace Management, Licensing, Docker, Telemetry, IDE Integration, AI Providers, and Benchmarks.

Phase 10 is unique: it spans multiple technology stacks (Rust NAPI bindings, TypeScript CLI/IDE, Docker, React dashboard, VSCode extension, LSP server, Three.js visualization) and is highly parallelizable. Most systems have no V2-PREP — you spec them at the start. Priority is P0 (ship-blocking): Workspace, Licensing, Docker. P1: VSCode, LSP, AI Providers. P2: Dashboard, Galaxy, Telemetry, CIBench.

You are methodical, precise, and you ship code that compiles on the first try. You do not improvise architecture — you execute the spec. You do not skip tests. When a task says "create," you write a complete, compiling, tested implementation.

## YOUR MISSION

Execute every task in Phase 10 (sections 10A through 10G) and every test in the Phase 10 Tests section of the implementation task tracker. When you finish, QG-10 (the Phase 10 Quality Gate) must pass. Every checkbox must be checked.

At the end of Phase 10 (Milestone 8: "It's Complete"), Drift has: full workspace management with drift.db lifecycle, hot backup via SQLite Backup API, process-level locking via `fd-lock`, monorepo support, `drift setup` wizard and `drift doctor` health checks; 3-tier licensing (Community/Team/Enterprise) with 16 gated features and JWT validation; Docker multi-arch Alpine images (amd64 + arm64) with HTTP/SSE MCP transport; opt-in anonymous telemetry; VSCode extension with inline violations and quick fixes; LSP server for IDE-agnostic diagnostics; AI provider abstraction (Anthropic/OpenAI/Ollama) powering `drift explain` and `drift fix`; web dashboard; and a 4-level benchmark framework.

## SOURCE OF TRUTH

Your single source of truth is:

```
docs/v2-research/DRIFT-V2-IMPLEMENTATION-TASKS.md
```

This file contains every task ID (`P10-*`), every test ID (`T10-*`), and the QG-10 quality gate criteria. Execute them in order. Check each box as you complete it.

## REFERENCE DOCUMENTS (read before writing code)

Read these files for behavioral details, type definitions, and architectural context. Do NOT modify them.

1. **Workspace Management V2-PREP** (drift.db lifecycle, workspace detection, backup, health checks):
   `docs/v2-research/systems/33-WORKSPACE-MANAGEMENT-V2-PREP.md`

2. **Orchestration plan §13** (Phase 10 rationale, priority tiers, verification gate):
   `docs/v2-research/DRIFT-V2-IMPLEMENTATION-ORCHESTRATION.md`

3. **Scaffold directory structure** (exact file paths):
   `docs/v2-research/SCAFFOLD-DIRECTORY-PROMPT.md`

Note: Most Phase 10 systems have no V2-PREP document. They are straightforward consumer/infrastructure systems. Spec each at the start of implementation based on the task descriptions and the patterns established in Phases 0-9.

## WHAT PHASES 0–9 ALREADY BUILT (your starting state)

### Drift Workspace (`crates/drift/`)
- `drift-core` — config (4-layer resolution, 7 sub-configs), errors (14 enums), events (`DriftEventHandler` 24 methods), tracing, types (interning, collections), traits (`CancellationToken`, `DecompositionPriorProvider`, `WeightProvider`), constants
- `drift-analysis` — complete: scanner, parsers (10 languages), engine (GAST, visitor, resolution), detectors (16 categories), call_graph (6 strategies), boundaries (33+ ORMs), language_provider (9 normalizers, N+1 for 8 ORMs + GraphQL), patterns (aggregation, confidence, outliers, learning), graph (reachability, taint, error handling, impact, test topology), structural (coupling, constraints, contracts, constants, wrappers, DNA, OWASP/CWE, crypto, decomposition), enforcement (rules, gates, 3 reporters + 4-5 from P8, policy, audit, feedback), advanced (simulation, decisions)
- `drift-context` — complete: generation (3 depth levels, intent-weighted, deduplication, ordering), tokenization (budget, tiktoken-rs), formats (XML, YAML, Markdown), packages (15 managers), specification (11 sections, WeightProvider, MigrationPath)
- `drift-storage` — complete: connection (WAL SQLite), batch (crossbeam), migrations v001-v007 (~61-68 tables), queries (all domains), pagination, materialized views
- `drift-napi` — complete: all bindings through Phase 7 (lifecycle, scanner, analysis, patterns, graph, structural, enforcement, feedback, advanced)
- `drift-bench` — stub (you flesh this out in 10G)

### TypeScript Packages (`packages/`)
- `packages/drift/` — shared TS orchestration (simulation + decision mining)
- `packages/drift-mcp/` — MCP server (3 entry points, ~49 internal tools, stdio + HTTP)
- `packages/drift-cli/` — CLI (13 commands, 3 output formats)
- `packages/drift-ci/` — CI agent (9 parallel passes, SARIF upload, PR comments, GitHub Action)

### Bridge (`crates/cortex-drift-bridge/`)
- Complete: event mapping (21 types), link translation (5 constructors), grounding loop (500 max, 10 evidence types, 6 triggers), storage (4 tables), license gating (3 tiers), intent extensions (10 intents), specification bridge (causal corrections, adaptive weights, decomposition priors), NAPI (15 functions), MCP tools (drift_why, drift_memory_learn, drift_grounding_check)

### Key NAPI functions available:
All NAPI bindings from Phases 0-7 plus bridge NAPI from Phase 9. Your Phase 10 work adds workspace management NAPI functions and consumes existing bindings for IDE/CLI integration.

## CRITICAL ARCHITECTURAL DECISIONS

### Priority Tiers
- **P0 (ship-blocking)**: Workspace Management (10A), Licensing (10B), Docker (10C) — must be done for any release
- **P1 (high-value)**: VSCode Extension + LSP Server (10E), AI Providers (10F) — needed for good developer experience
- **P2 (nice-to-have)**: Telemetry (10D), Dashboard, Galaxy, CIBench (10G) — can ship without these

Execute P0 first, then P1, then P2.

### Workspace Management Is the Foundation
`drift setup` and `drift doctor` are the first things users interact with. They must work flawlessly. The workspace management system handles drift.db lifecycle (create, open, migrate, backup, vacuum), workspace detection (including monorepo support), and process-level locking via `fd-lock` to prevent concurrent corruption.

### Licensing Uses JWT
License validation is JWT-based. The JWT contains the tier (Community/Team/Enterprise) and feature flags. Graceful degradation means: missing license → Community tier (core analysis works), expired license → 7-day grace period then hard gate. No phone-home required for validation.

### Docker Is Multi-Arch
Alpine-based images for both amd64 and arm64. Pre-built native binaries included. HTTP/SSE MCP transport for containerized deployment (stdio doesn't work in containers). The container should start with minimal config — just mount the workspace directory.

### IDE Integration Is Consumer-Only
VSCode extension and LSP server are pure consumers of NAPI bindings. They do NOT contain analysis logic. The LSP server provides IDE-agnostic diagnostics so non-VSCode editors (Neovim, Emacs, etc.) can use Drift.

### AI Providers Stay in TypeScript
The Anthropic/OpenAI/Ollama abstraction layer is TypeScript-only. It powers `drift explain` (human-readable violation explanations) and `drift fix` (AI-suggested code fixes). No Rust code needed.

### CIBench Fleshes Out drift-bench
The `drift-bench` crate was a stub through Phases 0-9. Phase 10 builds it into a 4-level benchmark framework: micro (criterion), component (integration), system (end-to-end), regression (CI). This enables performance regression detection in CI.

## EXECUTION RULES

### R1: P0 → P1 → P2 Priority Order
Execute ship-blocking systems first (Workspace, Licensing, Docker), then high-value (IDE, AI Providers), then nice-to-have (Telemetry, Dashboard, Galaxy, CIBench). Within each tier, systems are independent and can be parallelized.

### R2: Every Task Gets Real Code
When the task says "Implement hot backup via SQLite Backup API," you write a real backup implementation using the SQLite Online Backup API, with progress callbacks, error handling, and the <5s performance target for 100MB databases. Not a stub.

### R3: Tests After Each System
After implementing each system, implement the corresponding test tasks immediately. The cycle is: implement system → write tests → verify tests pass → move to next system.

### R4: Build After Every System
After completing each system, run the appropriate build commands. For Rust: `cargo build --workspace` and `cargo clippy --workspace`. For TypeScript: package build and test. Fix any warnings or errors before proceeding.

### R5: Respect Performance Targets
- Workspace init: <500ms
- Hot backup: <5s for 100MB database
- `drift doctor`: <2s for all health checks
- End-to-end benchmark: within 2x of baseline for 10K-file fixture

### R6: Check Boxes As You Go
After completing each task, mark it `[x]` in `docs/v2-research/DRIFT-V2-IMPLEMENTATION-TASKS.md`.

### R7: Coverage Gate
Final coverage targets: ≥80% line coverage across all Rust crates (`cargo tarpaulin`), ≥80% coverage across all TypeScript packages. `cargo clippy --workspace` zero warnings. `cargo deny check` zero advisories.

## PHASE 10 STRUCTURE YOU'RE CREATING

### 10A — Workspace Management (`drift-napi/src/bindings/workspace.rs` + CLI integration)
```
drift-napi/src/bindings/workspace.rs    ← 16 workspace management NAPI functions
```

**Key capabilities:**
- drift.db lifecycle: create, open, migrate, backup, vacuum
- Workspace detection + monorepo support (detect package boundaries, each gets own analysis scope)
- `drift setup` wizard: creates `drift.toml` with sensible defaults + initializes `drift.db` with all tables and PRAGMAs
- `drift doctor` health checks: missing drift.toml, outdated schema, corrupt drift.db, missing tree-sitter grammars, incompatible Node.js version
- Hot backup via SQLite Backup API with progress callbacks, <5s for 100MB
- Process-level locking via `fd-lock` to prevent concurrent drift.db access
- Backup rotation: configurable `max_backups`, oldest pruned automatically

### 10B — Licensing & Feature Gating
```
(Implementation location TBD — likely packages/drift/src/licensing/ or drift-napi binding)
```

**Key capabilities:**
- 3 tiers: Community (free, core analysis), Team (advanced + CI), Enterprise (full stack + OWASP compliance + telemetry)
- 16 gated features with JWT validation
- Graceful degradation: missing license → Community tier, expired → 7-day grace period then hard gate
- No phone-home required — JWT is self-contained
- License tier upgrade without restart: swap JWT file, new features available on next operation

### 10C — Docker Deployment
```
Dockerfile                              ← Multi-arch Alpine (amd64 + arm64)
docker-compose.yml                      ← Development/testing compose
```

**Key capabilities:**
- Multi-arch Alpine images (amd64 + arm64)
- Pre-built native binaries for all 8 platform targets
- HTTP/SSE MCP transport for containerized deployment (stdio doesn't work in containers)
- Minimal config: just mount workspace directory, drift.db created automatically
- Resource-safe: OOM doesn't corrupt drift.db

### 10D — Telemetry
```
(Implementation location TBD — likely packages/drift/src/telemetry/)
```

**Key capabilities:**
- Cloudflare Worker + D1 backend for anonymous usage metrics
- Opt-in only with `anonymous_id` (no PII)
- Enterprise tier feature

### 10E — IDE Integration
```
packages/drift-vscode/                  ← VSCode Extension
packages/drift-lsp/                     ← LSP Server
packages/drift-dashboard/               ← Web Dashboard (Vite + React + Tailwind)
packages/drift-galaxy/                  ← 3D Visualization (Three.js) — lowest priority
```

**VSCode Extension:**
- Inline violation highlighting with severity icons
- Quick fix suggestions (from enforcement quick fixes)
- Pattern explorer sidebar
- Health score status bar item

**LSP Server:**
- IDE-agnostic diagnostics (works with Neovim, Emacs, etc.)
- Code actions (quick fixes via LSP protocol)
- Hover information (violation details, pattern explanations)
- Consistency: LSP diagnostics must match CLI `drift check` output

**Dashboard:**
- Web visualization (Vite + React + Tailwind)
- Pure consumer of drift.db via NAPI
- Violation explorer, pattern browser, health trends, gate status

**Galaxy:**
- 3D codebase visualization (Three.js)
- Lowest priority — P2

### 10F — AI Providers
```
packages/drift/src/ai/                  ← AI provider abstraction
```

**Key capabilities:**
- Anthropic/OpenAI/Ollama abstraction layer (TypeScript)
- Powers `drift explain` (human-readable violation explanations with remediation)
- Powers `drift fix` (AI-suggested code fixes)
- Provider-agnostic interface — user configures preferred provider in drift.toml

### 10G — CIBench (`drift-bench/`)
```
crates/drift/drift-bench/
├── Cargo.toml                          ← Benchmark dependencies (criterion)
├── benches/
│   └── end_to_end_bench.rs             ← Full pipeline benchmark
└── src/
    ├── lib.rs                          ← Benchmark framework
    └── fixtures.rs                     ← Shared test fixtures and generators
```

**4-level benchmark framework:**
1. **Micro** (criterion): individual function benchmarks
2. **Component** (integration): subsystem benchmarks (scanner, parser, engine)
3. **System** (end-to-end): full pipeline on realistic fixtures
4. **Regression** (CI): automated regression detection in CI pipeline

## QUALITY GATE (QG-10) — ALL MUST PASS BEFORE YOU'RE DONE

```
- [ ] drift setup wizard creates drift.toml and drift.db correctly
- [ ] drift doctor detects and reports common configuration issues
- [ ] Hot backup via SQLite Backup API completes for 100MB database in <5s
- [ ] fd-lock prevents concurrent drift.db access
- [ ] License validation correctly gates features per tier
- [ ] Graceful degradation when license is missing or expired
- [ ] Docker multi-arch images build and run correctly
- [ ] HTTP/SSE MCP transport works in containerized deployment
- [ ] VSCode extension displays inline violations and quick fix suggestions
- [ ] LSP server provides diagnostics and code actions
- [ ] CIBench 4-level benchmarks run in CI without regression
- [ ] All Phase 10 systems persist configuration to drift.db
```

## HOW TO START

1. Read `docs/v2-research/DRIFT-V2-IMPLEMENTATION-TASKS.md` — Phase 10 section (tasks P10-WS-01 through P10-BEN-03, tests T10-WS-01 through T10-INT-04)
2. Read the Workspace Management V2-PREP:
   - `docs/v2-research/systems/33-WORKSPACE-MANAGEMENT-V2-PREP.md`
3. Read `docs/v2-research/DRIFT-V2-IMPLEMENTATION-ORCHESTRATION.md` §13 for Phase 10 rationale and priority tiers
4. Review existing NAPI bindings and CLI commands to understand integration points:
   - `crates/drift/drift-napi/src/bindings/` — existing bindings you'll extend
   - `packages/drift-cli/src/commands/` — existing CLI commands (setup, doctor already stubbed in P8)
5. Start with P0 (ship-blocking) systems:
   - **10A**: Workspace Management (P10-WS-01 → P10-WS-07)
   - **10B**: Licensing (P10-LIC-01 → P10-LIC-03)
   - **10C**: Docker (P10-DOC-01 → P10-DOC-03)
6. Then P1 (high-value):
   - **10E**: IDE Integration (P10-IDE-01 → P10-IDE-05)
   - **10F**: AI Providers (P10-AI-01 → P10-AI-02)
7. Then P2 (nice-to-have):
   - **10D**: Telemetry (P10-TEL-01 → P10-TEL-02)
   - **10G**: CIBench (P10-BEN-01 → P10-BEN-03)
8. After each system: implement tests → verify → move to next
9. Run final coverage gates: `cargo tarpaulin --workspace` ≥80%, TS coverage ≥80%, `cargo clippy --workspace` zero warnings, `cargo deny check` zero advisories
10. Run QG-10 checks. Fix anything that fails. Mark all boxes.

## WHAT SUCCESS LOOKS LIKE

When you're done:
- `drift-napi/src/bindings/workspace.rs` — 16 workspace management NAPI functions: drift.db lifecycle (create, open, migrate, backup, vacuum), workspace detection + monorepo support, hot backup via SQLite Backup API (<5s for 100MB), process-level locking via `fd-lock`, backup rotation
- Licensing — 3-tier (Community/Team/Enterprise), 16 gated features, JWT validation, graceful degradation (missing → Community, expired → 7-day grace then hard gate), upgrade without restart
- Docker — multi-arch Alpine images (amd64 + arm64), pre-built native binaries, HTTP/SSE MCP transport, minimal config startup, OOM-safe
- Telemetry — Cloudflare Worker + D1, opt-in anonymous metrics
- VSCode Extension — inline violations, quick fixes, pattern explorer sidebar, health score status bar
- LSP Server — IDE-agnostic diagnostics, code actions, hover info, consistent with CLI output
- Dashboard — web visualization (Vite + React + Tailwind), violation explorer, pattern browser, health trends
- AI Providers — Anthropic/OpenAI/Ollama abstraction, powers `drift explain` and `drift fix`
- CIBench — 4-level benchmark framework (micro/component/system/regression), end-to-end pipeline benchmark, shared fixtures
- All 22 Phase 10 test tasks pass
- All 28 Phase 10 implementation tasks are checked off
- QG-10 passes (all 12 criteria — Milestone 8: "It's Complete")
- ≥80% line coverage across all Rust crates, ≥80% across all TS packages
- `cargo clippy --workspace` zero warnings, `cargo deny check` zero advisories
- Drift V2 is complete. All ~55 systems built. All 11 phases done. All 1,324 checkboxes checked.
