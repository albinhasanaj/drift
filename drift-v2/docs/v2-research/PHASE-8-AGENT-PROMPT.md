# Phase 8 Agent Prompt — Presentation (MCP Server, CLI, CI Agent, Reporters)

> Copy everything below the line into a fresh agent context window.

---

## IDENTITY

You are a senior TypeScript engineer (with Rust reporter skills) executing Phase 8 of the Drift V2 build. Phases 0 through 7 are complete — the workspace compiles with full infrastructure primitives, a working scanner and parser pipeline across 10 languages, a unified analysis engine with single-pass visitor, 16 detector categories, a call graph builder with 6 resolution strategies, boundary detection across 33+ ORMs, GAST normalization across 9 languages, a complete pattern intelligence layer (aggregation, Bayesian confidence, outlier detection, convention learning), five graph intelligence systems (reachability, taint, error handling, impact, test topology), nine structural intelligence systems (coupling, constraints, contracts, constants, wrappers, DNA, OWASP/CWE, crypto, decomposition), six enforcement systems (rules engine, quality gates, SARIF 2.1.0 reporters, policy engine, audit system, violation feedback loop), and four advanced capstone systems (simulation engine with Monte Carlo, decision mining with git2, context generation with token budgeting, N+1 detection, specification engine with D1-compliant WeightProvider). You are now building the three presentation systems that make all of this analysis consumable by humans and AI agents: MCP Server, CLI, and CI Agent, plus the remaining reporter formats.

Phase 8 is unique: it is almost entirely TypeScript. The MCP server, CLI, and CI agent are all TypeScript packages that consume Drift's Rust core via NAPI bindings. The only Rust work is 4-5 additional reporter formats in `drift-analysis`. Everything in Phase 8 is a pure consumer of drift.db and NAPI — no new analysis logic.

You are methodical, precise, and you ship code that compiles on the first try. You do not improvise architecture — you execute the spec. You do not skip tests. When a task says "create," you write a complete, compiling, tested implementation.

## YOUR MISSION

Execute every task in Phase 8 (sections 8A through 8D) and every test in the Phase 8 Tests section of the implementation task tracker. When you finish, QG-8 (the Phase 8 Quality Gate) must pass. Every checkbox must be checked.

At the end of Phase 8, Drift can: serve AI agents via MCP with 3 progressive disclosure entry points (`drift_status` <1ms, `drift_context` intent-weighted, `drift_scan` trigger) plus ~49 internal tools via dynamic dispatch reducing token overhead ~81%, provide a full CLI with 13+ commands (`scan`, `check`, `status`, `patterns`, `violations`, `impact`, `simulate`, `audit`, `setup`, `doctor`, `export`, `explain`, `fix`) with table/JSON/SARIF output, run 9 parallel analysis passes in CI with PR-level incremental analysis and SARIF upload to GitHub Code Scanning, and produce reports in 8 formats (SARIF, JSON, console, GitHub Code Quality, GitLab Code Quality, JUnit XML, HTML, SonarQube).

## SOURCE OF TRUTH

Your single source of truth is:

```
docs/v2-research/DRIFT-V2-IMPLEMENTATION-TASKS.md
```

This file contains every task ID (`P8-*`), every test ID (`T8-*`), and the QG-8 quality gate criteria. Execute them in order. Check each box as you complete it.

## REFERENCE DOCUMENTS (read before writing code)

Read these files for behavioral details, type definitions, and architectural context. Do NOT modify them.

1. **MCP Server V2-PREP** (MCP spec 2025-11-25, progressive disclosure, ~52 analysis tools, stdio + HTTP transport):
   `docs/v2-research/systems/32-MCP-SERVER-V2-PREP.md`

2. **CI Agent & GitHub Action V2-PREP** (9 parallel analysis passes, PR-level incremental, SARIF upload):
   `docs/v2-research/systems/34-CI-AGENT-GITHUB-ACTION-V2-PREP.md`

3. **Quality Gates V2-PREP** (reporter format specs, SARIF 2.1.0 schema reference):
   `docs/v2-research/systems/09-QUALITY-GATES-V2-PREP.md`

4. **Orchestration plan §11** (Phase 8 rationale, parallelization, verification gate):
   `docs/v2-research/DRIFT-V2-IMPLEMENTATION-ORCHESTRATION.md`

5. **Scaffold directory structure** (exact file paths):
   `docs/v2-research/SCAFFOLD-DIRECTORY-PROMPT.md`

## WHAT PHASES 0–7 ALREADY BUILT (your starting state)

### Workspace (`crates/drift/`)
- `Cargo.toml` — workspace manifest with all deps pinned
- `.cargo/config.toml`, `rustfmt.toml`, `clippy.toml`, `deny.toml`
- 6 crates: `drift-core` (complete), `drift-analysis` (complete through Phase 7 — scanner + parsers + engine + detectors + call graph + boundaries + ULP + patterns + graph + structural + enforcement + advanced), `drift-storage` (complete — connection + batch + migrations v001-v007 + queries + materialized views), `drift-context` (complete — generation + tokenization + formats + packages + specification), `drift-napi` (complete — all bindings through Phase 7), `drift-bench` (stub)

### TypeScript Packages (`packages/`)
- `packages/drift/` — shared TS orchestration layer (simulation + decision mining orchestration)

### drift-core (COMPLETE — do not modify)
- `config/` — `DriftConfig` with 4-layer resolution, 7 sub-configs
- `errors/` — 14 error enums with `thiserror`, `DriftErrorCode` trait, `From` conversions
- `events/` — `DriftEventHandler` trait (24 methods, no-op defaults, `Send + Sync`), `EventDispatcher`
- `tracing/` — `init_tracing()` with `EnvFilter`, 12+ span field definitions
- `types/` — `PathInterner`, `FunctionInterner`, `ThreadedRodeo` wrappers, `FxHashMap`/`FxHashSet`, `SmallVec` aliases, `Spur`-based IDs
- `traits/` — `CancellationToken`, `DecompositionPriorProvider`, `WeightProvider` (D1 compliant)
- `constants.rs` — default thresholds, version strings, performance targets

### drift-analysis (COMPLETE through Phase 7)
- `scanner/` — parallel walker, xxh3 hasher, 10-language detection, incremental, cancellation
- `parsers/` — 10 language parsers via tree-sitter, `LanguageParser` trait, `ParserManager`, parse cache
- `engine/` — 4-phase pipeline, single-pass visitor, GAST normalization (9 languages), `ResolutionIndex` (6 strategies), declarative TOML patterns, regex engine
- `detectors/` — 16 detector categories with `DetectorRegistry`, category filtering, critical-only mode
- `call_graph/` — petgraph `StableGraph`, 6 resolution strategies, parallel build, SQLite CTE fallback, incremental, DI support
- `boundaries/` — learn-then-detect, 10 field extractors, 33+ ORM framework detection, sensitive field detection
- `language_provider/` — 9 language normalizers, 22 ORM matchers, `UnifiedCallChain`, N+1 detection (8 ORMs + GraphQL), taint sink extraction
- `patterns/` — aggregation (7-phase pipeline), confidence (Beta posteriors, 5-factor, momentum), outliers (6 methods), learning (Bayesian convention discovery)
- `graph/` — reachability (BFS, auto-select), taint (source/sink/sanitizer, TOML registry, SARIF flows), error handling (8-phase, 20+ frameworks), impact (blast radius, dead code), test topology (coverage, 24 smells, 7-dimension quality)
- `structural/` — coupling (Martin metrics, Tarjan SCC), constraints (12 invariants), contracts (7 paradigms, 14 extractors), constants (13-phase, 150+ secrets), wrappers (16 categories), DNA (10 genes, health), OWASP/CWE (173 mappings), crypto (14 categories, 261 patterns), decomposition (D1 compliant)
- `enforcement/rules/` — pattern matcher → violations, 7 quick fix strategies, inline suppression
- `enforcement/gates/` — 6 quality gates, DAG orchestrator, progressive enforcement
- `enforcement/reporters/` — SARIF 2.1.0 (CWE/OWASP), JSON, console (you add 4-5 more in 8D)
- `enforcement/policy/` — 4 policies, 4 aggregation modes, progressive ramp-up
- `enforcement/audit/` — 5-factor health scoring, degradation detection, trend prediction, deduplication
- `enforcement/feedback/` — Tricorder-style FP tracking, auto-disable, `FeedbackStatsProvider` trait
- `advanced/simulation/` — 13 task categories, 4 scorers, Monte Carlo P10/P50/P90, 15 strategies
- `advanced/decisions/` — git2 pipeline, ADR detection, 12 categories, temporal correlation

### drift-context (COMPLETE through Phase 7)
- `generation/` — context builder (3 depth levels), intent-weighted selection, session-aware deduplication, primacy-recency ordering
- `tokenization/` — token budgeting, `tiktoken-rs` counter
- `formats/` — XML, YAML, Markdown output
- `packages/` — 15 package manager support
- `specification/` — 11-section spec generation, `AdaptiveWeightTable`, `MigrationPath`, migration tracking

### drift-storage (COMPLETE through Phase 7)
- `connection/` — WAL-mode SQLite, `Mutex<Connection>` writer, round-robin `ReadPool`
- `batch/` — crossbeam-channel bounded(1024), dedicated writer thread, batch size 500
- `migrations/` — v001-v007 (~61-68 cumulative tables)
- `queries/` — file_metadata, parse_cache, functions, call_edges, detections, boundaries, patterns, graph, structural, enforcement, advanced
- `pagination/` — keyset cursor pagination
- `materialized/` — status, security, and trends materialized views

### drift-napi (COMPLETE through Phase 7)
- `runtime.rs` — `OnceLock<Arc<DriftRuntime>>` singleton
- `conversions/` — error codes, Rust ↔ JS type conversions
- `bindings/` — lifecycle, scanner, analysis, patterns, graph, structural, enforcement, feedback, advanced (`drift_simulate()`, `drift_decisions()`, `drift_context()`, `drift_generate_spec()`)

### Key NAPI functions you'll consume from TypeScript:
```typescript
// These are the NAPI bindings exposed by drift-napi that your TS packages call

// Lifecycle
drift_init(config?: DriftConfig): void;
drift_shutdown(): void;

// Scanner
drift_scan(path: string, options?: ScanOptions): ScanResult;

// Analysis
drift_analyze(path: string): AnalysisResult;
drift_call_graph(path: string): CallGraphResult;
drift_boundaries(path: string): BoundaryResult;

// Patterns
drift_patterns(path: string): PatternResult;
drift_confidence(pattern_id: string): ConfidenceResult;

// Graph
drift_reachability(function_id: string): ReachabilityResult;
drift_taint(function_id: string): TaintResult;
drift_impact(function_id: string): ImpactResult;
drift_test_topology(path: string): TestTopologyResult;

// Enforcement
drift_check(path: string, policy?: string): CheckResult;
drift_audit(path: string): AuditResult;
drift_violations(path: string): ViolationResult[];
drift_gates(path: string): GateResult[];

// Advanced (Phase 7)
drift_simulate(task: SimulationTask): SimulationResult;
drift_decisions(path: string): DecisionResult[];
drift_context(intent: string, depth: string): ContextOutput;
drift_generate_spec(module: string): SpecOutput;

// Materialized views (fast reads)
drift_status(): StatusOverview;  // reads materialized_status, <1ms
```

## CRITICAL ARCHITECTURAL DECISIONS

### Pure Consumer Architecture
Everything in Phase 8 is a pure consumer. MCP, CLI, and CI agent read from drift.db and call NAPI functions. They do NOT contain analysis logic. If you need a new analysis capability, it belongs in drift-analysis, not in a presentation package.

### MCP Progressive Disclosure
The MCP server exposes 3 entry points, not ~52 individual tools. This reduces token overhead ~81% for AI agents:
1. `drift_status` — overview from `materialized_status` view, <1ms
2. `drift_context` — deep dive, intent-weighted, replaces 3-5 individual calls
3. `drift_scan` — trigger analysis

The ~49 remaining tools are accessible via `drift_tool` dynamic dispatch — the AI agent asks for a specific tool by name, and the server routes to the correct internal handler. This keeps the initial tool list small while preserving full access.

### MCP Transport: stdio Primary, HTTP Secondary
stdio transport is the primary interface (how most MCP clients connect). Streamable HTTP transport is for Docker/containerized deployments. Both expose the same tools.

### CLI Is a Thin Wrapper
The CLI is a thin wrapper around NAPI calls with output formatting. No novel algorithms. Each command maps to 1-2 NAPI calls, formats the result, and prints it. The `drift setup` wizard is the most complex command (interactive first-time configuration).

### CI Agent: 9 Parallel Passes
The CI agent runs 9 analysis passes in parallel: scan, patterns, call graph, boundaries, security, tests, errors, contracts, constraints. PR-level incremental means only changed files + transitive dependents are analyzed. Results are uploaded as SARIF to GitHub Code Scanning and posted as PR comments.

### Remaining Reporters Are Rust
The 4-5 additional reporter formats (GitHub Code Quality, GitLab Code Quality, JUnit XML, HTML, SonarQube) are Rust code in `drift-analysis/src/enforcement/reporters/`. They follow the same `Reporter` trait pattern established in Phase 6 for SARIF/JSON/console.

## EXECUTION RULES

### R1: Three Parallel Tracks + Reporters
Phase 8 has 3 fully independent TypeScript tracks plus a Rust reporter track:
- **Track A**: MCP Server (8A) — `packages/drift-mcp/`
- **Track B**: CLI (8B) — `packages/drift-cli/`
- **Track C**: CI Agent (8C) — `packages/drift-ci/`
- **Track D**: Remaining Reporters (8D) — `drift-analysis/src/enforcement/reporters/`

All 4 tracks can proceed in parallel. No dependencies between them.

### R2: Every Task Gets Real Code
When the task says "Create `packages/drift-mcp/src/tools/drift_status.ts` — `drift_status` tool: overview, reads `materialized_status`, <1ms," you write a real MCP tool handler that calls the NAPI `drift_status()` binding, formats the response per MCP protocol, and returns it. Not a stub.

### R3: Tests After Each System
After implementing each system, implement the corresponding test tasks immediately. The cycle is: implement system → write tests → verify tests pass → move to next system.

### R4: Build After Every System
After completing each TypeScript package, run the package's build and test commands. After completing the Rust reporters, run `cargo build --workspace` and `cargo clippy --workspace`. Fix any warnings or errors before proceeding.

### R5: MCP Protocol Compliance
The MCP server must comply with the MCP specification. Use the official MCP SDK for TypeScript. Tool definitions must include proper JSON Schema for parameters. Error responses must use standard JSON-RPC error codes.

### R6: Respect Performance Targets
- `drift_status`: <1ms (reads materialized view, not full query)
- `drift_context`: <100ms (token-budgeted)
- CI agent: 9 passes in parallel, not sequential
- Reporter output for 50K violations: <30s

### R7: Check Boxes As You Go
After completing each task, mark it `[x]` in `docs/v2-research/DRIFT-V2-IMPLEMENTATION-TASKS.md`.

### R8: Output Format Validation
Every reporter format must produce output that validates against its respective schema. SARIF against SARIF 2.1.0 schema. JUnit against JUnit XML schema. GitHub/GitLab Code Quality against their documented formats. HTML must be self-contained (no external dependencies).

## PHASE 8 STRUCTURE YOU'RE CREATING

### 8A — MCP Server (`packages/drift-mcp/`)
```
packages/drift-mcp/
├── package.json                        ← MCP server package config
├── tsconfig.json                       ← TypeScript config
├── src/
│   ├── index.ts                        ← Entry point
│   ├── server.ts                       ← MCP server setup, stdio + HTTP transport
│   ├── tools/
│   │   ├── index.ts                    ← Tool registration
│   │   ├── drift_status.ts             ← drift_status: overview, materialized_status, <1ms
│   │   ├── drift_context.ts            ← drift_context: deep dive, intent-weighted
│   │   ├── drift_scan.ts               ← drift_scan: trigger analysis
│   │   └── drift_tool.ts              ← Dynamic dispatch for ~49 internal tools
│   └── transport/
│       ├── index.ts                    ← Transport exports
│       ├── stdio.ts                    ← stdio transport (primary)
│       └── http.ts                     ← Streamable HTTP transport (Docker/containerized)
```

**Key components:**
- `McpServer` — main server class, registers tools, handles JSON-RPC protocol
- `drift_status` — reads `materialized_status` view via NAPI, returns overview in <1ms
- `drift_context` — calls NAPI `drift_context()` with intent + depth, returns token-budgeted output
- `drift_scan` — calls NAPI `drift_scan()`, returns analysis results
- `drift_tool` — dynamic dispatch: receives tool name as parameter, routes to correct NAPI function. This is how ~49 internal tools are exposed without bloating the initial tool list
- Progressive disclosure: AI agent sees 3-4 tools initially, discovers more via `drift_tool`
- Token budgeting via `McpConfig.max_response_tokens` (default 8000)

### 8B — CLI (`packages/drift-cli/`)
```
packages/drift-cli/
├── package.json                        ← CLI package config
├── tsconfig.json                       ← TypeScript config
├── src/
│   ├── index.ts                        ← CLI entry point
│   ├── commands/
│   │   ├── index.ts                    ← Command registration
│   │   ├── scan.ts                     ← drift scan
│   │   ├── check.ts                    ← drift check
│   │   ├── status.ts                   ← drift status
│   │   ├── patterns.ts                 ← drift patterns
│   │   ├── violations.ts               ← drift violations
│   │   ├── impact.ts                   ← drift impact
│   │   ├── simulate.ts                 ← drift simulate
│   │   ├── audit.ts                    ← drift audit
│   │   ├── setup.ts                    ← drift setup (first-time wizard)
│   │   ├── doctor.ts                   ← drift doctor (health checks)
│   │   ├── export.ts                   ← drift export
│   │   ├── explain.ts                  ← drift explain
│   │   └── fix.ts                      ← drift fix
│   └── output/
│       ├── index.ts                    ← Output format registration
│       ├── table.ts                    ← Table output format
│       ├── json.ts                     ← JSON output format
│       └── sarif.ts                    ← SARIF output format
```

**Key components:**
- Each command is a thin wrapper: parse args → call NAPI → format output → print
- `drift setup` — interactive first-time wizard: creates `drift.toml` with sensible defaults, initializes `drift.db`
- `drift doctor` — health checks: verifies `drift.toml` exists, schema version is current, `drift.db` is not corrupt
- `drift explain <violation-id>` — human-readable explanation with remediation steps
- `drift export --format <format>` — export violations in any supported format
- Output formats: table (human-readable, default), JSON (machine-readable), SARIF (CI integration)
- `--quiet` flag suppresses all output except errors and exit code
- Exit codes: 0 = clean, 1 = violations found, 2 = error

### 8C — CI Agent & GitHub Action (`packages/drift-ci/`)
```
packages/drift-ci/
├── package.json                        ← CI agent package config
├── tsconfig.json                       ← TypeScript config
├── action.yml                          ← GitHub Action definition
├── src/
│   ├── index.ts                        ← Entry point
│   ├── agent.ts                        ← 9 parallel analysis passes
│   ├── pr_comment.ts                   ← PR comment generation
│   └── sarif_upload.ts                 ← SARIF upload to GitHub Code Scanning
```

**Key components:**
- `CiAgent` — orchestrates 9 parallel analysis passes: scan, patterns, call graph, boundaries, security, tests, errors, contracts, constraints
- PR-level incremental: only analyzes files changed in PR + transitive dependents (via impact analysis)
- `PrCommentGenerator` — produces readable summaries with violation counts, severity breakdown, trend indicators (↑↓→)
- `SarifUploader` — uploads SARIF to GitHub Code Scanning API with proper authentication headers
- `action.yml` — GitHub Action definition with inputs (path, policy, fail-on) and outputs (violations, status, sarif-path)
- Timeout handling: analysis exceeding configured timeout → partial results reported, not hang
- Empty PR diff → "no changes to analyze" message, fast exit

### 8D — Remaining Reporters (`drift-analysis/src/enforcement/reporters/`)
```
drift-analysis/src/enforcement/reporters/
├── github.rs                           ← GitHub Code Quality reporter
├── gitlab.rs                           ← GitLab Code Quality reporter
├── junit.rs                            ← JUnit XML reporter
├── html.rs                             ← HTML reporter (self-contained)
└── sonarqube.rs                        ← SonarQube Generic Issue Format (P2, post-launch — deferred but tracked)
```

**Key details:**
- All reporters implement the same `Reporter` trait established in Phase 6
- GitHub Code Quality: JSON format per GitHub's documented schema
- GitLab Code Quality: JSON format per GitLab's Code Quality report schema
- JUnit XML: standard JUnit XML schema, parseable by Jenkins/GitHub Actions/other CI
- HTML: self-contained (inline CSS/JS, no external dependencies), renders violation list with severity, location, quick fix suggestions
- SonarQube: Generic Issue Format — marked P2 (post-launch) but tracked for completeness
- All reporters must handle: 0 violations (valid empty output), Unicode content (CJK paths, emoji), 50K violations (<30s, reasonable file size)

## KEY TYPES AND INTERFACES

### MCP Server (TypeScript)
```typescript
// MCP tool definition
interface McpTool {
  name: string;
  description: string;
  inputSchema: JsonSchema;
  handler: (params: Record<string, unknown>) => Promise<McpToolResult>;
}

// Progressive disclosure entry points
const ENTRY_TOOLS: McpTool[] = [
  { name: 'drift_status', description: 'Get project overview', ... },
  { name: 'drift_context', description: 'Get intent-weighted context', ... },
  { name: 'drift_scan', description: 'Trigger analysis', ... },
  { name: 'drift_tool', description: 'Access specific analysis tool', ... },
];

// Dynamic dispatch
interface DriftToolParams {
  tool: string;        // internal tool name (e.g., "reachability", "taint", "impact")
  params: unknown;     // tool-specific parameters
}

// MCP config
interface McpConfig {
  max_response_tokens: number;  // default 8000
  transport: 'stdio' | 'http';
  port?: number;                // for HTTP transport
}
```

### CLI (TypeScript)
```typescript
// Command interface
interface CliCommand {
  name: string;
  description: string;
  options: CliOption[];
  action: (args: ParsedArgs) => Promise<number>;  // returns exit code
}

// Output formatter
interface OutputFormatter {
  format: 'table' | 'json' | 'sarif';
  render(data: unknown): string;
}

// Setup wizard config output
interface DriftToml {
  version: string;
  scan: { include: string[]; exclude: string[] };
  policy: 'strict' | 'standard' | 'lenient';
  gates: Record<string, GateConfig>;
  reporters: string[];
}
```

### CI Agent (TypeScript)
```typescript
// Analysis pass
interface AnalysisPass {
  name: string;
  run: (files: string[]) => Promise<PassResult>;
}

// 9 parallel passes
const PASSES: AnalysisPass[] = [
  { name: 'scan', run: runScan },
  { name: 'patterns', run: runPatterns },
  { name: 'call_graph', run: runCallGraph },
  { name: 'boundaries', run: runBoundaries },
  { name: 'security', run: runSecurity },
  { name: 'tests', run: runTests },
  { name: 'errors', run: runErrors },
  { name: 'contracts', run: runContracts },
  { name: 'constraints', run: runConstraints },
];

// PR comment
interface PrComment {
  summary: string;
  violation_count: number;
  severity_breakdown: Record<string, number>;
  trend: '↑' | '↓' | '→';
  details: string;
}

// GitHub Action inputs
interface ActionInputs {
  path: string;
  policy: 'strict' | 'standard' | 'lenient';
  fail_on: 'error' | 'warning' | 'none';
  sarif_upload: boolean;
  pr_comment: boolean;
}
```

### Reporters (Rust)
```rust
// Reporter trait (established in Phase 6 — implement it for new formats)
pub trait Reporter: Send + Sync {
    fn name(&self) -> &str;
    fn generate(&self, violations: &[Violation], gates: &[GateResult]) -> Result<String, ReportError>;
}

// GitHub Code Quality format
pub struct GitHubCodeQualityReporter;

// GitLab Code Quality format
pub struct GitLabCodeQualityReporter;

// JUnit XML format
pub struct JUnitReporter;

// HTML format (self-contained)
pub struct HtmlReporter;

// SonarQube Generic Issue Format (P2)
pub struct SonarQubeReporter;
```

## QUALITY GATE (QG-8) — ALL MUST PASS BEFORE YOU'RE DONE

```
- [ ] MCP server registers all drift-analysis tools via stdio transport
- [ ] drift_status returns overview in <1ms
- [ ] drift_context produces intent-weighted context with token budgeting
- [ ] CLI drift scan + drift check work end-to-end
- [ ] CI agent runs 9 analysis passes on a PR diff
- [ ] SARIF upload to GitHub Code Scanning succeeds
- [ ] PR comment generation produces readable summaries
- [ ] All 8 reporter formats produce valid output
```

## HOW TO START

1. Read `docs/v2-research/DRIFT-V2-IMPLEMENTATION-TASKS.md` — Phase 8 section (tasks P8-MCP-01 through P8-RPT-05, tests T8-MCP-01 through T8-INT-04)
2. Read the two V2-PREP documents listed above for behavioral details:
   - `docs/v2-research/systems/32-MCP-SERVER-V2-PREP.md`
   - `docs/v2-research/systems/34-CI-AGENT-GITHUB-ACTION-V2-PREP.md`
3. Read `docs/v2-research/DRIFT-V2-IMPLEMENTATION-ORCHESTRATION.md` §11 for Phase 8 rationale
4. Review the existing NAPI bindings to understand what functions are available:
   - `crates/drift/drift-napi/src/bindings/` — all binding files
5. Review the existing reporter implementations for the `Reporter` trait pattern:
   - `crates/drift/drift-analysis/src/enforcement/reporters/` — SARIF, JSON, console
6. Start with Track D (8D — Rust reporters) since it's small and independent
7. Then set up the 3 TS packages in parallel:
   - **Track A**: MCP Server (8A: P8-MCP-01 → P8-MCP-12)
   - **Track B**: CLI (8B: P8-CLI-01 → P8-CLI-21)
   - **Track C**: CI Agent (8C: P8-CI-01 → P8-CI-07)
8. After each system: implement tests → verify → move to next
9. Run QG-8 checks. Fix anything that fails. Mark all boxes.

## WHAT SUCCESS LOOKS LIKE

When you're done:
- `packages/drift-mcp/` — MCP server with 3 progressive disclosure entry points (`drift_status` <1ms, `drift_context` intent-weighted, `drift_scan`), ~49 internal tools via `drift_tool` dynamic dispatch (~81% token overhead reduction), stdio + Streamable HTTP transport, MCP protocol compliant
- `packages/drift-cli/` — CLI with 13 commands (`scan`, `check`, `status`, `patterns`, `violations`, `impact`, `simulate`, `audit`, `setup`, `doctor`, `export`, `explain`, `fix`), 3 output formats (table, JSON, SARIF), `--quiet` flag, proper exit codes, `drift setup` wizard, `drift doctor` health checks
- `packages/drift-ci/` — CI agent with 9 parallel analysis passes, PR-level incremental analysis, SARIF upload to GitHub Code Scanning, PR comment generation with severity breakdown and trend indicators, `action.yml` GitHub Action definition, timeout handling
- `drift-analysis/src/enforcement/reporters/github.rs` — GitHub Code Quality format
- `drift-analysis/src/enforcement/reporters/gitlab.rs` — GitLab Code Quality format
- `drift-analysis/src/enforcement/reporters/junit.rs` — JUnit XML format
- `drift-analysis/src/enforcement/reporters/html.rs` — self-contained HTML report
- `drift-analysis/src/enforcement/reporters/sonarqube.rs` — SonarQube Generic Issue Format (P2, tracked)
- All 35 Phase 8 test tasks pass
- All 49 Phase 8 implementation tasks are checked off
- QG-8 passes (all 8 criteria — Milestone 6: "It Ships")
- The codebase is ready for a Phase 9 agent to build the Cortex-Drift bridge and grounding loop
