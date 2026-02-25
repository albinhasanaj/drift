# 10 CLI — Research Recap

## Executive Summary

The CLI (`packages/cli/`) is Drift's primary user-facing interface — a 100% TypeScript presentation layer comprising ~50 command files, ~5 services, ~10 UI/reporter modules, and a comprehensive setup wizard. It provides 50+ commands for scanning codebases, managing patterns, running analysis, enforcing quality gates, managing the Cortex memory system, and orchestrating multi-project workflows. The CLI is architecturally a thin wrapper: all heavy computation is delegated to `driftdetect-core`, `driftdetect-detectors`, and Rust NAPI bindings. The v2 strategy keeps the CLI in TypeScript (presentation layer) while dramatically thinning the services layer as Rust absorbs scanning, detection, and analysis. The key migration boundary is `ScannerService` → Rust NAPI, where today's worker-thread parallelism (Piscina) is replaced entirely by Rust's native Rayon-based parallelism.

---

## Current Implementation

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    bin/drift.ts                                  │
│  (Commander.js program — registers all 50+ commands)            │
├──────────┬──────────┬──────────┬────────────────────────────────┤
│  Core    │ Analysis │ Language │  Infrastructure                 │
│ Commands │ Commands │ Commands │  Commands                       │
│ (scan,   │ (call-   │ (ts, py,│  (projects, backup,             │
│  check,  │  graph,  │  java,  │   setup, memory,                │
│  approve)│  env,    │  go...) │   gate, telemetry)              │
│          │  dna...) │         │                                  │
├──────────┴──────────┴──────────┴────────────────────────────────┤
│                    Services Layer                                │
│  ScannerService │ PatternServiceFactory │ BackupService          │
│  BoundaryScanner│ ContractScanner                                │
├─────────────────────────────────────────────────────────────────┤
│                    UI Layer                                      │
│  Spinner │ Table │ Prompts │ Progress │ ProjectIndicator         │
├─────────────────────────────────────────────────────────────────┤
│                    Reporters                                     │
│  Text │ JSON │ GitHub │ GitLab │ SARIF                           │
├─────────────────────────────────────────────────────────────────┤
│                    Workers                                       │
│  detector-worker.ts (Piscina thread pool)                       │
├─────────────────────────────────────────────────────────────────┤
│                    Git Integration                               │
│  staged-files.ts │ hooks.ts (pre-commit, pre-push)              │
├─────────────────────────────────────────────────────────────────┤
│                    Core / Detectors / Native                     │
│  driftdetect-core │ driftdetect-detectors │ Rust NAPI           │
└─────────────────────────────────────────────────────────────────┘
```

### Component Inventory

| Component | Location | Files (est.) | Lines (est.) | Purpose |
|-----------|----------|-------------|-------------|---------|
| Entry Point | `src/bin/drift.ts` | 1 | ~200 | Commander.js program, command registration |
| Commands | `src/commands/` | 48 + 2 subdirs | ~12,000 | All 50+ CLI commands |
| Commands/Setup | `src/commands/setup/` | 15 | ~3,000 | 8-phase setup wizard with 13 runners |
| Commands/DNA | `src/commands/dna/` | 7 | ~1,200 | DNA subcommands |
| Memory Command | `src/commands/memory.ts` | 1 | ~2,800 | 20+ memory subcommands (largest single file) |
| Services | `src/services/` | 5 | ~2,500 | ScannerService (~1,400 LOC), PatternServiceFactory, BoundaryScanner, ContractScanner, BackupService |
| Reporters | `src/reporters/` | 6 | ~800 | Text, JSON, GitHub, GitLab reporters + types |
| UI | `src/ui/` | 6 | ~1,200 | Spinner, Table, Prompts, Progress, ProjectIndicator |
| Git | `src/git/` | 3 | ~400 | Staged files, hooks (pre-commit, pre-push) |
| Workers | `src/workers/` | 1 | ~200 | Piscina detector worker |
| Types | `src/types/` | 1 | ~50 | CLIOptions, CheckResult |
| Tests | co-located | 4 | ~500 | Property-based (check), integration (cli), git, UI |
| **Total** | | **~98** | **~22,850** | |

---

## Subsystem Deep Dives

### 1. Command System (48 commands + 2 subdirectories)

**Framework**: Commander.js with `program.addCommand()` registration pattern.

**Command Categories**:

| Category | Commands | Purpose |
|----------|----------|---------|
| Core Workflow | init, scan, check, status, approve, ignore, watch | Primary scan/check/approve lifecycle |
| Reporting & Export | report, export, trends, dashboard | Output generation and visualization |
| Analysis | callgraph, boundaries, env, constants, coupling, error-handling, test-topology, constraints, wrappers, simulate | Deep analysis subsystems |
| DNA | dna (scan, status, gene, mutations, playbook, export) | Styling DNA analysis |
| Memory | memory (20+ subcommands), memory-setup | Cortex memory management |
| Language-Specific | ts, py, java, php, go, rust, cpp, wpf | Per-language analysis |
| Project Management | projects (list, switch, add, remove, info, cleanup, rename) | Multi-project workflows |
| Quality Gates | gate | CI/CD enforcement |
| Infrastructure | setup, backup, migrate-storage, import, skills, parser, license, telemetry, audit, next-steps, troubleshoot, where, files, decisions, context | Tooling and maintenance |

**Command Lifecycle**:
```
User types "drift scan --incremental"
  → Commander.js parses args
  → scanCommand.action(options) called
  → Resolves project root (walk up from cwd looking for .drift/)
  → Creates ScannerService (loads detectors, optionally spawns worker pool)
  → FileWalker discovers source files (respects ignore patterns)
  → ScannerService.scanFiles() runs detectors against each file
  → Patterns aggregated, deduplicated, scored
  → PatternStore persists results (auto-detects SQLite vs JSON)
  → Data lake views materialized
  → History snapshot created
  → Telemetry recorded (if enabled)
  → Results displayed via UI components (spinner, table)
```

**Global Options**: `--verbose`, `--no-color`, `-v/--version`

**Output Format Convention**: Every command supports `--format json` for machine consumption. The `--ci` flag auto-selects JSON format and disables interactive prompts.

### 2. ScannerService (~1,400 LOC — Largest Service)

**Location**: `src/services/scanner-service.ts`

**Purpose**: Orchestrates the entire scan pipeline — the primary migration target for v2.

**Key Types**:
```typescript
interface ScannerServiceConfig {
  rootDir: string;
  verbose?: boolean;
  useWorkerThreads?: boolean;
  workerCount?: number;
  categories?: string[];
  generateManifest?: boolean;
  incremental?: boolean;
}

interface ScanResults {
  patterns: AggregatedPattern[];
  violations: AggregatedViolation[];
  filesScanned: number;
  duration: number;
  detectorResults: Map<string, FileScanResult>;
}
```

**Lifecycle**:
1. `constructor(config)` — stores config
2. `initialize()` — loads detectors from driftdetect-detectors, optionally creates Piscina worker pool
3. `scanFiles(files, projectContext)` — runs scan (worker or single-threaded)
4. `destroy()` — shuts down worker pool

**Worker Thread Mode** (Piscina):
- Creates thread pool with `detector-worker.ts` as worker script
- Sends warmup task to each worker (loads detectors once per thread)
- Distributes files across workers via `pool.run(task)`
- Aggregates results from all workers via `aggregateWorkerResults()`

**Single-Threaded Mode** (default for small codebases):
- Iterates files sequentially
- For each file: reads content, determines language, filters applicable detectors
- Runs each detector's `detect()` method
- Aggregates patterns with location deduplication

**Location Deduplication**: Two strategies:
- `locationKey(loc)` — `"file:line:column"` for standard locations
- `semanticLocationKey(loc)` — includes function/class context for semantic locations

**Health Monitoring**: `ScanHealthMonitor` tracks elapsed time, warns after 30s, enforces configurable timeout (default 300s). Progress updates every 10s for long scans.

### 3. PatternServiceFactory

**Purpose**: Store creation with auto-detection of SQLite vs JSON backend.

**Detection Logic**:
1. `.drift/drift.db` exists → SQLite (HybridPatternStore)
2. `.drift/patterns/*.json` exists → JSON (PatternStore)
3. Neither exists → default to SQLite (new projects)

**Functions**:
- `createCLIPatternServiceAsync(rootDir)` — async, auto-detects backend
- `createCLIPatternService(rootDir)` — sync, always JSON (backward compat)
- `createCLIPatternStore(rootDir)` — async, auto-detects backend
- `getCLIStorageInfo(rootDir)` — returns backend info

### 4. Reporters (Pluggable Output Formatters)

**Interface**:
```typescript
interface Reporter {
  generate(data: ReportData): string;
}

interface ReportData {
  violations: Violation[];
  summary: ViolationSummary;
  patterns: Pattern[];
  timestamp: string;
  rootDir: string;
}
```

**Implementations**:

| Reporter | Format | Use Case |
|----------|--------|----------|
| TextReporter | Colored terminal output | Human consumption, local dev |
| JsonReporter | Structured JSON | CI/CD pipelines, machine parsing |
| GitHubReporter | `::error`/`::warning` annotations | GitHub Actions PR annotations |
| GitLabReporter | Code Quality JSON | GitLab CI code quality reports |
| SarifReporter | SARIF JSON | Security tool integration (in gate.ts) |

**Selection**: `--format` flag or `--ci` auto-selects JSON.

### 5. UI Components

**Spinner** (`spinner.ts`):
- Wraps `ora` with fluent API (start/succeed/fail/warn/info/stop)
- Auto-disables in CI environments (`process.env.CI`)
- `withSpinner()` utility wraps async operations with automatic succeed/fail
- Pre-configured spinners: scanning (cyan), analyzing (blue), loading (yellow), saving (green), checking (magenta)
- Status indicators: success (✔), error (✖), warning (⚠), info (ℹ), pending (○)

**Table** (`table.ts`):
- 4 style presets: default, compact, borderless, minimal
- Pre-built factories: patterns, violations, status, categories, summary
- Color formatters: severity, confidence, count, path

**Prompts** (`prompts.ts`):
- Wraps `@inquirer/prompts` with typed helpers
- Domain-specific: pattern approval, batch approval, severity selection, variant config
- Batch approval pre-selects patterns with confidence ≥ 0.85

**Progress** (`progress.ts`): Progress bar for long-running operations.

**ProjectIndicator** (`project-indicator.ts`): Active project display for multi-project workflows.

### 6. Git Integration

**Staged Files** (`staged-files.ts`):
- `getStagedFiles()` — `git diff --cached --name-only --diff-filter=ACMR`
- `getChangedFiles()` — `git diff --name-only --diff-filter=ACMR HEAD`
- `getUntrackedFiles()` — `git ls-files --others --exclude-standard`
- `isGitRepository()` — `git rev-parse --git-dir`
- `getGitRoot()` — `git rev-parse --show-toplevel`
- All use `child_process.exec` with `promisify`
- Error handling distinguishes "git not installed" (ENOENT) vs other failures

**Git Hooks** (`hooks.ts`):
- Two hook types: `pre-commit` (runs `drift check --staged`), `pre-push` (runs `drift check`)
- Installation strategy: Husky-first (`.husky/`), fallback to `.git/hooks/`
- Conflict handling: refuses to overwrite non-Drift hooks unless `--force`
- Hooks written with `mode: 0o755` (executable)

### 7. Setup Wizard (8 Phases, 13 Runners)

**Location**: `src/commands/setup/`

**Phases**:
1. Prerequisites Check — existing patterns, category counts
2. Init — creates `.drift/` with 30+ subdirectories
3. Pattern Approval — interactive batch approval (≥85% confidence pre-selected)
4. Core Features — boundaries, contracts, environment, constants
5. Deep Analysis — callgraph, test-topology, coupling, DNA, error-handling
6. Derived Features — constraints, audit
7. Memory — Cortex initialization
8. Finalize — SQLite sync, source-of-truth generation, summary

**Resume Capability**: `SetupState` tracks phase progress for `--resume`.

**Source of Truth**: Generated at end of setup, saved to `.drift/source-of-truth.json` with baseline checksums, feature configs, and history.

**13 Runners** (each extends `BaseRunner`):
BoundariesRunner, ContractsRunner, EnvironmentRunner, ConstantsRunner, CallGraphRunner, TestTopologyRunner, CouplingRunner, DNARunner, ErrorHandlingRunner, ConstraintsRunner, AuditRunner, MemoryRunner, SqliteSyncRunner.

### 8. Decision Mining (`decisions.ts`)

Git-based architectural decision mining — analyzes commit history to extract implicit ADRs.

**Subcommands**: mine, status, list, show, export, confirm, for-file, timeline

**Categories**: Architecture, API, security, performance, testing, infrastructure, dependency, naming, error-handling — each with distinct icons.

**Evidence Types**: Commit messages, code changes, config changes, dependency updates.

### 9. Memory Command (~2,800 LOC — Largest Single File)

20+ subcommands for Cortex memory management: init, status, add, list, show, search, update, delete, learn, feedback, validate, consolidate, warnings, why, export, import, health.

Uses `getCortex()` helper that dynamically imports `driftdetect-cortex` and creates a `CortexV2` instance.

---

## Key Data Models

### CLI-Specific Types

```typescript
// Common CLI options
interface CLIOptions {
  verbose?: boolean;
  format?: 'text' | 'json' | 'github' | 'gitlab';
  ci?: boolean;
  staged?: boolean;
}

// Check command result
interface CheckResult {
  violationCount: number;
  errorCount: number;
  warningCount: number;
  exitCode: number;  // 0 = pass, 1 = violations above threshold
}

// Scanner service config
interface ScannerServiceConfig {
  rootDir: string;
  verbose?: boolean;
  useWorkerThreads?: boolean;
  workerCount?: number;
  categories?: string[];
  generateManifest?: boolean;
  incremental?: boolean;
}

// Scan results
interface ScanResults {
  patterns: AggregatedPattern[];
  violations: AggregatedViolation[];
  filesScanned: number;
  duration: number;
  detectorResults: Map<string, FileScanResult>;
}

// Aggregated pattern (cross-file)
interface AggregatedPattern {
  patternId: string;
  detectorId: string;
  category: string;
  subcategory: string;
  name: string;
  description: string;
  confidence: number;
  locations: Array<{
    file: string;
    line: number;
    column: number;
    endLine?: number;
    endColumn?: number;
  }>;
  outliers: Array<{...}>;
  severity: string;
  autoFixable: boolean;
  metadata: {...};
}

// Setup wizard state
interface SetupState {
  phase: number;
  completed: string[];
  choices: SetupChoices;
  startedAt: string;
}

// Source of truth (baseline)
interface SourceOfTruth {
  version: string;
  schemaVersion: string;
  createdAt: string;
  updatedAt: string;
  project: { id, name, rootPath };
  baseline: {
    scanId: string;
    scannedAt: string;
    fileCount: number;
    patternCount: number;
    approvedCount: number;
    categories: Record<string, number>;
    checksum: string;
  };
  features: Record<string, FeatureConfig>;
  settings: { autoApproveThreshold, autoApproveEnabled };
  history: HistoryEntry[];
}

// Reporter types
interface Reporter {
  generate(data: ReportData): string;
}

interface ReportData {
  violations: Violation[];
  summary: ViolationSummary;
  patterns: Pattern[];
  timestamp: string;
  rootDir: string;
}

// Git hook types
type HookType = 'pre-commit' | 'pre-push';

interface HookInstallResult {
  success: boolean;
  hookType: HookType;
  method: 'husky' | 'git';
  message: string;
  path?: string;
}

// Worker types
interface DetectorWorkerTask {
  type: 'scan';
  file: string;
  content: string;
  language: string;
  categories?: string[];
  projectContext: ProjectContext;
}

interface DetectorWorkerResult {
  file: string;
  patterns: WorkerPatternMatch[];
  violations: WorkerViolation[];
  duration: number;
  detectorCount: number;
  error?: string;
}
```

---

## Key Algorithms

### 1. Exit Code Determination (Property-Tested)

```typescript
function getExitCode(violations: Violation[], failOn: 'error' | 'warning' | 'none'): number
```

**Severity Order**: error (4) > warning (3) > info (2) > hint (1)

**Logic**: Exit code = 1 if any violation severity ≥ threshold severity. Exit code = 0 otherwise.

**Properties Verified** (via fast-check):
1. `failOn: 'none'` → always exit 0
2. No violations → always exit 0
3. Error violations + `failOn: 'error'` → exit 1
4. Determinism — same input always produces same output
5. Binary — exit code is always 0 or 1
6. Severity ordering — higher severity always triggers if lower does
7. Monotonicity — adding violations never decreases exit code

### 2. Pattern Store Auto-Detection

```
1. Check if .drift/drift.db exists → SQLite (HybridPatternStore)
2. Check if .drift/patterns/*.json exists → JSON (PatternStore)
3. Neither exists → default to SQLite (new projects)
```

### 3. Worker Thread Distribution

```
1. Create Piscina pool with N workers (configurable)
2. Send warmup task to each worker (loads detectors once per thread)
3. For each file: pool.run({ type: 'scan', file, content, language, categories })
4. Workers filter applicable detectors by language, run detect()
5. Aggregate results from all workers via aggregateWorkerResults()
```

### 4. Location Deduplication

Two strategies:
- `locationKey(loc)` → `"file:line:column"` — standard dedup
- `semanticLocationKey(loc)` → includes function/class context — semantic dedup
- `addUniqueLocation()` checks existing keys before adding

### 5. Scan Health Monitoring

```
ScanHealthMonitor:
  - Tracks elapsed time from scan start
  - Warns after 30 seconds (configurable)
  - Enforces timeout at 300 seconds (configurable)
  - Progress updates every 10 seconds for long scans
```

### 6. Setup Wizard Phase Execution

```
For each phase (1-8):
  1. Print phase header
  2. Check if already completed (resume support)
  3. Execute phase logic (may prompt user in interactive mode)
  4. Record completion in SetupState
  5. Persist state for resume capability
```

---

## Dependencies

| Package | Purpose | Version Concern |
|---------|---------|-----------------|
| `commander` | Command framework | Stable, well-maintained |
| `chalk` | Terminal colors | v5 is ESM-only |
| `ora` | Spinners | v6+ is ESM-only |
| `cli-table3` | Table formatting | Stable |
| `@inquirer/prompts` | Interactive prompts | Modern replacement for inquirer |
| `piscina` | Worker thread pool | Will be eliminated in v2 |
| `driftdetect-core` | Core analysis engine | Internal dependency |
| `driftdetect-detectors` | Pattern detectors | Internal dependency |
| Rust NAPI bindings | Native performance | Internal dependency |

---

## Capabilities

### What It Can Do Today

1. **50+ Commands**: Comprehensive CLI covering scan, check, approve, analysis, memory, projects, gates, and more
2. **Pluggable Reporters**: Text, JSON, GitHub, GitLab, SARIF output formats
3. **Interactive Setup Wizard**: 8-phase guided onboarding with resume capability
4. **Multi-Project Management**: Register, switch, scan across multiple projects
5. **Worker Thread Parallelism**: Piscina-based parallel detection for large codebases
6. **Git Integration**: Staged file detection, pre-commit/pre-push hooks, Husky support
7. **CI/CD Ready**: `--ci` flag, `--format json`, exit code contracts, SARIF output
8. **Quality Gates**: Policy-based enforcement with multiple reporter formats
9. **Decision Mining**: Git-based architectural decision extraction
10. **Memory Management**: 20+ subcommands for Cortex memory CRUD
11. **Source of Truth**: Baseline generation with checksums and feature configs
12. **Watch Mode**: Real-time file watching with debounced pattern detection

### Limitations

1. **memory.ts is 2,800 lines**: Monolithic file that should be split into subcommand files (like `dna/`)
2. **No structured error handling**: Commands use ad-hoc try/catch with string messages; no unified error taxonomy
3. **No progress streaming**: Long scans show spinner but no granular progress (files scanned, patterns found)
4. **No command composition**: Cannot pipe commands or compose workflows programmatically
5. **No shell completion**: No bash/zsh/fish completion scripts
6. **No config file for CLI preferences**: No `.driftrc` or similar for default flags
7. **No dry-run for all commands**: Only some commands support `--dry-run`
8. **Worker threads are TS-only**: Piscina parallelism doesn't leverage Rust; will be eliminated
9. **No telemetry dashboard**: Telemetry is recorded but not visualized in CLI
10. **No offline mode**: Commands that need network (telemetry, license) don't gracefully degrade
11. **Limited test coverage**: Only 4 test files; no tests for ScannerService, reporters, setup wizard, or worker threads
12. **No internationalization**: All output is English-only
13. **No plugin system**: Cannot extend CLI with custom commands
14. **Reporter interface is string-only**: `generate()` returns string, not structured data; limits composability
15. **Setup wizard is all-or-nothing**: Cannot run individual phases independently after initial setup
16. **No machine-readable error codes**: Errors are human-readable strings, not structured codes for CI parsing

---

## Integration Points

| Connects To | Direction | How |
|-------------|-----------|-----|
| **01-rust-core** | Consumes | NAPI bindings for native scan, call graph, analysis |
| **02-parsers** | Consumes (indirect) | Via core/detectors for file parsing |
| **03-detectors** | Consumes | Loads detectors via driftdetect-detectors package |
| **04-call-graph** | Consumes | callgraph command delegates to core call graph builder |
| **05-analyzers** | Consumes | Analysis commands delegate to core analyzers |
| **06-cortex** | Consumes | Memory commands use CortexV2 via dynamic import |
| **07-mcp** | Parallel | Both consume core; MCP is the AI-facing interface, CLI is the human-facing interface |
| **08-storage** | Consumes | PatternServiceFactory creates stores; commands read/write .drift/ |
| **09-quality-gates** | Consumes | gate command uses GateOrchestrator from core |
| **11-ide** | Parallel | IDE uses LSP; CLI is the terminal interface |
| **12-infrastructure** | Consumed by | CI/CD pipelines invoke CLI commands |
| **13-advanced** | Consumes | DNA, simulation, decision mining commands |
| **23-pattern-repository** | Consumes | Pattern CRUD via PatternServiceFactory |
| **24-data-lake** | Consumes | Scan materializes data lake views |
| **25-services-layer** | Consumes | ScannerService orchestrates scan pipeline |
| **26-workspace** | Consumes | Project management, backup, migration |

### Critical Downstream Dependencies

The CLI is a **terminal consumer** — it depends on nearly everything but nothing depends on it except:
- **Users** (human developers)
- **CI/CD pipelines** (automated workflows)
- **Git hooks** (pre-commit, pre-push)

This makes the CLI the safest layer to evolve — changes here don't break other subsystems.

---

## V2 Migration Status

### What Stays in TypeScript (Presentation Layer)

| Component | Rationale |
|-----------|-----------|
| All 50+ commands | Commander.js, arg parsing, output formatting are presentation concerns |
| Reporters (Text, JSON, GitHub, GitLab, SARIF) | Output formatting is presentation-layer |
| UI components (spinner, table, prompts, progress) | Terminal interaction is presentation-layer |
| Git integration | Shells out to `git` CLI, no performance concern |
| Setup wizard | Interactive UI orchestration |
| Memory commands | Cortex orchestration |
| Project management | Filesystem operations |

### What Thins Out

| Component | Current | V2 |
|-----------|---------|-----|
| ScannerService | ~1,400 LOC, loads TS detectors, manages Piscina workers | Thin wrapper around `nativeScan()` NAPI call |
| Worker threads (Piscina) | Parallel detection via thread pool | Eliminated — Rust handles parallelism via Rayon |
| PatternServiceFactory | Auto-detects SQLite vs JSON, creates TS stores | Wraps Rust NAPI storage calls |
| BoundaryScanner | CLI progress wrapper around TS boundary analysis | Thin wrapper around Rust boundary analysis |
| ContractScanner | CLI progress wrapper around TS contract analysis | Thin wrapper around Rust contract analysis |

### Key Migration Boundary

```
CLI (TypeScript) ──→ ScannerService ──→ nativeScan() (Rust NAPI)
                                         ├── File walking (walkdir + rayon)
                                         ├── Parsing (tree-sitter)
                                         ├── Detection (visitor pattern)
                                         ├── Aggregation
                                         └── Storage (SQLite)
                                         
Returns: ScanResults { patterns, violations, filesScanned, duration }
```

Post-migration, the CLI's ScannerService becomes ~100 lines: parse args → call Rust → format output.

---

## Testing

### Current Test Coverage

| Test File | Framework | What It Tests |
|-----------|-----------|---------------|
| `commands/check.test.ts` | vitest + fast-check | Property-based tests for exit code consistency (10 properties) |
| `commands/cli.test.ts` | vitest | CLI integration tests |
| `git/git.test.ts` | vitest | Git integration functions |
| `ui/ui.test.ts` | vitest | UI component tests |

### Coverage Gaps

- No tests for ScannerService (complex orchestration)
- No tests for reporters (output formatting)
- No tests for setup wizard (interactive prompts)
- No tests for worker thread mode
- No tests for memory commands
- No tests for decision mining
- No tests for project management
- No end-to-end CLI tests (full command execution)

### Requirements Traceability

- `check.test.ts` validates exit code consistency (CI contract)
- `git.test.ts` validates staged file detection

---

## Open Questions

1. **Should language-specific commands merge?** V2 Rust handles all languages uniformly — `drift ts`, `drift py`, etc. could become `drift analyze <lang>` or even just flags on `drift scan`.
2. **Should memory.ts be split?** At 2,800 lines, it's the largest single file. The `dna/` pattern (subcommand directory) is proven.
3. **Should the CLI support plugins?** Enterprise users may want custom commands without forking.
4. **Should reporters return structured data?** Current string-only interface limits composability. A `ReportResult { data, formatted }` pattern would enable both.
5. **Should the setup wizard support partial re-runs?** Currently all-or-nothing after initial setup. Individual phase re-execution would be useful.
6. **What's the telemetry strategy for v2?** Current telemetry is opt-in but not visualized. Should v2 include a telemetry dashboard?

---

## Quality Checklist

- [x] All 9 CLI documentation files read and understood
- [x] Architecture clearly diagrammed
- [x] All subsystems inventoried with line counts
- [x] All key algorithms documented
- [x] All data models listed with field types
- [x] Limitations honestly assessed (16 items)
- [x] Integration points mapped (16 connections)
- [x] V2 migration status documented
- [x] Testing coverage and gaps identified
- [x] Open questions raised
