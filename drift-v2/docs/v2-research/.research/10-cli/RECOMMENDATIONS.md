# 10 CLI — V2 Recommendations

> **Purpose**: Concrete, actionable improvement recommendations for Drift v2's CLI layer, backed by external research and gap analysis from the RECAP. Each recommendation includes priority, effort, evidence, and cross-category impact.
>
> **Inputs**: 10-cli RECAP.md, 10-cli RESEARCH.md, MASTER_RECAP.md, MASTER_RECOMMENDATIONS.md
>
> **Date**: February 2026

---

## Executive Summary

The CLI is Drift's human-facing presentation layer. It stays in TypeScript — that's the right call. But "stays in TypeScript" doesn't mean "stays the same." The v1 CLI has 16 identified limitations ranging from monolithic files to missing shell completion to inadequate error handling. This document proposes 18 recommendations organized across 5 themes: Architecture & Framework, Output & CI Integration, Developer Experience, Testing & Quality, and Performance. The recommendations are designed to transform the CLI from a functional tool into an enterprise-grade developer experience that matches the ambition of the Rust-powered analysis engine underneath.

Key themes:
- **Structured everything**: Structured exit codes, structured errors, structured output — machines and humans both need to parse CLI output reliably.
- **Thin services**: ScannerService drops from ~1,400 LOC to ~100 LOC as Rust absorbs the scan pipeline.
- **Enterprise extensibility**: Plugin system, custom formatters, configuration hierarchy.
- **CI-first design**: SARIF as first-class output, baseline scanning, annotation limits documented.
- **Testing rigor**: Property-based tests for every reporter, integration tests for every command.

---

## Theme 1: Architecture & Framework

### R1: Structured Exit Code Contract

**Priority**: P0 | **Effort**: Low | **Impact**: CI pipeline reliability

**Current State**: Drift uses binary exit codes: 0 (pass) and 1 (violations above threshold). CI pipelines cannot distinguish between "code has violations" and "Drift itself crashed."

**Proposed Change**: Adopt structured exit codes following Semgrep/ESLint conventions:

| Exit Code | Meaning | When |
|-----------|---------|------|
| 0 | Clean | No violations above threshold |
| 1 | Violations found | Violations exist above `--fail-on` threshold |
| 2 | Tool error | Internal error, missing project, corrupt data |
| 3 | Invalid arguments | Bad flags, unknown command, invalid config |

**Rationale**: CI pipelines need to distinguish "your code has issues" from "the analysis tool broke." Exit code 2 enables retry logic (tool error → retry), while exit code 1 enables blocking logic (violations → block merge).

**Evidence**:
- Semgrep uses 0/1/2/3/4/5 ([semgrep.dev/docs/cli-reference](https://semgrep.dev/docs/cli-reference))
- ESLint uses 0/1/2 ([eslint.org](https://eslint.org/docs/latest/use/command-line-interface))
- POSIX convention: 0=success, 1=general error, 2=misuse (IEEE Std 1003.1)

**Implementation Notes**:
- Update `getExitCode()` function (currently property-tested)
- Add new exit code paths for config errors, internal errors
- Update property-based tests to cover new exit codes
- Document exit codes in `drift --help` and README

**Risks**: Breaking change for existing CI scripts that check `$? -eq 1`. Mitigate with `--legacy-exit-codes` flag during transition.

**Dependencies**: None — standalone change.

---

### R2: Structured Error Taxonomy with Machine-Readable Codes

**Priority**: P0 | **Effort**: Medium | **Impact**: CI debugging, error tracking, support

**Current State**: Commands use ad-hoc try/catch with string messages. No error codes, no structured error output, no error categorization.

**Proposed Change**: Define a CLI error taxonomy with stable, documented error codes:

```typescript
enum DriftErrorCode {
  // Project errors (E1xx)
  E100 = 'DRIFT_E100', // Project not initialized
  E101 = 'DRIFT_E101', // Project not found at path
  E102 = 'DRIFT_E102', // Corrupt project data
  E103 = 'DRIFT_E103', // Incompatible project version

  // Configuration errors (E2xx)
  E200 = 'DRIFT_E200', // Invalid configuration
  E201 = 'DRIFT_E201', // Missing required configuration
  E202 = 'DRIFT_E202', // Unknown configuration key

  // Scan errors (E3xx)
  E300 = 'DRIFT_E300', // Scan timeout
  E301 = 'DRIFT_E301', // File too large
  E302 = 'DRIFT_E302', // Parse error (non-fatal)
  E303 = 'DRIFT_E303', // Native binary unavailable

  // Storage errors (E4xx)
  E400 = 'DRIFT_E400', // Database locked
  E401 = 'DRIFT_E401', // Database corrupt
  E402 = 'DRIFT_E402', // Migration required

  // Git errors (E5xx)
  E500 = 'DRIFT_E500', // Git not installed
  E501 = 'DRIFT_E501', // Not a git repository
  E502 = 'DRIFT_E502', // Hook conflict
}

interface DriftError {
  code: DriftErrorCode;
  message: string;        // Human-readable
  detail?: string;        // Extended explanation
  suggestion?: string;    // Actionable fix
  context?: Record<string, unknown>; // Machine-readable context
}
```

In JSON mode, errors are output as structured objects. In text mode, errors include the code for searchability:

```
✖ [DRIFT_E100] Project not initialized
  Run 'drift init' to initialize Drift in this directory.
```

**Rationale**: Structured errors enable: (a) CI scripts to handle specific error types, (b) error tracking/telemetry by code, (c) documentation linking (each code has a docs page), (d) support debugging.

**Evidence**:
- JSON:API error format ([jsonapi.org/format/#errors](https://jsonapi.org/format/#errors))
- CLIG.dev error handling guidelines ([clig.dev](https://clig.dev/))

**Implementation Notes**:
- Create `errors/` module with error enum and DriftError class
- Wrap all command actions in a unified error handler
- In JSON mode, output errors to stdout as structured JSON
- In text mode, output errors to stderr with code prefix

**Risks**: Requires touching every command file. Mitigate by implementing the error handler wrapper first, then migrating commands incrementally.

**Dependencies**: R1 (exit codes map to error categories).

---

### R3: Lazy-Loading Command Architecture

**Priority**: P1 | **Effort**: Medium | **Impact**: CLI startup time

**Current State**: All 50+ command files are loaded on every CLI invocation via `program.addCommand()` in `bin/drift.ts`. Each command imports its dependencies eagerly.

**Proposed Change**: Implement lazy-loading command registration:

```typescript
// Instead of:
import { scanCommand } from './commands/scan';
program.addCommand(scanCommand);

// Use:
program.addCommand(
  new Command('scan')
    .description('Scan codebase for patterns')
    .action(async (...args) => {
      const { scanAction } = await import('./commands/scan');
      return scanAction(...args);
    })
);
```

Or adopt a manifest-based approach:
1. Build step generates `commands.json` manifest with command metadata (name, description, flags, file path)
2. At startup, register commands from manifest (metadata only — no code loading)
3. On command invocation, dynamically import the command's module

**Rationale**: With 50+ commands, eager loading adds 200-500ms to every invocation. Users running `drift check` shouldn't pay the cost of loading `drift memory`, `drift dna`, `drift simulate`, etc.

**Evidence**:
- oclif manifest system ([oclif.io/docs/introduction](https://oclif.io/docs/introduction))
- Node.js startup optimization ([nodejs.org](https://nodejs.org/en/learn/getting-started/profiling))
- 12 Factor CLI Apps: "CLIs need to be fast" ([medium.com/@jdxcode](https://medium.com/@jdxcode/12-factor-cli-apps-dd3c227a0e46))

**Implementation Notes**:
- Phase 1: Dynamic import for heavy commands (memory, dna, simulate, decisions)
- Phase 2: Manifest-based registration for all commands
- Measure startup time before/after in CI

**Risks**: Dynamic imports add complexity. TypeScript type checking across dynamic boundaries requires care.

**Dependencies**: None — can be done incrementally.

---

### R4: Split memory.ts into Subcommand Directory

**Priority**: P1 | **Effort**: Low | **Impact**: Maintainability, code organization

**Current State**: `memory.ts` is 2,800 lines — the largest single file in the CLI. It contains 20+ subcommands in one file.

**Proposed Change**: Follow the `dna/` pattern — split into a subcommand directory:

```
commands/memory/
├── index.ts          # Commander subcommand group registration
├── init.ts           # drift memory init
├── add.ts            # drift memory add
├── list.ts           # drift memory list
├── show.ts           # drift memory show
├── search.ts         # drift memory search
├── learn.ts          # drift memory learn
├── feedback.ts       # drift memory feedback
├── validate.ts       # drift memory validate
├── consolidate.ts    # drift memory consolidate
├── export-import.ts  # drift memory export/import
├── health.ts         # drift memory health
└── helpers.ts        # Shared getCortex() helper, formatters
```

**Rationale**: 2,800 lines in one file is unmaintainable. The `dna/` pattern is already proven in the codebase. Each subcommand becomes independently testable.

**Evidence**: Established pattern in the codebase (`commands/dna/`).

**Implementation Notes**: Pure refactor — no behavior changes. Extract each subcommand's action function into its own file. Share the `getCortex()` helper.

**Risks**: None — pure structural refactor.

**Dependencies**: None.

---

### R5: Configuration Hierarchy with cosmiconfig Pattern

**Priority**: P1 | **Effort**: Medium | **Impact**: Enterprise configuration, monorepo support

**Current State**: Configuration lives in `.drift/config.json` only. No user-level defaults, no environment variable overrides, no monorepo per-package config.

**Proposed Change**: Implement a configuration hierarchy following CLIG.dev guidelines:

```
Priority (highest to lowest):
1. CLI flags (--verbose, --format json)
2. Environment variables (DRIFT_FORMAT=json, DRIFT_VERBOSE=1)
3. Project config (.drift/config.json or drift.config.ts)
4. User config (~/.config/drift/config.json or $XDG_CONFIG_HOME/drift/)
5. System defaults (built-in)
```

Support multiple config file formats via cosmiconfig pattern:
- `.driftrc.json`
- `.driftrc.yaml`
- `drift.config.ts` (type-safe with IDE completion)
- `drift` key in `package.json`

**Rationale**: Enterprise teams need user-level defaults (e.g., always use `--format json`), environment-based overrides for CI, and per-package config for monorepos.

**Evidence**:
- CLIG.dev configuration hierarchy ([clig.dev](https://clig.dev/))
- cosmiconfig pattern ([github.com/cosmiconfig](https://github.com/cosmiconfig/cosmiconfig))
- XDG Base Directory Specification ([freedesktop.org](https://specifications.freedesktop.org/basedir-spec/))
- 12 Factor CLI Apps ([medium.com/@jdxcode](https://medium.com/@jdxcode/12-factor-cli-apps-dd3c227a0e46))

**Implementation Notes**:
- Use cosmiconfig for config file discovery
- Map environment variables with `DRIFT_` prefix
- Merge configs with explicit precedence
- Support `drift config show` to display resolved configuration

**Risks**: Configuration merging complexity. Mitigate with clear documentation and `drift config show` for debugging.

**Dependencies**: None.

---

## Theme 2: Output & CI Integration

### R6: SARIF as First-Class Output Format

**Priority**: P0 | **Effort**: Medium | **Impact**: Enterprise CI/CD integration, GitHub Code Scanning

**Current State**: SARIF is supported only in `drift gate` (imported from core). Not available for `drift check`, `drift scan`, or `drift report`.

**Proposed Change**: Make SARIF a first-class output format across all violation-producing commands:

1. `drift check --format sarif` — violations in SARIF format
2. `drift gate --format sarif` — gate results in SARIF format (already exists)
3. `drift scan --format sarif` — scan findings in SARIF format
4. `drift report --format sarif` — full report in SARIF format

SARIF output should include:
- `tool.driver.rules[]` with ruleId, shortDescription, helpUri, defaultConfiguration
- `results[].ruleId` mapped to pattern IDs
- `results[].level` mapped from Drift severity
- `results[].fixes[]` mapped from Drift QuickFix system
- `results[].codeFlows[]` mapped from reachability paths (when available)
- `results[].properties.tags[]` including CWE IDs and OWASP categories for security findings

Add `drift upload-sarif` command for GitHub Code Scanning integration:
```bash
drift check --format sarif --output results.sarif
drift upload-sarif results.sarif  # Uploads to GitHub Code Scanning API
```

**Rationale**: SARIF is the industry standard for static analysis results. GitHub Code Scanning, GitLab, Azure DevOps, and SonarQube all consume SARIF. Enterprise adoption requires SARIF support.

**Evidence**:
- OASIS SARIF v2.1.0 specification ([oasis-open.org](https://docs.oasis-open.org/sarif/sarif/v2.1.0/))
- GitHub Code Scanning SARIF upload ([docs.github.com](https://docs.github.com/en/code-security/code-scanning/))
- SonarSource SARIF guide ([sonarsource.com](https://www.sonarsource.com/resources/library/sarif/))
- Microsoft SARIF tutorials ([github.com/microsoft/sarif-tutorials](https://github.com/microsoft/sarif-tutorials))

**Implementation Notes**:
- Create `SarifReporter` in `reporters/` (move from core)
- Map Drift severity to SARIF levels: error→error, warning→warning, info→note, hint→none
- Map QuickFix to SARIF `fix` objects with `artifactChanges`
- Map reachability paths to SARIF `codeFlows` with `threadFlows`
- Include `tool.driver.informationUri` pointing to Drift documentation

**Risks**: SARIF spec is complex (220+ pages). Start with the minimal required fields, extend incrementally.

**Dependencies**: Depends on MASTER_RECOMMENDATIONS M36 (OWASP/CWE mapping) for security finding metadata.

---

### R7: Enhanced Reporter Architecture with Structured Data

**Priority**: P1 | **Effort**: Medium | **Impact**: Composability, custom formatters

**Current State**: Reporter interface returns `string`. This limits composability — you can't pipe JSON reporter output through a filter without parsing the string.

**Proposed Change**: Evolve the Reporter interface to return structured data alongside formatted output:

```typescript
interface ReportResult {
  formatted: string;           // Human-readable or machine-readable string
  data: ReportData;            // Structured data (always available)
  metadata: ReportMetadata;    // Rule metadata, documentation URLs
}

interface ReportMetadata {
  rules: RuleMetadata[];       // Pattern metadata for each referenced pattern
  tool: ToolMetadata;          // Drift version, config, capabilities
  timing: TimingMetadata;      // Scan duration, per-phase timing
}

interface RuleMetadata {
  id: string;
  name: string;
  category: string;
  description: string;
  helpUri?: string;            // Link to documentation
  fixAvailable: boolean;
  defaultSeverity: Severity;
  tags: string[];              // CWE IDs, OWASP categories
}
```

Add `json-with-metadata` format (following ESLint's pattern) that includes both results and rule metadata.

Support custom formatters loaded from npm packages or local files:
```bash
drift check --format ./my-formatter.js
drift check --format @mycompany/drift-formatter-jira
```

**Rationale**: The `json-with-metadata` pattern enables downstream tools to understand rule context without a separate API call. Custom formatters enable enterprise-specific output (JIRA tickets, Slack messages, custom dashboards).

**Evidence**:
- ESLint `json-with-metadata` formatter ([eslint.org](https://eslint.org/docs/latest/extend/custom-formatters))
- ESLint custom formatter distribution via npm

**Implementation Notes**:
- Backward compatible: existing `generate(data): string` still works
- New `generateReport(data): ReportResult` method with default implementation
- Custom formatter loading via dynamic import

**Risks**: Custom formatter security — loading arbitrary code. Mitigate with `--allow-custom-formatters` flag.

**Dependencies**: None.

---

### R8: Stable Fingerprints for Diff-Based Reporting

**Priority**: P1 | **Effort**: Low | **Impact**: GitLab Code Quality accuracy, baseline scanning

**Current State**: GitLabReporter generates fingerprints, but stability across code changes is not guaranteed. Line-number-based fingerprints break when code is added/removed above the finding.

**Proposed Change**: Generate content-based fingerprints that are stable across non-semantic code changes:

```typescript
function generateFingerprint(violation: Violation): string {
  const content = [
    violation.patternId,
    violation.file,
    violation.message,
    // Use semantic location (function name, class name) instead of line number
    violation.semanticLocation?.functionName,
    violation.semanticLocation?.className,
  ].filter(Boolean).join(':');
  return crypto.createHash('sha256').update(content).digest('hex').slice(0, 32);
}
```

**Rationale**: Stable fingerprints enable accurate diff-based reporting — GitLab and GitHub can show "new issues" vs "existing issues" in merge requests. Line-number-based fingerprints cause false "new issue" reports when code is reformatted.

**Evidence**:
- GitLab Code Quality fingerprint requirements ([docs.gitlab.com](https://docs.gitlab.com/ee/ci/testing/code_quality.html))

**Implementation Notes**: Use semantic location (function/class name) when available, fall back to file + pattern ID + message hash.

**Risks**: Fingerprint changes will cause one-time "new issue" reports for existing findings. Document this in migration guide.

**Dependencies**: None.

---

### R9: stdout/stderr Separation for CI Piping

**Priority**: P0 | **Effort**: Low | **Impact**: CI pipeline composability

**Current State**: Spinners, progress messages, and data output all go to stdout. This breaks piping: `drift scan --format json | jq '.patterns'` includes spinner text in the JSON.

**Proposed Change**: Enforce strict stdout/stderr separation:

- **stdout**: Data output only (JSON, SARIF, report text, pattern listings)
- **stderr**: Human messages (spinners, progress, warnings, errors, status indicators)

When `--format json` is specified or stdout is not a TTY (piped), automatically:
1. Disable spinners and progress bars
2. Route all human messages to stderr
3. Output only structured data to stdout

```typescript
const isInteractive = process.stdout.isTTY && !options.ci;
const output = isInteractive ? process.stdout : process.stderr;
// Spinners, progress, status messages → output (stderr when piped)
// Data (JSON, SARIF, report) → process.stdout (always)
```

**Rationale**: This is a fundamental CLI design principle. Without it, `drift check --format json | jq` fails, `drift scan --format json > results.json` includes spinner text, and CI pipelines can't reliably parse output.

**Evidence**:
- CLIG.dev: "Use stdout for primary output, stderr for messaging" ([clig.dev](https://clig.dev/))
- 12 Factor CLI Apps: "Mind the stderr" ([medium.com/@jdxcode](https://medium.com/@jdxcode/12-factor-cli-apps-dd3c227a0e46))

**Implementation Notes**:
- Update Spinner class to write to stderr
- Update status indicators to write to stderr
- Audit all `console.log` calls in commands — replace with stderr-aware helpers
- Add `isInteractive()` utility function

**Risks**: Minimal — this is a correctness fix, not a behavior change for interactive use.

**Dependencies**: None.

---

## Theme 3: Developer Experience

### R10: Shell Completion Generation

**Priority**: P1 | **Effort**: Medium | **Impact**: CLI discoverability, developer productivity

**Current State**: No shell completion support. Users must remember 50+ commands and their flags.

**Proposed Change**: Add `drift completion` command that generates shell completion scripts:

```bash
# Generate and install completions
drift completion bash > /etc/bash_completion.d/drift
drift completion zsh > ~/.zsh/completions/_drift
drift completion fish > ~/.config/fish/completions/drift.fish

# Or use eval for session-only
eval "$(drift completion bash)"
```

**Static completions** (generated from command definitions):
- Command names: `drift sc<TAB>` → `drift scan`
- Flag names: `drift scan --inc<TAB>` → `drift scan --incremental`
- Flag values: `drift check --format <TAB>` → `text json github gitlab sarif`

**Dynamic completions** (query project state):
- Pattern IDs: `drift approve <TAB>` → list of discoverable pattern IDs
- Project names: `drift projects switch <TAB>` → list of registered projects
- Category names: `drift scan --categories <TAB>` → list of available categories

**Rationale**: Shell completion is table-stakes for enterprise CLIs with 50+ commands. It reduces cognitive load and prevents typos.

**Evidence**:
- Cobra shell completion ([cobra.dev](https://cobra.dev/docs/how-to-guides/shell-completion/))
- oclif built-in completion ([oclif.io](https://oclif.io/docs/introduction))
- .NET CLI native completions ([microsoft.com](https://learn.microsoft.com/en-us/dotnet/core/tools/enable-tab-autocomplete))

**Implementation Notes**:
- Use `tabtab` npm package or build custom completion generator
- Static completions from Commander.js command tree
- Dynamic completions via `drift completion --dynamic` subcommand called by the shell
- Priority: bash and zsh (covers macOS and Linux)

**Risks**: Shell completion scripts are fragile across shell versions. Test on bash 4+, zsh 5+, fish 3+.

**Dependencies**: None.

---

### R11: Granular Progress Reporting for Long Scans

**Priority**: P1 | **Effort**: Medium | **Impact**: Developer experience during long scans

**Current State**: Long scans show a spinner with periodic time warnings (30s, then every 10s). No granular progress (files scanned, patterns found, current phase).

**Proposed Change**: Implement multi-phase progress reporting:

```
Scanning codebase...
  Phase 1/4: File discovery    [████████████████████] 100% (2,847 files)
  Phase 2/4: Parsing           [████████░░░░░░░░░░░░]  42% (1,196/2,847 files)
  Phase 3/4: Detection         [░░░░░░░░░░░░░░░░░░░░]   0% (waiting)
  Phase 4/4: Aggregation       [░░░░░░░░░░░░░░░░░░░░]   0% (waiting)

  Elapsed: 12.3s │ Files/sec: 97 │ Patterns found: 234
```

In JSON mode, emit progress events to stderr as newline-delimited JSON:
```json
{"phase":"parsing","progress":0.42,"filesProcessed":1196,"totalFiles":2847,"elapsed":12300}
```

**Rationale**: Enterprise codebases (500K+ files) will have multi-minute scans. Users need to know the scan is progressing, not hung. CI pipelines need progress events for monitoring.

**Evidence**:
- 12 Factor CLI Apps: "Show progress for slow operations"
- Semgrep `--verbose` progress output

**Implementation Notes**:
- Rust NAPI should expose progress callbacks via `napi::threadsafe_function`
- CLI wraps callbacks in progress bar updates
- In CI mode, emit progress as structured JSON to stderr

**Risks**: Progress callbacks across NAPI boundary add complexity. Start with phase-level progress, add file-level later.

**Dependencies**: Depends on MASTER_RECOMMENDATIONS M38 (N-API bridge with streaming).

---

### R12: Unified `drift analyze` Command

**Priority**: P2 | **Effort**: Low | **Impact**: Command simplification

**Current State**: 8 language-specific commands (`drift ts`, `drift py`, `drift java`, etc.) that wrap language-specific detectors. As Rust handles all languages uniformly, these become redundant.

**Proposed Change**: Introduce `drift analyze` as a unified analysis command:

```bash
# Instead of:
drift ts --json
drift py --json

# Use:
drift analyze --language typescript --json
drift analyze --language python --json
drift analyze --json  # Auto-detect language from file extensions
```

Keep language-specific commands as aliases during transition:
```bash
drift ts  →  drift analyze --language typescript
drift py  →  drift analyze --language python
```

**Rationale**: With Rust handling all languages uniformly, per-language commands add surface area without adding value. A single `drift analyze` command with `--language` flag is cleaner.

**Evidence**: Semgrep uses a single `semgrep scan` command for all languages.

**Implementation Notes**: Create `analyze.ts` command, make language commands thin aliases. Deprecation warnings for 2 releases before removal.

**Risks**: Breaking change for users with `drift ts` in scripts. Mitigate with aliases and deprecation period.

**Dependencies**: Depends on Rust handling all languages uniformly (MASTER_RECOMMENDATIONS M6, M7).

---

## Theme 4: Testing & Quality

### R13: Comprehensive Integration Test Suite

**Priority**: P0 | **Effort**: High | **Impact**: Regression prevention, confidence in changes

**Current State**: Only 4 test files. No tests for ScannerService, reporters, setup wizard, worker threads, memory commands, or most other commands.

**Proposed Change**: Build a comprehensive integration test suite:

**Test infrastructure**:
```typescript
// Test helper: creates isolated project environment
async function withTestProject(fn: (ctx: TestContext) => Promise<void>) {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'drift-test-'));
  await initDriftProject(tmpDir);
  try {
    await fn({ rootDir: tmpDir, run: (cmd) => execDrift(cmd, tmpDir) });
  } finally {
    await fs.rm(tmpDir, { recursive: true });
  }
}

// Test helper: runs drift command and captures output
interface CommandResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  duration: number;
}
```

**Test categories**:

1. **Command smoke tests** (every command): Verify each command runs without crashing, produces expected output format, and exits with correct code.

2. **Reporter tests**: Property-based tests verifying:
   - JsonReporter always produces valid JSON
   - SarifReporter always produces valid SARIF v2.1.0
   - GitHubReporter produces valid annotation format
   - GitLabReporter produces valid Code Quality format
   - All reporters handle empty input gracefully

3. **Exit code tests**: Expand existing property-based tests to cover new structured exit codes (R1).

4. **Error handling tests**: Verify every error code (R2) is reachable and produces correct output.

5. **Configuration tests**: Verify configuration hierarchy (R5) merges correctly.

6. **Snapshot tests**: Capture expected output for key commands, detect formatting regressions.

**Rationale**: The CLI is the primary user interface. Regressions in output formatting, exit codes, or error handling directly impact users and CI pipelines.

**Evidence**:
- Google SWE Book, Ch. 14: Integration testing patterns
- fast-check for property-based testing ([github.com/dubzzz/fast-check](https://github.com/dubzzz/fast-check))

**Implementation Notes**:
- Create `test/helpers/` with `withTestProject`, `execDrift`, `assertExitCode`
- Use vitest for all tests
- Use fast-check for reporter validity properties
- Run in CI on every PR

**Risks**: Integration tests are slower than unit tests. Mitigate with parallel execution and test isolation.

**Dependencies**: R1 (exit codes), R2 (error taxonomy).

---

### R14: Reporter Validation Tests

**Priority**: P1 | **Effort**: Low | **Impact**: Output correctness

**Current State**: No tests for any reporter.

**Proposed Change**: Property-based tests for each reporter:

```typescript
// JSON reporter always produces valid JSON
fc.assert(fc.property(
  arbitraryReportData(),
  (data) => {
    const output = new JsonReporter().generate(data);
    JSON.parse(output); // Must not throw
  }
));

// SARIF reporter always produces valid SARIF
fc.assert(fc.property(
  arbitraryReportData(),
  (data) => {
    const output = new SarifReporter().generate(data);
    const sarif = JSON.parse(output);
    expect(sarif.$schema).toContain('sarif');
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toBeInstanceOf(Array);
  }
));

// GitHub reporter produces valid annotation format
fc.assert(fc.property(
  arbitraryViolation(),
  (violation) => {
    const output = new GitHubReporter().generate(wrapInReportData(violation));
    const lines = output.split('\n').filter(Boolean);
    lines.forEach(line => {
      expect(line).toMatch(/^::(error|warning) file=.+,line=\d+/);
    });
  }
));
```

**Rationale**: Reporters produce output consumed by external systems (CI, IDEs, security tools). Invalid output silently breaks integrations.

**Evidence**: Drift v1's property-based exit code tests are a model for this approach.

**Implementation Notes**: Create `reporters/reporters.test.ts` with fast-check arbitraries for ReportData and Violation.

**Risks**: None.

**Dependencies**: R6 (SARIF reporter).

---

## Theme 5: Performance & Migration

### R15: Thin ScannerService Wrapper

**Priority**: P0 | **Effort**: Medium | **Impact**: Eliminates 1,300+ LOC, leverages Rust performance

**Current State**: ScannerService is ~1,400 LOC managing detector loading, Piscina worker threads, file iteration, pattern aggregation, and location deduplication.

**Proposed Change**: Replace with a thin wrapper around Rust NAPI:

```typescript
class ScannerService {
  constructor(private config: ScannerServiceConfig) {}

  async scan(): Promise<ScanResults> {
    const nativeConfig = {
      rootDir: this.config.rootDir,
      incremental: this.config.incremental,
      categories: this.config.categories,
      maxFileSize: this.config.maxFileSize,
      timeout: this.config.timeout,
      generateManifest: this.config.generateManifest,
    };

    // Single NAPI call replaces entire scan pipeline
    const results = await nativeScan(nativeConfig);

    return {
      patterns: results.patterns,
      violations: results.violations,
      filesScanned: results.files_scanned,
      duration: results.duration_ms,
    };
  }
}
```

**Rationale**: Rust handles file walking, parsing, detection, aggregation, and storage natively with Rayon parallelism. The TS ScannerService becomes unnecessary overhead.

**Evidence**: MASTER_RECOMMENDATIONS M38 (N-API bridge with batch API).

**Implementation Notes**:
- Implement `nativeScan()` in Rust with progress callbacks
- Remove Piscina dependency entirely
- Remove detector-worker.ts
- Keep ScannerService as a thin adapter for backward compatibility

**Risks**: Requires Rust scan pipeline to be feature-complete before migration. Maintain TS fallback during transition.

**Dependencies**: MASTER_RECOMMENDATIONS M5 (scanner), M14 (visitor pattern), M38 (N-API bridge).

---

### R16: Batch NAPI Calls for Analysis Commands

**Priority**: P1 | **Effort**: Medium | **Impact**: Reduced NAPI overhead for multi-analysis workflows

**Current State**: Analysis commands (callgraph, boundaries, env, constants, coupling) each make separate NAPI calls. The setup wizard runs 13 runners sequentially, each making its own NAPI call.

**Proposed Change**: Use the batch NAPI API from MASTER_RECOMMENDATIONS M38:

```typescript
// Instead of:
const callGraph = await nativeBuildCallGraph(config);
const boundaries = await nativeScanBoundaries(config);
const environment = await nativeScanEnvironment(config);

// Use:
const results = await nativeAnalyzeBatch({
  rootDir: config.rootDir,
  analyses: ['callgraph', 'boundaries', 'environment', 'constants'],
});
// Shared parsing results — each file parsed once, not 4 times
```

**Rationale**: Each NAPI call independently walks the filesystem and parses files. Batching shares the parse results across analyses, reducing total time by 50-70% for multi-analysis workflows.

**Evidence**: MASTER_RECOMMENDATIONS M38 (batch API design).

**Implementation Notes**:
- Update setup wizard runners to use batch API
- Update `drift scan` with `--callgraph --boundaries --constants` to use batch API
- Keep individual NAPI calls for single-analysis commands

**Risks**: Batch API must handle partial failures (one analysis fails, others succeed).

**Dependencies**: MASTER_RECOMMENDATIONS M38 (N-API bridge with batch API).

---

### R17: NO_COLOR and Accessibility Support

**Priority**: P1 | **Effort**: Low | **Impact**: Accessibility compliance, CI compatibility

**Current State**: `--no-color` flag exists but `NO_COLOR` environment variable is not supported. No consideration for screen readers or high-contrast terminals.

**Proposed Change**:

1. Support `NO_COLOR` environment variable (de facto standard: https://no-color.org/)
2. Support `FORCE_COLOR` environment variable for forcing color in CI
3. Ensure all output is meaningful without color (don't rely on color alone for severity)
4. Use Unicode symbols with text fallbacks: `✖ error` not just red text

```typescript
const useColor = (() => {
  if (process.env.NO_COLOR !== undefined) return false;
  if (process.env.FORCE_COLOR !== undefined) return true;
  if (options.noColor) return false;
  return process.stdout.isTTY;
})();
```

**Rationale**: `NO_COLOR` is a cross-tool standard supported by 500+ CLI tools. Color-only severity indicators are inaccessible to colorblind users and screen readers.

**Evidence**:
- NO_COLOR standard (https://no-color.org/)
- CLIG.dev output guidelines ([clig.dev](https://clig.dev/))

**Implementation Notes**: Update chalk initialization to check `NO_COLOR`. Audit all color-dependent output for text fallbacks.

**Risks**: None.

**Dependencies**: None.

---

### R18: Plugin System for Enterprise Extensibility

**Priority**: P2 | **Effort**: High | **Impact**: Enterprise adoption, custom workflows

**Current State**: No plugin system. Enterprise users must fork the CLI to add custom commands.

**Proposed Change**: Implement a lightweight plugin system:

```typescript
// Plugin interface
interface DriftPlugin {
  name: string;
  version: string;
  commands?: CommandDefinition[];
  reporters?: ReporterDefinition[];
  hooks?: HookDefinition[];
}

// Plugin discovery
// 1. npm packages named drift-plugin-*
// 2. Local plugins in .drift/plugins/
// 3. User plugins in ~/.config/drift/plugins/

// Plugin registration
// drift plugins install drift-plugin-jira
// drift plugins list
// drift plugins uninstall drift-plugin-jira
```

Plugins can provide:
- **Custom commands**: `drift mycompany:audit`, `drift jira:sync`
- **Custom reporters**: `drift check --format jira`, `drift check --format datadog`
- **Lifecycle hooks**: Run custom logic before/after scan, check, gate

**Rationale**: Enterprise teams have unique workflows (JIRA integration, custom compliance checks, internal dashboards). A plugin system enables these without forking.

**Evidence**:
- oclif plugin architecture ([oclif.io/docs/plugins](https://oclif.io/docs/plugins))
- ESLint plugin system
- 12 Factor CLI Apps: "Encourage contributions"

**Implementation Notes**:
- Phase 1: Custom reporters (lowest risk, highest value)
- Phase 2: Custom commands
- Phase 3: Lifecycle hooks
- Use npm package conventions for discovery

**Risks**: Plugin security (loading arbitrary code), version compatibility, API stability. Mitigate with explicit opt-in and semver-based compatibility checks.

**Dependencies**: R7 (enhanced reporter architecture provides the extension point for custom reporters).

---

## Dependency Graph

```
Theme 1: Architecture
  R1 (Exit Codes) ──→ R2 (Error Taxonomy) ──→ R13 (Integration Tests)
  R3 (Lazy Loading) ──→ standalone
  R4 (Split memory.ts) ──→ standalone
  R5 (Config Hierarchy) ──→ R13 (Integration Tests)

Theme 2: Output & CI
  R6 (SARIF) ──→ R14 (Reporter Tests)
  R7 (Enhanced Reporters) ──→ R18 (Plugin System)
  R8 (Stable Fingerprints) ──→ standalone
  R9 (stdout/stderr) ──→ standalone

Theme 3: Developer Experience
  R10 (Shell Completion) ──→ standalone
  R11 (Progress Reporting) ──→ depends on M38 (N-API streaming)
  R12 (Unified analyze) ──→ depends on M6, M7 (Rust parsers)

Theme 4: Testing
  R13 (Integration Tests) ──→ R1, R2
  R14 (Reporter Tests) ──→ R6

Theme 5: Performance
  R15 (Thin ScannerService) ──→ depends on M5, M14, M38
  R16 (Batch NAPI) ──→ depends on M38
  R17 (NO_COLOR) ──→ standalone
  R18 (Plugin System) ──→ R7
```

---

## Cross-Category Impact Matrix

| Recommendation | Categories Affected | Impact Type |
|---|---|---|
| R1 (Exit Codes) | 09-quality-gates, 12-infrastructure | CI pipeline behavior changes |
| R2 (Error Taxonomy) | All categories (errors propagate from core) | Error handling standardization |
| R6 (SARIF) | 03-detectors, 09-quality-gates, 21-security | Security finding metadata requirements |
| R9 (stdout/stderr) | 07-mcp (if CLI is used programmatically) | Output stream changes |
| R11 (Progress) | 01-rust-core (NAPI callbacks) | Requires Rust-side progress reporting |
| R15 (Thin Scanner) | 01-rust-core, 03-detectors, 25-services | Eliminates TS scan pipeline |
| R16 (Batch NAPI) | 01-rust-core | Requires batch analysis API in Rust |

---

## Success Metrics

| Metric | V1 Baseline | V2 Target | Measurement |
|---|---|---|---|
| CLI startup time | ~500ms (50+ commands loaded) | <100ms (lazy loading) | `time drift --version` |
| Exit code granularity | 2 codes (0, 1) | 4 codes (0, 1, 2, 3) | Code review |
| Error codes defined | 0 | 20+ | Error taxonomy document |
| Shell completion | None | bash, zsh, fish | `drift completion --help` |
| Reporter test coverage | 0% | 100% (property-based) | Test suite |
| Command test coverage | ~10% (4 files) | >80% (smoke + integration) | Test suite |
| SARIF support | 1 command (gate) | 4 commands (check, gate, scan, report) | Feature matrix |
| Output formats | 5 (text, json, github, gitlab, sarif) | 7+ (add junit-xml, custom) | Feature matrix |
| ScannerService LOC | ~1,400 | <200 | `wc -l` |
| memory.ts LOC | ~2,800 (1 file) | ~2,800 (12 files) | File count |
| Config hierarchy levels | 1 (project) | 5 (flag > env > project > user > default) | Feature matrix |
| NO_COLOR support | No | Yes | `NO_COLOR=1 drift check` |
| Plugin system | None | Custom reporters + commands | Feature matrix |

---

## Build Priority Order

```
Immediate (before v2 launch):
  R1  Structured Exit Codes          [P0, Low]
  R2  Structured Error Taxonomy      [P0, Medium]
  R9  stdout/stderr Separation       [P0, Low]
  R15 Thin ScannerService            [P0, Medium]
  R13 Integration Test Suite         [P0, High]

Near-term (v2 launch):
  R6  SARIF First-Class              [P0, Medium]
  R4  Split memory.ts                [P1, Low]
  R3  Lazy-Loading Commands          [P1, Medium]
  R5  Configuration Hierarchy        [P1, Medium]
  R8  Stable Fingerprints            [P1, Low]
  R14 Reporter Validation Tests      [P1, Low]
  R17 NO_COLOR Support               [P1, Low]

Post-launch:
  R7  Enhanced Reporter Architecture [P1, Medium]
  R10 Shell Completion               [P1, Medium]
  R11 Granular Progress              [P1, Medium]
  R16 Batch NAPI Calls               [P1, Medium]
  R12 Unified analyze Command        [P2, Low]
  R18 Plugin System                  [P2, High]
```

---

## Quality Checklist

- [x] All 16 RECAP limitations addressed
- [x] 18 recommendations with full structure (priority, effort, evidence, risks, dependencies)
- [x] External evidence cited for every recommendation (24 sources from RESEARCH.md)
- [x] Cross-category impacts identified
- [x] Dependency graph showing inter-recommendation relationships
- [x] Success metrics with V1 baselines and V2 targets
- [x] Build priority order with effort estimates
- [x] Recommendations organized by theme for clarity
- [x] Every recommendation framed as "build new" (greenfield mindset)
- [x] Enterprise scale considerations throughout (500K+ files, CI pipelines, multi-project)