# 19 Error Handling — Research Recap

> **Purpose**: Complete synthesis of Drift v1's error handling subsystem — capturing every implementation detail, algorithm, data model, limitation, and integration point in one authoritative document. This serves as the requirements specification for the v2 greenfield rebuild.
>
> **Scope**: 4 primary source documents (~1,750 lines), 6 cross-category references, 3 master documents.
>
> **Date**: February 2026

---

## Executive Summary

The Error Handling subsystem is Drift's error topology intelligence layer — a dual-implementation engine (TypeScript call-graph-aware analysis + Rust AST-level pattern detection) that builds a complete map of how errors flow through a codebase. It detects error boundaries (try/catch, framework error handlers, global handlers), identifies error handling gaps (unhandled promises, swallowed errors, missing boundaries), traces error propagation chains across function boundaries via call graph integration, and scores error handling quality per function (0-100). The system spans ~600 lines of TypeScript in `packages/core/src/error-handling/` and ~300 lines of Rust in `crates/drift-core/src/error_handling/`, exposed via 1 NAPI function and 1 MCP tool with 3 actions. It is the critical bridge between static pattern detection and actionable error handling intelligence — feeding quality gates, security boundary analysis, and AI-assisted code review.

**Core thesis**: Error handling is a topology problem, not a per-function problem. Errors propagate across call chains, and the quality of error handling depends on where boundaries exist relative to where errors originate.

---

## Current Implementation

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PRESENTATION LAYER                              │
│  MCP Tool (drift_error_handling) │ Quality Gates │ CLI │ IDE            │
│  Actions: types | gaps | boundaries | propagation | summary            │
├─────────────────────────────────────────────────────────────────────────┤
│                    TypeScript Analysis Engine                            │
│  ErrorHandlingAnalyzer (~600 LOC)                                       │
│  ┌──────────┬──────────────┬──────────────┬─────────────────────┐      │
│  │ Function │   Boundary   │ Propagation  │    Gap Detection    │      │
│  │ Profiling│  Detection   │   Chains     │    & Scoring        │      │
│  │          │              │              │                     │      │
│  │ Per-func │ Framework    │ Source→Sink  │ no-try-catch        │      │
│  │ quality  │ boundaries   │ traversal    │ swallowed-error     │      │
│  │ score    │ (5 types)    │ Max depth 20 │ unhandled-async     │      │
│  │ (0-100)  │ Coverage %   │ Cycle detect │ bare-catch          │      │
│  │          │              │              │ missing-boundary    │      │
│  └──────────┴──────────────┴──────────────┴─────────────────────┘      │
│                    ↕ Call Graph Integration                              │
│  calledBy lookup │ Path traversal │ Native SQLite queries               │
├─────────────────────────────────────────────────────────────────────────┤
│                    Rust Core Engine                                      │
│  ErrorHandlingAnalyzer (~300 LOC)                                       │
│  ┌──────────────┬──────────────┬──────────────────┐                    │
│  │  Boundary    │    Gap       │   Error Type     │                    │
│  │  Extraction  │  Detection   │   Extraction     │                    │
│  │              │              │                  │                    │
│  │  TryCatch    │ Unhandled    │ Custom classes   │                    │
│  │  TryExcept   │ Promise      │ extending Error  │                    │
│  │  PromiseCatch│ Empty catch  │ /Exception       │                    │
│  │  ResultMatch │ Unwrap calls │                  │                    │
│  │  PanicHandler│              │                  │                    │
│  └──────────────┴──────────────┴──────────────────┘                    │
│                    ↕ NAPI Bridge                                        │
│  analyze_error_handling(files: Vec<String>) → JsErrorHandlingResult    │
├─────────────────────────────────────────────────────────────────────────┤
│                    Tree-sitter Parsing Layer                             │
│  10 Languages: TS, JS, Python, Java, C#, PHP, Go, Rust, C++, C        │
└─────────────────────────────────────────────────────────────────────────┘
```

### Component Inventory

| Component | Location | LOC | Language | Purpose |
|-----------|----------|-----|----------|---------|
| ErrorHandlingAnalyzer | `core/src/error-handling/error-handling-analyzer.ts` | ~600 | TS | Main analysis engine: 3-phase build, quality scoring, gap detection |
| Types | `core/src/error-handling/types.ts` | ~400 | TS | ~15 interfaces: profiles, boundaries, gaps, propagation, topology |
| Index | `core/src/error-handling/index.ts` | ~20 | TS | Public exports |
| Rust Analyzer | `crates/drift-core/src/error_handling/analyzer.rs` | ~300 | Rust | AST-level boundary/gap/type extraction |
| Rust Types | `crates/drift-core/src/error_handling/types.rs` | ~150 | Rust | 8 structs/enums: ErrorBoundary, ErrorGap, ErrorType, etc. |
| Rust Module | `crates/drift-core/src/error_handling/mod.rs` | ~10 | Rust | Module exports |
| MCP Tool | `packages/mcp/src/tools/surgical/errors.ts` | ~350 | TS | drift_error_handling: types, gaps, boundaries actions |

**Total**: ~1,830 lines across TypeScript and Rust

---

## Subsystem Deep Dives

### 1. TypeScript ErrorHandlingAnalyzer

**Class API**:
```typescript
class ErrorHandlingAnalyzer {
  constructor(options: ErrorHandlingOptions)
  setCallGraph(callGraph: CallGraph): void
  build(): ErrorHandlingTopology
  getTopology(): ErrorHandlingTopology | null
  getMetrics(): ErrorHandlingMetrics | null
  getSummary(): ErrorHandlingSummary | null
  analyzeFunction(funcId: string, func?: FunctionNode): ErrorHandlingProfile
  getFunctionAnalysis(funcId: string): FunctionErrorAnalysis | null
  getGaps(options?: GapDetectionOptions): ErrorHandlingGap[]
  getBoundaries(options?: BoundaryAnalysisOptions): ErrorBoundary[]
  getUnhandledPaths(minSeverity?: ErrorSeverity): UnhandledErrorPath[]
}
```

**Factory**: `createErrorHandlingAnalyzer(options) → ErrorHandlingAnalyzer`

#### Build Algorithm (3 Phases)

**Phase 1: Function Profiling**
For each function in the call graph:
1. Detect try/catch presence (`hasTryCatch`)
2. Detect throw capability (`canThrow` — conservative: any function with calls can throw)
3. Find throw locations in source
4. Extract catch clauses (error type, action, preservesError flag)
5. Check for rethrows
6. Analyze async handling (if async function): `.catch()` presence, `await` in try/catch, unhandled promise chains
7. Calculate quality score (0-100)
8. If function has try/catch → evaluate as potential boundary

**Phase 2: Propagation Chain Building**
For each function that can throw:
1. Start at thrower, walk UP the call graph via `calledBy`
2. At each level, check if any caller has try/catch
3. If found → chain terminates at that boundary (sink)
4. If not found and no more callers → chain escapes (sink = null, meaning uncaught)
5. Max depth: 20 levels (configurable via `maxPropagationDepth`)
6. Cycle detection: skip already-visited functions

**Phase 3: Unhandled Path Detection**
For each propagation chain where `sink === null`:
1. Identify the entry point (last function in the path)
2. Calculate severity based on entry point type:
   - Exported function → `critical`
   - Entry point file → `critical`
   - Otherwise → `medium`
3. Suggest boundary location (middle of the chain)

#### Quality Score Algorithm

```
Base score: 50

Positive factors:
  +20  has try/catch
  +15  catch action is 'recover'
  +10  catch action is 'transform'
  +5   catch preserves original error
  +10  async function has try/catch with await
  +5   async function has .catch()

Negative factors:
  -20  can throw but no try/catch
  -25  catch swallows error (empty catch)
  -5   bare catch (catches 'any')
  -20  async with unhandled promises

Result: clamp(0, 100)
```

**Quality mapping**: ≥80 = excellent, ≥60 = good, ≥40 = fair, <40 = poor

#### Risk Score Algorithm (for gaps)

```
Base score: 50

Gap type weights:
  +20  no-try-catch
  +30  swallowed-error
  +25  unhandled-async
  +5   bare-catch

Function importance:
  +15  exported function
  +20  entry point file
  +10  called by >5 functions

Result: min(100, score)
```

#### Framework Boundary Detection

| Framework | Detection Signal | Boundary Type |
|-----------|-----------------|---------------|
| React ErrorBoundary | `componentDidCatch` method OR class name contains "ErrorBoundary" | ErrorBoundary |
| Express middleware | Function with exactly 4 parameters (err, req, res, next) | ErrorMiddleware |
| NestJS filter | Class name contains "filter" + method named "catch" | Decorator |
| Spring handler | `@ExceptionHandler` or `@ControllerAdvice` annotations | Decorator |
| Laravel handler | Class hierarchy detection (extends Handler) | ErrorMiddleware |

#### Call Graph Integration
- Uses `setCallGraph()` to receive the call graph instance
- Checks for native SQLite call graph availability first
- Falls back to in-memory `calledBy` arrays
- `getFunctionCallers()` tries: calledBy array → native SQLite query
- Propagation chains traverse the call graph in reverse (callee → caller)

---

### 2. Rust ErrorHandlingAnalyzer

**Class API**:
```rust
impl ErrorHandlingAnalyzer {
    pub fn new() -> Self
    pub fn analyze(&mut self, files: &[String]) -> ErrorHandlingResult
}
```

#### AST-First Approach

The Rust analyzer works directly on source files WITHOUT a call graph — fundamentally different from the TS analyzer:

1. Parse each file with `ParserManager`
2. Extract boundaries from AST (line-by-line scan for try/catch/except patterns)
3. Detect gaps from AST (async functions without error handling, `.then()` without `.catch()`)
4. Extract custom error types from class definitions

#### Boundary Extraction Algorithm
```
For each line in source:
  1. Detect "try" keyword → mark try_start
  2. Detect "catch" / "except" keyword → create ErrorBoundary
     - Check if catch is empty (swallowed) via is_empty_catch()
     - Check if catch logs error via check_logs_error() (scans next 10 lines)
     - Check if catch rethrows via check_rethrows() (scans next 10 lines)
     - Extract caught types from catch signature (multi-language)
  3. Detect .catch() calls from AST call sites → PromiseCatch boundary
```

#### Gap Detection Algorithm
```
For each function in ParseResult:
  1. If async:
     - Check if function body contains try/catch
     - Check if function has .catch() calls within its range
     - If neither and contains "await" → UnhandledAsync gap (High severity)
  2. For all call sites:
     - .then() without nearby .catch() → UnhandledPromise gap (Medium severity)
     - .unwrap() → UnwrapWithoutCheck gap (High severity)
     - .expect() → UnwrapWithoutCheck gap (Medium severity)
```

#### Error Type Extraction
```
For each class in ParseResult:
  If class.extends contains "Error" or "Exception" or "Throwable"
  OR class.name ends with "Error" or "Exception"
  → Extract as ErrorType { name, file, line, extends, is_exported }
```

#### Caught Type Extraction (Multi-Language)
```
JavaScript/TypeScript: "catch (e: Error)" → extract type after ':'
Python: "except ValueError as e" → extract word after "except"
Java/C#: "catch (IOException e)" → extract first word in parens
```

#### Helper Methods
- `is_empty_catch(lines, line)` — Checks for `{}`, `{ }`, or `pass`
- `check_logs_error(lines, line)` — Scans next 10 lines for console.error, logger.error, logging.error, log.error
- `check_rethrows(lines, line)` — Scans next 10 lines for `throw`, `raise`, `rethrow`
- `get_function_source(lines, func)` — Extracts function body text by line range
- `function_has_try_catch(lines, func)` — Checks if function body contains both "try" and "catch"/"except"

---

### 3. MCP Integration

**Tool**: `drift_error_handling` / `drift_errors`
**Layer**: Surgical (low token cost: 300 target, 800 max)

**Arguments**:
```typescript
interface ErrorsArgs {
  action?: 'types' | 'gaps' | 'boundaries';  // Default: 'types'
  severity?: 'critical' | 'high' | 'medium' | 'low';
  limit?: number;  // Default: 20
}
```

**Action: `types`** — List custom error classes
```typescript
interface ErrorTypeInfo {
  name: string;        // "NotFoundError"
  file: string;        // "src/errors/not-found.ts"
  line: number;
  extends?: string;    // "HttpError"
  properties: string[];
  usages: number;      // How many times this error is thrown
}
```

**Action: `gaps`** — Find error handling gaps (filterable by severity)
```typescript
interface ErrorGapInfo {
  function: string;    // "fetchUser"
  file: string;
  line: number;
  gapType: string;     // "unhandled-async", "swallowed-error", etc.
  severity: string;    // "critical", "high", "medium", "low"
  suggestion: string;  // "Add .catch() or wrap await in try/catch"
}
```

**Action: `boundaries`** — List error boundaries
```typescript
interface ErrorBoundaryInfo {
  function: string;
  file: string;
  line: number;
  handledTypes: string[];
  coverage: number;    // % of callers protected
  isFramework: boolean;
}
```

**Stats Response** (all actions):
```typescript
stats: {
  totalTypes?: number;
  totalGaps?: number;
  totalBoundaries?: number;
  criticalGaps?: number;
  avgCoverage?: number;
}
```

**Prerequisites**: Call graph must be built (`drift callgraph build`). Throws `CALLGRAPH_NOT_BUILT` error if missing.

**Integration**: Uses `createErrorHandlingAnalyzer()` factory → sets call graph from `CallGraphStore` → builds topology → queries based on action.

---

### 4. Error Detector Category (03-detectors)

The error handling analyzer is complemented by 7 dedicated error detectors in the detector system:

| Detector | Base | Learning | Semantic | Purpose |
|----------|------|----------|----------|---------|
| `async-errors` | ✅ | ✅ | ✅ | Async error handling patterns |
| `circuit-breaker` | ✅ | ✅ | ✅ | Circuit breaker implementation patterns |
| `error-codes` | ✅ | ✅ | ✅ | Error code usage conventions |
| `error-logging` | ✅ | ✅ | ✅ | Error logging patterns |
| `error-propagation` | ✅ | ✅ | ✅ | Error propagation conventions |
| `exception-hierarchy` | ✅ | ✅ | ✅ | Exception class hierarchy patterns |
| `try-catch-placement` | ✅ | ✅ | ✅ | Try/catch placement conventions |

**Framework Extensions**:
- ASP.NET: ASP.NET error handling patterns
- Laravel: Laravel error handling patterns
- Go: Go error handling patterns (error wrapping, sentinel errors)
- Rust: Rust error handling patterns (Result, thiserror, anyhow)
- C++: C++ error handling patterns (exceptions, error codes)

**Total**: 7 detectors × 3 variants = 21 base detectors + 5 framework extensions = ~26 error-related detectors

---

## Key Data Models

### TypeScript Types (~15 interfaces)

#### Core Enums
```typescript
type CatchAction = 'log' | 'rethrow' | 'swallow' | 'transform' | 'recover';
type ErrorSeverity = 'critical' | 'high' | 'medium' | 'low';
type ErrorHandlingQuality = 'excellent' | 'good' | 'fair' | 'poor';
```

#### Per-Function Analysis

```typescript
// ErrorHandlingProfile — Per-function error handling assessment
interface ErrorHandlingProfile {
  functionId: string;
  file: string;
  name: string;
  qualifiedName: string;           // "ClassName.methodName"
  line: number;
  hasTryCatch: boolean;
  canThrow: boolean;
  throwLocations: number[];
  catchClauses: CatchClause[];
  rethrows: boolean;
  asyncHandling: AsyncErrorHandling | null;
  isAsync: boolean;
  qualityScore: number;            // 0-100
}

// CatchClause — What happens in each catch block
interface CatchClause {
  errorType: string;               // Error type or 'any' for bare catch
  action: CatchAction;             // log, rethrow, swallow, transform, recover
  line: number;
  preservesError: boolean;         // Does it preserve the original error?
}

// AsyncErrorHandling — Async-specific error handling status
interface AsyncErrorHandling {
  hasCatch: boolean;               // Has .catch() on promises
  hasAsyncTryCatch: boolean;       // Uses try/catch with await
  hasUnhandledPromises: boolean;   // Has unhandled promise chains
  unhandledLocations: Array<{ line: number; expression: string }>;
}
```

#### Boundary & Topology Types

```typescript
// ErrorBoundary — Function that catches errors from callees
interface ErrorBoundary {
  functionId: string;
  file: string;
  name: string;
  catchesFrom: string[];           // Function IDs caught from
  handledTypes: string[];
  isFrameworkBoundary: boolean;
  frameworkType?: 'react-error-boundary' | 'express-middleware' | 'nestjs-filter'
                | 'spring-handler' | 'laravel-handler';
  coverage: number;                // % of callers protected
  line: number;
}

// UnhandledErrorPath — Error path that escapes without being caught
interface UnhandledErrorPath {
  entryPoint: string;
  path: string[];                  // Function IDs in the path
  errorType: string;
  severity: ErrorSeverity;
  suggestedBoundary: string;       // Where to add error handling
  reason: string;
}

// ErrorTransformation — How errors change along propagation chains
interface ErrorTransformation {
  location: string;                // Function ID
  fromType: string;
  toType: string;
  preservesStack: boolean;
  line: number;
}

// ErrorPropagationChain — Source-to-sink error flow
interface ErrorPropagationChain {
  source: { functionId: string; throwLine: number };
  sink: { functionId: string; catchLine: number } | null;  // null = uncaught
  propagationPath: string[];
  transformations: ErrorTransformation[];
  depth: number;
}

// ErrorHandlingTopology — Complete analysis result
interface ErrorHandlingTopology {
  functions: Map<string, ErrorHandlingProfile>;
  boundaries: ErrorBoundary[];
  unhandledPaths: UnhandledErrorPath[];
  propagationChains: ErrorPropagationChain[];
  generatedAt: string;
  projectRoot: string;
}
```

#### Gap & Analysis Types

```typescript
// ErrorHandlingGap — Specific error handling deficiency
interface ErrorHandlingGap {
  functionId: string;
  file: string;
  name: string;
  line: number;
  gapType: 'no-try-catch' | 'swallowed-error' | 'unhandled-async'
         | 'bare-catch' | 'missing-boundary';
  severity: ErrorSeverity;
  description: string;
  suggestion: string;
  riskScore: number;               // 0-100
}

// FunctionErrorAnalysis — Detailed per-function analysis
interface FunctionErrorAnalysis {
  profile: ErrorHandlingProfile;
  incomingErrors: Array<{ from: string; errorType: string }>;
  outgoingErrors: Array<{ to: string; caught: boolean }>;
  isProtected: boolean;
  protectingBoundary?: ErrorBoundary;
  issues: Array<{ type: string; message: string; severity: ErrorSeverity; line?: number }>;
  suggestions: string[];
}
```

#### Metrics & Summary Types

```typescript
// ErrorHandlingMetrics — Aggregate statistics
interface ErrorHandlingMetrics {
  totalFunctions: number;
  functionsWithTryCatch: number;
  functionsThatThrow: number;
  boundaryCount: number;
  unhandledCount: number;
  unhandledBySeverity: Record<ErrorSeverity, number>;
  avgQualityScore: number;
  swallowedErrorCount: number;
  unhandledAsyncCount: number;
  frameworkBoundaries: number;
}

// ErrorHandlingSummary — High-level overview
interface ErrorHandlingSummary {
  totalFunctions: number;
  coveragePercent: number;
  unhandledPaths: number;
  criticalUnhandled: number;
  avgQuality: number;
  qualityDistribution: Record<ErrorHandlingQuality, number>;
  topIssues: Array<{
    type: 'swallowed' | 'unhandled-async' | 'no-boundary' | 'bare-catch';
    count: number;
    severity: ErrorSeverity;
  }>;
}
```

#### Options Types

```typescript
interface ErrorHandlingOptions {
  rootDir: string;
  includeAsync?: boolean;          // Default: true
  detectFrameworkBoundaries?: boolean; // Default: true
  maxPropagationDepth?: number;    // Default: 20
}

interface GapDetectionOptions {
  minSeverity?: ErrorSeverity;     // Default: 'low'
  limit?: number;                  // Default: 20
  includeSuggestions?: boolean;    // Default: true
  files?: string[];                // Focus on specific files
}

interface BoundaryAnalysisOptions {
  includeFramework?: boolean;
  minCoverage?: number;
}
```

### Rust Types (~8 structs/enums)

```rust
// Boundary classification
pub enum BoundaryType {
    TryCatch,           // JS/TS/Java/C# try-catch
    TryExcept,          // Python try-except
    TryFinally,         // try-finally without catch
    ErrorHandler,       // Framework error handler
    PromiseCatch,       // .catch() on promises
    AsyncAwait,         // async/await with try-catch
    ResultMatch,        // Rust match on Result<T, E>
    PanicHandler,       // Rust panic::catch_unwind
}

// Error boundary detected in source
pub struct ErrorBoundary {
    pub file: String,
    pub start_line: u32,
    pub end_line: u32,
    pub boundary_type: BoundaryType,
    pub caught_types: Vec<String>,
    pub rethrows: bool,
    pub logs_error: bool,
    pub is_swallowed: bool,
}

// Gap classification
pub enum GapType {
    UnhandledPromise,      // .then() without .catch()
    UnhandledAsync,        // async function without try/catch
    MissingCatch,          // try without catch
    SwallowedError,        // empty catch block
    UnwrapWithoutCheck,    // Rust .unwrap() / .expect()
    UncheckedResult,       // Rust Result not matched
    MissingErrorBoundary,  // Entry point without error handling
}

pub enum GapSeverity { Low, Medium, High, Critical }

pub struct ErrorGap {
    pub file: String,
    pub line: u32,
    pub function: String,
    pub gap_type: GapType,
    pub severity: GapSeverity,
    pub description: String,
}

pub struct ErrorType {
    pub name: String,
    pub file: String,
    pub line: u32,
    pub extends: Option<String>,
    pub is_exported: bool,
}

// Aggregate result
pub struct ErrorHandlingResult {
    pub boundaries: Vec<ErrorBoundary>,
    pub gaps: Vec<ErrorGap>,
    pub error_types: Vec<ErrorType>,
    pub files_analyzed: usize,
    pub duration_ms: u64,
}
```

### Rust ↔ TypeScript Type Mapping

| Concept | Rust | TypeScript |
|---------|------|------------|
| Boundary | `ErrorBoundary` (file-level, AST-detected) | `ErrorBoundary` (function-level, call-graph-aware, with coverage %) |
| Gap | `ErrorGap` (AST-detected, per-file) | `ErrorHandlingGap` (call-graph-aware, with risk score 0-100) |
| Error type | `ErrorType` (class extraction) | Extracted via `FunctionErrorAnalysis` |
| Propagation | **Not implemented** | `ErrorPropagationChain` (call graph traversal) |
| Topology | **Not implemented** | `ErrorHandlingTopology` (complete graph) |
| Quality | **Not implemented** | `qualityScore` (0-100) per function |
| Async handling | Basic (has try/catch check) | `AsyncErrorHandling` (detailed: .catch, await try/catch, unhandled locations) |
| Framework detection | **Not implemented** | 5 frameworks (React, Express, NestJS, Spring, Laravel) |
| Metrics | `files_analyzed`, `duration_ms` only | `ErrorHandlingMetrics` (12 fields) |
| Summary | **Not implemented** | `ErrorHandlingSummary` (coverage %, quality distribution, top issues) |

**Key insight**: The Rust implementation is AST-first (pattern detection within files), while TypeScript is call-graph-first (topology analysis across files). V2 must merge both approaches into a single Rust engine.

---

## Capabilities

### What It Can Do Today

1. **Error Boundary Detection**: Identifies 8 boundary types (TryCatch, TryExcept, TryFinally, ErrorHandler, PromiseCatch, AsyncAwait, ResultMatch, PanicHandler)
2. **Error Gap Detection**: Finds 7 gap types (UnhandledPromise, UnhandledAsync, MissingCatch, SwallowedError, UnwrapWithoutCheck, UncheckedResult, MissingErrorBoundary)
3. **Gap Severity Classification**: 4 levels (Critical, High, Medium, Low) with fix suggestions
4. **Error Type Extraction**: Custom error classes with inheritance tracking (extends field)
5. **Error Propagation Chains**: Source-to-sink tracing via call graph (TS only)
6. **Error Transformation Tracking**: Type changes along propagation chains (TS only)
7. **Quality Scoring**: Per-function quality score (0-100) with quality distribution (TS only)
8. **Risk Scoring**: Per-gap risk score (0-100) based on gap type + function importance (TS only)
9. **Framework Boundary Detection**: 5 frameworks (React, Express, NestJS, Spring, Laravel) (TS only)
10. **Boundary Coverage Metrics**: % of callers protected by each boundary (TS only)
11. **Unhandled Path Detection**: Identifies error paths that escape without being caught (TS only)
12. **Multi-Language Support**: Caught type extraction for JS/TS, Python, Java/C# (Rust)
13. **MCP Integration**: 3 actions (types, gaps, boundaries) with severity filtering
14. **Async Error Analysis**: Detects unhandled promises, missing .catch(), await without try/catch
15. **Swallowed Error Detection**: Empty catch blocks, catch without logging or rethrowing

### Limitations

#### Performance Limitations
1. **No incremental analysis**: Full re-analysis on every scan — no caching of error profiles or topology
2. **No parallel analysis**: TS analyzer runs sequentially through all functions
3. **Call graph dependency**: TS analyzer requires pre-built call graph; cannot run standalone
4. **No streaming results**: Entire topology built in memory before any results available

#### Feature Limitations
5. **Rust lacks propagation analysis**: No cross-function error flow tracking in Rust
6. **Rust lacks quality scoring**: No per-function quality score in Rust
7. **Rust lacks framework detection**: No framework-specific boundary detection in Rust
8. **No error type hierarchy tracking**: Knows `extends` but doesn't build full hierarchy tree
9. **No error message quality analysis**: Doesn't evaluate error message informativeness
10. **No error context preservation scoring**: Basic `preservesError` boolean, no depth analysis
11. **No error recovery strategy classification**: CatchAction enum exists but no pattern learning
12. **No field-level error tracking**: Tracks function-level, not which specific fields/operations fail

#### Architectural Limitations
13. **Dual implementation overhead**: Same concepts implemented differently in Rust and TS
14. **No structured error handling in Rust core itself**: Drift's own Rust code uses string-based errors
15. **Poor NAPI error propagation**: Rust errors become generic JS errors crossing the bridge
16. **No error decay**: Stale error patterns enforced forever; no temporal decay mechanism
17. **No feedback loop**: No mechanism to mark false positive gaps or learn from user corrections

#### Coverage Limitations
18. **Limited to 5 framework boundary types**: Missing Vue, Angular, Svelte, Koa, Hapi, Fastify, Django, Flask, Gin, Echo, Actix, Axum
19. **No cross-service error boundary detection**: Cannot trace errors across microservice boundaries
20. **No error handling in configuration files**: Doesn't analyze error handling in Terraform, CloudFormation, etc.
21. **No GraphQL/gRPC error handling patterns**: Only REST/HTTP error patterns detected
22. **Limited Rust-specific analysis**: Basic .unwrap()/.expect() detection; no ? operator analysis, no custom Result type tracking

---

## Integration Points

| Connects To | Direction | How |
|-------------|-----------|-----|
| **01-rust-core** | Bidirectional | Rust analyzer lives in drift-core; NAPI exposes `analyze_error_handling` |
| **02-parsers** | Consumes | Both Rust and TS analyzers consume ParseResult (functions, classes, calls) |
| **03-detectors** | Parallel | 7 error detectors (21 variants) detect error CONVENTIONS; analyzer detects error TOPOLOGY |
| **04-call-graph** | Consumes | TS analyzer requires call graph for propagation chains, boundary coverage, unhandled paths |
| **05-analyzers** | Bidirectional | Flow analyzer CFG feeds error path analysis; error profiles feed quality gates |
| **07-mcp** | Produces | drift_error_handling MCP tool exposes types, gaps, boundaries to AI agents |
| **08-storage** | Produces | Error handling results stored for regression detection and trend analysis |
| **09-quality-gates** | Produces | Error handling coverage as quality gate criterion; security boundary gate uses error paths |
| **21-security** | Produces | Error handling gaps can expose sensitive information (CWE-209: information exposure through error messages) |

### Critical Data Flow

```
Parsers → Rust ErrorHandlingAnalyzer → Boundaries + Gaps + ErrorTypes
                                              ↓
Call Graph → TS ErrorHandlingAnalyzer → Propagation Chains + Quality Scores
                                              ↓
                                    ErrorHandlingTopology
                                              ↓
                              ┌────────────────┼────────────────┐
                              ↓                ↓                ↓
                         MCP Tool        Quality Gates    Security Analysis
                    (AI consumption)   (CI enforcement)  (vulnerability detection)
```

### Relationship to Error Detectors (03-detectors)

The error handling analyzer and error detectors serve complementary purposes:

| Aspect | Error Handling Analyzer (19) | Error Detectors (03) |
|--------|----------------------------|---------------------|
| Purpose | Topology: how errors flow | Conventions: how errors should be handled |
| Approach | Call graph traversal | Pattern matching (regex, AST, semantic) |
| Output | Boundaries, gaps, propagation chains | Patterns, violations, confidence scores |
| Scope | Cross-function, cross-file | Per-file, per-pattern |
| Learning | None (static analysis) | ValueDistribution (convention learning) |
| Framework | 5 boundary types | 5 framework extensions |
| Variants | Single implementation | Base + Learning + Semantic per detector |

**V2 opportunity**: Merge these into a unified error intelligence system where topology analysis informs convention detection and vice versa.

---

## V2 Migration Status

### Current State: Split Implementation

```
TypeScript (Rich Analysis)              Rust (Fast Detection)
├── ErrorHandlingAnalyzer (~600 LOC)    ├── ErrorHandlingAnalyzer (~300 LOC)
│   ├── 3-phase build algorithm         │   ├── Boundary extraction (AST)
│   ├── Quality scoring (0-100)         │   ├── Gap detection (AST)
│   ├── Risk scoring (0-100)            │   └── Error type extraction
│   ├── Propagation chain analysis      │
│   ├── Framework boundary detection    │
│   ├── Boundary coverage metrics       │
│   └── Unhandled path detection        │
├── Types (~400 LOC, ~15 interfaces)    ├── Types (~150 LOC, ~8 types)
└── MCP Tool (~350 LOC)                 └── NAPI: analyze_error_handling
```

### V2 Merge Strategy (from analyzer.md)

1. **Keep Rust for AST-level extraction**: Boundaries, gaps, error types — fast per-file detection
2. **Move propagation chain analysis to Rust**: Graph traversal is ideal for Rust performance
3. **Move quality scoring to Rust**: Pure math, no reason to be in TS
4. **Keep framework boundary detection in Rust**: Pattern matching is Rust's strength
5. **Expose topology via NAPI for MCP tools**: TS becomes thin query layer

### What Must Migrate to Rust

| Priority | Component | Rationale | Effort |
|----------|-----------|-----------|--------|
| P0 | Propagation chain analysis | Graph traversal — Rust excels at this | High |
| P0 | Quality scoring | Pure computation — trivial port | Low |
| P0 | Framework boundary detection | Pattern matching — Rust's strength | Medium |
| P1 | Boundary coverage calculation | Requires call graph integration | Medium |
| P1 | Unhandled path detection | Depends on propagation chains | Medium |
| P1 | Risk scoring | Pure computation | Low |
| P2 | Error type hierarchy building | Tree construction from extends chains | Low |
| P2 | Async error deep analysis | Requires richer AST extraction | Medium |

---

## Open Questions

1. **Merge with error detectors?**: Should the error handling analyzer and 7 error detectors be unified in v2?
2. **Quality score calibration**: Is the current scoring formula (base 50, ±adjustments) well-calibrated? Should it be data-driven?
3. **Propagation depth limit**: Is 20 levels sufficient for enterprise codebases? Should it be adaptive?
4. **Framework detection extensibility**: Should framework boundary detection be declarative (TOML/YAML) for easy extension?
5. **Cross-service boundaries**: How should error handling analysis work across microservice boundaries?
6. **Error handling for Drift itself**: Should v2 use the same error handling patterns it recommends? (Eat your own dog food)
7. **CWE mapping**: Should error handling gaps be mapped to CWE identifiers for security compliance?
8. **Temporal analysis**: Should error handling quality be tracked over time for regression detection?
9. **IDE integration**: Should error handling gaps produce real-time IDE diagnostics (squiggly lines)?
10. **AI-assisted fixes**: Should the MCP tool suggest specific error handling code fixes?

---

## Quality Checklist

- [x] All 4 primary source documents read (overview, types, analyzer, mcp-tools)
- [x] All 6 cross-category references integrated (rust-core, napi-bridge, detectors, analyzers, quality-gates, master docs)
- [x] Architecture clearly described with diagram
- [x] Both Rust and TypeScript implementations fully documented
- [x] All algorithms documented with formulas (quality score, risk score, propagation, detection)
- [x] All data models listed with field descriptions (~15 TS interfaces, ~8 Rust types)
- [x] Rust↔TypeScript type mapping table included
- [x] MCP integration fully documented (3 actions, schemas, prerequisites)
- [x] Framework boundary detection signals documented (5 frameworks)
- [x] Error detector category integration documented (7 detectors × 3 variants)
- [x] 22 limitations honestly assessed across 4 categories (performance, features, architecture, coverage)
- [x] 9 integration points mapped to other categories
- [x] V2 migration status documented with merge strategy and priority ordering
- [x] 10 open questions identified
- [x] Critical data flow diagram included
