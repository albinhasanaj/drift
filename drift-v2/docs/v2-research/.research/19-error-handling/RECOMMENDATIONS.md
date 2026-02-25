# 19 Error Handling — V2 Build Recommendations

> **Context**: Drift v2 is a greenfield build. These recommendations define how to BUILD the error handling subsystem from scratch using best practices. V1 research serves as a requirements specification. All recommendations are backed by external research from Tier 1-2 sources.
>
> **Inputs**: RECAP.md (v1 complete state), RESEARCH.md (22 external sources), AUDIT.md (coverage verification)
>
> **Date**: February 2026

---

## Executive Summary

12 recommendations organized into 4 build phases, synthesized from comprehensive analysis of Drift v1's error handling subsystem and external research from 22 authoritative sources. The recommendations address six critical gaps: (1) unified Rust implementation merging AST-level and call-graph-level analysis, (2) interprocedural error propagation with compositional per-function summaries, (3) CWE/OWASP security mapping for enterprise compliance, (4) multi-dimensional quality scoring replacing the simplistic 0-100 model, (5) comprehensive framework boundary detection expanding from 5 to 20+ frameworks, and (6) incremental analysis enabling IDE-grade responsiveness. Combined, these changes transform Drift's error handling from a capable but split dual-implementation into an enterprise-grade, Rust-powered error topology engine suitable for million-line codebases with sub-second incremental response times.

---

## Phase 0: Architectural Foundations

### R1: Unified Error Handling Analyzer in Rust

**Priority**: P0 (Critical)
**Effort**: High
**Impact**: Eliminates dual-implementation overhead; enables 10-100x performance improvement

**Current State**:
V1 has two separate implementations: Rust (~300 LOC) for AST-level pattern detection and TypeScript (~600 LOC) for call-graph-aware topology analysis. They produce different result types, use different algorithms, and have no shared state. The Rust version lacks propagation chains, quality scoring, and framework detection. The TypeScript version lacks AST-level extraction efficiency.

**What to Build**:
A single Rust `ErrorHandlingAnalyzer` that combines both approaches:

```rust
pub struct ErrorHandlingAnalyzer {
    call_graph: Option<Arc<CallGraphDb>>,
    config: ErrorHandlingConfig,
}

impl ErrorHandlingAnalyzer {
    /// Phase 1: Per-file AST analysis (parallelizable via rayon)
    pub fn analyze_file(&self, file: &ParseResult) -> FileErrorProfile {
        // Extract boundaries, gaps, error types from AST
        // Compute per-function throws sets
        // Detect framework boundary patterns
    }
    
    /// Phase 2: Cross-file topology (requires call graph)
    pub fn build_topology(
        &self, 
        profiles: &[FileErrorProfile]
    ) -> ErrorHandlingTopology {
        // Compose per-function throws sets along call graph edges
        // Build propagation chains
        // Detect unhandled paths
        // Calculate boundary coverage
    }
    
    /// Phase 3: Quality assessment
    pub fn assess_quality(
        &self, 
        topology: &ErrorHandlingTopology
    ) -> ErrorHandlingAssessment {
        // Multi-dimensional quality scoring
        // CWE mapping for each gap
        // Risk scoring with function importance
    }
}
```

**Key Design Decisions**:
1. Phase 1 is embarrassingly parallel (per-file) — use rayon
2. Phase 2 requires call graph — sequential but uses efficient graph traversal
3. Phase 3 is pure computation on topology results — trivially parallelizable
4. All phases produce cacheable, hashable output for incremental analysis (aligned with M1)

**Evidence**:
- rust-analyzer architecture: layered analysis with clear phase boundaries
- Facebook Infer: compositional per-function analysis composed along call graph
- MASTER_RECOMMENDATIONS R10: error handling analyzer with propagation tracking in Rust

**Dependencies**:
- 01-rust-core: Rust core infrastructure (rayon, rusqlite, tree-sitter)
- 04-call-graph: Call graph must be available for Phase 2
- 02-parsers: ParseResult must include error handling constructs

---

### R2: Structured Error Types for Drift's Own Error Handling

**Priority**: P0 (Critical)
**Effort**: Low
**Impact**: Every subsystem uses this — impossible to retrofit cleanly

**Current State**:
V1's Rust code uses string-based errors. NAPI bridge converts Rust errors to generic JavaScript errors, losing structured information. This makes programmatic error handling in the TypeScript layer impossible.

**What to Build**:
Use `thiserror` for all error handling analyzer error types:

```rust
#[derive(thiserror::Error, Debug)]
pub enum ErrorHandlingError {
    #[error("call graph not available: {reason}")]
    CallGraphNotAvailable { reason: String },
    
    #[error("parse result missing error constructs for {file}")]
    MissingErrorConstructs { file: String },
    
    #[error("propagation depth exceeded ({depth} > {max_depth}) at {function}")]
    PropagationDepthExceeded { 
        depth: u32, 
        max_depth: u32, 
        function: String 
    },
    
    #[error("cycle detected in error propagation: {cycle:?}")]
    CycleDetected { cycle: Vec<String> },
    
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
}
```

**Evidence**:
- thiserror: https://docs.rs/thiserror (Rust ecosystem standard)
- MASTER_RECOMMENDATIONS M2: Structured error handling from day one
- GreptimeDB practices: per-subsystem error enums with structured variants

**Dependencies**: None — this is foundational.

---

## Phase 1: Core Analysis Engine

### R3: Interprocedural Error Propagation Engine

**Priority**: P0 (Critical)
**Effort**: High
**Impact**: Enables cross-function error flow analysis — the core value proposition

**Current State**:
V1 TypeScript walks the call graph from each throw statement upward, checking each caller for try/catch. This is O(T × D) where T = throw statements and D = average call depth. No caching, no incrementality, no compositional analysis.

**What to Build**:
A compositional error propagation engine based on per-function error summaries:

```rust
/// Per-function error summary (computed once, cached, incrementally updated)
pub struct FunctionErrorSummary {
    pub function_id: FunctionId,
    /// Exception types this function can throw (escaping throws)
    pub throws_set: Vec<ErrorTypeId>,
    /// Exception types this function catches
    pub catches_set: Vec<CatchInfo>,
    /// Whether this function has a catch-all handler
    pub has_catch_all: bool,
    /// Whether this function rethrows caught exceptions
    pub rethrows: bool,
    /// Async error handling status
    pub async_handling: Option<AsyncErrorStatus>,
    /// Content hash for incremental invalidation
    pub content_hash: u64,
}

/// Propagation is computed by composing summaries along call graph edges
pub fn compute_propagation(
    summaries: &HashMap<FunctionId, FunctionErrorSummary>,
    call_graph: &CallGraphDb,
) -> Vec<ErrorPropagationChain> {
    // For each function with non-empty throws_set:
    //   Walk callers via call graph
    //   At each caller, check if catches_set covers the thrown types
    //   If covered → chain terminates (sink)
    //   If not covered → propagate to caller's callers
    //   Track transformations along the chain
    //   Detect cycles, enforce max depth
}
```

**Key Design Decisions**:
1. Per-function summaries are computed in Phase 1 (per-file, parallel)
2. Propagation is computed in Phase 2 (cross-file, requires call graph)
3. Summaries are content-hashed for incremental invalidation
4. When a function changes, only its summary and direct callers need re-analysis
5. Cycle detection via visited set (same as v1, but at summary level)

**Evidence**:
- Interprocedural Exception Analysis for Java (academic): set-constraint framework for exception flow
- Google Research IECFG: compact representation for exception type sets
- Facebook Infer: compositional per-function analysis

**Dependencies**:
- R1: Unified analyzer architecture
- 04-call-graph: Call graph for caller/callee relationships

---

### R4: Expanded Error Type System

**Priority**: P0 (Critical)
**Effort**: Medium
**Impact**: Enables precise gap detection and CWE mapping

**Current State**:
V1 tracks error types as simple strings (name + extends). No hierarchy, no cross-file resolution, no language-specific type semantics.

**What to Build**:
A comprehensive error type system:

```rust
pub struct ErrorTypeRegistry {
    /// All error types discovered in the codebase
    types: HashMap<ErrorTypeId, ErrorTypeInfo>,
    /// Inheritance hierarchy (child → parent)
    hierarchy: HashMap<ErrorTypeId, ErrorTypeId>,
    /// Usage tracking (where each type is thrown/caught)
    usage: HashMap<ErrorTypeId, ErrorTypeUsage>,
}

pub struct ErrorTypeInfo {
    pub id: ErrorTypeId,
    pub name: String,
    pub file: String,
    pub line: u32,
    pub extends: Option<ErrorTypeId>,
    pub implements: Vec<String>,
    pub is_custom: bool,
    pub is_exported: bool,
    pub language: Language,
    /// Properties defined on the error type
    pub properties: Vec<ErrorProperty>,
    /// Whether this type preserves the original error (has 'cause' field)
    pub preserves_cause: bool,
}

pub struct ErrorTypeUsage {
    pub throw_locations: Vec<Location>,
    pub catch_locations: Vec<Location>,
    pub is_dead_catch: bool,  // caught but never thrown
    pub is_uncaught: bool,    // thrown but never caught
}
```

**Key Capabilities**:
1. Build full inheritance hierarchy (ErrorTypeA extends ErrorTypeB extends Error)
2. Detect dead error handling (catch blocks for types never thrown)
3. Detect uncaught error types (thrown but no catch block covers them)
4. Track error type specificity (catching specific types vs generic Exception)
5. Cross-file error type resolution (error defined in one file, thrown in another)

**Evidence**:
- Java exception hierarchy design: checked vs unchecked, hierarchy depth
- CWE-396: Declaration of Catch for Generic Exception
- CodeQL: "find exception types that are caught but never thrown"

**Dependencies**:
- R1: Unified analyzer architecture
- 02-parsers: ParseResult must include class inheritance information

---

### R5: Multi-Dimensional Quality Scoring Model

**Priority**: P0 (Critical)
**Effort**: Medium
**Impact**: Replaces simplistic 0-100 score with enterprise-grade quality assessment

**Current State**:
V1 uses a simple additive score (base 50, ±adjustments) that doesn't capture the multi-dimensional nature of error handling quality. A function with try/catch that swallows errors scores higher than a function without try/catch, even though the swallowing function is arguably worse.

**What to Build**:
A multi-dimensional quality model with four assessment categories:

```rust
pub struct ErrorHandlingAssessment {
    /// Overall composite score (0-100)
    pub composite_score: f32,
    /// Per-dimension scores
    pub coverage: CoverageMetrics,
    pub depth: DepthMetrics,
    pub quality: QualityMetrics,
    pub security: SecurityMetrics,
    /// Per-function quality distribution
    pub distribution: QualityDistribution,
    /// Top issues ranked by impact
    pub top_issues: Vec<RankedIssue>,
}

pub struct CoverageMetrics {
    /// % of throwable functions with error handling
    pub handling_coverage: f32,
    /// % of entry points protected by boundaries
    pub boundary_coverage: f32,
    /// % of async functions with proper error handling
    pub async_coverage: f32,
    /// % of framework entry points with framework-appropriate handlers
    pub framework_coverage: f32,
}

pub struct DepthMetrics {
    /// Average number of function calls before errors are caught
    pub avg_propagation_depth: f32,
    /// Longest unhandled error path
    pub max_propagation_depth: u32,
    /// catch blocks / throw statements
    pub catch_to_throw_ratio: f32,
    /// % of catch blocks catching specific types vs generic
    pub type_specificity: f32,
}

pub struct QualityMetrics {
    /// % of catch blocks that don't log, rethrow, or recover
    pub swallowed_error_rate: f32,
    /// % of catch blocks preserving original error
    pub context_preservation_rate: f32,
    /// % of error transformations preserving stack traces
    pub stack_preservation_rate: f32,
    /// % of catch blocks implementing recovery logic
    pub recovery_rate: f32,
}

pub struct SecurityMetrics {
    /// % of error handlers that may expose sensitive data
    pub information_disclosure_risk: f32,
    /// % of auth paths with fail-open error handling
    pub fail_open_risk: f32,
    /// Number of CWE violations detected
    pub cwe_violation_count: u32,
    /// Mapped CWE IDs
    pub cwe_ids: Vec<String>,
}
```

**Composite Score Formula**:
```
composite = coverage_score × 0.30 
          + depth_score × 0.20 
          + quality_score × 0.30 
          + security_score × 0.20

Where each dimension score is 0-100 computed from its sub-metrics.
```

**Evidence**:
- SonarQube: multi-quality model (security, reliability, maintainability)
- Academic papers: exception handling metrics (type specificity, handler coverage, propagation depth)
- DORA metrics: correlation between error handling quality and change failure rate

**Dependencies**:
- R3: Propagation engine (for depth metrics)
- R4: Error type system (for type specificity)

---

## Phase 2: Detection & Classification

### R6: CWE/OWASP Security-Mapped Gap Detection

**Priority**: P0 (Critical)
**Effort**: Medium
**Impact**: Enables enterprise compliance reporting; maps gaps to industry-standard vulnerability taxonomy

**Current State**:
V1 has 7 gap types (UnhandledPromise, EmptyCatch, MissingCatch, SwallowedError, UncheckedResult, IgnoredError, MissingErrorBoundary) with no security mapping. Enterprise customers cannot use Drift's error handling analysis for compliance reporting.

**What to Build**:
Expanded gap type system with CWE mapping and OWASP A10:2025 alignment:

```rust
pub enum ErrorGapType {
    // === Existing (enhanced) ===
    UnhandledPromise,           // CWE-248: Uncaught Exception
    SwallowedError,             // CWE-390: Detection Without Action
    MissingCatch,               // CWE-248: Uncaught Exception
    EmptyCatch,                 // CWE-390: Detection Without Action
    UncheckedResult,            // CWE-252: Unchecked Return Value
    IgnoredErrorReturn,         // CWE-391: Unchecked Error Condition
    MissingBoundary,            // CWE-248: Uncaught Exception
    
    // === New: Security-focused ===
    InformationDisclosure,      // CWE-209: Sensitive Info in Error Message
    FailOpenAuth,               // CWE-755 + OWASP A10: Auth bypass on error
    GenericCatch,               // CWE-396: Catch for Generic Exception
    GenericThrows,              // CWE-397: Throws for Generic Exception
    MissingErrorLogging,        // CWE-392: Missing Report of Error
    SensitiveDataInLog,         // CWE-532: Info Exposure Through Log Files
    
    // === New: Quality-focused ===
    NestedTryCatch,             // Excessive nesting (>2 levels)
    RethrowWithoutContext,      // Rethrow without adding context
    MixedErrorParadigms,       // Callbacks + promises in same function
    DeadErrorHandling,          // Catch for exception type never thrown
    CatchingProgrammingError,   // Catching NullPointerException, TypeError
    
    // === New: Language-specific ===
    RustUnwrapInLibrary,        // .unwrap() in library code
    RustExpectWithoutMessage,   // .expect("") with empty message
    RustPanicInNonTest,         // panic!() outside test code
    GoIgnoredErrorReturn,       // _ = functionReturningError()
    PythonBareExcept,           // except: (no type)
    PythonBroadExcept,          // except Exception:
    PhpErrorSuppression,        // @ operator usage
    CppCatchEllipsis,           // catch(...) without rethrow
}

impl ErrorGapType {
    pub fn cwe_id(&self) -> Option<&str> {
        match self {
            Self::InformationDisclosure => Some("CWE-209"),
            Self::SwallowedError | Self::EmptyCatch => Some("CWE-390"),
            Self::UncheckedResult | Self::IgnoredErrorReturn => Some("CWE-391"),
            Self::MissingErrorLogging => Some("CWE-392"),
            Self::GenericCatch => Some("CWE-396"),
            Self::GenericThrows => Some("CWE-397"),
            Self::UnhandledPromise | Self::MissingCatch 
                | Self::MissingBoundary => Some("CWE-248"),
            Self::SensitiveDataInLog => Some("CWE-532"),
            Self::FailOpenAuth => Some("CWE-755"),
            _ => None,
        }
    }
    
    pub fn owasp_category(&self) -> Option<&str> {
        match self {
            Self::InformationDisclosure | Self::FailOpenAuth 
                | Self::SensitiveDataInLog => Some("A10:2025"),
            _ => None,
        }
    }
}
```

**Evidence**:
- CWE-703 hierarchy: 11 child CWEs mapped to gap types
- OWASP Top 10 2025 A10: Mishandling of Exceptional Conditions (24 CWEs)
- OWASP Error Handling Cheat Sheet: information disclosure through errors
- SonarQube: zero false positive target for reliability rules

**Dependencies**:
- R1: Unified analyzer architecture
- R4: Error type system (for type-specific gap detection)

---

### R7: Comprehensive Framework Boundary Detection

**Priority**: P1 (Important)
**Effort**: Medium
**Impact**: Expands from 5 to 20+ framework boundary types; enables accurate coverage metrics

**Current State**:
V1 detects 5 framework boundary types: React ErrorBoundary, Express middleware, NestJS filter, Spring handler, Laravel handler. Missing: Vue, Angular, Svelte, Next.js, Koa, Fastify, Django, Flask, FastAPI, Gin, Echo, Actix, Axum, Rocket, ASP.NET.

**What to Build**:
Declarative framework boundary detection loaded from TOML configuration:

```toml
# Framework boundary detection rules
# Each rule defines how to detect error boundaries for a specific framework

[[boundaries]]
id = "react-error-boundary"
framework = "react"
language = "typescript"
detection = "class"
signals = [
    { type = "method", name = "componentDidCatch" },
    { type = "static_method", name = "getDerivedStateFromError" },
    { type = "class_name", pattern = ".*ErrorBoundary.*" },
]
boundary_type = "ErrorBoundary"

[[boundaries]]
id = "nextjs-error-page"
framework = "nextjs"
language = "typescript"
detection = "file"
signals = [
    { type = "file_name", pattern = "error\\.(tsx|ts|jsx|js)$" },
    { type = "directory", pattern = "app/" },
]
boundary_type = "ErrorBoundary"

[[boundaries]]
id = "vue-error-handler"
framework = "vue"
language = "typescript"
detection = "call"
signals = [
    { type = "property_access", pattern = "app\\.config\\.errorHandler" },
    { type = "lifecycle_hook", name = "onErrorCaptured" },
]
boundary_type = "GlobalHandler"

[[boundaries]]
id = "express-error-middleware"
framework = "express"
language = "typescript"
detection = "function"
signals = [
    { type = "parameter_count", value = 4 },
    { type = "parameter_name", index = 0, pattern = "err|error" },
]
boundary_type = "ErrorMiddleware"

# ... 16 more framework rules
```

**Full Framework Coverage** (20+ frameworks):
React, Next.js, Vue, Angular, Svelte, Express, Koa, Fastify, Hapi, NestJS, Spring, Django, Flask, FastAPI, Laravel, ASP.NET, Gin, Echo, Actix, Axum, Rocket

**Evidence**:
- Official framework documentation for each framework's error handling pattern
- RESEARCH.md Section 12.1: comprehensive detection signals per framework
- Semgrep: declarative rule definitions for pattern matching

**Dependencies**:
- R1: Unified analyzer architecture
- 02-parsers: ParseResult must include decorators, lifecycle hooks, parameter info

---

### R8: Language-Specific Gap Detection

**Priority**: P1 (Important)
**Effort**: Medium
**Impact**: Accurate gap detection across all 10 supported languages

**Current State**:
V1's gap detection is primarily JavaScript/TypeScript focused. Rust-specific analysis is limited to basic .unwrap()/.expect() detection. Go, Python, Java, C#, PHP, C++ have minimal language-specific gap detection.

**What to Build**:
Per-language gap detection modules that understand each language's error handling idioms:

**Go-Specific**:
- Detect ignored error returns: `result, _ := functionReturningError()` or `functionReturningError()` without capturing error
- Detect error wrapping: `fmt.Errorf("context: %w", err)` vs `fmt.Errorf("context: %v", err)` (wrapping vs formatting)
- Detect sentinel error patterns: `var ErrNotFound = errors.New("not found")`
- Detect errors.Is/errors.As usage vs direct comparison

**Rust-Specific**:
- Detect `.unwrap()` in non-test code (severity: high in library, medium in binary)
- Detect `.expect("")` with empty or non-descriptive message
- Detect `panic!()` in library code (should use Result instead)
- Detect `?` operator usage patterns (good) vs manual match (verbose but acceptable)
- Detect custom Result type aliases and their usage
- Detect `#[must_use]` attribute on Result-returning functions

**Python-Specific**:
- Detect bare `except:` (catches everything including SystemExit, KeyboardInterrupt)
- Detect broad `except Exception:` where specific types are appropriate
- Detect `except` with `pass` (swallowed error)
- Detect context manager usage (`with` statement) for resource cleanup
- Detect `raise` without `from` (loses original exception context in Python 3)

**Java-Specific**:
- Detect `catch (Throwable)` (catches errors that shouldn't be caught)
- Detect `catch (Exception)` where specific types are appropriate
- Detect missing try-with-resources for AutoCloseable resources
- Detect `throws Exception` in method signatures (too broad)
- Detect checked exception swallowing (catch checked, throw unchecked without wrapping)

**Evidence**:
- RESEARCH.md Section 10.1: multi-language error handling taxonomy
- PMD: AvoidCatchingGenericException, AvoidThrowingRawExceptionTypes
- Error Prone: CatchAndPrintStackTrace, FutureReturnValueIgnored
- Rust error handling best practices: unwrap/expect/panic guidelines

**Dependencies**:
- R1: Unified analyzer architecture
- 02-parsers: Language-specific AST extraction

---

## Phase 3: Advanced Analysis

### R9: Incremental Error Analysis with Salsa Integration

**Priority**: P1 (Important)
**Effort**: High
**Impact**: 10-100x performance improvement for incremental workflows; enables IDE-grade responsiveness

**Current State**:
V1 performs full re-analysis on every scan. No caching of error profiles, propagation chains, or topology. For a 10,000-file codebase, every scan re-analyzes all 10,000 files even if only one file changed.

**What to Build**:
Incremental error analysis integrated with the Salsa-based query system (MASTER_RECOMMENDATIONS M1):

```rust
#[salsa::query_group(ErrorHandlingDatabase)]
pub trait ErrorHandlingDb: AnalyzerDb {
    /// Input: file content (from AnalyzerDb)
    /// Derived: per-file error profile
    fn file_error_profile(&self, file: FileId) -> Arc<FileErrorProfile>;
    
    /// Derived: per-function error summary
    fn function_error_summary(
        &self, func: FunctionId
    ) -> Arc<FunctionErrorSummary>;
    
    /// Derived: propagation chains (depends on call graph + summaries)
    fn error_propagation_chains(&self) -> Arc<Vec<ErrorPropagationChain>>;
    
    /// Derived: error handling topology (depends on all above)
    fn error_topology(&self) -> Arc<ErrorHandlingTopology>;
    
    /// Derived: quality assessment (depends on topology)
    fn error_quality_assessment(&self) -> Arc<ErrorHandlingAssessment>;
}
```

**Invalidation Rules**:
1. `file_error_profile` invalidated when file content changes
2. `function_error_summary` invalidated when function body changes OR callee summary changes
3. `error_propagation_chains` invalidated when any summary in a chain changes
4. `error_topology` invalidated when any propagation chain changes
5. `error_quality_assessment` invalidated when topology changes

**Key Invariant** (from rust-analyzer): "Typing inside a function body never invalidates global derived data." Error summaries for unchanged functions are never recomputed.

**Evidence**:
- Salsa framework: incremental computation with automatic dependency tracking
- rust-analyzer: function-body isolation invariant
- CodeQL incremental analysis: 10-100x speedup for small changes
- MASTER_RECOMMENDATIONS M1: incremental-first computation model

**Dependencies**:
- MASTER_RECOMMENDATIONS M1: Salsa framework integration
- R1: Unified analyzer architecture
- R3: Propagation engine (defines the queries)

---

### R10: Error Context Preservation Analysis

**Priority**: P1 (Important)
**Effort**: Medium
**Impact**: Ensures errors carry sufficient context for debugging; reduces MTTR

**Current State**:
V1 has a basic `preservesError` boolean on CatchClause. No analysis of context richness, no detection of context loss through error transformations, no assessment of error message quality.

**What to Build**:
Deep analysis of how error context is preserved, enriched, or lost through propagation chains:

```rust
pub struct ContextPreservationAnalysis {
    /// Per-catch-block context assessment
    pub catch_assessments: Vec<CatchContextAssessment>,
    /// Per-chain context flow
    pub chain_context_flows: Vec<ChainContextFlow>,
    /// Overall context preservation score
    pub preservation_score: f32,
}

pub struct CatchContextAssessment {
    pub location: Location,
    /// Does the catch block use the caught error variable?
    pub uses_error_variable: bool,
    /// Does it preserve the original error as a cause?
    pub preserves_cause: bool,
    /// Does it add contextual information?
    pub adds_context: bool,
    /// Does it log the error with structured logging?
    pub has_structured_logging: bool,
    /// Does it report to an error monitoring service?
    pub reports_to_monitoring: bool,
    /// Context preservation score (0-100)
    pub score: f32,
}

pub enum ContextAction {
    Preserved,          // Error passed through unchanged
    Enriched,           // Context added (wrapping, additional fields)
    Transformed,        // Error type changed but cause preserved
    Degraded,           // Some context lost (e.g., stack trace stripped)
    Lost,               // Original error discarded entirely
}
```

**Detection Signals**:
- `uses_error_variable`: Check if the caught error parameter is referenced in the catch body
- `preserves_cause`: Check for `new Error("msg", { cause: err })`, `raise ... from err`, `fmt.Errorf("%w", err)`
- `adds_context`: Check for string concatenation or template literals with error info
- `has_structured_logging`: Check for logger.error(err), console.error(err) with structured format
- `reports_to_monitoring`: Check for Sentry.captureException, Bugsnag.notify, etc.

**Evidence**:
- Sentry SDK: error context model (breadcrumbs, tags, user context)
- error-stack crate: rich, structured error context preservation
- OWASP: error logging should be structured, contextual, and sufficient for forensic analysis
- DORA metrics: MTTR correlates with error context quality

**Dependencies**:
- R3: Propagation engine (for chain-level context flow)
- R4: Error type system (for cause chain tracking)

---

### R11: Resilience Pattern Detection

**Priority**: P2 (Nice to Have)
**Effort**: Medium
**Impact**: Detects enterprise resilience patterns; complements error handling with fault tolerance

**Current State**:
V1's error detector category includes `circuit-breaker` detection. No detection of retry, bulkhead, timeout, fallback, dead letter queue, or health check patterns.

**What to Build**:
Resilience pattern detection integrated with error handling analysis:

```rust
pub enum ResiliencePattern {
    CircuitBreaker {
        states: Vec<String>,        // closed, open, half-open
        failure_threshold: Option<u32>,
        timeout: Option<Duration>,
    },
    RetryWithBackoff {
        max_retries: Option<u32>,
        backoff_type: BackoffType,   // fixed, exponential, jitter
        retry_on: Vec<String>,       // exception types
    },
    Timeout {
        duration: Option<Duration>,
        on_timeout: TimeoutAction,   // throw, fallback, cancel
    },
    Bulkhead {
        max_concurrent: Option<u32>,
        max_wait: Option<Duration>,
    },
    Fallback {
        fallback_type: FallbackType, // default_value, cached, alternative_service
    },
    HealthCheck {
        endpoint: Option<String>,
        checks_dependencies: bool,
    },
}

pub struct ResilienceAssessment {
    /// Detected resilience patterns
    pub patterns: Vec<DetectedResiliencePattern>,
    /// External calls without resilience protection
    pub unprotected_calls: Vec<UnprotectedExternalCall>,
    /// Resilience coverage: protected calls / total external calls
    pub coverage: f32,
    /// Configuration audit findings
    pub config_issues: Vec<ResilienceConfigIssue>,
}
```

**Detection Signals**:
- Circuit Breaker: state machine pattern, failure counting, timeout-based state transitions
- Retry: loop with catch, exponential delay calculation, max retry check
- Timeout: Promise.race with timeout, AbortController, context.WithTimeout (Go)
- Bulkhead: semaphore/mutex limiting concurrent access, thread pool isolation
- Fallback: catch block returning default/cached value, try-primary-catch-fallback pattern

**Evidence**:
- Resilience4j: definitive pattern taxonomy and configuration model
- Microservice resilience patterns: industry consensus on required patterns
- RESEARCH.md Section 6: resilience engineering patterns

**Dependencies**:
- R1: Unified analyzer architecture
- 04-call-graph: Identifying external calls (API calls, database calls)

---

### R12: Enhanced MCP Tool Surface

**Priority**: P1 (Important)
**Effort**: Low-Medium
**Impact**: Richer AI-assisted error handling analysis and remediation

**Current State**:
V1 exposes 3 MCP actions: types, gaps, boundaries. Missing: propagation chains, quality assessment, resilience patterns, CWE mapping, framework coverage.

**What to Build**:
Expanded MCP tool with 7 actions:

```typescript
interface ErrorHandlingArgs {
  action: 'types' | 'gaps' | 'boundaries' | 'propagation' 
        | 'quality' | 'resilience' | 'summary';
  // Filtering
  severity?: ErrorSeverity;
  cwe?: string;              // Filter by CWE ID
  framework?: string;        // Filter by framework
  file?: string;             // Focus on specific file
  function?: string;         // Focus on specific function
  // Pagination
  limit?: number;            // Default: 20
  offset?: number;           // Default: 0
}
```

**New Actions**:
- `propagation`: Trace error propagation chains from a specific function or file
- `quality`: Get multi-dimensional quality assessment (coverage, depth, quality, security)
- `resilience`: List resilience patterns and unprotected external calls
- `summary`: Enhanced summary with CWE mapping, OWASP alignment, and trend data

**Token Budget**: Maintain surgical tool design (300 target, 800 max tokens per response). Use pagination for large result sets. Include `stats` in every response for quick overview without full results.

**Evidence**:
- V1 MCP tool design: proven surgical approach with stats
- RESEARCH.md: AI-assisted error handling analysis is a key use case
- 07-mcp RECOMMENDATIONS: MCP tool design patterns

**Dependencies**:
- R1-R11: All analysis capabilities feed MCP tool
- 07-mcp: MCP infrastructure

---

## Build Order

```
Phase 0 (Foundations):   R1 + R2                    [Unified architecture + structured errors]
Phase 1 (Core Engine):   R3 → R4 → R5              [Propagation, type system, quality model]
Phase 2 (Detection):     R6 → R7 → R8              [CWE mapping, frameworks, language-specific]
Phase 3 (Advanced):      R9 → R10 → R11 → R12      [Incremental, context, resilience, MCP]
```

Note: R2 (structured errors) should be applied from the first line of code. R9 (incremental) should be designed into the architecture from Phase 0, even if full Salsa integration comes later.

---

## Dependency Graph

```
R2 (Structured Errors) ──→ ALL recommendations (foundational)
R1 (Unified Analyzer) ──→ R3, R4, R5, R6, R7, R8, R9, R10, R11, R12
R3 (Propagation) ──→ R5 (quality: depth metrics), R10 (context flow)
R4 (Type System) ──→ R5 (quality: type specificity), R6 (CWE mapping)
R5 (Quality Model) ──→ R12 (MCP: quality action)
R6 (CWE Mapping) ──→ R12 (MCP: CWE filtering)
R7 (Frameworks) ──→ R5 (quality: framework coverage)
R8 (Language-Specific) ──→ R6 (language-specific CWE gaps)
R9 (Incremental) ──→ R12 (MCP: fast responses)
R10 (Context) ──→ R5 (quality: context preservation rate)
R11 (Resilience) ──→ R12 (MCP: resilience action)

External Dependencies:
  M1 (Incremental-First) ──→ R9
  M2 (Structured Errors) ──→ R2
  04-call-graph ──→ R3, R7, R11
  02-parsers ──→ R4, R7, R8
  07-mcp ──→ R12
  09-quality-gates ──→ R5, R6
```

---

## Cross-Category Impact Analysis

| Recommendation | Categories Affected | Impact Type |
|---------------|-------------------|-------------|
| R1 (Unified Analyzer) | 01-rust-core, 05-analyzers | Architecture: new Rust crate |
| R2 (Structured Errors) | ALL | Convention: error handling pattern for all Drift code |
| R3 (Propagation) | 04-call-graph | Dependency: requires call graph queries |
| R4 (Type System) | 02-parsers, 03-detectors | Dependency: requires class hierarchy from parsers |
| R5 (Quality Model) | 09-quality-gates | Producer: feeds error handling quality gate |
| R6 (CWE Mapping) | 21-security, 09-quality-gates | Producer: feeds security analysis and SARIF output |
| R7 (Frameworks) | 03-detectors | Parallel: complements error detector category |
| R8 (Language-Specific) | 02-parsers | Dependency: requires language-specific AST features |
| R9 (Incremental) | 01-rust-core (M1) | Architecture: integrates with Salsa framework |
| R10 (Context) | 06-cortex | Producer: context quality feeds AI context generation |
| R11 (Resilience) | 03-detectors | Parallel: extends circuit-breaker detector |
| R12 (MCP) | 07-mcp | Producer: new MCP tool actions |

---

## Success Metrics

| Metric | V1 Baseline | V2 Target | Measurement |
|--------|-------------|-----------|-------------|
| Gap types | 7 | 25+ | Count of distinct gap types |
| Framework boundaries | 5 | 20+ | Count of detected framework types |
| Languages with specific gaps | 2 (JS/TS, Rust partial) | 10 | Languages with language-specific gap detection |
| CWE coverage | 0 | 11+ CWEs | CWE IDs mapped to gap types |
| Quality dimensions | 1 (single score) | 4 (coverage, depth, quality, security) | Dimension count |
| False positive rate | Unknown | <5% | Manual validation on benchmark codebases |
| Incremental analysis time | Full re-analysis | <100ms for single file change | Benchmark on 10K file codebase |
| MCP actions | 3 | 7 | Count of MCP tool actions |
| Propagation analysis | TS only | Rust (10-100x faster) | Implementation language |
| Resilience patterns | 1 (circuit breaker) | 6+ | Count of detected resilience patterns |

---

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| Salsa integration complexity | Medium | High | Start with simple content-hash cache; upgrade to Salsa later |
| False positives in language-specific gaps | Medium | Medium | Validate each gap type against 5+ real codebases before shipping |
| Framework detection maintenance burden | Low | Medium | Declarative TOML rules enable community contributions |
| CWE mapping accuracy | Low | High | Validate against MITRE CWE examples; automated test suite |
| Performance regression from richer analysis | Medium | Medium | Benchmark each phase; incremental analysis mitigates |
| Call graph dependency for propagation | Low | High | Graceful degradation: file-level analysis without call graph |

---

## Quality Checklist

- [x] All 22 limitations from RECAP addressed by recommendations
- [x] All 12 research topics from RESEARCH cited in recommendations
- [x] Every recommendation framed as "build new" not "migrate/port"
- [x] External evidence cited for every recommendation
- [x] Build order defined with dependency graph
- [x] Cross-category impact analyzed for all 12 recommendations
- [x] Success metrics defined with V1 baseline and V2 target
- [x] Risk assessment with mitigation strategies
- [x] No feature deferred to "add later" — everything built into the right phase
- [x] Traceability: every RECAP limitation maps to at least one recommendation
- [x] Traceability: every RESEARCH finding maps to at least one recommendation
- [x] CWE/OWASP compliance requirements addressed (R6)
- [x] Incremental analysis designed in from Phase 0 (R9)
- [x] MCP tool surface expanded for AI-assisted workflows (R12)
