# 19 Error Handling — V2 Research Encyclopedia

> **Purpose**: Curated encyclopedia of external research findings from authoritative sources, organized by topic area. Each entry includes source, tier, key findings, and applicability to Drift v2's error handling subsystem.
>
> **Methodology**: Tier 1 (authoritative specs/papers/standards), Tier 2 (industry expert/production tools), Tier 3 (community validated), Tier 4 (reference only).
>
> **Date**: February 2026

---

## 1. Security Standards for Error Handling

### 1.1 OWASP Error Handling Cheat Sheet

**Source**: https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
**Tier**: 1 (OWASP — authoritative security standard)

**Key Findings**:
- Error handling is part of the overall security posture. Unhandled errors assist attackers in reconnaissance by revealing technology stack details.
- Stack traces, database dumps, and error codes displayed to users are information disclosure vulnerabilities.
- A global error handler should return generic responses to users while logging full details server-side.
- RFC 7807 (Problem Details for HTTP APIs) defines a standard format for error responses that avoids leakage.
- Per-technology configuration recommended: Java web.xml, ASP.NET customErrors, Express middleware, Spring @ControllerAdvice.
- Error logging should follow the OWASP Logging Cheat Sheet — structured, contextual, never containing sensitive data.

**Applicability to Drift v2**: The error handling analyzer should detect when applications expose stack traces or detailed error information to end users. Gap detection should flag missing global error handlers and missing RFC 7807 compliance. New gap types: `information-disclosure-in-error`, `missing-global-handler`, `sensitive-data-in-error-response`.

---

### 1.2 OWASP Top 10 2025: A10 — Mishandling of Exceptional Conditions

**Source**: https://authgear.com/post/owasp-2025-mishandling-of-exceptional-conditions
**Tier**: 1 (OWASP Top 10 — authoritative security standard)

**Key Findings**:
- New entry in OWASP Top 10 2025 at position #10, encompassing 24 CWEs centered on improper error handling.
- Covers logic flaws, "fail-open" behaviors, and issues when systems encounter abnormal conditions.
- Fail-open behavior: system defaults to allowing access when an error occurs in auth path — critical security vulnerability.
- Recognizes error handling as maintaining security invariants under all conditions, not just catching exceptions.

**Applicability to Drift v2**: Validates error handling as a first-class security concern. Drift should map gaps to OWASP A10:2025 and the 24 associated CWEs. The analyzer should detect fail-open patterns where auth checks are bypassed on error. P0 requirement for enterprise adoption.

---

### 1.3 CWE Error Handling Hierarchy (CWE-703)

**Source**: https://cwe.mitre.org/data/definitions/703.html
**Tier**: 1 (MITRE CWE — authoritative vulnerability taxonomy)

**Key Findings**:
CWE-703 is the pillar weakness for "Improper Check or Handling of Exceptional Conditions." Key child CWEs:

| CWE ID | Name | Drift Gap Type Mapping |
|--------|------|----------------------|
| CWE-209 | Error Message Containing Sensitive Information | `information-disclosure-in-error` |
| CWE-390 | Detection of Error Condition Without Action | `swallowed-error` |
| CWE-391 | Unchecked Error Condition | `unchecked-result` |
| CWE-392 | Missing Report of Error Condition | `missing-error-logging` |
| CWE-396 | Declaration of Catch for Generic Exception | `bare-catch` |
| CWE-397 | Declaration of Throws for Generic Exception | `generic-throws` |
| CWE-248 | Uncaught Exception | `missing-boundary` |
| CWE-252 | Unchecked Return Value | `unchecked-return` |
| CWE-754 | Improper Check for Unusual Conditions | `missing-edge-case-handling` |
| CWE-755 | Improper Handling of Exceptional Conditions | `improper-error-handling` |

**Applicability to Drift v2**: Every error handling gap should map to CWE identifiers. Enables enterprise compliance reporting (SARIF with CWE references), vulnerability management integration, and industry-standard taxonomy alignment.

---

### 1.4 OWASP Proactive Controls C10: Handle All Errors and Exceptions

**Source**: https://owasp.org/www-project-proactive-controls/v3/en/c10-errors-exceptions
**Tier**: 1 (OWASP Proactive Controls)

**Key Findings**:
- A lack of basic error handling can lead to system shutdown — usually easy for attackers to exploit.
- Error handling problems can lead to increased CPU or disk usage that degrades the system (DoS vector).
- Three key principles: (1) manage exceptions in a centralized manner, (2) ensure error messages don't leak sensitive data, (3) ensure errors don't lead to denial of service.
- Error handlers should be tested as rigorously as normal code paths.

**Applicability to Drift v2**: The analyzer should detect centralized vs distributed error handling patterns. A new metric: "error handling centralization score" measuring what percentage of error handling goes through centralized handlers vs ad-hoc try/catch blocks.

---

## 2. Static Analysis Tools for Error Handling

### 2.1 SonarQube Multi-Quality Rule Model

**Source**: https://docs.sonarsource.com/sonarqube-server/latest/user-guide/rules/overview/
**Tier**: 2 (Industry-leading static analysis platform)

**Key Findings**:
- SonarQube categorizes rules into three software qualities: security, reliability, and maintainability. A single rule may impact multiple qualities simultaneously.
- For reliability and maintainability rules, the target is zero false positives — developers should never have to question whether a reported issue is real.
- For security vulnerability rules, the target is >80% true positive rate.
- Security hotspot rules flag security-sensitive code for developer review, with >80% expected to be quickly resolved as "reviewed."
- The Multi-Quality Rule (MQR) mode allows a single rule to produce issues tagged with multiple quality impacts, reflecting that error handling defects often span reliability and security simultaneously.
- SonarQube's bug detection advances include interprocedural analysis for tracking null dereferences and resource leaks across function boundaries.

**Applicability to Drift v2**: Drift's error handling gap types should follow SonarQube's multi-quality model — a single gap (e.g., `swallowed-error`) can impact both reliability and security. The zero false positive target for reliability rules sets the bar for Drift's gap detection precision. Each gap type should carry quality impact tags (security, reliability, maintainability) rather than a single severity.

---

### 2.2 Semgrep Taint Analysis for Error Flow Tracking

**Source**: https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/overview
**Tier**: 2 (Production static analysis tool, widely adopted)

**Key Findings**:
- Semgrep's taint analysis tracks the flow of untrusted (tainted) data from sources through propagators to sinks within function bodies.
- Taint rules use a declarative `mode: taint` specification with explicit `pattern-sources`, `pattern-sinks`, and optional `pattern-sanitizers`.
- Advanced features include by-side-effect tainting (a variable becomes tainted at a specific program point), taint propagators (functions that transfer taint from input to output), and cross-file analysis for handling duplicate function names.
- Semgrep's approach is intraprocedural by default but supports cross-file analysis for resolving function calls across modules.
- The declarative rule format enables community-contributed rules — Semgrep's registry contains thousands of rules across languages.

**Applicability to Drift v2**: Error flow tracking in Drift is analogous to taint analysis — errors are "tainted" values that flow from throw sites (sources) through function calls (propagators) to catch blocks (sinks/sanitizers). Drift should adopt a similar declarative rule format for defining error handling patterns, enabling extensibility. The source→propagator→sink model maps directly to throw→propagation chain→catch boundary.

---

### 2.3 Facebook Infer Pulse: Interprocedural Compositional Analysis

**Source**: https://fbinfer.com/docs/checker-pulse/
**Tier**: 1 (Academic-grade tool used at Meta scale)

**Key Findings**:
- Pulse is an interprocedural memory safety analysis that replaced Infer's original biabduction engine. It detects null dereferences, resource leaks, and use-after-free errors.
- Errors are only reported when all conditions on the erroneous path are true regardless of input — this eliminates false positives from infeasible paths.
- Pulse uses a "latent issue" model: when an error depends on parameter values, it is recorded as latent. When a call site satisfies all conditions, the latent issue becomes manifest and is reported. This is compositional analysis — per-function summaries composed along call edges.
- For unknown functions (third-party code without source), Pulse makes optimistic assumptions, scrambling reachable state to avoid false positives at the cost of potential false negatives.
- Pulse supports 60+ issue types including `NULLPTR_DEREFERENCE`, `PULSE_RESOURCE_LEAK`, `PULSE_UNAWAITED_AWAITABLE`, `TAINT_ERROR`, and `SENSITIVE_DATA_FLOW`.
- The `PULSE_UNAWAITED_AWAITABLE` issue type is directly relevant — it detects async functions whose results are not awaited, analogous to floating promises.

**Applicability to Drift v2**: Pulse's compositional per-function summary model is the gold standard for Drift's error propagation engine. Each function should produce an error summary (throws set, catches set, rethrow behavior) that is composed along call graph edges. The latent/manifest distinction maps to Drift's concept of "potential" vs "confirmed" error handling gaps. The `PULSE_UNAWAITED_AWAITABLE` pattern validates Drift's `UnhandledPromise` gap type.

---

### 2.4 Google Error Prone: Compile-Time Bug Pattern Detection

**Source**: https://errorprone.info/bugpatterns
**Tier**: 2 (Google internal tool, open-sourced, widely adopted in Java ecosystem)

**Key Findings**:
- Error Prone is a compile-time static analysis tool for Java that integrates directly with javac. It catches common programming mistakes as compiler errors or warnings.
- Error handling-specific bug patterns include:
  - `CatchAndPrintStackTrace`: Catching an exception and only printing the stack trace (should log or rethrow).
  - `FutureReturnValueIgnored`: Ignoring the return value of a method that returns a Future (analogous to floating promises).
  - `MissingFail`: Test method catches an expected exception but doesn't call `fail()` if the exception isn't thrown.
  - `EmptyCatch`: Empty catch block that silently swallows exceptions.
  - `CatchFail`: Catching an exception in a test and calling `fail()` instead of using `assertThrows`.
  - `IgnoredPureGetter`: Ignoring the return value of a pure method (potential unchecked result).
- Error Prone's approach is intraprocedural (single-function analysis) but leverages type information from the Java compiler for high precision.
- The tool achieves near-zero false positive rates by being conservative — only flagging patterns that are almost certainly bugs.

**Applicability to Drift v2**: Error Prone's bug patterns provide a validated catalog of error handling anti-patterns. Drift should detect all of these patterns across languages: `CatchAndPrintStackTrace` → `swallowed-error` variant, `FutureReturnValueIgnored` → `unhandled-promise`, `EmptyCatch` → `empty-catch`. The near-zero false positive philosophy should guide Drift's gap detection — only flag patterns that are definitively problematic.

---

### 2.5 PMD Error Handling Rules

**Source**: https://pmd.github.io/pmd/pmd_rules_java_design.html
**Tier**: 2 (Established Java static analysis tool)

**Key Findings**:
- PMD's error handling rules target Java-specific anti-patterns:
  - `AvoidCatchingGenericException`: Flags `catch(Exception e)` and `catch(Throwable t)` — catching overly broad exception types masks specific errors that should be handled differently.
  - `AvoidThrowingRawExceptionTypes`: Flags `throw new Exception()` and `throw new RuntimeException()` — raw exception types provide no semantic information about the error.
  - `AvoidCatchingNPE`: Flags `catch(NullPointerException)` — NPE should be prevented through null checks, not caught.
  - `AvoidThrowingNullPointerException`: Flags explicit `throw new NullPointerException()` — use `IllegalArgumentException` or `Objects.requireNonNull()` instead.
  - `DoNotThrowExceptionInFinally`: Throwing in finally blocks can mask the original exception.
  - `ExceptionAsFlowControl`: Using exceptions for normal control flow (performance and readability anti-pattern).
- PMD rules are configurable with priority levels (1-5) and can be customized per project.

**Applicability to Drift v2**: PMD's rules map directly to Drift gap types: `AvoidCatchingGenericException` → `generic-catch` (CWE-396), `AvoidThrowingRawExceptionTypes` → `generic-throws` (CWE-397), `AvoidCatchingNPE` → `catching-programming-error`. The `ExceptionAsFlowControl` pattern is a new gap type Drift should detect — using exceptions for non-exceptional control flow degrades performance and readability.

---

### 2.6 typescript-eslint: Promise Error Handling Rules

**Source**: https://typescript-eslint.io/rules/no-floating-promises
**Tier**: 2 (Official TypeScript linting ecosystem)

**Key Findings**:
- `no-floating-promises`: Detects Promise-valued statements that are not handled via `.then()` with two arguments, `.catch()`, `await`, `return`, or `void`. A "floating" Promise can cause improperly sequenced operations and ignored rejections.
- The rule also detects arrays containing Promises that are not handled via `Promise.all()`, `Promise.allSettled()`, `Promise.any()`, or `Promise.race()`.
- `checkThenables` option extends detection to any object with a `.then()` method, not just native Promises — important for polyfills and custom async abstractions.
- `no-misused-promises`: Detects Promises provided to logical locations (if statements, conditionals) where they are not properly awaited — a Promise in an `if` condition is always truthy, which is almost certainly a bug.
- Both rules require TypeScript type information to run, enabling precise detection that pure AST analysis cannot achieve.

**Applicability to Drift v2**: These rules validate and extend Drift's `UnhandledPromise` gap type. Drift should detect: (1) floating promises (no await/catch/then), (2) promise arrays without concurrency methods, (3) promises in conditional positions. The `checkThenables` concept means Drift should track custom async abstractions, not just native Promise. The type-information requirement confirms that Drift needs type-aware analysis for accurate async error detection.

---

### 2.7 CodeQL: Code-as-Data Semantic Analysis

**Source**: https://docs.github.com/en/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning-with-codeql
**Tier**: 1 (GitHub/Semmle — academic-grade, production-deployed)

**Key Findings**:
- CodeQL treats code as data by compiling source into a relational database capturing ASTs, control flow, data flow, types, and call graphs. Queries are written in a declarative QL language to find patterns across these structures.
- CodeQL's data flow analysis tracks how values move through code, enabling detection of security vulnerabilities like SQL injection, XSS, and — critically — error handling defects.
- The code-as-data approach enables queries like "find all catch blocks that catch Exception but don't log or rethrow" or "find all functions that return Result but whose callers ignore the error variant."
- CodeQL supports incremental analysis: a research paper on "Incrementalizing Production CodeQL Analyses" demonstrates that instead of re-analyzing from scratch, incremental analysis updates previous results based on code changes, achieving 10-100x speedup for small changes.
- CodeQL's query language enables composable, reusable analysis patterns — a library of error handling queries can be built and shared.

**Applicability to Drift v2**: CodeQL's code-as-data philosophy validates Drift's approach of building a queryable representation of error handling topology. The incremental analysis research directly supports R9 (Incremental Error Analysis). CodeQL's composable query model suggests Drift's MCP tool should support composable error handling queries, not just predefined actions.

---

## 3. Rust Error Handling Ecosystem

### 3.1 thiserror: Derive Macros for Custom Error Types

**Source**: https://docs.rs/thiserror
**Tier**: 2 (Rust ecosystem standard, maintained by David Tolnay)

**Key Findings**:
- `thiserror` provides derive macros for implementing `std::error::Error` on custom error enums and structs, eliminating boilerplate for `Display`, `Error`, and `From` implementations.
- The `#[error("...")]` attribute generates `Display` implementations with format string support.
- The `#[from]` attribute generates `From` implementations for automatic error conversion via the `?` operator.
- The `#[source]` attribute designates the underlying cause of an error, enabling error chain traversal.
- `thiserror` is the consensus choice for library code where callers need to match on specific error variants. It produces zero-cost abstractions — no runtime overhead compared to hand-written implementations.
- The Mithril Network project's ADR documents a standard: "thiserror is used to create module or domain errors that come from our developments and can be easily identified (as they are strongly typed). anyhow is used to add context to errors triggered by sub-systems."

**Applicability to Drift v2**: `thiserror` is the recommended foundation for all Drift v2 error types (R2). Every Drift subsystem should define a `thiserror`-derived error enum with structured variants. The `#[from]` and `#[source]` patterns are what Drift's analyzer should detect in user codebases — presence of proper error chaining indicates high-quality error handling.

---

### 3.2 anyhow: Ergonomic Error Handling for Applications

**Source**: https://docs.rs/anyhow
**Tier**: 2 (Rust ecosystem standard, maintained by David Tolnay)

**Key Findings**:
- `anyhow` provides `anyhow::Result<T>` (alias for `Result<T, anyhow::Error>`) and `anyhow::Error` (a type-erased error wrapper) for application-level error handling.
- The `.context("message")` and `.with_context(|| format!("..."))` methods add contextual information to errors as they propagate up the call stack, creating rich error chains.
- `anyhow` is designed for applications (binaries) where the caller doesn't need to programmatically match on error variants — it prioritizes ergonomics and context richness over type specificity.
- The `bail!("message")` macro provides early return with an error, and `ensure!(condition, "message")` provides assertion-like error creation.
- Key design principle: thiserror for libraries (typed errors), anyhow for applications (context-rich errors). Using anyhow in library code is an anti-pattern because it erases type information that callers need.

**Applicability to Drift v2**: Drift's analyzer should detect the thiserror-vs-anyhow boundary: library crates using `anyhow::Error` in public APIs should be flagged as a gap (type erasure in library boundary). Application crates using raw `Box<dyn Error>` instead of `anyhow` should be flagged as missing context enrichment. The `.context()` pattern is a positive signal for error handling quality.

---

### 3.3 error-stack: Context-Aware Structured Error Reporting

**Source**: https://hash.dev/blog/announcing-error-stack
**Tier**: 2 (Production-grade, developed by HASH for their simulation engine)

**Key Findings**:
- `error-stack` was created to solve limitations HASH encountered with `thiserror` in a large, multi-threaded, multi-language codebase. The core problem: `thiserror` error chains produce flat, unhelpful messages like "Engine Error: Simulation Error: Experiment Error: Datastore Error: No such file or directory."
- `error-stack` introduces a `Report` type that wraps errors with arbitrary user-attached context. Unlike `anyhow`, which provides string context, `error-stack` supports typed, structured context attachments.
- Key capabilities: (1) automatic backtraces on every error, (2) arbitrary typed attachments (not just strings), (3) rich display formatting showing the full error context tree, (4) support for multiple error sources (not just linear chains).
- The v0.2 release added support for `#[diagnostic]` attributes for structured error reporting with suggestions and help text.
- Design philosophy: errors should carry enough context to debug the issue without needing to reproduce it. Every error should answer "what happened, where, and why."

**Applicability to Drift v2**: `error-stack`'s context model directly informs R10 (Error Context Preservation Analysis). Drift should detect whether error transformations preserve, enrich, or lose context. The "what/where/why" framework provides a scoring rubric for context preservation quality. Drift's own internal error handling could use `error-stack` for rich debugging context in development builds.

---

## 4. Interprocedural Exception Analysis (Academic Research)

### 4.1 Interprocedural Exception Analysis for Java (Set-Constraint Framework)

**Source**: https://www.researchgate.net/publication/2435417_Interprocedural_Exception_Analysis_for_Java
**Tier**: 1 (Peer-reviewed academic research)

**Key Findings**:
- Proposes a static analysis that estimates exception flows in Java programs independently of programmer-declared `throws` clauses, using a set-constraint framework.
- The analysis computes, for each method, the set of exception types that may escape (be thrown and not caught within the method). This is the "throws set" — the foundation of compositional exception analysis.
- Set constraints model exception flow as inclusion relationships: if method A calls method B, then B's throws set is included in A's potential throws set (minus what A catches).
- The analysis handles: direct throw statements, exception propagation through method calls, catch block filtering by exception type hierarchy, and finally block semantics.
- Key insight: programmer-declared `throws` clauses are often inaccurate (too broad or too narrow). Static analysis can compute more precise exception flow information.

**Applicability to Drift v2**: This paper provides the theoretical foundation for R3 (Interprocedural Error Propagation Engine). Drift's per-function error summaries are exactly the "throws sets" described here. The set-constraint framework validates the compositional approach: compute per-function summaries, then compose along call graph edges. The finding that programmer declarations are inaccurate justifies Drift's approach of analyzing actual code rather than trusting type annotations.

---

### 4.2 Interprocedural Exception Analysis for C++ (IECFG and Signed-TypeSet)

**Source**: https://research.google/pubs/interprocedural-exception-analysis-for-c/
**Tier**: 1 (Google Research, peer-reviewed)

**Key Findings**:
- Introduces the Interprocedural Exception Control Flow Graph (IECFG), which captures control flow induced by exceptions across function boundaries.
- Uses a novel "Signed-TypeSet" domain — a compact representation for sets of exception types that supports efficient set operations (union, intersection, difference) needed for compositional analysis.
- The interprocedural dataflow analysis computes, for each function, which exception types may propagate out and which are caught internally.
- The analysis results enable a "lowering transformation" that converts exception-handling code into equivalent exception-free code, making the program amenable to standard static analysis techniques.
- Key contribution: the Signed-TypeSet domain enables efficient representation of exception type sets even when the type hierarchy is deep, avoiding the exponential blowup of naive set representations.

**Applicability to Drift v2**: The IECFG concept maps to Drift's error handling topology — a graph of error flow across function boundaries. The Signed-TypeSet domain is directly applicable to Drift's error type system (R4): Drift needs efficient set operations on error types for computing propagation. The lowering transformation concept suggests Drift could "normalize" error handling patterns for analysis, abstracting away language-specific syntax.

---

### 4.3 Uncaught Exception Analysis for Java

**Source**: https://www.researchgate.net/publication/2845086_An_Uncaught_Exception_Analysis_for_Java
**Tier**: 1 (Peer-reviewed academic research)

**Key Findings**:
- Focuses specifically on detecting uncaught exceptions — exceptions that propagate to the top of the call stack without being handled.
- Uses a set-based framework similar to 4.1 but optimized for the uncaught exception detection problem.
- The analysis is sound (no false negatives for uncaught exceptions) but may produce false positives due to conservative approximation of dynamic dispatch and exception type hierarchies.
- Key finding: uncaught exception analysis is most valuable at program entry points (main methods, request handlers, event listeners) where an uncaught exception causes program termination or request failure.

**Applicability to Drift v2**: Validates Drift's focus on error handling boundaries (R7). The most critical gaps are uncaught exceptions at entry points — framework request handlers, event listeners, main functions. Drift should prioritize gap detection at these boundaries over internal function-level analysis. The soundness-vs-precision tradeoff informs Drift's design: aim for high precision (low false positives) even at the cost of some false negatives.

---

### 4.4 Demanded Abstract Interpretation (Incremental Compositional Analysis)

**Source**: https://arxiv.org/abs/2104.01270
**Tier**: 1 (Peer-reviewed, published at PLDI)

**Key Findings**:
- Presents "demanded abstract interpretation" — a framework combining incremental and demand-driven techniques for interactive-speed static analysis.
- The framework answers 95% of analysis queries within 1.2 seconds by only computing the parts of the analysis relevant to the current query, rather than analyzing the entire program.
- Key innovation: "demanded summarization" computes per-function summaries on demand, only analyzing functions reachable from the current query point. This avoids the cost of whole-program analysis.
- The approach guarantees "from-scratch consistency" — incremental results are identical to what a full re-analysis would produce.
- Experimental results show consistent interactive-speed performance even on large codebases.

**Applicability to Drift v2**: This research directly supports R9 (Incremental Error Analysis) and validates the Salsa-based query model. Drift's error analysis should be demand-driven: when querying error handling quality for a specific file or function, only analyze the relevant portion of the call graph. The 1.2-second query response time sets a concrete performance target for Drift's MCP tool responses.

---

### 4.5 Incrementalizing Production CodeQL Analyses

**Source**: https://www.researchgate.net/publication/373246740_Incrementalizing_Production_CodeQL_Analyses
**Tier**: 1 (Peer-reviewed research from GitHub/Semmle)

**Key Findings**:
- Demonstrates that production-grade static analyses (CodeQL) can be incrementalized: instead of re-analyzing from scratch on every code change, update previous results based on the diff.
- The key challenge is determining which analysis results are invalidated by a code change and which can be reused. The paper presents algorithms for efficient invalidation tracking.
- Incremental analysis achieves 10-100x speedup for typical code changes (single file edits) compared to full re-analysis.
- The approach works for interprocedural analyses, not just intraprocedural — changes in one function can invalidate results in callers/callees.
- Critical insight: the granularity of invalidation matters. Function-level granularity (invalidate all results for a changed function) provides a good balance between precision and overhead.

**Applicability to Drift v2**: Confirms the feasibility and value of incremental error analysis (R9). Function-level invalidation granularity aligns with Drift's per-function error summary model — when a function changes, invalidate its summary and propagate invalidation to direct callers. The 10-100x speedup target is achievable and critical for IDE-grade responsiveness.

---

## 5. Error Monitoring and Observability

### 5.1 Sentry SDK Error Context Model

**Source**: https://docs.sentry.io/platforms/javascript/guides/express/enriching-events/breadcrumbs/
**Tier**: 2 (Industry-leading error monitoring platform)

**Key Findings**:
- Sentry's error context model consists of multiple layers: (1) the error itself (type, message, stack trace), (2) breadcrumbs (trail of events leading to the error), (3) tags (key-value metadata for filtering), (4) user context (who was affected), (5) extra data (arbitrary structured data).
- Breadcrumbs are automatically captured for: console messages, network requests (XHR/fetch), UI interactions (clicks, inputs), navigation changes, and earlier-occurring errors. Server-side SDKs capture logging messages, database queries, and HTTP requests.
- Breadcrumbs are privacy-aware by default — they record that an input was used but not what was typed.
- The SDK supports custom breadcrumbs for application-specific events, enabling developers to add domain context to error reports.
- Sentry's `captureException` API enriches errors with the full context model, while `captureMessage` captures non-exception events with the same context.
- The `max_breadcrumbs` configuration controls memory usage (default varies by SDK, typically 100).

**Applicability to Drift v2**: Sentry's context model defines what "good" error context looks like. Drift's context preservation analysis (R10) should detect whether error handlers capture sufficient context: does the catch block log the error with structured data? Does it report to a monitoring service? Does it preserve breadcrumb-equivalent information? The breadcrumb model suggests a new metric: "context richness score" measuring how many context layers are present in error handling code.

---

### 5.2 Structured Logging for Error Context

**Source**: OWASP Logging Cheat Sheet (referenced from Section 1.1) + Sentry structured logging patterns
**Tier**: 1-2 (OWASP standard + industry practice)

**Key Findings**:
- Structured logging (JSON-formatted log entries with typed fields) is the industry standard for production error logging. Unstructured string logs are insufficient for automated analysis and alerting.
- Key fields for error log entries: timestamp, severity level, error type, error message, stack trace, request ID (for correlation), user ID (for impact assessment), and custom context fields.
- OWASP recommends: never log sensitive data (passwords, tokens, PII), always log sufficient context for forensic analysis, use correlation IDs to trace errors across distributed systems.
- The structured logging ecosystem includes: Winston (Node.js), log4j2/SLF4J (Java), slog (Go), tracing (Rust), structlog (Python).
- Anti-patterns: `console.log(error.message)` (loses stack trace), `logger.error("Error occurred")` (no context), `logger.error(JSON.stringify(user))` (PII in logs).

**Applicability to Drift v2**: Drift should detect structured vs unstructured error logging patterns. A catch block that calls `console.log("error")` is lower quality than one calling `logger.error({ error, requestId, context })`. New gap types: `unstructured-error-logging`, `sensitive-data-in-error-log` (CWE-532), `missing-correlation-id`. The structured logging detection feeds into the quality dimension of R5's multi-dimensional scoring model.

---

## 6. Resilience Engineering Patterns

### 6.1 Resilience4j: Definitive Pattern Taxonomy

**Source**: https://resilience4j.readme.io + multiple production deployment references
**Tier**: 2 (Industry-standard resilience library, successor to Netflix Hystrix)

**Key Findings**:
- Resilience4j provides six core resilience patterns as modular, composable decorators:
  1. **Circuit Breaker**: Monitors failure rates and transitions between closed (normal), open (failing, fast-fail), and half-open (testing recovery) states. Configurable failure rate threshold, wait duration in open state, and permitted calls in half-open state.
  2. **Retry**: Automatically re-executes failed operations with configurable max attempts, wait duration, and backoff strategy (fixed, exponential, exponential with jitter). Supports retry-on-exception and retry-on-result predicates.
  3. **Rate Limiter**: Controls the rate of calls to prevent overwhelming downstream services. Configurable limit for a refresh period, with timeout for waiting threads.
  4. **Bulkhead**: Isolates system resources by limiting concurrent calls. Two implementations: semaphore-based (limits concurrent calls) and thread-pool-based (isolates execution in a separate thread pool).
  5. **Time Limiter**: Limits the duration of an operation, canceling it if it exceeds the configured timeout. Prevents hanging calls from consuming resources indefinitely.
  6. **Fallback**: Not a standalone module but a pattern applied after any of the above — provides an alternative result when the primary operation fails.
- Patterns are composable: `Retry(CircuitBreaker(TimeLimiter(function)))` applies all three patterns in order.
- Each pattern emits events (success, failure, state transition) that can be monitored and alerted on.

**Applicability to Drift v2**: Resilience4j's taxonomy defines the complete set of resilience patterns Drift should detect (R11). The six patterns map to detection rules: circuit breaker (state machine pattern), retry (loop with catch and delay), rate limiter (token bucket or sliding window), bulkhead (semaphore/mutex limiting), time limiter (timeout with cancellation), fallback (catch with default value). Drift should detect both library-based usage (Resilience4j, Polly, cockatiel) and hand-rolled implementations of these patterns.

---

### 6.2 Microservice Resilience Patterns in Practice

**Source**: Multiple production references (Spring Boot + Resilience4j deployments)
**Tier**: 2-3 (Industry practice, widely documented)

**Key Findings**:
- In microservice architectures, resilience patterns are essential at service boundaries — every external call (HTTP, gRPC, database, message queue) should be protected by at least one resilience pattern.
- The recommended minimum protection stack for external calls: Timeout + Retry + Circuit Breaker. This prevents: hanging calls (timeout), transient failures (retry), and cascading failures (circuit breaker).
- Bulkhead isolation is critical for preventing a slow downstream service from consuming all threads/connections in the calling service, which would cause cascading failure across all endpoints.
- Configuration anti-patterns: retry without backoff (thundering herd), retry without circuit breaker (hammering a failing service), timeout longer than circuit breaker wait duration (inconsistent behavior).
- Health checks should verify downstream dependencies, not just the service itself. A service reporting "healthy" while its database is down provides false confidence.

**Applicability to Drift v2**: Drift should detect unprotected external calls — HTTP requests, database queries, gRPC calls, and message queue operations without resilience patterns. This is a new gap category: `unprotected-external-call`. The recommended protection stack (timeout + retry + circuit breaker) provides a scoring rubric: 0 patterns = critical gap, 1 pattern = partial protection, 3 patterns = fully protected. Configuration anti-patterns should be flagged as `resilience-misconfiguration`.

---

## 7. Async Error Handling Patterns

### 7.1 Node.js Unhandled Promise Rejections

**Source**: https://nodejs.org/api/process.html#event-unhandledrejection + multiple production incident reports
**Tier**: 1 (Node.js official documentation)

**Key Findings**:
- Starting with Node.js 15, unhandled promise rejections terminate the process by default (`--unhandled-rejections=throw`). Prior versions only emitted a deprecation warning.
- The `process.on('unhandledRejection', callback)` event allows global handling of unhandled rejections, but the official recommendation is to fix the root cause rather than rely on global handlers.
- Common causes of unhandled rejections: (1) missing `await` on async function calls, (2) missing `.catch()` on promise chains, (3) errors in `.then()` callbacks without a subsequent `.catch()`, (4) rejected promises in `Promise.all()` where one rejection masks others.
- The `process.on('uncaughtException', callback)` event catches synchronous exceptions that escape all try/catch blocks. The official guidance is to perform synchronous cleanup and exit — it is not safe to resume normal operation after an uncaught exception.
- Anti-pattern: using `process.on('unhandledRejection')` as a catch-all instead of properly handling errors at their source. This masks bugs and makes debugging harder.

**Applicability to Drift v2**: Node.js's behavior change (rejection = crash) makes `UnhandledPromise` detection a P0 reliability concern, not just a code quality issue. Drift should detect: (1) missing await on async calls, (2) promise chains without terminal `.catch()`, (3) `Promise.all()` without error handling for individual promises, (4) global rejection handlers used as a crutch instead of proper error handling. The process termination behavior means every unhandled promise is a potential production crash.

---

### 7.2 Async Error Handling Anti-Patterns

**Source**: Synthesized from typescript-eslint rules, Node.js documentation, and production incident patterns
**Tier**: 2-3 (Community-validated patterns)

**Key Findings**:
- **Callback-Promise Mixing**: Using callbacks and promises in the same function creates error handling blind spots. An error in a callback won't be caught by a promise `.catch()`, and vice versa.
- **Async void functions**: Functions declared `async` but returning `void` (not `Promise<void>`) cannot have their errors caught by the caller. Common in event handlers and Express middleware.
- **Error in .then() without .catch()**: `promise.then(onFulfilled)` without a second argument or subsequent `.catch()` means rejection in `onFulfilled` is unhandled.
- **Promise.all() partial failure**: `Promise.all()` rejects on the first failure, but the other promises continue executing. Their results (or errors) are lost. `Promise.allSettled()` is the correct choice when all results are needed.
- **Async iteration errors**: `for await...of` loops can throw on any iteration. Without a surrounding try/catch, the error propagates to the enclosing async function.
- **Timer-based async**: `setTimeout(async () => { ... })` — errors in the async callback are unhandled because `setTimeout` doesn't return a promise.

**Applicability to Drift v2**: Each anti-pattern maps to a detectable gap type: `callback-promise-mixing` (CWE-755), `async-void-function`, `promise-then-without-catch`, `promise-all-without-settled`, `unhandled-async-iteration`, `async-in-timer`. These are language-specific gaps for JavaScript/TypeScript (R8) that require understanding of async semantics beyond simple try/catch analysis.

---

### 7.3 Kotlin Coroutines Structured Concurrency and Exception Handling

**Source**: https://kotlinlang.org/docs/exception-handling.html (official Kotlin documentation)
**Tier**: 1 (Official language documentation)

**Key Findings**:
- Kotlin's structured concurrency model propagates exceptions through the coroutine hierarchy: an unhandled exception in a child coroutine cancels the parent and all sibling coroutines.
- `supervisorScope` and `SupervisorJob` break this propagation — child failures don't cancel siblings, enabling independent failure handling.
- `CoroutineExceptionHandler` is a context element that handles uncaught exceptions in root coroutines (similar to `Thread.uncaughtExceptionHandler`). It only works with `launch`, not `async` (which exposes exceptions via `Deferred.await()`).
- The `launch` vs `async` distinction is critical: `launch` propagates exceptions automatically (fire-and-forget), while `async` exposes them to the caller via `await()`. Forgetting to `await()` an `async` result means its exception is silently lost.
- Exception handling in coroutines differs fundamentally from thread-based concurrency — the structured hierarchy means errors have well-defined propagation paths.

**Applicability to Drift v2**: Kotlin coroutine error handling requires language-specific analysis (R8). Drift should detect: (1) missing `supervisorScope` where independent failure handling is needed, (2) `async` without `await` (analogous to floating promises), (3) missing `CoroutineExceptionHandler` in root coroutines, (4) `try/catch` around `launch` (doesn't work — exceptions propagate through the job hierarchy, not the call stack). The structured concurrency model is a paradigm Drift should understand natively.

---

## 8. IDE-Grade Analyzers

### 8.1 rust-analyzer: Resilient Parsing and Incremental Analysis

**Source**: https://rust-analyzer.github.io/blog/2023/07/24/durable-incrementality.html + https://rust-analyzer.github.io/book/contributing/syntax.html
**Tier**: 1 (Production IDE analyzer, reference implementation for incremental analysis)

**Key Findings**:
- rust-analyzer's parsing is lossless (the syntax tree represents the input exactly, even if invalid) and resilient (the parser extracts as many valid syntax tree fragments as possible from invalid input). This enables analysis of incomplete or erroneous code — critical for IDE use cases.
- The incremental computation model uses Salsa, a framework for on-demand, incrementalized computation inspired by adapton and rustc's query system. The key idea: define the program as a set of queries (functions K → V) with automatic dependency tracking and memoization.
- "Durable incrementality" means analysis results survive IDE restarts by persisting the Salsa database to disk. On restart, only changed inputs need re-analysis.
- Critical invariant: "Typing inside a function body never invalidates global derived data." This means per-function analysis results are isolated — editing one function doesn't trigger re-analysis of unrelated functions.
- The Salsa framework handles dependency tracking automatically: when a query reads another query's result, a dependency edge is recorded. When an input changes, only queries transitively depending on that input are invalidated.
- rust-analyzer achieves sub-100ms response times for most operations on large codebases (100K+ lines) through this incremental model.

**Applicability to Drift v2**: rust-analyzer is the reference architecture for Drift's incremental analysis (R9). The function-body isolation invariant is directly applicable: editing a function body should only invalidate that function's error summary and its direct callers' propagation results. The Salsa framework is the recommended computation engine. The sub-100ms response time target is achievable and should be Drift's performance goal for incremental error analysis.

---

### 8.2 Salsa Framework: On-Demand Incremental Computation

**Source**: https://github.com/salsa-rs/salsa
**Tier**: 2 (Production framework used by rust-analyzer and rustc)

**Key Findings**:
- Salsa defines programs as sets of queries. Each query is a memoized function from key to value. Queries can depend on other queries, forming a dependency graph.
- When an input changes, Salsa uses a "red-green" algorithm: mark all transitively dependent queries as potentially stale (red), then lazily re-evaluate them. If a re-evaluated query produces the same result as before, its dependents are marked green (still valid) — this "early cutoff" prevents unnecessary re-computation.
- Salsa supports two types of queries: "input" queries (set by the user, e.g., file contents) and "derived" queries (computed from other queries, e.g., parsed AST, error analysis results).
- The framework is generic — it works for any computation that can be expressed as queries with deterministic results. Error analysis is a natural fit: file contents → parsed AST → error profile → propagation chains → quality assessment.
- Salsa's overhead is minimal: the dependency tracking and memoization add ~5-10% overhead compared to non-incremental computation, but save 90-99% of computation on incremental updates.

**Applicability to Drift v2**: Salsa is the recommended computation framework for Drift v2's entire analysis pipeline, not just error handling. For error analysis specifically, the query chain would be: `file_content(FileId)` → `parsed_ast(FileId)` → `file_error_profile(FileId)` → `function_error_summary(FunctionId)` → `error_propagation_chains()` → `error_topology()` → `error_quality_assessment()`. Each level is automatically memoized and incrementally updated.

---

## 9. Error Handling Quality Metrics

### 9.1 Exception Handling Anti-Pattern Evolution Study

**Source**: https://link.springer.com/10.1186/s13173-019-0095-5
**Tier**: 1 (Peer-reviewed empirical study, Journal of the Brazilian Computer Society)

**Key Findings**:
- Studied the evolution of exception handling anti-patterns in a long-lived, large-scale Java project over its entire history.
- Identified that the quality of exception handling code is directly affected by: (1) the absence or lack of awareness of an explicit exception handling policy, and (2) the silent accumulation of exception handling anti-patterns over time.
- Key anti-patterns tracked: generic catch (catching Exception/Throwable), empty catch blocks, catch-and-ignore, destructive wrapping (losing original exception context), catch-and-log-and-rethrow (duplicate logging), and overcatching (catching more exception types than necessary).
- Finding: anti-patterns tend to accumulate over time unless actively monitored. Projects without explicit exception handling policies show monotonically increasing anti-pattern density.
- The study found a correlation between exception handling anti-pattern density and defect density — projects with more anti-patterns had more bugs.

**Applicability to Drift v2**: This study validates Drift's core value proposition — continuous monitoring of error handling quality prevents anti-pattern accumulation. Drift should track anti-pattern density over time (trend analysis) and alert when density increases. The correlation between anti-pattern density and defect density provides the business case for error handling analysis. The identified anti-patterns map directly to Drift gap types.

---

### 9.2 Exception Handling Defects: Empirical Study

**Source**: https://www.researchgate.net/publication/262277939_Exception_Handling_Defects_An_Empirical_Study
**Tier**: 1 (Peer-reviewed empirical study)

**Key Findings**:
- Found that the density of defects closely related to exception handling constructs is relatively high compared to overall defect density — exception handling code is disproportionately buggy.
- This implies a relationship between the use of exception handling constructs and the risk of defects — more complex exception handling doesn't necessarily mean better error handling.
- The study categorized exception handling defects into: incorrect exception type caught, missing exception handler, incorrect handler logic, resource leak in exception path, and exception masking (catching and rethrowing a different type without preserving the original).
- Key insight: exception handling code is rarely tested as thoroughly as normal code paths, leading to latent defects that only manifest under error conditions.

**Applicability to Drift v2**: Validates the need for Drift's error handling analysis — exception handling code is a high-defect-density area that benefits disproportionately from static analysis. The defect categories map to Drift gap types: incorrect type → `generic-catch`, missing handler → `missing-boundary`, incorrect logic → `swallowed-error`, resource leak → `resource-leak-in-error-path`, masking → `rethrow-without-context`. The testing insight suggests Drift should flag untested error handling paths.

---

### 9.3 Multi-Dimensional Quality Scoring (SonarQube Model)

**Source**: https://docs.sonarsource.com/sonarqube-server/2025.2/user-guide/rules/software-qualities/
**Tier**: 2 (Industry-standard quality model)

**Key Findings**:
- SonarQube's quality model assesses code across three independent dimensions: Security (protection from unauthorized access), Reliability (maintaining performance under stated conditions), and Maintainability (ease of modification and understanding).
- Each dimension has its own rating (A-E) computed from the density and severity of issues in that dimension. A single piece of code can have different ratings across dimensions.
- The model recognizes that a single code issue can impact multiple dimensions simultaneously — an empty catch block impacts both reliability (error is silently lost) and security (error condition may bypass security checks).
- Quality gates enforce minimum thresholds across all dimensions — code must pass all dimension thresholds to be considered acceptable.
- The rating system uses a ratio-based approach: rating = f(issue_density, severity_distribution), where issue density is normalized by code size.

**Applicability to Drift v2**: SonarQube's multi-dimensional model directly informs R5 (Multi-Dimensional Quality Scoring). Drift's error handling quality should be assessed across four dimensions (coverage, depth, quality, security) with independent scores. The composite score should be a weighted combination, not a simple average. Quality gates should enforce minimum thresholds per dimension — a project with 100% coverage but 0% security score should not pass.

---

## 10. Language-Specific Error Handling Patterns

### 10.1 Multi-Language Error Handling Taxonomy

**Source**: Synthesized from official language documentation for 10 languages
**Tier**: 1-2 (Official documentation per language)

The following taxonomy captures the error handling paradigm, key constructs, and common anti-patterns for each language Drift v2 should support:

| Language | Paradigm | Throw/Raise | Catch/Handle | Error Type | Key Anti-Patterns |
|----------|----------|-------------|-------------|------------|-------------------|
| JavaScript/TypeScript | Exception-based | `throw` | `try/catch/finally` | `Error` class hierarchy | Floating promises, empty catch, callback-promise mixing |
| Java | Checked + unchecked exceptions | `throw` | `try/catch/finally` | `Throwable` hierarchy | Generic catch, swallowed checked exceptions, missing try-with-resources |
| Python | Exception-based | `raise` | `try/except/else/finally` | `BaseException` hierarchy | Bare except, broad except, raise without from |
| Go | Return-value based | `return err` | `if err != nil` | `error` interface | Ignored error return, `_` for error, missing error wrapping |
| Rust | Return-value based | `Err(e)` / `panic!()` | `match` / `?` operator | `Result<T,E>` / `Option<T>` | `.unwrap()` in library code, `panic!()` in non-test, empty `.expect("")` |
| C# | Exception-based | `throw` | `try/catch/finally` | `Exception` hierarchy | Generic catch, missing `using` for IDisposable, catch-and-rethrow losing stack |
| Kotlin | Exception-based + coroutines | `throw` | `try/catch/finally` | `Throwable` hierarchy | Uncaught coroutine exceptions, async without await, missing supervisorScope |
| Swift | Typed throws | `throw` | `do/try/catch` | `Error` protocol | Force-try (`try!`), untyped catch, ignoring Result |
| C++ | Exception-based | `throw` | `try/catch` | Any type (typically `std::exception`) | `catch(...)` without rethrow, exception in destructor, missing noexcept |
| PHP | Exception-based | `throw` | `try/catch/finally` | `Throwable` hierarchy | `@` error suppression, generic catch, missing error_reporting config |

---

### 10.2 Go Error Handling: Return-Value Paradigm

**Source**: https://go.dev/blog/error-handling-and-go + Go 1.13+ errors package documentation
**Tier**: 1 (Official Go documentation)

**Key Findings**:
- Go uses explicit error return values instead of exceptions. Functions return `(result, error)` tuples, and callers check `if err != nil`.
- Go 1.13 introduced error wrapping via `fmt.Errorf("context: %w", err)` — the `%w` verb wraps the error, preserving the chain for `errors.Is()` and `errors.As()` inspection. Using `%v` instead of `%w` formats the error as a string, breaking the chain.
- `errors.Is(err, target)` checks if any error in the chain matches the target (by value equality). `errors.As(err, &target)` checks if any error in the chain can be assigned to the target type. These replace direct comparison (`err == ErrNotFound`) and type assertion (`err.(*MyError)`).
- Sentinel errors (`var ErrNotFound = errors.New("not found")`) are the Go idiom for well-known error conditions. They should be package-level variables, not created inline.
- Anti-patterns: `_ = functionReturningError()` (explicitly ignoring error), calling a function that returns error without capturing the error value, wrapping with `%v` instead of `%w` (breaks error chain).

**Applicability to Drift v2**: Go's return-value paradigm requires fundamentally different analysis than exception-based languages. Drift must detect: (1) ignored error returns (the `_` pattern and uncaptured returns), (2) `%v` vs `%w` wrapping (context preservation), (3) direct comparison vs `errors.Is/As` (proper chain inspection), (4) sentinel error patterns. These are Go-specific gap types (R8) that don't exist in exception-based languages.

---

### 10.3 Java Exception Handling: Checked vs Unchecked

**Source**: https://docs.oracle.com/javase/tutorial/essential/exceptions/ + production best practices
**Tier**: 1 (Official Java documentation)

**Key Findings**:
- Java's exception hierarchy: `Throwable` → `Error` (unrecoverable, should not be caught) and `Exception` → `RuntimeException` (unchecked) and checked exceptions.
- Checked exceptions must be declared in method signatures (`throws`) or caught — the compiler enforces this. Unchecked exceptions (RuntimeException subclasses) have no such requirement.
- `try-with-resources` (Java 7+) automatically closes `AutoCloseable` resources, even when exceptions occur. Missing try-with-resources is a resource leak risk and a common defect.
- Modern best practice: favor unchecked exceptions for non-recoverable errors in multi-layered architectures to avoid boilerplate `throws` declarations propagating through every layer.
- Anti-patterns: catching `Throwable` (catches `Error` types like `OutOfMemoryError` that should crash the JVM), `catch(Exception e) { e.printStackTrace(); }` (swallowed error with only console output), checked exception swallowing (catch checked, throw unchecked without wrapping).

**Applicability to Drift v2**: Java-specific gap detection (R8) should include: `catch-throwable` (catching errors that should crash), `missing-try-with-resources` (AutoCloseable without try-with-resources), `checked-exception-swallowing` (catch checked → throw unchecked without cause), `throws-exception` (overly broad throws declaration). The checked/unchecked distinction affects propagation analysis — checked exceptions have compiler-enforced handling, unchecked do not.

---

### 10.4 Python Exception Handling: Context and Chaining

**Source**: https://docs.python.org/3/library/exceptions.html + PEP 3134 (Exception Chaining)
**Tier**: 1 (Official Python documentation)

**Key Findings**:
- Python's exception hierarchy: `BaseException` → `Exception` (for application errors) and `BaseException` → `KeyboardInterrupt`, `SystemExit`, `GeneratorExit` (should not be caught by application code).
- `raise ... from err` (PEP 3134) explicitly chains exceptions, setting `__cause__`. `raise ... from None` suppresses implicit chaining. Without `from`, Python still sets `__context__` (implicit chaining) but the display is different.
- Bare `except:` catches everything including `KeyboardInterrupt` and `SystemExit` — this prevents Ctrl+C from working and `sys.exit()` from exiting. Always use `except Exception:` at minimum.
- `except Exception as e: pass` is the Python equivalent of an empty catch block — the error is silently swallowed.
- Python 3.11+ introduced `ExceptionGroup` and `except*` for handling multiple simultaneous exceptions (e.g., from `asyncio.TaskGroup`).
- Context managers (`with` statement) are Python's equivalent of try-with-resources — they ensure cleanup even when exceptions occur.

**Applicability to Drift v2**: Python-specific gap detection (R8): `bare-except` (catches BaseException), `broad-except` (catches Exception where specific types are appropriate), `raise-without-from` (loses exception context), `except-pass` (swallowed error), `missing-context-manager` (resource without `with`). The `ExceptionGroup` pattern is a new construct Drift should understand for Python 3.11+ codebases.

---

### 10.5 Swift Error Handling: Typed Throws and Result

**Source**: https://docs.swift.org/swift-book/documentation/the-swift-programming-language/errorhandling/ + SE-0413 (Typed Throws)
**Tier**: 1 (Official Swift documentation)

**Key Findings**:
- Swift uses `throws` functions with `do/try/catch` blocks. The `Error` protocol is the base type for all throwable errors, and enums conforming to `Error` are the idiomatic pattern.
- Swift 6 introduced typed throws (SE-0413): functions can declare the specific error type they throw (`func load() throws(NetworkError)`), enabling compile-time checking of catch block completeness.
- `try?` converts a throwing call to an optional (nil on error) — convenient but loses all error information. `try!` force-unwraps, crashing on error — should only be used when failure is logically impossible.
- `Result<Success, Failure>` type provides an alternative to throws for cases where errors need to be stored, passed around, or handled asynchronously.
- Anti-patterns: `try!` in production code (crash on error), untyped `catch` blocks that don't inspect the error, `try?` when error information is needed for recovery.

**Applicability to Drift v2**: Swift-specific gap detection (R8): `force-try` (`try!` in non-test code), `untyped-catch` (catch block that doesn't match specific error types), `try-optional-losing-context` (`try?` where error information is needed). Typed throws (Swift 6) enables more precise analysis — Drift can verify catch block completeness against declared error types.

---

### 10.6 C# Exception Handling: IExceptionHandler and Middleware

**Source**: https://learn.microsoft.com/en-us/aspnet/core/fundamentals/error-handling + ASP.NET Core 8.0 documentation
**Tier**: 1 (Official Microsoft documentation)

**Key Findings**:
- ASP.NET Core 8.0 introduced `IExceptionHandler` as the preferred mechanism for global exception handling, replacing custom middleware patterns. It provides a clean, structured, and centralized error-handling system.
- The exception handling middleware should be registered early in the pipeline (before routing, controllers, etc.) to catch exceptions from all downstream middleware.
- `using` statements (C#'s equivalent of try-with-resources) ensure `IDisposable`/`IAsyncDisposable` resources are cleaned up. Missing `using` is a resource leak risk.
- C# supports exception filters (`catch (Exception e) when (e is not OperationCanceledException)`) for selective catching without unwinding the stack.
- Anti-patterns: `catch (Exception) { throw; }` without additional logic (pointless catch-and-rethrow), `catch (Exception e) { throw e; }` (resets stack trace — should use `throw;` without argument), missing `IExceptionHandler` registration in ASP.NET Core apps.

**Applicability to Drift v2**: C#-specific gap detection (R8): `catch-rethrow-reset-stack` (`throw e` instead of `throw`), `missing-using-statement` (IDisposable without using), `missing-global-exception-handler` (ASP.NET Core without IExceptionHandler). The exception filter pattern (`when` clause) is a positive signal for error handling quality — it enables precise catching without stack unwinding.

---

## 11. Incremental Error Analysis

### 11.1 Salsa Framework: Incremental Computation Model

**Source**: https://github.com/salsa-rs/salsa + https://medium.com/@eliah.lakhin/salsa-algorithm-explained-c5d6df1dd291
**Tier**: 2 (Production framework, used by rust-analyzer and rustc)

**Key Findings**:
- Salsa's core algorithm: (1) define inputs (mutable data set by the user), (2) define derived queries (computed from inputs or other queries), (3) when an input changes, Salsa marks dependent queries as potentially stale, (4) on next access, re-evaluate stale queries, (5) if the result is unchanged, propagate "green" (still valid) to dependents — this is "early cutoff."
- The "red-green" marking algorithm: Red = potentially stale (input changed), Green = verified still valid (re-evaluated and result unchanged). Early cutoff means that if a query's result doesn't change despite its input changing, its dependents are not re-evaluated.
- Salsa supports "interning" — deduplicating values to enable cheap equality checks. This is critical for error types: intern error type names so that equality checks are pointer comparisons, not string comparisons.
- The framework handles cycles (queries that depend on each other) through configurable cycle recovery strategies.
- Performance characteristics: first computation is ~5-10% slower than non-incremental (due to dependency tracking overhead). Subsequent incremental updates are 10-100x faster for typical changes.

**Applicability to Drift v2**: Salsa is the recommended computation engine for Drift v2's entire analysis pipeline (R9, MASTER_RECOMMENDATIONS M1). For error analysis, the query graph would be:
```
file_content(FileId) [input]
  → parsed_ast(FileId) [derived]
    → file_error_profile(FileId) [derived]
      → function_error_summary(FunctionId) [derived]
        → error_propagation_chains() [derived]
          → error_topology() [derived]
            → error_quality_assessment() [derived]
```
Early cutoff is critical: if editing a function body doesn't change its error summary (e.g., reformatting), no downstream re-computation occurs.

---

### 11.2 Durable Incrementality (rust-analyzer)

**Source**: https://rust-analyzer.github.io/blog/2023/07/24/durable-incrementality.html
**Tier**: 2 (Production implementation, detailed technical blog)

**Key Findings**:
- "Durable incrementality" extends incremental computation across IDE restarts. Instead of re-analyzing the entire codebase on startup, persist the Salsa database to disk and only re-analyze files that changed since the last session.
- The naive approach (invalidate all transitive dependents of changed inputs) is too aggressive — it re-computes too much. The durable approach uses content hashing: compare the hash of the current file content with the stored hash. If unchanged, all derived queries are still valid.
- For changed files, the incremental re-analysis follows the normal Salsa algorithm: re-evaluate the file's derived queries, and if results are unchanged (early cutoff), stop propagation.
- Implementation detail: the Salsa database is serialized to a single file on disk. On startup, it's deserialized and validated against current file system state.
- This approach reduces IDE startup time from minutes (full re-analysis) to seconds (incremental validation) for large codebases.

**Applicability to Drift v2**: Durable incrementality is essential for Drift's CLI and MCP tool use cases. When Drift is invoked on a codebase it has analyzed before, it should load the persisted analysis database and only re-analyze changed files. This transforms Drift from a batch tool (re-analyze everything) to an incremental tool (analyze only changes). The content-hashing approach for validation is straightforward to implement with Salsa.

---

### 11.3 Demanded Summarization for Compositional Analysis

**Source**: https://dl.acm.org/doi/10.1145/3648441
**Tier**: 1 (Peer-reviewed, published at OOPSLA 2024)

**Key Findings**:
- "Demanded summarization" is the first algorithm for incremental compositional analysis in arbitrary abstract domains that guarantees from-scratch consistency.
- The approach analyzes individual procedures using demanded analysis, computing summaries on demand for procedure calls. This means only procedures reachable from the current query are analyzed.
- Key advantage over whole-program analysis: for a query about a specific function's error handling, only that function and its transitive callees need analysis — not the entire codebase.
- The algorithm supports arbitrary abstract domains, meaning it can be applied to error handling analysis (where the abstract domain is the set of possible error types at each program point).
- Experimental results show interactive-speed performance: most queries answered in under 2 seconds, even on large codebases.

**Applicability to Drift v2**: Demanded summarization is the theoretical foundation for Drift's on-demand error analysis. When the MCP tool receives a query about a specific file's error handling, Drift should compute only the relevant portion of the error topology — not the entire codebase's topology. This enables sub-second MCP responses even on million-line codebases.

---

## 12. Framework-Specific Error Handling Detection

### 12.1 Frontend Framework Error Boundaries

**Source**: Official documentation for React, Vue, Angular, Svelte, Next.js
**Tier**: 1 (Official framework documentation)

**React Error Boundaries**:
- Class components implementing `componentDidCatch(error, errorInfo)` and `static getDerivedStateFromError(error)` lifecycle methods.
- Error boundaries catch errors during rendering, in lifecycle methods, and in constructors of the whole tree below them.
- Error boundaries do NOT catch errors in: event handlers, asynchronous code (setTimeout, requestAnimationFrame), server-side rendering, or errors thrown in the error boundary itself.
- The `react-error-boundary` library provides a functional component wrapper (`ErrorBoundary`) with `fallbackRender`, `onError`, and `onReset` props.
- Detection signals: class with `componentDidCatch` method, class with `getDerivedStateFromError` static method, `<ErrorBoundary>` JSX element.

**Next.js Error Handling**:
- App Router: `error.tsx` files in route segments automatically create error boundaries. `global-error.tsx` handles root layout errors.
- The `error.tsx` component receives `error` and `reset` props, enabling error display and retry functionality.
- Detection signals: file named `error.tsx`/`error.js` in `app/` directory, `global-error.tsx` at app root.

**Vue Error Handling**:
- `app.config.errorHandler` — global error handler for uncaught errors from any component.
- `onErrorCaptured` lifecycle hook — component-level error boundary (captures errors from descendant components).
- `errorCaptured` option in Options API.
- Detection signals: `app.config.errorHandler` assignment, `onErrorCaptured()` call, `errorCaptured` option.

**Angular Error Handling**:
- `ErrorHandler` class — global error handler, replaceable via dependency injection.
- Custom `ErrorHandler` implementations can log errors, display user-friendly messages, and report to monitoring services.
- HTTP interceptors for handling HTTP errors globally.
- Detection signals: class extending `ErrorHandler`, `@Injectable()` with `ErrorHandler` in providers.

**Svelte Error Handling**:
- `<svelte:boundary>` element (Svelte 5) — component-level error boundary with `onerror` handler.
- `handleError` hook in `hooks.server.ts` and `hooks.client.ts` for global error handling.
- Detection signals: `<svelte:boundary>` element, `handleError` export in hooks files.

**Applicability to Drift v2**: Each framework has distinct error boundary patterns that Drift must detect (R7). The detection signals listed above should be encoded as declarative rules in TOML configuration. Missing error boundaries at route/page level should be flagged as `missing-framework-boundary`. The distinction between what error boundaries catch and don't catch (e.g., React boundaries don't catch event handler errors) should inform gap detection — an app with error boundaries but no event handler error handling still has gaps.

---

### 12.2 Backend Framework Error Handling

**Source**: Official documentation for Express, NestJS, Spring, Django, Flask, FastAPI, Laravel, ASP.NET Core
**Tier**: 1 (Official framework documentation)

**Express.js Error Handling**:
- Error-handling middleware: functions with 4 parameters `(err, req, res, next)`. Must be registered after all route handlers.
- `express-async-errors` package or manual wrapping needed for async route handlers (Express 4). Express 5 natively handles async errors.
- Detection signals: function with 4 parameters where first is named `err`/`error`, `app.use()` with error middleware.

**NestJS Error Handling**:
- Exception filters: classes decorated with `@Catch()` implementing `ExceptionFilter` interface.
- Built-in `HttpException` hierarchy for HTTP-specific errors.
- Global filters via `app.useGlobalFilters()` or `APP_FILTER` provider.
- Detection signals: `@Catch()` decorator, `implements ExceptionFilter`, `useGlobalFilters()` call.

**Spring Boot Error Handling**:
- `@ControllerAdvice` + `@ExceptionHandler` — global exception handling for all controllers.
- `ResponseEntityExceptionHandler` base class for customizing Spring's default exception handling.
- `@ResponseStatus` annotation for mapping exceptions to HTTP status codes.
- Detection signals: `@ControllerAdvice` annotation, `@ExceptionHandler` annotation, `extends ResponseEntityExceptionHandler`.

**Django Error Handling**:
- Custom error views: `handler400`, `handler403`, `handler404`, `handler500` in URL configuration.
- Middleware-based error handling via `process_exception()` method.
- `DEBUG = False` in production to prevent stack trace exposure.
- Detection signals: `handler404`/`handler500` assignments in urls.py, `process_exception` method in middleware classes.

**Flask Error Handling**:
- `@app.errorhandler(404)` decorator for registering error handlers by HTTP status code or exception type.
- `app.register_error_handler()` for programmatic registration.
- Detection signals: `@errorhandler` decorator, `register_error_handler()` call.

**FastAPI Error Handling**:
- `@app.exception_handler(ExceptionClass)` for custom exception handlers.
- `HTTPException` for HTTP-specific errors with status codes.
- Starlette's `ServerErrorMiddleware` for unhandled exceptions.
- Detection signals: `@exception_handler` decorator, `HTTPException` usage.

**Laravel Error Handling**:
- `App\Exceptions\Handler` class — centralized exception handling.
- `report()` method for logging, `render()` method for HTTP responses.
- `$dontReport` array for exceptions that should not be logged.
- Detection signals: class extending `ExceptionHandler`, `report()`/`render()` methods.

**ASP.NET Core Error Handling**:
- `IExceptionHandler` interface (ASP.NET Core 8+) — the preferred modern approach.
- `UseExceptionHandler()` middleware for global exception handling.
- `ProblemDetails` for RFC 7807-compliant error responses.
- Detection signals: class implementing `IExceptionHandler`, `UseExceptionHandler()` call, `ProblemDetails` usage.

**Applicability to Drift v2**: Each backend framework has a specific error handling registration pattern. Drift should detect: (1) whether the framework's error handling mechanism is registered (missing = `missing-framework-boundary`), (2) whether it covers all error types (partial coverage = `incomplete-framework-boundary`), (3) whether it follows framework best practices (e.g., Express error middleware must have 4 parameters). The declarative TOML rule format (R7) should encode these detection signals per framework.

---

### 12.3 Server-Side Runtime Error Handling

**Source**: Official documentation for Go (Gin, Echo), Rust (Actix, Axum, Rocket)
**Tier**: 1 (Official framework documentation)

**Gin (Go)**:
- `gin.Recovery()` middleware — recovers from panics and returns 500 status.
- Custom recovery middleware via `gin.CustomRecovery()`.
- Error handling via `c.Error(err)` to collect errors during request processing.
- Detection signals: `Recovery()` or `CustomRecovery()` middleware registration.

**Echo (Go)**:
- `HTTPErrorHandler` — customizable global error handler.
- `echo.DefaultHTTPErrorHandler` as the default implementation.
- Middleware-based error handling with `echo.MiddlewareFunc`.
- Detection signals: `HTTPErrorHandler` assignment, custom error handler function.

**Actix-web (Rust)**:
- `ResponseError` trait — implement for custom error types to control HTTP response.
- `web::ErrorHandlers` middleware for handling specific HTTP error codes.
- `actix_web::Error` wraps any error implementing `ResponseError`.
- Detection signals: `impl ResponseError for`, `ErrorHandlers::new()` usage.

**Axum (Rust)**:
- `IntoResponse` trait — implement for error types to convert to HTTP responses.
- `HandleError` layer for converting infallible services to fallible ones.
- Tower middleware for error handling at the service layer.
- Detection signals: `impl IntoResponse for`, error type implementations.

**Rocket (Rust)**:
- `#[catch(404)]` attribute for registering error catchers by status code.
- `register()` method on `Rocket` instance for mounting catchers.
- `Responder` trait for custom error responses.
- Detection signals: `#[catch()]` attribute, `.register()` call with catchers.

**Applicability to Drift v2**: Go and Rust web frameworks have distinct error handling patterns that differ from exception-based frameworks. Go frameworks use middleware recovery from panics (analogous to global exception handlers). Rust frameworks use trait implementations for error-to-response conversion. Drift should detect both patterns and flag missing implementations as `missing-framework-boundary`.

---

## 13. Research Summary

### Sources by Tier

**Tier 1 — Authoritative (11 sources)**:
1. OWASP Error Handling Cheat Sheet
2. OWASP Top 10 2025 A10
3. MITRE CWE-703 Hierarchy
4. OWASP Proactive Controls C10
5. Facebook Infer Pulse
6. Interprocedural Exception Analysis for Java (academic)
7. Interprocedural Exception Analysis for C++ (Google Research)
8. Uncaught Exception Analysis for Java (academic)
9. Demanded Abstract Interpretation (PLDI)
10. Incrementalizing Production CodeQL Analyses (GitHub/Semmle)
11. Demanded Summarization for Compositional Analysis (OOPSLA 2024)

**Tier 2 — Industry Expert (11 sources)**:
1. SonarQube Multi-Quality Rule Model
2. Semgrep Taint Analysis
3. Google Error Prone Bug Patterns
4. PMD Error Handling Rules
5. typescript-eslint Promise Rules
6. CodeQL Code-as-Data Analysis
7. thiserror / anyhow / error-stack (Rust ecosystem)
8. Sentry SDK Error Context Model
9. Resilience4j Pattern Taxonomy
10. rust-analyzer / Salsa Framework
11. Exception Handling Anti-Pattern Evolution Study

**Tier 3 — Community Validated (supplementary)**:
- Node.js unhandled rejection patterns
- Async error handling anti-patterns
- Framework-specific error handling documentation (20+ frameworks)
- Multi-language error handling taxonomy (10 languages)

### Key Themes Across Sources

1. **Compositional Analysis**: The academic consensus (Infer, set-constraint papers, demanded summarization) converges on per-function summaries composed along call graph edges. This is the architecture Drift v2 should adopt.

2. **Multi-Dimensional Quality**: SonarQube, academic studies, and OWASP all recognize that error handling quality is multi-dimensional (security, reliability, maintainability). A single score is insufficient.

3. **Incremental-First**: rust-analyzer, Salsa, CodeQL incremental research, and demanded summarization all demonstrate that incremental analysis is both feasible and essential for IDE-grade responsiveness. The 10-100x speedup for incremental updates is consistently reported.

4. **Security as First-Class Concern**: OWASP A10:2025, CWE-703 hierarchy, and the information disclosure patterns establish error handling as a security concern, not just a code quality concern. Enterprise adoption requires CWE/OWASP mapping.

5. **Language-Specific Semantics**: Error handling paradigms vary fundamentally across languages (exceptions vs return values vs typed throws). A universal analyzer must understand each paradigm's specific anti-patterns and quality signals.

6. **Framework Boundary Detection**: Every major framework has a specific error handling registration pattern. Missing framework-level error handling is the highest-impact gap because it affects all requests/events, not just individual functions.

7. **Context Preservation**: error-stack, Sentry, and OWASP all emphasize that errors must carry sufficient context for debugging. The quality of error context (what/where/why) is a measurable dimension of error handling quality.

8. **Zero False Positive Target**: SonarQube, Error Prone, and Infer Pulse all prioritize precision over recall. Drift should only flag patterns that are definitively problematic, accepting some false negatives to maintain developer trust.

9. **Resilience Beyond Error Handling**: Resilience4j and microservice patterns show that error handling is one layer of a broader resilience strategy. Drift should detect resilience patterns (circuit breaker, retry, bulkhead) as complementary to error handling.

10. **Anti-Pattern Accumulation**: The empirical studies show that error handling anti-patterns accumulate silently over time unless actively monitored. This validates Drift's continuous analysis model — periodic scanning catches drift before it becomes technical debt.

---

*Research completed February 2026. 22 primary sources across 13 topic areas. All sources verified and accessible at time of research.*