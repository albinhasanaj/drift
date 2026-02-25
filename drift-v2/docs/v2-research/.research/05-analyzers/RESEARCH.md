# 05 Analyzers — External Research

> Phase 3: Verifiable best practices from trusted sources, applied to Drift's analyzer system.

---

## R1: rust-analyzer Architecture — Incremental Semantic Analysis at Scale

**Source**: rust-analyzer Architecture Documentation
https://rust-analyzer.github.io/book/contributing/architecture.html
**Type**: Tier 1 (Authoritative — Official rust-analyzer documentation)
**Accessed**: 2026-02-06

**Source**: "The Heart of a Language Server" — rust-analyzer Blog
https://rust-analyzer.github.io/blog/2023/12/26/the-heart-of-a-language-server.html
**Type**: Tier 1 (Official blog)
**Accessed**: 2026-02-06

**Source**: "Durable Incrementality" — rust-analyzer Blog
https://rust-analyzer.github.io/blog/2023/07/24/durable-incrementality.html
**Type**: Tier 1 (Official blog)
**Accessed**: 2026-02-06

**Key Findings**:

1. **Layered Architecture with Clear Boundaries**: rust-analyzer separates concerns into distinct crates with explicit API boundaries:
   - `syntax` — Pure syntax tree, no semantic info, completely independent
   - `hir-def`, `hir-ty` — Low-level semantic analysis with ECS flavor
   - `hir` — High-level API boundary, OO-flavored facade
   - `ide` — IDE features built on semantic model, POD types only

2. **Salsa-Based Incremental Computation**: Uses the Salsa framework for on-demand, incrementalized computation. Key insight: "typing inside a function's body never invalidates global derived data." This is achieved through careful query design where function bodies are isolated from module-level analysis.

3. **Syntax Tree as Value Type**: "The tree is fully determined by the contents of its syntax nodes, it doesn't need global context (like an interner) and doesn't store semantic info." This enables parallel parsing and clean separation of concerns.

4. **Source-to-HIR Mapping Pattern**: A recursive pattern for resolving syntax to semantic elements: "We first resolve the parent syntax node to the parent hir element. Then we ask the hir parent what syntax children does it have. Then we look for our node in the set of children." This is described as an "uber-IDE pattern" present in Roslyn and Kotlin.

5. **Cancellation via Unwinding**: Long-running analyses can be cancelled by checking a global revision counter. If incremented, the analysis panics with a special `Cancelled` value, caught at the IDE boundary.


**Applicability to Drift**:

This is directly relevant to Drift's analyzer architecture. Key gaps and opportunities:

- **Drift lacks clear API boundaries**: The analyzer crates mix concerns. rust-analyzer's strict layering (syntax → hir-* → hir → ide) should be adopted.
- **No incremental analysis**: Drift re-analyzes everything on each scan. Salsa-style query-based incrementality would dramatically improve performance.
- **Semantic info mixed with syntax**: Drift's analyzers store semantic info alongside syntax. Separating these (like rust-analyzer's syntax crate) would enable parallel parsing.
- **Missing cancellation mechanism**: Long-running analyses can't be cancelled. The revision-counter + panic approach is elegant and should be adopted.

**Confidence**: Very High — rust-analyzer is the reference implementation for IDE-grade semantic analysis in Rust, processing millions of lines of code with sub-second response times.

---

## R2: Roslyn Semantic Model — Compiler-as-a-Service Architecture

**Source**: Microsoft Learn — "Get started with semantic analysis"
https://learn.microsoft.com/en-us/dotnet/csharp/roslyn-sdk/get-started/semantic-analysis
**Type**: Tier 1 (Authoritative — Official Microsoft documentation)
**Accessed**: 2026-02-06

**Source**: PVS-Studio — "Introduction to Roslyn and its use in program development"
https://pvs-studio.com/en/blog/posts/csharp/0399/
**Type**: Tier 2 (Industry Expert — PVS-Studio, commercial static analyzer)
**Accessed**: 2026-02-06

**Key Findings**:

1. **Compilation as Context**: "An instance of Compilation is analogous to a single project as seen by the compiler and represents everything needed to compile a program." The Compilation includes source files, assembly references, and compiler options — all context needed for semantic analysis.

2. **Symbol and Binding APIs**: Roslyn separates syntax (structure) from semantics (meaning). The Semantic API answers questions like "What names are in scope?", "What members are accessible?", "What does this name refer to?" through Symbol and Binding APIs.

3. **SemanticModel as Query Interface**: "You can think of the semantic model as the source for all the information you would normally get from intellisense." The SemanticModel is created from a Compilation and SyntaxTree, providing type info, symbol resolution, and flow analysis.

4. **Two-Phase Analysis**: First parse to get SyntaxTree (cheap, parallelizable), then create Compilation and SemanticModel (expensive, requires context). This separation enables efficient incremental updates.

5. **Type Information via GetTypeInfo**: For any expression, `model.GetTypeInfo(expression)` returns the semantic type, enabling type-aware analysis without re-implementing type inference.

**Applicability to Drift**:

Roslyn's architecture validates several design decisions and highlights gaps:

- **Drift's Type Analyzer is TypeScript-only**: Roslyn shows how to build language-agnostic semantic APIs. Drift should expose similar APIs for all supported languages.
- **Missing Compilation abstraction**: Drift doesn't have a unified "Compilation" concept that bundles source files with their dependencies. This makes cross-file analysis ad-hoc.
- **SemanticModel pattern**: Drift's Semantic Analyzer builds scope trees and symbol tables, but doesn't expose a clean query interface like Roslyn's SemanticModel.

**Confidence**: Very High — Roslyn is the production C#/VB compiler used by millions of developers, with the most mature compiler-as-a-service API in the industry.

---

## R3: Salsa Framework — Incremental Computation for Compilers

**Source**: "Salsa Algorithm Explained" — Medium
https://medium.com/@eliah.lakhin/salsa-algorithm-explained-c5d6df1dd291
**Type**: Tier 2 (Industry Expert — Detailed technical explanation)
**Accessed**: 2026-02-06

**Source**: Salsa Reference — Algorithm Documentation
https://salsa-rs.github.io/salsa/reference/algorithm.html
**Type**: Tier 1 (Official documentation)
**Accessed**: 2026-02-06

**Source**: salsa-rs/salsa GitHub Repository
https://github.com/salsa-rs/salsa
**Type**: Tier 1 (Official source)
**Accessed**: 2026-02-06

**Key Findings**:

1. **Query-Based Computation Model**: "The key idea of salsa is that you define your program as a set of queries. Every query is used like a function K -> V that maps from some key of type K to a value of type V." Queries can depend on other queries, forming a computation graph.

2. **Revision Tracking**: "The Salsa database always tracks a single revision. Each time you set an input, the revision is incremented." Each query result is tagged with the revision when it was computed, enabling efficient invalidation.

3. **Memoization with Invalidation**: Query results are cached. When inputs change, Salsa determines which cached results are still valid by checking if their dependencies changed. Only invalidated queries are recomputed.

4. **Red-Green Algorithm**: Derived from rustc's incremental compilation. "Green" queries have valid cached results; "red" queries need recomputation. The algorithm efficiently propagates invalidation through the query graph.

5. **Durability Levels**: Queries can be marked with durability (low, medium, high) indicating how often they change. High-durability queries (like standard library types) are checked less frequently, improving performance.

**Applicability to Drift**:

Salsa provides the theoretical foundation for incremental analysis that Drift lacks:

- **Drift's analyzers are stateless**: Each analysis runs from scratch. Adopting Salsa's query model would enable caching and incremental updates.
- **No dependency tracking**: Drift doesn't track which analysis results depend on which inputs. Salsa's automatic dependency tracking would enable precise invalidation.
- **Durability concept maps to Drift**: Standard library patterns (high durability) vs. user code patterns (low durability) — Drift could skip re-analyzing stable patterns.

**Implementation Path**: Salsa is a Rust crate. Drift's Rust core could adopt Salsa directly, with the TypeScript layer querying cached results via NAPI.

**Confidence**: High — Salsa powers both rustc and rust-analyzer, proven at massive scale.

---

## R4: Clang Static Analyzer — Path-Sensitive Symbolic Execution

**Source**: Clang Static Analyzer — Checker Developer Manual
https://clang-analyzer.llvm.org/checker_dev_manual.html
**Type**: Tier 1 (Authoritative — Official LLVM documentation)
**Accessed**: 2026-02-06

**Source**: LLVM Discourse — "RFC: Scalable Static Analysis Framework"
https://discourse.llvm.org/t/rfc-scalable-static-analysis-framework/88678
**Type**: Tier 1 (Official LLVM discussion)
**Accessed**: 2026-02-06

**Key Findings**:

1. **Symbolic Execution Engine**: "The static analyzer engine performs path-sensitive exploration of the program and relies on a set of checkers to implement the logic for detecting and constructing specific bug reports." The engine explores multiple execution paths by reasoning about branches.

2. **Checker Architecture**: Checkers register for specific events (function calls, branch conditions, memory operations) and are notified during symbolic execution. This is similar to ESLint's visitor pattern but for control flow paths.

3. **Program State Abstraction**: The analyzer maintains abstract program state (variable values, memory regions, constraints) that checkers can query and modify. This enables sophisticated analysis like null pointer detection.

4. **Cross-Translation-Unit Analysis**: The RFC discusses summary-based analysis for scaling to large codebases: "We plan to create a summary-based cross-translation unit static analysis framework." Summaries capture function behavior without re-analyzing the function body.

5. **False Positive Management**: "The main goal is to have very few false positives." Google's deployment shows that aggressive false positive reduction (via lifetime annotations and dataflow analysis) significantly reduces crashes.

**Applicability to Drift**:

Clang's architecture informs Drift's Flow Analyzer and security detection:

- **Drift's Flow Analyzer is intraprocedural**: It builds CFGs per function but doesn't do path-sensitive analysis. Clang's symbolic execution approach would enable more precise null dereference and security detection.
- **No summary-based analysis**: Drift re-analyzes called functions. Summaries would enable efficient cross-file analysis.
- **Checker pattern for security**: Drift's security detectors could be refactored as "checkers" that register for specific patterns (user input → SQL query) and are notified during data flow traversal.

**Confidence**: Very High — Clang Static Analyzer is used by Apple, Google, and many enterprises for production C/C++ analysis.

---

## R5: Data Flow Analysis — Foundational Algorithms

**Source**: Wikipedia — "Data-flow analysis"
https://en.wikipedia.org/wiki/Data-flow_analysis
**Type**: Tier 1 (Authoritative — Well-established computer science)
**Accessed**: 2026-02-06

**Source**: University of Wisconsin — "DATAFLOW ANALYSIS"
https://pages.cs.wisc.edu/~horwitz/CS704-NOTES/2.DATAFLOW.html
**Type**: Tier 1 (Academic — University course notes)
**Accessed**: 2026-02-06

**Source**: University of Washington — "CSE 401 Section 8 Part 2"
https://courses.cs.washington.edu/courses/cse401/16wi/sections/section8/dfa.html
**Type**: Tier 1 (Academic — University course notes)
**Accessed**: 2026-02-06

**Key Findings**:

1. **Fixpoint Iteration**: "A simple way to perform data-flow analysis is to set up data-flow equations for each node of the control-flow graph and solve them by repeatedly calculating the output from the input locally at each node until the whole system stabilizes (reaches a fixpoint)."

2. **Forward vs Backward Analysis**:
   - Forward: Reaching definitions, available expressions, constant propagation
   - Backward: Live variables, very busy expressions
   The direction determines whether we reason about facts "up to" or "from" a program point.

3. **Meet Operator**: Combines information from multiple control flow paths. For "may" analyses (something might happen), use union. For "must" analyses (something definitely happens), use intersection.

4. **Lattice Theory Foundation**: Data flow values form a lattice with a partial order. The analysis computes the least (or greatest) fixpoint, guaranteeing termination and soundness.

5. **Worklist Algorithm**: More efficient than naive iteration. Maintains a worklist of nodes to process; when a node's output changes, add its successors (forward) or predecessors (backward) to the worklist.

**Applicability to Drift**:

Drift's Flow Analyzer implements basic CFG construction but lacks sophisticated data flow:

- **No reaching definitions**: Drift doesn't track which definitions reach each use. This is needed for dead code detection and constant propagation.
- **No live variable analysis**: Drift can't determine which variables are live at each point, needed for unused variable detection.
- **Missing worklist optimization**: If Drift implements data flow, it should use the worklist algorithm for efficiency.
- **Lattice design needed**: For each analysis (null tracking, taint tracking), define the lattice and meet operator explicitly.

**Confidence**: Very High — These are foundational algorithms from compiler theory, proven over 50+ years.

---

## R6: Taint Analysis — Security Data Flow Tracking

**Source**: JetBrains — "What is Taint Analysis?"
https://www.jetbrains.com/pages/static-code-analysis-guide/what-is-taint-analysis/
**Type**: Tier 2 (Industry Expert — JetBrains, IDE vendor)
**Accessed**: 2026-02-06

**Source**: SonarSource — "Static Taint Flow Analysis Tool"
https://www.sonarsource.com/solutions/taint-analysis/
**Type**: Tier 2 (Industry Expert — SonarQube vendor)
**Accessed**: 2026-02-06

**Source**: Qt — "Taint Analysis: Key Concepts Explained"
https://www.qt.io/quality-assurance/blog/taint-analysis-key-concepts
**Type**: Tier 2 (Industry Expert)
**Accessed**: 2026-02-06

**Key Findings**:

1. **Source-Sink-Sanitizer Model**: "Taint analysis traces the flow of untrusted data ('tainted') through your application to determine whether it can reach sensitive or dangerous operations ('sinks') without proper validation or sanitization."
   - Sources: User input, network data, file reads
   - Sinks: SQL queries, command execution, file writes
   - Sanitizers: Validation functions, encoding, escaping

2. **Interprocedural Tracking**: "SonarQube's taint analysis tracks user-controllable data through your entire application." Effective taint analysis must follow data across function boundaries.

3. **Context Sensitivity**: Modern taint analyzers distinguish between different call sites of the same function, reducing false positives when a function is called with both tainted and untainted data.

4. **Taint Propagation Rules**: Define how taint flows through operations:
   - String concatenation: if either operand is tainted, result is tainted
   - Array access: if array is tainted, element access is tainted
   - Object property: if object is tainted, property access may be tainted

5. **False Positive Challenge**: "Pattern matching inevitably flags legitimate code that resembles secrets. Development teams, overwhelmed by false alarms, begin to ignore alerts entirely." Taint analysis with proper sanitizer recognition reduces false positives.

**Applicability to Drift**:

Drift's security detectors lack taint tracking:

- **Current approach is pattern-based**: Drift detects SQL injection by pattern matching (e.g., string concatenation in query), not by tracking data flow from user input.
- **No sanitizer recognition**: Drift can't distinguish between raw user input and properly sanitized input.
- **Missing interprocedural analysis**: Drift's security analysis is per-file; taint often flows across files.

**Implementation Priority**: Taint analysis is the single most impactful improvement for Drift's security detection. It would dramatically reduce false positives while catching more real vulnerabilities.

**Confidence**: High — Taint analysis is the industry standard for SAST security detection, used by all major tools (SonarQube, Checkmarx, Fortify, Semgrep).

---

## R7: Abstract Interpretation — Sound Static Analysis Foundation

**Source**: NYU — "Software Verification by Abstract Interpretation"
https://cs.nyu.edu/~pmc309/COUSOTtalks/EPFL07.shtml
**Type**: Tier 1 (Academic — Patrick Cousot, inventor of abstract interpretation)
**Accessed**: 2026-02-06

**Source**: ResearchGate — "Formal Verification by Abstract Interpretation"
https://www.researchgate.net/publication/262328455_Formal_Verification_by_Abstract_Interpretation
**Type**: Tier 1 (Peer-reviewed academic paper)
**Accessed**: 2026-02-06

**Key Findings**:

1. **Sound Over-Approximation**: "Abstract interpretation is a theory of sound approximation of the behavior of dynamic systems. This is the formal basis for automatic correctness proofs by static analyzers considering an over-approximation of the set of all possible executions."

2. **No False Negatives**: "Contrary to bug-finding methods (e.g., by test, bounded model-checking or error pattern search), no potential error is ever omitted." Sound analysis guarantees that if no error is reported, no error exists.

3. **Abstract Domains**: Different abstract domains trade precision for efficiency:
   - Intervals: [0, 100] — simple, fast, imprecise
   - Octagons: x - y ≤ 5 — more precise, slower
   - Polyhedra: ax + by ≤ c — most precise, expensive

4. **Widening for Termination**: Loops can cause infinite iteration. Widening operators force convergence by over-approximating, ensuring the analysis terminates.

5. **ASTRÉE Success**: The ASTRÉE analyzer, based on abstract interpretation, proved absence of runtime errors in Airbus A380 flight control software — 132,000 lines of C with zero false alarms.

**Applicability to Drift**:

Abstract interpretation provides theoretical grounding for Drift's analyzers:

- **Drift's analysis is unsound**: It finds bugs but can miss them. For enterprise use cases requiring guarantees, sound analysis is valuable.
- **Interval analysis for bounds checking**: Drift could use interval abstract domain to detect array out-of-bounds, integer overflow.
- **Not a replacement, a complement**: Sound analysis is expensive. Drift should offer both fast unsound analysis (current) and optional sound analysis for critical code.

**Confidence**: Very High — Abstract interpretation is the theoretical foundation for industrial-strength static analyzers (ASTRÉE, Polyspace, Infer).

---

## R8: Secret Detection — Enterprise Credential Scanning

**Source**: GitGuardian — "Protect Code and Prevent Credential Leaks"
https://blog.gitguardian.com/secret-scanning-tools/
**Type**: Tier 2 (Industry Expert — GitGuardian, secret detection vendor)
**Accessed**: 2026-02-06

**Source**: Zetcode — "Secrets Scanning Tutorial: Definition, Types, and Best Practices"
https://zetcode.com/terms-testing/secrets-scanning/
**Type**: Tier 3 (Community — Tutorial site)
**Accessed**: 2026-02-06

**Key Findings**:

1. **Pattern + Entropy Hybrid**: "Modern tools integrate pattern matching, regular expressions, and entropy analysis to detect secrets in various formats." High-entropy strings that match secret patterns are more likely to be real secrets.

2. **Git History Scanning**: "Secret detection uses pattern-based scanning to identify exposed credentials in your codebase, git history, and configuration files." Secrets removed from current code may still exist in git history.

3. **Provider-Specific Patterns**: Each cloud provider has distinct key formats:
   - AWS: `AKIA[0-9A-Z]{16}` for access keys
   - GCP: Service account JSON with specific fields
   - Azure: Connection strings with specific prefixes
   - GitHub: `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` prefixes

4. **False Positive Reduction**: "Secrets detection typically prioritizes structured, identifiable formats." Generic patterns (like "password=") have high false positive rates; provider-specific patterns are more reliable.

5. **Verification via API**: Some tools verify detected secrets by attempting to use them (with read-only operations), confirming they're active credentials.

**Applicability to Drift**:

Drift's secret detection (21 patterns) is solid but has gaps:

- **Missing cloud providers**: No Azure, GCP patterns. These are increasingly common in enterprise codebases.
- **No entropy analysis**: Drift uses pure regex. Adding entropy scoring would reduce false positives on placeholder values.
- **No git history scanning**: Drift only scans current files. Secrets in git history remain exposed.
- **No verification**: Drift can't confirm if detected secrets are active. This is a nice-to-have for reducing false positives.

**Recommended Additions**:
- Azure: `DefaultEndpointsProtocol=https;AccountName=...`
- GCP: `"type": "service_account"` in JSON
- npm: `npm_[A-Za-z0-9]{36}`
- PyPI: `pypi-[A-Za-z0-9]{32,}`

**Confidence**: High — GitGuardian processes millions of commits daily and has comprehensive pattern coverage.

---

## R9: Module Coupling Metrics — Robert C. Martin's Principles

**Source**: Paul Serban — "Measuring Modularity: Metrics That Matter"
https://paulserban.eu/blog/post/measuring-modularity-metrics-that-matter/
**Type**: Tier 3 (Community — Developer blog)
**Accessed**: 2026-02-06

**Source**: GeeksforGeeks — "Coupling and Cohesion in System Design"
https://www.geeksforgeeks.org/coupling-and-cohesion-in-system-design/
**Type**: Tier 3 (Community — Tutorial site)
**Accessed**: 2026-02-06

**Source**: ResearchGate — "Comparing Static and Dynamic Weighted Software Coupling Metrics"
https://www.researchgate.net/publication/340320232_Comparing_Static_and_Dynamic_Weighted_Software_Coupling_Metrics
**Type**: Tier 1 (Peer-reviewed academic paper)
**Accessed**: 2026-02-06

**Key Findings**:

1. **Robert C. Martin's Metrics** (from "Clean Architecture"):
   - **Ca (Afferent Coupling)**: Number of modules that depend on this module
   - **Ce (Efferent Coupling)**: Number of modules this module depends on
   - **I (Instability)**: Ce / (Ca + Ce) — 0 = stable, 1 = unstable
   - **A (Abstractness)**: Abstract types / total types
   - **D (Distance from Main Sequence)**: |A + I - 1| — 0 = ideal

2. **Zone of Pain**: Modules with low I (stable) and low A (concrete). These are hard to change because many modules depend on them, but they're not abstract enough to accommodate change.

3. **Zone of Uselessness**: Modules with high I (unstable) and high A (abstract). These are too abstract for their instability — they change frequently but provide little concrete value.

4. **Weighted Coupling**: "Coupling metrics that count the number of inter-module connections are an established way to measure internal software quality." Weighted metrics consider the type of dependency (inheritance vs. method call vs. data).

5. **Dynamic vs Static**: Static coupling (from source code) may differ from dynamic coupling (from runtime behavior). Both provide valuable but different insights.

**Applicability to Drift**:

Drift implements Robert C. Martin's metrics but has gaps:

- **Zone detection missing in Rust**: TypeScript version detects zone of pain/uselessness; Rust version doesn't.
- **No weighted coupling**: All dependencies are treated equally. Inheritance coupling is stronger than method call coupling.
- **No dynamic coupling**: Drift only does static analysis. Runtime profiling could reveal actual coupling patterns.

**Confidence**: High — Robert C. Martin's metrics are industry standard, used by SonarQube, NDepend, and other architecture analysis tools.

---

## R10: ORM Anti-Pattern Detection — Database Performance Analysis

**Source**: ResearchGate — "Detecting Performance Anti-patterns for Applications Developed using Object-Relational Mapping"
https://www.researchgate.net/publication/265049388_Detecting_Performance_Anti-patterns_for_Applications_Developed_using_Object-Relational_Mapping
**Type**: Tier 1 (Peer-reviewed academic paper)
**Accessed**: 2026-02-06

**Source**: Meta Engineering — "Enabling static analysis of SQL queries at Meta"
https://engineering.fb.com/2022/11/30/data-infrastructure/static-analysis-sql-queries/
**Type**: Tier 2 (Industry Expert — Meta engineering blog)
**Accessed**: 2026-02-06

**Key Findings**:

1. **N+1 Query Detection**: "Developers often write ORM code without considering the impact on database performance, leading to transactions with timeouts or hangs." The N+1 pattern (one query to fetch list, N queries to fetch related data) is detectable statically.

2. **Eager vs Lazy Loading Analysis**: Static analysis can detect when lazy loading will cause excessive queries by analyzing access patterns in loops.

3. **SQL Query Understanding**: "In a growing number of use cases at Meta, we must understand programmatically what happens in SQL queries before they are executed." This requires parsing SQL strings and understanding their semantics.

4. **Framework-Specific Patterns**: Each ORM has specific anti-patterns:
   - Django: `select_related` / `prefetch_related` missing
   - SQLAlchemy: `joinedload` / `subqueryload` missing
   - Entity Framework: `Include` missing

5. **Automated Detection Framework**: The paper proposes "an automated framework to detect ORM performance anti-patterns" that "automatically flags performance anti-patterns in the source code."

**Applicability to Drift**:

Drift's Unified Provider has 20 ORM matchers but lacks anti-pattern detection:

- **No N+1 detection**: Drift identifies ORM usage but doesn't detect N+1 patterns.
- **No eager loading suggestions**: Drift doesn't suggest when to add eager loading.
- **SQL parsing limited**: Drift detects SQL strings but doesn't parse them to understand semantics.

**Implementation Priority**: N+1 detection would be high-value for enterprise users. It requires combining call graph analysis (to detect loops) with ORM pattern detection.

**Confidence**: High — ORM performance issues are a major source of production incidents; automated detection is valuable.

---

## R11: Quick Fix Generation — IDE Code Action Best Practices

**Source**: Microsoft — "Quick Actions, light bulbs, and screwdrivers"
https://learn.microsoft.com/en-us/visualstudio/ide/quick-actions
**Type**: Tier 1 (Authoritative — Official Microsoft documentation)
**Accessed**: 2026-02-06

**Source**: JetBrains — "Quick Fixes & On-the-Fly Code Analysis"
https://www.jetbrains.com/clion/features/code-analysis.html
**Type**: Tier 2 (Industry Expert — JetBrains, IDE vendor)
**Accessed**: 2026-02-06

**Key Findings**:

1. **Light Bulb UI Pattern**: "Quick Actions are available for C#, C++, and Visual Basic code files. Some actions are specific to a language, and others apply to all languages." The light bulb icon indicates available fixes.

2. **Fix Categories**:
   - Error fixes (red light bulb): Fix compilation errors
   - Refactorings (yellow light bulb): Improve code without changing behavior
   - Suggestions (screwdriver): Optional improvements

3. **Fix All of Type**: "Noticed multiple fixable issues in one file? Not a problem. Just use the 'Fix all' quick fix." Batch fixing is essential for large-scale code improvements.

4. **Preview Before Apply**: "When a problem is highlighted, place the caret on it, press Alt+Enter and choose from the suggested quick-fix solutions." Users should see what the fix will do before applying.

5. **Confidence Indication**: Fixes should indicate confidence level. High-confidence fixes can be auto-applied; low-confidence fixes require user review.

**Applicability to Drift**:

Drift's Quick Fix Generator has 7 strategies but limited coverage:

- **Many violations lack fixes**: Drift generates violations but not all have corresponding fixes.
- **No "Fix All" support**: Drift fixes one violation at a time. Batch fixing would improve UX.
- **Preview exists but underutilized**: Drift has `generatePreview` but it's not exposed in all UIs.
- **Confidence not surfaced**: Drift calculates fix confidence but doesn't show it to users.

**Confidence**: High — Quick fixes are a core IDE feature; the patterns are well-established.

---

## R12: Google Tricorder — Static Analysis at Scale (Revisited for Analyzers)

**Source**: "Software Engineering at Google" — Chapter 20: Static Analysis
https://abseil.io/resources/swe-book/html/ch20.html
**Type**: Tier 1 (Authoritative — Google's internal engineering practices)
**Accessed**: 2026-02-06

**Key Findings Specific to Analyzers**:

1. **Analyzer Independence**: "Each analyzer is independent — it receives context and reports problems. Analyzers don't know about each other." This enables easy contribution and testing.

2. **Incremental by Design**: "Instead of analyzing entire large projects, we focus analyses on files affected by a pending code change." Analyzers should be designed for incremental execution.

3. **Suggested Fixes Critical**: "Automated fixes reduce the cost of addressing issues. Authors apply automated fixes ~3,000 times per day." Analyzers without fixes are significantly less useful.

4. **Effective False Positive Tracking**: "An issue is an 'effective false positive' if developers did not take some positive action after seeing the issue." Track whether developers act on analyzer output.

5. **Compiler Warnings Useless**: "Google found developers ignore compiler warnings. They either make a check an error (break the build) or don't show it." Analyzers should produce actionable, high-confidence results.

**Applicability to Drift**:

- **Drift analyzers are not independent**: They share state and have implicit dependencies. Refactoring to independent analyzers would improve testability.
- **No incremental analysis**: Drift re-runs all analyzers on every scan. Incremental execution is critical for scale.
- **Fix coverage low**: Many Drift analyzer findings lack fixes. Increasing fix coverage should be a priority.
- **No feedback tracking**: Drift doesn't track whether developers act on findings. This data is essential for tuning.

**Confidence**: Very High — Google's Tricorder processes 50,000+ code reviews daily with 100+ analyzers.


---

## Summary of Research Findings

### Tier 1 Sources (Authoritative)
| Source | Key Contribution |
|--------|------------------|
| rust-analyzer Architecture | Layered architecture, Salsa incrementality, cancellation |
| Roslyn Semantic Model | Compilation abstraction, SemanticModel query interface |
| Salsa Framework | Query-based incremental computation, revision tracking |
| Clang Static Analyzer | Path-sensitive symbolic execution, checker architecture |
| Data Flow Analysis (Academic) | Fixpoint iteration, forward/backward analysis, lattices |
| Abstract Interpretation | Sound over-approximation, abstract domains |
| Google Tricorder | Analyzer independence, incremental design, fix importance |

### Tier 2 Sources (Industry Expert)
| Source | Key Contribution |
|--------|------------------|
| JetBrains Taint Analysis | Source-sink-sanitizer model, interprocedural tracking |
| SonarSource Taint Analysis | Context sensitivity, taint propagation rules |
| GitGuardian Secret Detection | Pattern + entropy hybrid, provider-specific patterns |
| Meta SQL Analysis | Static SQL understanding, ORM anti-pattern detection |
| JetBrains Quick Fixes | Fix categories, batch fixing, preview patterns |

### Key Themes Across Sources

1. **Incremental Computation is Essential**: Every production-grade analyzer (rust-analyzer, Roslyn, Tricorder) uses incremental computation. Drift's lack of incrementality is a critical gap.

2. **Clear API Boundaries**: Successful analyzers separate syntax from semantics, and low-level analysis from high-level APIs. Drift's mixed concerns make evolution difficult.

3. **Fixes Are Not Optional**: Google's data shows fixes are applied 3,000 times/day. Analyzers without fixes are significantly less useful.

4. **Taint Analysis for Security**: Pattern-based security detection has high false positive rates. Taint analysis with sanitizer recognition is the industry standard.

5. **Sound vs. Unsound Trade-off**: Abstract interpretation provides soundness guarantees but is expensive. Most tools offer both fast unsound analysis and optional sound analysis.

6. **Feedback Loops**: Tracking whether developers act on findings enables continuous improvement. Drift lacks this feedback mechanism.

---

## Research Quality Checklist

- [x] At least 3 Tier 1 sources consulted (7 Tier 1 sources)
- [x] Sources properly cited with URLs
- [x] Access dates recorded (2026-02-06)
- [x] Findings are specific, not generic
- [x] Applicability to Drift explained for each source
- [x] Confidence levels assessed for each source
