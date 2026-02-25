# 05 Analyzers — V2 Recommendations

## Summary

14 recommendations organized by priority, synthesized from comprehensive analysis of Drift's analyzer system and external research from 12+ authoritative sources. The recommendations address five critical gaps: incremental computation (Salsa-based query system), architectural boundaries (rust-analyzer-inspired layering), security analysis (taint tracking), semantic generalization (multi-language type/scope analysis), and developer experience (fix coverage, feedback loops). Combined, these changes would transform Drift's analyzer system from a capable but monolithic TypeScript implementation into an enterprise-grade, Rust-powered semantic analysis engine suitable for million-line codebases with sub-second response times.

---

## Recommendations

### R1: Salsa-Based Incremental Query System

**Priority**: P0 (Critical)
**Effort**: Very High
**Impact**: 10-100x performance improvement for incremental analysis; enables IDE-grade responsiveness

**Current State**:
Drift's analyzers are stateless functions that re-compute everything on each invocation. There is no caching, no dependency tracking, and no incremental updates. For a 10,000-file codebase, every scan re-analyzes all 10,000 files even if only one file changed.

**Proposed Change**:
Adopt the Salsa framework for incremental computation in Drift's Rust core. Define analyzers as Salsa queries with explicit inputs and outputs:

```rust
#[salsa::query_group(AnalyzerDatabase)]
pub trait AnalyzerDb {
    // Inputs (set by the client)
    #[salsa::input]
    fn file_content(&self, file: FileId) -> Arc<String>;
    
    #[salsa::input]
    fn file_config(&self, file: FileId) -> Arc<FileConfig>;
    
    // Derived queries (computed on demand, cached)
    fn parse(&self, file: FileId) -> Arc<ParseResult>;
    fn symbols(&self, file: FileId) -> Arc<SymbolTable>;
    fn types(&self, file: FileId) -> Arc<TypeInfo>;
    fn flow(&self, file: FileId) -> Arc<FlowAnalysis>;
    fn secrets(&self, file: FileId) -> Arc<Vec<SecretCandidate>>;
    fn coupling(&self, module: ModuleId) -> Arc<CouplingMetrics>;
}
```

**Key Design Decisions**:

1. **File-level granularity**: Each file is an independent query input. Changing one file only invalidates queries that depend on that file.

2. **Function-body isolation**: Following rust-analyzer's invariant: "typing inside a function's body never invalidates global derived data." Achieve this by separating function signatures (module-level) from function bodies (local).

3. **Durability levels**: Mark standard library analysis as high-durability (rarely changes), user code as low-durability (changes frequently).

4. **Revision-based cancellation**: When inputs change, increment a global revision counter. Long-running queries check the counter and cancel if stale.


**Rationale**:
Every production-grade semantic analyzer uses incremental computation. rust-analyzer processes millions of lines with sub-second response times using Salsa. Roslyn uses a similar query-based model. Google's Tricorder explicitly designs for incremental analysis. Without incrementality, Drift cannot scale to enterprise codebases.

**Evidence**:
- rust-analyzer (R1): Salsa-based incremental computation enables IDE-grade responsiveness
- Salsa Framework (R3): "The key idea is that you define your program as a set of queries"
- Google Tricorder (R12): "Instead of analyzing entire large projects, we focus on files affected by a pending code change"

**Implementation Notes**:
- Salsa is a Rust crate; integrate directly into `drift-core`
- Expose query results to TypeScript via NAPI
- Start with file-level queries, refine to function-level as needed
- Implement cancellation via `Cancelled::throw()` pattern from rust-analyzer

**Risks**:
- Salsa has a learning curve; requires understanding query dependencies
- Retrofitting existing analyzers to query model is significant work
- TypeScript layer must handle cancelled queries gracefully

**Dependencies**:
- 01-rust-core: Salsa integration is Rust-only
- 02-parsers: Parsing must be a Salsa query for incremental parsing
- All analyzer categories: Must be refactored to query model

---

### R2: Layered Architecture with Explicit API Boundaries

**Priority**: P0 (Critical)
**Effort**: High
**Impact**: Enables independent evolution of layers; improves testability; clarifies responsibilities

**Current State**:
Drift's analyzer code mixes concerns. The same crate contains parsing, semantic analysis, and IDE features. There are no explicit API boundaries. Internal types leak across layers. This makes refactoring difficult and testing complex.

**Proposed Change**:
Adopt rust-analyzer's layered architecture with explicit boundaries:

```
Layer 1: syntax (API Boundary)
├── Tree-sitter parsing
├── Syntax tree types (value types, no semantic info)
├── No dependencies on other Drift crates
└── Can be used standalone for syntax-only tools

Layer 2: hir-def, hir-ty (Internal)
├── Low-level semantic analysis
├── ECS-style with raw IDs and direct DB queries
├── Scope resolution, type inference, flow analysis
└── Not an API boundary — can change freely

Layer 3: hir (API Boundary)
├── High-level semantic API
├── OO-flavored facade over hir-def/hir-ty
├── Stable types for external consumers
└── Source-to-HIR mapping

Layer 4: ide (API Boundary)
├── IDE features built on hir
├── POD types only (no syntax trees, no hir types)
├── Editor terminology (offsets, labels, not definitions)
└── Conceptually serializable
```

**Key Design Decisions**:

1. **Syntax as value type**: "The tree is fully determined by the contents of its syntax nodes, it doesn't need global context." This enables parallel parsing and clean separation.

2. **Internal layers can change**: hir-def and hir-ty are not API boundaries. They can be refactored freely without breaking external consumers.

3. **IDE layer uses editor terminology**: The ide layer talks about "offsets" and "labels", not "definitions" and "types". This makes it easy to serialize for LSP.

4. **Source-to-HIR mapping in hir**: The recursive pattern for resolving syntax to semantics lives in the hir layer, not scattered across the codebase.

**Rationale**:
rust-analyzer's architecture enables a small team to maintain a complex codebase. Clear boundaries mean changes in one layer don't cascade. The syntax crate can be used by tools that don't need semantic analysis. The ide crate provides a stable API for multiple consumers (LSP, CLI, tests).

**Evidence**:
- rust-analyzer (R1): "syntax crate is completely independent from the rest of rust-analyzer"
- rust-analyzer (R1): "hir-xxx crates are not, and will never be, an API boundary"
- Roslyn (R2): Separates Syntax API from Semantic API with clear boundaries

**Implementation Notes**:
- Start by extracting syntax layer from drift-core
- Define hir types as the stable semantic API
- Refactor ide layer to use only POD types
- Document which crates are API boundaries

**Risks**:
- Large refactoring effort across multiple crates
- May break existing consumers during transition
- Requires discipline to maintain boundaries

**Dependencies**:
- All Drift crates: Affects the entire codebase structure
- 07-mcp: MCP tools should consume ide layer, not internal types
- 11-ide: VSCode extension should use ide layer

---

### R3: Taint Analysis for Security Detection

**Priority**: P0 (Critical)
**Effort**: Very High
**Impact**: Dramatically reduces false positives in security detection; catches real vulnerabilities that pattern matching misses

**Current State**:
Drift's security detectors use pattern matching (regex, AST patterns) to find vulnerabilities. This approach has high false positive rates because it can't distinguish between sanitized and unsanitized data. For example, Drift flags `query("SELECT * FROM users WHERE id = " + userId)` even if `userId` was validated.

**Proposed Change**:
Implement interprocedural taint analysis with source-sink-sanitizer model:

```rust
// Taint sources (where untrusted data enters)
enum TaintSource {
    UserInput,      // req.body, req.query, req.params
    NetworkData,    // fetch response, socket data
    FileRead,       // fs.readFile, file input
    DatabaseResult, // query results (for second-order injection)
    Environment,    // process.env (for some contexts)
}

// Taint sinks (where untrusted data is dangerous)
enum TaintSink {
    SqlQuery,       // database queries
    CommandExec,    // child_process, exec, system
    FileWrite,      // fs.writeFile, file output
    HtmlRender,     // innerHTML, dangerouslySetInnerHTML
    UrlRedirect,    // res.redirect, window.location
    Deserialization,// JSON.parse, pickle.loads
}

// Sanitizers (functions that make data safe)
struct Sanitizer {
    function: FunctionId,
    sanitizes: Vec<TaintSink>, // which sinks this sanitizer protects against
}

// Taint analysis result
struct TaintFlow {
    source: TaintSource,
    source_location: Location,
    sink: TaintSink,
    sink_location: Location,
    path: Vec<Location>,       // data flow path
    sanitized: bool,           // was data sanitized?
    sanitizer: Option<FunctionId>,
}
```

**Key Design Decisions**:

1. **Interprocedural**: Track taint across function boundaries using call graph.

2. **Context-sensitive**: Distinguish between different call sites of the same function.

3. **Configurable sanitizers**: Allow users to mark custom functions as sanitizers.

4. **Path recording**: Record the data flow path for debugging and explanation.

5. **Framework-aware**: Recognize framework-specific sources (Express req.body, Django request.POST).

**Rationale**:
Taint analysis is the industry standard for SAST security detection. SonarQube, Checkmarx, Fortify, and Semgrep all use taint analysis. Pattern-based detection has unacceptably high false positive rates for enterprise use.

**Evidence**:
- JetBrains (R6): "Taint analysis traces the flow of untrusted data through your application"
- SonarSource (R6): "SonarQube's taint analysis tracks user-controllable data through your entire application"
- Qt (R6): "Taint analysis is a core technique used in Static Analysis Security Testing (SAST)"

**Implementation Notes**:
- Build on Flow Analyzer's CFG and data flow infrastructure
- Integrate with Call Graph for interprocedural analysis
- Start with SQL injection and XSS (highest value)
- Add sanitizer recognition for common libraries (express-validator, DOMPurify)

**Risks**:
- Interprocedural analysis is expensive; may impact performance
- Sanitizer database requires ongoing maintenance
- False negatives possible if sanitizers not recognized

**Dependencies**:
- 04-call-graph: Required for interprocedural tracking
- 05-analyzers/flow-analyzer: CFG and data flow infrastructure
- 21-security: Security boundary integration

---

### R4: Generalized Semantic Analysis for All Languages

**Priority**: P1 (Important)
**Effort**: Very High
**Impact**: Enables type-aware analysis for Python, Java, Go, etc.; currently TypeScript-only

**Current State**:
Drift's Type Analyzer and Semantic Analyzer only work for TypeScript. Other languages get basic AST analysis but no type information, no scope resolution, and no symbol tables. This limits the quality of analysis for non-TypeScript codebases.

**Proposed Change**:
Design a language-agnostic semantic model with per-language implementations:

```rust
// Language-agnostic semantic traits
trait TypeSystem {
    fn infer_type(&self, expr: ExprId) -> TypeId;
    fn is_subtype(&self, sub: TypeId, super_: TypeId) -> bool;
    fn resolve_member(&self, type_: TypeId, name: &str) -> Option<MemberId>;
}

trait ScopeResolver {
    fn resolve_name(&self, name: &str, scope: ScopeId) -> Option<SymbolId>;
    fn visible_symbols(&self, scope: ScopeId) -> Vec<SymbolId>;
    fn scope_at_position(&self, pos: Position) -> ScopeId;
}

// Per-language implementations
struct TypeScriptSemantics { /* ... */ }
struct PythonSemantics { /* ... */ }
struct JavaSemantics { /* ... */ }
struct GoSemantics { /* ... */ }

impl TypeSystem for TypeScriptSemantics { /* ... */ }
impl TypeSystem for PythonSemantics { /* ... */ }
// etc.
```

**Key Design Decisions**:

1. **Trait-based abstraction**: Define semantic operations as traits, implement per language.

2. **Gradual typing support**: Python and JavaScript have optional types; the model must handle untyped code gracefully.

3. **Type inference levels**: Some languages (TypeScript, Rust) have full inference; others (Python) have limited inference. Support both.

4. **External type information**: Support type stubs (Python .pyi), declaration files (TypeScript .d.ts), and IDE-provided types.

**Rationale**:
Roslyn provides semantic analysis for C# and VB.NET through a unified API. rust-analyzer provides it for Rust. Drift should provide equivalent capabilities for all supported languages, not just TypeScript.

**Evidence**:
- Roslyn (R2): "The Semantic API answers questions like 'What names are in scope?', 'What members are accessible?'"
- rust-analyzer (R1): "hir provides a static, fully resolved view of the code"

**Implementation Notes**:
- Start with Python (large user base, type hints increasingly common)
- Leverage existing type checkers (pyright, mypy) for Python type info
- Java and Go have strong type systems; implementation is more straightforward
- Consider LSP integration for external type information

**Risks**:
- Each language is a significant implementation effort
- Type systems differ significantly; abstraction may leak
- Maintaining parity across languages is ongoing work

**Dependencies**:
- 02-parsers: Need rich AST for each language
- Per-language analyzers: Existing language analyzers become semantic implementations

---

### R5: Compilation Abstraction for Cross-File Analysis

**Priority**: P1 (Important)
**Effort**: High
**Impact**: Enables accurate cross-file analysis; provides context for semantic queries

**Current State**:
Drift analyzes files independently. There's no unified "Compilation" concept that bundles source files with their dependencies, configuration, and target environment. This makes cross-file analysis ad-hoc and incomplete.

**Proposed Change**:
Introduce a Compilation abstraction inspired by Roslyn:

```rust
struct Compilation {
    // Source files in this compilation
    source_files: Vec<FileId>,
    
    // External dependencies (node_modules, pip packages, etc.)
    dependencies: Vec<DependencyId>,
    
    // Compilation options (target, module system, etc.)
    options: CompilationOptions,
    
    // Language-specific compiler (for type checking, etc.)
    language: Language,
}

impl Compilation {
    // Get semantic model for a file in this compilation
    fn get_semantic_model(&self, file: FileId) -> SemanticModel;
    
    // Get all symbols defined in this compilation
    fn get_all_symbols(&self) -> Vec<Symbol>;
    
    // Resolve a symbol reference
    fn resolve_symbol(&self, reference: SymbolReference) -> Option<Symbol>;
}

struct SemanticModel {
    compilation: Arc<Compilation>,
    file: FileId,
}

impl SemanticModel {
    fn get_type_info(&self, expr: ExprId) -> TypeInfo;
    fn get_symbol_info(&self, name: NameId) -> SymbolInfo;
    fn get_declared_symbols(&self) -> Vec<Symbol>;
}
```

**Key Design Decisions**:

1. **Compilation as context**: All semantic queries happen in the context of a Compilation.

2. **Dependency resolution**: The Compilation knows about external dependencies (npm packages, pip packages) and can resolve imports to them.

3. **SemanticModel per file**: Each file gets a SemanticModel that provides semantic queries in the Compilation context.

4. **Immutable snapshots**: Compilations are immutable. Changes create new Compilations (with shared unchanged data via Salsa).

**Rationale**:
Roslyn's Compilation abstraction is the key to accurate semantic analysis. "An instance of Compilation is analogous to a single project as seen by the compiler and represents everything needed to compile a program."

**Evidence**:
- Roslyn (R2): "The compilation includes the set of source files, assembly references, and compiler options"
- Roslyn (R2): "You can reason about the meaning of the code using all the other information in this context"

**Implementation Notes**:
- Integrate with project discovery (package.json, pyproject.toml, Cargo.toml)
- Cache dependency analysis (node_modules rarely changes)
- Support multi-project workspaces (monorepos)

**Risks**:
- Dependency resolution is complex and language-specific
- Large dependency trees may impact memory usage
- External type information may be incomplete or incorrect

**Dependencies**:
- R4: Generalized semantic analysis uses Compilation context
- 25-services-layer: Project discovery feeds Compilation creation


---

### R6: Interprocedural Data Flow Analysis

**Priority**: P1 (Important)
**Effort**: High
**Impact**: Enables cross-function analysis for security, null safety, and resource tracking

**Current State**:
Drift's Flow Analyzer builds CFGs and performs intraprocedural data flow analysis (within a single function). It cannot track data flow across function boundaries, limiting its ability to detect issues like null pointer dereferences from function returns or resource leaks across call chains.

**Proposed Change**:
Extend the Flow Analyzer with interprocedural capabilities using function summaries:

```rust
// Function summary captures relevant behavior without re-analyzing the body
struct FunctionSummary {
    // Which parameters flow to the return value?
    param_to_return: Vec<(ParamIndex, Confidence)>,
    
    // Which parameters are modified (out parameters)?
    modified_params: Vec<ParamIndex>,
    
    // Can this function return null/undefined?
    may_return_null: bool,
    
    // Does this function throw exceptions?
    may_throw: bool,
    
    // Resource effects (allocates, releases, etc.)
    resource_effects: Vec<ResourceEffect>,
    
    // Taint propagation (for security analysis)
    taint_propagation: TaintSummary,
}

// Interprocedural analysis using summaries
fn analyze_interprocedural(
    call_graph: &CallGraph,
    summaries: &HashMap<FunctionId, FunctionSummary>,
    entry_point: FunctionId,
) -> InterproceduralResult {
    // Use worklist algorithm with summary application
    // When encountering a call, apply the callee's summary
    // Propagate results back to callers
}
```

**Key Design Decisions**:

1. **Summary-based**: Compute summaries once per function, reuse across call sites. This is more efficient than inlining.

2. **Demand-driven**: Only compute summaries for functions that are actually called. Don't analyze dead code.

3. **Context-insensitive summaries**: Start with context-insensitive summaries (same summary for all call sites). Add context sensitivity later if needed.

4. **Incremental summary updates**: When a function changes, only recompute its summary and propagate to callers.

**Rationale**:
Clang Static Analyzer and other production tools use summary-based interprocedural analysis. "We plan to create a summary-based cross-translation unit static analysis framework." Summaries enable scaling to large codebases.

**Evidence**:
- Clang (R4): "Summary-based cross-translation unit static analysis framework"
- Data Flow (R5): "Dataflow analysis is usually performed on the program's control-flow graph"

**Implementation Notes**:
- Build on existing Call Graph infrastructure
- Start with simple summaries (may_return_null, may_throw)
- Add taint summaries for security analysis (R3)
- Consider using abstract interpretation for sound summaries

**Risks**:
- Summary computation can be expensive for complex functions
- Context-insensitive summaries may be imprecise
- Recursive functions require special handling (fixpoint)

**Dependencies**:
- 04-call-graph: Provides the call graph structure
- R3: Taint analysis uses interprocedural data flow
- R1: Salsa enables incremental summary updates

---

### R7: Expanded Secret Detection Patterns

**Priority**: P1 (Important)
**Effort**: Low
**Impact**: Catches secrets from Azure, GCP, npm, PyPI that current patterns miss

**Current State**:
Drift's secret detection has 21 patterns covering AWS, GitHub, Stripe, Google, Slack, SendGrid, Twilio, and generic patterns. Missing: Azure, GCP, npm, PyPI, and other common providers.

**Proposed Change**:
Add patterns for missing providers and enhance detection with entropy analysis:

```rust
// New patterns to add
const AZURE_PATTERNS: &[SecretPattern] = &[
    // Azure Storage connection string
    SecretPattern {
        name: "azure_storage_connection",
        regex: r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
        severity: SecretSeverity::Critical,
        confidence: 0.95,
    },
    // Azure AD client secret
    SecretPattern {
        name: "azure_ad_client_secret",
        regex: r"[a-zA-Z0-9~._-]{34}",
        context_required: "azure|client.?secret|tenant",
        severity: SecretSeverity::High,
        confidence: 0.8,
    },
];

const GCP_PATTERNS: &[SecretPattern] = &[
    // GCP service account key (JSON)
    SecretPattern {
        name: "gcp_service_account",
        regex: r#""type"\s*:\s*"service_account""#,
        severity: SecretSeverity::Critical,
        confidence: 0.95,
    },
    // GCP API key
    SecretPattern {
        name: "gcp_api_key",
        regex: r"AIza[0-9A-Za-z\-_]{35}",
        severity: SecretSeverity::High,
        confidence: 0.9,
    },
];

const PACKAGE_REGISTRY_PATTERNS: &[SecretPattern] = &[
    // npm token
    SecretPattern {
        name: "npm_token",
        regex: r"npm_[A-Za-z0-9]{36}",
        severity: SecretSeverity::High,
        confidence: 0.95,
    },
    // PyPI token
    SecretPattern {
        name: "pypi_token",
        regex: r"pypi-[A-Za-z0-9]{32,}",
        severity: SecretSeverity::High,
        confidence: 0.95,
    },
    // NuGet API key
    SecretPattern {
        name: "nuget_api_key",
        regex: r"oy2[a-z0-9]{43}",
        severity: SecretSeverity::High,
        confidence: 0.9,
    },
];

// Entropy-based enhancement
fn calculate_entropy(s: &str) -> f64 {
    // Shannon entropy calculation
    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    let len = s.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn adjust_confidence_by_entropy(base_confidence: f64, value: &str) -> f64 {
    let entropy = calculate_entropy(value);
    // High entropy (>4.0) increases confidence
    // Low entropy (<3.0) decreases confidence
    if entropy > 4.0 {
        (base_confidence + 0.1).min(1.0)
    } else if entropy < 3.0 {
        (base_confidence - 0.2).max(0.0)
    } else {
        base_confidence
    }
}
```

**Rationale**:
GitGuardian and other secret detection tools cover these providers. Enterprise codebases increasingly use Azure and GCP. Package registry tokens (npm, PyPI) are common attack vectors.

**Evidence**:
- GitGuardian (R8): "Each cloud provider has distinct key formats"
- GitGuardian (R8): "Modern tools integrate pattern matching, regular expressions, and entropy analysis"

**Implementation Notes**:
- Add patterns to existing `secrets.rs` in drift-core
- Implement entropy calculation as confidence adjustment
- Add context-aware patterns (require nearby keywords for ambiguous patterns)
- Test against real-world secret datasets (GitGuardian publishes test cases)

**Risks**:
- New patterns may have false positives; need tuning
- Entropy calculation adds overhead (mitigate by only calculating for pattern matches)

**Dependencies**:
- 01-rust-core/constants: Secret detection lives here

---

### R8: N+1 Query Detection for ORM Analysis

**Priority**: P1 (Important)
**Effort**: Medium
**Impact**: Catches common performance anti-pattern that causes production incidents

**Current State**:
Drift's Unified Provider detects ORM usage (20 matchers) but doesn't detect anti-patterns like N+1 queries. It identifies that code uses Prisma or Django ORM but not that the usage pattern will cause performance issues.

**Proposed Change**:
Add N+1 query detection by combining call graph analysis with ORM pattern detection:

```rust
struct NPlusOneDetector {
    call_graph: Arc<CallGraph>,
    orm_patterns: Arc<OrmPatterns>,
}

impl NPlusOneDetector {
    fn detect(&self, file: FileId) -> Vec<NPlusOneViolation> {
        let mut violations = Vec::new();
        
        // Find loops in the file
        for loop_node in self.find_loops(file) {
            // Find ORM queries inside the loop
            let queries_in_loop = self.find_orm_queries_in_range(
                file,
                loop_node.body_range,
            );
            
            // Check if any query depends on loop variable
            for query in queries_in_loop {
                if self.query_depends_on_loop_var(&query, &loop_node) {
                    // Check if there's a bulk query before the loop
                    let has_bulk_query = self.has_bulk_query_before(
                        file,
                        loop_node.start,
                        &query.table,
                    );
                    
                    if !has_bulk_query {
                        violations.push(NPlusOneViolation {
                            loop_location: loop_node.location,
                            query_location: query.location,
                            table: query.table.clone(),
                            suggestion: self.generate_fix_suggestion(&query),
                        });
                    }
                }
            }
        }
        
        violations
    }
    
    fn generate_fix_suggestion(&self, query: &OrmQuery) -> String {
        match query.orm {
            Orm::Prisma => format!("Use `include` or `select` with the parent query"),
            Orm::Django => format!("Use `select_related` or `prefetch_related`"),
            Orm::SqlAlchemy => format!("Use `joinedload` or `subqueryload`"),
            Orm::EntityFramework => format!("Use `Include` with the parent query"),
            // ... other ORMs
        }
    }
}
```

**Rationale**:
N+1 queries are one of the most common causes of database performance issues. Academic research shows automated detection is effective: "Our framework automatically flags performance anti-patterns in the source code."

**Evidence**:
- ResearchGate (R10): "Detecting Performance Anti-patterns for Applications Developed using Object-Relational Mapping"
- Meta (R10): "We must understand programmatically what happens in SQL queries before they are executed"

**Implementation Notes**:
- Build on existing Unified Provider ORM detection
- Use Flow Analyzer to identify loops
- Track data dependencies from loop variable to query parameters
- Generate framework-specific fix suggestions

**Risks**:
- False positives when query is intentionally in loop (rare but possible)
- Complex control flow may hide the N+1 pattern

**Dependencies**:
- 05-analyzers/unified-provider: ORM pattern detection
- 05-analyzers/flow-analyzer: Loop detection
- 04-call-graph: Cross-function tracking

---

### R9: Quick Fix Coverage Expansion

**Priority**: P1 (Important)
**Effort**: Medium
**Impact**: Dramatically increases developer adoption; Google data shows fixes are applied 3,000 times/day

**Current State**:
Drift's Quick Fix Generator has 7 strategies but many violations lack fixes. The fix coverage is estimated at <30% of violation types.

**Proposed Change**:
Systematically expand fix coverage with a target of 80%+ violations having at least one fix:

```typescript
// New fix strategies to add

// 1. Add Missing Import Fix
class AddImportFixStrategy implements FixStrategy {
    canHandle(violation: Violation): boolean {
        return violation.code === 'undefined-reference' &&
               this.canResolveImport(violation);
    }
    
    generate(violation: Violation): QuickFix[] {
        const candidates = this.findImportCandidates(violation.actual);
        return candidates.map(candidate => ({
            title: `Import '${candidate.symbol}' from '${candidate.module}'`,
            fixType: 'import',
            edit: this.createImportEdit(candidate),
            confidence: candidate.confidence,
        }));
    }
}

// 2. Convert to Async/Await Fix
class AsyncAwaitFixStrategy implements FixStrategy {
    canHandle(violation: Violation): boolean {
        return violation.code === 'promise-not-awaited' ||
               violation.code === 'callback-to-promise';
    }
    
    generate(violation: Violation): QuickFix[] {
        // Transform .then().catch() to async/await
        // Or add missing await
    }
}

// 3. Add Type Annotation Fix
class AddTypeAnnotationFixStrategy implements FixStrategy {
    canHandle(violation: Violation): boolean {
        return violation.code === 'missing-type-annotation';
    }
    
    generate(violation: Violation): QuickFix[] {
        const inferredType = this.inferType(violation);
        return [{
            title: `Add type annotation: ${inferredType}`,
            fixType: 'replace',
            edit: this.createTypeAnnotationEdit(inferredType),
            confidence: 0.8,
        }];
    }
}

// 4. Security Fix Strategies
class SqlInjectionFixStrategy implements FixStrategy {
    canHandle(violation: Violation): boolean {
        return violation.code === 'sql-injection';
    }
    
    generate(violation: Violation): QuickFix[] {
        // Convert string concatenation to parameterized query
        return [{
            title: 'Convert to parameterized query',
            fixType: 'replace',
            edit: this.createParameterizedQueryEdit(violation),
            confidence: 0.7,
        }];
    }
}

// 5. Batch Fix Support
interface BatchFix {
    title: string;
    violations: Violation[];
    edits: WorkspaceEdit;
    confidence: number;
}

function generateBatchFixes(violations: Violation[]): BatchFix[] {
    // Group violations by fix type
    // Generate combined fix for each group
    // E.g., "Add all missing imports" or "Fix all naming convention violations"
}
```

**Rationale**:
Google's data is clear: "Automated fixes reduce the cost of addressing issues. Authors apply automated fixes ~3,000 times per day." Analyzers without fixes are significantly less useful.

**Evidence**:
- Google Tricorder (R12): "Suggested fixes are critical"
- Microsoft (R11): "Quick Actions let you easily refactor, generate, or otherwise modify your code"
- JetBrains (R11): "Use IDE quick fixes to automatically fix highlighted fixable issues"

**Implementation Notes**:
- Audit all violation types; prioritize high-frequency violations
- Add batch fix support ("Fix all in file", "Fix all of type")
- Expose fix confidence in UI
- Track fix application rate for feedback

**Risks**:
- Low-confidence fixes may introduce bugs
- Batch fixes may have unintended interactions

**Dependencies**:
- 05-analyzers/rules-engine: Quick fix infrastructure
- 11-ide: VSCode extension must support batch fixes

---

### R10: Feedback Loop for Analyzer Tuning

**Priority**: P1 (Important)
**Effort**: Medium
**Impact**: Enables continuous improvement; identifies ineffective analyzers

**Current State**:
Drift has no mechanism to track whether developers act on analyzer findings. There's no feedback loop between violation consumers and analyzer authors. The "effective false positive" rate is unknown.

**Proposed Change**:
Implement Google Tricorder's feedback model:

```typescript
// Track violation actions
enum ViolationAction {
    Fixed,          // Developer fixed the violation
    Dismissed,      // Developer explicitly dismissed
    Ignored,        // Developer saw but took no action
    AutoFixed,      // Quick fix was applied
    NotSeen,        // Violation was never displayed
}

interface ViolationFeedback {
    violationId: string;
    analyzerId: string;
    action: ViolationAction;
    timestamp: Date;
    timeToAction?: number; // milliseconds from display to action
}

// Analyzer health metrics
interface AnalyzerHealth {
    analyzerId: string;
    totalViolations: number;
    fixedCount: number;
    dismissedCount: number;
    ignoredCount: number;
    autoFixedCount: number;
    effectiveFPRate: number; // (dismissed + ignored) / total
    avgTimeToFix: number;
    trend: 'improving' | 'stable' | 'degrading';
}

// Health dashboard
function computeAnalyzerHealth(
    feedback: ViolationFeedback[],
    window: Duration,
): Map<string, AnalyzerHealth> {
    // Group by analyzer
    // Compute metrics
    // Flag analyzers with >10% effective FP rate
}

// Auto-disable unhealthy analyzers
function enforceHealthPolicy(health: Map<string, AnalyzerHealth>) {
    for (const [id, metrics] of health) {
        if (metrics.effectiveFPRate > 0.2 && metrics.totalViolations > 100) {
            // Disable analyzer, notify maintainer
            disableAnalyzer(id);
            notifyMaintainer(id, metrics);
        }
    }
}
```

**Rationale**:
Google's #1 lesson: "Focus on developer happiness." Tricorder maintains <5% effective FP rate by aggressively tracking and tuning. Without feedback, analyzers accumulate false positives over time.

**Evidence**:
- Google Tricorder (R12): "'Not useful' button on every analysis result"
- Google Tricorder (R12): "Analyzers with high 'not useful' rates are disabled"

**Implementation Notes**:
- Add telemetry to IDE extension (opt-in)
- Track violation display, fix, dismiss events
- Build health dashboard for analyzer maintainers
- Implement auto-disable policy for unhealthy analyzers

**Risks**:
- Privacy concerns with tracking developer actions
- Small teams may not generate enough data for statistical significance
- Feedback delay (violations may be fixed days later)

**Dependencies**:
- 11-ide: VSCode extension must report actions
- 10-cli: CLI must track fix/dismiss actions
- 08-storage: Need feedback storage


---

### R11: Coupling Analyzer Rust Parity

**Priority**: P2 (Nice to Have)
**Effort**: Medium
**Impact**: Enables full coupling analysis in Rust; removes TypeScript dependency for coupling

**Current State**:
The Rust coupling analyzer has basic metrics (Ca, Ce, I, A, D) and cycle detection. The TypeScript version adds: Tarjan's SCC algorithm, module roles, break point suggestions, refactor impact analysis, zone of pain/uselessness detection.

**Proposed Change**:
Port all TypeScript coupling features to Rust:

```rust
// Module roles
#[derive(Debug, Clone, Copy)]
enum ModuleRole {
    Hub,        // High Ca AND high Ce
    Authority,  // High Ca, low Ce
    Balanced,   // Moderate Ca and Ce
    Isolated,   // Low Ca and Ce
}

// Zone detection
enum CouplingZone {
    MainSequence,   // |A + I - 1| < 0.2
    ZoneOfPain,     // Low I, low A
    ZoneOfUselessness, // High I, high A
}

// Tarjan's SCC for cycle detection
fn tarjan_scc(graph: &DependencyGraph) -> Vec<Vec<ModuleId>> {
    let mut index = 0;
    let mut stack = Vec::new();
    let mut indices = HashMap::new();
    let mut lowlinks = HashMap::new();
    let mut on_stack = HashSet::new();
    let mut sccs = Vec::new();
    
    fn strongconnect(
        v: ModuleId,
        graph: &DependencyGraph,
        index: &mut usize,
        stack: &mut Vec<ModuleId>,
        indices: &mut HashMap<ModuleId, usize>,
        lowlinks: &mut HashMap<ModuleId, usize>,
        on_stack: &mut HashSet<ModuleId>,
        sccs: &mut Vec<Vec<ModuleId>>,
    ) {
        indices.insert(v, *index);
        lowlinks.insert(v, *index);
        *index += 1;
        stack.push(v);
        on_stack.insert(v);
        
        for w in graph.successors(v) {
            if !indices.contains_key(&w) {
                strongconnect(w, graph, index, stack, indices, lowlinks, on_stack, sccs);
                lowlinks.insert(v, lowlinks[&v].min(lowlinks[&w]));
            } else if on_stack.contains(&w) {
                lowlinks.insert(v, lowlinks[&v].min(indices[&w]));
            }
        }
        
        if lowlinks[&v] == indices[&v] {
            let mut scc = Vec::new();
            loop {
                let w = stack.pop().unwrap();
                on_stack.remove(&w);
                scc.push(w);
                if w == v { break; }
            }
            sccs.push(scc);
        }
    }
    
    for v in graph.nodes() {
        if !indices.contains_key(&v) {
            strongconnect(v, graph, &mut index, &mut stack, &mut indices, &mut lowlinks, &mut on_stack, &mut sccs);
        }
    }
    
    sccs
}

// Break point suggestions
struct BreakPoint {
    from: ModuleId,
    to: ModuleId,
    effort: BreakEffort,
    rationale: String,
    approach: BreakApproach,
}

enum BreakApproach {
    ExtractInterface,
    DependencyInversion,
    MergeModules,
    IntroduceMediator,
}

fn suggest_break_points(cycle: &[ModuleId], metrics: &CouplingMetrics) -> Vec<BreakPoint> {
    // Find the weakest edge in the cycle
    // Suggest approach based on module characteristics
}

// Refactor impact analysis
struct RefactorImpact {
    target: ModuleId,
    direct_dependents: Vec<ModuleId>,
    transitive_dependents: Vec<ModuleId>,
    affected_tests: Vec<FileId>,
    risk: RefactorRisk,
    effort: RefactorEffort,
}

fn analyze_refactor_impact(
    target: ModuleId,
    graph: &DependencyGraph,
    test_topology: &TestTopology,
) -> RefactorImpact {
    // BFS from target to find all dependents
    // Cross-reference with test topology
    // Estimate risk and effort
}
```

**Rationale**:
Having coupling analysis split between Rust and TypeScript creates maintenance burden and performance overhead. Full Rust implementation enables faster analysis and simpler architecture.

**Evidence**:
- Robert C. Martin metrics (R9): Industry standard for architecture analysis
- ResearchGate (R9): "Coupling metrics count inter-module connections to measure internal software quality"

**Implementation Notes**:
- Port Tarjan's SCC algorithm (more efficient than current DFS)
- Add zone detection based on A and I values
- Implement break point suggestion heuristics
- Add refactor impact using call graph and test topology

**Risks**:
- Tarjan's algorithm is more complex than DFS
- Break point suggestions are heuristic; may not always be helpful

**Dependencies**:
- 01-rust-core/coupling: Existing Rust coupling analyzer
- 04-call-graph: For transitive dependency analysis
- Test topology: For affected tests calculation

---

### R12: Cancellation Support for Long-Running Analysis

**Priority**: P2 (Nice to Have)
**Effort**: Low
**Impact**: Improves responsiveness; prevents blocking on stale analysis

**Current State**:
Drift's analyzers run to completion. If a user types while analysis is running, the analysis continues with stale input. There's no way to cancel in-progress analysis.

**Proposed Change**:
Implement rust-analyzer's cancellation pattern:

```rust
use std::sync::atomic::{AtomicU64, Ordering};

// Global revision counter
static REVISION: AtomicU64 = AtomicU64::new(0);

// Cancellation token
#[derive(Clone)]
struct CancellationToken {
    revision_at_start: u64,
}

impl CancellationToken {
    fn new() -> Self {
        Self {
            revision_at_start: REVISION.load(Ordering::SeqCst),
        }
    }
    
    fn is_cancelled(&self) -> bool {
        REVISION.load(Ordering::SeqCst) != self.revision_at_start
    }
    
    fn check(&self) -> Result<(), Cancelled> {
        if self.is_cancelled() {
            Err(Cancelled)
        } else {
            Ok(())
        }
    }
}

// Cancelled error (uses unwinding)
struct Cancelled;

impl Cancelled {
    fn throw() -> ! {
        std::panic::resume_unwind(Box::new(Cancelled))
    }
}

// Usage in analyzer
fn analyze_file(file: FileId, token: &CancellationToken) -> Result<Analysis, Cancelled> {
    token.check()?;
    
    let ast = parse(file);
    token.check()?;
    
    let types = analyze_types(&ast);
    token.check()?;
    
    let flow = analyze_flow(&ast);
    token.check()?;
    
    Ok(Analysis { ast, types, flow })
}

// Increment revision when input changes
fn on_file_changed(file: FileId, content: String) {
    REVISION.fetch_add(1, Ordering::SeqCst);
    // Update file content in database
}

// Catch cancellation at API boundary
fn handle_analysis_request(file: FileId) -> Result<Analysis, Error> {
    let token = CancellationToken::new();
    match std::panic::catch_unwind(|| analyze_file(file, &token)) {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(Cancelled)) => Err(Error::Cancelled),
        Err(panic) => {
            if panic.is::<Cancelled>() {
                Err(Error::Cancelled)
            } else {
                std::panic::resume_unwind(panic)
            }
        }
    }
}
```

**Rationale**:
rust-analyzer uses this pattern to maintain responsiveness. "When applying a change, salsa bumps this counter and waits until all other threads using salsa finish."

**Evidence**:
- rust-analyzer (R1): "If a thread notices that the counter is incremented, it panics with a special value"
- rust-analyzer (R1): "ide is the boundary where the panic is caught and transformed into a Result"

**Implementation Notes**:
- Add revision counter to Rust core
- Insert cancellation checks at key points in analysis
- Catch cancellation at NAPI boundary
- TypeScript layer should retry cancelled requests

**Risks**:
- Requires unwinding support (Rust default)
- Too many cancellation checks add overhead
- Must ensure cleanup on cancellation (no resource leaks)

**Dependencies**:
- R1: Salsa integration includes cancellation support
- 01-rust-core: All analyzers need cancellation checks

---

### R13: Abstract Interpretation for Sound Analysis (Optional)

**Priority**: P3 (Future)
**Effort**: Very High
**Impact**: Provides soundness guarantees for critical code; enables formal verification

**Current State**:
Drift's analysis is unsound — it finds bugs but can miss them. For enterprise use cases requiring guarantees (safety-critical systems, financial software), sound analysis is valuable.

**Proposed Change**:
Add optional sound analysis using abstract interpretation:

```rust
// Abstract domain for integer intervals
#[derive(Clone, Debug)]
struct Interval {
    lo: i64,  // Lower bound (i64::MIN for -∞)
    hi: i64,  // Upper bound (i64::MAX for +∞)
}

impl Interval {
    fn top() -> Self { Interval { lo: i64::MIN, hi: i64::MAX } }
    fn bottom() -> Self { Interval { lo: 1, hi: 0 } } // Empty
    
    fn join(&self, other: &Self) -> Self {
        Interval {
            lo: self.lo.min(other.lo),
            hi: self.hi.max(other.hi),
        }
    }
    
    fn meet(&self, other: &Self) -> Self {
        Interval {
            lo: self.lo.max(other.lo),
            hi: self.hi.min(other.hi),
        }
    }
    
    fn add(&self, other: &Self) -> Self {
        Interval {
            lo: self.lo.saturating_add(other.lo),
            hi: self.hi.saturating_add(other.hi),
        }
    }
    
    fn widen(&self, other: &Self) -> Self {
        // Widening for loop convergence
        Interval {
            lo: if other.lo < self.lo { i64::MIN } else { self.lo },
            hi: if other.hi > self.hi { i64::MAX } else { self.hi },
        }
    }
}

// Abstract interpretation engine
struct AbstractInterpreter {
    domain: Box<dyn AbstractDomain>,
}

impl AbstractInterpreter {
    fn analyze(&self, cfg: &ControlFlowGraph) -> AbstractState {
        let mut state = self.domain.initial_state();
        let mut worklist = vec![cfg.entry()];
        
        while let Some(node) = worklist.pop() {
            let old_state = state.get(node).clone();
            let new_state = self.transfer(node, &state);
            
            if new_state != old_state {
                state.set(node, new_state);
                worklist.extend(cfg.successors(node));
            }
        }
        
        state
    }
    
    fn transfer(&self, node: NodeId, state: &AbstractState) -> AbstractValue {
        // Apply transfer function based on node type
        // Use widening at loop heads
    }
}

// Use cases
fn check_array_bounds(access: ArrayAccess, state: &AbstractState) -> Option<Violation> {
    let index_interval = state.get_interval(access.index);
    let array_length = state.get_interval(access.array_length);
    
    if index_interval.lo < 0 || index_interval.hi >= array_length.lo {
        Some(Violation::PossibleOutOfBounds { ... })
    } else {
        None // Proven safe
    }
}
```

**Rationale**:
Abstract interpretation provides soundness guarantees. "Contrary to bug-finding methods, no potential error is ever omitted." ASTRÉE proved absence of runtime errors in Airbus A380 flight control software.

**Evidence**:
- Cousot (R7): "Abstract interpretation is a theory of sound approximation"
- ResearchGate (R7): "Provides scaling solutions to achieving assurance in mission-critical systems"

**Implementation Notes**:
- Start with interval domain (simplest, useful for bounds checking)
- Add nullness domain for null pointer analysis
- Consider using existing abstract interpretation libraries
- Make sound analysis opt-in (expensive)

**Risks**:
- Abstract interpretation is complex to implement correctly
- Sound analysis is expensive; may not scale to large codebases
- Over-approximation leads to false positives

**Dependencies**:
- R6: Interprocedural analysis for sound cross-function analysis
- 05-analyzers/flow-analyzer: CFG infrastructure

---

### R14: Unified Provider Rust Migration

**Priority**: P2 (Nice to Have)
**Effort**: Very High
**Impact**: Enables full ORM analysis in Rust; removes TypeScript dependency

**Current State**:
The Unified Provider has 9 language normalizers and 20 ORM matchers, all in TypeScript. The Rust unified analyzer has ~30 AST patterns but no ORM-specific matching.

**Proposed Change**:
Migrate the Unified Provider to Rust using traits:

```rust
// Language normalizer trait
trait LanguageNormalizer {
    fn normalize(&self, ast: &Tree, source: &str) -> Vec<UnifiedCallChain>;
    fn supported_language(&self) -> Language;
}

// ORM matcher trait
trait OrmMatcher {
    fn match_pattern(&self, chain: &UnifiedCallChain) -> Option<OrmPattern>;
    fn supported_orms(&self) -> Vec<OrmType>;
}

// Unified call chain (language-agnostic)
struct UnifiedCallChain {
    receiver: Option<String>,
    method_calls: Vec<MethodCall>,
    arguments: Vec<Argument>,
    location: Location,
}

// ORM pattern result
struct OrmPattern {
    orm: OrmType,
    operation: OrmOperation,  // Select, Insert, Update, Delete
    table: Option<String>,
    fields: Vec<String>,
    conditions: Vec<Condition>,
    confidence: f32,
}

// Per-language normalizers
struct TypeScriptNormalizer;
struct PythonNormalizer;
struct JavaNormalizer;
// ... 9 total

impl LanguageNormalizer for TypeScriptNormalizer {
    fn normalize(&self, ast: &Tree, source: &str) -> Vec<UnifiedCallChain> {
        // Extract call chains from TypeScript AST
    }
    
    fn supported_language(&self) -> Language {
        Language::TypeScript
    }
}

// Per-ORM matchers
struct PrismaMatcher;
struct DjangoOrmMatcher;
struct SqlAlchemyMatcher;
// ... 20 total

impl OrmMatcher for PrismaMatcher {
    fn match_pattern(&self, chain: &UnifiedCallChain) -> Option<OrmPattern> {
        // Match Prisma patterns: prisma.user.findMany(), etc.
    }
    
    fn supported_orms(&self) -> Vec<OrmType> {
        vec![OrmType::Prisma]
    }
}

// Registry
struct UnifiedProvider {
    normalizers: HashMap<Language, Box<dyn LanguageNormalizer>>,
    matchers: Vec<Box<dyn OrmMatcher>>,
}

impl UnifiedProvider {
    fn analyze(&self, file: FileId, ast: &Tree, source: &str, lang: Language) -> Vec<OrmPattern> {
        let normalizer = self.normalizers.get(&lang)?;
        let chains = normalizer.normalize(ast, source);
        
        chains.iter()
            .filter_map(|chain| {
                self.matchers.iter()
                    .find_map(|matcher| matcher.match_pattern(chain))
            })
            .collect()
    }
}
```

**Rationale**:
The Unified Provider is a prime Rust candidate. It's pure data transformation with no I/O. Moving to Rust enables single-pass analysis (parse + extract call graph + detect ORM patterns simultaneously).

**Evidence**:
- Drift v1 docs: "This entire system is a prime Rust candidate. It's the core extraction pipeline."
- Drift v1 docs: "20 ORM matchers is impressive coverage — must be preserved in v2."

**Implementation Notes**:
- Start with most-used ORMs (Prisma, Django, SQLAlchemy)
- Port normalizers one language at a time
- Maintain TypeScript fallback during migration
- Add N+1 detection (R8) as part of migration

**Risks**:
- Large migration effort (20 matchers, 9 normalizers)
- ORM APIs change; matchers need ongoing maintenance
- Some ORMs have complex patterns that are hard to match

**Dependencies**:
- R8: N+1 detection builds on ORM pattern detection
- 02-parsers: Rich AST needed for call chain extraction

---

## Summary

### Priority Matrix

| Priority | Recommendations | Combined Effort | Combined Impact |
|----------|-----------------|-----------------|-----------------|
| P0 (Critical) | R1, R2, R3 | Very High | Foundational for enterprise-grade analysis |
| P1 (Important) | R4, R5, R6, R7, R8, R9, R10 | Very High | Major capability and UX improvements |
| P2 (Nice to Have) | R11, R12, R14 | High | Performance and completeness |
| P3 (Future) | R13 | Very High | Advanced capability for specialized use cases |

### Implementation Order

**Phase 1 (Foundation)**:
1. R1: Salsa-based incremental query system
2. R2: Layered architecture with API boundaries
3. R12: Cancellation support (low effort, high value)

**Phase 2 (Security)**:
4. R3: Taint analysis for security detection
5. R7: Expanded secret detection patterns

**Phase 3 (Semantic Generalization)**:
6. R4: Generalized semantic analysis
7. R5: Compilation abstraction
8. R6: Interprocedural data flow

**Phase 4 (Developer Experience)**:
9. R9: Quick fix coverage expansion
10. R10: Feedback loop for analyzer tuning
11. R8: N+1 query detection

**Phase 5 (Completeness)**:
12. R11: Coupling analyzer Rust parity
13. R14: Unified Provider Rust migration

**Phase 6 (Advanced)**:
14. R13: Abstract interpretation (optional)

### Key Metrics for Success

| Metric | Current | Target |
|--------|---------|--------|
| Incremental scan time (1 file changed) | ~10s | <100ms |
| Full scan time (10K files) | ~30s | <5s |
| Security false positive rate | ~30% | <10% |
| Quick fix coverage | ~30% | >80% |
| Languages with semantic analysis | 1 (TS) | 5+ |
| Effective false positive rate | Unknown | <5% |

---

## Quality Checklist

- [x] Each recommendation has clear rationale
- [x] Evidence is cited for each recommendation
- [x] Priority and effort are assessed
- [x] Risks are identified
- [x] Dependencies are noted
- [x] Implementation is actionable
- [x] Recommendations are organized by priority
- [x] Implementation order is specified
- [x] Success metrics are defined
