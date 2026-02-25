# Taint Analysis (Source/Sink/Sanitizer, Intraprocedural, Interprocedural) — V2 Implementation Prep

> Comprehensive build specification for Drift v2's Taint Analysis subsystem (System 15).
> Synthesized from: 14-REACHABILITY-ANALYSIS-V2-PREP.md (§9 Taint Analysis Integration, AD11),
> .research/04-call-graph/RECOMMENDATIONS.md (R1 Taint Analysis Layer, R11 Field-Level Flow),
> .research/16-gap-analysis/RESEARCH.md (§2.3 Taint Analysis Industry Consensus, §2.4 SAST Landscape),
> .research/16-gap-analysis/RECOMMENDATIONS.md (GE4 Security Gap Closure Roadmap, GAP-4.3/4.5/4.6),
> .research/21-security/RECOMMENDATIONS.md (SAD3 Taint as First-Class Engine, TA1-TA8),
> 21-security/overview.md (Security Analysis Pipeline, ORM Frameworks),
> 21-security/types.md (DataAccessPoint, SensitiveField, ORMModel),
> 05-CALL-GRAPH-V2-PREP.md (petgraph StableGraph, Resolution, CallEdge),
> 06-DETECTOR-SYSTEM.md (Visitor Pattern, GAST Normalization, Detection Pipeline),
> 06-UNIFIED-ANALYSIS-ENGINE-V2-PREP.md (4-phase pipeline, ParseResult contract),
> 07-BOUNDARY-DETECTION-V2-PREP.md (learn-then-detect, 33 ORM frameworks, field-level flow),
> 03-NAPI-BRIDGE-V2-PREP.md (command/query pattern, async tasks, §10.6 analyze_taint),
> 02-STORAGE-V2-PREP.md (batch writer, keyset pagination, medallion architecture),
> 04-INFRASTRUCTURE-V2-PREP.md (thiserror, tracing, FxHashMap, petgraph),
> DRIFT-V2-FULL-SYSTEM-AUDIT.md (AD11 Taint Analysis as First-Class Subsystem),
> DRIFT-V2-STACK-HIERARCHY.md (Level 2B — Graph Intelligence),
> DRIFT-V2-SYSTEMS-REFERENCE.md (taint capabilities),
> PLANNING-DRIFT.md (D1-D7),
> FlowDroid (Arzt et al., PLDI 2014 — context/flow/field/object-sensitive taint),
> Semgrep taint mode (source/sink/sanitizer, intraprocedural default, cross-function Pro),
> SemTaint (arxiv 2025 — multi-agent LLM taint specification extraction),
> SonarSource taint analysis (deep security scan, interprocedural tracking),
> JetBrains taint analysis guide (untrusted data tracing),
> Moderne/OpenRewrite taint analysis (introduction to taint for Java),
> OWASP Top 10 2021 (A03 Injection requires taint, A10 SSRF requires taint),
> CWE Top 25 2024 (CWE-79 XSS, CWE-89 SQLi, CWE-78 OS Command Injection).
>
> Purpose: Everything needed to build the Taint Analysis subsystem from scratch.
> This is the DEDICATED deep-dive for taint analysis — the 14-REACHABILITY-ANALYSIS-V2-PREP
> doc covers the reachability engine that taint analysis extends; this document covers the
> taint-specific machinery: source/sink/sanitizer registries, intraprocedural data flow,
> interprocedural function summaries, taint label propagation, declarative rule definitions,
> framework-specific taint specifications, SARIF code flow generation, and the full
> integration with the call graph, detector system, and security pipeline.
> Every v1 gap accounted for. Every algorithm specified. Every type defined.
> Every integration point documented. Every architectural decision resolved.
> Generated: 2026-02-07

---

## Table of Contents

1. Architectural Position
2. V1 Gap Inventory (No V1 Taint — This Is Net-New)
3. V2 Architecture — Taint Analysis Engine
4. Core Data Model
5. Source Registry (Taint Origins)
6. Sink Registry (Dangerous Operations)
7. Sanitizer Registry (Data Cleansing)
8. Propagator Model (How Taint Flows)
9. Intraprocedural Taint Analysis (Phase 1)
10. Interprocedural Taint Analysis via Function Summaries (Phase 2)
11. Taint Label System (Multi-Type Tracking)
12. Declarative Taint Rule Definitions (TOML)
13. Framework-Specific Taint Specifications
14. Field-Level Taint Tracking
15. Taint Path Construction & Code Flow Generation
16. SARIF Integration (Code Flows for Security Findings)
17. Integration with Call Graph (petgraph BFS Extension)
18. Integration with Detector System (Visitor Pattern)
19. Integration with Boundary Detection (ORM Sink Auto-Discovery)
20. Storage Schema (drift.db Taint Tables)
21. NAPI Interface
22. MCP Tool Interface
23. CLI Interface
24. Tracing & Observability
25. Performance Targets & Benchmarks
26. Build Order & Dependencies
27. CWE/OWASP Mapping
28. Inconsistencies & Decisions
29. Risk Register

---

## 1. Architectural Position

Taint Analysis is **Level 2B — Graph Intelligence** in the Drift v2 stack hierarchy.
It is the single most impactful security improvement for v2 (per AD11, GE4, R1).
Without it, Drift can detect structural patterns but cannot answer the question that
matters most for security: "Can untrusted user input reach this dangerous operation
without being sanitized?"

Per DRIFT-V2-FULL-SYSTEM-AUDIT.md AD11:

> AD11: Taint Analysis as First-Class Subsystem — Not an afterthought.
> Source/sink/sanitizer registry (TOML-configurable, per-framework defaults).
> Phase 1: intraprocedural taint tracking in Rust.
> Phase 2: interprocedural via call graph taint summaries.

Per .research/16-gap-analysis/RESEARCH.md §2.3:

> Taint analysis is the industry standard for SAST security detection. All major tools
> (SonarQube, Checkmarx, Fortify, Semgrep, JetBrains) implement it.

Per .research/21-security/RECOMMENDATIONS.md SAD3:

> Build intraprocedural taint analysis as a core engine in Rust, not as an afterthought.
> The taint engine should be composable with the existing call graph for interprocedural
> expansion.

### What Lives Here

- Source registry (user input, env vars, file reads, HTTP params — per-framework)
- Sink registry (SQL queries, command exec, file writes, HTML rendering — per-CWE)
- Sanitizer registry (encoding, validation, hashing, escaping — per-sink-type)
- Propagator model (assignments, function calls, string operations, collection ops)
- Intraprocedural taint engine (within single function, data flow analysis)
- Interprocedural taint engine (cross-function via call graph + function summaries)
- Taint label system (multi-type: user-input, file-read, env-var, db-read)
- Declarative taint rule definitions (TOML-based, user-extensible)
- Framework-specific taint specifications (Express, FastAPI, Spring, Django, etc.)
- Field-level taint tracking (users.password vs users.name)
- Taint path construction (source → propagation chain → sink)
- SARIF code flow generation (for CI/CD integration)
- CWE/OWASP mapping for every taint finding
- Taint result persistence (drift.db taint_flows, taint_sources, taint_sinks tables)

### What Does NOT Live Here

- Call graph construction → Call Graph Builder (Level 1, produces the graph we traverse)
- Reachability BFS engine → Reachability Analysis (Level 2B, provides traversal primitives)
- Data access detection → Boundary Detection (Level 1, produces DataAccessPoint[])
- ORM framework detection → Boundary Detection (Level 1, learns frameworks)
- Secret detection → Detector System (Level 1, pattern-based, no data flow needed)
- Cryptographic failure detection → Detector System (Level 1, pattern-based)
- Quality gate evaluation → Quality Gates (Level 3, consumes taint results)
- MCP tool routing → MCP Server (Level 5, presentation layer)

### Critical Path Position

```
Scanner (Level 0)
  → Parsers (Level 0) — produce ParseResult with FunctionInfo, CallSite
    → Call Graph Builder (Level 1) — builds petgraph + drift.db edges
      → Boundary Detection (Level 1) — produces DataAccessPoint[], SensitiveField[]
        → Reachability Engine (Level 2B) — provides BFS traversal primitives
          → Taint Analysis (Level 2B) ← YOU ARE HERE
            → Quality Gates (Level 3) — taint gate blocks on unresolved critical paths
              → MCP Tools (Level 5) — drift_taint_analysis, drift_taint_paths
                → CLI (Level 5) — drift security taint
```

### Why Taint Analysis Is the #1 Security Priority

1. **OWASP A03 (Injection)** — SQL injection, XSS, command injection all require taint
   analysis for reliable detection. Pattern matching alone produces 30-50% false positives.
2. **OWASP A10 (SSRF)** — Server-side request forgery requires tracking user input to
   HTTP client calls. Cannot be detected without data flow analysis.
3. **CWE Top 25** — 9 of the top 25 CWEs are detectable via taint analysis:
   CWE-79 (XSS), CWE-89 (SQLi), CWE-78 (OS Command Injection), CWE-22 (Path Traversal),
   CWE-94 (Code Injection), CWE-918 (SSRF), CWE-502 (Deserialization),
   CWE-77 (Command Injection), CWE-434 (Unrestricted Upload).
4. **False positive reduction** — Taint analysis with sanitizer recognition reduces
   false positives by 60-80% compared to pattern-only detection (per Semgrep, SonarSource).
5. **Drift's competitive advantage** — Drift already has the call graph infrastructure.
   Taint is an incremental addition that transforms structural analysis into security analysis.

### Consumer Count: 8+ Downstream Systems

| Consumer | What It Reads | Why |
|----------|--------------|-----|
| Quality Gates | Taint flow count by severity | Security gate blocks on critical taint |
| MCP Tools | Taint paths, source/sink pairs | drift_taint_analysis, drift_taint_paths |
| CLI | Taint summary, detailed paths | drift security taint |
| IDE/LSP | Per-file taint warnings | Inline diagnostics |
| SARIF Output | Code flows for CI/CD | GitHub Code Scanning, GitLab SAST |
| Context Generation | Security context budget | AI-ready taint summaries |
| DNA System | Security health metrics | Taint coverage in DNA profile |
| Audit System | Taint trend tracking | Security posture over time |

---

## 2. V1 Gap Inventory (No V1 Taint — This Is Net-New)

V1 has **zero** taint analysis capability. This is the single largest security gap
identified across all research documents.

### What V1 Can Do (Without Taint)

| Capability | V1 Mechanism | Limitation |
|-----------|-------------|------------|
| SQL injection detection | Regex pattern matching | 30-50% false positive rate |
| XSS detection | Regex pattern matching | Cannot track data flow |
| Command injection detection | Regex pattern matching | Cannot distinguish sanitized paths |
| Data reachability | BFS on call graph | No data labels, no sanitizer awareness |
| Sensitive field detection | Pattern matching on field names | Table-level, not field-level |

### What V2 Taint Adds (Closing GAP-4.3, GAP-4.5, GAP-4.6)

| Gap | Description | Taint Solution |
|-----|-------------|---------------|
| GAP-4.3 | No taint analysis | Full source/sink/sanitizer engine |
| GAP-4.5 | No field-level data flow | Field-level taint propagation |
| GAP-4.6 | No cross-file data flow | Interprocedural via function summaries |

### Concrete Example: Why Pattern Matching Fails

```javascript
// V1 pattern matching flags BOTH as SQL injection — 50% false positive rate
function route1(req, res) {
    const id = req.params.id;
    const sanitized = parseInt(id, 10);  // ← SANITIZED
    const result = db.query(`SELECT * FROM users WHERE id = ${sanitized}`);
    res.json(result);
}

function route2(req, res) {
    const id = req.params.id;
    // No sanitization!
    const result = db.query(`SELECT * FROM users WHERE id = ${id}`);  // ← REAL VULN
    res.json(result);
}
```

V2 taint analysis correctly identifies:
- `route1`: Source (`req.params.id`) → Sanitizer (`parseInt`) → Sink (`db.query`) → **SAFE**
- `route2`: Source (`req.params.id`) → Sink (`db.query`) → **VULNERABLE** (CWE-89)

---

## 3. V2 Architecture — Taint Analysis Engine

### 3.1 Design Philosophy

Following Semgrep's pragmatic approach (per .research/16-gap-analysis/RESEARCH.md §2.3):

1. **Intraprocedural first** — Track taint within single functions. This catches 70-80%
   of real vulnerabilities with minimal complexity.
2. **Function summaries for interprocedural** — Don't re-analyze callees at every call site.
   Pre-compute "if parameter 0 is tainted, return value is tainted" summaries.
3. **No path sensitivity** — Don't track which branch was taken. Too expensive for
   convention detection. Accept some false positives in exchange for speed.
4. **No soundness guarantees** — False negatives are acceptable. The goal is practical
   vulnerability detection, not formal verification.
5. **Declarative rules** — Source/sink/sanitizer definitions in TOML, not hardcoded.
   Users can add custom definitions without recompiling.
6. **Framework-aware** — Per-framework source/sink definitions. Express `req.params`
   is a source; Django `request.GET` is a source. Same concept, different syntax.

### 3.2 Engine Architecture

```rust
/// The taint analysis engine. Operates on parsed ASTs and the call graph.
pub struct TaintEngine {
    /// Source definitions (where tainted data originates).
    source_registry: SourceRegistry,

    /// Sink definitions (where tainted data is dangerous).
    sink_registry: SinkRegistry,

    /// Sanitizer definitions (what makes tainted data safe).
    sanitizer_registry: SanitizerRegistry,

    /// Propagator rules (how taint flows through operations).
    propagator_rules: PropagatorRules,

    /// Pre-computed function summaries for interprocedural analysis.
    summaries: FxHashMap<FunctionId, TaintSummary>,

    /// Call graph reference (for interprocedural traversal).
    call_graph: Option<Arc<CallGraph>>,

    /// Database for persisting results.
    db: Arc<DatabaseManager>,

    /// Configuration.
    config: TaintConfig,
}

impl TaintEngine {
    /// Create engine with registries loaded from TOML + built-in defaults.
    pub fn new(
        db: Arc<DatabaseManager>,
        call_graph: Option<Arc<CallGraph>>,
        config: TaintConfig,
    ) -> Result<Self, TaintError> {
        let source_registry = SourceRegistry::load_or_default(&config)?;
        let sink_registry = SinkRegistry::load_or_default(&config)?;
        let sanitizer_registry = SanitizerRegistry::load_or_default(&config)?;
        let propagator_rules = PropagatorRules::default();

        Ok(Self {
            source_registry,
            sink_registry,
            sanitizer_registry,
            propagator_rules,
            summaries: FxHashMap::default(),
            call_graph,
            db,
            config,
        })
    }

    /// Phase 1: Intraprocedural analysis on a single function.
    /// Returns taint flows found within this function.
    pub fn analyze_function(
        &self,
        func: &FunctionInfo,
        gast: &GASTNode,
        ctx: &TaintContext,
    ) -> Result<Vec<TaintFlow>, TaintError> {
        let mut analyzer = IntraprocAnalyzer::new(
            &self.source_registry,
            &self.sink_registry,
            &self.sanitizer_registry,
            &self.propagator_rules,
            &self.summaries,
            ctx,
        );
        analyzer.analyze(func, gast)
    }

    /// Phase 2: Build function summaries for interprocedural analysis.
    /// Must be called after all functions have been analyzed intraprocedurally.
    pub fn build_summaries(
        &mut self,
        parse_results: &[ParseResult],
    ) -> Result<(), TaintError> {
        // Bottom-up traversal of call graph (leaves first)
        let order = self.topological_order()?;
        for func_id in order {
            let summary = self.compute_summary(&func_id, parse_results)?;
            self.summaries.insert(func_id, summary);
        }
        Ok(())
    }

    /// Full analysis: intraprocedural + interprocedural.
    /// Returns all taint flows across the entire codebase.
    pub fn analyze_all(
        &mut self,
        parse_results: &[ParseResult],
    ) -> Result<TaintAnalysisResult, TaintError> {
        let start = std::time::Instant::now();

        // Phase 1: Build function summaries (bottom-up)
        self.build_summaries(parse_results)?;

        // Phase 2: Analyze each function with summaries available
        let mut all_flows = Vec::new();
        for parse_result in parse_results {
            let ctx = TaintContext::from_parse_result(parse_result);
            for func in &parse_result.functions {
                let gast = self.normalize(parse_result, func)?;
                let flows = self.analyze_function(func, &gast, &ctx)?;
                all_flows.extend(flows);
            }
        }

        // Phase 3: Deduplicate and rank flows
        let flows = self.deduplicate_and_rank(all_flows);

        // Phase 4: Persist to drift.db
        self.persist_results(&flows)?;

        Ok(TaintAnalysisResult {
            flows,
            summaries_computed: self.summaries.len(),
            duration_ms: start.elapsed().as_millis() as u32,
        })
    }
}
```

### 3.3 Two-Phase Architecture

```
Phase 1: Intraprocedural (within single function)
┌─────────────────────────────────────────────────────────┐
│  For each function:                                      │
│  1. Identify sources (parameters, API calls, env reads)  │
│  2. Track taint through assignments and operations       │
│  3. Check if tainted data reaches any sink               │
│  4. Check if sanitizers appear on the path               │
│  5. Produce TaintFlow if source reaches sink unsanitized │
└─────────────────────────────────────────────────────────┘

Phase 2: Interprocedural (across functions via call graph)
┌─────────────────────────────────────────────────────────┐
│  1. Topological sort of call graph (leaves first)        │
│  2. For each function (bottom-up):                       │
│     a. Compute TaintSummary: which params taint return?  │
│     b. Store summary for use by callers                  │
│  3. Re-analyze functions using callee summaries          │
│  4. Propagate taint across function boundaries           │
└─────────────────────────────────────────────────────────┘
```

### 3.4 Relationship to Reachability Engine

The Taint Engine is **complementary** to the Reachability Engine, not a replacement.

| Aspect | Reachability Engine | Taint Engine |
|--------|-------------------|-------------|
| Question answered | "Can function A reach function B?" | "Can untrusted data reach this sink?" |
| Traversal | BFS on call edges | Data flow within + across functions |
| Labels | None (structural only) | Taint labels (user-input, file-read, etc.) |
| Sanitizer awareness | No | Yes (core feature) |
| Granularity | Function-level | Variable/expression-level |
| Output | ReachabilityResult (paths) | TaintFlow (source → path → sink) |

The Taint Engine uses the call graph (same as Reachability) but operates at a finer
granularity — tracking individual variables and expressions, not just function calls.
For interprocedural analysis, it uses function summaries rather than full BFS traversal.

---

## 4. Core Data Model

### 4.1 TaintFlow — The Primary Output

```rust
/// A complete taint flow from source to sink.
/// This is the primary output of taint analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintFlow {
    /// Unique identifier for this flow.
    pub id: String,

    /// Where the tainted data originates.
    pub source: TaintSource,

    /// Where the tainted data reaches a dangerous operation.
    pub sink: TaintSink,

    /// Ordered list of steps from source to sink.
    pub path: Vec<TaintStep>,

    /// Sanitizers encountered along the path (if any).
    pub sanitizers: Vec<TaintSanitizer>,

    /// Whether the flow is sanitized (all required sanitizers present).
    pub is_sanitized: bool,

    /// Risk level (derived from sink severity × sanitization status).
    pub risk: RiskLevel,

    /// Confidence in this flow (0.0 - 1.0).
    pub confidence: f64,

    /// CWE IDs this flow maps to.
    pub cwe_ids: Vec<u32>,

    /// OWASP categories this flow maps to.
    pub owasp_categories: Vec<String>,

    /// Whether this flow crosses function boundaries.
    pub is_interprocedural: bool,

    /// File where the source is located.
    pub source_file: String,

    /// File where the sink is located.
    pub sink_file: String,
}
```

### 4.2 TaintSource — Where Tainted Data Originates

```rust
/// A source of tainted data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSource {
    /// Source definition ID (from registry).
    pub definition_id: String,

    /// The taint label applied to data from this source.
    pub label: TaintLabel,

    /// Location in source code.
    pub location: CodeLocation,

    /// The expression that produces tainted data.
    pub expression: String,

    /// Framework that defines this source (if any).
    pub framework: Option<String>,

    /// Function containing this source.
    pub function_id: String,

    /// Parameter index (if source is a function parameter).
    pub parameter_index: Option<u32>,
}
```

### 4.3 TaintSink — Where Tainted Data Is Dangerous

```rust
/// A sink where tainted data causes a vulnerability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSink {
    /// Sink definition ID (from registry).
    pub definition_id: String,

    /// The type of dangerous operation.
    pub sink_type: SinkType,

    /// Location in source code.
    pub location: CodeLocation,

    /// The expression that consumes tainted data.
    pub expression: String,

    /// Which parameter of the sink receives tainted data.
    pub tainted_parameter: u32,

    /// CWE IDs for this sink type.
    pub cwe_ids: Vec<u32>,

    /// Required sanitizer types to make this sink safe.
    pub required_sanitizers: Vec<SanitizerType>,

    /// Function containing this sink.
    pub function_id: String,
}
```

### 4.4 TaintSanitizer — What Makes Data Safe

```rust
/// A sanitizer that removes or neutralizes taint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSanitizer {
    /// Sanitizer definition ID (from registry).
    pub definition_id: String,

    /// The type of sanitization performed.
    pub sanitizer_type: SanitizerType,

    /// Location in source code.
    pub location: CodeLocation,

    /// The expression that sanitizes data.
    pub expression: String,

    /// Which sink types this sanitizer is effective against.
    pub effective_against: Vec<SinkType>,

    /// Function containing this sanitizer.
    pub function_id: String,
}
```

### 4.5 Supporting Types

```rust
/// Taint label — what kind of untrusted data this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaintLabel {
    UserInput,      // HTTP params, form data, URL params
    FileRead,       // Data read from filesystem
    EnvVar,         // Environment variables
    DbRead,         // Data read from database (second-order)
    ApiResponse,    // Data from external API calls
    Deserialized,   // Data from deserialization
    CommandOutput,  // Output from command execution
    Custom(u32),    // User-defined label (ID from TOML)
}

/// Sink type — what dangerous operation is being performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SinkType {
    SqlQuery,           // CWE-89: SQL Injection
    OsCommand,          // CWE-78: OS Command Injection
    CodeExecution,      // CWE-94: Code Injection (eval)
    FileWrite,          // CWE-22: Path Traversal (write)
    FileRead,           // CWE-22: Path Traversal (read)
    HtmlOutput,         // CWE-79: Cross-Site Scripting (XSS)
    HttpRedirect,       // CWE-601: Open Redirect
    HttpRequest,        // CWE-918: Server-Side Request Forgery
    Deserialization,    // CWE-502: Insecure Deserialization
    LdapQuery,          // CWE-90: LDAP Injection
    XpathQuery,         // CWE-643: XPath Injection
    TemplateRender,     // CWE-1336: Template Injection
    LogOutput,          // CWE-117: Log Injection
    HeaderInjection,    // CWE-113: HTTP Response Splitting
    RegexConstruction,  // CWE-1333: ReDoS
    Custom(u32),        // User-defined sink (ID from TOML)
}

/// Sanitizer type — what kind of cleansing is performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SanitizerType {
    HtmlEscape,         // Escapes HTML entities (prevents XSS)
    SqlParameterize,    // Uses parameterized queries (prevents SQLi)
    UrlEncode,          // URL-encodes data
    ShellEscape,        // Escapes shell metacharacters
    PathCanonicalize,   // Canonicalizes file paths
    InputValidation,    // Validates against allowlist/regex
    TypeCast,           // Casts to safe type (parseInt, Number())
    Hashing,            // Cryptographic hash (one-way)
    Encryption,         // Encrypts data
    DomPurify,          // DOM sanitization library
    Custom(u32),        // User-defined sanitizer (ID from TOML)
}

/// Risk level for a taint flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Critical,   // Unsanitized flow to high-severity sink (SQLi, RCE)
    High,       // Unsanitized flow to medium-severity sink (XSS, SSRF)
    Medium,     // Partially sanitized or low-confidence flow
    Low,        // Sanitized flow (informational)
    Info,       // Fully sanitized, reported for awareness only
}

/// A single step in a taint path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintStep {
    /// Location of this step.
    pub location: CodeLocation,
    /// The expression at this step.
    pub expression: String,
    /// What happens to the taint at this step.
    pub action: TaintAction,
    /// Function containing this step.
    pub function_id: String,
}

/// What happens to taint at a given step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaintAction {
    Source { label: TaintLabel },
    Assignment { from: String, to: String },
    FunctionCall { callee: String, arg_index: u32 },
    Return { from_function: String },
    StringConcat,
    CollectionAdd,
    FieldAccess { field: String },
    Sanitize { sanitizer_type: SanitizerType },
    Sink { sink_type: SinkType },
}

/// Code location (file + line + column).
#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct CodeLocation {
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub end_line: Option<u32>,
    pub end_column: Option<u32>,
}
```


---

## 5. Source Registry (Taint Origins)

### 5.1 Built-In Sources by Framework

Sources are where untrusted data enters the application. Each framework has its own
syntax for accessing user input, but the semantic meaning is the same.

```rust
/// Source definition in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceDefinition {
    /// Unique identifier.
    pub id: String,
    /// Language this source applies to.
    pub language: Language,
    /// Framework (None = language-generic).
    pub framework: Option<String>,
    /// Pattern to match (AST pattern or qualified name).
    pub pattern: SourcePattern,
    /// Taint label to apply.
    pub label: TaintLabel,
    /// Whether this is a parameter source (function param is tainted).
    pub is_parameter: bool,
    /// Description for reporting.
    pub description: String,
}

/// How to match a source in code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SourcePattern {
    /// Match a qualified name (e.g., "flask.request.args").
    QualifiedName(String),
    /// Match a member access pattern (e.g., "req.params.$ANYTHING").
    MemberAccess { object: String, property: String },
    /// Match a function call (e.g., "input()").
    FunctionCall { name: String },
    /// Match a decorator/annotation (e.g., "@RequestParam").
    Decorator { name: String, parameter_index: u32 },
    /// Match a type annotation (e.g., "Request" parameter type).
    TypeAnnotation { type_name: String },
}
```

### 5.2 Framework Source Catalog

Per .research/21-security/RECOMMENDATIONS.md TA8:

| Framework | Source Expression | Label | Language |
|-----------|-----------------|-------|----------|
| **Express.js** | `req.params.*` | UserInput | TypeScript/JS |
| | `req.query.*` | UserInput | TypeScript/JS |
| | `req.body.*` | UserInput | TypeScript/JS |
| | `req.headers.*` | UserInput | TypeScript/JS |
| | `req.cookies.*` | UserInput | TypeScript/JS |
| **FastAPI** | Function parameters with type hints | UserInput | Python |
| | `request.query_params.*` | UserInput | Python |
| | `request.path_params.*` | UserInput | Python |
| **Django** | `request.GET.*` | UserInput | Python |
| | `request.POST.*` | UserInput | Python |
| | `request.data` | UserInput | Python |
| | `request.FILES.*` | UserInput | Python |
| **Flask** | `flask.request.args.*` | UserInput | Python |
| | `flask.request.form.*` | UserInput | Python |
| | `flask.request.json` | UserInput | Python |
| **Spring Boot** | `@RequestParam` parameters | UserInput | Java |
| | `@PathVariable` parameters | UserInput | Java |
| | `@RequestBody` parameters | UserInput | Java |
| | `@RequestHeader` parameters | UserInput | Java |
| **Laravel** | `$request->input()` | UserInput | PHP |
| | `$request->get()` | UserInput | PHP |
| | `$request->query()` | UserInput | PHP |
| | `$_GET`, `$_POST`, `$_REQUEST` | UserInput | PHP |
| **Go (Gin)** | `c.Param()` | UserInput | Go |
| | `c.Query()` | UserInput | Go |
| | `c.PostForm()` | UserInput | Go |
| | `c.GetHeader()` | UserInput | Go |
| **ASP.NET** | `[FromQuery]` parameters | UserInput | C# |
| | `[FromBody]` parameters | UserInput | C# |
| | `[FromRoute]` parameters | UserInput | C# |
| | `[FromHeader]` parameters | UserInput | C# |
| **Axum (Rust)** | `Path<T>` extractor | UserInput | Rust |
| | `Query<T>` extractor | UserInput | Rust |
| | `Json<T>` extractor | UserInput | Rust |
| **Generic** | `std::env::var()` / `os.environ` | EnvVar | All |
| | `fs.readFile()` / `open()` | FileRead | All |
| | `fetch()` / `requests.get()` | ApiResponse | All |
| | `stdin` / `input()` | UserInput | All |

### 5.3 Source Registry Implementation

```rust
pub struct SourceRegistry {
    /// Built-in sources (shipped with Drift).
    builtin: Vec<SourceDefinition>,
    /// User-defined sources (from drift.toml or .drift/taint.toml).
    custom: Vec<SourceDefinition>,
    /// Index: language → sources for that language.
    by_language: FxHashMap<Language, Vec<usize>>,
    /// Index: framework → sources for that framework.
    by_framework: FxHashMap<String, Vec<usize>>,
}

impl SourceRegistry {
    /// Load built-in sources + user-defined sources from TOML.
    pub fn load_or_default(config: &TaintConfig) -> Result<Self, TaintError> {
        let mut registry = Self::builtin();

        // Load user-defined sources from config
        if let Some(path) = &config.custom_rules_path {
            let custom = Self::load_from_toml(path)?;
            registry.add_custom(custom);
        }

        registry.build_indexes();
        Ok(registry)
    }

    /// Get all sources applicable to a given language and detected frameworks.
    pub fn sources_for(
        &self,
        language: Language,
        frameworks: &[String],
    ) -> Vec<&SourceDefinition> {
        let mut result = Vec::new();

        // Language-generic sources
        if let Some(indices) = self.by_language.get(&language) {
            for &idx in indices {
                let source = &self.all()[idx];
                if source.framework.is_none() {
                    result.push(source);
                }
            }
        }

        // Framework-specific sources
        for framework in frameworks {
            if let Some(indices) = self.by_framework.get(framework) {
                for &idx in indices {
                    result.push(&self.all()[idx]);
                }
            }
        }

        result
    }

    fn all(&self) -> impl Iterator<Item = &SourceDefinition> {
        self.builtin.iter().chain(self.custom.iter())
    }
}
```

---

## 6. Sink Registry (Dangerous Operations)

### 6.1 Built-In Sinks by CWE

Per .research/21-security/RECOMMENDATIONS.md (Taint Sinks by Category):

| Sink Type | CWE | Dangerous Functions | Languages |
|-----------|-----|-------------------|-----------|
| **SQL Injection** | CWE-89 | `cursor.execute()`, `db.query()`, `$queryRaw`, `raw()`, `createSQLQuery()` | All |
| **OS Command Injection** | CWE-78 | `exec()`, `spawn()`, `system()`, `popen()`, `Runtime.exec()` | All |
| **Code Injection** | CWE-94 | `eval()`, `Function()`, `exec()` (Python), `compile()` | JS/TS/Python |
| **Path Traversal** | CWE-22 | `fs.readFile()`, `open()`, `Path.join()` with user input | All |
| **XSS** | CWE-79 | `innerHTML`, `dangerouslySetInnerHTML`, `res.send()`, `document.write()` | JS/TS |
| **SSRF** | CWE-918 | `fetch()`, `axios()`, `http.get()`, `requests.get()` with user URL | All |
| **Deserialization** | CWE-502 | `pickle.loads()`, `ObjectInputStream.readObject()`, `JSON.parse()` (with eval) | Python/Java |
| **LDAP Injection** | CWE-90 | `ldap.search()`, `ldap.bind()` with user input | All |
| **Template Injection** | CWE-1336 | `render()` with user-controlled template, `Jinja2.from_string()` | Python/JS |
| **Log Injection** | CWE-117 | `logger.info()`, `console.log()` with unsanitized user data | All |
| **Open Redirect** | CWE-601 | `res.redirect()`, `HttpResponseRedirect()` with user URL | All |
| **Header Injection** | CWE-113 | `res.setHeader()`, `response.headers[]` with user data | All |
| **ReDoS** | CWE-1333 | `new RegExp()`, `re.compile()` with user-controlled pattern | All |

### 6.2 Unsafe ORM API Patterns (Auto-Discovered Sinks)

Per .research/21-security/RECOMMENDATIONS.md OR1:

These are ORM methods that bypass parameterization. When user input reaches these,
it's a SQL injection vulnerability regardless of the ORM being used.

```rust
/// ORM-specific raw SQL bypass patterns.
/// These are automatically registered as SQL injection sinks.
pub const UNSAFE_ORM_PATTERNS: &[(&str, &str, &str)] = &[
    // (framework, pattern, description)
    ("prisma",      "$queryRaw",           "Prisma raw query"),
    ("prisma",      "$executeRaw",         "Prisma raw execute"),
    ("prisma",      "$queryRawUnsafe",     "Prisma unsafe raw query"),
    ("django",      ".extra()",            "Django extra() — deprecated, unsafe"),
    ("django",      ".raw()",              "Django raw SQL"),
    ("django",      "RawSQL()",            "Django RawSQL expression"),
    ("django",      "cursor.execute()",    "Django cursor raw execute"),
    ("sqlalchemy",  "text()",              "SQLAlchemy text() — raw SQL"),
    ("sqlalchemy",  "textual()",           "SQLAlchemy textual SQL"),
    ("eloquent",    "DB::raw()",           "Laravel raw expression"),
    ("eloquent",    "whereRaw()",          "Laravel raw WHERE"),
    ("eloquent",    "selectRaw()",         "Laravel raw SELECT"),
    ("spring-data", "@Query(nativeQuery)", "Spring native query with concat"),
    ("hibernate",   "createSQLQuery()",    "Hibernate raw SQL with concat"),
    ("gorm",        "db.Raw()",            "GORM raw SQL"),
    ("gorm",        "db.Exec()",           "GORM raw exec"),
    ("knex",        ".raw()",              "Knex raw SQL"),
    ("knex",        "knex.raw()",          "Knex raw expression"),
    ("sequelize",   "sequelize.query()",   "Sequelize raw query"),
    ("typeorm",     ".query()",            "TypeORM raw query"),
];
```

### 6.3 Sink Registry Implementation

```rust
/// Sink definition in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkDefinition {
    /// Unique identifier.
    pub id: String,
    /// Sink type (maps to CWE).
    pub sink_type: SinkType,
    /// Language this sink applies to.
    pub language: Language,
    /// Framework (None = language-generic).
    pub framework: Option<String>,
    /// Pattern to match.
    pub pattern: SinkPattern,
    /// Which parameter index receives the dangerous data.
    /// -1 means the receiver/object itself.
    pub tainted_parameter: i32,
    /// CWE IDs for this sink.
    pub cwe_ids: Vec<u32>,
    /// OWASP categories.
    pub owasp_categories: Vec<String>,
    /// Required sanitizer types to make this sink safe.
    pub required_sanitizers: Vec<SanitizerType>,
    /// Severity if tainted data reaches this sink unsanitized.
    pub severity: Severity,
    /// Description for reporting.
    pub description: String,
}

/// How to match a sink in code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SinkPattern {
    /// Match a function call by name.
    FunctionCall { name: String, receiver: Option<String> },
    /// Match a property assignment (e.g., `element.innerHTML = ...`).
    PropertyAssignment { object: String, property: String },
    /// Match a template literal with interpolation in dangerous context.
    TemplateLiteral { context: String },
    /// Match a string concatenation in dangerous context.
    StringConcat { context: String },
}

pub struct SinkRegistry {
    builtin: Vec<SinkDefinition>,
    custom: Vec<SinkDefinition>,
    by_language: FxHashMap<Language, Vec<usize>>,
    by_sink_type: FxHashMap<SinkType, Vec<usize>>,
    by_cwe: FxHashMap<u32, Vec<usize>>,
}
```


---

## 7. Sanitizer Registry (Data Cleansing)

### 7.1 Sanitizer-to-Sink Effectiveness Matrix

Not all sanitizers protect against all sinks. HTML escaping prevents XSS but not SQLi.
Parameterized queries prevent SQLi but not XSS. The registry tracks which sanitizers
are effective against which sink types.

| Sanitizer Type | Effective Against | NOT Effective Against |
|---------------|------------------|---------------------|
| HtmlEscape | XSS, Template Injection | SQLi, Command Injection, SSRF |
| SqlParameterize | SQL Injection | XSS, Command Injection, SSRF |
| UrlEncode | Open Redirect, SSRF (partial) | SQLi, XSS, Command Injection |
| ShellEscape | OS Command Injection | SQLi, XSS, SSRF |
| PathCanonicalize | Path Traversal | SQLi, XSS, Command Injection |
| InputValidation | All (if allowlist-based) | None (if blocklist-based) |
| TypeCast | SQLi (parseInt), XSS | Command Injection, SSRF |
| DomPurify | XSS (DOM-based) | SQLi, Command Injection |

### 7.2 Built-In Sanitizer Catalog

```rust
/// Sanitizer definition in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizerDefinition {
    /// Unique identifier.
    pub id: String,
    /// Sanitizer type.
    pub sanitizer_type: SanitizerType,
    /// Language this sanitizer applies to.
    pub language: Language,
    /// Pattern to match.
    pub pattern: SanitizerPattern,
    /// Which sink types this sanitizer is effective against.
    pub effective_against: Vec<SinkType>,
    /// Whether this sanitizer fully removes taint or just reduces risk.
    pub removes_taint: bool,
    /// Description for reporting.
    pub description: String,
}

/// How to match a sanitizer in code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SanitizerPattern {
    /// Match a function call (e.g., `escapeHtml(data)`).
    FunctionCall { name: String, receiver: Option<String> },
    /// Match a type cast (e.g., `parseInt(data, 10)`).
    TypeCast { target_type: String },
    /// Match a method call on the tainted value (e.g., `data.trim()`).
    MethodCall { method: String },
    /// Match a validation pattern (e.g., `if (isValid(data)) { ... }`).
    ValidationGuard { validator: String },
}
```

**Per-Language Sanitizer Examples:**

| Language | Sanitizer | Type | Effective Against |
|----------|-----------|------|------------------|
| **JavaScript/TS** | `parseInt()`, `Number()` | TypeCast | SQLi |
| | `encodeURIComponent()` | UrlEncode | Open Redirect, SSRF |
| | `DOMPurify.sanitize()` | DomPurify | XSS |
| | `escape()` (lodash) | HtmlEscape | XSS |
| | `validator.isEmail()` | InputValidation | All |
| **Python** | `int()`, `float()` | TypeCast | SQLi |
| | `bleach.clean()` | HtmlEscape | XSS |
| | `shlex.quote()` | ShellEscape | Command Injection |
| | `os.path.realpath()` | PathCanonicalize | Path Traversal |
| | `markupsafe.escape()` | HtmlEscape | XSS |
| **Java** | `Integer.parseInt()` | TypeCast | SQLi |
| | `StringEscapeUtils.escapeHtml4()` | HtmlEscape | XSS |
| | `PreparedStatement` (parameterized) | SqlParameterize | SQLi |
| | `Paths.get().normalize()` | PathCanonicalize | Path Traversal |
| **Go** | `strconv.Atoi()` | TypeCast | SQLi |
| | `html.EscapeString()` | HtmlEscape | XSS |
| | `filepath.Clean()` | PathCanonicalize | Path Traversal |
| **PHP** | `intval()` | TypeCast | SQLi |
| | `htmlspecialchars()` | HtmlEscape | XSS |
| | `escapeshellarg()` | ShellEscape | Command Injection |
| | `realpath()` | PathCanonicalize | Path Traversal |
| **C#** | `int.Parse()` | TypeCast | SQLi |
| | `HttpUtility.HtmlEncode()` | HtmlEscape | XSS |
| | `Path.GetFullPath()` | PathCanonicalize | Path Traversal |
| **Rust** | Parameterized queries (default in Diesel/SeaORM) | SqlParameterize | SQLi |
| | `ammonia::clean()` | HtmlEscape | XSS |

### 7.3 Sanitizer Matching Strategy

Sanitizers are matched in two ways:

1. **Direct match**: The sanitizer function is called on the tainted value.
   `escapeHtml(userInput)` → taint is removed for XSS sinks.

2. **Validation guard**: The tainted value is checked in a conditional, and only
   the "valid" branch is considered sanitized.
   ```javascript
   if (isValidEmail(userInput)) {
       // userInput is considered sanitized here
       db.query(`... WHERE email = '${userInput}'`);
   }
   ```

For Phase 1 (intraprocedural), only direct match is implemented.
Validation guards are Phase 2 (requires control flow analysis).

---

## 8. Propagator Model (How Taint Flows)

### 8.1 Taint Propagation Rules

Taint propagates through code via assignments, function calls, string operations,
and collection operations. The propagator model defines how taint flows through
each type of operation.

```rust
/// Rules for how taint propagates through operations.
pub struct PropagatorRules {
    /// Assignment propagation: `y = x` → if x is tainted, y is tainted.
    pub assignment: bool,

    /// String concatenation: `y = x + "safe"` → if x is tainted, y is tainted.
    pub string_concat: bool,

    /// Template literal: `` `${x}` `` → if x is tainted, result is tainted.
    pub template_literal: bool,

    /// Collection operations: `arr.push(x)` → if x is tainted, arr is tainted.
    pub collection_add: bool,

    /// Spread operator: `{...x}` → if x is tainted, result is tainted.
    pub spread: bool,

    /// Destructuring: `const {a, b} = x` → if x is tainted, a and b are tainted.
    pub destructuring: bool,

    /// Field access: `x.field` → if x is tainted, x.field is tainted.
    pub field_access: bool,

    /// Array index: `x[i]` → if x is tainted, x[i] is tainted.
    pub array_index: bool,

    /// Ternary: `cond ? x : y` → if x OR y is tainted, result is tainted.
    pub ternary: bool,

    /// Logical OR: `x || y` → if x OR y is tainted, result is tainted.
    pub logical_or: bool,

    /// Nullish coalescing: `x ?? y` → if x OR y is tainted, result is tainted.
    pub nullish_coalescing: bool,
}

impl Default for PropagatorRules {
    fn default() -> Self {
        Self {
            assignment: true,
            string_concat: true,
            template_literal: true,
            collection_add: true,
            spread: true,
            destructuring: true,
            field_access: true,
            array_index: true,
            ternary: true,
            logical_or: true,
            nullish_coalescing: true,
        }
    }
}
```

### 8.2 Taint State Tracking

During intraprocedural analysis, the engine maintains a taint state map that tracks
which variables/expressions are currently tainted and with what labels.

```rust
/// Taint state for a single function analysis.
pub struct TaintState {
    /// Variable name → set of taint labels.
    /// A variable can carry multiple taint labels simultaneously.
    tainted: FxHashMap<String, TaintLabelSet>,

    /// Sanitized variables: variable → set of sanitizer types applied.
    sanitized: FxHashMap<String, Vec<SanitizerType>>,

    /// Path from source to current point (for reporting).
    paths: FxHashMap<String, Vec<TaintStep>>,
}

/// A set of taint labels (bitset for efficiency).
#[derive(Debug, Clone, Default)]
pub struct TaintLabelSet {
    bits: u64,  // Up to 64 taint labels (8 built-in + 56 custom)
}

impl TaintLabelSet {
    pub fn add(&mut self, label: TaintLabel) { self.bits |= 1 << label.as_u8(); }
    pub fn contains(&self, label: TaintLabel) -> bool { self.bits & (1 << label.as_u8()) != 0 }
    pub fn is_empty(&self) -> bool { self.bits == 0 }
    pub fn union(&self, other: &Self) -> Self { Self { bits: self.bits | other.bits } }
    pub fn clear(&mut self) { self.bits = 0; }
}

impl TaintState {
    /// Mark a variable as tainted with a given label.
    pub fn taint(&mut self, var: &str, label: TaintLabel, step: TaintStep) {
        self.tainted.entry(var.to_string())
            .or_default()
            .add(label);
        self.paths.entry(var.to_string())
            .or_default()
            .push(step);
    }

    /// Mark a variable as sanitized by a given sanitizer type.
    pub fn sanitize(&mut self, var: &str, sanitizer_type: SanitizerType) {
        self.sanitized.entry(var.to_string())
            .or_default()
            .push(sanitizer_type);
    }

    /// Check if a variable is tainted (has any taint labels).
    pub fn is_tainted(&self, var: &str) -> bool {
        self.tainted.get(var).map_or(false, |labels| !labels.is_empty())
    }

    /// Check if a variable is sanitized against a specific sink type.
    pub fn is_sanitized_for(&self, var: &str, sink_type: SinkType, registry: &SanitizerRegistry) -> bool {
        if let Some(sanitizers) = self.sanitized.get(var) {
            sanitizers.iter().any(|s| registry.is_effective(s, &sink_type))
        } else {
            false
        }
    }

    /// Propagate taint from one variable to another (assignment).
    pub fn propagate(&mut self, from: &str, to: &str, step: TaintStep) {
        if let Some(labels) = self.tainted.get(from).cloned() {
            self.tainted.entry(to.to_string())
                .or_default()
                .bits |= labels.bits;
            // Copy path and extend
            if let Some(path) = self.paths.get(from).cloned() {
                let mut new_path = path;
                new_path.push(step);
                self.paths.insert(to.to_string(), new_path);
            }
        }
        // Also propagate sanitization status
        if let Some(sanitizers) = self.sanitized.get(from).cloned() {
            self.sanitized.entry(to.to_string())
                .or_default()
                .extend(sanitizers);
        }
    }
}
```


---

## 9. Intraprocedural Taint Analysis (Phase 1)

### 9.1 Algorithm

Intraprocedural analysis operates within a single function. It walks the function's
GAST (Generic AST) in execution order, maintaining a TaintState that tracks which
variables are tainted at each point.

```rust
/// Intraprocedural taint analyzer.
/// Analyzes a single function for taint flows.
pub struct IntraprocAnalyzer<'a> {
    sources: &'a SourceRegistry,
    sinks: &'a SinkRegistry,
    sanitizers: &'a SanitizerRegistry,
    propagators: &'a PropagatorRules,
    summaries: &'a FxHashMap<FunctionId, TaintSummary>,
    ctx: &'a TaintContext,
    state: TaintState,
    flows: Vec<TaintFlow>,
}

impl<'a> IntraprocAnalyzer<'a> {
    /// Analyze a function's GAST for taint flows.
    pub fn analyze(
        &mut self,
        func: &FunctionInfo,
        gast: &GASTNode,
    ) -> Result<Vec<TaintFlow>, TaintError> {
        // Step 1: Mark function parameters as tainted if they match sources
        self.initialize_parameter_taint(func);

        // Step 2: Walk the GAST in execution order
        self.visit_node(gast)?;

        // Step 3: Return discovered flows
        Ok(std::mem::take(&mut self.flows))
    }

    /// Initialize taint for function parameters.
    /// HTTP handler parameters are tainted by default (framework-specific).
    fn initialize_parameter_taint(&mut self, func: &FunctionInfo) {
        for source in self.sources.sources_for(self.ctx.language, &self.ctx.frameworks) {
            match &source.pattern {
                SourcePattern::Decorator { name, parameter_index } => {
                    // Check if function has this decorator
                    if func.decorators.iter().any(|d| d.contains(name.as_str())) {
                        if let Some(param) = func.parameters.get(*parameter_index as usize) {
                            self.state.taint(
                                &param.name,
                                source.label,
                                TaintStep {
                                    location: CodeLocation::from_func(func),
                                    expression: format!("parameter '{}'", param.name),
                                    action: TaintAction::Source { label: source.label },
                                    function_id: func.id(),
                                },
                            );
                        }
                    }
                }
                SourcePattern::TypeAnnotation { type_name } => {
                    // Check if any parameter has this type
                    for param in &func.parameters {
                        if param.type_annotation.as_deref() == Some(type_name.as_str()) {
                            self.state.taint(
                                &param.name,
                                source.label,
                                TaintStep {
                                    location: CodeLocation::from_func(func),
                                    expression: format!("parameter '{}' of type '{}'", param.name, type_name),
                                    action: TaintAction::Source { label: source.label },
                                    function_id: func.id(),
                                },
                            );
                        }
                    }
                }
                _ => {} // Other source patterns are matched during traversal
            }
        }
    }

    /// Visit a GAST node and update taint state.
    fn visit_node(&mut self, node: &GASTNode) -> Result<(), TaintError> {
        match node {
            // === Assignments: propagate taint ===
            GASTNode::Variable { name, value: Some(value), .. } => {
                self.visit_node(value)?;
                let expr_name = self.expression_name(value);
                if self.state.is_tainted(&expr_name) {
                    self.state.propagate(
                        &expr_name,
                        name,
                        TaintStep {
                            location: self.node_location(node),
                            expression: format!("{} = {}", name, expr_name),
                            action: TaintAction::Assignment {
                                from: expr_name.clone(),
                                to: name.clone(),
                            },
                            function_id: self.ctx.current_function.clone(),
                        },
                    );
                }
            }

            GASTNode::Assignment { target, value } => {
                self.visit_node(value)?;
                let target_name = self.expression_name(target);
                let value_name = self.expression_name(value);
                if self.state.is_tainted(&value_name) {
                    self.state.propagate(
                        &value_name,
                        &target_name,
                        TaintStep {
                            location: self.node_location(node),
                            expression: format!("{} = {}", target_name, value_name),
                            action: TaintAction::Assignment {
                                from: value_name,
                                to: target_name.clone(),
                            },
                            function_id: self.ctx.current_function.clone(),
                        },
                    );
                }
            }

            // === Function calls: check sources, sinks, sanitizers ===
            GASTNode::Call { callee, args, .. } => {
                // Visit arguments first
                for arg in args {
                    self.visit_node(arg)?;
                }

                let callee_name = self.expression_name(callee);

                // Check if this call is a source
                self.check_source_call(&callee_name, node);

                // Check if this call is a sanitizer
                self.check_sanitizer_call(&callee_name, args, node);

                // Check if this call is a sink
                self.check_sink_call(&callee_name, args, node)?;

                // Check interprocedural summary (if available)
                self.apply_callee_summary(&callee_name, args, node);
            }

            // === Member access: propagate taint through field access ===
            GASTNode::MemberAccess { object, property, .. } => {
                self.visit_node(object)?;
                let obj_name = self.expression_name(object);

                // Check if this is a source (e.g., req.params.id)
                let full_name = format!("{}.{}", obj_name, property);
                self.check_source_member_access(&full_name, node);

                // Propagate taint from object to member access
                if self.propagators.field_access && self.state.is_tainted(&obj_name) {
                    self.state.propagate(
                        &obj_name,
                        &full_name,
                        TaintStep {
                            location: self.node_location(node),
                            expression: full_name.clone(),
                            action: TaintAction::FieldAccess { field: property.clone() },
                            function_id: self.ctx.current_function.clone(),
                        },
                    );
                }
            }

            // === Template literals: propagate taint through interpolation ===
            GASTNode::TemplateLiteral { parts } => {
                for part in parts {
                    if let TemplatePart::Expression(expr) = part {
                        self.visit_node(expr)?;
                    }
                }
                // If any interpolated expression is tainted, the whole template is tainted
                let template_name = self.node_temp_name(node);
                for part in parts {
                    if let TemplatePart::Expression(expr) = part {
                        let expr_name = self.expression_name(expr);
                        if self.state.is_tainted(&expr_name) {
                            self.state.propagate(
                                &expr_name,
                                &template_name,
                                TaintStep {
                                    location: self.node_location(node),
                                    expression: "template literal".to_string(),
                                    action: TaintAction::StringConcat,
                                    function_id: self.ctx.current_function.clone(),
                                },
                            );
                        }
                    }
                }
            }

            // === Binary operations: propagate taint through string concat ===
            GASTNode::BinaryOp { left, op, right } if op == "+" => {
                self.visit_node(left)?;
                self.visit_node(right)?;
                let left_name = self.expression_name(left);
                let right_name = self.expression_name(right);
                let result_name = self.node_temp_name(node);

                if self.propagators.string_concat {
                    if self.state.is_tainted(&left_name) {
                        self.state.propagate(&left_name, &result_name, TaintStep {
                            location: self.node_location(node),
                            expression: format!("{} + {}", left_name, right_name),
                            action: TaintAction::StringConcat,
                            function_id: self.ctx.current_function.clone(),
                        });
                    }
                    if self.state.is_tainted(&right_name) {
                        self.state.propagate(&right_name, &result_name, TaintStep {
                            location: self.node_location(node),
                            expression: format!("{} + {}", left_name, right_name),
                            action: TaintAction::StringConcat,
                            function_id: self.ctx.current_function.clone(),
                        });
                    }
                }
            }

            // === Return: track what the function returns (for summaries) ===
            GASTNode::Return { value: Some(value) } => {
                self.visit_node(value)?;
                let value_name = self.expression_name(value);
                if self.state.is_tainted(&value_name) {
                    self.state.taint(
                        "__return__",
                        TaintLabel::UserInput, // Will be refined by actual label
                        TaintStep {
                            location: self.node_location(node),
                            expression: format!("return {}", value_name),
                            action: TaintAction::Return {
                                from_function: self.ctx.current_function.clone(),
                            },
                            function_id: self.ctx.current_function.clone(),
                        },
                    );
                }
            }

            // === Recurse into children for all other nodes ===
            _ => {
                for child in node.children() {
                    self.visit_node(child)?;
                }
            }
        }

        Ok(())
    }

    /// Check if a function call is a sink and report a taint flow if so.
    fn check_sink_call(
        &mut self,
        callee_name: &str,
        args: &[GASTNode],
        node: &GASTNode,
    ) -> Result<(), TaintError> {
        for sink_def in self.sinks.sinks_for(self.ctx.language, &self.ctx.frameworks) {
            if self.matches_sink_pattern(callee_name, &sink_def.pattern) {
                // Check if the tainted parameter is actually tainted
                let param_idx = sink_def.tainted_parameter as usize;
                if let Some(arg) = args.get(param_idx) {
                    let arg_name = self.expression_name(arg);
                    if self.state.is_tainted(&arg_name) {
                        // Check if sanitized for this sink type
                        let is_sanitized = self.state.is_sanitized_for(
                            &arg_name,
                            sink_def.sink_type,
                            self.sanitizers,
                        );

                        let risk = if is_sanitized {
                            RiskLevel::Info
                        } else {
                            self.risk_from_severity(sink_def.severity)
                        };

                        // Build the taint path
                        let path = self.state.paths.get(&arg_name)
                            .cloned()
                            .unwrap_or_default();

                        let flow = TaintFlow {
                            id: self.generate_flow_id(),
                            source: self.build_source(&arg_name),
                            sink: TaintSink {
                                definition_id: sink_def.id.clone(),
                                sink_type: sink_def.sink_type,
                                location: self.node_location(node),
                                expression: callee_name.to_string(),
                                tainted_parameter: sink_def.tainted_parameter as u32,
                                cwe_ids: sink_def.cwe_ids.clone(),
                                required_sanitizers: sink_def.required_sanitizers.clone(),
                                function_id: self.ctx.current_function.clone(),
                            },
                            path,
                            sanitizers: self.collect_sanitizers(&arg_name),
                            is_sanitized,
                            risk,
                            confidence: self.compute_confidence(is_sanitized),
                            cwe_ids: sink_def.cwe_ids.clone(),
                            owasp_categories: sink_def.owasp_categories.clone(),
                            is_interprocedural: false,
                            source_file: self.ctx.file_path.clone(),
                            sink_file: self.ctx.file_path.clone(),
                        };

                        self.flows.push(flow);
                    }
                }
            }
        }
        Ok(())
    }
}
```

### 9.2 Confidence Scoring for Taint Flows

```rust
impl IntraprocAnalyzer<'_> {
    /// Compute confidence for a taint flow.
    fn compute_confidence(&self, is_sanitized: bool) -> f64 {
        let mut confidence = 1.0;

        // Reduce confidence for sanitized flows (informational only)
        if is_sanitized {
            confidence *= 0.3;
        }

        // Reduce confidence for long paths (more likely to be false positive)
        let path_len = self.flows.last()
            .map(|f| f.path.len())
            .unwrap_or(0);
        if path_len > 10 {
            confidence *= 0.8;
        }
        if path_len > 20 {
            confidence *= 0.6;
        }

        // Reduce confidence for fuzzy-resolved call edges
        // (interprocedural only — intraprocedural is always high confidence)

        confidence.clamp(0.1, 1.0)
    }
}
```


---

## 10. Interprocedural Taint Analysis via Function Summaries (Phase 2)

### 10.1 Function Summary Model

Per FlowDroid (Arzt et al., PLDI 2014): function summaries capture the taint behavior
of a function without requiring re-analysis at every call site. A summary says:
"If parameter N is tainted, then the return value / parameter M is tainted."

```rust
/// Taint summary for a single function.
/// Pre-computed during bottom-up analysis, used by callers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSummary {
    /// Function this summary describes.
    pub function_id: String,

    /// Parameter-to-return taint transfers.
    /// If parameter at index N is tainted, return value is tainted.
    pub param_to_return: Vec<ParamTaintTransfer>,

    /// Parameter-to-parameter taint transfers (via mutation).
    /// If parameter at index N is tainted, parameter at index M becomes tainted.
    pub param_to_param: Vec<ParamToParamTransfer>,

    /// Parameter-to-sink flows.
    /// If parameter at index N is tainted, it reaches sink S.
    pub param_to_sink: Vec<ParamToSinkFlow>,

    /// Internal sources (function creates tainted data internally).
    pub internal_sources: Vec<InternalSource>,

    /// Whether this function acts as a sanitizer.
    pub is_sanitizer: bool,

    /// If sanitizer, what type.
    pub sanitizer_type: Option<SanitizerType>,

    /// Confidence in this summary (based on analysis completeness).
    pub confidence: f64,
}

/// Transfer: if param[from_param] is tainted, return value is tainted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamTaintTransfer {
    pub from_param: u32,
    pub taint_labels: TaintLabelSet,
    /// Whether the taint is transformed (e.g., string concat changes the data).
    pub transformation: Option<TaintAction>,
}

/// Transfer: if param[from_param] is tainted, param[to_param] becomes tainted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamToParamTransfer {
    pub from_param: u32,
    pub to_param: u32,
}

/// Flow: if param[param_index] is tainted, it reaches this sink.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamToSinkFlow {
    pub param_index: u32,
    pub sink: TaintSink,
    pub is_sanitized: bool,
    pub path: Vec<TaintStep>,
}

/// Internal source: function creates tainted data (e.g., reads from DB).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalSource {
    pub label: TaintLabel,
    pub flows_to_return: bool,
    pub flows_to_param: Option<u32>,
}
```

### 10.2 Bottom-Up Summary Computation

```rust
impl TaintEngine {
    /// Compute taint summary for a function.
    /// Assumes callees already have summaries (bottom-up order).
    fn compute_summary(
        &self,
        func_id: &FunctionId,
        parse_results: &[ParseResult],
    ) -> Result<TaintSummary, TaintError> {
        let (func, gast) = self.find_function(func_id, parse_results)?;

        // Create a special analysis context where each parameter is
        // individually tainted to discover transfer relationships.
        let mut param_to_return = Vec::new();
        let mut param_to_sink = Vec::new();

        for (idx, param) in func.parameters.iter().enumerate() {
            // Analyze with only this parameter tainted
            let mut analyzer = IntraprocAnalyzer::new(
                &self.source_registry,
                &self.sink_registry,
                &self.sanitizer_registry,
                &self.propagator_rules,
                &self.summaries,
                &TaintContext::for_summary(func, parse_results),
            );

            // Taint this parameter
            analyzer.state.taint(
                &param.name,
                TaintLabel::UserInput, // Generic label for summary computation
                TaintStep {
                    location: CodeLocation::from_func(func),
                    expression: format!("param[{}]", idx),
                    action: TaintAction::Source { label: TaintLabel::UserInput },
                    function_id: func.id(),
                },
            );

            // Run analysis
            let flows = analyzer.analyze(func, &gast)?;

            // Check if return value is tainted
            if analyzer.state.is_tainted("__return__") {
                param_to_return.push(ParamTaintTransfer {
                    from_param: idx as u32,
                    taint_labels: analyzer.state.tainted
                        .get("__return__")
                        .cloned()
                        .unwrap_or_default(),
                    transformation: None,
                });
            }

            // Collect param-to-sink flows
            for flow in flows {
                param_to_sink.push(ParamToSinkFlow {
                    param_index: idx as u32,
                    sink: flow.sink,
                    is_sanitized: flow.is_sanitized,
                    path: flow.path,
                });
            }
        }

        // Check if this function is a sanitizer
        let is_sanitizer = self.sanitizer_registry
            .matches_function(func_id)
            .is_some();
        let sanitizer_type = self.sanitizer_registry
            .matches_function(func_id)
            .map(|s| s.sanitizer_type);

        Ok(TaintSummary {
            function_id: func_id.to_string(),
            param_to_return,
            param_to_param: Vec::new(), // TODO: mutation tracking
            param_to_sink,
            internal_sources: Vec::new(), // TODO: internal source detection
            is_sanitizer,
            sanitizer_type,
            confidence: 0.9, // High confidence for intraprocedural summary
        })
    }

    /// Get topological order of call graph (leaves first).
    /// Functions with no callees are analyzed first, then their callers, etc.
    fn topological_order(&self) -> Result<Vec<FunctionId>, TaintError> {
        match &self.call_graph {
            Some(graph) => {
                // Use petgraph's topological sort (reversed for bottom-up)
                let mut order: Vec<_> = petgraph::algo::toposort(&graph.graph, None)
                    .map_err(|_| TaintError::CyclicCallGraph)?;
                order.reverse(); // Bottom-up: leaves first
                Ok(order.into_iter()
                    .map(|idx| graph.node_id(idx))
                    .collect())
            }
            None => {
                // Fallback: analyze in file order (less precise but functional)
                tracing::warn!("No call graph available; using file order for taint summaries");
                Ok(Vec::new())
            }
        }
    }
}
```

### 10.3 Applying Callee Summaries at Call Sites

```rust
impl IntraprocAnalyzer<'_> {
    /// Apply a callee's taint summary at a call site.
    /// If any argument is tainted and the summary says it flows to return,
    /// then the call result is tainted.
    fn apply_callee_summary(
        &mut self,
        callee_name: &str,
        args: &[GASTNode],
        node: &GASTNode,
    ) {
        // Look up callee summary
        let callee_id = self.resolve_callee(callee_name);
        let summary = match callee_id.and_then(|id| self.summaries.get(&id)) {
            Some(s) => s,
            None => return, // No summary available — conservative (no propagation)
        };

        // Check if callee is a sanitizer
        if summary.is_sanitizer {
            if let Some(sanitizer_type) = summary.sanitizer_type {
                // Sanitize all tainted arguments
                for arg in args {
                    let arg_name = self.expression_name(arg);
                    if self.state.is_tainted(&arg_name) {
                        self.state.sanitize(&arg_name, sanitizer_type);
                    }
                }
            }
            return;
        }

        // Apply param-to-return transfers
        let result_name = self.node_temp_name(node);
        for transfer in &summary.param_to_return {
            let param_idx = transfer.from_param as usize;
            if let Some(arg) = args.get(param_idx) {
                let arg_name = self.expression_name(arg);
                if self.state.is_tainted(&arg_name) {
                    self.state.propagate(
                        &arg_name,
                        &result_name,
                        TaintStep {
                            location: self.node_location(node),
                            expression: format!("{}(...) [param {} → return]", callee_name, param_idx),
                            action: TaintAction::FunctionCall {
                                callee: callee_name.to_string(),
                                arg_index: param_idx as u32,
                            },
                            function_id: self.ctx.current_function.clone(),
                        },
                    );
                }
            }
        }

        // Apply param-to-sink flows (report interprocedural taint flows)
        for flow in &summary.param_to_sink {
            let param_idx = flow.param_index as usize;
            if let Some(arg) = args.get(param_idx) {
                let arg_name = self.expression_name(arg);
                if self.state.is_tainted(&arg_name) && !flow.is_sanitized {
                    // Build interprocedural flow
                    let mut path = self.state.paths.get(&arg_name)
                        .cloned()
                        .unwrap_or_default();
                    path.push(TaintStep {
                        location: self.node_location(node),
                        expression: format!("{}(...) [interprocedural]", callee_name),
                        action: TaintAction::FunctionCall {
                            callee: callee_name.to_string(),
                            arg_index: param_idx as u32,
                        },
                        function_id: self.ctx.current_function.clone(),
                    });
                    path.extend(flow.path.clone());

                    let taint_flow = TaintFlow {
                        id: self.generate_flow_id(),
                        source: self.build_source(&arg_name),
                        sink: flow.sink.clone(),
                        path,
                        sanitizers: self.collect_sanitizers(&arg_name),
                        is_sanitized: false,
                        risk: RiskLevel::High, // Interprocedural unsanitized = high risk
                        confidence: 0.8, // Slightly lower for interprocedural
                        cwe_ids: flow.sink.cwe_ids.clone(),
                        owasp_categories: Vec::new(),
                        is_interprocedural: true,
                        source_file: self.ctx.file_path.clone(),
                        sink_file: flow.sink.location.file.clone(),
                    };

                    self.flows.push(taint_flow);
                }
            }
        }
    }
}
```

### 10.4 Handling Cycles in the Call Graph

Real call graphs contain cycles (recursion, mutual recursion). The topological sort
will fail for cyclic components. Strategy:

1. Detect strongly connected components (SCCs) using Tarjan's algorithm
2. For each SCC, compute a conservative summary (assume all params taint return)
3. Iterate within the SCC until summaries stabilize (fixed-point iteration)
4. Maximum 3 iterations per SCC (per Semgrep's pragmatic approach)

```rust
impl TaintEngine {
    fn handle_cyclic_components(
        &mut self,
        parse_results: &[ParseResult],
    ) -> Result<(), TaintError> {
        let sccs = petgraph::algo::tarjan_scc(&self.call_graph.as_ref().unwrap().graph);

        for scc in sccs {
            if scc.len() == 1 {
                // Single node — no cycle, compute normally
                let func_id = self.call_graph.as_ref().unwrap().node_id(scc[0]);
                let summary = self.compute_summary(&func_id, parse_results)?;
                self.summaries.insert(func_id, summary);
            } else {
                // Cycle detected — fixed-point iteration
                tracing::debug!(scc_size = scc.len(), "Computing taint summaries for cyclic SCC");

                // Initialize with conservative summaries
                for &node_idx in &scc {
                    let func_id = self.call_graph.as_ref().unwrap().node_id(node_idx);
                    self.summaries.insert(func_id.clone(), TaintSummary::conservative(&func_id));
                }

                // Iterate until stable (max 3 iterations)
                for iteration in 0..3 {
                    let mut changed = false;
                    for &node_idx in &scc {
                        let func_id = self.call_graph.as_ref().unwrap().node_id(node_idx);
                        let new_summary = self.compute_summary(&func_id, parse_results)?;
                        let old_summary = self.summaries.get(&func_id);
                        if old_summary != Some(&new_summary) {
                            self.summaries.insert(func_id, new_summary);
                            changed = true;
                        }
                    }
                    if !changed {
                        tracing::debug!(iterations = iteration + 1, "SCC summaries stabilized");
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}
```


---

## 11. Taint Label System (Multi-Type Tracking)

### 11.1 Why Multiple Labels

A single variable can carry multiple taint labels simultaneously. For example:

```javascript
const data = req.body;           // UserInput
const enriched = await fetch(    // ApiResponse
    `https://api.example.com/enrich?q=${data}`
);
const result = JSON.parse(enriched.body);  // UserInput + ApiResponse
db.query(`SELECT * FROM users WHERE id = ${result.id}`);  // Both labels reach sink
```

The label system tracks which types of untrusted data are present, enabling:
- More precise risk assessment (UserInput → SQLi is critical; DbRead → SQLi is medium)
- Better remediation advice (different sanitizers for different source types)
- Compliance reporting (which data types flow where)

### 11.2 Label Hierarchy

```
TaintLabel
├── UserInput (highest risk — directly attacker-controlled)
│   ├── HttpParam (URL parameters)
│   ├── HttpBody (request body)
│   ├── HttpHeader (request headers)
│   └── HttpCookie (cookies)
├── FileRead (medium risk — file contents)
├── EnvVar (medium risk — environment variables)
├── DbRead (medium-low risk — second-order injection)
├── ApiResponse (medium risk — external API data)
├── Deserialized (high risk — deserialized objects)
├── CommandOutput (medium risk — command execution output)
└── Custom(u32) (user-defined)
```

### 11.3 Risk Matrix: Label × Sink

| Label \ Sink | SQLi | XSS | Command Inj. | Path Traversal | SSRF |
|-------------|------|-----|-------------|---------------|------|
| UserInput | Critical | Critical | Critical | Critical | Critical |
| FileRead | High | High | High | Medium | Medium |
| EnvVar | Medium | Low | High | Medium | Medium |
| DbRead | High | High | Medium | Medium | Low |
| ApiResponse | High | High | Medium | Medium | High |
| Deserialized | Critical | High | Critical | High | High |
| CommandOutput | Medium | Medium | High | Medium | Medium |

---

## 12. Declarative Taint Rule Definitions (TOML)

### 12.1 User-Extensible Rules

Per AD3 and SAD3: taint rules should be declarative TOML, enabling users to add
custom sources, sinks, and sanitizers without recompiling Drift.

```toml
# .drift/taint.toml — User-defined taint rules

# Custom source: internal auth service returns user-controlled data
[[taint.sources]]
id = "auth-service-user"
language = "typescript"
framework = "express"
pattern = { type = "function_call", name = "authService.getUser" }
label = "user-input"
description = "Auth service returns user-controlled profile data"

# Custom sink: internal logging that should not receive PII
[[taint.sinks]]
id = "audit-log-pii"
language = "typescript"
pattern = { type = "function_call", name = "auditLog.write", receiver = "auditLog" }
tainted_parameter = 0
cwe_ids = [532]
owasp_categories = ["A09"]
required_sanitizers = ["input-validation"]
severity = "warning"
description = "Audit log should not contain raw PII"

# Custom sanitizer: internal validation library
[[taint.sanitizers]]
id = "internal-validator"
language = "typescript"
pattern = { type = "function_call", name = "validateInput" }
sanitizer_type = "input-validation"
effective_against = ["sql-query", "os-command", "html-output"]
removes_taint = true
description = "Internal input validation library"

# Custom propagator: disable taint through specific function
[[taint.propagator_overrides]]
function = "deepClone"
propagates = false  # deepClone does NOT propagate taint (safe copy)
```

### 12.2 TOML Schema

```rust
/// Parsed TOML taint configuration.
#[derive(Debug, Deserialize)]
pub struct TaintTomlConfig {
    pub taint: TaintSection,
}

#[derive(Debug, Deserialize)]
pub struct TaintSection {
    #[serde(default)]
    pub sources: Vec<TomlSourceDef>,
    #[serde(default)]
    pub sinks: Vec<TomlSinkDef>,
    #[serde(default)]
    pub sanitizers: Vec<TomlSanitizerDef>,
    #[serde(default)]
    pub propagator_overrides: Vec<TomlPropagatorOverride>,
}

#[derive(Debug, Deserialize)]
pub struct TomlSourceDef {
    pub id: String,
    pub language: String,
    pub framework: Option<String>,
    pub pattern: TomlPattern,
    pub label: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TomlPattern {
    #[serde(rename = "type")]
    pub pattern_type: String,  // "function_call", "member_access", "decorator", "type_annotation"
    pub name: String,
    pub receiver: Option<String>,
    pub parameter_index: Option<u32>,
}
```

---

## 13. Framework-Specific Taint Specifications

### 13.1 Framework Detection Integration

The taint engine integrates with the detector system's framework detection (06-DETECTOR-SYSTEM.md).
When frameworks are detected during the detection pass, the taint engine loads the
corresponding source/sink/sanitizer definitions.

```rust
impl TaintEngine {
    /// Load framework-specific taint specs based on detected frameworks.
    pub fn load_framework_specs(
        &mut self,
        detected_frameworks: &[FrameworkInfo],
    ) {
        for framework in detected_frameworks {
            match framework.name.as_str() {
                "express" => self.load_express_specs(),
                "fastapi" => self.load_fastapi_specs(),
                "django" => self.load_django_specs(),
                "flask" => self.load_flask_specs(),
                "spring-boot" => self.load_spring_specs(),
                "laravel" => self.load_laravel_specs(),
                "gin" => self.load_gin_specs(),
                "aspnet" => self.load_aspnet_specs(),
                "axum" => self.load_axum_specs(),
                "actix" => self.load_actix_specs(),
                _ => {
                    tracing::debug!(framework = %framework.name, "No taint specs for framework");
                }
            }
        }
    }
}
```

### 13.2 Express.js Taint Specification (Example)

```rust
fn load_express_specs(&mut self) {
    // Sources
    let express_sources = vec![
        SourceDefinition {
            id: "express-req-params".into(),
            language: Language::TypeScript,
            framework: Some("express".into()),
            pattern: SourcePattern::MemberAccess {
                object: "req".into(),
                property: "params".into(),
            },
            label: TaintLabel::UserInput,
            is_parameter: false,
            description: "Express request URL parameters".into(),
        },
        SourceDefinition {
            id: "express-req-query".into(),
            language: Language::TypeScript,
            framework: Some("express".into()),
            pattern: SourcePattern::MemberAccess {
                object: "req".into(),
                property: "query".into(),
            },
            label: TaintLabel::UserInput,
            is_parameter: false,
            description: "Express request query string".into(),
        },
        SourceDefinition {
            id: "express-req-body".into(),
            language: Language::TypeScript,
            framework: Some("express".into()),
            pattern: SourcePattern::MemberAccess {
                object: "req".into(),
                property: "body".into(),
            },
            label: TaintLabel::UserInput,
            is_parameter: false,
            description: "Express request body (parsed)".into(),
        },
        SourceDefinition {
            id: "express-req-headers".into(),
            language: Language::TypeScript,
            framework: Some("express".into()),
            pattern: SourcePattern::MemberAccess {
                object: "req".into(),
                property: "headers".into(),
            },
            label: TaintLabel::UserInput,
            is_parameter: false,
            description: "Express request headers".into(),
        },
        SourceDefinition {
            id: "express-req-cookies".into(),
            language: Language::TypeScript,
            framework: Some("express".into()),
            pattern: SourcePattern::MemberAccess {
                object: "req".into(),
                property: "cookies".into(),
            },
            label: TaintLabel::UserInput,
            is_parameter: false,
            description: "Express request cookies".into(),
        },
    ];

    self.source_registry.add_builtin(express_sources);

    // Sinks (Express-specific)
    let express_sinks = vec![
        SinkDefinition {
            id: "express-res-send-xss".into(),
            sink_type: SinkType::HtmlOutput,
            language: Language::TypeScript,
            framework: Some("express".into()),
            pattern: SinkPattern::FunctionCall {
                name: "send".into(),
                receiver: Some("res".into()),
            },
            tainted_parameter: 0,
            cwe_ids: vec![79],
            owasp_categories: vec!["A03".into()],
            required_sanitizers: vec![SanitizerType::HtmlEscape],
            severity: Severity::Warning, // res.send() is often safe (JSON)
            description: "Express response send — potential XSS if HTML".into(),
        },
        SinkDefinition {
            id: "express-res-redirect".into(),
            sink_type: SinkType::HttpRedirect,
            language: Language::TypeScript,
            framework: Some("express".into()),
            pattern: SinkPattern::FunctionCall {
                name: "redirect".into(),
                receiver: Some("res".into()),
            },
            tainted_parameter: 0,
            cwe_ids: vec![601],
            owasp_categories: vec!["A01".into()],
            required_sanitizers: vec![SanitizerType::UrlEncode],
            severity: Severity::Warning,
            description: "Express redirect with user-controlled URL — open redirect".into(),
        },
    ];

    self.sink_registry.add_builtin(express_sinks);
}
```


---

## 14. Field-Level Taint Tracking

Per R11 (.research/04-call-graph/RECOMMENDATIONS.md) and GAP-4.5:

### 14.1 Why Field-Level Matters

Table-level taint says "data from the users table is tainted." Field-level taint says
"users.password_hash is tainted (Critical) but users.display_name is not (Safe)."
This reduces false positives by 50-80% (per FlowDroid research).

```rust
/// Field-level taint tracking.
/// Tracks taint at the individual field level within objects/records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldTaint {
    /// Object/variable name.
    pub object: String,
    /// Field name → taint labels for that field.
    pub fields: FxHashMap<String, TaintLabelSet>,
}

impl TaintState {
    /// Taint a specific field of an object.
    pub fn taint_field(
        &mut self,
        object: &str,
        field: &str,
        label: TaintLabel,
        step: TaintStep,
    ) {
        let key = format!("{}.{}", object, field);
        self.taint(&key, label, step);
    }

    /// Check if a specific field is tainted.
    pub fn is_field_tainted(&self, object: &str, field: &str) -> bool {
        let key = format!("{}.{}", object, field);
        self.is_tainted(&key)
    }

    /// Propagate field-level taint through destructuring.
    /// `const { password, name } = user` → password gets user.password taint
    pub fn propagate_destructuring(
        &mut self,
        source_object: &str,
        bindings: &[(String, String)], // (field_name, binding_name)
        step: TaintStep,
    ) {
        for (field, binding) in bindings {
            let source_key = format!("{}.{}", source_object, field);
            if self.is_tainted(&source_key) {
                self.propagate(&source_key, binding, step.clone());
            }
        }
    }
}
```

### 14.2 Field Transformation Tracking

Per R11: track how fields are transformed along the taint path.

```rust
/// How a field was transformed along the taint path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FieldTransformation {
    DirectAccess,       // Field read directly (highest risk)
    Aggregation,        // Used in COUNT/SUM/AVG (lower risk — no individual data)
    Hashing,            // Passed through hash function (low risk if strong hash)
    Encryption,         // Encrypted (low risk)
    Masking,            // Partially masked (e.g., last 4 digits)
    Concatenation,      // Combined with other data
    Filtering,          // Used in WHERE clause (not returned)
    Projection,         // Selected in query (returned)
}
```

---

## 15. Taint Path Construction & Code Flow Generation

### 15.1 Path Construction

Every taint flow includes an ordered list of steps from source to sink.
This path is used for:
1. Developer understanding ("how does user input reach this SQL query?")
2. SARIF code flow generation (for CI/CD integration)
3. Confidence scoring (longer paths = lower confidence)
4. Deduplication (same source-sink pair via different paths)

```rust
impl TaintEngine {
    /// Build a human-readable taint path description.
    pub fn describe_path(flow: &TaintFlow) -> String {
        let mut description = String::new();
        description.push_str(&format!(
            "Taint flow: {} → {}\n",
            flow.source.expression,
            flow.sink.expression,
        ));
        description.push_str(&format!(
            "Risk: {:?} | CWE: {:?} | Sanitized: {}\n",
            flow.risk,
            flow.cwe_ids,
            flow.is_sanitized,
        ));
        description.push_str("Path:\n");
        for (i, step) in flow.path.iter().enumerate() {
            description.push_str(&format!(
                "  {}. [{}:{}] {} — {:?}\n",
                i + 1,
                step.location.file,
                step.location.line,
                step.expression,
                step.action,
            ));
        }
        if !flow.sanitizers.is_empty() {
            description.push_str("Sanitizers on path:\n");
            for sanitizer in &flow.sanitizers {
                description.push_str(&format!(
                    "  - {} ({:?}) at {}:{}\n",
                    sanitizer.expression,
                    sanitizer.sanitizer_type,
                    sanitizer.location.file,
                    sanitizer.location.line,
                ));
            }
        }
        description
    }
}
```

---

## 16. SARIF Integration (Code Flows for Security Findings)

Per .research/21-security/RECOMMENDATIONS.md SA1-SA6:

### 16.1 SARIF Code Flow Generation

SARIF 2.1 supports `codeFlows` for representing data flow paths. Each taint flow
maps to a SARIF `codeFlow` with `threadFlows` containing `threadFlowLocations`.

```rust
/// Generate SARIF code flow from a taint flow.
pub fn to_sarif_code_flow(flow: &TaintFlow) -> serde_json::Value {
    let locations: Vec<serde_json::Value> = flow.path.iter()
        .map(|step| {
            serde_json::json!({
                "location": {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": step.location.file,
                        },
                        "region": {
                            "startLine": step.location.line,
                            "startColumn": step.location.column,
                        }
                    },
                    "message": {
                        "text": step.expression,
                    }
                },
                "importance": match &step.action {
                    TaintAction::Source { .. } => "essential",
                    TaintAction::Sink { .. } => "essential",
                    TaintAction::Sanitize { .. } => "important",
                    _ => "unimportant",
                }
            })
        })
        .collect();

    serde_json::json!({
        "threadFlows": [{
            "locations": locations,
            "message": {
                "text": format!(
                    "Taint flow from {} to {} ({})",
                    flow.source.expression,
                    flow.sink.expression,
                    if flow.is_sanitized { "sanitized" } else { "UNSANITIZED" },
                )
            }
        }]
    })
}

/// Generate full SARIF result for a taint flow.
pub fn to_sarif_result(flow: &TaintFlow) -> serde_json::Value {
    serde_json::json!({
        "ruleId": format!("taint/{}", flow.sink.sink_type.as_str()),
        "level": match flow.risk {
            RiskLevel::Critical => "error",
            RiskLevel::High => "error",
            RiskLevel::Medium => "warning",
            RiskLevel::Low => "note",
            RiskLevel::Info => "none",
        },
        "message": {
            "text": format!(
                "Tainted data from {} reaches {} without proper sanitization",
                flow.source.expression,
                flow.sink.expression,
            )
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": flow.sink.location.file,
                },
                "region": {
                    "startLine": flow.sink.location.line,
                    "startColumn": flow.sink.location.column,
                }
            }
        }],
        "codeFlows": [to_sarif_code_flow(flow)],
        "properties": {
            "cwe": flow.cwe_ids,
            "owasp": flow.owasp_categories,
            "confidence": flow.confidence,
            "isInterprocedural": flow.is_interprocedural,
        }
    })
}
```

---

## 17. Integration with Call Graph (petgraph BFS Extension)

The taint engine extends the reachability engine's BFS with taint label tracking.
When performing interprocedural taint analysis, the engine traverses the call graph
and applies function summaries at each call site.

```rust
/// Taint-aware BFS on the call graph.
/// Extends the reachability engine's forward BFS with taint labels.
pub fn taint_aware_bfs(
    graph: &CallGraph,
    source_func: NodeIndex,
    taint_label: TaintLabel,
    summaries: &FxHashMap<FunctionId, TaintSummary>,
    max_depth: u32,
) -> Vec<TaintFlow> {
    let mut flows = Vec::new();
    let mut visited = FxHashSet::default();
    let mut queue = VecDeque::new();

    // Start BFS from source function
    queue.push_back((source_func, 0u32, vec![taint_label]));

    while let Some((node, depth, labels)) = queue.pop_front() {
        if depth > max_depth || !visited.insert(node) {
            continue;
        }

        let func_id = graph.node_id(node);

        // Check if this function has a summary with param-to-sink flows
        if let Some(summary) = summaries.get(&func_id) {
            for sink_flow in &summary.param_to_sink {
                if !sink_flow.is_sanitized {
                    // Found an unsanitized taint flow through the call graph
                    flows.push(TaintFlow {
                        id: format!("bfs-{}-{}", func_id, sink_flow.sink.definition_id),
                        source: TaintSource {
                            definition_id: "bfs-origin".into(),
                            label: taint_label,
                            location: CodeLocation::default(),
                            expression: "BFS origin".into(),
                            framework: None,
                            function_id: graph.node_id(source_func).to_string(),
                            parameter_index: None,
                        },
                        sink: sink_flow.sink.clone(),
                        path: Vec::new(), // Simplified for BFS
                        sanitizers: Vec::new(),
                        is_sanitized: false,
                        risk: RiskLevel::High,
                        confidence: 0.7, // Lower for BFS-discovered flows
                        cwe_ids: sink_flow.sink.cwe_ids.clone(),
                        owasp_categories: Vec::new(),
                        is_interprocedural: true,
                        source_file: String::new(),
                        sink_file: sink_flow.sink.location.file.clone(),
                    });
                }
            }
        }

        // Continue BFS to callees
        for edge in graph.graph.edges(node) {
            let callee = edge.target();
            let callee_id = graph.node_id(callee);

            // Check if callee summary propagates taint
            if let Some(summary) = summaries.get(&callee_id) {
                if summary.param_to_return.iter().any(|t| !t.taint_labels.is_empty()) {
                    queue.push_back((callee, depth + 1, labels.clone()));
                }
            }
        }
    }

    flows
}
```


---

## 18. Integration with Detector System (Visitor Pattern)

Per SAD1 (.research/21-security/RECOMMENDATIONS.md): security analysis must be woven
into the detection pipeline, not bolted on as a separate phase.

### 18.1 Taint Detector as Visitor

The taint engine registers as a visitor in the detection engine (06-DETECTOR-SYSTEM.md).
During the single-pass AST traversal, the taint detector collects source/sink/sanitizer
matches. After traversal, it runs the intraprocedural analysis.

```rust
/// Taint detector — registered as a visitor in the detection engine.
pub struct TaintDetector {
    engine: TaintEngine,
    /// Per-file taint analysis results (accumulated during traversal).
    pending_analyses: Vec<PendingTaintAnalysis>,
}

struct PendingTaintAnalysis {
    func: FunctionInfo,
    sources_found: Vec<TaintSource>,
    sinks_found: Vec<TaintSink>,
    sanitizers_found: Vec<TaintSanitizer>,
}

impl Detector for TaintDetector {
    fn id(&self) -> &str { "security/taint-analysis" }
    fn name(&self) -> &str { "Taint Analysis" }
    fn category(&self) -> Category { Category::Security }
    fn languages(&self) -> &[Language] { &[] } // All languages via GAST

    fn node_interests(&self) -> &[NodeType] {
        &[
            NodeType::Call,
            NodeType::MemberAccess,
            NodeType::Assignment,
            NodeType::Variable,
            NodeType::TemplateLiteral,
            NodeType::Return,
        ]
    }

    fn on_node(&mut self, node: &GASTNode, ctx: &mut DetectionContext) {
        // During traversal, collect source/sink/sanitizer matches
        // Actual taint analysis runs in finalize()
        match node {
            GASTNode::Call { callee, args, .. } => {
                let callee_name = expression_name(callee);
                // Check sources
                if let Some(source) = self.engine.source_registry
                    .match_call(&callee_name, ctx.language, &ctx.frameworks)
                {
                    // Record source match for later analysis
                }
                // Check sinks
                if let Some(sink) = self.engine.sink_registry
                    .match_call(&callee_name, ctx.language, &ctx.frameworks)
                {
                    // Record sink match for later analysis
                }
                // Check sanitizers
                if let Some(sanitizer) = self.engine.sanitizer_registry
                    .match_call(&callee_name, ctx.language)
                {
                    // Record sanitizer match for later analysis
                }
            }
            _ => {}
        }
    }

    fn finalize(&mut self, ctx: &DetectionContext) -> DetectionResult {
        // Run intraprocedural taint analysis on each function
        let mut violations = Vec::new();

        for analysis in &self.pending_analyses {
            match self.engine.analyze_function(
                &analysis.func,
                &GASTNode::Block { statements: Vec::new() }, // Simplified
                &TaintContext::from_detection_context(ctx),
            ) {
                Ok(flows) => {
                    for flow in flows {
                        if !flow.is_sanitized {
                            violations.push(Violation {
                                pattern_id: format!("taint/{}", flow.sink.sink_type.as_str()),
                                detector_id: self.id().to_string(),
                                file: PathBuf::from(&flow.sink_file),
                                line: flow.sink.location.line,
                                column: flow.sink.location.column,
                                message: format!(
                                    "Tainted data from {} reaches {} without sanitization",
                                    flow.source.expression,
                                    flow.sink.expression,
                                ),
                                severity: match flow.risk {
                                    RiskLevel::Critical | RiskLevel::High => Severity::Error,
                                    RiskLevel::Medium => Severity::Warning,
                                    _ => Severity::Info,
                                },
                                fix: self.generate_fix_suggestion(&flow),
                                cwe_ids: flow.cwe_ids.iter().map(|c| *c).collect(),
                                owasp_category: flow.owasp_categories.first().cloned(),
                            });
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Taint analysis failed for function");
                }
            }
        }

        DetectionResult {
            detector_id: self.id().to_string(),
            patterns: Vec::new(),
            conventions: Vec::new(),
            violations,
            fixes: Vec::new(),
            performance_ms: 0,
        }
    }
}
```

---

## 19. Integration with Boundary Detection (ORM Sink Auto-Discovery)

Per .research/21-security/RECOMMENDATIONS.md TA7:

The boundary detection system (07-BOUNDARY-DETECTION-V2-PREP.md) learns which ORM
frameworks are used in the codebase. The taint engine uses this information to
automatically register ORM-specific sinks.

```rust
impl TaintEngine {
    /// Auto-discover sinks from boundary detection results.
    /// Called after boundary detection completes.
    pub fn discover_orm_sinks(
        &mut self,
        detected_orms: &[ORMModel],
        data_access_points: &[DataAccessPoint],
    ) {
        for orm in detected_orms {
            // Register unsafe API patterns for this ORM
            let unsafe_patterns = UNSAFE_ORM_PATTERNS.iter()
                .filter(|(framework, _, _)| *framework == orm.framework)
                .collect::<Vec<_>>();

            for (_, pattern, description) in unsafe_patterns {
                self.sink_registry.add_dynamic(SinkDefinition {
                    id: format!("orm-{}-{}", orm.framework, pattern),
                    sink_type: SinkType::SqlQuery,
                    language: Language::from_framework(&orm.framework),
                    framework: Some(orm.framework.clone()),
                    pattern: SinkPattern::FunctionCall {
                        name: pattern.to_string(),
                        receiver: None,
                    },
                    tainted_parameter: 0,
                    cwe_ids: vec![89],
                    owasp_categories: vec!["A03".into()],
                    required_sanitizers: vec![SanitizerType::SqlParameterize],
                    severity: Severity::Error,
                    description: description.to_string(),
                });
            }
        }

        tracing::info!(
            orm_count = detected_orms.len(),
            sink_count = self.sink_registry.len(),
            "Auto-discovered ORM sinks from boundary detection"
        );
    }
}
```

---

## 20. Storage Schema (drift.db Taint Tables)

### 20.1 Taint Tables in drift.db

```sql
-- Taint flows (primary output)
CREATE TABLE IF NOT EXISTS taint_flows (
    id TEXT PRIMARY KEY,
    source_definition_id TEXT NOT NULL,
    source_label TEXT NOT NULL,
    source_file TEXT NOT NULL,
    source_line INTEGER NOT NULL,
    source_expression TEXT NOT NULL,
    source_function_id TEXT NOT NULL,
    sink_definition_id TEXT NOT NULL,
    sink_type TEXT NOT NULL,
    sink_file TEXT NOT NULL,
    sink_line INTEGER NOT NULL,
    sink_expression TEXT NOT NULL,
    sink_function_id TEXT NOT NULL,
    is_sanitized INTEGER NOT NULL DEFAULT 0,
    risk TEXT NOT NULL,  -- 'critical', 'high', 'medium', 'low', 'info'
    confidence REAL NOT NULL,
    is_interprocedural INTEGER NOT NULL DEFAULT 0,
    path_json TEXT NOT NULL,  -- JSON array of TaintStep
    sanitizers_json TEXT,     -- JSON array of TaintSanitizer (nullable)
    cwe_ids TEXT NOT NULL,    -- Comma-separated CWE IDs
    owasp_categories TEXT,    -- Comma-separated OWASP categories
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    scan_id TEXT              -- Links to scan that produced this flow
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_taint_flows_risk ON taint_flows(risk);
CREATE INDEX IF NOT EXISTS idx_taint_flows_sink_type ON taint_flows(sink_type);
CREATE INDEX IF NOT EXISTS idx_taint_flows_source_file ON taint_flows(source_file);
CREATE INDEX IF NOT EXISTS idx_taint_flows_sink_file ON taint_flows(sink_file);
CREATE INDEX IF NOT EXISTS idx_taint_flows_cwe ON taint_flows(cwe_ids);
CREATE INDEX IF NOT EXISTS idx_taint_flows_sanitized ON taint_flows(is_sanitized);

-- Function taint summaries (for interprocedural analysis)
CREATE TABLE IF NOT EXISTS taint_summaries (
    function_id TEXT PRIMARY KEY,
    param_to_return_json TEXT,   -- JSON array of ParamTaintTransfer
    param_to_sink_json TEXT,     -- JSON array of ParamToSinkFlow
    is_sanitizer INTEGER NOT NULL DEFAULT 0,
    sanitizer_type TEXT,
    confidence REAL NOT NULL,
    computed_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Taint source/sink registry (user-defined + auto-discovered)
CREATE TABLE IF NOT EXISTS taint_registry (
    id TEXT PRIMARY KEY,
    registry_type TEXT NOT NULL,  -- 'source', 'sink', 'sanitizer'
    definition_json TEXT NOT NULL,
    is_builtin INTEGER NOT NULL DEFAULT 0,
    is_auto_discovered INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

### 20.2 Materialized View: Taint Summary

```sql
-- Materialized view for quick taint summary queries
CREATE TABLE IF NOT EXISTS taint_summary_mv (
    id INTEGER PRIMARY KEY,
    total_flows INTEGER NOT NULL,
    unsanitized_flows INTEGER NOT NULL,
    critical_flows INTEGER NOT NULL,
    high_flows INTEGER NOT NULL,
    medium_flows INTEGER NOT NULL,
    low_flows INTEGER NOT NULL,
    top_cwe_ids TEXT,           -- JSON: [{cwe: 89, count: 5}, ...]
    top_sink_types TEXT,        -- JSON: [{type: "sql_query", count: 3}, ...]
    interprocedural_count INTEGER NOT NULL,
    last_computed TEXT NOT NULL DEFAULT (datetime('now'))
);
```


---

## 21. NAPI Interface

Per 03-NAPI-BRIDGE-V2-PREP.md §10.6:

```rust
/// Analyze taint flows for a function or the entire codebase.
#[napi]
pub fn analyze_taint(options: TaintAnalysisOptions) -> AsyncTask<TaintAnalysisTask> {
    AsyncTask::new(TaintAnalysisTask { options })
}

#[napi(object)]
pub struct TaintAnalysisOptions {
    /// Root directory to analyze.
    pub root: String,
    /// Specific function to analyze (None = all functions).
    pub function_id: Option<String>,
    /// Whether to include interprocedural analysis.
    pub interprocedural: Option<bool>,
    /// Minimum risk level to report.
    pub min_risk: Option<String>,
    /// Whether to include sanitized flows.
    pub include_sanitized: Option<bool>,
}

#[napi(object)]
pub struct TaintSummaryResult {
    pub total_flows: u32,
    pub unsanitized_flows: u32,
    pub critical_flows: u32,
    pub high_flows: u32,
    pub medium_flows: u32,
    pub low_flows: u32,
    pub top_cwes: Vec<CweCount>,
    pub top_sink_types: Vec<SinkTypeCount>,
    pub duration_ms: u32,
}

/// Query taint flows with filters and pagination.
#[napi]
pub fn query_taint_flows(
    filter: TaintFlowFilter,
    pagination: Option<PaginationOptions>,
) -> napi::Result<PaginatedResult> {
    let rt = crate::runtime::get()?;
    // Query drift.db taint_flows table with filters
    // Return paginated results
    todo!()
}

#[napi(object)]
pub struct TaintFlowFilter {
    /// Filter by risk level.
    pub risk: Option<String>,
    /// Filter by CWE ID.
    pub cwe_id: Option<u32>,
    /// Filter by sink type.
    pub sink_type: Option<String>,
    /// Filter by source file.
    pub source_file: Option<String>,
    /// Filter by sink file.
    pub sink_file: Option<String>,
    /// Whether to include sanitized flows.
    pub include_sanitized: Option<bool>,
    /// Whether to include only interprocedural flows.
    pub interprocedural_only: Option<bool>,
}

/// Get detailed taint flow by ID (includes full path).
#[napi]
pub fn query_taint_flow_detail(flow_id: String) -> napi::Result<serde_json::Value> {
    let rt = crate::runtime::get()?;
    // Query drift.db for full flow detail including path_json
    todo!()
}
```

---

## 22. MCP Tool Interface

Per .research/21-security/RECOMMENDATIONS.md MT2:

```typescript
// drift_taint_analysis — Run taint analysis
{
    name: "drift_taint_analysis",
    description: "Analyze taint flows in the codebase. Tracks untrusted data from sources to sinks.",
    parameters: {
        function_id: { type: "string", optional: true, description: "Specific function to analyze" },
        interprocedural: { type: "boolean", optional: true, default: true },
        min_risk: { type: "string", optional: true, enum: ["critical", "high", "medium", "low"] },
    },
    returns: "TaintSummaryResult with flow counts by risk level and top CWEs"
}

// drift_taint_paths — Query specific taint paths
{
    name: "drift_taint_paths",
    description: "Query taint flow paths with filters. Returns detailed source-to-sink paths.",
    parameters: {
        cwe_id: { type: "number", optional: true, description: "Filter by CWE ID (e.g., 89 for SQLi)" },
        sink_type: { type: "string", optional: true, description: "Filter by sink type" },
        risk: { type: "string", optional: true, description: "Minimum risk level" },
        file: { type: "string", optional: true, description: "Filter by file path" },
        limit: { type: "number", optional: true, default: 10 },
    },
    returns: "Array of TaintFlow with full source-to-sink paths"
}

// drift_taint_sources — List all taint sources in the codebase
{
    name: "drift_taint_sources",
    description: "List all detected taint sources (user input entry points).",
    parameters: {
        label: { type: "string", optional: true, description: "Filter by taint label" },
        framework: { type: "string", optional: true, description: "Filter by framework" },
    },
    returns: "Array of TaintSource with location and label"
}
```

---

## 23. CLI Interface

```
drift security taint [OPTIONS]

OPTIONS:
    --root <PATH>           Project root (default: current directory)
    --function <ID>         Analyze specific function
    --min-risk <LEVEL>      Minimum risk level (critical, high, medium, low)
    --cwe <ID>              Filter by CWE ID
    --sink-type <TYPE>      Filter by sink type
    --include-sanitized     Include sanitized flows in output
    --format <FORMAT>       Output format (table, json, sarif)
    --output <FILE>         Write output to file
    --interprocedural       Enable interprocedural analysis (default: true)
    --no-interprocedural    Disable interprocedural analysis

EXAMPLES:
    drift security taint                           # Full taint analysis
    drift security taint --min-risk critical        # Only critical flows
    drift security taint --cwe 89                   # Only SQL injection
    drift security taint --format sarif -o report   # SARIF output for CI
    drift security taint --function handleLogin     # Analyze specific function
```

---

## 24. Tracing & Observability

```rust
impl TaintEngine {
    pub fn analyze_all(
        &mut self,
        parse_results: &[ParseResult],
    ) -> Result<TaintAnalysisResult, TaintError> {
        let span = tracing::info_span!("taint_analysis",
            files = parse_results.len(),
            sources = self.source_registry.len(),
            sinks = self.sink_registry.len(),
            sanitizers = self.sanitizer_registry.len(),
        );
        let _guard = span.enter();

        let start = std::time::Instant::now();

        // Phase 1: Build summaries
        let summary_span = tracing::info_span!("build_summaries");
        let _summary_guard = summary_span.enter();
        self.build_summaries(parse_results)?;
        tracing::info!(summaries = self.summaries.len(), "Function summaries computed");
        drop(_summary_guard);

        // Phase 2: Analyze functions
        let analysis_span = tracing::info_span!("analyze_functions");
        let _analysis_guard = analysis_span.enter();
        let mut all_flows = Vec::new();
        let mut functions_analyzed = 0u64;

        for parse_result in parse_results {
            let ctx = TaintContext::from_parse_result(parse_result);
            for func in &parse_result.functions {
                let gast = self.normalize(parse_result, func)?;
                let flows = self.analyze_function(func, &gast, &ctx)?;
                all_flows.extend(flows);
                functions_analyzed += 1;
            }
        }
        tracing::info!(
            functions = functions_analyzed,
            raw_flows = all_flows.len(),
            "Intraprocedural analysis complete"
        );
        drop(_analysis_guard);

        // Phase 3: Deduplicate and rank
        let flows = self.deduplicate_and_rank(all_flows);
        tracing::info!(
            final_flows = flows.len(),
            unsanitized = flows.iter().filter(|f| !f.is_sanitized).count(),
            critical = flows.iter().filter(|f| f.risk == RiskLevel::Critical).count(),
            duration_ms = start.elapsed().as_millis(),
            "Taint analysis complete"
        );

        Ok(TaintAnalysisResult {
            flows,
            summaries_computed: self.summaries.len(),
            duration_ms: start.elapsed().as_millis() as u32,
        })
    }
}
```

---

## 25. Performance Targets & Benchmarks

| Metric | Target | Rationale |
|--------|--------|-----------|
| Intraprocedural analysis per function | <1ms | Must not slow down detection pipeline |
| Full intraprocedural analysis (10K functions) | <10s | Acceptable for batch scan |
| Summary computation (10K functions) | <30s | One-time cost, cached |
| Interprocedural analysis (10K functions) | <60s | Acceptable for full security scan |
| Memory overhead per function summary | <1KB | 10K functions = 10MB |
| Taint flow deduplication | <1s | Post-processing step |
| SARIF generation (1000 flows) | <500ms | CI/CD integration |
| Incremental re-analysis (10 changed files) | <5s | IDE integration target |

### Benchmark Strategy

```rust
#[cfg(test)]
mod benchmarks {
    use criterion::{criterion_group, criterion_main, Criterion};

    fn bench_intraprocedural(c: &mut Criterion) {
        // Benchmark single-function taint analysis
        // Target: <1ms per function
    }

    fn bench_summary_computation(c: &mut Criterion) {
        // Benchmark function summary computation
        // Target: <30s for 10K functions
    }

    fn bench_interprocedural(c: &mut Criterion) {
        // Benchmark full interprocedural analysis
        // Target: <60s for 10K functions
    }

    criterion_group!(benches,
        bench_intraprocedural,
        bench_summary_computation,
        bench_interprocedural,
    );
    criterion_main!(benches);
}
```

---

## 26. Build Order & Dependencies

### Phase 1: Foundation (Week 1-2)
1. Core data model (TaintFlow, TaintSource, TaintSink, TaintSanitizer, TaintStep)
2. TaintLabel enum and TaintLabelSet bitset
3. TaintState tracking (tainted variables, sanitized variables, paths)
4. PropagatorRules (assignment, string concat, template literal, etc.)
5. Error types (TaintError enum with thiserror)

### Phase 2: Registries (Week 3)
6. SourceRegistry with built-in sources for Express, FastAPI, Django, Spring
7. SinkRegistry with built-in sinks for all 15 sink types
8. SanitizerRegistry with built-in sanitizers per language
9. TOML loading for user-defined rules
10. Sanitizer-to-sink effectiveness matrix

### Phase 3: Intraprocedural Engine (Week 4-5)
11. IntraprocAnalyzer — GAST traversal with taint state tracking
12. Source matching (function calls, member access, decorators, type annotations)
13. Sink matching (function calls, property assignments, template literals)
14. Sanitizer matching (function calls, type casts, method calls)
15. Taint propagation (assignments, string concat, destructuring, field access)
16. Flow construction (source → path → sink)
17. Confidence scoring

### Phase 4: Interprocedural Engine (Week 6-7)
18. TaintSummary model (param-to-return, param-to-sink)
19. Bottom-up summary computation (topological sort of call graph)
20. Callee summary application at call sites
21. Cyclic SCC handling (Tarjan's + fixed-point iteration)
22. Taint-aware BFS on call graph

### Phase 5: Integration (Week 8)
23. TaintDetector as visitor in detection engine
24. ORM sink auto-discovery from boundary detection
25. Framework-specific taint spec loading
26. Storage persistence (drift.db taint tables)
27. NAPI bindings (analyze_taint, query_taint_flows, query_taint_flow_detail)

### Phase 6: Output & Reporting (Week 9)
28. SARIF code flow generation
29. MCP tool integration (drift_taint_analysis, drift_taint_paths)
30. CLI integration (drift security taint)
31. Taint summary materialized view
32. Tracing and observability

### Dependencies

```
Parser (Level 0) ──→ GAST Normalization ──→ Taint Intraprocedural
Scanner (Level 0) ──→ File list ──→ Taint Analysis
Call Graph (Level 1) ──→ petgraph ──→ Taint Interprocedural
Boundary Detection (Level 1) ──→ ORM models ──→ Taint Sink Auto-Discovery
Detector System (Level 1) ──→ Visitor pattern ──→ Taint Detector registration
Storage (Level 0) ──→ drift.db ──→ Taint persistence
Infrastructure (Level 0) ──→ thiserror, tracing ──→ Error handling, observability
```


---

## 27. CWE/OWASP Mapping

### 27.1 CWE Coverage via Taint Analysis

| CWE | Name | Sink Type | OWASP | Priority |
|-----|------|-----------|-------|----------|
| CWE-79 | Cross-Site Scripting (XSS) | HtmlOutput | A03 | P0 |
| CWE-89 | SQL Injection | SqlQuery | A03 | P0 |
| CWE-78 | OS Command Injection | OsCommand | A03 | P0 |
| CWE-22 | Path Traversal | FileRead/FileWrite | A01 | P0 |
| CWE-94 | Code Injection | CodeExecution | A03 | P1 |
| CWE-918 | Server-Side Request Forgery | HttpRequest | A10 | P1 |
| CWE-502 | Insecure Deserialization | Deserialization | A08 | P1 |
| CWE-90 | LDAP Injection | LdapQuery | A03 | P2 |
| CWE-601 | Open Redirect | HttpRedirect | A01 | P1 |
| CWE-117 | Log Injection | LogOutput | A09 | P2 |
| CWE-113 | HTTP Response Splitting | HeaderInjection | A03 | P2 |
| CWE-643 | XPath Injection | XpathQuery | A03 | P2 |
| CWE-1336 | Template Injection | TemplateRender | A03 | P1 |
| CWE-1333 | ReDoS | RegexConstruction | A03 | P2 |

### 27.2 OWASP Top 10 Coverage via Taint

| OWASP | Category | Taint Contribution |
|-------|----------|-------------------|
| A01 | Broken Access Control | Path traversal, open redirect, IDOR via taint |
| A03 | Injection | SQLi, XSS, command injection, LDAP, template — ALL via taint |
| A08 | Software & Data Integrity | Insecure deserialization via taint |
| A09 | Security Logging Failures | Log injection via taint |
| A10 | Server-Side Request Forgery | SSRF via taint |

Taint analysis directly enables detection for 5 of the OWASP Top 10 categories.
Combined with pattern-based detection (A02, A05, A07), Drift v2 covers 8/10.

---

## 28. Inconsistencies & Decisions

### 28.1 Resolved Inconsistencies

| Issue | Resolution | Confidence |
|-------|-----------|------------|
| AD11 says "Phase 1: intraprocedural" but 14-REACHABILITY says taint is integrated into BFS | Both are correct — intraprocedural runs during detection pass, BFS integration is for interprocedural queries | High |
| .research/04-call-graph R1 defines TaintFlow in TypeScript; SAD3 defines it in Rust | Rust is authoritative (v2 is Rust-first). TS types are generated from Rust via napi-rs | High |
| Semgrep uses YAML for taint rules; Drift uses TOML | TOML is consistent with drift.toml configuration. YAML would be a second config format | High |
| FlowDroid uses object-sensitivity; Drift does not | Object-sensitivity is too expensive for Drift's use case. Semgrep also skips it | High |
| SemTaint uses LLM for taint spec extraction | Future enhancement (Phase 3+). Not needed for launch — built-in specs cover 80%+ | Medium |

### 28.2 Open Decisions

| Decision | Options | Recommendation | Confidence |
|----------|---------|---------------|------------|
| Path sensitivity | Yes (track branches) / No (merge at join points) | No — too expensive, Semgrep validates this | High |
| Alias analysis | Yes (track pointer aliases) / No | No for Phase 1, Yes for Phase 2 (limited) | Medium |
| Taint through collections | Full (track individual elements) / Approximate (taint whole collection) | Approximate — taint whole collection if any element is tainted | High |
| Second-order taint (DB read → sink) | Track / Ignore | Track with DbRead label, lower confidence | Medium |
| Taint through callbacks | Track / Ignore | Track via function summaries (Phase 2) | Medium |

---

## 29. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| High false positive rate | Medium | High | Start intraprocedural only; sanitizer registry; feedback loop |
| Performance regression in detection pipeline | Medium | High | Taint detector is a visitor — single pass, no extra traversal |
| Incomplete sanitizer coverage | High | Medium | Declarative TOML rules; user-extensible; community contributions |
| Framework source/sink coverage gaps | Medium | Medium | Start with top 5 frameworks; add incrementally |
| Interprocedural analysis too slow | Low | Medium | Function summaries are O(functions), not O(paths) |
| Cyclic call graphs cause infinite loops | Low | High | Tarjan's SCC + max 3 iterations + timeout |
| SARIF output format incompatibility | Low | Low | Test against GitHub Code Scanning validator |
| User confusion about taint vs pattern detection | Medium | Low | Clear documentation; separate MCP tools; distinct violation messages |

---

## 30. Summary of All Decisions

| Decision | Choice | Confidence | Source |
|----------|--------|------------|--------|
| Taint as first-class engine | Yes — dedicated subsystem, not afterthought | Very High | AD11, SAD3 |
| Intraprocedural first | Phase 1 intraprocedural, Phase 2 interprocedural | Very High | Semgrep, FlowDroid |
| No path sensitivity | Merge at join points, accept some FPs | High | Semgrep validation |
| No object sensitivity | Too expensive for convention detection | High | Semgrep, SonarSource |
| Declarative rules (TOML) | User-extensible source/sink/sanitizer definitions | Very High | AD3, Semgrep YAML |
| Framework-specific specs | Per-framework source/sink definitions | Very High | TA7, TA8 |
| Function summaries for interprocedural | Pre-compute param→return taint transfers | Very High | FlowDroid |
| Taint labels (multi-type) | Bitset-based, 8 built-in + 56 custom | High | SonarSource |
| Field-level tracking | Track taint at field level within objects | High | FlowDroid, R11 |
| ORM sink auto-discovery | Use boundary detection results | High | TA7 |
| SARIF code flow output | Full SARIF 2.1 with codeFlows | Very High | SA1-SA6 |
| CWE/OWASP mapping | Every finding carries CWE IDs + OWASP categories | Very High | SAD4 |
| Visitor pattern integration | Taint detector registered as visitor in detection engine | Very High | SAD1 |
| Cyclic SCC handling | Tarjan's + fixed-point iteration (max 3) | High | Semgrep |
| Storage in drift.db | taint_flows, taint_summaries, taint_registry tables | Very High | Medallion architecture |
| Performance target | <1ms per function intraprocedural | High | Detection pipeline budget |
