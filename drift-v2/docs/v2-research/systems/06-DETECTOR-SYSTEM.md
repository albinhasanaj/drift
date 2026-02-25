# Detector System — V2 Implementation Prep

> Comprehensive build specification for Drift v2's detector subsystem.
> Synthesized from: 03-detectors/ (19 research docs), DRIFT-V2-FULL-SYSTEM-AUDIT.md (Cat 03),
> DRIFT-V2-STACK-HIERARCHY.md (Level 1), PLANNING-DRIFT.md (D1-D7, AD1-AD12),
> .research/03-detectors/ (RECAP, RESEARCH, RECOMMENDATIONS, AUDIT),
> 02-STORAGE-V2-PREP.md, 03-NAPI-BRIDGE-V2-PREP.md, 04-INFRASTRUCTURE.md,
> 05-CALL-GRAPH-V2-PREP.md, 01-PARSERS.md,
> and internet validation of Bayesian scoring, visitor patterns, OWASP/CWE alignment.
>
> Purpose: Everything needed to build the detector system from scratch.
> 100% v1 feature coverage guaranteed — every detector, variant, framework.
> Generated: 2026-02-07

---

## 1. Architectural Position

The detector system is Level 1 — Structural Skeleton. It is the central intelligence
layer of Drift: ~8 downstream systems depend on its output. Without detectors, Drift
can parse code but cannot discover conventions, score patterns, or generate violations.

Per PLANNING-DRIFT.md D1: Drift is standalone. Detectors write to drift.db only.
Per AD4: Single-pass visitor pattern — the single most impactful architectural change.
Per AD3: Declarative TOML pattern definitions — ship hardcoded, users add custom.
Per AD8: Bayesian confidence with momentum — replaces static v1 scoring.
Per AD9: Feedback loop — "Not useful" / "Useful" signals on every violation.

### What Lives Here

- 16 detection categories × 3 variants (base, learning, semantic)
- Visitor-pattern detection engine (single-pass AST traversal)
- Generic AST normalization layer (GAST — 10 languages → ~30 node types)
- Detector registry with category mapping and language filtering
- Bayesian confidence scoring with momentum
- Outlier detection (Z-Score, Grubbs', IQR, rule-based)
- Pattern matching engine (AST, regex, structural)
- Convention learning system (Bayesian ValueDistribution)
- Contract detection (REST, GraphQL, gRPC)
- Framework middleware (Spring, ASP.NET, Laravel, Django, Go, Rust, C++)
- Rules engine (violation generation, severity, quick fixes)
- Fix generation system (7 strategies, 3 safety levels)
- Feedback loop (violation action tracking, detector health)
- TOML-based declarative pattern definitions
- Incremental detection (3-layer content-hash skipping)

### What Does NOT Live Here

- File scanning (scanner, Level 0)
- AST parsing (parser, Level 0)
- Call graph construction (call-graph, Level 1 — parallel)
- Storage layer (drift.db, Level 0)
- NAPI bridge (drift-napi, Level 0)
- Quality gates (gates, Level 2 — consumes detector output)
- MCP tools (presentation layer — consumes detector output)
- CLI commands (presentation layer)
- IDE integration (presentation layer)

### Dependencies (What Detectors Need)

| Dependency | What It Provides | Interface |
|-----------|-----------------|-----------|
| drift-core::parser | Parsed ASTs (tree-sitter Trees) | `ParseResult { tree, source, language }` |
| drift-core::scanner | File list, content hashes, diffs | `ScanDiff { added, modified, removed }` |
| drift-core::storage | Read/write drift.db | `DatabaseManager` (writer + read pool) |
| drift-core::config | Detection thresholds, enabled categories | `DetectorConfig` |

### Consumers (What Uses Detector Output)

| Consumer | What It Reads | How |
|---------|--------------|-----|
| Quality Gates | Pattern counts, confidence scores, violations | drift.db Silver tables |
| MCP Tools | Pattern summaries, violation details, health | NAPI query functions |
| CLI | Violations, pattern reports, health scores | NAPI query functions |
| IDE/LSP | Per-file violations, quick fixes | NAPI `query_violations(file_filter)` |
| Audit System | Pattern trends, health degradation | drift.db health_trends |
| DNA Fingerprint | Category distribution, pattern signatures | drift.db patterns table |
| Boundary Detection | Security patterns, auth patterns | drift.db patterns by category |
| Consolidation (Cortex) | Pattern data for memory creation | cortex-drift-napi bridge |

---

## 2. V1 Feature Inventory — 100% Coverage Guarantee

Every v1 feature is accounted for below. Status: KEPT (unchanged), UPGRADED (improved),
REPLACED (different mechanism, same capability), or NEW (v2 addition).

### 2A. Base Detection Classes (v1: 7 TypeScript classes → v2: 5 Rust traits)

| v1 Class | Lines | v2 Replacement | Status |
|----------|-------|---------------|--------|
| `BaseDetector` | ~200 | `Detector` trait | REPLACED |
| `LearningDetector` | ~350 | `LearningDetector` trait (extends Detector) | REPLACED |
| `SemanticDetector` | ~300 | `SemanticDetector` trait (extends Detector) | REPLACED |
| `PatternMatcher` | ~250 | `PatternMatcher` trait | REPLACED |
| `OutlierDetector` | ~200 | `OutlierAnalyzer` trait | REPLACED |
| `ConventionLearner` | ~300 | Merged into `LearningDetector` | REPLACED |
| `RuleEvaluator` | ~150 | `RuleEvaluator` struct (not trait) | REPLACED |

### 2B. Detection Categories (v1: 16 categories, 350+ files → v2: 16 categories, TOML + Rust)

| # | Category | v1 Detectors | v2 Status | Notes |
|---|----------|-------------|-----------|-------|
| 1 | accessibility | 8 | KEPT | WCAG pattern detection |
| 2 | api | 12 | UPGRADED | + GraphQL/gRPC contracts |
| 3 | auth | 10 | UPGRADED | + OWASP A01/A07 alignment |
| 4 | components | 15 | KEPT | React/Vue/Angular patterns |
| 5 | config | 8 | KEPT | Configuration management |
| 6 | contracts | 6 | UPGRADED | REST + GraphQL + gRPC |
| 7 | data-access | 12 | UPGRADED | + taint tracking |
| 8 | documentation | 6 | KEPT | JSDoc/docstring patterns |
| 9 | errors | 14 | KEPT | Error handling patterns |
| 10 | logging | 8 | UPGRADED | + OWASP A09 alignment |
| 11 | performance | 10 | KEPT | Performance anti-patterns |
| 12 | security | 18 | UPGRADED | + OWASP Top 10 full coverage |
| 13 | structural | 20 | KEPT | Code structure patterns |
| 14 | styling | 6 | KEPT | CSS/styling conventions |
| 15 | testing | 12 | KEPT | Test pattern detection |
| 16 | types | 8 | KEPT | Type usage patterns |

Total v1 detectors: ~173 base + ~173 learning + ~173 semantic = ~519 detector variants
Total v2: Same 16 categories, same coverage, fewer files (TOML declarative + Rust engine)

### 2C. Framework Support (v1: 7 frameworks → v2: 7 frameworks + middleware architecture)

| Framework | v1 Files | v2 Status | v2 Mechanism |
|-----------|---------|-----------|-------------|
| Express.js | ~15 | KEPT | FrameworkMiddleware trait |
| Spring Boot | ~12 | KEPT | FrameworkMiddleware trait |
| ASP.NET | ~10 | KEPT | FrameworkMiddleware trait |
| Laravel | ~12 | KEPT | FrameworkMiddleware trait |
| Django | ~10 | KEPT | FrameworkMiddleware trait |
| Go (net/http, Gin, Echo) | ~8 | KEPT | FrameworkMiddleware trait |
| Rust (Axum, Actix) | ~6 | KEPT | FrameworkMiddleware trait |
| C++ (Crow, Drogon) | ~4 | KEPT | FrameworkMiddleware trait |

### 2D. Detection Algorithms (v1 → v2)

| Algorithm | v1 Implementation | v2 Implementation | Status |
|-----------|------------------|-------------------|--------|
| Frequency analysis | Linear 0-1 scale | Beta-Binomial Bayesian posterior | UPGRADED |
| Consistency scoring | Ratio-based | Bayesian with prior | UPGRADED |
| Age factor | Linear 0.1→1.0 over 30d, then flat | Temporal decay + momentum | UPGRADED |
| Spread factor | File count ratio | Bayesian spread with minimum evidence | UPGRADED |
| Outlier detection (Z-Score) | \|z\| > 2.0 | \|z\| > 2.5 with Grubbs' for small samples | UPGRADED |
| Outlier detection (IQR) | 1.5×IQR | 1.5×IQR with iterative masking removal | UPGRADED |
| Convention learning | Binary 60% threshold | Graduated Bayesian with contested detection | UPGRADED |
| Pattern matching | Regex + AST queries | Regex + AST + Structural + TOML declarative | UPGRADED |

### 2E. Detection Pipeline (v1 → v2)

| Pipeline Stage | v1 | v2 | Status |
|---------------|----|----|--------|
| File discovery | Scanner provides file list | Same | KEPT |
| AST parsing | tree-sitter per file | Same (shared parse cache) | KEPT |
| Detection traversal | N detectors × M files = N×M traversals | Single-pass visitor: 1 traversal × M files | UPGRADED |
| Pattern aggregation | Per-detector aggregation | Centralized pattern store | UPGRADED |
| Confidence scoring | 4-factor static formula | 5-factor Bayesian with momentum | UPGRADED |
| Outlier flagging | Z-Score only | Z-Score + Grubbs' + IQR + iterative | UPGRADED |
| Violation generation | Per-detector rules | Centralized rules engine | UPGRADED |
| Result storage | JSON shards + SQLite | SQLite only (drift.db) | UPGRADED |

### 2F. Data Types (v1 → v2)

| v1 Type | v2 Equivalent | Changes |
|---------|--------------|---------|
| `Pattern` | `Pattern` (Rust struct) | + alpha/beta, + momentum, + decay_rate |
| `PatternLocation` | `PatternLocation` | + deviation_score, + end_line/end_column |
| `PatternVariant` | `PatternVariant` | + expires_at |
| `PatternExample` | `PatternExample` | Unchanged |
| `Violation` | `Violation` | + cwe_ids, + owasp_category, + fix |
| `Convention` | `Convention` | + trend, + category (Universal/Emerging/Legacy/Contested) |
| `DetectorResult` | `DetectionResult` | + fix_coverage, + performance_ms |
| `ConfidenceScore` | `BayesianConfidence` | Alpha/beta posterior, not static weights |

### 2G. Registry & Configuration (v1 → v2)

| Feature | v1 | v2 | Status |
|---------|----|----|--------|
| Detector registration | Runtime class instantiation | Compile-time registry macro | UPGRADED |
| Category filtering | Config file | drift.toml `[detectors]` section | KEPT |
| Language filtering | Per-detector hardcoded | Registry metadata + GAST auto-filter | UPGRADED |
| Severity overrides | Pattern variants | Pattern variants + TOML overrides | KEPT |
| Custom detectors | Not supported | TOML pattern definitions | NEW |
| Detector enable/disable | Config per-detector | drift.toml + pattern_suppressions table | UPGRADED |

---

## 3. Core Trait Hierarchy

Five Rust traits replace seven TypeScript classes. The trait hierarchy is flat —
no deep inheritance chains. Composition over inheritance.

```rust
/// Core detection trait. Every detector implements this.
/// Replaces v1's BaseDetector class.
pub trait Detector: Send + Sync {
    /// Unique identifier (e.g., "security/sql-injection")
    fn id(&self) -> &str;

    /// Human-readable name
    fn name(&self) -> &str;

    /// Detection category
    fn category(&self) -> Category;

    /// Languages this detector supports. Empty = all languages (via GAST).
    fn languages(&self) -> &[Language];

    /// AST node types this detector is interested in (for visitor dispatch).
    fn node_interests(&self) -> &[NodeType];

    /// Called once per interested node during single-pass traversal.
    fn on_node(&mut self, node: &GASTNode, ctx: &mut DetectionContext);

    /// Called after all files have been traversed. Produce final results.
    fn finalize(&mut self, ctx: &DetectionContext) -> DetectionResult;

    /// Optional: generate a fix for a violation.
    fn generate_fix(&self, violation: &Violation, ctx: &DetectionContext) -> Option<Fix> {
        None // Default: no fix
    }

    /// Percentage of violations this detector can auto-fix (0.0-1.0).
    fn fix_coverage(&self) -> f64 { 0.0 }
}

/// Learning detector — discovers conventions from codebase patterns.
/// Replaces v1's LearningDetector + ConventionLearner classes.
pub trait LearningDetector: Detector {
    /// Learning phase: collect observations from AST nodes.
    fn observe(&mut self, node: &GASTNode, ctx: &DetectionContext);

    /// After all files observed, compute learned conventions.
    fn learn(&mut self, ctx: &DetectionContext) -> Vec<Convention>;

    /// Detection phase uses learned conventions to find violations.
    /// Default implementation: compare each node against learned conventions.
    fn detect_with_conventions(
        &self,
        node: &GASTNode,
        conventions: &[Convention],
        ctx: &DetectionContext,
    ) -> Vec<PatternMatch>;
}

/// Semantic detector — uses cross-file context for detection.
/// Replaces v1's SemanticDetector class.
pub trait SemanticDetector: Detector {
    /// Additional context this detector needs (call graph, imports, etc.)
    fn required_context(&self) -> &[ContextRequirement];

    /// Called with enriched context after cross-file analysis.
    fn on_node_with_context(
        &mut self,
        node: &GASTNode,
        ctx: &mut DetectionContext,
        semantic_ctx: &SemanticContext,
    );
}

/// Pattern matcher — matches AST/regex/structural patterns.
/// Replaces v1's PatternMatcher class.
pub trait PatternMatcher: Send + Sync {
    /// Match a pattern definition against a GAST node.
    fn matches(&self, pattern: &PatternDefinition, node: &GASTNode) -> Option<PatternMatch>;

    /// Match method (AST query, regex, structural).
    fn method(&self) -> DetectionMethod;
}

/// Outlier analyzer — statistical outlier detection.
/// Replaces v1's OutlierDetector class.
pub trait OutlierAnalyzer: Send + Sync {
    /// Analyze a set of values for outliers.
    fn detect_outliers(&self, values: &[f64], config: &OutlierConfig) -> Vec<OutlierResult>;

    /// Statistical method used.
    fn method(&self) -> OutlierMethod;
}
```

### Supporting Types

```rust
#[derive(Debug, Clone)]
pub struct DetectionContext {
    pub file_path: PathBuf,
    pub language: Language,
    pub source: Arc<str>,
    pub project_root: PathBuf,
    pub frameworks: Vec<FrameworkInfo>,
    pub config: DetectorConfig,
    pub db: Arc<DatabaseManager>,
}

#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub detector_id: String,
    pub patterns: Vec<PatternMatch>,
    pub conventions: Vec<Convention>,
    pub violations: Vec<Violation>,
    pub fixes: Vec<Fix>,
    pub performance_ms: u64,
}

#[derive(Debug, Clone)]
pub struct PatternMatch {
    pub pattern_id: String,
    pub file: PathBuf,
    pub line: u32,
    pub column: u32,
    pub end_line: Option<u32>,
    pub end_column: Option<u32>,
    pub snippet: Option<String>,
    pub confidence: f64,
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct Violation {
    pub pattern_id: String,
    pub detector_id: String,
    pub file: PathBuf,
    pub line: u32,
    pub column: u32,
    pub message: String,
    pub severity: Severity,
    pub fix: Option<Fix>,
    pub cwe_ids: Vec<u32>,
    pub owasp_category: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity { Error, Warning, Info, Hint }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Accessibility, Api, Auth, Components, Config, Contracts,
    DataAccess, Documentation, Errors, Logging, Performance,
    Security, Structural, Styling, Testing, Types,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    TypeScript, JavaScript, Python, Java, Go, Rust, CSharp,
    Php, Cpp, Ruby,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionMethod { AstQuery, Regex, Structural }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutlierMethod { ZScore, Grubbs, Iqr, RuleBased }
```


---

## 4. Detection Engine — Visitor Pattern (AD4)

The single most impactful architectural change from v1. Replaces O(detectors × files × nodes)
with O(files × nodes × handlers_per_node). Since most detectors care about 2-5 node types,
this is a 10-100x improvement.

### Engine Architecture

```rust
pub struct DetectionEngine {
    /// Node type → list of detector handlers interested in that node type.
    handlers: HashMap<NodeType, Vec<usize>>,
    /// All registered detectors (indexed by position).
    detectors: Vec<Box<dyn Detector>>,
    /// Learning detectors (subset, need two-pass).
    learning_detectors: Vec<usize>,
    /// Semantic detectors (subset, need enriched context).
    semantic_detectors: Vec<usize>,
    /// Framework middleware stack.
    middleware: Vec<Box<dyn FrameworkMiddleware>>,
    /// GAST normalizers per language.
    normalizers: HashMap<Language, Box<dyn GASTNormalizer>>,
    /// Registry metadata.
    registry: DetectorRegistry,
}

impl DetectionEngine {
    /// Build the engine from registry. Called once at initialization.
    pub fn new(config: &DetectorConfig, registry: DetectorRegistry) -> Self {
        let mut engine = Self {
            handlers: HashMap::new(),
            detectors: Vec::new(),
            learning_detectors: Vec::new(),
            semantic_detectors: Vec::new(),
            middleware: Vec::new(),
            normalizers: Self::build_normalizers(),
            registry,
        };

        // Register all enabled detectors
        for entry in engine.registry.enabled_detectors(config) {
            let idx = engine.detectors.len();
            let detector = entry.create();

            // Register handler for each node type the detector cares about
            for node_type in detector.node_interests() {
                engine.handlers
                    .entry(*node_type)
                    .or_default()
                    .push(idx);
            }

            // Track learning/semantic detectors for multi-pass
            if entry.is_learning { engine.learning_detectors.push(idx); }
            if entry.is_semantic { engine.semantic_detectors.push(idx); }

            engine.detectors.push(detector);
        }

        engine
    }

    /// Main detection entry point. Processes all files in a single pass.
    pub fn detect_all(
        &mut self,
        parse_results: &[ParseResult],
        db: &DatabaseManager,
        config: &DetectorConfig,
    ) -> Result<Vec<DetectionResult>, DetectionError> {
        let start = std::time::Instant::now();

        // Phase 0: Detect frameworks (enriches context for all detectors)
        let frameworks = self.detect_frameworks(parse_results);

        // Phase 1: Learning pass (learning detectors observe all files)
        if !self.learning_detectors.is_empty() {
            self.learning_pass(parse_results, &frameworks, config);
        }

        // Phase 2: Detection pass (single traversal, all detectors notified)
        self.detection_pass(parse_results, &frameworks, config);

        // Phase 3: Finalize all detectors and collect results
        let results = self.finalize_all(parse_results, db, config);

        // Phase 4: Write results to drift.db via batch writer
        self.persist_results(&results, db)?;

        Ok(results)
    }

    /// Single-pass traversal of one file's GAST.
    fn traverse_file(
        &mut self,
        gast: &GASTNode,
        ctx: &mut DetectionContext,
    ) {
        // Dispatch to all handlers interested in this node type
        let node_type = gast.node_type();
        if let Some(handler_indices) = self.handlers.get(&node_type) {
            for &idx in handler_indices {
                self.detectors[idx].on_node(gast, ctx);
            }
        }

        // Recurse into children
        for child in gast.children() {
            self.traverse_file(child, ctx);
        }
    }

    /// Learning pass: learning detectors observe all files before detection.
    fn learning_pass(
        &mut self,
        parse_results: &[ParseResult],
        frameworks: &[FrameworkInfo],
        config: &DetectorConfig,
    ) {
        for parse_result in parse_results {
            let normalizer = self.normalizers.get(&parse_result.language);
            if let Some(normalizer) = normalizer {
                let gast = normalizer.normalize(&parse_result.tree, &parse_result.source);
                let ctx = DetectionContext::new(parse_result, frameworks, config);

                for &idx in &self.learning_detectors {
                    if let Some(learner) = self.detectors[idx]
                        .as_any_mut()
                        .downcast_mut::<dyn LearningDetector>()
                    {
                        learner.observe(&gast, &ctx);
                    }
                }
            }
        }

        // After observing all files, compute conventions
        for &idx in &self.learning_detectors {
            if let Some(learner) = self.detectors[idx]
                .as_any_mut()
                .downcast_mut::<dyn LearningDetector>()
            {
                let conventions = learner.learn(&DetectionContext::empty());
                // Store conventions for detection phase
            }
        }
    }
}
```

### Two-Pass Architecture for Learning Detectors

Learning detectors require two passes:
1. **Observe pass**: Scan all files, collect frequency distributions
2. **Detect pass**: Using learned conventions, flag violations during single-pass traversal

Non-learning detectors only participate in the detect pass. The observe pass is
a separate traversal that runs before the main single-pass detection.

```
Files → [Observe Pass: learning detectors only] → Conventions
Files → [Detect Pass: ALL detectors, single traversal] → Patterns + Violations
```

This means the total traversal count is 2 (not N×M). For 100+ detectors on 10K files,
this is still a massive improvement over v1's 100+ traversals.

---

## 5. Generic AST Normalization Layer (GAST)

Inspired by Semgrep's `ast_generic`. Normalizes language-specific tree-sitter CSTs into
a common representation that detectors can work with language-agnostically.

### GAST Node Types (~30)

```rust
/// Generic AST node. Covers ~80% of detection needs across all 10 languages.
/// Language-specific constructs that don't normalize cleanly are represented
/// as `Raw` nodes with the original tree-sitter node attached.
#[derive(Debug, Clone)]
pub enum GASTNode {
    // === Declarations ===
    Function {
        name: String,
        params: Vec<Param>,
        return_type: Option<String>,
        body: Box<GASTNode>,       // Block
        is_async: bool,
        is_generator: bool,
        visibility: Visibility,
        decorators: Vec<Decorator>,
        doc_comment: Option<String>,
    },
    Class {
        name: String,
        extends: Option<String>,
        implements: Vec<String>,
        members: Vec<GASTNode>,    // Methods, fields, constructors
        decorators: Vec<Decorator>,
        is_abstract: bool,
        doc_comment: Option<String>,
    },
    Interface {
        name: String,
        extends: Vec<String>,
        members: Vec<GASTNode>,
    },
    Variable {
        name: String,
        type_annotation: Option<String>,
        value: Option<Box<GASTNode>>,
        kind: VarKind,             // Const, Let, Var, Final, Val
    },
    Enum {
        name: String,
        variants: Vec<EnumVariant>,
    },

    // === Statements ===
    Block { statements: Vec<GASTNode> },
    If { condition: Box<GASTNode>, then_branch: Box<GASTNode>, else_branch: Option<Box<GASTNode>> },
    TryCatch {
        try_block: Box<GASTNode>,
        catch_clauses: Vec<CatchClause>,
        finally_block: Option<Box<GASTNode>>,
    },
    Loop {
        kind: LoopKind,            // For, ForIn, ForOf, While, DoWhile
        body: Box<GASTNode>,
        iterable: Option<Box<GASTNode>>,
    },
    Return { value: Option<Box<GASTNode>> },
    Throw { value: Box<GASTNode> },
    Switch { discriminant: Box<GASTNode>, cases: Vec<SwitchCase> },

    // === Expressions ===
    Call {
        callee: Box<GASTNode>,
        args: Vec<GASTNode>,
        is_await: bool,
        is_optional: bool,         // ?. optional chaining
    },
    MemberAccess {
        object: Box<GASTNode>,
        property: String,
        is_optional: bool,
    },
    BinaryOp { left: Box<GASTNode>, op: String, right: Box<GASTNode> },
    UnaryOp { op: String, operand: Box<GASTNode> },
    Literal { value: LiteralValue },
    Identifier { name: String },
    TemplateLiteral { parts: Vec<TemplatePart> },
    Lambda {
        params: Vec<Param>,
        body: Box<GASTNode>,
        is_async: bool,
    },
    Assignment { target: Box<GASTNode>, value: Box<GASTNode> },

    // === Module System ===
    Import {
        source: String,
        specifiers: Vec<ImportSpec>,
        is_type_only: bool,
    },
    Export {
        declaration: Option<Box<GASTNode>>,
        specifiers: Vec<ExportSpec>,
        source: Option<String>,
    },

    // === Framework-Specific (Normalized) ===
    Route {
        method: HttpMethod,
        path: String,
        handler: Box<GASTNode>,
        middleware: Vec<GASTNode>,
    },
    Middleware {
        handler: Box<GASTNode>,
        applies_to: MiddlewareScope,
    },
    DatabaseQuery {
        kind: QueryKind,           // Select, Insert, Update, Delete, Raw
        table: Option<String>,
        is_parameterized: bool,
        raw_sql: Option<String>,
    },

    // === Escape Hatch ===
    Raw {
        language: Language,
        node_type: String,
        text: String,
        children: Vec<GASTNode>,
    },
}
```

### Language Normalizers (10)

Each language gets a normalizer that converts tree-sitter CST → GAST:

| Language | Normalizer | Complexity | Notes |
|----------|-----------|------------|-------|
| TypeScript | `TsNormalizer` | High | JSX, decorators, type annotations |
| JavaScript | `JsNormalizer` | Medium | Shares ~80% with TS normalizer |
| Python | `PyNormalizer` | Medium | Decorators, with-statement → TryCatch |
| Java | `JavaNormalizer` | Medium | Annotations → decorators |
| Go | `GoNormalizer` | Low | Simple syntax, defer → finally |
| Rust | `RustNormalizer` | Medium | Lifetimes stripped, Result → TryCatch |
| C# | `CsharpNormalizer` | Medium | Attributes → decorators, LINQ |
| PHP | `PhpNormalizer` | Medium | Attributes, namespaces |
| C++ | `CppNormalizer` | High | Templates, preprocessor |
| Ruby | `RubyNormalizer` | Medium | Blocks, method_missing |

### Normalization Strategy

```rust
pub trait GASTNormalizer: Send + Sync {
    /// Convert a tree-sitter Tree + source into a GAST tree.
    fn normalize(&self, tree: &tree_sitter::Tree, source: &str) -> GASTNode;

    /// Language this normalizer handles.
    fn language(&self) -> Language;

    /// Estimated GAST coverage (what % of source constructs normalize cleanly).
    fn coverage(&self) -> f64;
}
```

Detectors that need language-specific access can match on `GASTNode::Raw` and inspect
the original tree-sitter node. This is the escape hatch for ~20% of constructs that
don't normalize cleanly (e.g., Rust lifetimes, C++ templates, PHP attributes).


---

## 6. Detector Registry

Compile-time registry with runtime filtering. Every detector is registered via macro,
enabling the engine to discover all available detectors without manual wiring.

```rust
/// Registry entry for a single detector.
pub struct DetectorEntry {
    pub id: &'static str,
    pub name: &'static str,
    pub category: Category,
    pub languages: &'static [Language],
    pub is_learning: bool,
    pub is_semantic: bool,
    pub default_enabled: bool,
    pub default_severity: Severity,
    pub node_interests: &'static [NodeType],
    pub create: fn() -> Box<dyn Detector>,
}

/// Global detector registry. Populated at compile time via inventory crate.
pub struct DetectorRegistry {
    entries: Vec<DetectorEntry>,
    by_id: HashMap<String, usize>,
    by_category: HashMap<Category, Vec<usize>>,
    by_language: HashMap<Language, Vec<usize>>,
}

impl DetectorRegistry {
    /// Build registry from all registered entries.
    pub fn new() -> Self {
        let mut registry = Self {
            entries: Vec::new(),
            by_id: HashMap::new(),
            by_category: HashMap::new(),
            by_language: HashMap::new(),
        };

        // Collect all detectors registered via inventory::submit!
        for entry in inventory::iter::<DetectorEntry> {
            let idx = registry.entries.len();
            registry.by_id.insert(entry.id.to_string(), idx);
            registry.by_category
                .entry(entry.category)
                .or_default()
                .push(idx);
            for &lang in entry.languages {
                registry.by_language
                    .entry(lang)
                    .or_default()
                    .push(idx);
            }
            registry.entries.push(entry.clone());
        }

        registry
    }

    /// Get all detectors enabled by config.
    pub fn enabled_detectors(&self, config: &DetectorConfig) -> Vec<&DetectorEntry> {
        self.entries.iter()
            .filter(|e| {
                e.default_enabled
                    && config.is_category_enabled(e.category)
                    && !config.is_detector_disabled(e.id)
            })
            .collect()
    }

    /// Get detectors for a specific language.
    pub fn detectors_for_language(&self, lang: Language) -> Vec<&DetectorEntry> {
        let mut result: Vec<&DetectorEntry> = Vec::new();
        // Language-specific detectors
        if let Some(indices) = self.by_language.get(&lang) {
            for &idx in indices {
                result.push(&self.entries[idx]);
            }
        }
        // Language-agnostic detectors (empty languages = all)
        for entry in &self.entries {
            if entry.languages.is_empty() {
                result.push(entry);
            }
        }
        result
    }

    /// Health metrics for the registry.
    pub fn health(&self) -> RegistryHealth {
        RegistryHealth {
            total_detectors: self.entries.len(),
            by_category: self.by_category.iter()
                .map(|(cat, indices)| (*cat, indices.len()))
                .collect(),
            learning_count: self.entries.iter().filter(|e| e.is_learning).count(),
            semantic_count: self.entries.iter().filter(|e| e.is_semantic).count(),
            fix_coverage: self.entries.iter()
                .filter(|e| (e.create)().fix_coverage() > 0.0)
                .count() as f64 / self.entries.len() as f64,
        }
    }
}

/// Registration macro. Used by each detector module.
/// Example: register_detector!(SecuritySqlInjection);
macro_rules! register_detector {
    ($detector:ty) => {
        inventory::submit! {
            DetectorEntry {
                id: <$detector>::ID,
                name: <$detector>::NAME,
                category: <$detector>::CATEGORY,
                languages: <$detector>::LANGUAGES,
                is_learning: <$detector>::IS_LEARNING,
                is_semantic: <$detector>::IS_SEMANTIC,
                default_enabled: true,
                default_severity: <$detector>::DEFAULT_SEVERITY,
                node_interests: <$detector>::NODE_INTERESTS,
                create: || Box::new(<$detector>::new()),
            }
        }
    };
}
```

---

## 7. Learning System — Bayesian Convention Discovery

Replaces v1's binary 60% threshold with a graduated Bayesian model.
Uses Beta-Binomial conjugate prior for natural uncertainty handling.

### Bayesian ValueDistribution

```rust
/// Bayesian convention strength. Replaces v1's binary threshold.
pub struct BayesianConvention {
    pub value: String,
    pub alpha: f64,              // Beta distribution α (successes + prior)
    pub beta: f64,               // Beta distribution β (failures + prior)
    pub file_count: usize,       // Absolute count of files using this convention
    pub total_files: usize,      // Total files in scope
    pub trend: ConventionTrend,
    pub category: ConventionCategory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConventionTrend { Rising, Stable, Declining }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConventionCategory {
    Universal,       // >90% frequency, high confidence
    ProjectSpecific, // >60% frequency, project-level convention
    Emerging,        // <60% but rising trend
    Legacy,          // Was dominant, now declining
    Contested,       // Two conventions at similar frequency (within 15%)
}

impl BayesianConvention {
    /// Posterior mean: (α + successes) / (α + β + total)
    pub fn confidence(&self) -> f64 {
        self.alpha / (self.alpha + self.beta)
    }

    /// Frequency: file_count / total_files
    pub fn frequency(&self) -> f64 {
        if self.total_files == 0 { return 0.0; }
        self.file_count as f64 / self.total_files as f64
    }

    /// Update with new observation (Bayesian update)
    pub fn observe(&mut self, matches: bool) {
        if matches {
            self.alpha += 1.0;
            self.file_count += 1;
        } else {
            self.beta += 1.0;
        }
        self.total_files += 1;
    }

    /// Classify convention category based on frequency and trend
    pub fn classify(&self) -> ConventionCategory {
        let freq = self.frequency();
        match (freq, self.trend) {
            (f, _) if f >= 0.90 => ConventionCategory::Universal,
            (f, ConventionTrend::Declining) if f >= 0.30 => ConventionCategory::Legacy,
            (f, ConventionTrend::Rising) if f < 0.60 => ConventionCategory::Emerging,
            (f, _) if f >= 0.60 => ConventionCategory::ProjectSpecific,
            _ => ConventionCategory::Contested, // Determined by multi-convention analysis
        }
    }
}
```

### Contested Convention Detection

When two conventions are within 15% frequency of each other, flag as contested
instead of enforcing either one:

```rust
pub fn detect_contested(conventions: &[BayesianConvention]) -> Vec<ContestedPair> {
    let mut contested = Vec::new();
    let sorted: Vec<_> = conventions.iter()
        .sorted_by(|a, b| b.frequency().partial_cmp(&a.frequency()).unwrap())
        .collect();

    for window in sorted.windows(2) {
        let diff = window[0].frequency() - window[1].frequency();
        if diff < 0.15 && window[0].frequency() > 0.25 {
            contested.push(ContestedPair {
                convention_a: window[0].value.clone(),
                convention_b: window[1].value.clone(),
                frequency_a: window[0].frequency(),
                frequency_b: window[1].frequency(),
                recommendation: "Team should make a deliberate choice between these conventions",
            });
        }
    }
    contested
}
```

### Minimum Evidence Requirements

```rust
pub struct LearningConfig {
    pub min_files: usize,           // 5 (up from v1's 2)
    pub min_occurrences: usize,     // 10 (up from v1's 3)
    pub min_confidence: f64,        // 0.7 (Bayesian posterior)
    pub contested_threshold: f64,   // 0.15 — within 15% = contested
    pub prior_alpha: f64,           // 1.0 (uniform prior)
    pub prior_beta: f64,            // 1.0 (uniform prior)
}
```

---

## 8. Semantic Detection System

Preserved from v1. Semantic detectors use cross-file context (call graph, imports,
type information) to detect patterns that single-file analysis cannot find.

### Context Requirements

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextRequirement {
    CallGraph,          // Needs caller/callee information
    ImportGraph,        // Needs import/export relationships
    TypeInformation,    // Needs resolved type information
    DataFlow,           // Needs data flow analysis
    ControlFlow,        // Needs control flow graph
    ProjectStructure,   // Needs package/module boundaries
}

pub struct SemanticContext {
    pub call_graph: Option<Arc<CallGraph>>,
    pub import_graph: Option<Arc<ImportGraph>>,
    pub type_info: Option<Arc<TypeInfo>>,
    pub data_flow: Option<Arc<DataFlowGraph>>,
    pub project_structure: Option<Arc<ProjectStructure>>,
}
```

### Semantic Detector Examples

| Detector | Context Needed | What It Finds |
|----------|---------------|---------------|
| `security/sql-injection` | DataFlow | User input flowing to SQL queries |
| `api/unused-endpoints` | CallGraph | Routes with no callers |
| `errors/unhandled-promise` | CallGraph + ControlFlow | Async calls without catch |
| `contracts/mismatch` | ImportGraph + TypeInfo | BE↔FE type mismatches |
| `testing/untested-critical` | CallGraph + ProjectStructure | Entry points without tests |
| `security/ssrf` | DataFlow | User input in URL construction |
| `auth/missing-checks` | CallGraph + ProjectStructure | Routes without auth middleware |

### Execution Order

Semantic detectors run after the main detection pass because they need cross-file
context that's only available after all files have been processed:

```
Phase 1: Learning pass (learning detectors observe)
Phase 2: Detection pass (all detectors, single traversal)
Phase 3: Semantic pass (semantic detectors with enriched context)
Phase 4: Finalize + persist
```

---

## 9. Confidence Scoring — Bayesian Upgrade (AD8)

Replaces v1's static 4-factor formula with a 5-factor Bayesian model including momentum.

### V1 Formula (Being Replaced)

```
score = frequency × 0.40 + consistency × 0.30 + age × 0.15 + spread × 0.15
```

Problems: No decay, no momentum, age caps at 1.0 after 30 days, no sample size awareness.

### V2 Formula

```rust
pub struct BayesianConfidence {
    pub alpha: f64,              // Beta prior α (successes)
    pub beta: f64,               // Beta prior β (failures)
    pub frequency: f64,          // 0.0-1.0 — proportion of files
    pub consistency: f64,        // 0.0-1.0 — how consistent within files
    pub age_factor: f64,         // 0.0-1.0 — with temporal decay
    pub spread: f64,             // 0.0-1.0 — directory spread
    pub momentum: f64,           // -1.0 to 1.0 — trend direction
}

impl BayesianConfidence {
    /// Compute final confidence score.
    /// Weights: frequency 0.30, consistency 0.25, age 0.10, spread 0.15, momentum 0.20
    pub fn score(&self) -> f64 {
        let posterior = self.alpha / (self.alpha + self.beta);
        let weighted = self.frequency * 0.30
            + self.consistency * 0.25
            + self.age_factor * 0.10
            + self.spread * 0.15
            + self.momentum_normalized() * 0.20;

        // Blend posterior with weighted factors
        // Posterior dominates when sample size is large
        let sample_size = self.alpha + self.beta - 2.0; // Subtract prior
        let posterior_weight = (sample_size / (sample_size + 10.0)).min(0.5);
        posterior * posterior_weight + weighted * (1.0 - posterior_weight)
    }

    /// Normalize momentum from [-1, 1] to [0, 1] for scoring
    fn momentum_normalized(&self) -> f64 {
        (self.momentum + 1.0) / 2.0
    }

    /// Compute momentum from frequency history
    pub fn compute_momentum(current_freq: f64, previous_freq: f64) -> f64 {
        if previous_freq < 0.01 { return 0.0; } // Avoid division by near-zero
        let raw = (current_freq - previous_freq) / previous_freq;
        raw.clamp(-1.0, 1.0)
    }

    /// Apply temporal decay when frequency declines
    pub fn apply_decay(&mut self, current_freq: f64, previous_freq: f64) {
        if current_freq < previous_freq && previous_freq > 0.0 {
            let decay_factor = current_freq / previous_freq;
            self.age_factor *= decay_factor;
        }
    }

    /// V1 fallback: compute score using v1's 4-factor formula.
    /// Used during migration period for comparison.
    pub fn score_v1_compat(&self) -> f64 {
        self.frequency * 0.40
            + self.consistency * 0.30
            + self.age_factor * 0.15
            + self.spread * 0.15
    }
}
```

### Momentum Activation Rules

Momentum only activates after sufficient data to avoid noise:
- Minimum 3 scans with frequency history
- Minimum 50 files in project
- Momentum weight drops to 0.0 if either condition not met

### Convention Migration Scenario

```
Scan 1: Old pattern 80%, New pattern 20%
  Old: momentum=0.0 (no history), confidence=high
  New: momentum=0.0 (no history), confidence=low

Scan 2: Old 60%, New 40%
  Old: momentum=-0.25 (declining), confidence drops
  New: momentum=+1.0 (rising), confidence rises

Scan 3: Old 30%, New 70%
  Old: momentum=-0.50 (declining fast), confidence=low
  New: momentum=+0.75 (rising), confidence=high → becomes dominant

Without momentum, Drift would flag the new pattern as violations through all 3 scans.
With momentum, the crossover happens naturally at Scan 3.
```

---

## 10. Outlier Detection — Statistical Refinements

Replaces v1's single Z-Score (|z| > 2.0) with a multi-method approach.

### Method Selection by Sample Size

```rust
pub fn detect_outliers(values: &[f64], config: &OutlierConfig) -> Vec<OutlierResult> {
    let n = values.len();

    if n < config.min_sample_size {
        return vec![]; // Not enough data for statistical outlier detection
    }

    match n {
        0..=9 => vec![],                                    // Too few samples
        10..=29 => grubbs_test(values, config.alpha),       // Small sample: Grubbs'
        30.. => z_score_iterative(values, config.z_threshold), // Large sample: Z-Score
        _ => unreachable!(),
    }
}
```

### Z-Score with Iterative Masking (n ≥ 30)

```rust
pub fn z_score_iterative(values: &[f64], threshold: f64) -> Vec<OutlierResult> {
    let mut outliers = Vec::new();
    let mut remaining: Vec<(usize, f64)> = values.iter().copied().enumerate().collect();
    let max_iterations = 3; // Cap to prevent over-removal

    for iteration in 0..max_iterations {
        let vals: Vec<f64> = remaining.iter().map(|(_, v)| *v).collect();
        let mean = vals.iter().sum::<f64>() / vals.len() as f64;
        let std_dev = (vals.iter().map(|v| (v - mean).powi(2)).sum::<f64>()
            / (vals.len() - 1) as f64).sqrt();

        if std_dev < f64::EPSILON { break; } // All values identical

        let mut found_new = false;
        remaining.retain(|(idx, v)| {
            let z = (v - mean) / std_dev;
            if z.abs() > threshold {
                outliers.push(OutlierResult {
                    index: *idx,
                    value: *v,
                    z_score: z,
                    method: OutlierMethod::ZScore,
                    significance: classify_significance(z.abs()),
                    iteration,
                });
                found_new = true;
                false // Remove from remaining
            } else {
                true
            }
        });

        if !found_new { break; }
    }

    outliers
}

fn classify_significance(z_abs: f64) -> Significance {
    match z_abs {
        z if z > 3.5 => Significance::Critical,
        z if z > 3.0 => Significance::High,
        z if z > 2.5 => Significance::Moderate,
        _ => Significance::Low, // Should not reach here given threshold
    }
}
```

### Grubbs' Test (10 ≤ n < 30)

```rust
pub fn grubbs_test(values: &[f64], alpha: f64) -> Vec<OutlierResult> {
    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;
    let std_dev = (values.iter().map(|v| (v - mean).powi(2)).sum::<f64>()
        / (n - 1.0)).sqrt();

    if std_dev < f64::EPSILON { return vec![]; }

    // Critical value from t-distribution
    let t_crit = t_critical(alpha / (2.0 * n), (n - 2.0) as u32);
    let grubbs_crit = ((n - 1.0) / n.sqrt())
        * (t_crit.powi(2) / (n - 2.0 + t_crit.powi(2))).sqrt();

    values.iter().enumerate()
        .filter_map(|(i, v)| {
            let g = ((v - mean) / std_dev).abs();
            if g > grubbs_crit {
                Some(OutlierResult {
                    index: i,
                    value: *v,
                    z_score: g,
                    method: OutlierMethod::Grubbs,
                    significance: classify_significance(g),
                    iteration: 0,
                })
            } else {
                None
            }
        })
        .collect()
}
```

### IQR Method (Supplementary)

Used alongside Z-Score for robustness. IQR is resistant to extreme outliers
that inflate standard deviation:

```rust
pub fn iqr_outliers(values: &[f64], multiplier: f64) -> Vec<OutlierResult> {
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let q1 = percentile(&sorted, 25.0);
    let q3 = percentile(&sorted, 75.0);
    let iqr = q3 - q1;

    if iqr < f64::EPSILON { return vec![]; }

    let lower = q1 - multiplier * iqr;
    let upper = q3 + multiplier * iqr;

    values.iter().enumerate()
        .filter_map(|(i, v)| {
            if *v < lower || *v > upper {
                Some(OutlierResult {
                    index: i,
                    value: *v,
                    z_score: 0.0, // Not applicable for IQR
                    method: OutlierMethod::Iqr,
                    significance: if *v < lower - iqr || *v > upper + iqr {
                        Significance::High
                    } else {
                        Significance::Moderate
                    },
                    iteration: 0,
                })
            } else {
                None
            }
        })
        .collect()
}
```

### Outlier Configuration

```rust
pub struct OutlierConfig {
    pub min_sample_size: usize,  // 10 (up from v1's 3)
    pub z_threshold: f64,        // 2.5 (up from v1's 2.0)
    pub iqr_multiplier: f64,     // 1.5 (standard)
    pub alpha: f64,              // 0.05 (for Grubbs' test)
    pub max_iterations: usize,   // 3 (iterative masking cap)
}

impl Default for OutlierConfig {
    fn default() -> Self {
        Self {
            min_sample_size: 10,
            z_threshold: 2.5,
            iqr_multiplier: 1.5,
            alpha: 0.05,
            max_iterations: 3,
        }
    }
}
```


---

## 11. Pattern Matching Engine

Three matching methods: AST query, regex, and structural. All three can be defined
declaratively in TOML (see §21) or programmatically in Rust.

### AST Query Matching

Uses tree-sitter queries against the GAST for precise structural matching:

```rust
pub struct AstPatternMatcher;

impl PatternMatcher for AstPatternMatcher {
    fn matches(&self, pattern: &PatternDefinition, node: &GASTNode) -> Option<PatternMatch> {
        match &pattern.ast_query {
            Some(query) => {
                // Match GAST node against pattern's structural requirements
                if self.node_matches(node, &query.node_type, &query.constraints) {
                    Some(PatternMatch {
                        pattern_id: pattern.id.clone(),
                        confidence: query.base_confidence,
                        metadata: self.extract_metadata(node, &query.captures),
                        ..Default::default()
                    })
                } else {
                    None
                }
            }
            None => None,
        }
    }

    fn method(&self) -> DetectionMethod { DetectionMethod::AstQuery }
}
```

### Regex Matching

For text-level patterns (comments, string literals, naming conventions):

```rust
pub struct RegexPatternMatcher {
    compiled: HashMap<String, regex::Regex>,
}

impl PatternMatcher for RegexPatternMatcher {
    fn matches(&self, pattern: &PatternDefinition, node: &GASTNode) -> Option<PatternMatch> {
        match &pattern.regex {
            Some(regex_def) => {
                let text = node.text();
                let re = self.compiled.get(&pattern.id)?;
                if let Some(captures) = re.captures(text) {
                    Some(PatternMatch {
                        pattern_id: pattern.id.clone(),
                        confidence: regex_def.base_confidence,
                        metadata: self.captures_to_metadata(&captures, &regex_def.capture_names),
                        ..Default::default()
                    })
                } else {
                    None
                }
            }
            None => None,
        }
    }

    fn method(&self) -> DetectionMethod { DetectionMethod::Regex }
}
```

### Structural Matching

For higher-level patterns that span multiple nodes (e.g., "function with >5 parameters
that also has a try-catch"):

```rust
pub struct StructuralPatternMatcher;

impl PatternMatcher for StructuralPatternMatcher {
    fn matches(&self, pattern: &PatternDefinition, node: &GASTNode) -> Option<PatternMatch> {
        match &pattern.structural {
            Some(structural_def) => {
                let mut score = 0.0;
                let mut matched_constraints = 0;

                for constraint in &structural_def.constraints {
                    if self.check_constraint(node, constraint) {
                        matched_constraints += 1;
                        score += constraint.weight;
                    }
                }

                let total_weight: f64 = structural_def.constraints.iter()
                    .map(|c| c.weight).sum();

                if matched_constraints >= structural_def.min_matches
                    && score / total_weight >= structural_def.min_score
                {
                    Some(PatternMatch {
                        pattern_id: pattern.id.clone(),
                        confidence: score / total_weight,
                        ..Default::default()
                    })
                } else {
                    None
                }
            }
            None => None,
        }
    }

    fn method(&self) -> DetectionMethod { DetectionMethod::Structural }
}
```

---

## 12. Contract Detection System

REST preserved from v1. GraphQL and gRPC are new additions.

### Unified Contract Model

```rust
#[derive(Debug, Clone)]
pub struct ApiContract {
    pub paradigm: ApiParadigm,
    pub operations: Vec<ApiOperation>,
    pub types: Vec<ApiType>,
    pub source: ContractSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiParadigm { Rest, GraphQL, Grpc }

#[derive(Debug, Clone)]
pub struct ApiOperation {
    pub name: String,
    pub method: Option<HttpMethod>,    // REST only
    pub path: Option<String>,          // REST only
    pub input_type: Option<ApiType>,
    pub output_type: Option<ApiType>,
    pub is_deprecated: bool,
    pub source_file: PathBuf,
    pub source_line: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractSource {
    SchemaFile,     // OpenAPI, .graphql, .proto
    CodeExtraction, // Extracted from route handlers
    Both,           // Schema + code, cross-validated
}
```

### REST Contract Detection (v1 Preserved + Refined)

- Backend endpoint extraction from 7 frameworks (Express, Spring, ASP.NET, Laravel, Django, Go, Rust)
- Frontend API call extraction (fetch, axios, custom clients)
- OpenAPI/Swagger spec parsing as first-class contract source
- Path similarity matching with version-awareness (/v1/users vs /v2/users)
- Breaking change classification: breaking | non-breaking | deprecation

### GraphQL Contract Detection (NEW)

```rust
pub struct GraphQLContractDetector;

impl GraphQLContractDetector {
    /// Detect GraphQL contracts from schema files and code-first definitions.
    pub fn detect(&self, parse_results: &[ParseResult]) -> Vec<ApiContract> {
        let mut contracts = Vec::new();

        // 1. Schema files (.graphql, .gql)
        for pr in parse_results.iter().filter(|p| p.is_graphql_schema()) {
            contracts.push(self.parse_schema_file(pr));
        }

        // 2. Code-first definitions (type-graphql, nexus, pothos)
        for pr in parse_results.iter().filter(|p| p.has_graphql_decorators()) {
            contracts.push(self.extract_code_first(pr));
        }

        // 3. Frontend queries (gql tagged templates, .graphql query files)
        // Cross-reference with schema to find mismatches

        contracts
    }
}
```

### gRPC/Protobuf Contract Detection (NEW)

```rust
pub struct GrpcContractDetector;

impl GrpcContractDetector {
    /// Detect gRPC contracts from .proto files.
    pub fn detect(&self, parse_results: &[ParseResult]) -> Vec<ApiContract> {
        let mut contracts = Vec::new();

        for pr in parse_results.iter().filter(|p| p.is_proto_file()) {
            let proto = self.parse_proto(pr);
            contracts.push(ApiContract {
                paradigm: ApiParadigm::Grpc,
                operations: proto.services.into_iter()
                    .flat_map(|s| s.methods.into_iter().map(|m| ApiOperation {
                        name: format!("{}.{}", s.name, m.name),
                        method: None,
                        path: None,
                        input_type: Some(m.input_type),
                        output_type: Some(m.output_type),
                        is_deprecated: m.is_deprecated,
                        source_file: pr.file_path.clone(),
                        source_line: m.line,
                    }))
                    .collect(),
                types: proto.messages,
                source: ContractSource::SchemaFile,
            });
        }

        contracts
    }
}
```

### Contract Mismatch Detection

Cross-paradigm analysis: compare backend contracts with frontend usage:

```rust
pub struct ContractMismatchDetector;

impl ContractMismatchDetector {
    pub fn detect_mismatches(
        &self,
        backend_contracts: &[ApiContract],
        frontend_calls: &[FrontendApiCall],
    ) -> Vec<ContractMismatch> {
        let mut mismatches = Vec::new();

        for call in frontend_calls {
            match self.find_matching_contract(call, backend_contracts) {
                Some(contract) => {
                    // Check type compatibility
                    if let Some(mismatch) = self.check_types(call, contract) {
                        mismatches.push(mismatch);
                    }
                }
                None => {
                    mismatches.push(ContractMismatch {
                        kind: MismatchKind::OrphanedCall,
                        frontend_file: call.file.clone(),
                        frontend_line: call.line,
                        message: format!("API call to {} has no matching backend endpoint", call.path),
                        severity: Severity::Warning,
                    });
                }
            }
        }

        mismatches
    }
}
```

---

## 13. Framework Middleware Architecture

All 7 v1 frameworks preserved. Middleware pattern enables community-contributed framework support.

### FrameworkMiddleware Trait

```rust
pub trait FrameworkMiddleware: Send + Sync {
    /// Unique framework identifier (e.g., "spring-boot", "express")
    fn framework_id(&self) -> &str;

    /// Detect if this framework is used in the project.
    fn detect_framework(&self, project: &ProjectContext) -> Option<FrameworkInfo>;

    /// Enrich detection context with framework-specific knowledge.
    /// Called before detection pass for each file.
    fn enrich_context(&self, ctx: &mut DetectionContext, framework: &FrameworkInfo);

    /// Additional pattern definitions contributed by this framework.
    fn additional_patterns(&self) -> Vec<PatternDefinition>;

    /// Map framework-specific constructs to generic GAST nodes.
    /// E.g., Spring's @GetMapping → Route { method: GET, ... }
    fn normalize_nodes(&self, node: &GASTNode) -> Option<GASTNode>;
}
```

### Framework Detection

```rust
pub struct FrameworkDetector {
    middleware: Vec<Box<dyn FrameworkMiddleware>>,
}

impl FrameworkDetector {
    pub fn detect_all(&self, project: &ProjectContext) -> Vec<FrameworkInfo> {
        self.middleware.iter()
            .filter_map(|mw| mw.detect_framework(project))
            .collect()
    }
}

pub struct ProjectContext {
    pub root: PathBuf,
    pub package_manifests: Vec<PackageManifest>,  // package.json, pom.xml, etc.
    pub config_files: Vec<PathBuf>,               // tsconfig, spring config, etc.
    pub file_list: Vec<PathBuf>,
}

pub struct FrameworkInfo {
    pub name: String,
    pub version: Option<String>,
    pub language: Language,
    pub evidence: Vec<FrameworkEvidence>,
    pub confidence: f64,
}

pub enum FrameworkEvidence {
    PackageDependency { name: String, version: String },
    ImportStatement { module: String, file: PathBuf },
    ConfigFile { path: PathBuf },
    DirectoryStructure { pattern: String },
}
```

### Implemented Frameworks (7 — All v1 Preserved)

| Framework | Detection Evidence | Normalization |
|-----------|-------------------|---------------|
| Express.js | `express` in package.json, `require('express')` | `app.get()` → Route |
| Spring Boot | `spring-boot-starter` in pom.xml | `@GetMapping` → Route |
| ASP.NET | `.csproj` with `Microsoft.AspNetCore` | `[HttpGet]` → Route |
| Laravel | `laravel/framework` in composer.json | `Route::get()` → Route |
| Django | `django` in requirements.txt | `path()` → Route |
| Go (Gin/Echo) | `gin-gonic/gin` or `labstack/echo` in go.mod | `r.GET()` → Route |
| Rust (Axum/Actix) | `axum` or `actix-web` in Cargo.toml | `get()` handler → Route |
| C++ (Crow/Drogon) | `#include <crow.h>` or `#include <drogon>` | `CROW_ROUTE` → Route |

---

## 14. Rules Engine & Violation Generation

Centralized rules engine replaces v1's per-detector violation logic.

### Rule Evaluator

```rust
pub struct RuleEvaluator {
    rules: Vec<Rule>,
    severity_overrides: HashMap<String, Severity>,
}

pub struct Rule {
    pub id: String,
    pub detector_id: String,
    pub condition: RuleCondition,
    pub severity: Severity,
    pub message_template: String,
    pub fix_strategy: Option<FixStrategy>,
}

pub enum RuleCondition {
    /// Pattern confidence below threshold → violation
    BelowConfidence { threshold: f64 },
    /// Pattern is an outlier → violation
    IsOutlier { min_significance: Significance },
    /// Convention violated → violation
    ConventionViolation { convention_id: String },
    /// Security pattern detected → violation
    SecurityFinding { cwe_ids: Vec<u32> },
    /// Custom condition (evaluated by detector)
    Custom { evaluator: Box<dyn Fn(&PatternMatch) -> bool + Send + Sync> },
}

impl RuleEvaluator {
    pub fn evaluate(
        &self,
        patterns: &[PatternMatch],
        conventions: &[Convention],
        outliers: &[OutlierResult],
    ) -> Vec<Violation> {
        let mut violations = Vec::new();

        for rule in &self.rules {
            match &rule.condition {
                RuleCondition::IsOutlier { min_significance } => {
                    for outlier in outliers {
                        if &outlier.significance >= min_significance {
                            violations.push(self.create_violation(rule, outlier));
                        }
                    }
                }
                RuleCondition::ConventionViolation { convention_id } => {
                    // Find patterns that violate the convention
                    if let Some(convention) = conventions.iter()
                        .find(|c| &c.id == convention_id)
                    {
                        for pattern in patterns {
                            if !convention.matches(pattern) {
                                violations.push(self.create_violation(rule, pattern));
                            }
                        }
                    }
                }
                RuleCondition::SecurityFinding { cwe_ids } => {
                    for pattern in patterns {
                        if pattern.has_security_finding(cwe_ids) {
                            violations.push(self.create_violation(rule, pattern));
                        }
                    }
                }
                _ => {}
            }
        }

        // Apply severity overrides from pattern_variants
        for violation in &mut violations {
            if let Some(override_severity) = self.severity_overrides.get(&violation.pattern_id) {
                violation.severity = *override_severity;
            }
        }

        violations
    }
}
```

### Violation Severity Levels

| Level | Meaning | Gate Impact | IDE Display |
|-------|---------|-------------|-------------|
| Error | Must fix — blocks quality gate | Fails gate | Red squiggly |
| Warning | Should fix — counted in gate threshold | Counted | Yellow squiggly |
| Info | Informational — no gate impact | Ignored | Blue info |
| Hint | Suggestion — optional improvement | Ignored | Faded text |


---

## 15. Fix Generation System (NEW)

First-class fix output. Every detector is encouraged to provide fixes.
Detectors without fixes are flagged in the health dashboard.

### Fix Types (7 Strategies)

```rust
pub enum FixKind {
    /// Exact text replacement — high confidence, safe to auto-apply
    TextEdit { range: Range, new_text: String },

    /// Multi-location edit — all edits must be applied atomically
    MultiEdit { edits: Vec<TextEdit>, description: String },

    /// Symbol rename across files
    Rename { old_name: String, new_name: String, scope: RenameScope },

    /// Import addition or removal
    ImportChange { action: ImportAction, module: String, specifiers: Vec<String> },

    /// Structural refactoring (move code, extract function)
    Structural { description: String, edits: Vec<TextEdit> },

    /// Suggestion — human must decide, AI can help
    Suggestion { description: String, options: Vec<FixOption> },

    /// No-op — detector acknowledges it can't fix this
    NoFix { reason: String },
}

pub struct Fix {
    pub kind: FixKind,
    pub confidence: f64,          // How confident the fix is correct
    pub safety_level: SafetyLevel,
    pub description: String,
    pub detector_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SafetyLevel {
    /// Auto-apply without review. Pure formatting, naming, import ordering.
    AutoApply = 1,
    /// Apply with diff preview. Code structure changes, pattern migration.
    ReviewRequired = 2,
    /// Suggestion only. Architectural changes, security fixes that may change behavior.
    SuggestionOnly = 3,
}
```

### Fix Application (CLI)

```
drift fix --auto                          # Apply all SafetyLevel::AutoApply fixes
drift fix --review                        # Apply AutoApply + ReviewRequired with diff preview
drift fix --category=security             # Fix only security violations
drift fix --detector=structural/file-naming  # Fix specific detector's violations
drift fix --dry-run                       # Show what would be fixed without applying
```

### Fix Coverage Tracking

Every detector reports its fix coverage. The health dashboard tracks this:

```rust
pub struct DetectorFixCoverage {
    pub detector_id: String,
    pub total_violations: usize,
    pub fixable_violations: usize,
    pub auto_fixable: usize,       // SafetyLevel::AutoApply
    pub review_fixable: usize,     // SafetyLevel::ReviewRequired
    pub suggestion_only: usize,    // SafetyLevel::SuggestionOnly
    pub no_fix: usize,
    pub coverage: f64,             // fixable / total
}
```

---

## 16. Feedback Loop & Detector Health (AD9)

Implements Google Tricorder's feedback model. Tracks whether developers act on violations.

### Violation Action Tracking

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationAction {
    Fixed,          // Developer fixed the violation
    Dismissed,      // Developer explicitly dismissed ("Not useful")
    Ignored,        // Developer saw but took no action
    AutoFixed,      // Quick fix was applied
    NotSeen,        // Violation was never displayed to developer
}

pub struct ViolationFeedback {
    pub violation_id: String,
    pub pattern_id: String,
    pub detector_id: String,
    pub action: ViolationAction,
    pub timestamp: DateTime<Utc>,
    pub source: FeedbackSource,    // IDE, CLI, CI
}

pub enum FeedbackSource { Ide, Cli, Ci }
```

### Effective False-Positive Rate

```rust
pub struct DetectorHealth {
    pub detector_id: String,
    pub total_violations: usize,
    pub fixed: usize,
    pub dismissed: usize,
    pub ignored: usize,
    pub auto_fixed: usize,
    pub not_seen: usize,
    pub effective_fp_rate: f64,
    pub status: DetectorStatus,
}

impl DetectorHealth {
    /// Effective FP rate = (dismissed + ignored) / (fixed + dismissed + ignored + auto_fixed)
    pub fn compute_fp_rate(&self) -> f64 {
        let acted_on = self.fixed + self.dismissed + self.ignored + self.auto_fixed;
        if acted_on == 0 { return 0.0; }
        (self.dismissed + self.ignored) as f64 / acted_on as f64
    }

    /// Detector status based on FP rate thresholds
    pub fn compute_status(&self) -> DetectorStatus {
        let fp_rate = self.compute_fp_rate();
        match fp_rate {
            r if r > 0.20 => DetectorStatus::Disabled,    // >20% FP for 30+ days → auto-disable
            r if r > 0.10 => DetectorStatus::Warning,     // >10% FP → alert
            _ => DetectorStatus::Healthy,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectorStatus { Healthy, Warning, Disabled }
```

### Health Dashboard Data

Exposed via NAPI `get_detector_health()` and MCP tools:

```rust
pub struct DetectorHealthDashboard {
    pub total_detectors: usize,
    pub healthy: usize,
    pub warning: usize,
    pub disabled: usize,
    pub most_useful: Vec<DetectorHealth>,    // Top 10 by fix rate
    pub least_useful: Vec<DetectorHealth>,   // Bottom 10 by FP rate
    pub overall_fp_rate: f64,
}
```

---

## 17. Detection Categories — Complete Inventory

All 16 categories with every detector listed. Status: KEPT, UPGRADED, or NEW.

### Category 1: Accessibility (8 detectors)

| Detector | Type | Status | Description |
|----------|------|--------|-------------|
| `accessibility/aria-attributes` | Base | KEPT | ARIA attribute usage patterns |
| `accessibility/color-contrast` | Base | KEPT | Color contrast ratio patterns |
| `accessibility/focus-management` | Base | KEPT | Focus handling patterns |
| `accessibility/form-labels` | Learning | KEPT | Form label conventions |
| `accessibility/image-alt` | Base | KEPT | Image alt text patterns |
| `accessibility/keyboard-nav` | Base | KEPT | Keyboard navigation patterns |
| `accessibility/semantic-html` | Learning | KEPT | Semantic HTML element usage |
| `accessibility/screen-reader` | Base | KEPT | Screen reader compatibility |

### Category 2: API (12 detectors)

| Detector | Type | Status | Description |
|----------|------|--------|-------------|
| `api/endpoint-naming` | Learning | KEPT | REST endpoint naming conventions |
| `api/error-responses` | Learning | KEPT | API error response patterns |
| `api/pagination` | Base | KEPT | Pagination pattern detection |
| `api/rate-limiting` | Base | UPGRADED | + OWASP A04 alignment |
| `api/request-validation` | Base | UPGRADED | + input sanitization checks |
| `api/response-format` | Learning | KEPT | Response structure conventions |
| `api/versioning` | Base | KEPT | API versioning patterns |
| `api/authentication` | Semantic | UPGRADED | + OWASP A07 alignment |
| `api/graphql-schema` | Base | NEW | GraphQL schema patterns |
| `api/graphql-n-plus-one` | Semantic | NEW | N+1 query detection in resolvers |
| `api/grpc-evolution` | Base | NEW | Protobuf breaking change detection |
| `api/contract-mismatch` | Semantic | UPGRADED | + GraphQL/gRPC support |

### Category 3: Auth (10 detectors)

| Detector | Type | Status | Description |
|----------|------|--------|-------------|
| `auth/permission-checks` | Semantic | UPGRADED | + OWASP A01 (Broken Access Control) |
| `auth/rbac-patterns` | Learning | KEPT | Role-based access patterns |
| `auth/session-management` | Base | KEPT | Session handling patterns |
| `auth/token-handling` | Base | KEPT | JWT/token patterns |
| `auth/password-policy` | Base | UPGRADED | + OWASP A07 alignment |
| `auth/mfa-checks` | Base | NEW | Multi-factor auth detection |
| `auth/credential-storage` | Base | UPGRADED | + CWE-256, CWE-257 |
| `auth/oauth-patterns` | Learning | KEPT | OAuth flow patterns |
| `auth/cors-config` | Base | UPGRADED | + OWASP A01 CORS misconfiguration |
| `auth/csrf-protection` | Base | KEPT | CSRF token patterns |

### Category 4: Components (15 detectors)

| Detector | Type | Status | Description |
|----------|------|--------|-------------|
| `components/naming` | Learning | KEPT | Component naming conventions |
| `components/props-pattern` | Learning | KEPT | Props/interface patterns |
| `components/state-management` | Learning | KEPT | State management patterns |
| `components/lifecycle` | Base | KEPT | Lifecycle hook patterns |
| `components/composition` | Learning | KEPT | Composition vs inheritance |
| `components/event-handling` | Learning | KEPT | Event handler patterns |
| `components/rendering` | Base | KEPT | Render pattern detection |
| `components/styling-approach` | Learning | KEPT | CSS-in-JS vs modules vs utility |
| `components/testing-pattern` | Learning | KEPT | Component test patterns |
| `components/accessibility` | Base | KEPT | Component a11y patterns |
| `components/error-boundary` | Base | KEPT | Error boundary patterns |
| `components/lazy-loading` | Base | KEPT | Code splitting patterns |
| `components/memoization` | Base | KEPT | useMemo/useCallback patterns |
| `components/ref-usage` | Base | KEPT | Ref forwarding patterns |
| `components/context-usage` | Learning | KEPT | Context API patterns |

### Category 5: Config (8 detectors)

| Detector | Type | Status | Description |
|----------|------|--------|-------------|
| `config/env-management` | Learning | KEPT | Environment variable patterns |
| `config/feature-flags` | Base | KEPT | Feature flag patterns |
| `config/secrets-handling` | Base | UPGRADED | + OWASP A02 alignment |
| `config/build-config` | Learning | KEPT | Build configuration patterns |
| `config/runtime-config` | Learning | KEPT | Runtime config patterns |
| `config/debug-mode` | Base | UPGRADED | + OWASP A05 (debug in prod) |
| `config/default-values` | Learning | KEPT | Default config patterns |
| `config/validation` | Base | KEPT | Config validation patterns |

### Category 6: Contracts (6 detectors)

| Detector | Type | Status | Description |
|----------|------|--------|-------------|
| `contracts/rest-endpoint` | Semantic | KEPT | REST endpoint extraction |
| `contracts/api-call` | Semantic | KEPT | Frontend API call extraction |
| `contracts/type-mismatch` | Semantic | UPGRADED | + cross-paradigm |
| `contracts/breaking-change` | Semantic | UPGRADED | + GraphQL/gRPC |
| `contracts/schema-drift` | Base | NEW | Schema file vs code drift |
| `contracts/deprecation` | Base | KEPT | Deprecated endpoint usage |

### Category 7: Data Access (12 detectors)

| Detector | Type | Status | Description |
|----------|------|--------|-------------|
| `data-access/query-pattern` | Learning | KEPT | SQL/ORM query patterns |
| `data-access/connection-management` | Base | KEPT | Connection pool patterns |
| `data-access/transaction-handling` | Base | KEPT | Transaction patterns |
| `data-access/sql-injection` | Semantic | UPGRADED | + taint tracking, CWE-89 |
| `data-access/n-plus-one` | Semantic | KEPT | N+1 query detection |
| `data-access/migration-pattern` | Learning | KEPT | DB migration patterns |
| `data-access/orm-usage` | Learning | KEPT | ORM vs raw SQL patterns |
| `data-access/caching` | Base | KEPT | Cache layer patterns |
| `data-access/batch-operations` | Base | KEPT | Batch vs individual ops |
| `data-access/read-write-split` | Base | KEPT | Read replica patterns |
| `data-access/sensitive-data` | Semantic | UPGRADED | + PII detection |
| `data-access/parameterization` | Base | UPGRADED | + CWE-89 alignment |

### Category 8: Documentation (6 detectors)

| Detector | Type | Status | Description |
|----------|------|--------|-------------|
| `documentation/jsdoc` | Learning | KEPT | JSDoc patterns |
| `documentation/readme` | Base | KEPT | README patterns |
| `documentation/api-docs` | Learning | KEPT | API documentation patterns |
| `documentation/inline-comments` | Learning | KEPT | Comment conventions |
| `documentation/changelog` | Base | KEPT | Changelog patterns |
| `documentation/type-docs` | Learning | KEPT | Type documentation patterns |

### Category 9: Errors (14 detectors)

| Detector | Type | Status | Description |
|----------|------|--------|-------------|
| `errors/try-catch` | Learning | KEPT | Try-catch patterns |
| `errors/error-types` | Learning | KEPT | Custom error type patterns |
| `errors/error-propagation` | Semantic | KEPT | Error propagation chains |
| `errors/error-logging` | Learning | KEPT | Error logging patterns |
| `errors/error-recovery` | Base | KEPT | Recovery strategy patterns |
| `errors/unhandled-rejection` | Semantic | KEPT | Unhandled promise rejection |
| `errors/error-boundary` | Base | KEPT | Framework error boundaries |
| `errors/retry-pattern` | Base | KEPT | Retry logic patterns |
| `errors/circuit-breaker` | Base | KEPT | Circuit breaker patterns |
| `errors/graceful-degradation` | Base | KEPT | Graceful degradation |
| `errors/error-codes` | Learning | KEPT | Error code conventions |
| `errors/stack-trace` | Base | KEPT | Stack trace handling |
| `errors/empty-catch` | Base | KEPT | Empty catch block detection |
| `errors/swallowed-errors` | Semantic | KEPT | Errors caught but not handled |

### Category 10: Logging (8 detectors)

| Detector | Type | Status | Description |
|----------|------|--------|-------------|
| `logging/log-levels` | Learning | KEPT | Log level conventions |
| `logging/structured-logging` | Learning | KEPT | Structured vs unstructured |
| `logging/sensitive-data` | Base | UPGRADED | + OWASP A09, PII in logs |
| `logging/log-format` | Learning | KEPT | Log format patterns |
| `logging/audit-trail` | Base | UPGRADED | + OWASP A09 alignment |
| `logging/performance-logging` | Base | KEPT | Performance metric logging |
| `logging/error-context` | Learning | KEPT | Error context in logs |
| `logging/log-rotation` | Base | KEPT | Log rotation patterns |

### Category 11: Performance (10 detectors)

| Detector | Type | Status | Description |
|----------|------|--------|-------------|
| `performance/bundle-size` | Base | KEPT | Bundle size patterns |
| `performance/lazy-loading` | Base | KEPT | Lazy loading patterns |
| `performance/memoization` | Base | KEPT | Memoization patterns |
| `performance/async-patterns` | Learning | KEPT | Async/await patterns |
| `performance/loop-optimization` | Base | KEPT | Loop performance |
| `performance/memory-leaks` | Semantic | KEPT | Memory leak patterns |
| `performance/render-optimization` | Base | KEPT | Render performance |
| `performance/caching-strategy` | Learning | KEPT | Caching patterns |
| `performance/database-queries` | Semantic | KEPT | Query performance |
| `performance/network-calls` | Base | KEPT | Network optimization |

### Category 12: Security (18 detectors)

| Detector | Type | Status | Description |
|----------|------|--------|-------------|
| `security/xss-prevention` | Semantic | UPGRADED | + CWE-79, taint tracking |
| `security/input-validation` | Base | UPGRADED | + OWASP A03 alignment |
| `security/output-encoding` | Base | KEPT | Output encoding patterns |
| `security/dependency-audit` | Base | KEPT | Known vulnerability deps |
| `security/hardcoded-secrets` | Base | UPGRADED | + 100+ patterns |
| `security/encryption` | Base | KEPT | Encryption usage patterns |
| `security/authentication` | Semantic | UPGRADED | + OWASP A07 |
| `security/authorization` | Semantic | UPGRADED | + OWASP A01 |
| `security/weak-crypto` | Base | NEW | MD5, SHA1, DES, RC4, ECB detection (CWE-327) |
| `security/insecure-random` | Base | NEW | Math.random() in security contexts (CWE-330) |
| `security/command-injection` | Semantic | NEW | exec/system with user input (CWE-78) |
| `security/ssrf` | Semantic | NEW | URL from user input (CWE-918) |
| `security/path-traversal` | Semantic | NEW | File path from user input (CWE-22) |
| `security/insecure-deserialization` | Base | NEW | pickle.loads, unsafe JSON.parse (CWE-502) |
| `security/missing-security-headers` | Base | NEW | CSP, HSTS, X-Frame-Options (CWE-693) |
| `security/cors-misconfiguration` | Base | NEW | Access-Control-Allow-Origin: * |
| `security/template-injection` | Semantic | NEW | SSTI detection (CWE-1336) |
| `security/open-redirect` | Semantic | NEW | Unvalidated redirects (CWE-601) |

### Category 13: Structural (20 detectors)

| Detector | Type | Status | Description |
|----------|------|--------|-------------|
| `structural/file-naming` | Learning | KEPT | File naming conventions |
| `structural/directory-structure` | Learning | KEPT | Directory organization |
| `structural/module-boundaries` | Semantic | KEPT | Module boundary patterns |
| `structural/import-ordering` | Learning | KEPT | Import order conventions |
| `structural/export-patterns` | Learning | KEPT | Export patterns |
| `structural/code-organization` | Learning | KEPT | Code organization patterns |
| `structural/dependency-direction` | Semantic | KEPT | Dependency flow patterns |
| `structural/circular-deps` | Semantic | KEPT | Circular dependency detection |
| `structural/barrel-files` | Learning | KEPT | Index/barrel file patterns |
| `structural/colocation` | Learning | KEPT | File colocation patterns |
| `structural/layer-violations` | Semantic | KEPT | Architecture layer violations |
| `structural/dead-code` | Semantic | KEPT | Unreachable code detection |
| `structural/code-duplication` | Base | KEPT | Duplicate code patterns |
| `structural/function-length` | Base | KEPT | Function size patterns |
| `structural/parameter-count` | Base | KEPT | Parameter count patterns |
| `structural/nesting-depth` | Base | KEPT | Nesting depth patterns |
| `structural/complexity` | Base | KEPT | Cyclomatic complexity |
| `structural/coupling` | Semantic | KEPT | Module coupling metrics |
| `structural/cohesion` | Semantic | KEPT | Module cohesion metrics |
| `structural/god-class` | Base | KEPT | God class detection |

### Category 14: Styling (6 detectors)

| Detector | Type | Status | Description |
|----------|------|--------|-------------|
| `styling/css-methodology` | Learning | KEPT | BEM, SMACSS, etc. |
| `styling/naming-convention` | Learning | KEPT | CSS class naming |
| `styling/responsive-patterns` | Learning | KEPT | Responsive design patterns |
| `styling/theme-usage` | Learning | KEPT | Theme/design token usage |
| `styling/utility-classes` | Learning | KEPT | Utility-first patterns |
| `styling/css-in-js` | Learning | KEPT | CSS-in-JS patterns |

### Category 15: Testing (12 detectors)

| Detector | Type | Status | Description |
|----------|------|--------|-------------|
| `testing/test-naming` | Learning | KEPT | Test naming conventions |
| `testing/test-structure` | Learning | KEPT | AAA/GWT patterns |
| `testing/assertion-style` | Learning | KEPT | Assertion library patterns |
| `testing/mock-patterns` | Learning | KEPT | Mocking conventions |
| `testing/fixture-patterns` | Learning | KEPT | Test fixture patterns |
| `testing/coverage-gaps` | Semantic | KEPT | Untested critical paths |
| `testing/test-isolation` | Base | KEPT | Test isolation patterns |
| `testing/snapshot-testing` | Learning | KEPT | Snapshot test patterns |
| `testing/integration-tests` | Learning | KEPT | Integration test patterns |
| `testing/e2e-patterns` | Learning | KEPT | E2E test patterns |
| `testing/test-utilities` | Learning | KEPT | Test helper patterns |
| `testing/flaky-indicators` | Base | KEPT | Flaky test indicators |

### Category 16: Types (8 detectors)

| Detector | Type | Status | Description |
|----------|------|--------|-------------|
| `types/type-annotations` | Learning | KEPT | Type annotation patterns |
| `types/generic-usage` | Learning | KEPT | Generic type patterns |
| `types/union-types` | Learning | KEPT | Union/intersection patterns |
| `types/type-guards` | Learning | KEPT | Type guard patterns |
| `types/enum-patterns` | Learning | KEPT | Enum usage patterns |
| `types/interface-patterns` | Learning | KEPT | Interface conventions |
| `types/type-exports` | Learning | KEPT | Type export patterns |
| `types/strict-mode` | Base | KEPT | Strict type checking |

### Totals

| Metric | Count |
|--------|-------|
| Total categories | 16 |
| Total base detectors | ~173 |
| Total with learning variants | ~346 |
| Total with semantic variants | ~519 |
| v1 detectors KEPT | ~155 |
| v1 detectors UPGRADED | ~18 |
| NEW detectors (v2) | ~14 |
| OWASP Top 10 coverage | 9/10 (A06 deferred to Snyk/Dependabot) |
| CWE-tagged detectors | 18 (all security + auth) |


---

## 18. SQLite Storage Schema (drift.db — Detector Tables)

All detector data lives in drift.db Silver layer. Schema uses STRICT tables,
JSONB for queryable JSON columns, generated columns for derived fields,
and keyset pagination indexes. Follows 02-STORAGE-V2-PREP.md conventions.

### 18.1 `patterns` — Core Pattern Table

```sql
CREATE TABLE patterns (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL CHECK(category IN (
        'accessibility','api','auth','components','config','contracts',
        'data-access','documentation','errors','logging','performance',
        'security','structural','styling','testing','types'
    )),
    subcategory TEXT NOT NULL DEFAULT '',
    description TEXT,
    status TEXT NOT NULL DEFAULT 'discovered' CHECK(status IN (
        'discovered','approved','ignored'
    )),
    detection_method TEXT NOT NULL CHECK(detection_method IN (
        'ast_query','regex','structural'
    )),
    detector_id TEXT NOT NULL,

    -- Bayesian confidence (replaces v1's 4 static fields)
    confidence_alpha REAL NOT NULL DEFAULT 1.0,
    confidence_beta REAL NOT NULL DEFAULT 1.0,
    confidence_score REAL NOT NULL DEFAULT 0.0,

    -- Momentum scoring (NEW in v2)
    momentum REAL NOT NULL DEFAULT 0.0,          -- -1.0 to 1.0
    previous_frequency REAL,                      -- Last scan's frequency

    -- Counts
    location_count INTEGER NOT NULL DEFAULT 0,
    outlier_count INTEGER NOT NULL DEFAULT 0,

    -- Metadata
    severity TEXT NOT NULL DEFAULT 'info' CHECK(severity IN (
        'error','warning','info','hint'
    )),
    auto_fixable INTEGER NOT NULL DEFAULT 0,
    hash TEXT,
    parent_id TEXT REFERENCES patterns(id),
    decay_rate REAL,
    tags TEXT CHECK(tags IS NULL OR json_valid(tags)),  -- JSONB array

    -- Security metadata (NEW — OWASP/CWE alignment)
    cwe_ids TEXT CHECK(cwe_ids IS NULL OR json_valid(cwe_ids)),  -- JSONB array of ints
    owasp_category TEXT,                          -- e.g., "A03:2021"

    -- Timestamps
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen TEXT NOT NULL DEFAULT (datetime('now')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,

    -- Generated columns (indexed, computed from stored columns)
    confidence_level TEXT GENERATED ALWAYS AS (
        CASE
            WHEN confidence_score >= 0.85 THEN 'high'
            WHEN confidence_score >= 0.70 THEN 'medium'
            WHEN confidence_score >= 0.50 THEN 'low'
            ELSE 'uncertain'
        END
    ) VIRTUAL,
    is_actionable INTEGER GENERATED ALWAYS AS (
        CASE WHEN status = 'approved' AND confidence_score >= 0.70 THEN 1 ELSE 0 END
    ) VIRTUAL,
    momentum_direction TEXT GENERATED ALWAYS AS (
        CASE
            WHEN momentum > 0.05 THEN 'rising'
            WHEN momentum < -0.05 THEN 'declining'
            ELSE 'stable'
        END
    ) VIRTUAL
) STRICT;
```

### 18.2 `pattern_locations` — Where Patterns Are Found

```sql
CREATE TABLE pattern_locations (
    pattern_id TEXT NOT NULL REFERENCES patterns(id) ON DELETE CASCADE,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    column_num INTEGER NOT NULL,
    end_line INTEGER,
    end_column INTEGER,
    snippet TEXT,
    deviation_score REAL,                         -- How far from convention (for outliers)
    is_outlier INTEGER NOT NULL DEFAULT 0,
    outlier_reason TEXT,
    metadata TEXT CHECK(metadata IS NULL OR json_valid(metadata)),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (pattern_id, file, line)
) STRICT;
```

### 18.3 `pattern_variants` — Scoped Overrides

```sql
CREATE TABLE pattern_variants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_id TEXT NOT NULL REFERENCES patterns(id) ON DELETE CASCADE,
    scope TEXT NOT NULL CHECK(scope IN ('global','directory','file')),
    scope_path TEXT,                              -- Directory or file path
    severity_override TEXT CHECK(severity_override IS NULL OR severity_override IN (
        'error','warning','info','hint'
    )),
    enabled_override INTEGER,                     -- 0 = disabled, 1 = enabled
    threshold_override REAL,
    config_override TEXT CHECK(config_override IS NULL OR json_valid(config_override)),
    expires_at TEXT,                               -- Optional expiration
    created_at INTEGER NOT NULL
) STRICT;
```

### 18.4 `pattern_examples` — Code Examples for Patterns

```sql
CREATE TABLE pattern_examples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_id TEXT NOT NULL REFERENCES patterns(id) ON DELETE CASCADE,
    file TEXT NOT NULL,
    code TEXT NOT NULL,
    line_start INTEGER,
    line_end INTEGER,
    is_positive INTEGER NOT NULL DEFAULT 1,       -- 1 = good example, 0 = bad example
    created_at INTEGER NOT NULL
) STRICT;
```

### 18.5 `pattern_history` — Pattern Change Tracking

```sql
CREATE TABLE pattern_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN (
        'created','updated','approved','ignored','deleted','score_changed'
    )),
    old_value TEXT CHECK(old_value IS NULL OR json_valid(old_value)),
    new_value TEXT CHECK(new_value IS NULL OR json_valid(new_value)),
    created_at INTEGER NOT NULL
) STRICT;
```

### 18.6 `pattern_scan_history` — Per-Pattern Frequency Across Scans (NEW)

Required for momentum scoring (§9). Tracks frequency per pattern per scan.

```sql
CREATE TABLE pattern_scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_id TEXT NOT NULL REFERENCES patterns(id) ON DELETE CASCADE,
    scan_id TEXT NOT NULL,
    frequency REAL NOT NULL,                      -- 0.0-1.0 at time of scan
    location_count INTEGER NOT NULL,
    total_files INTEGER NOT NULL,
    confidence_score REAL NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;
```

### 18.7 `pattern_tags` — Junction Table for Tag Filtering

Dual storage: tags stored as JSONB in `patterns.tags` for full retrieval,
and normalized here for indexed multi-tag filtering.

```sql
CREATE TABLE pattern_tags (
    pattern_id TEXT NOT NULL REFERENCES patterns(id) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    PRIMARY KEY (pattern_id, tag)
) STRICT;
```

### 18.8 `pattern_suppressions` — Detector Enable/Disable

```sql
CREATE TABLE pattern_suppressions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    detector_id TEXT NOT NULL,
    scope TEXT NOT NULL CHECK(scope IN ('global','category','file','line')),
    scope_value TEXT,                             -- Category name, file path, or file:line
    reason TEXT,
    expires_at TEXT,
    created_at INTEGER NOT NULL
) STRICT;
```

### 18.9 `violation_actions` — Feedback Loop Storage (NEW)

Stores developer actions on violations for the feedback loop (§16).

```sql
CREATE TABLE violation_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    violation_id TEXT NOT NULL,
    pattern_id TEXT NOT NULL,
    detector_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN (
        'fixed','dismissed','ignored','auto_fixed','not_seen'
    )),
    source TEXT NOT NULL CHECK(source IN ('ide','cli','ci')),
    file TEXT,
    line INTEGER,
    created_at INTEGER NOT NULL
) STRICT;
```

### 18.10 `detector_health` — Detector Health Metrics (NEW)

Materialized from `violation_actions`. Refreshed after each scan.

```sql
CREATE TABLE detector_health (
    detector_id TEXT PRIMARY KEY,
    total_violations INTEGER NOT NULL DEFAULT 0,
    fixed_count INTEGER NOT NULL DEFAULT 0,
    dismissed_count INTEGER NOT NULL DEFAULT 0,
    ignored_count INTEGER NOT NULL DEFAULT 0,
    auto_fixed_count INTEGER NOT NULL DEFAULT 0,
    not_seen_count INTEGER NOT NULL DEFAULT 0,
    effective_fp_rate REAL NOT NULL DEFAULT 0.0,
    status TEXT NOT NULL DEFAULT 'healthy' CHECK(status IN (
        'healthy','warning','disabled'
    )),
    last_updated INTEGER NOT NULL,

    -- Generated column
    fix_rate REAL GENERATED ALWAYS AS (
        CASE WHEN (fixed_count + auto_fixed_count + dismissed_count + ignored_count) > 0
        THEN CAST(fixed_count + auto_fixed_count AS REAL) /
             (fixed_count + auto_fixed_count + dismissed_count + ignored_count)
        ELSE 0.0 END
    ) VIRTUAL
) STRICT;
```

### 18.11 `learned_conventions` — Convention Learning Results

```sql
CREATE TABLE learned_conventions (
    id TEXT PRIMARY KEY,
    detector_id TEXT NOT NULL,
    category TEXT NOT NULL,
    convention_name TEXT NOT NULL,
    convention_value TEXT NOT NULL,
    alpha REAL NOT NULL DEFAULT 1.0,
    beta REAL NOT NULL DEFAULT 1.0,
    frequency REAL NOT NULL DEFAULT 0.0,
    file_count INTEGER NOT NULL DEFAULT 0,
    total_files INTEGER NOT NULL DEFAULT 0,
    trend TEXT NOT NULL DEFAULT 'stable' CHECK(trend IN ('rising','stable','declining')),
    convention_category TEXT NOT NULL DEFAULT 'discovered' CHECK(convention_category IN (
        'universal','project_specific','emerging','legacy','contested'
    )),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;
```

### 18.12 Indexes

```sql
-- Pattern queries
CREATE INDEX idx_patterns_category ON patterns(category, status, confidence_score DESC);
CREATE INDEX idx_patterns_detector ON patterns(detector_id);
CREATE INDEX idx_patterns_status ON patterns(status);
CREATE INDEX idx_patterns_momentum ON patterns(momentum_direction, category);

-- Covering index for pattern listing (avoids table lookup)
CREATE INDEX idx_patterns_covering ON patterns(
    category, status, confidence_score DESC,
    id, name, severity, location_count, outlier_count
);

-- Partial indexes for hot queries
CREATE INDEX idx_approved_patterns ON patterns(category, confidence_score DESC)
    WHERE status = 'approved';
CREATE INDEX idx_high_confidence ON patterns(category, status)
    WHERE confidence_score >= 0.85;
CREATE INDEX idx_actionable_patterns ON patterns(category, severity)
    WHERE is_actionable = 1;

-- Location queries
CREATE INDEX idx_locations_file ON pattern_locations(file);
CREATE INDEX idx_locations_pattern ON pattern_locations(pattern_id);
CREATE INDEX idx_locations_outlier ON pattern_locations(pattern_id)
    WHERE is_outlier = 1;

-- Variant queries
CREATE INDEX idx_variants_pattern ON pattern_variants(pattern_id);
CREATE INDEX idx_variants_scope ON pattern_variants(scope, scope_path);

-- Scan history (for momentum calculation)
CREATE INDEX idx_scan_history_pattern ON pattern_scan_history(pattern_id, created_at DESC);

-- Tag filtering
CREATE INDEX idx_tags_tag ON pattern_tags(tag);

-- Suppression queries
CREATE INDEX idx_suppressions_detector ON pattern_suppressions(detector_id);
CREATE INDEX idx_suppressions_scope ON pattern_suppressions(scope, scope_value);

-- Violation action queries
CREATE INDEX idx_violation_actions_detector ON violation_actions(detector_id, created_at DESC);
CREATE INDEX idx_violation_actions_pattern ON violation_actions(pattern_id);

-- Convention queries
CREATE INDEX idx_conventions_detector ON learned_conventions(detector_id);
CREATE INDEX idx_conventions_category ON learned_conventions(category, convention_category);
```


---

## 19. NAPI Bridge Interface (Detector Functions)

All detector NAPI functions follow the patterns established in 03-NAPI-BRIDGE-V2-PREP.md:
command functions write to drift.db and return summaries, query functions read from drift.db
with keyset pagination. Uses napi-rs v3 with `#[napi(object)]` structs.

### 19.1 Command Functions (Write-Heavy)

```rust
/// Run all detectors on the project. Writes patterns, locations, violations to drift.db.
/// Returns a lightweight summary.
#[napi]
pub fn detect_patterns(
    root: String,
    options: DetectOptions,
) -> AsyncTask<DetectPatternsTask> {
    AsyncTask::new(DetectPatternsTask { root, options })
}

#[napi(object)]
pub struct DetectOptions {
    /// Run incrementally (skip unchanged files). Default: true.
    pub incremental: Option<bool>,
    /// Categories to run. Default: all enabled in config.
    pub categories: Option<Vec<String>>,
    /// Specific detectors to run. Default: all enabled.
    pub detectors: Option<Vec<String>>,
    /// Force full re-learning (ignore cached conventions). Default: false.
    pub force_relearn: Option<bool>,
}

#[napi(object)]
pub struct DetectionSummary {
    pub total_patterns: u32,
    pub new_patterns: u32,
    pub updated_patterns: u32,
    pub removed_patterns: u32,
    pub total_violations: u32,
    pub violations_by_severity: HashMap<String, u32>,  // {"error": 5, "warning": 12, ...}
    pub categories_scanned: Vec<String>,
    pub detectors_run: u32,
    pub files_analyzed: u32,
    pub files_skipped: u32,                            // Incremental skip count
    pub conventions_learned: u32,
    pub contested_conventions: u32,
    pub duration_ms: u32,
    pub status: String,                                // "complete" | "partial" | "cancelled"
}

/// Learn conventions without generating violations. Useful for initial setup.
#[napi]
pub fn learn_conventions(
    root: String,
    options: LearnOptions,
) -> AsyncTask<LearnConventionsTask> {
    AsyncTask::new(LearnConventionsTask { root, options })
}

#[napi(object)]
pub struct LearnOptions {
    pub categories: Option<Vec<String>>,
    pub min_files: Option<u32>,
    pub min_confidence: Option<f64>,
}

#[napi(object)]
pub struct LearningSummary {
    pub conventions_learned: u32,
    pub conventions_by_category: HashMap<String, u32>,
    pub contested_pairs: u32,
    pub files_observed: u32,
    pub duration_ms: u32,
}

/// Register a violation action (feedback loop).
#[napi]
pub fn register_violation_action(
    violation_id: String,
    pattern_id: String,
    detector_id: String,
    action: String,          // "fixed" | "dismissed" | "ignored" | "auto_fixed"
    source: String,          // "ide" | "cli" | "ci"
) -> napi::Result<()> {
    let rt = crate::runtime::get()?;
    drift_core::feedback::register_action(
        &rt.db, &violation_id, &pattern_id, &detector_id,
        action.parse().map_err(to_napi_error)?,
        source.parse().map_err(to_napi_error)?,
    ).map_err(to_napi_error)
}
```

### 19.2 Query Functions (Read-Only, Paginated)

```rust
/// Query patterns with filters and pagination.
#[napi]
pub fn query_patterns(
    filter: PatternFilter,
    pagination: Option<PaginationOptions>,
) -> napi::Result<PaginatedResult> {
    let rt = crate::runtime::get()?;
    // ... (follows 03-NAPI-BRIDGE-V2-PREP.md §11 pagination pattern)
}

#[napi(object)]
pub struct PatternFilter {
    pub category: Option<String>,
    pub status: Option<String>,
    pub confidence_min: Option<f64>,
    pub confidence_max: Option<f64>,
    pub severity: Option<String>,
    pub detector_id: Option<String>,
    pub file: Option<String>,                     // Filter by file containing pattern
    pub tag: Option<String>,
    pub momentum_direction: Option<String>,        // "rising" | "stable" | "declining"
    pub search: Option<String>,                    // Full-text search on name/description
}

/// Query full pattern detail including locations, examples, history.
#[napi]
pub fn query_pattern_detail(id: String) -> napi::Result<PatternDetail> {
    let rt = crate::runtime::get()?;
    drift_core::storage::get_pattern_detail(&rt.db, &id)
        .map_err(to_napi_error)?
        .ok_or_else(|| napi::Error::from_reason("[NOT_FOUND] Pattern not found"))
}

#[napi(object)]
pub struct PatternDetail {
    pub id: String,
    pub name: String,
    pub category: String,
    pub status: String,
    pub confidence_score: f64,
    pub confidence_level: String,
    pub momentum: f64,
    pub momentum_direction: String,
    pub severity: String,
    pub location_count: u32,
    pub outlier_count: u32,
    pub locations: Vec<LocationSummary>,           // First 50 locations
    pub examples: Vec<ExampleSummary>,
    pub history: Vec<HistorySummary>,              // Last 20 changes
    pub variants: Vec<VariantSummary>,
    pub cwe_ids: Option<Vec<u32>>,
    pub owasp_category: Option<String>,
    pub fix_available: bool,
    pub auto_fixable: bool,
}

/// Query violations with filters and pagination.
#[napi]
pub fn query_violations(
    filter: ViolationFilter,
    pagination: Option<PaginationOptions>,
) -> napi::Result<PaginatedResult> {
    let rt = crate::runtime::get()?;
    // ... pagination pattern
}

#[napi(object)]
pub struct ViolationFilter {
    pub file: Option<String>,
    pub severity: Option<String>,
    pub category: Option<String>,
    pub detector_id: Option<String>,
    pub has_fix: Option<bool>,
    pub cwe_id: Option<u32>,
    pub owasp_category: Option<String>,
}

/// Query detector health metrics.
#[napi]
pub fn query_detector_health(
    detector_id: Option<String>,
) -> napi::Result<serde_json::Value> {
    let rt = crate::runtime::get()?;
    match detector_id {
        Some(id) => {
            let health = drift_core::feedback::get_detector_health(&rt.db, &id)
                .map_err(to_napi_error)?;
            serde_json::to_value(&health)
                .map_err(|e| napi::Error::from_reason(format!("[INTERNAL_ERROR] {e}")))
        }
        None => {
            let dashboard = drift_core::feedback::get_health_dashboard(&rt.db)
                .map_err(to_napi_error)?;
            serde_json::to_value(&dashboard)
                .map_err(|e| napi::Error::from_reason(format!("[INTERNAL_ERROR] {e}")))
        }
    }
}

/// Query learned conventions.
#[napi]
pub fn query_conventions(
    filter: ConventionFilter,
    pagination: Option<PaginationOptions>,
) -> napi::Result<PaginatedResult> {
    let rt = crate::runtime::get()?;
    // ... pagination pattern
}

#[napi(object)]
pub struct ConventionFilter {
    pub category: Option<String>,
    pub convention_category: Option<String>,       // "universal" | "emerging" | "contested" etc.
    pub detector_id: Option<String>,
    pub trend: Option<String>,                     // "rising" | "stable" | "declining"
    pub min_confidence: Option<f64>,
}
```

### 19.3 NAPI Function Summary (Detector Domain)

| Function | Sync/Async | Returns | Category |
|----------|-----------|---------|----------|
| `detect_patterns(root, options)` | Async | `DetectionSummary` | Command |
| `learn_conventions(root, options)` | Async | `LearningSummary` | Command |
| `register_violation_action(...)` | Sync | `void` | Command |
| `query_patterns(filter, pagination)` | Sync | `PaginatedResult` | Query |
| `query_pattern_detail(id)` | Sync | `PatternDetail` | Query |
| `query_violations(filter, pagination)` | Sync | `PaginatedResult` | Query |
| `query_detector_health(detector_id?)` | Sync | `DetectorHealth/Dashboard` | Query |
| `query_conventions(filter, pagination)` | Sync | `PaginatedResult` | Query |

Total: 8 detector-specific NAPI functions (subset of the ~55 total in drift-napi).


---

## 20. Incremental Detection (3-Layer System)

From R2. Eliminates redundant work for typical development workflows where
1-10 files change between scans. Three layers of incrementality, each building
on the previous.

### Layer 1: File-Level Skip (Content Hash)

If a file's content hash hasn't changed since the last scan, reuse all previous
detection results for that file. Skip parsing, skip detection entirely.

```rust
pub struct IncrementalDetector {
    db: Arc<DatabaseManager>,
}

impl IncrementalDetector {
    /// Determine which files need re-detection.
    pub fn partition_files(
        &self,
        scan_diff: &ScanDiff,
        all_files: &[FileEntry],
    ) -> IncrementalPartition {
        let mut needs_detection = Vec::new();
        let mut skip_unchanged = Vec::new();

        for file in all_files {
            if scan_diff.added.contains(&file.path)
                || scan_diff.modified.contains(&file.path)
            {
                needs_detection.push(file.clone());
            } else {
                // File unchanged — reuse cached results
                skip_unchanged.push(file.clone());
            }
        }

        // Removed files: delete their pattern_locations from drift.db
        let removed = scan_diff.removed.clone();

        IncrementalPartition {
            needs_detection,
            skip_unchanged,
            removed,
            skip_ratio: skip_unchanged.len() as f64
                / all_files.len().max(1) as f64,
        }
    }
}

pub struct IncrementalPartition {
    pub needs_detection: Vec<FileEntry>,
    pub skip_unchanged: Vec<FileEntry>,
    pub removed: Vec<PathBuf>,
    pub skip_ratio: f64,                          // 0.0-1.0, higher = more skipped
}
```

### Layer 2: Pattern-Level Re-Scoring

When files change, only re-score patterns that had locations in changed files.
All other pattern scores remain unchanged.

```rust
impl IncrementalDetector {
    /// Re-score only affected patterns after incremental detection.
    pub fn rescore_affected_patterns(
        &self,
        changed_files: &[PathBuf],
        new_results: &[DetectionResult],
    ) -> Result<RescoringReport, DetectionError> {
        // 1. Find patterns with locations in changed files
        let affected_pattern_ids = self.db.query_patterns_in_files(changed_files)?;

        // 2. Remove old locations for changed files
        self.db.delete_locations_for_files(changed_files)?;

        // 3. Insert new locations from detection results
        self.db.insert_locations(&new_results)?;

        // 4. Re-score only affected patterns
        let mut rescored = 0;
        for pattern_id in &affected_pattern_ids {
            let new_score = self.recompute_score(pattern_id)?;
            self.db.update_pattern_score(pattern_id, new_score)?;
            rescored += 1;
        }

        Ok(RescoringReport {
            affected_patterns: affected_pattern_ids.len(),
            rescored,
            unchanged_patterns: self.db.total_patterns()? - rescored,
        })
    }
}
```

### Layer 3: Convention Re-Learning Threshold

Convention learning is expensive (observes all files). Skip re-learning when
few files changed. Thresholds:

```rust
pub struct RelearnConfig {
    /// Below this ratio, skip re-learning entirely. Reuse cached conventions.
    pub skip_threshold: f64,       // 0.10 (< 10% files changed)
    /// Between skip and full, do incremental re-learning (update distributions).
    pub incremental_threshold: f64, // 0.30 (10-30% files changed)
    /// Above this, do full re-learning from scratch.
    /// (> 30% files changed → full relearn)
}

impl Default for RelearnConfig {
    fn default() -> Self {
        Self {
            skip_threshold: 0.10,
            incremental_threshold: 0.30,
        }
    }
}

pub enum RelearnStrategy {
    /// < 10% changed: reuse all cached conventions
    Skip,
    /// 10-30% changed: update Bayesian distributions with new observations only
    Incremental,
    /// > 30% changed: full re-learning from scratch
    Full,
}

impl RelearnConfig {
    pub fn strategy(&self, change_ratio: f64) -> RelearnStrategy {
        if change_ratio < self.skip_threshold {
            RelearnStrategy::Skip
        } else if change_ratio < self.incremental_threshold {
            RelearnStrategy::Incremental
        } else {
            RelearnStrategy::Full
        }
    }
}
```

### Incremental Detection Flow

```
1. Scanner provides ScanDiff (added, modified, removed, unchanged)
2. Layer 1: Partition files → needs_detection vs skip_unchanged
3. Parse only needs_detection files
4. Layer 3: Determine relearn strategy based on change ratio
   - Skip: use cached conventions
   - Incremental: update distributions with changed files only
   - Full: observe all files, recompute conventions
5. Run detection pass on needs_detection files only
6. Layer 2: Re-score only affected patterns
7. Clean up removed file locations
8. Refresh Gold layer (materialized_status, health_trends)
```

### Force Full Scan Escape Hatch

```
drift scan --full          # Ignore incremental, re-detect everything
drift scan --relearn       # Force full convention re-learning
```

Exposed via NAPI `detect_patterns(root, { incremental: false })`.

---

## 21. TOML Pattern Definitions (AD3)

Declarative pattern definitions in TOML. Ship with hardcoded patterns,
users add custom patterns in `.drift/patterns/` directory.

### TOML Schema

```toml
# .drift/patterns/custom-api-patterns.toml

[metadata]
name = "Custom API Patterns"
version = "1.0.0"
author = "Team Name"
description = "Project-specific API conventions"

# --- AST Query Pattern ---
[[patterns]]
id = "api/custom-response-format"
name = "API Response Format"
category = "api"
severity = "warning"
description = "All API responses should use the standard ResponseWrapper"
languages = ["typescript", "javascript"]

[patterns.ast_query]
node_type = "Call"
base_confidence = 0.85

[patterns.ast_query.constraints]
callee_pattern = "res\\.(json|send)"
# Must be wrapped in ResponseWrapper
negative_pattern = "ResponseWrapper"

[patterns.fix]
kind = "text_edit"
description = "Wrap response in ResponseWrapper"
safety_level = "review_required"
template = "ResponseWrapper.success({{original}})"

# --- Regex Pattern ---
[[patterns]]
id = "logging/custom-log-format"
name = "Structured Log Format"
category = "logging"
severity = "info"
description = "Use structured logging with context object"
languages = ["typescript", "javascript"]

[patterns.regex]
pattern = 'console\.(log|warn|error)\('
base_confidence = 0.70
capture_names = ["method"]

[patterns.fix]
kind = "suggestion"
description = "Replace console.log with structured logger"
safety_level = "review_required"

# --- Structural Pattern ---
[[patterns]]
id = "errors/custom-error-handling"
name = "Error Handler Pattern"
category = "errors"
severity = "warning"
description = "All route handlers must have try-catch with error logging"

[patterns.structural]
min_matches = 2
min_score = 0.7

[[patterns.structural.constraints]]
name = "has_try_catch"
node_type = "TryCatch"
weight = 0.5

[[patterns.structural.constraints]]
name = "has_error_logging"
node_type = "Call"
callee_pattern = "logger\\.(error|warn)"
parent_type = "CatchClause"
weight = 0.5

# --- Learning Pattern (Convention Discovery) ---
[[patterns]]
id = "structural/custom-file-naming"
name = "File Naming Convention"
category = "structural"
severity = "info"
description = "Discover and enforce file naming conventions"
is_learning = true

[patterns.learning]
observe_target = "file_name"
min_files = 10
min_confidence = 0.75
```

### Built-in vs Custom Patterns

| Source | Location | Priority | Editable |
|--------|----------|----------|----------|
| Built-in | Compiled into drift-core | Lowest | No |
| Project | `.drift/patterns/*.toml` | Medium | Yes |
| User | `~/.drift/patterns/*.toml` | Highest | Yes |

Higher priority patterns override lower priority patterns with the same `id`.

### Pattern Loading

```rust
pub struct PatternLoader;

impl PatternLoader {
    pub fn load_all(project_root: &Path) -> Vec<PatternDefinition> {
        let mut patterns = Vec::new();

        // 1. Built-in patterns (compiled in)
        patterns.extend(Self::builtin_patterns());

        // 2. Project patterns (.drift/patterns/*.toml)
        let project_dir = project_root.join(".drift/patterns");
        if project_dir.exists() {
            patterns.extend(Self::load_toml_dir(&project_dir));
        }

        // 3. User patterns (~/.drift/patterns/*.toml)
        if let Some(home) = dirs::home_dir() {
            let user_dir = home.join(".drift/patterns");
            if user_dir.exists() {
                patterns.extend(Self::load_toml_dir(&user_dir));
            }
        }

        // Deduplicate by id (last wins = highest priority)
        let mut by_id: HashMap<String, PatternDefinition> = HashMap::new();
        for pattern in patterns {
            by_id.insert(pattern.id.clone(), pattern);
        }

        by_id.into_values().collect()
    }

    fn load_toml_dir(dir: &Path) -> Vec<PatternDefinition> {
        std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                if path.extension()? == "toml" {
                    let content = std::fs::read_to_string(&path).ok()?;
                    let file: PatternFile = toml::from_str(&content).ok()?;
                    Some(file.patterns)
                } else {
                    None
                }
            })
            .flatten()
            .collect()
    }
}
```

### TOML Validation

Patterns are validated at load time:

```rust
pub fn validate_pattern(pattern: &PatternDefinition) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();

    if pattern.id.is_empty() { errors.push(ValidationError::MissingField("id")); }
    if pattern.category.is_none() { errors.push(ValidationError::MissingField("category")); }
    if pattern.ast_query.is_none() && pattern.regex.is_none() && pattern.structural.is_none() {
        errors.push(ValidationError::NoDetectionMethod);
    }
    if let Some(regex) = &pattern.regex {
        if regex::Regex::new(&regex.pattern).is_err() {
            errors.push(ValidationError::InvalidRegex(regex.pattern.clone()));
        }
    }

    if errors.is_empty() { Ok(()) } else { Err(errors) }
}
```


---

## 22. Testing & Validation Framework

Dedicated testing infrastructure for detectors. Goes beyond unit tests to ensure
correctness, prevent regressions, and validate statistical calibration.

### 22.1 Snapshot Testing with Annotated Fixtures

Each detector gets a fixture directory with annotated source files:

```
tests/fixtures/
├── security/
│   ├── sql-injection/
│   │   ├── vulnerable.ts          # Known vulnerabilities
│   │   ├── safe.ts                # Should NOT trigger
│   │   ├── edge-cases.ts          # Tricky cases
│   │   └── expected.json          # Expected detection results
│   ├── xss-prevention/
│   │   ├── vulnerable.tsx
│   │   ├── safe.tsx
│   │   └── expected.json
│   └── ...
├── structural/
│   ├── file-naming/
│   │   ├── sample-project/        # Mini project structure
│   │   └── expected.json
│   └── ...
└── cross-language/                # Cross-language parity tests
    ├── try-catch/
    │   ├── typescript.ts
    │   ├── python.py
    │   ├── java.java
    │   ├── go.go
    │   ├── rust.rs
    │   └── expected.json          # Same expected patterns for all
    └── ...
```

### Inline Annotations

Fixture files use inline annotations to mark expected detections:

```typescript
// @drift-expect: security/sql-injection, confidence>=0.8, cwe=89
const query = `SELECT * FROM users WHERE id = ${userId}`;

// @drift-expect: none
const query = db.query('SELECT * FROM users WHERE id = ?', [userId]);

// @drift-expect: security/sql-injection, severity=error
const raw = connection.execute(`DROP TABLE ${tableName}`);
```

### Test Runner

```rust
pub struct DetectorTestRunner;

impl DetectorTestRunner {
    /// Run all fixture tests for a detector.
    pub fn test_detector(detector_id: &str) -> TestReport {
        let fixture_dir = Path::new("tests/fixtures")
            .join(detector_id.replace('/', "/"));

        let mut report = TestReport::new(detector_id);

        // Load expected results
        let expected: ExpectedResults = load_json(fixture_dir.join("expected.json"));

        // Run detector on each fixture file
        for fixture_file in list_fixture_files(&fixture_dir) {
            let parse_result = parse_file(&fixture_file);
            let actual = run_single_detector(detector_id, &parse_result);

            // Compare with inline annotations
            let annotations = extract_annotations(&fixture_file);
            for annotation in &annotations {
                match annotation {
                    Annotation::Expect { detector, constraints } => {
                        let matching = actual.iter()
                            .find(|m| m.detector_id == *detector && m.line == annotation.line);
                        if let Some(m) = matching {
                            report.add_true_positive(m, constraints);
                        } else {
                            report.add_false_negative(annotation);
                        }
                    }
                    Annotation::ExpectNone => {
                        let false_positives: Vec<_> = actual.iter()
                            .filter(|m| m.line == annotation.line)
                            .collect();
                        for fp in false_positives {
                            report.add_false_positive(fp);
                        }
                    }
                }
            }
        }

        report
    }
}
```

### 22.2 Cross-Language Parity Testing

For detectors that should work across languages (via GAST), test the same logical
pattern in all supported languages:

```rust
#[test]
fn try_catch_parity_across_languages() {
    let languages = ["typescript", "python", "java", "go", "rust"];
    let fixture_dir = Path::new("tests/fixtures/cross-language/try-catch");
    let expected: ExpectedResults = load_json(fixture_dir.join("expected.json"));

    for lang in &languages {
        let fixture = fixture_dir.join(format!("{}.{}", lang, extension_for(lang)));
        let result = run_detector("errors/try-catch", &fixture);

        // Same number of patterns expected regardless of language
        assert_eq!(
            result.patterns.len(), expected.pattern_count,
            "Language {} produced {} patterns, expected {}",
            lang, result.patterns.len(), expected.pattern_count
        );
    }
}
```

### 22.3 False-Positive Regression Tests

Maintain a corpus of known false positives that have been fixed:

```
tests/false-positives/
├── security/
│   ├── sql-injection/
│   │   ├── fp-001-template-literal.ts    # Was flagged, shouldn't be
│   │   ├── fp-002-orm-query.py           # Was flagged, shouldn't be
│   │   └── manifest.json                 # Metadata about each FP
│   └── ...
└── structural/
    └── ...
```

```rust
#[test]
fn no_known_false_positives_regressed() {
    let fp_dir = Path::new("tests/false-positives");
    let mut regressions = Vec::new();

    for manifest in find_manifests(fp_dir) {
        let entries: Vec<FPEntry> = load_json(&manifest);
        for entry in entries {
            let result = run_detector(&entry.detector_id, &entry.file);
            if !result.patterns.is_empty() {
                regressions.push(format!(
                    "REGRESSION: {} re-flagged {} (fixed in {})",
                    entry.detector_id, entry.file.display(), entry.fixed_date
                ));
            }
        }
    }

    assert!(
        regressions.is_empty(),
        "False positive regressions:\n{}",
        regressions.join("\n")
    );
}
```

### 22.4 Confidence Calibration Tests

Verify that confidence scores are well-calibrated (a score of 0.9 should be
correct ~90% of the time):

```rust
#[test]
fn confidence_calibration() {
    let corpus = load_calibration_corpus("tests/calibration-corpus/");
    let results = run_all_detectors_on_corpus(&corpus);

    // Bin results by confidence level
    let bins = [
        (0.85, 1.0, "high"),
        (0.70, 0.85, "medium"),
        (0.50, 0.70, "low"),
    ];

    for (min, max, label) in &bins {
        let in_bin: Vec<_> = results.iter()
            .filter(|r| r.confidence >= *min && r.confidence < *max)
            .collect();

        if in_bin.len() < 20 { continue; } // Not enough samples

        let true_positive_rate = in_bin.iter()
            .filter(|r| r.is_true_positive)
            .count() as f64 / in_bin.len() as f64;

        assert!(
            true_positive_rate >= min - 0.10,
            "Confidence bin '{}' ({}-{}): TP rate {:.2} is below expected {:.2}",
            label, min, max, true_positive_rate, min - 0.10
        );
    }
}
```

### 22.5 Performance Benchmarks

Each detector has a performance budget. Benchmarks run in CI to catch regressions:

```rust
use criterion::{criterion_group, criterion_main, Criterion};

fn detector_benchmarks(c: &mut Criterion) {
    let corpus_1k = load_benchmark_corpus("benches/corpus-1k");
    let corpus_10k = load_benchmark_corpus("benches/corpus-10k");

    // Single detector benchmark
    c.bench_function("security/sql-injection on 1K files", |b| {
        b.iter(|| {
            let detector = SqlInjectionDetector::new();
            run_detector_on_corpus(&detector, &corpus_1k)
        });
    });

    // Full detection engine benchmark
    c.bench_function("full detection engine on 1K files", |b| {
        b.iter(|| {
            let engine = DetectionEngine::new(&DetectorConfig::default(), DetectorRegistry::new());
            engine.detect_all(&corpus_1k, &mock_db(), &DetectorConfig::default())
        });
    });

    // Incremental detection benchmark (10 files changed out of 10K)
    c.bench_function("incremental detection 10/10K files", |b| {
        // Pre-populate with full scan results
        let db = setup_full_scan(&corpus_10k);
        let changed = &corpus_10k[..10]; // Only 10 files changed

        b.iter(|| {
            let engine = DetectionEngine::new(&DetectorConfig::default(), DetectorRegistry::new());
            engine.detect_incremental(changed, &db, &DetectorConfig::default())
        });
    });
}

criterion_group!(benches, detector_benchmarks);
criterion_main!(benches);
```

### Performance Budgets

| Operation | Budget | Measured On |
|-----------|--------|-------------|
| Single detector on 1 file | < 1ms | M1 MacBook Pro |
| Full engine on 1K files | < 5s | M1 MacBook Pro |
| Full engine on 10K files | < 30s | M1 MacBook Pro |
| Incremental (10 files changed) | < 500ms | M1 MacBook Pro |
| Convention learning on 10K files | < 10s | M1 MacBook Pro |
| Outlier detection on 100K values | < 100ms | M1 MacBook Pro |

---

## 23. Build Order & Dependencies

Phased implementation plan. Each phase builds on the previous.
Total estimated timeline: ~20 weeks for a senior engineer.

### Phase 1: Core Engine (Weeks 1-4)

Build the detection engine skeleton and core algorithms. No detectors yet —
just the infrastructure they plug into.

| Week | Deliverable | Dependencies |
|------|------------|-------------|
| 1 | `Detector` trait, `DetectionContext`, `DetectionResult` types | drift-core types |
| 1 | `DetectorRegistry` with `inventory` crate registration | None |
| 1 | `OutlierAnalyzer` — Z-Score, Grubbs', IQR implementations | None (pure math) |
| 2 | `BayesianConfidence` — scoring with momentum | None (pure math) |
| 2 | `BayesianConvention` — learning with contested detection | None (pure math) |
| 2 | `RuleEvaluator` — violation generation from patterns | Detector trait |
| 3 | `DetectionEngine` — visitor pattern, single-pass traversal | Detector trait, Registry |
| 3 | Two-pass architecture (learning pass + detection pass) | LearningDetector trait |
| 4 | `PatternMatcher` — AST, regex, structural matching | GAST types |
| 4 | TOML pattern loader and validator | PatternMatcher |

### Phase 2: GAST & Infrastructure (Weeks 5-8)

Build the Generic AST normalization layer and storage integration.

| Week | Deliverable | Dependencies |
|------|------------|-------------|
| 5 | `GASTNode` enum (~30 node types) | None |
| 5 | `GASTNormalizer` trait | GASTNode |
| 6 | TypeScript/JavaScript normalizer | tree-sitter-typescript |
| 6 | Python normalizer | tree-sitter-python |
| 7 | Java, Go, Rust normalizers | tree-sitter-* |
| 7 | C#, PHP, C++, Ruby normalizers | tree-sitter-* |
| 8 | SQLite schema (§18 — all detector tables) | drift.db storage layer |
| 8 | Incremental detection (3-layer system) | Scanner, storage |
| 8 | NAPI binding module (`bindings/detection.rs`) | drift-napi scaffold |

### Phase 3: Detector Categories (Weeks 9-16)

Build detectors category by category, starting with highest-value categories.
Each category includes base + learning + semantic variants, plus fixes.

| Week | Category | Detectors | Priority |
|------|----------|-----------|----------|
| 9 | Security (P0) | 18 detectors, OWASP/CWE mapping | Highest value |
| 10 | Auth (P0) | 10 detectors, OWASP A01/A07 | Security-adjacent |
| 10 | Errors (P0) | 14 detectors | Core quality |
| 11 | Structural (P1) | 20 detectors | Architecture quality |
| 11 | API (P1) | 12 detectors + GraphQL/gRPC | Contract detection |
| 12 | Contracts (P1) | 6 detectors, unified model | API-adjacent |
| 12 | Data Access (P1) | 12 detectors + taint | Security-adjacent |
| 13 | Components (P1) | 15 detectors | Frontend quality |
| 13 | Testing (P1) | 12 detectors | Test quality |
| 14 | Performance (P2) | 10 detectors | Performance quality |
| 14 | Logging (P2) | 8 detectors + OWASP A09 | Observability |
| 15 | Config (P2) | 8 detectors | Configuration quality |
| 15 | Types (P2) | 8 detectors | Type safety |
| 16 | Documentation (P2) | 6 detectors | Documentation quality |
| 16 | Accessibility (P2) | 8 detectors | A11y quality |
| 16 | Styling (P2) | 6 detectors | CSS quality |

### Phase 4: Ecosystem & Polish (Weeks 17-20)

| Week | Deliverable | Dependencies |
|------|------------|-------------|
| 17 | Framework middleware system | FrameworkMiddleware trait |
| 17 | Express, Spring Boot, Django middleware | Framework detection |
| 18 | Laravel, ASP.NET, Go, Rust, C++ middleware | Framework detection |
| 18 | Fix generation system (7 strategies) | All detectors |
| 19 | Feedback loop (violation action tracking) | NAPI, IDE integration |
| 19 | Detector health dashboard | Feedback loop |
| 20 | Testing framework (fixtures, calibration, benchmarks) | All detectors |
| 20 | Performance optimization pass | Benchmarks |

### Dependency Graph (Simplified)

```
drift-core types ──→ Detector trait ──→ Registry ──→ Engine
                                    ──→ PatternMatcher
                                    ──→ OutlierAnalyzer
                                    ──→ BayesianConfidence

tree-sitter ──→ GASTNode ──→ Normalizers (10) ──→ Engine

drift.db schema ──→ Storage integration ──→ Incremental detection

Engine + Normalizers + Storage ──→ Individual detectors (16 categories)

Detectors ──→ Framework middleware
          ──→ Fix generation
          ──→ Feedback loop
          ──→ Testing framework
```

---

## 24. V1 → V2 Migration Checklist

Final verification that every v1 feature is accounted for. Each item references
the section where it's specified.

### Core Architecture

- [x] 16 detection categories preserved (§17)
- [x] Base detector variant for all categories (§3 — `Detector` trait)
- [x] Learning detector variant for all categories (§3 — `LearningDetector` trait)
- [x] Semantic detector variant for all categories (§3 — `SemanticDetector` trait)
- [x] Pattern matching (AST, regex) preserved + structural added (§11)
- [x] Outlier detection preserved + upgraded (§10)
- [x] Convention learning preserved + Bayesian upgrade (§7)
- [x] Confidence scoring preserved + momentum added (§9)

### Detection Pipeline

- [x] File discovery via scanner (§1 — dependencies)
- [x] AST parsing via tree-sitter (§1 — dependencies)
- [x] Per-file detection (§4 — visitor pattern, single-pass)
- [x] Pattern aggregation (§4 — finalize phase)
- [x] Confidence scoring (§9 — Bayesian with momentum)
- [x] Outlier flagging (§10 — Z-Score + Grubbs' + IQR)
- [x] Violation generation (§14 — centralized rules engine)
- [x] Result storage (§18 — drift.db Silver tables)

### Data Types

- [x] Pattern (§18.1 — patterns table)
- [x] PatternLocation (§18.2 — pattern_locations table)
- [x] PatternVariant (§18.3 — pattern_variants table)
- [x] PatternExample (§18.4 — pattern_examples table)
- [x] PatternHistory (§18.5 — pattern_history table)
- [x] Violation (§3 — Violation struct, §14 — rules engine)
- [x] Convention (§7 — BayesianConvention, §18.11 — learned_conventions table)
- [x] DetectorResult (§3 — DetectionResult struct)
- [x] ConfidenceScore (§9 — BayesianConfidence struct)

### Framework Support

- [x] Express.js (§13)
- [x] Spring Boot (§13)
- [x] ASP.NET (§13)
- [x] Laravel (§13)
- [x] Django (§13)
- [x] Go (Gin/Echo) (§13)
- [x] Rust (Axum/Actix) (§13)
- [x] C++ (Crow/Drogon) (§13)

### Registry & Configuration

- [x] Detector registration (§6 — compile-time registry)
- [x] Category filtering (§6 — `enabled_detectors()`)
- [x] Language filtering (§6 — `detectors_for_language()`)
- [x] Severity overrides (§18.3 — pattern_variants)
- [x] Detector enable/disable (§18.8 — pattern_suppressions)
- [x] Custom detectors via TOML (§21 — NEW)

### Storage

- [x] Pattern persistence (§18.1 — patterns table)
- [x] Location persistence (§18.2 — pattern_locations table)
- [x] Variant persistence (§18.3 — pattern_variants table)
- [x] Example persistence (§18.4 — pattern_examples table)
- [x] History tracking (§18.5 — pattern_history table)
- [x] JSON shard files → ELIMINATED (SQLite only)
- [x] Index files → ELIMINATED (SQLite indexes)
- [x] Backup system → drift.db hot backup (02-STORAGE-V2-PREP.md)

### NAPI Interface

- [x] detect_patterns (§19.1 — command function)
- [x] query_patterns (§19.2 — paginated query)
- [x] query_pattern_detail (§19.2 — full detail)
- [x] query_violations (§19.2 — paginated query)
- [x] learn_conventions (§19.1 — command function)
- [x] query_conventions (§19.2 — paginated query)
- [x] register_violation_action (§19.1 — feedback loop)
- [x] query_detector_health (§19.2 — health dashboard)

### New V2 Capabilities (Not in V1)

- [x] Single-pass visitor pattern (§4 — 10-100x performance)
- [x] Generic AST normalization / GAST (§5 — write-once detectors)
- [x] Bayesian confidence with momentum (§9 — convention migration)
- [x] Temporal confidence decay (§9 — stale convention handling)
- [x] Grubbs' test for small samples (§10 — statistical rigor)
- [x] Iterative outlier masking (§10 — hidden outlier detection)
- [x] GraphQL contract detection (§12 — NEW paradigm)
- [x] gRPC/Protobuf contract detection (§12 — NEW paradigm)
- [x] OWASP Top 10 alignment (§17 Cat 12 — 9/10 coverage)
- [x] CWE ID tagging on security findings (§17 Cat 12)
- [x] Fix generation system (§15 — 7 strategies, 3 safety levels)
- [x] Feedback loop / detector health (§16 — Google Tricorder model)
- [x] TOML declarative patterns (§21 — user-extensible)
- [x] Incremental detection (§20 — 3-layer system)
- [x] Contested convention detection (§7 — Bayesian)
- [x] Framework middleware architecture (§13 — composable, extensible)
- [x] Structural pattern matching (§11 — multi-constraint)
- [x] Scan history for momentum (§18.6 — pattern_scan_history)
- [x] Detector health metrics (§18.10 — detector_health table)
- [x] Convention categories (Universal/Emerging/Legacy/Contested) (§7)

### Verification: Zero Feature Loss

| v1 Feature Count | v2 Feature Count | Delta |
|-----------------|-----------------|-------|
| 16 categories | 16 categories | 0 |
| ~173 base detectors | ~173 base detectors | 0 |
| ~519 total variants | ~519 total variants | 0 |
| 7 frameworks | 8 frameworks (+ C++) | +1 |
| 4 scoring factors | 5 scoring factors (+ momentum) | +1 |
| 1 outlier method | 4 outlier methods | +3 |
| 1 contract paradigm (REST) | 3 paradigms (+ GraphQL, gRPC) | +2 |
| 0 fix strategies | 7 fix strategies | +7 |
| 0 feedback tracking | Full feedback loop | NEW |
| 0 custom patterns | TOML declarative patterns | NEW |
| 0 incremental detection | 3-layer incremental | NEW |
| Binary convention learning | Bayesian graduated learning | UPGRADED |

**Result: 100% v1 feature coverage + 14 new capabilities.**

---

## 25. Summary of All Decisions

| Decision | Choice | Confidence | Source |
|----------|--------|------------|--------|
| Detection architecture | Single-pass visitor pattern | Very High | R1, ESLint, Tricorder |
| AST abstraction | Generic AST (GAST) ~30 node types | High | R4, Semgrep ast_generic |
| Confidence scoring | 5-factor Bayesian with momentum | High | R3, R9, Allamanis et al. |
| Outlier detection | Z-Score + Grubbs' + IQR, iterative | High | R6, NIST handbook |
| Convention learning | Beta-Binomial Bayesian, contested detection | High | R9, Naturalize paper |
| Contract detection | REST + GraphQL + gRPC unified model | High | R8 |
| Framework support | Composable middleware architecture | High | R11, ESLint plugins |
| Fix generation | 7 strategies, 3 safety levels | High | R10, Tricorder |
| Feedback loop | Violation action tracking, auto-disable | High | R5, Tricorder |
| Pattern definitions | TOML declarative + Rust programmatic | High | AD3 |
| Incremental detection | 3-layer (file skip, pattern rescore, relearn) | High | R2, CodeQL, SonarQube |
| Security alignment | OWASP Top 10 + CWE ID tagging | High | R7 |
| Storage | drift.db STRICT tables, JSONB, generated columns | Very High | 02-STORAGE-V2-PREP.md |
| NAPI interface | 8 functions (3 command + 5 query) | High | 03-NAPI-BRIDGE-V2-PREP.md |
| Testing framework | Fixtures + annotations + calibration + benchmarks | High | R12 |
| Registry | Compile-time via `inventory` crate | High | Rust ecosystem standard |
| Build timeline | ~20 weeks, 4 phases | Medium-High | R1-R12 implementation order |
