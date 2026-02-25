# Unified Analysis Engine — V2 Implementation Prep

> Comprehensive build specification for Drift v2's Unified Analysis Engine.
> Synthesized from: 06-UNIFIED-ANALYSIS-ENGINE.md (complete v1 audit + v2 architecture),
> DRIFT-V2-FULL-SYSTEM-AUDIT.md (Cat 01-03, 05, AD1-AD12),
> DRIFT-V2-STACK-HIERARCHY.md (Level 1 — Structural Skeleton),
> PLANNING-DRIFT.md (D1-D7),
> 01-PARSERS.md (ParseResult contract),
> 02-STORAGE-V2-PREP.md (batch writer, keyset pagination, medallion architecture),
> 03-NAPI-BRIDGE-V2-PREP.md (command/query pattern, async tasks, cancellation),
> 04-INFRASTRUCTURE.md (thiserror, tracing, DriftEventHandler, FxHashMap, SmallVec, lasso),
> 05-CALL-GRAPH-V2-PREP.md (resolution index consumer contract),
> .research/01-rust-core/RECOMMENDATIONS.md (FA1-FA3, R2-R5, R16-R18),
> .research/03-detectors/RECOMMENDATIONS.md (R1-R12),
> .research/05-analyzers/RECOMMENDATIONS.md (R1-R14),
> and internet research on Salsa, Semgrep GAST, rust-analyzer architecture.
>
> Purpose: Everything needed to build the unified analysis engine from scratch.
> Decisions resolved, inconsistencies flagged, interface contracts defined,
> build order specified. Zero feature loss from v1.
> Generated: 2026-02-07

---

## 1. Architectural Position

The Unified Analysis Engine is Level 1 — Structural Skeleton. It is the core pattern
detection pipeline that feeds into nearly every downstream system. Without it, Drift
can parse files but cannot detect patterns, generate violations, or score confidence.

Per PLANNING-DRIFT.md D1: Drift is standalone. The engine writes to drift.db only.
Per PLANNING-DRIFT.md D5: The engine emits events via DriftEventHandler (no-op defaults).
Per AD4: Single-pass visitor pattern for detection (10-100x performance improvement).
Per AD3: Declarative TOML patterns (user-extensible without recompiling).
Per AD1: Incremental-first (3-layer content-hash skipping).

### What Lives Here
- 4-phase per-file pipeline (AST queries → string extraction → regex → resolution)
- Visitor pattern detection engine (single-pass, all detectors as visitors)
- GAST normalization layer (~30 node types, 10 per-language normalizers)
- Declarative pattern definitions (TOML-based, graduated complexity)
- 4 core analyzers ported from TS (AST, Type, Semantic, Flow)
- Unified Language Provider ported from TS (9 normalizers, 20 ORM matchers)
- 10 per-language framework-aware analyzers ported from TS
- String interning (lasso — ThreadedRodeo/RodeoReader)
- Resolution index (6 strategies, BTreeMap + FxHashMap + SmallVec)
- Incremental computation (content-hash skip + cached results)
- Cancellation support (revision counter pattern)
- Moka parse cache (TinyLFU + LRU, SQLite-backed persistence)

### What Does NOT Live Here
- Detector trait definitions (16 categories × 3 variants) → Detector System
- Pattern aggregation & deduplication → Pattern Intelligence (Level 2A)
- Bayesian confidence scoring → Pattern Intelligence (Level 2A)
- Outlier detection → Pattern Intelligence (Level 2A)
- Call graph builder → Call Graph (Level 1, separate)
- Rules engine orchestration → Enforcement (Level 3)
- Quality gates → Enforcement (Level 3)

### Downstream Consumers

| Consumer | What It Reads | Interface |
|----------|--------------|-----------|
| Detector System | DetectedPattern[], GAST nodes, DetectionContext | DetectorHandler trait |
| Pattern Aggregation | Per-file DetectedPattern[] | Vec<FilePatterns> |
| Confidence Scoring | Pattern frequency/consistency data | PatternStats |
| Call Graph Builder | ResolutionIndex, FunctionEntry[] | ResolutionIndex API |
| Boundary Detection | ORM patterns from Unified Provider | Vec<OrmPattern> |
| DNA System | Per-file convention fingerprints | FilePatterns |
| Taint Analysis | String literals, resolution index | StringLiteral[], ResolutionIndex |
| Context Generation | Pattern summaries | UnifiedResult |

### Upstream Dependencies

| Dependency | What It Provides | Contract |
|-----------|-----------------|----------|
| Parsers (Level 0) | ParseResult | See Section 2 |
| Scanner (Level 0) | ScanResult with ScanDiff | file_path, content_hash, language |
| Storage (Level 0) | DatabaseManager | batch_writer, keyset_pagination |
| String Interning (Level 1) | ThreadedRodeo / RodeoReader | Spur handles |
| Infrastructure (Level 0) | thiserror, tracing, events, config | Error enums, spans, handlers |

---

## 2. Input Contract: ParseResult

The unified analysis engine consumes ParseResult from the parser layer.
This is the exact contract — every field listed here must be available.

```rust
pub struct ParseResult {
    pub file: Spur,                        // Interned file path
    pub language: Language,
    pub tree: Tree,                        // tree-sitter AST (owned)
    pub source: Vec<u8>,                   // Raw source bytes
    pub functions: Vec<FunctionInfo>,
    pub classes: Vec<ClassInfo>,
    pub imports: Vec<ImportInfo>,
    pub exports: Vec<ExportInfo>,
    pub call_sites: Vec<CallSite>,
    pub decorators: Vec<DecoratorInfo>,
    pub string_literals: Vec<StringLiteralInfo>,  // Pre-extracted by parser
    pub numeric_literals: Vec<NumericLiteralInfo>, // For magic number detection
    pub error_handling: Vec<ErrorHandlingInfo>,    // try/catch/finally
    pub doc_comments: Vec<DocCommentInfo>,
    pub parse_time_us: u64,
    pub error_count: u32,                  // tree-sitter ERROR nodes
    pub content_hash: u64,                 // xxhash of source
}
```

### FunctionInfo (from parser)
```rust
pub struct FunctionInfo {
    pub name: Spur,
    pub qualified_name: Option<Spur>,      // "Class.method"
    pub file: Spur,
    pub line: u32,
    pub end_line: u32,
    pub column: u32,
    pub is_exported: bool,
    pub is_async: bool,
    pub is_generator: bool,
    pub visibility: Visibility,            // Public, Private, Protected, Internal
    pub return_type: Option<String>,
    pub parameters: SmallVec<[ParamInfo; 4]>,
    pub decorators: SmallVec<[Spur; 2]>,
    pub generic_params: SmallVec<[String; 2]>,
    pub doc_comment: Option<String>,
    pub body_hash: u64,                    // For function-level incrementality
    pub signature_hash: u64,               // For cross-file invalidation
}
```

### CallSite (from parser)
```rust
pub struct CallSite {
    pub callee_name: Spur,
    pub receiver: Option<Spur>,            // For method calls: obj.method()
    pub file: Spur,
    pub line: u32,
    pub column: u32,
    pub argument_count: u8,
    pub is_await: bool,
}
```

### ImportInfo / ExportInfo (from parser)
```rust
pub struct ImportInfo {
    pub source: String,                    // Module path
    pub specifiers: SmallVec<[ImportSpecifier; 4]>,
    pub is_type_only: bool,
    pub file: Spur,
    pub line: u32,
}

pub struct ExportInfo {
    pub name: Option<Spur>,
    pub is_default: bool,
    pub is_type_only: bool,
    pub source: Option<String>,            // Re-export source
    pub file: Spur,
    pub line: u32,
}
```

---

## 3. Core Data Model

### 3.1 Primary Output: UnifiedResult

```rust
pub struct UnifiedResult {
    /// Per-file detection results
    pub file_patterns: Vec<FilePatterns>,

    /// Cross-file resolution statistics (NOW WIRED UP — v1 was TODO)
    pub resolution: ResolutionStats,

    /// Call graph summary from resolution index
    pub call_graph: CallGraphSummary,

    /// Timing and count metrics
    pub metrics: AnalysisMetrics,

    /// Aggregate counts
    pub total_patterns: u64,
    pub total_violations: u64,

    /// Taint analysis results (NEW)
    pub taint_flows: Vec<TaintFlow>,

    /// Incremental analysis stats (NEW)
    pub skipped_files: u64,
    pub cache_hits: u64,
}
```

### 3.2 Per-File Results: FilePatterns

```rust
pub struct FilePatterns {
    pub file: Spur,
    pub language: Language,
    pub patterns: Vec<DetectedPattern>,
    pub violations: Vec<Violation>,         // NOW POPULATED (v1 gap fixed)
    pub fixes: Vec<Fix>,                    // NEW
    pub parse_time_us: u64,
    pub detect_time_us: u64,               // Phase 1 + 1.5
    pub gast_time_us: u64,                 // NEW: GAST normalization
    pub string_time_us: u64,              // NEW: Phase 2 + 3
    pub resolve_time_us: u64,             // NEW: Phase 4
}
```

### 3.3 Detection Result: DetectedPattern

```rust
pub struct DetectedPattern {
    pub category: PatternCategory,
    pub pattern_type: Spur,                // Interned pattern type string
    pub subcategory: Option<Spur>,
    pub file: Spur,
    pub line: u32,                         // 1-indexed
    pub column: u32,                       // 1-indexed
    pub end_line: u32,
    pub end_column: u32,
    pub matched_text: String,
    pub confidence: f32,                   // 0.0-1.0
    pub detection_method: DetectionMethod,
    pub metadata: Option<FxHashMap<Spur, serde_json::Value>>,
    pub cwe_ids: SmallVec<[u32; 2]>,       // NEW: CWE mapping
    pub owasp: Option<Spur>,              // NEW: OWASP mapping
    pub fix: Option<Fix>,                  // NEW: suggested fix
}
```

### 3.4 Violation (NOW IMPLEMENTED — v1 gap)

```rust
pub struct Violation {
    pub id: String,                        // Unique violation ID
    pub pattern_id: Spur,
    pub severity: ViolationSeverity,       // Error, Warning, Info, Hint
    pub file: Spur,
    pub line: u32,
    pub column: u32,
    pub end_line: u32,
    pub end_column: u32,
    pub message: String,
    pub expected: String,
    pub actual: String,
    pub suggested_fix: Option<Fix>,
    pub cwe_ids: SmallVec<[u32; 2]>,
    pub source: &'static str,             // "drift"
}

pub enum ViolationSeverity {
    Error,
    Warning,
    Info,
    Hint,
}
```

### 3.5 PatternCategory (16 variants)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PatternCategory {
    Api,
    Auth,
    Components,
    Config,
    DataAccess,
    Documentation,
    Errors,
    Logging,
    Performance,
    Security,
    Structural,
    Styling,
    Testing,
    Types,
    Validation,      // PRESERVED from v1 (was at risk of being dropped)
    Accessibility,   // NEW in v2
}
```

### 3.6 Language (10 variants — all preserved)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    TypeScript, JavaScript, Python, Java, CSharp,
    Php, Go, Rust, Cpp, C,
}
```

Extension mapping (all preserved from v1):
ts|tsx|mts|cts → TypeScript, js|jsx|mjs|cjs → JavaScript, py|pyi → Python,
java → Java, cs → CSharp, php → Php, go → Go, rs → Rust,
cpp|cc|cxx|c++|hpp|hxx|hh → Cpp, c|h → C

### 3.7 DetectionMethod (4 variants)

```rust
pub enum DetectionMethod {
    AstQuery,           // Pre-compiled tree-sitter query (Phase 1)
    VisitorPattern,     // Visitor engine detection (Phase 1.5) — NEW
    RegexFallback,      // Regex on extracted strings (Phase 3)
    Structural,         // File/directory pattern analysis
}
```

### 3.8 StringContext (7 variants — all preserved)

```rust
pub enum StringContext {
    FunctionArgument,
    VariableAssignment,
    ObjectProperty,
    Decorator,
    ReturnValue,
    ArrayElement,
    Unknown,
}
```


---

## 4. The 4-Phase Pipeline (Preserved + Expanded)

### Overview

The v1 4-phase per-file pipeline is proven architecture. V2 preserves it and adds
Phase 1.5 (visitor pattern engine) between Phase 1 and Phase 2.

```
File → tree-sitter parse → ParseResult (from parser layer)
  │
  ├─ Phase 1:   Pre-compiled tree-sitter queries (27 queries, 9 languages)
  │             → Vec<DetectedPattern> (confidence 0.85-0.95)
  │
  ├─ Phase 1.5: Visitor pattern engine (NEW)
  │             → Vec<PatternMatch> (complex, stateful, multi-node patterns)
  │
  ├─ Phase 2:   String extraction from AST (strings >3 chars, 7 node kinds)
  │             → Vec<StringLiteral> with StringContext
  │
  ├─ Phase 3:   Regex on extracted strings (33 patterns across 5 sets)
  │             → Vec<DetectedPattern> (confidence 0.80-0.90)
  │
  └─ Phase 4:   Resolution index population
               → FunctionEntry[] inserted into shared ResolutionIndex
```

### Phase 1: AST Pattern Detection

Pre-compiled tree-sitter queries run against the AST. All 27 v1 queries preserved.
Queries compiled once at startup via `AstPatternDetector::new()`.

```rust
pub struct AstPatternDetector {
    /// Per-language compiled queries. Key: Language, Value: compiled queries.
    queries: FxHashMap<Language, Vec<CompiledQuery>>,

    /// TOML-loaded custom queries (merged with hardcoded defaults).
    custom_queries: FxHashMap<Language, Vec<CompiledQuery>>,
}

pub struct CompiledQuery {
    pub query: tree_sitter::Query,
    pub pattern_type: Spur,            // Interned
    pub category: PatternCategory,
    pub confidence: f32,
    pub cwe_ids: SmallVec<[u32; 2]>,   // NEW
    pub owasp: Option<Spur>,           // NEW
    pub source: QuerySource,           // Hardcoded | Toml(path)
}

pub enum QuerySource {
    Hardcoded,
    Toml(PathBuf),
}
```

Detection method:
```rust
fn detect(
    &self,
    tree: &Tree,
    source: &[u8],
    language: Language,
    file: Spur,
) -> Vec<DetectedPattern> {
    let queries = self.queries.get(&language)
        .into_iter()
        .chain(self.custom_queries.get(&language));

    let mut results = Vec::new();
    let mut cursor = QueryCursor::new();

    for compiled in queries.flatten() {
        for match_ in cursor.matches(&compiled.query, tree.root_node(), source) {
            if let Some(capture) = match_.captures.first() {
                let node = capture.node;
                results.push(DetectedPattern {
                    category: compiled.category,
                    pattern_type: compiled.pattern_type,
                    file,
                    line: node.start_position().row as u32 + 1,
                    column: node.start_position().column as u32 + 1,
                    end_line: node.end_position().row as u32 + 1,
                    end_column: node.end_position().column as u32 + 1,
                    matched_text: node.utf8_text(source).unwrap_or("").to_string(),
                    confidence: compiled.confidence,
                    detection_method: DetectionMethod::AstQuery,
                    cwe_ids: compiled.cwe_ids.clone(),
                    owasp: compiled.owasp,
                    ..Default::default()
                });
            }
        }
    }

    results
}
```

### Phase 1.5: Visitor Pattern Engine

See Section 5 for full specification. This phase runs the DetectionEngine with all
registered DetectorHandler implementations. Single-pass AST traversal.

### Phase 2: String Extraction

Walks the AST recursively looking for string literal nodes. Node kinds vary by language
(all 7 mappings preserved from v1). Strings < 4 chars discarded. Quotes stripped.

```rust
pub struct StringExtractor;

impl StringExtractor {
    pub fn extract(
        tree: &Tree,
        source: &[u8],
        language: Language,
        file: Spur,
    ) -> Vec<StringLiteral> {
        let string_kinds = Self::string_node_kinds(language);
        let mut results = Vec::new();
        Self::walk_recursive(tree.root_node(), source, &string_kinds, file, &mut results);
        results
    }

    fn string_node_kinds(language: Language) -> &'static [&'static str] {
        match language {
            Language::TypeScript | Language::JavaScript => &["string", "template_string"],
            Language::Python => &["string", "concatenated_string"],
            Language::Java | Language::CSharp => &["string_literal"],
            Language::Php => &["string", "encapsed_string"],
            Language::Go => &["interpreted_string_literal", "raw_string_literal"],
            Language::Rust => &["string_literal", "raw_string_literal"],
            Language::Cpp | Language::C => &["string_literal", "raw_string_literal"],
        }
    }

    fn determine_context(parent: Option<Node>) -> StringContext {
        match parent.map(|p| p.kind()) {
            Some("arguments" | "argument_list" | "call_expression") => StringContext::FunctionArgument,
            Some("variable_declarator" | "assignment_expression" | "assignment") => StringContext::VariableAssignment,
            Some("pair" | "property" | "key_value_pair") => StringContext::ObjectProperty,
            Some("decorator" | "annotation" | "attribute") => StringContext::Decorator,
            Some("return_statement") => StringContext::ReturnValue,
            Some("array" | "list" | "array_expression") => StringContext::ArrayElement,
            _ => StringContext::Unknown,
        }
    }
}
```

### Phase 3: String Literal Analysis

Regex applied ONLY to pre-extracted string literals, never to raw source code.
Uses `RegexSet` for efficient multi-pattern matching.

```rust
pub struct StringLiteralAnalyzer {
    sql_patterns: RegexSet,        // 9 patterns → DataAccess, 0.9
    route_patterns: RegexSet,      // 6 patterns → Api, 0.85
    sensitive_patterns: RegexSet,  // 8 patterns → Security, 0.8
    env_patterns: RegexSet,        // 6 patterns → Config, 0.85
    log_patterns: RegexSet,        // 4 patterns → Logging, 0.85 (NOW WIRED — v1 gap)
}

impl StringLiteralAnalyzer {
    pub fn analyze(
        &self,
        strings: &[StringLiteral],
        file: Spur,
    ) -> Vec<DetectedPattern> {
        let mut results = Vec::new();

        for string in strings {
            // Check each pattern set
            if self.sql_patterns.is_match(&string.value) {
                results.push(Self::make_pattern(string, file, PatternCategory::DataAccess, "sql-query", 0.9));
            }
            if self.route_patterns.is_match(&string.value) {
                results.push(Self::make_pattern(string, file, PatternCategory::Api, "route-path", 0.85));
            }
            if self.sensitive_patterns.is_match(&string.value) {
                results.push(Self::make_pattern(string, file, PatternCategory::Security, "sensitive-data", 0.8));
            }
            if self.env_patterns.is_match(&string.value) {
                results.push(Self::make_pattern(string, file, PatternCategory::Config, "env-reference", 0.85));
            }
            // NEW: Log patterns now wired (v1 compiled but never used)
            if self.log_patterns.is_match(&string.value) {
                results.push(Self::make_pattern(string, file, PatternCategory::Logging, "log-call", 0.85));
            }
        }

        results
    }
}
```

### Phase 4: Resolution Index Population

Every function discovered during parsing is inserted into the shared ResolutionIndex.
This enables cross-file call resolution without a separate build phase.

```rust
impl ResolutionIndex {
    pub fn insert_from_parse_result(
        &mut self,
        parse_result: &ParseResult,
    ) {
        for func in &parse_result.functions {
            let id = FunctionId(self.next_id.fetch_add(1, Ordering::Relaxed));
            let entry = FunctionEntry {
                id,
                name: func.name,
                qualified_name: func.qualified_name,
                file: parse_result.file,
                line: func.line,
                end_line: func.end_line,
                is_exported: func.is_exported,
                is_async: func.is_async,
                is_entry_point: Self::detect_entry_point(func, parse_result),
                is_data_accessor: false, // Set later by boundary detection
                body_hash: func.body_hash,
                signature_hash: func.signature_hash,
                decorators: func.decorators.clone(),
                parameters: func.parameters.clone(),
            };

            // Index by name
            self.name_index
                .entry(func.name)
                .or_insert_with(SmallVec::new)
                .push(id);

            // Index by file
            self.file_index
                .entry(parse_result.file)
                .or_default()
                .push(id);

            // Store entry
            self.entries.insert(id, entry);
        }
    }
}
```

---

## 5. Visitor Pattern Detection Engine

### The Core Problem

V1: O(files × detectors × AST_nodes) — 100+ traversals per file.
V2: O(files × AST_nodes × handlers_per_node) — 1 traversal per file.

### DetectorHandler Trait

```rust
/// Every detector implements this. The engine calls on_enter/on_exit
/// during a single depth-first traversal.
pub trait DetectorHandler: Send + Sync {
    /// Unique identifier for this detector.
    fn id(&self) -> &str;

    /// Which AST node types this handler wants to visit.
    fn node_types(&self) -> &[&str];

    /// Which languages this handler applies to.
    fn languages(&self) -> &[Language];

    /// Called when entering a node of a registered type.
    fn on_enter(&mut self, node: &Node, ctx: &DetectionContext);

    /// Called when leaving a node of a registered type.
    fn on_exit(&mut self, node: &Node, ctx: &DetectionContext);

    /// Collect results after traversal completes.
    fn results(&self) -> Vec<PatternMatch>;

    /// Reset state for next file.
    fn reset(&mut self);

    /// Optional: generate fix for a violation.
    fn generate_fix(&self, violation: &Violation, ctx: &DetectionContext) -> Option<Fix> {
        None
    }

    /// Fix coverage percentage (0.0-1.0).
    fn fix_coverage(&self) -> f64 { 0.0 }
}
```

### FileDetectorHandler (Full-File Context)

```rust
/// For detectors that need full-file context, not per-node.
pub trait FileDetectorHandler: Send + Sync {
    fn id(&self) -> &str;
    fn languages(&self) -> &[Language];
    fn analyze_file(
        &mut self,
        tree: &Tree,
        source: &[u8],
        ctx: &DetectionContext,
    ) -> Result<Vec<PatternMatch>, AnalysisError>;
}
```

### LearningDetectorHandler (Two-Pass)

```rust
/// Learning detectors: learn conventions first, then detect deviations.
pub trait LearningDetectorHandler: DetectorHandler {
    /// Phase 1: Learn from a file during the learning pass.
    fn learn(&mut self, tree: &Tree, source: &[u8], ctx: &DetectionContext);

    /// Phase 2: Finalize learned conventions after all files processed.
    fn finalize_learning(&mut self);

    /// Phase 3: on_enter/on_exit from DetectorHandler run during detect pass.
}
```

### DetectionEngine

```rust
pub struct DetectionEngine {
    /// Node type → handlers interested in that type.
    node_handlers: FxHashMap<String, Vec<usize>>,  // indices into handlers vec

    /// All registered handlers.
    handlers: Vec<Box<dyn DetectorHandler>>,

    /// File-level handlers.
    file_handlers: Vec<Box<dyn FileDetectorHandler>>,

    /// Learning handlers (run learn pass before detect pass).
    learning_handlers: Vec<Box<dyn LearningDetectorHandler>>,
}

impl DetectionEngine {
    pub fn register(&mut self, handler: Box<dyn DetectorHandler>) {
        let idx = self.handlers.len();
        for node_type in handler.node_types() {
            self.node_handlers
                .entry(node_type.to_string())
                .or_default()
                .push(idx);
        }
        self.handlers.push(handler);
    }

    /// Single-pass traversal dispatching to all registered handlers.
    pub fn analyze(
        &mut self,
        tree: &Tree,
        source: &[u8],
        ctx: &DetectionContext,
        cancel: &CancellationToken,
    ) -> Result<Vec<PatternMatch>, AnalysisError> {
        cancel.check()?;

        // Reset all handlers for this file
        for handler in &mut self.handlers {
            handler.reset();
        }

        // Depth-first traversal
        let mut cursor = tree.walk();
        self.traverse(&mut cursor, source, ctx, cancel)?;

        // Collect results
        let mut results = Vec::new();
        for handler in &self.handlers {
            results.extend(handler.results());
        }

        // Run file-level handlers
        for handler in &mut self.file_handlers {
            cancel.check()?;
            results.extend(handler.analyze_file(tree, source, ctx)?);
        }

        Ok(results)
    }

    fn traverse(
        &mut self,
        cursor: &mut TreeCursor,
        source: &[u8],
        ctx: &DetectionContext,
        cancel: &CancellationToken,
    ) -> Result<(), AnalysisError> {
        let node = cursor.node();
        let kind = node.kind();

        // Dispatch on_enter
        if let Some(indices) = self.node_handlers.get(kind) {
            for &idx in indices {
                self.handlers[idx].on_enter(&node, ctx);
            }
        }

        // Recurse children
        if cursor.goto_first_child() {
            loop {
                // Check cancellation every N nodes (not every node — too expensive)
                if node.id() % 1024 == 0 {
                    cancel.check()?;
                }
                self.traverse(cursor, source, ctx, cancel)?;
                if !cursor.goto_next_sibling() { break; }
            }
            cursor.goto_parent();
        }

        // Dispatch on_exit
        if let Some(indices) = self.node_handlers.get(kind) {
            for &idx in indices {
                self.handlers[idx].on_exit(&node, ctx);
            }
        }

        Ok(())
    }
}
```

### DetectionContext

```rust
pub struct DetectionContext<'a> {
    pub file: Spur,
    pub language: Language,
    pub source: &'a [u8],
    pub imports: &'a [ImportInfo],
    pub exports: &'a [ExportInfo],
    pub functions: &'a [FunctionInfo],
    pub classes: &'a [ClassInfo],
    pub project_context: &'a ProjectContext,
    pub framework_context: &'a FrameworkContext,
    pub interner: &'a RodeoReader,
}

pub struct ProjectContext {
    pub root: PathBuf,
    pub detected_frameworks: Vec<FrameworkInfo>,
    pub package_manager: Option<PackageManager>,
    pub language_distribution: FxHashMap<Language, u64>,
}

pub struct FrameworkContext {
    pub frameworks: Vec<FrameworkInfo>,
    pub orm: Option<OrmType>,
    pub test_framework: Option<TestFramework>,
    pub web_framework: Option<WebFramework>,
}
```

---

## 6. Resolution Index (6 Strategies)

### Updated Data Structure

```rust
pub struct ResolutionIndex {
    /// Name → function IDs. BTreeMap for ordered lookups + prefix search.
    name_index: BTreeMap<Spur, SmallVec<[FunctionId; 4]>>,

    /// Function ID → full entry. FxHashMap for O(1) lookup.
    entries: FxHashMap<FunctionId, FunctionEntry>,

    /// File → function IDs. For file-level queries.
    file_index: FxHashMap<Spur, Vec<FunctionId>>,

    /// Import source → resolved targets. NEW: for import-based resolution.
    import_index: FxHashMap<Spur, Vec<ImportResolution>>,

    /// Class name → class info. NEW: for method call resolution via MRO.
    class_hierarchy: FxHashMap<Spur, ClassHierarchyEntry>,

    /// String interner (shared, read-only during resolution).
    interner: Arc<RodeoReader>,

    /// Next function ID.
    next_id: AtomicU32,
}
```

### 6 Resolution Strategies

```rust
pub fn resolve(
    &self,
    name: Spur,
    caller_file: Spur,
    receiver: Option<Spur>,
    call_site: &CallSite,
) -> Resolution {
    let candidates = match self.name_index.get(&name) {
        Some(ids) if !ids.is_empty() => ids,
        _ => return Resolution::Unresolved,
    };

    // Strategy 1: Same-file (High confidence)
    if let Some(id) = candidates.iter().find(|id| {
        self.entries.get(id).map_or(false, |e| e.file == caller_file)
    }) {
        return Resolution::Resolved(self.to_resolved(*id), Confidence::High);
    }

    // Strategy 2: Method call via class hierarchy MRO (High confidence)
    if let Some(recv) = receiver {
        if let Some(resolved) = self.resolve_method_call(recv, name) {
            return Resolution::Resolved(resolved, Confidence::High);
        }
    }

    // Strategy 3: DI injection (Medium-High confidence)
    if let Some(resolved) = self.resolve_di_injection(name, caller_file) {
        return Resolution::Resolved(resolved, Confidence::MediumHigh);
    }

    // Strategy 4: Import-based (Medium confidence)
    if let Some(resolved) = self.resolve_via_imports(name, caller_file) {
        return Resolution::Resolved(resolved, Confidence::Medium);
    }

    // Strategy 5: Export-based (Medium confidence)
    let exported: SmallVec<[FunctionId; 4]> = candidates.iter()
        .filter(|id| self.entries.get(id).map_or(false, |e| e.is_exported))
        .copied()
        .collect();

    if exported.len() == 1 {
        return Resolution::Resolved(self.to_resolved(exported[0]), Confidence::Medium);
    }

    // Strategy 6: Fuzzy name matching (Low confidence)
    if let Some(resolved) = self.resolve_fuzzy(name) {
        return Resolution::Resolved(resolved, Confidence::Low);
    }

    // Multiple candidates, none resolved
    if candidates.len() > 1 {
        Resolution::Ambiguous(candidates.iter().map(|id| self.to_resolved(*id)).collect())
    } else {
        Resolution::Unresolved
    }
}

pub enum Resolution {
    Resolved(ResolvedFunction, Confidence),
    Ambiguous(Vec<ResolvedFunction>),
    Unresolved,
}

pub enum Confidence {
    High,        // Same-file, method call
    MediumHigh,  // DI injection
    Medium,      // Import-based, export-based
    Low,         // Fuzzy matching
}
```

### Method Call Resolution via MRO (Strategy 2)

Following PyCG's approach — resolve method calls via class hierarchy Method Resolution Order.

```rust
fn resolve_method_call(&self, receiver: Spur, method: Spur) -> Option<ResolvedFunction> {
    // 1. Look up receiver in class_hierarchy
    let class = self.class_hierarchy.get(&receiver)?;

    // 2. Walk MRO chain: class → parent → grandparent → ...
    let mut current = Some(class);
    while let Some(cls) = current {
        // Check if this class has the method
        if let Some(method_id) = cls.methods.get(&method) {
            return Some(self.to_resolved(*method_id));
        }
        // Walk to parent
        current = cls.parent.and_then(|p| self.class_hierarchy.get(&p));
    }

    None
}
```

### ResolutionStats (NOW TRACKED — v1 gap fixed)

```rust
pub struct ResolutionStats {
    pub total_calls: u64,
    pub resolved_calls: u64,
    pub resolution_rate: f32,
    pub same_file_resolutions: u64,
    pub method_call_resolutions: u64,
    pub di_resolutions: u64,
    pub import_resolutions: u64,
    pub export_resolutions: u64,
    pub fuzzy_resolutions: u64,
    pub unresolved_calls: u64,
    pub ambiguous_calls: u64,
}
```

All fields are incremented during resolution. `resolution_rate` computed as
`resolved_calls as f32 / total_calls as f32`. Target: 60-85%.


---

## 7. GAST Normalization Layer

### The Problem

V1 has 27 AST queries across 9 languages and 350+ detector files in TypeScript.
Many detectors are language-specific variants of the same concept — try-catch detection
exists separately for JS, Python, Java, Go, Rust, and C++. Adding a new language
requires writing 100+ new detectors.

### The Solution

A Generic AST (GAST) normalization layer between tree-sitter parsing and detection,
inspired by Semgrep's `ast_generic`. Language-specific CSTs are normalized into a
universal ~30-node-type representation. Detectors written against GAST work for
all languages automatically.

```
Source Code → tree-sitter → Language-Specific CST → GASTNormalizer → GAST → Detectors
```

### ~30 Normalized Node Types

```rust
/// Generic AST node types covering ~80% of detection needs.
/// Language-specific detectors kept for truly unique patterns.
pub enum GASTNode {
    // ── Declarations ──────────────────────────────────────────────
    Function {
        name: String,
        params: Vec<Param>,
        body: Block,
        return_type: Option<TypeRef>,
        is_async: bool,
        is_generator: bool,
        decorators: Vec<Decorator>,
        visibility: Visibility,
        doc_comment: Option<String>,
    },
    Class {
        name: String,
        extends: Option<String>,
        implements: Vec<String>,
        members: Vec<ClassMember>,
        decorators: Vec<Decorator>,
        is_abstract: bool,
    },
    Interface {
        name: String,
        extends: Vec<String>,
        members: Vec<InterfaceMember>,
    },
    Enum {
        name: String,
        variants: Vec<EnumVariant>,
    },

    // ── Control Flow ──────────────────────────────────────────────
    TryCatch {
        try_block: Block,
        catch_clauses: Vec<CatchClause>,
        finally_block: Option<Block>,
    },
    IfElse {
        condition: Expr,
        then_block: Block,
        else_block: Option<Block>,
    },
    Loop {
        kind: LoopKind,  // For, ForIn, ForOf, While, DoWhile
        condition: Option<Expr>,
        body: Block,
        variable: Option<String>,
    },
    Switch {
        discriminant: Expr,
        cases: Vec<SwitchCase>,
    },

    // ── Expressions ───────────────────────────────────────────────
    Call {
        callee: Expr,
        args: Vec<Expr>,
        is_await: bool,
        type_args: Vec<TypeRef>,
    },
    MethodCall {
        receiver: Expr,
        method: String,
        args: Vec<Expr>,
        is_await: bool,
    },
    Assignment {
        target: Expr,
        value: Expr,
        operator: AssignOp,
    },
    BinaryOp {
        left: Expr,
        right: Expr,
        operator: BinOp,
    },

    // ── Module System ─────────────────────────────────────────────
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

    // ── Data ──────────────────────────────────────────────────────
    StringLiteral { value: String, context: StringContext },
    NumberLiteral { value: f64, raw: String },
    TemplateLiteral { parts: Vec<TemplatePart> },
    ObjectLiteral { properties: Vec<Property> },
    ArrayLiteral { elements: Vec<Expr> },

    // ── Framework-Aware ───────────────────────────────────────────
    Route {
        method: HttpMethod,
        path: String,
        handler: Expr,
        middleware: Vec<Expr>,
    },
    Decorator {
        name: String,
        args: Vec<Expr>,
        target: DecoratorTarget,
    },
    TypeAnnotation {
        kind: TypeKind,
        text: String,
        is_optional: bool,
    },

    // ── Statements ────────────────────────────────────────────────
    Return { value: Option<Expr> },
    Throw { value: Expr },
    VariableDecl {
        name: String,
        kind: VarKind,  // Const, Let, Var, Val, Final
        type_annotation: Option<TypeRef>,
        initializer: Option<Expr>,
    },

    // ── Block ─────────────────────────────────────────────────────
    Block { statements: Vec<GASTNode> },
}
```

### Supporting Types

```rust
pub enum LoopKind { For, ForIn, ForOf, While, DoWhile }
pub enum VarKind { Const, Let, Var, Val, Final }
pub enum HttpMethod { Get, Post, Put, Patch, Delete, All, Options, Head }
pub enum DecoratorTarget { Class, Method, Property, Parameter }
pub enum AssignOp { Assign, AddAssign, SubAssign, MulAssign, DivAssign, ModAssign }
pub enum BinOp { Add, Sub, Mul, Div, Mod, Eq, Neq, Lt, Gt, Lte, Gte, And, Or }

pub struct Param {
    pub name: String,
    pub type_annotation: Option<TypeRef>,
    pub default_value: Option<Expr>,
    pub is_rest: bool,
}

pub struct CatchClause {
    pub param: Option<String>,
    pub param_type: Option<TypeRef>,
    pub body: Block,
}

pub struct SwitchCase {
    pub test: Option<Expr>,  // None = default case
    pub body: Block,
}

pub struct ClassMember {
    pub kind: ClassMemberKind,
    pub name: String,
    pub visibility: Visibility,
    pub is_static: bool,
    pub is_abstract: bool,
}

pub enum ClassMemberKind {
    Method(Box<GASTNode>),   // Function node
    Property(Option<TypeRef>, Option<Expr>),
    Constructor(Box<GASTNode>),
}
```

### GASTNormalizer Trait

```rust
/// Each language implements this trait to convert its tree-sitter CST
/// into the generic GAST representation.
pub trait GASTNormalizer: Send + Sync {
    /// Which language this normalizer handles.
    fn language(&self) -> Language;

    /// Convert a tree-sitter tree + source into GAST nodes.
    fn normalize(&self, tree: &Tree, source: &[u8]) -> Vec<GASTNode>;

    /// Optional: report normalization coverage (what % of AST nodes mapped).
    fn coverage(&self) -> f32 { 0.0 }
}
```

### 10 Per-Language Normalizers

| Normalizer | Language | Priority | Estimated LOC |
|-----------|----------|----------|---------------|
| TypeScriptNormalizer | TypeScript | P0 (Week 5) | ~800 |
| JavaScriptNormalizer | JavaScript | P0 (Week 5) | ~400 (shares TS base) |
| PythonNormalizer | Python | P0 (Week 6) | ~700 |
| JavaNormalizer | Java | P1 (Week 6) | ~600 |
| GoNormalizer | Go | P1 (Week 7) | ~500 |
| RustNormalizer | Rust | P1 (Week 7) | ~500 |
| CSharpNormalizer | C# | P2 (Week 7) | ~500 |
| PhpNormalizer | PHP | P2 (Week 8) | ~500 |
| CppNormalizer | C++ | P2 (Week 8) | ~600 |
| CNormalizer | C | P2 (Week 8) | ~400 |

### What Stays Language-Specific (NOT Normalized)

Some patterns are truly language-unique and bypass GAST:
- PHP 8 attributes (unique syntax)
- Rust lifetimes and ownership patterns
- Go goroutines and channels
- C++ templates and RAII patterns
- Python complex decorator argument patterns
- WPF/XAML bindings

These keep dedicated language-specific detectors via `FileDetectorHandler`.

### Reduction Impact

GAST reduces the detector codebase by 50-70%. Instead of 6 separate try-catch
detectors (JS, Python, Java, Go, Rust, C++), one GAST-based TryCatch detector
handles all languages. Same for route detection, error handling, import analysis.

---

## 8. Declarative Pattern Definitions (TOML)

### Architecture Decision AD3

Ship with hardcoded defaults (all v1 patterns compiled into binary). Users add
custom patterns via TOML without recompiling. Tree-sitter query syntax as the
pattern language for AST patterns; regex for string patterns.

### TOML Format — Graduated Complexity (4 Levels)

#### Level 1: Simple Node Match
```toml
[[patterns]]
id = "express-route"
language = "typescript"
category = "Api"
confidence = 0.90
query = '''
(call_expression
  function: (member_expression
    property: (property_identifier) @method
    (#match? @method "^(get|post|put|patch|delete|all)$"))
  arguments: (arguments (string) @path))
'''
```

#### Level 2: Structural Parent-Child
```toml
[[patterns]]
id = "spring-security"
language = "java"
category = "Auth"
confidence = 0.95
query = '''
(annotation
  name: (identifier) @name
  (#match? @name "^(PreAuthorize|Secured|RolesAllowed|PermitAll|DenyAll)$"))
'''
```

#### Level 3: Predicate Matching
```toml
[[patterns]]
id = "fastapi-depends-auth"
language = "python"
category = "Auth"
confidence = 0.90
query = '''
(call
  function: (identifier) @func (#eq? @func "Depends")
  arguments: (argument_list
    (identifier) @dep (#match? @dep "auth|protect|guard|verify")))
'''
```

#### Level 4: Cross-Reference Constraints
```toml
[[patterns]]
id = "unprotected-route"
language = "typescript"
category = "Security"
confidence = 0.85
query = '''
(call_expression
  function: (member_expression
    property: (property_identifier) @method
    (#match? @method "^(get|post|put|patch|delete)$")))
'''
requires_absence = "auth-decorator"  # Flag if no auth decorator in same scope
```

### String Pattern TOML Format

```toml
[[string_patterns]]
id = "sql-select"
category = "DataAccess"
confidence = 0.9
regex = '(?i)SELECT\s+.+\s+FROM\s+\w+'

[[string_patterns]]
id = "route-api-path"
category = "Api"
confidence = 0.85
regex = '^/api/v?\d*/'
```

### Pattern Metadata (Every Pattern Carries)

```toml
[[patterns]]
id = "unique-pattern-id"
language = "typescript"           # or "any" for GAST patterns
category = "Auth"                 # one of 16 PatternCategory variants
confidence = 0.95                 # 0.0-1.0
severity = "error"                # error|warning|info|hint (optional, default from category)
description = "Human-readable description"
cwe_ids = [287]                   # CWE mapping for security patterns
owasp = "A01:2021"               # OWASP mapping (optional)
fix_suggestion = "Add @Auth decorator"  # Optional fix hint
tags = ["framework:spring", "security"]  # Searchable tags
enabled = true                    # Can be disabled without removing
```

### Loading Strategy

```rust
pub struct PatternLoader {
    /// Hardcoded defaults (compiled into binary).
    defaults: Vec<CompiledPattern>,

    /// Project-level custom patterns.
    project_patterns: Vec<CompiledPattern>,

    /// User-level custom patterns.
    user_patterns: Vec<CompiledPattern>,
}

impl PatternLoader {
    /// Load order:
    /// 1. Hardcoded defaults (all v1 patterns)
    /// 2. Project-level TOML from `.drift/patterns/*.toml`
    /// 3. User-level TOML from `~/.drift/patterns/*.toml`
    /// Merge: user overrides project overrides defaults (by pattern id).
    /// Compile all tree-sitter queries at startup (fail fast on invalid).
    pub fn load(
        project_root: &Path,
        user_home: &Path,
    ) -> Result<Self, PatternLoadError> {
        let defaults = Self::load_hardcoded_defaults();
        let project = Self::load_toml_dir(project_root.join(".drift/patterns"))?;
        let user = Self::load_toml_dir(user_home.join(".drift/patterns"))?;

        // Merge: later entries override earlier by id
        let mut merged = FxHashMap::default();
        for p in defaults.into_iter().chain(project).chain(user) {
            merged.insert(p.id.clone(), p);
        }

        Ok(Self {
            defaults: Vec::new(), // originals kept for reset
            project_patterns: Vec::new(),
            user_patterns: merged.into_values().collect(),
        })
    }

    fn load_toml_dir(dir: PathBuf) -> Result<Vec<CompiledPattern>, PatternLoadError> {
        if !dir.exists() { return Ok(Vec::new()); }
        let mut patterns = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            if entry.path().extension() == Some("toml".as_ref()) {
                let content = std::fs::read_to_string(entry.path())?;
                let parsed: PatternFile = toml::from_str(&content)?;
                for p in parsed.patterns {
                    patterns.push(Self::compile_pattern(p)?);
                }
                for sp in parsed.string_patterns {
                    patterns.push(Self::compile_string_pattern(sp)?);
                }
            }
        }
        Ok(patterns)
    }
}
```

### Validation at Load Time

All tree-sitter queries are compiled at startup. Invalid queries produce
`PatternLoadError::InvalidQuery { id, language, error }` and are logged
at `warn!` level but do not prevent startup. Invalid patterns are skipped.

---

## 9. Incremental Computation

### Three-Layer Incrementality (AD1)

#### Layer 1 — File-Level Skip (Content Hash)

```
if file.content_hash == cached.content_hash:
    reuse cached detection results for this file
    skip all 4 phases entirely
```

Two-level change detection:
- Level 1: mtime comparison (instant, catches most changes)
- Level 2: content hash via xxhash (catches mtime-only changes from git operations)

Storage: `detection_cache` table in drift.db stores
`(file_path, content_hash, language, patterns_json, violations_json, resolution_entries_json, analyzed_at)`.

```rust
pub struct IncrementalAnalyzer {
    cache: ParseCache,
    db: Arc<DatabaseManager>,
}

impl IncrementalAnalyzer {
    /// Determine which files need re-analysis.
    pub fn partition_files(
        &self,
        files: &[ScanEntry],
    ) -> (Vec<ScanEntry>, Vec<CachedResult>) {
        let mut needs_analysis = Vec::new();
        let mut cached = Vec::new();

        for file in files {
            match self.db.get_detection_cache(file.path, file.content_hash) {
                Some(result) => cached.push(result),
                None => needs_analysis.push(file.clone()),
            }
        }

        (needs_analysis, cached)
    }

    /// After analysis, store results for future incremental runs.
    pub fn cache_results(
        &self,
        results: &[FilePatterns],
    ) -> Result<(), StorageError> {
        self.db.batch_upsert_detection_cache(results)
    }
}
```

#### Layer 2 — Pattern-Level Re-Scoring

```
When files change:
    Re-detect only changed files
    Query: SELECT DISTINCT pattern_id FROM pattern_locations WHERE file IN (changed_files)
    Re-aggregate only those patterns
    Re-score only affected patterns
    Keep all other pattern scores unchanged
```

#### Layer 3 — Convention Re-Learning (Threshold-Based)

```
Track convention stability across scans:
    if changed_files / total_files < 0.10:
        skip re-learning, reuse conventions
    elif changed_files / total_files < 0.30:
        incremental re-learning (update distributions with delta)
    else:
        full re-learning
```

### Function-Body Isolation

Following rust-analyzer's invariant: "typing inside a function body never invalidates
global derived data." Achieved via `body_hash` and `signature_hash` on FunctionEntry.

When only a function body changes (signature_hash unchanged):
- Only that function's local analysis is invalidated
- Cross-file analysis (call graph, coupling) is preserved
- Resolution index entries for that function are NOT invalidated

When a function signature changes (signature_hash changed):
- All callers of that function are invalidated
- Resolution index entries are updated
- Cross-file analysis is re-run for affected call chains

### Cancellation Token (Revision Counter Pattern)

```rust
use std::sync::atomic::{AtomicU64, Ordering};

/// Global revision counter. Incremented when any input changes.
static REVISION: AtomicU64 = AtomicU64::new(0);

pub struct CancellationToken {
    revision_at_start: u64,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self { revision_at_start: REVISION.load(Ordering::SeqCst) }
    }

    pub fn check(&self) -> Result<(), AnalysisError> {
        if REVISION.load(Ordering::SeqCst) != self.revision_at_start {
            Err(AnalysisError::Cancelled {
                revision: self.revision_at_start,
            })
        } else {
            Ok(())
        }
    }
}

/// Increment when any input changes (file edit, config change, etc.)
pub fn bump_revision() {
    REVISION.fetch_add(1, Ordering::SeqCst);
}
```

Insertion points for `cancel.check()?`:
- Between pipeline phases (Phase 1 → 1.5 → 2 → 3 → 4)
- Between files in parallel scan (every N files via rayon)
- At loop boundaries in visitor traversal (every 1024 nodes)
- Caught at NAPI boundary → returns `napi::Error` to TypeScript

### Moka Parse Cache

Content-addressed parse cache using Moka (TinyLFU + LRU eviction):

```rust
use moka::sync::Cache;

pub struct ParseCache {
    /// (interned_path, content_hash) → full ParseResult
    cache: Cache<(Spur, u64), Arc<ParseResult>>,
}

impl ParseCache {
    pub fn new(capacity: u64) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(capacity)  // 10_000 entries default
                .time_to_idle(std::time::Duration::from_secs(3600))
                .build(),
        }
    }

    pub fn get(&self, path: Spur, hash: u64) -> Option<Arc<ParseResult>> {
        self.cache.get(&(path, hash))
    }

    pub fn insert(&self, path: Spur, hash: u64, result: Arc<ParseResult>) {
        self.cache.insert((path, hash), result);
    }

    /// Persist cache to SQLite blob column for cross-restart durability.
    pub fn persist(&self, db: &DatabaseManager) -> Result<(), StorageError> {
        for (key, value) in self.cache.iter() {
            let bytes = bincode::serialize(value.as_ref())?;
            db.upsert_parse_cache(key.0, key.1, &bytes)?;
        }
        Ok(())
    }

    /// Restore cache from SQLite on startup.
    pub fn restore(&self, db: &DatabaseManager) -> Result<u64, StorageError> {
        let mut count = 0u64;
        for row in db.iter_parse_cache()? {
            let result: ParseResult = bincode::deserialize(&row.data)?;
            self.cache.insert((row.path, row.hash), Arc::new(result));
            count += 1;
        }
        Ok(count)
    }
}
```


---

## 10. Core Analyzers in Rust

V1 has 4 core analyzers totaling ~5,350 lines of TypeScript. All move to Rust in v2.
Every method and capability is preserved. Per-language extensibility added via traits.

### 10.1 AST Analyzer (~800 lines TS → Rust)

```rust
pub struct AstAnalyzer {
    interner: Arc<RodeoReader>,
}

impl AstAnalyzer {
    /// Structural pattern matching against tree-sitter AST.
    /// Preserves v1 findPattern() — now uses tree-sitter queries internally.
    pub fn find_pattern(
        &self,
        tree: &Tree,
        source: &[u8],
        pattern: &AstPattern,
    ) -> Vec<PatternMatch> { /* ... */ }

    /// Subtree similarity scoring (0.0-1.0).
    /// Preserves v1 compareSubtrees().
    pub fn compare_subtrees(
        &self,
        node1: &Node,
        node2: &Node,
        source: &[u8],
        options: &CompareOptions,
    ) -> SubtreeComparison { /* ... */ }

    /// Node count, depth, leaf count, type distribution.
    /// Preserves v1 getStats().
    pub fn get_stats(&self, tree: &Tree) -> AstStats { /* ... */ }

    /// Walk AST with visitor callback.
    /// Preserves v1 traverse() — now integrated with visitor engine.
    pub fn traverse<V: AstVisitor>(
        &self,
        tree: &Tree,
        source: &[u8],
        visitor: &mut V,
    ) { /* ... */ }

    /// Find all nodes of a given type.
    /// Preserves v1 findNodesByType().
    pub fn find_nodes_by_type<'a>(
        &self,
        tree: &'a Tree,
        node_type: &str,
    ) -> Vec<Node<'a>> { /* ... */ }

    /// Find node at cursor position (LSP needs this).
    /// Preserves v1 findNodeAtPosition().
    pub fn find_node_at_position<'a>(
        &self,
        tree: &'a Tree,
        line: u32,
        column: u32,
    ) -> Option<Node<'a>> { /* ... */ }

    /// All descendants of a node.
    /// Preserves v1 getDescendants().
    pub fn get_descendants<'a>(&self, node: Node<'a>) -> Vec<Node<'a>> { /* ... */ }

    /// Depth of a node in the tree.
    /// Preserves v1 getNodeDepth().
    pub fn get_node_depth(&self, tree: &Tree, node: &Node) -> u32 { /* ... */ }

    /// Ancestors from root to node.
    /// Preserves v1 getParentChain().
    pub fn get_parent_chain<'a>(&self, node: Node<'a>) -> Vec<Node<'a>> { /* ... */ }

    /// Run multiple patterns, return matches with confidence.
    /// Preserves v1 analyze().
    pub fn analyze(
        &self,
        tree: &Tree,
        source: &[u8],
        patterns: &[AstPattern],
    ) -> Vec<PatternMatch> { /* ... */ }
}
```

#### AstPattern (Rust equivalent of v1 interface)

```rust
pub struct AstPattern {
    pub node_type: String,                          // Required tree-sitter node type
    pub text: Option<TextMatch>,                    // Text content match
    pub children: Option<Vec<AstPattern>>,          // Child pattern requirements
    pub min_children: Option<usize>,
    pub max_children: Option<usize>,
    pub has_child: Option<String>,                  // Must have child of this type
    pub not_has_child: Option<String>,              // Must NOT have child of this type
    pub depth: Option<u32>,                         // Expected depth
    pub metadata: Option<FxHashMap<String, serde_json::Value>>,
}

pub enum TextMatch {
    Exact(String),
    Regex(regex::Regex),
}

pub struct SubtreeComparison {
    pub similarity: f32,           // 0.0-1.0
    pub differences: Vec<AstDiff>,
    pub is_equivalent: bool,
}

pub struct AstStats {
    pub node_count: u64,
    pub depth: u32,
    pub leaf_count: u64,
    pub type_distribution: FxHashMap<String, u64>,
}
```

### 10.2 Type Analyzer (~1,600 lines TS → Rust)

V1 is TypeScript-only. V2 adds per-language type extraction via `TypeSystem` trait.
Start with TypeScript (P0), Python (P1), Java (P1), Go (P2).

```rust
/// Per-language type system trait. Each language implements this.
pub trait TypeSystem: Send + Sync {
    fn language(&self) -> Language;

    /// Extract TypeInfo from an AST node.
    fn extract_type(&self, node: &Node, source: &[u8]) -> Option<TypeInfo>;

    /// Full type analysis of a file.
    fn analyze_types(&self, tree: &Tree, source: &[u8]) -> TypeAnalysisResult;

    /// Structural subtype check.
    fn is_subtype_of(&self, type1: &TypeInfo, type2: &TypeInfo) -> bool;

    /// Compatibility check (looser than subtype).
    fn are_types_compatible(&self, type1: &TypeInfo, type2: &TypeInfo) -> bool;

    /// Percentage of typed locations.
    fn get_type_coverage(&self, tree: &Tree, source: &[u8]) -> TypeCoverageInfo;

    /// Inheritance, implementation, composition relationships.
    fn analyze_type_relationships(&self, tree: &Tree, source: &[u8]) -> Vec<TypeRelationship>;

    /// Structural equivalence check.
    fn are_types_equivalent(&self, type1: &TypeInfo, type2: &TypeInfo) -> bool;
}
```

#### TypeInfo (All v1 fields preserved)

```rust
pub struct TypeInfo {
    pub kind: TypeKind,
    pub text: String,
    pub name: Option<String>,
    pub members: Option<Vec<TypePropertyInfo>>,
    pub parameters: Option<Vec<TypeInfo>>,
    pub return_type: Option<Box<TypeInfo>>,
    pub element_type: Option<Box<TypeInfo>>,
    pub types: Option<Vec<TypeInfo>>,           // Union/intersection members
    pub type_arguments: Option<Vec<TypeInfo>>,
    pub constraint: Option<Box<TypeInfo>>,
    pub default_type: Option<Box<TypeInfo>>,
    pub is_optional: bool,
    pub is_readonly: bool,
    pub is_exported: bool,
}

pub enum TypeKind {
    Primitive,    // string, number, boolean, etc.
    Reference,    // Named types, generics
    Union,        // A | B
    Intersection, // A & B
    Array,        // T[], Array<T>
    Tuple,        // [A, B, C]
    Function,     // (a: A) => B
    Object,       // { key: Type }
    Literal,      // "hello", 42, true
    Parameter,    // Generic <T extends Base>
    Unknown,
}

pub struct TypeCoverageInfo {
    pub total_locations: u64,
    pub typed_count: u64,
    pub untyped_count: u64,
    pub percentage: f32,
}

pub struct TypeRelationship {
    pub kind: RelationshipKind,  // Inheritance, Implementation, Composition
    pub source: String,
    pub target: String,
    pub file: Spur,
    pub line: u32,
}
```

### 10.3 Semantic Analyzer (~1,350 lines TS → Rust)

Critical for call resolution accuracy. V2 adds per-language scope resolution
via `ScopeResolver` trait.

```rust
/// Per-language scope resolution trait.
pub trait ScopeResolver: Send + Sync {
    fn language(&self) -> Language;

    /// Full semantic analysis of a file.
    fn analyze(
        &self,
        tree: &Tree,
        source: &[u8],
        interner: &RodeoReader,
    ) -> SemanticAnalysisResult;

    /// Resolve a symbol name in a scope chain.
    fn resolve_symbol(
        &self,
        name: &str,
        scope_id: ScopeId,
        scopes: &[ScopeInfo],
        symbols: &[SymbolInfo],
    ) -> Option<SymbolInfo>;

    /// All symbols visible in a scope.
    fn get_visible_symbols(
        &self,
        scope_id: ScopeId,
        scopes: &[ScopeInfo],
        symbols: &[SymbolInfo],
    ) -> Vec<SymbolInfo>;

    /// Find scope at cursor position (LSP needs this).
    fn get_scope_at_position(
        &self,
        line: u32,
        column: u32,
        scopes: &[ScopeInfo],
    ) -> Option<ScopeId>;
}
```

#### Scope Types (11 — all preserved from v1)

```rust
pub enum ScopeType {
    Global,
    Module,
    Function,
    Method,
    Class,
    Block,
    ForLoop,
    IfBranch,
    SwitchCase,
    Try,
    Catch,
}
```

#### Symbol Collection Sources (all preserved from v1)

Function declarations (async, generator), arrow functions, method definitions,
class declarations (with members), field definitions, variable declarations
(const/let/var with mutability tracking), destructuring patterns (object and array),
import declarations (named, default, namespace), export declarations,
interface declarations, type alias declarations, enum declarations.

#### SemanticAnalysisResult

```rust
pub struct SemanticAnalysisResult {
    pub scopes: Vec<ScopeInfo>,
    pub symbols: Vec<SymbolInfo>,
    pub references: Vec<SymbolReference>,
    pub unresolved_references: Vec<SymbolReference>,
    pub shadowed_variables: Vec<ShadowedVariable>,
    pub errors: Vec<AnalysisError>,
}

pub struct ScopeInfo {
    pub id: ScopeId,
    pub scope_type: ScopeType,
    pub parent: Option<ScopeId>,
    pub children: Vec<ScopeId>,
    pub symbols: Vec<SymbolId>,
    pub start_line: u32,
    pub end_line: u32,
}

pub struct SymbolInfo {
    pub id: SymbolId,
    pub name: Spur,
    pub kind: SymbolKind,
    pub scope: ScopeId,
    pub visibility: Visibility,
    pub is_mutable: bool,
    pub type_info: Option<TypeInfo>,
    pub decorators: SmallVec<[Spur; 2]>,
    pub references: Vec<SymbolReference>,
    pub line: u32,
    pub column: u32,
}

pub enum SymbolKind {
    Variable, Function, Class, Interface, TypeAlias,
    Enum, Parameter, Property, Method, Import, Export,
}
```

### 10.4 Flow Analyzer (~1,600 lines TS → Rust)

V1 is intraprocedural only. V2 adds interprocedural data flow via function summaries
(R6 from analyzers recommendations). Per-language lowering to normalized IR.

```rust
pub struct FlowAnalyzer;

impl FlowAnalyzer {
    /// Full flow analysis of a file.
    pub fn analyze(
        &self,
        tree: &Tree,
        source: &[u8],
        language: Language,
    ) -> FlowAnalysisResult { /* ... */ }

    /// Per-function flow analysis.
    pub fn analyze_function(
        &self,
        node: &Node,
        source: &[u8],
        language: Language,
    ) -> FlowAnalysisResult { /* ... */ }

    /// CFG access.
    pub fn get_nodes(&self, cfg: &ControlFlowGraph) -> &[CfgNode] { /* ... */ }
    pub fn get_edges(&self, cfg: &ControlFlowGraph) -> &[CfgEdge] { /* ... */ }

    /// Reachability check.
    pub fn is_node_reachable(&self, cfg: &ControlFlowGraph, node_id: CfgNodeId) -> bool { /* ... */ }

    /// CFG navigation.
    pub fn get_predecessors(&self, cfg: &ControlFlowGraph, node_id: CfgNodeId) -> Vec<CfgNodeId> { /* ... */ }
    pub fn get_successors(&self, cfg: &ControlFlowGraph, node_id: CfgNodeId) -> Vec<CfgNodeId> { /* ... */ }
}
```

#### CFG Node Types (all preserved from v1)

```rust
pub enum CfgNodeKind {
    Entry,
    Exit,
    Statement(StatementKind),  // Expression, Declaration, Assignment
    Branch(BranchKind),        // If, Switch
    Loop(LoopKind),            // For, ForIn, ForOf, While, DoWhile
    Exception(ExceptionKind),  // Try, Catch, Finally
    Return,
    Throw,
    Break,
    Continue,
}
```

#### CFG Edge Types (8 — all preserved from v1)

```rust
pub enum CfgEdgeKind {
    Normal,
    TrueBranch,
    FalseBranch,
    Exception,
    Break,
    Continue,
    Return,
    Throw,
}
```

#### FlowAnalysisResult

```rust
pub struct FlowAnalysisResult {
    pub cfg: ControlFlowGraph,
    pub data_flow: DataFlowInfo,
    pub unreachable_code: Vec<SourceLocation>,
    pub infinite_loops: Vec<SourceLocation>,
    pub missing_returns: Vec<SourceLocation>,
    pub null_dereferences: Vec<SourceLocation>,
}

pub struct DataFlowInfo {
    pub definitions: Vec<VarDefinition>,
    pub uses: Vec<VarUse>,
    pub reaching_definitions: FxHashMap<VarUse, Vec<VarDefinition>>,
}

/// NEW: Interprocedural function summary for cross-function data flow.
pub struct FunctionSummary {
    pub function_id: FunctionId,
    pub param_taints: Vec<bool>,           // Which params taint the return
    pub return_tainted_by: Vec<usize>,     // Which param indices taint return
    pub side_effects: Vec<SideEffect>,     // Global state mutations
    pub may_throw: bool,
}
```


---

## 11. Unified Language Provider in Rust

The most sophisticated extraction system in v1. Normalizes AST differences across
languages into a universal `UnifiedCallChain` representation, enabling language-agnostic
ORM/framework pattern matching. All 9 normalizers and 20 ORM matchers move to Rust.

### LanguageNormalizer Trait

```rust
/// Each language implements this to convert its AST into UnifiedCallChain.
/// This is SEPARATE from GASTNormalizer — GAST normalizes for detection,
/// LanguageNormalizer normalizes for ORM/framework matching.
pub trait LanguageNormalizer: Send + Sync {
    fn language(&self) -> Language;

    /// Extract call chains from the AST.
    fn extract_call_chains(
        &self,
        tree: &Tree,
        source: &[u8],
        interner: &RodeoReader,
    ) -> Vec<UnifiedCallChain>;

    /// Extract framework-specific patterns (routes, decorators, etc.).
    fn extract_framework_patterns(
        &self,
        tree: &Tree,
        source: &[u8],
        interner: &RodeoReader,
    ) -> Vec<FrameworkPattern>;
}
```

### 9 Language Normalizers (all preserved from v1)

| Normalizer | Language | Key Extractions |
|-----------|----------|-----------------|
| TypeScriptNormalizer | TS/JS | Method chains, optional chaining, decorators, JSX |
| PythonNormalizer | Python | Method chains, keyword args, decorators, context managers |
| JavaNormalizer | Java | Builder patterns, annotations, generics, streams |
| CSharpNormalizer | C# | LINQ chains, attributes, extension methods, async/await |
| PhpNormalizer | PHP | Arrow functions, attributes (PHP 8), static calls, facades |
| GoNormalizer | Go | Method chains, error returns, goroutines, channels |
| RustNormalizer | Rust | Method chains, ? operator, trait methods, turbofish |
| CppNormalizer | C++ | Method chains, templates, operator overloads, RAII |
| BaseNormalizer | Abstract | Default implementations, shared utilities |

### UnifiedCallChain Type

```rust
/// Universal representation of a method call sequence.
/// e.g., supabase.from('users').select('*').eq('id', userId)
pub struct UnifiedCallChain {
    pub receiver: Option<Spur>,            // Initial object (e.g., "supabase")
    pub segments: SmallVec<[CallSegment; 4]>,
    pub file: Spur,
    pub line: u32,
    pub column: u32,
    pub language: Language,
}

pub struct CallSegment {
    pub method: Spur,                      // Method name (e.g., "from", "select", "eq")
    pub args: SmallVec<[CallArg; 4]>,      // Arguments
    pub is_await: bool,
    pub is_optional: bool,                 // Optional chaining (?.)
}

pub struct CallArg {
    pub value: ArgValue,
    pub name: Option<Spur>,               // Named/keyword argument
}

pub enum ArgValue {
    StringLiteral(String),
    NumberLiteral(f64),
    Identifier(Spur),
    Expression(String),                    // Fallback: raw expression text
    Array(Vec<ArgValue>),
    Object(Vec<(String, ArgValue)>),
}
```

### OrmMatcher Trait

```rust
/// Each ORM/framework matcher implements this.
pub trait OrmMatcher: Send + Sync {
    /// Unique identifier for this matcher.
    fn id(&self) -> &str;

    /// Which languages this matcher applies to.
    fn languages(&self) -> &[Language];

    /// Check if a call chain matches this ORM's patterns.
    fn matches(&self, chain: &UnifiedCallChain) -> Option<OrmPattern>;

    /// Extract table/collection name from a matched chain.
    fn extract_table(&self, chain: &UnifiedCallChain) -> Option<String>;

    /// Extract operation type (SELECT, INSERT, UPDATE, DELETE).
    fn extract_operation(&self, chain: &UnifiedCallChain) -> Option<DataOperation>;

    /// Extract field names from a matched chain.
    fn extract_fields(&self, chain: &UnifiedCallChain) -> Vec<String>;
}
```

### 20 ORM Matchers (all preserved from v1)

| Matcher | ORM/Framework | Languages | Key Patterns |
|---------|---------------|-----------|-------------|
| SupabaseMatcher | Supabase | TS/JS | `.from('table').select().eq()` |
| PrismaMatcher | Prisma | TS/JS | `prisma.model.findMany()` |
| TypeOrmMatcher | TypeORM | TS/JS | `repository.find()`, `@Entity` |
| SequelizeMatcher | Sequelize | TS/JS | `Model.findAll()`, `Model.create()` |
| DrizzleMatcher | Drizzle | TS/JS | `db.select().from(table)` |
| KnexMatcher | Knex | TS/JS | `knex('table').select()` |
| MongooseMatcher | Mongoose | TS/JS | `Model.find()`, `Model.aggregate()` |
| DjangoMatcher | Django ORM | Python | `Model.objects.filter()` |
| SqlAlchemyMatcher | SQLAlchemy | Python | `session.query(Model).filter()` |
| EfCoreMatcher | EF Core | C# | `context.Set<T>().Where()`, LINQ |
| EloquentMatcher | Eloquent | PHP | `Model::where()->get()` |
| SpringDataMatcher | Spring Data | Java | `repository.findBy*()`, `@Query` |
| GormMatcher | GORM | Go | `db.Where().Find()` |
| DieselMatcher | Diesel | Rust | `table.filter().select()` |
| SeaOrmMatcher | SeaORM | Rust | `Entity::find().filter()` |
| SqlxMatcher | SQLx | Rust | `sqlx::query!()`, `query_as!()` |
| RawSqlMatcher | Raw SQL | All | SQL string literal detection |
| DatabaseSqlMatcher | database/sql | Go | `db.Query()`, `db.Exec()` |
| BaseMatcher | Abstract | — | Default implementations |
| MatcherRegistry | Registry | — | Registration + dispatch |

### OrmPattern Result

```rust
pub struct OrmPattern {
    pub orm: OrmType,
    pub table: Option<String>,
    pub operation: DataOperation,
    pub fields: Vec<String>,
    pub conditions: Vec<String>,
    pub file: Spur,
    pub line: u32,
    pub column: u32,
    pub chain_length: u8,
    pub confidence: f32,
}

pub enum OrmType {
    Supabase, Prisma, TypeOrm, Sequelize, Drizzle, Knex, Mongoose,
    Django, SqlAlchemy, EfCore, Eloquent, SpringData,
    Gorm, Diesel, SeaOrm, Sqlx, RawSql, DatabaseSql,
}

pub enum DataOperation {
    Select, Insert, Update, Delete, Upsert, Count, Aggregate, Raw,
}
```

### Matcher Registry

```rust
pub struct MatcherRegistry {
    matchers: Vec<Box<dyn OrmMatcher>>,
    language_index: FxHashMap<Language, Vec<usize>>,  // Language → matcher indices
}

impl MatcherRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            matchers: Vec::new(),
            language_index: FxHashMap::default(),
        };
        // Register all 18 concrete matchers (excluding base + registry)
        registry.register(Box::new(SupabaseMatcher));
        registry.register(Box::new(PrismaMatcher));
        // ... all 18
        registry
    }

    pub fn register(&mut self, matcher: Box<dyn OrmMatcher>) {
        let idx = self.matchers.len();
        for lang in matcher.languages() {
            self.language_index.entry(*lang).or_default().push(idx);
        }
        self.matchers.push(matcher);
    }

    /// Run all applicable matchers against a call chain.
    pub fn match_chain(&self, chain: &UnifiedCallChain) -> Vec<OrmPattern> {
        let indices = self.language_index.get(&chain.language)
            .map(|v| v.as_slice())
            .unwrap_or(&[]);

        indices.iter()
            .filter_map(|&idx| self.matchers[idx].matches(chain))
            .collect()
    }
}
```

---

## 12. Per-Language Analyzers

Each language has a dedicated analyzer that extracts framework-aware patterns.
All 10 language analyzers from v1 move to Rust. Every extraction capability preserved.

### 12.1 TypeScript/JavaScript Analyzer

```rust
pub struct TypeScriptAnalyzer;

impl TypeScriptAnalyzer {
    /// Extract routes (Express, Fastify, NestJS, Hono).
    pub fn extract_routes(&self, tree: &Tree, source: &[u8]) -> Vec<TsRoute> { /* ... */ }

    /// Extract React/Vue/Svelte components.
    pub fn extract_components(&self, tree: &Tree, source: &[u8]) -> Vec<TsComponent> { /* ... */ }

    /// Extract custom React hooks (use* pattern).
    pub fn extract_hooks(&self, tree: &Tree, source: &[u8]) -> Vec<TsHook> { /* ... */ }

    /// Extract error handling patterns.
    pub fn extract_error_patterns(&self, tree: &Tree, source: &[u8]) -> Vec<TsErrorPattern> { /* ... */ }

    /// Extract data access points (7 ORMs via UnifiedLanguageProvider).
    pub fn extract_data_access(&self, tree: &Tree, source: &[u8]) -> Vec<TsDataAccessPoint> { /* ... */ }

    /// Extract NestJS/TypeORM decorators.
    pub fn extract_decorators(&self, tree: &Tree, source: &[u8]) -> Vec<TsDecorator> { /* ... */ }
}
```

### 12.2 Python Analyzer

```rust
pub struct PythonAnalyzer;

impl PythonAnalyzer {
    /// Extract routes (Django, Flask, FastAPI).
    pub fn extract_routes(&self, tree: &Tree, source: &[u8]) -> Vec<PyRoute> { /* ... */ }

    /// Extract error handling (try/except, custom exceptions).
    pub fn extract_error_patterns(&self, tree: &Tree, source: &[u8]) -> Vec<PyErrorPattern> { /* ... */ }

    /// Extract data access (Django ORM, SQLAlchemy, raw SQL).
    pub fn extract_data_access(&self, tree: &Tree, source: &[u8]) -> Vec<PyDataAccessPoint> { /* ... */ }

    /// Extract decorators with complex argument patterns.
    pub fn extract_decorators(&self, tree: &Tree, source: &[u8]) -> Vec<PyDecorator> { /* ... */ }

    /// Extract async patterns (async def, await, asyncio).
    pub fn extract_async_patterns(&self, tree: &Tree, source: &[u8]) -> Vec<PyAsyncPattern> { /* ... */ }
}
```

### 12.3 Java Analyzer

```rust
pub struct JavaAnalyzer;

impl JavaAnalyzer {
    /// Extract Spring Boot routes (@RequestMapping, @GetMapping, etc.).
    pub fn extract_routes(&self, tree: &Tree, source: &[u8]) -> Vec<JavaRoute> { /* ... */ }

    /// Extract JPA entities (@Entity, @Table, @Repository, @Query).
    pub fn extract_jpa_entities(&self, tree: &Tree, source: &[u8]) -> Vec<JavaJpaEntity> { /* ... */ }

    /// Extract Hibernate patterns.
    pub fn extract_hibernate_patterns(&self, tree: &Tree, source: &[u8]) -> Vec<JavaHibernatePattern> { /* ... */ }
}
```

### 12.4 Go Analyzer

```rust
pub struct GoAnalyzer;

impl GoAnalyzer {
    /// Extract routes (Gin, Echo, Chi, net/http).
    pub fn extract_routes(&self, tree: &Tree, source: &[u8]) -> Vec<GoRoute> { /* ... */ }

    /// Extract error handling (if err != nil).
    pub fn extract_error_patterns(&self, tree: &Tree, source: &[u8]) -> Vec<GoErrorPattern> { /* ... */ }

    /// Extract interfaces.
    pub fn extract_interfaces(&self, tree: &Tree, source: &[u8]) -> Vec<GoInterface> { /* ... */ }

    /// Extract data access (GORM, sqlx, database/sql).
    pub fn extract_data_access(&self, tree: &Tree, source: &[u8]) -> Vec<GoDataAccessPoint> { /* ... */ }

    /// Extract goroutines and channels.
    pub fn extract_goroutines(&self, tree: &Tree, source: &[u8]) -> Vec<GoGoroutine> { /* ... */ }
}
```

### 12.5 Rust Analyzer

```rust
pub struct RustLangAnalyzer;

impl RustLangAnalyzer {
    /// Extract routes (Actix, Axum).
    pub fn extract_routes(&self, tree: &Tree, source: &[u8]) -> Vec<RustRoute> { /* ... */ }

    /// Extract error patterns (Result<T,E>, ? operator).
    pub fn extract_error_patterns(&self, tree: &Tree, source: &[u8]) -> Vec<RustErrorPattern> { /* ... */ }

    /// Extract traits.
    pub fn extract_traits(&self, tree: &Tree, source: &[u8]) -> Vec<RustTrait> { /* ... */ }

    /// Extract async functions.
    pub fn extract_async_functions(&self, tree: &Tree, source: &[u8]) -> Vec<RustAsyncFunction> { /* ... */ }

    /// Extract crate usage patterns.
    pub fn extract_crate_usage(&self, tree: &Tree, source: &[u8]) -> Vec<RustCrateUsage> { /* ... */ }
}
```

### 12.6 C# Analyzer

```rust
pub struct CSharpAnalyzer;

impl CSharpAnalyzer {
    /// Extract ASP.NET routes ([HttpGet], [HttpPost], [Route]).
    pub fn extract_routes(&self, tree: &Tree, source: &[u8]) -> Vec<CSharpRoute> { /* ... */ }

    /// Extract Entity Framework entities ([Table], [Key], [DbContext]).
    pub fn extract_ef_entities(&self, tree: &Tree, source: &[u8]) -> Vec<CSharpEfEntity> { /* ... */ }
}
```

### 12.7 PHP Analyzer

```rust
pub struct PhpAnalyzer;

impl PhpAnalyzer {
    /// Extract Laravel routes (Route::get, Route::post, etc.).
    pub fn extract_routes(&self, tree: &Tree, source: &[u8]) -> Vec<PhpRoute> { /* ... */ }

    /// Extract Eloquent models (class X extends Model).
    pub fn extract_eloquent_models(&self, tree: &Tree, source: &[u8]) -> Vec<PhpEloquentModel> { /* ... */ }

    /// Extract PHP 8 attributes.
    pub fn extract_attributes(&self, tree: &Tree, source: &[u8]) -> Vec<PhpAttribute> { /* ... */ }

    /// Extract docblock annotations.
    pub fn extract_docblocks(&self, tree: &Tree, source: &[u8]) -> Vec<PhpDocblock> { /* ... */ }
}
```

### 12.8 C++ Analyzer

```rust
pub struct CppAnalyzer;

impl CppAnalyzer {
    /// Extract class hierarchies (inheritance, virtual methods).
    pub fn extract_classes(&self, tree: &Tree, source: &[u8]) -> Vec<CppClass> { /* ... */ }

    /// Extract memory patterns (new/delete, smart pointers, RAII).
    pub fn extract_memory_patterns(&self, tree: &Tree, source: &[u8]) -> Vec<CppMemoryPattern> { /* ... */ }

    /// Extract templates.
    pub fn extract_templates(&self, tree: &Tree, source: &[u8]) -> Vec<CppTemplate> { /* ... */ }

    /// Extract virtual methods.
    pub fn extract_virtual_methods(&self, tree: &Tree, source: &[u8]) -> Vec<CppVirtualMethod> { /* ... */ }
}
```

### 12.9 C Analyzer

```rust
pub struct CAnalyzer;

impl CAnalyzer {
    /// Extract function declarations and definitions.
    pub fn extract_functions(&self, tree: &Tree, source: &[u8]) -> Vec<CFunction> { /* ... */ }

    /// Extract struct definitions.
    pub fn extract_structs(&self, tree: &Tree, source: &[u8]) -> Vec<CStruct> { /* ... */ }

    /// Extract memory patterns (malloc/free, pointer arithmetic).
    pub fn extract_memory_patterns(&self, tree: &Tree, source: &[u8]) -> Vec<CMemoryPattern> { /* ... */ }
}
```

### 12.10 WPF/XAML Analyzer (Evaluate Priority)

Most complex language analyzer (~8 files in v1). Requires dedicated tree-sitter
grammar for XAML parsing. Extracts: XAML controls/bindings/resources/styles,
ViewModel linking, MVVM analysis, binding errors, resource dictionaries,
dependency properties, data flow through bindings.

Decision: Defer to Phase 7. Evaluate based on user demand. If needed, implement
as `FileDetectorHandler` (full-file context) rather than per-node visitor.


---

## 13. String Interning

### V1 Implementation (Custom)

```rust
// V1 — custom interner
pub struct StringInterner {
    map: HashMap<String, Symbol>,    // string → symbol (dedup lookup)
    strings: Vec<String>,           // symbol.0 → string (reverse lookup)
    next_id: AtomicU32,
}
```

Methods: `intern(&mut self, s: &str) → Symbol`, `resolve(&self, sym: Symbol) → Option<&str>`,
`memory_stats() → InternerStats`.

PathInterner: normalizes `\` → `/` before interning. Default capacity: 4096.
FunctionInterner: supports `intern_qualified(class, method)`. Default capacity: 8192.

Claims 60-80% memory reduction for large codebases.

### V2 Implementation (lasso)

Replace custom interner with `lasso` crate for production-grade performance:

```rust
use lasso::{ThreadedRodeo, RodeoReader, Spur};

/// Build phase: concurrent writes from multiple threads.
pub struct BuildInterner {
    rodeo: ThreadedRodeo,
}

impl BuildInterner {
    pub fn new() -> Self {
        Self { rodeo: ThreadedRodeo::new() }
    }

    pub fn intern(&self, s: &str) -> Spur {
        self.rodeo.get_or_intern(s)
    }

    /// Freeze into read-only reader for query phase.
    pub fn into_reader(self) -> RodeoReader {
        self.rodeo.into_reader()
    }
}

/// Query phase: contention-free reads from any thread.
pub struct QueryInterner {
    reader: RodeoReader,
}

impl QueryInterner {
    pub fn resolve(&self, key: Spur) -> &str {
        self.reader.resolve(&key)
    }

    pub fn try_resolve(&self, key: Spur) -> Option<&str> {
        self.reader.try_resolve(&key)
    }
}
```

### Domain Wrappers (Preserved from v1)

```rust
/// Path interner: normalizes \ → / before interning.
pub struct PathInterner {
    inner: Arc<ThreadedRodeo>,
}

impl PathInterner {
    pub fn intern(&self, path: &str) -> Spur {
        let normalized = path.replace('\\', "/");
        self.inner.get_or_intern(&normalized)
    }
}

/// Function interner: supports qualified names (Class.method).
pub struct FunctionInterner {
    inner: Arc<ThreadedRodeo>,
}

impl FunctionInterner {
    pub fn intern(&self, name: &str) -> Spur {
        self.inner.get_or_intern(name)
    }

    pub fn intern_qualified(&self, class: &str, method: &str) -> Spur {
        let qualified = format!("{}.{}", class, method);
        self.inner.get_or_intern(&qualified)
    }
}
```

### Lifecycle

```
Scan/Build Phase:
    ThreadedRodeo (mutable, concurrent via DashMap internally)
    All parsers, analyzers, detectors intern strings here

Freeze:
    ThreadedRodeo::into_reader() → RodeoReader

Query/Read Phase:
    RodeoReader (immutable, zero contention)
    Resolution index, pattern queries, NAPI serialization read from here
```

---

## 14. Storage Schema

All unified analysis data persists to drift.db (SQLite via rusqlite).
Per PLANNING-DRIFT.md D1: standalone, no external dependencies.

### detection_cache — Per-File Detection Results

```sql
CREATE TABLE detection_cache (
    file_path TEXT NOT NULL,
    content_hash INTEGER NOT NULL,
    language TEXT NOT NULL,
    patterns_json TEXT NOT NULL CHECK(json_valid(patterns_json)),
    violations_json TEXT NOT NULL CHECK(json_valid(violations_json)),
    resolution_entries_json TEXT NOT NULL CHECK(json_valid(resolution_entries_json)),
    analyzed_at TEXT NOT NULL,
    PRIMARY KEY (file_path)
) STRICT;

CREATE INDEX idx_detection_cache_hash ON detection_cache(content_hash);
```

### pattern_scan_history — For Momentum Calculation

```sql
CREATE TABLE pattern_scan_history (
    pattern_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    frequency REAL NOT NULL,
    file_count INTEGER NOT NULL,
    total_files INTEGER NOT NULL,
    scanned_at TEXT NOT NULL,
    PRIMARY KEY (pattern_id, scan_id)
) STRICT;

CREATE INDEX idx_pattern_history_pattern ON pattern_scan_history(pattern_id);
```

### pattern_posteriors — Bayesian Parameters

```sql
CREATE TABLE pattern_posteriors (
    pattern_id TEXT PRIMARY KEY,
    alpha REAL NOT NULL DEFAULT 1.0,
    beta REAL NOT NULL DEFAULT 1.0,
    last_updated TEXT NOT NULL
) STRICT;
```

### custom_patterns — User TOML Patterns (Compiled Cache)

```sql
CREATE TABLE custom_patterns (
    id TEXT PRIMARY KEY,
    language TEXT NOT NULL,
    category TEXT NOT NULL,
    confidence REAL NOT NULL,
    query TEXT,
    regex TEXT,
    toml_source TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;
```

### parse_cache — Moka Persistence Layer

```sql
CREATE TABLE parse_cache (
    file_path TEXT NOT NULL,
    content_hash INTEGER NOT NULL,
    data BLOB NOT NULL,           -- bincode-serialized ParseResult
    cached_at TEXT NOT NULL,
    PRIMARY KEY (file_path, content_hash)
) STRICT;
```

### violation_actions — Feedback Loop

```sql
CREATE TABLE violation_actions (
    violation_id TEXT NOT NULL,
    detector_id TEXT NOT NULL,
    action TEXT NOT NULL,          -- Fixed, Dismissed, Ignored, AutoFixed, NotSeen
    timestamp TEXT NOT NULL,
    time_to_action_ms INTEGER,
    PRIMARY KEY (violation_id)
) STRICT;

CREATE INDEX idx_violation_actions_detector ON violation_actions(detector_id);
```

### detector_health — Per-Detector Health Metrics

```sql
CREATE TABLE detector_health (
    detector_id TEXT PRIMARY KEY,
    total_violations INTEGER NOT NULL DEFAULT 0,
    fixed_count INTEGER NOT NULL DEFAULT 0,
    dismissed_count INTEGER NOT NULL DEFAULT 0,
    ignored_count INTEGER NOT NULL DEFAULT 0,
    auto_fixed_count INTEGER NOT NULL DEFAULT 0,
    effective_fp_rate REAL NOT NULL DEFAULT 0.0,
    trend TEXT NOT NULL DEFAULT 'stable',  -- improving, stable, degrading
    last_updated TEXT NOT NULL
) STRICT;
```

### pattern_locations — For Incremental Re-Scoring

```sql
CREATE TABLE pattern_locations (
    pattern_id TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line INTEGER NOT NULL,
    column INTEGER NOT NULL,
    PRIMARY KEY (pattern_id, file_path, line, column)
) STRICT;

CREATE INDEX idx_pattern_locations_file ON pattern_locations(file_path);
```

---

## 15. NAPI Interface

Three NAPI entry points for unified analysis. All follow the command/query pattern
from 03-NAPI-BRIDGE-V2-PREP.md.

### analyze_unified — Primary Entry Point

```rust
#[napi]
pub async fn analyze_unified(
    root: String,
    options: JsUnifiedOptions,
) -> Result<JsUnifiedResult, napi::Error> {
    let span = tracing::info_span!("analyze_unified", root = %root);
    let _guard = span.enter();

    // 1. Convert JS options to Rust options
    let opts = UnifiedOptions::from_js(options)?;

    // 2. Create cancellation token
    let cancel = CancellationToken::new();

    // 3. Acquire string interner (ThreadedRodeo for build phase)
    let interner = Arc::new(ThreadedRodeo::new());

    // 4. Run scanner to get file list
    let scan_result = scanner::scan(&root, &opts.patterns)?;

    // 5. Partition files (incremental: skip unchanged)
    let (needs_analysis, cached) = if opts.incremental {
        incremental::partition_files(&scan_result.files, &db)?
    } else {
        (scan_result.files.clone(), Vec::new())
    };

    // 6. Run 4-phase pipeline in parallel via rayon
    let file_results: Vec<FilePatterns> = needs_analysis
        .par_iter()
        .map(|file| {
            cancel.check()?;
            pipeline::analyze_file(file, &opts, &interner, &cancel)
        })
        .collect::<Result<Vec<_>, _>>()?;

    // 7. Merge with cached results
    let all_results = merge_results(file_results, cached);

    // 8. Build resolution index from all results
    let resolution = resolution::build_index(&all_results, &interner);

    // 9. Cache new results for future incremental runs
    if opts.incremental {
        incremental::cache_results(&file_results, &db)?;
    }

    // 10. Freeze interner for query phase
    let reader = Arc::try_unwrap(interner)
        .map_err(|_| AnalysisError::InternerInUse)?
        .into_reader();

    // 11. Convert to JS result
    let result = UnifiedResult::to_js(&all_results, &resolution, &reader)?;

    // 12. Emit event
    event_handler.on_analysis_complete(&result.metrics);

    Ok(result)
}
```

### analyze_unified_incremental — Changed Files Only

```rust
#[napi]
pub async fn analyze_unified_incremental(
    root: String,
    changed_files: Vec<String>,
    options: JsUnifiedOptions,
) -> Result<JsUnifiedResult, napi::Error> {
    let span = tracing::info_span!("analyze_unified_incremental",
        root = %root, changed = changed_files.len());
    let _guard = span.enter();

    // 1. Load cached results for unchanged files from drift.db
    let cached = db.load_detection_cache_except(&changed_files)?;

    // 2. Re-analyze only changed files
    let opts = UnifiedOptions::from_js(options)?;
    let cancel = CancellationToken::new();
    let interner = Arc::new(ThreadedRodeo::new());

    let new_results: Vec<FilePatterns> = changed_files
        .par_iter()
        .map(|path| {
            cancel.check()?;
            let file = scanner::scan_single(path)?;
            pipeline::analyze_file(&file, &opts, &interner, &cancel)
        })
        .collect::<Result<Vec<_>, _>>()?;

    // 3. Merge results
    let all_results = merge_results(new_results.clone(), cached);

    // 4. Update cache
    db.batch_upsert_detection_cache(&new_results)?;

    // 5. Rebuild resolution index
    let resolution = resolution::build_index(&all_results, &interner);

    // 6. Convert and return
    let reader = Arc::try_unwrap(interner)
        .map_err(|_| AnalysisError::InternerInUse)?
        .into_reader();
    Ok(UnifiedResult::to_js(&all_results, &resolution, &reader)?)
}
```

### analyze_batch — Multiple Analysis Types in One Call

```rust
#[napi]
pub async fn analyze_batch(
    root: String,
    analyses: Vec<String>,  // ["unified", "call_graph", "boundaries", ...]
    options: JsBatchOptions,
) -> Result<JsBatchResult, napi::Error> {
    let span = tracing::info_span!("analyze_batch",
        root = %root, analyses = ?analyses);
    let _guard = span.enter();

    // Shares parsed results across analysis types.
    // Parse once, run multiple analysis passes.
    let parse_results = parser::parse_all(&root, &options)?;

    let mut batch_result = JsBatchResult::default();

    for analysis in &analyses {
        match analysis.as_str() {
            "unified" => {
                batch_result.unified = Some(
                    pipeline::run_unified(&parse_results, &options)?
                );
            }
            "call_graph" => {
                batch_result.call_graph = Some(
                    call_graph::build(&parse_results, &options)?
                );
            }
            "boundaries" => {
                batch_result.boundaries = Some(
                    boundaries::detect(&parse_results, &options)?
                );
            }
            _ => {
                tracing::warn!("Unknown analysis type: {}", analysis);
            }
        }
    }

    Ok(batch_result)
}
```


---

## 16. Event Interface

The unified analysis engine emits events via the DriftEventHandler trait (D5).
In standalone mode, these are no-ops. When the bridge is active, they become
Cortex memories.

### UnifiedAnalysisEvents

```rust
pub trait UnifiedAnalysisEvents {
    /// Emitted after full analysis completes.
    fn on_analysis_complete(&self, metrics: &AnalysisMetrics) {}

    /// Emitted for each file analyzed.
    fn on_file_analyzed(&self, file: Spur, patterns: &[DetectedPattern]) {}

    /// Emitted when a new pattern type is first detected in the project.
    fn on_new_pattern_type(&self, pattern_type: Spur, category: PatternCategory) {}

    /// Emitted when incremental analysis skips files.
    fn on_incremental_skip(&self, skipped_count: u64, total_count: u64) {}

    /// Emitted when a taint flow is detected.
    fn on_taint_flow_detected(&self, flow: &TaintFlow) {}

    /// Emitted when analysis is cancelled due to revision change.
    fn on_analysis_cancelled(&self, revision: u64) {}

    /// Emitted when a violation is detected.
    fn on_violation_detected(&self, violation: &Violation) {}

    /// Emitted when a violation is fixed by the developer.
    fn on_violation_fixed(&self, violation_id: &str) {}

    /// Emitted when a violation is dismissed by the developer.
    fn on_violation_dismissed(&self, violation_id: &str) {}

    /// Emitted when a detector is auto-disabled due to high FP rate.
    fn on_detector_disabled(&self, detector_id: &str, reason: &str) {}
}
```

### Integration with DriftEventHandler

```rust
/// The unified analysis engine holds a reference to the event handler.
pub struct UnifiedPipeline {
    event_handler: Arc<dyn DriftEventHandler>,
    // ... other fields
}

impl UnifiedPipeline {
    fn emit_file_analyzed(&self, file: Spur, patterns: &[DetectedPattern]) {
        self.event_handler.on_file_analyzed(file, patterns);
    }

    fn emit_analysis_complete(&self, metrics: &AnalysisMetrics) {
        self.event_handler.on_analysis_complete(metrics);
    }
}
```

---

## 17. Tracing & Observability

Per AD10: observability-first. Every phase gets a tracing span with timing metrics.

### Per-Phase Spans

```rust
fn analyze_file(
    file: &ScanEntry,
    opts: &UnifiedOptions,
    interner: &ThreadedRodeo,
    cancel: &CancellationToken,
) -> Result<FilePatterns, AnalysisError> {
    let file_span = tracing::info_span!("analyze_file",
        file = %file.path,
        language = ?file.language,
    );
    let _file_guard = file_span.enter();

    // Phase 1: AST Pattern Detection
    let phase1_patterns = {
        let _span = tracing::info_span!("phase1_ast_queries").entered();
        ast_detector.detect(&parse_result.tree, &parse_result.source, file.language, file_spur)?
    };

    // Phase 1.5: Visitor Pattern Engine
    let phase15_patterns = {
        let _span = tracing::info_span!("phase1_5_visitor_engine",
            handler_count = detection_engine.handler_count(),
        ).entered();
        detection_engine.analyze(&parse_result.tree, &parse_result.source, &ctx, cancel)?
    };

    // Phase 2: String Extraction
    let strings = {
        let _span = tracing::info_span!("phase2_string_extraction").entered();
        string_extractor.extract(&parse_result.tree, &parse_result.source, file.language, file_spur)
    };

    // Phase 3: String Literal Analysis
    let phase3_patterns = {
        let _span = tracing::info_span!("phase3_string_analysis",
            string_count = strings.len(),
        ).entered();
        string_analyzer.analyze(&strings, file_spur)
    };

    // Phase 4: Resolution Index Population
    {
        let _span = tracing::info_span!("phase4_resolution_index",
            function_count = parse_result.functions.len(),
        ).entered();
        resolution_index.insert_from_parse_result(&parse_result);
    }

    // GAST Normalization (if enabled)
    let gast_time = if opts.enable_gast {
        let _span = tracing::info_span!("gast_normalization").entered();
        let start = std::time::Instant::now();
        let _gast_nodes = gast_normalizer.normalize(&parse_result.tree, &parse_result.source);
        start.elapsed().as_micros() as u64
    } else { 0 };

    // Merge all patterns
    let mut all_patterns = phase1_patterns;
    all_patterns.extend(phase15_patterns.into_iter().map(|m| m.into_detected_pattern()));
    all_patterns.extend(phase3_patterns);

    tracing::info!(
        pattern_count = all_patterns.len(),
        "file analysis complete"
    );

    Ok(FilePatterns {
        file: file_spur,
        language: file.language,
        patterns: all_patterns,
        violations: Vec::new(), // Populated by rules engine
        fixes: Vec::new(),
        parse_time_us: parse_result.parse_time_us,
        detect_time_us: phase1_time + phase15_time,
        gast_time_us: gast_time,
        string_time_us: phase2_time + phase3_time,
        resolve_time_us: phase4_time,
    })
}
```

### Metrics Collected

| Metric | Span | Type |
|--------|------|------|
| Files processed | `analyze_unified` | Counter |
| Files skipped (incremental) | `analyze_unified` | Counter |
| Total patterns detected | `analyze_unified` | Counter |
| Per-file pattern count | `analyze_file` | Gauge |
| Phase 1 time (AST queries) | `phase1_ast_queries` | Duration |
| Phase 1.5 time (visitor) | `phase1_5_visitor_engine` | Duration |
| Phase 2 time (string extraction) | `phase2_string_extraction` | Duration |
| Phase 3 time (string analysis) | `phase3_string_analysis` | Duration |
| Phase 4 time (resolution) | `phase4_resolution_index` | Duration |
| GAST normalization time | `gast_normalization` | Duration |
| Parse cache hit rate | `analyze_unified` | Gauge |
| Handler count per traversal | `phase1_5_visitor_engine` | Gauge |
| String count per file | `phase3_string_analysis` | Gauge |
| Function count per file | `phase4_resolution_index` | Gauge |
| Cancellation events | `analyze_unified` | Counter |

---

## 18. Build Order & Dependencies

### Phase 0 — Prerequisites (Must Exist Before Starting)

| Dependency | System | Status |
|-----------|--------|--------|
| Parsers (10 languages) | 01-PARSERS | ParseResult with full extraction |
| Scanner | 00-SCANNER | File walking, content hashing, ScanDiff |
| Storage | 02-STORAGE | drift.db with batch writer, keyset pagination |
| String Interning | 04-INFRASTRUCTURE | lasso ThreadedRodeo/RodeoReader |
| Infrastructure | 04-INFRASTRUCTURE | thiserror, tracing, DriftEventHandler, config |
| NAPI Bridge | 03-NAPI-BRIDGE | Command/query pattern, async tasks, cancellation |

### Phase 1 — Core Pipeline (Weeks 1-3)

```
1. Port v1 4-phase pipeline to v2 Rust
   - Phase 1: All 27 AST queries across 9 languages (preserve exact patterns)
   - Phase 2: String extraction with all 7 node kinds per language
   - Phase 3: All 33 regex patterns (SQL 9, routes 6, sensitive 8, env 6, log 4)
   - Phase 4: Resolution index with BTreeMap + FxHashMap + SmallVec
   - Wire up log patterns (v1 gap — compiled but unused)
   - Wire up ResolutionStats tracking (v1 gap — all fields were TODO)
   - Wire up Violation population (v1 gap — always empty Vec)

2. Replace custom StringInterner with lasso
   - ThreadedRodeo for build, RodeoReader for query
   - PathInterner wrapper (normalize \ → /)
   - FunctionInterner wrapper (intern_qualified)

3. Fix parser pool
   - Replace per-thread parser creation with bounded crossbeam channel pool
   - Checkout/return pattern instead of thread_local!
```

### Phase 2 — Visitor Pattern Engine (Weeks 3-5)

```
4. Build DetectionEngine with visitor pattern
   - DetectorHandler trait (node_types, on_enter, on_exit, results, reset)
   - FileDetectorHandler trait (full-file context)
   - LearningDetectorHandler trait (learn + detect two-pass)
   - Single-pass traversal with handler dispatch via FxHashMap<String, Vec<usize>>
   - Cancellation support (revision counter, check every 1024 nodes)

5. Integrate as Phase 1.5 in pipeline
   - Pre-compiled queries remain as Phase 1 (fast path for simple patterns)
   - Visitor engine runs as Phase 1.5 (complex, stateful, multi-node patterns)
   - Results merged before Phase 2
```

### Phase 3 — GAST Normalization (Weeks 5-8)

```
6. Define ~30 GAST node types (GASTNode enum)
7. Build GASTNormalizer trait + 10 per-language normalizers
   - P0: TypeScript, JavaScript, Python (highest usage)
   - P1: Java, Go, Rust
   - P2: C#, PHP, C++, C
8. Migrate duplicated detectors to GAST-based
   - try-catch → single GAST detector for all languages
   - route detection → single GAST detector
   - error handling patterns → single GAST detector
```

### Phase 4 — Core Analyzers in Rust (Weeks 8-12)

```
9.  Port AST Analyzer (10 methods)
    - findPattern, compareSubtrees, traverse, getStats
    - ASTPattern matching in Rust

10. Port Semantic Analyzer (4 methods + ScopeResolver trait)
    - Scope tree building (11 scope types)
    - Symbol table (all declaration types)
    - Reference resolution
    - Shadowed variable detection
    - Per-language ScopeResolver trait (start with TS, Python, Java)

11. Port Type Analyzer (7 methods + TypeSystem trait)
    - Type extraction (all TypeScript type kinds)
    - Subtype checking, compatibility
    - Type coverage calculation
    - Per-language TypeSystem trait (P0: TS, P1: Python/Java, P2: Go)

12. Port Flow Analyzer (6 methods)
    - CFG construction (all node types, 8 edge types)
    - Data flow analysis (definitions, uses, reaching definitions)
    - Issue detection (unreachable, infinite loops, missing returns, null deref)
    - Per-language IR lowering
    - NEW: Function summaries for interprocedural data flow
```

### Phase 5 — Unified Language Provider in Rust (Weeks 12-15)

```
13. Port 9 language normalizers (LanguageNormalizer trait)
14. Port 20 ORM matchers (OrmMatcher trait)
    - P0: Prisma, Django, SQLAlchemy (highest usage)
    - P1: TypeORM, Sequelize, Spring Data, EF Core
    - P2: Supabase, Drizzle, Knex, Mongoose, Eloquent, GORM
    - P3: Diesel, SeaORM, SQLx, database/sql, Raw SQL
15. UnifiedCallChain type in Rust
16. OrmPattern result type in Rust
17. MatcherRegistry with language-indexed dispatch
```

### Phase 6 — Advanced Features (Weeks 15-18)

```
18. Declarative pattern definitions (TOML loading + validation)
19. Incremental computation (3-layer model + detection_cache table)
20. Moka parse cache with SQLite persistence
21. Taint analysis integration (Phase 1: intraprocedural only)
22. Fix generation as first-class output (Fix struct, FixKind enum)
23. Feedback loop infrastructure (violation_actions, detector_health tables)
24. Cancellation support end-to-end (NAPI → pipeline → visitor → NAPI)
```

### Phase 7 — Per-Language Analyzers (Weeks 18-22)

```
25. Port TypeScript/JavaScript analyzer (routes, components, hooks, decorators)
26. Port Python analyzer (routes, error handling, data access, decorators, async)
27. Port Java analyzer (Spring Boot routes, JPA entities, Hibernate)
28. Port Go analyzer (routes, error handling, interfaces, goroutines)
29. Port Rust analyzer (routes, error patterns, traits, async)
30. Port C# analyzer (ASP.NET routes, EF entities)
31. Port PHP analyzer (Laravel routes, Eloquent models, attributes, docblocks)
32. Port C++ analyzer (classes, memory patterns, templates, virtual methods)
33. Port C analyzer (functions, structs, memory patterns)
34. Evaluate WPF/XAML analyzer priority
```

---

## 19. Performance Targets & Benchmarks

### Targets

| Metric | V1 Baseline | V2 Target | How Achieved |
|--------|-------------|-----------|-------------|
| Full scan (10K files) | ~30s | <5s | Rayon parallelism + visitor pattern + GAST |
| Incremental scan (1 file) | ~10s (full rescan) | <100ms | Content-hash skip + cached results |
| Incremental scan (10 files) | ~10s | <500ms | Selective re-analysis |
| Per-file detection time | ~3ms | <1ms | Single-pass visitor, no redundant traversals |
| Parse cache hit rate | 0% (no cache) | >80% | Moka TinyLFU + SQLite persistence |
| Memory usage (10K files) | ~500MB | <200MB | String interning (60-80% reduction) |
| Resolution rate | Unknown (TODO) | 60-85% | 6 resolution strategies |
| NAPI serialization overhead | ~15% | <5% | Batch API, streaming for large results |
| MCP response time (cached) | ~200ms | <50ms | Moka cache with semantic keys |

### Benchmark Suite

```rust
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_full_scan_1k(c: &mut Criterion) {
    c.bench_function("full_scan_1k_files", |b| {
        b.iter(|| { /* target: <500ms */ })
    });
}

fn bench_full_scan_10k(c: &mut Criterion) {
    c.bench_function("full_scan_10k_files", |b| {
        b.iter(|| { /* target: <5s */ })
    });
}

fn bench_incremental_1_file(c: &mut Criterion) {
    c.bench_function("incremental_1_file", |b| {
        b.iter(|| { /* target: <100ms */ })
    });
}

fn bench_visitor_traversal_large_file(c: &mut Criterion) {
    c.bench_function("visitor_traversal_large_file", |b| {
        b.iter(|| { /* target: <1ms for 10K node file */ })
    });
}

fn bench_gast_normalization(c: &mut Criterion) {
    c.bench_function("gast_normalization_per_file", |b| {
        b.iter(|| { /* target: <500us */ })
    });
}

fn bench_string_analysis(c: &mut Criterion) {
    c.bench_function("string_analysis_per_file", |b| {
        b.iter(|| { /* target: <200us */ })
    });
}

fn bench_resolution_index(c: &mut Criterion) {
    c.bench_function("resolution_index_10k_functions", |b| {
        b.iter(|| { /* target: <50ms build, <1us lookup */ })
    });
}

fn bench_parse_cache_hit(c: &mut Criterion) {
    c.bench_function("parse_cache_hit", |b| {
        b.iter(|| { /* target: <10us */ })
    });
}

criterion_group!(
    benches,
    bench_full_scan_1k,
    bench_full_scan_10k,
    bench_incremental_1_file,
    bench_visitor_traversal_large_file,
    bench_gast_normalization,
    bench_string_analysis,
    bench_resolution_index,
    bench_parse_cache_hit,
);
criterion_main!(benches);
```


---

## 20. V1 → V2 Feature Cross-Reference

Every v1 feature mapped to its exact v2 location. Zero feature loss.

### Preserved Features (Direct Port)

| V1 Feature | V1 Location | V2 Location | Notes |
|-----------|-------------|-------------|-------|
| 4-phase pipeline | unified/analyzer.rs | unified/pipeline.rs | Architecture preserved |
| 27 AST queries (9 langs) | unified/ast_patterns.rs | unified/ast_patterns.rs + patterns/*.toml | + TOML extensibility |
| 33 string regex patterns | unified/string_analyzer.rs | unified/string_analyzer.rs | + log patterns wired |
| String extraction (7 node kinds) | unified/ast_patterns.rs | unified/string_extractor.rs | All 7 per-language mappings |
| 7 StringContext variants | unified/types.rs | unified/types.rs | All 7 preserved |
| Resolution index | unified/index.rs | unified/resolution.rs | + 3 new strategies |
| FunctionEntry (7 fields) | unified/index.rs | unified/resolution.rs | + 6 new fields |
| String interning | unified/interner.rs | interning/mod.rs | Upgraded to lasso |
| PathInterner | unified/interner.rs | interning/path.rs | Preserved as wrapper |
| FunctionInterner | unified/interner.rs | interning/function.rs | Preserved as wrapper |
| Parallel execution (rayon) | unified/analyzer.rs | unified/pipeline.rs | + parser pool fix |
| UnifiedOptions (6 fields) | unified/types.rs | unified/types.rs | + 5 new fields |
| UnifiedResult (6 fields) | unified/types.rs | unified/types.rs | + 3 new fields |
| FilePatterns (6 fields) | unified/types.rs | unified/types.rs | + 4 new fields |
| AnalysisMetrics (6 fields) | unified/types.rs | unified/types.rs | + 5 new fields |
| DetectedPattern (12 fields) | unified/types.rs | unified/types.rs | + 4 new fields |
| Language enum (10 variants) | unified/types.rs | core/types.rs | All 10 preserved |
| PatternCategory (15 variants) | unified/types.rs | core/types.rs | + Accessibility |
| DetectionMethod (3 variants) | unified/types.rs | core/types.rs | + VisitorPattern |
| Confidence baselines | unified/ast_patterns.rs | unified/ast_patterns.rs | All values preserved |

### Moved Features (TS → Rust)

| V1 Feature | V1 Location (TS) | V2 Location (Rust) |
|-----------|-------------------|-------------------|
| AST Analyzer (10 methods) | analyzers/ast-analyzer.ts | analyzers/ast.rs |
| Type Analyzer (7 methods) | analyzers/type-analyzer.ts | analyzers/types.rs |
| Semantic Analyzer (4 methods) | analyzers/semantic-analyzer.ts | analyzers/semantic.rs |
| Flow Analyzer (6 methods) | analyzers/flow-analyzer.ts | analyzers/flow.rs |
| 9 language normalizers | unified-provider/*.ts | unified_provider/normalizers/*.rs |
| 20 ORM matchers | unified-provider/*.ts | unified_provider/matchers/*.rs |
| UnifiedCallChain | unified-provider/types.ts | unified_provider/types.rs |
| TS/JS analyzer | typescript/*.ts | lang/typescript.rs |
| Python analyzer | python/*.ts | lang/python.rs |
| Java analyzer | java/*.ts | lang/java.rs |
| Go analyzer | go/*.ts | lang/go.rs |
| Rust analyzer | rust/*.ts | lang/rust_lang.rs |
| C# analyzer | (via unified-provider) | lang/csharp.rs |
| PHP analyzer | php/*.ts | lang/php.rs |
| C++ analyzer | cpp/*.ts | lang/cpp.rs |
| Evaluator core | rules/evaluator.ts | rules/evaluator.rs |

### Features Staying in TypeScript (Thin Layer)

| Feature | Location | Reason |
|---------|----------|--------|
| Quick fix generation (7 strategies) | rules/quick-fix-generator.ts | Text manipulation, presentation |
| Severity manager | rules/severity-manager.ts | Configuration, no hot path |
| Variant manager (3 scopes) | rules/variant-manager.ts | Persistence + querying |
| Rule engine limits (100/pattern, 50/file) | rules/rule-engine.ts | Orchestration |
| Violation dedup by key | rules/rule-engine.ts | Orchestration |
| MCP tool routing | mcp/*.ts | Presentation layer |

### V1 Gaps Fixed in V2

| Gap | V1 Status | V2 Fix |
|-----|-----------|--------|
| Log patterns unused | Compiled but never called in analyze() | Wired into Phase 3 |
| Violation always empty | Vec always empty, never populated | Populated by rules evaluator |
| ResolutionStats all zero | Fields initialized to 0 with TODO | Incremented during resolution |
| Parser pool per-thread | Creates new parser per thread | Bounded crossbeam channel pool |
| Resolution only 3 strategies | Same-file → exported → ambiguous | 6 strategies (+ MRO, DI, import, fuzzy) |

### New V2 Features (Not in V1)

| Feature | Location | Source Decision |
|---------|----------|----------------|
| Visitor pattern engine | unified/visitor.rs | AD4, R1 (detectors) |
| GAST normalization (~30 types) | gast/mod.rs + normalizers/*.rs | R4 (detectors) |
| Declarative TOML patterns | patterns/*.toml + pattern_loader.rs | AD3 |
| Incremental computation (3 layers) | unified/incremental.rs | AD1 |
| Taint analysis integration | taint/mod.rs | AD11, R3 (analyzers) |
| Fix generation as first-class | fixes/mod.rs | R10 (detectors) |
| Feedback loop / detector health | health/mod.rs | R5 (detectors) |
| Cancellation support | core/cancellation.rs | R12 (analyzers) |
| Moka parse cache | cache/parse_cache.rs | AD12 |
| Per-language TypeSystem trait | analyzers/type_system.rs | R4 (analyzers) |
| Per-language ScopeResolver trait | analyzers/scope_resolver.rs | R4 (analyzers) |
| Interprocedural data flow | analyzers/data_flow.rs | R6 (analyzers) |
| CWE/OWASP mapping on patterns | core/types.rs | R7 (detectors) |
| Accessibility category | core/types.rs | Audit |
| body_hash / signature_hash | unified/resolution.rs | Audit A3 |

---

## 21. Inconsistencies & Decisions

Conflicts found between source documents, resolved here.

### I1: PatternCategory Count

- `data-models.md` lists 15 categories (includes Validation)
- `DRIFT-V2-FULL-SYSTEM-AUDIT.md` lists 16 (adds Accessibility)
- Some detector docs reference only 14 (missing Validation)

Resolution: V2 has 16 categories. All 15 from v1 preserved (including Validation).
Accessibility added as 16th. The Validation category was at risk of being dropped
because some docs omitted it — explicitly preserved here.

### I2: Resolution Algorithm Strategies

- `unified-analysis.md` describes 3 strategies (same-file, exported, ambiguous)
- `DRIFT-V2-FULL-SYSTEM-AUDIT.md` proposes 6 strategies
- `05-CALL-GRAPH-V2-PREP.md` references resolution index but doesn't define strategies

Resolution: V2 has 6 strategies. The 3 v1 strategies are preserved as strategies 1, 5,
and the ambiguous fallback. Strategies 2 (MRO), 3 (DI), 4 (import-based), and 6 (fuzzy)
are new additions.

### I3: String Interning — Custom vs. lasso

- `unified-analysis.md` describes custom StringInterner
- `PLANNING-DRIFT.md` D7 specifies lasso
- `04-INFRASTRUCTURE.md` specifies lasso

Resolution: V2 uses lasso. Custom interner replaced. PathInterner and FunctionInterner
preserved as domain wrappers around lasso.

### I4: Rules Engine Location (Rust vs. TS)

- `DRIFT-V2-FULL-SYSTEM-AUDIT.md` says evaluator core moves to Rust
- `rules-engine.md` v2 notes say "evaluator core is pure computation — ideal for Rust"
- `rules-engine.md` v2 notes say "quick fix generation stays TS"

Resolution: Evaluator core (pattern matching, violation detection) moves to Rust.
Quick fix generation, severity management, variant management, and rule engine
orchestration stay in TypeScript as thin presentation/config layers.

### I5: Bayesian Confidence — Unified Analysis vs. Pattern Intelligence

- Research doc Section 8 places Bayesian scoring in unified analysis
- `DRIFT-V2-STACK-HIERARCHY.md` places it at Level 2A (Pattern Intelligence)

Resolution: Bayesian confidence scoring lives in Pattern Intelligence (Level 2A),
NOT in the unified analysis engine. The unified analysis engine provides the raw
detection data (frequency, consistency, spread) that Pattern Intelligence consumes.
The research doc Section 8 content is reference material for the Pattern Intelligence
system, not for implementation here.

### I6: Taint Analysis — Unified Analysis vs. Separate System

- Research doc Section 9 integrates taint analysis into the pipeline
- `DRIFT-V2-STACK-HIERARCHY.md` doesn't list taint as a separate system

Resolution: Taint analysis is integrated into the unified analysis pipeline as an
optional phase. Phase 1 (intraprocedural) runs within the per-file pipeline.
Phase 2 (interprocedural) requires the call graph and runs as a post-processing step.
Controlled by `UnifiedOptions.enable_taint`.

### I7: DetectionMethod Variants

- V1 has 3 variants: AstQuery, RegexFallback, Structural
- Research doc adds VisitorPattern as 4th

Resolution: V2 has 4 variants. VisitorPattern added for Phase 1.5 detections.
All 3 v1 variants preserved.

---

## 22. Risk Register

| # | Risk | Impact | Likelihood | Mitigation |
|---|------|--------|------------|------------|
| R1 | GAST normalization loses language-specific details | Medium | Medium | Keep raw AST escape hatch via FileDetectorHandler for language-specific detectors |
| R2 | Visitor pattern doesn't handle all detector patterns | High | Low | FileDetectorHandler variant for full-file context; LearningDetectorHandler for two-pass |
| R3 | Incremental cache produces stale results | High | Medium | Force full scan escape hatch (`incremental: false`); cross-file invalidation via signature_hash |
| R4 | 20 ORM matcher port is large effort (~3K lines each) | Medium | High | Prioritize top 7 ORMs by usage; port rest incrementally in Phase 5 |
| R5 | Taint analysis false positives overwhelm developers | Medium | Medium | Sanitizer recognition; configurable sensitivity; off by default (`enable_taint: false`) |
| R6 | Parser pool contention under high parallelism | Low | Low | Bounded crossbeam channel with backpressure; pool size = num_cpus |
| R7 | TOML pattern syntax too complex for users | Medium | Low | Graduated complexity (4 levels); good docs; validation at load time |
| R8 | Type Analyzer multi-language scope creep | Medium | Medium | Start with TS only (P0); add Python/Java via TypeSystem trait incrementally |
| R9 | Semantic Analyzer scope resolution accuracy varies by language | Medium | Medium | Per-language ScopeResolver trait; start with TS; measure resolution rate |
| R10 | Flow Analyzer interprocedural analysis is expensive | Medium | Medium | Function summaries are lazy (computed on demand); intraprocedural first |
| R11 | WPF/XAML analyzer requires dedicated tree-sitter grammar | Low | High | Defer to Phase 7; evaluate based on user demand |
| R12 | Cancellation token overhead on hot path | Low | Low | Check every 1024 nodes (not every node); atomic load is ~1ns |
| R13 | lasso interner freeze (ThreadedRodeo → RodeoReader) blocks pipeline | Medium | Low | Freeze happens once after all parsing complete; pipeline is sequential at that point |
| R14 | bincode serialization for parse cache is fragile across versions | Medium | Medium | Version tag in cache entries; invalidate cache on drift version upgrade |

---

*End of Unified Analysis Engine V2 Implementation Prep.*
*Sections 1-6: Core pipeline, visitor engine, resolution index.*
*Sections 7-9: GAST, declarative patterns, incremental computation.*
*Sections 10-12: Core analyzers, unified provider, per-language analyzers.*
*Sections 13-17: String interning, storage, NAPI, events, tracing.*
*Sections 18-22: Build order, performance, cross-reference, inconsistencies, risks.*
*Every v1 feature accounted for. Zero feature loss. Build-ready.*
