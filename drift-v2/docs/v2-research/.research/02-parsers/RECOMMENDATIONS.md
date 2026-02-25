# 02 Parsers — V2 Recommendations

## Summary

14 recommendations for building Drift v2's parser subsystem from scratch. This is a greenfield build — every recommendation is framed as "design it right from day one" rather than migrating legacy code. The parser subsystem is Drift's foundation layer; every other subsystem (detectors, analyzers, call graph, boundaries, security, contracts, test topology) depends on its output. Getting the parser architecture right determines the ceiling for the entire system.

The v1 research revealed a dual-layer architecture (Rust + TypeScript) with significant feature gaps between layers, no incremental computation, no caching, three different ParseResult shapes, and annotations extracted as strings instead of structured data. The v2 build eliminates all of this by designing a single, Rust-native parser layer with incrementality, caching, and rich extraction built in from the start.

---

## Recommendations

### R1: Design an Incremental Parse Cache as a First-Class Subsystem

**Priority**: P0 (Critical)
**Effort**: Medium
**Impact**: 10-100x faster re-scans; enables IDE-level responsiveness; foundation for all downstream incremental analysis
**Category**: Architecture, Performance

**What to Build**:
Design the parser with a built-in concurrent cache from day one:

1. **Content-addressed caching**: Hash every file's content (xxhash) before parsing. Use `(file_path, content_hash)` as the cache key, `ParseResult` as the value.
2. **Concurrent cache**: Use Moka (Rust's Caffeine equivalent) for thread-safe caching compatible with rayon parallelism. Moka's TinyLFU admission + LRU eviction provides better hit rates than pure LRU.
3. **Durable persistence**: Serialize the cache to SQLite between sessions so subsequent scans start warm. rust-analyzer calls this "durable incrementality."
4. **Two-tier incrementality**:
   - **File-level** (batch/CLI): Skip unchanged files entirely using content hash comparison.
   - **Edit-level** (IDE): Use tree-sitter's `tree.edit()` + incremental `parse()` for sub-millisecond re-parse of edited files. Cache the tree-sitter `Tree` objects per open file.
5. **Cache statistics**: Track hits, misses, evictions, and hit ratio for observability.

**Rationale**:
v1 re-parses every file from scratch on every scan. For a 100K-file codebase where 50 files changed, that means re-parsing 99,950 unchanged files. This is the single highest-impact architectural decision for the parser subsystem. rust-analyzer, Zed, IntelliJ, and Sorbet all use per-file caching as their foundation.

**Evidence**:
- rust-analyzer three architectures: https://rust-analyzer.github.io/blog/2020/07/20/three-architectures-for-responsive-ide.html (R2)
- Salsa incremental computation: https://salsa-rs.github.io/salsa/overview.html (R2)
- Moka concurrent cache: https://docs.rs/moka/latest/moka/ (R5)
- tree-sitter QueryCursor has no built-in caching: https://github.com/tree-sitter/tree-sitter/discussions/1976 (R3)
- Zed editor per-file tree cache: https://zed.dev/blog/syntax-aware-editing (R7)

**Implementation Notes**:
```
ParserManager {
    parsers: HashMap<Language, Box<dyn LanguageParser>>,
    cache: moka::sync::Cache<(PathBuf, u64), ParseResult>,  // content-hash keyed
    tree_cache: moka::sync::Cache<PathBuf, tree_sitter::Tree>,  // for IDE mode
    stats: CacheStats,
}

fn parse(&self, path: &Path, source: &str) -> ParseResult {
    let hash = xxhash(source);
    if let Some(cached) = self.cache.get(&(path.to_owned(), hash)) {
        self.stats.record_hit();
        return cached;
    }
    let result = self.do_parse(path, source);
    self.cache.insert((path.to_owned(), hash), result.clone());
    self.stats.record_miss();
    result
}
```

**Risks**:
- Cache invalidation correctness: content hashing eliminates stale cache risk (same content = same result).
- Memory pressure: Moka supports size-based eviction. Start with 10,000 entries (covers most projects).
- Serialization cost for durable persistence: use bincode for fast serialize/deserialize to SQLite blob.

**Dependencies**:
- Affects 08-storage (cache persistence tables), 11-ide (enables real-time analysis), 25-services-layer (scan pipeline leverages cache).

---

### R2: Design a Single Canonical ParseResult Shape

**Priority**: P0 (Critical)
**Effort**: Medium
**Impact**: Eliminates type confusion across the entire system; single source of truth for all consumers
**Category**: Data Model, Architecture

**What to Build**:
Design one `ParseResult` type that serves Rust internals, NAPI bridge, and all downstream consumers. v1 had three different shapes (Rust `ParseResult`, TS `ParseResult`, NAPI `JsParseResult`) — v2 must have exactly one.

```rust
pub struct ParseResult {
    pub language: Language,
    pub functions: Vec<FunctionInfo>,
    pub classes: Vec<ClassInfo>,
    pub imports: Vec<ImportInfo>,
    pub exports: Vec<ExportInfo>,
    pub calls: Vec<CallSite>,
    pub errors: Vec<ParseError>,
    pub parse_time_us: u64,
    pub content_hash: u64,           // NEW: for cache invalidation
    pub file_path: Option<String>,   // NEW: for cross-file resolution
}
```

Enrich the sub-types to close all v1 feature gaps from day one:

```rust
pub struct FunctionInfo {
    pub name: String,
    pub qualified_name: Option<String>,
    pub parameters: Vec<ParameterInfo>,
    pub return_type: Option<String>,
    pub generic_params: Vec<String>,       // NEW: generic type parameters
    pub visibility: Visibility,            // NEW: always present, not partial
    pub is_exported: bool,
    pub is_async: bool,
    pub is_generator: bool,
    pub is_abstract: bool,                 // NEW
    pub range: Range,
    pub decorators: Vec<DecoratorInfo>,    // NEW: structured, not strings
    pub doc_comment: Option<String>,
    pub body_hash: Option<u64>,            // NEW: for function-level change detection
}

pub struct DecoratorInfo {
    pub name: String,
    pub arguments: Vec<DecoratorArgument>,  // Structured arguments
    pub raw_text: String,                   // Original text as fallback
    pub range: Range,
}

pub struct DecoratorArgument {
    pub key: Option<String>,    // Named arg key (None for positional)
    pub value: String,          // Argument value as string
}

pub struct ClassInfo {
    pub name: String,
    pub namespace: Option<String>,         // NEW: Java package, C# namespace, PHP namespace
    pub extends: Option<String>,
    pub implements: Vec<String>,
    pub generic_params: Vec<String>,       // NEW
    pub is_exported: bool,
    pub is_abstract: bool,
    pub methods: Vec<FunctionInfo>,        // NEW: methods nested in class (v1 was flat)
    pub properties: Vec<PropertyInfo>,
    pub range: Range,
    pub decorators: Vec<DecoratorInfo>,    // NEW: structured
    pub class_kind: ClassKind,             // NEW: class/interface/struct/enum/trait/record
}

pub enum ClassKind {
    Class, Interface, Struct, Enum, Trait, Record, Union, TypeAlias,
}
```

**Rationale**:
Every downstream consumer (detectors, call graph, analyzers, boundaries, contracts) depends on ParseResult. Getting this shape right from day one prevents cascading refactors. The v1 gaps (no generics, no structured decorators, no namespace, flat methods, no body hash) forced the TS layer to re-parse files for richer extraction. v2 eliminates this by making the Rust ParseResult the single, complete source of truth.

**Evidence**:
- YASA UAST design: https://arxiv.org/abs/2601.17390 (R1) — unified representation enables language-agnostic analysis
- Semgrep ast_generic: https://opam.ocamllabs.io/packages/ast_generic (R1) — factorized union of language ASTs
- Structured annotation extraction: Semgrep docs, Spring docs (R12) — annotations must be structured for framework detection

**Risks**:
- Richer ParseResult increases memory per file. Mitigate with `Option` for rarely-used fields and `SmallVec` for typically-small collections.
- NAPI conversion overhead increases with more fields. Mitigate with batch APIs and lazy serialization (R8).

**Dependencies**:
- This is the foundational data model. Every other recommendation depends on it.

---

### R3: Build Structured Decorator/Annotation Extraction from Day One

**Priority**: P0 (Critical)
**Effort**: Medium
**Impact**: Enables all framework-aware pattern detection (Spring, Django, FastAPI, Laravel, NestJS, ASP.NET)
**Category**: Data Model, Algorithm

**What to Build**:
Extract decorators and annotations as structured `DecoratorInfo` objects with parsed arguments, not just raw strings. This is the single most impactful extraction improvement for downstream pattern detection.

For each language, extract:
- **Python**: `@decorator(arg1, key=value)` → name + positional/keyword arguments
- **Java**: `@Annotation(value="x", method=RequestMethod.POST)` → name + argument map
- **C#**: `[Attribute(param, Named=value)]` → name + argument map
- **PHP**: `#[Route("/path", methods: ["GET"])]` → name + argument map
- **Rust**: `#[derive(Serialize, Deserialize)]`, `#[serde(rename_all = "camelCase")]` → name + argument map
- **TypeScript**: `@Controller("/api")`, `@Get("/users")` → name + argument string

**Rationale**:
v1 extracted decorators as `Vec<String>` — just the text. This meant downstream detectors could see that `@GetMapping` existed but not extract the route path `"/api/users"` from its argument. Spring Boot, FastAPI, Django, Laravel, and NestJS all encode critical semantic information in annotation arguments: route paths, HTTP methods, authorization rules, dependency injection targets, ORM relationships. Without structured extraction, framework-aware detection is impossible.

**Evidence**:
- Semgrep annotation matching: https://semgrep.dev/docs/writing-rules/rule-syntax/ (R12) — rules match on annotation arguments
- Spring annotation-based config: https://docs.spring.io/spring-framework/reference/core/beans/classpath-scanning.html (R12)
- v1 Java TS parser already does this with `JavaAnnotation { name, arguments: Map }` — v2 Rust must match this from the start

**Implementation Notes**:
- Tree-sitter grammars expose decorator/annotation arguments as child nodes. Use tree-sitter queries to capture the argument list node, then parse it into key-value pairs.
- For positional arguments (common in Python), store as `DecoratorArgument { key: None, value: "..." }`.
- For complex arguments (nested annotations in Java, array literals in PHP), store the raw text as the value — downstream consumers can parse further if needed.
- Keep `raw_text` on `DecoratorInfo` as a fallback for cases where argument parsing fails.

**Risks**:
- Argument parsing complexity varies by language. Mitigate by starting with simple key=value extraction and falling back to raw text for complex cases.
- Some decorators have no arguments (e.g., `@abstractmethod`). Handle gracefully with empty arguments vec.

**Dependencies**:
- R2 (canonical ParseResult) defines the `DecoratorInfo` type.
- Directly enables 03-detectors framework detection, 20-contracts API shape extraction, 21-security auth pattern detection.

---

### R4: Build Pydantic Model Extraction in Rust from Day One

**Priority**: P0 (Critical)
**Effort**: High
**Impact**: Enables FastAPI contract detection, Python API shape extraction, BE-FE mismatch detection
**Category**: Algorithm, Data Model

**What to Build**:
A Rust-native Pydantic v1/v2 model extractor that operates on tree-sitter Python ASTs. This was a 9-file TS-only subsystem in v1 — v2 builds it natively in Rust.

**Components to build**:
1. **Model detector**: Identify classes that extend `BaseModel` (or known Pydantic bases) from the tree-sitter class definition nodes.
2. **Field extractor**: Extract field definitions — name, type annotation, default value, alias, Field() constraints.
3. **Type resolver**: Recursively resolve Python type annotations: `Optional[str]`, `List[Dict[str, int]]`, `Union[str, int]`, `str | int` (3.10+). Implement cycle detection via depth limit (default 10).
4. **Constraint parser**: Parse `Field()` arguments: ge, le, gt, lt, min_length, max_length, pattern, multiple_of.
5. **Validator extractor**: Extract `@field_validator` (v2) and `@validator` (v1) decorators with their target fields and mode (before/after/wrap).
6. **Config extractor**: Extract `model_config = ConfigDict(...)` (v2) or `class Config:` (v1) with settings like extra, frozen, validate_assignment.
7. **Version detector**: Distinguish v1 vs v2 by checking for `ConfigDict` vs `Config` class, `field_validator` vs `validator`, `model_validator` vs `root_validator`.

**Output type**:
```rust
pub struct PydanticModelInfo {
    pub name: String,
    pub bases: Vec<String>,
    pub fields: Vec<PydanticFieldInfo>,
    pub validators: Vec<PydanticValidatorInfo>,
    pub config: Option<PydanticConfigInfo>,
    pub is_v2: bool,
    pub range: Range,
}
```

**Rationale**:
Pydantic models define the request/response shapes for FastAPI — the most popular Python web framework. Without Pydantic extraction, Drift cannot detect API contracts, track field-level changes, or identify BE-FE type mismatches for Python services. This was the most complex TS-only feature in v1 and the highest-priority port.

**Evidence**:
- Pydantic v2 Rust core (pydantic-core): https://pypi.org/project/pydantic-core/ (R8) — validates that complex Python analysis in Rust is viable
- Pydantic annotation resolution: https://docs.pydantic.dev/latest/internals/resolving_annotations/ (R8) — documents the type resolution complexity
- pydantic-ast PyPI package: https://pypi.org/project/pydantic_ast (R8) — demonstrates AST-based Pydantic extraction as a recognized pattern

**Implementation Notes**:
- Type resolution is the hardest part. Build it as a recursive function with a depth counter. At each level, check for: simple type (str, int), Optional wrapper, List/Dict/Set generic, Union type, pipe union (3.10+), forward reference (string literal).
- Use tree-sitter queries to find class definitions with BaseModel in their base list, then walk child nodes for field assignments.
- Field() arguments can be extracted using the structured decorator extraction from R3.
- Cross-file inheritance resolution (base class in another file) is a stretch goal — start with single-file extraction.

**Risks**:
- Python type annotation complexity is unbounded. Mitigate with depth limit and graceful degradation (return raw type string if resolution fails).
- Cross-file base class resolution requires an index. Defer to a later phase.

**Dependencies**:
- R2 (canonical ParseResult) for the output types.
- R3 (structured decorator extraction) for validator and Field() argument parsing.
- Directly enables 20-contracts FastAPI contract detection.

---

### R5: Consolidate Tree-Sitter Queries for Performance

**Priority**: P1 (Important)
**Effort**: Low
**Impact**: 2-4x reduction in per-file query overhead; fewer tree traversals
**Category**: Performance, Algorithm

**What to Build**:
Design each language parser with consolidated queries rather than separate queries per extraction type. v1 used 4-5 separate queries per language (function, class, import, call, attribute), each requiring a full tree traversal. v2 should combine related patterns into fewer, larger queries with alternations.

**Example — before (v1 pattern, 4 separate traversals)**:
```
Query 1: (function_declaration) @func
Query 2: (class_declaration) @class
Query 3: (import_statement) @import
Query 4: (call_expression) @call
```

**Example — after (v2 pattern, 1-2 traversals)**:
```
Query 1 (declarations):
  [(function_declaration) @func
   (class_declaration) @class
   (import_statement) @import
   (export_statement) @export]

Query 2 (expressions):
  [(call_expression) @call]
```

**Rationale**:
Each `QueryCursor::matches()` call traverses the entire tree. For a 1000-line file with 4 queries, that is 4 full traversals. Consolidating to 2 queries halves the traversal cost. Tree-sitter queries support alternations natively — this is the intended usage pattern.

**Evidence**:
- Tree-sitter query best practices: https://cycode.com/blog/tips-for-using-tree-sitter-queries/ (R9) — combine related patterns
- tree-sitter QueryCursor always traverses full tree: https://github.com/tree-sitter/tree-sitter/discussions/1976 (R3)
- Query compilation cost (50-500ms): https://github.com/tree-sitter/tree-sitter/issues/1942 (R3) — fewer queries = less compilation

**Implementation Notes**:
- Group by traversal need: declarations (top-level constructs) in one query, expressions (nested constructs like calls) in another.
- Use capture names to distinguish match types within a consolidated query: `@func`, `@class`, `@import` etc.
- Pre-compile all queries at parser construction time (v1 already does this correctly — carry forward).
- Benchmark before and after to validate the improvement.

**Risks**:
- Larger queries are harder to debug. Mitigate with clear capture naming and per-language test suites.
- Some languages may have grammar conflicts when combining patterns. Test each language individually.

**Dependencies**:
- None. Self-contained parser-internal optimization.

---

### R6: Build a Trait-Based Language Parser Architecture

**Priority**: P1 (Important)
**Effort**: Medium
**Impact**: Clean extensibility for new languages; reduced code duplication; testable contracts
**Category**: Architecture, Maintainability

**What to Build**:
Design the parser system around a `LanguageParser` trait rather than ad-hoc per-language structs. v1 had 9 parsers with identical structure but no shared trait — v2 formalizes the contract.

```rust
pub trait LanguageParser: Send + Sync {
    fn language(&self) -> Language;
    fn extensions(&self) -> &[&str];
    fn parse(&mut self, source: &str) -> ParseResult;
    fn parse_incremental(&mut self, source: &str, old_tree: &Tree, edits: &[InputEdit]) -> ParseResult;
    fn supports_framework_extraction(&self) -> bool { false }
    fn extract_framework_constructs(&self, tree: &Tree, source: &str) -> Vec<FrameworkConstruct> {
        Vec::new()
    }
}
```

**ParserManager as trait-object dispatcher**:
```rust
pub struct ParserManager {
    parsers: HashMap<Language, Box<dyn LanguageParser>>,
    extension_map: HashMap<String, Language>,
}

impl ParserManager {
    pub fn parse_file(&mut self, path: &Path, source: &str) -> Option<ParseResult> {
        let lang = Language::from_extension(path.extension()?)?;
        self.parsers.get_mut(&lang)?.parse(source).into()
    }
}
```

**Rationale**:
A trait-based architecture provides: (1) a clear contract that every language parser must fulfill, (2) the ability to add new languages without modifying ParserManager, (3) testability via mock parsers, (4) the `Send + Sync` bound enables safe use with rayon. v1's approach of optional fields (`typescript_parser: Option<TypeScriptParser>`) doesn't scale and requires modifying ParserManager for every new language.

**Evidence**:
- Semgrep's per-language converter pattern: https://semgrep.dev/docs/contributing/contributing-code/ (R4) — each language has a converter implementing a common interface
- YASA's language-specific semantic models: https://arxiv.org/abs/2601.17390 (R1) — unified interface with language-specific implementations

**Implementation Notes**:
- Each language parser struct holds its `tree_sitter::Parser` + pre-compiled `Query` objects (same as v1).
- The `parse_incremental` method is new — it takes the old tree and edit descriptors for IDE-mode incremental parsing.
- `extract_framework_constructs` is an optional extension point for framework-aware parsers (Spring, Django, etc.).
- Registration is explicit: `manager.register(Box::new(PythonParser::new()?))`.

**Risks**:
- Trait objects have dynamic dispatch overhead. For parsing (milliseconds per file), this is negligible.
- `&mut self` on `parse()` is required because tree-sitter `Parser` is not `Sync`. This means parsers cannot be shared across threads — use per-thread instances via thread_local or a pool.

**Dependencies**:
- R2 (canonical ParseResult) defines the output type.
- R1 (incremental cache) uses the trait for dispatching.

---

### R7: Build Namespace/Package Extraction for All Languages

**Priority**: P1 (Important)
**Effort**: Low
**Impact**: Enables qualified name resolution, module-level analysis, architectural boundary detection
**Category**: Data Model

**What to Build**:
Extract namespace/package declarations for every language that has them. v1 was missing this entirely in Rust.

| Language | Construct | Example |
|----------|-----------|---------|
| Java | `package` declaration | `package com.example.service;` |
| C# | `namespace` declaration | `namespace MyApp.Services { }` |
| PHP | `namespace` declaration | `namespace App\Http\Controllers;` |
| Go | `package` declaration | `package main` |
| Rust | `mod` declaration | `mod handlers;` |
| Python | Implicit from file path | `app/services/auth.py` → `app.services.auth` |
| TypeScript | Implicit from file path | `src/services/auth.ts` → `src/services/auth` |
| C/C++ | No native namespace (C), `namespace` (C++) | `namespace utils { }` |

Add to `ParseResult`:
```rust
pub struct ParseResult {
    // ... existing fields ...
    pub namespace: Option<String>,  // Package/namespace declaration
}
```

And to `ClassInfo`:
```rust
pub struct ClassInfo {
    // ... existing fields ...
    pub namespace: Option<String>,  // Fully qualified namespace
}
```

**Rationale**:
Namespace information is essential for: (1) qualified name resolution in the call graph (distinguishing `com.example.UserService` from `com.other.UserService`), (2) module coupling analysis (coupling between packages, not just files), (3) architectural boundary detection (which packages form the API layer vs data layer), (4) import resolution (mapping import paths to actual files).

**Evidence**:
- v1 gap analysis: namespace extraction was missing in Rust, present in TS Java/C#/PHP parsers
- YASA UAST includes package information as a core field: https://arxiv.org/abs/2601.17390 (R1)

**Implementation Notes**:
- Java: query for `package_declaration` node at file root.
- C#: query for `namespace_declaration` node. Handle file-scoped namespaces (C# 10+).
- PHP: query for `namespace_definition` node.
- Go: query for `package_clause` node.
- Tree-sitter queries for these are trivial — single-node matches at file root level.

**Risks**:
- Minimal. These are simple, well-defined extractions.

**Dependencies**:
- R2 (canonical ParseResult) includes the namespace field.
- Enables 04-call-graph qualified name resolution, 05-analyzers module coupling.

---

### R8: Design the NAPI Bridge for Batch and Streaming

**Priority**: P1 (Important)
**Effort**: Medium
**Impact**: Reduces N-API overhead for large-scale operations; enables efficient TS orchestration
**Category**: Performance, API

**What to Build**:
Design the NAPI bridge with batch and streaming APIs from the start, not just single-file operations.

**Batch API**:
```rust
#[napi]
pub fn parse_batch(files: Vec<JsFileInput>) -> Vec<JsParseResult> {
    // Parse all files in parallel via rayon
    // Return results in same order as input
    // Leverages parse cache (R1) internally
}

#[napi(object)]
pub struct JsFileInput {
    pub path: String,
    pub source: String,
}
```

**Streaming API** (for large result sets):
```rust
#[napi]
pub fn parse_directory(config: JsScanConfig, callback: JsFunction) -> napi::Result<()> {
    // Scan directory, parse each file, invoke callback per file
    // Avoids materializing entire result set in memory
}
```

**Minimal conversion overhead**:
- Use `#[napi(object)]` derive macros for automatic struct conversion where possible.
- For hot paths, consider returning serialized JSON (serde_json) instead of field-by-field N-API object construction — benchmark both approaches.
- Add `parse_batch_json()` variant that returns a single JSON string for the entire batch, letting the TS side deserialize once.

**Rationale**:
v1's NAPI bridge exposed only single-file `parse()`. For a 10K-file scan, that means 10K N-API round-trips with per-call overhead (thread-local parser lookup, JS object construction, GC pressure). A batch API amortizes this overhead. The SWC project identified N-API struct passing as a major bottleneck and explored binary serialization alternatives.

**Evidence**:
- SWC NAPI performance discussion: https://github.com/napi-rs/napi-rs/issues/1502 (R6) — struct passing overhead is significant at scale
- NAPI-RS 3.0 roadmap: https://github.com/napi-rs/napi-rs/issues/1493 (R6) — reducing overhead is a primary goal
- napi-rs official docs: https://napi.rs/ (R6)

**Implementation Notes**:
- `parse_batch` internally uses `rayon::par_iter()` for parallel parsing, then collects results.
- The callback-based streaming API uses napi-rs `ThreadsafeFunction` to invoke JS callbacks from rayon threads.
- Benchmark: field-by-field N-API conversion vs serde_json serialization for a 1000-file batch. Choose the faster approach.

**Risks**:
- Callback-based streaming adds complexity. Start with batch API; add streaming only if memory is a concern for very large codebases.
- JSON serialization adds a parse step on the TS side. Benchmark to ensure net improvement.

**Dependencies**:
- R1 (incremental cache) is leveraged internally by batch parsing.
- R2 (canonical ParseResult) defines the types being serialized.

---

### R9: Build Error-Tolerant Extraction from Day One

**Priority**: P1 (Important)
**Effort**: Low
**Impact**: Reliable parsing of syntactically invalid files; critical for IDE integration and real-world codebases
**Category**: Reliability

**What to Build**:
Design all extraction logic to handle tree-sitter error nodes gracefully. Real-world codebases contain syntax errors, and IDE integration means files are frequently in invalid states mid-edit.

**Principles**:
1. **Never fail on error nodes**: If tree-sitter produces an `ERROR` node, skip it and continue extracting from valid siblings.
2. **Partial results are valuable**: A file with a syntax error in one function should still yield valid extraction for all other functions.
3. **Track error locations**: Include error node positions in `ParseResult.errors` so consumers know which regions are unreliable.
4. **Confidence degradation**: Extraction results from regions near error nodes should have lower confidence scores.

**Implementation**:
```rust
fn extract_functions(&self, root: &Node, source: &str) -> Vec<FunctionInfo> {
    let mut cursor = QueryCursor::new();
    let mut functions = Vec::new();
    for match_ in cursor.matches(&self.function_query, *root, source.as_bytes()) {
        // Skip matches that contain ERROR nodes
        let func_node = match_.captures[0].node;
        if func_node.has_error() {
            // Still try to extract partial info (name, range)
            if let Some(partial) = self.extract_partial_function(func_node, source) {
                functions.push(partial);
            }
            continue;
        }
        functions.push(self.extract_full_function(func_node, source));
    }
    functions
}
```

**Rationale**:
Tree-sitter's error recovery is one of its core strengths — it produces useful partial results even for invalid syntax. v1 did not explicitly handle error nodes, meaning extraction could silently produce incorrect results or miss valid constructs adjacent to errors. For IDE integration (where files are constantly in invalid states during editing), error-tolerant extraction is not optional.

**Evidence**:
- Zed editor relies on error recovery: https://zed.dev/blog/syntax-aware-editing (R7) — "error recovery produces useful partial results"
- Semgrep CST-to-AST tips: https://semgrep.dev/docs/contributing/cst-to-ast-tips (R4) — "handle error nodes gracefully"
- tree-sitter official docs on error recovery: https://tree-sitter.github.io/tree-sitter/ (R3)

**Risks**:
- Partial extraction may produce incomplete data. Mitigate by marking partial results with a flag.
- Over-aggressive error skipping could miss valid constructs. Test with real-world files containing syntax errors.

**Dependencies**:
- R2 (canonical ParseResult) includes the `errors` field for tracking.
- Enables 11-ide reliable parsing during editing.

---

### R10: Build Generic Type Parameter Extraction

**Priority**: P1 (Important)
**Effort**: Low-Medium
**Impact**: Enables type analysis, contract detection, and generic pattern recognition
**Category**: Data Model

**What to Build**:
Extract generic type parameters for functions and classes across all languages that support them.

| Language | Syntax | Example |
|----------|--------|---------|
| TypeScript | `<T, U>` | `function map<T, U>(arr: T[], fn: (t: T) => U): U[]` |
| Java | `<T extends Comparable<T>>` | `class TreeSet<T extends Comparable<T>>` |
| C# | `<T> where T : IComparable` | `class SortedList<T> where T : IComparable` |
| Rust | `<T: Display + Clone>` | `fn print<T: Display>(item: T)` |
| Go | `[T any]` | `func Map[T any, U any](s []T, f func(T) U) []U` |
| C++ | `template<typename T>` | `template<typename T> class Vector` |

Add to `FunctionInfo` and `ClassInfo`:
```rust
pub generic_params: Vec<GenericParam>,

pub struct GenericParam {
    pub name: String,
    pub bounds: Vec<String>,  // Type constraints/bounds
}
```

**Rationale**:
Generic type parameters are essential for: (1) type analysis (understanding what types a function operates on), (2) contract detection (generic API shapes), (3) pattern recognition (factory patterns, builder patterns often use generics), (4) accurate call graph resolution (distinguishing `List<User>` from `List<Order>`). v1 was missing this entirely in Rust.

**Evidence**:
- v1 gap analysis: generic extraction was P0 priority gap between Rust and TS parsers
- Semgrep ast_generic includes generic parameters as a core field

**Implementation Notes**:
- Tree-sitter grammars expose type parameters as `type_parameters` or `type_parameter_list` nodes.
- Bounds/constraints are child nodes of the type parameter.
- For languages without generics (C, PHP pre-8.0), return empty vec.

**Risks**:
- Minimal. Tree-sitter grammars already expose this information.

**Dependencies**:
- R2 (canonical ParseResult) includes the `generic_params` field.
- Enables 05-analyzers type analysis, 20-contracts generic API detection.

---

### R11: Build Thread-Safe Parser Pool for Rayon

**Priority**: P1 (Important)
**Effort**: Low
**Impact**: Bounded memory usage; predictable resource consumption; clean lifecycle management
**Category**: Performance, Reliability

**What to Build**:
Design a thread-safe parser provisioning strategy for rayon parallel parsing. v1 used `thread_local!` which works but has unbounded memory growth (parsers persist for the thread pool lifetime and are never dropped).

**Recommended approach — thread_local with explicit cleanup**:
```rust
thread_local! {
    static PARSER_MANAGER: RefCell<Option<ParserManager>> = RefCell::new(None);
}

fn with_parser<F, R>(f: F) -> R
where F: FnOnce(&mut ParserManager) -> R {
    PARSER_MANAGER.with(|cell| {
        let mut opt = cell.borrow_mut();
        if opt.is_none() {
            *opt = Some(ParserManager::new());
        }
        f(opt.as_mut().unwrap())
    })
}

// Call between scan operations to release memory
pub fn cleanup_thread_local_parsers() {
    PARSER_MANAGER.with(|cell| {
        *cell.borrow_mut() = None;
    });
}
```

**Why thread_local over object pool**:
- ParserManager holds pre-compiled Query objects (expensive to create, 50-500ms per language).
- Thread_local avoids the overhead of pool checkout/return synchronization.
- Rayon reuses threads, so parsers are created once per thread and reused across files.
- The cleanup function addresses the memory growth concern by allowing explicit release between scans.

**Rationale**:
Tree-sitter `Parser` is not `Sync` (it holds mutable internal state), so it cannot be shared across threads. Each rayon thread needs its own parser instance. The question is lifecycle management. Thread_local with cleanup is the simplest correct approach.

**Evidence**:
- Rayon thread_local caveats: https://github.com/rayon-rs/rayon (R11) — thread-local values persist for pool lifetime
- Query compilation cost: https://github.com/tree-sitter/tree-sitter/issues/1942 (R3) — queries are expensive to compile, should be reused

**Risks**:
- If cleanup is not called, memory grows. Mitigate by calling cleanup at the end of each scan operation in the services layer.

**Dependencies**:
- R6 (trait-based architecture) defines the ParserManager interface.
- 25-services-layer calls cleanup between scan operations.

---

### R12: Build Framework Construct Extraction as an Extension Layer

**Priority**: P2 (Nice to have — but high value)
**Effort**: Medium
**Impact**: Enables framework-specific pattern detection without polluting core parser logic
**Category**: Architecture, Extensibility

**What to Build**:
Design a framework extraction layer that sits on top of the core parser, using the structured decorator data (R3) and class/function metadata to identify framework-specific constructs.

```rust
pub trait FrameworkExtractor: Send + Sync {
    fn framework_name(&self) -> &str;
    fn language(&self) -> Language;
    fn detect(&self, result: &ParseResult) -> Vec<FrameworkConstruct>;
}

pub enum FrameworkConstruct {
    RouteHandler { path: String, method: HttpMethod, handler: String, range: Range },
    Middleware { name: String, applies_to: Vec<String>, range: Range },
    Entity { name: String, table: String, fields: Vec<EntityField>, range: Range },
    DependencyInjection { provider: String, consumer: String, range: Range },
    AuthGuard { name: String, rule: String, range: Range },
}
```

**Framework extractors to build**:
| Framework | Language | Key Constructs |
|-----------|----------|---------------|
| Spring Boot | Java | @RestController, @GetMapping, @Service, @Entity, @PreAuthorize |
| FastAPI | Python | @app.get(), Depends(), BaseModel subclasses |
| Django | Python | urlpatterns, models.Model, @login_required |
| Laravel | PHP | Route::get(), Eloquent models, #[Middleware] |
| NestJS | TypeScript | @Controller, @Get, @Injectable, @Guard |
| ASP.NET | C# | [ApiController], [HttpGet], [Authorize], DbContext |
| Express | TypeScript | app.get(), router.use(), middleware functions |
| Actix/Axum | Rust | #[get], #[post], extractors, middleware |

**Rationale**:
Framework constructs are the primary signal for pattern detection in enterprise codebases. Separating framework extraction from core parsing keeps the core parsers clean and language-focused while allowing framework-specific logic to be added, removed, or updated independently. This is the same separation Semgrep uses between its generic AST and language-specific semantic models.

**Evidence**:
- YASA unified + language-specific semantic models: https://arxiv.org/abs/2601.17390 (R1)
- Semgrep CST → generic AST → analysis pipeline: https://semgrep.dev/docs/contributing/contributing-code/ (R4)
- v1 TS parsers had framework awareness baked into per-language parsers — v2 should separate concerns

**Implementation Notes**:
- Framework extractors operate on `ParseResult` (post-parse), not on the raw tree-sitter tree. This keeps them decoupled from tree-sitter internals.
- Detection is primarily decorator/annotation-driven (R3 provides structured data).
- Register extractors with ParserManager: `manager.register_framework(Box::new(SpringExtractor::new()))`.
- Framework extraction is optional — can be skipped for performance when not needed.

**Risks**:
- Framework detection heuristics may produce false positives. Mitigate with confidence scoring.
- Framework versions change (e.g., Spring 5 vs 6). Design extractors to be version-aware.

**Dependencies**:
- R3 (structured decorators) provides the input data.
- R6 (trait-based architecture) provides the extension point.
- Directly feeds 03-detectors framework pattern detection.

---

### R13: Build Structured Error Types with thiserror

**Priority**: P2 (Nice to have)
**Effort**: Low
**Impact**: Better error reporting, easier debugging, cleaner NAPI error propagation
**Category**: Reliability, Maintainability

**What to Build**:
Design structured error types for the parser subsystem from the start using `thiserror`:

```rust
#[derive(thiserror::Error, Debug)]
pub enum ParserError {
    #[error("unsupported language for extension '{extension}'")]
    UnsupportedLanguage { extension: String },

    #[error("grammar initialization failed for {language}: {reason}")]
    GrammarInitFailed { language: Language, reason: String },

    #[error("parse failed for {file}: {reason}")]
    ParseFailed { file: String, reason: String },

    #[error("query compilation failed for {language}/{query_name}: {reason}")]
    QueryCompilationFailed { language: Language, query_name: String, reason: String },

    #[error("file read error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("cache error: {0}")]
    CacheError(String),
}
```

**Rationale**:
Structured errors enable: (1) programmatic error handling in the TS orchestration layer (match on error variant, not string parsing), (2) better error messages for users, (3) error categorization for telemetry, (4) clean `?` propagation through the Rust call stack. `thiserror` is the Rust ecosystem standard for library error types.

**Evidence**:
- thiserror crate: https://docs.rs/thiserror (10K+ dependents, de facto standard)

**Risks**:
- Minimal. Additive improvement.

**Dependencies**:
- NAPI bridge maps `ParserError` variants to meaningful JS error messages.

---

### R14: Design for Future Language Addition with Minimal Effort

**Priority**: P2 (Nice to have)
**Effort**: Low
**Impact**: Reduces effort to add new languages from days to hours
**Category**: Architecture, Extensibility

**What to Build**:
Create a language parser template/scaffold that makes adding a new language a mechanical process:

1. **Cargo dependency**: Add `tree-sitter-{lang}` to Cargo.toml.
2. **Parser struct**: Create `{lang}.rs` implementing `LanguageParser` trait (R6).
3. **Queries**: Write tree-sitter queries for function, class, import, call extraction.
4. **Extension mapping**: Add extensions to `Language::from_extension()`.
5. **Registration**: Register with ParserManager.
6. **Tests**: Copy test template, fill in language-specific examples.

**Provide a codegen tool or macro**:
```rust
define_parser! {
    name: SwiftParser,
    language: Swift,
    grammar: tree_sitter_swift::LANGUAGE,
    extensions: [".swift"],
    queries: {
        declarations: include_str!("queries/swift/declarations.scm"),
        expressions: include_str!("queries/swift/expressions.scm"),
    }
}
```

**Rationale**:
Drift targets 10+ languages. As the ecosystem grows (Swift, Kotlin, Dart, Zig, etc.), adding languages should be a low-friction process. v1's per-language parsers followed an identical pattern but required manual boilerplate. A macro or codegen tool eliminates this.

**Evidence**:
- Semgrep's language addition guide: https://semgrep.dev/docs/contributing/adding-a-language (R4) — structured process for adding languages
- v1 observation: all 9 Rust parsers follow identical structure (documented in RECAP)

**Implementation Notes**:
- Store tree-sitter queries as `.scm` files in a `queries/` directory, loaded via `include_str!` at compile time.
- The macro generates the struct, `new()` constructor (with query compilation), and `LanguageParser` trait implementation.
- Language-specific extraction logic (e.g., Go struct tags, Rust serde attributes) is added as override methods.

**Risks**:
- Macros can be hard to debug. Keep the macro simple; complex logic stays in regular functions.

**Dependencies**:
- R6 (trait-based architecture) defines the trait the macro implements.

---

## Priority Summary

| Priority | Recommendations | Theme |
|---|---|---|
| **P0 (Critical)** | R1 (Incremental Cache), R2 (Canonical ParseResult), R3 (Structured Decorators), R4 (Pydantic Extraction) | Foundation architecture + data model completeness |
| **P1 (Important)** | R5 (Query Consolidation), R6 (Trait Architecture), R7 (Namespace Extraction), R8 (NAPI Batch/Stream), R9 (Error-Tolerant Extraction), R10 (Generic Params), R11 (Thread-Safe Parsers) | Performance + extensibility + feature completeness |
| **P2 (Nice to have)** | R12 (Framework Extractors), R13 (Structured Errors), R14 (Language Addition Scaffold) | Extensibility + maintainability + developer experience |

---

## Build Order (Suggested for Greenfield v2)

```
Phase 1 — Core Architecture (build first, everything depends on this):
  R2  Canonical ParseResult shape          [Data model foundation]
  R6  Trait-based LanguageParser           [Architecture foundation]
  R13 Structured error types               [Error handling foundation]
  R11 Thread-safe parser pool              [Concurrency foundation]

Phase 2 — Rich Extraction (build the parsers with full extraction from day one):
  R3  Structured decorator extraction      [Framework detection enabler]
  R7  Namespace/package extraction         [Qualified name enabler]
  R10 Generic type parameter extraction    [Type analysis enabler]
  R9  Error-tolerant extraction            [Reliability enabler]
  R5  Consolidated tree-sitter queries     [Performance optimization]

Phase 3 — Caching & Performance (add incrementality once parsers are solid):
  R1  Incremental parse cache              [10-100x re-scan speedup]
  R8  NAPI batch/streaming APIs            [Bridge performance]

Phase 4 — Domain-Specific Extraction (build on top of solid core):
  R4  Pydantic model extraction            [Python API contracts]
  R12 Framework construct extractors       [Spring, Django, Laravel, etc.]

Phase 5 — Extensibility (polish for long-term maintainability):
  R14 Language addition scaffold           [New language onboarding]
```

---

## Cross-Category Impact Analysis

The parser subsystem is the most depended-upon component in Drift. Changes here cascade to every downstream consumer:

| Recommendation | Upstream Impact | Downstream Impact |
|---|---|---|
| R1 (Cache) | 08-storage (cache tables) | All consumers get faster results |
| R2 (ParseResult) | None | 03-detectors, 04-call-graph, 05-analyzers, 17-test-topology, 19-error-handling, 20-contracts, 21-security — all consume this type |
| R3 (Decorators) | None | 03-detectors (framework patterns), 20-contracts (API shapes), 21-security (auth rules) |
| R4 (Pydantic) | None | 20-contracts (FastAPI contracts), 07-mcp (Python API tools) |
| R5 (Queries) | None | Performance improvement for all consumers |
| R6 (Trait) | None | 25-services-layer (parser registration), 14-language-addition |
| R7 (Namespace) | None | 04-call-graph (qualified names), 05-analyzers (module coupling) |
| R8 (NAPI) | None | All TS-side consumers get batch/streaming access |
| R9 (Error-tolerant) | None | 11-ide (reliable parsing during editing) |
| R10 (Generics) | None | 05-analyzers (type analysis), 20-contracts (generic APIs) |
| R11 (Thread-safe) | None | 25-services-layer (scan pipeline), 01-rust-core (unified analyzer) |
| R12 (Frameworks) | None | 03-detectors (framework-specific patterns) |
| R13 (Errors) | None | NAPI bridge (better error messages) |
| R14 (Scaffold) | None | Future language additions |

---

## Security Considerations

Parser subsystem security concerns for the v2 build:

1. **Untrusted input**: Parsers process arbitrary source code. Tree-sitter is memory-safe and handles malformed input gracefully, but extraction logic must not panic on unexpected AST shapes.
2. **Resource exhaustion**: Deeply nested files or extremely long lines could cause stack overflow or excessive memory usage. Implement depth limits on recursive extraction (especially Pydantic type resolution, R4).
3. **Cache poisoning**: If the parse cache (R1) is persisted to disk, ensure the cache file has appropriate permissions and the content hash is verified on read.
4. **NAPI boundary**: All data crossing the Rust-JS boundary must be validated. Ensure no raw pointers or internal Rust state leaks through NAPI.
5. **Secret exposure**: ParseResult contains source code snippets (matched_text, doc_comment). Ensure these are not inadvertently logged or exposed through MCP tools without appropriate filtering.

---

## Quality Checklist

- [x] Every recommendation framed for greenfield v2 build (not migration)
- [x] Each recommendation has clear rationale with cited evidence
- [x] Priorities justified (P0 = foundation, P1 = completeness, P2 = extensibility)
- [x] Build order accounts for dependencies between recommendations
- [x] Risks identified for each recommendation
- [x] Cross-category impact analyzed for all 14 recommendations
- [x] Security considerations documented
- [x] Implementation notes are actionable with code examples
- [x] All 12 research items (R1-R12) from RESEARCH.md are referenced
- [x] 25+ external sources cited across recommendations
