# Parsers — Complete V2 Specification

> System: Tree-sitter AST extraction across 10 languages
> Hierarchy: Level 0 — Bedrock
> Dependencies: Scanner, Configuration, thiserror, tracing, DriftEventHandler
> Consumers: Every analysis system (detectors, call graph, boundaries, taint, contracts, test topology, error handling, DNA, constraints, unified analysis engine)
> Source: Synthesized from 01-PARSERS research, .research/02-parsers/RECOMMENDATIONS.md (R1-R14), DRIFT-V2-FULL-SYSTEM-AUDIT.md (Cat 02, A3), DRIFT-V2-STACK-HIERARCHY.md, PLANNING-DRIFT.md, 02-parsers/* research docs

---

## Why This System Matters

The parser system is the single most critical system in Drift. Every analysis path starts with parsed ASTs — zero detectors, zero call graph, zero boundaries, zero taint, zero contracts, zero test topology, zero error handling, zero DNA, zero constraints work without it. Getting the parser architecture right determines the ceiling for the entire system.

---

## 1. Core Library: tree-sitter (v0.25+)

tree-sitter is the clear choice. No other parser generator offers:
- Incremental parsing (sub-millisecond re-parse after edits)
- Error recovery (produces partial ASTs even with syntax errors)
- Concrete syntax trees (lossless — can regenerate source)
- S-expression query language for pattern matching
- 100+ community-maintained grammars
- Production-proven: GitHub, Neovim, Helix, Zed, Difftastic, ast-grep

All grammars compiled to C at build time, linked statically. No WASM, no dynamic loading.

### Per-Language Grammar Crates

| Language | Crate | Maturity | Extensions |
|----------|-------|----------|------------|
| TypeScript | `tree-sitter-typescript` | Excellent (tree-sitter org) | `.ts`, `.tsx`, `.mts`, `.cts` |
| JavaScript | `tree-sitter-javascript` | Excellent (tree-sitter org) | `.js`, `.jsx`, `.mjs`, `.cjs` |
| Python | `tree-sitter-python` | Excellent | `.py`, `.pyi` |
| Java | `tree-sitter-java` | Good | `.java` |
| C# | `tree-sitter-c-sharp` | Good | `.cs` |
| PHP | `tree-sitter-php` | Good | `.php` |
| Go | `tree-sitter-go` | Excellent | `.go` |
| Rust | `tree-sitter-rust` | Excellent (tree-sitter org) | `.rs` |
| C | `tree-sitter-c` | Excellent | `.c`, `.h` |
| C++ | `tree-sitter-cpp` | Good | `.cpp`, `.cc`, `.cxx`, `.hpp`, `.hh`, `.hxx` |

---

## 2. Canonical Data Model (Single Source of Truth)

v1 had three different ParseResult shapes (Rust, TS, NAPI). v2 has exactly one. Rust defines it. NAPI serializes it. TS consumes it. No three-shape problem.

### ParseResult

```rust
pub struct ParseResult {
    pub language: Language,
    pub functions: Vec<FunctionInfo>,
    pub classes: Vec<ClassInfo>,
    pub imports: Vec<ImportInfo>,
    pub exports: Vec<ExportInfo>,
    pub calls: Vec<CallSite>,
    pub errors: Vec<ParseError>,
    pub has_errors: bool,
    pub error_ranges: Vec<Range>,
    pub parse_time_us: u64,
    pub content_hash: u64,            // xxh3 — for cache invalidation
    pub file_path: Option<String>,    // for cross-file resolution
    pub namespace: Option<String>,    // Java package, C# namespace, PHP namespace, Go package
}
```

### FunctionInfo

```rust
pub struct FunctionInfo {
    pub name: String,                       // interned via lasso
    pub qualified_name: Option<String>,     // class.method or module.function
    pub file: PathBuf,
    pub line: u32,
    pub column: u32,
    pub end_line: u32,
    pub parameters: Vec<ParameterInfo>,
    pub return_type: Option<String>,
    pub generic_params: Vec<GenericParam>,  // <T: Display, U>
    pub visibility: Visibility,             // always present
    pub is_exported: bool,
    pub is_async: bool,
    pub is_generator: bool,
    pub is_abstract: bool,
    pub range: Range,
    pub decorators: Vec<DecoratorInfo>,     // structured, not strings
    pub doc_comment: Option<String>,
    pub body_hash: u64,                     // xxh3 of function body text
    pub signature_hash: u64,                // xxh3 of signature (name + params + return type)
}
```

### DecoratorInfo (Structured — Not Strings)

v1 extracted decorators as `Vec<String>`. v2 extracts structured data with parsed arguments. This is the single most impactful extraction improvement — framework detection (Spring, Django, FastAPI, Laravel, NestJS, ASP.NET) depends on annotation argument values, not just names.

```rust
pub struct DecoratorInfo {
    pub name: String,
    pub arguments: Vec<DecoratorArgument>,
    pub raw_text: String,                   // original text as fallback
    pub range: Range,
}

pub struct DecoratorArgument {
    pub key: Option<String>,    // named arg key (None for positional)
    pub value: String,          // argument value as string
}
```

Per-language extraction targets:
- Python: `@decorator(arg1, key=value)` → name + positional/keyword arguments
- Java: `@Annotation(value="x", method=RequestMethod.POST)` → name + argument map
- C#: `[Attribute(param, Named=value)]` → name + argument map
- PHP: `#[Route("/path", methods: ["GET"])]` → name + argument map
- Rust: `#[derive(Serialize)]`, `#[serde(rename_all = "camelCase")]` → name + argument map
- TypeScript: `@Controller("/api")`, `@Get("/users")` → name + argument string

### ClassInfo

```rust
pub struct ClassInfo {
    pub name: String,
    pub namespace: Option<String>,          // fully qualified namespace
    pub extends: Option<String>,
    pub implements: Vec<String>,
    pub generic_params: Vec<GenericParam>,
    pub is_exported: bool,
    pub is_abstract: bool,
    pub class_kind: ClassKind,              // class/interface/struct/enum/trait/record
    pub methods: Vec<FunctionInfo>,         // methods nested in class (v1 was flat)
    pub properties: Vec<PropertyInfo>,
    pub range: Range,
    pub decorators: Vec<DecoratorInfo>,
}

pub enum ClassKind {
    Class, Interface, Struct, Enum, Trait, Record, Union, TypeAlias,
}
```

### GenericParam

```rust
pub struct GenericParam {
    pub name: String,
    pub bounds: Vec<String>,  // type constraints/bounds
}
```

Extraction per language:
- TypeScript: `<T, U>` → `function map<T, U>(...)`
- Java: `<T extends Comparable<T>>` → `class TreeSet<T extends Comparable<T>>`
- C#: `<T> where T : IComparable` → `class SortedList<T> where T : IComparable`
- Rust: `<T: Display + Clone>` → `fn print<T: Display>(item: T)`
- Go: `[T any]` → `func Map[T any, U any](...)`
- C++: `template<typename T>` → `template<typename T> class Vector`

### Supporting Types

```rust
pub struct ParameterInfo {
    pub name: String,
    pub type_annotation: Option<String>,
    pub default_value: Option<String>,
    pub is_rest: bool,                    // variadic/rest parameter
}

pub struct PropertyInfo {
    pub name: String,
    pub type_annotation: Option<String>,
    pub is_static: bool,
    pub is_readonly: bool,
    pub visibility: Visibility,
    pub tags: Option<Vec<StructTag>>,     // Go struct tags, serde attrs
}

pub struct StructTag {
    pub key: String,    // e.g., "json", "gorm", "validate", "serde"
    pub value: String,
}

pub enum Visibility { Public, Private, Protected }

pub struct ImportInfo {
    pub source: String,
    pub named: Vec<String>,
    pub default: Option<String>,
    pub namespace: Option<String>,
    pub is_type_only: bool,
    pub range: Range,
}

pub struct ExportInfo {
    pub name: String,
    pub original_name: Option<String>,
    pub from_source: Option<String>,
    pub is_type_only: bool,
    pub is_default: bool,
    pub range: Range,
}

pub struct CallSite {
    pub callee: String,
    pub receiver: Option<String>,  // e.g., "db" in db.query()
    pub arg_count: usize,
    pub range: Range,
}

pub struct Position { pub line: u32, pub column: u32 }
pub struct Range { pub start: Position, pub end: Position }
pub struct ParseError { pub message: String, pub range: Range }
```

---

## 3. Parser Architecture

### Trait-Based Language Parsers

v1 had 9 parsers with identical structure but no shared trait. v2 formalizes the contract:

```rust
pub trait LanguageParser: Send + Sync {
    fn language(&self) -> Language;
    fn extensions(&self) -> &[&str];
    fn parse(&mut self, source: &str) -> Result<ParseResult, ParseError>;
    fn parse_incremental(
        &mut self,
        source: &str,
        old_tree: &Tree,
        edits: &[InputEdit],
    ) -> Result<ParseResult, ParseError>;
    fn supports_framework_extraction(&self) -> bool { false }
    fn extract_framework_constructs(
        &self,
        tree: &Tree,
        source: &str,
    ) -> Vec<FrameworkConstruct> {
        Vec::new()
    }
}
```

Benefits:
- Clear contract every language parser must fulfill
- New languages added without modifying ParserManager
- Testable via mock parsers
- `Send + Sync` bound enables safe use with rayon

### ParserManager (Trait-Object Dispatcher)

```rust
pub struct ParserManager {
    parsers: HashMap<Language, Box<dyn LanguageParser>>,
    extension_map: HashMap<String, Language>,
    cache: moka::sync::Cache<(PathBuf, u64), ParseResult>,
    framework_extractors: Vec<Box<dyn FrameworkExtractor>>,
    stats: CacheStats,
}

impl ParserManager {
    pub fn parse_file(&mut self, path: &Path, source: &str) -> Option<ParseResult> {
        let lang = Language::from_extension(path.extension()?)?;
        self.parsers.get_mut(&lang)?.parse(source).ok()
    }

    pub fn register(&mut self, parser: Box<dyn LanguageParser>) { ... }
    pub fn register_framework(&mut self, extractor: Box<dyn FrameworkExtractor>) { ... }
}
```

### Thread Safety: thread_local! with Explicit Cleanup

Tree-sitter `Parser` is NOT `Send` — it holds mutable internal state. Each rayon worker thread needs its own parser instance.

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

/// Call between scan operations to release memory
pub fn cleanup_thread_local_parsers() {
    PARSER_MANAGER.with(|cell| {
        *cell.borrow_mut() = None;
    });
}
```

Why thread_local over object pool:
- ParserManager holds pre-compiled Query objects (expensive: 50-500ms per language)
- thread_local avoids pool checkout/return synchronization overhead
- Rayon reuses threads, so parsers are created once per thread and reused across files
- Cleanup function addresses memory growth between scans

### Language Addition Scaffold

Adding a new language should be mechanical. Provide a `define_parser!` macro:

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

The macro generates the struct, `new()` constructor (with query compilation), and `LanguageParser` trait implementation. Language-specific extraction logic (Go struct tags, Rust serde attributes) is added as override methods.

Steps to add a language:
1. Add `tree-sitter-{lang}` to Cargo.toml
2. Create `{lang}.rs` implementing `LanguageParser` trait
3. Write tree-sitter queries for function, class, import, call extraction
4. Add extensions to `Language::from_extension()`
5. Register with ParserManager
6. Copy test template, fill in language-specific examples

---

## 4. Query Architecture (S-Expression Queries)

This is the most important architectural decision for parser performance.

### Pre-Compiled, Consolidated Queries

v1 used 4-5 separate queries per language, each requiring a full tree traversal. v2 consolidates to 2 traversals per file:

1. **Structure query**: functions, classes, imports, exports, decorators, inheritance
2. **Call site query**: function calls, method calls, constructor calls

```scheme
;; Combined structure query (multiple patterns in one Query)
(function_item name: (identifier) @fn_name) @function
(impl_item type: (type_identifier) @class_name) @class
(use_declaration argument: (_) @import_path) @import
```

Tree-sitter supports multiple patterns in one query — each match tells you which pattern matched via the pattern index. This halves traversal cost.

### Query Compilation Strategy

Queries compiled once at startup, reused across all files of the same language:

```rust
struct LanguageQueries {
    structure: Query,    // functions, classes, imports, exports, decorators
    calls: Query,        // function calls, method calls, constructor calls
}

lazy_static! {
    static ref TYPESCRIPT_QUERIES: LanguageQueries = compile_queries(Language::TypeScript);
    static ref PYTHON_QUERIES: LanguageQueries = compile_queries(Language::Python);
    // ... per language
}
```

Store tree-sitter queries as `.scm` files in a `queries/` directory, loaded via `include_str!` at compile time.

### Query Predicates

Key tree-sitter query features used:
- `@name` captures nodes into named variables
- `#match?` applies regex predicates to captures
- `#eq?` checks exact string equality
- `(_)` is a wildcard matching any node type
- Field names (`name:`, `parameters:`) constrain which child is matched

```scheme
;; Match function calls with string arguments
((call_expression
  function: (_) @fn_name
  arguments: (arguments (string_literal) @arg))
 (#match? @fn_name "std::env::(var|remove_var)"))
```

---

## 5. Parse Cache (Moka + SQLite Persistence)

### Why Cache Parses?

Parsing is fast (~6ms for a 2000-line file) but adds up across 100K files. Content-addressed caching means unchanged files are never re-parsed. This is the single highest-impact architectural decision for re-scan performance — 10-100x faster.

### In-Memory: Moka (TinyLFU + LRU)

Moka is a concurrent cache inspired by Java's Caffeine. TinyLFU admission + LRU eviction provides near-optimal hit rates.

```rust
use moka::sync::Cache;

let parse_cache: Cache<(PathBuf, u64), ParseResult> = Cache::builder()
    .max_capacity(10_000)
    .time_to_live(Duration::from_secs(3600))
    .build();

// Key: (file_path, content_hash)
// Value: ParseResult
```

Properties:
- Thread-safe (lock-free reads, fine-grained locking for writes)
- TinyLFU admission prevents cache pollution from one-time accesses
- 10K entry capacity covers most projects
- Track hits, misses, evictions, hit ratio for observability

### Durable Persistence: SQLite

Parse results survive process restarts via bincode serialization to a SQLite blob column:

```sql
CREATE TABLE parse_cache (
    path TEXT NOT NULL,
    content_hash BLOB NOT NULL,
    parse_result BLOB NOT NULL,  -- bincode-serialized ParseResult
    cached_at INTEGER NOT NULL,
    PRIMARY KEY (path, content_hash)
) STRICT;
```

On startup: load hot entries from SQLite into Moka. On cache miss: parse, store in Moka AND SQLite.

### Two-Tier Incrementality

1. **File-level (batch/CLI)**: Skip unchanged files entirely using content hash comparison against `file_metadata` table
2. **Edit-level (IDE)**: Use tree-sitter's `tree.edit()` + incremental `parse()` for sub-millisecond re-parse of edited files. Cache tree-sitter `Tree` objects per open file.

### Cache Lookup Flow

```rust
fn parse(&self, path: &Path, source: &str) -> ParseResult {
    let hash = xxh3_hash(source);
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

---

## 6. Error-Tolerant Parsing

Tree-sitter is inherently error-tolerant — it produces `ERROR` nodes where it can't parse but continues parsing the rest of the file. This is critical for real-world codebases and IDE integration where files are frequently in invalid states mid-edit.

### Strategy

1. **Never fail on error nodes**: Skip ERROR nodes, continue extracting from valid siblings
2. **Partial results are valuable**: A file with a syntax error in one function still yields valid extraction for all other functions
3. **Track error locations**: Include error node positions in `ParseResult.errors`
4. **Attempt partial extraction**: Even from error regions, try to extract name and range

```rust
fn extract_functions(&self, root: &Node, source: &str) -> Vec<FunctionInfo> {
    let mut cursor = QueryCursor::new();
    let mut functions = Vec::new();
    for match_ in cursor.matches(&self.function_query, *root, source.as_bytes()) {
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

### Metrics

Track error recovery rate per language for observability. Log warnings with file path and error node location. Return `ParseResult` with `has_errors: true` flag.

---

## 7. Body Hash & Signature Hash (Function-Level Change Detection)

Add `body_hash: u64` and `signature_hash: u64` fields to `FunctionInfo`. This enables function-level change detection:

- When only a function body changes (not its signature), only that function's analysis is invalidated
- Cross-file analysis (call graph edges based on signatures) is preserved
- Same principle as rust-analyzer's "editing a function body never invalidates cross-file derived data"

```rust
// body_hash: xxh3 of function body text (between opening and closing braces)
// signature_hash: xxh3 of (name + parameter types + return type)
```

This is the foundation for Layer 2 incrementality (pattern re-scoring only for changed functions) and Layer 3 (convention re-learning threshold).

---

## 8. Namespace/Package Extraction

v1 was missing this entirely in Rust. v2 extracts namespace/package declarations for every language:

| Language | Construct | Example | Query Target |
|----------|-----------|---------|--------------|
| Java | `package` declaration | `package com.example.service;` | `package_declaration` |
| C# | `namespace` declaration | `namespace MyApp.Services { }` | `namespace_declaration` |
| PHP | `namespace` declaration | `namespace App\Http\Controllers;` | `namespace_definition` |
| Go | `package` declaration | `package main` | `package_clause` |
| Rust | `mod` declaration | `mod handlers;` | `mod_item` |
| Python | Implicit from file path | `app/services/auth.py` → `app.services.auth` | File path |
| TypeScript | Implicit from file path | `src/services/auth.ts` → `src/services/auth` | File path |
| C++ | `namespace` declaration | `namespace utils { }` | `namespace_definition` |
| C | No native namespace | — | — |

Essential for: qualified name resolution in call graph, module coupling analysis, architectural boundary detection, import resolution.

---

## 9. Per-Language Parser Details

Each language parser follows an identical pattern:
1. Initialize tree-sitter `Parser` with compile-time-linked grammar
2. Pre-compile tree-sitter `Query` objects (2 consolidated queries: structure + calls)
3. `parse(source)` → parse tree → run queries → collect into `ParseResult`

### TypeScript/JavaScript (`typescript.rs`)
- Grammar: `tree-sitter-typescript` (handles both TS and JS via `is_typescript` flag)
- Extracts: `function_declaration`, `method_definition`, `arrow_function`, `class_declaration` with `extends_clause`/`implements_clause`, `import_statement` (default, named, namespace), `export_statement`, `call_expression`, `new_expression`
- Enterprise: Decorator extraction (structured), JSDoc comments, type annotations, return types, async/generator detection, constructor properties, generic type parameters

### Python (`python.rs`)
- Grammar: `tree-sitter-python`
- Extracts: `function_definition`, `decorated_definition`, `class_definition` (with bases, multiple inheritance), `import_statement`, `import_from_statement`, `call` with `identifier`/`attribute` callee
- Enterprise: Structured decorator extraction (`@decorator(args)`), parameter types + defaults, return type (`-> Type`), docstrings, base class extraction, generator detection (`yield`), class property extraction
- Framework awareness: FastAPI, Django, Flask, SQLAlchemy patterns via decorators
- Deduplication: Tracks decorated function lines to avoid double-counting

### Java (`java.rs`)
- Grammar: `tree-sitter-java`
- Extracts: `method_declaration`, `constructor_declaration` with modifiers, `class_declaration`, `interface_declaration` with superclass/interfaces, `import_declaration`, `method_invocation`, `object_creation_expression`
- Enterprise: Structured annotation extraction (`@Service`, `@GetMapping(path="/api")`, `@Autowired`), Javadoc comments, visibility modifiers, abstract class detection, generic type support, package declaration
- Framework awareness: Spring, JPA, validation annotations — annotations are first-class citizens for Spring Boot pattern detection

### C# (`csharp.rs`)
- Grammar: `tree-sitter-c-sharp`
- Extracts: `method_declaration`, `constructor_declaration`, `class_declaration`, `interface_declaration`, `struct_declaration`, `record_declaration`, `using_directive`, `invocation_expression`, `object_creation_expression`
- Enterprise: `[Attribute]` extraction (structured), XML doc comments (`/// <summary>`), parameter types, property extraction with attributes, namespace extraction (including file-scoped C# 10+), async detection
- Framework awareness: ASP.NET Core routes (`[HttpGet]`, `[Route]`), authorization (`[Authorize]`), Entity Framework (`[Key]`, `[Required]`, `[ForeignKey]`)

### PHP (`php.rs`)
- Grammar: `tree-sitter-php` (LANGUAGE_PHP)
- Extracts: `function_definition`, `method_declaration` with visibility, `class_declaration`, `interface_declaration`, `trait_declaration`, `namespace_use_declaration`, `function_call_expression`, `member_call_expression`, `scoped_call_expression`, `object_creation_expression`
- Enterprise: PHP 8 attributes (`#[Route]`, `#[IsGranted]`) structured extraction, extends/implements, parameter types + defaults, return types, PHPDoc comments, visibility modifiers, abstract class detection, property extraction with visibility/static/readonly
- Framework awareness: Laravel, Symfony attribute patterns

### Go (`go.rs`)
- Grammar: `tree-sitter-go`
- Extracts: `function_declaration`, `method_declaration` (with receiver), `type_declaration` → `struct_type`/`interface_type`, `import_declaration` with alias support, `call_expression` with `selector_expression` receiver
- Enterprise: Struct field extraction with tags (`json:"name" gorm:"primaryKey"`), parameter types, return types, doc comments, Go export convention (uppercase = exported), variadic parameters, interface detection, generic type parameters (`[T any]`)
- Unique: `StructTag` parsing for `json`, `gorm`, `validate`, `db` tags

### Rust (`rust_lang.rs`)
- Grammar: `tree-sitter-rust`
- Extracts: `function_item` with visibility/params/return type, `struct_item`, `enum_item`, `trait_item`, `impl_item`, `use_declaration`, `call_expression` with `field_expression`/`scoped_identifier`
- Enterprise: `#[derive(...)]` extraction, `#[serde(...)]` tag parsing, route attributes for Actix/Axum/Rocket, parameter types, return types, doc comments (`///`, `//!`), visibility modifiers (`pub`, `pub(crate)`), async detection, struct field extraction with serde tags, generic type parameters with trait bounds
- Unique: Separate attribute query, `self` parameter handling, serde attribute → StructTag conversion

### C++ (`cpp.rs`)
- Grammar: `tree-sitter-cpp`
- Extracts: `function_definition` (regular, qualified, pointer, inline method), `class_specifier` with `base_class_clause`, `struct_specifier`, `preproc_include` (string and system paths), `call_expression` with `field_expression`/`qualified_identifier`
- Enterprise: Parameter types + defaults, Doxygen doc comments (`/**`, `///`, `//!`), class member extraction with access specifiers (`public:`, `private:`, `protected:`), static/const field detection, template function/class support, namespace extraction

### C (`c.rs`)
- Grammar: `tree-sitter-c`
- Extracts: `function_definition`, pointer function declarations, `struct_specifier`, `union_specifier`, `enum_specifier`, `type_definition`, `preproc_include`, `call_expression` with `field_expression`, function pointer calls
- Enterprise: Parameter types (including pointer params), struct field extraction, doc comments, variadic parameter support, typedef detection

---

## 10. Pydantic Model Extraction (Rust-Native)

This was a 9-file TS-only subsystem in v1. v2 builds it natively in Rust. Priority P0 — FastAPI contract detection depends on this.

### Components

1. **Model detector**: Identify classes extending `BaseModel` (or known Pydantic bases) from tree-sitter class definition nodes
2. **Field extractor**: Extract field definitions — name, type annotation, default value, alias, `Field()` constraints
3. **Type resolver**: Recursively resolve Python type annotations: `Optional[str]`, `List[Dict[str, int]]`, `Union[str, int]`, `str | int` (3.10+). Cycle detection via depth limit (default 10)
4. **Constraint parser**: Parse `Field()` arguments: ge, le, gt, lt, min_length, max_length, pattern, multiple_of
5. **Validator extractor**: Extract `@field_validator` (v2) and `@validator` (v1) decorators with target fields and mode (before/after/wrap)
6. **Config extractor**: Extract `model_config = ConfigDict(...)` (v2) or `class Config:` (v1) with settings
7. **Version detector**: Distinguish v1 vs v2 by checking for `ConfigDict` vs `Config` class, `field_validator` vs `validator`

### Output Types

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

pub struct PydanticFieldInfo {
    pub name: String,
    pub type_info: TypeInfo,
    pub default: Option<String>,
    pub default_factory: Option<String>,
    pub alias: Option<String>,
    pub description: Option<String>,
    pub constraints: FieldConstraints,
    pub is_required: bool,
    pub is_optional: bool,
    pub range: Range,
}

pub struct TypeInfo {
    pub name: String,
    pub args: Vec<TypeInfo>,
    pub is_optional: bool,
    pub union_members: Vec<TypeInfo>,
    pub raw: String,
}

pub struct FieldConstraints {
    pub ge: Option<f64>,
    pub le: Option<f64>,
    pub gt: Option<f64>,
    pub lt: Option<f64>,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub pattern: Option<String>,
    pub multiple_of: Option<f64>,
}

pub struct PydanticValidatorInfo {
    pub name: String,
    pub fields: Vec<String>,
    pub mode: ValidatorMode,  // Before, After, Wrap
    pub is_class_method: bool,
    pub range: Range,
}

pub struct PydanticConfigInfo {
    pub extra: Option<String>,           // "allow", "forbid", "ignore"
    pub frozen: Option<bool>,
    pub validate_assignment: Option<bool>,
    pub populate_by_name: Option<bool>,
    pub use_enum_values: Option<bool>,
    pub strict_mode: Option<bool>,
}
```

### v1 vs v2 Detection

| Feature | v1 | v2 |
|---------|----|----|
| Config | `class Config:` | `model_config = ConfigDict(...)` |
| Validators | `@validator` | `@field_validator` |
| Root validators | `@root_validator` | `@model_validator` |
| Frozen | `class Config: allow_mutation = False` | `ConfigDict(frozen=True)` |

---

## 11. GAST (Generic AST Normalization Layer)

### The Problem

Without GAST, every detector needs per-language variants. A "detect try-catch patterns" detector needs to know:
- TypeScript: `try_statement` with `catch_clause`
- Python: `try_statement` with `except_clause`
- Java: `try_statement` with `catch_clause` (different field names than TS)
- Go: no try-catch, uses `if err != nil` pattern
- Rust: no try-catch, uses `Result<T, E>` and `?` operator

### The Solution: ~30 Normalized Node Types

```rust
pub enum GastNode {
    Function { name: Spur, params: Vec<Param>, body: Vec<GastNode>, is_async: bool },
    Class { name: Spur, methods: Vec<GastNode>, extends: Option<Spur> },
    TryCatch { try_body: Vec<GastNode>, catch_clauses: Vec<CatchClause>, finally: Option<Vec<GastNode>> },
    Call { target: Spur, args: Vec<GastNode> },
    Import { path: Spur, names: Vec<Spur> },
    Route { method: HttpMethod, path: Spur, handler: Spur },
    // ~30 total node types covering 80% of detection needs
}
```

Each language gets a normalizer (~500-1000 lines) that converts language-specific CST → GAST. Detectors then work on GAST only.

### Decision: Optimization Layer, Not Replacement

Build GAST as a Tier 1 system (after basic parsers work). Keep language-specific detectors for truly unique patterns (Rust lifetimes, PHP attributes, Go goroutines). Use GAST for the ~80% of detectors that work across languages (error handling, naming conventions, import patterns, etc.).

Benefits:
- Adding a new language requires only a normalizer — all existing detectors work automatically
- Reduces detector codebase by 50-70%
- Single test suite for cross-language behavior

Same approach as ast-grep — native query language for language-specific patterns, normalized API for cross-language operations.

---

## 12. Framework Construct Extraction

Framework-specific constructs (route decorators, DI annotations, ORM model definitions) are critical for boundary detection, contract tracking, and security analysis. These run as a post-pass after base parsing.

### FrameworkExtractor Trait

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

### Framework Extractors to Build

| Framework | Language | Key Constructs |
|-----------|----------|---------------|
| Spring Boot | Java | `@RestController`, `@GetMapping`, `@Service`, `@Entity`, `@PreAuthorize` |
| FastAPI | Python | `@app.get()`, `Depends()`, BaseModel subclasses |
| Django | Python | `urlpatterns`, `models.Model`, `@login_required` |
| Laravel | PHP | `Route::get()`, Eloquent models, `#[Middleware]` |
| NestJS | TypeScript | `@Controller`, `@Get`, `@Injectable`, `@Guard` |
| ASP.NET | C# | `[ApiController]`, `[HttpGet]`, `[Authorize]`, `DbContext` |
| Express | TypeScript | `app.get()`, `router.use()`, middleware functions |
| Actix/Axum/Rocket | Rust | `#[get]`, `#[post]`, extractors, middleware |
| Gin/Echo | Go | Handler patterns, middleware |

Framework extractors operate on `ParseResult` (post-parse), not on the raw tree-sitter tree. Detection is primarily decorator/annotation-driven (structured DecoratorInfo provides the data). Registration: `manager.register_framework(Box::new(SpringExtractor::new()))`. Framework extraction is optional — can be skipped for performance when not needed.

---

## 13. Structured Error Types

Per AD6 (thiserror from first line of code):

```rust
#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    #[error("Unsupported language for extension '{extension}'")]
    UnsupportedLanguage { extension: String },

    #[error("Grammar initialization failed for {language}: {reason}")]
    GrammarInitFailed { language: Language, reason: String },

    #[error("Parse failed for {file}: {reason}")]
    ParseFailed { file: String, reason: String },

    #[error("Query compilation failed for {language}/{query_name}: {reason}")]
    QueryCompilationFailed { language: Language, query_name: String, reason: String },

    #[error("File read error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Cache error: {0}")]
    CacheError(String),
}
```

At the NAPI boundary, convert to structured error codes:
```rust
impl From<ParseError> for napi::Error {
    fn from(err: ParseError) -> Self {
        let code = match &err {
            ParseError::UnsupportedLanguage { .. } => "UNSUPPORTED_LANGUAGE",
            ParseError::GrammarInitFailed { .. } => "GRAMMAR_INIT_FAILED",
            ParseError::ParseFailed { .. } => "PARSE_FAILED",
            ParseError::QueryCompilationFailed { .. } => "QUERY_COMPILATION_FAILED",
            ParseError::IoError(_) => "IO_ERROR",
            ParseError::CacheError(_) => "CACHE_ERROR",
        };
        napi::Error::new(napi::Status::GenericFailure, format!("[{}] {}", code, err))
    }
}
```

---

## 14. Event Emissions (per D5)

The parser should emit events via `DriftEventHandler`:

```rust
pub trait DriftEventHandler: Send + Sync {
    fn on_parse_started(&self, _file: &Path, _language: Language) {}
    fn on_parse_complete(&self, _file: &Path, _result: &ParseResult) {}
    fn on_parse_error(&self, _file: &Path, _error: &ParseError) {}
    fn on_parse_cache_hit(&self, _file: &Path) {}
    fn on_parse_cache_miss(&self, _file: &Path) {}
}
```

Zero overhead when no handlers registered (standalone mode). When the bridge is active, these events can feed into Cortex memory creation.

---

## 15. Observability (per AD10)

Instrument with `tracing` crate from day one:

```rust
#[instrument(skip(source), fields(language = %language, file_size = source.len()))]
pub fn parse(&mut self, source: &str, language: Language) -> Result<ParseResult, ParseError> {
    let _span = tracing::info_span!("parse_file").entered();
    // ...
    info!(
        functions = result.functions.len(),
        classes = result.classes.len(),
        calls = result.calls.len(),
        parse_time_us = result.parse_time_us,
        cache_hit = false,
        "parse complete"
    );
}
```

Key metrics:
- `parse_time_per_language` — identify slow grammars
- `cache_hit_rate` — validate caching strategy
- `error_recovery_rate_per_language` — track parser reliability
- `query_execution_time` — find expensive queries

---

## 16. NAPI Bridge for Parsers

### Core Principle

Minimize data crossing the NAPI boundary. Rust does all heavy computation AND writes results to drift.db. NAPI return values are lightweight summaries.

### APIs

```rust
/// Single file parse (for queries, IDE)
#[napi]
pub fn parse(source: String, file_path: String) -> Option<JsParseResult> { ... }

/// Batch parse (for scans — amortizes NAPI overhead)
#[napi]
pub fn parse_batch(files: Vec<JsFileInput>) -> Vec<JsParseResult> {
    // Parse all files in parallel via rayon
    // Leverages parse cache internally
}

/// Streaming parse with progress (for large scans)
#[napi]
pub fn parse_directory_with_progress(
    config: JsScanConfig,
    progress_callback: ThreadsafeFunction<ProgressUpdate, NonBlocking>,
) -> AsyncTask<ParseDirectoryTask> { ... }

/// List supported languages
#[napi]
pub fn supported_languages() -> Vec<String> { ... }
```

### What Crosses NAPI

Crosses (lightweight): `JsParseResult` (functions, classes, imports, exports, calls — paginated for large files), `ParseSummary` (counts, timing)

Does NOT cross (stays in Rust/SQLite): Raw tree-sitter `Tree` objects, intermediate query cursor state, full cache contents

### Type Mapping

| Rust Type | NAPI Type | Notes |
|-----------|-----------|-------|
| `ParseResult` | `JsParseResult` | Drops `tree`, serializes all fields |
| `FunctionInfo` | `JsFunctionInfo` | `range` → `start_line`/`end_line` |
| `ClassInfo` | `JsClassInfo` | Properties as `JsPropertyInfo[]` |
| `Language` | `String` | Lowercase string |
| `Visibility` | `String` | "public", "private", "protected" |
| `DecoratorInfo` | `JsDecoratorInfo` | Structured with arguments |

---

## 17. Performance Characteristics

### Benchmarks (from tree-sitter)

- Initial parse of a 2000-line Rust file: ~6ms
- Incremental re-parse after edit: <1ms
- Query execution on a parsed tree: ~1-5ms depending on complexity
- Memory per parsed tree: ~10-20 bytes per node
- Query compilation: 50-500ms per language (done once at startup)

### Targets for Drift v2

| Scenario | Target | Strategy |
|----------|--------|----------|
| 10K files cold parse | <3s total pipeline | 8 threads, rayon |
| 100K files cold parse | <15s total pipeline | 8 threads, rayon |
| 100K files warm (90% cache hit) | <6s with 8 threads | Moka + SQLite cache |
| Incremental (10 files changed) | <100ms | Content hash skip + cache |
| Single file re-parse (IDE) | <1ms | tree-sitter incremental parse |

### macOS Caveat

APFS directory scanning is single-threaded at the kernel level. Parallel walking helps with per-file work (hashing, metadata) but not directory enumeration. This is a known limitation — ripgrep has the same constraint.

---

## 18. v1 → v2 Gap Closure

These are the specific gaps from v1 Rust parsers that v2 must close:

| Feature | v1 Rust | v2 Requirement | Priority |
|---------|---------|----------------|----------|
| Generic type parameters | ❌ Missing | Full extraction with bounds | P0 |
| Structured decorators/annotations | ❌ Strings only | `DecoratorInfo` with parsed arguments | P0 |
| Pydantic model support | ❌ Missing | Full Rust-native extraction | P0 |
| Namespace/package extraction | ❌ Missing | All languages | P1 |
| Full inheritance chains | Partial | Complete MRO resolution | P1 |
| Framework construct detection | Partial | `FrameworkExtractor` trait system | P1 |
| Access modifiers on functions | Partial | Always present `Visibility` | P1 |
| Incremental parsing | ❌ Missing | tree-sitter `tree.edit()` for IDE | P2 |
| AST caching | ❌ Missing | Moka + SQLite persistence | P0 |
| Body hash for change detection | ❌ Missing | xxh3 on function body | P0 |
| Consolidated queries (2 per file) | ❌ 4-5 per file | Structure + calls | P1 |
| Methods nested in ClassInfo | ❌ Flat | Methods as children of class | P1 |
| ClassKind enum | ❌ Missing | class/interface/struct/enum/trait/record | P1 |
| Content hash on ParseResult | ❌ Missing | xxh3 for cache key | P0 |

---

## 19. Security Considerations

1. **Untrusted input**: Parsers process arbitrary source code. Tree-sitter is memory-safe and handles malformed input gracefully, but extraction logic must not panic on unexpected AST shapes
2. **Resource exhaustion**: Deeply nested files or extremely long lines could cause stack overflow. Implement depth limits on recursive extraction (especially Pydantic type resolution — default 10)
3. **Cache poisoning**: Parse cache persisted to disk must have appropriate permissions. Content hash verified on read
4. **NAPI boundary**: All data crossing Rust-JS boundary must be validated. No raw pointers or internal Rust state leaks through NAPI
5. **Secret exposure**: ParseResult contains source code snippets (doc_comment, decorator raw_text). Ensure these are not inadvertently logged or exposed through MCP tools without filtering

---

## 20. Build Order

```
Phase 1 — Core Architecture (everything depends on this):
  Canonical ParseResult shape with all enriched types
  LanguageParser trait + ParserManager
  thiserror ParseError enum
  thread_local! parser pool with cleanup

Phase 2 — Rich Extraction (build parsers with full extraction from day one):
  Structured decorator/annotation extraction (DecoratorInfo)
  Namespace/package extraction
  Generic type parameter extraction (GenericParam)
  Error-tolerant extraction (partial results from ERROR nodes)
  Consolidated tree-sitter queries (2 per file)
  Body hash + signature hash on FunctionInfo
  ClassKind enum, methods nested in ClassInfo

Phase 3 — Caching & Performance:
  Moka parse cache (content-addressed, 10K entries)
  SQLite cache persistence (bincode serialization)
  NAPI batch/streaming APIs

Phase 4 — Domain-Specific Extraction:
  Pydantic model extraction (Rust-native, v1+v2)
  Framework construct extractors (Spring, Django, FastAPI, Laravel, etc.)

Phase 5 — Normalization & Extensibility:
  GAST normalization layer (~30 node types)
  define_parser! macro for new language onboarding
```

---

## 21. Summary of All Decisions

| Decision | Choice | Confidence | Source |
|----------|--------|------------|--------|
| Parser library | tree-sitter (v0.25+) | Very High | Research, industry standard |
| Thread safety | thread_local! per rayon worker with cleanup | High | R11, ast-grep pattern |
| Query strategy | Pre-compiled, 2 consolidated traversals per file | High | R5, A3 |
| Parse cache | Moka (TinyLFU) + SQLite persistence | High | R1, A3 |
| Error handling | Extract partial results from valid subtrees | High | R9 |
| Body hash | xxh3 of function body for fine-grained invalidation | High | A3 |
| Signature hash | xxh3 of signature for cross-file stability | High | A3 |
| Data model | Single canonical ParseResult, enriched types | Very High | R2 |
| Decorators | Structured DecoratorInfo with parsed arguments | Very High | R3 |
| Generics | GenericParam with bounds on FunctionInfo + ClassInfo | High | R10 |
| Namespaces | Extracted for all languages that have them | High | R7 |
| Pydantic | Rust-native extraction, v1+v2 support | High | R4 |
| GAST | Optimization layer, not replacement | Medium-High | Audit Cat 02 |
| Framework extraction | Trait-based post-pass after base parsing | High | R12 |
| Parser architecture | LanguageParser trait, ParserManager dispatcher | High | R6 |
| Error types | thiserror per-subsystem enum | Very High | R13, AD6 |
| NAPI bridge | Batch + streaming, minimal boundary crossing | High | R8 |
| Config format | TOML for declarative patterns | High | AD3 |
| Observability | tracing crate, per-language metrics | Very High | AD10 |
| Events | DriftEventHandler with no-op defaults | High | D5 |
| Language scaffold | define_parser! macro | Medium | R14 |
| String interning | lasso (ThreadedRodeo → RodeoReader) | High | AD12 |
| Content hashing | xxh3 via xxhash-rust | High | Scanner research |

---

## 22. Cross-System Impact

The parser subsystem is the most depended-upon component in Drift. Changes cascade everywhere:

| Consumer | What It Needs From Parsers |
|----------|---------------------------|
| Unified Analysis Engine | ParseResult → 4-phase pipeline (AST patterns, string extraction, regex, resolution index) |
| Call Graph Builder | FunctionInfo + CallSite → function→function edges |
| Detector System | ParseResult → pattern matching across 16 categories |
| Boundary Detection | ImportInfo + CallSite + DecoratorInfo → ORM framework detection |
| Taint Analysis | CallSite + FunctionInfo → source/sink/sanitizer identification |
| Contract Tracking | DecoratorInfo (route paths) + PydanticModelInfo → BE↔FE matching |
| Test Topology | FunctionInfo + DecoratorInfo → test framework detection |
| Error Handling | FunctionInfo (try/catch patterns) → error propagation chains |
| DNA System | All ParseResult fields → codebase fingerprinting |
| Constraints | FunctionInfo + ClassInfo → invariant detection |
| Coupling Analysis | ImportInfo + ExportInfo → module dependency tracking |
| Security | DecoratorInfo (auth patterns) + CallSite → auth bypass detection |
| GAST | ParseResult → normalized cross-language representation |

Every improvement to parser extraction quality directly improves every downstream system. This is why parsers are Level 0 — Bedrock.
