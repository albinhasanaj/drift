# 02 Parsers — Research Recap

## Executive Summary

The Parser subsystem is Drift's foundation layer — every other subsystem (detectors, analyzers, call graph, boundaries, security, contracts, test topology) depends on its output. It extracts structured metadata (functions, classes, imports, exports, call sites, decorators, parameters, doc comments) from source code across 10+ languages using tree-sitter grammars. The architecture is dual-layer: Rust parsers (~8,000 lines) provide native-speed extraction for 10 languages, while TypeScript parsers (~10,000+ lines across custom + tree-sitter wrappers) provide richer, framework-aware extraction for 14 languages. A NAPI bridge (~2,200 lines) connects the two layers, with a fallback adapter that tries Rust first and degrades to TypeScript on failure. The v2 vision is to bring Rust parsers to full feature parity with TypeScript, then deprecate the TS parsing layer entirely.

## Current Implementation

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Consumer Layer                                   │
│  Detectors (350+) │ Call Graph │ Analyzers │ Boundaries │ Security       │
│  Contracts │ Test Topology │ Constraints │ Context Generation            │
├─────────────────────────────────────────────────────────────────────────┤
│                         NAPI Bridge (drift-napi)                         │
│  parse() │ supported_languages() │ version()                            │
│  JsParseResult ← manual field-by-field conversion from Rust ParseResult │
├─────────────────────────────────────────────────────────────────────────┤
│                         Native Adapters (native-adapters.ts)             │
│  parseWithFallback(): try Rust → fall back to TS → return null          │
├──────────────────────────┬──────────────────────────────────────────────┤
│   Rust Parsers           │   TypeScript Parsers                          │
│   (drift-core/parsers)   │   (packages/core/parsers)                     │
│   ~8,000 lines           │   ~10,000+ lines                              │
│                          │                                                │
│   ParserManager          │   ParserManager (LRU cache, incremental)      │
│   ├─ TypeScriptParser    │   ├─ TypeScriptParser (TS Compiler API)       │
│   ├─ PythonParser        │   ├─ PythonParser (regex-based)               │
│   ├─ JavaParser          │   ├─ CSSParser, JSONParser, MarkdownParser    │
│   ├─ CSharpParser        │   └─ Tree-Sitter Wrappers (7 languages)      │
│   ├─ PhpParser           │       ├─ Python (+Pydantic, +AST converter)   │
│   ├─ GoParser            │       ├─ Java (+Spring annotations, +5 files) │
│   ├─ RustParser          │       ├─ C# (+ASP.NET, +AST converter)       │
│   ├─ CppParser           │       ├─ PHP (+Laravel/Symfony)               │
│   └─ CParser             │       ├─ Go (+struct tags)                    │
│                          │       ├─ Rust (+derive macros)                │
│                          │       └─ C++ (+templates)                     │
├──────────────────────────┴──────────────────────────────────────────────┤
│                         Tree-Sitter Grammars                             │
│  Rust: compile-time linked (native, no WASM)                            │
│  TS: dynamic loading via require() + createRequire(import.meta.url)     │
└─────────────────────────────────────────────────────────────────────────┘
```

### File Inventory

| Location | Files | Lines | Purpose |
|----------|-------|-------|---------|
| `crates/drift-core/src/parsers/` | 12 | ~8,000 | Rust native parsers (10 languages) |
| `packages/core/src/parsers/` | 8 | ~4,000 | TS custom parsers (TypeScript, Python, CSS, JSON, Markdown) |
| `packages/core/src/parsers/tree-sitter/` | 22+ | ~6,000 | TS tree-sitter wrappers (7 languages) |
| `packages/core/src/parsers/tree-sitter/pydantic/` | 9 | ~1,500 | Pydantic v1/v2 model extraction |
| `packages/core/src/parsers/tree-sitter/java/` | 5 | ~800 | Java annotation/class/method extractors |
| `crates/drift-napi/src/lib.rs` (parser section) | 1 | ~400 | NAPI bridge types + parse() function |
| `packages/core/src/native/native-adapters.ts` | 1 | ~200 | Rust→TS fallback adapter |
| **Total** | **~58** | **~20,900** | |

---

### Core Design Principles

1. **Dual-layer architecture**: Rust for speed, TypeScript for richness (v1 reality, v2 eliminates this)
2. **Native tree-sitter in Rust**: Grammars linked at compile time — no WASM overhead, no dynamic loading
3. **Graceful fallback**: Rust → TS tree-sitter → TS regex, per language
4. **Unified output format**: All parsers produce the same `ParseResult` shape (though Rust and TS shapes differ — see Data Models)
5. **Query-based extraction**: Tree-sitter `Query` API for pattern matching on AST nodes
6. **Framework-aware**: TS parsers understand Spring, Django, Laravel, NestJS, ASP.NET, FastAPI, Pydantic, etc.

---

## Subsystem Deep Dives

### 1. Rust ParserManager (`manager.rs`)

**Purpose**: Unified dispatch layer holding optional instances of all 9 language parsers.

**Structure**:
```rust
pub struct ParserManager {
    typescript_parser: Option<TypeScriptParser>,
    python_parser: Option<PythonParser>,
    java_parser: Option<JavaParser>,
    csharp_parser: Option<CSharpParser>,
    php_parser: Option<PhpParser>,
    go_parser: Option<GoParser>,
    rust_parser: Option<RustParser>,
    cpp_parser: Option<CppParser>,
    c_parser: Option<CParser>,
}
```

**API**:
- `new()` — Creates all parsers (each `Option` — `None` if grammar fails to load)
- `supports(language) -> bool`
- `supported_languages() -> Vec<Language>`
- `parse_file(path, source) -> Option<ParseResult>` — Auto-detects language from extension
- `parse(source, language) -> Option<ParseResult>` — Explicit language
- `parse_batch(files) -> HashMap<String, ParseResult>` — Bulk parsing

**Key Characteristics**:
- Each parser wraps a `tree_sitter::Parser` + pre-compiled `Query` objects
- Parsers are `Option` to handle grammar load failures gracefully
- No caching, no incremental parsing, no thread safety (uses `thread_local!` in callers)
- `parse_batch()` exists but parallelism is handled by callers via rayon

---

### 2. Rust Per-Language Parsers (9 parsers)

All follow an identical structural pattern:

```rust
pub struct XxxParser {
    parser: Parser,
    function_query: Query,
    class_query: Query,       // or struct_query
    import_query: Query,      // or use_query / include_query
    call_query: Query,
    // Some have additional: attribute_query (Rust), etc.
}
```

**Common extraction pipeline per file**:
1. `parser.parse(source, None)` → tree-sitter `Tree`
2. `QueryCursor::new()` → run queries against tree root
3. Iterate matches, extract captures by name
4. Build typed structs (`FunctionInfo`, `ClassInfo`, etc.)
5. Return `ParseResult` with timing (`parse_time_us`)

**Per-Language Capabilities**:

| Parser | Grammar | Queries | Enterprise Features | Framework Awareness |
|--------|---------|---------|--------------------|--------------------|
| TypeScript/JS | `tree-sitter-typescript` | 5 (function, class, import, export, call) | Decorators, JSDoc, type annotations, return types, async/generator, constructor properties | NestJS, Express |
| Python | `tree-sitter-python` | 4 (function, class, import, call) | Decorators, parameter types + defaults, return types, docstrings, base classes, generators, deduplication of decorated functions | FastAPI, Django, Flask, SQLAlchemy |
| Java | `tree-sitter-java` | 4 (method, class, import, call) | Annotations (`@Service`, `@GetMapping`, `@Autowired`), Javadoc, visibility modifiers, abstract classes, generics | Spring, JPA |
| C# | `tree-sitter-c-sharp` | 4 (method, class, using, call) | `[Attribute]` extraction, XML doc comments, records, structs, interfaces, namespace extraction, async | ASP.NET Core, Entity Framework |
| PHP | `tree-sitter-php` | 4 (function, class, use, call) | PHP 8 attributes (`#[Route]`, `#[IsGranted]`), traits, visibility, abstract, property extraction | Laravel, Symfony |
| Go | `tree-sitter-go` | 4 (function, struct, import, call) | Struct tags (`json`, `gorm`, `validate`, `db`), interfaces, Go export convention (uppercase), variadic params, method receivers | Gin, Echo |
| Rust | `tree-sitter-rust` | 5 (function, struct, use, call, attribute) | `#[derive()]`, `#[serde()]` → StructTag, route attributes, `pub`/`pub(crate)`, async, enums, traits, impl blocks | Actix, Axum, Rocket |
| C++ | `tree-sitter-cpp` | 4 (function, class, include, call) | Templates, Doxygen comments, access specifiers, static/const fields, qualified names | Boost, Qt |
| C | `tree-sitter-c` | 4 (function, struct, include, call) | Pointer function declarations, unions, enums, typedefs, variadic params | Embedded/HAL |

**Extension Mapping** (Rust `Language::from_extension()`):

| Extensions | Language |
|---|---|
| `.ts`, `.tsx`, `.mts`, `.cts` | TypeScript |
| `.js`, `.jsx`, `.mjs`, `.cjs` | JavaScript |
| `.py`, `.pyi` | Python |
| `.java` | Java |
| `.cs` | CSharp |
| `.php` | PHP |
| `.go` | Go |
| `.rs` | Rust |
| `.cpp`, `.cc`, `.cxx`, `.c++`, `.hpp`, `.hxx`, `.hh` | C++ |
| `.c`, `.h` | C |

---

### 3. TypeScript ParserManager (`parser-manager.ts`, ~900 lines)

**Purpose**: Parser orchestration with LRU caching, incremental parsing, and language detection.

**Configuration**:
```typescript
interface ParserManagerOptions {
  cacheSize: number;           // Default: 100
  cacheTTL: number;            // Default: 0 (no expiry)
  enableStats: boolean;        // Default: true
  enableIncremental: boolean;  // Default: true
  incrementalThreshold: number;// Default: 10 (min chars for incremental)
}
```

**LRU Cache Implementation**: Custom doubly-linked list LRU (not a library):
- Key: file path
- Value: `CachedAST { result, hash (SHA-256), timestamp, hits, source }`
- On parse: compute hash → check cache → hit (hash match) → return cached; miss → parse, insert, evict LRU if over capacity
- TTL check on access (if configured)
- Stats tracking: hits, misses, evictions, hit ratio

**Incremental Parsing**:
- Requires previous AST in cache + `TextChange[]` describing edits
- Applies edits to tree-sitter tree via `tree.edit()`, re-parses affected regions
- Returns `IncrementalParseResult` with `wasIncremental` flag and `reparsedRegions`
- Threshold: minimum 10 chars changed before using incremental path

**Language Detection**: Extension-based mapping for 14 languages (10 from Rust + CSS, SCSS, JSON, YAML, Markdown)

---

### 4. BaseParser Abstract Class (`base-parser.ts`, ~600 lines)

**Purpose**: Common interface and utility methods for all TS-side parsers.

**Abstract Contract**:
```typescript
abstract class BaseParser {
  abstract readonly language: Language;
  abstract readonly extensions: string[];
  abstract parse(source: string, filePath?: string): ParseResult;
}
```

**Utility Categories** (20+ methods):
- **Parsing**: `parse()`, `parseWithOptions()`
- **AST Querying**: `queryWithOptions()`, `findNodesByType()`, `findFirstNodeByType()`, `findNodeAtPosition()`
- **Tree Traversal**: `traverse()` (depth-first with visitor), `getParentChain()`, `getDescendants()`, `getSiblings()`
- **Position Utilities**: `positionInRange()`, `comparePositions()`, `getTextBetween()`
- **Node Creation**: `createNode()`, `createAST()`, `nodesEqual()`
- **Result Builders**: `createSuccessResult()`, `createFailureResult()`, `createPartialResult()`
- **Extension Checking**: `canHandle(extension)`

**v2 Note**: This class becomes unnecessary when Rust handles all parsing. The visitor pattern maps to Rust's `TreeCursor` API. Position utilities are trivial to port.

### 5. Tree-Sitter Integration Layer (TS, 22+ files)

**Purpose**: TypeScript wrappers around Node.js tree-sitter bindings providing enhanced, framework-aware extraction beyond Rust parsers.

**Loader Pattern** (7 loaders — one per language):
```typescript
// Lazy initialization with caching and error tracking
let available: boolean | null = null;
let cachedParser: TreeSitterParser | null = null;
let cachedLanguage: TreeSitterLanguage | null = null;
let loadingError: string | null = null;

export function isXxxTreeSitterAvailable(): boolean;
export function getXxxLanguage(): TreeSitterLanguage;
export function createXxxParser(): TreeSitterParser;
export function getXxxLoadingError(): string | null;
export function resetXxxLoader(): void;  // for testing
```
- Uses `createRequire(import.meta.url)` for ESM compatibility
- Grammars loaded via `require('tree-sitter-xxx')`

**Per-Language TS Tree-Sitter Parsers**:

| Parser | Special Features |
|--------|-----------------|
| Python | Pydantic extraction, fallback to regex, AST converter |
| Java | Full semantic extraction, Spring annotations, 5-file subdirectory (class/method/annotation extractors) |
| C# | ASP.NET attributes, records, structs, AST converter |
| PHP | Laravel/Symfony attributes, traits |
| Go | Struct tags, interfaces |
| Rust | Derive macros, serde attributes |
| C++ | Templates, virtual methods |

**Configuration** (`config.ts`):
```typescript
interface PythonParserConfig {
  useTreeSitter: boolean;        // Default: true
  extractPydanticModels: boolean; // Default: true
  maxTypeDepth: number;          // Default: 10
  includePositions: boolean;     // Default: true
  parseTimeout: number;          // Default: 5000ms
  useIncremental: boolean;       // Default: true
  includeComments: boolean;      // Default: true
  includeAnonymous: boolean;     // Default: false
}
```
- Environment variable overrides: `DRIFT_PYTHON_USE_TREE_SITTER`, `DRIFT_PYTHON_EXTRACT_PYDANTIC`, etc.
- Validation returns `ConfigValidationResult` with field-level errors

---

### 6. Pydantic Model Extraction (9 files, TS-only)

**Purpose**: Extract Pydantic v1 and v2 model definitions from Python source code. Critical for API contract detection — Pydantic models define request/response shapes in FastAPI.

**Sub-Extractors**:
| Component | Purpose |
|-----------|---------|
| `PydanticExtractor` | Main orchestrator — coordinates all sub-extractors |
| `FieldExtractor` | Field definitions (name, type, default, alias) |
| `TypeResolver` | Type annotations (Optional, List, Dict, Union, nested models) |
| `ConstraintParser` | `Field()` constraints (ge, le, gt, lt, min_length, max_length, pattern, multiple_of) |
| `ValidatorExtractor` | `@field_validator` and `@model_validator` decorators |
| `ConfigExtractor` | Model `Config` class / `model_config` dict |
| `InheritanceResolver` | Base class chain resolution (Model → BaseModel hierarchy) |

**Type Resolution Capabilities**:
- Simple: `str`, `int`, `float`, `bool`
- Optional: `Optional[str]` → `{name: "str", isOptional: true}`
- Generic: `List[str]`, `Dict[str, int]`, `Set[User]`
- Union: `Union[str, int]` or `str | int` (Python 3.10+)
- Nested: `List[Optional[Dict[str, List[int]]]]`
- Circular reference protection via `maxTypeDepth` (default: 10)

**Pydantic v1 vs v2 Detection**:
| Feature | v1 | v2 |
|---------|----|----|
| Config | `class Config:` | `model_config = ConfigDict(...)` |
| Validators | `@validator` | `@field_validator` |
| Root validators | `@root_validator` | `@model_validator` |
| Frozen | `class Config: allow_mutation = False` | `ConfigDict(frozen=True)` |

**v2 Port Complexity**: This is one of the most complex TS-only features to port to Rust. Type resolution requires recursive AST traversal with cycle detection. Inheritance resolver needs cross-file information. Priority: P0 — FastAPI contract detection depends on this.

---

### 7. Java Annotation System (5 files, TS-only)

**Purpose**: First-class annotation extraction for Spring Boot pattern detection.

**Components**:
| File | Purpose |
|------|---------|
| `types.ts` | `JavaParseResult`, `PackageInfo`, `JavaImportInfo`, `JavaClassInfo`, `JavaMethodInfo`, `JavaFieldInfo`, `JavaAnnotation` |
| `class-extractor.ts` | `extractClasses()`, `extractInterfaces()`, `extractEnums()`, `extractRecords()`, `extractAnnotationDefinitions()` |
| `method-extractor.ts` | Method and constructor extraction with annotations |
| `annotation-extractor.ts` | First-class annotation extraction (Spring pattern detection) |

**Key Insight**: Annotations are the primary signal for Spring Boot pattern detection. The Rust Java parser extracts annotations as strings, but the TS layer extracts them as structured objects with arguments, enabling semantic analysis.

### 8. NAPI Bridge (Parser Section)

**Purpose**: Exposes Rust parser functionality to Node.js via napi-rs.

**Exported Functions** (3 parser-specific):
| Function | Signature | Purpose |
|----------|-----------|---------|
| `parse` | `(source: String, file_path: String) -> Option<JsParseResult>` | Parse source, extract metadata |
| `supported_languages` | `() -> Vec<String>` | List parseable languages |
| `version` | `() -> String` | Get drift-core version |

**Type Conversion** (10 NAPI structs for parsing):
- `JsParseResult` — language, functions, classes, imports, exports, calls, errors, parse_time_us
- `JsFunctionInfo` — name, qualified_name, parameters, return_type, is_exported, is_async, start_line, end_line, decorators, doc_comment
- `JsClassInfo` — name, extends, implements, is_exported, start_line, end_line, decorators, properties
- `JsPropertyInfo` — name, type_annotation, is_static, is_readonly, visibility, tags
- `JsParameterInfo` — name, type_annotation, default_value, is_rest
- `JsImportInfo` — source, named, default, namespace, is_type_only, line
- `JsExportInfo` — name, from_source, is_default, line
- `JsCallSite` — callee, receiver, arg_count, line
- `JsStructTag` — key, value
- `JsParseError` — message, line

**Conversion Approach**: Manual field-by-field mapping (not serde). Intentional for type narrowing (`usize` → `i64`), enum-to-string conversion, and structure flattening (`Range` → `start_line`/`end_line`).

**Thread Safety**: `parse()` uses `thread_local!` for `ParserManager` to avoid re-initialization overhead per rayon thread.

### 9. Native Adapter (`native-adapters.ts`)

**Purpose**: Fallback mechanism — try Rust first, degrade to TypeScript on failure.

**Module Loading**:
```typescript
try { nativeModule = require('driftdetect-native'); }    // Published package
catch { try { nativeModule = require('@drift/native'); } // Local dev
catch { /* Native not available */ } }
```

**`parseWithFallback()` Flow**:
1. Check if native module available
2. Try native parse
3. If success → return result
4. If failure → log, fall back to TS ParserManager
5. If TS also fails → return null

**Debug Logging**: Controlled by `DRIFT_DEBUG=true` environment variable.

---

## Key Data Models

### Rust ParseResult (primary output)
```rust
ParseResult {
    language: Language,                    // Enum: 10 variants
    tree: Option<tree_sitter::Tree>,       // Raw AST (not serializable, dropped in NAPI)
    functions: Vec<FunctionInfo>,
    classes: Vec<ClassInfo>,
    imports: Vec<ImportInfo>,
    exports: Vec<ExportInfo>,
    calls: Vec<CallSite>,
    errors: Vec<ParseError>,
    parse_time_us: u64,
}
```

### TypeScript ParseResult (different shape)
```typescript
ParseResult {
    ast: AST | null,       // Raw tree (not extracted metadata)
    language: Language,     // String union: 14 variants
    errors: ParseError[],
    success: boolean,
}
```

**Critical Difference**: Rust `ParseResult` contains extracted metadata (functions, classes, etc.). TS `ParseResult` contains the raw AST tree. These are fundamentally different shapes. The NAPI bridge converts Rust's extracted metadata into `JsParseResult`, which is a third shape consumed by TS callers.

### Shared Sub-Types

```
FunctionInfo { name, qualified_name, parameters: Vec<ParameterInfo>, return_type, is_exported,
               is_async, is_generator, range, decorators: Vec<String>, doc_comment }

ClassInfo { name, extends, implements: Vec<String>, is_exported, is_abstract,
            methods: Vec<FunctionInfo>, properties: Vec<PropertyInfo>, range, decorators }

PropertyInfo { name, type_annotation, is_static, is_readonly, visibility: Visibility,
               tags: Option<Vec<StructTag>> }

ImportInfo { source, named: Vec<String>, default, namespace, is_type_only, range }

ExportInfo { name, original_name, from_source, is_type_only, is_default, range }

CallSite { callee, receiver, arg_count, range }

ParameterInfo { name, type_annotation, default_value, is_rest }

Position { line: u32, column: u32 }
Range { start: Position, end: Position }
```

### Pydantic Types (TS-only)
```
PydanticModelInfo { name, bases, fields, validators, config, positions, isPydanticV2 }
PydanticFieldInfo { name, type: TypeInfo, default, defaultFactory, alias, description,
                    constraints: FieldConstraints, isRequired, isOptional, positions }
TypeInfo { name, args: TypeInfo[], isOptional, unionMembers: TypeInfo[], raw }
FieldConstraints { ge, le, gt, lt, minLength, maxLength, pattern, multipleOf }
PydanticValidatorInfo { name, fields, mode: 'before'|'after'|'wrap', isClassMethod }
PydanticConfigInfo { extra, frozen, validateAssignment, populateByName, useEnumValues,
                     strictMode, jsonSchemaExtra }
```

### Java Types (TS-only)
```
JavaParseResult extends ParseResult { packageInfo, javaImports, javaClasses }
JavaClassInfo { name, type, annotations, fields, methods, superClass, interfaces,
                isAbstract, isStatic, isFinal, genericParams }
JavaAnnotation { name, arguments: Map<string, any>, raw }
```

---

## Parse Pipeline (End-to-End)

```
1. Input: source code string + file path
2. Language detection (from file extension → Language enum)
3. Parser selection (ParserManager dispatches to correct language parser)
4. Tree-sitter parsing → raw AST tree
5. Query-based extraction (per-language tree-sitter Query objects):
   a. Functions (name, params, return type, decorators, doc comments, async, generator)
   b. Classes (name, extends, implements, properties, decorators, abstract)
   c. Imports (source, named, default, namespace, type-only)
   d. Exports (name, original, re-exports, type-only, default)
   e. Call sites (callee, receiver, arg count, line)
6. Output: ParseResult with all extracted metadata + timing (parse_time_us)
```

**Fallback Chain** (TS side):
```
Rust native parse (via NAPI)
  ↓ failure
TS tree-sitter parse (via Node.js bindings)
  ↓ failure / unavailable
TS regex-based parse (custom parsers)
  ↓ failure
null (unsupported language)
```

---

## Performance Characteristics

| Layer | Speed | Notes |
|-------|-------|-------|
| Rust parsers | ~1-10ms/file | Native tree-sitter, compile-time linked grammars, no WASM |
| TS tree-sitter parsers | ~5-20ms/file | Node.js bindings, dynamic grammar loading |
| TS regex parsers | ~5-50ms/file | Fallback, variable performance |
| LRU cache (TS) | O(1) lookup | 100 entries default, SHA-256 hash-based invalidation |
| NAPI bridge | ~0.1-1ms overhead | Manual field-by-field conversion, no serde |
| Batch parsing (Rust) | Parallelized via rayon | `parse_batch()` for bulk operations |

---

## Feature Parity Gap: Rust vs TypeScript

| Feature | Rust Status | TS Status | Priority | Impact |
|---------|-------------|-----------|----------|--------|
| Basic function/class/import/call extraction | ✅ Complete | ✅ | — | — |
| Parameter types + defaults | ✅ Complete | ✅ | — | — |
| Return types | ✅ Complete | ✅ | — | — |
| Doc comments (all styles) | ✅ Complete | ✅ | — | — |
| Visibility modifiers | ✅ Complete | ✅ | — | — |
| Decorator/annotation extraction (as strings) | ✅ Complete | ✅ | — | — |
| **Generic type parameters** | ❌ Missing | ✅ | **P0** | Type analysis, contract detection |
| **Pydantic model support** | ❌ Missing | ✅ | **P0** | FastAPI contract detection |
| **Structured annotation extraction** | Partial (strings only) | ✅ (objects with args) | **P0** | Spring/Django/Laravel pattern detection |
| **Full inheritance chains** | Partial (direct only) | ✅ (multi-level) | **P1** | Component hierarchy, ORM models |
| **Framework construct detection** | Partial | ✅ | **P1** | All framework-aware detectors |
| **Namespace/package extraction** | ❌ Missing | ✅ | **P1** | Java packages, C# namespaces, PHP namespaces |
| **Access modifiers on functions** | Partial | ✅ | **P1** | Visibility analysis, API surface detection |
| **Incremental parsing** | ❌ Missing | ✅ (tree.edit()) | **P2** | IDE integration, large codebase performance |
| **AST caching** | ❌ Missing | ✅ (LRU, 100 entries) | **P2** | Repeated parse avoidance |
| **Body hash for change detection** | ❌ Missing | ❌ Missing | **P2** | Incremental analysis |

---

## Integration Points

The parser subsystem is the most depended-upon component in Drift. Every analysis subsystem consumes its output.

| Consumer | What It Uses | How |
|----------|-------------|-----|
| **Call Graph** (04) | `FunctionInfo`, `CallSite`, `ImportInfo`, `ExportInfo`, `ClassInfo` | Builds function-level dependency graph; 8 language-specific extractors |
| **Detectors** (03) | `FunctionInfo.decorators`, `ClassInfo.extends/implements`, `ImportInfo`, `ClassInfo.properties` | 350+ pattern detectors across 22 categories |
| **Analyzers** (05) | Full `ParseResult` — AST, functions, classes, properties | AST analyzer, type analyzer, semantic analyzer, flow analyzer |
| **Boundaries** (21) | `ImportInfo` (ORM detection), `ClassInfo.decorators` (entity detection), `ClassInfo.properties` (sensitive fields) | Data access point and sensitive field detection |
| **Security** (21) | Parser output via boundaries + call graph | Data access learning, reachability tracing |
| **Test Topology** (17) | `ImportInfo` (framework detection), `FunctionInfo` (test functions), `CallSite` (mock usage) | Test-to-source mapping, framework detection |
| **Contracts** (20) | Pydantic models (TS-only), `FunctionInfo`, `ClassInfo` | API request/response shape extraction, BE↔FE mismatch detection |
| **Constraints** (18) | Code structure from `ParseResult` | Architectural invariant detection |
| **Context Generation** (22) | Patterns derived from parser output | AI context generation, token budgeting |
| **Services Layer** (25) | Parser output via scan pipeline | Scan orchestration |

**Upstream Dependencies**:
- `01-rust-core`: Rust parsers are part of drift-core

**Downstream Dependents** (direct):
- `03-detectors`, `04-call-graph`, `05-analyzers`, `17-test-topology`, `19-error-handling`, `20-contracts`, `21-security`

---

## Testing

### Rust Tests
- Every parser has inline `#[cfg(test)]` tests
- ~109 tests total across 9 parsers
- Coverage: basic extraction, framework patterns, parameter extraction, doc comments, edge cases, enterprise features
- Run: `cargo test -p drift-core parsers`

### TypeScript Tests
- Located in `packages/core/src/parsers/tree-sitter/__tests__/`
- Parser-specific test suites for each tree-sitter wrapper
- Pydantic extraction tests
- Java annotation extraction tests
- Configuration validation tests
- Loader availability tests

### Integration Tests
- NAPI bridge tests verify Rust → JS type conversion
- Native adapter tests verify fallback behavior
- End-to-end tests parse real project files

### v2 Testing Strategy
- Port all TS parser tests to Rust as feature parity is achieved
- Add property-based tests for type resolution (especially Pydantic)
- Add benchmark tests comparing Rust vs TS parser performance
- Add cross-language consistency tests (same patterns detected regardless of parser path)

---

## V2 Migration Status

### Already in Rust (Solid Foundation)
- Tree-sitter parsing for 10 languages with compile-time linked grammars
- Basic metadata extraction: functions, classes, imports, exports, call sites
- Parameter types, defaults, return types, doc comments
- Decorator/annotation extraction (as strings)
- Visibility modifiers
- Go struct tags, Rust serde attributes
- Framework-specific route/annotation detection (basic)
- `ParserManager` with language dispatch
- `parse_batch()` for bulk operations
- NAPI bridge with manual type conversion

### Needs Migration from TS → Rust (Ordered by Priority)

**P0 — Critical for v2 feature parity**:
1. Generic type parameter extraction (affects type analysis, contract detection)
2. Pydantic v1/v2 model extraction (9 files, complex — affects FastAPI contract detection)
3. Structured annotation/decorator extraction (objects with arguments, not just strings — affects all framework detection)

**P1 — Important for full parity**:
4. Full inheritance chain resolution (multi-level, cross-file)
5. Framework construct detection (Spring, Django, Laravel, NestJS, ASP.NET patterns)
6. Namespace/package extraction (Java, C#, PHP)
7. Access modifiers on functions (full visibility analysis)
8. Java annotation system (5-file subdirectory with class/method/annotation extractors)

**P2 — Performance and IDE integration**:
9. Incremental parsing (tree-sitter `tree.edit()` API)
10. AST caching (LRU or similar)
11. Body hash for change detection
12. Thread-safe parser pool (replace `thread_local!` pattern)

### Can Stay in TypeScript
- CSS, JSON, Markdown parsers (not performance-critical, not used by core analysis)
- YAML parser (configuration files, not code analysis)

### Becomes Unnecessary After Migration
- All TS tree-sitter loaders (7 files — grammars are compile-time linked in Rust)
- All TS tree-sitter wrappers (7 parsers — Rust handles natively)
- AST converters (2 files — tree-sitter nodes are native in Rust)
- BaseParser abstract class (600 lines — Rust uses trait-based dispatch)
- TS ParserManager (900 lines — replaced by Rust ParserManager + NAPI)
- Native adapter fallback logic (Rust becomes the only path)

---

## Architectural Observations

### Strengths
1. **Clean separation of concerns**: Each language parser is self-contained with identical structure
2. **Graceful degradation**: Three-tier fallback (Rust → TS tree-sitter → TS regex) ensures parsing always works
3. **Unified output format**: All parsers produce the same `ParseResult` shape, simplifying consumers
4. **Compile-time grammar linking**: No runtime grammar loading failures in Rust
5. **Comprehensive language support**: 10 languages in Rust, 14 in TS, covering major enterprise ecosystems
6. **Enterprise features**: Doc comments, decorators, visibility, async/generator detection across all languages
7. **Framework awareness**: Spring, Django, FastAPI, Laravel, NestJS, ASP.NET, Entity Framework, etc.

### Weaknesses
1. **Dual-layer complexity**: Two complete parsing implementations (Rust + TS) with different output shapes creates maintenance burden and inconsistency risk
2. **Feature gap**: Rust parsers extract significantly less detail than TS parsers (no generics, no structured annotations, no Pydantic, no inheritance chains)
3. **No incremental parsing in Rust**: Full re-parse on every scan, even for unchanged files
4. **No caching in Rust**: No LRU cache, no hash-based invalidation
5. **Thread safety via workaround**: `thread_local!` for ParserManager in rayon contexts instead of proper thread-safe design
6. **Three different ParseResult shapes**: Rust `ParseResult`, TS `ParseResult`, and NAPI `JsParseResult` — unification needed
7. **Pydantic extraction is TS-only**: Critical for FastAPI contract detection, complex to port (9 files, recursive type resolution)
8. **No body hash**: Cannot detect function-level changes for incremental analysis
9. **ClassInfo.methods is unused**: Methods are placed in the top-level `functions` vec instead of nested in their class

---

## Open Questions

1. **Unified ParseResult shape**: Should v2 define a single canonical `ParseResult` that works across Rust, NAPI, and TS? What fields are needed?
2. **Pydantic port strategy**: Port the 9-file Pydantic extractor to Rust, or use a hybrid approach (Rust parses, TS resolves types)?
3. **Incremental parsing scope**: Should Rust support incremental parsing for CLI scans (batch), IDE integration (single file), or both?
4. **Parser pool vs thread_local**: Should Rust use a bounded parser pool with rayon, or keep `thread_local!` with explicit cleanup?
5. **Annotation/decorator semantics**: Should Rust extract annotations as structured objects (name + arguments map) or keep them as strings?
6. **Cross-file type resolution**: How should Rust handle inheritance chains and type references that span multiple files?
7. **Grammar version pinning**: Tree-sitter grammars are pinned at compile time. What's the upgrade strategy for grammar updates?
8. **TS deprecation timeline**: When can the TS parsing layer be safely deprecated? What's the minimum feature set?
9. **ClassInfo.methods**: Should v2 nest methods inside their class, or keep the flat structure?
10. **Body hash algorithm**: SHA-256 (consistent with TS cache) or xxhash (consistent with Rust scanner)?

---

## Quality Checklist

- [x] All 12 files in category have been read and understood
- [x] Architecture is clearly described with diagram
- [x] All 9 Rust parsers documented with capabilities
- [x] All TS parsers documented (custom + tree-sitter wrappers)
- [x] Pydantic extraction system fully documented
- [x] Java annotation system documented
- [x] NAPI bridge types and conversion approach documented
- [x] Native adapter fallback mechanism documented
- [x] All data models listed with fields (Rust, TS, NAPI, Pydantic, Java)
- [x] Feature parity gap assessed with priorities
- [x] Performance characteristics documented
- [x] Integration points mapped to all consuming categories
- [x] V2 migration status documented with priority ordering
- [x] Testing strategy documented
- [x] Limitations honestly assessed
- [x] Open questions identified
