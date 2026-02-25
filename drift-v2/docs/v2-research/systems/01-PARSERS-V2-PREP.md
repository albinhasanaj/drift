# Tree-Sitter Parsers — V2 Implementation Prep

> Comprehensive build specification for Drift v2's parser subsystem (System 01).
> Synthesized from: 01-PARSERS.md (22 sections, 1053 lines — complete v2 spec pre-dating
> downstream V2-PREP docs), 06-UNIFIED-ANALYSIS-ENGINE-V2-PREP.md (§2 ParseResult contract —
> PRIMARY consumer, defines fields NOT in 01-PARSERS.md), 05-CALL-GRAPH-V2-PREP.md
> (§2 FunctionNode, §4 extraction pipeline — consumer contract for FunctionInfo + CallSite),
> 07-BOUNDARY-DETECTION-V2-PREP.md (§5 Unified Language Provider — needs DecoratorInfo for
> ORM detection, FrameworkSignature for learn phase), 15-TAINT-ANALYSIS-V2-PREP.md (§5
> Source Registry — needs CallSite for source/sink identification, FunctionInfo for parameter
> taint), 18-TEST-TOPOLOGY-V2-PREP.md (§5 Per-Language Extraction — needs FunctionInfo +
> DecoratorInfo for test framework detection), 16-ERROR-HANDLING-ANALYSIS-V2-PREP.md (§5
> Phase 1 — needs error handling constructs from AST: try/catch/throw/finally),
> 22-CONSTANTS-ENVIRONMENT-V2-PREP.md (§6 Magic Number Detection — needs NumericLiteralInfo;
> §7 Secret Detection — needs StringLiteralInfo), 24-DNA-SYSTEM-V2-PREP.md (§6 Gene
> Extraction — needs all ParseResult fields for codebase fingerprinting),
> 03-NAPI-BRIDGE-V2-PREP.md (§5 Minimize NAPI Boundary — parse results never cross NAPI;
> §9 Batch API — shared parse results across analyses), 04-INFRASTRUCTURE-V2-PREP.md
> (§2 thiserror, §3 tracing, §4 DriftEventHandler, §6 FxHashMap/SmallVec/lasso),
> 02-STORAGE-V2-PREP.md (parse_cache table, bincode serialization),
> DRIFT-V2-STACK-HIERARCHY.md (Level 0 Bedrock, tree-sitter v0.24, 10 languages),
> DRIFT-V2-FULL-SYSTEM-AUDIT.md (Cat 02, A3), PLANNING-DRIFT.md (D1-D7),
> .research/02-parsers/ (12 research docs: overview, base-parser, tree-sitter-layer,
> rust-parsers, ts-parsers, types, pydantic, integration, napi-bridge, testing,
> rust-vs-ts-comparison, ts-parser-manager),
> .research/02-parsers/RECOMMENDATIONS.md (R1-R14),
> existing cortex parser implementation (crates/cortex/) for reference patterns.
>
> Purpose: Everything needed to build the parser subsystem from scratch. This is the
> DEFINITIVE parser spec — reconciling the original 01-PARSERS.md (written before
> downstream V2-PREP docs existed) with the ParseResult contracts defined by 30+
> downstream consumers. All discrepancies identified and resolved. All type definitions
> reconciled. All downstream expectations verified. Build order specified.
> Generated: 2026-02-08

---

## Table of Contents

1. Architectural Position
2. Resolved Inconsistencies (Critical — Read First)
3. Core Library: tree-sitter v0.24
4. Canonical Data Model (Reconciled ParseResult)
5. Parser Architecture (Trait-Based)
6. Query Architecture (S-Expression, 2 Consolidated Traversals)
7. Parse Cache (Moka + SQLite Persistence)
8. Error-Tolerant Parsing
9. Per-Language Parser Details (10 Languages)
10. Namespace/Package Extraction
11. Pydantic Model Extraction (Rust-Native)
12. GAST Normalization Layer (~30 Node Types)
13. Framework Construct Extraction
14. Structured Error Types (thiserror)
15. Event Emissions (DriftEventHandler)
16. Observability (tracing)
17. NAPI Bridge for Parsers
18. Performance Targets
19. v1 → v2 Gap Closure
20. Security Considerations
21. Build Order
22. Cross-System Impact Matrix
23. Decision Registry


---

## 1. Architectural Position

The parser system is Level 0 — Bedrock. It is the single most critical system in Drift.
Every analysis path starts with parsed ASTs — zero detectors, zero call graph, zero
boundaries, zero taint, zero contracts, zero test topology, zero error handling, zero
DNA, zero constraints work without it. Getting the parser architecture right determines
the ceiling for the entire system.

Per PLANNING-DRIFT.md D1: Drift is standalone. Parsers depend only on drift-core.
Per PLANNING-DRIFT.md D5: Parsers emit events via DriftEventHandler (no-op defaults).
Per AD6: thiserror error enums from the first line of code.
Per AD10: tracing instrumentation from the first line of code.
Per AD12: FxHashMap, SmallVec, lasso for all internal data structures.

### What Lives Here
- 10 per-language tree-sitter parsers (TS, JS, Python, Java, C#, Go, Rust, Ruby, PHP, Kotlin)
- Per-language tree-sitter grammars compiled via `build.rs` (static linking, no WASM)
- `thread_local!` parser instances (tree-sitter `Parser` is not `Send`)
- Pre-compiled, consolidated tree-sitter `Query` objects (2 per language: structure + calls)
- Moka LRU parse cache (in-memory, TinyLFU admission) + SQLite `parse_cache` table
- Canonical `ParseResult` with all enriched types (reconciled across 30+ downstream docs)
- `LanguageParser` trait + `ParserManager` dispatcher
- `FrameworkExtractor` trait for post-parse framework construct detection
- Pydantic model extraction (Rust-native, v1+v2 support)
- GAST normalization layer (~30 node types for cross-language detection)
- `define_parser!` macro for mechanical language addition
- Error-tolerant parsing (partial results from ERROR nodes)
- Body hash + signature hash for function-level change detection
- String interning via lasso (ThreadedRodeo → RodeoReader)

### What Does NOT Live Here
- Unified Analysis Engine 4-phase pipeline (Level 1 — consumes ParseResult)
- Detector System (Level 1 — consumes ParseResult via DetectionContext)
- Call Graph Builder (Level 1 — consumes FunctionInfo + CallSite)
- Boundary Detection (Level 1 — consumes DecoratorInfo + ImportInfo)
- Any analysis logic beyond extraction
- Any persistence beyond parse cache
- Any NAPI serialization (ParseResult never crosses NAPI — per 03-NAPI-BRIDGE-V2-PREP §5)

### Downstream Consumers (30+ Systems)

| Consumer | What It Reads From ParseResult | Critical Fields |
|----------|-------------------------------|-----------------|
| Unified Analysis Engine | Everything — primary consumer | tree, source, all extraction vectors |
| Call Graph Builder | FunctionInfo, CallSite, ImportInfo, ExportInfo, ClassInfo | name (Spur), qualified_name, call_sites, is_exported |
| Detector System | Full ParseResult via DetectionContext | tree, source, functions, classes, imports |
| Boundary Detection | DecoratorInfo, ImportInfo, ClassInfo | decorator arguments, import sources |
| Taint Analysis | CallSite, FunctionInfo (parameters), StringLiteralInfo | callee_name, receiver, parameter types |
| Test Topology | FunctionInfo, DecoratorInfo | decorators (test annotations), is_async |
| Error Handling | ErrorHandlingInfo, FunctionInfo | try/catch/throw/finally constructs |
| Constants/Environment | StringLiteralInfo, NumericLiteralInfo | literal values, contexts, locations |
| Contract Tracking | DecoratorInfo (route paths), PydanticModelInfo | decorator arguments, model fields |
| DNA System | All ParseResult fields | Full codebase fingerprinting |
| Coupling Analysis | ImportInfo, ExportInfo | import sources, export names |
| Constraints | FunctionInfo, ClassInfo | naming patterns, structural invariants |
| GAST | tree + source | Raw AST for normalization |

### Upstream Dependencies

| Dependency | What It Provides | Why Needed |
|-----------|-----------------|------------|
| Scanner (Level 0) | ScanDiff (files to parse), content hashes | Determines which files need parsing |
| Configuration (Level 0) | DriftConfig.scan (max_file_size, languages) | Parser configuration |
| thiserror (Level 0) | ParseError enum | Structured error handling |
| tracing (Level 0) | Spans and metrics | Observability |
| DriftEventHandler (Level 0) | Event emission trait | Parse lifecycle events |
| lasso (Level 1) | ThreadedRodeo / RodeoReader | String interning for names, paths |

**Dependency truth**: Config + thiserror + tracing + DriftEventHandler → Scanner → **Parsers** → Storage → NAPI → everything else


---

## 2. Resolved Inconsistencies (Critical — Read First)

The original 01-PARSERS.md was written BEFORE the 30+ downstream V2-PREP documents that
define contracts against ParseResult. Those downstream docs evolved the ParseResult shape
to meet their needs. This section reconciles every discrepancy.

### Inconsistency #1: ParseResult Shape (01-PARSERS.md vs 06-UAE-V2-PREP.md)

The UAE (06-UNIFIED-ANALYSIS-ENGINE-V2-PREP.md §2) defines a ParseResult with fields
NOT present in 01-PARSERS.md. The UAE is the PRIMARY consumer — its contract wins.

| Field | 01-PARSERS.md | 06-UAE-V2-PREP.md | Resolution |
|-------|--------------|-------------------|------------|
| `tree: Tree` | ❌ Not included | ✅ Owned tree-sitter AST | **ADD** — UAE needs raw AST for visitor pattern engine |
| `source: Vec<u8>` | ❌ Not included | ✅ Raw source bytes | **ADD** — UAE needs source for string extraction, query matching |
| `string_literals: Vec<StringLiteralInfo>` | ❌ Not extracted | ✅ Pre-extracted by parser | **ADD** — 22-CONSTANTS needs these for secret/magic number detection |
| `numeric_literals: Vec<NumericLiteralInfo>` | ❌ Not extracted | ✅ For magic number detection | **ADD** — 22-CONSTANTS needs these for AST-based magic number detection |
| `error_handling: Vec<ErrorHandlingInfo>` | ❌ Not extracted | ✅ try/catch/finally | **ADD** — 16-ERROR-HANDLING needs these for Phase 1 profiling |
| `doc_comments: Vec<DocCommentInfo>` | `doc_comment: Option<String>` on FunctionInfo | ✅ Standalone vector | **ADD** — Standalone doc comments (module-level, class-level) needed by DNA |
| `file: Spur` | `file_path: Option<String>` | `file: Spur` (interned) | **CHANGE** — Use interned Spur, always present (not Optional) |
| `call_sites` (name) | `calls: Vec<CallSite>` | `call_sites: Vec<CallSite>` | **RENAME** — `call_sites` is more precise |
| `error_count: u32` | `has_errors: bool` + `error_ranges: Vec<Range>` | `error_count: u32` | **KEEP BOTH** — `error_count` for quick check, `error_ranges` for detail |
| `decorators` (top-level) | Only on FunctionInfo/ClassInfo | ✅ Top-level vector | **ADD** — Module-level decorators needed by boundary detection |

**Decision**: The reconciled ParseResult includes ALL fields from both documents.
The parser extracts everything in a single pass. See §4 for the definitive type.

### Inconsistency #2: FunctionInfo Field Types (String vs Spur, Vec vs SmallVec)

| Field | 01-PARSERS.md | 06-UAE-V2-PREP.md | Resolution |
|-------|--------------|-------------------|------------|
| `name` | `String` | `Spur` (interned) | **CHANGE** → `Spur` — per AD12, all identifiers interned |
| `qualified_name` | `Option<String>` | `Option<Spur>` | **CHANGE** → `Option<Spur>` |
| `file` | `PathBuf` | `Spur` | **CHANGE** → `Spur` — per PathInterner |
| `parameters` | `Vec<ParameterInfo>` | `SmallVec<[ParamInfo; 4]>` | **CHANGE** → `SmallVec<[ParameterInfo; 4]>` — most functions have ≤4 params |
| `decorators` | `Vec<DecoratorInfo>` | `SmallVec<[Spur; 2]>` | **KEEP Vec<DecoratorInfo>** — UAE's `SmallVec<[Spur; 2]>` is a simplified reference; full DecoratorInfo needed by boundary detection |
| `generic_params` | `Vec<GenericParam>` | `SmallVec<[String; 2]>` | **CHANGE** → `SmallVec<[GenericParam; 2]>` — keep rich type, use SmallVec |

**Decision**: Use `Spur` for all identifiers and paths. Use `SmallVec` for collections
that are typically small (parameters, generics, decorators). Keep rich types (not just
Spur references) where downstream consumers need structured data.

### Inconsistency #3: tree-sitter Version (v0.24 vs v0.25+)

| Source | Version |
|--------|---------|
| DRIFT-V2-STACK-HIERARCHY.md | `tree-sitter v0.24` (pinned in workspace dependencies) |
| 04-INFRASTRUCTURE-V2-PREP.md §7 | `tree-sitter = "0.24"` (Cargo workspace) |
| 01-PARSERS.md §1 | `tree-sitter (v0.25+)` |

**Resolution**: **v0.24** — The hierarchy and infrastructure docs pin v0.24 in the Cargo
workspace. The 01-PARSERS.md was written speculatively before the workspace was pinned.
v0.24 is the current stable release. If v0.25 ships before Drift v2 and offers compelling
improvements, upgrade then. For now, pin v0.24.

### Inconsistency #4: Language Count (10 languages — which 10?)

| Source | Languages Listed |
|--------|-----------------|
| 01-PARSERS.md §1 | TS, JS, Python, Java, C#, PHP, Go, Rust, **C, C++** |
| DRIFT-V2-STACK-HIERARCHY.md | TS, JS, Python, Java, C#, Go, Rust, **Ruby, PHP, Kotlin** |

**Resolution**: The hierarchy is the authority. **10 languages: TypeScript, JavaScript,
Python, Java, C#, Go, Rust, Ruby, PHP, Kotlin.** C and C++ from 01-PARSERS.md are
replaced by Ruby and Kotlin. Rationale: Ruby and Kotlin have larger web framework
ecosystems (Rails, Spring Kotlin) relevant to Drift's pattern detection. C/C++ can be
added later via the `define_parser!` macro.

### Inconsistency #5: CallSite Field Names

| Field | 01-PARSERS.md | 06-UAE-V2-PREP.md | 05-CALL-GRAPH-V2-PREP.md |
|-------|--------------|-------------------|--------------------------|
| Name of callee | `callee: String` | `callee_name: Spur` | `callee_name: String` |
| Argument info | `arg_count: usize` | `argument_count: u8` | `arg_count: usize` |
| Await tracking | Not present | `is_await: bool` | Not present |
| Column | Not present | `column: u32` | Not present |

**Resolution**: Reconciled CallSite uses `callee_name: Spur`, `argument_count: u8`
(u8 is sufficient — no function has >255 args), adds `is_await: bool` and `column: u32`.
See §4 for definitive type.

### Inconsistency #6: Numbering Discrepancy in Stack Hierarchy

Both Error Handling Analysis and Impact Analysis are labeled "System 16" in the hierarchy.
This is a documentation numbering error. Error Handling is System 16, Impact Analysis is
System 17. The parser doc is unaffected — both consume ParseResult identically.

### Summary of All Resolutions

| # | Inconsistency | Resolution | Impact |
|---|--------------|------------|--------|
| 1 | ParseResult missing 6 fields | Add all 6 (tree, source, string_literals, numeric_literals, error_handling, doc_comments) | Parser extracts more per file |
| 2 | String vs Spur, Vec vs SmallVec | Use Spur for identifiers, SmallVec for small collections | Memory reduction, faster comparison |
| 3 | tree-sitter v0.24 vs v0.25+ | Pin v0.24 per hierarchy | No code impact |
| 4 | C/C++ vs Ruby/Kotlin | Ruby + Kotlin replace C + C++ | Different grammar crates |
| 5 | CallSite field names | Reconcile to UAE contract + add is_await | Minor field rename |
| 6 | System numbering | Documentation fix only | No code impact |


---

## 3. Core Library: tree-sitter v0.24

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
| Ruby | `tree-sitter-ruby` | Good (tree-sitter org) | `.rb`, `.rake`, `.gemspec` |
| Kotlin | `tree-sitter-kotlin` | Good | `.kt`, `.kts` |

### Cargo Dependencies

```toml
[workspace.dependencies]
tree-sitter = "0.24"
tree-sitter-typescript = "0.23"
tree-sitter-javascript = "0.23"
tree-sitter-python = "0.23"
tree-sitter-java = "0.23"
tree-sitter-c-sharp = "0.23"
tree-sitter-php = "0.23"
tree-sitter-go = "0.23"
tree-sitter-rust = "0.23"
tree-sitter-ruby = "0.23"
tree-sitter-kotlin = "0.23"
```

Note: Grammar crate versions track tree-sitter core. Pin to compatible versions.
Exact minor versions may vary — use the latest compatible with tree-sitter 0.24.


---

## 4. Canonical Data Model (Reconciled ParseResult — Single Source of Truth)

This is the DEFINITIVE ParseResult shape. It reconciles 01-PARSERS.md with
06-UAE-V2-PREP.md and all downstream consumer contracts. v1 had three different
ParseResult shapes (Rust, TS, NAPI). v2 has exactly one. Rust defines it.
The UAE consumes it. Nothing else defines it.

### ParseResult

```rust
/// The canonical parse result. Produced by LanguageParser, consumed by every
/// downstream system. This is the single source of truth — no other crate
/// defines a competing ParseResult shape.
pub struct ParseResult {
    // ---- Identity ----
    pub file: Spur,                                // Interned file path (always present)
    pub language: Language,
    pub content_hash: u64,                         // xxh3 of source — cache key

    // ---- Raw AST (owned by this result) ----
    pub tree: Tree,                                // tree-sitter AST (owned, not Send)
    pub source: Vec<u8>,                           // Raw source bytes (needed by UAE visitor)

    // ---- Structural Extraction ----
    pub functions: Vec<FunctionInfo>,
    pub classes: Vec<ClassInfo>,
    pub imports: Vec<ImportInfo>,
    pub exports: Vec<ExportInfo>,

    // ---- Call & Reference Extraction ----
    pub call_sites: Vec<CallSite>,                 // Renamed from `calls` for precision
    pub decorators: Vec<DecoratorInfo>,             // Top-level + all nested

    // ---- Literal Extraction (NEW — required by UAE, Constants, Taint) ----
    pub string_literals: Vec<StringLiteralInfo>,    // Pre-extracted strings with context
    pub numeric_literals: Vec<NumericLiteralInfo>,  // For magic number detection
    pub error_handling: Vec<ErrorHandlingInfo>,     // try/catch/throw/finally constructs
    pub doc_comments: Vec<DocCommentInfo>,          // Standalone doc comments

    // ---- Metadata ----
    pub namespace: Option<Spur>,                   // Java package, C# namespace, PHP namespace, Go package
    pub parse_time_us: u64,
    pub error_count: u32,                          // tree-sitter ERROR node count
    pub error_ranges: Vec<Range>,                  // Locations of ERROR nodes
    pub has_errors: bool,                          // Quick check: error_count > 0
}
```

**Why `tree` and `source` are included**: The UAE's visitor pattern engine (Phase 1.5)
needs the raw tree-sitter AST for single-pass traversal. The string extractor (Phase 2)
needs raw source bytes. The GAST normalizer needs both. Without these, every downstream
consumer would need to re-parse — defeating the "parse once, analyze many" architecture.

**Why `string_literals` and `numeric_literals` are pre-extracted**: The Constants &
Environment system (22-CONSTANTS-V2-PREP) needs these for secret detection and magic
number detection. Pre-extracting during the parse pass (which already walks the AST)
is essentially free — adding a second AST walk later would double the cost.

**Why `error_handling` is pre-extracted**: The Error Handling Analysis system
(16-ERROR-HANDLING-V2-PREP) needs try/catch/throw/finally constructs for Phase 1
profiling. These are structural AST nodes extracted during the same pass as functions
and classes.

**Thread safety note**: `Tree` is NOT `Send`. ParseResult therefore is NOT `Send`.
This is fine — ParseResult is produced and consumed within the same rayon worker thread
via `thread_local!` parsers. Cross-thread sharing happens via the extracted data
(FunctionInfo, CallSite, etc.), which ARE `Send`.

### FunctionInfo (Reconciled)

```rust
pub struct FunctionInfo {
    pub name: Spur,                                 // Interned via lasso
    pub qualified_name: Option<Spur>,               // "Class.method" or "module.function"
    pub file: Spur,                                 // Interned file path
    pub line: u32,
    pub column: u32,
    pub end_line: u32,
    pub parameters: SmallVec<[ParameterInfo; 4]>,   // SmallVec — most functions have ≤4 params
    pub return_type: Option<String>,
    pub generic_params: SmallVec<[GenericParam; 2]>, // SmallVec — most have 0-2 generics
    pub visibility: Visibility,                     // Always present (Public default)
    pub is_exported: bool,
    pub is_async: bool,
    pub is_generator: bool,
    pub is_abstract: bool,
    pub range: Range,
    pub decorators: Vec<DecoratorInfo>,             // Full structured decorators
    pub doc_comment: Option<String>,                // Per-function doc comment
    pub body_hash: u64,                             // xxh3 of function body text
    pub signature_hash: u64,                        // xxh3 of (name + params + return type)
}
```

### ClassInfo

```rust
pub struct ClassInfo {
    pub name: Spur,
    pub namespace: Option<Spur>,                    // Fully qualified namespace
    pub extends: Option<Spur>,
    pub implements: SmallVec<[Spur; 2]>,
    pub generic_params: SmallVec<[GenericParam; 2]>,
    pub is_exported: bool,
    pub is_abstract: bool,
    pub class_kind: ClassKind,
    pub methods: Vec<FunctionInfo>,                 // Methods nested in class (v1 was flat)
    pub properties: Vec<PropertyInfo>,
    pub range: Range,
    pub decorators: Vec<DecoratorInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClassKind {
    Class, Interface, Struct, Enum, Trait, Record, Union, TypeAlias,
}
```

### DecoratorInfo (Structured — Not Strings)

v1 extracted decorators as `Vec<String>`. v2 extracts structured data with parsed
arguments. This is the single most impactful extraction improvement — framework
detection (Spring, Django, FastAPI, Laravel, NestJS, ASP.NET) depends on annotation
argument values, not just names.

```rust
pub struct DecoratorInfo {
    pub name: Spur,                                 // Interned decorator name
    pub arguments: SmallVec<[DecoratorArgument; 2]>,
    pub raw_text: String,                           // Original text as fallback
    pub range: Range,
}

pub struct DecoratorArgument {
    pub key: Option<String>,                        // Named arg key (None for positional)
    pub value: String,                              // Argument value as string
}
```

### CallSite (Reconciled)

```rust
pub struct CallSite {
    pub callee_name: Spur,                          // Interned callee name
    pub receiver: Option<Spur>,                     // e.g., "db" in db.query()
    pub file: Spur,                                 // File containing the call
    pub line: u32,
    pub column: u32,
    pub argument_count: u8,                         // u8 sufficient (max 255)
    pub is_await: bool,                             // Whether call is awaited
}
```

### ImportInfo / ExportInfo

```rust
pub struct ImportInfo {
    pub source: String,                             // Module path
    pub specifiers: SmallVec<[ImportSpecifier; 4]>,
    pub is_type_only: bool,
    pub file: Spur,
    pub line: u32,
}

pub struct ImportSpecifier {
    pub name: Spur,                                 // Imported name
    pub alias: Option<Spur>,                        // Renamed import
}

pub struct ExportInfo {
    pub name: Option<Spur>,
    pub is_default: bool,
    pub is_type_only: bool,
    pub source: Option<String>,                     // Re-export source
    pub file: Spur,
    pub line: u32,
}
```

### NEW: StringLiteralInfo (Required by UAE Phase 2, Constants §7)

```rust
/// A string literal extracted from the AST with context.
/// Pre-extracted during parse to avoid a second AST walk.
pub struct StringLiteralInfo {
    pub value: String,                              // Unquoted string value
    pub context: StringContext,                      // Where this string appears
    pub file: Spur,
    pub line: u32,
    pub column: u32,
    pub range: Range,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

### NEW: NumericLiteralInfo (Required by Constants §6)

```rust
/// A numeric literal extracted from the AST with context.
/// Used by magic number detection (AST-based, not regex).
pub struct NumericLiteralInfo {
    pub value: f64,                                 // Parsed numeric value
    pub raw: String,                                // Original text (e.g., "0xFF", "1_000")
    pub context: NumericContext,                     // Where this number appears
    pub file: Spur,
    pub line: u32,
    pub column: u32,
    pub range: Range,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumericContext {
    ConstDeclaration,                               // const X = 42
    VariableAssignment,                             // let x = 42
    FunctionArgument,                               // foo(42)
    ArrayElement,                                   // [1, 2, 42]
    Comparison,                                     // if (x > 42)
    BinaryOperation,                                // x + 42
    ReturnValue,                                    // return 42
    DefaultParameter,                               // function f(x = 42)
    EnumValue,                                      // enum { A = 42 }
    Unknown,
}
```

### NEW: ErrorHandlingInfo (Required by Error Handling §5)

```rust
/// An error handling construct extracted from the AST.
/// Used by Error Handling Analysis Phase 1 (per-file profiling).
pub struct ErrorHandlingInfo {
    pub kind: ErrorHandlingKind,
    pub file: Spur,
    pub line: u32,
    pub end_line: u32,
    pub range: Range,
    pub caught_type: Option<String>,                // Exception type in catch clause
    pub has_body: bool,                             // false = empty catch (swallowed)
    pub function_scope: Option<Spur>,               // Enclosing function name
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorHandlingKind {
    TryCatch,                                       // try/catch (JS, Java, C#, PHP, Kotlin)
    TryExcept,                                      // try/except (Python)
    TryFinally,                                     // try/finally (all)
    Throw,                                          // throw/raise/panic
    ResultMatch,                                    // match on Result<T, E> (Rust)
    QuestionMark,                                   // ? operator (Rust)
    Unwrap,                                         // .unwrap() / .expect() (Rust)
    PromiseCatch,                                   // .catch() (JS/TS)
    AsyncAwaitTry,                                  // async function with try/catch
    Rescue,                                         // begin/rescue (Ruby)
    Defer,                                          // defer + recover (Go)
}
```

### NEW: DocCommentInfo (Required by DNA §6)

```rust
/// A standalone doc comment (module-level, class-level, or orphaned).
/// Per-function doc comments are on FunctionInfo.doc_comment.
/// This captures doc comments NOT attached to a function.
pub struct DocCommentInfo {
    pub text: String,
    pub style: DocCommentStyle,
    pub file: Spur,
    pub line: u32,
    pub range: Range,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocCommentStyle {
    JsDoc,                                          // /** ... */
    TripleSlash,                                    // /// (Rust, C#)
    Docstring,                                      // """ ... """ (Python)
    Pound,                                          // ## (Ruby)
    KDoc,                                           // /** ... */ (Kotlin)
    PhpDoc,                                         // /** ... */ (PHP)
    GoDoc,                                          // // Package ... (Go)
}
```

### Supporting Types (Preserved from 01-PARSERS.md)

```rust
pub struct ParameterInfo {
    pub name: Spur,
    pub type_annotation: Option<String>,
    pub default_value: Option<String>,
    pub is_rest: bool,                              // Variadic/rest parameter
}

pub struct PropertyInfo {
    pub name: Spur,
    pub type_annotation: Option<String>,
    pub is_static: bool,
    pub is_readonly: bool,
    pub visibility: Visibility,
    pub tags: Option<SmallVec<[StructTag; 2]>>,     // Go struct tags, serde attrs
}

pub struct StructTag {
    pub key: String,                                // e.g., "json", "gorm", "validate", "serde"
    pub value: String,
}

pub struct GenericParam {
    pub name: String,
    pub bounds: SmallVec<[String; 2]>,              // Type constraints/bounds
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Visibility { Public, Private, Protected }

pub struct Position { pub line: u32, pub column: u32 }
pub struct Range { pub start: Position, pub end: Position }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    TypeScript, JavaScript, Python, Java, CSharp,
    Php, Go, Rust, Ruby, Kotlin,
}
```

### Language Extension Mapping (All Preserved)

```
ts|tsx|mts|cts → TypeScript
js|jsx|mjs|cjs → JavaScript
py|pyi → Python
java → Java
cs → CSharp
php → Php
go → Go
rs → Rust
rb|rake|gemspec → Ruby
kt|kts → Kotlin
```


---

## 5. Parser Architecture (Trait-Based)

### LanguageParser Trait

v1 had 9 parsers with identical structure but no shared trait. v2 formalizes the contract:

```rust
pub trait LanguageParser: Send + Sync {
    fn language(&self) -> Language;
    fn extensions(&self) -> &[&str];
    fn parse(&mut self, source: &[u8], file: Spur) -> Result<ParseResult, ParseError>;
    fn parse_incremental(
        &mut self,
        source: &[u8],
        old_tree: &Tree,
        edits: &[InputEdit],
        file: Spur,
    ) -> Result<ParseResult, ParseError>;
    fn supports_framework_extraction(&self) -> bool { false }
    fn extract_framework_constructs(
        &self,
        tree: &Tree,
        source: &[u8],
    ) -> Vec<FrameworkConstruct> {
        Vec::new()
    }
}
```

Benefits:
- Clear contract every language parser must fulfill
- New languages added without modifying ParserManager
- Testable via mock parsers
- `Send + Sync` bound enables safe use with rayon (the trait is Send+Sync,
  but the Parser instance inside is thread_local — the trait bound is for
  the type itself, not the tree-sitter Parser it wraps)

### ParserManager (Trait-Object Dispatcher)

```rust
pub struct ParserManager {
    parsers: FxHashMap<Language, Box<dyn LanguageParser>>,
    extension_map: FxHashMap<String, Language>,
    cache: moka::sync::Cache<(Spur, u64), CachedParseData>,
    framework_extractors: Vec<Box<dyn FrameworkExtractor>>,
    interner: Arc<lasso::ThreadedRodeo>,
    stats: CacheStats,
}

impl ParserManager {
    pub fn new(interner: Arc<lasso::ThreadedRodeo>) -> Self { ... }

    pub fn parse_file(&mut self, path: &Path, source: &[u8]) -> Result<ParseResult, ParseError> {
        let ext = path.extension()
            .and_then(|e| e.to_str())
            .ok_or_else(|| ParseError::UnsupportedLanguage {
                extension: path.display().to_string()
            })?;
        let lang = *self.extension_map.get(ext)
            .ok_or_else(|| ParseError::UnsupportedLanguage {
                extension: ext.to_string()
            })?;
        let file_spur = self.interner.get_or_intern(
            &path.to_string_lossy().replace('\\', "/")
        );
        let hash = xxh3_hash(source);

        // Check cache
        if let Some(cached) = self.cache.get(&(file_spur, hash)) {
            self.stats.record_hit();
            return Ok(cached.to_parse_result(source, file_spur));
        }

        // Parse
        let parser = self.parsers.get_mut(&lang)
            .ok_or_else(|| ParseError::UnsupportedLanguage {
                extension: ext.to_string()
            })?;
        let result = parser.parse(source, file_spur)?;

        // Cache (without tree and source — those aren't Send)
        let cached = CachedParseData::from(&result);
        self.cache.insert((file_spur, hash), cached);
        self.stats.record_miss();

        Ok(result)
    }

    pub fn register(&mut self, parser: Box<dyn LanguageParser>) {
        for ext in parser.extensions() {
            self.extension_map.insert(ext.to_string(), parser.language());
        }
        self.parsers.insert(parser.language(), parser);
    }

    pub fn register_framework(&mut self, extractor: Box<dyn FrameworkExtractor>) {
        self.framework_extractors.push(extractor);
    }
}
```

### CachedParseData (Serializable Subset)

The parse cache stores everything EXCEPT `tree` and `source` (which are not
serializable/Send). On cache hit, the caller re-parses to get the tree (fast —
tree-sitter caches internally) but reuses all extracted data.

```rust
/// Cacheable subset of ParseResult. Excludes tree (not Send) and source (large).
/// Serialized via bincode for SQLite persistence.
#[derive(Clone, Serialize, Deserialize)]
pub struct CachedParseData {
    pub language: Language,
    pub functions: Vec<FunctionInfo>,
    pub classes: Vec<ClassInfo>,
    pub imports: Vec<ImportInfo>,
    pub exports: Vec<ExportInfo>,
    pub call_sites: Vec<CallSite>,
    pub decorators: Vec<DecoratorInfo>,
    pub string_literals: Vec<StringLiteralInfo>,
    pub numeric_literals: Vec<NumericLiteralInfo>,
    pub error_handling: Vec<ErrorHandlingInfo>,
    pub doc_comments: Vec<DocCommentInfo>,
    pub namespace: Option<Spur>,
    pub parse_time_us: u64,
    pub error_count: u32,
    pub error_ranges: Vec<Range>,
}
```

### Thread Safety: thread_local! with Explicit Cleanup

Tree-sitter `Parser` is NOT `Send` — it holds mutable internal state. Each rayon
worker thread needs its own parser instance.

```rust
thread_local! {
    static PARSER_MANAGER: RefCell<Option<ParserManager>> = RefCell::new(None);
}

pub fn with_parser<F, R>(interner: &Arc<lasso::ThreadedRodeo>, f: F) -> R
where F: FnOnce(&mut ParserManager) -> R {
    PARSER_MANAGER.with(|cell| {
        let mut opt = cell.borrow_mut();
        if opt.is_none() {
            *opt = Some(ParserManager::new(Arc::clone(interner)));
        }
        f(opt.as_mut().unwrap())
    })
}

/// Call between scan operations to release memory.
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

### Language Addition Scaffold: define_parser! Macro

Adding a new language should be mechanical:

```rust
define_parser! {
    name: RubyParser,
    language: Ruby,
    grammar: tree_sitter_ruby::LANGUAGE,
    extensions: [".rb", ".rake", ".gemspec"],
    queries: {
        structure: include_str!("queries/ruby/structure.scm"),
        calls: include_str!("queries/ruby/calls.scm"),
    }
}
```

The macro generates the struct, `new()` constructor (with query compilation), and
`LanguageParser` trait implementation. Language-specific extraction logic (Go struct
tags, Rust serde attributes, Ruby blocks) is added as override methods.

Steps to add a language:
1. Add `tree-sitter-{lang}` to Cargo.toml
2. Create `{lang}.rs` implementing `LanguageParser` trait (or use `define_parser!`)
3. Write tree-sitter queries for function, class, import, call extraction
4. Add extensions to `Language::from_extension()`
5. Register with ParserManager
6. Copy test template, fill in language-specific examples


---

## 6. Query Architecture (S-Expression, 2 Consolidated Traversals)

This is the most important architectural decision for parser performance.

### Pre-Compiled, Consolidated Queries

v1 used 4-5 separate queries per language, each requiring a full tree traversal.
v2 consolidates to 2 traversals per file:

1. **Structure query**: functions, classes, imports, exports, decorators, inheritance,
   string literals, numeric literals, error handling constructs, doc comments
2. **Call site query**: function calls, method calls, constructor calls

Tree-sitter supports multiple patterns in one query — each match tells you which
pattern matched via the pattern index. This halves traversal cost.

### Query Compilation Strategy

Queries compiled once at startup, reused across all files of the same language:

```rust
struct LanguageQueries {
    structure: Query,    // functions, classes, imports, exports, decorators, literals, error handling
    calls: Query,        // function calls, method calls, constructor calls
}
```

Store tree-sitter queries as `.scm` files in a `queries/` directory, loaded via
`include_str!` at compile time. Example structure:

```
crates/drift-core/src/parsers/queries/
├── typescript/
│   ├── structure.scm
│   └── calls.scm
├── python/
│   ├── structure.scm
│   └── calls.scm
├── java/
│   ├── structure.scm
│   └── calls.scm
... (10 languages)
```

### Query Predicates

Key tree-sitter query features used:
- `@name` captures nodes into named variables
- `#match?` applies regex predicates to captures
- `#eq?` checks exact string equality
- `(_)` is a wildcard matching any node type
- Field names (`name:`, `parameters:`) constrain which child is matched

### Example: TypeScript Structure Query (Consolidated)

```scheme
;; Functions
(function_declaration name: (identifier) @fn_name) @function
(method_definition name: (property_identifier) @fn_name) @method
(arrow_function) @arrow

;; Classes
(class_declaration name: (type_identifier) @class_name
  (class_heritage (extends_clause (identifier) @extends))?) @class

;; Imports
(import_statement source: (string) @import_source) @import

;; Exports
(export_statement) @export

;; Decorators
(decorator (call_expression function: (identifier) @decorator_name
  arguments: (arguments) @decorator_args)?) @decorator

;; String literals (for Constants/Environment)
(string) @string_literal
(template_string) @template_literal

;; Numeric literals (for magic number detection)
(number) @numeric_literal

;; Error handling
(try_statement) @try_catch
(throw_statement) @throw

;; Doc comments
(comment) @comment
```

Each capture group maps to an extraction function. The parser walks matches once,
dispatching to the appropriate extractor based on the capture name.


---

## 7. Parse Cache (Moka + SQLite Persistence)

### Why Cache Parses?

Parsing is fast (~6ms for a 2000-line file) but adds up across 100K files.
Content-addressed caching means unchanged files are never re-parsed. This is the
single highest-impact architectural decision for re-scan performance — 10-100x faster.

### In-Memory: Moka (TinyLFU + LRU)

Moka is a concurrent cache inspired by Java's Caffeine. TinyLFU admission + LRU
eviction provides near-optimal hit rates.

```rust
use moka::sync::Cache;

let parse_cache: Cache<(Spur, u64), CachedParseData> = Cache::builder()
    .max_capacity(10_000)
    .time_to_live(Duration::from_secs(3600))
    .build();

// Key: (interned_file_path, content_hash)
// Value: CachedParseData (everything except tree and source)
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
    content_hash BLOB NOT NULL,          -- xxh3 hash (8 bytes)
    parse_result BLOB NOT NULL,          -- bincode-serialized CachedParseData
    cached_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (path, content_hash)
) STRICT;
```

On startup: load hot entries from SQLite into Moka. On cache miss: parse, store in
Moka AND SQLite.

### Two-Tier Incrementality

1. **File-level (batch/CLI)**: Skip unchanged files entirely using content hash
   comparison against `file_metadata` table
2. **Edit-level (IDE)**: Use tree-sitter's `tree.edit()` + incremental `parse()` for
   sub-millisecond re-parse of edited files. Cache tree-sitter `Tree` objects per open file.

### Cache Invalidation

Cache entries are keyed by `(file_path, content_hash)`. When a file changes, its
content hash changes, so the old entry is naturally bypassed. No explicit invalidation
needed. Stale entries are evicted by Moka's LRU/TinyLFU policy.

---

## 8. Error-Tolerant Parsing

Tree-sitter is inherently error-tolerant — it produces `ERROR` nodes where it can't
parse but continues parsing the rest of the file. This is critical for real-world
codebases and IDE integration where files are frequently in invalid states mid-edit.

### Strategy

1. **Never fail on error nodes**: Skip ERROR nodes, continue extracting from valid siblings
2. **Partial results are valuable**: A file with a syntax error in one function still
   yields valid extraction for all other functions
3. **Track error locations**: Include error node positions in `ParseResult.error_ranges`
4. **Attempt partial extraction**: Even from error regions, try to extract name and range

```rust
fn extract_functions(&self, root: &Node, source: &[u8]) -> Vec<FunctionInfo> {
    let mut cursor = QueryCursor::new();
    let mut functions = Vec::new();
    for match_ in cursor.matches(&self.structure_query, *root, source) {
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

Track error recovery rate per language for observability. Log warnings with file path
and error node location. Return `ParseResult` with `has_errors: true` flag and
`error_count` for quick filtering.

---

## 9. Per-Language Parser Details (10 Languages)

Each language parser follows an identical pattern:
1. Initialize tree-sitter `Parser` with compile-time-linked grammar
2. Pre-compile tree-sitter `Query` objects (2 consolidated queries: structure + calls)
3. `parse(source)` → parse tree → run queries → collect into `ParseResult`

### TypeScript/JavaScript (`typescript.rs`)
- Grammar: `tree-sitter-typescript` (handles both TS and JS via `is_typescript` flag)
- Extracts: `function_declaration`, `method_definition`, `arrow_function`,
  `class_declaration` with `extends_clause`/`implements_clause`, `import_statement`
  (default, named, namespace), `export_statement`, `call_expression`, `new_expression`
- Enterprise: Decorator extraction (structured), JSDoc comments, type annotations,
  return types, async/generator detection, constructor properties, generic type parameters
- Literals: `string`, `template_string` → StringLiteralInfo; `number` → NumericLiteralInfo
- Error handling: `try_statement`, `catch_clause`, `throw_statement`, `.catch()` chains

### Python (`python.rs`)
- Grammar: `tree-sitter-python`
- Extracts: `function_definition`, `decorated_definition`, `class_definition` (with bases,
  multiple inheritance), `import_statement`, `import_from_statement`, `call` with
  `identifier`/`attribute` callee
- Enterprise: Structured decorator extraction (`@decorator(args)`), parameter types +
  defaults, return type (`-> Type`), docstrings, base class extraction, generator
  detection (`yield`), class property extraction
- Framework awareness: FastAPI, Django, Flask, SQLAlchemy patterns via decorators
- Deduplication: Tracks decorated function lines to avoid double-counting
- Literals: `string`, `concatenated_string` → StringLiteralInfo; `integer`, `float` → NumericLiteralInfo
- Error handling: `try_statement`, `except_clause`, `raise_statement`

### Java (`java.rs`)
- Grammar: `tree-sitter-java`
- Extracts: `method_declaration`, `constructor_declaration` with modifiers,
  `class_declaration`, `interface_declaration` with superclass/interfaces,
  `import_declaration`, `method_invocation`, `object_creation_expression`
- Enterprise: Structured annotation extraction (`@Service`, `@GetMapping(path="/api")`,
  `@Autowired`), Javadoc comments, visibility modifiers, abstract class detection,
  generic type support, package declaration
- Framework awareness: Spring, JPA, validation annotations
- Literals: `string_literal` → StringLiteralInfo; `decimal_integer_literal`, `decimal_floating_point_literal` → NumericLiteralInfo
- Error handling: `try_statement`, `catch_clause`, `throw_statement`, `throws` declaration

### C# (`csharp.rs`)
- Grammar: `tree-sitter-c-sharp`
- Extracts: `method_declaration`, `constructor_declaration`, `class_declaration`,
  `interface_declaration`, `struct_declaration`, `record_declaration`, `using_directive`,
  `invocation_expression`, `object_creation_expression`
- Enterprise: `[Attribute]` extraction (structured), XML doc comments (`/// <summary>`),
  parameter types, property extraction with attributes, namespace extraction (including
  file-scoped C# 10+), async detection
- Framework awareness: ASP.NET Core routes, authorization, Entity Framework
- Literals: `string_literal`, `verbatim_string_literal` → StringLiteralInfo; `integer_literal`, `real_literal` → NumericLiteralInfo
- Error handling: `try_statement`, `catch_clause`, `throw_statement`

### PHP (`php.rs`)
- Grammar: `tree-sitter-php` (LANGUAGE_PHP)
- Extracts: `function_definition`, `method_declaration` with visibility,
  `class_declaration`, `interface_declaration`, `trait_declaration`,
  `namespace_use_declaration`, `function_call_expression`, `member_call_expression`,
  `scoped_call_expression`, `object_creation_expression`
- Enterprise: PHP 8 attributes (`#[Route]`, `#[IsGranted]`) structured extraction,
  extends/implements, parameter types + defaults, return types, PHPDoc comments,
  visibility modifiers, abstract class detection, property extraction
- Framework awareness: Laravel, Symfony attribute patterns
- Literals: `string`, `encapsed_string` → StringLiteralInfo; `integer`, `float` → NumericLiteralInfo
- Error handling: `try_statement`, `catch_clause`, `throw_expression`

### Go (`go.rs`)
- Grammar: `tree-sitter-go`
- Extracts: `function_declaration`, `method_declaration` (with receiver),
  `type_declaration` → `struct_type`/`interface_type`, `import_declaration` with alias
  support, `call_expression` with `selector_expression` receiver
- Enterprise: Struct field extraction with tags (`json:"name" gorm:"primaryKey"`),
  parameter types, return types, doc comments, Go export convention (uppercase = exported),
  variadic parameters, interface detection, generic type parameters (`[T any]`)
- Unique: `StructTag` parsing for `json`, `gorm`, `validate`, `db` tags
- Literals: `interpreted_string_literal`, `raw_string_literal` → StringLiteralInfo; `int_literal`, `float_literal` → NumericLiteralInfo
- Error handling: `if` + `err != nil` pattern detection, `defer` + `recover` detection

### Rust (`rust_lang.rs`)
- Grammar: `tree-sitter-rust`
- Extracts: `function_item` with visibility/params/return type, `struct_item`,
  `enum_item`, `trait_item`, `impl_item`, `use_declaration`, `call_expression` with
  `field_expression`/`scoped_identifier`
- Enterprise: `#[derive(...)]` extraction, `#[serde(...)]` tag parsing, route attributes
  for Actix/Axum/Rocket, parameter types, return types, doc comments (`///`, `//!`),
  visibility modifiers (`pub`, `pub(crate)`), async detection, struct field extraction
  with serde tags, generic type parameters with trait bounds
- Unique: Separate attribute query, `self` parameter handling, serde attribute → StructTag
- Literals: `string_literal`, `raw_string_literal` → StringLiteralInfo; `integer_literal`, `float_literal` → NumericLiteralInfo
- Error handling: `match` on `Result`, `?` operator, `.unwrap()`, `.expect()`

### Ruby (`ruby.rs`) — NEW (replaces C from 01-PARSERS.md)
- Grammar: `tree-sitter-ruby`
- Extracts: `method`, `singleton_method`, `class`, `module`, `call` with
  `identifier`/`scope_resolution`, block arguments
- Enterprise: Method visibility (`private`, `protected`, `public` calls), module mixins
  (`include`, `extend`, `prepend`), attr_accessor/reader/writer, RSpec/Minitest patterns
- Framework awareness: Rails routes, ActiveRecord models, concerns
- Literals: `string`, `heredoc_body` → StringLiteralInfo; `integer`, `float` → NumericLiteralInfo
- Error handling: `begin`/`rescue`/`ensure` blocks, `raise` statements

### Kotlin (`kotlin.rs`) — NEW (replaces C++ from 01-PARSERS.md)
- Grammar: `tree-sitter-kotlin`
- Extracts: `function_declaration`, `class_declaration`, `object_declaration`,
  `import_header`, `call_expression`
- Enterprise: Annotation extraction (`@RestController`, `@GetMapping`), data classes,
  sealed classes, companion objects, extension functions, coroutine detection (`suspend`),
  null safety operators
- Framework awareness: Spring Kotlin, Ktor routes, Exposed ORM
- Literals: `string_literal`, `multiline_string_literal` → StringLiteralInfo; `integer_literal`, `real_literal` → NumericLiteralInfo
- Error handling: `try_expression`, `catch_block`, `throw` expression


---

## 10. Namespace/Package Extraction

v1 was missing this entirely in Rust. v2 extracts namespace/package declarations for
every language:

| Language | Construct | Example | Query Target |
|----------|-----------|---------|--------------|
| Java | `package` declaration | `package com.example.service;` | `package_declaration` |
| C# | `namespace` declaration | `namespace MyApp.Services { }` | `namespace_declaration` |
| PHP | `namespace` declaration | `namespace App\Http\Controllers;` | `namespace_definition` |
| Go | `package` declaration | `package main` | `package_clause` |
| Rust | `mod` declaration | `mod handlers;` | `mod_item` |
| Kotlin | `package` declaration | `package com.example.api` | `package_header` |
| Python | Implicit from file path | `app/services/auth.py` → `app.services.auth` | File path |
| TypeScript | Implicit from file path | `src/services/auth.ts` → `src/services/auth` | File path |
| Ruby | `module` declaration | `module MyApp::Services` | `module` |

Essential for: qualified name resolution in call graph, module coupling analysis,
architectural boundary detection, import resolution.

---

## 11. Pydantic Model Extraction (Rust-Native)

This was a 9-file TS-only subsystem in v1. v2 builds it natively in Rust.
Priority P0 — FastAPI contract detection depends on this.

### Components

1. **Model detector**: Identify classes extending `BaseModel` (or known Pydantic bases)
   from tree-sitter class definition nodes
2. **Field extractor**: Extract field definitions — name, type annotation, default value,
   alias, `Field()` constraints
3. **Type resolver**: Recursively resolve Python type annotations: `Optional[str]`,
   `List[Dict[str, int]]`, `Union[str, int]`, `str | int` (3.10+). Cycle detection
   via depth limit (default 10)
4. **Constraint parser**: Parse `Field()` arguments: ge, le, gt, lt, min_length,
   max_length, pattern, multiple_of
5. **Validator extractor**: Extract `@field_validator` (v2) and `@validator` (v1)
   decorators with target fields and mode (before/after/wrap)
6. **Config extractor**: Extract `model_config = ConfigDict(...)` (v2) or
   `class Config:` (v1) with settings
7. **Version detector**: Distinguish v1 vs v2 by checking for `ConfigDict` vs `Config`
   class, `field_validator` vs `validator`

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

pub enum ValidatorMode { Before, After, Wrap }

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

| Feature | Pydantic v1 | Pydantic v2 |
|---------|-------------|-------------|
| Config | `class Config:` | `model_config = ConfigDict(...)` |
| Validators | `@validator` | `@field_validator` |
| Root validators | `@root_validator` | `@model_validator` |
| Frozen | `class Config: allow_mutation = False` | `ConfigDict(frozen=True)` |

---

## 12. GAST Normalization Layer (~30 Node Types)

### The Problem

Without GAST, every detector needs per-language variants. A "detect try-catch patterns"
detector needs to know the specific AST node names for each of 10 languages.

### The Solution: ~30 Normalized Node Types

```rust
pub enum GastNode {
    Function { name: Spur, params: Vec<Param>, body: Vec<GastNode>, is_async: bool },
    Class { name: Spur, methods: Vec<GastNode>, extends: Option<Spur> },
    TryCatch { try_body: Vec<GastNode>, catch_clauses: Vec<CatchClause>, finally: Option<Vec<GastNode>> },
    Call { target: Spur, args: Vec<GastNode> },
    Import { path: Spur, names: Vec<Spur> },
    Export { name: Spur, is_default: bool },
    Route { method: HttpMethod, path: Spur, handler: Spur },
    Assignment { target: Spur, value: Box<GastNode> },
    Return { value: Option<Box<GastNode>> },
    If { condition: Box<GastNode>, then: Vec<GastNode>, else_: Option<Vec<GastNode>> },
    Loop { body: Vec<GastNode> },
    StringLiteral { value: String },
    NumericLiteral { value: f64 },
    Identifier { name: Spur },
    MemberAccess { object: Box<GastNode>, property: Spur },
    Decorator { name: Spur, args: Vec<GastNode> },
    Block { statements: Vec<GastNode> },
    // ~30 total node types covering 80% of detection needs
}
```

Each language gets a normalizer (~500-1000 lines) that converts language-specific
CST → GAST. Detectors then work on GAST only.

### Decision: Optimization Layer, Not Replacement

Build GAST as a Tier 1 system (after basic parsers work). Keep language-specific
detectors for truly unique patterns (Rust lifetimes, PHP attributes, Go goroutines).
Use GAST for the ~80% of detectors that work across languages (error handling, naming
conventions, import patterns, etc.).

Benefits:
- Adding a new language requires only a normalizer — all existing detectors work automatically
- Reduces detector codebase by 50-70%
- Single test suite for cross-language behavior

Same approach as ast-grep — native query language for language-specific patterns,
normalized API for cross-language operations.

---

## 13. Framework Construct Extraction

Framework-specific constructs (route decorators, DI annotations, ORM model definitions)
are critical for boundary detection, contract tracking, and security analysis. These
run as a post-pass after base parsing.

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

pub enum HttpMethod { Get, Post, Put, Patch, Delete, Head, Options, Any }
```

### Framework Extractors to Build

| Framework | Language | Key Constructs |
|-----------|----------|---------------|
| Spring Boot | Java/Kotlin | `@RestController`, `@GetMapping`, `@Service`, `@Entity`, `@PreAuthorize` |
| FastAPI | Python | `@app.get()`, `Depends()`, BaseModel subclasses |
| Django | Python | `urlpatterns`, `models.Model`, `@login_required` |
| Laravel | PHP | `Route::get()`, Eloquent models, `#[Middleware]` |
| NestJS | TypeScript | `@Controller`, `@Get`, `@Injectable`, `@Guard` |
| ASP.NET | C# | `[ApiController]`, `[HttpGet]`, `[Authorize]`, `DbContext` |
| Express | TypeScript | `app.get()`, `router.use()`, middleware functions |
| Actix/Axum/Rocket | Rust | `#[get]`, `#[post]`, extractors, middleware |
| Gin/Echo | Go | Handler patterns, middleware |
| Rails | Ruby | `routes.rb`, ActiveRecord models, `before_action` |
| Ktor | Kotlin | `routing { get("/") { } }`, `install()` |

Framework extractors operate on `ParseResult` (post-parse), not on the raw tree-sitter
tree. Detection is primarily decorator/annotation-driven (structured DecoratorInfo
provides the data). Registration: `manager.register_framework(Box::new(SpringExtractor::new()))`.
Framework extraction is optional — can be skipped for performance when not needed.


---

## 14. Structured Error Types (thiserror)

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
impl ParseError {
    pub fn error_code(&self) -> &'static str {
        match self {
            ParseError::UnsupportedLanguage { .. } => "UNSUPPORTED_LANGUAGE",
            ParseError::GrammarInitFailed { .. } => "GRAMMAR_INIT_FAILED",
            ParseError::ParseFailed { .. } => "PARSE_ERROR",
            ParseError::QueryCompilationFailed { .. } => "QUERY_COMPILATION",
            ParseError::IoError(_) => "IO_ERROR",
            ParseError::CacheError(_) => "CACHE_ERROR",
        }
    }
}
```

---

## 15. Event Emissions (DriftEventHandler)

Per D5: The parser emits events via `DriftEventHandler`. Zero overhead when no handlers
registered (standalone mode). When the bridge is active, these events can feed into
Cortex memory creation.

```rust
// Parser-specific event methods (added to DriftEventHandler trait)
fn on_parse_started(&self, _file: Spur, _language: Language) {}
fn on_parse_complete(&self, _file: Spur, _parse_time_us: u64, _function_count: usize) {}
fn on_parse_error(&self, _file: Spur, _error: &ParseError) {}
fn on_parse_cache_hit(&self, _file: Spur) {}
fn on_parse_cache_miss(&self, _file: Spur) {}
```

---

## 16. Observability (tracing)

Per AD10: Instrument with `tracing` crate from day one.

```rust
#[instrument(skip(source), fields(language = %language, file_size = source.len()))]
pub fn parse(&mut self, source: &[u8], language: Language) -> Result<ParseResult, ParseError> {
    let _span = tracing::info_span!("parse_file").entered();
    // ...
    info!(
        functions = result.functions.len(),
        classes = result.classes.len(),
        call_sites = result.call_sites.len(),
        string_literals = result.string_literals.len(),
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
- `string_literal_count` — monitor extraction volume
- `error_handling_count` — monitor error construct extraction

---

## 17. NAPI Bridge for Parsers

### Core Principle (from 03-NAPI-BRIDGE-V2-PREP §5)

**ParseResult NEVER crosses the NAPI boundary.** Rust does ALL heavy computation AND
writes results to drift.db. NAPI return values are lightweight summaries. The tree-sitter
`Tree` object is not serializable and not Send — it stays in Rust.

### What Crosses NAPI (lightweight)

- `ParseSummary` — counts (functions, classes, imports, calls), timing, error count
- `JsFunctionInfo` — for specific query results (paginated)
- `supported_languages()` — list of language strings

### What Does NOT Cross NAPI (stays in Rust)

- Raw tree-sitter `Tree` objects — never leave Rust
- `source: Vec<u8>` — stays in Rust
- Full `ParseResult` — consumed by UAE, call graph, detectors in Rust
- Intermediate query cursor state
- Full cache contents
- `StringLiteralInfo`, `NumericLiteralInfo`, `ErrorHandlingInfo` — consumed in Rust only

### APIs

```rust
/// Parse summary for a single file (for IDE/query use)
#[napi]
pub fn parse_file_summary(file_path: String) -> napi::Result<ParseSummary> { ... }

/// List supported languages
#[napi]
pub fn supported_languages() -> Vec<String> { ... }

/// Cache statistics
#[napi]
pub fn parse_cache_stats() -> napi::Result<CacheStats> { ... }
```

The batch parse API is internal to the Rust pipeline — it's called by the scanner
and UAE, not by TypeScript. The `analyze_batch()` NAPI function (from 03-NAPI-BRIDGE-V2-PREP §9)
orchestrates parsing internally as part of the analysis pipeline.

---

## 18. Performance Targets

### Benchmarks (from tree-sitter)

- Initial parse of a 2000-line file: ~6ms
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

APFS directory scanning is single-threaded at the kernel level. Parallel walking helps
with per-file work (hashing, metadata) but not directory enumeration. This is a known
limitation — ripgrep has the same constraint.

---

## 19. v1 → v2 Gap Closure

These are the specific gaps from v1 Rust parsers that v2 must close:

| Feature | v1 Rust | v2 Requirement | Priority |
|---------|---------|----------------|----------|
| Generic type parameters | ❌ Missing | Full extraction with bounds | P0 |
| Structured decorators/annotations | ❌ Strings only | `DecoratorInfo` with parsed arguments | P0 |
| Pydantic model support | ❌ Missing | Full Rust-native extraction | P0 |
| Namespace/package extraction | ❌ Missing | All 10 languages | P1 |
| Full inheritance chains | Partial | Complete MRO resolution | P1 |
| Framework construct detection | Partial | `FrameworkExtractor` trait system | P1 |
| Access modifiers on functions | Partial | Always present `Visibility` | P1 |
| Incremental parsing | ❌ Missing | tree-sitter `tree.edit()` for IDE | P2 |
| AST caching | ❌ Missing | Moka + SQLite persistence | P0 |
| Body hash for change detection | ❌ Missing | xxh3 on function body | P0 |
| Consolidated queries (2 per file) | ❌ 4-5 per file | Structure + calls | P1 |
| Methods nested in ClassInfo | ❌ Flat | Methods as children of class | P1 |
| ClassKind enum | ❌ Missing | class/interface/struct/enum/trait/record/union/typealias | P1 |
| Content hash on ParseResult | ❌ Missing | xxh3 for cache key | P0 |
| String literal extraction | ❌ Missing | StringLiteralInfo with context | P0 |
| Numeric literal extraction | ❌ Missing | NumericLiteralInfo with context | P0 |
| Error handling extraction | ❌ Missing | ErrorHandlingInfo (try/catch/throw) | P0 |
| Standalone doc comments | ❌ Missing | DocCommentInfo | P1 |
| Ruby parser | ❌ Missing | Full extraction | P1 |
| Kotlin parser | ❌ Missing | Full extraction | P1 |
| String interning (lasso) | ❌ Missing | Spur for all identifiers/paths | P0 |

---

## 20. Security Considerations

1. **Untrusted input**: Parsers process arbitrary source code. Tree-sitter is memory-safe
   and handles malformed input gracefully, but extraction logic must not panic on
   unexpected AST shapes
2. **Resource exhaustion**: Deeply nested files or extremely long lines could cause stack
   overflow. Implement depth limits on recursive extraction (especially Pydantic type
   resolution — default 10)
3. **Cache poisoning**: Parse cache persisted to disk must have appropriate permissions.
   Content hash verified on read
4. **NAPI boundary**: All data crossing Rust-JS boundary must be validated. No raw
   pointers or internal Rust state leaks through NAPI
5. **Secret exposure**: ParseResult contains source code snippets (doc_comment, decorator
   raw_text, string_literals). Ensure these are not inadvertently logged or exposed
   through MCP tools without filtering


---

## 21. Build Order

The parser subsystem is built in 5 phases. Each phase is independently testable.
No phase depends on a later phase. Updated from 01-PARSERS.md §20 to include
the 6 new extraction types (string_literals, numeric_literals, error_handling,
doc_comments) and the 2 new languages (Ruby, Kotlin).

```
Phase 1 — Core Architecture (everything depends on this):
  ├── Canonical ParseResult shape with ALL enriched types (§4)
  │   └── Including: tree, source, string_literals, numeric_literals,
  │       error_handling, doc_comments (reconciled with UAE contract)
  ├── LanguageParser trait + ParserManager dispatcher
  ├── thiserror ParseError enum (per AD6)
  ├── thread_local! parser pool with explicit cleanup
  ├── Language enum (10 variants) + extension mapping
  ├── String interning setup (ThreadedRodeo integration)
  └── All supporting types: FunctionInfo, ClassInfo, ImportInfo, ExportInfo,
      CallSite, DecoratorInfo, ParameterInfo, PropertyInfo, GenericParam,
      StringLiteralInfo, NumericLiteralInfo, ErrorHandlingInfo, DocCommentInfo

Phase 2 — Rich Extraction (build parsers with full extraction from day one):
  ├── 8 existing language parsers (TS, JS, Python, Java, C#, PHP, Go, Rust)
  │   └── Each with 2 consolidated tree-sitter queries (structure + calls)
  ├── 2 NEW language parsers (Ruby, Kotlin)
  │   └── Ruby: method, singleton_method, class, module, begin/rescue
  │   └── Kotlin: function_declaration, class_declaration, object_declaration
  ├── Structured decorator/annotation extraction (DecoratorInfo with arguments)
  ├── Namespace/package extraction (all 10 languages)
  ├── Generic type parameter extraction (GenericParam with bounds)
  ├── String literal extraction with context (StringLiteralInfo)
  ├── Numeric literal extraction with context (NumericLiteralInfo)
  ├── Error handling construct extraction (ErrorHandlingInfo)
  ├── Standalone doc comment extraction (DocCommentInfo)
  ├── Error-tolerant extraction (partial results from ERROR nodes)
  ├── Body hash + signature hash on FunctionInfo (xxh3)
  ├── ClassKind enum (class/interface/struct/enum/trait/record/union/typealias)
  ├── Methods nested in ClassInfo (not flat)
  └── tracing instrumentation on all parse paths (per AD10)

Phase 3 — Caching & Performance:
  ├── Moka parse cache (content-addressed, TinyLFU, 10K entries)
  ├── CachedParseData (serializable subset — excludes tree + source)
  ├── SQLite cache persistence (bincode serialization to parse_cache table)
  ├── Cache hit/miss/eviction metrics via tracing
  ├── DriftEventHandler event emissions (on_parse_started, on_parse_complete, etc.)
  └── NAPI lightweight APIs (parse_file_summary, supported_languages, cache_stats)

Phase 4 — Domain-Specific Extraction:
  ├── Pydantic model extraction (Rust-native, v1+v2 support)
  │   └── Model detector, field extractor, type resolver, constraint parser,
  │       validator extractor, config extractor, version detector
  ├── Framework construct extractors (FrameworkExtractor trait)
  │   └── Spring Boot, FastAPI, Django, Laravel, NestJS, ASP.NET,
  │       Express, Actix/Axum/Rocket, Gin/Echo, Rails, Ktor
  └── Framework registration with ParserManager

Phase 5 — Normalization & Extensibility:
  ├── GAST normalization layer (~30 node types)
  │   └── Per-language normalizers (10 languages × ~500-1000 lines each)
  ├── define_parser! macro for mechanical language addition
  └── Incremental parsing support (tree-sitter tree.edit() for IDE mode)
```

### Phase Dependencies

```
Phase 1 ← nothing (pure type definitions + trait contracts)
Phase 2 ← Phase 1 (parsers implement the trait, produce the types)
Phase 3 ← Phase 1 + Phase 2 (cache wraps parser output)
Phase 4 ← Phase 2 (framework extractors consume ParseResult)
Phase 5 ← Phase 2 (GAST normalizes ParseResult; macro wraps parser pattern)
```

Phase 4 and Phase 5 are independent of each other and can be built in parallel.

### Estimated Effort

| Phase | Estimated Lines | Estimated Time |
|-------|----------------|----------------|
| Phase 1 | ~800 (types + traits + error types) | 2-3 days |
| Phase 2 | ~6,000 (10 parsers × ~600 lines each) | 8-12 days |
| Phase 3 | ~600 (cache layer + NAPI + events) | 2-3 days |
| Phase 4 | ~2,500 (Pydantic ~1000 + 11 framework extractors ~150 each) | 4-6 days |
| Phase 5 | ~6,000 (GAST normalizers + macro + incremental) | 6-10 days |
| **Total** | **~16,000** | **22-34 days** |


---

## 22. Cross-System Impact Matrix

The parser subsystem is the most depended-upon component in Drift. Changes to
ParseResult cascade to every downstream system. This matrix maps every consumer
to the specific ParseResult fields it requires, including the 6 NEW fields
added during reconciliation with the UAE contract.

### Field → Consumer Mapping

| ParseResult Field | Consumers | Why They Need It |
|-------------------|-----------|-----------------|
| `tree: Tree` | UAE (Phase 1.5 visitor), GAST normalizer | Raw AST traversal for single-pass analysis |
| `source: Vec<u8>` | UAE (Phase 2 string extraction), GAST normalizer | Source bytes for string extraction, node text |
| `functions: Vec<FunctionInfo>` | Call Graph, Detectors, Test Topology, Error Handling, DNA, Constraints, Taint | Function-level analysis across all systems |
| `classes: Vec<ClassInfo>` | Call Graph, Detectors, Boundary Detection, DNA, Constraints, Coupling | Class hierarchy, inheritance, method grouping |
| `imports: Vec<ImportInfo>` | Call Graph, Boundary Detection, Coupling Analysis, Detectors | Module dependency tracking, ORM detection |
| `exports: Vec<ExportInfo>` | Call Graph, Coupling Analysis, Detectors | Public API surface, dead export detection |
| `call_sites: Vec<CallSite>` | Call Graph, Taint Analysis, Boundary Detection, Security, N+1 Detection | Function→function edges, source/sink identification |
| `decorators: Vec<DecoratorInfo>` | Boundary Detection, Contract Tracking, Test Topology, Security, Framework Extractors | Annotation-driven framework detection, route extraction |
| `string_literals: Vec<StringLiteralInfo>` | Constants/Environment (§7 secrets), Taint Analysis, DNA | Secret detection, magic string detection, codebase fingerprinting |
| `numeric_literals: Vec<NumericLiteralInfo>` | Constants/Environment (§6 magic numbers), DNA | Magic number detection (AST-based, not regex) |
| `error_handling: Vec<ErrorHandlingInfo>` | Error Handling Analysis (Phase 1), DNA, Detectors | Error propagation profiling, swallowed exception detection |
| `doc_comments: Vec<DocCommentInfo>` | DNA System (§6 gene extraction), Documentation detectors | Module-level documentation analysis, codebase fingerprinting |
| `namespace: Option<Spur>` | Call Graph (qualified names), Coupling Analysis, Boundary Detection | Fully qualified name resolution, module grouping |
| `content_hash: u64` | Scanner (incrementality), Cache (key), Storage | Change detection, cache invalidation |
| `error_count: u32` / `has_errors: bool` | UAE (skip/warn on high-error files), Quality Gates | Parse quality filtering |
| `error_ranges: Vec<Range>` | IDE integration, Error Handling Analysis | Error location reporting |
| `file: Spur` | Every consumer | File identity (interned for O(1) comparison) |
| `language: Language` | Every consumer | Language-specific dispatch |
| `parse_time_us: u64` | Observability, Performance monitoring | Parse performance tracking |

### Consumer → Required Fields Mapping

| Consumer System | Required Fields | Optional Fields |
|----------------|-----------------|-----------------|
| **Unified Analysis Engine** | tree, source, functions, classes, imports, exports, call_sites, decorators, string_literals, numeric_literals, error_handling, doc_comments | All (primary consumer) |
| **Call Graph Builder** | functions (name, qualified_name, parameters, is_exported), call_sites, imports, exports, classes (methods) | namespace |
| **Detector System** | tree, source, functions, classes, imports, decorators | string_literals, error_handling |
| **Boundary Detection** | decorators (arguments), imports (source), classes (extends, implements) | call_sites, string_literals |
| **Taint Analysis** | call_sites (callee_name, receiver, argument_count), functions (parameters), string_literals | imports |
| **Test Topology** | functions (decorators, is_async), decorators | classes, imports |
| **Error Handling Analysis** | error_handling (kind, caught_type, has_body, function_scope), functions | call_sites |
| **Constants/Environment** | string_literals (value, context), numeric_literals (value, context) | functions (scope) |
| **Contract Tracking** | decorators (route paths, arguments), PydanticModelInfo | imports, exports |
| **DNA System** | ALL fields | None optional — full codebase fingerprinting |
| **Coupling Analysis** | imports (source, specifiers), exports (name, source) | functions, classes |
| **Constraints** | functions (name, parameters), classes (name, methods) | decorators, imports |
| **GAST Normalizer** | tree, source | All extraction vectors (for validation) |
| **Security Analysis** | decorators (auth patterns), call_sites, string_literals | error_handling |
| **Quality Gates** | error_count, has_errors, parse_time_us | error_ranges |

### Cascade Impact of ParseResult Changes

Any change to ParseResult shape requires updates in:

1. **CachedParseData** — must mirror all serializable fields
2. **bincode serialization** — schema version bump for SQLite cache
3. **UAE Phase 1.5 visitor** — if new fields affect visitor dispatch
4. **GAST normalizer** — if new AST constructs are extracted
5. **DNA gene extraction** — if new fields contribute to fingerprint
6. **Test fixtures** — all parser test files need updated expected output

This is why ParseResult changes are the highest-risk modifications in the system.
The reconciled shape in §4 is designed to be complete enough that no further
field additions should be needed for v2 launch.


---

## 23. Decision Registry

All architectural decisions for the parser subsystem, updated with resolutions
from the reconciliation process (§2). Decisions marked with ⚡ were changed
from the original 01-PARSERS.md based on downstream V2-PREP document contracts.

| # | Decision | Choice | Confidence | Source | Notes |
|---|----------|--------|------------|--------|-------|
| D1 | Parser library | tree-sitter v0.24 | Very High | Hierarchy, Infrastructure | ⚡ Changed from v0.25+ (01-PARSERS.md) to v0.24 (pinned in workspace) |
| D2 | Thread safety | thread_local! per rayon worker with cleanup | High | R11, ast-grep pattern | Unchanged |
| D3 | Query strategy | Pre-compiled, 2 consolidated traversals per file | High | R5, A3 | Unchanged |
| D4 | Parse cache | Moka (TinyLFU) + SQLite persistence | High | R1, A3 | Unchanged |
| D5 | Error handling | Extract partial results from valid subtrees | High | R9 | Unchanged |
| D6 | Body hash | xxh3 of function body for fine-grained invalidation | High | A3 | Unchanged |
| D7 | Signature hash | xxh3 of signature for cross-file stability | High | A3 | Unchanged |
| D8 | Data model | Single canonical ParseResult, enriched types | Very High | R2, UAE contract | ⚡ Expanded: 6 new fields from UAE reconciliation |
| D9 | Decorators | Structured DecoratorInfo with parsed arguments | Very High | R3 | Unchanged |
| D10 | Generics | GenericParam with bounds on FunctionInfo + ClassInfo | High | R10 | Unchanged |
| D11 | Namespaces | Extracted for all 10 languages | High | R7 | ⚡ Updated: 10 languages (was "all languages that have them") |
| D12 | Pydantic | Rust-native extraction, v1+v2 support | High | R4 | Unchanged |
| D13 | GAST | Optimization layer, not replacement | Medium-High | Audit Cat 02 | Unchanged |
| D14 | Framework extraction | Trait-based post-pass after base parsing | High | R12 | ⚡ Updated: 11 frameworks (added Rails, Ktor) |
| D15 | Parser architecture | LanguageParser trait, ParserManager dispatcher | High | R6 | Unchanged |
| D16 | Error types | thiserror per-subsystem enum | Very High | R13, AD6 | Unchanged |
| D17 | NAPI bridge | Lightweight summaries only, ParseResult stays in Rust | High | R8, 03-NAPI §5 | Unchanged |
| D18 | Config format | TOML for declarative patterns | High | AD3 | Unchanged |
| D19 | Observability | tracing crate, per-language metrics | Very High | AD10 | Unchanged |
| D20 | Events | DriftEventHandler with no-op defaults | High | D5 | Unchanged |
| D21 | Language scaffold | define_parser! macro | Medium | R14 | Unchanged |
| D22 | String interning | lasso (ThreadedRodeo → RodeoReader) | High | AD12 | Unchanged |
| D23 | Content hashing | xxh3 via xxhash-rust | High | Scanner research | Unchanged |
| D24 | Language list | TS, JS, Python, Java, C#, Go, Rust, Ruby, PHP, Kotlin | Very High | Hierarchy | ⚡ Changed: Ruby + Kotlin replace C + C++ |
| D25 | Identifier types | Spur for all identifiers and paths | High | AD12, UAE contract | ⚡ New: reconciled from String → Spur |
| D26 | Collection types | SmallVec for small collections (params, generics) | High | AD12, UAE contract | ⚡ New: reconciled from Vec → SmallVec where appropriate |
| D27 | Literal extraction | Pre-extract string + numeric literals during parse | High | UAE, 22-CONSTANTS | ⚡ New: required by Constants/Environment system |
| D28 | Error handling extraction | Pre-extract try/catch/throw during parse | High | UAE, 16-ERROR-HANDLING | ⚡ New: required by Error Handling Analysis |
| D29 | Doc comment extraction | Standalone doc comments as separate vector | Medium-High | UAE, 24-DNA | ⚡ New: required by DNA gene extraction |
| D30 | CallSite field names | callee_name (Spur), argument_count (u8), is_await, column | High | UAE, Call Graph | ⚡ Reconciled across 3 docs |

### Decisions Deferred

| Decision | Status | Revisit When |
|----------|--------|-------------|
| tree-sitter v0.25 upgrade | Deferred | When v0.25 ships stable and offers compelling improvements |
| C/C++ language support | Deferred | Post-launch, via define_parser! macro |
| WASM parser loading | Rejected | Static linking is simpler, faster, and sufficient for 10 languages |
| Async parsing | Rejected | tree-sitter is synchronous; thread_local! + rayon is the correct model |
| Custom query language | Rejected | tree-sitter S-expressions are sufficient; ast-grep validates this approach |

---

*End of document. 23 sections. Reconciled against 15+ source documents.*
*This is the DEFINITIVE parser specification for Drift v2.*
