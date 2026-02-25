# Unified Language Provider — V2 Implementation Prep

> Comprehensive build specification for Drift v2's Unified Language Provider subsystem.
> Synthesized from: 05-analyzers/unified-provider.md (v1 architecture, 9 normalizers, 20 matchers),
> 05-analyzers/language-analyzers.md (10 per-language analyzers, framework extractions),
> 05-analyzers/core-analyzers.md (4 core analyzers consumed by ULP),
> 13-advanced/language-intelligence/ (normalizers, frameworks, registry, queries, types),
> 06-UNIFIED-ANALYSIS-ENGINE-V2-PREP.md §11 (Rust port spec, LanguageNormalizer trait, OrmMatcher trait),
> DRIFT-V2-FULL-SYSTEM-AUDIT.md (AD4, AD11, Cat 05),
> DRIFT-V2-STACK-HIERARCHY.md (Level 1 — Structural Skeleton),
> PLANNING-DRIFT.md (D1-D7),
> 03-NAPI-BRIDGE-V2-PREP.md (command/query pattern),
> 04-INFRASTRUCTURE-V2-PREP.md (thiserror, tracing, FxHashMap, SmallVec, lasso),
> .research/05-analyzers/RECOMMENDATIONS.md (R4, R5, R8),
> .research/03-detectors/RECOMMENDATIONS.md (R1-R12),
> Semgrep ast_generic architecture, Ant Group YASA UAST research (2025),
> MLCPD universal AST schema research (2025).
>
> Purpose: Everything needed to build the Unified Language Provider from scratch.
> This is the DEDICATED deep-dive for the ULP subsystem — the 06-UNIFIED-ANALYSIS-ENGINE
> doc covers ULP at summary level (§11); this document is the full implementation spec
> with every normalizer, every matcher, every type, every edge case, every integration
> point, and every v1 feature accounted for. Zero feature loss.
> Generated: 2026-02-07

---

## 1. Architectural Position

The Unified Language Provider (ULP) is the semantic bridge between raw tree-sitter
parsing and language-agnostic pattern detection. It is the most sophisticated extraction
system in Drift — responsible for normalizing AST differences across 9 languages into
a universal `UnifiedCallChain` representation, then running 20 ORM/framework matchers
against those chains to detect data access patterns.

It sits at Level 1 — Structural Skeleton, alongside the Unified Analysis Engine.
The ULP is a subsystem OF the analysis engine, not a peer. It runs during the
per-file analysis pipeline and feeds results into boundary detection, taint analysis,
and pattern aggregation.

Per PLANNING-DRIFT.md D1: Drift is standalone. ULP writes ORM patterns to drift.db.
Per AD4: Single-pass visitor pattern — ULP extraction happens during the same traversal.
Per AD11: Taint analysis integration — ULP's ORM patterns feed taint sink detection.

### What Lives Here
- 9 language normalizers (TS/JS, Python, Java, C#, PHP, Go, Rust, C++, base)
- 20 ORM/framework matchers (Supabase through Raw SQL)
- UnifiedCallChain universal representation
- OrmPattern result type with table/operation/field extraction
- MatcherRegistry with language-indexed dispatch
- 5 language intelligence normalizers (TS, Python, Java, C#, PHP)
- Framework registry with 5 framework pattern sets (Spring, FastAPI, NestJS, Laravel, ASP.NET)
- Decorator normalization pipeline (raw → normalized → semantic)
- Cross-language semantic query engine (entry points, data accessors, auth handlers)
- 12 semantic categories (routing, di, orm, auth, validation, test, logging, caching, scheduling, messaging, middleware, unknown)
- Legacy compatibility adapters (unified-scanner, unified-data-access-adapter)

### What Does NOT Live Here
- GAST normalization (~30 node types) → Unified Analysis Engine §7
- Per-language analyzers (route/component/hook extraction) → Unified Analysis Engine §12
- Detector trait definitions → Detector System
- Pattern aggregation & deduplication → Pattern Intelligence (Level 2A)
- Call graph builder → Call Graph (Level 1, separate)
- Rules engine → Enforcement (Level 3)

### Downstream Consumers

| Consumer | What It Reads | Interface |
|----------|--------------|-----------|
| Boundary Detection | OrmPattern[] with table/operation/fields | Vec<OrmPattern> |
| Taint Analysis | ORM sinks (SQL queries, command exec) | Vec<TaintSink> from OrmPattern |
| Pattern Aggregation | Data access pattern frequency/consistency | PatternStats |
| Context Generation | Framework detection, entry points, data flow | NormalizedExtractionResult |
| DNA System | ORM fingerprint (which ORMs, which patterns) | OrmFingerprint |
| Call Graph Enrichment | Semantic function classification | FunctionSemantics |
| MCP Tools | Cross-language queries (find entry points, etc.) | QueryResult[] |

### Upstream Dependencies

| Dependency | What It Provides | Contract |
|-----------|-----------------|----------|
| Parsers (Level 0) | ParseResult with tree, source, functions, imports | §2 of 06-UAE-V2-PREP |
| String Interning (Level 1) | ThreadedRodeo / RodeoReader, Spur handles | lasso crate |
| Infrastructure (Level 0) | thiserror, tracing, FxHashMap, SmallVec | 04-INFRASTRUCTURE |
| Call Graph Extractors | FunctionExtraction, FileExtractionResult | Per-language extractors |

---

## 2. V1 Complete Feature Inventory

Every feature in the v1 Unified Language Provider, catalogued for zero-loss verification.

### 2.1 Core Files (v1 TypeScript)

```
packages/core/src/unified-provider/
├── unified-language-provider.ts    # Main provider class
├── unified-scanner.ts              # Drop-in replacement for SemanticDataAccessScanner
├── unified-data-access-adapter.ts  # Bridge to existing DataAccessPoint format
├── legacy-extractors.ts            # Backward-compatible extractor aliases
├── legacy-scanner.ts               # Backward-compatible scanner wrapper
├── normalizers/
│   ├── base-normalizer.ts          # Abstract base normalizer
│   ├── typescript-normalizer.ts    # TS/JS normalizer
│   ├── python-normalizer.ts        # Python normalizer
│   ├── java-normalizer.ts          # Java normalizer
│   ├── csharp-normalizer.ts        # C# normalizer
│   ├── php-normalizer.ts           # PHP normalizer
│   ├── go-normalizer.ts            # Go normalizer
│   ├── rust-normalizer.ts          # Rust normalizer
│   └── cpp-normalizer.ts           # C++ normalizer
├── matchers/
│   ├── base-matcher.ts             # Abstract base matcher
│   ├── matcher-registry.ts         # Registry + dispatch
│   ├── supabase-matcher.ts         # Supabase
│   ├── prisma-matcher.ts           # Prisma
│   ├── typeorm-matcher.ts          # TypeORM
│   ├── sequelize-matcher.ts        # Sequelize
│   ├── drizzle-matcher.ts          # Drizzle
│   ├── knex-matcher.ts             # Knex
│   ├── mongoose-matcher.ts         # Mongoose
│   ├── django-matcher.ts           # Django ORM
│   ├── sqlalchemy-matcher.ts       # SQLAlchemy
│   ├── efcore-matcher.ts           # Entity Framework Core
│   ├── eloquent-matcher.ts         # Laravel Eloquent
│   ├── spring-data-matcher.ts      # Spring Data JPA
│   ├── gorm-matcher.ts             # GORM
│   ├── diesel-matcher.ts           # Diesel
│   ├── seaorm-matcher.ts           # SeaORM
│   ├── sqlx-matcher.ts             # SQLx
│   ├── raw-sql-matcher.ts          # Raw SQL (all languages)
│   └── database-sql-matcher.ts     # database/sql (Go)
└── types.ts                        # All ULP types
```

### 2.2 Language Intelligence Files (v1 TypeScript)

```
packages/core/src/language-intelligence/
├── language-intelligence.ts        # Main orchestrator (query engine)
├── base-normalizer.ts              # Abstract base for LI normalizers
├── framework-registry.ts           # Singleton framework pattern registry
├── types.ts                        # Semantic types (12 categories, decorators, etc.)
├── normalizers/
│   ├── typescript-normalizer.ts    # TS/JS LI normalizer
│   ├── python-normalizer.ts        # Python LI normalizer
│   ├── java-normalizer.ts          # Java LI normalizer
│   ├── csharp-normalizer.ts        # C# LI normalizer
│   └── php-normalizer.ts           # PHP LI normalizer
└── frameworks/
    ├── index.ts                    # Aggregation + utilities
    ├── spring.ts                   # Spring Boot patterns
    ├── fastapi.ts                  # FastAPI patterns
    ├── nestjs.ts                   # NestJS patterns
    ├── laravel.ts                  # Laravel patterns
    └── aspnet.ts                   # ASP.NET Core patterns
```

### 2.3 Feature Matrix — Every Capability

| # | Feature | V1 Status | V2 Status | V2 Location |
|---|---------|-----------|-----------|-------------|
| F1 | 8 language normalizers (TS, Py, Java, C#, PHP, Go, Rust, C++) | ✅ | PRESERVED | normalizers/*.rs |
| F2 | Base normalizer abstract class | ✅ | UPGRADED → trait | NormalizerBase trait |
| F3 | 18 concrete ORM matchers | ✅ | PRESERVED | matchers/*.rs |
| F4 | Base matcher abstract class | ✅ | UPGRADED → trait | OrmMatcher trait |
| F5 | Matcher registry with language dispatch | ✅ | PRESERVED | MatcherRegistry |
| F6 | UnifiedCallChain type | ✅ | PRESERVED + enhanced | types.rs |
| F7 | CallSegment with method/args/await/optional | ✅ | PRESERVED | types.rs |
| F8 | ArgValue enum (string, number, ident, expr, array, object) | ✅ | PRESERVED | types.rs |
| F9 | OrmPattern result (orm, table, operation, fields, conditions) | ✅ | PRESERVED + enhanced | types.rs |
| F10 | DataOperation enum (Select, Insert, Update, Delete, etc.) | ✅ | PRESERVED | types.rs |
| F11 | OrmType enum (18 variants) | ✅ | PRESERVED | types.rs |
| F12 | Unified scanner (drop-in replacement) | ✅ | DROPPED (no legacy) | — |
| F13 | Data access adapter (bridge to DataAccessPoint) | ✅ | DROPPED (native type) | — |
| F14 | Legacy extractors (backward compat aliases) | ✅ | DROPPED (clean break) | — |
| F15 | Legacy scanner wrapper | ✅ | DROPPED (clean break) | — |
| F16 | 5 LI normalizers (TS, Py, Java, C#, PHP) | ✅ | MERGED into ULP | normalizers/*.rs |
| F17 | Decorator normalization pipeline | ✅ | PRESERVED | decorator.rs |
| F18 | Framework registry (singleton, indexed by language) | ✅ | PRESERVED | framework_registry.rs |
| F19 | 5 framework pattern sets (Spring, FastAPI, NestJS, Laravel, ASP.NET) | ✅ | PRESERVED + expanded | frameworks/*.rs |
| F20 | Decorator semantic classification (12 categories) | ✅ | PRESERVED | types.rs |
| F21 | Function semantics derivation | ✅ | PRESERVED | semantics.rs |
| F22 | File semantics derivation (isController, isService, etc.) | ✅ | PRESERVED | semantics.rs |
| F23 | Cross-language query engine (findEntryPoints, etc.) | ✅ | PRESERVED | queries.rs |
| F24 | QueryOptions (category, isEntryPoint, framework, language) | ✅ | PRESERVED | types.rs |
| F25 | QueryResult (function, file, framework, matchedDecorators) | ✅ | PRESERVED | types.rs |
| F26 | DecoratorSemantics (category, intent, isEntryPoint, etc.) | ✅ | PRESERVED | types.rs |
| F27 | NormalizedDecorator (raw, name, language, framework, semantic, args) | ✅ | PRESERVED | types.rs |
| F28 | DecoratorArguments (path, methods, roles, extensible) | ✅ | PRESERVED | types.rs |
| F29 | FunctionSemantics (8 boolean flags + structured data) | ✅ | PRESERVED | types.rs |
| F30 | NormalizedExtractionResult (functions, frameworks, fileSemantics) | ✅ | PRESERVED | types.rs |
| F31 | FrameworkPattern (framework, languages, detection, mappings) | ✅ | PRESERVED | types.rs |
| F32 | DecoratorMapping (pattern, semantic, confidence, extractArgs) | ✅ | PRESERVED | types.rs |
| F33 | Factory functions (createNormalizer, createAllNormalizers, etc.) | ✅ | UPGRADED → registry | NormalizerRegistry |
| F34 | Framework detection from source (import + decorator regex) | ✅ | PRESERVED | framework_registry.rs |
| F35 | Decorator name extraction (strip @, #, [], ()) | ✅ | PRESERVED | decorator.rs |
| F36 | Generic argument extraction from decorators | ✅ | PRESERVED | decorator.rs |
| F37 | Per-language dependency extraction | ✅ | PRESERVED | normalizers/*.rs |

### 2.4 Dropped Features — Justification

| Feature | Why Dropped |
|---------|-------------|
| F12: Unified scanner (drop-in) | V2 has no legacy scanner to replace. Clean architecture. |
| F13: Data access adapter | V2 uses OrmPattern natively. No DataAccessPoint bridge needed. |
| F14: Legacy extractors | V2 is a clean break. No backward-compat aliases. |
| F15: Legacy scanner wrapper | Same as F12. |

All 4 dropped features are compatibility shims. Zero functional loss.

---

## 3. V2 Architecture — Unified Design

### The Key Insight: Merge ULP + Language Intelligence

V1 has two separate but overlapping systems:
1. **Unified Language Provider** — Call chain extraction + ORM matching (data access focus)
2. **Language Intelligence** — Decorator normalization + semantic classification (framework focus)

These share normalizers, framework detection, and language dispatch. V2 merges them
into a single `UnifiedLanguageProvider` that does both call chain extraction AND
semantic classification in one pass.

### V2 Architecture

```
                    UnifiedLanguageProvider
                    ┌─────────────────────────────────────────┐
                    │                                         │
  ParseResult ──────►  NormalizerRegistry                     │
                    │  ├── TypeScriptNormalizer                │
                    │  ├── PythonNormalizer                    │
                    │  ├── JavaNormalizer                      │
                    │  ├── CSharpNormalizer                    │
                    │  ├── PhpNormalizer                       │
                    │  ├── GoNormalizer                        │
                    │  ├── RustNormalizer                      │
                    │  └── CppNormalizer                       │
                    │       │                                  │
                    │       ├── extract_call_chains() ─────────┤──► Vec<UnifiedCallChain>
                    │       ├── extract_framework_patterns() ──┤──► Vec<FrameworkExtraction>
                    │       └── normalize_decorators() ────────┤──► Vec<NormalizedDecorator>
                    │                                          │
                    │  MatcherRegistry                         │
                    │  ├── SupabaseMatcher                     │
                    │  ├── PrismaMatcher                       │
                    │  ├── ... (18 concrete matchers)          │
                    │  └── RawSqlMatcher                       │
                    │       │                                  │
                    │       └── match_chain() ─────────────────┤──► Vec<OrmPattern>
                    │                                          │
                    │  FrameworkRegistry                        │
                    │  ├── Spring patterns                     │
                    │  ├── FastAPI patterns                    │
                    │  ├── NestJS patterns                     │
                    │  ├── Laravel patterns                    │
                    │  └── ASP.NET patterns                    │
                    │       │                                  │
                    │       └── detect_frameworks() ───────────┤──► Vec<DetectedFramework>
                    │                                          │
                    │  SemanticDeriver                          │
                    │  ├── derive_function_semantics()          │
                    │  ├── derive_file_semantics()             │
                    │  └── classify_decorators()               │
                    │       │                                  │
                    │       └── ──────────────────────────────┤──► UlpResult
                    └─────────────────────────────────────────┘
```

### Single-Pass Integration

The ULP runs as part of the per-file analysis pipeline (Phase 1.5 in the Unified
Analysis Engine). During the visitor pattern traversal, the ULP's normalizer is
invoked for call chain extraction. After traversal, matchers run against extracted
chains, and semantic derivation classifies functions and files.

```
Per-File Pipeline:
  Phase 1:   AST queries (27 pre-compiled)
  Phase 1.5: Visitor engine + ULP extraction (single traversal)
              ├── Call chain extraction (normalizer)
              ├── Decorator normalization (normalizer)
              ├── ORM matching (matcher registry)
              └── Semantic derivation (deriver)
  Phase 2:   String extraction
  Phase 3:   String literal analysis
  Phase 4:   Resolution index population
```



---

## 4. Core Data Model

### 4.1 UnifiedCallChain — The Universal Representation

Every language normalizer produces this. It represents a sequence of method calls
that matchers analyze to detect ORM/framework patterns.

```rust
/// Universal representation of a method call sequence.
/// Examples:
///   supabase.from('users').select('*').eq('id', userId)
///   prisma.user.findMany({ where: { active: true } })
///   Model.objects.filter(active=True).order_by('name')
///   db.Where("age > ?", 18).Find(&users)
///   context.Set<User>().Where(u => u.Active).ToListAsync()
pub struct UnifiedCallChain {
    /// Initial receiver object (e.g., "supabase", "prisma", "db", "Model")
    pub receiver: Option<Spur>,

    /// Ordered sequence of method calls in the chain
    pub segments: SmallVec<[CallSegment; 4]>,

    /// Source location
    pub file: Spur,
    pub line: u32,
    pub column: u32,
    pub end_line: u32,
    pub end_column: u32,

    /// Language that produced this chain
    pub language: Language,

    /// Whether the entire chain is awaited (async context)
    pub is_awaited: bool,

    /// Raw source text of the full chain (for debugging/display)
    pub raw_text: Option<String>,

    /// Enclosing function (for context — which function contains this chain)
    pub enclosing_function: Option<Spur>,
}

/// A single method call within a chain.
pub struct CallSegment {
    /// Method name (e.g., "from", "select", "eq", "findMany")
    pub method: Spur,

    /// Arguments passed to this method
    pub args: SmallVec<[CallArg; 4]>,

    /// Whether this specific segment is awaited
    pub is_await: bool,

    /// Whether this uses optional chaining (?. in TS/JS)
    pub is_optional: bool,

    /// Generic type arguments (e.g., Set<User> in C#, query_as::<User> in Rust)
    pub type_args: SmallVec<[String; 2]>,
}

/// A single argument in a method call.
pub struct CallArg {
    /// The argument value
    pub value: ArgValue,

    /// Named/keyword argument name (Python kwargs, C# named args)
    pub name: Option<Spur>,

    /// Position index (0-based)
    pub position: u8,
}

/// Argument value variants — covers all language argument types.
pub enum ArgValue {
    /// String literal: 'users', "SELECT * FROM users"
    StringLiteral(String),

    /// Numeric literal: 42, 3.14
    NumberLiteral(f64),

    /// Boolean literal: true, false
    BooleanLiteral(bool),

    /// Identifier reference: userId, Model, table
    Identifier(Spur),

    /// Raw expression text (fallback for complex expressions)
    Expression(String),

    /// Array literal: ['id', 'name', 'email']
    Array(Vec<ArgValue>),

    /// Object literal: { where: { active: true }, select: { id: true } }
    Object(Vec<(String, ArgValue)>),

    /// Lambda/closure: u => u.Active, |x| x.id
    Lambda {
        params: Vec<String>,
        body: String,
    },

    /// Null/None/nil
    Null,

    /// Spread/rest: ...args, *args, **kwargs
    Spread(Box<ArgValue>),
}
```

### 4.2 OrmPattern — Matcher Output

```rust
/// Result of an ORM matcher recognizing a call chain pattern.
pub struct OrmPattern {
    /// Which ORM/framework was detected
    pub orm: OrmType,

    /// Table/collection/model name (if extractable)
    pub table: Option<String>,

    /// Data operation type
    pub operation: DataOperation,

    /// Field names referenced (SELECT fields, INSERT columns, etc.)
    pub fields: Vec<String>,

    /// WHERE/filter conditions (simplified representation)
    pub conditions: Vec<String>,

    /// Source location (from the call chain)
    pub file: Spur,
    pub line: u32,
    pub column: u32,
    pub end_line: u32,
    pub end_column: u32,

    /// Number of segments in the matched chain
    pub chain_length: u8,

    /// Matcher confidence (0.0-1.0)
    pub confidence: f32,

    /// Whether this is a raw/inline SQL query (vs. ORM builder)
    pub is_raw_sql: bool,

    /// The raw SQL string if detected (for raw SQL matcher)
    pub raw_sql: Option<String>,

    /// Enclosing function (inherited from call chain)
    pub enclosing_function: Option<Spur>,

    /// Whether the query includes joins
    pub has_joins: bool,

    /// Whether the query includes aggregations (COUNT, SUM, etc.)
    pub has_aggregation: bool,

    /// Ordering/sorting detected
    pub has_ordering: bool,

    /// Pagination detected (LIMIT/OFFSET, take/skip, etc.)
    pub has_pagination: bool,

    /// Whether this is inside a transaction context
    pub in_transaction: bool,
}

/// All supported ORM types (18 concrete + 1 unknown).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OrmType {
    Supabase,
    Prisma,
    TypeOrm,
    Sequelize,
    Drizzle,
    Knex,
    Mongoose,
    Django,
    SqlAlchemy,
    EfCore,
    Eloquent,
    SpringData,
    Gorm,
    Diesel,
    SeaOrm,
    Sqlx,
    RawSql,
    DatabaseSql,
    Unknown,
}

/// Data operation types (8 variants — all preserved from v1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataOperation {
    Select,
    Insert,
    Update,
    Delete,
    Upsert,
    Count,
    Aggregate,
    Raw,
}
```

### 4.3 Semantic Types — Decorator Normalization

```rust
/// 12 semantic categories for decorator/annotation classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SemanticCategory {
    Routing,
    DependencyInjection,
    Orm,
    Auth,
    Validation,
    Test,
    Logging,
    Caching,
    Scheduling,
    Messaging,
    Middleware,
    Unknown,
}

/// Semantic meaning of a decorator/annotation.
pub struct DecoratorSemantics {
    pub category: SemanticCategory,
    pub intent: String,
    pub is_entry_point: bool,
    pub is_injectable: bool,
    pub requires_auth: bool,
    pub data_access: Option<DataAccessMode>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataAccessMode {
    Read,
    Write,
    Both,
}

/// A decorator/annotation after normalization.
pub struct NormalizedDecorator {
    /// Original string from tree-sitter (e.g., "@GetMapping(\"/users\")")
    pub raw: String,

    /// Normalized name (e.g., "GetMapping") — stripped of @, #, [], ()
    pub name: String,

    /// Source language
    pub language: Language,

    /// Detected framework (e.g., "spring", "nestjs")
    pub framework: Option<String>,

    /// Semantic classification
    pub semantic: DecoratorSemantics,

    /// Extracted arguments
    pub arguments: DecoratorArguments,
}

/// Extracted arguments from a decorator.
pub struct DecoratorArguments {
    /// Route path (e.g., "/users", "/api/v1/items")
    pub path: Option<String>,

    /// HTTP methods (e.g., [GET, POST])
    pub methods: SmallVec<[HttpMethod; 2]>,

    /// Required auth roles (e.g., ["ADMIN", "USER"])
    pub roles: SmallVec<[String; 2]>,

    /// Framework-specific extra arguments
    pub extra: Option<FxHashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpMethod {
    Get, Post, Put, Delete, Patch, Options, Head, All,
}
```

### 4.4 Function & File Semantics

```rust
/// Semantic classification of a function based on its decorators.
pub struct FunctionSemantics {
    pub is_entry_point: bool,
    pub is_data_accessor: bool,
    pub is_auth_handler: bool,
    pub is_test_case: bool,
    pub is_injectable: bool,
    pub requires_auth: bool,

    /// Entry point details (if is_entry_point)
    pub entry_point: Option<EntryPointInfo>,

    /// Injected dependencies (language-specific)
    pub dependencies: Vec<String>,

    /// Data access points within this function
    pub data_access: Vec<OrmPattern>,

    /// Auth requirements
    pub auth: Option<AuthInfo>,
}

pub struct EntryPointInfo {
    pub kind: EntryPointKind,
    pub path: Option<String>,
    pub methods: SmallVec<[HttpMethod; 2]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryPointKind {
    Http,
    Event,
    Cli,
    Cron,
    WebSocket,
    GraphQL,
}

pub struct AuthInfo {
    pub required: bool,
    pub roles: SmallVec<[String; 2]>,
    pub strategy: Option<String>,
}

/// Semantic classification of a file based on its functions.
pub struct FileSemantics {
    pub is_controller: bool,
    pub is_service: bool,
    pub is_model: bool,
    pub is_test_file: bool,
    pub is_middleware: bool,
    pub is_config: bool,
    pub primary_framework: Option<String>,
    pub detected_frameworks: Vec<String>,
}
```

### 4.5 ULP Result — Complete Output

```rust
/// Complete result from the Unified Language Provider for a single file.
pub struct UlpResult {
    /// File identification
    pub file: Spur,
    pub language: Language,

    /// Call chains extracted by the normalizer
    pub call_chains: Vec<UnifiedCallChain>,

    /// ORM patterns detected by matchers
    pub orm_patterns: Vec<OrmPattern>,

    /// Normalized decorators
    pub decorators: Vec<NormalizedDecorator>,

    /// Per-function semantic classification
    pub function_semantics: Vec<(Spur, FunctionSemantics)>,

    /// File-level semantic classification
    pub file_semantics: FileSemantics,

    /// Detected frameworks
    pub detected_frameworks: Vec<DetectedFramework>,

    /// Timing metrics
    pub extraction_time_us: u64,
    pub matching_time_us: u64,
    pub semantic_time_us: u64,
}

pub struct DetectedFramework {
    pub name: String,
    pub confidence: f32,
    pub detection_source: FrameworkDetectionSource,
}

#[derive(Debug, Clone, Copy)]
pub enum FrameworkDetectionSource {
    Import,
    Decorator,
    CallPattern,
    FileStructure,
}
```

### 4.6 Query Types — Cross-Language Semantic Queries

```rust
/// Options for cross-language semantic queries.
pub struct QueryOptions {
    pub category: Option<SemanticCategory>,
    pub is_entry_point: Option<bool>,
    pub is_data_accessor: Option<bool>,
    pub is_auth_handler: Option<bool>,
    pub is_injectable: Option<bool>,
    pub framework: Option<String>,
    pub language: Option<Language>,
}

/// Result of a semantic query.
pub struct QueryResult {
    pub function_name: Spur,
    pub file: Spur,
    pub line: u32,
    pub framework: Option<String>,
    pub matched_decorators: Vec<NormalizedDecorator>,
    pub semantics: FunctionSemantics,
}
```


---

## 5. Normalizer System — 9 Language Normalizers

### 5.1 LanguageNormalizer Trait

```rust
/// Every language normalizer implements this trait.
/// Responsible for extracting call chains and framework patterns from
/// language-specific tree-sitter ASTs.
pub trait LanguageNormalizer: Send + Sync {
    /// Which language this normalizer handles.
    fn language(&self) -> Language;

    /// File extensions this normalizer can process.
    fn extensions(&self) -> &[&str];

    /// Check if this normalizer can handle a given file path.
    fn can_handle(&self, file_path: &str) -> bool {
        let ext = file_path.rsplit('.').next().unwrap_or("");
        self.extensions().iter().any(|e| *e == ext)
    }

    /// Extract method call chains from the AST.
    /// This is the primary extraction — produces UnifiedCallChain objects
    /// that matchers will analyze for ORM/framework patterns.
    fn extract_call_chains(
        &self,
        tree: &Tree,
        source: &[u8],
        interner: &ThreadedRodeo,
    ) -> Vec<UnifiedCallChain>;

    /// Extract framework-specific patterns (routes, decorators, DI, etc.).
    fn extract_framework_patterns(
        &self,
        tree: &Tree,
        source: &[u8],
        interner: &ThreadedRodeo,
    ) -> Vec<FrameworkExtraction>;

    /// Normalize raw decorator/annotation strings into semantic form.
    fn normalize_decorators(
        &self,
        tree: &Tree,
        source: &[u8],
        frameworks: &[FrameworkPattern],
        interner: &ThreadedRodeo,
    ) -> Vec<NormalizedDecorator>;

    /// Extract language-specific dependency injection patterns.
    /// Default: empty (override for languages with DI frameworks).
    fn extract_dependencies(
        &self,
        _tree: &Tree,
        _source: &[u8],
        _decorators: &[NormalizedDecorator],
    ) -> Vec<String> {
        Vec::new()
    }
}
```

### 5.2 Call Chain Extraction Algorithm (Shared Logic)

All normalizers share a common algorithm for extracting method call chains from
tree-sitter ASTs. The language-specific part is mapping node types.

```rust
/// Shared call chain extraction logic.
/// Each normalizer provides language-specific node type mappings.
pub struct CallChainExtractor {
    /// tree-sitter node type for method call expressions
    method_call_type: &'static str,
    /// tree-sitter node type for the receiver in a method call
    receiver_field: &'static str,
    /// tree-sitter node type for the method name
    method_field: &'static str,
    /// tree-sitter node type for arguments
    arguments_type: &'static str,
    /// tree-sitter node type for await expressions
    await_type: Option<&'static str>,
    /// tree-sitter node type for optional chaining
    optional_chain_type: Option<&'static str>,
}

impl CallChainExtractor {
    /// Walk the AST and extract all method call chains.
    pub fn extract(
        &self,
        tree: &Tree,
        source: &[u8],
        language: Language,
        file: Spur,
        interner: &ThreadedRodeo,
    ) -> Vec<UnifiedCallChain> {
        let mut chains = Vec::new();
        let mut cursor = tree.walk();
        self.walk_recursive(&mut cursor, source, language, file, interner, &mut chains);
        chains
    }

    fn walk_recursive(
        &self,
        cursor: &mut TreeCursor,
        source: &[u8],
        language: Language,
        file: Spur,
        interner: &ThreadedRodeo,
        chains: &mut Vec<UnifiedCallChain>,
    ) {
        let node = cursor.node();

        // Check if this is the outermost call in a chain
        if node.kind() == self.method_call_type && !self.is_inner_call(&node) {
            if let Some(chain) = self.extract_chain(&node, source, language, file, interner) {
                if chain.segments.len() >= 1 {
                    chains.push(chain);
                }
            }
        }

        // Recurse into children
        if cursor.goto_first_child() {
            loop {
                self.walk_recursive(cursor, source, language, file, interner, chains);
                if !cursor.goto_next_sibling() { break; }
            }
            cursor.goto_parent();
        }
    }

    /// Check if this call expression is nested inside another call chain
    /// (i.e., it's not the outermost call — we only want to extract from the top).
    fn is_inner_call(&self, node: &Node) -> bool {
        let mut parent = node.parent();
        while let Some(p) = parent {
            if p.kind() == self.method_call_type {
                // Check if this node is the receiver of the parent call
                if let Some(recv) = p.child_by_field_name(self.receiver_field) {
                    if recv.id() == node.id() || self.contains_node(&recv, node) {
                        return true;
                    }
                }
            }
            parent = p.parent();
        }
        false
    }

    /// Recursively extract a chain by walking the receiver chain.
    fn extract_chain(
        &self,
        node: &Node,
        source: &[u8],
        language: Language,
        file: Spur,
        interner: &ThreadedRodeo,
    ) -> Option<UnifiedCallChain> {
        let mut segments = SmallVec::new();
        let mut current = *node;
        let mut receiver = None;

        loop {
            if current.kind() == self.method_call_type {
                // Extract method name
                let method_node = current.child_by_field_name(self.method_field)?;
                let method_text = method_node.utf8_text(source).ok()?;
                let method = interner.get_or_intern(method_text);

                // Extract arguments
                let args = self.extract_arguments(&current, source, interner);

                // Check for await
                let is_await = self.await_type.map_or(false, |at| {
                    current.parent().map_or(false, |p| p.kind() == at)
                });

                // Check for optional chaining
                let is_optional = self.optional_chain_type.map_or(false, |oc| {
                    current.kind() == oc || current.child(0).map_or(false, |c| c.kind() == oc)
                });

                segments.push(CallSegment {
                    method,
                    args,
                    is_await,
                    is_optional,
                    type_args: SmallVec::new(),
                });

                // Walk to receiver
                if let Some(recv) = current.child_by_field_name(self.receiver_field) {
                    current = recv;
                } else {
                    break;
                }
            } else {
                // This is the base receiver (identifier or expression)
                let recv_text = current.utf8_text(source).ok()?;
                receiver = Some(interner.get_or_intern(recv_text));
                break;
            }
        }

        // Segments were collected in reverse order (outermost first)
        segments.reverse();

        Some(UnifiedCallChain {
            receiver,
            segments,
            file,
            line: node.start_position().row as u32 + 1,
            column: node.start_position().column as u32 + 1,
            end_line: node.end_position().row as u32 + 1,
            end_column: node.end_position().column as u32 + 1,
            language,
            is_awaited: false,
            raw_text: node.utf8_text(source).ok().map(|s| s.to_string()),
            enclosing_function: None, // Set by pipeline after extraction
        })
    }

    fn extract_arguments(
        &self,
        call_node: &Node,
        source: &[u8],
        interner: &ThreadedRodeo,
    ) -> SmallVec<[CallArg; 4]> {
        let mut args = SmallVec::new();
        if let Some(args_node) = call_node.child_by_field_name("arguments") {
            let mut position = 0u8;
            let mut cursor = args_node.walk();
            if cursor.goto_first_child() {
                loop {
                    let child = cursor.node();
                    if !child.is_named() || child.kind() == "(" || child.kind() == ")" ||
                       child.kind() == "," {
                        if !cursor.goto_next_sibling() { break; }
                        continue;
                    }
                    let value = self.parse_arg_value(&child, source, interner);
                    args.push(CallArg {
                        value,
                        name: None, // Language-specific normalizers override for kwargs
                        position,
                    });
                    position = position.saturating_add(1);
                    if !cursor.goto_next_sibling() { break; }
                }
            }
        }
        args
    }

    fn parse_arg_value(
        &self,
        node: &Node,
        source: &[u8],
        interner: &ThreadedRodeo,
    ) -> ArgValue {
        let text = node.utf8_text(source).unwrap_or("");
        match node.kind() {
            "string" | "string_literal" | "template_string" |
            "interpreted_string_literal" | "raw_string_literal" |
            "encapsed_string" | "concatenated_string" => {
                // Strip quotes
                let stripped = text.trim_matches(|c| c == '\'' || c == '"' || c == '`');
                ArgValue::StringLiteral(stripped.to_string())
            }
            "number" | "integer" | "float" | "integer_literal" |
            "float_literal" | "decimal_integer_literal" => {
                text.parse::<f64>().map(ArgValue::NumberLiteral)
                    .unwrap_or(ArgValue::Expression(text.to_string()))
            }
            "true" | "false" => {
                ArgValue::BooleanLiteral(text == "true")
            }
            "null" | "nil" | "None" | "nullptr" => {
                ArgValue::Null
            }
            "identifier" | "property_identifier" | "field_identifier" => {
                ArgValue::Identifier(interner.get_or_intern(text))
            }
            "array" | "array_expression" | "list" => {
                let elements = self.extract_array_elements(node, source, interner);
                ArgValue::Array(elements)
            }
            "object" | "object_expression" | "dictionary" | "hash" => {
                let props = self.extract_object_properties(node, source, interner);
                ArgValue::Object(props)
            }
            "spread_element" | "rest_pattern" => {
                if let Some(child) = node.named_child(0) {
                    ArgValue::Spread(Box::new(self.parse_arg_value(&child, source, interner)))
                } else {
                    ArgValue::Expression(text.to_string())
                }
            }
            _ => ArgValue::Expression(text.to_string()),
        }
    }

    fn extract_array_elements(
        &self, node: &Node, source: &[u8], interner: &ThreadedRodeo,
    ) -> Vec<ArgValue> {
        let mut elements = Vec::new();
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if child.is_named() {
                    elements.push(self.parse_arg_value(&child, source, interner));
                }
                if !cursor.goto_next_sibling() { break; }
            }
        }
        elements
    }

    fn extract_object_properties(
        &self, node: &Node, source: &[u8], interner: &ThreadedRodeo,
    ) -> Vec<(String, ArgValue)> {
        let mut props = Vec::new();
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if child.kind() == "pair" || child.kind() == "property" ||
                   child.kind() == "key_value_pair" {
                    if let (Some(key), Some(val)) = (child.child(0), child.child(2)) {
                        let key_text = key.utf8_text(source).unwrap_or("").to_string();
                        let val_parsed = self.parse_arg_value(&val, source, interner);
                        props.push((key_text, val_parsed));
                    }
                }
                if !cursor.goto_next_sibling() { break; }
            }
        }
        props
    }

    fn contains_node(&self, haystack: &Node, needle: &Node) -> bool {
        if haystack.id() == needle.id() { return true; }
        let mut cursor = haystack.walk();
        if cursor.goto_first_child() {
            loop {
                if self.contains_node(&cursor.node(), needle) { return true; }
                if !cursor.goto_next_sibling() { break; }
            }
        }
        false
    }
}
```

### 5.3 Per-Language Normalizer Specifications

#### TypeScript/JavaScript Normalizer

```rust
pub struct TypeScriptNormalizer;

impl LanguageNormalizer for TypeScriptNormalizer {
    fn language(&self) -> Language { Language::TypeScript }
    fn extensions(&self) -> &[&str] { &["ts", "tsx", "js", "jsx", "mts", "cts", "mjs", "cjs"] }

    fn extract_call_chains(&self, tree: &Tree, source: &[u8], interner: &ThreadedRodeo)
        -> Vec<UnifiedCallChain>
    {
        let extractor = CallChainExtractor {
            method_call_type: "call_expression",
            receiver_field: "function",
            method_field: "property",  // member_expression.property
            arguments_type: "arguments",
            await_type: Some("await_expression"),
            optional_chain_type: Some("optional_chain_expression"),
        };
        let mut chains = extractor.extract(tree, source, Language::TypeScript, /* file */, interner);

        // TS-specific: handle tagged template literals (e.g., sql`SELECT ...`)
        self.extract_tagged_templates(tree, source, interner, &mut chains);

        // TS-specific: handle decorator factory calls (@Controller('/users'))
        self.extract_decorator_chains(tree, source, interner, &mut chains);

        chains
    }

    // ... framework_patterns and normalize_decorators implementations
}
```

TS/JS-specific extraction capabilities:
- Method chains with optional chaining (`?.`)
- Await expressions (`await db.query()`)
- Tagged template literals (`sql\`SELECT * FROM users\``, `gql\`query { ... }\``)
- Decorator factory calls (`@Controller('/users')`)
- Computed property access (`obj[method]()`)
- Destructured imports (`const { findMany } = prisma.user`)
- Proxy patterns (`new Proxy(target, handler)`)

#### Python Normalizer

```rust
pub struct PythonNormalizer;

impl LanguageNormalizer for PythonNormalizer {
    fn language(&self) -> Language { Language::Python }
    fn extensions(&self) -> &[&str] { &["py", "pyi"] }

    fn extract_call_chains(&self, tree: &Tree, source: &[u8], interner: &ThreadedRodeo)
        -> Vec<UnifiedCallChain>
    {
        let extractor = CallChainExtractor {
            method_call_type: "call",
            receiver_field: "function",
            method_field: "attribute",
            arguments_type: "argument_list",
            await_type: Some("await"),
            optional_chain_type: None,  // Python has no optional chaining
        };
        let mut chains = extractor.extract(tree, source, Language::Python, /* file */, interner);

        // Python-specific: handle keyword arguments
        self.annotate_keyword_args(tree, source, interner, &mut chains);

        // Python-specific: handle context managers (with session.begin():)
        self.extract_context_manager_chains(tree, source, interner, &mut chains);

        chains
    }
}
```

Python-specific extraction capabilities:
- Keyword arguments (`Model.objects.filter(active=True, name="test")`)
- Context managers (`with session.begin() as tx:`)
- Decorator chains (`@app.route('/users', methods=['GET', 'POST'])`)
- F-string interpolation in SQL (`f"SELECT * FROM {table}"`)
- Class-level method calls (`Model.objects.all()`)
- Django manager chains (`User.objects.filter().exclude().order_by()`)

#### Java Normalizer

```rust
pub struct JavaNormalizer;

impl LanguageNormalizer for JavaNormalizer {
    fn language(&self) -> Language { Language::Java }
    fn extensions(&self) -> &[&str] { &["java"] }
}
```

Java-specific extraction capabilities:
- Builder patterns (`QueryBuilder.select("*").from("users").where("id = ?").build()`)
- Annotation arguments (`@RequestMapping(value="/users", method=RequestMethod.GET)`)
- Generic type arguments (`repository.findById(Long id)`)
- Stream API chains (`list.stream().filter().map().collect()`)
- Spring Data derived query methods (`findByNameAndAge()`)
- JPA Criteria API chains

#### C# Normalizer

```rust
pub struct CSharpNormalizer;

impl LanguageNormalizer for CSharpNormalizer {
    fn language(&self) -> Language { Language::CSharp }
    fn extensions(&self) -> &[&str] { &["cs"] }
}
```

C#-specific extraction capabilities:
- LINQ query syntax (`from u in context.Users where u.Active select u`)
- LINQ method syntax (`context.Users.Where(u => u.Active).ToListAsync()`)
- Attribute arguments (`[HttpGet("users/{id}")]`)
- Extension methods (`.Include()`, `.ThenInclude()`)
- Async/await with `Async` suffix convention
- Lambda expressions in LINQ predicates

#### PHP Normalizer

```rust
pub struct PhpNormalizer;

impl LanguageNormalizer for PhpNormalizer {
    fn language(&self) -> Language { Language::Php }
    fn extensions(&self) -> &[&str] { &["php"] }
}
```

PHP-specific extraction capabilities:
- Static method calls (`Model::where('active', true)->get()`)
- Facade patterns (`DB::table('users')->select('*')->get()`)
- Arrow functions (`->map(fn($user) => $user->name)`)
- PHP 8 attributes (`#[Route('/users', methods: ['GET'])]`)
- Eloquent scope chains (`User::active()->verified()->get()`)
- Laravel query builder chains

#### Go Normalizer

```rust
pub struct GoNormalizer;

impl LanguageNormalizer for GoNormalizer {
    fn language(&self) -> Language { Language::Go }
    fn extensions(&self) -> &[&str] { &["go"] }
}
```

Go-specific extraction capabilities:
- Method chains (`db.Where("age > ?", 18).Order("name").Find(&users)`)
- Error return patterns (`rows, err := db.Query("SELECT ...")`)
- Struct literal arguments (`db.Create(&User{Name: "test"})`)
- Context propagation (`db.WithContext(ctx).Find(&users)`)
- Interface method calls (resolved via type assertion)
- Standard library `database/sql` patterns

#### Rust Normalizer

```rust
pub struct RustLangNormalizer;

impl LanguageNormalizer for RustLangNormalizer {
    fn language(&self) -> Language { Language::Rust }
    fn extensions(&self) -> &[&str] { &["rs"] }
}
```

Rust-specific extraction capabilities:
- Method chains with `?` operator (`table.filter(id.eq(1)).first::<User>(&conn)?`)
- Turbofish syntax (`sqlx::query_as::<_, User>("SELECT ...")`)
- Macro invocations (`sqlx::query!("SELECT * FROM users")`)
- Trait method calls (resolved via impl blocks)
- Async `.await` chains
- Diesel DSL chains (`users.filter(name.eq("test")).select(id)`)

#### C++ Normalizer

```rust
pub struct CppNormalizer;

impl LanguageNormalizer for CppNormalizer {
    fn language(&self) -> Language { Language::Cpp }
    fn extensions(&self) -> &[&str] { &["cpp", "cc", "cxx", "c++", "hpp", "hxx", "hh"] }
}
```

C++ specific extraction capabilities:
- Method chains with `->` and `.` operators
- Template method calls (`db.query<User>("SELECT ...")`)
- Operator overloads (`stream << "SELECT * FROM users"`)
- RAII patterns (constructor/destructor chains)
- Smart pointer method chains (`ptr->method()`)

### 5.4 NormalizerRegistry

```rust
/// Registry of all language normalizers. Indexed by language and extension.
pub struct NormalizerRegistry {
    /// Language → normalizer mapping
    by_language: FxHashMap<Language, Box<dyn LanguageNormalizer>>,

    /// Extension → language mapping (for file dispatch)
    extension_map: FxHashMap<String, Language>,
}

impl NormalizerRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            by_language: FxHashMap::default(),
            extension_map: FxHashMap::default(),
        };

        // Register all 8 concrete normalizers
        registry.register(Box::new(TypeScriptNormalizer));
        registry.register(Box::new(PythonNormalizer));
        registry.register(Box::new(JavaNormalizer));
        registry.register(Box::new(CSharpNormalizer));
        registry.register(Box::new(PhpNormalizer));
        registry.register(Box::new(GoNormalizer));
        registry.register(Box::new(RustLangNormalizer));
        registry.register(Box::new(CppNormalizer));

        registry
    }

    fn register(&mut self, normalizer: Box<dyn LanguageNormalizer>) {
        let lang = normalizer.language();
        for ext in normalizer.extensions() {
            self.extension_map.insert(ext.to_string(), lang);
        }
        self.by_language.insert(lang, normalizer);
    }

    /// Get normalizer for a language.
    pub fn get(&self, language: Language) -> Option<&dyn LanguageNormalizer> {
        self.by_language.get(&language).map(|b| b.as_ref())
    }

    /// Get normalizer for a file path (by extension).
    pub fn get_for_file(&self, file_path: &str) -> Option<&dyn LanguageNormalizer> {
        let ext = file_path.rsplit('.').next()?;
        let lang = self.extension_map.get(ext)?;
        self.get(*lang)
    }

    /// Get all registered normalizers.
    pub fn all(&self) -> impl Iterator<Item = &dyn LanguageNormalizer> {
        self.by_language.values().map(|b| b.as_ref())
    }
}
```


---

## 6. Matcher System — 20 ORM/Framework Matchers

### 6.1 OrmMatcher Trait

```rust
/// Every ORM/framework matcher implements this trait.
/// Matchers analyze UnifiedCallChain objects to detect data access patterns.
pub trait OrmMatcher: Send + Sync {
    /// Unique identifier for this matcher (e.g., "prisma", "django", "raw-sql").
    fn id(&self) -> &str;

    /// Which ORM type this matcher detects.
    fn orm_type(&self) -> OrmType;

    /// Which languages this matcher applies to.
    fn languages(&self) -> &[Language];

    /// Check if a call chain matches this ORM's patterns.
    /// Returns Some(OrmPattern) if matched, None otherwise.
    fn matches(&self, chain: &UnifiedCallChain) -> Option<OrmPattern>;

    /// Extract table/collection name from a matched chain.
    /// Called after matches() returns Some.
    fn extract_table(&self, chain: &UnifiedCallChain) -> Option<String>;

    /// Extract the data operation type (SELECT, INSERT, UPDATE, DELETE, etc.).
    fn extract_operation(&self, chain: &UnifiedCallChain) -> Option<DataOperation>;

    /// Extract field names referenced in the query.
    fn extract_fields(&self, chain: &UnifiedCallChain) -> Vec<String>;

    /// Extract WHERE/filter conditions (simplified string representation).
    fn extract_conditions(&self, chain: &UnifiedCallChain) -> Vec<String> {
        Vec::new()
    }

    /// Confidence level for this matcher (0.0-1.0).
    /// Higher = more specific pattern, fewer false positives.
    fn base_confidence(&self) -> f32;

    /// Whether this matcher can detect joins.
    fn supports_join_detection(&self) -> bool { false }

    /// Whether this matcher can detect transactions.
    fn supports_transaction_detection(&self) -> bool { false }
}
```

### 6.2 Per-Matcher Specifications

#### Matcher 1: Supabase (TS/JS)

```rust
pub struct SupabaseMatcher;

impl OrmMatcher for SupabaseMatcher {
    fn id(&self) -> &str { "supabase" }
    fn orm_type(&self) -> OrmType { OrmType::Supabase }
    fn languages(&self) -> &[Language] { &[Language::TypeScript, Language::JavaScript] }
    fn base_confidence(&self) -> f32 { 0.95 }

    fn matches(&self, chain: &UnifiedCallChain) -> Option<OrmPattern> {
        // Pattern: supabase.from('table').select/insert/update/delete/upsert(...)
        // Also: supabase.rpc('function_name', params)
        // Also: supabase.storage.from('bucket').upload/download(...)
        let receiver = chain.receiver_text()?;
        if !receiver.contains("supabase") { return None; }

        // Check for .from() segment
        let from_idx = chain.segments.iter().position(|s| {
            s.method_text() == "from"
        })?;

        let table = chain.segments[from_idx].args.first()
            .and_then(|a| a.as_string());

        let operation = self.detect_operation(chain, from_idx);
        let fields = self.extract_supabase_fields(chain, from_idx);

        Some(OrmPattern {
            orm: OrmType::Supabase,
            table,
            operation,
            fields,
            confidence: self.base_confidence(),
            // ... other fields from chain
            ..OrmPattern::from_chain(chain)
        })
    }
}
```

Supabase patterns detected:
- `supabase.from('table').select('*')` → Select
- `supabase.from('table').insert({...})` → Insert
- `supabase.from('table').update({...}).eq('id', x)` → Update
- `supabase.from('table').delete().eq('id', x)` → Delete
- `supabase.from('table').upsert({...})` → Upsert
- `supabase.from('table').select('*').eq().gt().order().limit()` → Select with filters
- `supabase.rpc('function_name', params)` → Raw (stored procedure)
- `supabase.from('table').select('*, posts(*)')` → Select with joins (foreign key)

#### Matcher 2: Prisma (TS/JS)

```rust
pub struct PrismaMatcher;
```

Prisma patterns detected:
- `prisma.user.findMany({ where: {...} })` → Select
- `prisma.user.findUnique({ where: { id } })` → Select
- `prisma.user.findFirst({ where: {...} })` → Select
- `prisma.user.create({ data: {...} })` → Insert
- `prisma.user.createMany({ data: [...] })` → Insert (batch)
- `prisma.user.update({ where: {...}, data: {...} })` → Update
- `prisma.user.updateMany({ where: {...}, data: {...} })` → Update (batch)
- `prisma.user.delete({ where: {...} })` → Delete
- `prisma.user.deleteMany({ where: {...} })` → Delete (batch)
- `prisma.user.upsert({ where: {...}, create: {...}, update: {...} })` → Upsert
- `prisma.user.count({ where: {...} })` → Count
- `prisma.user.aggregate({ _avg: {...} })` → Aggregate
- `prisma.user.groupBy({ by: [...] })` → Aggregate
- `prisma.$queryRaw\`SELECT ...\`` → Raw
- `prisma.$executeRaw\`INSERT ...\`` → Raw
- `prisma.$transaction([...])` → Transaction detection

Table extraction: second segment name (e.g., `prisma.user` → "user").
Field extraction: from `select` and `include` objects in arguments.

#### Matcher 3: TypeORM (TS/JS)

```rust
pub struct TypeOrmMatcher;
```

TypeORM patterns detected:
- `repository.find({ where: {...} })` → Select
- `repository.findOne({ where: {...} })` → Select
- `repository.findOneBy({ id })` → Select
- `repository.save(entity)` → Upsert
- `repository.insert(entity)` → Insert
- `repository.update(criteria, data)` → Update
- `repository.delete(criteria)` → Delete
- `repository.remove(entity)` → Delete
- `repository.count({ where: {...} })` → Count
- `connection.createQueryBuilder().select().from().where().getMany()` → Select (query builder)
- `getRepository(Entity).find()` → Select
- `@Entity()` decorator → Table detection
- `@Column()`, `@PrimaryColumn()` → Field detection

#### Matcher 4: Sequelize (TS/JS)

```rust
pub struct SequelizeMatcher;
```

Sequelize patterns detected:
- `Model.findAll({ where: {...} })` → Select
- `Model.findOne({ where: {...} })` → Select
- `Model.findByPk(id)` → Select
- `Model.findAndCountAll({ where: {...} })` → Select + Count
- `Model.create({...})` → Insert
- `Model.bulkCreate([...])` → Insert (batch)
- `Model.update({...}, { where: {...} })` → Update
- `Model.destroy({ where: {...} })` → Delete
- `Model.count({ where: {...} })` → Count
- `Model.sum('field')` / `Model.max('field')` → Aggregate
- `sequelize.query('SELECT ...')` → Raw
- `sequelize.transaction(async (t) => {...})` → Transaction detection

#### Matcher 5: Drizzle (TS/JS)

```rust
pub struct DrizzleMatcher;
```

Drizzle patterns detected:
- `db.select().from(users)` → Select
- `db.select({ id: users.id }).from(users)` → Select with fields
- `db.insert(users).values({...})` → Insert
- `db.update(users).set({...}).where(eq(users.id, 1))` → Update
- `db.delete(users).where(eq(users.id, 1))` → Delete
- `db.select().from(users).leftJoin(posts, eq(...))` → Select with join
- `db.select({ count: count() }).from(users)` → Count/Aggregate

#### Matcher 6: Knex (TS/JS)

```rust
pub struct KnexMatcher;
```

Knex patterns detected:
- `knex('users').select('*')` → Select
- `knex('users').where('id', 1).first()` → Select
- `knex('users').insert({...})` → Insert
- `knex('users').where('id', 1).update({...})` → Update
- `knex('users').where('id', 1).del()` → Delete
- `knex('users').count('* as count')` → Count
- `knex.raw('SELECT ...')` → Raw
- `knex('users').join('posts', 'users.id', 'posts.user_id')` → Select with join
- `knex.transaction(async (trx) => {...})` → Transaction detection

#### Matcher 7: Mongoose (TS/JS)

```rust
pub struct MongooseMatcher;
```

Mongoose patterns detected:
- `Model.find({ active: true })` → Select
- `Model.findOne({ _id: id })` → Select
- `Model.findById(id)` → Select
- `Model.create({...})` → Insert
- `Model.insertMany([...])` → Insert (batch)
- `Model.updateOne({ _id: id }, { $set: {...} })` → Update
- `Model.updateMany(filter, update)` → Update (batch)
- `Model.deleteOne({ _id: id })` → Delete
- `Model.deleteMany(filter)` → Delete (batch)
- `Model.countDocuments(filter)` → Count
- `Model.aggregate([{ $match: {...} }, { $group: {...} }])` → Aggregate
- `Model.populate('field')` → Join equivalent

Table extraction: Model name (from class/variable name).

#### Matcher 8: Django ORM (Python)

```rust
pub struct DjangoMatcher;
```

Django patterns detected:
- `Model.objects.all()` → Select
- `Model.objects.filter(active=True)` → Select with filter
- `Model.objects.get(pk=1)` → Select (single)
- `Model.objects.exclude(deleted=True)` → Select with exclusion
- `Model.objects.create(name="test")` → Insert
- `Model.objects.bulk_create([...])` → Insert (batch)
- `Model.objects.filter(pk=1).update(name="new")` → Update
- `Model.objects.filter(pk=1).delete()` → Delete
- `Model.objects.count()` → Count
- `Model.objects.aggregate(Avg('price'))` → Aggregate
- `Model.objects.values('name', 'email')` → Select with fields
- `Model.objects.select_related('profile')` → Select with join
- `Model.objects.prefetch_related('posts')` → Select with prefetch
- `Model.objects.order_by('name')` → Ordering detection
- `Model.objects.all()[:10]` → Pagination detection
- `Model.objects.raw('SELECT ...')` → Raw

Table extraction: Model class name (receiver before `.objects`).

#### Matcher 9: SQLAlchemy (Python)

```rust
pub struct SqlAlchemyMatcher;
```

SQLAlchemy patterns detected:
- `session.query(User).filter(User.active == True).all()` → Select
- `session.query(User).filter_by(active=True).first()` → Select
- `session.query(User).get(1)` → Select (single)
- `session.add(user)` → Insert
- `session.add_all([...])` → Insert (batch)
- `session.query(User).filter(User.id == 1).update({...})` → Update
- `session.query(User).filter(User.id == 1).delete()` → Delete
- `session.query(func.count(User.id))` → Count
- `session.query(func.avg(User.age))` → Aggregate
- `session.query(User).join(Post)` → Select with join
- `session.execute(text('SELECT ...'))` → Raw
- `select(User).where(User.active == True)` → Select (2.0 style)
- `insert(User).values(name="test")` → Insert (2.0 style)

#### Matcher 10: Entity Framework Core (C#)

```rust
pub struct EfCoreMatcher;
```

EF Core patterns detected:
- `context.Users.Where(u => u.Active).ToListAsync()` → Select
- `context.Users.FirstOrDefaultAsync(u => u.Id == id)` → Select (single)
- `context.Users.FindAsync(id)` → Select (single)
- `context.Users.Add(user)` → Insert
- `context.Users.AddRange(users)` → Insert (batch)
- `context.Users.Update(user)` → Update
- `context.Users.Remove(user)` → Delete
- `context.Users.CountAsync()` → Count
- `context.Users.AverageAsync(u => u.Age)` → Aggregate
- `context.Users.Include(u => u.Posts).ThenInclude(p => p.Comments)` → Select with joins
- `context.Users.AsNoTracking().ToListAsync()` → Select (read-only)
- `context.Database.ExecuteSqlRawAsync("SELECT ...")` → Raw
- `context.Users.FromSqlRaw("SELECT ...")` → Raw
- LINQ query syntax: `from u in context.Users where u.Active select u` → Select

#### Matcher 11: Eloquent (PHP)

```rust
pub struct EloquentMatcher;
```

Eloquent patterns detected:
- `User::all()` → Select
- `User::where('active', true)->get()` → Select with filter
- `User::find(1)` → Select (single)
- `User::findOrFail(1)` → Select (single, throws)
- `User::create([...])` → Insert
- `User::insert([...])` → Insert (batch)
- `User::where('id', 1)->update([...])` → Update
- `User::where('id', 1)->delete()` → Delete
- `User::destroy(1)` → Delete
- `User::count()` → Count
- `User::avg('age')` → Aggregate
- `User::with('posts')->get()` → Select with eager loading
- `User::has('posts')->get()` → Select with relationship filter
- `DB::table('users')->select('*')->get()` → Select (query builder)
- `DB::raw('SELECT ...')` → Raw
- `DB::transaction(function () {...})` → Transaction detection

#### Matcher 12: Spring Data JPA (Java)

```rust
pub struct SpringDataMatcher;
```

Spring Data patterns detected:
- `repository.findAll()` → Select
- `repository.findById(id)` → Select (single)
- `repository.findByNameAndAge(name, age)` → Select (derived query)
- `repository.findByNameContaining(name)` → Select (derived query)
- `repository.save(entity)` → Upsert
- `repository.saveAll(entities)` → Upsert (batch)
- `repository.delete(entity)` → Delete
- `repository.deleteById(id)` → Delete
- `repository.deleteAll()` → Delete (batch)
- `repository.count()` → Count
- `@Query("SELECT u FROM User u WHERE u.active = true")` → Raw (JPQL)
- `@Query(value = "SELECT * FROM users", nativeQuery = true)` → Raw (native)
- `entityManager.createQuery("SELECT ...")` → Raw
- `entityManager.find(User.class, id)` → Select (single)
- `Specification` chains → Select with dynamic filters

Table extraction: from `@Entity` / `@Table` annotations, or repository generic type.

#### Matcher 13: GORM (Go)

```rust
pub struct GormMatcher;
```

GORM patterns detected:
- `db.Find(&users)` → Select
- `db.First(&user, 1)` → Select (single)
- `db.Where("active = ?", true).Find(&users)` → Select with filter
- `db.Create(&user)` → Insert
- `db.CreateInBatches(&users, 100)` → Insert (batch)
- `db.Save(&user)` → Upsert
- `db.Model(&user).Update("name", "new")` → Update
- `db.Model(&user).Updates(map[string]interface{}{...})` → Update
- `db.Delete(&user, 1)` → Delete
- `db.Model(&User{}).Count(&count)` → Count
- `db.Raw("SELECT ...").Scan(&result)` → Raw
- `db.Joins("JOIN posts ON ...").Find(&users)` → Select with join
- `db.Preload("Posts").Find(&users)` → Select with preload
- `db.Order("name").Limit(10).Offset(0).Find(&users)` → Select with ordering/pagination
- `db.Transaction(func(tx *gorm.DB) error {...})` → Transaction detection

#### Matcher 14: Diesel (Rust)

```rust
pub struct DieselMatcher;
```

Diesel patterns detected:
- `users.filter(name.eq("test")).load::<User>(&conn)` → Select
- `users.find(1).first::<User>(&conn)` → Select (single)
- `diesel::insert_into(users).values(&new_user).execute(&conn)` → Insert
- `diesel::update(users.find(1)).set(name.eq("new")).execute(&conn)` → Update
- `diesel::delete(users.find(1)).execute(&conn)` → Delete
- `users.count().get_result::<i64>(&conn)` → Count
- `diesel::sql_query("SELECT ...").load::<User>(&conn)` → Raw
- `users.inner_join(posts).load::<(User, Post)>(&conn)` → Select with join
- `conn.transaction(|conn| {...})` → Transaction detection

#### Matcher 15: SeaORM (Rust)

```rust
pub struct SeaOrmMatcher;
```

SeaORM patterns detected:
- `Entity::find().all(&db).await` → Select
- `Entity::find_by_id(1).one(&db).await` → Select (single)
- `Entity::find().filter(Column::Active.eq(true)).all(&db).await` → Select with filter
- `ActiveModel { ... }.insert(&db).await` → Insert
- `Entity::insert_many([...]).exec(&db).await` → Insert (batch)
- `ActiveModel { ... }.update(&db).await` → Update
- `Entity::delete_by_id(1).exec(&db).await` → Delete
- `Entity::find().count(&db).await` → Count
- `Statement::from_sql_and_values(...)` → Raw
- `Entity::find().find_also_related(RelatedEntity).all(&db).await` → Select with join

#### Matcher 16: SQLx (Rust)

```rust
pub struct SqlxMatcher;
```

SQLx patterns detected:
- `sqlx::query("SELECT * FROM users").fetch_all(&pool).await` → Select
- `sqlx::query_as::<_, User>("SELECT ...").fetch_one(&pool).await` → Select
- `sqlx::query!("SELECT * FROM users WHERE id = $1", id).fetch_one(&pool).await` → Select
- `sqlx::query!("INSERT INTO users ...").execute(&pool).await` → Insert
- `sqlx::query!("UPDATE users SET ...").execute(&pool).await` → Update
- `sqlx::query!("DELETE FROM users ...").execute(&pool).await` → Delete
- `pool.begin().await` → Transaction detection

SQLx is unique: it uses compile-time checked SQL macros. The matcher extracts
the SQL string from the macro invocation and parses it for table/operation/fields.

#### Matcher 17: Raw SQL (All Languages)

```rust
pub struct RawSqlMatcher;
```

The universal fallback matcher. Detects raw SQL strings in any language.
Runs AFTER all ORM-specific matchers (lower priority).

Detection patterns:
- String literals matching SQL syntax: `SELECT`, `INSERT INTO`, `UPDATE`, `DELETE FROM`
- Template literals with SQL: `` sql`SELECT ...` ``
- String concatenation with SQL keywords
- Prepared statement patterns: `?`, `$1`, `:param`, `%s`

SQL parsing (lightweight, not full parser):
- Extract table names from `FROM`, `INTO`, `UPDATE`, `JOIN` clauses
- Extract operation from first keyword
- Extract field names from `SELECT` clause
- Detect `WHERE` conditions
- Detect `JOIN` presence
- Detect `ORDER BY`, `LIMIT`, `GROUP BY`

Confidence: 0.80 (lower than ORM-specific matchers due to potential false positives).

#### Matcher 18: database/sql (Go)

```rust
pub struct DatabaseSqlMatcher;
```

Go standard library `database/sql` patterns:
- `db.Query("SELECT ...")` → Select
- `db.QueryRow("SELECT ... WHERE id = $1", id)` → Select (single)
- `db.QueryContext(ctx, "SELECT ...")` → Select (with context)
- `db.Exec("INSERT INTO ...")` → Insert/Update/Delete (parsed from SQL)
- `db.ExecContext(ctx, "INSERT INTO ...")` → Insert/Update/Delete
- `db.Prepare("SELECT ...")` → Prepared statement
- `stmt.Query(args...)` → Select (prepared)
- `stmt.Exec(args...)` → Insert/Update/Delete (prepared)
- `db.Begin()` / `tx.Commit()` / `tx.Rollback()` → Transaction detection

### 6.3 MatcherRegistry

```rust
/// Registry of all ORM matchers. Indexed by language for fast dispatch.
pub struct MatcherRegistry {
    /// All registered matchers
    matchers: Vec<Box<dyn OrmMatcher>>,

    /// Language → matcher indices (for fast language-filtered dispatch)
    language_index: FxHashMap<Language, Vec<usize>>,

    /// ORM type → matcher index (for targeted lookup)
    orm_index: FxHashMap<OrmType, usize>,
}

impl MatcherRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            matchers: Vec::with_capacity(20),
            language_index: FxHashMap::default(),
            orm_index: FxHashMap::default(),
        };

        // Register all 18 concrete matchers in priority order.
        // ORM-specific matchers first, Raw SQL last (fallback).
        registry.register(Box::new(SupabaseMatcher));
        registry.register(Box::new(PrismaMatcher));
        registry.register(Box::new(TypeOrmMatcher));
        registry.register(Box::new(SequelizeMatcher));
        registry.register(Box::new(DrizzleMatcher));
        registry.register(Box::new(KnexMatcher));
        registry.register(Box::new(MongooseMatcher));
        registry.register(Box::new(DjangoMatcher));
        registry.register(Box::new(SqlAlchemyMatcher));
        registry.register(Box::new(EfCoreMatcher));
        registry.register(Box::new(EloquentMatcher));
        registry.register(Box::new(SpringDataMatcher));
        registry.register(Box::new(GormMatcher));
        registry.register(Box::new(DieselMatcher));
        registry.register(Box::new(SeaOrmMatcher));
        registry.register(Box::new(SqlxMatcher));
        registry.register(Box::new(DatabaseSqlMatcher));
        registry.register(Box::new(RawSqlMatcher)); // Always last — fallback

        registry
    }

    fn register(&mut self, matcher: Box<dyn OrmMatcher>) {
        let idx = self.matchers.len();
        self.orm_index.insert(matcher.orm_type(), idx);
        for lang in matcher.languages() {
            self.language_index.entry(*lang).or_default().push(idx);
        }
        self.matchers.push(matcher);
    }

    /// Run all applicable matchers against a call chain.
    /// Returns the FIRST match (highest priority). ORM-specific matchers
    /// take precedence over Raw SQL.
    pub fn match_chain(&self, chain: &UnifiedCallChain) -> Option<OrmPattern> {
        let indices = self.language_index.get(&chain.language)?;
        for &idx in indices {
            if let Some(pattern) = self.matchers[idx].matches(chain) {
                return Some(pattern);
            }
        }
        None
    }

    /// Run all applicable matchers and return ALL matches (for multi-ORM detection).
    pub fn match_chain_all(&self, chain: &UnifiedCallChain) -> Vec<OrmPattern> {
        let indices = match self.language_index.get(&chain.language) {
            Some(v) => v.as_slice(),
            None => return Vec::new(),
        };
        indices.iter()
            .filter_map(|&idx| self.matchers[idx].matches(chain))
            .collect()
    }

    /// Get a specific matcher by ORM type.
    pub fn get(&self, orm: OrmType) -> Option<&dyn OrmMatcher> {
        self.orm_index.get(&orm).map(|&idx| self.matchers[idx].as_ref())
    }
}
```


---

## 7. Framework Registry & Decorator Normalization

### 7.1 FrameworkRegistry

```rust
/// Singleton registry holding all known framework patterns.
/// Indexed by language for fast lookup during normalization.
pub struct FrameworkRegistry {
    /// All registered framework patterns
    frameworks: Vec<FrameworkPattern>,

    /// Language → framework indices
    by_language: FxHashMap<Language, Vec<usize>>,

    /// Framework name → index
    by_name: FxHashMap<String, usize>,
}

impl FrameworkRegistry {
    /// Create registry with all built-in framework patterns.
    pub fn new() -> Self {
        let mut registry = Self {
            frameworks: Vec::new(),
            by_language: FxHashMap::default(),
            by_name: FxHashMap::default(),
        };

        // Register all 5 built-in framework pattern sets
        registry.register(spring_patterns());
        registry.register(fastapi_patterns());
        registry.register(nestjs_patterns());
        registry.register(laravel_patterns());
        registry.register(aspnet_patterns());

        // NEW v2: Additional framework patterns
        registry.register(express_patterns());
        registry.register(flask_patterns());
        registry.register(django_patterns());
        registry.register(gin_patterns());
        registry.register(actix_patterns());
        registry.register(axum_patterns());

        registry
    }

    pub fn register(&mut self, pattern: FrameworkPattern) {
        let idx = self.frameworks.len();
        self.by_name.insert(pattern.framework.clone(), idx);
        for lang in &pattern.languages {
            self.by_language.entry(*lang).or_default().push(idx);
        }
        self.frameworks.push(pattern);
    }

    /// Detect which frameworks are used in a source file.
    /// Checks import patterns and decorator patterns against source text.
    pub fn detect_frameworks(
        &self,
        source: &[u8],
        language: Language,
    ) -> Vec<&FrameworkPattern> {
        let source_str = std::str::from_utf8(source).unwrap_or("");
        let indices = match self.by_language.get(&language) {
            Some(v) => v,
            None => return Vec::new(),
        };

        indices.iter()
            .filter_map(|&idx| {
                let pattern = &self.frameworks[idx];
                let detected = pattern.detection_patterns.imports.iter()
                    .any(|re| re.is_match(source_str))
                    || pattern.detection_patterns.decorators.iter()
                    .any(|re| re.is_match(source_str));
                if detected { Some(pattern) } else { None }
            })
            .collect()
    }

    /// Find the decorator mapping for a raw decorator string.
    /// Searches across the given frameworks for a matching pattern.
    pub fn find_decorator_mapping(
        &self,
        raw: &str,
        frameworks: &[&FrameworkPattern],
    ) -> Option<(&DecoratorMapping, &str)> {
        for framework in frameworks {
            for mapping in &framework.decorator_mappings {
                if mapping.pattern.is_match(raw) {
                    return Some((mapping, &framework.framework));
                }
            }
        }
        None
    }

    /// Get all frameworks for a language.
    pub fn get_for_language(&self, language: Language) -> Vec<&FrameworkPattern> {
        self.by_language.get(&language)
            .map(|indices| indices.iter().map(|&i| &self.frameworks[i]).collect())
            .unwrap_or_default()
    }

    /// Get a specific framework by name.
    pub fn get(&self, name: &str) -> Option<&FrameworkPattern> {
        self.by_name.get(name).map(|&i| &self.frameworks[i])
    }
}
```

### 7.2 FrameworkPattern Definition

```rust
/// Defines how to detect a framework and interpret its decorators/annotations.
pub struct FrameworkPattern {
    /// Framework identifier (e.g., "spring", "nestjs", "fastapi")
    pub framework: String,

    /// Languages this framework applies to
    pub languages: Vec<Language>,

    /// Patterns for detecting this framework in source code
    pub detection_patterns: DetectionPatterns,

    /// Mappings from raw decorators to semantic meaning
    pub decorator_mappings: Vec<DecoratorMapping>,
}

pub struct DetectionPatterns {
    /// Import patterns that indicate this framework
    pub imports: Vec<regex::Regex>,

    /// Decorator/annotation patterns that indicate this framework
    pub decorators: Vec<regex::Regex>,
}

/// Maps a raw decorator pattern to its semantic meaning.
pub struct DecoratorMapping {
    /// Regex pattern matching the raw decorator string
    pub pattern: regex::Regex,

    /// Semantic meaning of this decorator
    pub semantic: DecoratorSemantics,

    /// Override confidence (default: 1.0)
    pub confidence: f32,

    /// Argument extraction function (implemented per mapping)
    pub arg_extractor: ArgExtractorFn,
}

/// Function type for extracting arguments from a raw decorator string.
pub type ArgExtractorFn = fn(&str) -> DecoratorArguments;
```

### 7.3 Built-In Framework Patterns (All 5 Preserved + 6 New)

#### Spring Boot (Java) — Preserved from v1

```rust
pub fn spring_patterns() -> FrameworkPattern {
    FrameworkPattern {
        framework: "spring".to_string(),
        languages: vec![Language::Java],
        detection_patterns: DetectionPatterns {
            imports: vec![
                regex!("import\\s+org\\.springframework"),
                regex!("import\\s+javax\\.persistence"),
            ],
            decorators: vec![
                regex!("@(Controller|RestController|Service|Repository|Component)"),
                regex!("@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)"),
                regex!("@RequestMapping"),
                regex!("@SpringBootApplication"),
            ],
        },
        decorator_mappings: vec![
            // Routing decorators
            DecoratorMapping {
                pattern: regex!("@Controller"),
                semantic: DecoratorSemantics {
                    category: SemanticCategory::Routing,
                    intent: "Spring MVC controller".to_string(),
                    is_entry_point: true,
                    is_injectable: true,
                    requires_auth: false,
                    data_access: None,
                    confidence: 1.0,
                },
                confidence: 1.0,
                arg_extractor: extract_spring_controller_args,
            },
            DecoratorMapping {
                pattern: regex!("@RestController"),
                semantic: DecoratorSemantics {
                    category: SemanticCategory::Routing,
                    intent: "Spring REST controller".to_string(),
                    is_entry_point: true,
                    is_injectable: true,
                    requires_auth: false,
                    data_access: None,
                    confidence: 1.0,
                },
                confidence: 1.0,
                arg_extractor: extract_spring_controller_args,
            },
            DecoratorMapping {
                pattern: regex!("@(Get|Post|Put|Delete|Patch)Mapping"),
                semantic: DecoratorSemantics {
                    category: SemanticCategory::Routing,
                    intent: "Spring HTTP endpoint".to_string(),
                    is_entry_point: true,
                    is_injectable: false,
                    requires_auth: false,
                    data_access: None,
                    confidence: 1.0,
                },
                confidence: 1.0,
                arg_extractor: extract_spring_mapping_args,
            },
            DecoratorMapping {
                pattern: regex!("@RequestMapping"),
                semantic: DecoratorSemantics {
                    category: SemanticCategory::Routing,
                    intent: "Spring request mapping".to_string(),
                    is_entry_point: true,
                    is_injectable: false,
                    requires_auth: false,
                    data_access: None,
                    confidence: 1.0,
                },
                confidence: 1.0,
                arg_extractor: extract_spring_request_mapping_args,
            },
            // DI decorators
            DecoratorMapping {
                pattern: regex!("@Service"),
                semantic: DecoratorSemantics {
                    category: SemanticCategory::DependencyInjection,
                    intent: "Spring service component".to_string(),
                    is_entry_point: false,
                    is_injectable: true,
                    requires_auth: false,
                    data_access: None,
                    confidence: 1.0,
                },
                confidence: 1.0,
                arg_extractor: |_| DecoratorArguments::default(),
            },
            DecoratorMapping {
                pattern: regex!("@Repository"),
                semantic: DecoratorSemantics {
                    category: SemanticCategory::Orm,
                    intent: "Spring data repository".to_string(),
                    is_entry_point: false,
                    is_injectable: true,
                    requires_auth: false,
                    data_access: Some(DataAccessMode::Both),
                    confidence: 1.0,
                },
                confidence: 1.0,
                arg_extractor: |_| DecoratorArguments::default(),
            },
            DecoratorMapping {
                pattern: regex!("@Autowired"),
                semantic: DecoratorSemantics {
                    category: SemanticCategory::DependencyInjection,
                    intent: "Spring dependency injection".to_string(),
                    is_entry_point: false,
                    is_injectable: false,
                    requires_auth: false,
                    data_access: None,
                    confidence: 1.0,
                },
                confidence: 1.0,
                arg_extractor: |_| DecoratorArguments::default(),
            },
            DecoratorMapping {
                pattern: regex!("@Entity"),
                semantic: DecoratorSemantics {
                    category: SemanticCategory::Orm,
                    intent: "JPA entity".to_string(),
                    is_entry_point: false,
                    is_injectable: false,
                    requires_auth: false,
                    data_access: Some(DataAccessMode::Both),
                    confidence: 1.0,
                },
                confidence: 1.0,
                arg_extractor: |_| DecoratorArguments::default(),
            },
            // Auth decorators
            DecoratorMapping {
                pattern: regex!("@(PreAuthorize|Secured|RolesAllowed)"),
                semantic: DecoratorSemantics {
                    category: SemanticCategory::Auth,
                    intent: "Spring security authorization".to_string(),
                    is_entry_point: false,
                    is_injectable: false,
                    requires_auth: true,
                    data_access: None,
                    confidence: 1.0,
                },
                confidence: 1.0,
                arg_extractor: extract_spring_auth_args,
            },
        ],
    }
}
```

The remaining 4 preserved framework patterns (FastAPI, NestJS, Laravel, ASP.NET)
follow the same structure. Each defines:
- Detection patterns (imports + decorators)
- Decorator mappings with semantic classification
- Argument extraction functions

#### FastAPI (Python) — Key Mappings

| Decorator | Category | Entry Point | Notes |
|-----------|----------|-------------|-------|
| `@app.get/post/put/delete/patch` | Routing | ✅ | Path + methods extracted |
| `@Depends` | DependencyInjection | — | DI function reference |
| `@Body/@Query/@Path/@Header` | Validation | — | Parameter validation |
| `@HTTPException` | Middleware | — | Error handling |

#### NestJS (TypeScript) — Key Mappings

| Decorator | Category | Entry Point | Injectable |
|-----------|----------|-------------|------------|
| `@Controller` | Routing | ✅ | ✅ |
| `@Get/@Post/@Put/@Delete/@Patch` | Routing | ✅ | — |
| `@Injectable` | DependencyInjection | — | ✅ |
| `@Module` | DependencyInjection | — | — |
| `@UseGuards` | Middleware | — | — |
| `@UseInterceptors` | Middleware | — | — |
| `@UsePipes` | Validation | — | — |

#### Laravel (PHP) — Key Mappings

| Pattern | Category | Entry Point | Notes |
|---------|----------|-------------|-------|
| `Route::get/post/put/delete` | Routing | ✅ | Static method calls |
| `Route::resource` | Routing | ✅ | RESTful resource |
| `Route::middleware` | Middleware | — | Middleware chain |
| `Route::group` | Routing | — | Route grouping |

#### ASP.NET Core (C#) — Key Mappings

| Attribute | Category | Entry Point | Auth |
|-----------|----------|-------------|------|
| `[ApiController]` | Routing | ✅ | — |
| `[HttpGet/Post/Put/Delete]` | Routing | ✅ | — |
| `[Route]` | Routing | ✅ | — |
| `[Authorize]` | Auth | — | ✅ |
| `[AllowAnonymous]` | Auth | — | — |
| `[FromBody/FromQuery/FromRoute]` | Validation | — | — |

#### NEW v2 Framework Patterns (6 additions)

| Framework | Language | Key Patterns |
|-----------|----------|-------------|
| Express | TS/JS | `app.get/post/put/delete()`, `router.use()`, `express.Router()` |
| Flask | Python | `@app.route()`, `@blueprint.route()`, `@login_required` |
| Django | Python | `path()`, `re_path()`, `@login_required`, `@permission_required` |
| Gin | Go | `r.GET/POST/PUT/DELETE()`, `r.Group()`, `c.JSON()` |
| Actix | Rust | `#[get/post/put/delete]`, `web::resource()`, `HttpResponse` |
| Axum | Rust | `Router::new().route()`, `axum::extract::*`, `Json()` |

### 7.4 Decorator Normalization Pipeline

```rust
/// The decorator normalization pipeline.
/// Converts raw decorator strings into semantically classified NormalizedDecorator objects.
pub struct DecoratorNormalizer {
    framework_registry: Arc<FrameworkRegistry>,
}

impl DecoratorNormalizer {
    pub fn new(registry: Arc<FrameworkRegistry>) -> Self {
        Self { framework_registry: registry }
    }

    /// Normalize a single raw decorator string.
    pub fn normalize(
        &self,
        raw: &str,
        language: Language,
        frameworks: &[&FrameworkPattern],
    ) -> NormalizedDecorator {
        // Step 1: Extract clean name (strip @, #, [], ())
        let name = self.extract_name(raw);

        // Step 2: Try framework registry for known decorator mapping
        if let Some((mapping, framework)) = self.framework_registry
            .find_decorator_mapping(raw, frameworks)
        {
            let arguments = (mapping.arg_extractor)(raw);
            return NormalizedDecorator {
                raw: raw.to_string(),
                name,
                language,
                framework: Some(framework.to_string()),
                semantic: DecoratorSemantics {
                    confidence: mapping.confidence,
                    ..mapping.semantic.clone()
                },
                arguments,
            };
        }

        // Step 3: Fallback — unknown decorator with generic extraction
        let arguments = self.extract_generic_arguments(raw);
        NormalizedDecorator {
            raw: raw.to_string(),
            name,
            language,
            framework: None,
            semantic: DecoratorSemantics {
                category: SemanticCategory::Unknown,
                intent: String::new(),
                is_entry_point: false,
                is_injectable: false,
                requires_auth: false,
                data_access: None,
                confidence: 0.0,
            },
            arguments,
        }
    }

    /// Extract clean decorator name from raw string.
    /// Strips language-specific prefixes/suffixes:
    ///   @GetMapping("/users") → "GetMapping"
    ///   #[get("/users")]      → "get"
    ///   [HttpGet("users")]    → "HttpGet"
    ///   @app.route("/users")  → "app.route"
    fn extract_name(&self, raw: &str) -> String {
        let mut name = raw.to_string();

        // Strip leading @ (Java, Python, TS)
        if name.starts_with('@') { name = name[1..].to_string(); }

        // Strip leading # (Rust attributes)
        if name.starts_with('#') { name = name[1..].to_string(); }

        // Strip surrounding [] (C#, Rust)
        if name.starts_with('[') && name.ends_with(']') {
            name = name[1..name.len()-1].to_string();
        }

        // Strip arguments (everything after first '(')
        if let Some(paren_idx) = name.find('(') {
            name = name[..paren_idx].to_string();
        }

        name.trim().to_string()
    }

    /// Extract generic arguments from decorator string.
    /// Handles path-like arguments: @Route("/users") → path: "/users"
    fn extract_generic_arguments(&self, raw: &str) -> DecoratorArguments {
        let mut args = DecoratorArguments::default();

        // Extract string argument (likely a path)
        if let Some(start) = raw.find('(') {
            let inner = &raw[start+1..raw.len().saturating_sub(1)];
            // Look for quoted string
            if let Some(quote_start) = inner.find(|c| c == '\'' || c == '"') {
                let quote_char = inner.as_bytes()[quote_start] as char;
                if let Some(quote_end) = inner[quote_start+1..].find(quote_char) {
                    let path = &inner[quote_start+1..quote_start+1+quote_end];
                    if path.starts_with('/') || path.starts_with("api") {
                        args.path = Some(path.to_string());
                    }
                }
            }
        }

        args
    }
}
```

### 7.5 Semantic Derivation

```rust
/// Derives function-level and file-level semantics from normalized decorators.
pub struct SemanticDeriver;

impl SemanticDeriver {
    /// Derive function semantics from its normalized decorators.
    pub fn derive_function_semantics(
        decorators: &[NormalizedDecorator],
        orm_patterns: &[OrmPattern],
    ) -> FunctionSemantics {
        let is_entry_point = decorators.iter().any(|d| d.semantic.is_entry_point);
        let is_injectable = decorators.iter().any(|d| d.semantic.is_injectable);
        let is_auth_handler = decorators.iter().any(|d| d.semantic.category == SemanticCategory::Auth);
        let is_test_case = decorators.iter().any(|d| d.semantic.category == SemanticCategory::Test);
        let is_data_accessor = !orm_patterns.is_empty()
            || decorators.iter().any(|d| d.semantic.data_access.is_some());
        let requires_auth = decorators.iter().any(|d| d.semantic.requires_auth);

        // Extract entry point info from routing decorators
        let entry_point = if is_entry_point {
            let routing_dec = decorators.iter()
                .find(|d| d.semantic.category == SemanticCategory::Routing);
            routing_dec.map(|d| EntryPointInfo {
                kind: EntryPointKind::Http,
                path: d.arguments.path.clone(),
                methods: d.arguments.methods.clone(),
            })
        } else { None };

        // Extract auth info
        let auth = if requires_auth {
            let auth_dec = decorators.iter()
                .find(|d| d.semantic.requires_auth);
            auth_dec.map(|d| AuthInfo {
                required: true,
                roles: d.arguments.roles.clone(),
                strategy: None,
            })
        } else { None };

        FunctionSemantics {
            is_entry_point,
            is_data_accessor,
            is_auth_handler,
            is_test_case,
            is_injectable,
            requires_auth,
            entry_point,
            dependencies: Vec::new(), // Filled by language-specific extraction
            data_access: orm_patterns.to_vec(),
            auth,
        }
    }

    /// Derive file-level semantics from all function semantics in the file.
    pub fn derive_file_semantics(
        function_semantics: &[(Spur, FunctionSemantics)],
        detected_frameworks: &[DetectedFramework],
    ) -> FileSemantics {
        let has_entry_points = function_semantics.iter().any(|(_, s)| s.is_entry_point);
        let has_injectables = function_semantics.iter().any(|(_, s)| s.is_injectable);
        let has_data_accessors = function_semantics.iter().any(|(_, s)| s.is_data_accessor);
        let has_tests = function_semantics.iter().any(|(_, s)| s.is_test_case);
        let has_middleware = function_semantics.iter().any(|(_, s)| {
            // Heuristic: functions with auth but no entry point are middleware
            s.is_auth_handler && !s.is_entry_point
        });

        let primary_framework = detected_frameworks.first()
            .map(|f| f.name.clone());

        FileSemantics {
            is_controller: has_entry_points,
            is_service: has_injectables && !has_entry_points,
            is_model: has_data_accessors && !has_entry_points && !has_injectables,
            is_test_file: has_tests,
            is_middleware: has_middleware,
            is_config: false, // Detected by file path heuristics
            primary_framework,
            detected_frameworks: detected_frameworks.iter()
                .map(|f| f.name.clone()).collect(),
        }
    }
}
```


---

## 8. Cross-Language Query Engine

### 8.1 QueryEngine

The query engine provides high-level semantic queries across all normalized files.
This is the v2 equivalent of v1's `LanguageIntelligence` class.

```rust
/// Cross-language semantic query engine.
/// Operates on UlpResult objects from multiple files.
pub struct QueryEngine;

impl QueryEngine {
    /// Find all HTTP entry points across all files.
    pub fn find_entry_points(results: &[UlpResult]) -> Vec<QueryResult> {
        Self::query(results, &QueryOptions {
            is_entry_point: Some(true),
            ..Default::default()
        })
    }

    /// Find all data accessor functions, optionally filtered by table name.
    pub fn find_data_accessors(
        results: &[UlpResult],
        table: Option<&str>,
    ) -> Vec<QueryResult> {
        let mut matches = Self::query(results, &QueryOptions {
            is_data_accessor: Some(true),
            ..Default::default()
        });

        if let Some(table_name) = table {
            matches.retain(|r| {
                r.semantics.data_access.iter()
                    .any(|p| p.table.as_deref() == Some(table_name))
            });
        }

        matches
    }

    /// Find all injectable services (DI components).
    pub fn find_injectables(results: &[UlpResult]) -> Vec<QueryResult> {
        Self::query(results, &QueryOptions {
            is_injectable: Some(true),
            ..Default::default()
        })
    }

    /// Find all auth-related functions.
    pub fn find_auth_handlers(results: &[UlpResult]) -> Vec<QueryResult> {
        Self::query(results, &QueryOptions {
            is_auth_handler: Some(true),
            ..Default::default()
        })
    }

    /// Find functions by semantic category.
    pub fn find_by_category(
        results: &[UlpResult],
        category: SemanticCategory,
    ) -> Vec<QueryResult> {
        Self::query(results, &QueryOptions {
            category: Some(category),
            ..Default::default()
        })
    }

    /// General cross-language query with flexible filters.
    pub fn query(results: &[UlpResult], options: &QueryOptions) -> Vec<QueryResult> {
        let mut matches = Vec::new();

        for result in results {
            // Language filter
            if let Some(lang) = options.language {
                if result.language != lang { continue; }
            }

            // Framework filter
            if let Some(ref fw) = options.framework {
                if !result.detected_frameworks.iter().any(|f| &f.name == fw) {
                    continue;
                }
            }

            for (func_name, semantics) in &result.function_semantics {
                // Boolean filters
                if let Some(ep) = options.is_entry_point {
                    if semantics.is_entry_point != ep { continue; }
                }
                if let Some(da) = options.is_data_accessor {
                    if semantics.is_data_accessor != da { continue; }
                }
                if let Some(ah) = options.is_auth_handler {
                    if semantics.is_auth_handler != ah { continue; }
                }
                if let Some(inj) = options.is_injectable {
                    if semantics.is_injectable != inj { continue; }
                }

                // Category filter (match any decorator with this category)
                if let Some(cat) = options.category {
                    let has_category = result.decorators.iter()
                        .any(|d| d.semantic.category == cat);
                    if !has_category { continue; }
                }

                // Collect matched decorators for this function
                let matched_decorators: Vec<NormalizedDecorator> = result.decorators.iter()
                    .filter(|d| {
                        // Match decorators that contributed to this function's semantics
                        options.category.map_or(true, |cat| d.semantic.category == cat)
                    })
                    .cloned()
                    .collect();

                matches.push(QueryResult {
                    function_name: *func_name,
                    file: result.file,
                    line: 0, // Populated from function info
                    framework: result.file_semantics.primary_framework.clone(),
                    matched_decorators,
                    semantics: semantics.clone(),
                });
            }
        }

        matches
    }

    /// Get ORM usage summary across all files.
    pub fn orm_summary(results: &[UlpResult]) -> OrmUsageSummary {
        let mut by_orm: FxHashMap<OrmType, u64> = FxHashMap::default();
        let mut by_operation: FxHashMap<DataOperation, u64> = FxHashMap::default();
        let mut tables: FxHashMap<String, u64> = FxHashMap::default();

        for result in results {
            for pattern in &result.orm_patterns {
                *by_orm.entry(pattern.orm).or_default() += 1;
                *by_operation.entry(pattern.operation).or_default() += 1;
                if let Some(ref table) = pattern.table {
                    *tables.entry(table.clone()).or_default() += 1;
                }
            }
        }

        OrmUsageSummary {
            total_patterns: results.iter().map(|r| r.orm_patterns.len() as u64).sum(),
            by_orm,
            by_operation,
            tables,
            files_with_data_access: results.iter()
                .filter(|r| !r.orm_patterns.is_empty()).count() as u64,
        }
    }
}

pub struct OrmUsageSummary {
    pub total_patterns: u64,
    pub by_orm: FxHashMap<OrmType, u64>,
    pub by_operation: FxHashMap<DataOperation, u64>,
    pub tables: FxHashMap<String, u64>,
    pub files_with_data_access: u64,
}
```

---

## 9. Integration with Analysis Pipeline

### 9.1 Pipeline Integration Point

The ULP runs as part of the per-file analysis pipeline in the Unified Analysis Engine.
It integrates at Phase 1.5 (visitor pattern engine phase).

```rust
/// ULP integration into the per-file analysis pipeline.
pub struct UnifiedLanguageProvider {
    normalizer_registry: NormalizerRegistry,
    matcher_registry: MatcherRegistry,
    framework_registry: Arc<FrameworkRegistry>,
    decorator_normalizer: DecoratorNormalizer,
}

impl UnifiedLanguageProvider {
    pub fn new() -> Self {
        let framework_registry = Arc::new(FrameworkRegistry::new());
        Self {
            normalizer_registry: NormalizerRegistry::new(),
            matcher_registry: MatcherRegistry::new(),
            framework_registry: framework_registry.clone(),
            decorator_normalizer: DecoratorNormalizer::new(framework_registry),
        }
    }

    /// Process a single file through the full ULP pipeline.
    /// Called by the Unified Analysis Engine during per-file analysis.
    pub fn process_file(
        &self,
        tree: &Tree,
        source: &[u8],
        language: Language,
        file: Spur,
        interner: &ThreadedRodeo,
    ) -> UlpResult {
        let start = std::time::Instant::now();

        // Step 1: Get the appropriate normalizer
        let normalizer = match self.normalizer_registry.get(language) {
            Some(n) => n,
            None => return UlpResult::empty(file, language),
        };

        // Step 2: Detect frameworks in this file
        let detected_frameworks_patterns = self.framework_registry
            .detect_frameworks(source, language);
        let detected_frameworks: Vec<DetectedFramework> = detected_frameworks_patterns.iter()
            .map(|fp| DetectedFramework {
                name: fp.framework.clone(),
                confidence: 0.9,
                detection_source: FrameworkDetectionSource::Import,
            })
            .collect();

        // Step 3: Extract call chains
        let extraction_start = std::time::Instant::now();
        let call_chains = normalizer.extract_call_chains(tree, source, interner);
        let extraction_time = extraction_start.elapsed().as_micros() as u64;

        // Step 4: Run ORM matchers against call chains
        let matching_start = std::time::Instant::now();
        let orm_patterns: Vec<OrmPattern> = call_chains.iter()
            .filter_map(|chain| self.matcher_registry.match_chain(chain))
            .collect();
        let matching_time = matching_start.elapsed().as_micros() as u64;

        // Step 5: Normalize decorators
        let semantic_start = std::time::Instant::now();
        let decorators = normalizer.normalize_decorators(
            tree, source, &detected_frameworks_patterns, interner,
        );

        // Step 6: Derive function semantics
        // Group decorators and ORM patterns by enclosing function
        let function_semantics = self.derive_all_function_semantics(
            tree, source, &decorators, &orm_patterns, interner,
        );

        // Step 7: Derive file semantics
        let file_semantics = SemanticDeriver::derive_file_semantics(
            &function_semantics, &detected_frameworks,
        );
        let semantic_time = semantic_start.elapsed().as_micros() as u64;

        UlpResult {
            file,
            language,
            call_chains,
            orm_patterns,
            decorators,
            function_semantics,
            file_semantics,
            detected_frameworks,
            extraction_time_us: extraction_time,
            matching_time_us: matching_time,
            semantic_time_us: semantic_time,
        }
    }

    /// Derive function semantics for all functions in a file.
    fn derive_all_function_semantics(
        &self,
        tree: &Tree,
        source: &[u8],
        decorators: &[NormalizedDecorator],
        orm_patterns: &[OrmPattern],
        interner: &ThreadedRodeo,
    ) -> Vec<(Spur, FunctionSemantics)> {
        // Walk the AST to find function declarations and their associated decorators
        let mut results = Vec::new();
        let mut cursor = tree.walk();
        self.collect_function_semantics(
            &mut cursor, source, decorators, orm_patterns, interner, &mut results,
        );
        results
    }

    fn collect_function_semantics(
        &self,
        cursor: &mut TreeCursor,
        source: &[u8],
        decorators: &[NormalizedDecorator],
        orm_patterns: &[OrmPattern],
        interner: &ThreadedRodeo,
        results: &mut Vec<(Spur, FunctionSemantics)>,
    ) {
        let node = cursor.node();
        let kind = node.kind();

        // Check if this is a function-like node
        let is_function = matches!(kind,
            "function_declaration" | "method_definition" | "function_definition" |
            "method_declaration" | "arrow_function" | "function_item" |
            "function_definition" | "method_declaration"
        );

        if is_function {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name_text = name_node.utf8_text(source).unwrap_or("");
                let name = interner.get_or_intern(name_text);
                let line = node.start_position().row as u32 + 1;
                let end_line = node.end_position().row as u32 + 1;

                // Find decorators that belong to this function (by line proximity)
                let func_decorators: Vec<&NormalizedDecorator> = decorators.iter()
                    .filter(|d| {
                        // Decorator should be on lines immediately before the function
                        // This is a heuristic — exact association requires parent node check
                        true // Simplified — real impl checks AST parent
                    })
                    .collect();

                // Find ORM patterns within this function's body
                let func_orm: Vec<OrmPattern> = orm_patterns.iter()
                    .filter(|p| p.line >= line && p.line <= end_line)
                    .cloned()
                    .collect();

                let semantics = SemanticDeriver::derive_function_semantics(
                    &func_decorators.iter().map(|d| (*d).clone()).collect::<Vec<_>>(),
                    &func_orm,
                );

                results.push((name, semantics));
            }
        }

        // Recurse
        if cursor.goto_first_child() {
            loop {
                self.collect_function_semantics(
                    cursor, source, decorators, orm_patterns, interner, results,
                );
                if !cursor.goto_next_sibling() { break; }
            }
            cursor.goto_parent();
        }
    }
}
```

### 9.2 Integration with Boundary Detection

The ULP's ORM patterns feed directly into boundary detection for data flow analysis.

```rust
/// Boundary detection consumes ULP ORM patterns to identify data boundaries.
pub fn extract_data_boundaries(ulp_results: &[UlpResult]) -> Vec<DataBoundary> {
    let mut boundaries = Vec::new();

    for result in ulp_results {
        for pattern in &result.orm_patterns {
            if let Some(ref table) = pattern.table {
                boundaries.push(DataBoundary {
                    table: table.clone(),
                    orm: pattern.orm,
                    operations: vec![pattern.operation],
                    fields: pattern.fields.clone(),
                    file: result.file,
                    line: pattern.line,
                    has_sensitive_fields: false, // Set by boundary analyzer
                });
            }
        }
    }

    // Deduplicate by table name, merge operations
    deduplicate_boundaries(&mut boundaries);
    boundaries
}
```

### 9.3 Integration with Taint Analysis

ORM patterns provide taint sinks for security analysis.

```rust
/// Convert ORM patterns to taint sinks for security analysis.
pub fn extract_taint_sinks(ulp_results: &[UlpResult]) -> Vec<TaintSink> {
    let mut sinks = Vec::new();

    for result in ulp_results {
        for pattern in &result.orm_patterns {
            // Raw SQL queries are high-priority taint sinks (SQL injection risk)
            if pattern.is_raw_sql {
                sinks.push(TaintSink {
                    kind: TaintSinkKind::SqlQuery,
                    file: result.file,
                    line: pattern.line,
                    column: pattern.column,
                    severity: TaintSeverity::Critical,
                    orm: Some(pattern.orm),
                });
            }

            // ORM queries with string interpolation are medium-priority sinks
            if pattern.has_string_interpolation() {
                sinks.push(TaintSink {
                    kind: TaintSinkKind::SqlQuery,
                    file: result.file,
                    line: pattern.line,
                    column: pattern.column,
                    severity: TaintSeverity::High,
                    orm: Some(pattern.orm),
                });
            }
        }
    }

    sinks
}
```

### 9.4 Integration with N+1 Query Detection

Per R8 from analyzer recommendations: detect N+1 query anti-patterns by combining
ULP ORM patterns with control flow analysis.

```rust
/// Detect N+1 query patterns by finding ORM queries inside loops.
pub fn detect_n_plus_one(
    ulp_result: &UlpResult,
    flow_result: &FlowAnalysisResult,
) -> Vec<NPlusOneViolation> {
    let mut violations = Vec::new();

    // Find all loops in the control flow graph
    for loop_node in &flow_result.cfg.loops {
        // Find ORM patterns within the loop's line range
        let queries_in_loop: Vec<&OrmPattern> = ulp_result.orm_patterns.iter()
            .filter(|p| p.line >= loop_node.start_line && p.line <= loop_node.end_line)
            .collect();

        for query in queries_in_loop {
            // Check if there's a bulk/batch query before the loop for the same table
            let has_prefetch = ulp_result.orm_patterns.iter().any(|p| {
                p.line < loop_node.start_line
                    && p.table == query.table
                    && matches!(p.operation, DataOperation::Select)
            });

            if !has_prefetch {
                violations.push(NPlusOneViolation {
                    loop_location: SourceLocation {
                        file: ulp_result.file,
                        line: loop_node.start_line,
                        column: 0,
                    },
                    query_location: SourceLocation {
                        file: ulp_result.file,
                        line: query.line,
                        column: query.column,
                    },
                    table: query.table.clone(),
                    orm: query.orm,
                    suggestion: generate_n_plus_one_fix(query.orm),
                });
            }
        }
    }

    violations
}

fn generate_n_plus_one_fix(orm: OrmType) -> String {
    match orm {
        OrmType::Prisma => "Use `include` or `select` with the parent query".to_string(),
        OrmType::Django => "Use `select_related()` or `prefetch_related()`".to_string(),
        OrmType::SqlAlchemy => "Use `joinedload()` or `subqueryload()`".to_string(),
        OrmType::EfCore => "Use `.Include()` with the parent query".to_string(),
        OrmType::Eloquent => "Use `with()` for eager loading".to_string(),
        OrmType::Gorm => "Use `Preload()` with the parent query".to_string(),
        OrmType::Sequelize => "Use `include` option in the parent query".to_string(),
        OrmType::TypeOrm => "Use `relations` option or `leftJoinAndSelect()`".to_string(),
        _ => "Batch the query outside the loop".to_string(),
    }
}
```

---

## 10. Storage Schema

ULP results persist to drift.db for incremental analysis and cross-file queries.

### orm_patterns — Detected ORM Patterns

```sql
CREATE TABLE orm_patterns (
    id TEXT PRIMARY KEY,
    file_path TEXT NOT NULL,
    orm TEXT NOT NULL,
    table_name TEXT,
    operation TEXT NOT NULL,
    fields_json TEXT NOT NULL CHECK(json_valid(fields_json)),
    conditions_json TEXT NOT NULL CHECK(json_valid(conditions_json)),
    line INTEGER NOT NULL,
    column INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    end_column INTEGER NOT NULL,
    chain_length INTEGER NOT NULL,
    confidence REAL NOT NULL,
    is_raw_sql INTEGER NOT NULL DEFAULT 0,
    raw_sql TEXT,
    enclosing_function TEXT,
    has_joins INTEGER NOT NULL DEFAULT 0,
    has_aggregation INTEGER NOT NULL DEFAULT 0,
    has_ordering INTEGER NOT NULL DEFAULT 0,
    has_pagination INTEGER NOT NULL DEFAULT 0,
    in_transaction INTEGER NOT NULL DEFAULT 0,
    scan_id TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE INDEX idx_orm_patterns_file ON orm_patterns(file_path);
CREATE INDEX idx_orm_patterns_orm ON orm_patterns(orm);
CREATE INDEX idx_orm_patterns_table ON orm_patterns(table_name);
CREATE INDEX idx_orm_patterns_operation ON orm_patterns(operation);
CREATE INDEX idx_orm_patterns_scan ON orm_patterns(scan_id);
```

### file_semantics — Per-File Semantic Classification

```sql
CREATE TABLE file_semantics (
    file_path TEXT PRIMARY KEY,
    language TEXT NOT NULL,
    is_controller INTEGER NOT NULL DEFAULT 0,
    is_service INTEGER NOT NULL DEFAULT 0,
    is_model INTEGER NOT NULL DEFAULT 0,
    is_test_file INTEGER NOT NULL DEFAULT 0,
    is_middleware INTEGER NOT NULL DEFAULT 0,
    is_config INTEGER NOT NULL DEFAULT 0,
    primary_framework TEXT,
    detected_frameworks_json TEXT NOT NULL CHECK(json_valid(detected_frameworks_json)),
    scan_id TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE INDEX idx_file_semantics_framework ON file_semantics(primary_framework);
CREATE INDEX idx_file_semantics_scan ON file_semantics(scan_id);
```

### function_semantics — Per-Function Semantic Classification

```sql
CREATE TABLE function_semantics (
    id TEXT PRIMARY KEY,
    file_path TEXT NOT NULL,
    function_name TEXT NOT NULL,
    is_entry_point INTEGER NOT NULL DEFAULT 0,
    is_data_accessor INTEGER NOT NULL DEFAULT 0,
    is_auth_handler INTEGER NOT NULL DEFAULT 0,
    is_test_case INTEGER NOT NULL DEFAULT 0,
    is_injectable INTEGER NOT NULL DEFAULT 0,
    requires_auth INTEGER NOT NULL DEFAULT 0,
    entry_point_kind TEXT,
    entry_point_path TEXT,
    entry_point_methods_json TEXT,
    dependencies_json TEXT NOT NULL CHECK(json_valid(dependencies_json)),
    auth_roles_json TEXT,
    line INTEGER NOT NULL,
    scan_id TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE INDEX idx_function_semantics_file ON function_semantics(file_path);
CREATE INDEX idx_function_semantics_entry ON function_semantics(is_entry_point);
CREATE INDEX idx_function_semantics_data ON function_semantics(is_data_accessor);
CREATE INDEX idx_function_semantics_scan ON function_semantics(scan_id);
```

### decorator_cache — Normalized Decorator Cache

```sql
CREATE TABLE decorator_cache (
    file_path TEXT NOT NULL,
    content_hash INTEGER NOT NULL,
    decorators_json TEXT NOT NULL CHECK(json_valid(decorators_json)),
    frameworks_json TEXT NOT NULL CHECK(json_valid(frameworks_json)),
    cached_at TEXT NOT NULL,
    PRIMARY KEY (file_path)
) STRICT;

CREATE INDEX idx_decorator_cache_hash ON decorator_cache(content_hash);
```


---

## 11. NAPI Interface

Three NAPI entry points for ULP queries. All follow the command/query pattern
from 03-NAPI-BRIDGE-V2-PREP.md. ULP processing itself happens inside
`analyze_unified` — these are query-only functions for reading results.

### Query Functions

```rust
/// Query ORM patterns with filters and pagination.
#[napi]
pub fn query_orm_patterns(
    filter: OrmPatternFilter,
    pagination: Option<PaginationOptions>,
) -> napi::Result<PaginatedResult> {
    let rt = crate::runtime::get()?;
    let page = pagination.unwrap_or_default();
    let limit = page.limit.unwrap_or(50).min(100) as usize;

    let cursor = page.cursor.as_deref()
        .map(decode_cursor).transpose()?;

    let result = drift_core::ulp::query_orm_patterns(
        &rt.db, &filter.into(), cursor.as_ref(), limit,
    ).map_err(to_napi_error)?;

    Ok(PaginatedResult {
        items: serde_json::to_value(&result.items)
            .map_err(|e| napi::Error::from_reason(format!("[INTERNAL_ERROR] {e}")))?,
        total: result.total as u32,
        has_more: result.has_more,
        next_cursor: result.next_cursor,
    })
}

/// Query semantic entry points across all files.
#[napi]
pub fn query_entry_points(
    filter: Option<EntryPointFilter>,
) -> napi::Result<Vec<JsEntryPoint>> {
    let rt = crate::runtime::get()?;
    let results = drift_core::ulp::query_entry_points(
        &rt.db, &filter.unwrap_or_default().into(),
    ).map_err(to_napi_error)?;

    Ok(results.into_iter().map(JsEntryPoint::from).collect())
}

/// Query file semantic classifications.
#[napi]
pub fn query_file_semantics(
    filter: Option<FileSemanticFilter>,
    pagination: Option<PaginationOptions>,
) -> napi::Result<PaginatedResult> {
    let rt = crate::runtime::get()?;
    let page = pagination.unwrap_or_default();
    let limit = page.limit.unwrap_or(50).min(100) as usize;

    let result = drift_core::ulp::query_file_semantics(
        &rt.db, &filter.unwrap_or_default().into(),
        page.cursor.as_deref().map(decode_cursor).transpose()?.as_ref(),
        limit,
    ).map_err(to_napi_error)?;

    Ok(PaginatedResult {
        items: serde_json::to_value(&result.items)
            .map_err(|e| napi::Error::from_reason(format!("[INTERNAL_ERROR] {e}")))?,
        total: result.total as u32,
        has_more: result.has_more,
        next_cursor: result.next_cursor,
    })
}

/// Get ORM usage summary (aggregate statistics).
#[napi]
pub fn query_orm_summary() -> napi::Result<JsOrmSummary> {
    let rt = crate::runtime::get()?;
    let summary = drift_core::ulp::orm_summary(&rt.db)
        .map_err(to_napi_error)?;
    Ok(JsOrmSummary::from(summary))
}
```

### NAPI Filter Types

```rust
#[napi(object)]
pub struct OrmPatternFilter {
    pub orm: Option<String>,
    pub table: Option<String>,
    pub operation: Option<String>,
    pub file: Option<String>,
    pub is_raw_sql: Option<bool>,
    pub has_joins: Option<bool>,
    pub min_confidence: Option<f64>,
}

#[napi(object)]
pub struct EntryPointFilter {
    pub framework: Option<String>,
    pub language: Option<String>,
    pub method: Option<String>,
    pub path_prefix: Option<String>,
}

#[napi(object)]
pub struct FileSemanticFilter {
    pub is_controller: Option<bool>,
    pub is_service: Option<bool>,
    pub is_model: Option<bool>,
    pub is_test_file: Option<bool>,
    pub framework: Option<String>,
    pub language: Option<String>,
}
```

---

## 12. Event Interface

The ULP emits events via the DriftEventHandler trait for Cortex integration.

```rust
pub trait UlpEvents {
    /// Emitted when a new ORM is first detected in the project.
    fn on_new_orm_detected(&self, orm: OrmType, file: Spur) {}

    /// Emitted when a new table/collection is first accessed.
    fn on_new_table_detected(&self, table: &str, orm: OrmType, file: Spur) {}

    /// Emitted when a raw SQL query is detected (potential security concern).
    fn on_raw_sql_detected(&self, sql: &str, file: Spur, line: u32) {}

    /// Emitted when an N+1 query pattern is detected.
    fn on_n_plus_one_detected(&self, violation: &NPlusOneViolation) {}

    /// Emitted when a new framework is detected in the project.
    fn on_framework_detected(&self, framework: &str, language: Language) {}

    /// Emitted when file semantic classification changes.
    fn on_file_classification_changed(
        &self, file: Spur, old: &FileSemantics, new: &FileSemantics,
    ) {}
}
```

---

## 13. Tracing & Observability

```rust
fn process_file_traced(
    ulp: &UnifiedLanguageProvider,
    tree: &Tree,
    source: &[u8],
    language: Language,
    file: Spur,
    interner: &ThreadedRodeo,
) -> UlpResult {
    let span = tracing::info_span!("ulp_process_file",
        file = %interner.resolve(&file),
        language = ?language,
    );
    let _guard = span.enter();

    let result = ulp.process_file(tree, source, language, file, interner);

    tracing::info!(
        call_chains = result.call_chains.len(),
        orm_patterns = result.orm_patterns.len(),
        decorators = result.decorators.len(),
        frameworks = result.detected_frameworks.len(),
        extraction_us = result.extraction_time_us,
        matching_us = result.matching_time_us,
        semantic_us = result.semantic_time_us,
        file_type = ?result.file_semantics.primary_framework,
        "ULP file processing complete"
    );

    result
}
```

### Metrics Collected

| Metric | Span | Type |
|--------|------|------|
| Call chains extracted per file | `ulp_process_file` | Gauge |
| ORM patterns detected per file | `ulp_process_file` | Gauge |
| Decorators normalized per file | `ulp_process_file` | Gauge |
| Frameworks detected per file | `ulp_process_file` | Gauge |
| Extraction time (µs) | `ulp_process_file` | Duration |
| Matching time (µs) | `ulp_process_file` | Duration |
| Semantic derivation time (µs) | `ulp_process_file` | Duration |
| Total ORM patterns across project | `ulp_summary` | Counter |
| Unique tables accessed | `ulp_summary` | Counter |
| N+1 violations detected | `ulp_n_plus_one` | Counter |
| Raw SQL queries detected | `ulp_raw_sql` | Counter |
| Framework distribution | `ulp_summary` | Histogram |

---

## 14. Performance Targets & Benchmarks

### Targets

| Metric | V1 Baseline | V2 Target | How Achieved |
|--------|-------------|-----------|-------------|
| Call chain extraction per file | ~5ms | <500µs | Rust + single-pass extraction |
| ORM matching per chain | ~1ms | <50µs | Language-indexed dispatch, early exit |
| Decorator normalization per file | ~2ms | <200µs | Pre-compiled regex, cached framework detection |
| Semantic derivation per file | ~1ms | <100µs | Boolean aggregation, trivial in Rust |
| Full ULP pipeline per file | ~10ms | <1ms | Combined single-pass |
| Full ULP pipeline (10K files) | ~100s | <10s | Rayon parallelism + incremental skip |
| ORM pattern query (paginated) | ~50ms | <5ms | SQLite indexed queries |
| Entry point query (all) | ~100ms | <10ms | SQLite indexed queries |
| Memory per file (ULP result) | ~50KB | <10KB | String interning, SmallVec |

### Benchmark Suite

```rust
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_call_chain_extraction_ts(c: &mut Criterion) {
    c.bench_function("ulp_extract_chains_typescript", |b| {
        b.iter(|| { /* target: <500µs for typical TS file */ })
    });
}

fn bench_orm_matching_prisma(c: &mut Criterion) {
    c.bench_function("ulp_match_prisma_chain", |b| {
        b.iter(|| { /* target: <50µs per chain */ })
    });
}

fn bench_decorator_normalization(c: &mut Criterion) {
    c.bench_function("ulp_normalize_decorators", |b| {
        b.iter(|| { /* target: <200µs for file with 20 decorators */ })
    });
}

fn bench_framework_detection(c: &mut Criterion) {
    c.bench_function("ulp_detect_frameworks", |b| {
        b.iter(|| { /* target: <100µs per file */ })
    });
}

fn bench_full_pipeline_per_file(c: &mut Criterion) {
    c.bench_function("ulp_full_pipeline_per_file", |b| {
        b.iter(|| { /* target: <1ms */ })
    });
}

fn bench_matcher_registry_dispatch(c: &mut Criterion) {
    c.bench_function("ulp_matcher_registry_dispatch", |b| {
        b.iter(|| { /* target: <10µs for language-filtered dispatch */ })
    });
}

fn bench_query_orm_patterns(c: &mut Criterion) {
    c.bench_function("ulp_query_orm_patterns_paginated", |b| {
        b.iter(|| { /* target: <5ms for 50-item page */ })
    });
}

criterion_group!(
    benches,
    bench_call_chain_extraction_ts,
    bench_orm_matching_prisma,
    bench_decorator_normalization,
    bench_framework_detection,
    bench_full_pipeline_per_file,
    bench_matcher_registry_dispatch,
    bench_query_orm_patterns,
);
criterion_main!(benches);
```

---

## 15. Build Order & Dependencies

### Phase 0 — Prerequisites (Must Exist Before Starting)

| Dependency | System | Status |
|-----------|--------|--------|
| Parsers (10 languages) | 01-PARSERS | ParseResult with tree, source |
| String Interning | 04-INFRASTRUCTURE | lasso ThreadedRodeo/RodeoReader |
| Infrastructure | 04-INFRASTRUCTURE | thiserror, tracing, FxHashMap, SmallVec, regex |
| Storage | 02-STORAGE | drift.db with batch writer |

### Phase 1 — Core Types & Shared Logic (Week 1)

```
1. Define all ULP types in Rust
   - UnifiedCallChain, CallSegment, CallArg, ArgValue
   - OrmPattern, OrmType, DataOperation
   - NormalizedDecorator, DecoratorSemantics, SemanticCategory
   - FunctionSemantics, FileSemantics, UlpResult
   - QueryOptions, QueryResult

2. Implement CallChainExtractor (shared extraction logic)
   - AST walking algorithm
   - Argument parsing (all ArgValue variants)
   - Chain reversal and assembly

3. Implement DecoratorNormalizer (shared normalization logic)
   - Name extraction (strip @, #, [], ())
   - Generic argument extraction
   - Framework registry lookup
```

### Phase 2 — Framework Registry (Week 2)

```
4. Implement FrameworkRegistry
   - Singleton pattern (OnceLock)
   - Language-indexed lookup
   - Framework detection from source

5. Port all 5 v1 framework pattern sets
   - Spring Boot (Java) — all decorator mappings
   - FastAPI (Python) — all decorator mappings
   - NestJS (TypeScript) — all decorator mappings
   - Laravel (PHP) — all pattern mappings
   - ASP.NET Core (C#) — all attribute mappings

6. Add 6 new framework pattern sets
   - Express (TS/JS)
   - Flask (Python)
   - Django (Python)
   - Gin (Go)
   - Actix (Rust)
   - Axum (Rust)
```

### Phase 3 — Language Normalizers (Weeks 3-5)

```
7. P0 Normalizers (highest usage):
   - TypeScriptNormalizer (TS/JS — most complex, optional chaining, tagged templates)
   - PythonNormalizer (keyword args, context managers, Django chains)

8. P1 Normalizers:
   - JavaNormalizer (builder patterns, annotations, streams)
   - CSharpNormalizer (LINQ, attributes, extension methods)
   - GoNormalizer (error returns, struct literals, context propagation)

9. P2 Normalizers:
   - PhpNormalizer (static calls, facades, PHP 8 attributes)
   - RustLangNormalizer (? operator, turbofish, macros)
   - CppNormalizer (-> and . operators, templates, RAII)

10. NormalizerRegistry with language + extension dispatch
```

### Phase 4 — ORM Matchers (Weeks 5-8)

```
11. P0 Matchers (highest usage):
    - PrismaMatcher, DjangoMatcher, SqlAlchemyMatcher
    - RawSqlMatcher (universal fallback)

12. P1 Matchers:
    - TypeOrmMatcher, SequelizeMatcher, SpringDataMatcher, EfCoreMatcher

13. P2 Matchers:
    - SupabaseMatcher, DrizzleMatcher, KnexMatcher, MongooseMatcher
    - EloquentMatcher, GormMatcher

14. P3 Matchers:
    - DieselMatcher, SeaOrmMatcher, SqlxMatcher, DatabaseSqlMatcher

15. MatcherRegistry with language-indexed dispatch + priority ordering
```

### Phase 5 — Semantic Derivation & Queries (Weeks 8-9)

```
16. SemanticDeriver
    - Function semantics derivation (8 boolean flags + structured data)
    - File semantics derivation (controller/service/model/test classification)

17. QueryEngine
    - findEntryPoints, findDataAccessors, findInjectables, findAuthHandlers
    - findByCategory, general query with QueryOptions
    - ORM usage summary

18. N+1 query detection integration
```

### Phase 6 — Storage & NAPI (Weeks 9-10)

```
19. Storage schema (4 tables)
    - orm_patterns, file_semantics, function_semantics, decorator_cache

20. NAPI query functions (4)
    - query_orm_patterns, query_entry_points, query_file_semantics, query_orm_summary

21. Event interface (6 events)

22. Tracing spans and metrics
```

### Phase 7 — Integration & Testing (Weeks 10-11)

```
23. Integration with Unified Analysis Engine pipeline (Phase 1.5)
24. Integration with Boundary Detection (ORM patterns → data boundaries)
25. Integration with Taint Analysis (ORM patterns → taint sinks)
26. Integration with N+1 Detection (ORM patterns + flow analysis)
27. Benchmark suite (7 benchmarks)
28. Integration tests (per-language, per-matcher, cross-language queries)
```

---

## 16. V1 → V2 Feature Cross-Reference

Every v1 feature mapped to its exact v2 location. Zero feature loss.

### Preserved Features (Direct Port)

| V1 Feature | V1 Location | V2 Location |
|-----------|-------------|-------------|
| 8 language normalizers | unified-provider/normalizers/*.ts | ulp/normalizers/*.rs |
| 18 concrete ORM matchers | unified-provider/matchers/*.ts | ulp/matchers/*.rs |
| UnifiedCallChain type | unified-provider/types.ts | ulp/types.rs |
| CallSegment with method/args | unified-provider/types.ts | ulp/types.rs |
| ArgValue enum (6 variants) | unified-provider/types.ts | ulp/types.rs (10 variants) |
| OrmPattern result | unified-provider/types.ts | ulp/types.rs (enhanced) |
| DataOperation enum (8 variants) | unified-provider/types.ts | ulp/types.rs |
| OrmType enum (18 variants) | unified-provider/types.ts | ulp/types.rs (19 variants) |
| Matcher registry + dispatch | unified-provider/matcher-registry.ts | ulp/matcher_registry.rs |
| 5 LI normalizers | language-intelligence/normalizers/*.ts | Merged into ulp/normalizers/*.rs |
| Decorator normalization | language-intelligence/base-normalizer.ts | ulp/decorator.rs |
| Framework registry | language-intelligence/framework-registry.ts | ulp/framework_registry.rs |
| 5 framework pattern sets | language-intelligence/frameworks/*.ts | ulp/frameworks/*.rs |
| 12 semantic categories | language-intelligence/types.ts | ulp/types.rs |
| DecoratorSemantics | language-intelligence/types.ts | ulp/types.rs |
| NormalizedDecorator | language-intelligence/types.ts | ulp/types.rs |
| DecoratorArguments | language-intelligence/types.ts | ulp/types.rs |
| FunctionSemantics (8 flags) | language-intelligence/types.ts | ulp/types.rs |
| FileSemantics (4 booleans) | language-intelligence/types.ts | ulp/types.rs (6 booleans) |
| NormalizedExtractionResult | language-intelligence/types.ts | ulp/types.rs (UlpResult) |
| FrameworkPattern | language-intelligence/types.ts | ulp/types.rs |
| DecoratorMapping | language-intelligence/types.ts | ulp/types.rs |
| QueryOptions | language-intelligence/types.ts | ulp/types.rs |
| QueryResult | language-intelligence/types.ts | ulp/types.rs |
| Cross-language queries | language-intelligence/language-intelligence.ts | ulp/queries.rs |
| findEntryPoints | language-intelligence/language-intelligence.ts | QueryEngine::find_entry_points |
| findDataAccessors | language-intelligence/language-intelligence.ts | QueryEngine::find_data_accessors |
| findInjectables | language-intelligence/language-intelligence.ts | QueryEngine::find_injectables |
| findAuthHandlers | language-intelligence/language-intelligence.ts | QueryEngine::find_auth_handlers |
| findByCategory | language-intelligence/language-intelligence.ts | QueryEngine::find_by_category |
| General query | language-intelligence/language-intelligence.ts | QueryEngine::query |
| Factory functions | language-intelligence/normalizers/*.ts | NormalizerRegistry |
| Framework detection | language-intelligence/framework-registry.ts | FrameworkRegistry::detect_frameworks |
| Decorator name extraction | language-intelligence/base-normalizer.ts | DecoratorNormalizer::extract_name |
| Generic arg extraction | language-intelligence/base-normalizer.ts | DecoratorNormalizer::extract_generic_arguments |

### Dropped Features (Compatibility Shims Only)

| V1 Feature | Why Dropped |
|-----------|-------------|
| unified-scanner.ts (drop-in) | No legacy scanner in v2 |
| unified-data-access-adapter.ts | Native OrmPattern type in v2 |
| legacy-extractors.ts | Clean break, no aliases |
| legacy-scanner.ts | Clean break, no wrappers |

### New V2 Features (Not in V1)

| Feature | Location | Source Decision |
|---------|----------|----------------|
| 6 new framework patterns (Express, Flask, Django, Gin, Actix, Axum) | frameworks/*.rs | Gap analysis |
| ArgValue::Lambda variant | types.rs | C#/Python lambda support |
| ArgValue::BooleanLiteral variant | types.rs | Completeness |
| ArgValue::Null variant | types.rs | Completeness |
| ArgValue::Spread variant | types.rs | JS/Python spread/rest |
| OrmPattern.has_joins | types.rs | Join detection |
| OrmPattern.has_aggregation | types.rs | Aggregation detection |
| OrmPattern.has_ordering | types.rs | Ordering detection |
| OrmPattern.has_pagination | types.rs | Pagination detection |
| OrmPattern.in_transaction | types.rs | Transaction context |
| OrmPattern.enclosing_function | types.rs | Function-level association |
| FileSemantics.is_middleware | types.rs | Middleware classification |
| FileSemantics.is_config | types.rs | Config file classification |
| EntryPointKind.Cron/WebSocket/GraphQL | types.rs | Extended entry point types |
| N+1 query detection | n_plus_one.rs | R8 recommendation |
| Taint sink extraction | taint_integration.rs | AD11 |
| ORM usage summary | queries.rs | Analytics |
| Per-file ULP timing metrics | types.rs | Observability |
| SQLite persistence (4 tables) | storage schema | Incremental analysis |
| NAPI query functions (4) | napi/ulp.rs | Query API |
| Event interface (6 events) | events.rs | Cortex integration |
| Benchmark suite (7 benchmarks) | benches/ | Performance validation |

---

## 17. Inconsistencies & Decisions

### I1: Two Separate Normalizer Systems

V1 has two normalizer systems:
- **ULP normalizers** (8): Extract call chains for ORM matching
- **LI normalizers** (5): Normalize decorators for semantic classification

These overlap in language coverage and share framework detection logic.

Resolution: V2 merges both into a single `LanguageNormalizer` trait with three
methods: `extract_call_chains()`, `extract_framework_patterns()`, and
`normalize_decorators()`. One normalizer per language does everything.

### I2: LI Normalizers Missing Go, Rust, C++

V1 Language Intelligence has normalizers for only 5 languages (TS, Python, Java, C#, PHP).
V1 ULP has normalizers for 8 languages (adds Go, Rust, C++).

Resolution: V2 has 8 normalizers that do both call chain extraction AND decorator
normalization. Go, Rust, and C++ get decorator normalization they didn't have in v1.

### I3: Framework Registry Scope

V1 FrameworkRegistry has 5 frameworks (Spring, FastAPI, NestJS, Laravel, ASP.NET).
V1 language analyzers reference additional frameworks (Express, Flask, Django, Gin, Actix, Axum).

Resolution: V2 FrameworkRegistry has 11 frameworks (5 preserved + 6 new).
All frameworks referenced anywhere in v1 are now in the registry.

### I4: OrmPattern vs DataAccessPoint

V1 has two overlapping types:
- `OrmPattern` (from ULP matchers)
- `DataAccessPoint` (from language analyzers)

Resolution: V2 uses `OrmPattern` exclusively. The `unified-data-access-adapter.ts`
bridge is dropped. All data access detection flows through ULP matchers.

### I5: Matcher Priority (First Match vs All Matches)

V1 matcher registry returns the first match. Some chains could match multiple matchers
(e.g., a Prisma query that also contains raw SQL).

Resolution: V2 provides both `match_chain()` (first match, for normal use) and
`match_chain_all()` (all matches, for comprehensive analysis). Default behavior
is first-match with priority ordering (ORM-specific before Raw SQL).

### I6: ULP Location in Crate Structure

06-UNIFIED-ANALYSIS-ENGINE-V2-PREP.md §11 places ULP inside the unified analysis engine.
This document defines ULP as a dedicated subsystem.

Resolution: ULP is a module within `drift-core`, consumed by the unified analysis engine.
It is NOT a separate crate. File structure:

```
crates/drift-core/src/ulp/
├── mod.rs                  # Public API
├── types.rs                # All ULP types
├── provider.rs             # UnifiedLanguageProvider main struct
├── normalizers/
│   ├── mod.rs              # NormalizerRegistry
│   ├── base.rs             # CallChainExtractor (shared logic)
│   ├── typescript.rs       # TypeScriptNormalizer
│   ├── python.rs           # PythonNormalizer
│   ├── java.rs             # JavaNormalizer
│   ├── csharp.rs           # CSharpNormalizer
│   ├── php.rs              # PhpNormalizer
│   ├── go.rs               # GoNormalizer
│   ├── rust_lang.rs        # RustLangNormalizer
│   └── cpp.rs              # CppNormalizer
├── matchers/
│   ├── mod.rs              # MatcherRegistry
│   ├── supabase.rs
│   ├── prisma.rs
│   ├── typeorm.rs
│   ├── sequelize.rs
│   ├── drizzle.rs
│   ├── knex.rs
│   ├── mongoose.rs
│   ├── django.rs
│   ├── sqlalchemy.rs
│   ├── efcore.rs
│   ├── eloquent.rs
│   ├── spring_data.rs
│   ├── gorm.rs
│   ├── diesel.rs
│   ├── seaorm.rs
│   ├── sqlx.rs
│   ├── database_sql.rs
│   └── raw_sql.rs
├── frameworks/
│   ├── mod.rs              # FrameworkRegistry
│   ├── spring.rs
│   ├── fastapi.rs
│   ├── nestjs.rs
│   ├── laravel.rs
│   ├── aspnet.rs
│   ├── express.rs
│   ├── flask.rs
│   ├── django.rs
│   ├── gin.rs
│   ├── actix.rs
│   └── axum.rs
├── decorator.rs            # DecoratorNormalizer
├── semantics.rs            # SemanticDeriver
├── queries.rs              # QueryEngine
├── n_plus_one.rs           # N+1 detection
├── taint_integration.rs    # Taint sink extraction
└── storage.rs              # SQLite persistence
```

---

## 18. Risk Register

| # | Risk | Impact | Likelihood | Mitigation |
|---|------|--------|------------|------------|
| R1 | 20 ORM matcher port is large effort (~500-1000 lines each) | Medium | High | Prioritize by usage: Prisma/Django/SQLAlchemy first. Shared CallChainExtractor reduces per-matcher LOC. |
| R2 | Call chain extraction misses language-specific patterns | High | Medium | Per-language test suites with real-world code samples. Fallback to raw expression text for unrecognized patterns. |
| R3 | Framework detection false positives (import regex too broad) | Medium | Medium | Require multiple signals (import + decorator) for high confidence. Single signal = lower confidence. |
| R4 | Decorator normalization loses framework-specific nuance | Medium | Low | Framework-specific arg extractors preserve all arguments. Unknown decorators get generic extraction. |
| R5 | N+1 detection false positives (query in loop is intentional) | Medium | Medium | Configurable severity. Check for bulk query before loop. Allow suppression via comment/config. |
| R6 | LINQ query syntax (C#) is hard to extract as call chains | Medium | High | Implement LINQ as a special case in CSharpNormalizer. Convert query syntax to method syntax internally. |
| R7 | Python decorator argument parsing is complex (nested calls, kwargs) | Medium | Medium | Use tree-sitter AST for argument extraction, not regex. Handle common patterns, fallback to raw text. |
| R8 | Matcher priority ordering may miss secondary patterns | Low | Low | `match_chain_all()` available for comprehensive analysis. Default first-match is correct for most use cases. |
| R9 | SQLx compile-time macros require special handling | Medium | Medium | Extract SQL string from macro invocation. Parse SQL for table/operation. Confidence slightly lower for macro patterns. |
| R10 | New framework patterns (Express, Flask, etc.) need validation | Low | Low | Test against real-world projects. Start with high-confidence patterns only. |
| R11 | Memory usage for large projects with many ORM patterns | Medium | Low | SQLite persistence. In-memory only for current scan. Query on demand via NAPI. |
| R12 | Incremental analysis invalidation for ULP results | Medium | Medium | Content-hash based cache. Invalidate file's ULP results when content changes. Cross-file queries re-run from SQLite. |

---

*End of Unified Language Provider V2 Implementation Prep.*
*Sections 1-4: Architecture, v1 inventory, v2 design, data model.*
*Sections 5-7: 9 normalizers, 20 matchers, framework registry, decorator normalization.*
*Sections 8-9: Query engine, pipeline integration, boundary/taint/N+1 integration.*
*Sections 10-13: Storage, NAPI, events, tracing.*
*Sections 14-18: Performance, build order, cross-reference, inconsistencies, risks.*
*Every v1 feature accounted for. 37 features preserved, 4 compatibility shims dropped.*
*20+ new features added. Zero functional loss. Build-ready.*
