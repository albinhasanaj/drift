# Boundary Detection — V2 Implementation Prep

> Comprehensive build specification for Drift v2's Boundary Detection subsystem.
> Synthesized from: 21-security/overview.md, 21-security/boundary-scanner.md,
> 21-security/learning.md, 21-security/types.md, DRIFT-V2-FULL-SYSTEM-AUDIT.md
> (Cat 01, Cat 21, A6, A18), DRIFT-V2-STACK-HIERARCHY.md (Level 1 Skeleton),
> PLANNING-DRIFT.md (D1-D7), 05-analyzers/unified-provider.md,
> 01-rust-core/boundaries.md, 01-rust-core/reachability.md,
> .research/21-security/RECOMMENDATIONS.md (SAD1-SAD4, SE1-SE10, TA1-TA8,
> OR1-OR5, BR1-BR4), .research/05-analyzers/RECOMMENDATIONS.md (R3, R6, R8),
> 03-NAPI-BRIDGE-V2-PREP.md (§10.7 Boundary Functions), 02-STORAGE-V2-PREP.md,
> existing v1 implementations (packages/core/src/boundaries/,
> packages/core/src/unified-provider/, crates/drift-core/src/boundaries/),
> and internet research on ORM landscape (2025-2026).
>
> Purpose: Everything needed to build boundary detection from scratch. Decisions
> resolved, inconsistencies flagged, interface contracts defined, build order
> specified. 100% v1 feature coverage verified with v2 upgrades documented.
> Generated: 2026-02-07

---

## 1. Architectural Position

Boundary Detection is Level 1 Structural Skeleton. It sits between the parsers (Level 0)
and the security intelligence layer (Level 2D). It is the foundation for all data access
awareness in Drift — without it, there is no sensitive field classification, no boundary
enforcement, no taint sink registry, no N+1 detection, and no security quality gate.

Per DRIFT-V2-STACK-HIERARCHY.md:
- Downstream consumers: Security, taint (sinks), reachability (sensitivity), constraints
  (data_flow), quality gates (security gate), N+1 detection, contract extraction
- Upstream dependencies: Parsers (Level 0), Unified Language Provider (Level 1)

Per PLANNING-DRIFT.md D1: Drift is standalone. Boundary detection depends only on drift-core.
Per PLANNING-DRIFT.md D6: All boundary data lives in drift.db. No Cortex dependency.

### What Lives Here
- Two-phase learn-then-detect architecture (proven by v1)
- 33+ ORM framework detection across 9 languages (28 from v1 + 5 new)
- 10 dedicated field extractors (7 from v1 + 3 new)
- Unified Language Provider: 9 language normalizers + 22 ORM/framework matchers
- Sensitive field detection: 4 categories (PII, Credentials, Financial, Health)
- False positive filtering pipeline (6 filter types)
- Confidence scoring with transparent breakdown (5 weighted factors)
- Boundary rule engine: per-table allowed/denied files, operations, auth requirements
- Boundary violation detection and reporting
- Data access map generation (aggregate view of all data access)
- Security tier classification (Critical/High/Medium/Low)
- Unsafe ORM API detection (raw SQL bypass patterns per framework)
- Field-level data flow tracking (7 transformation types)

### What Does NOT Live Here
- Taint analysis engine (Level 2B — consumes boundary sinks)
- Reachability analysis (Level 2B — consumes sensitivity classification)
- Secret detection (Level 2D — separate subsystem)
- Security quality gate evaluation (Level 3 — consumes boundary violations)
- MCP tool routing (Level 5 — presentation layer)
- Any Cortex integration (bridge crate only)

---

## 2. Resolved Inconsistency: v1 Split Architecture → v2 Unified Rust

### The v1 Problem

v1 boundary detection was split across two implementations:

**Rust (crates/drift-core/src/boundaries/)** — 4 files:
- `detector.rs` — Basic data access point detection from AST
- `sensitive.rs` — Sensitive field pattern matching
- `types.rs` — Core types (DataAccessPoint, SensitiveField, ORMModel)
- `mod.rs` — Module exports

**TypeScript (packages/core/src/boundaries/)** — 12+ files:
- `boundary-scanner.ts` — Two-phase learn-then-detect orchestration
- `data-access-learner.ts` — Framework/table/convention learning
- `boundary-store.ts` — Persistence (JSON shards)
- `security-prioritizer.ts` — Risk scoring and tier classification
- `table-name-validator.ts` — Table name validation
- `field-extractors/` — 7 ORM-specific extractors (Prisma, Django, SQLAlchemy,
  Supabase, GORM, Diesel, Raw SQL)

**TypeScript (packages/core/src/unified-provider/)** — 25+ files:
- 9 language normalizers (TS, JS, Python, Java, C#, PHP, Go, Rust, C++)
- 20 ORM/framework matchers
- Integration layer (unified-scanner, adapter, provider)
- Legacy compatibility layer

This split caused:
1. Redundant detection logic (Rust detected basic patterns, TS re-detected with more context)
2. Two serialization boundaries (Rust→NAPI→TS for basic detection, then TS did the real work)
3. Field extractors only in TS (Rust couldn't extract ORM-specific fields)
4. Learning phase only in TS (Rust had no learning capability)
5. ~3,500 lines of TS code that should have been Rust

### The v2 Resolution

**Everything moves to Rust.** The entire boundary detection pipeline — learning, detection,
field extraction, sensitivity classification, validation, prioritization — runs in Rust.
TS is presentation only (MCP tool formatting, CLI output).

This is consistent with AD1 (Rust does all analysis) and the audit's directive:
"Boundary scanning is I/O + regex heavy — Rust gives 10-50x speedup."

```
v1: Rust (basic) → NAPI → TS (learning + extractors + scoring + storage)
v2: Rust (everything) → drift.db → NAPI (summary) → TS (presentation)
```

---

## 3. Two-Phase Architecture: Learn-Then-Detect (Preserved from v1)

The learn-then-detect pattern is v1's best architectural decision for boundary detection.
It reduces false positives by basing detection on YOUR codebase's actual patterns, not
hardcoded assumptions. v2 preserves this architecture entirely, moving it to Rust.

### Phase 1: LEARN (DataAccessLearner)

Scans the codebase to discover:

| Aspect | How | v1 Status | v2 Status |
|--------|-----|-----------|-----------|
| Frameworks used | ORM import/decorator/usage pattern detection | TS only | Rust (tree-sitter) |
| Table names | Model definitions, query strings, schema files | TS only | Rust (tree-sitter + regex) |
| Naming conventions | Analyze table names → snake_case/camelCase/PascalCase/mixed | TS only | Rust |
| Variable patterns | Map variable names to tables (userRepo → users) | TS only | Rust |
| Access patterns | Record which files access which tables | TS only | Rust |
| Schema files | Parse schema.prisma, models.py, migrations/ | TS only | Rust (dedicated parsers) |

### Phase 2: DETECT (BoundaryScanner)

Using learned patterns + regex fallback:

1. For each source file:
   a. Check if it's a data access file (ORM patterns present)
   b. Run Unified Language Provider (normalize AST → UnifiedCallChain)
   c. Run ORM-specific matchers on normalized chains
   d. Run field extractors for detected frameworks
   e. Extract data access points (table, fields, operation, confidence)
   f. Detect sensitive fields
   g. Detect unsafe ORM API usage (raw SQL bypass)
2. Aggregate into BoundaryScanResult
3. Write to drift.db (boundaries, sensitive_fields, boundary_rules tables)
4. Return lightweight BoundariesSummary via NAPI

### Why Learn-Then-Detect Matters

Without learning: Drift assumes every project uses every ORM. Detection runs 33+ framework
matchers on every file. False positive rate: ~15-25%.

With learning: Drift discovers your project uses Prisma + Supabase. Detection runs only
those 2 matchers (plus raw SQL fallback). False positive rate: ~3-5%.

The learning phase adds ~200ms to the first scan but saves significant time on detection
and dramatically improves precision.

---

## 4. ORM Framework Coverage: 33+ Frameworks, 9 Languages

### v1 Coverage (28 frameworks, 8 languages)

| Language | Frameworks | Count |
|----------|-----------|-------|
| C# | EF Core, Dapper | 2 |
| Python | Django, SQLAlchemy, Tortoise, Peewee | 4 |
| TypeScript/JS | Prisma, TypeORM, Sequelize, Drizzle, Knex, Mongoose, Supabase | 7 |
| Java | Spring Data, Hibernate, jOOQ, MyBatis | 4 |
| PHP | Eloquent, Doctrine | 2 |
| Go | GORM, sqlx, Ent, Bun | 4 |
| Rust | Diesel, SeaORM, tokio-postgres, rusqlite | 4 |
| Generic | Raw SQL | 1 |
| **Total** | | **28** |

### v2 Additions (5 new frameworks)

| Language | New Framework | Rationale |
|----------|--------------|-----------|
| TypeScript/JS | MikroORM | Top 5 TS ORM by adoption (2025-2026), Data Mapper pattern |
| TypeScript/JS | Kysely | Rising SQL-first query builder, type-safe, growing fast |
| Go | sqlc | SQL code generator, ~16K GitHub stars, generates type-safe Go |
| Go | SQLBoiler | Schema-first code generator, popular in production Go |
| C++ | Qt SQL | Primary C++ database access framework |

### v2 Total: 33 Frameworks, 9 Languages

| Language | Frameworks | Count |
|----------|-----------|-------|
| C# | EF Core, Dapper | 2 |
| Python | Django, SQLAlchemy, Tortoise, Peewee | 4 |
| TypeScript/JS | Prisma, TypeORM, Sequelize, Drizzle, Knex, Mongoose, Supabase, MikroORM, Kysely | 9 |
| Java | Spring Data, Hibernate, jOOQ, MyBatis | 4 |
| PHP | Eloquent, Doctrine | 2 |
| Go | GORM, sqlx, Ent, Bun, sqlc, SQLBoiler | 6 |
| Rust | Diesel, SeaORM, tokio-postgres, rusqlite | 4 |
| C++ | Qt SQL | 1 |
| Generic | Raw SQL | 1 |
| **Total** | | **33** |

### Framework Detection Signatures (Rust)

Each framework has a detection signature used during the LEARN phase:

```rust
pub struct FrameworkSignature {
    pub name: &'static str,
    pub language: Language,
    /// Import patterns that indicate this framework is used
    pub import_patterns: &'static [&'static str],
    /// Decorator/attribute patterns
    pub decorator_patterns: &'static [&'static str],
    /// Usage patterns in code (method calls, type references)
    pub usage_patterns: &'static [&'static str],
    /// Config/schema file patterns (e.g., schema.prisma, models.py)
    pub schema_files: &'static [&'static str],
}
```

Example signatures:

```rust
const PRISMA_SIGNATURE: FrameworkSignature = FrameworkSignature {
    name: "prisma",
    language: Language::TypeScript,
    import_patterns: &["@prisma/client", "PrismaClient"],
    decorator_patterns: &[],
    usage_patterns: &["prisma.", "PrismaClient", "$queryRaw", "$executeRaw"],
    schema_files: &["schema.prisma", "prisma/schema.prisma"],
};

const DJANGO_SIGNATURE: FrameworkSignature = FrameworkSignature {
    name: "django",
    language: Language::Python,
    import_patterns: &["django.db", "from django.db import models"],
    decorator_patterns: &[],
    usage_patterns: &["models.Model", "models.CharField", "models.ForeignKey",
                       ".objects.", ".filter(", ".exclude(", ".aggregate("],
    schema_files: &["models.py", "*/models.py", "*/models/*.py"],
};

const GORM_SIGNATURE: FrameworkSignature = FrameworkSignature {
    name: "gorm",
    language: Language::Go,
    import_patterns: &["gorm.io/gorm", "gorm.io/driver/"],
    decorator_patterns: &[],
    usage_patterns: &["gorm.Model", "db.Where", "db.Find", "db.Create",
                       "db.First", "db.Save", "db.Delete"],
    schema_files: &[],
};

const MIKROORM_SIGNATURE: FrameworkSignature = FrameworkSignature {
    name: "mikroorm",
    language: Language::TypeScript,
    import_patterns: &["@mikro-orm/core", "@mikro-orm/postgresql",
                        "@mikro-orm/mysql", "@mikro-orm/sqlite"],
    decorator_patterns: &["@Entity", "@Property", "@ManyToOne",
                           "@OneToMany", "@ManyToMany"],
    usage_patterns: &["em.find", "em.findOne", "em.persist",
                       "em.flush", "em.create", "EntityManager"],
    schema_files: &["mikro-orm.config.ts", "mikro-orm.config.js"],
};

const KYSELY_SIGNATURE: FrameworkSignature = FrameworkSignature {
    name: "kysely",
    language: Language::TypeScript,
    import_patterns: &["kysely"],
    decorator_patterns: &[],
    usage_patterns: &["db.selectFrom", "db.insertInto", "db.updateTable",
                       "db.deleteFrom", "Kysely<", ".where(", ".execute()"],
    schema_files: &[],
};

const SQLC_SIGNATURE: FrameworkSignature = FrameworkSignature {
    name: "sqlc",
    language: Language::Go,
    import_patterns: &[],
    decorator_patterns: &[],
    usage_patterns: &["Queries", "New("],  // sqlc generates a Queries struct
    schema_files: &["sqlc.yaml", "sqlc.yml", "query.sql", "queries/*.sql"],
};
```

---

## 5. Unified Language Provider (Rust Port)

The Unified Language Provider is the extraction engine that normalizes language-specific
AST into a universal representation for ORM pattern matching. v1 had this entirely in TS.
v2 ports it to Rust with the same architecture.

### Architecture

```
UnifiedLanguageProvider (Rust)
├── Normalizer Registry  → 9 language normalizers (AST → UnifiedCallChain)
├── Matcher Registry     → 22 ORM/framework matchers (chain → DataAccessPoint)
└── Integration          → Single-pass: parse + normalize + match
```

### UnifiedCallChain: The Universal Representation

Every language normalizer produces `UnifiedCallChain` — a sequence of method calls
that represents a data access operation regardless of language syntax.

```rust
/// A normalized chain of method calls representing a data access operation.
/// Example: supabase.from('users').select('*').eq('id', userId)
/// becomes: [from("users"), select("*"), eq("id", <param>)]
#[derive(Debug, Clone)]
pub struct UnifiedCallChain {
    /// The receiver object (e.g., "supabase", "prisma", "db")
    pub receiver: String,
    /// Ordered sequence of method calls
    pub calls: Vec<ChainCall>,
    /// Source location
    pub location: Location,
    /// Detected language
    pub language: Language,
}

#[derive(Debug, Clone)]
pub struct ChainCall {
    /// Method name (e.g., "from", "select", "where", "eq")
    pub method: String,
    /// Arguments (string literals extracted, variables as placeholders)
    pub args: Vec<CallArg>,
}

#[derive(Debug, Clone)]
pub enum CallArg {
    /// String literal value (e.g., table name, field name)
    StringLiteral(String),
    /// Numeric literal
    NumberLiteral(f64),
    /// Variable reference (name only, not resolved)
    Variable(String),
    /// Nested call chain (e.g., subquery)
    NestedChain(Box<UnifiedCallChain>),
    /// Array of arguments
    Array(Vec<CallArg>),
    /// Object literal with key-value pairs
    Object(Vec<(String, CallArg)>),
    /// Unknown/complex expression
    Unknown,
}
```

### Language Normalizers (9 — Rust Traits)

```rust
/// Trait implemented by each language normalizer.
/// Converts language-specific AST nodes into UnifiedCallChain.
pub trait LanguageNormalizer: Send + Sync {
    /// The language this normalizer handles
    fn language(&self) -> Language;

    /// Extract call chains from a parsed file's AST
    fn extract_chains(
        &self,
        tree: &tree_sitter::Tree,
        source: &[u8],
    ) -> Vec<UnifiedCallChain>;

    /// Extract ORM model definitions (class/struct with DB annotations)
    fn extract_models(
        &self,
        tree: &tree_sitter::Tree,
        source: &[u8],
    ) -> Vec<RawModelDefinition>;
}
```

| Normalizer | Language | Key Extraction Patterns |
|-----------|----------|------------------------|
| TypeScriptNormalizer | TS/JS | Method chains, decorator models, template literals |
| PythonNormalizer | Python | Method chains, class-based models, f-strings |
| JavaNormalizer | Java | Method chains, annotation-based models, JPQL strings |
| CSharpNormalizer | C# | LINQ chains, attribute-based models, lambda expressions |
| PhpNormalizer | PHP | Method chains (->), Eloquent models, raw queries |
| GoNormalizer | Go | Method chains (.), struct tag models, SQL strings |
| RustNormalizer | Rust | Method chains (.), macro-based models (diesel::table!) |
| CppNormalizer | C++ | Method chains (. and ->), Qt SQL patterns |
| BaseNormalizer | Fallback | Regex-based extraction for unknown patterns |

### ORM/Framework Matchers (22 — Rust Traits)

```rust
/// Trait implemented by each ORM matcher.
/// Analyzes UnifiedCallChain to detect data access patterns.
pub trait OrmMatcher: Send + Sync {
    /// The ORM framework this matcher handles
    fn framework(&self) -> &'static str;

    /// Languages this matcher applies to
    fn languages(&self) -> &[Language];

    /// Check if a call chain matches this ORM's patterns
    fn matches(&self, chain: &UnifiedCallChain) -> Option<DataAccessMatch>;

    /// Extract table name from a matched chain
    fn extract_table(&self, chain: &UnifiedCallChain) -> Option<String>;

    /// Extract field names from a matched chain
    fn extract_fields(&self, chain: &UnifiedCallChain) -> Vec<String>;

    /// Extract the data operation type
    fn extract_operation(&self, chain: &UnifiedCallChain) -> DataOperation;

    /// Detect unsafe API usage (raw SQL bypass)
    fn detect_unsafe_api(&self, chain: &UnifiedCallChain) -> Option<UnsafeApiUsage>;
}
```

v2 matchers (22 total — 20 from v1 + 2 new):

| Matcher | Framework | Languages | New in v2? |
|---------|-----------|-----------|------------|
| PrismaMatcher | Prisma | TS/JS | No |
| TypeOrmMatcher | TypeORM | TS/JS | No |
| SequelizeMatcher | Sequelize | TS/JS | No |
| DrizzleMatcher | Drizzle | TS/JS | No |
| KnexMatcher | Knex | TS/JS | No |
| MongooseMatcher | Mongoose | TS/JS | No |
| SupabaseMatcher | Supabase | TS/JS | No |
| MikroOrmMatcher | MikroORM | TS/JS | **Yes** |
| KyselyMatcher | Kysely | TS/JS | **Yes** |
| DjangoMatcher | Django ORM | Python | No |
| SqlAlchemyMatcher | SQLAlchemy | Python | No |
| EfCoreMatcher | EF Core | C# | No |
| EloquentMatcher | Eloquent | PHP | No |
| SpringDataMatcher | Spring Data | Java | No |
| GormMatcher | GORM | Go | No |
| DieselMatcher | Diesel | Rust | No |
| SeaOrmMatcher | SeaORM | Rust | No |
| SqlxMatcher | SQLx | Go/Rust | No |
| DatabaseSqlMatcher | database/sql | Go | No |
| RawSqlMatcher | Raw SQL | All | No |
| SqlcMatcher | sqlc | Go | **Yes** (detection only) |
| SqlBoilerMatcher | SQLBoiler | Go | **Yes** (detection only) |

Note: sqlc and SQLBoiler are code generators — they produce Go code from SQL schemas.
The matchers detect the generated code patterns (Queries struct, model types) rather than
the SQL files themselves. Schema file detection happens in the LEARN phase.

---

## 6. Dedicated Field Extractors: 10 Extractors (7 v1 + 3 New)

Field extractors parse ORM-specific model definitions to extract table names, field names,
field types, and relationships. They are more precise than generic chain matching because
they understand the schema definition language of each ORM.

### v1 Field Extractors (7)

| Extractor | ORM | What It Extracts |
|-----------|-----|-----------------|
| PrismaExtractor | Prisma | Models, fields, relations from schema.prisma |
| DjangoExtractor | Django | Models, CharField, ForeignKey, Meta.db_table |
| SqlAlchemyExtractor | SQLAlchemy | Declarative models, Column types, __tablename__ |
| SupabaseExtractor | Supabase | Table references from .from() calls, RPC calls |
| GormExtractor | GORM | Go struct tags (gorm:"column:name"), table names |
| DieselExtractor | Diesel | table! macro declarations, schema.rs |
| RawSqlExtractor | Raw SQL | SELECT/INSERT/UPDATE/DELETE column parsing |

### v2 New Field Extractors (3)

| Extractor | ORM | What It Extracts | Rationale |
|-----------|-----|-----------------|-----------|
| EfCoreExtractor | EF Core | DbSet<T>, [Table], [Column], Fluent API | From .research/21-security RECOMMENDATIONS OR5: "Add dedicated field extractors for Java, C#, PHP" |
| HibernateExtractor | Hibernate/Spring Data | @Entity, @Table, @Column, @JoinColumn | Same OR5 recommendation |
| EloquentExtractor | Eloquent | $table, $fillable, $guarded, $casts, relationships | Same OR5 recommendation |

### Field Extractor Trait (Rust)

```rust
/// Trait for ORM-specific field extraction from schema/model definitions.
/// More precise than generic chain matching — understands schema DSL.
pub trait FieldExtractor: Send + Sync {
    /// The ORM framework this extractor handles
    fn framework(&self) -> &'static str;

    /// File patterns that may contain model definitions
    /// (e.g., "schema.prisma", "models.py", "*.entity.ts")
    fn schema_file_patterns(&self) -> &[&str];

    /// Extract model definitions from a file's AST
    fn extract_models(
        &self,
        tree: &tree_sitter::Tree,
        source: &[u8],
        file_path: &Path,
    ) -> Vec<ExtractedModel>;
}

/// A model definition extracted by a field extractor
#[derive(Debug, Clone)]
pub struct ExtractedModel {
    /// Model/class name (e.g., "User", "Order")
    pub name: String,
    /// Database table name (explicit or inferred from model name)
    pub table_name: String,
    /// How the table name was determined
    pub table_name_source: TableNameSource,
    /// Fields with types and metadata
    pub fields: Vec<ExtractedField>,
    /// Relationships to other models
    pub relationships: Vec<ExtractedRelationship>,
    /// Source location
    pub location: Location,
    /// Framework that defined this model
    pub framework: &'static str,
    /// Extraction confidence
    pub confidence: f32,
}

#[derive(Debug, Clone)]
pub enum TableNameSource {
    /// Explicitly set (e.g., @Table("users"), __tablename__ = "users")
    Explicit,
    /// Inferred from model name (e.g., User → users)
    InferredFromModelName,
    /// From schema file (e.g., schema.prisma model User)
    SchemaFile,
    /// From migration file
    Migration,
}

#[derive(Debug, Clone)]
pub struct ExtractedField {
    /// Field name as declared in code
    pub name: String,
    /// Database column name (may differ from field name)
    pub column_name: Option<String>,
    /// Field type (language-specific string, e.g., "String", "Integer")
    pub field_type: String,
    /// Whether this field is a primary key
    pub is_primary_key: bool,
    /// Whether this field is nullable
    pub is_nullable: bool,
    /// Whether this field has a unique constraint
    pub is_unique: bool,
    /// Whether this field has a default value
    pub has_default: bool,
    /// Sensitivity classification (if detectable from type/name)
    pub sensitivity: Option<SensitivityType>,
}

#[derive(Debug, Clone)]
pub struct ExtractedRelationship {
    /// Relationship type
    pub kind: RelationshipKind,
    /// Target model name
    pub target_model: String,
    /// Foreign key field (if applicable)
    pub foreign_key: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum RelationshipKind {
    OneToOne,
    OneToMany,
    ManyToOne,
    ManyToMany,
}
```


### Extractor Implementation Examples

**PrismaExtractor** — Parses schema.prisma files (not tree-sitter, custom parser):
```rust
impl FieldExtractor for PrismaExtractor {
    fn framework(&self) -> &'static str { "prisma" }
    fn schema_file_patterns(&self) -> &[&str] {
        &["schema.prisma", "prisma/schema.prisma", "*/schema.prisma"]
    }

    fn extract_models(&self, _tree: &Tree, source: &[u8], _path: &Path) -> Vec<ExtractedModel> {
        // Prisma schema is not a programming language — use regex-based parser
        // Pattern: model ModelName { ... }
        let source_str = std::str::from_utf8(source).unwrap_or("");
        let mut models = Vec::new();

        for model_match in PRISMA_MODEL_RE.captures_iter(source_str) {
            let name = model_match.get(1).unwrap().as_str();
            let body = model_match.get(2).unwrap().as_str();
            let fields = self.parse_prisma_fields(body);
            let relationships = self.parse_prisma_relations(body);

            models.push(ExtractedModel {
                name: name.to_string(),
                table_name: self.infer_table_name(name, body),
                table_name_source: if body.contains("@@map(") {
                    TableNameSource::Explicit
                } else {
                    TableNameSource::SchemaFile
                },
                fields,
                relationships,
                location: Location { /* ... */ },
                framework: "prisma",
                confidence: 0.95,
            });
        }
        models
    }
}
```

**EfCoreExtractor** (NEW in v2) — Parses C# entity classes:
```rust
impl FieldExtractor for EfCoreExtractor {
    fn framework(&self) -> &'static str { "efcore" }
    fn schema_file_patterns(&self) -> &[&str] {
        &["*.cs"]  // Any C# file may contain entities
    }

    fn extract_models(&self, tree: &Tree, source: &[u8], _path: &Path) -> Vec<ExtractedModel> {
        // Tree-sitter query for C# classes with [Table] attribute or DbSet<T> references
        // Pattern 1: [Table("users")] public class User { ... }
        // Pattern 2: public DbSet<User> Users { get; set; }
        // Pattern 3: Fluent API: modelBuilder.Entity<User>(e => { e.ToTable("users"); })
        let mut models = Vec::new();

        // Query for classes with [Table] attribute
        let query = tree_sitter::Query::new(
            tree.language(),
            r#"
            (class_declaration
                (attribute_list
                    (attribute name: (identifier) @attr_name
                        (#eq? @attr_name "Table")
                        (attribute_argument_list
                            (attribute_argument (string_literal) @table_name))))
                name: (identifier) @class_name
                body: (declaration_list) @body)
            "#,
        );
        // ... extract fields from properties with [Column] attributes
        models
    }
}
```

**HibernateExtractor** (NEW in v2) — Parses Java entity classes:
```rust
impl FieldExtractor for HibernateExtractor {
    fn framework(&self) -> &'static str { "hibernate" }
    fn schema_file_patterns(&self) -> &[&str] {
        &["*.java"]
    }

    fn extract_models(&self, tree: &Tree, source: &[u8], _path: &Path) -> Vec<ExtractedModel> {
        // Tree-sitter query for Java classes with @Entity annotation
        // Pattern: @Entity @Table(name = "users") public class User { ... }
        // Extract: @Column(name = "email"), @Id, @GeneratedValue, @JoinColumn
        let mut models = Vec::new();
        // ... implementation using tree-sitter Java grammar
        models
    }
}
```

---

## 7. Sensitive Field Detection (Expanded)

### v1 Pattern Coverage

v1 had pattern-based detection with 4 sensitivity categories. v2 preserves all patterns
and expands coverage per .research/21-security RECOMMENDATIONS CP1.

### Sensitivity Categories & Patterns

```rust
/// Sensitivity classification for detected fields
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SensitivityType {
    Pii,
    Credentials,
    Financial,
    Health,
}

/// A sensitive field pattern with specificity scoring
pub struct SensitiveFieldPattern {
    /// Pattern to match against field/column names (case-insensitive)
    pub pattern: &'static str,
    /// Sensitivity category
    pub sensitivity: SensitivityType,
    /// Base specificity score (0.0-1.0). Higher = more confident this is sensitive.
    pub specificity: f32,
    /// Whether this is an exact match or substring match
    pub match_type: MatchType,
}

#[derive(Debug, Clone, Copy)]
pub enum MatchType {
    /// Field name must exactly match (e.g., "ssn")
    Exact,
    /// Field name must contain this substring (e.g., "password")
    Contains,
    /// Field name must match this regex
    Regex,
}
```

### PII Patterns (v1 preserved + v2 expanded)

| Pattern | Specificity | Match Type | v1/v2 |
|---------|------------|------------|-------|
| ssn | 0.95 | Exact | v1 |
| social_security | 0.95 | Contains | v1 |
| social_security_number | 0.95 | Contains | v1 |
| date_of_birth | 0.90 | Contains | v1 |
| dob | 0.85 | Exact | v1 |
| birth_date | 0.90 | Contains | v1 |
| national_id | 0.90 | Contains | v1 |
| passport | 0.90 | Contains | v2 new |
| passport_number | 0.95 | Contains | v2 new |
| drivers_license | 0.90 | Contains | v2 new |
| driver_license | 0.90 | Contains | v2 new |
| phone_number | 0.80 | Contains | v1 |
| phone | 0.65 | Exact | v1 |
| mobile | 0.60 | Exact | v1 |
| email | 0.65 | Exact | v1 |
| email_address | 0.75 | Contains | v1 |
| home_address | 0.85 | Contains | v1 |
| street_address | 0.85 | Contains | v2 new |
| postal_code | 0.70 | Contains | v2 new |
| zip_code | 0.70 | Contains | v2 new |
| full_name | 0.70 | Contains | v1 |
| first_name | 0.55 | Contains | v1 |
| last_name | 0.55 | Contains | v1 |
| middle_name | 0.55 | Contains | v2 new |
| maiden_name | 0.75 | Contains | v2 new |
| gender | 0.50 | Exact | v1 |
| ethnicity | 0.75 | Exact | v2 new |
| race | 0.60 | Exact | v2 new |
| religion | 0.70 | Exact | v2 new |
| ip_address | 0.60 | Contains | v2 new |
| mac_address | 0.55 | Contains | v2 new |
| biometric | 0.90 | Contains | v2 new |
| fingerprint | 0.85 | Contains | v2 new |
| face_id | 0.85 | Contains | v2 new |
| geolocation | 0.70 | Contains | v2 new |
| latitude | 0.55 | Exact | v2 new |
| longitude | 0.55 | Exact | v2 new |

### Credentials Patterns (v1 preserved + v2 expanded)

| Pattern | Specificity | Match Type | v1/v2 |
|---------|------------|------------|-------|
| password_hash | 0.95 | Contains | v1 |
| password_digest | 0.95 | Contains | v1 |
| hashed_password | 0.95 | Contains | v1 |
| encrypted_password | 0.95 | Contains | v1 |
| api_key | 0.90 | Contains | v1 |
| api_secret | 0.95 | Contains | v1 |
| access_token | 0.85 | Contains | v1 |
| refresh_token | 0.85 | Contains | v1 |
| secret_key | 0.90 | Contains | v1 |
| private_key | 0.90 | Contains | v1 |
| password | 0.75 | Exact | v1 |
| passwd | 0.80 | Exact | v1 |
| auth_token | 0.85 | Contains | v1 |
| session_token | 0.80 | Contains | v2 new |
| jwt_secret | 0.95 | Contains | v2 new |
| oauth_token | 0.85 | Contains | v2 new |
| client_secret | 0.90 | Contains | v2 new |
| signing_key | 0.90 | Contains | v2 new |
| encryption_key | 0.90 | Contains | v2 new |
| master_key | 0.95 | Contains | v2 new |
| recovery_code | 0.85 | Contains | v2 new |
| mfa_secret | 0.90 | Contains | v2 new |
| totp_secret | 0.90 | Contains | v2 new |

### Financial Patterns (v1 preserved + v2 expanded)

| Pattern | Specificity | Match Type | v1/v2 |
|---------|------------|------------|-------|
| credit_card | 0.95 | Contains | v1 |
| credit_card_number | 0.95 | Contains | v1 |
| card_number | 0.90 | Contains | v1 |
| cvv | 0.95 | Exact | v1 |
| cvc | 0.90 | Exact | v1 |
| bank_account | 0.90 | Contains | v1 |
| account_number | 0.85 | Contains | v1 |
| routing_number | 0.90 | Contains | v1 |
| salary | 0.85 | Exact | v1 |
| income | 0.80 | Exact | v1 |
| tax_id | 0.90 | Contains | v1 |
| ein | 0.80 | Exact | v2 new |
| iban | 0.90 | Exact | v2 new |
| swift_code | 0.85 | Contains | v2 new |
| bic | 0.80 | Exact | v2 new |
| sort_code | 0.85 | Contains | v2 new |
| payment_method | 0.70 | Contains | v2 new |
| billing_address | 0.75 | Contains | v2 new |
| stripe_customer_id | 0.80 | Contains | v2 new |

### Health Patterns (v1 preserved + v2 expanded)

| Pattern | Specificity | Match Type | v1/v2 |
|---------|------------|------------|-------|
| medical_record | 0.95 | Contains | v1 |
| medical_record_number | 0.95 | Contains | v1 |
| diagnosis | 0.90 | Exact | v1 |
| diagnosis_code | 0.95 | Contains | v1 |
| prescription | 0.90 | Exact | v1 |
| medication | 0.85 | Exact | v1 |
| treatment | 0.80 | Exact | v1 |
| blood_type | 0.90 | Contains | v1 |
| allergy | 0.85 | Exact | v2 new |
| allergies | 0.85 | Exact | v2 new |
| insurance_id | 0.85 | Contains | v2 new |
| insurance_number | 0.85 | Contains | v2 new |
| patient_id | 0.80 | Contains | v2 new |
| health_condition | 0.85 | Contains | v2 new |
| disability | 0.85 | Exact | v2 new |
| mental_health | 0.90 | Contains | v2 new |
| genetic_data | 0.95 | Contains | v2 new |
| dna_sample | 0.95 | Contains | v2 new |

### False Positive Filtering Pipeline (6 Filters)

v1 had basic false positive filtering. v2 formalizes it as a pipeline of 6 filters,
each reducing confidence or eliminating the match entirely.

```rust
pub struct FalsePositiveFilter;

impl FalsePositiveFilter {
    /// Apply all filters to a candidate sensitive field detection.
    /// Returns adjusted confidence (0.0 = filtered out entirely).
    pub fn apply(
        &self,
        field_name: &str,
        context: &DetectionContext,
        base_confidence: f32,
    ) -> f32 {
        let mut confidence = base_confidence;

        // Filter 1: Function name context
        // "validatePassword", "checkEmail" → not actual sensitive data
        if context.is_function_name {
            confidence *= 0.3;
        }

        // Filter 2: Import statement context
        // "import { password } from 'config'" → not sensitive data
        if context.is_import {
            confidence = 0.0;
            return confidence;
        }

        // Filter 3: Comment context
        // "// TODO: add password validation" → not sensitive data
        if context.is_comment {
            confidence = 0.0;
            return confidence;
        }

        // Filter 4: Mock/test/dummy prefix
        // "mockPassword", "testEmail", "dummySSN" → test data
        if context.has_test_prefix {
            confidence *= 0.2;
        }

        // Filter 5: Health check false positive
        // "health_check", "health_endpoint", "healthz" → not health data
        if field_name.contains("health_check")
            || field_name.contains("health_endpoint")
            || field_name.contains("healthz")
            || field_name.contains("health_status")
        {
            confidence = 0.0;
            return confidence;
        }

        // Filter 6: Common non-sensitive homonyms
        // "password_policy", "email_template", "card_layout" → not sensitive
        if self.is_non_sensitive_compound(field_name) {
            confidence *= 0.3;
        }

        confidence
    }

    fn is_non_sensitive_compound(&self, name: &str) -> bool {
        const NON_SENSITIVE_SUFFIXES: &[&str] = &[
            "_policy", "_template", "_layout", "_format", "_pattern",
            "_validator", "_checker", "_verifier", "_handler", "_manager",
            "_service", "_controller", "_middleware", "_config", "_setting",
            "_length", "_strength", "_requirement", "_rule", "_regex",
        ];
        NON_SENSITIVE_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
    }
}
```

---

## 8. Confidence Scoring (Transparent Breakdown)

Every data access detection includes a transparent confidence breakdown explaining WHY
the detection was made. This is critical for developer trust and for the feedback loop.

### v1 Confidence Formula (Preserved)

```
confidence = tableNameFound(0.3) + fieldsFound(0.2) + operationClear(0.2)
           + frameworkMatched(0.2) + fromLiteral(0.1)
```

Weights sum to 1.0. Each factor is binary (0 or weight value).

### v2 Confidence Types

```rust
/// Transparent confidence breakdown for a data access detection
#[derive(Debug, Clone)]
pub struct ConfidenceBreakdown {
    /// Was a table name found? (0.3 weight)
    pub table_name_found: bool,
    /// Were field names found? (0.2 weight)
    pub fields_found: bool,
    /// Was the operation type clear? (0.2 weight)
    pub operation_clear: bool,
    /// Was a known framework matched? (0.2 weight)
    pub framework_matched: bool,
    /// Was the table name from a string literal (vs variable)? (0.1 weight)
    pub from_literal: bool,
    /// Individual factor scores
    pub factors: ConfidenceFactors,
    /// Human-readable explanation
    pub explanation: String,
}

#[derive(Debug, Clone)]
pub struct ConfidenceFactors {
    pub table_name: f32,    // 0.0 or 0.3
    pub fields: f32,        // 0.0 or 0.2
    pub operation: f32,     // 0.0 or 0.2
    pub framework: f32,     // 0.0 or 0.2
    pub literal: f32,       // 0.0 or 0.1
}

impl ConfidenceBreakdown {
    pub fn compute(
        table_name_found: bool,
        fields_found: bool,
        operation_clear: bool,
        framework_matched: bool,
        from_literal: bool,
    ) -> Self {
        let factors = ConfidenceFactors {
            table_name: if table_name_found { 0.3 } else { 0.0 },
            fields: if fields_found { 0.2 } else { 0.0 },
            operation: if operation_clear { 0.2 } else { 0.0 },
            framework: if framework_matched { 0.2 } else { 0.0 },
            literal: if from_literal { 0.1 } else { 0.0 },
        };

        let score = factors.table_name + factors.fields + factors.operation
            + factors.framework + factors.literal;

        let mut parts = Vec::new();
        if table_name_found { parts.push("table name found"); }
        if fields_found { parts.push("fields extracted"); }
        if operation_clear { parts.push("operation identified"); }
        if framework_matched { parts.push("framework matched"); }
        if from_literal { parts.push("from string literal"); }

        Self {
            table_name_found,
            fields_found,
            operation_clear,
            framework_matched,
            from_literal,
            factors,
            explanation: format!(
                "Confidence {:.0}%: {}",
                score * 100.0,
                parts.join(", ")
            ),
        }
    }

    pub fn score(&self) -> f32 {
        self.factors.table_name + self.factors.fields + self.factors.operation
            + self.factors.framework + self.factors.literal
    }
}
```

---

## 9. Unsafe ORM API Detection (New in v2)

From .research/21-security RECOMMENDATIONS OR1: "Detect unsafe ORM API usage per framework
(raw SQL bypass patterns)." This is a critical security feature — ORMs provide safe
parameterized queries, but every ORM has escape hatches that bypass safety.

### Unsafe API Patterns Per Framework

```rust
pub struct UnsafeApiUsage {
    /// The unsafe API method called
    pub method: String,
    /// The framework
    pub framework: &'static str,
    /// Why this is unsafe
    pub reason: &'static str,
    /// CWE mapping
    pub cwe: &'static str,
    /// Severity
    pub severity: Severity,
    /// Safe alternative suggestion
    pub safe_alternative: &'static str,
    /// Location
    pub location: Location,
}
```

| Framework | Unsafe API | Safe Alternative | CWE |
|-----------|-----------|-----------------|-----|
| Prisma | `$queryRaw` | `$queryRaw` with tagged template | CWE-89 |
| Prisma | `$executeRaw` | `$executeRaw` with tagged template | CWE-89 |
| Prisma | `$queryRawUnsafe` | `$queryRaw` with Prisma.sql | CWE-89 |
| Django | `.extra()` | `.annotate()` / `.filter()` | CWE-89 |
| Django | `.raw()` | Parameterized `.raw()` | CWE-89 |
| Django | `RawSQL()` | Django ORM expressions | CWE-89 |
| Django | `cursor.execute()` with string concat | `cursor.execute()` with params | CWE-89 |
| SQLAlchemy | `text()` with string concat | `text()` with `:param` binding | CWE-89 |
| SQLAlchemy | `execute()` with string | `execute()` with bound params | CWE-89 |
| Eloquent | `DB::raw()` | Eloquent query builder | CWE-89 |
| Eloquent | `whereRaw()` with concat | `whereRaw()` with bindings | CWE-89 |
| Eloquent | `selectRaw()` with concat | `selectRaw()` with bindings | CWE-89 |
| Spring Data | `@Query(nativeQuery=true)` + concat | Named parameters `:param` | CWE-89 |
| Hibernate | `createSQLQuery()` + concat | `createQuery()` with params | CWE-89 |
| GORM | `db.Raw()` with concat | `db.Raw()` with `?` params | CWE-89 |
| GORM | `db.Exec()` with concat | `db.Exec()` with `?` params | CWE-89 |
| Knex | `.raw()` with concat | `.raw()` with `?` bindings | CWE-89 |
| Sequelize | `sequelize.query()` with string | `sequelize.query()` with replacements | CWE-89 |
| TypeORM | `.query()` with string | QueryBuilder with parameters | CWE-89 |
| TypeORM | `createQueryBuilder().where(string)` | `.where("col = :val", {val})` | CWE-89 |

### Detection Strategy

The unsafe API detector runs as part of the ORM matcher pipeline. When a matcher identifies
a data access chain, it also checks if the chain uses an unsafe API pattern:

```rust
impl OrmMatcher for PrismaMatcher {
    fn detect_unsafe_api(&self, chain: &UnifiedCallChain) -> Option<UnsafeApiUsage> {
        for call in &chain.calls {
            match call.method.as_str() {
                "$queryRawUnsafe" | "$executeRawUnsafe" => {
                    return Some(UnsafeApiUsage {
                        method: call.method.clone(),
                        framework: "prisma",
                        reason: "Bypasses Prisma's SQL injection protection. \
                                 User input in the query string is not parameterized.",
                        cwe: "CWE-89",
                        severity: Severity::Error,
                        safe_alternative: "Use $queryRaw with Prisma.sql tagged template \
                                           for automatic parameterization",
                        location: chain.location.clone(),
                    });
                }
                "$queryRaw" | "$executeRaw" => {
                    // Check if using tagged template (safe) or string concat (unsafe)
                    if self.uses_string_concatenation(call) {
                        return Some(UnsafeApiUsage {
                            method: call.method.clone(),
                            framework: "prisma",
                            reason: "String concatenation in raw query bypasses parameterization",
                            cwe: "CWE-89",
                            severity: Severity::Warning,
                            safe_alternative: "Use Prisma.sql tagged template literal",
                            location: chain.location.clone(),
                        });
                    }
                }
                _ => {}
            }
        }
        None
    }
}
```


---

## 10. Boundary Rules & Enforcement

Boundary rules define which code is allowed to access which data. They are the enforcement
mechanism that turns data access detection into actionable security findings.

### Rule Definition

```rust
/// A boundary rule defining allowed data access patterns for a table
#[derive(Debug, Clone, Deserialize)]
pub struct BoundaryRule {
    /// Table name this rule applies to
    pub table: String,
    /// Glob patterns for files allowed to access this table
    pub allowed_files: Vec<String>,
    /// Glob patterns for files explicitly denied access (overrides allowed)
    pub denied_files: Vec<String>,
    /// Allowed operations (if empty, all operations allowed)
    pub allowed_operations: Vec<DataOperation>,
    /// Whether access to this table requires authentication context
    pub require_auth: bool,
    /// Severity of violations (default: warning)
    pub violation_severity: Option<Severity>,
    /// Optional description/rationale
    pub description: Option<String>,
}

/// Data operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
pub enum DataOperation {
    Read,
    Write,
    Delete,
    Update,
    Unknown,
}
```

### Rule Sources (3 — Priority Order)

1. **Explicit rules** — User-defined in `drift-boundaries.toml` (highest priority)
2. **Learned rules** — Auto-discovered from codebase patterns (medium priority)
3. **Default rules** — Built-in rules for common sensitive tables (lowest priority)

```toml
# drift-boundaries.toml — User-defined boundary rules

[[rules]]
table = "users"
allowed_files = ["src/repositories/user-*.ts", "src/services/auth-*.ts"]
denied_files = ["src/controllers/**"]
allowed_operations = ["read", "write", "update"]
require_auth = true
description = "User data should only be accessed through repository layer"

[[rules]]
table = "payments"
allowed_files = ["src/services/payment-*.ts", "src/repositories/payment-*.ts"]
require_auth = true
violation_severity = "error"
description = "Payment data is PCI-sensitive — strict access control"

[[rules]]
table = "audit_logs"
allowed_files = ["src/services/audit-*.ts"]
allowed_operations = ["write"]
description = "Audit logs are append-only"
```

### Learned Rules (Auto-Discovery)

During the LEARN phase, the system observes which files access which tables. If a table
is only accessed from a small set of files (≤5), it auto-generates a boundary rule:

```rust
pub fn learn_boundary_rules(
    access_map: &DataAccessMap,
    config: &BoundaryConfig,
) -> Vec<BoundaryRule> {
    let mut rules = Vec::new();

    for (table, access_info) in &access_map.tables {
        let accessing_files: Vec<&str> = access_info.files.iter()
            .map(|f| f.as_str())
            .collect();

        // Only generate rules for tables with focused access patterns
        if accessing_files.len() <= config.max_files_for_auto_rule
            && accessing_files.len() >= config.min_files_for_auto_rule
        {
            // Generate glob patterns from actual file paths
            let patterns = generalize_file_patterns(&accessing_files);

            rules.push(BoundaryRule {
                table: table.clone(),
                allowed_files: patterns,
                denied_files: vec![],
                allowed_operations: vec![], // all operations allowed
                require_auth: access_info.has_sensitive_fields,
                violation_severity: None,
                description: Some(format!(
                    "Auto-learned: {} is accessed from {} files",
                    table, accessing_files.len()
                )),
            });
        }
    }

    rules
}
```

### Violation Detection

```rust
/// A boundary violation — code accessing data outside its allowed boundary
#[derive(Debug, Clone)]
pub struct BoundaryViolation {
    /// The rule that was violated
    pub rule: BoundaryRule,
    /// The data access point that violated the rule
    pub access_point: DataAccessPoint,
    /// Type of violation
    pub violation_type: BoundaryViolationType,
    /// Human-readable message
    pub message: String,
    /// Severity (from rule or default)
    pub severity: Severity,
}

#[derive(Debug, Clone, Copy)]
pub enum BoundaryViolationType {
    /// File is not in the allowed list
    UnauthorizedFile,
    /// Operation is not in the allowed list
    UnauthorizedOperation,
    /// Access requires auth but no auth context detected
    MissingAuth,
    /// File is in the denied list
    ExplicitlyDenied,
}

pub fn check_violations(
    access_points: &[DataAccessPoint],
    rules: &[BoundaryRule],
) -> Vec<BoundaryViolation> {
    let mut violations = Vec::new();

    for point in access_points {
        for rule in rules {
            if rule.table != point.table { continue; }

            // Check denied files first (highest priority)
            if rule.denied_files.iter().any(|p| glob_match(p, &point.file)) {
                violations.push(BoundaryViolation {
                    rule: rule.clone(),
                    access_point: point.clone(),
                    violation_type: BoundaryViolationType::ExplicitlyDenied,
                    message: format!(
                        "File '{}' is explicitly denied access to table '{}'",
                        point.file, point.table
                    ),
                    severity: rule.violation_severity.unwrap_or(Severity::Error),
                });
                continue;
            }

            // Check allowed files
            if !rule.allowed_files.is_empty()
                && !rule.allowed_files.iter().any(|p| glob_match(p, &point.file))
            {
                violations.push(BoundaryViolation {
                    rule: rule.clone(),
                    access_point: point.clone(),
                    violation_type: BoundaryViolationType::UnauthorizedFile,
                    message: format!(
                        "File '{}' is not authorized to access table '{}'",
                        point.file, point.table
                    ),
                    severity: rule.violation_severity.unwrap_or(Severity::Warning),
                });
            }

            // Check allowed operations
            if !rule.allowed_operations.is_empty()
                && !rule.allowed_operations.contains(&point.operation)
            {
                violations.push(BoundaryViolation {
                    rule: rule.clone(),
                    access_point: point.clone(),
                    violation_type: BoundaryViolationType::UnauthorizedOperation,
                    message: format!(
                        "Operation '{:?}' on table '{}' is not allowed from '{}'",
                        point.operation, point.table, point.file
                    ),
                    severity: rule.violation_severity.unwrap_or(Severity::Warning),
                });
            }

            // Check auth requirement
            if rule.require_auth && !point.has_auth_context {
                violations.push(BoundaryViolation {
                    rule: rule.clone(),
                    access_point: point.clone(),
                    violation_type: BoundaryViolationType::MissingAuth,
                    message: format!(
                        "Access to table '{}' requires authentication but none detected in '{}'",
                        point.table, point.file
                    ),
                    severity: rule.violation_severity.unwrap_or(Severity::Warning),
                });
            }
        }
    }

    violations
}
```

---

## 11. Security Tier Classification

The SecurityPrioritizer classifies all boundary findings into 4 tiers for prioritized
reporting. This is pure logic — no external dependencies.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityTier {
    /// Direct access to credentials, financial data, or health records
    Critical = 1,
    /// PII access, health data access
    High = 2,
    /// General data access with some sensitive fields
    Medium = 3,
    /// Standard data access, no sensitive fields detected
    Low = 4,
}

pub fn classify_tier(
    access_point: &DataAccessPoint,
    sensitive_fields: &[SensitiveField],
) -> SecurityTier {
    // Check if any fields in this access point are sensitive
    let sensitivities: Vec<SensitivityType> = sensitive_fields.iter()
        .filter(|sf| {
            sf.table.as_deref() == Some(&access_point.table)
                || access_point.fields.iter().any(|f| f == &sf.field)
        })
        .map(|sf| sf.sensitivity_type)
        .collect();

    if sensitivities.is_empty() {
        return SecurityTier::Low;
    }

    // Highest sensitivity determines tier
    if sensitivities.contains(&SensitivityType::Credentials)
        || sensitivities.contains(&SensitivityType::Financial)
    {
        SecurityTier::Critical
    } else if sensitivities.contains(&SensitivityType::Pii)
        || sensitivities.contains(&SensitivityType::Health)
    {
        SecurityTier::High
    } else {
        SecurityTier::Medium
    }
}

/// Aggregate security summary for the entire codebase
#[derive(Debug, Clone)]
pub struct SecuritySummary {
    pub total_access_points: u32,
    pub total_sensitive_fields: u32,
    pub total_violations: u32,
    pub tier_counts: TierCounts,
    pub top_risks: Vec<SecurityRisk>,
    pub frameworks_detected: Vec<String>,
    pub tables_with_sensitive_data: Vec<String>,
    pub unsafe_api_count: u32,
}

#[derive(Debug, Clone)]
pub struct TierCounts {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
}

#[derive(Debug, Clone)]
pub struct SecurityRisk {
    pub table: String,
    pub tier: SecurityTier,
    pub reason: String,
    pub access_point_count: u32,
    pub violation_count: u32,
}
```

---

## 12. Field-Level Data Flow Tracking (New in v2)

From the audit: "Field-level data flow: track individual fields through call paths
(users.password_hash vs users.display_name), detect transformations."

This is a v2 enhancement that tracks how individual fields are transformed as they
flow through the codebase. It bridges boundary detection and taint analysis.

### 7 Transformation Types

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldTransformation {
    /// Field accessed directly without transformation
    DirectAccess,
    /// Field aggregated (COUNT, SUM, AVG, etc.)
    Aggregation,
    /// Field hashed (bcrypt, sha256, etc.)
    Hashing,
    /// Field encrypted (AES, RSA, etc.)
    Encryption,
    /// Field masked (last 4 digits, email domain only, etc.)
    Masking,
    /// Field concatenated with other data
    Concatenation,
    /// Field filtered/subset (WHERE clause, array filter)
    Filtering,
}

/// Tracks how a specific field flows through the codebase
#[derive(Debug, Clone)]
pub struct FieldFlow {
    /// The field being tracked
    pub field: String,
    /// The table it belongs to
    pub table: String,
    /// Sensitivity classification
    pub sensitivity: Option<SensitivityType>,
    /// Access points where this field is used
    pub access_points: Vec<FieldAccessPoint>,
}

#[derive(Debug, Clone)]
pub struct FieldAccessPoint {
    /// File where the field is accessed
    pub file: String,
    /// Line number
    pub line: u32,
    /// Function containing the access
    pub function: Option<String>,
    /// How the field is transformed at this point
    pub transformation: FieldTransformation,
    /// Whether the transformation reduces sensitivity
    /// (e.g., hashing a password makes it less sensitive)
    pub reduces_sensitivity: bool,
}
```

### Transformation Detection

Transformations are detected by analyzing the call chain context around field access:

```rust
fn detect_transformation(chain: &UnifiedCallChain, field: &str) -> FieldTransformation {
    // Check for aggregation functions
    if chain.calls.iter().any(|c| {
        matches!(c.method.as_str(),
            "count" | "sum" | "avg" | "min" | "max" | "aggregate"
            | "Count" | "Sum" | "Average" | "Min" | "Max"
        )
    }) {
        return FieldTransformation::Aggregation;
    }

    // Check for hashing
    if chain.calls.iter().any(|c| {
        matches!(c.method.as_str(),
            "hash" | "bcrypt" | "sha256" | "sha512" | "md5"
            | "hashSync" | "pbkdf2" | "scrypt" | "argon2"
        )
    }) {
        return FieldTransformation::Hashing;
    }

    // Check for encryption
    if chain.calls.iter().any(|c| {
        matches!(c.method.as_str(),
            "encrypt" | "cipher" | "createCipheriv" | "seal"
            | "Encrypt" | "AES" | "RSA"
        )
    }) {
        return FieldTransformation::Encryption;
    }

    // Check for masking
    if chain.calls.iter().any(|c| {
        matches!(c.method.as_str(),
            "mask" | "redact" | "anonymize" | "obfuscate"
            | "substring" | "slice" | "replace"
        )
    }) {
        return FieldTransformation::Masking;
    }

    // Check for concatenation
    if chain.calls.iter().any(|c| {
        matches!(c.method.as_str(),
            "concat" | "join" | "format" | "interpolate" | "template"
        )
    }) {
        return FieldTransformation::Concatenation;
    }

    // Check for filtering
    if chain.calls.iter().any(|c| {
        matches!(c.method.as_str(),
            "filter" | "where" | "select" | "pick" | "omit" | "exclude"
        )
    }) {
        return FieldTransformation::Filtering;
    }

    FieldTransformation::DirectAccess
}
```

---

## 13. Core Data Types (Complete)

### DataAccessPoint (The Primary Output)

```rust
/// A detected data access point in the codebase
#[derive(Debug, Clone)]
pub struct DataAccessPoint {
    /// Unique identifier (content-addressed hash)
    pub id: String,
    /// Table/collection being accessed
    pub table: String,
    /// Fields being accessed (empty if unknown)
    pub fields: Vec<String>,
    /// Type of operation
    pub operation: DataOperation,
    /// Source file path
    pub file: String,
    /// Line number
    pub line: u32,
    /// Column number
    pub column: u32,
    /// Surrounding code context (for display)
    pub context: String,
    /// Detection confidence (0.0-1.0)
    pub confidence: f32,
    /// Transparent confidence breakdown
    pub confidence_breakdown: ConfidenceBreakdown,
    /// Detected ORM framework
    pub framework: String,
    /// Source language
    pub language: Language,
    /// Whether auth context was detected nearby
    pub has_auth_context: bool,
    /// Security tier classification
    pub security_tier: SecurityTier,
    /// Unsafe API usage (if detected)
    pub unsafe_api: Option<UnsafeApiUsage>,
    /// Field transformations detected
    pub transformations: Vec<(String, FieldTransformation)>,
}
```

### ORMModel

```rust
/// An ORM model definition detected in the codebase
#[derive(Debug, Clone)]
pub struct ORMModel {
    /// Model/class name
    pub name: String,
    /// Database table name (explicit or inferred)
    pub table_name: String,
    /// How the table name was determined
    pub table_name_source: TableNameSource,
    /// Fields defined in the model
    pub fields: Vec<String>,
    /// Source file
    pub file: String,
    /// Line number
    pub line: u32,
    /// ORM framework
    pub framework: String,
    /// Detection confidence
    pub confidence: f32,
}
```

### SensitiveField

```rust
/// A field classified as sensitive
#[derive(Debug, Clone)]
pub struct SensitiveField {
    /// Field/column name
    pub field: String,
    /// Table it belongs to (if known)
    pub table: Option<String>,
    /// Sensitivity category
    pub sensitivity_type: SensitivityType,
    /// Source file where detected
    pub file: String,
    /// Line number
    pub line: u32,
    /// Detection confidence (after false positive filtering)
    pub confidence: f32,
    /// Base specificity from pattern match
    pub base_specificity: f32,
    /// Whether false positive filters reduced confidence
    pub filtered: bool,
}
```

### BoundaryScanResult (Aggregate Output)

```rust
/// Complete result of a boundary scan
#[derive(Debug, Clone)]
pub struct BoundaryScanResult {
    /// All detected data access points
    pub access_points: Vec<DataAccessPoint>,
    /// All detected ORM models
    pub models: Vec<ORMModel>,
    /// All detected sensitive fields
    pub sensitive_fields: Vec<SensitiveField>,
    /// All boundary violations
    pub violations: Vec<BoundaryViolation>,
    /// All unsafe API usages
    pub unsafe_apis: Vec<UnsafeApiUsage>,
    /// Aggregate security summary
    pub security_summary: SecuritySummary,
    /// Scan statistics
    pub stats: BoundaryScanStats,
}

#[derive(Debug, Clone)]
pub struct BoundaryScanStats {
    pub files_scanned: u32,
    pub data_access_files: u32,
    pub total_access_points: u32,
    pub total_models: u32,
    pub total_sensitive_fields: u32,
    pub total_violations: u32,
    pub total_unsafe_apis: u32,
    pub frameworks_detected: Vec<String>,
    pub duration_ms: u32,
}
```

### DataAccessMap (Aggregate View)

```rust
/// Aggregate view of all data access in the codebase
#[derive(Debug, Clone)]
pub struct DataAccessMap {
    /// Project root
    pub project_root: String,
    /// Per-table access information
    pub tables: FxHashMap<String, TableAccessInfo>,
    /// Per-file access information
    pub files: FxHashMap<String, FileAccessInfo>,
    /// All ORM models
    pub models: Vec<ORMModel>,
    /// All sensitive fields
    pub sensitive_fields: Vec<SensitiveField>,
    /// Aggregate statistics
    pub stats: AccessMapStats,
}

#[derive(Debug, Clone)]
pub struct TableAccessInfo {
    /// Files that access this table
    pub files: Vec<String>,
    /// Operations performed on this table
    pub operations: Vec<DataOperation>,
    /// Fields accessed
    pub fields: Vec<String>,
    /// Whether this table has sensitive fields
    pub has_sensitive_fields: bool,
    /// Security tier
    pub tier: SecurityTier,
    /// Total access count
    pub access_count: u32,
}

#[derive(Debug, Clone)]
pub struct FileAccessInfo {
    /// Tables accessed from this file
    pub tables: Vec<String>,
    /// Frameworks used in this file
    pub frameworks: Vec<String>,
    /// Whether this file has boundary violations
    pub has_violations: bool,
    /// Total access count
    pub access_count: u32,
}
```


---

## 14. Table Name Validation (v1 Feature — Preserved)

v1's `TableNameValidator` (packages/core/src/boundaries/table-name-validator.ts) filters
noise from detected table names. Without validation, the detector produces false positives
like variable names, function names, and string fragments that look like table names but
aren't. v2 preserves this as a Rust module with expanded rules.

### Validation Rules

```rust
pub struct TableNameValidator {
    /// Known table names from the LEARN phase
    known_tables: FxHashSet<String>,
    /// Learned naming convention
    convention: NamingConvention,
    /// Custom allowlist (from drift-boundaries.toml)
    allowlist: FxHashSet<String>,
    /// Custom blocklist (common false positives)
    blocklist: FxHashSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamingConvention {
    SnakeCase,
    CamelCase,
    PascalCase,
    Mixed,
    Unknown,
}

impl TableNameValidator {
    /// Validate a candidate table name. Returns None if invalid.
    pub fn validate(&self, candidate: &str) -> Option<ValidatedTableName> {
        // Rule 1: Empty or whitespace-only
        if candidate.trim().is_empty() {
            return None;
        }

        // Rule 2: Too short (single char) or too long (>128 chars)
        if candidate.len() < 2 || candidate.len() > 128 {
            return None;
        }

        // Rule 3: Contains SQL keywords that indicate this is a query fragment
        if self.is_sql_fragment(candidate) {
            return None;
        }

        // Rule 4: Contains path separators (it's a file path, not a table)
        if candidate.contains('/') || candidate.contains('\\') {
            return None;
        }

        // Rule 5: Starts with a digit (invalid SQL identifier)
        if candidate.starts_with(|c: char| c.is_ascii_digit()) {
            return None;
        }

        // Rule 6: Contains spaces (likely a sentence fragment)
        if candidate.contains(' ') {
            return None;
        }

        // Rule 7: Blocklist check (common false positives)
        if self.blocklist.contains(candidate) {
            return None;
        }

        // Rule 8: Known table from LEARN phase (highest confidence)
        if self.known_tables.contains(candidate) {
            return Some(ValidatedTableName {
                name: candidate.to_string(),
                source: TableNameValidation::KnownFromLearning,
                confidence_boost: 0.2,
            });
        }

        // Rule 9: Allowlist check
        if self.allowlist.contains(candidate) {
            return Some(ValidatedTableName {
                name: candidate.to_string(),
                source: TableNameValidation::Allowlisted,
                confidence_boost: 0.15,
            });
        }

        // Rule 10: Convention match (if learned)
        let matches_convention = match self.convention {
            NamingConvention::SnakeCase => is_snake_case(candidate),
            NamingConvention::CamelCase => is_camel_case(candidate),
            NamingConvention::PascalCase => is_pascal_case(candidate),
            NamingConvention::Mixed | NamingConvention::Unknown => true,
        };

        if matches_convention {
            Some(ValidatedTableName {
                name: candidate.to_string(),
                source: TableNameValidation::ConventionMatch,
                confidence_boost: 0.05,
            })
        } else {
            // Doesn't match convention — still valid but lower confidence
            Some(ValidatedTableName {
                name: candidate.to_string(),
                source: TableNameValidation::NoConventionMatch,
                confidence_boost: 0.0,
            })
        }
    }

    fn is_sql_fragment(&self, s: &str) -> bool {
        const SQL_KEYWORDS: &[&str] = &[
            "select", "insert", "update", "delete", "from", "where",
            "join", "inner", "outer", "left", "right", "group", "order",
            "having", "limit", "offset", "union", "create", "alter",
            "drop", "index", "table", "into", "values", "set",
            "and", "or", "not", "null", "true", "false", "between",
            "like", "in", "exists", "case", "when", "then", "else",
        ];
        let lower = s.to_lowercase();
        SQL_KEYWORDS.contains(&lower.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct ValidatedTableName {
    pub name: String,
    pub source: TableNameValidation,
    /// Added to the base confidence score
    pub confidence_boost: f32,
}

#[derive(Debug, Clone, Copy)]
pub enum TableNameValidation {
    KnownFromLearning,
    Allowlisted,
    ConventionMatch,
    NoConventionMatch,
}
```

### Default Blocklist (Common False Positives)

```rust
const DEFAULT_BLOCKLIST: &[&str] = &[
    // Common variable names that look like tables
    "data", "result", "results", "response", "request", "body",
    "params", "args", "options", "config", "settings", "context",
    "state", "props", "payload", "item", "items", "list", "array",
    "object", "value", "values", "key", "keys", "map", "set",
    // Common function/method names
    "get", "post", "put", "patch", "find", "create", "save",
    "remove", "fetch", "query", "execute", "run", "call",
    // Common type names
    "string", "number", "boolean", "integer", "float", "double",
    "text", "blob", "date", "datetime", "timestamp",
    // Framework artifacts
    "model", "schema", "migration", "seed", "factory",
    "controller", "service", "repository", "middleware",
];
```

---

## 15. Variable-to-Table Inference (v1 Learning Feature — Preserved)

v1's DataAccessLearner could infer table names from variable names (e.g., `userRepo` →
`users`, `orderService` → `orders`). This is a key learning feature that reduces false
negatives for indirect data access patterns. v2 preserves and expands it.

### Inference Rules

```rust
pub struct VariableTableInferencer {
    /// Known table names from LEARN phase
    known_tables: FxHashSet<String>,
    /// Learned variable → table mappings
    learned_mappings: FxHashMap<String, String>,
    /// Naming convention for tables
    convention: NamingConvention,
}

impl VariableTableInferencer {
    /// Attempt to infer a table name from a variable name.
    /// Returns the inferred table name and confidence.
    pub fn infer(&self, variable_name: &str) -> Option<(String, f32)> {
        // Strategy 1: Direct learned mapping
        if let Some(table) = self.learned_mappings.get(variable_name) {
            return Some((table.clone(), 0.85));
        }

        // Strategy 2: Strip common suffixes and check known tables
        let stripped = self.strip_suffixes(variable_name);
        let candidates = self.generate_table_candidates(&stripped);

        for candidate in &candidates {
            if self.known_tables.contains(candidate) {
                return Some((candidate.clone(), 0.70));
            }
        }

        // Strategy 3: Pluralize stripped name and check
        for candidate in &candidates {
            let plural = self.pluralize(candidate);
            if self.known_tables.contains(&plural) {
                return Some((plural, 0.60));
            }
        }

        None
    }

    fn strip_suffixes(&self, name: &str) -> String {
        const SUFFIXES: &[&str] = &[
            "Repo", "Repository", "Service", "Store", "Model",
            "Manager", "Handler", "Controller", "Client", "Dao",
            "Gateway", "Provider", "Adapter", "Mapper",
            "_repo", "_repository", "_service", "_store", "_model",
            "_manager", "_handler", "_controller", "_client", "_dao",
        ];
        let mut result = name.to_string();
        for suffix in SUFFIXES {
            if let Some(stripped) = result.strip_suffix(suffix) {
                result = stripped.to_string();
                break;
            }
        }
        result
    }

    fn generate_table_candidates(&self, base: &str) -> Vec<String> {
        vec![
            base.to_lowercase(),
            to_snake_case(base),
            to_camel_case(base),
            base.to_string(),
        ]
    }

    fn pluralize(&self, name: &str) -> String {
        // Simple English pluralization rules
        if name.ends_with('s') || name.ends_with('x') || name.ends_with('z')
            || name.ends_with("ch") || name.ends_with("sh")
        {
            format!("{}es", name)
        } else if name.ends_with('y')
            && !name.ends_with("ay") && !name.ends_with("ey")
            && !name.ends_with("oy") && !name.ends_with("uy")
        {
            format!("{}ies", &name[..name.len() - 1])
        } else {
            format!("{}s", name)
        }
    }

    /// Learn variable-to-table mappings from observed access patterns.
    /// Called during the LEARN phase.
    pub fn learn_from_access(
        &mut self,
        variable_name: &str,
        table_name: &str,
        confidence: f32,
    ) {
        if confidence >= 0.7 {
            self.learned_mappings.insert(
                variable_name.to_string(),
                table_name.to_string(),
            );
        }
    }
}
```

### Learning Flow

During the LEARN phase, when the system detects a high-confidence data access like
`userRepo.findAll()` → table `users`, it records the mapping `userRepo → users`.
On subsequent detections, if it sees `userRepo.customMethod()` where the table isn't
directly visible, it can infer the table is `users` from the learned mapping.

---

## 16. Storage Schema (drift.db Tables)

Per 02-STORAGE-V2-PREP.md, boundary detection writes to 3 Silver tables plus contributes
to the `data_access` table shared with the call graph. All tables use STRICT mode.

### Table: `boundaries`

```sql
CREATE TABLE boundaries (
    id TEXT PRIMARY KEY,                    -- Content-addressed hash
    scan_id TEXT NOT NULL,                  -- Links to scan that found this
    table_name TEXT NOT NULL,               -- Database table being accessed
    operation TEXT NOT NULL                  -- 'read', 'write', 'delete', 'update', 'unknown'
        CHECK(operation IN ('read','write','delete','update','unknown')),
    file TEXT NOT NULL,                     -- Source file path (relative)
    line INTEGER NOT NULL,                  -- Line number
    col INTEGER NOT NULL,                   -- Column number
    context TEXT,                           -- Surrounding code snippet
    framework TEXT NOT NULL,                -- ORM framework name
    language TEXT NOT NULL,                 -- Source language
    confidence REAL NOT NULL,               -- 0.0-1.0
    confidence_breakdown TEXT,              -- JSONB: {table_name, fields, operation, framework, literal}
    fields TEXT,                            -- JSONB array of field names
    has_auth_context INTEGER NOT NULL       -- 0 or 1
        DEFAULT 0,
    security_tier TEXT NOT NULL             -- 'critical', 'high', 'medium', 'low'
        CHECK(security_tier IN ('critical','high','medium','low')),
    unsafe_api TEXT,                        -- JSONB: {method, reason, cwe, safe_alternative} or NULL
    transformations TEXT,                   -- JSONB array: [{field, transformation}]
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

-- Primary query patterns
CREATE INDEX idx_boundaries_table ON boundaries(table_name);
CREATE INDEX idx_boundaries_file ON boundaries(file);
CREATE INDEX idx_boundaries_scan ON boundaries(scan_id);
CREATE INDEX idx_boundaries_tier ON boundaries(security_tier)
    WHERE security_tier IN ('critical', 'high');

-- Covering index for boundary listing (avoids table lookup)
CREATE INDEX idx_boundaries_covering ON boundaries(
    table_name, security_tier, confidence DESC,
    id, file, line, operation, framework
);
```

### Table: `sensitive_fields`

```sql
CREATE TABLE sensitive_fields (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    field_name TEXT NOT NULL,               -- Field/column name
    table_name TEXT,                        -- Table it belongs to (NULL if unknown)
    sensitivity TEXT NOT NULL               -- 'pii', 'credentials', 'financial', 'health'
        CHECK(sensitivity IN ('pii','credentials','financial','health')),
    file TEXT NOT NULL,                     -- Source file where detected
    line INTEGER NOT NULL,                  -- Line number
    confidence REAL NOT NULL,               -- After false positive filtering
    base_specificity REAL NOT NULL,         -- From pattern match (before filtering)
    filtered INTEGER NOT NULL DEFAULT 0,    -- 1 if false positive filter reduced confidence
    scan_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

-- Partial indexes for sensitivity-specific queries
CREATE INDEX idx_sensitive_pii
    ON sensitive_fields(table_name, field_name)
    WHERE sensitivity = 'pii';

CREATE INDEX idx_sensitive_credentials
    ON sensitive_fields(table_name, field_name)
    WHERE sensitivity = 'credentials';

CREATE INDEX idx_sensitive_financial
    ON sensitive_fields(table_name, field_name)
    WHERE sensitivity = 'financial';

CREATE INDEX idx_sensitive_health
    ON sensitive_fields(table_name, field_name)
    WHERE sensitivity = 'health';

CREATE INDEX idx_sensitive_scan ON sensitive_fields(scan_id);
```

### Table: `boundary_rules`

```sql
CREATE TABLE boundary_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    table_name TEXT NOT NULL,               -- Table this rule applies to
    source TEXT NOT NULL                     -- 'explicit', 'learned', 'default'
        CHECK(source IN ('explicit','learned','default')),
    allowed_files TEXT,                     -- JSONB array of glob patterns
    denied_files TEXT,                      -- JSONB array of glob patterns
    allowed_operations TEXT,                -- JSONB array: ['read','write',...]
    require_auth INTEGER NOT NULL DEFAULT 0,
    violation_severity TEXT                 -- 'error', 'warning' (NULL = default)
        CHECK(violation_severity IS NULL OR violation_severity IN ('error','warning')),
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE UNIQUE INDEX idx_boundary_rules_table_source
    ON boundary_rules(table_name, source);
```

### Table: `boundary_violations`

```sql
CREATE TABLE boundary_violations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    boundary_id TEXT NOT NULL               -- FK to boundaries.id
        REFERENCES boundaries(id) ON DELETE CASCADE,
    rule_id INTEGER NOT NULL                -- FK to boundary_rules.id
        REFERENCES boundary_rules(id) ON DELETE CASCADE,
    violation_type TEXT NOT NULL
        CHECK(violation_type IN (
            'unauthorized_file','unauthorized_operation',
            'missing_auth','explicitly_denied'
        )),
    message TEXT NOT NULL,
    severity TEXT NOT NULL
        CHECK(severity IN ('error','warning')),
    scan_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_violations_boundary ON boundary_violations(boundary_id);
CREATE INDEX idx_violations_rule ON boundary_violations(rule_id);
CREATE INDEX idx_violations_scan ON boundary_violations(scan_id);
CREATE INDEX idx_violations_severity ON boundary_violations(severity)
    WHERE severity = 'error';
```

### Table: `data_access` (Shared with Call Graph)

Per 02-STORAGE-V2-PREP.md, the `data_access` table links functions to the tables they
access. It's populated by boundary detection but queried by call graph reachability.

```sql
CREATE TABLE data_access (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    function_id TEXT NOT NULL               -- FK to functions.id (call graph)
        REFERENCES functions(id) ON DELETE CASCADE,
    table_name TEXT NOT NULL,
    operation TEXT NOT NULL
        CHECK(operation IN ('read','write','delete','update','unknown')),
    boundary_id TEXT                        -- FK to boundaries.id (optional link)
        REFERENCES boundaries(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_data_access_table ON data_access(table_name);
CREATE INDEX idx_data_access_function ON data_access(function_id);
```

### Table: `orm_models`

```sql
CREATE TABLE orm_models (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,                     -- Model/class name
    table_name TEXT NOT NULL,               -- Database table name
    table_name_source TEXT NOT NULL         -- 'explicit', 'inferred', 'schema_file', 'migration'
        CHECK(table_name_source IN ('explicit','inferred','schema_file','migration')),
    fields TEXT,                            -- JSONB array of field definitions
    relationships TEXT,                     -- JSONB array of relationships
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    framework TEXT NOT NULL,
    confidence REAL NOT NULL,
    scan_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_orm_models_table ON orm_models(table_name);
CREATE INDEX idx_orm_models_framework ON orm_models(framework);
CREATE INDEX idx_orm_models_scan ON orm_models(scan_id);
```

### Batch Writer Integration

Boundary detection uses the same `BatchWriter` pattern as all other subsystems
(per 02-STORAGE-V2-PREP.md §6):

```rust
// Boundary detection sends rows to the batch writer channel
enum WritePayload {
    // ... other variants from scanner, detectors, call graph ...
    Boundaries(Vec<BoundaryRow>),
    SensitiveFields(Vec<SensitiveFieldRow>),
    BoundaryRules(Vec<BoundaryRuleRow>),
    BoundaryViolations(Vec<BoundaryViolationRow>),
    OrmModels(Vec<OrmModelRow>),
    DataAccess(Vec<DataAccessRow>),
    Flush,
}
```

---

## 17. NAPI Interface (per 03-NAPI-BRIDGE-V2-PREP.md §10.7)

5 NAPI functions expose boundary detection to the TypeScript layer.
All heavy computation happens in Rust; NAPI returns summaries.

### Function Registry

| Function | Sync/Async | Returns | Description |
|----------|-----------|---------|-------------|
| `detect_boundaries(root)` | Async | `BoundariesSummary` | Full boundary scan (learn + detect) |
| `query_boundaries(filter, pagination?)` | Sync | `PaginatedResult<BoundarySummary>` | Query detected boundaries |
| `query_sensitive_fields(table?)` | Sync | `SensitiveField[]` | List sensitive fields |
| `detect_secrets(root)` | Async | `SecretsSummary` | Enterprise secret detection |
| `query_security_summary()` | Sync | `SecuritySummary` | Materialized security overview |

### NAPI Binding Signatures (Rust)

```rust
// crates/drift-napi/src/bindings/boundaries.rs

use napi::bindgen_prelude::*;
use napi_derive::napi;

/// Full boundary detection: learn phase + detect phase.
/// Writes results to drift.db, returns summary.
#[napi]
pub async fn detect_boundaries(root: String) -> Result<serde_json::Value> {
    let runtime = get_runtime()?;

    // Check cancellation
    if runtime.cancelled() {
        return Err(napi_error("[CANCELLED] Boundary detection cancelled"));
    }

    let result = tokio::task::spawn_blocking(move || {
        let db = runtime.database();
        let event_handler = runtime.event_handler();
        let config = runtime.config();

        drift_core::boundaries::detect_boundaries(
            &root,
            db,
            &*event_handler,
            &config.boundaries,
        )
    })
    .await
    .map_err(|e| napi_error(&format!("[INTERNAL] {}", e)))?
    .map_err(|e| napi_error(&format!("[{}] {}", e.code(), e)))?;

    // Convert BoundaryScanResult → BoundariesSummary (lightweight)
    let summary = BoundariesSummary::from(result);
    serde_json::to_value(&summary)
        .map_err(|e| napi_error(&format!("[SERIALIZATION] {}", e)))
}

/// Query boundaries with optional filter and pagination.
/// Reads from drift.db (sync, fast).
#[napi]
pub fn query_boundaries(
    filter: serde_json::Value,
    pagination: Option<serde_json::Value>,
) -> Result<serde_json::Value> {
    let runtime = get_runtime()?;
    let db = runtime.database();

    let filter: BoundaryFilter = serde_json::from_value(filter)
        .map_err(|e| napi_error(&format!("[INVALID_FILTER] {}", e)))?;
    let pagination: Option<PaginationOptions> = pagination
        .map(|p| serde_json::from_value(p))
        .transpose()
        .map_err(|e| napi_error(&format!("[INVALID_PAGINATION] {}", e)))?;

    let result = drift_core::boundaries::query_boundaries(db, &filter, pagination.as_ref())
        .map_err(|e| napi_error(&format!("[{}] {}", e.code(), e)))?;

    serde_json::to_value(&result)
        .map_err(|e| napi_error(&format!("[SERIALIZATION] {}", e)))
}

/// Query sensitive fields, optionally filtered by table name.
#[napi]
pub fn query_sensitive_fields(table: Option<String>) -> Result<serde_json::Value> {
    let runtime = get_runtime()?;
    let db = runtime.database();

    let fields = drift_core::boundaries::query_sensitive_fields(db, table.as_deref())
        .map_err(|e| napi_error(&format!("[{}] {}", e.code(), e)))?;

    serde_json::to_value(&fields)
        .map_err(|e| napi_error(&format!("[SERIALIZATION] {}", e)))
}

/// Query the materialized security summary (from Gold layer).
#[napi]
pub fn query_security_summary() -> Result<serde_json::Value> {
    let runtime = get_runtime()?;
    let db = runtime.database();

    let summary = drift_core::boundaries::query_security_summary(db)
        .map_err(|e| napi_error(&format!("[{}] {}", e.code(), e)))?;

    serde_json::to_value(&summary)
        .map_err(|e| napi_error(&format!("[SERIALIZATION] {}", e)))
}
```

### BoundariesSummary (NAPI Return Type)

```rust
/// Lightweight summary returned via NAPI after detect_boundaries().
/// Full data lives in drift.db — TS queries for details on demand.
#[derive(Debug, Clone, Serialize)]
pub struct BoundariesSummary {
    pub total_access_points: u32,
    pub total_models: u32,
    pub total_sensitive_fields: u32,
    pub total_violations: u32,
    pub total_unsafe_apis: u32,
    pub frameworks_detected: Vec<String>,
    pub tables_found: u32,
    pub security_tier_counts: TierCounts,
    pub duration_ms: u32,
}
```

### BoundaryFilter (Query Parameter)

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct BoundaryFilter {
    /// Filter by table name (exact match)
    pub table: Option<String>,
    /// Filter by file path (glob pattern)
    pub file: Option<String>,
    /// Filter by framework
    pub framework: Option<String>,
    /// Filter by security tier
    pub security_tier: Option<String>,
    /// Filter by operation type
    pub operation: Option<String>,
    /// Minimum confidence threshold
    pub min_confidence: Option<f32>,
    /// Only show entries with violations
    pub has_violations: Option<bool>,
    /// Only show entries with unsafe API usage
    pub has_unsafe_api: Option<bool>,
}
```


---

## 18. Error Handling (BoundaryError Enum)

Per AD6 (thiserror from the first line of code), boundary detection uses a dedicated
error enum with structured error codes. These propagate through NAPI as `[CODE] message`.

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BoundaryError {
    // --- Learning Phase Errors ---

    #[error("Failed to read source file '{path}': {source}")]
    FileRead {
        path: String,
        source: std::io::Error,
    },

    #[error("Failed to parse schema file '{path}': {reason}")]
    SchemaParse {
        path: String,
        reason: String,
    },

    #[error("No frameworks detected during learning phase")]
    NoFrameworksDetected,

    // --- Detection Phase Errors ---

    #[error("Tree-sitter parse failed for '{path}': {reason}")]
    ParseFailed {
        path: String,
        reason: String,
    },

    #[error("Language normalizer not found for {language:?}")]
    NormalizerNotFound {
        language: Language,
    },

    #[error("ORM matcher failed for framework '{framework}': {reason}")]
    MatcherFailed {
        framework: String,
        reason: String,
    },

    #[error("Field extractor failed for framework '{framework}': {reason}")]
    ExtractorFailed {
        framework: String,
        reason: String,
    },

    // --- Storage Errors ---

    #[error("Database write failed: {source}")]
    DatabaseWrite {
        #[from]
        source: StorageError,
    },

    #[error("Database query failed: {reason}")]
    DatabaseQuery {
        reason: String,
    },

    // --- Rule Errors ---

    #[error("Failed to parse boundary rules from '{path}': {reason}")]
    RuleParse {
        path: String,
        reason: String,
    },

    #[error("Invalid glob pattern in boundary rule: '{pattern}'")]
    InvalidGlobPattern {
        pattern: String,
    },

    // --- Configuration Errors ---

    #[error("Invalid boundary configuration: {reason}")]
    InvalidConfig {
        reason: String,
    },

    // --- Cancellation ---

    #[error("Boundary detection cancelled")]
    Cancelled,
}

impl BoundaryError {
    /// Error code for NAPI propagation
    pub fn code(&self) -> &'static str {
        match self {
            Self::FileRead { .. } => "FILE_READ",
            Self::SchemaParse { .. } => "SCHEMA_PARSE",
            Self::NoFrameworksDetected => "NO_FRAMEWORKS",
            Self::ParseFailed { .. } => "PARSE_FAILED",
            Self::NormalizerNotFound { .. } => "NORMALIZER_NOT_FOUND",
            Self::MatcherFailed { .. } => "MATCHER_FAILED",
            Self::ExtractorFailed { .. } => "EXTRACTOR_FAILED",
            Self::DatabaseWrite { .. } => "DB_WRITE",
            Self::DatabaseQuery { .. } => "DB_QUERY",
            Self::RuleParse { .. } => "RULE_PARSE",
            Self::InvalidGlobPattern { .. } => "INVALID_GLOB",
            Self::InvalidConfig { .. } => "INVALID_CONFIG",
            Self::Cancelled => "CANCELLED",
        }
    }

    /// Whether this error is recoverable (detection can continue for other files)
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::FileRead { .. }
                | Self::SchemaParse { .. }
                | Self::ParseFailed { .. }
                | Self::MatcherFailed { .. }
                | Self::ExtractorFailed { .. }
        )
    }
}
```

### Error Recovery Strategy

Boundary detection processes many files. A single file failure should not abort the
entire scan. Recoverable errors are collected and reported in `BoundaryScanStats.errors`:

```rust
pub struct BoundaryScanStats {
    // ... other fields from §13 ...
    pub errors: Vec<BoundaryFileError>,
}

pub struct BoundaryFileError {
    pub file: String,
    pub error: String,
    pub error_code: String,
}
```

Non-recoverable errors (database write failure, cancellation, invalid config) abort
the scan immediately and propagate to the caller.

---

## 19. Tracing & Observability (per AD10)

Per AD10 (tracing from the first line of code), boundary detection emits structured
spans and events for performance monitoring and debugging.

### Span Hierarchy

```
boundary_detection                          # Root span for entire boundary scan
├── boundary_learn                          # LEARN phase
│   ├── learn_file{path}                    # Per-file learning
│   ├── learn_framework_detection           # Framework signature matching
│   ├── learn_table_extraction              # Table name extraction
│   └── learn_convention_detection          # Naming convention analysis
├── boundary_detect                         # DETECT phase
│   ├── detect_file{path, language}         # Per-file detection
│   │   ├── normalize_chains               # Language normalizer
│   │   ├── match_orm                      # ORM matcher
│   │   ├── extract_fields                 # Field extractor
│   │   ├── detect_sensitive               # Sensitive field detection
│   │   └── detect_unsafe_api              # Unsafe API detection
│   └── validate_table_names               # Table name validation pass
├── boundary_rules                          # Rule evaluation
│   ├── load_explicit_rules                # From drift-boundaries.toml
│   ├── generate_learned_rules             # From access patterns
│   └── check_violations                   # Violation detection
├── boundary_storage                        # Write to drift.db
│   ├── write_boundaries                   # Batch write boundaries
│   ├── write_sensitive_fields             # Batch write sensitive fields
│   ├── write_models                       # Batch write ORM models
│   └── write_violations                   # Batch write violations
└── boundary_summary                        # Generate summary
```

### Key Metrics (Emitted as Span Attributes)

```rust
use tracing::{instrument, info, warn, debug, Span};

#[instrument(
    name = "boundary_detection",
    skip(db, event_handler, config),
    fields(
        root = %root,
        files_scanned = tracing::field::Empty,
        data_access_files = tracing::field::Empty,
        access_points = tracing::field::Empty,
        sensitive_fields = tracing::field::Empty,
        violations = tracing::field::Empty,
        frameworks = tracing::field::Empty,
        duration_ms = tracing::field::Empty,
    )
)]
pub fn detect_boundaries(
    root: &str,
    db: &DatabaseManager,
    event_handler: &dyn DriftEventHandler,
    config: &BoundaryConfig,
) -> Result<BoundaryScanResult, BoundaryError> {
    let start = std::time::Instant::now();

    // LEARN phase
    let conventions = {
        let _span = tracing::info_span!("boundary_learn").entered();
        learn_data_access(root, config)?
    };

    info!(
        frameworks = ?conventions.frameworks,
        tables = conventions.known_tables.len(),
        convention = ?conventions.table_naming_convention,
        "Learning phase complete"
    );

    // DETECT phase
    let result = {
        let _span = tracing::info_span!("boundary_detect").entered();
        detect_all_boundaries(root, &conventions, db, config)?
    };

    // Fill in span fields
    let span = Span::current();
    span.record("files_scanned", result.stats.files_scanned);
    span.record("data_access_files", result.stats.data_access_files);
    span.record("access_points", result.stats.total_access_points);
    span.record("sensitive_fields", result.stats.total_sensitive_fields);
    span.record("violations", result.stats.total_violations);
    span.record("frameworks", &format!("{:?}", result.stats.frameworks_detected));
    span.record("duration_ms", start.elapsed().as_millis() as u32);

    Ok(result)
}
```

### Log Levels

| Level | What | Example |
|-------|------|---------|
| ERROR | Unrecoverable failures | Database write failed, invalid config |
| WARN | Recoverable per-file failures | Parse failed for file X, unknown language |
| INFO | Phase completions, summary stats | "Learning complete: 3 frameworks, 42 tables" |
| DEBUG | Per-file processing details | "Detected 5 access points in user-service.ts" |
| TRACE | Individual pattern matches | "Prisma matcher: found table 'users' at line 42" |

Enable via `DRIFT_LOG` environment variable:
```
DRIFT_LOG=boundaries=debug        # Debug boundary detection
DRIFT_LOG=boundaries=trace        # Full trace (very verbose)
DRIFT_LOG=boundaries::learn=debug # Debug learning phase only
```

---

## 20. Event Emissions (per D5, DriftEventHandler)

Boundary detection emits events via the `DriftEventHandler` trait. In standalone mode
these are no-ops. When the bridge crate is active, they become Cortex memories.

### Boundary-Specific Events

```rust
pub trait DriftEventHandler: Send + Sync {
    // ... scanner events, parser events, etc. ...

    // --- Boundary Events ---

    /// Emitted when boundary detection starts
    fn on_boundary_scan_started(&self, _root: &Path, _file_count: Option<usize>) {}

    /// Emitted after the LEARN phase completes
    fn on_boundary_learn_complete(
        &self,
        _conventions: &LearnedDataAccessConventions,
    ) {}

    /// Emitted when a new data access point is detected
    fn on_boundary_detected(
        &self,
        _access_point: &DataAccessPoint,
    ) {}

    /// Emitted when a sensitive field is detected
    fn on_sensitive_field_detected(
        &self,
        _field: &SensitiveField,
    ) {}

    /// Emitted when a boundary violation is found
    fn on_boundary_violation(
        &self,
        _violation: &BoundaryViolation,
    ) {}

    /// Emitted when an unsafe ORM API usage is detected
    fn on_unsafe_api_detected(
        &self,
        _usage: &UnsafeApiUsage,
    ) {}

    /// Emitted when boundary detection completes
    fn on_boundary_scan_complete(
        &self,
        _result: &BoundaryScanResult,
    ) {}
}
```

### Bridge Consumption (cortex-drift-bridge)

When the bridge crate is active, these events create Cortex memories:

| Event | Cortex Memory Type | Purpose |
|-------|-------------------|---------|
| `on_boundary_violation` | `boundary_violation` | Track violations over time |
| `on_sensitive_field_detected` | `sensitive_data_location` | Remember where sensitive data lives |
| `on_unsafe_api_detected` | `security_concern` | Track unsafe API usage patterns |
| `on_boundary_scan_complete` | `security_posture` | Snapshot of security state |

---

## 21. Integration Points

Boundary detection is a Level 1 system that feeds into multiple Level 2+ consumers.
These integration points define the contracts between subsystems.

### 21.1 → Taint Analysis (Level 2B)

Boundary detection provides the **sink registry** for taint analysis. Every unsafe ORM
API usage and every raw SQL access point is a potential SQL injection sink.

```rust
/// Boundary detection exports sinks for the taint engine
pub fn export_taint_sinks(
    access_points: &[DataAccessPoint],
    unsafe_apis: &[UnsafeApiUsage],
) -> Vec<TaintSink> {
    let mut sinks = Vec::new();

    // Every unsafe API is a taint sink
    for api in unsafe_apis {
        sinks.push(TaintSink {
            id: format!("boundary:unsafe:{}", api.method),
            location: api.location.clone(),
            cwe: api.cwe.to_string(),
            label: "sql-injection".to_string(),
            framework: Some(api.framework.to_string()),
        });
    }

    // Every raw SQL access point is a potential sink
    for point in access_points {
        if point.framework == "raw-sql" {
            sinks.push(TaintSink {
                id: format!("boundary:raw-sql:{}:{}", point.file, point.line),
                location: Location {
                    file: point.file.clone(),
                    line: point.line,
                    column: point.column,
                },
                cwe: "CWE-89".to_string(),
                label: "sql-injection".to_string(),
                framework: None,
            });
        }
    }

    sinks
}
```

Per SAD3 and TA7: "Use learned ORM patterns as sinks (raw SQL bypass = automatic sink)."

### 21.2 → Reachability Analysis (Level 2B)

Boundary detection provides **sensitivity classification** for reachability analysis.
The reachability engine uses this to determine which code paths reach sensitive data.

```rust
/// Boundary detection exports sensitivity info for reachability
pub fn export_sensitivity_map(
    sensitive_fields: &[SensitiveField],
    access_points: &[DataAccessPoint],
) -> FxHashMap<String, SensitivityInfo> {
    let mut map = FxHashMap::default();

    for point in access_points {
        let sensitivities: Vec<&SensitiveField> = sensitive_fields.iter()
            .filter(|sf| {
                sf.table.as_deref() == Some(&point.table)
                    || point.fields.iter().any(|f| f == &sf.field)
            })
            .collect();

        if !sensitivities.is_empty() {
            map.insert(
                format!("{}:{}:{}", point.file, point.line, point.table),
                SensitivityInfo {
                    tier: point.security_tier,
                    sensitivity_types: sensitivities.iter()
                        .map(|sf| sf.sensitivity_type)
                        .collect(),
                    table: point.table.clone(),
                    fields: sensitivities.iter()
                        .map(|sf| sf.field.clone())
                        .collect(),
                },
            );
        }
    }

    map
}
```

Per BR1: "Add sensitivity propagation (transitive sensitivity through call graph)."

### 21.3 → Constraints System (Level 2C)

Boundary detection feeds the `data_flow` constraint type. Constraints can enforce
rules like "user data must not flow to logging" or "payment data must be encrypted
before storage."

```rust
/// Constraint types that boundary detection can generate
pub enum DataFlowConstraint {
    /// Sensitive data must not flow to specified sinks
    NoFlowTo {
        sensitivity: SensitivityType,
        denied_sinks: Vec<String>,  // e.g., ["logging", "analytics", "third_party"]
    },
    /// Data must be transformed before reaching a sink
    RequireTransformation {
        field: String,
        required_transformation: FieldTransformation,
        before_sink: String,
    },
    /// Access requires specific auth context
    RequireAuth {
        table: String,
        required_auth_type: String,  // e.g., "jwt", "session", "api_key"
    },
}
```

### 21.4 → Quality Gates (Level 3)

Boundary detection contributes to the **security quality gate**. The gate reads from
`materialized_security` (Gold layer) and evaluates pass/fail criteria.

```rust
/// Security gate criteria (evaluated by quality gate engine)
pub struct SecurityGateCriteria {
    /// Maximum allowed critical-tier access points without boundary rules
    pub max_unprotected_critical: u32,      // Default: 0
    /// Maximum allowed boundary violations (error severity)
    pub max_error_violations: u32,          // Default: 0
    /// Maximum allowed unsafe API usages
    pub max_unsafe_apis: u32,               // Default: 5
    /// Minimum percentage of sensitive tables with boundary rules
    pub min_rule_coverage_pct: f32,         // Default: 80.0
    /// Whether to fail on any credential exposure
    pub fail_on_credential_exposure: bool,  // Default: true
}
```

### 21.5 → N+1 Detection (Level 2A)

Boundary detection's `DataAccessMap` feeds N+1 query detection. The N+1 detector
looks for patterns where a loop body contains a data access point that could be
batched:

```
for user in users:           # Loop detected by call graph
    orders = db.query(       # Data access point detected by boundary detection
        "SELECT * FROM orders WHERE user_id = ?", user.id
    )
```

The boundary detector provides the data access points; the N+1 detector correlates
them with loop structures from the call graph.

### 21.6 → Contract Extraction (Level 2C)

Boundary detection's ORM model extraction feeds contract detection. When a model
defines fields, those fields become part of the data contract between backend and
frontend:

```
ORMModel { name: "User", fields: ["id", "email", "name"] }
  → DataContract { entity: "User", fields: [...], source: "prisma" }
```

### Integration Summary

```
                    ┌──────────────────────────────────┐
                    │     Boundary Detection (L1)       │
                    │  learn → detect → store → report  │
                    └──────┬───────┬───────┬───────┬───┘
                           │       │       │       │
              ┌────────────┘       │       │       └────────────┐
              ▼                    ▼       ▼                    ▼
    ┌─────────────────┐  ┌──────────┐ ┌──────────┐  ┌─────────────────┐
    │ Taint Analysis  │  │Reachab.  │ │Constraints│  │ Quality Gates   │
    │ (sinks from     │  │(sensitiv.│ │(data_flow │  │ (security gate  │
    │  unsafe APIs)   │  │ map)     │ │ rules)    │  │  criteria)      │
    │ Level 2B        │  │Level 2B  │ │Level 2C   │  │ Level 3         │
    └─────────────────┘  └──────────┘ └──────────┘  └─────────────────┘
              │                                              │
              ▼                                              ▼
    ┌─────────────────┐                            ┌─────────────────┐
    │ N+1 Detection   │                            │ Contract Extract│
    │ (access points  │                            │ (ORM models →   │
    │  in loops)      │                            │  data contracts)│
    │ Level 2A        │                            │ Level 2C        │
    └─────────────────┘                            └─────────────────┘
```


---

## 22. File Module Structure

```
crates/drift-core/src/boundaries/
├── mod.rs                      # Module exports, public API
├── engine.rs                   # BoundaryEngine: orchestrates learn + detect + store
├── config.rs                   # BoundaryConfig (from drift.toml [boundaries] section)
├── errors.rs                   # BoundaryError enum (§18)
│
├── learning/
│   ├── mod.rs                  # Learning phase orchestration
│   ├── learner.rs              # DataAccessLearner: framework/table/convention discovery
│   ├── conventions.rs          # LearnedDataAccessConventions, NamingConvention
│   └── variable_inference.rs   # VariableTableInferencer (§15)
│
├── detection/
│   ├── mod.rs                  # Detection phase orchestration
│   ├── detector.rs             # Main detection loop (per-file, parallel via rayon)
│   ├── sensitive.rs            # SensitiveFieldDetector: 4 categories, pattern tables
│   ├── false_positive.rs       # FalsePositiveFilter: 6-filter pipeline (§7)
│   └── unsafe_api.rs           # UnsafeApiDetector: per-framework unsafe patterns (§9)
│
├── normalizers/
│   ├── mod.rs                  # LanguageNormalizer trait + NormalizerRegistry
│   ├── typescript.rs           # TypeScriptNormalizer (TS/JS)
│   ├── python.rs               # PythonNormalizer
│   ├── java.rs                 # JavaNormalizer
│   ├── csharp.rs               # CSharpNormalizer
│   ├── php.rs                  # PhpNormalizer
│   ├── go.rs                   # GoNormalizer
│   ├── rust_lang.rs            # RustNormalizer (rust_lang to avoid keyword)
│   ├── cpp.rs                  # CppNormalizer
│   └── base.rs                 # BaseNormalizer (regex fallback)
│
├── matchers/
│   ├── mod.rs                  # OrmMatcher trait + MatcherRegistry
│   ├── prisma.rs               # PrismaMatcher
│   ├── typeorm.rs              # TypeOrmMatcher
│   ├── sequelize.rs            # SequelizeMatcher
│   ├── drizzle.rs              # DrizzleMatcher
│   ├── knex.rs                 # KnexMatcher
│   ├── mongoose.rs             # MongooseMatcher
│   ├── supabase.rs             # SupabaseMatcher
│   ├── mikroorm.rs             # MikroOrmMatcher (NEW v2)
│   ├── kysely.rs               # KyselyMatcher (NEW v2)
│   ├── django.rs               # DjangoMatcher
│   ├── sqlalchemy.rs           # SqlAlchemyMatcher
│   ├── efcore.rs               # EfCoreMatcher
│   ├── eloquent.rs             # EloquentMatcher
│   ├── spring_data.rs          # SpringDataMatcher
│   ├── gorm.rs                 # GormMatcher
│   ├── diesel.rs               # DieselMatcher
│   ├── seaorm.rs               # SeaOrmMatcher
│   ├── sqlx.rs                 # SqlxMatcher
│   ├── database_sql.rs         # DatabaseSqlMatcher (Go database/sql)
│   ├── raw_sql.rs              # RawSqlMatcher (all languages)
│   ├── sqlc.rs                 # SqlcMatcher (NEW v2, detection only)
│   └── sqlboiler.rs            # SqlBoilerMatcher (NEW v2, detection only)
│
├── extractors/
│   ├── mod.rs                  # FieldExtractor trait + ExtractorRegistry
│   ├── prisma.rs               # PrismaExtractor (schema.prisma parser)
│   ├── django.rs               # DjangoExtractor (models.py parser)
│   ├── sqlalchemy.rs           # SqlAlchemyExtractor (declarative models)
│   ├── supabase.rs             # SupabaseExtractor (table references)
│   ├── gorm.rs                 # GormExtractor (Go struct tags)
│   ├── diesel.rs               # DieselExtractor (table! macro)
│   ├── raw_sql.rs              # RawSqlExtractor (SELECT/INSERT/UPDATE/DELETE)
│   ├── efcore.rs               # EfCoreExtractor (NEW v2: DbSet, [Table], Fluent API)
│   ├── hibernate.rs            # HibernateExtractor (NEW v2: @Entity, @Table, @Column)
│   └── eloquent.rs             # EloquentExtractor (NEW v2: $table, $fillable, $casts)
│
├── validation/
│   ├── mod.rs                  # Validation orchestration
│   └── table_name.rs           # TableNameValidator (§14)
│
├── rules/
│   ├── mod.rs                  # Rule engine orchestration
│   ├── loader.rs               # Load rules from drift-boundaries.toml + learned + defaults
│   ├── learned.rs              # Auto-generate rules from access patterns
│   └── violations.rs           # Violation detection (§10)
│
├── scoring/
│   ├── mod.rs                  # Scoring orchestration
│   ├── confidence.rs           # ConfidenceBreakdown (§8)
│   ├── security_tier.rs        # SecurityTier classification (§11)
│   └── prioritizer.rs          # SecurityPrioritizer: summary generation
│
├── flow/
│   ├── mod.rs                  # Field-level data flow tracking
│   └── transformations.rs      # FieldTransformation detection (§12)
│
├── signatures/
│   ├── mod.rs                  # FrameworkSignature definitions
│   └── registry.rs             # All 33 framework signatures (§4)
│
├── types.rs                    # All boundary types (§13): DataAccessPoint, ORMModel,
│                               # SensitiveField, BoundaryScanResult, DataAccessMap,
│                               # UnifiedCallChain, ChainCall, CallArg, etc.
│
└── storage.rs                  # Boundary-specific DB read/write functions
                                # (uses drift-core's DatabaseManager)
```

### File Count Summary

| Directory | Files | Purpose |
|-----------|-------|---------|
| `boundaries/` root | 4 | Engine, config, errors, types |
| `learning/` | 4 | LEARN phase |
| `detection/` | 5 | DETECT phase |
| `normalizers/` | 10 | 9 language normalizers + registry |
| `matchers/` | 23 | 22 ORM matchers + registry |
| `extractors/` | 11 | 10 field extractors + registry |
| `validation/` | 2 | Table name validation |
| `rules/` | 4 | Boundary rules engine |
| `scoring/` | 4 | Confidence + security tier |
| `flow/` | 2 | Field-level data flow |
| `signatures/` | 2 | Framework signatures |
| `storage.rs` | 1 | DB operations |
| **Total** | **72** | |

This is the largest subsystem in drift-core by file count. The v1 equivalent was
~37 TS files (12 boundary + 25 unified-provider) + 4 Rust files = ~41 files.
v2 consolidates into 72 Rust files because:
1. Each ORM matcher is its own file (22 vs v1's 20 — cleaner than a mega-file)
2. Each normalizer is its own file (9 — same as v1)
3. Each extractor is its own file (10 vs v1's 7)
4. Learning, detection, rules, scoring are properly separated (v1 mixed concerns)

---

## 23. Build Order (Phased, with Dependencies)

### Phase 0: Types & Infrastructure (Week 1)

**Dependencies**: drift-core config, thiserror, tracing, DatabaseManager

1. `types.rs` — All boundary types (DataAccessPoint, ORMModel, SensitiveField,
   UnifiedCallChain, ChainCall, CallArg, BoundaryScanResult, DataAccessMap)
2. `errors.rs` — BoundaryError enum with error codes
3. `config.rs` — BoundaryConfig (thresholds, enabled frameworks, rule paths)
4. `storage.rs` — DDL for boundaries, sensitive_fields, boundary_rules,
   boundary_violations, orm_models, data_access tables
5. `signatures/registry.rs` — All 33 FrameworkSignature definitions

**Verify**: Types compile, tables create in drift.db, signatures load.

### Phase 1: Sensitive Field Detection (Week 2)

**Dependencies**: Phase 0 types

6. `detection/sensitive.rs` — SensitiveFieldDetector with all 4 category pattern tables
7. `detection/false_positive.rs` — FalsePositiveFilter (6 filters)
8. `scoring/confidence.rs` — ConfidenceBreakdown (5 weighted factors)
9. `scoring/security_tier.rs` — SecurityTier classification

**Verify**: Can detect sensitive fields from field name strings with correct
confidence and tier classification. Unit tests for all 4 categories + false positives.

### Phase 2: Language Normalizers (Weeks 3-4)

**Dependencies**: Phase 0 types, tree-sitter grammars (from Parsers Level 0)

10. `normalizers/mod.rs` — LanguageNormalizer trait + NormalizerRegistry
11. `normalizers/typescript.rs` — TypeScriptNormalizer (highest priority — most ORMs)
12. `normalizers/python.rs` — PythonNormalizer
13. `normalizers/go.rs` — GoNormalizer
14. `normalizers/java.rs` — JavaNormalizer
15. `normalizers/csharp.rs` — CSharpNormalizer
16. `normalizers/php.rs` — PhpNormalizer
17. `normalizers/rust_lang.rs` — RustNormalizer
18. `normalizers/cpp.rs` — CppNormalizer
19. `normalizers/base.rs` — BaseNormalizer (regex fallback)

**Verify**: Each normalizer produces correct UnifiedCallChain from sample AST.
Golden tests with known input → expected chain output per language.

### Phase 3: ORM Matchers (Weeks 5-6)

**Dependencies**: Phase 2 normalizers, Phase 0 signatures

20. `matchers/mod.rs` — OrmMatcher trait + MatcherRegistry
21. `matchers/prisma.rs` through `matchers/sqlboiler.rs` — All 22 matchers
22. `detection/unsafe_api.rs` — UnsafeApiDetector (integrated into matchers)

**Verify**: Each matcher correctly identifies data access from normalized chains.
Golden tests with known call chains → expected DataAccessPoint output per ORM.

### Phase 4: Field Extractors (Week 7)

**Dependencies**: Phase 0 types, tree-sitter grammars

23. `extractors/mod.rs` — FieldExtractor trait + ExtractorRegistry
24. `extractors/prisma.rs` through `extractors/eloquent.rs` — All 10 extractors

**Verify**: Each extractor correctly parses model definitions from sample files.
Golden tests with known schema files → expected ExtractedModel output.

### Phase 5: Learning Phase (Week 8)

**Dependencies**: Phase 0 signatures, Phase 2 normalizers

25. `learning/conventions.rs` — LearnedDataAccessConventions, NamingConvention
26. `learning/variable_inference.rs` — VariableTableInferencer
27. `learning/learner.rs` — DataAccessLearner (framework + table + convention discovery)
28. `learning/mod.rs` — Learning phase orchestration
29. `validation/table_name.rs` — TableNameValidator

**Verify**: Learning phase correctly discovers frameworks, tables, and conventions
from sample codebases. Integration test with multi-framework project.

### Phase 6: Detection & Rules (Week 9)

**Dependencies**: All previous phases

30. `detection/detector.rs` — Main detection loop (per-file, rayon parallel)
31. `detection/mod.rs` — Detection phase orchestration
32. `rules/loader.rs` — Load rules from TOML + learned + defaults
33. `rules/learned.rs` — Auto-generate rules from access patterns
34. `rules/violations.rs` — Violation detection
35. `rules/mod.rs` — Rule engine orchestration

**Verify**: Full learn-then-detect pipeline works end-to-end on sample codebase.
Violations correctly detected against explicit and learned rules.

### Phase 7: Scoring, Flow & Engine (Week 10)

**Dependencies**: Phase 6 detection

36. `scoring/prioritizer.rs` — SecurityPrioritizer (summary generation)
37. `flow/transformations.rs` — FieldTransformation detection
38. `flow/mod.rs` — Field-level data flow tracking
39. `engine.rs` — BoundaryEngine: orchestrates learn + detect + store + report
40. `mod.rs` — Public API exports

**Verify**: Full boundary scan produces correct BoundaryScanResult with all fields
populated. Integration test against real-world sample projects (Prisma, Django, Spring).

### Phase 8: NAPI Integration (Week 11)

**Dependencies**: Phase 7 engine, drift-napi crate

41. `crates/drift-napi/src/bindings/boundaries.rs` — 5 NAPI functions
42. `crates/drift-napi/src/conversions/boundary_types.rs` — Type conversions
43. TS bridge types in `packages/drift/src/bridge/types.ts`

**Verify**: TS can call detect_boundaries(), query results, get security summary.
End-to-end test: TS → NAPI → Rust → drift.db → NAPI → TS.

### Dependency Graph

```
Phase 0 (Types/Infra)
  ↓
Phase 1 (Sensitive Detection) ──────────────────────────┐
  ↓                                                      │
Phase 2 (Normalizers) ← tree-sitter grammars (Parsers)  │
  ↓                                                      │
Phase 3 (Matchers) ← Phase 2                            │
  ↓                                                      │
Phase 4 (Extractors) ← tree-sitter grammars             │
  ↓                                                      │
Phase 5 (Learning) ← Phase 0, Phase 2                   │
  ↓                                                      │
Phase 6 (Detection + Rules) ← ALL previous              │
  ↓                                                      │
Phase 7 (Scoring + Flow + Engine) ← Phase 6, Phase 1 ←──┘
  ↓
Phase 8 (NAPI) ← Phase 7
```

---

## 24. v1 Feature Verification — Complete Gap Analysis

Cross-referenced against all v1 documentation and source files to ensure 100% feature
coverage in v2. Every v1 feature is accounted for: kept, upgraded, moved, or dropped
with explicit rationale.

### v1 Source Files Cross-Reference

**TypeScript (packages/core/src/boundaries/) — 12+ files:**

| v1 File | v1 Feature | v2 Status | v2 Location |
|---------|-----------|-----------|-------------|
| `boundary-scanner.ts` | Two-phase learn-then-detect orchestration | **KEPT** — Same architecture, ported to Rust | §3, engine.rs |
| `data-access-learner.ts` | Framework/table/convention/variable learning | **KEPT** — Ported to Rust with same learning flow | §3, §15, learning/ |
| `boundary-store.ts` | JSON shard persistence, access maps, rules, violations | **UPGRADED** — drift.db replaces JSON shards. Same data, better storage. | §16, storage.rs |
| `security-prioritizer.ts` | 4-tier risk classification, SecuritySummary | **KEPT** — Same 4 tiers, same logic, Rust port | §11, scoring/prioritizer.rs |
| `table-name-validator.ts` | Filters noise from detected table names | **KEPT** — Same validation rules, expanded blocklist | §14, validation/table_name.rs |
| `types.ts` | DataAccessPoint, ORMModel, SensitiveField, etc. | **UPGRADED** — Same types + new fields (unsafe_api, transformations, security_tier) | §13, types.rs |
| `field-extractors/index.ts` | Extractor registry | **KEPT** — ExtractorRegistry trait in Rust | extractors/mod.rs |
| `field-extractors/prisma-extractor.ts` | Prisma schema.prisma parsing | **KEPT** — Regex-based parser (not tree-sitter, Prisma isn't a PL) | extractors/prisma.rs |
| `field-extractors/django-extractor.ts` | Django models.py parsing | **KEPT** — Tree-sitter Python + pattern matching | extractors/django.rs |
| `field-extractors/sqlalchemy-extractor.ts` | SQLAlchemy declarative model parsing | **KEPT** — Tree-sitter Python + pattern matching | extractors/sqlalchemy.rs |
| `field-extractors/supabase-extractor.ts` | Supabase .from() table references | **KEPT** — Chain matching via SupabaseMatcher | extractors/supabase.rs |
| `field-extractors/gorm-extractor.ts` | Go struct tag parsing | **KEPT** — Tree-sitter Go + struct tag regex | extractors/gorm.rs |
| `field-extractors/diesel-extractor.ts` | Diesel table! macro parsing | **KEPT** — Tree-sitter Rust + macro pattern matching | extractors/diesel.rs |
| `field-extractors/raw-sql-extractor.ts` | SELECT/INSERT/UPDATE/DELETE column parsing | **KEPT** — Regex-based SQL parser | extractors/raw_sql.rs |

**TypeScript (packages/core/src/unified-provider/) — 25+ files:**

| v1 File | v1 Feature | v2 Status | v2 Location |
|---------|-----------|-----------|-------------|
| `unified-language-provider.ts` | Main provider class, normalizer + matcher orchestration | **KEPT** — Same architecture as Rust traits | normalizers/mod.rs, matchers/mod.rs |
| `unified-scanner.ts` | Drop-in replacement for SemanticDataAccessScanner | **ABSORBED** — No separate scanner; detection/detector.rs handles this | detection/detector.rs |
| `unified-data-access-adapter.ts` | Bridge to DataAccessPoint format | **DROPPED** — No adapter needed; Rust types are native | N/A |
| `legacy-extractors.ts` | Backward-compatible extractor aliases | **DROPPED** — No legacy compatibility needed in v2 | N/A |
| `legacy-scanner.ts` | Backward-compatible scanner wrapper | **DROPPED** — No legacy compatibility needed in v2 | N/A |
| `typescript-normalizer.ts` | TS/JS AST → UnifiedCallChain | **KEPT** — Ported to Rust tree-sitter | normalizers/typescript.rs |
| `python-normalizer.ts` | Python AST → UnifiedCallChain | **KEPT** — Ported to Rust tree-sitter | normalizers/python.rs |
| `java-normalizer.ts` | Java AST → UnifiedCallChain | **KEPT** — Ported to Rust tree-sitter | normalizers/java.rs |
| `csharp-normalizer.ts` | C# AST → UnifiedCallChain | **KEPT** — Ported to Rust tree-sitter | normalizers/csharp.rs |
| `php-normalizer.ts` | PHP AST → UnifiedCallChain | **KEPT** — Ported to Rust tree-sitter | normalizers/php.rs |
| `go-normalizer.ts` | Go AST → UnifiedCallChain | **KEPT** — Ported to Rust tree-sitter | normalizers/go.rs |
| `rust-normalizer.ts` | Rust AST → UnifiedCallChain | **KEPT** — Ported to Rust tree-sitter | normalizers/rust_lang.rs |
| `cpp-normalizer.ts` | C++ AST → UnifiedCallChain | **KEPT** — Ported to Rust tree-sitter | normalizers/cpp.rs |
| `base-normalizer.ts` | Abstract base normalizer | **KEPT** — BaseNormalizer (regex fallback) | normalizers/base.rs |
| `supabase-matcher.ts` | Supabase pattern matching | **KEPT** — Ported to Rust | matchers/supabase.rs |
| `prisma-matcher.ts` | Prisma pattern matching | **KEPT** — Ported to Rust | matchers/prisma.rs |
| `typeorm-matcher.ts` | TypeORM pattern matching | **KEPT** — Ported to Rust | matchers/typeorm.rs |
| `sequelize-matcher.ts` | Sequelize pattern matching | **KEPT** — Ported to Rust | matchers/sequelize.rs |
| `drizzle-matcher.ts` | Drizzle pattern matching | **KEPT** — Ported to Rust | matchers/drizzle.rs |
| `knex-matcher.ts` | Knex pattern matching | **KEPT** — Ported to Rust | matchers/knex.rs |
| `mongoose-matcher.ts` | Mongoose pattern matching | **KEPT** — Ported to Rust | matchers/mongoose.rs |
| `django-matcher.ts` | Django ORM pattern matching | **KEPT** — Ported to Rust | matchers/django.rs |
| `sqlalchemy-matcher.ts` | SQLAlchemy pattern matching | **KEPT** — Ported to Rust | matchers/sqlalchemy.rs |
| `efcore-matcher.ts` | EF Core pattern matching | **KEPT** — Ported to Rust | matchers/efcore.rs |
| `eloquent-matcher.ts` | Eloquent pattern matching | **KEPT** — Ported to Rust | matchers/eloquent.rs |
| `spring-data-matcher.ts` | Spring Data pattern matching | **KEPT** — Ported to Rust | matchers/spring_data.rs |
| `gorm-matcher.ts` | GORM pattern matching | **KEPT** — Ported to Rust | matchers/gorm.rs |
| `diesel-matcher.ts` | Diesel pattern matching | **KEPT** — Ported to Rust | matchers/diesel.rs |
| `seaorm-matcher.ts` | SeaORM pattern matching | **KEPT** — Ported to Rust | matchers/seaorm.rs |
| `sqlx-matcher.ts` | SQLx pattern matching | **KEPT** — Ported to Rust | matchers/sqlx.rs |
| `database-sql-matcher.ts` | Go database/sql pattern matching | **KEPT** — Ported to Rust | matchers/database_sql.rs |
| `raw-sql-matcher.ts` | Raw SQL pattern matching | **KEPT** — Ported to Rust | matchers/raw_sql.rs |
| `matcher-registry.ts` | Matcher registration and dispatch | **KEPT** — MatcherRegistry in Rust | matchers/mod.rs |


**Rust (crates/drift-core/src/boundaries/) — 4 files:**

| v1 File | v1 Feature | v2 Status | v2 Location |
|---------|-----------|-----------|-------------|
| `detector.rs` | Basic data access point detection from AST | **UPGRADED** — Full detection with normalizers + matchers + extractors | detection/detector.rs |
| `sensitive.rs` | Sensitive field pattern matching (4 categories) | **UPGRADED** — Expanded patterns (v1 ~30 → v2 ~100+), added false positive pipeline | detection/sensitive.rs, detection/false_positive.rs |
| `types.rs` | DataAccessPoint, SensitiveField, ORMModel | **UPGRADED** — Same types + new fields (confidence_breakdown, security_tier, unsafe_api, transformations) | types.rs |
| `mod.rs` | Module exports | **KEPT** — Expanded for new module structure | mod.rs |

### v1 Features NOT in Original v2 Prep (Gaps Found & Resolved)

These v1 features were identified during cross-referencing and needed explicit accounting:

**1. Learned Convention Caching**
v1's DataAccessLearner cached learned conventions across scans. If the codebase didn't
change, the learning phase was skipped entirely.
**Resolution**: Store learned conventions in drift.db. On subsequent scans, check if
source files changed (via scanner's mtime+hash). If no boundary-relevant files changed,
reuse cached conventions. Add `learned_conventions` table:
```sql
CREATE TABLE learned_conventions (
    id INTEGER PRIMARY KEY CHECK (id = 1),  -- Singleton
    frameworks TEXT NOT NULL,               -- JSONB array
    naming_convention TEXT NOT NULL,
    known_tables TEXT NOT NULL,             -- JSONB array
    variable_patterns TEXT NOT NULL,        -- JSONB map
    files_analyzed INTEGER NOT NULL,
    scan_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;
```

**2. Skip-Learning Mode**
v1 had `skipLearning: boolean` in BoundaryScannerConfig. When true, detection used
regex-only matching without the learning phase (faster but less accurate).
**Resolution**: Preserve as `BoundaryConfig.skip_learning: bool`. Default false.
When true, all 33 framework matchers run on every file (no framework filtering).
Useful for CI where speed matters more than precision.

**3. Test File Skipping**
v1's BoundaryScanner skipped test files during detection (files matching `*.test.*`,
`*.spec.*`, `__tests__/`, `test/`, etc.).
**Resolution**: Preserve. Add `BoundaryConfig.skip_test_files: bool` (default true)
and `BoundaryConfig.test_file_patterns: Vec<String>` with sensible defaults:
```rust
const DEFAULT_TEST_PATTERNS: &[&str] = &[
    "*.test.*", "*.spec.*", "*_test.*", "*_spec.*",
    "__tests__/**", "test/**", "tests/**", "spec/**",
    "**/*.test.ts", "**/*.spec.ts", "**/*.test.js", "**/*.spec.js",
    "**/*_test.go", "**/*_test.py", "**/test_*.py",
];
```

**4. Data Access File Pre-Filter**
v1 checked if a file was a "data access file" before running full detection. This
pre-filter looked for ORM import patterns and skipped files without them.
**Resolution**: Preserve. During the DETECT phase, before running normalizers and
matchers, check if the file contains any framework signature patterns (from the
LEARN phase's detected frameworks). Skip files that don't match. This is a fast
string search, not full AST parsing.

**5. BoundaryStore JSON Shard Persistence**
v1 persisted boundary data as JSON shards in the data lake.
**Resolution**: **DROPPED** — Replaced by drift.db (§16). All boundary data lives
in SQLite tables. This is consistent with the v2 storage architecture (02-STORAGE-V2-PREP.md).
No feature loss — same data, better storage.

**6. BoundaryStore Access Map Generation**
v1's BoundaryStore generated a DataAccessMap (aggregate view of all data access).
**Resolution**: **KEPT** — DataAccessMap is generated from drift.db queries after
detection completes. The `materialized_security` Gold table provides the aggregate
view. Per-table and per-file access info is queryable via `query_boundaries()`.

**7. BoundaryStore Violation Checking**
v1's BoundaryStore checked violations against stored rules.
**Resolution**: **KEPT** — Violation checking moved to `rules/violations.rs` (§10).
Same logic, runs during detection phase instead of as a separate store operation.

**8. SecurityPrioritizer Recommendations**
v1's SecurityPrioritizer generated human-readable recommendations (e.g., "Add boundary
rules for table 'users' — it contains PII fields").
**Resolution**: **KEPT** — SecuritySummary includes `top_risks: Vec<SecurityRisk>`
where each risk has a `reason` field with actionable text. The MCP tool
`drift_security_summary` exposes these recommendations.

**9. Reachability Integration (Sensitivity Propagation)**
v1's reachability engine used boundary detection's sensitivity classification to
determine which code paths reach sensitive data.
**Resolution**: **KEPT** — §21.2 defines the `export_sensitivity_map()` function
that provides sensitivity info to the reachability engine. Per BR1: "Add sensitivity
propagation (transitive sensitivity through call graph)."

**10. MCP Tool Integration**
v1 exposed 3 MCP tools: `drift_security_summary`, `drift_reachability`, `drift_boundaries`.
**Resolution**: **KEPT** — All 3 tools preserved. `drift_boundaries` queries from
drift.db via NAPI `query_boundaries()`. `drift_security_summary` reads from
`materialized_security` Gold table via `query_security_summary()`. Reachability
is a separate subsystem that consumes boundary data.

### New v2 Features NOT in v1

| New Feature | Why | Location |
|------------|-----|----------|
| Unsafe ORM API detection | OR1: detect raw SQL bypass per framework | §9, detection/unsafe_api.rs |
| CWE mapping on unsafe APIs | SAD4: every finding maps to CWE | §9, UnsafeApiUsage.cwe |
| Field-level data flow tracking | Audit: track fields through transformations | §12, flow/ |
| 5 new ORM frameworks | MikroORM, Kysely, sqlc, SQLBoiler, Qt SQL | §4, matchers/ |
| 3 new field extractors | EF Core, Hibernate, Eloquent (per OR5) | §6, extractors/ |
| Expanded sensitive patterns | ~30 → ~100+ patterns across 4 categories | §7 |
| False positive filter pipeline | 6 formal filters (v1 had ad-hoc filtering) | §7 |
| Taint sink export | Boundary → taint engine integration | §21.1 |
| Constraint data flow export | Boundary → constraints integration | §21.3 |
| Security quality gate criteria | Boundary → quality gate integration | §21.4 |
| drift.db persistence | SQLite replaces JSON shards | §16 |
| Keyset pagination on queries | Constant-time page retrieval | §17 |
| Structured error codes | BoundaryError enum with NAPI codes | §18 |
| Tracing instrumentation | Structured spans + metrics | §19 |
| DriftEventHandler events | 7 boundary-specific events | §20 |
| Learned convention caching | Skip learning when files unchanged | §24 Gap #1 |

### Feature Coverage Summary

| Category | v1 Count | v2 Count | Status |
|----------|---------|---------|--------|
| ORM frameworks | 28 | 33 | +5 new |
| Language normalizers | 9 | 9 | Parity (TS → Rust) |
| ORM matchers | 20 | 22 | +2 new (MikroORM, Kysely) + 2 detection-only (sqlc, SQLBoiler) |
| Field extractors | 7 | 10 | +3 new (EF Core, Hibernate, Eloquent) |
| Sensitivity categories | 4 | 4 | Parity (expanded patterns within each) |
| Sensitivity patterns | ~30 | ~100+ | 3x expansion |
| False positive filters | Ad-hoc | 6 formal | Formalized pipeline |
| Confidence factors | 5 | 5 | Parity (same weights) |
| Security tiers | 4 | 4 | Parity |
| Boundary rule sources | 2 (explicit, learned) | 3 (+default) | +1 |
| Violation types | 3 | 4 | +1 (ExplicitlyDenied) |
| NAPI functions | 2 (scan, scan_source) | 5 | +3 (query, sensitive, summary) |
| MCP tools | 3 | 3 | Parity |
| Storage | JSON shards | drift.db (6 tables) | Upgraded |
| **v1 features dropped** | — | **0** | **Zero feature loss** |

---

## 25. Performance Targets

| Metric | Target | Rationale |
|--------|--------|-----------|
| Learning phase (10K files) | < 500ms | File scanning + regex matching, parallelized |
| Detection phase (10K files) | < 3s | Tree-sitter parse + normalize + match, rayon parallel |
| Full boundary scan (10K files) | < 4s | Learn + detect + store |
| Sensitive field detection (1K fields) | < 10ms | Pattern matching, no I/O |
| Table name validation (1K candidates) | < 5ms | String operations, no I/O |
| Rule violation checking (1K access points × 100 rules) | < 50ms | Glob matching, no I/O |
| NAPI query_boundaries (100 results) | < 5ms | SQLite indexed query + serialization |
| NAPI query_sensitive_fields (all) | < 10ms | SQLite query + serialization |
| NAPI query_security_summary | < 1ms | Read from materialized Gold table |
| Memory usage (10K files) | < 200MB | Streaming detection, batch DB writes |
| drift.db boundary tables (10K files) | < 50MB | STRICT tables, JSONB for variable-length data |

### Performance Strategy

1. **Rayon parallelism** — Detection phase uses `rayon::par_iter` over files.
   Each file is independent (no shared mutable state during detection).
2. **Framework pre-filter** — Only run matchers for detected frameworks (from LEARN phase).
   For a project using Prisma + Supabase, skip 31 of 33 matchers per file.
3. **Batch DB writes** — Accumulate results in memory, write in batches via BatchWriter.
   One transaction per batch, not per access point.
4. **Learned convention caching** — Skip learning phase when files haven't changed.
5. **Early termination** — Skip files that don't contain any framework patterns.
6. **String interning** — Table names, field names, framework names are interned
   (via `lasso` crate) to avoid repeated allocations.

---

## 26. Open Items / Decisions Still Needed

1. **Prisma schema parser strategy**: Prisma's schema.prisma is not a programming language —
   tree-sitter doesn't have a grammar for it. v1 used regex. Should v2 use regex (simple,
   proven) or build a custom parser (more robust, handles edge cases)?
   **Recommendation**: Start with regex (proven by v1). If edge cases emerge, consider
   a simple hand-written recursive descent parser. Not worth a tree-sitter grammar for
   a single schema format.

2. **MongoDB/Mongoose field extraction**: Mongoose doesn't have a fixed schema — fields
   are defined at runtime. The MongooseMatcher can detect collection access but can't
   reliably extract field names. Should we attempt field extraction from Mongoose schemas
   (when defined) or mark Mongoose fields as "unknown"?
   **Recommendation**: Extract from explicit Mongoose schema definitions when present.
   For schemaless usage, mark fields as unknown and set confidence lower (0.5).

3. **Cross-file model resolution**: Some ORMs define models in one file and use them in
   another. v1 handled this within the learning phase (learned table names are global).
   v2 should do the same — but should we also resolve model imports to link usage to
   definition?
   **Recommendation**: Phase 1: Use learned table names (same as v1). Phase 2 (future):
   Integrate with call graph's import resolution to link model definitions to usage sites.
   This enables richer data flow tracking but isn't required for launch.

4. **Boundary rule format**: v2 uses `drift-boundaries.toml`. Should this be a standalone
   file or a section within `drift.toml`?
   **Recommendation**: Standalone `drift-boundaries.toml` in project root. Boundary rules
   can be large (one rule per sensitive table) and benefit from a dedicated file. Reference
   it from `drift.toml` via `boundaries.rules_file = "drift-boundaries.toml"`.

5. **Confidence threshold for storage**: Should all detected access points be stored in
   drift.db, or only those above a confidence threshold?
   **Recommendation**: Store all access points with confidence ≥ 0.3. Below 0.3 is almost
   certainly noise. The `query_boundaries()` NAPI function accepts `min_confidence` filter
   so consumers can set their own threshold. Default display threshold: 0.5.

6. **Unsafe API severity levels**: Should all unsafe API usages be the same severity, or
   should `$queryRawUnsafe` (always unsafe) be higher than `$queryRaw` with string concat
   (sometimes unsafe)?
   **Recommendation**: Two levels. Methods that are inherently unsafe (e.g., `$queryRawUnsafe`,
   `.extra()`) are `Severity::Error`. Methods that are conditionally unsafe (e.g., `$queryRaw`
   with string concat detected) are `Severity::Warning`. This matches the pattern in §9.

---

## 27. Summary of All Decisions

| # | Decision | Choice | Confidence | Source |
|---|----------|--------|------------|--------|
| 1 | Architecture | Everything in Rust, TS is presentation only | Very High | AD1, §2 |
| 2 | Two-phase pattern | Learn-then-detect preserved from v1 | Very High | §3, v1 proven |
| 3 | ORM coverage | 33 frameworks, 9 languages (28 v1 + 5 new) | High | §4, internet research |
| 4 | Unified provider | Rust traits: LanguageNormalizer + OrmMatcher | Very High | §5, v1 architecture |
| 5 | Field extractors | 10 extractors (7 v1 + 3 new per OR5) | High | §6, RECOMMENDATIONS |
| 6 | Sensitivity patterns | ~100+ patterns across 4 categories (3x v1) | High | §7, CP1 |
| 7 | False positive pipeline | 6 formal filters | High | §7, v1 ad-hoc → formalized |
| 8 | Confidence scoring | 5 weighted factors, same as v1 | Very High | §8, v1 proven |
| 9 | Unsafe API detection | Per-framework patterns with CWE mapping | High | §9, OR1, SAD4 |
| 10 | Boundary rules | 3 sources: explicit TOML + learned + defaults | High | §10 |
| 11 | Security tiers | 4 tiers: Critical/High/Medium/Low | Very High | §11, v1 proven |
| 12 | Field-level flow | 7 transformation types | Medium-High | §12, audit directive |
| 13 | Core types | DataAccessPoint, ORMModel, SensitiveField, BoundaryScanResult | Very High | §13, v1 types + extensions |
| 14 | Table validation | 10 rules + blocklist + convention matching | High | §14, v1 preserved |
| 15 | Variable inference | Suffix stripping + pluralization + learned mappings | High | §15, v1 preserved |
| 16 | Storage | 6 drift.db tables (STRICT, JSONB, indexed) | Very High | §16, 02-STORAGE-V2-PREP |
| 17 | NAPI interface | 5 functions per 03-NAPI-BRIDGE-V2-PREP §10.7 | Very High | §17 |
| 18 | Error handling | BoundaryError enum with 13 variants, structured codes | Very High | §18, AD6 |
| 19 | Tracing | Hierarchical spans, 5 log levels, DRIFT_LOG env var | Very High | §19, AD10 |
| 20 | Events | 7 boundary events via DriftEventHandler | High | §20, D5 |
| 21 | Integration points | 6 downstream consumers (taint, reachability, constraints, gates, N+1, contracts) | High | §21 |
| 22 | Module structure | 72 Rust files across 11 directories | High | §22 |
| 23 | Build order | 8 phases over ~11 weeks | High | §23 |
| 24 | v1 feature coverage | 100% — zero features dropped | Very High | §24 |
| 25 | Prisma parser | Regex (proven by v1), upgrade to RD parser if needed | Medium-High | §26 #1 |
| 26 | Confidence storage threshold | Store ≥ 0.3, display ≥ 0.5 | Medium-High | §26 #5 |
| 27 | Unsafe API severity | Error (inherently unsafe) vs Warning (conditionally unsafe) | High | §26 #6 |
| 28 | Boundary rules file | Standalone drift-boundaries.toml | Medium-High | §26 #4 |
| 29 | Skip-learning mode | Preserved as config flag (default false) | High | §24 Gap #2 |
| 30 | Test file skipping | Preserved as config flag (default true) | High | §24 Gap #3 |
| 31 | Convention caching | learned_conventions table in drift.db | High | §24 Gap #1 |
| 32 | Independence | Zero imports from cortex-napi/cortex-core (per D1) | Very High | D1, D4 |

---

*End of Boundary Detection V2 Implementation Prep.*
*Total v1 features accounted for: 100% (0 dropped, 10 gaps found and resolved).*
*Total v2 enhancements: 16 new capabilities.*
*Estimated build time: ~11 weeks (8 phases).*
