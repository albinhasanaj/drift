# Unified Analysis Engine — V2 Research & V1 Feature Audit

> Complete research document for Drift v2's Unified Analysis Engine (System 06).
> Covers: v1 feature inventory, 4-phase pipeline, visitor pattern, GAST normalization,
> declarative patterns, incremental computation, and all downstream integration points.
>
> Synthesized from: 01-rust-core/unified-analysis.md, 05-analyzers/core-analyzers.md,
> 05-analyzers/language-analyzers.md, 05-analyzers/unified-provider.md,
> 05-analyzers/rules-engine.md, DRIFT-V2-FULL-SYSTEM-AUDIT.md (Cat 01, 02, 03, 05),
> DRIFT-V2-STACK-HIERARCHY.md (Level 1), PLANNING-DRIFT.md (D1-D7, AD1-AD12),
> .research/01-rust-core/RECOMMENDATIONS.md (FA1, R2, R3, R4, R5, R18),
> .research/03-detectors/RECOMMENDATIONS.md (R1-R12),
> .research/05-analyzers/RECOMMENDATIONS.md (R1-R14),
> and internet research on Salsa incremental computation, Semgrep generic AST,
> and rust-analyzer architecture patterns.
>
> Purpose: Everything needed to understand what v1 does, what v2 must preserve,
> and what v2 upgrades. No feature loss. Decisions resolved. Build-ready.
> Generated: 2026-02-07

---

## Table of Contents

1. Architectural Position & Scope
2. V1 Complete Feature Inventory (What Must Be Preserved)
3. V1 4-Phase Pipeline — Detailed Breakdown
4. V1 Core Analyzers (AST, Type, Semantic, Flow)
5. V1 Unified Language Provider (9 Normalizers, 20 ORM Matchers)
6. V1 Per-Language Analyzers (10 Languages)
7. V1 Rules Engine & Evaluator
8. V1 String Interning System
9. V1 Resolution Index
10. V1 Type System & Data Models
11. V2 Architecture — What Changes
12. V2 Visitor Pattern Detection Engine
13. V2 Generic AST Normalization Layer (GAST)
14. V2 Declarative Pattern Definitions (TOML)
15. V2 Incremental Computation Model
16. V2 Bayesian Confidence & Momentum Scoring
17. V2 Taint Analysis Integration
18. V2 Fix Generation as First-Class Output
19. V2 Feedback Loop & Detector Health
20. V2 Cancellation Support
21. V2 Core Data Model & Type Definitions
22. V2 Interface Contracts (NAPI, Storage, Events)
23. V2 Build Order & Dependencies
24. V2 Performance Targets & Benchmarks
25. Cross-Reference: V1 Feature → V2 Location

---

## 1. Architectural Position & Scope

The Unified Analysis Engine is Level 1 — Structural Skeleton in the Drift v2 hierarchy.
It sits directly above the Level 0 bedrock (parsers, scanner, storage, NAPI, infrastructure)
and feeds into nearly every downstream system.

### What Lives Here

- 4-phase per-file analysis pipeline (AST patterns → string extraction → regex → resolution)
- Visitor pattern detection engine (single-pass AST traversal, all detectors as visitors)
- Generic AST Normalization Layer (GAST — ~30 normalized node types)
- Declarative pattern definitions (TOML-based, user-extensible)
- 4 core analyzers (AST structural, Type, Semantic scope/symbol, Flow CFG/dataflow)
- Unified Language Provider (9 language normalizers, 20 ORM/framework matchers)
- Per-language framework-aware analyzers (10 languages)
- String interning (lasso — ThreadedRodeo for build, RodeoReader for query)
- Resolution index (cross-file function resolution)
- String literal analysis (RegexSet on extracted strings, never raw source)
- Incremental computation model (content-hash skipping, Salsa-inspired queries)
- Cancellation support (revision counter pattern from rust-analyzer)

### What Does NOT Live Here

- Detector trait system (16 categories × 3 variants) → Detector System (separate)
- Pattern aggregation & deduplication → Pattern Intelligence (Level 2A)
- Bayesian confidence scoring → Pattern Intelligence (Level 2A)
- Outlier detection (Z-Score/Grubbs'/IQR) → Pattern Intelligence (Level 2A)
- Learning system (dominant convention discovery) → Pattern Intelligence (Level 2A)
- Call graph builder → Call Graph (Level 1, separate)
- Rules engine evaluator → Enforcement (Level 3)
- Quality gates → Enforcement (Level 3)
- Violation feedback loop → Enforcement (Level 3)
- MCP tool routing → Presentation (Level 5)

### Downstream Consumers (All Depend on Unified Analysis)

| Consumer | What It Reads | Why |
|----------|--------------|-----|
| Detector System | DetectedPattern[], FilePatterns, GAST nodes | Detectors register as visitors on the engine |
| Pattern Aggregation | Per-file DetectedPattern[] | Groups per-file matches into project-level patterns |
| Confidence Scoring | Pattern frequency, consistency, spread data | Computes Bayesian posterior from detection results |
| Outlier Detection | Pattern location distributions | Statistical deviation analysis |
| Rules Engine | PatternMatchResult[], Violation[] | Evaluates patterns against files for violations |
| Call Graph Builder | ResolutionIndex, FunctionEntry[] | Cross-file function resolution for call edges |
| Boundary Detection | ORM patterns from Unified Language Provider | Data access point discovery |
| DNA System | Per-file convention fingerprints | Gene extraction from detection results |
| Constraint Detection | Invariant patterns from detection | Mines constraints from detected patterns |
| Context Generation | Pattern summaries, file analysis | AI-ready context from analysis data |
| Taint Analysis | String literal analysis, data flow | Source/sink identification |

### Upstream Dependencies (Must Exist Before Unified Analysis)

| Dependency | What It Provides | Why Needed |
|-----------|-----------------|------------|
| Parsers (Level 0) | ParseResult with full AST, FunctionInfo, ClassInfo, ImportInfo, ExportInfo, CallSite | Raw extraction data for all 4 phases |
| Scanner (Level 0) | File list with content hashes, ScanDiff | Input files + incremental change detection |
| Storage (Level 0) | DatabaseManager, batch writer | Persistence of detection results to drift.db |
| String Interning (Level 1) | ThreadedRodeo / RodeoReader, PathInterner, FunctionInterner | Memory-efficient identifiers |
| Infrastructure (Level 0) | thiserror, tracing, DriftEventHandler, config | Error handling, observability, events |

---

## 2. V1 Complete Feature Inventory (What Must Be Preserved)

This is the exhaustive list of every feature, capability, algorithm, data structure,
and behavior in v1 that v2 must account for. Nothing here can be dropped without
explicit justification.

### 2.1 Unified Analyzer (Rust — `crates/drift-core/src/unified/`)

| Feature | V1 Status | V2 Action |
|---------|-----------|-----------|
| 4-phase per-file pipeline | ✅ Implemented | PRESERVE — proven architecture |
| Phase 1: AST pattern detection via tree-sitter queries | ✅ 9 languages | PRESERVE + EXPAND (add GAST layer) |
| Phase 2: String extraction from AST (>3 chars) | ✅ Implemented | PRESERVE |
| Phase 3: Regex on extracted strings (RegexSet) | ✅ 4 pattern sets (SQL 9, routes 6, sensitive 8, env 6) | PRESERVE + ADD logging (4 patterns compiled but unused in v1) |
| Phase 4: Resolution index building | ✅ Implemented | PRESERVE + WIRE UP stats tracking (v1 TODO) |
| Parallel execution via rayon | ✅ Implemented | PRESERVE + FIX parser pool (v1 creates new parser per thread) |
| Pre-compiled tree-sitter queries | ✅ All compiled at init | PRESERVE |
| Per-language query sets (9 languages) | ✅ TS, JS, Py, Java, C#, PHP, Go, Rust, C++ | PRESERVE all + add C |
| String context determination (7 contexts) | ✅ FunctionArgument, VariableAssignment, ObjectProperty, Decorator, ReturnValue, ArrayElement, Unknown | PRESERVE all 7 |
| Confidence scoring per detection method | ✅ AST: 0.85-0.95, SQL: 0.9, Routes: 0.85, Sensitive: 0.8, Env: 0.85 | PRESERVE baseline values |
| Resolution algorithm (same-file → exported → ambiguous) | ✅ Implemented | PRESERVE + ADD import-based, DI, fuzzy strategies |
| UnifiedOptions (patterns, categories, parallel, threads) | ✅ Implemented | PRESERVE + ADD incremental mode |
| UnifiedResult (file_patterns, resolution, call_graph, metrics) | ✅ Implemented | PRESERVE + ADD violation data (v1 always empty) |
| FilePatterns (file, language, patterns, violations, timing) | ✅ Implemented | PRESERVE |
| AnalysisMetrics (files, lines, parse/detect/resolve/total time) | ✅ Implemented | PRESERVE + ADD per-phase breakdown |
| Violation type (id, pattern_id, severity, file, line, message, expected, actual, fix) | ✅ Defined but never populated | IMPLEMENT (v1 gap) |
| Log patterns RegexSet (4 patterns) | ✅ Compiled but unused | IMPLEMENT (v1 gap — wire into analyze()) |

### 2.2 AST Pattern Queries — Complete Per-Language Inventory

Every single AST query from v1 must be preserved. This is the detection foundation.

#### TypeScript (4 queries)
| Pattern Type | Category | Confidence | Matches |
|-------------|----------|------------|---------|
| auth-decorator | Auth | 0.95 | @Auth, @RequireAuth, @Authenticated, @Protected, @Guard |
| middleware-usage | Auth | 0.90 | .use(auth), .use(protect), .use(guard), .use(verify), .use(session) |
| express-route | Api | 0.90 | .get("/"), .post("/"), .put(), .patch(), .delete(), .all() |
| try-catch | Errors | 0.95 | try { } catch (e) { } |

#### JavaScript (2 queries)
| Pattern Type | Category | Confidence | Matches |
|-------------|----------|------------|---------|
| express-route | Api | 0.90 | Same as TypeScript |
| try-catch | Errors | 0.95 | Same as TypeScript |

#### Python (4 queries)
| Pattern Type | Category | Confidence | Matches |
|-------------|----------|------------|---------|
| fastapi-depends | Auth | 0.90 | Depends(auth_function) |
| auth-decorator | Auth | 0.95 | @login_required, @requires_auth, @authenticated, @permission_required |
| fastapi-route | Api | 0.90 | @app.get("/"), @app.post(), etc. |
| try-except | Errors | 0.95 | try: ... except ExceptionType as e: |

#### Java (4 queries)
| Pattern Type | Category | Confidence | Matches |
|-------------|----------|------------|---------|
| spring-security | Auth | 0.95 | @PreAuthorize, @Secured, @RolesAllowed, @PermitAll, @DenyAll |
| spring-route | Api | 0.95 | @RequestMapping, @GetMapping, @PostMapping, @PutMapping, @DeleteMapping, @PatchMapping |
| jpa-entity | DataAccess | 0.95 | @Entity, @Table, @Repository, @Query |
| try-catch | Errors | 0.95 | try { } catch (ExceptionType e) { } |

#### C# (3 queries)
| Pattern Type | Category | Confidence | Matches |
|-------------|----------|------------|---------|
| authorize-attribute | Auth | 0.95 | [Authorize], [AllowAnonymous] |
| aspnet-route | Api | 0.95 | [HttpGet], [HttpPost], [HttpPut], [HttpDelete], [HttpPatch], [Route] |
| ef-entity | DataAccess | 0.95 | [Table], [Key], [Column], [ForeignKey], [DbContext] |

#### PHP (3 queries)
| Pattern Type | Category | Confidence | Matches |
|-------------|----------|------------|---------|
| laravel-middleware | Auth | 0.90 | ->middleware('auth') |
| laravel-route | Api | 0.90 | Route::get(), Route::post(), etc. |
| eloquent-model | DataAccess | 0.90 | class X extends Model |

#### Go (2 queries)
| Pattern Type | Category | Confidence | Matches |
|-------------|----------|------------|---------|
| http-handler | Api | 0.90 | .HandleFunc(), .Handle(), .Get(), .Post(), .Put(), .Delete(), .Patch() |
| error-check | Errors | 0.90 | if err != nil { } |

#### Rust (3 queries)
| Pattern Type | Category | Confidence | Matches |
|-------------|----------|------------|---------|
| actix-route | Api | 0.90 | #[get], #[post], #[put], #[delete], #[patch], #[route] |
| result-match | Errors | 0.85 | match expr? { } |
| derive-attribute | DataAccess | 0.80 | #[derive(...)] |

#### C++ (2 queries)
| Pattern Type | Category | Confidence | Matches |
|-------------|----------|------------|---------|
| try-catch | Errors | 0.95 | try { } catch (ExceptionType) { } |
| cpp-route | Api | 0.85 | CROW_ROUTE, route calls |

**Total v1 AST queries: 27 across 9 languages. All must be preserved in v2.**

### 2.3 String Literal Analysis — Complete Regex Inventory

#### SQL Patterns (9 regexes) → Category: DataAccess, Confidence: 0.9
```
(?i)SELECT\s+.+\s+FROM\s+\w+
(?i)INSERT\s+INTO\s+\w+
(?i)UPDATE\s+\w+\s+SET
(?i)DELETE\s+FROM\s+\w+
(?i)CREATE\s+TABLE\s+\w+
(?i)ALTER\s+TABLE\s+\w+
(?i)DROP\s+TABLE\s+\w+
(?i)JOIN\s+\w+\s+ON
(?i)WHERE\s+\w+\s*[=<>]
```

#### Route Patterns (6 regexes) → Category: Api, Confidence: 0.85
```
^/api/v?\d*/
^/api/(?:admin|user|account|auth|profile|settings)
^/(?:dashboard|admin|settings|profile|billing)
^/auth/(?:login|logout|register|reset|verify)
:\w+                    ← path params like :id
\{[^}]+\}              ← path params like {userId}
```

#### Sensitive Data Patterns (8 regexes) → Category: Security, Confidence: 0.8
```
(?i)password|passwd|pwd
(?i)secret|private[_-]?key
(?i)api[_-]?key|apikey
(?i)access[_-]?token|auth[_-]?token
(?i)credit[_-]?card|card[_-]?number
(?i)ssn|social[_-]?security
(?i)bearer\s+
(?i)authorization
```

#### Environment Patterns (6 regexes) → Category: Config, Confidence: 0.85
```
(?i)process\.env\.\w+
(?i)os\.environ\[
(?i)getenv\(
(?i)env\(
(?i)\$\{[A-Z_]+\}
(?i)%[A-Z_]+%
```

#### Log Patterns (4 regexes) → Category: Logging, Confidence: 0.85 (v1: COMPILED BUT UNUSED)
```
(?i)console\.(log|error|warn|info|debug)
(?i)logger\.(log|error|warn|info|debug)
(?i)logging\.(log|error|warn|info|debug)
(?i)log\.(error|warn|info|debug)
```

**Total v1 string patterns: 33 regexes across 5 sets. All must be preserved + log patterns wired up.**

### 2.4 String Extraction — Node Kinds Per Language

| Language | String Node Kinds |
|----------|-------------------|
| TypeScript/JavaScript | `string`, `template_string` |
| Python | `string`, `concatenated_string` |
| Java/C# | `string_literal` |
| PHP | `string`, `encapsed_string` |
| Go | `interpreted_string_literal`, `raw_string_literal` |
| Rust | `string_literal`, `raw_string_literal` |
| C/C++ | `string_literal`, `raw_string_literal` |

**Filter: strings shorter than 4 characters are discarded. Quotes are stripped.**


### 2.5 Core Analyzers (4 Engines — All Must Be Preserved)

These are the 4 foundational analysis engines from `packages/core/src/analyzers/`.
In v1 they are TypeScript. In v2 they move to Rust. Every capability must be preserved.

#### AST Analyzer (~800 lines TS)
| Method | Purpose | V2 Action |
|--------|---------|-----------|
| findPattern(ast, pattern, options) | Structural pattern matching | MOVE TO RUST — tree-sitter query patterns |
| compareSubtrees(node1, node2, options) | Subtree similarity scoring (0-1) | MOVE TO RUST |
| getStats(ast) | Node count, depth, leaf count, type distribution | MOVE TO RUST |
| traverse(ast, visitor) | Walk AST with visitor callback | REPLACE — visitor pattern engine |
| findNodesByType(ast, type) | Find all nodes of a given type | MOVE TO RUST |
| findNodeAtPosition(ast, position) | Find node at cursor position | MOVE TO RUST (LSP needs this) |
| getDescendants(node) | All descendants of a node | MOVE TO RUST |
| getNodeDepth(ast, node) | Depth of a node in the tree | MOVE TO RUST |
| getParentChain(ast, node) | Ancestors from root to node | MOVE TO RUST |
| analyze(ast, patterns) | Run multiple patterns, return matches with confidence | REPLACE — visitor pattern engine |

ASTPattern interface (must be preserved in Rust equivalent):
```
nodeType: string           — Required tree-sitter node type
text?: string | RegExp     — Text content match
children?: ASTPattern[]    — Child pattern requirements
minChildren?: number
maxChildren?: number
hasChild?: string          — Must have child of this type
notHasChild?: string       — Must NOT have child of this type
depth?: number             — Expected depth
metadata?: Record<string, unknown>
```

#### Type Analyzer (~1600 lines TS)
| Method | Purpose | V2 Action |
|--------|---------|-----------|
| extractType(node, options) | Extract TypeInfo from AST node | MOVE TO RUST — per-language |
| analyzeTypes(ast, options) | Full type analysis of a file | MOVE TO RUST |
| isSubtypeOf(type1, type2) | Structural subtype check | MOVE TO RUST |
| areTypesCompatible(type1, type2) | Compatibility check (looser) | MOVE TO RUST |
| getTypeCoverage(ast) | % of typed locations | MOVE TO RUST |
| analyzeTypeRelationships(ast) | Inheritance, implementation, composition | MOVE TO RUST |
| areTypesEquivalent(type1, type2) | Structural equivalence | MOVE TO RUST |

Type kinds handled (all must be preserved):
primitives, references, unions, intersections, arrays, tuples, functions, objects,
literals, type parameters (generics), unknown

TypeInfo structure fields (all must be preserved):
kind, text, name, members, parameters, returnType, elementType, types,
typeArguments, constraint, defaultType, isOptional, isReadonly, isExported

**V2 critical change**: v1 Type Analyzer is TypeScript-only. V2 must implement per-language
type extraction via `TypeSystem` trait (R4 from analyzers recommendations). Start with
TypeScript, Python, Java, Go. Each language implements the trait.

#### Semantic Analyzer (~1350 lines TS)
| Method | Purpose | V2 Action |
|--------|---------|-----------|
| analyze(ast, options) | Full semantic analysis | MOVE TO RUST |
| resolveSymbol(name, scopeId) | Resolve symbol in scope chain | MOVE TO RUST — critical for call resolution |
| getVisibleSymbols(scopeId) | All symbols visible in scope | MOVE TO RUST |
| getScopeAtPosition(position) | Find scope at cursor position | MOVE TO RUST (LSP needs this) |

What it builds (all must be preserved):
1. Scope tree — nested scopes (global → module → function → block → etc.)
2. Symbol table — all declarations with type, visibility, mutability, references
3. Reference resolution — links identifier uses to declarations
4. Shadowed variable detection

Scope types (11 — all must be preserved):
global, module, function, method, class, block, for-loop, if-branch, switch-case, try, catch

Symbol collection sources (all must be preserved):
function declarations (async, generator), arrow functions, method definitions,
class declarations (with members), field definitions, variable declarations
(const/let/var with mutability tracking), destructuring patterns (object and array),
import declarations (named, default, namespace), export declarations,
interface declarations, type alias declarations, enum declarations

**V2 critical change**: v1 Semantic Analyzer is TypeScript-only. V2 must implement
per-language scope resolution via `ScopeResolver` trait. Critical for call resolution
accuracy — the call graph depends on this.

#### Flow Analyzer (~1600 lines TS)
| Method | Purpose | V2 Action |
|--------|---------|-----------|
| analyze(ast, options) | Full flow analysis | MOVE TO RUST |
| analyzeFunction(node, options) | Per-function flow analysis | MOVE TO RUST |
| getNodes() / getEdges() | CFG access | MOVE TO RUST |
| isNodeReachable(nodeId) | Reachability check | MOVE TO RUST |
| getPredecessors/getSuccessors | CFG navigation | MOVE TO RUST |

CFG node types (all must be preserved):
entry, exit, statement (expression, declaration, assignment), branch (if/else, switch/case),
loop (for, for-in/of, while, do-while), exception (try/catch/finally), return, throw, break, continue

CFG edge types (8 — all must be preserved):
normal, true-branch, false-branch, exception, break, continue, return, throw

Data flow capabilities (all must be preserved):
- Variable definitions (where assigned)
- Variable uses (where read)
- Reaching definitions (which definitions reach each use)
- Null dereference detection

Issue detection (4 types — all must be preserved):
- Unreachable code
- Infinite loops
- Missing returns
- Null dereferences

**V2 critical change**: v1 Flow Analyzer is intraprocedural only. V2 adds interprocedural
data flow via function summaries (R6 from analyzers recommendations). Per-language
lowering to normalized IR, separate from analysis algorithms.

### 2.6 Unified Language Provider (9 Normalizers, 20 ORM Matchers)

The Unified Language Provider is the most sophisticated extraction system in v1.
It normalizes AST differences across languages into a universal `UnifiedCallChain`
representation, enabling language-agnostic ORM/framework pattern matching.

#### 9 Language Normalizers (all must be preserved)
| Normalizer | Language | V2 Action |
|-----------|----------|-----------|
| typescript-normalizer | TypeScript/JavaScript | MOVE TO RUST — LanguageNormalizer trait |
| python-normalizer | Python | MOVE TO RUST |
| java-normalizer | Java | MOVE TO RUST |
| csharp-normalizer | C# | MOVE TO RUST |
| php-normalizer | PHP | MOVE TO RUST |
| go-normalizer | Go | MOVE TO RUST |
| rust-normalizer | Rust | MOVE TO RUST |
| cpp-normalizer | C++ | MOVE TO RUST |
| base-normalizer | Abstract base | MOVE TO RUST — becomes trait |

#### 20 ORM/Framework Matchers (all must be preserved)
| Matcher | ORM/Framework | Languages | V2 Action |
|---------|---------------|-----------|-----------|
| supabase-matcher | Supabase | TS/JS | MOVE TO RUST — OrmMatcher trait |
| prisma-matcher | Prisma | TS/JS | MOVE TO RUST |
| typeorm-matcher | TypeORM | TS/JS | MOVE TO RUST |
| sequelize-matcher | Sequelize | TS/JS | MOVE TO RUST |
| drizzle-matcher | Drizzle | TS/JS | MOVE TO RUST |
| knex-matcher | Knex | TS/JS | MOVE TO RUST |
| mongoose-matcher | Mongoose | TS/JS | MOVE TO RUST |
| django-matcher | Django ORM | Python | MOVE TO RUST |
| sqlalchemy-matcher | SQLAlchemy | Python | MOVE TO RUST |
| efcore-matcher | Entity Framework Core | C# | MOVE TO RUST |
| eloquent-matcher | Laravel Eloquent | PHP | MOVE TO RUST |
| spring-data-matcher | Spring Data JPA | Java | MOVE TO RUST |
| gorm-matcher | GORM | Go | MOVE TO RUST |
| diesel-matcher | Diesel | Rust | MOVE TO RUST |
| seaorm-matcher | SeaORM | Rust | MOVE TO RUST |
| sqlx-matcher | SQLx | Rust | MOVE TO RUST |
| raw-sql-matcher | Raw SQL | All | MOVE TO RUST |
| database-sql-matcher | database/sql | Go | MOVE TO RUST |
| base-matcher | Abstract base | — | MOVE TO RUST — becomes trait |
| matcher-registry | Registry | — | MOVE TO RUST |

Key concept: `UnifiedCallChain` — universal representation of method call sequences
(e.g., `supabase.from('users').select('*').eq('id', userId)`). Matchers analyze these
chains to detect ORM patterns and extract table names, operations, and fields.

### 2.7 Per-Language Analyzers (10 Languages)

Each language has a dedicated analyzer that extracts framework-aware patterns.
All extraction capabilities must be preserved in v2.

#### TypeScript/JavaScript (~8 files)
Extracts: routes (Express/Fastify/NestJS), components (React/Vue/Svelte),
hooks (custom React hooks), error patterns, data access (7 ORMs), decorators (NestJS/TypeORM)

Types: TSRoute, TSComponent, TSHook, TSErrorPattern, TSDataAccessPoint, TSDecorator

#### Python (~4 files)
Extracts: routes (Django/Flask/FastAPI), error handling (try/except, custom exceptions),
data access (Django ORM, SQLAlchemy, raw SQL), decorators, async patterns

Types: PyRoute, PyErrorPattern, PyDataAccessPoint, PyDecorator

#### Java (~3 files)
Extracts: routes (Spring Boot), JPA entities, Hibernate patterns

#### C# (via unified-provider)
Extracts: ASP.NET routes, Entity Framework entities

#### PHP (~4 files)
Extracts: routes (Laravel), Eloquent models, PHP 8 attributes, docblocks

#### Go (2 files)
Extracts: routes (Gin/Echo/Chi/net/http), error handling (if err != nil),
interfaces, data access (GORM/sqlx/database/sql), goroutines

Types: GoRoute, GoErrorPattern, GoInterface, GoGoroutine

#### Rust (2 files + test)
Extracts: routes (Actix/Axum), error patterns (Result<T,E>, ? operator),
traits, async functions, crate usage

Types: RustRoute, RustErrorPattern, RustTrait, RustAsyncFunction

#### C++ (2 files)
Extracts: classes (hierarchies, virtual methods), memory patterns (new/delete, smart pointers),
templates, virtual methods

Types: CppClass, CppMemoryPattern, CppTemplate, CppVirtualMethod

#### WPF/XAML (~8 files — most complex)
Extracts: XAML controls/bindings/resources/styles, ViewModel linking, MVVM analysis,
binding errors, resource dictionaries, dependency properties, data flow through bindings

**V2 decision**: WPF/XAML is the most complex language analyzer. It requires a dedicated
tree-sitter grammar for XAML parsing. Evaluate priority based on user demand.

### 2.8 Rules Engine & Evaluator

The rules engine is the enforcement layer that consumes unified analysis output.
While the evaluator core moves to Rust, the orchestration stays in TS.

#### Evaluator Pipeline (must be preserved)
```
1. checkMatch(input, pattern) → boolean
2. getMatchDetails(input, pattern) → MatchDetails[]
3. evaluate(input, pattern) → EvaluationResult
   a. Create matcher context
   b. Convert pattern to PatternDefinition
   c. Run pattern matcher → PatternMatchResult[]
   d. Find violations (outliers from established pattern)
   e. Determine severity
   f. Generate quick fixes
   g. Return EvaluationResult
4. evaluateAll(input, patterns[]) → EvaluationResult[]
5. evaluateFiles(files[], patterns[]) → EvaluationSummary
```

#### Violation Sources (3 — all must be preserved)
1. Outlier locations — statistical deviations from pattern
2. Missing patterns — file should have pattern but doesn't
3. Outlier location details — specific code deviating from expected form

#### Rule Engine Limits (must be preserved)
- maxViolationsPerPattern: 100
- maxViolationsPerFile: 50
- Deduplication by `patternId:file:range` key

#### Severity Defaults (must be preserved)
| Category | Default |
|----------|---------|
| security | error |
| auth | error |
| errors | warning |
| api | warning |
| data-access | warning |
| testing | info |
| logging | info |
| documentation | hint |
| styling | hint |
| (all others) | warning |

#### Quick Fix Generator — 7 Strategies (all must be preserved)
| Strategy | Confidence | What It Does |
|----------|------------|-------------|
| Replace | Pattern-based | Replace code at violation range |
| Wrap | 0.6 | Wrap in try/catch, if-check, function |
| Extract | 0.5 | Extract into named function/variable |
| Import | 0.7 | Add missing import |
| Rename | 0.7 | Rename to match convention |
| Move | 0.4 | Move code to different location |
| Delete | 0.5 | Remove unnecessary code |

#### Variant Manager (must be preserved)
- 3 scopes: global, directory, file
- Lifecycle: create → activate/deactivate → query → expire → delete
- Expiration support via `expires_at` timestamp
- V2 change: persistence moves from `.drift/variants/` JSON to drift.db

### 2.9 String Interning System

#### V1 Implementation (custom)
```rust
pub struct StringInterner {
    map: HashMap<String, Symbol>,    // string → symbol (dedup lookup)
    strings: Vec<String>,           // symbol.0 → string (reverse lookup)
    next_id: AtomicU32,
}
```

Methods: intern(&mut self, s: &str) → Symbol, resolve(&self, sym: Symbol) → Option<&str>,
memory_stats() → InternerStats

PathInterner: normalizes `\` → `/` before interning. Default capacity: 4096.
FunctionInterner: supports intern_qualified(class, method). Default capacity: 8192.

Claims 60-80% memory reduction for large codebases.

#### V2 Change
Replace custom interner with `lasso` crate:
- `ThreadedRodeo` during build/scan phase (mutable, concurrent)
- `RodeoReader` for query/read phase (immutable, contention-free)
- Keep PathInterner and FunctionInterner as domain wrappers

### 2.10 Resolution Index

#### V1 Data Structures
```rust
pub struct ResolutionIndex {
    name_index: BTreeMap<Symbol, SmallVec<[FunctionId; 4]>>,
    entries: FxHashMap<FunctionId, FunctionEntry>,
    file_index: FxHashMap<Symbol, Vec<FunctionId>>,
    path_interner: PathInterner,
    func_interner: FunctionInterner,
    next_id: u32,
}
```

#### V1 Resolution Algorithm
```
1. Look up name symbol in name_index → Not found? Unresolved
2. Get candidate FunctionIds → Empty? Unresolved → Exactly 1? Resolved
3. Prefer same-file: any candidate's file == caller_file → Resolved
4. Prefer exported: filter to exported → Exactly 1? Resolved
5. Multiple remain → Ambiguous(all candidates)
```

#### V1 FunctionEntry
```rust
pub struct FunctionEntry {
    pub id: FunctionId,
    pub name: Symbol,
    pub qualified_name: Option<Symbol>,
    pub file: Symbol,
    pub line: u32,
    pub is_exported: bool,
    pub is_async: bool,
}
```

#### V1 Resolution Enum
Resolved(ResolvedFunction) | Ambiguous(Vec<ResolvedFunction>) | Unresolved

#### V1 IndexStats
unique_names, total_functions, files, exported_functions

#### V1 Gaps (must be fixed in v2)
- ResolutionStats fields initialized to 0 with TODO comments — never wired up
- No import-based resolution strategy
- No DI injection resolution strategy
- No fuzzy name matching for dynamic calls
- No method call resolution via class hierarchy


### 2.11 Type System & Data Models (Complete)

#### Language Enum (10 variants — all must be preserved)
TypeScript, JavaScript, Python, Java, CSharp, Php, Go, Rust, Cpp, C

Extension mapping (all must be preserved):
- ts|tsx|mts|cts → TypeScript
- js|jsx|mjs|cjs → JavaScript
- py|pyi → Python
- java → Java
- cs → CSharp
- php → Php
- go → Go
- rs → Rust
- cpp|cc|cxx|c++|hpp|hxx|hh → Cpp
- c|h → C

#### PatternCategory Enum (15 variants in v1, 16 in v2)
V1: Api, Auth, Components, Config, DataAccess, Documentation, Errors, Logging,
Performance, Security, Structural, Styling, Testing, Types, Validation

V2 adds: Accessibility (ARIA patterns, semantic HTML, keyboard navigation)

**Critical**: v1 data-models.md lists 15 categories explicitly including "validation".
The audit doc lists 16 (adds accessibility). Ensure "validation" is NOT dropped.

#### DetectionMethod Enum (3 variants)
AstQuery (primary), RegexFallback (secondary), Structural (file/directory patterns)

#### DetectedPattern (all fields must be preserved)
category, pattern_type, subcategory, file, line (1-indexed), column (1-indexed),
end_line, end_column, matched_text, confidence (0.0-1.0), detection_method,
metadata (optional HashMap)

#### StringLiteral (from Phase 2)
value, file, line, column, context (StringContext enum)

#### StringContext Enum (7 variants — all must be preserved)
FunctionArgument, VariableAssignment, ObjectProperty, Decorator, ReturnValue,
ArrayElement, Unknown

---

## 3. V2 Architecture — What Changes

This section defines every architectural change from v1 to v2. The principle is:
preserve all v1 capabilities, upgrade the architecture, add new capabilities.

### 3.1 The Big Picture: V1 → V2 Transformation

```
V1 Architecture:
  Rust: 4-phase pipeline (27 AST queries, 33 regex patterns, resolution index)
  TS:   4 core analyzers (AST, Type, Semantic, Flow) — ~5350 lines
  TS:   9 language normalizers + 20 ORM matchers — ~3000 lines
  TS:   10 per-language analyzers — ~4000 lines
  TS:   Rules engine + evaluator — ~4980 lines
  TS:   350+ detector files — ~50000+ lines

V2 Architecture:
  Rust: 4-phase pipeline (PRESERVED + expanded)
       + Visitor pattern engine (NEW — replaces per-detector traversal)
       + GAST normalization layer (NEW — ~30 node types, 10 normalizers)
       + 4 core analyzers (MOVED from TS)
       + 9 language normalizers + 20 ORM matchers (MOVED from TS)
       + 10 per-language analyzers (MOVED from TS)
       + Declarative pattern definitions (NEW — TOML-based)
       + Incremental computation (NEW — content-hash + Salsa-inspired)
       + Taint analysis integration (NEW)
       + Cancellation support (NEW)
       + Rules engine evaluator core (MOVED from TS)
  TS:   Rules engine orchestration (severity, variants, limits) — THIN
  TS:   Quick fix generation (text manipulation) — THIN
  TS:   MCP tool routing — THIN
```

### 3.2 Key Architectural Decisions Affecting This System

| Decision | Source | Impact on Unified Analysis |
|----------|--------|---------------------------|
| AD1: Incremental-First | Audit | 3-layer incrementality: file-level skip, pattern re-scoring, convention re-learning |
| AD2: Single Canonical Data Model | Audit | One ParseResult, one Pattern, one FunctionEntry — Rust defines, NAPI serializes |
| AD3: Declarative Patterns (TOML) | Audit | Ship hardcoded defaults + user custom patterns without recompiling |
| AD4: Visitor Pattern for Detection | Audit | Single-pass AST traversal, all detectors as visitors. O(files × nodes × handlers) |
| AD8: Bayesian Confidence | Audit | Beta(1+k, 1+n-k) posterior + momentum replaces static scoring |
| AD10: Observability-First | Audit | tracing crate for every phase, per-language timing |
| AD12: Performance Data Structures | Audit | FxHashMap, SmallVec, BTreeMap, xxhash, lasso, Moka cache |
| D1: Standalone Independence | Planning | Zero Cortex dependency. Writes to drift.db only |
| D5: Trait-Based Events | Planning | DriftEventHandler with on_scan_complete, on_pattern_detected |
| R1 (Detectors): Visitor Pattern | .research | ESLint-style single-pass traversal |
| R4 (Detectors): GAST | .research | Semgrep-inspired generic AST normalization |
| R1 (Analyzers): Salsa Queries | .research | Incremental computation framework |
| R2 (Analyzers): Layered Architecture | .research | syntax → hir-def/hir-ty → hir → ide layers |
| R3 (Analyzers): Taint Analysis | .research | Source/sink/sanitizer model integrated into pipeline |

---

## 4. V2 Visitor Pattern Detection Engine

### The Problem V1 Has

V1 runs each detector independently against each file's AST. With 100+ enabled detectors,
this means 100+ traversals of the same AST per file. For 10,000 files:
`O(10,000 files × 100 detectors × AST_nodes) = 1,000,000+ traversals`

### The V2 Solution

Single-pass AST traversal with all detectors registered as visitors. Detectors declare
which node types they care about. The engine traverses once and dispatches to all
registered handlers per node.

```
V1: O(files × detectors × AST_nodes)
V2: O(files × AST_nodes × handlers_per_node)
```

Since most detectors care about 2-5 node types, `handlers_per_node` is typically 2-5.
This is the single most impactful performance optimization (10-100x improvement).

### Core Trait

```rust
/// Every detector implements this trait. The engine calls on_enter/on_exit
/// during a single depth-first traversal of the AST.
pub trait DetectorHandler: Send + Sync {
    /// Which AST node types this handler wants to visit.
    /// The engine only calls on_enter/on_exit for matching types.
    fn node_types(&self) -> &[&str];

    /// Called when entering a node of a registered type.
    fn on_enter(&mut self, node: &Node, ctx: &DetectionContext);

    /// Called when leaving a node of a registered type.
    fn on_exit(&mut self, node: &Node, ctx: &DetectionContext);

    /// Collect results after traversal completes.
    fn results(&self) -> Vec<PatternMatch>;

    /// Optional: generate fixes for detected violations.
    fn generate_fix(&self, violation: &Violation, ctx: &DetectionContext) -> Option<Fix>;

    /// Percentage of violations this detector can auto-fix.
    fn fix_coverage(&self) -> f64 { 0.0 }
}
```

### Detection Engine

```rust
pub struct DetectionEngine {
    /// Node type → list of handlers interested in that type.
    handlers: FxHashMap<String, Vec<Box<dyn DetectorHandler>>>,

    /// File-level handlers that need the full file context (not per-node).
    file_handlers: Vec<Box<dyn FileDetectorHandler>>,

    /// Cancellation token for long-running analysis.
    cancel: CancellationToken,
}

impl DetectionEngine {
    /// Register a detector handler. Automatically indexes by node types.
    pub fn register(&mut self, handler: Box<dyn DetectorHandler>) {
        for node_type in handler.node_types() {
            self.handlers
                .entry(node_type.to_string())
                .or_default()
                .push(handler.clone());
        }
    }

    /// Single-pass traversal of the AST, dispatching to all registered handlers.
    pub fn analyze(&mut self, tree: &Tree, source: &[u8], ctx: &DetectionContext)
        -> Result<Vec<PatternMatch>, AnalysisError>
    {
        self.cancel.check()?;

        // Depth-first traversal
        let mut cursor = tree.walk();
        self.traverse_recursive(&mut cursor, source, ctx)?;

        // Collect results from all handlers
        let mut results = Vec::new();
        for handlers in self.handlers.values() {
            for handler in handlers {
                results.extend(handler.results());
            }
        }

        // Run file-level handlers
        for handler in &mut self.file_handlers {
            self.cancel.check()?;
            results.extend(handler.analyze_file(tree, source, ctx)?);
        }

        Ok(results)
    }

    fn traverse_recursive(
        &mut self,
        cursor: &mut TreeCursor,
        source: &[u8],
        ctx: &DetectionContext,
    ) -> Result<(), AnalysisError> {
        let node = cursor.node();
        let node_type = node.kind();

        // Dispatch on_enter to interested handlers
        if let Some(handlers) = self.handlers.get(node_type) {
            for handler in handlers.iter_mut() {
                handler.on_enter(&node, ctx);
            }
        }

        // Recurse into children
        if cursor.goto_first_child() {
            loop {
                self.cancel.check()?;
                self.traverse_recursive(cursor, source, ctx)?;
                if !cursor.goto_next_sibling() { break; }
            }
            cursor.goto_parent();
        }

        // Dispatch on_exit to interested handlers
        if let Some(handlers) = self.handlers.get(node_type) {
            for handler in handlers.iter_mut() {
                handler.on_exit(&node, ctx);
            }
        }

        Ok(())
    }
}
```

### File-Level Handler Variant

Some detectors need full-file context (not per-node). These run after the traversal:

```rust
pub trait FileDetectorHandler: Send + Sync {
    fn analyze_file(
        &mut self,
        tree: &Tree,
        source: &[u8],
        ctx: &DetectionContext,
    ) -> Result<Vec<PatternMatch>, AnalysisError>;
}
```

### Learning Detector Two-Pass Model

Learning detectors need a learn pass (scan all files to discover conventions) then a
detect pass (flag deviations). The visitor pattern applies to the detect pass.
The learn pass runs first as a separate file-level scan.

```rust
pub trait LearningDetectorHandler: DetectorHandler {
    /// Phase 1: Learn conventions from the codebase.
    /// Called once per file during the learning pass.
    fn learn(&mut self, tree: &Tree, source: &[u8], ctx: &DetectionContext);

    /// Phase 2: Finalize learned conventions after all files processed.
    fn finalize_learning(&mut self);

    /// Phase 3: on_enter/on_exit from DetectorHandler trait run during detect pass.
}
```

### DetectionContext

```rust
pub struct DetectionContext<'a> {
    pub file: &'a str,
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
```

### Integration with 4-Phase Pipeline

The visitor pattern engine becomes Phase 1.5 — it runs AFTER the existing Phase 1
(AST pattern detection via pre-compiled queries) and BEFORE Phase 2 (string extraction).
The pre-compiled queries remain as the fast path for simple patterns. The visitor engine
handles complex, stateful, multi-node patterns.

```
File → tree-sitter parse → ParseResult
  Phase 1:   Pre-compiled tree-sitter queries (fast, simple patterns)
  Phase 1.5: Visitor pattern engine (complex, stateful patterns)
  Phase 2:   String extraction from AST
  Phase 3:   Regex on extracted strings
  Phase 4:   Resolution index population
```

---

## 5. V2 Generic AST Normalization Layer (GAST)

### The Problem

V1 has per-language AST queries (27 across 9 languages) and per-language detectors
(350+ TS files). Many detectors are language-specific variants of the same concept
(e.g., try-catch detection exists separately for JS, Python, Java, Go, Rust, C++).
Adding a new language requires writing 100+ new detectors.

### The Solution

A Generic AST (GAST) normalization layer between tree-sitter parsing and detection,
inspired by Semgrep's `ast_generic`. Source: [Semgrep architecture](https://semgrep.dev/docs/contributing/contributing-code/)

```
Source Code → tree-sitter → Language-Specific CST → GAST Normalizer → Generic AST → Detectors
```

### ~30 Normalized Node Types

```rust
/// Generic AST node types covering ~80% of detection needs.
/// Language-specific detectors kept for truly unique patterns.
pub enum GASTNode {
    // Declarations
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

    // Control Flow
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

    // Expressions
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

    // Module System
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

    // Data
    StringLiteral { value: String, context: StringContext },
    NumberLiteral { value: f64, raw: String },
    TemplateLiteral { parts: Vec<TemplatePart> },
    ObjectLiteral { properties: Vec<Property> },
    ArrayLiteral { elements: Vec<Expr> },

    // Framework-Aware
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

    // Statements
    Return { value: Option<Expr> },
    Throw { value: Expr },
    VariableDecl {
        name: String,
        kind: VarKind,  // Const, Let, Var, Val, Final
        type_annotation: Option<TypeRef>,
        initializer: Option<Expr>,
    },

    // Block
    Block { statements: Vec<GASTNode> },
}
```

### Per-Language Normalizers

Each language implements the `GASTNormalizer` trait:

```rust
pub trait GASTNormalizer: Send + Sync {
    fn language(&self) -> Language;
    fn normalize(&self, tree: &Tree, source: &[u8]) -> Vec<GASTNode>;
}
```

10 normalizers required (one per language). Adding a new language requires only
a normalizer (~500-1000 lines) — all existing GAST-based detectors work automatically.

### What Stays Language-Specific

Some patterns are truly language-unique and should NOT be normalized:
- PHP attributes (PHP 8 specific syntax)
- Rust lifetimes and ownership patterns
- Go goroutines and channels
- C++ templates and RAII patterns
- Python decorators with complex argument patterns
- WPF/XAML bindings

These keep dedicated language-specific detectors that run alongside GAST detectors.

### Reduction Impact

GAST reduces the detector codebase by 50-70%. Instead of 6 separate try-catch detectors
(JS, Python, Java, Go, Rust, C++), one GAST-based TryCatch detector handles all languages.


---

## 6. V2 Declarative Pattern Definitions (TOML)

### Architecture Decision AD3

Ship with hardcoded defaults (all v1 patterns). Users add custom patterns via TOML
without recompiling. Tree-sitter query syntax as the pattern language.

### TOML Format — Graduated Complexity

#### Level 1: Simple Node Match
```toml
[[patterns]]
id = "express-route"
language = "typescript"
category = "Api"
confidence = 0.90
query = '(call_expression function: (member_expression property: (property_identifier) @method (#match? @method "^(get|post|put|patch|delete|all)$")) arguments: (arguments (string) @path))'
```

#### Level 2: Structural Parent-Child
```toml
[[patterns]]
id = "spring-security"
language = "java"
category = "Auth"
confidence = 0.95
query = '(annotation name: (identifier) @name (#match? @name "^(PreAuthorize|Secured|RolesAllowed|PermitAll|DenyAll)$"))'
```

#### Level 3: Predicate Matching
```toml
[[patterns]]
id = "fastapi-depends-auth"
language = "python"
category = "Auth"
confidence = 0.90
query = '(call function: (identifier) @func (#eq? @func "Depends") arguments: (argument_list (identifier) @dep (#match? @dep "auth|protect|guard|verify")))'
```

#### Level 4: Cross-Reference Constraints
```toml
[[patterns]]
id = "unprotected-route"
language = "typescript"
category = "Security"
confidence = 0.85
query = '(call_expression function: (member_expression property: (property_identifier) @method (#match? @method "^(get|post|put|patch|delete)$")))'
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

### Loading Strategy

1. Load hardcoded defaults (all v1 patterns compiled into binary)
2. Load project-level TOML from `.drift/patterns/*.toml`
3. Load user-level TOML from `~/.drift/patterns/*.toml`
4. Merge: user patterns override project patterns override defaults
5. Compile all tree-sitter queries at startup (fail fast on invalid queries)
6. Store compiled patterns in Moka cache for reuse across files

### Pattern Metadata

Every pattern (hardcoded or TOML) carries:
```toml
[[patterns]]
id = "unique-16-char-hex"
language = "typescript"        # or "any" for GAST patterns
category = "Auth"              # one of 16 categories
confidence = 0.95              # 0.0-1.0
severity = "error"             # error|warning|info|hint (optional, default from category)
description = "Human-readable description"
cwe_ids = [287]                # CWE mapping for security patterns
owasp = "A01:2021"             # OWASP mapping (optional)
fix_suggestion = "Add @Auth decorator"  # Optional fix hint
tags = ["framework:spring", "security"]  # Searchable tags
```

---

## 7. V2 Incremental Computation Model

### Three-Layer Incrementality (AD1)

#### Layer 1 — File-Level Skip (Content Hash)
```
if file.content_hash == previous_scan.content_hash:
    reuse previous detection results for this file
    skip all 4 phases entirely
```

Implementation: `file_metadata` table in drift.db stores `(file_path, content_hash, last_analyzed)`.
On scan: compare xxhash of file content against stored hash. Only re-analyze changed files.

Two-level change detection:
- Level 1: mtime comparison (instant, catches most changes)
- Level 2: content hash (catches mtime-only changes from git operations)

#### Layer 2 — Pattern-Level Re-Scoring
```
When files change:
    Re-detect only changed files
    Re-aggregate only patterns that had locations in changed files
    Re-score only affected patterns
    Keep all other pattern scores unchanged
```

Implementation: `pattern_locations` table tracks which patterns have locations in which files.
When file X changes, query `SELECT DISTINCT pattern_id FROM pattern_locations WHERE file = X`,
then re-aggregate only those patterns.

#### Layer 3 — Convention Re-Learning (Threshold-Based)
```
Track convention stability across scans:
    If <10% of files changed: skip re-learning, reuse conventions
    If 10-30% changed: incremental re-learning (update distributions)
    If >30% changed: full re-learning
```

### Salsa-Inspired Query Model

While full Salsa integration is evaluated (high complexity), the core principle is adopted:
define analysis as queries with explicit inputs and outputs, cache results, invalidate
on input change.

```rust
/// Analysis queries — each is a pure function of its inputs.
/// Results are cached and invalidated when inputs change.
pub trait AnalysisQueries {
    /// Input: file content (set by scanner)
    fn file_content(&self, file: FileId) -> Arc<String>;

    /// Derived: parse result (cached, invalidated when file_content changes)
    fn parse(&self, file: FileId) -> Arc<ParseResult>;

    /// Derived: per-file detection results
    fn detect(&self, file: FileId) -> Arc<Vec<DetectedPattern>>;

    /// Derived: per-file string literals
    fn strings(&self, file: FileId) -> Arc<Vec<StringLiteral>>;

    /// Derived: per-file string analysis results
    fn string_patterns(&self, file: FileId) -> Arc<Vec<DetectedPattern>>;

    /// Derived: resolution index entries for this file
    fn resolution_entries(&self, file: FileId) -> Arc<Vec<FunctionEntry>>;
}
```

### Function-Body Isolation

Following rust-analyzer's invariant: "typing inside a function's body never invalidates
global derived data." Achieve this by separating function signatures (module-level)
from function bodies (local).

Implementation: `body_hash` field on FunctionInfo. When only a function body changes
(not its signature), only that function's analysis is invalidated — cross-file analysis
(call graph, coupling) is preserved.

### Cancellation Pattern

Global revision counter. When inputs change, increment revision. Long-running queries
check the counter and cancel if stale.

```rust
use std::sync::atomic::{AtomicU64, Ordering};

static REVISION: AtomicU64 = AtomicU64::new(0);

pub struct CancellationToken {
    revision_at_start: u64,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self { revision_at_start: REVISION.load(Ordering::SeqCst) }
    }

    pub fn check(&self) -> Result<(), Cancelled> {
        if REVISION.load(Ordering::SeqCst) != self.revision_at_start {
            Err(Cancelled)
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

Insert `cancel.check()?` at key points: between phases, between files in parallel scan,
at loop boundaries in traversal. Catch `Cancelled` at NAPI boundary and return
appropriate error to TypeScript.

### Moka Cache for Parse Results

Content-addressed parse cache using Moka (TinyLFU + LRU):
- Cache key: `(file_path, content_hash)`
- Cache value: full `ParseResult`
- Capacity: 10K entries
- Durable: serialize via bincode to SQLite blob column for persistence across restarts

```rust
use moka::sync::Cache;

pub struct ParseCache {
    cache: Cache<(Spur, u64), Arc<ParseResult>>,  // (interned_path, content_hash) → result
}
```

---

## 8. V2 Bayesian Confidence & Momentum Scoring

### V1 Baseline (Must Be Preserved as Fallback)
```
score = frequency × 0.40 + consistency × 0.30 + age × 0.15 + spread × 0.15
```

Levels: high ≥ 0.85, medium ≥ 0.70, low ≥ 0.50, uncertain < 0.50

### V2 Target: Bayesian Posterior + Momentum

```
posterior = Beta(1 + k, 1 + n - k)
    where k = files matching convention, n = total files analyzed

posterior_mean = (1 + k) / (2 + n)

momentum = (current_freq - prev_freq) / max(prev_freq, 0.01)
momentum_normalized = clamp((momentum + 1) / 2, 0, 1)

consistency = std_dev_of_per_directory_frequencies (inverted, normalized [0,1])

final_score = posterior_mean × 0.70 + consistency × 0.15 + momentum × 0.15
```

### Graduated Tiers (Replace v1 Levels)
| Tier | Criteria | Meaning |
|------|----------|---------|
| Established | mean > 0.7, CI width < 0.15 | Strong convention, enforce |
| Emerging | mean > 0.5, CI width < 0.25 | Growing convention, suggest |
| Tentative | mean > 0.3, CI width < 0.40 | Possible convention, inform |
| Uncertain | else | Not enough evidence |

### Credible Interval Width
```
CI_width = 2 × 1.96 × sqrt(α × β / ((α + β)² × (α + β + 1)))
    where α = 1 + k, β = 1 + n - k
```

### Storage
Store posterior parameters (α, β) per pattern in drift.db for incremental updates
without full recalculation. On new scan: α_new = α_old + new_successes,
β_new = β_old + new_failures.

### Contested Convention Handling
When two conventions are close in frequency (gap < 20%):
- Report both as "contested" rather than picking one as dominant
- Generate "inconsistency" finding rather than violations against either
- Suggest the team make a deliberate choice

### Momentum Activation
Momentum only active after 3+ scans with 50+ files. Before that, use v1 baseline
formula as fallback. This prevents noisy momentum signals from small codebases.

---

## 9. V2 Taint Analysis Integration

### How Taint Analysis Connects to Unified Analysis

The unified analysis engine provides two critical inputs to taint analysis:

1. **String literal analysis (Phase 3)** identifies potential sinks:
   - SQL patterns → SQL injection sinks
   - Route patterns → SSRF sinks
   - Sensitive data patterns → data exposure sinks

2. **Resolution index (Phase 4)** enables cross-file taint tracking:
   - Function resolution connects taint sources to sinks across files
   - Import/export tracking follows taint through module boundaries

### Source/Sink/Sanitizer Registry (TOML)

```toml
# Sources — where untrusted data enters
[[taint.sources]]
id = "express-request-body"
language = "typescript"
pattern = '(member_expression object: (identifier) @obj (#eq? @obj "req") property: (property_identifier) @prop (#match? @prop "^(body|query|params|headers)$"))'
taint_type = "UserInput"

[[taint.sources]]
id = "django-request-post"
language = "python"
pattern = '(attribute object: (identifier) @obj (#eq? @obj "request") attribute: (identifier) @attr (#match? @attr "^(POST|GET|data|query_params)$"))'
taint_type = "UserInput"

# Sinks — where untrusted data is dangerous
[[taint.sinks]]
id = "sql-query-construction"
category = "SqlInjection"
cwe = 89
languages = ["typescript", "javascript", "python", "java", "csharp", "php", "go", "rust"]
# Matched via string literal analysis Phase 3 SQL patterns

# Sanitizers — functions that make data safe
[[taint.sanitizers]]
id = "express-validator"
language = "typescript"
functions = ["body", "param", "query", "check", "validationResult"]
module = "express-validator"
sanitizes = ["SqlInjection", "XSS"]

[[taint.sanitizers]]
id = "dompurify"
language = "typescript"
functions = ["sanitize"]
module = "dompurify"
sanitizes = ["XSS"]
```

### Phase 1 — Intraprocedural (Build First)
For each function, build mini data-flow graph. Track taint through assignments and
calls within a single function. Report taint flows as DetectedPattern with category
Security and source→sink path metadata.

### Phase 2 — Interprocedural (Build Second)
Produce taint summaries per function (which parameters taint which return values).
Propagate across function boundaries via call graph. Requires call graph to be built.

### 4 Vulnerability Detectors
1. SQL Injection: HTTP params → ORM raw methods (CWE-89)
2. XSS: user input → innerHTML/template rendering (CWE-79)
3. SSRF: user input → HTTP client URL (CWE-918)
4. Path Traversal: user input → filesystem path (CWE-22)

---

## 10. V2 Fix Generation as First-Class Output

### Architecture Decision

Every detector should produce optional `Fix` alongside violations. Fixes are not
an afterthought — they are a core output. Google's data: developers apply automated
fixes ~3,000 times per day on Tricorder.

### Fix Kind Enum

```rust
pub enum FixKind {
    /// Exact text replacement — high confidence, safe to auto-apply
    TextEdit { range: Range, new_text: String },

    /// Multi-location edit — all edits must be applied together
    MultiEdit { edits: Vec<TextEdit>, description: String },

    /// Symbol rename across files
    Rename { old_name: String, new_name: String, scope: RenameScope },

    /// Import addition/removal
    ImportChange { action: ImportAction, module: String, specifiers: Vec<String> },

    /// Structural — move code, extract function, etc.
    Structural { description: String, edits: Vec<TextEdit> },

    /// Suggestion — human must decide, AI can help
    Suggestion { description: String, options: Vec<FixOption> },
}
```

### Fix Safety Levels
| Level | Description | Auto-Apply? |
|-------|-------------|-------------|
| 1 | Pure formatting, naming convention, import ordering | Yes |
| 2 | Code structure changes, pattern migration | With review |
| 3 | Architectural changes, security fixes that may change behavior | Suggestion only |

### Fix Struct

```rust
pub struct Fix {
    pub kind: FixKind,
    pub confidence: f64,
    pub is_safe: bool,
    pub safety_level: u8,        // 1, 2, or 3
    pub description: String,
    pub detector_id: String,
}
```

### Detector Contract (Updated)

```rust
pub trait Detector {
    fn detect(&self, ctx: &DetectionContext) -> DetectionResult;

    /// Optional but strongly encouraged. Detectors without fixes
    /// are flagged in the detector health dashboard.
    fn generate_fix(&self, violation: &Violation, ctx: &DetectionContext) -> Option<Fix>;

    fn fix_coverage(&self) -> f64;
}
```

### V1 Quick Fix Strategies (All Preserved)
Replace (pattern-based), Wrap (0.6), Extract (0.5), Import (0.7), Rename (0.7),
Move (0.4), Delete (0.5)

### V2 New Fix Strategies
- AddTypeAnnotation — infer type, add annotation
- ConvertToAsync — transform .then().catch() to async/await
- ParameterizeQuery — convert string concatenation to parameterized query
- AddErrorHandling — wrap in try/catch with appropriate error type
- AddAuthCheck — add authentication middleware/decorator

### Batch Fix CLI
```
drift fix --auto              # Apply all Level 1 fixes
drift fix --review            # Apply Level 1+2 with diff preview
drift fix --category=security # Fix only security violations
drift fix --detector=<id>     # Fix specific detector
```

### Target: 80%+ of violations should have at least one fix suggestion.

---

## 11. V2 Feedback Loop & Detector Health

### Violation Action Tracking

```rust
pub enum ViolationAction {
    Fixed,          // Developer fixed the violation
    Dismissed,      // Developer explicitly dismissed
    Ignored,        // Developer saw but took no action
    AutoFixed,      // Quick fix was applied
    NotSeen,        // Violation was never displayed
}
```

### Effective False-Positive Rate Per Detector

```
effective_fp_rate = (dismissed + ignored) / (fixed + dismissed + ignored + auto_fixed)
```

### Detector Health Policy
- Alert when FP rate exceeds 10%
- Auto-disable detectors with >20% FP rate for 30+ days
- Surface "most useful" and "least useful" detectors via MCP
- Track per-detector health in `detector_health` table in drift.db

### Feedback Storage
```sql
CREATE TABLE violation_actions (
    violation_id TEXT NOT NULL,
    detector_id TEXT NOT NULL,
    action TEXT NOT NULL,  -- Fixed, Dismissed, Ignored, AutoFixed, NotSeen
    timestamp TEXT NOT NULL,
    time_to_action_ms INTEGER,
    PRIMARY KEY (violation_id)
) STRICT;

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

### DriftEventHandler Integration (D5)
```rust
// Events emitted by the unified analysis engine
trait DriftEventHandler {
    fn on_detection_complete(&self, result: &DetectionResult) {}
    fn on_violation_detected(&self, violation: &Violation) {}
    fn on_violation_fixed(&self, violation_id: &str) {}
    fn on_violation_dismissed(&self, violation_id: &str) {}
    fn on_detector_disabled(&self, detector_id: &str, reason: &str) {}
    fn on_pattern_detected(&self, pattern: &DetectedPattern) {}
}
```


---

## 12. V2 Core Data Model & Type Definitions

### Updated UnifiedOptions

```rust
pub struct UnifiedOptions {
    pub patterns: Vec<String>,              // File globs (empty = "**/*")
    pub categories: Vec<PatternCategory>,   // Filter categories (empty = all)
    pub max_resolution_depth: u32,          // Call graph depth limit
    pub parallel: bool,                     // Use rayon parallelism
    pub threads: usize,                     // Thread count (0 = auto)
    pub include_violations: bool,           // Include violation detection
    pub incremental: bool,                  // NEW: enable incremental mode
    pub custom_patterns: Vec<PathBuf>,      // NEW: additional TOML pattern files
    pub enable_taint: bool,                 // NEW: enable taint analysis
    pub enable_gast: bool,                  // NEW: enable GAST normalization
    pub cancellation_token: Option<CancellationToken>, // NEW
}
```

### Updated UnifiedResult

```rust
pub struct UnifiedResult {
    pub file_patterns: Vec<FilePatterns>,
    pub resolution: ResolutionStats,
    pub call_graph: CallGraphSummary,
    pub metrics: AnalysisMetrics,
    pub total_patterns: u64,
    pub total_violations: u64,
    pub taint_flows: Vec<TaintFlow>,        // NEW
    pub skipped_files: u64,                 // NEW: files skipped by incremental
    pub cache_hits: u64,                    // NEW: parse cache hits
}
```

### Updated FilePatterns

```rust
pub struct FilePatterns {
    pub file: String,
    pub language: Language,
    pub patterns: Vec<DetectedPattern>,
    pub violations: Vec<Violation>,         // NOW POPULATED (v1 was always empty)
    pub fixes: Vec<Fix>,                    // NEW
    pub parse_time_us: u64,
    pub detect_time_us: u64,
    pub gast_time_us: u64,                  // NEW
    pub string_time_us: u64,               // NEW: Phase 2+3 timing
    pub resolve_time_us: u64,              // NEW: Phase 4 timing
}
```

### Updated AnalysisMetrics

```rust
pub struct AnalysisMetrics {
    pub files_processed: u64,
    pub files_skipped: u64,                // NEW: incremental skip count
    pub total_lines: u64,
    pub parse_time_ms: u64,
    pub detect_time_ms: u64,
    pub gast_time_ms: u64,                 // NEW
    pub string_extract_time_ms: u64,       // NEW
    pub string_analyze_time_ms: u64,       // NEW
    pub resolve_time_ms: u64,
    pub total_time_ms: u64,
    pub cache_hit_rate: f32,               // NEW
    pub patterns_per_language: FxHashMap<Language, u64>, // NEW
}
```

### Updated PatternCategory (16 variants)

```rust
pub enum PatternCategory {
    Api, Auth, Components, Config, DataAccess, Documentation,
    Errors, Logging, Performance, Security, Structural,
    Styling, Testing, Types, Validation,
    Accessibility,  // NEW in v2
}
```

### Updated DetectedPattern

```rust
pub struct DetectedPattern {
    pub category: PatternCategory,
    pub pattern_type: String,
    pub subcategory: Option<String>,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub end_line: u32,
    pub end_column: u32,
    pub matched_text: String,
    pub confidence: f32,
    pub detection_method: DetectionMethod,
    pub metadata: Option<FxHashMap<String, serde_json::Value>>,
    pub cwe_ids: Vec<u32>,                 // NEW: CWE mapping
    pub owasp: Option<String>,             // NEW: OWASP mapping
    pub fix: Option<Fix>,                  // NEW: suggested fix
    pub taint_flow: Option<TaintFlowRef>,  // NEW: taint analysis reference
}
```

### Updated DetectionMethod (4 variants)

```rust
pub enum DetectionMethod {
    AstQuery,           // Pre-compiled tree-sitter query (Phase 1)
    VisitorPattern,     // Visitor engine detection (Phase 1.5) — NEW
    RegexFallback,      // Regex on extracted strings (Phase 3)
    Structural,         // File/directory pattern analysis
}
```

### Updated Resolution Index

```rust
pub struct ResolutionIndex {
    name_index: BTreeMap<Spur, SmallVec<[FunctionId; 4]>>,
    entries: FxHashMap<FunctionId, FunctionEntry>,
    file_index: FxHashMap<Spur, Vec<FunctionId>>,
    import_index: FxHashMap<Spur, Vec<ImportResolution>>,  // NEW
    class_hierarchy: FxHashMap<Spur, ClassInfo>,            // NEW: for MRO resolution
    interner: Arc<ThreadedRodeo>,
    next_id: AtomicU32,
}
```

### Updated FunctionEntry

```rust
pub struct FunctionEntry {
    pub id: FunctionId,
    pub name: Spur,                        // Interned via lasso
    pub qualified_name: Option<Spur>,
    pub file: Spur,
    pub line: u32,
    pub end_line: u32,                     // NEW
    pub is_exported: bool,
    pub is_async: bool,
    pub is_entry_point: bool,              // NEW
    pub is_data_accessor: bool,            // NEW
    pub body_hash: u64,                    // NEW: for function-level incrementality
    pub signature_hash: u64,               // NEW: for cross-file invalidation
    pub decorators: SmallVec<[Spur; 2]>,   // NEW
    pub parameters: SmallVec<[ParamInfo; 4]>, // NEW
}
```

### Updated Resolution Algorithm (6 Strategies)

```
1. Same-file (High confidence)
   If any candidate's file == caller_file → Resolved

2. Method call via class hierarchy (High confidence) — NEW
   If call is obj.method(), resolve via class hierarchy MRO

3. DI injection (Medium-High confidence) — NEW
   FastAPI Depends, Spring @Autowired, NestJS @Inject

4. Import-based (Medium confidence) — NEW
   Follow import chains to resolve

5. Export-based (Medium confidence)
   Filter to exported candidates

6. Fuzzy name matching (Low confidence) — NEW
   Name similarity for dynamic calls, last resort
```

### ResolutionStats (NOW WIRED UP — v1 was TODO)

```rust
pub struct ResolutionStats {
    pub total_calls: u64,
    pub resolved_calls: u64,
    pub resolution_rate: f32,
    pub same_file_resolutions: u64,
    pub method_call_resolutions: u64,      // NEW
    pub di_resolutions: u64,               // NEW
    pub import_resolutions: u64,           // NEW
    pub export_resolutions: u64,
    pub fuzzy_resolutions: u64,            // NEW
    pub unresolved_calls: u64,
    pub ambiguous_calls: u64,              // NEW
}
```

---

## 13. V2 Interface Contracts (NAPI, Storage, Events)

### NAPI Interface

```rust
/// Primary NAPI entry point for unified analysis.
/// Called from TypeScript: const result = await analyzeUnified(root, options);
#[napi]
pub async fn analyze_unified(
    root: String,
    options: JsUnifiedOptions,
) -> Result<JsUnifiedResult, napi::Error> {
    // 1. Convert JS options to Rust options
    // 2. Create cancellation token
    // 3. Run analysis (parallel via rayon)
    // 4. Convert Rust result to JS result
    // 5. Emit DriftEventHandler::on_detection_complete
}

/// Incremental analysis — only re-analyze changed files.
#[napi]
pub async fn analyze_unified_incremental(
    root: String,
    changed_files: Vec<String>,
    options: JsUnifiedOptions,
) -> Result<JsUnifiedResult, napi::Error> {
    // 1. Load cached results for unchanged files
    // 2. Re-analyze only changed files
    // 3. Merge results
    // 4. Update cache
}

/// Batch analysis — multiple analysis types in one NAPI call.
#[napi]
pub async fn analyze_batch(
    root: String,
    analyses: Vec<String>,  // ["unified", "call_graph", "boundaries", ...]
    options: JsBatchOptions,
) -> Result<JsBatchResult, napi::Error> {
    // Shares parsed results across analysis types
}
```

### Storage Interface (drift.db Tables)

```sql
-- Per-file detection results (for incremental caching)
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

-- Pattern scan history (for momentum calculation)
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

-- Bayesian posterior parameters
CREATE TABLE pattern_posteriors (
    pattern_id TEXT PRIMARY KEY,
    alpha REAL NOT NULL DEFAULT 1.0,
    beta REAL NOT NULL DEFAULT 1.0,
    last_updated TEXT NOT NULL
) STRICT;

-- Custom TOML pattern definitions
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

### Event Interface (DriftEventHandler)

The unified analysis engine emits these events via the DriftEventHandler trait.
In standalone mode, these are no-ops. When the bridge is active, they become
Cortex memories.

```rust
pub trait UnifiedAnalysisEvents {
    /// Emitted after full analysis completes
    fn on_analysis_complete(&self, metrics: &AnalysisMetrics) {}

    /// Emitted for each file analyzed
    fn on_file_analyzed(&self, file: &str, patterns: &[DetectedPattern]) {}

    /// Emitted when a new pattern type is first detected
    fn on_new_pattern_type(&self, pattern_type: &str, category: PatternCategory) {}

    /// Emitted when incremental analysis skips files
    fn on_incremental_skip(&self, skipped_count: u64, total_count: u64) {}

    /// Emitted when a taint flow is detected
    fn on_taint_flow_detected(&self, flow: &TaintFlow) {}

    /// Emitted when analysis is cancelled
    fn on_analysis_cancelled(&self, revision: u64) {}
}
```

---

## 14. V2 Build Order & Dependencies

### Phase 0 — Prerequisites (Must Exist)
- [x] Parsers (10 languages) — ParseResult with full extraction
- [x] Scanner — file walking, content hashing, ScanDiff
- [x] Storage — drift.db with detection_cache, pattern_scan_history tables
- [x] String Interning — lasso ThreadedRodeo/RodeoReader
- [x] Infrastructure — thiserror, tracing, DriftEventHandler, config
- [x] NAPI Bridge — command/query pattern, async tasks

### Phase 1 — Core Pipeline (Weeks 1-3)
```
1. Port v1 4-phase pipeline to v2 Rust
   - Phase 1: All 27 AST queries across 9 languages (preserve exact patterns)
   - Phase 2: String extraction with all 7 node kinds per language
   - Phase 3: All 33 regex patterns (SQL 9, routes 6, sensitive 8, env 6, log 4)
   - Phase 4: Resolution index with BTreeMap + FxHashMap + SmallVec
   - Wire up log patterns (v1 gap)
   - Wire up ResolutionStats tracking (v1 gap)
   - Wire up Violation population (v1 gap)

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
   - DetectorHandler trait (node_types, on_enter, on_exit, results)
   - FileDetectorHandler trait (full-file context)
   - LearningDetectorHandler trait (learn + detect two-pass)
   - Single-pass traversal with handler dispatch
   - Cancellation support (revision counter)

5. Integrate as Phase 1.5 in pipeline
   - Pre-compiled queries remain as Phase 1 (fast path)
   - Visitor engine runs as Phase 1.5 (complex patterns)
```

### Phase 3 — GAST Normalization (Weeks 5-8)
```
6. Define ~30 GAST node types
7. Build 10 per-language normalizers (GASTNormalizer trait)
   - Start with TypeScript, Python, Java (highest usage)
   - Then Go, Rust, C#, PHP, C++, JavaScript, C
8. Migrate duplicated detectors to GAST-based
   - try-catch → single GAST detector for all languages
   - route detection → single GAST detector
   - error handling patterns → single GAST detector
```

### Phase 4 — Core Analyzers in Rust (Weeks 8-12)
```
9. Port AST Analyzer
   - findPattern, compareSubtrees, traverse, getStats
   - ASTPattern matching in Rust

10. Port Semantic Analyzer
    - Scope tree building (11 scope types)
    - Symbol table (all declaration types)
    - Reference resolution
    - Shadowed variable detection
    - Per-language ScopeResolver trait

11. Port Type Analyzer
    - Type extraction (all TypeScript type kinds)
    - Subtype checking, compatibility
    - Type coverage calculation
    - Per-language TypeSystem trait (start with TS, Python, Java)

12. Port Flow Analyzer
    - CFG construction (all node types, 8 edge types)
    - Data flow analysis (definitions, uses, reaching definitions)
    - Issue detection (unreachable, infinite loops, missing returns, null deref)
    - Per-language IR lowering
```

### Phase 5 — Unified Language Provider in Rust (Weeks 12-15)
```
13. Port 9 language normalizers (LanguageNormalizer trait)
14. Port 20 ORM matchers (OrmMatcher trait)
    - Start with Prisma, Django, SQLAlchemy (highest usage)
    - Then TypeORM, Sequelize, Spring Data, EF Core
    - Then remaining 13 matchers
15. UnifiedCallChain type in Rust
16. OrmPattern result type in Rust
```

### Phase 6 — Advanced Features (Weeks 15-18)
```
17. Declarative pattern definitions (TOML loading)
18. Incremental computation (3-layer model)
19. Bayesian confidence scoring
20. Taint analysis integration (Phase 1: intraprocedural)
21. Fix generation as first-class output
22. Feedback loop infrastructure
23. Moka parse cache with SQLite persistence
```

### Phase 7 — Per-Language Analyzers (Weeks 18-22)
```
24. Port TypeScript/JavaScript analyzer (routes, components, hooks, decorators)
25. Port Python analyzer (routes, error handling, data access, decorators)
26. Port Java analyzer (Spring Boot routes, JPA entities)
27. Port Go analyzer (routes, error handling, interfaces, goroutines)
28. Port Rust analyzer (routes, error patterns, traits, async)
29. Port C# analyzer (ASP.NET routes, EF entities)
30. Port PHP analyzer (Laravel routes, Eloquent models, attributes)
31. Port C++ analyzer (classes, memory patterns, templates, virtual methods)
32. Evaluate WPF/XAML analyzer priority
```

---

## 15. V2 Performance Targets & Benchmarks

| Metric | V1 | V2 Target | How |
|--------|-----|-----------|-----|
| Full scan (10K files) | ~30s | <5s | Rayon parallelism + visitor pattern + GAST |
| Incremental scan (1 file changed) | ~10s (full rescan) | <100ms | Content-hash skip + cached results |
| Incremental scan (10 files changed) | ~10s | <500ms | Selective re-analysis |
| Per-file detection time | ~3ms | <1ms | Single-pass visitor, no redundant traversals |
| Parse cache hit rate | 0% (no cache) | >80% | Moka TinyLFU + SQLite persistence |
| Memory usage (10K files) | ~500MB | <200MB | String interning (60-80% reduction) |
| Resolution rate | Unknown (TODO) | 60-85% | 6 resolution strategies |
| NAPI serialization overhead | ~15% | <5% | Batch API, streaming for large results |
| MCP response time (cached) | ~200ms | <50ms | Moka cache with semantic keys |

### Benchmark Suite

```rust
#[bench] fn bench_full_scan_1k_files(b: &mut Bencher) { /* target: <500ms */ }
#[bench] fn bench_full_scan_10k_files(b: &mut Bencher) { /* target: <5s */ }
#[bench] fn bench_incremental_1_file(b: &mut Bencher) { /* target: <100ms */ }
#[bench] fn bench_visitor_traversal_large_file(b: &mut Bencher) { /* target: <1ms */ }
#[bench] fn bench_gast_normalization_per_file(b: &mut Bencher) { /* target: <500us */ }
#[bench] fn bench_string_analysis_per_file(b: &mut Bencher) { /* target: <200us */ }
#[bench] fn bench_resolution_index_10k_functions(b: &mut Bencher) { /* target: <50ms */ }
#[bench] fn bench_parse_cache_hit(b: &mut Bencher) { /* target: <10us */ }
```

---

## 16. Cross-Reference: V1 Feature → V2 Location

This table maps every v1 feature to its exact v2 location, ensuring zero feature loss.

| V1 Feature | V1 Location | V2 Location | Status |
|-----------|-------------|-------------|--------|
| 4-phase pipeline | unified/analyzer.rs | unified/pipeline.rs | PRESERVED |
| 27 AST queries (9 langs) | unified/ast_patterns.rs | unified/ast_patterns.rs + patterns/*.toml | PRESERVED + TOML |
| 33 string regex patterns | unified/string_analyzer.rs | unified/string_analyzer.rs + patterns/*.toml | PRESERVED + log wired |
| String extraction (7 node kinds) | unified/ast_patterns.rs | unified/string_extractor.rs | PRESERVED |
| 7 StringContext variants | unified/types.rs | unified/types.rs | PRESERVED |
| Resolution index (BTreeMap+FxHashMap) | unified/index.rs | unified/resolution.rs | PRESERVED + 6 strategies |
| FunctionEntry (7 fields) | unified/index.rs | unified/resolution.rs | PRESERVED + 6 new fields |
| Resolution algorithm (3 strategies) | unified/index.rs | unified/resolution.rs | EXPANDED to 6 strategies |
| ResolutionStats (6 fields, all TODO) | unified/types.rs | unified/types.rs | IMPLEMENTED (v1 gap fixed) |
| String interning (custom) | unified/interner.rs | interning/mod.rs (lasso) | UPGRADED |
| PathInterner | unified/interner.rs | interning/path.rs | PRESERVED |
| FunctionInterner | unified/interner.rs | interning/function.rs | PRESERVED |
| Parallel execution (rayon) | unified/analyzer.rs | unified/pipeline.rs | PRESERVED + parser pool fix |
| UnifiedOptions (6 fields) | unified/types.rs | unified/types.rs | PRESERVED + 5 new fields |
| UnifiedResult (6 fields) | unified/types.rs | unified/types.rs | PRESERVED + 3 new fields |
| FilePatterns (6 fields) | unified/types.rs | unified/types.rs | PRESERVED + 4 new fields |
| AnalysisMetrics (6 fields) | unified/types.rs | unified/types.rs | PRESERVED + 5 new fields |
| DetectedPattern (12 fields) | unified/types.rs | unified/types.rs | PRESERVED + 4 new fields |
| Violation type (10 fields) | unified/types.rs | unified/types.rs | IMPLEMENTED (v1 gap) |
| Language enum (10 variants) | unified/types.rs | core/types.rs | PRESERVED |
| PatternCategory (15 variants) | unified/types.rs | core/types.rs | PRESERVED + Accessibility |
| DetectionMethod (3 variants) | unified/types.rs | core/types.rs | PRESERVED + VisitorPattern |
| AST Analyzer (10 methods) | analyzers/ast-analyzer.ts | analyzers/ast.rs | MOVED TO RUST |
| Type Analyzer (7 methods) | analyzers/type-analyzer.ts | analyzers/types.rs | MOVED TO RUST |
| Semantic Analyzer (4 methods) | analyzers/semantic-analyzer.ts | analyzers/semantic.rs | MOVED TO RUST |
| Flow Analyzer (6 methods) | analyzers/flow-analyzer.ts | analyzers/flow.rs | MOVED TO RUST |
| 9 language normalizers | unified-provider/*.ts | unified_provider/normalizers/*.rs | MOVED TO RUST |
| 20 ORM matchers | unified-provider/*.ts | unified_provider/matchers/*.rs | MOVED TO RUST |
| UnifiedCallChain | unified-provider/types.ts | unified_provider/types.rs | MOVED TO RUST |
| TS/JS analyzer (routes, components, hooks) | typescript/*.ts | lang/typescript.rs | MOVED TO RUST |
| Python analyzer (routes, errors, data) | python/*.ts | lang/python.rs | MOVED TO RUST |
| Java analyzer (Spring, JPA) | java/*.ts | lang/java.rs | MOVED TO RUST |
| Go analyzer (routes, errors, interfaces) | go/*.ts | lang/go.rs | MOVED TO RUST |
| Rust analyzer (routes, errors, traits) | rust/*.ts | lang/rust_lang.rs | MOVED TO RUST |
| C# analyzer (ASP.NET, EF) | (via unified-provider) | lang/csharp.rs | MOVED TO RUST |
| PHP analyzer (Laravel, Eloquent) | php/*.ts | lang/php.rs | MOVED TO RUST |
| C++ analyzer (classes, memory, templates) | cpp/*.ts | lang/cpp.rs | MOVED TO RUST |
| WPF/XAML analyzer (8 files) | wpf/*.ts | lang/wpf.rs (evaluate priority) | EVALUATE |
| Evaluator pipeline (5 steps) | rules/evaluator.ts | rules/evaluator.rs (core) + TS (orchestration) | SPLIT |
| 7 quick fix strategies | rules/quick-fix-generator.ts | rules/fixes.ts (stays TS) | PRESERVED |
| Severity defaults (9 categories) | rules/severity-manager.ts | rules/severity.ts (stays TS) | PRESERVED |
| Variant manager (3 scopes) | rules/variant-manager.ts | rules/variants.ts (stays TS) | PRESERVED |
| Rule engine limits (100/pattern, 50/file) | rules/rule-engine.ts | rules/engine.ts (stays TS) | PRESERVED |
| Violation dedup by key | rules/rule-engine.ts | rules/engine.ts (stays TS) | PRESERVED |
| Log patterns (compiled, unused) | unified/string_analyzer.rs | unified/string_analyzer.rs | FIXED (now wired) |
| Violation population | unified/types.rs (empty Vec) | unified/pipeline.rs | FIXED (now populated) |
| ResolutionStats tracking | unified/types.rs (all 0) | unified/resolution.rs | FIXED (now tracked) |
| Parser pool optimization | unified/analyzer.rs (TODO) | unified/pipeline.rs | FIXED (crossbeam pool) |

### New V2 Features (Not in V1)

| Feature | Location | Source |
|---------|----------|--------|
| Visitor pattern engine | unified/visitor.rs | AD4, R1 (detectors) |
| GAST normalization (~30 types) | gast/mod.rs + gast/normalizers/*.rs | R4 (detectors) |
| Declarative TOML patterns | patterns/*.toml + unified/pattern_loader.rs | AD3 |
| Incremental computation (3 layers) | unified/incremental.rs | AD1, R2 (detectors) |
| Bayesian confidence + momentum | scoring/bayesian.rs | AD8, R3 (detectors), R9 (detectors) |
| Taint analysis integration | taint/mod.rs | AD11, R3 (analyzers), R12 (rust-core) |
| Fix generation as first-class | fixes/mod.rs | R10 (detectors), R9 (analyzers) |
| Feedback loop / detector health | health/mod.rs | R5 (detectors), R10 (analyzers) |
| Cancellation support | core/cancellation.rs | R12 (analyzers) |
| Moka parse cache | cache/parse_cache.rs | AD12, A3 (audit appendix) |
| Contested convention handling | scoring/contested.rs | R9 (detectors) |
| 6 resolution strategies | unified/resolution.rs | A5 (audit appendix) |
| body_hash on FunctionEntry | unified/resolution.rs | A3 (audit appendix) |
| Per-language TypeSystem trait | analyzers/type_system.rs | R4 (analyzers) |
| Per-language ScopeResolver trait | analyzers/scope_resolver.rs | R4 (analyzers) |
| Interprocedural data flow summaries | analyzers/data_flow.rs | R6 (analyzers) |
| N+1 query detection | analyzers/n_plus_one.rs | R8 (analyzers) |
| OWASP/CWE mapping on patterns | core/types.rs (cwe_ids, owasp fields) | R7 (detectors) |
| Framework middleware architecture | frameworks/mod.rs | R11 (detectors) |
| Detector testing framework | tests/detector_framework.rs | R12 (detectors) |

---

## 17. Open Questions & Decisions Needed

### Q1: Salsa vs. Custom Incremental
Full Salsa integration is high complexity. Alternative: custom content-hash + dependency
tracking cache (simpler, less powerful). Decision needed before Phase 6.
**Recommendation**: Start with custom cache (Phase 1-5), evaluate Salsa for Phase 6+.

### Q2: GAST Coverage Target
~30 node types covers ~80% of detection needs. Should we target more?
**Recommendation**: Start with 30, expand based on detector migration needs.

### Q3: WPF/XAML Priority
Most complex language analyzer (~8 files). Requires dedicated tree-sitter grammar.
**Recommendation**: Defer to Phase 7, evaluate based on user demand.

### Q4: Type Analyzer Multi-Language Scope
V1 is TypeScript-only. How many languages need full type analysis in v2?
**Recommendation**: TypeScript (P0), Python (P1), Java (P1), Go (P2). Others get basic
type extraction without full subtype checking.

### Q5: Abstract Interpretation
R13 from analyzers recommendations proposes optional sound analysis via abstract
interpretation. Very high effort.
**Recommendation**: P3 (Future). Not in initial v2 build.

### Q6: Compilation Abstraction
R5 from analyzers recommendations proposes a Roslyn-inspired Compilation object.
**Recommendation**: Build incrementally. Start with per-file SemanticModel, add
cross-file Compilation context when call graph and import resolution are mature.

---

## 18. Risk Register

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| GAST normalization loses language-specific details | Medium | Medium | Keep raw AST escape hatch for language-specific detectors |
| Visitor pattern doesn't handle all detector patterns | High | Low | FileDetectorHandler variant for full-file context |
| Incremental cache produces stale results | High | Medium | Force full scan escape hatch, cross-file invalidation |
| Bayesian scoring confuses developers | Medium | Medium | Clear UX, v1 baseline as fallback |
| 20 ORM matcher port is large effort | Medium | High | Prioritize top 7 ORMs, port rest incrementally |
| Taint analysis false positives | Medium | Medium | Sanitizer recognition, configurable sensitivity |
| Parser pool contention under high parallelism | Low | Low | Bounded crossbeam channel with backpressure |
| TOML pattern syntax too complex for users | Medium | Low | Graduated complexity (4 levels), good docs |

---

*End of Unified Analysis Engine research document.*
*Every v1 feature is accounted for in the cross-reference table (Section 16).*
*All v2 architectural decisions (AD1-AD12, D1-D7) are incorporated.*
*All relevant recommendations from .research/ are addressed.*
*This is a build-ready specification. V1 is the requirements doc. V2 is the architecture.*
