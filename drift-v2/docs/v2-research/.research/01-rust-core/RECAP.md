# 01 Rust Core — Research Recap

## Executive Summary

The Rust Core (`crates/drift-core/`) is Drift's native performance engine — the foundational layer that handles all computationally intensive work: parsing source code across 10 languages via tree-sitter, building and querying call graphs with SQLite-backed storage, detecting patterns through a unified AST-first + regex-fallback pipeline, and running specialized analyzers for boundaries, coupling, constants/secrets, environment variables, error handling, test topology, reachability, and wrapper detection. It is exposed to the TypeScript orchestration layer via ~25 N-API bindings. The v2 vision is to migrate all detection and analysis logic into this Rust layer, reducing TypeScript to a thin orchestration shell.

## Current Implementation

### Crate Structure

```
crates/
├── drift-core/src/
│   ├── parsers/          # Tree-sitter parsers for 10 languages
│   ├── scanner/          # Parallel filesystem walking
│   ├── call_graph/       # Call graph building, storage, querying
│   ├── unified/          # Core pattern detection engine (AST + regex)
│   ├── boundaries/       # Data access point & sensitive field detection
│   ├── coupling/         # Module coupling metrics (Martin's Ca/Ce/I/A/D)
│   ├── constants/        # Constants, magic numbers, secret detection
│   ├── environment/      # Environment variable usage analysis
│   ├── error_handling/   # Error boundary & gap detection
│   ├── test_topology/    # Test file mapping, framework detection
│   ├── reachability/     # Forward/inverse data flow reachability
│   └── wrappers/         # Framework wrapper detection & clustering
│
└── drift-napi/           # N-API bridge (~25 exported functions)
```

### Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                        TypeScript Layer                              │
│  (Orchestration, Presentation, Storage Integration, Richer Analysis) │
└──────────────────────────┬───────────────────────────────────────────┘
                           │ N-API (~25 functions)
┌──────────────────────────▼───────────────────────────────────────────┐
│                        drift-napi                                    │
│  scan │ parse │ build_call_graph │ analyze_* │ scan_boundaries │ ... │
└──────────────────────────┬───────────────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────────────┐
│                        drift-core                                    │
│                                                                      │
│  ┌─────────┐  ┌──────────┐  ┌────────────┐  ┌──────────────────┐   │
│  │ Scanner │  │ Parsers  │  │ Call Graph │  │ Unified Analyzer │   │
│  │ walkdir │  │ tree-    │  │ builder    │  │ AST queries      │   │
│  │ rayon   │  │ sitter   │  │ storage    │  │ string analyzer  │   │
│  │ ignore  │  │ 10 langs │  │ SQLite     │  │ resolution index │   │
│  └────┬────┘  └────┬─────┘  │ rayon      │  │ string interning │   │
│       │            │        └─────┬──────┘  └────────┬─────────┘   │
│       │            │              │                   │              │
│  ┌────▼────────────▼──────────────▼───────────────────▼──────────┐  │
│  │                    Specialized Analyzers                       │  │
│  │  boundaries │ coupling │ constants │ environment │ error_handling│ │
│  │  test_topology │ reachability │ wrappers                       │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  Shared Infrastructure                                        │  │
│  │  rayon (parallelism) │ rusqlite (SQLite) │ xxhash (hashing)  │  │
│  │  smallvec │ rustc-hash (FxHashMap) │ serde │ globset │ regex │  │
│  └──────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Subsystem Deep Dives

### 1. Scanner (`scanner/`)

**Purpose**: Parallel filesystem traversal with enterprise-grade ignore support.

**Components**:
- `walker.rs` — Parallel file walking via `walkdir` + `rayon`
- `ignores.rs` — `.gitignore`, `.driftignore`, configurable patterns
- `types.rs` — `ScanConfig`, `ScanResult`, `FileInfo`, `ScanStats`

**Key Characteristics**:
- Rayon-based parallelism for thread-level file walking
- Respects `.gitignore` and `.driftignore`
- Configurable max file size, include/exclude globs, symlink following
- Returns file metadata: path, size, detected language

**Current Limitations**:
- No incremental scanning (full rescan every time)
- No dependency graph building (done in TS)
- No change detection (done in TS)
- Worker pool concept in TS could be replaced by rayon's built-in parallelism

**NAPI**: `scan(config) -> JsScanResult`

---

### 2. Parsers (`parsers/`)

**Purpose**: Tree-sitter-based AST parsing for 10 languages.

**Components**:
- `manager.rs` — Language detection, parser selection
- Per-language parsers: `typescript.rs`, `python.rs`, `java.rs`, `csharp.rs`, `php.rs`, `go.rs`, `rust_lang.rs`, `cpp.rs`, `c.rs`
- `types.rs` — `ParseResult`, `FunctionInfo`, `ClassInfo`, `ImportInfo`, `ExportInfo`, `CallSite`

**Languages Supported** (tree-sitter v0.23):
TypeScript/JavaScript, Python, Java, C#, PHP, Go, Rust, C++, C

**Extension Mapping**:
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

**Extracts**: Functions, classes, imports, exports, call sites, parameters, properties, decorators, doc comments, ranges.

**Current Limitations**:
- TS-side parsers extract significantly more detail (especially Java, C#, PHP)
- Missing: decorator/annotation detail, generics, full type information
- No framework-aware parsing (e.g., Next.js conventions, Spring Boot structure)

**NAPI**: `parse(source, file_path)`, `supported_languages()`

---

### 3. Call Graph (`call_graph/`)

**Purpose**: Build, store, and query function-level call relationships.

**Components**:
- `builder.rs` — `StreamingBuilder`: parallel file processing via rayon, SQLite writing, resolution pass
- `extractor.rs` — `CallGraphExtractor` trait + `to_function_entries()` helper
- `universal_extractor.rs` — Language-agnostic extraction from `ParseResult`
- `storage.rs` — `CallGraphDb` (SQLite CRUD) + `ParallelWriter` (threaded batch writer)
- `types.rs` — `FunctionEntry`, `CallEntry`, `DataAccessRef`, `CallGraphShard`, `BuildResult`

**Key Data Model**:
```
FunctionEntry {
  id: "file:name:line"
  calls: Vec<CallEntry>        // outgoing
  called_by: Vec<String>       // incoming
  data_access: Vec<DataAccessRef>  // DB/API access
  is_entry_point, is_data_accessor
}
```

**Architecture**:
- Sharded building: files processed in parallel via rayon
- SQLite persistence via `CallGraphDb` with `ParallelWriter`
- Resolution pass: resolves call targets to function IDs
- Confidence scoring on call resolution

**NAPI** (7 functions): `build_call_graph`, `is_call_graph_available`, `get_call_graph_stats`, `get_call_graph_entry_points`, `get_call_graph_data_accessors`, `get_call_graph_callers`, `get_call_graph_file_callers`

---

### 4. Unified Analysis Engine (`unified/`)

**Purpose**: Core pattern detection — the heart of Drift's Rust engine.

**Components**:
- `analyzer.rs` (~170 lines) — Combined pattern detection pipeline
- `ast_patterns.rs` (~600 lines) — AST-based detection with per-language tree-sitter queries
- `string_analyzer.rs` (~200 lines) — Regex-on-strings fallback
- `interner.rs` (~220 lines) — String interning (`Symbol`, `PathInterner`, `FunctionInterner`)
- `index.rs` (~280 lines) — In-memory function resolution index
- `types.rs` (~250 lines) — All unified analysis types

**4-Phase Per-File Pipeline**:
```
File → tree-sitter parse → ParseResult
  Phase 1: AST Pattern Detection (confidence 0.85-0.95)
  Phase 2: String Extraction (strings >3 chars from AST)
  Phase 3: String Literal Analysis (regex on extracted strings, confidence 0.80-0.90)
  Phase 4: Resolution Index population (function indexing for cross-file resolution)
```

**AST Query Inventory** (per language):
| Language | Patterns | Categories |
|---|---|---|
| TypeScript | auth-decorator, middleware-usage, express-route, try-catch | Auth, Api, Errors |
| JavaScript | express-route, try-catch | Api, Errors |
| Python | fastapi-depends, auth-decorator, fastapi-route, try-except | Auth, Api, Errors |
| Java | spring-security, spring-route, jpa-entity, try-catch | Auth, Api, DataAccess, Errors |
| C# | authorize-attribute, aspnet-route, ef-entity | Auth, Api, DataAccess |
| PHP | laravel-middleware, laravel-route, eloquent-model | Auth, Api, DataAccess |
| Go | http-handler, error-check | Api, Errors |
| Rust | actix-route, result-match, derive-attribute | Api, Errors, DataAccess |
| C++ | try-catch, cpp-route | Errors, Api |

**String Regex Sets**:
- SQL patterns (9 regexes) → DataAccess, confidence 0.9
- Route patterns (6 regexes) → Api, confidence 0.85
- Sensitive data patterns (8 regexes) → Security, confidence 0.8
- Environment patterns (6 regexes) → Config, confidence 0.85
- Log patterns (4 regexes) → compiled but NOT USED (TODO)

**Resolution Index**: BTreeMap + FxHashMap + SmallVec for efficient function lookup. Resolution algorithm: exact name → same-file preference → exported preference → ambiguous.

**String Interning**: Claims 60-80% memory reduction. PathInterner (capacity 4096), FunctionInterner (capacity 8192).

**Known Gaps**:
- `log_patterns` RegexSet compiled but never called in `analyze()`
- `ResolutionStats` fields initialized to 0 with TODO comments — not wired up
- `Violation` type defined but `violations` always `Vec::new()` — not implemented
- Thread-local `ParserManager` per rayon thread noted as optimization TODO

**NAPI**: `analyze_unified(root, options) -> JsUnifiedResult`

---

### 5. Boundaries (`boundaries/`)

**Purpose**: Detect data access points, ORM models, and sensitive fields.

**Components**:
- `detector.rs` — Data access point detection (DB queries, API calls, file I/O)
- `sensitive.rs` — Sensitive field detection (PII, credentials, financial)
- `types.rs` — `DataAccessPoint`, `SensitiveField`, `ORMModel`, `BoundaryScanResult`

**Detects**:
- Database queries, API calls, file operations
- ORM model definitions (Prisma, Django, SQLAlchemy, Entity Framework, etc.)
- Sensitive fields: passwords, emails, SSNs, credit cards, API keys
- Data operation classification: Read, Write, Delete, Update

**Current Limitations**:
- No ORM-specific field extractors (done in TS)
- No learning capability (done in TS)
- No risk scoring (done in TS)

**NAPI**: `scan_boundaries(files)`, `scan_boundaries_source(source, file_path)`

---

### 6. Coupling Analyzer (`coupling/`)

**Purpose**: Module coupling metrics based on Robert C. Martin's principles.

**Metrics**: Afferent Coupling (Ca), Efferent Coupling (Ce), Instability (I = Ce/(Ca+Ce)), Abstractness (A), Distance from Main Sequence (D = |A+I-1|)

**Cycle Detection**: DFS with recursion stack (TS uses Tarjan's SCC — more efficient)

**Health Score**: Starts at 100, penalizes cycles (Critical: -15, Warning: -8, Info: -3) and high coupling (>10: -2) and high distance (>0.7: -1)

**Feature Gap vs TypeScript**:
| Feature | Rust | TS |
|---|---|---|
| Basic metrics (Ca, Ce, I, A, D) | ✅ | ✅ |
| Cycle detection | DFS | Tarjan's SCC |
| Module roles (hub/authority/balanced/isolated) | ❌ | ✅ |
| Cycle break suggestions | ❌ | ✅ |
| Refactor impact analysis | ❌ | ✅ |
| Transitive dependencies | ❌ | ✅ |
| Zone of pain/uselessness detection | ❌ | ✅ |
| Call graph integration | ❌ | ✅ |

**NAPI**: `analyze_coupling(files)`

---

### 7. Constants & Secrets Analyzer (`constants/`)

**Purpose**: Find hardcoded values, magic numbers, and potential secrets.

**Architecture**: Parallel via rayon with `thread_local!` pattern for ParserManager, ConstantExtractor, SecretDetector.

**Secret Detection**: 21 regex patterns across 4 severity levels:
- Critical (0.9 base): AWS keys, GitHub tokens, Stripe keys, RSA/SSH/PGP private keys
- High (0.8 base): Google API keys, passwords, JWTs, DB connections, Slack/SendGrid/Twilio tokens
- Medium (0.6 base): Hardcoded passwords, bearer tokens, generic API keys, Slack webhooks
- Confidence adjustments: +0.05 for high entropy, +0.05 for length >30

**Placeholder Detection**: Skips "example", "placeholder", "your_", "xxx", "todo", "changeme", "replace"

**Magic Number Detection**: Regex `\b(\d{2,})\b` with exclusion list (common values, time constants, powers of 2, HTTP status codes, years 1900-2100). Context-aware naming suggestions.

**Inconsistency Detection**: Groups constants by normalized name, flags differing values.

**Current Limitations**:
- Missing: Azure keys, GCP service accounts, npm tokens, PyPI tokens
- Magic number detection is line-level regex (AST-based would be more accurate)
- Inconsistency detection lacks fuzzy name matching (e.g., `MAX_RETRIES` vs `maxRetries`)

**NAPI**: `analyze_constants(files)`

---

### 8. Environment Analyzer (`environment/`)

**Purpose**: Extract and classify environment variable access patterns.

**Detects**: `process.env.X`, `os.environ["X"]`, `getenv("X")`, `env("X")`, `${X}`, `%X%`

**Sensitivity Classification**:
- Critical: `*_SECRET`, `*_PRIVATE_KEY`, `DATABASE_URL`, `*_PASSWORD`
- Secret: `*_KEY`, `*_TOKEN`, `*_AUTH`, `*_CREDENTIAL`
- Internal: `*_HOST`, `*_PORT`, `*_URL`, `*_ENDPOINT`
- Public: everything else

**Current Limitations**:
- No `.env` file parsing (done in TS)
- No missing variable detection (done in TS)
- No framework-specific detection (Next.js `NEXT_PUBLIC_*`, Vite `VITE_*`)

**NAPI**: `analyze_environment(files)`

---

### 9. Error Handling Analyzer (`error_handling/`)

**Purpose**: Detect error boundaries and identify error handling gaps.

**Boundary Types**: TryCatch, ErrorMiddleware, ErrorBoundary, GlobalHandler, Decorator, ResultType

**Gap Types**: UnhandledPromise, EmptyCatch, MissingCatch, SwallowedError, UncheckedResult, IgnoredError

**Gap Severities**: Critical, High, Medium, Low

**Current Limitations**:
- No error propagation chain tracking (done in TS)
- No error profile generation per module (done in TS)
- No call graph integration for cross-function error flow (done in TS)
- No data flow analysis for tracking error variables through code

**NAPI**: `analyze_error_handling(files)`

---

### 10. Test Topology Analyzer (`test_topology/`)

**Purpose**: Map tests to source code, detect frameworks, analyze coverage.

**Frameworks Detected**: Jest, Vitest, Mocha, Pytest, JUnit, NUnit, XUnit, GoTest, PHPUnit, RustTest

**Test Types**: Unit, Integration, E2E, Performance, Snapshot

**Mock Types**: Full, Partial, Spy

**Risk Levels**: Low, Medium, High, Critical

**Current Limitations**:
- TS side has per-language extractors for 8 languages and 35+ frameworks
- No minimum test set calculation (done in TS)
- No quality scoring (done in TS)
- Test-to-source mapping via imports only — could use call graph

**NAPI**: `analyze_test_topology(files)`

---

### 11. Reachability Engine (`reachability/`)

**Purpose**: Forward and inverse data flow reachability analysis.

**Capabilities**:
- Forward: "From function X, what data can it access?"
- Inverse: "What functions can reach sensitive data Y?"
- Call path tracing through the call graph
- Sensitive field access identification along paths
- SQLite variant for large codebases (too large for in-memory)

**Current Limitations**:
- No taint analysis
- No granular data flow tracking
- No cross-service reachability

**NAPI** (4 functions): `analyze_reachability`, `analyze_inverse_reachability`, `analyze_reachability_sqlite`, `analyze_inverse_reachability_sqlite`

---

### 12. Wrappers Analyzer (`wrappers/`)

**Purpose**: Detect functions that wrap framework primitives, cluster related wrappers.

**Detection**: Analyzes call targets within functions against a known primitives registry (useState, useReducer, useEffect, fetch, axios, zod, yup, console.*, logger.*, etc.)

**Confidence Scoring**:
- Base: 0.6
- +0.15 for naming patterns (use*, with*, create*, make*)
- +0.15 for wrapper/hook/helper in name
- +0.10 for custom hook pattern (useXxx)
- -0.10 for complex functions (>10 calls)
- +0.10 for focused functions (≤3 calls)
- Minimum threshold: 0.5

**12 Categories**: StateManagement, SideEffects, DataFetching, Validation, Logging, Authentication, Caching, ErrorHandling, FormHandling, Routing, Factory, Other

**Current Limitations**:
- Primitive registry is React-focused; needs Vue, Angular, Svelte, Express expansion
- Usage counting requires call graph — currently 0 in Rust, filled by TS
- Clustering algorithm undocumented

**NAPI**: `analyze_wrappers(files)`

---

## Key Data Models

### Core Parse Types
```
ParseResult { language, tree, functions, classes, imports, exports, calls, errors, parse_time_us }
FunctionInfo { name, qualified_name, parameters, return_type, is_exported, is_async, is_generator, range, decorators, doc_comment }
ClassInfo { name, extends, implements, is_exported, is_abstract, methods, properties, range, decorators }
ImportInfo { source, named, default, namespace, is_type_only, range }
ExportInfo { name, original_name, from_source, is_type_only, is_default, range }
CallSite { callee, receiver, arg_count, range }
```

### Pattern Detection Types
```
DetectedPattern { category (15 variants), pattern_type, subcategory, file, line, column, end_line, end_column, matched_text, confidence, detection_method, metadata }
PatternCategory: Api | Auth | Components | Config | DataAccess | Documentation | Errors | Logging | Performance | Security | Structural | Styling | Testing | Types | Validation
DetectionMethod: AstQuery | RegexFallback | Structural
```

### Call Graph Types
```
FunctionEntry { id: "file:name:line", name, start_line, end_line, is_entry_point, is_data_accessor, calls, called_by, data_access }
CallEntry { target, resolved_id, resolved, confidence, line }
DataAccessRef { table, fields, operation: Read|Write|Delete, line }
BuildResult { files_processed, total_functions, total_calls, resolved_calls, resolution_rate, entry_points, data_accessors, errors, duration_ms }
```

---

## Performance Characteristics

| Aspect | Implementation |
|---|---|
| Parallelism | rayon (data parallelism across files) |
| Parsing | tree-sitter v0.23 (incremental, error-tolerant) |
| Storage | rusqlite with bundled SQLite |
| Hashing | xxhash (xxh3) for fast hashing |
| Small vectors | smallvec for ≤4 element vectors |
| Hash maps | rustc-hash (FxHashMap) for fast lookups |
| String dedup | Custom string interning (60-80% memory reduction) |
| Build profile | LTO enabled, codegen-units=1, opt-level=3 |

---

## N-API Bridge Summary

~25 exported functions across 4 categories:

| Category | Functions | Count |
|---|---|---|
| Scanning | `scan` | 1 |
| Parsing | `parse`, `supported_languages`, `version` | 3 |
| Call Graph | `build_call_graph`, `build_call_graph_legacy`, `is_call_graph_available`, `get_call_graph_stats`, `get_call_graph_entry_points`, `get_call_graph_data_accessors`, `get_call_graph_callers`, `get_call_graph_file_callers` | 8 |
| Analysis | `scan_boundaries`, `scan_boundaries_source`, `analyze_coupling`, `analyze_test_topology`, `analyze_error_handling`, `analyze_reachability`, `analyze_inverse_reachability`, `analyze_reachability_sqlite`, `analyze_inverse_reachability_sqlite`, `analyze_unified`, `analyze_constants`, `analyze_environment`, `analyze_wrappers` | 13 |

**Platform Support**: darwin-arm64, darwin-x64, linux-arm64-gnu, linux-arm64-musl, linux-x64-gnu, linux-x64-musl, win32-x64-msvc

---

## Integration Points

| Connects To | How |
|---|---|
| **02-parsers** | Rust parsers ARE the parsing layer; TS parsers add richer extraction |
| **03-detectors** | Unified analyzer is the Rust detection engine; 350+ TS detectors are far richer |
| **04-call-graph** | Call graph builder/storage/querying lives here |
| **05-analyzers** | All specialized analyzers (coupling, constants, etc.) live here |
| **06-cortex** | No direct connection yet — cortex is TS-only |
| **07-mcp** | MCP queries call through TS which calls Rust via NAPI |
| **08-storage** | Call graph uses SQLite; other analyzers return in-memory results |
| **17-test-topology** | Test topology analyzer lives here |
| **19-error-handling** | Error handling analyzer lives here |
| **21-security** | Boundary detection and secret scanning contribute to security analysis |

---

## V2 Migration Status

### Already in Rust (Solid)
- File scanning with parallel walking
- Tree-sitter parsing for 10 languages
- Call graph building, storage, querying
- Unified pattern detection (AST + regex)
- All 8 specialized analyzers
- Reachability (forward + inverse, in-memory + SQLite)
- String interning and resolution index

### Needs Migration from TS → Rust
- 350+ pattern detectors (currently only ~30 AST patterns in Rust)
- Pattern matching and confidence scoring (full system)
- Storage operations (pattern CRUD, contract CRUD)
- Language intelligence (normalization, framework detection)
- Richer call graph queries
- Module roles, cycle break suggestions, refactor impact analysis
- Error propagation chains, error profiles
- Test quality scoring, minimum test set calculation
- .env file parsing, missing variable detection
- ORM-specific field extractors, risk scoring
- Cross-file wrapper usage counting

### Architectural Decisions Pending
- FFI approach: Keep NAPI (thicker) vs Rust CLI with JSON IPC?
- Incremental analysis: How to support analyzing only changed files?
- Pattern storage: Should Rust own SQLite pattern CRUD?
- Cortex integration: Should memory/embedding operations move to Rust?

---

## Open Questions

1. **Thread-local vs pooled parsers**: The unified analyzer creates a new `ParserManager` per rayon thread. Should this use a thread-local pool instead?
2. **Violation system**: Types are defined but never populated. What's the implementation plan?
3. **Log pattern detection**: Compiled but unused. Intentional deferral or oversight?
4. **Resolution tracking**: Stats fields are TODO. Is this blocking any downstream features?
5. **Cycle detection algorithm**: Rust uses DFS, TS uses Tarjan's SCC. Should Rust switch for v2?
6. **Magic number detection**: Line-level regex vs AST-based. What's the accuracy tradeoff?
7. **Cross-service reachability**: How should this work for microservice architectures?
8. **Wrapper registry expansion**: What's the priority order for Vue/Angular/Svelte/Express primitives?

---

## Quality Checklist

- [x] All 15 files in category have been read
- [x] Architecture is clearly described with diagram
- [x] Key algorithms documented (cycle detection, confidence scoring, resolution, string interning, secret detection, reachability)
- [x] All data models listed with fields
- [x] Limitations honestly assessed per subsystem
- [x] Integration points mapped to other categories
- [x] V2 migration status documented
- [x] Open questions identified
- [x] Traceability audit performed — all 15 source documents verified against RECAP, RESEARCH, and RECOMMENDATIONS
- [x] 7 gaps identified and closed via supplementary recommendations R13-R18
