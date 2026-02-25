# Drift V2 — Master Recap

> **Purpose**: Unified synthesis of all v1 research across 5 categories (Rust Core, Parsers, Detectors, Call Graph, Analyzers). This document captures the complete state of Drift v1 as a requirements specification for the v2 greenfield rebuild.
>
> **Scope**: ~20,000+ lines of research distilled into a single authoritative reference.
>
> **Date**: February 2026

---

## 1. System Overview

### What Drift Is

Drift is a codebase convention discovery and indexing tool. It scans codebases to automatically discover patterns (how the team actually writes code), indexes them in SQLite, and exposes them to AI agents via MCP (Model Context Protocol).

**Core thesis**: Discover and index a codebase's conventions offline (no AI), then expose them to AI at query time — giving it exactly the context it needs without wasting tokens on discovery.

### Architecture Layers (V1)

```
┌─────────────────────────────────────────────────────────────────┐
│ PRESENTATION    CLI │ MCP Server │ VSCode │ Dashboard           │
├─────────────────────────────────────────────────────────────────┤
│ ORCHESTRATION   Commands │ Services │ Quality Gates │ Workspace │
├─────────────────────────────────────────────────────────────────┤
│ INTELLIGENCE    Detectors (350+) │ Analyzers │ Cortex Memory    │
├─────────────────────────────────────────────────────────────────┤
│ ANALYSIS        Call Graph │ Boundaries │ Reachability │ etc.   │
├─────────────────────────────────────────────────────────────────┤
│ PARSING         Tree-sitter (10 languages) │ Regex fallback     │
├─────────────────────────────────────────────────────────────────┤
│ STORAGE         drift.db (SQLite) │ cortex.db (SQLite + vectors)│
├─────────────────────────────────────────────────────────────────┤
│ RUST CORE       Native parsers │ Scanner │ Call graph │ NAPI    │
└─────────────────────────────────────────────────────────────────┘
```

### V2 Vision

Move ALL parsing, detection, and analysis to Rust. TypeScript becomes a thin orchestration layer. Target: enterprise-grade performance for 500K+ file codebases with sub-second incremental response times.

### Language Support

- **Parsed (10)**: TypeScript, JavaScript, Python, Java, C#, PHP, Go, Rust, C, C++
- **ORMs (28+)**: Prisma, Django, SQLAlchemy, Entity Framework, Sequelize, TypeORM, GORM, Diesel, SeaORM, etc.
- **Frameworks (21+)**: React, Vue, Angular, Express, FastAPI, Spring, Laravel, Django, ASP.NET, NestJS, etc.

---

## 2. Subsystem Inventory

### 2.1 Rust Core (`crates/drift-core/`)

**~11,000 lines of Rust** across 15 files, exposed via ~25 N-API bindings.

| Subsystem | Purpose | Key Algorithms | NAPI Functions |
|-----------|---------|---------------|----------------|
| Scanner | Parallel filesystem traversal | walkdir + rayon, .gitignore/.driftignore | 1 |
| Parsers | Tree-sitter AST extraction (10 langs) | Per-language query-based extraction | 3 |
| Call Graph | Function relationship mapping | StreamingBuilder, ParallelWriter, 3-strategy resolution | 8 |
| Unified Analyzer | Core pattern detection | 4-phase pipeline (AST → strings → regex → resolution) | 1 |
| Boundaries | Data access + sensitive field detection | ORM detection, PII/credential patterns | 2 |
| Coupling | Module coupling metrics | Martin's Ca/Ce/I/A/D, DFS cycle detection | 1 |
| Constants | Secret + magic number detection | 21 regex patterns, entropy scoring, placeholder filtering | 1 |
| Environment | Env variable analysis | Multi-language extraction, sensitivity classification | 1 |
| Error Handling | Error boundary + gap detection | AST pattern matching for try/catch, error types | 1 |
| Test Topology | Test-to-source mapping | Framework detection (11 frameworks), type classification | 1 |
| Reachability | Forward/inverse data flow | BFS traversal, SQLite CTE variant, sensitivity classification | 4 |
| Wrappers | Framework wrapper detection | Primitive registry matching, confidence scoring, clustering | 1 |

**Shared Infrastructure**: rayon (parallelism), rusqlite (SQLite), xxhash (hashing), smallvec, FxHashMap, serde, globset, regex, string interning (custom).

**Platform Support**: darwin-arm64, darwin-x64, linux-arm64-gnu, linux-arm64-musl, linux-x64-gnu, linux-x64-musl, win32-x64-msvc.

### 2.2 Parsers (Dual-Layer)

**~20,900 lines** across ~58 files (Rust + TypeScript).

| Layer | Files | Lines | Languages | Key Feature |
|-------|-------|-------|-----------|-------------|
| Rust Parsers | 12 | ~8,000 | 10 | Compile-time linked tree-sitter grammars |
| TS Custom Parsers | 8 | ~4,000 | 5 (TS, Python, CSS, JSON, Markdown) | Regex-based fallback |
| TS Tree-Sitter Wrappers | 22+ | ~6,000 | 7 | Framework-aware extraction |
| Pydantic Extraction | 9 | ~1,500 | Python | v1/v2 model extraction |
| Java Annotation System | 5 | ~800 | Java | Structured annotation objects |
| NAPI Bridge | 1 | ~400 | — | Manual field-by-field conversion |
| Native Adapter | 1 | ~200 | — | Rust → TS fallback |

**Fallback Chain**: Rust native → TS tree-sitter → TS regex → null.

**Three ParseResult Shapes** (critical v1 problem):
1. Rust `ParseResult` — extracted metadata (functions, classes, imports, exports, calls)
2. TS `ParseResult` — raw AST tree (fundamentally different)
3. NAPI `JsParseResult` — bridge conversion of Rust shape

### 2.3 Detectors (350+ TypeScript)

**~100+ source files** organized into 16 categories with up to 3 variants each (base, learning, semantic).

| Category | Base | Learning | Semantic | Framework Extensions |
|----------|------|----------|----------|---------------------|
| security | 7 | 7 | 7 | Laravel, ASP.NET |
| auth | 6 | 6 | 6 | ASP.NET(5), Laravel, Go, C++, Rust |
| errors | 7 | 7 | 7 | Laravel, ASP.NET, C++, Go, Rust |
| api | 7 | 7 | — | Go(5), Rust(4), C++(3), Laravel |
| components | 8 | 7 | 8 | — |
| config | 7 | 6 | 6 | Laravel, ASP.NET |
| contracts | 4+ | — | — | Spring(2), Laravel, Django(4), ASP.NET |
| data-access | 10 | 7 | 10 | Laravel, ASP.NET |
| documentation | 5 | 5 | 5 | ASP.NET |
| logging | 7 | 7 | 7 | Laravel, ASP.NET |
| performance | 6 | 6 | 6 | Laravel, ASP.NET |
| structural | 9 | 8 | 8 | Laravel, ASP.NET |
| styling | 8 | 8 | 8 | — |
| testing | 7 | 7 | 7 | Laravel, ASP.NET |
| types | 7 | 7 | 7 | ASP.NET |
| accessibility | 6 | 6 | 6 | — |

**Framework Coverage**: Spring Boot (12 categories), ASP.NET (11), Laravel (12), Django (contracts only), Go/Rust/C++ (api+auth+errors only).

**7 Base Classes**: BaseDetector, RegexDetector, ASTDetector, StructuralDetector, LearningDetector, SemanticDetector, UnifiedDetector.

### 2.4 Call Graph (Dual-Layer)

**~18,900 lines** across ~53 files (TypeScript + Rust).

| Layer | Component | Key Capability |
|-------|-----------|---------------|
| TS Extractors | 8 languages × 3 variants | Hybrid extraction (tree-sitter + regex fallback) |
| TS Analysis | GraphBuilder, Reachability, Impact, DeadCode, Coverage, PathFinder | 6-strategy resolution, enrichment pipeline |
| TS Enrichment | Sensitivity, Impact Scoring, Remediation | Security-focused analysis |
| Rust Core | StreamingBuilder, UniversalExtractor, CallGraphDb, ParallelWriter | Parallel construction, SQLite storage |
| Rust Reachability | In-memory + SQLite engines | BFS traversal, sensitivity classification |

**Resolution Strategies (TS)**: Same-file → Method call → DI injection → Import-based → Export-based → Fuzzy. Resolution rate: 60-85%.

**Resolution Strategies (Rust)**: Local → Import → Export. Resolution rate: ~50%.

### 2.5 Analyzers (Dual-Layer)

**~22,000+ lines** across TypeScript and Rust.

| Analyzer | TS LOC | Rust LOC | Purpose |
|----------|--------|----------|---------|
| AST Analyzer | 800 | — | Structural pattern matching, subtree comparison |
| Type Analyzer | 1,600 | — | Type extraction, subtyping, coverage (TS-only) |
| Semantic Analyzer | 1,350 | — | Scope analysis, symbol resolution (TS/JS-only) |
| Flow Analyzer | 1,600 | — | CFG construction, data flow, unreachable code |
| Unified Provider | 2,500 | 1,700 | 9 normalizers, 20 ORM matchers, ~30 AST patterns |
| Module Coupling | 900 | 600 | Martin metrics, cycle detection |
| Constants | 600 | 800 | Secret detection (21 patterns), magic numbers |
| Environment | 400 | 500 | Env var extraction, sensitivity classification |
| Wrappers | 600 | 700 | Wrapper detection, primitive registry |
| Rules Engine | 4,900 | — | Evaluator, severity, variants, quick fixes (7 strategies) |
| Language Analyzers | 3,000 | — | 9 languages with framework awareness |

---

## 3. Core Algorithms

### 3.1 Confidence Scoring (Heart of Drift)

```
score = frequency × 0.4 + consistency × 0.3 + ageFactor × 0.15 + spread × 0.15
```

- **Frequency**: occurrences / totalLocations [0.0, 1.0]
- **Consistency**: 1 - variance (clamped) [0.0, 1.0]
- **Age Factor**: Linear 0.1 → 1.0 over 30 days, then flat forever
- **Spread**: fileCount / totalFiles [0.0, 1.0]
- **Classification**: high (≥0.85), medium (≥0.70), low (≥0.50), uncertain (<0.50)

**Known gap**: No temporal decay. Once high confidence, stays there forever even if convention changes.

### 3.2 Convention Learning (ValueDistribution)

```
For each unique value:
  filePercentage = filesWithValue / totalFiles
  if filePercentage >= 0.6 AND occurrences >= 3:
    → dominant convention (confidence = filePercentage)
```

**Known gap**: Binary threshold (60%) with no Bayesian uncertainty modeling.

### 3.3 Outlier Detection

- **n ≥ 30**: Z-Score with |z| > 2.0 threshold (flags ~4.6% — too aggressive)
- **n < 30**: IQR with 1.5× multiplier
- **Sensitivity adjustment**: Both scale by `(1 + (1 - sensitivity))`

**Known gaps**: No Grubbs' test for small samples, no iterative detection, threshold too low.

### 3.4 Pattern Detection Pipeline (8 Phases)

```
1. FILE SCANNING    → FileMetadata[] (path, language, size, hash)
2. PARSING          → DetectionContext[] (AST, imports, exports, language)
3. DETECTION        → DetectionResult[] (per-file per-detector)
4. AGGREGATION      → AggregatedMatchResult[] (cross-file pattern data)
5. CONFIDENCE       → Pattern[] with ConfidenceScore
6. OUTLIER          → Pattern[] with outlier annotations
7. STORAGE          → SQLite + JSON shards
8. VIOLATIONS       → Violation[] (IDE diagnostics, CLI, CI)
```

### 3.5 Unified Analysis (4-Phase Per-File)

```
File → tree-sitter parse → ParseResult
  Phase 1: AST Pattern Detection (confidence 0.85-0.95)
  Phase 2: String Extraction (strings >3 chars from AST)
  Phase 3: String Literal Analysis (regex, confidence 0.80-0.90)
  Phase 4: Resolution Index population
```

**Pattern inventory**: SQL (9 regexes), routes (6), sensitive data (8), environment (6), logging (4 — compiled but NEVER USED).

### 3.6 Call Resolution (6 Strategies in TS)

1. Same-file lookup — O(1)
2. Method resolution — O(k) methods in class
3. DI injection — O(1) pattern match on decorators
4. Import-based — O(d) import chain depth
5. Export-based — O(e) exported functions
6. Fuzzy matching — O(f) all functions (expensive)

### 3.7 Reachability (BFS)

- **Forward**: From function X → BFS through calls → collect data_access points
- **Inverse**: Find all accessors of table Y → reverse BFS to entry points
- **Complexity**: O(V + E) per query
- **Variants**: In-memory (fast, memory-heavy) and SQLite-backed (scalable)

### 3.8 Module Coupling (Martin's Metrics)

```
Ca = modules depending on this one
Ce = modules this one depends on
I  = Ce / (Ca + Ce)           — Instability
A  = abstract exports / total — Abstractness
D  = |A + I - 1|              — Distance from main sequence
```

**Cycle detection**: DFS in Rust (incomplete), Tarjan's SCC in TS (correct).

### 3.9 Secret Detection (21 Patterns)

- **Critical (0.9)**: AWS keys, GitHub tokens, Stripe keys, RSA/SSH/PGP private keys
- **High (0.8)**: Google API keys, passwords, JWTs, DB connections, Slack/SendGrid/Twilio
- **Medium (0.6)**: Hardcoded passwords, bearer tokens, generic API keys, webhooks
- **Adjustments**: +0.05 high entropy, +0.05 length >30
- **Placeholder skip**: "example", "placeholder", "your_", "xxx", "todo", "changeme"

### 3.10 Wrapper Detection

```
base = 0.6
+ 0.15 naming patterns (use*, with*, create*, make*)
+ 0.15 wrapper/hook/helper in name
+ 0.10 custom hook pattern (useXxx)
- 0.10 complex functions (>10 calls)
+ 0.10 focused functions (≤3 calls)
threshold = 0.5
```

**12 Categories**: StateManagement, SideEffects, DataFetching, Validation, Logging, Authentication, Caching, ErrorHandling, FormHandling, Routing, Factory, Other.

---

## 4. Key Data Models

### 4.1 ParseResult (Rust — Primary)

```
ParseResult {
  language: Language (10 variants),
  tree: Option<Tree>,              // Raw AST (dropped in NAPI)
  functions: Vec<FunctionInfo>,
  classes: Vec<ClassInfo>,
  imports: Vec<ImportInfo>,
  exports: Vec<ExportInfo>,
  calls: Vec<CallSite>,
  errors: Vec<ParseError>,
  parse_time_us: u64,
}
```

### 4.2 Pattern (Central Entity)

```
Pattern {
  id: String (16-char hex hash),
  subcategory, name, description,
  status: discovered | approved | ignored,
  detectionMethod: ast | regex | semantic | structural | custom,
  confidence: ConfidenceScore,
  confidenceLevel: high | medium | low | uncertain,
  locations: Vec<PatternLocation>,
  outliers: Vec<PatternLocation>,
  severity: error | warning | info | hint,
  autoFixable: bool,
  metadata: { firstSeen, lastSeen, source, tags },
}
```

### 4.3 FunctionEntry (Call Graph)

```
FunctionEntry {
  id: "file:name:line",
  name, start_line, end_line,
  is_entry_point, is_data_accessor,
  calls: Vec<CallEntry>,
  called_by: Vec<String>,
  data_access: Vec<DataAccessRef>,
}
```

### 4.4 Violation (Actionable Output)

```
Violation {
  id, patternId, severity,
  file, range: { start, end },
  message, expected, actual, explanation,
  quickFixes: Vec<QuickFix>,
  aiExplainAvailable, aiFixAvailable,
}
```

### 4.5 Storage Schema

| Database | Tables | Purpose |
|----------|--------|---------|
| drift.db | patterns, pattern_locations, pattern_variants, pattern_examples, pattern_history | Pattern persistence |
| callgraph.db | functions, call_edges, data_access, metadata | Call graph persistence |
| cortex.db | 23 memory types + vectors | AI memory (TS-only) |

---

## 5. Integration Map

### Data Flow

```
Files → Scanner → Parser → [Detectors, Call Graph, Analyzers, Boundaries]
                              ↓              ↓              ↓
                          Patterns      Relationships    Semantic Data
                              ↓              ↓              ↓
                          Storage ←──────────┴──────────────┘
                              ↓
                    MCP Server → AI Agents
                    Quality Gates → CI/CD
                    IDE → Developer Feedback
```

### Dependency Matrix (5 Core Categories)

```
01-rust-core ← Foundation (no dependencies)
02-parsers   ← 01-rust-core
03-detectors ← 02-parsers, 05-analyzers
04-call-graph ← 02-parsers, 01-rust-core
05-analyzers ← 02-parsers, 04-call-graph
```

### Downstream Consumers

| Producer | Consumers |
|----------|-----------|
| Parsers | Detectors, Call Graph, Analyzers, Boundaries, Security, Contracts, Test Topology |
| Patterns | MCP (6+ tools), Quality Gates, Context Generation, Constraints |
| Call Graph | Test Topology, Error Handling, Constraints, Quality Gates, Security, MCP |
| Analyzers | Detectors, Quality Gates, MCP |

---

## 6. Comprehensive Gap Analysis

### 6.1 Performance Gaps

| Gap | Impact | Category |
|-----|--------|----------|
| No incremental scanning | Full rescan every time | Scanner |
| No incremental parsing | Re-parse all files on every scan | Parsers |
| No incremental detection | Re-detect all files on every scan | Detectors |
| No incremental call graph | Full rebuild required | Call Graph |
| No incremental analysis | Full re-analysis every time | Analyzers |
| 350+ TS detectors run sequentially | 5-10s for 10K files (target <1s) | Detectors |
| No parallel detection in TS | Single-threaded execution | Detectors |
| Separate AST traversal per detector | 100+ traversals per file | Detectors |

### 6.2 Feature Gaps (Rust vs TypeScript)

| Feature | Rust | TS | Priority |
|---------|------|-----|----------|
| Generic type parameters | ❌ | ✅ | P0 |
| Pydantic model extraction | ❌ | ✅ (9 files) | P0 |
| Structured annotations | Partial (strings) | ✅ (objects) | P0 |
| Full inheritance chains | Partial (direct) | ✅ (multi-level) | P1 |
| Namespace/package extraction | ❌ | ✅ | P1 |
| Incremental parsing | ❌ | ✅ (tree.edit()) | P2 |
| AST caching | ❌ | ✅ (LRU, 100) | P2 |
| Per-language call extractors | 1 universal | 8 × 3 variants | P0 |
| 6-strategy call resolution | 3 strategies | 6 strategies | P0 |
| DI injection resolution | ❌ | ✅ | P0 |
| Impact analysis | ❌ | ✅ | P1 |
| Dead code detection | ❌ | ✅ | P1 |
| Tarjan's SCC | ❌ (DFS) | ✅ | P1 |
| Module roles/zones | ❌ | ✅ | P1 |
| Refactor impact | ❌ | ✅ | P1 |
| Type analysis | ❌ | ✅ (TS-only) | P0 |
| Scope/symbol resolution | ❌ | ✅ (TS/JS-only) | P0 |
| CFG construction | ❌ | ✅ | P1 |
| 20 ORM matchers | ~30 AST patterns | ✅ | P1 |
| Rules engine | ❌ | ✅ (4,900 LOC) | P1 |
| Quick fix generation | ❌ | ✅ (7 strategies) | P2 |

### 6.3 Architectural Gaps

| Gap | Impact |
|-----|--------|
| Three ParseResult shapes | Type confusion, maintenance burden |
| Dual-layer architecture | Feature parity drift, double maintenance |
| No structured error handling in Rust | String-based errors, poor NAPI propagation |
| thread_local! for parsers | Unbounded memory growth |
| Violations defined but never populated | Dead code in unified analyzer |
| Log patterns compiled but never used | Wasted compilation, missing detection |
| ResolutionStats fields all TODO | No resolution quality tracking |
| JSON shard duplication | Patterns in both SQLite and JSON |
| No pattern decay | Stale conventions enforced forever |
| No pattern merging | Duplicate patterns from different detectors |
| No feedback loop | Unknown false-positive rate |
| No cross-file data flow | Intraprocedural only |
| No taint analysis | Cannot track data transformations |
| No field-level reachability | Table-level only |

### 6.4 Security Gaps

| Gap | Impact |
|-----|--------|
| Only 21 secret patterns | Missing Azure, GCP, npm, PyPI tokens |
| No OWASP/CWE mapping | Cannot produce compliance reports |
| No taint analysis | Cannot distinguish sanitized from unsanitized data |
| No command injection detection | Missing OWASP A03 coverage |
| No SSRF detection | Missing OWASP A10 coverage |
| No insecure deserialization | Missing OWASP A08 coverage |
| No weak crypto detection | Missing OWASP A02 coverage |

### 6.5 Coverage Gaps

| Gap | Impact |
|-----|--------|
| Django: contracts only | No learning/semantic detectors |
| Go/Rust/C++: api+auth+errors only | Missing config, logging, testing, structural |
| SemanticLearningDetector: stub | Not implemented |
| Custom match strategy: defined but unused | Not implemented |
| No GraphQL contract detection | Missing modern API paradigm |
| No gRPC contract detection | Missing microservice paradigm |
| Wrapper registry: React-focused | Missing Vue, Angular, Svelte, Express |
| Type analysis: TS-only | No type analysis for Python, Java, Go |
| Semantic analysis: TS/JS-only | No scope analysis for other languages |

---

## 7. Cross-Cutting Themes

### 7.1 Incrementality

Every subsystem lacks incremental computation. V1 is batch-only. V2 must be incremental-first:
- File-level: skip unchanged files via content hash
- Edit-level: tree-sitter `tree.edit()` for IDE integration
- Query-level: Salsa-based derived queries with auto-invalidation

### 7.2 Single-Pass Architecture

V1 traverses each file's AST 100+ times (once per detector). V2 must use ESLint's visitor pattern: traverse once, dispatch to all interested handlers.

### 7.3 Rust-First

V1 is TypeScript-heavy with Rust as a performance accelerator. V2 inverts this: Rust owns all computation, TypeScript is thin orchestration.

### 7.4 Enterprise Security

V1 has basic security detection. V2 needs OWASP/CWE alignment, taint analysis, 100+ secret patterns, and compliance reporting.

### 7.5 Statistical Rigor

V1's confidence scoring lacks decay, momentum, and Bayesian modeling. V2 needs temporal awareness, contested convention handling, and calibrated thresholds.

---

## 8. V1 Metrics Summary

| Metric | Value |
|--------|-------|
| Total Rust code | ~11,000 lines |
| Total TypeScript code | ~40,000+ lines |
| Languages supported | 10 (parsing), 7 (detection) |
| Detector count | 350+ (16 categories) |
| Framework integrations | 6 (Spring, ASP.NET, Laravel, Django, Go, Rust/C++) |
| ORM matchers | 20 |
| Secret patterns | 21 |
| NAPI functions | ~25 |
| Call resolution strategies | 6 (TS), 3 (Rust) |
| SQLite tables | 9+ (patterns: 5, call graph: 4) |
| Pattern categories | 15 (AST) + 16 (detectors) |
| Test frameworks detected | 11 (Rust), 35+ (TS) |

---

## Quality Checklist

- [x] All 5 category RECAPs synthesized
- [x] All subsystems inventoried with line counts
- [x] All 10+ core algorithms documented
- [x] All key data models captured
- [x] Complete integration map with dependency matrix
- [x] Comprehensive gap analysis (performance, features, architecture, security, coverage)
- [x] Cross-cutting themes identified
- [x] V1 metrics summarized
- [x] V2 vision stated
