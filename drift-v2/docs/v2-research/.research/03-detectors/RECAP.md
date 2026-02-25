# 03 Detectors — Research Recap

## Executive Summary

The Detector System (`packages/detectors/`) is Drift's pattern recognition intelligence layer — a 100% TypeScript engine comprising 350+ source files organized into 16 categories, each with up to 3 detection variants (base, learning, semantic). It discovers codebase conventions through statistical analysis rather than enforcing prescribed rules, scores patterns with a weighted confidence algorithm (frequency 0.4, consistency 0.3, age 0.15, spread 0.15), identifies outliers via Z-score/IQR statistical methods, and generates actionable violations through a rules engine. The system supports 7 languages natively, extends to 6 frameworks (Laravel, Spring, ASP.NET, Django, Go, Rust/C++), and feeds patterns to the MCP layer, quality gates, and context generation — making it the central intelligence that powers Drift's core thesis of offline convention discovery.

## Current Implementation

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PRESENTATION LAYER                              │
│  MCP Tools (drift_patterns_list, drift_pattern_get, drift_file_patterns,│
│  drift_code_examples, drift_validate_change, drift_prevalidate)         │
├─────────────────────────────────────────────────────────────────────────┤
│                         RULES ENGINE                                    │
│  Evaluator → Violation Generation → Severity Manager → Variant Manager  │
│  (evaluator.ts, rule-engine.ts, variant-manager.ts, severity-manager.ts)│
├──────────┬──────────┬──────────┬────────────────────────────────────────┤
│ Pattern  │Confidence│ Outlier  │   Detection Pipeline                   │
│ Matcher  │ Scorer   │ Detector │   (8-phase end-to-end)                 │
│ (AST,    │ (4-factor│ (Z-score,│                                        │
│  Regex,  │  weighted│  IQR,    │                                        │
│  Struct) │  0.4/0.3/│  Rule-   │                                        │
│          │  0.15/   │  based)  │                                        │
│          │  0.15)   │          │                                        │
├──────────┴──────────┴──────────┴────────────────────────────────────────┤
│                    DETECTOR REGISTRY & LOADER                           │
│  DetectorRegistry (register/query/enable/disable/events)                │
│  DetectorLoader (lazy loading, factory functions, dependency tracking)   │
├─────────────────────────────────────────────────────────────────────────┤
│                    BASE CLASSES (7 types)                                │
│  BaseDetector → RegexDetector                                           │
│              → ASTDetector                                              │
│              → StructuralDetector                                       │
│              → LearningDetector (ValueDistribution algorithm)           │
│              → SemanticDetector (keyword + context classification)       │
│              → SemanticLearningDetector (stub/placeholder)              │
│              → UnifiedDetector (multi-strategy merge)                   │
├─────────────────────────────────────────────────────────────────────────┤
│                    16 DETECTOR CATEGORIES                                │
│  security(7) │ auth(6) │ errors(7) │ api(7) │ components(8)            │
│  config(7) │ contracts(4+) │ data-access(7+3) │ documentation(5)       │
│  logging(7) │ performance(6) │ structural(9) │ styling(8)              │
│  testing(7) │ types(7) │ accessibility(6)                               │
├─────────────────────────────────────────────────────────────────────────┤
│                    FRAMEWORK EXTENSIONS                                  │
│  Spring(12 categories) │ ASP.NET(11 categories) │ Laravel(12 categories)│
│  Django(contracts) │ Go(api+auth+errors) │ Rust(api+auth+errors)        │
│  C++(api+auth+errors)                                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                    STORAGE LAYER                                        │
│  SQLite: patterns, pattern_locations, pattern_variants,                 │
│          pattern_examples, pattern_history                               │
│  JSON Shards: .drift/patterns/*.json (14 category files)               │
│  Indexes: .drift/indexes/by-category.json, by-file.json                │
└─────────────────────────────────────────────────────────────────────────┘
```

### Component Inventory

| Component | Location | Files | Purpose |
|-----------|----------|-------|---------|
| Base Classes | `detectors/src/base/` | 7 | Abstract detector hierarchy |
| Registry | `detectors/src/registry/` | 3 | Central registration, lazy loading, querying |
| 16 Categories | `detectors/src/{category}/` | ~100 base + ~100 learning + ~100 semantic | Pattern detection |
| Framework Extensions | Distributed across categories | ~60+ | Framework-specific detection |
| PHP Utilities | `detectors/src/php/` | 5 | PHP extraction (class, method, attribute, docblock) |
| Contract System | `detectors/src/contracts/` | 4 core + 4 framework extensions | BE↔FE contract matching |
| Confidence Scorer | `core/src/matcher/confidence-scorer.ts` | 1 | Weighted composite scoring |
| Pattern Matcher | `core/src/matcher/pattern-matcher.ts` | 1 | Multi-strategy matching engine |
| Outlier Detector | `core/src/matcher/outlier-detector.ts` | 1 | Statistical deviation detection |
| Rules Engine | `core/src/rules/` | 4 | Violation generation pipeline |
| Storage | `core/src/storage/` | Multiple | SQLite + JSON persistence |

---

## Key Algorithms

### 1. Confidence Scoring (Heart of Drift's Learning)

**Complexity**: O(1) per pattern, O(n) for batch scoring across n patterns

```
score = frequency × 0.4 + consistency × 0.3 + ageFactor × 0.15 + spread × 0.15
```

| Factor | Calculation | Range |
|--------|------------|-------|
| Frequency | occurrences / totalLocations | [0.0, 1.0] |
| Consistency | 1 - variance (clamped) | [0.0, 1.0] |
| Age Factor | Linear scale: 0.1 → 1.0 over 30 days | [0.1, 1.0] |
| Spread | fileCount / totalFiles | [0.0, 1.0] |

**Classification**: high (≥0.85), medium (≥0.70), low (≥0.50), uncertain (<0.50)

**Weight validation**: Constructor enforces sum = 1.0 (±0.001 tolerance).

**Note**: Gap analysis documentation lists weights as 0.35/0.25/0.15/0.25 but the actual code uses 0.4/0.3/0.15/0.15. The code is authoritative.

### 2. ValueDistribution (Convention Learning)

**Complexity**: O(n) for learning across n files, O(1) for dominance check

```
For each unique value:
  filePercentage = filesWithValue / totalFiles
  if filePercentage >= 0.6 AND occurrences >= 3:
    → dominant convention (confidence = filePercentage)
```

**Configuration**: minOccurrences=3, dominanceThreshold=0.6, minFiles=2

### 3. Outlier Detection (Statistical Deviation)

**Method Selection**: n ≥ 30 → Z-Score, n < 30 → IQR

**Z-Score** (O(n)):
```
zScore = (value - mean) / stdDev
adjustedThreshold = baseThreshold × (1 + (1 - sensitivity))
|zScore| > adjustedThreshold → outlier
```
Significance: |z| > 3.0 (high), > 2.5 (medium), > 2.0 (low)

**IQR** (O(n log n) due to sorting):
```
Q1 = 25th percentile, Q3 = 75th percentile, IQR = Q3 - Q1
lowerBound = Q1 - 1.5 × IQR, upperBound = Q3 + 1.5 × IQR
value outside bounds → outlier
```

**Sensitivity adjustment**: Both methods scale thresholds by `(1 + (1 - sensitivity))`, where sensitivity ∈ [0.0, 1.0].

### 4. Pattern Matching (Multi-Strategy)

**AST Matching** (O(n) tree traversal):
- Depth-first traversal with nodeType, property, and child pattern matching
- Confidence = matchedChecks / totalChecks × childConfidence
- Supports depth constraints, descendant search, regex property values

**Regex Matching** (O(n) per pattern):
- Global flag always applied, multiline optional
- Named capture group extraction
- Confidence always 1.0 (binary match)

**Structural Matching** (O(1) per file):
- Glob patterns, naming conventions (5 styles), sibling/parent checks
- AND logic: all checks must pass
- Confidence 1.0 if all pass, 0.0 otherwise

**Caching**: LRU cache (max 1000 entries, 60s TTL, content-hash validation)

### 5. Contract Matching (Path Similarity)

**Complexity**: O(n × m) where n = endpoints, m = API calls

Multi-factor weighted path matching:
- Segment name Jaccard similarity
- Segment count penalty
- Suffix match scoring
- Resource name matching
- Parameter position alignment

### 6. Semantic Context Classification

**Complexity**: O(n × k) where n = lines, k = keywords

```
For each keyword match:
  Classify context: function_call | import | assignment | declaration | comment | string | other
  Score: base (keyword strength) + context boost + import alignment - ambiguity penalty
```

### 7. Unified Strategy Merging

**Complexity**: O(s × n) where s = strategies, n = results per strategy

```
1. Run all strategies in parallel
2. Deduplicate patterns by location (keep highest confidence)
3. Deduplicate violations by file+line
4. Combined confidence = weighted average (configurable: max | average | weighted)
```

---

## Data Models

### Core Types

```typescript
// Pattern — The central entity
Pattern {
  id: string;                    // 16-char hex hash (detectorId + patternId)
  subcategory: string;           // e.g., "sql-injection"
  name: string;                  // Human-readable
  description: string;
  status: "discovered" | "approved" | "ignored";
  detectionMethod: "ast" | "regex" | "semantic" | "structural" | "custom";
  detector: { type, config: { detectorId, patternId } };
  confidence: ConfidenceScore;
  confidenceLevel: "high" | "medium" | "low" | "uncertain";
  locations: PatternLocation[];
  outliers: PatternLocation[];
  severity: "error" | "warning" | "info" | "hint";
  autoFixable: boolean;
  metadata: { firstSeen, lastSeen, source, tags[] };
}

// ConfidenceScore — Statistical scoring
ConfidenceScore {
  frequency: number;     // 0.0-1.0
  consistency: number;   // 0.0-1.0
  age: number;           // days since firstSeen
  spread: number;        // file count
  score: number;         // 0.0-1.0 weighted composite
  level: ConfidenceLevel;
}

// PatternLocation — Where patterns are found
PatternLocation {
  file: string;
  line: number;          // 1-indexed
  column: number;        // 1-indexed
  isOutlier: boolean;
  confidence: number;    // 0.0-1.0
  outlierReason?: string;
}

// DetectionContext — Input to every detector
DetectionContext {
  file: string;
  content: string;
  ast: AST | null;
  imports: ImportInfo[];
  exports: ExportInfo[];
  projectContext: { rootDir, files[], config };
  language: Language;
  extension: string;
  isTestFile: boolean;
  isTypeDefinition: boolean;
}

// DetectionResult — Output from every detector
DetectionResult {
  patterns: PatternMatch[];
  violations: Violation[];
  confidence: number;
  metadata?: { duration?, nodesAnalyzed?, warnings?, custom? };
}

// Violation — Actionable feedback
Violation {
  id: string;
  patternId: string;
  severity: "error" | "warning" | "info" | "hint";
  file: string;
  range: { start: Position; end: Position };
  message: string;
  expected: string;
  actual: string;
  explanation: string;
  quickFixes?: QuickFix[];
  aiExplainAvailable: boolean;
  aiFixAvailable: boolean;
}

// OutlierInfo — Statistical deviation
OutlierInfo {
  location: Location;
  patternId: string;
  reason: string;
  deviationScore: number;        // 0.0-1.0
  deviationType: OutlierType;    // structural|syntactic|semantic|stylistic|missing|extra|inconsistent
  expected?: string;
  actual?: string;
  suggestedFix?: string;
  significance: "high" | "medium" | "low";
}
```

### Contract Types

```typescript
ExtractedEndpoint {
  method: HttpMethod;
  path: string;
  normalizedPath: string;
  file: string;
  line: number;
  responseFields: ContractField[];
  requestFields?: ContractField[];
  framework: string;
}

ExtractedApiCall {
  method: HttpMethod;
  path: string;
  normalizedPath: string;
  file: string;
  line: number;
  responseFields: ContractField[];
  requestFields?: ContractField[];
  library: string;
}

MatchingResult {
  contracts: Contract[];
  unmatchedEndpoints: ExtractedEndpoint[];
  unmatchedApiCalls: ExtractedApiCall[];
}
```

### PHP Types (Comprehensive)

```typescript
PhpClassInfo { name, namespace?, modifiers, extends?, implements[], traits[], properties[], methods[], constants[], attributes[], docblock?, location }
PhpMethodInfo { name, modifiers, parameters[], returnType?, attributes[], docblock?, location }
PhpAttribute { name, arguments[], target, location }
DocblockInfo { summary, description?, tags[], location }
// Plus: PhpInterfaceInfo, PhpTraitInfo, PhpEnumInfo, PhpFunctionInfo, PhpUseStatement, PhpNamespace, PhpPropertyInfo, PhpConstantInfo, PhpTypeInfo
```

### Storage Schema (5 SQLite tables)

| Table | Purpose | Key Columns |
|-------|---------|-------------|
| `patterns` | Core pattern data | id, category, subcategory, confidence_*, status, severity |
| `pattern_locations` | Where patterns appear | pattern_id, file, line, column_num, is_outlier |
| `pattern_variants` | Scoped overrides | pattern_id, scope (global/directory/file), *_override |
| `pattern_examples` | Code examples | pattern_id, file, code, is_positive |
| `pattern_history` | Change tracking | pattern_id, action, old_value, new_value |

**Indexes**: 7 indexes covering category, status, confidence, file, pattern_id, scope lookups.

---

## Detection Pipeline (8 Phases)

```
Phase 1: FILE SCANNING
  Walk directory → .driftignore → config excludes → content hash → incremental skip
  Output: FileMetadata[] (path, language, size, hash)

Phase 2: PARSING
  Language detection → tree-sitter AST → import/export extraction → file classification
  Output: DetectionContext[] (one per file)

Phase 3: DETECTION
  Registry query → priority sort → per-file per-detector execution
  Order: Base (regex, fast) → Learning (adaptive) → Semantic (deep) → Unified (merged)
  Output: DetectionResult[] (patterns + violations per file per detector)

Phase 4: AGGREGATION
  Group by pattern ID → collect locations → count occurrences → calculate variance
  Output: AggregatedMatchResult[] (cross-file pattern data)

Phase 5: CONFIDENCE SCORING
  frequency × 0.4 + consistency × 0.3 + ageFactor × 0.15 + spread × 0.15
  Classify: high/medium/low/uncertain
  Output: Pattern[] with ConfidenceScore

Phase 6: OUTLIER DETECTION
  n ≥ 30 → Z-Score | n < 30 → IQR | + rule-based
  Mark outlier locations with reason and significance
  Output: Pattern[] with outlier annotations

Phase 7: STORAGE
  SQLite transaction → upsert patterns → bulk insert locations → history tracking
  JSON shards → index updates → checksum validation
  Output: Persisted state

Phase 8: VIOLATION GENERATION
  Pattern matcher → outlier detector → violation creation → missing pattern check → quick fixes
  Output: Violation[] (IDE diagnostics, CLI output, CI checks)
```

---

## Detector Categories — Complete Inventory

### Category Summary (16 categories, ~100+ base detectors)

| # | Category | Base Detectors | Learning | Semantic | Framework Extensions |
|---|----------|---------------|----------|----------|---------------------|
| 1 | security | 7 (csrf, csp, input-sanitization, rate-limiting, secret-mgmt, sql-injection, xss) | 7 | 7 | Laravel, ASP.NET |
| 2 | auth | 6 (audit-logging, middleware, permissions, rbac, resource-ownership, token-handling) | 6 | 6 | ASP.NET(5), Laravel, Go, C++, Rust |
| 3 | errors | 7 (async-errors, circuit-breaker, error-codes, error-logging, propagation, hierarchy, try-catch) | 7 | 7 | Laravel, ASP.NET, C++, Go, Rust |
| 4 | api | 7 (client-patterns, error-format, http-methods, pagination, response-envelope, retry, route-structure) | 7 | — | Go(5), Rust(4), C++(3), Laravel |
| 5 | components | 8 (structure, composition, duplicate, near-duplicate, props, ref-forwarding, state, modal) | 7 | 8 | — |
| 6 | config | 7 (validation, constants, defaults, env-naming, environment, feature-flags, required-optional) | 6 | 6 | Laravel, ASP.NET |
| 7 | contracts | 4 core (backend-endpoint, frontend-type, contract-matcher, schema-parser) | — | — | Spring(2), Laravel, Django(4), ASP.NET |
| 8 | data-access | 7+3 boundary (connection-pooling, dto, n+1, query, repository, transaction, validation + orm-model, query-access, sensitive-field) | 7 | 7+3 | Laravel, ASP.NET |
| 9 | documentation | 5 (deprecation, example-code, jsdoc, readme, todo) | 5 | 5 | ASP.NET |
| 10 | logging | 7 (context-fields, correlation-ids, health-checks, log-levels, metric-naming, pii-redaction, structured-format) | 7 | 7 | Laravel, ASP.NET |
| 11 | performance | 6 (bundle-size, caching, code-splitting, debounce-throttle, lazy-loading, memoization) | 6 | 6 | Laravel, ASP.NET |
| 12 | structural | 9 (barrel-exports, circular-deps, co-location, directory, file-naming, file-naming-unified, import-ordering, module-boundaries, package-boundaries) | 8 | 8 | Laravel, ASP.NET |
| 13 | styling | 8 (class-naming, color-usage, design-tokens, responsive, spacing-scale, tailwind, typography, z-index) | 8 | 8 | — |
| 14 | testing | 7 (co-location, describe-naming, file-naming, fixtures, mocks, setup-teardown, test-structure) | 7 | 7 | Laravel, ASP.NET |
| 15 | types | 7 (any-usage, file-location, generics, interface-vs-type, naming-conventions, type-assertions, utility-types) | 7 | 7 | ASP.NET |
| 16 | accessibility | 6 (alt-text, aria-roles, focus-management, heading-hierarchy, keyboard-nav, semantic-html) | 6 | 6 | — |

### Framework Extension Coverage

| Framework | Language | Categories Covered | Depth |
|-----------|---------|-------------------|-------|
| Spring Boot | Java | 12 (api, async, auth, config, data, di, errors, logging, structural, testing, transaction, validation) | Full (learning + semantic per category) |
| ASP.NET | C# | 11 (auth(5), config, contracts, data-access, documentation, errors, logging, performance, security, structural, testing, types) | Deep (many with semantic variants) |
| Laravel | PHP | 12 (api, async, auth, config, contracts, data-access, errors, logging, performance, security, structural, testing, validation) | Full (aggregator index) |
| Django | Python | 1 (contracts: url-extractor, viewset-extractor, serializer-extractor) | Contracts only |
| Go | Go | 3 (api: gin/echo/fiber/chi/net-http, auth: middleware, errors) | API-focused |
| Rust | Rust | 3 (api: actix/axum/rocket/warp, auth: middleware, errors) | API-focused |
| C++ | C++ | 3 (api: crow/boost-beast/qt-network, auth: middleware, errors) | API-focused |

---

## Capabilities

### What It Can Do Today

1. **Convention Discovery**: Automatically discovers 100+ convention types across 16 categories without configuration
2. **Statistical Confidence**: Every pattern scored with 4-factor weighted algorithm — no binary pass/fail
3. **Learning from Codebase**: ValueDistribution algorithm identifies dominant conventions (≥60% threshold)
4. **Outlier Detection**: Z-score (large samples) and IQR (small samples) identify statistical deviations
5. **Multi-Strategy Detection**: Base (regex, fast), Learning (adaptive), Semantic (keyword-context), Unified (merged)
6. **Framework Awareness**: Deep integration with Spring Boot (12 categories), ASP.NET (11), Laravel (12)
7. **Contract Matching**: BE↔FE API contract detection with path similarity scoring
8. **Violation Generation**: Actionable violations with severity, expected/actual, explanations, quick fixes
9. **Pattern Lifecycle**: discovered → approved/ignored → enforced, with history tracking
10. **Scoped Overrides**: Variant system (global/directory/file scope) with expiration
11. **Lazy Loading**: Factory-based detector loading with dependency tracking
12. **7 Language Support**: TypeScript, JavaScript, Python, Go, Rust, C++, PHP/C#
13. **LRU Caching**: Pattern matcher cache (1000 entries, 60s TTL, content-hash validation)
14. **PHP Extraction**: Comprehensive PHP 8 parsing (classes, methods, attributes, docblocks, enums)
15. **Quick Fix Generation**: Auto-fixable violations with workspace edit suggestions

### Limitations

1. **Performance**: 350+ TypeScript detectors running sequentially per file — slow for large codebases (5-10s for 10K files target is <1s)
2. **No Incremental Detection**: Full re-detection on every scan; no per-file delta analysis
3. **Rust Parity Gap**: Rust unified analyzer has ~30 AST patterns vs 350+ TS detectors — massive feature gap
4. **SemanticLearningDetector**: Stub/placeholder — not implemented
5. **Custom Match Strategy**: Defined in types but not implemented
6. **Django Coverage**: Only contracts — no learning/semantic detectors for Django patterns
7. **Go/Rust/C++ Coverage**: Only api+auth+errors — missing config, logging, testing, structural, etc.
8. **No Cross-File Learning**: Learning detectors operate per-file during detection; learning phase is project-wide but detection is file-scoped
9. **No Call Graph Integration**: Detectors don't leverage call graph for cross-function pattern analysis
10. **No Data Flow Analysis**: Pattern matching is structural/textual — no taint tracking or data flow
11. **Confidence Weight Discrepancy**: Documentation says 0.35/0.25/0.15/0.25, code uses 0.4/0.3/0.15/0.15
12. **No Parallel Detection**: Detectors run sequentially in TypeScript — no multi-threaded execution
13. **JSON Shard Duplication**: Patterns stored in both SQLite and JSON — dual-write overhead
14. **No Pattern Decay**: Old patterns never lose confidence even if the convention changes
15. **No Pattern Merging**: Similar patterns from different detectors aren't consolidated
16. **Contract Matching Limitations**: No GraphQL support, no gRPC support, no WebSocket contract detection

---

## Integration Points

| Connects To | Direction | How |
|-------------|-----------|-----|
| **02-parsers** | Consumes | AST input via tree-sitter; imports/exports extraction; language detection |
| **05-analyzers** | Consumes | Analysis utilities; rules engine shared infrastructure |
| **01-rust-core** | Parallel | Rust unified analyzer (~30 patterns) runs alongside TS detectors (350+) |
| **23-pattern-repository** | Produces | Patterns written to storage abstraction layer |
| **07-mcp** | Produces | Patterns queried by 6+ MCP tools for AI consumption |
| **09-quality-gates** | Produces | Pattern compliance checked for CI/CD enforcement |
| **18-constraints** | Produces | Pattern data used for architectural constraint verification |
| **22-context-generation** | Produces | Patterns feed AI context generation and token budgeting |
| **25-services-layer** | Consumed by | Scan pipeline orchestrates detector execution |
| **08-storage** | Produces | SQLite persistence (5 tables, 7 indexes) + JSON shards |

### Critical Downstream Dependencies

The detector system is a **producer** — it creates the patterns that the entire downstream pipeline depends on:
- **MCP layer** cannot serve AI agents without patterns
- **Quality gates** cannot enforce compliance without patterns
- **Context generation** cannot budget tokens without pattern data
- **Constraints** cannot verify architecture without pattern evidence

Any change to detector output format, confidence scoring, or pattern schema has **cascading impact** across 5+ downstream categories.

---

## V2 Migration Status

### Current State: Dual Engine

```
TypeScript (350+ detectors)          Rust (unified analyzer, ~30 patterns)
├── Full 16-category coverage        ├── AST queries for 9 languages
├── Learning + Semantic variants     ├── String regex fallback
├── Framework extensions (6)         ├── Resolution index
├── Contract matching                ├── String interning
├── Rules engine                     └── ~30 AST patterns total
├── Confidence scoring               
├── Outlier detection                
└── Storage (SQLite + JSON)          
```

### What Must Migrate to Rust (Priority Order)

| Priority | Component | Rationale |
|----------|-----------|-----------|
| P0 | Pattern matching engine | Hot path — called per-file per-pattern; biggest perf win |
| P0 | Confidence scoring | Pure math — trivial port, called for every pattern |
| P0 | Outlier detection | Pure math — Z-score/IQR, benefits from SIMD |
| P1 | Base detectors (regex) | 100+ regex detectors — Rust regex crate is 10-100x faster |
| P1 | Storage writes | Bulk SQLite inserts — Rust's rusqlite with transactions |
| P1 | Aggregation pipeline | Cross-file data merging — memory-efficient in Rust |
| P2 | Learning detectors | ValueDistribution algorithm — straightforward port |
| P2 | Semantic detectors | Keyword scanning + context classification |
| P2 | Framework detectors | Large surface area — migrate incrementally by framework |
| P3 | Contract matching | Complex but lower frequency — can stay in TS longer |
| P3 | Rules engine | Orchestration-heavy — may stay as thin TS wrapper |

### Architectural Decisions Pending

1. **Detector registration in Rust**: Should Rust own the registry, or should TS orchestrate which Rust detectors to run?
2. **Learning state persistence**: Where do learned conventions live? Rust memory? SQLite? Shared via NAPI?
3. **Incremental detection**: How to detect only changed files without re-running all detectors?
4. **Pattern schema ownership**: Should Rust define the canonical Pattern type, with TS consuming via NAPI?
5. **Framework detector strategy**: Migrate all at once per framework, or incrementally by category?

---

## Open Questions

1. **SemanticLearningDetector**: Is this a planned feature or abandoned? It's a stub with no implementation.
2. **Custom match strategy**: Defined in types but not implemented — is this planned for v2?
3. **Confidence weight discrepancy**: Documentation (0.35/0.25/0.15/0.25) vs code (0.4/0.3/0.15/0.15) — which is intended for v2?
4. **Pattern decay**: Should old patterns lose confidence over time if the convention shifts? Currently no decay mechanism exists.
5. **Pattern merging**: When multiple detectors find the same convention, should patterns be consolidated?
6. **GraphQL/gRPC contracts**: Is contract detection planned beyond REST APIs?
7. **Django/Go/Rust/C++ expansion**: What's the priority for expanding framework coverage beyond api+auth+errors?
8. **Call graph integration**: Should detectors leverage the call graph for cross-function pattern analysis?
9. **Data flow analysis**: Is intraprocedural taint tracking planned for security detectors?
10. **Parallel detection in TS**: Before Rust migration, should TS detectors run in worker threads?

---

## Quality Checklist

- [x] All 19 files in category have been read (11 main + 8 patterns/)
- [x] Architecture is clearly described with diagram
- [x] All 7 key algorithms documented with complexity analysis
- [x] All data models listed with field descriptions (Pattern, ConfidenceScore, PatternLocation, DetectionContext, DetectionResult, Violation, OutlierInfo, Contract types, PHP types)
- [x] All 16 detector categories inventoried with detector counts
- [x] All 7 framework extensions documented with coverage depth
- [x] 8-phase detection pipeline documented end-to-end
- [x] Storage schema documented (5 tables, 7 indexes, JSON shards)
- [x] 16 limitations honestly assessed
- [x] 10 integration points mapped to other categories
- [x] V2 migration status documented with priority ordering
- [x] 10 open questions identified
