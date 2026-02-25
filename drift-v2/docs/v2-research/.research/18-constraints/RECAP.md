# 18 Constraints — Research Recap

## Executive Summary

The Constraints System (`packages/core/src/constraints/`, ~8 TypeScript source files across 4 subdirectories) is Drift's architectural enforcement layer — the subsystem that transforms statistically discovered patterns into enforceable invariants. Unlike patterns (which describe what IS), constraints enforce what MUST BE. The system mines invariants from 5 Drift data sources (patterns, call graph, boundaries, test topology, error handling), synthesizes them into typed constraints with confidence scoring and evidence tracking, persists them as JSON files organized by category, and verifies code changes against applicable constraints to produce violation reports. It supports 12 invariant types (must_have, must_not_have, must_precede, must_follow, must_colocate, must_separate, must_wrap, must_propagate, cardinality, data_flow, naming, structure), 10 constraint categories (api, auth, data, error, test, security, structural, performance, logging, validation), and a lifecycle model (discovered → approved → enforced → ignored). The system is consumed by Quality Gates (constraint-verification gate), MCP tools (drift_validate_change, drift_prevalidate), CLI commands (drift constraints list/approve/ignore), and the Cortex memory system (constraint_override memories, constraint links). This is Layer 3 (Intelligence) of Drift's architecture — sitting between the Analysis layer (detectors, call graph) and the Enforcement layer (quality gates, rules engine).

---

## Current Implementation

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         CONSUMER LAYER                                   │
│  Quality Gates (constraint-verification gate)                            │
│  MCP Tools (drift_validate_change, drift_prevalidate)                    │
│  CLI (drift constraints list/approve/ignore)                             │
│  Cortex (constraint_override memories, memory_constraints links)         │
│  Context Generation (constraint gatherer, 20% token budget)              │
├─────────────────────────────────────────────────────────────────────────┤
│                         CONSTRAINT PIPELINE                              │
│                                                                          │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐  │
│  │ InvariantDetector │───▶│ConstraintSynth.  │───▶│ ConstraintStore  │  │
│  │                   │    │                   │    │                   │  │
│  │ Mines invariants  │    │ Converts to typed │    │ JSON persistence │  │
│  │ from 5 sources    │    │ constraints with  │    │ Category-indexed │  │
│  │ Calculates conf.  │    │ IDs, dedup, merge │    │ CRUD + lifecycle │  │
│  │ Collects evidence │    │ Auto-approval     │    │ Scope matching   │  │
│  └──────────────────┘    └──────────────────┘    └────────┬─────────┘  │
│                                                            │             │
│  ┌─────────────────────────────────────────────────────────▼──────────┐ │
│  │                    ConstraintVerifier                               │ │
│  │  Validates code against applicable constraints                     │ │
│  │  Change-aware verification (only checks changed lines)             │ │
│  │  Produces VerificationResult with violations, pass/fail/skip       │ │
│  └────────────────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────────────┤
│                         DATA SOURCES                                     │
│  Patterns (high-confidence approved) │ Call Graph (auth-before-data)     │
│  Boundaries (data access invariants) │ Test Topology (coverage reqs)     │
│  Error Handling (boundary patterns)                                      │
└─────────────────────────────────────────────────────────────────────────┘
```

### Component Inventory

| Component | Location | LOC (est.) | Purpose |
|-----------|----------|------------|---------|
| Core Types | `constraints/types.ts` | ~300 | Constraint, ConstraintInvariant, ConstraintScope, ConstraintConfidence, ConstraintEnforcement, ConstraintViolation, VerificationResult, query types |
| Invariant Detector | `constraints/extraction/invariant-detector.ts` | ~400 | Mines invariants from 5 Drift data sources |
| Constraint Synthesizer | `constraints/extraction/constraint-synthesizer.ts` | ~350 | Converts invariants to Constraint objects, dedup, merge, auto-approve |
| Constraint Store | `constraints/store/constraint-store.ts` | ~500 | JSON file persistence, CRUD, lifecycle, querying, scope matching |
| Constraint Verifier | `constraints/verification/constraint-verifier.ts` | ~450 | Validates code against constraints, change-aware, violation reporting |
| Index | `constraints/index.ts` | ~30 | Public exports |
| **Total** | | **~2,030** | |

### Storage Layout

```
.drift/constraints/
├── discovered/
│   ├── api.json           # API endpoint constraints
│   ├── auth.json          # Authentication/authorization constraints
│   ├── data.json          # Data access layer constraints
│   ├── error.json         # Error handling constraints
│   ├── test.json          # Test coverage constraints
│   ├── security.json      # Security pattern constraints
│   ├── structural.json    # Module/file structure constraints
│   ├── performance.json   # Performance pattern constraints
│   ├── logging.json       # Logging requirement constraints
│   └── validation.json    # Input validation constraints
├── index.json             # Category index for fast lookups
└── (custom constraints stored alongside)
```

---

## Subsystem Deep Dives

### 1. Type System (`types.ts`)

The type system defines the complete constraint data model — ~300 lines, ~15 interfaces.

**Core Type: Constraint**
```typescript
interface Constraint {
  id: string;                          // Generated hash-based ID
  name: string;                        // Human-readable name
  description: string;                 // What this constraint enforces
  category: ConstraintCategory;        // 1 of 10 categories
  derivedFrom: ConstraintSource;       // What Drift data produced this
  invariant: ConstraintInvariant;      // The actual rule
  scope: ConstraintScope;              // Where it applies
  confidence: ConstraintConfidence;    // Statistical confidence
  enforcement: ConstraintEnforcement;  // How to enforce
  status: ConstraintStatus;            // Lifecycle state
  language: ConstraintLanguage;        // Target language(s)
  metadata: ConstraintMetadata;        // Timestamps, version, etc.
}
```

**10 Constraint Categories**: `api` | `auth` | `data` | `error` | `test` | `security` | `structural` | `performance` | `logging` | `validation`

**4 Status States**: `discovered` (pending review) → `approved` (actively enforced) → `ignored` (not enforced) | `custom` (user-defined)

**9 Supported Languages**: `typescript` | `javascript` | `python` | `java` | `csharp` | `php` | `rust` | `cpp` | `all`

**12 Invariant Types**:

| Type | Semantics | Verification Strategy |
|------|-----------|----------------------|
| `must_have` | "X must have Y" | AST pattern matching |
| `must_not_have` | "X must not have Y" | AST pattern matching (negated) |
| `must_precede` | "X must come before Y" | Call graph path analysis |
| `must_follow` | "X must come after Y" | Call graph path analysis |
| `must_colocate` | "X and Y must be in same location" | File/directory structure |
| `must_separate` | "X and Y must be in different locations" | File/directory structure |
| `must_wrap` | "X must be wrapped in Y" | AST containment check |
| `must_propagate` | "X must propagate to Y" | Call graph reachability |
| `cardinality` | "X must have exactly N of Y" | Count-based AST check |
| `data_flow` | "Data must not flow from X to Y" | Taint/data flow analysis |
| `naming` | "X must match naming pattern" | Regex/glob matching |
| `structure` | "Module must contain X" | File system check |

**ConstraintSource** — Tracks provenance:
```typescript
interface ConstraintSource {
  type: 'pattern' | 'call_graph' | 'boundary' | 'test_topology' | 'error_handling' | 'manual';
  sourceIds: string[];           // Pattern IDs, function IDs, etc.
  evidence: {
    conforming: number;          // Instances that follow the invariant
    violating: number;           // Instances that break the invariant
    conformingLocations: string[];
    violatingLocations: string[];
  };
}
```

**ConstraintScope** — Where the constraint applies:
```typescript
interface ConstraintScope {
  files?: string[];              // Glob patterns (e.g., "src/api/**/*.ts")
  directories?: string[];        // Directory patterns
  functions?: string[];          // Function name patterns
  classes?: string[];            // Class name patterns
  entryPoints?: boolean;         // Only entry points (API handlers)
}
```

**ConstraintConfidence** — Statistical backing:
```typescript
interface ConstraintConfidence {
  score: number;                 // 0.0-1.0
  conformingInstances: number;   // How many follow the rule
  violatingInstances: number;    // How many break the rule
  lastVerified: string;          // ISO timestamp
}
```

**ConstraintEnforcement** — How violations are reported:
```typescript
interface ConstraintEnforcement {
  level: 'error' | 'warning' | 'info';
  autoFix?: boolean;
  message: string;
  suggestion?: string;
}
```

**ConstraintViolation** — Individual violation:
```typescript
interface ConstraintViolation {
  constraintId: string;
  constraintName: string;
  file: string;
  line: number;
  message: string;
  severity: 'error' | 'warning' | 'info';
  suggestion?: string;
  snippet?: string;
}
```

**VerificationResult** — Per-file verification output:
```typescript
interface VerificationResult {
  file: string;
  violations: ConstraintViolation[];
  passed: number;
  failed: number;
  skipped: number;
  summary: VerificationSummary;
}
```

---

### 2. Invariant Detector (`extraction/invariant-detector.ts`)

**Purpose**: The semantic analysis engine that mines architectural invariants from Drift's existing data. This is the "learning" component — it discovers what rules the codebase actually follows.

**Dependencies**:
```typescript
interface InvariantDetectorConfig {
  rootDir: string;
  patternStore?: PatternStore;        // From category 23
  callGraphStore?: CallGraphStore;    // From category 04
  boundaryStore?: BoundaryStore;      // From category 21
  testTopologyAnalyzer?: TestTopologyAnalyzer;  // From category 17
  errorHandlingAnalyzer?: ErrorHandlingAnalyzer; // From category 19
}
```

**Detection Algorithm**:
```
For each data source (patterns, call graph, boundaries, tests, errors):
  1. Query for high-confidence, approved data
  2. Identify recurring invariants (>= threshold conforming instances)
  3. Check for violations (instances that break the invariant)
  4. Calculate confidence: conforming / (conforming + violating)
  5. Produce DetectedInvariant with evidence
Merge invariants from all sources
Return sorted by confidence (highest first)
```

**Complexity**: O(P + E + B + T + H) where P = patterns, E = call graph edges, B = boundaries, T = test mappings, H = error handlers. Each source is queried independently.

**Detection Sources — Detailed**:

| Source | What It Detects | Example Invariants | Categories |
|--------|----------------|-------------------|------------|
| **Patterns** | High-confidence approved patterns → invariants | "All API endpoints use @Auth decorator" | api, auth, data, error, test, security, structural |
| **Call Graph** | Auth-before-data-access ordering, validation chains | "Authentication check precedes database query" | auth, security, data |
| **Boundaries** | Data access layer invariants, sensitive data rules | "Controllers must not directly access database" | data, security |
| **Test Topology** | Coverage requirements, test patterns | "Every exported function has a test" | test |
| **Error Handling** | Error boundary patterns, propagation rules | "Async handlers must have try/catch" | error |

**DetectedInvariant Output**:
```typescript
interface DetectedInvariant {
  constraint: Omit<Constraint, 'id' | 'metadata'>;  // Constraint without generated fields
  evidence: InvariantEvidence;
  violations: ConstraintViolationDetail[];
}

interface InvariantEvidence {
  conforming: number;
  violating: number;
  conformingLocations: string[];    // File paths where invariant holds
  violatingLocations: string[];     // File paths where invariant is broken
  sources: string[];                // Source IDs (pattern IDs, function IDs)
}
```

**Current Limitations**:
- Pattern-based detection only considers approved patterns — misses emerging conventions
- Call graph detection limited to direct caller-callee relationships — no transitive analysis
- No temporal analysis — doesn't detect invariants that are strengthening or weakening over time
- No cross-language invariant detection — each language analyzed independently
- Threshold for "recurring" is static — doesn't adapt to codebase size
- No negative invariant mining — only detects what IS done, not what is AVOIDED

---

### 3. Constraint Synthesizer (`extraction/constraint-synthesizer.ts`)

**Purpose**: Converts detected invariants into full Constraint objects. Handles ID generation, deduplication, merging of similar constraints, and comparison with existing constraints.

**Synthesis Pipeline**:
```
1. Detect invariants (via InvariantDetector)
2. Convert each invariant → Constraint (with generated ID, metadata)
3. Merge similar constraints (if enabled, using similarity threshold)
4. Diff against existing constraints in store
5. Save new/updated constraints
6. Return ExtractionResult with stats
```

**Configuration**:
```typescript
interface SynthesisOptions {
  categories?: ConstraintCategory[];     // Filter to specific categories
  minConfidence?: number;                // Minimum confidence threshold
  autoApproveThreshold?: number;         // Auto-approve above this (e.g., 0.95)
  mergeSimilar?: boolean;                // Merge similar constraints
  similarityThreshold?: number;          // 0-1, default 0.8
}
```

**Deduplication Strategy**:
- Hash-based: category + invariant type + predicate + scope → deterministic ID
- Existing constraints with same hash → update (confidence refreshed, evidence merged)
- New constraints → add as `discovered`
- Constraints no longer detected → flagged for review (not auto-deleted)

**Auto-Approval**: When `autoApproveThreshold` is set (e.g., 0.95), constraints with confidence above the threshold are automatically set to `approved` status. This reduces manual review burden for high-confidence invariants.

**Merging**: When `mergeSimilar` is enabled, constraints with similarity above `similarityThreshold` (default 0.8) are merged. Similarity is calculated from category, invariant type, predicate overlap, and scope overlap.

**Current Limitations**:
- Similarity calculation is heuristic — no semantic understanding of predicate equivalence
- Merging can lose specificity — two specific constraints merged into one generic one
- No conflict detection — contradictory constraints can coexist
- No priority resolution — when two constraints conflict, no mechanism to determine which wins
- ExtractionResult stats are basic — no trend tracking across runs

---

### 4. Constraint Store (`store/constraint-store.ts`)

**Purpose**: File-based persistence for constraints. JSON files organized by category in `.drift/constraints/`.

**Storage Model**:
- One JSON file per category in `discovered/` directory
- Each file contains an array of Constraint objects
- `index.json` maintains category-based index for fast lookups
- Custom constraints stored alongside discovered ones

**Key Methods**:

| Method | Purpose | Complexity |
|--------|---------|------------|
| `initialize()` | Load all constraints from disk, rebuild index | O(C × N) where C = categories, N = constraints per category |
| `add(constraint)` | Add single constraint, update index | O(1) amortized |
| `addMany(constraints)` | Batch add, single index rebuild | O(N) |
| `get(id)` | Get by ID | O(N) linear scan (no ID index) |
| `getAll()` | Get all constraints | O(N) |
| `update(id, updates)` | Partial update | O(N) for find + O(1) for update |
| `delete(id)` | Remove constraint | O(N) |
| `approve(id, approvedBy?)` | Transition to approved | O(N) for find |
| `ignore(id, reason?)` | Transition to ignored | O(N) for find |
| `query(options)` | Filtered, sorted, paginated | O(N) filter + O(N log N) sort |
| `getForFile(filePath)` | Get applicable constraints for a file | O(N × S) where S = scope patterns |
| `getByCategory(category)` | Filter by category | O(1) with index |
| `getByStatus(status)` | Filter by status | O(N) |
| `getActive(minConfidence)` | Approved + above confidence | O(N) |
| `getCounts()` | Summary counts | O(N) |
| `getSummaries()` | Lightweight summaries | O(N) |

**File Applicability** (`getForFile()`):
- Glob pattern matching on `scope.files` (e.g., `src/api/**/*.ts`)
- Directory matching on `scope.directories`
- Language matching based on file extension
- Returns all constraints whose scope matches the given file

**Index Structure** (`index.json`):
- Maps category → constraint IDs for O(1) category lookups
- Rebuilt automatically when constraints change
- Rebuild is O(N) — acceptable for current scale

**Current Limitations**:
- File-based storage — no ACID transactions, no concurrent access safety
- Linear scan for ID lookups — O(N) instead of O(1) with hash index
- No versioning — constraint history is lost on update
- No bulk lifecycle transitions — approve/ignore is one-at-a-time
- Index is category-only — no indexes on status, language, confidence
- No change notification — consumers must poll for updates
- No backup/restore — constraints lost if `.drift/` is deleted
- JSON serialization overhead for large constraint sets
- No compression — each constraint stored with full field set

---

### 5. Constraint Verifier (`verification/constraint-verifier.ts`)

**Purpose**: Validates code against applicable constraints. The enforcement engine that produces violation reports.

**Key Methods**:

| Method | Purpose |
|--------|---------|
| `verifyFile(filePath, content, constraints)` | Verify a file against all applicable constraints |
| `verifyChange(filePath, oldContent, newContent, constraints)` | Verify only changed lines (change-aware) |

**Verification Flow**:
```
1. Determine file language from extension
2. Filter constraints applicable to this file (scope matching, language matching)
3. For each applicable constraint:
   a. Extract relevant code elements (functions, classes, entry points, imports)
   b. Evaluate predicate against extracted elements
   c. Record pass/fail with violation details (line, message, severity, suggestion, snippet)
4. Build summary with pass/fail/skip counts
5. Return VerificationResult
```

**Predicate Evaluation Matrix**:

| Predicate Type | What It Checks | Extraction Method |
|---------------|----------------|-------------------|
| **Function** | Functions matching pattern must have/not have properties | Language-specific regex |
| **Class** | Classes matching pattern must contain methods/properties | Language-specific regex |
| **Entry Point** | API endpoints must have auth, validation, etc. | Route decorator/handler detection |
| **Naming** | Files/functions/classes must match naming conventions | Regex/glob matching |
| **File Structure** | Modules must contain certain files | File system check |

**Code Element Extraction**:
- Functions: Detected via language-specific regex (function declarations, arrow functions, methods)
- Classes: Class declarations with methods and properties
- Entry Points: Route decorators, controller methods, exported handlers
- Imports: Import/require statements

**Change-Aware Verification** (`verifyChange()`):
```
1. Diff old vs new content to find changed line numbers
2. Only evaluate constraints where violations fall on changed lines
3. Existing violations on unchanged lines are NOT reported
4. Reduces noise — existing violations don't block new changes
```

**Language Support**: All 8 languages with language-specific patterns for:
- Function detection (def, func, fn, function, etc.)
- Class detection (class, struct, interface)
- Error handling detection (try/catch, try/except, defer, etc.)
- Import detection (import, require, use, using, etc.)

**Current Limitations**:
- Regex-based code element extraction — duplicates work done by parsers, misses complex patterns
- No AST-based verification — cannot check structural properties accurately
- No call graph integration in verifier — ordering constraints (must_precede, must_follow) cannot be verified
- No data flow integration — data_flow constraints cannot be verified
- No cross-file verification — each file verified independently
- No incremental verification — re-verifies all applicable constraints on every run
- No caching of extraction results — same file re-extracted for each constraint
- Suggestion generation is template-based — not context-aware
- No auto-fix implementation — `autoFix` field exists but is never used

---

## Key Algorithms

### 1. Invariant Mining (O(P + E + B + T + H))

The core algorithm that discovers architectural invariants from Drift data:

```
Input: PatternStore, CallGraphStore, BoundaryStore, TestTopologyAnalyzer, ErrorHandlingAnalyzer
Output: DetectedInvariant[]

For each source:
  patterns → scan approved patterns with confidence > threshold
    → group by category
    → for each group, identify recurring properties (decorators, return types, error handling)
    → calculate conforming/violating ratio
    → produce invariant if ratio > minConfidence

  call_graph → scan entry points
    → for each entry point, check if auth check precedes data access
    → calculate conforming/violating ratio
    → produce auth-before-data invariant

  boundaries → scan data access points
    → check if access is through approved layers (services, repositories)
    → produce layer-separation invariant

  test_topology → scan exported functions
    → check if each has corresponding test
    → produce coverage invariant

  error_handling → scan async handlers
    → check if each has error boundary
    → produce error-handling invariant

Merge all invariants
Sort by confidence (descending)
Return
```

### 2. Constraint Deduplication (O(N × M))

Where N = new invariants, M = existing constraints:

```
For each new invariant:
  hash = SHA256(category + invariant.type + predicate + scope)
  if hash exists in store:
    update existing constraint (refresh confidence, merge evidence)
  else:
    create new constraint with status = 'discovered'
```

### 3. Scope Matching (O(N × S × G))

Where N = constraints, S = scope patterns per constraint, G = glob evaluation cost:

```
For file F:
  applicable = []
  for each constraint C:
    if C.language matches F.language OR C.language == 'all':
      if C.scope.files matches F.path (glob):
        applicable.push(C)
      elif C.scope.directories matches F.directory:
        applicable.push(C)
  return applicable
```

### 4. Change-Aware Verification (O(L + C × E))

Where L = lines in diff, C = applicable constraints, E = extraction cost per constraint:

```
changedLines = diff(oldContent, newContent)
for each applicable constraint:
  violations = evaluate(constraint, newContent)
  filteredViolations = violations.filter(v => changedLines.includes(v.line))
  report filteredViolations
```

---

## Data Flow

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Patterns   │     │  Call Graph   │     │  Boundaries  │
│ (Category 03)│     │ (Category 04) │     │ (Category 21)│
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                    │                     │
       ▼                    ▼                     ▼
┌──────────────────────────────────────────────────────────┐
│              InvariantDetector                             │
│  Mines invariants from all 5 data sources                 │
└──────────────────────────┬───────────────────────────────┘
                           │ DetectedInvariant[]
                           ▼
┌──────────────────────────────────────────────────────────┐
│              ConstraintSynthesizer                         │
│  Converts → Deduplicates → Merges → Auto-approves         │
└──────────────────────────┬───────────────────────────────┘
                           │ Constraint[]
                           ▼
┌──────────────────────────────────────────────────────────┐
│              ConstraintStore                               │
│  Persists to .drift/constraints/ as JSON                  │
└──────────────────────────┬───────────────────────────────┘
                           │ Constraint[]
                           ▼
┌──────────────────────────────────────────────────────────┐
│              ConstraintVerifier                             │
│  Validates code changes → VerificationResult               │
└──────────────────────────┬───────────────────────────────┘
                           │ VerificationResult
                           ▼
┌──────────────────────────────────────────────────────────┐
│  Quality Gates │ MCP Tools │ CLI │ Cortex │ Context Gen   │
└──────────────────────────────────────────────────────────┘
```

---

## Integration Points

### Upstream Dependencies (What Constraints Consumes)

| Category | What It Provides | How Constraints Uses It |
|----------|-----------------|------------------------|
| 03 — Detectors | Approved patterns with confidence scores | Pattern-based invariant mining |
| 04 — Call Graph | Function relationships, entry points | Ordering invariants (must_precede, must_follow), reachability |
| 05 — Analyzers | AST analysis, type information | (Indirect) Through patterns and call graph |
| 17 — Test Topology | Test-to-source mappings, coverage data | Test coverage invariants |
| 19 — Error Handling | Error boundaries, propagation chains | Error handling invariants |
| 21 — Security/Boundaries | Data access points, sensitive fields | Data access layer invariants, security constraints |

### Downstream Consumers (What Depends on Constraints)

| Category | What It Consumes | How It Uses Constraints |
|----------|-----------------|------------------------|
| 09 — Quality Gates | Active constraints, verification results | `constraint-verification` gate — blocking gate in CI |
| 07 — MCP | Constraint data, verification API | `drift_validate_change`, `drift_prevalidate` tools |
| 10 — CLI | Constraint CRUD, verification | `drift constraints list/approve/ignore` commands |
| 06 — Cortex | Constraint links, override memories | `memory_constraints` table, `constraint_override` memory type |
| 22 — Context Generation | Active constraints for file/package | Constraint gatherer (20% of token budget) |

### Cross-Category Data Contracts

| Interface | Direction | Format |
|-----------|-----------|--------|
| `PatternStore.query()` | Constraints ← Detectors | `Pattern[]` with confidence, locations |
| `CallGraphStore.getCallers()` | Constraints ← Call Graph | `FunctionEntry[]` with call relationships |
| `BoundaryStore.getBoundaries()` | Constraints ← Security | `Boundary[]` with data access points |
| `ConstraintStore.getActive()` | Constraints → Quality Gates | `Constraint[]` with enforcement level |
| `ConstraintVerifier.verifyFile()` | Constraints → MCP/CLI | `VerificationResult` with violations |
| `ConstraintStore.getForFile()` | Constraints → Context Gen | `Constraint[]` applicable to file |

---

## V2 Migration Status

### What Should Move to Rust

| Component | Priority | Rationale |
|-----------|----------|-----------|
| Predicate evaluation | P0 | Regex-heavy, hot path during verification — Rust would be 10-50x faster |
| Code element extraction | P0 | Currently duplicates parser work — should use Rust AST directly |
| Scope matching (glob) | P1 | `globset` crate is faster than JS glob libraries |
| Invariant detection (call graph) | P1 | Graph traversal is compute-intensive |
| Invariant detection (boundaries) | P2 | Straightforward, moderate benefit |

### What Should Stay in TypeScript

| Component | Rationale |
|-----------|-----------|
| Constraint Store | File I/O, not performance-critical (or migrate to SQLite in Rust) |
| Constraint Synthesizer | Complex merging/dedup logic, not hot-path |
| Pattern-based detection | I/O bound (reading pattern store), not compute-bound |
| CLI integration | Presentation layer |

### What's Missing for V2

| Gap | Impact | Priority |
|-----|--------|----------|
| No AST-based verification | Cannot accurately check structural properties | P0 |
| No call graph integration in verifier | Ordering constraints unverifiable | P0 |
| No data flow integration | data_flow constraints unverifiable | P1 |
| No cross-file verification | Cannot enforce module-level invariants | P1 |
| No incremental verification | Re-verifies everything on every run | P1 |
| No constraint versioning | History lost on update | P2 |
| No conflict detection | Contradictory constraints can coexist | P2 |
| No feedback loop | No mechanism to track false positives | P1 |
| No declarative constraint format | Cannot version-control constraints | P1 |
| No constraint inheritance | Package-level constraints not inherited | P2 |
| File-based storage | No ACID, no concurrent access, no indexing | P1 |
| No auto-fix implementation | autoFix field exists but unused | P2 |

---

## Capabilities Summary

### What Works Today
- ✅ Invariant mining from 5 data sources (patterns, call graph, boundaries, tests, errors)
- ✅ 12 invariant types covering structural, ordering, colocation, data flow, naming
- ✅ 10 constraint categories spanning the full application stack
- ✅ Confidence-based scoring with conforming/violating evidence
- ✅ Lifecycle management (discovered → approved → enforced → ignored)
- ✅ Auto-approval for high-confidence constraints
- ✅ Change-aware verification (only checks changed lines)
- ✅ Deduplication and merging of similar constraints
- ✅ Integration with quality gates, MCP, CLI, Cortex, context generation
- ✅ 8-language support for verification
- ✅ Scope-based applicability (file globs, directories, functions, classes, entry points)

### What Doesn't Work / Is Missing
- ❌ Ordering constraints (must_precede, must_follow) — verifier has no call graph access
- ❌ Data flow constraints (data_flow) — verifier has no taint analysis
- ❌ Cross-file constraints — each file verified independently
- ❌ AST-based verification — uses regex, misses complex patterns
- ❌ Auto-fix — field exists but never implemented
- ❌ Constraint versioning — no history tracking
- ❌ Conflict detection — contradictory constraints can coexist
- ❌ Feedback loop — no false-positive tracking
- ❌ Declarative format — constraints are internal JSON, not user-editable
- ❌ Constraint inheritance — no package-level inheritance
- ❌ Temporal analysis — no trend detection for strengthening/weakening invariants
- ❌ Cross-language invariants — each language analyzed independently
- ❌ Negative invariant mining — only detects what IS done, not what is AVOIDED

---

## Open Questions

1. **Should constraints move to SQLite?** File-based JSON works for small sets but doesn't scale. SQLite would enable proper indexing, transactions, and concurrent access. The v2 storage consolidation (drift.db) suggests yes.

2. **How should constraint conflicts be resolved?** When two constraints contradict (e.g., "must_have auth" vs "must_not_have auth" for different scopes that overlap), what's the resolution strategy? Priority-based? Scope-specificity? User override?

3. **Should constraints support composition?** Can constraints reference other constraints? E.g., "If constraint A is satisfied, then constraint B must also be satisfied." This enables complex architectural rules.

4. **What's the right auto-approval threshold?** Currently configurable but no guidance. Too low = noise, too high = nothing auto-approved. Should it adapt based on codebase size and constraint category?

5. **How should constraints interact with the incremental architecture?** When a file changes, which constraints need re-verification? Only those scoped to the changed file? Or also constraints that depend on cross-file invariants?

6. **Should the verifier use the Rust parser directly?** Currently extracts code elements via regex. Using the Rust parser's AST would be more accurate and eliminate duplicate work. But it creates a tight coupling between constraints and parsers.

7. **How should custom (user-defined) constraints be expressed?** TOML? YAML? Tree-sitter query syntax? A DSL? The format needs to be expressive enough for complex invariants but simple enough for non-expert users.
