# 23 Pattern Repository — Master Recap

> **Purpose**: Complete synthesis of every architectural pattern, design pattern, data pattern, algorithm, anti-pattern, and cross-cutting convention used across the entire Drift v1 codebase. This document captures the full pattern landscape in one authoritative reference — serving as the definitive requirements specification for the v2 enterprise greenfield rebuild's pattern architecture.
>
> **Scope**: 16 category RECAPs (~20,000+ lines of research), 3 master documents, 8 overview documents, 150+ identified gaps, and the complete AUDIT.md forensic inventory.
>
> **Date**: February 2026

---

## Executive Summary

The Pattern Repository is Drift's central abstraction layer for pattern lifecycle management — the system that stores, queries, scores, evolves, and enforces discovered codebase conventions. In v1, this responsibility is fragmented across 6 storage backends, 3 service interfaces, 2 store implementations (JSON + SQLite), a hybrid bridge layer, a data lake with materialized views, and 9 repository classes. The pattern entity itself is the most connected data type in the system: created by 350+ detectors, scored by the confidence algorithm, stored in dual backends, queried by 87+ MCP tools, enforced by 6 quality gates, audited by the health system, linked to Cortex memories, and consumed by every presentation layer (CLI, MCP, IDE, Dashboard).

V1's pattern repository evolved organically from a simple JSON file store into a complex multi-backend system with ~12,000 lines of storage code. The v2 vision consolidates this into a single Rust-owned SQLite database with a clean repository interface, incremental updates, temporal confidence decay, Bayesian learning, and pattern lifecycle automation.

**Scale**: ~4,750 lines of pattern-specific code + ~7,250 lines of shared storage infrastructure = ~12,000 total lines. 40+ SQLite tables, 50+ indexes, 9 repository classes, 3 sync paths, 6 storage backends.

**Language**: 100% TypeScript in v1. V2 migrates all pattern storage and querying to Rust, with TypeScript retaining read-only access via NAPI.

---

## Current Implementation

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PRESENTATION LAYER                              │
│  CLI (drift scan, check, approve, ignore, status)                       │
│  MCP (drift_patterns_list, drift_pattern_get, drift_file_patterns,      │
│       drift_code_examples, drift_validate_change, drift_prevalidate,    │
│       drift_context, drift_status, drift_trends)                        │
│  Quality Gates (pattern-compliance, regression-detection)               │
│  IDE (LSP diagnostics, inline annotations)                              │
│  Dashboard (pattern explorer, health trends)                            │
├─────────────────────────────────────────────────────────────────────────┤
│                         SERVICE LAYER                                   │
│  IPatternService (new API)                                              │
│  ├── getPatterns(filters) → Pattern[]                                   │
│  ├── getPattern(id) → Pattern                                           │
│  ├── getPatternsByFile(file) → Pattern[]                                │
│  ├── getPatternsByCategory(category) → Pattern[]                        │
│  ├── approvePattern(id) → void                                          │
│  ├── ignorePattern(id) → void                                           │
│  ├── getExamples(patternId) → Example[]                                 │
│  └── getStatistics() → PatternStats                                     │
│                                                                         │
│  PatternServiceFactory (CLI)                                            │
│  ├── Auto-detects storage backend                                       │
│  └── Creates appropriate service implementation                         │
├─────────────────────────────────────────────────────────────────────────┤
│                         CONFIDENCE ENGINE                               │
│  ConfidenceScorer                                                       │
│  ├── score = freq×0.40 + consistency×0.30 + age×0.15 + spread×0.15     │
│  ├── Classification: high(≥0.85), medium(≥0.70), low(≥0.50), uncertain │
│  └── Weight validation: sum = 1.0 (±0.001)                             │
│                                                                         │
│  OutlierDetector                                                        │
│  ├── Z-Score (n ≥ 30): |z| > threshold → outlier                       │
│  ├── IQR (n < 30): value outside Q1-1.5×IQR..Q3+1.5×IQR → outlier     │
│  └── Sensitivity adjustment: threshold × (1 + (1 - sensitivity))       │
│                                                                         │
│  PatternMatcher                                                         │
│  ├── AST matching: depth-first traversal, confidence = matched/total    │
│  ├── Regex matching: global flag, named captures, confidence = 1.0      │
│  └── Structural matching: globs, naming conventions, sibling/parent     │
├─────────────────────────────────────────────────────────────────────────┤
│                         RULES ENGINE                                    │
│  Evaluator (900 LOC) → RuleEngine (900 LOC) → SeverityManager (760 LOC)│
│  VariantManager (1100 LOC) → QuickFixGenerator (1320 LOC, 7 strategies) │
│  ├── Violation generation from pattern deviations                       │
│  ├── Severity classification with overrides                             │
│  ├── Variant scoping (global, directory, file)                          │
│  └── Quick fix generation (replace, wrap, extract, import, rename, etc.)│
├─────────────────────────────────────────────────────────────────────────┤
│                         AUDIT ENGINE                                    │
│  AuditEngine                                                            │
│  ├── Duplicate detection (Jaccard similarity > 0.85)                    │
│  ├── Cross-validation (call graph, constraints, test coverage)          │
│  ├── Health scoring (5-factor weighted: 0.30+0.20+0.20+0.15+0.15)      │
│  ├── Auto-approve recommendations (confidence ≥ 0.90)                   │
│  └── Degradation tracking (7-day rolling averages, 90-day history)      │
├─────────────────────────────────────────────────────────────────────────┤
│                         STORAGE LAYER (6 backends)                      │
│  Backend 1: JSON Files (.drift/patterns/{status}/{category}.json)       │
│  Backend 2: SQLite Unified Store (drift.db — 40+ tables, 50+ indexes)  │
│  Backend 3: Data Lake (views, indexes, shards — pre-computed queries)   │
│  Backend 4: Rust SQLite (callgraph.db — call graph persistence)         │
│  Backend 5: Cortex SQLite (cortex.db — memory + vectors)                │
│  Backend 6: Hybrid Stores (SQLite↔JSON bridge layers)                   │
├─────────────────────────────────────────────────────────────────────────┤
│                         LEARNING SYSTEM                                 │
│  ValueDistribution algorithm                                            │
│  ├── filePercentage = filesWithValue / totalFiles                       │
│  ├── Dominant if filePercentage ≥ 0.6 AND occurrences ≥ 3              │
│  ├── Persists to .drift/learned/{detector-id}.json                      │
│  └── 24-hour expiry, minFiles=2, maxFiles=1000                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Component Inventory

| Component | Location | LOC (est.) | Purpose |
|-----------|----------|-----------|---------|
| PatternStore (JSON) | `core/src/store/pattern-store.ts` | ~1,168 | JSON file-based pattern persistence |
| PatternRepository (SQLite) | `core/src/storage/repositories/pattern-repository.ts` | ~500 | SQLite CRUD + queries |
| HybridPatternStore | `core/src/storage/hybrid-pattern-store.ts` | ~450 | SQLite↔JSON bridge |
| IPatternService | `core/src/storage/pattern-service.ts` | ~300 | New unified API interface |
| ConfidenceScorer | `core/src/matcher/confidence-scorer.ts` | ~200 | 4-factor weighted scoring |
| PatternMatcher | `core/src/matcher/pattern-matcher.ts` | ~400 | Multi-strategy matching |
| OutlierDetector | `core/src/matcher/outlier-detector.ts` | ~300 | Z-Score + IQR detection |
| Rules Engine | `core/src/rules/` | ~4,900 | Evaluator, severity, variants, quick fixes |
| Audit Engine | `core/src/audit/audit-engine.ts` | ~600 | Validation, dedup, health scoring |
| Audit Store | `core/src/audit/audit-store.ts` | ~400 | Persistence, degradation tracking |
| Learning System | `core/src/learning/` | ~300 | Convention persistence across sessions |
| Data Lake (pattern-related) | `core/src/lake/` | ~2,500 | Views, indexes, shards, query engine |
| Sync Service (pattern domain) | `core/src/storage/sync-service.ts` | ~200 | JSON↔SQLite pattern sync |
| **Total** | | **~12,220** | |

---

## Core Data Model

### Pattern (Primary Entity)

```typescript
interface Pattern {
  id: string;                          // Unique identifier
  category: PatternCategory;           // 15 categories
  subcategory: string;                 // Detector-specific subcategory
  name: string;                        // Human-readable name
  description: string;                 // What this pattern represents
  status: PatternStatus;               // discovered | approved | ignored
  detection_method: string;            // How it was detected
  detector_id: string;                 // Which detector found it
  pattern_id: string;                  // Detector's internal pattern ID
  confidence: ConfidenceScore;         // Composite confidence
  severity: Severity;                  // error | warning | info | hint
  auto_fixable: boolean;              // Whether quick fix is available
  locations: PatternLocation[];        // Where pattern appears
  outliers: OutlierLocation[];         // Where pattern is violated
  metadata: PatternMetadata;           // Timestamps, tags, approval info
}
```

### Pattern Categories (15)

| Category | Description | Detector Count |
|----------|-------------|---------------|
| `api` | API patterns (REST, GraphQL, response formats) | 7 |
| `auth` | Authentication/authorization patterns | 6 |
| `components` | UI component patterns | 8 |
| `config` | Configuration patterns | 7 |
| `contracts` | API contract patterns (BE↔FE) | 4+ |
| `data-access` | Database/ORM patterns | 7+3 |
| `documentation` | Documentation patterns | 5 |
| `errors` | Error handling patterns | 7 |
| `logging` | Logging patterns | 7 |
| `performance` | Performance patterns | 6 |
| `security` | Security patterns | 7 |
| `structural` | Code structure patterns | 9 |
| `styling` | CSS/styling patterns | 8 |
| `testing` | Testing patterns | 7 |
| `types` | Type system patterns | 7 |
| `accessibility` | Accessibility patterns | 6 |

### Pattern Lifecycle State Machine

```
                    ┌──────────┐
         ┌─────────│discovered│─────────┐
         │         └──────────┘         │
         │              │               │
         ▼              ▼               ▼
    ┌────────┐    ┌────────┐      ┌───────┐
    │approved│    │mismatch│      │ignored│
    └────────┘    └────────┘      └───────┘
         │                              │
         └──────────────────────────────┘
              (can transition between)
```

**Transitions**:
- `discovered → approved`: Manual approval or auto-approve (confidence ≥ 0.90, outlierRatio ≤ 0.50, locations ≥ 3)
- `discovered → ignored`: Manual dismissal
- `approved → ignored`: Pattern no longer relevant
- `ignored → approved`: Reconsidered pattern

### Confidence Score

```typescript
interface ConfidenceScore {
  score: number;                       // Composite [0.0, 1.0]
  level: 'high' | 'medium' | 'low' | 'uncertain';
  frequency: number;                   // occurrences / totalLocations
  consistency: number;                 // 1 - variance
  age: number;                         // Days since first seen
  spread: number;                      // fileCount / totalFiles
}
```

### Pattern Location

```typescript
interface PatternLocation {
  file: string;                        // Relative file path
  line: number;                        // Line number
  column: number;                      // Column number
  endLine?: number;                    // End line (optional)
  endColumn?: number;                  // End column (optional)
  snippet?: string;                    // Code snippet
  confidence: number;                  // Per-location confidence
  is_outlier: boolean;                 // Whether this is a deviation
  outlier_reason?: string;             // Why it's an outlier
}
```

### Pattern Example

```typescript
interface PatternExample {
  file: string;                        // Source file
  code: string;                        // Code snippet
  line_start: number;                  // Start line
  line_end: number;                    // End line
  is_positive: boolean;                // Good example (true) or anti-example (false)
}
```

### SQLite Schema (Pattern Domain)

```sql
-- Core pattern table
CREATE TABLE patterns (
  id TEXT PRIMARY KEY,
  category TEXT NOT NULL,
  subcategory TEXT,
  name TEXT NOT NULL,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'discovered',  -- discovered|approved|ignored
  detection_method TEXT,
  detector_id TEXT,
  pattern_id TEXT,
  confidence_frequency REAL,
  confidence_consistency REAL,
  confidence_age INTEGER,
  confidence_spread INTEGER,
  confidence_score REAL,
  confidence_level TEXT,
  severity TEXT DEFAULT 'info',
  auto_fixable INTEGER DEFAULT 0,
  first_seen TEXT,
  last_seen TEXT,
  source TEXT,
  tags TEXT,                                   -- JSON array
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

-- Pattern locations (1:N)
CREATE TABLE pattern_locations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pattern_id TEXT NOT NULL REFERENCES patterns(id),
  file TEXT NOT NULL,
  line INTEGER,
  column_num INTEGER,
  is_outlier INTEGER DEFAULT 0,
  confidence REAL,
  outlier_reason TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

-- Pattern variants (scope overrides)
CREATE TABLE pattern_variants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pattern_id TEXT NOT NULL REFERENCES patterns(id),
  scope TEXT NOT NULL,                         -- global|directory|file
  scope_path TEXT,
  severity_override TEXT,
  enabled_override INTEGER,
  threshold_override REAL,
  config_override TEXT,                        -- JSON
  expires_at TEXT
);

-- Pattern examples (code snippets)
CREATE TABLE pattern_examples (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pattern_id TEXT NOT NULL REFERENCES patterns(id),
  file TEXT NOT NULL,
  code TEXT NOT NULL,
  line_start INTEGER,
  line_end INTEGER,
  is_positive INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now'))
);

-- Pattern history (audit trail)
CREATE TABLE pattern_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pattern_id TEXT,
  action TEXT NOT NULL,                        -- created|updated|approved|ignored|deleted
  old_value TEXT,                               -- JSON
  new_value TEXT,                               -- JSON
  created_at TEXT DEFAULT (datetime('now'))
);
```

**Indexes** (pattern domain):
```sql
CREATE INDEX idx_patterns_category ON patterns(category);
CREATE INDEX idx_patterns_status ON patterns(status);
CREATE INDEX idx_patterns_confidence ON patterns(confidence_score);
CREATE INDEX idx_patterns_detector ON patterns(detector_id);
CREATE INDEX idx_patterns_severity ON patterns(severity);
CREATE INDEX idx_pattern_locations_pattern ON pattern_locations(pattern_id);
CREATE INDEX idx_pattern_locations_file ON pattern_locations(file);
CREATE INDEX idx_pattern_locations_outlier ON pattern_locations(is_outlier);
CREATE INDEX idx_pattern_variants_pattern ON pattern_variants(pattern_id);
CREATE INDEX idx_pattern_examples_pattern ON pattern_examples(pattern_id);
CREATE INDEX idx_pattern_history_pattern ON pattern_history(pattern_id);
CREATE INDEX idx_pattern_history_action ON pattern_history(action);
```

**Triggers**:
```sql
-- Auto-update location/outlier counts on pattern_locations changes
CREATE TRIGGER update_pattern_counts_insert AFTER INSERT ON pattern_locations ...
CREATE TRIGGER update_pattern_counts_delete AFTER DELETE ON pattern_locations ...

-- Sync log trigger for JSON↔SQLite sync
CREATE TRIGGER sync_log_patterns AFTER INSERT ON patterns ...
```

---

## Subsystem Deep Dives

### 1. JSON Pattern Store (`pattern-store.ts`, ~1,168 LOC)

The original persistence layer. Stores patterns as JSON files organized by status and category.

**File Layout**:
```
.drift/patterns/
├── discovered/
│   ├── api.json
│   ├── auth.json
│   ├── security.json
│   └── ... (15 category files)
├── approved/
│   └── ... (same structure)
├── ignored/
│   └── ... (same structure)
└── .backups/
    └── YYYY-MM-DD-HH-mm-ss/
        └── ... (timestamped backup)
```

**Key Operations**:
- `loadPatterns()` — Reads all JSON files, parses, validates, deduplicates
- `savePatterns()` — Writes patterns grouped by status/category, with 30s debounce
- `addPattern(pattern)` — Adds to in-memory store, triggers debounced save
- `approvePattern(id)` — Moves from discovered → approved, updates metadata
- `ignorePattern(id)` — Moves from discovered → ignored
- `getPatternsByFile(file)` — O(n) scan across all patterns
- `getPatternsByCategory(category)` — O(1) lookup by category key

**Auto-Save**: 30-second debounce timer. Writes only dirty categories. Creates timestamped backup before overwrite. SHA-256 checksums for integrity verification.

**Fatal Flaws**:
1. O(n) reads — must parse entire category file to find one pattern
2. No concurrent access safety — advisory file locks only
3. No transactional guarantees — partial writes corrupt data
4. 50+ JSON files cluttering `.drift/`
5. No query optimization — all filtering in-memory after full load
6. Version control noise — every scan changes dozens of files

### 2. SQLite Pattern Repository (`pattern-repository.ts`, ~500 LOC)

The v1 SQLite implementation. Typed access to the patterns domain in drift.db.

**Key Operations**:
- `create(pattern)` — INSERT with all fields
- `update(id, changes)` — UPDATE with partial fields
- `delete(id)` — DELETE by ID
- `findById(id)` — SELECT by primary key
- `findByCategory(category, options?)` — SELECT with optional status/confidence filters
- `findByFile(file)` — JOIN with pattern_locations
- `findByDetector(detectorId)` — SELECT by detector_id
- `search(query)` — Full-text search across name, description, category
- `getStatistics()` — Aggregate counts by status, category, confidence level
- `getTopOutliers(limit)` — Patterns with highest outlier ratios
- `getRecentlyDiscovered(since)` — Patterns discovered after timestamp

**Prepared Statements**: Each query uses prepared statements for performance. No statement caching across calls (recreated each time — v2 improvement opportunity).

### 3. Hybrid Pattern Store (`hybrid-pattern-store.ts`, ~450 LOC)

Transitional bridge during Phase 3→4 migration. Reads from SQLite, optionally writes to both SQLite + JSON.

**Strategy**: Read from SQLite (source of truth). Write to SQLite always. Optionally write to JSON for backward compatibility. Sync on demand via SyncService.

**V2 Status**: DEPRECATED. Remove entirely — SQLite is the only backend.

### 4. Confidence Scoring Engine

**Location**: `core/src/matcher/confidence-scorer.ts`

The heart of Drift's learning system. Calculates a composite confidence score for each pattern based on 4 weighted factors.

**Algorithm**:
```
score = frequency × 0.40 + consistency × 0.30 + ageFactor × 0.15 + spread × 0.15

Where:
  frequency = occurrences / totalLocations           [0.0, 1.0]
  consistency = 1 - variance(locationConfidences)    [0.0, 1.0]
  ageFactor = min(1.0, 0.1 + (daysSinceFirstSeen / 30) × 0.9)  [0.1, 1.0]
  spread = uniqueFiles / totalFiles                  [0.0, 1.0]
```

**Classification Thresholds**:
| Level | Score Range | Meaning |
|-------|------------|---------|
| high | ≥ 0.85 | Established convention |
| medium | ≥ 0.70 | Likely convention |
| low | ≥ 0.50 | Possible convention |
| uncertain | < 0.50 | Insufficient evidence |

**Weight Validation**: Constructor enforces `|sum(weights) - 1.0| < 0.001`. Prevents misconfiguration.

**Limitations**:
1. No temporal decay — old patterns never lose confidence
2. No momentum signal — rapidly growing patterns scored same as stable ones
3. No Bayesian updating — each scan recalculates from scratch
4. Linear age factor — should be logarithmic (most learning happens early)
5. No cross-pattern correlation — related patterns scored independently

### 5. Outlier Detection Engine

**Location**: `core/src/matcher/outlier-detector.ts`

Statistical deviation detection using two methods based on sample size.

**Z-Score Method** (n ≥ 30):
```
zScore = (value - mean) / stdDev
adjustedThreshold = baseThreshold × (1 + (1 - sensitivity))
|zScore| > adjustedThreshold → outlier

Significance levels:
  |z| > 3.0 → high significance
  |z| > 2.5 → medium significance
  |z| > 2.0 → low significance
```

**IQR Method** (n < 30):
```
Q1 = 25th percentile, Q3 = 75th percentile
IQR = Q3 - Q1
lowerBound = Q1 - 1.5 × IQR
upperBound = Q3 + 1.5 × IQR
value outside bounds → outlier
```

**Sensitivity**: Both methods scale thresholds by `(1 + (1 - sensitivity))` where sensitivity ∈ [0.0, 1.0]. Higher sensitivity = lower threshold = more outliers detected.

### 6. Pattern Matcher

**Location**: `core/src/matcher/pattern-matcher.ts`

Multi-strategy matching engine that determines whether code matches a pattern.

**AST Matching** (O(n) tree traversal):
- Depth-first traversal with nodeType, property, and child pattern matching
- Confidence = matchedChecks / totalChecks × childConfidence
- Supports depth constraints, descendant search, regex property values

**Regex Matching** (O(n) per pattern):
- Global flag always applied, multiline optional
- Named capture group extraction
- Confidence always 1.0 (binary match)

**Structural Matching** (O(1) per file):
- Glob patterns for file path matching
- Naming conventions (5 styles: camelCase, PascalCase, snake_case, kebab-case, SCREAMING_SNAKE)
- Sibling file checks, parent directory checks
- AND logic: all checks must pass

### 7. Rules Engine (~4,900 LOC)

**Location**: `core/src/rules/`

Transforms pattern matches into actionable violations.

**Components**:
| Component | LOC | Purpose |
|-----------|-----|---------|
| Evaluator | 900 | Evaluates files against approved patterns |
| RuleEngine | 900 | Rule definition, matching, violation generation |
| SeverityManager | 760 | Severity classification with config overrides |
| VariantManager | 1,100 | Scope-based pattern variants (global/directory/file) |
| QuickFixGenerator | 1,320 | 7 fix strategies: replace, wrap, extract, import, rename, move, delete |

**Evaluation Flow**:
```
For each file:
  For each approved pattern applicable to this file:
    Match pattern against file content (AST/regex/structural)
    If deviation found:
      Generate Violation with severity, message, location
      Check for variant overrides (scope narrowing)
      Generate quick fix suggestions
```

### 8. Audit Engine

**Location**: `core/src/audit/`

Pattern validation, duplicate detection, cross-validation, and health scoring.

**Audit Pipeline**:
1. Filter patterns by category
2. Detect duplicates (Jaccard similarity on location sets, threshold 0.85)
3. Cross-validate (call graph presence, constraint alignment, test coverage)
4. Generate per-pattern recommendations (auto-approve, review, likely-false-positive)
5. Calculate health score (5-factor weighted)
6. Build summary with degradation alerts

**Health Score**:
```
score = (avgConfidence × 0.30 + approvalRatio × 0.20 + complianceRate × 0.20
       + crossValidationRate × 0.15 + duplicateFreeRate × 0.15) × 100
```

**Degradation Tracking**: 7-day rolling averages compared to previous 7 days. Alerts at -5 (warning) and -15 (critical) point drops. 90-day history retention.

### 9. Learning System

**Location**: `core/src/learning/`

Convention persistence across sessions using the ValueDistribution algorithm.

**Algorithm**:
```
For each unique value detected by a detector:
  filePercentage = filesWithValue / totalFiles
  if filePercentage >= 0.6 AND occurrences >= 3:
    → dominant convention (confidence = filePercentage)
```

**Configuration**: minOccurrences=3, dominanceThreshold=0.6, minFiles=2, maxFiles=1000.

**Persistence**: `.drift/learned/{detector-id}.json` with 24-hour expiry.

### 10. Data Lake (Pattern-Related)

**Location**: `core/src/lake/`

Pre-computed views and indexes for instant pattern queries.

**Pattern-Specific Components**:
- `PatternIndexView`: Lightweight pattern listing with id, name, category, status, confidence, SHA-256 locations hash
- `PatternShardStore`: Patterns by category at `.drift/lake/patterns/{category}.json`
- `FileIndex`: `file → patternId[]` mapping for O(1) file-to-pattern lookup
- `CategoryIndex`: `category → patternId[]` mapping for O(1) category queries
- `ExamplesStore`: Code examples by pattern at `.drift/lake/examples/{patternId}.json`

---

## Integration Points

### Upstream (What Feeds Patterns)

| Source | What It Provides | How |
|--------|-----------------|-----|
| 350+ Detectors | Raw pattern matches | `detect(file, content, ast, context) → PatternMatch[]` |
| Confidence Scorer | Composite scores | Post-detection scoring pass |
| Learning System | Dominant conventions | ValueDistribution algorithm |
| User Actions | Status transitions | approve, ignore, tag operations |
| Scan Pipeline | Aggregated patterns | Deduplication, location merging |

### Downstream (What Consumes Patterns)

| Consumer | What It Needs | Access Pattern |
|----------|--------------|---------------|
| MCP Server (87+ tools) | Pattern queries, examples, statistics | IPatternService, DataLake |
| Quality Gates (6 gates) | Approved patterns, compliance rates | PatternRepository |
| Audit Engine | All patterns for validation | PatternStore/Repository |
| CLI (50+ commands) | Pattern display, status management | PatternServiceFactory |
| Cortex Memory | Pattern links for memory retrieval | Pattern IDs |
| Context Generation | Relevant patterns for AI context | Filtered queries |
| IDE (LSP) | Inline diagnostics from violations | Rules Engine output |
| Dashboard | Pattern explorer, trends | DataLake views |
| Regression Detection | Historical pattern snapshots | SnapshotStore |
| DNA System | Pattern alignment for gene extraction | PatternService |
| Simulation Engine | Pattern alignment scoring | PatternService |

### Cross-Domain Links

Patterns are linked to nearly every other domain:

| Domain | Link Type | Table/Field |
|--------|-----------|-------------|
| Cortex Memory | memory_patterns | memory_id → pattern_id |
| Constraints | constraint alignment | constraint references pattern |
| Call Graph | function patterns | function → pattern locations |
| Contracts | contract patterns | contract field patterns |
| Quality Gates | compliance checking | gate evaluates pattern |
| Audit | health scoring | audit validates pattern |
| DNA | gene alignment | gene references pattern conventions |

---

## Capabilities

### What the Pattern Repository Can Do Today

1. **Multi-backend persistence**: JSON files + SQLite + Data Lake shards
2. **15-category organization**: Patterns organized by domain
3. **4-factor confidence scoring**: Frequency, consistency, age, spread
4. **Statistical outlier detection**: Z-Score (n≥30) and IQR (n<30)
5. **Multi-strategy matching**: AST, regex, structural
6. **Violation generation**: Rules engine with severity and quick fixes
7. **Pattern lifecycle**: discovered → approved/ignored with audit trail
8. **Duplicate detection**: Jaccard similarity on location sets
9. **Health scoring**: 5-factor weighted composite (0-100)
10. **Degradation tracking**: 7-day rolling averages, 90-day history
11. **Auto-approve recommendations**: Confidence ≥ 0.90 threshold
12. **Pre-computed views**: Instant status/pattern queries via Data Lake
13. **O(1) index lookups**: File → patterns, category → patterns
14. **Code examples**: Positive and negative examples per pattern
15. **Variant overrides**: Scope-based severity/threshold overrides
16. **Convention learning**: ValueDistribution algorithm for dominant patterns
17. **Content-hash change detection**: SHA-256 for incremental support

### Limitations

1. **No temporal decay**: Patterns never lose confidence over time
2. **No Bayesian updating**: Each scan recalculates from scratch
3. **No pattern merging**: Duplicates accumulate, manual review required
4. **No momentum signal**: Rapidly growing patterns scored same as stable
5. **No cross-pattern correlation**: Related patterns scored independently
6. **No incremental updates**: Full rescan writes all patterns
7. **No prepared statement caching**: Queries re-parsed each call
8. **No connection pooling**: Single SQLite connection
9. **No keyset pagination**: OFFSET/LIMIT degrades at scale
10. **No write batching**: Individual inserts, not batch transactions
11. **No OWASP/CWE mapping**: Security patterns lack standard references
12. **No pattern grouping**: No hierarchical pattern organization
13. **No pattern dependencies**: No modeling of pattern relationships
14. **No pattern versioning**: No tracking of pattern evolution over time
15. **No pattern templates**: No reusable pattern definitions
16. **6 fragmented backends**: Inconsistency risk, 3 sync paths
17. **No retention policies**: History grows unbounded
18. **No data integrity validation**: No periodic consistency checks

---

## V2 Migration Strategy

### What Stays (Solid Foundation)
- SQLite schema (patterns, locations, variants, examples, history tables)
- Confidence scoring algorithm (with enhancements)
- Outlier detection (Z-Score + IQR)
- Pattern lifecycle state machine
- Rules engine architecture (evaluator, severity, variants, quick fixes)
- Audit engine concepts (duplicate detection, health scoring, degradation tracking)
- Repository pattern for typed access

### What Gets Removed (~7,500 lines)
- JSON Pattern Store (~1,168 LOC)
- Hybrid Pattern Store (~450 LOC)
- Data Lake pattern components (~2,500 LOC)
- Sync Service pattern domain (~200 LOC)
- All JSON files in `.drift/patterns/`
- All JSON files in `.drift/lake/patterns/`
- All JSON files in `.drift/lake/examples/`

### What Gets Rebuilt in Rust
- Pattern storage and querying (Rust owns drift.db)
- Confidence scoring (with Bayesian updating, temporal decay)
- Outlier detection (with momentum signals)
- Pattern matching (AST-first, single-pass visitor)
- Write batching and connection pooling
- Incremental pattern updates (content-hash based)

### What Stays in TypeScript
- Rules engine (violation generation, quick fixes)
- Audit engine (health scoring, degradation tracking)
- MCP tool handlers (presentation layer)
- CLI commands (presentation layer)
- Pattern lifecycle management (orchestration)

---

## Open Questions

1. **Pattern versioning**: Should patterns track their own evolution (v1 → v2 → v3) as detection algorithms improve?
2. **Pattern dependencies**: Should we model "pattern A implies pattern B" relationships?
3. **Pattern templates**: Should there be reusable pattern definitions that can be shared across projects?
4. **Cross-project patterns**: Should patterns be shareable across projects in a team?
5. **Pattern confidence decay curve**: Linear, logarithmic, or exponential decay?
6. **Bayesian prior selection**: What prior distribution for pattern confidence?
7. **Pattern grouping granularity**: Category → subcategory → group → pattern, or flatter?
8. **OWASP/CWE mapping strategy**: Manual mapping or automated classification?
9. **Pattern merge strategy**: Auto-merge high-similarity patterns or always require human review?
10. **Retention policy**: How long to keep pattern history? Per-pattern or global?
