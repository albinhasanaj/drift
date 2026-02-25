# Pattern Aggregation & Deduplication — V2 Implementation Prep

> Comprehensive build specification for Drift v2's Pattern Aggregation & Deduplication subsystem.
> Synthesized from: 03-detectors/patterns/pipeline.md (Phase 4 Aggregation, Phase 5 Scoring),
> 03-detectors/patterns/data-model.md (AggregatedMatchResult, PatternMatchResult),
> 03-detectors/patterns/pattern-matching.md (multi-strategy matching, batch matching),
> 03-detectors/patterns/storage.md (pattern_locations, pattern_history, indexes),
> 06-DETECTOR-SYSTEM.md §2E (pipeline: per-detector → centralized pattern store),
> 06-UNIFIED-ANALYSIS-ENGINE-V2-PREP.md (downstream consumer contract),
> 10-BAYESIAN-CONFIDENCE-SCORING-V2-PREP.md (confidence integration, PatternStats),
> 11-OUTLIER-DETECTION-V2-PREP.md (AggregatedPattern consumer contract),
> 02-STORAGE-V2-PREP.md (patterns table schema, batch writer, medallion architecture),
> 03-NAPI-BRIDGE-V2-PREP.md (command/query pattern, async tasks),
> 04-INFRASTRUCTURE-V2-PREP.md (thiserror, tracing, FxHashMap, SmallVec),
> DRIFT-V2-FULL-SYSTEM-AUDIT.md (Jaccard similarity threshold=0.85, merge>0.9, GA3 audit),
> DRIFT-V2-STACK-HIERARCHY.md (Level 2A — Pattern Intelligence, critical path position),
> DRIFT-V2-SYSTEMS-REFERENCE.md §Duplicate Detection (Jaccard on location sets),
> PLANNING-DRIFT.md (D1-D7),
> .research/03-detectors/RECOMMENDATIONS.md (R3 temporal decay, R5 feedback, R6 outlier),
> .research/16-gap-analysis/RECAP.md §2.6 (duplicate detection gaps), §3.10 (no pattern merging),
> .research/23-pattern-repository/RECAP.md §5 (outlier engine inventory), §8 (audit engine),
> .research/25-services-layer/RECAP.md §5.1 (location deduplication algorithms),
> 00-overview/subsystem-connections.md (aggregation pipeline position),
> cortex-consolidation/src/algorithms/similarity.rs (cosine similarity reference),
> cortex-consolidation/src/pipeline/phase2_clustering.rs (HDBSCAN composite similarity),
> cortex-consolidation/src/pipeline/phase5_integration.rs (overlap-based dedup),
> cortex-retrieval/src/ranking/deduplication.rs (session-aware dedup),
> cortex-core/src/memory/links.rs (PatternLink),
> cortex-temporal/src/drift/patterns.rs (evolution patterns),
> Internet research: MinHash LSH for scalable near-duplicate detection (Milvus, gaoya crate),
> Nelhage (2024) "Finding near-duplicates with Jaccard similarity and MinHash",
> FxHashMap/FxHashSet performance (Rust Performance Book — nnethercote),
> Broder (1997) MinHash original paper, Indyk & Motwani (1998) LSH foundations.
>
> Purpose: Everything needed to build the Pattern Aggregation & Deduplication subsystem
> from scratch. Decisions resolved, inconsistencies flagged, algorithms specified,
> interface contracts defined, build order specified. Zero feature loss from v1.
> This is the DEDICATED deep-dive — the 06-DETECTOR-SYSTEM doc covers aggregation
> at summary level (§2E "centralized pattern store"); this document is the full
> implementation spec with every algorithm, every type, every edge case, every
> integration point, and every v1 feature accounted for.
> Generated: 2026-02-07

---

## Table of Contents

1. Architectural Position
2. V1 Complete Feature Inventory
3. V2 Architecture — Multi-Strategy Aggregation Engine
4. Core Data Model
5. Phase 1: Per-File Collection & Normalization
6. Phase 2: Cross-File Grouping (Pattern ID Bucketing)
7. Phase 3: Location Deduplication (Exact + Semantic)
8. Phase 4: Near-Duplicate Pattern Detection (Jaccard Similarity)
9. Phase 5: Pattern Merging & Alias Resolution
10. Phase 6: Aggregate Statistics Computation
11. Phase 7: Incremental Aggregation (Content-Hash Aware)
12. MinHash LSH for Scalable Deduplication (Future: n > 50K patterns)
13. Integration with Confidence Scoring
14. Integration with Outlier Detection
15. Integration with Rules Engine & Quality Gates
16. Integration with Audit Engine
17. Integration with Drift Temporal Patterns
18. Storage Schema
19. NAPI Interface
20. Event Interface
21. Tracing & Observability
22. Performance Targets & Benchmarks
23. Build Order & Dependencies
24. V1 → V2 Feature Cross-Reference
25. Inconsistencies & Decisions
26. Risk Register

---

## 1. Architectural Position

Pattern Aggregation & Deduplication is Level 2A — Pattern Intelligence in the Drift v2
stack hierarchy. It sits between the detection layer (Level 1) and the confidence scoring /
outlier detection systems (also Level 2A). It is the bridge that transforms per-file,
per-detector raw matches into project-level Pattern entities — without it, Drift has
thousands of scattered matches but no coherent view of codebase conventions.

Per DRIFT-V2-STACK-HIERARCHY.md:
> Pattern Aggregation & Deduplication: Group by ID, Jaccard similarity (0.85 flag,
> 0.95 auto-merge), cross-file merging. Turns per-file matches into project-level
> Pattern entities.

Per PLANNING-DRIFT.md D1: Drift is standalone. Aggregation results write to drift.db.
Per DRIFT-V2-FULL-SYSTEM-AUDIT.md: Duplicate Detection uses Jaccard similarity on
location sets, threshold=0.85, merge>0.9.
Per 00-overview/subsystem-connections.md: Detectors → Patterns → Storage is the
sequential scan pipeline. Aggregation is the "Patterns" step.

### Critical Path Position

```
Detector System (Level 1)
  → Pattern Aggregation & Dedup (Level 2A) ← YOU ARE HERE
    → Bayesian Confidence Scoring (Level 2A)
      → Outlier Detection (Level 2A)
        → Rules Engine (Level 3)
          → Quality Gates (Level 3)
            → Storage (Level 0)
```

Pattern Aggregation is on the critical path. Every downstream system depends on its
output. If aggregation produces duplicates, confidence scoring double-counts. If it
misses merges, outlier detection operates on fragmented data. If it drops locations,
the rules engine generates incomplete violations.

### What Lives Here

- Per-file match collection and normalization
- Cross-file pattern grouping by pattern ID
- Location deduplication (exact position + semantic context)
- Near-duplicate pattern detection via Jaccard similarity on location sets
- Pattern merging with alias preservation (auto-merge > 0.95, flag > 0.85)
- Aggregate statistics computation (occurrence count, file count, outlier count)
- Metadata merging (union strategy across detectors)
- Incremental aggregation (content-hash aware — only re-aggregate changed files)
- Pattern history event emission (Discovered, LocationsUpdated, Merged)
- MinHash LSH index for scalable near-duplicate detection (future: n > 50K)

### What Does NOT Live Here

- Confidence scoring (Bayesian posterior) → Bayesian Confidence Scoring (Level 2A, separate)
- Outlier detection (Z-Score, Grubbs', IQR) → Outlier Detection (Level 2A, separate)
- Convention learning (ValueDistribution) → Learning System (Level 2A, separate)
- Violation generation (severity, quick fixes) → Rules Engine (Level 3)
- Pattern matching (AST, regex, structural) → Detector System (Level 1)
- Quality gates (pass/fail thresholds) → Enforcement (Level 3)
- Pattern storage CRUD → Storage Layer (Level 0)
- MCP tool routing → Presentation (Level 5)

### Downstream Consumers

| Consumer | What It Reads | Interface |
|----------|--------------|-----------|
| Confidence Scoring | AggregatedPattern with location counts, file counts | Vec<AggregatedPattern> |
| Outlier Detection | AggregatedPattern with per-location confidence values | Vec<AggregatedPattern> |
| Rules Engine | Merged Pattern entities with outlier annotations | drift.db patterns table |
| Quality Gates | Pattern counts, duplicate-free rate, compliance rates | drift.db patterns table |
| Audit Engine | Duplicate groups, merge history, health metrics | drift.db pattern_duplicates |
| MCP Tools | Pattern summaries, per-file patterns, duplicate info | NAPI query functions |
| CLI | Pattern reports, duplicate warnings | NAPI query functions |
| IDE/LSP | Per-file pattern annotations | NAPI query_patterns(file) |
| DNA System | Category distribution, pattern fingerprints | AggregatedPattern[] |
| Context Generation | Relevant patterns for AI context | AggregatedPattern[] |
| Drift Temporal | Pattern evolution tracking (crystallization, erosion) | pattern_history events |

### Upstream Dependencies

| Dependency | What It Provides | Contract |
|-----------|-----------------|----------|
| Detector System | Vec<FilePatterns> — per-file, per-detector matches | FilePatterns { file, detector_id, matches: Vec<PatternMatch> } |
| Unified Analysis Engine | DetectionResult[] from single-pass traversal | Vec<DetectionResult> |
| Storage | Read/write drift.db (patterns, pattern_locations, pattern_duplicates) | DatabaseManager |
| Configuration | AggregationConfig (thresholds, merge policy, incremental mode) | drift.toml |
| Scanner | ScanDiff with content hashes for incremental support | ScanDiff { added, modified, removed } |


---

## 2. V1 Complete Feature Inventory

Every feature in the v1 Pattern Aggregation & Deduplication system, catalogued for
zero-loss verification. Sources: 03-detectors/patterns/pipeline.md Phase 4,
.research/25-services-layer/RECAP.md §5.1, .research/23-pattern-repository/RECAP.md §8,
DRIFT-V2-SYSTEMS-REFERENCE.md §Duplicate Detection.

### 2.1 V1 Files

```
packages/core/src/
├── matcher/
│   ├── pattern-matcher.ts     # PatternMatcher class (~400 LOC) — batch matching
│   ├── confidence-scorer.ts   # ConfidenceScorer class (~200 LOC) — post-aggregation scoring
│   ├── outlier-detector.ts    # OutlierDetector class (~300 LOC) — post-aggregation outliers
│   └── types.ts               # AggregatedMatchResult, PatternMatchResult, MatchingResult
├── audit/
│   └── audit-engine.ts        # AuditEngine (~600 LOC) — duplicate detection via Jaccard
├── storage/
│   ├── pattern-store.ts       # PatternStore (~1,168 LOC) — JSON persistence with dedup
│   └── repositories/
│       └── pattern-repository.ts  # SQLite CRUD (~500 LOC)
└── services/
    └── scanner-service.ts     # ScannerService — aggregation engine (~1,400 LOC)
```

### 2.2 Feature Matrix — Every Capability

| # | Feature | V1 Status | V2 Status | V2 Location |
|---|---------|-----------|-----------|-------------|
| F1 | Group PatternMatch[] by pattern ID across files | ✅ | PRESERVED | grouping.rs |
| F2 | Collect all locations per pattern across files | ✅ | PRESERVED | grouping.rs |
| F3 | Count occurrences per pattern | ✅ | PRESERVED | stats.rs |
| F4 | Count unique files per pattern | ✅ | PRESERVED | stats.rs |
| F5 | Calculate variance in confidence values | ✅ | PRESERVED | stats.rs |
| F6 | Track first/last seen timestamps | ✅ | PRESERVED | stats.rs |
| F7 | Build AggregatedMatchResult per pattern | ✅ | UPGRADED → AggregatedPattern | types.rs |
| F8 | Exact location dedup via locationKey(file:line:column) | ✅ | PRESERVED | dedup.rs |
| F9 | Semantic location dedup via semanticLocationKey | ✅ | PRESERVED | dedup.rs |
| F10 | Metadata merging (union strategy across detectors) | ✅ | PRESERVED | merge.rs |
| F11 | Outlier count tracking per pattern | ✅ | PRESERVED | stats.rs |
| F12 | Jaccard similarity on location sets (file:line pairs) | ✅ | UPGRADED | jaccard.rs |
| F13 | Duplicate detection threshold 0.85 | ✅ | PRESERVED | config.rs |
| F14 | Same-category-only comparison for duplicates | ✅ | PRESERVED | jaccard.rs |
| F15 | Merge recommendation if similarity > 0.9 | ✅ | UPGRADED → auto-merge > 0.95 | merge.rs |
| F16 | Review recommendation if similarity > 0.85 | ✅ | PRESERVED | merge.rs |
| F17 | Keep higher-confidence pattern on merge | ✅ | PRESERVED | merge.rs |
| F18 | Combine locations on merge | ✅ | PRESERVED | merge.rs |
| F19 | Preserve both names as aliases on merge | ✅ | PRESERVED | merge.rs |
| F20 | Health score: duplicateFreeRate factor (weight 0.15) | ✅ | PRESERVED | health.rs |
| F21 | Auto-approve: duplicate group membership downgrades | ✅ | PRESERVED | health.rs |
| F22 | Pattern history tracking (created/updated/merged) | ✅ | PRESERVED | events.rs |
| F23 | Batch aggregation (all patterns in single pass) | ✅ | PRESERVED | engine.rs |
| F24 | Per-pattern occurrence counts for outlier detection | ✅ | PRESERVED | stats.rs |
| F25 | Content-hash integrity (SHA-256 checksums) | ✅ | UPGRADED → xxhash | integrity.rs |
| F26 | Cross-file pattern merging | ✅ | PRESERVED | merge.rs |
| F27 | Incremental aggregation (content-hash skip) | ❌ NEW | NEW | incremental.rs |
| F28 | MinHash LSH index for scalable dedup | ❌ NEW | NEW | minhash.rs |
| F29 | Auto-merge at > 0.95 similarity (was manual > 0.9) | ❌ NEW | NEW | merge.rs |
| F30 | Merge conflict resolution (detector priority) | ❌ NEW | NEW | merge.rs |
| F31 | Pattern alias registry | ❌ NEW | NEW | aliases.rs |
| F32 | Aggregate statistics: mean, stddev, quartiles | ❌ NEW | NEW | stats.rs |
| F33 | Parallel aggregation across categories (rayon) | ❌ NEW | NEW | engine.rs |
| F34 | Tracing spans for aggregation phases | ❌ NEW | NEW | engine.rs |
| F35 | Event emission (PatternDiscovered, PatternMerged, etc.) | ❌ NEW | NEW | events.rs |
| F36 | Cross-category duplicate detection (optional) | ❌ NEW | NEW | jaccard.rs |
| F37 | Weighted Jaccard (location + confidence + metadata) | ❌ NEW | NEW | jaccard.rs |

### 2.3 V1 Known Gaps (from .research/16-gap-analysis/RECAP.md)

| Gap | Description | V2 Resolution |
|-----|-------------|---------------|
| G1 | §3.10: No pattern merging — duplicates accumulate, manual review required | Auto-merge at > 0.95 Jaccard similarity |
| G2 | §2.6: Jaccard only flags, doesn't auto-merge | Two-tier: flag > 0.85, auto-merge > 0.95 |
| G3 | §3.10: Multiple detectors discover same convention independently | Detector-priority merge with alias preservation |
| G4 | No incremental aggregation — full rescan writes all patterns | Content-hash aware incremental aggregation |
| G5 | No cross-category duplicate detection | Optional cross-category mode with higher threshold |
| G6 | O(n²) pairwise Jaccard comparison doesn't scale | MinHash LSH for O(n) approximate near-duplicate detection |
| G7 | No pattern grouping or hierarchy | Merge groups with primary + alias structure |
| G8 | No aggregate statistics beyond count | Mean, stddev, quartiles, percentiles for outlier detection |
| G9 | No temporal tracking of aggregation changes | Pattern history events with structured event types |
| G10 | No parallel aggregation | rayon-based parallel aggregation across categories |

---

## 3. V2 Architecture — Multi-Strategy Aggregation Engine

### The Key Insight: Aggregation Is a 7-Phase Pipeline

V1 aggregation is a single pass: group by ID, collect locations, count. V2 treats
aggregation as a structured pipeline with distinct phases, each with clear inputs,
outputs, and invariants. This enables incremental execution (skip phases for unchanged
data), parallel execution (phases 1-3 per-category via rayon), and observability
(tracing spans per phase).

### V2 Architecture

```
                    AggregationEngine
                    ┌──────────────────────────────────────────────────────────┐
                    │                                                          │
  Vec<FilePatterns> ►  Phase 1: Per-File Collection & Normalization            │
                    │  ├── Normalize PatternMatch → NormalizedMatch             │
                    │  ├── Validate required fields                             │
                    │  └── Assign canonical pattern IDs                         │
                    │       │                                                   │
                    │       ▼                                                   │
                    │  Phase 2: Cross-File Grouping                             │
                    │  ├── Bucket by pattern_id (FxHashMap)                     │
                    │  ├── Collect locations per pattern                        │
                    │  └── Track detector provenance                            │
                    │       │                                                   │
                    │       ▼                                                   │
                    │  Phase 3: Location Deduplication                          │
                    │  ├── Exact dedup: locationKey(file:line:column)           │
                    │  ├── Semantic dedup: semanticKey(+function+class)         │
                    │  └── Keep highest-confidence on collision                 │
                    │       │                                                   │
                    │       ▼                                                   │
                    │  Phase 4: Near-Duplicate Pattern Detection                │
                    │  ├── Within-category Jaccard on location sets             │
                    │  ├── Flag pairs > 0.85 similarity                        │
                    │  ├── Auto-merge pairs > 0.95 similarity                  │
                    │  └── Optional: cross-category at > 0.90 threshold        │
                    │       │                                                   │
                    │       ▼                                                   │
                    │  Phase 5: Pattern Merging & Alias Resolution              │
                    │  ├── Merge flagged pairs (keep higher confidence)         │
                    │  ├── Combine locations (union, re-deduplicate)            │
                    │  ├── Preserve aliases (both names)                        │
                    │  └── Resolve detector priority conflicts                  │
                    │       │                                                   │
                    │       ▼                                                   │
                    │  Phase 6: Aggregate Statistics                            │
                    │  ├── Occurrence count, file count, outlier count          │
                    │  ├── Mean, stddev, quartiles of confidence values         │
                    │  ├── First/last seen timestamps                           │
                    │  └── Location set hash (for change detection)             │
                    │       │                                                   │
                    │       ▼                                                   │
                    │  Phase 7: Incremental Reconciliation                      │
                    │  ├── Compare with previous aggregation (location hash)    │
                    │  ├── Emit events: Discovered, Updated, Merged, Removed    │
                    │  └── Write to drift.db via batch writer                   │
                    │       │                                                   │
                    │       └── Vec<AggregatedPattern> ─────────────────────────┤──► Downstream
                    └──────────────────────────────────────────────────────────┘
```

### Why 7 Phases Instead of 1

| Phase | V1 | V2 | Why Separate |
|-------|----|----|-------------|
| Collection | Inline | Explicit | Validates input, normalizes IDs, catches malformed matches early |
| Grouping | Inline | Explicit | FxHashMap bucketing is the hot path — isolate for profiling |
| Location Dedup | Inline | Explicit | Two strategies (exact + semantic) need clear precedence rules |
| Near-Duplicate | Audit engine (separate) | Integrated | Dedup must happen before scoring — not after as in v1 |
| Merging | Manual (v1 only flags) | Automated | Auto-merge > 0.95 eliminates manual review burden |
| Statistics | Inline | Explicit | Outlier detection needs mean/stddev/quartiles — compute once |
| Incremental | None | New | Content-hash aware — skip unchanged patterns entirely |


---

## 4. Core Data Model

### 4.1 Input Types — What Detectors Produce

```rust
/// Per-file detection results from the Detector System.
/// This is the input contract — one per file per scan.
/// Source: 06-UNIFIED-ANALYSIS-ENGINE-V2-PREP.md, 06-DETECTOR-SYSTEM.md §3.
#[derive(Debug, Clone)]
pub struct FilePatterns {
    /// File path (interned via lasso Spur for zero-copy comparisons)
    pub file: Spur,
    /// Language of the file
    pub language: Language,
    /// Content hash for incremental support (xxhash64)
    pub content_hash: u64,
    /// All pattern matches found in this file across all detectors
    pub matches: Vec<PatternMatch>,
    /// Which detectors contributed matches
    pub detector_ids: SmallVec<[Spur; 4]>,
}

/// A single pattern match from a detector.
/// Source: 06-DETECTOR-SYSTEM.md §3 PatternMatch.
#[derive(Debug, Clone)]
pub struct PatternMatch {
    /// Canonical pattern ID (16-char hex hash of detector_id + pattern_id)
    pub pattern_id: PatternId,
    /// File path (interned)
    pub file: Spur,
    /// Location in file
    pub line: u32,
    pub column: u32,
    pub end_line: Option<u32>,
    pub end_column: Option<u32>,
    /// Per-match confidence [0.0, 1.0]
    pub confidence: f64,
    /// Code snippet (optional, for examples)
    pub snippet: Option<String>,
    /// Whether this was flagged as outlier by the detector
    pub is_outlier: bool,
    /// Outlier reason if flagged
    pub outlier_reason: Option<String>,
    /// Detector that produced this match
    pub detector_id: Spur,
    /// Semantic context for semantic deduplication
    pub function_name: Option<Spur>,
    pub class_name: Option<Spur>,
    /// Arbitrary metadata from the detector
    pub metadata: Option<FxHashMap<String, serde_json::Value>>,
}

/// Pattern ID — 16-char hex hash. Cheap to copy, compare, and hash.
/// Generated from: xxhash64(detector_id + "/" + pattern_id_suffix)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PatternId(pub u128);

impl PatternId {
    pub fn new(detector_id: &str, pattern_suffix: &str) -> Self {
        let input = format!("{}/{}", detector_id, pattern_suffix);
        // xxhash128 for 16-byte ID — collision-resistant for our scale
        Self(xxhash_rust::xxh3::xxh3_128(input.as_bytes()))
    }

    pub fn to_hex(&self) -> String {
        format!("{:032x}", self.0)
    }
}
```

### 4.2 Output Types — What Aggregation Produces

```rust
/// The primary output of the aggregation engine.
/// One per unique pattern across the entire project.
/// This is what Confidence Scoring, Outlier Detection, and Rules Engine consume.
#[derive(Debug, Clone)]
pub struct AggregatedPattern {
    /// Canonical pattern ID
    pub pattern_id: PatternId,
    /// Pattern category (security, structural, etc.)
    pub category: Category,
    /// Pattern subcategory (e.g., "sql-injection", "file-naming")
    pub subcategory: String,
    /// Human-readable name (from primary detector)
    pub name: String,
    /// Description (from primary detector)
    pub description: String,
    /// Detection method used
    pub detection_method: DetectionMethod,
    /// Primary detector that discovered this pattern
    pub primary_detector_id: Spur,
    /// All detectors that contributed matches (for provenance)
    pub contributing_detectors: SmallVec<[Spur; 4]>,
    /// Deduplicated locations across all files
    pub locations: Vec<AggregatedLocation>,
    /// Aggregate statistics
    pub stats: PatternStats,
    /// Aliases (names from merged patterns)
    pub aliases: SmallVec<[String; 2]>,
    /// Merged pattern IDs (if this pattern absorbed others)
    pub merged_from: SmallVec<[PatternId; 2]>,
    /// Metadata merged from all detectors (union strategy)
    pub metadata: FxHashMap<String, serde_json::Value>,
    /// Location set hash for change detection (xxhash of sorted location keys)
    pub location_hash: u64,
    /// Whether this pattern was modified in the current aggregation pass
    pub is_dirty: bool,
}

/// A deduplicated location within an aggregated pattern.
#[derive(Debug, Clone)]
pub struct AggregatedLocation {
    /// File path (interned)
    pub file: Spur,
    /// Position
    pub line: u32,
    pub column: u32,
    pub end_line: Option<u32>,
    pub end_column: Option<u32>,
    /// Per-location confidence (highest among duplicates)
    pub confidence: f64,
    /// Outlier status (from detector or post-aggregation analysis)
    pub is_outlier: bool,
    pub outlier_reason: Option<String>,
    /// Semantic context
    pub function_name: Option<Spur>,
    pub class_name: Option<Spur>,
    /// Code snippet (from first match at this location)
    pub snippet: Option<String>,
    /// Which detector(s) found this location
    pub detector_ids: SmallVec<[Spur; 2]>,
}

/// Aggregate statistics for a pattern — computed in Phase 6.
/// This is the contract consumed by Confidence Scoring and Outlier Detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternStats {
    /// Total number of deduplicated locations
    pub occurrence_count: usize,
    /// Number of unique files containing this pattern
    pub file_count: usize,
    /// Number of locations flagged as outliers
    pub outlier_count: usize,
    /// Outlier rate: outlier_count / occurrence_count
    pub outlier_rate: f64,
    /// Confidence statistics across all locations
    pub confidence_mean: f64,
    pub confidence_stddev: f64,
    pub confidence_min: f64,
    pub confidence_max: f64,
    pub confidence_q1: f64,
    pub confidence_median: f64,
    pub confidence_q3: f64,
    /// First time this pattern was seen (across all scans)
    pub first_seen: DateTime<Utc>,
    /// Last time this pattern was seen
    pub last_seen: DateTime<Utc>,
    /// Number of scans this pattern has appeared in
    pub scan_count: u32,
    /// Confidence values array (for outlier detection consumption)
    /// Sorted ascending for efficient percentile computation.
    pub confidence_values: Vec<f64>,
}

/// Duplicate pair detected by Jaccard similarity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicatePair {
    /// First pattern in the pair
    pub pattern_a: PatternId,
    /// Second pattern in the pair
    pub pattern_b: PatternId,
    /// Jaccard similarity [0.0, 1.0]
    pub similarity: f64,
    /// Action taken
    pub action: DuplicateAction,
    /// When detected
    pub detected_at: DateTime<Utc>,
}

/// Action taken on a duplicate pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DuplicateAction {
    /// Similarity > 0.95 — automatically merged
    AutoMerged,
    /// Similarity > 0.85 — flagged for review
    FlaggedForReview,
    /// User approved the merge
    UserMerged,
    /// User dismissed the duplicate flag
    UserDismissed,
}
```

### 4.3 Configuration

```rust
/// Aggregation configuration — loaded from drift.toml [aggregation] section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationConfig {
    /// Jaccard similarity threshold for flagging potential duplicates.
    /// Default: 0.85 (from DRIFT-V2-FULL-SYSTEM-AUDIT.md)
    pub duplicate_flag_threshold: f64,

    /// Jaccard similarity threshold for automatic merging.
    /// Default: 0.95 (upgraded from v1's manual 0.9 recommendation)
    /// Rationale: 0.95 is conservative enough to avoid false merges
    /// while eliminating the manual review burden for obvious duplicates.
    pub auto_merge_threshold: f64,

    /// Whether to check for duplicates across categories.
    /// Default: false (v1 behavior: same-category only)
    /// When true, uses cross_category_threshold instead.
    pub cross_category_enabled: bool,

    /// Threshold for cross-category duplicate detection.
    /// Default: 0.90 (higher than within-category to reduce noise)
    pub cross_category_threshold: f64,

    /// Maximum number of locations to store per pattern.
    /// Default: 10_000 (prevents unbounded growth for very common patterns)
    pub max_locations_per_pattern: usize,

    /// Whether to use semantic deduplication (function/class context).
    /// Default: true
    pub semantic_dedup_enabled: bool,

    /// Whether to enable MinHash LSH for scalable dedup.
    /// Default: false (only needed for > 50K patterns)
    /// When true, uses approximate Jaccard via MinHash instead of exact.
    pub minhash_enabled: bool,

    /// Number of MinHash permutations (higher = more accurate, slower).
    /// Default: 128
    pub minhash_num_perm: usize,

    /// Number of LSH bands (controls sensitivity/specificity tradeoff).
    /// Default: 32 (with 128 perms → 4 rows per band)
    pub minhash_num_bands: usize,

    /// Whether to run aggregation incrementally (skip unchanged files).
    /// Default: true
    pub incremental: bool,

    /// Maximum number of patterns before switching to MinHash LSH.
    /// Default: 50_000
    pub minhash_auto_threshold: usize,
}

impl Default for AggregationConfig {
    fn default() -> Self {
        Self {
            duplicate_flag_threshold: 0.85,
            auto_merge_threshold: 0.95,
            cross_category_enabled: false,
            cross_category_threshold: 0.90,
            max_locations_per_pattern: 10_000,
            semantic_dedup_enabled: true,
            minhash_enabled: false,
            minhash_num_perm: 128,
            minhash_num_bands: 32,
            incremental: true,
            minhash_auto_threshold: 50_000,
        }
    }
}
```


---

## 5. Phase 1: Per-File Collection & Normalization

### Purpose

Transform raw detector output into a normalized, validated form suitable for
cross-file aggregation. This phase catches malformed matches early, assigns
canonical pattern IDs, and ensures consistent data quality.

### Algorithm

```rust
/// Phase 1: Collect and normalize per-file matches.
///
/// Input: Vec<FilePatterns> from the Detector System
/// Output: Vec<NormalizedMatch> — validated, canonical IDs assigned
///
/// Invariants:
/// - Every NormalizedMatch has a valid PatternId
/// - Every NormalizedMatch has line > 0, column > 0
/// - Confidence is clamped to [0.0, 1.0]
/// - File paths are interned (Spur handles)
#[tracing::instrument(skip_all, fields(file_count = file_patterns.len()))]
pub fn collect_and_normalize(
    file_patterns: &[FilePatterns],
    interner: &ThreadedRodeo,
) -> Vec<NormalizedMatch> {
    let mut normalized = Vec::with_capacity(
        file_patterns.iter().map(|fp| fp.matches.len()).sum()
    );

    for fp in file_patterns {
        for m in &fp.matches {
            // Validate required fields
            if m.line == 0 || m.column == 0 {
                tracing::warn!(
                    pattern_id = %m.pattern_id.to_hex(),
                    file = %interner.resolve(&fp.file),
                    "Skipping match with zero line/column"
                );
                continue;
            }

            normalized.push(NormalizedMatch {
                pattern_id: m.pattern_id,
                file: fp.file,
                language: fp.language,
                content_hash: fp.content_hash,
                line: m.line,
                column: m.column,
                end_line: m.end_line,
                end_column: m.end_column,
                confidence: m.confidence.clamp(0.0, 1.0),
                is_outlier: m.is_outlier,
                outlier_reason: m.outlier_reason.clone(),
                detector_id: m.detector_id,
                function_name: m.function_name,
                class_name: m.class_name,
                snippet: m.snippet.clone(),
                metadata: m.metadata.clone(),
            });
        }
    }

    tracing::info!(
        total_matches = normalized.len(),
        "Phase 1 complete: collected and normalized matches"
    );

    normalized
}
```

### Validation Rules

| Field | Rule | On Failure |
|-------|------|-----------|
| line | Must be > 0 | Skip match, warn |
| column | Must be > 0 | Skip match, warn |
| confidence | Must be in [0.0, 1.0] | Clamp to range |
| pattern_id | Must be non-zero | Skip match, error |
| file | Must be valid interned Spur | Skip match, error |
| detector_id | Must be valid interned Spur | Skip match, warn |

---

## 6. Phase 2: Cross-File Grouping (Pattern ID Bucketing)

### Purpose

Group all normalized matches by their canonical pattern ID. This is the core
aggregation step — it transforms per-file data into per-pattern data.

### Algorithm

```rust
/// Phase 2: Group matches by pattern ID using FxHashMap.
///
/// Input: Vec<NormalizedMatch> from Phase 1
/// Output: FxHashMap<PatternId, PatternBucket>
///
/// Performance: O(n) where n = total matches. FxHashMap provides
/// ~2-6x faster hashing than std HashMap for integer keys
/// (per Rust Performance Book — nnethercote).
#[tracing::instrument(skip_all, fields(match_count = matches.len()))]
pub fn group_by_pattern(
    matches: Vec<NormalizedMatch>,
) -> FxHashMap<PatternId, PatternBucket> {
    let estimated_patterns = matches.len() / 10; // Heuristic: ~10 locations per pattern
    let mut buckets: FxHashMap<PatternId, PatternBucket> =
        FxHashMap::with_capacity_and_hasher(estimated_patterns, Default::default());

    for m in matches {
        let bucket = buckets.entry(m.pattern_id).or_insert_with(|| {
            PatternBucket {
                pattern_id: m.pattern_id,
                matches: Vec::with_capacity(16),
                detector_ids: SmallVec::new(),
                files: FxHashSet::default(),
            }
        });

        // Track unique files
        bucket.files.insert(m.file);

        // Track contributing detectors
        if !bucket.detector_ids.contains(&m.detector_id) {
            bucket.detector_ids.push(m.detector_id);
        }

        bucket.matches.push(m);
    }

    tracing::info!(
        pattern_count = buckets.len(),
        "Phase 2 complete: grouped into pattern buckets"
    );

    buckets
}

/// Intermediate bucket for a single pattern during aggregation.
#[derive(Debug)]
struct PatternBucket {
    pattern_id: PatternId,
    matches: Vec<NormalizedMatch>,
    detector_ids: SmallVec<[Spur; 4]>,
    files: FxHashSet<Spur>,
}
```

### Why FxHashMap

Per the Rust Performance Book (nnethercote), FxHashMap uses a fast, non-cryptographic
hash function that outperforms the default SipHash by 2-6x for integer keys. PatternId
is a u128 — an ideal key type for FxHashMap. This is the same approach used by rustc
internally and recommended by 04-INFRASTRUCTURE-V2-PREP.md.

---

## 7. Phase 3: Location Deduplication (Exact + Semantic)

### Purpose

Remove duplicate locations within each pattern bucket. Multiple detectors can find
the same pattern at the same location — we keep only the highest-confidence match.
Two deduplication strategies are applied in sequence.

### Algorithm

```rust
/// Phase 3: Deduplicate locations within each pattern bucket.
///
/// Strategy 1 (Exact): locationKey = "file:line:column"
///   - If two matches have the same file:line:column, keep highest confidence.
///
/// Strategy 2 (Semantic): semanticKey = "file:line:column:function:class"
///   - If semantic dedup is enabled, further dedup by function/class context.
///   - This catches cases where the same logical location is reported with
///     slightly different line numbers (e.g., decorator vs function body).
///
/// Source: .research/25-services-layer/RECAP.md §5.1
#[tracing::instrument(skip_all)]
pub fn deduplicate_locations(
    buckets: &mut FxHashMap<PatternId, PatternBucket>,
    config: &AggregationConfig,
) {
    for bucket in buckets.values_mut() {
        // Strategy 1: Exact dedup by file:line:column
        let mut seen: FxHashMap<LocationKey, usize> = FxHashMap::default();
        let mut deduped: Vec<NormalizedMatch> = Vec::with_capacity(bucket.matches.len());

        for m in bucket.matches.drain(..) {
            let key = LocationKey {
                file: m.file,
                line: m.line,
                column: m.column,
            };

            if let Some(&existing_idx) = seen.get(&key) {
                // Keep higher confidence
                if m.confidence > deduped[existing_idx].confidence {
                    deduped[existing_idx] = m;
                }
            } else {
                seen.insert(key, deduped.len());
                deduped.push(m);
            }
        }

        // Strategy 2: Semantic dedup (optional)
        if config.semantic_dedup_enabled {
            let mut semantic_seen: FxHashMap<SemanticKey, usize> = FxHashMap::default();
            let mut final_deduped: Vec<NormalizedMatch> = Vec::with_capacity(deduped.len());

            for m in deduped.drain(..) {
                let key = SemanticKey {
                    file: m.file,
                    line: m.line,
                    column: m.column,
                    function_name: m.function_name,
                    class_name: m.class_name,
                };

                if let Some(&existing_idx) = semantic_seen.get(&key) {
                    if m.confidence > final_deduped[existing_idx].confidence {
                        // Merge detector IDs before replacing
                        let existing_detector = final_deduped[existing_idx].detector_id;
                        final_deduped[existing_idx] = m;
                        // Preserve provenance — both detectors found this
                        // (tracked at bucket level via detector_ids)
                        let _ = existing_detector; // Already in bucket.detector_ids
                    }
                } else {
                    semantic_seen.insert(key, final_deduped.len());
                    final_deduped.push(m);
                }
            }

            bucket.matches = final_deduped;
        } else {
            bucket.matches = deduped;
        }
    }
}

/// Exact location key for deduplication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct LocationKey {
    file: Spur,
    line: u32,
    column: u32,
}

/// Semantic location key — includes function/class context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SemanticKey {
    file: Spur,
    line: u32,
    column: u32,
    function_name: Option<Spur>,
    class_name: Option<Spur>,
}
```

### Deduplication Precedence

1. Exact dedup runs first (cheapest, catches most duplicates)
2. Semantic dedup runs second (catches context-aware duplicates)
3. On collision: always keep the match with higher confidence
4. Detector provenance is preserved at the bucket level (not per-location)

### Edge Cases

| Case | Handling |
|------|---------|
| Same location, different detectors, same confidence | Keep first encountered (stable ordering) |
| Same location, different end_line/end_column | Keep higher confidence; end range from winner |
| Same semantic key, different snippets | Keep snippet from higher-confidence match |
| Location at line 0 or column 0 | Already filtered in Phase 1 |


---

## 8. Phase 4: Near-Duplicate Pattern Detection (Jaccard Similarity)

### Purpose

Detect patterns that are near-duplicates of each other — different pattern IDs but
overlapping location sets. This happens when multiple detectors independently discover
the same convention, or when a pattern definition is refined across versions.

### The Jaccard Similarity Algorithm

Jaccard similarity measures the overlap between two sets:

```
J(A, B) = |A ∩ B| / |A ∪ B|
```

For pattern deduplication, the sets are location keys (file:line pairs).

```rust
/// Compute Jaccard similarity between two patterns' location sets.
///
/// Uses FxHashSet for O(1) lookups. Total complexity: O(|A| + |B|).
///
/// Source: DRIFT-V2-FULL-SYSTEM-AUDIT.md — "Jaccard similarity on location sets,
/// threshold=0.85, merge>0.9"
/// Source: DRIFT-V2-SYSTEMS-REFERENCE.md — "Jaccard similarity on location sets
/// (file:line pairs), threshold: 0.85 similarity, only compares within same category"
pub fn jaccard_similarity(
    locations_a: &[AggregatedLocation],
    locations_b: &[AggregatedLocation],
) -> f64 {
    if locations_a.is_empty() && locations_b.is_empty() {
        return 1.0; // Both empty = identical
    }
    if locations_a.is_empty() || locations_b.is_empty() {
        return 0.0; // One empty = no overlap
    }

    // Build set A
    let set_a: FxHashSet<(Spur, u32)> = locations_a
        .iter()
        .map(|loc| (loc.file, loc.line))
        .collect();

    // Count intersection and build union size
    let mut intersection = 0usize;
    let mut union_extra = 0usize; // Elements in B not in A

    for loc in locations_b {
        let key = (loc.file, loc.line);
        if set_a.contains(&key) {
            intersection += 1;
        } else {
            union_extra += 1;
        }
    }

    let union_size = set_a.len() + union_extra;

    if union_size == 0 {
        return 0.0;
    }

    intersection as f64 / union_size as f64
}
```

### Weighted Jaccard (V2 Enhancement)

Standard Jaccard treats all locations equally. Weighted Jaccard incorporates
confidence values, giving more weight to high-confidence locations:

```rust
/// Weighted Jaccard similarity — locations weighted by confidence.
///
/// For each location in the intersection, the weight is the minimum
/// confidence of the two matches. For locations in only one set,
/// the weight is the confidence of that match.
///
/// WJ(A, B) = Σ min(w_a, w_b) for shared / Σ max(w_a, w_b) for all
///
/// This prevents two patterns from being merged just because they share
/// many low-confidence locations while differing on high-confidence ones.
pub fn weighted_jaccard_similarity(
    locations_a: &[AggregatedLocation],
    locations_b: &[AggregatedLocation],
) -> f64 {
    if locations_a.is_empty() && locations_b.is_empty() {
        return 1.0;
    }
    if locations_a.is_empty() || locations_b.is_empty() {
        return 0.0;
    }

    // Build map A: (file, line) → confidence
    let map_a: FxHashMap<(Spur, u32), f64> = locations_a
        .iter()
        .map(|loc| ((loc.file, loc.line), loc.confidence))
        .collect();

    let mut min_sum = 0.0f64; // Numerator: sum of min weights
    let mut max_sum = 0.0f64; // Denominator: sum of max weights

    // Process all keys in B
    let mut seen_in_b: FxHashSet<(Spur, u32)> = FxHashSet::default();
    for loc in locations_b {
        let key = (loc.file, loc.line);
        seen_in_b.insert(key);

        if let Some(&conf_a) = map_a.get(&key) {
            // In both sets
            min_sum += conf_a.min(loc.confidence);
            max_sum += conf_a.max(loc.confidence);
        } else {
            // Only in B
            min_sum += 0.0;
            max_sum += loc.confidence;
        }
    }

    // Process keys only in A
    for loc in locations_a {
        let key = (loc.file, loc.line);
        if !seen_in_b.contains(&key) {
            min_sum += 0.0;
            max_sum += loc.confidence;
        }
    }

    if max_sum < f64::EPSILON {
        return 0.0;
    }

    min_sum / max_sum
}
```

### Pairwise Comparison Strategy

```rust
/// Phase 4: Detect near-duplicate patterns via Jaccard similarity.
///
/// Within each category, compare all pairs of patterns.
/// Complexity: O(k²) per category where k = patterns in category.
/// For typical projects (< 1000 patterns per category), this is fast.
/// For large projects (> 50K total patterns), use MinHash LSH (§12).
///
/// Source: DRIFT-V2-SYSTEMS-REFERENCE.md — "Only compares within same category"
#[tracing::instrument(skip_all)]
pub fn detect_near_duplicates(
    patterns: &FxHashMap<PatternId, AggregatedPattern>,
    config: &AggregationConfig,
) -> Vec<DuplicatePair> {
    let mut duplicates = Vec::new();

    // Group patterns by category for within-category comparison
    let mut by_category: FxHashMap<Category, Vec<PatternId>> = FxHashMap::default();
    for (id, pattern) in patterns {
        by_category.entry(pattern.category).or_default().push(*id);
    }

    // Within-category pairwise comparison
    for (_category, pattern_ids) in &by_category {
        let n = pattern_ids.len();
        if n < 2 {
            continue;
        }

        // Check if we should use MinHash LSH instead
        let total_patterns: usize = by_category.values().map(|v| v.len()).sum();
        if config.minhash_enabled || total_patterns > config.minhash_auto_threshold {
            // Delegate to MinHash LSH (§12) — O(n) approximate
            // This path is covered in Section 12
            continue;
        }

        // Exact pairwise Jaccard — O(k²) per category
        for i in 0..n {
            for j in (i + 1)..n {
                let a = &patterns[&pattern_ids[i]];
                let b = &patterns[&pattern_ids[j]];

                let sim = jaccard_similarity(&a.locations, &b.locations);

                if sim >= config.duplicate_flag_threshold {
                    let action = if sim >= config.auto_merge_threshold {
                        DuplicateAction::AutoMerged
                    } else {
                        DuplicateAction::FlaggedForReview
                    };

                    duplicates.push(DuplicatePair {
                        pattern_a: pattern_ids[i],
                        pattern_b: pattern_ids[j],
                        similarity: sim,
                        action,
                        detected_at: Utc::now(),
                    });
                }
            }
        }
    }

    // Optional: cross-category comparison
    if config.cross_category_enabled {
        let all_ids: Vec<PatternId> = patterns.keys().copied().collect();
        let n = all_ids.len();

        for i in 0..n {
            for j in (i + 1)..n {
                let a = &patterns[&all_ids[i]];
                let b = &patterns[&all_ids[j]];

                // Skip same-category pairs (already handled above)
                if a.category == b.category {
                    continue;
                }

                let sim = jaccard_similarity(&a.locations, &b.locations);

                if sim >= config.cross_category_threshold {
                    duplicates.push(DuplicatePair {
                        pattern_a: all_ids[i],
                        pattern_b: all_ids[j],
                        similarity: sim,
                        action: DuplicateAction::FlaggedForReview,
                        detected_at: Utc::now(),
                    });
                }
            }
        }
    }

    tracing::info!(
        duplicate_pairs = duplicates.len(),
        auto_merged = duplicates.iter().filter(|d| d.action == DuplicateAction::AutoMerged).count(),
        flagged = duplicates.iter().filter(|d| d.action == DuplicateAction::FlaggedForReview).count(),
        "Phase 4 complete: near-duplicate detection"
    );

    duplicates
}
```

### Threshold Rationale

| Threshold | Value | Source | Rationale |
|-----------|-------|--------|-----------|
| Flag threshold | 0.85 | DRIFT-V2-FULL-SYSTEM-AUDIT.md | V1 value, proven in production. 85% location overlap is strong evidence of duplication. |
| Auto-merge threshold | 0.95 | V2 upgrade (was 0.9 manual) | 95% overlap is near-certain duplication. Raised from 0.9 to 0.95 for safety — auto-merge must not produce false merges. |
| Cross-category threshold | 0.90 | V2 new | Higher than within-category because cross-category duplicates are less expected and more surprising. |

### Complexity Analysis

| Scenario | Patterns per Category | Pairs | Time (est.) |
|----------|----------------------|-------|-------------|
| Small project | 50 | 1,225 | < 1ms |
| Medium project | 200 | 19,900 | < 10ms |
| Large project | 1,000 | 499,500 | < 100ms |
| Enterprise | 5,000 | 12,497,500 | ~1-5s (switch to MinHash) |

For enterprise scale (> 50K total patterns), MinHash LSH (§12) provides O(n)
approximate Jaccard with tunable accuracy.


---

## 9. Phase 5: Pattern Merging & Alias Resolution

### Purpose

Execute merges for auto-merge pairs (> 0.95 similarity) and prepare flagged pairs
(> 0.85) for user review. Merging combines two patterns into one, preserving all
locations, metadata, and provenance while establishing a primary/alias relationship.

### Merge Algorithm

```rust
/// Phase 5: Merge near-duplicate patterns.
///
/// For auto-merge pairs: merge B into A (A = higher confidence).
/// For flagged pairs: record in pattern_duplicates table for user review.
///
/// Merge strategy (from DRIFT-V2-FULL-SYSTEM-AUDIT.md):
/// - Keep higher-confidence pattern as primary
/// - Combine locations (union, re-deduplicate)
/// - Preserve both names as aliases
/// - Merge metadata (union strategy)
/// - Record merge in pattern_history
#[tracing::instrument(skip_all)]
pub fn merge_patterns(
    patterns: &mut FxHashMap<PatternId, AggregatedPattern>,
    duplicates: &[DuplicatePair],
    config: &AggregationConfig,
) -> Vec<MergeEvent> {
    let mut events = Vec::new();
    let mut absorbed: FxHashSet<PatternId> = FxHashSet::default();

    // Process auto-merge pairs first (sorted by similarity descending)
    let mut auto_merges: Vec<&DuplicatePair> = duplicates
        .iter()
        .filter(|d| d.action == DuplicateAction::AutoMerged)
        .collect();
    auto_merges.sort_by(|a, b| b.similarity.partial_cmp(&a.similarity).unwrap());

    for pair in auto_merges {
        // Skip if either pattern was already absorbed by a previous merge
        if absorbed.contains(&pair.pattern_a) || absorbed.contains(&pair.pattern_b) {
            continue;
        }

        // Determine primary (higher confidence mean) and secondary
        let conf_a = patterns.get(&pair.pattern_a)
            .map(|p| p.stats.confidence_mean)
            .unwrap_or(0.0);
        let conf_b = patterns.get(&pair.pattern_b)
            .map(|p| p.stats.confidence_mean)
            .unwrap_or(0.0);

        let (primary_id, secondary_id) = if conf_a >= conf_b {
            (pair.pattern_a, pair.pattern_b)
        } else {
            (pair.pattern_b, pair.pattern_a)
        };

        // Extract secondary pattern
        if let Some(secondary) = patterns.remove(&secondary_id) {
            if let Some(primary) = patterns.get_mut(&primary_id) {
                // Merge locations (union)
                let mut location_keys: FxHashSet<(Spur, u32, u32)> = primary
                    .locations
                    .iter()
                    .map(|l| (l.file, l.line, l.column))
                    .collect();

                for loc in secondary.locations {
                    let key = (loc.file, loc.line, loc.column);
                    if location_keys.insert(key) {
                        primary.locations.push(loc);
                    }
                }

                // Merge aliases
                primary.aliases.push(secondary.name.clone());
                for alias in secondary.aliases {
                    if !primary.aliases.contains(&alias) {
                        primary.aliases.push(alias);
                    }
                }

                // Track merged pattern IDs
                primary.merged_from.push(secondary_id);
                for merged in secondary.merged_from {
                    primary.merged_from.push(merged);
                }

                // Merge contributing detectors
                for det in secondary.contributing_detectors {
                    if !primary.contributing_detectors.contains(&det) {
                        primary.contributing_detectors.push(det);
                    }
                }

                // Merge metadata (union strategy)
                for (key, value) in secondary.metadata {
                    primary.metadata.entry(key).or_insert(value);
                }

                // Mark as dirty for incremental reconciliation
                primary.is_dirty = true;

                events.push(MergeEvent {
                    primary_id,
                    secondary_id,
                    similarity: pair.similarity,
                    locations_added: primary.locations.len(),
                    timestamp: Utc::now(),
                });
            }

            absorbed.insert(secondary_id);
        }
    }

    tracing::info!(
        merges_executed = events.len(),
        patterns_absorbed = absorbed.len(),
        "Phase 5 complete: pattern merging"
    );

    events
}

/// Event emitted when two patterns are merged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeEvent {
    pub primary_id: PatternId,
    pub secondary_id: PatternId,
    pub similarity: f64,
    pub locations_added: usize,
    pub timestamp: DateTime<Utc>,
}
```

### Merge Conflict Resolution

When two patterns have conflicting metadata, the resolution strategy is:

| Field | Resolution | Rationale |
|-------|-----------|-----------|
| name | Keep primary's name | Higher confidence = more authoritative |
| description | Keep primary's description | Same rationale |
| category | Keep primary's category | Category should match |
| subcategory | Keep primary's subcategory | More specific wins |
| detection_method | Keep primary's method | Primary detector is authoritative |
| severity | Keep higher severity | Conservative — don't downgrade |
| auto_fixable | Keep true if either is true | Preserve fix capability |
| metadata | Union (primary wins on key conflict) | Don't lose detector-specific data |
| locations | Union (deduplicate by position) | Preserve all evidence |
| aliases | Append secondary's name + aliases | Preserve naming history |

### Transitive Merge Prevention

If A merges with B, and B was flagged as duplicate of C, we don't automatically
merge A with C. Each merge is evaluated independently. This prevents cascade merges
that could combine unrelated patterns through a chain of weak similarities.

```
A (sim=0.96 with B) → merge A+B
B (sim=0.87 with C) → flag only (below auto-merge threshold)
A+B is NOT automatically compared with C — the next scan will re-evaluate.
```

---

## 10. Phase 6: Aggregate Statistics Computation

### Purpose

Compute comprehensive statistics for each aggregated pattern. These statistics are
the primary input for Confidence Scoring (§13) and Outlier Detection (§14).

### Algorithm

```rust
/// Phase 6: Compute aggregate statistics for each pattern.
///
/// Computes: occurrence count, file count, outlier count/rate,
/// confidence distribution (mean, stddev, quartiles), timestamps.
///
/// The confidence_values array is sorted ascending for efficient
/// percentile computation — Outlier Detection consumes this directly.
#[tracing::instrument(skip_all)]
pub fn compute_statistics(
    patterns: &mut FxHashMap<PatternId, AggregatedPattern>,
    total_files: usize,
    now: DateTime<Utc>,
) {
    for pattern in patterns.values_mut() {
        let locations = &pattern.locations;
        let n = locations.len();

        if n == 0 {
            pattern.stats = PatternStats::empty(now);
            continue;
        }

        // Collect and sort confidence values
        let mut confidence_values: Vec<f64> = locations
            .iter()
            .map(|l| l.confidence)
            .collect();
        confidence_values.sort_by(|a, b| a.partial_cmp(b).unwrap());

        // Basic counts
        let file_count = {
            let mut files: FxHashSet<Spur> = FxHashSet::default();
            for loc in locations {
                files.insert(loc.file);
            }
            files.len()
        };

        let outlier_count = locations.iter().filter(|l| l.is_outlier).count();

        // Confidence distribution
        let sum: f64 = confidence_values.iter().sum();
        let mean = sum / n as f64;
        let variance = confidence_values
            .iter()
            .map(|v| (v - mean).powi(2))
            .sum::<f64>()
            / n as f64;
        let stddev = variance.sqrt();

        // Quartiles (using nearest-rank method)
        let q1 = percentile(&confidence_values, 25.0);
        let median = percentile(&confidence_values, 50.0);
        let q3 = percentile(&confidence_values, 75.0);

        // Location set hash for change detection
        let location_hash = compute_location_hash(locations);

        pattern.stats = PatternStats {
            occurrence_count: n,
            file_count,
            outlier_count,
            outlier_rate: if n > 0 { outlier_count as f64 / n as f64 } else { 0.0 },
            confidence_mean: mean,
            confidence_stddev: stddev,
            confidence_min: confidence_values[0],
            confidence_max: confidence_values[n - 1],
            confidence_q1: q1,
            confidence_median: median,
            confidence_q3: q3,
            first_seen: pattern.stats.first_seen.min(now), // Preserve earliest
            last_seen: now,
            scan_count: pattern.stats.scan_count + 1,
            confidence_values,
        };

        // Update location hash
        pattern.location_hash = location_hash;
    }
}

/// Nearest-rank percentile computation on a sorted array.
fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = (p / 100.0 * sorted.len() as f64).ceil() as usize;
    let idx = rank.saturating_sub(1).min(sorted.len() - 1);
    sorted[idx]
}

/// Compute a hash of the location set for change detection.
/// Uses xxhash on sorted (file, line, column) tuples.
fn compute_location_hash(locations: &[AggregatedLocation]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut keys: Vec<(Spur, u32, u32)> = locations
        .iter()
        .map(|l| (l.file, l.line, l.column))
        .collect();
    keys.sort();

    let mut hasher = xxhash_rust::xxh3::Xxh3Default::new();
    for key in &keys {
        key.hash(&mut hasher);
    }
    hasher.finish()
}
```

### Statistics Contract for Downstream Systems

| Consumer | Fields Used | Why |
|----------|-----------|-----|
| Confidence Scoring | occurrence_count, file_count, confidence_mean, first_seen, last_seen | 5-factor Bayesian scoring formula |
| Outlier Detection | confidence_values (sorted), occurrence_count | Statistical outlier analysis on confidence distribution |
| Audit Engine | outlier_rate, occurrence_count | Auto-approve decisions (outlierRatio ≤ 0.50) |
| Quality Gates | occurrence_count, file_count, outlier_rate | Pattern compliance gate |
| DNA System | file_count, category distribution | Gene extraction |
| Health Scoring | confidence_mean, outlier_rate | duplicateFreeRate factor |


---

## 11. Phase 7: Incremental Aggregation (Content-Hash Aware)

### Purpose

Avoid re-aggregating unchanged patterns. When a scan only modifies a few files,
only patterns with locations in those files need re-aggregation. This is the
single biggest performance optimization for typical development workflows.

### Algorithm

```rust
/// Phase 7: Incremental reconciliation with previous aggregation state.
///
/// Uses content hashes from the scanner to determine which files changed.
/// Only patterns with locations in changed files are re-aggregated.
/// Unchanged patterns are carried forward with their existing statistics.
///
/// Source: .research/03-detectors/RECOMMENDATIONS.md R2 — "Three-layer
/// incremental detection: file-level skip, pattern-level re-scoring,
/// convention re-learning"
#[tracing::instrument(skip_all)]
pub fn incremental_reconcile(
    new_patterns: &mut FxHashMap<PatternId, AggregatedPattern>,
    previous_patterns: &FxHashMap<PatternId, AggregatedPattern>,
    scan_diff: &ScanDiff,
    config: &AggregationConfig,
) -> ReconciliationResult {
    if !config.incremental {
        // Full aggregation mode — all patterns are new
        return ReconciliationResult {
            discovered: new_patterns.keys().copied().collect(),
            updated: vec![],
            removed: previous_patterns.keys().copied().collect(),
            unchanged: vec![],
        };
    }

    let changed_files: FxHashSet<Spur> = scan_diff.added
        .iter()
        .chain(scan_diff.modified.iter())
        .chain(scan_diff.removed.iter())
        .copied()
        .collect();

    let mut result = ReconciliationResult::default();

    // Carry forward unchanged patterns from previous state
    for (id, prev_pattern) in previous_patterns {
        if new_patterns.contains_key(id) {
            // Pattern exists in both — check if locations changed
            let new_pattern = &new_patterns[id];
            if new_pattern.location_hash == prev_pattern.location_hash {
                // Location set unchanged — carry forward previous stats
                // (preserves first_seen, scan_count, etc.)
                result.unchanged.push(*id);
            } else {
                // Locations changed — mark as updated
                // Preserve first_seen from previous
                if let Some(np) = new_patterns.get_mut(id) {
                    np.stats.first_seen = prev_pattern.stats.first_seen;
                    np.stats.scan_count = prev_pattern.stats.scan_count;
                    np.is_dirty = true;
                }
                result.updated.push(*id);
            }
        } else {
            // Pattern was in previous but not in new scan
            // Check if it had locations only in removed files
            let all_in_removed = prev_pattern.locations.iter().all(|loc| {
                changed_files.contains(&loc.file)
            });

            if all_in_removed {
                // All locations were in removed files — pattern is gone
                result.removed.push(*id);
            } else {
                // Pattern still has locations in unchanged files — carry forward
                new_patterns.insert(*id, prev_pattern.clone());
                result.unchanged.push(*id);
            }
        }
    }

    // New patterns not in previous state
    for id in new_patterns.keys() {
        if !previous_patterns.contains_key(id)
            && !result.unchanged.contains(id)
            && !result.updated.contains(id)
        {
            result.discovered.push(*id);
        }
    }

    tracing::info!(
        discovered = result.discovered.len(),
        updated = result.updated.len(),
        removed = result.removed.len(),
        unchanged = result.unchanged.len(),
        "Phase 7 complete: incremental reconciliation"
    );

    result
}

/// Result of incremental reconciliation.
#[derive(Debug, Default)]
pub struct ReconciliationResult {
    /// Patterns seen for the first time
    pub discovered: Vec<PatternId>,
    /// Patterns with changed location sets
    pub updated: Vec<PatternId>,
    /// Patterns no longer present (all locations in removed files)
    pub removed: Vec<PatternId>,
    /// Patterns with unchanged location sets (carried forward)
    pub unchanged: Vec<PatternId>,
}

/// Scan diff from the scanner — which files changed.
/// Source: 00-SCANNER-V2-PREP.md
#[derive(Debug, Clone)]
pub struct ScanDiff {
    pub added: Vec<Spur>,
    pub modified: Vec<Spur>,
    pub removed: Vec<Spur>,
}
```

### Incremental Performance Impact

| Scenario | Files Changed | Patterns Re-Aggregated | Time Savings |
|----------|--------------|----------------------|-------------|
| Single file edit | 1 | ~5-20 (patterns in that file) | ~95-99% |
| Feature branch (10 files) | 10 | ~50-200 | ~80-95% |
| Large refactor (100 files) | 100 | ~500-2000 | ~50-80% |
| Full rescan | All | All | 0% (baseline) |

---

## 12. MinHash LSH for Scalable Deduplication

### Purpose

When the number of patterns exceeds ~50K, pairwise Jaccard comparison becomes
expensive (O(n²)). MinHash with Locality-Sensitive Hashing (LSH) provides
approximate near-duplicate detection in O(n) time.

### Background

MinHash (Broder, 1997) is a probabilistic technique that estimates Jaccard
similarity by transforming each set into a compact signature vector. The
probability that two MinHash signatures agree at any position equals the
Jaccard similarity of the original sets.

LSH (Indyk & Motwani, 1998) partitions MinHash signatures into bands,
hashing each band to a bucket. Documents with identical bands hash to the
same bucket, creating candidate pairs for exact Jaccard verification.

### Algorithm

```rust
/// MinHash signature computation for a pattern's location set.
///
/// Each location is represented as a (file, line) pair, hashed to u64.
/// The MinHash signature is the minimum hash value across all locations
/// for each of `num_perm` random hash functions.
///
/// Crate: We implement this directly rather than using gaoya or probminhash
/// because our sets are small (typically 10-1000 elements) and we need
/// tight integration with our Spur-based interning.
pub struct MinHasher {
    /// Random coefficients for hash functions: h(x) = (a*x + b) mod p
    /// where p is a large prime (2^61 - 1, a Mersenne prime).
    coefficients: Vec<(u64, u64)>,
    num_perm: usize,
}

impl MinHasher {
    pub fn new(num_perm: usize) -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let p: u64 = (1u64 << 61) - 1; // Mersenne prime

        let coefficients: Vec<(u64, u64)> = (0..num_perm)
            .map(|_| (rng.gen_range(1..p), rng.gen_range(0..p)))
            .collect();

        Self { coefficients, num_perm }
    }

    /// Compute MinHash signature for a set of location keys.
    pub fn signature(&self, locations: &[AggregatedLocation]) -> Vec<u64> {
        let p: u64 = (1u64 << 61) - 1;
        let mut sig = vec![u64::MAX; self.num_perm];

        for loc in locations {
            // Hash the location to a u64
            let loc_hash = {
                let mut hasher = xxhash_rust::xxh3::Xxh3Default::new();
                use std::hash::Hash;
                loc.file.hash(&mut hasher);
                loc.line.hash(&mut hasher);
                std::hash::Hasher::finish(&hasher)
            };

            // Apply each hash function and keep minimum
            for (i, &(a, b)) in self.coefficients.iter().enumerate() {
                let h = (a.wrapping_mul(loc_hash).wrapping_add(b)) % p;
                sig[i] = sig[i].min(h);
            }
        }

        sig
    }

    /// Estimate Jaccard similarity from two MinHash signatures.
    pub fn estimated_similarity(sig_a: &[u64], sig_b: &[u64]) -> f64 {
        assert_eq!(sig_a.len(), sig_b.len());
        let matches = sig_a.iter().zip(sig_b.iter()).filter(|(a, b)| a == b).count();
        matches as f64 / sig_a.len() as f64
    }
}

/// LSH index for efficient candidate pair generation.
///
/// Partitions MinHash signatures into `num_bands` bands of `rows_per_band` rows.
/// Patterns with identical band hashes are candidate pairs.
///
/// With 128 permutations and 32 bands (4 rows per band):
/// - Probability of detecting a pair with Jaccard 0.85: ~99.7%
/// - Probability of detecting a pair with Jaccard 0.50: ~17.8%
/// - Probability of detecting a pair with Jaccard 0.30: ~2.1%
///
/// This gives excellent recall for our 0.85 threshold with minimal false candidates.
pub struct LshIndex {
    num_bands: usize,
    rows_per_band: usize,
    /// band_index → bucket_hash → list of pattern IDs
    buckets: Vec<FxHashMap<u64, Vec<PatternId>>>,
}

impl LshIndex {
    pub fn new(num_bands: usize, num_perm: usize) -> Self {
        let rows_per_band = num_perm / num_bands;
        Self {
            num_bands,
            rows_per_band,
            buckets: (0..num_bands).map(|_| FxHashMap::default()).collect(),
        }
    }

    /// Insert a pattern's MinHash signature into the LSH index.
    pub fn insert(&mut self, pattern_id: PatternId, signature: &[u64]) {
        for band in 0..self.num_bands {
            let start = band * self.rows_per_band;
            let end = start + self.rows_per_band;
            let band_slice = &signature[start..end];

            // Hash the band slice to a bucket key
            let mut hasher = xxhash_rust::xxh3::Xxh3Default::new();
            for &val in band_slice {
                use std::hash::Hash;
                val.hash(&mut hasher);
            }
            let bucket_key = std::hash::Hasher::finish(&hasher);

            self.buckets[band]
                .entry(bucket_key)
                .or_default()
                .push(pattern_id);
        }
    }

    /// Query for candidate near-duplicates of a pattern.
    /// Returns pattern IDs that share at least one LSH band.
    pub fn query_candidates(&self, signature: &[u64]) -> FxHashSet<PatternId> {
        let mut candidates = FxHashSet::default();

        for band in 0..self.num_bands {
            let start = band * self.rows_per_band;
            let end = start + self.rows_per_band;
            let band_slice = &signature[start..end];

            let mut hasher = xxhash_rust::xxh3::Xxh3Default::new();
            for &val in band_slice {
                use std::hash::Hash;
                val.hash(&mut hasher);
            }
            let bucket_key = std::hash::Hasher::finish(&hasher);

            if let Some(bucket) = self.buckets[band].get(&bucket_key) {
                for &id in bucket {
                    candidates.insert(id);
                }
            }
        }

        candidates
    }
}
```

### LSH Tuning Parameters

The probability that two patterns with Jaccard similarity `s` become candidates is:

```
P(candidate) = 1 - (1 - s^r)^b
```

where `r` = rows per band, `b` = number of bands.

| num_perm | num_bands | rows_per_band | P(s=0.85) | P(s=0.50) | P(s=0.30) |
|----------|-----------|---------------|-----------|-----------|-----------|
| 128 | 32 | 4 | 99.7% | 17.8% | 2.1% |
| 128 | 16 | 8 | 72.7% | 0.4% | 0.0% |
| 256 | 64 | 4 | 99.99% | 17.8% | 2.1% |

Default (128 perms, 32 bands) provides excellent recall at our 0.85 threshold
while keeping false candidate rate low. Candidates are verified with exact
Jaccard before any merge decision.

### When to Use MinHash LSH

```
if total_patterns > config.minhash_auto_threshold (default 50_000):
    use MinHash LSH (approximate, O(n))
else:
    use exact pairwise Jaccard (O(k² per category))
```

The threshold of 50K is based on the complexity analysis in §8: at 5K patterns
per category, exact pairwise takes ~1-5s. At 50K total, the O(n²) cost becomes
prohibitive for interactive scan times.


---

## 13. Integration with Confidence Scoring

### Contract

Pattern Aggregation produces `AggregatedPattern` with `PatternStats`. Bayesian
Confidence Scoring (10-BAYESIAN-CONFIDENCE-SCORING-V2-PREP.md) consumes these
to compute the 5-factor Bayesian posterior.

### What Confidence Scoring Needs from Aggregation

| Field | Used For | Formula Reference |
|-------|---------|-------------------|
| stats.occurrence_count | Frequency factor | frequency = occurrences / totalLocations |
| stats.file_count | Spread factor | spread = fileCount / totalFiles |
| stats.confidence_mean | Consistency factor | consistency = 1 - variance |
| stats.confidence_stddev | Consistency factor | variance = stddev² |
| stats.first_seen | Age factor | ageFactor = temporal decay function |
| stats.last_seen | Momentum signal | momentum = current vs previous frequency |
| stats.scan_count | Bayesian prior strength | More scans = stronger prior |
| stats.confidence_values | Outlier detection input | Passed through to outlier engine |
| locations (count) | Total evidence | Alpha/beta update: Beta(1+k, 1+n-k) |

### Ordering Constraint

Aggregation MUST complete before Confidence Scoring begins. The pipeline is:

```
Detectors → Aggregation → Confidence Scoring → Outlier Detection → Rules Engine
```

This is sequential — no parallelism between these phases. Within each phase,
parallelism is possible (e.g., aggregate categories in parallel via rayon).

### Confidence Scoring Callback

```rust
/// Trait for confidence scoring integration.
/// Aggregation calls this after Phase 6 (statistics computation).
pub trait ConfidenceConsumer: Send + Sync {
    /// Called with aggregated patterns ready for scoring.
    fn on_patterns_aggregated(
        &self,
        patterns: &[AggregatedPattern],
        total_files: usize,
        total_locations: usize,
    );
}
```

---

## 14. Integration with Outlier Detection

### Contract

Pattern Aggregation produces `PatternStats` with `confidence_values` (sorted).
Outlier Detection (11-OUTLIER-DETECTION-V2-PREP.md) consumes these to run
statistical analysis.

### What Outlier Detection Needs from Aggregation

| Field | Used For | Method |
|-------|---------|--------|
| stats.confidence_values | The numeric data points for outlier analysis | All methods |
| stats.occurrence_count | Sample size → method selection | n < 10: skip, 10-24: Grubbs', 25-29: ESD, 30+: Z-Score |
| locations[].is_outlier | Pre-existing outlier flags from detectors | Preserved, not overwritten |
| locations[].confidence | Per-location confidence for deviation scoring | Z-Score, IQR |

### Bidirectional Update

After Outlier Detection runs, it writes back to the aggregated patterns:

```rust
/// Outlier Detection writes back outlier annotations to aggregated locations.
/// This is a post-aggregation update — not a re-aggregation.
pub fn apply_outlier_results(
    pattern: &mut AggregatedPattern,
    outlier_results: &[OutlierResult],
) {
    for result in outlier_results {
        if result.index < pattern.locations.len() {
            let loc = &mut pattern.locations[result.index];
            loc.is_outlier = true;
            loc.outlier_reason = Some(result.reason.to_string());
        }
    }

    // Recompute outlier stats
    pattern.stats.outlier_count = pattern.locations.iter().filter(|l| l.is_outlier).count();
    pattern.stats.outlier_rate = if pattern.stats.occurrence_count > 0 {
        pattern.stats.outlier_count as f64 / pattern.stats.occurrence_count as f64
    } else {
        0.0
    };
}
```

---

## 15. Integration with Rules Engine & Quality Gates

### Rules Engine

The Rules Engine (Level 3) consumes aggregated patterns to generate violations.
It reads from drift.db after aggregation has written results.

| What Rules Engine Reads | Where | Purpose |
|------------------------|-------|---------|
| patterns table | drift.db | Approved patterns with confidence scores |
| pattern_locations table | drift.db | Locations with outlier annotations |
| pattern_variants table | drift.db | Scope-based severity overrides |

### Quality Gates

Quality Gates consume aggregate metrics for pass/fail decisions.

| Gate | Metric from Aggregation | Threshold |
|------|------------------------|-----------|
| Pattern Compliance | occurrence_count, confidence_score | Configurable per policy |
| Regression Detection | Previous vs current pattern counts | Delta threshold |
| Audit Health | duplicateFreeRate = 1 - (duplicate_patterns / total_patterns) | Weight 0.15 in health score |

### duplicateFreeRate Computation

```rust
/// Compute the duplicate-free rate for health scoring.
/// Source: DRIFT-V2-FULL-SYSTEM-AUDIT.md — Health Score weight 0.15
pub fn duplicate_free_rate(
    total_patterns: usize,
    duplicate_pairs: &[DuplicatePair],
) -> f64 {
    if total_patterns == 0 {
        return 1.0;
    }

    // Count unique patterns involved in any duplicate pair
    let mut involved: FxHashSet<PatternId> = FxHashSet::default();
    for pair in duplicate_pairs {
        if pair.action == DuplicateAction::FlaggedForReview {
            involved.insert(pair.pattern_a);
            involved.insert(pair.pattern_b);
        }
    }

    let duplicate_count = involved.len();
    1.0 - (duplicate_count as f64 / total_patterns as f64)
}
```

---

## 16. Integration with Audit Engine

### Contract

The Audit Engine consumes duplicate detection results for its validation pipeline.
Source: .research/23-pattern-repository/RECAP.md §8.

### Audit Pipeline Integration

```
Audit Engine Pipeline:
1. Filter patterns by category
2. Detect duplicates (Jaccard similarity) ← NOW DONE BY AGGREGATION ENGINE
3. Cross-validate (call graph, constraints, test coverage)
4. Generate per-pattern recommendations
5. Calculate health score
6. Build summary with degradation alerts
```

In v1, duplicate detection lived in the Audit Engine. In v2, it moves to the
Aggregation Engine (Phase 4) because deduplication must happen BEFORE confidence
scoring, not after. The Audit Engine now consumes the `pattern_duplicates` table
rather than computing duplicates itself.

### What Audit Engine Reads

| Table | Fields | Purpose |
|-------|--------|---------|
| pattern_duplicates | pattern_a, pattern_b, similarity, action | Duplicate pair inventory |
| patterns | confidence_score, outlier_rate, occurrence_count | Auto-approve decisions |
| pattern_history | action = 'merged' | Merge audit trail |

### Auto-Approve Impact

From DRIFT-V2-FULL-SYSTEM-AUDIT.md:
> Duplicate group membership downgrades auto-approve to review.

If a pattern is part of an unresolved duplicate pair (FlaggedForReview), it cannot
be auto-approved regardless of its confidence score. This prevents approving a
pattern that might be a duplicate of another already-approved pattern.

```rust
/// Check if a pattern is eligible for auto-approve.
/// Source: .research/16-gap-analysis/RECAP.md §2.3
pub fn is_auto_approve_eligible(
    pattern: &AggregatedPattern,
    unresolved_duplicates: &FxHashSet<PatternId>,
) -> bool {
    pattern.stats.confidence_mean >= 0.90
        && pattern.stats.outlier_rate <= 0.50
        && pattern.stats.occurrence_count >= 3
        && !unresolved_duplicates.contains(&pattern.pattern_id)
}
```

---

## 17. Integration with Drift Temporal Patterns

### Contract

The Drift temporal system (cortex-temporal/src/drift/patterns.rs) tracks evolution
patterns: crystallization, erosion, explosion, conflict waves. Pattern Aggregation
feeds this system through pattern_history events.

### Evolution Pattern Signals from Aggregation

| Pattern | Signal from Aggregation | How |
|---------|------------------------|-----|
| Crystallization | Pattern discovered → confidence rising → approved | pattern_history events |
| Erosion | Pattern confidence declining across scans | stats.confidence_mean trend |
| Explosion | Sudden increase in pattern count | ReconciliationResult.discovered count |
| Conflict Wave | Multiple patterns flagged as duplicates in same category | DuplicatePair density |

### Event Emission

```rust
/// Events emitted by the Aggregation Engine for downstream consumption.
/// Source: PLANNING-DRIFT.md D5 — DriftEventHandler pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AggregationEvent {
    /// New pattern discovered (first time seen)
    PatternDiscovered {
        pattern_id: PatternId,
        category: Category,
        name: String,
        initial_locations: usize,
    },
    /// Pattern locations updated (locations added/removed)
    PatternUpdated {
        pattern_id: PatternId,
        locations_before: usize,
        locations_after: usize,
        confidence_before: f64,
        confidence_after: f64,
    },
    /// Two patterns merged (auto-merge or user-merge)
    PatternMerged {
        primary_id: PatternId,
        secondary_id: PatternId,
        similarity: f64,
        merged_by: MergeActor,
    },
    /// Pattern removed (all locations in removed files)
    PatternRemoved {
        pattern_id: PatternId,
        reason: String,
    },
    /// Duplicate pair detected (flagged for review)
    DuplicateDetected {
        pattern_a: PatternId,
        pattern_b: PatternId,
        similarity: f64,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MergeActor {
    System,  // Auto-merge (> 0.95 similarity)
    User,    // User-initiated merge
}
```


---

## 18. Storage Schema

### Tables

All tables use STRICT mode (per 02-STORAGE-V2-PREP.md). Pattern Aggregation owns
the write path for these tables; other systems read from them.

```sql
-- Aggregated patterns (Silver layer — post-aggregation, pre-scoring)
-- This is the primary output of the Aggregation Engine.
-- Confidence scoring writes to the confidence_* columns after aggregation.
CREATE TABLE patterns (
    id TEXT PRIMARY KEY NOT NULL,          -- PatternId hex (32 chars)
    category TEXT NOT NULL,                -- Category enum as string
    subcategory TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'discovered',  -- discovered|approved|ignored
    detection_method TEXT NOT NULL,
    primary_detector_id TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    auto_fixable INTEGER NOT NULL DEFAULT 0,

    -- Aggregate statistics (written by Aggregation Engine)
    occurrence_count INTEGER NOT NULL DEFAULT 0,
    file_count INTEGER NOT NULL DEFAULT 0,
    outlier_count INTEGER NOT NULL DEFAULT 0,
    outlier_rate REAL NOT NULL DEFAULT 0.0,

    -- Confidence statistics (written by Aggregation Engine)
    confidence_mean REAL NOT NULL DEFAULT 0.0,
    confidence_stddev REAL NOT NULL DEFAULT 0.0,
    confidence_min REAL NOT NULL DEFAULT 0.0,
    confidence_max REAL NOT NULL DEFAULT 0.0,
    confidence_q1 REAL NOT NULL DEFAULT 0.0,
    confidence_median REAL NOT NULL DEFAULT 0.0,
    confidence_q3 REAL NOT NULL DEFAULT 0.0,

    -- Bayesian confidence (written by Confidence Scoring, NOT Aggregation)
    alpha REAL NOT NULL DEFAULT 1.0,       -- Beta distribution α
    beta_param REAL NOT NULL DEFAULT 1.0,  -- Beta distribution β
    bayesian_score REAL,                   -- Posterior mean
    bayesian_tier TEXT,                    -- Established/Emerging/Tentative/Uncertain
    momentum REAL,                         -- Trend direction [-1, 1]
    decay_rate REAL,                       -- Per-category decay rate

    -- Timestamps
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    scan_count INTEGER NOT NULL DEFAULT 1,

    -- Change detection
    location_hash INTEGER NOT NULL DEFAULT 0,  -- xxhash of sorted location keys

    -- Metadata
    aliases TEXT,                           -- JSON array of alias names
    merged_from TEXT,                       -- JSON array of merged pattern IDs
    contributing_detectors TEXT,            -- JSON array of detector IDs
    metadata TEXT,                          -- JSON object (union of detector metadata)
    tags TEXT,                              -- JSON array of tags

    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

-- Pattern locations (1:N relationship with patterns)
CREATE TABLE pattern_locations (
    id INTEGER PRIMARY KEY,
    pattern_id TEXT NOT NULL REFERENCES patterns(id) ON DELETE CASCADE,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    column_num INTEGER NOT NULL,
    end_line INTEGER,
    end_column INTEGER,
    confidence REAL NOT NULL DEFAULT 0.0,
    is_outlier INTEGER NOT NULL DEFAULT 0,
    outlier_reason TEXT,
    function_name TEXT,
    class_name TEXT,
    snippet TEXT,
    detector_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

-- Duplicate pairs detected by Jaccard similarity
CREATE TABLE pattern_duplicates (
    id INTEGER PRIMARY KEY,
    pattern_a TEXT NOT NULL REFERENCES patterns(id) ON DELETE CASCADE,
    pattern_b TEXT NOT NULL REFERENCES patterns(id) ON DELETE CASCADE,
    similarity REAL NOT NULL,
    action TEXT NOT NULL,                   -- AutoMerged|FlaggedForReview|UserMerged|UserDismissed
    detected_at TEXT NOT NULL,
    resolved_at TEXT,
    resolved_by TEXT,                       -- 'system' or 'user'
    UNIQUE(pattern_a, pattern_b)
) STRICT;

-- Pattern aliases (names from merged patterns)
CREATE TABLE pattern_aliases (
    id INTEGER PRIMARY KEY,
    pattern_id TEXT NOT NULL REFERENCES patterns(id) ON DELETE CASCADE,
    alias_name TEXT NOT NULL,
    original_pattern_id TEXT NOT NULL,      -- The pattern this alias came from
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

-- Pattern history (audit trail for all aggregation events)
CREATE TABLE pattern_history (
    id INTEGER PRIMARY KEY,
    pattern_id TEXT NOT NULL,
    event_type TEXT NOT NULL,               -- Discovered|Updated|Merged|Removed|StatusChanged
    old_value TEXT,                         -- JSON snapshot of previous state
    new_value TEXT,                         -- JSON snapshot of new state
    actor TEXT NOT NULL DEFAULT 'system',   -- 'system' or 'user'
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;
```

### Indexes

```sql
-- Primary query patterns
CREATE INDEX idx_patterns_category ON patterns(category);
CREATE INDEX idx_patterns_status ON patterns(status);
CREATE INDEX idx_patterns_confidence ON patterns(bayesian_score);
CREATE INDEX idx_patterns_severity ON patterns(severity);
CREATE INDEX idx_patterns_detector ON patterns(primary_detector_id);
CREATE INDEX idx_patterns_category_status ON patterns(category, status);

-- Location queries (hot path for IDE integration)
CREATE INDEX idx_locations_pattern ON pattern_locations(pattern_id);
CREATE INDEX idx_locations_file ON pattern_locations(file);
CREATE INDEX idx_locations_file_line ON pattern_locations(file, line);
CREATE INDEX idx_locations_outlier ON pattern_locations(is_outlier)
    WHERE is_outlier = 1;

-- Duplicate queries
CREATE INDEX idx_duplicates_pattern_a ON pattern_duplicates(pattern_a);
CREATE INDEX idx_duplicates_pattern_b ON pattern_duplicates(pattern_b);
CREATE INDEX idx_duplicates_action ON pattern_duplicates(action);
CREATE INDEX idx_duplicates_unresolved ON pattern_duplicates(action)
    WHERE action = 'FlaggedForReview';

-- Alias queries
CREATE INDEX idx_aliases_pattern ON pattern_aliases(pattern_id);
CREATE INDEX idx_aliases_name ON pattern_aliases(alias_name);

-- History queries
CREATE INDEX idx_history_pattern ON pattern_history(pattern_id);
CREATE INDEX idx_history_event ON pattern_history(event_type);
CREATE INDEX idx_history_time ON pattern_history(created_at);
```

### Batch Write Strategy

Per 02-STORAGE-V2-PREP.md, all writes use the batch writer with crossbeam
backpressure. Aggregation writes are batched per-phase:

```rust
/// Write aggregated patterns to drift.db via batch writer.
/// Uses a single transaction for atomicity.
pub fn persist_aggregation(
    writer: &Mutex<Connection>,
    patterns: &FxHashMap<PatternId, AggregatedPattern>,
    duplicates: &[DuplicatePair],
    events: &[AggregationEvent],
    reconciliation: &ReconciliationResult,
) -> Result<(), AggregationError> {
    let conn = writer.lock().map_err(|_| AggregationError::LockFailed)?;

    conn.execute_batch("BEGIN IMMEDIATE")?;

    // 1. Upsert patterns (only dirty ones)
    let mut pattern_stmt = conn.prepare_cached(
        "INSERT OR REPLACE INTO patterns (id, category, subcategory, name, description,
         status, detection_method, primary_detector_id, severity, auto_fixable,
         occurrence_count, file_count, outlier_count, outlier_rate,
         confidence_mean, confidence_stddev, confidence_min, confidence_max,
         confidence_q1, confidence_median, confidence_q3,
         first_seen, last_seen, scan_count, location_hash,
         aliases, merged_from, contributing_detectors, metadata, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                 ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21,
                 ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, datetime('now'))"
    )?;

    for pattern in patterns.values().filter(|p| p.is_dirty) {
        pattern_stmt.execute(rusqlite::params![
            pattern.pattern_id.to_hex(),
            pattern.category.as_str(),
            pattern.subcategory,
            pattern.name,
            pattern.description,
            "discovered", // Default status — Audit Engine manages transitions
            pattern.detection_method.as_str(),
            // ... remaining fields
        ])?;
    }

    // 2. Bulk insert locations (delete + re-insert for dirty patterns)
    for pattern in patterns.values().filter(|p| p.is_dirty) {
        conn.execute(
            "DELETE FROM pattern_locations WHERE pattern_id = ?1",
            [&pattern.pattern_id.to_hex()],
        )?;

        let mut loc_stmt = conn.prepare_cached(
            "INSERT INTO pattern_locations
             (pattern_id, file, line, column_num, end_line, end_column,
              confidence, is_outlier, outlier_reason, function_name, class_name,
              snippet, detector_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)"
        )?;

        for loc in &pattern.locations {
            loc_stmt.execute(rusqlite::params![
                pattern.pattern_id.to_hex(),
                // ... location fields
            ])?;
        }
    }

    // 3. Upsert duplicate pairs
    for dup in duplicates {
        conn.execute(
            "INSERT OR REPLACE INTO pattern_duplicates
             (pattern_a, pattern_b, similarity, action, detected_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                dup.pattern_a.to_hex(),
                dup.pattern_b.to_hex(),
                dup.similarity,
                format!("{:?}", dup.action),
                dup.detected_at.to_rfc3339(),
            ],
        )?;
    }

    // 4. Record history events
    for event in events {
        conn.execute(
            "INSERT INTO pattern_history (pattern_id, event_type, new_value, actor)
             VALUES (?1, ?2, ?3, 'system')",
            rusqlite::params![
                event.pattern_id_str(),
                event.event_type_str(),
                serde_json::to_string(event).unwrap_or_default(),
            ],
        )?;
    }

    // 5. Remove patterns that are gone
    for id in &reconciliation.removed {
        conn.execute(
            "DELETE FROM patterns WHERE id = ?1",
            [&id.to_hex()],
        )?;
    }

    conn.execute_batch("COMMIT")?;

    Ok(())
}
```


---

## 19. NAPI Interface

### Command/Query Pattern

Per 03-NAPI-BRIDGE-V2-PREP.md, all NAPI functions follow the command/query pattern.
Aggregation exposes query functions only — commands are internal (triggered by scan).

```rust
/// Query aggregated patterns with filters.
/// Returns JSON-serializable results for TypeScript consumption.
#[napi]
pub fn query_patterns(
    filters: PatternQueryFilters,
    pagination: KeysetPagination,
) -> napi::Result<PatternQueryResult> {
    let runtime = get_runtime()?;
    let db = runtime.database();

    let patterns = db.readers().with_conn(|conn| {
        query_patterns_impl(conn, &filters, &pagination)
    })?;

    Ok(patterns)
}

/// Query patterns by file path (hot path for IDE integration).
#[napi]
pub fn query_patterns_by_file(
    file_path: String,
) -> napi::Result<Vec<NapiPatternLocation>> {
    let runtime = get_runtime()?;
    let db = runtime.database();

    db.readers().with_conn(|conn| {
        let mut stmt = conn.prepare_cached(
            "SELECT pl.*, p.name, p.category, p.bayesian_score
             FROM pattern_locations pl
             JOIN patterns p ON pl.pattern_id = p.id
             WHERE pl.file = ?1
             ORDER BY pl.line ASC"
        )?;
        // ... map to NapiPatternLocation
        Ok(vec![])
    })
}

/// Query duplicate pairs (for audit UI and MCP tools).
#[napi]
pub fn query_duplicate_pairs(
    status_filter: Option<String>,
) -> napi::Result<Vec<NapiDuplicatePair>> {
    let runtime = get_runtime()?;
    let db = runtime.database();

    db.readers().with_conn(|conn| {
        let query = if let Some(status) = &status_filter {
            format!(
                "SELECT * FROM pattern_duplicates WHERE action = '{}' ORDER BY similarity DESC",
                status
            )
        } else {
            "SELECT * FROM pattern_duplicates ORDER BY similarity DESC".to_string()
        };
        // ... map to NapiDuplicatePair
        Ok(vec![])
    })
}

/// Resolve a duplicate pair (user action: merge or dismiss).
#[napi]
pub fn resolve_duplicate_pair(
    pattern_a: String,
    pattern_b: String,
    action: String,  // "merge" or "dismiss"
) -> napi::Result<()> {
    let runtime = get_runtime()?;
    let db = runtime.database();

    match action.as_str() {
        "merge" => {
            // Execute merge (same as auto-merge but user-initiated)
            // Update pattern_duplicates.action = 'UserMerged'
            // Record in pattern_history
        }
        "dismiss" => {
            // Update pattern_duplicates.action = 'UserDismissed'
            // Record in pattern_history
        }
        _ => return Err(napi::Error::from_reason("Invalid action")),
    }

    Ok(())
}

/// Query pattern aliases.
#[napi]
pub fn query_pattern_aliases(
    pattern_id: String,
) -> napi::Result<Vec<String>> {
    let runtime = get_runtime()?;
    let db = runtime.database();

    db.readers().with_conn(|conn| {
        let mut stmt = conn.prepare_cached(
            "SELECT alias_name FROM pattern_aliases WHERE pattern_id = ?1"
        )?;
        let aliases: Vec<String> = stmt
            .query_map([&pattern_id], |row| row.get(0))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(aliases)
    })
}

/// Get aggregation health metrics.
#[napi]
pub fn query_aggregation_health() -> napi::Result<NapiAggregationHealth> {
    let runtime = get_runtime()?;
    let db = runtime.database();

    db.readers().with_conn(|conn| {
        let total_patterns: usize = conn.query_row(
            "SELECT COUNT(*) FROM patterns", [], |row| row.get(0)
        )?;
        let unresolved_duplicates: usize = conn.query_row(
            "SELECT COUNT(*) FROM pattern_duplicates WHERE action = 'FlaggedForReview'",
            [], |row| row.get(0)
        )?;
        let duplicate_free_rate = if total_patterns > 0 {
            1.0 - (unresolved_duplicates as f64 / total_patterns as f64)
        } else {
            1.0
        };

        Ok(NapiAggregationHealth {
            total_patterns: total_patterns as u32,
            unresolved_duplicates: unresolved_duplicates as u32,
            duplicate_free_rate,
            // ... additional metrics
        })
    })
}
```

### TypeScript Types (Generated by napi-rs v3)

```typescript
interface PatternQueryFilters {
    category?: string;
    status?: string;
    minConfidence?: number;
    detectorId?: string;
    filePattern?: string;
}

interface KeysetPagination {
    afterId?: string;
    limit: number;
}

interface PatternQueryResult {
    patterns: NapiPattern[];
    hasMore: boolean;
    nextCursor?: string;
}

interface NapiDuplicatePair {
    patternA: string;
    patternB: string;
    similarity: number;
    action: string;
    detectedAt: string;
}

interface NapiAggregationHealth {
    totalPatterns: number;
    unresolvedDuplicates: number;
    duplicateFreeRate: number;
}
```

---

## 20. Event Interface

### DriftEventHandler Integration

Per PLANNING-DRIFT.md D5, all state-changing operations emit events via
DriftEventHandler. In standalone mode, these are no-ops. When the bridge
is active, they become Cortex memories.

```rust
/// Event handler trait for aggregation events.
/// Source: PLANNING-DRIFT.md D5 — DriftEventHandler pattern.
pub trait AggregationEventHandler: Send + Sync {
    fn on_pattern_discovered(&self, event: &AggregationEvent) {}
    fn on_pattern_updated(&self, event: &AggregationEvent) {}
    fn on_pattern_merged(&self, event: &AggregationEvent) {}
    fn on_pattern_removed(&self, event: &AggregationEvent) {}
    fn on_duplicate_detected(&self, event: &AggregationEvent) {}
}

/// No-op implementation for standalone mode.
pub struct NoOpAggregationHandler;
impl AggregationEventHandler for NoOpAggregationHandler {}
```

### Bridge Event Mapping

When the cortex-drift-napi bridge is active, aggregation events map to Cortex
memory creation:

| Aggregation Event | Cortex Memory Type | Content |
|-------------------|-------------------|---------|
| PatternDiscovered | pattern_rationale | "New pattern discovered: {name} in {category}" |
| PatternMerged | pattern_rationale | "Patterns merged: {primary} absorbed {secondary} (similarity: {sim})" |
| PatternRemoved | pattern_rationale | "Pattern removed: {name} — all locations in deleted files" |

---

## 21. Tracing & Observability

### Tracing Spans

Per 04-INFRASTRUCTURE-V2-PREP.md, all operations use `tracing` for structured
logging and performance monitoring.

```rust
/// Top-level aggregation span.
#[tracing::instrument(
    name = "aggregation.run",
    skip_all,
    fields(
        file_count = file_patterns.len(),
        total_matches = file_patterns.iter().map(|fp| fp.matches.len()).sum::<usize>(),
    )
)]
pub fn run_aggregation(
    file_patterns: &[FilePatterns],
    previous: &FxHashMap<PatternId, AggregatedPattern>,
    scan_diff: &ScanDiff,
    config: &AggregationConfig,
    event_handler: &dyn AggregationEventHandler,
) -> Result<AggregationResult, AggregationError> {
    // Phase 1
    let _phase1 = tracing::info_span!("aggregation.phase1_collect").entered();
    let normalized = collect_and_normalize(file_patterns, &interner);
    drop(_phase1);

    // Phase 2
    let _phase2 = tracing::info_span!("aggregation.phase2_group").entered();
    let mut buckets = group_by_pattern(normalized);
    drop(_phase2);

    // Phase 3
    let _phase3 = tracing::info_span!("aggregation.phase3_dedup").entered();
    deduplicate_locations(&mut buckets, config);
    drop(_phase3);

    // Phase 4
    let _phase4 = tracing::info_span!("aggregation.phase4_jaccard").entered();
    let mut patterns = build_aggregated_patterns(buckets);
    let duplicates = detect_near_duplicates(&patterns, config);
    drop(_phase4);

    // Phase 5
    let _phase5 = tracing::info_span!("aggregation.phase5_merge").entered();
    let merge_events = merge_patterns(&mut patterns, &duplicates, config);
    drop(_phase5);

    // Phase 6
    let _phase6 = tracing::info_span!("aggregation.phase6_stats").entered();
    compute_statistics(&mut patterns, total_files, Utc::now());
    drop(_phase6);

    // Phase 7
    let _phase7 = tracing::info_span!("aggregation.phase7_reconcile").entered();
    let reconciliation = incremental_reconcile(&mut patterns, previous, scan_diff, config);
    drop(_phase7);

    // Emit events
    for event in &merge_events {
        event_handler.on_pattern_merged(&AggregationEvent::PatternMerged {
            primary_id: event.primary_id,
            secondary_id: event.secondary_id,
            similarity: event.similarity,
            merged_by: MergeActor::System,
        });
    }

    Ok(AggregationResult {
        patterns,
        duplicates,
        reconciliation,
        merge_events,
    })
}
```

### Key Metrics

| Metric | Span | What It Measures |
|--------|------|-----------------|
| aggregation.run.duration | Top-level | Total aggregation time |
| aggregation.phase1_collect.duration | Phase 1 | Collection + normalization time |
| aggregation.phase2_group.duration | Phase 2 | Grouping time |
| aggregation.phase3_dedup.duration | Phase 3 | Location deduplication time |
| aggregation.phase4_jaccard.duration | Phase 4 | Near-duplicate detection time |
| aggregation.phase5_merge.duration | Phase 5 | Pattern merging time |
| aggregation.phase6_stats.duration | Phase 6 | Statistics computation time |
| aggregation.phase7_reconcile.duration | Phase 7 | Incremental reconciliation time |
| aggregation.patterns_total | Result | Total aggregated patterns |
| aggregation.duplicates_found | Result | Duplicate pairs detected |
| aggregation.merges_executed | Result | Auto-merges performed |
| aggregation.locations_deduped | Phase 3 | Locations removed by dedup |


---

## 22. Performance Targets & Benchmarks

### Targets

| Metric | Target | V1 Baseline | Rationale |
|--------|--------|-------------|-----------|
| Full aggregation (10K files, 50K matches) | < 200ms | ~500ms (TS) | Rust + FxHashMap + no JSON serialization |
| Full aggregation (100K files, 500K matches) | < 2s | N/A (untested) | Linear scaling with match count |
| Incremental aggregation (1 file changed) | < 10ms | N/A (no incremental) | Only re-aggregate affected patterns |
| Incremental aggregation (10 files changed) | < 50ms | N/A | Proportional to changed patterns |
| Jaccard pairwise (1000 patterns/category) | < 100ms | ~200ms (TS) | FxHashSet intersection is fast |
| MinHash LSH build (50K patterns) | < 500ms | N/A | One-time index build |
| MinHash LSH query (per pattern) | < 1ms | N/A | O(1) bucket lookup |
| Location dedup (500K locations) | < 100ms | ~300ms (TS) | FxHashMap with pre-allocated capacity |
| Statistics computation (50K patterns) | < 50ms | ~100ms (TS) | Sorted array percentiles, no allocation |
| Storage write (50K patterns, batch) | < 500ms | ~1s (TS) | Single transaction, prepared statements |

### Benchmark Strategy

```rust
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};

fn bench_aggregation(c: &mut Criterion) {
    let mut group = c.benchmark_group("aggregation");

    for size in [1_000, 10_000, 50_000, 100_000] {
        let file_patterns = generate_test_file_patterns(size);

        group.bench_with_input(
            BenchmarkId::new("full_aggregation", size),
            &file_patterns,
            |b, fp| {
                b.iter(|| {
                    run_aggregation(fp, &FxHashMap::default(), &ScanDiff::empty(),
                                   &AggregationConfig::default(), &NoOpAggregationHandler)
                });
            },
        );
    }

    group.finish();
}

fn bench_jaccard(c: &mut Criterion) {
    let mut group = c.benchmark_group("jaccard");

    for size in [10, 100, 1_000, 10_000] {
        let locations_a = generate_test_locations(size);
        let locations_b = generate_test_locations_with_overlap(size, 0.85);

        group.bench_with_input(
            BenchmarkId::new("jaccard_similarity", size),
            &(locations_a.clone(), locations_b.clone()),
            |b, (a, b_locs)| {
                b.iter(|| jaccard_similarity(a, b_locs));
            },
        );
    }

    group.finish();
}

fn bench_minhash(c: &mut Criterion) {
    let mut group = c.benchmark_group("minhash");
    let hasher = MinHasher::new(128);

    for size in [100, 1_000, 10_000] {
        let locations = generate_test_locations(size);

        group.bench_with_input(
            BenchmarkId::new("minhash_signature", size),
            &locations,
            |b, locs| {
                b.iter(|| hasher.signature(locs));
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_aggregation, bench_jaccard, bench_minhash);
criterion_main!(benches);
```

### Memory Budget

| Component | Estimated Memory | Notes |
|-----------|-----------------|-------|
| AggregatedPattern (50K patterns) | ~50MB | ~1KB per pattern (name, description, metadata) |
| AggregatedLocation (500K locations) | ~40MB | ~80 bytes per location |
| FxHashMap overhead | ~5MB | Hash table overhead for 50K entries |
| MinHash signatures (50K × 128) | ~50MB | 8 bytes × 128 perms × 50K patterns |
| LSH index (32 bands) | ~10MB | Bucket hash maps |
| Total peak | ~155MB | Acceptable for analysis workload |

---

## 23. Build Order & Dependencies

### Crate Dependencies

```toml
[package]
name = "drift-aggregation"
version = "0.1.0"
edition = "2021"

[dependencies]
drift-core = { path = "../drift-core" }       # PatternId, Category, Language, etc.
drift-storage = { path = "../drift-storage" }  # DatabaseManager, batch writer
chrono = { version = "0.4", features = ["serde"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
rustc-hash = "2"                               # FxHashMap, FxHashSet
smallvec = { version = "1", features = ["serde"] }
xxhash-rust = { version = "0.8", features = ["xxh3"] }
tracing = "0.1"
thiserror = "2"
rand = "0.8"                                   # MinHash coefficient generation
rayon = "1"                                    # Parallel aggregation across categories

[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }
proptest = "1"
```

### Build Order (within drift-core)

```
1. drift-core types (PatternId, Category, Language, PatternMatch)
2. drift-storage (DatabaseManager, batch writer, schema migration)
3. drift-aggregation (this system)
   ├── types.rs (AggregatedPattern, AggregatedLocation, PatternStats, etc.)
   ├── config.rs (AggregationConfig)
   ├── normalize.rs (Phase 1: collection & normalization)
   ├── grouping.rs (Phase 2: cross-file grouping)
   ├── dedup.rs (Phase 3: location deduplication)
   ├── jaccard.rs (Phase 4: Jaccard similarity + weighted Jaccard)
   ├── merge.rs (Phase 5: pattern merging & alias resolution)
   ├── stats.rs (Phase 6: aggregate statistics)
   ├── incremental.rs (Phase 7: incremental reconciliation)
   ├── minhash.rs (MinHash LSH for scalable dedup)
   ├── events.rs (AggregationEvent, AggregationEventHandler)
   ├── health.rs (duplicate_free_rate, auto-approve eligibility)
   ├── storage.rs (persist_aggregation, query functions)
   ├── engine.rs (run_aggregation — orchestrates all phases)
   ├── errors.rs (AggregationError enum)
   └── mod.rs (public API)
4. drift-confidence (Bayesian Confidence Scoring — consumes AggregatedPattern)
5. drift-outlier (Outlier Detection — consumes PatternStats)
```

### File Structure

```
drift-aggregation/
├── Cargo.toml
├── src/
│   ├── mod.rs              # Public API: run_aggregation(), AggregationResult
│   ├── types.rs            # AggregatedPattern, AggregatedLocation, PatternStats,
│   │                       # DuplicatePair, DuplicateAction, PatternId
│   ├── config.rs           # AggregationConfig with defaults
│   ├── normalize.rs        # Phase 1: collect_and_normalize()
│   ├── grouping.rs         # Phase 2: group_by_pattern()
│   ├── dedup.rs            # Phase 3: deduplicate_locations()
│   ├── jaccard.rs          # Phase 4: jaccard_similarity(), weighted_jaccard_similarity(),
│   │                       # detect_near_duplicates()
│   ├── merge.rs            # Phase 5: merge_patterns(), MergeEvent
│   ├── stats.rs            # Phase 6: compute_statistics(), percentile()
│   ├── incremental.rs      # Phase 7: incremental_reconcile(), ReconciliationResult
│   ├── minhash.rs          # MinHasher, LshIndex
│   ├── events.rs           # AggregationEvent, AggregationEventHandler
│   ├── health.rs           # duplicate_free_rate(), is_auto_approve_eligible()
│   ├── storage.rs          # persist_aggregation(), query functions
│   ├── engine.rs           # run_aggregation() — top-level orchestrator
│   └── errors.rs           # AggregationError enum (thiserror)
├── benches/
│   └── aggregation_bench.rs  # Criterion benchmarks
└── tests/
    ├── aggregation_test.rs   # Integration tests
    ├── jaccard_test.rs       # Jaccard similarity unit tests
    ├── minhash_test.rs       # MinHash LSH tests
    ├── dedup_test.rs         # Location deduplication tests
    ├── merge_test.rs         # Pattern merging tests
    ├── incremental_test.rs   # Incremental reconciliation tests
    └── property_tests.rs     # Property-based tests (proptest)
```

---

## 24. V1 → V2 Feature Cross-Reference

Complete mapping of every v1 feature to its v2 location. Zero feature loss.

| V1 Feature | V1 Location | V2 Location | Status |
|-----------|-------------|-------------|--------|
| Group by pattern ID | scanner-service.ts aggregation | grouping.rs | PRESERVED |
| Collect locations across files | scanner-service.ts | grouping.rs | PRESERVED |
| Count occurrences | scanner-service.ts | stats.rs | PRESERVED |
| Count unique files | scanner-service.ts | stats.rs | PRESERVED |
| Calculate confidence variance | scanner-service.ts | stats.rs | PRESERVED |
| Track first/last seen | scanner-service.ts | stats.rs | PRESERVED |
| AggregatedMatchResult type | types.ts | types.rs (AggregatedPattern) | UPGRADED |
| locationKey dedup (file:line:column) | scanner-service.ts | dedup.rs | PRESERVED |
| semanticLocationKey dedup | scanner-service.ts | dedup.rs | PRESERVED |
| Metadata union merge | scanner-service.ts | merge.rs | PRESERVED |
| Outlier count tracking | scanner-service.ts | stats.rs | PRESERVED |
| Jaccard similarity (location sets) | audit-engine.ts | jaccard.rs | UPGRADED |
| Duplicate threshold 0.85 | audit-engine.ts | config.rs | PRESERVED |
| Same-category comparison | audit-engine.ts | jaccard.rs | PRESERVED |
| Merge recommendation > 0.9 | audit-engine.ts | merge.rs (auto-merge > 0.95) | UPGRADED |
| Keep higher confidence on merge | audit-engine.ts | merge.rs | PRESERVED |
| Combine locations on merge | audit-engine.ts | merge.rs | PRESERVED |
| Preserve names as aliases | audit-engine.ts | merge.rs + aliases.rs | PRESERVED |
| duplicateFreeRate health factor | audit-engine.ts | health.rs | PRESERVED |
| Auto-approve downgrade for duplicates | audit-engine.ts | health.rs | PRESERVED |
| Pattern history tracking | pattern-store.ts | events.rs + storage.rs | PRESERVED |
| Batch aggregation | scanner-service.ts | engine.rs | PRESERVED |
| Content-hash integrity | pattern-store.ts (SHA-256) | integrity via xxhash | UPGRADED |
| Cross-file merging | scanner-service.ts | merge.rs | PRESERVED |
| Incremental aggregation | ❌ (not in v1) | incremental.rs | NEW |
| MinHash LSH | ❌ (not in v1) | minhash.rs | NEW |
| Auto-merge > 0.95 | ❌ (not in v1) | merge.rs | NEW |
| Weighted Jaccard | ❌ (not in v1) | jaccard.rs | NEW |
| Parallel aggregation (rayon) | ❌ (not in v1) | engine.rs | NEW |
| Tracing spans | ❌ (not in v1) | engine.rs | NEW |
| Structured events | ❌ (not in v1) | events.rs | NEW |
| Cross-category dedup | ❌ (not in v1) | jaccard.rs | NEW |
| Pattern alias registry | ❌ (not in v1) | storage.rs (pattern_aliases table) | NEW |
| Aggregate quartiles/percentiles | ❌ (not in v1) | stats.rs | NEW |


---

## 25. Inconsistencies & Decisions

### I1: Duplicate Detection Location — Audit Engine vs Aggregation Engine

**Inconsistency**: In v1, duplicate detection lives in the Audit Engine (post-scoring).
In v2, it must move to the Aggregation Engine (pre-scoring) because duplicates inflate
confidence scores if not caught before scoring.

**Decision**: Duplicate detection moves to Aggregation Engine (Phase 4). The Audit Engine
consumes the `pattern_duplicates` table instead of computing duplicates itself.

**Impact**: Audit Engine loses ~100 LOC of Jaccard computation. Gains cleaner separation
of concerns. Confidence scores are more accurate because duplicates are merged before scoring.

### I2: Auto-Merge Threshold — 0.9 vs 0.95

**Inconsistency**: DRIFT-V2-FULL-SYSTEM-AUDIT.md says "merge>0.9" but also says
"threshold=0.85, merge>0.9" in the same sentence. The DRIFT-V2-SYSTEMS-REFERENCE.md
says "Recommendation: merge if > 0.9, review if > 0.85."

**Decision**: Auto-merge threshold is 0.95 (not 0.9). Rationale: auto-merge is
irreversible — a false merge loses pattern identity. 0.95 is conservative enough
to avoid false merges while still eliminating obvious duplicates. The 0.85-0.95
range is flagged for human review.

**Impact**: Slightly more patterns flagged for review (0.9-0.95 range). Better safety.

### I3: Jaccard on file:line vs file:line:column

**Inconsistency**: DRIFT-V2-SYSTEMS-REFERENCE.md says "Jaccard similarity on location
sets (file:line pairs)" — using file:line, not file:line:column.

**Decision**: Use file:line for Jaccard similarity (not file:line:column). Rationale:
two patterns at the same file:line but different columns are almost certainly the same
logical location (e.g., different detectors matching different parts of the same line).
Using file:line:column would undercount overlap and miss valid duplicates.

**Impact**: Slightly higher Jaccard scores (more overlap detected). This is the
conservative direction — better to flag more duplicates than miss them.

### I4: Cross-Category Duplicate Detection

**Inconsistency**: V1 only compares within same category. But some patterns genuinely
span categories (e.g., a security pattern that's also a data-access pattern).

**Decision**: Cross-category detection is optional (default: off). When enabled, uses
a higher threshold (0.90 vs 0.85) to reduce noise. Cross-category duplicates are
always flagged for review, never auto-merged.

**Impact**: No change to default behavior. Power users can enable cross-category
detection for more thorough deduplication.

### I5: Pattern ID Generation — SHA-256 vs xxhash

**Inconsistency**: V1 uses SHA-256 for pattern IDs (16-char hex). V2 infrastructure
(04-INFRASTRUCTURE-V2-PREP.md) recommends xxhash for non-cryptographic hashing.

**Decision**: Use xxhash128 for pattern ID generation. Pattern IDs are not
security-sensitive — they're identifiers, not integrity checks. xxhash128 provides
128-bit collision resistance (more than sufficient for our scale) at ~10x the speed
of SHA-256.

**Impact**: Pattern IDs change format between v1 and v2. Migration must map old IDs
to new IDs. The 32-char hex representation is preserved for compatibility.

### I6: Location Cap — Unbounded vs Bounded

**Inconsistency**: V1 has no cap on locations per pattern. Very common patterns
(e.g., "camelCase naming") can have 100K+ locations, consuming excessive memory
and making outlier detection slow.

**Decision**: Cap at 10,000 locations per pattern (configurable). When a pattern
exceeds the cap, keep a representative sample: all outlier locations + random
sample of non-outlier locations. This preserves statistical validity while
bounding memory usage.

**Impact**: Very common patterns lose some location data. Statistics remain valid
because the sample is representative. Outlier locations are always preserved.

### I7: Merge Conflict — Different Categories

**Inconsistency**: What happens when two patterns with > 0.95 similarity are in
different categories? (Only possible with cross-category detection enabled.)

**Decision**: Cross-category duplicates are never auto-merged. They are always
flagged for review. The user must decide which category is correct.

**Impact**: No automatic category changes. User retains control over categorization.

---

## 26. Risk Register

| # | Risk | Likelihood | Impact | Mitigation |
|---|------|-----------|--------|-----------|
| R1 | False auto-merge destroys distinct patterns | Low | High | Conservative 0.95 threshold; merge history enables undo |
| R2 | O(n²) Jaccard doesn't scale for enterprise | Medium | Medium | MinHash LSH auto-activates at 50K patterns |
| R3 | Incremental aggregation produces stale results | Medium | Medium | Force full rescan escape hatch; location hash change detection |
| R4 | MinHash approximation misses valid duplicates | Low | Low | Tuned for 99.7% recall at 0.85 threshold; exact verification on candidates |
| R5 | Location cap loses important data | Low | Medium | Outlier locations always preserved; cap is configurable |
| R6 | Pattern ID format change breaks v1 migration | Medium | Medium | Migration script maps old SHA-256 IDs to new xxhash IDs |
| R7 | Metadata union merge creates bloated metadata | Low | Low | Metadata size cap (64KB per pattern); oldest entries evicted |
| R8 | Parallel aggregation introduces race conditions | Low | High | rayon's work-stealing is deterministic; no shared mutable state between categories |
| R9 | Semantic dedup misses duplicates when function/class names differ | Medium | Low | Exact dedup (Phase 3 Strategy 1) catches these; semantic is supplementary |
| R10 | Cross-category detection generates excessive noise | Medium | Medium | Disabled by default; higher threshold (0.90); review-only (no auto-merge) |

---

## Error Handling

```rust
/// Errors that can occur during pattern aggregation.
/// Uses thiserror per 04-INFRASTRUCTURE-V2-PREP.md.
#[derive(Debug, thiserror::Error)]
pub enum AggregationError {
    #[error("Failed to acquire database lock")]
    LockFailed,

    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Invalid pattern ID: {0}")]
    InvalidPatternId(String),

    #[error("Pattern not found: {0}")]
    PatternNotFound(String),

    #[error("Merge conflict: patterns {0} and {1} have incompatible categories")]
    MergeConflict(String, String),

    #[error("Location cap exceeded for pattern {0}: {1} locations (max: {2})")]
    LocationCapExceeded(String, usize, usize),

    #[error("MinHash configuration error: num_perm ({0}) must be divisible by num_bands ({1})")]
    MinHashConfig(usize, usize),
}
```

---

## Cortex Cross-Reference

### Patterns from Cortex That Inform This Design

| Cortex Component | What We Learned | How It's Applied |
|-----------------|----------------|-----------------|
| cortex-consolidation/similarity.rs | Cosine similarity with NOVELTY (0.85) and OVERLAP (0.90) thresholds | Informed our Jaccard thresholds (0.85 flag, 0.95 merge) |
| cortex-consolidation/phase2_clustering.rs | HDBSCAN with 5-signal composite similarity | Informed weighted Jaccard (confidence-weighted locations) |
| cortex-consolidation/phase5_integration.rs | Overlap > 0.9 → UPDATE, else CREATE | Informed auto-merge > 0.95 → merge, else flag |
| cortex-retrieval/deduplication.rs | Session-aware dedup (HashSet, keep highest-scored) | Informed location dedup (keep highest confidence) |
| cortex-core/memory/links.rs | PatternLink (pattern_id, pattern_name) | Informed pattern alias structure |
| cortex-temporal/drift/patterns.rs | Evolution patterns (crystallization, erosion) | Informed event emission for temporal tracking |

### What Drift Aggregation Does NOT Borrow from Cortex

| Cortex Feature | Why Not Used |
|---------------|-------------|
| Embedding-based similarity | Drift patterns are structural, not semantic — Jaccard on locations is more appropriate |
| HDBSCAN clustering | Drift patterns have explicit IDs — clustering is unnecessary when grouping by ID |
| sqlite-vec extension | Drift doesn't use vector embeddings — no need for vector similarity search |
| Cosine similarity | Location sets are discrete (file:line), not continuous vectors |

---

## Summary of All Decisions

| # | Decision | Value | Source |
|---|----------|-------|--------|
| D1 | Duplicate flag threshold | 0.85 | DRIFT-V2-FULL-SYSTEM-AUDIT.md |
| D2 | Auto-merge threshold | 0.95 | Upgraded from 0.9 for safety (§25 I2) |
| D3 | Cross-category threshold | 0.90 | New, higher than within-category |
| D4 | Cross-category default | Disabled | V1 behavior preserved |
| D5 | Jaccard key | file:line (not file:line:column) | DRIFT-V2-SYSTEMS-REFERENCE.md (§25 I3) |
| D6 | Pattern ID hash | xxhash128 | 04-INFRASTRUCTURE-V2-PREP.md |
| D7 | Location cap | 10,000 per pattern | New, prevents unbounded growth |
| D8 | MinHash auto-threshold | 50,000 total patterns | Complexity analysis (§8) |
| D9 | MinHash permutations | 128 | 99.7% recall at 0.85 threshold |
| D10 | MinHash bands | 32 (4 rows/band) | Optimal for 0.85 threshold |
| D11 | Semantic dedup default | Enabled | V1 behavior preserved |
| D12 | Incremental default | Enabled | New, major performance win |
| D13 | Merge conflict resolution | Higher confidence wins | V1 behavior preserved |
| D14 | Cross-category auto-merge | Never (review only) | Safety constraint (§25 I7) |
| D15 | Dedup moved from Audit to Aggregation | Pre-scoring, not post-scoring | Correctness (§25 I1) |
| D16 | Weighted Jaccard | Available, not default | Enhancement for advanced users |
| D17 | Event handler pattern | DriftEventHandler (no-op default) | PLANNING-DRIFT.md D5 |
