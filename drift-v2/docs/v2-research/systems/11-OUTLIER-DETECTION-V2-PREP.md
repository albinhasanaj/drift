# Outlier Detection — V2 Implementation Prep

> Comprehensive build specification for Drift v2's Outlier Detection subsystem.
> Synthesized from: 03-detectors/patterns/outlier-detection.md (v1 feature spec, ~300 LOC),
> 03-detectors/patterns/rules-engine.md (outlier→violation pipeline),
> 03-detectors/detector-contracts.md (OutlierDetector contract),
> 06-DETECTOR-SYSTEM.md §10 (v2 outlier algorithms, OutlierAnalyzer trait),
> 10-BAYESIAN-CONFIDENCE-SCORING-V2-PREP.md (confidence integration),
> .research/03-detectors/RECOMMENDATIONS.md R6 (statistical refinements),
> .research/03-detectors/RESEARCH.md R7 (NIST outlier detection),
> .research/16-gap-analysis/RECAP.md §2.7 (outlier gaps),
> .research/23-pattern-repository/RECAP.md §5 (outlier engine inventory),
> .research/MASTER_RESEARCH.md §8.1 (NIST standards),
> .research/MASTER_RECAP.md §3.3 (v1 outlier summary),
> DRIFT-V2-FULL-SYSTEM-AUDIT.md (AD8, AD9),
> DRIFT-V2-STACK-HIERARCHY.md (Level 2A — Pattern Intelligence),
> PLANNING-DRIFT.md (D1-D7),
> 00-overview/subsystem-connections.md (outlier pipeline position),
> 25-services-layer/scanner-service.md §6 (scan pipeline integration),
> 02-STORAGE-V2-PREP.md (patterns table outlier_count),
> 03-NAPI-BRIDGE-V2-PREP.md (command/query pattern),
> 04-INFRASTRUCTURE-V2-PREP.md (thiserror, tracing, FxHashMap),
> NIST/SEMATECH e-Handbook §1.3.5.17 (Z-Score, Grubbs', Generalized ESD),
> Rosner (1983) Generalized ESD test,
> Grubbs (1969) outlier detection in small samples,
> Modified Z-Score / MAD robust statistics,
> statrs crate (Rust t-distribution, inverse CDF).
>
> Purpose: Everything needed to build the Outlier Detection subsystem from scratch.
> This is the DEDICATED deep-dive — the 06-DETECTOR-SYSTEM doc covers outlier
> detection at summary level (§10); this document is the full implementation spec
> with every algorithm, every type, every edge case, every integration point,
> and every v1 feature accounted for. Zero feature loss.
> Generated: 2026-02-07

---

## Table of Contents

1. Architectural Position
2. V1 Complete Feature Inventory
3. V2 Architecture — Multi-Method Statistical Engine
4. Core Data Model
5. Method 1: Z-Score with Iterative Masking (n ≥ 30)
6. Method 2: Grubbs' Test (10 ≤ n < 30)
7. Method 3: Generalized ESD / Rosner Test (n ≥ 25, multiple outliers)
8. Method 4: IQR with Tukey Fences (supplementary, non-normal data)
9. Method 5: Modified Z-Score / MAD (robust alternative)
10. Method 6: Rule-Based Detection (custom domain rules)
11. Sensitivity System & Threshold Adjustment
12. Significance Classification & Tiers
13. Outlier-to-Violation Pipeline
14. Integration with Confidence Scoring
15. Integration with Pattern Aggregation
16. Integration with Rules Engine & Quality Gates
17. Storage Schema
18. NAPI Interface
19. Event Interface
20. Tracing & Observability
21. T-Distribution Critical Value Computation
22. Performance Targets & Benchmarks
23. Build Order & Dependencies
24. V1 → V2 Feature Cross-Reference
25. Inconsistencies & Decisions
26. Risk Register

---

## 1. Architectural Position

Outlier Detection is Level 2A — Pattern Intelligence in the Drift v2 hierarchy.
It sits directly above the detection layer (Level 1) and feeds into the enforcement
layer (Level 3). It is the statistical backbone that transforms raw pattern locations
into actionable violations — without it, Drift knows conventions but cannot flag
deviations.

Per PLANNING-DRIFT.md D1: Drift is standalone. Outlier results write to drift.db.
Per AD8: Bayesian confidence with momentum — outlier detection consumes confidence data.
Per AD9: Feedback loop — outlier false-positive rates feed detector health.
Per DRIFT-V2-STACK-HIERARCHY.md: Outlier Detection sits between Bayesian Confidence
Scoring and Pattern Aggregation in the intelligence pipeline.

### What Lives Here
- 6 statistical detection methods (Z-Score, Grubbs', Generalized ESD, IQR, Modified Z-Score/MAD, Rule-Based)
- Method selection engine (sample-size-aware automatic dispatch)
- Iterative masking for Z-Score (3-iteration cap, addresses masking effects)
- Sensitivity adjustment system (0.0-1.0 scale, threshold modulation)
- Significance classification (4 tiers: Critical, High, Moderate, Low)
- Deviation scoring (normalized 0.0-1.0 severity)
- Outlier-to-violation conversion pipeline
- T-distribution critical value computation (for Grubbs' and Generalized ESD)
- Per-pattern outlier statistics (mean, stddev, quartiles, sample size)
- Outlier configuration (per-project, per-category overrides)
- Rule-based detection with custom rule registry

### What Does NOT Live Here
- Confidence scoring (Bayesian posterior) → Bayesian Confidence Scoring (Level 2A, separate)
- Pattern aggregation & deduplication → Pattern Aggregation (Level 2A, separate)
- Convention learning (ValueDistribution) → Learning System (Level 2A, separate)
- Violation generation (severity, quick fixes) → Rules Engine (Level 3)
- Quality gates (pass/fail thresholds) → Enforcement (Level 3)
- Detector trait system → Detector System (Level 1)
- Pattern matching (AST, regex, structural) → Pattern Matcher (Level 1)
- MCP tool routing → Presentation (Level 5)

### Downstream Consumers

| Consumer | What It Reads | Interface |
|----------|--------------|-----------|
| Rules Engine | OutlierResult[] per pattern → generates Violation[] | Vec<OutlierResult> |
| Quality Gates | outlier_count, outlier_rate per pattern | drift.db patterns table |
| Audit Engine | outlier_ratio for auto-approve decisions | drift.db patterns table |
| MCP Tools | Outlier summaries, per-file outlier details | NAPI query functions |
| CLI | Outlier reports, pattern health | NAPI query functions |
| IDE/LSP | Per-file outlier annotations | NAPI query_outliers(file) |
| Feedback Loop | Outlier false-positive rate per detector | drift.db detector_health |
| DNA System | Outlier distribution as fingerprint signal | OutlierStats |
| Confidence Scoring | Outlier rate feeds confidence adjustment | outlier_rate field |
| Context Generation | Outlier summaries for AI context | OutlierSummary |

### Upstream Dependencies

| Dependency | What It Provides | Contract |
|-----------|-----------------|----------|
| Pattern Aggregation | AggregatedPattern with location[] and confidence[] | Vec<AggregatedPattern> |
| Confidence Scoring | Per-location confidence values (the numeric data for outlier analysis) | Vec<f64> |
| Detector System | PatternMatch[] per file per detector | Vec<PatternMatch> |
| Storage | Read/write drift.db (patterns, pattern_locations) | DatabaseManager |
| Configuration | OutlierConfig (thresholds, sensitivity, method overrides) | drift.toml |

---

## 2. V1 Complete Feature Inventory

Every feature in the v1 Outlier Detection system, catalogued for zero-loss verification.

### 2.1 V1 Files

```
packages/core/src/matcher/
├── outlier-detector.ts    # OutlierDetector class (~300 LOC)
├── types.ts               # OutlierInfo, OutlierStatistics, OutlierDetectionResult,
│                          # OutlierType, OutlierSignificance, OutlierDetectorConfig,
│                          # OutlierRule, OutlierContext
└── index.ts               # Re-exports
```

### 2.2 Feature Matrix — Every Capability

| # | Feature | V1 Status | V2 Status | V2 Location |
|---|---------|-----------|-----------|-------------|
| F1 | Z-Score detection (n ≥ 30) | ✅ | UPGRADED | z_score.rs |
| F2 | IQR detection (n < 30) | ✅ | PRESERVED + supplementary role | iqr.rs |
| F3 | Rule-based detection | ✅ | PRESERVED | rules.rs |
| F4 | Sensitivity adjustment (0.0-1.0) | ✅ | PRESERVED | config.rs |
| F5 | Significance classification (high/medium/low) | ✅ | UPGRADED → 4 tiers | types.rs |
| F6 | Deviation score (0.0-1.0 normalized) | ✅ | PRESERVED | types.rs |
| F7 | OutlierInfo output type | ✅ | PRESERVED + enhanced | types.rs |
| F8 | OutlierType enum (7 variants) | ✅ | PRESERVED | types.rs |
| F9 | OutlierDetectionResult aggregate | ✅ | PRESERVED + enhanced | types.rs |
| F10 | OutlierStatistics per-outlier | ✅ | PRESERVED + enhanced | types.rs |
| F11 | OutlierDetectorConfig | ✅ | UPGRADED → OutlierConfig | config.rs |
| F12 | Custom rule registration/unregistration | ✅ | PRESERVED | rules.rs |
| F13 | detectOutliers() convenience function | ✅ | PRESERVED | mod.rs |
| F14 | calculateStatistics() helper | ✅ | PRESERVED | stats.rs |
| F15 | Method selection by sample size | ✅ | UPGRADED → 6 methods | engine.rs |
| F16 | Outlier reason strings | ✅ | PRESERVED | types.rs |
| F17 | Expected/actual value reporting | ✅ | PRESERVED | types.rs |
| F18 | Suggested fix per outlier | ✅ | PRESERVED | types.rs |
| F19 | Outlier rate calculation | ✅ | PRESERVED | types.rs |
| F20 | DataPoint conversion from PatternMatchResult | ✅ | PRESERVED | conversion.rs |
| F21 | Outlier context (surrounding code info) | ✅ | PRESERVED | types.rs |
| F22 | Merge statistical + rule-based results | ✅ | PRESERVED | engine.rs |
| F23 | Deduplication of merged results | ✅ | PRESERVED | engine.rs |
| F24 | Grubbs' test (10 ≤ n < 30) | ❌ NEW | NEW | grubbs.rs |
| F25 | Generalized ESD / Rosner test (n ≥ 25) | ❌ NEW | NEW | esd.rs |
| F26 | Modified Z-Score / MAD (robust) | ❌ NEW | NEW | mad.rs |
| F27 | Iterative masking (3-iteration cap) | ❌ NEW | NEW | z_score.rs |
| F28 | T-distribution critical value computation | ❌ NEW | NEW | t_dist.rs |
| F29 | 4-tier significance (Critical/High/Moderate/Low) | ❌ NEW | NEW | types.rs |
| F30 | Per-category outlier config overrides | ❌ NEW | NEW | config.rs |
| F31 | Outlier false-positive rate tracking | ❌ NEW | NEW | health.rs |
| F32 | Parallel outlier detection across patterns | ❌ NEW | NEW | engine.rs |

### 2.3 V1 Known Gaps (from .research/16-gap-analysis/RECAP.md §2.7)

| Gap | Description | V2 Resolution |
|-----|-------------|---------------|
| G1 | Z-Score threshold too low (|z| > 2.0 flags ~4.6%) | Raised to |z| > 2.5 (~1.2%) |
| G2 | Min sample size too low (n=3) | Raised to n=10 |
| G3 | No Grubbs' test for small samples | Added: Grubbs' for 10 ≤ n < 30 |
| G4 | No iterative detection (masking effects) | Added: 3-iteration cap |
| G5 | No Modified Z-Score for non-normal data | Added: MAD-based robust method |
| G6 | No Generalized ESD for multiple outliers | Added: Rosner (1983) test |
| G7 | Only 3 significance levels | Expanded to 4 tiers |
| G8 | No false-positive tracking for outliers | Added: per-detector FP rate |

---

## 3. V2 Architecture — Multi-Method Statistical Engine

### The Key Insight: Method Selection by Sample Size AND Distribution

V1 uses a simple binary dispatch: n ≥ 30 → Z-Score, n < 30 → IQR.
V2 uses a graduated multi-method approach that considers sample size,
distribution shape, and the number of suspected outliers.

### V2 Architecture

```
                    OutlierEngine
                    ┌─────────────────────────────────────────────┐
                    │                                             │
  AggregatedPattern ►  MethodSelector                             │
  (with locations)  │  ├── n < 10 → NoOp (insufficient data)     │
                    │  ├── 10 ≤ n < 25 → Grubbs' (single outlier)│
                    │  ├── 25 ≤ n < 30 → Generalized ESD (multi) │
                    │  ├── n ≥ 30 → Z-Score iterative (primary)   │
                    │  │            + IQR (supplementary cross-check)│
                    │  └── Any n ≥ 10 → Modified Z-Score/MAD      │
                    │                    (if non-normal detected)  │
                    │       │                                      │
                    │       ├── StatisticalResult[] ───────────────┤
                    │       │                                      │
                    │  RuleEngine                                   │
                    │  ├── Custom rules per detector                │
                    │  └── Domain-specific checks                   │
                    │       │                                      │
                    │       ├── RuleResult[] ──────────────────────┤
                    │       │                                      │
                    │  ResultMerger                                 │
                    │  ├── Deduplicate by location                  │
                    │  ├── Keep highest significance                │
                    │  └── Compute aggregate stats                  │
                    │       │                                      │
                    │       └── OutlierDetectionResult ────────────┤──► Vec<OutlierResult>
                    └─────────────────────────────────────────────┘
```

### Method Selection Decision Tree

```
detect_outliers(values, config):
  n = values.len()

  if n < config.min_sample_size (default 10):
    return [] // Insufficient data

  // Primary statistical method
  statistical_outliers = match n:
    10..=24 → grubbs_test(values, config.alpha)
    25..=29 → generalized_esd(values, min(3, n/5), config.alpha)
    30..    → z_score_iterative(values, config.z_threshold, config.max_iterations)

  // Supplementary methods (run in parallel, cross-validate)
  if n >= 30:
    iqr_outliers = iqr_detection(values, config.iqr_multiplier)
    // Outliers flagged by BOTH methods get significance boost

  if config.enable_mad && !shapiro_wilk_normal(values):
    mad_outliers = modified_z_score(values, config.mad_threshold)
    // Use MAD results when data is non-normal

  // Rule-based (always runs if rules registered)
  rule_outliers = rule_engine.evaluate(matches, config.rules)

  // Merge all results
  merge_and_deduplicate(statistical_outliers, iqr_outliers, mad_outliers, rule_outliers)
```

### Why 6 Methods Instead of 2

| Method | When | Why |
|--------|------|-----|
| Z-Score (iterative) | n ≥ 30 | Standard for large samples. Iterative masking prevents one extreme outlier from hiding others. |
| Grubbs' | 10 ≤ n < 25 | Designed for small samples. Accounts for sample size in critical value via t-distribution. |
| Generalized ESD | 25 ≤ n < 30 | Handles multiple outliers without specifying exact count. Rosner (1983) — NIST recommended. |
| IQR | n ≥ 30 (supplementary) | Resistant to extreme outliers that inflate stddev. Cross-validates Z-Score results. |
| Modified Z-Score/MAD | Non-normal data | Uses median instead of mean, MAD instead of stddev. Robust when normality assumption fails. |
| Rule-Based | Always (if rules exist) | Domain-specific checks that statistics can't capture (e.g., "security patterns must not be outliers"). |

---

## 4. Core Data Model

### 4.1 OutlierResult — The Primary Output

```rust
/// Result of outlier analysis for a single data point.
/// Every outlier detection method produces these.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutlierResult {
    /// Index into the original values array
    pub index: usize,

    /// The actual value that was flagged
    pub value: f64,

    /// Z-score or equivalent test statistic
    /// - Z-Score method: actual z-score
    /// - Grubbs': Grubbs' G statistic
    /// - Generalized ESD: Ri test statistic
    /// - IQR: normalized distance from fence (distance / IQR)
    /// - Modified Z-Score: modified z-score (using MAD)
    /// - Rule-based: 0.0 (not applicable)
    pub test_statistic: f64,

    /// Which method detected this outlier
    pub method: OutlierMethod,

    /// Significance tier
    pub significance: Significance,

    /// Normalized deviation score [0.0, 1.0]
    /// How far beyond the threshold — higher = more extreme
    pub deviation_score: f64,

    /// Which iteration detected this (for iterative methods)
    /// 0 = first pass, 1 = second pass after removal, etc.
    pub iteration: u8,

    /// Human-readable reason
    pub reason: OutlierReason,

    /// Direction of deviation
    pub direction: OutlierDirection,
}

/// Detection method used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OutlierMethod {
    ZScore,
    Grubbs,
    GeneralizedEsd,
    Iqr,
    ModifiedZScore,
    RuleBased,
}

/// Significance tiers — revised from v1's 3 levels to 4.
/// Based on NIST recommendations and .research/03-detectors/RECOMMENDATIONS.md R6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Significance {
    /// |z| > 3.5 — Architectural violation, likely intentional deviation or bug
    Critical,
    /// |z| > 3.0 — Strong deviation, worth investigating
    High,
    /// |z| > 2.5 — Mild deviation, informational
    Moderate,
    /// Below threshold but flagged by supplementary method or rule
    Low,
}

/// Direction of the outlier relative to the population.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutlierDirection {
    /// Value is below the population (low confidence, missing pattern)
    Below,
    /// Value is above the population (unusually high, extra pattern)
    Above,
}

/// Structured reason for the outlier flag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutlierReason {
    /// Low confidence relative to population
    LowConfidence { expected_min: f64, actual: f64 },
    /// High confidence relative to population (unusual — investigate)
    HighConfidence { expected_max: f64, actual: f64 },
    /// Below IQR lower fence
    BelowLowerFence { fence: f64, actual: f64 },
    /// Above IQR upper fence
    AboveUpperFence { fence: f64, actual: f64 },
    /// Custom rule triggered
    RuleViolation { rule_id: String, description: String },
    /// Non-normal distribution detected, MAD-based flag
    MadDeviation { median: f64, mad: f64, actual: f64 },
}
```

### 4.2 OutlierType — Semantic Classification

Preserved from v1. Classifies what kind of deviation the outlier represents.

```rust
/// Semantic type of the outlier — what kind of deviation is this?
/// Preserved from v1 (F8). Used by the rules engine to generate
/// appropriate violation messages and quick fixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OutlierType {
    /// File organization, naming convention deviation
    Structural,
    /// Code structure deviation (e.g., missing try-catch)
    Syntactic,
    /// Meaning/behavior deviation (e.g., different error handling strategy)
    Semantic,
    /// Formatting, style convention deviation
    Stylistic,
    /// Missing expected element (e.g., no auth check)
    Missing,
    /// Extra unexpected element (e.g., redundant validation)
    Extra,
    /// Inconsistent with other occurrences of the same pattern
    Inconsistent,
}
```

### 4.3 OutlierDetectionResult — Aggregate Result

```rust
/// Aggregate result of outlier detection for a single pattern.
/// Contains all detected outliers plus summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutlierDetectionResult {
    /// Pattern ID this analysis was run for
    pub pattern_id: String,

    /// Optional file scope (None = project-wide analysis)
    pub file: Option<String>,

    /// All detected outliers
    pub outliers: Vec<OutlierResult>,

    /// Total data points analyzed
    pub total_analyzed: usize,

    /// Outlier rate: outliers.len() / total_analyzed
    pub outlier_rate: f64,

    /// Primary method used for detection
    pub primary_method: OutlierMethod,

    /// Supplementary methods that ran (for cross-validation)
    pub supplementary_methods: Vec<OutlierMethod>,

    /// Summary statistics of the analyzed population
    pub statistics: PopulationStatistics,

    /// Timestamp of analysis
    pub timestamp: u64,

    /// Duration of analysis in microseconds
    pub duration_us: u64,
}

/// Summary statistics for the analyzed population.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PopulationStatistics {
    pub n: usize,
    pub mean: f64,
    pub median: f64,
    pub std_dev: f64,
    pub mad: f64,           // Median Absolute Deviation
    pub q1: f64,
    pub q3: f64,
    pub iqr: f64,
    pub min: f64,
    pub max: f64,
    pub skewness: f64,      // For normality assessment
    pub kurtosis: f64,      // For normality assessment
}
```

### 4.4 OutlierConfig — Configuration

```rust
/// Configuration for the outlier detection engine.
/// Can be overridden per-project in drift.toml and per-category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutlierConfig {
    /// Minimum data points before any statistical detection runs.
    /// V1: 3 (too low). V2: 10 (per NIST recommendation).
    pub min_sample_size: usize,

    /// Z-Score threshold for flagging outliers.
    /// V1: 2.0 (flags ~4.6%). V2: 2.5 (flags ~1.2%).
    /// NIST recommends 3.0 for general use; 2.5 balances
    /// sensitivity with precision for code pattern analysis.
    pub z_threshold: f64,

    /// IQR fence multiplier. 1.5 is the standard Tukey fence.
    /// 3.0 would be the "far outlier" fence.
    pub iqr_multiplier: f64,

    /// Significance level for Grubbs' and Generalized ESD tests.
    /// 0.05 = 95% confidence. Lower = fewer false positives.
    pub alpha: f64,

    /// Maximum iterations for iterative Z-Score masking.
    /// 3 prevents over-removal while addressing masking effects.
    pub max_iterations: usize,

    /// Sensitivity adjustment (0.0 = most lenient, 1.0 = strictest).
    /// Modulates all thresholds: adjusted = base × (1 + (1 - sensitivity))
    /// V1 default: 0.7. V2 default: 0.7 (preserved).
    pub sensitivity: f64,

    /// Whether to enable statistical methods.
    pub enable_statistical: bool,

    /// Whether to enable rule-based detection.
    pub enable_rule_based: bool,

    /// Whether to enable Modified Z-Score/MAD for non-normal data.
    pub enable_mad: bool,

    /// Modified Z-Score threshold (using MAD).
    /// Standard threshold is 3.5 (Iglewicz & Hoaglin, 1993).
    pub mad_threshold: f64,

    /// Maximum suspected outliers for Generalized ESD test.
    /// Default: min(10, n/5). Rosner recommends upper bound approach.
    pub max_esd_outliers: Option<usize>,

    /// Whether to run IQR as supplementary cross-validation for n ≥ 30.
    pub enable_iqr_crosscheck: bool,

    /// Per-category overrides. Key = pattern category (e.g., "security").
    /// Security patterns might use stricter thresholds.
    pub category_overrides: FxHashMap<String, OutlierCategoryConfig>,
}

/// Per-category configuration overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutlierCategoryConfig {
    pub z_threshold: Option<f64>,
    pub sensitivity: Option<f64>,
    pub min_sample_size: Option<usize>,
    pub alpha: Option<f64>,
}

impl Default for OutlierConfig {
    fn default() -> Self {
        Self {
            min_sample_size: 10,
            z_threshold: 2.5,
            iqr_multiplier: 1.5,
            alpha: 0.05,
            max_iterations: 3,
            sensitivity: 0.7,
            enable_statistical: true,
            enable_rule_based: true,
            enable_mad: true,
            mad_threshold: 3.5,
            max_esd_outliers: None,
            enable_iqr_crosscheck: true,
            category_overrides: FxHashMap::default(),
        }
    }
}
```

### 4.5 OutlierRule — Custom Rule Definition

```rust
/// A custom rule for domain-specific outlier detection.
/// Preserved from v1 (F3, F12). Rules run alongside statistical methods.
pub struct OutlierRule {
    /// Unique rule identifier
    pub id: String,

    /// Human-readable name
    pub name: String,

    /// Description of what this rule checks
    pub description: String,

    /// The check function — returns true if the match is an outlier
    pub check: Box<dyn Fn(&PatternMatchContext) -> bool + Send + Sync>,

    /// Reason string when rule triggers
    pub reason: String,

    /// Significance level for rule-triggered outliers
    pub significance: Significance,

    /// Outlier type classification
    pub outlier_type: OutlierType,
}

/// Context provided to rule check functions.
pub struct PatternMatchContext {
    pub match_result: PatternMatch,
    pub population_stats: PopulationStatistics,
    pub pattern_category: String,
    pub file_path: String,
}
```

---

## 5. Method 1: Z-Score with Iterative Masking (n ≥ 30)

The primary detection method for large samples. V2 adds iterative masking
to address the masking effect where one extreme outlier inflates the standard
deviation, hiding other outliers.

### Algorithm

```rust
/// Z-Score outlier detection with iterative masking.
///
/// Per NIST/SEMATECH e-Handbook §1.3.5.17:
/// Z-score assumes approximately normal distribution, which requires
/// n ≥ 30 for the Central Limit Theorem to apply.
///
/// V1 used |z| > 2.0 (flags ~4.6% of normal data — too aggressive).
/// V2 uses |z| > 2.5 (flags ~1.2% — balances sensitivity with precision).
///
/// Iterative masking (new in V2):
/// 1. Compute z-scores for all values
/// 2. Flag outliers (|z| > threshold)
/// 3. Remove flagged outliers from dataset
/// 4. Recompute mean/stddev on remaining data
/// 5. Re-check for newly exposed outliers
/// 6. Repeat until no new outliers found or max_iterations reached
///
/// The 3-iteration cap prevents over-removal. Per .research/03-detectors/
/// RECOMMENDATIONS.md R6: "Cap iterations at 3 to prevent over-removal."
pub fn z_score_iterative(
    values: &[f64],
    threshold: f64,
    sensitivity: f64,
    max_iterations: usize,
) -> Vec<OutlierResult> {
    let adjusted_threshold = threshold * (1.0 + (1.0 - sensitivity));
    let mut outliers = Vec::new();
    let mut remaining: Vec<(usize, f64)> = values.iter().copied().enumerate().collect();

    for iteration in 0..max_iterations {
        if remaining.len() < 3 {
            break; // Need at least 3 points for meaningful statistics
        }

        let vals: Vec<f64> = remaining.iter().map(|(_, v)| *v).collect();
        let n = vals.len() as f64;
        let mean = vals.iter().sum::<f64>() / n;
        let std_dev = (vals.iter()
            .map(|v| (v - mean).powi(2))
            .sum::<f64>() / (n - 1.0))
            .sqrt();

        if std_dev < f64::EPSILON {
            break; // All remaining values identical — no outliers possible
        }

        let mut found_new = false;
        remaining.retain(|(idx, v)| {
            let z = (v - mean) / std_dev;
            if z.abs() > adjusted_threshold {
                outliers.push(OutlierResult {
                    index: *idx,
                    value: *v,
                    test_statistic: z,
                    method: OutlierMethod::ZScore,
                    significance: classify_z_significance(z.abs()),
                    deviation_score: compute_deviation_score(z.abs(), adjusted_threshold),
                    iteration: iteration as u8,
                    reason: if z < 0.0 {
                        OutlierReason::LowConfidence {
                            expected_min: mean - adjusted_threshold * std_dev,
                            actual: *v,
                        }
                    } else {
                        OutlierReason::HighConfidence {
                            expected_max: mean + adjusted_threshold * std_dev,
                            actual: *v,
                        }
                    },
                    direction: if z < 0.0 {
                        OutlierDirection::Below
                    } else {
                        OutlierDirection::Above
                    },
                });
                found_new = true;
                false // Remove from remaining
            } else {
                true // Keep
            }
        });

        if !found_new {
            break; // No new outliers found — converged
        }
    }

    outliers
}

/// Classify significance by |z| magnitude.
/// Revised from v1's 3 levels to 4 per RECOMMENDATIONS.md R6.
fn classify_z_significance(z_abs: f64) -> Significance {
    if z_abs > 3.5 {
        Significance::Critical
    } else if z_abs > 3.0 {
        Significance::High
    } else if z_abs > 2.5 {
        Significance::Moderate
    } else {
        Significance::Low
    }
}

/// Normalized deviation score [0.0, 1.0].
/// Preserved from v1 (F6): how far beyond the threshold.
/// deviationScore = min(1.0, (|z| - threshold) / threshold)
fn compute_deviation_score(z_abs: f64, threshold: f64) -> f64 {
    ((z_abs - threshold) / threshold).min(1.0).max(0.0)
}
```

### Statistical Properties

| Property | Value |
|----------|-------|
| Assumption | Approximately normal distribution |
| Minimum n | 30 (Central Limit Theorem) |
| V1 threshold | \|z\| > 2.0 (flags ~4.6%) |
| V2 threshold | \|z\| > 2.5 (flags ~1.2%) |
| NIST standard | \|z\| > 3.0 (flags ~0.3%) |
| Iterative cap | 3 iterations |
| Sensitivity range | 0.0 (lenient, threshold ×2.0) to 1.0 (strict, threshold ×1.0) |

---

## 6. Method 2: Grubbs' Test (10 ≤ n < 30)

New in V2. Specifically designed for small-sample outlier detection.
Grubbs' test (1969) accounts for sample size in the critical value
calculation via the t-distribution, unlike raw Z-Score which uses
a fixed threshold regardless of n.

### Algorithm

```rust
/// Grubbs' test for outlier detection in small samples.
///
/// Per Grubbs (1969) and NIST/SEMATECH e-Handbook §1.3.5.17.1:
/// The test statistic G is the maximum absolute deviation from the
/// sample mean divided by the sample standard deviation.
///
/// G = max|xi - x̄| / s
///
/// The critical value depends on sample size n and significance level α:
/// G_crit = ((n-1) / √n) × √(t²_{α/(2n), n-2} / (n - 2 + t²_{α/(2n), n-2}))
///
/// where t_{p,ν} is the critical value of the t-distribution with ν
/// degrees of freedom at probability p.
///
/// Reject H0 (no outlier) if G > G_crit.
///
/// Limitation: Grubbs' test detects ONE outlier at a time. For multiple
/// outliers in small samples, use iterative application (remove outlier,
/// retest) or switch to Generalized ESD when n ≥ 25.
pub fn grubbs_test(
    values: &[f64],
    alpha: f64,
    sensitivity: f64,
) -> Vec<OutlierResult> {
    let mut outliers = Vec::new();
    let mut remaining: Vec<(usize, f64)> = values.iter().copied().enumerate().collect();
    let max_removals = 3; // Cap iterative Grubbs' applications

    for iteration in 0..max_removals {
        let n = remaining.len();
        if n < 3 {
            break; // Grubbs' requires at least 3 data points
        }

        let vals: Vec<f64> = remaining.iter().map(|(_, v)| *v).collect();
        let n_f = n as f64;
        let mean = vals.iter().sum::<f64>() / n_f;
        let std_dev = (vals.iter()
            .map(|v| (v - mean).powi(2))
            .sum::<f64>() / (n_f - 1.0))
            .sqrt();

        if std_dev < f64::EPSILON {
            break;
        }

        // Find the value with maximum |deviation| from mean
        let (max_idx_in_remaining, max_g) = remaining.iter()
            .enumerate()
            .map(|(ri, (_, v))| (ri, ((v - mean) / std_dev).abs()))
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
            .unwrap();

        // Compute Grubbs' critical value
        let adjusted_alpha = alpha * (1.0 + (1.0 - sensitivity));
        let t_crit = t_critical(adjusted_alpha / (2.0 * n_f), (n - 2) as u32);
        let g_crit = ((n_f - 1.0) / n_f.sqrt())
            * (t_crit.powi(2) / (n_f - 2.0 + t_crit.powi(2))).sqrt();

        if max_g > g_crit {
            let (original_idx, value) = remaining[max_idx_in_remaining];
            let z = (value - mean) / std_dev;

            outliers.push(OutlierResult {
                index: original_idx,
                value,
                test_statistic: max_g,
                method: OutlierMethod::Grubbs,
                significance: classify_z_significance(max_g),
                deviation_score: compute_deviation_score(max_g, g_crit),
                iteration: iteration as u8,
                reason: if z < 0.0 {
                    OutlierReason::LowConfidence {
                        expected_min: mean - g_crit * std_dev,
                        actual: value,
                    }
                } else {
                    OutlierReason::HighConfidence {
                        expected_max: mean + g_crit * std_dev,
                        actual: value,
                    }
                },
                direction: if z < 0.0 {
                    OutlierDirection::Below
                } else {
                    OutlierDirection::Above
                },
            });

            remaining.remove(max_idx_in_remaining);
        } else {
            break; // No more outliers detected
        }
    }

    outliers
}
```

### Statistical Properties

| Property | Value |
|----------|-------|
| Assumption | Approximately normal distribution |
| Minimum n | 10 (practical minimum for meaningful results) |
| Maximum n | 29 (switch to Z-Score at 30) |
| Detects | One outlier per iteration |
| Critical value | Depends on n and α via t-distribution |
| Default α | 0.05 (95% confidence) |
| Iterative cap | 3 removals (same as Z-Score) |

### Why Grubbs' Over Raw Z-Score for Small Samples

For n=15 with α=0.05, the Grubbs' critical value is approximately G=2.41.
A raw Z-Score threshold of 2.5 would be too strict (miss real outliers),
while 2.0 would be too lenient (flag too many). Grubbs' automatically
adjusts the threshold based on sample size — this is why NIST recommends
it for small samples.

---

## 7. Method 3: Generalized ESD / Rosner Test (n ≥ 25, multiple outliers)

New in V2. The Generalized Extreme Studentized Deviate (ESD) test,
published by Rosner (1983), is the NIST-recommended method for detecting
multiple outliers when the exact number is unknown. It only requires an
upper bound on the number of suspected outliers.

### Why Generalized ESD Over Sequential Grubbs'

Per NIST/SEMATECH e-Handbook §1.3.5.17.3:
"The primary limitation of the Grubbs test is that the suspected number
of outliers must be specified exactly. If k is not specified correctly,
this can distort the conclusions. The generalized ESD test only requires
that an upper bound for the suspected number of outliers be specified."

Sequential application of Grubbs' test can fail due to masking — if two
outliers are present, the first Grubbs' test may not detect either one
because both inflate the standard deviation. The Generalized ESD test
makes appropriate adjustments for critical values that sequential Grubbs'
does not.

### Algorithm

```rust
/// Generalized ESD test (Rosner, 1983) for multiple outlier detection.
///
/// Per NIST/SEMATECH e-Handbook §1.3.5.17.3:
/// Given upper bound r for suspected outliers, performs r separate tests:
/// a test for 1 outlier, a test for 2 outliers, ..., up to r outliers.
///
/// For each i = 1, 2, ..., r:
///   Ri = max|xi - x̄| / s  (same as Grubbs' statistic)
///   Remove the observation that maximizes |xi - x̄|
///   Recompute on remaining n-i observations
///
/// Critical values:
///   λi = ((n-i) × t_{p, n-i-1}) / √((n-i-1 + t²_{p, n-i-1}) × (n-i+1))
///   where p = 1 - α/(2(n-i+1))
///
/// The number of outliers = largest i such that Ri > λi.
///
/// Rosner's simulation studies show this approximation is very accurate
/// for n ≥ 25 and reasonably accurate for n ≥ 15.
pub fn generalized_esd(
    values: &[f64],
    max_outliers: usize,
    alpha: f64,
    sensitivity: f64,
) -> Vec<OutlierResult> {
    let n = values.len();
    let r = max_outliers.min(n / 3); // Never test more than n/3 outliers

    if r == 0 || n < 10 {
        return vec![];
    }

    // Phase 1: Compute all r test statistics and critical values
    let mut working: Vec<(usize, f64)> = values.iter().copied().enumerate().collect();
    let mut test_stats: Vec<(f64, usize, f64)> = Vec::with_capacity(r); // (Ri, original_idx, value)
    let mut critical_values: Vec<f64> = Vec::with_capacity(r);

    let adjusted_alpha = alpha * (1.0 + (1.0 - sensitivity));

    for i in 0..r {
        let current_n = working.len();
        if current_n < 3 {
            break;
        }

        let vals: Vec<f64> = working.iter().map(|(_, v)| *v).collect();
        let n_f = current_n as f64;
        let mean = vals.iter().sum::<f64>() / n_f;
        let std_dev = (vals.iter()
            .map(|v| (v - mean).powi(2))
            .sum::<f64>() / (n_f - 1.0))
            .sqrt();

        if std_dev < f64::EPSILON {
            break;
        }

        // Find max |xi - x̄| / s
        let (max_working_idx, max_ri) = working.iter()
            .enumerate()
            .map(|(wi, (_, v))| (wi, ((v - mean) / std_dev).abs()))
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
            .unwrap();

        let (original_idx, value) = working[max_working_idx];
        test_stats.push((max_ri, original_idx, value));

        // Compute critical value λi
        let ni = (n - i) as f64;
        let p = 1.0 - adjusted_alpha / (2.0 * (ni + 1.0));
        let df = (n - i - 2) as u32;
        let t_p = t_critical_upper(p, df);
        let lambda_i = ((ni) * t_p)
            / ((ni - 1.0 + t_p.powi(2)) * (ni + 1.0)).sqrt();
        critical_values.push(lambda_i);

        // Remove the max deviation observation
        working.remove(max_working_idx);
    }

    // Phase 2: Find largest i where Ri > λi
    let num_outliers = test_stats.iter()
        .zip(critical_values.iter())
        .enumerate()
        .rev()
        .find(|(_, ((ri, _, _), lambda))| ri > lambda)
        .map(|(i, _)| i + 1)
        .unwrap_or(0);

    // Phase 3: Build results for the first num_outliers entries
    let population_mean = values.iter().sum::<f64>() / values.len() as f64;
    let population_std = (values.iter()
        .map(|v| (v - population_mean).powi(2))
        .sum::<f64>() / (values.len() - 1) as f64)
        .sqrt();

    test_stats.into_iter()
        .take(num_outliers)
        .enumerate()
        .map(|(iteration, (ri, original_idx, value))| {
            let z = if population_std > f64::EPSILON {
                (value - population_mean) / population_std
            } else {
                0.0
            };

            OutlierResult {
                index: original_idx,
                value,
                test_statistic: ri,
                method: OutlierMethod::GeneralizedEsd,
                significance: classify_z_significance(ri),
                deviation_score: compute_deviation_score(
                    ri,
                    critical_values.get(iteration).copied().unwrap_or(2.5),
                ),
                iteration: iteration as u8,
                reason: if z < 0.0 {
                    OutlierReason::LowConfidence {
                        expected_min: population_mean - 2.5 * population_std,
                        actual: value,
                    }
                } else {
                    OutlierReason::HighConfidence {
                        expected_max: population_mean + 2.5 * population_std,
                        actual: value,
                    }
                },
                direction: if z < 0.0 {
                    OutlierDirection::Below
                } else {
                    OutlierDirection::Above
                },
            }
        })
        .collect()
}
```

### Statistical Properties

| Property | Value |
|----------|-------|
| Assumption | Approximately normal distribution |
| Minimum n | 25 (accurate per Rosner), 15 (reasonably accurate) |
| Detects | Multiple outliers simultaneously |
| Upper bound r | User-specified or default min(10, n/5) |
| Critical value | Adjusted per iteration via t-distribution |
| Default α | 0.05 |
| Key advantage | Handles masking that defeats sequential Grubbs' |

---

## 8. Method 4: IQR with Tukey Fences (supplementary, non-normal data)

Preserved from v1 (F2). In V2, IQR shifts from primary small-sample method
to supplementary cross-validation method for large samples. IQR is resistant
to extreme outliers that inflate the standard deviation — making it a valuable
second opinion alongside Z-Score.

### Algorithm

```rust
/// IQR-based outlier detection using Tukey fences.
///
/// The IQR method does not assume normal distribution, making it
/// appropriate for skewed data. The standard 1.5×IQR multiplier
/// defines the "inner fence" (mild outliers). 3.0×IQR defines
/// the "outer fence" (extreme outliers).
///
/// V1 role: Primary method for n < 30.
/// V2 role: Supplementary cross-validation for n ≥ 30.
///          For n < 30, Grubbs' or Generalized ESD are preferred.
pub fn iqr_detection(
    values: &[f64],
    multiplier: f64,
    sensitivity: f64,
) -> Vec<OutlierResult> {
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let q1 = percentile(&sorted, 25.0);
    let q3 = percentile(&sorted, 75.0);
    let iqr = q3 - q1;

    if iqr < f64::EPSILON {
        return vec![]; // All values in the same quartile range
    }

    let adjusted_multiplier = multiplier * (1.0 + (1.0 - sensitivity));
    let lower_fence = q1 - adjusted_multiplier * iqr;
    let upper_fence = q3 + adjusted_multiplier * iqr;

    // Outer fences for significance classification
    let lower_outer = q1 - (adjusted_multiplier * 2.0) * iqr;
    let upper_outer = q3 + (adjusted_multiplier * 2.0) * iqr;

    values.iter().enumerate()
        .filter_map(|(i, v)| {
            if *v < lower_fence {
                let distance = (lower_fence - v) / iqr;
                Some(OutlierResult {
                    index: i,
                    value: *v,
                    test_statistic: distance,
                    method: OutlierMethod::Iqr,
                    significance: if *v < lower_outer {
                        Significance::High
                    } else {
                        Significance::Moderate
                    },
                    deviation_score: (distance / 3.0).min(1.0),
                    iteration: 0,
                    reason: OutlierReason::BelowLowerFence {
                        fence: lower_fence,
                        actual: *v,
                    },
                    direction: OutlierDirection::Below,
                })
            } else if *v > upper_fence {
                let distance = (v - upper_fence) / iqr;
                Some(OutlierResult {
                    index: i,
                    value: *v,
                    test_statistic: distance,
                    method: OutlierMethod::Iqr,
                    significance: if *v > upper_outer {
                        Significance::High
                    } else {
                        Significance::Moderate
                    },
                    deviation_score: (distance / 3.0).min(1.0),
                    iteration: 0,
                    reason: OutlierReason::AboveUpperFence {
                        fence: upper_fence,
                        actual: *v,
                    },
                    direction: OutlierDirection::Above,
                })
            } else {
                None
            }
        })
        .collect()
}

/// Linear interpolation percentile calculation.
fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let k = (p / 100.0) * (sorted.len() - 1) as f64;
    let f = k.floor() as usize;
    let c = k.ceil() as usize;
    if f == c {
        sorted[f]
    } else {
        sorted[f] * (c as f64 - k) + sorted[c] * (k - f as f64)
    }
}
```

### Cross-Validation with Z-Score

When both Z-Score and IQR run (n ≥ 30), outliers flagged by BOTH methods
receive a significance boost:

```rust
fn cross_validate(
    z_outliers: &[OutlierResult],
    iqr_outliers: &[OutlierResult],
) -> Vec<OutlierResult> {
    let iqr_indices: FxHashSet<usize> = iqr_outliers.iter()
        .map(|o| o.index)
        .collect();

    z_outliers.iter().map(|o| {
        if iqr_indices.contains(&o.index) {
            // Both methods agree — boost significance
            OutlierResult {
                significance: boost_significance(o.significance),
                ..o.clone()
            }
        } else {
            o.clone()
        }
    }).collect()
}

fn boost_significance(s: Significance) -> Significance {
    match s {
        Significance::Low => Significance::Moderate,
        Significance::Moderate => Significance::High,
        Significance::High => Significance::Critical,
        Significance::Critical => Significance::Critical,
    }
}
```

---

## 9. Method 5: Modified Z-Score / MAD (robust alternative)

New in V2. The Modified Z-Score uses the Median Absolute Deviation (MAD)
instead of the standard deviation, and the median instead of the mean.
This makes it robust against the very outliers it's trying to detect —
a fundamental weakness of the standard Z-Score.

### Why MAD?

The standard Z-Score has a circular problem: outliers inflate the standard
deviation, which raises the threshold, which hides the outliers. The MAD
is resistant to this because the median is not affected by extreme values.

Per Iglewicz & Hoaglin (1993), the Modified Z-Score threshold of 3.5 is
recommended for outlier detection. The constant 0.6745 is the 0.75th
quantile of the standard normal distribution, used to make MAD consistent
with the standard deviation for normally distributed data.

### Algorithm

```rust
/// Modified Z-Score using Median Absolute Deviation (MAD).
///
/// Modified Z-Score = 0.6745 × (xi - median) / MAD
///
/// where MAD = median(|xi - median|)
///
/// The constant 0.6745 is the 0.75th quantile of the standard normal
/// distribution. It makes MAD a consistent estimator of the standard
/// deviation when the data is normally distributed.
///
/// Threshold: |Modified Z| > 3.5 (Iglewicz & Hoaglin, 1993)
///
/// Use case: When the data is non-normal (high skewness or kurtosis),
/// or when the standard Z-Score is suspected of masking outliers.
pub fn modified_z_score(
    values: &[f64],
    threshold: f64,
    sensitivity: f64,
) -> Vec<OutlierResult> {
    let n = values.len();
    if n < 3 {
        return vec![];
    }

    // Compute median
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = if n % 2 == 0 {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    } else {
        sorted[n / 2]
    };

    // Compute MAD = median(|xi - median|)
    let mut abs_devs: Vec<f64> = values.iter()
        .map(|v| (v - median).abs())
        .collect();
    abs_devs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mad = if n % 2 == 0 {
        (abs_devs[n / 2 - 1] + abs_devs[n / 2]) / 2.0
    } else {
        abs_devs[n / 2]
    };

    if mad < f64::EPSILON {
        // MAD is zero — more than half the values are identical to the median.
        // Fall back to mean absolute deviation or return empty.
        return vec![];
    }

    let adjusted_threshold = threshold * (1.0 + (1.0 - sensitivity));
    let consistency_constant = 0.6745; // Makes MAD consistent with stddev for normal data

    values.iter().enumerate()
        .filter_map(|(i, v)| {
            let modified_z = consistency_constant * (v - median) / mad;
            if modified_z.abs() > adjusted_threshold {
                Some(OutlierResult {
                    index: i,
                    value: *v,
                    test_statistic: modified_z,
                    method: OutlierMethod::ModifiedZScore,
                    significance: classify_mad_significance(modified_z.abs()),
                    deviation_score: compute_deviation_score(
                        modified_z.abs(),
                        adjusted_threshold,
                    ),
                    iteration: 0,
                    reason: OutlierReason::MadDeviation {
                        median,
                        mad,
                        actual: *v,
                    },
                    direction: if modified_z < 0.0 {
                        OutlierDirection::Below
                    } else {
                        OutlierDirection::Above
                    },
                })
            } else {
                None
            }
        })
        .collect()
}

/// Significance classification for Modified Z-Score.
/// Thresholds are higher than standard Z-Score because MAD
/// is a more conservative estimator.
fn classify_mad_significance(mz_abs: f64) -> Significance {
    if mz_abs > 5.0 {
        Significance::Critical
    } else if mz_abs > 4.0 {
        Significance::High
    } else if mz_abs > 3.5 {
        Significance::Moderate
    } else {
        Significance::Low
    }
}
```

### When to Use MAD vs Standard Z-Score

| Condition | Use |
|-----------|-----|
| Data approximately normal, n ≥ 30 | Standard Z-Score (primary) |
| Data skewed or heavy-tailed | Modified Z-Score/MAD |
| Suspected masking (extreme outlier hiding others) | Modified Z-Score/MAD |
| Both methods available | Run both, cross-validate |

### Normality Assessment

V2 uses a lightweight normality check to decide whether to activate MAD:

```rust
/// Quick normality assessment using skewness and kurtosis.
/// Not a formal test (Shapiro-Wilk is expensive) — just a heuristic.
/// If |skewness| > 2.0 or |kurtosis - 3.0| > 7.0, data is likely non-normal.
fn is_approximately_normal(stats: &PopulationStatistics) -> bool {
    stats.skewness.abs() < 2.0 && (stats.kurtosis - 3.0).abs() < 7.0
}
```

---

## 10. Method 6: Rule-Based Detection (custom domain rules)

Preserved from v1 (F3, F12). Rule-based detection runs alongside statistical
methods and catches domain-specific outliers that statistics cannot.

### Architecture

```rust
/// Rule-based outlier detection engine.
/// Custom rules are registered per detector or globally.
pub struct RuleBasedDetector {
    /// Registered rules, indexed by ID for O(1) lookup
    rules: FxHashMap<String, OutlierRule>,

    /// Rule execution order (rules run in registration order)
    order: Vec<String>,
}

impl RuleBasedDetector {
    pub fn new() -> Self {
        Self {
            rules: FxHashMap::default(),
            order: Vec::new(),
        }
    }

    /// Register a custom rule. Preserved from v1 (F12).
    pub fn register_rule(&mut self, rule: OutlierRule) {
        let id = rule.id.clone();
        self.rules.insert(id.clone(), rule);
        self.order.push(id);
    }

    /// Unregister a rule by ID. Preserved from v1 (F12).
    pub fn unregister_rule(&mut self, rule_id: &str) -> bool {
        if self.rules.remove(rule_id).is_some() {
            self.order.retain(|id| id != rule_id);
            true
        } else {
            false
        }
    }

    /// Run all registered rules against pattern matches.
    pub fn evaluate(
        &self,
        matches: &[PatternMatch],
        population_stats: &PopulationStatistics,
        pattern_category: &str,
    ) -> Vec<OutlierResult> {
        let mut results = Vec::new();

        for (i, m) in matches.iter().enumerate() {
            let ctx = PatternMatchContext {
                match_result: m.clone(),
                population_stats: population_stats.clone(),
                pattern_category: pattern_category.to_string(),
                file_path: m.file.clone(),
            };

            for rule_id in &self.order {
                if let Some(rule) = self.rules.get(rule_id) {
                    if (rule.check)(&ctx) {
                        results.push(OutlierResult {
                            index: i,
                            value: m.confidence,
                            test_statistic: 0.0,
                            method: OutlierMethod::RuleBased,
                            significance: rule.significance,
                            deviation_score: 0.5, // Rules don't have continuous scores
                            iteration: 0,
                            reason: OutlierReason::RuleViolation {
                                rule_id: rule_id.clone(),
                                description: rule.reason.clone(),
                            },
                            direction: OutlierDirection::Below, // Rules typically flag missing/wrong
                        });
                    }
                }
            }
        }

        results
    }
}
```

### Default Rules

V2 ships with these built-in rules (registered automatically):

| Rule ID | Description | Significance |
|---------|-------------|-------------|
| `security-must-not-outlier` | Security patterns with outliers are always flagged | High |
| `auth-consistency` | Auth patterns must be consistent across all entry points | High |
| `error-handling-coverage` | Error handling patterns should cover all try-catch blocks | Moderate |
| `zero-confidence` | Any match with confidence = 0.0 is an outlier | Critical |
| `singleton-pattern` | Pattern with only 1 location is suspicious | Low |

---

## 11. Sensitivity System & Threshold Adjustment

Preserved from v1 (F4). The sensitivity system modulates all statistical
thresholds without changing the core algorithms. This allows per-project
tuning without understanding the underlying statistics.

### Formula

```
adjustedThreshold = baseThreshold × (1 + (1 - sensitivity))
```

| Sensitivity | Multiplier | Effect |
|-------------|-----------|--------|
| 1.0 | ×1.0 | Strictest — base threshold unchanged |
| 0.9 | ×1.1 | Slightly lenient |
| 0.7 | ×1.3 | Default — balanced |
| 0.5 | ×1.5 | Lenient |
| 0.3 | ×1.7 | Very lenient |
| 0.0 | ×2.0 | Most lenient — threshold doubled |

### Per-Method Application

| Method | Base Threshold | At sensitivity=0.7 |
|--------|---------------|-------------------|
| Z-Score | 2.5 | 3.25 |
| Grubbs' α | 0.05 | 0.065 |
| IQR multiplier | 1.5 | 1.95 |
| Modified Z-Score | 3.5 | 4.55 |

### Configuration in drift.toml

```toml
[outlier]
sensitivity = 0.7
min_sample_size = 10
z_threshold = 2.5
iqr_multiplier = 1.5
alpha = 0.05
enable_mad = true
mad_threshold = 3.5
enable_iqr_crosscheck = true

[outlier.category.security]
sensitivity = 0.9    # Stricter for security patterns
z_threshold = 2.0    # Lower threshold — catch more deviations

[outlier.category.styling]
sensitivity = 0.3    # Very lenient for style patterns
```

---

## 12. Significance Classification & Tiers

V2 expands from v1's 3 significance levels to 4 tiers, aligned with
NIST recommendations and the violation severity system.

### Tier Definitions

| Tier | Z-Score Range | IQR Distance | MAD Range | Meaning |
|------|--------------|-------------|-----------|---------|
| Critical | \|z\| > 3.5 | > 3.0×IQR from fence | \|mz\| > 5.0 | Architectural violation — likely intentional deviation or bug |
| High | \|z\| > 3.0 | > 2.0×IQR from fence | \|mz\| > 4.0 | Strong deviation — worth investigating |
| Moderate | \|z\| > 2.5 | > 1.0×IQR from fence | \|mz\| > 3.5 | Mild deviation — informational |
| Low | Below threshold | At fence boundary | Below threshold | Flagged by supplementary method or cross-validation only |

### Mapping to Violation Severity

| Significance | Default Violation Severity | Can Escalate To |
|-------------|--------------------------|----------------|
| Critical | error | — (already max) |
| High | warning | error (if security category) |
| Moderate | info | warning (if approved pattern) |
| Low | hint | info (if high-confidence pattern) |

### Cross-Validation Significance Boost

When multiple methods agree on an outlier, significance is boosted:

| Agreement | Boost |
|-----------|-------|
| Z-Score only | No boost |
| Z-Score + IQR | +1 tier |
| Z-Score + IQR + MAD | +2 tiers (cap at Critical) |
| Any statistical + Rule-Based | +1 tier |

---

## 13. Outlier-to-Violation Pipeline

This is the critical integration point between outlier detection and the
rules engine. Outliers become violations — the actionable feedback that
developers see in their IDE, CLI, and CI.

### Pipeline

```
AggregatedPattern
  │
  ├── Extract confidence values → Vec<f64>
  │
  ├── Run OutlierEngine.detect() → OutlierDetectionResult
  │
  ├── For each OutlierResult:
  │     │
  │     ├── Map to PatternLocation (find the source location)
  │     │
  │     ├── Determine OutlierType (structural/syntactic/semantic/etc.)
  │     │
  │     ├── Map Significance → Violation Severity
  │     │
  │     ├── Generate violation message:
  │     │   "Inconsistent {pattern_name}: {actual} but project uses {expected}"
  │     │
  │     ├── Generate quick fix suggestion (if applicable)
  │     │
  │     └── Create Violation {
  │           pattern_id, severity, file, range,
  │           message, expected, actual, explanation,
  │           quick_fixes, outlier_info
  │         }
  │
  └── Return Vec<Violation>
```

### Violation Message Templates

```rust
fn generate_violation_message(
    pattern: &Pattern,
    outlier: &OutlierResult,
    population: &PopulationStatistics,
) -> String {
    match &outlier.reason {
        OutlierReason::LowConfidence { expected_min, actual } => {
            format!(
                "Inconsistent {}: confidence {:.2} is below expected minimum {:.2} \
                 (population mean: {:.2}, stddev: {:.2})",
                pattern.name, actual, expected_min,
                population.mean, population.std_dev,
            )
        }
        OutlierReason::HighConfidence { expected_max, actual } => {
            format!(
                "Unusual {}: confidence {:.2} is above expected maximum {:.2} \
                 — investigate if this is intentional",
                pattern.name, actual, expected_max,
            )
        }
        OutlierReason::BelowLowerFence { fence, actual } => {
            format!(
                "Outlier {}: value {:.2} is below the statistical lower bound {:.2}",
                pattern.name, actual, fence,
            )
        }
        OutlierReason::AboveUpperFence { fence, actual } => {
            format!(
                "Outlier {}: value {:.2} is above the statistical upper bound {:.2}",
                pattern.name, actual, fence,
            )
        }
        OutlierReason::RuleViolation { description, .. } => {
            format!("{}: {}", pattern.name, description)
        }
        OutlierReason::MadDeviation { median, mad, actual } => {
            format!(
                "Robust outlier {}: value {:.2} deviates significantly from \
                 median {:.2} (MAD: {:.2})",
                pattern.name, actual, median, mad,
            )
        }
    }
}
```

### OutlierType Determination

```rust
/// Determine the semantic type of an outlier based on the pattern
/// category and the direction of deviation.
/// Preserved from v1 (F8) with enhanced logic.
fn determine_outlier_type(
    pattern: &Pattern,
    outlier: &OutlierResult,
) -> OutlierType {
    match (pattern.category.as_str(), &outlier.direction) {
        ("structural", _) => OutlierType::Structural,
        ("styling", _) => OutlierType::Stylistic,
        ("security" | "auth", OutlierDirection::Below) => OutlierType::Missing,
        ("errors", OutlierDirection::Below) => OutlierType::Missing,
        (_, OutlierDirection::Below) => OutlierType::Inconsistent,
        (_, OutlierDirection::Above) => OutlierType::Extra,
    }
}
```

---

## 14. Integration with Confidence Scoring

Outlier detection and confidence scoring are tightly coupled. Confidence
scoring produces the numeric values that outlier detection analyzes, and
outlier results feed back into confidence adjustments.

### Data Flow

```
Confidence Scoring → per-location confidence values (Vec<f64>)
                   → Outlier Detection analyzes these values
                   → OutlierDetectionResult with outlier_rate

Outlier Detection → outlier_rate feeds back into pattern health
                  → High outlier_rate (>0.50) prevents auto-approve
                  → outlier_count stored in patterns table
```

### Confidence Values as Input

The primary input to outlier detection is the per-location confidence
values from the confidence scoring system:

```rust
/// Extract numeric values for outlier analysis from aggregated pattern.
fn extract_outlier_values(pattern: &AggregatedPattern) -> Vec<f64> {
    pattern.locations.iter()
        .map(|loc| loc.confidence)
        .collect()
}
```

### Outlier Rate as Feedback

```rust
/// Update pattern with outlier analysis results.
fn update_pattern_outlier_data(
    pattern: &mut Pattern,
    result: &OutlierDetectionResult,
) {
    pattern.outlier_count = result.outliers.len() as u32;
    pattern.outlier_rate = result.outlier_rate;

    // Mark individual locations as outliers
    for outlier in &result.outliers {
        if let Some(loc) = pattern.locations.get_mut(outlier.index) {
            loc.is_outlier = true;
            loc.outlier_reason = Some(format!("{:?}", outlier.reason));
            loc.deviation_score = Some(outlier.deviation_score);
        }
    }
}
```

### Auto-Approve Gate

Per .research/23-pattern-repository/RECAP.md §Audit Recommendation Thresholds:
- Auto-approve requires: confidence ≥ 0.90, outlierRatio ≤ 0.50, locations ≥ 3
- If outlier_rate > 0.50, pattern cannot be auto-approved regardless of confidence

---

## 15. Integration with Pattern Aggregation

Outlier detection runs AFTER pattern aggregation. The aggregation step
groups per-file pattern matches into project-level patterns with location
arrays. Outlier detection then analyzes the confidence distribution across
those locations.

### Pipeline Position

```
Per-File Detection (Level 1)
  → Pattern Aggregation (Level 2A) — groups matches, deduplicates
    → Confidence Scoring (Level 2A) — computes per-location confidence
      → OUTLIER DETECTION (Level 2A) — flags statistical deviations
        → Rules Engine (Level 3) — generates violations from outliers
          → Quality Gates (Level 3) — pass/fail based on violation counts
```

### Batch Processing

Outlier detection runs across all aggregated patterns in parallel:

```rust
/// Run outlier detection across all aggregated patterns.
/// Uses rayon for parallel processing — each pattern is independent.
pub fn detect_all_outliers(
    patterns: &[AggregatedPattern],
    config: &OutlierConfig,
    rule_detector: &RuleBasedDetector,
) -> Vec<OutlierDetectionResult> {
    patterns.par_iter()
        .map(|pattern| {
            let values = extract_outlier_values(pattern);
            detect_outliers_for_pattern(
                &pattern.id,
                &values,
                &pattern.matches,
                config,
                rule_detector,
                &pattern.category,
            )
        })
        .collect()
}
```

---

## 16. Integration with Rules Engine & Quality Gates

### Rules Engine Integration

The rules engine (03-detectors/patterns/rules-engine.md) consumes outlier
results to generate violations. The Evaluator's pipeline:

```
evaluate(input, pattern):
  1. checkMatch(input, pattern) → boolean
  2. getMatchDetails(input, pattern) → MatchDetails[]
  3. Run outlier detection on match confidences
  4. Convert outliers to violations (§13 pipeline)
  5. Check for missing patterns
  6. Determine severity (with outlier significance mapping)
  7. Generate quick fixes
  8. Return EvaluationResult
```

### Quality Gate Integration

Quality gates consume outlier metrics from drift.db:

```sql
-- Gate query: pattern compliance rate
SELECT
  COUNT(*) as total_patterns,
  COUNT(*) FILTER (WHERE outlier_rate <= 0.10) as compliant_patterns,
  CAST(COUNT(*) FILTER (WHERE outlier_rate <= 0.10) AS REAL) / COUNT(*) as compliance_rate
FROM patterns
WHERE status = 'approved';
```

### Gate Scoring Impact

Per .research/16-gap-analysis/RECAP.md §2.8:
```
penalty = Σ(error_violations × 10) + Σ(warning_violations × 3) + Σ(info_violations × 1)
```

Outlier-generated violations contribute to this penalty based on their
mapped severity (§12 Significance → Severity mapping).

---

## 17. Storage Schema

Outlier data is stored in drift.db alongside pattern data. No separate
tables needed — outlier information is embedded in the existing pattern
and pattern_locations tables, with a dedicated outlier_history table
for temporal tracking.

### Pattern Table Extensions

```sql
-- Already in patterns table (02-STORAGE-V2-PREP.md):
-- outlier_count INTEGER NOT NULL DEFAULT 0
-- These are additions for v2 outlier tracking:
ALTER TABLE patterns ADD COLUMN outlier_rate REAL DEFAULT 0.0;
ALTER TABLE patterns ADD COLUMN outlier_method TEXT;  -- primary method used
ALTER TABLE patterns ADD COLUMN last_outlier_analysis TEXT;  -- ISO timestamp
```

### Pattern Locations Extensions

```sql
-- Already in pattern_locations table:
-- is_outlier INTEGER DEFAULT 0
-- outlier_reason TEXT
-- These are additions:
ALTER TABLE pattern_locations ADD COLUMN deviation_score REAL;
ALTER TABLE pattern_locations ADD COLUMN outlier_significance TEXT;
ALTER TABLE pattern_locations ADD COLUMN outlier_method TEXT;
ALTER TABLE pattern_locations ADD COLUMN test_statistic REAL;
```

### Outlier History Table (new)

```sql
-- Track outlier analysis results over time for trend detection
CREATE TABLE outlier_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_id TEXT NOT NULL REFERENCES patterns(id),
    scan_id TEXT NOT NULL,
    total_analyzed INTEGER NOT NULL,
    outlier_count INTEGER NOT NULL,
    outlier_rate REAL NOT NULL,
    primary_method TEXT NOT NULL,
    mean REAL,
    std_dev REAL,
    median REAL,
    mad REAL,
    q1 REAL,
    q3 REAL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_outlier_history_pattern ON outlier_history(pattern_id);
CREATE INDEX idx_outlier_history_scan ON outlier_history(scan_id);
CREATE INDEX idx_outlier_history_created ON outlier_history(created_at);
```

### Outlier Trend Query

```sql
-- Detect patterns with increasing outlier rates (degradation)
SELECT
    pattern_id,
    AVG(CASE WHEN created_at > datetime('now', '-7 days') THEN outlier_rate END) as recent_rate,
    AVG(CASE WHEN created_at <= datetime('now', '-7 days')
         AND created_at > datetime('now', '-14 days') THEN outlier_rate END) as previous_rate
FROM outlier_history
GROUP BY pattern_id
HAVING recent_rate > previous_rate * 1.2;  -- 20% increase triggers alert
```

---

## 18. NAPI Interface

Four query functions exposed via drift-napi for TypeScript consumption.
Follows the command/query pattern from 03-NAPI-BRIDGE-V2-PREP.md.

### Query Functions

```rust
/// Get outlier analysis results for a specific pattern.
#[napi]
pub fn query_pattern_outliers(
    runtime: &DriftRuntime,
    pattern_id: String,
) -> napi::Result<JsOutlierDetectionResult> {
    let result = runtime.outlier_engine()
        .get_latest_result(&pattern_id)
        .map_err(to_napi_error)?;
    Ok(result.into())
}

/// Get all outlier locations for a specific file.
#[napi]
pub fn query_file_outliers(
    runtime: &DriftRuntime,
    file_path: String,
) -> napi::Result<Vec<JsOutlierLocation>> {
    let locations = runtime.outlier_engine()
        .get_file_outliers(&file_path)
        .map_err(to_napi_error)?;
    Ok(locations.into_iter().map(Into::into).collect())
}

/// Get outlier summary statistics across all patterns.
#[napi]
pub fn query_outlier_summary(
    runtime: &DriftRuntime,
) -> napi::Result<JsOutlierSummary> {
    let summary = runtime.outlier_engine()
        .get_summary()
        .map_err(to_napi_error)?;
    Ok(summary.into())
}

/// Get outlier trend data for a pattern over time.
#[napi]
pub fn query_outlier_trend(
    runtime: &DriftRuntime,
    pattern_id: String,
    days: u32,
) -> napi::Result<Vec<JsOutlierTrendPoint>> {
    let trend = runtime.outlier_engine()
        .get_trend(&pattern_id, days)
        .map_err(to_napi_error)?;
    Ok(trend.into_iter().map(Into::into).collect())
}
```

### TypeScript Types (generated by napi-rs v3)

```typescript
interface OutlierDetectionResult {
  patternId: string;
  file?: string;
  outliers: OutlierResult[];
  totalAnalyzed: number;
  outlierRate: number;
  primaryMethod: string;
  supplementaryMethods: string[];
  statistics: PopulationStatistics;
  timestamp: number;
  durationUs: number;
}

interface OutlierResult {
  index: number;
  value: number;
  testStatistic: number;
  method: string;
  significance: string;
  deviationScore: number;
  iteration: number;
  reason: string;
  direction: string;
}

interface OutlierSummary {
  totalPatterns: number;
  patternsWithOutliers: number;
  totalOutliers: number;
  averageOutlierRate: number;
  methodDistribution: Record<string, number>;
  significanceDistribution: Record<string, number>;
}

interface OutlierTrendPoint {
  scanId: string;
  timestamp: number;
  outlierCount: number;
  outlierRate: number;
  totalAnalyzed: number;
}
```

---

## 19. Event Interface

Events emitted by the outlier detection engine for downstream consumers.
Uses the trait-based event system from PLANNING-DRIFT.md D5.

```rust
/// Events emitted by the outlier detection engine.
pub trait OutlierEventHandler: Send + Sync {
    /// Fired when outlier analysis completes for a pattern.
    fn on_outlier_analysis_complete(
        &self,
        _pattern_id: &str,
        _result: &OutlierDetectionResult,
    ) {}

    /// Fired when a new critical-significance outlier is detected.
    fn on_critical_outlier_detected(
        &self,
        _pattern_id: &str,
        _outlier: &OutlierResult,
    ) {}

    /// Fired when a pattern's outlier rate crosses a threshold.
    /// Thresholds: 0.10 (warning), 0.25 (high), 0.50 (critical).
    fn on_outlier_rate_threshold_crossed(
        &self,
        _pattern_id: &str,
        _rate: f64,
        _threshold: f64,
    ) {}

    /// Fired when outlier trend shows degradation (increasing rate).
    fn on_outlier_degradation_detected(
        &self,
        _pattern_id: &str,
        _recent_rate: f64,
        _previous_rate: f64,
    ) {}
}
```

### Event Consumers

| Consumer | Event | Action |
|----------|-------|--------|
| Audit Engine | on_outlier_rate_threshold_crossed | Downgrade auto-approve recommendation |
| Feedback Loop | on_outlier_analysis_complete | Track effective FP rate |
| MCP Server | on_critical_outlier_detected | Surface in drift_status tool |
| IDE/LSP | on_outlier_analysis_complete | Update inline diagnostics |
| Cortex Bridge | on_critical_outlier_detected | Create memory for investigation |

---

## 20. Tracing & Observability

Per AD10: Observability-first with the `tracing` crate.

### Spans

```rust
#[tracing::instrument(skip(values, config), fields(
    pattern_id = %pattern_id,
    n = values.len(),
    method = tracing::field::Empty,
))]
pub fn detect_outliers_for_pattern(
    pattern_id: &str,
    values: &[f64],
    matches: &[PatternMatch],
    config: &OutlierConfig,
    rule_detector: &RuleBasedDetector,
    category: &str,
) -> OutlierDetectionResult {
    let span = tracing::Span::current();

    // Method selection
    let method = select_method(values.len(), config);
    span.record("method", &tracing::field::display(&method));

    // ... detection logic ...

    tracing::info!(
        pattern_id = %pattern_id,
        n = values.len(),
        outlier_count = result.outliers.len(),
        outlier_rate = result.outlier_rate,
        method = ?result.primary_method,
        duration_us = result.duration_us,
        "outlier detection complete"
    );

    result
}
```

### Key Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `outlier.detection_time_us` | Histogram | Per-pattern detection duration |
| `outlier.total_analyzed` | Counter | Total data points analyzed |
| `outlier.total_detected` | Counter | Total outliers detected |
| `outlier.method_used` | Counter (by method) | Which methods are being used |
| `outlier.significance_distribution` | Counter (by tier) | Distribution of significance tiers |
| `outlier.cross_validation_agreement` | Gauge | % of outliers confirmed by multiple methods |
| `outlier.false_positive_rate` | Gauge (by detector) | Effective FP rate from feedback |

---

## 21. T-Distribution Critical Value Computation

Both Grubbs' test and Generalized ESD require t-distribution critical values.
V2 uses the `statrs` crate for this — it provides the Student's t-distribution
with inverse CDF (quantile function) computation.

### Dependency

```toml
[dependencies]
statrs = "0.17"  # Statistical distributions including Student's t
```

### Implementation

```rust
use statrs::distribution::{StudentsT, ContinuousCDF};

/// Compute the critical value of the t-distribution.
///
/// Returns t such that P(T ≤ t) = 1 - alpha for T ~ t(df).
/// Used by Grubbs' test and Generalized ESD.
///
/// Parameters:
/// - alpha: significance level (e.g., 0.05 for 95% confidence)
/// - df: degrees of freedom (n - 2 for Grubbs')
///
/// The statrs crate uses the regularized incomplete beta function
/// internally, which is accurate to ~15 significant digits.
pub fn t_critical(alpha: f64, df: u32) -> f64 {
    if df == 0 {
        return f64::INFINITY; // Degenerate case
    }

    let t_dist = StudentsT::new(0.0, 1.0, df as f64)
        .expect("valid t-distribution parameters");

    // Two-tailed: we want the upper critical value
    // P(|T| > t_crit) = alpha, so P(T > t_crit) = alpha/2
    // inverse_cdf(1 - alpha/2) gives the upper critical value
    t_dist.inverse_cdf(1.0 - alpha)
}

/// Upper-tail critical value for Generalized ESD.
/// Returns t such that P(T ≤ t) = p for T ~ t(df).
pub fn t_critical_upper(p: f64, df: u32) -> f64 {
    if df == 0 {
        return f64::INFINITY;
    }

    let t_dist = StudentsT::new(0.0, 1.0, df as f64)
        .expect("valid t-distribution parameters");

    t_dist.inverse_cdf(p)
}
```

### Why statrs Over a Lookup Table

V1 would have needed a hardcoded lookup table for t-distribution critical
values (limited to specific df and α combinations). The `statrs` crate
provides exact computation via the regularized incomplete beta function,
supporting any df and α combination. This is essential because:

1. Grubbs' test uses df = n - 2, where n varies per pattern (10-29)
2. Generalized ESD uses df = n - i - 2, where i varies per iteration
3. Sensitivity adjustment modifies α, creating non-standard values
4. A lookup table would need interpolation; `statrs` gives exact values

### statrs Crate Properties

| Property | Value |
|----------|-------|
| Crate | `statrs` v0.17+ |
| License | MIT |
| Dependencies | Minimal (no_std compatible core) |
| Accuracy | ~15 significant digits |
| Performance | Sub-microsecond per inverse CDF call |
| Distributions | Normal, Student's t, Chi-squared, F, Beta, Gamma, etc. |

---

## 22. Performance Targets & Benchmarks

### Targets

| Operation | Target | V1 Baseline | Notes |
|-----------|--------|-------------|-------|
| Single pattern outlier detection (n=100) | < 10μs | ~50μs (TS) | Pure math, no I/O |
| Single pattern outlier detection (n=10,000) | < 500μs | N/A | Large pattern |
| Batch detection (1,000 patterns) | < 50ms | ~500ms (TS) | Parallel via rayon |
| Batch detection (10,000 patterns) | < 500ms | N/A | Parallel via rayon |
| T-distribution critical value | < 1μs | N/A (no Grubbs' in v1) | statrs inverse CDF |
| Generalized ESD (n=50, r=10) | < 100μs | N/A (new) | 10 iterations |
| Modified Z-Score (n=1,000) | < 50μs | N/A (new) | Sort + median |
| IQR cross-validation (n=1,000) | < 20μs | ~100μs (TS) | Sort + percentile |
| Outlier result serialization (NAPI) | < 5μs per result | ~20μs (TS) | serde + napi-rs v3 |

### Benchmarks

```rust
// crates/drift-core/benches/outlier_bench.rs

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use drift_core::outlier::*;

fn bench_z_score(c: &mut Criterion) {
    let mut group = c.benchmark_group("z_score_iterative");
    for n in [30, 100, 1_000, 10_000] {
        let values = generate_normal_with_outliers(n, 3);
        group.bench_with_input(
            BenchmarkId::from_parameter(n),
            &values,
            |b, v| b.iter(|| z_score_iterative(v, 2.5, 0.7, 3)),
        );
    }
    group.finish();
}

fn bench_grubbs(c: &mut Criterion) {
    let mut group = c.benchmark_group("grubbs_test");
    for n in [10, 15, 20, 25, 29] {
        let values = generate_normal_with_outliers(n, 1);
        group.bench_with_input(
            BenchmarkId::from_parameter(n),
            &values,
            |b, v| b.iter(|| grubbs_test(v, 0.05, 0.7)),
        );
    }
    group.finish();
}

fn bench_generalized_esd(c: &mut Criterion) {
    let mut group = c.benchmark_group("generalized_esd");
    for n in [25, 50, 100] {
        let values = generate_normal_with_outliers(n, 5);
        let r = (n / 5).min(10);
        group.bench_with_input(
            BenchmarkId::from_parameter(n),
            &values,
            |b, v| b.iter(|| generalized_esd(v, r, 0.05, 0.7)),
        );
    }
    group.finish();
}

fn bench_iqr(c: &mut Criterion) {
    let mut group = c.benchmark_group("iqr_detection");
    for n in [30, 100, 1_000, 10_000] {
        let values = generate_normal_with_outliers(n, 3);
        group.bench_with_input(
            BenchmarkId::from_parameter(n),
            &values,
            |b, v| b.iter(|| iqr_detection(v, 1.5, 0.7)),
        );
    }
    group.finish();
}

fn bench_modified_z_score(c: &mut Criterion) {
    let mut group = c.benchmark_group("modified_z_score");
    for n in [30, 100, 1_000, 10_000] {
        let values = generate_skewed_with_outliers(n, 3);
        group.bench_with_input(
            BenchmarkId::from_parameter(n),
            &values,
            |b, v| b.iter(|| modified_z_score(v, 3.5, 0.7)),
        );
    }
    group.finish();
}

fn bench_full_engine(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_engine");
    for n_patterns in [100, 1_000, 10_000] {
        let patterns = generate_test_patterns(n_patterns, 50);
        let config = OutlierConfig::default();
        let rules = RuleBasedDetector::new();
        group.bench_with_input(
            BenchmarkId::from_parameter(n_patterns),
            &patterns,
            |b, p| b.iter(|| detect_all_outliers(p, &config, &rules)),
        );
    }
    group.finish();
}

fn bench_t_critical(c: &mut Criterion) {
    c.bench_function("t_critical_value", |b| {
        b.iter(|| t_critical(0.05, 28))
    });
}

criterion_group!(
    benches,
    bench_z_score,
    bench_grubbs,
    bench_generalized_esd,
    bench_iqr,
    bench_modified_z_score,
    bench_full_engine,
    bench_t_critical,
);
criterion_main!(benches);
```

---

## 23. Build Order & Dependencies

### Phase 1: Core Types & Statistics (Week 1)

| Deliverable | Dependencies |
|------------|-------------|
| `types.rs` — OutlierResult, Significance, OutlierMethod, etc. | None |
| `config.rs` — OutlierConfig, OutlierCategoryConfig | None |
| `stats.rs` — PopulationStatistics, calculateStatistics() | None |
| `t_dist.rs` — t_critical(), t_critical_upper() | statrs crate |

### Phase 2: Individual Methods (Weeks 2-3)

| Deliverable | Dependencies |
|------------|-------------|
| `z_score.rs` — z_score_iterative() | types, stats |
| `grubbs.rs` — grubbs_test() | types, stats, t_dist |
| `esd.rs` — generalized_esd() | types, stats, t_dist |
| `iqr.rs` — iqr_detection(), percentile() | types, stats |
| `mad.rs` — modified_z_score() | types, stats |
| `rules.rs` — RuleBasedDetector, OutlierRule | types |

### Phase 3: Engine & Integration (Week 4)

| Deliverable | Dependencies |
|------------|-------------|
| `engine.rs` — OutlierEngine, method selection, cross-validation | All methods |
| `conversion.rs` — extract_outlier_values(), update_pattern_outlier_data() | types, engine |
| `health.rs` — false-positive rate tracking | types, storage |
| `mod.rs` — public API, detect_outliers() convenience function | All |

### Phase 4: Storage & NAPI (Week 5)

| Deliverable | Dependencies |
|------------|-------------|
| `storage.rs` — outlier_history table, trend queries | drift-core storage |
| NAPI functions (4 query functions) | engine, storage |
| Event interface implementation | engine |
| Tracing instrumentation | engine |

### Phase 5: Benchmarks & Testing (Week 6)

| Deliverable | Dependencies |
|------------|-------------|
| `outlier_bench.rs` — criterion benchmarks (7 benchmarks) | All methods |
| Unit tests per method (property-based with proptest) | All methods |
| Integration tests (outlier → violation pipeline) | engine, rules engine |
| Golden tests (known datasets with expected outlier results) | All methods |

### Dependency Graph

```
statrs ──→ t_dist ──→ grubbs
                  ──→ esd
types ──→ z_score ──→ engine ──→ NAPI
      ──→ iqr     ──→        ──→ storage
      ──→ mad     ──→        ──→ events
      ──→ rules   ──→        ──→ tracing
stats ──→ (all methods)
config ──→ engine
```

---

## 24. V1 → V2 Feature Cross-Reference

Complete mapping of every v1 feature to its v2 location.

| V1 Feature | V1 Location | V2 Location | Status |
|-----------|-------------|-------------|--------|
| Z-Score detection | outlier-detector.ts | z_score.rs | UPGRADED (iterative masking) |
| IQR detection | outlier-detector.ts | iqr.rs | PRESERVED (supplementary role) |
| Rule-based detection | outlier-detector.ts | rules.rs | PRESERVED |
| Sensitivity adjustment | outlier-detector.ts | config.rs | PRESERVED |
| Significance (3 levels) | types.ts | types.rs | UPGRADED (4 tiers) |
| Deviation score | outlier-detector.ts | types.rs | PRESERVED |
| OutlierInfo type | types.ts | types.rs (OutlierResult) | UPGRADED (richer) |
| OutlierType enum (7) | types.ts | types.rs | PRESERVED |
| OutlierDetectionResult | types.ts | types.rs | UPGRADED (+ stats) |
| OutlierStatistics | types.ts | types.rs (PopulationStatistics) | UPGRADED (+ MAD, skewness, kurtosis) |
| OutlierDetectorConfig | types.ts | config.rs (OutlierConfig) | UPGRADED (+ MAD, ESD, category overrides) |
| Custom rule register/unregister | outlier-detector.ts | rules.rs | PRESERVED |
| detectOutliers() convenience | outlier-detector.ts | mod.rs | PRESERVED |
| calculateStatistics() | outlier-detector.ts | stats.rs | PRESERVED |
| Method selection by n | outlier-detector.ts | engine.rs | UPGRADED (6 methods) |
| Outlier reason strings | outlier-detector.ts | types.rs (OutlierReason enum) | UPGRADED (structured) |
| Expected/actual reporting | types.ts | types.rs (in OutlierReason) | PRESERVED |
| Suggested fix per outlier | types.ts | types.rs | PRESERVED |
| Outlier rate calculation | outlier-detector.ts | types.rs | PRESERVED |
| DataPoint conversion | outlier-detector.ts | conversion.rs | PRESERVED |
| Outlier context | types.ts | types.rs | PRESERVED |
| Merge stat + rule results | outlier-detector.ts | engine.rs | PRESERVED |
| Deduplication | outlier-detector.ts | engine.rs | PRESERVED |
| Grubbs' test | — | grubbs.rs | NEW |
| Generalized ESD | — | esd.rs | NEW |
| Modified Z-Score/MAD | — | mad.rs | NEW |
| Iterative masking | — | z_score.rs | NEW |
| T-distribution computation | — | t_dist.rs | NEW |
| 4-tier significance | — | types.rs | NEW |
| Per-category config | — | config.rs | NEW |
| FP rate tracking | — | health.rs | NEW |
| Parallel detection | — | engine.rs | NEW |
| Cross-validation boost | — | engine.rs | NEW |
| Outlier trend tracking | — | storage.rs | NEW |
| Normality assessment | — | mad.rs | NEW |

23 v1 features preserved. 0 features dropped. 13 new features added.
Zero functional loss.

---

## 25. Inconsistencies & Decisions

### I1: Outlier Detection Position in Architecture

06-DETECTOR-SYSTEM.md §10 places outlier detection inside the detector system.
DRIFT-V2-STACK-HIERARCHY.md places it at Level 2A (Pattern Intelligence).
00-overview/subsystem-connections.md shows it between pattern aggregation and
the rules engine.

Resolution: Outlier detection is a module within `drift-core`, consumed by
the detector system's post-aggregation pipeline. It is architecturally at
Level 2A but physically lives in the detector system's crate. File structure:

```
crates/drift-core/src/outlier/
├── mod.rs              # Public API
├── types.rs            # All outlier types
├── config.rs           # OutlierConfig
├── engine.rs           # OutlierEngine (method selection, cross-validation)
├── stats.rs            # PopulationStatistics, calculateStatistics()
├── z_score.rs          # Z-Score with iterative masking
├── grubbs.rs           # Grubbs' test
├── esd.rs              # Generalized ESD (Rosner)
├── iqr.rs              # IQR with Tukey fences
├── mad.rs              # Modified Z-Score / MAD
├── rules.rs            # Rule-based detection
├── t_dist.rs           # T-distribution critical values
├── conversion.rs       # Pattern → outlier value extraction
├── health.rs           # False-positive rate tracking
└── storage.rs          # SQLite persistence
```

### I2: Z-Score Threshold — 2.0 vs 2.5 vs 3.0

V1 uses 2.0 (flags ~4.6%). NIST recommends 3.0 (flags ~0.3%).
.research/03-detectors/RECOMMENDATIONS.md R6 recommends 2.5 (~1.2%).

Resolution: V2 default is 2.5. Rationale: 3.0 is too conservative for
code pattern analysis where we want to catch meaningful deviations, not
just extreme outliers. 2.0 is too aggressive and generates noise. 2.5
balances sensitivity with precision. Configurable via drift.toml.

### I3: Minimum Sample Size — 3 vs 10

V1 uses 3. .research/03-detectors/RECOMMENDATIONS.md R6 recommends 10.
NIST recommends at least 10 for any statistical test.

Resolution: V2 default is 10. With n=3, any single unusual value creates
a statistically meaningless outlier. n=10 is the minimum for Grubbs' test
to produce reliable results.

### I4: IQR Role — Primary vs Supplementary

V1 uses IQR as the primary method for n < 30.
V2 introduces Grubbs' and Generalized ESD for small samples.

Resolution: IQR shifts to supplementary cross-validation role for n ≥ 30.
For n < 30, Grubbs' (10-24) and Generalized ESD (25-29) are preferred
because they account for sample size in their critical values. IQR uses
a fixed 1.5× multiplier regardless of n, which is less precise for small
samples. IQR remains valuable as a non-parametric cross-check.

### I5: Sensitivity Default — 0.7

V1 default is 0.7. No research recommends a specific value.

Resolution: Preserve 0.7 as default. It provides a balanced starting point
(threshold multiplied by 1.3). Users can tune via drift.toml. Security
category defaults to 0.9 (stricter). Styling category defaults to 0.3
(more lenient).

### I6: Outlier Method for Generalized ESD Range (25-29)

Both Grubbs' and Generalized ESD could handle n=25-29. Grubbs' is simpler
but detects one outlier at a time. Generalized ESD handles multiple outliers
but Rosner's accuracy guarantee is for n ≥ 25.

Resolution: Use Generalized ESD for n=25-29 because:
1. It handles multiple outliers without specifying exact count
2. Rosner's simulation shows accuracy for n ≥ 25
3. It addresses masking that sequential Grubbs' misses
4. The computational cost difference is negligible for n < 30

### I7: statrs vs Lookup Table for T-Distribution

Could use a hardcoded lookup table (faster, no dependency) or the statrs
crate (exact, any df/α combination).

Resolution: Use statrs. The lookup table approach fails because:
1. Grubbs' uses df = n-2 where n varies (8-27 possible df values)
2. Generalized ESD uses df = n-i-2 where i varies per iteration
3. Sensitivity adjustment modifies α to non-standard values
4. Interpolation between table entries introduces error
5. statrs is sub-microsecond per call — no performance concern
6. statrs is MIT-licensed, minimal dependencies, well-maintained

---

## 26. Risk Register

| # | Risk | Impact | Likelihood | Mitigation |
|---|------|--------|------------|------------|
| R1 | Grubbs' test misses multiple outliers in small samples | Medium | Medium | Generalized ESD handles n ≥ 25. For n < 25, iterative Grubbs' with 3-removal cap. |
| R2 | Modified Z-Score/MAD returns empty when >50% values are identical | Low | Medium | Documented behavior. Fall back to standard Z-Score. MAD=0 means the majority value IS the convention. |
| R3 | Normality heuristic (skewness/kurtosis) is imprecise | Low | Medium | It's a heuristic, not a formal test. False activation of MAD is harmless (MAD is always valid). False non-activation means standard Z-Score runs (also valid for large n). |
| R4 | Cross-validation significance boost creates false confidence | Low | Low | Boost is capped at Critical. Two independent methods agreeing is strong evidence. |
| R5 | Per-category config overrides create inconsistent behavior | Low | Low | Document clearly. Provide drift.toml validation. Default config is consistent. |
| R6 | statrs crate dependency adds build time | Low | Low | statrs is lightweight (~2s compile). The alternative (lookup table) is worse in every other dimension. |
| R7 | Iterative Z-Score over-removes in pathological distributions | Medium | Low | 3-iteration cap. Minimum 3 remaining points. Over-removal is better than masking (missed outliers). |
| R8 | Generalized ESD accuracy degrades for n < 25 | Medium | Low | Only used for n ≥ 25. Grubbs' handles 10-24. Rosner's simulations confirm accuracy for n ≥ 25. |
| R9 | Outlier trend tracking adds storage overhead | Low | Low | outlier_history table with 90-day retention policy. One row per pattern per scan. |
| R10 | Rule-based detection rules are hard to test | Medium | Medium | Each rule is a pure function. Unit test each rule independently. Property-based tests for rule composition. |
| R11 | Sensitivity adjustment makes thresholds hard to reason about | Medium | Medium | Document the adjusted thresholds at each sensitivity level. Provide a `drift outlier explain` CLI command that shows effective thresholds. |
| R12 | False-positive rate tracking requires violation action data | Medium | High | Depends on IDE/CLI reporting violation actions (fix/dismiss/ignore). Until feedback loop is active, FP rate is estimated from outlier_rate trends. |

---

*End of Outlier Detection V2 Implementation Prep.*
*Sections 1-4: Architecture, v1 inventory, v2 design, data model.*
*Sections 5-10: 6 detection methods (Z-Score, Grubbs', Generalized ESD, IQR, Modified Z-Score/MAD, Rule-Based).*
*Sections 11-12: Sensitivity system, significance classification.*
*Sections 13-16: Integration (violations, confidence, aggregation, rules/gates).*
*Sections 17-20: Storage, NAPI, events, tracing.*
*Sections 21-26: T-distribution, performance, build order, cross-reference, inconsistencies, risks.*
*Every v1 feature accounted for. 23 features preserved, 0 dropped, 13 new features added.*
*6 statistical methods. Zero functional loss. Build-ready.*
