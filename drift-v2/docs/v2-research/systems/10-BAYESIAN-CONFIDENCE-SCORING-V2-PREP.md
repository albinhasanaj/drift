# Bayesian Confidence Scoring — V2 Implementation Prep

> Comprehensive build specification for Drift v2's Bayesian confidence scoring system.
> Synthesized from: DRIFT-V2-FULL-SYSTEM-AUDIT.md (AD8, AD9), DRIFT-V2-STACK-HIERARCHY.md
> (Level 2A Pattern Intelligence), DRIFT-V2-SYSTEMS-REFERENCE.md (§6), PLANNING-DRIFT.md (D7),
> MASTER_RECOMMENDATIONS.md (M33, M34, M35), 03-detectors/RECOMMENDATIONS.md (R3, R6, R9),
> 03-detectors/confidence-scoring.md (v1 algorithm), 03-detectors/patterns/confidence-scoring.md
> (v1 ConfidenceScorer class), 03-detectors/learning-system.md (v1 ValueDistribution),
> 06-DETECTOR-SYSTEM.md (§7 Bayesian Convention Discovery, §9 Confidence Scoring Bayesian Upgrade,
> §10 Outlier Detection Statistical Refinements), 06-UNIFIED-ANALYSIS-ENGINE-V2-PREP.md
> (storage tables, inconsistency I5), 02-STORAGE-V2-PREP.md (patterns table schema),
> 03-NAPI-BRIDGE-V2-PREP.md (NAPI interface patterns), 07-BOUNDARY-DETECTION-V2-PREP.md
> (boundary confidence cross-reference), cortex-core/src/memory/confidence.rs (Cortex Confidence type),
> cortex-validation/src/healing/confidence_adjust.rs (Cortex confidence adjustment patterns).
>
> Purpose: Everything needed to build Drift v2's Bayesian confidence scoring from scratch.
> Decisions resolved, inconsistencies flagged, mathematical foundations specified,
> interface contracts defined, build order specified. This system is the numerical backbone
> of the entire pattern intelligence layer.
> Generated: 2026-02-07

---

## Table of Contents

1. [Architectural Position](#1-architectural-position)
2. [Resolved Inconsistencies](#2-resolved-inconsistencies)
3. [V1 System — Complete Documentation](#3-v1-system--complete-documentation)
4. [V2 Beta Distribution Model](#4-v2-beta-distribution-model)
5. [V2 Scoring Formula](#5-v2-scoring-formula)
6. [Temporal Decay](#6-temporal-decay)
7. [Momentum Signal](#7-momentum-signal)
8. [Graduated Confidence Tiers](#8-graduated-confidence-tiers)
9. [Bayesian Convention Learning](#9-bayesian-convention-learning)
10. [Outlier Detection Integration](#10-outlier-detection-integration)
11. [Feedback Loop Integration (AD9)](#11-feedback-loop-integration-ad9)
12. [Core Data Types](#12-core-data-types)
13. [Storage Schema](#13-storage-schema)
14. [NAPI Interface](#14-napi-interface)
15. [Integration Points](#15-integration-points)
16. [Cortex Cross-Reference](#16-cortex-cross-reference)
17. [Error Handling](#17-error-handling)
18. [Tracing & Observability](#18-tracing--observability)
19. [File & Module Structure](#19-file--module-structure)
20. [Build Order](#20-build-order)
21. [V1 Feature Verification](#21-v1-feature-verification)
22. [Performance Targets](#22-performance-targets)
23. [Open Items](#23-open-items)
24. [Summary of All Decisions](#24-summary-of-all-decisions)

---

## 1. Architectural Position

Bayesian Confidence Scoring is **Level 2A Pattern Intelligence** in the Drift v2 stack hierarchy.
It is the "numerical backbone of the pattern system." Per DRIFT-V2-STACK-HIERARCHY.md:

> Without it: no ranking, no outlier thresholds, no quality gate thresholds.

This is a **cross-cutting concern** — not a standalone subsystem that runs in isolation. It is
a computation engine consumed by nearly every downstream system in Drift v2.

### Architectural Decision: AD8

From DRIFT-V2-FULL-SYSTEM-AUDIT.md:

> **AD8: Bayesian Confidence with Momentum** — Replace static confidence scoring with
> Bayesian posterior + momentum.

This is one of 12 foundational architectural decisions (P0 — decide before writing code).
It constrains every subsystem that consumes confidence scores.

### What Lives Here

- Beta distribution model (prior, posterior, conjugate update)
- 5-factor scoring formula (frequency, consistency, age, spread, momentum)
- Posterior blending with weighted factors (sample-size-adaptive)
- Temporal decay engine (frequency decline → confidence reduction)
- Momentum computation (trend direction and magnitude)
- Graduated confidence tiers (Established/Emerging/Tentative/Uncertain by credible interval width)
- Bayesian convention learning (replaces binary 60% threshold)
- Convention categorization (Universal/ProjectSpecific/Emerging/Legacy/Contested)
- Contested convention detection (within 15% frequency)
- Outlier detection integration (Z-Score iterative, Grubbs', IQR)
- V1 compatibility scoring (migration period fallback)

### What Does NOT Live Here

- Pattern matching engine (06-DETECTOR-SYSTEM — produces the raw matches this system scores)
- Pattern storage (02-STORAGE — stores the α, β, score columns this system writes)
- Pattern aggregation & deduplication (separate Level 2A system — groups matches before scoring)
- Scan orchestration (06-UNIFIED-ANALYSIS-ENGINE — calls this system during Phase 4: Finalize)
- Quality gates (consume confidence scores but don't compute them)
- MCP tool routing (packages/mcp — exposes confidence data but doesn't compute it)
- Boundary detection confidence (07-BOUNDARY-DETECTION — has its own 5-factor formula for
  data access detection, distinct from pattern confidence)

### Dependency Direction

```
                    ┌─────────────────────────────────────────────┐
                    │         Downstream Consumers                │
                    │  Quality Gates, Grounding Loop (D7),        │
                    │  Pattern Ranking, Outlier Thresholds,       │
                    │  Convention Enforcement, MCP Tools,         │
                    │  Feedback Loop (AD9), DNA Health            │
                    └──────────────────┬──────────────────────────┘
                                       │ reads confidence scores
                    ┌──────────────────▼──────────────────────────┐
                    │   Bayesian Confidence Scoring (this system) │
                    │   Level 2A — Pattern Intelligence           │
                    └──────────────────┬──────────────────────────┘
                                       │ reads raw matches + history
                    ┌──────────────────▼──────────────────────────┐
                    │         Upstream Producers                  │
                    │  Detector System (raw matches),             │
                    │  Scanner (file counts),                     │
                    │  Storage (α/β persistence, scan history),   │
                    │  Pattern Aggregation (grouped matches)      │
                    └─────────────────────────────────────────────┘
```

### D7 Impact (Grounding Feedback Loop)

Per PLANNING-DRIFT.md Decision 7 and DRIFT-V2-STACK-HIERARCHY.md:

> Confidence scores are what the grounding loop compares against Cortex memories —
> but Drift computes them independently.

The grounding loop reads confidence scores from drift.db to validate Cortex memories.
This is a one-way read — Drift computes confidence independently, the bridge consumes it.
No change to internal dependencies, but it means **confidence scoring quality directly
affects the killer integration feature**. Get this right and the grounding loop is powerful.
Get it wrong and grounding produces garbage.

---

## 2. Resolved Inconsistencies

### I1: Weight Discrepancy (0.35/0.25/0.15/0.25 vs 0.40/0.30/0.15/0.15)

**Source conflict**: The gap analysis document (`03-detectors/confidence-scoring.md`) lists
weights as `frequency: 0.35, consistency: 0.25, age: 0.15, spread: 0.25`. The actual v1 code
and the canonical pattern documentation (`03-detectors/patterns/confidence-scoring.md`) use
`frequency: 0.40, consistency: 0.30, age: 0.15, spread: 0.15`.

**Resolution**: The code is authoritative. V1 weights are `0.40/0.30/0.15/0.15`.
The gap analysis document had a transcription error. This is explicitly noted in
`03-detectors/patterns/confidence-scoring.md`:

> Note: The gap analysis doc lists weights as 0.35/0.25/0.15/0.25.
> The actual code uses 0.4/0.3/0.15/0.15. The code is authoritative.

**V2 impact**: Moot. V2 uses entirely new weights (`0.30/0.25/0.10/0.15/0.20`) with a
5th factor (momentum). The v1 weights are preserved only in the `score_v1_compat()` fallback.

### I2: AD8 Formula vs 06-DETECTOR-SYSTEM Formula

**Source conflict**: AD8 in DRIFT-V2-FULL-SYSTEM-AUDIT.md defines:
```
final_score = posterior_mean × 0.70 + consistency × 0.15 + momentum × 0.15
```

06-DETECTOR-SYSTEM.md §9 defines:
```
score = frequency × 0.30 + consistency × 0.25 + age × 0.10 + spread × 0.15 + momentum × 0.20
```
with posterior blending via sample-size-adaptive weighting.

**Resolution**: The 06-DETECTOR-SYSTEM formula is the refined version. AD8 was the initial
architectural decision (high-level direction). The detector system spec refined it into the
full 5-factor model with posterior blending. **This document uses the 06-DETECTOR-SYSTEM
formula as canonical.** AD8's intent (Bayesian posterior + momentum) is fully preserved —
the posterior is blended in via sample-size-adaptive weighting rather than a fixed 0.70 weight.

**Rationale**: The 5-factor model preserves all v1 factors (frequency, consistency, age, spread)
while adding momentum. This ensures no v1 scoring dimension is lost. The posterior blending
approach is more nuanced than a fixed weight — it lets the Bayesian model dominate as evidence
accumulates, while the weighted factors provide stability with small samples.

### I3: Outlier Detection Method Selection (v1 IQR vs v2 Grubbs')

**Source conflict**: DRIFT-V2-SYSTEMS-REFERENCE.md §6 says v1 uses IQR for n < 30.
06-DETECTOR-SYSTEM.md §10 says v2 uses Grubbs' test for 10 ≤ n < 30.

**Resolution**: No conflict. V1 used IQR as the small-sample method. V2 replaces it with
Grubbs' test for the 10-29 range (more statistically rigorous for small samples) and retains
IQR as a supplementary method for robustness. Both are documented in this spec.

### I4: V1 Outlier Thresholds

**Source conflict**: V1 used `zScoreThreshold=2.0`, `minSampleSize=3`.
V2 uses `zScoreThreshold=2.5`, `minSampleSize=10`.

**Resolution**: Intentional upgrade. V1's thresholds were too aggressive — `minSampleSize=3`
is statistically meaningless for Z-Score, and `zScoreThreshold=2.0` flags ~4.6% of normally
distributed data as outliers (too many false positives). V2's thresholds are evidence-based:
NIST recommends 3.0, M35 recommends 2.5 as a balance between sensitivity and precision.
The minimum sample size of 10 ensures statistical validity.

### I5: Confidence Scoring Placement

**Source conflict**: 06-UNIFIED-ANALYSIS-ENGINE-V2-PREP.md flagged inconsistency I5 —
confidence scoring logic appears in both the detector system spec and the unified analysis
engine spec.

**Resolution**: Confidence scoring is a **standalone module** within `crates/drift-core`.
The detector system produces raw matches. The unified analysis engine orchestrates the
pipeline. The confidence scoring module is called during Phase 4 (Finalize + Persist) of
the analysis pipeline. It is not embedded in either the detector system or the analysis
engine — it is a dependency of both.

```
Detector System → raw matches → Analysis Engine → calls → Confidence Scorer → scored patterns → Storage
```

---

## 3. V1 System — Complete Documentation

This section documents every feature of the v1 confidence scoring system. Every item here
must be accounted for in v2 — either preserved, upgraded, or explicitly replaced with rationale.

### 3.1 V1 Scoring Algorithm

**Location**: `packages/core/src/matcher/confidence-scorer.ts`

**Formula**:
```
score = frequency × 0.40 + consistency × 0.30 + ageFactor × 0.15 + spread × 0.15
```

All factors normalized to [0.0, 1.0]. Weighted sum clamped to [0.0, 1.0].
Weights must sum to 1.0 (±0.001 tolerance). Constructor validates at instantiation.

### 3.2 V1 Factor Calculations

**Factor 1 — Frequency** (weight 0.40):
```
frequency = occurrences / totalLocations
```
- How often the pattern appears relative to all applicable locations
- 0 occurrences or 0 total → 0.0
- Clamped to [0.0, 1.0]

**Factor 2 — Consistency** (weight 0.30):
```
consistency = 1 - variance
```
- Inverted variance — higher means more uniform implementation across files
- Negative variance treated as 0 (returns 1.0 — perfectly consistent)
- Variance clamped to [0.0, 1.0] before inversion

**Factor 3 — Age Factor** (weight 0.15):
```
if daysSinceFirstSeen <= 0:  return minAgeFactor (0.1)
if daysSinceFirstSeen >= maxAgeDays (30):  return 1.0
normalizedAge = daysSinceFirstSeen / maxAgeDays
ageFactor = minAgeFactor + normalizedAge × (1.0 - minAgeFactor)
```
- Linear scaling from 0.1 to 1.0 over 30 days
- Brand new patterns start at 0.1 (10% age contribution)
- Patterns older than 30 days get 1.0 (full age contribution)
- **No decay** — once at 1.0, stays at 1.0 forever regardless of frequency changes
- This is the primary v1 limitation: stale patterns never lose confidence from age alone

**Factor 4 — Spread** (weight 0.15):
```
spread = fileCount / totalFiles
```
- How widely the pattern is used across the codebase
- 0 files or 0 total → 0.0
- Clamped to [0.0, 1.0]

### 3.3 V1 Confidence Levels

```typescript
classifyLevel(score: number): ConfidenceLevel {
  if (score >= 0.85) return 'high';
  if (score >= 0.70) return 'medium';
  if (score >= 0.50) return 'low';
  return 'uncertain';
}
```

| Level | Threshold | Meaning | Enforcement |
|-------|-----------|---------|-------------|
| high | ≥ 0.85 | Well-established pattern | Safe to enforce, violations flagged |
| medium | ≥ 0.70 | Likely pattern | Worth flagging, informational |
| low | ≥ 0.50 | Emerging pattern | Informational only |
| uncertain | < 0.50 | Insufficient evidence | Not reported |

### 3.4 V1 Data Types

```typescript
interface ConfidenceScore {
  frequency: number;    // 0.0-1.0
  consistency: number;  // 0.0-1.0
  age: number;          // days since first seen (raw, not normalized)
  spread: number;       // file count (raw, not normalized)
  score: number;        // 0.0-1.0 weighted composite
  level: 'high' | 'medium' | 'low' | 'uncertain';
}

interface ConfidenceWeights {
  frequency: number;    // 0.40
  consistency: number;  // 0.30
  age: number;          // 0.15
  spread: number;       // 0.15
}

interface ConfidenceInput {
  occurrences: number;         // Pattern occurrence count
  totalLocations: number;      // Total applicable locations
  variance: number;            // Implementation variance (0 = perfectly consistent)
  daysSinceFirstSeen: number;  // Age in days
  fileCount: number;           // Files containing the pattern
  totalFiles: number;          // Total files in scope
}

interface AgeNormalizationConfig {
  minAgeFactor: number;   // 0.1
  maxAgeDays: number;     // 30
}
```

### 3.5 V1 ConfidenceScorer Class

```typescript
class ConfidenceScorer {
  constructor(weights: ConfidenceWeights, ageConfig: AgeNormalizationConfig);
  calculateScore(input: ConfidenceInput): ConfidenceScore;
  private calculateFrequency(occurrences: number, total: number): number;
  private calculateConsistency(variance: number): number;
  private calculateAgeFactor(days: number): number;
  private calculateSpread(fileCount: number, totalFiles: number): number;
  private classifyLevel(score: number): ConfidenceLevel;
}

// Functional helpers
function createConfidenceScore(freq, consistency, age, spread, score, level): ConfidenceScore;
function calculateConfidence(input: ConfidenceInput): ConfidenceScore;
```

### 3.6 V1 Convention Learning (ValueDistribution)

**Location**: `packages/detectors/src/base/learning-detector.ts`

The learning system uses `ValueDistribution` to discover conventions:

```typescript
class ValueDistribution<T> {
  add(value: T, file: string): void;
  getDominant(config: PatternLearningConfig): LearnedConvention<T> | null;
  getAll(): Array<{ value: T; count: number; files: string[] }>;
}
```

**Dominance calculation**:
```
filePercentage = filesWithValue / totalFiles
if filePercentage >= dominanceThreshold (0.60) AND occurrences >= minOccurrences (3):
  → dominant convention, confidence = filePercentage
```

**Configuration**:
```typescript
interface PatternLearningConfig {
  minOccurrences: number;       // 3
  dominanceThreshold: number;   // 0.60 (60%)
  minFiles: number;             // 2
}
```

**Limitations**:
- Binary: either dominant (≥60%) or not. No graduated strength.
- No sample size awareness: 3 files at 67% treated same as 300 files at 67%.
- No trend tracking: can't detect rising or declining conventions.
- No contested detection: two conventions at 45%/40% → neither is dominant → no learning.
- No category system: all conventions treated identically regardless of universality.

### 3.7 V1 Outlier Detection

**Location**: `packages/core/src/matcher/outlier-detector.ts`

**Configuration**:
```typescript
minSampleSize: 3
zScoreThreshold: 2.0
iqrMultiplier: 1.5
sensitivity: 0.7
```

**Method selection**:
- n ≥ 30: Z-Score (`|z| > adjustedThreshold`)
- n < 30: IQR (`value < Q1 - 1.5×IQR` or `value > Q3 + 1.5×IQR`)
- Any n: Rule-based (custom rules per detector)

**Sensitivity adjustment**: `adjustedThreshold = baseThreshold × (1 + (1 - sensitivity))`

**Significance levels**: |z| > 3.0 = high, > 2.5 = medium, > 2.0 = low

**Deviation score**: `min(1.0, (|zScore| - threshold) / threshold)`

**Outlier types**: structural, syntactic, semantic, stylistic, missing, extra, inconsistent

### 3.8 V1 Pattern Matcher (Confidence-Adjacent)

The pattern matcher produces the raw data that feeds confidence scoring:

**Match types**: AST, Regex, Structural, Semantic (falls back to AST), Custom (not implemented)

**Caching**: LRU cache, 1000 entries max, 60s TTL, content-hash invalidation.
Key: `{file}:{patternId}`.

**AST matching confidence**: `matched_checks / total_checks × child_confidence`
**Regex matching confidence**: Always 1.0 (binary match)
**Structural matching confidence**: All checks must pass (AND logic), binary result

**V2 note**: Pattern matching moves to Rust. The caching layer is replaced by Rust's
built-in performance + Moka cache. AST matching maps to tree-sitter queries.
Confidence scoring is decoupled from matching — the matcher produces matches,
the scorer scores them.

### 3.9 V1 Feature Inventory (Exhaustive)

Every v1 feature that must be accounted for in v2:

| # | Feature | V1 Behavior | V2 Status |
|---|---------|-------------|-----------|
| F1 | 4-factor weighted scoring | freq×0.40 + cons×0.30 + age×0.15 + spread×0.15 | Upgraded → 5-factor (§5) |
| F2 | Weight validation | Sum must equal 1.0 ±0.001 | Preserved (§5) |
| F3 | Frequency calculation | occurrences / totalLocations | Preserved (§5) |
| F4 | Consistency calculation | 1 - variance, clamped | Preserved (§5) |
| F5 | Age factor linear scaling | 0.1 → 1.0 over 30 days | Preserved + decay added (§6) |
| F6 | Spread calculation | fileCount / totalFiles | Preserved (§5) |
| F7 | 4 confidence levels | high/medium/low/uncertain at 0.85/0.70/0.50 | Replaced → graduated tiers (§8) |
| F8 | ConfidenceScore output type | 6 fields: freq, cons, age, spread, score, level | Upgraded → BayesianConfidence (§12) |
| F9 | ConfidenceInput type | 6 fields: occurrences, total, variance, days, files, totalFiles | Preserved + extended (§12) |
| F10 | ConfidenceWeights configurable | Custom weights via constructor | Preserved (§5) |
| F11 | AgeNormalizationConfig | minAgeFactor=0.1, maxAgeDays=30 | Preserved (§6) |
| F12 | Class-based scorer | ConfidenceScorer class | Replaced → module functions (§19) |
| F13 | Functional helpers | createConfidenceScore, calculateConfidence | Preserved as NAPI exports (§14) |
| F14 | ValueDistribution learning | Binary dominant at 60% | Replaced → Bayesian learning (§9) |
| F15 | Dominance threshold | 60% file percentage | Replaced → posterior confidence (§9) |
| F16 | Min occurrences | 3 | Upgraded → 10 (§9) |
| F17 | Min files | 2 | Upgraded → 5 (§9) |
| F18 | Z-Score outlier detection | \|z\| > 2.0, n ≥ 30 | Upgraded → \|z\| > 2.5, iterative (§10) |
| F19 | IQR outlier detection | Q1-1.5×IQR to Q3+1.5×IQR, n < 30 | Preserved as supplementary (§10) |
| F20 | Rule-based outlier detection | Custom rules per detector | Preserved (§10) |
| F21 | Sensitivity adjustment | adjustedThreshold formula | Preserved (§10) |
| F22 | Outlier significance levels | high/medium/low by z-score | Upgraded → 4 levels + method tag (§10) |
| F23 | Outlier types enum | 7 types | Preserved (§10) |
| F24 | Deviation score | min(1.0, (z-threshold)/threshold) | Preserved (§10) |
| F25 | Pattern matcher caching | LRU, 1000 entries, 60s TTL | Out of scope (matcher system) |
| F26 | AST match confidence | matched/total × child confidence | Out of scope (matcher system) |
| F27 | Regex match confidence | Always 1.0 | Out of scope (matcher system) |

**Coverage**: 27/27 v1 features accounted for. 0 features lost.


---

## 4. V2 Beta Distribution Model

### 4.1 Mathematical Foundation

The Beta distribution is the conjugate prior for the Bernoulli likelihood. This means
that if we model each file as a Bernoulli trial (pattern present = success, absent = failure),
and our prior belief about the success probability is Beta-distributed, then the posterior
after observing data is also Beta-distributed. This gives us closed-form updates — no MCMC,
no approximation, no iterative optimization. Pure arithmetic.

**Prior**: Beta(α=1, β=1) — the uniform distribution on [0, 1]. This encodes "no prior
assumption about pattern frequency." Every pattern starts here.

**Posterior after n observations with k successes**:
```
Beta(α + k, β + n - k)
```
where:
- α = prior alpha (1.0)
- β = prior beta (1.0)
- k = number of files where pattern is present (successes)
- n = total files examined (trials)

**Posterior mean** (point estimate of pattern frequency):
```
posterior_mean = (α + k) / (α + β + n)
```

**Posterior variance**:
```
posterior_variance = (α + k)(β + n - k) / ((α + β + n)² × (α + β + n + 1))
```

**95% Credible Interval** (where we believe the true frequency lies):
```
CI_lower = BetaInv(0.025, α + k, β + n - k)
CI_upper = BetaInv(0.975, α + k, β + n - k)
CI_width = CI_upper - CI_lower
```

The credible interval width is the key signal for graduated tiers (§8). Wide interval =
uncertain. Narrow interval = confident.

### 4.2 Why Beta-Binomial

1. **Conjugate prior**: Posterior is same family as prior → closed-form update, O(1) per observation
2. **Natural uncertainty**: Small samples → wide posterior → low confidence. Large samples → narrow posterior → high confidence. No arbitrary thresholds needed.
3. **Incremental updates**: New scan data updates α and β directly. No need to recompute from scratch. Store (α, β) in SQLite, update in place.
4. **Interpretable**: α ≈ "pseudo-count of successes + 1", β ≈ "pseudo-count of failures + 1". Developers can understand "we've seen this pattern in 50 of 100 files, so α=51, β=51, mean=0.50."
5. **Prior flexibility**: Beta(1,1) = uniform = "no opinion." Beta(2,2) = slight preference for 0.5. Beta(0.5,0.5) = Jeffreys prior = slight preference for extremes. We use Beta(1,1) for simplicity and neutrality.

### 4.3 Conjugate Update Procedure

When a new scan completes:

```rust
/// Update posterior parameters with new scan observation.
/// This is the core Bayesian update — called once per pattern per scan.
pub fn bayesian_update(
    alpha: f64,
    beta: f64,
    files_with_pattern: usize,
    total_files_scanned: usize,
) -> (f64, f64) {
    let k = files_with_pattern as f64;
    let n = total_files_scanned as f64;
    (alpha + k, beta + (n - k))
}
```

**Important**: This is a cumulative update. After 3 scans of 100 files each where the
pattern appears in 80 files per scan:
```
Initial:  α=1, β=1
Scan 1:   α=81, β=21    (mean=0.794)
Scan 2:   α=161, β=41   (mean=0.797)
Scan 3:   α=241, β=61   (mean=0.798)
```

The posterior converges toward the true frequency (0.80) and the credible interval narrows
with each scan. After 3 scans, the system is very confident.

**Decision: Cumulative vs. Sliding Window**

We use **cumulative** updates (all historical data contributes to the posterior). This is
the mathematically correct Bayesian approach. However, this means the posterior is slow to
react to sudden changes (e.g., a team migrating away from a convention).

The **momentum signal** (§7) compensates for this. Momentum captures short-term trend
direction, while the posterior captures long-term evidence. Together they handle both
stability and responsiveness.

If a sliding window is ever needed (e.g., "only consider the last 10 scans"), it can be
implemented by storing per-scan (k, n) in `pattern_scan_history` and recomputing α, β
from the window. This is a future optimization, not a launch requirement.

### 4.4 Credible Interval Computation

The Beta distribution's quantile function (inverse CDF) is needed for credible intervals.
We use the regularized incomplete beta function:

```rust
use statrs::distribution::{Beta as BetaDist, ContinuousCDF};

/// Compute 95% credible interval for a Beta(alpha, beta) distribution.
pub fn credible_interval(alpha: f64, beta: f64) -> (f64, f64, f64) {
    let dist = BetaDist::new(alpha, beta).unwrap();
    let lower = dist.inverse_cdf(0.025);
    let upper = dist.inverse_cdf(0.975);
    let width = upper - lower;
    (lower, upper, width)
}
```

**Dependency**: `statrs` crate for Beta distribution CDF/inverse CDF. This is a well-maintained
Rust statistics library. Alternative: implement the regularized incomplete beta function
directly using the continued fraction expansion (Lentz's algorithm), but `statrs` is
battle-tested and avoids reinventing numerical methods.

**Cargo.toml addition**:
```toml
statrs = "0.17"
```

### 4.5 Posterior Mean vs. MAP vs. Median

Three point estimates are available from the Beta posterior:

| Estimate | Formula | When to Use |
|----------|---------|-------------|
| Mean | (α)/(α+β) | Default. Minimizes squared error. Stable. |
| Mode (MAP) | (α-1)/(α+β-2) | Undefined for α<1 or β<1. Sharper than mean. |
| Median | ≈ (α-1/3)/(α+β-2/3) | Approximation. Between mean and mode. |

**Decision**: Use **posterior mean** as the point estimate. It is always defined (even for
the uniform prior), stable, and the most commonly used Bayesian point estimate. The MAP
is undefined for the initial prior Beta(1,1) and would require special-casing.

### 4.6 Prior Selection Rationale

| Prior | α | β | Interpretation | Pros | Cons |
|-------|---|---|---------------|------|------|
| Uniform | 1 | 1 | No opinion | Simple, neutral | Slightly biased toward 0.5 for tiny samples |
| Jeffreys | 0.5 | 0.5 | Minimally informative | Theoretically optimal | Biased toward 0/1 for tiny samples |
| Weak informative | 2 | 2 | Slight belief in 0.5 | Regularizes extreme estimates | Assumes patterns are ~50% frequent |

**Decision**: Beta(1, 1) uniform prior. Rationale:
1. Simplest to explain and implement
2. No assumption about pattern frequency (some patterns are 90%, some are 10%)
3. The prior is quickly overwhelmed by data (after 10 files, the prior contributes <10% to the posterior)
4. Consistent with M34 and 06-DETECTOR-SYSTEM.md §7 specifications

### 4.7 Numerical Stability

Edge cases that must be handled:

```rust
/// Safe posterior mean computation with edge case handling.
pub fn posterior_mean(alpha: f64, beta: f64) -> f64 {
    let total = alpha + beta;
    if total < f64::EPSILON {
        return 0.5; // Degenerate case — return uniform mean
    }
    alpha / total
}

/// Safe credible interval with edge case handling.
pub fn safe_credible_interval(alpha: f64, beta: f64) -> (f64, f64, f64) {
    // statrs panics if alpha <= 0 or beta <= 0
    let a = alpha.max(f64::EPSILON);
    let b = beta.max(f64::EPSILON);
    credible_interval(a, b)
}
```

**Overflow protection**: After many scans, α and β can grow very large. For a project
scanned daily for a year with 1000 files: α could reach ~365,000. This is fine for f64
(max ~1.8×10³⁰⁸). No overflow concern in practice.

---

## 5. V2 Scoring Formula

### 5.1 The 5-Factor Model

```rust
/// Compute final confidence score.
/// This is the canonical v2 scoring formula.
pub fn compute_score(conf: &BayesianConfidence) -> f64 {
    let posterior = posterior_mean(conf.alpha, conf.beta);

    let weighted = conf.frequency * 0.30
        + conf.consistency * 0.25
        + conf.age_factor * 0.10
        + conf.spread * 0.15
        + momentum_normalized(conf.momentum) * 0.20;

    // Blend posterior with weighted factors.
    // Posterior weight increases with sample size — dominates when evidence is strong.
    let sample_size = (conf.alpha + conf.beta - 2.0).max(0.0); // Subtract prior
    let posterior_weight = (sample_size / (sample_size + 10.0)).min(0.5);

    let raw = posterior * posterior_weight + weighted * (1.0 - posterior_weight);
    raw.clamp(0.0, 1.0)
}

/// Normalize momentum from [-1, 1] to [0, 1] for scoring.
fn momentum_normalized(momentum: f64) -> f64 {
    ((momentum + 1.0) / 2.0).clamp(0.0, 1.0)
}
```

### 5.2 Weight Rationale

| Factor | V1 Weight | V2 Weight | Change | Rationale |
|--------|-----------|-----------|--------|-----------|
| Frequency | 0.40 | 0.30 | -0.10 | Reduced to make room for momentum. Still the largest single factor. |
| Consistency | 0.30 | 0.25 | -0.05 | Slightly reduced. Consistency matters but momentum captures some of its signal. |
| Age Factor | 0.15 | 0.10 | -0.05 | Reduced because momentum subsumes some of age's purpose (trend detection). Decay (§6) makes age more dynamic. |
| Spread | 0.15 | 0.15 | 0.00 | Unchanged. Directory spread is an independent signal not captured by other factors. |
| Momentum | — | 0.20 | +0.20 | New. Convention migration is a critical enterprise scenario (R3). |
| **Total** | **1.00** | **1.00** | | Weights sum to 1.0. |

### 5.3 Posterior Blending

The posterior mean is blended with the weighted factors using a sample-size-adaptive weight:

```
posterior_weight = min(0.5, sample_size / (sample_size + 10))
```

| Sample Size (n) | Posterior Weight | Weighted Factors Weight |
|-----------------|-----------------|------------------------|
| 0 (prior only) | 0.00 | 1.00 |
| 5 | 0.33 | 0.67 |
| 10 | 0.50 | 0.50 |
| 50 | 0.50 | 0.50 |
| 1000 | 0.50 | 0.50 |

**Design choice**: Posterior weight caps at 0.50. The weighted factors always contribute
at least 50% of the final score. This prevents the posterior from completely dominating —
the 5 factors capture dimensions (consistency, spread, momentum) that the posterior mean
alone does not encode.

**Why 10 as the blending constant**: At n=10, the posterior has seen enough data to be
meaningful (credible interval is reasonably narrow). Below n=10, the weighted factors
provide stability. The value 10 aligns with the minimum sample size for outlier detection.

### 5.4 V1 Compatibility Scoring

During the migration period, both v1 and v2 scores are computed for comparison:

```rust
/// V1 fallback: compute score using v1's 4-factor formula.
/// Used during migration period for comparison and validation.
pub fn score_v1_compat(conf: &BayesianConfidence) -> f64 {
    let raw = conf.frequency * 0.40
        + conf.consistency * 0.30
        + conf.age_factor * 0.15
        + conf.spread * 0.15;
    raw.clamp(0.0, 1.0)
}
```

The v1 compat score is stored alongside the v2 score during migration. When the
`bayesian_confidence` feature flag is disabled, the system falls back to v1 scoring.
This ensures zero-risk rollback.

### 5.5 Factor Computation (Preserved from V1)

All four original factors are computed identically to v1:

```rust
/// Frequency: proportion of applicable locations where pattern appears.
pub fn compute_frequency(occurrences: usize, total_locations: usize) -> f64 {
    if total_locations == 0 { return 0.0; }
    (occurrences as f64 / total_locations as f64).clamp(0.0, 1.0)
}

/// Consistency: inverted variance. Higher = more uniform implementation.
pub fn compute_consistency(variance: f64) -> f64 {
    let clamped = variance.clamp(0.0, 1.0);
    1.0 - clamped
}

/// Age factor: linear scaling from minAgeFactor to 1.0 over maxAgeDays.
/// V2 addition: temporal decay applied separately (§6).
pub fn compute_age_factor(days_since_first_seen: f64, config: &AgeConfig) -> f64 {
    if days_since_first_seen <= 0.0 {
        return config.min_age_factor;
    }
    if days_since_first_seen >= config.max_age_days {
        return 1.0;
    }
    let normalized = days_since_first_seen / config.max_age_days;
    config.min_age_factor + normalized * (1.0 - config.min_age_factor)
}

/// Spread: proportion of files containing the pattern.
pub fn compute_spread(file_count: usize, total_files: usize) -> f64 {
    if total_files == 0 { return 0.0; }
    (file_count as f64 / total_files as f64).clamp(0.0, 1.0)
}
```

---

## 6. Temporal Decay

### 6.1 The Problem

V1's age factor reaches 1.0 after 30 days and stays there forever. A pattern that was
dominant 6 months ago but is now declining still gets full age contribution. Combined with
no momentum signal, v1 actively fights convention migrations by maintaining high confidence
on declining patterns.

### 6.2 Decay Mechanism

When a pattern's frequency declines between consecutive scans, the age factor is reduced
proportionally:

```rust
/// Apply temporal decay when frequency declines.
/// Called after each scan with current and previous frequency.
pub fn apply_decay(
    age_factor: f64,
    current_freq: f64,
    previous_freq: f64,
) -> f64 {
    if previous_freq <= 0.0 || current_freq >= previous_freq {
        return age_factor; // No decay — frequency stable or rising
    }
    let decay_factor = current_freq / previous_freq;
    (age_factor * decay_factor).max(0.0)
}
```

**Example**:
```
Scan 1: frequency=0.80, age_factor=1.0
Scan 2: frequency=0.60 → decay_factor = 0.60/0.80 = 0.75 → age_factor = 0.75
Scan 3: frequency=0.30 → decay_factor = 0.30/0.60 = 0.50 → age_factor = 0.375
```

The age factor decays multiplicatively. A pattern that drops from 80% to 30% over two
scans sees its age contribution drop from 1.0 to 0.375 — a 62.5% reduction.

### 6.3 Decay + Momentum Interaction

Decay and momentum work together but on different axes:

- **Decay** reduces the age factor (one of 5 scoring factors, weight 0.10)
- **Momentum** directly captures trend direction (weight 0.20)

A declining pattern gets hit twice: its age factor decays AND its momentum goes negative.
This is intentional — it ensures declining patterns lose confidence quickly enough to
not block convention migrations.

### 6.4 Decay Floor

The age factor can decay to 0.0 but the overall score cannot go below 0.0 (clamped).
In practice, a pattern with 0.0 age factor still has frequency, consistency, spread,
and momentum contributing to its score. The decay only affects the age dimension.

### 6.5 No Decay on Stable/Rising Patterns

If `current_freq >= previous_freq`, no decay is applied. The age factor retains its
current value. This means a stable pattern at 1.0 age factor stays at 1.0 — identical
to v1 behavior for non-declining patterns.

---

## 7. Momentum Signal

### 7.1 Computation

Momentum captures the direction and magnitude of frequency change between consecutive scans:

```rust
/// Compute momentum from current and previous frequency.
/// Returns value in [-1.0, 1.0].
pub fn compute_momentum(current_freq: f64, previous_freq: f64) -> f64 {
    if previous_freq < 0.01 {
        return 0.0; // Avoid division by near-zero
    }
    let raw = (current_freq - previous_freq) / previous_freq;
    raw.clamp(-1.0, 1.0)
}
```

**Examples**:
| Current | Previous | Raw | Clamped | Interpretation |
|---------|----------|-----|---------|---------------|
| 0.80 | 0.80 | 0.00 | 0.00 | Stable |
| 0.90 | 0.60 | +0.50 | +0.50 | Rising fast |
| 0.40 | 0.80 | -0.50 | -0.50 | Declining fast |
| 0.05 | 0.80 | -0.94 | -0.94 | Near-abandoned |
| 0.80 | 0.00 | 0.00 | 0.00 | New pattern (no history) |

### 7.2 Normalization for Scoring

Momentum is in [-1, 1] but the scoring formula needs [0, 1]:

```
momentum_normalized = (momentum + 1) / 2
```

| Momentum | Normalized | Contribution (×0.20 weight) |
|----------|-----------|---------------------------|
| -1.0 | 0.00 | 0.000 |
| -0.5 | 0.25 | 0.050 |
| 0.0 | 0.50 | 0.100 |
| +0.5 | 0.75 | 0.150 |
| +1.0 | 1.00 | 0.200 |

A stable pattern (momentum=0.0) contributes 0.10 to the score from momentum alone.
A rapidly rising pattern contributes up to 0.20. A rapidly declining pattern contributes 0.00.

### 7.3 Activation Rules

Momentum only activates after sufficient data to avoid noise:

```rust
pub struct MomentumConfig {
    pub min_scans: usize,       // 3 — minimum scan history entries
    pub min_files: usize,       // 50 — minimum project size
}

impl Default for MomentumConfig {
    fn default() -> Self {
        Self { min_scans: 3, min_files: 50 }
    }
}

/// Check if momentum should be active for this pattern.
pub fn momentum_active(scan_count: usize, total_files: usize, config: &MomentumConfig) -> bool {
    scan_count >= config.min_scans && total_files >= config.min_files
}
```

When momentum is inactive, the momentum factor defaults to 0.0 (neutral). The 0.20 weight
is redistributed: momentum's contribution becomes 0.10 (the neutral midpoint), which is
equivalent to "no trend information."

**Rationale for thresholds**:
- **3 scans**: Need at least 2 data points for a trend, plus 1 for confirmation. With only
  1-2 scans, frequency changes could be noise (e.g., scanning a subset of files).
- **50 files**: In small projects (<50 files), a single file addition/removal can swing
  frequency by 2%+. Momentum would be noisy and misleading.

### 7.4 Convention Migration Scenario

This is the motivating use case for momentum (from R3 and 06-DETECTOR-SYSTEM.md §9):

```
Scan 1: Old pattern 80%, New pattern 20%
  Old: momentum=0.0 (no history), confidence=high
  New: momentum=0.0 (no history), confidence=low

Scan 2: Old 60%, New 40%
  Old: momentum=-0.25 (declining), confidence drops
  New: momentum=+1.0 (rising), confidence rises

Scan 3: Old 30%, New 70%
  Old: momentum=-0.50 (declining fast), confidence=low
  New: momentum=+0.75 (rising), confidence=high → becomes dominant

Without momentum, Drift would flag the new pattern as violations through all 3 scans.
With momentum, the crossover happens naturally at Scan 3.
```

### 7.5 Multi-Scan Momentum (Smoothing)

For patterns with long history, momentum can be smoothed over the last N scans to reduce
noise from single-scan fluctuations:

```rust
/// Compute smoothed momentum from frequency history.
/// Uses exponential moving average with decay factor.
pub fn compute_smoothed_momentum(
    history: &[(f64, f64)], // (current_freq, previous_freq) pairs, newest first
    decay: f64,             // 0.7 — weight of most recent observation
) -> f64 {
    if history.is_empty() { return 0.0; }

    let mut weighted_sum = 0.0;
    let mut weight_total = 0.0;
    let mut weight = 1.0;

    for (current, previous) in history.iter() {
        let m = compute_momentum(*current, *previous);
        weighted_sum += m * weight;
        weight_total += weight;
        weight *= decay;
    }

    if weight_total < f64::EPSILON { return 0.0; }
    (weighted_sum / weight_total).clamp(-1.0, 1.0)
}
```

**Decision**: Use simple (non-smoothed) momentum for v2 launch. Smoothed momentum is a
future optimization. The simple version is easier to reason about, debug, and explain.
The `pattern_scan_history` table stores all the data needed for smoothing later.


---

## 8. Graduated Confidence Tiers

### 8.1 V1 → V2 Tier Comparison

V1 used static score thresholds. V2 uses credible interval width as the primary
discriminator, with posterior mean as a secondary signal. This is fundamentally different:
v1 asks "is the score high enough?" while v2 asks "how certain are we about this score?"

| | V1 | V2 |
|---|---|---|
| Basis | Composite score thresholds | Credible interval width + posterior mean |
| Tiers | 4 (high/medium/low/uncertain) | 4 (Established/Emerging/Tentative/Uncertain) |
| Sample size awareness | None | Built-in (CI width narrows with more data) |
| Threshold type | Fixed score cutoffs | Dual criteria (mean + CI width) |

### 8.2 V2 Tier Definitions

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConfidenceTier {
    /// High confidence, narrow uncertainty. Safe to enforce.
    /// Criteria: posterior_mean > 0.7 AND ci_width < 0.15
    Established,

    /// Moderate confidence, moderate uncertainty. Worth flagging.
    /// Criteria: posterior_mean > 0.5 AND ci_width < 0.25
    Emerging,

    /// Low confidence, wide uncertainty. Informational only.
    /// Criteria: posterior_mean > 0.3 AND ci_width < 0.40
    Tentative,

    /// Insufficient evidence or very wide uncertainty.
    /// Criteria: everything else
    Uncertain,
}

impl ConfidenceTier {
    pub fn classify(posterior_mean: f64, ci_width: f64) -> Self {
        if posterior_mean > 0.7 && ci_width < 0.15 {
            ConfidenceTier::Established
        } else if posterior_mean > 0.5 && ci_width < 0.25 {
            ConfidenceTier::Emerging
        } else if posterior_mean > 0.3 && ci_width < 0.40 {
            ConfidenceTier::Tentative
        } else {
            ConfidenceTier::Uncertain
        }
    }

    /// Map to enforcement behavior.
    pub fn enforcement(&self) -> EnforcementLevel {
        match self {
            ConfidenceTier::Established => EnforcementLevel::Enforce,
            ConfidenceTier::Emerging => EnforcementLevel::Flag,
            ConfidenceTier::Tentative => EnforcementLevel::Inform,
            ConfidenceTier::Uncertain => EnforcementLevel::Silent,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementLevel {
    Enforce, // Violations are errors/warnings
    Flag,    // Violations are informational with suggested action
    Inform,  // Mentioned in reports but no violation generated
    Silent,  // Not reported
}
```

### 8.3 Tier Progression Examples

**New pattern, first scan (10 files, 8 matches)**:
```
α = 1 + 8 = 9, β = 1 + 2 = 3
posterior_mean = 9/12 = 0.75
CI_95 = [0.47, 0.93], width = 0.46
Tier: Tentative (mean > 0.3 but CI too wide)
```

**Same pattern, after 5 scans (50 files, 40 matches cumulative)**:
```
α = 1 + 40 = 41, β = 1 + 10 = 11
posterior_mean = 41/52 = 0.788
CI_95 = [0.66, 0.88], width = 0.22
Tier: Emerging (mean > 0.5, CI < 0.25)
```

**Same pattern, after 20 scans (200 files, 160 matches cumulative)**:
```
α = 1 + 160 = 161, β = 1 + 40 = 41
posterior_mean = 161/202 = 0.797
CI_95 = [0.74, 0.85], width = 0.11
Tier: Established (mean > 0.7, CI < 0.15)
```

The pattern naturally progresses from Tentative → Emerging → Established as evidence
accumulates. No manual promotion needed.

### 8.4 V1 Level Mapping

For backward compatibility in APIs and reports, v2 tiers map to v1 levels:

```rust
impl ConfidenceTier {
    pub fn to_v1_level(&self) -> &'static str {
        match self {
            ConfidenceTier::Established => "high",
            ConfidenceTier::Emerging => "medium",
            ConfidenceTier::Tentative => "low",
            ConfidenceTier::Uncertain => "uncertain",
        }
    }
}
```

### 8.5 Generated Column in SQLite

The `patterns` table has a generated column for tier-based indexing (from 02-STORAGE-V2-PREP.md):

```sql
confidence_level TEXT GENERATED ALWAYS AS (
    CASE
        WHEN confidence_score >= 0.85 THEN 'high'
        WHEN confidence_score >= 0.70 THEN 'medium'
        WHEN confidence_score >= 0.50 THEN 'low'
        ELSE 'uncertain'
    END
) VIRTUAL
```

**Note**: This generated column uses v1-style score thresholds for the virtual column because
SQLite generated columns cannot call Rust functions. The actual tier classification happens
in Rust using the full Bayesian model (posterior mean + CI width). The generated column is
an approximation for SQL-level filtering. The Rust-computed tier is authoritative.

**Decision**: Keep the generated column as-is for SQL query performance. Add a separate
`confidence_tier TEXT` column that Rust writes explicitly after computing the true Bayesian
tier. Queries that need exact tier use `confidence_tier`. Queries that need approximate
filtering use the generated `confidence_level`.

---

## 9. Bayesian Convention Learning

### 9.1 V1 → V2 Comparison

| Aspect | V1 (ValueDistribution) | V2 (BayesianConvention) |
|--------|----------------------|------------------------|
| Model | Binary: dominant at 60% or not | Continuous: Beta posterior per convention |
| Threshold | Fixed 60% file percentage | Posterior confidence ≥ 0.7 |
| Sample size | minOccurrences=3, minFiles=2 | minOccurrences=10, minFiles=5 |
| Categories | None (all conventions equal) | 5 categories (Universal → Contested) |
| Trend tracking | None | Rising/Stable/Declining |
| Contested detection | None (both below 60% → no learning) | Explicit detection within 15% |
| Output | Single dominant or null | All conventions with strengths |

### 9.2 BayesianConvention Type

```rust
/// Bayesian convention strength. Replaces v1's binary threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BayesianConvention {
    /// The convention value (e.g., "camelCase", "tabs", "prisma")
    pub value: String,
    /// Beta distribution α (successes + prior)
    pub alpha: f64,
    /// Beta distribution β (failures + prior)
    pub beta: f64,
    /// Absolute count of files using this convention
    pub file_count: usize,
    /// Total files in scope
    pub total_files: usize,
    /// Trend direction
    pub trend: ConventionTrend,
    /// Convention category (computed from frequency + trend)
    pub category: ConventionCategory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConventionTrend {
    Rising,    // Frequency increasing across recent scans
    Stable,    // Frequency within ±5% across recent scans
    Declining, // Frequency decreasing across recent scans
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConventionCategory {
    /// >90% frequency, high confidence — universal convention
    Universal,
    /// >60% frequency — project-level convention
    ProjectSpecific,
    /// <60% but rising trend — convention gaining adoption
    Emerging,
    /// Was dominant (>60%), now declining — legacy convention
    Legacy,
    /// Two conventions within 15% frequency — team should decide
    Contested,
}
```

### 9.3 Convention Classification

```rust
impl BayesianConvention {
    /// Posterior mean: point estimate of convention frequency.
    pub fn confidence(&self) -> f64 {
        self.alpha / (self.alpha + self.beta)
    }

    /// Raw frequency: file_count / total_files.
    pub fn frequency(&self) -> f64 {
        if self.total_files == 0 { return 0.0; }
        self.file_count as f64 / self.total_files as f64
    }

    /// Bayesian update with new observation.
    pub fn observe(&mut self, matches: bool) {
        if matches {
            self.alpha += 1.0;
            self.file_count += 1;
        } else {
            self.beta += 1.0;
        }
        self.total_files += 1;
    }

    /// Classify convention category based on frequency and trend.
    pub fn classify(&self) -> ConventionCategory {
        let freq = self.frequency();
        match (freq, self.trend) {
            (f, _) if f >= 0.90 => ConventionCategory::Universal,
            (f, ConventionTrend::Declining) if f >= 0.30 => ConventionCategory::Legacy,
            (f, ConventionTrend::Rising) if f < 0.60 => ConventionCategory::Emerging,
            (f, _) if f >= 0.60 => ConventionCategory::ProjectSpecific,
            _ => ConventionCategory::Contested, // Determined by multi-convention analysis
        }
    }
}
```

### 9.4 Contested Convention Detection

When two conventions are within 15% frequency of each other, flag as contested
instead of enforcing either one:

```rust
#[derive(Debug, Clone, Serialize)]
pub struct ContestedPair {
    pub convention_a: String,
    pub convention_b: String,
    pub frequency_a: f64,
    pub frequency_b: f64,
    pub recommendation: &'static str,
}

/// Detect contested conventions from a set of conventions for the same key.
pub fn detect_contested(conventions: &[BayesianConvention]) -> Vec<ContestedPair> {
    let mut contested = Vec::new();

    // Sort by frequency descending
    let mut sorted: Vec<_> = conventions.iter().collect();
    sorted.sort_by(|a, b| b.frequency().partial_cmp(&a.frequency()).unwrap_or(std::cmp::Ordering::Equal));

    for window in sorted.windows(2) {
        let diff = window[0].frequency() - window[1].frequency();
        if diff < 0.15 && window[0].frequency() > 0.25 {
            contested.push(ContestedPair {
                convention_a: window[0].value.clone(),
                convention_b: window[1].value.clone(),
                frequency_a: window[0].frequency(),
                frequency_b: window[1].frequency(),
                recommendation: "Team should make a deliberate choice between these conventions",
            });
        }
    }

    contested
}
```

**Behavior when contested**: Instead of generating violations against either convention,
the system generates an "inconsistency" finding. This is surfaced in reports and MCP tools
as a team decision point, not an enforcement action.

### 9.5 Minimum Evidence Requirements

```rust
#[derive(Debug, Clone)]
pub struct LearningConfig {
    /// Minimum files that must contain the convention (up from v1's 2)
    pub min_files: usize,           // 5
    /// Minimum total occurrences across all files (up from v1's 3)
    pub min_occurrences: usize,     // 10
    /// Minimum Bayesian posterior confidence to consider a convention learned
    pub min_confidence: f64,        // 0.7
    /// Frequency difference threshold for contested detection
    pub contested_threshold: f64,   // 0.15
    /// Beta prior α (uniform)
    pub prior_alpha: f64,           // 1.0
    /// Beta prior β (uniform)
    pub prior_beta: f64,            // 1.0
}

impl Default for LearningConfig {
    fn default() -> Self {
        Self {
            min_files: 5,
            min_occurrences: 10,
            min_confidence: 0.7,
            contested_threshold: 0.15,
            prior_alpha: 1.0,
            prior_beta: 1.0,
        }
    }
}
```

**Rationale for increased minimums**:
- **min_files: 5** (was 2): With only 2 files, a 100% frequency is meaningless. 5 files
  provides a minimally meaningful sample. The Beta posterior at 5/5 gives mean=0.857 with
  CI width ~0.30 — still Tentative tier, not Established.
- **min_occurrences: 10** (was 3): 3 occurrences is too few to distinguish signal from noise.
  10 occurrences across 5+ files provides a reasonable evidence base.
- **min_confidence: 0.7** (was 0.6 implicit): The Bayesian posterior naturally handles this —
  a convention needs enough evidence to push the posterior above 0.7. This replaces the
  arbitrary 60% frequency threshold with a principled Bayesian criterion.

### 9.6 Convention Trend Computation

```rust
/// Compute trend from frequency history.
/// Requires at least 2 data points.
pub fn compute_trend(
    frequency_history: &[f64], // Oldest first
    stability_threshold: f64,  // 0.05 — within ±5% = stable
) -> ConventionTrend {
    if frequency_history.len() < 2 {
        return ConventionTrend::Stable; // Not enough data
    }

    let recent = frequency_history.last().unwrap();
    let previous = frequency_history[frequency_history.len() - 2];

    let change = recent - previous;
    if change > stability_threshold {
        ConventionTrend::Rising
    } else if change < -stability_threshold {
        ConventionTrend::Declining
    } else {
        ConventionTrend::Stable
    }
}
```

---

## 10. Outlier Detection Integration

### 10.1 V1 → V2 Changes

| Aspect | V1 | V2 |
|--------|---|---|
| Z-Score threshold | 2.0 | 2.5 |
| Min sample size | 3 | 10 |
| Small sample method | IQR only | Grubbs' test (10 ≤ n < 30) |
| IQR role | Primary (n < 30) | Supplementary (robustness check) |
| Iterative detection | No | Yes (3-iteration cap) |
| Significance levels | 3 (high/medium/low) | 4 (critical/high/moderate/low) |

### 10.2 Method Selection

```rust
/// Select and run outlier detection based on sample size.
pub fn detect_outliers(values: &[f64], config: &OutlierConfig) -> Vec<OutlierResult> {
    let n = values.len();

    if n < config.min_sample_size {
        return vec![]; // Not enough data for statistical outlier detection
    }

    match n {
        0..=9 => vec![],                                         // Too few samples
        10..=29 => grubbs_test(values, config.alpha),            // Small sample: Grubbs'
        30.. => z_score_iterative(values, config.z_threshold),   // Large sample: Z-Score
    }
}
```

### 10.3 Z-Score with Iterative Masking (n ≥ 30)

V1 used a single-pass Z-Score. V2 uses iterative masking to handle the "masking effect"
where extreme outliers inflate the standard deviation, hiding moderate outliers:

```rust
/// Z-Score outlier detection with iterative masking.
/// Removes detected outliers and recomputes, up to max_iterations.
pub fn z_score_iterative(values: &[f64], threshold: f64) -> Vec<OutlierResult> {
    let mut outliers = Vec::new();
    let mut remaining: Vec<(usize, f64)> = values.iter().copied().enumerate().collect();
    let max_iterations = 3;

    for iteration in 0..max_iterations {
        let vals: Vec<f64> = remaining.iter().map(|(_, v)| *v).collect();
        if vals.len() < 2 { break; }

        let mean = vals.iter().sum::<f64>() / vals.len() as f64;
        let std_dev = (vals.iter().map(|v| (v - mean).powi(2)).sum::<f64>()
            / (vals.len() - 1) as f64).sqrt();

        if std_dev < f64::EPSILON { break; } // All values identical

        let mut found_new = false;
        remaining.retain(|(idx, v)| {
            let z = (v - mean) / std_dev;
            if z.abs() > threshold {
                outliers.push(OutlierResult {
                    index: *idx,
                    value: *v,
                    z_score: z,
                    method: OutlierMethod::ZScore,
                    significance: classify_significance(z.abs()),
                    iteration,
                });
                found_new = true;
                false
            } else {
                true
            }
        });

        if !found_new { break; }
    }

    outliers
}

fn classify_significance(z_abs: f64) -> Significance {
    if z_abs > 3.5 { Significance::Critical }
    else if z_abs > 3.0 { Significance::High }
    else if z_abs > 2.5 { Significance::Moderate }
    else { Significance::Low }
}
```

### 10.4 Grubbs' Test (10 ≤ n < 30)

Grubbs' test is designed for small samples where Z-Score is unreliable:

```rust
/// Grubbs' test for outlier detection in small samples.
/// Uses t-distribution critical value for statistical rigor.
pub fn grubbs_test(values: &[f64], alpha: f64) -> Vec<OutlierResult> {
    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;
    let std_dev = (values.iter().map(|v| (v - mean).powi(2)).sum::<f64>()
        / (n - 1.0)).sqrt();

    if std_dev < f64::EPSILON { return vec![]; }

    let t_crit = t_critical(alpha / (2.0 * n), (n - 2.0) as u32);
    let grubbs_crit = ((n - 1.0) / n.sqrt())
        * (t_crit.powi(2) / (n - 2.0 + t_crit.powi(2))).sqrt();

    values.iter().enumerate()
        .filter_map(|(i, v)| {
            let g = ((v - mean) / std_dev).abs();
            if g > grubbs_crit {
                Some(OutlierResult {
                    index: i,
                    value: *v,
                    z_score: g,
                    method: OutlierMethod::Grubbs,
                    significance: classify_significance(g),
                    iteration: 0,
                })
            } else {
                None
            }
        })
        .collect()
}
```

### 10.5 IQR Method (Supplementary)

Retained from v1 as a supplementary method. IQR is resistant to extreme outliers
that inflate standard deviation, making it a useful cross-check:

```rust
/// IQR-based outlier detection. Supplementary to Z-Score/Grubbs'.
pub fn iqr_outliers(values: &[f64], multiplier: f64) -> Vec<OutlierResult> {
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let q1 = percentile(&sorted, 25.0);
    let q3 = percentile(&sorted, 75.0);
    let iqr = q3 - q1;

    if iqr < f64::EPSILON { return vec![]; }

    let lower = q1 - multiplier * iqr;
    let upper = q3 + multiplier * iqr;

    values.iter().enumerate()
        .filter_map(|(i, v)| {
            if *v < lower || *v > upper {
                Some(OutlierResult {
                    index: i,
                    value: *v,
                    z_score: 0.0,
                    method: OutlierMethod::Iqr,
                    significance: if *v < lower - iqr || *v > upper + iqr {
                        Significance::High
                    } else {
                        Significance::Moderate
                    },
                    iteration: 0,
                })
            } else {
                None
            }
        })
        .collect()
}
```

### 10.6 Rule-Based Detection (Preserved from V1)

Custom rules registered per detector. These are non-statistical, domain-specific checks:

```rust
pub struct OutlierRule {
    pub id: String,
    pub check: Box<dyn Fn(&f64, &OutlierContext) -> bool + Send + Sync>,
    pub reason: String,
    pub significance: Significance,
}
```

Rule-based detection runs alongside statistical methods. Results are merged and deduplicated.

### 10.7 Outlier Configuration

```rust
#[derive(Debug, Clone)]
pub struct OutlierConfig {
    pub min_sample_size: usize,  // 10 (up from v1's 3)
    pub z_threshold: f64,        // 2.5 (up from v1's 2.0)
    pub iqr_multiplier: f64,     // 1.5 (standard)
    pub alpha: f64,              // 0.05 (for Grubbs' test)
    pub max_iterations: usize,   // 3 (iterative masking cap)
    pub sensitivity: f64,        // 0.7 (preserved from v1)
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
        }
    }
}
```

### 10.8 Sensitivity Adjustment (Preserved from V1)

```rust
/// Adjust threshold based on sensitivity setting.
/// Sensitivity 1.0 = strictest (lowest threshold), 0.0 = most lenient.
pub fn adjust_threshold(base_threshold: f64, sensitivity: f64) -> f64 {
    base_threshold * (1.0 + (1.0 - sensitivity))
}
```

### 10.9 Outlier Types (Preserved from V1)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutlierType {
    Structural,    // File/directory structure deviation
    Syntactic,     // Code syntax deviation
    Semantic,      // Meaning/intent deviation
    Stylistic,     // Style/formatting deviation
    Missing,       // Expected element absent
    Extra,         // Unexpected element present
    Inconsistent,  // Contradicts established pattern
}
```

---

## 11. Feedback Loop Integration (AD9)

### 11.1 Architectural Decision AD9

From DRIFT-V2-FULL-SYSTEM-AUDIT.md:

> **AD9: Feedback Loop Architecture (Tricorder-style)** — "Not useful" / "Useful" signals
> on every violation. Track effective false-positive rate per detector (<5% target).
> Detectors with >10% FP rate get alert, >20% for 30+ days get auto-disabled.
> Developer action (fix, ignore, approve) feeds back into pattern confidence.

### 11.2 How Feedback Affects Confidence

Developer actions on violations feed back into the Bayesian model:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationAction {
    Fixed,      // Developer fixed the violation → pattern is valid
    Ignored,    // Developer ignored → possible false positive
    Approved,   // Developer approved the deviation → pattern may be wrong
    NotUseful,  // Explicit "not useful" signal → likely false positive
    Useful,     // Explicit "useful" signal → pattern is valid
}

/// Adjust confidence based on developer feedback.
/// This is a soft signal — it nudges the posterior, not overrides it.
pub fn apply_feedback(
    alpha: &mut f64,
    beta: &mut f64,
    action: ViolationAction,
    feedback_weight: f64, // 0.1 — each feedback event is worth 0.1 pseudo-observations
) {
    match action {
        ViolationAction::Fixed | ViolationAction::Useful => {
            // Positive signal: pattern is valid, violation was correct
            *alpha += feedback_weight;
        }
        ViolationAction::Ignored => {
            // Weak negative signal: might be false positive, might be lazy
            *beta += feedback_weight * 0.5;
        }
        ViolationAction::Approved | ViolationAction::NotUseful => {
            // Strong negative signal: pattern may be wrong here
            *beta += feedback_weight;
        }
    }
}
```

**Design choice**: Feedback weight is 0.1 (one-tenth of a real observation). This means
10 "not useful" signals have the same effect as 1 file where the pattern is absent.
This prevents a single frustrated developer from tanking a well-established pattern's
confidence. The evidence from actual code (file observations) always dominates.

### 11.3 Detector Health Metrics

Per AD9, each detector tracks its effective false-positive rate:

```rust
pub struct DetectorHealth {
    pub detector_id: String,
    pub total_violations: usize,
    pub fixed_count: usize,
    pub ignored_count: usize,
    pub approved_count: usize,
    pub not_useful_count: usize,
    pub useful_count: usize,
    pub fp_rate: f64,           // (ignored + not_useful + approved) / total
    pub status: DetectorStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectorStatus {
    Healthy,       // FP rate < 5%
    Warning,       // FP rate 5-10%
    Alert,         // FP rate 10-20%
    AutoDisabled,  // FP rate > 20% for 30+ days
}
```

### 11.4 Confidence ↔ Feedback Data Flow

```
Developer acts on violation
  → ViolationAction recorded in drift.db
  → Feedback aggregated per pattern per detector
  → apply_feedback() nudges α/β
  → Next score computation reflects feedback
  → Detector health metrics updated
  → Detectors exceeding FP threshold get alert/disabled
```

This is a slow loop — it operates on human timescales (days/weeks), not scan timescales
(seconds/minutes). The Bayesian model naturally handles this: feedback is just another
source of observations, weighted appropriately.


---

## 12. Core Data Types

### 12.1 BayesianConfidence (Primary Scoring Type)

```rust
/// Complete Bayesian confidence state for a pattern.
/// This is the primary type consumed by all downstream systems.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BayesianConfidence {
    /// Beta distribution α (prior + cumulative successes)
    pub alpha: f64,
    /// Beta distribution β (prior + cumulative failures)
    pub beta: f64,
    /// Frequency: proportion of applicable locations (0.0-1.0)
    pub frequency: f64,
    /// Consistency: inverted variance (0.0-1.0)
    pub consistency: f64,
    /// Age factor: linear scaling with temporal decay (0.0-1.0)
    pub age_factor: f64,
    /// Spread: proportion of files containing pattern (0.0-1.0)
    pub spread: f64,
    /// Momentum: trend direction and magnitude (-1.0 to 1.0)
    pub momentum: f64,
    /// Computed composite score (0.0-1.0)
    pub score: f64,
    /// Graduated confidence tier
    pub tier: ConfidenceTier,
    /// 95% credible interval
    pub ci_lower: f64,
    pub ci_upper: f64,
    pub ci_width: f64,
    /// V1 compatibility score (for migration period)
    pub score_v1: f64,
}
```

### 12.2 ConfidenceInput (Scoring Input)

```rust
/// Input data for confidence score computation.
/// Produced by the detector system and pattern aggregation.
#[derive(Debug, Clone)]
pub struct ConfidenceInput {
    /// Number of pattern occurrences across all files
    pub occurrences: usize,
    /// Total applicable locations (files × applicable positions)
    pub total_locations: usize,
    /// Implementation variance (0.0 = perfectly consistent)
    pub variance: f64,
    /// Days since pattern was first seen
    pub days_since_first_seen: f64,
    /// Number of files containing the pattern
    pub file_count: usize,
    /// Total files in scope
    pub total_files: usize,
    /// Previous scan frequency (for momentum/decay). None if first scan.
    pub previous_frequency: Option<f64>,
    /// Number of scans with frequency history (for momentum activation)
    pub scan_count: usize,
    /// Current α from storage (for incremental update)
    pub current_alpha: f64,
    /// Current β from storage (for incremental update)
    pub current_beta: f64,
}
```

### 12.3 ConventionStrength (Convention Learning Output)

```rust
/// Convention strength assessment. Output of Bayesian convention learning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConventionStrength {
    /// The convention value (e.g., "camelCase", "tabs", "prisma")
    pub value: String,
    /// Raw frequency: file_count / total_files
    pub frequency: f64,
    /// Absolute file count
    pub file_count: usize,
    /// Bayesian posterior confidence
    pub confidence: f64,
    /// Trend direction
    pub trend: ConventionTrend,
    /// Convention category
    pub category: ConventionCategory,
    /// Whether this convention is contested with another
    pub is_contested: bool,
    /// The competing convention (if contested)
    pub contested_with: Option<String>,
}
```

### 12.4 OutlierResult

```rust
/// Result of outlier detection for a single data point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutlierResult {
    /// Index in the original values array
    pub index: usize,
    /// The outlier value
    pub value: f64,
    /// Z-score or Grubbs' statistic (0.0 for IQR method)
    pub z_score: f64,
    /// Detection method used
    pub method: OutlierMethod,
    /// Significance level
    pub significance: Significance,
    /// Iteration in which this outlier was detected (for iterative Z-Score)
    pub iteration: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutlierMethod {
    ZScore,   // n ≥ 30, iterative masking
    Grubbs,   // 10 ≤ n < 30
    Iqr,      // Supplementary
    RuleBased, // Custom detector rules
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Significance {
    Low,       // Barely significant
    Moderate,  // Notable deviation
    High,      // Strong deviation
    Critical,  // Extreme deviation
}
```

### 12.5 Configuration Types

```rust
/// Age normalization configuration (preserved from v1).
#[derive(Debug, Clone)]
pub struct AgeConfig {
    pub min_age_factor: f64,  // 0.1
    pub max_age_days: f64,    // 30.0
}

impl Default for AgeConfig {
    fn default() -> Self {
        Self { min_age_factor: 0.1, max_age_days: 30.0 }
    }
}

/// Scoring weights configuration.
#[derive(Debug, Clone)]
pub struct ScoringWeights {
    pub frequency: f64,    // 0.30
    pub consistency: f64,  // 0.25
    pub age_factor: f64,   // 0.10
    pub spread: f64,       // 0.15
    pub momentum: f64,     // 0.20
}

impl ScoringWeights {
    /// Validate that weights sum to 1.0 (±0.001 tolerance).
    /// Preserved from v1 — constructor validation.
    pub fn validate(&self) -> Result<(), ConfidenceError> {
        let sum = self.frequency + self.consistency + self.age_factor
            + self.spread + self.momentum;
        if (sum - 1.0).abs() > 0.001 {
            return Err(ConfidenceError::InvalidWeights {
                sum,
                expected: 1.0,
            });
        }
        Ok(())
    }
}

impl Default for ScoringWeights {
    fn default() -> Self {
        Self {
            frequency: 0.30,
            consistency: 0.25,
            age_factor: 0.10,
            spread: 0.15,
            momentum: 0.20,
        }
    }
}

/// Complete confidence scoring configuration.
#[derive(Debug, Clone)]
pub struct ConfidenceConfig {
    pub weights: ScoringWeights,
    pub age: AgeConfig,
    pub momentum: MomentumConfig,
    pub learning: LearningConfig,
    pub outlier: OutlierConfig,
    pub prior_alpha: f64,         // 1.0
    pub prior_beta: f64,          // 1.0
    pub blending_constant: f64,   // 10.0
    pub max_posterior_weight: f64, // 0.5
    pub feedback_weight: f64,     // 0.1
}

impl Default for ConfidenceConfig {
    fn default() -> Self {
        Self {
            weights: ScoringWeights::default(),
            age: AgeConfig::default(),
            momentum: MomentumConfig::default(),
            learning: LearningConfig::default(),
            outlier: OutlierConfig::default(),
            prior_alpha: 1.0,
            prior_beta: 1.0,
            blending_constant: 10.0,
            max_posterior_weight: 0.5,
            feedback_weight: 0.1,
        }
    }
}
```

---

## 13. Storage Schema

### 13.1 patterns Table (Confidence Columns)

From 02-STORAGE-V2-PREP.md. The `patterns` table stores the computed confidence state:

```sql
CREATE TABLE patterns (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL CHECK(category IN (
        'api','auth','components','config','contracts','data-access',
        'documentation','errors','logging','performance','security',
        'structural','styling','testing','types','accessibility'
    )),
    status TEXT NOT NULL CHECK(status IN ('discovered','approved','ignored')),
    confidence_alpha REAL NOT NULL DEFAULT 1.0,
    confidence_beta REAL NOT NULL DEFAULT 1.0,
    confidence_score REAL NOT NULL DEFAULT 0.0,
    confidence_tier TEXT CHECK(confidence_tier IN (
        'established','emerging','tentative','uncertain'
    )),
    location_count INTEGER NOT NULL DEFAULT 0,
    outlier_count INTEGER NOT NULL DEFAULT 0,
    severity TEXT NOT NULL DEFAULT 'info' CHECK(severity IN ('error','warning','info','hint')),
    hash TEXT,
    parent_id TEXT REFERENCES patterns(id),
    decay_rate REAL,
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    -- Generated columns for indexed derived fields
    confidence_level TEXT GENERATED ALWAYS AS (
        CASE
            WHEN confidence_score >= 0.85 THEN 'high'
            WHEN confidence_score >= 0.70 THEN 'medium'
            WHEN confidence_score >= 0.50 THEN 'low'
            ELSE 'uncertain'
        END
    ) VIRTUAL,
    is_actionable INTEGER GENERATED ALWAYS AS (
        CASE WHEN status = 'approved' AND confidence_score >= 0.70 THEN 1 ELSE 0 END
    ) VIRTUAL
) STRICT;
```

**Columns owned by this system**:
- `confidence_alpha` — Beta α parameter, updated by `bayesian_update()` + `apply_feedback()`
- `confidence_beta` — Beta β parameter, updated by `bayesian_update()` + `apply_feedback()`
- `confidence_score` — Computed by `compute_score()`, written after each scan
- `confidence_tier` — Computed by `ConfidenceTier::classify()`, written after each scan
- `confidence_level` — Generated column (SQL-level approximation, read-only)

### 13.2 pattern_posteriors Table

From 06-UNIFIED-ANALYSIS-ENGINE-V2-PREP.md. Stores Bayesian parameters separately
for patterns that need detailed posterior tracking:

```sql
CREATE TABLE pattern_posteriors (
    pattern_id TEXT PRIMARY KEY,
    alpha REAL NOT NULL DEFAULT 1.0,
    beta REAL NOT NULL DEFAULT 1.0,
    last_updated TEXT NOT NULL
) STRICT;
```

**Decision**: The `pattern_posteriors` table is redundant with `confidence_alpha`/`confidence_beta`
in the `patterns` table. **Use the `patterns` table columns as the canonical store.** The
`pattern_posteriors` table is kept only if we need to store posteriors for entities that
are not patterns (e.g., convention-level posteriors). For v2 launch, the `patterns` table
columns are sufficient.

### 13.3 pattern_scan_history Table

From 06-UNIFIED-ANALYSIS-ENGINE-V2-PREP.md. Stores per-pattern frequency history
for momentum computation:

```sql
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
```

**Queries this system runs**:
```sql
-- Get frequency history for momentum computation (most recent N scans)
SELECT frequency, scanned_at
FROM pattern_scan_history
WHERE pattern_id = ?
ORDER BY scanned_at DESC
LIMIT ?;

-- Get previous frequency for decay computation
SELECT frequency
FROM pattern_scan_history
WHERE pattern_id = ?
ORDER BY scanned_at DESC
LIMIT 1 OFFSET 1;

-- Count scans for momentum activation check
SELECT COUNT(*) as scan_count
FROM pattern_scan_history
WHERE pattern_id = ?;
```

### 13.4 violation_feedback Table (New)

Stores developer feedback on violations for the feedback loop (AD9):

```sql
CREATE TABLE violation_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    violation_id TEXT NOT NULL,
    pattern_id TEXT NOT NULL REFERENCES patterns(id),
    detector_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('fixed','ignored','approved','not_useful','useful')),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_feedback_pattern ON violation_feedback(pattern_id);
CREATE INDEX idx_feedback_detector ON violation_feedback(detector_id);
```

### 13.5 convention_state Table (New)

Stores Bayesian convention learning state:

```sql
CREATE TABLE convention_state (
    convention_key TEXT NOT NULL,   -- e.g., "naming_style", "import_order"
    convention_value TEXT NOT NULL, -- e.g., "camelCase", "alphabetical"
    alpha REAL NOT NULL DEFAULT 1.0,
    beta REAL NOT NULL DEFAULT 1.0,
    file_count INTEGER NOT NULL DEFAULT 0,
    total_files INTEGER NOT NULL DEFAULT 0,
    trend TEXT NOT NULL DEFAULT 'stable' CHECK(trend IN ('rising','stable','declining')),
    category TEXT NOT NULL DEFAULT 'uncertain' CHECK(category IN (
        'universal','project_specific','emerging','legacy','contested'
    )),
    last_updated TEXT NOT NULL,
    PRIMARY KEY (convention_key, convention_value)
) STRICT;
```

### 13.6 Feature Flag

From 02-STORAGE-V2-PREP.md, the `drift_config` table stores feature flags:

```sql
-- Enable/disable Bayesian confidence scoring
INSERT INTO drift_config (key, value) VALUES ('bayesian_confidence', 'true');
```

When `bayesian_confidence = false`:
- `compute_score()` falls back to `score_v1_compat()`
- Tier classification uses v1 thresholds (score-based, not CI-based)
- Momentum is disabled
- Convention learning uses v1 binary threshold
- Outlier detection uses v1 thresholds (z=2.0, min_sample=3)

---

## 14. NAPI Interface

### 14.1 Exported Functions

Following the pattern from 03-NAPI-BRIDGE-V2-PREP.md, all confidence scoring functions
are exposed via NAPI for TypeScript consumption:

```rust
use napi_derive::napi;

/// Compute confidence score for a pattern.
/// Called by the analysis engine during Phase 4 (Finalize).
#[napi]
pub fn compute_confidence(input: ConfidenceInputNapi) -> napi::Result<BayesianConfidenceNapi> {
    let config = ConfidenceConfig::default();
    let result = scoring::compute_full(&input.into(), &config)?;
    Ok(result.into())
}

/// Compute confidence scores for multiple patterns in batch.
/// More efficient than calling compute_confidence in a loop.
#[napi]
pub fn compute_confidence_batch(
    inputs: Vec<ConfidenceInputNapi>,
) -> napi::Result<Vec<BayesianConfidenceNapi>> {
    let config = ConfidenceConfig::default();
    inputs.into_iter()
        .map(|input| scoring::compute_full(&input.into(), &config).map(Into::into))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| napi::Error::from_reason(e.to_string()))
}

/// Get confidence tier for a pattern by ID.
/// Reads from drift.db, returns the Rust-computed tier.
#[napi]
pub fn get_confidence_tier(pattern_id: String) -> napi::Result<String> {
    let runtime = get_runtime()?;
    let pattern = runtime.storage().get_pattern(&pattern_id)?;
    Ok(pattern.confidence_tier.to_string())
}

/// Detect outliers in a set of numeric values.
#[napi]
pub fn detect_outliers(values: Vec<f64>) -> napi::Result<Vec<OutlierResultNapi>> {
    let config = OutlierConfig::default();
    let results = outlier::detect_outliers(&values, &config);
    Ok(results.into_iter().map(Into::into).collect())
}

/// Get convention strengths for a convention key.
#[napi]
pub fn get_convention_strengths(
    convention_key: String,
) -> napi::Result<Vec<ConventionStrengthNapi>> {
    let runtime = get_runtime()?;
    let conventions = runtime.storage().get_conventions(&convention_key)?;
    Ok(conventions.into_iter().map(Into::into).collect())
}

/// Detect contested conventions for a convention key.
#[napi]
pub fn detect_contested_conventions(
    convention_key: String,
) -> napi::Result<Vec<ContestedPairNapi>> {
    let runtime = get_runtime()?;
    let conventions = runtime.storage().get_conventions(&convention_key)?;
    let contested = convention::detect_contested(
        &conventions.iter().map(Into::into).collect::<Vec<_>>()
    );
    Ok(contested.into_iter().map(Into::into).collect())
}

/// Record developer feedback on a violation.
#[napi]
pub fn record_violation_feedback(
    violation_id: String,
    pattern_id: String,
    detector_id: String,
    action: String,
) -> napi::Result<()> {
    let runtime = get_runtime()?;
    let action = ViolationAction::from_str(&action)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    runtime.storage().record_feedback(&violation_id, &pattern_id, &detector_id, action)?;
    feedback::apply_feedback_to_pattern(runtime.storage(), &pattern_id, action)?;
    Ok(())
}

/// Get detector health metrics.
#[napi]
pub fn get_detector_health(detector_id: String) -> napi::Result<DetectorHealthNapi> {
    let runtime = get_runtime()?;
    let health = runtime.storage().get_detector_health(&detector_id)?;
    Ok(health.into())
}

/// Compute V1-compatible confidence score (for migration comparison).
#[napi]
pub fn compute_confidence_v1(input: ConfidenceInputNapi) -> napi::Result<f64> {
    let conf: BayesianConfidence = scoring::compute_factors(&input.into(), &ConfidenceConfig::default());
    Ok(scoring::score_v1_compat(&conf))
}
```

### 14.2 NAPI Type Mappings

```rust
/// NAPI-compatible input type (all fields are JS-friendly types).
#[napi(object)]
pub struct ConfidenceInputNapi {
    pub occurrences: u32,
    pub total_locations: u32,
    pub variance: f64,
    pub days_since_first_seen: f64,
    pub file_count: u32,
    pub total_files: u32,
    pub previous_frequency: Option<f64>,
    pub scan_count: u32,
    pub current_alpha: f64,
    pub current_beta: f64,
}

/// NAPI-compatible output type.
#[napi(object)]
pub struct BayesianConfidenceNapi {
    pub alpha: f64,
    pub beta: f64,
    pub frequency: f64,
    pub consistency: f64,
    pub age_factor: f64,
    pub spread: f64,
    pub momentum: f64,
    pub score: f64,
    pub tier: String,
    pub ci_lower: f64,
    pub ci_upper: f64,
    pub ci_width: f64,
    pub score_v1: f64,
}
```

---

## 15. Integration Points

### 15.1 Upstream Dependencies (What This System Reads)

| System | What It Provides | How It's Used |
|--------|-----------------|---------------|
| Detector System | Raw pattern matches per file | Input to frequency, consistency, spread calculations |
| Scanner | File counts, content hashes | total_files, file change detection |
| Storage (drift.db) | α/β persistence, scan history | Incremental Bayesian updates, momentum computation |
| Pattern Aggregation | Grouped matches by pattern ID | Aggregated counts for scoring |

### 15.2 Downstream Consumers (What Reads This System's Output)

| Consumer | What It Reads | How It Uses It |
|----------|--------------|---------------|
| Quality Gates | confidence_score, confidence_tier | Gate thresholds (e.g., "no Uncertain patterns in enforced rules") |
| Grounding Loop (D7) | confidence_score, tier | Validates Cortex memories against empirical evidence |
| Pattern Ranking | score | Orders patterns by confidence for display |
| Outlier Thresholds | tier | Established patterns use stricter outlier thresholds |
| Convention Enforcement | ConventionStrength, category | Determines which conventions to enforce |
| MCP Tools | All confidence data | Exposed via `drift_confidence`, `drift_conventions` tools |
| Feedback Loop (AD9) | α, β, score | Feedback adjusts posterior parameters |
| DNA Health | confidence_score | Contributes to overall codebase health score |
| Boundary Detection | N/A (has its own confidence model) | Cross-reference only — boundary confidence is independent |
| CI Agent | tier, score | PR analysis uses confidence to prioritize findings |

### 15.3 Quality Gate Integration

Quality gates consume confidence tiers to make enforcement decisions:

```rust
/// Example quality gate rule using confidence tiers.
pub fn should_enforce_pattern(pattern: &Pattern) -> bool {
    match pattern.confidence_tier {
        ConfidenceTier::Established => true,  // Always enforce
        ConfidenceTier::Emerging => pattern.status == PatternStatus::Approved,
        ConfidenceTier::Tentative => false,   // Never enforce
        ConfidenceTier::Uncertain => false,   // Never enforce
    }
}
```

### 15.4 Grounding Loop Integration (D7)

Per PLANNING-DRIFT.md Decision 7:

```
1. Cortex stores memory: "Team uses repository pattern for data access"
2. Drift scans → finds 87% repository pattern → confidence=high, tier=Established
3. Bridge reads drift.db → memory is 87% grounded
4. Team refactors away from repository pattern
5. Next scan → 45% repository pattern → momentum=-0.48, tier=Emerging
6. Bridge detects drift → memory confidence should decrease
7. Cortex validation engine heals or flags the memory
```

The confidence scoring system's output is the primary signal for grounding. The tier
progression (Established → Emerging → Tentative → Uncertain) maps directly to grounding
confidence levels. The momentum signal provides early warning of drift before the tier
changes.

### 15.5 Boundary Detection Cross-Reference

07-BOUNDARY-DETECTION-V2-PREP.md §8 defines a separate confidence model for data access
detection:

```
boundary_confidence = tableNameFound(0.3) + fieldsFound(0.2) + operationClear(0.2)
                    + frameworkMatched(0.2) + fromLiteral(0.1)
```

This is **independent** of pattern confidence scoring. Boundary detection confidence
measures "how sure are we that this code accesses a database?" Pattern confidence measures
"how established is this coding convention?" They are different questions with different
models. No unification needed.

---

## 16. Cortex Cross-Reference

### 16.1 Cortex Confidence Type

From `crates/cortex/cortex-core/src/memory/confidence.rs`:

```rust
pub struct Confidence(f64);  // Clamped to [0.0, 1.0]

impl Confidence {
    pub const HIGH: f64 = 0.8;
    pub const MEDIUM: f64 = 0.5;
    pub const LOW: f64 = 0.3;
    pub const ARCHIVAL: f64 = 0.15;
}
```

Cortex uses a simple f64 wrapper with 4 threshold constants. This is fundamentally
different from Drift's Bayesian model:

| Aspect | Cortex Confidence | Drift Confidence |
|--------|------------------|-----------------|
| Type | Single f64 | BayesianConfidence struct (13 fields) |
| Model | Direct assignment + adjustment | Beta distribution posterior |
| Thresholds | 0.8/0.5/0.3/0.15 | CI-width-based tiers |
| Update | `adjust()` with blending weight | Conjugate Bayesian update |
| Decay | Via cortex-decay subsystem | Via temporal decay on age factor |

### 16.2 Cortex Confidence Adjustment

From `crates/cortex/cortex-validation/src/healing/confidence_adjust.rs`:

```rust
pub fn adjust(memory: &mut BaseMemory, validation_score: f64, adjustment_strength: f64) {
    let current = memory.confidence.value();
    let strength = adjustment_strength.clamp(0.0, 1.0);
    let new_value = current * (1.0 - strength) + validation_score * strength;
    memory.confidence = Confidence::new(new_value);
}
```

This is a linear blend: `new = current × (1-strength) + target × strength`. The grounding
loop (D7) would use this function to adjust Cortex memory confidence based on Drift's
confidence scores. The `validation_score` would be Drift's `confidence_score` for the
corresponding pattern, and `adjustment_strength` would be calibrated based on how much
the Drift evidence should influence the Cortex memory.

### 16.3 Bridge Consumption Pattern

The cortex-drift bridge reads Drift confidence data from drift.db (via ATTACH or NAPI)
and feeds it into Cortex's validation pipeline:

```
Drift scan → compute_score() → write to drift.db
Bridge reads drift.db → maps Drift tier to Cortex confidence adjustment
Bridge calls cortex adjust() → Cortex memory confidence updated
```

**Key design principle**: Drift computes confidence independently. Cortex consumes it
through the bridge. There is no circular dependency. Drift never reads Cortex confidence.
Cortex never writes to drift.db.


---

## 17. Error Handling

Per AD6: Use `thiserror` for all Rust error types. One error enum per subsystem.

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfidenceError {
    #[error("Invalid weights: sum={sum:.4}, expected={expected:.1}")]
    InvalidWeights { sum: f64, expected: f64 },

    #[error("Invalid alpha/beta: alpha={alpha}, beta={beta} (must be > 0)")]
    InvalidParameters { alpha: f64, beta: f64 },

    #[error("Insufficient data: {count} samples, minimum {minimum} required")]
    InsufficientData { count: usize, minimum: usize },

    #[error("Pattern not found: {pattern_id}")]
    PatternNotFound { pattern_id: String },

    #[error("Convention key not found: {key}")]
    ConventionNotFound { key: String },

    #[error("Invalid violation action: {action}")]
    InvalidAction { action: String },

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Numerical error: {message}")]
    Numerical { message: String },

    #[error("Feature disabled: bayesian_confidence flag is false")]
    FeatureDisabled,
}
```

### Error Propagation to NAPI

Errors cross the NAPI boundary as structured error codes:

```rust
impl From<ConfidenceError> for napi::Error {
    fn from(err: ConfidenceError) -> Self {
        let code = match &err {
            ConfidenceError::InvalidWeights { .. } => "CONFIDENCE_INVALID_WEIGHTS",
            ConfidenceError::InvalidParameters { .. } => "CONFIDENCE_INVALID_PARAMS",
            ConfidenceError::InsufficientData { .. } => "CONFIDENCE_INSUFFICIENT_DATA",
            ConfidenceError::PatternNotFound { .. } => "CONFIDENCE_PATTERN_NOT_FOUND",
            ConfidenceError::ConventionNotFound { .. } => "CONFIDENCE_CONVENTION_NOT_FOUND",
            ConfidenceError::InvalidAction { .. } => "CONFIDENCE_INVALID_ACTION",
            ConfidenceError::Storage(_) => "CONFIDENCE_STORAGE_ERROR",
            ConfidenceError::Numerical { .. } => "CONFIDENCE_NUMERICAL_ERROR",
            ConfidenceError::FeatureDisabled => "CONFIDENCE_FEATURE_DISABLED",
        };
        napi::Error::new(napi::Status::GenericFailure, format!("[{code}] {err}"))
    }
}
```

---

## 18. Tracing & Observability

Per AD10: Use the `tracing` crate for structured logging and span-based instrumentation.

### 18.1 Key Spans

```rust
use tracing::{instrument, info, warn, debug};

#[instrument(skip(input, config), fields(pattern_id = %input.pattern_id))]
pub fn compute_full(input: &ConfidenceInput, config: &ConfidenceConfig) -> Result<BayesianConfidence, ConfidenceError> {
    debug!(
        occurrences = input.occurrences,
        total_locations = input.total_locations,
        file_count = input.file_count,
        total_files = input.total_files,
        "computing confidence score"
    );

    let result = compute_score_inner(input, config)?;

    info!(
        score = result.score,
        tier = ?result.tier,
        alpha = result.alpha,
        beta = result.beta,
        momentum = result.momentum,
        ci_width = result.ci_width,
        "confidence score computed"
    );

    Ok(result)
}

#[instrument(skip(values, config), fields(n = values.len()))]
pub fn detect_outliers_traced(values: &[f64], config: &OutlierConfig) -> Vec<OutlierResult> {
    let results = detect_outliers(values, config);

    info!(
        outlier_count = results.len(),
        method = ?if values.len() >= 30 { "z_score" } else { "grubbs" },
        "outlier detection complete"
    );

    results
}
```

### 18.2 Key Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `confidence.compute_time_ms` | Histogram | Time to compute a single confidence score |
| `confidence.batch_compute_time_ms` | Histogram | Time to compute a batch of scores |
| `confidence.tier_distribution` | Counter | Count of patterns per tier |
| `confidence.momentum_active_count` | Gauge | Patterns with active momentum |
| `confidence.outlier_count` | Counter | Outliers detected per scan |
| `confidence.feedback_count` | Counter | Feedback events by action type |
| `confidence.convention_contested_count` | Gauge | Number of contested conventions |
| `confidence.fp_rate_by_detector` | Gauge | False positive rate per detector |

### 18.3 Log Levels

```
DRIFT_LOG=confidence=debug    # Full computation details
DRIFT_LOG=confidence=info     # Score results + outlier counts
DRIFT_LOG=confidence=warn     # Threshold violations, high FP rates
DRIFT_LOG=confidence=error    # Computation failures, storage errors
```

---

## 19. File & Module Structure

```
crates/drift-core/src/confidence/
├── mod.rs              # Module root, re-exports
├── scoring.rs          # compute_score(), compute_factors(), score_v1_compat()
├── bayesian.rs         # bayesian_update(), posterior_mean(), credible_interval()
├── momentum.rs         # compute_momentum(), momentum_active(), smoothed momentum
├── decay.rs            # apply_decay()
├── tiers.rs            # ConfidenceTier, classify(), enforcement mapping
├── convention.rs       # BayesianConvention, classify(), detect_contested()
├── outlier.rs          # detect_outliers(), z_score_iterative(), grubbs_test(), iqr_outliers()
├── feedback.rs         # apply_feedback(), DetectorHealth, ViolationAction
├── config.rs           # ConfidenceConfig, ScoringWeights, AgeConfig, etc.
├── types.rs            # BayesianConfidence, ConfidenceInput, OutlierResult, etc.
└── error.rs            # ConfidenceError enum
```

### Module Dependencies (Internal)

```
scoring.rs → bayesian.rs, momentum.rs, decay.rs, tiers.rs, config.rs, types.rs
convention.rs → bayesian.rs, types.rs
outlier.rs → types.rs, config.rs
feedback.rs → bayesian.rs, types.rs
All → error.rs
```

### NAPI Bindings

```
crates/drift-napi/src/bindings/
└── confidence.rs       # All #[napi] exports for confidence scoring
```

---

## 20. Build Order

### Phase 1: Core Math (No Dependencies)

1. `types.rs` — All data types (BayesianConfidence, ConfidenceInput, OutlierResult, etc.)
2. `error.rs` — ConfidenceError enum
3. `config.rs` — All configuration types with defaults
4. `bayesian.rs` — Beta distribution: posterior_mean, bayesian_update, credible_interval
5. `tiers.rs` — ConfidenceTier classification

**Milestone**: Can compute posterior mean and classify tiers from α/β. Unit testable in isolation.

### Phase 2: Scoring Factors (Depends on Phase 1)

6. `decay.rs` — Temporal decay on age factor
7. `momentum.rs` — Momentum computation and activation rules
8. `scoring.rs` — Full 5-factor scoring formula + v1 compat + posterior blending

**Milestone**: Can compute full confidence scores from ConfidenceInput. All v1 scoring behavior preserved via score_v1_compat.

### Phase 3: Convention Learning (Depends on Phase 1)

9. `convention.rs` — BayesianConvention, classification, contested detection

**Milestone**: Can learn conventions from file observations and detect contested pairs.

### Phase 4: Outlier Detection (Depends on Phase 1)

10. `outlier.rs` — Z-Score iterative, Grubbs', IQR, method selection, rule-based

**Milestone**: Can detect outliers with correct method selection by sample size.

### Phase 5: Feedback Loop (Depends on Phase 1 + Storage)

11. `feedback.rs` — Feedback application, detector health metrics

**Milestone**: Can record feedback and adjust posteriors. Detector health tracking operational.

### Phase 6: Integration (Depends on All Above + Storage)

12. `mod.rs` — Module root, public API surface
13. NAPI bindings (`crates/drift-napi/src/bindings/confidence.rs`)
14. Storage integration (read/write α/β, scan history, convention state, feedback)
15. Analysis engine integration (called during Phase 4: Finalize)

**Milestone**: Full system operational end-to-end. NAPI functions callable from TypeScript.

### Phase 7: Feature Flag + Migration

16. Feature flag check (`bayesian_confidence` in drift_config)
17. V1 compat mode (fallback to v1 scoring when flag is off)
18. Migration tooling (compute both scores, compare, validate)

**Milestone**: Safe rollout with zero-risk rollback capability.

---

## 21. V1 Feature Verification

Exhaustive accounting of every v1 feature. Every row must have a v2 status.

| # | V1 Feature | V2 Status | V2 Location | Notes |
|---|-----------|-----------|-------------|-------|
| F1 | 4-factor weighted scoring | **Upgraded** | §5 scoring.rs | 5-factor model with momentum |
| F2 | Weight validation (sum=1.0) | **Preserved** | §12 ScoringWeights::validate() | Identical validation logic |
| F3 | Frequency = occurrences/total | **Preserved** | §5 compute_frequency() | Identical computation |
| F4 | Consistency = 1 - variance | **Preserved** | §5 compute_consistency() | Identical computation |
| F5 | Age factor linear 0.1→1.0/30d | **Preserved** | §5 compute_age_factor() | Identical + decay added (§6) |
| F6 | Spread = fileCount/totalFiles | **Preserved** | §5 compute_spread() | Identical computation |
| F7 | 4 confidence levels | **Replaced** | §8 ConfidenceTier | 4 graduated tiers (CI-based) |
| F8 | ConfidenceScore output type | **Upgraded** | §12 BayesianConfidence | 13 fields (superset of v1's 6) |
| F9 | ConfidenceInput type | **Preserved+** | §12 ConfidenceInput | Extended with momentum/Bayesian fields |
| F10 | Configurable weights | **Preserved** | §12 ScoringWeights | Now 5 weights instead of 4 |
| F11 | AgeNormalizationConfig | **Preserved** | §12 AgeConfig | Identical fields |
| F12 | ConfidenceScorer class | **Replaced** | §19 scoring.rs | Module functions (Rust idiomatic) |
| F13 | Functional helpers | **Preserved** | §14 NAPI exports | compute_confidence, compute_confidence_v1 |
| F14 | ValueDistribution learning | **Replaced** | §9 BayesianConvention | Bayesian model with categories |
| F15 | 60% dominance threshold | **Replaced** | §9 posterior ≥ 0.7 | Bayesian posterior replaces fixed threshold |
| F16 | Min occurrences = 3 | **Upgraded** | §9 min_occurrences = 10 | Higher bar for statistical validity |
| F17 | Min files = 2 | **Upgraded** | §9 min_files = 5 | Higher bar for meaningful sample |
| F18 | Z-Score \|z\|>2.0 | **Upgraded** | §10 \|z\|>2.5 iterative | Higher threshold + iterative masking |
| F19 | IQR outlier detection | **Preserved** | §10 iqr_outliers() | Supplementary role (was primary for n<30) |
| F20 | Rule-based outlier detection | **Preserved** | §10 OutlierRule | Identical concept |
| F21 | Sensitivity adjustment | **Preserved** | §10 adjust_threshold() | Identical formula |
| F22 | Outlier significance levels | **Upgraded** | §10 Significance enum | 4 levels (was 3) + method tag |
| F23 | Outlier types enum | **Preserved** | §10 OutlierType | All 7 types preserved |
| F24 | Deviation score | **Preserved** | §10 | Identical formula |
| F25 | Pattern matcher caching | **Out of scope** | Matcher system | Not part of confidence scoring |
| F26 | AST match confidence | **Out of scope** | Matcher system | Not part of confidence scoring |
| F27 | Regex match confidence | **Out of scope** | Matcher system | Not part of confidence scoring |

**Result**: 24 in-scope features. 10 preserved exactly, 8 upgraded, 6 replaced with superior alternatives. 3 out of scope (matcher system). **0 features lost.**

---

## 22. Performance Targets

| Operation | Target | Rationale |
|-----------|--------|-----------|
| Single score computation | < 1μs | Pure arithmetic, no I/O |
| Batch score (1000 patterns) | < 1ms | Parallelizable with rayon |
| Bayesian update (single) | < 100ns | Two additions |
| Credible interval | < 10μs | Beta inverse CDF (statrs) |
| Outlier detection (100 values) | < 50μs | Z-Score iterative, 3 iterations max |
| Grubbs' test (25 values) | < 20μs | Single pass + t-distribution lookup |
| Convention classification | < 1μs | Simple threshold checks |
| Contested detection (10 conventions) | < 5μs | Sort + window scan |
| Momentum computation | < 100ns | Single division + clamp |
| Full scan scoring (10K patterns) | < 50ms | Batch compute + storage write |

### Memory Budget

| Structure | Size | For 10K Patterns |
|-----------|------|-----------------|
| BayesianConfidence | ~120 bytes | ~1.2 MB |
| ConfidenceInput | ~96 bytes | ~960 KB |
| OutlierResult | ~48 bytes | N/A (per-detection) |
| ConventionStrength | ~128 bytes | ~128 KB (for 1K conventions) |

Total memory for confidence scoring state: < 5 MB for a 10K-pattern project.

### Benchmark Strategy

```rust
// In crates/drift-core/benches/confidence_bench.rs
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_single_score(c: &mut Criterion) {
    let input = test_confidence_input();
    let config = ConfidenceConfig::default();
    c.bench_function("confidence_single_score", |b| {
        b.iter(|| scoring::compute_full(&input, &config))
    });
}

fn bench_batch_score(c: &mut Criterion) {
    let inputs: Vec<_> = (0..1000).map(|_| test_confidence_input()).collect();
    let config = ConfidenceConfig::default();
    c.bench_function("confidence_batch_1000", |b| {
        b.iter(|| {
            inputs.iter().map(|i| scoring::compute_full(i, &config)).collect::<Vec<_>>()
        })
    });
}

fn bench_outlier_detection(c: &mut Criterion) {
    let values: Vec<f64> = (0..100).map(|i| i as f64 + rand::random::<f64>()).collect();
    let config = OutlierConfig::default();
    c.bench_function("outlier_z_score_100", |b| {
        b.iter(|| outlier::detect_outliers(&values, &config))
    });
}
```

---

## 23. Open Items

### O1: Smoothed Momentum (Deferred)

Exponential moving average over N scans for noise reduction. Data is stored in
`pattern_scan_history` — can be implemented post-launch without schema changes.

### O2: Sliding Window Posterior (Deferred)

Recompute α/β from only the last N scans instead of cumulative. Useful if patterns
need to "forget" very old data. Requires iterating `pattern_scan_history` — more expensive
than cumulative update. Evaluate after launch based on real-world behavior.

### O3: SIMD Batch Scoring (Deferred)

For projects with 100K+ patterns, SIMD-accelerated batch scoring could provide 4-8x
speedup. The scoring formula is embarrassingly parallel and maps well to SIMD lanes.
Evaluate if performance targets are not met with scalar code.

### O4: Calibration Validation

After launch, compare v1 and v2 scores on real projects to validate that the Bayesian
model produces sensible results. The v1 compat score is stored alongside v2 for this purpose.
Define acceptance criteria: v2 scores should correlate with v1 scores (r > 0.8) for
stable patterns, and diverge meaningfully for declining/rising patterns.

### O5: Convention Learning Persistence Across Renames

If a convention value is renamed (e.g., "camelCase" → "camel_case" in a config), the
Bayesian state is lost. Consider a convention aliasing mechanism. Low priority — rare scenario.

### O6: Feedback Weight Tuning

The feedback weight (0.1) is an initial estimate. After collecting real feedback data,
tune this value. Too high → single developer can manipulate scores. Too low → feedback
has no effect. Target: 50-100 feedback events should have noticeable impact on a pattern
with 1000+ file observations.

---

## 24. Summary of All Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | Beta(1,1) uniform prior | Simplest, neutral, quickly overwhelmed by data |
| D2 | Posterior mean (not MAP/median) | Always defined, stable, standard |
| D3 | Cumulative updates (not sliding window) | Mathematically correct, momentum compensates for lag |
| D4 | 5-factor formula from 06-DETECTOR-SYSTEM (not AD8's 3-factor) | Preserves all v1 dimensions, more nuanced |
| D5 | Posterior weight caps at 0.50 | Weighted factors always contribute ≥50% |
| D6 | Blending constant = 10 | Posterior meaningful at n=10, matches outlier min_sample |
| D7 | Simple momentum for launch (not smoothed) | Easier to debug, data stored for future smoothing |
| D8 | Momentum activation: 3 scans, 50 files | Prevents noise in small/new projects |
| D9 | CI-width-based tiers (not score thresholds) | Sample-size-aware, natural Bayesian approach |
| D10 | `patterns` table columns as canonical α/β store | Avoids redundancy with pattern_posteriors |
| D11 | `statrs` crate for Beta CDF | Battle-tested, avoids reinventing numerical methods |
| D12 | Feedback weight = 0.1 | 10 feedbacks ≈ 1 file observation, prevents manipulation |
| D13 | Z-Score threshold 2.5 (not 2.0 or 3.0) | Balances sensitivity and precision (M35) |
| D14 | Min sample size 10 (not 3) | Statistical validity for Z-Score and Grubbs' |
| D15 | Grubbs' for 10≤n<30 (not IQR) | More rigorous for small samples |
| D16 | IQR retained as supplementary | Robust against extreme outliers inflating std dev |
| D17 | Confidence scoring as standalone module | Resolves I5 placement conflict |
| D18 | Feature flag for zero-risk rollback | `bayesian_confidence` in drift_config |
| D19 | V1 compat score stored alongside V2 | Enables calibration validation (O4) |
| D20 | Boundary detection confidence is independent | Different question, different model, no unification |
| D21 | Min files=5, min occurrences=10 for learning | Higher bar for statistical validity |
| D22 | Contested threshold = 15% frequency difference | From 06-DETECTOR-SYSTEM §7, prevents false enforcement |
| D23 | Convention categories: 5 types | Universal/ProjectSpecific/Emerging/Legacy/Contested |
| D24 | Iterative Z-Score with 3-iteration cap | Addresses masking effect without over-removal |
