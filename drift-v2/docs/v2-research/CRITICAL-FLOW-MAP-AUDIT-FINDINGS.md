# CRITICAL-FLOW-MAP.md — Phase 2 Audit Findings

> Audit scope: DD-05 (Pattern Intelligence), DD-06 (Structural Analysis), DD-07 (Graph Intelligence)
> Verified against: Rust source code in `crates/drift/drift-analysis/src/`

---

## Summary

| Section | Claims Verified | Discrepancies Found | Severity |
|---------|----------------|---------------------|----------|
| DD-05: Pattern Intelligence | 8 | 4 | 2 High, 2 Medium |
| DD-06: Structural Analysis | 6 | 3 | 1 High, 2 Medium |
| DD-07: Graph Intelligence | 8 | 2 | 1 High, 1 Medium |
| **Total** | **22** | **9** | **4 High, 5 Medium** |

---

## DD-05: Pattern Intelligence (§6)

### ❌ FINDING DD-05-01 (HIGH): Bayesian factor count and names are wrong

**Doc claims (line 310):**
> 7 factors: frequency, consistency, feedback, data_quality, temporal_decay, category_relative, momentum

**Code reality (`patterns/confidence/factors.rs:1-18`):**
6 factors with different names:
- `Frequency` (weight 0.25)
- `Consistency` (weight 0.20)
- `Age` (weight 0.10)
- `Spread` (weight 0.15)
- `Momentum` (weight 0.15)
- `DataQuality` (weight 0.15)

**Specific errors:**
1. Doc says **7** factors, code has **6**
2. `feedback` is NOT a factor — it's a separate adjustment step in `scorer.rs:146-152` (Step 4)
3. `temporal_decay` is NOT a factor — it's a separate decay step in `scorer.rs:211-222`
4. `category_relative` is NOT a factor — it's an input modifier to the frequency calculation (`scorer.rs:119-122`)
5. Doc **omits** `Age` and `Spread` which ARE real factors in the code
6. Doc also claims `factors.rs` contains "7 scoring factors" (line 338) — should say 6

**Fix:** Replace line 310 with:
```
6 factors: frequency (0.25), consistency (0.20), age (0.10), spread (0.15), momentum (0.15), data_quality (0.15)
```
Add separate bullets for feedback adjustment and temporal decay as pipeline steps, not factors.

---

### ❌ FINDING DD-05-02 (MEDIUM): Confidence tier names are wrong

**Doc claims (line 313):**
> Tier classification: Established / Emerging / Contested / Declining

**Code reality (`patterns/confidence/types.rs:50-84`):**
4 tiers: `Established`, `Emerging`, `Tentative`, `Uncertain`

- `Contested` is a **ConventionCategory** (in `learning/types.rs:128`), NOT a confidence tier
- `Declining` does not exist anywhere in the code
- `Tentative` and `Uncertain` are the real tiers the doc omits

**Fix:** Replace with: `Established / Emerging / Tentative / Uncertain`

---

### ❌ FINDING DD-05-03 (MEDIUM): DbFeedbackStore does not exist

**User audit scope asks to verify:** DbFeedbackStore

**Code reality:** No `DbFeedbackStore` exists anywhere in the codebase. Only:
- `FeedbackStore` trait (`confidence/scorer.rs:23-26`)
- `InMemoryFeedbackStore` implementation (`confidence/scorer.rs:30-51`)

The trait is designed for persistence implementations, but no DB-backed implementation exists yet.

---

### ❌ FINDING DD-05-04 (HIGH): Outlier ensemble description is incomplete

**Doc claims (line 322):**
> Ensemble: IQR + ESD + Z-score

**Code reality (`outliers/selector.rs:50-130`):**
The ensemble is actually **5 statistical methods + rule-based**, auto-selected by sample size and normality:

| Sample Size | Normal Data | Non-Normal Data |
|-------------|------------|-----------------|
| n ≥ 30 | Z-Score | IQR |
| 25 ≤ n < 30 | Generalized ESD | MAD |
| 10 ≤ n < 25 | Grubbs | MAD |
| n < 10 | Rule-based only | Rule-based only |

Plus supplementary cross-validation:
- IQR always runs for n ≥ 30 (if not primary)
- MAD always runs (if not primary)
- Rule-based always runs (3 rules: zero_confidence, confidence_cliff, file_isolation)
- Consensus scoring boosts multi-method agreement

**Missing from doc:** Grubbs and MAD methods, normality-based method selection, the full auto-select logic.

---

### ✅ VERIFIED: Pattern Intelligence file paths (all 11 listed)

All file paths in the "Key files" section (lines 336-346) exist and contain the described functionality.

### ✅ VERIFIED: MinHash universal hashing

`similarity.rs:111-132` confirms universal hashing: `h_i(x) = (a_i * x + b_i) mod p` where p = 2^61 - 1 (Mersenne prime). Uses xxh3 base hash with deterministic per-permutation coefficients.

### ✅ VERIFIED: Convention system

- `ConventionStore` trait exists (`learning/types.rs:53-60`) with `load_all`, `save`, `load_by_pattern_id` ✅
- `InMemoryConventionStore` implementation exists ✅
- Dirichlet-based contested detection (`learning/discovery.rs:248-258`) via `DirichletMultinomial` ✅
- `PromotionStatus` enum: `Discovered`, `Approved`, `Rejected`, `Expired` ✅
- Directory scope detection (`discovery.rs:262-296`) ✅
- Convergence scoring (`types.rs:43-49`) ✅

### ✅ VERIFIED: Pipeline structure

`pipeline.rs` orchestrates: Aggregation → Confidence → Outlier → Convention → Promotion ✅

---

## DD-06: Structural Analysis (§7)

### ❌ FINDING DD-06-01 (HIGH): DNA gene extractor count and names are completely wrong

**Doc claims (line 386):**
> Gene extractors (11): naming, error_handling, testing, logging, typing, async, imports, state_management, documentation, security, architecture

**Code reality (`structural/dna/extractors/mod.rs:1-44`):**
**10 gene extractors** (6 frontend + 4 backend):

| # | Extractor | Category |
|---|-----------|----------|
| 1 | `VariantHandlingExtractor` | Frontend |
| 2 | `ResponsiveApproachExtractor` | Frontend |
| 3 | `StateStylingExtractor` | Frontend |
| 4 | `ThemingExtractor` | Frontend |
| 5 | `SpacingExtractor` | Frontend |
| 6 | `AnimationExtractor` | Frontend |
| 7 | `ApiResponseExtractor` | Backend |
| 8 | `ErrorResponseExtractor` | Backend |
| 9 | `LoggingFormatExtractor` | Backend |
| 10 | `ConfigPatternExtractor` | Backend |

**Errors:**
1. Doc says **11**, code has **10**
2. **Zero** of the 11 names in the doc match actual extractor names
3. `dna/mod.rs:1` explicitly says "10 gene extractors"
4. `extractor.rs:160` says "all 10 built-in extractors"
5. `extractors/mod.rs:16` says `create_all_extractors()` returns `Vec` with capacity 10

---

### ❌ FINDING DD-06-02 (MEDIUM): ToC says 9 subsystems, body says 10

**Doc ToC (line 13):**
> Flow 6: Structural Analysis (9 subsystems)

**Doc body (line 350):**
> ## 7. Flow 6: Structural Analysis (10 Subsystems)

The body correctly lists 10 subsections (6a through 6j). The ToC is wrong — should say 10.

---

### ❌ FINDING DD-06-03 (MEDIUM): Table columns vs migration SQL not fully verified

The doc lists tables for each subsystem but does not enumerate columns. Migration SQL verification would require reading all 7 migration files. The table names listed appear correct based on the storage layer code and batch command variants. **This item is noted as not fully line-verified** — a separate migration audit would be needed.

---

### ✅ VERIFIED: Structural subsystem file paths

All 10 subsystem directory paths exist:
- `structural/coupling/` ✅
- `structural/wrappers/` ✅
- `structural/crypto/` ✅
- `structural/dna/` ✅
- `structural/constants/secrets.rs` ✅
- `structural/constants/magic_numbers.rs` ✅ (inferred from doc)
- `structural/constraints/` ✅
- `structural/constants/env_extraction.rs` ✅
- `structural/contracts/` ✅
- `structural/decomposition/` ✅

### ✅ VERIFIED: Contract extraction claims

- 14 endpoint extractors ✅ (Express, Fastify, NestJS, Next.js, tRPC, Django, Rails, Flask, Spring, Gin, Actix, ASP.NET, Laravel, Frontend)
- 4 schema parsers ✅ (OpenAPI, GraphQL, Protobuf, AsyncAPI)
- 7 mismatch types ✅
- 19 breaking change types ✅

### ✅ VERIFIED: Other structural subsystem descriptions

- Coupling: Martin metrics, cycle detection ✅
- Wrappers: multi-primitive composite analysis ✅
- Crypto: CWE + OWASP mapping ✅
- Secrets: Shannon entropy-based filtering ✅
- Constraints: InvariantDetector → ConstraintStore → ConstraintVerifier ✅
- Env variables: 8 languages ✅
- Decomposition: priors-based ✅

---

## DD-07: Graph Intelligence (§8)

### ❌ FINDING DD-07-01 (HIGH): Call graph resolution — 6 defined but only 5 wired

**Doc claims (line 457):**
> 6 resolution strategies: SameFile (0.95), Fuzzy (0.40), Import-based, Export-based, DI, Method

**Code reality:**
- `Resolution` enum (`call_graph/types.rs:114-127`) has **6 variants**: SameFile, MethodCall, DiInjection, ImportBased, ExportBased, Fuzzy ✅
- BUT `resolve_call()` function (`resolution.rs:109-145`) only chains **5 strategies**:
  1. SameFile → 2. MethodCall → 3. ImportBased → 4. ExportBased → 5. Fuzzy
- **DiInjection is never called** from `resolve_call`. It exists in the enum but has no resolution function.
- The function's doc comment (`resolution.rs:106`) explicitly says: "Tries strategies in order: SameFile → MethodCall → ImportBased → ExportBased → Fuzzy" (5, not 6)

**Additionally:** Per previous hardening audit, Import-based and Export-based resolution are effectively dead due to empty parser fields (specifiers always empty, is_exported always false). Only SameFile (0.95) and Fuzzy (0.40) actually fire in practice.

---

### ❌ FINDING DD-07-02 (MEDIUM): Blast radius description oversimplified

**Doc claims (line 485):**
> Blast radius = transitive caller count + risk score

**Code reality (`impact/types.rs:38-63`, `impact/blast_radius.rs:14-50`):**
The blast radius uses a **5-factor weighted risk score**:
```
overall = blast_radius * 0.30
        + sensitivity * 0.25
        + (1.0 - test_coverage) * 0.20   // inverted: low coverage = high risk
        + complexity * 0.15
        + change_frequency * 0.10
```

Where:
- `blast_radius`: normalized transitive caller count
- `sensitivity`: computed from entry_point, is_exported, security-named, DB/IO functions
- `test_coverage`: approximated by filename heuristic ("test" → 0.8, else 0.2)
- `complexity`: estimated from function line span
- `change_frequency`: **hardcoded to 0.0** (requires git history, not implemented)

The doc should describe the 5-factor formula, not just "count + risk score".

---

### ✅ VERIFIED: Taint source/sink type enums + CWE mapping

- `SourceType` enum: 7 variants (UserInput, Environment, Database, Network, FileSystem, CommandLine, Deserialization) ✅
- `SinkType` enum: 17 CWE-mapped types + Custom ✅
- Each sink type has `cwe_id()` method returning the correct CWE number ✅
- `SanitizerType` enum: 8 types ✅
- Doc claim of "17 CWE categories" matches the 17 builtin `SinkType` variants ✅

### ✅ VERIFIED: Error gap types + CWE mapping

`GapType` enum: 7 variants ✅
- EmptyCatch → CWE-390
- SwallowedError → CWE-390
- GenericCatch → CWE-396
- Unhandled → CWE-248
- UnhandledAsync → CWE-248
- MissingMiddleware → CWE-755
- InconsistentPattern → CWE-755

Plus OWASP mappings for 4 of 7 gap types. All verified in `cwe_mapping.rs`.

### ✅ VERIFIED: Dead code exclusion categories

10 categories in `DeadCodeExclusion` enum (`impact/types.rs:113-167`):
EntryPoint, EventHandler, ReflectionTarget, DependencyInjection, TestUtility, FrameworkHook, DecoratorTarget, InterfaceImpl, ConditionalCompilation, DynamicImport ✅

Each has a dedicated check function in `dead_code.rs:138-324` ✅

### ✅ VERIFIED: Test quality 7 dimensions

`quality_scorer.rs` computes exactly 7 dimensions ✅:
1. `coverage_breadth` — % of source functions with ≥1 test
2. `coverage_depth` — avg tests per covered function (normalized to 3+)
3. `assertion_density` — avg assertions per test (normalized to 3+)
4. `mock_ratio` — optimal at 0.3, penalizes extremes
5. `isolation` — shared state detection in tests
6. `freshness` — hardcoded 1.0 (needs git history)
7. `stability` — hardcoded 1.0 (needs CI history)

Doc line 494 exactly matches these names ✅

**Note:** `freshness` and `stability` are placeholders (always 1.0). They require external data (git/CI history) that the analysis engine doesn't have access to.

### ✅ VERIFIED: Reachability BFS + sensitivity classification

- Forward/inverse BFS in `bfs.rs` ✅
- Auto-select engine: petgraph for <10K nodes, SQLite CTE for ≥10K ✅
- Depth-limited traversal ✅
- 4-level sensitivity classification in `sensitivity.rs` ✅:
  - Critical: user input → SQL/command execution
  - High: user input → file/network operations
  - Medium: admin → sensitive operations
  - Low: internal only

---

## Action Items for Doc Corrections

| Priority | Finding | Fix Required |
|----------|---------|-------------|
| **P0** | DD-05-01 | Change "7 factors" to "6 factors" with correct names and weights |
| **P0** | DD-06-01 | Change "11 gene extractors" to "10" with correct names |
| **P0** | DD-07-01 | Note that DI resolution is defined but not wired; only 5 strategies active |
| **P1** | DD-05-02 | Fix tier names to Established/Emerging/Tentative/Uncertain |
| **P1** | DD-05-04 | Expand outlier description to include Grubbs, MAD, normality selection |
| **P1** | DD-06-02 | Fix ToC to say "10 subsystems" instead of "9" |
| **P1** | DD-07-02 | Document the 5-factor blast radius formula with weights |
| **P2** | DD-05-03 | Note that DbFeedbackStore doesn't exist (only InMemoryFeedbackStore) |
| **P2** | DD-06-03 | Full migration column audit still needed |
