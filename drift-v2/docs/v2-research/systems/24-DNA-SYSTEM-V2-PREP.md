# DNA System (Gene Extractors, Health Scoring, Mutations) — V2 Implementation Prep

> Comprehensive build specification for Drift v2's DNA System (System 24).
> Synthesized from: 13-advanced/dna-system.md (architecture overview, 10 gene extractors,
> 6 frontend + 4 backend, analysis pipeline, MCP integration, subsystem connections),
> 13-advanced/dna/types.md (Gene, Allele, AlleleExample, Mutation, StylingDNAProfile,
> DNASummary, EvolutionEntry, EvolutionChange, GeneId, AlleleId, framework types),
> 13-advanced/dna/analyzer.md (DNAAnalyzer orchestrator, DNAAnalyzerConfig, 5-phase
> pipeline, AnalysisResult, file discovery, gene extraction, mutation detection, health
> calculation, profile assembly), 13-advanced/dna/gene-extractors.md (BaseGeneExtractor
> abstract class, AlleleDefinition, DetectedAllele, FileExtractionResult, aggregation
> pipeline, factory functions, 10 extractor implementations), 13-advanced/dna/health-and-
> mutations.md (HealthCalculator 4-factor formula, MutationDetector algorithm, impact
> classification, DEFAULT_DNA_THRESHOLDS, filter methods), 13-advanced/dna/output.md
> (PlaybookGenerator markdown output, AIContextBuilder 4-level context, token-efficient
> AI injection), 13-advanced/dna/store.md (DNAStore JSON persistence, evolution tracking,
> 50-entry sliding window, DNAStoreConfig),
> DRIFT-V2-FULL-SYSTEM-AUDIT.md (Cat 13 — DNA System Rust, 10 gene extractors, health
> score formula, genetic diversity, mutation detector, impact classification, thresholds,
> DORA-adjacent metrics, event bus DnaAnalysisComplete/MutationDetected, setup wizard
> DNARunner, sync service syncDna, batch API AnalysisType::Dna),
> DRIFT-V2-STACK-HIERARCHY.md (Level 2C — Structural Intelligence, capstone metric,
> consumed by simulation/quality gates, D7 grounding signal for Cortex bridge),
> DRIFT-V2-SYSTEMS-REFERENCE.md §18 (DNA System TOC entry),
> 03-NAPI-BRIDGE-V2-PREP.md (§10.11 analyze_dna/compare_dna, §9 batch API Dna variant,
> §12 dna_types.rs conversion module, §15 bindings/dna.rs),
> 02-STORAGE-V2-PREP.md (drift.db schema: dna_profile, dna_genes, dna_mutations tables),
> 08-storage/sqlite-schema.md (DNA table definitions),
> 07-mcp/tools-by-category.md (drift_dna_profile ~800-2000 tokens, drift_context DNA-aware),
> 10-cli/commands.md (drift dna: scan/status/gene/mutations/playbook/export — 6 subcommands),
> 09-quality-gates/audit.md (health score feeds audit, degradation tracking),
> 19-COUPLING-ANALYSIS-V2-PREP.md (downstream consumer pattern, CouplingSnapshot → DNA),
> 04-INFRASTRUCTURE-V2-PREP.md (thiserror, tracing, FxHashMap, rayon, regex),
> cortex-core/src/models/health_report.rs (HealthReport, HealthStatus, HealthMetrics),
> cortex-core/src/traits/health_reporter.rs (IHealthReporter trait),
> cortex-core/src/models/degradation_event.rs (DegradationEvent),
> Rust regex crate RegexSet (single-pass multi-pattern matching for gene extraction),
> Rust sha2 crate (SHA-256 for deterministic mutation IDs),
> PLANNING-DRIFT.md (D1 standalone, D5 event system, D7 Cortex grounding).
>
> Purpose: Everything needed to build the DNA System from scratch in Rust.
> Every v1 feature accounted for. Zero feature loss. Every gene extractor specified.
> Every algorithm defined. Every type modeled. Every integration point documented.
> Every architectural decision resolved. The DNA system is the capstone metric —
> it consumes data from nearly every other subsystem and produces the single most
> human-readable output: "here's what your codebase looks like, genetically."
> Generated: 2026-02-08

---

## Table of Contents

1. Architectural Position
2. V1 Complete Feature Inventory
3. V2 Architecture — Unified DNA Engine
4. Core Data Model (Rust Types)
5. Phase 1: File Discovery & Content Loading
6. Phase 2: Gene Extraction Pipeline (10 Extractors)
7. Phase 3: Frontend Gene Extractors (6)
8. Phase 4: Backend Gene Extractors (4)
9. Phase 5: Allele Aggregation & Gene Assembly
10. Phase 6: Mutation Detection
11. Phase 7: Health Score Calculation
12. Phase 8: Genetic Diversity Calculation
13. Phase 9: Profile Assembly
14. Phase 10: Evolution Tracking
15. Phase 11: DNA Comparison Engine
16. Phase 12: Playbook Generation (Markdown Output)
17. Phase 13: AI Context Builder (4-Level Token-Efficient Output)
18. RegexSet Optimization — Single-Pass Multi-Pattern Matching
19. Incremental DNA Analysis (Content-Hash Aware)
20. Integration with Unified Analysis Engine
21. Integration with Coupling Analysis
22. Integration with Quality Gates & Audit
23. Integration with Simulation Engine
24. Integration with Context Generation
25. Integration with Cortex Grounding (D7)
26. Storage Schema (drift.db DNA Tables)
27. NAPI Interface
28. MCP Tool Interface (drift_dna_profile — 3 Actions)
29. CLI Interface (drift dna — 6 Subcommands)
30. Event Interface
31. Tracing & Observability
32. Performance Targets & Benchmarks
33. Build Order & Dependencies
34. V1 → V2 Feature Cross-Reference
35. Inconsistencies & Decisions
36. Risk Register

---

## 1. Architectural Position

The DNA System is **Level 2C — Structural Intelligence** in the Drift v2 stack
hierarchy. It is the capstone metric system — the one that synthesizes convention
data from across the entire codebase into a single, biologically-inspired model
that answers: "what does this codebase look like, genetically?"

Per DRIFT-V2-STACK-HIERARCHY.md:

> DNA System: 10 gene extractors, health scoring, mutation detection. Capstone metric.
> Per D7: DNA health scores are another grounding signal the bridge can compare against
> Cortex memories, but Drift computes them independently.

Per DRIFT-V2-FULL-SYSTEM-AUDIT.md Category 13:

> DNA System (Rust) — 10 Gene Extractors. Extracts "genetic fingerprint" of codebase
> conventions. Gene extractors: naming conventions, file structure, import patterns,
> error handling style, test patterns, documentation style, type usage, API conventions,
> security patterns, logging patterns. Each gene: name, value (dominant convention),
> confidence, evidence count. DNA Profile: collection of all genes for a project.
> DNA Comparison: diff two profiles to measure convention drift.

Per DRIFT-V2-FULL-SYSTEM-AUDIT.md Supplemental:

> DNA Health & Mutations (Rust): Health score: consistency(40%) + confidence(30%) +
> mutations(20%) + coverage(10%) → [0,100]. Genetic diversity metric. Mutation detector.
> Impact classification: high/medium/low. Thresholds configurable.

### Core Thesis

The DNA system models codebase conventions as a biological genome. Each convention
concern (e.g., "how do we handle component variants?") is a **gene**. Each approach
to that concern (e.g., "CVA", "inline conditionals", "CSS modules") is an **allele**.
The most common allele becomes **dominant** — it represents the team's established
pattern. Files that deviate from the dominant allele are **mutations** — not errors,
but measurable deviations with graded impact.

This biological metaphor is powerful because it:
1. Makes abstract convention data tangible and communicable
2. Provides a natural vocabulary (genes, alleles, mutations, health, evolution)
3. Enables quantitative health scoring (0-100) from qualitative convention data
4. Supports temporal tracking (evolution over time, like a genetic record)
5. Produces AI-ready context at multiple detail levels for token efficiency

The v1 implementation is 100% TypeScript (~15 source files). v2 moves the
computationally intensive parts (gene extraction, mutation detection, health
calculation) to Rust while keeping presentation-layer output (playbook generation,
AI context building) available from both Rust and TypeScript.

### What Lives Here

- File discovery and content loading (component paths + backend paths)
- 10 regex-based gene extractors (6 frontend + 4 backend)
- BaseGeneExtractor trait with shared aggregation/gene-building pipeline
- Allele detection via RegexSet (single-pass multi-pattern matching)
- Mutation detection with impact grading (high/medium/low)
- Health score calculation (4-factor weighted composite, 0-100)
- Genetic diversity calculation (normalized allele count)
- DNA profile assembly (StylingDnaProfile)
- Evolution tracking (50-entry sliding window)
- DNA comparison engine (diff two profiles)
- Playbook generation (human-readable Markdown)
- AI context builder (4 detail levels, token-efficient)
- Incremental analysis (content-hash aware, skip unchanged files)
- DNA result persistence (drift.db DNA tables)

### What Does NOT Live Here

- Source file parsing (lives in Parsers / Unified Analysis Engine)
- Pattern detection (lives in Detector System)
- Coupling metrics (lives in Coupling Analysis — DNA consumes them)
- Quality gate evaluation (lives in Quality Gates — consumes DNA health)
- Simulation scoring (lives in Simulation Engine — consumes DNA data)
- Audit snapshots (lives in Audit System — consumes DNA health)
- MCP tool routing (lives in MCP Server)
- CLI command parsing (lives in CLI)

### Downstream Consumers

| Consumer | What It Reads | Interface |
|----------|--------------|-----------|
| Quality Gates | DNA health score, mutation count | `DnaGateInput` |
| Audit System | Health score for degradation tracking | `DnaHealthSnapshot` |
| Simulation Engine | Convention alignment for friction scoring | `DnaProfile` |
| Context Generation | Convention summary for AI context | `DnaContextData` |
| Cortex Bridge (D7) | Health scores as grounding signal | `DnaHealthScore` |
| CI Agent | DNA health (part of PR score) | `DnaSummary` |
| MCP Server | drift_dna_profile tool responses | `DnaProfile` |
| CLI | drift dna command output | `DnaProfile` |
| Setup Wizard | DNARunner for onboarding | `DnaAnalysisResult` |

### Upstream Dependencies

| Dependency | What It Provides | Contract |
|-----------|-----------------|----------|
| Scanner (Level 0) | File list, content hashes | `ScanDiff`, `ContentHash` |
| Storage (Level 0) | DatabaseManager for persistence | `batch_writer`, `keyset_pagination` |
| Coupling Analysis (Level 2C) | Module metrics for enrichment | `CouplingSnapshot` (optional) |
| Infrastructure (Level 0) | thiserror, tracing, events, config | Error enums, spans, handlers |


---

## 2. V1 Complete Feature Inventory

Every feature from the v1 TypeScript implementation must be preserved in v2.
This is the zero-feature-loss guarantee.

### 2.1 Core Types (packages/core/src/dna/types.ts)

| # | Feature | V2 Action |
|---|---------|-----------|
| T1 | `GeneId` — 10 gene identifiers (6 frontend + 4 backend) | Rust enum `GeneId` |
| T2 | `FrontendGeneId` — 6 frontend gene IDs | Subset of `GeneId` enum |
| T3 | `BackendGeneId` — 4 backend gene IDs | Subset of `GeneId` enum |
| T4 | `StylingFramework` — 7 framework variants | Rust enum `StylingFramework` |
| T5 | `BackendFramework` — 10 backend framework variants | Rust enum `BackendFramework` |
| T6 | `Gene` — id, name, description, dominant, alleles, confidence, consistency, exemplars | Rust struct `Gene` |
| T7 | `Allele` — id, name, description, frequency, fileCount, pattern, examples, isDominant | Rust struct `Allele` |
| T8 | `AlleleExample` — file, line, code, context | Rust struct `AlleleExample` |
| T9 | `Mutation` — id (SHA-256), file, line, gene, expected, actual, impact, code, suggestion, detectedAt, resolved, resolvedAt | Rust struct `Mutation` |
| T10 | `MutationImpact` — high, medium, low | Rust enum `MutationImpact` |
| T11 | `StylingDNAProfile` — version, generatedAt, projectRoot, summary, genes, mutations, evolution | Rust struct `DnaProfile` |
| T12 | `DNASummary` — totalComponentsAnalyzed, totalFilesAnalyzed, healthScore, geneticDiversity, dominantFramework, dominantBackendFramework, lastUpdated | Rust struct `DnaSummary` |
| T13 | `EvolutionEntry` — timestamp, commitHash, healthScore, geneticDiversity, changes | Rust struct `EvolutionEntry` |
| T14 | `EvolutionChange` — type (gene_shift/mutation_introduced/mutation_resolved/new_allele), gene, description, files | Rust struct `EvolutionChange` |
| T15 | `DNA_VERSION = '1.0.0'` constant | Rust const `DNA_VERSION: &str = "1.0.0"` |

### 2.2 Gene Extractors (packages/core/src/dna/gene-extractors/)

| # | Feature | V2 Action |
|---|---------|-----------|
| E1 | `BaseGeneExtractor` — abstract base with analyze(), aggregateResults(), buildGene() | Rust trait `GeneExtractor` |
| E2 | `AlleleDefinition` — id, name, description, patterns (RegExp[]), keywords, importPatterns, priority | Rust struct `AlleleDefinition` |
| E3 | `DetectedAllele` — alleleId, line, code, confidence, context | Rust struct `DetectedAllele` |
| E4 | `FileExtractionResult` — file, detectedAlleles, isComponent, errors | Rust struct `FileExtractionResult` |
| E5 | `VariantHandlingExtractor` — CVA, clsx, inline conditionals, CSS modules | Rust struct implementing `GeneExtractor` |
| E6 | `ResponsiveApproachExtractor` — Tailwind breakpoints, media queries, container queries | Rust struct implementing `GeneExtractor` |
| E7 | `StateStylingExtractor` — data attributes, aria states, pseudo-classes | Rust struct implementing `GeneExtractor` |
| E8 | `ThemingExtractor` — CSS variables, Tailwind config, theme providers | Rust struct implementing `GeneExtractor` |
| E9 | `SpacingPhilosophyExtractor` — Tailwind spacing, CSS custom properties, design tokens | Rust struct implementing `GeneExtractor` |
| E10 | `AnimationApproachExtractor` — Framer Motion, CSS transitions, Tailwind animate | Rust struct implementing `GeneExtractor` |
| E11 | `ApiResponseFormatExtractor` — envelope patterns, direct returns, status codes | Rust struct implementing `GeneExtractor` |
| E12 | `ErrorResponseFormatExtractor` — error classes, error codes, HTTP status mapping | Rust struct implementing `GeneExtractor` |
| E13 | `LoggingFormatExtractor` — structured logging, console, winston, pino | Rust struct implementing `GeneExtractor` |
| E14 | `ConfigPatternExtractor` — env vars, config files, dependency injection | Rust struct implementing `GeneExtractor` |
| E15 | `createAllGeneExtractors()` — factory returning all 10 | Rust function `create_all_extractors()` |
| E16 | `createFrontendGeneExtractors()` — factory returning 6 frontend | Rust function `create_frontend_extractors()` |
| E17 | `createBackendGeneExtractors()` — factory returning 4 backend | Rust function `create_backend_extractors()` |
| E18 | `createGeneExtractor(geneId)` — factory returning single by ID | Rust function `create_extractor(gene_id)` |
| E19 | `isComponentFile()` — extension + export pattern check | Rust function `is_component_file()` |
| E20 | `extractImports()` — regex extraction of import statements | Rust function `extract_imports()` |
| E21 | `extractContext()` — line number + surrounding 5 lines for match | Rust function `extract_context()` |

### 2.3 Health Calculator (packages/core/src/dna/health-calculator.ts)

| # | Feature | V2 Action |
|---|---------|-----------|
| H1 | 4-factor weighted health score: consistency(40%) + confidence(30%) + mutations(20%) + coverage(10%) | Preserve exactly |
| H2 | Consistency = average consistency across all genes | Preserve exactly |
| H3 | Confidence = average dominant allele frequency | Preserve exactly |
| H4 | Mutation penalty = `(1 - penalty)` scaled by mutation count relative to gene count | Preserve exactly |
| H5 | Dominant coverage = proportion of genes with a dominant allele | Preserve exactly |
| H6 | Result clamped to [0, 100] and rounded | Preserve exactly |
| H7 | Genetic diversity = distinct alleles across genes, normalized | Preserve exactly |
| H8 | `DEFAULT_DNA_THRESHOLDS` — dominantMinFrequency=0.6, mutationImpactHigh=0.1, mutationImpactMedium=0.3, healthScoreWarning=70, healthScoreCritical=50 | Preserve exactly |

### 2.4 Mutation Detector (packages/core/src/dna/mutation-detector.ts)

| # | Feature | V2 Action |
|---|---------|-----------|
| M1 | For each gene with dominant: non-dominant allele occurrences → Mutation records | Preserve exactly |
| M2 | Impact: high (frequency<10% ∧ dominant>80%), medium (frequency<30%), low (else) | Preserve exactly |
| M3 | Mutation ID = SHA-256 hash of file + geneId + alleleId (16 chars) | Preserve exactly (sha2 crate) |
| M4 | Suggestion = "Refactor to use {dominant} instead of {actual}" | Preserve exactly |
| M5 | Sort by impact (high→medium→low), then by file path | Preserve exactly |
| M6 | `filterByGene(mutations, geneId)` — filter to specific gene | Preserve |
| M7 | `filterByImpact(mutations, impact)` — filter by severity | Preserve |
| M8 | Resolution tracking: resolved flag, resolvedAt timestamp | Preserve |

### 2.5 Playbook Generator (packages/core/src/dna/playbook-generator.ts)

| # | Feature | V2 Action |
|---|---------|-----------|
| P1 | Human-readable Markdown playbook from DNA profile | Rust implementation |
| P2 | Quick Reference table: Concern, Our Approach, Confidence | Preserve exactly |
| P3 | Health Score display | Preserve exactly |
| P4 | Per-gene sections: dominant pattern, code example, exemplar files, "avoid" list | Preserve exactly |
| P5 | Top 10 mutations with "and N more" overflow | Preserve exactly |
| P6 | Genes without dominant show "No dominant pattern established" | Preserve exactly |

### 2.6 AI Context Builder (packages/core/src/dna/ai-context.ts)

| # | Feature | V2 Action |
|---|---------|-----------|
| A1 | Level 1 (~20 tokens): one-liner summary | Preserve exactly |
| A2 | Level 2 (~200 tokens): Markdown table | Preserve exactly |
| A3 | Level 3 (~500-2000 tokens): full sections with code examples | Preserve exactly |
| A4 | Level 4 (unlimited): raw JSON profile | Preserve exactly |
| A5 | Token-efficient design for LLM context injection | Preserve exactly |

### 2.7 DNA Store (packages/core/src/dna/dna-store.ts)

| # | Feature | V2 Action |
|---|---------|-----------|
| S1 | JSON persistence to `.drift/dna/styling.json` | **REPLACED** — SQLite (drift.db) |
| S2 | `initialize()` — create directory, load profile | Replaced by DB migration |
| S3 | `load()` → StylingDNAProfile or null | Replaced by SQL query |
| S4 | `save(profile)` — write JSON, append evolution entry | Replaced by SQL upsert |
| S5 | `getProfile()` — in-memory profile | Replaced by SQL query |
| S6 | `getConfig()` — store configuration | Preserved in DnaConfig |
| S7 | Evolution tracking — append snapshot on each save | Preserved in dna_evolution table |
| S8 | 50-entry evolution cap (sliding window) | Preserved via SQL DELETE + LIMIT |

### 2.8 DNA Analyzer Orchestrator (packages/core/src/dna/dna-analyzer.ts)

| # | Feature | V2 Action |
|---|---------|-----------|
| O1 | `DNAAnalyzerConfig` — rootDir, componentPaths, backendPaths, excludePaths, thresholds, verbose, mode | Rust struct `DnaConfig` |
| O2 | Mode selection: frontend/backend/all | Preserve exactly |
| O3 | 5-phase pipeline: discover → extract → mutate → score → assemble | Preserve, enhance with parallelism |
| O4 | `AnalysisResult` — profile, stats, errors | Rust struct `DnaAnalysisResult` |
| O5 | Stats: totalFiles, componentFiles, backendFiles, filesAnalyzed, duration, genesAnalyzed | Preserve exactly |

### 2.9 MCP Integration

| # | Feature | V2 Action |
|---|---------|-----------|
| MCP1 | `drift_dna_profile` — DNA profile query (~800-2000 tokens) | Preserve, route through NAPI |
| MCP2 | `drift_context` — DNA-aware context injection | Preserve, DNA data in context |
| MCP3 | Dual-path: prefer UnifiedStore (SQLite) when available | **SIMPLIFIED** — SQLite only |

### 2.10 CLI Integration

| # | Feature | V2 Action |
|---|---------|-----------|
| CLI1 | `drift dna` — status (default) | Preserve |
| CLI2 | `drift dna scan` — analyze styling DNA | Preserve |
| CLI3 | `drift dna status` — show DNA status | Preserve |
| CLI4 | `drift dna gene <id>` — gene details | Preserve |
| CLI5 | `drift dna mutations` — mutation detection | Preserve |
| CLI6 | `drift dna playbook` — generate styling playbook | Preserve |
| CLI7 | `drift dna export` — export DNA data | Preserve |

### 2.11 Cross-Subsystem Integration

| # | Feature | V2 Action |
|---|---------|-----------|
| X1 | Audit system — health scores feed degradation tracking | Preserve |
| X2 | Pattern service — framework detection aligns with pattern categories | Preserve |
| X3 | Setup wizard — DNARunner for onboarding | Preserve |
| X4 | Sync service — syncDna bidirectional sync | **DROPPED** — SQLite only, no JSON sync |
| X5 | Event bus — DnaAnalysisComplete, MutationDetected events | Preserve via DriftEventHandler |
| X6 | DORA-adjacent metrics — Drift Velocity, Compliance Rate, Health Trend, Mutation Resolution Rate | Preserve |
| X7 | Batch API — AnalysisType::Dna in analyze_batch | Preserve |
| X8 | DNA comparison — diff two profiles | Preserve, new dedicated engine |


---

## 3. V2 Architecture — Unified DNA Engine

### Design Philosophy

The v1 DNA system is a well-designed TypeScript implementation with clean separation
of concerns. The v2 port to Rust preserves this architecture while gaining:

1. **RegexSet single-pass matching** — v1 runs each allele's regex patterns sequentially
   per file. v2 compiles all allele patterns for a gene into a `RegexSet` and matches
   them in a single pass through the file content. For 10 genes × ~4 alleles × ~3
   patterns = ~120 patterns, this is a significant speedup.

2. **Rayon parallelism** — v1 processes files sequentially. v2 uses `rayon::par_iter()`
   to process files in parallel across all CPU cores.

3. **SQLite persistence** — v1 uses JSON files. v2 writes directly to drift.db,
   enabling SQL queries, joins with other analysis data, and atomic transactions.

4. **Content-hash incremental** — v1 re-analyzes all files every time. v2 tracks
   content hashes and only re-analyzes changed files, merging results with cached data.

5. **Zero-copy file reading** — v1 reads files into JavaScript strings (UTF-16). v2
   reads files as `&[u8]` and operates on UTF-8 bytes directly.

### Engine Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        DnaEngine                                 │
│  (drift-core/src/dna/engine.rs — main orchestrator)             │
├──────────┬──────────┬──────────┬──────────┬─────────────────────┤
│ File     │ Gene     │ Mutation │ Health   │ Output              │
│Discovery │Extractors│ Detector │Calculator│ Generators          │
├──────────┴──────────┴──────────┴──────────┴─────────────────────┤
│              Gene Extractors (10, trait-based)                    │
│  Frontend (6)  │  Backend (4)  │  GeneExtractor trait            │
├──────────────────────────────────────────────────────────────────┤
│              RegexSet Optimization Layer                          │
│  Per-gene RegexSet compiled once, reused across all files        │
├──────────────────────────────────────────────────────────────────┤
│              Persistence (drift.db)                               │
│  dna_profiles │ dna_genes │ dna_alleles │ dna_mutations          │
│  dna_evolution │ dna_comparisons                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Module Structure

```
crates/drift-core/src/dna/
├── mod.rs                    # Public API: DnaEngine, analyze(), compare()
├── engine.rs                 # DnaEngine orchestrator (5-phase pipeline)
├── config.rs                 # DnaConfig, DnaThresholds, DnaMode
├── types.rs                  # All DNA types (Gene, Allele, Mutation, Profile, etc.)
├── extractors/
│   ├── mod.rs                # GeneExtractor trait, factory functions
│   ├── base.rs               # Shared aggregation/gene-building logic
│   ├── variant_handling.rs   # VariantHandlingExtractor
│   ├── responsive.rs         # ResponsiveApproachExtractor
│   ├── state_styling.rs      # StateStylingExtractor
│   ├── theming.rs            # ThemingExtractor
│   ├── spacing.rs            # SpacingPhilosophyExtractor
│   ├── animation.rs          # AnimationApproachExtractor
│   ├── api_response.rs       # ApiResponseFormatExtractor
│   ├── error_response.rs     # ErrorResponseFormatExtractor
│   ├── logging.rs            # LoggingFormatExtractor
│   └── config_pattern.rs     # ConfigPatternExtractor
├── mutation.rs               # MutationDetector
├── health.rs                 # HealthCalculator, GeneticDiversityCalculator
├── comparison.rs             # DnaComparisonEngine
├── output/
│   ├── mod.rs                # Output generators
│   ├── playbook.rs           # PlaybookGenerator (Markdown)
│   └── ai_context.rs         # AiContextBuilder (4 levels)
└── storage.rs                # DNA persistence (drift.db read/write)
```

---

## 4. Core Data Model (Rust Types)

### 4.1 Gene Identification

```rust
use serde::{Deserialize, Serialize};

/// All gene identifiers. 10 total: 6 frontend + 4 backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GeneId {
    // Frontend genes (6)
    VariantHandling,
    ResponsiveApproach,
    StateStyling,
    Theming,
    SpacingPhilosophy,
    AnimationApproach,
    // Backend genes (4)
    ApiResponseFormat,
    ErrorResponseFormat,
    LoggingFormat,
    ConfigPattern,
}

impl GeneId {
    pub const FRONTEND: &'static [GeneId] = &[
        GeneId::VariantHandling,
        GeneId::ResponsiveApproach,
        GeneId::StateStyling,
        GeneId::Theming,
        GeneId::SpacingPhilosophy,
        GeneId::AnimationApproach,
    ];

    pub const BACKEND: &'static [GeneId] = &[
        GeneId::ApiResponseFormat,
        GeneId::ErrorResponseFormat,
        GeneId::LoggingFormat,
        GeneId::ConfigPattern,
    ];

    pub const ALL: &'static [GeneId] = &[
        GeneId::VariantHandling,
        GeneId::ResponsiveApproach,
        GeneId::StateStyling,
        GeneId::Theming,
        GeneId::SpacingPhilosophy,
        GeneId::AnimationApproach,
        GeneId::ApiResponseFormat,
        GeneId::ErrorResponseFormat,
        GeneId::LoggingFormat,
        GeneId::ConfigPattern,
    ];

    pub fn is_frontend(&self) -> bool {
        Self::FRONTEND.contains(self)
    }

    pub fn is_backend(&self) -> bool {
        Self::BACKEND.contains(self)
    }

    pub fn name(&self) -> &'static str {
        match self {
            GeneId::VariantHandling => "Variant Handling",
            GeneId::ResponsiveApproach => "Responsive Approach",
            GeneId::StateStyling => "State Styling",
            GeneId::Theming => "Theming",
            GeneId::SpacingPhilosophy => "Spacing Philosophy",
            GeneId::AnimationApproach => "Animation Approach",
            GeneId::ApiResponseFormat => "API Response Format",
            GeneId::ErrorResponseFormat => "Error Response Format",
            GeneId::LoggingFormat => "Logging Format",
            GeneId::ConfigPattern => "Config Pattern",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            GeneId::VariantHandling => "How component variants are managed",
            GeneId::ResponsiveApproach => "How responsive design is implemented",
            GeneId::StateStyling => "How component state affects styling",
            GeneId::Theming => "How theming and design tokens are managed",
            GeneId::SpacingPhilosophy => "How spacing and layout are handled",
            GeneId::AnimationApproach => "How animations and transitions are implemented",
            GeneId::ApiResponseFormat => "How API responses are structured",
            GeneId::ErrorResponseFormat => "How error responses are formatted",
            GeneId::LoggingFormat => "How logging is structured",
            GeneId::ConfigPattern => "How configuration is managed",
        }
    }
}
```

### 4.2 Framework Types

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StylingFramework {
    Tailwind,
    CssModules,
    StyledComponents,
    Emotion,
    VanillaCss,
    Scss,
    Mixed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackendFramework {
    Fastapi,
    Flask,
    Django,
    Express,
    Nestjs,
    Spring,
    Laravel,
    Gin,
    Actix,
    Unknown,
}
```


### 4.3 Core Gene Types

```rust
/// A single allele example — a code snippet demonstrating the allele in context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlleleExample {
    pub file: String,
    pub line: u32,
    pub code: String,
    pub context: String,
}

/// An allele — one variant of a gene (one approach to a convention concern).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Allele {
    pub id: String,
    pub name: String,
    pub description: String,
    pub frequency: f64,         // Proportion of occurrences (0.0–1.0)
    pub file_count: u32,
    pub pattern: String,        // Regex source(s) joined by |
    pub examples: Vec<AlleleExample>,  // Up to 5 code examples
    pub is_dominant: bool,
}

/// A gene — one convention concern with competing alleles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gene {
    pub id: GeneId,
    pub name: String,
    pub description: String,
    pub dominant: Option<Allele>,     // Most common variant (≥30% frequency)
    pub alleles: Vec<Allele>,         // All detected variants, sorted by frequency
    pub confidence: f64,              // Dominant allele frequency (0.0–1.0)
    pub consistency: f64,             // Gap between dominant and second (0.0–1.0)
    pub exemplars: Vec<String>,       // Up to 5 files demonstrating dominant
}

/// Mutation impact severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MutationImpact {
    High,
    Medium,
    Low,
}

/// A mutation — a file deviating from the dominant allele for a gene.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mutation {
    pub id: String,                   // SHA-256 hash (16 chars) of file + geneId + alleleId
    pub file: String,
    pub line: u32,
    pub gene: GeneId,
    pub expected: String,             // Dominant allele ID
    pub actual: String,               // What was found
    pub impact: MutationImpact,
    pub code: String,
    pub suggestion: String,
    pub detected_at: String,          // ISO 8601 timestamp
    pub resolved: bool,
    pub resolved_at: Option<String>,
}
```

### 4.4 Profile Types

```rust
/// DNA summary — aggregate metrics for the profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnaSummary {
    pub total_components_analyzed: u32,
    pub total_files_analyzed: u32,
    pub health_score: u32,            // 0–100, rounded
    pub genetic_diversity: f64,       // 0.0–1.0
    pub dominant_framework: StylingFramework,
    pub dominant_backend_framework: Option<BackendFramework>,
    pub last_updated: String,         // ISO 8601
}

/// Evolution change type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvolutionChangeType {
    GeneShift,
    MutationIntroduced,
    MutationResolved,
    NewAllele,
}

/// A single change within an evolution entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionChange {
    #[serde(rename = "type")]
    pub change_type: EvolutionChangeType,
    pub gene: Option<GeneId>,
    pub description: String,
    pub files: Option<Vec<String>>,
}

/// An evolution snapshot — one point in the DNA's history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionEntry {
    pub timestamp: String,            // ISO 8601
    pub commit_hash: Option<String>,
    pub health_score: u32,
    pub genetic_diversity: f64,
    pub changes: Vec<EvolutionChange>,
}

/// The complete DNA profile — the "genome" of the codebase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnaProfile {
    pub version: String,              // "1.0.0"
    pub generated_at: String,         // ISO 8601
    pub project_root: String,
    pub summary: DnaSummary,
    pub genes: FxHashMap<GeneId, Gene>,
    pub mutations: Vec<Mutation>,
    pub evolution: Vec<EvolutionEntry>,
}

/// DNA analysis result — returned from the engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnaAnalysisResult {
    pub profile: DnaProfile,
    pub stats: DnaAnalysisStats,
    pub errors: Vec<String>,
}

/// Analysis statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnaAnalysisStats {
    pub total_files: u32,
    pub component_files: u32,
    pub backend_files: u32,
    pub files_analyzed: u32,
    pub duration_ms: u32,
    pub genes_analyzed: u32,
}
```

### 4.5 Configuration Types

```rust
/// DNA analysis mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnaMode {
    Frontend,
    Backend,
    All,
}

impl Default for DnaMode {
    fn default() -> Self {
        DnaMode::All
    }
}

/// DNA analysis thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnaThresholds {
    pub dominant_min_frequency: f64,    // Default: 0.6
    pub mutation_impact_high: f64,      // Default: 0.1
    pub mutation_impact_medium: f64,    // Default: 0.3
    pub health_score_warning: u32,      // Default: 70
    pub health_score_critical: u32,     // Default: 50
}

impl Default for DnaThresholds {
    fn default() -> Self {
        Self {
            dominant_min_frequency: 0.6,
            mutation_impact_high: 0.1,
            mutation_impact_medium: 0.3,
            health_score_warning: 70,
            health_score_critical: 50,
        }
    }
}

/// DNA engine configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnaConfig {
    pub component_paths: Vec<String>,   // Default: ["src/components", "src/features"]
    pub backend_paths: Vec<String>,     // Default: ["src", "app", "api", "routes", ...]
    pub exclude_paths: Vec<String>,     // Default: ["**/*.test.*", "**/*.stories.*", ...]
    pub thresholds: DnaThresholds,
    pub mode: DnaMode,
    pub verbose: bool,
}

impl Default for DnaConfig {
    fn default() -> Self {
        Self {
            component_paths: vec![
                "src/components".into(),
                "src/features".into(),
            ],
            backend_paths: vec![
                "src".into(), "app".into(), "api".into(),
                "routes".into(), "handlers".into(),
                "controllers".into(), "services".into(),
            ],
            exclude_paths: vec![
                "**/*.test.*".into(),
                "**/*.stories.*".into(),
                "**/index.ts".into(),
            ],
            thresholds: DnaThresholds::default(),
            mode: DnaMode::All,
            verbose: false,
        }
    }
}
```

### 4.6 Comparison Types

```rust
/// Comparison between two DNA profiles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnaComparison {
    pub profile_a_root: String,
    pub profile_b_root: String,
    pub health_delta: i32,              // B.health - A.health
    pub diversity_delta: f64,           // B.diversity - A.diversity
    pub gene_diffs: Vec<GeneDiff>,
    pub mutation_diffs: MutationDiff,
    pub overall_similarity: f64,        // 0.0–1.0
}

/// Diff for a single gene between two profiles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneDiff {
    pub gene: GeneId,
    pub dominant_a: Option<String>,     // Allele ID in profile A
    pub dominant_b: Option<String>,     // Allele ID in profile B
    pub confidence_delta: f64,
    pub consistency_delta: f64,
    pub dominant_changed: bool,
}

/// Aggregate mutation diff between two profiles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationDiff {
    pub count_a: u32,
    pub count_b: u32,
    pub new_mutations: u32,             // In B but not A
    pub resolved_mutations: u32,        // In A but not B
    pub shared_mutations: u32,          // In both
}
```

---

## 5. Phase 1: File Discovery & Content Loading

### Algorithm

File discovery walks configured paths relative to the project root, applies exclude
filters, and categorizes files as component (frontend) or backend.

```rust
use std::path::{Path, PathBuf};
use globset::{Glob, GlobSet, GlobSetBuilder};
use rayon::prelude::*;

pub struct FileDiscovery {
    component_paths: Vec<PathBuf>,
    backend_paths: Vec<PathBuf>,
    exclude_set: GlobSet,
}

pub struct DiscoveredFiles {
    pub component_files: Vec<PathBuf>,
    pub backend_files: Vec<PathBuf>,
    pub all_files: Vec<PathBuf>,
    pub file_contents: FxHashMap<PathBuf, String>,
}

impl FileDiscovery {
    pub fn new(config: &DnaConfig, root: &Path) -> Self {
        let mut builder = GlobSetBuilder::new();
        for pattern in &config.exclude_paths {
            if let Ok(glob) = Glob::new(pattern) {
                builder.add(glob);
            }
        }
        let exclude_set = builder.build().unwrap_or_default();

        Self {
            component_paths: config.component_paths.iter()
                .map(|p| root.join(p))
                .collect(),
            backend_paths: config.backend_paths.iter()
                .map(|p| root.join(p))
                .collect(),
            exclude_set,
        }
    }

    pub fn discover(&self, root: &Path) -> DiscoveredFiles {
        let component_files = self.walk_paths(&self.component_paths, root);
        let backend_files = self.walk_paths(&self.backend_paths, root);

        let mut all_files = component_files.clone();
        all_files.extend(backend_files.iter().cloned());
        all_files.sort();
        all_files.dedup();

        // Parallel file reading
        let file_contents: FxHashMap<PathBuf, String> = all_files
            .par_iter()
            .filter_map(|path| {
                std::fs::read_to_string(path).ok().map(|content| (path.clone(), content))
            })
            .collect();

        DiscoveredFiles {
            component_files,
            backend_files,
            all_files,
            file_contents,
        }
    }

    fn walk_paths(&self, paths: &[PathBuf], root: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        for base in paths {
            if !base.exists() { continue; }
            for entry in walkdir::WalkDir::new(base)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
            {
                let path = entry.path();
                let relative = path.strip_prefix(root).unwrap_or(path);
                if !self.exclude_set.is_match(relative) {
                    files.push(path.to_path_buf());
                }
            }
        }
        files
    }
}
```

### Content-Hash Integration

When running incrementally, file discovery checks content hashes from the scanner.
Only files with changed hashes are re-read and re-analyzed. Unchanged files use
cached gene extraction results from drift.db.

```rust
pub fn discover_incremental(
    &self,
    root: &Path,
    db: &DatabaseManager,
    scan_diff: &ScanDiff,
) -> DiscoveredFiles {
    // Only re-analyze files that changed
    let changed_paths: FxHashSet<PathBuf> = scan_diff.added.iter()
        .chain(scan_diff.modified.iter())
        .map(|f| root.join(&f.path))
        .collect();

    let mut discovered = self.discover(root);

    // Filter to only changed files for re-analysis
    discovered.all_files.retain(|f| changed_paths.contains(f));
    discovered.file_contents.retain(|k, _| changed_paths.contains(k));

    discovered
}
```


---

## 6. Phase 2: Gene Extraction Pipeline (10 Extractors)

### GeneExtractor Trait

The core abstraction. Each of the 10 extractors implements this trait.

```rust
use regex::RegexSet;

/// Definition of a single allele (one approach to a convention concern).
pub struct AlleleDefinition {
    pub id: String,
    pub name: String,
    pub description: String,
    pub patterns: Vec<String>,          // Regex pattern strings
    pub keywords: Vec<String>,          // Additional keyword matching
    pub import_patterns: Vec<String>,   // Import-based detection patterns
    pub priority: u32,                  // Higher = preferred when tied
}

/// A detected allele occurrence in a single file.
pub struct DetectedAllele {
    pub allele_id: String,
    pub line: u32,
    pub code: String,
    pub confidence: f64,
    pub context: Option<String>,
}

/// Result of extracting genes from a single file.
pub struct FileExtractionResult {
    pub file: String,
    pub detected_alleles: Vec<DetectedAllele>,
    pub is_component: bool,
    pub errors: Vec<String>,
}

/// The gene extractor trait — implemented by all 10 extractors.
pub trait GeneExtractor: Send + Sync {
    /// The gene this extractor targets.
    fn gene_id(&self) -> GeneId;

    /// Human-readable gene name.
    fn gene_name(&self) -> &str;

    /// Gene description.
    fn gene_description(&self) -> &str;

    /// All allele definitions for this gene.
    fn allele_definitions(&self) -> &[AlleleDefinition];

    /// Extract alleles from a single file.
    fn extract_from_file(
        &self,
        file_path: &str,
        content: &str,
        imports: &[String],
    ) -> FileExtractionResult;

    /// Compiled RegexSet for all allele patterns (cached on construction).
    fn regex_set(&self) -> &RegexSet;

    /// Map from RegexSet index → (allele_id, pattern_index).
    fn pattern_index_map(&self) -> &[(String, usize)];
}
```

### Shared Aggregation Logic (base.rs)

The aggregation and gene-building pipeline is shared across all extractors.
This is the equivalent of v1's `BaseGeneExtractor.analyze()`.

```rust
use rustc_hash::{FxHashMap, FxHashSet};

/// Aggregated extraction results across all files for one gene.
pub struct AggregatedResults {
    pub allele_counts: FxHashMap<String, u32>,
    pub allele_files: FxHashMap<String, FxHashSet<String>>,
    pub allele_examples: FxHashMap<String, Vec<AlleleExample>>,
    pub total_occurrences: u32,
}

/// Run a gene extractor across all files and build the Gene.
pub fn analyze_gene(
    extractor: &dyn GeneExtractor,
    files: &FxHashMap<PathBuf, String>,
    thresholds: &DnaThresholds,
) -> Gene {
    // Phase 1: Aggregate results across all files
    let aggregated = aggregate_results(extractor, files);

    // Phase 2: Build gene from aggregated data
    build_gene(extractor, &aggregated, thresholds)
}

fn aggregate_results(
    extractor: &dyn GeneExtractor,
    files: &FxHashMap<PathBuf, String>,
) -> AggregatedResults {
    let mut result = AggregatedResults {
        allele_counts: FxHashMap::default(),
        allele_files: FxHashMap::default(),
        allele_examples: FxHashMap::default(),
        total_occurrences: 0,
    };

    for (path, content) in files {
        let file_str = path.to_string_lossy().to_string();
        let imports = extract_imports(content);
        let extraction = extractor.extract_from_file(&file_str, content, &imports);

        for detected in &extraction.detected_alleles {
            *result.allele_counts.entry(detected.allele_id.clone()).or_insert(0) += 1;
            result.allele_files
                .entry(detected.allele_id.clone())
                .or_default()
                .insert(file_str.clone());

            let examples = result.allele_examples
                .entry(detected.allele_id.clone())
                .or_default();
            if examples.len() < 5 {
                examples.push(AlleleExample {
                    file: file_str.clone(),
                    line: detected.line,
                    code: detected.code.clone(),
                    context: detected.context.clone().unwrap_or_default(),
                });
            }

            result.total_occurrences += 1;
        }
    }

    result
}

fn build_gene(
    extractor: &dyn GeneExtractor,
    aggregated: &AggregatedResults,
    thresholds: &DnaThresholds,
) -> Gene {
    if aggregated.total_occurrences == 0 {
        return Gene {
            id: extractor.gene_id(),
            name: extractor.gene_name().to_string(),
            description: extractor.gene_description().to_string(),
            dominant: None,
            alleles: Vec::new(),
            confidence: 0.0,
            consistency: 0.0,
            exemplars: Vec::new(),
        };
    }

    let definitions = extractor.allele_definitions();
    let total = aggregated.total_occurrences as f64;

    // Build alleles sorted by frequency descending
    let mut alleles: Vec<Allele> = definitions.iter()
        .filter_map(|def| {
            let count = aggregated.allele_counts.get(&def.id).copied().unwrap_or(0);
            if count == 0 { return None; }

            let frequency = count as f64 / total;
            let file_count = aggregated.allele_files
                .get(&def.id)
                .map(|s| s.len() as u32)
                .unwrap_or(0);
            let examples = aggregated.allele_examples
                .get(&def.id)
                .cloned()
                .unwrap_or_default();

            Some(Allele {
                id: def.id.clone(),
                name: def.name.clone(),
                description: def.description.clone(),
                frequency,
                file_count,
                pattern: def.patterns.join("|"),
                examples,
                is_dominant: false,
            })
        })
        .collect();

    alleles.sort_by(|a, b| b.frequency.partial_cmp(&a.frequency).unwrap());

    // Select dominant: top allele if frequency ≥ 0.3 (v1 threshold)
    let dominant = if let Some(top) = alleles.first() {
        if top.frequency >= 0.3 {
            let mut dom = top.clone();
            dom.is_dominant = true;
            Some(dom)
        } else {
            None
        }
    } else {
        None
    };

    // Mark dominant in alleles list
    if let Some(ref dom) = dominant {
        if let Some(a) = alleles.iter_mut().find(|a| a.id == dom.id) {
            a.is_dominant = true;
        }
    }

    // Confidence = dominant allele's frequency
    let confidence = dominant.as_ref().map(|d| d.frequency).unwrap_or(0.0);

    // Consistency = 0.5 + (dominant - second) * 0.5, clamped to [0, 1]
    let consistency = if alleles.len() >= 2 {
        let gap = alleles[0].frequency - alleles[1].frequency;
        (0.5 + gap * 0.5).clamp(0.0, 1.0)
    } else if alleles.len() == 1 {
        1.0
    } else {
        0.0
    };

    // Exemplars = up to 5 files from dominant allele's file set
    let exemplars = dominant.as_ref()
        .and_then(|d| aggregated.allele_files.get(&d.id))
        .map(|files| files.iter().take(5).cloned().collect())
        .unwrap_or_default();

    Gene {
        id: extractor.gene_id(),
        name: extractor.gene_name().to_string(),
        description: extractor.gene_description().to_string(),
        dominant,
        alleles,
        confidence,
        consistency,
        exemplars,
    }
}
```

### Helper Functions

```rust
/// Check if a file is a component file (frontend).
/// Checks extension (.tsx, .jsx, .vue, .svelte) + export pattern.
pub fn is_component_file(file_path: &str, content: &str) -> bool {
    let ext_match = file_path.ends_with(".tsx")
        || file_path.ends_with(".jsx")
        || file_path.ends_with(".vue")
        || file_path.ends_with(".svelte");

    if !ext_match { return false; }

    // Check for component export pattern
    content.contains("export default")
        || content.contains("export function")
        || content.contains("export const")
}

/// Extract import statements from file content via regex.
pub fn extract_imports(content: &str) -> Vec<String> {
    use regex::Regex;
    use std::sync::LazyLock;

    static IMPORT_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?m)^(?:import\s+.*?from\s+['"]([^'"]+)['"]|const\s+\w+\s*=\s*require\(['"]([^'"]+)['"]\))"#).unwrap()
    });

    IMPORT_RE.captures_iter(content)
        .filter_map(|cap| {
            cap.get(1).or(cap.get(2)).map(|m| m.as_str().to_string())
        })
        .collect()
}

/// Extract context around a match: line number + surrounding 5 lines.
pub fn extract_context(content: &str, byte_offset: usize) -> (u32, String) {
    let line_num = content[..byte_offset].matches('\n').count() as u32 + 1;
    let lines: Vec<&str> = content.lines().collect();
    let start = line_num.saturating_sub(3) as usize;
    let end = (line_num as usize + 2).min(lines.len());
    let context = lines[start..end].join("\n");
    (line_num, context)
}
```

---

## 7. Phase 3: Frontend Gene Extractors (6)

Each frontend extractor targets a specific styling/UI convention concern.
All use the same pattern: define alleles with regex patterns, implement
`extract_from_file()` to scan content, return detected alleles.

### 7.1 VariantHandlingExtractor

Detects how component variants are managed.

| Allele ID | Name | Detection Patterns |
|-----------|------|--------------------|
| `cva-variants` | CVA (Class Variance Authority) | `cva\(`, `import.*cva`, `variants:\s*\{` |
| `clsx-conditionals` | clsx/classnames | `clsx\(`, `classnames\(`, `cn\(`, `import.*clsx` |
| `inline-conditionals` | Inline Conditionals | `className=\{.*\?.*:`, `style=\{.*\?` |
| `css-module-variants` | CSS Modules | `styles\[`, `styles\.`, `import.*\.module\.` |

### 7.2 ResponsiveApproachExtractor

Detects responsive design implementation approach.

| Allele ID | Name | Detection Patterns |
|-----------|------|--------------------|
| `tailwind-breakpoints` | Tailwind Breakpoints | `\b(sm|md|lg|xl|2xl):`, `className=.*\b(sm|md|lg|xl):` |
| `media-queries` | CSS Media Queries | `@media\s*\(`, `useMediaQuery`, `matchMedia` |
| `container-queries` | Container Queries | `@container`, `container-type:`, `useContainerQuery` |

### 7.3 StateStylingExtractor

Detects how component state affects styling.

| Allele ID | Name | Detection Patterns |
|-----------|------|--------------------|
| `data-attributes` | Data Attributes | `data-\w+=`, `\[data-`, `data-state=` |
| `aria-states` | ARIA States | `aria-\w+=`, `\[aria-`, `aria-selected`, `aria-expanded` |
| `pseudo-classes` | CSS Pseudo-classes | `:hover`, `:focus`, `:active`, `:disabled` |

### 7.4 ThemingExtractor

Detects theming and design token management.

| Allele ID | Name | Detection Patterns |
|-----------|------|--------------------|
| `css-variables` | CSS Custom Properties | `var\(--`, `--\w+:`, `setProperty\(` |
| `tailwind-config` | Tailwind Config | `theme\.\w+`, `colors\.`, `extend:\s*\{` |
| `theme-provider` | Theme Provider | `ThemeProvider`, `useTheme`, `createTheme` |

### 7.5 SpacingPhilosophyExtractor

Detects spacing and layout approach.

| Allele ID | Name | Detection Patterns |
|-----------|------|--------------------|
| `tailwind-spacing` | Tailwind Spacing | `\b(p|m|gap|space)-\d`, `\b(px|py|mx|my)-\d` |
| `css-custom-spacing` | CSS Custom Properties | `var\(--spacing`, `var\(--gap`, `var\(--margin` |
| `design-tokens` | Design Tokens | `tokens\.spacing`, `theme\.spacing`, `spacing\[` |

### 7.6 AnimationApproachExtractor

Detects animation and transition implementation.

| Allele ID | Name | Detection Patterns |
|-----------|------|--------------------|
| `framer-motion` | Framer Motion | `motion\.`, `animate=`, `import.*framer-motion`, `useAnimation` |
| `css-transitions` | CSS Transitions | `transition:`, `transition-`, `@keyframes`, `animation:` |
| `tailwind-animate` | Tailwind Animate | `animate-`, `transition-all`, `duration-`, `ease-` |

---

## 8. Phase 4: Backend Gene Extractors (4)

### 8.1 ApiResponseFormatExtractor

Detects API response structure patterns.

| Allele ID | Name | Detection Patterns |
|-----------|------|--------------------|
| `envelope-pattern` | Envelope Pattern | `\{.*data:.*,.*meta:`, `\{.*success:.*,.*data:`, `\{.*status:.*,.*result:` |
| `direct-return` | Direct Return | `return\s+res\.(json|send)\(`, `Response\(`, `JsonResponse\(` |
| `status-code-pattern` | Status Code Pattern | `res\.status\(\d+\)`, `status_code=\d+`, `HttpStatus\.\w+` |

### 8.2 ErrorResponseFormatExtractor

Detects error response formatting patterns.

| Allele ID | Name | Detection Patterns |
|-----------|------|--------------------|
| `error-class` | Error Classes | `extends\s+Error`, `class\s+\w+Error`, `HttpException` |
| `error-code-pattern` | Error Codes | `error_code:`, `errorCode:`, `code:\s*['"]ERR_` |
| `http-status-mapping` | HTTP Status Mapping | `HttpStatus\.`, `status\(\d{3}\)`, `StatusCode::` |

### 8.3 LoggingFormatExtractor

Detects logging approach.

| Allele ID | Name | Detection Patterns |
|-----------|------|--------------------|
| `structured-logging` | Structured Logging | `logger\.\w+\(\{`, `log\.\w+\(\{`, `structlog`, `JSON\.stringify.*log` |
| `console-logging` | Console Logging | `console\.(log|warn|error|info)`, `print\(`, `println!` |
| `winston-pino` | Winston/Pino | `winston`, `pino`, `createLogger`, `import.*winston`, `import.*pino` |

### 8.4 ConfigPatternExtractor

Detects configuration management approach.

| Allele ID | Name | Detection Patterns |
|-----------|------|--------------------|
| `env-vars` | Environment Variables | `process\.env\.`, `os\.environ`, `env::var`, `getenv` |
| `config-files` | Config Files | `config\.\w+`, `loadConfig`, `readConfig`, `import.*config` |
| `dependency-injection` | Dependency Injection | `@Injectable`, `@Inject`, `inject\(`, `provide\(`, `useInjection` |


---

## 9. Phase 5: Allele Aggregation & Gene Assembly

This phase is handled by the shared `analyze_gene()` function in `base.rs` (§6).
The pipeline for each gene:

1. Iterate all files, call `extract_from_file()` per file
2. Tally `allele_counts` (HashMap<AlleleId, u32>)
3. Track `allele_files` (HashMap<AlleleId, HashSet<String>>)
4. Collect `allele_examples` (up to 5 per allele)
5. Calculate frequency per allele: `count / total_occurrences`
6. Sort alleles by frequency descending
7. Select dominant: top allele if frequency ≥ 0.3
8. Confidence = dominant allele's frequency
9. Consistency = `0.5 + (dominant - second) * 0.5`, clamped to [0, 1]
10. Exemplars = up to 5 files from dominant allele's file set

### Parallel Gene Extraction

All 10 genes are extracted in parallel using rayon. Each gene's extraction is
independent — no shared mutable state between extractors.

```rust
use rayon::prelude::*;

pub fn extract_all_genes(
    extractors: &[Box<dyn GeneExtractor>],
    files: &FxHashMap<PathBuf, String>,
    thresholds: &DnaThresholds,
) -> FxHashMap<GeneId, Gene> {
    extractors.par_iter()
        .map(|extractor| {
            let gene = analyze_gene(extractor.as_ref(), files, thresholds);
            (extractor.gene_id(), gene)
        })
        .collect()
}
```

---

## 10. Phase 6: Mutation Detection

### Algorithm

For each gene with a dominant allele, every occurrence of a non-dominant allele
becomes a mutation. This is the v1 algorithm preserved exactly.

```rust
use sha2::{Sha256, Digest};

pub struct MutationDetector {
    thresholds: DnaThresholds,
}

impl MutationDetector {
    pub fn new(thresholds: DnaThresholds) -> Self {
        Self { thresholds }
    }

    pub fn detect_mutations(
        &self,
        genes: &FxHashMap<GeneId, Gene>,
    ) -> Vec<Mutation> {
        let mut mutations = Vec::new();
        let now = chrono::Utc::now().to_rfc3339();

        for (gene_id, gene) in genes {
            let dominant = match &gene.dominant {
                Some(d) => d,
                None => continue,
            };

            for allele in &gene.alleles {
                if allele.is_dominant { continue; }

                let impact = self.classify_impact(
                    allele.frequency,
                    dominant.frequency,
                );

                for example in &allele.examples {
                    let id = self.generate_mutation_id(
                        &example.file,
                        gene_id,
                        &allele.id,
                    );

                    mutations.push(Mutation {
                        id,
                        file: example.file.clone(),
                        line: example.line,
                        gene: *gene_id,
                        expected: dominant.id.clone(),
                        actual: allele.id.clone(),
                        impact,
                        code: example.code.clone(),
                        suggestion: format!(
                            "Refactor to use {} instead of {}",
                            dominant.name, allele.name
                        ),
                        detected_at: now.clone(),
                        resolved: false,
                        resolved_at: None,
                    });
                }
            }
        }

        // Sort by impact (high → medium → low), then by file path
        mutations.sort_by(|a, b| {
            impact_order(&a.impact).cmp(&impact_order(&b.impact))
                .then_with(|| a.file.cmp(&b.file))
        });

        mutations
    }

    fn classify_impact(&self, allele_freq: f64, dominant_freq: f64) -> MutationImpact {
        if allele_freq < self.thresholds.mutation_impact_high && dominant_freq > 0.8 {
            MutationImpact::High
        } else if allele_freq < self.thresholds.mutation_impact_medium {
            MutationImpact::Medium
        } else {
            MutationImpact::Low
        }
    }

    fn generate_mutation_id(
        &self,
        file: &str,
        gene_id: &GeneId,
        allele_id: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(file.as_bytes());
        hasher.update(format!("{:?}", gene_id).as_bytes());
        hasher.update(allele_id.as_bytes());
        let result = hasher.finalize();
        hex::encode(&result[..8]) // 16 hex chars from first 8 bytes
    }
}

fn impact_order(impact: &MutationImpact) -> u8 {
    match impact {
        MutationImpact::High => 0,
        MutationImpact::Medium => 1,
        MutationImpact::Low => 2,
    }
}
```

### Mutation Filtering

```rust
impl MutationDetector {
    pub fn filter_by_gene(mutations: &[Mutation], gene_id: GeneId) -> Vec<&Mutation> {
        mutations.iter().filter(|m| m.gene == gene_id).collect()
    }

    pub fn filter_by_impact(mutations: &[Mutation], impact: MutationImpact) -> Vec<&Mutation> {
        mutations.iter().filter(|m| m.impact == impact).collect()
    }
}
```

### Resolution Tracking

When a mutation is resolved (the file is updated to match the dominant allele),
the mutation's `resolved` flag is set to `true` and `resolved_at` is timestamped.
This is tracked across analysis runs by comparing mutation IDs — if a mutation ID
from the previous run is absent in the current run, it's marked resolved.

```rust
pub fn reconcile_mutations(
    current: &mut Vec<Mutation>,
    previous: &[Mutation],
) {
    let now = chrono::Utc::now().to_rfc3339();
    let current_ids: FxHashSet<&str> = current.iter().map(|m| m.id.as_str()).collect();

    // Mutations in previous but not current → resolved
    for prev in previous {
        if !current_ids.contains(prev.id.as_str()) && !prev.resolved {
            let mut resolved = prev.clone();
            resolved.resolved = true;
            resolved.resolved_at = Some(now.clone());
            current.push(resolved);
        }
    }
}
```

---

## 11. Phase 7: Health Score Calculation

### Formula (Preserved Exactly from V1)

```
healthScore = consistency(40%) + confidence(30%) + mutations(20%) + coverage(10%)
```

```rust
pub struct HealthCalculator {
    thresholds: DnaThresholds,
}

impl HealthCalculator {
    pub fn new(thresholds: DnaThresholds) -> Self {
        Self { thresholds }
    }

    pub fn calculate_health_score(
        &self,
        genes: &FxHashMap<GeneId, Gene>,
        mutations: &[Mutation],
    ) -> u32 {
        let gene_count = genes.len() as f64;
        if gene_count == 0.0 { return 0; }

        // Component 1: Consistency (40%)
        let avg_consistency: f64 = genes.values()
            .map(|g| g.consistency)
            .sum::<f64>() / gene_count;
        let consistency_score = avg_consistency * 40.0;

        // Component 2: Confidence (30%)
        let avg_confidence: f64 = genes.values()
            .map(|g| g.confidence)
            .sum::<f64>() / gene_count;
        let confidence_score = avg_confidence * 30.0;

        // Component 3: Mutation penalty (20%)
        let mutation_count = mutations.iter().filter(|m| !m.resolved).count() as f64;
        let mutation_penalty = (mutation_count / gene_count).min(1.0);
        let mutation_score = (1.0 - mutation_penalty) * 20.0;

        // Component 4: Dominant coverage (10%)
        let genes_with_dominant = genes.values()
            .filter(|g| g.dominant.is_some())
            .count() as f64;
        let dominant_coverage = genes_with_dominant / gene_count;
        let coverage_score = dominant_coverage * 10.0;

        // Total: clamped to [0, 100], rounded
        let total = consistency_score + confidence_score + mutation_score + coverage_score;
        total.clamp(0.0, 100.0).round() as u32
    }
}
```

---

## 12. Phase 8: Genetic Diversity Calculation

Measures how many distinct alleles exist across all genes, normalized.
Higher diversity means more competing approaches — informational, not inherently bad.

```rust
impl HealthCalculator {
    pub fn calculate_genetic_diversity(
        &self,
        genes: &FxHashMap<GeneId, Gene>,
    ) -> f64 {
        let gene_count = genes.len() as f64;
        if gene_count == 0.0 { return 0.0; }

        let total_alleles: usize = genes.values()
            .map(|g| g.alleles.len())
            .sum();

        // Normalize: 1 allele per gene = 0.0 diversity, many alleles = higher
        // Max theoretical: if every gene had all possible alleles
        let avg_alleles_per_gene = total_alleles as f64 / gene_count;

        // Normalize to 0.0–1.0 range
        // 1 allele = 0.0, 2 = 0.25, 3 = 0.5, 4 = 0.625, 5+ = approaching 1.0
        if avg_alleles_per_gene <= 1.0 {
            0.0
        } else {
            1.0 - (1.0 / avg_alleles_per_gene)
        }
    }
}
```

---

## 13. Phase 9: Profile Assembly

The DnaEngine orchestrates all phases and assembles the final profile.

```rust
pub struct DnaEngine {
    config: DnaConfig,
    extractors: Vec<Box<dyn GeneExtractor>>,
    mutation_detector: MutationDetector,
    health_calculator: HealthCalculator,
}

impl DnaEngine {
    pub fn new(config: DnaConfig) -> Self {
        let extractors = match config.mode {
            DnaMode::Frontend => create_frontend_extractors(),
            DnaMode::Backend => create_backend_extractors(),
            DnaMode::All => create_all_extractors(),
        };

        Self {
            mutation_detector: MutationDetector::new(config.thresholds.clone()),
            health_calculator: HealthCalculator::new(config.thresholds.clone()),
            extractors,
            config,
        }
    }

    pub fn analyze(
        &self,
        root: &Path,
        db: &DatabaseManager,
        event_handler: &dyn DriftEventHandler,
    ) -> Result<DnaAnalysisResult, DnaError> {
        let start = std::time::Instant::now();
        let mut errors = Vec::new();

        // Phase 1: Discover files
        let discovery = FileDiscovery::new(&self.config, root);
        let files = discovery.discover(root);

        event_handler.on_dna_progress(DnaProgress::FilesDiscovered {
            total: files.all_files.len(),
        });

        // Phase 2-5: Extract genes (parallel)
        let genes = extract_all_genes(
            &self.extractors,
            &files.file_contents,
            &self.config.thresholds,
        );

        event_handler.on_dna_progress(DnaProgress::GenesExtracted {
            count: genes.len(),
        });

        // Phase 6: Detect mutations
        let mut mutations = self.mutation_detector.detect_mutations(&genes);

        // Reconcile with previous mutations from DB
        if let Ok(previous) = load_previous_mutations(db) {
            reconcile_mutations(&mut mutations, &previous);
        }

        event_handler.on_dna_progress(DnaProgress::MutationsDetected {
            count: mutations.len(),
        });

        // Phase 7-8: Calculate health and diversity
        let health_score = self.health_calculator.calculate_health_score(&genes, &mutations);
        let genetic_diversity = self.health_calculator.calculate_genetic_diversity(&genes);

        // Phase 9: Assemble profile
        let now = chrono::Utc::now().to_rfc3339();
        let profile = DnaProfile {
            version: DNA_VERSION.to_string(),
            generated_at: now.clone(),
            project_root: root.to_string_lossy().to_string(),
            summary: DnaSummary {
                total_components_analyzed: files.component_files.len() as u32,
                total_files_analyzed: files.all_files.len() as u32,
                health_score,
                genetic_diversity,
                dominant_framework: detect_dominant_framework(&genes),
                dominant_backend_framework: detect_dominant_backend_framework(&genes),
                last_updated: now,
            },
            genes,
            mutations,
            evolution: Vec::new(), // Loaded from DB, appended in storage phase
        };

        let stats = DnaAnalysisStats {
            total_files: files.all_files.len() as u32,
            component_files: files.component_files.len() as u32,
            backend_files: files.backend_files.len() as u32,
            files_analyzed: files.file_contents.len() as u32,
            duration_ms: start.elapsed().as_millis() as u32,
            genes_analyzed: self.extractors.len() as u32,
        };

        // Persist to drift.db
        save_dna_profile(db, &profile)?;

        // Emit events
        event_handler.on_dna_complete(&profile);
        for mutation in &profile.mutations {
            if !mutation.resolved {
                event_handler.on_mutation_detected(mutation);
            }
        }

        Ok(DnaAnalysisResult { profile, stats, errors })
    }
}

const DNA_VERSION: &str = "1.0.0";
```


---

## 14. Phase 10: Evolution Tracking

Each analysis run appends an evolution snapshot. The sliding window caps at 50 entries.

```rust
pub fn append_evolution_entry(
    db: &DatabaseManager,
    profile: &DnaProfile,
    previous: Option<&DnaProfile>,
) -> Result<(), DnaError> {
    let changes = if let Some(prev) = previous {
        detect_evolution_changes(prev, profile)
    } else {
        Vec::new()
    };

    let entry = EvolutionEntry {
        timestamp: profile.generated_at.clone(),
        commit_hash: detect_current_commit(),
        health_score: profile.summary.health_score,
        genetic_diversity: profile.summary.genetic_diversity,
        changes,
    };

    // Insert into dna_evolution table
    db.execute(
        "INSERT INTO dna_evolution (timestamp, commit_hash, health_score, genetic_diversity, changes_json)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            entry.timestamp,
            entry.commit_hash,
            entry.health_score,
            entry.genetic_diversity,
            serde_json::to_string(&entry.changes)?,
        ],
    )?;

    // Cap at 50 entries (sliding window)
    db.execute(
        "DELETE FROM dna_evolution WHERE rowid NOT IN (
            SELECT rowid FROM dna_evolution ORDER BY timestamp DESC LIMIT 50
        )",
        [],
    )?;

    Ok(())
}

fn detect_evolution_changes(
    previous: &DnaProfile,
    current: &DnaProfile,
) -> Vec<EvolutionChange> {
    let mut changes = Vec::new();

    for (gene_id, current_gene) in &current.genes {
        if let Some(prev_gene) = previous.genes.get(gene_id) {
            // Check for gene shift (dominant allele changed)
            let prev_dominant = prev_gene.dominant.as_ref().map(|d| &d.id);
            let curr_dominant = current_gene.dominant.as_ref().map(|d| &d.id);
            if prev_dominant != curr_dominant {
                changes.push(EvolutionChange {
                    change_type: EvolutionChangeType::GeneShift,
                    gene: Some(*gene_id),
                    description: format!(
                        "{}: dominant shifted from {:?} to {:?}",
                        gene_id.name(), prev_dominant, curr_dominant
                    ),
                    files: None,
                });
            }

            // Check for new alleles
            let prev_allele_ids: FxHashSet<&str> = prev_gene.alleles.iter()
                .map(|a| a.id.as_str()).collect();
            for allele in &current_gene.alleles {
                if !prev_allele_ids.contains(allele.id.as_str()) {
                    changes.push(EvolutionChange {
                        change_type: EvolutionChangeType::NewAllele,
                        gene: Some(*gene_id),
                        description: format!(
                            "{}: new allele detected — {}",
                            gene_id.name(), allele.name
                        ),
                        files: None,
                    });
                }
            }
        }
    }

    // Check for new/resolved mutations
    let prev_mutation_ids: FxHashSet<&str> = previous.mutations.iter()
        .filter(|m| !m.resolved)
        .map(|m| m.id.as_str())
        .collect();
    let curr_mutation_ids: FxHashSet<&str> = current.mutations.iter()
        .filter(|m| !m.resolved)
        .map(|m| m.id.as_str())
        .collect();

    let new_count = curr_mutation_ids.difference(&prev_mutation_ids).count();
    let resolved_count = prev_mutation_ids.difference(&curr_mutation_ids).count();

    if new_count > 0 {
        changes.push(EvolutionChange {
            change_type: EvolutionChangeType::MutationIntroduced,
            gene: None,
            description: format!("{} new mutation(s) introduced", new_count),
            files: None,
        });
    }
    if resolved_count > 0 {
        changes.push(EvolutionChange {
            change_type: EvolutionChangeType::MutationResolved,
            gene: None,
            description: format!("{} mutation(s) resolved", resolved_count),
            files: None,
        });
    }

    changes
}

fn detect_current_commit() -> Option<String> {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok().map(|s| s.trim().to_string())
            } else {
                None
            }
        })
}
```

---

## 15. Phase 11: DNA Comparison Engine

Compares two DNA profiles to measure convention drift between projects,
branches, or time periods.

```rust
pub struct DnaComparisonEngine;

impl DnaComparisonEngine {
    pub fn compare(a: &DnaProfile, b: &DnaProfile) -> DnaComparison {
        let health_delta = b.summary.health_score as i32 - a.summary.health_score as i32;
        let diversity_delta = b.summary.genetic_diversity - a.summary.genetic_diversity;

        let mut gene_diffs = Vec::new();
        let all_gene_ids: FxHashSet<GeneId> = a.genes.keys()
            .chain(b.genes.keys())
            .copied()
            .collect();

        let mut similarity_sum = 0.0;
        let mut gene_count = 0;

        for gene_id in &all_gene_ids {
            let gene_a = a.genes.get(gene_id);
            let gene_b = b.genes.get(gene_id);

            let dominant_a = gene_a.and_then(|g| g.dominant.as_ref()).map(|d| d.id.clone());
            let dominant_b = gene_b.and_then(|g| g.dominant.as_ref()).map(|d| d.id.clone());
            let dominant_changed = dominant_a != dominant_b;

            let confidence_a = gene_a.map(|g| g.confidence).unwrap_or(0.0);
            let confidence_b = gene_b.map(|g| g.confidence).unwrap_or(0.0);
            let consistency_a = gene_a.map(|g| g.consistency).unwrap_or(0.0);
            let consistency_b = gene_b.map(|g| g.consistency).unwrap_or(0.0);

            // Similarity: 1.0 if same dominant, 0.0 if different, weighted by confidence
            let gene_similarity = if !dominant_changed {
                (confidence_a + confidence_b) / 2.0
            } else {
                0.0
            };
            similarity_sum += gene_similarity;
            gene_count += 1;

            gene_diffs.push(GeneDiff {
                gene: *gene_id,
                dominant_a,
                dominant_b,
                confidence_delta: confidence_b - confidence_a,
                consistency_delta: consistency_b - consistency_a,
                dominant_changed,
            });
        }

        let overall_similarity = if gene_count > 0 {
            similarity_sum / gene_count as f64
        } else {
            0.0
        };

        // Mutation diff
        let a_ids: FxHashSet<&str> = a.mutations.iter().map(|m| m.id.as_str()).collect();
        let b_ids: FxHashSet<&str> = b.mutations.iter().map(|m| m.id.as_str()).collect();

        let mutation_diffs = MutationDiff {
            count_a: a.mutations.len() as u32,
            count_b: b.mutations.len() as u32,
            new_mutations: b_ids.difference(&a_ids).count() as u32,
            resolved_mutations: a_ids.difference(&b_ids).count() as u32,
            shared_mutations: a_ids.intersection(&b_ids).count() as u32,
        };

        DnaComparison {
            profile_a_root: a.project_root.clone(),
            profile_b_root: b.project_root.clone(),
            health_delta,
            diversity_delta,
            gene_diffs,
            mutation_diffs,
            overall_similarity,
        }
    }
}
```

---

## 16. Phase 12: Playbook Generation (Markdown Output)

Generates a human-readable Markdown playbook — the "style guide" output.

```rust
pub struct PlaybookGenerator;

impl PlaybookGenerator {
    pub fn generate(profile: &DnaProfile) -> String {
        let mut output = String::with_capacity(4096);

        // Header
        output.push_str("# Styling Playbook\n");
        output.push_str(&format!(
            "> Auto-generated by drift DNA analysis. Last updated: {}\n\n",
            profile.summary.last_updated
        ));

        // Quick Reference table
        output.push_str("## Quick Reference\n");
        output.push_str("| Concern | Our Approach | Confidence |\n");
        output.push_str("|---------|--------------|------------|\n");
        for gene in profile.genes.values() {
            let approach = gene.dominant.as_ref()
                .map(|d| d.name.as_str())
                .unwrap_or("*No dominant*");
            let confidence = format!("{}%", (gene.confidence * 100.0).round() as u32);
            output.push_str(&format!(
                "| {} | {} | {} |\n",
                gene.name, approach, confidence
            ));
        }

        // Health Score
        output.push_str(&format!(
            "\n## Health Score: {}/100\n\n---\n",
            profile.summary.health_score
        ));

        // Per-gene sections
        for gene in profile.genes.values() {
            output.push_str(&format!("\n## {}\n", gene.name));

            if let Some(ref dominant) = gene.dominant {
                output.push_str(&format!("**Our Pattern**: {}\n", dominant.name));
                output.push_str(&format!("{}\n", dominant.description));

                // Code example from first exemplar
                if let Some(example) = dominant.examples.first() {
                    output.push_str("```\n");
                    output.push_str(&example.code);
                    output.push_str("\n```\n");
                }

                // Exemplar files
                if !gene.exemplars.is_empty() {
                    output.push_str("**Exemplar Files**:\n");
                    for file in &gene.exemplars {
                        output.push_str(&format!("- `{}`\n", file));
                    }
                }

                // Avoid list (non-dominant alleles)
                let avoid: Vec<&str> = gene.alleles.iter()
                    .filter(|a| !a.is_dominant)
                    .map(|a| a.name.as_str())
                    .collect();
                if !avoid.is_empty() {
                    output.push_str("**Avoid**:\n");
                    for name in avoid {
                        output.push_str(&format!("- {}\n", name));
                    }
                }
            } else {
                output.push_str("*No dominant pattern established*\n");
            }
        }

        // Mutations section (top 10)
        let active_mutations: Vec<&Mutation> = profile.mutations.iter()
            .filter(|m| !m.resolved)
            .collect();
        if !active_mutations.is_empty() {
            output.push_str("\n---\n## Mutations\n");
            output.push_str("Files deviating from established patterns:\n");
            let show_count = active_mutations.len().min(10);
            for mutation in &active_mutations[..show_count] {
                output.push_str(&format!(
                    "- **{}:{}** - {} (expected: {})\n",
                    mutation.file, mutation.line, mutation.actual, mutation.expected
                ));
            }
            if active_mutations.len() > 10 {
                output.push_str(&format!(
                    "- ... and {} more\n",
                    active_mutations.len() - 10
                ));
            }
        }

        output
    }
}
```

---

## 17. Phase 13: AI Context Builder (4-Level Token-Efficient Output)

Generates AI-ready context at 4 detail levels for injection into LLM prompts.

```rust
pub struct AiContextBuilder;

impl AiContextBuilder {
    pub fn build(profile: &DnaProfile, level: u8) -> String {
        match level {
            1 => Self::build_level_1(profile),
            2 => Self::build_level_2(profile),
            3 => Self::build_level_3(profile),
            4 => Self::build_level_4(profile),
            _ => Self::build_level_2(profile), // Default to level 2
        }
    }

    /// Level 1 (~20 tokens): One-liner summary.
    fn build_level_1(profile: &DnaProfile) -> String {
        let framework = format!("{:?}", profile.summary.dominant_framework).to_lowercase();
        let approaches: Vec<&str> = profile.genes.values()
            .filter_map(|g| g.dominant.as_ref().map(|d| d.name.as_str()))
            .collect();
        format!(
            "{} codebase using {}. Health: {}/100.",
            framework,
            approaches.join(", "),
            profile.summary.health_score
        )
    }

    /// Level 2 (~200 tokens): Markdown table.
    fn build_level_2(profile: &DnaProfile) -> String {
        let mut output = String::new();
        output.push_str("## Styling Conventions\n\n");
        output.push_str("| Concern | Approach | Confidence |\n");
        output.push_str("|---------|----------|------------|\n");
        for gene in profile.genes.values() {
            let approach = gene.dominant.as_ref()
                .map(|d| d.name.as_str())
                .unwrap_or("*None*");
            output.push_str(&format!(
                "| {} | {} | {}% |\n",
                gene.name, approach, (gene.confidence * 100.0).round() as u32
            ));
        }
        output.push_str(&format!(
            "\nHealth Score: {}/100\n",
            profile.summary.health_score
        ));
        output
    }

    /// Level 3 (~500-2000 tokens): Full sections with code examples.
    fn build_level_3(profile: &DnaProfile) -> String {
        let mut output = String::new();
        let framework = format!("{:?}", profile.summary.dominant_framework).to_lowercase();
        output.push_str(&format!("# Styling Conventions ({})\n\n", framework));

        for gene in profile.genes.values() {
            if let Some(ref dominant) = gene.dominant {
                output.push_str(&format!("## {}\n", gene.name));
                output.push_str(&format!("Use {}:\n", dominant.name));
                if let Some(example) = dominant.examples.first() {
                    output.push_str("```\n");
                    output.push_str(&example.code);
                    output.push_str("\n```\n\n");
                }
            }
        }

        // Mutation warning
        let active = profile.mutations.iter().filter(|m| !m.resolved).count();
        if active > 0 {
            output.push_str(&format!("---\n⚠️ {} mutations detected\n", active));
            for mutation in profile.mutations.iter().filter(|m| !m.resolved).take(5) {
                output.push_str(&format!(
                    "- {}: {}\n",
                    mutation.file, mutation.actual
                ));
            }
        }

        output
    }

    /// Level 4 (unlimited): Raw JSON profile.
    fn build_level_4(profile: &DnaProfile) -> String {
        serde_json::to_string_pretty(profile).unwrap_or_default()
    }
}
```


---

## 18. RegexSet Optimization — Single-Pass Multi-Pattern Matching

### The Problem

v1 runs each allele's regex patterns sequentially per file. For 10 genes × ~4 alleles
× ~3 patterns = ~120 patterns, each file is scanned ~120 times. For a 10K file codebase,
that's 1.2M regex scans.

### The Solution: RegexSet

Rust's `regex::RegexSet` compiles multiple patterns into a single automaton and matches
all of them in a single pass through the input. This is the key performance optimization
for gene extraction.

```rust
use regex::{RegexSet, Regex};

/// Compiled regex set for a single gene extractor.
/// Maps RegexSet match indices back to (allele_id, pattern_index).
pub struct CompiledGenePatterns {
    pub regex_set: RegexSet,
    pub individual_regexes: Vec<Regex>,
    pub index_map: Vec<(String, usize)>,  // (allele_id, pattern_index_within_allele)
}

impl CompiledGenePatterns {
    pub fn new(definitions: &[AlleleDefinition]) -> Self {
        let mut all_patterns = Vec::new();
        let mut index_map = Vec::new();

        for def in definitions {
            for (i, pattern) in def.patterns.iter().enumerate() {
                all_patterns.push(pattern.as_str());
                index_map.push((def.id.clone(), i));
            }
        }

        let regex_set = RegexSet::new(&all_patterns)
            .expect("All allele patterns must be valid regex");

        let individual_regexes: Vec<Regex> = all_patterns.iter()
            .map(|p| Regex::new(p).unwrap())
            .collect();

        Self { regex_set, individual_regexes, index_map }
    }

    /// Single-pass matching: returns all allele IDs that matched in this content.
    pub fn match_all(&self, content: &str) -> Vec<(String, Vec<regex::Match<'_>>)> {
        let matches: Vec<usize> = self.regex_set.matches(content).into_iter().collect();

        let mut results: FxHashMap<String, Vec<regex::Match<'_>>> = FxHashMap::default();

        for idx in matches {
            let (allele_id, _) = &self.index_map[idx];
            // Use individual regex to get match locations
            for m in self.individual_regexes[idx].find_iter(content) {
                results.entry(allele_id.clone()).or_default().push(m);
            }
        }

        results.into_iter().collect()
    }
}
```

### Performance Impact

| Metric | v1 (Sequential) | v2 (RegexSet) | Improvement |
|--------|-----------------|---------------|-------------|
| Regex scans per file | ~120 | 1 (set) + N (individual for matches) | ~10-50x fewer |
| 10K file codebase | ~1.2M scans | ~10K set scans + ~50K individual | ~10x faster |
| Pattern compilation | Per-call (JS) | Once at startup (Rust) | Amortized to zero |

The RegexSet determines *which* patterns match in a single pass. Individual regexes
are only invoked for patterns that actually matched, to get match locations. For most
files, only 1-3 alleles match per gene, so the individual regex overhead is minimal.

---

## 19. Incremental DNA Analysis (Content-Hash Aware)

### Strategy

Full DNA analysis on every run is wasteful for large codebases. v2 supports incremental
analysis by tracking which files have changed since the last run.

```rust
pub fn analyze_incremental(
    engine: &DnaEngine,
    root: &Path,
    db: &DatabaseManager,
    scan_diff: &ScanDiff,
    event_handler: &dyn DriftEventHandler,
) -> Result<DnaAnalysisResult, DnaError> {
    // Load previous gene extraction results from drift.db
    let cached_results = load_cached_gene_results(db)?;

    // Discover only changed files
    let discovery = FileDiscovery::new(&engine.config, root);
    let changed_files = discovery.discover_incremental(root, db, scan_diff);

    // Extract genes from changed files only
    let fresh_results = extract_all_genes(
        &engine.extractors,
        &changed_files.file_contents,
        &engine.config.thresholds,
    );

    // Merge: fresh results override cached for changed files
    let merged_genes = merge_gene_results(&cached_results, &fresh_results);

    // Continue with mutation detection, health scoring, etc.
    let mutations = engine.mutation_detector.detect_mutations(&merged_genes);
    let health_score = engine.health_calculator.calculate_health_score(&merged_genes, &mutations);
    let genetic_diversity = engine.health_calculator.calculate_genetic_diversity(&merged_genes);

    // Assemble and persist
    // ... (same as full analysis from Phase 9)
    todo!()
}

fn merge_gene_results(
    cached: &FxHashMap<GeneId, CachedGeneData>,
    fresh: &FxHashMap<GeneId, Gene>,
) -> FxHashMap<GeneId, Gene> {
    // For each gene, merge allele counts from cached (unchanged files)
    // with fresh counts (changed files). Rebuild gene from merged counts.
    // This ensures the gene reflects the full codebase, not just changed files.
    todo!()
}
```

### Cache Invalidation

A gene's cached data is invalidated when:
1. Any file contributing to that gene's allele counts has changed
2. The gene extractor's patterns have changed (version bump)
3. The DNA configuration has changed (paths, thresholds)

Cache invalidation is tracked per-file in the `dna_file_cache` table:

```sql
CREATE TABLE dna_file_cache (
    file_path TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    gene_id TEXT NOT NULL,
    allele_counts_json TEXT NOT NULL,  -- JSON: {allele_id: count}
    extracted_at TEXT NOT NULL,
    PRIMARY KEY (file_path, gene_id)
) STRICT;
```

---

## 20. Integration with Unified Analysis Engine

The DNA system can optionally consume data from the Unified Analysis Engine's
ParseResult to enrich gene extraction. When ParseResult data is available,
extractors can use AST-level information instead of pure regex.

```rust
/// Enhanced extraction using ParseResult data when available.
pub trait EnhancedGeneExtractor: GeneExtractor {
    /// Extract alleles using both content and parsed AST data.
    fn extract_from_parsed(
        &self,
        file_path: &str,
        content: &str,
        parse_result: &ParseResult,
    ) -> FileExtractionResult {
        // Default: fall back to regex-only extraction
        let imports = extract_imports(content);
        self.extract_from_file(file_path, content, &imports)
    }
}
```

This is an optional enhancement — the DNA system works standalone with regex-only
extraction. AST-enhanced extraction improves accuracy for patterns that are ambiguous
in regex (e.g., distinguishing a CSS module import from a regular import).

---

## 21. Integration with Coupling Analysis

The DNA system consumes coupling metrics as an optional enrichment signal.
Coupling data can inform gene extraction (e.g., modules with high coupling
may have different convention patterns than isolated modules).

```rust
/// Coupling data consumed by DNA for enrichment.
pub struct CouplingEnrichment {
    pub module_metrics: FxHashMap<String, ModuleMetrics>,
    pub cycle_count: u32,
    pub health_score: u32,
}

/// DNA can optionally weight gene confidence by module coupling.
/// Highly-coupled modules' conventions carry more weight because
/// they affect more of the codebase.
pub fn weight_by_coupling(
    gene: &mut Gene,
    coupling: &CouplingEnrichment,
) {
    // Adjust exemplar selection: prefer files in highly-coupled modules
    // This ensures the "style guide" reflects the most impactful conventions
    if let Some(ref dominant) = gene.dominant {
        let mut weighted_exemplars: Vec<(String, f64)> = gene.exemplars.iter()
            .map(|file| {
                let module = extract_module_from_path(file);
                let weight = coupling.module_metrics.get(&module)
                    .map(|m| m.afferent as f64 + m.efferent as f64)
                    .unwrap_or(1.0);
                (file.clone(), weight)
            })
            .collect();
        weighted_exemplars.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        gene.exemplars = weighted_exemplars.into_iter()
            .take(5)
            .map(|(f, _)| f)
            .collect();
    }
}
```

---

## 22. Integration with Quality Gates & Audit

### Quality Gate Input

The DNA system provides a gate input for the quality gate evaluator.

```rust
/// Input to the DNA quality gate.
pub struct DnaGateInput {
    pub health_score: u32,
    pub mutation_count: u32,
    pub high_impact_mutations: u32,
    pub genes_without_dominant: u32,
    pub genetic_diversity: f64,
}

impl From<&DnaProfile> for DnaGateInput {
    fn from(profile: &DnaProfile) -> Self {
        Self {
            health_score: profile.summary.health_score,
            mutation_count: profile.mutations.iter().filter(|m| !m.resolved).count() as u32,
            high_impact_mutations: profile.mutations.iter()
                .filter(|m| !m.resolved && m.impact == MutationImpact::High)
                .count() as u32,
            genes_without_dominant: profile.genes.values()
                .filter(|g| g.dominant.is_none())
                .count() as u32,
            genetic_diversity: profile.summary.genetic_diversity,
        }
    }
}
```

### Audit Integration

DNA health scores feed the audit system's degradation tracking.

```rust
/// Snapshot for audit system consumption.
pub struct DnaHealthSnapshot {
    pub health_score: u32,
    pub previous_health_score: Option<u32>,
    pub health_delta: Option<i32>,
    pub mutation_count: u32,
    pub timestamp: String,
}
```

The audit system compares consecutive DNA health snapshots to detect degradation:
- Health drop > 5 points → warning
- Health drop > 15 points → critical
- Health trend (7-day rolling average) → improving / stable / declining

### DORA-Adjacent Convention Health Metrics

From the audit spec, DNA feeds 4 DORA-adjacent metrics:

| Metric | Calculation | Assessment |
|--------|-------------|------------|
| Drift Velocity | Dominant allele changes per month | Stable / Evolving / Volatile |
| Compliance Rate | Files matching dominant alleles / total files | Percentage |
| Health Trend | Slope of health score over time (linear regression) | Improving / Stable / Degrading / Critical |
| Mutation Resolution Rate | Median days to resolve detected mutations | Days |

```rust
pub struct DoraMetrics {
    pub drift_velocity: f64,          // Changes per month
    pub drift_assessment: String,     // "Stable" | "Evolving" | "Volatile"
    pub compliance_rate: f64,         // 0.0–1.0
    pub health_trend: f64,            // Slope (positive = improving)
    pub health_assessment: String,    // "Improving" | "Stable" | "Degrading" | "Critical"
    pub mutation_resolution_rate: f64, // Median days
}

pub fn calculate_dora_metrics(
    evolution: &[EvolutionEntry],
    mutations: &[Mutation],
) -> DoraMetrics {
    // Drift Velocity: count gene_shift events in last 30 days
    let thirty_days_ago = chrono::Utc::now() - chrono::Duration::days(30);
    let recent_shifts = evolution.iter()
        .filter(|e| {
            chrono::DateTime::parse_from_rfc3339(&e.timestamp)
                .map(|t| t > thirty_days_ago)
                .unwrap_or(false)
        })
        .flat_map(|e| &e.changes)
        .filter(|c| c.change_type == EvolutionChangeType::GeneShift)
        .count();

    let drift_velocity = recent_shifts as f64;
    let drift_assessment = match drift_velocity {
        v if v < 1.0 => "Stable",
        v if v < 3.0 => "Evolving",
        _ => "Volatile",
    }.to_string();

    // Health Trend: linear regression on evolution health scores
    let health_trend = if evolution.len() >= 2 {
        simple_linear_regression(
            &evolution.iter().enumerate()
                .map(|(i, e)| (i as f64, e.health_score as f64))
                .collect::<Vec<_>>()
        )
    } else {
        0.0
    };

    let health_assessment = match health_trend {
        t if t > 2.0 => "Improving",
        t if t > -2.0 => "Stable",
        t if t > -5.0 => "Degrading",
        _ => "Critical",
    }.to_string();

    // Mutation Resolution Rate: median days between detected_at and resolved_at
    let resolution_days: Vec<f64> = mutations.iter()
        .filter(|m| m.resolved)
        .filter_map(|m| {
            let detected = chrono::DateTime::parse_from_rfc3339(&m.detected_at).ok()?;
            let resolved = chrono::DateTime::parse_from_rfc3339(m.resolved_at.as_ref()?).ok()?;
            Some((resolved - detected).num_days() as f64)
        })
        .collect();

    let mutation_resolution_rate = if resolution_days.is_empty() {
        0.0
    } else {
        let mut sorted = resolution_days;
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        sorted[sorted.len() / 2]
    };

    // Compliance Rate: calculated from gene data (not available here, passed in)
    let compliance_rate = 0.0; // Calculated externally from gene allele frequencies

    DoraMetrics {
        drift_velocity,
        drift_assessment,
        compliance_rate,
        health_trend,
        health_assessment,
        mutation_resolution_rate,
    }
}

fn simple_linear_regression(points: &[(f64, f64)]) -> f64 {
    let n = points.len() as f64;
    let sum_x: f64 = points.iter().map(|(x, _)| x).sum();
    let sum_y: f64 = points.iter().map(|(_, y)| y).sum();
    let sum_xy: f64 = points.iter().map(|(x, y)| x * y).sum();
    let sum_x2: f64 = points.iter().map(|(x, _)| x * x).sum();

    let denominator = n * sum_x2 - sum_x * sum_x;
    if denominator.abs() < f64::EPSILON { return 0.0; }

    (n * sum_xy - sum_x * sum_y) / denominator
}
```


---

## 23. Integration with Simulation Engine

The simulation engine consumes DNA data for friction scoring and pattern alignment.

```rust
/// DNA data consumed by the simulation engine's PatternAlignmentScorer.
pub struct DnaSimulationInput {
    pub dominant_alleles: FxHashMap<GeneId, String>,  // Gene → dominant allele ID
    pub health_score: u32,
    pub mutation_files: FxHashSet<String>,             // Files with active mutations
}

impl From<&DnaProfile> for DnaSimulationInput {
    fn from(profile: &DnaProfile) -> Self {
        Self {
            dominant_alleles: profile.genes.iter()
                .filter_map(|(id, g)| {
                    g.dominant.as_ref().map(|d| (*id, d.id.clone()))
                })
                .collect(),
            health_score: profile.summary.health_score,
            mutation_files: profile.mutations.iter()
                .filter(|m| !m.resolved)
                .map(|m| m.file.clone())
                .collect(),
        }
    }
}
```

The simulation engine uses this to:
1. Score pattern alignment of proposed changes against dominant alleles
2. Flag friction when changes touch files with active mutations
3. Weight risk scores by DNA health (lower health = higher risk)

---

## 24. Integration with Context Generation

The context generation system uses DNA data to produce AI-ready context.

```rust
/// DNA context data for the context generation system.
pub struct DnaContextData {
    pub level_1: String,   // One-liner (~20 tokens)
    pub level_2: String,   // Table (~200 tokens)
    pub level_3: String,   // Full sections (~500-2000 tokens)
    pub health_score: u32,
    pub mutation_count: u32,
}

impl From<&DnaProfile> for DnaContextData {
    fn from(profile: &DnaProfile) -> Self {
        Self {
            level_1: AiContextBuilder::build(profile, 1),
            level_2: AiContextBuilder::build(profile, 2),
            level_3: AiContextBuilder::build(profile, 3),
            health_score: profile.summary.health_score,
            mutation_count: profile.mutations.iter().filter(|m| !m.resolved).count() as u32,
        }
    }
}
```

The `drift_context` MCP tool includes DNA context at the appropriate level based on
the available token budget. Level 1 is always included (20 tokens is negligible).
Level 2 is included when budget allows. Level 3 is included for code generation tasks.

---

## 25. Integration with Cortex Grounding (D7)

Per PLANNING-DRIFT.md D7: DNA health scores are a grounding signal that the bridge
crate can compare against Cortex memories. Drift computes them independently.

```rust
/// DNA grounding data for the cortex-drift-napi bridge crate.
/// This is NOT part of drift-core — it lives in the bridge crate.
pub struct DnaGroundingSignal {
    pub health_score: u32,
    pub dominant_conventions: Vec<(String, String, f64)>,  // (gene_name, allele_name, confidence)
    pub mutation_count: u32,
    pub timestamp: String,
}
```

The bridge crate uses this to:
1. Validate Cortex memories about code conventions against actual DNA data
2. Flag stale memories when DNA shows convention shifts
3. Provide grounding context for memory-linked AI responses

---

## 26. Storage Schema (drift.db DNA Tables)

### Table Definitions

```sql
-- DNA profile (singleton — one active profile per project)
CREATE TABLE dna_profiles (
    id INTEGER PRIMARY KEY DEFAULT 1,
    version TEXT NOT NULL DEFAULT '1.0.0',
    generated_at TEXT NOT NULL,
    project_root TEXT NOT NULL,
    health_score INTEGER NOT NULL,
    genetic_diversity REAL NOT NULL,
    dominant_framework TEXT,
    dominant_backend_framework TEXT,
    total_components_analyzed INTEGER NOT NULL,
    total_files_analyzed INTEGER NOT NULL,
    last_updated TEXT NOT NULL
) STRICT;

-- DNA genes (one row per gene, 10 total)
CREATE TABLE dna_genes (
    gene_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    dominant_allele_id TEXT,
    confidence REAL NOT NULL DEFAULT 0.0,
    consistency REAL NOT NULL DEFAULT 0.0,
    alleles_json TEXT NOT NULL DEFAULT '[]',    -- JSON array of Allele objects
    exemplars_json TEXT NOT NULL DEFAULT '[]',  -- JSON array of file paths
    updated_at TEXT NOT NULL
) STRICT;

-- DNA mutations (one row per active mutation)
CREATE TABLE dna_mutations (
    id TEXT PRIMARY KEY,                        -- SHA-256 hash (16 chars)
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    gene_id TEXT NOT NULL REFERENCES dna_genes(gene_id),
    expected_allele TEXT NOT NULL,
    actual_allele TEXT NOT NULL,
    impact TEXT NOT NULL CHECK (impact IN ('high', 'medium', 'low')),
    code TEXT NOT NULL,
    suggestion TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    resolved INTEGER NOT NULL DEFAULT 0,
    resolved_at TEXT
) STRICT;

-- DNA evolution (sliding window, max 50 entries)
CREATE TABLE dna_evolution (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    commit_hash TEXT,
    health_score INTEGER NOT NULL,
    genetic_diversity REAL NOT NULL,
    changes_json TEXT NOT NULL DEFAULT '[]'     -- JSON array of EvolutionChange
) STRICT;

-- DNA file cache (for incremental analysis)
CREATE TABLE dna_file_cache (
    file_path TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    gene_id TEXT NOT NULL,
    allele_counts_json TEXT NOT NULL,           -- JSON: {allele_id: count}
    extracted_at TEXT NOT NULL,
    PRIMARY KEY (file_path, gene_id)
) STRICT;

-- DNA comparisons (stored comparison results)
CREATE TABLE dna_comparisons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_a_root TEXT NOT NULL,
    profile_b_root TEXT NOT NULL,
    health_delta INTEGER NOT NULL,
    diversity_delta REAL NOT NULL,
    overall_similarity REAL NOT NULL,
    gene_diffs_json TEXT NOT NULL,
    mutation_diffs_json TEXT NOT NULL,
    compared_at TEXT NOT NULL
) STRICT;

-- Indexes
CREATE INDEX idx_dna_mutations_gene ON dna_mutations(gene_id);
CREATE INDEX idx_dna_mutations_impact ON dna_mutations(impact);
CREATE INDEX idx_dna_mutations_file ON dna_mutations(file);
CREATE INDEX idx_dna_mutations_resolved ON dna_mutations(resolved);
CREATE INDEX idx_dna_evolution_timestamp ON dna_evolution(timestamp);
CREATE INDEX idx_dna_file_cache_hash ON dna_file_cache(content_hash);
```

### Persistence Functions

```rust
pub fn save_dna_profile(db: &DatabaseManager, profile: &DnaProfile) -> Result<(), DnaError> {
    let tx = db.begin_transaction()?;

    // Upsert profile (singleton)
    tx.execute(
        "INSERT OR REPLACE INTO dna_profiles (id, version, generated_at, project_root,
         health_score, genetic_diversity, dominant_framework, dominant_backend_framework,
         total_components_analyzed, total_files_analyzed, last_updated)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        rusqlite::params![
            profile.version,
            profile.generated_at,
            profile.project_root,
            profile.summary.health_score,
            profile.summary.genetic_diversity,
            serde_json::to_string(&profile.summary.dominant_framework)?,
            profile.summary.dominant_backend_framework.map(|f| serde_json::to_string(&f).unwrap()),
            profile.summary.total_components_analyzed,
            profile.summary.total_files_analyzed,
            profile.summary.last_updated,
        ],
    )?;

    // Upsert genes
    for (gene_id, gene) in &profile.genes {
        tx.execute(
            "INSERT OR REPLACE INTO dna_genes (gene_id, name, description, dominant_allele_id,
             confidence, consistency, alleles_json, exemplars_json, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                serde_json::to_string(gene_id)?,
                gene.name,
                gene.description,
                gene.dominant.as_ref().map(|d| &d.id),
                gene.confidence,
                gene.consistency,
                serde_json::to_string(&gene.alleles)?,
                serde_json::to_string(&gene.exemplars)?,
                profile.generated_at,
            ],
        )?;
    }

    // Replace mutations (delete all, insert current)
    tx.execute("DELETE FROM dna_mutations", [])?;
    for mutation in &profile.mutations {
        tx.execute(
            "INSERT INTO dna_mutations (id, file, line, gene_id, expected_allele, actual_allele,
             impact, code, suggestion, detected_at, resolved, resolved_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params![
                mutation.id,
                mutation.file,
                mutation.line,
                serde_json::to_string(&mutation.gene)?,
                mutation.expected,
                mutation.actual,
                serde_json::to_string(&mutation.impact)?,
                mutation.code,
                mutation.suggestion,
                mutation.detected_at,
                mutation.resolved as i32,
                mutation.resolved_at,
            ],
        )?;
    }

    tx.commit()?;
    Ok(())
}

pub fn load_dna_profile(db: &DatabaseManager) -> Result<Option<DnaProfile>, DnaError> {
    // Query profile, genes, mutations, evolution from drift.db
    // Assemble into DnaProfile struct
    // Returns None if no profile exists yet
    todo!()
}

pub fn load_previous_mutations(db: &DatabaseManager) -> Result<Vec<Mutation>, DnaError> {
    // Query all mutations from dna_mutations table
    todo!()
}
```


---

## 27. NAPI Interface

### DNA Binding Module (bindings/dna.rs)

Per 03-NAPI-BRIDGE-V2-PREP.md §10.11, the DNA system exposes 2 NAPI functions.
v2 adds 2 more for query and history.

| Function | Sync/Async | Returns | Description |
|----------|-----------|---------|-------------|
| `analyze_dna(root)` | Async | `DnaProfileSummary` | Full DNA analysis → write to drift.db → return summary |
| `compare_dna(profile_a_json, profile_b_json)` | Sync | `DnaComparison` | Compare two profiles |
| `query_dna_profile()` | Sync | `DnaProfile` | Read current profile from drift.db |
| `query_dna_mutations(filter)` | Sync | `PaginatedResult<Mutation>` | Query mutations with filters |
| `query_dna_evolution(limit)` | Sync | `Vec<EvolutionEntry>` | Query evolution history |
| `generate_dna_playbook()` | Sync | `String` | Generate Markdown playbook |
| `generate_dna_context(level)` | Sync | `String` | Generate AI context at specified level |

### NAPI Types (conversions/dna_types.rs)

```rust
#[napi(object)]
pub struct NapiDnaProfileSummary {
    pub health_score: u32,
    pub genetic_diversity: f64,
    pub total_files_analyzed: u32,
    pub total_components_analyzed: u32,
    pub genes_analyzed: u32,
    pub mutation_count: u32,
    pub high_impact_mutations: u32,
    pub dominant_framework: String,
    pub duration_ms: u32,
}

#[napi(object)]
pub struct NapiDnaMutationFilter {
    pub gene_id: Option<String>,
    pub impact: Option<String>,
    pub file_pattern: Option<String>,
    pub resolved: Option<bool>,
}

#[napi(object)]
pub struct NapiDnaComparison {
    pub health_delta: i32,
    pub diversity_delta: f64,
    pub overall_similarity: f64,
    pub gene_diffs: serde_json::Value,
    pub mutation_diffs: serde_json::Value,
}
```

### Implementation Pattern

Following the command/query pattern from 03-NAPI-BRIDGE-V2-PREP.md §5:

```rust
use napi::bindgen_prelude::*;

pub struct AnalyzeDnaTask {
    root: String,
}

#[napi]
impl Task for AnalyzeDnaTask {
    type Output = NapiDnaProfileSummary;
    type JsValue = NapiDnaProfileSummary;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let rt = crate::runtime::get()?;
        let root = PathBuf::from(&self.root);

        let config = rt.config.dna.clone();
        let engine = DnaEngine::new(config);

        let result = engine.analyze(&root, &rt.db, &NoOpEventHandler)
            .map_err(to_napi_error)?;

        Ok(NapiDnaProfileSummary {
            health_score: result.profile.summary.health_score,
            genetic_diversity: result.profile.summary.genetic_diversity,
            total_files_analyzed: result.stats.total_files,
            total_components_analyzed: result.stats.component_files,
            genes_analyzed: result.stats.genes_analyzed,
            mutation_count: result.profile.mutations.iter()
                .filter(|m| !m.resolved).count() as u32,
            high_impact_mutations: result.profile.mutations.iter()
                .filter(|m| !m.resolved && m.impact == MutationImpact::High)
                .count() as u32,
            dominant_framework: format!("{:?}", result.profile.summary.dominant_framework),
            duration_ms: result.stats.duration_ms,
        })
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(output)
    }
}

#[napi]
pub fn analyze_dna(root: String) -> AsyncTask<AnalyzeDnaTask> {
    AsyncTask::new(AnalyzeDnaTask { root })
}

#[napi]
pub fn compare_dna(
    profile_a_json: String,
    profile_b_json: String,
) -> napi::Result<NapiDnaComparison> {
    let profile_a: DnaProfile = serde_json::from_str(&profile_a_json)
        .map_err(|e| napi::Error::from_reason(format!("[DNA_ERROR] Invalid profile A: {e}")))?;
    let profile_b: DnaProfile = serde_json::from_str(&profile_b_json)
        .map_err(|e| napi::Error::from_reason(format!("[DNA_ERROR] Invalid profile B: {e}")))?;

    let comparison = DnaComparisonEngine::compare(&profile_a, &profile_b);

    Ok(NapiDnaComparison {
        health_delta: comparison.health_delta,
        diversity_delta: comparison.diversity_delta,
        overall_similarity: comparison.overall_similarity,
        gene_diffs: serde_json::to_value(&comparison.gene_diffs)
            .map_err(|e| napi::Error::from_reason(format!("[INTERNAL_ERROR] {e}")))?,
        mutation_diffs: serde_json::to_value(&comparison.mutation_diffs)
            .map_err(|e| napi::Error::from_reason(format!("[INTERNAL_ERROR] {e}")))?,
    })
}

#[napi]
pub fn query_dna_profile() -> napi::Result<serde_json::Value> {
    let rt = crate::runtime::get()?;
    let profile = load_dna_profile(&rt.db)
        .map_err(to_napi_error)?
        .ok_or_else(|| napi::Error::from_reason("[NOT_FOUND] No DNA profile exists"))?;
    serde_json::to_value(&profile)
        .map_err(|e| napi::Error::from_reason(format!("[INTERNAL_ERROR] {e}")))
}

#[napi]
pub fn generate_dna_playbook() -> napi::Result<String> {
    let rt = crate::runtime::get()?;
    let profile = load_dna_profile(&rt.db)
        .map_err(to_napi_error)?
        .ok_or_else(|| napi::Error::from_reason("[NOT_FOUND] No DNA profile exists"))?;
    Ok(PlaybookGenerator::generate(&profile))
}

#[napi]
pub fn generate_dna_context(level: u32) -> napi::Result<String> {
    let rt = crate::runtime::get()?;
    let profile = load_dna_profile(&rt.db)
        .map_err(to_napi_error)?
        .ok_or_else(|| napi::Error::from_reason("[NOT_FOUND] No DNA profile exists"))?;
    Ok(AiContextBuilder::build(&profile, level as u8))
}
```

### Error Codes

```rust
pub mod dna_codes {
    pub const DNA_ERROR: &str = "DNA_ERROR";
    pub const DNA_NO_PROFILE: &str = "DNA_NO_PROFILE";
    pub const DNA_INVALID_GENE: &str = "DNA_INVALID_GENE";
    pub const DNA_INVALID_LEVEL: &str = "DNA_INVALID_LEVEL";
    pub const DNA_COMPARISON_ERROR: &str = "DNA_COMPARISON_ERROR";
}
```

---

## 28. MCP Tool Interface (drift_dna_profile — 3 Actions)

### Tool: drift_dna_profile

Per 07-mcp/tools-by-category.md: ~800-2000 tokens, analysis category.

```typescript
// MCP tool definition
{
    name: "drift_dna_profile",
    description: "Analyze codebase DNA — conventions, health score, mutations",
    inputSchema: {
        type: "object",
        properties: {
            action: {
                type: "string",
                enum: ["profile", "compare", "playbook"],
                description: "Action to perform"
            },
            level: {
                type: "number",
                enum: [1, 2, 3, 4],
                description: "AI context detail level (for profile action)"
            },
            compare_root: {
                type: "string",
                description: "Second project root for comparison (for compare action)"
            }
        },
        required: ["action"]
    }
}
```

### Action: profile
Returns DNA profile at the requested detail level. Default level 2.
Uses `AiContextBuilder` for levels 1-3, raw JSON for level 4.

### Action: compare
Compares current project's DNA against another project or a saved profile.
Returns gene diffs, mutation diffs, and overall similarity score.

### Action: playbook
Returns the full Markdown playbook — the human-readable style guide.

### Integration with drift_context

The `drift_context` MCP tool includes DNA data automatically:
- Level 1 DNA context is always included (20 tokens)
- Level 2 is included when token budget > 2000
- Level 3 is included for code generation intents

---

## 29. CLI Interface (drift dna — 6 Subcommands)

Per 10-cli/commands.md, the DNA CLI has 6 subcommands:

### drift dna (default: status)

```
$ drift dna
DNA Health: 87/100  Diversity: 0.35  Mutations: 12 (3 high)
Last analyzed: 2026-02-08T10:30:00Z
```

### drift dna scan

```
$ drift dna scan
Discovering files... 1,247 files found (892 components, 355 backend)
Extracting genes... 10/10 complete
Detecting mutations... 12 found
Calculating health... 87/100

DNA Analysis Complete
  Health Score: 87/100
  Genetic Diversity: 0.35
  Genes Analyzed: 10
  Mutations: 12 (3 high, 5 medium, 4 low)
  Duration: 1.2s
```

### drift dna status

Same as default, with additional evolution trend data.

### drift dna gene <id>

```
$ drift dna gene variant-handling
Gene: Variant Handling
Dominant: CVA (Class Variance Authority) — 85% confidence
Consistency: 0.92

Alleles:
  ● cva-variants      85%  (142 files)
  ○ clsx-conditionals  10%  (17 files)
  ○ inline-conditionals 3%  (5 files)
  ○ css-module-variants 2%  (3 files)

Exemplar Files:
  src/components/Button.tsx
  src/components/Card.tsx
  src/components/Input.tsx
```

### drift dna mutations

```
$ drift dna mutations
12 mutations detected (3 high, 5 medium, 4 low)

HIGH IMPACT:
  src/legacy/OldButton.tsx:42 — inline-conditionals (expected: cva-variants)
  src/legacy/OldCard.tsx:18 — inline-conditionals (expected: cva-variants)
  src/utils/styles.ts:7 — css-module-variants (expected: cva-variants)

MEDIUM IMPACT:
  src/features/auth/LoginForm.tsx:23 — clsx-conditionals (expected: cva-variants)
  ...
```

### drift dna playbook

Outputs the full Markdown playbook to stdout (or file with `--output`).

### drift dna export

Exports the full DNA profile as JSON to stdout or file.

```
$ drift dna export --output dna-profile.json
Exported DNA profile to dna-profile.json
```

---

## 30. Event Interface

Per PLANNING-DRIFT.md D5: trait-based event system with no-op defaults.

```rust
/// DNA-specific events emitted during analysis.
pub enum DnaProgress {
    FilesDiscovered { total: usize },
    GenesExtracted { count: usize },
    MutationsDetected { count: usize },
}

/// Extension to DriftEventHandler for DNA events.
pub trait DnaEventHandler: Send + Sync {
    fn on_dna_progress(&self, _progress: DnaProgress) {}
    fn on_dna_complete(&self, _profile: &DnaProfile) {}
    fn on_mutation_detected(&self, _mutation: &Mutation) {}
}
```

Events emitted:
- `DnaAnalysisComplete` — after full analysis, includes health score and mutation count
- `MutationDetected` — for each new (unresolved) mutation found
- `DnaProgress::FilesDiscovered` — after file discovery phase
- `DnaProgress::GenesExtracted` — after gene extraction phase
- `DnaProgress::MutationsDetected` — after mutation detection phase

---

## 31. Tracing & Observability

```rust
use tracing::{info, debug, warn, instrument, Span};

#[instrument(skip(db, event_handler), fields(root = %root.display()))]
pub fn analyze(
    &self,
    root: &Path,
    db: &DatabaseManager,
    event_handler: &dyn DriftEventHandler,
) -> Result<DnaAnalysisResult, DnaError> {
    let _span = tracing::info_span!("dna_analysis").entered();

    info!(mode = ?self.config.mode, "Starting DNA analysis");

    // Phase 1
    let _discovery_span = tracing::debug_span!("file_discovery").entered();
    let files = discovery.discover(root);
    debug!(total = files.all_files.len(), "Files discovered");

    // Phase 2-5
    let _extraction_span = tracing::debug_span!("gene_extraction").entered();
    let genes = extract_all_genes(&self.extractors, &files.file_contents, &self.config.thresholds);
    debug!(genes = genes.len(), "Genes extracted");

    // Phase 6
    let _mutation_span = tracing::debug_span!("mutation_detection").entered();
    let mutations = self.mutation_detector.detect_mutations(&genes);
    debug!(mutations = mutations.len(), "Mutations detected");

    // Phase 7-8
    let health_score = self.health_calculator.calculate_health_score(&genes, &mutations);
    info!(
        health_score,
        mutations = mutations.len(),
        diversity = %self.health_calculator.calculate_genetic_diversity(&genes),
        "DNA analysis complete"
    );

    // ...
}
```

### Key Spans

| Span | Level | Fields |
|------|-------|--------|
| `dna_analysis` | INFO | root, mode |
| `file_discovery` | DEBUG | total_files |
| `gene_extraction` | DEBUG | genes_count |
| `gene_extract_{id}` | TRACE | gene_id, alleles_found |
| `mutation_detection` | DEBUG | mutation_count |
| `health_calculation` | DEBUG | score, diversity |
| `dna_persistence` | DEBUG | rows_written |


---

## 32. Performance Targets & Benchmarks

### Target Performance

| Metric | Target | Rationale |
|--------|--------|-----------|
| 1K file codebase (full) | < 500ms | Interactive CLI response |
| 10K file codebase (full) | < 3s | Acceptable for CI |
| 100K file codebase (full) | < 30s | Large monorepo |
| 1K file incremental (10 changed) | < 50ms | Near-instant |
| 10K file incremental (100 changed) | < 200ms | Fast feedback |
| Gene extraction per file | < 50µs | RegexSet single-pass |
| Health calculation | < 1ms | Pure arithmetic |
| Mutation detection | < 10ms | Iteration + comparison |
| Playbook generation | < 5ms | String templating |
| AI context (level 1-3) | < 1ms | String templating |
| Profile persistence | < 50ms | SQLite batch write |

### Benchmark Strategy

```rust
#[cfg(test)]
mod benchmarks {
    use criterion::{criterion_group, criterion_main, Criterion};

    fn bench_gene_extraction(c: &mut Criterion) {
        let extractor = VariantHandlingExtractor::new();
        let content = include_str!("../../test_fixtures/large_component.tsx");

        c.bench_function("variant_handling_extract", |b| {
            b.iter(|| extractor.extract_from_file("test.tsx", content, &[]))
        });
    }

    fn bench_regex_set_vs_sequential(c: &mut Criterion) {
        let definitions = VariantHandlingExtractor::new().allele_definitions();
        let compiled = CompiledGenePatterns::new(&definitions);
        let content = include_str!("../../test_fixtures/large_component.tsx");

        c.bench_function("regex_set_single_pass", |b| {
            b.iter(|| compiled.match_all(content))
        });

        // Compare with sequential regex matching
        let regexes: Vec<Regex> = definitions.iter()
            .flat_map(|d| &d.patterns)
            .map(|p| Regex::new(p).unwrap())
            .collect();

        c.bench_function("sequential_regex", |b| {
            b.iter(|| {
                for re in &regexes {
                    re.find_iter(content).count();
                }
            })
        });
    }

    fn bench_health_calculation(c: &mut Criterion) {
        let genes = create_test_genes(10);
        let mutations = create_test_mutations(50);
        let calculator = HealthCalculator::new(DnaThresholds::default());

        c.bench_function("health_score", |b| {
            b.iter(|| calculator.calculate_health_score(&genes, &mutations))
        });
    }

    fn bench_mutation_detection(c: &mut Criterion) {
        let genes = create_test_genes(10);
        let detector = MutationDetector::new(DnaThresholds::default());

        c.bench_function("mutation_detection", |b| {
            b.iter(|| detector.detect_mutations(&genes))
        });
    }
}
```

---

## 33. Build Order & Dependencies

### Cargo.toml Dependencies

```toml
# In drift-core/Cargo.toml, DNA module dependencies:
[dependencies]
regex = "1"                    # RegexSet for single-pass multi-pattern matching
sha2 = "0.10"                 # SHA-256 for deterministic mutation IDs
hex = "0.4"                   # Hex encoding for mutation ID display
globset = "0.4"               # Glob pattern matching for file exclusion
walkdir = "2"                 # Directory walking for file discovery
chrono = { version = "0.4", features = ["serde"] }  # Timestamps
serde = { version = "1", features = ["derive"] }
serde_json = "1"
rustc-hash = "2"              # FxHashMap/FxHashSet for fast hashing
rayon = "1"                   # Parallel gene extraction
tracing = "0.1"               # Observability
thiserror = "2"               # Error types
```

### Build Phases

The DNA system is built after the foundation (scanner, storage, parsers) is in place.
It has minimal upstream dependencies — primarily scanner (for file lists and content
hashes) and storage (for persistence).

#### Phase 1: Core Types & Config (Day 1)
1. `types.rs` — All DNA types (Gene, Allele, Mutation, Profile, etc.)
2. `config.rs` — DnaConfig, DnaThresholds, DnaMode
3. Verify: Types compile, serialize/deserialize correctly

#### Phase 2: Gene Extractor Trait & Base Logic (Day 2)
4. `extractors/mod.rs` — GeneExtractor trait
5. `extractors/base.rs` — Shared aggregation/gene-building pipeline
6. Verify: Trait compiles, base logic works with mock extractor

#### Phase 3: Frontend Extractors (Day 3-4)
7. `extractors/variant_handling.rs`
8. `extractors/responsive.rs`
9. `extractors/state_styling.rs`
10. `extractors/theming.rs`
11. `extractors/spacing.rs`
12. `extractors/animation.rs`
13. Verify: All 6 frontend extractors pass unit tests

#### Phase 4: Backend Extractors (Day 4-5)
14. `extractors/api_response.rs`
15. `extractors/error_response.rs`
16. `extractors/logging.rs`
17. `extractors/config_pattern.rs`
18. Verify: All 4 backend extractors pass unit tests

#### Phase 5: Mutation & Health (Day 5-6)
19. `mutation.rs` — MutationDetector with SHA-256 IDs
20. `health.rs` — HealthCalculator (4-factor formula) + GeneticDiversity
21. Verify: Health scores match v1 test fixtures exactly

#### Phase 6: Engine & Storage (Day 6-7)
22. `engine.rs` — DnaEngine orchestrator (5-phase pipeline)
23. `storage.rs` — drift.db persistence (save/load profile)
24. Verify: Full analysis pipeline works end-to-end

#### Phase 7: Output Generators (Day 7-8)
25. `output/playbook.rs` — PlaybookGenerator
26. `output/ai_context.rs` — AiContextBuilder (4 levels)
27. Verify: Output matches v1 format exactly

#### Phase 8: Comparison & Evolution (Day 8-9)
28. `comparison.rs` — DnaComparisonEngine
29. Evolution tracking in engine.rs
30. Verify: Comparison produces correct diffs

#### Phase 9: Incremental & Integration (Day 9-10)
31. Incremental analysis (content-hash aware)
32. Integration with coupling, quality gates, audit
33. NAPI bindings (bindings/dna.rs + conversions/dna_types.rs)
34. Verify: Full integration tests pass

---

## 34. V1 → V2 Feature Cross-Reference

| V1 Feature | V1 Location | V2 Location | Status |
|-----------|-------------|-------------|--------|
| Gene type definitions | types.ts | types.rs | ✅ Ported |
| 10 gene IDs (6 frontend + 4 backend) | types.ts | types.rs GeneId enum | ✅ Ported |
| Framework type enums | types.ts | types.rs StylingFramework/BackendFramework | ✅ Ported |
| Gene struct (dominant, alleles, confidence, consistency) | types.ts | types.rs Gene | ✅ Ported |
| Allele struct (frequency, fileCount, examples) | types.ts | types.rs Allele | ✅ Ported |
| AlleleExample struct | types.ts | types.rs AlleleExample | ✅ Ported |
| Mutation struct (SHA-256 ID, impact, suggestion) | types.ts | types.rs Mutation | ✅ Ported |
| StylingDNAProfile | types.ts | types.rs DnaProfile | ✅ Ported (renamed) |
| DNASummary | types.ts | types.rs DnaSummary | ✅ Ported |
| EvolutionEntry + EvolutionChange | types.ts | types.rs | ✅ Ported |
| BaseGeneExtractor abstract class | base-extractor.ts | extractors/base.rs GeneExtractor trait | ✅ Ported |
| AlleleDefinition | base-extractor.ts | extractors/mod.rs | ✅ Ported |
| analyze() → aggregateResults() → buildGene() | base-extractor.ts | extractors/base.rs | ✅ Ported |
| Dominant selection (≥30% frequency) | base-extractor.ts | extractors/base.rs | ✅ Preserved exactly |
| Confidence = dominant frequency | base-extractor.ts | extractors/base.rs | ✅ Preserved exactly |
| Consistency = 0.5 + (dom - second) * 0.5 | base-extractor.ts | extractors/base.rs | ✅ Preserved exactly |
| isComponentFile() | base-extractor.ts | extractors/base.rs | ✅ Ported |
| extractImports() | base-extractor.ts | extractors/base.rs | ✅ Ported |
| extractContext() | base-extractor.ts | extractors/base.rs | ✅ Ported |
| VariantHandlingExtractor | variant-handling.ts | extractors/variant_handling.rs | ✅ Ported |
| ResponsiveApproachExtractor | responsive-approach.ts | extractors/responsive.rs | ✅ Ported |
| StateStylingExtractor | state-styling.ts | extractors/state_styling.rs | ✅ Ported |
| ThemingExtractor | theming.ts | extractors/theming.rs | ✅ Ported |
| SpacingPhilosophyExtractor | spacing-philosophy.ts | extractors/spacing.rs | ✅ Ported |
| AnimationApproachExtractor | animation-approach.ts | extractors/animation.rs | ✅ Ported |
| ApiResponseFormatExtractor | api-response-format.ts | extractors/api_response.rs | ✅ Ported |
| ErrorResponseFormatExtractor | error-response-format.ts | extractors/error_response.rs | ✅ Ported |
| LoggingFormatExtractor | logging-format.ts | extractors/logging.rs | ✅ Ported |
| ConfigPatternExtractor | config-pattern.ts | extractors/config_pattern.rs | ✅ Ported |
| createAllGeneExtractors() | index.ts | extractors/mod.rs | ✅ Ported |
| createFrontendGeneExtractors() | index.ts | extractors/mod.rs | ✅ Ported |
| createBackendGeneExtractors() | index.ts | extractors/mod.rs | ✅ Ported |
| createGeneExtractor(id) | index.ts | extractors/mod.rs | ✅ Ported |
| Health score: 4-factor weighted (40/30/20/10) | health-calculator.ts | health.rs | ✅ Preserved exactly |
| Genetic diversity calculation | health-calculator.ts | health.rs | ✅ Preserved exactly |
| DEFAULT_DNA_THRESHOLDS | health-calculator.ts | config.rs DnaThresholds::default() | ✅ Preserved exactly |
| MutationDetector.detectMutations() | mutation-detector.ts | mutation.rs | ✅ Ported |
| Impact classification (high/medium/low) | mutation-detector.ts | mutation.rs | ✅ Preserved exactly |
| SHA-256 mutation IDs (16 chars) | mutation-detector.ts | mutation.rs (sha2 crate) | ✅ Ported |
| filterByGene() | mutation-detector.ts | mutation.rs | ✅ Ported |
| filterByImpact() | mutation-detector.ts | mutation.rs | ✅ Ported |
| Resolution tracking | mutation-detector.ts | mutation.rs | ✅ Ported |
| PlaybookGenerator (Markdown output) | playbook-generator.ts | output/playbook.rs | ✅ Ported |
| Quick Reference table | playbook-generator.ts | output/playbook.rs | ✅ Preserved exactly |
| Per-gene sections with code examples | playbook-generator.ts | output/playbook.rs | ✅ Preserved exactly |
| Top 10 mutations with overflow | playbook-generator.ts | output/playbook.rs | ✅ Preserved exactly |
| AIContextBuilder (4 levels) | ai-context.ts | output/ai_context.rs | ✅ Ported |
| Level 1 (~20 tokens) | ai-context.ts | output/ai_context.rs | ✅ Preserved exactly |
| Level 2 (~200 tokens) | ai-context.ts | output/ai_context.rs | ✅ Preserved exactly |
| Level 3 (~500-2000 tokens) | ai-context.ts | output/ai_context.rs | ✅ Preserved exactly |
| Level 4 (raw JSON) | ai-context.ts | output/ai_context.rs | ✅ Preserved exactly |
| DNAStore JSON persistence | dna-store.ts | **REPLACED** → storage.rs (SQLite) | ✅ Upgraded |
| Evolution tracking (50-entry cap) | dna-store.ts | storage.rs + dna_evolution table | ✅ Preserved |
| DNAAnalyzer orchestrator | dna-analyzer.ts | engine.rs DnaEngine | ✅ Ported |
| Mode selection (frontend/backend/all) | dna-analyzer.ts | config.rs DnaMode | ✅ Preserved |
| AnalysisResult (profile + stats + errors) | dna-analyzer.ts | types.rs DnaAnalysisResult | ✅ Ported |
| drift_dna_profile MCP tool | dna-profile.ts | NAPI → MCP routing | ✅ Preserved |
| drift_context DNA integration | context tools | NAPI → context generation | ✅ Preserved |
| drift dna CLI (6 subcommands) | commands/dna/ | CLI → NAPI routing | ✅ Preserved |
| Setup wizard DNARunner | setup/dna-runner.ts | Setup wizard integration | ✅ Preserved |
| Sync service syncDna | sync-service.ts | **DROPPED** — SQLite only | ✅ Simplified |
| Event: DnaAnalysisComplete | event bus | DriftEventHandler trait | ✅ Ported |
| Event: MutationDetected | event bus | DriftEventHandler trait | ✅ Ported |
| Batch API: AnalysisType::Dna | batch API | NAPI batch integration | ✅ Preserved |

### New V2 Features (Not in V1)

| Feature | Why | Location |
|---------|-----|----------|
| RegexSet single-pass matching | 10-50x faster gene extraction | extractors/base.rs |
| Rayon parallel gene extraction | Multi-core utilization | extractors/base.rs |
| SQLite persistence (replaces JSON) | Queryable, atomic, joins | storage.rs |
| Incremental analysis (content-hash) | Skip unchanged files | engine.rs |
| DNA comparison engine | Cross-project/branch comparison | comparison.rs |
| DORA-adjacent metrics | Convention health monitoring | health.rs |
| Coupling-weighted exemplars | More impactful style guide | Integration |
| Structured error codes | Programmatic error handling | NAPI |
| Tracing instrumentation | Production observability | All modules |
| Evolution change detection | Detailed change tracking | engine.rs |

---

## 35. Inconsistencies & Decisions

### I1: Gene Extractor Patterns — v1 Research vs Audit

The v1 research docs (13-advanced/dna/gene-extractors.md) list 10 extractors with
specific allele patterns. The audit (DRIFT-V2-FULL-SYSTEM-AUDIT.md Cat 13) lists
different gene names: "naming conventions, file structure, import patterns, error
handling style, test patterns, documentation style, type usage, API conventions,
security patterns, logging patterns."

**Decision**: The research docs are authoritative — they describe the actual v1
implementation. The audit uses higher-level descriptions. v2 preserves the exact
10 gene IDs from the research docs: variant-handling, responsive-approach,
state-styling, theming, spacing-philosophy, animation-approach, api-response-format,
error-response-format, logging-format, config-pattern.

### I2: Dominant Threshold — 0.3 vs 0.6

The v1 code uses 0.3 as the minimum frequency for an allele to be considered dominant
(in `buildGene()`). The `DEFAULT_DNA_THRESHOLDS.dominantMinFrequency` is 0.6.

**Decision**: These serve different purposes. The 0.3 threshold in `buildGene()` is
the minimum to *qualify* as dominant (prevents a 20% allele from being "dominant").
The 0.6 threshold in `DnaThresholds` is used for mutation impact classification
(alleles below this frequency in a gene with a strong dominant are flagged). v2
preserves both thresholds with clear documentation of their distinct roles.

### I3: Playbook Generation — Rust vs TypeScript

The v1 research notes say "Playbook generation and AI context are text templating —
stay in TypeScript." However, having the playbook generator in Rust means it can be
called from the NAPI bridge without a round-trip to TypeScript.

**Decision**: Implement in Rust. The playbook is string concatenation — trivial in
either language. Having it in Rust means `generate_dna_playbook()` is a single NAPI
call, and the CLI can generate playbooks without loading the TypeScript runtime.
The TypeScript side can still format/enhance the output if needed.

### I4: JSON Store → SQLite Migration

v1 persists DNA profiles to `.drift/dna/styling.json`. v2 uses drift.db exclusively.

**Decision**: No migration needed. DNA profiles are regenerated on each analysis run.
The first v2 analysis will create the SQLite tables and populate them fresh. The JSON
store is simply not used in v2. If a user has v1 JSON data, it's ignored — the next
`drift dna scan` regenerates everything.

### I5: DNA Comparison — New Feature

v1 has no DNA comparison feature. The NAPI bridge spec (03-NAPI-BRIDGE-V2-PREP.md
§10.11) lists `compare_dna(profile_a, profile_b)` as a v2 function.

**Decision**: Implement as a new feature. The comparison engine (§15) is straightforward
— diff genes, diff mutations, calculate similarity. This enables cross-project and
cross-branch convention comparison, which is a natural extension of the DNA metaphor.

### I6: DORA Metrics — New Feature

The audit mentions DORA-adjacent convention health metrics. These are not in v1.

**Decision**: Implement as part of the health calculator (§22). The 4 metrics (Drift
Velocity, Compliance Rate, Health Trend, Mutation Resolution Rate) are calculated from
evolution history and mutation data that already exists. Minimal additional code.

---

## 36. Risk Register

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Regex patterns don't match v1 behavior | High | Medium | Port exact regex strings from v1 TS, comprehensive test fixtures |
| Health scores differ from v1 | High | Low | Preserve exact formula, test with v1 golden outputs |
| RegexSet compilation fails for complex patterns | Medium | Low | Fallback to sequential matching, log warning |
| Large codebase (100K+ files) OOM | Medium | Low | Streaming file reading, bounded allele example collection |
| Incremental cache invalidation misses | Medium | Medium | Conservative invalidation (re-analyze on any config change) |
| Evolution tracking loses history on schema change | Low | Low | Migration script preserves dna_evolution data |
| Gene extractor patterns need updating for new frameworks | Low | High | AlleleDefinition is data-driven — add patterns without code changes |
| SHA-256 mutation IDs collide | Negligible | Negligible | 16 hex chars = 64 bits = 2^64 space, collision probability ~0 |

