# Context Generation (Unified Context Engine) — V2 Implementation Prep

> Comprehensive build specification for Drift v2's Context Generation subsystem — the
> engine that transforms raw analysis data into AI-optimized, token-budgeted, intent-aware
> context for AI agents. Powers the two most important MCP tools: `drift_context` and
> `drift_package_context`.
>
> Synthesized from: 22-context-generation/ (overview.md, types.md, package-detector.md,
> token-management.md, gaps.md), .research/22-context-generation/ (AUDIT.md, RECAP.md,
> RECOMMENDATIONS.md — CG1-CG18), DRIFT-V2-FULL-SYSTEM-AUDIT.md (Pipeline 3: MCP Context
> Query), 07-mcp/ (tools-inventory.md, tools-by-category.md, overview.md),
> 00-overview/pipelines.md (drift_context 7-step pipeline), 03-NAPI-BRIDGE-V2-PREP.md
> (§10.14 Context Generation Functions, template structure reference),
> existing v1 implementation (~2,575 lines across packages/core/src/context/ and
> packages/mcp/src/orchestration/context.ts), and external research (R1-R22 from
> RECOMMENDATIONS.md: Anthropic context isolation, Cursor semantic search, Augment
> SWE-bench results, NVIDIA two-stage retrieval, tiktoken-rs, Inkeep attention budgets,
> Manus compaction, LangChain tiered compression, Phil Schmid format optimization).
>
> Purpose: Everything needed to build the unified context engine from scratch. Decisions
> resolved, dual-path architecture merged, interface contracts defined, build order specified.
> Generated: 2026-02-08

---

## 1. Architectural Position

Context Generation is the consumer-facing crown jewel of Drift. It sits at the top of the
analysis stack, consuming output from every other subsystem (patterns, constraints, call graph,
boundaries, security, DNA, Cortex memories) and synthesizing it into exactly what an AI agent
needs for a specific task — nothing more, nothing less.

Per DRIFT-V2-FULL-SYSTEM-AUDIT.md Pipeline 3: The MCP Context Query Pipeline is a 7-step
sequence — pattern retrieval → code examples → Cortex retrieval → call graph context →
boundary context → synthesis → response. This is the online query path that must complete
in <100ms for standard depth.

Per PLANNING-DRIFT.md D1: Drift is standalone. Context generation depends only on drift-core
(for data access) and optionally on Cortex (for memory enrichment).

### What Lives Here

- Unified `ContextEngine` merging both v1 paths (CG1)
- `PackageDetector` with 15 package manager support (11 v1 + 4 new: Bun, Deno, Swift, Kotlin)
- Intent-weighted scoring system (6 intent types with category multipliers)
- Semantic relevance scoring (two-stage: fast metadata + optional embedding re-ranking)
- Three-layer context depth (overview ~2K, standard ~6K, deep ~12K tokens)
- Accurate BPE token counting via tiktoken-rs / splintr
- Intelligent proportional budget allocation with relevance-aware trimming
- Session-aware context deduplication (30-50% token savings on follow-ups)
- Cortex memory integration (tribal knowledge, decisions, rationale)
- Package dependency graph for cross-package context
- Model-aware output formatting (markdown, XML for Claude, JSON)
- Freshness indicators and staleness classification
- Content-hash-based incremental cache invalidation
- Graceful degradation matrix (every component has a defined fallback)
- Strategic content ordering (primacy-recency for transformer attention)

### What Does NOT Live Here

- MCP tool handlers (thin wrappers in packages/drift-mcp, call context engine via NAPI)
- Pattern detection logic (lives in drift-core detectors)
- Call graph construction (lives in drift-core call graph)
- Constraint mining (lives in drift-core constraints)
- Security analysis (lives in drift-core boundaries/secrets)
- Cortex memory storage/retrieval internals (lives in cortex-core)
- SQLite schema/migrations (lives in drift-core storage)

### The v1 Problem This Solves

v1 has two parallel context implementations that don't share code:

1. `PackageContextGenerator` (~280 LOC in packages/core/src/context/) — package-scoped,
   token-budgeted, 9-step pipeline, 11 package managers. But: no intent awareness, no
   Cortex memory, no semantic ranking.

2. `orchestration/context.ts` (~1,500 LOC in packages/mcp/src/) — intent-aware, semantic
   insights, suggested files, Cortex integration. But: no package detection, no structured
   token budgeting, bypasses the generator entirely.

v2 merges these into a single `ContextEngine` that is simultaneously package-aware,
intent-aware, memory-integrated, and semantically ranked.

---

## 2. Crate Structure

```
crates/drift-context/
├── Cargo.toml
├── src/
│   ├── lib.rs                      # Public API: ContextEngine, PackageDetector
│   ├── engine.rs                   # Unified ContextEngine (CG1)
│   ├── request.rs                  # ContextRequest, ContextIntent, ContextDepth, ContextScope
│   ├── response.rs                 # ContextResult, AIContextFormat, ContextSection
│   ├── scoring/
│   │   ├── mod.rs                  # Re-exports
│   │   ├── relevance.rs            # Two-stage relevance scoring (CG3)
│   │   ├── intent_weights.rs       # Intent-weighted multipliers (CG2)
│   │   └── file_proximity.rs       # File proximity scoring
│   ├── budget/
│   │   ├── mod.rs                  # Re-exports
│   │   ├── token_counter.rs        # BPE token counting via tiktoken-rs (CG5)
│   │   ├── allocator.rs            # Proportional budget allocation (CG6)
│   │   └── trimmer.rs              # Relevance-aware trimming
│   ├── package/
│   │   ├── mod.rs                  # Re-exports
│   │   ├── detector.rs             # PackageDetector (15 managers)
│   │   ├── managers/
│   │   │   ├── mod.rs              # PackageManagerDetector trait + registry
│   │   │   ├── npm.rs              # npm workspace detection
│   │   │   ├── pnpm.rs             # pnpm workspace detection
│   │   │   ├── yarn.rs             # yarn workspace detection
│   │   │   ├── bun.rs              # Bun workspace detection (NEW)
│   │   │   ├── deno.rs             # Deno workspace detection (NEW)
│   │   │   ├── python.rs           # pip/poetry detection
│   │   │   ├── go.rs               # Go module detection
│   │   │   ├── maven.rs            # Maven module detection
│   │   │   ├── gradle.rs           # Gradle/Kotlin project detection
│   │   │   ├── composer.rs         # Composer package detection
│   │   │   ├── dotnet.rs           # .NET solution detection
│   │   │   ├── cargo.rs            # Cargo workspace detection
│   │   │   ├── swift.rs            # Swift Package Manager (NEW)
│   │   │   └── root_fallback.rs    # Root package fallback
│   │   ├── graph.rs                # PackageDependencyGraph (CG10)
│   │   └── lookup.rs               # 4-strategy package resolution
│   ├── session.rs                  # Session-aware deduplication (CG7)
│   ├── formatting/
│   │   ├── mod.rs                  # Re-exports
│   │   ├── markdown.rs             # Markdown format (default)
│   │   ├── xml.rs                  # XML format (Claude-optimized)
│   │   ├── json.rs                 # JSON format (programmatic)
│   │   └── ordering.rs             # Strategic content ordering (CG17)
│   ├── freshness.rs                # Freshness indicators (CG13)
│   ├── cache.rs                    # Content-hash invalidation cache (CG14)
│   ├── degradation.rs              # Graceful degradation matrix (CG16)
│   └── guidance.rs                 # Guidance synthesis (insights, patterns, warnings)
├── benches/
│   └── context_bench.rs            # Criterion benchmarks
└── tests/
    ├── engine_test.rs              # Integration tests
    ├── package_detection_test.rs   # Package detector tests
    ├── scoring_test.rs             # Relevance scoring tests
    ├── budget_test.rs              # Token counting + trimming tests
    ├── session_test.rs             # Session deduplication tests
    ├── golden_test.rs              # Golden dataset tests
    ├── property_tests.rs           # Property-based tests (proptest)
    └── degradation_test.rs         # Graceful degradation tests
```

### Cargo.toml

```toml
[package]
name = "drift-context"
version = "0.1.0"
edition = "2021"

[dependencies]
drift-core = { path = "../drift-core" }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tiktoken-rs = "0.6"                    # BPE token counting (CG5)
rustc-hash = "2"                       # Fast hashing for content hashes
base64 = "0.22"                        # Cursor encoding
glob = "0.3"                           # Workspace glob resolution
toml = "0.8"                           # pyproject.toml, Cargo.toml parsing
quick-xml = "0.36"                     # pom.xml, .csproj parsing
serde_yaml = "0.9"                     # pnpm-workspace.yaml parsing
regex = "1"                            # Gradle settings parsing
tracing = "0.1"                        # Structured logging

[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }
proptest = "1"
tempfile = "3"
insta = "1"                            # Snapshot testing for golden datasets

[[bench]]
name = "context_bench"
harness = false
```

---

## 3. The Unified Context Engine (CG1)

The single most important architectural change. Merges both v1 paths into one pipeline.

### ContextEngine

```rust
use drift_core::storage::DatabaseManager;
use std::sync::Arc;

pub struct ContextEngine {
    db: Arc<DatabaseManager>,
    package_detector: PackageDetector,
    token_counter: TokenCounter,
    session_tracker: SessionTracker,
    cache: ContextCache,
}

impl ContextEngine {
    pub fn new(db: Arc<DatabaseManager>, root_dir: PathBuf) -> Self {
        Self {
            db: db.clone(),
            package_detector: PackageDetector::new(root_dir),
            token_counter: TokenCounter::new(ModelFamily::Generic),
            session_tracker: SessionTracker::new(),
            cache: ContextCache::new(100, Duration::from_secs(300)),
        }
    }

    /// Primary entry point. Both MCP tools call this with different defaults.
    ///
    /// drift_package_context → scope=Package, intent=None (defaults to Understand)
    /// drift_context → scope=Package|CrossPackage|Repo, intent=Some(...)
    pub fn generate(&self, request: &ContextRequest) -> Result<ContextResult, ContextError> {
        // Check cache first
        let cache_key = self.compute_cache_key(request)?;
        if let Some(cached) = self.cache.get(&cache_key) {
            return Ok(cached);
        }

        // 7-step unified pipeline
        let mut warnings: Vec<ContextWarning> = Vec::new();

        // Step 1: Resolve scope — package detection + scope expansion
        let scope = self.resolve_scope(request, &mut warnings)?;

        // Step 2: Gather candidates — patterns, constraints, entry points,
        //         data accessors, key files from SQLite
        let candidates = self.gather_candidates(&scope, request, &mut warnings)?;

        // Step 3: Retrieve Cortex memories (optional enrichment)
        let memories = self.retrieve_memories(&scope, request, &mut warnings);

        // Step 4: Score — compute relevance per candidate (CG3)
        let scored = self.score_candidates(candidates, memories, request)?;

        // Step 5: Rank — apply intent weighting, sort by composite score (CG2)
        let ranked = self.rank_by_intent(scored, request.intent())?;

        // Step 6: Budget — allocate tokens per section, trim to fit (CG6)
        let budgeted = self.allocate_and_trim(ranked, request, &mut warnings)?;

        // Step 7: Format — produce AI-optimized output (CG12)
        let result = self.format_output(budgeted, request, warnings)?;

        // Session tracking for deduplication (CG7)
        if let Some(session_id) = &request.session {
            self.session_tracker.record_delivery(session_id, &result);
        }

        // Cache the result
        self.cache.insert(cache_key, result.clone());

        Ok(result)
    }
}
```

### How Both MCP Tools Use the Same Engine

```rust
// drift_package_context calls:
engine.generate(&ContextRequest {
    package: Some("@drift/core".into()),
    intent: None,                    // defaults to Understand (balanced weights)
    query: None,
    max_tokens: 8000,
    session: None,
    depth: ContextDepth::Standard,
    scope: ContextScope::Package,
    format: OutputFormat::Markdown,
    include_snippets: true,
    include_dependencies: true,
    min_confidence: None,
    categories: None,
    active_file: None,
})

// drift_context calls:
engine.generate(&ContextRequest {
    package: None,                   // inferred from active_file
    intent: Some(ContextIntent::AddFeature),
    query: Some("authentication".into()),
    max_tokens: 3000,
    session: Some(session_id),
    depth: ContextDepth::Standard,
    scope: ContextScope::Package,    // or CrossPackage, Repo
    format: OutputFormat::Markdown,
    include_snippets: true,
    include_dependencies: false,
    min_confidence: None,
    categories: None,
    active_file: Some("src/auth/login.ts".into()),
})
```

---

## 4. Request & Response Types

### ContextRequest

```rust
#[derive(Debug, Clone)]
pub struct ContextRequest {
    /// Package name or path. If None, inferred from active_file.
    pub package: Option<String>,
    /// What the agent is trying to do. None = balanced/understand.
    pub intent: Option<ContextIntent>,
    /// Natural language query (focus area).
    pub query: Option<String>,
    /// Token budget. Default: 8000 for package context, 3000 for drift_context.
    pub max_tokens: u32,
    /// Session ID for deduplication. None = no dedup.
    pub session: Option<SessionId>,
    /// Context depth level.
    pub depth: ContextDepth,
    /// Scope of context generation.
    pub scope: ContextScope,
    /// Output format.
    pub format: OutputFormat,
    /// Include code snippets in patterns.
    pub include_snippets: bool,
    /// Include patterns from internal dependencies.
    pub include_dependencies: bool,
    /// Minimum confidence threshold. None = no filter.
    pub min_confidence: Option<f64>,
    /// Filter to specific categories. None = all.
    pub categories: Option<Vec<String>>,
    /// Currently active file in the editor.
    pub active_file: Option<String>,
    /// Model family for token counting accuracy.
    pub model: ModelFamily,
}

impl ContextRequest {
    /// Returns the effective intent (defaults to Understand if None).
    pub fn intent(&self) -> ContextIntent {
        self.intent.unwrap_or(ContextIntent::Understand)
    }
}
```

### ContextIntent

```rust
/// The 6 intent types from v1's drift_context orchestrator, preserved and formalized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContextIntent {
    /// Adding new functionality. Prioritizes architectural patterns, entry points, conventions.
    AddFeature,
    /// Fixing a bug. Prioritizes error patterns, recent changes, constraints.
    FixBug,
    /// Understanding existing code. Balanced weights across all categories.
    Understand,
    /// Restructuring code. Prioritizes coupling patterns, conventions, constraints.
    Refactor,
    /// Reviewing security posture. Prioritizes security patterns, data accessors, boundaries.
    SecurityReview,
    /// Writing tests. Prioritizes test topology, entry points, error patterns.
    AddTest,
}
```

### ContextDepth (CG4)

```rust
/// Three-layer progressive disclosure.
/// overview ⊂ standard ⊂ deep (strict subset relationship).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ContextDepth {
    /// ~2K tokens. Quick orientation. Top 5 patterns, critical constraints only.
    Overview,
    /// ~6K tokens. Default. Full pattern list (top 20), all constraints, entry points.
    Standard,
    /// ~12K tokens. Deep investigation. Code examples, data accessors, extended memories.
    Deep,
}
```

### ContextScope

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextScope {
    /// Single package only.
    Package,
    /// Package + direct dependencies (1 hop in dependency graph).
    CrossPackage,
    /// Entire repository.
    Repo,
}
```

### OutputFormat (CG12)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Markdown with headers and separators (default, works well for most models).
    Markdown,
    /// XML tags (optimized for Claude — better structured extraction).
    Xml,
    /// Structured JSON (for programmatic consumption by agent frameworks).
    Json,
}
```

### ModelFamily (CG5)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelFamily {
    /// OpenAI GPT-4, GPT-4o (cl100k_base / o200k_base tokenizer).
    OpenAI,
    /// Anthropic Claude (claude tokenizer).
    Anthropic,
    /// Generic fallback (cl100k_base — reasonable approximation for most models).
    Generic,
}
```

### SessionId

```rust
/// Opaque session identifier for context deduplication.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(pub String);
```


---

## 5. ContextResult — The Primary Output

### ContextResult

```rust
/// The unified output of context generation. Contains structured data + formatted text.
#[derive(Debug, Clone, Serialize)]
pub struct ContextResult {
    /// Unique identifier for this context generation (for feedback/session tracking).
    pub context_id: String,
    /// Package information (if package-scoped).
    pub package: Option<PackageInfo>,
    /// Summary statistics.
    pub summary: ContextSummary,
    /// Scored and ranked patterns (survived budget trimming).
    pub patterns: Vec<ScoredPattern>,
    /// Applicable constraints.
    pub constraints: Vec<ScoredConstraint>,
    /// Entry points (API endpoints, handlers, CLI commands).
    pub entry_points: Vec<ContextEntryPoint>,
    /// Data access points with sensitivity flags.
    pub data_accessors: Vec<ContextDataAccessor>,
    /// Key files ranked by pattern density + relevance.
    pub key_files: Vec<KeyFile>,
    /// Synthesized guidance (insights, common patterns, warnings).
    pub guidance: Guidance,
    /// Cortex memories (tribal knowledge, decisions, rationale).
    pub memories: Vec<ContextMemory>,
    /// Dependency patterns (from internal package dependencies).
    pub dependencies: Vec<DependencyContext>,
    /// Freshness metadata for all data sources (CG13).
    pub freshness: FreshnessMetadata,
    /// Warnings from graceful degradation (CG16).
    pub warnings: Vec<ContextWarning>,
    /// Pre-formatted AI context (the primary output for MCP tools).
    pub formatted: FormattedContext,
    /// Generation metadata.
    pub metadata: ContextMetadata,
}

#[derive(Debug, Clone, Serialize)]
pub struct PackageInfo {
    pub name: String,
    pub path: String,
    pub language: String,
    pub description: Option<String>,
    pub package_manager: PackageManager,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContextSummary {
    pub total_patterns: u32,
    pub total_constraints: u32,
    pub total_files: u32,
    pub total_entry_points: u32,
    pub total_data_accessors: u32,
    pub total_memories: u32,
    pub estimated_tokens: u32,
    pub depth: ContextDepth,
    pub intent: ContextIntent,
    pub scope: ContextScope,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContextMetadata {
    pub generated_at: String,
    pub drift_version: String,
    pub context_version: String,       // "2.0.0"
    pub generation_time_ms: u32,
    pub cache_hit: bool,
    pub session_dedup_savings: Option<u32>,  // Tokens saved via dedup
}
```

### ScoredPattern

```rust
/// A pattern with its computed relevance score, ready for budget allocation.
#[derive(Debug, Clone, Serialize)]
pub struct ScoredPattern {
    pub id: String,
    pub name: String,
    pub category: String,
    pub confidence: f64,
    pub occurrences: u32,
    pub relevance_score: f64,          // Composite score from CG3 + CG2
    pub example: Option<String>,       // Code snippet (if include_snippets=true)
    pub files: Vec<String>,            // Up to 5 file paths
    pub from_dependency: Option<String>,
    pub token_cost: u32,               // Pre-computed token count for this item
}
```

### ScoredConstraint

```rust
#[derive(Debug, Clone, Serialize)]
pub struct ScoredConstraint {
    pub id: String,
    pub name: String,
    pub category: String,
    pub enforcement: Enforcement,
    pub condition: String,
    pub guidance: String,
    pub relevance_score: f64,
    pub token_cost: u32,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum Enforcement {
    Error,
    Warning,
    Info,
}
```

### ContextEntryPoint (preserved from v1)

```rust
#[derive(Debug, Clone, Serialize)]
pub struct ContextEntryPoint {
    pub name: String,
    pub file: String,
    pub entry_type: String,            // "api", "event", "cli", "function", etc.
    pub method: Option<String>,        // HTTP method if API
    pub path: Option<String>,          // Route path if API
    pub relevance_score: f64,
    pub token_cost: u32,
}
```

### ContextDataAccessor (preserved from v1)

```rust
#[derive(Debug, Clone, Serialize)]
pub struct ContextDataAccessor {
    pub name: String,
    pub file: String,
    pub tables: Vec<String>,
    pub accesses_sensitive: bool,
    pub relevance_score: f64,
    pub token_cost: u32,
}
```

### KeyFile (preserved from v1, enhanced with relevance)

```rust
#[derive(Debug, Clone, Serialize)]
pub struct KeyFile {
    pub file: String,
    pub reason: String,
    pub patterns: Vec<String>,         // Up to 5 pattern names
    pub score: f64,                    // Pattern density score
    pub relevance_score: f64,          // Intent-weighted relevance
    pub token_cost: u32,
}
```

### Guidance (preserved from v1)

```rust
#[derive(Debug, Clone, Serialize)]
pub struct Guidance {
    /// Categories with 2+ patterns (e.g., "api: 5 patterns detected").
    pub key_insights: Vec<String>,
    /// Top 5 patterns with confidence ≥ 0.8.
    pub common_patterns: Vec<String>,
    /// Up to 3 constraints with enforcement=Error.
    pub warnings: Vec<String>,
    /// Suggested files relevant to the intent (NEW — from v1 drift_context).
    pub suggested_files: Vec<SuggestedFile>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SuggestedFile {
    pub file: String,
    pub reason: String,
}
```

### ContextMemory (NEW — Cortex integration, CG8)

```rust
#[derive(Debug, Clone, Serialize)]
pub struct ContextMemory {
    pub id: String,
    pub memory_type: String,           // "decision", "tribal", "convention", "semantic"
    pub content: String,
    pub confidence: f64,
    pub files: Vec<String>,
    pub relevance_score: f64,
    pub token_cost: u32,
}
```

### FormattedContext (the actual MCP response payload)

```rust
#[derive(Debug, Clone, Serialize)]
pub struct FormattedContext {
    /// Pre-formatted text in the requested OutputFormat.
    pub text: String,
    /// Per-section token breakdown.
    pub tokens: TokenBreakdown,
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenBreakdown {
    pub system_prompt: u32,
    pub patterns: u32,
    pub constraints: u32,
    pub entry_points: u32,
    pub key_files: u32,
    pub guidance: u32,
    pub memories: u32,
    pub examples: u32,
    pub data_accessors: u32,
    pub total: u32,
}
```

---

## 6. Intent-Weighted Scoring (CG2)

Each intent type defines weight multipliers for different data categories. These weights
are applied on top of the base relevance score (CG3) to prioritize the right data for
the right task.

### Weight Tables

```rust
use rustc_hash::FxHashMap;

/// Category weight multipliers per intent type.
/// Default weight is 1.0 (neutral). Range: 0.3 (deprioritize) to 2.0 (strong boost).
pub fn intent_weights(intent: ContextIntent) -> FxHashMap<&'static str, f64> {
    match intent {
        ContextIntent::AddFeature => [
            ("architectural",    1.5),
            ("entry_points",     1.3),
            ("conventions",      1.2),
            ("constraints",      1.0),
            ("security",         0.8),
            ("data_accessors",   0.7),
            ("error_handling",   0.6),
            ("test_topology",    0.5),
            ("memories",         1.0),
        ],
        ContextIntent::FixBug => [
            ("error_handling",   1.5),
            ("recent_changes",   1.3),
            ("constraints",      1.2),
            ("data_accessors",   1.1),
            ("entry_points",     0.9),
            ("conventions",      0.7),
            ("architectural",    0.6),
            ("security",         0.8),
            ("memories",         1.2),  // Past decisions about this area
        ],
        ContextIntent::SecurityReview => [
            ("security",         2.0),
            ("data_accessors",   1.8),
            ("constraints",      1.5),
            ("entry_points",     1.0),
            ("error_handling",   1.0),
            ("conventions",      0.5),
            ("architectural",    0.5),
            ("memories",         1.3),  // Past security decisions
        ],
        ContextIntent::Refactor => [
            ("architectural",    1.5),
            ("conventions",      1.3),
            ("coupling",         1.3),
            ("constraints",      1.0),
            ("entry_points",     0.8),
            ("data_accessors",   0.5),
            ("error_handling",   0.7),
            ("memories",         1.1),
        ],
        ContextIntent::AddTest => [
            ("test_topology",    1.8),
            ("entry_points",     1.3),
            ("error_handling",   1.2),
            ("conventions",      1.0),
            ("constraints",      0.8),
            ("data_accessors",   0.7),
            ("architectural",    0.6),
            ("memories",         0.8),
        ],
        ContextIntent::Understand => {
            // Balanced — all categories at 1.0. This is the default.
            // No category is boosted or penalized.
            FxHashMap::default() // Empty map = all weights default to 1.0
        },
    }
    .into_iter()
    .collect()
}

/// Apply intent weight to a base relevance score.
/// If the category has no explicit weight, defaults to 1.0.
pub fn apply_intent_weight(
    base_score: f64,
    category: &str,
    weights: &FxHashMap<&str, f64>,
) -> f64 {
    let weight = weights.get(category).copied().unwrap_or(1.0);
    base_score * weight
}
```

### Scoring Formula

```
final_score(item) = base_relevance_score(item) × intent_weight(item.category, intent)
```

When no intent is provided (e.g., `drift_package_context` with `intent=None`), all weights
default to 1.0 — equivalent to v1's behavior but with proper relevance scoring instead of
occurrence-based sorting.

---

## 7. Semantic Relevance Scoring (CG3)

Replaces v1's occurrence-based sorting with actual relevance. This is the single biggest
quality improvement in v2.

### Two-Stage Architecture

Mirrors NVIDIA's recommended bi-encoder → cross-encoder pipeline (R6):

- Stage 1 (all candidates): Fast metadata-based scoring — O(N) with simple arithmetic
- Stage 2 (top-K only): Semantic re-ranking via embeddings — only for top 50 candidates

### Stage 1 — Fast Candidate Scoring

```rust
/// Compute base relevance score for a candidate item.
/// All components normalized to [0.0, 1.0]. Composite score in [0.0, 1.0].
pub fn base_relevance_score(item: &CandidateItem, context: &ScoringContext) -> f64 {
    let confidence = item.confidence;                              // 0.0-1.0

    let category_match = if context.priority_categories.contains(&item.category) {
        1.0
    } else {
        0.5
    };

    let file_proximity = match &context.active_file {
        Some(active) => compute_file_proximity(&item.files, active),
        None => 0.5,  // No file context — neutral score
    };

    let recency = 1.0 / (1.0 + item.days_since_update as f64 / 30.0);

    let importance = (item.occurrences as f64 / context.max_occurrences as f64)
        .min(1.0);

    // Weighted composite
    confidence     * 0.30
    + category_match * 0.25
    + file_proximity * 0.20
    + recency        * 0.15
    + importance     * 0.10
}

/// File proximity: how close are the item's files to the active file?
/// Same directory = 1.0, parent directory = 0.8, same package = 0.5, different = 0.2.
fn compute_file_proximity(item_files: &[String], active_file: &str) -> f64 {
    let active_dir = Path::new(active_file).parent().unwrap_or(Path::new(""));
    let active_parent = active_dir.parent().unwrap_or(Path::new(""));

    item_files.iter().map(|f| {
        let file_dir = Path::new(f).parent().unwrap_or(Path::new(""));
        if file_dir == active_dir {
            1.0  // Same directory
        } else if file_dir == active_parent || active_dir.starts_with(file_dir) {
            0.8  // Parent or ancestor
        } else if shares_package_root(f, active_file) {
            0.5  // Same package
        } else {
            0.2  // Different package
        }
    }).fold(0.0_f64, f64::max)  // Best proximity across all files
}
```

### Stage 2 — Semantic Re-Ranking (Optional)

When Cortex embeddings are available, compute embedding similarity for the top-K candidates:

```rust
/// Re-rank top candidates using embedding similarity.
/// Only runs when Cortex is available and query text is provided.
pub fn semantic_rerank(
    candidates: &mut [ScoredCandidate],
    query: &str,
    cortex: &CortexClient,
    top_k: usize,
) -> Result<(), ContextError> {
    // Only re-rank the top K candidates (default K=50)
    let k = top_k.min(candidates.len());
    let top_slice = &mut candidates[..k];

    // Get query embedding
    let query_embedding = cortex.embed(query)?;

    for candidate in top_slice.iter_mut() {
        // Get or compute candidate embedding
        let item_embedding = cortex.get_embedding(&candidate.content_hash)?;
        if let Some(emb) = item_embedding {
            let similarity = cosine_similarity(&query_embedding, &emb);
            // Blend: 60% base score + 40% semantic similarity
            candidate.score = candidate.score * 0.6 + similarity * 0.4;
        }
        // If no embedding available, keep base score unchanged
    }

    // Re-sort after blending
    top_slice.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    Ok(())
}
```

### Graceful Degradation

When embeddings are unavailable (Cortex not initialized, embedding model not loaded),
Stage 2 is skipped entirely. Stage 1 metadata-only scoring still provides significantly
better ranking than v1's occurrence-based sorting.


---

## 8. Accurate BPE Token Counting (CG5)

Replaces v1's `JSON.stringify(context).length × 0.25` with actual BPE tokenization.
The character-based approximation was off by 20-40% — code tokenizes differently than
prose due to identifiers, operators, and whitespace patterns.

### TokenCounter

```rust
use tiktoken_rs::CoreBPE;
use std::sync::OnceLock;
use rustc_hash::FxHashMap;
use std::sync::Mutex;

/// Thread-safe token counter with model-aware tokenizer selection and caching.
pub struct TokenCounter {
    model: ModelFamily,
    /// Cache: content_hash → token count. Avoids re-counting immutable content.
    cache: Mutex<FxHashMap<u64, u32>>,
}

static CL100K: OnceLock<CoreBPE> = OnceLock::new();
static O200K: OnceLock<CoreBPE> = OnceLock::new();

impl TokenCounter {
    pub fn new(model: ModelFamily) -> Self {
        Self {
            model,
            cache: Mutex::new(FxHashMap::default()),
        }
    }

    /// Count tokens in a text string using the model-appropriate tokenizer.
    pub fn count(&self, text: &str) -> u32 {
        let bpe = self.get_tokenizer();
        bpe.encode_ordinary(text).len() as u32
    }

    /// Count with caching. Use for immutable content (patterns, constraints)
    /// whose token counts don't change between requests.
    pub fn count_cached(&self, text: &str, content_hash: u64) -> u32 {
        // Check cache first
        if let Ok(cache) = self.cache.lock() {
            if let Some(&count) = cache.get(&content_hash) {
                return count;
            }
        }

        let count = self.count(text);

        // Store in cache
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(content_hash, count);
        }

        count
    }

    /// Batch count for multiple items. More efficient than individual calls
    /// when counting many items (e.g., all patterns in a package).
    pub fn count_batch(&self, items: &[&str]) -> Vec<u32> {
        let bpe = self.get_tokenizer();
        items.iter()
            .map(|text| bpe.encode_ordinary(text).len() as u32)
            .collect()
    }

    fn get_tokenizer(&self) -> &CoreBPE {
        match self.model {
            ModelFamily::OpenAI => {
                O200K.get_or_init(|| tiktoken_rs::o200k_base().unwrap())
            }
            ModelFamily::Anthropic | ModelFamily::Generic => {
                // cl100k_base is a reasonable approximation for Claude and other models.
                // Anthropic doesn't publish their tokenizer, but cl100k_base is within
                // ~5% accuracy for most content types.
                CL100K.get_or_init(|| tiktoken_rs::cl100k_base().unwrap())
            }
        }
    }
}
```

### Fallback Chain

If tiktoken-rs fails to initialize (missing data files, unsupported platform):

1. Try `splintr` crate (alternative BPE implementation, ~12x faster for batch)
2. Fall back to character estimation with 20% safety margin: `length / 4 * 0.8`
3. Log a `ContextWarning::FallbackUsed` so the agent knows budget accuracy is reduced

```rust
impl TokenCounter {
    /// Fallback counting when BPE tokenizer is unavailable.
    fn count_fallback(text: &str) -> u32 {
        // Character-based with 20% safety margin (conservative — better to
        // undercount and leave room than overcount and truncate).
        (text.len() as f64 / 4.0 * 0.8) as u32
    }
}
```

### Pre-Computing Token Costs

During the scoring phase, each candidate item gets its `token_cost` pre-computed.
This enables the budget allocator to make precise decisions without re-counting.

```rust
fn precompute_token_costs(
    items: &mut [ScoredCandidate],
    counter: &TokenCounter,
) {
    for item in items.iter_mut() {
        let serialized = item.to_context_string();
        item.token_cost = counter.count_cached(&serialized, item.content_hash);
    }
}
```

---

## 9. Intelligent Budget Allocation (CG6)

Replaces v1's greedy section-cutting with proportional, relevance-aware trimming.
v1 would cut entire sections (all code examples, then all patterns beyond 20, etc.).
v2 allocates a token budget per section, then trims the lowest-scored items within
each section.

### Section Budget Allocation

```rust
/// Allocate the total token budget across sections based on depth and intent.
pub fn allocate_budget(
    total_budget: u32,
    depth: ContextDepth,
    intent: ContextIntent,
) -> SectionBudgets {
    let base = match depth {
        ContextDepth::Overview => overview_allocation(total_budget),
        ContextDepth::Standard => standard_allocation(total_budget),
        ContextDepth::Deep => deep_allocation(total_budget),
    };

    // Apply intent-specific adjustments
    apply_intent_adjustments(base, intent)
}

/// Standard depth (~6K tokens) default allocation.
fn standard_allocation(total: u32) -> SectionBudgets {
    SectionBudgets {
        system_prompt:  (total as f64 * 0.10) as u32,  //  10%
        patterns:       (total as f64 * 0.35) as u32,  //  35%
        constraints:    (total as f64 * 0.15) as u32,  //  15%
        entry_points:   (total as f64 * 0.10) as u32,  //  10%
        key_files:      (total as f64 * 0.08) as u32,  //   8%
        guidance:       (total as f64 * 0.08) as u32,  //   8%
        memories:       (total as f64 * 0.07) as u32,  //   7%
        examples:       (total as f64 * 0.05) as u32,  //   5%
        data_accessors: (total as f64 * 0.02) as u32,  //   2%
    }
}

/// Overview depth (~2K tokens) — minimal, orientation-only.
fn overview_allocation(total: u32) -> SectionBudgets {
    SectionBudgets {
        system_prompt:  (total as f64 * 0.20) as u32,  //  20%
        patterns:       (total as f64 * 0.35) as u32,  //  35%
        constraints:    (total as f64 * 0.20) as u32,  //  20%
        entry_points:   0,                               //   0% (excluded)
        key_files:      0,                               //   0% (excluded)
        guidance:       (total as f64 * 0.25) as u32,  //  25%
        memories:       0,                               //   0% (excluded)
        examples:       0,                               //   0% (excluded)
        data_accessors: 0,                               //   0% (excluded)
    }
}

/// Deep depth (~12K tokens) — full investigation.
fn deep_allocation(total: u32) -> SectionBudgets {
    SectionBudgets {
        system_prompt:  (total as f64 * 0.06) as u32,  //   6%
        patterns:       (total as f64 * 0.28) as u32,  //  28%
        constraints:    (total as f64 * 0.12) as u32,  //  12%
        entry_points:   (total as f64 * 0.10) as u32,  //  10%
        key_files:      (total as f64 * 0.08) as u32,  //   8%
        guidance:       (total as f64 * 0.06) as u32,  //   6%
        memories:       (total as f64 * 0.10) as u32,  //  10%
        examples:       (total as f64 * 0.12) as u32,  //  12%
        data_accessors: (total as f64 * 0.08) as u32,  //   8%
    }
}

#[derive(Debug, Clone)]
pub struct SectionBudgets {
    pub system_prompt: u32,
    pub patterns: u32,
    pub constraints: u32,
    pub entry_points: u32,
    pub key_files: u32,
    pub guidance: u32,
    pub memories: u32,
    pub examples: u32,
    pub data_accessors: u32,
}

impl SectionBudgets {
    pub fn total(&self) -> u32 {
        self.system_prompt + self.patterns + self.constraints
        + self.entry_points + self.key_files + self.guidance
        + self.memories + self.examples + self.data_accessors
    }
}
```

### Intent-Specific Adjustments

```rust
/// Shift budget between sections based on intent.
/// Example: SecurityReview shifts tokens from patterns → data_accessors + constraints.
fn apply_intent_adjustments(
    mut budgets: SectionBudgets,
    intent: ContextIntent,
) -> SectionBudgets {
    match intent {
        ContextIntent::SecurityReview => {
            // Shift 10% from patterns to data_accessors and constraints
            let shift = budgets.patterns / 10;
            budgets.patterns -= shift * 2;
            budgets.data_accessors += shift;
            budgets.constraints += shift;
        }
        ContextIntent::FixBug => {
            // Shift 5% from entry_points to memories (past decisions matter)
            let shift = budgets.entry_points / 5;
            budgets.entry_points -= shift;
            budgets.memories += shift;
        }
        ContextIntent::AddTest => {
            // Shift from data_accessors to examples (test templates)
            let shift = budgets.data_accessors / 2;
            budgets.data_accessors -= shift;
            budgets.examples += shift;
        }
        _ => {} // AddFeature, Refactor, Understand — use base allocation
    }
    budgets
}
```

### Within-Section Trimming

Items within each section are sorted by relevance score. Trimming removes the
lowest-scored items first. Items are never partially trimmed — either the full
item fits or it's excluded.

```rust
/// Trim a section's items to fit within the allocated budget.
/// Items are sorted by relevance_score descending. Lowest-scored items removed first.
/// Returns the items that fit and any surplus budget (unused tokens).
pub fn trim_section(
    items: &[impl HasTokenCost + HasRelevanceScore],
    budget: u32,
) -> (Vec<&impl HasTokenCost>, u32) {
    let mut remaining = budget;
    let mut kept = Vec::new();

    // Items already sorted by relevance_score descending
    for item in items {
        if item.token_cost() <= remaining {
            remaining -= item.token_cost();
            kept.push(item);
        }
        // If item doesn't fit, skip it (don't partially include)
    }

    let surplus = remaining;
    (kept, surplus)
}
```

### Surplus Redistribution

If a section uses fewer tokens than allocated (e.g., only 3 constraints exist,
using 400 of 900 allocated tokens), the surplus is redistributed to the
highest-demand section (typically patterns).

```rust
/// Redistribute surplus tokens from under-utilized sections to over-demand sections.
pub fn redistribute_surplus(
    budgets: &mut SectionBudgets,
    actual_usage: &SectionBudgets,
) {
    let surplus = budgets.total().saturating_sub(actual_usage.total());
    if surplus == 0 { return; }

    // Redistribution priority: patterns > constraints > memories > entry_points
    let priority_fields = [
        &mut budgets.patterns,
        &mut budgets.constraints,
        &mut budgets.memories,
        &mut budgets.entry_points,
    ];

    let mut remaining_surplus = surplus;
    for field in priority_fields {
        if remaining_surplus == 0 { break; }
        // Give each priority field up to 50% of remaining surplus
        let grant = remaining_surplus / 2;
        *field += grant;
        remaining_surplus -= grant;
    }
    // Any leftover goes to patterns (the catch-all)
    budgets.patterns += remaining_surplus;
}
```

### Invariant

`sum(section_budgets) <= total_budget`. No section budget is negative.
Redistribution never exceeds total. Verified by property-based tests (§19).

---

## 10. Package Detection — 15 Package Managers

Preserves v1's 11-language detection (the biggest differentiator) and adds 4 new
managers: Bun, Deno, Swift Package Manager, and Kotlin Multiplatform.

### PackageDetector

```rust
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub struct PackageDetector {
    root_dir: PathBuf,
    /// Cached detection result. None = not yet detected.
    cache: Mutex<Option<MonorepoStructure>>,
}

impl PackageDetector {
    pub fn new(root_dir: PathBuf) -> Self {
        Self {
            root_dir,
            cache: Mutex::new(None),
        }
    }

    /// Full monorepo detection. Cached after first call.
    pub fn detect(&self) -> Result<MonorepoStructure, PackageDetectionError> {
        if let Ok(guard) = self.cache.lock() {
            if let Some(ref cached) = *guard {
                return Ok(cached.clone());
            }
        }

        let result = self.detect_inner()?;

        if let Ok(mut guard) = self.cache.lock() {
            *guard = Some(result.clone());
        }

        Ok(result)
    }

    /// Find package by name, path, or partial match.
    /// Resolution order: exact name → exact path → path suffix/prefix → substring.
    pub fn get_package(&self, name_or_path: &str) -> Result<Option<DetectedPackage>, PackageDetectionError> {
        let structure = self.detect()?;
        Ok(lookup::resolve_package(&structure.packages, name_or_path))
    }

    /// Invalidate cached detection results.
    pub fn clear_cache(&self) {
        if let Ok(mut guard) = self.cache.lock() {
            *guard = None;
        }
    }

    fn detect_inner(&self) -> Result<MonorepoStructure, PackageDetectionError> {
        let detectors: Vec<Box<dyn PackageManagerDetector>> = vec![
            Box::new(managers::NpmDetector::new(&self.root_dir)),
            Box::new(managers::PnpmDetector::new(&self.root_dir)),
            Box::new(managers::YarnDetector::new(&self.root_dir)),
            Box::new(managers::BunDetector::new(&self.root_dir)),       // NEW
            Box::new(managers::DenoDetector::new(&self.root_dir)),      // NEW
            Box::new(managers::PythonDetector::new(&self.root_dir)),
            Box::new(managers::GoDetector::new(&self.root_dir)),
            Box::new(managers::MavenDetector::new(&self.root_dir)),
            Box::new(managers::GradleDetector::new(&self.root_dir)),
            Box::new(managers::ComposerDetector::new(&self.root_dir)),
            Box::new(managers::DotNetDetector::new(&self.root_dir)),
            Box::new(managers::CargoDetector::new(&self.root_dir)),
            Box::new(managers::SwiftDetector::new(&self.root_dir)),     // NEW
            Box::new(managers::RootFallback::new(&self.root_dir)),
        ];

        for detector in &detectors {
            match detector.detect() {
                Ok(packages) if !packages.is_empty() => {
                    let is_monorepo = packages.len() > 1;
                    return Ok(MonorepoStructure {
                        root_dir: self.root_dir.to_string_lossy().to_string(),
                        is_monorepo,
                        packages,
                        package_manager: detector.manager_type(),
                        workspace_config: detector.config_file(),
                    });
                }
                Ok(_) => continue,  // No packages found, try next detector
                Err(e) => {
                    tracing::warn!(
                        detector = %detector.manager_type(),
                        error = %e,
                        "Package detector failed, trying next"
                    );
                    continue;
                }
            }
        }

        // Should never reach here — RootFallback always returns at least 1 package
        Err(PackageDetectionError::NoPackagesFound)
    }
}
```

### PackageManagerDetector Trait

```rust
/// Trait implemented by each package manager detector.
pub trait PackageManagerDetector {
    /// Attempt to detect packages managed by this package manager.
    fn detect(&self) -> Result<Vec<DetectedPackage>, PackageDetectionError>;
    /// The package manager type this detector handles.
    fn manager_type(&self) -> PackageManager;
    /// The config file that triggered detection (e.g., "pnpm-workspace.yaml").
    fn config_file(&self) -> Option<String>;
}
```

### Package Manager Support Matrix (15 managers)

| # | Manager | Detection File | Language | Workspace | Status |
|---|---------|---------------|----------|-----------|--------|
| 1 | npm | `package.json` → `workspaces` | TS/JS | Glob patterns | v1 ✓ |
| 2 | pnpm | `pnpm-workspace.yaml` | TS/JS | YAML packages list | v1 ✓ |
| 3 | yarn | `package.json` + `yarn.lock` | TS/JS | Same as npm | v1 ✓ |
| 4 | Bun | `bun.lockb` / `bun.lock` | TS/JS | `package.json` workspaces | NEW |
| 5 | Deno | `deno.json` / `deno.jsonc` + `deno.lock` | TS/JS | `workspace` field | NEW |
| 6 | pip | `requirements.txt` / `setup.py` | Python | `src/*/` directories | v1 ✓ |
| 7 | poetry | `pyproject.toml` | Python | `[tool.poetry]` section | v1 ✓ |
| 8 | cargo | `Cargo.toml` → `[workspace]` | Rust | `members` array | v1 ✓ |
| 9 | go | `go.mod` | Go | `internal/`, `pkg/`, `cmd/` | v1 ✓ |
| 10 | maven | `pom.xml` → `<modules>` | Java | `<module>` elements | v1 ✓ |
| 11 | gradle | `settings.gradle` / `.kts` | Java/Kotlin | `include` statements | v1 ✓ |
| 12 | composer | `composer.json` | PHP | Single package | v1 ✓ |
| 13 | nuget | `*.sln` → Project references | C# | `.csproj` references | v1 ✓ |
| 14 | Swift PM | `Package.swift` | Swift | `dependencies` + targets | NEW |
| 15 | Root fallback | Any manifest file | Any | Single package | v1 ✓ |

### DetectedPackage (preserved from v1, all 10 fields)

```rust
#[derive(Debug, Clone, Serialize)]
pub struct DetectedPackage {
    pub name: String,
    pub path: String,                    // Relative path from project root
    pub absolute_path: String,           // Absolute filesystem path
    pub package_manager: PackageManager,
    pub language: String,                // "typescript", "python", "rust", etc.
    pub internal_dependencies: Vec<String>,
    pub external_dependencies: Vec<String>, // First 20
    pub is_root: bool,
    pub version: Option<String>,
    pub description: Option<String>,
}
```

### PackageManager Enum (12 → 15 values)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PackageManager {
    Npm,
    Pnpm,
    Yarn,
    Bun,        // NEW
    Deno,       // NEW
    Pip,
    Poetry,
    Cargo,
    Go,
    Maven,
    Gradle,
    Composer,
    Nuget,
    Swift,      // NEW
    Unknown,
}
```

### MonorepoStructure (preserved from v1)

```rust
#[derive(Debug, Clone, Serialize)]
pub struct MonorepoStructure {
    pub root_dir: String,
    pub is_monorepo: bool,
    pub packages: Vec<DetectedPackage>,
    pub package_manager: PackageManager,
    pub workspace_config: Option<String>,
}
```

### New Detector: Bun

```rust
pub struct BunDetector { root: PathBuf }

impl PackageManagerDetector for BunDetector {
    fn detect(&self) -> Result<Vec<DetectedPackage>, PackageDetectionError> {
        // Bun uses the same workspace format as npm (package.json → workspaces)
        // but is identified by the presence of bun.lockb or bun.lock
        let has_bun_lock = self.root.join("bun.lockb").exists()
            || self.root.join("bun.lock").exists();
        if !has_bun_lock { return Ok(vec![]); }

        // Reuse npm workspace detection logic
        let packages = detect_npm_workspaces(&self.root, PackageManager::Bun)?;
        Ok(packages)
    }

    fn manager_type(&self) -> PackageManager { PackageManager::Bun }
    fn config_file(&self) -> Option<String> { Some("bun.lockb".into()) }
}
```

### New Detector: Deno

```rust
pub struct DenoDetector { root: PathBuf }

impl PackageManagerDetector for DenoDetector {
    fn detect(&self) -> Result<Vec<DetectedPackage>, PackageDetectionError> {
        let deno_json = self.root.join("deno.json");
        let deno_jsonc = self.root.join("deno.jsonc");
        let config_path = if deno_json.exists() {
            deno_json
        } else if deno_jsonc.exists() {
            deno_jsonc
        } else {
            return Ok(vec![]);
        };

        let content = std::fs::read_to_string(&config_path)?;
        let config: serde_json::Value = serde_json::from_str(&content)?;

        // Deno workspaces: deno.json → "workspace" field (array of paths)
        if let Some(workspace) = config.get("workspace").and_then(|w| w.as_array()) {
            let mut packages = Vec::new();
            for member in workspace {
                if let Some(path) = member.as_str() {
                    let pkg_path = self.root.join(path);
                    if pkg_path.exists() {
                        packages.push(detect_deno_package(&pkg_path, path)?);
                    }
                }
            }
            if !packages.is_empty() { return Ok(packages); }
        }

        // Single Deno project (no workspace)
        Ok(vec![detect_deno_package(&self.root, ".")?])
    }

    fn manager_type(&self) -> PackageManager { PackageManager::Deno }
    fn config_file(&self) -> Option<String> { Some("deno.json".into()) }
}
```

### New Detector: Swift Package Manager

```rust
pub struct SwiftDetector { root: PathBuf }

impl PackageManagerDetector for SwiftDetector {
    fn detect(&self) -> Result<Vec<DetectedPackage>, PackageDetectionError> {
        let package_swift = self.root.join("Package.swift");
        if !package_swift.exists() { return Ok(vec![]); }

        let content = std::fs::read_to_string(&package_swift)?;

        // Extract package name from: let package = Package(name: "MyPackage", ...)
        let name = extract_swift_package_name(&content)
            .unwrap_or_else(|| self.root.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string());

        // Extract targets as sub-packages
        let targets = extract_swift_targets(&content);

        let mut packages = vec![DetectedPackage {
            name: name.clone(),
            path: ".".into(),
            absolute_path: self.root.to_string_lossy().to_string(),
            package_manager: PackageManager::Swift,
            language: "swift".into(),
            internal_dependencies: vec![],
            external_dependencies: extract_swift_dependencies(&content),
            is_root: true,
            version: None,
            description: None,
        }];

        // Each target becomes a sub-package
        for target in targets {
            packages.push(DetectedPackage {
                name: target.name.clone(),
                path: format!("Sources/{}", target.name),
                absolute_path: self.root.join("Sources").join(&target.name)
                    .to_string_lossy().to_string(),
                package_manager: PackageManager::Swift,
                language: "swift".into(),
                internal_dependencies: target.dependencies,
                external_dependencies: vec![],
                is_root: false,
                version: None,
                description: None,
            });
        }

        Ok(packages)
    }

    fn manager_type(&self) -> PackageManager { PackageManager::Swift }
    fn config_file(&self) -> Option<String> { Some("Package.swift".into()) }
}
```


---

## 11. Package Dependency Graph (CG10)

Builds a graph from detected packages to enable cross-package context, affected-package
analysis, and smarter dependency pattern loading. v1 had flat `internalDependencies` lists
with no graph structure and no transitive awareness.

### PackageDependencyGraph

```rust
use rustc_hash::FxHashMap;

#[derive(Debug, Clone)]
pub struct PackageDependencyGraph {
    nodes: FxHashMap<String, PackageNode>,
    edges: Vec<DependencyEdge>,
}

#[derive(Debug, Clone)]
pub struct PackageNode {
    pub package: DetectedPackage,
    pub depth: usize,  // Distance from root (0 = root package)
}

#[derive(Debug, Clone)]
pub struct DependencyEdge {
    pub from: String,       // Package name
    pub to: String,         // Package name
    pub dep_type: DependencyType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyType {
    Direct,
    Dev,
    Peer,
    Transitive,
}

impl PackageDependencyGraph {
    /// Build graph from detected packages.
    pub fn build(packages: &[DetectedPackage]) -> Self {
        let mut nodes = FxHashMap::default();
        let mut edges = Vec::new();

        // Create nodes
        for pkg in packages {
            nodes.insert(pkg.name.clone(), PackageNode {
                package: pkg.clone(),
                depth: 0, // Computed below
            });
        }

        // Create edges from internal dependencies
        for pkg in packages {
            for dep in &pkg.internal_dependencies {
                if nodes.contains_key(dep) {
                    edges.push(DependencyEdge {
                        from: pkg.name.clone(),
                        to: dep.clone(),
                        dep_type: DependencyType::Direct,
                    });
                }
            }
        }

        // Compute depths via BFS from root packages
        let mut graph = Self { nodes, edges };
        graph.compute_depths();
        graph
    }

    /// Get direct dependencies of a package (1 hop).
    pub fn direct_deps(&self, package: &str) -> Vec<&DetectedPackage> {
        self.edges.iter()
            .filter(|e| e.from == package)
            .filter_map(|e| self.nodes.get(&e.to).map(|n| &n.package))
            .collect()
    }

    /// Get all transitive dependencies (full reachability).
    pub fn transitive_deps(&self, package: &str) -> Vec<&DetectedPackage> {
        let mut visited = FxHashSet::default();
        let mut queue = VecDeque::new();
        queue.push_back(package.to_string());

        while let Some(current) = queue.pop_front() {
            for edge in &self.edges {
                if edge.from == current && visited.insert(edge.to.clone()) {
                    queue.push_back(edge.to.clone());
                }
            }
        }

        visited.iter()
            .filter_map(|name| self.nodes.get(name).map(|n| &n.package))
            .collect()
    }

    /// Get packages affected by changes in a given package (reverse dependencies).
    pub fn affected_packages(&self, changed_package: &str) -> Vec<&DetectedPackage> {
        let mut visited = FxHashSet::default();
        let mut queue = VecDeque::new();
        queue.push_back(changed_package.to_string());

        while let Some(current) = queue.pop_front() {
            for edge in &self.edges {
                if edge.to == current && visited.insert(edge.from.clone()) {
                    queue.push_back(edge.from.clone());
                }
            }
        }

        visited.iter()
            .filter_map(|name| self.nodes.get(name).map(|n| &n.package))
            .collect()
    }

    /// Dependency distance weight for cross-package context scoring.
    /// Direct dep: 0.5, transitive (depth 2): 0.33, etc.
    pub fn dep_weight(distance: usize) -> f64 {
        1.0 / (1.0 + distance as f64)
    }

    fn compute_depths(&mut self) {
        // BFS from root packages
        let roots: Vec<String> = self.nodes.iter()
            .filter(|(_, n)| n.package.is_root)
            .map(|(name, _)| name.clone())
            .collect();

        let mut queue = VecDeque::new();
        for root in &roots {
            queue.push_back((root.clone(), 0usize));
        }

        while let Some((current, depth)) = queue.pop_front() {
            if let Some(node) = self.nodes.get_mut(&current) {
                if node.depth == 0 || depth < node.depth {
                    node.depth = depth;
                }
            }
            for edge in &self.edges {
                if edge.from == current {
                    queue.push_back((edge.to.clone(), depth + 1));
                }
            }
        }
    }
}
```

### Cross-Package Context

When `scope: CrossPackage`, the engine gathers candidates from the target package
AND its direct dependencies, weighting dependency patterns by distance:

```rust
fn gather_cross_package_candidates(
    &self,
    target_package: &str,
    graph: &PackageDependencyGraph,
    db: &DatabaseManager,
) -> Result<Vec<CandidateItem>, ContextError> {
    let mut candidates = Vec::new();

    // Primary package — full weight
    candidates.extend(
        self.gather_package_candidates(target_package, db)?
    );

    // Direct dependencies — weighted by distance
    for dep in graph.direct_deps(target_package) {
        let dep_candidates = self.gather_package_candidates(&dep.name, db)?;
        for mut c in dep_candidates {
            c.from_dependency = Some(dep.name.clone());
            c.relevance_boost *= PackageDependencyGraph::dep_weight(1);
            candidates.push(c);
        }
    }

    Ok(candidates)
}
```

---

## 12. Session-Aware Context Deduplication (CG7)

Tracks what context has been delivered per session and delivers only deltas on
subsequent requests. Estimated 30-50% token reduction on follow-up requests.

### SessionTracker

```rust
use std::collections::HashMap;
use std::time::{Duration, Instant};

const SESSION_TTL: Duration = Duration::from_secs(30 * 60); // 30 minutes

pub struct SessionTracker {
    sessions: Mutex<HashMap<SessionId, SessionState>>,
}

struct SessionState {
    delivered: HashMap<u64, DeliveredItem>,  // content_hash → delivery info
    last_activity: Instant,
    request_count: u32,
}

struct DeliveredItem {
    item_id: String,
    content_hash: u64,
    delivered_at: Instant,
    depth: ContextDepth,
    intent: ContextIntent,
}

impl SessionTracker {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Record what was delivered in a context response.
    pub fn record_delivery(
        &self,
        session_id: &SessionId,
        result: &ContextResult,
    ) {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let state = sessions.entry(session_id.clone()).or_insert_with(|| SessionState {
            delivered: HashMap::new(),
            last_activity: Instant::now(),
            request_count: 0,
        });

        state.last_activity = Instant::now();
        state.request_count += 1;

        // Record all delivered items
        for pattern in &result.patterns {
            let hash = compute_content_hash(&pattern.id, &pattern.name);
            state.delivered.insert(hash, DeliveredItem {
                item_id: pattern.id.clone(),
                content_hash: hash,
                delivered_at: Instant::now(),
                depth: result.summary.depth,
                intent: result.summary.intent,
            });
        }
        // Same for constraints, entry_points, memories, etc.
    }

    /// Check if an item was already delivered in this session.
    /// Returns None if not delivered, Some(DeliveredItem) if already sent.
    pub fn check_delivered(
        &self,
        session_id: &SessionId,
        content_hash: u64,
    ) -> Option<bool> {
        let sessions = self.sessions.lock().ok()?;
        let state = sessions.get(session_id)?;

        // Check TTL
        if state.last_activity.elapsed() > SESSION_TTL {
            return None; // Session expired
        }

        Some(state.delivered.contains_key(&content_hash))
    }

    /// Apply deduplication to candidates. Items already delivered get compacted.
    pub fn deduplicate(
        &self,
        session_id: &SessionId,
        candidates: &mut Vec<ScoredCandidate>,
    ) -> u32 {
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let state = match sessions.get(session_id) {
            Some(s) if s.last_activity.elapsed() < SESSION_TTL => s,
            _ => return 0, // No session or expired
        };

        let mut tokens_saved = 0u32;

        for candidate in candidates.iter_mut() {
            if let Some(delivered) = state.delivered.get(&candidate.content_hash) {
                // Item was already delivered — compact it
                let original_cost = candidate.token_cost;
                candidate.compact_reference = Some(format!(
                    "[Previously delivered: {} — see earlier in conversation]",
                    candidate.name
                ));
                // Compacted reference costs ~15 tokens instead of full item
                candidate.token_cost = 15;
                tokens_saved += original_cost.saturating_sub(15);
            }
        }

        tokens_saved
    }

    /// Evict expired sessions. Called periodically (e.g., every 100 requests).
    pub fn evict_expired(&self) {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.retain(|_, state| state.last_activity.elapsed() < SESSION_TTL);
    }
}
```

### Deduplication Behavior

1. First request in session: Full context generation (no deduplication)
2. Subsequent requests (same intent): Items already delivered get compacted to references
3. Subsequent requests (different intent): Items that are now higher-priority get
   re-delivered with new framing. Items that are now lower-priority get compacted.
4. Session expires after 30 minutes of inactivity. State is in-memory only.

---

## 13. Cortex Memory Integration (CG8)

Enriches context with tribal knowledge, decisions, and rationale from Cortex.
v1's `drift_context` had this but `drift_package_context` did not. v2 unifies
both paths so all context includes memories when Cortex is available.

### Memory Retrieval Step

Inserted into the unified pipeline between "Gather candidates" and "Score":

```rust
/// Retrieve relevant Cortex memories for the current context scope.
/// Returns empty vec if Cortex is unavailable (graceful degradation).
fn retrieve_memories(
    &self,
    scope: &ResolvedScope,
    request: &ContextRequest,
    warnings: &mut Vec<ContextWarning>,
) -> Vec<ContextMemory> {
    let cortex = match self.get_cortex_client() {
        Some(c) => c,
        None => return vec![], // Cortex not available — skip silently
    };

    let limit = match request.depth {
        ContextDepth::Overview => 3,
        ContextDepth::Standard => 5,
        ContextDepth::Deep => 15,
    };

    let query = CortexQuery {
        scope: scope.package_paths.clone(),
        intent: Some(request.intent()),
        memory_types: vec!["semantic", "tribal", "decision", "convention"],
        limit,
        min_confidence: 0.5,
        exclude_archived: true,
    };

    match cortex.retrieve_memories(&query) {
        Ok(memories) => {
            memories.into_iter().map(|m| ContextMemory {
                id: m.id,
                memory_type: m.memory_type,
                content: m.content,
                confidence: m.confidence,
                files: m.related_files,
                relevance_score: 0.0, // Scored in the scoring phase
                token_cost: 0,        // Computed in pre-computation phase
            }).collect()
        }
        Err(e) => {
            warnings.push(ContextWarning::DataSourceUnavailable {
                source: "cortex_memories",
                reason: format!("Cortex retrieval failed: {e}"),
            });
            vec![]
        }
    }
}
```

### Memory Scoring Integration

Cortex memories participate in the same relevance scoring as patterns and constraints:

- `confidence` → maps to the `confidence` component (0.30 weight)
- `importance` → maps to `min(1.0, access_count / max_access_count)` (0.10 weight)
- `recency` → uses `last_accessed_at` instead of `updated_at` (0.15 weight)
- `category_match` → memory_type mapped to intent priority categories (0.25 weight)
- `file_proximity` → uses `related_files` for proximity calculation (0.20 weight)

### Memory Section in AI Output

```
## Tribal Knowledge & Decisions

- [decision] Always use idempotency keys for payment API calls (confidence: 0.92)
  Files: src/payments/api.ts, src/checkout/service.ts

- [tribal] The legacy auth module has a race condition under high load — use AuthV2
  Files: src/auth/legacy.ts, src/auth/v2.ts

- [convention] Team prefers explicit error types over generic Error throws
```

### Fallback

If Cortex is unavailable (not initialized, database locked, etc.), the memory retrieval
step is skipped entirely. Context generation works without memories — they're an
enrichment, not a requirement. No warning is surfaced to the agent (memories are
optional by design).

---

## 14. Freshness Indicators (CG13)

Agents need to know how stale context data is. v1 included `metadata.generatedAt` but
nothing about when the underlying data was last updated.

### FreshnessMetadata

```rust
#[derive(Debug, Clone, Serialize)]
pub struct FreshnessMetadata {
    pub patterns: SourceFreshness,
    pub constraints: SourceFreshness,
    pub call_graph: SourceFreshness,
    pub security: SourceFreshness,
    pub cortex_memories: Option<SourceFreshness>,
    /// Aggregate staleness classification.
    pub staleness: Staleness,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceFreshness {
    pub last_scan_at: Option<String>,   // ISO 8601
    pub age_minutes: u64,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum Staleness {
    /// All data sources updated within 1 hour.
    Fresh,
    /// Some data sources updated within 1 hour, others older.
    Partial,
    /// All data sources older than 24 hours.
    Stale,
}

impl FreshnessMetadata {
    pub fn compute(
        patterns_ts: Option<i64>,
        constraints_ts: Option<i64>,
        call_graph_ts: Option<i64>,
        security_ts: Option<i64>,
        memories_ts: Option<i64>,
        now: i64,
    ) -> Self {
        let sources = [
            ("patterns", patterns_ts),
            ("constraints", constraints_ts),
            ("call_graph", call_graph_ts),
            ("security", security_ts),
        ];

        let ages: Vec<u64> = sources.iter()
            .filter_map(|(_, ts)| ts.map(|t| ((now - t) / 60).max(0) as u64))
            .collect();

        let staleness = if ages.is_empty() {
            Staleness::Stale
        } else if ages.iter().all(|&a| a < 60) {
            Staleness::Fresh
        } else if ages.iter().all(|&a| a > 1440) {
            Staleness::Stale
        } else {
            Staleness::Partial
        };

        Self {
            patterns: to_source_freshness(patterns_ts, now),
            constraints: to_source_freshness(constraints_ts, now),
            call_graph: to_source_freshness(call_graph_ts, now),
            security: to_source_freshness(security_ts, now),
            cortex_memories: memories_ts.map(|ts| to_source_freshness(Some(ts), now)),
            staleness,
        }
    }
}

fn to_source_freshness(ts: Option<i64>, now: i64) -> SourceFreshness {
    match ts {
        Some(t) => SourceFreshness {
            last_scan_at: Some(format_iso8601(t)),
            age_minutes: ((now - t) / 60).max(0) as u64,
        },
        None => SourceFreshness {
            last_scan_at: None,
            age_minutes: u64::MAX,
        },
    }
}
```

### Guidance Integration

When data is stale, a warning is automatically added to the guidance section:

```rust
fn add_freshness_warnings(guidance: &mut Guidance, freshness: &FreshnessMetadata) {
    match freshness.staleness {
        Staleness::Stale => {
            guidance.warnings.push(
                "⚠️ All analysis data is >24 hours old. Run `drift scan` to refresh.".into()
            );
        }
        Staleness::Partial => {
            // Add specific warnings for stale sources
            if freshness.call_graph.age_minutes > 1440 {
                guidance.warnings.push(format!(
                    "⚠️ Call graph data is {} hours old. Recent code changes may not be reflected.",
                    freshness.call_graph.age_minutes / 60
                ));
            }
            if freshness.security.age_minutes > 1440 {
                guidance.warnings.push(format!(
                    "⚠️ Security data is {} hours old. Run `drift scan` to refresh.",
                    freshness.security.age_minutes / 60
                ));
            }
        }
        Staleness::Fresh => {} // No warnings needed
    }
}
```


---

## 15. Model-Aware Context Formatting (CG12)

v1 produced a single markdown format. v2 supports three formats optimized for different
AI model families. Research (R21 — Phil Schmid) shows format matters: Claude performs
better with XML tags, GPT models prefer markdown, and agent frameworks need structured JSON.

### Formatter Trait

```rust
pub trait ContextFormatter {
    fn format(&self, context: &BudgetedContext) -> FormattedContext;
}
```

### Markdown Formatter (Default)

```rust
pub struct MarkdownFormatter;

impl ContextFormatter for MarkdownFormatter {
    fn format(&self, ctx: &BudgetedContext) -> FormattedContext {
        let mut sections = Vec::new();

        // System prompt
        sections.push(format!(
            "## Package: {} ({})\n{}\n\n## Summary\n- {} patterns detected\n\
             - {} constraints apply\n- {} entry points\n- {} data accessors",
            ctx.package_name(), ctx.language(),
            ctx.description().unwrap_or(""),
            ctx.patterns.len(), ctx.constraints.len(),
            ctx.entry_points.len(), ctx.data_accessors.len(),
        ));

        // Patterns (strategic ordering — CG17)
        if !ctx.patterns.is_empty() {
            let mut pattern_lines = vec!["## Conventions".to_string()];
            for (i, p) in ctx.patterns.iter().enumerate() {
                pattern_lines.push(format!(
                    "{}. **{}** (confidence: {:.0}%, seen {} times)\n   {}",
                    i + 1, p.name, p.confidence * 100.0, p.occurrences,
                    p.example.as_deref().unwrap_or(""),
                ));
            }
            sections.push(pattern_lines.join("\n"));
        }

        // Constraints
        if !ctx.constraints.is_empty() {
            let mut constraint_lines = vec!["## Constraints".to_string()];
            for c in &ctx.constraints {
                let icon = match c.enforcement {
                    Enforcement::Error => "🚫",
                    Enforcement::Warning => "⚠️",
                    Enforcement::Info => "ℹ️",
                };
                constraint_lines.push(format!(
                    "- {} [{}] {} — {}",
                    icon, c.enforcement_str(), c.condition, c.guidance,
                ));
            }
            sections.push(constraint_lines.join("\n"));
        }

        // Memories (if present)
        if !ctx.memories.is_empty() {
            let mut memory_lines = vec!["## Tribal Knowledge & Decisions".to_string()];
            for m in &ctx.memories {
                memory_lines.push(format!(
                    "- [{}] {} (confidence: {:.2})\n  Files: {}",
                    m.memory_type, m.content, m.confidence,
                    m.files.join(", "),
                ));
            }
            sections.push(memory_lines.join("\n"));
        }

        // Guidance
        if !ctx.guidance.key_insights.is_empty()
            || !ctx.guidance.warnings.is_empty()
        {
            let mut guidance_lines = vec!["## Guidance".to_string()];
            for insight in &ctx.guidance.key_insights {
                guidance_lines.push(format!("- {insight}"));
            }
            for warning in &ctx.guidance.warnings {
                guidance_lines.push(format!("- {warning}"));
            }
            sections.push(guidance_lines.join("\n"));
        }

        let text = sections.join("\n\n---\n\n");
        let tokens = compute_section_tokens(&sections, &ctx.token_counter);

        FormattedContext { text, tokens }
    }
}
```

### XML Formatter (Claude-Optimized)

```rust
pub struct XmlFormatter;

impl ContextFormatter for XmlFormatter {
    fn format(&self, ctx: &BudgetedContext) -> FormattedContext {
        let mut xml = String::new();

        xml.push_str(&format!(
            "<context package=\"{}\" language=\"{}\">\n",
            ctx.package_name(), ctx.language(),
        ));

        // Patterns
        xml.push_str(&format!("  <patterns count=\"{}\">\n", ctx.patterns.len()));
        for p in &ctx.patterns {
            xml.push_str(&format!(
                "    <pattern name=\"{}\" confidence=\"{:.2}\" occurrences=\"{}\">\n\
                 {}\
                 {}\
                     </pattern>\n",
                p.name, p.confidence, p.occurrences,
                p.example.as_ref().map(|e| format!("      <example>{e}</example>\n"))
                    .unwrap_or_default(),
                if !p.files.is_empty() {
                    format!("      <files>{}</files>\n", p.files.join(", "))
                } else { String::new() },
            ));
        }
        xml.push_str("  </patterns>\n");

        // Constraints
        xml.push_str(&format!("  <constraints count=\"{}\">\n", ctx.constraints.len()));
        for c in &ctx.constraints {
            xml.push_str(&format!(
                "    <constraint enforcement=\"{}\" name=\"{}\">\n\
                 {}      <guidance>{}</guidance>\n\
                     </constraint>\n",
                c.enforcement_str(), c.name, c.condition, c.guidance,
            ));
        }
        xml.push_str("  </constraints>\n");

        // Memories
        if !ctx.memories.is_empty() {
            xml.push_str(&format!("  <memories count=\"{}\">\n", ctx.memories.len()));
            for m in &ctx.memories {
                xml.push_str(&format!(
                    "    <memory type=\"{}\" confidence=\"{:.2}\">\n\
                     {}      <files>{}</files>\n\
                         </memory>\n",
                    m.memory_type, m.confidence, m.content,
                    m.files.join(", "),
                ));
            }
            xml.push_str("  </memories>\n");
        }

        xml.push_str("</context>");

        let tokens = TokenBreakdown::from_xml_sections(&xml, &ctx.token_counter);
        FormattedContext { text: xml, tokens }
    }
}
```

### JSON Formatter (Programmatic)

```rust
pub struct JsonFormatter;

impl ContextFormatter for JsonFormatter {
    fn format(&self, ctx: &BudgetedContext) -> FormattedContext {
        let json = serde_json::json!({
            "package": ctx.package_name(),
            "language": ctx.language(),
            "patterns": ctx.patterns.iter().map(|p| serde_json::json!({
                "name": p.name,
                "confidence": p.confidence,
                "occurrences": p.occurrences,
                "category": p.category,
                "example": p.example,
                "files": p.files,
            })).collect::<Vec<_>>(),
            "constraints": ctx.constraints.iter().map(|c| serde_json::json!({
                "name": c.name,
                "enforcement": c.enforcement_str(),
                "condition": c.condition,
                "guidance": c.guidance,
            })).collect::<Vec<_>>(),
            "memories": ctx.memories.iter().map(|m| serde_json::json!({
                "type": m.memory_type,
                "content": m.content,
                "confidence": m.confidence,
                "files": m.files,
            })).collect::<Vec<_>>(),
            "metadata": {
                "tokens": ctx.total_tokens(),
                "depth": format!("{:?}", ctx.depth),
                "intent": format!("{:?}", ctx.intent),
            },
        });

        let text = serde_json::to_string_pretty(&json).unwrap_or_default();
        let tokens = TokenBreakdown::from_json(&text, &ctx.token_counter);
        FormattedContext { text, tokens }
    }
}
```

### Format Selection

The MCP protocol doesn't expose which model the client is using. Format is specified
in the tool call parameters. Default is `markdown`. Agents that know they're running
on Claude can request `xml`.

```rust
fn get_formatter(format: OutputFormat) -> Box<dyn ContextFormatter> {
    match format {
        OutputFormat::Markdown => Box::new(MarkdownFormatter),
        OutputFormat::Xml => Box::new(XmlFormatter),
        OutputFormat::Json => Box::new(JsonFormatter),
    }
}
```

---

## 16. Strategic Content Ordering (CG17)

Transformer models exhibit the "lost in the middle" problem (R6 — NVIDIA): items at the
beginning and end of context receive more attention than items in the middle. v2 exploits
this by placing the most important items at primacy and recency positions.

### Item Ordering Within Sections

```rust
/// Apply primacy-recency ordering to maximize AI attention on the most important items.
/// Position 1 (first): Highest relevance score
/// Position N (last): Second highest relevance score
/// Middle: Everything else in descending order
pub fn apply_primacy_recency_ordering(items: &mut Vec<impl HasRelevanceScore>) {
    if items.len() < 3 { return; } // No reordering needed for 1-2 items

    // Items are already sorted by relevance_score descending
    // Move the second-highest item to the last position
    let second = items.remove(1);
    items.push(second);
}
```

### Section Ordering (Within Combined Output)

```
1. System prompt (always first — sets the frame)
2. Critical constraints (enforcement=Error — must not be missed)
3. Top patterns (highest relevance — the core conventions)
4. Entry points (structural orientation)
5. Guidance (insights, common patterns, warnings)
6. Key files (reference material)
7. Examples (supplementary — can be skimmed)
8. Cortex memories (enrichment — most recent/relevant last for recency)
```

This ordering ensures:
- Critical constraints get primacy attention (position 2, right after system prompt)
- Cortex memories get recency attention (last section)
- Patterns get near-primacy attention (position 3)

---

## 17. Graceful Degradation Matrix (CG16)

Context generation never fails completely. Every component has a defined fallback.
Degraded quality is always better than no context.

### Degradation Matrix

| Component | Failure Mode | Fallback | User Impact |
|---|---|---|---|
| SQLite database | Connection failure / corruption | Return minimal context with package info only | Reduced data, slower |
| Pattern loading | No patterns found / query error | Context without patterns section + guidance warning | Agent misses conventions |
| Constraint loading | Query error | Context without constraints + guidance warning | Agent misses constraints |
| Call graph data | Missing or corrupt | Context without entry points + guidance warning | Agent misses entry points |
| Security data | Missing or corrupt | Context without data accessors + guidance warning | Agent misses security info |
| Cortex memories | Cortex unavailable | Skip memory retrieval entirely (no warning) | No tribal knowledge |
| Token counting | Tokenizer unavailable | Character estimation with 20% safety margin | Budget less accurate |
| Package detection | No packages detected | Use root directory as single package | Repo-scoped context |
| Semantic scoring | Embeddings unavailable | Metadata-only scoring (Stage 1 only) | Ranking less precise |
| Session tracking | Session state lost | Full context (no deduplication) | Slightly more tokens |

### Implementation Pattern

Each pipeline step returns `PipelineResult<T>` where warnings are non-fatal:

```rust
struct PipelineResult<T> {
    data: T,
    warnings: Vec<ContextWarning>,
}

#[derive(Debug, Clone, Serialize)]
pub enum ContextWarning {
    DataSourceUnavailable {
        source: &'static str,
        reason: String,
    },
    FallbackUsed {
        component: &'static str,
        fallback: &'static str,
    },
    DataStale {
        source: &'static str,
        age_minutes: u64,
    },
}
```

The pipeline continues through all steps regardless of individual failures.
Warnings accumulate and are included in the context output's guidance section.

```rust
impl ContextEngine {
    fn gather_candidates(
        &self,
        scope: &ResolvedScope,
        request: &ContextRequest,
        warnings: &mut Vec<ContextWarning>,
    ) -> Result<CandidateSet, ContextError> {
        let mut candidates = CandidateSet::new();

        // Each data source is independently fallible
        match self.load_patterns(scope, request) {
            Ok(patterns) => candidates.patterns = patterns,
            Err(e) => {
                warnings.push(ContextWarning::DataSourceUnavailable {
                    source: "patterns",
                    reason: e.to_string(),
                });
                // Continue with empty patterns — other sources may still work
            }
        }

        match self.load_constraints(scope) {
            Ok(constraints) => candidates.constraints = constraints,
            Err(e) => {
                warnings.push(ContextWarning::DataSourceUnavailable {
                    source: "constraints",
                    reason: e.to_string(),
                });
            }
        }

        match self.load_entry_points(scope) {
            Ok(entry_points) => candidates.entry_points = entry_points,
            Err(e) => {
                warnings.push(ContextWarning::DataSourceUnavailable {
                    source: "call_graph",
                    reason: e.to_string(),
                });
            }
        }

        match self.load_data_accessors(scope) {
            Ok(accessors) => candidates.data_accessors = accessors,
            Err(e) => {
                warnings.push(ContextWarning::DataSourceUnavailable {
                    source: "security",
                    reason: e.to_string(),
                });
            }
        }

        Ok(candidates)
    }
}
```

---

## 18. SQLite-Backed Data Access (CG11)

Replaces v1's JSON file I/O with SQLite queries against drift.db. This is the primary
performance improvement: JSON file I/O for 20 packages took ~300ms; SQLite indexed
queries take ~5ms.

### Query Functions

```rust
/// Load patterns for a package scope from drift.db.
fn load_patterns(
    &self,
    scope: &ResolvedScope,
    request: &ContextRequest,
) -> Result<Vec<CandidatePattern>, ContextError> {
    let conn = self.db.read_connection()?;
    let min_confidence = request.min_confidence.unwrap_or(0.0);

    let mut stmt = conn.prepare_cached(
        "SELECT id, name, category, confidence, occurrences, example, files,
                updated_at, content_hash
         FROM patterns
         WHERE package_scope = ?1
           AND status IN ('approved', 'discovered')
           AND confidence >= ?2
         ORDER BY confidence DESC, occurrences DESC"
    )?;

    let rows = stmt.query_map(
        rusqlite::params![scope.package_path(), min_confidence],
        |row| {
            Ok(CandidatePattern {
                id: row.get(0)?,
                name: row.get(1)?,
                category: row.get(2)?,
                confidence: row.get(3)?,
                occurrences: row.get(4)?,
                example: row.get(5)?,
                files: serde_json::from_str(row.get::<_, String>(6)?.as_str())
                    .unwrap_or_default(),
                updated_at: row.get(7)?,
                content_hash: row.get(8)?,
            })
        },
    )?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| ContextError::Storage(e.to_string()))
}

/// Load constraints for a package scope.
fn load_constraints(
    &self,
    scope: &ResolvedScope,
) -> Result<Vec<CandidateConstraint>, ContextError> {
    let conn = self.db.read_connection()?;

    let mut stmt = conn.prepare_cached(
        "SELECT id, name, category, enforcement, condition, guidance,
                updated_at, content_hash
         FROM constraints
         WHERE package_scope = ?1
           AND status IN ('approved', 'discovered')"
    )?;

    let rows = stmt.query_map(
        rusqlite::params![scope.package_path()],
        |row| {
            Ok(CandidateConstraint {
                id: row.get(0)?,
                name: row.get(1)?,
                category: row.get(2)?,
                enforcement: row.get::<_, String>(3)?.parse().unwrap_or(Enforcement::Info),
                condition: row.get(4)?,
                guidance: row.get(5)?,
                updated_at: row.get(6)?,
                content_hash: row.get(7)?,
            })
        },
    )?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| ContextError::Storage(e.to_string()))
}

/// Load entry points (API endpoints, event handlers, CLI commands).
fn load_entry_points(
    &self,
    scope: &ResolvedScope,
) -> Result<Vec<CandidateEntryPoint>, ContextError> {
    let conn = self.db.read_connection()?;

    let mut stmt = conn.prepare_cached(
        "SELECT name, file, type, method, path
         FROM functions
         WHERE package_path LIKE ?1
           AND type IN ('api_endpoint', 'event_handler', 'cli_command')
         LIMIT 50"
    )?;

    let like_pattern = format!("{}%", scope.package_path());
    let rows = stmt.query_map(
        rusqlite::params![like_pattern],
        |row| {
            Ok(CandidateEntryPoint {
                name: row.get(0)?,
                file: row.get(1)?,
                entry_type: row.get(2)?,
                method: row.get(3)?,
                path: row.get(4)?,
            })
        },
    )?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| ContextError::Storage(e.to_string()))
}

/// Load data access points with sensitivity flags.
fn load_data_accessors(
    &self,
    scope: &ResolvedScope,
) -> Result<Vec<CandidateDataAccessor>, ContextError> {
    let conn = self.db.read_connection()?;

    let mut stmt = conn.prepare_cached(
        "SELECT name, file, tables, accesses_sensitive
         FROM data_access_points
         WHERE package_path LIKE ?1
         LIMIT 30"
    )?;

    let like_pattern = format!("{}%", scope.package_path());
    let rows = stmt.query_map(
        rusqlite::params![like_pattern],
        |row| {
            Ok(CandidateDataAccessor {
                name: row.get(0)?,
                file: row.get(1)?,
                tables: serde_json::from_str(row.get::<_, String>(2)?.as_str())
                    .unwrap_or_default(),
                accesses_sensitive: row.get(3)?,
            })
        },
    )?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| ContextError::Storage(e.to_string()))
}
```

### Required Indexes

```sql
CREATE INDEX idx_patterns_package_scope ON patterns(package_scope, status, confidence);
CREATE INDEX idx_constraints_package_scope ON constraints(package_scope, status);
CREATE INDEX idx_functions_package_type ON functions(package_path, type);
CREATE INDEX idx_data_access_package ON data_access_points(package_path);
```

### Performance Impact

| Operation | v1 (JSON files) | v2 (SQLite) | Speedup |
|-----------|-----------------|-------------|---------|
| Pattern loading (20 packages) | ~100ms | ~2ms | 50x |
| Constraint loading | ~50ms | ~1ms | 50x |
| Entry point extraction | ~100ms | ~2ms | 50x |
| Data accessor extraction | ~50ms | ~1ms | 50x |
| Total data access | ~300ms | ~6ms | 50x |


---

## 19. Content-Hash Cache Invalidation (CG14)

Only regenerates context sections affected by data changes. Uses content hashes
to detect when upstream data has changed since the last context generation.

### SectionHash

```rust
use rustc_hash::FxHasher;
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SectionHash {
    pub patterns_hash: u64,
    pub constraints_hash: u64,
    pub entry_points_hash: u64,
    pub data_accessors_hash: u64,
    pub memories_hash: u64,
    pub composite_hash: u64,
}

impl SectionHash {
    pub fn compute(
        patterns: &[CandidatePattern],
        constraints: &[CandidateConstraint],
        entry_points: &[CandidateEntryPoint],
        data_accessors: &[CandidateDataAccessor],
        memories: &[ContextMemory],
    ) -> Self {
        let patterns_hash = hash_items(patterns.iter().map(|p| p.content_hash));
        let constraints_hash = hash_items(constraints.iter().map(|c| c.content_hash));
        let entry_points_hash = hash_items(entry_points.iter().map(|e| {
            let mut h = FxHasher::default();
            e.name.hash(&mut h);
            e.file.hash(&mut h);
            h.finish()
        }));
        let data_accessors_hash = hash_items(data_accessors.iter().map(|d| {
            let mut h = FxHasher::default();
            d.name.hash(&mut h);
            d.file.hash(&mut h);
            h.finish()
        }));
        let memories_hash = hash_items(memories.iter().map(|m| {
            let mut h = FxHasher::default();
            m.id.hash(&mut h);
            m.confidence.to_bits().hash(&mut h);
            h.finish()
        }));

        let mut composite = FxHasher::default();
        patterns_hash.hash(&mut composite);
        constraints_hash.hash(&mut composite);
        entry_points_hash.hash(&mut composite);
        data_accessors_hash.hash(&mut composite);
        memories_hash.hash(&mut composite);

        Self {
            patterns_hash,
            constraints_hash,
            entry_points_hash,
            data_accessors_hash,
            memories_hash,
            composite_hash: composite.finish(),
        }
    }
}

fn hash_items(hashes: impl Iterator<Item = u64>) -> u64 {
    let mut hasher = FxHasher::default();
    for h in hashes {
        h.hash(&mut hasher);
    }
    hasher.finish()
}
```

### ContextCache

```rust
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct ContextCache {
    entries: Mutex<HashMap<CacheKey, CacheEntry>>,
    max_entries: usize,
    ttl: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    package_scope: String,
    intent: ContextIntent,
    depth: ContextDepth,
    composite_hash: u64,
}

struct CacheEntry {
    result: ContextResult,
    created_at: Instant,
}

impl ContextCache {
    pub fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_entries,
            ttl,
        }
    }

    pub fn get(&self, key: &CacheKey) -> Option<ContextResult> {
        let entries = self.entries.lock().ok()?;
        let entry = entries.get(key)?;
        if entry.created_at.elapsed() > self.ttl {
            return None; // Expired
        }
        Some(entry.result.clone())
    }

    pub fn insert(&self, key: CacheKey, result: ContextResult) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());

        // LRU eviction if at capacity
        if entries.len() >= self.max_entries {
            // Remove oldest entry
            if let Some(oldest_key) = entries.iter()
                .min_by_key(|(_, v)| v.created_at)
                .map(|(k, _)| k.clone())
            {
                entries.remove(&oldest_key);
            }
        }

        entries.insert(key, CacheEntry {
            result,
            created_at: Instant::now(),
        });
    }

    /// Invalidate all entries for a specific package scope.
    pub fn invalidate_package(&self, package_scope: &str) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.retain(|k, _| k.package_scope != package_scope);
    }

    /// Invalidate all entries (e.g., after a new scan).
    pub fn invalidate_all(&self) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.clear();
    }
}
```

---

## 20. Guidance Synthesis (Preserved from v1, Enhanced)

v1's guidance generation was one of the most valuable outputs — it gives AI agents
actionable direction beyond raw data. v2 preserves the algorithm and adds suggested
files (from v1's `drift_context` path) and freshness warnings.

### Guidance Generation Algorithm

```rust
pub fn generate_guidance(
    patterns: &[ScoredPattern],
    constraints: &[ScoredConstraint],
    freshness: &FreshnessMetadata,
    intent: ContextIntent,
) -> Guidance {
    // Key insights: categories with 2+ patterns
    let mut category_counts: FxHashMap<&str, usize> = FxHashMap::default();
    for p in patterns {
        *category_counts.entry(&p.category).or_default() += 1;
    }
    let key_insights: Vec<String> = category_counts.iter()
        .filter(|(_, &count)| count >= 2)
        .map(|(cat, count)| format!("{cat}: {count} patterns detected"))
        .collect();

    // Common patterns: top 5 with confidence ≥ 0.8
    let common_patterns: Vec<String> = patterns.iter()
        .filter(|p| p.confidence >= 0.8)
        .take(5)
        .map(|p| format!("{} (confidence: {:.0}%, {} occurrences)",
            p.name, p.confidence * 100.0, p.occurrences))
        .collect();

    // Warnings: up to 3 constraints with enforcement=Error
    let mut warnings: Vec<String> = constraints.iter()
        .filter(|c| c.enforcement == Enforcement::Error)
        .take(3)
        .map(|c| format!("🚫 {}", c.guidance))
        .collect();

    // Add freshness warnings
    add_freshness_warnings_to(&mut warnings, freshness);

    // Suggested files (NEW — from v1 drift_context path)
    let suggested_files = suggest_files(patterns, intent);

    Guidance {
        key_insights,
        common_patterns,
        warnings,
        suggested_files,
    }
}

/// Suggest files relevant to the current intent based on pattern data.
fn suggest_files(
    patterns: &[ScoredPattern],
    intent: ContextIntent,
) -> Vec<SuggestedFile> {
    let mut file_scores: FxHashMap<String, (f64, Vec<String>)> = FxHashMap::default();

    for pattern in patterns {
        for file in &pattern.files {
            let entry = file_scores.entry(file.clone()).or_insert((0.0, vec![]));
            entry.0 += pattern.relevance_score;
            if entry.1.len() < 3 {
                entry.1.push(pattern.name.clone());
            }
        }
    }

    let mut suggestions: Vec<SuggestedFile> = file_scores.into_iter()
        .map(|(file, (score, patterns))| SuggestedFile {
            file: file.clone(),
            reason: format!(
                "Contains {} relevant patterns: {}",
                patterns.len(),
                patterns.join(", ")
            ),
        })
        .collect();

    suggestions.sort_by(|a, b| b.reason.len().cmp(&a.reason.len())); // Rough proxy for relevance
    suggestions.truncate(5);
    suggestions
}
```

---

## 21. Key File Scoring (Preserved from v1)

Files scored by pattern density, enhanced with intent-weighted relevance.

```rust
/// Score files by pattern density and intent relevance.
/// Formula: score = Σ(pattern.confidence × pattern.occurrences × intent_weight)
pub fn score_key_files(
    patterns: &[ScoredPattern],
    intent_weights: &FxHashMap<&str, f64>,
    max_files: usize,
) -> Vec<KeyFile> {
    let mut file_scores: FxHashMap<String, FileScoreAccumulator> = FxHashMap::default();

    for pattern in patterns {
        let weight = intent_weights.get(pattern.category.as_str()).copied().unwrap_or(1.0);
        for file in &pattern.files {
            let entry = file_scores.entry(file.clone()).or_default();
            entry.score += pattern.confidence * pattern.occurrences as f64 * weight;
            if entry.patterns.len() < 5 {
                entry.patterns.push(pattern.name.clone());
            }
            entry.pattern_count += 1;
        }
    }

    let mut key_files: Vec<KeyFile> = file_scores.into_iter()
        .map(|(file, acc)| KeyFile {
            file: file.clone(),
            reason: format!("Contains {} patterns", acc.pattern_count),
            patterns: acc.patterns,
            score: acc.score,
            relevance_score: acc.score, // Already intent-weighted
            token_cost: 0, // Computed later
        })
        .collect();

    key_files.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    key_files.truncate(max_files);
    key_files
}

#[derive(Default)]
struct FileScoreAccumulator {
    score: f64,
    patterns: Vec<String>,
    pattern_count: usize,
}
```

---

## 22. NAPI Interface

Context generation is exposed to TypeScript via two NAPI functions, matching the
contract defined in 03-NAPI-BRIDGE-V2-PREP.md §10.14.

### NAPI Binding Module

```rust
// crates/drift-napi/src/bindings/context.rs

use napi_derive::napi;
use napi::bindgen_prelude::*;

#[napi(object)]
pub struct NapiContextOptions {
    /// Package name or path. Null = infer from active_file.
    pub package: Option<String>,
    /// Intent: "add_feature", "fix_bug", "understand", "refactor", "security_review", "add_test".
    pub intent: Option<String>,
    /// Natural language query (focus area).
    pub query: Option<String>,
    /// Token budget. Default: 8000.
    pub max_tokens: Option<u32>,
    /// Session ID for deduplication.
    pub session: Option<String>,
    /// Depth: "overview", "standard", "deep". Default: "standard".
    pub depth: Option<String>,
    /// Scope: "package", "cross_package", "repo". Default: "package".
    pub scope: Option<String>,
    /// Format: "markdown", "xml", "json". Default: "markdown".
    pub format: Option<String>,
    /// Include code snippets. Default: true.
    pub include_snippets: Option<bool>,
    /// Include dependency patterns. Default: true.
    pub include_dependencies: Option<bool>,
    /// Minimum confidence threshold.
    pub min_confidence: Option<f64>,
    /// Filter to specific categories.
    pub categories: Option<Vec<String>>,
    /// Currently active file in the editor.
    pub active_file: Option<String>,
    /// Model family: "openai", "anthropic", "generic". Default: "generic".
    pub model: Option<String>,
}

/// Generate AI-ready context for a focus area.
/// This is the unified entry point — both drift_context and drift_package_context
/// call this with different default parameters.
#[napi]
pub fn generate_context(
    options: NapiContextOptions,
) -> napi::Result<serde_json::Value> {
    let rt = crate::runtime::get()?;
    let request = convert_to_request(options)?;
    let result = rt.context_engine.generate(&request)
        .map_err(|e| napi::Error::from_reason(format!("[CONTEXT_ERROR] {e}")))?;
    serde_json::to_value(&result)
        .map_err(|e| napi::Error::from_reason(format!("[INTERNAL_ERROR] {e}")))
}

/// Generate context for a specific package (convenience wrapper).
/// Equivalent to generate_context with scope=Package and no intent.
#[napi]
pub fn generate_package_context(
    package: String,
    options: Option<NapiContextOptions>,
) -> napi::Result<serde_json::Value> {
    let rt = crate::runtime::get()?;
    let mut opts = options.unwrap_or_default();
    opts.package = Some(package);
    opts.scope = Some("package".into());
    // No intent = Understand (balanced weights)
    let request = convert_to_request(opts)?;
    let result = rt.context_engine.generate(&request)
        .map_err(|e| napi::Error::from_reason(format!("[CONTEXT_ERROR] {e}")))?;
    serde_json::to_value(&result)
        .map_err(|e| napi::Error::from_reason(format!("[INTERNAL_ERROR] {e}")))
}

/// List all detected packages in the project.
#[napi]
pub fn list_packages() -> napi::Result<serde_json::Value> {
    let rt = crate::runtime::get()?;
    let structure = rt.context_engine.detect_packages()
        .map_err(|e| napi::Error::from_reason(format!("[PACKAGE_DETECTION_ERROR] {e}")))?;
    serde_json::to_value(&structure)
        .map_err(|e| napi::Error::from_reason(format!("[INTERNAL_ERROR] {e}")))
}

fn convert_to_request(opts: NapiContextOptions) -> napi::Result<ContextRequest> {
    Ok(ContextRequest {
        package: opts.package,
        intent: opts.intent.as_deref().map(parse_intent).transpose()?,
        query: opts.query,
        max_tokens: opts.max_tokens.unwrap_or(8000),
        session: opts.session.map(SessionId),
        depth: opts.depth.as_deref().map(parse_depth).transpose()?
            .unwrap_or(ContextDepth::Standard),
        scope: opts.scope.as_deref().map(parse_scope).transpose()?
            .unwrap_or(ContextScope::Package),
        format: opts.format.as_deref().map(parse_format).transpose()?
            .unwrap_or(OutputFormat::Markdown),
        include_snippets: opts.include_snippets.unwrap_or(true),
        include_dependencies: opts.include_dependencies.unwrap_or(true),
        min_confidence: opts.min_confidence,
        categories: opts.categories,
        active_file: opts.active_file,
        model: opts.model.as_deref().map(parse_model).transpose()?
            .unwrap_or(ModelFamily::Generic),
    })
}

fn parse_intent(s: &str) -> napi::Result<ContextIntent> {
    match s {
        "add_feature" => Ok(ContextIntent::AddFeature),
        "fix_bug" => Ok(ContextIntent::FixBug),
        "understand" | "understand_code" => Ok(ContextIntent::Understand),
        "refactor" => Ok(ContextIntent::Refactor),
        "security_review" | "security_audit" => Ok(ContextIntent::SecurityReview),
        "add_test" => Ok(ContextIntent::AddTest),
        _ => Err(napi::Error::from_reason(
            format!("[INVALID_INTENT] Unknown intent: {s}. \
                     Valid: add_feature, fix_bug, understand, refactor, security_review, add_test")
        )),
    }
}

fn parse_depth(s: &str) -> napi::Result<ContextDepth> {
    match s {
        "overview" => Ok(ContextDepth::Overview),
        "standard" => Ok(ContextDepth::Standard),
        "deep" => Ok(ContextDepth::Deep),
        _ => Err(napi::Error::from_reason(
            format!("[INVALID_DEPTH] Unknown depth: {s}. Valid: overview, standard, deep")
        )),
    }
}

fn parse_scope(s: &str) -> napi::Result<ContextScope> {
    match s {
        "package" => Ok(ContextScope::Package),
        "cross_package" => Ok(ContextScope::CrossPackage),
        "repo" => Ok(ContextScope::Repo),
        _ => Err(napi::Error::from_reason(
            format!("[INVALID_SCOPE] Unknown scope: {s}. Valid: package, cross_package, repo")
        )),
    }
}

fn parse_format(s: &str) -> napi::Result<OutputFormat> {
    match s {
        "markdown" => Ok(OutputFormat::Markdown),
        "xml" => Ok(OutputFormat::Xml),
        "json" => Ok(OutputFormat::Json),
        _ => Err(napi::Error::from_reason(
            format!("[INVALID_FORMAT] Unknown format: {s}. Valid: markdown, xml, json")
        )),
    }
}

fn parse_model(s: &str) -> napi::Result<ModelFamily> {
    match s {
        "openai" => Ok(ModelFamily::OpenAI),
        "anthropic" | "claude" => Ok(ModelFamily::Anthropic),
        "generic" => Ok(ModelFamily::Generic),
        _ => Ok(ModelFamily::Generic), // Unknown model → generic fallback
    }
}
```

### TypeScript Bridge Types

```typescript
// packages/drift/src/bridge/context-types.ts

export interface ContextOptions {
    package?: string;
    intent?: 'add_feature' | 'fix_bug' | 'understand' | 'refactor' | 'security_review' | 'add_test';
    query?: string;
    maxTokens?: number;
    session?: string;
    depth?: 'overview' | 'standard' | 'deep';
    scope?: 'package' | 'cross_package' | 'repo';
    format?: 'markdown' | 'xml' | 'json';
    includeSnippets?: boolean;
    includeDependencies?: boolean;
    minConfidence?: number;
    categories?: string[];
    activeFile?: string;
    model?: 'openai' | 'anthropic' | 'generic';
}

export interface ContextResult {
    contextId: string;
    package?: PackageInfo;
    summary: ContextSummary;
    patterns: ScoredPattern[];
    constraints: ScoredConstraint[];
    entryPoints: ContextEntryPoint[];
    dataAccessors: ContextDataAccessor[];
    keyFiles: KeyFile[];
    guidance: Guidance;
    memories: ContextMemory[];
    dependencies: DependencyContext[];
    freshness: FreshnessMetadata;
    warnings: ContextWarning[];
    formatted: FormattedContext;
    metadata: ContextMetadata;
}
```


---

## 23. Layered Context Depth (CG4)

Three depth levels implementing progressive disclosure. Agents get focused context
first, details on demand. The invariant `overview ⊂ standard ⊂ deep` is enforced
by generating the deep layer internally and filtering down.

### Depth Specifications

**Overview (~2K tokens)**:
- Package name, language, description
- Top 5 patterns (name + one-line summary only, no examples)
- Critical constraints (enforcement=Error only)
- Key insight summary (3 bullets max)
- Package dependency list (names only)
- No entry points, no data accessors, no memories, no examples

**Standard (~6K tokens, default)**:
- Everything in overview
- Full pattern list (top 20 by relevance score, with confidence + occurrences)
- All applicable constraints with guidance text
- Top 10 entry points with types
- Top 5 key files with pattern associations
- Guidance section (insights, common patterns, warnings)
- Cortex memories relevant to scope (top 5)
- No code examples, no data accessor details

**Deep (~12K tokens)**:
- Everything in standard
- Code examples for top patterns (fenced blocks)
- Data accessor details with table names and sensitivity flags
- Dependency patterns from internal packages
- Full entry point list (up to 50)
- Extended Cortex memories (top 15)
- File-level detail for key files (imports, exports, function signatures)

### Depth Filtering

```rust
/// Apply depth filtering to a fully-generated context.
/// The engine generates at deep level internally, then filters down.
pub fn apply_depth_filter(
    context: &mut BudgetedContext,
    depth: ContextDepth,
) {
    match depth {
        ContextDepth::Overview => {
            context.patterns.truncate(5);
            // Remove examples from all patterns
            for p in &mut context.patterns {
                p.example = None;
            }
            // Keep only Error constraints
            context.constraints.retain(|c| c.enforcement == Enforcement::Error);
            // Clear sections not in overview
            context.entry_points.clear();
            context.data_accessors.clear();
            context.memories.clear();
            context.key_files.clear();
            // Truncate guidance
            context.guidance.key_insights.truncate(3);
            context.guidance.common_patterns.clear();
            context.guidance.suggested_files.clear();
        }
        ContextDepth::Standard => {
            context.patterns.truncate(20);
            // Remove examples (standard doesn't include them)
            for p in &mut context.patterns {
                p.example = None;
            }
            context.entry_points.truncate(10);
            context.key_files.truncate(5);
            context.memories.truncate(5);
            context.data_accessors.clear(); // Not in standard
        }
        ContextDepth::Deep => {
            // Deep = full context, no filtering needed
            context.entry_points.truncate(50);
            context.memories.truncate(15);
        }
    }
}
```

### Depth-Aware Token Budgets

| Section | Overview | Standard | Deep |
|---------|----------|----------|------|
| System prompt | 20% | 10% | 6% |
| Patterns | 35% | 35% | 28% |
| Constraints | 20% | 15% | 12% |
| Entry points | — | 10% | 10% |
| Key files | — | 8% | 8% |
| Guidance | 25% | 8% | 6% |
| Memories | — | 7% | 10% |
| Examples | — | 5% | 12% |
| Data accessors | — | 2% | 8% |

---

## 24. Error Types

### ContextError

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ContextError {
    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Package not found: {0}")]
    PackageNotFound(String),

    #[error("Package detection failed: {0}")]
    PackageDetection(#[from] PackageDetectionError),

    #[error("Token counting failed: {0}")]
    TokenCounting(String),

    #[error("Formatting error: {0}")]
    Formatting(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

#[derive(Debug, Error)]
pub enum PackageDetectionError {
    #[error("I/O error reading {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to parse {file}: {reason}")]
    ParseError {
        file: String,
        reason: String,
    },

    #[error("No packages found in {root}")]
    NoPackagesFound,

    #[error("Invalid workspace configuration: {0}")]
    InvalidWorkspace(String),
}
```

### NAPI Error Code Mapping

```rust
impl ContextError {
    pub fn error_code(&self) -> &'static str {
        match self {
            ContextError::Storage(_) => "STORAGE_ERROR",
            ContextError::PackageNotFound(_) => "PACKAGE_NOT_FOUND",
            ContextError::PackageDetection(_) => "PACKAGE_DETECTION_ERROR",
            ContextError::TokenCounting(_) => "TOKEN_COUNTING_ERROR",
            ContextError::Formatting(_) => "FORMATTING_ERROR",
            ContextError::Config(_) => "CONFIG_ERROR",
            ContextError::Internal(_) => "INTERNAL_ERROR",
        }
    }
}
```

---

## 25. v1 Feature Verification — Complete Gap Analysis

Cross-referenced against all v1 documentation, the existing v1 implementation
(~2,575 lines across 2 packages), and the forensic audit (AUDIT.md) to ensure
100% feature coverage in v2.

### v1 Features from PackageContextGenerator (Path 1)

| # | v1 Feature | v2 Status | v2 Location |
|---|-----------|-----------|-------------|
| F1 | 9-step pipeline (detect → load → extract → score → trim → format) | UPGRADED — 7-step unified pipeline with scoring + ranking | §3 |
| F2 | Package detection across 11 package managers | UPGRADED — 15 managers (+ Bun, Deno, Swift, Kotlin) | §10 |
| F3 | Package lookup (exact name → exact path → suffix → substring) | PRESERVED — identical 4-strategy resolution | §10 |
| F4 | Pattern loading from .drift/patterns/{approved,discovered}/*.json | UPGRADED — SQLite queries against drift.db | §18 |
| F5 | Constraint loading from .drift/constraints/ | UPGRADED — SQLite queries | §18 |
| F6 | Entry point extraction from call graph (max 50) | PRESERVED — same limit, SQLite source | §18 |
| F7 | Data accessor extraction from security lake (max 30) | PRESERVED — same limit, SQLite source | §18 |
| F8 | Key file scoring by pattern density (confidence × occurrences) | UPGRADED — intent-weighted relevance scoring | §21 |
| F9 | Guidance generation (insights, common patterns, warnings) | UPGRADED — adds suggested files + freshness warnings | §20 |
| F10 | Dependency pattern loading from internal deps (10 per dep) | UPGRADED — graph-aware with distance weighting | §11 |
| F11 | Token estimation (JSON.stringify × 0.25) | UPGRADED — BPE tokenization via tiktoken-rs | §8 |
| F12 | Priority-based token trimming (6 levels) | UPGRADED — proportional budget allocation + relevance trimming | §9 |
| F13 | AI context formatting (4 sections: prompt, conventions, examples, constraints) | UPGRADED — 3 formats (markdown, XML, JSON) + 8 sections | §15 |
| F14 | PackageContext output type (all fields) | PRESERVED — all fields present in ContextResult | §5 |
| F15 | AIContextFormat output type (5 text sections + token breakdown) | UPGRADED — FormattedContext with 9-section token breakdown | §5 |
| F16 | EventEmitter lifecycle events (6 event types) | UPGRADED — tracing spans + ContextWarning accumulation | §17 |
| F17 | Detection result caching (MonorepoStructure) | PRESERVED — Mutex<Option<MonorepoStructure>> | §10 |
| F18 | Cache invalidation (clearCache) | PRESERVED — clear_cache() method | §10 |
| F19 | PackageContextOptions (8 fields) | UPGRADED — ContextRequest (15 fields, superset) | §4 |
| F20 | ContextPattern type (8 fields) | UPGRADED — ScoredPattern (11 fields, adds relevance_score + token_cost) | §5 |
| F21 | ContextConstraint type (6 fields) | UPGRADED — ScoredConstraint (8 fields, adds relevance_score + token_cost) | §5 |
| F22 | ContextEntryPoint type (5 fields) | UPGRADED — 7 fields (adds relevance_score + token_cost) | §5 |
| F23 | ContextDataAccessor type (4 fields) | UPGRADED — 6 fields (adds relevance_score + token_cost) | §5 |
| F24 | ContextCacheEntry type | UPGRADED — ContextCache with content-hash invalidation | §19 |
| F25 | DEFAULT_MAX_TOKENS = 8000 | PRESERVED — default max_tokens = 8000 | §4 |
| F26 | CONTEXT_VERSION = '1.0.0' | UPGRADED — '2.0.0' | §5 |
| F27 | Data source hard caps (50 entry points, 30 accessors, 10 key files, 5 files/pattern) | PRESERVED — identical limits | §18, §21 |
| F28 | Language detection from package.json (typescript/react/vue/angular → typescript) | PRESERVED — identical heuristics | §10 |
| F29 | Internal dependency cross-referencing | UPGRADED — full dependency graph | §11 |
| F30 | External dependency extraction (first 20) | PRESERVED | §10 |
| F31 | Workspace glob resolution (single-level wildcards) | PRESERVED — same algorithm | §10 |

### v1 Features from drift_context Orchestrator (Path 2)

| # | v1 Feature | v2 Status | v2 Location |
|---|-----------|-----------|-------------|
| F32 | Intent-aware context (add_feature, fix_bug, understand, refactor, security_review) | PRESERVED + EXTENDED — adds add_test intent | §4, §6 |
| F33 | Intent strategies with category weighting | UPGRADED — formalized weight tables | §6 |
| F34 | Semantic insights generation | PRESERVED — in guidance.key_insights | §20 |
| F35 | Suggested files for intent | PRESERVED — in guidance.suggested_files | §20 |
| F36 | Cortex memory retrieval with intent weighting | UPGRADED — unified integration, all depths | §13 |
| F37 | Session deduplication (skip already-sent memories) | UPGRADED — full session tracking for all items | §12 |
| F38 | Code examples (prefer same-directory) | PRESERVED — file_proximity scoring | §7 |
| F39 | Call graph context (1-2 hops from active function) | PRESERVED — entry point extraction | §18 |
| F40 | Boundary context (sensitive field warnings) | PRESERVED — data accessor sensitivity flags | §5 |
| F41 | Token budget synthesis (default 2000 for drift_context) | PRESERVED — configurable max_tokens | §4 |
| F42 | Response metadata (tokenEstimate, patternCount, memoryCount, warnings) | UPGRADED — full ContextMetadata + TokenBreakdown | §5 |

### v1 Features from Type System

| # | v1 Feature | v2 Status | v2 Location |
|---|-----------|-----------|-------------|
| F43 | PackageManager enum (12 values) | UPGRADED — 15 values | §10 |
| F44 | DetectedPackage type (10 fields) | PRESERVED — all 10 fields | §10 |
| F45 | MonorepoStructure type (5 fields) | PRESERVED — all 5 fields | §10 |
| F46 | ContextEventType (6 values) | UPGRADED — ContextWarning enum + tracing | §17 |

### New v2 Features NOT in v1

| # | New Feature | Why | Location |
|---|------------|-----|----------|
| N1 | Unified context engine (merged dual paths) | Eliminates architectural debt, consistent behavior | §3 |
| N2 | Semantic relevance scoring (two-stage) | 12.5% accuracy improvement (Cursor research) | §7 |
| N3 | BPE token counting (tiktoken-rs) | Eliminates 20-40% budget estimation error | §8 |
| N4 | Proportional budget allocation | Replaces greedy section-cutting | §9 |
| N5 | 4 new package managers (Bun, Deno, Swift, Kotlin) | Modern runtime support | §10 |
| N6 | Package dependency graph | Cross-package context, affected analysis | §11 |
| N7 | Session-aware deduplication | 30-50% token savings on follow-ups | §12 |
| N8 | Cortex memory in all context (not just drift_context) | Tribal knowledge everywhere | §13 |
| N9 | Freshness indicators | Agents know data staleness | §14 |
| N10 | Model-aware formatting (markdown, XML, JSON) | Optimized for different AI models | §15 |
| N11 | Strategic content ordering (primacy-recency) | Better transformer attention allocation | §16 |
| N12 | Graceful degradation matrix | Never fails completely | §17 |
| N13 | Content-hash cache invalidation | Only regenerate changed sections | §19 |
| N14 | Three-layer context depth (overview/standard/deep) | Progressive disclosure | §23 |
| N15 | Cross-package context scope | Context spanning multiple packages | §11 |
| N16 | Context quality feedback loop (future) | Self-improving context | CG15 (deferred) |

### Features Intentionally Dropped

| v1 Feature | Why Dropped | Replacement |
|-----------|-------------|-------------|
| JSON file I/O for patterns/constraints | Performance bottleneck | SQLite queries (§18) |
| Separate orchestration/context.ts (~1,500 LOC) | Dual-path architectural debt | Unified engine (§3) |
| Character-based token estimation | 20-40% inaccuracy | BPE tokenization (§8) |
| Greedy section-cutting trimming | Loses high-value items | Proportional allocation (§9) |
| EventEmitter base class | Node.js-specific | tracing spans + ContextWarning (§17) |

**Total: 46 v1 features preserved/upgraded. 0 features lost. 16 new features added.**

---

## 26. Performance Targets

### Benchmarks (criterion)

| Benchmark | Target | v1 Baseline |
|-----------|--------|-------------|
| Package detection (20 packages) | < 100ms | ~200ms |
| Context generation (standard, 50 patterns) | < 50ms | ~535ms |
| Token counting (10KB context) | < 1ms | ~5ms (JSON.stringify) |
| Relevance scoring (100 candidates) | < 5ms | N/A (occurrence sort) |
| Semantic re-ranking (50 candidates) | < 20ms | N/A |
| SQLite query (patterns for 1 package) | < 2ms | ~100ms (JSON files) |
| Full pipeline (detect + generate + format) | < 100ms | ~535ms (medium) |
| Session deduplication check | < 1ms | N/A |
| Cache lookup (hit) | < 0.1ms | N/A |

### Performance Improvement Summary

| Operation | v1 | v2 Target | Improvement |
|-----------|-----|-----------|-------------|
| Data access (20 packages) | ~300ms | ~6ms | 50x |
| Token estimation | ~5ms (inaccurate) | ~1ms (accurate) | 5x + accuracy |
| Full pipeline (medium project) | ~535ms | ~50ms | 10x |
| Full pipeline (large project) | ~2.5s | ~100ms | 25x |

---

## 27. Testing Strategy (CG18)

### Layer 1 — Property-Based Tests (proptest)

| Subsystem | Properties |
|---|---|
| Token counting | `count(a + b) <= count(a) + count(b) + 1`. `count("") == 0`. Cached == uncached. |
| Budget allocation | `sum(section_budgets) <= total_budget`. No section budget negative. Redistribution ≤ total. |
| Trimming | `output_tokens <= maxTokens`. Higher-scored items survive over lower-scored. Deterministic. |
| Relevance scoring | `score ∈ [0.0, 2.0]`. Intent weight changes ranking. Same inputs → same scores. |
| Package detection | Deterministic. Root fallback always returns ≥ 1 package. |
| Session dedup | Second request tokens < first request tokens (same scope, same session). |
| Layered context | `tokens(overview) < tokens(standard) < tokens(deep)`. Subset relationships hold. |
| Freshness | `staleness` consistent with source ages. `Fresh` implies all sources < 1 hour. |
| Degradation | Every component failure → `ContextWarning`, not panic. Output always non-empty. |

### Layer 2 — Golden Dataset Tests (insta snapshots)

- 5 package detection scenarios: npm monorepo, Python poetry, Go modules, polyglot, single root
- 5 context generation scenarios: one per intent type with known expected top patterns
- 3 trimming scenarios: over budget by 10%, 50%, 200%
- 3 session dedup scenarios: first request, follow-up same intent, follow-up different intent
- 3 depth scenarios: overview, standard, deep for same package

Golden datasets in `crates/drift-context/test-fixtures/`.

### Layer 3 — Performance Benchmarks (criterion)

All benchmarks from §26. Regressions > 20% fail the build.

### Layer 4 — Integration Tests

- Full pipeline: detect → generate → verify budget → verify format
- Multi-intent: same package, different intents → different top patterns
- Session flow: 3 sequential requests → verify dedup → verify savings
- Degradation: disable each data source → verify context still generates with warnings
- Cross-package: context spanning 2 dependent packages → verify dependency patterns

---

## 28. Build Order

### Phase 1: Foundation (Week 1)
1. `Cargo.toml` + crate scaffold
2. `request.rs` + `response.rs` — all type definitions
3. `budget/token_counter.rs` — BPE token counting with tiktoken-rs
4. `degradation.rs` — ContextWarning, PipelineResult
5. Verify: token counting works, types compile

### Phase 2: Package Detection (Week 2)
6. `package/managers/mod.rs` — PackageManagerDetector trait
7. `package/managers/npm.rs` through `package/managers/root_fallback.rs` — all 15 detectors
8. `package/detector.rs` — PackageDetector with caching
9. `package/lookup.rs` — 4-strategy package resolution
10. `package/graph.rs` — PackageDependencyGraph
11. Verify: detect packages in test fixtures, graph construction

### Phase 3: Scoring & Ranking (Week 3)
12. `scoring/relevance.rs` — base_relevance_score, file_proximity
13. `scoring/intent_weights.rs` — weight tables for 6 intents
14. `budget/allocator.rs` — proportional budget allocation
15. `budget/trimmer.rs` — relevance-aware within-section trimming
16. Verify: scoring produces expected rankings, budget invariants hold

### Phase 4: Core Engine (Week 4)
17. `engine.rs` — ContextEngine with 7-step pipeline
18. SQLite query functions (load_patterns, load_constraints, etc.)
19. `guidance.rs` — guidance synthesis
20. `freshness.rs` — freshness indicators
21. Verify: full pipeline produces valid context from test drift.db

### Phase 5: Formatting & Session (Week 5)
22. `formatting/markdown.rs` — default formatter
23. `formatting/xml.rs` — Claude-optimized formatter
24. `formatting/json.rs` — programmatic formatter
25. `formatting/ordering.rs` — primacy-recency ordering
26. `session.rs` — session tracking + deduplication
27. Verify: all 3 formats produce valid output, session dedup works

### Phase 6: Cache & Cortex (Week 6)
28. `cache.rs` — content-hash cache with LRU eviction
29. Cortex memory integration (retrieve_memories)
30. Semantic re-ranking (Stage 2, optional)
31. Verify: cache hits, Cortex memories appear in context

### Phase 7: NAPI & Integration (Week 7)
32. `crates/drift-napi/src/bindings/context.rs` — NAPI functions
33. TypeScript bridge types
34. Integration tests (TS → NAPI → Rust → drift.db → formatted context)
35. Golden dataset tests + property-based tests
36. Performance benchmarks

---

## 29. Integration Points

### Upstream (What Context Generation Consumes)

| Subsystem | What's Consumed | How (v2) |
|-----------|----------------|----------|
| 03-detectors | Pattern data | SQLite: `SELECT FROM patterns WHERE package_scope = ?` |
| 04-call-graph | Entry points, function data | SQLite: `SELECT FROM functions WHERE type IN (...)` |
| 07-boundaries | Data accessors, sensitive fields | SQLite: `SELECT FROM data_access_points` |
| 18-constraints | Constraint data | SQLite: `SELECT FROM constraints WHERE package_scope = ?` |
| 06-cortex | Memory retrieval | Cortex API: `retrieve_memories(scope, intent, limit)` |
| 02-storage | Database connections | `DatabaseManager.read_connection()` |
| Package manifests | Package detection | Direct filesystem reads (package.json, Cargo.toml, etc.) |

### Downstream (What Consumes Context Generation)

| Consumer | Interface | Data |
|----------|-----------|------|
| MCP `drift_context` | `ContextEngine.generate(request)` via NAPI | `ContextResult` |
| MCP `drift_package_context` | `ContextEngine.generate(request)` via NAPI | `ContextResult` |
| MCP `drift_capabilities` | `PackageDetector.detect()` via NAPI | `MonorepoStructure` |
| CLI `drift context` | `ContextEngine.generate(request)` direct | `ContextResult` |
| Quality gates | Package detection for scope resolution | `DetectedPackage` |

### Cross-Cutting

| Concern | Implementation |
|---------|---------------|
| Caching | Content-hash LRU cache (§19), 100 entries, 5-min TTL |
| Token management | BPE counting via tiktoken-rs (§8) |
| Error handling | ContextError enum with NAPI error codes (§24) |
| Logging | tracing spans for pipeline steps |
| Metrics | Generation time, cache hit rate, token accuracy |
| Concurrency | Read-only SQLite connections (WAL mode), Mutex for cache/session |

---

## 30. Summary of All Decisions

| Decision | Choice | Confidence | Source |
|----------|--------|------------|--------|
| Merge dual context paths | Unified ContextEngine | Very High | Audit L1, CG1 |
| Intent-weighted scoring | 6 intents with category multipliers | High | CG2, v1 drift_context |
| Two-stage relevance scoring | Metadata + optional embedding re-rank | High | CG3, NVIDIA R6 |
| Three-layer depth | overview/standard/deep with subset invariant | High | CG4, Inkeep R13 |
| BPE token counting | tiktoken-rs (cl100k_base / o200k_base) | Very High | CG5, R7 |
| Proportional budget allocation | Per-section budgets with redistribution | High | CG6, R1/R13 |
| Session deduplication | In-memory tracking, 30-min TTL | High | CG7, OpenAI R8 |
| Cortex memory integration | Unified pipeline step, graceful fallback | High | CG8, Anthropic R3 |
| 15 package managers | 11 v1 + Bun, Deno, Swift, Kotlin | High | CG9, R10 |
| Package dependency graph | BFS-based, in-memory, distance weighting | High | CG10, Nx R9 |
| SQLite data access | Indexed queries replacing JSON file I/O | Very High | CG11, R4 |
| Model-aware formatting | markdown (default), XML (Claude), JSON | High | CG12, Phil Schmid R21 |
| Freshness indicators | Per-source timestamps + staleness classification | High | CG13, Comet R20 |
| Content-hash cache | LRU, 100 entries, 5-min TTL, hash-based keys | High | CG14, Cursor R4 |
| Graceful degradation | Every component has defined fallback | Very High | CG16, Cortex CX18 |
| Strategic ordering | Primacy-recency for transformer attention | High | CG17, NVIDIA R6 |
| Testing strategy | 4 layers: property, golden, benchmark, integration | Very High | CG18, Cortex CX17 |
| Package detection location | Rust (drift-context crate) | High | Performance + consistency |
| Context formatting location | Rust (drift-context crate) | High | Token counting accuracy |
| MCP tool handlers | TypeScript (thin NAPI wrappers) | Very High | MCP is JSON-RPC |
| Total NAPI functions | 3 (generate_context, generate_package_context, list_packages) | High | §22 |
| v1 feature coverage | 46/46 preserved or upgraded, 0 lost | Very High | §25 |
