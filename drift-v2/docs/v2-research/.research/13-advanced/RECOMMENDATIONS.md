# 13 Advanced Systems — V2 Recommendations

## Summary

16 recommendations organized by priority, synthesized from comprehensive analysis of Drift v1's 4 Advanced Systems subsystems (DNA, Decision Mining, Simulation Engine, Language Intelligence) and external research from 40+ authoritative sources. The recommendations address seven critical improvement areas: **convention intelligence** (structural genes, ensemble fingerprinting, graduated scoring), **decision knowledge** (graph-backed storage, NLP extraction, ADR lifecycle), **simulation fidelity** (6-dimensional scoring, fitness functions, incremental caching), **cross-language normalization** (Generic AST layer, declarative framework mappings, expanded language coverage), **Rust migration** (parallel gene extraction, git2 integration, RegexSet optimization), **enterprise metrics** (DORA-adjacent convention health, maturity scorecards, trend tracking), and **cross-subsystem integration** (shared knowledge graph, event-driven data flow, unified query API). Combined, these changes transform Drift's Advanced Systems from a capable TypeScript prototype into an enterprise-grade intelligence layer that provides unique, defensible capabilities no competitor offers.

---

## Recommendations

### R1: Declarative Gene Definitions with TOML Configuration

**Priority**: P0 (Critical — foundational for all DNA improvements)
**Effort**: Medium
**Impact**: Enables community gene contributions, eliminates hardcoded extractors, unlocks gene expansion without code changes

**Current State (v1)**:
Each gene is a dedicated TypeScript class (e.g., `VariantHandlingExtractor`, `ApiResponseFormatExtractor`) with hardcoded regex patterns, allele definitions, and extraction logic. Adding a new gene requires writing a new class, registering it, and redeploying. The 10 existing genes are frozen in code — no user customization, no community contributions.

**Proposed Change**:
Define genes as declarative TOML files. Each gene file specifies: gene ID, display name, category (frontend/backend/infra/testing), allele definitions with regex patterns, and scoring weights. The Rust extraction engine loads these definitions at startup and executes them generically.

```toml
[gene]
id = "api-response-format"
name = "API Response Format"
category = "backend"
description = "How API responses are structured and returned"
version = "1.0.0"

[gene.config]
min_files_for_significance = 3
file_patterns = ["**/*.ts", "**/*.js", "**/*.py", "**/*.java"]
exclude_patterns = ["**/*.test.*", "**/*.spec.*"]

[[gene.alleles]]
id = "envelope-pattern"
name = "Envelope Pattern"
description = "Wraps responses in { data, error, meta } structure"
patterns = [
  '(success|data|error|meta)\s*[:=]',
  'ResponseEnvelope|ApiResponse|BaseResponse',
  '\{\s*data\s*[:=].*error\s*[:=]',
]
match_mode = "any"  # any pattern match counts

[[gene.alleles]]
id = "direct-return"
name = "Direct Return"
description = "Returns data directly without wrapper"
patterns = [
  'return\s+res\.(json|send)\(',
  'return\s+\{(?!.*(?:data|error|meta)\s*:)',
  'JSONResponse\(',
]
match_mode = "any"

[[gene.alleles]]
id = "status-code-driven"
name = "Status Code Driven"
description = "Uses HTTP status codes as primary response signal"
patterns = [
  'res\.status\(\d+\)',
  'HttpStatus\.\w+',
  'status_code\s*=\s*\d+',
]
match_mode = "any"
```

**Rust Implementation**:
```rust
use serde::Deserialize;
use regex::RegexSet;

#[derive(Deserialize)]
struct GeneDefinition {
    gene: GeneMetadata,
    #[serde(default)]
    alleles: Vec<AlleleDefinition>,
}

#[derive(Deserialize)]
struct AlleleDefinition {
    id: String,
    name: String,
    patterns: Vec<String>,
    match_mode: MatchMode,  // Any, All, Threshold(f64)
}

struct CompiledGene {
    meta: GeneMetadata,
    alleles: Vec<CompiledAllele>,
}

struct CompiledAllele {
    id: String,
    name: String,
    regex_set: RegexSet,  // All patterns compiled into single RegexSet
    match_mode: MatchMode,
}

impl CompiledGene {
    fn from_definition(def: GeneDefinition) -> Result<Self> {
        let alleles = def.alleles.into_iter()
            .map(|a| CompiledAllele {
                id: a.id,
                name: a.name,
                regex_set: RegexSet::new(&a.patterns)?,
                match_mode: a.match_mode,
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { meta: def.gene, alleles })
    }

    fn extract(&self, content: &str) -> Vec<DetectedAllele> {
        self.alleles.iter()
            .filter(|allele| allele.matches(content))
            .map(|allele| DetectedAllele {
                gene_id: self.meta.id.clone(),
                allele_id: allele.id.clone(),
                // ... confidence, location
            })
            .collect()
    }
}
```

**Gene Expansion Plan (enabled by declarative definitions)**:

| Tier | New Genes | Category |
|------|-----------|----------|
| Launch | database-access-pattern, auth-pattern, testing-pattern, di-pattern, middleware-pattern | Backend |
| Launch | component-composition, state-management, data-fetching | Frontend |
| 3 months | error-boundary-pattern, logging-strategy, config-management, api-versioning | Backend |
| 6 months | Community-contributed genes via `.drift/genes/` directory | All |

**Rationale**:
Semgrep's success is built on declarative YAML rules — developers write patterns in a familiar format, not code. Flyway uses TOML-based regex rules for the same reason. Declarative definitions separate the "what to detect" from the "how to detect," enabling non-Rust-developers to contribute genes. This is the single most important architectural decision for the DNA system's long-term growth.

**Evidence**:
- Semgrep rule syntax (Research §4.2): Declarative YAML rules are the industry standard for pattern definition
- Flyway regex rules (Research search): TOML-based rule definitions for code analysis
- Convention consistency research (Research §1.3): More genes = more comprehensive convention measurement

**Risks**:
- TOML expressiveness may be insufficient for complex extraction logic (mitigate: allow inline Lua/Rhai scripts for advanced cases)
- Regex-only detection misses structural patterns (addressed by R2)
- Gene definition versioning needs careful schema evolution strategy

**Dependencies**:
- 01-rust-core: TOML parsing infrastructure (already uses TOML for Cargo)
- 08-storage: Gene definition loading and caching
- 12-infrastructure: Gene distribution mechanism for community genes

---

### R2: Structural Gene Extraction via Normalized AST Features

**Priority**: P0 (Critical — addresses the biggest accuracy gap in DNA)
**Effort**: High
**Impact**: 10x improvement in convention detection accuracy; enables detection of patterns invisible to regex

**Current State (v1)**:
All 10 gene extractors use regex-only detection. This misses: multi-line patterns, patterns with variable names changed, structural patterns (function decomposition style, error handling structure, module organization), and any pattern requiring AST awareness. The research (§1.1, §1.2) conclusively shows that structural features are more stable and meaningful than surface-level regex matches.

**Proposed Change**:
Add a second extraction tier alongside regex: tree-sitter query-based structural extraction. Each gene definition can specify both regex patterns (fast, surface-level) and tree-sitter queries (precise, structural). The extraction engine runs both and combines results with configurable weighting.

**Extended TOML Definition (building on R1)**:
```toml
[gene]
id = "error-handling-pattern"
name = "Error Handling Pattern"
category = "backend"

[[gene.alleles]]
id = "try-catch-rethrow"
name = "Try-Catch with Rethrow"
patterns = ['try\s*\{', 'catch\s*\(']  # Regex tier (fast)

[gene.alleles.structural]
language = "typescript"
query = """
(try_statement
  handler: (catch_clause
    body: (statement_block
      (throw_statement) @rethrow)))
"""
weight = 0.7  # Structural match weighted higher than regex

[[gene.alleles]]
id = "result-type"
name = "Result/Either Type"
patterns = ['Result<', 'Either<', 'Ok\(', 'Err\(']

[gene.alleles.structural]
language = "rust"
query = """
(call_expression
  function: (field_expression
    field: (field_identifier) @method
    (#match? @method "^(map_err|unwrap_or|and_then)$")))
"""
weight = 0.7
```

**Rust Implementation**:
```rust
use tree_sitter::{Query, QueryCursor};

struct StructuralExtractor {
    queries: HashMap<Language, Vec<CompiledQuery>>,
}

struct CompiledQuery {
    allele_id: String,
    query: Query,
    weight: f64,
}

impl StructuralExtractor {
    fn extract(&self, tree: &Tree, language: Language, source: &[u8])
        -> Vec<StructuralMatch>
    {
        let queries = match self.queries.get(&language) {
            Some(q) => q,
            None => return vec![],  // No structural queries for this language
        };

        let mut cursor = QueryCursor::new();
        let mut matches = Vec::new();

        for compiled in queries {
            let query_matches = cursor.matches(
                &compiled.query, tree.root_node(), source
            );
            for m in query_matches {
                matches.push(StructuralMatch {
                    allele_id: compiled.allele_id.clone(),
                    weight: compiled.weight,
                    node: m.captures[0].node,
                });
            }
        }
        matches
    }
}
```

**Ensemble Scoring (combining regex + structural)**:
```rust
fn combine_extraction_results(
    regex_matches: &[DetectedAllele],
    structural_matches: &[StructuralMatch],
    config: &EnsembleConfig,
) -> Vec<DetectedAllele> {
    // Merge by allele_id
    // If both regex and structural match: confidence = max(regex, structural * weight)
    // If only regex: confidence = regex_confidence * 0.6
    // If only structural: confidence = structural_confidence * 0.9
    // Structural matches are more reliable, hence higher base confidence
}
```

**Rationale**:
The research is unambiguous: structural patterns (control flow, nesting depth, function decomposition) are more stable indicators of team conventions than surface-level patterns (Research §1.2). CEBin's ensemble approach (Research §1.1) shows that combining multiple similarity measures consistently outperforms any single measure. Tree-sitter queries are already in Drift's Rust core — this extends their use to gene extraction.

**Evidence**:
- CEBin (Research §1.1): Ensemble of structural + lexical features outperforms either alone
- Structural authorship attribution (Research §1.2): Structural patterns are remarkably stable fingerprints
- YASA UAST (Research §4.1): Unified AST enables cross-language structural analysis

**Risks**:
- Tree-sitter queries are language-specific (need per-language query variants)
- Structural extraction is slower than regex (mitigate: run in parallel, cache results)
- Query authoring requires tree-sitter expertise (mitigate: provide query templates and documentation)

**Dependencies**:
- 01-rust-core: Tree-sitter integration already exists; needs query compilation API
- 02-parsers: AST must be available for structural extraction (already parsed for other subsystems)
- R1: Declarative gene definitions must support structural query sections

---

### R3: Graduated Dominance Thresholds and Cross-Gene Consistency

**Priority**: P0 (Critical — fixes fundamental scoring accuracy)
**Effort**: Low
**Impact**: More meaningful health scores; eliminates false confidence from weak dominance

**Current State (v1)**:
Dominance is binary: an allele with >=30% frequency becomes dominant. A gene with 31% dominance and one with 95% dominance are treated identically in health scoring. Health score treats each gene independently — a codebase consistent across ALL genes doesn't score higher than one with mixed consistency.

**Proposed Change**:
Three improvements:

**1. Graduated Dominance Tiers**:
```rust
enum DominanceTier {
    Weak,       // 30-59% — convention exists but not established
    Moderate,   // 60-79% — convention is established
    Strong,     // 80-94% — convention is well-established
    Dominant,   // 95%+   — convention is near-universal
}

impl DominanceTier {
    fn weight(&self) -> f64 {
        match self {
            Self::Weak => 0.3,
            Self::Moderate => 0.6,
            Self::Strong => 0.85,
            Self::Dominant => 1.0,
        }
    }
}
```

**2. Cross-Gene Consistency Score**:
```rust
fn cross_gene_consistency(genes: &[Gene]) -> f64 {
    // A codebase where ALL genes are consistent is healthier
    // than one where some genes are consistent and others aren't
    let tier_counts: HashMap<DominanceTier, usize> = genes.iter()
        .filter_map(|g| g.dominant_allele.as_ref())
        .map(|a| a.dominance_tier())
        .fold(HashMap::new(), |mut m, t| { *m.entry(t).or_default() += 1; m });

    let total = genes.len() as f64;
    let strong_or_dominant = (tier_counts.get(&Strong).unwrap_or(&0)
        + tier_counts.get(&Dominant).unwrap_or(&0)) as f64;

    // Cross-gene consistency: what fraction of genes have strong+ dominance?
    strong_or_dominant / total
}
```

**3. Revised Health Score Formula**:
```rust
fn calculate_health_score(genes: &[Gene], mutations: &[Mutation]) -> HealthScore {
    let gene_consistency = genes.iter()
        .map(|g| g.consistency * g.dominant_tier().weight())
        .sum::<f64>() / genes.len() as f64;

    let cross_gene = cross_gene_consistency(genes);

    let mutation_penalty = calculate_mutation_penalty(mutations);

    let coverage = genes.iter()
        .filter(|g| g.dominant_allele.is_some())
        .count() as f64 / genes.len() as f64;

    // Revised weights: cross-gene consistency is now a factor
    let score = gene_consistency * 0.30      // Per-gene consistency (was 0.40)
        + cross_gene * 0.20                   // Cross-gene consistency (NEW)
        + (1.0 - mutation_penalty) * 0.20     // Mutation penalty (unchanged)
        + coverage * 0.15                     // Gene coverage (was 0.10)
        + avg_confidence(genes) * 0.15;       // Confidence (was 0.30)

    HealthScore {
        total: (score * 100.0).round().clamp(0.0, 100.0) as u8,
        breakdown: HealthBreakdown {
            gene_consistency,
            cross_gene_consistency: cross_gene,
            mutation_penalty,
            coverage,
            confidence: avg_confidence(genes),
        },
    }
}
```

**Rationale**:
The convention consistency research (Research §1.3) establishes that convention strength should be graduated, not binary. A 95% dominant pattern is qualitatively different from a 61% dominant pattern. Cross-gene consistency captures a dimension v1 completely misses: overall codebase coherence. Cortex.io's maturity scorecards (Research §3.1) use tiered levels for exactly this reason.

**Evidence**:
- Convention consistency as quality dimension (Research §1.3): Graduated thresholds are more meaningful
- Cortex.io scorecards (Research §3.1): Tiered maturity levels (bronze/silver/gold)
- Hindle et al. "Naturalness of Software" (Research §1.3): Statistical regularity strength matters

**Risks**:
- Changing the health score formula breaks comparisons with v1 scores (acceptable for greenfield v2)
- Cross-gene consistency penalizes codebases with few genes analyzed (mitigate: require minimum 5 genes for cross-gene scoring)

**Dependencies**:
- R1: Gene definitions determine which genes are analyzed
- 08-storage: Health score schema changes for new breakdown fields
- 09-quality-gates: Quality gates consuming health scores need updated thresholds

---

### R4: Knowledge Graph-Backed Decision Storage

**Priority**: P0 (Critical — foundational for decision mining value)
**Effort**: High
**Impact**: Enables temporal queries, decision traceability, cross-subsystem knowledge sharing

**Current State (v1)**:
Decision mining produces `MinedDecision[]` as in-memory results. No persistent storage. No linking between decisions and code locations. No temporal queries. No integration with Cortex memory. Decisions are computed on-demand and discarded — the most expensive analysis in Drift produces ephemeral results.

**Proposed Change**:
Store mined decisions as first-class entities in a graph-backed knowledge store (SQLite with adjacency lists, not a full graph database — pragmatic for CLI tool distribution). Decisions link to: files, functions, patterns, commits, other decisions (supersedes/reverses), and time.

**Schema Design**:
```sql
-- Core decision entity
CREATE TABLE decisions (
    id TEXT PRIMARY KEY,           -- SHA-256 hash
    title TEXT NOT NULL,
    category TEXT NOT NULL,        -- 12 categories
    status TEXT NOT NULL DEFAULT 'draft',  -- draft, confirmed, superseded, rejected
    confidence TEXT NOT NULL,      -- high, medium, low
    confidence_score REAL,         -- 0.0-1.0 numeric
    summary TEXT,
    context TEXT,                  -- ADR context section
    decision_text TEXT,            -- ADR decision section
    mined_at INTEGER NOT NULL,     -- Unix timestamp
    first_commit_date INTEGER,     -- Earliest commit in cluster
    last_commit_date INTEGER,      -- Latest commit in cluster
    commit_count INTEGER,
    CONSTRAINT valid_category CHECK (category IN (
        'technology-adoption', 'technology-removal', 'pattern-introduction',
        'pattern-migration', 'architecture-change', 'api-change',
        'security-enhancement', 'performance-optimization', 'refactoring',
        'testing-strategy', 'infrastructure', 'other'
    ))
);

-- Decision-to-code location links
CREATE TABLE decision_locations (
    decision_id TEXT NOT NULL REFERENCES decisions(id),
    file_path TEXT NOT NULL,
    function_name TEXT,
    line_start INTEGER,
    line_end INTEGER,
    link_type TEXT NOT NULL,  -- 'introduced', 'affected', 'removed'
    PRIMARY KEY (decision_id, file_path, link_type)
);

-- Decision-to-commit links
CREATE TABLE decision_commits (
    decision_id TEXT NOT NULL REFERENCES decisions(id),
    commit_sha TEXT NOT NULL,
    role TEXT NOT NULL,  -- 'primary', 'supporting', 'evidence'
    PRIMARY KEY (decision_id, commit_sha)
);

-- Decision relationships (supersedes, reverses, extends)
CREATE TABLE decision_relations (
    from_decision TEXT NOT NULL REFERENCES decisions(id),
    to_decision TEXT NOT NULL REFERENCES decisions(id),
    relation_type TEXT NOT NULL,  -- 'supersedes', 'reverses', 'extends', 'conflicts'
    confidence REAL,
    PRIMARY KEY (from_decision, to_decision, relation_type)
);

-- Decision consequences (from ADR)
CREATE TABLE decision_consequences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_id TEXT NOT NULL REFERENCES decisions(id),
    consequence TEXT NOT NULL,
    type TEXT NOT NULL,  -- 'positive', 'negative', 'neutral'
    verified INTEGER DEFAULT 0  -- Has this consequence been observed?
);

-- Decision tags for flexible querying
CREATE TABLE decision_tags (
    decision_id TEXT NOT NULL REFERENCES decisions(id),
    tag TEXT NOT NULL,
    PRIMARY KEY (decision_id, tag)
);

-- Indexes for temporal and spatial queries
CREATE INDEX idx_decisions_category ON decisions(category);
CREATE INDEX idx_decisions_mined_at ON decisions(mined_at);
CREATE INDEX idx_decisions_first_commit ON decisions(first_commit_date);
CREATE INDEX idx_locations_file ON decision_locations(file_path);
CREATE INDEX idx_tags_tag ON decision_tags(tag);
```

**Temporal Query API**:
```rust
pub trait DecisionStore {
    /// Find all decisions affecting a specific file
    fn decisions_for_file(&self, path: &str) -> Result<Vec<Decision>>;

    /// Find all decisions in a time range
    fn decisions_in_range(&self, from: i64, to: i64) -> Result<Vec<Decision>>;

    /// Find decisions that were later reversed or superseded
    fn reversed_decisions(&self) -> Result<Vec<(Decision, Decision)>>;

    /// Find the decision chain for a specific pattern
    fn decision_chain(&self, pattern_id: &str) -> Result<Vec<Decision>>;

    /// Temporal query: "What decisions affected this module in the last N days?"
    fn recent_decisions_for_module(
        &self, module_path: &str, days: u32
    ) -> Result<Vec<Decision>>;

    /// Find decisions by category with optional confidence filter
    fn decisions_by_category(
        &self, category: &str, min_confidence: Option<f64>
    ) -> Result<Vec<Decision>>;
}
```

**Rationale**:
The context graph research (Research §2.2) establishes that decisions need to be linked to entities and time-stamped for temporal queries. Agent Trace (Research §2.2) identifies the core problem: Git captures line differences but throws away all reasoning. Persistent, queryable decision storage transforms decision mining from a one-shot analysis into a living institutional knowledge base. This is the foundation for Cortex memory integration and the "why was this done?" query that no other tool answers.

**Evidence**:
- Context graphs (Research §2.2): Decisions as first-class entities linked to code and time
- Agent Trace (Research §2.2): Capturing reasoning alongside code changes
- MemoriesDB (web search): Temporal-semantic-relational storage for long-term memory
- ADR best practices (Research §2.3): Decisions should survive personnel changes

**Risks**:
- SQLite adds a dependency (mitigate: already recommended for storage layer in category 08)
- Graph queries on adjacency lists are less efficient than native graph DBs (mitigate: codebase-scale graphs are small enough for SQLite)
- Schema evolution needs migration strategy from day one

**Dependencies**:
- 08-storage: SQLite infrastructure (shared with pattern storage, DNA storage)
- 06-cortex: Decision store feeds Cortex memory for AI context
- 07-mcp: MCP tools expose decision queries to AI assistants


---

### R5: Enhanced NLP Extraction with Decision Reversal Detection

**Priority**: P1 (High — significantly improves decision mining quality)
**Effort**: Medium
**Impact**: 3-5x improvement in decision extraction accuracy; detects decision lifecycle events

**Current State (v1)**:
Decision mining uses basic keyword extraction from commit messages ("because", "instead of", "decided to"). No detection of decision reversals (revert commits, pattern migrations back). No mining from PR descriptions or issue trackers. No detection of existing ADR documents in the repository.

**Proposed Change**:
Three-layer extraction enhancement:

**Layer 1 — Enhanced Commit Message NLP**:
```rust
struct CommitMessageAnalyzer {
    decision_patterns: Vec<DecisionPattern>,
    reversal_patterns: Vec<ReversalPattern>,
    conventional_commit_parser: ConventionalCommitParser,
}

struct DecisionPattern {
    id: &'static str,
    regex: Regex,
    category: DecisionCategory,
    confidence_boost: f64,
    examples: Vec<&'static str>,
}

// Validated patterns from academic research (Research §2.1)
const DECISION_PATTERNS: &[DecisionPattern] = &[
    // Explicit decision language
    DecisionPattern {
        id: "explicit-because",
        regex: r"because\s+(?:we|the|it|this)",
        category: DecisionCategory::Any,
        confidence_boost: 0.3,
    },
    DecisionPattern {
        id: "explicit-instead-of",
        regex: r"instead\s+of\s+(?:using|implementing|keeping)",
        category: DecisionCategory::PatternMigration,
        confidence_boost: 0.4,
    },
    DecisionPattern {
        id: "explicit-switched",
        regex: r"switch(?:ed|ing)\s+(?:from|to)\s+\w+",
        category: DecisionCategory::TechnologyAdoption,
        confidence_boost: 0.4,
    },
    // Architectural signals
    DecisionPattern {
        id: "arch-introduce",
        regex: r"introduc(?:e|ed|ing)\s+(?:a\s+)?(?:new\s+)?(?:pattern|approach|strategy|layer|module)",
        category: DecisionCategory::PatternIntroduction,
        confidence_boost: 0.3,
    },
    DecisionPattern {
        id: "arch-deprecate",
        regex: r"deprecat(?:e|ed|ing)\s+(?:the\s+)?(?:old|existing|legacy|current)",
        category: DecisionCategory::TechnologyRemoval,
        confidence_boost: 0.3,
    },
    // Performance decisions
    DecisionPattern {
        id: "perf-optimize",
        regex: r"optimiz(?:e|ed|ing)\s+(?:for|by|the|performance)",
        category: DecisionCategory::PerformanceOptimization,
        confidence_boost: 0.2,
    },
    // Security decisions
    DecisionPattern {
        id: "sec-fix",
        regex: r"(?:fix|patch|address|mitigat)(?:ed|ing|es)?\s+(?:security|vulnerability|CVE|XSS|CSRF|injection)",
        category: DecisionCategory::SecurityEnhancement,
        confidence_boost: 0.4,
    },
];

// Reversal detection patterns
const REVERSAL_PATTERNS: &[ReversalPattern] = &[
    ReversalPattern {
        id: "revert-commit",
        regex: r"^[Rr]evert\s+\"",
        reversal_type: ReversalType::Revert,
        confidence: 0.95,
    },
    ReversalPattern {
        id: "rollback",
        regex: r"roll(?:ing)?\s*back\s+(?:to|the)",
        reversal_type: ReversalType::Rollback,
        confidence: 0.8,
    },
    ReversalPattern {
        id: "undo-change",
        regex: r"undo(?:ing)?\s+(?:the\s+)?(?:previous|last|recent)",
        reversal_type: ReversalType::Undo,
        confidence: 0.7,
    },
    ReversalPattern {
        id: "migration-back",
        regex: r"migrat(?:e|ed|ing)\s+back\s+(?:to|from)",
        reversal_type: ReversalType::MigrationReversal,
        confidence: 0.85,
    },
];
```

**Layer 2 — ADR Document Detection**:
```rust
struct AdrDetector {
    /// Common ADR directory patterns
    adr_paths: Vec<&'static str>,
    /// ADR filename patterns
    adr_patterns: Vec<Regex>,
}

impl AdrDetector {
    fn new() -> Self {
        Self {
            adr_paths: vec![
                "docs/adr/", "docs/decisions/", "docs/architecture/decisions/",
                "adr/", "decisions/", "doc/adr/", "doc/decisions/",
                ".adr/", "architecture/decisions/",
            ],
            adr_patterns: vec![
                Regex::new(r"^\d{4}-.*\.md$").unwrap(),        // 0001-use-react.md
                Regex::new(r"^ADR-\d+.*\.md$").unwrap(),       // ADR-001-use-react.md
                Regex::new(r"^adr-\d+.*\.md$").unwrap(),       // adr-001-use-react.md
                Regex::new(r"^\d{4}-\d{2}-\d{2}-.*\.md$").unwrap(), // 2024-01-15-use-react.md
            ],
        }
    }

    fn detect_adrs(&self, file_paths: &[&str]) -> Vec<DetectedAdr> {
        file_paths.iter()
            .filter(|p| self.is_adr_path(p))
            .map(|p| self.parse_adr(p))
            .collect()
    }

    fn parse_adr(&self, path: &str) -> DetectedAdr {
        // Parse ADR markdown for: Status, Context, Decision, Consequences
        // Link to code locations via file references in ADR content
        // Track ADR lifecycle: proposed -> accepted -> deprecated -> superseded
    }
}
```

**Layer 3 — Conventional Commit Confidence Weighting**:
```rust
fn adjust_confidence_for_commit_quality(
    base_confidence: f64,
    commit: &GitCommit,
) -> f64 {
    let mut multiplier = 1.0;

    // Conventional commits are more reliable signals
    if commit.is_conventional() {
        multiplier *= 1.3;
    }

    // Longer, descriptive messages are more reliable
    if commit.body.as_ref().map_or(false, |b| b.len() > 100) {
        multiplier *= 1.2;
    }

    // Co-authored commits suggest reviewed decisions
    if commit.has_co_authors() {
        multiplier *= 1.1;
    }

    // Signed commits suggest higher-trust changes
    if commit.is_signed() {
        multiplier *= 1.05;
    }

    (base_confidence * multiplier).min(1.0)
}
```

**Rationale**:
DRMiner (Research §2.1) demonstrates that NLP heuristics can extract design rationale from developer discussions with high accuracy. The academic research provides validated patterns for decision-bearing sentences. ADR detection fills a critical gap — many teams already document decisions but Drift v1 ignores them. Conventional commit weighting leverages structured signals that are inherently more reliable.

**Evidence**:
- DRMiner (Research §2.1): Automated extraction of developer rationale from issue logs
- Automated rationale extraction (Research §2.1): NLP heuristics for decision-bearing sentences
- Conventional Commits (Research §2.3): Structured commit messages as reliable decision signals
- Microsoft ADR practices (Research §2.3): ADRs should live next to code in the repository

**Risks**:
- NLP heuristics produce false positives (mitigate: confidence scoring filters noise)
- ADR format varies across teams (mitigate: support multiple common formats)
- Reversal detection may flag intentional rollbacks as failures (mitigate: distinguish planned vs unplanned reversals)

**Dependencies**:
- R4: Decision storage must support reversal relationships and ADR links
- 01-rust-core: Regex infrastructure for pattern matching
- Git integration: Commit message access (git2 in Rust)

---

### R6: Six-Dimensional Simulation Scoring

**Priority**: P1 (High — addresses two missing quality dimensions)
**Effort**: Medium
**Impact**: More accurate simulation recommendations; catches test coverage and complexity risks

**Current State (v1)**:
Simulation scores across 4 dimensions: friction (30%), impact (25%), pattern alignment (30%), security (15%). Missing: test coverage impact and complexity change. A simulation might recommend an approach that reduces test coverage or dramatically increases cyclomatic complexity — v1 wouldn't flag this.

**Proposed Change**:
Add two new scoring dimensions and rebalance weights:

**New Dimension: Test Coverage Impact Scorer**:
```rust
struct TestCoverageScorer {
    test_mapping: Option<TestFileMapping>,  // From test topology
}

struct TestCoverageMetrics {
    score: f64,                    // 0.0-1.0
    affected_files_with_tests: usize,
    affected_files_without_tests: usize,
    test_coverage_ratio: f64,      // Files with tests / total affected files
    estimated_new_tests_needed: usize,
    risk_level: RiskLevel,
    warnings: Vec<String>,
}

impl TestCoverageScorer {
    fn score(&self, approach: &SimulationApproach) -> TestCoverageMetrics {
        let affected_files = &approach.target_files;
        let new_files = approach.new_files.as_ref().map_or(0, |f| f.len());

        let (with_tests, without_tests) = match &self.test_mapping {
            Some(mapping) => {
                let with = affected_files.iter()
                    .filter(|f| mapping.has_test_for(f))
                    .count();
                (with, affected_files.len() - with)
            }
            None => (0, affected_files.len()),  // No test mapping = worst case
        };

        let coverage_ratio = if affected_files.is_empty() {
            1.0
        } else {
            with_tests as f64 / affected_files.len() as f64
        };

        // Score: high coverage ratio = good, new files without tests = bad
        let base_score = coverage_ratio;
        let new_file_penalty = (new_files as f64 * 0.1).min(0.3);
        let score = (base_score - new_file_penalty).max(0.0);

        TestCoverageMetrics {
            score,
            affected_files_with_tests: with_tests,
            affected_files_without_tests: without_tests,
            test_coverage_ratio: coverage_ratio,
            estimated_new_tests_needed: without_tests + new_files,
            risk_level: RiskLevel::from_score(score),
            warnings: self.generate_warnings(coverage_ratio, new_files),
        }
    }
}
```

**New Dimension: Complexity Change Scorer**:
```rust
struct ComplexityScorer;

struct ComplexityMetrics {
    score: f64,                    // 0.0-1.0
    estimated_complexity_delta: i32,  // Positive = more complex
    affected_function_count: usize,
    new_function_count: usize,
    nesting_depth_increase: u8,
    risk_level: RiskLevel,
    warnings: Vec<String>,
}

impl ComplexityScorer {
    fn score(&self, approach: &SimulationApproach) -> ComplexityMetrics {
        // Estimate complexity based on approach strategy
        let strategy_complexity = match approach.strategy {
            Strategy::Centralized => 0.8,   // Low complexity (one place)
            Strategy::Middleware => 0.7,     // Low-medium
            Strategy::Decorator => 0.7,     // Low-medium
            Strategy::Distributed => 0.3,   // High complexity (many places)
            Strategy::Custom => 0.4,        // High complexity (novel code)
            Strategy::PerRoute => 0.4,      // High complexity (repetitive)
            _ => 0.5,
        };

        let file_count_factor = match approach.target_files.len() {
            0..=2 => 1.0,
            3..=5 => 0.9,
            6..=10 => 0.7,
            _ => 0.5,
        };

        let new_file_factor = match approach.new_files.as_ref().map_or(0, |f| f.len()) {
            0 => 1.0,
            1 => 0.9,
            2..=3 => 0.7,
            _ => 0.5,
        };

        let score = strategy_complexity * 0.5
            + file_count_factor * 0.3
            + new_file_factor * 0.2;

        ComplexityMetrics {
            score,
            estimated_complexity_delta: self.estimate_delta(approach),
            affected_function_count: approach.target_functions
                .as_ref().map_or(0, |f| f.len()),
            new_function_count: approach.estimated_lines_added
                .map_or(0, |l| l / 20),  // Rough estimate: 1 function per 20 lines
            nesting_depth_increase: self.estimate_nesting(approach),
            risk_level: RiskLevel::from_score(score),
            warnings: vec![],
        }
    }
}
```

**Rebalanced Composite Score**:
```rust
fn composite_score(
    friction: f64,
    impact: f64,
    alignment: f64,
    security: f64,
    test_coverage: f64,
    complexity: f64,
) -> f64 {
    // Rebalanced weights (sum = 1.0)
    friction    * 0.20  // Was 0.30 — reduced to make room
    + impact      * 0.20  // Was 0.25 — slightly reduced
    + alignment   * 0.25  // Was 0.30 — slightly reduced
    + security    * 0.15  // Unchanged
    + test_coverage * 0.10  // NEW
    + complexity  * 0.10  // NEW
}
```

**Rationale**:
Cortex.io's production readiness research (Research §3.1) establishes that multi-dimensional scoring is the industry standard. Test coverage and complexity are universally recognized quality dimensions (Research §5.1). Missing these dimensions means simulation can recommend approaches that degrade code quality in ways v1 doesn't detect.

**Evidence**:
- Cortex.io scorecards (Research §3.1): Multi-dimensional scoring across security, reliability, testing, performance
- Code quality metrics (Research §5.1): Test coverage (80% target) and maintainability index are critical metrics
- Architectural fitness functions (Research §3.2): Complexity is a key fitness function dimension

**Risks**:
- Test coverage scoring requires test mapping data (graceful degradation if unavailable)
- Complexity estimation from approach metadata is approximate (acceptable for pre-flight simulation)
- Rebalancing weights changes existing simulation rankings (acceptable for v2 greenfield)

**Dependencies**:
- 17-test-topology: Test file mapping for coverage scoring
- 04-call-graph: Function-level complexity data
- R7: Fitness function framework can consume these scores

---

### R7: Architectural Fitness Function Framework

**Priority**: P1 (High — transforms simulation from one-shot to continuous)
**Effort**: High
**Impact**: Enables continuous architectural health monitoring; bridges simulation and quality gates

**Current State (v1)**:
Simulation is a one-shot analysis: run it, get results, done. No tracking of fitness function trends over time. No user-defined architectural constraints. No integration with quality gates for CI/CD enforcement.

**Proposed Change**:
Frame simulation results as fitness function evaluations. Allow users to define custom fitness functions declaratively. Track fitness function trends over time. Integrate with quality gates for merge blocking.

**Fitness Function Definition (TOML)**:
```toml
[fitness_function]
id = "api-consistency"
name = "API Consistency"
description = "All API endpoints follow established patterns"
category = "architecture"
threshold = 0.8  # Minimum passing score
trend_window = 30  # Days to track trend

[[fitness_function.checks]]
type = "pattern-alignment"
description = "New endpoints must use the established response format"
patterns = ["api-response-format", "error-response-format"]
min_alignment = 0.9

[[fitness_function.checks]]
type = "convention-compliance"
description = "New code must follow dominant conventions"
genes = ["api-response-format", "error-response-format", "logging-format"]
min_health = 70

[[fitness_function.checks]]
type = "security"
description = "All endpoints must have auth checks"
require_auth = true
exceptions = ["health-check", "public-api"]

[[fitness_function.checks]]
type = "test-coverage"
description = "New endpoints must have integration tests"
min_coverage_ratio = 0.8
```

**Rust Implementation**:
```rust
pub struct FitnessFunction {
    id: String,
    name: String,
    checks: Vec<FitnessCheck>,
    threshold: f64,
    trend_window_days: u32,
}

pub struct FitnessEvaluation {
    function_id: String,
    score: f64,
    passed: bool,
    check_results: Vec<CheckResult>,
    trend: Option<FitnessTrend>,
    evaluated_at: i64,
}

pub struct FitnessTrend {
    direction: TrendDirection,  // Improving, Stable, Degrading
    velocity: f64,              // Rate of change per day
    data_points: Vec<(i64, f64)>,  // (timestamp, score) pairs
}

pub trait FitnessEvaluator {
    fn evaluate(
        &self,
        function: &FitnessFunction,
        context: &EvaluationContext,
    ) -> Result<FitnessEvaluation>;

    fn evaluate_trend(
        &self,
        function_id: &str,
        window_days: u32,
    ) -> Result<FitnessTrend>;
}
```

**Quality Gate Integration**:
```rust
pub struct FitnessGateResult {
    pub passed: bool,
    pub evaluations: Vec<FitnessEvaluation>,
    pub blocking_failures: Vec<FitnessEvaluation>,  // Functions that failed AND are blocking
    pub warnings: Vec<FitnessEvaluation>,            // Functions that failed but non-blocking
    pub trends: Vec<(String, FitnessTrend)>,
}

impl FitnessGate {
    pub fn evaluate_for_merge(&self, changed_files: &[&str]) -> FitnessGateResult {
        // Only evaluate fitness functions relevant to changed files
        let relevant = self.functions.iter()
            .filter(|f| f.is_relevant_to(changed_files))
            .collect::<Vec<_>>();

        let evaluations = relevant.iter()
            .map(|f| self.evaluator.evaluate(f, &self.context))
            .collect::<Result<Vec<_>>>()?;

        let blocking = evaluations.iter()
            .filter(|e| !e.passed && self.is_blocking(&e.function_id))
            .cloned()
            .collect();

        FitnessGateResult {
            passed: blocking.is_empty(),
            evaluations,
            blocking_failures: blocking,
            warnings: evaluations.iter()
                .filter(|e| !e.passed && !self.is_blocking(&e.function_id))
                .cloned()
                .collect(),
            trends: self.get_trends(&relevant),
        }
    }
}
```

**Rationale**:
"Building Evolutionary Architectures" (Research §3.2) establishes fitness functions as the standard for continuous architectural health monitoring. ArchUnit (Research §3.2) proves the concept works in practice. The key insight: architecture is perpetually evolving — fitness functions guard invariants while allowing evolution. This aligns perfectly with Drift's convention-based approach and bridges the gap between simulation (pre-flight) and quality gates (enforcement).

**Evidence**:
- Building Evolutionary Architectures (Research §3.2): Fitness functions as architectural unit tests
- ArchUnit (Research §3.2): Production-proven architectural constraint enforcement
- Cortex.io scorecards (Research §3.1): Tiered maturity levels with trend tracking

**Risks**:
- Fitness function definitions need careful design to avoid being too rigid or too loose
- Trend tracking requires persistent storage (addressed by R4's SQLite infrastructure)
- False blocking in CI/CD can frustrate developers (mitigate: start with warnings, graduate to blocking)

**Dependencies**:
- R6: Six-dimensional scoring provides the data for fitness function checks
- R3: Graduated health scores feed convention compliance checks
- 09-quality-gates: Fitness functions integrate as a new gate type
- 08-storage: Trend data persistence

---

### R8: Generic AST (GAST) Normalization Layer

**Priority**: P1 (High — foundational for cross-language intelligence)
**Effort**: High
**Impact**: Enables true cross-language pattern comparison; extends normalization beyond decorators

**Current State (v1)**:
Language Intelligence normalizes decorators/annotations to a common semantic model — a lightweight form of UAST. But normalization stops at decorators. Function signatures, class hierarchies, module structures, error handling patterns, and control flow are NOT normalized. This means cross-language comparison only works for decorator-based patterns.

**Proposed Change**:
Formalize the normalization as a proper Generic AST (GAST) layer, following YASA's approach (Research §4.1) of "unified semantic model for common constructs + language-specific semantic models for unique features." Extend normalization beyond decorators to cover the 6 most valuable construct types.

**GAST Node Types**:
```rust
/// Generic AST — language-agnostic representation of code constructs
pub enum GastNode {
    // Function-level
    Function(GastFunction),
    Method(GastMethod),
    Constructor(GastConstructor),

    // Class-level
    Class(GastClass),
    Interface(GastInterface),
    Enum(GastEnum),

    // Module-level
    Import(GastImport),
    Export(GastExport),
    Module(GastModule),

    // Decorator/Annotation
    Decorator(GastDecorator),  // Existing normalization, formalized

    // Error handling
    TryCatch(GastTryCatch),
    ErrorType(GastErrorType),

    // Type system
    TypeDefinition(GastTypeDefinition),
    GenericParameter(GastGenericParameter),
}

pub struct GastFunction {
    pub name: String,
    pub visibility: Visibility,       // Public, Private, Protected, Internal
    pub is_async: bool,
    pub is_static: bool,
    pub parameters: Vec<GastParameter>,
    pub return_type: Option<GastType>,
    pub decorators: Vec<GastDecorator>,
    pub semantics: FunctionSemantics,  // Existing semantic classification
    pub body_complexity: u32,          // Cyclomatic complexity
    pub line_count: u32,
}

pub struct GastParameter {
    pub name: String,
    pub type_annotation: Option<GastType>,
    pub default_value: bool,           // Has default?
    pub is_variadic: bool,
    pub decorators: Vec<GastDecorator>,  // Parameter decorators (@Body, @Query, etc.)
}

pub struct GastClass {
    pub name: String,
    pub visibility: Visibility,
    pub is_abstract: bool,
    pub superclass: Option<String>,
    pub interfaces: Vec<String>,
    pub decorators: Vec<GastDecorator>,
    pub methods: Vec<GastMethod>,
    pub properties: Vec<GastProperty>,
    pub constructor: Option<GastConstructor>,
}

pub struct GastImport {
    pub source: String,              // Module path
    pub specifiers: Vec<ImportSpecifier>,
    pub is_type_only: bool,          // TypeScript `import type`
    pub import_style: ImportStyle,   // Named, Default, Namespace, SideEffect
}

pub enum ImportStyle {
    Named,      // import { foo } from 'bar'  /  from bar import foo
    Default,    // import foo from 'bar'  /  import bar
    Namespace,  // import * as foo from 'bar'
    SideEffect, // import 'bar'  /  import bar (Python)
}
```

**Language-Specific Translators**:
```rust
pub trait GastTranslator {
    fn language(&self) -> Language;
    fn translate_function(&self, node: &Node, source: &[u8]) -> Option<GastFunction>;
    fn translate_class(&self, node: &Node, source: &[u8]) -> Option<GastClass>;
    fn translate_import(&self, node: &Node, source: &[u8]) -> Option<GastImport>;
    fn translate_decorator(&self, node: &Node, source: &[u8]) -> Option<GastDecorator>;
    fn translate_error_handling(&self, node: &Node, source: &[u8]) -> Option<GastTryCatch>;
}

// Each language implements GastTranslator
struct TypeScriptTranslator;
struct PythonTranslator;
struct JavaTranslator;
struct RustTranslator;    // NEW in v2
struct GoTranslator;      // NEW in v2
struct CSharpTranslator;
struct PhpTranslator;
struct CppTranslator;     // NEW in v2
```

**Rationale**:
YASA (Research §4.1) validates the UAST approach at 100M+ lines across 7,300 applications. MLCPD (Research §4.1) demonstrates that cross-language structural regularities exist — syntactic graphs from Python, Java, and Go can be aligned under a shared schema. Semgrep's ast_generic (Research §4.2) is the most production-proven implementation. Drift v2's GAST doesn't need to be as comprehensive as Semgrep's — it needs to cover the 6 construct types that matter for convention analysis.

**Evidence**:
- YASA UAST (Research §4.1): Unified AST at 100M+ line scale, 92 confirmed 0-day vulnerabilities found
- MLCPD (Research §4.1): 7M+ files normalized under universal AST schema
- Semgrep ast_generic (Research §4.2): 30+ languages with single analysis engine

**Risks**:
- GAST design is a critical architectural decision — getting it wrong affects all downstream consumers
- Language-specific nuances may not map cleanly (mitigate: YASA's "unified + language-specific" approach)
- Maintaining translators for 8 languages is significant ongoing effort

**Dependencies**:
- 01-rust-core: Tree-sitter parsers for all supported languages
- 02-parsers: GAST sits between parsing and analysis
- R2: Structural gene extraction consumes GAST nodes
- 04-call-graph: Call graph can be built from GAST function/method nodes


---

### R9: Declarative Framework Mappings with Plugin Architecture

**Priority**: P1 (High — enables framework coverage expansion without code changes)
**Effort**: Medium
**Impact**: Unlocks community framework contributions; expands from 5 to 20+ frameworks

**Current State (v1)**:
Framework patterns are hardcoded in TypeScript files (`frameworks/spring.ts`, `frameworks/fastapi.ts`, etc.). Adding a new framework requires writing a new TypeScript file, implementing decorator mappings, and redeploying. Only 5 frameworks supported. Missing: Go frameworks (Gin, Echo, Fiber), Rust frameworks (Actix, Axum, Rocket), Django REST Framework, Quarkus, Micronaut, and many more.

**Proposed Change**:
Define framework mappings as declarative TOML files. The normalization engine loads these definitions at startup. Users can add custom framework mappings in `.drift/frameworks/` without code changes.

**Framework Definition (TOML)**:
```toml
[framework]
id = "spring-boot"
name = "Spring Boot"
languages = ["java"]
version_range = "2.0-4.0"

[framework.detection]
# How to detect this framework in a project
imports = [
    "org.springframework.boot",
    "org.springframework.web",
]
config_files = ["application.yml", "application.properties"]
build_files = { "pom.xml" = "spring-boot-starter", "build.gradle" = "spring-boot" }

[[framework.decorators]]
pattern = '@(Get|Post|Put|Delete|Patch)Mapping\("([^"]*)"'
semantic.category = "routing"
semantic.is_entry_point = true
extract_args.path = "$2"
extract_args.methods = ["$1"]
confidence = 0.95

[[framework.decorators]]
pattern = '@RequestMapping\((?:value\s*=\s*)?"([^"]*)"(?:,\s*method\s*=\s*RequestMethod\.(\w+))?\)'
semantic.category = "routing"
semantic.is_entry_point = true
extract_args.path = "$1"
extract_args.methods = ["$2"]
confidence = 0.9

[[framework.decorators]]
pattern = '@Service'
semantic.category = "di"
semantic.is_injectable = true
confidence = 0.95

[[framework.decorators]]
pattern = '@Repository'
semantic.category = "orm"
semantic.is_data_accessor = true
confidence = 0.95

[[framework.decorators]]
pattern = '@Autowired'
semantic.category = "di"
semantic.is_dependency = true
confidence = 0.95

[[framework.decorators]]
pattern = '@PreAuthorize\("([^"]*)"\)'
semantic.category = "auth"
semantic.requires_auth = true
extract_args.roles = "$1"
confidence = 0.9

[[framework.decorators]]
pattern = '@Entity'
semantic.category = "orm"
semantic.is_data_accessor = true
confidence = 0.95
```

**New Framework Definitions to Ship with v2**:

| Framework | Language | Priority | Decorator Count |
|-----------|----------|----------|-----------------|
| Spring Boot | Java | Tier 1 (existing) | ~15 |
| FastAPI | Python | Tier 1 (existing) | ~8 |
| NestJS | TypeScript | Tier 1 (existing) | ~12 |
| Laravel | PHP | Tier 1 (existing) | ~8 |
| ASP.NET Core | C# | Tier 1 (existing) | ~10 |
| Django REST Framework | Python | Tier 1 (new) | ~10 |
| Express.js | TypeScript | Tier 1 (new) | ~5 |
| Gin | Go | Tier 2 (new) | ~8 |
| Echo | Go | Tier 2 (new) | ~8 |
| Actix Web | Rust | Tier 2 (new) | ~8 |
| Axum | Rust | Tier 2 (new) | ~6 |
| Quarkus | Java | Tier 2 (new) | ~12 |
| Micronaut | Java | Tier 2 (new) | ~10 |
| Flask | Python | Tier 2 (new) | ~6 |
| Fiber | Go | Tier 3 (new) | ~6 |
| Rocket | Rust | Tier 3 (new) | ~8 |
| Symfony | PHP | Tier 3 (new) | ~10 |
| Phoenix | Elixir | Tier 3 (new) | ~6 |

**Plugin Loading**:
```rust
pub struct FrameworkRegistry {
    builtin: Vec<CompiledFramework>,   // Ship with Drift
    custom: Vec<CompiledFramework>,    // From .drift/frameworks/
}

impl FrameworkRegistry {
    pub fn load(drift_dir: &Path) -> Result<Self> {
        // Load built-in framework definitions from embedded TOML
        let builtin = Self::load_builtin_frameworks()?;

        // Load custom framework definitions from .drift/frameworks/*.toml
        let custom_dir = drift_dir.join("frameworks");
        let custom = if custom_dir.exists() {
            Self::load_custom_frameworks(&custom_dir)?
        } else {
            vec![]
        };

        Ok(Self { builtin, custom })
    }

    pub fn detect_frameworks(&self, project: &ProjectContext) -> Vec<DetectedFramework> {
        self.all_frameworks()
            .filter(|f| f.matches_project(project))
            .map(|f| DetectedFramework {
                framework: f.clone(),
                confidence: f.detection_confidence(project),
                evidence: f.detection_evidence(project),
            })
            .collect()
    }
}
```

**Rationale**:
Semgrep's success (Research §4.2) is built on declarative rule definitions that look like source code. The framework middleware pattern from category 03 recommendations (R11) establishes the architectural precedent. Declarative TOML definitions make framework support a data problem, not a code problem — dramatically lowering the barrier for community contributions and enterprise customization.

**Evidence**:
- Semgrep rule syntax (Research §4.2): Declarative patterns are the industry standard
- Framework detection signals (Research §4.3): Import + decorator + config + directory = high confidence
- Category 03 R11: Framework middleware architecture establishes the pattern

**Risks**:
- TOML regex patterns may not capture all framework nuances (mitigate: allow escape to Rust plugins for complex cases)
- Framework version detection adds complexity (mitigate: version_range is optional)
- Custom framework definitions need validation (mitigate: `drift validate-framework` CLI command)

**Dependencies**:
- R8: GAST layer provides the normalized constructs that framework mappings target
- 01-rust-core: TOML parsing and regex compilation
- 12-infrastructure: Framework definition distribution for community contributions

---

### R10: git2 Integration for High-Performance Decision Mining

**Priority**: P1 (High — 5-10x performance improvement for large repositories)
**Effort**: Medium
**Impact**: Enables decision mining on 100K+ commit repositories; eliminates Node.js bottleneck

**Current State (v1)**:
Decision mining uses `simple-git` (Node.js library) for git operations. For large repositories (10K+ commits), commit walking, diff generation, and blame analysis are slow due to: (1) shelling out to git CLI per operation, (2) JSON serialization overhead across NAPI boundary, (3) no parallel commit analysis.

**Proposed Change**:
Use `git2` (Rust binding for libgit2) for all git operations in the decision mining pipeline. This eliminates CLI overhead, enables parallel commit analysis via rayon, and keeps the entire extraction pipeline in Rust.

**Rust Implementation**:
```rust
use git2::{Repository, Commit, Diff, DiffOptions};
use rayon::prelude::*;

pub struct GitMiner {
    repo_path: PathBuf,
}

pub struct MiningConfig {
    pub since: Option<i64>,        // Unix timestamp
    pub until: Option<i64>,
    pub max_commits: usize,        // Default 1000
    pub exclude_paths: Vec<String>,
    pub exclude_merges: bool,      // Default true
    pub parallel_workers: usize,   // Default: num_cpus
}

impl GitMiner {
    pub fn walk_commits(&self, config: &MiningConfig) -> Result<Vec<MinedCommit>> {
        let repo = Repository::open(&self.repo_path)?;
        let mut revwalk = repo.revwalk()?;
        revwalk.push_head()?;
        revwalk.set_sorting(git2::Sort::TIME)?;

        let commits: Vec<git2::Oid> = revwalk
            .filter_map(|oid| oid.ok())
            .take(config.max_commits)
            .collect();

        // Parallel commit analysis using rayon
        // git2::Repository is not Send, so open per-thread
        let repo_path = self.repo_path.clone();
        let results: Vec<MinedCommit> = commits
            .par_chunks(100)  // Process in chunks of 100
            .flat_map(|chunk| {
                // Open a new Repository per thread (git2 requirement)
                let repo = Repository::open(&repo_path).unwrap();
                chunk.iter()
                    .filter_map(|oid| {
                        let commit = repo.find_commit(*oid).ok()?;
                        if config.exclude_merges && commit.parent_count() > 1 {
                            return None;
                        }
                        if let Some(since) = config.since {
                            if commit.time().seconds() < since {
                                return None;
                            }
                        }
                        Some(self.analyze_commit(&repo, &commit))
                    })
                    .collect::<Vec<_>>()
            })
            .filter_map(|r| r.ok())
            .collect();

        Ok(results)
    }

    fn analyze_commit(
        &self,
        repo: &Repository,
        commit: &Commit,
    ) -> Result<MinedCommit> {
        let parent = commit.parent(0).ok();
        let parent_tree = parent.as_ref().and_then(|p| p.tree().ok());
        let commit_tree = commit.tree()?;

        let mut diff_opts = DiffOptions::new();
        diff_opts.ignore_whitespace(true);

        let diff = repo.diff_tree_to_tree(
            parent_tree.as_ref(),
            Some(&commit_tree),
            Some(&mut diff_opts),
        )?;

        let file_changes = self.extract_file_changes(&diff)?;
        let message = commit.message().unwrap_or("").to_string();
        let semantic = self.extract_semantics(&message, &file_changes)?;

        Ok(MinedCommit {
            sha: commit.id().to_string(),
            message,
            author: commit.author().name().unwrap_or("").to_string(),
            timestamp: commit.time().seconds(),
            file_changes,
            semantic,
        })
    }

    fn extract_file_changes(&self, diff: &Diff) -> Result<Vec<FileChange>> {
        let mut changes = Vec::new();
        diff.foreach(
            &mut |delta, _| {
                changes.push(FileChange {
                    path: delta.new_file().path()
                        .unwrap_or(Path::new(""))
                        .to_string_lossy()
                        .to_string(),
                    status: match delta.status() {
                        git2::Delta::Added => ChangeStatus::Added,
                        git2::Delta::Deleted => ChangeStatus::Deleted,
                        git2::Delta::Modified => ChangeStatus::Modified,
                        git2::Delta::Renamed => ChangeStatus::Renamed,
                        _ => ChangeStatus::Other,
                    },
                    additions: 0,  // Updated in hunk callback
                    deletions: 0,
                });
                true
            },
            None, None, None,
        )?;
        Ok(changes)
    }
}
```

**Performance Comparison**:

| Operation | simple-git (v1) | git2 (v2) | Speedup |
|-----------|----------------|-----------|---------|
| Walk 10K commits | ~5-10s | ~0.5-1s | 5-10x |
| Generate diffs (10K) | ~30-60s | ~3-6s | 10x |
| Parallel analysis | Not possible | 4-8 threads | 4-8x |
| Total pipeline (10K) | ~2-5 min | ~10-30s | 10-20x |

**Rationale**:
git2/libgit2 is the standard for programmatic Git access (Research §6.1). The performance improvement is critical for enterprise repositories with 100K+ commits. Parallel commit analysis via rayon (web search: rayon data parallelism) enables linear scaling with CPU cores. Keeping the entire extraction pipeline in Rust eliminates NAPI serialization overhead.

**Evidence**:
- git2 crate (Research §6.1): Standard Rust binding for libgit2
- Rayon parallelism (web search): Data parallelism library enabling parallel file/commit processing
- git2 thread safety (Research §6.1): Open Repository per thread for parallel access

**Risks**:
- git2 Repository is not Send/Sync (mitigate: open per-thread, as shown above)
- libgit2 doesn't support all git features (mitigate: only need commit walking, diff, blame)
- Shallow clones may limit commit history (mitigate: detect and warn)

**Dependencies**:
- 01-rust-core: git2 crate dependency
- R5: Enhanced NLP extraction runs on git2-provided commit data
- R4: Decision storage receives git2-mined results

---

### R11: DORA-Adjacent Convention Health Metrics

**Priority**: P1 (High — provides enterprise-grade metrics for executive reporting)
**Effort**: Medium
**Impact**: Positions Drift as a measurable engineering intelligence platform; enables trend-based decision making

**Current State (v1)**:
DNA health score is a point-in-time snapshot (0-100). Evolution tracking stores the last 50 snapshots but provides no trend analysis, no velocity metrics, no comparison across time periods. No DORA-like metrics for convention health.

**Proposed Change**:
Define and track 4 DORA-adjacent metrics that measure convention health over time. These metrics complement DORA's delivery performance metrics with code quality intelligence.

**Metric Definitions**:
```rust
pub struct ConventionHealthMetrics {
    /// How fast are conventions changing? (Lower = more stable)
    /// Measured as: number of dominant allele changes per month
    pub drift_velocity: DriftVelocity,

    /// What percentage of code follows established patterns?
    /// Measured as: files matching dominant alleles / total files analyzed
    pub compliance_rate: ComplianceRate,

    /// Is the codebase getting healthier or sicker?
    /// Measured as: slope of health score over time window
    pub health_trend: HealthTrend,

    /// How quickly are deviations fixed after detection?
    /// Measured as: median time from mutation detection to resolution
    pub mutation_resolution_rate: MutationResolutionRate,
}

pub struct DriftVelocity {
    pub changes_per_month: f64,
    pub trend: TrendDirection,     // Accelerating, Stable, Decelerating
    pub most_volatile_genes: Vec<(String, f64)>,  // Gene ID, change rate
    pub assessment: VelocityAssessment,
}

pub enum VelocityAssessment {
    Stable,      // < 0.5 changes/month — conventions are established
    Evolving,    // 0.5-2.0 changes/month — active convention development
    Volatile,    // > 2.0 changes/month — conventions are unstable
}

pub struct ComplianceRate {
    pub overall: f64,              // 0.0-1.0
    pub per_gene: HashMap<String, f64>,
    pub trend: TrendDirection,
    pub worst_compliance_genes: Vec<(String, f64)>,
}

pub struct HealthTrend {
    pub direction: TrendDirection,
    pub slope: f64,                // Points per day (positive = improving)
    pub current_score: u8,
    pub score_30d_ago: Option<u8>,
    pub score_90d_ago: Option<u8>,
    pub projected_30d: u8,         // Linear projection
    pub assessment: HealthAssessment,
}

pub enum HealthAssessment {
    Improving,   // Slope > 0.1 points/day
    Stable,      // Slope between -0.1 and 0.1
    Degrading,   // Slope < -0.1 points/day
    Critical,    // Score < 50 AND degrading
}

pub struct MutationResolutionRate {
    pub median_days: f64,
    pub p90_days: f64,
    pub unresolved_count: usize,
    pub resolution_rate: f64,      // Resolved / (Resolved + Unresolved)
    pub trend: TrendDirection,
}
```

**Tracking Implementation**:
```rust
pub struct MetricsTracker {
    store: Box<dyn MetricsStore>,
}

impl MetricsTracker {
    pub fn record_snapshot(&self, profile: &DnaProfile) -> Result<()> {
        let snapshot = MetricsSnapshot {
            timestamp: now(),
            health_score: profile.health_score,
            gene_states: profile.genes.iter()
                .map(|g| GeneState {
                    gene_id: g.id.clone(),
                    dominant_allele: g.dominant.clone(),
                    dominance_tier: g.dominance_tier(),
                    consistency: g.consistency,
                })
                .collect(),
            mutation_count: profile.mutations.len(),
            compliance_rate: self.calculate_compliance(profile),
        };
        self.store.save_snapshot(snapshot)
    }

    pub fn compute_metrics(&self, window_days: u32) -> Result<ConventionHealthMetrics> {
        let snapshots = self.store.get_snapshots(window_days)?;
        Ok(ConventionHealthMetrics {
            drift_velocity: self.compute_drift_velocity(&snapshots),
            compliance_rate: self.compute_compliance_rate(&snapshots),
            health_trend: self.compute_health_trend(&snapshots),
            mutation_resolution_rate: self.compute_resolution_rate(&snapshots),
        })
    }
}
```

**MCP Tool Exposure**:
```json
{
  "tool": "drift_convention_metrics",
  "description": "Get DORA-adjacent convention health metrics",
  "parameters": {
    "window_days": { "type": "integer", "default": 30 },
    "include_per_gene": { "type": "boolean", "default": false }
  }
}
```

**Rationale**:
DORA metrics (Research §5.2) are the gold standard for measuring software delivery performance. Convention health is a natural extension — it measures code quality trends that DORA doesn't capture. Cortex.io's production readiness report (Research §5.2) validates that engineering leaders focus on standardization metrics. These metrics transform Drift from a point-in-time scanner into a continuous intelligence platform.

**Evidence**:
- DORA metrics (Research §5.2): Gold standard for delivery performance measurement
- Cortex.io standardization (Research §5.1): Engineering leaders focus on standardization metrics
- Convention consistency research (Research §1.3): Consistency correlates with fewer defects

**Risks**:
- Metrics require sufficient historical data (mitigate: minimum 7 days of snapshots for meaningful trends)
- Mutation resolution tracking requires comparing snapshots (mitigate: hash-based mutation identity from v1)
- Executive reporting needs clear visualization (mitigate: provide both raw data and assessments)

**Dependencies**:
- R3: Graduated health scores provide more meaningful trend data
- 08-storage: Metrics snapshot persistence (SQLite)
- 07-mcp: MCP tools expose metrics to AI assistants
- 09-quality-gates: Metrics feed quality gate thresholds

---

### R12: Incremental Analysis with Content-Hash Caching

**Priority**: P1 (High — critical for developer adoption on large codebases)
**Effort**: Medium
**Impact**: 10-100x faster for typical development workflows; enables real-time DNA feedback

**Current State (v1)**:
Every DNA analysis re-reads and re-analyzes all files. No change detection. No caching of intermediate results. For a 10K-file codebase, this means reading 10K files and running 10 gene extractors against each — every single time.

**Proposed Change**:
Three-layer incremental analysis:

**Layer 1 — File-Level Skip (content hash)**:
```rust
use std::collections::HashMap;
use sha2::{Sha256, Digest};

pub struct IncrementalCache {
    /// file_path -> (content_hash, Vec<DetectedAllele>)
    file_cache: HashMap<String, (String, Vec<DetectedAllele>)>,
    /// Gene definition version hash (invalidate if genes change)
    gene_version: String,
}

impl IncrementalCache {
    pub fn should_analyze(&self, path: &str, content: &str) -> bool {
        let hash = Self::content_hash(content);
        match self.file_cache.get(path) {
            Some((cached_hash, _)) if cached_hash == &hash => false,  // Skip
            _ => true,  // Analyze
        }

    }

    pub fn get_cached(&self, path: &str) -> Option<&Vec<DetectedAllele>> {
        self.file_cache.get(path).map(|(_, alleles)| alleles)
    }

    pub fn update(&mut self, path: &str, content: &str, alleles: Vec<DetectedAllele>) {
        let hash = Self::content_hash(content);
        self.file_cache.insert(path.to_string(), (hash, alleles));
    }

    fn content_hash(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}
```

**Layer 2 — Gene-Level Re-Aggregation**:
```rust
pub struct IncrementalDnaAnalyzer {
    cache: IncrementalCache,
    genes: Vec<CompiledGene>,
}

impl IncrementalDnaAnalyzer {
    pub fn analyze_incremental(
        &mut self,
        files: &HashMap<String, String>,
    ) -> DnaProfile {
        let mut changed_files = Vec::new();
        let mut all_alleles: Vec<DetectedAllele> = Vec::new();

        for (path, content) in files {
            if self.cache.should_analyze(path, content) {
                // File changed — re-extract
                let alleles = self.extract_all_genes(path, content);
                self.cache.update(path, content, alleles.clone());
                all_alleles.extend(alleles);
                changed_files.push(path.clone());
            } else {
                // File unchanged — use cached results
                if let Some(cached) = self.cache.get_cached(path) {
                    all_alleles.extend(cached.clone());
                }
            }
        }

        // Re-aggregate only if any files changed
        if changed_files.is_empty() {
            return self.cache.last_profile.clone();
        }

        // Full re-aggregation (fast — just counting)
        self.aggregate_and_score(all_alleles)
    }
}
```

**Layer 3 — Simulation Result Caching**:
```rust
pub struct SimulationCache {
    /// task_hash -> (file_hashes, SimulationResult)
    cache: HashMap<String, (Vec<(String, String)>, SimulationResult)>,
}

impl SimulationCache {
    pub fn get_cached(
        &self,
        task: &SimulationTask,
        current_file_hashes: &[(String, String)],
    ) -> Option<&SimulationResult> {
        let task_hash = Self::task_hash(task);
        match self.cache.get(&task_hash) {
            Some((cached_hashes, result))
                if cached_hashes == current_file_hashes => Some(result),
            _ => None,
        }
    }
}
```

**Expected Performance**:

| Scenario | v1 Time | v2 Time (incremental) | Speedup |
|----------|---------|----------------------|---------|
| First run (10K files) | ~5s | ~5s | 1x (no cache) |
| No changes | ~5s | ~50ms | 100x |
| 10 files changed | ~5s | ~200ms | 25x |
| 100 files changed | ~5s | ~500ms | 10x |
| Gene definitions changed | ~5s | ~5s | 1x (cache invalidated) |

**Rationale**:
Google, CodeQL, and SonarQube all use incremental analysis as a core strategy (category 03 R2). For typical development workflows (1-10 files changed), incremental analysis reduces scan time from seconds to milliseconds. This is critical for developer adoption — slow analysis gets skipped. Content-hash caching is the simplest, most reliable approach.

**Evidence**:
- Category 03 R2: Incremental detection with content-hash skipping
- Rayon parallel processing (web search): Parallel file hashing in Rust
- SonarQube incremental analysis: Industry standard for fast re-analysis

**Risks**:
- Cache invalidation on gene definition changes must be reliable (mitigate: gene version hash)
- Memory usage for large caches (mitigate: LRU eviction, persist to disk for very large codebases)
- Cache corruption could produce stale results (mitigate: periodic full re-analysis, cache integrity checks)

**Dependencies**:
- R1: Declarative gene definitions include version hash for cache invalidation
- 08-storage: Cache persistence (optional — in-memory is sufficient for single-run CLI)
- 01-rust-core: SHA-256 hashing (sha2 crate)


---

### R13: Expanded Language Coverage (Go, Rust, C++)

**Priority**: P2 (Important — expands addressable market)
**Effort**: High
**Impact**: Extends Drift to 3 additional language ecosystems; enables polyglot enterprise analysis

**Current State (v1)**:
Language Intelligence supports 5 languages (TypeScript, Python, Java, C#, PHP) with dedicated normalizers. Decision mining has 5 dedicated extractors for the same languages. Go, Rust, and C++ fall back to generic analysis — missing language-specific patterns, framework detection, and semantic normalization.

**Proposed Change**:
Add dedicated support for Go, Rust, and C++ across all 4 Advanced Systems subsystems. Prioritize Go and Rust (growing enterprise adoption) over C++ (complex, niche).

**Go Support**:
```rust
// Go doesn't use decorators — it uses struct tags, interfaces, and conventions
pub struct GoTranslator;

impl GastTranslator for GoTranslator {
    fn language(&self) -> Language { Language::Go }

    fn translate_function(&self, node: &Node, source: &[u8]) -> Option<GastFunction> {
        // Go functions: func Name(params) (returns) { ... }
        // Go methods: func (r *Receiver) Name(params) (returns) { ... }
        // Detect: handler functions (http.HandlerFunc signature)
        // Detect: middleware (func(http.Handler) http.Handler)
        // Detect: test functions (func TestXxx(t *testing.T))
    }

    fn translate_decorator(&self, node: &Node, source: &[u8]) -> Option<GastDecorator> {
        // Go doesn't have decorators — normalize struct tags instead
        // `json:"name,omitempty"` -> GastDecorator { category: "serialization" }
        // `db:"column_name"` -> GastDecorator { category: "orm" }
        // `validate:"required"` -> GastDecorator { category: "validation" }
        None  // Handled via struct tag extraction
    }
}

// Go framework detection
// Gin: gin.Default(), gin.New(), r.GET(), r.POST()
// Echo: echo.New(), e.GET(), e.POST()
// Fiber: fiber.New(), app.Get(), app.Post()
// Chi: chi.NewRouter(), r.Get(), r.Post()
// Standard library: http.HandleFunc(), http.ListenAndServe()
```

**Rust Support**:
```rust
pub struct RustTranslator;

impl GastTranslator for RustTranslator {
    fn language(&self) -> Language { Language::Rust }

    fn translate_function(&self, node: &Node, source: &[u8]) -> Option<GastFunction> {
        // Rust functions: fn name(params) -> Return { ... }
        // Rust methods: impl Type { fn name(&self, params) -> Return { ... } }
        // Detect: async functions (async fn)
        // Detect: trait implementations
        // Detect: test functions (#[test], #[tokio::test])
    }

    fn translate_decorator(&self, node: &Node, source: &[u8]) -> Option<GastDecorator> {
        // Rust uses derive macros and attributes instead of decorators
        // #[derive(Serialize, Deserialize)] -> GastDecorator { category: "serialization" }
        // #[get("/path")] (Actix/Rocket) -> GastDecorator { category: "routing" }
        // #[tokio::main] -> GastDecorator { category: "runtime" }
        // #[test] -> GastDecorator { category: "test" }
    }
}

// Rust framework detection
// Actix Web: actix_web::*, #[get], #[post], HttpServer::new()
// Axum: axum::*, Router::new(), .route()
// Rocket: rocket::*, #[get], #[post], #[launch]
// Warp: warp::*, warp::path(), warp::get()
```

**C++ Support (Minimal)**:
```rust
pub struct CppTranslator;

impl GastTranslator for CppTranslator {
    fn language(&self) -> Language { Language::Cpp }

    fn translate_function(&self, node: &Node, source: &[u8]) -> Option<GastFunction> {
        // C++ functions: ReturnType name(params) { ... }
        // C++ methods: ReturnType Class::name(params) { ... }
        // Detect: virtual functions, override, const methods
        // Detect: template functions
    }

    fn translate_decorator(&self, node: &Node, source: &[u8]) -> Option<GastDecorator> {
        // C++ uses attributes (C++11+)
        // [[nodiscard]] -> GastDecorator { category: "annotation" }
        // [[deprecated("reason")]] -> GastDecorator { category: "lifecycle" }
        // No framework-specific decorators (C++ frameworks use different patterns)
        None
    }
}
```

**Decision Mining Extractors**:
```rust
// Go commit extractor
struct GoCommitExtractor;
impl CommitExtractor for GoCommitExtractor {
    fn languages(&self) -> &[Language] { &[Language::Go] }
    fn extensions(&self) -> &[&str] { &[".go"] }
    fn dependency_manifests(&self) -> &[&str] { &["go.mod", "go.sum"] }
    // Extract: module changes, interface additions, goroutine patterns
}

// Rust commit extractor
struct RustCommitExtractor;
impl CommitExtractor for RustCommitExtractor {
    fn languages(&self) -> &[Language] { &[Language::Rust] }
    fn extensions(&self) -> &[&str] { &[".rs"] }
    fn dependency_manifests(&self) -> &[&str] { &["Cargo.toml", "Cargo.lock"] }
    // Extract: crate additions, trait implementations, unsafe blocks
}
```

**Rationale**:
Go and Rust are the fastest-growing languages in enterprise backend development. Missing support for these languages limits Drift's addressable market. The GAST layer (R8) makes adding new languages a translator implementation, not a full subsystem rewrite. Go's convention-heavy culture (gofmt, standard project layout) makes it an ideal target for convention analysis.

**Evidence**:
- YASA (Research §4.1): Supports 7+ languages including Go
- MLCPD (Research §4.1): Cross-language structural regularities exist across Go, Python, Java
- Semgrep (Research §4.2): 30+ languages with single analysis engine

**Risks**:
- Go's lack of decorators requires different normalization approach (struct tags, conventions)
- Rust's macro system is complex (mitigate: focus on derive macros and attribute macros, skip proc macros)
- C++ template metaprogramming is extremely complex (mitigate: minimal C++ support, focus on modern C++17+)

**Dependencies**:
- R8: GAST layer provides the translator interface
- R9: Framework definitions for Go/Rust frameworks
- 02-parsers: Tree-sitter grammars for Go, Rust, C++ (likely already available)

---

### R14: Learned Strategy Templates from Codebase Patterns

**Priority**: P2 (Important — transforms simulation from generic to codebase-specific)
**Effort**: High
**Impact**: Simulation recommendations match actual codebase patterns; eliminates generic template mismatch

**Current State (v1)**:
Simulation strategy templates are hardcoded per language/framework. A Spring Boot "middleware" strategy always suggests the same implementation pattern, regardless of how the actual codebase implements middleware. This creates a disconnect: the simulation recommends patterns the team doesn't use.

**Proposed Change**:
Learn strategy templates from the codebase's actual patterns. Use DNA genes, detected patterns, and Language Intelligence to build codebase-specific templates that reflect how THIS team writes code.

**Template Learning Pipeline**:
```rust
pub struct TemplateLearner {
    dna_profile: DnaProfile,
    patterns: Vec<DetectedPattern>,
    normalized_files: Vec<NormalizedExtractionResult>,
}

pub struct LearnedTemplate {
    pub strategy: Strategy,
    pub language: Language,
    pub framework: Option<String>,
    pub source: TemplateSource,     // Learned vs Builtin
    pub confidence: f64,
    pub exemplar_files: Vec<String>,  // Real files this was learned from
    pub structure: TemplateStructure,
}

pub struct TemplateStructure {
    pub file_organization: FileOrganization,  // Where to put new files
    pub import_style: ImportStyle,            // How imports are organized
    pub error_handling: ErrorHandlingStyle,   // How errors are handled
    pub naming_convention: NamingConvention,  // How things are named
    pub test_pattern: Option<TestPattern>,    // How tests are structured
}

impl TemplateLearner {
    pub fn learn_templates(&self) -> Vec<LearnedTemplate> {
        let mut templates = Vec::new();

        // Learn from existing middleware implementations
        let middleware_files = self.find_files_by_semantic("middleware");
        if !middleware_files.is_empty() {
            templates.push(self.learn_from_exemplars(
                Strategy::Middleware,
                &middleware_files,
            ));
        }

        // Learn from existing decorator usage
        let decorator_files = self.find_files_by_pattern("decorator");
        if !decorator_files.is_empty() {
            templates.push(self.learn_from_exemplars(
                Strategy::Decorator,
                &decorator_files,
            ));
        }

        // Learn from DNA genes
        for gene in &self.dna_profile.genes {
            if let Some(dominant) = &gene.dominant_allele {
                templates.extend(self.learn_from_gene(gene, dominant));
            }
        }

        templates
    }

    fn learn_from_exemplars(
        &self,
        strategy: Strategy,
        exemplar_files: &[&NormalizedExtractionResult],
    ) -> LearnedTemplate {
        // Analyze exemplar files to extract:
        // 1. File organization (directory structure, naming)
        // 2. Import patterns (what's imported, how)
        // 3. Error handling (try/catch style, Result type, etc.)
        // 4. Naming conventions (camelCase, snake_case, prefixes)
        // 5. Test patterns (co-located, separate directory, naming)
        LearnedTemplate {
            strategy,
            language: exemplar_files[0].language,
            framework: exemplar_files[0].primary_framework.clone(),
            source: TemplateSource::Learned,
            confidence: 0.8,  // Learned templates have high confidence
            exemplar_files: exemplar_files.iter()
                .map(|f| f.file_path.clone())
                .collect(),
            structure: self.extract_structure(exemplar_files),
        }
    }
}
```

**Simulation Integration**:
```rust
impl SimulationEngine {
    fn generate_approaches(&self, task: &SimulationTask) -> Vec<SimulationApproach> {
        // Priority: learned templates > builtin templates > fallback
        let learned = self.template_learner.learn_templates();
        let builtin = self.builtin_templates.get(&task.language);

        let mut approaches = Vec::new();

        // Learned templates first (highest relevance)
        for template in &learned {
            if template.matches_task(task) {
                approaches.push(self.approach_from_template(template, task));
            }
        }

        // Builtin templates as fallback
        if approaches.len() < task.max_approaches {
            for template in builtin.unwrap_or(&vec![]) {
                if !self.is_redundant_with(&approaches, template) {
                    approaches.push(self.approach_from_builtin(template, task));
                }
            }
        }

        approaches.truncate(task.max_approaches);
        approaches
    }
}
```

**Rationale**:
The convention consistency research (Research §1.3) establishes that project-specific models are significantly better at predicting conventions than generic models. Hardcoded templates are generic by definition — they can't capture how a specific team writes middleware, handles errors, or organizes files. Learned templates close this gap by using the codebase itself as the source of truth.

**Evidence**:
- Hindle et al. "Naturalness of Software" (Research §1.3): Project-specific models outperform generic models
- Developer-provided context study (Research §7.1): Conventions are the most valuable context type
- DNA system (RECAP §1): Gene data already captures convention patterns — reuse for templates

**Risks**:
- Learning requires sufficient exemplars (mitigate: fall back to builtin templates if < 3 exemplars)
- Learned templates may encode bad patterns (mitigate: combine with pattern alignment scoring)
- Template learning adds latency to simulation (mitigate: cache learned templates, invalidate on DNA change)

**Dependencies**:
- R1: DNA gene data provides convention patterns for learning
- R8: GAST provides normalized code structure for analysis
- R12: Incremental caching avoids re-learning on every simulation

---

### R15: Cross-Subsystem Event Bus for Data Flow

**Priority**: P2 (Important — eliminates tight coupling between subsystems)
**Effort**: Medium
**Impact**: Clean data flow between 4 subsystems; enables independent subsystem evolution

**Current State (v1)**:
The 4 Advanced Systems subsystems communicate via direct function calls and shared data structures. DNA doesn't know about Decision Mining results. Simulation doesn't consume DNA health data. Language Intelligence results aren't fed back to DNA for gene enrichment. The subsystems are islands of intelligence that don't share knowledge.

**Proposed Change**:
Implement a lightweight event bus that enables subsystems to publish and subscribe to analysis events. This decouples subsystems while enabling rich data flow.

**Event Types**:
```rust
pub enum AdvancedSystemEvent {
    // DNA events
    DnaAnalysisComplete(DnaProfile),
    MutationDetected(Vec<Mutation>),
    HealthScoreChanged { old: u8, new: u8 },
    GeneEvolved { gene_id: String, old_dominant: String, new_dominant: String },

    // Decision Mining events
    DecisionMined(Vec<MinedDecision>),
    DecisionReversalDetected { original: String, reversal: String },
    AdrDetected(Vec<DetectedAdr>),

    // Simulation events
    SimulationComplete(SimulationResult),
    FitnessEvaluationComplete(Vec<FitnessEvaluation>),

    // Language Intelligence events
    FrameworkDetected(Vec<DetectedFramework>),
    NormalizationComplete(Vec<NormalizedExtractionResult>),
}

pub trait EventSubscriber: Send + Sync {
    fn on_event(&self, event: &AdvancedSystemEvent);
}

pub struct EventBus {
    subscribers: Vec<Box<dyn EventSubscriber>>,
}

impl EventBus {
    pub fn publish(&self, event: AdvancedSystemEvent) {
        for subscriber in &self.subscribers {
            subscriber.on_event(&event);
        }
    }

    pub fn subscribe(&mut self, subscriber: Box<dyn EventSubscriber>) {
        self.subscribers.push(subscriber);
    }
}
```

**Cross-Subsystem Data Flows Enabled**:

| Publisher | Event | Subscriber | Action |
|-----------|-------|------------|--------|
| DNA | HealthScoreChanged | Quality Gates | Update gate thresholds |
| DNA | MutationDetected | Simulation | Factor mutations into risk scoring |
| Decision Mining | DecisionMined | DNA | Enrich genes with decision context |
| Decision Mining | DecisionReversalDetected | Simulation | Flag reversed patterns as risky |
| Language Intelligence | FrameworkDetected | DNA | Select framework-specific genes |
| Language Intelligence | NormalizationComplete | Simulation | Use normalized data for scoring |
| Simulation | FitnessEvaluationComplete | Quality Gates | Enforce fitness function thresholds |

**Rationale**:
The cross-subsystem integration points documented in the RECAP show that all 4 subsystems produce data that other subsystems could consume. Direct coupling makes this fragile — adding a new consumer requires modifying the producer. An event bus decouples producers from consumers, enabling independent evolution and new integrations without code changes.

**Evidence**:
- RECAP cross-subsystem integration table: All 4 subsystems have bidirectional data needs
- Category 03 R1 (visitor pattern): Event-driven architecture for detection
- Architectural fitness functions (Research §3.2): Fitness functions need data from multiple subsystems

**Risks**:
- Event ordering may matter for some consumers (mitigate: synchronous event dispatch, ordered by registration)
- Event bus adds indirection (mitigate: keep it simple — no async, no persistence, no replay)
- Debugging event flows is harder than direct calls (mitigate: event logging in verbose mode)

**Dependencies**:
- All 4 subsystems: Each subsystem publishes and subscribes to events
- 08-storage: Event-triggered persistence (e.g., save decision on DecisionMined event)
- 12-infrastructure: Event bus initialization during pipeline setup

---

### R16: Unified Cross-Language Query API

**Priority**: P2 (Important — provides the developer-facing interface for all Advanced Systems)
**Effort**: Medium
**Impact**: Single API for all cross-language intelligence queries; enables powerful MCP tool composition

**Current State (v1)**:
Language Intelligence provides a query API (`findEntryPoints`, `findDataAccessors`, etc.) but it only covers normalized decorator data. DNA, Decision Mining, and Simulation each have their own separate APIs. There's no unified way to ask: "Show me all entry points in this module, their convention compliance, any decisions that affected them, and the simulation risk if I change them."

**Proposed Change**:
Build a unified query API that composes results from all 4 subsystems into a single, rich response. This becomes the primary interface for MCP tools and CLI commands.

**Query API Design**:
```rust
pub struct UnifiedQuery {
    /// File or directory scope
    pub scope: QueryScope,
    /// What to include in results
    pub include: QueryIncludes,
    /// Filters
    pub filters: QueryFilters,
}

pub enum QueryScope {
    File(String),
    Directory(String),
    Module(String),       // Logical module (detected from structure)
    Function(String),     // Specific function by name
    Pattern(String),      // All code matching a pattern
    Global,               // Entire codebase
}

pub struct QueryIncludes {
    pub semantics: bool,       // Language Intelligence: normalized functions, decorators
    pub conventions: bool,     // DNA: gene compliance, mutations, health
    pub decisions: bool,       // Decision Mining: related decisions, ADRs
    pub simulation: bool,      // Simulation: risk score, fitness functions
    pub metrics: bool,         // DORA-adjacent metrics for scope
}

pub struct QueryFilters {
    pub languages: Option<Vec<Language>>,
    pub frameworks: Option<Vec<String>>,
    pub semantic_categories: Option<Vec<String>>,  // routing, di, orm, auth, etc.
    pub min_confidence: Option<f64>,
    pub time_range: Option<(i64, i64)>,  // For decision queries
}

pub struct UnifiedQueryResult {
    pub scope: QueryScope,
    pub files: Vec<FileIntelligence>,
    pub summary: IntelligenceSummary,
}

pub struct FileIntelligence {
    pub path: String,
    pub language: Language,
    pub framework: Option<String>,

    // Language Intelligence
    pub functions: Vec<NormalizedFunction>,
    pub file_semantics: FileSemantics,

    // DNA
    pub convention_compliance: ConventionCompliance,
    pub mutations: Vec<Mutation>,

    // Decision Mining
    pub related_decisions: Vec<DecisionSummary>,

    // Simulation
    pub change_risk: Option<ChangeRisk>,
}

pub struct IntelligenceSummary {
    pub total_files: usize,
    pub languages: HashMap<Language, usize>,
    pub frameworks: HashMap<String, usize>,
    pub health_score: u8,
    pub entry_points: usize,
    pub decisions_count: usize,
    pub avg_change_risk: f64,
}
```

**MCP Tool Composition**:
```json
{
  "tool": "drift_intelligence",
  "description": "Unified cross-language intelligence query",
  "parameters": {
    "scope": { "type": "string", "description": "File, directory, or 'global'" },
    "include": {
      "type": "object",
      "properties": {
        "semantics": { "type": "boolean", "default": true },
        "conventions": { "type": "boolean", "default": true },
        "decisions": { "type": "boolean", "default": false },
        "simulation": { "type": "boolean", "default": false },
        "metrics": { "type": "boolean", "default": false }
      }
    },
    "filters": {
      "type": "object",
      "properties": {
        "languages": { "type": "array", "items": { "type": "string" } },
        "categories": { "type": "array", "items": { "type": "string" } },
        "min_confidence": { "type": "number" }
      }
    }
  }
}
```

**Rationale**:
The developer-provided context study (Research §7.1) shows that conventions are the most valuable context type for AI assistants. A unified query API enables AI assistants to get comprehensive intelligence about any code scope in a single call — semantics, conventions, decisions, and risk. This is the interface that makes Drift's Advanced Systems accessible and composable.

**Evidence**:
- Developer context study (Research §7.1): Unified context is more valuable than fragmented queries
- Cortex.io scorecards (Research §3.1): Multi-dimensional views of code health
- MCP tool design: Single comprehensive tool > many narrow tools for AI consumption

**Risks**:
- Query performance for Global scope on large codebases (mitigate: lazy loading, pagination)
- Response size for full includes (mitigate: configurable includes, summary-only mode)
- API stability — changes affect all consumers (mitigate: versioned API, backward compatibility)

**Dependencies**:
- R4: Decision storage for decision queries
- R8: GAST for normalized semantic data
- R11: Metrics for convention health data
- R15: Event bus ensures all subsystem data is up-to-date
- 07-mcp: MCP tool registration

---

## Recommendation Priority Matrix

| # | Recommendation | Priority | Effort | Category |
|---|---------------|----------|--------|----------|
| R1 | Declarative Gene Definitions (TOML) | P0 | Medium | DNA Architecture |
| R2 | Structural Gene Extraction (AST) | P0 | High | DNA Accuracy |
| R3 | Graduated Dominance + Cross-Gene Consistency | P0 | Low | DNA Scoring |
| R4 | Knowledge Graph-Backed Decision Storage | P0 | High | Decision Mining |
| R5 | Enhanced NLP Extraction + Reversal Detection | P1 | Medium | Decision Mining |
| R6 | Six-Dimensional Simulation Scoring | P1 | Medium | Simulation |
| R7 | Architectural Fitness Function Framework | P1 | High | Simulation + Gates |
| R8 | Generic AST (GAST) Normalization Layer | P1 | High | Language Intelligence |
| R9 | Declarative Framework Mappings (TOML) | P1 | Medium | Language Intelligence |
| R10 | git2 Integration for Decision Mining | P1 | Medium | Performance |
| R11 | DORA-Adjacent Convention Health Metrics | P1 | Medium | Metrics |
| R12 | Incremental Analysis with Content-Hash Caching | P1 | Medium | Performance |
| R13 | Expanded Language Coverage (Go, Rust, C++) | P2 | High | Language Coverage |
| R14 | Learned Strategy Templates | P2 | High | Simulation |
| R15 | Cross-Subsystem Event Bus | P2 | Medium | Architecture |
| R16 | Unified Cross-Language Query API | P2 | Medium | Developer Experience |

---

## Implementation Order (Fresh Build)

Since this is a greenfield build, the implementation order accounts for dependency chains and foundation-laying:

```
Phase 1 — Foundations (Weeks 1-4):
  R1:  Declarative gene definitions (TOML) — this IS the gene system, build it first
  R3:  Graduated dominance + cross-gene consistency — pure math, no dependencies
  R10: git2 integration — foundational for all decision mining
  R12: Incremental caching infrastructure — needed from day one for performance

Phase 2 — Core Intelligence (Weeks 5-10):
  R8:  GAST normalization layer — foundational for cross-language everything
  R4:  Knowledge graph-backed decision storage (SQLite) — foundational for decisions
  R9:  Declarative framework mappings — builds on R8's GAST layer
  R5:  Enhanced NLP extraction — builds on R10's git2 and R4's storage

Phase 3 — Advanced Capabilities (Weeks 11-16):
  R2:  Structural gene extraction — builds on R1 (gene definitions) + R8 (GAST)
  R6:  Six-dimensional simulation scoring — builds on existing simulation engine
  R11: DORA-adjacent metrics — builds on R3 (graduated scoring) + R12 (caching)
  R7:  Fitness function framework — builds on R6 (scoring) + R3 (health)

Phase 4 — Integration & Expansion (Weeks 17-24):
  R15: Cross-subsystem event bus — connects all subsystems
  R16: Unified query API — builds on all subsystems being operational
  R14: Learned strategy templates — builds on R1 (DNA) + R8 (GAST) + R9 (frameworks)
  R13: Go/Rust/C++ language support — builds on R8 (GAST) + R9 (framework mappings)
```

---

## Cross-Category Impact Analysis

| Recommendation | Categories Affected | Impact Type |
|---------------|-------------------|-------------|
| R1 (Declarative Genes) | 01-rust-core, 08-storage, 12-infrastructure | TOML parsing, gene loading, distribution |
| R2 (Structural Extraction) | 01-rust-core, 02-parsers | Tree-sitter query API, AST availability |
| R3 (Graduated Scoring) | 08-storage, 09-quality-gates | Schema changes, threshold updates |
| R4 (Decision Storage) | 06-cortex, 07-mcp, 08-storage | Memory integration, MCP tools, SQLite schema |
| R5 (NLP Extraction) | 01-rust-core | Regex infrastructure for pattern matching |
| R6 (6D Scoring) | 04-call-graph, 17-test-topology | Complexity data, test mapping |
| R7 (Fitness Functions) | 09-quality-gates, 08-storage | New gate type, trend persistence |
| R8 (GAST) | 01-rust-core, 02-parsers, 04-call-graph | New normalization layer, call graph enrichment |
| R9 (Framework Mappings) | 01-rust-core, 12-infrastructure | TOML parsing, plugin distribution |
| R10 (git2) | 01-rust-core | New crate dependency |
| R11 (DORA Metrics) | 07-mcp, 09-quality-gates | New MCP tools, gate thresholds |
| R12 (Incremental Cache) | 08-storage | Cache persistence |
| R13 (Language Coverage) | 02-parsers | Tree-sitter grammars for Go, Rust, C++ |
| R14 (Learned Templates) | 07-mcp | Template data in simulation MCP tools |
| R15 (Event Bus) | All subsystems | Event publishing/subscribing |
| R16 (Unified Query) | 07-mcp | New comprehensive MCP tool |

---

## Quality Checklist

- [x] 16 recommendations documented with full detail
- [x] Each recommendation has: Priority, Effort, Impact, Current State, Proposed Change, Rationale, Evidence, Risks, Dependencies
- [x] All recommendations framed for greenfield v2 build (no migration constraints)
- [x] Priorities justified: P0 = foundational architecture, P1 = core capabilities, P2 = expansion and integration
- [x] Effort assessed for each recommendation (Low/Medium/High)
- [x] Rust implementation sketches provided for all compute-heavy recommendations
- [x] Cross-category dependencies mapped for each recommendation
- [x] Implementation order accounts for dependency chains across 4 phases (24 weeks)
- [x] Cross-category impact analysis completed for all 16 recommendations
- [x] All 4 subsystems (DNA, Decision Mining, Simulation, Language Intelligence) have dedicated recommendations
- [x] Research evidence cited for every recommendation (40+ sources across 7 research sections)
- [x] TOML configuration examples provided for declarative definitions (R1, R7, R9)
- [x] SQL schema provided for decision storage (R4)
- [x] Performance estimates provided where applicable (R10, R12)
- [x] DORA-adjacent metrics fully specified with data structures (R11)
- [x] GAST node types fully specified for cross-language normalization (R8)
- [x] Unified query API fully specified with MCP tool definition (R16)
