# The Specification Engine — Drift's Unreplicable Loop

> **Proposal:** A new operating mode for Drift v2 that transforms the analysis pipeline
> into an enterprise legacy migration engine — generating machine-verified, human-reviewed
> specifications from any codebase, in any language, entirely offline.
>
> **Thesis:** The hardest part of legacy migration isn't rewriting code — it's understanding
> what the old code does. Drift v2 already solves the understanding problem. This proposal
> adds the specification output layer that turns understanding into actionable migration specs.
>
> **Competitive Position:** Morgan Stanley built DevGen.AI internally (9M lines, 280K hours
> saved). MetroStar built MIDAS for USMC. Google halved migration time on 500M lines with
> internal tooling. All proprietary. All single-customer. None productized. Drift would be
> the first commercially available tool that does this — and the only one that works offline.
>
> **Novel Loop:** The self-reinforcing cycle that makes this nearly impossible to replicate:
> Structural Analysis → Specification Generation → Human Review → Grounded Memory →
> Specification Refinement → Migration Execution → Contract Verification → Loop.
>
> Generated: 2026-02-08

---

## 1. Why This Is The Right Play

### The Market Reality

Every Fortune 500 company has legacy code they can't migrate. The numbers:

- 70% of Fortune 500 software was written 20+ years ago (industry estimates)
- Maintaining legacy systems consumes up to 80% of IT budgets
- Morgan Stanley saved 280,000 developer hours in 6 months with an internal tool
- Google halved migration time on 500M+ lines of Java 8→17 with internal AI tooling
- The US Marine Corps contracted MetroStar to migrate 24,000 lines across 6 modules

The pattern is clear: every large organization is doing this work. All of them are
building internal tools or hiring consultancies. None of them have access to a
commercial product that does the hard part — understanding the legacy codebase
structurally before any AI touches it.

### Why Nobody Has Productized This

Three reasons:

1. **The understanding problem is genuinely hard.** You need parsers for 10+ languages,
   call graph resolution across files, data flow analysis, boundary detection, pattern
   recognition, convention learning, and contract tracking. Building this from scratch
   takes years. Drift v2 already has all of it specced across 35 V2-PREP documents.

2. **LLMs alone can't do it.** A 1M line codebase doesn't fit in any context window.
   Even with RAG, you get fragments — not structural understanding. You need deterministic
   static analysis first, then LLM synthesis on top. This is exactly Drift's architecture:
   offline indexing (Rust, deterministic) → online querying (context generation, LLM-ready).

3. **Enterprise security requirements kill cloud-dependent tools.** Banks, healthcare,
   defense — they won't send source code to external APIs. Drift runs entirely locally.
   The analysis pipeline is pure Rust. No network calls. No telemetry. The LLM calls
   for spec synthesis can use local models (Ollama) or air-gapped deployments.

### What Drift Already Has (The 80% That's Done)

| Capability | Drift v2 System | Status |
|-----------|----------------|--------|
| Multi-language parsing (10 langs) | System 01 — Parsers | Specced |
| Call graph with 6 resolution strategies | System 05 — Call Graph | Specced |
| Data flow / taint analysis | System 15 — Taint Analysis | Specced |
| Module boundary detection (33+ ORMs) | System 07 — Boundary Detection | Specced |
| API contract tracking (REST/GraphQL/gRPC) | System 21 — Contract Tracking | Specced |
| Coupling analysis (Tarjan's SCC, zones) | System 19 — Coupling Analysis | Specced |
| Convention/pattern discovery (350+ detectors) | System 06 — Detector System | Specced |
| Architectural decision mining (git history) | System 29 — Decision Mining | Specced |
| Codebase DNA fingerprinting | System 24 — DNA System | Specced |
| Error handling gap analysis | System 16 — Error Handling | Specced |
| Test topology mapping | System 18 — Test Topology | Specced |
| Constraint extraction (architectural invariants) | System 20 — Constraints | Specced |
| AI-optimized context generation | System 30 — Context Generation | Specced |
| Speculative execution / what-if analysis | System 28 — Simulation Engine | Specced |
| Empirically validated memory (grounding loop) | System 34 — Cortex Bridge | Specced |

That's 15 major subsystems. The structural understanding layer is complete. What's
missing is the specification output layer — the part that takes all this structural
data and produces human-reviewable migration specifications.

---

## 2. The Novel Loop — Why This Is Nearly Impossible To Replicate

This isn't just "add a feature." It's a self-reinforcing flywheel where each component
makes every other component better, and the whole system gets smarter with every
migration it participates in.

### The Seven-Stage Loop

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐              │
│  │ 1. STRUCTURAL │───▶│ 2. MODULE    │───▶│ 3. SPEC      │              │
│  │    INDEX      │    │    DECOMPOSE │    │    GENERATE   │              │
│  │              │    │              │    │              │              │
│  │ Drift scans  │    │ Coupling +   │    │ Per-module   │              │
│  │ 1M lines,    │    │ call graph   │    │ specs from   │              │
│  │ builds full  │    │ clustering   │    │ structural   │              │
│  │ structural   │    │ identifies   │    │ index +      │              │
│  │ index in     │    │ 47 logical   │    │ LLM synthesis│              │
│  │ drift.db     │    │ modules      │    │ (offline OK) │              │
│  └──────────────┘    └──────────────┘    └──────┬───────┘              │
│                                                  │                      │
│                                                  ▼                      │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐              │
│  │ 7. CONTRACT  │◀───│ 6. MIGRATION │◀───│ 4. HUMAN     │              │
│  │    VERIFY    │    │    EXECUTE   │    │    REVIEW     │              │
│  │              │    │              │    │              │              │
│  │ New code's   │    │ AI agents    │    │ Engineers    │              │
│  │ contracts    │    │ rebuild from │    │ review specs,│              │
│  │ verified     │    │ approved     │    │ correct      │              │
│  │ against old  │    │ specs, module│    │ business     │              │
│  │ code's       │    │ by module    │    │ logic, mark  │              │
│  │ contracts    │    │              │    │ approved     │              │
│  └──────┬───────┘    └──────────────┘    └──────┬───────┘              │
│         │                                        │                      │
│         ▼                                        ▼                      │
│  ┌──────────────────────────────────────────────────────┐              │
│  │              5. GROUNDED MEMORY (Cortex)              │              │
│  │                                                        │              │
│  │  Human corrections become Cortex memories.             │              │
│  │  Grounding loop validates memories against code.       │              │
│  │  Next spec generation is BETTER because it knows:      │              │
│  │  - What humans corrected last time                     │              │
│  │  - Which business logic descriptions were wrong        │              │
│  │  - Which module boundaries humans adjusted             │              │
│  │  - Which conventions the team actually cares about     │              │
│  │                                                        │              │
│  │  This is the flywheel. Every human review makes the    │              │
│  │  system smarter. No competitor has this because no     │              │
│  │  competitor has empirically validated memory.           │              │
│  └──────────────────────────────────────────────────────┘              │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Why Each Stage Creates Lock-In

**Stage 1 (Structural Index):** Drift's analysis pipeline is 35 specced subsystems,
553 implementation tasks, 504 test tasks. A competitor would need to build parsers for
10 languages, a call graph with 6 resolution strategies, taint analysis, boundary
detection for 33+ ORMs, coupling analysis with Tarjan's SCC, contract tracking across
REST/GraphQL/gRPC, convention learning with Bayesian confidence, and a DNA fingerprinting
system. This alone is 2-3 years of engineering. And it all has to work together — the
call graph feeds taint analysis, taint feeds security scoring, security feeds simulation,
simulation feeds quality gates. It's not 35 independent systems — it's a dependency graph
where removing any node degrades the whole.

**Stage 2 (Module Decomposition):** This is where Drift's coupling analysis + call graph
+ boundary detection + convention learning combine into something no individual tool can
replicate. The decomposition algorithm uses:
- Call graph clustering (functions that call each other heavily → same module)
- Data access patterns (functions touching same tables → same module)
- Convention similarity (functions following same patterns → same module)
- Import/export dependency graph (Tarjan's SCC identifies tightly coupled groups)
- Directory structure as a signal (existing organization as a prior)
- Boundary detection (ORM usage patterns define data domain boundaries)

No single tool has all six signals. CodeScene has behavioral analysis but no call graph.
SonarQube has code quality but no convention learning. Semgrep has pattern matching but
no coupling analysis. Drift has all of them in one index.

**Stage 3 (Spec Generation):** The Context Generation system (System 30) already produces
AI-optimized, token-budgeted, intent-aware context. The specification mode is a new
`ContextIntent::GenerateSpec` that changes the weight tables to prioritize:
- Architectural patterns (how the module is structured)
- API contracts (what the module exposes and consumes)
- Data flow paths (what data enters, transforms, and exits)
- Business logic narratives (what the module does, synthesized by LLM from structural data)
- Convention compliance (what patterns the module follows)
- Security boundaries (what sensitive data the module touches)
- Error handling patterns (how the module handles failures)
- Test coverage (what's tested, what's not)

This isn't a new system — it's a new mode of an existing system. The structural data
is identical. The output format and LLM prompting strategy change.

**Stage 4 (Human Review):** This is where the magic happens. Engineers review specs and
make corrections. "This isn't just user validation — it's KYC compliance logic." "This
module doesn't just call the database — it implements the 30-day trial period." These
corrections are the highest-value data in the entire pipeline.

**Stage 5 (Grounded Memory):** Human corrections flow into Cortex as memories. The
grounding feedback loop (D7 — the killer feature) validates these memories against
the codebase on every scan. If the codebase changes, the memories are flagged for
review. If the memories are confirmed, their confidence increases. This means:
- The next time Drift generates specs for a similar module, it knows what humans
  corrected last time
- Business logic descriptions improve over time without retraining any model
- Module boundary suggestions get better because the system remembers which
  boundaries humans adjusted
- Convention descriptions become more accurate because the system knows which
  conventions the team actually cares about

**No competitor has this loop.** Semgrep has "memories" for false positive triage, but
those are simple FP/TP labels — not structured business logic corrections validated
against code reality. CodeScene has behavioral analysis but no memory system. Morgan
Stanley's DevGen.AI is proprietary and single-customer. The grounding loop is what
makes Drift's specification engine self-improving.

**Stage 6 (Migration Execution):** AI agents consume approved specs via the MCP server
(System 32). The specs are the source of truth — not the old code. The AI reads a
structured specification document, not a tangled legacy codebase. This is fundamentally
easier for any LLM because:
- Specs are 2-5K tokens per module (fits in any context window)
- Specs are structured (not spaghetti code)
- Specs include explicit contracts (what the module must expose)
- Specs include explicit conventions (how the new code should be written)
- Specs include explicit test requirements (what must be tested)

**Stage 7 (Contract Verification):** After the new module is built, Drift scans it and
compares its API contracts against the old module's contracts (System 21 — Contract
Tracking). This is the verification step that closes the loop:
- Does the new TypeScript module expose the same REST endpoints as the old Java module?
- Do the response schemas match?
- Are there breaking changes?
- Does the new module follow the target codebase's conventions?

If verification fails, the spec is updated, the memory is adjusted, and the cycle
continues. This is not a one-shot process — it's iterative refinement.

---

## 3. The Five Gaps — What Needs To Be Built

Everything below sits on top of the existing v2 architecture. No new crates. No new
architectural decisions. These are features that extend existing systems.

### Gap 1: Module Decomposition Algorithm

**Where it lives:** `drift-analysis/src/structural/decomposition.rs` (new file in
existing `structural/` module, Phase 5 — Structural Intelligence)

**What it does:** Takes the full structural index (call graph + coupling metrics +
boundary data + convention patterns + directory structure) and produces a set of
logical modules with defined boundaries, interfaces, and responsibilities.

**Algorithm sketch:**

```
ModuleDecomposition(index: StructuralIndex) -> Vec<LogicalModule>:
  1. Build weighted dependency graph from import/export + call edges
  2. Run Tarjan's SCC to identify tightly coupled components
  3. Run community detection (Louvain or label propagation) on the
     condensation graph to find natural clusters
  4. Enrich clusters with data access patterns (which tables each cluster touches)
  5. Enrich with convention similarity (which patterns each cluster follows)
  6. Enrich with boundary data (which ORMs/APIs each cluster uses)
  7. Score each candidate module boundary:
     - Internal cohesion (call density within module)
     - External coupling (call density between modules)
     - Data isolation (how many tables are shared across modules)
     - Convention consistency (how uniform are patterns within module)
  8. Iteratively refine boundaries to maximize cohesion / minimize coupling
  9. For each module, extract:
     - Public interface (functions called from outside the module)
     - Internal functions (called only within the module)
     - Data dependencies (tables, APIs, external services)
     - Convention profile (dominant patterns within this module)
  10. Return Vec<LogicalModule> with dependency graph between modules
```

**Key types:**

```rust
pub struct LogicalModule {
    pub id: String,
    pub name: String,                    // Human-readable, derived from directory/purpose
    pub files: Vec<FileId>,
    pub public_interface: Vec<FunctionId>,
    pub internal_functions: Vec<FunctionId>,
    pub data_dependencies: Vec<DataDependency>,
    pub convention_profile: ConventionProfile,
    pub cohesion_score: f64,             // 0.0-1.0
    pub coupling_score: f64,             // 0.0-1.0 (lower is better)
    pub estimated_complexity: u32,       // Lines of code equivalent
    pub dependencies: Vec<ModuleDependency>,
}

pub struct ModuleDependency {
    pub target_module_id: String,
    pub interface_functions: Vec<FunctionId>,  // Which functions cross the boundary
    pub call_count: u32,                       // How many calls cross
    pub data_shared: Vec<String>,              // Shared tables/APIs
    pub direction: DependencyDirection,        // Unidirectional or bidirectional
}

pub struct DataDependency {
    pub kind: DataDependencyKind,        // Database, API, FileSystem, MessageQueue
    pub identifier: String,              // Table name, endpoint path, queue name
    pub operations: Vec<DataOperation>,  // Read, Write, ReadWrite
    pub sensitive_fields: Vec<String>,   // From boundary detection
}
```

**Why this is hard to replicate:** It requires call graph + coupling + boundary +
convention data all in one index. No other tool has all four. Building any one of
them is a multi-month effort. Building all four and making them work together is
what Drift v2's 11-phase plan does over ~6 months.

### Gap 2: Specification Generation Mode

**Where it lives:** `drift-context/src/modes/specification.rs` (new module in
existing drift-context crate, Phase 7 — Advanced & Capstone)

**What it does:** A new `ContextIntent::GenerateSpec` mode for the unified
ContextEngine that produces structured migration specification documents instead
of AI coding context.

**How it differs from existing context generation:**

| Aspect | Current (Code Context) | New (Spec Generation) |
|--------|----------------------|----------------------|
| Purpose | Help AI write code that fits patterns | Document what code does for human review |
| Token budget | 2K-12K per request | 3K-8K per module (structured document) |
| Output format | Markdown/XML/JSON context blob | Structured spec document with sections |
| Audience | AI agent (Claude, GPT, etc.) | Human engineer reviewing for migration |
| Scope | Single file or package | Logical module (from decomposition) |
| Data sources | Patterns, constraints, entry points | Everything + business logic synthesis |
| LLM involvement | None (pure data assembly) | Optional LLM pass for narrative synthesis |

**Specification document template:**

```markdown
# Module Specification: {module_name}

## 1. Overview
- **Purpose:** {2-3 sentence description synthesized from structural data + LLM}
- **Complexity:** {estimated_complexity} lines across {file_count} files
- **Languages:** {languages used}
- **Frameworks:** {detected frameworks}

## 2. Public API
| Function | Signature | Called By | Description |
|----------|-----------|----------|-------------|
| {name}   | {params → return} | {caller modules} | {LLM-synthesized description} |

## 3. Data Model
| Entity | Source | Fields | Sensitive | Operations |
|--------|--------|--------|-----------|------------|
| {table/model} | {ORM/raw SQL} | {field list} | {yes/no + which} | {CRUD} |

## 4. Data Flow
- **Inputs:** {what data enters this module, from where}
- **Transformations:** {key processing steps, derived from call graph paths}
- **Outputs:** {what data leaves this module, to where}
- **Taint Paths:** {source→sink paths with sensitivity classification}

## 5. Business Logic (Requires Human Review ⚠️)
{LLM-synthesized narrative from structural data. Explicitly marked as requiring
human verification. Based on:
- Function names and signatures
- Call graph paths (what calls what in what order)
- Data access patterns (what data is read/written)
- Error handling patterns (what failures are handled)
- Decision mining results (what architectural decisions led to this)
- Convention patterns (what coding patterns are used)}

## 6. Dependencies
| Module | Interface | Direction | Strength |
|--------|-----------|-----------|----------|
| {module_name} | {shared functions/data} | {→ or ←→} | {call count} |

## 7. Conventions
- **Naming:** {detected naming convention}
- **Error Handling:** {detected error handling pattern}
- **Logging:** {detected logging pattern}
- **Testing:** {test coverage %, test patterns}

## 8. Security Considerations
- **Sensitive Data:** {fields flagged by boundary detection}
- **Auth Requirements:** {detected auth patterns}
- **Taint Paths:** {source→sink paths that cross this module}
- **CWE Mappings:** {relevant CWE IDs from OWASP/CWE mapping}

## 9. Constraints (Architectural Invariants)
{Constraints that apply to this module, from the constraint system.
These must be preserved in the new implementation.}

## 10. Test Requirements
- **Current Coverage:** {from test topology}
- **Critical Paths:** {entry points → data access paths that must be tested}
- **Edge Cases:** {error handling paths, boundary conditions}

## 11. Migration Notes
- **Target Language/Framework:** {configured by user}
- **Equivalent Patterns:** {Drift's convention mapping for target stack}
- **Breaking Change Risks:** {from contract tracking}
- **Estimated Effort:** {from simulation engine}
```

**Every field in this template is populated from existing Drift v2 subsystems.** The
only new computation is the LLM synthesis pass for Section 5 (Business Logic), which
takes the structural data and produces a human-readable narrative. Everything else is
direct data assembly from drift.db.

**Implementation approach:**

```rust
// New intent variant in drift-context/src/request.rs
pub enum ContextIntent {
    AddFeature,
    FixBug,
    Understand,
    Refactor,
    SecurityReview,
    AddTest,
    GenerateSpec,        // NEW — specification generation mode
}

// New weight table for spec generation
ContextIntent::GenerateSpec => [
    ("public_api",        2.0),   // Highest priority — what the module exposes
    ("data_model",        1.8),   // What data it owns
    ("data_flow",         1.7),   // How data moves through it
    ("conventions",       1.5),   // How it's built
    ("constraints",       1.5),   // What invariants must be preserved
    ("security",          1.4),   // What sensitive data it touches
    ("error_handling",    1.3),   // How it handles failures
    ("test_topology",     1.2),   // What's tested
    ("dependencies",      1.0),   // What it depends on
    ("entry_points",      0.8),   // Less important for spec (covered in public API)
    ("memories",          1.6),   // Critical — past human corrections
],
```

### Gap 3: Specification Document Renderer

**Where it lives:** `drift-context/src/formatting/specification.rs` (new file in
existing formatting module)

**What it does:** Takes the scored and budgeted context data from the ContextEngine
and renders it into the structured specification document template above.

This is straightforward template rendering. The ContextEngine already does the hard
work of gathering, scoring, ranking, and budgeting data from all subsystems. The
renderer just formats it into the spec template instead of the existing markdown/XML/JSON
context formats.

**Key addition:** A `SpecificationRenderer` that implements the same `OutputFormatter`
trait as the existing Markdown/XML/JSON renderers:

```rust
pub struct SpecificationRenderer;

impl OutputFormatter for SpecificationRenderer {
    fn format(&self, data: &BudgetedContext, request: &ContextRequest) -> FormattedContext {
        // Render each section of the spec template
        // Sections 1-4, 6-10: Pure data assembly from BudgetedContext
        // Section 5: Marked as "requires human review" with structural hints
        // Section 11: Migration-specific notes from config
    }
}
```

### Gap 4: Migration Tracking System

**Where it lives:** New tables in drift.db (extends existing storage schema),
new module in `drift-analysis/src/structural/migration.rs`

**What it does:** Tracks the state of a migration project:
- Which modules have specs generated
- Which specs have been human-reviewed and approved
- Which modules have been rebuilt in the target language
- Which rebuilt modules have passed contract verification
- Overall migration progress and health

**Schema additions to drift.db:**

```sql
CREATE TABLE migration_projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    source_root TEXT NOT NULL,
    target_language TEXT NOT NULL,
    target_framework TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'  -- active, paused, completed
) STRICT;

CREATE TABLE migration_modules (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES migration_projects(id),
    module_id TEXT NOT NULL,              -- References LogicalModule
    module_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', -- pending, spec_generated, spec_reviewed,
                                            -- spec_approved, rebuilding, rebuilt,
                                            -- verified, complete
    spec_generated_at TEXT,
    spec_reviewed_at TEXT,
    spec_approved_at TEXT,
    rebuilt_at TEXT,
    verified_at TEXT,
    reviewer TEXT,                         -- Who reviewed the spec
    notes TEXT,                            -- Human notes from review
    estimated_effort_hours REAL,           -- From simulation engine
    actual_effort_hours REAL               -- Tracked by team
) STRICT;

CREATE TABLE migration_corrections (
    id TEXT PRIMARY KEY,
    module_id TEXT NOT NULL REFERENCES migration_modules(id),
    section TEXT NOT NULL,                 -- Which spec section was corrected
    original_text TEXT NOT NULL,           -- What Drift generated
    corrected_text TEXT NOT NULL,          -- What the human wrote
    correction_type TEXT NOT NULL,         -- business_logic, boundary, convention,
                                          -- data_model, security, other
    created_at TEXT NOT NULL,
    created_by TEXT                        -- Who made the correction
) STRICT;
```

**Why corrections are stored separately:** Every correction is a training signal.
When Drift generates specs for the next module (or the next project), it can query
past corrections to improve accuracy. "Last time I described a module that touches
the `users` table, the human corrected my business logic description to mention KYC
compliance. This module also touches `users` — I should mention KYC."

This is where the Cortex grounding loop becomes critical. Corrections flow into
Cortex as memories. The grounding loop validates them against the codebase. The
context generation system retrieves relevant memories when generating new specs.
The loop tightens with every human review.

### Gap 5: Cross-Module Contract Verification

**Where it lives:** Extension of existing Contract Tracking system (System 21),
new module `drift-analysis/src/structural/contract_verification.rs`

**What it does:** After a module is rebuilt in the target language, Drift scans the
new code and compares its API contracts against the old code's contracts. This is
bidirectional contract verification:

- **Forward:** Does the new module expose the same API as the old module?
- **Backward:** Do the modules that depended on the old module still work with the new one?

The Contract Tracking system (System 21) already does multi-paradigm contract
extraction (REST, GraphQL, gRPC, event-driven, tRPC) and breaking change
classification. The extension is:

1. **Cross-language contract normalization:** The old module is Java, the new module
   is TypeScript. Normalize both to the unified contract model and compare.
2. **Spec-vs-implementation verification:** Compare the approved spec's API section
   against the actual implementation. Flag any deviations.
3. **Dependency contract propagation:** When module A is rebuilt, check that modules
   B, C, D (which depend on A) still have compatible contracts.

```rust
pub struct ContractVerification {
    pub module_id: String,
    pub old_contracts: Vec<UnifiedContract>,   // From old codebase scan
    pub new_contracts: Vec<UnifiedContract>,   // From new codebase scan
    pub spec_contracts: Vec<SpecContract>,     // From approved specification
    pub mismatches: Vec<ContractMismatch>,
    pub breaking_changes: Vec<BreakingChange>,
    pub compatibility_score: f64,              // 0.0-1.0
    pub verdict: VerificationVerdict,          // Pass, Warn, Fail
}

pub enum VerificationVerdict {
    Pass,                    // All contracts match
    PassWithWarnings,        // Minor differences (additive changes)
    Fail(Vec<String>),       // Breaking changes detected
}
```

This closes the loop. The specification says "this module exposes GET /users/{id}
returning {id, name, email}." The new implementation is scanned. If it exposes
GET /users/{id} returning {id, name} (missing email), that's a contract violation.
The spec is updated, the developer fixes it, and the verification passes.

---

## 4. The Competitive Moat — Layer by Layer

Here's why this is nearly impossible to replicate, broken down by what a competitor
would need to build:

### Layer 1: The Analysis Pipeline (2-3 years)

A competitor needs:
- Tree-sitter parsers for 10 languages with canonical ParseResult
- Call graph builder with 6 resolution strategies
- Taint analysis (source→sink→sanitizer)
- Boundary detection for 33+ ORMs
- Coupling analysis with Tarjan's SCC
- Contract tracking across 4+ API paradigms
- 350+ pattern detectors across 16 categories
- Convention learning with Bayesian confidence
- DNA fingerprinting system
- Decision mining from git history
- Error handling gap analysis
- Test topology mapping
- Constraint extraction
- All of it incremental (content-hash aware)
- All of it performant (10K files < 3s)

This is the foundation. Without it, you can't generate accurate specs because you
don't have accurate structural data. LLMs hallucinate when they don't have ground
truth. Drift's analysis pipeline IS the ground truth.

### Layer 2: The Context Engine (6-12 months)

A competitor needs:
- Intent-weighted scoring across all data sources
- Token-budgeted output with proportional allocation
- Session-aware deduplication
- Model-aware formatting (different tokenizers)
- Graceful degradation when data sources are incomplete
- Package detection for 15 package managers
- Semantic relevance scoring (two-stage: metadata + embeddings)

This is what turns raw analysis data into useful output. Without it, you have a
database full of structural data but no way to assemble it into coherent specs.

### Layer 3: The Memory System (1-2 years)

A competitor needs:
- 23 typed memory types with confidence scoring
- Bitemporal tracking (valid time + transaction time)
- Causal inference graphs
- Multi-factor decay with type-specific half-lives
- HDBSCAN consolidation (episodic → semantic)
- 4-dimension validation with automatic healing
- Contradiction detection and propagation
- Hybrid retrieval (FTS5 + vector + RRF fusion)

This is Cortex. It's what makes the system learn from human corrections. Without it,
every migration project starts from zero. With it, the system gets better with every
project.

### Layer 4: The Grounding Loop (The Killer)

A competitor needs:
- Event-driven memory creation from analysis events
- Groundability classification (which memories can be validated)
- Grounding algorithms that compare memories against scan results
- Confidence adjustment based on grounding scores
- Contradiction generation when memories drift from reality
- Temporal grounding (tracking how grounding scores change over time)

This is the bridge. It's what makes the memory system trustworthy. Without it,
memories are just LLM outputs — they might be wrong and you'd never know. With it,
memories are empirically validated against the codebase.

### Layer 5: The Specification Engine (3-6 months)

This is the new work proposed in this document:
- Module decomposition algorithm
- Specification generation mode
- Document renderer
- Migration tracking
- Cross-module contract verification

This is the smallest layer — but it only works because Layers 1-4 exist. A competitor
who builds Layer 5 without Layers 1-4 gets a spec generator that hallucinates. A
competitor who builds Layers 1-4 without Layer 5 gets a code analysis tool (which is
what CodeScene and SonarQube are). The combination is what's novel.

### Total Replication Cost

| Layer | Effort | Why It's Hard |
|-------|--------|---------------|
| Analysis Pipeline | 2-3 years | 35 subsystems, 10 languages, all interconnected |
| Context Engine | 6-12 months | Token budgeting, intent weighting, multi-source assembly |
| Memory System | 1-2 years | 23 memory types, causal graphs, consolidation, validation |
| Grounding Loop | 6-12 months | Novel — no prior art, requires both analysis + memory |
| Specification Engine | 3-6 months | Requires all four layers above |
| **Total** | **4-7 years** | **And that's with a team that knows what to build** |

The key insight: it's not any single layer that's hard. It's the integration between
all five. The grounding loop requires both the analysis pipeline AND the memory system.
The specification engine requires the context engine AND the module decomposition AND
the contract verification. Each layer depends on the others. A competitor can't build
them independently and bolt them together — they have to be designed as a unified system
from the start.

That's what Drift + Cortex is. That's the moat.

---

## 5. Implementation Strategy — Where This Fits In The V2 Plan

This proposal does NOT change the v2 build order. It adds work to existing phases.

### Phase 5 Addition: Module Decomposition

The coupling analysis system (System 19) is already Phase 5. The module decomposition
algorithm is a natural extension — it consumes coupling data, call graph data, boundary
data, and convention data (all available by Phase 5) to produce logical modules.

**New tasks (estimate: 8-12 tasks):**
- `P5-DECOMP-01` — Create `drift-analysis/src/structural/decomposition.rs`
- `P5-DECOMP-02` — Implement weighted dependency graph construction
- `P5-DECOMP-03` — Implement community detection on condensation graph
- `P5-DECOMP-04` — Implement data access pattern enrichment
- `P5-DECOMP-05` — Implement convention similarity enrichment
- `P5-DECOMP-06` — Implement boundary cohesion scoring
- `P5-DECOMP-07` — Implement iterative boundary refinement
- `P5-DECOMP-08` — Implement public interface extraction per module
- `P5-DECOMP-09` — Create `LogicalModule` types and serialization
- `P5-DECOMP-10` — Storage: `logical_modules` table in drift.db

### Phase 7 Addition: Specification Generation Mode

The context generation system (System 30) is already Phase 7. The specification mode
is a new intent type with a new renderer.

**New tasks (estimate: 6-8 tasks):**
- `P7-SPEC-01` — Add `ContextIntent::GenerateSpec` variant
- `P7-SPEC-02` — Implement spec-mode weight tables
- `P7-SPEC-03` — Create `SpecificationRenderer` in formatting module
- `P7-SPEC-04` — Implement per-section data assembly from BudgetedContext
- `P7-SPEC-05` — Implement LLM synthesis integration for business logic section
- `P7-SPEC-06` — Implement spec document template with all 11 sections
- `P7-SPEC-07` — Create migration tracking tables in drift.db
- `P7-SPEC-08` — Implement migration project CRUD operations

### Phase 8 Addition: MCP Tools for Specification Workflow

The MCP server (System 32) is already Phase 8. New tools for the spec workflow:

**New MCP tools (estimate: 4-6 tasks):**
- `drift_decompose` — Run module decomposition, return logical modules
- `drift_generate_spec` — Generate specification for a logical module
- `drift_migration_status` — Query migration project progress
- `drift_verify_contracts` — Run cross-module contract verification
- `drift_spec_corrections` — Submit human corrections (flows to Cortex)

### Phase 9 Addition: Grounding Loop for Specifications

The Cortex-Drift bridge (System 34) is already Phase 9. The specification corrections
flow naturally into the existing event mapping system:

**New event mappings:**
- `on_spec_generated` → `Insight` memory (low confidence, pending review)
- `on_spec_reviewed` → `Feedback` memory (human reviewed, learning signal)
- `on_spec_approved` → `DecisionContext` memory (high confidence, architectural record)
- `on_spec_corrected` → `ConstraintOverride` memory (correction = override of AI output)
- `on_contract_verified` → `Feedback` memory (verification result = quality signal)

These map directly to existing Cortex memory types. No new memory types needed.

---

## 6. The Business Case

### Pricing Model

| Tier | What You Get | Price Point |
|------|-------------|-------------|
| Community | Full analysis pipeline, CLI, basic MCP | Free |
| Team | + Quality gates, simulation, DNA, CI agent | $X/dev/month |
| Enterprise | + Specification engine, migration tracking, contract verification | $Y/dev/month |
| Migration Services | + Guided migration with Drift + AI agents, human review workflow | Custom |

The specification engine is an Enterprise feature. It's the kind of thing a bank
pays $500K-$2M for as a consulting engagement. Productizing it at $Y/dev/month
undercuts every consulting firm while delivering better results (because the tool
gets smarter with every project, consultants don't).

### Target Customers

1. **Financial services** — Legacy COBOL/Perl/Java codebases, strict security
   requirements (offline-only is a selling point), regulatory compliance means
   specs must be human-reviewed (which is exactly what this workflow enforces)

2. **Government/defense** — Legacy systems that can't be replaced overnight,
   air-gapped environments (Drift runs locally), USMC already contracted MetroStar
   for exactly this kind of work

3. **Healthcare** — HIPAA compliance means source code can't leave the network,
   legacy systems with decades of business logic encoded in code

4. **Any enterprise with >500K lines of legacy code** — The ROI is clear: Morgan
   Stanley saved 280,000 hours. Even at 10% of that efficiency, the tool pays for
   itself in weeks.

### The Morgan Stanley Comparison

Morgan Stanley's DevGen.AI:
- Proprietary, internal only
- Processes code → English specs → human review → rewrite
- 9 million lines processed, 280,000 hours saved
- Single customer, single codebase, single team

Drift's Specification Engine:
- Commercial product, any customer
- Same pipeline but with structural analysis (not just LLM reading code)
- Works offline (no source code leaves the network)
- Gets smarter with every project (grounding loop)
- Verifies the output (contract verification)
- Tracks progress (migration tracking)

The key difference: DevGen.AI feeds raw code to an LLM and asks it to describe what
it does. Drift feeds structurally analyzed, cross-referenced, confidence-scored data
to an LLM and asks it to synthesize a narrative from verified facts. The structural
analysis is the ground truth that prevents hallucination.

---

## 7. Summary

The Specification Engine is not a new product. It's a new mode of Drift v2 that
leverages the entire analysis pipeline (Phases 0-6), the context generation system
(Phase 7), the MCP server (Phase 8), and the Cortex grounding loop (Phase 9) to
produce something no other tool can: machine-verified, human-reviewed, memory-grounded
migration specifications.

The novel loop is:
1. **Analyze** — Drift's 35 subsystems build a complete structural index
2. **Decompose** — Coupling + call graph + boundaries identify logical modules
3. **Specify** — Context engine generates structured specs per module
4. **Review** — Humans correct business logic, approve specs
5. **Remember** — Corrections become Cortex memories, grounded against code
6. **Rebuild** — AI agents consume approved specs to write new code
7. **Verify** — Contract tracking confirms new code matches old contracts
8. **Loop** — Every correction makes the next spec better

The moat is the integration. No competitor has all five layers (analysis + context +
memory + grounding + specification). Building them takes 4-7 years. And even if someone
starts today, Drift will have years of grounded memories from real migration projects
that make its specs more accurate than any fresh competitor.

That's the play. That's the $100.
