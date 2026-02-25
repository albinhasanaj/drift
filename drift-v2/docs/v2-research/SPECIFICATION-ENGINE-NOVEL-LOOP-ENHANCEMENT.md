# The Specification Engine — Novel Loop Enhancement Proposal

> **Status:** Enhancement to DRIFT-SPECIFICATION-ENGINE-PROPOSAL.md
> **Author:** Engineering Lead Review
> **Date:** 2026-02-08
>
> **Thesis:** The original proposal's 7-stage loop is strong but leaves three
> exploitable gaps that a well-funded competitor (AWS Transform, a VC-backed
> startup, or a Big 4 consultancy) could use to build a "good enough" alternative
> in 18-24 months instead of 4-7 years. This document closes those gaps by
> introducing three interlocking mechanisms that transform the loop from
> "hard to replicate" into "architecturally impossible to replicate without
> building the same system."
>
> **The Three Gaps in the Original Proposal:**
> 1. The grounding loop validates memories but doesn't create *causal chains*
>    between corrections — a competitor with a flat memory store could approximate it
> 2. Module decomposition is a one-shot algorithm — it doesn't learn from past
>    decompositions across projects
> 3. Contract verification is binary (pass/fail) — it doesn't feed semantic
>    understanding back into the spec generation weights
>
> **The Three Enhancements:**
> 1. Causal Correction Graphs — corrections form causal DAGs, not flat memories
> 2. Cross-Project Decomposition Transfer — module boundary patterns transfer
>    between codebases via DNA fingerprinting
> 3. Verification-Weighted Spec Refinement — contract verification results
>    dynamically retune the context engine's weight tables

---

## Why The Original Loop Has Gaps

The original proposal describes a 7-stage flywheel. It's genuinely good. But
after auditing the full Cortex codebase (19 crates, 23 memory types, causal
inference engine, 4-dimension validation, HDBSCAN consolidation) and the full
Drift v2 spec (35 systems, 553 implementation tasks, 11 phases), three
structural weaknesses emerge:

### Gap 1: Flat Corrections vs. Causal Correction Chains

The original proposal says: "Human corrections flow into Cortex as memories."
That's true — but they flow as *independent* memories. A correction to Module A's
business logic description and a correction to Module B's data model are stored
as two separate `Feedback` memories with no structural relationship.

**Why this matters:** Cortex already has a causal inference engine (`cortex-causal`)
with DAG enforcement, narrative generation, counterfactual analysis, and chain
confidence scoring. The specification engine proposal *doesn't use any of it*.
That's leaving the most powerful weapon in the arsenal on the table.

**What a competitor could do:** Build a flat key-value memory store (Redis +
embeddings), store corrections as documents, retrieve them via similarity search.
They'd get 60-70% of the grounding loop's value without any causal reasoning.
Semgrep's Memories already does something like this for FP triage.

**What we should do instead:** Every correction creates a causal edge in the
correction graph. "I corrected Module A's business logic because the data flow
from Module C was mischaracterized" creates a causal chain: `Module C data flow
correction → Module A business logic correction`. When Drift generates specs for
Module D (which also consumes Module C's data), it traverses the causal graph
and knows: "corrections to modules consuming Module C's data tend to involve
business logic mischaracterization of the data flow." This is *structural*
learning, not just similarity-based retrieval.

### Gap 2: One-Shot Decomposition vs. Transfer Learning

The original proposal's module decomposition algorithm uses 6 signals (call graph,
data access, conventions, imports, directory structure, boundaries) to cluster a
*single* codebase into logical modules. It's a good algorithm. But it starts from
scratch every time.

**Why this matters:** Drift's DNA System (System 24) already fingerprints codebases
with 10 gene extractors and health scoring. Two codebases with similar DNA profiles
(same frameworks, similar patterns, comparable complexity) will have similar natural
module boundaries. A Spring Boot monolith at Bank A and a Spring Boot monolith at
Bank B will decompose similarly — but the original proposal doesn't exploit this.

**What a competitor could do:** Use an LLM to analyze directory structure and
produce "good enough" module boundaries. For well-structured codebases (which are
the easy cases), this works surprisingly well. The hard cases — tangled legacy
monoliths — are where Drift's 6-signal algorithm shines, but only if it learns
from past decompositions.

**What we should do instead:** After a human reviews and adjusts module boundaries,
store the adjustment as a `DecisionContext` memory linked to the codebase's DNA
profile. When decomposing a new codebase with a similar DNA profile, retrieve
past boundary adjustments and use them as priors in the community detection
algorithm. "Codebases with this DNA profile tend to have their auth logic split
from their user management logic, even though the call graph clusters them
together." This is cross-project transfer learning grounded in structural
similarity, not just pattern matching.

### Gap 3: Binary Verification vs. Semantic Feedback

The original proposal's contract verification is: "Does the new module expose the
same API as the old module? Pass/Fail." That's necessary but insufficient.

**Why this matters:** A contract verification failure contains rich semantic
information about *what kind* of specification errors lead to *what kind* of
implementation errors. If 80% of contract failures in TypeScript→Rust migrations
involve response schema mismatches (not endpoint mismatches), the spec generation
system should learn to weight data model sections higher for TypeScript→Rust
migrations. The original proposal doesn't feed verification results back into
the weight tables.

**What a competitor could do:** Build a simple diff tool that compares OpenAPI
specs. For REST APIs, this covers the majority of contract verification needs.
Drift's multi-paradigm contract tracking (REST, GraphQL, gRPC, AsyncAPI, tRPC,
WebSocket, event-driven) is overkill unless the verification results actually
improve future spec generation.

**What we should do instead:** Every contract verification result becomes a
`Feedback` memory with structured metadata about the failure mode. The context
engine's weight tables for `ContextIntent::GenerateSpec` become *adaptive* —
they start with the static weights from the proposal but adjust based on
accumulated verification feedback. "For TypeScript→Rust migrations, boost
data_model weight from 1.8 to 2.2 because 73% of past verification failures
involved schema mismatches." This closes the loop between verification and
generation in a way that no static system can replicate.

---

## Enhancement 1: Causal Correction Graphs

### The Concept

Every human correction to a specification creates not just a memory, but a node
in a causal DAG. The edges represent *why* the correction was needed — which
upstream data, which structural mischaracterization, which missing context led
to the error.

### How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                  CAUSAL CORRECTION GRAPH                            │
│                                                                     │
│  ┌─────────────┐     caused_by     ┌─────────────┐                │
│  │ Correction:  │◄────────────────── │ Correction:  │                │
│  │ Module A     │                    │ Module C     │                │
│  │ "Business    │                    │ "Data flow   │                │
│  │  logic desc  │                    │  from users  │                │
│  │  wrong —     │                    │  table was   │                │
│  │  this is KYC │                    │  missing     │                │
│  │  compliance" │                    │  the audit   │                │
│  └──────┬──────┘                    │  trail join" │                │
│         │                            └──────┬──────┘                │
│         │ generalizes_to                     │ generalizes_to       │
│         ▼                                    ▼                      │
│  ┌─────────────┐                    ┌─────────────┐                │
│  │ Pattern:     │                    │ Pattern:     │                │
│  │ "Modules     │                    │ "Data flow   │                │
│  │  touching    │                    │  sections    │                │
│  │  users table │                    │  miss JOIN   │                │
│  │  often have  │                    │  paths when  │                │
│  │  compliance  │                    │  tables have │                │
│  │  logic"      │                    │  audit       │                │
│  └─────────────┘                    │  columns"    │                │
│                                      └─────────────┘                │
│                                                                     │
│  When generating specs for Module D (also touches users table):     │
│  → Traverse causal graph                                            │
│  → Find: corrections to users-table modules involve compliance      │
│  → Find: data flow sections miss audit trail JOINs                  │
│  → Boost: business_logic weight for compliance-related modules      │
│  → Inject: "Check for audit trail JOIN paths" into data flow hints  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Integration with Existing Cortex Architecture

This leverages three existing Cortex systems that the original proposal ignores:

1. **CausalEngine** (`cortex-causal/src/engine.rs`): Already supports `add_edge()`
   with DAG enforcement, `infer_and_connect()` for automatic relationship discovery,
   `trace_origins()` / `trace_effects()` for traversal, and `narrative()` for
   human-readable causal explanations. The specification engine just needs to
   *use* it.

2. **NarrativeGenerator** (`cortex-causal/src/narrative/`): Already generates
   causal narratives with section headers, chain confidence scoring, and
   template-based rendering. When a human asks "why did Drift generate this
   business logic description?", the narrative generator can trace back through
   the correction graph and explain: "Based on 3 past corrections to modules
   touching the users table, compliance logic was identified as a common
   mischaracterization. Confidence: 0.82 (chain of 2 corrections)."

3. **InferenceEngine** (`cortex-causal/src/inference/`): Already infers causal
   relationships between memories based on temporal proximity, content similarity,
   and structural overlap. When a new correction is submitted, the inference
   engine can automatically discover causal links to past corrections without
   the human explicitly stating them.

### New Types (Extends Bridge Crate)

```rust
/// A correction to a specification section, with causal metadata.
pub struct SpecCorrection {
    /// The correction itself (stored as migration_corrections in drift.db).
    pub correction_id: String,
    /// The module being corrected.
    pub module_id: String,
    /// Which spec section was corrected (business_logic, data_flow, etc.).
    pub section: SpecSection,
    /// What structural data led to the incorrect generation.
    pub root_cause: CorrectionRootCause,
    /// Which upstream modules' data contributed to the error.
    pub upstream_modules: Vec<String>,
    /// Which Drift subsystems produced the data that was wrong.
    pub data_sources: Vec<DataSourceAttribution>,
}

pub enum CorrectionRootCause {
    /// The call graph missed a relationship.
    MissingCallEdge { from: String, to: String },
    /// The boundary detection missed a data access pattern.
    MissingBoundary { table: String, orm: String },
    /// The convention detection was wrong about a pattern.
    WrongConvention { expected: String, actual: String },
    /// The LLM synthesis hallucinated business logic.
    LlmHallucination { claim: String, reality: String },
    /// The data flow analysis missed a transformation step.
    MissingDataFlow { source: String, sink: String },
    /// The taint analysis missed a sensitive field.
    MissingSensitiveField { table: String, field: String },
    /// Human domain knowledge not capturable by static analysis.
    DomainKnowledge { description: String },
}

pub struct DataSourceAttribution {
    /// Which Drift system produced the data (call_graph, boundary, convention, etc.).
    pub system: String,
    /// Confidence of the data at generation time.
    pub confidence_at_generation: f64,
    /// Whether the data was correct.
    pub was_correct: bool,
}
```

### Why This Is Unreplicable

A competitor building a flat memory store gets similarity-based retrieval.
They can find "past corrections to modules touching the users table." But they
can't answer:

- "What *caused* the correction?" (causal traversal)
- "If we hadn't made correction X, would correction Y still have been needed?"
  (counterfactual analysis — already in CausalEngine)
- "What's the chain confidence of this correction pattern?" (chain_confidence
  scoring — already in `cortex-causal/src/narrative/confidence.rs`)
- "Generate a human-readable explanation of why this spec section was generated
  this way" (NarrativeGenerator — already built)

These require a causal DAG with inference, traversal, and narrative generation.
Cortex has all three. Building them from scratch is 1-2 years of work (the
Cortex memory system estimate from the original proposal). And even then, the
causal graph needs *data* — years of corrections across projects — to be useful.
The data is the moat within the moat.

---

## Enhancement 2: Cross-Project Decomposition Transfer

### The Concept

When Drift decomposes a new codebase into logical modules, it doesn't start from
scratch. It queries Cortex for past decomposition decisions from codebases with
similar DNA profiles, and uses those decisions as Bayesian priors in the community
detection algorithm.

### How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│              CROSS-PROJECT DECOMPOSITION TRANSFER                   │
│                                                                     │
│  Project A (completed migration, Spring Boot monolith):             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐          │
│  │ Auth     │  │ Users    │  │ Payments │  │ Notif    │          │
│  │ Module   │  │ Module   │  │ Module   │  │ Module   │          │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘          │
│       ↓ Human adjusted: split auth from users (call graph          │
│         clustered them together, but auth is cross-cutting)        │
│                                                                     │
│  DNA Profile A: {spring_boot, hibernate, 85K_loc, 4_db_tables,    │
│                  rest_api, jwt_auth, postgresql}                    │
│                                                                     │
│  Stored as DecisionContext memory:                                  │
│    "In Spring Boot monoliths with JWT auth, auth logic should      │
│     be a separate module even when call graph clusters it with      │
│     user management. Reason: auth is cross-cutting, user mgmt      │
│     is domain-specific."                                           │
│    Linked to: DNA profile hash, module boundary adjustment         │
│    Confidence: 0.75 (single project)                               │
│                                                                     │
│  ─────────────────────────────────────────────────────────────     │
│                                                                     │
│  Project B (new migration, Spring Boot monolith):                  │
│  DNA Profile B: {spring_boot, jpa, 120K_loc, 6_db_tables,         │
│                  rest_api, oauth2_auth, postgresql}                 │
│                                                                     │
│  DNA Similarity(A, B) = 0.78 (high — same framework, same DB,     │
│                                similar auth pattern, similar size)  │
│                                                                     │
│  Decomposition algorithm (Drift standalone — D1 compliant):        │
│  1. Run standard 6-signal clustering → produces 5 modules          │
│  2. Call DecompositionPriorProvider trait (no-op if no bridge)      │
│     Bridge impl queries Cortex: "decisions for DNA ≥ 0.6"         │
│  3. Find: "auth should be separate from user management"           │
│  4. Check: does current clustering merge auth + users? YES         │
│  5. Apply prior: split auth into separate module                   │
│  6. Adjust confidence: prior was 0.75, DNA similarity is 0.78     │
│     → applied with weight 0.75 × 0.78 = 0.585                    │
│  7. Present to human: "Suggested split based on similar project.   │
│     Confidence: 0.585. Reason: [causal narrative from bridge]"     │
│                                                                     │
│  If human confirms → confidence increases to 0.85                  │
│  If human rejects → confidence decreases, correction stored        │
│  Either way, the system learns.                                    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Integration with Existing Systems

> **D1/D4 compliance note:** Drift's decomposition algorithm never calls Cortex
> directly. It calls a `DecompositionPriorProvider` trait (defined in drift-core
> with a no-op default). The bridge crate (Phase 9) implements this trait using
> the Cortex systems listed below. In standalone mode, priors are empty.

1. **DNA System (System 24)**: Already produces codebase fingerprints with 10 gene
   extractors (language distribution, framework detection, pattern density, coupling
   metrics, etc.) and a health score. The decomposition transfer uses DNA similarity
   as the weight for applying past priors. **Lives in Drift — no Cortex dependency.**

2. **Cortex Retrieval** (`cortex-retrieval`): Already has hybrid search (FTS5 +
   vector + RRF fusion) with intent-aware weighting. **Accessed only by the bridge
   crate (Phase 9)**, which implements `DecompositionPriorProvider` by querying
   Cortex for past decomposition decisions matching the DNA profile.

3. **Cortex Consolidation** (`cortex-consolidation`): Already consolidates episodic
   memories into semantic memories via HDBSCAN clustering. After 5+ projects with
   similar DNA profiles make the same boundary adjustment, the consolidation engine
   can promote the episodic corrections into a semantic rule. **Runs inside Cortex
   autonomously — Drift never triggers or observes this directly.** The bridge
   simply retrieves the consolidated result when querying for priors.

### New Algorithm: Prior-Weighted Community Detection

```rust
/// Enhanced module decomposition with cross-project transfer learning.
pub fn decompose_with_priors(
    index: &StructuralIndex,
    dna_profile: &DnaProfile,
    past_decisions: &[DecompositionDecision],
) -> Vec<LogicalModule> {
    // Step 1: Standard decomposition (original algorithm)
    let mut modules = decompose(index);

    // Step 2: Retrieve applicable priors
    let applicable_priors: Vec<_> = past_decisions
        .iter()
        .filter(|d| d.dna_similarity(dna_profile) >= 0.6)
        .collect();

    // Step 3: Apply priors as boundary adjustments
    for prior in &applicable_priors {
        let weight = prior.confidence * prior.dna_similarity(dna_profile);
        match &prior.adjustment {
            BoundaryAdjustment::Split { module, into } => {
                if weight >= 0.4 {
                    // Attempt to split the module
                    apply_split(&mut modules, module, into, weight);
                }
            }
            BoundaryAdjustment::Merge { modules: to_merge } => {
                if weight >= 0.5 {  // Higher threshold for merges
                    apply_merge(&mut modules, to_merge, weight);
                }
            }
            BoundaryAdjustment::Reclassify { function, from, to } => {
                if weight >= 0.3 {
                    move_function(&mut modules, function, from, to, weight);
                }
            }
        }
    }

    // Step 4: Re-score cohesion/coupling after adjustments
    rescore_modules(&mut modules, index);

    // Step 5: Annotate each module with applied priors for human review
    for module in &mut modules {
        module.applied_priors = applicable_priors
            .iter()
            .filter(|p| p.affects_module(&module.id))
            .map(|p| AppliedPrior {
                source_project_dna: p.dna_hash.clone(),
                adjustment: p.adjustment.clone(),
                weight: p.confidence * p.dna_similarity(dna_profile),
                narrative: p.causal_narrative.clone(),
            })
            .collect();
    }

    modules
}
```

### Why This Is Unreplicable

The transfer learning requires three things no competitor has simultaneously:

1. **Structural DNA fingerprinting** — not just "it's a Java project" but a
   10-dimensional profile including framework detection, pattern density, coupling
   metrics, and convention similarity. Building this is System 24 (Phase 5).

2. **Grounded decomposition memories** — not just "someone said to split auth"
   but memories validated against the actual codebase structure, with confidence
   scores that increase when confirmed and decrease when contradicted. This is
   the grounding loop (D7).

3. **Consolidation from episodic to semantic** — after enough projects confirm
   the same boundary pattern, it becomes a rule, not a suggestion. This is
   HDBSCAN consolidation (`cortex-consolidation`), already built.

A competitor would need all three. And even if they built them, they'd need
*data* — dozens of completed migration projects with human-reviewed decompositions.
That data takes years to accumulate. First-mover advantage is real here.

---

## Enhancement 3: Verification-Weighted Spec Refinement

### The Concept

Contract verification results don't just pass/fail — they feed back into the
context engine's weight tables, making future spec generation more accurate for
the specific migration path (source language → target language, source framework
→ target framework).

### How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│           VERIFICATION-WEIGHTED SPEC REFINEMENT                     │
│                                                                     │
│  Static Weights (original proposal):                               │
│  ┌──────────────────────────────────────────────┐                  │
│  │ public_api:     2.0                           │                  │
│  │ data_model:     1.8                           │                  │
│  │ data_flow:      1.7                           │                  │
│  │ memories:       1.6                           │                  │
│  │ conventions:    1.5                           │                  │
│  │ constraints:    1.5                           │                  │
│  │ security:       1.4                           │                  │
│  │ error_handling: 1.3                           │                  │
│  │ test_topology:  1.2                           │                  │
│  │ dependencies:   1.0                           │                  │
│  │ entry_points:   0.8                           │                  │
│  └──────────────────────────────────────────────┘                  │
│                          │                                          │
│                          ▼                                          │
│  After 20 modules verified (Java → TypeScript migration):          │
│  ┌──────────────────────────────────────────────┐                  │
│  │ Verification Failure Analysis:                │                  │
│  │                                               │                  │
│  │ Schema mismatch:     12 failures (60%)        │                  │
│  │ Missing endpoint:     4 failures (20%)        │                  │
│  │ Wrong HTTP method:    2 failures (10%)        │                  │
│  │ Auth pattern diff:    2 failures (10%)        │                  │
│  │                                               │                  │
│  │ → data_model failures dominate                │                  │
│  │ → security (auth) failures non-trivial        │                  │
│  └──────────────────────────────────────────────┘                  │
│                          │                                          │
│                          ▼                                          │
│  Adaptive Weights (for Java → TypeScript migrations):              │
│  ┌──────────────────────────────────────────────┐                  │
│  │ public_api:     2.0  (unchanged — low fail%)  │                  │
│  │ data_model:     2.4  (↑ boosted — 60% fails)  │                  │
│  │ data_flow:      1.7  (unchanged)              │                  │
│  │ memories:       1.6  (unchanged)              │                  │
│  │ conventions:    1.5  (unchanged)              │                  │
│  │ constraints:    1.5  (unchanged)              │                  │
│  │ security:       1.7  (↑ boosted — 10% fails)  │                  │
│  │ error_handling: 1.3  (unchanged)              │                  │
│  │ test_topology:  1.2  (unchanged)              │                  │
│  │ dependencies:   1.0  (unchanged)              │                  │
│  │ entry_points:   0.8  (unchanged)              │                  │
│  └──────────────────────────────────────────────┘                  │
│                                                                     │
│  Weight adjustment formula:                                        │
│  adjusted_weight = base_weight × (1 + failure_rate × boost_factor) │
│  where boost_factor = 0.5 (configurable)                           │
│  and failure_rate = section_failures / total_failures              │
│                                                                     │
│  For data_model: 1.8 × (1 + 0.60 × 0.5) = 1.8 × 1.30 = 2.34    │
│  For security:   1.4 × (1 + 0.10 × 0.5) = 1.4 × 1.05 = 1.47    │
│                                                                     │
│  These weights are stored per migration path:                      │
│  Key: (source_lang, target_lang, source_framework, target_fw)      │
│  Value: adjusted weight table                                      │
│  Stored as: Cortex Skill memory (half-life: 365d)                  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Integration with Existing Systems

> **D1/D4 compliance note:** Drift's context engine never calls Cortex directly.
> It calls a `WeightProvider` trait (defined in drift-core with a default returning
> static weights). The bridge crate (Phase 9) implements this trait using the
> Cortex systems listed below. In standalone mode, static weights are used.

1. **Context Generation (System 30)**: Already has intent-weighted scoring with
   configurable weight tables per `ContextIntent`. The adaptive weights are a
   new source of weight overrides, provided via the `WeightProvider` trait.
   **Lives in Drift — no Cortex dependency.**

2. **Contract Tracking (System 21)**: Already classifies breaking changes and
   extracts contracts across 7 paradigms. The verification feedback system
   categorizes failures by spec section, creating the failure distribution
   that drives weight adjustment. **Lives in Drift — no Cortex dependency.**
   Drift stores verification results in drift.db. The bridge reads them and
   creates Feedback memories in Cortex.

3. **Cortex Learning** (`cortex-learning`): Already implements adaptive learning
   from feedback signals. The verification results are a new feedback signal
   type that the learning system can consume. **Accessed only by the bridge.**

4. **Cortex Skill Memory Type**: Already exists in the 23 memory types. Adaptive
   weight tables are stored as `Skill` memories — "For Java→TypeScript migrations,
   boost data_model weight by 30%." Half-life of 365 days means the weights
   slowly decay if not reinforced by new verification results, preventing stale
   optimizations. **The bridge implements `WeightProvider` by reading these
   Skill memories from cortex.db and returning the weight table to Drift.**

### New Types

```rust
/// Verification feedback that drives weight adaptation.
pub struct VerificationFeedback {
    /// The migration path this feedback applies to.
    pub migration_path: MigrationPath,
    /// Which spec section the failure maps to.
    pub section: SpecSection,
    /// The type of contract mismatch.
    pub mismatch_type: ContractMismatchType,
    /// Severity of the mismatch.
    pub severity: VerificationSeverity,
    /// The module that was verified.
    pub module_id: String,
}

pub struct MigrationPath {
    pub source_language: String,
    pub target_language: String,
    pub source_framework: Option<String>,
    pub target_framework: Option<String>,
}

/// Adaptive weight table, stored as a Skill memory in Cortex.
pub struct AdaptiveWeightTable {
    /// The migration path these weights apply to.
    pub migration_path: MigrationPath,
    /// Number of verification results that informed these weights.
    pub sample_size: u32,
    /// The adjusted weights per spec section.
    pub weights: HashMap<SpecSection, f64>,
    /// Failure distribution that produced these weights.
    pub failure_distribution: HashMap<SpecSection, f64>,
    /// When these weights were last updated.
    pub last_updated: DateTime<Utc>,
}

pub enum SpecSection {
    Overview,
    PublicApi,
    DataModel,
    DataFlow,
    BusinessLogic,
    Dependencies,
    Conventions,
    Security,
    Constraints,
    TestRequirements,
    MigrationNotes,
}
```

### Why This Is Unreplicable

The adaptive weight system requires:

1. **Multi-paradigm contract extraction** — you need to detect failures across
   REST, GraphQL, gRPC, AsyncAPI, tRPC, WebSocket, and event-driven APIs.
   System 21 does this. Building it is months of work per paradigm.

2. **Structured failure categorization** — you need to map contract mismatches
   back to spec sections. This requires understanding the spec template structure
   and the data lineage from each section to the contract it produces.

3. **Persistent adaptive weights** — you need a memory system that stores weights
   per migration path, decays them over time, and retrieves them for new projects.
   This is Cortex's Skill memory type with half-life decay.

4. **Enough data to be useful** — adaptive weights need 15-20+ verification
   results per migration path to produce statistically meaningful adjustments.
   This data accumulates over months of real migrations. First-mover advantage
   compounds here.

A competitor with a static spec generator can't adapt. A competitor with a
simple feedback loop (thumbs up/down) can't categorize failures by section.
Only a system with structural contract verification + typed memory + decay-based
persistence can close this loop.

---

## The Enhanced Loop — All Three Working Together

Here's the complete 10-stage loop with all three enhancements integrated:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    THE ENHANCED SPECIFICATION LOOP                       │
│                                                                         │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐              │
│  │ 1. STRUCTURAL │───▶│ 2. MODULE    │───▶│ 3. SPEC      │              │
│  │    INDEX      │    │    DECOMPOSE │    │    GENERATE   │              │
│  │              │    │    + PRIORS   │    │    + ADAPTIVE │              │
│  │ 35 subsystems│    │              │    │    WEIGHTS    │              │
│  │ build full   │    │ 6-signal     │    │              │              │
│  │ structural   │    │ clustering   │    │ Weight tables│              │
│  │ index        │    │ WITH cross-  │    │ adjusted per │              │
│  │              │    │ project      │    │ migration    │              │
│  │              │    │ transfer     │    │ path from    │              │
│  │              │    │ priors from  │    │ past verify  │              │
│  │              │    │ DNA-similar  │    │ failures     │              │
│  │              │    │ projects     │    │              │              │
│  └──────────────┘    └──────────────┘    └──────┬───────┘              │
│                                                  │                      │
│                                                  ▼                      │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐              │
│  │ 7. CONTRACT  │    │ 6. MIGRATION │◀───│ 4. HUMAN     │              │
│  │    VERIFY    │    │    EXECUTE   │    │    REVIEW     │              │
│  │    + FEED    │    │              │    │              │              │
│  │    BACK TO   │◀───│ AI agents    │    │ Engineers    │              │
│  │    WEIGHTS   │    │ rebuild from │    │ correct      │              │
│  │              │    │ approved     │    │ specs with   │              │
│  │ Failures     │    │ specs        │    │ causal       │              │
│  │ categorized  │    │              │    │ attribution  │              │
│  │ by section,  │    └──────────────┘    └──────┬───────┘              │
│  │ stored as    │                                │                      │
│  │ Feedback     │                                │                      │
│  │ memories     │                                │                      │
│  └──────┬───────┘                                │                      │
│         │                                        │                      │
│         ▼                                        ▼                      │
│  ┌──────────────────────────────────────────────────────┐              │
│  │         5. GROUNDED MEMORY + CAUSAL GRAPHS            │              │
│  │                                                        │              │
│  │  THREE MEMORY CHANNELS (not one):                      │              │
│  │                                                        │              │
│  │  Channel A: Correction Memories (Feedback type)        │              │
│  │  → Stored with causal edges to root cause              │              │
│  │  → CausalEngine.infer_and_connect() discovers links    │              │
│  │  → NarrativeGenerator explains correction chains       │              │
│  │  → Grounding loop validates against code reality       │              │
│  │                                                        │              │
│  │  Channel B: Decomposition Decisions (DecisionContext)   │              │
│  │  → Linked to DNA profile hash                          │              │
│  │  → Retrieved for DNA-similar future projects            │              │
│  │  → Consolidation promotes to semantic rules             │              │
│  │  → Grounding loop validates boundaries still hold       │              │
│  │                                                        │              │
│  │  Channel C: Adaptive Weights (Skill type)              │              │
│  │  → Keyed by migration path                             │              │
│  │  → Updated from verification failure distributions      │              │
│  │  → 365-day half-life prevents stale optimization        │              │
│  │  → Retrieved by context engine for weight override      │              │
│  │                                                        │              │
│  │  ALL THREE are grounded against code reality.           │              │
│  │  ALL THREE use causal inference for relationship        │              │
│  │  discovery. ALL THREE consolidate over time.            │              │
│  │  This is the unreplicable core.                         │              │
│  └──────────────────────────────────────────────────────┘              │
│                                                                         │
│  ┌──────────────────────────────────────────────────────┐              │
│  │         8-10. THE COMPOUND EFFECTS                     │              │
│  │                                                        │              │
│  │  8. CAUSAL NARRATIVE GENERATION                        │              │
│  │     "Why was this spec generated this way?"            │              │
│  │     → Traces through correction graph                  │              │
│  │     → Shows chain of past corrections that influenced  │              │
│  │     → Confidence scoring per causal chain               │              │
│  │     → Human can audit the reasoning, not just output   │              │
│  │                                                        │              │
│  │  9. CONSOLIDATION (automatic, background)              │              │
│  │     → After 5+ projects confirm same boundary pattern  │              │
│  │     → HDBSCAN clusters episodic corrections            │              │
│  │     → Promotes to semantic rules                       │              │
│  │     → "Spring Boot monoliths always need auth split"   │              │
│  │     → Rules have higher confidence than individual      │              │
│  │       corrections                                      │              │
│  │                                                        │              │
│  │  10. CONTRADICTION DETECTION (automatic)               │              │
│  │      → If Project A says "split auth" but Project B    │              │
│  │        says "keep auth merged" for similar DNA          │              │
│  │      → Contradiction detected by validation engine     │              │
│  │      → Flagged for human resolution                    │              │
│  │      → Resolution becomes new causal evidence          │              │
│  │      → System learns WHEN to split and WHEN not to     │              │
│  │                                                        │              │
│  └──────────────────────────────────────────────────────┘              │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Implementation Impact — What Changes in the V2 Plan

These enhancements add minimal new code because they leverage existing Cortex
systems. Here's the delta:

### Phase 5 Additions (Module Decomposition — Drift Standalone)

> **D1 compliance:** All Phase 5 types and algorithms live in `drift-analysis`.
> They accept priors as parameters but have ZERO knowledge of Cortex. In standalone
> mode, priors are empty and the algorithm falls back to standard decomposition.
> The bridge (Phase 9) is what retrieves priors from Cortex and passes them in.

| Task ID | Description | Effort |
|---------|-------------|--------|
| P5-DECOMP-11 | Add `DecompositionDecision` type in `drift-analysis` (no Cortex imports) | 2h |
| P5-DECOMP-12 | Implement `decompose_with_priors(index, dna, priors)` — priors param is `&[DecompositionDecision]`, empty in standalone mode | 4h |
| P5-DECOMP-13 | Add `DecompositionPriorProvider` trait in `drift-core` with no-op default (same pattern as `DriftEventHandler`) | 2h |
| P5-DECOMP-14 | Add `AppliedPrior` annotation to `LogicalModule` | 1h |
| P5-DECOMP-15 | Storage: `decomposition_decisions` table in drift.db (Drift's own DB, not cortex.db) | 1h |

### Phase 7 Additions (Spec Generation — Drift Standalone)

> **D1 compliance:** The context engine accepts an optional `WeightOverride` via
> a trait. In standalone mode, static weights are used. The bridge (Phase 9)
> implements the trait and provides adaptive weights from Cortex Skill memories.
> Drift never imports from Cortex.

| Task ID | Description | Effort |
|---------|-------------|--------|
| P7-SPEC-09 | Add `AdaptiveWeightTable` type in `drift-context` (no Cortex imports) | 1h |
| P7-SPEC-10 | Add `WeightProvider` trait in `drift-core` with default returning static weights | 2h |
| P7-SPEC-11 | Implement weight override in ContextEngine — calls `WeightProvider`, uses static weights if no provider registered | 3h |
| P7-SPEC-12 | Add `MigrationPath` key type for weight table lookup in `drift-context` | 1h |

### Phase 9 Additions (Bridge — The ONLY Place That Imports Both)

> **D4 compliance:** All Cortex interaction happens here. The bridge implements
> `DecompositionPriorProvider` (retrieves priors from Cortex) and `WeightProvider`
> (retrieves adaptive weights from Cortex Skill memories). It also handles all
> event→memory mapping and causal edge creation. Nothing in Drift depends on
> this crate — it's a leaf per D4.

| Task ID | Description | Effort |
|---------|-------------|--------|
| P9-BRIDGE-01 | Implement `SpecCorrection` → CausalEngine edge creation (bridge reads correction from drift.db, creates causal edge in cortex.db) | 4h |
| P9-BRIDGE-02 | Implement `CorrectionRootCause` classification in bridge | 3h |
| P9-BRIDGE-03 | Implement `DataSourceAttribution` tracking in bridge | 2h |
| P9-BRIDGE-04 | Bridge implements `DriftEventHandler::on_spec_corrected` → creates Feedback memory + causal edge in Cortex | 2h |
| P9-BRIDGE-05 | Bridge implements `DriftEventHandler::on_contract_verified` → creates VerificationFeedback in Cortex | 2h |
| P9-BRIDGE-06 | Bridge implements `WeightProvider` trait — reads Cortex Skill memories, computes adaptive weights, returns to Drift's context engine | 4h |
| P9-BRIDGE-07 | Bridge implements `DriftEventHandler::on_decomposition_adjusted` → creates DecisionContext memory in Cortex linked to DNA hash | 2h |
| P9-BRIDGE-08 | Bridge implements `DecompositionPriorProvider` trait — queries Cortex for past decisions by DNA similarity, returns to Drift's decomposition algorithm | 3h |
| P9-BRIDGE-09 | Implement causal narrative generation for spec explanations (bridge calls CausalEngine.narrative()) | 3h |

### Total Additional Effort

| Category | Tasks | Estimated Hours |
|----------|-------|----------------|
| Phase 5 additions (Drift standalone) | 5 | ~10h |
| Phase 7 additions (Drift standalone) | 4 | ~7h |
| Phase 9 additions (Bridge only) | 9 | ~25h |
| **Total** | **18** | **~42h** |

That's roughly one week of additional work spread across three phases. The ROI
is enormous: 42 hours of implementation creates three interlocking mechanisms
that add 2-3 years to the replication timeline.

**Architectural guarantee:** Phases 5 and 7 compile and pass all tests without
Cortex existing. The bridge is Phase 9. If Cortex development stalls, Drift
ships with standard decomposition (no priors) and static spec weights. The
enhancements activate only when the bridge is present — exactly like
`DriftEventHandler` events are no-ops without the bridge (D5).

---

## The Replication Timeline — Before and After

### Original Proposal (4-7 years to replicate)

| Layer | Effort | Cumulative |
|-------|--------|-----------|
| Analysis Pipeline | 2-3 years | 2-3 years |
| Context Engine | 6-12 months | 3-4 years |
| Memory System | 1-2 years | 4-5 years |
| Grounding Loop | 6-12 months | 5-6 years |
| Specification Engine | 3-6 months | 5.5-6.5 years |

### Enhanced Proposal (6-10+ years to replicate)

| Layer | Effort | Why Harder | Cumulative |
|-------|--------|-----------|-----------|
| Analysis Pipeline | 2-3 years | Same | 2-3 years |
| Context Engine | 6-12 months | Same | 3-4 years |
| Memory System | 1-2 years | Same | 4-5 years |
| Grounding Loop | 6-12 months | Same | 5-6 years |
| Causal Inference | 6-12 months | NEW — needs DAG, traversal, narrative | 6-7 years |
| Specification Engine | 3-6 months | Same | 6.5-7.5 years |
| Cross-Project Transfer | 6-12 months | NEW — needs DNA + grounded decisions + consolidation | 7-8 years |
| Adaptive Weights | 3-6 months | NEW — needs contract verification + typed feedback | 7.5-8.5 years |
| **Data Accumulation** | **2+ years** | **NEW — causal graphs, decomposition decisions, and adaptive weights all need real project data to be useful** | **9.5-10.5 years** |

The data accumulation row is the killer. Even if a competitor builds all the
systems, they start with empty causal graphs, zero decomposition priors, and
static weight tables. Drift will have years of accumulated, grounded, causally-
linked migration intelligence. That data is the ultimate moat.

---

## Competitive Landscape Update (Feb 2026)

### AWS Transform (launched May 2025)

AWS Transform is the closest commercial competitor. It uses agentic AI for
mainframe modernization (COBOL → Java/cloud-native). Key differences:

- **Cloud-dependent** — requires AWS infrastructure, sends code to AWS services
- **Mainframe-focused** — COBOL/JCL/BMS, not general-purpose multi-language
- **No memory system** — each migration starts from scratch
- **No grounding loop** — no empirical validation of AI-generated specs
- **No cross-project transfer** — no DNA fingerprinting or decomposition priors

AWS Transform is a serious product with serious backing. But it's architecturally
limited to cloud-hosted, mainframe-specific migrations. Drift's offline-first,
multi-language, memory-grounded approach is complementary, not competitive — and
for the enterprise segments that can't send code to the cloud (finance, defense,
healthcare), Drift is the only option.

### Semgrep Memories (launched Jan 2025)

Semgrep's "Memories" feature stores organizational context for false positive
triage. It's the closest thing to Cortex's memory system in the market. Key
differences:

- **Flat memories** — no causal graphs, no consolidation, no grounding
- **Security-only** — FP/TP labels for SAST findings, not general-purpose
- **No structural analysis** — Semgrep has pattern matching but no call graph,
  no coupling analysis, no boundary detection, no convention learning
- **Cloud-dependent** — Semgrep Assistant requires cloud API access
- **No specification generation** — memories improve triage, not migration

Semgrep Memories validates the market for "AI tools that learn from human
feedback." But it's a single-dimension memory (FP/TP labels) vs. Cortex's
23-type, causally-linked, grounded memory system. The gap is structural.

### EverMemOS (launched Jan 2026)

EverMemOS is a general-purpose AI memory system with episodic→semantic
consolidation. It's the closest academic competitor to Cortex. Key differences:

- **General-purpose** — not code-aware, no structural analysis integration
- **No grounding** — memories are not validated against external data sources
- **Cloud-hosted** — API-based, not offline-capable
- **No causal inference** — episodic→semantic consolidation but no causal DAGs
- **No specification generation** — memory system only, no analysis pipeline

EverMemOS validates the architecture of episodic→semantic consolidation (which
Cortex already implements via HDBSCAN). But without code-aware grounding, it
can't validate memories against codebase reality. The grounding loop remains
unique to Drift+Cortex.

### Morgan Stanley DevGen.AI (internal, 2024-2025)

DevGen.AI translates legacy code into plain English specifications, which
developers then use to rewrite in modern languages. It processed 9M lines and
saved 280K developer hours. Key differences:

- **Proprietary, single-customer** — not commercially available
- **LLM-only** — feeds raw code to LLMs, no structural analysis pipeline
- **No memory system** — each translation is independent
- **No verification** — no contract comparison between old and new code
- **No grounding** — no empirical validation of generated specs

DevGen.AI proves the market. Drift's specification engine does the same thing
but with structural analysis (ground truth), memory (learning), grounding
(validation), and verification (correctness). The quality gap is structural.

---

## Summary: The Three-Layer Moat

The original proposal creates a moat through system complexity (35 subsystems,
553 tasks). The enhancements create a moat through *emergent intelligence* —
the system gets smarter in ways that can't be replicated by building the same
components, because the intelligence comes from accumulated data flowing through
causal graphs, cross-project transfer, and adaptive optimization.

**Layer 1 (Systems):** 35 analysis subsystems, 19 Cortex crates, 11 build phases.
A competitor needs 4-7 years to build equivalent systems.

**Layer 2 (Integration):** Causal correction graphs, DNA-linked decomposition
transfer, verification-weighted spec refinement. A competitor needs the systems
AND the integration architecture. Add 2-3 years.

**Layer 3 (Data):** Accumulated causal chains from real corrections, decomposition
priors from real projects, adaptive weights from real verifications. A competitor
needs the systems AND the integration AND years of real-world usage data. This
layer is time-locked — you can't buy it, you can't shortcut it, you can only
earn it by being first to market with a system that accumulates it.

That's the play. Three layers deep. Each one multiplies the replication cost
of the others. And the deepest layer — the data — is the one that compounds
with time.

---

## Appendix: Memory Type Mapping for Specification Engine

How each specification engine event maps to Cortex memory types, leveraging
the existing 23-type system without adding new types:

| Event | Memory Type | Content Type | Causal Edges | Grounding |
|-------|------------|-------------|-------------|-----------|
| Spec generated | `Insight` | InsightContent | → source structural data | Groundable (compare spec vs code) |
| Spec corrected (business logic) | `Feedback` | FeedbackContent | → root cause correction, → upstream modules | Groundable (correction validated against code) |
| Spec corrected (boundary) | `DecisionContext` | DecisionContextContent | → DNA profile, → decomposition decision | Groundable (boundary validated against coupling) |
| Spec approved | `Decision` | DecisionContent | → all corrections that led to approval | Groundable (approved spec vs code) |
| Module boundary adjusted | `DecisionContext` | DecisionContextContent | → DNA profile hash, → prior decisions | Groundable (boundary vs coupling metrics) |
| Contract verification pass | `Feedback` | FeedbackContent | → approved spec, → implementation | Groundable (contracts match) |
| Contract verification fail | `Feedback` | FeedbackContent | → spec section, → mismatch type | Groundable (contracts don't match) |
| Adaptive weight update | `Skill` | SkillContent | → verification failures that drove update | Partially groundable (weights vs failure rates) |
| Decomposition prior applied | `Procedural` | ProceduralContent | → source project DNA, → target project DNA | Groundable (prior vs actual boundary) |
| Consolidation: corrections → rule | `Semantic` | SemanticContent | → all episodic corrections consolidated | Groundable (rule vs code patterns) |

Every single mapping uses an existing memory type. Zero new types needed.
The specification engine is a *consumer* of Cortex's type system, not an
extension of it. This is architecturally clean and consistent with D2
(memory types stay generic in cortex-core).
