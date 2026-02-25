# Specification Engine — Comprehensive Test Plan

> **Scope:** All testable surfaces from SPECIFICATION-ENGINE-NOVEL-LOOP-ENHANCEMENT.md
> and DRIFT-SPECIFICATION-ENGINE-PROPOSAL.md.
> **Convention:** Test IDs follow existing pattern: `T{phase}-{system}-{number}`.
> Phase 5 = decomposition, Phase 7 = spec generation, Phase 9 = bridge.
> **Coverage target:** ≥80% line coverage per crate (`cargo tarpaulin`).
> **D1 compliance:** Phase 5 and 7 tests compile without Cortex. Phase 9 tests
> require both systems.
>
> **Test categories per requirement:**
> 1. Happy path — basic correct usage
> 2. Edge cases — empty inputs, max values, boundary conditions
> 3. Adversarial — malformed data, injection attempts, unexpected nulls
> 4. Concurrency — race conditions, parallel access, deadlock scenarios
> 5. Corruption recovery — interrupted writes, partial state, invalid persisted data
> 6. Regression — specific bugs we'd never want to reintroduce
>
> For each test: what production failure it prevents.
> Generated: 2026-02-08

---

## Phase 5 Tests: Module Decomposition (Drift Standalone)

> **Crate:** `drift-analysis`
> **File:** `drift-analysis/tests/decomposition_test.rs`
> **D1:** Zero Cortex imports. `DecompositionPriorProvider` uses no-op default.

### 1. Happy Path

| ID | Test | Prevents |
|----|------|----------|
| `T5-DECOMP-01` | **6-signal decomposition produces valid modules.** Feed a synthetic `StructuralIndex` with 3 clear clusters (disjoint call graphs, separate tables, different conventions). Assert: 3 `LogicalModule`s returned, each with non-empty `files`, `public_interface`, `data_dependencies`. Cohesion > 0.5 for all, coupling < 0.3 for all. | Production: decomposition returns garbage modules with no files or inverted cohesion/coupling, causing specs to describe empty modules. |
| `T5-DECOMP-02` | **Public interface extraction is correct.** Create 2 modules where Module A calls 3 functions in Module B. Assert: those 3 functions appear in Module B's `public_interface` and NOT in `internal_functions`. | Production: public API section of spec lists internal functions, causing migration to expose implementation details. |
| `T5-DECOMP-03` | **Data dependencies extracted per module.** Module touches `users` (Read) and `orders` (ReadWrite) tables via Sequelize. Assert: `data_dependencies` contains both with correct `DataDependencyKind::Database`, correct operations, and `sensitive_fields` includes `email` from boundary detection. | Production: spec's data model section is empty, migration builds module without database access layer. |
| `T5-DECOMP-04` | **Convention profile populated.** Module uses camelCase naming, try/catch error handling, winston logging. Assert: `convention_profile` reflects all three. | Production: spec's conventions section is blank, migrated code uses wrong naming/error patterns for the target codebase. |
| `T5-DECOMP-05` | **Module dependency graph is acyclic.** Decompose a codebase with 5 modules. Assert: the dependency graph between modules (from `ModuleDependency`) has no cycles. Verify with topological sort. | Production: circular module dependencies make migration ordering impossible — you can't rebuild Module A before Module B if they depend on each other. |
| `T5-DECOMP-06` | **`decompose_with_priors()` applies a Split prior.** Provide one `DecompositionDecision` with `BoundaryAdjustment::Split` at weight 0.6. Standard decomposition clusters auth+users together. Assert: after priors, auth and users are separate modules. `AppliedPrior` annotation present on both. | Production: cross-project transfer silently fails, system never learns from past decompositions. |
| `T5-DECOMP-07` | **`decompose_with_priors()` with empty priors equals standard decomposition.** Run both `decompose()` and `decompose_with_priors(index, dna, &[])`. Assert: identical output. | Production: standalone mode (no bridge) produces different results than bridge mode with no priors, causing inconsistent behavior. |
| `T5-DECOMP-08` | **`DecompositionPriorProvider` no-op default returns empty vec.** Instantiate the trait's default impl. Assert: `get_priors()` returns `Ok(vec![])`. | Production: D1 violation — Drift panics in standalone mode because the trait has no default. |

### 2. Edge Cases

| ID | Test | Prevents |
|----|------|----------|
| `T5-DECOMP-09` | **Single-file codebase → single module.** Index with 1 file, 1 function, 0 call edges. Assert: exactly 1 `LogicalModule` with cohesion 1.0, coupling 0.0. | Production: decomposition panics on trivial codebases, blocking spec generation for small projects. |
| `T5-DECOMP-10` | **10,000-file codebase completes in < 10s.** Synthetic index with 10K files, 50K call edges, 200 tables. Assert: decomposition completes within time budget. | Production: decomposition hangs on large enterprise codebases, making the tool unusable for the exact customers who need it most. |
| `T5-DECOMP-11` | **All files in one SCC → single module.** Every function calls every other function (complete graph). Assert: 1 module, cohesion 1.0. | Production: Tarjan's SCC produces a single giant component, decomposition crashes trying to split it. |
| `T5-DECOMP-12` | **Zero call edges → directory-based decomposition.** Index with files but no call edges (e.g., config files, static assets). Assert: modules formed from directory structure signal alone. | Production: codebases with no function calls (pure data, config repos) produce 0 modules, blocking the pipeline. |
| `T5-DECOMP-13` | **Prior with weight exactly at threshold (0.4 for Split).** Assert: prior IS applied (boundary inclusive). Prior at 0.399 → NOT applied. | Production: off-by-one in threshold comparison causes priors to be silently dropped or incorrectly applied. |
| `T5-DECOMP-14` | **Prior references a module that doesn't exist in current decomposition.** Split prior says "split module auth_users" but current decomposition has no module with that name. Assert: prior is skipped gracefully, no panic, no corruption. | Production: stale priors from old projects crash decomposition of new projects with different structure. |
| `T5-DECOMP-15` | **Cohesion and coupling scores are always in [0.0, 1.0].** Generate 100 random decompositions with varying inputs. Assert: all scores clamped. | Production: NaN or >1.0 scores break downstream sorting, comparison, and display logic. |
| `T5-DECOMP-16` | **DNA similarity of 0.0 → no priors applied.** Provide priors with DNA similarity 0.0 to current profile. Assert: zero priors applied, output equals standard decomposition. | Production: completely unrelated projects' decomposition decisions pollute new project's module boundaries. |

### 3. Adversarial

| ID | Test | Prevents |
|----|------|----------|
| `T5-DECOMP-17` | **Module name with SQL injection payload.** File path contains `'; DROP TABLE modules; --`. Assert: module name is sanitized or escaped before storage. Query `decomposition_decisions` table — it still exists. | Production: attacker crafts a filename that corrupts drift.db when decomposition results are persisted. |
| `T5-DECOMP-18` | **Module name with 100KB Unicode string.** File path is 100KB of CJK characters. Assert: module name is truncated to reasonable length (≤ 1024 chars), no OOM. | Production: pathological filenames cause unbounded memory allocation in module name derivation. |
| `T5-DECOMP-19` | **NaN in coupling metrics.** Inject NaN into a call edge weight. Assert: decomposition handles gracefully (skip edge or treat as 0.0), does not propagate NaN into cohesion/coupling scores. | Production: one corrupted call edge poisons all module scores with NaN, making every module look equally good/bad. |
| `T5-DECOMP-20` | **Negative confidence in prior.** `DecompositionDecision` with confidence -0.5. Assert: prior is rejected or clamped to 0.0, not applied with negative weight (which would invert the adjustment). | Production: malformed prior from corrupted cortex.db inverts a split into a merge, producing wrong module boundaries. |
| `T5-DECOMP-21` | **Contradictory priors.** Two priors: one says Split(auth, users), other says Merge(auth, users), both weight 0.6. Assert: deterministic resolution (e.g., higher confidence wins, or first-wins), no infinite loop. | Production: contradictory priors from different projects cause the algorithm to oscillate or deadlock. |

### 4. Concurrency

| ID | Test | Prevents |
|----|------|----------|
| `T5-DECOMP-22` | **Parallel decomposition of same index from 4 threads.** Spawn 4 threads, each calling `decompose()` on the same `StructuralIndex` (read-only). Assert: all 4 produce identical results, no data races. | Production: concurrent spec generation requests for the same project produce inconsistent module boundaries. |
| `T5-DECOMP-23` | **Decomposition while index is being updated.** One thread runs decomposition, another thread adds files to the index. Assert: decomposition either sees a consistent snapshot or returns an error — never a partial/torn read. | Production: incremental scan updates the index mid-decomposition, producing modules that reference files that don't exist. |

### 5. Corruption Recovery

| ID | Test | Prevents |
|----|------|----------|
| `T5-DECOMP-24` | **`decomposition_decisions` table missing.** Delete the table from drift.db, then call `decompose_with_priors()`. Assert: graceful fallback to standard decomposition (no priors), table is recreated on next write. | Production: database migration failure leaves drift.db without the new table, blocking all decomposition. |
| `T5-DECOMP-25` | **Corrupted prior in `decomposition_decisions` table.** Insert a row with invalid JSON in the `adjustment` column. Assert: that row is skipped, valid rows still loaded, warning logged. | Production: one corrupted row prevents loading ALL priors, losing all cross-project transfer learning. |
| `T5-DECOMP-26` | **Interrupted write to `decomposition_decisions`.** Simulate crash mid-transaction (write 3 of 5 decisions, then abort). Assert: table has 0 new rows (transaction rolled back), not 3 partial rows. | Production: partial writes leave the table in an inconsistent state where some modules have decisions and others don't. |

### 6. Regression

| ID | Test | Prevents |
|----|------|----------|
| `T5-DECOMP-27` | **Decomposition is deterministic.** Same input → same output, 10 consecutive runs. Assert: module IDs, file assignments, scores are byte-identical. | Production: non-deterministic decomposition causes specs to change on every run, confusing reviewers and breaking diffing. |
| `T5-DECOMP-28` | **Empty `public_interface` only when module has zero external callers.** If any function in the module is called from outside, `public_interface` must be non-empty. | Production: module appears to have no API, spec's Public API section is empty, migration builds an isolated module that nothing can call. |
| `T5-DECOMP-29` | **`estimated_complexity` matches sum of file line counts.** Assert: `estimated_complexity` equals total lines across all files in the module (±5% for comment stripping). | Production: complexity estimate is wildly wrong, effort estimation in spec is off by 10x, project planning fails. |

---

## Phase 7 Tests: Specification Generation & Adaptive Weights (Drift Standalone)

> **Crate:** `drift-context`
> **File:** `drift-context/tests/specification_test.rs`
> **D1:** Zero Cortex imports. `WeightProvider` uses default (static weights).

### 7A. Spec Generation — Happy Path

| ID | Test | Prevents |
|----|------|----------|
| `T7-SPEC-01` | **`ContextIntent::GenerateSpec` produces all 11 sections.** Create a `LogicalModule` with populated fields (public_interface, data_dependencies, convention_profile, etc.). Call `ContextEngine::generate()` with `GenerateSpec` intent. Assert: output contains all 11 section headers (Overview, Public API, Data Model, Data Flow, Business Logic, Dependencies, Conventions, Security, Constraints, Test Requirements, Migration Notes). | Production: spec document is missing sections, human reviewer sees incomplete spec, migration proceeds without critical information (e.g., missing Security section means sensitive data handling is undocumented). |
| `T7-SPEC-02` | **Static weight table for `GenerateSpec` matches spec.** Assert: `ContextIntent::GenerateSpec` weight table has `public_api: 2.0`, `data_model: 1.8`, `data_flow: 1.7`, `memories: 1.6`, `conventions: 1.5`, `constraints: 1.5`, `security: 1.4`, `error_handling: 1.3`, `test_topology: 1.2`, `dependencies: 1.0`, `entry_points: 0.8`. | Production: weight table drift causes spec sections to be prioritized incorrectly — e.g., entry_points ranked above public_api means the spec focuses on internal call sites instead of the module's external interface. |
| `T7-SPEC-03` | **`SpecificationRenderer` formats Public API section correctly.** Module has 3 public functions with signatures and callers. Assert: rendered output contains a table with all 3 functions, their signatures, caller modules, and descriptions. No internal functions leak into the table. | Production: public API table includes internal functions, migration team builds a module that exposes implementation details as public API. |
| `T7-SPEC-04` | **`SpecificationRenderer` formats Data Model section correctly.** Module touches 2 tables via Sequelize ORM with Read and ReadWrite operations. Assert: rendered output contains both tables, correct ORM attribution, correct operations, and sensitive fields flagged. | Production: data model section omits a table, migrated module silently drops database access, data loss in production. |
| `T7-SPEC-05` | **Business Logic section is marked as requiring human review.** Assert: Section 5 output contains the `⚠️` marker and explicit text indicating human verification is required. | Production: reviewer assumes all sections are machine-verified, skips business logic review, incorrect business logic propagates to migrated code. |
| `T7-SPEC-06` | **`WeightProvider` default returns static weights.** Instantiate the trait's default impl. Call `get_weights(migration_path)`. Assert: returns the static weight table from the spec, identical to `ContextIntent::GenerateSpec` defaults. | Production: D1 violation — Drift panics in standalone mode because `WeightProvider` has no default, blocking spec generation without Cortex. |
| `T7-SPEC-07` | **Spec generation with `WeightProvider` override applies custom weights.** Create a `WeightProvider` that returns `data_model: 2.4` (boosted). Generate spec. Assert: Data Model section receives proportionally more token budget than with static weights. | Production: adaptive weights from bridge are accepted but silently ignored, verification feedback loop has no effect on spec quality. |
| `T7-SPEC-08` | **Migration tracking tables created on first use.** Call migration project CRUD on a fresh drift.db. Assert: `migration_projects`, `migration_modules`, `migration_corrections` tables exist with correct schemas. Insert a project, module, and correction — all succeed. | Production: first-time user hits "table not found" error, migration tracking is unusable until manual schema migration. |

### 7B. Spec Generation — Edge Cases

| ID | Test | Prevents |
|----|------|----------|
| `T7-SPEC-09` | **Module with zero public functions → Public API section says "No public interface detected."** Assert: section is present but explicitly states no public API, not an empty table. | Production: empty table renders as broken markdown, reviewer thinks the renderer crashed. |
| `T7-SPEC-10` | **Module with 500 public functions → section is truncated with count.** Assert: table shows top N functions (by call count) and a note: "Showing 50 of 500 public functions. Full list available via `drift_generate_spec --full`." | Production: 500-row table blows up the spec document to 50+ pages, making it unreadable and unusable for human review. |
| `T7-SPEC-11` | **Module with zero data dependencies → Data Model section says "No database access detected."** Assert: section present, explicit message, not empty. | Production: reviewer assumes data model section was accidentally omitted, files a bug instead of proceeding. |
| `T7-SPEC-12` | **`MigrationPath` with `None` frameworks → weight lookup still works.** Create `MigrationPath { source_language: "Java", target_language: "TypeScript", source_framework: None, target_framework: None }`. Assert: `WeightProvider` returns weights (falls back to language-only lookup). | Production: projects without framework detection get no adaptive weights, even though language-level patterns exist. |
| `T7-SPEC-13` | **`SpecSection` enum covers all 11 sections.** Assert: `SpecSection` has exactly 11 variants matching the template (Overview, PublicApi, DataModel, DataFlow, BusinessLogic, Dependencies, Conventions, Security, Constraints, TestRequirements, MigrationNotes). | Production: new section added to template but not to enum, weight adjustments for that section silently fail. |
| `T7-SPEC-14` | **Spec generation with all weight overrides set to 0.0.** Assert: spec still generates (no division by zero), all sections present but with minimal content. Token budget distributed equally as fallback. | Production: adversarial or corrupted weight table with all zeros causes panic in proportional budget allocation. |
| `T7-SPEC-15` | **Migration module status transitions are enforced.** Assert: `pending → spec_generated → spec_reviewed → spec_approved → rebuilding → rebuilt → verified → complete` is the only valid forward path. Attempting `pending → spec_approved` (skipping generation) returns error. | Production: module marked as approved without ever having a spec generated, migration proceeds with no specification. |
| `T7-SPEC-16` | **Spec generation for module with only convention data (no call graph, no data deps).** Assert: spec generates successfully with Overview, Conventions, and Migration Notes populated. Other sections contain "Insufficient data" messages. | Production: partially-analyzed codebases (e.g., config-only repos) crash spec generation because it assumes all data sources are present. |

### 7C. Spec Generation — Adversarial

| ID | Test | Prevents |
|----|------|----------|
| `T7-SPEC-17` | **Module name with markdown injection.** Module name is `## Injected Header\n\nMalicious content`. Assert: module name is escaped in the rendered spec. The output has exactly 11 `## ` headers (the template sections), not 12. | Production: attacker crafts a directory name that injects arbitrary content into the spec document, misleading reviewers. |
| `T7-SPEC-18` | **Function signature with XSS payload in description.** Public function description contains `<script>alert('xss')</script>`. Assert: HTML is escaped or stripped in rendered output. | Production: spec viewed in a web-based review tool executes injected JavaScript. |
| `T7-SPEC-19` | **`AdaptiveWeightTable` with negative weights.** Weight table has `data_model: -1.5`. Assert: negative weights are clamped to 0.0 before use, not applied as negative (which would invert section priority). | Production: corrupted Skill memory from Cortex produces negative weights, spec generation inverts priorities — least important sections get most tokens. |
| `T7-SPEC-20` | **`AdaptiveWeightTable` with NaN weight.** Assert: NaN is replaced with the static default for that section. | Production: one NaN poisons the entire weight normalization, all sections get NaN budget → empty spec. |
| `T7-SPEC-21` | **`MigrationPath` with empty strings.** `source_language: ""`, `target_language: ""`. Assert: treated as unknown migration path, falls back to static weights. No panic, no empty key in lookup table. | Production: empty migration path creates a phantom entry in the weight table that matches everything, corrupting all future lookups. |
| `T7-SPEC-22` | **Correction text with 1MB of content.** `migration_corrections.corrected_text` is 1MB. Assert: stored successfully (TEXT column has no limit in SQLite), but rendered spec truncates the correction display to a reasonable length with a "see full correction" link. | Production: one massive correction causes the spec document to be 1MB+, crashing markdown renderers and review tools. |

### 7D. Spec Generation — Concurrency

| ID | Test | Prevents |
|----|------|----------|
| `T7-SPEC-23` | **Parallel spec generation for 10 modules from same project.** Spawn 10 threads, each generating a spec for a different module in the same project. Assert: all 10 complete without deadlock, each spec references only its own module's data, no cross-contamination. | Production: parallel spec generation for a 47-module project causes data races — Module A's spec contains Module B's public API. |
| `T7-SPEC-24` | **Concurrent migration status updates.** 4 threads update different modules' statuses simultaneously (`spec_generated`, `spec_reviewed`, `spec_approved`, `rebuilt`). Assert: all updates succeed, no lost writes, each module has correct status. | Production: concurrent reviewers approving different modules cause SQLite write conflicts, some approvals are silently lost. |
| `T7-SPEC-25` | **Spec generation while weight table is being updated.** One thread generates a spec (reads weights), another thread updates the `AdaptiveWeightTable` (writes weights). Assert: spec generation sees a consistent snapshot of weights — either all old or all new, never a mix. | Production: spec generated with half-updated weights produces inconsistent section priorities — some sections use old weights, others use new. |

### 7E. Spec Generation — Corruption Recovery

| ID | Test | Prevents |
|----|------|----------|
| `T7-SPEC-26` | **`migration_projects` table missing.** Delete table from drift.db. Call `create_migration_project()`. Assert: table is recreated, project is created successfully. | Production: database migration failure leaves drift.db without migration tables, blocking all migration tracking. |
| `T7-SPEC-27` | **`migration_modules` row with invalid status string.** Insert a row with `status = 'banana'`. Assert: reading the row returns an error for that row but doesn't crash the query. Other valid rows are still returned. | Production: one corrupted row prevents loading the entire migration project status, blocking progress tracking for all modules. |
| `T7-SPEC-28` | **Interrupted spec generation leaves no partial spec.** Simulate crash mid-render (after 6 of 11 sections). Assert: no partial spec is persisted. `migration_modules.status` remains `pending`, not `spec_generated`. | Production: partial spec is marked as generated, reviewer sees a 6-section spec and assumes the other 5 sections are intentionally empty. |
| `T7-SPEC-29` | **Corrupted `AdaptiveWeightTable` JSON in drift.db.** Store `{"weights": "not_a_map"}` in the weight table storage. Assert: weight loading falls back to static defaults with a warning, not a panic. | Production: one corrupted weight entry prevents all spec generation for that migration path, even though static weights would work fine. |

### 7F. Spec Generation — Regression

| ID | Test | Prevents |
|----|------|----------|
| `T7-SPEC-30` | **Spec generation is deterministic.** Same module, same weights, same data → same spec output, 10 consecutive runs. Assert: byte-identical output (excluding timestamps). | Production: non-deterministic spec generation causes diffs on every run, making it impossible to track what actually changed between reviews. |
| `T7-SPEC-31` | **Weight override does not mutate the static weight table.** Apply a `WeightProvider` override, generate spec, then generate another spec with default provider. Assert: second spec uses original static weights, not the overridden values. | Production: weight override permanently mutates the global weight table, all subsequent specs use wrong weights even in standalone mode. |
| `T7-SPEC-32` | **`SpecSection::BusinessLogic` always has the highest token budget among narrative sections.** Assert: regardless of weight configuration, BusinessLogic section receives at least 20% of the total narrative token budget. | Production: weight adjustment reduces BusinessLogic to near-zero tokens, the most critical section (the one humans review most) becomes a single sentence. |
| `T7-SPEC-33` | **Migration correction preserves original text verbatim.** Store a correction with `original_text` containing Unicode, newlines, and special characters. Read it back. Assert: byte-identical to input. | Production: original text is mangled during storage, making it impossible to diff what Drift generated vs. what the human wrote. |

---

## Phase 9 Tests: Bridge — Causal Corrections, Decomposition Transfer, Adaptive Weights

> **Crate:** `cortex-drift-bridge`
> **File:** `cortex-drift-bridge/tests/spec_bridge_test.rs`
> **D4:** This is the ONLY crate that imports both Drift and Cortex.
> All tests require both systems present.

### 9A. Causal Correction Graphs — Happy Path

| ID | Test | Prevents |
|----|------|----------|
| `T9-BRIDGE-01` | **`SpecCorrection` creates a causal edge in CausalEngine.** Create a `SpecCorrection` with `root_cause: MissingCallEdge { from: "auth", to: "users" }` and `upstream_modules: ["module_c"]`. Bridge processes it. Assert: CausalEngine contains an edge from the upstream module's memory to the correction memory with relation `Caused`, strength proportional to confidence. | Production: corrections are stored as flat memories with no causal links, the system can never answer "why was this spec wrong?" — losing the entire value of Enhancement 1. |
| `T9-BRIDGE-02` | **`CorrectionRootCause` classification maps to correct causal relation.** For each of the 7 `CorrectionRootCause` variants (MissingCallEdge, MissingBoundary, WrongConvention, LlmHallucination, MissingDataFlow, MissingSensitiveField, DomainKnowledge), create a `SpecCorrection` and process it. Assert: each produces a causal edge with the correct relation type and metadata. | Production: root cause classification is wrong, causal graph contains edges with incorrect semantics, downstream traversal produces misleading explanations. |
| `T9-BRIDGE-03` | **`DataSourceAttribution` tracking records which Drift system was wrong.** Create a `SpecCorrection` with `data_sources: [{ system: "call_graph", confidence_at_generation: 0.85, was_correct: false }, { system: "boundary", confidence_at_generation: 0.72, was_correct: true }]`. Assert: bridge stores attribution metadata on the causal edge, queryable later for system reliability analysis. | Production: no attribution tracking means we can never identify which Drift subsystem is producing bad data — can't improve what we can't measure. |
| `T9-BRIDGE-04` | **`DriftEventHandler::on_spec_corrected` creates Feedback memory + causal edge.** Fire the event with a business logic correction. Assert: (1) a `Feedback` memory exists in cortex.db with `FeedbackContent` containing the correction text, (2) a causal edge links it to the original spec's `Insight` memory, (3) the Feedback memory's tags include the module ID and spec section. | Production: `on_spec_corrected` is a no-op in the bridge (forgot to implement), corrections never reach Cortex, the grounding loop never learns from human reviews. |
| `T9-BRIDGE-05` | **`DriftEventHandler::on_contract_verified` (pass) creates positive Feedback memory.** Verify a module with all contracts matching. Assert: `Feedback` memory created with positive sentiment, linked to the approved spec's `Decision` memory, confidence boost applied to the spec memory. | Production: successful verifications are silently dropped, the system only learns from failures — positive reinforcement is lost, confidence scores never increase. |
| `T9-BRIDGE-06` | **`DriftEventHandler::on_contract_verified` (fail) creates `VerificationFeedback` with section mapping.** Verify a module with a schema mismatch on the `users` endpoint. Assert: `Feedback` memory created with `VerificationFeedback` metadata mapping the failure to `SpecSection::DataModel`, mismatch type recorded, severity recorded. | Production: verification failures are stored without section mapping, adaptive weight system can't determine which spec sections need boosting. |
| `T9-BRIDGE-07` | **`DriftEventHandler::on_decomposition_adjusted` creates DecisionContext memory linked to DNA hash.** Human splits auth from users module. Assert: `DecisionContext` memory created in cortex.db with `BoundaryAdjustment::Split`, linked to the project's DNA profile hash, confidence 0.75 (single project). | Production: decomposition adjustments are lost, cross-project transfer has no data to transfer — Enhancement 2 is dead on arrival. |
| `T9-BRIDGE-08` | **Causal narrative generation for spec explanation.** Create a chain of 3 corrections: Module C data flow → Module A business logic → Module D business logic. Call bridge's `explain_spec_section(module_d, BusinessLogic)`. Assert: returns a narrative string that mentions both upstream corrections, includes chain confidence, and is human-readable. | Production: "Why was this spec generated this way?" returns empty or garbage, humans can't audit the reasoning, trust in the system erodes. |

### 9B. Causal Correction Graphs — Edge Cases

| ID | Test | Prevents |
|----|------|----------|
| `T9-BRIDGE-09` | **Correction with zero upstream modules.** `SpecCorrection` with `upstream_modules: []` (pure domain knowledge correction). Assert: memory created with no causal edges to other modules, only a self-referential "DomainKnowledge" annotation. No panic on empty upstream list. | Production: domain knowledge corrections (the most valuable kind) crash the bridge because it assumes at least one upstream module. |
| `T9-BRIDGE-10` | **Correction referencing a module that doesn't exist in drift.db.** `upstream_modules: ["nonexistent_module"]`. Assert: bridge logs a warning, creates the correction memory without the invalid causal edge, does not create a dangling edge in the causal graph. | Production: stale module reference creates a dangling edge in the causal graph, traversal hits a dead end and returns incomplete narratives. |
| `T9-BRIDGE-11` | **100 corrections for the same module.** Create 100 `SpecCorrection`s for Module A, each with different root causes. Assert: all 100 create causal edges, CausalEngine handles the fan-in gracefully, narrative generation summarizes rather than listing all 100. | Production: heavily-corrected module creates a causal subgraph so large that narrative generation times out or produces a 50-page explanation. |
| `T9-BRIDGE-12` | **Correction chain depth of 20.** Create a chain: correction_1 → correction_2 → ... → correction_20. Assert: `trace_origins()` traverses the full chain, narrative generation includes a depth summary ("Chain of 20 corrections, showing top 5 by confidence"). | Production: deep correction chains cause stack overflow in recursive traversal, or narrative generation produces an unreadable wall of text. |
| `T9-BRIDGE-13` | **Two corrections with identical content but different modules.** Same correction text applied to Module A and Module B. Assert: two separate memories created, two separate causal edges, no deduplication (they're semantically different because they apply to different modules). | Production: deduplication merges corrections across modules, Module B's correction is lost because it "looks like" Module A's. |
| `T9-BRIDGE-14` | **`SpecSection` variant not in the weight table.** Create a `VerificationFeedback` with a section that has no entry in the current `AdaptiveWeightTable`. Assert: section is added to the table with the static default weight as baseline, then adjusted. | Production: new spec section added to the enum but not to the weight table, verification failures for that section are silently ignored. |

### 9C. Decomposition Transfer — Happy Path

| ID | Test | Prevents |
|----|------|----------|
| `T9-BRIDGE-15` | **Bridge `DecompositionPriorProvider` returns priors for DNA-similar project.** Store a `DecisionContext` memory in cortex.db linked to DNA profile A (Spring Boot, PostgreSQL, JWT). Query with DNA profile B (Spring Boot, PostgreSQL, OAuth2, similarity 0.78). Assert: returns the stored decision as a `DecompositionDecision` with `dna_similarity: 0.78`. | Production: bridge's `DecompositionPriorProvider` always returns empty, cross-project transfer never activates even when relevant priors exist. |
| `T9-BRIDGE-16` | **Bridge filters out low-similarity priors.** Store decisions for DNA profiles with similarities 0.3, 0.5, 0.6, 0.8 to the query profile. Assert: only 0.6 and 0.8 are returned (threshold is 0.6). | Production: low-similarity priors from unrelated projects pollute decomposition, causing incorrect module boundaries. |
| `T9-BRIDGE-17` | **Bridge returns consolidated semantic rules with higher confidence than episodic decisions.** Store 6 episodic `DecisionContext` memories for the same boundary pattern. Trigger consolidation (HDBSCAN promotes to semantic rule). Query priors. Assert: returns the semantic rule with confidence > any individual episodic memory. | Production: consolidated rules are ignored in favor of individual episodic memories, the system never "learns" general patterns — only remembers specific instances. |
| `T9-BRIDGE-18` | **Prior confidence increases when human confirms.** Store a prior with confidence 0.75. Human confirms the suggested split. Bridge calls `on_decomposition_adjusted` with confirmation. Assert: prior's confidence increases to ≥ 0.85. | Production: human confirmations are ignored, prior confidence never increases, the system never becomes more confident in patterns that are repeatedly confirmed. |
| `T9-BRIDGE-19` | **Prior confidence decreases when human rejects.** Store a prior with confidence 0.75. Human rejects the suggested split. Bridge calls `on_decomposition_adjusted` with rejection. Assert: prior's confidence decreases to ≤ 0.6. | Production: human rejections are ignored, bad priors persist at high confidence, the system keeps suggesting wrong boundaries. |

### 9D. Decomposition Transfer — Edge Cases

| ID | Test | Prevents |
|----|------|----------|
| `T9-BRIDGE-20` | **No priors exist in cortex.db.** Fresh Cortex database, no `DecisionContext` memories. Assert: `DecompositionPriorProvider` returns empty vec, no error. Drift falls back to standard decomposition. | Production: empty Cortex database causes bridge to return an error instead of empty priors, blocking decomposition entirely on first-ever project. |
| `T9-BRIDGE-21` | **1000 priors exist for the same DNA profile.** Assert: bridge returns all applicable priors (no arbitrary limit), but sorts by confidence descending so the decomposition algorithm can apply the most confident first. | Production: bridge returns priors in random order, low-confidence priors are applied first and exhaust the adjustment budget before high-confidence priors are considered. |
| `T9-BRIDGE-22` | **DNA profile with all zero genes.** Query with a degenerate DNA profile (all dimensions zero). Assert: similarity to any stored profile is 0.0, no priors returned. | Production: zero-vector DNA profile has undefined cosine similarity (0/0), causing NaN comparisons that match everything. |
| `T9-BRIDGE-23` | **Cross-DB ATTACH query (drift.db ↔ cortex.db).** Bridge needs to join decomposition data from drift.db with memory data from cortex.db. Assert: ATTACH works, query returns correct joined results, DETACH cleans up. | Production: ATTACH fails silently, bridge reads from wrong database, returns stale or empty priors. |

### 9E. Adaptive Weights — Happy Path

| ID | Test | Prevents |
|----|------|----------|
| `T9-BRIDGE-24` | **Bridge `WeightProvider` computes adaptive weights from verification failures.** Store 20 `Feedback` memories with `VerificationFeedback` metadata: 12 DataModel failures, 4 PublicApi failures, 2 Security failures, 2 Conventions failures. Query weights for the migration path. Assert: `data_model` weight is boosted most (≈ 2.34), `public_api` boosted moderately, `security` and `conventions` boosted slightly. Other weights unchanged. | Production: bridge's `WeightProvider` returns static weights regardless of verification history, the adaptive feedback loop is broken — Enhancement 3 is dead. |
| `T9-BRIDGE-25` | **Weight adjustment formula is correct.** For `data_model`: base 1.8, failure_rate 0.60, boost_factor 0.5. Assert: `adjusted = 1.8 × (1 + 0.60 × 0.5) = 1.8 × 1.30 = 2.34`. | Production: formula is implemented wrong (e.g., additive instead of multiplicative), weights diverge from expected values, spec quality degrades unpredictably. |
| `T9-BRIDGE-26` | **Adaptive weights stored as Skill memory with 365-day half-life.** After computing adaptive weights, assert: a `Skill` memory exists in cortex.db with `SkillContent` containing the weight table, `MigrationPath` as key, and half-life of 365 days. | Production: adaptive weights are computed but never persisted, every restart recomputes from scratch — or worse, they're persisted with no decay and stale optimizations accumulate forever. |
| `T9-BRIDGE-27` | **Adaptive weights decay over time.** Store a Skill memory with adaptive weights, advance time by 365 days. Query weights. Assert: weights have decayed toward static defaults (half-life decay). After 730 days, weights are ≈75% back to static defaults. | Production: weights never decay, a migration path that had many failures 3 years ago still has heavily boosted weights even though the underlying issues may have been fixed. |
| `T9-BRIDGE-28` | **Minimum sample size enforced.** Store only 3 verification results (below the 15-20 threshold). Query adaptive weights. Assert: returns static weights with a note "insufficient sample size (3/15)", does not compute adjustments from too-small a sample. | Production: 3 verification results (2 DataModel failures) produce a 67% failure rate, massively over-boosting data_model weight from a statistically meaningless sample. |

### 9F. Adaptive Weights — Edge Cases

| ID | Test | Prevents |
|----|------|----------|
| `T9-BRIDGE-29` | **All verification results are passes (zero failures).** 20 verifications, all pass. Assert: adaptive weights equal static weights (no adjustment needed). No division by zero in failure_rate calculation. | Production: zero total failures causes division by zero in `section_failures / total_failures`, crashing weight computation. |
| `T9-BRIDGE-30` | **All failures map to a single section.** 20 verifications, 15 failures, all `DataModel`. Assert: `data_model` weight is heavily boosted, all other weights unchanged. Total weight sum is reasonable (not unbounded). | Production: single-section dominance causes that section to consume 90% of the token budget, leaving 10% for the other 10 sections combined. |
| `T9-BRIDGE-31` | **Migration path with no stored Skill memory.** Query weights for a migration path that has never been seen. Assert: returns static defaults, no error. | Production: unseen migration path causes a lookup miss that propagates as an error, blocking spec generation for new migration types. |
| `T9-BRIDGE-32` | **Two migration paths with same languages but different frameworks.** Java→TypeScript with Spring→Express vs. Java→TypeScript with Spring→NestJS. Assert: separate weight tables, different adaptive weights (because different frameworks have different failure patterns). | Production: framework is ignored in the key, all Java→TypeScript migrations share one weight table even though Spring→Express and Spring→NestJS have very different failure profiles. |

### 9G. Bridge Event→Memory Mapping — Adversarial

| ID | Test | Prevents |
|----|------|----------|
| `T9-BRIDGE-33` | **`on_spec_corrected` with SQL injection in correction text.** Correction text: `'; DROP TABLE memories; --`. Assert: correction stored safely (parameterized query), `memories` table still exists in cortex.db. | Production: attacker crafts a correction that destroys the Cortex memory database. |
| `T9-BRIDGE-34` | **`on_contract_verified` with NaN severity score.** `VerificationFeedback` with `severity: NaN`. Assert: bridge rejects or clamps the severity, does not store NaN in cortex.db. | Production: NaN severity propagates into weight calculations, poisoning the adaptive weight table for that migration path. |
| `T9-BRIDGE-35` | **`on_decomposition_adjusted` with contradictory adjustment.** Adjustment says Split(auth, users) but the module list shows auth and users are already separate. Assert: bridge detects the no-op, stores the confirmation (not a split), does not create a duplicate split decision. | Production: redundant split decisions accumulate, inflating the confidence of a pattern that was never actually applied. |
| `T9-BRIDGE-36` | **Rapid-fire events: 1000 corrections in 1 second.** Fire 1000 `on_spec_corrected` events in rapid succession. Assert: all 1000 are processed (no drops), causal graph has 1000 new nodes, total processing time < 10s. | Production: burst of corrections during a review session overwhelms the bridge, some corrections are silently dropped, causal graph is incomplete. |
| `T9-BRIDGE-37` | **Event with empty module_id.** `on_spec_corrected` with `module_id: ""`. Assert: event is rejected with a clear error, no empty-key memory created in cortex.db. | Production: empty module_id creates an unlinked memory that can never be retrieved by module, polluting the memory store. |

### 9H. Bridge — Concurrency

| ID | Test | Prevents |
|----|------|----------|
| `T9-BRIDGE-38` | **Parallel `on_spec_corrected` and `on_contract_verified` for same module.** Two threads: one fires a correction event, the other fires a verification event, both for Module A. Assert: both memories created, both causal edges created, no deadlock on CausalEngine's internal lock. | Production: concurrent events for the same module deadlock on the causal graph's write lock, blocking all bridge processing. |
| `T9-BRIDGE-39` | **Parallel `DecompositionPriorProvider` queries from 4 threads.** 4 decomposition jobs query priors simultaneously. Assert: all 4 get consistent results, no torn reads from cortex.db. | Production: concurrent prior queries return inconsistent results, different decomposition jobs for the same project get different priors. |
| `T9-BRIDGE-40` | **Concurrent weight table read and write.** One thread reads adaptive weights (for spec generation), another thread writes new weights (from verification feedback). Assert: reader sees a consistent snapshot — either all old weights or all new weights, never a mix. | Production: spec generated with half-updated weights produces inconsistent section priorities. |
| `T9-BRIDGE-41` | **Cross-DB ATTACH under concurrent access.** Two threads both ATTACH cortex.db to their drift.db connections simultaneously. Assert: both succeed (SQLite allows multiple readers), queries return correct results. | Production: concurrent ATTACH causes "database is locked" errors, blocking bridge operations during high-activity periods. |

### 9I. Bridge — Corruption Recovery

| ID | Test | Prevents |
|----|------|----------|
| `T9-BRIDGE-42` | **cortex.db is missing (Drift standalone mode).** Bridge is initialized but cortex.db doesn't exist. Assert: all `DriftEventHandler` methods are no-ops (return Ok(())), `DecompositionPriorProvider` returns empty vec, `WeightProvider` returns static defaults. No panics. | Production: D1 violation — Drift crashes when Cortex isn't installed, even though Phases 0-8 should work standalone. |
| `T9-BRIDGE-43` | **cortex.db exists but `memories` table is corrupted.** Truncate the `memories` table mid-row. Assert: bridge catches the SQLite error, falls back to no-op behavior for affected operations, logs the corruption. Other operations (e.g., weight queries from a separate table) still work. | Production: one corrupted table in cortex.db takes down the entire bridge, blocking all Drift↔Cortex integration. |
| `T9-BRIDGE-44` | **Causal graph has a corrupted edge (invalid node reference).** Insert an edge in the causal graph referencing a node_id that doesn't exist. Assert: traversal skips the dangling edge, narrative generation excludes it, no panic. | Production: one corrupted edge causes `trace_origins()` to panic, breaking causal narrative generation for all modules in the graph. |
| `T9-BRIDGE-45` | **Interrupted `on_spec_corrected` leaves no partial state.** Simulate crash after creating the Feedback memory but before creating the causal edge. Assert: on restart, the orphaned Feedback memory is detected and either (a) the causal edge is created retroactively, or (b) the memory is flagged as "unlinked" for manual review. | Production: interrupted event processing leaves memories without causal edges, the causal graph has gaps, narrative generation misses corrections. |
| `T9-BRIDGE-46` | **Skill memory with corrupted weight JSON.** Store a Skill memory where `SkillContent` contains `{"weights": null}`. Assert: `WeightProvider` falls back to static defaults for that migration path, logs a warning. | Production: corrupted Skill memory causes `WeightProvider` to panic on deserialization, blocking spec generation for that migration path. |

### 9J. Bridge — Regression

| ID | Test | Prevents |
|----|------|----------|
| `T9-BRIDGE-47` | **All 10 event→memory mappings from the Appendix are implemented.** For each row in the Appendix table (spec generated→Insight, spec corrected→Feedback, spec corrected boundary→DecisionContext, spec approved→Decision, module boundary adjusted→DecisionContext, contract verify pass→Feedback, contract verify fail→Feedback, adaptive weight update→Skill, decomposition prior applied→Procedural, consolidation→Semantic), fire the event and assert the correct memory type is created. | Production: one of the 10 mappings is missing, that event type silently disappears, the corresponding memory channel is empty. |
| `T9-BRIDGE-48` | **Causal edge direction is always cause→effect, never reversed.** Create 10 corrections with known causal relationships. Assert: every edge in the causal graph points from cause to effect. `trace_origins(effect)` returns causes, not the other way around. | Production: reversed edge direction inverts the causal graph, "why was this wrong?" returns effects instead of causes, explanations are nonsensical. |
| `T9-BRIDGE-49` | **`WeightProvider` returns weights that sum to a reasonable total.** For any migration path, assert: sum of all 11 weights is between 5.0 and 30.0. No single weight exceeds 5.0. | Production: unbounded weight growth causes one section to dominate the entire token budget, producing a spec that's 90% Data Model and 10% everything else. |
| `T9-BRIDGE-50` | **Bridge does not import from `drift-analysis` or `drift-context` internals.** Static analysis: bridge's `Cargo.toml` depends on `drift-core` (for traits) and `cortex-*` crates. It does NOT depend on `drift-analysis` or `drift-context` directly. | Production: D4 violation — bridge depends on Drift internals, creating a circular dependency that breaks the build when Drift changes internal APIs. |

---

## Integration Tests: End-to-End Loop (Phase 5 + 7 + 9)

> **Crate:** `cortex-drift-bridge`
> **File:** `cortex-drift-bridge/tests/spec_integration_test.rs`
> **Purpose:** Verify the three enhancements work together as a closed loop.
> These tests exercise the full path: Drift standalone → Bridge → Cortex → Bridge → Drift.

### INT-A. Full Loop — Happy Path

| ID | Test | Prevents |
|----|------|----------|
| `TINT-LOOP-01` | **Complete correction→causal→narrative loop.** (1) Generate spec for Module A. (2) Human corrects business logic ("this is KYC compliance"). (3) Bridge creates Feedback memory + causal edge. (4) Generate spec for Module B (same data dependencies as A). (5) Assert: Module B's spec includes a hint about KYC compliance derived from Module A's correction, with causal narrative explaining why. | Production: the three enhancements work individually but don't compose — corrections are stored but never influence future specs, the loop is open, not closed. |
| `TINT-LOOP-02` | **Complete decomposition→transfer→confirmation loop.** (1) Decompose Project A (Spring Boot). Human splits auth from users. Bridge stores DecisionContext. (2) Decompose Project B (similar DNA). Assert: `decompose_with_priors()` suggests splitting auth from users. (3) Human confirms. Assert: prior confidence increases. (4) Decompose Project C (similar DNA). Assert: prior is applied with higher confidence than for Project B. | Production: decomposition transfer works for one hop but confidence doesn't compound — the system never becomes more confident in patterns that are repeatedly confirmed across projects. |
| `TINT-LOOP-03` | **Complete verification→weight→spec loop.** (1) Generate specs for 20 modules in a Java→TypeScript migration. (2) Simulate verification: 12 DataModel failures, 4 PublicApi failures, 4 passes. (3) Bridge computes adaptive weights, stores as Skill memory. (4) Generate spec for Module 21 in the same migration. Assert: Module 21's spec has a proportionally larger Data Model section than Module 1's spec (because weights were adjusted). | Production: verification feedback is collected but never reaches the spec generator — the weight adjustment pipeline is broken at some handoff point. |
| `TINT-LOOP-04` | **All three enhancements compound on the same module.** Module X in Project B: (1) Decomposition priors from Project A suggest splitting it. (2) Causal corrections from Project A's similar module boost business logic section. (3) Adaptive weights from Project A's verification failures boost data model section. Assert: Module X's spec reflects all three influences, and the causal narrative explains all three sources. | Production: the three enhancements interfere with each other — e.g., decomposition priors change the module boundary, which invalidates the causal corrections that were retrieved for the old boundary. |

### INT-B. Full Loop — Edge Cases

| ID | Test | Prevents |
|----|------|----------|
| `TINT-LOOP-05` | **First-ever project (empty Cortex).** No prior corrections, no decomposition decisions, no adaptive weights. Assert: full pipeline works with all defaults — standard decomposition, static weights, no causal narratives. Output is identical to Drift standalone mode. | Production: first customer hits errors because the pipeline assumes Cortex has data, empty-state handling is broken. |
| `TINT-LOOP-06` | **Project with 100 modules, 500 corrections, 200 verifications.** Scale test for the full loop. Assert: (1) all 100 specs generate in < 60s total, (2) causal graph has ≤ 500 correction nodes, (3) adaptive weights are computed from all 200 verifications, (4) no memory leaks (RSS < 500MB). | Production: the loop works for toy examples but falls over at realistic scale — O(n²) algorithms in causal traversal or weight computation cause timeouts. |
| `TINT-LOOP-07` | **Bridge disabled mid-pipeline.** Generate specs for modules 1-10 with bridge active (adaptive weights, priors). Disable bridge (simulate cortex.db becoming unavailable). Generate specs for modules 11-20. Assert: modules 11-20 use static weights and no priors (graceful degradation), no errors, no partial bridge state. | Production: bridge failure mid-pipeline causes a hard crash instead of graceful fallback, blocking the entire migration project. |
| `TINT-LOOP-08` | **Correction contradicts a prior.** Project A's prior says "merge auth+users." Project B's human correction says "split auth from users." Assert: (1) contradiction is detected, (2) prior confidence decreases, (3) correction is stored as a new DecisionContext with the opposite adjustment, (4) future projects see both and the system presents the contradiction for human resolution. | Production: contradictions are silently resolved by last-write-wins, the system flip-flops between merge and split without ever surfacing the disagreement to a human. |

### INT-C. Full Loop — Adversarial

| ID | Test | Prevents |
|----|------|----------|
| `TINT-LOOP-09` | **Malicious project poisons the prior pool.** Project A stores 50 bogus decomposition decisions (random splits with confidence 0.99). Project B has similar DNA. Assert: priors are applied but (1) human review catches the bad suggestions, (2) human rejections decrease confidence rapidly, (3) after 5 rejections, the bogus priors drop below the 0.4 threshold and stop being applied. | Production: one bad-faith project permanently corrupts the prior pool for all similar projects, with no self-healing mechanism. |
| `TINT-LOOP-10` | **Feedback loop amplification attack.** Create a cycle: verification failure → boost weight → spec over-emphasizes section → different verification failure → boost different weight → repeat. Run 10 iterations. Assert: weights are bounded (no single weight exceeds 5.0), the system converges rather than oscillating. | Production: positive feedback loop causes weights to grow without bound, spec quality degrades with each iteration instead of improving. |
| `TINT-LOOP-11` | **Stale corrections from a deleted codebase.** Project A is deleted from drift.db but its corrections remain in cortex.db. Project B queries priors. Assert: stale corrections are still returned (they're valid knowledge) but flagged as "source project no longer available" with reduced confidence. | Production: stale corrections from deleted projects are returned at full confidence, but can't be validated against the source codebase anymore — grounding loop can't run on them. |

### INT-D. Full Loop — Concurrency

| ID | Test | Prevents |
|----|------|----------|
| `TINT-LOOP-12` | **Two projects decomposing simultaneously with shared priors.** Project B and Project C both have similar DNA to Project A. Both decompose at the same time, both query priors. Assert: both get the same priors, both apply them independently, no interference. | Production: concurrent prior queries cause a race condition where one project's decomposition modifies the prior pool mid-query for the other project. |
| `TINT-LOOP-13` | **Spec generation and verification running in parallel for different modules.** Modules 1-5 are being verified (writing feedback to Cortex) while modules 6-10 are being spec-generated (reading weights from Cortex). Assert: no deadlock, spec generation sees a consistent weight snapshot, verification writes don't block reads. | Production: write-heavy verification phase blocks read-heavy spec generation phase, serializing what should be parallel work. |

### INT-E. Full Loop — Corruption Recovery

| ID | Test | Prevents |
|----|------|----------|
| `TINT-LOOP-14` | **cortex.db corrupted mid-pipeline, then restored.** (1) Generate specs for modules 1-5 with bridge active. (2) Corrupt cortex.db (truncate file). (3) Generate specs for modules 6-10 — assert: graceful fallback to standalone mode. (4) Restore cortex.db from backup. (5) Generate specs for modules 11-15 — assert: bridge reconnects, priors and weights are available again. | Production: cortex.db corruption is permanent — even after restoration, the bridge doesn't reconnect, requiring a full restart. |
| `TINT-LOOP-15` | **drift.db and cortex.db have inconsistent state.** drift.db says Module A is `spec_approved`, but cortex.db has no `Decision` memory for Module A (bridge event was lost). Assert: bridge detects the inconsistency on next access, logs a warning, and either (a) creates the missing Decision memory retroactively, or (b) flags Module A for re-approval. | Production: inconsistent state between the two databases causes silent data loss — the grounding loop thinks Module A was never approved, corrections for it are orphaned. |

### INT-F. Full Loop — Regression

| ID | Test | Prevents |
|----|------|----------|
| `TINT-LOOP-16` | **D1 compliance: Drift crates have zero Cortex imports.** Static analysis of `drift-core`, `drift-analysis`, `drift-context`, `drift-storage`, `drift-napi`, `drift-bench` Cargo.toml files. Assert: none of them list any `cortex-*` crate as a dependency. | Production: D1 violation — someone adds a "quick fix" that imports Cortex directly into Drift, creating a hard dependency that breaks standalone mode. |
| `TINT-LOOP-17` | **D4 compliance: Nothing depends on `cortex-drift-bridge`.** Static analysis of all Cargo.toml files in the workspace. Assert: `cortex-drift-bridge` appears only in the workspace members list, never as a dependency of any other crate. | Production: D4 violation — a Drift crate depends on the bridge, creating a circular dependency that breaks the build. |
| `TINT-LOOP-18` | **Loop convergence: spec quality improves over 5 iterations.** (1) Generate spec for Module A. (2) Human corrects 5 sections. (3) Re-generate spec. (4) Human corrects 3 sections (fewer). (5) Re-generate. (6) Human corrects 1 section. Assert: correction count monotonically decreases (or at least doesn't increase) over iterations, demonstrating the loop is converging. | Production: the loop doesn't converge — corrections don't improve future specs, the system makes the same mistakes every time, humans lose trust and stop using it. |
| `TINT-LOOP-19` | **Memory type mapping is exhaustive.** For each of the 10 events in the Appendix table, assert: the bridge produces exactly the memory type specified (Insight, Feedback, DecisionContext, Decision, Skill, Procedural, Semantic). No event produces an unexpected type. Cross-reference with `cortex-core`'s `MemoryType` enum to ensure all used types exist. | Production: memory type mapping is wrong (e.g., correction stored as Insight instead of Feedback), downstream systems that filter by type miss the memory entirely. |

---

## Test Summary

| Phase | Category | Count | Crate |
|-------|----------|-------|-------|
| Phase 5 | Happy path | 8 | `drift-analysis` |
| Phase 5 | Edge cases | 8 | `drift-analysis` |
| Phase 5 | Adversarial | 5 | `drift-analysis` |
| Phase 5 | Concurrency | 2 | `drift-analysis` |
| Phase 5 | Corruption recovery | 3 | `drift-analysis` |
| Phase 5 | Regression | 3 | `drift-analysis` |
| **Phase 5 total** | | **29** | |
| Phase 7 | Happy path | 8 | `drift-context` |
| Phase 7 | Edge cases | 8 | `drift-context` |
| Phase 7 | Adversarial | 6 | `drift-context` |
| Phase 7 | Concurrency | 3 | `drift-context` |
| Phase 7 | Corruption recovery | 4 | `drift-context` |
| Phase 7 | Regression | 4 | `drift-context` |
| **Phase 7 total** | | **33** | |
| Phase 9 | Causal corrections (happy) | 8 | `cortex-drift-bridge` |
| Phase 9 | Causal corrections (edge) | 6 | `cortex-drift-bridge` |
| Phase 9 | Decomposition transfer (happy) | 5 | `cortex-drift-bridge` |
| Phase 9 | Decomposition transfer (edge) | 4 | `cortex-drift-bridge` |
| Phase 9 | Adaptive weights (happy) | 5 | `cortex-drift-bridge` |
| Phase 9 | Adaptive weights (edge) | 4 | `cortex-drift-bridge` |
| Phase 9 | Adversarial | 5 | `cortex-drift-bridge` |
| Phase 9 | Concurrency | 4 | `cortex-drift-bridge` |
| Phase 9 | Corruption recovery | 5 | `cortex-drift-bridge` |
| Phase 9 | Regression | 4 | `cortex-drift-bridge` |
| **Phase 9 total** | | **50** | |
| Integration | Happy path | 4 | `cortex-drift-bridge` |
| Integration | Edge cases | 4 | `cortex-drift-bridge` |
| Integration | Adversarial | 3 | `cortex-drift-bridge` |
| Integration | Concurrency | 2 | `cortex-drift-bridge` |
| Integration | Corruption recovery | 2 | `cortex-drift-bridge` |
| Integration | Regression | 4 | `cortex-drift-bridge` |
| **Integration total** | | **19** | |
| **GRAND TOTAL** | | **131** | |

### Coverage Targets

| Crate | Line Coverage | Branch Coverage | Notes |
|-------|-------------|----------------|-------|
| `drift-analysis` (decomposition) | ≥ 85% | ≥ 75% | All 6 signals, prior application, scoring |
| `drift-context` (spec generation) | ≥ 85% | ≥ 75% | All 11 sections, weight override, renderer |
| `drift-core` (traits) | 100% | 100% | `DecompositionPriorProvider` + `WeightProvider` defaults |
| `cortex-drift-bridge` (bridge) | ≥ 80% | ≥ 70% | Event handlers, providers, cross-DB queries |

### Test Execution Order

1. **Phase 5 tests first** — decomposition is the foundation, must pass before Phase 7
2. **Phase 7 tests second** — spec generation depends on decomposition output
3. **Phase 9 tests third** — bridge depends on both Drift and Cortex types
4. **Integration tests last** — require all three phases working together

Run with: `cargo test --workspace -- --test-threads=1` for integration tests
(SQLite doesn't love high parallelism on the same DB file).

Run with: `cargo test -p drift-analysis -p drift-context -- --test-threads=4` for
Phase 5+7 tests (no shared state, safe to parallelize).
