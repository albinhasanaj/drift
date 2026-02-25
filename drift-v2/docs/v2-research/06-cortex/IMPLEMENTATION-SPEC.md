# PLC Indexer — Unified Implementation Specification

> **Version:** 5.0.0
> **Status:** APPROVED FOR IMPLEMENTATION
> **Package:** `@drift-studio/plc-indexer`
> **Last Updated:** 2026-02-05
> **Research Corpus:** 75 documents across 12 phases
> **Supersedes:** `ARCHITECTURE-SPECIFICATION.md` (v2.0)

## What This Document Is

This is the single source of truth for building the PLC Indexer. An agent reading this document should be able to implement every module, understand every connection, and know why every decision was made. No source code is included — only specifications, interfaces, data shapes, and rationale.

This document merges the previously separate "scanner" (Phase 11) and "indexer" (Phase 10) into one unified package. The scanner's 5-phase pipeline becomes the orchestration layer. The indexer's parsing and analysis modules become the engine underneath.

## Why This System Exists

Legacy PLC code (IEC 61131-3) controls physical machinery in factories worldwide. This code is often decades old, written in visual languages (FBD, LD, SFC), locked in proprietary vendor formats, and undocumented. AI tools cannot work with it because they don't understand the domain.

This system bridges that gap by:
1. Scanning a PLC project to discover what exists
2. Parsing all code into a unified model (regardless of vendor or language)
3. Analyzing relationships, patterns, safety, and hidden dependencies
4. Producing a Migration Map for human review and AI-assisted migration

The core question this system answers: **"What information should we extract from a codebase to be maximally informative for an agent generating migrated code?"**

---

## Technology Stack

| Concern | Choice | Why |
|---------|--------|-----|
| Language | TypeScript (strict mode) | Type safety, tooling, matches existing monorepo |
| XML Parsing | fast-xml-parser | Performance, streaming support, no native deps |
| Layout | ELK.js (elkjs) | Port support, hierarchical layout, edge routing |
| Rendering | React Flow | TypeScript, custom nodes, active community |
| State | Zustand | Simplicity for UI state |
| Testing | Vitest | Speed, ESM support, matches monorepo |
| Build | tsup | Fast, simple bundling |

---

## Architecture: 9 Layers

The system is organized into 9 layers with strict dependency rules. Lower layers cannot import from higher layers. Layer 0 has zero dependencies.

```
Layer 0: Core         — Types, interfaces, errors, constants (depends on: nothing)
Layer 1: Ingestion    — File discovery, format detection, vendor fingerprinting (depends on: 0)
Layer 2: Adapters     — Vendor-specific XML → unified model (depends on: 0, 3)
Layer 3: Parsers      — Language-specific body parsing (depends on: 0, 4)
Layer 4: Graph        — Unified graph model, traversal, conversion (depends on: 0)
Layer 5: Analysis     — Entity extraction, relationships, patterns, safety, external/implicit deps (depends on: 0, 4)
Layer 6: Planning     — Migration ordering, risk assessment, review identification (depends on: 0)
Layer 7: Layout       — ELK.js integration, position computation (depends on: 0, 4)
Layer 8: Output       — Reports, AI chunks, cross-references, file organization, Migration Map assembly (depends on: 0, 4, 5, 6, 7)
```

---

## Incremental Testing & Quality Gates Philosophy

Every layer in this system is tested in isolation BEFORE the next layer is built. This is not optional — it's the primary defense against silent failures that compound across layers.

**Why this matters for PLC code:** This system analyzes safety-critical industrial code. A silent failure in Layer 3 (parser drops a negated input) propagates to Layer 5 (analysis misses a safety interlock) which propagates to Layer 8 (migration plan doesn't flag the POU for review) which results in a real-world safety incident. The cost of catching bugs increases exponentially with distance from the source.

**The rule:** No layer N+1 code is written until all layer N tests pass. No phase N+1 begins until the phase N quality gate is satisfied.

### Quality Gate Summary

| Gate | Layer/Phase | Test Count | Key Validation |
|------|-------------|------------|----------------|
| QG-0 | Layer 0: Core | 16 | Types compile, errors hierarchy works, logger outputs JSON, audit trail appends |
| QG-1 | Layer 1: Ingestion | 17 | Format detection correct for all vendors, binary rejection, encoding handling |
| QG-2 | Layer 2: Adapters | 14 | PLCopen produces complete project shells, back-reference inversion correct |
| QG-3 | Layer 3: Parsers | 26 | FBD connections resolved, execution order correct, SFC qualifiers parsed, LD rungs extracted |
| QG-4 | Layer 4: Graph | 15 | Topological sort valid, cycles detected, ELK JSON valid, ST generation correct |
| QG-5 | Layer 5: Analysis | 33 | Entities complete, call graph accurate, patterns detected, safety boundaries found |
| QG-6 | Layer 6: Planning | 12 | Migration order dependency-safe, safety POUs flagged for review, risk scores valid |
| QG-7 | Layer 7: Layout | 9 | Positions valid, ports mapped, SFC vertical flow, original positions preserved |
| QG-8 | Layer 8: Output | 24 | MigrationMap complete, chunks fit limits, quality honest, diff detects changes |
| **Total** | | **166** | |

### Silent Failure Detection Strategy

Silent failures are the most dangerous bugs — the system produces output that looks correct but is subtly wrong. Each layer's tests include specific silent failure traps:

| Layer | Silent Failure Risk | Detection Test |
|-------|-------------------|----------------|
| 0: Core | Missing barrel export → downstream import returns `undefined` | Import every public type, assert not undefined |
| 1: Ingestion | Non-PLC XML classified as PLC → wrong adapter crashes | Feed SVG, HTML, random XML → must return Unknown |
| 2: Adapters | Back-reference inversion wrong → all edges backwards | Assert edge source is the data producer, not consumer |
| 3: Parsers | Negated input dropped → inverted logic in migration | Assert `port.negated === true` for negated inputs |
| 3: Parsers | EN/ENO missed → conditional execution lost | Assert `block.enableInput === true` when EN present |
| 3: Parsers | Connector/continuation unresolved → disconnected graph | Assert edge exists between matched connector/continuation |
| 4: Graph | Cycle not detected → infinite loop in topological sort | Graph with known cycle → cycle info returned |
| 5: Analysis | Multi-writer not flagged → race condition in migration | Two POUs write same global → SharedStateWarning exists |
| 5: Analysis | Safety boundary missed → safety code modified without review | Non-safety calls safety → boundary in results |
| 6: Planning | Dependency violation in batch order → compile errors | For every batch entity, all deps in earlier batches |
| 8: Output | Quality always reports 100% → false confidence | Incomplete parse → completeness < 100 |
| 8: Output | Diff misses safety change → safety code changed without review | Modified safety POU → safetyImpact entry exists |

### Test-As-You-Build Workflow

For each implementation step:
1. **Write the test first** (or immediately after the module) — not at the end of the phase
2. **Run the test** — confirm it fails for the right reason (not a false pass)
3. **Implement the module** — make the test pass
4. **Run ALL previous layer tests** — confirm nothing broke
5. **Check the quality gate** — if all tests for the current layer pass, proceed

This is not TDD dogma — it's practical defense against a system where bugs in layer N silently corrupt layers N+1 through 8.

---

## Complete Package Structure

The `@drift-studio/plc-indexer` package follows a strict `src/` layout. Every layer is a top-level directory. Every module lives in a subdirectory that reflects its single responsibility.

```
src/
├── index.ts                          # Public API: PLCIndexer class + re-exports
├── core/                             # Layer 0
│   ├── index.ts                      # Barrel: re-exports types, interfaces, errors, constants
│   ├── types/                        # All type definitions (18 files)
│   ├── interfaces/                   # All interface contracts (9 files)
│   ├── errors/                       # Error class hierarchy (5 files)
│   ├── constants/                    # Enums, catalogs, lookup tables (5 files)
│   └── schemas/                      # Output schema definitions (JSON Schema)
│       ├── migration-map.schema.json
│       └── schema-changelog.md
├── ingestion/                        # Layer 1
│   ├── index.ts                      # Barrel: format-sniffer, file-loader, project-scanner, schema-validator
│   ├── format-sniffer.ts
│   ├── file-loader.ts
│   ├── project-scanner.ts
│   └── schema-validator.ts
├── adapters/                         # Layer 2
│   ├── index.ts                      # Barrel: adapter-registry + all adapters
│   ├── adapter-registry.ts
│   ├── base-adapter.ts
│   ├── plcopen/                      # PLCopen XML adapter (5 files)
│   │   ├── plcopen-adapter.ts
│   │   ├── plcopen-project.ts
│   │   ├── plcopen-pou.ts
│   │   ├── plcopen-body.ts
│   │   ├── plcopen-types.ts
│   │   └── plcopen-config.ts
│   ├── rockwell/                     # Rockwell L5X adapter (4 files)
│   │   ├── l5x-adapter.ts
│   │   ├── l5x-controller.ts
│   │   ├── l5x-routine.ts
│   │   ├── l5x-tag.ts
│   │   └── l5x-aoi.ts
│   ├── siemens/                      # Siemens SimaticML adapter (3 files)
│   │   ├── simatic-adapter.ts
│   │   ├── simatic-block.ts
│   │   ├── simatic-network.ts
│   │   └── simatic-multi-instance.ts
│   └── codesys/                      # CODESYS adapter (2 files)
│       ├── codesys-adapter.ts
│       └── codesys-library.ts
├── parsers/                          # Layer 3
│   ├── index.ts                      # Barrel: all language parsers
│   ├── fbd/                          # FBD parser (7 files)
│   │   ├── fbd-parser.ts
│   │   ├── fbd-block.ts
│   │   ├── fbd-connection.ts
│   │   ├── fbd-execution-order.ts
│   │   ├── fbd-enable-logic.ts
│   │   ├── fbd-negation.ts
│   │   └── fbd-connector.ts
│   ├── ld/                           # LD parser (3 files)
│   │   ├── ld-parser.ts
│   │   ├── ld-rung.ts
│   │   └── ld-contact.ts
│   ├── sfc/                          # SFC parser (8 files)
│   │   ├── sfc-parser.ts
│   │   ├── sfc-step.ts
│   │   ├── sfc-transition.ts
│   │   ├── sfc-action.ts
│   │   ├── sfc-branch.ts
│   │   ├── sfc-qualifier.ts
│   │   ├── sfc-jump-step.ts
│   │   ├── sfc-macro-step.ts
│   │   └── sfc-state-machine.ts
│   ├── st/                           # ST parser (3 files)
│   │   ├── st-parser.ts
│   │   ├── st-lexer.ts
│   │   └── st-ast.ts
│   └── il/                           # IL parser (1 file)
│       └── il-parser.ts
├── graph/                            # Layer 4
│   ├── index.ts                      # Barrel: model, network, utils, converters
│   ├── model/                        # Node/edge classes
│   │   ├── graph-node.ts
│   │   ├── block-node.ts
│   │   ├── variable-node.ts
│   │   ├── control-node.ts
│   │   ├── sfc-node.ts
│   │   └── graph-edge.ts
│   ├── network/                      # Network containers
│   │   ├── fbd-network.ts
│   │   ├── ld-network.ts
│   │   ├── sfc-network.ts
│   │   └── network-builder.ts
│   ├── utils/                        # Graph algorithms
│   │   ├── graph-traversal.ts
│   │   ├── cycle-detection.ts
│   │   ├── feedback-handler.ts
│   │   ├── predecessors.ts
│   │   └── successors.ts
│   └── converters/                   # Format converters
│       ├── to-elk.ts
│       ├── to-reactflow.ts
│       ├── to-st.ts
│       └── sfc-to-state-diagram.ts
├── analysis/                         # Layer 5
│   ├── index.ts                      # Barrel: entities, relationships, external, implicit, patterns, safety
│   ├── entities/                     # Entity extraction (4 files)
│   │   ├── entity-extractor.ts
│   │   ├── pou-analyzer.ts
│   │   ├── variable-analyzer.ts
│   │   └── type-analyzer.ts
│   ├── relationships/                # Relationship analysis (4 files)
│   │   ├── call-graph-builder.ts
│   │   ├── data-flow-analyzer.ts
│   │   ├── dependency-mapper.ts
│   │   └── fb-instance-tracker.ts
│   ├── external/                     # External dependencies (5 files)
│   │   ├── hmi-tag-extractor.ts
│   │   ├── io-mapping-analyzer.ts
│   │   ├── library-dependency.ts
│   │   ├── opcua-namespace.ts
│   │   └── recipe-system.ts
│   ├── implicit/                     # Implicit dependencies (4 files)
│   │   ├── timing-dependency.ts
│   │   ├── global-state-tracker.ts
│   │   ├── execution-order-deps.ts
│   │   └── convention-detector.ts
│   ├── patterns/                     # Pattern detection
│   │   ├── pattern-registry.ts
│   │   ├── pattern-matcher.ts
│   │   └── detectors/               # 12 individual detectors
│   │       ├── motor-control.ts
│   │       ├── pid-control.ts
│   │       ├── state-machine.ts
│   │       ├── analog-scaling.ts
│   │       ├── timer-usage.ts
│   │       ├── safety-interlock.ts
│   │       ├── cascade-control.ts
│   │       ├── voting-logic.ts
│   │       ├── latching-logic.ts
│   │       ├── edge-detection.ts
│   │       ├── counter-pattern.ts
│   │       └── sequencer-pattern.ts
│   └── safety/                       # Safety analysis (7 files)
│       ├── safety-analyzer.ts
│       ├── sil-detector.ts
│       ├── safety-flags.ts
│       ├── safety-fb-catalog.ts
│       ├── safety-boundary.ts
│       ├── certification-tracker.ts
│       └── voting-logic-detector.ts
├── planning/                         # Layer 6
│   ├── index.ts                      # Barrel: batch-planner, risk-assessor, review-identifier, blocker-detector
│   ├── batch-planner.ts
│   ├── risk-assessor.ts
│   ├── review-identifier.ts
│   ├── blocker-detector.ts
│   └── migration-order-computer.ts
├── layout/                           # Layer 7
│   ├── index.ts                      # Barrel: layout-engine + strategies
│   ├── layout-engine.ts
│   └── strategies/
│       ├── elk-layout.ts
│       ├── original-layout.ts
│       ├── hybrid-layout.ts
│       └── sfc-layout.ts
├── output/                           # Layer 8
│   ├── index.ts                      # Barrel: migration-map, reports, chunks, prompts, files
│   ├── migration-map/
│   │   ├── migration-map-builder.ts
│   │   ├── json-serializer.ts
│   │   ├── validation-runner.ts
│   │   └── navigation-builder.ts
│   ├── reports/
│   │   ├── report-generator.ts
│   │   └── templates/
│   │       ├── executive-summary.ts
│   │       ├── architecture-overview.ts
│   │       ├── entity-catalog.ts
│   │       ├── dependency-map.ts
│   │       ├── external-dependencies.ts
│   │       ├── safety-analysis.ts
│   │       └── migration-recommendations.ts
│   ├── chunks/
│   │   ├── context-chunker.ts
│   │   ├── token-estimator.ts
│   │   ├── cross-reference-builder.ts
│   │   └── navigation-index.ts
│   ├── prompts/
│   │   ├── prompt-generator.ts
│   │   └── templates/
│   │       ├── migration.template.ts
│   │       ├── review.template.ts
│   │       ├── analysis.template.ts
│   │       └── documentation.template.ts
│   ├── files/
│   │   └── file-organizer.ts
│   ├── diff/                         # Scan-to-scan comparison
│   │   ├── scan-differ.ts
│   │   └── diff-reporter.ts
│   └── quality/                      # Self-assessment and loss tracking
│       ├── quality-assessor.ts
│       └── loss-tracker.ts
└── shared/                           # Cross-cutting concerns (not a layer)
    ├── logger.ts                     # Structured logging (see Observability section)
    ├── progress.ts                   # Pipeline progress reporting
    ├── result.ts                     # Result<T, E> type for error recovery
    └── audit.ts                      # Provenance and decision audit trail
```

**Total: ~125 files across 9 layers + shared utilities. No file exceeds a single responsibility.**

---

## Layer 0: Core

**Purpose:** Define every type, interface, error, and constant used by the system. This layer is the contract. Everything else implements it.

**Why it exists:** Every other layer imports from core. Getting these types right before writing any parsing code prevents cascading refactors.

### Types to Define

The complete `core/types/` directory:
```
core/types/
├── project.types.ts
├── pou.types.ts
├── variable.types.ts
├── graph.types.ts
├── sfc.types.ts
├── ld.types.ts
├── analysis.types.ts
├── external.types.ts
├── implicit.types.ts
├── safety.types.ts
├── migration.types.ts
├── output.types.ts
├── vendor-extension.types.ts
├── provenance.types.ts
├── quality.types.ts
├── diff.types.ts
├── information-loss.types.ts
└── pipeline.types.ts
```

**`project.types.ts`** — The IEC 61131-3 software model hierarchy.
- `Project`: root container with metadata (name, vendor, format, version, creation date, author)
- `Configuration`: top-level hardware config, contains Resources and global variables
- `Resource`: represents a CPU/device, contains Tasks and global variables
- `Task`: execution scheduling (name, interval as string like "T#10ms", priority as number, single trigger)
- `POUInstance`: a POU assigned to a task (instance name, type name, is-entry-point flag)
- `EntryPoint`: links a POU to its task, resource, and configuration

Why this matters: The IEC 61131-3 hierarchy is Configuration → Resource → Task → POU. Entry points are programs assigned to tasks. This hierarchy determines execution context and timing assumptions.

**`pou.types.ts`** — Program Organization Units.
- `POU`: name, pouType (program | functionBlock | function), language (ST | FBD | LD | SFC | IL), interface, body reference, documentation, author, version, extends (optional parent FB/class name), implements (optional interface names array), isAbstract flag, isFinal flag, methods (POUMethod array), properties (POUProperty array)
- `POUInterface`: returnType (string, for functions only), inputs, outputs, inOuts, locals, temps, externals (VAR_EXTERNAL), access (VAR_ACCESS)
- `POUType`: enum of program, functionBlock, function
- `POUMethod`: name, returnType, interface (POUInterface), accessModifier (public | private | protected | internal), isAbstract flag, isFinal flag, body reference
- `POUProperty`: name, type, getter (optional body reference), setter (optional body reference), accessModifier

Why OOP extensions matter: IEC 61131-3 Edition 3+ and vendors like Beckhoff/CODESYS support EXTENDS (inheritance), IMPLEMENTS (interfaces), ABSTRACT/FINAL modifiers, methods, and properties. Real-world projects using these vendors commonly use OOP features. Missing them means incomplete extraction for modern codebases.

Why returnType matters: Functions in IEC 61131-3 have return types. The PLCopen schema has `<returnType>` as part of the interface. The extraction checklist marks this as CRITICAL. Missing it means function signatures are incomplete.

Why externals/access matter: VAR_EXTERNAL lets a POU reference a global variable by name (creating an implicit dependency). VAR_ACCESS defines access paths for communication. The PLCopen schema defines 8 variable scope types — all 8 must be modeled.

**`variable.types.ts`** — Variables and data types.
- `Variable`: name, type (string reference), scope (input | output | inOut | local | temp | external | access | global), initialValue, address (I/O address like %IX0.0), retain flag, persistent flag, constant flag, comment
- `DataType`: name, kind (struct | enum | array | alias | subrange), fields (for struct), values (for enum with optional numeric value), dimensions (for array with lower/upper bounds), baseType (for alias/subrange/array element type), rangeMin/rangeMax (for subrange)

Why retain/persistent matter: RETAIN variables survive power cycles. PERSISTENT variables survive program downloads. These have special semantics that must be preserved in migration.

**`graph.types.ts`** — The unified graph model for graphical languages.
- `FBDBody`: language identifier, array of FBDNetwork, global comments
- `FBDNetwork`: id, number (execution order among networks), label (jump target), comment, nodes array, edges array, computed execution order (node ID array), data flow summary
- `FBDNode`: base with id, type enum, position (x, y), width, height, comment
- `FBDNodeType`: enum of block, inVariable, outVariable, inOutVariable, connector, continuation, return, jump, label, comment
- `BlockNode`: extends FBDNode with typeName, instanceName, inputs (BlockPort array), outputs (BlockPort array), executionOrderId, enableInput (EN), enableOutput (ENO), isUserDefined, libraryPath
- `BlockPort`: name, direction, dataType, negated flag, edge modifier (rising | falling | none), connected edge IDs
- `VariableNode`: extends FBDNode with expression, dataType, isLiteral, literalValue
- `ConnectorNode`: extends FBDNode with name (for matching to continuation)
- `ContinuationNode`: extends FBDNode with name (must match a connector)
- `JumpNode`: extends FBDNode with targetLabel
- `LabelNode`: extends FBDNode with name
- `ReturnNode`: extends FBDNode (no extra fields)
- `CommentNode`: extends FBDNode with content string
- `FBDEdge`: id, sourceNodeId, sourcePort, targetNodeId, targetPort, dataType, negated flag, waypoints (Position array for routing), isFeedback flag
- `Position`: x number, y number

Why connectors exist: FBD diagrams can split across pages using named connector/continuation pairs. The connector is the source, the continuation is the target. They must be resolved into edges during parsing.

Why negation matters: Both inputs and connections can be negated (NOT). This changes the logic without changing the topology.

**`sfc.types.ts`** — Sequential Function Chart types.
- `SFCBody`: language identifier, steps array, transitions array, actions array, branches array
- `SFCStep`: id, name, isInitial flag, actions (SFCActionAssociation array), position
- `SFCTransition`: id, sourceSteps (string array — multiple for simultaneous convergence), targetSteps (string array — multiple for simultaneous divergence), condition (string for ST expression OR FBDNetwork for graphical condition), priority (for selection divergence ordering)
- `SFCAction`: name, qualifier (ActionQualifier), body (can be ST, FBD, or LD — language mixing is common in SFC), duration (for timed qualifiers like L, D, SD, DS, SL)
- `SFCActionAssociation`: links a step to an action with qualifier
- `ActionQualifier`: N (non-stored, execute while active), S (set/latch on), R (reset/latch off), L (time limited), D (time delayed), P (pulse, single scan), P0 (pulse on deactivation), P1 (pulse on activation), SD (stored and delayed), DS (delayed and stored), SL (stored and time limited)
- `SFCBranch`: type (selection | simultaneous), direction (divergence | convergence), paths (step/transition ID array)
- `SFCJumpStep`: id, targetStepName, position — represents a jump back to a named step (loop construct)
- `SFCMacroStep`: id, name, referencedSFC (name of nested SFC body), position, input/output connections
- `StateMachine`: derived model built from SFC — states array, transitions array, initial state, parallel regions

Why SFC is the hardest parser: SFC has nested languages (actions can be ST, FBD, or LD), branching (selection = OR, simultaneous = AND), 11 action qualifiers with timing semantics, macro steps that reference sub-SFCs, and jump steps for loops. All of this must be modeled.

**`ld.types.ts`** — Ladder Diagram types. (Layer 0 — `core/types/ld.types.ts`)
- `LDBody`: language identifier, rungs array
- `LDRung`: id, number, comment, elements (contacts, coils, blocks), connections
- `LDContact`: variable name, type (normally open | normally closed), edge modifier (rising | falling | none)
- `LDCoil`: variable name, type (normal | negated | set | reset)
- `LDPowerRail`: side (left | right)
- `LDBranch`: type (parallel | series), elements array

**`analysis.types.ts`** — Analysis result types.
- `DetectedPattern`: patternId, patternName, category, confidence (0-1), location (POU name, line range), elements (pattern-specific key-value pairs like startInput, stopInput)
- `PatternCategory`: motor_control, process_control, safety, timing, counting, sequencing, analog, communication
- `CallGraphNode`: id, pouType, inDegree, outDegree, isEntryPoint, isLeaf, isOrphan
- `CallGraphEdge`: caller, callee, callType (direct | instance | method), instanceName, callCount, parameterBindings
- `DataFlowAccess`: variable name, readers (POU + location), writers (POU + location), accessPattern (single_writer_single_reader | single_writer_multi_reader | multi_writer)
- `SharedStateWarning`: variable name, writers array, severity, description
- `MultipleWriterWarning`: variable name, writers (POU names), tasks (if cross-task), severity
- `OrphanPOU`: name, reason (never called | unreachable from entry point)
- `CycleInfo`: nodes involved, edges involved, is it a legitimate feedback loop or a bug

Why orphan detection matters: POUs that exist but are never called from any task chain are dead code. Migrating them wastes effort. The scanning pipeline must flag these.

Why multi-writer detection matters: Multiple POUs writing to the same global variable is a race condition risk, especially across tasks. This must be surfaced as a warning.

**`external.types.ts`** — External dependency types.
- `HMITagReference`: hmiTagName, plcVariable, accessMode (read | write | readwrite), screen name, dataType
- `InferredHMIRef`: variable name, reason for inference (naming convention, access pattern), confidence
- `IOMapping`: address (%IX0.0 format), variable name, dataType, direction (input | output | memory), physicalDescription, moduleInfo (type, slot, channel)
- `LibraryDependency`: name, version, vendor, usedPOUs array, usedTypes array
- `OPCUANode`: nodeId, browseName, plcVariable, dataType, accessLevel
- `RecipeVariable`: variableName, recipeParameter, dataType, accessMode, recipeSystem name

**`implicit.types.ts`** — Implicit/hidden dependency types.
- `TimingDependency`: location (POU + line), assumption description, taskCycleTime, risk level
- `ExecutionOrderDependency`: description, tasks involved, assumed order
- `GlobalStateAccess`: variable name, accessors (POU + access type), isCrossTask flag
- `NamingConvention`: pattern (regex), examples, usedBy (POU names), purpose description

Why naming conventions matter: HMI/SCADA systems often auto-discover tags by naming pattern (e.g., all variables ending in `_Run` are motor status). Renaming during migration breaks this. The scanner must detect and document these patterns.

**`safety.types.ts`** — Safety analysis types.
- `SafetyPOUInfo`: pouName, silLevel (SIL1-SIL4 or null), safetyFBsUsed array, safetyVariables array, certificationStatus
- `SafetyBoundary`: safetyPOU name, nonSafetyPOU name, interfaceVariables, validationRequired flag, boundaryType (input | output)
- `CertificationRequirement`: pouName, reason, silLevel, standard (IEC 61508, IEC 62443, etc.)
- `VotingPattern`: type (1oo1 | 1oo2 | 2oo2 | 2oo3 | 1oo2D), inputs, output, diagnosticCoverage
- `SafetyFBUsage`: instanceName, fbType, category (timer | counter | logic | communication | motion), isCertified, certificationInfo

**`migration.types.ts`** — Migration planning types.
- `MigrationMap`: the top-level output — metadata, discovery, structure, entities, relationships, context, migrationPlan, riskAssessment, navigation, validation
- `MigrationPlan`: strategy (bottom-up | top-down | hybrid), phases array, batches array, batchDependencies, humanReviewRequirements, blockers
- `MigrationBatch`: id, name, order, entities array, canParallelize flag, estimatedTokens, riskLevel
- `MigrationEntity`: name, entityType (type | pou | gvl), priority, dependencies, risks, notes
- `HumanReviewRequirement`: entity name, reason, reviewType (safety | logic | timing | external | pattern), priority (required | recommended), checklist items
- `MigrationBlocker`: description, affectedEntities, severity (blocking | warning), resolution suggestion
- `RiskAssessment`: overallScore (0-100), overallRating (low | medium | high | critical), categories (safety, timing, external, complexity, coverage — each with score, rating, factors), individual risks array, mitigations array
- `Risk`: id, category, severity, description, affectedEntities, likelihood (0-1), impact (0-1), mitigation suggestion

**`output.types.ts`** — Output format types.
- `ContextChunk`: id, level (1-4: project | module | entity | code), content, tokenEstimate, crossReferences
- `CrossReference`: from chunk ID, to chunk ID, type (contains | calls | uses_type | reads | writes | instantiates | safety_boundary | hmi_reference | io_mapping)
- `NavigationIndex`: entryPoint, byPOU map, byType map, byPattern map, bySafetyLevel map, hierarchy tree, searchIndex
- `ValidationResult`: isValid, completeness (0-100), checks array, errors array, warnings array, coverage stats

**`vendor-extension.types.ts`** — Vendor extension handling.
- `VendorExtension`: vendor name, extensionName, data (preserved as raw XML string or parsed object), handleUnknown strategy (preserve | ignore | warn)

Why this type exists: PLCopen XML has `<addData>` elements containing arbitrary vendor-specific XML. CODESYS uses it for folder structure, Beckhoff for OOP extensions. Real-world files will contain these. The system must preserve them (for round-trip fidelity) or at minimum not crash on them.

**`provenance.types.ts`** — Provenance and audit trail types.
- `Provenance`: sourceFile, sourceLocation (startLine, endLine, xpath), parserVersion, adapterUsed, confidence (0-1), inferredFields (string array), warnings (string array)
- `AuditEntry`: timestamp, phase, module, action, entity, decision, rationale
- `AuditLog`: entries array, scanId, startTime, endTime

Why provenance matters: For every fact in the MigrationMap, a reviewer must trace it back to the source XML. Safety certification bodies (TÜV, UL) require reproducible, traceable analysis. Without provenance, the output cannot be cited in a safety case.

**`quality.types.ts`** — Self-assessment and completeness types.
- `QualityAssessment`: overallCompleteness (0-100), overallConfidence (0-1), perPhase array, perLanguage array, perVendor array, safetyCompleteness, recommendations (string array)
- `TrustTier`: HIGH | MEDIUM | LOW — computed from completeness and confidence thresholds
- `PhaseQuality`: phase, completeness, duration, errors count, warnings count
- `LanguageQuality`: language, pouCount, parsedCount, failedCount, completeness
- `VendorQuality`: vendor, fileCount, parsedCount, completeness, knownLimitations (string array)
- `SafetyCompleteness`: totalSafetyPOUs, analyzedSafetyPOUs, silAssignments, boundariesDetected, completeness, missingAnalysis (string array)

**`diff.types.ts`** — Scan-to-scan comparison types.
- `ScanDiff`: added, removed, modified, impacted, safetyImpact, summary
- `DiffAdded`: pous (string array), types (string array), variables (string array)
- `DiffRemoved`: pous (string array), types (string array), variables (string array)
- `DiffModified`: entity, changes array (field, previous, current)
- `DiffImpacted`: entity, reason (string — "calls modified POU X" | "uses modified type Y")
- `SafetyDiffImpact`: entity, change, requiresReview (boolean), requiresRecertification (boolean)
- `DiffSummary`: totalChanges, safetyChanges, riskDelta (change in overall risk score)

**`information-loss.types.ts`** — Information loss tracking types.
- `InformationLoss`: droppedElements array, approximations array, unsupportedFeatures array, coverageStats
- `DroppedElement`: element (XPath), file, reason, rawContent (truncated to 1KB)
- `Approximation`: entity, field, original, approximation, reason
- `UnsupportedFeature`: feature, files (string array), impact (low | medium | high), workaround
- `CoverageStats`: totalXMLElements, parsedElements, skippedElements, coveragePercent

Why information loss tracking matters: When a tool says "100% complete" with no caveats, engineers don't trust it. Explicit loss tracking — "97.3% coverage, here are the 14 elements I couldn't parse" — is enterprise-grade honesty.

**`pipeline.types.ts`** — Pipeline extensibility types.
- `PipelineHook`: phase ('discovery' | 'structure' | 'entities' | 'relationships' | 'context' | 'output' | '*'), timing ('before' | 'after'), handler ((context: PhaseContext) → Promise<void>)
- `PhaseContext`: phaseName, input (phase-specific), config, logger, progress, audit
- `PluginConfig`: adapters (IVendorAdapter array), patternDetectors (IPatternDetector array), contextExtractors (IContextExtractor array), safetyFBs (SafetyFBEntry array), outputFormats (IOutputFormat array), pipelineHooks (PipelineHook array)

Why pipeline types matter: These types define the plugin contract. Any consumer can extend the system via configuration without forking the package. The orchestrator iterates registries populated from defaults + config — it never needs to change when capabilities are added.

### Interfaces to Define

The complete `core/interfaces/` directory:
```
core/interfaces/
├── vendor-adapter.interface.ts       # IVendorAdapter
├── language-parser.interface.ts      # ILanguageParser<T>
├── pattern-detector.interface.ts     # IPatternDetector
├── context-extractor.interface.ts    # IContextExtractor<T>
├── safety-analyzer.interface.ts      # ISafetyAnalyzer
├── feedback-handler.interface.ts     # IFeedbackHandler
├── layout-engine.interface.ts        # ILayoutEngine
├── context-chunker.interface.ts      # IContextChunker
└── output-format.interface.ts        # IOutputFormat
```

**`IVendorAdapter`**: vendorId, supportedVersions, supportedLanguages, detect(content) → DetectionResult, parse(content) → UnifiedProject, validate(content) → ValidationResult

**`ILanguageParser<T>`**: language, parse(xmlElement, context) → ParseResult<T>, canParse(xmlElement) → boolean

**`IPatternDetector`**: patternId, patternName, category, detect(network) → PatternMatch | null, getConfidence(match) → number

**`IContextExtractor<T>`**: name, category (external | safety | timing | implicit), extract(entities, relationships, context) → T, isApplicable(entities) → boolean

**`ISafetyAnalyzer`**: detectSILRating(pou) → SILRating | null, identifySafetyBoundary(project) → SafetyBoundary[], flagCertificationRequired(pou) → CertificationRequirement[], detectVotingLogic(network) → VotingPattern | null, identifySafetyFBs(project) → SafetyFBUsage[]

**`IFeedbackHandler`**: detectFeedbackLoops(network) → FeedbackLoop[], resolveFeedbackSemantics(loop) → FeedbackResolution, generatePreviousValueCode(loop) → string. Defined in `core/interfaces/feedback-handler.interface.ts` so Layer 3 parsers can reference it without importing from Layer 4.

**`ILayoutEngine`**: layout(network, options) → LayoutResult (async)

**`IContextChunker`**: chunk(project, options) → ChunkResult, estimateTokens(content) → number, buildCrossReferences(chunks) → CrossReference[], buildNavigationIndex(chunks) → NavigationIndex

**`IOutputFormat`**: formatId, formatName, generate(map, options) → string | Buffer, fileExtension

### Errors to Define

The complete `core/errors/` directory:
```
core/errors/
├── base-error.ts                     # PLCIndexerError base class
├── parse-error.ts                    # ParseError (file path, line, element)
├── validation-error.ts              # ValidationError (field path, expected vs actual)
├── adapter-error.ts                 # AdapterError (vendor, format)
└── scan-error.ts                    # ScanError (phase name, partial results)
```

- `PLCIndexerError`: base class with code, message, context
- `ParseError`: extends base, adds file path, line number, element name
- `ValidationError`: extends base, adds field path, expected vs actual
- `AdapterError`: extends base, adds vendor, format
- `ScanError`: extends base, adds phase name, partial results

### Constants to Define

The complete `core/constants/` directory:
```
core/constants/
├── languages.ts                      # LANGUAGES enum
├── vendors.ts                        # VENDORS enum + VENDOR_DETECTION_PATTERNS
├── safety-fbs.ts                     # SAFETY_FB_CATALOG
├── action-qualifiers.ts             # ACTION_QUALIFIERS with descriptions
└── namespaces.ts                    # PLCOPEN_NAMESPACES
```

- `LANGUAGES`: ST, FBD, LD, SFC, IL
- `VENDORS`: PLCopen, Rockwell, Siemens, Schneider, Beckhoff, CODESYS
- `SAFETY_FB_CATALOG`: array of known safety FBs with vendor, category, certification info, SIL level (F_TON, F_TOF, F_TP, F_CTU, F_CTD, F_AND, F_OR, F_NOT, F_RS, F_SR, plus vendor-specific: Siemens ESTOP1/TWO_H_EN, Rockwell CROUT/DCS, Pilz SF_EDM/SF_ESTOP)
- `ACTION_QUALIFIERS`: N, S, R, L, D, P, P0, P1, SD, DS, SL with descriptions and timing behavior
- `PLCOPEN_NAMESPACES`: map of namespace URI → format/version
- `VENDOR_DETECTION_PATTERNS`: regex patterns per vendor for fingerprinting

### Layer 0 Incremental Tests — Build Before Moving to Layer 1

These tests are written and passing BEFORE any Layer 1 code exists. They catch silent type errors, missing exports, and broken contracts early.

**Test file:** `tests/unit/core/core.test.ts`

| Test | What It Catches | Pass Criteria |
|------|----------------|---------------|
| All 18 type files compile with zero errors | Typos, circular type refs, missing imports | `tsc --noEmit` exits 0 |
| Every type file is re-exported from `core/index.ts` | Missing barrel exports (silent import failures downstream) | Import every public type from `@plc-indexer/core` — no undefined |
| All 9 interfaces are importable and structurally correct | Interface contract drift | Create a mock implementing each interface — TypeScript compiles |
| All 5 error classes extend `PLCIndexerError` | Broken error hierarchy | `new ParseError(...) instanceof PLCIndexerError === true` |
| Error classes carry correct `code` field | Silent error misclassification | `new ParseError(...).code === 'PARSE_ERROR'` |
| `LANGUAGES` enum has exactly 5 members | Missing language constant | `Object.keys(LANGUAGES).length === 5` |
| `VENDORS` enum has exactly 6 members | Missing vendor constant | `Object.keys(VENDORS).length === 6` |
| `SAFETY_FB_CATALOG` has entries for all 3 vendor families | Incomplete safety catalog | Filter by vendor — Siemens, Rockwell, Pilz each have ≥2 entries |
| `ACTION_QUALIFIERS` has exactly 11 entries | Missing SFC qualifier | `Object.keys(ACTION_QUALIFIERS).length === 11` |
| `Result<T,E>` ok/err constructors work | Broken error recovery pattern | `Result.ok(42).isOk === true`, `Result.err(new Error()).isErr === true` |
| `Result.unwrap()` throws on err | Silent error swallowing | `expect(() => Result.err(...).unwrap()).toThrow()` |
| Logger outputs valid JSON to stdout | Broken structured logging | Parse logger output with `JSON.parse` — no throw |
| Logger respects log level config | Noisy logs in production | Set level to 'error', call logger.debug() — no output |
| Audit log appends entries with timestamps | Missing audit trail | Append 3 entries, read back — 3 entries with valid ISO timestamps |
| Audit log entries are JSONL (one JSON per line) | Broken audit format | Split by newline, parse each line — all valid JSON |
| `Provenance` type requires sourceFile field | Missing traceability | Construct without sourceFile — TypeScript error |

**Quality Gate QG-0:** All 16 tests pass. `tsc --noEmit` on entire `core/` exits 0. Zero `any` types in core. Only then proceed to Layer 1.

---

## Layer 1: Ingestion

**Purpose:** Discover files, detect formats, fingerprint vendors, classify what can be parsed vs what needs manual export.

**Why it's separate from adapters:** Discovery is breadth-first — scan everything, classify everything, before parsing anything. This follows the scanning pipeline's principle: "Know what exists before diving into details."

### Modules

**`format-sniffer.ts`** — Detect file format from content.
- Input: file path or raw content string
- Output: `DetectionResult` with format (PLCopen_XML | L5X | SimaticML | CODESYS | PlainST | Unknown), version, vendor, languages found, confidence (0-1), warnings
- Detection strategy (in priority order): XML namespace check → root element check → schema validation → vendor signature patterns → file extension fallback
- Must handle: files that are XML but not PLC-related, files with BOM markers, files with mixed encodings
- PLCopen detection: namespace `http://www.plcopen.org/xml/tc6_0201` or `tc6_0200`
- Rockwell detection: root element `<RSLogix5000Content>`, no namespace used
- Siemens detection: namespace containing `siemens.com/automation/Openness`, elements like `<SW.Blocks`
- CODESYS detection: `<project>` with CODESYS-specific attributes, `3S-Smart Software` in content

**`file-loader.ts`** — Load files from disk with validation.
- Input: file path
- Output: raw content string
- Must enforce max file size (configurable, default 50MB)
- Must detect binary files and reject them (PLC projects often contain binary .ap13, .zap files that need vendor IDE export first)
- Must handle UTF-8, UTF-16, and ISO-8859-1 encodings

**`project-scanner.ts`** — Recursively scan directories for PLC files.
- Input: directory path, include/exclude glob patterns
- Output: `FileInventory` with discovered files, vendor fingerprint, export requirements, warnings
- Must classify each file: project | library | export | config | unknown
- Must identify files that need manual export (binary vendor files) and generate human-readable instructions
- Must compute content hashes for incremental rescan support

**`schema-validator.ts`** — Validate XML against PLCopen XSD.
- Input: XML content, expected format
- Output: validation result with errors/warnings
- Must handle: missing optional elements gracefully, vendor extensions in `<addData>`, namespace variations between PLCopen versions

### Data Flow

```
Directory path → project-scanner → FileInfo[] → format-sniffer (per file) → DetectionResult[]
                                                                              ↓
                                                              vendor fingerprinting (aggregate)
                                                                              ↓
                                                              FileInventory (with export requirements)
```

### Layer 1 Incremental Tests — Build Before Moving to Layer 2

These tests validate that ingestion works correctly in isolation before any adapter code exists.

**Test file:** `tests/unit/ingestion/ingestion.test.ts`

| Test | What It Catches | Pass Criteria |
|------|----------------|---------------|
| `format-sniffer` detects PLCopen XML by namespace | Wrong format classification → wrong adapter selected | `detect(plcopenXml).format === 'PLCopen_XML'` with confidence >0.9 |
| `format-sniffer` detects Rockwell L5X by root element | L5X misclassified as generic XML | `detect(l5xContent).format === 'L5X'` |
| `format-sniffer` detects Siemens by namespace substring | SimaticML missed entirely | `detect(simaticContent).format === 'SimaticML'` |
| `format-sniffer` returns Unknown for non-PLC XML | False positive on random XML (e.g., SVG, HTML) | `detect('<svg>...</svg>').format === 'Unknown'` |
| `format-sniffer` detects plain ST files | ST files skipped by scanner | `detect('PROGRAM Main...END_PROGRAM').format === 'PlainST'` |
| `format-sniffer` handles BOM markers | UTF-16 BOM causes parse failure | File with BOM → still detects format correctly |
| `file-loader` rejects binary files | Binary .acd/.ap13 crash the parser | Load a binary file → throws `ParseError` with helpful message |
| `file-loader` enforces max file size | OOM on huge files | Load 51MB file → throws with size limit message |
| `file-loader` handles UTF-8, UTF-16, ISO-8859-1 | Encoding mismatch → garbled content | Load each encoding → content matches expected string |
| `project-scanner` finds all XML files recursively | Nested files missed | Scan fixture dir with nested folders → all .xml files found |
| `project-scanner` respects exclude patterns | node_modules or build dirs scanned | Exclude `**/build/**` → no build dir files in result |
| `project-scanner` computes content hashes | Incremental rescan broken | Scan same file twice → same hash. Modify file → different hash |
| `project-scanner` classifies binary vs parseable | Binary files sent to adapter → crash | Binary .acd in fixture → classified as `needs_export` |
| `project-scanner` generates export instructions for binary files | User doesn't know how to export | Binary file found → `exportInstructions` is non-empty human-readable string |
| `schema-validator` accepts valid PLCopen XML | Valid files rejected | Validate plcopen-sample.xml → `isValid === true` |
| `schema-validator` rejects malformed XML | Bad XML silently accepted | Validate truncated XML → `isValid === false` with error details |
| `schema-validator` tolerates `<addData>` vendor extensions | Vendor extensions cause validation failure | PLCopen with `<addData>` → still valid |

**Silent failure smoke test:** Feed `format-sniffer` an empty string, null bytes, and a 1-byte file. None should throw an unhandled exception — all should return `Unknown` with confidence 0.

**Quality Gate QG-1:** All 17 tests pass. format-sniffer correctly classifies all 4 vendor formats + ST + Unknown. file-loader rejects binary. project-scanner finds all files. Only then proceed to Layer 2.

---

## Layer 2: Adapters

**Purpose:** Transform vendor-specific XML into the unified project model. Each adapter knows one vendor's XML dialect and produces the same output type.

**Why the adapter pattern:** Vendor fragmentation is the #1 challenge. Siemens uses `<Call>` where PLCopen uses `<block>`. Rockwell uses `<Wire>` as separate elements where PLCopen nests connections inside blocks. The adapter pattern isolates this complexity.

### Modules

**`adapter-registry.ts`** — Register and lookup adapters by format.
- Maps DetectionResult.format → IVendorAdapter
- Supports fallback (unknown format → attempt PLCopen)

**`base-adapter.ts`** — Abstract base with shared XML utilities.
- Common XML traversal helpers (find element, get attribute, resolve namespace)
- Common type mapping (vendor type names → unified type names)
- Vendor extension extraction (preserve `<addData>` content)

**`plcopen/plcopen-adapter.ts`** — Primary adapter. PLCopen XML (IEC 61131-10) is the interchange format most vendors can export to.
- `plcopen-project.ts`: parse `<project>` root → extract fileHeader, contentHeader, coordinateInfo
- `plcopen-pou.ts`: parse `<pou>` elements → extract name, pouType, interface (all 8 variable scopes), returnType, documentation. Does NOT parse body yet — just the shell.
- `plcopen-body.ts`: route `<body>` to language-specific parser based on child element (FBD | LD | ST | SFC | IL)
- `plcopen-types.ts`: parse `<dataTypes>` → extract structs, enums, arrays, aliases, subranges
- `plcopen-config.ts`: parse `<instances><configurations>` → extract configuration hierarchy, tasks, POU instances, global variables

Key PLCopen parsing detail: Connections in PLCopen XML are back-references. An `<outVariable>` has a `<connectionPointIn>` with `<connection refLocalId="20" formalParameter="OUT"/>` — this means "my input comes from element 20, port OUT." This is backwards from how you'd naturally build a graph (source → target). The adapter must invert these during edge construction.

**`rockwell/l5x-adapter.ts`** — Rockwell Allen-Bradley L5X format.
- `l5x-controller.ts`: parse `<Controller>` → extract programs, tasks, tags
- `l5x-routine.ts`: parse `<Routine>` → extract FBD sheets, LD rungs, ST code
- `l5x-tag.ts`: parse `<Tag>` → extract variables with scope, type, address
- `l5x-aoi.ts`: parse Add-On Instructions (Rockwell's equivalent of Function Blocks)

Key L5X difference: Wires are separate elements (`<Wire FromID="0" ToID="1" ToParam="In1"/>`) rather than nested in blocks. Sheets group networks. IRef/ORef elements replace inVariable/outVariable.

**`siemens/simatic-adapter.ts`** — Siemens TIA Portal SimaticML format.
- `simatic-block.ts`: parse `<SW.Blocks.FB>`, `<SW.Blocks.FC>`, `<SW.Blocks.OB>`, `<SW.Blocks.DB>` → extract POUs and data blocks
- `simatic-network.ts`: parse `<FlgNet>` → extract Parts (Access, Call) and Wires (IdentCon, NameCon)
- `simatic-multi-instance.ts`: handle Siemens multi-instance data blocks (a DB that contains FB instances — unique to Siemens)

Key Siemens difference: No position data in XML — auto-layout is always required. Uses `<Access>` for variables and `<Call>` for blocks. Wire endpoints use `<IdentCon>` (by ID) and `<NameCon>` (by name + parameter).

**`codesys/codesys-adapter.ts`** — CODESYS export format.
- `codesys-library.ts`: parse library references and resolve used POUs/types

Key CODESYS detail: CODESYS is used by 200+ OEMs (Beckhoff, Wago, etc.). Its export format is close to PLCopen XML but uses `<addData>` extensively for folder structure and OOP extensions.

### Layer 2 Incremental Tests — Build Before Moving to Layer 3

These tests validate that adapters produce correct unified models before any parser touches POU bodies.

**Test file:** `tests/unit/adapters/adapters.test.ts`

| Test | What It Catches | Pass Criteria |
|------|----------------|---------------|
| `adapter-registry` returns PLCopen adapter for PLCopen_XML format | Wrong adapter selected | `registry.get('PLCopen_XML')` returns PLCopen adapter instance |
| `adapter-registry` returns null for unknown format | Crash on unknown format | `registry.get('Unknown')` returns null, no throw |
| PLCopen adapter extracts project metadata (name, vendor, version) | Missing project context | Parse plcopen-sample.xml → metadata fields are non-empty strings |
| PLCopen adapter extracts ALL POU names and types | POUs silently dropped | Parse sample → POU count matches expected, each has name + pouType |
| PLCopen adapter extracts POU interfaces (all 8 variable scopes) | Missing VAR_EXTERNAL/VAR_ACCESS → broken dependency tracking | Parse POU with all scope types → all 8 scopes present in interface |
| PLCopen adapter extracts returnType for functions | Function signatures incomplete | Parse a FUNCTION POU → `returnType` is non-null |
| PLCopen adapter extracts data types (struct, enum, array, alias) | Custom types missing → type resolution fails | Parse sample with types → all type kinds present |
| PLCopen adapter extracts configuration hierarchy | Entry points unknown → orphan detection broken | Parse sample → Configuration → Resource → Task → POUInstance chain intact |
| PLCopen adapter preserves `<addData>` as vendor extensions | Vendor data silently dropped | Parse file with `<addData>` → vendorExtensions array is non-empty |
| PLCopen adapter does NOT parse POU bodies at this stage | Premature body parsing wastes time on breadth-first scan | Parse sample → POU bodies are null/deferred references, not parsed FBDBody |
| Connection back-reference inversion produces correct source→target edges | Edges are backwards → entire graph is wrong | Parse FBD network → edge.sourceNodeId points to the block producing data, edge.targetNodeId points to the consumer |
| Siemens adapter handles missing position data | Null positions crash layout engine | Parse Siemens XML → all nodes have position = null (not undefined, not crash) |
| Rockwell adapter parses wire-based connections | Wires ignored → no edges in graph | Parse L5X → edges created from `<Wire>` elements |
| Rockwell adapter parses AOIs as function blocks | AOIs missing → incomplete call graph | Parse L5X with AOI → AOI appears as POU with pouType = functionBlock |

**Cross-layer integration smoke test:** `format-sniffer` → `adapter-registry.get(result.format)` → `adapter.parse()` → valid UnifiedProject. This chain must work end-to-end for PLCopen XML before proceeding.

**Quality Gate QG-2:** All 14 tests pass. PLCopen adapter produces complete project shells (metadata, POUs, types, config hierarchy) without body parsing. Back-reference inversion is correct. Only then proceed to Layer 3.

---

## Layer 3: Parsers

**Purpose:** Parse language-specific POU bodies into typed models. Each parser handles one of the 5 IEC 61131-3 languages.

**Why separate from adapters:** Adapters handle vendor XML structure. Parsers handle language semantics. A PLCopen XML file can contain FBD, LD, ST, SFC, and IL bodies — the adapter routes to the correct parser.

### FBD Parser (`parsers/fbd/`)

The project lead's priority. Most complex graphical parser.

**`fbd-parser.ts`** — Orchestrator. Parse `<FBD>` element into FBDBody.
- Iterate `<network>` children
- For each network: parse all node types, collect edge builders, resolve edges, compute execution order

**`fbd-block.ts`** — Parse `<block>` elements into BlockNode.
- Extract typeName, instanceName, executionOrderId
- Parse inputVariables (each with formalParameter, negated flag, edge modifier, connectionPointIn)
- Parse outputVariables (each with formalParameter, connectionPointOut)
- Detect EN/ENO pins (enableInput/enableOutput flags)

**`fbd-connection.ts`** — Resolve `<connection refLocalId>` back-references into FBDEdge objects.
- Walk all nodes that have `<connectionPointIn>` elements
- For each `<connection>`: create edge from refLocalId (source) to current node (target), with formalParameter as target port
- Handle: missing refLocalId (dangling reference), multiple connections to same input (fan-in)

**`fbd-execution-order.ts`** — Compute execution order for blocks in a network.
- If explicit `executionOrderId` attributes exist on blocks: use them (sort ascending)
- Otherwise: compute from position (left-to-right, top-to-bottom) — this is the IEC 61131-3 default
- Only blocks have execution order, not variables or comments

**`fbd-enable-logic.ts`** — Handle EN/ENO conditional execution.
- When a block has EN pin: the block only executes if EN is TRUE
- When a block has ENO pin: ENO reflects whether the block executed successfully
- Must model this in the graph (EN/ENO are special ports that affect control flow, not just data flow)

**`fbd-negation.ts`** — Handle negated inputs.
- A block input can have `negated="true"` — this means the value is inverted before entering the block
- A connection can also be negated
- Must be preserved in the graph model for correct ST generation

**`fbd-connector.ts`** — Resolve connector/continuation pairs.
- `<connector name="X">` is a named output point
- `<continuation name="X">` is a named input point that references the connector
- Must resolve these into edges (connector → continuation) by matching names
- Used for cross-page connections in large diagrams

### LD Parser (`parsers/ld/`)

**`ld-parser.ts`** — Parse `<LD>` element into LDBody.
**`ld-rung.ts`** — Parse individual rungs with power rails.
**`ld-contact.ts`** — Parse contacts (NO/NC, edge detection) and coils (normal, negated, set, reset).

Key LD detail: LD is structured as rungs between left and right power rails. Contacts are inputs (conditions), coils are outputs (actions). Branches create parallel logic paths. Function blocks can appear inline within rungs.

### SFC Parser (`parsers/sfc/`)

The hardest parser. SFC has nested languages, branching, and timing semantics.

**`sfc-parser.ts`** — Orchestrator. Parse `<SFC>` element into SFCBody.
**`sfc-step.ts`** — Parse `<step>` elements. Extract name, isInitial flag, action associations.
**`sfc-transition.ts`** — Parse `<transition>` elements. Extract source/target steps, condition (which can be an ST expression OR an inline FBD/LD body — language mixing).
**`sfc-action.ts`** — Parse action bodies. Each action has a qualifier and a body in any language.
**`sfc-branch.ts`** — Parse `<selectionDivergence>`, `<selectionConvergence>`, `<simultaneousDivergence>`, `<simultaneousConvergence>`. Selection = OR (alternative paths). Simultaneous = AND (parallel paths).
**`sfc-qualifier.ts`** — Parse and validate action qualifiers (N, S, R, L, D, P, P0, P1, SD, DS, SL). Timed qualifiers (L, D, SD, DS, SL) require a duration parameter.
**`sfc-jump-step.ts`** — Parse `<jumpStep>` elements. These represent jumps back to named steps (loop constructs in SFC).
**`sfc-macro-step.ts`** — Parse macro steps that reference nested SFC bodies. Expand by inlining the referenced SFC.
**`sfc-state-machine.ts`** — Build a StateMachine model from the parsed SFC. This is a derived representation useful for analysis and visualization.

### ST Parser (`parsers/st/`)

Easiest language to parse — it's textual, Pascal-like.

**`st-parser.ts`** — Parse ST body text. For P1, this can be minimal: store raw source text, extract function/FB calls via regex or simple tokenization. Full AST parsing (lexer → parser → AST) is a Phase 2 enhancement.
**`st-lexer.ts`** — Tokenize ST source (keywords, identifiers, operators, literals).
**`st-ast.ts`** — Build AST from tokens. Needed for accurate data flow analysis of ST bodies.

### IL Parser (`parsers/il/`)

**`il-parser.ts`** — Parse Instruction List. IL is deprecated (removed in Edition 4, 2025) but exists in legacy code. Line-by-line parsing: each line is an operator + operand. Minimal investment here.

### Layer 3 Incremental Tests — Build Before Moving to Layer 4

These tests validate each language parser in isolation. FBD is the most critical — it gets the most tests.

**Test file:** `tests/unit/parsers/fbd-parser.test.ts`

| Test | What It Catches | Pass Criteria |
|------|----------------|---------------|
| FBD parser produces correct node count from sample network | Nodes silently dropped | Parse 3-block network → exactly 3 BlockNodes + expected variable nodes |
| FBD parser resolves `<connection refLocalId>` into edges | Back-references not inverted → no data flow | Parse network with connections → edge count matches expected |
| FBD parser assigns correct source/target ports on edges | Port names wrong → ST generation produces garbage | Edge from AND block output → target block input has correct formalParameter |
| FBD execution order uses explicit `executionOrderId` when present | Explicit order ignored → wrong execution sequence | Parse network with executionOrderId attrs → order matches attr values |
| FBD execution order falls back to position (left→right, top→bottom) when no explicit IDs | Position-based order broken → wrong execution | Parse network without executionOrderId → order matches spatial sort |
| FBD EN/ENO pins detected on blocks | Conditional execution missed → logic errors | Parse block with EN input → `block.enableInput === true` |
| FBD negated inputs preserved | NOT logic silently dropped → inverted behavior | Parse block with `negated="true"` input → `port.negated === true` |
| FBD connector/continuation pairs resolve to edges | Cross-page connections broken → disconnected graph | Parse network with connector "X" and continuation "X" → edge exists between them |
| FBD connector with no matching continuation produces warning | Dangling connector silently ignored | Parse orphan connector → warning in result, no crash |
| FBD handles fan-in (multiple connections to same input) | Only first connection kept → data loss | Parse input with 2 connections → both edges exist |

**Test file:** `tests/unit/parsers/sfc-parser.test.ts`

| Test | What It Catches | Pass Criteria |
|------|----------------|---------------|
| SFC parser extracts initial step | No initial state → state machine broken | Parse SFC → exactly one step with `isInitial === true` |
| SFC parser extracts all 11 action qualifiers | Missing qualifier → wrong timing behavior | Parse actions with each qualifier → all 11 recognized |
| SFC timed qualifiers (L, D, SD, DS, SL) carry duration | Duration silently dropped → timers don't work | Parse timed action → `duration` is non-null string |
| SFC transition with ST condition | Condition lost → transitions never fire | Parse transition → `condition` is non-empty string |
| SFC transition with inline FBD condition (language mixing) | FBD condition ignored → transition broken | Parse transition with FBD body → condition is FBDNetwork, not string |
| SFC selection divergence produces correct branch structure | Alternative paths lost | Parse selection divergence → `branch.type === 'selection'`, paths.length ≥ 2 |
| SFC simultaneous divergence produces correct branch structure | Parallel paths lost | Parse simultaneous divergence → `branch.type === 'simultaneous'` |
| SFC jump step references target by name | Jump targets broken → infinite loops or dead ends | Parse jump step → `targetStepName` matches an existing step name |
| SFC state machine builder produces valid StateMachine | Derived model broken → visualization wrong | Build state machine from SFC → states.length === steps.length, initial state set |

**Test file:** `tests/unit/parsers/ld-parser.test.ts`

| Test | What It Catches | Pass Criteria |
|------|----------------|---------------|
| LD parser extracts rungs with correct numbering | Rungs out of order → logic sequence wrong | Parse 3-rung LD → rung numbers are 1, 2, 3 |
| LD contacts have correct type (NO/NC) and edge modifier | Contact type wrong → inverted logic | Parse NO and NC contacts → types match |
| LD coils have correct type (normal/set/reset) | Coil type wrong → latch behavior broken | Parse set coil → `coil.type === 'set'` |
| LD branches create parallel paths | Parallel logic lost → simplified incorrectly | Parse rung with branch → branch elements present |

**Test file:** `tests/unit/parsers/st-parser.test.ts`

| Test | What It Catches | Pass Criteria |
|------|----------------|---------------|
| ST parser stores raw source text | Source code lost | Parse ST body → `rawSource` is non-empty |
| ST parser extracts function/FB calls | Call graph incomplete | Parse ST with `TON_inst(IN:=x, PT:=T#5s)` → call to TON detected |

**Test file:** `tests/unit/parsers/il-parser.test.ts`

| Test | What It Catches | Pass Criteria |
|------|----------------|---------------|
| IL parser handles basic instruction lines | IL bodies crash parser | Parse `LD x / AND y / ST z` → 3 instructions parsed |

**Quality Gate QG-3:** All FBD tests pass (10 tests). All SFC tests pass (9 tests). LD and ST/IL basic tests pass. Connection resolution is verified correct. Execution order is verified correct. Only then proceed to Layer 4.

---

## Layer 4: Graph

**Purpose:** Provide the unified graph model, traversal utilities, and format converters. This is the internal representation that all analysis operates on.

### Modules

**`model/`** — Node and edge classes (graph-node, block-node, variable-node, control-node, sfc-node, graph-edge)

**`network/`** — Network containers (fbd-network, ld-network, sfc-network, network-builder)

**`utils/graph-traversal.ts`** — DFS, BFS, topological sort on graph structures.
**`utils/cycle-detection.ts`** — Detect cycles (feedback loops) using DFS back-edge detection.
**`utils/feedback-handler.ts`** — Handle feedback loop semantics. In FBD, feedback loops use the previous scan's value. This module: detects loops, identifies entry/exit points, determines temp variables needed for previous-value injection, adjusts execution order.
**`utils/predecessors.ts`** — Find all upstream nodes for a given node.
**`utils/successors.ts`** — Find all downstream nodes for a given node.

**`converters/to-elk.ts`** — Convert graph model to ELK JSON format for layout computation.
**`converters/to-reactflow.ts`** — Convert graph model to React Flow nodes/edges for rendering.
**`converters/to-st.ts`** — Convert FBD/LD network to equivalent Structured Text code. This is critical for AI consumption — LLMs understand text better than graph structures.
**`converters/sfc-to-state-diagram.ts`** — Convert SFC to a state diagram representation for visualization.

### Layer 4 Incremental Tests — Build Before Moving to Layer 5

These tests validate the graph model, traversal algorithms, and converters before any analysis code depends on them.

**Test file:** `tests/unit/graph/graph.test.ts`

| Test | What It Catches | Pass Criteria |
|------|----------------|---------------|
| Graph traversal DFS visits all reachable nodes | Disconnected subgraphs silently ignored | Build 5-node graph → DFS from root visits all 5 |
| Graph traversal BFS produces correct level ordering | Level order wrong → dependency analysis broken | BFS from root → nodes returned in breadth-first order |
| Topological sort produces valid ordering | Execution order wrong → logic errors | Sort DAG → for every edge (u,v), u appears before v |
| Topological sort detects cycles | Cycles silently ignored → infinite loops | Sort graph with cycle → returns cycle info, not a valid ordering |
| Cycle detection finds all back edges | Feedback loops missed → wrong ST generation | Graph with 2 cycles → both detected |
| Feedback handler identifies loop entry/exit points | Previous-value injection wrong → subtle logic bugs | Feedback loop → entry node and exit node correctly identified |
| Feedback handler determines temp variables needed | Missing temp vars → compilation errors in generated ST | Feedback loop → `previousValueVars` array is non-empty |
| Predecessors returns all upstream nodes | Incomplete upstream analysis → missing dependencies | Node with 3 predecessors → all 3 returned |
| Successors returns all downstream nodes | Incomplete downstream analysis → missing impact | Node with 2 successors → both returned |
| `to-elk` converter produces valid ELK JSON | Invalid ELK input → layout engine crashes | Convert sample network → output has `id`, `children`, `edges` with valid structure |
| `to-elk` converter maps ports correctly | Port positions wrong → edges connect to wrong pins | Convert block with 2 inputs, 1 output → ELK node has 3 ports with correct sides |
| `to-reactflow` converter produces valid React Flow nodes/edges | Rendering crashes | Convert sample → every node has `id`, `position`, `type`; every edge has `source`, `target` |
| `to-st` converter produces compilable ST from simple FBD | Generated ST is syntactically wrong | Convert AND block with 2 inputs → output contains `:= input1 AND input2` |
| `to-st` converter handles EN/ENO in generated ST | Conditional execution lost in text form | Convert block with EN → output contains `IF EN THEN` guard |
| `sfc-to-state-diagram` produces valid state diagram | Visualization model broken | Convert SFC → states match steps, transitions match SFC transitions |

**Quality Gate QG-4:** All 15 tests pass. Topological sort is correct. Cycle detection works. ELK converter produces valid JSON. ST converter produces parseable output. Only then proceed to Layer 5.

---

## Layer 5: Analysis

**Purpose:** Extract entities, build relationships, detect patterns, analyze safety, and surface hidden dependencies. This is the intelligence layer.

### Entity Extraction (`analysis/entities/`)

**`entity-extractor.ts`** — Orchestrate full extraction from a parsed project. Produces EntityCatalog.
**`pou-analyzer.ts`** — Per-POU analysis: complexity assessment (low/medium/high based on line count, call count, branch depth), language statistics, flag computation (isSafety, isOrphan, isEntryPoint, hasExternalDeps).
**`variable-analyzer.ts`** — Variable usage analysis: collect all variables across all POUs, identify I/O addresses, flag RETAIN/PERSISTENT, detect unused variables.
**`type-analyzer.ts`** — Data type dependency graph: which types reference which other types, topological ordering for migration.

### Relationship Analysis (`analysis/relationships/`)

**`call-graph-builder.ts`** — Build the call graph. For each POU body: find all FB instantiations (instance calls) and function calls. Record caller, callee, instance name, parameter bindings. Detect recursive calls. Calculate depth from entry points.
**`data-flow-analyzer.ts`** — Track variable reads and writes across all POUs. Build producer-consumer graph. Detect multi-writer scenarios (multiple POUs writing same global). Classify access patterns.
**`dependency-mapper.ts`** — Map all dependencies: call deps, type deps, variable deps. Compute transitive closure. Identify orphan POUs (never reachable from any entry point).
**`fb-instance-tracker.ts`** — Track all FB instances: which types are instantiated where, how many instances of each type, instance naming patterns.

### External Dependencies (`analysis/external/`)

**`hmi-tag-extractor.ts`** — Extract HMI tag references. Strategy: parse HMI configuration files if available, infer from variable naming patterns and access modifiers, check for OPC UA publish attributes.
**`io-mapping-analyzer.ts`** — Analyze physical I/O mappings. Collect all variables with addresses (%I, %Q, %M). Map to physical descriptions if available. Identify direction (input/output/memory).
**`library-dependency.ts`** — Track library usage. Which external libraries are referenced, which POUs and types from each library are used.
**`opcua-namespace.ts`** — Extract OPC UA namespace structure if present. Identifies variables exposed to external systems.
**`recipe-system.ts`** — Track recipe system variable references. Identifies variables written by external recipe managers.

### Implicit Dependencies (`analysis/implicit/`)

**`timing-dependency.ts`** — Detect timing assumptions. Find: timer usage with hardcoded presets (assumes specific scan rate), counter-based debounce (assumes specific scan rate), sequence timing.
**`global-state-tracker.ts`** — Track shared state via global variables. Identify cross-task access patterns. Flag potential race conditions.
**`execution-order-deps.ts`** — Detect position-based execution order dependencies. In FBD, execution order is determined by position — changing layout changes behavior.
**`convention-detector.ts`** — Detect naming conventions. Find patterns like `*_Run`, `*_Fault`, `*_Status` that may be used by HMI/SCADA for auto-discovery. Document these as migration constraints.

### Pattern Detection (`analysis/patterns/`)

**`pattern-registry.ts`** — Register and manage pattern detectors.
**`pattern-matcher.ts`** — Run all registered detectors against a network/POU. Collect matches with confidence scores.

12 detectors in `analysis/patterns/detectors/`, each implementing IPatternDetector:

| Detector | What it finds | Confidence threshold |
|----------|--------------|---------------------|
| `motor-control.ts` | Start/stop latching with interlocks | 0.85 |
| `pid-control.ts` | PID loop with SP/PV/OUT | 0.90 |
| `state-machine.ts` | CASE-based state logic | 0.80 |
| `analog-scaling.ts` | Raw to engineering unit conversion | 0.85 |
| `timer-usage.ts` | TON/TOF/TP patterns | 0.90 |
| `safety-interlock.ts` | E-stop, safety chains | 0.95 |
| `cascade-control.ts` | Nested PID loops (outer sets inner SP) | 0.85 |
| `voting-logic.ts` | 2oo3, 1oo2, 1oo2D redundancy | 0.90 |
| `latching-logic.ts` | Set/reset with feedback | 0.85 |
| `edge-detection.ts` | R_TRIG/F_TRIG usage patterns | 0.95 |
| `counter-pattern.ts` | CTU/CTD/CTUD usage | 0.90 |
| `sequencer-pattern.ts` | Step-based sequencing (non-SFC) | 0.80 |

### Safety Analysis (`analysis/safety/`)

**`safety-analyzer.ts`** — Orchestrate safety analysis. Produces SafetyAnalysisResult.
**`sil-detector.ts`** — Detect SIL rating from: safety FB usage, SAFEBOOL/SAFEINT types, naming conventions (S_, Safe_, Safety_ prefixes), vendor-specific safety markers.
**`safety-flags.ts`** — Generate safety warnings: "do not modify without re-certification", "requires dual-channel verification", etc.
**`safety-fb-catalog.ts`** — Lookup table of known safety FBs. Used by sil-detector. Extensible via configuration.
**`safety-boundary.ts`** — Detect interfaces between safety and non-safety code. Any call from non-safety POU to safety POU (or vice versa) is a boundary that requires validation.
**`certification-tracker.ts`** — Track what needs re-certification after migration. Any modification to a SIL-rated POU triggers this.
**`voting-logic-detector.ts`** — Detect safety voting patterns (2oo3, 1oo2). These are specific redundancy architectures required by IEC 61508.

### Layer 5 Incremental Tests — Build Before Moving to Layer 6

Layer 5 is the largest and most critical layer. Tests are split by subsystem to catch failures early within the layer itself.

**Test file:** `tests/unit/analysis/entities.test.ts`

| Test | What It Catches | Pass Criteria |
|------|----------------|---------------|
| Entity extractor finds all POUs from parsed project | POUs silently dropped | Extract from sample → POU count matches adapter output |
| POU analyzer computes complexity (low/medium/high) | All POUs marked same complexity → useless metric | Simple POU → low, complex POU → high |
| POU analyzer flags entry points correctly | Entry points missed → orphan detection wrong | POU assigned to task → `isEntryPoint === true` |
| Variable analyzer collects all I/O addresses | I/O mappings incomplete | Project with %IX0.0, %QX1.0 → both found in results |
| Variable analyzer flags RETAIN/PERSISTENT | Power-cycle semantics lost | RETAIN var → `retain === true` in output |
| Variable analyzer detects unused variables | Dead variables migrated unnecessarily | Declared but never referenced var → flagged as unused |
| Type analyzer builds correct dependency order | Types migrated in wrong order → compile errors | STRUCT A uses STRUCT B → B appears before A in order |

**Test file:** `tests/unit/analysis/relationships.test.ts`

| Test | What It Catches | Pass Criteria |
|------|----------------|---------------|
| Call graph builder finds all FB instantiations | Missing calls → incomplete dependency graph | Main calls FB_Motor, FB_Valve → both edges in graph |
| Call graph builder records parameter bindings | Parameter mapping lost → migration produces wrong wiring | Call with `IN:=x, PT:=T#5s` → bindings recorded |
| Call graph detects recursive calls | Infinite recursion not flagged | FB_A calls FB_A → recursive flag set |
| Data flow analyzer tracks reads and writes | Variable access patterns unknown | FB_Motor reads GVL.Start, writes GVL.Running → both recorded |
| Data flow analyzer detects multi-writer scenarios | Race conditions not flagged | Two POUs write same global → `SharedStateWarning` generated |
| Data flow analyzer classifies access patterns | Wrong pattern classification | Single writer, multiple readers → `single_writer_multi_reader` |
| Dependency mapper detects orphan POUs | Dead code migrated | POU never called from any entry point → flagged as orphan |
| FB instance tracker counts instances per type | Instance count wrong → sizing estimates off | 3 instances of TON → `instanceCount === 3` |

**Test file:** `tests/unit/analysis/patterns.test.ts`

| Test | What It Catches | Pass Criteria |
|------|----------------|---------------|
| Motor control detector finds start/stop latching | Common pattern missed | Network with start/stop/interlock → detected with confidence ≥0.85 |
| PID detector finds PID loop | Process control pattern missed | Network with PID block (SP/PV/OUT) → detected with confidence ≥0.90 |
| State machine detector finds CASE-based states | State logic not recognized | ST with CASE on state variable → detected |
| Safety interlock detector finds E-stop chains | Safety-critical pattern missed | Network with E-stop → detected with confidence ≥0.95 |
| Pattern matcher returns empty array for patternless network | False positives | Simple assignment network → no patterns detected |
| Confidence scores are within [0, 1] range | Invalid confidence breaks downstream | All detected patterns → `0 <= confidence <= 1` |

**Test file:** `tests/unit/analysis/safety.test.ts`

| Test | What It Catches | Pass Criteria |
|------|----------------|---------------|
| SIL detector assigns rating from safety FB usage | SIL level missed → safety code modified without review | POU using F_TON → SIL rating assigned |
| SIL detector assigns rating from SAFEBOOL types | Type-based safety detection missed | POU with SAFEBOOL variable → flagged as safety |
| Safety boundary detector finds safety↔non-safety interfaces | Boundary crossing undetected | Safety POU called by non-safety POU → boundary recorded |
| Certification tracker flags modified safety POUs | Re-certification requirement missed | Safety POU → `requiresCertification === true` |
| Voting logic detector finds 2oo3 pattern | Safety architecture missed | 3 inputs, majority vote → `votingType === '2oo3'` |
| Safety FB catalog lookup works for all 3 vendor families | Vendor-specific safety FBs missed | Lookup F_TON (generic), ESTOP1 (Siemens), CROUT (Rockwell) → all found |

**Test file:** `tests/unit/analysis/external.test.ts`

| Test | What It Catches | Pass Criteria |
|------|----------------|---------------|
| HMI tag extractor infers from naming patterns | HMI dependencies invisible | Variables ending in `_Run`, `_Fault` → inferred as HMI refs |
| I/O mapping analyzer collects all addressed variables | Physical I/O mapping incomplete | All %I/%Q/%M variables → collected with direction |
| Library dependency tracker lists external libraries | Missing library deps → build failures | Project using vendor library → library name + used POUs recorded |

**Test file:** `tests/unit/analysis/implicit.test.ts`

| Test | What It Catches | Pass Criteria |
|------|----------------|---------------|
| Timing dependency detector flags hardcoded timer presets | Timing assumptions invisible | TON with PT:=T#100ms → timing dependency recorded |
| Global state tracker identifies cross-task shared variables | Race conditions invisible | Variable written in Task1, read in Task2 → `isCrossTask === true` |
| Convention detector finds naming patterns | Naming conventions lost → HMI breaks after rename | Variables `Motor1_Run`, `Motor2_Run`, `Motor3_Run` → pattern `*_Run` detected |

**Quality Gate QG-5:** All entity tests pass (7). All relationship tests pass (8). All pattern tests pass (6). All safety tests pass (6). All external tests pass (3). All implicit tests pass (3). Total: 33 tests. Multi-writer detection works. Orphan detection works. Safety boundaries detected. Only then proceed to Layer 6.

---

## Layer 6: Planning

**Purpose:** Compute migration strategy from analysis results. This layer answers: "In what order should we migrate, what are the risks, and what needs human review?"

**Why it's separate from analysis:** Analysis discovers facts. Planning makes decisions based on those facts. Keeping them separate means you can re-run planning with different strategies without re-analyzing.

### Modules

**`migration-order-computer.ts`** — Compute optimal migration order using topological sort on the dependency graph. Group into batches by dependency level. Within each level, prioritize by: safety criticality, usage frequency, complexity.

**`batch-planner.ts`** — Compute migration batches from dependency order.
- Input: EntityCatalog, RelationshipGraph (specifically the migration order from dependency-mapper)
- Output: MigrationBatch array
- Algorithm: topological sort on dependency graph → group by level → within each level, sub-group by parallelizability → estimate token cost per batch
- Level 0 (no dependencies): data types, utility functions — migrate first
- Level 1: POUs that depend only on Level 0
- Level N: POUs that depend on Level N-1
- Safety POUs go last (require separate certification workflow)

**`risk-assessor.ts`** — Score migration risks.
- Input: EntityCatalog, RelationshipGraph, ContextExtractionResult
- Output: RiskAssessment with overall score and per-category breakdown
- Risk categories: safety (SIL-rated code), timing (scan rate assumptions), external (HMI/OPC dependencies), complexity (deep call chains, many patterns), coverage (orphan code, missing docs)
- Each risk gets likelihood (0-1) and impact (0-1) scores
- Overall score = weighted sum of category scores

**`review-identifier.ts`** — Identify what needs human review and why.
- Safety POUs → required safety review with dual sign-off
- POUs with HMI dependencies → required external review (coordinate with HMI team)
- POUs with timing assumptions → recommended timing review
- POUs with detected patterns → recommended pattern verification
- Generates checklist items per entity

**`blocker-detector.ts`** — Identify things that block migration entirely.
- Binary files that need vendor IDE export → blocking
- Missing library dependencies → blocking
- Unresolvable vendor extensions → warning
- Cross-PLC communication dependencies → warning

### Layer 6 Incremental Tests — Build Before Moving to Layer 7

These tests validate that planning logic produces correct, safe migration strategies.

**Test file:** `tests/unit/planning/planning.test.ts`

| Test | What It Catches | Pass Criteria |
|------|----------------|---------------|
| Migration order has no dependency violations | Migrating POU before its dependencies → compile errors | For every entity in batch N, all dependencies are in batch <N |
| Batch planner puts types before POUs that use them | Type not available when POU is migrated | Data types appear in batch 0 or 1, POUs using them in later batches |
| Batch planner puts safety POUs in final batches | Safety code modified before non-safety is stable | Safety POUs → highest batch numbers |
| Batch planner estimates token cost per batch | Token estimates wildly wrong → chunks don't fit context | Each batch has `estimatedTokens > 0` and `< maxTokensPerChunk * entityCount` |
| Risk assessor produces score in [0, 100] range | Invalid risk score breaks UI | `overallScore >= 0 && overallScore <= 100` |
| Risk assessor scores safety projects higher than non-safety | Safety risk not weighted properly | Project with SIL-rated POUs → higher risk than project without |
| Risk assessor breaks down by category | No category detail → can't identify risk source | `categories` has entries for safety, timing, external, complexity, coverage |
| Review identifier flags safety POUs as required review | Safety code migrated without human review | Safety POU → `reviewType === 'safety'`, `priority === 'required'` |
| Review identifier flags HMI-dependent POUs | External dependency migration breaks HMI | POU with HMI refs → `reviewType === 'external'` |
| Review identifier generates checklist items | Empty checklists → reviewer doesn't know what to check | Safety review → `checklistItems.length > 0` |
| Blocker detector flags binary files needing export | Binary files silently skipped → incomplete migration | Binary .acd in inventory → blocker with `severity === 'blocking'` |
| Blocker detector flags missing library dependencies | Missing libs → build failures | Unresolved library ref → blocker generated |

**Quality Gate QG-6:** All 12 tests pass. Migration order is dependency-safe. Safety POUs require review. Risk scores are reasonable. Only then proceed to Layer 7.

---

## Layer 7: Layout

**Purpose:** Compute visual positions for graph nodes using layout algorithms.

### Modules

**`layout-engine.ts`** — Orchestrate layout computation. Select strategy based on options and input type.

**`strategies/elk-layout.ts`** — ELK layered layout (recommended for FBD).
- Convert graph model to ELK JSON format
- Configure: left-to-right direction, port constraints, edge routing (orthogonal), node spacing
- ELK handles: layer assignment, crossing minimization, node placement, edge routing
- Why ELK: it's the only layout algorithm that properly handles ports (input/output pins on blocks), which is essential for FBD

**`strategies/original-layout.ts`** — Preserve original positions from XML.
- Use x, y coordinates from parsed elements
- Normalize to canvas coordinates
- Handle missing positions (fall back to auto-layout)

**`strategies/hybrid-layout.ts`** — Use original positions where available, auto-layout for the rest.

**`strategies/sfc-layout.ts`** — SFC-specific layout.
- Vertical flow (top to bottom): steps → transitions → steps
- Parallel branches side by side
- Selection branches with priority ordering

### Layer 7 Incremental Tests — Build Before Moving to Layer 8

**Test file:** `tests/unit/layout/layout.test.ts`

| Test | What It Catches | Pass Criteria |
|------|----------------|---------------|
| ELK layout produces valid positions for all nodes | Nodes at (0,0) or overlapping | Every node has `x > 0, y > 0`, no two nodes share same position |
| ELK layout respects left-to-right flow direction | Blocks laid out randomly | For every edge, source node x < target node x (with tolerance for feedback) |
| ELK layout assigns port positions | Ports missing → edges connect to node center | Every port has computed position |
| Original layout preserves XML coordinates | Original positions overwritten | Nodes with XML positions → layout positions match original |
| Original layout handles missing positions gracefully | Null position crashes layout | Node without XML position → falls back to auto-layout, no crash |
| Hybrid layout uses original where available, auto for rest | All-or-nothing layout | Mix of positioned and unpositioned nodes → positioned ones keep coords, others get auto |
| SFC layout produces vertical flow | SFC laid out horizontally → confusing | Steps flow top-to-bottom: step1.y < transition1.y < step2.y |
| SFC layout places parallel branches side by side | Parallel branches overlap | Simultaneous branches → different x positions, same y level |
| Layout engine selects correct strategy from config | Wrong strategy used | Config `algorithm: 'original'` → original-layout used, not ELK |

**Quality Gate QG-7:** All 9 tests pass. ELK produces valid non-overlapping positions. Original positions preserved. SFC flows vertically. Only then proceed to Layer 8.

---

## Layer 8: Output

**Purpose:** Produce all output artifacts: Migration Map, reports, AI chunks, cross-references, and organized file output.

### Migration Map Assembly (`output/migration-map/`)

**`migration-map-builder.ts`** — Assemble the complete MigrationMap from all pipeline outputs.
- Input: DiscoveryResult, ProjectStructure, EntityCatalog, RelationshipGraph, ContextExtractionResult, MigrationPlan, RiskAssessment
- Output: MigrationMap (the top-level output type)
- Adds: metadata (timestamps, scanner version, statistics), navigation index, validation results

**`json-serializer.ts`** — Serialize MigrationMap to JSON with optional pretty-printing.

**`validation-runner.ts`** — Validate the MigrationMap for completeness and consistency.
- Check: all POUs in entity catalog are referenced in call graph
- Check: all types used by POUs exist in type catalog
- Check: no dangling references in edges
- Check: migration order has no dependency violations
- Output: ValidationResult with completeness score

**`navigation-builder.ts`** — Build navigation index for the MigrationMap.
- byName: entity name → location in map
- byType: entity type → list of names
- byLanguage: language → list of POU names
- hierarchy: tree structure (config → resource → task → POU)
- searchIndex: terms → entities (for full-text search)

### Reports (`output/reports/`)

**`report-generator.ts`** — Orchestrate report generation. Supports markdown, JSON, HTML output.

**`templates/executive-summary.ts`** — Project stats, complexity score, safety flags, migration risk.
**`templates/architecture-overview.ts`** — Entry points, call hierarchy, data flow diagram.
**`templates/entity-catalog.ts`** — Each POU with interface, purpose, patterns detected.
**`templates/dependency-map.ts`** — What depends on what, impact analysis.
**`templates/external-dependencies.ts`** — HMI tags, I/O mappings, library deps, OPC UA.
**`templates/safety-analysis.ts`** — SIL-rated code, safety boundaries, certification requirements.
**`templates/migration-recommendations.ts`** — Suggested order, risk areas, pattern migration guidance.

### AI Context (`output/chunks/`)

**`context-chunker.ts`** — Chunk the extracted project into token-limited pieces for LLM consumption.
- 4-level hierarchy: Level 1 (project overview, ~1000 tokens), Level 2 (module catalog, ~200 tokens per POU), Level 3 (entity details, ~1500 tokens per POU), Level 4 (code context with annotated sections)
- Max tokens per chunk: configurable, default 8000
- Each chunk is self-contained with enough context to be useful alone

**`token-estimator.ts`** — Estimate token count for content. Use character-based heuristic (1 token ≈ 4 characters for English/code).

**`cross-reference-builder.ts`** — Build cross-references between chunks.
- Types: contains, calls, uses_type, reads, writes, instantiates, safety_boundary, hmi_reference, io_mapping
- Enables AI to navigate between related chunks

**`navigation-index.ts`** — Build navigation helpers for AI.
- Entry point chunk, POU-to-chunk map, type-to-chunk map, pattern-to-chunk map, safety-level-to-chunk map

### Prompt Templates (`output/prompts/`)

**`prompt-generator.ts`** — Generate AI prompts from chunks and templates.
**`templates/migration.template.ts`** — Migration prompt: source platform, target platform, entity details, migration requirements.
**`templates/review.template.ts`** — Review prompt: original code, migrated code, analysis context, review checklist.
**`templates/analysis.template.ts`** — Analysis prompt: entity details, patterns, relationships.
**`templates/documentation.template.ts`** — Documentation generation prompt.

### File Organization (`output/files/`)

**`file-organizer.ts`** — Write output to organized directory structure.

```
analysis-output/
├── migration-map.json          # Complete MigrationMap
├── migration-map.schema.json   # JSON Schema for the MigrationMap format
├── overview.md                 # Human-readable executive summary
├── catalog.json                # Level 2: Module catalog
├── entities/                   # Level 3: Entity details (one JSON per POU)
├── code/                       # Level 4: Code context (one JSON per POU)
├── dependencies/
│   ├── call-graph.json
│   ├── data-flow.json
│   └── external.json
├── safety/
│   ├── analysis.json
│   └── boundaries.json
├── migration/
│   ├── plan.json
│   ├── plan.md
│   ├── risks.json
│   └── chunks/                 # Pre-chunked for AI consumption
├── hmi/
│   └── tag-mapping.json
├── quality/
│   ├── assessment.json         # QualityAssessment with trust tier
│   ├── information-loss.json   # What was dropped, approximated, unsupported
│   └── provenance.json         # Per-entity source tracing
├── audit-log.jsonl             # Append-only decision audit trail
└── validation.json
```

### Diff Engine (`output/diff/`)

**`scan-differ.ts`** — Compare two MigrationMaps and produce a ScanDiff.
- Entity-level comparison: added, removed, modified POUs/types/variables
- Transitive impact analysis: which unchanged entities are affected by changes
- Safety impact flagging: any change touching safety code gets explicit review/recertification flags
- Risk delta computation: how did the overall risk score change between scans

**`diff-reporter.ts`** — Generate human-readable diff reports (markdown, JSON).

### Quality Assessment (`output/quality/`)

**`quality-assessor.ts`** — Compute QualityAssessment from pipeline results.
- Per-phase completeness from error counts and entity counts
- Per-language completeness from parsed vs failed POU counts
- Per-vendor completeness from file counts
- Safety completeness from analyzed vs total safety POUs
- Trust tier computation from thresholds
- Recommendation generation based on gaps found

**`loss-tracker.ts`** — Aggregate information loss across all pipeline phases.
- Collect dropped XML elements from adapters/parsers
- Collect approximations from type mapping and expression simplification
- Collect unsupported features from vendor extension handling
- Compute coverage stats from total vs parsed element counts

### Layer 8 Incremental Tests — Final Layer Before Integration

These tests validate that all output artifacts are correct, complete, and internally consistent.

**Test file:** `tests/unit/output/migration-map.test.ts`

| Test | What It Catches | Pass Criteria |
|------|----------------|---------------|
| MigrationMap builder assembles all sections | Missing sections → incomplete output | Built map has non-null: metadata, discovery, structure, entities, relationships, context, migrationPlan, riskAssessment, navigation, validation |
| MigrationMap JSON serializes and deserializes without loss | Serialization drops fields | `JSON.parse(JSON.stringify(map))` deep-equals original |
| Validation runner catches missing POU in call graph | Dangling reference in output | Remove a POU from entity catalog but leave call graph ref → validation error |
| Validation runner computes completeness score | Completeness always 100% (lying) | Incomplete project → completeness < 100 |
| Navigation builder creates byName index | Entity lookup broken | Every POU name → maps to location in MigrationMap |
| Navigation builder creates hierarchy tree | Tree navigation broken | Config → Resource → Task → POU chain navigable |

**Test file:** `tests/unit/output/chunks.test.ts`

| Test | What It Catches | Pass Criteria |
|------|----------------|---------------|
| Context chunker respects max token limit | Chunks exceed context window → LLM truncation | Every chunk → `tokenEstimate <= maxTokensPerChunk` |
| Context chunker produces all 4 levels | Missing hierarchy level → AI can't zoom | Chunks include level 1 (project), 2 (module), 3 (entity), 4 (code) |
| Token estimator is within 20% of actual | Wildly wrong estimates → chunks too big or too small | Estimate vs actual (measured by tiktoken or char heuristic) → within 20% |
| Cross-reference builder links callers to callees | AI can't navigate between related chunks | POU A calls POU B → cross-ref exists from A's chunk to B's chunk |
| Cross-reference builder links safety boundaries | Safety context missing for AI | Safety boundary → cross-ref with type `safety_boundary` |

**Test file:** `tests/unit/output/reports.test.ts`

| Test | What It Catches | Pass Criteria |
|------|----------------|---------------|
| Executive summary includes project stats | Empty report | Summary contains POU count, type count, safety flag count |
| Entity catalog lists every POU | POUs missing from report | Report POU count matches EntityCatalog POU count |
| Safety analysis report lists all SIL-rated POUs | Safety POUs missing from report | Every safety POU in analysis → appears in report |

**Test file:** `tests/unit/output/quality.test.ts`

| Test | What It Catches | Pass Criteria |
|------|----------------|---------------|
| Quality assessor computes trust tier correctly | Wrong trust level → false confidence | 100% completeness + high confidence → HIGH tier. <50% → LOW tier |
| Quality assessor reports per-language completeness | Language-specific gaps invisible | 5 ST POUs parsed, 1 FBD failed → ST: 100%, FBD: 0% |
| Loss tracker records dropped XML elements | Information loss invisible | Unparseable element → appears in `droppedElements` with XPath and reason |
| Loss tracker computes coverage percentage | Coverage always 100% (lying) | 100 elements, 3 dropped → `coveragePercent === 97` |

**Test file:** `tests/unit/output/diff.test.ts`

| Test | What It Catches | Pass Criteria |
|------|----------------|---------------|
| Scan differ detects added POUs | New code invisible in diff | Add POU to second scan → appears in `diff.added.pous` |
| Scan differ detects removed POUs | Deleted code invisible in diff | Remove POU from second scan → appears in `diff.removed.pous` |
| Scan differ detects modified POUs | Changes invisible in diff | Modify POU body → appears in `diff.modified` with change details |
| Scan differ computes transitive impact | Downstream impact invisible | Modified POU has callers → callers appear in `diff.impacted` |
| Scan differ flags safety impact | Safety changes not escalated | Modified safety POU → `safetyImpact` entry with `requiresReview === true` |

**Quality Gate QG-8:** All 24 tests pass. MigrationMap is complete and valid. Chunks fit token limits. Reports include all entities. Quality assessment is honest. Diff detects all change types. Only then proceed to integration testing.

---

## Orchestration: The Scanning Pipeline

**Purpose:** The top-level orchestrator that runs the 5-phase scanning pipeline, then feeds results into detailed parsing and output generation.

This is the public API surface. Everything above is internal.

### Pipeline Phases

```
Phase 1: DISCOVERY (Layer 1)
    Input: directory path
    Output: FileInventory
    What it does: find files, detect formats, fingerprint vendor, identify export needs

Phase 2: STRUCTURE (Layer 2 adapters, partial)
    Input: FileInventory
    Output: ProjectStructure (configurations, resources, tasks, entry points)
    What it does: parse project hierarchy WITHOUT parsing POU bodies

Phase 3: ENTITIES (Layer 2 adapters + Layer 5 entity extraction)
    Input: ProjectStructure
    Output: EntityCatalog (POUs, types, variables, I/O, libraries — shells only, no body parsing)
    What it does: catalog everything that exists, breadth-first

Phase 4: DEEP PARSE + RELATIONSHIPS (Layer 3 parsers + Layer 5 relationship analysis)
    Input: EntityCatalog
    Output: RelationshipGraph + parsed bodies (FBDBody, LDBody, SFCBody, etc.)
    What it does: parse POU bodies, build call graph, analyze data flow, detect orphans

Phase 5: CONTEXT + PLANNING (Layer 5 external/implicit + Layer 6 planning)
    Input: EntityCatalog, RelationshipGraph
    Output: ContextExtractionResult, MigrationPlan, RiskAssessment
    What it does: extract HMI refs, safety analysis, timing deps, naming conventions, compute migration order, compute batches, assess risks
```

After all 5 phases: Layer 8 assembles the MigrationMap, generates reports, chunks for AI, and writes output files.

### Public API

```
PLCIndexer class:
  constructor(config?)

  // Full pipeline
  scan(path: string, options?): Promise<MigrationMap>

  // Quick scan (phases 1-3 only — inventory without relationships/context)
  quickScan(path: string, options?): Promise<EntityCatalog>

  // Targeted scan (specific POUs and their dependency closure)
  targetedScan(path: string, pouNames: string[], options?): Promise<MigrationMap>

  // Incremental (re-scan only changed files, update existing map)
  rescan(existingMap: MigrationMap, changedFiles: string[]): Promise<MigrationMap>

  // Individual phases (for testing/debugging)
  runDiscovery(path): Promise<FileInventory>
  runStructure(inventory): Promise<ProjectStructure>
  runEntities(structure): Promise<EntityCatalog>
  runRelationships(entities): Promise<RelationshipGraph>
  runContext(entities, relationships): Promise<ContextExtractionResult>

  // Analysis (can be called independently)
  detectPatterns(network): PatternMatch[]
  analyzeSafety(project): SafetyAnalysisResult
  extractExternalDeps(project): ExternalDependencies

  // Output generation
  generateReport(map, format: 'md' | 'json' | 'html'): string
  generateChunks(map, options?): ContextChunk[]
  generatePrompt(chunk, template): string
  buildCrossReferences(chunks): CrossReference[]
  writeOutput(map, outputDir): Promise<void>

  // Layout (for visualization)
  layoutNetwork(network, options?): Promise<LayoutResult>
  layoutSFC(sfc, options?): Promise<LayoutResult>

  // Validation
  validate(map): ValidationResult

  // Comparison
  diff(previous: MigrationMap, current: MigrationMap): ScanDiff
```

### Incremental Rescan

The system must support incremental rescans for efficiency:
- Phase 1 (Discovery): compare file hashes against previous scan → identify changed files
- Phase 2-3: re-parse only changed files, merge with cached entities
- Phase 4: rebuild relationships for affected POUs (callers/callees of changed POUs)
- Phase 5: re-run context extraction for affected areas

This requires: content hashing in discovery, entity-level timestamps, a cache layer for parsed results.

### Configuration

```
PLCIndexerConfig:
  ingestion:
    maxFileSize: number (default 50MB)
    supportedExtensions: string[]
    includePatterns: string[]
    excludePatterns: string[]

  parsing:
    strictMode: boolean (default false — lenient on malformed XML)
    preserveComments: boolean (default true)
    handleENENO: boolean (default true)
    resolveFeedbackLoops: boolean (default true)
    preserveVendorExtensions: boolean (default true)

  analysis:
    enablePatternDetection: boolean (default true)
    enableSafetyAnalysis: boolean (default true)
    enableExternalDeps: boolean (default true)
    enableImplicitDeps: boolean (default true)
    enableConventionDetection: boolean (default true)
    patternConfidenceThreshold: number (default 0.7)
    safetyFBCatalog: SafetyFBEntry[] (default built-in catalog)

  layout:
    algorithm: 'elk' | 'original' | 'hybrid' (default 'elk')
    sfcLayout: 'vertical' | 'horizontal' (default 'vertical')

  output:
    maxTokensPerChunk: number (default 8000)
    includeEquivalentST: boolean (default true)
    includeCrossReferences: boolean (default true)
    includeNavigationIndex: boolean (default true)
    prettyPrintJSON: boolean (default false)

  performance:
    parallelism: number (default 4)
    timeout: number (default 300000ms)
    cacheEnabled: boolean (default true)
    cachePath: string (default .plc-indexer-cache/)
```

---

## Observability: Logging and Progress Reporting

**Purpose:** A pipeline that runs for up to 2 minutes across 5 phases must report progress and produce structured logs. Without this, debugging failures in production is guesswork.

**Why it's in `shared/` not a layer:** Logging and progress are cross-cutting concerns used by every layer. They live in `shared/` and are injected via configuration, not imported as a layer dependency.

### Modules

**`shared/logger.ts`** — Structured logger with severity levels.
- Levels: debug, info, warn, error
- Output: structured JSON lines (timestamp, level, layer, module, message, context)
- Configurable: log level, output stream (stdout, file, callback)
- Each layer tags its logs with layer name and module name
- No external dependency — uses a simple interface that can be backed by console, file, or any logging library

**`shared/progress.ts`** — Pipeline progress reporter.
- Emits progress events: `{ phase: string, step: string, current: number, total: number, elapsed: number }`
- Supports: callback-based (for CLI progress bars), event-emitter (for UI integration), silent (for library use)
- Each pipeline phase reports: start, per-file progress, completion
- Example: "Phase 4: Parsing POU bodies — 42/87 complete (12.3s elapsed)"

### Configuration

```
PLCIndexerConfig:
  // ... existing sections ...

  observability:
    logLevel: 'debug' | 'info' | 'warn' | 'error' (default 'info')
    logOutput: 'stdout' | 'file' | 'callback' (default 'stdout')
    logFilePath: string (default 'plc-indexer.log')
    onProgress: (event: ProgressEvent) => void (optional callback)
    onLog: (entry: LogEntry) => void (optional callback)
```

---

## Error Recovery Strategy

**Purpose:** Define what happens when individual files or POUs fail to parse. A single malformed POU should not abort the entire pipeline.

**Why this matters:** Real-world PLC exports are messy. Vendor tools produce inconsistent XML. A single corrupt element in a 100-POU project should not prevent analysis of the other 99.

### Strategy: Partial Results with Error Collection

The pipeline uses a `Result<T, E>` pattern (defined in `shared/result.ts`):

```
Result<T, E> = { ok: true, value: T } | { ok: false, error: E, partialValue?: T }
```

### Per-Phase Recovery Rules

**Phase 1 (Discovery):** If a file cannot be read (permissions, encoding), log a warning and skip it. Include it in `FileInventory.skippedFiles` with reason.

**Phase 2 (Structure):** If project hierarchy parsing fails, abort — structure is required for all subsequent phases. This is the only phase where failure is fatal.

**Phase 3 (Entities):** If a single POU shell fails to parse (malformed interface XML), skip it and continue. Include it in `EntityCatalog.failedEntities` with the ParseError. Other POUs proceed normally.

**Phase 4 (Deep Parse):** If a POU body fails to parse (e.g., malformed FBD network), mark the POU as `parseStatus: 'failed'` with the error. Relationship analysis proceeds with available data — the failed POU appears in the call graph as a node with `bodyParsed: false`.

**Phase 5 (Context):** If a context extractor fails (e.g., HMI tag extraction crashes), log the error and continue with other extractors. The MigrationMap will have `null` for that context section with a warning.

### Error Aggregation

The final `MigrationMap` includes:
- `errors: ParseError[]` — all errors encountered during the pipeline
- `warnings: string[]` — all warnings (skipped files, partial results, fallback decisions)
- `completeness: number` — percentage of entities successfully parsed (0-100)
- `failedEntities: { name: string, phase: string, error: string }[]` — what failed and where

This lets consumers decide: is 95% completeness good enough, or do they need to fix the source files and re-run?

---

## Determinism and Reproducibility

**Purpose:** The same input must always produce the same output. If a company runs this tool on Monday and again on Friday against the same export files, the MigrationMap must be byte-identical. Without this, no one can trust the output for regulatory submissions.

**Why this matters for enterprise:** Safety certification bodies (TÜV, UL) require reproducible analysis. If the tool produces different results on different runs, the analysis cannot be cited in a safety case.

### Requirements

- All output must be deterministic: same input files → same MigrationMap JSON (byte-identical)
- No randomness anywhere: no random IDs, no timestamp-dependent ordering, no hash-map iteration order leaking into output
- Entity IDs derived from content (content-addressable): `sha256(filePath + pouName + pouType)` — not auto-increment or UUID
- Edge IDs derived from endpoints: `sha256(sourceNodeId + sourcePort + targetNodeId + targetPort)`
- Pattern match IDs derived from location: `sha256(pouName + patternId + lineRange)`
- Array ordering must be deterministic: alphabetical by name within each category, or by explicit sort key
- Timestamps in metadata section only (not in entity data), and only `scanStartTime` / `scanEndTime`
- JSON serialization uses sorted keys (`JSON.stringify` with key sorting)

### Verification

The test suite must include a determinism test: run the full pipeline twice on the same input, assert byte-equality of output JSON (excluding the metadata.timestamps section).

---

## Output Schema Versioning and Backward Compatibility

**Purpose:** The MigrationMap JSON schema will evolve. Enterprise customers build tooling on top of it — dashboards, review workflows, CI pipelines. Breaking the schema breaks their workflows.

### Requirements

- MigrationMap includes `schemaVersion: string` (semver) in its metadata
- Schema follows semver: MAJOR (breaking changes), MINOR (additive), PATCH (fixes)
- Additive changes only for MINOR versions: new optional fields, new enum values appended
- Breaking changes require MAJOR version bump with migration guide
- Schema published as JSON Schema (`.schema.json`) alongside the package
- Validation function: `validateSchema(map: unknown): { valid: boolean, errors: string[], schemaVersion: string }`
- Output includes `toolVersion: string` (package version) and `schemaVersion: string` (output format version)

### Schema Registry

```
core/schemas/
├── migration-map.schema.json         # Current schema (JSON Schema draft-07)
├── migration-map.v1.schema.json      # Archived v1 schema
└── schema-changelog.md               # What changed between versions
```

---

## Provenance and Audit Trail

**Purpose:** For every fact in the MigrationMap, a reviewer must be able to trace it back to the source. "Where did this come from?" must always be answerable. This is non-negotiable for safety-critical systems where regulatory auditors will ask.

### Requirements

Every entity in the MigrationMap carries provenance metadata:

```
Provenance:
  sourceFile: string              # Which file this was parsed from
  sourceLocation: {               # Where in the file
    startLine: number
    endLine: number
    xpath: string                 # XML path for XML-sourced entities
  }
  parserVersion: string           # Which parser version produced this
  adapterUsed: string             # Which vendor adapter was used
  confidence: number              # 0-1, how confident the parser is in this extraction
  inferredFields: string[]        # Which fields were inferred vs directly parsed
  warnings: string[]              # Any warnings generated during extraction of this entity
```

### Confidence Scoring Per Entity

Not just patterns — every parsed entity gets a confidence score:

| Confidence | Meaning | Example |
|------------|---------|---------|
| 1.0 | Directly parsed from explicit XML element | POU name from `<pou name="X">` |
| 0.9 | Parsed with minor inference | Return type from `<returnType>` element |
| 0.7 | Inferred from context | HMI tag from naming convention |
| 0.5 | Best guess | SIL level from safety FB usage alone |
| 0.3 | Low confidence inference | Timing dependency from timer preset value |

### Audit Log

The pipeline produces an audit log (separate from the MigrationMap) that records every decision:

```
shared/audit.ts — Audit log writer
  - Records: timestamp, phase, module, action, entity, decision, rationale
  - Example: "Phase 4, fbd-parser, parsed block, FB_Motor, executionOrder=3, reason: explicit executionOrderId attribute"
  - Example: "Phase 5, sil-detector, assigned SIL2, PRG_Safety, confidence=0.85, reason: uses SF_EmergencyStop + SAFEBOOL types"
  - Output: audit-log.jsonl (one JSON object per line, append-only)
```

Add to `shared/` directory:
```
shared/
├── logger.ts
├── progress.ts
├── result.ts
└── audit.ts                          # Provenance and decision audit trail
```

---

## Information Loss Tracking

**Purpose:** Parsing is inherently lossy. The tool must explicitly track what it could NOT parse, what it dropped, and what it approximated. An enterprise customer needs to know: "What did you miss?"

### Requirements

The MigrationMap includes an `informationLoss` section:

```
InformationLoss:
  droppedElements: {                  # XML elements that were not parsed
    element: string                   # XPath or element name
    file: string
    reason: string                    # "unsupported vendor extension" | "unknown element" | "malformed XML"
    rawContent: string                # Preserved raw XML (truncated to 1KB)
  }[]
  approximations: {                   # Things that were simplified
    entity: string
    field: string
    original: string                  # What was in the source
    approximation: string             # What we stored
    reason: string                    # "type not mappable" | "expression too complex" | "vendor-specific syntax"
  }[]
  unsupportedFeatures: {              # Features the tool doesn't handle yet
    feature: string                   # "OPC UA server configuration" | "motion control axes"
    files: string[]
    impact: string                    # "low" | "medium" | "high"
    workaround: string               # What the user can do
  }[]
  coverageStats: {
    totalXMLElements: number
    parsedElements: number
    skippedElements: number
    coveragePercent: number           # parsedElements / totalXMLElements * 100
  }
```

### Why This Builds Trust

When a tool says "100% complete" with no caveats, engineers don't trust it. When a tool says "97.3% coverage — here are the 14 elements I couldn't parse, here's why, and here's what you should check manually," that's enterprise-grade honesty.

---

## Input Security: Defensive XML Parsing

**Purpose:** The tool processes untrusted XML files from customer environments. These files could be malformed, malicious, or weaponized. The tool must not be a vector for attacks.

### Threat Model

| Threat | Attack Vector | Mitigation |
|--------|--------------|------------|
| XML External Entity (XXE) | `<!DOCTYPE>` with external entity references | Disable external entities in parser config |
| XML Bomb (Billion Laughs) | Exponential entity expansion | Limit entity expansion depth, max parsed size |
| Path Traversal | File paths in XML referencing `../../etc/passwd` | Sanitize all file paths, restrict to project directory |
| Denial of Service | Extremely large files, deeply nested XML | Max file size (50MB), max nesting depth (100), parse timeout |
| Code Injection | Malicious content in ST code bodies | ST bodies stored as strings, never evaluated/executed |

### Implementation Requirements

```
fast-xml-parser configuration:
  - allowBooleanAttributes: true
  - ignoreDeclaration: true
  - processEntities: false            # CRITICAL: prevents XXE
  - htmlEntities: false
  - maxEntityExpansionDepth: 0        # CRITICAL: prevents XML bombs
  - stopNodes: [] (none — parse everything)

file-loader.ts:
  - Resolve all paths to absolute, verify within project root
  - Reject symlinks pointing outside project directory
  - Enforce max file size before reading into memory
  - Enforce max total project size (configurable, default 500MB)
```

---

## Scan-to-Scan Comparison (Diff)

**Purpose:** When a customer re-exports their PLC project after making changes, they need to know: "What changed since the last scan?" This is critical for incremental migration workflows and change tracking.

### Requirements

Add to public API:
```
PLCIndexer class:
  // Compare two MigrationMaps
  diff(previous: MigrationMap, current: MigrationMap): ScanDiff
```

```
ScanDiff:
  added: {                            # New entities
    pous: string[]
    types: string[]
    variables: string[]
  }
  removed: {                          # Deleted entities
    pous: string[]
    types: string[]
    variables: string[]
  }
  modified: {                         # Changed entities
    entity: string
    changes: {
      field: string
      previous: string
      current: string
    }[]
  }[]
  impacted: {                         # Entities affected by changes (transitive)
    entity: string
    reason: string                    # "calls modified POU X" | "uses modified type Y"
  }[]
  safetyImpact: {                     # Changes affecting safety code
    entity: string
    change: string
    requiresReview: boolean
    requiresRecertification: boolean
  }[]
  summary: {
    totalChanges: number
    safetyChanges: number
    riskDelta: number                 # Change in overall risk score
  }
```

### Why This Matters

Without diff, every re-scan is a full re-review. With diff, reviewers focus only on what changed. For a 500-POU project where 3 POUs changed, this is the difference between a 2-week review and a 2-hour review.

---

## Internationalization: Non-ASCII Content Handling

**Purpose:** PLC projects worldwide use local-language comments, variable names, and documentation. German factories use German comments. Chinese factories use Chinese identifiers. The tool must handle all of this without corruption.

### Requirements

- All string processing must be Unicode-aware (TypeScript handles this natively, but regex patterns must use Unicode-aware flags)
- Comments preserved byte-for-byte regardless of language
- Variable names preserved exactly (IEC 61131-3 allows Unicode identifiers in Edition 3+)
- File encoding detection order: BOM → XML declaration encoding attribute → UTF-8 fallback
- Supported encodings: UTF-8, UTF-16 LE/BE, ISO-8859-1 (Western European — common in German PLC projects), Windows-1252
- Output always UTF-8
- Search/navigation index must handle Unicode normalization (NFC) for consistent lookups
- Token estimation must account for non-ASCII: CJK characters ≈ 2-3 tokens per character, not 0.25

---

## Completeness Self-Assessment

**Purpose:** The MigrationMap must include a machine-readable self-assessment of its own completeness. This lets downstream tools and reviewers make informed decisions about trust level.

### Requirements

Add to MigrationMap metadata:

```
QualityAssessment:
  overallCompleteness: number         # 0-100, percentage of source content successfully parsed
  overallConfidence: number           # 0-1, weighted average confidence across all entities
  
  perPhase: {
    phase: string
    completeness: number
    duration: number                  # milliseconds
    errors: number
    warnings: number
  }[]
  
  perLanguage: {
    language: string                  # ST | FBD | LD | SFC | IL
    pouCount: number
    parsedCount: number
    failedCount: number
    completeness: number
  }[]
  
  perVendor: {
    vendor: string
    fileCount: number
    parsedCount: number
    completeness: number
    knownLimitations: string[]        # "Siemens multi-instance DBs partially supported"
  }[]
  
  safetyCompleteness: {
    totalSafetyPOUs: number
    analyzedSafetyPOUs: number
    silAssignments: number
    boundariesDetected: number
    completeness: number
    missingAnalysis: string[]         # What safety analysis couldn't be performed and why
  }
  
  recommendations: string[]          # "3 POUs failed to parse — re-export from TIA Portal with latest version"
```

### Trust Tiers

| Completeness | Confidence | Trust Tier | Recommendation |
|-------------|------------|------------|----------------|
| >95% | >0.9 | HIGH | Safe for automated workflows |
| 80-95% | >0.7 | MEDIUM | Review failed entities before proceeding |
| <80% | any | LOW | Manual review required, likely export issues |
| any | <0.5 | LOW | Source files may be corrupt or unsupported format |

---

## Implementation Phases

### Phase 1: Foundation (Weeks 1-2)

Build order matters. Each step depends on the previous.

**Step 1 (Days 1-2): Package scaffold + Layer 0 core types + shared utilities**
- Initialize package: tsconfig (strict), vitest, eslint, tsup
- Implement ALL type files in `core/types/` — every type defined in this spec (18 files including provenance, quality, diff, information-loss, pipeline)
- Implement ALL interfaces in `core/interfaces/`
- Implement ALL error classes in `core/errors/`
- Implement ALL constants in `core/constants/`
- Implement `shared/logger.ts`, `shared/progress.ts`, `shared/result.ts`, `shared/audit.ts`
- Configure fast-xml-parser with security hardening (processEntities: false, maxEntityExpansionDepth: 0)
- Test: types compile, constants are correct, logger outputs structured JSON, Result type works, audit log appends entries

Why first: every other module imports from core. Type errors here cascade everywhere.

**Step 2 (Days 3-4): Layer 1 ingestion**
- Implement format-sniffer, file-loader, schema-validator, project-scanner
- Test against sample files: `07-examples/samples/plcopen-sample.xml`, traffic-light.st, conveyor-sequence.st
- Verify: PLCopen XML detected with >0.9 confidence, ST files detected, binary files rejected

**Step 3 (Days 5-6): Layer 2 PLCopen adapter (structure only)**
- Implement plcopen-adapter, plcopen-project, plcopen-pou (shells only — no body parsing), plcopen-types, plcopen-config
- Implement adapter-registry, base-adapter
- Test: parse plcopen-sample.xml → get project metadata, all POU names/types/interfaces, all data types, configuration hierarchy
- This is the "breadth before depth" cut point

**Step 4 (Days 7-8): Layer 3 FBD parser**
- Implement fbd-parser, fbd-block, fbd-connection, fbd-execution-order
- Implement plcopen-body (routes to FBD parser)
- Test: parse FBD networks from sample XML → get correct nodes, edges, execution order
- This is the hardest part of P1 — connection resolution (back-references) is where most bugs live

**Step 5 (Days 9-10): Layer 5 entity extraction + basic relationships**
- Implement entity-extractor, pou-analyzer, variable-analyzer, type-analyzer
- Implement call-graph-builder, fb-instance-tracker, dependency-mapper (orphan detection)
- Implement data-flow-analyzer (basic: track reads/writes, detect multi-writer)
- Test: full pipeline from XML → EntityCatalog + RelationshipGraph with correct call graph

**Step 6 (Day 10): Public API facade + integration test**
- Implement `index.ts` with PLCIndexer class (scan method only, no incremental yet)
- Integration test: plcopen-sample.xml → complete pipeline → verify entities, relationships, migration order

**P1 Exit Criteria:**
- Can parse PLCopen XML files into typed EntityCatalog
- FBD networks produce correct graph model with nodes, edges, execution order
- Call graph is complete and accurate
- Orphan POUs detected correctly
- Error recovery works: malformed POU skipped, pipeline continues
- Unit test coverage >80%

**P1 Quality Gate (MUST PASS before Phase 2):**
- [ ] QG-0 passes: all 16 Layer 0 core tests green
- [ ] QG-1 passes: all 17 Layer 1 ingestion tests green
- [ ] QG-2 passes: all 14 Layer 2 adapter tests green (PLCopen only)
- [ ] QG-3 passes: FBD parser tests green (10 tests minimum)
- [ ] Integration smoke test: `plcopen-sample.xml` → full pipeline → EntityCatalog with correct POU count
- [ ] Zero `any` types in all implemented code
- [ ] `tsc --noEmit` exits 0 across all implemented layers
- [ ] No silent failures: every test has an explicit assertion (no empty test bodies)
- **If any gate fails:** fix before proceeding. Do not accumulate debt across phase boundaries.

### Phase 2: Language Parsers + Graph (Weeks 3-5)

**Step 7 (Week 3): Complete FBD parser**
- Add fbd-enable-logic (EN/ENO handling)
- Add fbd-negation (negated inputs/connections)
- Add fbd-connector (connector/continuation pair resolution)
- Add feedback-handler in Layer 4 (cycle detection, previous-value semantics)
- Test: FBD networks with EN/ENO, negated inputs, feedback loops, cross-page connectors

**Step 8 (Week 3-4): SFC parser**
- Implement all sfc-* modules
- Test: SFC with initial step, transitions (ST and FBD conditions), actions with all 11 qualifiers, selection branches, simultaneous branches, jump steps, macro steps
- Build state machine model from parsed SFC

**Step 9 (Week 4): LD parser**
- Implement all ld-* modules
- Test: LD rungs with contacts (NO/NC, edge), coils (normal, set, reset), inline function blocks, branches

**Step 10 (Week 4-5): ST parser (basic) + IL parser**
- ST: store raw source, extract calls via regex/tokenization (full AST is Phase 4 enhancement)
- IL: line-by-line parsing, minimal investment
- Test: ST bodies produce call list, IL bodies parse without errors

**Step 11 (Week 5): Graph converters**
- Implement to-elk, to-reactflow, to-st (FBD → equivalent ST), sfc-to-state-diagram
- Test: FBD network → valid ELK JSON, FBD network → correct ST code

**P2 Quality Gate (MUST PASS before Phase 3):**
- [ ] QG-3 fully passes: all FBD tests (10), SFC tests (9), LD tests (4), ST tests (2), IL tests (1) green
- [ ] QG-4 passes: all 15 Layer 4 graph tests green
- [ ] SFC language mixing test: SFC with FBD action body → FBD body parsed correctly inside SFC
- [ ] Feedback loop test: FBD with cycle → feedback handler produces correct previous-value vars
- [ ] `to-st` converter: generated ST for sample FBD is syntactically valid (parseable by ST lexer)
- [ ] All 5 language parsers handle empty/minimal bodies without crashing
- **If any gate fails:** fix before proceeding. Parser bugs compound in analysis.

### Phase 3: Core Analysis (Weeks 6-7)

**Step 12 (Week 6): Complete relationship analysis**
- Enhance data-flow-analyzer: cross-network flow, global variable tracking, multi-writer detection with SharedStateWarning
- Implement fb-instance-tracker: instance counting, instance-by-type grouping
- Implement orphan detection in dependency-mapper
- Test: multi-writer scenarios flagged, orphan POUs detected, instance counts correct

**Step 13 (Week 6-7): Pattern detection**
- Implement pattern-registry, pattern-matcher
- Implement all 12 pattern detectors
- Test each detector against known patterns from sample code
- Verify confidence scores are calibrated

**P3 Quality Gate (MUST PASS before Phase 4):**
- [ ] QG-5 entity + relationship tests pass: all 15 tests green
- [ ] QG-5 pattern tests pass: all 6 tests green
- [ ] Multi-writer detection verified: 2 POUs writing same global → SharedStateWarning generated
- [ ] Orphan detection verified: unreachable POU → flagged
- [ ] Pattern confidence scores all within [0, 1] — no detector returns >1 or <0
- [ ] Call graph for sample project matches hand-verified expected graph
- **If any gate fails:** fix before proceeding. Analysis errors propagate to planning and output.

### Phase 4: External + Implicit Dependencies (Weeks 8-9)

**Step 14 (Week 8): External dependencies**
- Implement hmi-tag-extractor, io-mapping-analyzer, library-dependency, opcua-namespace, recipe-system
- Test: HMI tags extracted from naming patterns, I/O mappings collected, library deps tracked

**Step 15 (Week 8-9): Implicit dependencies**
- Implement timing-dependency, global-state-tracker, execution-order-deps, convention-detector
- Test: timing assumptions detected in timer/counter code, naming conventions identified

**Step 16 (Week 9): Safety analysis**
- Implement all safety-* modules
- Test: safety FBs detected, SIL levels assigned, safety boundaries identified, voting patterns found, certification requirements generated

**P4 Quality Gate (MUST PASS before Phase 5):**
- [ ] QG-5 safety tests pass: all 6 tests green
- [ ] QG-5 external tests pass: all 3 tests green
- [ ] QG-5 implicit tests pass: all 3 tests green
- [ ] Safety boundary crossing test: non-safety POU calling safety POU → boundary detected
- [ ] HMI inference test: variables with `_Run`/`_Fault` suffixes → inferred as HMI refs
- [ ] Timing dependency test: TON with hardcoded preset → timing assumption flagged
- [ ] Cross-task shared variable test: variable written in Task1, read in Task2 → flagged
- [ ] End-to-end context extraction: sample project → ContextExtractionResult with non-empty HMI, safety, timing sections
- **If any gate fails:** fix before proceeding. Missing context = missing migration risks.

### Phase 5: Planning + Output (Weeks 10-13)

**Step 17 (Week 10): Migration planning**
- Implement migration-order-computer, batch-planner, risk-assessor, review-identifier, blocker-detector
- Test: migration order has no dependency violations, batches respect dependency order, risk scores are reasonable, review requirements generated for safety POUs

**Step 18 (Week 10-11): Layout engine**
- Implement layout-engine, elk-layout, original-layout, hybrid-layout, sfc-layout
- Test: FBD networks get valid positions, SFC gets vertical layout, original positions preserved when available

**Step 19 (Week 11-12): Output generation**
- Implement report-generator with all 7 templates
- Implement context-chunker, token-estimator, cross-reference-builder, navigation-index
- Implement prompt-generator with all 4 templates
- Implement file-organizer
- Implement migration-map-builder, json-serializer, validation-runner, navigation-builder
- Implement quality-assessor, loss-tracker (QualityAssessment and InformationLoss in output)
- Implement provenance attachment (every entity carries Provenance metadata)
- Implement audit log writer (`shared/audit.ts` wired into pipeline)
- Publish migration-map.schema.json (JSON Schema for output format)
- Test: complete MigrationMap produced, reports render correctly, chunks fit token limits, cross-references are accurate
- Test: QualityAssessment trust tier computed correctly, InformationLoss tracks dropped elements
- Test: determinism — run pipeline twice on same input, assert byte-identical output (excluding timestamps)

**Step 20 (Week 12-13): Incremental rescan + diff**
- Add content hashing to discovery
- Add cache layer for parsed entities
- Implement rescan() method on PLCIndexer
- Implement scan-differ, diff-reporter (ScanDiff between two MigrationMaps)
- Implement diff() method on PLCIndexer
- Test: change one POU → only affected entities re-parsed, relationships updated
- Test: diff correctly identifies added/removed/modified entities, transitive impact, safety impact flags

**P5 Quality Gate (MUST PASS before Phase 6):**
- [ ] QG-6 passes: all 12 planning tests green
- [ ] QG-7 passes: all 9 layout tests green
- [ ] QG-8 passes: all 24 output tests green
- [ ] Full pipeline integration test: `plcopen-sample.xml` → complete MigrationMap → validates against JSON Schema
- [ ] Determinism test: run pipeline twice on same input → byte-identical output (excluding timestamps)
- [ ] Provenance test: every entity in MigrationMap has non-null `provenance.sourceFile`
- [ ] Quality assessment test: sample project → QualityAssessment with trust tier computed
- [ ] Information loss test: project with unsupported vendor extension → loss tracked in output
- [ ] Chunk token test: no chunk exceeds configured `maxTokensPerChunk`
- [ ] Diff test: modify one POU between scans → diff shows exactly that POU as modified + its callers as impacted
- [ ] Security test: XXE attack XML → blocked, no external entity loaded
- [ ] Security test: XML bomb → blocked, no exponential expansion
- **If any gate fails:** fix before proceeding. Output quality is the product.

### Phase 6: Vendor Adapters (Weeks 14-15)

**Step 21 (Week 14): Rockwell L5X adapter**
- Implement all rockwell/* modules including AOI parser
- Test against L5X sample files

**Step 22 (Week 15): Siemens SimaticML adapter**
- Implement all siemens/* modules including multi-instance DB
- Test against SimaticML sample files
- Note: Siemens has no position data → always triggers auto-layout

**Step 23 (Week 15): CODESYS adapter**
- Implement codesys-adapter, codesys-library
- Handle `<addData>` vendor extensions (preserve, don't crash)

**P6 Quality Gate (MUST PASS before Phase 7):**
- [ ] Rockwell L5X: full pipeline produces valid MigrationMap from L5X fixture
- [ ] Siemens SimaticML: full pipeline produces valid MigrationMap from SimaticML fixture
- [ ] Siemens auto-layout: all nodes get valid positions despite no XML coordinates
- [ ] CODESYS `<addData>`: vendor extensions preserved in output, no crash
- [ ] Multi-vendor test: project dir with PLCopen + L5X files → both parsed, correct adapter selected per file
- [ ] Adapter fallback: unknown format file in project dir → skipped with warning, pipeline continues
- **If any gate fails:** fix before Phase 7 polish. Vendor adapter bugs affect real customer files.

### Phase 7: Testing + Polish (Weeks 16-17)

**Step 24: Comprehensive test suite**
- Unit tests: >90% coverage across all layers
- Integration tests: full pipeline for PLCopen, L5X, SimaticML
- Edge case tests: SFC with parallel branches, FBD with feedback loops, safety boundary crossing, multi-vendor projects, large projects (100+ POUs)
- Performance tests: <30s for 50 POU project, <2min for 100+ POUs

**Step 25: Documentation**
- API documentation for public interface
- Usage guides for common scenarios
- Architecture documentation (this spec serves as the foundation)

---

## Dependency Rules (Enforced)

```
Layer 8 (output)    → 0, 4, 5, 6, 7
Layer 7 (layout)    → 0, 4
Layer 6 (planning)  → 0, 5 (reads RelationshipGraph for migration ordering)
Layer 5 (analysis)  → 0, 4
Layer 4 (graph)     → 0
Layer 3 (parsers)   → 0, 4
Layer 2 (adapters)  → 0, 3
Layer 1 (ingestion) → 0
Layer 0 (core)      → (nothing)
shared/ (logger, progress, result) → (nothing) — injectable by any layer
```

No circular dependencies. No upward dependencies. `shared/` is not a layer — it contains cross-cutting utilities with zero domain dependencies. Enforce layer rules with eslint import rules.

---

## Extensibility Architecture: Plugin-Ready Design

**Purpose:** When the project lead says "we need to extract motion control axes" or "add ABB adapter support" or "detect ISA-88 batch patterns," the developer should be able to add it without modifying any existing module. Open/Closed Principle at the system level.

**Why this section exists:** The 6 extension points listed below are not just documentation — they define the registration contracts that make the system truly plug-and-play. Every registry uses the same pattern: interface → implementation → register → auto-discovered by pipeline.

### The Registry Pattern (Used Everywhere)

Every extensible subsystem follows the same pattern:

```
1. Define interface in core/interfaces/ (Layer 0)
2. Implement in the appropriate layer
3. Register via the subsystem's registry (auto-discovery or explicit)
4. Pipeline picks it up automatically — no orchestrator changes needed
```

Registries support two modes:
- **Built-in registration:** Hardcoded in the registry's `registerDefaults()` method (for shipped modules)
- **Config-driven registration:** User provides additional implementations via `PLCIndexerConfig.plugins` (for custom extensions)

### Plugin Configuration

```
PLCIndexerConfig:
  // ... existing sections ...

  plugins:
    adapters: IVendorAdapter[]              # Additional vendor adapters
    patternDetectors: IPatternDetector[]    # Additional pattern detectors
    contextExtractors: IContextExtractor[]  # Additional context extractors
    safetyFBs: SafetyFBEntry[]             # Additional safety FB catalog entries
    outputFormats: IOutputFormat[]          # Additional output format generators
    pipelineHooks: PipelineHook[]          # Pre/post hooks for each pipeline phase
```

This means a consumer can extend the system without forking it:

```typescript
const indexer = new PLCIndexer({
  plugins: {
    patternDetectors: [new MyCustomMotionDetector()],
    adapters: [new ABBAdapter()],
    contextExtractors: [new MyMESIntegrationExtractor()],
    safetyFBs: [{ name: 'MY_SAFETY_FB', vendor: 'Custom', category: 'logic', silLevel: 'SIL2' }],
  }
});
```

### Pipeline Hooks (Pre/Post Phase)

For cross-cutting concerns that don't fit into a specific registry:

```
PipelineHook:
  phase: 'discovery' | 'structure' | 'entities' | 'relationships' | 'context' | 'output' | '*'
  timing: 'before' | 'after'
  handler: (context: PhaseContext) => Promise<void>
```

Use cases:
- "Before output phase, run our custom compliance checker"
- "After discovery phase, filter out test fixture files"
- "After every phase, push progress to our internal dashboard"

### Extension Point Catalog

**1. Adding a new vendor adapter**
- Create: `adapters/<vendor>/<vendor>-adapter.ts` (+ sub-modules as needed)
- Implement: `IVendorAdapter` interface
- Register: add to `adapter-registry.ts` defaults OR pass via `config.plugins.adapters`
- Auto-wired: format-sniffer detects vendor → adapter-registry returns your adapter → pipeline uses it
- Zero changes to: orchestrator, parsers, analysis, output

**2. Adding a new language parser**
- Create: `parsers/<language>/<language>-parser.ts`
- Implement: `ILanguageParser<T>` interface
- Register: add to body routing in `plcopen-body.ts` (or equivalent adapter body router)
- Note: this is the one extension that requires touching an existing file (the body router), because language detection is adapter-specific

**3. Adding a new pattern detector**
- Create: `analysis/patterns/detectors/<pattern-name>.ts`
- Implement: `IPatternDetector` interface (patternId, patternName, category, detect, getConfidence)
- Register: add to `pattern-registry.ts` defaults OR pass via `config.plugins.patternDetectors`
- Auto-wired: pattern-matcher iterates all registered detectors → your detector runs on every network/POU
- Zero changes to: anything else

**4. Adding a new context extractor**
- Create: `analysis/external/<extractor>.ts` or `analysis/implicit/<extractor>.ts`
- Implement: `IContextExtractor<T>` interface (name, category, extract, isApplicable)
- Register: add to context extraction phase OR pass via `config.plugins.contextExtractors`
- Auto-wired: Phase 5 iterates all registered extractors → your extractor runs if `isApplicable()` returns true
- Zero changes to: anything else

**5. Adding a new safety FB to catalog**
- Add: entry to `core/constants/safety-fbs.ts` OR pass via `config.plugins.safetyFBs`
- Auto-wired: `sil-detector.ts` checks the catalog → your FB is recognized as safety-related
- Zero changes to: anything else

**6. Adding a new output format**
- Create: `output/reports/templates/<format>.ts`
- Implement: `IOutputFormat` interface (formatId, generate)
- Register: add to `report-generator.ts` defaults OR pass via `config.plugins.outputFormats`
- Auto-wired: `generateReport(map, format)` dispatches to your generator
- Zero changes to: anything else

**7. Adding a new SFC action qualifier**
- Add: to `ActionQualifier` type in `core/types/sfc.types.ts`
- Add: parsing logic to `parsers/sfc/sfc-qualifier.ts`
- Add: timing semantics if applicable
- Note: this requires type changes (Layer 0) because qualifiers are part of the core model

**8. Adding a new analysis dimension** (e.g., "extract motion control axes", "detect ISA-88 batch patterns")
- If it's a pattern: use extension point #3
- If it's an external dependency: use extension point #4
- If it's a new analysis category entirely:
  - Create: `analysis/<category>/` subdirectory with analyzer + sub-modules
  - Add: result type to `core/types/`
  - Add: to Phase 5 context extraction pipeline
  - This is the "medium effort" extension — new types + new modules, but existing modules untouched

### What Makes This Truly Scalable

| Scenario | Files to Create | Files to Modify | Orchestrator Changes |
|----------|----------------|-----------------|---------------------|
| New vendor adapter | 2-5 | 0 (if config-driven) | None |
| New pattern detector | 1 | 0 (if config-driven) | None |
| New context extractor | 1 | 0 (if config-driven) | None |
| New safety FB | 0 | 1 (constants file) or 0 (config) | None |
| New output format | 1 | 0 (if config-driven) | None |
| New analysis dimension | 2-4 | 1 (add type file) | None |
| New language parser | 2-5 | 1 (body router) | None |
| Pipeline hook | 0 | 0 (config only) | None |

The key insight: the orchestrator (PLCIndexer class) never needs to change when you add capabilities. It iterates registries. Registries are populated from defaults + config. New capabilities register themselves.

---

## Testing Strategy

| Layer | Test Type | Coverage Target |
|-------|-----------|-----------------|
| Core (0) | Unit | 100% |
| Ingestion (1) | Unit + Integration | 90% |
| Adapters (2) | Unit + Integration | 95% |
| Parsers (3) | Unit | 95% |
| Graph (4) | Unit | 95% |
| Analysis (5) | Unit + Integration | 90% |
| Planning (6) | Unit | 90% |
| Layout (7) | Unit | 85% |
| Output (8) | Unit + Integration | 90% |

### Critical Test Scenarios

| Scenario | Priority | Why |
|----------|----------|-----|
| PLCopen XML full pipeline | P0 | Primary format, must work perfectly |
| FBD with feedback loops | P0 | Previous-value semantics are subtle |
| FBD with EN/ENO | P0 | Conditional execution changes behavior |
| SFC with parallel branches | P0 | Simultaneous divergence/convergence |
| SFC with timed actions (L, D, SD, DS, SL) | P0 | Timing semantics must be correct |
| Safety boundary crossing | P0 | Safety-critical, cannot miss |
| 2oo3 voting detection | P0 | Safety pattern, high consequence |
| Multi-writer global variable | P1 | Race condition detection |
| Orphan POU detection | P1 | Dead code identification |
| Connector/continuation resolution | P1 | Cross-page FBD connections |
| HMI tag extraction | P1 | External dependency capture |
| Naming convention detection | P1 | Hidden dependency surface |
| Multi-vendor project | P2 | Adapter switching |
| Large project (100+ POUs) | P2 | Performance validation |
| Incremental rescan | P2 | Efficiency for iterative use |
| Deterministic output | P0 | Same input → byte-identical output (regulatory requirement) |
| XXE attack prevention | P0 | Malicious XML must not trigger external entity loading |
| XML bomb prevention | P0 | Exponential entity expansion must be blocked |
| Provenance tracing | P1 | Every entity traceable to source file + line + xpath |
| Information loss tracking | P1 | Dropped elements, approximations, unsupported features reported |
| Scan-to-scan diff | P1 | Changed entities correctly identified with transitive impact |
| Safety diff impact | P0 | Changes to safety code flagged for review/recertification |
| Quality self-assessment | P1 | Trust tier computed correctly from completeness/confidence |
| Unicode content preservation | P1 | Non-ASCII comments/identifiers preserved byte-for-byte |
| Schema validation | P2 | Output validates against published JSON Schema |

### Test Fixtures

```
tests/fixtures/
├── plcopen/
│   ├── simple-project.xml        # Basic: 3 POUs, 2 types
│   ├── motor-control.xml         # Motor control pattern
│   ├── safety-project.xml        # Safety POUs with SIL ratings
│   ├── fbd-feedback.xml          # FBD with feedback loops
│   ├── fbd-en-eno.xml            # FBD with EN/ENO
│   ├── sfc-complex.xml           # SFC with branches, qualifiers
│   ├── large-project.xml         # 100+ POUs
│   └── vendor-extensions.xml     # PLCopen with <addData>
├── rockwell/
│   ├── simple-l5x.xml
│   └── aoi-project.xml
├── siemens/
│   └── simatic-project.xml
├── security/                         # Input security test cases
│   ├── xxe-attack.xml                # External entity injection attempt
│   ├── xml-bomb.xml                  # Billion laughs / entity expansion
│   ├── path-traversal.xml            # File paths referencing ../../
│   └── oversized.xml                 # Exceeds max file size
├── unicode/                          # Internationalization test cases
│   ├── german-comments.xml           # ISO-8859-1 encoded, German comments
│   ├── chinese-identifiers.xml       # UTF-8, CJK variable names
│   └── mixed-encoding.xml            # BOM + encoding declaration mismatch
└── expected/
    ├── simple-project-map.json       # Expected MigrationMap output
    ├── motor-control-map.json
    └── simple-project-quality.json   # Expected QualityAssessment
```

---

## Performance Targets

| Metric | Target |
|--------|--------|
| Small project (<20 POUs) | <5s full scan |
| Medium project (20-100 POUs) | <30s full scan |
| Large project (100+ POUs) | <2min full scan |
| Incremental rescan | <5s for changed files |
| Memory usage | <500MB peak |
| Parse accuracy | >99% |
| Safety detection recall | >95% |
| Pattern detection precision | >85% |
| External dep coverage | >90% |

---

## Success Metrics

| Metric | Target | How to Measure |
|--------|--------|----------------|
| Parse accuracy | >99% | Test suite pass rate against known-good fixtures |
| Layout quality | >90% satisfaction | Visual comparison with original diagrams |
| Review efficiency | <5 min per POU | Time tracking in review interface |
| AI migration success | >80% first-pass | Verification tests on migrated code |
| SFC state machine accuracy | >99% | State transition tests |
| Safety detection recall | >95% | Known safety code detection rate |
| External dep coverage | >90% | HMI/IO/Library capture rate |
| Pattern detection precision | >85% | False positive rate |
| Migration order correctness | 100% | No dependency violations in output |

---

## Risk Mitigation

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Vendor XML variations | High | Medium | Extensive test files per vendor, adapter pattern isolates changes |
| Large file performance | Medium | High | Streaming XML parser, lazy body parsing, parallel I/O |
| Layout quality | Medium | Medium | Multiple algorithms, original position preservation, manual override |
| Token limit issues | Low | High | Aggressive chunking, summarization, configurable limits |
| SFC complexity | Medium | High | Comprehensive test suite, state machine validation |
| Feedback loop edge cases | Medium | High | Explicit previous-value handling, cycle detection |
| Safety certification gaps | Low | Critical | Safety FB catalog, boundary detection, conservative flagging |
| HMI tag format variations | Medium | Medium | Multiple detection strategies (config files, naming patterns, access modifiers) |
| Binary file encounters | High | Low | Clear export instructions, fail-fast with helpful error messages |

---

## Research Cross-Reference

Every module in this spec traces back to research. Here's the mapping:

| Spec Module | Research Source | Key Insight |
|-------------|----------------|-------------|
| format-sniffer | `binary-vs-text.md`, `plcopen-xml-schema.md` | Namespace detection is highest confidence |
| plcopen-adapter | `plcopen-xml.md`, `plcopen-xml-schema.md` | Back-reference connection model |
| fbd-parser | `function-block-diagram.md`, `03-FBD-EXTRACTION.md` | Position-based execution order |
| fbd-enable-logic | `03-FBD-EXTRACTION.md` | EN/ENO changes control flow |
| fbd-connector | `03-FBD-EXTRACTION.md` | Cross-page connections via named pairs |
| feedback-handler | `02-XML-TO-GRAPH-MODEL.md` | Previous-value semantics for cycles |
| sfc-parser | `sequential-function-chart.md`, `04-SFC-EXTRACTION.md` | 11 qualifiers, nested languages |
| sfc-jump-step | `plcopen-xml-schema.md` | `<jumpStep>` element for loops |
| entity-extractor | `extraction-checklist.md` | Priority-tagged extraction requirements |
| call-graph-builder | `dependency-analysis.md` | Caller/callee with instance tracking |
| data-flow-analyzer | `dependency-analysis.md` | Multi-writer detection |
| orphan detection | `dependency-analysis.md` | Dead code exclusion |
| hmi-tag-extractor | `hmi-integration.md` | Tag databases, naming patterns |
| io-mapping-analyzer | `hardware-mapping.md` | Physical I/O to variable mapping |
| timing-dependency | `implicit-vs-explicit.md` | Scan rate assumptions |
| convention-detector | `implicit-vs-explicit.md` | Naming patterns as hidden deps |
| safety-analyzer | `safety-considerations.md` | SIL levels, dual-channel, certification |
| safety-fb-catalog | `safety-considerations.md`, `related-standards.md` | IEC 61508 compliance |
| voting-logic-detector | `safety-considerations.md` | 2oo3, 1oo2 architectures |
| batch-planner | `dependency-analysis.md` | Topological sort migration order |
| migration-order-computer | `dependency-analysis.md` | Dependency graph → migration ordering |
| risk-assessor | `migration-challenges.md` | Risk categories and scoring |
| review-identifier | `human-approval-workflow.md` | 4 checkpoints, safety gate |
| context-chunker | `ai-consumable-format.md`, `06-AI-CONTEXT-GENERATION.md` | 4-level hierarchy, token limits |
| cross-reference-builder | `06-AI-CONTEXT-GENERATION.md` | 9 cross-reference types |
| file-organizer | `ai-consumable-format.md` | Output directory structure |
| migration-map-builder | `07-MIGRATION-MAP-SCHEMA.md` | Complete schema specification |
| vendor-extensions | `plcopen-xml-schema.md`, `codesys-export.md` | `<addData>` handling |
| l5x-adapter | `rockwell-l5x.md` | Wire-based connections, sheets |
| simatic-adapter | `siemens-xml.md` | FlgNet, no positions, multi-instance DB |
| scanning pipeline | `01-SCANNING-PIPELINE.md` | 5-phase breadth-first model |
| incremental rescan | `01-SCANNING-PIPELINE.md` | Content hashing, delta updates |

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-02-05 | Initial architecture (Phase 10 only) |
| 2.0.0 | 2026-02-05 | Added SFC, feedback, external deps, safety expansion |
| 3.0.0 | 2026-02-05 | Unified scanner + indexer, added 12 gaps from audit, phased implementation plan |
| 3.1.0 | 2026-02-05 | Enterprise hardening: added complete src/ tree, observability, error recovery, SRP fixes |
| 4.0.0 | 2026-02-05 | Enterprise trust: determinism, provenance, audit trail, information loss, input security, schema versioning, scan diff, quality self-assessment, i18n |
| 4.1.0 | 2026-02-05 | Plugin architecture: config-driven registries, pipeline hooks, IOutputFormat, PluginConfig, extensibility catalog with effort matrix |
| 5.0.0 | 2026-02-05 | Incremental testing & quality gates: 166 tests across 9 quality gates, silent failure detection strategy, test-as-you-build workflow, per-phase gate enforcement |

### v5.0.0 Changes from v4.1.0

1. Added top-level "Incremental Testing & Quality Gates Philosophy" section with quality gate summary table, silent failure detection strategy, and test-as-you-build workflow
2. Added "Layer 0 Incremental Tests" after Layer 0 section: 16 tests covering type compilation, barrel exports, error hierarchy, Result type, logger, audit trail
3. Added "Layer 1 Incremental Tests" after Layer 1 section: 17 tests covering format detection for all vendors, binary rejection, encoding handling, content hashing
4. Added "Layer 2 Incremental Tests" after Layer 2 section: 14 tests covering adapter registry, PLCopen project shell extraction, back-reference inversion, vendor extension preservation
5. Added "Layer 3 Incremental Tests" after Layer 3 section: 26 tests across FBD (10), SFC (9), LD (4), ST (2), IL (1) covering connection resolution, execution order, qualifiers, language mixing
6. Added "Layer 4 Incremental Tests" after Layer 4 section: 15 tests covering graph traversal, cycle detection, feedback handling, all 4 converters (ELK, React Flow, ST, state diagram)
7. Added "Layer 5 Incremental Tests" after Layer 5 section: 33 tests across entities (7), relationships (8), patterns (6), safety (6), external (3), implicit (3)
8. Added "Layer 6 Incremental Tests" after Layer 6 section: 12 tests covering migration order safety, batch planning, risk scoring, review identification, blocker detection
9. Added "Layer 7 Incremental Tests" after Layer 7 section: 9 tests covering ELK positions, port mapping, original position preservation, SFC vertical flow, strategy selection
10. Added "Layer 8 Incremental Tests" after Layer 8 section: 24 tests across migration-map (6), chunks (5), reports (3), quality (4), diff (5)
11. Added quality gate checkboxes to each Implementation Phase (P1 through P6) with explicit "fix before proceeding" enforcement
12. Every quality gate specifies the exact test counts and key validations that must pass
13. Silent failure detection table maps each layer to its highest-risk silent failure and the specific test that catches it

### v4.1.0 Changes from v4.0.0

1. Replaced "Extension Points" section with comprehensive "Extensibility Architecture: Plugin-Ready Design"
2. Added `PluginConfig` to `PLCIndexerConfig` — consumers can extend via config without forking
3. Added `PipelineHook` type for pre/post phase hooks (cross-cutting extensions)
4. Added `IOutputFormat` interface (9th interface in `core/interfaces/`)
5. Added `pipeline.types.ts` to Layer 0 (18th type file) with PipelineHook, PhaseContext, PluginConfig
6. Added 8 extension point catalog entries with exact file-to-create / file-to-modify / orchestrator-changes matrix
7. Added config-driven registration mode for all registries (adapters, patterns, extractors, safety FBs, output formats)
8. Documented the registry pattern used by all extensible subsystems
9. Added effort matrix table: every extension scenario shows files to create, files to modify, and orchestrator changes (always "None")

### v4.0.0 Changes from v3.1.0

1. Added Determinism and Reproducibility section: content-addressable IDs, sorted output, determinism test requirement
2. Added Output Schema Versioning section: semver for MigrationMap schema, JSON Schema publication, `core/schemas/` directory
3. Added Provenance and Audit Trail section: per-entity source tracing, confidence scoring per entity, `shared/audit.ts` decision log
4. Added Information Loss Tracking section: dropped elements, approximations, unsupported features, coverage stats
5. Added Input Security section: XXE prevention, XML bomb prevention, path traversal protection, DoS limits
6. Added Scan-to-Scan Comparison (Diff) section: `diff()` API, ScanDiff type, transitive impact, safety impact flags
7. Added Internationalization section: Unicode-aware processing, encoding detection, CJK token estimation
8. Added Completeness Self-Assessment section: QualityAssessment type, trust tiers, per-phase/language/vendor/safety completeness
9. Added 4 new type files to Layer 0: `provenance.types.ts`, `quality.types.ts`, `diff.types.ts`, `information-loss.types.ts`
10. Added `output/diff/` modules: `scan-differ.ts`, `diff-reporter.ts`
11. Added `output/quality/` modules: `quality-assessor.ts`, `loss-tracker.ts`
12. Added `diff()` to PLCIndexer public API
13. Added 13 new critical test scenarios (determinism, XXE, provenance, diff, quality, unicode, schema)
14. Added security and unicode test fixtures
15. Updated output directory structure with `quality/`, `audit-log.jsonl`, `migration-map.schema.json`
16. Updated Step 1 to include new types, audit.ts, and XML security config
17. Updated Step 19 to include quality assessment, provenance, audit log, schema publication, determinism test
18. Updated Step 20 to include diff engine

### v3.1.0 Changes from v3.0.0

1. Added complete `src/` package directory tree (~120 files across 9 layers + shared)
2. Added `core/interfaces/` directory listing with all 8 interface files
3. Added `core/errors/` directory listing with all 5 error class files
4. Added `core/constants/` directory listing with all 5 constant files
5. Added `shared/` cross-cutting utilities: `logger.ts`, `progress.ts`, `result.ts`
6. Added Observability section: structured logging, pipeline progress reporting, configurable output
7. Added Error Recovery Strategy section: per-phase recovery rules, Result<T,E> pattern, error aggregation in MigrationMap
8. Moved `migration-order-computer.ts` from Layer 5 (analysis/relationships/) to Layer 6 (planning/) — SRP fix: computing migration order is a planning decision, not a relationship analysis
9. Added `detectors/` subdirectory to `analysis/patterns/` — 12 pattern detectors now properly namespaced
10. Added barrel `index.ts` exports per layer for clean public API boundaries
11. Updated Layer 6 dependency rule: `→ 0, 5` (needs RelationshipGraph for migration ordering)
12. Updated Phase 1 Step 1 to include shared utilities
13. Updated Phase 5 Step 17 to include migration-order-computer

### v3.0.0 Changes from v2.0.0

1. Merged `@drift-studio/plc-scanner` and `@drift-studio/plc-indexer` into single package
2. Added Layer 6 (Planning): batch-planner, risk-assessor, review-identifier, blocker-detector
3. Added MigrationMap as first-class output type with complete schema
4. Added incremental rescan support with content hashing and caching
5. Added vendor extension handling (`<addData>` preservation)
6. Added VAR_EXTERNAL and VAR_ACCESS to variable scopes (all 8 PLCopen scopes)
7. Added returnType to POU interface (critical for functions)
8. Added convention-detector for naming pattern detection
9. Added SFCJumpStep for SFC loop constructs
10. Added multi-writer detection and SharedStateWarning
11. Added orphan POU detection
12. Added file output organization (analysis-output/ directory structure)
13. Restructured implementation phases with strict build order and daily granularity
14. Added research cross-reference table mapping every module to its research source
