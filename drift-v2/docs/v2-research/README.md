# Drift v2 Research & Audit

Complete audit of Drift v1 organized by subsystem. Each document is single-feature focused and human-readable.

## Vision

Move all parsing, pattern detection, and analysis into Rust. TypeScript becomes a thin orchestration/presentation layer over a Rust-native engine. Fastest possible scanning and indexing for large enterprise codebases.

## Directory Structure

```
v2-research/
├── 00-overview/
│   ├── what-is-drift.md          # ★ START HERE — Complete system explanation for AI agents
│   ├── subsystem-connections.md  # ★ How every subsystem connects to every other
│   ├── pipelines.md              # ★ End-to-end flows: scan, check, MCP query, gates, setup, learning
│   ├── architecture.md           # Package layout, key observations, reading order
│   ├── dependency-graph.md       # Package dependency graph, external deps, versions
│   ├── language-split.md         # What's in Rust vs TS, migration priority
│   ├── data-models.md            # Core data models (Pattern, Violation, Contract, Memory, ParseResult, Config)
│   └── configuration.md          # Config file format, .driftignore, .drift/ directory structure
│
├── 01-rust-core/
│   ├── scanner.md                # Parallel file walking, ignore patterns
│   ├── parsers.md                # Tree-sitter parsing for 10 languages
│   ├── call-graph.md             # Call graph building, storage, queries (→ see 04-call-graph/)
│   ├── boundaries.md             # Data access detection, sensitive fields, ORM models
│   ├── reachability.md           # Forward/inverse data flow analysis (→ see 04-call-graph/reachability.md)
│   ├── unified-analysis.md       # Combined AST + string pattern detection
│   ├── coupling.md               # ★ Module coupling analysis (Rust vs TS comparison, full algorithms)
│   ├── constants.md              # ★ Secret detection (21 patterns), magic numbers (→ see 05-analyzers/)
│   ├── test-topology.md          # ★ Test framework detection, coverage mapping (→ see 17-test-topology/)
│   ├── error-handling.md         # ★ Error boundaries, gap detection (→ see 19-error-handling/)
│   ├── environment.md            # ★ Environment variable extraction (→ see 05-analyzers/)
│   ├── wrappers.md               # ★ Framework wrapper detection (→ see 05-analyzers/)
│   ├── other-analyzers.md        # Summary of test topology, error handling, constants, environment, wrappers
│   ├── napi-bridge.md            # N-API bridge (27 exported functions, platform support)
│   └── data-models.md            # Rust struct definitions, enums, performance characteristics
│
├── 02-parsers/
│   ├── overview.md               # Full parser subsystem architecture, pipeline, language coverage
│   ├── types.md                  # Rust + TS + NAPI type definitions, ParseResult, FunctionInfo, etc.
│   ├── rust-parsers.md           # 9 Rust parsers: queries, extraction, enterprise features, parity gaps
│   ├── base-parser.md            # TS BaseParser abstract class (20+ methods)
│   ├── ts-parser-manager.md      # TS ParserManager: LRU cache, incremental parsing, language detection
│   ├── ts-parsers.md             # TS-side parsers, tree-sitter loaders, extraction depth
│   ├── tree-sitter-layer.md      # TS tree-sitter wrappers (7 languages), loaders, config, types
│   ├── pydantic.md               # Pydantic v1/v2 model extraction (9 files, full pipeline)
│   ├── napi-bridge.md            # NAPI types, parse() function, native adapters, fallback
│   ├── rust-vs-ts-comparison.md  # Feature parity comparison across 11 languages
│   ├── integration.md            # How parsers connect to call graph, detectors, analyzers, security
│   └── testing.md                # Test coverage per language, test patterns, v2 strategy
│
├── 03-detectors/
│   ├── overview.md               # Architecture, base classes, registry system
│   ├── categories.md             # All 22 categories with every detector listed
│   ├── detector-contracts.md     # Interfaces, algorithms (learning, outlier, confidence scoring)
│   ├── confidence-scoring.md     # ★ Weighted scoring algorithm, factors, thresholds (moved from gap-analysis)
│   └── patterns/                 # Pattern system deep dive (cortex-style)
│       ├── overview.md           # Architecture, pipeline, categories, lifecycle
│       ├── data-model.md         # Pattern JSON schema, all types, full data model
│       ├── confidence-scoring.md # Weighted scoring algorithm, factors, thresholds
│       ├── outlier-detection.md  # Z-score, IQR, rule-based statistical detection
│       ├── pattern-matching.md   # AST, regex, structural matching engine
│       ├── rules-engine.md       # Violation generation, severity, variants
│       ├── storage.md            # SQLite schema, JSON shards, indexes, backups
│       └── pipeline.md           # End-to-end detection pipeline (8 phases)
│
├── 04-call-graph/                # ★ Canonical call graph docs (consolidated)
│   ├── overview.md               # ★ Full system overview: architecture, 9 languages, hybrid extraction, dual storage
│   ├── extractors.md             # Per-language extractors (8 languages × 3 variants), Rust universal extractor
│   ├── analysis.md               # GraphBuilder, Reachability, Impact, DeadCode, Coverage, PathFinder
│   ├── reachability.md           # Rust reachability engines (in-memory + SQLite), forward/inverse, types
│   ├── enrichment.md             # Sensitivity classification, impact scoring, remediation generation
│   ├── storage.md                # JSON legacy + SQLite sharded, streaming builders, unified provider
│   ├── types.md                  # FunctionNode, CallSite, CallGraph, ReachabilityResult (TS + Rust)
│   └── rust-core.md              # Rust call_graph/ module: StreamingBuilder, UniversalExtractor, CallGraphDb
│
├── 05-analyzers/
│   ├── core-analyzers.md         # ★ AST, type, semantic, flow analyzers (full method inventory + types)
│   ├── language-analyzers.md     # ★ Per-language analyzers (8 languages + WPF, framework-specific types)
│   ├── unified-provider.md       # Unified extraction pipeline, 9 normalizers, 20 ORM matchers
│   ├── rules-engine.md           # ★ Evaluator, rule engine, variant manager, severity, quick-fix (7 strategies)
│   ├── module-coupling.md        # ★ Coupling metrics, cycle detection, refactor impact, unused exports
│   ├── wrappers-analysis.md      # ★ TS wrapper orchestration (clustering, primitives, export)
│   ├── constants-analysis.md     # ★ TS constants orchestration (dead detection, storage, extractors)
│   └── environment-analysis.md   # ★ TS environment orchestration (.env parsing, missing detection)
│
├── 06-cortex/
│   ├── overview.md               # Full memory system (~150 files, 15+ subsystems)
│   └── retrieval-and-embeddings.md # Embedding providers, vector search, retrieval pipeline, intents
│
├── 07-mcp/
│   ├── overview.md               # ★ Full MCP system overview, architecture, request flow
│   ├── server.md                 # Enterprise server: store init, routing, dual-path, project resolution
│   ├── infrastructure.md         # Cache, rate limiter, metrics, cursors, errors, token estimation, tool filter
│   ├── tools-inventory.md        # Tool count, file map, dual-path summary, registration order
│   ├── tools-by-category.md      # Every tool with file, purpose, token cost (10 categories)
│   ├── curation.md               # Anti-hallucination pattern approval verification
│   ├── feedback-and-packs.md     # Example quality feedback + pattern packs
│   ├── server-infrastructure.md  # Navigation index to split docs
│   └── testing.md                # Test patterns and coverage
│
├── 08-storage/
│   ├── overview.md               # 6 storage backends, fragmentation analysis
│   └── sqlite-schema.md          # Full schema (26 tables, 50+ indexes, triggers, views) + Cortex schema
│
├── 09-quality-gates/
│   ├── overview.md               # Full quality gates system: 6 gates, policy engine, reporters
│   ├── orchestrator.md           # GateOrchestrator, GateRegistry, ParallelExecutor, ResultAggregator
│   ├── gates.md                  # 6 gate implementations: compliance, constraints, regression, impact, security, custom
│   ├── policy.md                 # PolicyLoader, PolicyEvaluator, 4 aggregation modes, 4 built-in policies
│   ├── reporters.md              # 5 reporters: text, JSON, SARIF, GitHub, GitLab
│   ├── store.md                  # SnapshotStore (branch-based), GateRunStore (history)
│   ├── types.md                  # 40+ interfaces, per-gate detail types, custom rule conditions
│   └── audit.md                  # ★ Audit engine, health scoring, degradation tracking (moved from gap-analysis)
│
├── 10-cli/
│   ├── overview.md               # 50+ commands, services, reporters, UI, git integration
│   ├── commands.md               # Complete command reference (all 50+ commands with flags)
│   ├── services.md               # ScannerService, PatternServiceFactory, workers
│   ├── setup-wizard.md           # 8-phase setup wizard, 13 runners, SourceOfTruth
│   ├── reporters.md              # Text, JSON, GitHub, GitLab, SARIF reporters
│   ├── ui.md                     # Spinner, table, prompts, progress, git integration
│   ├── git.md                    # Staged files, hooks (pre-commit/pre-push), Husky support
│   ├── types.md                  # CLI type definitions, type distribution map
│   └── testing.md                # Property-based tests, exit code invariants
│
├── 11-ide/
│   ├── vscode-extension.md       # Extension architecture, commands, views, UI
│   ├── lsp-server.md             # LSP handlers, commands, integration
│   └── dashboard.md              # Vite+React dashboard, server, client components
│
├── 12-infrastructure/
│   ├── overview.md               # ★ Full infrastructure overview, dependency graph, publish order
│   ├── build-system.md           # pnpm, Turborepo, tsconfig, ESLint, Vitest, Prettier
│   ├── ci-cd.md                  # GitHub Actions: ci.yml, native-build.yml, release.yml
│   ├── ci-agent.md               # CI agent package: PRAnalyzer, 12 interfaces, scoring, heuristics
│   ├── github-action.md          # GitHub Action: inputs, outputs, composite steps
│   ├── ai-providers.md           # AI package: Anthropic, OpenAI, Ollama, context building
│   ├── galaxy.md                 # Galaxy 3D visualization: Three.js, components, layout engine
│   ├── cibench.md                # CIBench benchmark: 4-level evaluation, calibration, probes
│   ├── telemetry.md              # Cloudflare Worker: D1 schema, endpoints, privacy
│   ├── rust-build.md             # Rust workspace: Cargo deps, NAPI exports, cross-platform
│   ├── docker.md                 # Docker: multi-stage build, compose, MCP server deployment
│   ├── scripts.md                # Scripts: publish, validate-docs, generation
│   ├── licensing.md              # ★ Licensing & feature gating (3 tiers, 16 features) (moved from gap-analysis)
│   └── ci-and-actions.md         # (Legacy summary, points to detailed docs)
│
├── 13-advanced/
│   ├── dna-system.md             # ★ DNA System overview (hub → sub-docs)
│   ├── dna/
│   │   ├── analyzer.md           # DNAAnalyzer orchestrator, pipeline, config
│   │   ├── gene-extractors.md    # 10 extractors (6 frontend + 4 backend), BaseGeneExtractor
│   │   ├── health-and-mutations.md # Health score formula, mutation detection algorithm
│   │   ├── output.md             # PlaybookGenerator + AIContextBuilder (4 levels)
│   │   ├── store.md              # DNAStore persistence, evolution tracking
│   │   └── types.md              # Gene, Allele, Mutation, StylingDNAProfile types
│   ├── decision-mining.md        # ★ Decision Mining overview (hub → sub-docs)
│   ├── decisions/
│   │   ├── analyzer.md           # DecisionMiningAnalyzer pipeline, config, usage
│   │   ├── git.md                # GitWalker, CommitParser, DiffAnalyzer
│   │   ├── extractors.md         # 5 language-specific commit extractors
│   │   └── types.md              # 30+ interfaces: decisions, clusters, ADRs
│   ├── simulation-engine.md      # ★ Simulation Engine overview (hub → sub-docs)
│   ├── simulation/
│   │   ├── engine.md             # SimulationEngine orchestrator, pipeline, config
│   │   ├── approach-generator.md # ApproachGenerator: category detection, strategy templates
│   │   ├── scorers.md            # 4 scorers: friction, impact, alignment, security
│   │   ├── language-strategies.md # 5 language providers, framework templates, keywords
│   │   └── types.md              # Task, approach, scoring, result types
│   ├── language-intelligence.md  # ★ Language Intelligence overview (hub → sub-docs)
│   └── language-intelligence/
│       ├── queries.md            # LanguageIntelligence class, cross-language query API
│       ├── normalizers.md        # BaseLanguageNormalizer + 5 language normalizers
│       ├── frameworks.md         # 5 framework pattern definitions (Spring, FastAPI, etc.)
│       ├── registry.md           # FrameworkRegistry singleton, detection, matching
│       └── types.md              # SemanticCategory, NormalizedDecorator, FunctionSemantics
│
├── 14-directory-map/
│   ├── crates.md                 # Every file in Rust crates
│   ├── packages-core.md          # Every file in packages/core
│   ├── packages-detectors.md     # Every file in packages/detectors
│   ├── packages-other.md         # Every file in all other packages
│   └── root-and-config.md        # Root directory, config files
│
├── 15-migration/
│   └── strategy.md               # 7-phase migration plan, what stays in TS, NAPI evolution
│
├── 16-gap-analysis/
│   ├── README.md                 # Gaps found: undocumented systems, corrections, priority order
│   └── rust-core-audit.md        # ★ Comprehensive Rust core documentation audit (moved from 01-rust-core/AUDIT.md)
│
├── 17-test-topology/
│   ├── overview.md               # Test topology system: framework detection, coverage mapping, quality scoring
│   ├── extractors.md             # Per-language test extractors (8 languages, 35+ frameworks)
│   ├── analyzer.md               # Coverage mapping, minimum test set, mock analysis, quality scoring
│   └── types.md                  # TestCase, TestCoverage, MockAnalysis, UncoveredFunction types
│
├── 18-constraints/
│   ├── overview.md               # Architectural constraint system: invariant detection → enforcement
│   ├── types.md                  # Constraint, ConstraintInvariant, predicates, scopes, verification types
│   ├── detection.md              # InvariantDetector (5 data sources) + ConstraintSynthesizer
│   ├── store.md                  # File-based persistence, querying, lifecycle management
│   └── verification.md           # ConstraintVerifier: predicate evaluation, change-aware verification
│
├── 19-error-handling/
│   ├── overview.md               # Error topology: profiles, boundaries, propagation chains, gap detection
│   ├── types.md                  # Full TS + Rust type definitions, type mapping between implementations
│   ├── analyzer.md               # Algorithms: quality scoring, risk scoring, propagation tracing, framework detection
│   └── mcp-tools.md              # drift_errors tool: types, gaps, boundaries actions
│
├── 20-contracts/
│   ├── overview.md               # API contract tracker: BE↔FE mismatch detection, field comparison
│   ├── types.md                  # Contract, BackendEndpoint, FrontendApiCall, FieldMismatch, query types
│   ├── storage.md                # SQLite schema, ContractRepository, JSON file format, migration
│   ├── detection.md              # Detection pipeline: endpoint extraction, path normalization, field comparison, confidence
│   └── mcp-tools.md              # drift_contracts_list tool, dual backend support, pagination
│
├── 21-security/
│   ├── overview.md               # Security infrastructure: boundaries, reachability, sensitive data
│   ├── boundary-scanner.md       # Two-phase learn-then-detect data access scanning
│   ├── learning.md               # DataAccessLearner: framework detection, convention learning
│   └── types.md                  # DataAccessPoint, SensitiveField, ORMModel, BoundaryRule types
│
├── 22-context-generation/
│   ├── overview.md               # ★ Context generation system: architecture, pipeline, MCP integration
│   ├── types.md                  # All type definitions: PackageContext, DetectedPackage, AIContextFormat
│   ├── package-detector.md       # 11-language monorepo package detection (npm, pnpm, cargo, go, maven, etc.)
│   ├── token-management.md       # Token budgeting, trimming strategy, AI formatting, MCP integration
│   └── gaps.md                   # ★ Context generation gaps & improvements (moved from gap-analysis)
│
├── 23-pattern-repository/
│   ├── overview.md               # ★ Pattern Repository: architecture, lifecycle, MCP integration
│   ├── types.md                  # Unified Pattern type, categories, status, confidence, severity
│   ├── repository.md             # IPatternRepository interface, query/filter/sort/pagination, events
│   ├── service.md                # IPatternService interface, PatternService implementation
│   ├── errors.md                 # PatternNotFoundError, InvalidStatusTransitionError, PatternAlreadyExistsError
│   ├── implementations.md        # 5 repository implementations: unified, legacy, memory, cached, factory
│   └── adapters.md               # Legacy PatternStore bridge, AutoInitPatternService, migration path
│
├── 24-data-lake/
│   ├── overview.md               # ★ Data Lake: architecture, disk layout, configuration, v2 replacement map
│   ├── types.md                  # Manifest, view, index, shard, config type definitions
│   ├── manifest.md               # ManifestStore: quick-load stats, file hashes, view freshness
│   ├── views.md                  # ViewStore: StatusView, PatternIndexView, SecuritySummaryView, TrendsView
│   ├── indexes.md                # IndexStore: file, category, table, entry point indexes
│   ├── query-engine.md           # QueryEngine: unified query API, routing strategy, pagination, stats
│   ├── materializer.md           # ViewMaterializer: post-scan rebuild pipeline, cross-domain sync
│   └── shards.md                 # PatternShardStore, CallGraphShardStore, SecurityShardStore, ExamplesStore
│
├── 25-services-layer/
│   ├── overview.md               # ★ Services: architecture, scan pipeline, data flow, v2 implications
│   ├── scanner-service.md        # ScannerService: worker pool, aggregation, outlier detection, results
│   └── detector-worker.md        # DetectorWorker: warmup, file processing, metadata preservation
│
└── 26-workspace/                 # ★ Workspace management (renumbered from 22-workspace)
    └── overview.md               # ★ Workspace lifecycle: backup, migration, context, projects (moved from gap-analysis)
```

## Document Count: ~165 files across 26 directories

## Recent Reorganization

The following files were moved to their proper categories:

| Original Location | New Location | Reason |
|-------------------|--------------|--------|
| `16-gap-analysis/workspace-management.md` | `26-workspace/overview.md` | This is the canonical workspace docs, not a gap |
| `16-gap-analysis/audit-system.md` | `09-quality-gates/audit.md` | Audit is part of quality gates |
| `16-gap-analysis/licensing-system.md` | `12-infrastructure/licensing.md` | Infrastructure concern |
| `16-gap-analysis/confidence-and-matching.md` | `03-detectors/confidence-scoring.md` | Core detector algorithm |
| `16-gap-analysis/context-generation.md` | `22-context-generation/gaps.md` | Belongs with context-gen docs |
| `01-rust-core/AUDIT.md` | `16-gap-analysis/rust-core-audit.md` | Meta-document, not core docs |
| `22-workspace/` | `26-workspace/` | Fixed numbering conflict with 22-context-generation |

Cross-references added to `01-rust-core/` files pointing to their full system counterparts in topic-specific categories.
