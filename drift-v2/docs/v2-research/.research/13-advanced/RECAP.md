# 13 Advanced Systems — Research Recap

> A complete synthesis of Drift v1's Advanced Systems layer — the intelligence tier that provides codebase fingerprinting (DNA), architectural decision mining, pre-flight simulation, and cross-language semantic normalization. This document captures everything important about category 13 in one place, serving as the definitive requirements specification for the v2 enterprise greenfield build.

---

## Executive Summary

Advanced Systems (`packages/core/src/dna/`, `packages/core/src/decisions/`, `packages/core/src/simulation/`, `packages/core/src/language-intelligence/`) is Drift's highest-level intelligence layer — 100% TypeScript (~60 source files across 4 subsystems) sitting at Layer 6 of the architecture. It builds on top of every other subsystem (parsers, detectors, call graph, patterns, storage) to provide capabilities that no other static analysis tool offers: biological modeling of codebase conventions (DNA), automated institutional knowledge extraction from git history (Decision Mining), speculative execution of code changes before writing a line (Simulation Engine), and cross-language semantic normalization that makes patterns from different languages comparable (Language Intelligence).

These four subsystems share a common architectural pattern: they are composite intelligence — they don't analyze code directly but instead synthesize higher-order insights from the outputs of lower-level subsystems. This makes them both the most powerful and the most fragile part of Drift: powerful because they produce unique insights, fragile because they depend on the quality of every upstream subsystem.

**Scale**: ~60 source files, ~45 type definitions, 10 gene extractors, 5 language normalizers, 5 language strategy providers, 5 commit extractors, 4 simulation scorers, 12 semantic categories, 13 task categories, 15 approach strategies, 12 decision categories.

**Language**: 100% TypeScript. V2 migrates compute-heavy paths (gene extraction, normalization, commit extraction) to Rust while keeping orchestration and AI-dependent features in TypeScript.

---

## Architecture

```
PRESENTATION LAYER
  MCP Tools | CLI (drift dna, drift decisions) | Quality Gates
ADVANCED SYSTEMS (Layer 6)
  DNA System (10 genes, health, mutations, evolution, playbook)
  Simulation Engine (4 scorers, 5 lang strategies, 13 task cats, 15 strats)
  Decision Mining (git walker, 5 extractors, 12 decision cats, ADR synth)
  Language Intelligence (5 normalizers, 5 frameworks, 12 semantic cats, registry)
DEPENDENCIES (consumed from lower layers)
  02-parsers | 03-detectors | 04-call-graph | 05-analyzers | 08-storage
  23-pattern-repository | 06-cortex | git (simple-git)
```


---

## Subsystem 1: DNA System (~15 files)

### What It Is

The DNA system extracts the "genetic fingerprint" of a codebase's styling and API conventions. It models conventions as **genes** (concerns like "variant-handling" or "api-response-format"), each with competing **alleles** (variants like "cva" vs "inline-conditionals"). The dominant allele represents the team's established pattern. Files deviating from the dominant allele are flagged as **mutations**. A composite health score (0-100) quantifies overall convention consistency.

### Core Design Principles
1. Every convention is a gene with measurable frequency
2. Dominance is earned by frequency (>=30% to qualify)
3. Mutations are deviations, not errors — impact is graded (high/medium/low)
4. Health is a composite score, not binary pass/fail
5. Evolution is tracked over time (last 50 snapshots)
6. AI context is generated at 4 detail levels for token efficiency

### Component Inventory

| Component | File | Purpose |
|-----------|------|---------|
| DNAAnalyzer | `dna-analyzer.ts` | Main orchestrator: discover, extract, score, assemble |
| BaseGeneExtractor | `gene-extractors/base-extractor.ts` | Abstract base with extraction, aggregation, gene-building pipeline |
| 6 Frontend Extractors | `gene-extractors/*.ts` | Variant handling, responsive, state styling, theming, spacing, animation |
| 4 Backend Extractors | `gene-extractors/*.ts` | API response format, error response format, logging format, config pattern |
| HealthCalculator | `health-calculator.ts` | 4-factor weighted health score (0-100) |
| MutationDetector | `mutation-detector.ts` | Deviation detection with impact grading |
| PlaybookGenerator | `playbook-generator.ts` | Human-readable Markdown style guide output |
| AIContextBuilder | `ai-context.ts` | AI-ready context at 4 detail levels |
| DNAStore | `dna-store.ts` | JSON persistence with evolution tracking |
| Types | `types.ts` | All type definitions |

### Analysis Pipeline

```
1. Initialize extractors based on mode (frontend/backend/all)
2. Discover files (componentPaths + backendPaths, apply excludePaths)
3. Read file contents -> Map<string, string>
4. Run each gene extractor's analyze() against file map
   a. Per file: extractFromFile() -> DetectedAllele[]
   b. Aggregate: alleleCounts, alleleFiles, alleleExamples
   c. Build Gene: frequency, dominant selection, confidence, consistency
5. MutationDetector.detectMutations(genes, files)
6. HealthCalculator.calculateHealthScore(genes, mutations)
7. Assemble StylingDNAProfile with summary, genes, mutations, evolution
```

### Gene Inventory (10 Genes)

**Frontend Genes (6)**:

| Gene ID | Extractor | Alleles Detected |
|---------|-----------|-----------------|
| `variant-handling` | VariantHandlingExtractor | cva, clsx, inline conditionals, CSS modules |
| `responsive-approach` | ResponsiveApproachExtractor | Tailwind breakpoints, media queries, container queries |
| `state-styling` | StateStylingExtractor | Data attributes, aria states, pseudo-classes |
| `theming` | ThemingExtractor | CSS variables, Tailwind config, theme providers |
| `spacing-philosophy` | SpacingPhilosophyExtractor | Tailwind spacing, CSS custom properties, design tokens |
| `animation-approach` | AnimationApproachExtractor | Framer Motion, CSS transitions, Tailwind animate |

**Backend Genes (4)**:

| Gene ID | Extractor | Alleles Detected |
|---------|-----------|-----------------|
| `api-response-format` | ApiResponseFormatExtractor | Envelope patterns, direct returns, status codes |
| `error-response-format` | ErrorResponseFormatExtractor | Error classes, error codes, HTTP status mapping |
| `logging-format` | LoggingFormatExtractor | Structured logging, console, winston, pino |
| `config-pattern` | ConfigPatternExtractor | Env vars, config files, dependency injection |

### Key Algorithms

**Gene Building** (per extractor):
```
For each file:
  extractFromFile(filePath, content, imports) -> DetectedAllele[]
  Tally alleleCounts[alleleId]++
  Track alleleFiles[alleleId].add(filePath)
  Collect alleleExamples[alleleId] (up to 5)

Build Gene:
  frequency[allele] = count / totalOccurrences
  Sort alleles by frequency descending
  dominant = top allele if frequency >= 0.3, else null
  confidence = dominant allele frequency (0-1)
  consistency = 0.5 + (dominant - second) * 0.5, clamped [0, 1]
  exemplars = up to 5 files from dominant allele's file set
```

**Health Score** (0-100):
```
healthScore = consistency(40%) + confidence(30%) + mutations(20%) + coverage(10%)
  consistency = avgConsistency * 40
  confidence = avgConfidence * 30
  mutations = (1 - mutationPenalty) * 20
  coverage = dominantCoverage * 10
Result clamped to [0, 100], rounded.
```

**Mutation Detection**:
```
For each gene with a dominant allele:
  For each non-dominant allele:
    For each example of that allele:
      Create Mutation { file, line, gene, expected, actual, impact, suggestion }
Impact classification:
  high: allele frequency < 10% AND dominant frequency > 80%
  medium: allele frequency < 30%
  low: everything else
Sort by impact (high first), then file path.
Mutation ID: SHA-256 hash of file + geneId + alleleId (16 chars)
```

**AI Context Levels**:
| Level | Tokens | Format | Use Case |
|-------|--------|--------|----------|
| 1 | ~20 | One-liner | System prompt injection |
| 2 | ~200 | Markdown table | Quick reference |
| 3 | ~500-2000 | Full sections with code | Code generation |
| 4 | Unlimited | Raw JSON | Maximum detail |

### Persistence

DNAStore writes to `.drift/dna/styling.json`. On each save, appends an EvolutionEntry (timestamp, healthScore, geneticDiversity, changes). Capped at 50 entries (sliding window). Enables health trend analysis and degradation detection.

### Configuration

```
DNAAnalyzerConfig {
  rootDir: string
  componentPaths: ['src/components', 'src/features']
  backendPaths: ['src', 'app', 'api', 'routes', 'handlers', 'controllers', 'services']
  excludePaths: ['**/*.test.*', '**/*.stories.*', '**/index.ts']
  thresholds: DNAThresholds
  verbose: boolean
  mode: 'frontend' | 'backend' | 'all'
}

DNAThresholds {
  dominantMinFrequency: 0.6
  mutationImpactHigh: 0.1
  mutationImpactMedium: 0.3
  healthScoreWarning: 70
  healthScoreCritical: 50
}
```


---

## Subsystem 2: Decision Mining (~15 files)

### What It Is

Mines architectural decisions from git history. Walks commits, extracts semantic signals per language, clusters related changes, and synthesizes Architecture Decision Records (ADRs). The goal: automatically surface "why was this done?" from commit history so teams don't lose institutional knowledge.

### Core Design Principles
1. Decisions are mined, not declared — they emerge from commit patterns
2. Multi-language extraction (5 dedicated extractors + 2 generic)
3. Clustering groups related commits by time, files, and patterns
4. ADRs are synthesized with context, decision, consequences, and evidence
5. Confidence scoring filters noise from signal

### Component Inventory

| Component | File | Purpose |
|-----------|------|---------|
| DecisionMiningAnalyzer | `analyzer/decision-mining-analyzer.ts` | Main orchestrator: walk, extract, cluster, synthesize |
| GitWalker | `git/git-walker.ts` | Traverse git history via simple-git |
| CommitParser | `git/commit-parser.ts` | Parse conventional commits, extract message signals |
| DiffAnalyzer | `git/diff-analyzer.ts` | Analyze diffs for architectural signals, dependency changes |
| BaseCommitExtractor | `extractors/base-commit-extractor.ts` | Abstract base for language extractors |
| TypeScriptCommitExtractor | `extractors/typescript-commit-extractor.ts` | TS/JS semantic extraction |
| PythonCommitExtractor | `extractors/python-commit-extractor.ts` | Python semantic extraction |
| JavaCommitExtractor | `extractors/java-commit-extractor.ts` | Java semantic extraction |
| CSharpCommitExtractor | `extractors/csharp-commit-extractor.ts` | C# semantic extraction |
| PhpCommitExtractor | `extractors/php-commit-extractor.ts` | PHP semantic extraction |
| Types | `types.ts` | 30+ interfaces |

### Mining Pipeline

```
1. Walk git history (GitWalker) -> GitCommit[]
   - Configurable: since, until, maxCommits (default 1000), excludePaths
   - Excludes merge commits by default
   - Returns structured commits with file changes, additions, deletions

2. Semantic extraction per commit (language extractors) -> CommitSemanticExtraction[]
   - Select extractor by file extension
   - Extract: patterns (added/removed/modified), functions (added/removed/modified/renamed),
     dependencies (added/removed/version changes), messageSignals (keywords),
     architecturalSignals (structural changes), significance score (0-1)

3. Cluster related commits -> CommitCluster[]
   - Temporal proximity (commits close in time)
   - File overlap (commits touching same files)
   - Pattern similarity (commits affecting same patterns)
   - Each cluster has ClusterReason[] and similarity score

4. Synthesize decisions from clusters -> MinedDecision[] with ADRs
   - SynthesizedADR: context, decision, consequences, alternatives, references, evidence
```

### Decision Categories (12)

| Category | Description |
|----------|-------------|
| `technology-adoption` | New framework/library added |
| `technology-removal` | Removing a dependency |
| `pattern-introduction` | New coding pattern introduced |
| `pattern-migration` | Changing from one pattern to another |
| `architecture-change` | Structural/architectural changes |
| `api-change` | API modifications (breaking or non-breaking) |
| `security-enhancement` | Security improvements |
| `performance-optimization` | Performance-related changes |
| `refactoring` | Code restructuring without behavior change |
| `testing-strategy` | Changes to testing approach |
| `infrastructure` | Build, deploy, CI/CD changes |
| `other` | Uncategorized |

### Language Extractor Coverage

| Extractor | Languages | Extensions | Dependency Manifest |
|-----------|-----------|------------|---------------------|
| TypeScriptCommitExtractor | TS, JS | .ts, .tsx, .js, .jsx | package.json |
| PythonCommitExtractor | Python | .py | requirements.txt, pyproject.toml |
| JavaCommitExtractor | Java | .java | pom.xml, build.gradle |
| CSharpCommitExtractor | C# | .cs | .csproj |
| PhpCommitExtractor | PHP | .php | composer.json |
| (generic) | Rust | .rs | Cargo.toml (not dedicated) |
| (generic) | C++ | .cpp, .h | CMakeLists.txt (not dedicated) |

### Git Integration

**GitWalker**: Traverses via `simple-git`. Returns GitCommit with sha, subject, body, author, date, files (path, status, additions, deletions), parents, isMerge.

**CommitParser**: Parses conventional commit format (type(scope): subject). Extracts message signals: "breaking", "deprecate", "migrate", "security", etc. Recognizes types: feat, fix, refactor, perf, chore, docs, test, ci, build, style.

**DiffAnalyzer**: Parses diffs into hunks with line-level changes. Detects architectural signals (new modules, moved files, API changes). Analyzes dependency changes across package.json, requirements.txt, pom.xml.

### Key Data Models

```
MinedDecision {
  id, title, status (draft|confirmed|superseded|rejected),
  category (12 types), confidence (high|medium|low),
  cluster: CommitCluster, adr: SynthesizedADR,
  codeLocations: CodeLocation[], tags: string[]
}

SynthesizedADR {
  context, decision, consequences[], alternatives[],
  references: ADRReference[], evidence: ADREvidence[]
}

CommitSemanticExtraction {
  patterns: PatternDelta[], functions: FunctionDelta[],
  dependencies: DependencyDelta[], messageSignals: MessageSignal[],
  architecturalSignals: ArchitecturalSignal[], significance: number
}

DecisionMiningResult {
  decisions: MinedDecision[], summary: DecisionMiningSummary,
  errors: MiningError[], warnings: string[]
}
```


---

## Subsystem 3: Simulation Engine (~15 files)

### What It Is

Pre-flight simulation of code changes. Given a task description (e.g., "add rate limiting to the API"), the engine generates multiple implementation approaches, scores each across 4 dimensions (friction, impact, pattern alignment, security), ranks them, and recommends the best path — all before writing a single line of code. This is an enterprise-licensed feature.

### Core Design Principles
1. Simulate before generating — explore the solution space first
2. Multi-dimensional scoring — no single metric dominates
3. Language-aware strategies — each language/framework gets tailored templates
4. Call-graph-powered impact — real dependency analysis, not guesswork
5. Pattern-aligned — recommendations follow established codebase conventions
6. Graceful degradation — works without call graph (estimates instead)

### Component Inventory

| Component | File | Purpose |
|-----------|------|---------|
| SimulationEngine | `simulation-engine.ts` | Main orchestrator: generate, score, rank, recommend |
| ApproachGenerator | `approach-generator.ts` | Generate candidate implementation approaches |
| FrictionScorer | `scorers/friction-scorer.ts` | Development friction estimation (5 factors) |
| ImpactScorer | `scorers/impact-scorer.ts` | Change blast radius via call graph |
| PatternAlignmentScorer | `scorers/pattern-alignment-scorer.ts` | Pattern compliance scoring |
| SecurityScorer | `scorers/security-scorer.ts` | Security risk assessment |
| TypeScriptStrategies | `language-strategies/typescript-strategies.ts` | Express, NestJS, Fastify templates |
| PythonStrategies | `language-strategies/python-strategies.ts` | FastAPI, Flask, Django templates |
| JavaStrategies | `language-strategies/java-strategies.ts` | Spring Boot, Quarkus templates |
| CSharpStrategies | `language-strategies/csharp-strategies.ts` | ASP.NET Core templates |
| PhpStrategies | `language-strategies/php-strategies.ts` | Laravel, Symfony templates |
| Types | `types.ts` | All type definitions |

### Simulation Pipeline

```
1. Parse task description -> detect category + language + framework
   - Keyword matching with weighted scores against 13 categories
   - Scan project files for primary language
   - Detect framework from imports/decorators

2. Generate candidate approaches (up to maxApproaches, default 5)
   - Query LanguageStrategyProvider for StrategyTemplates
   - Find relevant files matching task category keywords
   - Find relevant patterns from PatternService
   - Create SimulationApproach per template + custom + fallback

3. Score each approach across 4 dimensions (parallel)
   - FrictionScorer.score() -> FrictionMetrics (5 factors)
   - ImpactScorer.score() -> ImpactMetrics (call graph traversal)
   - PatternAlignmentScorer.score() -> PatternAlignmentMetrics
   - SecurityScorer.score() -> SecurityMetrics

4. Compute composite score
   compositeScore = friction*0.30 + impact*0.25 + alignment*0.30 + security*0.15

5. Rank by composite score (highest first)
   - Top approach = recommendation
   - Each approach gets: score breakdowns, rank, reasoning, pros/cons, warnings, next steps

6. Generate tradeoff comparisons between top approaches

7. Calculate confidence based on score gap, alignment strength, data availability
```

### Scoring Dimensions (4)

**Friction Scorer** (weight: 30%):
| Factor | What It Measures |
|--------|------------------|
| Code churn | Lines added + modified, new files created |
| Pattern deviation | How far approach deviates from established patterns |
| Testing effort | Estimated test code needed |
| Refactoring required | Existing code needing restructuring |
| Learning curve | Familiarity with strategy/framework |

**Impact Scorer** (weight: 25%):
- With call graph: traces callers/callees, affected entry points, sensitive data paths, max depth
- Without call graph: estimates based on file count, strategy-specific multipliers
- Risk score (0-100): files(25pts) + entry points(30pts) + sensitive data(30pts) + strategy risk(15pts)
- Risk levels: low(<25), medium(25-49), high(50-74), critical(>=75)
- Breaking change detection: entry points affected, sensitive data paths, distributed changes, depth>5

**Pattern Alignment Scorer** (weight: 30%):
- Queries PatternService for relevant patterns
- Finds aligned patterns (approach matches pattern keywords)
- Finds conflicting patterns (approach contradicts established patterns)
- Calculates alignment score, outlier risk, suggested patterns

**Security Scorer** (weight: 15%):
- Data access implications: which functions access sensitive data
- Auth implications: whether approach affects auth flows
- Warning generation based on strategy + data access + auth impact

### Task Categories (13)

`rate-limiting`, `authentication`, `authorization`, `api-endpoint`, `data-access`, `error-handling`, `caching`, `logging`, `testing`, `validation`, `middleware`, `refactoring`, `generic`

Auto-detected via weighted keyword matching against task description.

### Approach Strategies (15)

`middleware`, `decorator`, `wrapper`, `per-route`, `per-function`, `centralized`, `distributed`, `aspect`, `filter`, `interceptor`, `guard`, `policy`, `dependency`, `mixin`, `custom`

### Language Strategy Coverage

| Language | Frameworks | Strategy Count |
|----------|-----------|----------------|
| TypeScript | Express, NestJS, Fastify | ~15 strategies |
| Python | FastAPI, Flask, Django | ~12 strategies |
| Java | Spring Boot, Quarkus | ~10 strategies |
| C# | ASP.NET Core | ~8 strategies |
| PHP | Laravel, Symfony | ~8 strategies |

### Key Data Models

```
SimulationTask { description, category?, target?, constraints[], scope }
SimulationApproach { id, name, description, strategy, language, framework?,
  targetFiles[], targetFunctions?, newFiles?, followsPatterns?,
  estimatedLinesAdded?, estimatedLinesModified?, template?, frameworkNotes? }
SimulatedApproach { approach, friction, impact, patternAlignment, security,
  compositeScore, rank, reasoning, pros[], cons[], warnings[], nextSteps[] }
SimulationResult { task, approaches[], recommended, summary, tradeoffs[],
  confidence, metadata: { duration, callGraphAvailable, patternsAvailable } }
SimulationConstraint { type, value, description?, required? }
  types: must-work-with, avoid-changing, max-files, pattern-required, framework-required, custom
```


---

## Subsystem 4: Language Intelligence (~15 files)

### What It Is

Cross-language semantic normalization. Makes patterns from different languages comparable by normalizing decorators, functions, and framework constructs to a common semantic model. A `@GetMapping("/users")` in Spring, `@app.get("/users")` in FastAPI, and `@Get("/users")` in NestJS all normalize to the same semantic: `{ category: 'routing', isEntryPoint: true, path: '/users', methods: ['GET'] }`.

### Core Design Principles
1. Raw decorators/annotations are meaningless without semantic context
2. Framework patterns define the mapping from raw to semantic
3. Normalization enables cross-language pattern comparison
4. File-level semantics (controller, service, model, test) derived from function-level
5. Registry pattern enables extensibility (add new frameworks without code changes)

### Component Inventory

| Component | File | Purpose |
|-----------|------|---------|
| LanguageIntelligence | `language-intelligence.ts` | Main orchestrator with cross-language query API |
| BaseLanguageNormalizer | `base-normalizer.ts` | Abstract normalizer base with pipeline |
| TypeScriptNormalizer | `normalizers/typescript-normalizer.ts` | TS/JS normalization (NestJS, Express) |
| PythonNormalizer | `normalizers/python-normalizer.ts` | Python normalization (FastAPI, Flask, Django) |
| JavaNormalizer | `normalizers/java-normalizer.ts` | Java normalization (Spring Boot) |
| CSharpNormalizer | `normalizers/csharp-normalizer.ts` | C# normalization (ASP.NET Core) |
| PhpNormalizer | `normalizers/php-normalizer.ts` | PHP normalization (Laravel, Symfony) |
| FrameworkRegistry | `framework-registry.ts` | Singleton registry for framework patterns |
| Spring Patterns | `frameworks/spring.ts` | Spring Boot decorator mappings |
| FastAPI Patterns | `frameworks/fastapi.ts` | FastAPI decorator mappings |
| NestJS Patterns | `frameworks/nestjs.ts` | NestJS decorator mappings |
| Laravel Patterns | `frameworks/laravel.ts` | Laravel pattern mappings |
| ASP.NET Patterns | `frameworks/aspnet.ts` | ASP.NET attribute mappings |
| Types | `types.ts` | All type definitions |

### Normalization Pipeline

```
1. extractRaw(source, filePath) -> FileExtractionResult
   - Calls existing language-specific call graph extractor
   - Returns raw functions with decorators as strings

2. detectFrameworks(source) -> FrameworkPattern[]
   - Queries FrameworkRegistry for matching frameworks
   - Checks import patterns and decorator patterns against source

3. For each function: normalizeFunction(fn, frameworks)
   a. For each decorator: normalizeDecorator(raw, frameworks)
      - Try FrameworkRegistry.findDecoratorMapping(raw, frameworks)
      - If match: use mapping's semantic info + confidence + argument extraction
      - If no match: category='unknown', confidence=0
   b. Derive function semantics from all normalized decorators:
      - isEntryPoint, isInjectable, isAuthHandler, isTestCase, isDataAccessor
      - requiresAuth, entryPoint (path + methods), dependencies, auth (roles)

4. deriveFileSemantics(functions, frameworks)
   - isController: has entry points
   - isService: has injectables, no entry points
   - isModel: has data accessors, no entry points or injectables
   - isTestFile: has test cases
   - primaryFramework: most-used framework in file
```

### Semantic Categories (12)

`routing`, `di`, `orm`, `auth`, `validation`, `test`, `logging`, `caching`, `scheduling`, `messaging`, `middleware`, `unknown`

### Framework Coverage

**Spring (Java)**: @Controller, @RestController, @RequestMapping, @GetMapping/@PostMapping/etc., @Service, @Repository, @Autowired, @Entity

**FastAPI (Python)**: @app.get/@app.post/etc., @Depends, @Body/@Query/@Path

**NestJS (TypeScript)**: @Controller, @Get/@Post/etc., @Injectable, @Module, @UseGuards

**Laravel (PHP)**: Route::get/Route::post/etc., Route::resource, middleware()

**ASP.NET (C#)**: [ApiController], [HttpGet]/[HttpPost]/etc., [Authorize], [FromBody]/[FromQuery]

### Query API

The LanguageIntelligence class provides cross-language semantic queries:
- `normalizeFile(source, filePath)` — normalize a single file
- `findEntryPoints(results)` — all HTTP endpoints, event handlers, CLI commands
- `findDataAccessors(results, table?)` — all DB read/write functions
- `findInjectables(results)` — all DI services
- `findAuthHandlers(results)` — all auth-related functions
- `findByCategory(results, category)` — query by any of 12 semantic categories
- `query(results, options)` — flexible cross-language query with filters

### Key Data Models

```
NormalizedDecorator { raw, name, language, framework?, semantic: DecoratorSemantics, arguments }
DecoratorSemantics { category, intent, isEntryPoint, isInjectable, requiresAuth, dataAccess?, confidence }
DecoratorArguments { path?, methods?, roles?, [key: string]: unknown }
FunctionSemantics { isEntryPoint, isDataAccessor, isAuthHandler, isTestCase, isInjectable,
  entryPoint?, dependencies[], dataAccess[], auth? }
NormalizedFunction extends FunctionExtraction { normalizedDecorators[], semantics }
NormalizedExtractionResult extends FileExtractionResult {
  functions: NormalizedFunction[], detectedFrameworks[], fileSemantics }
FrameworkPattern { framework, languages[], detectionPatterns, decoratorMappings[] }
DecoratorMapping { pattern: RegExp, semantic, confidence?, extractArgs: (raw) => DecoratorArguments }
```

---

## Cross-Subsystem Integration Points

| Subsystem | Consumes From | Produces For |
|-----------|--------------|-------------|
| **DNA System** | File system (direct reads), Pattern Service (framework detection) | Audit System (health scores), MCP Tools (DNA context), Storage (.drift/dna/) |
| **Decision Mining** | Git history (simple-git), Pattern Service (enrichment), Call Graph (impact) | Cortex Memory (institutional knowledge), MCP Tools (decision queries), Audit (history) |
| **Simulation Engine** | Call Graph (impact analysis), Pattern Service (alignment), Language Intelligence (framework detection) | MCP Tools (simulation results), Quality Gates (pre-merge simulation) |
| **Language Intelligence** | Call Graph extractors (raw extraction), Framework Registry (pattern definitions) | Simulation Engine (framework detection), Detectors (semantic classification), Call Graph (enrichment) |

### Critical Dependency Chain

```
Language Intelligence -> feeds -> Simulation Engine (framework detection)
Language Intelligence -> feeds -> Call Graph (enriched extraction)
Call Graph -> feeds -> Simulation Engine (impact scoring)
Pattern Service -> feeds -> DNA System (framework alignment)
Pattern Service -> feeds -> Simulation Engine (alignment scoring)
Git History -> feeds -> Decision Mining (commit data)
All 4 subsystems -> feed -> MCP Tools (AI consumption)
```

---

## Capabilities

### What Advanced Systems Can Do Today

1. **DNA**: Extract 10 convention genes (6 frontend + 4 backend) with allele frequency analysis
2. **DNA**: Calculate composite health score (0-100) with 4 weighted factors
3. **DNA**: Detect mutations with impact grading (high/medium/low) and fix suggestions
4. **DNA**: Track evolution over time (50-snapshot sliding window)
5. **DNA**: Generate human-readable playbook and AI context at 4 detail levels
6. **Decision Mining**: Walk git history with configurable date ranges and commit limits
7. **Decision Mining**: Extract semantic signals from 5 languages with dedicated extractors
8. **Decision Mining**: Cluster related commits by temporal proximity, file overlap, pattern similarity
9. **Decision Mining**: Synthesize ADRs with context, decision, consequences, alternatives, evidence
10. **Simulation**: Generate multiple implementation approaches for 13 task categories
11. **Simulation**: Score approaches across 4 dimensions with call-graph-powered impact analysis
12. **Simulation**: Provide language-specific strategies for 5 languages and 13 frameworks
13. **Simulation**: Gracefully degrade without call graph (estimation fallbacks)
14. **Language Intelligence**: Normalize decorators/annotations across 5 languages to common semantic model
15. **Language Intelligence**: Detect frameworks from source code (5 frameworks)
16. **Language Intelligence**: Provide cross-language semantic queries (entry points, data accessors, auth handlers)
17. **Language Intelligence**: Classify files semantically (controller, service, model, test)

### Limitations

1. **DNA: Frontend-biased gene set** — 6 frontend genes vs 4 backend. Missing: database access patterns, authentication patterns, testing patterns, dependency injection patterns, middleware patterns
2. **DNA: Regex-only extraction** — No AST-based detection. Misses patterns that don't match simple regex (e.g., complex decorator arguments, multi-line patterns)
3. **DNA: No cross-gene consistency** — Health score treats genes independently. A codebase with consistent patterns across ALL genes should score higher than one with mixed consistency
4. **DNA: No structural fingerprinting** — Only pattern matching, no normalized AST features. Cannot detect similar code with different variable names
5. **DNA: No embedding-based similarity** — Cannot compare codebases or detect cross-project convention drift
6. **DNA: JSON persistence** — No SQLite, no querying, no indexing. Evolution tracking is append-only with no temporal queries
7. **Decision Mining: No Rust/Go/C++ dedicated extractors** — Falls back to generic analysis, missing language-specific patterns
8. **Decision Mining: No ADR detection in documentation** — Only mines from git history, doesn't detect existing ADR documents
9. **Decision Mining: No decision evolution tracking** — Doesn't detect when decisions are later reversed or modified
10. **Decision Mining: simple-git dependency** — Node.js library, not the fastest for large repos (10k+ commits)
11. **Simulation: No test coverage dimension** — Scores friction, impact, alignment, security but not "does this change reduce test coverage?"
12. **Simulation: No complexity dimension** — Doesn't measure cyclomatic complexity change
13. **Simulation: Static strategy templates** — Templates are hardcoded, not learned from the codebase's actual patterns
14. **Simulation: No incremental simulation** — Full simulation every time, no caching of intermediate results
15. **Simulation: Enterprise-only** — Gated behind commercial license, limiting community adoption and feedback
16. **Language Intelligence: Only 5 frameworks** — Missing: Gin, Echo, Fiber (Go), Actix, Axum, Rocket (Rust), Django REST Framework, Quarkus, Micronaut
17. **Language Intelligence: No Go/Rust/C++ normalizers** — Only TS, Python, Java, C#, PHP
18. **Language Intelligence: Decorator-centric** — Doesn't normalize non-decorator patterns (Go struct tags, Rust derive macros, C++ attributes)
19. **Language Intelligence: Singleton registry** — Not thread-safe for concurrent access in Rust migration
20. **All: 100% TypeScript** — No Rust implementation for any compute-heavy path

---

## V2 Migration Status

### Migrates to Rust (compute-heavy paths)
- Gene extraction (10 extractors — all regex-based, perfect Rust candidate)
- Mutation detection (iteration + comparison)
- Health calculation (pure arithmetic)
- Language normalization (pure data transformation)
- Framework detection (regex matching)
- Commit extraction (pattern matching on source text)
- Dependency manifest parsing (JSON, TOML, XML)

### Stays in TypeScript (orchestration + AI)
- DNA orchestrator (lightweight coordination)
- Playbook generator (text templating)
- AI context builder (text templating)
- Decision mining orchestrator (lightweight)
- ADR synthesis (may involve AI)
- Simulation engine orchestrator (lightweight)
- Simulation scorers (call Rust for heavy computation)
- Language strategy templates (static config)
- LanguageIntelligence query API (thin filtering)

### Architectural Decisions Pending
1. Should DNA genes be declarative (TOML/YAML config) or hardcoded Rust structs?
2. Should DNA persistence move from JSON to SQLite for better querying?
3. Should decision mining use git2 (Rust) instead of simple-git (Node.js)?
4. Should simulation strategies be learned from codebase patterns instead of hardcoded?
5. Should Language Intelligence support plugin-based framework registration?
6. How should the 4 subsystems share data (direct calls vs event bus vs shared storage)?

---

## Open Questions

1. **Gene expansion**: What backend genes should be added? Database access, auth, testing, DI, middleware?
2. **Cross-codebase DNA**: Should DNA support comparing fingerprints across multiple codebases?
3. **Decision confidence**: How should confidence scoring be calibrated? What's the false positive rate?
4. **Simulation validation**: How do we measure if simulation recommendations are actually good?
5. **Framework coverage**: Priority order for adding Go, Rust, C++ framework support?
6. **Performance**: What's the target latency for DNA analysis on a 100K-file codebase?
7. **Incremental DNA**: Should DNA support incremental analysis (only re-analyze changed files)?
8. **Decision linking**: Should mined decisions be linked to Cortex memories automatically?
9. **Simulation + Quality Gates**: Should simulation results feed into quality gate scoring?
10. **Language Intelligence + Detectors**: Should normalized semantics feed into pattern detection?

---

## Quality Checklist

- [x] All 19 files in category 13 have been read (4 overviews + 6 DNA + 4 decisions + 5 simulation + 5 language-intelligence)
- [x] Architecture clearly described with diagram
- [x] All 4 subsystems documented with component inventories
- [x] All pipelines documented end-to-end (DNA, Decision Mining, Simulation, Normalization)
- [x] All algorithms documented (gene building, health score, mutation detection, composite scoring, normalization)
- [x] All data models listed with fields
- [x] All configuration options documented
- [x] 20 limitations honestly assessed
- [x] Integration points mapped to other categories
- [x] V2 migration status documented with Rust/TS split
- [x] 10 open questions identified
- [x] Cross-referenced with MASTER-RECAP section 16 and MASTER-RESEARCH section 29