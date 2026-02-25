# 05 Analyzers — Research Recap

## Executive Summary

The Analyzer System is Drift's semantic intelligence layer — a dual-implementation engine (TypeScript orchestration + Rust performance core) comprising 8 distinct analyzer subsystems that transform raw AST data into actionable semantic understanding. The system spans ~15,000 lines of TypeScript across `packages/core/src/` and ~3,000 lines of Rust in `crates/drift-core/src/`, providing four foundational analyzers (AST, Type, Semantic, Flow), five specialized analyzers (Constants, Environment, Wrappers, Module Coupling, Unified Provider), and a sophisticated Rules Engine for violation generation. This category is the computational backbone that powers pattern detection, call graph construction, boundary analysis, and quality gate enforcement — making it the critical bridge between parsing and actionable intelligence.

## Current Implementation

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           PRESENTATION LAYER                                     │
│  MCP Tools │ Quality Gates │ CLI Commands │ LSP Diagnostics │ IDE Integration   │
├─────────────────────────────────────────────────────────────────────────────────┤
│                           RULES ENGINE                                           │
│  Evaluator (900 LOC) → RuleEngine (900 LOC) → SeverityManager (760 LOC)         │
│  VariantManager (1100 LOC) → QuickFixGenerator (1320 LOC, 7 strategies)         │
├─────────────────────────────────────────────────────────────────────────────────┤
│                     UNIFIED LANGUAGE PROVIDER                                    │
│  9 Language Normalizers → 20 ORM/Framework Matchers → Universal Call Chains     │
│  (TS, Python, Java, C#, PHP, Go, Rust, C++)                                     │
├──────────┬──────────┬──────────┬──────────┬──────────────────────────────────────┤
│   AST    │   Type   │ Semantic │   Flow   │     SPECIALIZED ANALYZERS            │
│ Analyzer │ Analyzer │ Analyzer │ Analyzer │                                      │
│ (800 LOC)│(1600 LOC)│(1350 LOC)│(1600 LOC)│  Constants │ Environment │ Wrappers │
│          │          │          │          │  Coupling  │ Language-Specific      │
├──────────┴──────────┴──────────┴──────────┴──────────────────────────────────────┤
│                        RUST CORE (NAPI Bridge)                                   │
│  UnifiedAnalyzer │ CouplingAnalyzer │ ConstantsAnalyzer │ EnvironmentAnalyzer   │
│  WrappersAnalyzer │ SecretDetector (21 patterns) │ ResolutionIndex             │
├─────────────────────────────────────────────────────────────────────────────────┤
│                        TREE-SITTER PARSING LAYER                                 │
│  10 Languages: TS, JS, Python, Java, C#, PHP, Go, Rust, C++, C                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```


### Component Inventory

| Component | Location | LOC (approx) | Language | Purpose |
|-----------|----------|--------------|----------|---------|
| AST Analyzer | `core/src/analyzers/ast-analyzer.ts` | 800 | TS | Structural pattern matching, subtree comparison, traversal |
| Type Analyzer | `core/src/analyzers/type-analyzer.ts` | 1600 | TS | Type extraction, subtyping, compatibility, coverage |
| Semantic Analyzer | `core/src/analyzers/semantic-analyzer.ts` | 1350 | TS | Scope analysis, symbol resolution, reference tracking |
| Flow Analyzer | `core/src/analyzers/flow-analyzer.ts` | 1600 | TS | CFG construction, data flow, unreachable code detection |
| Shared Types | `core/src/analyzers/types.ts` | 830 | TS | ~50 interfaces across all analyzers |
| Constants Analysis | `core/src/constants/` | ~600 | TS | Orchestration, per-language extractors, storage |
| Constants Core | `crates/drift-core/src/constants/` | ~800 | Rust | Secret detection (21 patterns), magic numbers, extraction |
| Environment Analysis | `core/src/environment/` | ~400 | TS | .env parsing, missing variable detection, consistency |
| Environment Core | `crates/drift-core/src/environment/` | ~500 | Rust | Env var extraction, sensitivity classification |
| Wrappers Analysis | `core/src/wrappers/` | ~600 | TS | Clustering, cross-file usage, documentation export |
| Wrappers Core | `crates/drift-core/src/wrappers/` | ~700 | Rust | Wrapper detection, primitive registry, confidence scoring |
| Module Coupling | `core/src/module-coupling/` | ~900 | TS | Cycle detection, refactor impact, break suggestions |
| Coupling Core | `crates/drift-core/src/coupling/` | ~600 | Rust | Basic metrics (Ca, Ce, I, A, D), cycle detection |
| Unified Provider | `core/src/unified-provider/` | ~2500 | TS | 9 normalizers, 20 matchers, universal call chains |
| Unified Core | `crates/drift-core/src/unified/` | ~1700 | Rust | AST patterns, string analysis, resolution index |
| Rules Engine | `core/src/rules/` | ~4900 | TS | Evaluator, severity, variants, quick fixes |
| Language Analyzers | `core/src/{language}/` | ~3000 | TS | Per-language framework-aware extraction |

**Total**: ~22,000+ lines across TypeScript and Rust

---

## Key Algorithms

### 1. AST Pattern Matching (O(n) tree traversal)

The AST Analyzer provides structural pattern matching against tree-sitter ASTs:

```typescript
interface ASTPattern {
  nodeType: string;              // Required tree-sitter node type
  text?: string | RegExp;        // Text content match
  children?: ASTPattern[];       // Child pattern requirements
  minChildren?: number;
  maxChildren?: number;
  hasChild?: string;             // Must have child of this type
  notHasChild?: string;          // Must NOT have child of this type
  depth?: number;                // Expected depth
  metadata?: Record<string, unknown>;
}
```

**Subtree Comparison Algorithm**:
- Compares two AST subtrees structurally
- Returns similarity score (0-1), list of differences, structural equivalence
- Used by pattern detection to find code following the same structural pattern
- Complexity: O(min(n1, n2)) where n1, n2 are subtree sizes

### 2. Type System Analysis (TypeScript-specific)

Full type extraction handling all TypeScript constructs:
- Primitives, references, unions, intersections, arrays, tuples
- Function types, object types, literal types, type parameters
- Generic type arguments, constraints, defaults
- Optional, readonly, exported modifiers

**Type Coverage Calculation**:
```
coverage = typedLocations / totalTypeableLocations
```
Where typeable locations = parameters + return types + variable declarations

**Subtype Checking**: Structural subtyping with variance handling for generics.

### 3. Scope Analysis & Symbol Resolution (O(n) AST walk)

Builds three interconnected structures:
1. **Scope Tree**: Nested scopes (global → module → function → block)
2. **Symbol Table**: All declarations with type, visibility, mutability, references
3. **Reference Resolution**: Links identifier uses to declarations

**Scope Types**: global, module, function, method, class, block, for-loop, if-branch, switch-case, try, catch

**Symbol Collection Sources**:
- Function/arrow/async/generator declarations
- Class declarations with members
- Variable declarations (const/let/var with mutability tracking)
- Destructuring patterns (object and array)
- Import/export declarations
- Interface, type alias, enum declarations

**Resolution Algorithm**:
```
for each identifier reference:
  walk scope chain from current scope to global
  find first matching declaration
  track read vs write reference
  record unresolved if not found
```

### 4. Control Flow Graph Construction (O(n) AST nodes)

Builds CFG with nodes for:
- Entry/exit points
- Statements (expression, declaration, assignment)
- Branches (if/else, switch/case)
- Loops (for, for-in/of, while, do-while)
- Exception handling (try/catch/finally)
- Control transfers (return, throw, break, continue)

**Edge Types**: normal, true-branch, false-branch, exception, break, continue, return, throw

**Data Flow Analysis**:
- Variable definitions (where assigned)
- Variable uses (where read)
- Reaching definitions (which definitions reach each use)
- Null dereference detection

**Issue Detection**:
- Unreachable code (nodes not reachable from entry)
- Infinite loops (loops without break/return)
- Missing returns (functions not returning on all paths)
- Null dereferences (potentially null variables used without check)

### 5. Secret Detection (21 Regex Patterns, Rust)

**Pattern Categories by Severity**:

| Severity | Patterns | Base Confidence |
|----------|----------|-----------------|
| Critical | AWS keys, GitHub tokens, Stripe keys, RSA/SSH/PGP private keys | 0.9 |
| High | Google API keys, passwords, JWTs, DB connections, Slack/SendGrid/Twilio | 0.8 |
| Medium | Hardcoded passwords, bearer tokens, generic API keys, webhooks | 0.6 |

**Confidence Scoring Algorithm**:
```
base = severity_to_base(severity)
adjustments:
  + 0.05 if high entropy (≥3 of: uppercase, lowercase, digit, special)
  + 0.05 if length > 30 chars
confidence = min(base + adjustments, 1.0)
```

**Placeholder Detection** (skips matches containing):
- "example", "placeholder", "your_", "xxx", "todo", "changeme", "replace"

### 6. Module Coupling Metrics (Robert C. Martin)

**Core Metrics**:
```
Ca (Afferent Coupling) = modules that depend on this one
Ce (Efferent Coupling) = modules this one depends on
I (Instability) = Ce / (Ca + Ce)  — 0=stable, 1=unstable
A (Abstractness) = abstract exports / total exports
D (Distance) = |A + I - 1|  — distance from main sequence
```

**Cycle Detection Algorithm** (DFS with recursion stack):
```rust
fn dfs_cycles(node, deps, visited, rec_stack, path, cycles) {
    visited.insert(node);
    rec_stack.insert(node);
    path.push(node);
    
    for neighbor in deps[node] {
        if !visited.contains(neighbor) {
            dfs_cycles(neighbor, ...);
        } else if rec_stack.contains(neighbor) {
            // Found cycle - extract from path
            let cycle_start = path.position(neighbor);
            cycles.push(path[cycle_start..]);
        }
    }
    
    path.pop();
    rec_stack.remove(node);
}
```

**Cycle Severity**: critical (>5 modules), high (>3), medium (>2), low (2)

**TypeScript Enhancements** (not in Rust):
- Module roles: hub, authority, balanced, isolated
- Tarjan's SCC algorithm (more efficient than DFS)
- Break point suggestions with effort estimation
- Refactor impact analysis with transitive dependencies
- Zone of pain/uselessness detection

### 7. Unified Call Chain Normalization

Converts language-specific AST into universal `UnifiedCallChain` format:

```
Source Code → tree-sitter → Language-Specific CST → Normalizer → UnifiedCallChain → Matchers
```

**9 Language Normalizers**: TypeScript, Python, Java, C#, PHP, Go, Rust, C++, base

**20 ORM/Framework Matchers**:
| Category | Matchers |
|----------|----------|
| JavaScript/TypeScript | Supabase, Prisma, TypeORM, Sequelize, Drizzle, Knex, Mongoose |
| Python | Django ORM, SQLAlchemy |
| C# | Entity Framework Core |
| PHP | Laravel Eloquent |
| Java | Spring Data JPA |
| Go | GORM, database/sql |
| Rust | Diesel, SeaORM, SQLx |
| Universal | Raw SQL |

### 8. Wrapper Detection (Rust Core)

**Detection Algorithm**:
```
For each function:
  Extract calls within function's line range
  For each call:
    Check against known primitives registry
    If match found:
      Calculate confidence
      If confidence > 0.5: record as wrapper
```

**Known Primitives Registry**:
| Category | Primitives |
|----------|-----------|
| StateManagement | useState, useReducer |
| SideEffects | useEffect, useLayoutEffect |
| DataFetching | fetch, axios, useSWR, useQuery |
| Validation | zod, yup, joi |
| Logging | console.*, logger.* |
| Authentication | Auth-related primitives |

**Confidence Scoring**:
```
base = 0.6
+ 0.15 if name starts with: use, with, create, make
+ 0.15 if name contains: wrapper, hook, helper
+ 0.10 if custom hook pattern (useXxx)
- 0.10 if total_calls > 10 (complex function)
+ 0.10 if total_calls ≤ 3 (focused wrapper)
confidence = clamp(base + adjustments, 0.0, 1.0)
```

### 9. Rules Engine Evaluation Pipeline

```
Input: EvaluationInput { file, content, ast?, imports, exports }
     + Pattern (from pattern store)

Pipeline:
1. checkMatch(input, pattern) → boolean
2. getMatchDetails(input, pattern) → MatchDetails[]
3. evaluate(input, pattern) → EvaluationResult
   a. Create matcher context
   b. Convert pattern to PatternDefinition
   c. Run pattern matcher → PatternMatchResult[]
   d. Find violations (outliers from established pattern)
   e. Determine severity
   f. Generate quick fixes (if enabled)
4. evaluateAll(input, patterns[]) → EvaluationResult[]
5. evaluateFiles(files[], patterns[]) → EvaluationSummary
```

**Violation Sources**:
1. Outlier locations — statistical deviations from pattern
2. Missing patterns — file should have pattern but doesn't
3. Outlier location details — specific code deviating from expected form

### 10. Quick Fix Generation (7 Strategies)

| Strategy | Purpose | Base Confidence |
|----------|---------|-----------------|
| ReplaceFixStrategy | Replace code at violation range | Pattern confidence |
| WrapFixStrategy | Wrap in try/catch, if-check, function | 0.6 |
| ExtractFixStrategy | Extract into named function/variable | 0.5 |
| ImportFixStrategy | Add missing import statement | 0.7 |
| RenameFixStrategy | Rename to match naming convention | 0.7 |
| MoveFixStrategy | Move code to different location | 0.4 |
| DeleteFixStrategy | Remove unnecessary code | 0.5 |

**Fix Generation Pipeline**:
```
For each registered strategy:
  Check canHandle(violation)
  Calculate confidence
  If confidence >= minConfidence: generate fix
Sort fixes by confidence (highest first)
Return FixGenerationResult
```


---

## Data Models

### Core Analyzer Types

```typescript
// Analysis Context — Input to all analyzers
interface AnalysisContext {
  file: string;
  content: string;
  ast?: Tree;
  language: Language;
  projectContext: ProjectContext;
}

interface ProjectContext {
  rootDir: string;
  files: string[];
  config: DriftConfig;
}

// AST Analysis Result
interface ASTAnalysisResult {
  patterns: PatternMatch[];
  stats: ASTStats;
}

interface ASTStats {
  nodeCount: number;
  depth: number;
  leafCount: number;
  typeDistribution: Map<string, number>;
}

// Type Analysis Result
interface TypeAnalysisResult {
  types: TypeInfo[];
  coverage: TypeCoverageInfo;
  relationships: TypeRelationship[];
}

interface TypeInfo {
  kind: TypeKind;  // primitive|reference|union|intersection|array|tuple|function|object|literal|parameter|unknown
  text: string;
  name?: string;
  members?: TypePropertyInfo[];
  parameters?: TypeInfo[];
  returnType?: TypeInfo;
  elementType?: TypeInfo;
  types?: TypeInfo[];  // union/intersection members
  typeArguments?: TypeInfo[];
  constraint?: TypeInfo;
  defaultType?: TypeInfo;
  isOptional?: boolean;
  isReadonly?: boolean;
  isExported?: boolean;
}

interface TypeCoverageInfo {
  totalLocations: number;
  typedCount: number;
  untypedCount: number;
  percentage: number;
}

// Semantic Analysis Result
interface SemanticAnalysisResult {
  scopes: ScopeInfo[];
  symbols: SymbolInfo[];
  references: SymbolReference[];
  unresolvedReferences: SymbolReference[];
  shadowedVariables: ShadowedVariable[];
  errors: AnalysisError[];
}

interface ScopeInfo {
  id: string;
  type: ScopeType;  // global|module|function|method|class|block|for|if|switch|try|catch
  parent?: string;
  children: string[];
  symbols: string[];
  references: string[];
}

interface SymbolInfo {
  name: string;
  kind: SymbolKind;  // function|class|variable|parameter|property|method|interface|type|enum
  visibility: Visibility;  // public|private|protected|internal
  mutability: Mutability;  // const|let|var|mutable
  type?: TypeInfo;
  decorators?: DecoratorInfo[];
  references: SymbolReference[];
}

// Flow Analysis Result
interface FlowAnalysisResult {
  cfg: ControlFlowGraph;
  dataFlow: DataFlowInfo;
  unreachableCode: SourceLocation[];
  infiniteLoops: SourceLocation[];
  missingReturns: SourceLocation[];
  nullDereferences: SourceLocation[];
}

interface ControlFlowGraph {
  nodes: ControlFlowNode[];
  edges: ControlFlowEdge[];
  entry: string;
  exit: string;
}

interface ControlFlowNode {
  id: string;
  type: CFGNodeType;  // entry|exit|statement|branch|loop|exception|return|throw
  location: SourceLocation;
  predecessors: string[];
  successors: string[];
}

interface ControlFlowEdge {
  from: string;
  to: string;
  type: EdgeType;  // normal|true-branch|false-branch|exception|break|continue|return|throw
}

interface DataFlowInfo {
  definitions: VariableDefinition[];
  uses: VariableUse[];
  reachingDefinitions: Map<string, Set<string>>;
}
```

### Rust Core Types

```rust
// Constants Analysis
struct ConstantInfo {
    name: String,
    value: String,
    category: ConstantCategory,
    file: String,
    line: u32,
    language: Language,
    is_exported: bool,
}

struct SecretCandidate {
    name: String,
    masked_value: String,
    secret_type: String,
    severity: SecretSeverity,  // Critical|High|Medium|Low|Info
    file: String,
    line: u32,
    confidence: f32,
    reason: String,
}

struct MagicNumber {
    value: f64,
    file: String,
    line: u32,
    context: String,
    suggested_name: Option<String>,
}

struct InconsistentValue {
    name_pattern: String,
    values: Vec<ValueLocation>,
    severity: Severity,
}

// Environment Analysis
struct EnvAccess {
    variable_name: String,
    file: String,
    line: u32,
    access_method: String,  // "process.env", "os.environ", "getenv", etc.
    has_default: bool,
    default_value: Option<String>,
    sensitivity: EnvSensitivity,  // Public|Internal|Secret|Critical
}

struct EnvVariable {
    name: String,
    accesses: Vec<EnvAccessLocation>,
    sensitivity: EnvSensitivity,
    has_default_anywhere: bool,
    access_count: usize,
}

// Wrappers Analysis
struct WrapperInfo {
    name: String,
    file: String,
    line: u32,
    wraps: Vec<String>,
    category: WrapperCategory,
    is_exported: bool,
    usage_count: u32,
    confidence: f32,
}

struct WrapperCluster {
    name: String,
    category: WrapperCategory,
    wrappers: Vec<WrapperInfo>,
    total_usage: u32,
}

// Module Coupling
struct ModuleMetrics {
    path: String,
    ca: usize,              // Afferent coupling
    ce: usize,              // Efferent coupling
    instability: f32,       // Ce / (Ca + Ce)
    abstractness: f32,
    distance: f32,          // |A + I - 1|
    files: Vec<String>,
}

struct DependencyCycle {
    modules: Vec<String>,
    severity: CycleSeverity,  // Info|Warning|Critical
    files_affected: usize,
}

struct CouplingHotspot {
    module: String,
    total_coupling: usize,
    incoming: Vec<String>,
    outgoing: Vec<String>,
}

// Unified Analysis
struct DetectedPattern {
    category: PatternCategory,
    pattern_type: String,
    subcategory: Option<String>,
    file: String,
    line: u32,
    column: u32,
    end_line: u32,
    end_column: u32,
    matched_text: String,
    confidence: f32,
    detection_method: DetectionMethod,  // AstQuery|RegexFallback|Structural
    metadata: Option<HashMap<String, Value>>,
}

struct UnifiedResult {
    file_patterns: Vec<FilePatterns>,
    resolution: ResolutionStats,
    call_graph: CallGraphSummary,
    metrics: AnalysisMetrics,
    total_patterns: u64,
    total_violations: u64,
}
```

### Rules Engine Types

```typescript
// Violation — Actionable feedback
interface Violation {
  id: string;
  patternId: string;
  patternName: string;
  category: PatternCategory;
  severity: Severity;  // error|warning|info|hint
  message: string;
  file: string;
  range: Range;
  expected: string;
  actual: string;
  quickFixes?: QuickFix[];
  source: string;  // 'drift'
  code?: string;
}

// Quick Fix
interface QuickFix {
  title: string;
  fixType: FixType;  // replace|wrap|extract|import|rename|move|delete
  edit: WorkspaceEdit;
  isPreferred: boolean;
  confidence: number;
  preview?: string;
}

interface WorkspaceEdit {
  changes: DocumentChange[];
}

interface DocumentChange {
  file: string;
  edits: TextEdit[];
}

interface TextEdit {
  range: Range;
  newText: string;
}

// Severity Configuration
interface SeverityConfig {
  defaultSeverity: Severity;
  categoryDefaults: Map<PatternCategory, Severity>;
  patternOverrides: Map<string, Severity>;
  escalationRules: SeverityEscalationRule[];
}

interface SeverityEscalationRule {
  condition: 'count' | 'category' | 'pattern' | 'file';
  threshold?: number;
  category?: PatternCategory;
  pattern?: string;  // regex
  file?: string;     // glob
  escalateTo: Severity;
}

// Variant (Scoped Override)
interface PatternVariant {
  id: string;
  patternId: string;
  scope: VariantScope;  // global|directory|file
  scopePath?: string;
  severityOverride?: Severity;
  enabledOverride?: boolean;
  configOverride?: Record<string, unknown>;
  expiresAt?: string;
  createdAt: string;
  updatedAt: string;
}
```


---

## Per-Language Analyzer Coverage

### Language Analyzer Inventory

| Language | Directory | Key Frameworks | Extraction Capabilities |
|----------|-----------|----------------|------------------------|
| TypeScript/JS | `typescript/` | Express, React, Next.js, NestJS, Fastify | Routes, components, hooks, error patterns, data access, decorators |
| Python | `python/` | Django, Flask, FastAPI, SQLAlchemy | Routes, error handling, data access, decorators, async patterns |
| Java | `java/` | Spring Boot, JPA, Hibernate | Spring routes, JPA entities, annotations |
| C# | (via unified-provider) | ASP.NET, Entity Framework | Attributes, EF entities, controllers |
| PHP | `php/` | Laravel, Symfony | Routes, Eloquent models, middleware |
| Go | `go/` | Gin, Echo, GORM, standard library | HTTP handlers, error patterns, interfaces, goroutines |
| Rust | `rust/` | Actix, Axum, Diesel, SeaORM | Route macros, Result patterns, traits, async |
| C++ | `cpp/` | STL, Qt, Boost | Classes, memory patterns, templates, virtual methods |
| WPF/XAML | `wpf/` | WPF, MVVM | XAML parsing, ViewModel linking, binding analysis |

### WPF/XAML Analyzer (Most Complex)

The WPF analyzer is the most sophisticated language analyzer (~8 files):

```
wpf/
├── wpf-analyzer.ts              # Main analyzer
├── types.ts                     # WPF-specific types
├── extractors/
│   ├── XamlHybridExtractor      # XAML parsing (tree-sitter + regex)
│   ├── ViewModelHybridExtractor # ViewModel extraction
│   └── CodeBehindLinker         # Links .xaml to .xaml.cs
├── linkers/
│   ├── DataContextResolver      # Resolves DataContext bindings
│   └── ViewModelLinker          # Links Views to ViewModels
└── integration/
    └── Call graph integration    # WPF-aware call graph
```

**Unique Capabilities**:
- Parses XAML as tree-sitter grammar (with regex fallback)
- Resolves `{Binding Path}` expressions to ViewModel properties
- Detects MVVM violations (code-behind with business logic)
- Traces data flow through XAML bindings to ViewModel properties
- Detects broken bindings (property doesn't exist on ViewModel)

---

## Capabilities

### What It Can Do Today

1. **Structural Pattern Matching**: AST-based pattern matching with subtree comparison, depth constraints, child requirements
2. **Full Type System Analysis**: TypeScript type extraction, subtyping, compatibility checking, coverage metrics
3. **Scope & Symbol Resolution**: Complete scope tree construction, symbol table building, reference resolution
4. **Control Flow Analysis**: CFG construction, data flow tracking, unreachable code detection, null dereference detection
5. **Secret Detection**: 21 regex patterns across 5 severity levels with confidence scoring and placeholder filtering
6. **Magic Number Detection**: Context-aware detection with suggested constant names
7. **Environment Variable Analysis**: Cross-language extraction, sensitivity classification, .env cross-referencing
8. **Wrapper Detection**: Framework primitive wrapping detection with clustering and usage counting
9. **Module Coupling Analysis**: Robert C. Martin metrics (Ca, Ce, I, A, D), cycle detection, hotspot identification
10. **Unified Call Chain Normalization**: 9 language normalizers, 20 ORM matchers, universal representation
11. **Rules Engine**: Pattern evaluation, violation generation, severity management, variant scoping
12. **Quick Fix Generation**: 7 fix strategies with confidence scoring and preview generation
13. **9 Language Support**: TypeScript, JavaScript, Python, Java, C#, PHP, Go, Rust, C++
14. **20 ORM/Framework Matchers**: Comprehensive data access pattern detection across ecosystems

### Limitations

1. **Dual Implementation Overhead**: Many analyzers exist in both Rust and TypeScript with feature gaps between them
2. **TypeScript Performance**: Core analyzers (AST, Type, Semantic, Flow) are 100% TypeScript — slow for large codebases
3. **No Incremental Analysis**: Full re-analysis on every scan; no caching of analyzer results
4. **Type Analyzer is TS-Only**: No Rust implementation; blocks type analysis for non-TS languages
5. **Semantic Analyzer Scope**: Only handles TypeScript/JavaScript; other languages lack scope analysis
6. **Flow Analyzer Limitations**: CFG construction is basic; no interprocedural analysis
7. **Secret Detection Gaps**: Missing Azure, GCP, npm, PyPI token patterns
8. **Magic Number Detection**: Line-level regex, not AST-based; misses context
9. **Wrapper Detection React-Focused**: Primitive registry lacks Vue, Angular, Svelte, Express middleware
10. **Coupling Analysis Feature Gap**: Rust version missing refactor impact, break suggestions, zone detection
11. **Unified Provider TS-Only**: 20 ORM matchers are TypeScript; Rust has ~30 AST patterns total
12. **Rules Engine Not Parallelized**: Sequential evaluation; no multi-threaded execution
13. **Quick Fix Limited Coverage**: Many violation types lack auto-fix support
14. **No Cross-File Data Flow**: Data flow analysis is intraprocedural only
15. **No Taint Tracking**: Security analysis lacks taint propagation
16. **WPF Analyzer Isolated**: Doesn't integrate with other analyzers for cross-platform analysis

---

## Integration Points

| Connects To | Direction | How |
|-------------|-----------|-----|
| **02-parsers** | Consumes | AST input via tree-sitter; ParseResult with functions, classes, imports, exports |
| **03-detectors** | Produces | Analyzers provide semantic context for pattern detection |
| **04-call-graph** | Bidirectional | Flow analyzer feeds CFG; call graph provides cross-file context |
| **01-rust-core** | Parallel | Rust analyzers run alongside TS; NAPI bridge for results |
| **07-mcp** | Produces | Analysis results exposed via MCP tools (drift_coupling, drift_constants) |
| **09-quality-gates** | Produces | Type coverage gate uses Type Analyzer; coupling gate uses Coupling Analyzer |
| **08-storage** | Produces | Analysis results persisted to .drift/ directories |
| **21-security** | Produces | Secret detection feeds security boundary analysis |
| **25-services-layer** | Consumed by | Scan pipeline orchestrates analyzer execution |

### Critical Data Flow

```
Parsers → AST Analyzer → Pattern Detection
       → Type Analyzer → Type Coverage Gates
       → Semantic Analyzer → Symbol Resolution → Call Graph
       → Flow Analyzer → CFG → Error Handling Analysis
       
Constants Analyzer → Secret Detection → Security Boundaries
Environment Analyzer → Config Validation → Missing Var Detection
Wrappers Analyzer → Pattern Store → Convention Learning
Coupling Analyzer → Quality Gates → Refactor Impact
Unified Provider → Call Graph → Data Access Boundaries
Rules Engine → Violations → IDE Diagnostics + CI Checks
```

---

## V2 Migration Status

### Current State: Fragmented Dual Implementation

```
TypeScript (Full Features)              Rust (Performance Core)
├── AST Analyzer (800 LOC)              ├── Unified Analyzer (~1700 LOC)
├── Type Analyzer (1600 LOC)            │   ├── ~30 AST patterns
├── Semantic Analyzer (1350 LOC)        │   ├── String regex fallback
├── Flow Analyzer (1600 LOC)            │   └── Resolution index
├── Unified Provider (~2500 LOC)        ├── Coupling Analyzer (~600 LOC)
│   ├── 9 normalizers                   │   └── Basic metrics only
│   └── 20 ORM matchers                 ├── Constants Analyzer (~800 LOC)
├── Module Coupling (~900 LOC)          │   └── 21 secret patterns
│   ├── Tarjan's SCC                    ├── Environment Analyzer (~500 LOC)
│   ├── Refactor impact                 └── Wrappers Analyzer (~700 LOC)
│   └── Break suggestions                   └── Basic detection only
├── Rules Engine (~4900 LOC)            
│   ├── Evaluator                       
│   ├── Severity manager                
│   ├── Variant manager                 
│   └── Quick fix generator             
└── Language Analyzers (~3000 LOC)      
    └── 9 languages                     
```

### What Must Migrate to Rust (Priority Order)

| Priority | Component | Rationale | Effort |
|----------|-----------|-----------|--------|
| P0 | AST Analyzer | Hot path — called per-file; tree-sitter queries native to Rust | Medium |
| P0 | Type Analyzer | 1600 LOC of pure computation; blocks type analysis for all languages | High |
| P0 | Semantic Analyzer | Symbol resolution critical for call graph accuracy | High |
| P1 | Flow Analyzer | CFG construction is algorithmic; benefits from Rust performance | High |
| P1 | Unified Provider Matchers | 20 ORM matchers are pure data transformation | High |
| P1 | Rules Engine Evaluator | Core evaluation loop; quick fixes can stay TS | Medium |
| P2 | Coupling Enhancements | Port Tarjan's SCC, refactor impact, break suggestions | Medium |
| P2 | Language Analyzers | Large surface area; migrate incrementally by language | Very High |
| P3 | Quick Fix Generator | Presentation layer; can stay TS longer | Low |
| P3 | Variant Manager | Configuration/persistence; stays TS | Low |

### Architectural Decisions Pending

1. **Analyzer Registration**: Should Rust own analyzer registry, or TS orchestrate which Rust analyzers run?
2. **Type System Generalization**: How to extend Type Analyzer beyond TypeScript to other typed languages?
3. **Scope Analysis Generalization**: How to provide semantic analysis for Python, Java, Go, etc.?
4. **CFG Standardization**: Should CFG format be language-agnostic for cross-language flow analysis?
5. **Unified Provider Architecture**: Should normalizers become Rust traits with per-language implementations?
6. **Rules Engine Split**: Which parts stay TS (orchestration) vs. move to Rust (evaluation)?
7. **Incremental Analysis**: How to cache analyzer results for unchanged files?

---

## Open Questions

1. **Type Analyzer Generalization**: Can the TypeScript type analyzer be generalized for Java, C#, Go type systems?
2. **Semantic Analyzer Scope**: Should scope analysis be language-specific or use a generic scope model?
3. **Flow Analyzer Interprocedural**: Is interprocedural data flow analysis planned for v2?
4. **Secret Pattern Expansion**: What additional secret patterns are needed (Azure, GCP, npm, PyPI)?
5. **Wrapper Registry Expansion**: Should the primitive registry be configurable/extensible?
6. **Coupling Rust Parity**: When will Rust coupling analyzer get Tarjan's SCC and refactor impact?
7. **Unified Provider Rust Migration**: What's the strategy for migrating 20 ORM matchers to Rust?
8. **Rules Engine Performance**: Should evaluation be parallelized before Rust migration?
9. **Quick Fix Coverage**: What percentage of violations should have auto-fixes in v2?
10. **Cross-File Analysis**: Is cross-file data flow / taint tracking planned?

---

## Quality Checklist

- [x] All analyzer files have been read and documented
- [x] Architecture is clearly described with diagram
- [x] All 10 key algorithms documented with complexity analysis
- [x] All data models listed with field descriptions
- [x] All 9 language analyzers inventoried
- [x] 16 limitations honestly assessed
- [x] 9 integration points mapped to other categories
- [x] V2 migration status documented with priority ordering
- [x] 10 open questions identified
- [x] Rust vs TypeScript feature gaps documented
