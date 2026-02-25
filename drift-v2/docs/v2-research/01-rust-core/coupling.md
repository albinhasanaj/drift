# Drift Coupling Analyzer Documentation

This document provides comprehensive documentation of Drift's module coupling analysis system, comparing the Rust native implementation with the TypeScript implementation.

## Overview

Drift provides two implementations of module coupling analysis:

1. **Rust Implementation** (`drift/crates/drift-core/src/coupling/`) - High-performance native analyzer exposed via NAPI
2. **TypeScript Implementation** (`drift/packages/core/src/module-coupling/`) - Feature-rich analyzer with advanced analysis capabilities

Both implementations are based on **Robert C. Martin's coupling metrics** (Ca, Ce, Instability, Abstractness, Distance).

---

## Rust Implementation

### File Structure
```
drift/crates/drift-core/src/coupling/
├── mod.rs       # Module exports
├── types.rs     # Type definitions
└── analyzer.rs  # Core analysis logic
```

### Types (`types.rs`)

#### ModuleMetrics
```rust
pub struct ModuleMetrics {
    pub path: String,           // Module path
    pub ca: usize,              // Afferent coupling (incoming dependencies)
    pub ce: usize,              // Efferent coupling (outgoing dependencies)
    pub instability: f32,       // Ce / (Ca + Ce) - 0=stable, 1=unstable
    pub abstractness: f32,      // abstract types / total types
    pub distance: f32,          // |A + I - 1| - distance from main sequence
    pub files: Vec<String>,     // Files in this module
}
```

#### DependencyCycle
```rust
pub struct DependencyCycle {
    pub modules: Vec<String>,       // Modules in the cycle
    pub severity: CycleSeverity,    // Info | Warning | Critical
    pub files_affected: usize,      // Total files affected
}

pub enum CycleSeverity {
    Info,      // 0-2 modules
    Warning,   // 3-4 modules
    Critical,  // 5+ modules
}
```

#### CouplingHotspot
```rust
pub struct CouplingHotspot {
    pub module: String,
    pub total_coupling: usize,  // Ca + Ce
    pub incoming: Vec<String>,
    pub outgoing: Vec<String>,
}
```

#### UnusedExport
```rust
pub struct UnusedExport {
    pub name: String,
    pub file: String,
    pub line: u32,
    pub export_type: String,
}
```

#### CouplingAnalysisResult
```rust
pub struct CouplingAnalysisResult {
    pub modules: Vec<ModuleMetrics>,
    pub cycles: Vec<DependencyCycle>,
    pub hotspots: Vec<CouplingHotspot>,
    pub unused_exports: Vec<UnusedExport>,
    pub health_score: f32,      // 0-100
    pub files_analyzed: usize,
    pub duration_ms: u64,
}
```

#### Internal Graph Types
```rust
pub struct FileGraph {
    pub path: String,
    pub imports: Vec<ImportEdge>,
    pub exports: Vec<ExportNode>,
}

pub struct ImportEdge {
    pub source: String,         // Source file path
    pub symbols: Vec<String>,   // Imported symbols
    pub line: u32,
}

pub struct ExportNode {
    pub name: String,
    pub line: u32,
    pub is_default: bool,
}
```

### Analyzer (`analyzer.rs`)

#### Core Analysis Flow
```rust
pub fn analyze(&mut self, files: &[String]) -> CouplingAnalysisResult {
    // 1. Parse all files via tree-sitter AST
    // 2. Build module map (directory -> files)
    // 3. Calculate module metrics from AST data
    // 4. Detect cycles using DFS
    // 5. Find hotspots (modules with coupling >= 3)
    // 6. Find unused exports
    // 7. Calculate health score
}
```

#### Key Methods

| Method | Description |
|--------|-------------|
| `build_file_graph_from_ast()` | Parses file using tree-sitter, extracts imports/exports |
| `resolve_import()` | Resolves relative import paths |
| `build_module_map()` | Groups files by directory (module) |
| `calculate_module_metrics()` | Computes Ca, Ce, Instability, Abstractness, Distance |
| `detect_cycles()` | DFS-based cycle detection |
| `dfs_cycles()` | Recursive DFS helper for cycle detection |
| `find_hotspots()` | Identifies modules with total coupling >= 3 |
| `find_unused_exports()` | Finds exports never imported elsewhere |
| `calculate_health_score()` | Computes 0-100 health score |

#### Cycle Detection Algorithm

The Rust implementation uses **DFS with recursion stack** for cycle detection:

```rust
fn dfs_cycles(&self, node, deps, visited, rec_stack, path, cycles, module_map) {
    visited.insert(node);
    rec_stack.insert(node);
    path.push(node);
    
    for neighbor in deps[node] {
        if !visited.contains(neighbor) {
            self.dfs_cycles(neighbor, ...);
        } else if rec_stack.contains(neighbor) {
            // Found cycle - extract from path
            let cycle_start = path.position(neighbor);
            let cycle_modules = path[cycle_start..].to_vec();
            cycles.push(DependencyCycle { ... });
        }
    }
    
    path.pop();
    rec_stack.remove(node);
}
```

#### Health Score Calculation
```rust
fn calculate_health_score(&self, modules, cycles) -> f32 {
    let mut score = 100.0;
    
    // Penalize cycles
    for cycle in cycles {
        match cycle.severity {
            Critical => score -= 15.0,
            Warning => score -= 8.0,
            Info => score -= 3.0,
        }
    }
    
    // Penalize high coupling
    for module in modules {
        if module.ca + module.ce > 10 { score -= 2.0; }
        if module.distance > 0.7 { score -= 1.0; }
    }
    
    score.max(0.0).min(100.0)
}
```

### NAPI Bindings

The Rust analyzer is exposed to JavaScript via NAPI:

```rust
#[napi]
pub fn analyze_coupling(files: Vec<String>) -> Result<JsCouplingResult>
```

#### JavaScript Types
```typescript
interface JsModuleMetrics {
    path: string;
    ca: number;
    ce: number;
    instability: number;
    abstractness: number;
    distance: number;
    files: string[];
}

interface JsDependencyCycle {
    modules: string[];
    severity: 'info' | 'warning' | 'critical';
    files_affected: number;
}

interface JsCouplingHotspot {
    module: string;
    total_coupling: number;
    incoming: string[];
    outgoing: string[];
}

interface JsUnusedExport {
    name: string;
    file: string;
    line: number;
    export_type: string;
}

interface JsCouplingResult {
    modules: JsModuleMetrics[];
    cycles: JsDependencyCycle[];
    hotspots: JsCouplingHotspot[];
    unused_exports: JsUnusedExport[];
    health_score: number;
    files_analyzed: number;
    duration_ms: number;
}
```

---

## TypeScript Implementation

### File Structure
```
drift/packages/core/src/module-coupling/
├── index.ts              # Module exports
├── types.ts              # Type definitions
└── coupling-analyzer.ts  # Core analysis logic
```

### Additional Features (vs Rust)

The TypeScript implementation provides significantly more features:

| Feature | Rust | TypeScript |
|---------|------|------------|
| Basic metrics (Ca, Ce, I, A, D) | ✅ | ✅ |
| Cycle detection | ✅ (DFS) | ✅ (Tarjan's SCC) |
| Unused exports | ✅ | ✅ |
| Hotspots | ✅ | ✅ |
| Health score | ✅ | ✅ |
| Module roles | ❌ | ✅ (hub/authority/balanced/isolated) |
| Cycle break suggestions | ❌ | ✅ |
| Refactor impact analysis | ❌ | ✅ |
| Transitive dependencies | ❌ | ✅ |
| Zone of pain/uselessness | ❌ | ✅ |
| Native SQLite queries | ❌ | ✅ |
| Call graph integration | ❌ | ✅ |

### Key Types

#### ModuleRole
```typescript
type ModuleRole = 'hub' | 'authority' | 'balanced' | 'isolated';
```

#### CycleBreakSuggestion
```typescript
interface CycleBreakSuggestion {
    edge: { from: string; to: string };
    rationale: string;
    effort: 'low' | 'medium' | 'high';
    approach: string;
}
```

#### RefactorImpact
```typescript
interface RefactorImpact {
    target: string;
    affectedModules: Array<{
        path: string;
        reason: string;
        effort: BreakEffort;
    }>;
    totalAffected: number;
    risk: 'low' | 'medium' | 'high' | 'critical';
    suggestions: string[];
}
```

### Cycle Detection (Tarjan's Algorithm)

The TypeScript implementation uses **Tarjan's algorithm** for finding strongly connected components:

```typescript
private detectCycles(modules: Map<string, ModuleNode>): DependencyCycle[] {
    // Tarjan's algorithm for strongly connected components
    const index = new Map<string, number>();
    const lowlink = new Map<string, number>();
    const onStack = new Set<string>();
    const stack: string[] = [];
    const sccs: string[][] = [];
    
    const strongConnect = (v: string) => {
        index.set(v, currentIndex);
        lowlink.set(v, currentIndex);
        currentIndex++;
        stack.push(v);
        onStack.add(v);
        
        // ... recursive processing
        
        if (lowlink.get(v) === index.get(v)) {
            // Found SCC - extract from stack
        }
    };
    
    // Process all nodes
    for (const v of modules.keys()) {
        if (!index.has(v)) strongConnect(v);
    }
    
    return sccs
        .filter(scc => scc.length > 1)
        .map((scc, i) => this.createCycle(scc, i, modules));
}
```

### Module Health Calculation
```typescript
private calculateModuleHealth(module, cycles) {
    let score = 100;
    const issues: string[] = [];
    const suggestions: string[] = [];
    
    // Penalize high coupling
    const coupling = module.metrics.Ca + module.metrics.Ce;
    if (coupling > 20) {
        score -= 30;
        issues.push(`Very high coupling (${coupling})`);
    } else if (coupling > 10) {
        score -= 15;
    }
    
    // Penalize cycles
    score -= cycles.length * 10;
    
    // Penalize zone of pain
    if (module.metrics.instability < 0.3 && module.metrics.abstractness < 0.3) {
        score -= 20;
        issues.push('In zone of pain (stable but concrete)');
    }
    
    // Penalize unused exports
    if (module.unusedExports.length > 3) {
        score -= 10;
    }
    
    return { score: Math.max(0, score), issues, suggestions };
}
```

### API Methods

| Method | Description |
|--------|-------------|
| `setCallGraph(callGraph)` | Set call graph for enhanced analysis |
| `build()` | Build the module coupling graph |
| `getGraph()` | Get the built graph |
| `analyzeModule(path)` | Analyze coupling for a specific module |
| `analyzeRefactorImpact(path)` | Analyze impact of refactoring a module |
| `getCycles(options)` | Get all dependency cycles |
| `getHotspots(options)` | Get coupling hotspots |
| `getUnusedExports()` | Get unused exports across all modules |

---

## Comparison Summary

### Rust Strengths
- **Performance**: Native code, faster execution
- **Memory efficiency**: Lower memory footprint
- **Simple API**: Single function call via NAPI

### TypeScript Strengths
- **Feature-rich**: Refactor impact, break suggestions, zone analysis
- **Integration**: Works with call graph and SQLite
- **Flexibility**: Configurable options, multiple analysis methods
- **Actionable insights**: Provides suggestions, not just metrics

### When to Use Which

| Use Case | Recommended |
|----------|-------------|
| Quick coupling scan | Rust |
| CI/CD pipeline checks | Rust |
| Deep refactoring analysis | TypeScript |
| Interactive IDE features | TypeScript |
| Large codebase initial scan | Rust |
| Detailed module investigation | TypeScript |

---

## Robert C. Martin Metrics Reference

### Afferent Coupling (Ca)
Number of modules that depend on this module. High Ca = many dependents = harder to change.

### Efferent Coupling (Ce)
Number of modules this module depends on. High Ce = many dependencies = more reasons to change.

### Instability (I)
```
I = Ce / (Ca + Ce)
```
- I = 0: Maximally stable (hard to change, many dependents)
- I = 1: Maximally unstable (easy to change, no dependents)

### Abstractness (A)
```
A = abstract_types / total_types
```
- A = 0: Completely concrete
- A = 1: Completely abstract

### Distance from Main Sequence (D)
```
D = |A + I - 1|
```
- D = 0: On the main sequence (ideal)
- D = 1: Far from main sequence (problematic)

### Zone of Pain
Modules with low I (stable) and low A (concrete). Hard to change but not abstract enough.

### Zone of Uselessness
Modules with high I (unstable) and high A (abstract). Too abstract for their instability.

---

## Usage Examples

### Rust (via NAPI)
```javascript
const { analyzeCoupling } = require('@drift/native');

const result = analyzeCoupling([
    'src/index.ts',
    'src/utils.ts',
    'src/components/Button.tsx'
]);

console.log(`Health Score: ${result.health_score}`);
console.log(`Cycles Found: ${result.cycles.length}`);
```

### TypeScript
```typescript
import { createModuleCouplingAnalyzer } from '@drift/core';

const analyzer = createModuleCouplingAnalyzer({
    rootDir: './src',
    includeExternal: false,
    granularity: 'file'
});

analyzer.setCallGraph(callGraph);
const graph = analyzer.build();

// Get hotspots
const hotspots = analyzer.getHotspots({ limit: 10, minCoupling: 5 });

// Analyze refactor impact
const impact = analyzer.analyzeRefactorImpact('src/core/utils.ts');
```

---

## v2 Notes

For the Rust-first v2 rebuild:

1. **Port all TS features to Rust**: Module roles, cycle break suggestions, refactor impact analysis, zone detection
2. **Use Tarjan's algorithm**: Replace DFS with Tarjan's SCC for more efficient cycle detection
3. **Add call graph integration**: The TS version's call graph integration is valuable for accurate impact analysis
4. **Keep the NAPI bridge thin**: Expose rich Rust analysis, don't duplicate logic in TS
5. **Consider incremental analysis**: For large codebases, support analyzing only changed modules
