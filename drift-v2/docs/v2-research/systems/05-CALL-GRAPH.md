# Call Graph Builder — Research & Decision Guide

> System: Function→function edges across entire codebase
> Hierarchy: Level 1 — Structural Skeleton
> Dependencies: Parsers, Storage
> Consumers: Reachability, impact analysis, dead code, taint, error handling, test topology, N+1 detection, contracts, simulation, constraints

---

## What This System Does

The call graph maps which functions call which other functions across the entire codebase. It's the highest-leverage Level 1 system — ~10 downstream systems depend on it. Without the call graph, Drift can detect patterns but can't answer "what happens if this changes?" or "can user input reach this SQL query?"

---

## Key Decision: In-Memory Graph Library

### petgraph (StableGraph) — RECOMMENDED

`petgraph` is the standard Rust graph library. `StableGraph` variant maintains stable node/edge indices even after removals (important for incremental updates).

```rust
use petgraph::stable_graph::StableGraph;
use petgraph::Directed;

type CallGraph = StableGraph<FunctionNode, CallEdge, Directed>;

struct FunctionNode {
    id: Spur,              // interned function ID
    file: Spur,            // interned file path
    line: u32,
    is_entry_point: bool,
    is_exported: bool,
}

struct CallEdge {
    resolution: Resolution,
    confidence: f64,
    call_site_line: u32,
}

enum Resolution {
    SameFile,       // High confidence
    MethodCall,     // High
    DiInjection,    // Medium-High
    ImportBased,    // Medium
    ExportBased,    // Medium
    Fuzzy,          // Low
}
```

Why StableGraph:
- Node/edge indices are stable across removals (NodeIndex is never reused)
- Supports directed graphs with parallel edges
- BFS/DFS iterators built in
- Petgraph is the most widely used graph library in Rust (100M+ downloads)

### Alternative: Custom Adjacency List

For maximum performance, a custom adjacency list with arena allocation could be faster. But petgraph is well-optimized and the graph operations (BFS, path finding) are already implemented.

**Decision**: petgraph StableGraph. Don't reinvent graph algorithms.

---

## Key Decision: Build Pipeline

### The Pattern: Rayon + MPSC Channel + Batch Writer

```
Files (rayon par_iter)
  → Parse (thread-local parser)
    → Extract call sites (per-language extractor)
      → MPSC channel (bounded, backpressure)
        → Batch writer thread (SQLite, 500 per transaction)
```

```rust
use rayon::prelude::*;
use crossbeam_channel::bounded;

fn build_call_graph(files: &[PathBuf], db: &DatabaseManager) -> CallGraphStats {
    let (tx, rx) = bounded(4 * num_cpus::get());
    
    // Writer thread
    let writer = std::thread::spawn(move || {
        let mut batch = Vec::with_capacity(500);
        // ... batch write to SQLite
    });
    
    // Parallel extraction
    files.par_iter().for_each(|file| {
        let parse_result = parse_file(file);
        let call_sites = extract_calls(&parse_result);
        for site in call_sites {
            tx.send(site).unwrap();
        }
    });
    
    drop(tx); // signal writer to finish
    writer.join().unwrap()
}
```

Custom rayon pool with `num_cpus - 1` threads (leave one core for the writer thread and OS).

---

## Key Decision: Resolution Strategies

The 6 resolution strategies from the audit, ordered by confidence:

### 1. Same-File (High Confidence)
Function defined in the same file as the call site. Trivial to resolve — just match names within the file's function list.

### 2. Method Call (High Confidence)
Resolved via class/receiver type. If `obj.method()` is called and `obj`'s type is known (from declaration or import), resolve to that class's method.

From audit A5 (PyCG approach): follow class hierarchy MRO (Method Resolution Order) for Python. Similar approach for Java/C# inheritance chains.

### 3. DI Injection (Medium-High)
Framework-specific dependency injection patterns:
- FastAPI: `Depends(service_function)`
- Spring: `@Autowired`, `@Inject`
- NestJS: `@Inject()`, constructor injection
- Laravel: type-hinted constructor parameters

These require framework detection (from the parser's FrameworkExtractor) to identify injection points.

### 4. Import-Based (Medium)
Follow import chains. If `import { foo } from './utils'` and `utils.ts` exports `foo`, resolve the call to `foo` in `utils.ts`.

### 5. Export-Based (Medium)
Match exported names across files. Less precise than import-based because it doesn't follow the import chain — just matches by name among all exports.

### 6. Fuzzy (Low)
Name similarity for dynamic calls. Last resort. Useful for dynamic dispatch patterns where the exact target can't be determined statically.

### Unified Resolution Algorithm

Don't implement per-language resolution variants. Instead:
1. Normalize all call sites to a common representation (caller, callee_name, receiver_type, import_path)
2. Run resolution strategies in order of confidence
3. First match wins (highest confidence)
4. Track resolution confidence on each edge

**Target resolution rate**: 60-85% (from audit). This is realistic for static analysis without type inference.

---

## Key Decision: SQLite Storage Schema

```sql
CREATE TABLE functions (
    id TEXT PRIMARY KEY,           -- interned qualified name
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    is_entry_point INTEGER NOT NULL DEFAULT 0,
    is_exported INTEGER NOT NULL DEFAULT 0,
    signature_hash BLOB,
    body_hash BLOB,
    language TEXT NOT NULL
) STRICT;

CREATE TABLE call_edges (
    caller_id TEXT NOT NULL REFERENCES functions(id),
    callee_id TEXT NOT NULL REFERENCES functions(id),
    resolution TEXT NOT NULL,      -- same_file, method_call, etc.
    confidence REAL NOT NULL,
    call_site_line INTEGER NOT NULL,
    PRIMARY KEY (caller_id, callee_id, call_site_line)
) STRICT;

CREATE TABLE data_access (
    function_id TEXT NOT NULL REFERENCES functions(id),
    table_name TEXT NOT NULL,
    operation TEXT NOT NULL,        -- select, insert, update, delete
    framework TEXT,
    line INTEGER NOT NULL
) STRICT;

-- Indexes for common queries
CREATE INDEX idx_call_edges_callee ON call_edges(callee_id);
CREATE INDEX idx_call_edges_caller ON call_edges(caller_id);
CREATE INDEX idx_functions_file ON functions(file);
CREATE INDEX idx_functions_entry ON functions(is_entry_point) WHERE is_entry_point = 1;
CREATE INDEX idx_data_access_table ON data_access(table_name);
CREATE INDEX idx_data_access_function ON data_access(function_id);
```

### Dual Storage: petgraph + SQLite

- **petgraph (in-memory)**: For fast BFS/DFS traversals during analysis (reachability, impact, taint)
- **SQLite**: For persistence across restarts and complex queries (join with patterns, filter by file)

On startup: load from SQLite into petgraph. After scan: write new edges to SQLite, rebuild petgraph.

For very large codebases (500K+ files), the in-memory graph may be too large. The audit mentions a SQLite-backed BFS engine using recursive CTEs as a fallback:

```sql
-- Forward reachability via recursive CTE
WITH RECURSIVE reachable(id, depth) AS (
    SELECT callee_id, 1 FROM call_edges WHERE caller_id = :start
    UNION
    SELECT e.callee_id, r.depth + 1
    FROM call_edges e JOIN reachable r ON e.caller_id = r.id
    WHERE r.depth < :max_depth
)
SELECT * FROM reachable;
```

---

## Key Decision: Entry Point Detection

Entry points are functions that can be called from outside the codebase (HTTP handlers, CLI commands, exported APIs). They're critical for:
- Reachability analysis (start BFS from entry points)
- Impact analysis (how many entry points are affected?)
- Security analysis (which entry points reach sensitive data?)

Detection heuristics:
1. Route decorators (`@app.get("/users")`, `@GetMapping`, `@Route`)
2. Controller classes (classes in `controllers/` or with `Controller` suffix)
3. Exported handlers (`export function handler()`, `module.exports`)
4. Main functions (`fn main()`, `if __name__ == "__main__"`)
5. Framework-specific patterns (Express `app.use()`, Spring `@RestController`)

---

## Key Decision: Incremental Updates

When a single file changes:
1. Remove all edges where caller or callee is in the changed file
2. Re-extract call sites from the changed file
3. Re-resolve edges for the changed file
4. Cross-file edges from OTHER files calling into the changed file are preserved (they depend on the callee's signature, not body — per the body_hash optimization)

This is O(edges_in_changed_file), not O(total_edges).

---

## Summary of Decisions

| Decision | Choice | Confidence |
|----------|--------|------------|
| Graph library | petgraph StableGraph | High |
| Build pipeline | rayon + crossbeam channel + batch writer | High |
| Resolution | 6 strategies, unified algorithm, highest-confidence-first | High |
| Storage | Dual: petgraph (in-memory) + SQLite (persistent) | High |
| Large codebase fallback | SQLite recursive CTEs for BFS | Medium |
| Entry point detection | 5 heuristic categories | High |
| Incremental | Remove + re-extract edges for changed files only | High |
