# Call Graph Builder — V2 Implementation Prep

> Comprehensive build specification for Drift v2's call graph subsystem.
> Synthesized from: 05-CALL-GRAPH.md, DRIFT-V2-FULL-SYSTEM-AUDIT.md (Cat 04, A5, AD1, AD12),
> DRIFT-V2-STACK-HIERARCHY.md (Level 1 — Structural Skeleton), PLANNING-DRIFT.md (D1-D7),
> 01-PARSERS.md (ParseResult, FunctionInfo, CallSite, ImportInfo, ExportInfo, ClassInfo),
> 02-STORAGE-V2-PREP.md (batch writer, keyset pagination, medallion architecture),
> 03-NAPI-BRIDGE-V2-PREP.md (command/query pattern, async tasks, cancellation),
> 04-INFRASTRUCTURE.md (thiserror, tracing, DriftEventHandler, FxHashMap, SmallVec, lasso),
> .research/04-call-graph/RECOMMENDATIONS.md (A5: PyCG MRO, accuracy benchmarking,
> cross-service reachability, reachability caching),
> and internet validation of petgraph, rayon, and crossbeam crate choices.
>
> Purpose: Everything needed to build the call graph from scratch. Decisions resolved,
> inconsistencies flagged, interface contracts defined, build order specified.
> Generated: 2026-02-07

---

## 1. Architectural Position

The call graph builder is Level 1 — Structural Skeleton. It is the highest-leverage system
at this level: ~10 downstream systems depend on it. Without the call graph, Drift can detect
patterns but cannot answer "what happens if this changes?", "can user input reach this SQL
query?", "which tests cover this function?", or "is this function dead code?"

Per PLANNING-DRIFT.md D1: Drift is standalone. The call graph writes to drift.db only.
Per PLANNING-DRIFT.md D7: The grounding feedback loop reads call graph data from drift.db
via ATTACH — but the call graph has zero knowledge of Cortex.

### What Lives Here
- Per-language call site extraction from ParseResult (9 languages)
- 6 resolution strategies (same-file → method call → DI → import → export → fuzzy)
- petgraph StableGraph in-memory representation
- SQLite persistence (functions, call_edges, data_access tables in drift.db)
- Parallel build pipeline (rayon + crossbeam channel + batch writer)
- Entry point detection (5 heuristic categories)
- Incremental updates (O(edges_in_changed_file), not O(total_edges))
- String interning for function IDs and file paths (lasso)

### What Does NOT Live Here
- Reachability analysis (separate engine, consumes call graph)
- Impact analysis (separate engine, consumes call graph)
- Taint analysis (separate engine, consumes call graph + boundaries)
- Dead code detection (separate engine, consumes call graph)
- Test topology coverage mapping (separate engine, consumes call graph)
- Error handling propagation (separate engine, consumes call graph)
- N+1 query detection (separate engine, consumes call graph + ORM patterns)
- Constraint verification for must_precede/must_follow (separate engine)
- Simulation engine (separate engine, consumes call graph)
- Cross-service reachability (separate engine, consumes call graph + contracts)

### Downstream Consumers (All Depend on Call Graph)

| Consumer | What It Reads | Why |
|----------|--------------|-----|
| Reachability Engine | Forward/inverse BFS on edges | "Can user input reach this SQL query?" |
| Impact Analyzer | Transitive caller analysis | "What breaks if I change this function?" |
| Dead Code Detector | Unreachable functions from entry points | "Which functions are never called?" |
| Taint Analysis | Call paths + data_access table | Source→sink tracking across functions |
| Test Topology | Call graph × test functions | "Which tests cover this function?" |
| Error Handling | Propagation chains via call edges | "Where do thrown errors get caught?" |
| N+1 Detection | Call graph + ORM patterns in loops | "Is this query inside a loop?" |
| Constraint Verifier | must_precede/must_follow ordering | "Does A always happen before B?" |
| Simulation Engine | Blast radius calculation | "What if I change this?" |
| Coupling Analysis | Import/call frequency between modules | "How tightly coupled are these modules?" |

### Upstream Dependencies (Must Exist Before Call Graph)

| Dependency | What It Provides | Why Needed |
|-----------|-----------------|------------|
| Parsers (Level 0) | ParseResult with FunctionInfo, CallSite, ImportInfo, ExportInfo, ClassInfo | Raw extraction data |
| Scanner (Level 0) | ScanDiff (added/modified/removed files) | Incremental build input |
| Storage (Level 0) | DatabaseManager with batch writer | Persistence to drift.db |
| String Interning (Level 1) | ThreadedRodeo / RodeoReader | Memory-efficient function IDs |
| Infrastructure (Level 0) | thiserror, tracing, DriftEventHandler, config | Error handling, observability, events |

---

## 2. Core Data Model

### In-Memory: petgraph StableGraph

petgraph is the standard Rust graph library (100M+ downloads on crates.io). StableGraph
maintains stable node/edge indices even after removals — critical for incremental updates
where we remove edges for changed files and re-add them.

```rust
use petgraph::stable_graph::{StableGraph, NodeIndex, EdgeIndex};
use petgraph::Directed;
use lasso::Spur;
use rustc_hash::FxHashMap;

/// The in-memory call graph. Loaded from drift.db on startup,
/// updated incrementally after scans, synced back to drift.db.
pub struct CallGraph {
    /// Directed graph: nodes are functions, edges are call relationships.
    graph: StableGraph<FunctionNode, CallEdge, Directed>,

    /// Function ID → NodeIndex lookup. Uses interned Spur keys for O(1) lookup.
    node_index: FxHashMap<Spur, NodeIndex>,

    /// File path → set of NodeIndex values in that file.
    /// Used for incremental invalidation: when a file changes,
    /// remove all nodes/edges owned by that file.
    file_nodes: FxHashMap<Spur, Vec<NodeIndex>>,

    /// String interner for function IDs and file paths.
    /// ThreadedRodeo during build, converted to RodeoReader for queries.
    interner: lasso::ThreadedRodeo,

    /// Build statistics for observability.
    stats: CallGraphStats,
}
```

### FunctionNode

```rust
/// A function in the call graph. Stored as a petgraph node.
pub struct FunctionNode {
    /// Interned qualified function name (e.g., "UserService.getUser").
    pub id: Spur,

    /// Interned file path (normalized, forward slashes).
    pub file: Spur,

    /// Line number where the function is defined.
    pub line: u32,

    /// End line of the function body.
    pub end_line: u32,

    /// Whether this function is an entry point (HTTP handler, CLI command, main, etc.).
    pub is_entry_point: bool,

    /// Whether this function is exported from its module.
    pub is_exported: bool,

    /// Language of the source file.
    pub language: Language,

    /// xxh3 hash of the function signature (name + params + return type).
    /// Used for incremental: if signature unchanged, cross-file edges are preserved.
    pub signature_hash: u64,

    /// xxh3 hash of the function body.
    /// Used for incremental: if body unchanged, skip re-extraction.
    pub body_hash: u64,

    /// Optional return type string for display/query purposes.
    pub return_type: Option<String>,
}
```

### CallEdge

```rust
/// A call relationship between two functions. Stored as a petgraph edge.
pub struct CallEdge {
    /// How this call was resolved (determines confidence).
    pub resolution: Resolution,

    /// Confidence in the resolution (0.0 - 1.0).
    pub confidence: f64,

    /// Line number of the call site in the caller's file.
    pub call_site_line: u32,
}

/// Resolution strategy that produced this edge, ordered by confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resolution {
    /// Function defined in the same file as the call site. Trivial to resolve.
    SameFile,       // confidence: 0.95

    /// Resolved via class/receiver type and method name.
    MethodCall,     // confidence: 0.90

    /// Framework-specific dependency injection pattern.
    DiInjection,    // confidence: 0.80

    /// Resolved by following import chains to the defining module.
    ImportBased,    // confidence: 0.75

    /// Matched by exported name across files (no import chain).
    ExportBased,    // confidence: 0.60

    /// Name similarity for dynamic calls. Last resort.
    Fuzzy,          // confidence: 0.40
}

impl Resolution {
    pub fn default_confidence(&self) -> f64 {
        match self {
            Resolution::SameFile => 0.95,
            Resolution::MethodCall => 0.90,
            Resolution::DiInjection => 0.80,
            Resolution::ImportBased => 0.75,
            Resolution::ExportBased => 0.60,
            Resolution::Fuzzy => 0.40,
        }
    }
}
```

### CallGraphStats

```rust
/// Statistics from a call graph build, returned via NAPI.
#[derive(Default, Debug)]
pub struct CallGraphStats {
    pub total_functions: usize,
    pub total_edges: usize,
    pub entry_points: usize,
    pub resolution_counts: FxHashMap<Resolution, usize>,
    pub unresolved_calls: usize,
    pub resolution_rate: f64,           // resolved / (resolved + unresolved)
    pub files_processed: usize,
    pub languages: FxHashMap<Language, usize>,
    pub build_duration_ms: u64,
    pub extraction_duration_ms: u64,
    pub resolution_duration_ms: u64,
    pub persistence_duration_ms: u64,
    pub data_access_points: usize,
}
```

---

## 3. SQLite Storage Schema

All call graph data lives in drift.db alongside other Drift data. No separate callgraph.db.
Tables use STRICT mode (per AD7). Indexes optimized for the most common query patterns:
forward traversal (caller→callees), inverse traversal (callee→callers), and file-based lookup.

```sql
-- Migration: 002_call_graph.sql

CREATE TABLE functions (
    id TEXT PRIMARY KEY,                -- Qualified name: "file::Class.method" or "file::function"
    file TEXT NOT NULL,                 -- Normalized file path
    name TEXT NOT NULL,                 -- Unqualified function name
    qualified_name TEXT,                -- Class.method or module.function
    line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    is_entry_point INTEGER NOT NULL DEFAULT 0,
    is_exported INTEGER NOT NULL DEFAULT 0,
    language TEXT NOT NULL,
    signature_hash BLOB,               -- xxh3 hash (8 bytes) for incremental
    body_hash BLOB,                    -- xxh3 hash (8 bytes) for incremental
    return_type TEXT,
    parameter_count INTEGER NOT NULL DEFAULT 0,
    is_async INTEGER NOT NULL DEFAULT 0,
    is_generator INTEGER NOT NULL DEFAULT 0,
    visibility TEXT NOT NULL DEFAULT 'public'
        CHECK(visibility IN ('public', 'private', 'protected')),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE TABLE call_edges (
    caller_id TEXT NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
    callee_id TEXT NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
    resolution TEXT NOT NULL
        CHECK(resolution IN ('same_file', 'method_call', 'di_injection',
                             'import_based', 'export_based', 'fuzzy')),
    confidence REAL NOT NULL,
    call_site_line INTEGER NOT NULL,
    PRIMARY KEY (caller_id, callee_id, call_site_line)
) STRICT;

CREATE TABLE data_access (
    function_id TEXT NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
    table_name TEXT NOT NULL,
    operation TEXT NOT NULL
        CHECK(operation IN ('select', 'insert', 'update', 'delete', 'upsert', 'raw')),
    framework TEXT,                     -- e.g., "prisma", "django", "sqlalchemy"
    line INTEGER NOT NULL,
    confidence REAL NOT NULL DEFAULT 0.8,
    raw_query TEXT,                     -- Optional: the raw SQL/ORM expression
    PRIMARY KEY (function_id, table_name, operation, line)
) STRICT;

CREATE TABLE call_graph_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

-- Forward traversal: given a caller, find all callees
CREATE INDEX idx_call_edges_caller ON call_edges(caller_id);

-- Inverse traversal: given a callee, find all callers
CREATE INDEX idx_call_edges_callee ON call_edges(callee_id);

-- File-based lookup: find all functions in a file
CREATE INDEX idx_functions_file ON functions(file);

-- Entry point queries: find all entry points
CREATE INDEX idx_functions_entry ON functions(is_entry_point)
    WHERE is_entry_point = 1;

-- Exported function queries
CREATE INDEX idx_functions_exported ON functions(is_exported)
    WHERE is_exported = 1;

-- Data access by table name (for boundary/security queries)
CREATE INDEX idx_data_access_table ON data_access(table_name);

-- Data access by function (for taint/reachability queries)
CREATE INDEX idx_data_access_function ON data_access(function_id);

-- Functions by language (for language-specific queries)
CREATE INDEX idx_functions_language ON functions(language);

-- Functions by name (for fuzzy resolution and search)
CREATE INDEX idx_functions_name ON functions(name);
```

### Metadata Table Usage

The `call_graph_metadata` table stores build metadata for incremental operations:

```sql
-- After each build, store:
INSERT OR REPLACE INTO call_graph_metadata (key, value) VALUES
    ('last_build_at', unixepoch()),
    ('total_functions', '12345'),
    ('total_edges', '45678'),
    ('resolution_rate', '0.73'),
    ('build_duration_ms', '1250');
```

### Dual Storage: petgraph + SQLite

- petgraph (in-memory): Fast BFS/DFS traversals during analysis (reachability, impact, taint).
  O(1) node lookup via FxHashMap, O(neighbors) edge traversal.
- SQLite: Persistence across restarts, complex queries (JOIN with patterns, filter by file),
  keyset pagination for MCP/CLI consumers.

On startup: load from SQLite into petgraph. After scan: write new edges to SQLite, rebuild
petgraph from SQLite (or incrementally update both).

### Large Codebase Fallback: SQLite Recursive CTEs

For very large codebases (500K+ files, 1M+ functions), the in-memory graph may exceed
available memory. The SQLite-backed BFS engine using recursive CTEs serves as a fallback:

```sql
-- Forward reachability via recursive CTE
WITH RECURSIVE reachable(id, depth, path) AS (
    -- Base case: direct callees of the start function
    SELECT callee_id, 1, caller_id || ' -> ' || callee_id
    FROM call_edges
    WHERE caller_id = :start_function

    UNION ALL

    -- Recursive case: callees of reachable functions
    SELECT e.callee_id, r.depth + 1, r.path || ' -> ' || e.callee_id
    FROM call_edges e
    JOIN reachable r ON e.caller_id = r.id
    WHERE r.depth < :max_depth
      AND r.path NOT LIKE '%' || e.callee_id || '%'  -- cycle detection
)
SELECT DISTINCT id, depth FROM reachable ORDER BY depth;
```

```sql
-- Inverse reachability: who can reach this function?
WITH RECURSIVE callers(id, depth) AS (
    SELECT caller_id, 1
    FROM call_edges
    WHERE callee_id = :target_function

    UNION ALL

    SELECT e.caller_id, c.depth + 1
    FROM call_edges e
    JOIN callers c ON e.callee_id = c.id
    WHERE c.depth < :max_depth
)
SELECT DISTINCT id, depth FROM callers ORDER BY depth;
```

Decision: Start with petgraph for all codebases. Add SQLite CTE fallback when memory
pressure is detected (configurable threshold, default 500K functions). The CTE approach
is ~10x slower than in-memory BFS but uses O(1) memory.


---

## 4. Build Pipeline: Rayon + Crossbeam Channel + Batch Writer

The call graph build follows the same parallel pipeline pattern used by the scanner and
storage layer. Files are processed in parallel via rayon, call sites extracted per-file,
sent through a bounded crossbeam channel, and batch-written to drift.db by a dedicated
writer thread.

### Pipeline Architecture

```
Phase 1: Extraction (rayon par_iter, N-1 threads)
  Files → Parse (thread_local! parser) → Extract functions + call sites → Channel

Phase 2: Resolution (single-threaded, after extraction completes)
  All call sites → Resolution index → 6 strategies → Resolved edges

Phase 3: Persistence (dedicated writer thread)
  Resolved edges → Crossbeam bounded channel → Batch writer → drift.db

Phase 4: In-Memory Build
  Load from drift.db → petgraph StableGraph → Ready for queries
```

### Phase 1: Parallel Extraction

```rust
use rayon::prelude::*;
use crossbeam_channel::{bounded, Sender};

/// Raw extraction output from a single file. Sent through the channel.
pub struct FileExtraction {
    pub file: PathBuf,
    pub language: Language,
    pub functions: Vec<ExtractedFunction>,
    pub call_sites: Vec<ExtractedCallSite>,
    pub data_accesses: Vec<ExtractedDataAccess>,
}

pub struct ExtractedFunction {
    pub name: String,
    pub qualified_name: Option<String>,
    pub line: u32,
    pub end_line: u32,
    pub is_exported: bool,
    pub is_async: bool,
    pub is_generator: bool,
    pub visibility: Visibility,
    pub signature_hash: u64,
    pub body_hash: u64,
    pub return_type: Option<String>,
    pub parameter_count: usize,
    pub decorators: Vec<DecoratorInfo>,
}

pub struct ExtractedCallSite {
    pub caller_name: String,           // function containing the call
    pub callee_name: String,           // function being called
    pub receiver: Option<String>,      // e.g., "db" in db.query()
    pub import_source: Option<String>, // e.g., "./utils" if callee is imported
    pub line: u32,
    pub arg_count: usize,
}

pub struct ExtractedDataAccess {
    pub function_name: String,
    pub table_name: String,
    pub operation: DataOperation,
    pub framework: Option<String>,
    pub line: u32,
    pub raw_query: Option<String>,
}

pub enum DataOperation {
    Select, Insert, Update, Delete, Upsert, Raw,
}

fn extract_all_files(
    files: &[PathBuf],
    tx: Sender<FileExtraction>,
    event_handler: &dyn DriftEventHandler,
) {
    let total = files.len();
    let processed = AtomicUsize::new(0);

    files.par_iter().for_each(|file| {
        // Check cancellation between files
        if is_cancelled() {
            return;
        }

        // Parse file using thread-local parser
        let parse_result = with_parser(|pm| pm.parse_file(file));
        let Some(result) = parse_result else { return };

        // Extract functions, call sites, and data accesses
        let extraction = extract_from_parse_result(file, &result);
        let _ = tx.send(extraction);

        // Progress reporting every 100 files
        let count = processed.fetch_add(1, Ordering::Relaxed) + 1;
        if count % 100 == 0 || count == total {
            event_handler.on_call_graph_progress(count, total);
        }
    });
}
```

### Phase 2: Resolution

Resolution runs single-threaded after all extractions complete. It builds a resolution
index from all extracted functions and imports, then resolves each call site using the
6 strategies in confidence order.

```rust
/// Index built from all extracted functions for cross-file resolution.
pub struct ResolutionIndex {
    /// Function name → list of (file, qualified_name) definitions.
    /// Used by export-based and fuzzy resolution.
    by_name: FxHashMap<String, SmallVec<[FunctionDef; 4]>>,

    /// (file, function_name) → qualified function ID.
    /// Used by same-file resolution.
    by_file_and_name: FxHashMap<(Spur, String), Spur>,

    /// Import source → exported names.
    /// Used by import-based resolution.
    by_import: FxHashMap<String, Vec<String>>,

    /// Class name → list of method names.
    /// Used by method call resolution.
    by_class: FxHashMap<String, Vec<String>>,

    /// Class name → parent class chain (MRO).
    /// Used by method call resolution with inheritance (PyCG approach).
    class_hierarchy: FxHashMap<String, Vec<String>>,

    /// Framework DI registrations.
    /// Used by DI injection resolution.
    di_registry: FxHashMap<String, String>,
}

struct FunctionDef {
    file: Spur,
    qualified_name: Spur,
    is_exported: bool,
}
```

### Phase 3: Persistence via Batch Writer

Uses the same batch writer pattern from 02-STORAGE-V2-PREP.md. The call graph builder
sends `WriteBatch::Functions` and `WriteBatch::CallEdges` through the crossbeam channel.

```rust
fn persist_call_graph(
    db: &DatabaseManager,
    functions: &[FunctionNode],
    edges: &[ResolvedEdge],
    data_accesses: &[DataAccessEntry],
) -> Result<WriteStats, StorageError> {
    let writer = db.batch_writer();

    // Batch functions (500 per transaction)
    for chunk in functions.chunks(500) {
        writer.send(WriteBatch::Functions(chunk.to_vec()))?;
    }

    // Batch edges (500 per transaction)
    for chunk in edges.chunks(500) {
        writer.send(WriteBatch::CallEdges(chunk.to_vec()))?;
    }

    // Batch data accesses (500 per transaction)
    for chunk in data_accesses.chunks(500) {
        writer.send(WriteBatch::DataAccess(chunk.to_vec()))?;
    }

    writer.send(WriteBatch::Flush)?;
    writer.finish()
}
```

### Phase 4: In-Memory Graph Build

After persistence, load from drift.db into petgraph:

```rust
impl CallGraph {
    /// Load the full call graph from drift.db into petgraph.
    pub fn load_from_db(db: &DatabaseManager) -> Result<Self, CallGraphError> {
        let reader = db.reader()?;
        let mut graph = StableGraph::new();
        let mut node_index = FxHashMap::default();
        let mut file_nodes: FxHashMap<Spur, Vec<NodeIndex>> = FxHashMap::default();
        let interner = lasso::ThreadedRodeo::default();

        // Load all functions as nodes
        let mut stmt = reader.prepare_cached(
            "SELECT id, file, name, line, end_line, is_entry_point, is_exported,
                    language, signature_hash, body_hash, return_type
             FROM functions"
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(FunctionRow {
                id: row.get::<_, String>(0)?,
                file: row.get::<_, String>(1)?,
                name: row.get::<_, String>(2)?,
                line: row.get::<_, u32>(3)?,
                end_line: row.get::<_, u32>(4)?,
                is_entry_point: row.get::<_, bool>(5)?,
                is_exported: row.get::<_, bool>(6)?,
                language: row.get::<_, String>(7)?,
                signature_hash: row.get::<_, Option<Vec<u8>>>(8)?,
                body_hash: row.get::<_, Option<Vec<u8>>>(9)?,
                return_type: row.get::<_, Option<String>>(10)?,
            })
        })?;

        for row in rows {
            let row = row?;
            let id_spur = interner.get_or_intern(&row.id);
            let file_spur = interner.get_or_intern(&row.file);

            let node = FunctionNode {
                id: id_spur,
                file: file_spur,
                line: row.line,
                end_line: row.end_line,
                is_entry_point: row.is_entry_point,
                is_exported: row.is_exported,
                language: Language::from_str(&row.language),
                signature_hash: bytes_to_u64(&row.signature_hash),
                body_hash: bytes_to_u64(&row.body_hash),
                return_type: row.return_type,
            };

            let idx = graph.add_node(node);
            node_index.insert(id_spur, idx);
            file_nodes.entry(file_spur).or_default().push(idx);
        }

        // Load all edges
        let mut stmt = reader.prepare_cached(
            "SELECT caller_id, callee_id, resolution, confidence, call_site_line
             FROM call_edges"
        )?;

        let edges = stmt.query_map([], |row| {
            Ok(EdgeRow {
                caller_id: row.get::<_, String>(0)?,
                callee_id: row.get::<_, String>(1)?,
                resolution: row.get::<_, String>(2)?,
                confidence: row.get::<_, f64>(3)?,
                call_site_line: row.get::<_, u32>(4)?,
            })
        })?;

        for edge in edges {
            let edge = edge?;
            let caller_spur = interner.get_or_intern(&edge.caller_id);
            let callee_spur = interner.get_or_intern(&edge.callee_id);

            if let (Some(&caller_idx), Some(&callee_idx)) =
                (node_index.get(&caller_spur), node_index.get(&callee_spur))
            {
                graph.add_edge(caller_idx, callee_idx, CallEdge {
                    resolution: Resolution::from_str(&edge.resolution),
                    confidence: edge.confidence,
                    call_site_line: edge.call_site_line,
                });
            }
        }

        Ok(CallGraph {
            graph,
            node_index,
            file_nodes,
            interner,
            stats: CallGraphStats::default(),
        })
    }
}
```

### Thread Pool Configuration

Custom rayon pool with `num_cpus - 1` threads. Leave one core for the batch writer thread
and OS. This prevents the writer from being starved by extraction workers.

```rust
let pool = rayon::ThreadPoolBuilder::new()
    .num_threads(num_cpus::get().saturating_sub(1).max(1))
    .thread_name(|i| format!("drift-cg-{}", i))
    .build()
    .expect("failed to build rayon thread pool");

pool.install(|| {
    extract_all_files(&files, tx, event_handler);
});
```

---

## 5. Resolution Strategies (Unified Algorithm)

The 6 resolution strategies run in confidence order. First match wins. This is a unified
algorithm — NOT per-language resolution variants. All languages normalize to the same
call site representation before resolution.

### Normalized Call Site Representation

```rust
/// A call site normalized for resolution. Language-agnostic.
pub struct NormalizedCallSite {
    /// File containing the call.
    pub caller_file: Spur,
    /// Function containing the call.
    pub caller_function: Spur,
    /// Name of the function being called.
    pub callee_name: String,
    /// Receiver/object if method call (e.g., "db" in db.query()).
    pub receiver_type: Option<String>,
    /// Import path if the callee was imported (e.g., "./utils").
    pub import_path: Option<String>,
    /// Line number of the call site.
    pub line: u32,
    /// Number of arguments passed.
    pub arg_count: usize,
}
```

### Strategy 1: Same-File (Confidence: 0.95)

Function defined in the same file as the call site. Trivial — match callee_name against
all functions defined in caller_file.

```rust
fn resolve_same_file(
    call: &NormalizedCallSite,
    index: &ResolutionIndex,
) -> Option<ResolvedEdge> {
    let target = index.by_file_and_name.get(&(call.caller_file, call.callee_name.clone()))?;
    Some(ResolvedEdge {
        caller: call.caller_function,
        callee: *target,
        resolution: Resolution::SameFile,
        confidence: 0.95,
        call_site_line: call.line,
    })
}
```

### Strategy 2: Method Call (Confidence: 0.90)

Resolved via class/receiver type. If `obj.method()` is called and `obj`'s type is known
(from declaration, import, or class context), resolve to that class's method.

Per A5 (PyCG approach): follow class hierarchy MRO (Method Resolution Order) for Python
and similar inheritance chains for Java/C#. When `obj.method()` is called, walk the MRO
chain to find the actual implementation.

```rust
fn resolve_method_call(
    call: &NormalizedCallSite,
    index: &ResolutionIndex,
) -> Option<ResolvedEdge> {
    let receiver = call.receiver_type.as_ref()?;

    // Direct class method lookup
    if let Some(methods) = index.by_class.get(receiver) {
        if methods.contains(&call.callee_name) {
            let qualified = format!("{}.{}", receiver, call.callee_name);
            if let Some(&target) = index.by_name_qualified(&qualified) {
                return Some(ResolvedEdge {
                    caller: call.caller_function,
                    callee: target,
                    resolution: Resolution::MethodCall,
                    confidence: 0.90,
                    call_site_line: call.line,
                });
            }
        }
    }

    // MRO walk: check parent classes
    if let Some(mro) = index.class_hierarchy.get(receiver) {
        for parent in mro {
            if let Some(methods) = index.by_class.get(parent) {
                if methods.contains(&call.callee_name) {
                    let qualified = format!("{}.{}", parent, call.callee_name);
                    if let Some(&target) = index.by_name_qualified(&qualified) {
                        return Some(ResolvedEdge {
                            caller: call.caller_function,
                            callee: target,
                            resolution: Resolution::MethodCall,
                            confidence: 0.85, // slightly lower for inherited
                            call_site_line: call.line,
                        });
                    }
                }
            }
        }
    }

    None
}
```

### Strategy 3: DI Injection (Confidence: 0.80)

Framework-specific dependency injection patterns. Requires framework detection from the
parser's FrameworkExtractor output.

| Framework | Pattern | Resolution |
|-----------|---------|------------|
| FastAPI | `Depends(service_function)` | Resolve `service_function` as callee |
| Spring | `@Autowired`, `@Inject` on field/constructor | Resolve field type to class |
| NestJS | `@Inject()`, constructor injection | Resolve parameter type to provider |
| Laravel | Type-hinted constructor parameters | Resolve type to service class |
| ASP.NET | Constructor injection, `[FromServices]` | Resolve parameter type to service |

```rust
fn resolve_di_injection(
    call: &NormalizedCallSite,
    index: &ResolutionIndex,
) -> Option<ResolvedEdge> {
    // Check if callee_name matches a DI-registered provider
    let target = index.di_registry.get(&call.callee_name)?;
    let target_spur = index.lookup_function(target)?;

    Some(ResolvedEdge {
        caller: call.caller_function,
        callee: target_spur,
        resolution: Resolution::DiInjection,
        confidence: 0.80,
        call_site_line: call.line,
    })
}
```

### Strategy 4: Import-Based (Confidence: 0.75)

Follow import chains. If `import { foo } from './utils'` and `utils.ts` exports `foo`,
resolve the call to `foo` in `utils.ts`.

```rust
fn resolve_import_based(
    call: &NormalizedCallSite,
    index: &ResolutionIndex,
) -> Option<ResolvedEdge> {
    let import_path = call.import_path.as_ref()?;

    // Look up what the import source exports
    let exports = index.by_import.get(import_path)?;
    if !exports.contains(&call.callee_name) {
        return None;
    }

    // Find the function definition in the imported file
    let resolved_file = index.resolve_import_path(import_path, &call.caller_file)?;
    let target = index.by_file_and_name.get(&(resolved_file, call.callee_name.clone()))?;

    Some(ResolvedEdge {
        caller: call.caller_function,
        callee: *target,
        resolution: Resolution::ImportBased,
        confidence: 0.75,
        call_site_line: call.line,
    })
}
```

### Strategy 5: Export-Based (Confidence: 0.60)

Match exported names across files. Less precise than import-based because it doesn't
follow the import chain — just matches by name among all exported functions.

```rust
fn resolve_export_based(
    call: &NormalizedCallSite,
    index: &ResolutionIndex,
) -> Option<ResolvedEdge> {
    let candidates = index.by_name.get(&call.callee_name)?;

    // Filter to exported functions only
    let exported: SmallVec<[&FunctionDef; 4]> = candidates
        .iter()
        .filter(|f| f.is_exported)
        .collect();

    match exported.len() {
        0 => None,
        1 => Some(ResolvedEdge {
            caller: call.caller_function,
            callee: exported[0].qualified_name,
            resolution: Resolution::ExportBased,
            confidence: 0.60,
            call_site_line: call.line,
        }),
        _ => {
            // Multiple candidates — pick the one in the closest directory
            let best = pick_closest_export(&exported, &call.caller_file, index)?;
            Some(ResolvedEdge {
                caller: call.caller_function,
                callee: best.qualified_name,
                resolution: Resolution::ExportBased,
                confidence: 0.50, // lower confidence for ambiguous
                call_site_line: call.line,
            })
        }
    }
}
```

### Strategy 6: Fuzzy (Confidence: 0.40)

Name similarity for dynamic calls. Last resort. Useful for dynamic dispatch patterns
where the exact target can't be determined statically.

```rust
fn resolve_fuzzy(
    call: &NormalizedCallSite,
    index: &ResolutionIndex,
) -> Option<ResolvedEdge> {
    let candidates = index.by_name.get(&call.callee_name)?;

    // Only use fuzzy if there's exactly one candidate with this name
    // (multiple candidates = too ambiguous for fuzzy)
    if candidates.len() != 1 {
        return None;
    }

    Some(ResolvedEdge {
        caller: call.caller_function,
        callee: candidates[0].qualified_name,
        resolution: Resolution::Fuzzy,
        confidence: 0.40,
        call_site_line: call.line,
    })
}
```

### Unified Resolution Runner

```rust
pub fn resolve_call_site(
    call: &NormalizedCallSite,
    index: &ResolutionIndex,
) -> Option<ResolvedEdge> {
    // Run strategies in confidence order. First match wins.
    resolve_same_file(call, index)
        .or_else(|| resolve_method_call(call, index))
        .or_else(|| resolve_di_injection(call, index))
        .or_else(|| resolve_import_based(call, index))
        .or_else(|| resolve_export_based(call, index))
        .or_else(|| resolve_fuzzy(call, index))
}
```

### Resolution Rate Target

From the audit: 60-85% resolution rate. This is realistic for static analysis without
full type inference. The rate varies by language:

| Language | Expected Rate | Why |
|----------|--------------|-----|
| TypeScript | 70-85% | Strong import system, explicit types |
| Java | 75-85% | Strong type system, explicit imports |
| C# | 75-85% | Strong type system, explicit imports |
| Python | 55-70% | Dynamic typing, duck typing |
| PHP | 60-75% | Mixed typing, magic methods |
| Go | 70-80% | Explicit imports, strong types |
| Rust | 75-85% | Strong type system, explicit paths |
| C/C++ | 50-65% | Headers, macros, function pointers |

Track resolution rate per language for observability. Alert if rate drops below 50%
for any language (indicates extraction or resolution bugs).


---

## 6. Entry Point Detection

Entry points are functions callable from outside the codebase — HTTP handlers, CLI commands,
exported APIs, main functions. They're critical for:
- Reachability analysis (start BFS from entry points)
- Impact analysis (how many entry points are affected by a change?)
- Security analysis (which entry points reach sensitive data?)
- Dead code detection (functions unreachable from any entry point)

### 5 Heuristic Categories

```rust
pub enum EntryPointKind {
    /// Route decorators: @app.get("/users"), @GetMapping, @Route, #[get("/")]
    RouteHandler,

    /// Controller classes: classes in controllers/ or with Controller suffix
    ControllerMethod,

    /// Exported handlers: export function handler(), module.exports
    ExportedHandler,

    /// Main functions: fn main(), if __name__ == "__main__", public static void main
    MainFunction,

    /// Framework-specific: Express app.use(), Spring @RestController, CLI commands
    FrameworkEntry,
}

pub struct EntryPoint {
    pub function_id: Spur,
    pub kind: EntryPointKind,
    pub route: Option<String>,       // HTTP path if applicable
    pub http_method: Option<String>, // GET, POST, etc.
    pub confidence: f64,
}
```

### Detection Logic

Entry point detection runs as a post-pass after function extraction, using both
ParseResult data (decorators, exports) and file path heuristics.

```rust
fn detect_entry_points(
    functions: &[FunctionNode],
    parse_results: &FxHashMap<Spur, ParseResult>,
    interner: &ThreadedRodeo,
) -> Vec<EntryPoint> {
    let mut entry_points = Vec::new();

    for func in functions {
        let file_path = interner.resolve(&func.file);
        let parse_result = parse_results.get(&func.file);

        // 1. Route decorators (highest confidence)
        if let Some(pr) = parse_result {
            if has_route_decorator(&func, pr) {
                entry_points.push(EntryPoint {
                    function_id: func.id,
                    kind: EntryPointKind::RouteHandler,
                    route: extract_route_path(&func, pr),
                    http_method: extract_http_method(&func, pr),
                    confidence: 0.95,
                });
                continue;
            }
        }

        // 2. Controller classes
        if is_controller_method(file_path, &func) {
            entry_points.push(EntryPoint {
                function_id: func.id,
                kind: EntryPointKind::ControllerMethod,
                route: None,
                http_method: None,
                confidence: 0.85,
            });
            continue;
        }

        // 3. Exported handlers
        if func.is_exported && is_handler_name(interner.resolve(&func.id)) {
            entry_points.push(EntryPoint {
                function_id: func.id,
                kind: EntryPointKind::ExportedHandler,
                route: None,
                http_method: None,
                confidence: 0.70,
            });
            continue;
        }

        // 4. Main functions
        if is_main_function(interner.resolve(&func.id), func.language) {
            entry_points.push(EntryPoint {
                function_id: func.id,
                kind: EntryPointKind::MainFunction,
                route: None,
                http_method: None,
                confidence: 0.99,
            });
            continue;
        }

        // 5. Framework-specific patterns
        if let Some(pr) = parse_result {
            if let Some(ep) = detect_framework_entry(&func, pr) {
                entry_points.push(ep);
            }
        }
    }

    entry_points
}
```

### Route Decorator Patterns (Per Language)

| Language | Patterns |
|----------|----------|
| Python | `@app.get()`, `@app.post()`, `@router.get()`, `@api_view()`, `@action()` |
| Java | `@GetMapping`, `@PostMapping`, `@RequestMapping`, `@Path` |
| C# | `[HttpGet]`, `[HttpPost]`, `[Route]`, `[ApiController]` methods |
| TypeScript | `@Get()`, `@Post()`, `@Controller()` methods (NestJS), `app.get()` (Express) |
| PHP | `#[Route]`, `Route::get()`, `Route::post()` (Laravel) |
| Go | `r.GET()`, `e.GET()`, `http.HandleFunc()` |
| Rust | `#[get("/")]`, `#[post("/")]` (Actix/Rocket), `.route()` (Axum) |

### Controller Detection Heuristics

```rust
fn is_controller_method(file_path: &str, func: &FunctionNode) -> bool {
    // File path heuristics
    let path_lower = file_path.to_lowercase();
    let is_controller_file = path_lower.contains("/controllers/")
        || path_lower.contains("/controller/")
        || path_lower.contains("/handlers/")
        || path_lower.contains("/routes/")
        || path_lower.contains("/endpoints/")
        || path_lower.ends_with("controller.ts")
        || path_lower.ends_with("controller.js")
        || path_lower.ends_with("controller.py")
        || path_lower.ends_with("controller.java")
        || path_lower.ends_with("controller.cs")
        || path_lower.ends_with("controller.php")
        || path_lower.ends_with("controller.go")
        || path_lower.ends_with("handler.rs");

    // Only public/exported methods in controller files
    is_controller_file && (func.is_exported || matches!(func.visibility, Visibility::Public))
}
```

### Main Function Detection

```rust
fn is_main_function(name: &str, language: Language) -> bool {
    match language {
        Language::Rust => name.ends_with("::main") || name == "main",
        Language::Go => name == "main" || name.ends_with(".main"),
        Language::Java => name.ends_with(".main"),
        Language::CSharp => name.ends_with(".Main"),
        Language::Python => false, // Python uses if __name__ == "__main__" (not a function)
        Language::C | Language::Cpp => name == "main",
        _ => false,
    }
}
```

---

## 7. Incremental Updates

When files change (detected by scanner's ScanDiff), the call graph updates incrementally
rather than rebuilding from scratch. This is O(edges_in_changed_files), not O(total_edges).

### Incremental Algorithm

```rust
pub fn update_incremental(
    &mut self,
    diff: &ScanDiff,
    db: &DatabaseManager,
    event_handler: &dyn DriftEventHandler,
) -> Result<CallGraphStats, CallGraphError> {
    let _span = tracing::info_span!("call_graph_incremental",
        added = diff.added.len(),
        modified = diff.modified.len(),
        removed = diff.removed.len(),
    ).entered();

    // Step 1: Remove all functions and edges for changed/removed files
    let affected_files: Vec<&PathBuf> = diff.modified.iter()
        .chain(diff.removed.iter())
        .collect();

    for file in &affected_files {
        self.remove_file_data(file, db)?;
    }

    // Step 2: Re-extract from added + modified files
    let files_to_process: Vec<&PathBuf> = diff.added.iter()
        .chain(diff.modified.iter())
        .collect();

    let extractions = extract_files_parallel(&files_to_process, event_handler);

    // Step 3: Build resolution index (needs ALL functions, not just changed)
    // Load existing functions from drift.db + new extractions
    let index = build_resolution_index_incremental(db, &extractions)?;

    // Step 4: Resolve call sites from new/changed files only
    let new_edges = resolve_all_calls(&extractions, &index);

    // Step 5: Persist new functions and edges
    persist_incremental(db, &extractions, &new_edges)?;

    // Step 6: Update in-memory graph
    self.apply_incremental(&extractions, &new_edges)?;

    // Step 7: Re-resolve cross-file edges FROM other files INTO changed files
    // (Other files may call functions in the changed files — those edges
    // need re-resolution if the changed file's exports changed)
    let cross_file_edges = re_resolve_incoming_edges(
        &affected_files, &index, db
    )?;
    self.apply_cross_file_edges(&cross_file_edges)?;

    Ok(self.stats.clone())
}
```

### File Data Removal

```rust
fn remove_file_data(
    &mut self,
    file: &Path,
    db: &DatabaseManager,
) -> Result<(), CallGraphError> {
    let file_str = file.to_string_lossy();

    // Remove from SQLite (CASCADE deletes edges and data_access)
    let writer = db.writer()?;
    writer.execute(
        "DELETE FROM functions WHERE file = ?",
        [&file_str as &dyn rusqlite::types::ToSql],
    )?;

    // Remove from in-memory graph
    let file_spur = self.interner.get(&file_str);
    if let Some(spur) = file_spur {
        if let Some(nodes) = self.file_nodes.remove(&spur) {
            for node_idx in nodes {
                self.graph.remove_node(node_idx);
                // StableGraph: removing a node also removes all its edges
            }
        }
    }

    Ok(())
}
```

### Body Hash Optimization

From A3 (parsers doc): `body_hash` on FunctionInfo enables fine-grained invalidation.
When a function's body changes but its signature doesn't, cross-file edges pointing TO
that function are preserved (they depend on the signature, not the body).

```rust
fn needs_re_extraction(
    existing: &FunctionNode,
    new_parse: &FunctionInfo,
) -> bool {
    // If body hash unchanged, skip re-extraction entirely
    existing.body_hash != new_parse.body_hash
}

fn needs_cross_file_re_resolution(
    existing: &FunctionNode,
    new_parse: &FunctionInfo,
) -> bool {
    // Only re-resolve incoming edges if signature changed
    // (signature change means callers might resolve differently)
    existing.signature_hash != new_parse.signature_hash
}
```

### Incremental Performance Target

From the audit:
- Single file change: <100ms total (extraction + resolution + persistence + graph update)
- 10 files changed: <500ms
- 100 files changed: <2s

These are achievable because:
- Extraction is per-file (parallel, cached parse results)
- Resolution index is loaded from drift.db (not rebuilt from scratch)
- Only changed files' edges are re-resolved
- Batch writer amortizes SQLite transaction overhead

---

## 8. Per-Language Call Site Extraction

Each language has specific patterns for function calls, method calls, constructor calls,
and framework-specific invocations. The extractor normalizes all of these into the
`ExtractedCallSite` format for the unified resolution algorithm.

### Universal Extraction from ParseResult

The call graph builder does NOT re-parse files. It consumes the `ParseResult` produced
by the parser system (Level 0). Specifically:

- `ParseResult.functions` → FunctionInfo with name, qualified_name, line, body_hash, signature_hash
- `ParseResult.calls` → CallSite with callee, receiver, arg_count, range
- `ParseResult.imports` → ImportInfo with source, named imports, default import
- `ParseResult.exports` → ExportInfo with name, is_default
- `ParseResult.classes` → ClassInfo with name, extends, implements, methods

### Language-Specific Extraction Notes

**TypeScript/JavaScript:**
- Arrow functions: `const handler = async (req, res) => { ... }` — extracted as function
- Dynamic imports: `import('./module')` — extracted as call site with import_source
- Chained calls: `db.users.findMany()` — receiver is "db.users", callee is "findMany"
- Callback patterns: `app.get('/path', handler)` — handler is a call site
- Express middleware: `app.use(middleware)` — middleware is a call site

**Python:**
- Decorators as calls: `@app.get("/users")` — extracted as both decorator and call site
- `super().method()` — resolved via MRO
- `cls.method()` — class method calls
- `*args, **kwargs` forwarding — track as call with unknown arg count
- Context managers: `with open(file) as f:` — `open` is a call site

**Java:**
- Constructor calls: `new UserService()` — extracted as call to constructor
- Static method calls: `Collections.sort(list)` — receiver is "Collections"
- Method references: `list.forEach(System.out::println)` — extracted as call
- Lambda expressions: `(x) -> x.process()` — inner calls extracted
- Chained builders: `builder.setName("x").build()` — each method is a call site

**C#:**
- Extension methods: `list.Where(x => x > 0)` — receiver is list type
- LINQ: `from x in list select x` — desugared to method calls
- Async/await: `await service.GetAsync()` — extracted as call to GetAsync
- Delegate invocations: `handler.Invoke()` or `handler()` — extracted as call

**PHP:**
- Static calls: `UserService::find($id)` — receiver is "UserService"
- `$this->method()` — receiver is current class
- `parent::method()` — resolved via class hierarchy
- Named arguments: `foo(name: 'value')` — extracted with arg count

**Go:**
- Method calls on interfaces: `reader.Read(buf)` — receiver type from declaration
- Goroutine calls: `go handler()` — extracted as call site
- Deferred calls: `defer file.Close()` — extracted as call site
- Package-qualified: `fmt.Println()` — receiver is "fmt"

**Rust:**
- Trait method calls: `item.display()` — resolved via impl blocks
- Associated functions: `Vec::new()` — receiver is "Vec"
- Macro invocations: `println!()` — NOT extracted (macros are compile-time)
- Closure calls: `let f = |x| x + 1; f(5)` — extracted as call to closure
- `?` operator: implicit call to `From::from()` — NOT extracted (too noisy)

**C/C++:**
- Function pointers: `void (*fp)(int) = &func; fp(5)` — extracted as fuzzy call
- Virtual method calls: `obj->method()` — resolved via vtable (class hierarchy)
- Template instantiations: `vector<int> v` — NOT extracted (compile-time)
- Operator overloads: `a + b` → `operator+(a, b)` — NOT extracted (too noisy)
- Preprocessor macros: `MACRO(args)` — NOT extracted (requires preprocessing)

### ORM-Aware Data Access Extraction

Alongside call sites, the extractor identifies data access operations for the
`data_access` table. This feeds boundary detection, taint analysis, and N+1 detection.

```rust
fn extract_data_access(
    call: &CallSite,
    imports: &[ImportInfo],
    language: Language,
) -> Option<ExtractedDataAccess> {
    // Match against known ORM patterns
    // e.g., prisma.user.findMany() → table="user", operation="select", framework="prisma"
    // e.g., User.objects.filter() → table="user", operation="select", framework="django"
    // e.g., db.query("SELECT * FROM users") → table="users", operation="select", framework="raw"
    match_orm_pattern(call, imports, language)
}
```

The 28+ ORM frameworks from the boundary detection system are reused here. The call graph
builder extracts data access points; the boundary detection system classifies sensitivity.

---

## 9. Error Handling (per AD6)

```rust
use thiserror::Error;
use std::path::PathBuf;

#[derive(Error, Debug)]
pub enum CallGraphError {
    #[error("Extraction failed for {file}: {reason}")]
    ExtractionFailed {
        file: PathBuf,
        reason: String,
    },

    #[error("Resolution failed: {reason}")]
    ResolutionFailed {
        reason: String,
    },

    #[error("Graph build failed: {reason}")]
    BuildFailed {
        reason: String,
    },

    #[error("Function not found: {function_id}")]
    FunctionNotFound {
        function_id: String,
    },

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Parse error: {0}")]
    Parse(#[from] ParseError),

    #[error("Call graph build cancelled")]
    Cancelled,

    #[error("Graph too large for in-memory representation: {functions} functions, {edges} edges")]
    GraphTooLarge {
        functions: usize,
        edges: usize,
    },
}
```

Errors are non-fatal at the file level. A single file failing extraction should not abort
the entire build. Collect errors, continue building, report at the end.

```rust
pub struct CallGraphBuildResult {
    pub stats: CallGraphStats,
    pub errors: Vec<CallGraphError>,
    pub status: BuildStatus,
}

pub enum BuildStatus {
    Complete,
    Partial,    // Some files failed, graph is incomplete
    Cancelled,  // Build was cancelled mid-way
}
```

---

## 10. Tracing / Observability (per AD10)

```rust
use tracing::{info, warn, instrument, info_span};

#[instrument(skip(files, db, event_handler), fields(file_count = files.len()))]
pub fn build_call_graph(
    files: &[PathBuf],
    db: &DatabaseManager,
    event_handler: &dyn DriftEventHandler,
) -> Result<CallGraphBuildResult, CallGraphError> {
    let _span = info_span!("call_graph_build").entered();

    // Phase 1: Extraction
    let _extraction = info_span!("extraction").entered();
    let extractions = extract_all_files(files, event_handler);
    info!(
        functions = extractions.iter().map(|e| e.functions.len()).sum::<usize>(),
        call_sites = extractions.iter().map(|e| e.call_sites.len()).sum::<usize>(),
        data_accesses = extractions.iter().map(|e| e.data_accesses.len()).sum::<usize>(),
        "extraction complete"
    );
    drop(_extraction);

    // Phase 2: Resolution
    let _resolution = info_span!("resolution").entered();
    let index = build_resolution_index(&extractions);
    let edges = resolve_all_calls(&extractions, &index);
    info!(
        resolved = edges.len(),
        unresolved = count_unresolved(&extractions, &edges),
        resolution_rate = format!("{:.1}%", resolution_rate(&extractions, &edges) * 100.0),
        "resolution complete"
    );
    drop(_resolution);

    // Phase 3: Persistence
    let _persistence = info_span!("persistence").entered();
    let write_stats = persist_call_graph(db, &extractions, &edges)?;
    info!(
        functions_written = write_stats.functions,
        edges_written = write_stats.call_edges,
        flushes = write_stats.flushes,
        "persistence complete"
    );
    drop(_persistence);

    // Phase 4: In-memory build
    let _build = info_span!("in_memory_build").entered();
    let graph = CallGraph::load_from_db(db)?;
    info!(
        nodes = graph.graph.node_count(),
        edges = graph.graph.edge_count(),
        entry_points = graph.entry_point_count(),
        "in-memory graph built"
    );

    Ok(CallGraphBuildResult { stats: graph.stats, errors: vec![], status: BuildStatus::Complete })
}
```

Key metrics to emit:
- `call_graph_extraction_time_ms` — Phase 1 duration
- `call_graph_resolution_time_ms` — Phase 2 duration
- `call_graph_persistence_time_ms` — Phase 3 duration
- `call_graph_load_time_ms` — Phase 4 duration
- `call_graph_resolution_rate` — % of call sites resolved
- `call_graph_resolution_by_strategy` — count per resolution type
- `call_graph_functions_per_language` — function count per language
- `call_graph_entry_points` — total entry points detected
- `call_graph_unresolved_calls` — count of unresolved call sites


---

## 11. Event Emissions (per D5)

The call graph builder emits events via `DriftEventHandler`. These are no-ops in standalone
mode, consumed by the bridge crate when Cortex is present.

```rust
pub trait DriftEventHandler: Send + Sync {
    // Call graph lifecycle
    fn on_call_graph_build_started(&self, _file_count: usize) {}
    fn on_call_graph_progress(&self, _processed: usize, _total: usize) {}
    fn on_call_graph_build_complete(&self, _stats: &CallGraphStats) {}
    fn on_call_graph_error(&self, _error: &CallGraphError) {}

    // Incremental updates
    fn on_call_graph_incremental_start(&self, _changed_files: usize) {}
    fn on_call_graph_incremental_complete(&self, _stats: &CallGraphStats) {}

    // Notable findings
    fn on_entry_point_detected(&self, _entry_point: &EntryPoint) {}
    fn on_dead_code_candidate(&self, _function_id: &str) {}
}
```

Emit `on_call_graph_progress` every 100 files (consistent with scanner pattern).

---

## 12. NAPI Interface

The call graph follows the "command + query" pattern from 03-NAPI-BRIDGE-V2-PREP.md.
Command functions perform analysis and write to drift.db. Query functions read from drift.db
and return paginated results.

### Command Functions

```rust
/// Build the full call graph. Writes to drift.db, returns stats.
#[napi]
pub fn build_call_graph(root: String) -> napi::Result<CallGraphStatsJs> {
    let rt = crate::runtime::get()?;
    let files = drift_core::scanner::discover_files(
        &PathBuf::from(&root), &rt.config.scan
    ).map_err(to_napi_error)?;

    let result = drift_core::call_graph::build_call_graph(
        &files, &rt.db, &NoOpEventHandler
    ).map_err(to_napi_error)?;

    Ok(CallGraphStatsJs::from(result.stats))
}

/// Async variant with progress callback.
#[napi]
pub fn build_call_graph_async(
    root: String,
    on_progress: ThreadsafeFunction<ProgressUpdate, ()>,
) -> AsyncTask<CallGraphBuildTask> {
    AsyncTask::new(CallGraphBuildTask {
        root,
        on_progress: Arc::new(on_progress),
    })
}

/// Incremental update after a scan. Only processes changed files.
#[napi]
pub fn update_call_graph_incremental(
    added: Vec<String>,
    modified: Vec<String>,
    removed: Vec<String>,
) -> napi::Result<CallGraphStatsJs> {
    let rt = crate::runtime::get()?;
    let diff = ScanDiff {
        added: added.into_iter().map(PathBuf::from).collect(),
        modified: modified.into_iter().map(PathBuf::from).collect(),
        removed: removed.into_iter().map(PathBuf::from).collect(),
        unchanged: vec![],
        errors: vec![],
        stats: ScanStats::default(),
    };

    let result = rt.call_graph.update_incremental(
        &diff, &rt.db, &NoOpEventHandler
    ).map_err(to_napi_error)?;

    Ok(CallGraphStatsJs::from(result))
}
```

### Query Functions

```rust
/// Get call graph statistics.
#[napi]
pub fn query_call_graph_stats() -> napi::Result<CallGraphStatsJs> {
    let rt = crate::runtime::get()?;
    let reader = rt.db.reader()?;
    let stats = drift_core::call_graph::query_stats(&reader)
        .map_err(to_napi_error)?;
    Ok(CallGraphStatsJs::from(stats))
}

/// Get all entry points with optional filtering.
#[napi]
pub fn query_entry_points(
    filter: Option<EntryPointFilter>,
) -> napi::Result<PaginatedResult<EntryPointJs>> {
    let rt = crate::runtime::get()?;
    let reader = rt.db.reader()?;
    drift_core::call_graph::query_entry_points(&reader, filter.as_ref())
        .map_err(to_napi_error)
        .map(|r| r.into())
}

/// Get direct callers and callees of a function (1-hop neighborhood).
#[napi]
pub fn query_function_calls(
    function_id: String,
    direction: String,  // "callers", "callees", "both"
    max_depth: Option<u32>,
) -> napi::Result<CallGraphSubset> {
    let rt = crate::runtime::get()?;
    let reader = rt.db.reader()?;
    let depth = max_depth.unwrap_or(1);
    let dir = match direction.as_str() {
        "callers" => Direction::Incoming,
        "callees" => Direction::Outgoing,
        _ => Direction::Both,
    };

    drift_core::call_graph::query_neighborhood(
        &reader, &function_id, dir, depth
    ).map_err(to_napi_error)
}

/// Find path between two functions (BFS with path tracking).
#[napi]
pub fn query_call_path(
    from_function: String,
    to_function: String,
    max_depth: Option<u32>,
) -> napi::Result<Option<CallPath>> {
    let rt = crate::runtime::get()?;
    let depth = max_depth.unwrap_or(10);

    // Use in-memory graph for fast BFS
    rt.call_graph.find_path(&from_function, &to_function, depth)
        .map_err(to_napi_error)
}

/// Get all functions in a file.
#[napi]
pub fn query_functions_in_file(
    file_path: String,
) -> napi::Result<Vec<FunctionSummaryJs>> {
    let rt = crate::runtime::get()?;
    let reader = rt.db.reader()?;
    drift_core::call_graph::query_functions_by_file(&reader, &file_path)
        .map_err(to_napi_error)
        .map(|fs| fs.into_iter().map(FunctionSummaryJs::from).collect())
}

/// Get data access points for a function.
#[napi]
pub fn query_data_access(
    function_id: Option<String>,
    table_name: Option<String>,
) -> napi::Result<Vec<DataAccessJs>> {
    let rt = crate::runtime::get()?;
    let reader = rt.db.reader()?;
    drift_core::call_graph::query_data_access(
        &reader, function_id.as_deref(), table_name.as_deref()
    ).map_err(to_napi_error)
    .map(|da| da.into_iter().map(DataAccessJs::from).collect())
}

/// Search functions by name (fuzzy).
#[napi]
pub fn search_functions(
    query: String,
    limit: Option<u32>,
) -> napi::Result<Vec<FunctionSummaryJs>> {
    let rt = crate::runtime::get()?;
    let reader = rt.db.reader()?;
    let lim = limit.unwrap_or(20) as usize;
    drift_core::call_graph::search_functions(&reader, &query, lim)
        .map_err(to_napi_error)
        .map(|fs| fs.into_iter().map(FunctionSummaryJs::from).collect())
}
```

### NAPI Types (What Crosses the Boundary)

```rust
#[napi(object)]
pub struct CallGraphStatsJs {
    pub total_functions: u32,
    pub total_edges: u32,
    pub entry_points: u32,
    pub unresolved_calls: u32,
    pub resolution_rate: f64,
    pub files_processed: u32,
    pub build_duration_ms: u32,
    pub data_access_points: u32,
}

#[napi(object)]
pub struct FunctionSummaryJs {
    pub id: String,
    pub name: String,
    pub file: String,
    pub line: u32,
    pub end_line: u32,
    pub is_entry_point: bool,
    pub is_exported: bool,
    pub language: String,
    pub caller_count: u32,
    pub callee_count: u32,
}

#[napi(object)]
pub struct CallGraphSubset {
    pub center: FunctionSummaryJs,
    pub callers: Vec<CallEdgeJs>,
    pub callees: Vec<CallEdgeJs>,
    pub depth: u32,
}

#[napi(object)]
pub struct CallEdgeJs {
    pub function: FunctionSummaryJs,
    pub resolution: String,
    pub confidence: f64,
    pub call_site_line: u32,
}

#[napi(object)]
pub struct CallPath {
    pub from: String,
    pub to: String,
    pub path: Vec<String>,       // function IDs along the path
    pub depth: u32,
    pub min_confidence: f64,     // lowest confidence edge in the path
}

#[napi(object)]
pub struct EntryPointJs {
    pub function_id: String,
    pub function_name: String,
    pub file: String,
    pub line: u32,
    pub kind: String,
    pub route: Option<String>,
    pub http_method: Option<String>,
    pub confidence: f64,
}

#[napi(object)]
pub struct DataAccessJs {
    pub function_id: String,
    pub function_name: String,
    pub table_name: String,
    pub operation: String,
    pub framework: Option<String>,
    pub line: u32,
    pub confidence: f64,
}

#[napi(object)]
pub struct EntryPointFilter {
    pub kind: Option<String>,
    pub language: Option<String>,
    pub file_pattern: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}
```

---

## 13. Query API (In-Memory Graph Operations)

These are the core graph operations exposed to downstream consumers (reachability, impact,
taint, test topology, etc.). They operate on the in-memory petgraph for performance.

### Forward BFS (Function → What It Calls)

```rust
impl CallGraph {
    /// BFS from a function, returning all reachable functions up to max_depth.
    pub fn forward_reachable(
        &self,
        start: &str,
        max_depth: u32,
    ) -> Result<Vec<ReachableFunction>, CallGraphError> {
        let start_spur = self.interner.get(start)
            .ok_or(CallGraphError::FunctionNotFound { function_id: start.to_string() })?;
        let start_idx = *self.node_index.get(&start_spur)
            .ok_or(CallGraphError::FunctionNotFound { function_id: start.to_string() })?;

        let mut visited = FxHashSet::default();
        let mut queue = VecDeque::new();
        let mut results = Vec::new();

        queue.push_back((start_idx, 0u32));
        visited.insert(start_idx);

        while let Some((node_idx, depth)) = queue.pop_front() {
            if depth > 0 {
                let node = &self.graph[node_idx];
                results.push(ReachableFunction {
                    id: self.interner.resolve(&node.id).to_string(),
                    depth,
                    is_entry_point: node.is_entry_point,
                });
            }

            if depth < max_depth {
                for neighbor in self.graph.neighbors_directed(node_idx, petgraph::Direction::Outgoing) {
                    if visited.insert(neighbor) {
                        queue.push_back((neighbor, depth + 1));
                    }
                }
            }
        }

        Ok(results)
    }

    /// BFS from a function, returning all callers up to max_depth.
    pub fn inverse_reachable(
        &self,
        target: &str,
        max_depth: u32,
    ) -> Result<Vec<ReachableFunction>, CallGraphError> {
        // Same as forward_reachable but with Direction::Incoming
        self.bfs(target, max_depth, petgraph::Direction::Incoming)
    }

    /// Find shortest path between two functions.
    pub fn find_path(
        &self,
        from: &str,
        to: &str,
        max_depth: u32,
    ) -> Result<Option<CallPath>, CallGraphError> {
        let from_spur = self.interner.get(from)
            .ok_or(CallGraphError::FunctionNotFound { function_id: from.to_string() })?;
        let to_spur = self.interner.get(to)
            .ok_or(CallGraphError::FunctionNotFound { function_id: to.to_string() })?;

        let from_idx = *self.node_index.get(&from_spur)
            .ok_or(CallGraphError::FunctionNotFound { function_id: from.to_string() })?;
        let to_idx = *self.node_index.get(&to_spur)
            .ok_or(CallGraphError::FunctionNotFound { function_id: to.to_string() })?;

        // BFS with parent tracking for path reconstruction
        let mut visited: FxHashMap<NodeIndex, NodeIndex> = FxHashMap::default();
        let mut queue = VecDeque::new();
        queue.push_back((from_idx, 0u32));
        visited.insert(from_idx, from_idx); // self-parent for start

        while let Some((node_idx, depth)) = queue.pop_front() {
            if node_idx == to_idx {
                // Reconstruct path
                let path = self.reconstruct_path(&visited, from_idx, to_idx);
                let min_confidence = self.min_confidence_along_path(&path);
                return Ok(Some(CallPath {
                    from: from.to_string(),
                    to: to.to_string(),
                    path: path.iter()
                        .map(|idx| self.interner.resolve(&self.graph[*idx].id).to_string())
                        .collect(),
                    depth,
                    min_confidence,
                }));
            }

            if depth < max_depth {
                for neighbor in self.graph.neighbors_directed(node_idx, petgraph::Direction::Outgoing) {
                    if !visited.contains_key(&neighbor) {
                        visited.insert(neighbor, node_idx);
                        queue.push_back((neighbor, depth + 1));
                    }
                }
            }
        }

        Ok(None) // No path found
    }

    /// Count of entry points in the graph.
    pub fn entry_point_count(&self) -> usize {
        self.graph.node_weights()
            .filter(|n| n.is_entry_point)
            .count()
    }

    /// Get all entry points.
    pub fn entry_points(&self) -> Vec<&FunctionNode> {
        self.graph.node_weights()
            .filter(|n| n.is_entry_point)
            .collect()
    }

    /// Get caller count for a function.
    pub fn caller_count(&self, function_id: &str) -> usize {
        self.lookup_node(function_id)
            .map(|idx| self.graph.neighbors_directed(idx, petgraph::Direction::Incoming).count())
            .unwrap_or(0)
    }

    /// Get callee count for a function.
    pub fn callee_count(&self, function_id: &str) -> usize {
        self.lookup_node(function_id)
            .map(|idx| self.graph.neighbors_directed(idx, petgraph::Direction::Outgoing).count())
            .unwrap_or(0)
    }
}

pub struct ReachableFunction {
    pub id: String,
    pub depth: u32,
    pub is_entry_point: bool,
}
```

### Reachability Result Caching (from A5)

Per A5 recommendation: LRU cache for reachability queries. Critical for MCP tools that
repeatedly query reachability (e.g., `drift_security_reachability` called multiple times
for different functions in the same session).

```rust
use moka::sync::Cache;

pub struct CachedCallGraph {
    graph: CallGraph,
    reachability_cache: Cache<(String, String), Option<CallPath>>,
    forward_cache: Cache<(String, u32), Vec<ReachableFunction>>,
}

impl CachedCallGraph {
    pub fn new(graph: CallGraph) -> Self {
        Self {
            graph,
            reachability_cache: Cache::builder()
                .max_capacity(1000)
                .time_to_live(Duration::from_secs(300)) // 5 min TTL
                .build(),
            forward_cache: Cache::builder()
                .max_capacity(500)
                .time_to_live(Duration::from_secs(300))
                .build(),
        }
    }

    /// Invalidate all caches. Called after call graph rebuild/update.
    pub fn invalidate(&self) {
        self.reachability_cache.invalidate_all();
        self.forward_cache.invalidate_all();
    }
}
```

Cache key: `(source_function, target_function)` for path queries,
`(start_function, max_depth)` for reachability queries.
Invalidate on call graph rebuild or incremental update.

---

## 14. Accuracy Benchmarking (from A5)

Per A5 recommendation: measure call graph accuracy with micro and macro benchmarks
following PyCG methodology.

### Metrics

```rust
pub struct AccuracyMetrics {
    /// Precision: correct_edges / total_edges_produced
    /// (What fraction of edges we produce are actually correct?)
    pub precision: f64,

    /// Recall: correct_edges / total_edges_in_ground_truth
    /// (What fraction of real edges did we find?)
    pub recall: f64,

    /// Resolution rate: resolved_calls / total_calls
    /// (What fraction of call sites did we resolve to at least one target?)
    pub resolution_rate: f64,

    /// Per-strategy breakdown
    pub per_strategy: FxHashMap<Resolution, StrategyMetrics>,

    /// Per-language breakdown
    pub per_language: FxHashMap<Language, LanguageMetrics>,
}

pub struct StrategyMetrics {
    pub count: usize,
    pub precision: f64,
    pub recall: f64,
}

pub struct LanguageMetrics {
    pub functions: usize,
    pub edges: usize,
    pub resolution_rate: f64,
}
```

### Benchmark Corpus

Create a `tests/call_graph_fixtures/` directory with small, well-understood codebases
where the ground truth call graph is manually annotated:

```
tests/call_graph_fixtures/
├── typescript/
│   ├── simple_imports/        # 5 files, known edges
│   ├── class_hierarchy/       # 3 classes with inheritance
│   ├── express_routes/        # Express app with routes
│   └── expected_edges.json    # Ground truth
├── python/
│   ├── django_views/          # Django views with decorators
│   ├── fastapi_deps/          # FastAPI with Depends()
│   └── expected_edges.json
├── java/
│   ├── spring_controllers/    # Spring Boot with DI
│   └── expected_edges.json
└── ...
```

Run accuracy benchmarks as part of CI. Alert if precision or recall drops below thresholds:
- Precision target: >85% (few false edges)
- Recall target: >60% (find most real edges)
- Resolution rate target: >65% overall

---

## 15. Cross-Service Reachability (from A5)

For microservice architectures, extend reachability analysis across service boundaries
via contract matching. This is a Level 2 feature that builds on both the call graph
(Level 1) and contract tracking (Level 2C).

### How It Works

1. Call graph identifies entry points with routes (e.g., `GET /api/users`)
2. Contract tracker identifies frontend API calls (e.g., `fetch('/api/users')`)
3. Cross-service reachability connects: frontend call → backend entry point → backend call graph

```rust
pub struct CrossServiceEdge {
    /// Frontend function making the API call
    pub caller_function: String,
    pub caller_service: String,

    /// Backend entry point handling the request
    pub callee_function: String,
    pub callee_service: String,

    /// The API contract connecting them
    pub contract_id: String,
    pub http_method: String,
    pub path: String,

    /// Confidence based on contract matching
    pub confidence: f64,
}
```

This is NOT part of the core call graph builder. It's a separate engine that consumes
call graph data + contract data. Mentioned here for completeness because the call graph's
entry point detection and route extraction directly feed this capability.

---

## 16. Configuration

```toml
# drift.toml — call graph section

[call_graph]
# Maximum depth for BFS/DFS traversals (default: 20)
max_depth = 20

# Batch size for SQLite writes (default: 500)
batch_size = 500

# Enable fuzzy resolution (default: true, set false to reduce false edges)
enable_fuzzy = true

# Minimum confidence threshold for edges (default: 0.0, keep all)
min_confidence = 0.0

# Maximum functions before falling back to SQLite CTE (default: 500000)
in_memory_threshold = 500000

# Reachability cache size (default: 1000 entries)
reachability_cache_size = 1000

# Reachability cache TTL in seconds (default: 300)
reachability_cache_ttl = 300
```

```rust
#[derive(Deserialize, Default)]
pub struct CallGraphConfig {
    pub max_depth: Option<u32>,
    pub batch_size: Option<usize>,
    pub enable_fuzzy: Option<bool>,
    pub min_confidence: Option<f64>,
    pub in_memory_threshold: Option<usize>,
    pub reachability_cache_size: Option<u64>,
    pub reachability_cache_ttl: Option<u64>,
}

impl CallGraphConfig {
    pub fn max_depth(&self) -> u32 { self.max_depth.unwrap_or(20) }
    pub fn batch_size(&self) -> usize { self.batch_size.unwrap_or(500) }
    pub fn enable_fuzzy(&self) -> bool { self.enable_fuzzy.unwrap_or(true) }
    pub fn min_confidence(&self) -> f64 { self.min_confidence.unwrap_or(0.0) }
    pub fn in_memory_threshold(&self) -> usize { self.in_memory_threshold.unwrap_or(500_000) }
    pub fn reachability_cache_size(&self) -> u64 { self.reachability_cache_size.unwrap_or(1000) }
    pub fn reachability_cache_ttl(&self) -> u64 { self.reachability_cache_ttl.unwrap_or(300) }
}
```


---

## 17. File Module Structure

```
crates/drift-core/src/call_graph/
├── mod.rs              # Public API: build(), update_incremental(), query functions
├── types.rs            # FunctionNode, CallEdge, Resolution, CallGraphStats, etc.
├── graph.rs            # CallGraph struct, petgraph operations, BFS/DFS, path finding
├── extraction.rs       # Per-language call site extraction from ParseResult
├── resolution.rs       # ResolutionIndex, 6 resolution strategies, unified resolver
├── entry_points.rs     # Entry point detection (5 heuristic categories)
├── data_access.rs      # ORM-aware data access extraction
├── persistence.rs      # SQLite read/write, batch writer integration
├── incremental.rs      # Incremental update algorithm
├── cache.rs            # Reachability result caching (Moka)
├── errors.rs           # CallGraphError enum (thiserror)
└── config.rs           # CallGraphConfig
```

### Module Responsibilities

| Module | Responsibility | Key Types |
|--------|---------------|-----------|
| `mod.rs` | Public API surface, orchestrates build pipeline | `build_call_graph()`, `update_incremental()` |
| `types.rs` | All data types, enums, conversion impls | `FunctionNode`, `CallEdge`, `Resolution`, `EntryPoint` |
| `graph.rs` | In-memory graph operations | `CallGraph`, `forward_reachable()`, `find_path()` |
| `extraction.rs` | ParseResult → ExtractedCallSite normalization | `extract_from_parse_result()`, `NormalizedCallSite` |
| `resolution.rs` | Call site → resolved edge mapping | `ResolutionIndex`, `resolve_call_site()` |
| `entry_points.rs` | Entry point detection heuristics | `detect_entry_points()`, `EntryPointKind` |
| `data_access.rs` | ORM pattern matching for data access | `extract_data_access()`, `DataOperation` |
| `persistence.rs` | SQLite CRUD for functions/edges/data_access | `persist_call_graph()`, `load_from_db()` |
| `incremental.rs` | Incremental update logic | `update_incremental()`, `remove_file_data()` |
| `cache.rs` | Moka-based reachability caching | `CachedCallGraph` |
| `errors.rs` | Error types | `CallGraphError` |
| `config.rs` | Configuration | `CallGraphConfig` |

---

## 18. Build Order

The call graph is the first system built after Level 0 bedrock and Level 1 prerequisites.
Exact sequence:

### Prerequisites (Must Exist)

1. **Infrastructure** (Level 0): thiserror, tracing, DriftEventHandler, config
2. **Scanner** (Level 0): file discovery, ScanDiff
3. **Parsers** (Level 0): ParseResult with FunctionInfo, CallSite, ImportInfo, ExportInfo, ClassInfo
4. **Storage** (Level 0): DatabaseManager, batch writer, migration system
5. **String Interning** (Level 1): lasso ThreadedRodeo/RodeoReader
6. **NAPI Bridge** (Level 0): runtime singleton, error propagation

### Call Graph Build Sequence

```
Phase 1 — Types & Errors:
  types.rs — FunctionNode, CallEdge, Resolution, CallGraphStats
  errors.rs — CallGraphError enum
  config.rs — CallGraphConfig

Phase 2 — Extraction:
  extraction.rs — ParseResult → ExtractedCallSite normalization
  data_access.rs — ORM-aware data access extraction
  entry_points.rs — 5 heuristic categories

Phase 3 — Resolution:
  resolution.rs — ResolutionIndex, 6 strategies, unified resolver

Phase 4 — Persistence:
  persistence.rs — SQLite schema (migration 002), read/write functions
  SQL migration file: sql/002_call_graph.sql

Phase 5 — Graph Operations:
  graph.rs — petgraph StableGraph, BFS/DFS, path finding
  cache.rs — Moka reachability cache

Phase 6 — Incremental:
  incremental.rs — Incremental update algorithm

Phase 7 — Pipeline:
  mod.rs — build_call_graph(), update_incremental(), query API

Phase 8 — NAPI:
  napi/call_graph.rs — Command + query functions
```

### Integration Tests

After each phase, write integration tests:
- Phase 2: Test extraction from fixture files (per language)
- Phase 3: Test resolution with known call graphs
- Phase 4: Test SQLite round-trip (write → read → verify)
- Phase 5: Test BFS/DFS on known graphs
- Phase 6: Test incremental update (add/modify/remove files)
- Phase 7: Test full pipeline end-to-end
- Phase 8: Test NAPI functions from TypeScript

---

## 19. v1 Feature Verification — Complete Gap Analysis

Cross-referenced against all v1 call graph documentation:
- `.research/04-call-graph/RECOMMENDATIONS.md` (A5: PyCG, accuracy, cross-service, caching)
- `DRIFT-V2-FULL-SYSTEM-AUDIT.md` (Cat 04: extractors, resolution, analysis engines, storage)
- `05-CALL-GRAPH.md` (research decisions: petgraph, pipeline, resolution, storage, entry points, incremental)
- `DRIFT-V2-STACK-HIERARCHY.md` (Level 1 position, downstream consumers)
- `PLANNING-DRIFT.md` (D1: standalone, D5: events, D6: drift.db, D7: grounding)
- v1 TS implementation references from audit appendix

### v1 Call Graph Features → v2 Status

| v1 Feature | v2 Status | v2 Location |
|-----------|-----------|-------------|
| Per-language extractors (9 langs) | **KEPT** — All 9 languages, extraction from ParseResult | §8 Per-Language Extraction |
| Same-file resolution | **KEPT** — Strategy 1, confidence 0.95 | §5 Strategy 1 |
| Method call resolution | **UPGRADED** — Now includes MRO walk (PyCG approach, A5) | §5 Strategy 2 |
| DI injection resolution | **KEPT** — 5 frameworks (FastAPI, Spring, NestJS, Laravel, ASP.NET) | §5 Strategy 3 |
| Import-based resolution | **KEPT** — Follow import chains | §5 Strategy 4 |
| Export-based resolution | **KEPT** — Match exported names, closest-directory tiebreaker | §5 Strategy 5 |
| Fuzzy resolution | **KEPT** — Name similarity, single-candidate only | §5 Strategy 6 |
| Entry point detection | **UPGRADED** — 5 categories with structured EntryPoint type | §6 Entry Points |
| Route decorator detection | **UPGRADED** — Uses structured DecoratorInfo from parsers | §6 Route Patterns |
| Controller detection | **KEPT** — File path + visibility heuristics | §6 Controller Detection |
| Main function detection | **KEPT** — Per-language patterns | §6 Main Functions |
| SQLite storage | **UPGRADED** — STRICT tables, more indexes, ON DELETE CASCADE | §3 Schema |
| petgraph in-memory graph | **KEPT** — StableGraph with stable indices | §2 Core Data Model |
| Parallel extraction (rayon) | **KEPT** — rayon par_iter with thread_local parsers | §4 Phase 1 |
| Batch writer (crossbeam) | **KEPT** — Crossbeam bounded channel, 500 per batch | §4 Phase 3 |
| Incremental updates | **UPGRADED** — Body hash optimization, cross-file re-resolution | §7 Incremental |
| Forward BFS | **KEPT** — In-memory petgraph BFS | §13 Forward BFS |
| Inverse BFS | **KEPT** — In-memory petgraph BFS (incoming direction) | §13 Inverse BFS |
| Path finding | **KEPT** — BFS with parent tracking, path reconstruction | §13 Path Finding |
| SQLite CTE fallback | **KEPT** — Recursive CTEs for large codebases | §3 Large Codebase Fallback |
| Data access extraction | **KEPT** — ORM-aware, 28+ frameworks | §8 ORM-Aware Extraction |
| Resolution confidence tracking | **KEPT** — Per-edge confidence from resolution strategy | §2 CallEdge |
| Resolution rate tracking | **KEPT** — Stats with per-strategy and per-language breakdown | §2 CallGraphStats |

### v1 Features NOT in Original Research (Gaps Found & Addressed)

| Gap | Source | Resolution | v2 Location |
|-----|--------|------------|-------------|
| MRO-based method resolution | A5 (PyCG approach) | Added: walk class hierarchy for inherited methods | §5 Strategy 2 |
| Accuracy benchmarking | A5 (PyCG methodology) | Added: precision/recall/resolution-rate metrics, fixture corpus | §14 Accuracy Benchmarking |
| Cross-service reachability | A5 (microservice architectures) | Added: contract-based cross-service edges (Level 2 feature) | §15 Cross-Service |
| Reachability result caching | A5 (LRU cache) | Added: Moka cache with TTL, invalidation on rebuild | §13 Caching |
| Body hash optimization | A3 (parsers) | Added: skip re-extraction when body unchanged, preserve cross-file edges when signature unchanged | §7 Body Hash |
| Signature hash for incremental | A3 (parsers) | Added: only re-resolve incoming edges when signature changes | §7 Incremental |
| Structured error types | AD6 (thiserror) | Added: CallGraphError enum with structured variants | §9 Error Handling |
| Tracing instrumentation | AD10 (tracing crate) | Added: per-phase spans, key metrics | §10 Observability |
| Event emissions | D5 (DriftEventHandler) | Added: call graph lifecycle events | §11 Events |
| NAPI command/query split | 03-NAPI-BRIDGE-V2-PREP | Added: command functions (write) + query functions (read) | §12 NAPI |
| Cancellation support | A6/A21 (AtomicBool) | Added: check between files in rayon par_iter | §4 Phase 1 |
| Configuration | 04-INFRASTRUCTURE | Added: CallGraphConfig with TOML section | §16 Configuration |
| Async NAPI with progress | 03-NAPI-BRIDGE-V2-PREP | Added: AsyncTask + ThreadsafeFunction | §12 NAPI |
| Keyset pagination for queries | 02-STORAGE-V2-PREP | Added: cursor-based pagination for entry points, functions | §12 Query Functions |
| Data access confidence | Boundary detection | Added: confidence field on data_access table | §3 Schema |
| Function search | MCP tool requirements | Added: search_functions() for fuzzy name search | §12 Query Functions |

### v1 TS Call Graph Components → v2 Mapping

| v1 TS Component | v2 Status | Notes |
|----------------|-----------|-------|
| `call-graph-builder.ts` | **REPLACED** — Rust `mod.rs` orchestrates full pipeline | TS was orchestration; now Rust does everything |
| `call-graph-extractor.ts` (per-language) | **REPLACED** — Rust `extraction.rs` consumes ParseResult | No per-language TS extractors needed |
| `resolution-engine.ts` | **REPLACED** — Rust `resolution.rs` with 6 strategies | Unified algorithm, not per-language |
| `call-graph-store.ts` (JSON shards) | **ELIMINATED** — SQLite only, no JSON | Per audit: no JSON shards in v2 |
| `call-graph-query.ts` | **REPLACED** — Rust `graph.rs` + NAPI query functions | In-memory petgraph + SQLite queries |
| `reachability-engine.ts` | **MOVED** — Separate Rust engine (Level 2B), not part of call graph builder | Consumes call graph, doesn't live here |
| `impact-analyzer.ts` | **MOVED** — Separate Rust engine (Level 2B) | Consumes call graph |
| `dead-code-detector.ts` | **MOVED** — Separate Rust engine (Level 2B) | Consumes call graph |

### CLI Commands (from audit Cat 10)

The call graph powers these CLI commands:

| Command | What It Does | Call Graph API Used |
|---------|-------------|-------------------|
| `drift callgraph build` | Build/rebuild call graph | `build_call_graph()` |
| `drift callgraph stats` | Show call graph statistics | `query_call_graph_stats()` |
| `drift callgraph entry-points` | List all entry points | `query_entry_points()` |
| `drift callgraph reachability <fn>` | Forward/inverse reachability | `forward_reachable()` / `inverse_reachable()` |
| `drift callgraph impact <fn>` | Impact analysis for a function | Impact analyzer (Level 2B) |
| `drift callgraph dead-code` | Find unreachable functions | Dead code detector (Level 2B) |
| `drift callgraph path <from> <to>` | Find call path between functions | `find_path()` |

### MCP Tools (from audit Cat 07)

| Tool | What It Does | Call Graph API Used |
|------|-------------|-------------------|
| `drift_call_graph` | Query call graph neighborhood | `query_function_calls()` |
| `drift_impact` | Impact analysis | Impact analyzer (Level 2B) |
| `drift_dead_code` | Dead code detection | Dead code detector (Level 2B) |
| `drift_security_reachability` | Security reachability analysis | `forward_reachable()` + boundaries |

---

## 20. Performance Targets

| Scenario | Target | Strategy |
|----------|--------|----------|
| 10K files full build | <1.5s (call graph portion) | 8 threads rayon, batch writer |
| 100K files full build | <8s (call graph portion) | 8 threads rayon, batch writer |
| Incremental (1 file changed) | <100ms | Remove + re-extract + re-resolve changed file only |
| Incremental (10 files changed) | <500ms | Parallel re-extraction, batch re-resolution |
| Incremental (100 files changed) | <2s | Parallel re-extraction, batch re-resolution |
| Forward BFS (depth 5) | <5ms | In-memory petgraph |
| Inverse BFS (depth 5) | <5ms | In-memory petgraph |
| Path finding (depth 10) | <10ms | In-memory petgraph BFS |
| SQLite CTE BFS (depth 5) | <50ms | Recursive CTE with indexes |
| Entry point query | <1ms | Partial index on is_entry_point |
| Function search | <5ms | Index on functions.name |
| Load from SQLite | <500ms for 100K functions | Bulk SELECT, batch node creation |

### Memory Estimates

| Codebase Size | Functions | Edges | petgraph Memory | Total with Indexes |
|--------------|-----------|-------|----------------|-------------------|
| 10K files | ~50K | ~150K | ~30MB | ~50MB |
| 50K files | ~250K | ~750K | ~150MB | ~250MB |
| 100K files | ~500K | ~1.5M | ~300MB | ~500MB |
| 500K files | ~2.5M | ~7.5M | ~1.5GB | Fallback to SQLite CTE |

The `in_memory_threshold` config (default 500K functions) triggers the SQLite CTE fallback
when the graph would exceed reasonable memory bounds.

---

## 21. Open Items / Decisions Still Needed

1. **Dynamic dispatch handling**: Languages with dynamic dispatch (Python, JavaScript, PHP)
   have call sites that can't be statically resolved. Current approach: fuzzy resolution
   as last resort. Alternative: track "possible targets" as multiple edges with lower
   confidence. Decision: start with single-target fuzzy, add multi-target in v2.1 if
   precision metrics show it's needed.

2. **Macro expansion (Rust/C/C++)**: Rust macros and C/C++ preprocessor macros can generate
   function calls that aren't visible in the AST. Current approach: don't extract macro
   invocations. Alternative: expand macros before parsing (requires cargo expand / cpp).
   Decision: skip macros in v2.0. Track as known limitation. Add macro expansion as
   optional post-pass in v2.1.

3. **Higher-order functions**: Functions passed as arguments (callbacks, event handlers)
   create implicit call edges. Current approach: not tracked. Alternative: when a function
   is passed as an argument, create an edge from the receiving function to the passed
   function with low confidence. Decision: add in v2.1 after core resolution is stable.

4. **Monorepo support**: Large monorepos may have multiple packages with internal
   dependencies. Import resolution needs to understand package boundaries (package.json
   exports, go.mod module paths, Cargo.toml workspace members). Decision: handle via
   import-based resolution using package manifest data. The scanner already detects
   11 package managers.

5. **Test function exclusion**: Should test functions be included in the call graph?
   They add noise to reachability/impact analysis but are needed for test topology.
   Decision: include all functions, tag test functions with `is_test: bool`. Downstream
   consumers (reachability, impact) filter out test functions. Test topology includes them.

6. **Watch mode integration**: When `drift scan --watch` detects file changes, should
   the call graph auto-update? Decision: yes, via `update_incremental()` triggered by
   the scanner's `on_scan_complete` event. This is a presentation-layer concern (CLI/IDE),
   not a call graph concern.

---

## 22. Summary of All Decisions

| Decision | Choice | Confidence | Source |
|----------|--------|------------|--------|
| Graph library | petgraph StableGraph | Very High | 05-CALL-GRAPH.md |
| Build pipeline | rayon + crossbeam channel + batch writer | Very High | 05-CALL-GRAPH.md, 02-STORAGE-V2-PREP |
| Resolution algorithm | 6 strategies, unified, highest-confidence-first | High | 05-CALL-GRAPH.md |
| MRO resolution | PyCG approach, walk class hierarchy | High | A5 |
| Storage | Dual: petgraph (in-memory) + SQLite (persistent) | Very High | 05-CALL-GRAPH.md |
| Large codebase fallback | SQLite recursive CTEs for BFS | Medium-High | 05-CALL-GRAPH.md |
| Entry point detection | 5 heuristic categories | High | 05-CALL-GRAPH.md |
| Incremental updates | Remove + re-extract for changed files, body/signature hash optimization | Very High | 05-CALL-GRAPH.md, A3 |
| String interning | lasso (ThreadedRodeo → RodeoReader) | High | AD12 |
| Hash maps | FxHashMap for all internal maps | High | AD12 |
| Small collections | SmallVec<[T; 4]> for function defs per name | Medium-High | AD12 |
| Error handling | thiserror CallGraphError enum | Very High | AD6 |
| Observability | tracing crate, per-phase spans | Very High | AD10 |
| Events | DriftEventHandler with call graph lifecycle events | High | D5 |
| NAPI pattern | Command (write to db) + Query (read from db) | High | 03-NAPI-BRIDGE-V2-PREP |
| Reachability caching | Moka LRU cache, 1000 entries, 5 min TTL | High | A5 |
| Accuracy benchmarking | Precision/recall/resolution-rate, fixture corpus | Medium-High | A5 |
| Configuration | TOML [call_graph] section with sensible defaults | High | 04-INFRASTRUCTURE |
| Cancellation | AtomicBool checked between files in rayon | High | A6/A21 |
| Data access extraction | ORM-aware, 28+ frameworks, alongside call sites | High | Audit Cat 04 |
| Cross-service reachability | Contract-based, Level 2 feature (not in call graph builder) | Medium | A5 |
| Dynamic dispatch | Fuzzy resolution only in v2.0, multi-target in v2.1 | Medium | Open Item 1 |
| Macro expansion | Skip in v2.0, optional post-pass in v2.1 | Medium | Open Item 2 |
| Higher-order functions | Skip in v2.0, add in v2.1 | Medium | Open Item 3 |
| Test function handling | Include all, tag with is_test, consumers filter | High | Open Item 5 |

---

## 23. Cross-System Impact

The call graph is the highest-leverage Level 1 system. Changes here cascade to ~10 downstream systems:

| Consumer | What Changes If Call Graph Changes |
|----------|----------------------------------|
| Reachability | Different paths found, different sensitivity classifications |
| Impact | Different blast radius calculations, different risk scores |
| Dead Code | Different unreachable function sets |
| Taint | Different source→sink paths, different vulnerability findings |
| Test Topology | Different coverage mappings, different minimum test sets |
| Error Handling | Different propagation chains, different unhandled paths |
| N+1 Detection | Different loop→query patterns found |
| Constraints | Different must_precede/must_follow verification results |
| Simulation | Different predicted impact for proposed changes |
| Coupling | Different inter-module dependency measurements |

This is why accuracy benchmarking (§14) is critical. A 5% improvement in call graph
resolution rate directly improves the quality of all 10 downstream systems.

Per D7 (grounding feedback loop): The call graph's accuracy also affects the bridge's
ability to ground Cortex memories. If the call graph says "87% of data access uses
repository pattern" and that number is wrong due to poor resolution, the grounding
loop produces garbage. Get the call graph right and everything downstream benefits.

---

*This document accounts for 100% of v1 call graph features plus all v2 upgrades from
the research documents. Every feature is either KEPT, UPGRADED, MOVED (to a downstream
consumer), or ELIMINATED (with justification). No v1 capability is lost.*

*The call graph is self-contained per D1. It writes to drift.db only. The bridge reads
from drift.db via ATTACH. The grounding loop consumes call graph data but the call graph
has zero knowledge of Cortex.*
