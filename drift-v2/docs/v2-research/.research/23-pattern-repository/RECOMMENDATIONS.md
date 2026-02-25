# 23 Pattern Repository — V2 Recommendations

> **Purpose**: Concrete, actionable recommendations for the v2 pattern repository architecture. Each recommendation is backed by research evidence, prioritized by impact, and assessed for effort and risk. Organized by build phase with dependency tracking.
>
> **Inputs**: AUDIT.md (forensic inventory), RECAP.md (v1 synthesis), RESEARCH.md (external evidence)
>
> **Date**: February 2026

---

## Executive Summary

The pattern repository is Drift's most connected subsystem — every other component either produces or consumes patterns. V1's organic evolution created 6 fragmented storage backends, 3 sync paths, and ~12,000 lines of storage code with no incremental computation, no temporal decay, no Bayesian learning, and no security standards mapping. V2 must rebuild this as a single, Rust-owned, incremental-first pattern repository with enterprise-grade confidence scoring, keyset pagination, connection pooling, and OWASP/CWE compliance.

These 18 recommendations are organized into 4 build phases. Phase 0 (architectural decisions) must be completed before any code. Phase 1 (core repository) is the foundation. Phase 2 (intelligence layer) adds advanced scoring and lifecycle automation. Phase 3 (enterprise features) adds compliance, multi-project, and observability.

**Total estimated effort**: 8-12 weeks for a senior Rust engineer.
**Lines of code eliminated**: ~7,500 (JSON stores, hybrid bridges, sync service, data lake pattern components).
**Lines of code created**: ~4,000-5,000 (Rust pattern repository, confidence engine, NAPI bindings).

---

## Phase 0: Architectural Decisions (Before Code)

### R1: Single Rust-Owned SQLite Database for All Pattern Data

**Priority**: P0 (Critical — load-bearing decision)
**Effort**: Low (decision, not implementation)
**Impact**: Eliminates 6-backend fragmentation, 3 sync paths, ~7,500 lines of dead code

**Current State**:
Patterns are stored across 6 backends: JSON files, SQLite unified store, Data Lake shards, Rust SQLite, Cortex SQLite, and hybrid bridge stores. Three sync paths (JSON→SQLite, SQLite→JSON, bidirectional) create consistency risks. ~12,000 lines of storage code.

**Proposed Change**:
One SQLite database (`drift.db`) owned by Rust. All pattern CRUD operations go through Rust via NAPI. TypeScript gets read-only access for presentation layer queries. No JSON pattern files. No hybrid stores. No sync service.

**Rationale**:
- Eliminates entire classes of bugs (sync failures, partial writes, inconsistent state)
- Reduces storage code by ~60% (7,500 lines removed)
- Enables Rust-level performance optimizations (prepared statement caching, connection pooling, write batching)
- Single source of truth — no "which backend is authoritative?" questions

**Evidence**:
- SQLite WAL mode enables concurrent reads during writes ([§4.1 SQLite Pragma Cheatsheet](https://cj.rs/blog/sqlite-pragma-cheatsheet-for-performance-and-consistency/))
- Connection pooling pattern from sqlite-rwc ([§4.2](https://lib.rs/crates/sqlite-rwc))
- V1's own migration trajectory was already moving toward SQLite-only

**Risks**:
- NAPI bridge becomes a bottleneck if not designed carefully. Mitigate with batch APIs and read-only TS connections.
- Loss of human-readable JSON files for debugging. Mitigate with `drift export --format json` command.

**Dependencies**: None — this is a foundational decision.

---

### R2: STRICT Tables with Enforced Types

**Priority**: P0 (Critical — prevents data integrity bugs)
**Effort**: Trivial
**Impact**: Prevents type confusion bugs that are hard to diagnose

**Current State**:
V1's SQLite tables use default type affinity — TEXT can be stored in INTEGER columns without error.

**Proposed Change**:
All pattern domain tables use the `STRICT` keyword:
```sql
CREATE TABLE patterns (
  id TEXT PRIMARY KEY,
  category TEXT NOT NULL,
  confidence_score REAL NOT NULL DEFAULT 0.0,
  ...
) STRICT;
```

**Rationale**:
- Catches data type errors at write time instead of producing silent corruption
- Aligns SQLite behavior with Rust's strict type system
- Zero performance cost — STRICT only adds a check on INSERT/UPDATE

**Evidence**:
- SQLite STRICT documentation and [§4.1 pragma cheatsheet](https://cj.rs/blog/sqlite-pragma-cheatsheet-for-performance-and-consistency/)

**Risks**: None. Pure improvement.

**Dependencies**: R1 (single database decision).

---

### R3: Connection Pool Architecture

**Priority**: P0 (Critical — enables concurrent access)
**Effort**: Medium
**Impact**: Eliminates read-blocking-on-write bottleneck, enables parallel MCP queries

**Current State**:
V1 uses a single SQLite connection per backend. Reads block during writes. MCP tools queue behind scan writes.

**Proposed Change**:
```rust
pub struct PatternDb {
    writer: Mutex<Connection>,           // Single write connection
    readers: Vec<Mutex<Connection>>,     // N read connections (default: CPU count)
    stmt_cache: bool,                    // Enable prepared statement caching
}
```

All connections open with:
```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA mmap_size = 268435456;  -- 256MB memory-mapped I/O
PRAGMA cache_size = -32000;    -- 32MB page cache
```

On close:
```sql
PRAGMA analysis_limit = 400;
PRAGMA optimize;
```

**Rationale**:
- WAL mode allows concurrent readers with one writer — perfect for Drift's read-heavy workload
- MCP tools (87+ tools, many querying patterns) can execute in parallel without blocking
- Scan writes go through the single writer, serialized by Mutex — no SQLITE_BUSY errors from internal contention

**Evidence**:
- sqlite-rwc connection pool pattern ([§4.2](https://lib.rs/crates/sqlite-rwc))
- SQLite WAL documentation and [pragma cheatsheet](https://cj.rs/blog/sqlite-pragma-cheatsheet-for-performance-and-consistency/)

**Risks**:
- Memory usage increases with reader count. Mitigate with configurable pool size.
- Each reader maintains its own statement cache. Acceptable tradeoff for concurrency.

**Dependencies**: R1.

---

## Phase 1: Core Pattern Repository (Foundation)

### R4: Rust Pattern Repository with NAPI Bindings

**Priority**: P0 (Critical — the core deliverable)
**Effort**: High
**Impact**: All pattern CRUD, querying, and lifecycle management in Rust

**Current State**:
Pattern storage split across PatternStore (JSON, ~1,168 LOC), PatternRepository (SQLite, ~500 LOC), HybridPatternStore (~450 LOC), and IPatternService (~300 LOC) — all TypeScript.

**Proposed Change**:
Single Rust implementation:
```rust
pub struct PatternRepository {
    db: PatternDb,  // Connection pool from R3
}

impl PatternRepository {
    // CRUD
    pub fn create_pattern(&self, pattern: Pattern) -> Result<PatternId>;
    pub fn update_pattern(&self, id: PatternId, changes: PatternUpdate) -> Result<()>;
    pub fn delete_pattern(&self, id: PatternId) -> Result<()>;
    
    // Queries
    pub fn get_by_id(&self, id: PatternId) -> Result<Option<Pattern>>;
    pub fn get_by_file(&self, file: &str) -> Result<Vec<Pattern>>;
    pub fn get_by_category(&self, cat: Category, opts: QueryOpts) -> Result<PatternPage>;
    pub fn search(&self, query: &str, opts: QueryOpts) -> Result<PatternPage>;
    pub fn get_statistics(&self) -> Result<PatternStats>;
    
    // Lifecycle
    pub fn approve(&self, id: PatternId, by: Option<&str>) -> Result<()>;
    pub fn ignore(&self, id: PatternId) -> Result<()>;
    pub fn merge_patterns(&self, ids: &[PatternId], target: PatternId) -> Result<()>;
    
    // Batch operations (for scan pipeline)
    pub fn upsert_batch(&self, patterns: Vec<PatternUpsert>) -> Result<BatchResult>;
    pub fn update_locations_batch(&self, updates: Vec<LocationUpdate>) -> Result<()>;
    
    // Incremental
    pub fn get_patterns_for_files(&self, files: &[&str]) -> Result<Vec<Pattern>>;
    pub fn invalidate_file(&self, file: &str) -> Result<()>;
}
```

NAPI bindings expose all operations to TypeScript:
```typescript
// Generated NAPI bindings
export function createPattern(pattern: JsPattern): JsPatternId;
export function getPatternById(id: string): JsPattern | null;
export function getPatternsByFile(file: string): JsPattern[];
export function getPatternsByCategory(category: string, opts?: JsQueryOpts): JsPatternPage;
export function approvePattern(id: string, by?: string): void;
export function upsertPatternBatch(patterns: JsPatternUpsert[]): JsBatchResult;
// ... etc
```

**Rationale**:
- Single implementation eliminates 3 TS implementations (~2,418 LOC removed)
- Rust ownership enables prepared statement caching, connection pooling, write batching
- NAPI batch APIs minimize bridge crossing overhead for scan pipeline
- Type-safe Rust structs prevent the data integrity issues possible with dynamic TS

**Evidence**:
- V1's own NAPI pattern for call graph (ParallelWriter) proves the architecture works
- rust-analyzer's Rust-owned database pattern ([§1.2](https://rust-analyzer.github.io/blog/2023/07/24/durable-incrementality.html))

**Risks**:
- NAPI bridge complexity. Mitigate with code generation for binding types.
- TS consumers must adapt to async NAPI calls. Mitigate with a thin TS wrapper that preserves the IPatternService interface.

**Dependencies**: R1, R2, R3.

---

### R5: Keyset Pagination for All List Queries

**Priority**: P1 (Important — performance at scale)
**Effort**: Low
**Impact**: O(log n) pagination regardless of depth, stable under concurrent writes

**Current State**:
V1 uses OFFSET/LIMIT which degrades linearly with page depth. MCP's CursorManager uses opaque cursors but backs them with OFFSET queries.

**Proposed Change**:
All list queries use keyset pagination:
```sql
-- Most confident patterns (default sort)
SELECT * FROM patterns
WHERE (confidence_score, id) < (:last_score, :last_id)
ORDER BY confidence_score DESC, id ASC
LIMIT :page_size;

-- Category-filtered
SELECT * FROM patterns
WHERE category = :category
  AND (confidence_score, id) < (:last_score, :last_id)
ORDER BY confidence_score DESC, id ASC
LIMIT :page_size;
```

Cursor encoding: `base64(json({"s": last_score, "i": last_id}))` — opaque to consumers.

**Rationale**:
- OFFSET/LIMIT at page 1000 with 50 rows/page scans 50,000 rows. Keyset scans ~50 rows regardless.
- Stable under concurrent writes — no missed or duplicated patterns when data changes between pages.
- MCP's existing opaque cursor system is preserved — only the backing query changes.

**Evidence**:
- [Keyset pagination benchmarks](https://openillumi.com/en/en-sqlite-limit-offset-slow-fix-seek-method/) showing 100x improvement at depth
- MCP's CursorManager already uses opaque cursors ([§7-mcp RECAP](../07-mcp/RECAP.md))

**Risks**: No "jump to page N" capability. Acceptable — MCP tools use forward-only pagination.

**Dependencies**: R4.

---

### R6: Write Batching via MPSC Channel Pattern

**Priority**: P1 (Important — scan pipeline performance)
**Effort**: Medium
**Impact**: 100x write throughput improvement for scan pipeline

**Current State**:
V1 writes patterns individually. Each INSERT creates its own transaction with filesystem sync (~10ms each). A scan discovering 500 patterns takes ~5 seconds just for writes.

**Proposed Change**:
Generalize v1's ParallelWriter pattern from call graph to patterns:
```rust
pub struct PatternWriter {
    sender: mpsc::Sender<PatternBatch>,
    handle: JoinHandle<Result<WriteStats>>,
}

impl PatternWriter {
    pub fn new(db: &PatternDb) -> Self {
        let (sender, receiver) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            let mut buffer = Vec::with_capacity(500);
            loop {
                match receiver.recv_timeout(Duration::from_millis(100)) {
                    Ok(batch) => {
                        buffer.extend(batch.patterns);
                        if buffer.len() >= 500 {
                            flush_batch(&writer_conn, &mut buffer)?;
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        if !buffer.is_empty() {
                            flush_batch(&writer_conn, &mut buffer)?;
                        }
                    }
                    Err(RecvTimeoutError::Disconnected) => {
                        flush_batch(&writer_conn, &mut buffer)?;
                        break;
                    }
                }
            }
            Ok(stats)
        });
        Self { sender, handle }
    }
}
```

**Rationale**:
- Amortizes transaction overhead: 500 patterns in one transaction = ~10ms instead of ~5 seconds
- Rayon detection workers send results via channel — no synchronization needed
- Dedicated writer thread eliminates contention between detection and persistence

**Evidence**:
- V1's ParallelWriter for call graph proves this pattern works in Drift's architecture
- SQLite transaction batching documentation ([§4.5](https://www.sqlite.org/faq.html))

**Risks**: Buffer loss on crash. Mitigate with flush-on-timeout (100ms) and flush-on-shutdown.

**Dependencies**: R3, R4.


---

### R7: Event Log / Audit Trail Table

**Priority**: P1 (Important — compliance and debugging)
**Effort**: Low
**Impact**: Complete audit trail for every pattern state change, enables time-travel queries

**Current State**:
V1's `pattern_history` table captures basic events (created, updated, approved, ignored, deleted) with JSON old/new values. No guaranteed ordering, no event replay capability, no structured event types, no actor tracking.

**Proposed Change**:
Replace the unstructured history table with a proper event log:
```sql
CREATE TABLE pattern_events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  pattern_id TEXT NOT NULL,
  event_type TEXT NOT NULL,          -- enum: see below
  actor TEXT,                        -- 'system', 'user:<name>', 'detector:<id>'
  payload TEXT,                      -- JSON: event-specific data
  metadata TEXT,                     -- JSON: scan_id, session_id, etc.
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (pattern_id) REFERENCES patterns(id)
) STRICT;

-- Composite index for time-range queries per pattern
CREATE INDEX idx_pattern_events_pattern_time
  ON pattern_events(pattern_id, created_at DESC);

-- Index for event type filtering (compliance reports)
CREATE INDEX idx_pattern_events_type
  ON pattern_events(event_type, created_at DESC);

-- Index for actor-based queries (who changed what)
CREATE INDEX idx_pattern_events_actor
  ON pattern_events(actor, created_at DESC);
```

**Event Types** (exhaustive enum):
```rust
pub enum PatternEvent {
    Discovered {
        detector_id: String,
        initial_confidence: f64,
        location_count: usize,
    },
    ConfidenceUpdated {
        old_score: f64,
        new_score: f64,
        old_level: ConfidenceLevel,
        new_level: ConfidenceLevel,
        reason: String,  // "scan_update", "temporal_decay", "bayesian_update"
    },
    StatusChanged {
        old_status: PatternStatus,
        new_status: PatternStatus,
        reason: String,  // "manual_approval", "auto_approve", "manual_ignore", "auto_archive"
    },
    LocationsUpdated {
        added: usize,
        removed: usize,
        total: usize,
    },
    Merged {
        source_ids: Vec<PatternId>,
        merge_strategy: String,
    },
    SecurityMapped {
        owasp_id: Option<String>,
        cwe_ids: Vec<String>,
    },
    Archived {
        reason: String,  // "confidence_below_threshold", "no_recent_observations", "manual"
    },
    Restored {
        from_status: PatternStatus,
    },
    FalsePositiveReported {
        file: String,
        reporter: String,
    },
}
```

**Rust Implementation**:
```rust
impl PatternRepository {
    /// Append an event to the log. Called internally by all mutation methods.
    fn log_event(
        &self,
        conn: &Connection,
        pattern_id: &PatternId,
        event: &PatternEvent,
        actor: &str,
        metadata: Option<&serde_json::Value>,
    ) -> Result<()> {
        conn.execute_cached(
            "INSERT INTO pattern_events (pattern_id, event_type, actor, payload, metadata)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                pattern_id.as_str(),
                event.type_name(),
                actor,
                serde_json::to_string(event)?,
                metadata.map(|m| serde_json::to_string(m).unwrap_or_default()),
            ],
        )?;
        Ok(())
    }

    /// Query: reconstruct pattern state at a point in time
    pub fn get_pattern_at(
        &self,
        id: &PatternId,
        at: &str,  // ISO 8601 timestamp
    ) -> Result<Option<PatternSnapshot>> {
        let events: Vec<StoredEvent> = self.db.read(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT event_type, payload, created_at FROM pattern_events
                 WHERE pattern_id = ?1 AND created_at <= ?2
                 ORDER BY event_id ASC"
            )?;
            // Replay events to reconstruct state
            stmt.query_map(params![id.as_str(), at], |row| {
                Ok(StoredEvent {
                    event_type: row.get(0)?,
                    payload: row.get(1)?,
                    created_at: row.get(2)?,
                })
            })?.collect::<Result<Vec<_>, _>>()
        })?;
        
        if events.is_empty() {
            return Ok(None);
        }
        Ok(Some(PatternSnapshot::from_events(&events)?))
    }

    /// Query: get timeline for a pattern (for UI display)
    pub fn get_pattern_timeline(
        &self,
        id: &PatternId,
        limit: usize,
    ) -> Result<Vec<TimelineEntry>> {
        self.db.read(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT event_type, actor, payload, created_at FROM pattern_events
                 WHERE pattern_id = ?1
                 ORDER BY created_at DESC
                 LIMIT ?2"
            )?;
            stmt.query_map(params![id.as_str(), limit], |row| {
                Ok(TimelineEntry {
                    event_type: row.get(0)?,
                    actor: row.get(1)?,
                    payload: row.get(2)?,
                    timestamp: row.get(3)?,
                })
            })?.collect::<Result<Vec<_>, _>>()
        })
    }
}
```

**Rationale**:
- Every mutation to a pattern is recorded with who, what, when, and why
- Time-travel queries enable "show me the state of patterns as of last Tuesday" — critical for regression debugging
- Actor tracking enables compliance: "who approved this pattern?" and "which detector discovered this?"
- Event replay enables future CQRS migration (Phase 2+) without schema changes
- Structured event types (Rust enum) prevent the untyped JSON blob problem in v1

**Evidence**:
- Event Sourcing pattern in Rust ([§5.1](https://softwarepatternslexicon.com/rust/microservices-design-patterns/event-sourcing-and-cqrs/))
- CQRS with cqrs-es ([§5.2](https://doc.rust-cqrs.org/))
- V1's pattern_history table proves the need — v2 formalizes it

**Risks**:
- Event table grows unbounded. Mitigate with periodic compaction: archive events older than 90 days to a separate `pattern_events_archive` table.
- Event replay performance for long-lived patterns. Mitigate with periodic snapshots stored alongside events.

**Dependencies**: R1, R2, R4.

---

## Phase 2: Intelligence Layer (Advanced Scoring & Lifecycle)

### R8: Bayesian Confidence Scoring with Beta Distribution

**Priority**: P1 (Important — replaces v1's static formula)
**Effort**: Medium
**Impact**: Principled confidence that improves with evidence, handles cold-start naturally

**Current State**:
V1 uses a fixed weighted formula: `score = freq×0.40 + consistency×0.30 + age×0.15 + spread×0.15`. No learning. No uncertainty quantification. A pattern with 3 observations and one with 3,000 observations can have the same score.

**Proposed Change**:
Model each pattern's confidence as a Beta distribution:
```rust
/// Bayesian confidence model using Beta distribution.
/// Beta(α, β) is the conjugate prior for binomial observations.
pub struct BayesianConfidence {
    /// Count of files where pattern is present (successes)
    alpha: f64,
    /// Count of files where pattern is absent (failures)
    beta: f64,
    /// Prior strength — how much weight the prior carries
    prior_alpha: f64,
    prior_beta: f64,
}

impl BayesianConfidence {
    /// Create with uninformative prior Beta(1, 1) = Uniform[0, 1]
    pub fn new() -> Self {
        Self {
            alpha: 1.0,
            beta: 1.0,
            prior_alpha: 1.0,
            prior_beta: 1.0,
        }
    }

    /// Create with informative prior (e.g., for security patterns
    /// where we expect ~30% prevalence)
    pub fn with_prior(expected_rate: f64, strength: f64) -> Self {
        let prior_alpha = expected_rate * strength;
        let prior_beta = (1.0 - expected_rate) * strength;
        Self {
            alpha: prior_alpha,
            beta: prior_beta,
            prior_alpha,
            prior_beta,
        }
    }

    /// Update with new scan observations
    pub fn update(&mut self, files_present: usize, files_absent: usize) {
        self.alpha += files_present as f64;
        self.beta += files_absent as f64;
    }

    /// Point estimate: posterior mean = α / (α + β)
    pub fn point_estimate(&self) -> f64 {
        self.alpha / (self.alpha + self.beta)
    }

    /// Uncertainty: width of 95% credible interval
    /// Narrow interval = high certainty, wide = uncertain
    pub fn uncertainty(&self) -> f64 {
        let n = self.alpha + self.beta;
        // Approximation of Beta distribution 95% CI width
        // Exact would use incomplete beta function
        let std_dev = (self.alpha * self.beta / (n * n * (n + 1.0))).sqrt();
        3.92 * std_dev  // ~2 × 1.96 standard deviations
    }

    /// Total observations (excluding prior)
    pub fn observation_count(&self) -> f64 {
        (self.alpha - self.prior_alpha) + (self.beta - self.prior_beta)
    }

    /// Confidence level based on BOTH point estimate AND uncertainty
    pub fn level(&self) -> ConfidenceLevel {
        let point = self.point_estimate();
        let uncertainty = self.uncertainty();
        let observations = self.observation_count();

        match (point, uncertainty, observations as usize) {
            // High: strong evidence, narrow interval, sufficient observations
            (p, u, n) if p >= 0.80 && u < 0.15 && n >= 20 => ConfidenceLevel::High,
            // Medium: moderate evidence or moderate uncertainty
            (p, u, n) if p >= 0.60 && u < 0.25 && n >= 10 => ConfidenceLevel::Medium,
            // Low: some evidence but wide uncertainty
            (p, _, n) if p >= 0.40 && n >= 5 => ConfidenceLevel::Low,
            // Uncertain: insufficient evidence
            _ => ConfidenceLevel::Uncertain,
        }
    }
}
```

**Storage Schema**:
```sql
-- Add Bayesian columns to patterns table
ALTER TABLE patterns ADD COLUMN bayes_alpha REAL NOT NULL DEFAULT 1.0;
ALTER TABLE patterns ADD COLUMN bayes_beta REAL NOT NULL DEFAULT 1.0;
ALTER TABLE patterns ADD COLUMN bayes_uncertainty REAL NOT NULL DEFAULT 1.0;
ALTER TABLE patterns ADD COLUMN observation_count INTEGER NOT NULL DEFAULT 0;
```

**Integration with Scan Pipeline**:
```rust
impl PatternRepository {
    /// Called after each scan completes for a set of files
    pub fn update_confidence_bayesian(
        &self,
        scan_results: &ScanResults,
    ) -> Result<Vec<ConfidenceChange>> {
        let mut changes = Vec::new();
        
        for pattern in self.get_active_patterns()? {
            let files_scanned = scan_results.files_scanned();
            let files_with_pattern = scan_results
                .files_matching_pattern(&pattern.id)
                .len();
            let files_without = files_scanned - files_with_pattern;
            
            let mut bayes = BayesianConfidence {
                alpha: pattern.bayes_alpha,
                beta: pattern.bayes_beta,
                prior_alpha: 1.0,
                prior_beta: 1.0,
            };
            
            let old_score = bayes.point_estimate();
            let old_level = bayes.level();
            
            bayes.update(files_with_pattern, files_without);
            
            let new_score = bayes.point_estimate();
            let new_level = bayes.level();
            
            if old_level != new_level {
                changes.push(ConfidenceChange {
                    pattern_id: pattern.id.clone(),
                    old_score,
                    new_score,
                    old_level,
                    new_level,
                });
            }
            
            self.update_pattern_confidence(
                &pattern.id,
                bayes.alpha,
                bayes.beta,
                new_score,
                bayes.uncertainty(),
                bayes.observation_count() as i64,
                new_level,
            )?;
        }
        
        Ok(changes)
    }
}
```

**Rationale**:
- Beta distribution is the mathematically correct model for "pattern present/absent" binary observations
- Naturally handles cold-start: new patterns have wide uncertainty (Beta(1,1) = uniform), which narrows as evidence accumulates
- A pattern seen in 3/3 files gets score 0.75 with high uncertainty. A pattern seen in 300/400 files gets score 0.75 with low uncertainty. V1 can't distinguish these.
- Progressive confidence tiers (from §3.2) use posterior width, not just point estimate — preventing premature auto-approval of low-observation patterns
- Informative priors allow category-specific expectations: security patterns might have Beta(3, 7) prior (expect ~30% prevalence), while structural patterns might have Beta(7, 3) prior (expect ~70% prevalence)

**Evidence**:
- Bayesian confidence calibration ([§3.1](https://arxiv.org/abs/2109.10092))
- Progressive Bayesian confidence architecture ([§3.2](https://arxiv.org/abs/2601.03299))
- Beta distribution as conjugate prior for binomial — standard statistical result

**Risks**:
- Computational cost of Beta distribution operations. Mitigate: all operations are O(1) arithmetic — no iterative computation needed.
- Migration from v1 scores. Mitigate: initialize Beta parameters from v1 data: α = locations_count, β = max(1, total_files - locations_count).

**Dependencies**: R4, R7 (events log confidence changes).

---

### R9: Temporal Confidence Decay with Half-Life Model

**Priority**: P1 (Important — prevents stale patterns)
**Effort**: Medium
**Impact**: Patterns that aren't re-observed gradually lose confidence, creating natural review pressure

**Current State**:
V1 has zero temporal decay. A pattern discovered 2 years ago with no recent observations maintains full confidence. The `ageFactor` in v1's formula actually *increases* confidence with age — the opposite of what's needed.

**Proposed Change**:
Apply exponential decay to observation weights using configurable half-lives:
```rust
/// Temporal decay model using half-life exponential decay.
/// weight(t) = 2^(-t / half_life)
pub struct TemporalDecay {
    /// Category-specific half-lives in days
    half_lives: HashMap<PatternCategory, f64>,
    /// Default half-life for unconfigured categories
    default_half_life: f64,
}

impl TemporalDecay {
    pub fn new() -> Self {
        let mut half_lives = HashMap::new();
        // Security practices evolve quickly
        half_lives.insert(PatternCategory::Security, 180.0);
        half_lives.insert(PatternCategory::Auth, 180.0);
        // API patterns change with framework updates
        half_lives.insert(PatternCategory::Api, 120.0);
        half_lives.insert(PatternCategory::Contracts, 120.0);
        // Performance patterns shift with runtime updates
        half_lives.insert(PatternCategory::Performance, 150.0);
        // Structural/styling conventions are stable
        half_lives.insert(PatternCategory::Structural, 365.0);
        half_lives.insert(PatternCategory::Styling, 365.0);
        half_lives.insert(PatternCategory::Components, 365.0);
        // Testing patterns evolve moderately
        half_lives.insert(PatternCategory::Testing, 270.0);
        // Type system patterns are very stable
        half_lives.insert(PatternCategory::Types, 365.0);
        
        Self {
            half_lives,
            default_half_life: 270.0,  // 9 months default
        }
    }

    /// Calculate decay weight for an observation at a given age
    pub fn weight(&self, category: &PatternCategory, days_old: f64) -> f64 {
        let half_life = self.half_lives
            .get(category)
            .copied()
            .unwrap_or(self.default_half_life);
        
        2.0_f64.powf(-days_old / half_life)
    }

    /// Apply decay to Bayesian parameters
    /// Decayed α and β represent the "effective" observation counts
    pub fn apply_to_bayesian(
        &self,
        bayes: &BayesianConfidence,
        category: &PatternCategory,
        observation_ages: &[(f64, bool)],  // (days_old, was_present)
    ) -> BayesianConfidence {
        let mut decayed_alpha = bayes.prior_alpha;
        let mut decayed_beta = bayes.prior_beta;
        
        for &(days_old, was_present) in observation_ages {
            let w = self.weight(category, days_old);
            if was_present {
                decayed_alpha += w;
            } else {
                decayed_beta += w;
            }
        }
        
        BayesianConfidence {
            alpha: decayed_alpha,
            beta: decayed_beta,
            prior_alpha: bayes.prior_alpha,
            prior_beta: bayes.prior_beta,
        }
    }
}
```

**Storage Schema**:
```sql
-- Track individual observations for decay calculation
CREATE TABLE pattern_observations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pattern_id TEXT NOT NULL,
  file_path TEXT NOT NULL,
  observed_at TEXT NOT NULL DEFAULT (datetime('now')),
  was_present INTEGER NOT NULL,  -- 1 = pattern found, 0 = pattern absent
  scan_id TEXT,                  -- Links to scan session
  FOREIGN KEY (pattern_id) REFERENCES patterns(id)
) STRICT;

CREATE INDEX idx_pattern_obs_pattern_time
  ON pattern_observations(pattern_id, observed_at DESC);

-- Periodic decay recalculation results
ALTER TABLE patterns ADD COLUMN decayed_score REAL;
ALTER TABLE patterns ADD COLUMN last_decay_at TEXT;
ALTER TABLE patterns ADD COLUMN last_observed_at TEXT;
```

**Decay Recalculation** (runs periodically or on-demand):
```rust
impl PatternRepository {
    /// Recalculate decayed confidence for all active patterns.
    /// Called daily by scheduler or on-demand before quality gate checks.
    pub fn recalculate_decay(&self) -> Result<DecayReport> {
        let decay = TemporalDecay::new();
        let now = Utc::now();
        let mut report = DecayReport::default();
        
        for pattern in self.get_active_patterns()? {
            let observations = self.get_observations(&pattern.id)?;
            let aged_obs: Vec<(f64, bool)> = observations.iter().map(|obs| {
                let age = (now - obs.observed_at).num_days() as f64;
                (age, obs.was_present)
            }).collect();
            
            let decayed = decay.apply_to_bayesian(
                &pattern.bayesian_confidence(),
                &pattern.category,
                &aged_obs,
            );
            
            let old_level = pattern.confidence_level;
            let new_level = decayed.level();
            
            if old_level != new_level {
                report.level_changes.push(LevelChange {
                    pattern_id: pattern.id.clone(),
                    old_level,
                    new_level,
                });
                
                // Auto-archive if decayed below threshold
                if new_level == ConfidenceLevel::Uncertain
                    && pattern.status == PatternStatus::Discovered
                {
                    self.archive_pattern(&pattern.id, "confidence_decay")?;
                    report.archived += 1;
                }
            }
            
            self.update_decayed_score(
                &pattern.id,
                decayed.point_estimate(),
                &now.to_rfc3339(),
            )?;
            report.patterns_processed += 1;
        }
        
        Ok(report)
    }
}
```

**Rationale**:
- Prevents stale patterns from polluting results — a pattern not seen in 2 years shouldn't have high confidence
- Category-specific half-lives reflect reality: security practices evolve faster than naming conventions
- Exponential decay is smooth and predictable — no cliff edges where confidence suddenly drops
- Creates natural review pressure: patterns must be re-observed to maintain confidence
- Integrates cleanly with Bayesian model (R8): decay reduces effective observation counts

**Evidence**:
- Temporal confidence decay with half-life models ([§3.3](https://www.researchgate.net/publication/319109840))
- HALO — half-life based fact filtering ([§3.4](https://arxiv.org/abs/2505.07509))
- V1's age factor actually rewards age — the inverse of what's needed

**Risks**:
- Observation table grows large. Mitigate: compact old observations into summary rows (e.g., "2024-Q1: 45 present, 12 absent") after 90 days.
- Decay recalculation cost. Mitigate: run incrementally — only recalculate patterns whose last_decay_at is older than 24 hours.

**Dependencies**: R4, R7, R8.

---

### R10: Pattern Momentum Signal

**Priority**: P2 (Nice to have — enhances pattern discovery UX)
**Effort**: Low
**Impact**: Surfaces rapidly growing patterns for early attention

**Current State**:
V1 has no momentum signal. A pattern that appeared in 2 files last week and 50 files this week looks the same as a pattern that's been in 50 files for a year. Users can't distinguish emerging conventions from established ones.

**Proposed Change**:
Calculate a momentum score based on observation velocity:
```rust
/// Pattern momentum: rate of change in observation frequency.
/// Positive momentum = pattern is spreading. Negative = pattern is declining.
pub struct PatternMomentum;

impl PatternMomentum {
    /// Calculate momentum as the slope of observation frequency over recent windows.
    /// Uses two time windows: recent (7 days) vs baseline (30 days).
    pub fn calculate(
        observations: &[PatternObservation],
        now: DateTime<Utc>,
    ) -> MomentumScore {
        let recent_window = Duration::days(7);
        let baseline_window = Duration::days(30);
        
        let recent_obs = observations.iter()
            .filter(|o| now - o.observed_at < recent_window)
            .count() as f64;
        let recent_present = observations.iter()
            .filter(|o| now - o.observed_at < recent_window && o.was_present)
            .count() as f64;
        
        let baseline_obs = observations.iter()
            .filter(|o| now - o.observed_at < baseline_window)
            .count() as f64;
        let baseline_present = observations.iter()
            .filter(|o| now - o.observed_at < baseline_window && o.was_present)
            .count() as f64;
        
        if baseline_obs < 5.0 {
            return MomentumScore::InsufficientData;
        }
        
        let recent_rate = if recent_obs > 0.0 {
            recent_present / recent_obs
        } else {
            0.0
        };
        let baseline_rate = baseline_present / baseline_obs;
        
        let velocity = recent_rate - baseline_rate;
        
        // Normalize to [-1.0, 1.0] range
        let normalized = velocity.clamp(-1.0, 1.0);
        
        match normalized {
            v if v > 0.2 => MomentumScore::Rising(normalized),
            v if v < -0.2 => MomentumScore::Declining(normalized),
            _ => MomentumScore::Stable(normalized),
        }
    }
}

#[derive(Debug, Clone)]
pub enum MomentumScore {
    Rising(f64),       // Pattern is spreading (positive velocity)
    Stable(f64),       // Pattern is steady
    Declining(f64),    // Pattern is fading (negative velocity)
    InsufficientData,  // Not enough observations
}
```

**Storage**:
```sql
ALTER TABLE patterns ADD COLUMN momentum REAL DEFAULT 0.0;
ALTER TABLE patterns ADD COLUMN momentum_label TEXT DEFAULT 'stable';
```

**Rationale**:
- Surfaces emerging conventions early — a pattern spreading rapidly across files is likely a new team convention being adopted
- Identifies declining patterns — a pattern losing presence may indicate a convention being abandoned
- Enables smart notifications: "Pattern X is spreading rapidly — consider approving it"
- Low effort: simple arithmetic on existing observation data

**Evidence**:
- V1's degradation tracking (7-day rolling averages) is a primitive version of this — v2 formalizes it
- SonarQube's trend analysis ([§8.1](https://www.augmentcode.com/guides/static-code-analysis-best-practices-enterprise))

**Risks**: Noisy for small codebases. Mitigate: require minimum 5 baseline observations before calculating momentum.

**Dependencies**: R9 (uses observation data).


---

### R11: Automatic Pattern Merging

**Priority**: P2 (Nice to have — reduces noise)
**Effort**: Medium
**Impact**: Eliminates duplicate patterns from different detectors, reduces pattern count by estimated 10-20%

**Current State**:
V1's AuditEngine detects duplicates using Jaccard similarity > 0.85 on location sets, but only reports them — no automatic merging. Multiple detectors can discover the same convention independently (e.g., a naming convention detected by both the structural detector and the documentation detector), creating duplicate patterns that confuse users and inflate counts.

**Proposed Change**:
Implement automatic pattern merging with configurable strategies:
```rust
/// Pattern merge engine. Identifies and merges duplicate patterns
/// based on location overlap and semantic similarity.
pub struct PatternMerger {
    /// Minimum Jaccard similarity on location sets to consider merge
    location_threshold: f64,
    /// Minimum name/description similarity (normalized Levenshtein)
    semantic_threshold: f64,
    /// Whether to auto-merge or just suggest
    auto_merge: bool,
}

impl PatternMerger {
    pub fn new() -> Self {
        Self {
            location_threshold: 0.80,
            semantic_threshold: 0.70,
            auto_merge: false,  // Default: suggest only
        }
    }

    /// Find merge candidates among active patterns.
    pub fn find_candidates(
        &self,
        patterns: &[Pattern],
    ) -> Vec<MergeCandidate> {
        let mut candidates = Vec::new();
        
        // Build location index: file → set of pattern IDs
        let mut file_index: HashMap<&str, HashSet<&PatternId>> = HashMap::new();
        for pattern in patterns {
            for loc in &pattern.locations {
                file_index.entry(loc.file.as_str())
                    .or_default()
                    .insert(&pattern.id);
            }
        }
        
        // Find patterns that share files (pre-filter for Jaccard)
        let mut checked: HashSet<(&PatternId, &PatternId)> = HashSet::new();
        for pattern_ids in file_index.values() {
            for &id_a in pattern_ids {
                for &id_b in pattern_ids {
                    if id_a >= id_b { continue; }
                    if checked.contains(&(id_a, id_b)) { continue; }
                    checked.insert((id_a, id_b));
                    
                    let a = patterns.iter().find(|p| &p.id == id_a).unwrap();
                    let b = patterns.iter().find(|p| &p.id == id_b).unwrap();
                    
                    let jaccard = self.jaccard_similarity(
                        &a.location_files(),
                        &b.location_files(),
                    );
                    
                    if jaccard >= self.location_threshold {
                        let semantic = self.semantic_similarity(a, b);
                        if semantic >= self.semantic_threshold {
                            candidates.push(MergeCandidate {
                                pattern_a: id_a.clone(),
                                pattern_b: id_b.clone(),
                                location_similarity: jaccard,
                                semantic_similarity: semantic,
                                suggested_target: self.pick_target(a, b),
                            });
                        }
                    }
                }
            }
        }
        
        candidates.sort_by(|a, b| b.location_similarity
            .partial_cmp(&a.location_similarity)
            .unwrap_or(std::cmp::Ordering::Equal));
        candidates
    }

    /// Execute a merge: combine source patterns into target.
    pub fn merge(
        &self,
        repo: &PatternRepository,
        target_id: &PatternId,
        source_ids: &[PatternId],
    ) -> Result<MergeResult> {
        let target = repo.get_by_id(target_id)?
            .ok_or_else(|| Error::NotFound(target_id.clone()))?;
        
        let mut merged_locations = target.locations.clone();
        let mut merged_examples = Vec::new();
        let mut total_observations = 0u64;
        
        for source_id in source_ids {
            let source = repo.get_by_id(source_id)?
                .ok_or_else(|| Error::NotFound(source_id.clone()))?;
            
            // Merge locations (deduplicate by file+line)
            for loc in &source.locations {
                if !merged_locations.iter().any(|l| l.file == loc.file && l.line == loc.line) {
                    merged_locations.push(loc.clone());
                }
            }
            
            // Merge examples
            merged_examples.extend(repo.get_examples(source_id)?);
            
            // Sum observations for Bayesian update
            total_observations += source.observation_count;
            
            // Archive source pattern with merge reference
            repo.archive_pattern(source_id, &format!("merged_into:{}", target_id))?;
        }
        
        // Update target with merged data
        repo.update_locations(target_id, &merged_locations)?;
        repo.add_examples(target_id, &merged_examples)?;
        
        // Log merge event
        repo.log_event(
            target_id,
            &PatternEvent::Merged {
                source_ids: source_ids.to_vec(),
                merge_strategy: "location_overlap".into(),
            },
            "system:merger",
            None,
        )?;
        
        Ok(MergeResult {
            target_id: target_id.clone(),
            sources_archived: source_ids.len(),
            locations_added: merged_locations.len() - target.locations.len(),
            examples_added: merged_examples.len(),
        })
    }

    /// Pick the better pattern as merge target.
    /// Prefers: higher confidence > more locations > approved status > older pattern.
    fn pick_target<'a>(&self, a: &'a Pattern, b: &'a Pattern) -> &'a PatternId {
        if a.status == PatternStatus::Approved && b.status != PatternStatus::Approved {
            return &a.id;
        }
        if b.status == PatternStatus::Approved && a.status != PatternStatus::Approved {
            return &b.id;
        }
        if a.confidence_score > b.confidence_score {
            &a.id
        } else if b.confidence_score > a.confidence_score {
            &b.id
        } else if a.locations.len() >= b.locations.len() {
            &a.id
        } else {
            &b.id
        }
    }

    fn jaccard_similarity(&self, a: &HashSet<&str>, b: &HashSet<&str>) -> f64 {
        let intersection = a.intersection(b).count() as f64;
        let union = a.union(b).count() as f64;
        if union == 0.0 { 0.0 } else { intersection / union }
    }

    fn semantic_similarity(&self, a: &Pattern, b: &Pattern) -> f64 {
        // Normalized Levenshtein distance on name + category
        let name_sim = 1.0 - strsim::normalized_levenshtein(&a.name, &b.name);
        let cat_match = if a.category == b.category { 1.0 } else { 0.0 };
        name_sim * 0.6 + cat_match * 0.4
    }
}
```

**Rationale**:
- V1's audit engine already identifies duplicates but can't act on them — v2 closes the loop
- Multiple detectors discovering the same convention is expected behavior (different detection strategies converge on the same truth) — merging is the correct response
- Merged patterns have stronger evidence (combined observations) and cleaner presentation (one pattern instead of three)
- Archive-based merging preserves history — source patterns aren't deleted, just archived with a merge reference

**Evidence**:
- V1's AuditEngine Jaccard similarity detection (RECAP §Audit Engine)
- SonarQube's rule deduplication across quality profiles ([§2.1](https://docs.sonarsource.com/sonarqube-server/2025.4/user-guide/rules/overview))

**Risks**:
- False merges (two genuinely different patterns with overlapping locations). Mitigate: require both location AND semantic similarity thresholds. Default to suggest-only mode.
- Merge cascades (A merges into B, then B merges into C). Mitigate: run merge detection in a single pass, not iteratively.

**Dependencies**: R4, R7, R8.

---

### R12: Pattern Lifecycle Automation

**Priority**: P2 (Nice to have — reduces manual curation burden)
**Effort**: Medium
**Impact**: Auto-approve high-confidence patterns, auto-archive stale ones, reducing manual review by ~60%

**Current State**:
V1's AuditEngine recommends auto-approval for patterns with confidence ≥ 0.90, outlierRatio ≤ 0.50, and locations ≥ 3. But it only recommends — a human must still approve. No auto-archival of stale patterns. No lifecycle state machine enforcement.

**Proposed Change**:
Formalize the pattern lifecycle as an automated state machine with configurable policies:
```rust
/// Pattern lifecycle automation engine.
/// Evaluates patterns against configurable policies and executes transitions.
pub struct LifecycleEngine {
    policies: LifecyclePolicies,
}

#[derive(Debug, Clone)]
pub struct LifecyclePolicies {
    /// Auto-approve: pattern must meet ALL criteria
    pub auto_approve: AutoApprovePolicy,
    /// Auto-archive: pattern must meet ANY criteria
    pub auto_archive: AutoArchivePolicy,
    /// Review triggers: conditions that flag patterns for human review
    pub review_triggers: ReviewTriggerPolicy,
}

#[derive(Debug, Clone)]
pub struct AutoApprovePolicy {
    pub enabled: bool,
    /// Minimum Bayesian point estimate
    pub min_confidence: f64,
    /// Maximum Bayesian uncertainty (credible interval width)
    pub max_uncertainty: f64,
    /// Minimum observation count
    pub min_observations: usize,
    /// Maximum outlier ratio (outliers / total locations)
    pub max_outlier_ratio: f64,
    /// Minimum number of distinct files
    pub min_file_count: usize,
    /// Minimum age in days (prevent premature approval)
    pub min_age_days: u32,
    /// Categories excluded from auto-approve (require human review)
    pub excluded_categories: Vec<PatternCategory>,
}

impl Default for AutoApprovePolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            min_confidence: 0.85,
            max_uncertainty: 0.12,
            min_observations: 25,
            max_outlier_ratio: 0.15,
            min_file_count: 5,
            min_age_days: 7,
            excluded_categories: vec![
                PatternCategory::Security,  // Security patterns always need human review
                PatternCategory::Auth,      // Auth patterns always need human review
            ],
        }
    }
}

#[derive(Debug, Clone)]
pub struct AutoArchivePolicy {
    pub enabled: bool,
    /// Archive if confidence drops below this after decay
    pub min_confidence: f64,
    /// Archive if not observed for this many days
    pub max_days_without_observation: u32,
    /// Archive if observation count is below this AND age > min_age_days
    pub min_observations_for_age: usize,
    pub min_age_days_for_observation_check: u32,
}

impl Default for AutoArchivePolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            min_confidence: 0.20,
            max_days_without_observation: 180,
            min_observations_for_age: 3,
            min_age_days_for_observation_check: 30,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReviewTriggerPolicy {
    /// Flag for review if confidence dropped by more than this in one scan
    pub confidence_drop_threshold: f64,
    /// Flag for review if momentum is declining rapidly
    pub declining_momentum_threshold: f64,
    /// Flag for review if outlier ratio exceeds this
    pub high_outlier_ratio: f64,
}

impl Default for ReviewTriggerPolicy {
    fn default() -> Self {
        Self {
            confidence_drop_threshold: 0.15,
            declining_momentum_threshold: -0.4,
            high_outlier_ratio: 0.40,
        }
    }
}

impl LifecycleEngine {
    pub fn new(policies: LifecyclePolicies) -> Self {
        Self { policies }
    }

    /// Evaluate all active patterns and execute lifecycle transitions.
    /// Returns a report of all transitions made.
    pub fn evaluate(
        &self,
        repo: &PatternRepository,
    ) -> Result<LifecycleReport> {
        let mut report = LifecycleReport::default();
        let patterns = repo.get_active_patterns()?;
        
        for pattern in &patterns {
            // Check auto-approve
            if pattern.status == PatternStatus::Discovered
                && self.should_auto_approve(pattern)
            {
                repo.approve(&pattern.id, Some("system:lifecycle"))?;
                report.auto_approved.push(pattern.id.clone());
                continue;
            }
            
            // Check auto-archive
            if pattern.status == PatternStatus::Discovered
                && self.should_auto_archive(pattern)
            {
                repo.archive_pattern(
                    &pattern.id,
                    &self.archive_reason(pattern),
                )?;
                report.auto_archived.push(pattern.id.clone());
                continue;
            }
            
            // Check review triggers
            if let Some(reason) = self.should_flag_for_review(pattern) {
                report.flagged_for_review.push((pattern.id.clone(), reason));
            }
        }
        
        Ok(report)
    }

    fn should_auto_approve(&self, pattern: &Pattern) -> bool {
        let policy = &self.policies.auto_approve;
        if !policy.enabled { return false; }
        if policy.excluded_categories.contains(&pattern.category) { return false; }
        
        pattern.confidence_score >= policy.min_confidence
            && pattern.bayes_uncertainty <= policy.max_uncertainty
            && pattern.observation_count >= policy.min_observations
            && pattern.outlier_ratio() <= policy.max_outlier_ratio
            && pattern.file_count() >= policy.min_file_count
            && pattern.age_days() >= policy.min_age_days
    }

    fn should_auto_archive(&self, pattern: &Pattern) -> bool {
        let policy = &self.policies.auto_archive;
        if !policy.enabled { return false; }
        
        // Confidence too low after decay
        if pattern.decayed_score.unwrap_or(pattern.confidence_score)
            < policy.min_confidence
        {
            return true;
        }
        
        // Not observed recently
        if let Some(last_obs) = &pattern.last_observed_at {
            let days_since = days_since_timestamp(last_obs);
            if days_since > policy.max_days_without_observation as f64 {
                return true;
            }
        }
        
        // Too few observations for age
        if pattern.age_days() >= policy.min_age_days_for_observation_check
            && pattern.observation_count < policy.min_observations_for_age
        {
            return true;
        }
        
        false
    }

    fn should_flag_for_review(&self, pattern: &Pattern) -> Option<String> {
        let triggers = &self.policies.review_triggers;
        
        if let Some(momentum) = pattern.momentum {
            if momentum < triggers.declining_momentum_threshold {
                return Some(format!(
                    "Rapidly declining momentum: {:.2}",
                    momentum
                ));
            }
        }
        
        if pattern.outlier_ratio() > triggers.high_outlier_ratio {
            return Some(format!(
                "High outlier ratio: {:.1}%",
                pattern.outlier_ratio() * 100.0
            ));
        }
        
        None
    }

    fn archive_reason(&self, pattern: &Pattern) -> String {
        let policy = &self.policies.auto_archive;
        if pattern.decayed_score.unwrap_or(1.0) < policy.min_confidence {
            return "confidence_below_threshold".into();
        }
        if pattern.observation_count < policy.min_observations_for_age {
            return "insufficient_observations_for_age".into();
        }
        "no_recent_observations".into()
    }
}
```

**Rationale**:
- Reduces manual curation burden: high-confidence, well-observed patterns are approved automatically
- Prevents pattern rot: stale patterns are archived before they pollute results
- Security/auth patterns are excluded from auto-approve by default — these always need human review
- Configurable policies allow teams to tune aggressiveness: strict teams can require more evidence, relaxed teams can auto-approve earlier
- Review triggers surface patterns that need attention without requiring manual scanning of all patterns

**Evidence**:
- V1's auto-approve recommendation criteria (RECAP §Audit Engine)
- SonarQube's quality profile management ([§2.1](https://docs.sonarsource.com/sonarqube-server/2025.4/user-guide/rules/overview))
- Progressive Bayesian confidence tiers ([§3.2](https://arxiv.org/abs/2601.03299)) — uncertainty-aware thresholds

**Risks**:
- Auto-approve false positives. Mitigate: conservative defaults (high confidence + low uncertainty + many observations + minimum age). Security/auth excluded.
- Auto-archive valid patterns. Mitigate: archived patterns can be restored. Archive events are logged. Notification on archive.

**Dependencies**: R4, R7, R8, R9, R10.


---

## Phase 3: Enterprise Features (Compliance, Multi-Project, Observability)

### R13: OWASP/CWE Security Standards Mapping

**Priority**: P1 (Important — enterprise compliance requirement)
**Effort**: Medium
**Impact**: Enables compliance reporting, maps Drift's security patterns to industry-standard vulnerability identifiers

**Current State**:
V1's security patterns have no OWASP or CWE identifiers. Security-category patterns are detected and stored with Drift-internal IDs only. Enterprise customers cannot generate compliance reports mapping their codebase to OWASP Top 10 or CWE categories.

**Proposed Change**:
Add security standards mapping to the pattern schema and build a compliance reporting layer:
```sql
-- Security standards mapping table
CREATE TABLE pattern_security_mappings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pattern_id TEXT NOT NULL,
  standard TEXT NOT NULL,          -- 'owasp_2025', 'cwe', 'nist_800_53'
  identifier TEXT NOT NULL,        -- 'A01', 'CWE-89', 'AC-1'
  relationship TEXT NOT NULL,      -- 'detects', 'prevents', 'mitigates'
  confidence REAL DEFAULT 1.0,     -- How confident is this mapping
  notes TEXT,
  FOREIGN KEY (pattern_id) REFERENCES patterns(id),
  UNIQUE(pattern_id, standard, identifier)
) STRICT;

CREATE INDEX idx_security_mappings_standard
  ON pattern_security_mappings(standard, identifier);

CREATE INDEX idx_security_mappings_pattern
  ON pattern_security_mappings(pattern_id);
```

**Rust Implementation**:
```rust
/// OWASP Top 10 (2025) categories
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OwaspCategory {
    A01BrokenAccessControl,
    A02CryptographicFailures,
    A03Injection,
    A04InsecureDesign,
    A05SecurityMisconfiguration,
    A06VulnerableComponents,
    A07AuthenticationFailures,
    A08DataIntegrityFailures,
    A09LoggingFailures,
    A10Ssrf,
}

/// Default mappings from Drift pattern categories to OWASP/CWE
pub fn default_security_mappings() -> Vec<SecurityMapping> {
    vec![
        // Auth patterns → A01 Broken Access Control
        SecurityMapping {
            category: PatternCategory::Auth,
            owasp: OwaspCategory::A01BrokenAccessControl,
            cwe_ids: vec!["CWE-284", "CWE-285", "CWE-639", "CWE-862"],
            relationship: "detects",
        },
        // Auth patterns → A07 Authentication Failures
        SecurityMapping {
            category: PatternCategory::Auth,
            owasp: OwaspCategory::A07AuthenticationFailures,
            cwe_ids: vec!["CWE-287", "CWE-384", "CWE-613"],
            relationship: "detects",
        },
        // Security patterns → A02 Cryptographic Failures
        SecurityMapping {
            category: PatternCategory::Security,
            owasp: OwaspCategory::A02CryptographicFailures,
            cwe_ids: vec!["CWE-259", "CWE-327", "CWE-328", "CWE-330"],
            relationship: "detects",
        },
        // Security patterns → A03 Injection
        SecurityMapping {
            category: PatternCategory::Security,
            owasp: OwaspCategory::A03Injection,
            cwe_ids: vec!["CWE-79", "CWE-89", "CWE-94", "CWE-78"],
            relationship: "detects",
        },
        // Config patterns → A05 Security Misconfiguration
        SecurityMapping {
            category: PatternCategory::Config,
            owasp: OwaspCategory::A05SecurityMisconfiguration,
            cwe_ids: vec!["CWE-16", "CWE-2", "CWE-215"],
            relationship: "detects",
        },
        // Error patterns → A09 Logging Failures
        SecurityMapping {
            category: PatternCategory::Errors,
            owasp: OwaspCategory::A09LoggingFailures,
            cwe_ids: vec!["CWE-778", "CWE-223", "CWE-532"],
            relationship: "mitigates",
        },
        // Logging patterns → A09 Logging Failures
        SecurityMapping {
            category: PatternCategory::Logging,
            owasp: OwaspCategory::A09LoggingFailures,
            cwe_ids: vec!["CWE-778", "CWE-117", "CWE-532"],
            relationship: "detects",
        },
    ]
}

/// Compliance report generator
pub struct ComplianceReporter;

impl ComplianceReporter {
    /// Generate OWASP Top 10 coverage report
    pub fn owasp_coverage(
        repo: &PatternRepository,
    ) -> Result<OwaspCoverageReport> {
        let mappings = repo.get_security_mappings("owasp_2025")?;
        let all_categories = OwaspCategory::all();
        
        let mut coverage = Vec::new();
        for owasp_cat in &all_categories {
            let mapped_patterns: Vec<_> = mappings.iter()
                .filter(|m| &m.owasp == owasp_cat)
                .collect();
            
            let pattern_count = mapped_patterns.len();
            let approved_count = mapped_patterns.iter()
                .filter(|m| m.pattern_status == PatternStatus::Approved)
                .count();
            let avg_confidence = if pattern_count > 0 {
                mapped_patterns.iter()
                    .map(|m| m.confidence_score)
                    .sum::<f64>() / pattern_count as f64
            } else {
                0.0
            };
            
            coverage.push(OwaspCategoryReport {
                category: owasp_cat.clone(),
                total_patterns: pattern_count,
                approved_patterns: approved_count,
                average_confidence: avg_confidence,
                coverage_level: match approved_count {
                    0 => CoverageLevel::None,
                    1..=2 => CoverageLevel::Minimal,
                    3..=5 => CoverageLevel::Partial,
                    _ => CoverageLevel::Good,
                },
            });
        }
        
        Ok(OwaspCoverageReport {
            standard: "OWASP Top 10 (2025)".into(),
            generated_at: Utc::now(),
            categories: coverage,
            overall_coverage: calculate_overall_coverage(&coverage),
        })
    }
}
```

**Rationale**:
- OWASP/CWE mapping is table stakes for enterprise static analysis tools — every competitor has it
- Enables compliance reporting: "which OWASP categories does our codebase cover?"
- Maps Drift's discovered patterns to industry-standard identifiers, making results actionable for security teams
- The mapping table is separate from patterns — allows many-to-many relationships (one pattern can map to multiple CWEs)
- Default mappings provide out-of-the-box coverage; teams can add custom mappings

**Evidence**:
- OWASP Top 10 2025 ([§6.1](https://owasp.org/www-project-top-ten/))
- CWE-specific vulnerability detection ([§6.2](https://arxiv.org/abs/2408.02329))
- Semgrep's OWASP/CWE rule tagging ([§2.3](https://github.com/semgrep/semgrep))
- CASTLE benchmark for static analyzer evaluation ([§6.3](https://arxiv.org/abs/2503.09433))

**Risks**:
- Incorrect mappings produce false compliance claims. Mitigate: default mappings are conservative (high confidence). Custom mappings require explicit confidence scores.
- Mapping maintenance as OWASP/CWE evolves. Mitigate: version the standard in the mapping table. Support multiple standard versions simultaneously.

**Dependencies**: R1, R2, R4.

---

### R14: False Positive Tracking & Detector Precision Metrics

**Priority**: P1 (Important — enables data-driven detector improvement)
**Effort**: Medium
**Impact**: Tracks false positive rates per detector, enables precision/recall metrics, improves detection quality over time

**Current State**:
V1 has no false positive tracking. When a user ignores a pattern, there's no distinction between "this is wrong" (false positive) and "this is correct but I don't care" (intentional ignore). No per-detector precision metrics. No feedback loop from user actions to detector tuning.

**Proposed Change**:
Add structured false positive tracking with per-detector metrics:
```sql
-- False positive reports
CREATE TABLE false_positive_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pattern_id TEXT NOT NULL,
  detector_id TEXT NOT NULL,
  file_path TEXT NOT NULL,
  line_number INTEGER,
  reason TEXT NOT NULL,            -- 'wrong_detection', 'outdated', 'not_applicable', 'other'
  reporter TEXT,                   -- 'user:<name>' or 'system:lifecycle'
  resolution TEXT,                 -- 'confirmed_fp', 'rejected', 'pending'
  resolved_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (pattern_id) REFERENCES patterns(id)
) STRICT;

CREATE INDEX idx_fp_reports_detector
  ON false_positive_reports(detector_id, created_at DESC);

CREATE INDEX idx_fp_reports_pattern
  ON false_positive_reports(pattern_id);

-- Materialized detector metrics (updated after each scan)
CREATE TABLE detector_metrics (
  detector_id TEXT PRIMARY KEY,
  total_detections INTEGER NOT NULL DEFAULT 0,
  confirmed_true_positives INTEGER NOT NULL DEFAULT 0,
  confirmed_false_positives INTEGER NOT NULL DEFAULT 0,
  precision REAL,                  -- TP / (TP + FP)
  patterns_discovered INTEGER NOT NULL DEFAULT 0,
  patterns_approved INTEGER NOT NULL DEFAULT 0,
  patterns_ignored INTEGER NOT NULL DEFAULT 0,
  avg_confidence REAL,
  last_scan_at TEXT,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;
```

**Rust Implementation**:
```rust
/// False positive tracking and detector precision metrics.
pub struct DetectorMetrics;

impl DetectorMetrics {
    /// Record a false positive report.
    pub fn report_false_positive(
        repo: &PatternRepository,
        pattern_id: &PatternId,
        file_path: &str,
        line: Option<i64>,
        reason: FalsePositiveReason,
        reporter: &str,
    ) -> Result<()> {
        let pattern = repo.get_by_id(pattern_id)?
            .ok_or_else(|| Error::NotFound(pattern_id.clone()))?;
        
        repo.db.write(|conn| {
            conn.execute_cached(
                "INSERT INTO false_positive_reports
                 (pattern_id, detector_id, file_path, line_number, reason, reporter)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    pattern_id.as_str(),
                    pattern.detector_id,
                    file_path,
                    line,
                    reason.as_str(),
                    reporter,
                ],
            )?;
            Ok(())
        })?;
        
        // Update detector metrics
        Self::recalculate_detector_metrics(repo, &pattern.detector_id)?;
        
        // Update pattern confidence (FP reports reduce effective confidence)
        repo.log_event(
            pattern_id,
            &PatternEvent::FalsePositiveReported {
                file: file_path.into(),
                reporter: reporter.into(),
            },
            reporter,
            None,
        )?;
        
        Ok(())
    }

    /// Recalculate precision metrics for a detector.
    pub fn recalculate_detector_metrics(
        repo: &PatternRepository,
        detector_id: &str,
    ) -> Result<DetectorMetricsSummary> {
        let metrics = repo.db.read(|conn| {
            let total: i64 = conn.query_row(
                "SELECT COUNT(*) FROM patterns WHERE detector_id = ?1",
                params![detector_id],
                |row| row.get(0),
            )?;
            
            let approved: i64 = conn.query_row(
                "SELECT COUNT(*) FROM patterns
                 WHERE detector_id = ?1 AND status = 'approved'",
                params![detector_id],
                |row| row.get(0),
            )?;
            
            let ignored: i64 = conn.query_row(
                "SELECT COUNT(*) FROM patterns
                 WHERE detector_id = ?1 AND status = 'ignored'",
                params![detector_id],
                |row| row.get(0),
            )?;
            
            let fp_count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM false_positive_reports
                 WHERE detector_id = ?1 AND resolution = 'confirmed_fp'",
                params![detector_id],
                |row| row.get(0),
            )?;
            
            let avg_conf: f64 = conn.query_row(
                "SELECT COALESCE(AVG(confidence_score), 0.0) FROM patterns
                 WHERE detector_id = ?1",
                params![detector_id],
                |row| row.get(0),
            )?;
            
            let precision = if (approved + fp_count) > 0 {
                Some(approved as f64 / (approved + fp_count) as f64)
            } else {
                None
            };
            
            Ok(DetectorMetricsSummary {
                detector_id: detector_id.into(),
                total_detections: total as usize,
                approved: approved as usize,
                ignored: ignored as usize,
                false_positives: fp_count as usize,
                precision,
                avg_confidence: avg_conf,
            })
        })?;
        
        // Persist to materialized table
        repo.db.write(|conn| {
            conn.execute_cached(
                "INSERT OR REPLACE INTO detector_metrics
                 (detector_id, total_detections, confirmed_true_positives,
                  confirmed_false_positives, precision, patterns_discovered,
                  patterns_approved, patterns_ignored, avg_confidence, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, datetime('now'))",
                params![
                    metrics.detector_id,
                    metrics.total_detections,
                    metrics.approved,
                    metrics.false_positives,
                    metrics.precision,
                    metrics.total_detections,
                    metrics.approved,
                    metrics.ignored,
                    metrics.avg_confidence,
                ],
            )?;
            Ok(())
        })?;
        
        Ok(metrics)
    }

    /// Get detectors ranked by precision (worst first — for improvement prioritization).
    pub fn get_detectors_by_precision(
        repo: &PatternRepository,
        limit: usize,
    ) -> Result<Vec<DetectorMetricsSummary>> {
        repo.db.read(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT detector_id, total_detections, confirmed_true_positives,
                        confirmed_false_positives, precision, patterns_approved,
                        patterns_ignored, avg_confidence
                 FROM detector_metrics
                 WHERE precision IS NOT NULL
                 ORDER BY precision ASC
                 LIMIT ?1"
            )?;
            stmt.query_map(params![limit], |row| {
                Ok(DetectorMetricsSummary {
                    detector_id: row.get(0)?,
                    total_detections: row.get::<_, i64>(1)? as usize,
                    approved: row.get::<_, i64>(2)? as usize,
                    false_positives: row.get::<_, i64>(3)? as usize,
                    precision: row.get(4)?,
                    ignored: row.get::<_, i64>(6)? as usize,
                    avg_confidence: row.get(7)?,
                })
            })?.collect::<Result<Vec<_>, _>>()
        })
    }
}
```

**Rationale**:
- False positive tracking is the missing feedback loop: user actions (ignore, dismiss) should inform detector quality
- Per-detector precision metrics enable data-driven improvement: focus engineering effort on the least precise detectors
- Distinguishing "wrong detection" from "intentional ignore" prevents conflating detector quality with user preference
- Materialized metrics table enables fast dashboard queries without expensive aggregation on every request
- CASTLE benchmark research ([§6.3]) confirms that false positive management is the primary enterprise concern with static analysis

**Evidence**:
- CASTLE benchmark — static analyzers vs LLMs ([§6.3](https://arxiv.org/abs/2503.09433))
- Enterprise static analysis best practices ([§8.1](https://www.augmentcode.com/guides/static-code-analysis-best-practices-enterprise))
- SonarQube's false positive management workflow ([§2.1](https://docs.sonarsource.com/sonarqube-server/2025.4/user-guide/rules/overview))

**Risks**:
- Users may not bother reporting false positives. Mitigate: make it one-click in IDE integration. Auto-detect potential FPs from ignore patterns.
- Precision metrics are noisy with few data points. Mitigate: require minimum 10 resolved reports before displaying precision.

**Dependencies**: R4, R7.


---

### R15: Multi-Project Pattern Sharing / Hierarchical Scoping

**Priority**: P2 (Nice to have — enterprise multi-repo feature)
**Effort**: High
**Impact**: Enables team-wide convention enforcement across multiple repositories

**Current State**:
V1 is single-project only. Patterns discovered in one repository have no relationship to patterns in another. If a team maintains 10 microservices that all follow the same auth pattern, Drift discovers it independently in each — no sharing, no consistency enforcement, no team-level conventions.

**Proposed Change**:
Implement hierarchical pattern scoping with promotion/demotion between levels:
```sql
-- Pattern scope hierarchy
CREATE TABLE pattern_scopes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scope_type TEXT NOT NULL,        -- 'global', 'team', 'project', 'directory', 'file'
  scope_path TEXT NOT NULL,        -- team name, project path, directory path, file path
  parent_scope_id INTEGER,         -- NULL for global scope
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (parent_scope_id) REFERENCES pattern_scopes(id),
  UNIQUE(scope_type, scope_path)
) STRICT;

-- Pattern-to-scope assignments (many-to-many)
CREATE TABLE pattern_scope_assignments (
  pattern_id TEXT NOT NULL,
  scope_id INTEGER NOT NULL,
  promoted_from_scope_id INTEGER,  -- NULL if originally discovered at this scope
  promoted_at TEXT,
  promoted_by TEXT,
  PRIMARY KEY (pattern_id, scope_id),
  FOREIGN KEY (pattern_id) REFERENCES patterns(id),
  FOREIGN KEY (scope_id) REFERENCES pattern_scopes(id)
) STRICT;
```

**Rust Implementation**:
```rust
/// Hierarchical pattern scoping.
/// Patterns can exist at multiple scope levels simultaneously.
/// Higher scopes override lower scopes for conflict resolution.
pub struct PatternScopeManager;

impl PatternScopeManager {
    /// Get effective patterns for a file, resolving scope hierarchy.
    /// Order: file → directory → project → team → global
    /// Higher scope patterns override lower scope patterns with same ID.
    pub fn get_effective_patterns(
        repo: &PatternRepository,
        file_path: &str,
        project: &str,
        team: Option<&str>,
    ) -> Result<Vec<EffectivePattern>> {
        let mut effective: HashMap<PatternId, EffectivePattern> = HashMap::new();
        
        // Layer 1: Global patterns (lowest priority)
        for pattern in repo.get_patterns_by_scope("global", "")? {
            effective.insert(pattern.id.clone(), EffectivePattern {
                pattern,
                source_scope: "global".into(),
                overridden: false,
            });
        }
        
        // Layer 2: Team patterns (override global)
        if let Some(team_name) = team {
            for pattern in repo.get_patterns_by_scope("team", team_name)? {
                effective.insert(pattern.id.clone(), EffectivePattern {
                    pattern,
                    source_scope: format!("team:{}", team_name),
                    overridden: false,
                });
            }
        }
        
        // Layer 3: Project patterns (override team)
        for pattern in repo.get_patterns_by_scope("project", project)? {
            effective.insert(pattern.id.clone(), EffectivePattern {
                pattern,
                source_scope: format!("project:{}", project),
                overridden: false,
            });
        }
        
        // Layer 4: Directory patterns (override project)
        let dir = std::path::Path::new(file_path).parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        for pattern in repo.get_patterns_by_scope("directory", &dir)? {
            effective.insert(pattern.id.clone(), EffectivePattern {
                pattern,
                source_scope: format!("directory:{}", dir),
                overridden: false,
            });
        }
        
        Ok(effective.into_values().collect())
    }

    /// Promote a pattern from project scope to team scope.
    /// This makes the pattern available to all projects in the team.
    pub fn promote_to_team(
        repo: &PatternRepository,
        pattern_id: &PatternId,
        team_name: &str,
        promoted_by: &str,
    ) -> Result<()> {
        let team_scope = repo.get_or_create_scope("team", team_name)?;
        let project_scope = repo.get_pattern_scope(pattern_id)?;
        
        repo.db.write(|conn| {
            conn.execute_cached(
                "INSERT OR IGNORE INTO pattern_scope_assignments
                 (pattern_id, scope_id, promoted_from_scope_id, promoted_at, promoted_by)
                 VALUES (?1, ?2, ?3, datetime('now'), ?4)",
                params![
                    pattern_id.as_str(),
                    team_scope.id,
                    project_scope.map(|s| s.id),
                    promoted_by,
                ],
            )?;
            Ok(())
        })?;
        
        repo.log_event(
            pattern_id,
            &PatternEvent::StatusChanged {
                old_status: PatternStatus::Approved,
                new_status: PatternStatus::Approved,
                reason: format!("promoted_to_team:{}", team_name),
            },
            promoted_by,
            None,
        )?;
        
        Ok(())
    }
}
```

**Rationale**:
- Enterprise teams with multiple repositories need consistent convention enforcement
- Hierarchical scoping mirrors how conventions actually work: some are universal (global), some are team-specific, some are project-specific
- Promotion workflow enables bottom-up convention discovery: pattern discovered in one project → validated → promoted to team level
- Override semantics (higher scope wins) prevent conflicts and enable project-specific exceptions

**Evidence**:
- SonarQube's quality profile inheritance ([§2.1](https://docs.sonarsource.com/sonarqube-server/2025.4/user-guide/rules/overview))
- ESLint's shareable configurations ([§2.2](https://eslint.org/docs/latest/use/core-concepts/))
- Multi-repo automated code review ([§8.2](https://www.qodo.ai/blog/automated-code-review/))

**Risks**:
- Complexity explosion with deep scope hierarchies. Mitigate: limit to 5 levels (global → team → project → directory → file).
- Cross-project pattern identity: same convention in different projects may have different IDs. Mitigate: use content-based hashing for pattern identity, not random UUIDs.

**Dependencies**: R4, R7.


---

### R16: Pattern Profiles — Named Configurations

**Priority**: P2 (Nice to have — enterprise configuration management)
**Effort**: Medium
**Impact**: Enables named pattern configurations (like SonarQube Quality Profiles) for different contexts

**Current State**:
V1 has no concept of pattern profiles. All patterns are either active or ignored — there's no way to say "use the strict profile for CI but the relaxed profile for IDE feedback." Teams can't share curated pattern sets.

**Proposed Change**:
Implement named pattern profiles with inheritance:
```sql
-- Pattern profiles (named configurations)
CREATE TABLE pattern_profiles (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  description TEXT,
  parent_profile_id TEXT,          -- Inheritance: child overrides parent
  is_default INTEGER DEFAULT 0,    -- At most one default profile
  created_by TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (parent_profile_id) REFERENCES pattern_profiles(id)
) STRICT;

-- Profile rules: which patterns/categories are active in this profile
CREATE TABLE profile_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  profile_id TEXT NOT NULL,
  rule_type TEXT NOT NULL,         -- 'include_category', 'exclude_category',
                                   -- 'include_pattern', 'exclude_pattern',
                                   -- 'severity_override', 'threshold_override'
  target TEXT NOT NULL,            -- Category name or pattern ID
  value TEXT,                      -- Override value (severity, threshold, etc.)
  FOREIGN KEY (profile_id) REFERENCES pattern_profiles(id)
) STRICT;

CREATE INDEX idx_profile_rules_profile
  ON profile_rules(profile_id);
```

**Rust Implementation**:
```rust
/// Pattern profile: a named configuration that controls which patterns
/// are active and how they behave in a given context.
pub struct PatternProfile {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub parent_id: Option<String>,
    pub rules: Vec<ProfileRule>,
}

#[derive(Debug, Clone)]
pub enum ProfileRule {
    IncludeCategory(PatternCategory),
    ExcludeCategory(PatternCategory),
    IncludePattern(PatternId),
    ExcludePattern(PatternId),
    SeverityOverride {
        target: String,  // Category or pattern ID
        severity: Severity,
    },
    ThresholdOverride {
        target: String,
        min_confidence: f64,
    },
}

impl PatternProfile {
    /// Resolve effective rules by walking the inheritance chain.
    /// Child rules override parent rules for the same target.
    pub fn resolve(
        &self,
        repo: &PatternRepository,
    ) -> Result<ResolvedProfile> {
        let mut chain = vec![self.clone()];
        let mut current = self.parent_id.clone();
        
        // Walk inheritance chain (max depth 5 to prevent cycles)
        for _ in 0..5 {
            match current {
                Some(parent_id) => {
                    let parent = repo.get_profile(&parent_id)?
                        .ok_or_else(|| Error::ProfileNotFound(parent_id.clone()))?;
                    current = parent.parent_id.clone();
                    chain.push(parent);
                }
                None => break,
            }
        }
        
        // Apply rules from root to leaf (child overrides parent)
        chain.reverse();
        let mut resolved = ResolvedProfile::default();
        for profile in &chain {
            for rule in &profile.rules {
                resolved.apply(rule);
            }
        }
        
        Ok(resolved)
    }
}

/// Built-in profiles
pub fn builtin_profiles() -> Vec<PatternProfile> {
    vec![
        PatternProfile {
            id: "drift-default".into(),
            name: "Drift Default".into(),
            description: Some("Balanced profile for general use".into()),
            parent_id: None,
            rules: vec![
                // All categories included by default
                // Minimum confidence: medium (0.60)
                ProfileRule::ThresholdOverride {
                    target: "*".into(),
                    min_confidence: 0.60,
                },
            ],
        },
        PatternProfile {
            id: "drift-strict".into(),
            name: "Drift Strict".into(),
            description: Some("High-confidence only, for CI/CD gates".into()),
            parent_id: Some("drift-default".into()),
            rules: vec![
                ProfileRule::ThresholdOverride {
                    target: "*".into(),
                    min_confidence: 0.85,
                },
                // Security patterns always included regardless of confidence
                ProfileRule::ThresholdOverride {
                    target: "security".into(),
                    min_confidence: 0.50,
                },
                ProfileRule::ThresholdOverride {
                    target: "auth".into(),
                    min_confidence: 0.50,
                },
            ],
        },
        PatternProfile {
            id: "drift-security".into(),
            name: "Drift Security".into(),
            description: Some("Security-focused profile for compliance".into()),
            parent_id: Some("drift-default".into()),
            rules: vec![
                // Only security-relevant categories
                ProfileRule::ExcludeCategory(PatternCategory::Styling),
                ProfileRule::ExcludeCategory(PatternCategory::Documentation),
                ProfileRule::ExcludeCategory(PatternCategory::Components),
                // Lower threshold for security patterns
                ProfileRule::ThresholdOverride {
                    target: "security".into(),
                    min_confidence: 0.40,
                },
                // Elevate security severity
                ProfileRule::SeverityOverride {
                    target: "security".into(),
                    severity: Severity::Error,
                },
            ],
        },
    ]
}
```

**Rationale**:
- Different contexts need different pattern configurations: IDE (fast, lenient), CI (comprehensive, strict), security audit (security-only, aggressive)
- Profile inheritance reduces duplication: "strict" inherits from "default" and only overrides thresholds
- Built-in profiles provide sensible defaults; teams customize by creating child profiles
- Profiles are the mechanism for quality gate configuration: each gate references a profile

**Evidence**:
- SonarQube's Quality Profiles with inheritance ([§2.1](https://docs.sonarsource.com/sonarqube-server/2025.4/user-guide/rules/overview))
- ESLint's shareable configurations and extends mechanism ([§2.2](https://eslint.org/docs/latest/use/core-concepts/))

**Risks**:
- Profile proliferation. Mitigate: limit inheritance depth to 3 levels. Provide profile diff tool.
- Circular inheritance. Mitigate: validate on save, reject cycles.

**Dependencies**: R4, R13 (security profiles reference OWASP mappings).


---

### R17: Remediation Effort Estimates per Violation

**Priority**: P2 (Nice to have — enterprise planning feature)
**Effort**: Low
**Impact**: Enables effort-based prioritization and technical debt quantification

**Current State**:
V1 violations have severity but no effort estimate. A team can't answer "how long would it take to fix all high-severity violations?" or "which violations give the best ROI to fix?"

**Proposed Change**:
Add remediation effort estimates to patterns and violations:
```sql
-- Add effort columns to patterns table
ALTER TABLE patterns ADD COLUMN remediation_effort TEXT DEFAULT 'medium';
  -- 'trivial' (< 5 min), 'low' (5-30 min), 'medium' (30-120 min),
  -- 'high' (2-8 hours), 'critical' (> 8 hours)
ALTER TABLE patterns ADD COLUMN remediation_minutes INTEGER;
  -- Estimated minutes for a single violation fix
ALTER TABLE patterns ADD COLUMN effort_source TEXT DEFAULT 'estimated';
  -- 'estimated' (heuristic), 'measured' (from actual fix times), 'manual' (user-set)
```

**Rust Implementation**:
```rust
/// Remediation effort estimation.
/// Combines heuristic estimates with measured fix times.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemediationEffort {
    Trivial,    // < 5 minutes: rename, add import, fix typo
    Low,        // 5-30 minutes: add error handling, fix type
    Medium,     // 30-120 minutes: refactor function, add validation
    High,       // 2-8 hours: restructure module, add auth layer
    Critical,   // > 8 hours: architectural change, major refactor
}

impl RemediationEffort {
    pub fn minutes(&self) -> u32 {
        match self {
            Self::Trivial => 3,
            Self::Low => 15,
            Self::Medium => 60,
            Self::High => 300,
            Self::Critical => 600,
        }
    }
}

/// Default effort estimates by pattern category and auto-fixability.
pub fn estimate_effort(
    category: &PatternCategory,
    auto_fixable: bool,
    severity: &Severity,
) -> RemediationEffort {
    if auto_fixable {
        return RemediationEffort::Trivial;
    }
    
    match (category, severity) {
        // Structural changes are expensive
        (PatternCategory::Structural, Severity::Error) => RemediationEffort::High,
        (PatternCategory::Structural, _) => RemediationEffort::Medium,
        // Security fixes vary but are generally non-trivial
        (PatternCategory::Security, Severity::Error) => RemediationEffort::High,
        (PatternCategory::Security, _) => RemediationEffort::Medium,
        (PatternCategory::Auth, _) => RemediationEffort::Medium,
        // Styling/naming fixes are usually quick
        (PatternCategory::Styling, _) => RemediationEffort::Low,
        (PatternCategory::Documentation, _) => RemediationEffort::Low,
        // Type fixes depend on severity
        (PatternCategory::Types, Severity::Error) => RemediationEffort::Medium,
        (PatternCategory::Types, _) => RemediationEffort::Low,
        // Default
        (_, Severity::Error) => RemediationEffort::Medium,
        _ => RemediationEffort::Low,
    }
}

/// Technical debt calculator.
pub struct TechnicalDebtCalculator;

impl TechnicalDebtCalculator {
    /// Calculate total remediation effort for all active violations.
    pub fn calculate(
        repo: &PatternRepository,
        profile: &ResolvedProfile,
    ) -> Result<DebtReport> {
        let patterns = repo.get_active_patterns()?;
        let mut total_minutes: u64 = 0;
        let mut by_category: HashMap<PatternCategory, u64> = HashMap::new();
        let mut by_severity: HashMap<Severity, u64> = HashMap::new();
        
        for pattern in &patterns {
            if !profile.includes_pattern(pattern) { continue; }
            
            let effort_minutes = pattern.remediation_minutes
                .unwrap_or_else(|| estimate_effort(
                    &pattern.category,
                    pattern.auto_fixable,
                    &pattern.severity,
                ).minutes() as i64) as u64;
            
            let violation_count = pattern.outlier_count() as u64;
            let pattern_debt = effort_minutes * violation_count;
            
            total_minutes += pattern_debt;
            *by_category.entry(pattern.category.clone()).or_default() += pattern_debt;
            *by_severity.entry(pattern.severity.clone()).or_default() += pattern_debt;
        }
        
        Ok(DebtReport {
            total_minutes,
            total_hours: total_minutes as f64 / 60.0,
            total_days: total_minutes as f64 / 480.0,  // 8-hour days
            by_category,
            by_severity,
            generated_at: Utc::now(),
        })
    }
}
```

**Rationale**:
- Effort estimates enable ROI-based prioritization: fix the violations that give the most improvement per hour invested
- Technical debt quantification in hours/days is meaningful to engineering managers — "we have 12 person-days of pattern debt"
- Auto-fixable violations are trivial by definition — this incentivizes building quick fixes
- Measured fix times (from actual user actions) gradually replace heuristic estimates, improving accuracy over time
- SonarQube's remediation effort model is proven in enterprise adoption

**Evidence**:
- SonarQube's remediation effort estimates ([§2.1](https://docs.sonarsource.com/sonarqube-server/2025.4/user-guide/rules/overview))
- Enterprise static analysis best practices — metrics that matter ([§8.1](https://www.augmentcode.com/guides/static-code-analysis-best-practices-enterprise))

**Risks**:
- Inaccurate estimates mislead planning. Mitigate: clearly label as estimates. Track actual fix times to calibrate.
- Effort varies by developer skill. Mitigate: use median estimates, not optimistic ones.

**Dependencies**: R4.

---

### R18: Observability — Query Timing, Cache Hit Rates, Per-Detector Metrics

**Priority**: P2 (Nice to have — operational excellence)
**Effort**: Medium
**Impact**: Enables performance monitoring, bottleneck identification, and capacity planning

**Current State**:
V1 has no observability for the pattern repository. No query timing, no cache hit rates, no per-detector performance metrics. When the system is slow, there's no data to diagnose why.

**Proposed Change**:
Add structured observability to the pattern repository:
```sql
-- Query performance metrics (ring buffer — keep last 10,000 entries)
CREATE TABLE query_metrics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  query_type TEXT NOT NULL,        -- 'get_by_id', 'get_by_file', 'search', etc.
  duration_us INTEGER NOT NULL,    -- Microseconds
  result_count INTEGER,
  cache_hit INTEGER DEFAULT 0,    -- 1 if served from cache
  caller TEXT,                     -- 'mcp:drift_patterns_list', 'cli:scan', etc.
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

-- Periodic cleanup: keep only last 10,000 entries
CREATE TRIGGER cleanup_query_metrics
  AFTER INSERT ON query_metrics
  WHEN (SELECT COUNT(*) FROM query_metrics) > 10000
BEGIN
  DELETE FROM query_metrics
  WHERE id IN (
    SELECT id FROM query_metrics
    ORDER BY id ASC
    LIMIT (SELECT COUNT(*) - 10000 FROM query_metrics)
  );
END;

-- Scan performance metrics
CREATE TABLE scan_metrics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  files_scanned INTEGER NOT NULL,
  patterns_discovered INTEGER NOT NULL,
  patterns_updated INTEGER NOT NULL,
  patterns_archived INTEGER NOT NULL,
  total_duration_ms INTEGER NOT NULL,
  detection_duration_ms INTEGER,
  storage_duration_ms INTEGER,
  confidence_duration_ms INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;
```

**Rust Implementation**:
```rust
/// Observability layer for the pattern repository.
/// Wraps all repository operations with timing and metrics collection.
pub struct ObservablePatternRepository {
    inner: PatternRepository,
    metrics: Arc<Mutex<MetricsCollector>>,
}

pub struct MetricsCollector {
    /// In-memory counters (flushed to SQLite periodically)
    query_counts: HashMap<String, u64>,
    query_durations: HashMap<String, Vec<u64>>,  // microseconds
    cache_hits: u64,
    cache_misses: u64,
}

impl ObservablePatternRepository {
    /// Wrap a query with timing and metrics collection.
    fn timed_query<T, F>(
        &self,
        query_type: &str,
        caller: &str,
        f: F,
    ) -> Result<T>
    where
        F: FnOnce(&PatternRepository) -> Result<T>,
    {
        let start = Instant::now();
        let result = f(&self.inner);
        let duration = start.elapsed();
        
        let mut metrics = self.metrics.lock().unwrap();
        *metrics.query_counts.entry(query_type.into()).or_default() += 1;
        metrics.query_durations
            .entry(query_type.into())
            .or_default()
            .push(duration.as_micros() as u64);
        
        // Log slow queries (> 100ms)
        if duration.as_millis() > 100 {
            tracing::warn!(
                query_type = query_type,
                duration_ms = duration.as_millis() as u64,
                caller = caller,
                "Slow pattern query detected"
            );
        }
        
        result
    }

    /// Get aggregated metrics for a time window.
    pub fn get_metrics_summary(
        &self,
        window: Duration,
    ) -> MetricsSummary {
        let metrics = self.metrics.lock().unwrap();
        let mut summary = MetricsSummary::default();
        
        for (query_type, durations) in &metrics.query_durations {
            if durations.is_empty() { continue; }
            
            let count = durations.len();
            let total: u64 = durations.iter().sum();
            let avg = total / count as u64;
            let mut sorted = durations.clone();
            sorted.sort_unstable();
            let p50 = sorted[count / 2];
            let p95 = sorted[(count as f64 * 0.95) as usize];
            let p99 = sorted[(count as f64 * 0.99) as usize.min(count - 1)];
            
            summary.queries.push(QueryMetrics {
                query_type: query_type.clone(),
                count: count as u64,
                avg_us: avg,
                p50_us: p50,
                p95_us: p95,
                p99_us: p99,
            });
        }
        
        summary.cache_hit_rate = if metrics.cache_hits + metrics.cache_misses > 0 {
            metrics.cache_hits as f64
                / (metrics.cache_hits + metrics.cache_misses) as f64
        } else {
            0.0
        };
        
        summary
    }

    /// Flush in-memory metrics to SQLite for persistence.
    pub fn flush_metrics(&self) -> Result<()> {
        let mut metrics = self.metrics.lock().unwrap();
        
        self.inner.db.write(|conn| {
            let mut stmt = conn.prepare_cached(
                "INSERT INTO query_metrics
                 (query_type, duration_us, result_count, cache_hit, caller)
                 VALUES (?1, ?2, ?3, ?4, ?5)"
            )?;
            
            for (query_type, durations) in metrics.query_durations.drain() {
                for duration in durations {
                    stmt.execute(params![
                        query_type,
                        duration,
                        0i64,  // result_count filled by caller
                        0i64,  // cache_hit filled by caller
                        "unknown",
                    ])?;
                }
            }
            Ok(())
        })?;
        
        metrics.query_counts.clear();
        metrics.cache_hits = 0;
        metrics.cache_misses = 0;
        
        Ok(())
    }
}

/// Health check endpoint for the pattern repository.
pub struct RepositoryHealthCheck;

impl RepositoryHealthCheck {
    pub fn check(repo: &ObservablePatternRepository) -> HealthReport {
        let metrics = repo.get_metrics_summary(Duration::from_secs(3600));
        let db_size = repo.inner.db_size_bytes();
        let pattern_count = repo.inner.count_patterns().unwrap_or(0);
        
        let mut issues = Vec::new();
        
        // Check for slow queries
        for qm in &metrics.queries {
            if qm.p95_us > 100_000 {  // > 100ms at p95
                issues.push(format!(
                    "Slow query: {} p95={}ms",
                    qm.query_type,
                    qm.p95_us / 1000
                ));
            }
        }
        
        // Check cache hit rate
        if metrics.cache_hit_rate < 0.70 && metrics.total_queries() > 100 {
            issues.push(format!(
                "Low cache hit rate: {:.1}%",
                metrics.cache_hit_rate * 100.0
            ));
        }
        
        // Check database size
        if db_size > 500 * 1024 * 1024 {  // > 500MB
            issues.push(format!(
                "Large database: {}MB",
                db_size / (1024 * 1024)
            ));
        }
        
        HealthReport {
            status: if issues.is_empty() { "healthy" } else { "degraded" },
            pattern_count,
            db_size_bytes: db_size,
            cache_hit_rate: metrics.cache_hit_rate,
            query_metrics: metrics.queries,
            issues,
            checked_at: Utc::now(),
        }
    }
}
```

**Rationale**:
- You can't optimize what you can't measure — observability is the foundation for performance work
- Slow query detection enables proactive optimization before users notice degradation
- Cache hit rate monitoring validates that the Moka cache (R3 area) is effective
- Per-query-type metrics identify which operations need optimization (is it search? file lookup? category listing?)
- Health check endpoint enables monitoring integration and alerting
- Ring buffer approach (10,000 entries) prevents metrics from consuming unbounded storage

**Evidence**:
- Enterprise static analysis observability requirements ([§8.1](https://www.augmentcode.com/guides/static-code-analysis-best-practices-enterprise))
- rust-analyzer's performance monitoring approach ([§1.2](https://rust-analyzer.github.io/blog/2023/07/24/durable-incrementality.html))

**Risks**:
- Metrics collection overhead. Mitigate: in-memory counters with periodic flush (every 60 seconds). Timing uses `Instant::now()` which is ~20ns.
- Metrics storage growth. Mitigate: ring buffer with 10,000 entry cap. Scan metrics kept for 90 days.

**Dependencies**: R3, R4.


---

## Recommendation Dependency Graph

```
Phase 0: Architectural Decisions
  R1 (Single SQLite) ─────────────────────────────────────────────────┐
  R2 (STRICT Tables) ← R1                                            │
  R3 (Connection Pool) ← R1                                          │
                                                                      │
Phase 1: Core Repository                                              │
  R4 (Rust Repository + NAPI) ← R1, R2, R3 ──────────────────────────┤
  R5 (Keyset Pagination) ← R4                                        │
  R6 (Write Batching / MPSC) ← R3, R4                                │
  R7 (Event Log) ← R1, R2, R4                                        │
                                                                      │
Phase 2: Intelligence Layer                                           │
  R8 (Bayesian Confidence) ← R4, R7                                  │
  R9 (Temporal Decay) ← R4, R7, R8                                   │
  R10 (Pattern Momentum) ← R9                                        │
  R11 (Pattern Merging) ← R4, R7, R8                                 │
  R12 (Lifecycle Automation) ← R4, R7, R8, R9, R10                   │
                                                                      │
Phase 3: Enterprise Features                                          │
  R13 (OWASP/CWE Mapping) ← R1, R2, R4                              │
  R14 (False Positive Tracking) ← R4, R7                             │
  R15 (Multi-Project Scoping) ← R4, R7                               │
  R16 (Pattern Profiles) ← R4, R13                                   │
  R17 (Remediation Effort) ← R4                                      │
  R18 (Observability) ← R3, R4                                       │
```

**Critical Path**: R1 → R3 → R4 → R7 → R8 → R9 → R12

This is the longest dependency chain and determines the minimum build time. R4 (Rust Repository) is the bottleneck — everything depends on it. Parallelization opportunities exist in Phase 3 where R13-R18 are largely independent of each other.

---

## Success Metrics

### Phase 0 Success Criteria
| Metric | Target | Measurement |
|--------|--------|-------------|
| Storage backends | 1 (down from 6) | Architecture review |
| Sync paths | 0 (down from 3) | Code audit |
| Lines of storage code | < 5,000 (down from ~12,000) | `tokei` or `cloc` |

### Phase 1 Success Criteria
| Metric | Target | Measurement |
|--------|--------|-------------|
| Pattern CRUD latency (p95) | < 5ms | Query metrics (R18) |
| Batch write throughput | > 5,000 patterns/sec | Benchmark |
| Pagination at depth 1000 | < 10ms | Benchmark |
| Concurrent read throughput | > 10,000 queries/sec | Benchmark with N readers |
| Event log completeness | 100% of mutations logged | Audit |

### Phase 2 Success Criteria
| Metric | Target | Measurement |
|--------|--------|-------------|
| Confidence calibration | Predicted 80% → observed 75-85% | Calibration validation |
| Cold-start uncertainty | New patterns show "uncertain" level | Unit test |
| Stale pattern detection | Patterns unseen for > half-life flagged | Integration test |
| Auto-approve precision | > 95% (approved patterns are valid) | Manual review sample |
| Auto-archive recall | > 90% (stale patterns are archived) | Manual review sample |
| Duplicate reduction | > 10% fewer patterns after merging | Before/after count |

### Phase 3 Success Criteria
| Metric | Target | Measurement |
|--------|--------|-------------|
| OWASP Top 10 coverage | All 10 categories mapped | Compliance report |
| False positive rate tracking | Per-detector precision available | Dashboard |
| Cross-project pattern sharing | Patterns promotable to team scope | Integration test |
| Profile switching latency | < 50ms | Benchmark |
| Technical debt quantification | Hours/days estimate available | Report output |
| Query p95 latency monitoring | Alerts on > 100ms | Health check |

---

## Implementation Timeline

```
Week 1-2: Phase 0 — Architectural Decisions
├── R1: Finalize single-database decision, document migration plan
├── R2: Define STRICT table schemas for all pattern domain tables
├── R3: Implement connection pool (PatternDb struct)
└── Deliverable: drift.db schema DDL, connection pool crate

Week 3-5: Phase 1 — Core Repository
├── R4: Implement PatternRepository in Rust + NAPI bindings
│   ├── Week 3: CRUD operations, basic queries
│   ├── Week 4: Batch operations, search, statistics
│   └── Week 5: NAPI bindings, TS wrapper, integration tests
├── R5: Keyset pagination (parallel with R4 query implementation)
├── R6: Write batching via MPSC (parallel with R4 batch operations)
├── R7: Event log table + log_event() integration
└── Deliverable: Working Rust pattern repository with NAPI, passing all v1 tests

Week 6-8: Phase 2 — Intelligence Layer
├── R8: Bayesian confidence scoring (Week 6)
│   ├── BayesianConfidence struct + unit tests
│   ├── Integration with scan pipeline
│   └── Migration: initialize Beta params from v1 data
├── R9: Temporal decay (Week 7)
│   ├── TemporalDecay struct + observation table
│   ├── Decay recalculation job
│   └── Integration with confidence scoring
├── R10: Pattern momentum (Week 7, parallel with R9)
├── R11: Pattern merging (Week 8)
├── R12: Lifecycle automation (Week 8)
└── Deliverable: Intelligent pattern repository with Bayesian scoring, decay, lifecycle

Week 9-12: Phase 3 — Enterprise Features
├── R13: OWASP/CWE mapping (Week 9)
├── R14: False positive tracking (Week 9, parallel with R13)
├── R15: Multi-project scoping (Week 10)
├── R16: Pattern profiles (Week 10-11)
├── R17: Remediation effort estimates (Week 11, low effort)
├── R18: Observability (Week 11-12)
└── Deliverable: Enterprise-ready pattern repository with compliance, multi-project, observability
```

**Parallelization Notes**:
- R5 and R6 can be built in parallel during Phase 1
- R10 and R9 share the observation data model — build R9 first, R10 is a thin layer on top
- R13 and R14 are independent — build in parallel during Week 9
- R17 is low effort and can be squeezed into any gap

---

## Cross-Cutting Concerns

### Migration from V1
Every recommendation includes a migration path from v1 data:
- **R1**: Export all JSON patterns → import into single SQLite database
- **R4**: Map v1's IPatternService interface to NAPI bindings — TS consumers see minimal API change
- **R7**: Import v1's pattern_history rows as legacy events
- **R8**: Initialize Beta(α, β) from v1 data: α = location_count, β = max(1, total_files - location_count)
- **R9**: Set initial last_observed_at from v1's last_seen timestamp
- **R13**: Apply default OWASP/CWE mappings to existing security-category patterns

### Impact on Other Subsystems
| Subsystem | Impact | Required Changes |
|-----------|--------|-----------------|
| Detectors (03) | Medium | Output PatternUpsert structs instead of raw JSON. Use batch API. |
| Call Graph (04) | Low | No change — call graph already in Rust SQLite. Cross-reference via pattern_id. |
| Analyzers (05) | Medium | Read patterns via NAPI instead of direct SQLite. Use keyset pagination. |
| Cortex (06) | Low | Memory→pattern links use pattern_id foreign key. No storage change. |
| MCP (07) | Medium | Replace CursorManager OFFSET queries with keyset cursors. Use NAPI read APIs. |
| Storage (08) | High | Entire storage layer replaced by R1-R4. Remove JSON stores, hybrid stores, sync service. |
| Quality Gates (09) | Medium | Gates reference pattern profiles (R16). Use compliance reports (R13). |
| CLI (10) | Low | CLI commands call NAPI bindings instead of TS pattern service. |

### Security Considerations
- **R1**: Single database = single attack surface. Encrypt at rest with SQLCipher if required.
- **R3**: Read connections are read-only at the SQLite level (`PRAGMA query_only = ON`).
- **R7**: Event log is append-only — no UPDATE or DELETE on pattern_events.
- **R13**: OWASP/CWE mappings must be validated by security team before use in compliance reports.
- **R15**: Multi-project scoping must enforce access control — team patterns only visible to team members.

---

## Completeness Checklist

- [x] R1: Single Rust-Owned SQLite Database (P0, Phase 0)
- [x] R2: STRICT Tables with Enforced Types (P0, Phase 0)
- [x] R3: Connection Pool Architecture (P0, Phase 0)
- [x] R4: Rust Pattern Repository with NAPI Bindings (P0, Phase 1)
- [x] R5: Keyset Pagination (P1, Phase 1)
- [x] R6: Write Batching via MPSC Channel (P1, Phase 1)
- [x] R7: Event Log / Audit Trail (P1, Phase 1)
- [x] R8: Bayesian Confidence Scoring (P1, Phase 2)
- [x] R9: Temporal Confidence Decay (P1, Phase 2)
- [x] R10: Pattern Momentum Signal (P2, Phase 2)
- [x] R11: Automatic Pattern Merging (P2, Phase 2)
- [x] R12: Pattern Lifecycle Automation (P2, Phase 2)
- [x] R13: OWASP/CWE Security Standards Mapping (P1, Phase 3)
- [x] R14: False Positive Tracking & Detector Precision (P1, Phase 3)
- [x] R15: Multi-Project Pattern Sharing (P2, Phase 3)
- [x] R16: Pattern Profiles (P2, Phase 3)
- [x] R17: Remediation Effort Estimates (P2, Phase 3)
- [x] R18: Observability (P2, Phase 3)
- [x] Dependency graph with critical path identified
- [x] Success metrics per phase with measurable targets
- [x] Implementation timeline with parallelization
- [x] Migration strategy from v1
- [x] Cross-subsystem impact analysis
- [x] Security considerations
- [x] All recommendations backed by RESEARCH.md evidence
- [x] All recommendations reference v1 current state from RECAP.md
