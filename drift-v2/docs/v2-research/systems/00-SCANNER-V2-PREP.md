# Scanner — V2 Implementation Prep

> Comprehensive build specification for Drift v2's scanner subsystem (System 00).
> Synthesized from: 00-SCANNER.md (research doc, 7 sections — library evaluation,
> hashing benchmarks, parallelism strategy), 00-SCANNER-V2-PREP.md (previous prep doc,
> 21 sections, 790 lines — v1 gap analysis, integration points, build order),
> 06-UNIFIED-ANALYSIS-ENGINE-V2-PREP.md (§1 upstream deps — consumes ScanDiff + ScanEntry),
> 05-CALL-GRAPH-V2-PREP.md (§7 incremental updates — consumes ScanDiff for edge invalidation),
> 01-PARSERS-V2-PREP.md (§1 upstream deps — consumes ScanDiff for file list),
> 02-STORAGE-V2-PREP.md (§11 file_metadata table — expanded schema with language, counters),
> 03-NAPI-BRIDGE-V2-PREP.md (§5 minimize boundary, §7 AsyncTask + progress, §8 cancellation,
> §9 batch API — scanner is first analysis in batch pipeline, §10 function registry),
> 04-INFRASTRUCTURE-V2-PREP.md (§2 ScanError enum, §3 tracing spans, §4 DriftEventHandler
> scan events, §5 ScanConfig, §6 FxHashMap/SmallVec, §7 Cargo workspace deps),
> 19-COUPLING-ANALYSIS-V2-PREP.md (consumes ScanDiff + content hashes),
> 21-CONTRACT-TRACKING-V2-PREP.md (consumes ScanDiff for incremental contract analysis),
> 24-DNA-SYSTEM-V2-PREP.md (consumes ScanDiff for incremental fingerprinting),
> DRIFT-V2-STACK-HIERARCHY.md (Level 0 Bedrock — authoritative specs for crate versions,
> default ignores, ScanConfig fields, ScanStats fields, performance targets),
> PLANNING-DRIFT.md (D1-D7), DRIFT-V2-FULL-SYSTEM-AUDIT.md (A1, A6, A8, A21, AD1, AD6, AD10).
>
> Purpose: Everything needed to build the scanner subsystem from scratch. This is the
> DEFINITIVE scanner spec — reconciling the original 00-SCANNER.md research and previous
> V2-PREP doc with the contracts defined by 30+ downstream consumers. All discrepancies
> identified and resolved. All type definitions reconciled. All downstream expectations
> verified. Build order specified.
> Generated: 2026-02-08

---

## Table of Contents

1. Architectural Position
2. Resolved Inconsistencies (Critical — Read First)
3. Core Library: `ignore` Crate v0.4
4. Content Hashing: xxh3 via `xxhash-rust` v0.8
5. Two-Phase Architecture
6. Canonical Data Model (Reconciled Types)
7. Incremental Detection: Two-Level Strategy
8. Three-Layer Incrementality (Scanner Owns Layer 1)
9. `.driftignore` Format + 18 Default Ignores
10. Configuration (ScanConfig — Reconciled)
11. Structured Error Types (thiserror)
12. Event Emissions (DriftEventHandler)
13. Observability (tracing)
14. Cancellation Support
15. NAPI Interface
16. Storage Integration (file_metadata — Reconciled)
17. Performance Targets
18. macOS / Platform Considerations
19. v1 → v2 Gap Closure
20. Security Considerations
21. Build Order
22. Cross-System Impact Matrix
23. Decision Registry

---

## 1. Architectural Position

The scanner is Level 0 — Bedrock. It is the entry point to the entire Drift pipeline.
Every analysis path starts with "which files exist and which changed?" Nothing runs
without it. No parsers, no detectors, no call graph, no boundaries, no taint, no
contracts, no test topology, no DNA, no constraints — nothing.

Per PLANNING-DRIFT.md D1: Drift is standalone. Scanner depends only on drift-core
infrastructure (config, thiserror, tracing, DriftEventHandler).
Per PLANNING-DRIFT.md D5: Scanner emits events via DriftEventHandler (no-op defaults).
Per AD6: thiserror ScanError enum from the first line of code.
Per AD10: tracing instrumentation from the first line of code.

### What Lives Here
- Parallel file discovery via `ignore` crate's `WalkParallel`
- Content hashing via xxh3 (optional blake3 behind config flag)
- Two-level incremental detection (mtime → content hash)
- `.driftignore` support (gitignore syntax, hierarchical)
- 18 built-in default ignore patterns
- Language detection from file extension
- `ScanDiff` output (added/modified/removed/unchanged)
- `ScanEntry` per-file metadata (path, hash, mtime, size, language)
- `ScanStats` timing and throughput metrics
- Binary file detection and skip
- Cancellation via `AtomicBool`
- Progress reporting via `DriftEventHandler`

### What Does NOT Live Here
- Parsing (Level 0 — consumes ScanDiff)
- Dependency graph / import resolution (Level 1 — Call Graph Builder)
- Detection / pattern matching (Level 1 — Unified Analysis Engine)
- File content analysis of any kind (scanner discovers, it does not analyze)
- Watch mode / file watcher (separate system, calls scanner on change events)

### Downstream Consumers (30+ Systems)

| Consumer | What It Reads From Scanner | Critical Fields |
|----------|--------------------------|-----------------|
| Parsers | ScanDiff.added + modified (file list) | paths to parse |
| Unified Analysis Engine | ScanDiff + ScanEntry (file list + metadata) | file_path, content_hash, language |
| Call Graph Builder | ScanDiff (incremental edge invalidation) | added, modified, removed |
| Detector System | ScanDiff (which files to re-detect) | added, modified |
| Storage (file_metadata) | ScanEntry (bulk upsert after scan) | path, content_hash, mtime, size, language |
| Coupling Analysis | ScanDiff + content hashes | file list for import/export extraction |
| Contract Tracking | ScanDiff (incremental contract analysis) | added, modified, removed |
| DNA System | ScanDiff (incremental fingerprinting) | added, modified |
| Test Topology | ScanDiff (test file discovery) | added, modified + language |
| Quality Gates | ScanStats (scan health metrics) | total_files, cache_hit_rate |
| NAPI Bridge | ScanSummary (lightweight summary) | counts, duration, languages |
| Batch API | Scanner is Phase 1 of analyze_batch() | ScanDiff feeds all subsequent phases |

### Upstream Dependencies

| Dependency | What It Provides | Why Needed |
|-----------|-----------------|------------|
| Configuration (Level 0) | ScanConfig (max_file_size, threads, ignores) | Scanner configuration |
| thiserror (Level 0) | ScanError enum | Structured error handling |
| tracing (Level 0) | Spans and metrics | Observability |
| DriftEventHandler (Level 0) | Event emission trait | Scan lifecycle events |
| Storage (Level 0) | DatabaseManager (file_metadata table) | Incremental detection cache |

**Dependency truth**: Config + thiserror + tracing + DriftEventHandler → **Scanner** → Parsers → Storage → NAPI → everything else



---

## 2. Resolved Inconsistencies (Critical — Read First)

The original 00-SCANNER.md research doc and previous V2-PREP doc were written BEFORE
the downstream V2-PREP documents that define contracts against scanner output. Those
downstream docs evolved the ScanDiff/ScanEntry/ScanStats shapes. This section reconciles
every discrepancy.

### Inconsistency #1: file_metadata Table Schema (00-SCANNER-V2-PREP vs 02-STORAGE-V2-PREP)

The previous scanner V2-PREP defined a minimal `file_metadata` table. The storage V2-PREP
(02-STORAGE-V2-PREP.md §11) defines an expanded schema with additional columns.

| Column | 00-SCANNER-V2-PREP | 02-STORAGE-V2-PREP | Resolution |
|--------|-------------------|-------------------|------------|
| `path` | TEXT PRIMARY KEY | TEXT PRIMARY KEY | ✅ Same |
| `content_hash` | BLOB NOT NULL | BLOB NOT NULL | ✅ Same |
| `mtime_secs` | INTEGER NOT NULL | INTEGER NOT NULL | ✅ Same |
| `mtime_nanos` | INTEGER NOT NULL | INTEGER NOT NULL | ✅ Same |
| `file_size` | INTEGER NOT NULL | `size` INTEGER NOT NULL | ⚡ Name differs — use `file_size` (more explicit) |
| `last_indexed_at` | INTEGER NOT NULL | `last_scanned` TEXT | ⚡ Name + type differ — use `last_scanned_at` INTEGER (epoch seconds) |
| `language` | ❌ Not present | TEXT | **ADD** — Language detection is scanner's job |
| `scan_duration_us` | ❌ Not present | INTEGER | **ADD** — Per-file scan timing for observability |
| `pattern_count` | ❌ Not present | INTEGER DEFAULT 0 | **ADD** — Counter cache, updated by detectors |
| `function_count` | ❌ Not present | INTEGER DEFAULT 0 | **ADD** — Counter cache, updated by parsers |
| `error_count` | ❌ Not present | INTEGER DEFAULT 0 | **ADD** — Parse error count |
| `error` | ❌ Not present | TEXT | **ADD** — Last parse/scan error message |

**Decision**: Use the expanded schema from 02-STORAGE-V2-PREP. The scanner writes the
core columns (path, content_hash, mtime, file_size, language, last_scanned_at, scan_duration_us).
Downstream systems (parsers, detectors) update the counter cache columns.

### Inconsistency #2: ScanEntry Fields (Previous V2-PREP vs Hierarchy)

| Field | Previous V2-PREP (§18) | Hierarchy | Resolution |
|-------|----------------------|-----------|------------|
| `language` | Added in §20 as afterthought | `ScanEntry includes language: Option<Language>` | **PROMOTE** — language is a first-class field |
| `content_hash` type | `u64` | Not specified | **KEEP** u64 — xxh3 produces 64-bit hash |

**Decision**: `ScanEntry.language: Option<Language>` is a first-class field, not an afterthought.
The scanner detects language from file extension during discovery — trivial and avoids
the parser having to re-derive it.

### Inconsistency #3: ScanConfig Fields (Previous V2-PREP vs Hierarchy)

| Field | Previous V2-PREP | Hierarchy | Resolution |
|-------|-----------------|-----------|------------|
| `hash_algorithm` | ❌ Not present | `hash_algorithm ("xxh3"|"blake3")` | **ADD** — Enterprise feature for audit trails |
| `max_file_size` default | 1MB (1_048_576) | 1MB default | ✅ Same |
| `threads` default | 0 = auto | 0 = auto | ✅ Same |

**Decision**: Add `hash_algorithm: Option<String>` to ScanConfig. Default "xxh3",
alternative "blake3" for enterprise audit trails.

### Inconsistency #4: ScanStats Fields (Previous V2-PREP vs Hierarchy)

| Field | Previous V2-PREP | Hierarchy | Resolution |
|-------|-----------------|-----------|------------|
| `languages_found` | Added in §20 as afterthought | `languages_found` in ScanStats | **PROMOTE** — first-class field |
| `files_skipped_large` | ✅ Present | ✅ Present | ✅ Same |
| `files_skipped_ignored` | ✅ Present | ✅ Present | ✅ Same |

### Inconsistency #5: Content Hash Storage (Open Item in Previous V2-PREP)

Previous V2-PREP §21 left this as an open question: store xxh3 as BLOB or INTEGER?

**Resolution**: Store as **BLOB** (8 bytes). Rationale:
- A hash is semantically an opaque identifier, not a number
- BLOB comparison is byte-exact (no integer overflow concerns)
- SQLite BLOB is exactly 8 bytes for xxh3 — same storage as INTEGER
- Consistent with how blake3 (32 bytes) would be stored if hash_algorithm changes
- The hierarchy says `content_hash BLOB NOT NULL`

### Inconsistency #6: Open Items Resolution (Previous V2-PREP §21)

The previous V2-PREP left 6 open items. All are now resolved:

| Open Item | Resolution |
|-----------|------------|
| Symlink handling | **Never follow** (matches git behavior). `follow_symlinks = false` default. |
| Binary file detection | **Skip by default**. `skip_binary = true`. Use `ignore` crate's null-byte heuristic. |
| Watch mode | **Separate system**. Not part of scanner. Uses `notify` crate, calls `scan()` on events. |
| Parallel hashing I/O saturation | **Ignore for v2** (target is SSD). Revisit if HDD users report issues. |
| Content hash storage format | **BLOB** (see Inconsistency #5 above). |
| Dependency graph ownership | **Confirmed**: scanner does NOT build import/export graphs. Call Graph Builder owns this. |

### Summary of All Resolutions

| # | Inconsistency | Resolution | Impact |
|---|--------------|------------|--------|
| 1 | file_metadata schema mismatch | Use expanded schema from 02-STORAGE-V2-PREP | Scanner writes more columns |
| 2 | ScanEntry.language as afterthought | Promote to first-class field | Language detected during discovery |
| 3 | ScanConfig missing hash_algorithm | Add hash_algorithm field | Enterprise blake3 support |
| 4 | ScanStats.languages_found as afterthought | Promote to first-class field | Language breakdown in stats |
| 5 | Content hash BLOB vs INTEGER | BLOB (8 bytes) | Consistent with blake3 upgrade path |
| 6 | 6 open items unresolved | All resolved | No open items remain |


---

## 3. Core Library: `ignore` Crate v0.4

The `ignore` crate is the parallel file walker extracted from ripgrep by BurntSushi
(Andrew Gallick). It is the clear winner — no other library offers the combination of
parallel walking, native gitignore support, and battle-tested reliability.

### Why `ignore` Over Alternatives

| Library | Parallel | Gitignore | Custom Ignore | Battle-Tested |
|---------|----------|-----------|---------------|---------------|
| `ignore` v0.4 | ✅ WalkParallel | ✅ Native (nested, hierarchical) | ✅ `add_custom_ignore_filename` | ripgrep, fd, delta, difftastic (80M+ downloads) |
| `walkdir` + rayon | ❌ Sequential walk, parallel post | ❌ Manual | ❌ Manual | walkdir is solid, but you reinvent ignore |
| `jwalk` | ✅ Parallel + sorted | ❌ None | ❌ None | Less battle-tested |

The `ignore` crate subsumes `walkdir` (same author) and adds everything Drift needs.
Using `walkdir` + manual gitignore + rayon is strictly worse.

### Key API

```rust
use ignore::WalkBuilder;

let walker = WalkBuilder::new(root)
    .hidden(false)                              // Don't skip hidden files by default
    .git_ignore(true)                           // Respect .gitignore
    .git_global(true)                           // Respect global gitignore
    .git_exclude(true)                          // Respect .git/info/exclude
    .add_custom_ignore_filename(".driftignore")  // Custom ignore file
    .max_filesize(Some(config.max_file_size()))  // 1MB default
    .follow_links(config.follow_symlinks())      // false default
    .threads(config.thread_count())              // 0 = auto
    .build_parallel();
```

### Cargo Dependencies

```toml
[workspace.dependencies]
ignore = "0.4"
rayon = "1.10"
xxhash-rust = { version = "0.8", features = ["xxh3"] }
num_cpus = "1.16"
```

Per 04-INFRASTRUCTURE-V2-PREP §7, these are pinned in the Cargo workspace.



---

## 4. Content Hashing: xxh3 via `xxhash-rust` v0.8

### Primary: xxh3

xxh3 is the right default for content hashing. It's fast, portable, deterministic,
and has excellent collision resistance for non-cryptographic use.

Benchmark data (from [rosetta-hashing](https://blog.goose.love/posts/rosetta-hashing/)):

| Algorithm | Large Input Time | Type | Portable |
|-----------|-----------------|------|----------|
| xxh3 | ~580µs | Non-crypto | ✅ All platforms |
| blake3 | ~4,472µs | Cryptographic | ✅ All platforms (SIMD auto) |
| SipHash (std) | ~2,175µs | Non-crypto | ✅ |
| FNV | ~8,937µs | Non-crypto | ✅ |

For typical source files (10-50KB): microseconds per file.
For 100K files at 20KB average: ~200ms total hashing time with xxh3.

### Optional: blake3 Behind Config Flag

blake3 is ~8x slower than xxh3 but provides cryptographic-quality hashes. Useful for:
- Enterprise audit trails (tamper-evident file integrity)
- Lock file verification
- Supply chain security

The performance difference only matters at scale: 100K files saves ~400ms with xxh3
over blake3. Meaningful but not critical.

### Implementation

```rust
use xxhash_rust::xxh3::xxh3_64;

pub fn hash_content(content: &[u8], algorithm: HashAlgorithm) -> ContentHash {
    match algorithm {
        HashAlgorithm::Xxh3 => {
            let hash = xxh3_64(content);
            ContentHash::Xxh3(hash)
        }
        HashAlgorithm::Blake3 => {
            let hash = blake3::hash(content);
            ContentHash::Blake3(*hash.as_bytes())
        }
    }
}

#[derive(Debug, Clone)]
pub enum ContentHash {
    Xxh3(u64),                    // 8 bytes
    Blake3([u8; 32]),             // 32 bytes
}

impl ContentHash {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            ContentHash::Xxh3(h) => &h.to_le_bytes(),
            ContentHash::Blake3(h) => h,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Xxh3,
    Blake3,
}

impl Default for HashAlgorithm {
    fn default() -> Self { HashAlgorithm::Xxh3 }
}
```

### Not Suitable

- **ahash**: Output not stable across versions/platforms (uses random state for DoS
  resistance). Cannot be persisted to disk.
- **SipHash (std)**: 4x slower than xxh3, no benefit for this use case.
- **FNV**: 15x slower, no benefit.
- **meowHash/gxHash**: Not portable (x86 only / hardware AES required).


---

## 5. Two-Phase Architecture

### Phase 1 — Discovery (`ignore::WalkParallel`)

Walk the filesystem in parallel, collecting paths into a `Vec<DiscoveredFile>`.
This gives us the total file count upfront for progress reporting.

```rust
pub struct DiscoveredFile {
    pub path: PathBuf,
    pub file_size: u64,
    pub mtime: SystemTime,
    pub language: Option<Language>,    // Detected from extension
}
```

The `ignore` crate's `WalkParallel` uses an internal work-stealing thread pool.
Each worker thread processes directory entries, applies ignore rules, and sends
results to a shared collector.

```rust
fn discover_files(
    root: &Path,
    config: &ScanConfig,
    event_handler: &dyn DriftEventHandler,
) -> Result<Vec<DiscoveredFile>, ScanError> {
    let (tx, rx) = crossbeam_channel::unbounded();
    let max_size = config.max_file_size();
    let skip_binary = config.skip_binary();

    let walker = WalkBuilder::new(root)
        .hidden(false)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .add_custom_ignore_filename(".driftignore")
        .max_filesize(Some(max_size))
        .follow_links(config.follow_symlinks())
        .threads(config.thread_count())
        .build_parallel();

    // Apply default ignores via overrides
    // (see §9 for the 18 default patterns)

    walker.run(|| {
        let tx = tx.clone();
        Box::new(move |entry| {
            match entry {
                Ok(entry) if entry.file_type().map_or(false, |ft| ft.is_file()) => {
                    let path = entry.path().to_path_buf();
                    let metadata = entry.metadata().ok();

                    // Skip binary files if configured
                    if skip_binary && is_binary_file(&path) {
                        return ignore::WalkState::Continue;
                    }

                    let language = Language::from_extension(
                        path.extension().and_then(|e| e.to_str())
                    );

                    if let Some(meta) = metadata {
                        let _ = tx.send(DiscoveredFile {
                            path,
                            file_size: meta.len(),
                            mtime: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                            language,
                        });
                    }
                    ignore::WalkState::Continue
                }
                _ => ignore::WalkState::Continue,
            }
        })
    });

    drop(tx);
    let files: Vec<DiscoveredFile> = rx.into_iter().collect();
    Ok(files)
}
```

### Phase 2 — Processing (`rayon::par_iter`)

Hash file contents, collect metadata, compare against cached state in drift.db.

```rust
fn process_files(
    files: &[DiscoveredFile],
    config: &ScanConfig,
    db: &DatabaseManager,
    event_handler: &dyn DriftEventHandler,
) -> Result<ScanDiff, ScanError> {
    let total = files.len();
    let processed = AtomicUsize::new(0);
    let hash_algo = config.hash_algorithm();

    // Load cached file_metadata from drift.db
    let cached = db.load_file_metadata()?;

    let entries: Vec<ScanEntry> = files.par_iter()
        .filter_map(|file| {
            // Check cancellation
            if is_cancelled() { return None; }

            // Progress reporting (every 100 files)
            let count = processed.fetch_add(1, Ordering::Relaxed);
            if count % 100 == 0 {
                event_handler.on_scan_progress(count, total);
            }

            // Two-level incrementality (see §7)
            let cached_entry = cached.get(&file.path);
            match classify_file(file, cached_entry, hash_algo, config) {
                Ok(entry) => Some(entry),
                Err(e) => {
                    tracing::warn!(path = %file.path.display(), error = %e, "file scan error");
                    None // Non-fatal — skip file, continue scanning
                }
            }
        })
        .collect();

    // Compute diff
    compute_diff(entries, &cached)
}
```

### Why Two Phases

1. **Progress reporting** requires knowing total count upfront (audit: AtomicU64 counter
   + ThreadsafeFunction every 100 files)
2. **Rayon's work-stealing** is better suited for CPU-bound hashing than `ignore`'s
   I/O-oriented thread pool
3. **Clean separation** of I/O-bound discovery from CPU-bound processing
4. **Cancellation** is cleaner — check between files in rayon, not inside walker callbacks


---

## 6. Canonical Data Model (Reconciled Types — Single Source of Truth)

These are the DEFINITIVE scanner types. Reconciled across the previous V2-PREP doc,
the hierarchy, the storage V2-PREP, and all downstream consumer contracts.

### ScanDiff (Primary Output)

```rust
/// The primary output of a scan operation. Classifies every file in the project
/// as added, modified, removed, or unchanged relative to the last scan.
/// Consumed by every downstream system for incremental processing.
pub struct ScanDiff {
    pub added: Vec<PathBuf>,          // New files not in cache
    pub modified: Vec<PathBuf>,       // Content hash changed
    pub removed: Vec<PathBuf>,        // In cache but not on disk
    pub unchanged: Vec<PathBuf>,      // Same content hash (or same mtime)
    pub errors: Vec<ScanError>,       // Non-fatal per-file errors
    pub stats: ScanStats,             // Timing and throughput metrics
    pub entries: FxHashMap<PathBuf, ScanEntry>,  // Full metadata per file
}
```

**Why `entries` map is included**: Downstream consumers (UAE, parsers) need per-file
metadata (language, content_hash) without re-reading the filesystem. The entries map
provides O(1) lookup by path. Memory cost is ~200 bytes per file × 100K files = ~20MB.

### ScanEntry (Per-File Metadata)

```rust
/// Metadata for a single discovered file. Produced during Phase 2 processing.
/// Written to file_metadata table in drift.db.
pub struct ScanEntry {
    pub path: PathBuf,
    pub content_hash: ContentHash,     // xxh3 (8 bytes) or blake3 (32 bytes)
    pub mtime_secs: i64,
    pub mtime_nanos: u32,
    pub file_size: u64,
    pub language: Option<Language>,    // Detected from file extension
    pub scan_duration_us: u64,         // Per-file scan time (hash + metadata)
}
```

### ScanStats (Timing and Throughput)

```rust
/// Aggregate statistics for a scan operation. Used by observability,
/// quality gates, and NAPI summary.
pub struct ScanStats {
    pub total_files: usize,
    pub total_size_bytes: u64,
    pub discovery_ms: u64,             // Phase 1 time
    pub hashing_ms: u64,               // Phase 2 time
    pub diff_ms: u64,                  // Diff computation time
    pub cache_hit_rate: f64,           // % skipped via mtime check (0.0-1.0)
    pub files_skipped_large: usize,    // Oversized files skipped
    pub files_skipped_ignored: usize,  // Ignored files skipped
    pub files_skipped_binary: usize,   // Binary files skipped
    pub languages_found: FxHashMap<Language, usize>,  // Language → file count
}
```

### ScanSummary (NAPI — Lightweight)

```rust
/// Lightweight summary that crosses the NAPI boundary.
/// Full results stay in drift.db.
#[napi(object)]
pub struct ScanSummary {
    pub files_total: u32,
    pub files_added: u32,
    pub files_modified: u32,
    pub files_removed: u32,
    pub files_unchanged: u32,
    pub duration_ms: u32,
    pub status: String,                // "complete" | "partial" | "cancelled"
    pub languages: HashMap<String, u32>,  // Language breakdown for CLI display
    pub cache_hit_rate: f64,
}
```

### Language Enum (Shared with Parsers)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    TypeScript, JavaScript, Python, Java, CSharp,
    Php, Go, Rust, Ruby, Kotlin,
}

impl Language {
    pub fn from_extension(ext: Option<&str>) -> Option<Language> {
        match ext? {
            "ts" | "tsx" | "mts" | "cts" => Some(Language::TypeScript),
            "js" | "jsx" | "mjs" | "cjs" => Some(Language::JavaScript),
            "py" | "pyi" => Some(Language::Python),
            "java" => Some(Language::Java),
            "cs" => Some(Language::CSharp),
            "php" => Some(Language::Php),
            "go" => Some(Language::Go),
            "rs" => Some(Language::Rust),
            "rb" | "rake" | "gemspec" => Some(Language::Ruby),
            "kt" | "kts" => Some(Language::Kotlin),
            _ => None,
        }
    }
}
```

This is the same `Language` enum used by the parser system (01-PARSERS-V2-PREP §4).
Defined once in drift-core, shared by scanner and parsers.



---

## 7. Incremental Detection: Two-Level Strategy

This is the core value of the scanner — avoiding redundant work. The two-level strategy
is the same approach used by git's index and rust-analyzer's VFS.

### Level 1: mtime Comparison (Instant — Catches ~95% Unchanged)

```
if file.mtime == cached.mtime → SKIP (unchanged, no hash needed)
```

A single `stat()` call per file — nanoseconds. This catches the vast majority of
unchanged files because most files don't change between scans.

### Level 2: Content Hash (For mtime-Changed Files)

```
if file.mtime != cached.mtime → compute xxh3 hash
  if hash == cached.hash → UNCHANGED (update mtime in cache, skip re-analysis)
  if hash != cached.hash → MODIFIED (needs re-analysis)
```

This handles:
- `git checkout` / `git rebase` (changes mtime but not content)
- `touch` command (changes mtime without editing)
- Editor save-without-change (some editors rewrite the file)
- CI environments that extract archives (new mtimes, same content)

### File Classification Algorithm

```rust
fn classify_file(
    file: &DiscoveredFile,
    cached: Option<&CachedFileMetadata>,
    hash_algo: HashAlgorithm,
    config: &ScanConfig,
) -> Result<(FileStatus, ScanEntry), ScanError> {
    let start = Instant::now();

    match cached {
        None => {
            // New file — not in cache
            let content = fs::read(&file.path)
                .map_err(|e| ScanError::Io { path: file.path.clone(), source: e })?;
            let hash = hash_content(&content, hash_algo);
            let entry = ScanEntry {
                path: file.path.clone(),
                content_hash: hash,
                mtime_secs: mtime_secs(&file.mtime),
                mtime_nanos: mtime_nanos(&file.mtime),
                file_size: file.file_size,
                language: file.language,
                scan_duration_us: start.elapsed().as_micros() as u64,
            };
            Ok((FileStatus::Added, entry))
        }
        Some(cached) => {
            // Level 1: mtime check
            if mtime_secs(&file.mtime) == cached.mtime_secs
                && mtime_nanos(&file.mtime) == cached.mtime_nanos
                && !config.force_full_scan()
            {
                // mtime unchanged — skip hash
                return Ok((FileStatus::Unchanged, cached.to_scan_entry()));
            }

            // Level 2: content hash
            let content = fs::read(&file.path)
                .map_err(|e| ScanError::Io { path: file.path.clone(), source: e })?;
            let hash = hash_content(&content, hash_algo);
            let entry = ScanEntry {
                path: file.path.clone(),
                content_hash: hash.clone(),
                mtime_secs: mtime_secs(&file.mtime),
                mtime_nanos: mtime_nanos(&file.mtime),
                file_size: file.file_size,
                language: file.language,
                scan_duration_us: start.elapsed().as_micros() as u64,
            };

            if hash.as_bytes() == cached.content_hash_bytes() {
                // Content unchanged — update mtime in cache
                Ok((FileStatus::Unchanged, entry))
            } else {
                // Content changed — needs re-analysis
                Ok((FileStatus::Modified, entry))
            }
        }
    }
}

enum FileStatus { Added, Modified, Unchanged }
```

### Diff Computation

```rust
fn compute_diff(
    entries: Vec<(FileStatus, ScanEntry)>,
    cached: &FxHashMap<PathBuf, CachedFileMetadata>,
) -> ScanDiff {
    let mut diff = ScanDiff::default();
    let mut seen_paths: FxHashSet<PathBuf> = FxHashSet::default();

    for (status, entry) in entries {
        seen_paths.insert(entry.path.clone());
        match status {
            FileStatus::Added => diff.added.push(entry.path.clone()),
            FileStatus::Modified => diff.modified.push(entry.path.clone()),
            FileStatus::Unchanged => diff.unchanged.push(entry.path.clone()),
        }
        diff.entries.insert(entry.path.clone(), entry);
    }

    // Files in cache but not on disk → removed
    for cached_path in cached.keys() {
        if !seen_paths.contains(cached_path) {
            diff.removed.push(cached_path.clone());
        }
    }

    diff
}
```


---

## 8. Three-Layer Incrementality (Scanner Owns Layer 1)

From AD1. The scanner owns Layer 1. Layers 2 and 3 are downstream but the scanner's
output drives them.

| Layer | Owner | Strategy | Trigger |
|-------|-------|----------|---------|
| **L1: File-level skip** | Scanner | mtime + content hash → skip unchanged files | Every scan |
| **L2: Pattern re-scoring** | Detectors | Only re-detect patterns in changed files | ScanDiff.modified |
| **L3: Re-learning threshold** | Conventions | Full re-learn if >10% files changed | ScanDiff ratio |

The scanner must provide enough information for downstream systems to make L2/L3 decisions.
This means `ScanStats` includes `cache_hit_rate` and `ScanDiff` provides the ratio:
`modified.len() / (total_files)`.

### L3 Threshold Calculation

```rust
impl ScanDiff {
    /// Ratio of changed files to total files.
    /// Used by convention learning to decide full re-learn vs incremental.
    pub fn change_ratio(&self) -> f64 {
        let total = self.added.len() + self.modified.len()
            + self.removed.len() + self.unchanged.len();
        if total == 0 { return 0.0; }
        (self.added.len() + self.modified.len()) as f64 / total as f64
    }

    /// Whether the change ratio exceeds the re-learning threshold.
    pub fn exceeds_relearn_threshold(&self, threshold: f64) -> bool {
        self.change_ratio() > threshold
    }
}
```


---

## 9. `.driftignore` Format + 18 Default Ignores

### `.driftignore` Format

Gitignore syntax exactly. No new format to learn. The `ignore` crate supports custom
ignore filenames via `add_custom_ignore_filename(".driftignore")`. This means `.driftignore`
files are hierarchical — a `.driftignore` in a subdirectory applies to that subtree.

```
# .driftignore
node_modules/
dist/
build/
*.min.js
*.bundle.js
vendor/
__pycache__/
*.pyc
target/
.next/
coverage/
```

### 18 Default Ignores (from Hierarchy)

These are applied even without a `.gitignore` or `.driftignore` file. They cover the
most common build output, dependency, and cache directories across all 10 supported
languages.

```rust
const DEFAULT_IGNORES: &[&str] = &[
    "node_modules",     // JavaScript/TypeScript
    ".git",             // Git
    "dist",             // Build output (JS/TS)
    "build",            // Build output (Java, Go, general)
    "target",           // Build output (Rust, Java/Maven)
    ".next",            // Next.js
    ".nuxt",            // Nuxt.js
    "__pycache__",      // Python bytecode cache
    ".pytest_cache",    // Python test cache
    "coverage",         // Test coverage output
    ".nyc_output",      // NYC coverage output
    "vendor",           // PHP Composer, Go modules
    ".venv",            // Python virtual environment
    "venv",             // Python virtual environment (alt)
    ".tox",             // Python tox testing
    ".mypy_cache",      // Python mypy type checker cache
    "bin",              // C#/Java build output
    "obj",              // C# build output
];
```

### Implementation via `ignore::overrides::OverrideBuilder`

```rust
fn apply_default_ignores(builder: &mut WalkBuilder, root: &Path) {
    let mut overrides = ignore::overrides::OverrideBuilder::new(root);
    for pattern in DEFAULT_IGNORES {
        // Negate pattern = exclude from results
        overrides.add(&format!("!{}/", pattern)).unwrap();
    }
    if let Ok(built) = overrides.build() {
        builder.overrides(built);
    }
}
```

Default ignores are overridable: if a user explicitly includes a default-ignored
directory in their `.driftignore` with `!node_modules/`, it will be scanned.


---

## 10. Configuration (ScanConfig — Reconciled)

From 04-INFRASTRUCTURE-V2-PREP §5, reconciled with the hierarchy's authoritative specs.

```rust
#[derive(Deserialize, Default, Debug, Clone)]
pub struct ScanConfig {
    /// Maximum file size in bytes. Files larger than this are skipped.
    /// Default: 1MB (1_048_576). Files over 1MB are typically generated code,
    /// bundles, or data files — not useful for convention detection.
    pub max_file_size: Option<u64>,

    /// Number of threads for parallel processing. 0 = auto-detect via num_cpus.
    pub threads: Option<usize>,

    /// Additional ignore patterns beyond .gitignore/.driftignore.
    #[serde(default)]
    pub extra_ignore: Vec<String>,

    /// Whether to follow symbolic links. Default: false.
    /// Never follow — matches git behavior, avoids infinite loops.
    pub follow_symlinks: Option<bool>,

    /// Whether to compute content hashes. Default: true.
    /// Set to false for fast file-list-only mode (discovery without hashing).
    pub compute_hashes: Option<bool>,

    /// Force full rescan, skipping mtime optimization. Default: false.
    /// Useful after git operations that touch many file mtimes.
    pub force_full_scan: Option<bool>,

    /// Skip binary files (detected via null-byte heuristic). Default: true.
    pub skip_binary: Option<bool>,

    /// Hash algorithm. Default: "xxh3". Alternative: "blake3" (enterprise).
    pub hash_algorithm: Option<String>,
}

impl ScanConfig {
    pub fn max_file_size(&self) -> u64 {
        self.max_file_size.unwrap_or(1_048_576)
    }

    pub fn thread_count(&self) -> usize {
        self.threads.unwrap_or(0) // 0 = auto
    }

    pub fn follow_symlinks(&self) -> bool {
        self.follow_symlinks.unwrap_or(false)
    }

    pub fn compute_hashes(&self) -> bool {
        self.compute_hashes.unwrap_or(true)
    }

    pub fn force_full_scan(&self) -> bool {
        self.force_full_scan.unwrap_or(false)
    }

    pub fn skip_binary(&self) -> bool {
        self.skip_binary.unwrap_or(true)
    }

    pub fn hash_algorithm(&self) -> HashAlgorithm {
        match self.hash_algorithm.as_deref() {
            Some("blake3") => HashAlgorithm::Blake3,
            _ => HashAlgorithm::Xxh3,
        }
    }
}
```

### TOML Example

```toml
[scan]
max_file_size = 1_048_576
threads = 0
extra_ignore = ["*.generated.ts", "vendor/"]
follow_symlinks = false
compute_hashes = true
force_full_scan = false
skip_binary = true
hash_algorithm = "xxh3"
```

### Environment Variable Overrides

| Env Var | Config Field | Example |
|---------|-------------|---------|
| `DRIFT_SCAN_MAX_FILE_SIZE` | max_file_size | `2097152` (2MB) |
| `DRIFT_SCAN_THREADS` | threads | `4` |
| `DRIFT_SCAN_HASH_ALGORITHM` | hash_algorithm | `blake3` |
| `DRIFT_SCAN_FORCE_FULL` | force_full_scan | `true` |



---

## 11. Structured Error Types (thiserror)

Per AD6 (thiserror from first line of code). From 04-INFRASTRUCTURE-V2-PREP §2.

```rust
#[derive(thiserror::Error, Debug)]
pub enum ScanError {
    #[error("IO error scanning {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },

    #[error("File too large: {path} ({size} bytes, max {max})")]
    FileTooLarge { path: PathBuf, size: u64, max: u64 },

    #[error("Permission denied: {path}")]
    PermissionDenied { path: PathBuf },

    #[error("Config error: {message}")]
    Config { message: String },

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Scan cancelled")]
    Cancelled,
}
```

### Error Behavior

Errors are **non-fatal at the file level**. A single file failing to read/hash does NOT
abort the entire scan. Collect errors, continue scanning, report at the end.

```rust
// In rayon par_iter:
match process_file(file) {
    Ok(entry) => entries.push(entry),
    Err(e) => {
        tracing::warn!(path = %file.path.display(), error = %e, "skipping file");
        errors.push(e);
    }
}
```

The `ScanDiff.errors` vector collects all non-fatal errors. The NAPI summary reports
the error count. Individual errors are queryable via drift.db's `file_metadata.error` column.

### NAPI Error Codes (from 03-NAPI-BRIDGE-V2-PREP §6)

| ScanError Variant | NAPI Code | Meaning |
|-------------------|-----------|---------|
| `Io { .. }` | `SCAN_ERROR` | File I/O error during scan |
| `FileTooLarge { .. }` | `FILE_TOO_LARGE` | File exceeds max_file_size |
| `PermissionDenied { .. }` | `PERMISSION_DENIED` | OS permission denied |
| `Config { .. }` | `CONFIG_ERROR` | Invalid scan configuration |
| `Storage(..)` | `STORAGE_ERROR` | Database error during scan |
| `Cancelled` | `SCAN_CANCELLED` | Scan cancelled by user |


---

## 12. Event Emissions (DriftEventHandler)

Per D5: The scanner emits events via `DriftEventHandler`. Zero overhead when no handlers
registered (standalone mode). When the bridge is active, these events feed into Cortex
memory creation.

From 04-INFRASTRUCTURE-V2-PREP §4, the scanner uses these event methods:

```rust
// Scanner-specific event methods (subset of DriftEventHandler trait)
fn on_scan_started(&self, _root: &Path, _file_count: Option<usize>) {}
fn on_scan_progress(&self, _processed: usize, _total: usize) {}
fn on_scan_complete(&self, _results: &ScanDiff) {}
fn on_scan_error(&self, _error: &ScanError) {}
```

### Emission Points

| Event | When Emitted | Data |
|-------|-------------|------|
| `on_scan_started` | After Phase 1 discovery completes | root path, total file count |
| `on_scan_progress` | Every 100 files during Phase 2 | processed count, total count |
| `on_scan_complete` | After diff computation | full ScanDiff |
| `on_scan_error` | On fatal scan error (not per-file) | ScanError |

### Progress Reporting Frequency

From audit: report every 100 files via `AtomicUsize` counter shared across rayon workers.
The `NapiProgressHandler` (from 03-NAPI-BRIDGE-V2-PREP §7) bridges `DriftEventHandler`
→ `ThreadsafeFunction` for TS progress callbacks.

```rust
let count = processed.fetch_add(1, Ordering::Relaxed);
if count % 100 == 0 || count == total {
    event_handler.on_scan_progress(count, total);
}
```

This keeps NAPI callback overhead negligible (<0.1% of scan time).


---

## 13. Observability (tracing)

Per AD10: Instrument with `tracing` crate from day one.

```rust
#[instrument(skip(config, db, event_handler), fields(root = %root.display()))]
pub fn scan(
    root: &Path,
    config: &ScanConfig,
    db: &DatabaseManager,
    event_handler: &dyn DriftEventHandler,
) -> Result<ScanDiff, ScanError> {
    let scan_start = Instant::now();

    // Phase 1: Discovery
    let _discovery = info_span!("discovery").entered();
    let files = discover_files(root, config, event_handler)?;
    let discovery_ms = scan_start.elapsed().as_millis() as u64;
    info!(file_count = files.len(), discovery_ms, "discovery complete");

    event_handler.on_scan_started(root, Some(files.len()));

    // Phase 2: Processing
    let hash_start = Instant::now();
    let _processing = info_span!("processing").entered();
    let mut diff = process_files(&files, config, db, event_handler)?;
    let hashing_ms = hash_start.elapsed().as_millis() as u64;

    // Compute stats
    diff.stats.discovery_ms = discovery_ms;
    diff.stats.hashing_ms = hashing_ms;
    diff.stats.total_files = files.len();
    diff.stats.total_size_bytes = files.iter().map(|f| f.file_size).sum();
    diff.stats.cache_hit_rate = diff.unchanged.len() as f64 / files.len().max(1) as f64;

    info!(
        added = diff.added.len(),
        modified = diff.modified.len(),
        removed = diff.removed.len(),
        unchanged = diff.unchanged.len(),
        cache_hit_rate = diff.stats.cache_hit_rate,
        total_ms = scan_start.elapsed().as_millis() as u64,
        "scan complete"
    );

    event_handler.on_scan_complete(&diff);
    Ok(diff)
}
```

### Key Metrics (from AD10, hierarchy)

| Metric | What It Measures | Why |
|--------|-----------------|-----|
| `scan_files_per_second` | Overall throughput | Performance target validation |
| `discovery_duration_ms` | Phase 1 time | Identify filesystem bottlenecks |
| `hashing_duration_ms` | Phase 2 time | Identify hashing bottlenecks |
| `cache_hit_rate` | % files skipped via mtime | Validate incrementality |
| `files_skipped_large` | Oversized files | Tune max_file_size |
| `files_skipped_ignored` | Ignored files | Validate ignore patterns |
| `files_skipped_binary` | Binary files | Validate binary detection |


---

## 14. Cancellation Support

From audit A6/A21 and 03-NAPI-BRIDGE-V2-PREP §8.

### Global Cancellation Flag

```rust
use std::sync::atomic::{AtomicBool, Ordering};

static SCAN_CANCELLED: AtomicBool = AtomicBool::new(false);

pub fn cancel_scan() {
    SCAN_CANCELLED.store(true, Ordering::SeqCst);
}

fn reset_cancellation() {
    SCAN_CANCELLED.store(false, Ordering::SeqCst);
}

pub fn is_cancelled() -> bool {
    SCAN_CANCELLED.load(Ordering::Relaxed)
}
```

### Cancellation Behavior

1. TS calls `cancel_scan()` → sets `AtomicBool` to true
2. Rayon workers check `is_cancelled()` between files
3. Already-processed files are persisted to drift.db
4. In-progress file is discarded (partial hash dropped)
5. Scan returns with `status: "partial"` in `ScanSummary`
6. Next scan call resets the flag via `reset_cancellation()`

### Integration with rayon

```rust
files.par_iter().try_for_each(|file| {
    if is_cancelled() {
        return Err(ScanError::Cancelled);
    }
    process_file(file)
})?;
```

`try_for_each` short-circuits on the first `Err`, causing all rayon workers to stop.
Already-completed work is preserved.


---

## 15. NAPI Interface

From 03-NAPI-BRIDGE-V2-PREP §5, §7, §9, §10. The scanner follows the "compute + store
in Rust, return summary" pattern.

### Command Functions

```rust
/// Full scan — discovers files, hashes, computes diff, writes to drift.db.
/// Returns lightweight summary. Full results queryable via drift.db.
#[napi]
pub fn native_scan(root: String, options: ScanOptions) -> AsyncTask<ScanTask> { ... }

/// Async variant with progress callback via ThreadsafeFunction (v3).
#[napi]
pub fn native_scan_with_progress(
    root: String,
    options: ScanOptions,
    on_progress: ThreadsafeFunction<ProgressUpdate, ()>,
) -> AsyncTask<ScanWithProgressTask> { ... }

/// Cancel a running scan operation.
#[napi]
pub fn cancel_scan() -> napi::Result<()> { ... }
```

### Query Functions

```rust
/// Query files changed since a given timestamp.
#[napi]
pub fn query_changed_files(since: Option<i64>) -> napi::Result<Vec<FileChangeJs>> { ... }

/// Query metadata for a specific file.
#[napi]
pub fn query_file_metadata(path: String) -> napi::Result<Option<FileMetadataJs>> { ... }

/// Get scan history (last N scans).
#[napi]
pub fn query_scan_history(limit: Option<u32>) -> napi::Result<Vec<ScanHistoryJs>> { ... }
```

### What Crosses NAPI (lightweight)

- `ScanSummary` — counts, duration, status, language breakdown
- `ProgressUpdate` — processed count, total count, phase
- `FileChangeJs` — path, change type, language
- `FileMetadataJs` — path, size, language, last scanned

### What Does NOT Cross NAPI (stays in Rust/SQLite)

- Full file list (100K+ paths)
- Content hashes (8-32 bytes per file)
- Full ScanDiff (consumed by Rust analysis pipeline)
- File contents (never read into JS)
- ScanEntry details (in drift.db, queryable on demand)

### Batch API Integration

The scanner is Phase 1 of the `analyze_batch()` API (03-NAPI-BRIDGE-V2-PREP §9).
When `analyze_batch(root, ["patterns", "call_graph", "boundaries"])` is called,
the scanner runs first, producing a `ScanDiff` that feeds all subsequent analyses.
The ScanDiff is shared in-memory — no round-trip through drift.db.


---

## 16. Storage Integration (file_metadata — Reconciled)

From 02-STORAGE-V2-PREP §11, reconciled with scanner requirements.

### Table Schema (Definitive)

```sql
CREATE TABLE file_metadata (
    path TEXT PRIMARY KEY,
    language TEXT,                        -- Detected by scanner from extension
    file_size INTEGER NOT NULL,
    content_hash BLOB NOT NULL,          -- xxh3 (8 bytes) or blake3 (32 bytes)
    mtime_secs INTEGER NOT NULL,
    mtime_nanos INTEGER NOT NULL,
    last_scanned_at INTEGER NOT NULL,    -- Epoch seconds
    scan_duration_us INTEGER,            -- Per-file scan time
    pattern_count INTEGER DEFAULT 0,     -- Counter cache (updated by detectors)
    function_count INTEGER DEFAULT 0,    -- Counter cache (updated by parsers)
    error_count INTEGER DEFAULT 0,       -- Parse error count
    error TEXT                           -- Last parse/scan error message
) STRICT;

CREATE INDEX idx_file_metadata_language ON file_metadata(language);
CREATE INDEX idx_file_metadata_errors ON file_metadata(path) WHERE error IS NOT NULL;
CREATE INDEX idx_file_metadata_scanned ON file_metadata(last_scanned_at);
```

### Scanner Writes These Columns

| Column | Written By | When |
|--------|-----------|------|
| `path` | Scanner | On discovery |
| `language` | Scanner | On discovery (from extension) |
| `file_size` | Scanner | On discovery |
| `content_hash` | Scanner | On Phase 2 hashing |
| `mtime_secs` | Scanner | On Phase 2 |
| `mtime_nanos` | Scanner | On Phase 2 |
| `last_scanned_at` | Scanner | On scan completion |
| `scan_duration_us` | Scanner | On Phase 2 |

### Downstream Systems Update These Columns

| Column | Updated By | When |
|--------|-----------|------|
| `pattern_count` | Detector System | After detection pass |
| `function_count` | Parser System | After parse pass |
| `error_count` | Parser System | After parse (error nodes) |
| `error` | Parser/Scanner | On parse/scan error |

### Bulk Write Strategy

Scanner uses the batch writer pattern (02-STORAGE-V2-PREP §7) for bulk updates:

```rust
// After scan completion, bulk upsert file_metadata
let batch: Vec<FileMetadataRow> = diff.entries.values()
    .map(|entry| FileMetadataRow::from(entry))
    .collect();
batch_writer.send(WriteBatch::FileMetadata(batch))?;

// Remove entries for deleted files
for removed_path in &diff.removed {
    batch_writer.send(WriteBatch::DeleteFileMetadata(removed_path.clone()))?;
}
```

### Ownership-Based Invalidation

From 02-STORAGE-V2-PREP §11 (AD3). Every derived fact (pattern location, function,
call edge) is linked to the source file via `file_metadata`. When a file is removed
or modified, only its owned facts are invalidated:

```sql
-- When a file is removed, cascade delete its derived data
DELETE FROM pattern_locations WHERE file = ?;
DELETE FROM functions WHERE file = ?;
DELETE FROM call_edges WHERE caller_file = ? OR callee_file = ?;
```

This is triggered by the scanner's `ScanDiff.removed` list.



---

## 17. Performance Targets

From the hierarchy and audit.

### Targets

| Scenario | Target | Strategy |
|----------|--------|----------|
| 10K files cold scan | <300ms | `ignore` parallel walk + rayon xxh3 |
| 100K files cold scan | <1.5s | `ignore` parallel walk + rayon xxh3 |
| Incremental (1 file changed) | <100ms | mtime skip (L1) — no hashing needed |
| Incremental (100 files changed) | <200ms | mtime skip 99.9% + hash 100 files |
| Discovery only (no hashing) | <500ms for 100K files | `ignore` WalkParallel |

### Why These Are Achievable

- `ignore` crate can walk 100K+ files in <500ms on SSD
- xxh3 hashes typical source files (10-50KB) in microseconds
- mtime check is a single `stat()` call — nanoseconds
- rayon distributes hashing across all CPU cores
- Two-level incrementality means 95%+ files are skipped on re-scan

### Benchmark Strategy

Use `criterion` for micro-benchmarks:

```rust
// crates/drift-bench/benches/scanner_bench.rs
fn bench_discovery(c: &mut Criterion) {
    c.bench_function("discover_10k_files", |b| {
        b.iter(|| discover_files(&test_root_10k, &ScanConfig::default()))
    });
}

fn bench_hashing(c: &mut Criterion) {
    c.bench_function("hash_10k_files_xxh3", |b| {
        b.iter(|| hash_files(&test_files_10k, HashAlgorithm::Xxh3))
    });
}

fn bench_incremental(c: &mut Criterion) {
    c.bench_function("incremental_1_file_changed", |b| {
        // Pre-populate cache, change 1 file
        b.iter(|| scan(&test_root, &config, &db, &NoOpHandler))
    });
}
```


---

## 18. macOS / Platform Considerations

### APFS Directory Scanning Limitation

APFS directory scanning is single-threaded at the kernel level. Parallel walking helps
with per-file work (hashing, metadata) but not directory enumeration itself. This is a
known limitation — ripgrep, fd, and the `ignore` crate all have the same constraint on macOS.

Impact: Phase 1 (discovery) may be slower on macOS than Linux for very large repositories.
Phase 2 (hashing) is unaffected — it's CPU-bound and fully parallel.

### Cross-Platform mtime Resolution

| Platform | mtime Resolution | Notes |
|----------|-----------------|-------|
| Linux (ext4) | Nanosecond | Full precision |
| macOS (APFS) | Nanosecond | Full precision |
| Windows (NTFS) | 100ns intervals | Slightly coarser |
| Linux (FAT32) | 2-second | Very coarse — content hash is essential |

The two-level strategy (mtime + content hash) handles all platforms correctly.
On FAT32, more files will fall through to Level 2 (hash check), but correctness
is maintained.

### Symlink Behavior

Default: `follow_symlinks = false`. This matches git behavior and avoids:
- Infinite loops from circular symlinks
- Scanning outside the project root
- Double-counting files accessible via multiple paths

If a user needs to follow symlinks, they can set `scan.follow_symlinks = true`
in drift.toml. The `ignore` crate handles cycle detection internally when
`follow_links(true)` is set.


---

## 19. v1 → v2 Gap Closure

Cross-referenced against all v1 scanner documentation. Every v1 feature accounted for.

### v1 Scanner Components → v2 Mapping

| v1 Component | v1 Location | v2 Status | v2 Location |
|-------------|-------------|-----------|-------------|
| `file-walker.ts` | Sequential TS file walker | **DROPPED** — Rust-only. `ignore` crate is faster. | N/A |
| `native-scanner.ts` | NAPI wrapper | **REPLACED** — TS calls `native_scan()` directly | §15 NAPI |
| `dependency-graph.ts` | Import/export tracking | **MOVED** — Call Graph Builder (Level 1) | 05-CALL-GRAPH |
| `change-detector.ts` | Incremental detection | **ABSORBED** — Two-level mtime+hash in Rust | §7 |
| `default-ignores.ts` | Default ignore patterns | **ABSORBED** — 18 patterns in Rust constant | §9 |
| `worker-pool.ts` | Piscina thread pool | **DROPPED** — Replaced by rayon | §5 |
| `threaded-worker-pool.ts` | Alt thread pool | **DROPPED** — Replaced by rayon | §5 |
| `file-processor-worker.ts` | Per-file processing | **DROPPED** — rayon `par_iter` | §5 |

### v1 ScannerService Features → v2 Mapping

| v1 Feature | v2 Status | v2 Owner |
|-----------|-----------|----------|
| Worker pool creation + warmup | **DROPPED** — Rayon replaces Piscina | Scanner |
| Task dispatch (1 task per file) | **REPLACED** — `rayon::par_iter` | Scanner |
| Detector execution per file | **MOVED** — Unified Analysis Engine | UAE (Level 1) |
| Pattern aggregation | **MOVED** — Post-detection in Rust | Pattern Aggregation (Level 2A) |
| Outlier detection | **MOVED** — After aggregation in Rust | Outlier Detection (Level 2A) |
| Manifest generation | **DROPPED** — SQLite Gold layer replaces | Storage |
| ScanResults assembly | **REPLACED** — Rust writes to drift.db | §15 NAPI |
| Worker stats tracking | **REPLACED** — `tracing` spans | §13 |
| Category filtering | **MOVED** — Detector registry | Detector System (Level 1) |
| Critical-only mode | **MOVED** — Detector registry | Detector System (Level 1) |
| Error collection (non-fatal) | **KEPT** — `ScanDiff.errors` | §11 |

### v1 Pipeline Steps → v2 Mapping

| Pipeline Step | v2 Status | Notes |
|--------------|-----------|-------|
| 1. Resolve project root | **KEPT** | Config system |
| 2. File discovery + ignore + max-file-size + incremental | **KEPT** | Scanner (this system) |
| 3. Parsing per file | **KEPT** | Parsers (Level 0) |
| 4. Detection per file (parallel) | **KEPT** | UAE (Level 1) |
| 5. Aggregation across files | **KEPT** | Pattern Aggregation (Level 2A) |
| 6. Confidence scoring | **UPGRADED** | Bayesian Beta posterior (Level 2A) |
| 7. Pattern storage | **UPGRADED** | drift.db replaces JSON shards |
| 8. Call graph build | **KEPT** | Call Graph (Level 1) |
| 9. Boundary scan | **KEPT** | Boundary Detection (Level 1) |
| 10. Contract scan | **KEPT** | Contract Tracking (Level 2C) |
| 11. Manifest generation | **DROPPED** | SQLite Gold layer |
| 12. Finalization | **KEPT** | Storage Gold refresh, Audit |

### Specific Gaps Closed

| Gap | v1 State | v2 Resolution | Priority |
|-----|----------|---------------|----------|
| Incremental scanning in Rust | ❌ Missing (TS only) | Two-level mtime+hash | P0 |
| Language detection in scanner | ❌ Missing in Rust | `Language::from_extension()` on ScanEntry | P0 |
| Content hashing in Rust | ❌ Missing | xxh3 via xxhash-rust | P0 |
| Default ignore patterns | Hardcoded in TS | 18 patterns in Rust constant | P0 |
| Binary file detection | ❌ Missing | Null-byte heuristic | P1 |
| Progress reporting from Rust | ❌ Missing | DriftEventHandler + AtomicUsize | P0 |
| Cancellation from Rust | ❌ Missing | AtomicBool + rayon try_for_each | P0 |
| Per-file scan timing | ❌ Missing | scan_duration_us on ScanEntry | P1 |
| Language breakdown in stats | ❌ Missing | languages_found on ScanStats | P1 |
| blake3 alternative | ❌ Missing | Behind config flag | P2 |


---

## 20. Security Considerations

1. **Path traversal**: The `ignore` crate respects `.gitignore` boundaries and does not
   follow symlinks by default. With `follow_symlinks = false`, the scanner cannot escape
   the project root via symlinks.

2. **Resource exhaustion**: `max_file_size` (1MB default) prevents the scanner from
   reading extremely large files into memory. The `ignore` crate's `max_filesize` filter
   applies during discovery, before any file content is read.

3. **Denial of service**: Deeply nested directory structures could cause stack overflow
   in recursive walking. The `ignore` crate handles this internally with iterative
   traversal (not recursive).

4. **Content hash collision**: xxh3 is non-cryptographic. A malicious actor could craft
   two files with the same xxh3 hash but different content, causing the scanner to
   incorrectly classify a modified file as unchanged. For security-sensitive environments,
   use `hash_algorithm = "blake3"` which provides cryptographic collision resistance.

5. **Cache poisoning**: The `file_metadata` table in drift.db stores content hashes.
   If drift.db is tampered with, the scanner could skip modified files. Mitigated by:
   - drift.db has appropriate file permissions (created by the user's process)
   - `force_full_scan = true` bypasses the cache entirely
   - blake3 hashes provide tamper evidence for enterprise use

6. **Sensitive file paths**: File paths in `ScanDiff` and `file_metadata` may reveal
   directory structure. Ensure these are not inadvertently exposed through MCP tools
   or telemetry without appropriate filtering.


---

## 21. Build Order

The scanner is the second system built (after infrastructure). Each phase is
independently testable.

```
Phase 1 — Types & Errors:
  ├── Language enum (shared with parsers — defined in drift-core)
  ├── ScanConfig struct (with all fields from §10)
  ├── ScanError enum (thiserror, per §11)
  ├── ScanEntry, ScanDiff, ScanStats, ScanSummary structs (§6)
  ├── ContentHash enum (xxh3 + blake3 variants)
  └── HashAlgorithm enum

Phase 2 — Discovery (Phase 1 of scan pipeline):
  ├── walker.rs — ignore crate WalkParallel integration
  ├── Default ignores (18 patterns, §9)
  ├── .driftignore support via add_custom_ignore_filename
  ├── Language detection from file extension
  ├── Binary file detection (null-byte heuristic)
  └── DiscoveredFile collection

Phase 3 — Processing (Phase 2 of scan pipeline):
  ├── hasher.rs — xxh3 content hashing (+ blake3 behind flag)
  ├── diff.rs — Two-level incremental detection (mtime → hash)
  ├── File classification (added/modified/removed/unchanged)
  ├── rayon par_iter integration
  ├── Cancellation via AtomicBool
  └── Progress reporting via DriftEventHandler

Phase 4 — Storage Integration:
  ├── file_metadata table migration (SQL, §16)
  ├── Bulk upsert via batch writer
  ├── Removed file cleanup (cascade delete)
  └── Cache loading for incremental detection

Phase 5 — NAPI & Observability:
  ├── native_scan() + native_scan_with_progress() (§15)
  ├── cancel_scan() NAPI function
  ├── Query functions (changed_files, file_metadata, scan_history)
  ├── tracing instrumentation on all scan paths (§13)
  └── ScanSummary construction for NAPI return
```

### Phase Dependencies

```
Phase 1 ← Infrastructure (thiserror, config, Language enum)
Phase 2 ← Phase 1 (uses types)
Phase 3 ← Phase 1 + Phase 2 (processes discovered files)
Phase 4 ← Phase 3 + Storage system (writes to drift.db)
Phase 5 ← Phase 3 + NAPI bridge (exposes to TS)
```

### Estimated Effort

| Phase | Estimated Lines | Estimated Time |
|-------|----------------|----------------|
| Phase 1 | ~300 (types + errors) | 1 day |
| Phase 2 | ~400 (walker + ignores + language detection) | 1-2 days |
| Phase 3 | ~500 (hasher + diff + rayon + cancellation) | 2-3 days |
| Phase 4 | ~200 (migration + batch write + cleanup) | 1 day |
| Phase 5 | ~300 (NAPI functions + tracing) | 1-2 days |
| **Total** | **~1,700** | **6-9 days** |

### File Module Structure

```
crates/drift-core/src/scanner/
├── mod.rs          # Public API: scan(), discover_files()
├── walker.rs       # Phase 1: ignore crate WalkParallel discovery
├── hasher.rs       # Content hashing (xxh3 + blake3)
├── diff.rs         # ScanDiff computation + two-level incrementality
├── types.rs        # ScanConfig, ScanDiff, ScanEntry, ScanStats, ScanSummary
├── errors.rs       # ScanError enum (thiserror)
└── language.rs     # Language enum + extension mapping (shared with parsers)
```


---

## 22. Cross-System Impact Matrix

The scanner is the entry point to the entire pipeline. Its output (ScanDiff) drives
every downstream system's incremental behavior.

### ScanDiff Field → Consumer Mapping

| ScanDiff Field | Consumers | How They Use It |
|---------------|-----------|-----------------|
| `added` | Parsers, UAE, Call Graph, Detectors, DNA, Contracts, Coupling | New files to parse/analyze from scratch |
| `modified` | Parsers, UAE, Call Graph, Detectors, DNA, Contracts, Coupling | Changed files to re-parse/re-analyze |
| `removed` | Call Graph, Storage, Coupling | Remove edges/data for deleted files |
| `unchanged` | Parsers (cache hit), UAE (skip) | Skip re-analysis, use cached results |
| `errors` | Quality Gates, Observability | Scan health metrics |
| `stats` | Quality Gates, NAPI, Observability | Throughput and timing metrics |
| `entries` | UAE (ScanEntry metadata), Parsers (language) | Per-file metadata without re-reading filesystem |

### ScanEntry Field → Consumer Mapping

| ScanEntry Field | Consumers | Why They Need It |
|----------------|-----------|-----------------|
| `path` | Every consumer | File identity |
| `content_hash` | Storage (cache key), Parsers (cache key) | Change detection, cache invalidation |
| `language` | Parsers (grammar selection), UAE (language dispatch), Detectors | Language-specific processing |
| `file_size` | Quality Gates, Observability | File size metrics |
| `mtime_secs/nanos` | Storage (file_metadata) | Incremental detection cache |
| `scan_duration_us` | Observability | Per-file performance tracking |

### ScanStats Field → Consumer Mapping

| ScanStats Field | Consumers | Why They Need It |
|----------------|-----------|-----------------|
| `total_files` | Quality Gates, NAPI Summary | Project size metrics |
| `cache_hit_rate` | Observability, Quality Gates | Incrementality effectiveness |
| `languages_found` | NAPI Summary (CLI display), DNA | Language distribution |
| `discovery_ms` / `hashing_ms` | Observability | Performance bottleneck identification |

### Cascade Impact of Scanner Changes

Any change to ScanDiff/ScanEntry/ScanStats shape requires updates in:

1. **Parsers** — consume ScanDiff.added + modified for file list
2. **UAE** — consumes ScanEntry for per-file metadata
3. **Call Graph** — consumes ScanDiff for incremental edge updates
4. **Storage** — file_metadata table schema must match ScanEntry
5. **NAPI** — ScanSummary must reflect ScanStats changes
6. **Batch API** — scanner is Phase 1, output feeds all subsequent phases
7. **Test fixtures** — all integration tests that create ScanDiff

The reconciled types in §6 are designed to be complete enough that no further
field additions should be needed for v2 launch.


---

## 23. Decision Registry

All architectural decisions for the scanner subsystem. Decisions marked with ⚡ were
changed or added during reconciliation with downstream V2-PREP documents.

| # | Decision | Choice | Confidence | Source | Notes |
|---|----------|--------|------------|--------|-------|
| D1 | File walker | `ignore` crate v0.4 (from ripgrep) | Very High | 00-SCANNER.md research | Unchanged |
| D2 | Content hash (primary) | xxh3 via `xxhash-rust` v0.8 | High | 00-SCANNER.md benchmarks | Unchanged |
| D3 | Content hash (enterprise) | blake3 behind config flag | Medium | 00-SCANNER.md | Unchanged |
| D4 | Parallelism | `ignore` for discovery, rayon for processing | High | 00-SCANNER.md | Unchanged |
| D5 | Incrementality | Two-level: mtime then content hash | Very High | 00-SCANNER.md, git/rust-analyzer pattern | Unchanged |
| D6 | Max file size | 1MB default, configurable | High | Hierarchy | Unchanged |
| D7 | Ignore format | gitignore syntax via `ignore` crate | Very High | 00-SCANNER.md | Unchanged |
| D8 | Default ignores | 18 patterns (node_modules, .git, dist, etc.) | High | Hierarchy | Unchanged |
| D9 | Symlink handling | Never follow (matches git) | High | Resolved from open item | ⚡ Resolved |
| D10 | Binary detection | Skip by default (null-byte heuristic) | High | Resolved from open item | ⚡ Resolved |
| D11 | Content hash storage | BLOB (8 bytes xxh3, 32 bytes blake3) | High | Resolved from open item | ⚡ Resolved |
| D12 | Language detection | Scanner detects from extension, stores on ScanEntry | High | Hierarchy, downstream contracts | ⚡ Promoted from afterthought |
| D13 | hash_algorithm config | `"xxh3"` \| `"blake3"` in ScanConfig | High | Hierarchy | ⚡ Added from hierarchy |
| D14 | file_metadata schema | Expanded (language, counters, error) from 02-STORAGE | High | 02-STORAGE-V2-PREP §11 | ⚡ Reconciled |
| D15 | ScanStats.languages_found | First-class field (FxHashMap<Language, usize>) | High | Hierarchy | ⚡ Promoted from afterthought |
| D16 | Error handling | Non-fatal at file level, collect in ScanDiff.errors | Very High | AD6, 04-INFRASTRUCTURE | Unchanged |
| D17 | Cancellation | Global AtomicBool, checked between files | High | A6/A21, 03-NAPI §8 | Unchanged |
| D18 | Progress reporting | Every 100 files via DriftEventHandler | High | Audit, 03-NAPI §7 | Unchanged |
| D19 | NAPI pattern | Compute + store in Rust, return lightweight summary | Very High | 03-NAPI §5 | Unchanged |
| D20 | Watch mode | Separate system (not part of scanner) | High | Resolved from open item | ⚡ Resolved |
| D21 | Dependency graph | NOT scanner's job (Call Graph Builder owns this) | Very High | Resolved from open item | ⚡ Resolved |
| D22 | ScanDiff.entries map | Include FxHashMap<PathBuf, ScanEntry> for O(1) lookup | High | UAE contract | ⚡ New |
| D23 | Three-layer incrementality | Scanner owns L1, provides ratio for L2/L3 | High | AD1 | Unchanged |

### Decisions Deferred

| Decision | Status | Revisit When |
|----------|--------|-------------|
| Watch mode (`notify` crate) | Deferred | Post-launch, separate system |
| HDD I/O concurrency limit | Deferred | If HDD users report issues |
| Per-operation CancellationToken | Deferred | When concurrent operations needed |
| FAT32 mtime workaround | Deferred | If FAT32 users report issues |

---

*End of document. 23 sections. Reconciled against 12+ source documents.*
*This is the DEFINITIVE scanner specification for Drift v2.*
