# Scanner — Research & Decision Guide

> System: Parallel file walking, content hashing, ignore patterns
> Hierarchy: Level 0 — Bedrock
> Dependencies: Configuration system
> Consumers: Parsers, incremental detection, every analysis pipeline

---

## What This System Does

The scanner is the entry point to the entire Drift pipeline. It walks the filesystem, discovers source files, computes content hashes for incremental detection, and respects ignore patterns. Every analysis path starts with "which files exist and which changed?"

---

## Key Library Decision: `ignore` crate vs `walkdir` + manual gitignore

### Option A: `ignore` crate (from ripgrep) — RECOMMENDED

The `ignore` crate is the parallel file walker extracted from ripgrep. It's maintained by BurntSushi (Andrew Gallick), the same author as `walkdir`, `regex`, and ripgrep itself.

Why this is the right choice:
- Built-in parallel walking via `WalkParallel` — uses a work-stealing thread pool internally
- Native `.gitignore` support (nested, hierarchical, all edge cases handled)
- Native `.ignore` file support (same syntax as gitignore — perfect for `.driftignore`)
- Respects `.git/info/exclude` and global gitignore
- File type filtering built in
- Battle-tested in ripgrep, fd, delta, difftastic, and hundreds of other tools
- The `fd` tool's speed is primarily attributed to the `ignore` crate's parallel walker ([source: HN discussion](https://news.ycombinator.com/item?id=15429648))

Key API: `WalkParallel` with `WalkState` for early termination:
```rust
use ignore::WalkBuilder;

let walker = WalkBuilder::new(root)
    .hidden(false)           // don't skip hidden files by default
    .git_ignore(true)        // respect .gitignore
    .git_global(true)        // respect global gitignore
    .git_exclude(true)       // respect .git/info/exclude
    .add_custom_ignore_filename(".driftignore")  // custom ignore file
    .max_filesize(Some(1_048_576))  // 1MB max file size
    .threads(num_cpus::get())
    .build_parallel();

walker.run(|| {
    Box::new(|entry| {
        match entry {
            Ok(entry) => {
                // process file
                ignore::WalkState::Continue
            }
            Err(err) => ignore::WalkState::Continue, // skip errors
        }
    })
});
```

### Option B: `walkdir` + rayon + manual gitignore

`walkdir` is a sequential directory walker. You'd need to:
1. Walk with `walkdir`
2. Collect entries into a Vec
3. Use `rayon::par_iter()` for parallel processing
4. Manually implement gitignore parsing (or use the `gitignore` crate separately)

This is strictly worse than Option A for this use case. The `ignore` crate was literally extracted from ripgrep to solve this exact problem.

### Option C: `jwalk` / `jwalk-meta`

`jwalk` provides parallel walking with sorted results. Claims ~4x walkdir speed for sorted results with metadata. However:
- No built-in gitignore support
- Less battle-tested than `ignore`
- You'd still need to layer gitignore handling on top

### Decision: Use `ignore` crate

The `ignore` crate is the clear winner. It's what ripgrep and fd use, it handles all the gitignore edge cases, and it provides parallel walking out of the box. Don't reinvent this.

---

## Key Decision: Content Hashing Algorithm

Your audit specifies xxh3 via `xxhash-rust`. Let's validate this.

### Benchmark Data (from Criterion benchmarks on Wikipedia articles)

| Algorithm | Long article time | Type | Notes |
|-----------|------------------|------|-------|
| meowHash | 333 µs | Non-crypto | x86 only, not portable |
| ahash | 340 µs | Non-crypto | Default in hashbrown/HashMap |
| gxHash | 342 µs | Non-crypto | Requires hardware AES |
| fasthash | 353 µs | Non-crypto | |
| rustc_hash (FxHash) | 468 µs | Non-crypto | Used in rustc |
| xxhash-rust (xxh3) | 580 µs | Non-crypto | Portable, well-known |
| twox-hash (xxh3) | 661 µs | Non-crypto | Older xxh3 impl |
| blake3 | 4,472 µs | Cryptographic | Parallelizable |
| SipHash (std) | 2,175 µs | Non-crypto | Rust default |
| FNV | 8,937 µs | Non-crypto | Simple but slow |

[Source: rosetta-hashing benchmarks](https://blog.goose.love/posts/rosetta-hashing/)

### Analysis

For content hashing (file change detection), you need:
- Speed (hashing thousands of files)
- Collision resistance (don't want false "unchanged" signals)
- Portability (all 7 NAPI platform targets)
- Determinism (same content → same hash, always)

You do NOT need:
- Cryptographic security (this isn't signing or authentication)

### Options

1. **xxhash-rust (xxh3)** — Your current choice. Good speed (~580µs for large inputs), excellent collision resistance for non-crypto, portable, well-known. The xxh3 algorithm is specifically designed for large inputs and has excellent distribution properties.

2. **blake3** — ~8x slower than xxh3 but still fast in absolute terms. Cryptographic quality. Parallelizable internally (uses SIMD + tree hashing). The `blake3` crate is maintained by the algorithm authors. If you ever need to verify file integrity against tampering (enterprise feature?), blake3 gives you that for free.

3. **ahash** — Fastest non-crypto option that's portable. But it's designed as a HashMap hasher, not a content hasher. Its output isn't stable across versions or platforms (by design — it uses random state for DoS resistance). Not suitable for persistent content hashing.

### Decision: xxh3 is correct, but consider blake3

xxh3 is the right default. It's fast enough (hashing a 1MB file takes ~5ms), portable, deterministic, and has excellent collision properties.

However, blake3 deserves consideration because:
- It's only ~8x slower, which for file hashing is still sub-millisecond for typical source files
- It gives you cryptographic-quality hashes for free
- If you ever need to verify file integrity (lock files, audit trails, supply chain), you already have it
- The `blake3` crate uses SIMD automatically and is extremely well-optimized

The performance difference only matters at scale: for 100K files, xxh3 saves ~400ms total over blake3. That's meaningful but not critical.

**Recommendation**: Start with xxh3 for speed. Add blake3 as an option behind a config flag if you need cryptographic hashes for enterprise features (audit trails, lock file verification).

Crate: `xxhash-rust` with the `xxh3` feature flag.

---

## Key Decision: Parallelism Strategy

### The Pipeline

```
File Discovery (ignore crate, parallel)
  → Content Hashing (per-file, embarrassingly parallel)
    → File Metadata Collection (size, mtime, extension)
      → Change Detection (compare against drift.db file_metadata table)
        → Output: Vec<ScanEntry> of files needing (re)analysis
```

### How to parallelize

The `ignore` crate's `WalkParallel` already handles parallel directory traversal. The question is how to handle the per-file work (hashing, metadata).

**Option A: Do everything in the WalkParallel callback**

```rust
walker.run(|| {
    Box::new(|entry| {
        let entry = entry.unwrap();
        let hash = xxh3_hash_file(&entry.path());
        let metadata = entry.metadata().unwrap();
        // send to channel
        tx.send(ScanEntry { path, hash, metadata });
        WalkState::Continue
    })
});
```

This is the simplest approach. The `ignore` crate's thread pool handles parallelism. Each worker thread does discovery + hashing + metadata in one pass.

**Option B: Two-phase (discover then process)**

```rust
// Phase 1: Discover files (fast)
let files: Vec<PathBuf> = discover_files(root);

// Phase 2: Process in parallel with rayon
let entries: Vec<ScanEntry> = files.par_iter()
    .map(|path| {
        let hash = xxh3_hash_file(path);
        let metadata = fs::metadata(path).unwrap();
        ScanEntry { path, hash, metadata }
    })
    .collect();
```

This gives you more control over the parallelism and lets you use rayon's work-stealing for the CPU-bound hashing work.

**Recommendation**: Option A for simplicity. The `ignore` crate's parallel walker already distributes work across threads. Adding a separate rayon phase adds complexity without meaningful benefit — the bottleneck is I/O (reading files for hashing), not CPU.

However, if you need progress reporting (which you do — the audit mentions `AtomicU64` counter + ThreadsafeFunction every 100 files), Option B is cleaner because you know the total file count upfront.

**Practical recommendation**: Use `ignore::WalkParallel` for discovery, collect paths into a Vec, then use rayon for the hashing/metadata phase. This gives you: total count for progress, rayon's work-stealing for CPU work, and clean separation of concerns.

---

## Key Decision: Incremental Detection Strategy

### Two-Level Change Detection (from audit A8)

1. **Level 1: mtime comparison** — Instant. If mtime hasn't changed, skip. Catches 90%+ of unchanged files.
2. **Level 2: content hash** — For files where mtime changed but content might not have (git operations, touch, etc.). Compare xxh3 hash against stored hash in `file_metadata` table.

### Storage Schema

```sql
CREATE TABLE file_metadata (
    path TEXT PRIMARY KEY,
    content_hash BLOB NOT NULL,    -- xxh3 hash (8 bytes)
    mtime_secs INTEGER NOT NULL,
    mtime_nanos INTEGER NOT NULL,
    file_size INTEGER NOT NULL,
    last_indexed_at INTEGER NOT NULL
) STRICT;
```

### The diff() Algorithm

```rust
pub struct ScanDiff {
    pub added: Vec<PathBuf>,      // new files not in cache
    pub modified: Vec<PathBuf>,   // content hash changed
    pub removed: Vec<PathBuf>,    // in cache but not on disk
    pub unchanged: Vec<PathBuf>,  // same content hash
}
```

1. Walk filesystem → collect current files with mtime
2. Load `file_metadata` from drift.db
3. For each current file:
   - Not in cache → `added`
   - In cache, mtime unchanged → `unchanged` (skip hash)
   - In cache, mtime changed → compute hash → if hash differs: `modified`, else: `unchanged` (update mtime in cache)
4. For each cached file not in current set → `removed`

This is the same strategy used by git's index and rust-analyzer's VFS.

---

## Key Decision: Max File Size

The audit says 1MB. This is reasonable for source code analysis. Files larger than 1MB are almost certainly:
- Generated code (bundle outputs, minified files)
- Binary files misidentified
- Data files (JSON fixtures, SQL dumps)

None of these are useful for convention detection. 1MB is the right default. Make it configurable.

---

## Key Decision: .driftignore Format

Use gitignore syntax exactly. The `ignore` crate supports custom ignore filenames via `add_custom_ignore_filename()`. Users already know gitignore syntax. Don't invent a new format.

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
```

---

## Performance Targets

From the audit:
- 10K files: <3s total pipeline (scanner is ~10% of this = <300ms)
- 100K files: <15s total pipeline (scanner = <1.5s)
- Incremental (1 file changed): <100ms

These are achievable with the `ignore` crate + xxh3. The `ignore` crate can walk 100K+ files in under 500ms on SSD. xxh3 can hash typical source files (10-50KB) in microseconds.

**macOS caveat**: APFS directory scanning is single-threaded at the kernel level. Parallel walking helps with the per-file work (hashing, metadata) but not with the directory enumeration itself. This is a known limitation — ripgrep has the same constraint on macOS.

---

## Event Emissions (per D5)

The scanner should emit events via `DriftEventHandler`:

```rust
pub trait DriftEventHandler: Send + Sync {
    fn on_scan_started(&self, root: &Path, file_count: Option<usize>) {}
    fn on_scan_progress(&self, processed: usize, total: usize) {}
    fn on_scan_complete(&self, results: &ScanDiff) {}
    fn on_scan_error(&self, error: &ScanError) {}
}
```

---

## Summary of Decisions

| Decision | Choice | Confidence |
|----------|--------|------------|
| File walker | `ignore` crate (from ripgrep) | Very High |
| Content hash | xxh3 via `xxhash-rust` | High |
| Parallelism | `ignore` for discovery, rayon for processing | High |
| Incremental | Two-level: mtime then content hash | Very High |
| Max file size | 1MB default, configurable | High |
| Ignore format | gitignore syntax via `ignore` crate | Very High |
| Hash alternative | blake3 behind config flag for enterprise | Medium |
