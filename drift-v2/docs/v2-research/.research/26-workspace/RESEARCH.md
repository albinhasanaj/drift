# 26 Workspace — V2 Research Encyclopedia

> Comprehensive external research from authoritative sources for building Drift v2's enterprise-grade workspace management subsystem. Every finding is sourced, tiered, and assessed for direct applicability to Drift's project lifecycle, backup/restore, schema migration, context caching, and multi-project management.

**Source Tiers**:
- Tier 1: Official documentation, specifications, authoritative standards, production-proven source code
- Tier 2: Industry experts, established engineering blogs, production-validated tools (10K+ stars)
- Tier 3: Community-validated guides, tutorials, benchmarks

**Total Sources Consulted**: 30+
**Tier 1 Sources**: 15+
**Tier 2 Sources**: 10+
**Tier 3 Sources**: 5+

---

## Table of Contents

1. [SQLite Schema Migration Architecture](#1-sqlite-schema-migration-architecture)
2. [SQLite Backup & Restore Patterns](#2-sqlite-backup--restore-patterns)
3. [Project Discovery & Workspace Detection](#3-project-discovery--workspace-detection)
4. [Monorepo & Multi-Project Workspace Management](#4-monorepo--multi-project-workspace-management)
5. [Context Caching & Cache Invalidation](#5-context-caching--cache-invalidation)
6. [Cross-Platform File Locking & Concurrent Access](#6-cross-platform-file-locking--concurrent-access)
7. [Workspace Integrity & Garbage Collection](#7-workspace-integrity--garbage-collection)
8. [Enterprise Backup Retention & Lifecycle](#8-enterprise-backup-retention--lifecycle)
9. [CI/CD Workspace Patterns](#9-cicd-workspace-patterns)
10. [Workspace Configuration Validation](#10-workspace-configuration-validation)

---

## 1. SQLite Schema Migration Architecture

### 1.1 Cargo's Migration Pattern (user_version pragma)

**Source**: Cargo SQLite migration source — https://doc.rust-lang.org/stable/nightly-rustc/src/cargo/util/sqlite.rs.html
**Type**: Tier 1 (Official Rust toolchain source code)
**Accessed**: 2026-02-06

**Key Findings**:
- Cargo uses `PRAGMA user_version` to track which migrations have been applied. The migrate function is called immediately after opening a connection. (Content rephrased for compliance with licensing restrictions.)
- Migrations are defined as a list of functions. The index in the list corresponds to the version number. The current `user_version` tells Cargo which migrations have already run.
- Critical rules enforced by Cargo: never remove a migration entry from the list (tracked by index), never perform backwards-incompatible changes (no DROP TABLE, no DROP COLUMN).
- Each migration receives a `&Connection` and can execute arbitrary SQL. Migrations run within a transaction for atomicity.

**Applicability to Drift**:
Drift v2 should adopt Cargo's exact pattern: `PRAGMA user_version` for version tracking, migrations as an ordered list of SQL strings (never removed, never reordered), each migration wrapped in a transaction. This is the simplest, most battle-tested approach — used by the Rust toolchain itself, which ships to millions of developers.

**Confidence**: Very High — Cargo is the official Rust build tool, used by every Rust project.

---

### 1.2 rusqlite_migration Crate

**Source**: rusqlite_migration documentation — https://cj.rs/rusqlite_migration
**Type**: Tier 2 (Production-validated Rust crate)
**Accessed**: 2026-02-06

**Additional Source**: rusqlite_migration GitHub — https://github.com/cljoly/rusqlite_migration
**Type**: Tier 2 (Open source, actively maintained)
**Accessed**: 2026-02-06

**Key Findings**:
- rusqlite_migration provides a simple, focused migration library for rusqlite. Migrations are defined as a const slice of SQL strings using `M::up()` and optionally `M::down()` for rollback.
- Uses `PRAGMA user_version` internally for tracking. Supports both forward migration (`to_latest()`) and rollback (`to_version()`).
- Migrations can be defined inline or loaded from files using `include_str!()`. The `include_str!` approach keeps SQL in separate `.sql` files for maintainability.
- Provides a `validate()` method that checks migration consistency without applying — useful for CI testing.
- Supports hooks that run before/after each migration for custom logic (e.g., data transformation).
- Works with rusqlite's bundled SQLite feature, ensuring consistent SQLite version across platforms.

**Applicability to Drift**:
This is the recommended crate for Drift v2's schema migration. It wraps Cargo's pattern in a clean API, adds rollback support (critical for Drift's backup-before-migrate workflow), and provides CI validation. The `validate()` method should be called in Drift's test suite to catch migration ordering issues early.

**Confidence**: High — well-maintained, focused crate that complements rusqlite perfectly.

---

### 1.3 Mozilla Application Services Migration Pattern

**Source**: Mozilla Application Services — webext_storage schema.rs — https://mozilla.github.io/application-services/book/rust-docs/src/webext_storage/schema.rs.html
**Type**: Tier 1 (Mozilla production code, ships in Firefox)
**Accessed**: 2026-02-06

**Additional Source**: Mozilla Application Services — push schema.rs — https://mozilla.github.io/application-services/book/rust-docs/src/push/internal/storage/schema.rs.html
**Type**: Tier 1 (Mozilla production code)
**Accessed**: 2026-02-06

**Key Findings**:
- Mozilla uses a `ConnectionInitializer` trait with `NAME`, `END_VERSION`, `prepare()`, `init()`, and `upgrade()` methods. The pattern separates initial schema creation from incremental upgrades.
- PRAGMAs are set in `prepare()`: `journal_mode=WAL`, `foreign_keys=ON`, `temp_store=2`. This ensures consistent database configuration regardless of migration state.
- Schema SQL is stored in separate `.sql` files loaded via `include_str!()`, keeping Rust code clean.
- The `END_VERSION` constant defines the target version. The migration system compares current `user_version` against `END_VERSION` and runs upgrade steps sequentially.
- Each component (webext_storage, push, places, nimbus) has its own schema.rs with independent versioning — supporting multiple databases with independent migration paths.

**Applicability to Drift**:
Drift v2 has two databases (drift.db, cortex.db) that need independent migration paths. Mozilla's pattern of per-component `ConnectionInitializer` with independent `END_VERSION` is exactly the right model. Each database gets its own migration chain, its own version tracking, and its own PRAGMA configuration.

**Confidence**: Very High — Mozilla ships this to hundreds of millions of Firefox users.

---

### 1.4 Database Migration Best Practices (Enterprise)

**Source**: Bytebase Migration Guidelines — https://docs.bytebase.com/gitops/best-practices/migration-guidelines
**Type**: Tier 2 (Enterprise database management tool)
**Accessed**: 2026-02-06

**Additional Source**: "How to Design Database Migrations That Never Need Rollback" — https://www.c-sharpcorner.com/article/how-to-design-database-migrations-that-never-need-rollback/
**Type**: Tier 3 (Community guide)
**Accessed**: 2026-02-06

**Key Findings**:
- The "expand and contract" pattern enables zero-downtime migrations: add new columns/tables first (expand), migrate data, update code to use new schema, then remove old columns/tables (contract). This eliminates the need for rollback in most cases.
- Backward compatibility is the foundation of rollback-free migrations. Every migration should be compatible with both the old and new code versions simultaneously.
- For SQLite specifically: avoid `ALTER TABLE ... DROP COLUMN` (only supported since SQLite 3.35.0, 2021). Instead, create a new table, copy data, drop old table, rename new table. Wrap in a transaction.
- Migration naming conventions: use sequential numbering (001, 002, 003) or timestamps. Never reorder. Never delete.
- Always test migrations against a copy of the production database before applying. For SQLite, this means: backup → apply to backup → verify → apply to production.

**Applicability to Drift**:
Drift should adopt the "expand and contract" pattern for all schema changes. Since Drift controls both the schema and the code, backward compatibility is achievable. The test-against-copy pattern maps directly to Drift's backup-before-migrate workflow: backup drift.db → apply migrations to backup → run integrity check → if pass, apply to production.

**Confidence**: High — enterprise-validated patterns from database management experts.

---

### 1.5 SQLite user_version Pragma for Migration Tracking

**Source**: "Keep track of migration state in SQLite" — https://www.jotaen.net/c54IG/migration-state-sqlite-user-version/
**Type**: Tier 3 (Community guide, well-explained)
**Accessed**: 2026-02-06

**Key Findings**:
- The `user_version` PRAGMA stores a single integer in the SQLite file header. It's atomic (set within a transaction), requires no separate table, and survives WAL checkpoints.
- The prerequisite for robust usage is an authoritative, immutable, ordered list of migration procedures. The `user_version` represents the ordinal number of the last applied migration.
- Advantages over a migration table: zero overhead (no extra table, no extra queries), atomic (part of the same transaction as the migration), and survives database corruption better (stored in the file header, not in a table).
- The pattern is: read `user_version` → compare against migration list length → apply missing migrations → set `user_version` to new value → all within a single transaction.

**Applicability to Drift**:
This confirms the approach recommended by Cargo and Mozilla. Drift v2 should use `user_version` exclusively for migration tracking, eliminating the v1 pattern of storing version in `config.json`. The atomic nature of `user_version` (set within the same transaction as the migration) prevents the v1 risk of version/schema mismatch if a migration partially fails.

**Confidence**: High — well-established SQLite pattern used by Cargo, Mozilla, and many other production systems.

---

## 2. SQLite Backup & Restore Patterns

### 2.1 SQLite Online Backup API

**Source**: SQLite Backup API — https://sqlite.org/backup.html
**Type**: Tier 1 (Official SQLite documentation)
**Accessed**: 2026-02-06

**Additional Source**: SQLite Online Backup API Reference — https://sqlite.org/c3ref/backup_finish.html
**Type**: Tier 1 (Official SQLite C API reference)
**Accessed**: 2026-02-06

**Key Findings**:
- The Online Backup API copies database contents page-by-page from source to destination. The copy can be done incrementally — the source database doesn't need to be locked for the entire duration, only during brief read periods.
- The result is a bit-wise identical copy (a "snapshot") of the source database as it was when copying commenced.
- Three-function API: `sqlite3_backup_init()` initializes the backup, `sqlite3_backup_step()` transfers pages (can be called multiple times with a page count), `sqlite3_backup_finish()` releases resources.
- The backup can be paused between `step()` calls, allowing other database operations to proceed. This is critical for not blocking readers/writers during backup.
- `VACUUM INTO 'backup.db'` (SQLite 3.27+) is a simpler alternative that creates a compacted copy. It works with WAL-mode databases and produces a single file (no WAL/SHM files). However, it requires a read lock for the entire duration and doesn't support incremental progress.

**Applicability to Drift**:
Drift v2 MUST use the Online Backup API (via rusqlite's `backup::Backup`) for all backup operations. The v1 approach of file copying is unsafe for WAL-mode databases — WAL pages may not be included, resulting in a corrupted backup. For Drift's typical database sizes (< 100MB), `VACUUM INTO` is also viable and simpler, but the Backup API is more flexible (supports progress reporting, cancellation, and non-blocking operation).

**Confidence**: Very High — this is the official SQLite backup mechanism, documented by the SQLite authors.

---

### 2.2 Safe SQLite Backup Practices

**Source**: "The Right Way to Backup SQLite: Prevent Data Corruption" — https://openillumi.com/en/en-sqlite-safe-backup-method/
**Type**: Tier 2 (Technical guide with production focus)
**Accessed**: 2026-02-06

**Additional Source**: "How to properly backup your SQLite databases" — https://www.adyxax.org/blog/2021/11/09/how-to-properly-backup-your-sqlite-databases/
**Type**: Tier 3 (Community guide)
**Accessed**: 2026-02-06

**Key Findings**:
- Direct file copy of a SQLite database in WAL mode risks creating an inconsistent backup. The WAL file (`.db-wal`) and shared memory file (`.db-shm`) must be consistent with the main database file. A file copy may capture them at different points in time.
- The SQLite Backup API is the professional solution for ensuring data integrity and transactional safety during backup.
- `VACUUM INTO` is a practical alternative that produces a single, compacted backup file. It works with WAL-mode databases and doesn't require copying WAL/SHM files. The backup is automatically in DELETE journal mode (single file).
- Post-backup verification: run `PRAGMA integrity_check` on the backup file to verify it's not corrupted. This should be automated as part of every backup operation.
- Backup compression: SQLite databases with text-heavy content (like Drift's pattern descriptions, code snippets) compress well with gzip (60-80% reduction). However, compressing the SQLite file directly prevents random access — only useful for archival backups, not for quick restore.

**Applicability to Drift**:
Drift v2 should implement a two-tier backup strategy: (1) Hot backup via SQLite Backup API for operational backups (fast, non-blocking, used before migrations and destructive ops), (2) `VACUUM INTO` + optional gzip for archival backups (compact, single file, used for export/transfer). Both tiers should include `PRAGMA integrity_check` verification.

**Confidence**: High — consistent advice across multiple sources, aligned with SQLite official documentation.

---

### 2.3 rusqlite Backup API

**Source**: rusqlite documentation — backup module — https://github.com/rusqlite/rusqlite
**Type**: Tier 2 (Production-validated Rust crate, 40M+ downloads)
**Accessed**: 2026-02-06

**Key Findings**:
- rusqlite wraps the SQLite Backup API in `rusqlite::backup::Backup`. The API mirrors the C API: `Backup::new(&source, &mut dest)` initializes, `backup.run_to_completion(pages_per_step, sleep_duration, progress_callback)` transfers.
- `run_to_completion` accepts a page count per step and a sleep duration between steps. For Drift's typical database sizes, 1000 pages per step with 10ms sleep is a good default — completes in under a second for databases up to 100MB while allowing concurrent reads.
- The progress callback receives `(remaining_pages, total_pages)`, enabling progress reporting for large databases.
- After backup, verify integrity: `dest.pragma_query(None, "integrity_check", ...)` should return "ok".

**Applicability to Drift**:
Direct mapping to Drift v2's BackupManager in Rust. The progress callback enables CLI progress bars for large database backups. The page-per-step approach ensures backup doesn't block MCP tool responses.

**Confidence**: High — rusqlite is the standard Rust SQLite binding with 40M+ downloads.

---

## 3. Project Discovery & Workspace Detection

### 3.1 rust-analyzer's Project Model Architecture

**Source**: rust-analyzer project_model documentation — https://rust-lang.github.io/rust-analyzer/project_model/index.html
**Type**: Tier 1 (Official rust-analyzer documentation)
**Accessed**: 2026-02-06

**Additional Source**: rust-analyzer architecture guide — https://rust-analyzer.github.io/book/contributing/architecture.html
**Type**: Tier 1 (Official documentation)
**Accessed**: 2026-02-06

**Additional Source**: rust-analyzer cargo_workspace.rs — https://rust-lang.github.io/rust-analyzer/src/project_model/cargo_workspace.rs.html
**Type**: Tier 1 (Source code)
**Accessed**: 2026-02-06

**Key Findings**:
- rust-analyzer maintains a strict separation between the abstract semantic project model (`CrateGraph`) and the concrete build system model (`CargoWorkspace`, `ProjectJson`). This separation allows supporting multiple build systems (Cargo, Buck, custom) with the same analysis engine.
- Project discovery works by searching upward from the current file for `Cargo.toml` or `rust-project.json`. Multiple project roots can be discovered in a multi-root workspace.
- `CargoWorkspace` mirrors `cargo metadata` output — it knows about packages, targets, and dependencies. `CrateGraph` is lower-level — it only knows about crates and their dependencies.
- The "lowering" step converts `CargoWorkspace` → `CrateGraph`, abstracting away Cargo-specific concepts. This is the key architectural insight: the analysis engine never sees Cargo concepts, only abstract crates.

**Applicability to Drift**:
Drift v2 should adopt rust-analyzer's two-level project model: (1) A concrete `ProjectDiscovery` layer that understands ecosystem-specific project files (package.json, Cargo.toml, pom.xml, etc.), and (2) An abstract `DriftProject` model that the analysis engine consumes. This separation enables supporting new ecosystems without changing the analysis engine. The upward-search discovery pattern is exactly what Drift v1's ProjectSwitcher does with `.drift/` directories.

**Confidence**: Very High — rust-analyzer is the gold standard for Rust IDE tooling, used by millions of developers.

---

### 3.2 Nx Project Graph & Auto-Detection

**Source**: Nx project configuration — https://github.com/nrwl/nx/blob/master/docs/shared/reference/project-configuration.md
**Type**: Tier 2 (Production-validated monorepo tool, 24K+ stars)
**Accessed**: 2026-02-06

**Additional Source**: Nx workspace concepts — https://nx.dev/blog/new-nx-experience-for-typescript-monorepos
**Type**: Tier 2 (Official Nx blog)
**Accessed**: 2026-02-06

**Key Findings**:
- Nx constructs a project graph by auto-detecting projects from workspace configuration. Projects can be defined explicitly in `project.json` files or inferred from package manager workspace configurations (pnpm-workspace.yaml, package.json workspaces).
- The project graph is the foundation for affected analysis (which projects changed?), task orchestration (build order), and caching (which outputs can be reused?).
- Nx distinguishes between `projectRoot` (the root of an individual package) and `workspaceRoot` (the top-level monorepo directory). This distinction is critical for correct path resolution.
- Project detection is plugin-based: different plugins detect different project types (React, Angular, Node, etc.). This extensible architecture allows adding new project types without modifying core logic.

**Applicability to Drift**:
Drift v2's workspace system should adopt Nx's project graph concept: auto-detect packages within a monorepo, build a dependency graph between them, and use the graph for affected analysis (which packages need re-scanning after a change?). The `projectRoot` vs `workspaceRoot` distinction maps directly to Drift's need to support both single-project and monorepo workspaces.

**Confidence**: High — Nx is the most popular monorepo tool with extensive production validation.

---

### 3.3 Turborepo Workspace Detection

**Source**: Turborepo — Add to existing repository — https://turbo.build/repo/docs/getting-started/add-to-existing-repository
**Type**: Tier 2 (Production-validated build tool by Vercel)
**Accessed**: 2026-02-06

**Key Findings**:
- Turborepo is built on top of package manager workspaces (npm, yarn, pnpm). It auto-detects the workspace configuration from the package manager's native format.
- Workspace detection order: check for `pnpm-workspace.yaml`, then `package.json` with `workspaces` field, then `lerna.json`. This cascading detection supports multiple ecosystem conventions.
- Each workspace package is treated as an independent unit with its own build/test/lint configuration. The workspace root provides shared configuration and dependency management.

**Applicability to Drift**:
Drift v2 should detect monorepo workspaces using the same cascading approach: check for ecosystem-specific workspace files (pnpm-workspace.yaml, package.json workspaces, Cargo.toml workspace members, go.work, etc.) and auto-discover packages. Each discovered package becomes a "project" within the Drift workspace.

**Confidence**: High — Turborepo is widely used, backed by Vercel.

---

## 4. Monorepo & Multi-Project Workspace Management

### 4.1 Large Rust Workspaces (matklad)

**Source**: "Large Rust Workspaces" — https://matklad.github.io/2021/08/22/large-rust-workspaces.html
**Type**: Tier 2 (matklad, creator of rust-analyzer)
**Accessed**: 2026-02-06

**Key Findings**:
- For workspaces approaching one million lines of code, a flat layout with all crates one level deep under a `crates/` directory works best. rust-analyzer (200K lines) uses this layout.
- A virtual manifest at the workspace root (no `[package]` section, only `[workspace]`) is the recommended pattern. All packages are listed as workspace members.
- Shared dependencies are specified in `[workspace.dependencies]` and inherited by member crates via `workspace = true`. This prevents version drift across packages.
- The flat layout enables fast filesystem operations (no deep nesting), simple glob patterns for CI, and easy navigation.

**Applicability to Drift**:
Drift v2's own crate structure should follow this flat layout pattern. More importantly, when Drift analyzes a user's monorepo, it should detect this flat layout pattern and treat each member as a separate analysis unit with shared workspace-level configuration.

**Confidence**: Very High — matklad is the creator of rust-analyzer and an authority on Rust workspace design.

---

### 4.2 SonarQube Monorepo Management

**Source**: SonarQube — Managing monorepo projects — https://docs.sonarsource.com/sonarqube-server/10.8/project-administration/monorepos
**Type**: Tier 1 (Official SonarQube documentation)
**Accessed**: 2026-02-06

**Key Findings**:
- SonarQube treats each module in a monorepo as a separate SonarQube project. Each build procedure is configured to analyze its particular project and send results to the corresponding SonarQube project.
- This per-project approach enables: independent quality gates per module, independent new code periods, independent issue assignment, and parallel analysis.
- The alternative (single SonarQube project for entire monorepo) is discouraged because it conflates issues across modules, makes quality gates meaningless (one failing module blocks all), and prevents per-team ownership.
- SonarQube supports multi-root workspace binding in VS Code, where each workspace folder maps to a different SonarQube project.

**Applicability to Drift**:
Drift v2 should follow SonarQube's per-module approach for monorepos: each package gets its own analysis results, its own pattern set, its own quality gate evaluation, and its own health score. A workspace-level view aggregates across packages. This enables per-team ownership of conventions — the frontend team's patterns don't interfere with the backend team's patterns.

**Confidence**: Very High — SonarQube is the industry standard for code quality, used by 400K+ organizations.

---

## 5. Context Caching & Cache Invalidation

### 5.1 Cache Invalidation Strategies: Time-Based vs Event-Driven

**Source**: "Cache Invalidation Strategies: Time-Based vs Event-Driven" — https://www.leapcell.io/blog/cache-invalidation-strategies-time-based-vs-event-driven
**Type**: Tier 2 (Technical engineering blog)
**Accessed**: 2026-02-06

**Additional Source**: "Cache Invalidation and Reactive Systems" — https://skiplabs.io/blog/cache_invalidation
**Type**: Tier 2 (Technical engineering blog)
**Accessed**: 2026-02-06

**Key Findings**:
- Time-based (TTL) invalidation is simple but introduces a staleness window. Data can be stale for up to the TTL duration after the source changes. This is acceptable for data that changes infrequently or where slight staleness is tolerable.
- Event-driven invalidation provides near-real-time consistency. When the source data changes, an event is emitted that triggers cache invalidation. This eliminates the staleness window but requires event infrastructure.
- Hybrid approach (recommended): use TTL as a safety net (catch events that were missed) combined with event-driven invalidation for known mutation points. This provides both consistency and resilience.
- Write-through caching: on every write to the source, simultaneously update the cache. This ensures the cache is always consistent but adds latency to write operations.
- For single-process applications (like Drift's CLI), event-driven invalidation can be as simple as calling `cache.invalidate()` after every write operation — no message queue needed.

**Applicability to Drift**:
Drift v1 uses TTL-only caching (5 minutes) for workspace context. This means after `drift scan`, MCP tools serve stale data for up to 5 minutes. V2 should adopt the hybrid approach: (1) After every scan completion, explicitly invalidate the context cache (event-driven), (2) Keep TTL as a safety net for edge cases (e.g., external modifications to `.drift/`), (3) For the MCP server (long-running process), use write-through caching — update the context cache as part of the scan pipeline's final step.

**Confidence**: High — cache invalidation patterns are well-established in distributed systems literature.

---

### 5.2 SQLite as Cache (Materialized Views)

**Source**: SQLite documentation — CREATE VIEW — https://sqlite.org/lang_createview.html
**Type**: Tier 1 (Official SQLite documentation)
**Accessed**: 2026-02-06

**Key Findings**:
- SQLite views are virtual tables computed on-the-fly from a SELECT statement. They don't store data — every query re-executes the SELECT.
- For caching, a "materialized view" pattern can be implemented manually: create a regular table that mirrors the view's schema, populate it with `INSERT INTO cache_table SELECT ... FROM source_tables`, and refresh it on demand.
- SQLite triggers can automate materialized view refresh: `CREATE TRIGGER refresh_cache AFTER INSERT ON source_table BEGIN DELETE FROM cache_table; INSERT INTO cache_table SELECT ...; END;`
- For Drift's workspace context, the materialized view approach eliminates the JSON cache file entirely. The context is a SQL query against drift.db, materialized into a `workspace_context` table, and refreshed after every scan.

**Applicability to Drift**:
Replace the v1 JSON context cache with a SQLite materialized view pattern. The `workspace_context` table is populated after every scan (event-driven) and queried by CLI/MCP (instant reads). This eliminates: the JSON cache file, the TTL staleness window, the L1/L2 cache complexity, and the cache invalidation problem entirely. The context is always consistent with the database because it IS the database.

**Confidence**: High — SQLite materialized views are a well-known pattern, and Drift already uses SQLite for all other storage.

---

## 6. Cross-Platform File Locking & Concurrent Access

### 6.1 fd-lock Crate (Advisory File Locks)

**Source**: fd-lock crate — https://lib.rs/crates/fd-lock
**Type**: Tier 2 (Production-validated Rust crate)
**Accessed**: 2026-02-06

**Key Findings**:
- fd-lock provides advisory cross-platform file locks using file descriptors. It supports both shared (read) and exclusive (write) locks.
- On Unix, it uses `flock(2)`. On Windows, it uses `LockFileEx`. This provides consistent behavior across platforms.
- Advisory locks are opt-in — other processes can freely ignore them. This means fd-lock should only be used for coordination between cooperative processes (like multiple Drift CLI invocations), not for security.
- Usage pattern: create an `RwLock<File>`, acquire a read or write lock, perform operations, lock is released on drop (RAII).

**Applicability to Drift**:
Drift v2 should use fd-lock (or the similar `fmutex` crate) for workspace locking. The lock file (`.drift/workspace.lock`) prevents concurrent CLI invocations from corrupting state. MCP server (long-running) holds a shared read lock; CLI write operations (scan, migrate, reset) acquire an exclusive write lock. This prevents the v1 risk of concurrent access corruption.

**Confidence**: High — fd-lock is well-maintained and provides the exact cross-platform locking Drift needs.

---

### 6.2 fmutex Crate (File-Based Mutex)

**Source**: fmutex crate — https://lib.rs/crates/fmutex
**Type**: Tier 2 (Production-validated Rust crate)
**Accessed**: 2026-02-06

**Key Findings**:
- fmutex provides mutual exclusion across processes using a file descriptor. On Unix it uses `flock(2)`, on Windows it uses `LockFileEx`.
- Simpler API than fd-lock: just `FileMutex::lock(path)` returns a guard that releases on drop.
- Supports both blocking and non-blocking lock acquisition. Non-blocking is useful for CLI commands that should fail fast if another operation is in progress.

**Applicability to Drift**:
fmutex's simpler API may be preferable for Drift's workspace locking. The non-blocking mode is particularly useful: `drift scan` should fail immediately with a clear error message if another scan is already running, rather than blocking indefinitely.

**Confidence**: High — simple, focused crate for cross-platform file locking.

---

### 6.3 SQLite's Built-in Locking (WAL Mode)

**Source**: SQLite WAL mode documentation — https://sqlite.org/wal.html
**Type**: Tier 1 (Official SQLite documentation)
**Accessed**: 2026-02-06

**Additional Source**: "Fix SQLite Database is Locked Errors: Enable WAL Mode" — https://openillumi.com/en/en-sqlite-concurrency-wal-mode/
**Type**: Tier 2 (Technical guide)
**Accessed**: 2026-02-06

**Key Findings**:
- WAL mode enables concurrent readers and a single writer. Readers don't block writers, and writers don't block readers. This is a significant improvement over the default rollback journal mode.
- SQLite enforces exclusive write access internally. Only one connection can write at a time. Other writers wait (with configurable busy timeout) or receive SQLITE_BUSY.
- For Drift's use case (single writer, multiple readers), WAL mode provides sufficient concurrency without external locking for database operations. However, external locking is still needed for non-database operations (file system operations, backup, migration).

**Applicability to Drift**:
SQLite's WAL mode handles database-level concurrency automatically. Drift v2 needs external locking only for: (1) Workspace-level operations that touch non-database files, (2) Backup operations (to prevent writes during backup), (3) Migration operations (to prevent reads during schema changes). A two-level locking strategy: SQLite WAL for database concurrency + fd-lock for workspace-level operations.

**Confidence**: Very High — SQLite's WAL mode is the standard concurrency solution for embedded databases.

---

### 6.4 sqlite-rwc: Read-Write Connection Pool

**Source**: sqlite-rwc crate — https://www.lib.rs/crates/sqlite-rwc
**Type**: Tier 2 (Rust crate for SQLite connection management)
**Accessed**: 2026-02-06

**Key Findings**:
- sqlite-rwc maintains a pool of read-only connections and one write connection. This leverages WAL mode's concurrent reader capability while enforcing exclusive write access at the application level.
- By enforcing exclusive write access at the pool level (not relying on SQLite's internal retry loop), the system provides more predictable writer access behavior and avoids SQLITE_BUSY errors from other connections within the same process.
- All non-writer connections are read-only, preventing accidental writes outside the designated writer.
- Supports async via an optional feature, where each connection gets its own thread with channel-based communication.

**Applicability to Drift**:
Drift v2's database manager should adopt this reader/writer pool pattern. The MCP server (long-running) maintains multiple read connections for concurrent tool requests. The scan pipeline uses the single write connection. This eliminates SQLITE_BUSY errors within the Drift process and provides clear separation of read/write responsibilities.

**Confidence**: High — well-designed pattern that maps directly to Drift's concurrent access needs.

---

## 7. Workspace Integrity & Garbage Collection

### 7.1 SQLite Integrity Checking

**Source**: SQLite PRAGMA integrity_check — https://sqlite.org/pragma.html#pragma_integrity_check
**Type**: Tier 1 (Official SQLite documentation)
**Accessed**: 2026-02-06

**Key Findings**:
- `PRAGMA integrity_check` performs a thorough check of the entire database: verifies that every page is reachable, that all indexes are consistent with their tables, and that all records are well-formed.
- `PRAGMA quick_check` is a faster alternative that skips index verification. Suitable for routine checks where full verification is too slow.
- For Drift's typical database sizes (< 100MB), `integrity_check` completes in under a second. For larger databases, `quick_check` is recommended for routine verification.
- Integrity check returns "ok" on success or a list of errors on failure. The check is read-only and doesn't modify the database.

**Applicability to Drift**:
Drift v2 should run `PRAGMA quick_check` on startup (fast, catches most corruption) and `PRAGMA integrity_check` on demand via `drift workspace verify` (thorough, catches everything). If corruption is detected, offer automatic recovery: restore from most recent verified backup.

**Confidence**: Very High — official SQLite integrity verification mechanism.

---

### 7.2 SQLite VACUUM for Garbage Collection

**Source**: SQLite VACUUM documentation — https://sqlite.org/lang_vacuum.html
**Type**: Tier 1 (Official SQLite documentation)
**Accessed**: 2026-02-06

**Additional Source**: "Automating SQLite Maintenance for Peak Performance" — https://www.sqliteforum.com/p/automating-sqlite-maintenance-backups
**Type**: Tier 3 (Community guide)
**Accessed**: 2026-02-06

**Key Findings**:
- VACUUM rebuilds the database file, reclaiming space from deleted rows and defragmenting the file. This can significantly reduce file size after bulk deletions (e.g., after removing old scan results).
- VACUUM requires exclusive access (no other connections) and creates a temporary copy of the database. For a 100MB database, this requires 100MB of temporary disk space.
- Auto-vacuum mode (`PRAGMA auto_vacuum = INCREMENTAL`) reclaims space incrementally without requiring exclusive access. However, it doesn't defragment — only moves free pages to the end of the file.
- Recommended maintenance schedule: run VACUUM after major data changes (e.g., after `drift reset`, after removing old scan results), not on every operation.
- `PRAGMA freelist_count` returns the number of free pages, indicating how much space could be reclaimed by VACUUM.

**Applicability to Drift**:
Drift v2 should implement workspace garbage collection as: (1) Enable `PRAGMA auto_vacuum = INCREMENTAL` for automatic space reclamation, (2) Run `PRAGMA incremental_vacuum(N)` periodically to reclaim N free pages, (3) Run full VACUUM only after major operations (reset, bulk delete) or when `freelist_count` exceeds a threshold (e.g., 20% of total pages), (4) Report disk usage via `drift workspace size` using `PRAGMA page_count * PRAGMA page_size`.

**Confidence**: Very High — official SQLite maintenance mechanisms.

---

## 8. Enterprise Backup Retention & Lifecycle

### 8.1 Tiered Retention Policies

**Source**: Database Rollback Strategies in DevOps — https://www.harness.io/harness-devops-academy/database-rollback-strategies-in-devops
**Type**: Tier 2 (Enterprise DevOps platform)
**Accessed**: 2026-02-06

**Key Findings**:
- Enterprise backup retention follows a tiered model: frequent backups for recent data (hourly/daily), less frequent for older data (weekly/monthly), and long-term archival (quarterly/yearly).
- Common enterprise retention policy: keep daily backups for 7 days, weekly backups for 4 weeks, monthly backups for 12 months. This balances storage cost with recovery granularity.
- Backup lifecycle: create → verify → store → age → archive → delete. Each stage has different storage and access requirements.
- Automated retention enforcement: a background process periodically checks backup ages and deletes those that exceed their retention tier's limit.

**Applicability to Drift**:
Drift v2 should support configurable tiered retention: (1) Operational backups (before migrations, destructive ops): keep last N (default 5), (2) Scheduled backups (daily): keep for D days (default 7), (3) Archival backups (weekly): keep for W weeks (default 4). The retention policy should be configurable in `drift.toml` and enforced automatically after every backup operation.

**Confidence**: High — standard enterprise backup practices.

---

## 9. CI/CD Workspace Patterns

### 9.1 SonarQube CI Analysis Caching

**Source**: SonarQube Incremental Analysis — https://docs.sonarsource.com/sonarqube-server/2025.5/analyzing-source-code/incremental-analysis/introduction
**Type**: Tier 1 (Official SonarQube documentation)
**Accessed**: 2026-02-06

**Key Findings**:
- SonarQube maintains per-branch analysis caches. Each branch has a single cache corresponding to the latest analysis. PR analysis downloads the target branch's cache as a baseline.
- Cache lifecycle: downloaded before analysis, read/written during analysis, uploaded after branch analysis (NOT after PR analysis — PR caches are ephemeral).
- Inactive branches (not scanned for 7+ days) have their cached data automatically deleted.
- CI integration: the scanner downloads the cache from the SonarQube server, runs analysis locally, and uploads the updated cache. This enables incremental analysis across CI runs.

**Applicability to Drift**:
Drift v2 should support CI workspace caching: (1) `drift.db` can be cached between CI runs (content-hash-based invalidation), (2) PR analysis should download the target branch's drift.db as baseline for regression detection, (3) Provide `drift workspace export --ci` and `drift workspace import --ci` commands for CI cache management, (4) Auto-detect CI environment (GitHub Actions, GitLab CI, Jenkins) and provide cache key recommendations.

**Confidence**: Very High — SonarQube's CI caching is production-proven at massive scale.

---

### 9.2 GitHub Actions Cache Patterns

**Source**: GitHub Actions cache documentation — https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows
**Type**: Tier 1 (Official GitHub documentation)
**Accessed**: 2026-02-06

**Key Findings**:
- GitHub Actions caches are keyed by a string (typically including the branch name and a hash of relevant files). Cache hits restore the cached directory; misses trigger a fresh build.
- Cache size limit: 10GB per repository. Individual caches are evicted after 7 days of no access.
- Best practice: use a hash of the lock file (package-lock.json, Cargo.lock) as part of the cache key. This ensures the cache is invalidated when dependencies change.
- Restore keys enable fallback: if the exact key doesn't match, try progressively less specific keys. This enables partial cache hits (e.g., same branch but different commit).

**Applicability to Drift**:
Drift v2 should provide CI cache guidance: cache key = `drift-{branch}-{hash of source files}`, restore key = `drift-{branch}-`, `drift-`. The `.drift/` directory (specifically drift.db) is the cache artifact. This enables incremental scanning in CI — only re-analyze files that changed since the last cached scan.

**Confidence**: Very High — GitHub Actions is the most popular CI platform.

---

## 10. Workspace Configuration Validation

### 10.1 TOML Configuration with Schema Validation

**Source**: TOML specification — https://toml.io/en/
**Type**: Tier 1 (Official specification)
**Accessed**: 2026-02-06

**Key Findings**:
- TOML is designed to be a minimal configuration file format that's easy to read. It maps unambiguously to a hash table and is used by Cargo (Cargo.toml), Python (pyproject.toml), and many other tools.
- TOML supports typed values (strings, integers, floats, booleans, dates), arrays, and tables (nested objects). This enables schema validation at the parser level.
- For configuration validation, the pattern is: define a Rust struct with `#[derive(Deserialize)]`, use `serde` to parse the TOML file, and let serde's type system enforce the schema. Missing required fields, wrong types, and unknown fields are caught at parse time.

**Applicability to Drift**:
Drift v2 should use TOML for workspace configuration (`drift.toml` at project root). The configuration struct in Rust serves as the schema — serde validates on parse. This replaces v1's unvalidated JSON config with a typed, validated, human-readable format. Unknown fields should produce warnings (not errors) for forward compatibility.

**Confidence**: Very High — TOML is the standard configuration format in the Rust ecosystem.

---

### 10.2 Configuration Layering & Defaults

**Source**: Cargo configuration — https://doc.rust-lang.org/cargo/reference/config.html
**Type**: Tier 1 (Official Cargo documentation)
**Accessed**: 2026-02-06

**Key Findings**:
- Cargo supports hierarchical configuration: values in `.cargo/config.toml` in the current directory override values in parent directories, which override values in `$CARGO_HOME/config.toml`. This enables per-project, per-workspace, and global configuration.
- Environment variables can override configuration values using a naming convention (`CARGO_` prefix). This is critical for CI environments where file-based configuration may not be available.
- Default values are built into the binary. Configuration files only need to specify overrides.

**Applicability to Drift**:
Drift v2 should support configuration layering: (1) Built-in defaults (compiled into binary), (2) Global config (`~/.drift/config.toml`), (3) Workspace config (`drift.toml` at workspace root), (4) Environment variables (`DRIFT_` prefix). Each layer overrides the previous. This enables: global preferences (backup retention), per-project settings (language detection), and CI overrides (disable interactive features).

**Confidence**: Very High — Cargo's configuration layering is the standard pattern in the Rust ecosystem.

---

## Source Index

### Tier 1 Sources (Official Documentation, Standards, Production Source Code)
1. Cargo SQLite migration source — https://doc.rust-lang.org/stable/nightly-rustc/src/cargo/util/sqlite.rs.html
2. SQLite Backup API — https://sqlite.org/backup.html
3. SQLite Online Backup API Reference — https://sqlite.org/c3ref/backup_finish.html
4. SQLite WAL mode — https://sqlite.org/wal.html
5. SQLite PRAGMA integrity_check — https://sqlite.org/pragma.html#pragma_integrity_check
6. SQLite VACUUM — https://sqlite.org/lang_vacuum.html
7. SQLite CREATE VIEW — https://sqlite.org/lang_createview.html
8. Mozilla Application Services — webext_storage schema.rs — https://mozilla.github.io/application-services/book/rust-docs/src/webext_storage/schema.rs.html
9. Mozilla Application Services — push schema.rs — https://mozilla.github.io/application-services/book/rust-docs/src/push/internal/storage/schema.rs.html
10. rust-analyzer project_model — https://rust-lang.github.io/rust-analyzer/project_model/index.html
11. rust-analyzer architecture — https://rust-analyzer.github.io/book/contributing/architecture.html
12. rust-analyzer cargo_workspace.rs — https://rust-lang.github.io/rust-analyzer/src/project_model/cargo_workspace.rs.html
13. SonarQube monorepo management — https://docs.sonarsource.com/sonarqube-server/10.8/project-administration/monorepos
14. SonarQube incremental analysis — https://docs.sonarsource.com/sonarqube-server/2025.5/analyzing-source-code/incremental-analysis/introduction
15. TOML specification — https://toml.io/en/
16. Cargo configuration — https://doc.rust-lang.org/cargo/reference/config.html
17. GitHub Actions cache — https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows

### Tier 2 Sources (Industry Experts, Production-Validated Tools)
18. rusqlite_migration — https://cj.rs/rusqlite_migration
19. rusqlite_migration GitHub — https://github.com/cljoly/rusqlite_migration
20. rusqlite GitHub — https://github.com/rusqlite/rusqlite
21. Nx project configuration — https://github.com/nrwl/nx/blob/master/docs/shared/reference/project-configuration.md
22. Turborepo workspace detection — https://turbo.build/repo/docs/getting-started/add-to-existing-repository
23. fd-lock crate — https://lib.rs/crates/fd-lock
24. fmutex crate — https://lib.rs/crates/fmutex
25. sqlite-rwc crate — https://www.lib.rs/crates/sqlite-rwc
26. "Large Rust Workspaces" (matklad) — https://matklad.github.io/2021/08/22/large-rust-workspaces.html
27. Bytebase Migration Guidelines — https://docs.bytebase.com/gitops/best-practices/migration-guidelines
28. Harness Database Rollback Strategies — https://www.harness.io/harness-devops-academy/database-rollback-strategies-in-devops
29. Cache Invalidation Strategies — https://www.leapcell.io/blog/cache-invalidation-strategies-time-based-vs-event-driven
30. SQLite Pragma Cheatsheet — https://cj.rs/blog/sqlite-pragma-cheatsheet-for-performance-and-consistency/

### Tier 3 Sources (Community Guides)
31. "The Right Way to Backup SQLite" — https://openillumi.com/en/en-sqlite-safe-backup-method/
32. "How to properly backup SQLite databases" — https://www.adyxax.org/blog/2021/11/09/how-to-properly-backup-your-sqlite-databases/
33. "Keep track of migration state in SQLite" — https://www.jotaen.net/c54IG/migration-state-sqlite-user-version/
34. "How to Design Migrations That Never Need Rollback" — https://www.c-sharpcorner.com/article/how-to-design-database-migrations-that-never-need-rollback/
35. "Automating SQLite Maintenance" — https://www.sqliteforum.com/p/automating-sqlite-maintenance-backups
36. "Fix SQLite Database is Locked Errors" — https://openillumi.com/en/en-sqlite-concurrency-wal-mode/
