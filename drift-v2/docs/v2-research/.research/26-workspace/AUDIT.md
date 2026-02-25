# 26 Workspace — Traceability Audit

> Systematic verification of every v1 workspace-related capability, gap, type, algorithm, and integration point across all categories. This audit ensures nothing is missed before building the v2 workspace recap, research, and recommendations.

---

## Audit Scope

Workspace management in Drift is the top-level orchestration layer for project lifecycle: initialization, multi-project switching, backup/restore, schema migration, and context pre-loading. While primarily contained in Category 26 (`packages/core/src/workspace/`, ~5 TypeScript files), workspace concerns touch storage (Category 08), CLI (Category 10), MCP (Category 07), infrastructure (Category 12), and every subsystem that reads/writes to `.drift/`.

---

## 1. Primary Workspace Subsystem (Category 26)

### Source Files Audited

| File | Location | Status |
|------|----------|--------|
| `overview.md` | `26-workspace/` | ✅ Read |

### Components Inventoried

| Component | Language | File | Purpose |
|-----------|----------|------|---------|
| WorkspaceManager | TS | `workspace-manager.ts` | Singleton orchestrator — initialization, status, project management, backup/restore, destructive ops, schema migration |
| BackupManager | TS | `backup-manager.ts` | SHA-256 checksums, gzip compression, retention policy (10 max), version-aware naming |
| ContextLoader | TS | `context-loader.ts` | 2-tier cache (L1 in-memory 5min TTL, L2 disk `.drift/.context-cache.json`), workspace context pre-loading |
| ProjectSwitcher | TS | `project-switcher.ts` | Multi-project management, 5-step resolution, health indicators, agent context |
| SchemaMigrator | TS | `schema-migrator.ts` | Sequential migrations with rollback, migration history, version detection |

### Capabilities Confirmed

- [x] Singleton orchestrator pattern (WorkspaceManager)
- [x] Project initialization with auto-migration
- [x] Full workspace status reporting (initialized, active project, context loaded, migration needed, schema version, backup count)
- [x] Context pre-loading for fast CLI/MCP access
- [x] Agent-friendly project context for MCP tools
- [x] Multi-project switching with cache invalidation
- [x] 5-step project resolution (explicit → path → ID → partial match → auto-detect)
- [x] Health indicators (🟢 healthy, 🟡 warning, 🔴 critical, ⚪ unknown)
- [x] Manual and automatic backup creation
- [x] SHA-256 checksum integrity verification
- [x] Gzip compression for JSON files
- [x] Retention policy enforcement (default: 10 backups max)
- [x] 6 backup reasons (version_upgrade, schema_migration, user_requested, pre_destructive_operation, scheduled, auto_save)
- [x] Backup manifest with metadata (id, version, checksum, files list)
- [x] Backup index file (`.drift-backups/index.json`)
- [x] Auto-backup before destructive operations
- [x] Restore with cache invalidation
- [x] Destructive operation safety (explicit confirmation token "DELETE")
- [x] Schema version detection from `.drift/config.json`
- [x] Sequential migration chain discovery
- [x] Pre-migration backup
- [x] Rollback on migration failure (reverse order)
- [x] Migration history recording (`.drift/migration-history.json`)
- [x] 2 built-in migrations (1.0.0→1.1.0, 1.1.0→2.0.0)
- [x] Language auto-detection (tsconfig.json, requirements.txt, pom.xml, etc.)
- [x] Framework auto-detection (package.json deps)
- [x] CLI output formatting (project indicator, project header)

### Gaps Confirmed

- [ ] No SQLite Online Backup API usage (uses file copy instead — unsafe for WAL-mode databases)
- [ ] No configurable retention policies (hardcoded 10 max, no time-based retention)
- [ ] No backup verification (no restore-to-temp + integrity check)
- [ ] No enterprise retention tiers (daily/weekly/monthly)
- [ ] No multi-project registry in SQLite (uses JSON files)
- [ ] No project health aggregation across multiple projects
- [ ] No workspace locking (concurrent CLI/MCP access can corrupt state)
- [ ] No workspace events/hooks (no notification when scan completes, project switches, etc.)
- [ ] No workspace telemetry (no tracking of scan frequency, backup frequency, migration success rate)
- [ ] No workspace export/import (cannot transfer workspace state between machines)
- [ ] No workspace garbage collection (stale cache, orphaned files, unused indexes)
- [ ] No workspace integrity check (no way to verify `.drift/` directory is consistent)
- [ ] No workspace recovery mode (no way to repair corrupted state without full reset)
- [ ] No monorepo workspace support (single project per `.drift/` directory)
- [ ] No remote/shared workspace support (no team-level workspace sharing)
- [ ] No workspace configuration validation (no schema for config.json)
- [ ] No workspace size reporting (no way to see how much disk space `.drift/` uses)
- [ ] Context cache has no invalidation on scan completion (stale until TTL expires)
- [ ] Context cache has no partial refresh (all-or-nothing reload)
- [ ] SchemaMigrator stores version in JSON config, not SQLite `user_version` pragma
- [ ] Migration history stored in JSON file, not SQLite table
- [ ] No migration dry-run capability
- [ ] No migration progress reporting for long-running migrations
- [ ] 100% TypeScript — no Rust implementation for startup performance

---

## 2. Cross-Category Workspace Dependencies

### 2.1 Storage (Category 08)

| Workspace Concern | Storage Impact | Status |
|-------------------|---------------|--------|
| Schema migration | Must migrate both drift.db and cortex.db | ⚠️ V1 migrates JSON files only, not SQLite schemas |
| Backup | Must backup drift.db + cortex.db + JSON config | ⚠️ V1 copies files, doesn't use SQLite Backup API |
| Project registry | Should be in SQLite, not JSON | ❌ V1 uses JSON |
| Context cache | Should be SQLite materialized view, not JSON file | ❌ V1 uses JSON file |
| Workspace integrity | Should verify SQLite integrity + file consistency | ❌ Not implemented |

### 2.2 CLI (Category 10)

| Workspace Concern | CLI Impact | Status |
|-------------------|-----------|--------|
| Project indicator | CLI shows active project in output | ✅ Implemented |
| Backup commands | `drift backup create/list/restore/delete` | ✅ Implemented |
| Migration commands | `drift migrate` | ✅ Implemented |
| Status command | `drift status` shows workspace state | ✅ Implemented |
| Reset command | `drift reset` with confirmation | ✅ Implemented |
| Init command | `drift init` initializes workspace | ✅ Implemented |
| Project switch | `drift project switch <name>` | ✅ Implemented |
| Workspace size | `drift workspace size` | ❌ Not implemented |
| Workspace verify | `drift workspace verify` | ❌ Not implemented |
| Workspace export | `drift workspace export` | ❌ Not implemented |
| Workspace gc | `drift workspace gc` | ❌ Not implemented |

### 2.3 MCP (Category 07)

| Workspace Concern | MCP Impact | Status |
|-------------------|-----------|--------|
| Agent context | `getAgentContext()` provides project summary | ✅ Implemented |
| Context pre-loading | Fast MCP responses via cached context | ✅ Implemented |
| Project switching | MCP tools should respect active project | ⚠️ Implicit via WorkspaceManager singleton |
| Workspace status | MCP tool for workspace health | ❌ No dedicated MCP tool |
| Multi-project queries | Query across projects | ❌ Not supported |

### 2.4 Infrastructure (Category 12)

| Workspace Concern | Infrastructure Impact | Status |
|-------------------|----------------------|--------|
| CI initialization | Auto-init in CI pipelines | ⚠️ Manual init required |
| Docker workspace | Workspace in containerized environments | ⚠️ No container-specific handling |
| Workspace in CI cache | Cache `.drift/` between CI runs | ❌ No CI cache guidance |
| Workspace versioning | Track workspace format version | ✅ Via schema version |

---

## 3. Data Model Audit

### 3.1 WorkspaceContext Structure

```typescript
{
  project: {
    id: string,
    name: string,
    rootPath: string,
    driftPath: string,
    schemaVersion: string,
    driftVersion: string,
    lastScanAt: string | null,
    healthScore: number | null,
    languages: string[],
    frameworks: string[]
  },
  lake: {
    available: boolean,
    patternSummary: { total, approved, discovered, ignored } | null,
    callGraphSummary: { functions, calls, files } | null,
    boundarySummary: { accessPoints, sensitiveFields, violations } | null,
    lastUpdatedAt: string | null
  },
  analysis: {
    callGraphBuilt: boolean,
    testTopologyBuilt: boolean,
    couplingBuilt: boolean,
    dnaProfileExists: boolean,
    memoryInitialized: boolean,
    constantsExtracted: boolean
  },
  loadedAt: string,
  validUntil: string
}
```

**Audit Findings on Data Model**:

| ID | Finding | Severity | Impact |
|----|---------|----------|--------|
| WS-DM1 | No constraint summary in WorkspaceContext | Medium | MCP tools can't report constraint status without separate query |
| WS-DM2 | No security summary in WorkspaceContext | Medium | Security posture not available in cached context |
| WS-DM3 | No error handling summary in WorkspaceContext | Low | Error analysis status not cached |
| WS-DM4 | healthScore is nullable with no calculation method exposed | Medium | Health score depends on audit system, not workspace |
| WS-DM5 | No workspace-level configuration in context (policies, gates enabled, etc.) | Medium | MCP tools can't report configuration state |
| WS-DM6 | languages/frameworks are auto-detected arrays with no confidence scores | Low | Detection accuracy unknown |

### 3.2 Backup Manifest Structure

```typescript
{
  id: string,           // backup-{timestamp}-{reason}
  version: string,      // Drift version at backup time
  checksum: string,     // SHA-256 of backup contents
  files: string[],      // List of backed-up files
  // Missing fields identified:
  // - schemaVersion (what schema version was backed up)
  // - databaseSizes (drift.db size, cortex.db size)
  // - patternCount (how many patterns at backup time)
  // - scanCount (how many scans had been run)
  // - createdAt (explicit timestamp, not just in filename)
  // - expiresAt (for retention policy)
  // - compressed (whether gzip was applied)
  // - integrityVerified (whether backup was verified after creation)
}
```

### 3.3 Configuration Structure

```typescript
{
  autoBackup: boolean,           // default: true
  backupRetentionDays: number,   // default: 30
  maxBackups: number,            // default: 10
  enableContextCache: boolean,   // default: true
  contextCacheTTL: number,       // default: 300 (5 min)
  showProjectIndicator: boolean, // default: true
  autoDetectProject: boolean,    // default: true
  // Missing fields identified:
  // - workspaceLockTimeout (for concurrent access)
  // - backupCompression (enable/disable gzip)
  // - backupVerification (enable/disable post-backup integrity check)
  // - contextCacheStrategy ('memory' | 'disk' | 'both')
  // - projectResolutionOrder (customize 5-step resolution)
  // - telemetryEnabled (workspace usage tracking)
  // - garbageCollectionInterval (auto-cleanup schedule)
  // - maxWorkspaceSize (disk usage limit)
}
```

---

## 4. Algorithm Audit

### 4.1 Project Resolution Algorithm

```
Input: project identifier (string)
Output: resolved project or error

Step 1: Exact name match in registry → return if found
Step 2: Path match in registry → return if found
Step 3: ID match in registry → return if found
Step 4: Partial name match (substring) → return if found
Step 5: Auto-detect from cwd (check for .drift/) → return if found
Step 6: Error — project not found
```

**Audit Finding**: Step 4 (partial match) can be ambiguous if multiple projects match. No disambiguation strategy. No fuzzy matching. No "did you mean?" suggestions.

### 4.2 Context Loading Algorithm

```
Input: forceRefresh flag
Output: WorkspaceContext

Step 1: If !forceRefresh, check L1 (in-memory) cache
  → If valid (within TTL), return cached
Step 2: If !forceRefresh, check L2 (disk) cache
  → If valid (within TTL), promote to L1, return
Step 3: Load fresh context:
  3a. Read project metadata from .drift/config.json
  3b. Read lake summary from .drift/lake/ (pattern count, call graph stats, boundary stats)
  3c. Check analysis status (call graph built? test topology? coupling? DNA? memory? constants?)
  3d. Auto-detect languages and frameworks
Step 4: Store in L1 and L2 cache
Step 5: Return context
```

**Audit Finding**: No cache invalidation on scan completion. After `drift scan`, the context cache still serves stale data until TTL expires (up to 5 minutes). This means MCP tools may report outdated pattern counts immediately after a scan.

### 4.3 Schema Migration Algorithm

```
Input: none (reads current version from config)
Output: success or rollback

Step 1: Read current version from .drift/config.json
Step 2: Find migration path (chain from current to latest)
Step 3: Create backup (via BackupManager)
Step 4: For each migration in chain:
  4a. Apply migration (run up() function)
  4b. If failure: rollback all applied migrations in reverse, restore from backup, throw error
Step 5: Update version in config.json
Step 6: Record in migration-history.json
```

**Audit Finding**: Migrations operate on JSON files and directory structures, not on SQLite databases. V2 must migrate SQLite schemas (drift.db, cortex.db) using proper database migration tools. The current approach cannot handle SQL DDL changes.

### 4.4 Backup Algorithm

```
Input: reason string
Output: backup ID

Step 1: Generate backup ID: backup-{ISO timestamp}-{reason}
Step 2: Create backup directory: .drift-backups/{backup ID}/
Step 3: Copy all files from .drift/ (excluding cache, history/snapshots, .backups)
Step 4: Gzip compress JSON files
Step 5: Calculate SHA-256 checksum of all backup files
Step 6: Write backup-manifest.json (id, version, checksum, files)
Step 7: Update .drift-backups/index.json
Step 8: Enforce retention policy (delete oldest if > maxBackups)
```

**Audit Finding**: File copy (Step 3) is unsafe for WAL-mode SQLite databases. WAL pages may not be included in the copy, resulting in a corrupted backup. Must use SQLite Online Backup API.

---

## 5. Integration Contract Audit

### 5.1 Workspace → Storage Contracts

| Contract | Type | Status |
|----------|------|--------|
| Read `.drift/config.json` | File I/O | ✅ Stable |
| Read `.drift/lake/` directory | File I/O | ⚠️ V2 replaces with SQLite queries |
| Read `.drift/constraints/` directory | File I/O | ⚠️ V2 replaces with SQLite |
| Copy `.drift/` for backup | File I/O | ❌ Must use SQLite Backup API |
| Write `.drift/migration-history.json` | File I/O | ⚠️ V2 should use SQLite table |

### 5.2 Workspace → CLI Contracts

| Contract | Type | Status |
|----------|------|--------|
| `getStatus()` → CLI status display | Function call | ✅ Stable |
| `formatProjectIndicator()` → CLI prompt | Function call | ✅ Stable |
| `createBackup(reason)` → CLI backup command | Function call | ✅ Stable |
| `restore(backupId)` → CLI restore command | Function call | ✅ Stable |
| `migrate()` → CLI migrate command | Function call | ✅ Stable |
| `reset("DELETE")` → CLI reset command | Function call | ✅ Stable |

### 5.3 Workspace → MCP Contracts

| Contract | Type | Status |
|----------|------|--------|
| `getContext()` → MCP context tools | Function call | ✅ Stable |
| `getAgentContext()` → MCP agent context | Function call | ✅ Stable |
| Workspace status → MCP status tool | Not exposed | ❌ No dedicated MCP tool |

---

## 6. Risk Assessment

| Risk | Severity | Likelihood | Impact | Mitigation |
|------|----------|------------|--------|------------|
| WAL-mode backup corruption | Critical | High (if WAL enabled) | Data loss | Use SQLite Backup API |
| Concurrent access corruption | High | Medium (CLI + MCP simultaneous) | State corruption | Implement workspace locking |
| Stale context after scan | Medium | High (every scan) | Incorrect MCP responses | Event-driven cache invalidation |
| Migration failure without proper rollback | High | Low | Workspace unusable | SQLite transaction-based migrations |
| JSON config corruption | Medium | Low | Workspace unusable | Move to SQLite, add validation |
| Disk space exhaustion from backups | Medium | Medium (no size limits) | System failure | Configurable retention + size limits |
| Multi-project registry inconsistency | Medium | Medium | Wrong project loaded | SQLite-backed registry with constraints |

---

## 7. V2 Non-Negotiables for Workspace

1. **SQLite Online Backup API** — No file copies for database backup
2. **SQLite-backed state** — No JSON files for configuration, registry, migration history, or context cache
3. **Workspace locking** — Prevent concurrent access corruption
4. **Event-driven cache invalidation** — Context refreshes immediately after scan
5. **Proper database migrations** — `user_version` pragma + `rusqlite_migration` crate
6. **Backup verification** — Restore-to-temp + integrity check after every backup
7. **Monorepo support** — Multiple packages within a single workspace
8. **Workspace integrity check** — Verify `.drift/` consistency on demand
9. **Rust implementation** — Workspace initialization and context loading in Rust for startup performance

---

## 8. Audit Summary

| Metric | Count |
|--------|-------|
| Source files audited | 1 (overview.md) + cross-category references |
| Components inventoried | 5 (WorkspaceManager, BackupManager, ContextLoader, ProjectSwitcher, SchemaMigrator) |
| Capabilities confirmed | 28 |
| Gaps identified | 24 |
| Data model issues | 6 |
| Algorithm issues | 4 |
| Integration contracts | 11 (8 stable, 3 need migration) |
| Risks identified | 7 |
| V2 non-negotiables | 9 |
| Cross-category dependencies | 4 (Storage, CLI, MCP, Infrastructure) |
