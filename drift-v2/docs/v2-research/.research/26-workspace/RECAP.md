# 26 Workspace — Research Recap

## Executive Summary

The Workspace Management System (`packages/core/src/workspace/`, ~5 TypeScript files, ~2,000 estimated LOC) is Drift's top-level orchestration layer for project lifecycle — the glue that ties all subsystems together. It manages initialization, multi-project switching, backup/restore with SHA-256 integrity verification, schema migration with rollback, and context pre-loading for fast CLI/MCP access. The system is composed of 5 components: WorkspaceManager (singleton orchestrator), BackupManager (enterprise-grade backup with checksums and retention), ContextLoader (2-tier cache with TTL), ProjectSwitcher (multi-project management with health indicators), and SchemaMigrator (sequential migrations with rollback). It sits in the Orchestration layer of Drift's architecture — between the Intelligence layer (detectors, analyzers, Cortex) and the Presentation layer (CLI, MCP, IDE) — and is consumed by CLI commands (`drift init`, `drift status`, `drift backup`, `drift migrate`, `drift reset`, `drift project switch`), MCP tools (via `getAgentContext()`), and internally by every subsystem that reads from or writes to the `.drift/` directory. The system is 100% TypeScript with critical gaps in SQLite backup safety (file copy instead of Backup API), concurrent access protection (no locking), context cache invalidation (TTL-only, no event-driven refresh), and monorepo support (single project per workspace).

---

## Current Implementation

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PRESENTATION LAYER                               │
│  CLI Commands                    │ MCP Tools          │ IDE Extension    │
│  drift init                      │ getAgentContext()   │ Status bar       │
│  drift status                    │ getContext()        │ Project picker   │
│  drift backup create/list/       │                     │                  │
│    restore/delete                │                     │                  │
│  drift migrate                   │                     │                  │
│  drift reset                     │                     │                  │
│  drift project switch/list       │                     │                  │
├─────────────────────────────────────────────────────────────────────────┤
│                         WORKSPACE MANAGER (Singleton Orchestrator)        │
│                                                                          │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────┐  │
│  │  BackupManager   │  │  ContextLoader   │  │  ProjectSwitcher     │  │
│  │                  │  │                  │  │                      │  │
│  │  SHA-256 verify  │  │  L1: In-memory   │  │  5-step resolution   │  │
│  │  Gzip compress   │  │  L2: Disk cache  │  │  Health indicators   │  │
│  │  Retention (10)  │  │  TTL: 5 minutes  │  │  Agent context       │  │
│  │  6 backup reasons│  │  Force refresh   │  │  Cache invalidation  │  │
│  │  Manifest + index│  │  Auto-detect     │  │  CLI formatting      │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────────┘  │
│                                                                          │
│  ┌──────────────────┐  ┌──────────────────────────────────────────────┐ │
│  │  SchemaMigrator  │  │  Destructive Operation Guard                 │ │
│  │                  │  │                                              │ │
│  │  Version detect  │  │  Auto-backup before destructive ops         │ │
│  │  Chain discovery │  │  Explicit "DELETE" confirmation token        │ │
│  │  Pre-migration   │  │  deleteDriftFolder() / reset()              │ │
│  │    backup        │  │                                              │ │
│  │  Sequential apply│  │                                              │ │
│  │  Rollback on fail│  │                                              │ │
│  │  History tracking│  │                                              │ │
│  └──────────────────┘  └──────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────────────┤
│                         STORAGE LAYER                                    │
│  .drift/                          │ .drift-backups/                      │
│  ├── config.json (schema version) │ ├── index.json                      │
│  ├── lake/ (patterns, call graph) │ ├── backup-{ts}-{reason}/           │
│  ├── constraints/ (JSON files)    │ │   ├── backup-manifest.json        │
│  ├── .context-cache.json          │ │   └── (compressed .drift/ files)  │
│  ├── migration-history.json       │ └── ...                             │
│  └── drift.db / cortex.db        │                                      │
└─────────────────────────────────────────────────────────────────────────┘
```

### Component Inventory

| Component | File | LOC (est.) | Purpose |
|-----------|------|------------|---------|
| WorkspaceManager | `workspace-manager.ts` | ~500 | Singleton orchestrator — composes all workspace components, lifecycle management |
| BackupManager | `backup-manager.ts` | ~400 | Enterprise backup with checksums, compression, retention, manifest tracking |
| ContextLoader | `context-loader.ts` | ~350 | 2-tier cache (memory + disk), workspace context pre-loading, auto-detection |
| ProjectSwitcher | `project-switcher.ts` | ~400 | Multi-project management, resolution, health indicators, agent context |
| SchemaMigrator | `schema-migrator.ts` | ~350 | Sequential migrations, rollback, history, version management |
| **Total** | | **~2,000** | |

---

## Subsystem Deep Dives

### 1. WorkspaceManager (Singleton Orchestrator)

**Purpose**: Main entry point for all workspace operations. Composes BackupManager, ContextLoader, ProjectSwitcher, and SchemaMigrator into a unified API.

**Lifecycle Methods**:
```
initialize(options)          → Auto-migrates schema if needed, sets up registry
getStatus()                  → Returns WorkspaceStatus (initialized, active project,
                                context loaded, migration needed, schema version, backup count)
getContext(forceRefresh?)     → Pre-loaded WorkspaceContext for fast CLI/MCP access
getAgentContext()             → Agent-friendly project context for MCP tools
```

**Project Management Methods**:
```
getActiveProject()            → Current project indicator
switchProject(request)        → Switch with cache invalidation
formatProjectIndicator()      → CLI output: "[project-name]" prefix
formatProjectHeader()         → CLI output: full project header block
```

**Backup/Restore Methods**:
```
createBackup(reason)          → Manual or automatic backup
restore(backupId)             → Restore with cache invalidation
listBackups()                 → List all backups with metadata
deleteBackup(id, "DELETE")    → Delete with confirmation token
```

**Destructive Operation Methods**:
```
performDestructiveOperation(request, fn)  → Auto-backup before destructive ops
deleteDriftFolder("DELETE")               → Requires explicit confirmation token
reset("DELETE")                           → Delete everything except backups
```

**Schema Migration Methods**:
```
needsMigration()              → Check if migration is needed
migrate()                     → Run pending migrations
getSchemaVersion()            → Current schema version string
```

**Design Pattern**: Singleton with lazy initialization. All sub-components are created on first access. This ensures workspace is only initialized when actually needed (not on every CLI command).

### 2. BackupManager

**Purpose**: Enterprise-grade backup with integrity verification and retention management.

**Backup Flow**:
```
1. Generate backup ID: backup-{ISO timestamp}-{reason}
2. Create backup directory: .drift-backups/{backup ID}/
3. Copy all files from .drift/ (excluding: cache, history/snapshots, .backups)
4. Gzip compress JSON files (60-80% size reduction)
5. Calculate SHA-256 checksum of all backup files
6. Write backup-manifest.json:
   { id, version, checksum, files: string[] }
7. Update .drift-backups/index.json (append entry)
8. Enforce retention policy (delete oldest if > maxBackups)
```

**Restore Flow**:
```
1. Locate backup by ID in index
2. Verify SHA-256 checksum matches manifest
3. Decompress gzipped files
4. Copy files back to .drift/
5. Invalidate all caches (context, analysis)
```

**Backup Reasons** (6 types):
| Reason | Trigger | Automatic? |
|--------|---------|------------|
| `version_upgrade` | Drift version update | Yes |
| `schema_migration` | Before schema migration | Yes |
| `user_requested` | `drift backup create` | No |
| `pre_destructive_operation` | Before reset/delete | Yes |
| `scheduled` | Scheduled backup (not implemented) | N/A |
| `auto_save` | Auto-save (not implemented) | N/A |

**Retention Policy**:
- Default: 10 backups maximum
- Configurable via `maxBackups` setting
- Oldest backups deleted first when limit exceeded
- No time-based retention (no daily/weekly/monthly tiers)
- No size-based retention (no disk space limits)

**Storage Layout**:
```
.drift-backups/
├── index.json                              # Backup registry
├── backup-2024-01-15T10-30-00-user_requested/
│   ├── backup-manifest.json                # Metadata + checksum
│   ├── config.json.gz                      # Compressed config
│   ├── lake/                               # Pattern data
│   └── constraints/                        # Constraint data
├── backup-2024-01-16T08-00-00-schema_migration/
│   └── ...
└── ...
```

### 3. ContextLoader

**Purpose**: Pre-loads workspace data for fast CLI/MCP access. This is what makes MCP tools respond in milliseconds instead of seconds.

**Caching Strategy**:
```
┌─────────────────────────────────────────────┐
│ Request for WorkspaceContext                 │
├─────────────────────────────────────────────┤
│ L1: In-memory cache (HashMap)               │
│   TTL: 5 minutes (configurable)             │
│   Hit: Return immediately (~0ms)            │
│   Miss: Fall through to L2                  │
├─────────────────────────────────────────────┤
│ L2: Disk cache (.drift/.context-cache.json) │
│   TTL: Same as L1                           │
│   Hit: Promote to L1, return (~5ms)         │
│   Miss: Fall through to fresh load          │
├─────────────────────────────────────────────┤
│ Fresh Load:                                 │
│   Read config.json                          │
│   Read lake/ directory (pattern stats)      │
│   Check analysis status flags               │
│   Auto-detect languages + frameworks        │
│   Store in L1 + L2                          │
│   Return (~50-200ms)                        │
└─────────────────────────────────────────────┘
```

**WorkspaceContext Data Model**:
```typescript
interface WorkspaceContext {
  project: {
    id: string;
    name: string;
    rootPath: string;
    driftPath: string;
    schemaVersion: string;
    driftVersion: string;
    lastScanAt: string | null;
    healthScore: number | null;
    languages: string[];        // Auto-detected
    frameworks: string[];       // Auto-detected
  };
  lake: {
    available: boolean;
    patternSummary: {
      total: number;
      approved: number;
      discovered: number;
      ignored: number;
    } | null;
    callGraphSummary: {
      functions: number;
      calls: number;
      files: number;
    } | null;
    boundarySummary: {
      accessPoints: number;
      sensitiveFields: number;
      violations: number;
    } | null;
    lastUpdatedAt: string | null;
  };
  analysis: {
    callGraphBuilt: boolean;
    testTopologyBuilt: boolean;
    couplingBuilt: boolean;
    dnaProfileExists: boolean;
    memoryInitialized: boolean;
    constantsExtracted: boolean;
  };
  loadedAt: string;
  validUntil: string;
}
```

**Auto-Detection**:
| Ecosystem | Detection File | Language/Framework |
|-----------|---------------|-------------------|
| TypeScript | `tsconfig.json` | TypeScript |
| Python | `requirements.txt`, `pyproject.toml` | Python |
| Java | `pom.xml`, `build.gradle` | Java |
| C# | `*.csproj` | C# |
| PHP | `composer.json` | PHP |
| Go | `go.mod` | Go |
| Rust | `Cargo.toml` | Rust |
| Next.js | `package.json` → `next` | Next.js |
| React | `package.json` → `react` | React |
| Vue | `package.json` → `vue` | Vue |
| Angular | `package.json` → `@angular/core` | Angular |
| Express | `package.json` → `express` | Express |
| Fastify | `package.json` → `fastify` | Fastify |
| NestJS | `package.json` → `@nestjs/core` | NestJS |

### 4. ProjectSwitcher

**Purpose**: Multi-project management with intelligent resolution and health monitoring.

**Project Resolution Algorithm** (5 steps, in order):
```
1. Exact name match in registry     → O(1) lookup
2. Path match in registry           → O(n) scan
3. ID match in registry             → O(1) lookup
4. Partial name match (substring)   → O(n) scan, ambiguity risk
5. Auto-detect from cwd (.drift/)   → Filesystem check
```

**Health Indicators**:
| Indicator | Meaning | Criteria |
|-----------|---------|----------|
| 🟢 Healthy | All systems operational | Recent scan, no errors, patterns discovered |
| 🟡 Warning | Some issues detected | Stale scan, some errors, low pattern count |
| 🔴 Critical | Major issues | No scan data, many errors, workspace corrupted |
| ⚪ Unknown | Cannot determine | New project, no data yet |

**Agent Context** (MCP-friendly output):
```typescript
interface AgentProjectContext {
  summary: string;           // "Project 'my-app' at /path/to/project"
  availableCommands: string[]; // ["drift scan", "drift patterns", ...]
  warnings: string[];        // ["Last scan was 7 days ago", ...]
  readiness: {
    scanned: boolean;
    callGraphBuilt: boolean;
    memoryInitialized: boolean;
  };
}
```

### 5. SchemaMigrator

**Purpose**: Version upgrades with automatic backup and rollback capability.

**Migration Chain**:
```
1.0.0 → 1.1.0: Add pattern confidence breakdown
1.1.0 → 2.0.0: Restructure lake directory, add memory system support
```

**Migration Flow**:
```
1. Detect current version from .drift/config.json
2. Find migration path (sequential chain from current to latest)
3. Create backup before migration (via BackupManager)
4. For each migration in chain:
   a. Run up() function (apply changes)
   b. On failure:
      i.  Rollback all applied migrations in reverse order (run down() functions)
      ii. Restore from pre-migration backup
      iii. Throw error with details
5. Update version in .drift/config.json
6. Record in .drift/migration-history.json:
   { version, appliedAt, duration, success, error? }
```

**Migration History** (stored in `.drift/migration-history.json`):
```json
[
  {
    "from": "1.0.0",
    "to": "1.1.0",
    "appliedAt": "2024-01-15T10:30:00Z",
    "duration": 1250,
    "success": true
  },
  {
    "from": "1.1.0",
    "to": "2.0.0",
    "appliedAt": "2024-02-01T08:00:00Z",
    "duration": 3400,
    "success": true
  }
]
```

---

## Configuration

```typescript
interface WorkspaceConfig {
  autoBackup: boolean;              // Auto-backup before destructive ops (default: true)
  backupRetentionDays: number;      // Retention period in days (default: 30)
  maxBackups: number;               // Maximum backups to keep (default: 10)
  enableContextCache: boolean;      // Enable disk caching (default: true)
  contextCacheTTL: number;          // Cache TTL in seconds (default: 300 = 5 min)
  showProjectIndicator: boolean;    // Show project in CLI output (default: true)
  autoDetectProject: boolean;       // Auto-detect from cwd (default: true)
}
```

---

## Integration Points

### Upstream Dependencies (Workspace depends on)
| Category | What Workspace Consumes | How |
|----------|------------------------|-----|
| 08-storage | drift.db, cortex.db, .drift/ directory | File I/O, SQLite reads |

### Downstream Dependents (What depends on Workspace)
| Category | What It Consumes from Workspace | How |
|----------|-------------------------------|-----|
| 10-cli | Status, backup, migrate, reset, project switch commands | Function calls |
| 07-mcp | Agent context, workspace context for tool responses | Function calls |
| 11-ide | Project indicator, workspace status | Function calls |

### Cross-Cutting Interactions
| Interaction | Description |
|-------------|-------------|
| Every scan | Workspace context becomes stale (TTL-based invalidation only) |
| Every CLI command | WorkspaceManager singleton accessed for project context |
| Every MCP request | ContextLoader provides cached workspace state |
| Schema upgrades | SchemaMigrator runs before any other operation |
| Destructive operations | BackupManager creates safety backup first |

---

## Capabilities Summary

| Capability | Status | Quality |
|------------|--------|---------|
| Project initialization | ✅ Implemented | Good — auto-migration on init |
| Workspace status | ✅ Implemented | Good — comprehensive status object |
| Context pre-loading | ✅ Implemented | Good — 2-tier cache, fast MCP responses |
| Multi-project switching | ✅ Implemented | Adequate — 5-step resolution works |
| Backup creation | ✅ Implemented | Adequate — SHA-256 + gzip, but file copy not API |
| Backup restore | ✅ Implemented | Adequate — checksum verification on restore |
| Retention policy | ⚠️ Partial | Count-based only, no time-based tiers |
| Schema migration | ✅ Implemented | Good — sequential with rollback |
| Destructive op safety | ✅ Implemented | Good — auto-backup + confirmation token |
| Language auto-detection | ✅ Implemented | Adequate — file-based heuristics |
| Framework auto-detection | ✅ Implemented | Adequate — package.json deps only |
| Health indicators | ✅ Implemented | Adequate — 4-level system |
| Agent context | ✅ Implemented | Good — MCP-friendly format |

---

## Limitations (24 identified in audit)

### Critical (blocks enterprise adoption)
1. **No SQLite Backup API** — File copy is unsafe for WAL-mode databases, risking backup corruption
2. **No workspace locking** — Concurrent CLI + MCP access can corrupt state
3. **No monorepo support** — Single project per `.drift/` directory, cannot analyze multiple packages
4. **100% TypeScript** — Workspace initialization adds latency to every CLI command startup

### High (significant functionality gaps)
5. **No event-driven cache invalidation** — Context stale for up to 5 minutes after scan
6. **JSON-based state** — Config, registry, migration history, context cache all in JSON files (no ACID)
7. **No backup verification** — No restore-to-temp + integrity check after backup creation
8. **No workspace integrity check** — No way to verify `.drift/` directory consistency
9. **No workspace recovery mode** — Corrupted state requires full reset (data loss)
10. **No configurable retention tiers** — No daily/weekly/monthly enterprise retention

### Medium (usability and operational gaps)
11. No workspace export/import (cannot transfer between machines)
12. No workspace garbage collection (stale cache, orphaned files)
13. No workspace size reporting (disk usage unknown)
14. No workspace events/hooks (no scan completion notification)
15. No workspace telemetry (no usage tracking)
16. No migration dry-run capability
17. No migration progress reporting
18. No project health aggregation across multiple projects
19. No workspace configuration validation (no schema for config.json)
20. No CI-specific workspace handling (auto-init, cache guidance)

### Low (nice-to-have)
21. No remote/shared workspace support
22. No partial context refresh (all-or-nothing reload)
23. No fuzzy project matching or "did you mean?" suggestions
24. No workspace size limits or disk usage alerts

---

## V2 Migration Status

| Component | V1 Language | V2 Target | Priority | Rationale |
|-----------|------------|-----------|----------|-----------|
| WorkspaceManager | TypeScript | Rust (core) + TS (orchestration) | P1 | Startup performance |
| BackupManager | TypeScript | Rust | P1 | SQLite Backup API requires Rust |
| ContextLoader | TypeScript | Rust (loading) + TS (caching) | P1 | Fast context assembly |
| ProjectSwitcher | TypeScript | TypeScript (thin) | P2 | Orchestration layer |
| SchemaMigrator | TypeScript | Rust | P0 | Must use rusqlite_migration |

---

## Open Questions

1. Should workspace state live entirely in SQLite (drift.db) or in a separate workspace.db?
2. How should monorepo workspaces work — one `.drift/` at root with per-package partitioning, or per-package `.drift/` directories?
3. Should workspace context be a SQLite materialized view that auto-refreshes on write, eliminating the cache entirely?
4. What is the workspace locking strategy — file locks, SQLite locks, or advisory locks?
5. Should workspace export/import use a portable format (e.g., SQLite dump + metadata) for cross-machine transfer?
6. How should workspace handle CI environments differently from local development (ephemeral vs persistent)?
7. Should workspace support "profiles" (different configurations for different use cases — development, CI, review)?
