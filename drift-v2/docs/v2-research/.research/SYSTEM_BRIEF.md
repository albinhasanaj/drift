# Drift System Brief

> This is a condensed overview for research agents. You don't need to memorize this — use it to understand how your assigned category fits into the larger system.

## What Drift Is

Drift is a codebase convention discovery and indexing tool. It scans codebases to automatically discover patterns (how the team actually writes code), indexes them in SQLite, and exposes them to AI agents via MCP (Model Context Protocol).

**Core thesis**: If you can discover and index a codebase's conventions offline (no AI), you can expose them to AI at query time, giving it exactly the context it needs without wasting tokens on discovery.

## Architecture Layers

```
┌─────────────────────────────────────────────────────────────────┐
│ PRESENTATION    CLI │ MCP Server │ VSCode │ Dashboard           │
├─────────────────────────────────────────────────────────────────┤
│ ORCHESTRATION   Commands │ Services │ Quality Gates │ Workspace │
├─────────────────────────────────────────────────────────────────┤
│ INTELLIGENCE    Detectors (350+) │ Analyzers │ Cortex Memory    │
├─────────────────────────────────────────────────────────────────┤
│ ANALYSIS        Call Graph │ Boundaries │ Reachability │ etc.   │
├─────────────────────────────────────────────────────────────────┤
│ PARSING         Tree-sitter (10 languages) │ Regex fallback     │
├─────────────────────────────────────────────────────────────────┤
│ STORAGE         drift.db (SQLite) │ cortex.db (SQLite + vectors)│
├─────────────────────────────────────────────────────────────────┤
│ RUST CORE       Native parsers │ Scanner │ Call graph │ NAPI    │
└─────────────────────────────────────────────────────────────────┘
```

## The 26 Categories

| # | Category | What It Covers |
|---|----------|----------------|
| 00 | overview | System architecture, pipelines, data models, configuration |
| 01 | rust-core | Native Rust implementation: parsers, scanner, call graph, analyzers |
| 02 | parsers | Tree-sitter parsing for 10 languages, AST extraction |
| 03 | detectors | 350+ pattern detectors across 16 categories |
| 04 | call-graph | Function relationship mapping, reachability, impact analysis |
| 05 | analyzers | AST, type, semantic, flow analyzers + rules engine |
| 06 | cortex | AI memory system: 23 memory types, embeddings, retrieval, learning |
| 07 | mcp | MCP server: 50+ tools for AI agents |
| 08 | storage | SQLite schemas, data persistence |
| 09 | quality-gates | CI/CD enforcement: 6 gate types, policy engine |
| 10 | cli | 50+ commands, services, reporters, UI |
| 11 | ide | VSCode extension, LSP server, dashboard |
| 12 | infrastructure | Build system, CI/CD, Docker, telemetry, licensing |
| 13 | advanced | DNA system, decision mining, simulation engine |
| 14 | directory-map | File listings for all packages |
| 15 | migration | Rust migration strategy |
| 16 | gap-analysis | Documentation gaps and audit |
| 17 | test-topology | Test framework detection, coverage mapping |
| 18 | constraints | Architectural constraint detection and enforcement |
| 19 | error-handling | Error boundary detection, gap analysis |
| 20 | contracts | API contract tracking (BE↔FE mismatch detection) |
| 21 | security | Security boundaries, sensitive data detection |
| 22 | context-generation | AI context generation, token budgeting |
| 23 | pattern-repository | Pattern storage abstraction layer |
| 24 | data-lake | Materialized views, indexes, query engine |
| 25 | services-layer | Scan pipeline, worker pools |
| 26 | workspace | Project lifecycle, backup, migration |

## Key Data Flows

**Scan Flow**: Files → Parser → Detectors → Patterns → Storage
**Query Flow**: MCP Request → Pattern/CallGraph/Cortex queries → Curated response
**Enforcement Flow**: Quality Gates → Pattern compliance check → Pass/Fail

## Subsystem Connections

- **Parsers** feed everything (detectors, call graph, boundaries, analyzers)
- **Patterns** are the central entity (created by detectors, queried by MCP, enforced by gates)
- **Call Graph** enables reachability, impact analysis, test coverage mapping
- **Cortex** provides persistent AI memory (linked to patterns, files, functions)
- **MCP** is the presentation layer for AI consumption
- **Storage** persists everything (drift.db for analysis, cortex.db for memory)

## V2 Vision

Move all parsing, detection, and analysis to Rust. TypeScript becomes a thin orchestration layer. The goal is enterprise-grade performance for large codebases.

## Language Support

- **Parsed (10)**: TypeScript, JavaScript, Python, Java, C#, PHP, Go, Rust, C, C++
- **ORMs (28+)**: Prisma, Django, SQLAlchemy, Entity Framework, Sequelize, TypeORM, etc.
- **Frameworks (21+)**: React, Vue, Angular, Express, FastAPI, Spring, etc.

## What Makes Drift Different

1. **Learns, doesn't prescribe** — Discovers YOUR conventions
2. **Statistical confidence** — Not binary pass/fail
3. **Offline indexing** — No AI needed for scanning
4. **MCP-native** — Built for AI consumption
5. **Call graph aware** — Understands function relationships
6. **Multi-language** — 10 languages, unified analysis
