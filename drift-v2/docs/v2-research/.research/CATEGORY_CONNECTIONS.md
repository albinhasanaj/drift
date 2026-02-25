# Category Connection Map

> Use this to understand how your assigned category connects to other parts of the system.

## Dependency Matrix

Each category lists what it **depends on** (consumes from) and what **depends on it** (produces for).

---

### 00-overview
- **Depends on**: Nothing (foundational documentation)
- **Depended on by**: All categories (provides system context)

### 01-rust-core
- **Depends on**: Nothing (foundational implementation)
- **Depended on by**: 02-parsers, 03-detectors, 04-call-graph, 05-analyzers, 17-test-topology, 19-error-handling, 21-security

### 02-parsers
- **Depends on**: 01-rust-core (native parsers)
- **Depended on by**: 03-detectors, 04-call-graph, 05-analyzers, 17-test-topology, 19-error-handling, 20-contracts, 21-security

### 03-detectors
- **Depends on**: 02-parsers (AST input), 05-analyzers (analysis utilities)
- **Depended on by**: 23-pattern-repository (pattern output), 07-mcp (pattern queries), 09-quality-gates (compliance)

### 04-call-graph
- **Depends on**: 02-parsers (function/call extraction), 01-rust-core (native builder)
- **Depended on by**: 21-security (reachability), 17-test-topology (coverage), 09-quality-gates (impact), 07-mcp (queries)

### 05-analyzers
- **Depends on**: 02-parsers (AST input), 04-call-graph (graph queries)
- **Depended on by**: 03-detectors (analysis utilities), 09-quality-gates (rules engine)

### 06-cortex
- **Depends on**: 08-storage (SQLite), 23-pattern-repository (pattern links)
- **Depended on by**: 07-mcp (memory tools), 22-context-generation (memory retrieval)

### 07-mcp
- **Depends on**: 03-detectors, 04-call-graph, 06-cortex, 21-security, 22-context-generation, 23-pattern-repository
- **Depended on by**: External AI agents (presentation layer)

### 08-storage
- **Depends on**: Nothing (foundational)
- **Depended on by**: All data-producing categories

### 09-quality-gates
- **Depends on**: 03-detectors (patterns), 04-call-graph (impact), 18-constraints, 21-security
- **Depended on by**: 10-cli (gate command), 12-infrastructure (CI)

### 10-cli
- **Depends on**: All core categories (thin wrapper)
- **Depended on by**: Users, CI pipelines

### 11-ide
- **Depends on**: 07-mcp, 10-cli
- **Depended on by**: VSCode users

### 12-infrastructure
- **Depends on**: All packages (build/deploy)
- **Depended on by**: CI/CD pipelines

### 13-advanced
- **Depends on**: 02-parsers, 04-call-graph, 05-analyzers
- **Depended on by**: 07-mcp (advanced tools)

### 17-test-topology
- **Depends on**: 02-parsers, 04-call-graph
- **Depended on by**: 09-quality-gates, 07-mcp

### 18-constraints
- **Depends on**: 03-detectors (pattern data), 04-call-graph
- **Depended on by**: 09-quality-gates (verification)

### 19-error-handling
- **Depends on**: 02-parsers, 04-call-graph
- **Depended on by**: 07-mcp, 09-quality-gates

### 20-contracts
- **Depends on**: 02-parsers, 08-storage
- **Depended on by**: 07-mcp, 09-quality-gates

### 21-security
- **Depends on**: 02-parsers, 04-call-graph
- **Depended on by**: 07-mcp, 09-quality-gates

### 22-context-generation
- **Depends on**: 03-detectors, 04-call-graph, 06-cortex, 21-security
- **Depended on by**: 07-mcp (drift_context tool)

### 23-pattern-repository
- **Depends on**: 08-storage
- **Depended on by**: 03-detectors, 07-mcp, 09-quality-gates

### 24-data-lake
- **Depends on**: 08-storage, 23-pattern-repository
- **Depended on by**: 07-mcp (queries)

### 25-services-layer
- **Depends on**: 02-parsers, 03-detectors
- **Depended on by**: 10-cli (scan command)

### 26-workspace
- **Depends on**: 08-storage
- **Depended on by**: 10-cli, 07-mcp

---

## Impact Analysis

When improving a category, consider:

1. **Upstream impact**: Will changes break categories that depend on this one?
2. **Downstream requirements**: Does this category need changes in its dependencies?
3. **API contracts**: What interfaces must remain stable?
4. **Data formats**: What schemas/types are shared across categories?
