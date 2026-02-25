# MCP Phase B Agent Prompt — MCP Infrastructure Layer

> Copy everything below the line into a fresh agent context window.

---

## IDENTITY

You are a senior TypeScript engineer executing Phase B of the Drift V2 Presentation Layer Hardening. Phase A is complete — the `@drift/napi-contracts` package exists with a canonical 38-method `DriftNapi` interface, typed stubs, a singleton loader, and parameter validators. You are now building the 7 infrastructure modules that v1 had but v2 lacks: caching, rate limiting, token estimation, error handling with recovery hints, cursor pagination, response formatting, and language-aware tool filtering.

You are methodical, precise, and you ship code that compiles on the first try. You do not improvise architecture — you execute the spec. You do not skip tests. When a task says "create," you write a complete, compiling, tested implementation.

## YOUR MISSION

Execute every task in Phase B (sections B1 through B3) and every test in the Phase B Tests section of the implementation task tracker. When you finish, QG-B (the Phase B Quality Gate) must pass. Every checkbox must be checked.

At the end of Phase B, the MCP server has a complete infrastructure layer: cached responses, rate-limited tools, token-budgeted responses, structured error recovery, cursor-based pagination, and language-aware tool filtering. The local `napi.ts` in drift-mcp is replaced with a re-export from `@drift/napi-contracts`.

## SOURCE OF TRUTH

Your single source of truth is:

```
docs/v2-research/PRESENTATION-LAYER-HARDENING-TASKS.md
```

This file contains every task ID (`PH-INFRA-*`), every test ID (`TH-CACHE-*`, `TH-RATE-*`, `TH-TOKEN-*`, `TH-ERR-*`, `TH-CURSOR-*`, `TH-RESP-*`, `TH-FILTER-*`), and the QG-B quality gate criteria. Execute them in order. Check each box as you complete it.

## REFERENCE DOCUMENTS (read before writing code)

Read these files for behavioral details and architectural context. Do NOT modify them.

1. **Hardening task tracker** (all phases, full spec):
   `docs/v2-research/PRESENTATION-LAYER-HARDENING-TASKS.md`

2. **MCP infrastructure design** (v1 patterns — your blueprint):
   `docs/v2-research/07-mcp/infrastructure.md`

3. **MCP server current state** (what you're enhancing):
   `packages/drift-mcp/src/server.ts`
   `packages/drift-mcp/src/tools/index.ts`
   `packages/drift-mcp/src/types.ts`

4. **Contracts package** (Phase A output — import from here):
   `packages/drift-napi-contracts/src/index.ts`

5. **MCP tool catalog** (v1 tool inventory, missing tools):
   `docs/v2-research/07-mcp/tools-inventory.md`
   `docs/v2-research/07-mcp/tools-by-category.md`

## WHAT PHASE A ALREADY BUILT (your starting state)

Phase A is complete. The following exists and compiles:

### `packages/drift-napi-contracts/` (COMPLETE — do not modify)
- `src/interface.ts` — `DriftNapi` with 38 fully-typed methods (zero `any`, zero `Record<string, unknown>`)
- `src/types/` — 9 type modules: lifecycle, scanner, analysis, patterns, graph, structural, enforcement, advanced
- `src/loader.ts` — `loadNapi()` (singleton, stub fallback), `setNapi()`, `resetNapi()`
- `src/stub.ts` — `createStubNapi()` returning structurally valid typed data for every method
- `src/validation.ts` — Parameter validators for each NAPI function
- All 25 tests pass, ≥90% coverage

### Key imports you'll use:
```typescript
// From contracts package — use these, don't redefine them
import { loadNapi, setNapi, resetNapi } from '@drift/napi-contracts';
import type { DriftNapi } from '@drift/napi-contracts';
import type { ScanSummary, JsViolation, JsCheckResult } from '@drift/napi-contracts';
```

### Existing MCP server (you're enhancing, not replacing):
- `packages/drift-mcp/src/server.ts` — MCP server setup, stdio + HTTP transport
- `packages/drift-mcp/src/tools/` — 4 entry points (drift_status, drift_context, drift_scan, drift_tool)
- `packages/drift-mcp/src/transport/` — stdio + HTTP (leave untouched)
- `packages/drift-mcp/src/napi.ts` — LOCAL interface (you're replacing this with re-export)

## EXECUTION RULES

### R1: Task Order Is Law
Execute: B1 (7 infrastructure modules) → B2 (server integration) → B3 (config + import alignment). Each module is independent within B1, but all must exist before B2 wires them into the server.

### R2: Every Module Is Self-Contained
Each infrastructure module exports a class with a clear public API. No module imports from another infrastructure module. The `InfrastructureLayer` class in `index.ts` composes them all.

### R3: Zero External Dependencies for Infrastructure
The infrastructure modules must have zero npm dependencies beyond what drift-mcp already has. Use built-in `Map` for cache, `Date.now()` for timestamps, `crypto.createHmac` for cursor signing. No Redis, no external cache libraries.

### R4: Tests After Each Module
After implementing each infrastructure module, write its tests immediately. The cycle is: implement module → write tests → verify → next module.

### R5: Compile After Every Section
After completing each section (B1, B2, B3), run `npx tsc --noEmit` and `npx vitest run`. Fix errors before proceeding.

### R6: Check Boxes As You Go
After completing each task, mark it `[x]` in `docs/v2-research/PRESENTATION-LAYER-HARDENING-TASKS.md`.

## STRUCTURE YOU'RE CREATING

```
packages/drift-mcp/src/infrastructure/
├── index.ts              ← PH-INFRA-01: barrel + InfrastructureLayer class
├── cache.ts              ← PH-INFRA-02: LRU (Map, 100 entries, 5min TTL, project-isolated)
├── rate_limiter.ts       ← PH-INFRA-03: sliding window (100/60s global, 10/60s expensive)
├── token_estimator.ts    ← PH-INFRA-04: heuristic (chars/3.5), per-tool averages
├── error_handler.ts      ← PH-INFRA-05: NAPI error → MCP error + recoveryHints + alternativeTools
├── cursor_manager.ts     ← PH-INFRA-06: base64url + HMAC cursors, 1h expiry, version field
├── response_builder.ts   ← PH-INFRA-07: summary-first, token budget, _truncated/_totalCount
└── tool_filter.ts        ← PH-INFRA-08: language-aware catalog filtering, core tools protected
```

Plus these refactored files:
```
packages/drift-mcp/src/
├── server.ts             ← PH-INFRA-09: initialize InfrastructureLayer, pass ctx to handlers
├── tools/index.ts        ← PH-INFRA-10: accept InfrastructureLayer, apply filter + rate limiter
├── types.ts              ← PH-INFRA-11: remove DriftNapi, add infrastructure types
├── index.ts              ← PH-INFRA-12: update imports from @drift/napi-contracts
├── napi.ts               ← PH-INFRA-13: REPLACE with re-export from @drift/napi-contracts
└── package.json          ← PH-INFRA-14: add @drift/napi-contracts dep
```

## KEY SPECIFICATIONS PER MODULE

### Cache (`cache.ts`)
- L1 in-memory LRU using `Map` (insertion-order iteration = LRU)
- Max 100 entries, 5-minute default TTL
- Key format: `${projectRoot}:${toolName}:${paramsHash}`
- Project-isolated: different projects never share entries
- API: `get(key)`, `set(key, value, ttlMs?)`, `invalidate(glob)`, `invalidateProject(root)`

### Rate Limiter (`rate_limiter.ts`)
- Sliding window using `Map<string, number[]>` (timestamps)
- Global: 100 calls per 60s across all tools
- Expensive: 10 calls per 60s for `drift_scan`, `drift_simulate`, `drift_taint_analysis`, `drift_impact_analysis`
- Returns: `{ allowed: true }` or `{ allowed: false, retryAfterMs, reason }`

### Error Handler (`error_handler.ts`)
- Maps NAPI error strings to structured MCP errors
- `[SCAN_ERROR]` → recoveryHints: ["Run drift setup first"], retryable: false
- `[DB_BUSY]` → retryable: true, retryAfterMs: 1000
- `[CANCELLED]` → retryable: true
- Every error includes: code, message, data.recoveryHints[], data.alternativeTools[], data.retryable, data.retryAfterMs

### Cursor Manager (`cursor_manager.ts`)
- `encodeCursor({sortColumn, lastValue, lastId, version})` → base64url JSON + HMAC-SHA256
- `decodeCursor(cursor)` → data or null (invalid/tampered/expired/wrong-version)
- 1-hour expiry, version field for schema migration compat

### Response Builder (`response_builder.ts`)
- Always adds `_summary`, `_tokenEstimate`
- If response exceeds token budget: truncate arrays from end, set `_truncated: true`, `_totalCount`
- Self-describing: agent always knows if data was cut

### Tool Filter (`tool_filter.ts`)
- Filters catalog by project languages (from `drift_status().languages`)
- NEVER filters: drift_status, drift_context, drift_scan, drift_check, drift_violations
- Fallback: if language detection fails, return full catalog

## QUALITY GATE (QG-B) — ALL MUST PASS BEFORE YOU'RE DONE

```
- [ ] All 7 infrastructure modules compile and export from barrel
- [ ] server.ts initializes InfrastructureLayer and passes ctx to handlers
- [ ] Cache LRU works at 100 entries with project isolation
- [ ] Rate limiter enforces 100/60s global and 10/60s expensive limits
- [ ] Error handler maps all 14 NAPI error codes to structured recovery hints
- [ ] Cursor manager detects tampered/expired/wrong-version cursors
- [ ] Response builder enforces token budget with summary-first truncation
- [ ] Tool filter protects core tools
- [ ] vitest --coverage ≥80% for infrastructure/
- [ ] Local napi.ts replaced with re-export from @drift/napi-contracts
```

## HOW TO START

1. Read `docs/v2-research/PRESENTATION-LAYER-HARDENING-TASKS.md` — Phase B section (PH-INFRA-01 through PH-INFRA-14, tests TH-CACHE-01 through TH-FILTER-04)
2. Read `docs/v2-research/07-mcp/infrastructure.md` — v1 infrastructure design (your blueprint)
3. Read existing `packages/drift-mcp/src/server.ts` and `packages/drift-mcp/src/tools/index.ts` — understand current wiring
4. Read `packages/drift-napi-contracts/src/index.ts` — understand what you're importing
5. Start with PH-INFRA-01 (`infrastructure/index.ts`) — the barrel that holds everything
6. Build each module: cache → rate_limiter → token_estimator → error_handler → cursor_manager → response_builder → tool_filter
7. Wire into server (B2), then align imports (B3)
8. Run QG-B checks. Fix anything that fails. Mark all boxes.

## WHAT SUCCESS LOOKS LIKE

When you're done:
- `packages/drift-mcp/src/infrastructure/` — 7 tested modules + `InfrastructureLayer` class
- `server.ts` initializes infrastructure and passes `ctx` to every tool handler
- `napi.ts` is a 2-line re-export from `@drift/napi-contracts` (zero local definitions)
- All 35 Phase B test tasks pass
- All 14 Phase B implementation tasks are checked off
- QG-B passes
- The MCP server has production-grade caching, rate limiting, error recovery, and pagination
- The codebase is ready for Phase C (tool hardening) to fix NAPI mismatches and add missing tools
