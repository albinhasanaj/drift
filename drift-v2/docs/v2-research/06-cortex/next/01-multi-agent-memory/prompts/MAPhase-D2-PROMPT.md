# MAPhase D2 — NAPI Bindings + TypeScript Bridge

> **ULTRA THINK. Quality over speed. No shortcuts. Enterprise-grade perfection.**
> Your boss audits every line through Codex. Make him stop needing to.

You are implementing Phase D2 of the Cortex multi-agent memory addition. This phase exposes the entire multi-agent Rust stack to TypeScript via NAPI bindings and a typed client. Read these files first:

- `MULTIAGENT-TASK-TRACKER.md` (Phase D2 section, tasks `PMD2-*` and tests `TMD2-*`)
- `MULTIAGENT-IMPLEMENTATION-SPEC.md` (full behavioral spec)
- `FILE-MAP.md` (complete file inventory with per-file details)

**Prerequisite:** QG-MA3a has passed — Phase D1's cross-crate integration is complete. Multi-agent features are threaded through consolidation, validation, retrieval, causal, cloud, and session crates. All `TMD1-*` tests pass, `cargo test --workspace` is green, and coverage ≥80% on all Phase D1 modified code. Feature flags work correctly in all 6 integrated crates.

---

## What This Phase Builds

Phase D2 creates the TypeScript-accessible surface for multi-agent operations. 6 impl tasks, 9 tests. Two layers:

### 1. NAPI Bindings (`cortex-napi/src/bindings/multiagent.rs`) — 12 Functions

Each function is a `#[napi]`-annotated async function that bridges TypeScript → Rust:

```
register_agent(name, capabilities)           → AgentRegistration
deregister_agent(agent_id)                   → void
get_agent(agent_id)                          → AgentRegistration | null
list_agents(status_filter?)                  → AgentRegistration[]
create_namespace(scope, name, owner)         → NamespaceId
share_memory(memory_id, target_ns, agent_id) → ProvenanceHop
create_projection(config)                    → string (projection_id)
retract_memory(memory_id, namespace, agent)  → void
get_provenance(memory_id)                    → ProvenanceRecord
trace_cross_agent(memory_id, max_depth)      → CrossAgentTrace
get_trust(agent_id, target_agent?)           → AgentTrust
sync_agents(source_agent, target_agent)      → SyncResult
```

### 2. NAPI Type Conversions (`cortex-napi/src/conversions/multiagent_types.rs`)

NAPI-friendly wrapper types with `From`/`Into` conversions:
- `NapiAgentRegistration` ↔ `AgentRegistration`
- `NapiProvenanceRecord` ↔ `ProvenanceRecord`
- `NapiProvenanceHop` ↔ `ProvenanceHop`
- `NapiCrossAgentTrace` ↔ `CrossAgentTrace`
- `NapiAgentTrust` ↔ `AgentTrust`
- `NapiSyncResult` ↔ `SyncResult`
- `NapiNamespaceACL` ↔ `NamespaceACL`

Round-trip must be lossless: Rust → NAPI → Rust preserves all fields.

### 3. TypeScript Types (`packages/cortex/src/bridge/types.ts`)

Add TypeScript interfaces matching the NAPI types:
```typescript
interface AgentRegistration { agent_id: string; name: string; namespace: string; ... }
interface AgentStatus { type: 'active' | 'idle' | 'deregistered'; since?: string; }
interface AgentId { id: string; }
interface NamespaceId { scope: NamespaceScope; name: string; }
interface NamespaceScope { type: 'agent' | 'team' | 'project'; id: string; }
interface NamespacePermission { type: 'read' | 'write' | 'share' | 'admin'; }
interface ProvenanceRecord { memory_id: string; origin: ProvenanceOrigin; chain: ProvenanceHop[]; }
interface ProvenanceHop { agent_id: string; action: ProvenanceAction; timestamp: string; confidence_delta: number; }
interface AgentTrust { agent_id: string; target_agent: string; overall_trust: number; domain_trust: Record<string, number>; }
interface CrossAgentTrace { path: Array<{ agent_id: string; memory_id: string; confidence: number }>; }
interface SyncResult { applied_count: number; buffered_count: number; errors: string[]; }
// ... etc
```

### 4. TypeScript Client (`packages/cortex/src/bridge/client.ts`)

Add 12 multi-agent methods to the existing bridge client:
```typescript
async registerAgent(name: string, capabilities: string[]): Promise<AgentRegistration>
async deregisterAgent(agentId: string): Promise<void>
async getAgent(agentId: string): Promise<AgentRegistration | null>
async listAgents(statusFilter?: string): Promise<AgentRegistration[]>
async createNamespace(scope: string, name: string, owner: string): Promise<string>
async shareMemory(memoryId: string, targetNamespace: string, agentId: string): Promise<ProvenanceHop>
async createProjection(config: ProjectionConfig): Promise<string>
async retractMemory(memoryId: string, namespace: string, agentId: string): Promise<void>
async getProvenance(memoryId: string): Promise<ProvenanceRecord>
async traceCrossAgent(memoryId: string, maxDepth: number): Promise<CrossAgentTrace>
async getTrust(agentId: string, targetAgent?: string): Promise<AgentTrust>
async syncAgents(sourceAgent: string, targetAgent: string): Promise<SyncResult>
```

---

## Critical Implementation Details

### NAPI Error Handling

Convert Rust errors to NAPI errors with clear messages:
```rust
#[napi]
pub async fn register_agent(name: String, capabilities: Vec<String>) -> napi::Result<NapiAgentRegistration> {
    let engine = get_multiagent_engine()?;
    let registration = engine
        .register_agent(&name, &capabilities)
        .await
        .map_err(|e| napi::Error::from_reason(format!("Failed to register agent: {e}")))?;
    Ok(NapiAgentRegistration::from(registration))
}
```

### Type Conversion Losslessness

Every conversion must be lossless. Test with round-trip:
```rust
let original = AgentRegistration { /* ... */ };
let napi = NapiAgentRegistration::from(original.clone());
let back: AgentRegistration = napi.into();
assert_eq!(original, back);
```

### Existing NAPI Pattern

Follow the exact pattern from existing NAPI bindings. Look at:
- `cortex-napi/src/bindings/memory.rs` — for function structure
- `cortex-napi/src/bindings/retrieval.rs` — for async function pattern
- `cortex-napi/src/conversions/memory_types.rs` — for type conversion pattern

### TypeScript Type Safety

Use strict TypeScript types. No `any`. All fields typed. JSDoc comments on all interfaces and methods. The types.ts file already has ts-rs generated types — add multi-agent types in the same style.

---

## Reference Crate Patterns

- **NAPI bindings**: Follow `cortex-napi/src/bindings/memory.rs` exactly — `#[napi]` attribute, async, error conversion, type conversion
- **Type conversions**: Follow `cortex-napi/src/conversions/memory_types.rs` — struct with `#[napi(object)]`, `From`/`Into` impls
- **TypeScript types**: Follow existing `packages/cortex/src/bridge/types.ts` — interfaces with JSDoc
- **TypeScript client**: Follow existing `packages/cortex/src/bridge/client.ts` — async methods wrapping NAPI calls

---

## Task Checklist

Check off tasks in `MULTIAGENT-TASK-TRACKER.md` as you complete them:

**NAPI**: `PMD2-NAPI-01` through `PMD2-NAPI-04`
**TypeScript**: `PMD2-TS-01`, `PMD2-TS-02`
**Tests**: All `TMD2-NAPI-*` (7), `TMD2-TS-*` (2)

---

## Quality Gate: QG-MA3b

Before proceeding to Phase D3, ALL of these must pass:

### Tests
- [ ] All 9 `TMD2-*` tests pass
- [ ] `cargo check -p cortex-napi` exits 0
- [ ] `cargo clippy -p cortex-napi` — zero warnings
- [ ] `cargo test --workspace` — zero regressions

### Coverage
- [ ] Coverage ≥80% for cortex-napi bindings/multiagent.rs
- [ ] Coverage ≥80% for cortex-napi conversions/multiagent_types.rs

### TypeScript
- [ ] `vitest run` in packages/cortex passes (including new multi-agent tests)
- [ ] All TypeScript types compile with strict mode
- [ ] All 12 bridge methods have JSDoc documentation

### Enterprise
- [ ] All NAPI functions validate inputs before calling Rust
- [ ] All error messages are clear and actionable from TypeScript
- [ ] Type conversions are lossless (round-trip tested)

---

## Common Pitfalls to Avoid

- ❌ **Don't use `any` in TypeScript types** — strict typing everywhere
- ❌ **Don't forget to register the module** — add `pub mod multiagent;` to bindings/mod.rs AND conversions/mod.rs
- ❌ **Don't lose data in type conversions** — test round-trip for every type
- ❌ **Don't expose internal Rust types directly** — always use NAPI wrapper types
- ✅ **Do validate inputs in NAPI functions** — check non-empty strings, valid UUIDs, etc.
- ✅ **Do add JSDoc comments** — TypeScript consumers need documentation
- ✅ **Do test from TypeScript** — NAPI compilation isn't enough, test the actual bridge

---

## Success Criteria

Phase D2 is complete when:

1. ✅ All 6 implementation tasks completed
2. ✅ All 9 tests pass
3. ✅ Coverage ≥80% on NAPI code
4. ✅ QG-MA3b quality gate passes
5. ✅ TypeScript tests pass
6. ✅ All 12 functions accessible from TypeScript with full type safety

**You'll know it works when:** A TypeScript caller can register an agent, share a memory, query provenance, check trust scores, and sync agents — all with full type safety and clear error messages.

---

## Next Steps After Phase D2

Once QG-MA3b passes, proceed to **MAPhase D3: MCP Tools + CLI Commands**, which creates the user-facing MCP tools and CLI commands for multi-agent operations.
