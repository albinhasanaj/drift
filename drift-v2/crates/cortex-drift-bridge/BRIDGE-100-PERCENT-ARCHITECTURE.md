# cortex-drift-bridge — 100% Architecture Blueprint

> The definitive directory plan for a fully realized bridge at enterprise-grade.
> Every module has single responsibility. Every gap from the audit is addressed.
> Generated: 2026-02-09

---

## Design Principles

1. **Leaf, not spine** (D4) — Nothing depends on this crate
2. **Event-driven** (D5) — All integration flows through trait implementations
3. **Read drift.db, write through cortex-core** — Never raw-write to cortex.db
4. **Graceful degradation** — Every subsystem has a no-op fallback
5. **Zero overhead when inactive** — If bridge is not initialized, no cost
6. **Synchronous dispatch** — No async runtime (per D5)
7. **Idempotent operations** — Re-processing the same event produces the same result
8. **Observable** — Every operation emits structured spans and metrics
9. **Recoverable** — Circuit breakers, retries, corruption recovery

---

## Full Directory Layout

```
crates/cortex-drift-bridge/
├── Cargo.toml
├── Cargo.lock
├── BRIDGE-100-PERCENT-ARCHITECTURE.md   # This file
│
├── src/
│   ├── lib.rs                           # Crate root: module declarations, BridgeRuntime
│   │
│   │ ══════════════════════════════════════════════════════
│   │  LAYER 0: FOUNDATION (errors, config, types, health)
│   │ ══════════════════════════════════════════════════════
│   │
│   ├── errors/
│   │   ├── mod.rs                       # Re-exports BridgeError, BridgeResult
│   │   ├── bridge_error.rs              # BridgeError enum — all error variants
│   │   ├── context.rs                   # ErrorContext: attach file/line/span to any error
│   │   ├── recovery.rs                  # RecoveryAction enum: Retry, Fallback, Escalate, Ignore
│   │   └── chain.rs                     # Error chain builder for multi-step operations
│   │
│   ├── config/
│   │   ├── mod.rs                       # Re-exports BridgeConfig, EventMappingConfig
│   │   ├── bridge_config.rs             # BridgeConfig: all bridge settings from drift.toml
│   │   ├── event_config.rs              # Per-event enable/disable (21 toggles from §6.3)
│   │   ├── grounding_config.rs          # GroundingConfig: thresholds, intervals, limits
│   │   ├── evidence_config.rs           # Per-evidence-type weight overrides
│   │   └── validation.rs               # Config validation: reject invalid combos at startup
│   │
│   ├── types/
│   │   ├── mod.rs                       # Re-exports all shared types
│   │   ├── grounding_result.rs          # GroundingResult (full spec: memory_type, data_sources, checked_at)
│   │   ├── grounding_snapshot.rs        # GroundingSnapshot (full spec: flagged_for_review, checked_at)
│   │   ├── confidence_adjustment.rs     # ConfidenceAdjustment + AdjustmentMode (5 variants incl. Set)
│   │   ├── grounding_verdict.rs         # GroundingVerdict (7 variants incl. Error)
│   │   ├── data_source.rs              # GroundingDataSource enum (12 Drift subsystems)
│   │   └── event_processing_result.rs   # EventProcessingResult with full metadata
│   │
│   ├── health/
│   │   ├── mod.rs                       # Re-exports HealthStatus, HealthCheck
│   │   ├── status.rs                    # BridgeHealth: Available, Degraded(reason), Unavailable
│   │   ├── checks.rs                    # Individual checks: cortex_db, drift_db, causal_engine
│   │   ├── readiness.rs                 # Readiness probe: all subsystems initialized?
│   │   └── degradation.rs              # DegradationTracker: which features are degraded and why
│   │
│   │ ══════════════════════════════════════════════════════
│   │  LAYER 1: DATA ACCESS (storage, query, connections)
│   │ ══════════════════════════════════════════════════════
│   │
│   ├── storage/
│   │   ├── mod.rs                       # Re-exports all storage operations
│   │   ├── schema.rs                    # CREATE TABLE statements for 5 bridge tables
│   │   ├── migrations.rs               # Schema versioning: v1→v2→v3 with rollback
│   │   ├── bridge_tables.rs             # CRUD for bridge-specific tables (grounding_results, etc.)
│   │   ├── cortex_writer.rs             # Writes through IMemoryStorage — memories are first-class
│   │   ├── retention.rs                 # Retention policies: 7d metrics, 30d events, 90d/∞ grounding
│   │   └── connection_pool.rs           # Connection management, health-checked pool
│   │
│   ├── query/
│   │   ├── mod.rs                       # Re-exports cross-DB query layer
│   │   ├── attach.rs                    # ATTACH/DETACH lifecycle with guard pattern (auto-detach)
│   │   ├── drift_queries.rs             # Parameterized read-only queries against drift.db
│   │   │                                #   - pattern confidence by pattern_id
│   │   │                                #   - occurrence rate by pattern_id
│   │   │                                #   - false positive rate by pattern_id
│   │   │                                #   - constraint verification status
│   │   │                                #   - coupling metrics by module path
│   │   │                                #   - DNA health by project
│   │   │                                #   - test coverage by module
│   │   │                                #   - error handling gaps
│   │   │                                #   - decision evidence
│   │   │                                #   - boundary data
│   │   ├── cortex_queries.rs            # Queries against cortex.db (memory lookup, search)
│   │   └── cross_db.rs                  # Joined queries across both databases
│   │
│   │ ══════════════════════════════════════════════════════
│   │  LAYER 2: CORE LOGIC (the 7 responsibilities)
│   │ ══════════════════════════════════════════════════════
│   │
│   ├── event_mapping/
│   │   ├── mod.rs                       # Re-exports BridgeEventHandler, EventMapping
│   │   ├── memory_types.rs              # 21-row EVENT_MAPPINGS const table + lookup helpers
│   │   ├── handler.rs                   # BridgeEventHandler: impl DriftEventHandler (21 methods)
│   │   ├── enrichment.rs                # Enrich events by querying drift.db at event time
│   │   │                                #   - PatternApproved → fetch confidence, file_count, locations
│   │   │                                #   - RegressionDetected → fetch affected_files, delta details
│   │   │                                #   - ViolationDismissed → fetch severity, file, line
│   │   │                                #   - BoundaryDiscovered → fetch full boundary metadata
│   │   ├── dedup.rs                     # Content-hash deduplication: same event → same memory
│   │   ├── cortex_handler.rs            # BridgeCortexEventHandler: impl CortexEventHandler
│   │   │                                #   - on_memory_created → check if groundable, schedule
│   │   │                                #   - on_memory_updated → re-ground affected memories
│   │   │                                #   - on_contradiction_detected → cross-ref with drift data
│   │   │                                #   - on_consolidation_complete → re-ground consolidated
│   │   └── memory_builder.rs            # BaseMemory construction helpers with full field population
│   │                                    #   - linked_files from Drift locations
│   │                                    #   - linked_functions from call graph
│   │                                    #   - entity_links from EntityLink constructors
│   │                                    #   - metadata JSON with drift_confidence, drift_category, etc.
│   │
│   ├── link_translation/
│   │   ├── mod.rs                       # Re-exports LinkTranslator, EntityLink
│   │   ├── entity_link.rs               # EntityLink struct + 5 constructors (pattern, constraint, detector, module, decision)
│   │   ├── translator.rs                # LinkTranslator: forward + reverse translation
│   │   │                                #   - translate_pattern, translate_constraint (existing)
│   │   │                                #   - translate_file → FileLink round-trip
│   │   │                                #   - translate_function → FunctionLink round-trip
│   │   ├── batch.rs                     # translate_all: batch translation with confidence map
│   │   └── round_trip.rs                # Round-trip fidelity: EntityLink ↔ PatternLink ↔ ConstraintLink
│   │
│   ├── grounding/
│   │   ├── mod.rs                       # Re-exports all grounding components
│   │   ├── classification.rs            # Groundability: 6 Full + 7 Partial + 10 NotGroundable
│   │   ├── scheduler.rs                 # GroundingScheduler: 6 trigger types, scan counting
│   │   ├── loop_runner.rs               # GroundingLoopRunner: orchestrates full/incremental loops
│   │   │                                #   - run(): batch grounding, 500-memory cap, excess deferred
│   │   │                                #   - ground_single(): on-demand single memory
│   │   │                                #   - trigger_from_scan(): wired to on_scan_complete
│   │   ├── scorer.rs                    # GroundingScorer: weighted average, 4 thresholds
│   │   │                                #   - compute_score()
│   │   │                                #   - score_to_verdict() (7 variants)
│   │   │                                #   - compute_confidence_adjustment() (5 modes incl. Set)
│   │   │                                #   - should_generate_contradiction()
│   │   │                                #   - score_delta uses for trend amplification
│   │   ├── contradiction.rs             # Contradiction generation: creates Cortex contradiction
│   │   │                                #   from grounding invalidation, wired to cortex-core
│   │   │                                #   validation engine
│   │   │
│   │   └── evidence/                    # *** THE KEY FIX: active evidence collectors ***
│   │       ├── mod.rs                   # Re-exports EvidenceCollector trait + all implementations
│   │       ├── types.rs                 # GroundingEvidence, EvidenceType (10), default weights
│   │       ├── collector.rs             # EvidenceCollector trait: fn collect(&self, memory, drift_db) -> Vec<Evidence>
│   │       ├── pattern_confidence.rs    # Queries drift.db: SELECT confidence FROM drift_patterns WHERE id = ?
│   │       ├── pattern_occurrence.rs    # Queries drift.db: SELECT occurrence_rate FROM drift_patterns WHERE id = ?
│   │       ├── false_positive_rate.rs   # Queries drift.db: SELECT fp_rate FROM drift_violation_feedback WHERE pattern_id = ?
│   │       ├── constraint_verification.rs # Queries drift.db: SELECT verified FROM drift_constraints WHERE id = ?
│   │       ├── coupling_metric.rs       # Queries drift.db: SELECT instability FROM drift_coupling WHERE module = ?
│   │       ├── dna_health.rs            # Queries drift.db: SELECT health_score FROM drift_dna WHERE project = ?
│   │       ├── test_coverage.rs         # Queries drift.db: SELECT coverage FROM drift_test_topology WHERE module = ?
│   │       ├── error_handling_gaps.rs   # Queries drift.db: SELECT gap_count FROM drift_error_handling WHERE module = ?
│   │       ├── decision_evidence.rs     # Queries drift.db: SELECT evidence_score FROM drift_decisions WHERE id = ?
│   │       ├── boundary_data.rs         # Queries drift.db: SELECT boundary_score FROM drift_boundaries WHERE id = ?
│   │       └── composite.rs             # CompositeCollector: runs all 10 collectors, merges results
│   │
│   ├── specification/
│   │   ├── mod.rs                       # Re-exports all spec bridge components
│   │   ├── corrections.rs               # SpecCorrection + 7 CorrectionRootCause → CausalRelation mapping
│   │   ├── attribution.rs               # DataSourceAttribution tracking + AttributionStats
│   │   ├── events.rs                    # on_spec_corrected, on_contract_verified, on_decomposition_adjusted
│   │   ├── narrative.rs                 # explain_spec_section, summarize_corrections via CausalEngine
│   │   │
│   │   ├── weights/
│   │   │   ├── mod.rs                   # Re-exports BridgeWeightProvider
│   │   │   ├── provider.rs              # BridgeWeightProvider: impl WeightProvider trait
│   │   │   ├── computation.rs           # Adaptive weight formula: base × (1 + failure_rate × 0.5)
│   │   │   ├── decay.rs                 # 365-day half-life decay: weights → static defaults over time
│   │   │   ├── bounds.rs                # Weight invariants: 0.0 ≤ w ≤ 5.0, sum ∈ [5.0, 30.0], NaN → default
│   │   │   └── persistence.rs           # Store/load adaptive weights as Skill memories in cortex.db
│   │   │
│   │   └── decomposition/
│   │       ├── mod.rs                   # Re-exports BridgeDecompositionPriorProvider
│   │       ├── provider.rs              # BridgeDecompositionPriorProvider: impl DecompositionPriorProvider
│   │       ├── dna_similarity.rs        # DNA similarity computation (threshold ≥ 0.6), replaces LIKE '%boundary%'
│   │       ├── structured_priors.rs     # Structured PriorAdjustmentType parsing (not string matching)
│   │       └── feedback_loop.rs         # Confirm → boost confidence; Reject → penalize confidence
│   │                                    #   Updates ORIGINAL prior, not just creates new memory
│   │
│   ├── intents/
│   │   ├── mod.rs                       # Re-exports CodeIntent, CODE_INTENTS
│   │   ├── extensions.rs                # 10 code-specific intent definitions
│   │   └── resolver.rs                  # Intent → relevant Drift data sources mapping for context
│   │
│   ├── license/
│   │   ├── mod.rs                       # Re-exports LicenseTier, FeatureGate
│   │   └── gating.rs                    # 3-tier feature gating: Community, Team, Enterprise
│   │
│   │ ══════════════════════════════════════════════════════
│   │  LAYER 3: CAUSAL INTELLIGENCE (graph operations)
│   │ ══════════════════════════════════════════════════════
│   │
│   ├── causal/
│   │   ├── mod.rs                       # Re-exports all causal bridge operations
│   │   ├── edge_builder.rs              # Typed edge creation: correction→memory, upstream→downstream
│   │   │                                #   Wraps CausalEngine.add_edge with bridge-specific defaults
│   │   ├── inference.rs                 # Auto-discovery: CausalEngine.infer_and_connect for bridge memories
│   │   │                                #   Run after batch event processing to find implicit relationships
│   │   ├── counterfactual.rs            # "What if pattern X didn't exist?" — wraps CausalEngine.counterfactual
│   │   │                                #   Returns impact assessment with affected memories + confidence deltas
│   │   ├── intervention.rs              # "If we change convention X, what breaks?" — wraps CausalEngine.intervention
│   │   │                                #   Returns downstream propagation graph with severity scores
│   │   ├── pruning.rs                   # Prune weak/invalidated causal edges after grounding
│   │   │                                #   Wraps CausalEngine.prune with bridge-specific thresholds
│   │   └── narrative_builder.rs         # Rich narrative generation combining all traversal operations
│   │                                    #   bidirectional + origins + effects → unified explanation
│   │
│   │ ══════════════════════════════════════════════════════
│   │  LAYER 4: PRESENTATION (tools, NAPI, observability)
│   │ ══════════════════════════════════════════════════════
│   │
│   ├── tools/
│   │   ├── mod.rs                       # Re-exports all MCP tool handlers
│   │   ├── drift_why.rs                 # "Why does this exist?" — memories + grounding + causal + counterfactual
│   │   ├── drift_memory_learn.rs        # "Learn from this correction" — Feedback memory + causal edge
│   │   ├── drift_grounding_check.rs     # "Check grounding status" — ground single + history + evidence
│   │   ├── drift_counterfactual.rs      # "What if X didn't exist?" — counterfactual analysis
│   │   ├── drift_intervention.rs        # "What breaks if we change X?" — intervention analysis
│   │   ├── drift_bridge_status.rs       # "Bridge health report" — subsystem status, degradation, metrics
│   │   └── drift_grounding_report.rs    # "Full grounding report" — snapshot + trends + contradictions
│   │
│   ├── napi/
│   │   ├── mod.rs                       # Re-exports all NAPI-ready functions
│   │   ├── status.rs                    # bridge_status (1)
│   │   ├── grounding.rs                 # bridge_ground_memory, bridge_ground_all, bridge_grounding_history (3)
│   │   ├── links.rs                     # bridge_translate_link, bridge_translate_constraint_link (2)
│   │   ├── mappings.rs                  # bridge_event_mappings, bridge_groundability (2)
│   │   ├── license.rs                   # bridge_license_check (1)
│   │   ├── intents.rs                   # bridge_intents (1)
│   │   ├── specification.rs             # bridge_adaptive_weights, bridge_spec_correction,
│   │   │                                #   bridge_contract_verified, bridge_decomposition_adjusted,
│   │   │                                #   bridge_explain_spec (5)
│   │   ├── causal.rs                    # bridge_counterfactual, bridge_intervention (2)
│   │   ├── health.rs                    # bridge_health_check, bridge_degradation_status (2)
│   │   └── metrics.rs                   # bridge_metrics_snapshot (1)
│   │                                    #   Total: 20 NAPI functions
│   │
│   ├── metrics/
│   │   ├── mod.rs                       # Re-exports MetricsCollector, all metric types
│   │   ├── collector.rs                 # MetricsCollector: thread-safe counters + gauges + histograms
│   │   ├── counters.rs                  # Event counters: events_processed, memories_created, errors
│   │   ├── gauges.rs                    # Gauges: grounding_score_avg, memories_groundable, bridge_available
│   │   ├── histograms.rs               # Histograms: grounding_duration_ms, event_processing_us
│   │   ├── persistence.rs              # Flush metrics to bridge_metrics table on interval
│   │   └── snapshot.rs                  # MetricsSnapshot: point-in-time export for NAPI/MCP
│   │
│   ├── tracing/
│   │   ├── mod.rs                       # Re-exports span builders
│   │   ├── spans.rs                     # Pre-built #[instrument] span definitions per operation
│   │   │                                #   - bridge.event_mapping (event_type, memory_type)
│   │   │                                #   - bridge.grounding (memory_count, trigger_type)
│   │   │                                #   - bridge.grounding.evidence (evidence_type, drift_value)
│   │   │                                #   - bridge.causal (operation, memory_id)
│   │   │                                #   - bridge.query (db_target, query_type)
│   │   └── fields.rs                    # Structured field extractors for consistent span attributes
│   │
│   │ ══════════════════════════════════════════════════════
│   │  LAYER 5: RESILIENCE (circuit breakers, recovery)
│   │ ══════════════════════════════════════════════════════
│   │
│   └── resilience/
│       ├── mod.rs                       # Re-exports CircuitBreaker, RetryPolicy
│       ├── circuit_breaker.rs           # Per-subsystem circuit breakers
│       │                                #   - cortex_db: trips after 5 consecutive failures, 30s cooldown
│       │                                #   - drift_db: trips after 3 failures, 60s cooldown
│       │                                #   - causal_engine: trips after 3 failures, 30s cooldown
│       │                                #   States: Closed → Open → HalfOpen → Closed
│       ├── retry.rs                     # RetryPolicy: exponential backoff with jitter, max 3 attempts
│       ├── fallback.rs                  # Fallback strategies per operation:
│       │                                #   - grounding fails → return InsufficientData verdict
│       │                                #   - cortex write fails → queue to bridge_memories (buffer)
│       │                                #   - causal edge fails → store correction without edge
│       │                                #   - weight query fails → return static defaults
│       │                                #   - prior query fails → return empty vec
│       └── recovery.rs                  # Corruption recovery:
│                                        #   - detect orphaned memories (no causal edges)
│                                        #   - detect dangling edges (referencing missing nodes)
│                                        #   - rebuild bridge tables from cortex.db + drift.db
│                                        #   - validate schema version on startup
│
├── tests/
│   │ ══════════════════════════════════════════════════════
│   │  TEST ORGANIZATION (mirrors Phase 9 test plan)
│   │ ══════════════════════════════════════════════════════
│   │
│   ├── common/
│   │   ├── mod.rs                       # Shared test utilities
│   │   ├── fixtures.rs                  # Test database setup: fresh drift.db + cortex.db
│   │   ├── builders.rs                  # Builder pattern for MemoryForGrounding, SpecCorrection, etc.
│   │   └── assertions.rs               # Custom assertion helpers: assert_memory_created, assert_grounded
│   │
│   ├── unit/
│   │   ├── event_mapping_test.rs        # §9A: 21 event→memory mappings (T9-BRIDGE-47)
│   │   ├── enrichment_test.rs           # Event enrichment from drift.db queries
│   │   ├── dedup_test.rs                # Idempotency: same event → same memory
│   │   ├── link_translation_test.rs     # 5 constructors + round-trip fidelity
│   │   ├── grounding_scorer_test.rs     # Score computation, thresholds, confidence adjustment
│   │   ├── grounding_classification_test.rs # 6 Full + 7 Partial + 10 NotGroundable
│   │   ├── evidence_collector_test.rs   # Each of 10 evidence collectors independently
│   │   ├── contradiction_test.rs        # Contradiction generation from invalidation
│   │   ├── weight_computation_test.rs   # Formula: base × (1 + failure_rate × 0.5)
│   │   ├── weight_decay_test.rs         # 365-day half-life decay
│   │   ├── weight_bounds_test.rs        # NaN, negative, overflow protection
│   │   ├── dna_similarity_test.rs       # Similarity computation + 0.6 threshold
│   │   ├── prior_feedback_test.rs       # Confirm → boost, reject → penalize
│   │   ├── correction_causal_test.rs    # 7 root causes → correct CausalRelation
│   │   ├── circuit_breaker_test.rs      # State transitions, cooldown, half-open
│   │   ├── retry_test.rs               # Exponential backoff, max attempts, jitter
│   │   ├── config_validation_test.rs    # Invalid config rejection
│   │   └── metrics_test.rs              # Counter increment, gauge set, histogram record
│   │
│   ├── integration/
│   │   ├── grounding_loop_test.rs       # Full loop: memories → evidence → score → verdict → adjust
│   │   ├── active_evidence_test.rs      # Evidence collectors querying real drift.db
│   │   ├── cortex_writer_test.rs        # Write through IMemoryStorage, verify in cortex.db
│   │   ├── causal_graph_test.rs         # Corrections → edges → narrative → traversal
│   │   ├── counterfactual_test.rs       # "What if" analysis end-to-end
│   │   ├── intervention_test.rs         # "What breaks" analysis end-to-end
│   │   ├── spec_bridge_test.rs          # T9-BRIDGE-01 through T9-BRIDGE-50
│   │   ├── spec_integration_test.rs     # TINT-LOOP-01 through TINT-LOOP-14
│   │   ├── scan_triggers_grounding_test.rs # on_scan_complete → grounding loop runs
│   │   └── bidirectional_events_test.rs # Drift→Cortex and Cortex→Drift event flow
│   │
│   ├── adversarial/
│   │   ├── hardening_test.rs            # SQL injection, NaN, empty strings, 1MB payloads
│   │   ├── feedback_amplification_test.rs # Weight oscillation attack (TINT-LOOP-10)
│   │   ├── poisoned_priors_test.rs      # Malicious project poisoning prior pool (TINT-LOOP-09)
│   │   └── rapid_fire_test.rs           # 1000 events/second burst (T9-BRIDGE-36)
│   │
│   ├── concurrency/
│   │   ├── parallel_grounding_test.rs   # 4 threads grounding simultaneously
│   │   ├── parallel_events_test.rs      # Correction + verification for same module
│   │   ├── cross_db_attach_test.rs      # Concurrent ATTACH from multiple threads
│   │   └── weight_read_write_test.rs    # Concurrent weight read during write
│   │
│   ├── recovery/
│   │   ├── corruption_test.rs           # Corrupted tables, truncated rows, invalid JSON
│   │   ├── missing_db_test.rs           # cortex.db missing → graceful degradation
│   │   ├── interrupted_operation_test.rs # Crash mid-correction → no partial state
│   │   └── schema_migration_test.rs     # v1→v2 migration preserves data
│   │
│   └── stress/
│       ├── stress_test.rs               # 100 modules, 500 corrections, 200 verifications
│       └── memory_test.rs               # RSS < 500MB under load, no leaks
│
└── benches/
    ├── grounding_bench.rs               # Grounding loop: 500 memories, measure wall time
    ├── evidence_collection_bench.rs     # 10 evidence collectors against real drift.db
    ├── event_mapping_bench.rs           # 1000 events/second throughput
    └── causal_traversal_bench.rs        # Narrative generation for deep chains (depth=20)
```

---

## Module Responsibility Matrix

| Module | Single Responsibility | Depends On | Depended On By |
|--------|----------------------|------------|----------------|
| `errors/` | Error taxonomy + recovery actions | — | Everything |
| `config/` | Parse + validate drift.toml [bridge] | `errors` | `lib.rs`, every module that reads config |
| `types/` | Shared data structures (no logic) | `cortex-core`, `drift-core` | `grounding`, `tools`, `napi`, `storage` |
| `health/` | Subsystem availability tracking | `errors`, `config` | `lib.rs`, `napi/health`, `tools/bridge_status` |
| `storage/` | All database writes + schema | `errors`, `types`, `cortex-core` | `event_mapping`, `grounding`, `specification` |
| `query/` | All database reads (both DBs) | `errors`, `storage` | `grounding/evidence`, `event_mapping/enrichment` |
| `event_mapping/` | Drift events → Cortex memories | `storage`, `query`, `config`, `license` | `lib.rs` (registered as handler) |
| `link_translation/` | Link type conversion | `cortex-core` | `event_mapping`, `tools` |
| `grounding/` | Memory validation against scan data | `query`, `storage`, `types`, `config` | `tools`, `napi`, `event_mapping` |
| `grounding/evidence/` | Active drift.db queries per evidence type | `query` | `grounding/loop_runner` |
| `specification/` | Spec corrections, weights, decomposition | `storage`, `causal`, `cortex-causal` | `tools`, `napi` |
| `specification/weights/` | Adaptive weight computation + decay | `storage`, `config` | `specification` |
| `specification/decomposition/` | DNA similarity priors + feedback | `storage`, `query` | `specification` |
| `intents/` | Code-specific intent definitions | — | `napi`, `tools` |
| `license/` | Feature gating per tier | — | `event_mapping`, `grounding`, `tools` |
| `causal/` | CausalEngine wrapper operations | `cortex-causal` | `specification`, `tools` |
| `tools/` | MCP tool request handlers | Everything above | `napi` |
| `napi/` | JSON serialization for Node.js FFI | `tools`, `types` | External (cortex-drift-napi crate) |
| `metrics/` | Counters, gauges, histograms | `storage` | Every module emits metrics |
| `tracing/` | Structured span definitions | — | Every module emits spans |
| `resilience/` | Circuit breakers, retry, fallback | `errors`, `health` | `storage`, `query`, `grounding` |

---

## Data Flow at 100%

### Flow 1: Drift Event → Enriched Cortex Memory
```
DriftEventHandler.on_pattern_approved(event)
  → license/gating.rs: check tier allows event
  → config/event_config.rs: check per-event toggle
  → event_mapping/dedup.rs: content-hash check (idempotent)
  → event_mapping/enrichment.rs: query drift.db for full pattern data
  → event_mapping/memory_builder.rs: construct BaseMemory with full fields
  → storage/cortex_writer.rs: write through IMemoryStorage.create()
  → storage/bridge_tables.rs: log to bridge_event_log
  → metrics/counters.rs: increment events_processed
  → grounding/scheduler.rs: schedule MemoryCreation trigger
```

### Flow 2: Scan Complete → Grounding Loop
```
DriftEventHandler.on_scan_complete(event)
  → grounding/scheduler.rs: determine trigger type (Incremental vs Full)
  → storage/cortex_writer.rs: query groundable memories via IMemoryStorage
  → grounding/loop_runner.rs: cap at 500, iterate
    → grounding/classification.rs: filter NotGroundable
    → grounding/evidence/composite.rs: collect evidence from ALL 10 collectors
      → grounding/evidence/pattern_confidence.rs: query drift.db
      → grounding/evidence/false_positive_rate.rs: query drift.db
      → ... (10 parallel collectors)
    → grounding/scorer.rs: weighted average → verdict
    → grounding/scorer.rs: confidence adjustment (5 modes)
    → grounding/contradiction.rs: generate contradiction if Invalidated
    → storage/cortex_writer.rs: update memory confidence via IMemoryStorage.update()
    → storage/bridge_tables.rs: record grounding result + snapshot
  → metrics: record grounding_duration, per-verdict counts
```

### Flow 3: Spec Correction → Causal Graph
```
tools/drift_memory_learn.rs (MCP request)
  → specification/corrections.rs: parse SpecCorrection + root cause
  → specification/events.rs: on_spec_corrected
    → storage/cortex_writer.rs: create Feedback memory via IMemoryStorage
    → causal/edge_builder.rs: add_edge(upstream → correction, relation, strength)
    → specification/attribution.rs: record DataSourceAttribution
  → causal/inference.rs: infer_and_connect with nearby memories
  → metrics: increment corrections_processed
```

### Flow 4: "Why does this exist?" (MCP Tool)
```
tools/drift_why.rs (MCP request)
  → query/cortex_queries.rs: find related memories
  → query/drift_queries.rs: get current scan data for entity
  → grounding/loop_runner.rs: ground_single for latest grounding
  → causal/narrative_builder.rs: bidirectional traversal → narrative
  → causal/counterfactual.rs: "what if this didn't exist?"
  → causal/intervention.rs: "what breaks if we change this?"
  → combine all into rich JSON response
```

---

## File Count Summary

| Layer | Module | Files | Purpose |
|-------|--------|-------|---------|
| L0 | `errors/` | 5 | Error taxonomy |
| L0 | `config/` | 6 | Configuration |
| L0 | `types/` | 7 | Shared types |
| L0 | `health/` | 5 | Health monitoring |
| L1 | `storage/` | 7 | Database writes |
| L1 | `query/` | 5 | Database reads |
| L2 | `event_mapping/` | 7 | Events → memories |
| L2 | `link_translation/` | 5 | Link conversion |
| L2 | `grounding/` | 6 + 13 = 19 | Memory validation |
| L2 | `specification/` | 5 + 5 + 5 = 15 | Spec engine bridge |
| L2 | `intents/` | 3 | Intent extensions |
| L2 | `license/` | 2 | Feature gating |
| L3 | `causal/` | 7 | Graph operations |
| L4 | `tools/` | 8 | MCP handlers |
| L4 | `napi/` | 11 | NAPI functions |
| L4 | `metrics/` | 7 | Observability |
| L4 | `tracing/` | 3 | Structured spans |
| L5 | `resilience/` | 5 | Circuit breakers |
| — | `lib.rs` | 1 | Crate root |
| **Total src** | | **~128 files** | |
| Tests | `tests/` | ~30 files | |
| Benchmarks | `benches/` | 4 files | |
| **Grand Total** | | **~162 files** | |

---

## Key Differences from Current State

| Area | Current (70%) | Target (100%) |
|------|--------------|---------------|
| Evidence collection | Passive (pre-populated) | Active (queries drift.db per evidence type) |
| Memory storage | `bridge_memories` table | Through `IMemoryStorage::create()` |
| CausalEngine usage | 3 of 8 operations | All 8 operations |
| Event enrichment | None (just pattern_id) | Full drift.db query at event time |
| Weight decay | None | 365-day half-life |
| Prior feedback | Creates new memory | Updates original prior confidence |
| Decomposition queries | `LIKE '%boundary%'` | DNA similarity computation |
| Idempotency | None | Content-hash dedup |
| Metrics | Plumbed but empty | Full counters + gauges + histograms |
| Tracing | Ad-hoc `info!`/`warn!` | Structured `#[instrument]` spans |
| Circuit breakers | None | Per-subsystem with state machine |
| MCP tools | 3 tools | 7 tools (+ counterfactual, intervention, status, report) |
| NAPI functions | 15 functions | 20 functions |
| Config | License-tier only | Per-event toggles + evidence weight overrides |
| Health checks | `is_available()` bool | Per-subsystem degradation tracking |
| Schema migrations | None | Versioned v1→v2→v3 with rollback |
| CortexEventHandler | Not implemented | Bidirectional event flow |
| `on_scan_complete` | Logs only | Actually triggers grounding loop |
| Spec types | Missing 7 fields | Full spec compliance |

---

## Research Verification — Architectural Choices Audited

> Every choice below was researched against primary sources (SQLite docs, crate docs,
> industry patterns, benchmarks). Corrections to the blueprint above are noted inline.

### 1. Circuit Breaker for SQLite — ⚠️ REVISED: Replace with Error Budget + Degradation Tracker

**Original choice**: Per-subsystem circuit breakers (Closed→Open→HalfOpen) for cortex_db, drift_db, causal_engine.

**Research findings**:
- Circuit breakers are designed for **network services** where the remote endpoint needs time to recover
  (Microsoft Azure Architecture Center, Martin Fowler's Release It!).
- SQLite is an **embedded database** — it doesn't "go down" like a network service. Failures are typically:
  (a) file locked (transient, resolves in milliseconds with `busy_timeout`),
  (b) disk full (persistent, no amount of waiting helps),
  (c) file corrupted (permanent, requires recovery).
- The ElizaOS project (github.com/elizaOS/eliza#712) added circuit breakers for database operations,
  but their use case is cloud-hosted databases, not local SQLite files.
- The resilience4j community (github.com/resilience4j#2071) notes circuit breakers for DBMS are
  "protecting the DB from overload" — irrelevant for embedded SQLite where the DB is in-process.

**Correction**: Replace `resilience/circuit_breaker.rs` with:
```
resilience/
├── mod.rs
├── error_budget.rs          # Track consecutive errors per subsystem. After N errors,
│                            # mark subsystem as degraded (not "tripped" — no cooldown timer).
│                            # Re-check on next access attempt (SQLite recovers instantly
│                            # once the cause is removed, unlike network services).
├── retry.rs                 # Keep: exponential backoff for SQLITE_BUSY (busy_timeout covers
│                            # most cases, but bridge should also retry on SQLITE_BUSY at the
│                            # application level for long transactions). Max 3 attempts.
├── fallback.rs              # Keep: typed fallback strategies per operation.
├── recovery.rs              # Keep: corruption detection + rebuild.
└── busy_timeout.rs          # NEW: ensure PRAGMA busy_timeout = 5000 on every connection
                             # (per drift-core's pattern in workspace/migration.rs).
                             # This is the PRIMARY concurrency mechanism for SQLite.
```

**Why**: `PRAGMA busy_timeout = 5000` is the correct SQLite-native solution for lock contention.
Circuit breaker timers (30s cooldown, half-open state) are meaningless for an in-process database —
if the file is accessible, it works immediately; if it's not, no timeout will fix it.

---

### 2. SQLite ATTACH Under Concurrent Access — ⚠️ CRITICAL FINDING

**Research findings** (sqlite.org/lang_attach.html, sqlite.org/wal.html, SO#39149065):

- **ATTACH is per-connection, not per-database**. Each connection can ATTACH up to 10 databases
  (SQLITE_LIMIT_ATTACHED default). Attaching drift.db to a bridge connection is fine.
- **WAL + ATTACH atomicity caveat**: "Transactions involving multiple attached databases are atomic,
  assuming that the main database is not ':memory:' and the journal_mode is not WAL. If the
  journal_mode is WAL, then transactions continue to be atomic **within each individual database
  file**." (sqlite.org/lang_attach.html)
  - This means: a cross-DB query that reads from drift.db and writes to bridge.db is **NOT atomic**
    across both files in WAL mode. If the process crashes mid-transaction, one file may have the
    changes and the other may not.
- **Concurrent ATTACH from multiple threads**: Each thread needs its own connection. ATTACH on
  connection A does not affect connection B. This is safe as long as each thread has its own
  connection (which rusqlite enforces via `Send` but not `Sync`).
- **WAL allows concurrent readers + one writer** per database file, but the **writer lock spans
  all attached databases on that connection** (tenthousandmeters.com).

**Correction to `query/attach.rs`**:
```rust
// IMPORTANT: Cross-DB writes are NOT atomic in WAL mode.
// Pattern: ATTACH drift.db READ-ONLY, execute read query, DETACH.
// Never write to drift.db from the bridge (D6 compliance).
// For bridge writes that depend on drift.db reads:
//   1. Read from drift.db (via ATTACH)
//   2. DETACH drift.db
//   3. Write to bridge.db/cortex.db in a separate transaction
// This avoids cross-DB atomicity issues entirely.
```

Also add to `storage/connection_pool.rs`:
- Every connection must set `PRAGMA busy_timeout = 5000` immediately after opening
  (matching drift-core's `initialize_workspace_db` pattern)
- Every connection must set `PRAGMA journal_mode = WAL` for read concurrency
- Use `rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY` for drift.db connections

---

### 3. Content-Hash Deduplication — ✅ CONFIRMED, with refinement

**Research findings** (architecture-weekly.com, Kafka idempotency patterns):

- Content-hash deduplication is a standard consumer-side dedup pattern. The approach:
  hash the event payload → check if hash exists in a seen-set → skip if exists.
- **Trade-offs identified**:
  - TTL is needed on the dedup cache — without it, the cache grows unbounded.
  - blake3 is an excellent choice (already a dependency, ~1GB/s throughput, 256-bit output).
  - For this bridge, events come from synchronous `DriftEventHandler` calls (not a message queue),
    so the dedup window is the same process lifetime. No need for persistent dedup across restarts.

**Refinement to `event_mapping/dedup.rs`**:
```rust
// Use an in-memory HashMap<[u8; 32], Instant> with TTL eviction.
// blake3 hash of (event_type + entity_id + key fields).
// TTL: 60 seconds (events within the same scan are deduped; across scans are not).
// No need for persistent dedup — events from different scans are legitimately different
// even if the content looks the same (the scan context changed).
// Capacity: cap at 10,000 entries with LRU eviction.
```

---

### 4. 365-Day Half-Life Decay — ✅ CONFIRMED

**Research findings** (exponential decay mathematics):

- Half-life decay formula: `current_weight = static_default + (stored_weight - static_default) × 0.5^(elapsed_days / 365)`
- This means after 365 days, the adaptive adjustment is halved (decays toward static defaults).
  After 730 days, it's at 25% of the original adjustment. After ~2.5 years, it's negligible.
- This is the standard exponential decay formula used in:
  - Radioactive decay (physics)
  - ELO rating temporal decay (chess/gaming)
  - Memory consolidation models (psychology — Ebbinghaus forgetting curve)
  - Bayesian prior aging (statistics)

**No changes needed**. The formula in the blueprint is correct. Implementation note:
```rust
fn decay_weight(stored: f64, static_default: f64, elapsed_days: f64) -> f64 {
    let half_life = 365.0;
    let decay_factor = 0.5_f64.powf(elapsed_days / half_life);
    static_default + (stored - static_default) * decay_factor
}
```

---

### 5. #[instrument] Tracing Overhead — ⚠️ REVISED: Use Level Guards

**Research findings** (tokio-rs/tracing docs, fastrace benchmarks, r/rust discussions):

- `#[instrument]` with an active subscriber has **measurable overhead** (~100-500ns per span
  depending on the number of recorded fields). The fastrace team specifically designed their
  library because "tokio-rs/tracing's overhead can be substantial when instrumented."
- With **no subscriber registered**, tracing macros short-circuit early via an atomic load
  (~1-5ns), but `#[instrument]` still generates the wrapper function at compile time.
- For the grounding loop processing 500 memories × 10 evidence collectors = 5,000 spans,
  this adds 0.5-2.5ms of overhead per grounding run — acceptable.
- **However**: the fastrace blog notes libraries should use `cfg_attr` feature gates for
  tracing in hot paths to achieve true zero-cost.

**Correction to `tracing/spans.rs`**:
```rust
// Use #[instrument] freely on:
//   - Event handlers (called ≤21 times per scan — negligible)
//   - MCP tool handlers (called on-demand by user — negligible)
//   - Grounding loop top-level (called once per trigger — negligible)
//
// Use level-guarded tracing (not #[instrument]) on:
//   - Individual evidence collectors (called 500×10 = 5000 times per grounding run)
//   - Memory builder helpers (called per-event, could be bursty)
//   - Score computation inner loops
//
// Pattern for hot paths:
//   if tracing::enabled!(tracing::Level::DEBUG) {
//       tracing::debug!(evidence_type = ?et, drift_value = dv, "collected evidence");
//   }
// This avoids span creation overhead while still allowing debug visibility.
```

---

### 6. Schema Migration: `rusqlite_migration` vs `refinery` — ✅ REVISED: Use `PRAGMA user_version` (match drift-core)

**Research findings**:

- **`rusqlite_migration`** (cljoly/rusqlite_migration): Uses `PRAGMA user_version` for tracking,
  no extra tables, fast compilation, no macros. 29 releases, well-maintained.
- **`refinery`** (rust-db/refinery): More powerful (supports multiple DBs, CLI, file-based
  migrations), but creates a `refinery_schema_history` table and uses proc macros.
  907 dependents, 81 contributors.
- **drift-core's own pattern** (`workspace/migration.rs`): Uses `PRAGMA user_version` directly
  with hand-written migration SQL. No external dependency.

**Correction**: Don't add either library. **Match drift-core's existing pattern**:
```rust
// storage/migrations.rs — follows drift-core's workspace/migration.rs pattern exactly
//
// Uses PRAGMA user_version for version tracking (no extra tables).
// Each version bump is a const SQL string.
// Migration history recorded in bridge_event_log (reuse existing table).
//
// This avoids adding a new dependency and keeps the bridge consistent
// with how drift-core manages its own schema migrations.

const BRIDGE_SCHEMA_V1: &str = "..."; // Current 5 tables
const BRIDGE_SCHEMA_V2: &str = "..."; // Future additions

pub fn migrate(conn: &Connection) -> BridgeResult<()> {
    let current = get_bridge_schema_version(conn)?;
    match current {
        0 => { conn.execute_batch(BRIDGE_SCHEMA_V1)?; set_version(conn, 1)?; }
        1 => { conn.execute_batch(BRIDGE_SCHEMA_V2)?; set_version(conn, 2)?; }
        _ => {} // Already at latest
    }
    Ok(())
}
```

**Why**: Adding `rusqlite_migration` or `refinery` for 5 tables is over-engineering.
drift-core already has a proven pattern. Consistency > libraries.

---

### 7. Per-Evidence-Type Collector (Strategy Pattern) — ✅ CONFIRMED, with note

**Research findings** (Rust Design Patterns — Strategy pattern):

- Rust's strategy pattern can use either **trait objects** (`Box<dyn EvidenceCollector>`) or
  **enums** for dispatch. For 10 fixed evidence types, an **enum dispatch** is preferable:
  no heap allocation, no vtable indirection, and the types are known at compile time.
- The 10 separate files are justified by single responsibility — each collector has different
  SQL queries and different interpretation logic.

**Refinement**: Use enum dispatch instead of trait objects:
```rust
// grounding/evidence/collector.rs
pub enum EvidenceCollector {
    PatternConfidence,
    PatternOccurrence,
    FalsePositiveRate,
    ConstraintVerification,
    CouplingMetric,
    DnaHealth,
    TestCoverage,
    ErrorHandlingGaps,
    DecisionEvidence,
    BoundaryData,
}

impl EvidenceCollector {
    pub fn collect(&self, memory: &MemoryForGrounding, drift_db: &Connection)
        -> Option<GroundingEvidence>
    {
        match self {
            Self::PatternConfidence => pattern_confidence::collect(memory, drift_db),
            Self::PatternOccurrence => pattern_occurrence::collect(memory, drift_db),
            // ...
        }
    }
}
```

**Why**: Enum dispatch is ~2-3x faster than trait object dispatch for this use case,
and all 10 types are known at compile time (no runtime extensibility needed).

---

### 8. Writing Through `IMemoryStorage` — ✅ CONFIRMED, with caveat

**Concern**: Performance of going through a trait vs direct SQL.

**Finding**: `IMemoryStorage` is a trait with methods like `create(&self, memory: &BaseMemory)`.
The implementor is `SqliteMemoryStorage` which does... direct SQL. The trait adds one level of
dynamic dispatch (vtable lookup, ~1ns) per call. For the bridge creating ~20 memories per scan,
this is completely negligible.

**The real concern is architectural**: the bridge currently holds its own `rusqlite::Connection`
to cortex.db. To write through `IMemoryStorage`, it needs either:
(a) A reference to the Cortex storage instance (requires Cortex to be initialized and passed in), or
(b) Its own `SqliteMemoryStorage` instance pointing at the same cortex.db file.

Option (b) is safer — the bridge opens its own connection to cortex.db and wraps it in
`SqliteMemoryStorage`. Both connections can coexist in WAL mode (concurrent readers + one writer).
The bridge's writes go through the same schema/validation as Cortex's own writes.

**Caveat**: The bridge must set `PRAGMA busy_timeout = 5000` on its cortex.db connection
to handle lock contention with Cortex's own writes.

---

### 9. SQLite PRAGMAs — 🔴 MISSING FROM BRIDGE

**Critical finding**: drift-core sets 8 PRAGMAs on every connection (`workspace/migration.rs:97-109`):
```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;
PRAGMA cache_size = -8000;      -- 8MB cache
PRAGMA mmap_size = 268435456;   -- 256MB mmap
PRAGMA temp_store = MEMORY;
PRAGMA auto_vacuum = INCREMENTAL;
```

**The bridge sets ZERO PRAGMAs.** `BridgeRuntime::initialize()` opens connections with
`rusqlite::Connection::open()` defaults (rollback journal mode, 2MB cache, no busy timeout).
This means:
- No WAL → no concurrent readers during writes
- No busy_timeout → immediate SQLITE_BUSY errors under contention
- No mmap → slower reads for large tables

**Correction**: Add `storage/pragmas.rs` (not `connection_pool.rs` — that's over-engineering
for an embedded DB):
```rust
pub fn configure_connection(conn: &Connection) -> BridgeResult<()> {
    conn.execute_batch("
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA foreign_keys = ON;
        PRAGMA busy_timeout = 5000;
        PRAGMA cache_size = -8000;
        PRAGMA mmap_size = 268435456;
        PRAGMA temp_store = MEMORY;
    ")?;
    Ok(())
}
```
Call this in `BridgeRuntime::initialize()` for every opened connection.

---

### Summary of Blueprint Corrections

| # | Original Choice | Verdict | Correction |
|---|----------------|---------|------------|
| 1 | Circuit breakers (Closed→Open→HalfOpen) | ❌ Wrong pattern for SQLite | Replace with error budget + degradation tracker. Use `busy_timeout` for contention. |
| 2 | ATTACH for cross-DB queries | ⚠️ Works, but atomicity caveat | Document non-atomic cross-DB writes in WAL mode. Read-then-DETACH-then-write pattern. |
| 3 | blake3 content-hash dedup | ✅ Correct | Add TTL (60s), cap at 10K entries, in-memory only (not persistent). |
| 4 | 365-day half-life decay | ✅ Correct | Standard exponential decay. No changes. |
| 5 | `#[instrument]` everywhere | ⚠️ Overhead in hot paths | Use `#[instrument]` for handlers/tools, level-guarded `debug!` for evidence collectors. |
| 6 | `rusqlite_migration` or `refinery` | ❌ Unnecessary dependency | Use `PRAGMA user_version` directly, matching drift-core's pattern. |
| 7 | Trait object collectors | ⚠️ Slight overhead | Use enum dispatch instead (all 10 types known at compile time). |
| 8 | Write through `IMemoryStorage` | ✅ Correct | Bridge opens its own connection + wraps in `SqliteMemoryStorage`. |
| 9 | SQLite PRAGMAs | 🔴 Missing entirely | Add `configure_connection()` matching drift-core's 8 PRAGMAs. |
| 10 | `connection_pool.rs` | ❌ Over-engineering | Replace with `pragmas.rs`. SQLite doesn't need connection pooling for an embedded use case — one connection per database is sufficient with `Mutex<Connection>`. |
| Corruption recovery | None | Orphan detection, dangling edge cleanup, table rebuild |
