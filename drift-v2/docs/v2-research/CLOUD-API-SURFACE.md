# Drift Cloud API Surface

> **Date:** Feb 12, 2026
> **Purpose:** Document all queryable PostgREST endpoints for the frontend dashboard team.
> **Auth:** All requests require `Authorization: Bearer <JWT>` + `apikey: <anon_key>` headers.
> **RLS:** Every table enforces `tenant_id = current_setting('app.tenant_id', true)::UUID`. Users only see their own data.

---

## Base URL

```
https://<project-ref>.supabase.co/rest/v1/
```

---

## Tier 1 — Dashboard Essentials (42 tables)

### Scan & Files

| Endpoint | Local Source | Key Columns |
|---|---|---|
| `GET /cloud_scan_history` | drift.db `scan_history` | local_id, root_path, total_files, changed_files, duration_ms, scan_mode |
| `GET /cloud_file_stats` | drift.db `file_metadata` | local_id, file_path, language, size_bytes, line_count, function_count |
| `GET /cloud_functions` | drift.db `functions` | local_id, file_path, name, language, start_line, end_line, complexity |

### Analysis & Patterns

| Endpoint | Local Source | Key Columns |
|---|---|---|
| `GET /cloud_call_edges` | drift.db `call_edges` | caller_id, callee_id, call_site_file, call_site_line, edge_type |
| `GET /cloud_data_access` | drift.db `data_access` | function_id, table_name, operation, file, line |
| `GET /cloud_detections` | drift.db `detections` | local_id, rule, file, line, severity, category |
| `GET /cloud_boundaries` | drift.db `boundaries` | local_id, boundary_type, name, file, confidence |
| `GET /cloud_pattern_confidence` | drift.db `pattern_confidence` | local_id, pattern_name, confidence, sample_count |
| `GET /cloud_outliers` | drift.db `outliers` | local_id, file, metric, value, deviation_score |
| `GET /cloud_conventions` | drift.db `conventions` | local_id, convention_name, language, pattern, compliance_rate |

### Graph Intelligence

| Endpoint | Local Source | Key Columns |
|---|---|---|
| `GET /cloud_taint_flows` | drift.db `taint_flows` | local_id, source_file, source_line, sink_file, sink_line, taint_type |
| `GET /cloud_error_gaps` | drift.db `error_gaps` | local_id, file, function_name, gap_type, severity |
| `GET /cloud_impact_scores` | drift.db `impact_scores` | local_id, function_id, score, dependents_count |
| `GET /cloud_test_coverage` | drift.db `test_coverage` | test_function_id, source_function_id, coverage_type |
| `GET /cloud_test_quality` | drift.db `test_quality` | local_id, test_file, quality_score, assertion_count |

### Structural Intelligence

| Endpoint | Local Source | Key Columns |
|---|---|---|
| `GET /cloud_coupling_metrics` | drift.db `coupling_metrics` | local_id, module_a, module_b, coupling_score, zone |
| `GET /cloud_coupling_cycles` | drift.db `coupling_cycles` | local_id, cycle_modules, cycle_length |
| `GET /cloud_constraints` | drift.db `constraints` | local_id, constraint_type, name, expression |
| `GET /cloud_constraint_results` | drift.db `constraint_verifications` | local_id, constraint_id, passed, checked_at |
| `GET /cloud_contracts` | drift.db `contracts` | local_id, endpoint, method, paradigm, confidence |
| `GET /cloud_contract_mismatches` | drift.db `contract_mismatches` | local_id, contract_id, mismatch_type, field |
| `GET /cloud_constants` | drift.db `constants` | local_id, name, value, file, line |
| `GET /cloud_secrets` | drift.db `secrets` | local_id, secret_type, file, line (**value is [REDACTED]**) |
| `GET /cloud_env_variables` | drift.db `env_variables` | local_id, name, file, line |
| `GET /cloud_wrappers` | drift.db `wrappers` | local_id, wrapper_type, name, file |
| `GET /cloud_dna_genes` | drift.db `dna_genes` | local_id, gene_type, name, expression |
| `GET /cloud_dna_mutations` | drift.db `dna_mutations` | local_id, gene_id, mutation_type, file |
| `GET /cloud_crypto_findings` | drift.db `crypto_findings` | local_id, finding_type, algorithm, file, severity |
| `GET /cloud_owasp_findings` | drift.db `owasp_findings` | local_id, owasp_id, cwe_id, file, severity |
| `GET /cloud_decomposition_decisions` | drift.db `decomposition_decisions` | local_id, decision_type, module, rationale |

### Enforcement

| Endpoint | Local Source | Key Columns |
|---|---|---|
| `GET /cloud_violations` | drift.db `violations` | local_id, rule, file, line, severity, message |
| `GET /cloud_gate_results` | drift.db `gate_results` | local_id, gate_id, passed, score |
| `GET /cloud_audit_snapshots` | drift.db `audit_snapshots` | local_id, total_violations, gates_passed, health_score |
| `GET /cloud_health_trends` | drift.db `health_trends` | local_id, metric_name, metric_value, recorded_at |
| `GET /cloud_feedback` | drift.db `feedback` | local_id, violation_id, action, reason |
| `GET /cloud_policy_results` | drift.db `policy_results` | local_id, policy_name, passed, details |
| `GET /cloud_degradation_alerts` | drift.db `degradation_alerts` | local_id, component, failure, fallback_used |

### Bridge

| Endpoint | Local Source | Key Columns |
|---|---|---|
| `GET /cloud_bridge_memories` | bridge.db `bridge_memories` | local_id, memory_type, content, summary, confidence, tags |
| `GET /cloud_grounding_results` | bridge.db `bridge_grounding_results` | local_id, memory_id, grounding_score, classification |
| `GET /cloud_grounding_snapshots` | bridge.db `bridge_grounding_snapshots` | local_id, total_memories, grounded_count, avg_score |
| `GET /cloud_bridge_events` | bridge.db `bridge_event_log` | local_id, event_type, memory_type, confidence |
| `GET /cloud_bridge_metrics` | bridge.db `bridge_metrics` | local_id, metric_name, metric_value |

---

## Tier 2 — Complete Cortex (19 tables)

### Core Memory System (16 from cortex.db)

| Endpoint | Local Source |
|---|---|
| `GET /cloud_memories` | `memories` |
| `GET /cloud_memory_relationships` | `memory_relationships` |
| `GET /cloud_memory_patterns` | `memory_patterns` |
| `GET /cloud_memory_constraints` | `memory_constraints` |
| `GET /cloud_memory_files` | `memory_files` |
| `GET /cloud_memory_functions` | `memory_functions` |
| `GET /cloud_causal_edges` | `causal_edges` |
| `GET /cloud_causal_evidence` | `causal_evidence` |
| `GET /cloud_memory_audit_log` | `memory_audit_log` |
| `GET /cloud_consolidation_metrics` | `consolidation_metrics` |
| `GET /cloud_cortex_degradation_log` | `degradation_log` |
| `GET /cloud_memory_validation` | `memory_validation_history` |
| `GET /cloud_memory_contradictions` | `memory_contradictions` |
| `GET /cloud_memory_versions` | `memory_versions` |
| `GET /cloud_memory_events` | `memory_events` |
| `GET /cloud_memory_snapshots` | `memory_snapshots` |

### Advanced (3 from drift.db)

| Endpoint | Local Source |
|---|---|
| `GET /cloud_simulations` | `simulations` |
| `GET /cloud_decisions` | `decisions` |
| `GET /cloud_embedding_models` | `embedding_model_info` |

---

## Tier 3 — Future Features (12 tables)

### Multi-Agent (6 from cortex.db)

| Endpoint | Local Source |
|---|---|
| `GET /cloud_agent_registry` | `agent_registry` |
| `GET /cloud_memory_namespaces` | `memory_namespaces` |
| `GET /cloud_namespace_permissions` | `namespace_permissions` |
| `GET /cloud_memory_projections` | `memory_projections` |
| `GET /cloud_provenance_log` | `provenance_log` |
| `GET /cloud_agent_trust` | `agent_trust` |

### Temporal & Reclassification (3 from cortex.db)

| Endpoint | Local Source |
|---|---|
| `GET /cloud_reclassification_history` | `reclassification_history` |
| `GET /cloud_reclassification_signals` | `reclassification_signals` |
| `GET /cloud_drift_snapshots` | `drift_snapshots` |

### Migration Tracking (3 from drift.db)

| Endpoint | Local Source |
|---|---|
| `GET /cloud_migration_projects` | `migration_projects` |
| `GET /cloud_migration_modules` | `migration_modules` |
| `GET /cloud_migration_corrections` | `migration_corrections` |

---

## Dashboard Views (4 aggregate views)

These are Postgres views that aggregate data for common dashboard queries.

| Endpoint | Purpose | Key Columns |
|---|---|---|
| `GET /v_project_health` | Per-project health overview | project_id, violation_count, gates_passed, gates_total, pass_rate, avg_confidence, avg_dna_health |
| `GET /v_trend_violations` | Daily violation count over 30 days | project_id, day, violation_count |
| `GET /v_top_violations` | Most frequent violation rules | project_id, rule, severity, occurrence_count |
| `GET /v_security_posture` | Security metrics overview | project_id, owasp_count, crypto_count, taint_flow_count, secret_count |

---

## Common Query Patterns

### Recent violations (paginated)
```
GET /cloud_violations?select=*&order=created_at.desc&limit=50&offset=0
```

### Failed gates only
```
GET /cloud_gate_results?select=*&passed=eq.false&order=created_at.desc
```

### Coupling zone of pain
```
GET /cloud_coupling_metrics?select=*&zone=eq.zone_of_pain&order=coupling_score.desc
```

### Project health dashboard
```
GET /v_project_health?project_id=eq.<uuid>
```

### Violation trend (last 30 days)
```
GET /v_trend_violations?project_id=eq.<uuid>&order=day.asc
```

### Security posture
```
GET /v_security_posture?project_id=eq.<uuid>
```

### Full-text search on violations
```
GET /cloud_violations?message=ilike.*authentication*&order=severity.desc
```

---

## Redaction Notes

The following fields are **always redacted** before sync:

| Category | Rule | Affected Tables |
|---|---|---|
| **File paths** | Stripped to project-relative | 17 tables (violations, detections, functions, etc.) |
| **Root paths** | Stripped entirely | scan_history |
| **Secret values** | Replaced with `[REDACTED]` | secrets, env_variables |
| **Source code** | Nulled out | detections (matched_text), dna_mutations (code), crypto_findings (code), owasp_findings (code) |
| **BLOBs** | Converted to hex digest | file_metadata (content_hash) |

---

## CLI Commands

| Command | Description |
|---|---|
| `drift cloud login --url <url> --anon-key <key> --email <email> --password <pwd>` | Authenticate |
| `drift cloud push` | Delta sync to cloud |
| `drift cloud push --full` | Full re-upload |
| `drift cloud status` | Show sync state |
| `drift cloud logout` | Clear credentials |
| `drift cortex cloud sync` | Cortex memory sync + data pipeline push |
| `drift cortex cloud status` | Combined cortex + pipeline status |

## MCP Tools

| Tool | Description |
|---|---|
| `drift_cloud_sync` | Trigger cortex sync + data pipeline push |
| `drift_cloud_status` | Get cortex + pipeline status |
| `drift_cloud_resolve` | Resolve cortex memory sync conflict |
| `cortex_cloud_sync` | Same as drift_cloud_sync (MCP server) |
| `cortex_cloud_status` | Same as drift_cloud_status (MCP server) |
