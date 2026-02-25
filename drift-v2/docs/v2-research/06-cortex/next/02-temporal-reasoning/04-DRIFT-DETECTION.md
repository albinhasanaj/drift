# Knowledge Drift & Evolution Tracking

## What is Knowledge Drift?

Knowledge drift is the phenomenon where a team's understanding of their system changes
over time — patterns emerge, conventions shift, tribal knowledge evolves, and old
assumptions become invalid. Tracking this drift is critical for:

1. **Health monitoring**: Is knowledge stabilizing or churning?
2. **Onboarding**: Show new team members how understanding evolved
3. **Decision quality**: Were past decisions made with good or bad information?
4. **Proactive maintenance**: Detect when knowledge is going stale before it causes bugs

---

## Drift Metrics

### 1. Knowledge Stability Index (KSI)

Measures how stable the knowledge base is over a time window.

```
KSI(window) = 1 - (created + archived + modified) / (2 × total_at_start)
```

- KSI = 1.0: perfectly stable, nothing changed
- KSI = 0.5: moderate churn, half the knowledge base changed
- KSI < 0.3: high churn, knowledge is unstable

Track KSI per memory type to identify which categories are churning:
- Episodic KSI is naturally low (episodes are transient)
- Core KSI should be high (core knowledge is stable)
- Tribal KSI dropping = team norms are shifting (worth investigating)

### 2. Confidence Trajectory

Track average confidence over time, per memory type:

```
confidence_trajectory(type, window) = [
    avg_confidence(type, t0),
    avg_confidence(type, t1),
    ...
    avg_confidence(type, tn),
]
```

Trends:
- Rising confidence = knowledge is being validated and reinforced
- Falling confidence = knowledge is decaying or being contradicted
- Flat confidence = stable but possibly stagnant

### 3. Contradiction Density

```
contradiction_density(window) = new_contradictions / total_memories
```

- Low density (<0.02): healthy, few conflicts
- Medium density (0.02-0.10): some disagreement, worth monitoring
- High density (>0.10): knowledge base is internally inconsistent, needs attention

### 4. Consolidation Efficiency

```
consolidation_efficiency(window) = semantic_created / episodic_archived
```

- Ratio > 0.5: good, most episodes are being consolidated into lasting knowledge
- Ratio < 0.2: poor, episodes are being archived without extracting value
- Ratio > 1.0: excellent, consolidation is creating more knowledge than it consumes

### 5. Knowledge Coverage Ratio

```
coverage(module) = memories_linked_to(module) / code_complexity(module)
```

Where code_complexity can be lines of code, cyclomatic complexity, or file count.

- High coverage: well-understood module
- Low coverage: knowledge gap, potential risk area
- Declining coverage: knowledge is decaying faster than it's being created

---

## Evolution Patterns

### Pattern 1: Knowledge Crystallization

Episodic memories about a topic accumulate → consolidation creates semantic memories →
semantic memories get validated → confidence rises → knowledge "crystallizes" into
stable, high-confidence understanding.

Detection: Track the lifecycle of knowledge clusters. Healthy clusters show:
episodic → semantic → validated → stable confidence.

### Pattern 2: Knowledge Erosion

A once-stable area of knowledge starts losing confidence. Citations go stale, patterns
are no longer followed, tribal knowledge contradicts new practices.

Detection: Confidence trajectory turns negative for a cluster of related memories.
Alert: "Knowledge about [auth module] has been eroding for 3 weeks."

### Pattern 3: Knowledge Explosion

A new area of the codebase suddenly generates many memories — new feature development,
major refactor, or incident response.

Detection: Memory creation rate for a file/module exceeds 3σ above the rolling average.
Opportunity: Proactively consolidate to prevent knowledge fragmentation.

### Pattern 4: Knowledge Conflict Wave

A change in convention or architecture creates a wave of contradictions as old knowledge
conflicts with new practices.

Detection: Contradiction density spikes, concentrated in a specific memory type or
file cluster.
Action: Trigger targeted validation + consolidation for the affected area.

---

## Time-Series Storage

### Metric Snapshots

Store drift metrics at regular intervals for trend analysis:

```rust
struct DriftSnapshot {
    timestamp: DateTime<Utc>,
    window: Duration,
    /// Per-type metrics
    type_metrics: HashMap<MemoryType, TypeDriftMetrics>,
    /// Per-module metrics
    module_metrics: HashMap<String, ModuleDriftMetrics>,
    /// Global metrics
    global: GlobalDriftMetrics,
}

struct TypeDriftMetrics {
    count: usize,
    avg_confidence: f64,
    ksi: f64,
    contradiction_density: f64,
    consolidation_efficiency: f64,
}

struct ModuleDriftMetrics {
    memory_count: usize,
    coverage_ratio: f64,
    avg_confidence: f64,
    churn_rate: f64,
}

struct GlobalDriftMetrics {
    total_memories: usize,
    active_memories: usize,
    archived_memories: usize,
    avg_confidence: f64,
    overall_ksi: f64,
    overall_contradiction_density: f64,
}
```

### Snapshot Frequency

- Hourly: lightweight counters only (memory count, avg confidence)
- Daily: full drift metrics per type and module
- Weekly: comprehensive snapshot with trend analysis
- Sprint boundary: materialized temporal view (pre-computed for fast queries)

---

## Alerting Rules

```rust
struct DriftAlert {
    severity: AlertSeverity,
    category: DriftAlertCategory,
    message: String,
    affected_memories: Vec<MemoryId>,
    recommended_action: String,
}

enum DriftAlertCategory {
    /// KSI dropped below threshold for a memory type
    KnowledgeChurn { memory_type: MemoryType, ksi: f64 },
    /// Confidence trajectory turned negative
    ConfidenceErosion { memory_type: MemoryType, trend: f64 },
    /// Contradiction density exceeded threshold
    ContradictionSpike { density: f64 },
    /// Knowledge coverage dropped for a module
    CoverageGap { module: String, coverage: f64 },
    /// Memory creation rate anomaly
    CreationAnomaly { module: String, rate: f64, baseline: f64 },
}
```

These alerts feed into our existing observability engine (cortex-observability) and
surface through the health report and MCP tools.
