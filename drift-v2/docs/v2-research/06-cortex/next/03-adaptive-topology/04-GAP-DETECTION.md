# Knowledge Gap Detection & Coverage Analysis

## The Problem

A knowledge base can be large but still have critical gaps. If the auth module has 89
memories but the payments module (which handles real money) has only 12, that's a risk.
Gap detection identifies areas where knowledge is sparse relative to code complexity.

---

## Knowledge Completeness Model

### Coverage Ratio

The simplest gap metric: memories per unit of code complexity.

```
coverage(module) = memories_linked_to(module) / complexity(module)
```

Where complexity can be:
- **Lines of code**: Simple, widely available
- **File count**: Proxy for surface area
- **Cyclomatic complexity**: Better measure of logical complexity
- **Dependency count**: How many other modules depend on this one (impact factor)

### Expected Coverage by Memory Type

Not all memory types are equally expected for all modules:

| Memory Type | Expected For | Coverage Threshold |
|---|---|---|
| PatternRationale | Modules with >500 LOC | ≥1 per 500 LOC |
| Tribal | Modules with team conventions | ≥1 per module |
| Procedural | Modules with deployment/setup | ≥1 per deployable |
| Decision | Modules with architecture choices | ≥1 per major choice |
| CodeSmell | Modules with known tech debt | ≥1 per known issue |
| Constraint | Modules with external requirements | ≥1 per constraint |

### Gap Score

```rust
struct KnowledgeGap {
    /// The module/file/directory with the gap
    target: String,
    /// Code complexity of the target
    complexity: f64,
    /// Current memory count
    memory_count: usize,
    /// Expected memory count based on complexity
    expected_count: usize,
    /// Gap severity (0.0 = fully covered, 1.0 = completely uncovered)
    severity: f64,
    /// Which memory types are missing
    missing_types: Vec<MemoryType>,
    /// Risk assessment
    risk: GapRisk,
    /// Suggested actions
    suggestions: Vec<String>,
}

enum GapRisk {
    /// Low complexity, few dependencies — gap is acceptable
    Low,
    /// Medium complexity or some dependencies — should be addressed
    Medium,
    /// High complexity, many dependencies, or critical path — urgent
    High,
    /// Security-sensitive or payment-related — critical
    Critical,
}
```

---

## Graph-Based Gap Detection

Beyond simple coverage ratios, we can detect gaps from the graph structure itself.

### Structural Holes

A structural hole is a gap between two densely connected communities with few bridges.
In knowledge terms: two well-understood areas with poor understanding of how they
interact.

Detection: Find pairs of communities with high internal density but low inter-community
edge count.

```rust
struct StructuralHole {
    community_a: CommunityId,
    community_b: CommunityId,
    /// How many edges connect A and B
    bridge_count: usize,
    /// Expected bridges based on community sizes
    expected_bridges: usize,
    /// Gap severity
    severity: f64,
    /// What kind of knowledge is missing
    missing_knowledge: String, // "How auth interacts with payments"
}
```

### Orphan Detection

Memories that are isolated (no relationships, no links, no causal edges) are either:
1. Newly created (not yet integrated) — normal
2. Poorly linked (should have connections but doesn't) — gap
3. Truly standalone (valid isolation) — rare

```rust
fn detect_orphans(memories: &[BaseMemory], graph: &CausalGraph) -> Vec<OrphanMemory> {
    memories.iter()
        .filter(|m| {
            let has_relationships = graph.has_edges(m.id);
            let has_links = !m.linked_patterns.is_empty()
                || !m.linked_files.is_empty()
                || !m.linked_functions.is_empty();
            let age = Utc::now() - m.transaction_time;
            
            // Orphan if: no connections AND older than 7 days
            !has_relationships && !has_links && age > Duration::days(7)
        })
        .map(|m| OrphanMemory {
            memory_id: m.id.clone(),
            age: Utc::now() - m.transaction_time,
            suggestion: suggest_links(m, memories, graph),
        })
        .collect()
}
```

### Knowledge Graph Completion

Research on Knowledge Graph Completion (KGC) provides methods for predicting missing
relationships in knowledge graphs. We can adapt these to predict missing memories.

Source: [Recent Advances in KGC](https://www.researchgate.net/publication/382035781) — 2024

For Cortex, a simpler approach:

1. For each file in the codebase, check if expected memory types exist
2. For each pattern, check if related constraints and tribal knowledge exist
3. For each decision, check if the causal chain is complete (what led to it, what it affects)
4. For each module, check if coverage meets the threshold for its complexity

---

## Attention Hotspot Tracking

Track which knowledge areas are being accessed most frequently to identify:
- **Hot spots**: Areas under active development (high access, high creation)
- **Cold spots**: Areas being neglected (low access, decaying confidence)
- **Conflict zones**: Areas with high contradiction density

### Hotspot Metrics

```rust
struct AttentionHotspot {
    /// The community/module this hotspot is about
    target: String,
    /// Access frequency (queries hitting this area per day)
    access_rate: f64,
    /// Creation rate (new memories per week)
    creation_rate: f64,
    /// Modification rate (updates per week)
    modification_rate: f64,
    /// Temperature (composite activity score)
    temperature: f64,
    /// Trend (heating up or cooling down)
    trend: TemperatureTrend,
}

enum TemperatureTrend {
    Heating { rate: f64 },   // activity increasing
    Stable,
    Cooling { rate: f64 },   // activity decreasing
}
```

### Temperature Calculation

```
temperature = 0.4 × normalized_access_rate
            + 0.3 × normalized_creation_rate
            + 0.2 × normalized_modification_rate
            + 0.1 × contradiction_density
```

Normalize each rate against the global average to get relative activity.

### Hotspot Map

Combine with the knowledge tree to create a heat map:

```
Backend (temp: 0.6, stable)
├── Auth (temp: 0.3, cooling) ← was hot last sprint, stabilizing
├── Payments (temp: 0.9, heating) ← active development!
├── API (temp: 0.5, stable)
└── Database (temp: 0.2, cooling) ← going cold, check for staleness
```

---

## Emergent Workflow Discovery

Track recurring patterns of memory creation to discover implicit workflows.

### Pattern Detection

When developers work on a feature, they typically create memories in a predictable order:
1. Decision memory ("we'll use approach X")
2. Pattern rationale ("the pattern for X is...")
3. Constraint ("X must satisfy Y")
4. Procedural ("to deploy X, do...")
5. Tribal ("when working on X, remember...")

If we detect this sequence recurring, we can:
1. Surface it as a discovered workflow template
2. Proactively prompt for missing steps ("you created a decision and pattern for the
   new API endpoint, but haven't added constraints or procedures yet")

```rust
struct DiscoveredWorkflow {
    /// Sequence of memory types typically created together
    type_sequence: Vec<MemoryType>,
    /// How many times this sequence has been observed
    occurrence_count: usize,
    /// Average time between steps
    avg_step_duration: Duration,
    /// Confidence that this is a real workflow
    confidence: f64,
    /// Associated file patterns
    file_patterns: Vec<String>,
}
```

### Workflow Suggestion

When a developer starts a sequence that matches a known workflow:

```
"You've created a Decision and PatternRationale for the new payment endpoint.
 Based on past patterns, you typically also create:
 - ConstraintOverride (usually within 2 hours)
 - Procedural memory for deployment (usually within 1 day)
 - Tribal knowledge note (usually within 3 days)
 
 Would you like to create any of these now?"
```

This is proactive knowledge gap filling based on observed behavior.
