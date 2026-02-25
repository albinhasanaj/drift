# Feature 2: Temporal Reasoning & Memory Time-Travel

> Status: Research Phase
> Priority: #2 (builds on existing bitemporal infrastructure)
> Estimated New Crates: 1 (cortex-temporal)
> Dependencies: cortex-core, cortex-storage, cortex-causal, cortex-validation

## The Problem

Cortex already tracks `transaction_time` (when we learned it) and `valid_time` (when it
was true), plus full version history. But there's no query-time temporal reasoning engine.

We can answer "what do we know now" but not:
- "What did we know at 3pm last Tuesday when we made that architecture decision?"
- "How has our understanding of the auth module evolved over the last 3 sprints?"
- "If we replay the context from when Decision X was made, was it the right call?"

## What This Enables

- Point-in-time knowledge reconstruction
- Decision replay and audit
- Knowledge drift detection over time
- Temporal causal queries ("at the time we adopted X, what was the chain?")
- Sprint-over-sprint knowledge health dashboards

## Research Documents

| File | Topic |
|------|-------|
| [01-BITEMPORAL-THEORY.md](./01-BITEMPORAL-THEORY.md) | Bitemporal database theory and XTDB patterns |
| [02-EVENT-SOURCING.md](./02-EVENT-SOURCING.md) | Event sourcing for knowledge state reconstruction |
| [03-TEMPORAL-QUERIES.md](./03-TEMPORAL-QUERIES.md) | Query algebra for temporal memory operations |
| [04-DRIFT-DETECTION.md](./04-DRIFT-DETECTION.md) | Knowledge drift and evolution tracking |
| [05-CORTEX-MAPPING.md](./05-CORTEX-MAPPING.md) | How this maps to existing Cortex architecture |
