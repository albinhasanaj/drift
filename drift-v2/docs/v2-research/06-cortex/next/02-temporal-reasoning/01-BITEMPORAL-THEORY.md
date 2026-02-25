# Bitemporal Database Theory

## Two Dimensions of Time

Every fact in a knowledge system has two independent time dimensions:

### Valid Time (VT)
"When was this true in the real world?"
- A pattern was adopted on March 1st
- A constraint was valid from Sprint 12 to Sprint 15
- A tribal rule has always been true (valid_time = epoch, valid_until = ∞)

### Transaction Time (TT)
"When did the system learn about this?"
- We recorded the pattern adoption on March 3rd (2 days after it happened)
- We discovered the constraint was removed on April 1st (but it was actually removed March 28th)

### The Four Temporal States

Any fact exists in one of four states relative to a query time:

```
                    Valid Time
                Past    |    Future
           ┌────────────┼────────────┐
    Past   │  Known     │  Predicted │
Trans.     │  history   │  (was      │
Time       │            │  expected) │
           ├────────────┼────────────┤
    Future │  Late      │  Unknown   │
           │  discovery │  future    │
           │  (backfill)│            │
           └────────────┴────────────┘
```

Source: [XTDB Bitemporality Docs](https://v1-docs.xtdb.com/concepts/bitemporality/)

---

## XTDB: The Gold Standard

XTDB (formerly Crux) is a bitemporal database that tracks both system_time and valid_time
automatically. All tables are bitemporal by default — no triggers, no history tables.

Key design principles from XTDB (rephrased for compliance):

1. Every record has four temporal bounds: valid_from, valid_to, system_from, system_to
2. Point-in-time queries specify both a system_time and valid_time
3. The database reconstructs the exact state visible at that (system_time, valid_time) pair
4. Transaction time is immutable — you can never change when you learned something
5. Valid time is mutable — you can correct when something was actually true

Source: [XTDB v2 Launch](https://www.xtdb.com/blog/launching-xtdb-v2)

---

## Bitemporal Patterns for Cortex

### Pattern 1: Temporal Referential Integrity

When querying memories at a past point in time, all references must also resolve at that
same point in time. If Memory A references Pattern B, and we query at time T, both A and
B must have been valid at time T.

This prevents temporal anomalies like: "At time T, Memory A referenced Pattern B, but
Pattern B didn't exist yet at time T."

Source: [Bitemporal Consistency Patterns](https://softwarepatternslexicon.com/bitemporal-modeling/bi-temporal-consistency-patterns/temporal-referential-integrity/)

### Pattern 2: Temporal Joins

When retrieving related memories at a past point in time, the join condition must include
temporal overlap. Two memories are "related at time T" only if both were valid at T and
both were known at T.

```sql
-- Pseudo-SQL for temporal join
SELECT m1.*, m2.*
FROM memories m1
JOIN memories m2 ON m1.related_to = m2.id
WHERE m1.valid_from <= @query_valid_time
  AND m1.valid_until > @query_valid_time
  AND m1.transaction_time <= @query_system_time
  AND m2.valid_from <= @query_valid_time
  AND m2.valid_until > @query_valid_time
  AND m2.transaction_time <= @query_system_time
```

### Pattern 3: Bitemporal Correction

When we discover that a fact was wrong, we don't delete the old record. We:
1. Close the old record's system_to (it's no longer the current version)
2. Create a new record with the corrected valid_time range
3. The old record remains queryable at its original system_time

This is exactly what our versioning system (cortex-storage/versioning/) already does,
but we need to make it queryable through a temporal API.

---

## Cortex's Existing Bitemporal Fields

Our `BaseMemory` already has:
- `transaction_time: DateTime<Utc>` — when the memory was created in the system
- `valid_time: DateTime<Utc>` — when the fact became true
- `valid_until: Option<DateTime<Utc>>` — when the fact stopped being true

And our versioning system stores:
- Full content snapshots on every update
- Version timestamps
- Change reasons

What's missing:
- A query engine that can reconstruct state at arbitrary (system_time, valid_time) pairs
- Temporal join logic for relationships and causal graphs
- A diff engine for comparing knowledge states across time
- Temporal aggregation (knowledge health metrics over time windows)
