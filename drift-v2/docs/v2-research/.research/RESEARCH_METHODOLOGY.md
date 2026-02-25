# Research Methodology

> This document defines the scientific research process for improving each Drift category.

## Overview

Each category goes through a 4-phase research process:

```
Phase 1: COMPREHENSION    → Deep understanding of current implementation
Phase 2: RECAP            → Structured summary document
Phase 3: RESEARCH         → External best practices from trusted sources
Phase 4: RECOMMENDATIONS  → Documented improvements with citations
```

---

## Phase 1: Comprehension

**Goal**: Achieve complete understanding of the category's current implementation.

### Tasks
1. Read ALL files in the category directory
2. Identify the core purpose and responsibilities
3. Map the internal architecture (components, data flow, algorithms)
4. Document current capabilities and limitations
5. Note any existing v2 migration notes or TODOs

### Questions to Answer
- What problem does this category solve?
- What are the key algorithms/data structures?
- What are the inputs and outputs?
- What are the current limitations or known issues?
- How does it connect to other categories?

---

## Phase 2: Recap Document

**Goal**: Produce a structured summary that captures everything important.

### Document Structure

```markdown
# [Category Name] - Research Recap

## Executive Summary
[2-3 sentences: what this category does and why it matters]

## Current Implementation

### Architecture
[Component diagram or description]

### Key Algorithms
[List and briefly describe each algorithm]

### Data Models
[Key types/interfaces with field descriptions]

### Capabilities
[What it can do today]

### Limitations
[Known issues, gaps, performance concerns]

## Integration Points
[How it connects to other categories]

## V2 Migration Status
[What's in Rust vs TS, migration priority]

## Open Questions
[Anything unclear that needs clarification]
```

---

## Phase 3: External Research

**Goal**: Find verifiable best practices from trusted sources.

### Trusted Source Hierarchy

**Tier 1 - Authoritative** (highest trust)
- Official language/framework documentation
- Academic papers (peer-reviewed)
- RFCs and specifications
- OWASP, NIST, ISO standards (for security)

**Tier 2 - Industry Expert** (high trust)
- Books by recognized experts
- Conference talks (Strange Loop, QCon, etc.)
- Official blogs from major tech companies (Google, Microsoft, Meta engineering blogs)
- Rust/TypeScript core team blogs

**Tier 3 - Community Validated** (moderate trust)
- High-quality open source projects (10k+ stars, active maintenance)
- Stack Overflow answers with 100+ votes
- Well-maintained awesome-* lists

**Tier 4 - Reference Only** (verify independently)
- Medium articles, dev.to posts
- Tutorial sites
- General blog posts

### Research Questions by Category Type

**For Parsing/Analysis categories**:
- What parsing techniques do similar tools use?
- What's the state of the art in static analysis?
- How do enterprise tools handle scale?

**For Storage categories**:
- What are SQLite best practices for this use case?
- How do similar tools handle data persistence?
- What indexing strategies improve query performance?

**For AI/ML categories**:
- What embedding models are recommended?
- What retrieval strategies work best?
- How do production systems handle context windows?

**For Security categories**:
- What does OWASP recommend?
- What patterns do security-focused tools use?
- What are common vulnerabilities to avoid?

### Documentation Requirements

For each external source:
```markdown
### [Topic]

**Source**: [Full URL]
**Type**: [Tier 1/2/3/4]
**Accessed**: [Date]

**Key Findings**:
- [Finding 1]
- [Finding 2]

**Applicability to Drift**:
[How this applies to the category]

**Confidence**: [High/Medium/Low]
[Why you trust or don't trust this source]
```

---

## Phase 4: Recommendations

**Goal**: Document specific, actionable improvements with full citations.

### Recommendation Structure

```markdown
# [Category Name] - V2 Recommendations

## Summary
[Overview of recommended changes]

## Recommendations

### R1: [Short Title]

**Priority**: P0 (Critical) | P1 (Important) | P2 (Nice to have)
**Effort**: Low | Medium | High
**Impact**: [What improves]

**Current State**:
[How it works today]

**Proposed Change**:
[What should change]

**Rationale**:
[Why this is better]

**Evidence**:
- [Source 1 with URL]
- [Source 2 with URL]

**Implementation Notes**:
[Technical details for implementation]

**Risks**:
[What could go wrong]

**Dependencies**:
[Other categories affected]

---

### R2: [Next recommendation...]
```

### Recommendation Categories

1. **Architecture** - Structural changes to how components are organized
2. **Algorithm** - Improvements to core algorithms
3. **Performance** - Speed, memory, scalability improvements
4. **API** - Interface changes (breaking or non-breaking)
5. **Data Model** - Schema or type changes
6. **Security** - Security hardening
7. **Reliability** - Error handling, edge cases
8. **Maintainability** - Code quality, testing, documentation

---

## Quality Standards

### For Recap Documents
- [ ] All files in category have been read
- [ ] Architecture is clearly described
- [ ] Key algorithms are documented
- [ ] Data models are listed with fields
- [ ] Limitations are honestly assessed
- [ ] Integration points are mapped

### For Research
- [ ] At least 3 Tier 1 or Tier 2 sources consulted
- [ ] Sources are properly cited with URLs
- [ ] Access dates are recorded
- [ ] Findings are specific, not generic
- [ ] Applicability to Drift is explained

### For Recommendations
- [ ] Each recommendation has clear rationale
- [ ] Evidence is cited for each recommendation
- [ ] Priority and effort are assessed
- [ ] Risks are identified
- [ ] Dependencies are noted
- [ ] Implementation is actionable

---

## Output Files

Each category research produces 3 files:

```
docs/v2-research/.research/[category-number]-[category-name]/
├── RECAP.md              # Phase 2 output
├── RESEARCH.md           # Phase 3 output  
└── RECOMMENDATIONS.md    # Phase 4 output
```

Example:
```
docs/v2-research/.research/04-call-graph/
├── RECAP.md
├── RESEARCH.md
└── RECOMMENDATIONS.md
```
