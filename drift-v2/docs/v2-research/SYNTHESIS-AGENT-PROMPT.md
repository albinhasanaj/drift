# Synthesis Agent Prompt — Drift V2 Audit Findings → Actionable Diff Manifest

> Copy everything below the line into a fresh agent context window.
> The agent will read all 17 source documents and produce a single actionable output document.

---

## YOUR TASK

You are a synthesis agent. Your job is to read 17 research documents that audited a large implementation plan, extract ONLY the actionable deltas, and produce a single clean "diff manifest" that tells a developer exactly what to change in the orchestration plan.

**You are NOT re-auditing anything. You are NOT verifying anything. You are extracting and organizing.**

## WHAT TO READ (in this order)

First, read the existing partial synthesis — it covers Round 1 (Sections 1-8) and already consolidates 29 revisions:
- #File docs/v2-research/AUDIT-SYNTHESIS-AND-REMAINING-WORK.md

Then read all 16 findings documents. Sections 1-8 are Round 1 (technical validation). Sections 9-16 are Round 2 (orchestration validation):
- #File docs/v2-research/SECTION-1-FINDINGS.md
- #File docs/v2-research/SECTION-2-FINDINGS.md
- #File docs/v2-research/SECTION-3-FINDINGS.md
- #File docs/v2-research/SECTION-4-FINDINGS.md
- #File docs/v2-research/SECTION-5-FINDINGS.md
- #File docs/v2-research/SECTION-6-FINDINGS.md
- #File docs/v2-research/SECTION-7-FINDINGS.md
- #File docs/v2-research/SECTION-8-FINDINGS.md
- #File docs/v2-research/SECTION-9-FINDINGS.md
- #File docs/v2-research/SECTION-10-FINDINGS.md
- #File docs/v2-research/SECTION-11-FINDINGS.md
- #File docs/v2-research/SECTION-12-FINDINGS.md
- #File docs/v2-research/SECTION-13-FINDINGS.md
- #File docs/v2-research/SECTION-14-FINDINGS.md
- #File docs/v2-research/SECTION-15-FINDINGS.md
- #File docs/v2-research/SECTION-16-FINDINGS.md

Finally, read the plan being modified so you understand the target structure:
- #File docs/v2-research/DRIFT-V2-IMPLEMENTATION-ORCHESTRATION.md

## WHAT TO EXTRACT (signal)

For every finding across all 17 documents, extract ONLY:

1. **Verdicts that require action**: ⚠️ REVISE and 🔧 APPLIED items. Skip ✅ CONFIRMED entirely — they mean "no change needed."
2. **Specific value changes**: Always capture as `old → new` (e.g., `tree-sitter 0.24 → 0.25`, `60 systems → ~53 systems`, `FP <5% → <10%`)
3. **Plan section references**: Every change must reference the exact orchestration plan section it affects (§1, §2, §3.1, §5.2, §7.3, §9, §14, §15, §16, §18, §19, §20, etc.)
4. **New items to add**: Things that don't exist in the plan yet (R17-R20 risks, missing dependency edges, new taint sink types, new reporter formats, etc.)
5. **Items to remove or rename**: Anything the audit says should be deleted, renamed, or replaced
6. **Corrected numbers**: Table counts, system counts, NAPI function counts, schema table counts, timeline estimates — any number that changed
7. **Resolved open decisions**: OD-1 through OD-5 resolutions with their final answers

## WHAT TO STRIP (noise)

Do NOT include any of the following in your output:

- "Why confirmed" reasoning (e.g., "This is correct because Semgrep also does it...")
- Internet verification methodology (e.g., "I checked crates.io and found...")
- Comparisons with alternative tools/libraries (e.g., "vs quick_cache: ...")
- Academic citations or algorithm explanations
- Lengthy justifications for why something is sound
- The verification checklists themselves (the [x] items)
- Duplicate findings (the same revision appears in multiple sections — deduplicate)
- Any prose that doesn't directly describe a change to make

## OUTPUT FORMAT

Write your output to: `docs/v2-research/DRIFT-V2-DIFF-MANIFEST.md`

Organize the output by orchestration plan section (§1 through §20). For each section that needs changes, use this format:

```
## §X — [Section Title]

### Change 1: [Brief description]
- **Source:** Section Y Finding #Z
- **Current value:** [what the plan says now]
- **New value:** [what it should say]
- **Type:** version-bump | architecture | timeline | missing-item | correction | rename

### Change 2: ...
```

If a section has NO changes needed, omit it entirely. Don't list sections just to say "no changes."

After all per-section changes, include these summary sections:

### Aggregate Statistics
A single table showing: total changes by type (version-bump, architecture, timeline, missing-item, correction, rename), total across all sections, and the combined Round 1 + Round 2 verdict counts.

### Resolved Open Decisions
A table of OD-1 through OD-5 with their final resolutions (one line each).

### Pre-Implementation Blockers
Any items from Section 16's pre-implementation checklist that were flagged as needing verification before coding can start. List only items that are NOT yet confirmed — skip anything already verified.

### Corrected §3.1 Cargo.toml
Section 16 produced a corrected Cargo.toml with all version bumps applied. Include it verbatim — this is the single most actionable artifact.

## CRITICAL RULES

1. **Deduplicate aggressively.** The same revision (e.g., "tree-sitter 0.24 → 0.25") appears in Sections 1, 2, 10, and 16. List it ONCE under the plan section it affects (§3.1), citing all source sections.
2. **Preserve precision.** If a finding says "~48-56 tables" don't round to "~50". Keep the exact range.
3. **Don't editorialize.** Don't add your own opinions or recommendations. You're a transcriber of decisions already made.
4. **Every change must be traceable.** The "Source" field must point to the exact Section and Finding number so a human can look it up.
5. **Group related changes.** If 5 version bumps all affect §3.1 Cargo.toml, group them under §3.1 — don't scatter them.
6. **Include the Round 2 additions.** The AUDIT-SYNTHESIS doc only covers Round 1 (Sections 1-8). Sections 9-16 contain additional findings that are NOT in the synthesis yet. Your job is to merge both rounds into one unified manifest.

## WRITING INSTRUCTIONS

- Write the document in chunks of ~350 lines using fsWrite for the first chunk, then fsAppend for subsequent chunks.
- Target total length: 400-600 lines. If you're over 600 lines, you're including too much noise. If under 300, you're probably missing Round 2 findings.
- Use terse, telegraphic language. This is a change manifest, not a narrative.
