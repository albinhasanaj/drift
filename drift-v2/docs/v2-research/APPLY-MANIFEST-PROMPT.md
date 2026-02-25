# Apply Diff Manifest to Orchestration Plan — Agent Prompt

> Copy everything below the line into a fresh agent context window.
> Provide both files as context references.

---

## YOUR TASK

You are an editing agent. You will read a diff manifest containing 66 precisely defined changes, then apply every one of them to the orchestration plan document. You are not auditing, verifying, or questioning any change. Every change in the manifest has already been validated by 16 research sections and 4 audit passes. Your job is mechanical execution with zero interpretation.

## INPUT FILES

Read both files fully before making any edits:

1. **The manifest (your instruction set):**
   #File docs/v2-research/DRIFT-V2-DIFF-MANIFEST.md

2. **The target document (what you are editing):**
   #File docs/v2-research/DRIFT-V2-IMPLEMENTATION-ORCHESTRATION.md

## HOW TO EXECUTE

### Step 1: Read the manifest's "Agent Instructions" section first
It defines the `Op` field semantics:
- `Op: replace` — find **Current value** text in the target §section, swap with **New value**
- `Op: insert` — add **New value** as new content, matching format of adjacent entries
- `Op: delete` — remove the **Current value** from the target §section
- `Op: replace-block` — replace an entire subsection or code block
- `Op: skip` — do NOT edit anything. The change is documented to prevent a rejected suggestion from being applied

### Step 2: Work section by section, §1 through §20
- Process changes in order: §1 → §2 → §3 → ... → §20
- Within each section, apply changes in change-number order
- After completing each §section, move to the next

### Step 3: Special handling for §3.1 Cargo.toml
The manifest contains a **Corrected §3.1 Cargo.toml** block near the bottom. This is the final, authoritative version with all version bumps pre-applied. Use it verbatim to replace the existing Cargo.toml block in §3.1. Do NOT apply Change 5's individual line items separately — the corrected block supersedes them.

### Step 4: Global replacements (after all section edits)
Two values must be updated everywhere they appear in the document, not just in their home section:
- `"60 systems"` or `"60-System"` → `"~55 systems"` or `"~55-System"` (per Changes 1 and 38)
- `"Professional"` or `"Pro"` tier → `"Team"` (per Change 31). Standardize to Community / Team / Enterprise everywhere.

### Step 5: Complete the verification checklist
The manifest ends with a "Verification Checklist." After all edits, go through each checkbox and confirm it. If any check fails, go back and fix it before finishing.

## RULES

1. **Do not add commentary, opinions, or explanations.** You are a transcriber of pre-validated decisions.
2. **Do not skip changes.** Every change with `Op: replace`, `Op: insert`, `Op: delete`, or `Op: replace-block` must be applied. The only exception is `Op: skip` (Change 37).
3. **Preserve document structure.** Do not reformat, renumber, or reorganize sections. Only modify the specific text targeted by each change.
4. **Match adjacent formatting.** When inserting new content (`Op: insert`), look at the entries immediately above and below the insertion point. Match their heading level, bullet style, indentation, and table format exactly.
5. **Do not touch sections not in the manifest.** §1 says "No changes" — leave it untouched. Any section not listed in the manifest should not be modified.
6. **If you cannot find a Current value** in the target section, search the full document for it. Some values appear in multiple places (system counts, tier names). If still not found, note it and continue — do not invent edits.
7. **Write in chunks.** The orchestration plan is large. Edit it section by section using targeted replacements, not by rewriting the entire file.

## OUTPUT

Your output is the modified `DRIFT-V2-IMPLEMENTATION-ORCHESTRATION.md` with all 66 changes applied. No separate summary document. No changelog. Just the edited file.

After all edits, paste the completed verification checklist with all boxes checked:

```
## Verification Checklist
- [x] Every §section referenced in this manifest was modified
- [x] No §section NOT referenced in this manifest was modified
- [x] §3.1 Cargo.toml matches the Corrected block verbatim
- [x] All Op: insert items have content matching the format of adjacent entries
- [x] All Op: replace items had their old value found and swapped
- [x] All Op: delete items had their target removed
- [x] Change 37 (Op: skip) was NOT applied
- [x] System count references updated globally ("60" → "~55")
- [x] License tier naming updated globally ("Professional"/"Pro" → "Team")
- [x] Total edits applied: 66 changes (excluding Change 37 skip)
```

If any box cannot be checked, explain which change failed and why.
