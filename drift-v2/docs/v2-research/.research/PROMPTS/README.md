# Category Research Prompts

This directory contains ready-to-use prompts for each category. Each prompt is pre-filled with:
- Category-specific context
- List of files to read
- Relevant research questions
- Connection information

## How to Use

1. Open the prompt file for your target category
2. Copy the entire content
3. Paste into a new agent session
4. The agent will execute the 4-phase research process

## Prompt Files

| File | Category |
|------|----------|
| `01-rust-core.md` | Rust native implementation |
| `02-parsers.md` | Tree-sitter parsing layer |
| `03-detectors.md` | Pattern detection system |
| `04-call-graph.md` | Function relationship mapping |
| `05-analyzers.md` | Code analysis engines |
| `06-cortex.md` | AI memory system |
| `07-mcp.md` | MCP server for AI agents |
| `08-storage.md` | Data persistence layer |
| `09-quality-gates.md` | CI/CD enforcement |
| `10-cli.md` | Command-line interface |
| `11-ide.md` | IDE integration |
| `12-infrastructure.md` | Build and deployment |
| `13-advanced.md` | Advanced analysis features |
| `17-test-topology.md` | Test framework detection |
| `18-constraints.md` | Architectural constraints |
| `19-error-handling.md` | Error analysis |
| `20-contracts.md` | API contract tracking |
| `21-security.md` | Security boundaries |
| `22-context-generation.md` | AI context generation |
| `23-pattern-repository.md` | Pattern storage |
| `24-data-lake.md` | Materialized views |
| `25-services-layer.md` | Scan pipeline |
| `26-workspace.md` | Project lifecycle |

## Research Output

Each research session produces 3 files in:
```
docs/v2-research/.research/[category-number]-[category-name]/
├── RECAP.md           # Comprehensive summary
├── RESEARCH.md        # External sources and findings
└── RECOMMENDATIONS.md # Prioritized improvements
```
