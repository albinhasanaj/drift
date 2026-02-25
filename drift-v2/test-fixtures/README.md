# Test Fixtures

Shared test fixtures for the Drift V2 analysis engine.

## Directory Structure

| Directory | Purpose |
|-----------|---------|
| `typescript/` | TypeScript reference source files |
| `javascript/` | JavaScript reference source files |
| `python/` | Python reference source files |
| `java/` | Java reference source files |
| `csharp/` | C# reference source files |
| `go/` | Go reference source files |
| `rust/` | Rust reference source files |
| `ruby/` | Ruby reference source files |
| `php/` | PHP reference source files |
| `kotlin/` | Kotlin reference source files |
| `malformed/` | Edge cases: syntax errors, binary files, 0-byte, large files, Unicode names |
| `conventions/` | Convention learning: 3 synthetic repos with consistent naming patterns |
| `orm/` | ORM/boundary detection: Sequelize, Prisma, Django, SQLAlchemy, ActiveRecord |
| `taint/` | Taint analysis: known source→sink paths for SQL injection, XSS, etc. |

## Fixture Contract

Each language directory contains a reference source file with:
- Named functions (≥5)
- Classes with methods (≥2)
- Import/export statements
- Call sites between functions
- At least one known pattern (naming convention, error handling style)
- Inline comments marking expected parse results (`// EXPECT: function_count=5`)

Tests reference these fixtures via relative paths from the workspace root.
