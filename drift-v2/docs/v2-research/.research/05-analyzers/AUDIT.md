# 05 Analyzers — Coverage Audit

> Systematic verification that every v1 source document was read, recapped, researched, and addressed in recommendations.

## Part 1: V1 Source Document → RECAP Coverage

### A. Primary Analyzer Source Documents (8 files)

| # | V1 Source File | Read? | Recapped? | Key Content | Coverage Notes |
|---|---------------|-------|-----------|-------------|----------------|
| 1 | `core-analyzers.md` | ✅ | ✅ | 4 foundational analyzers (AST, Type, Semantic, Flow), ~50 shared interfaces | All 4 in architecture diagram; algorithms, types documented |
| 2 | `constants-analysis.md` | ✅ | ✅ | TS orchestration, per-language extractors, dead constant detection, storage | Both TS/Rust in component inventory; secret detection algorithm documented |
| 3 | `environment-analysis.md` | ✅ | ✅ | EnvScanner, .env parsing, missing variable detection, consistency checking | Both TS/Rust listed; EnvAccess/EnvVariable types reproduced |
| 4 | `language-analyzers.md` | ✅ | ✅ | 9 language analyzers, per-language types, WPF/XAML architecture | Full inventory table; WPF architecture reproduced |
| 5 | `module-coupling.md` | ✅ | ✅ | Robert C. Martin metrics, Tarjan's SCC, module roles, break suggestions | Algorithm #6 with formulas; TS vs Rust gap documented |
| 6 | `rules-engine.md` | ✅ | ✅ | Evaluator, RuleEngine, VariantManager, SeverityManager, QuickFixGenerator | Algorithms #9 and #10; all types reproduced |
| 7 | `unified-provider.md` | ✅ | ✅ | 9 normalizers, 20 ORM matchers, UnifiedCallChain, matcher registry | Algorithm #7; all 20 matchers listed |
| 8 | `wrappers-analysis.md` | ✅ | ✅ | Detection, clustering, primitives registries, confidence scoring | Algorithm #8; confidence formula reproduced |

**Result: 8/8 primary source documents read and recapped. No gaps.**

### B. Rust Core Source Documents (6 files)

| # | V1 Source File | Read? | Recapped? | Key Content | Coverage Notes |
|---|---------------|-------|-----------|-------------|----------------|
| 9 | `other-analyzers.md` | ✅ | ✅ | Test Topology, Error Handling, Constants, Environment, Wrappers NAPI endpoints | All Rust analyzers in architecture diagram |
| 10 | `unified-analysis.md` | ✅ | ✅ | 4-phase pipeline, AstPatternDetector, StringLiteralAnalyzer, ResolutionIndex | Pipeline covered; detection methods documented |
| 11 | `coupling.md` | ✅ | ✅ | Rust DFS + TS Tarjan's SCC, Robert C. Martin reference | Algorithm #6 covers both implementations |
| 12 | `constants.md` | ✅ | ✅ | 21 secret patterns, confidence scoring, placeholder detection, magic numbers | Algorithm #5 with severity table |
| 13 | `environment.md` | ✅ | ✅ | EnvExtractor, sensitivity classification, access methods | Sensitivity classification reproduced |
| 14 | `wrappers.md` | ✅ | ✅ | WrapperDetector, 6 primitive categories, confidence formula | Algorithm #8 with full detection flow |

**Result: 6/6 Rust core documents read and recapped. No gaps.**

**Part 1 Total: 14/14 source documents fully read and recapped.**
