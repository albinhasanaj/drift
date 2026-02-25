# Drift V2 — Detector & Parser Parity Hardening Task Tracker

> **Source of Truth:** Deep audit of `crates/drift/drift-analysis/src/` — parsers, detectors, structural, language_provider
> **Target:** Every `ParseResult` field populated correctly for all 10 languages. Every detector maximally informative across all 10 languages.
> **Crate:** `crates/drift/drift-analysis/`
> **Total Phases:** 6 (A–F)
> **Quality Gates:** 6 (QG-A through QG-F)
> **Architectural Decision:** The architecture is sound — types, traits, enums, pipeline are all correct. This is purely additive extraction + data work. No refactors needed.
> **Rule:** No Phase N+1 begins until Phase N quality gate passes.
> **Rule:** All changes must compile with `cargo clippy --workspace -- -D warnings` clean.
> **Rule:** Every impl task has a corresponding test task. No untested code.
> **Verification:** This tracker accounts for 100% of gaps identified in the detector parity audit.
> **Languages:** TypeScript, JavaScript, Python, Java, C#, Go, Rust, Ruby, PHP, Kotlin (10 total)

---

## How To Use This Document

- Agents: check off `[ ]` → `[x]` as you complete each task
- Every implementation task has a unique ID: `DP-{system}-{number}` (DP = Detector Parity)
- Every test task has a unique ID: `DT-{system}-{number}` (DT = Detector Test)
- Quality gates are pass/fail — all criteria must pass before proceeding
- For parser types → cross-reference `crates/drift/drift-analysis/src/parsers/types.rs`
- For detector traits → cross-reference `crates/drift/drift-analysis/src/detectors/traits.rs`
- For shared extraction → cross-reference `crates/drift/drift-analysis/src/parsers/languages/mod.rs`

---

## Progress Summary

| Phase | Description | Impl Tasks | Test Tasks | Status |
|-------|-------------|-----------|-----------|--------|
| A | Parser Extraction Foundation | 20 | 30 | Not Started |
| B | Detector Language Parity | 16 | 20 | Not Started |
| C | Error Handling Accuracy | 10 | 14 | Not Started |
| D | Taint Sink & Security Parity | 10 | 12 | Not Started |
| E | False Positive Reduction & Language Guards | 8 | 10 | Not Started |
| F | Cross-Language Verification & Regression | 6 | 30 | Not Started |
| **TOTAL** | | **70** | **116** | |

---

## Audit Findings Reference

### Root Cause
All 10 language parsers delegate to a single `parse_with_language()` function in `parsers/languages/mod.rs`. The `ParseResult` type system is perfectly designed (every field, every enum variant exists), but the extraction functions leave ~12 fields at default/empty values. This cascades: detectors check these fields, find nothing, produce no matches.

### Fields Confirmed Always Empty/Wrong (line-verified)
| Field | Location | Current Value | Should Be |
|-------|----------|---------------|-----------|
| `func.generic_params` | `mod.rs:294,334` | `SmallVec::new()` | Extracted from `type_parameters` node |
| `func.is_exported` | `mod.rs:296,336` | `false` | Detected from `export`/`pub`/visibility modifiers |
| `func.doc_comment` | `mod.rs:302,343` | `None` | Previous sibling comment node |
| `func.decorators` | `mod.rs:301,341` | `Vec::new()` | Linked from parsed decorators |
| `class.implements` | `mod.rs:392,410,429` | `SmallVec::new()` | Extracted from `implements_clause` / `: Interface` |
| `class.generic_params` | `mod.rs:392,429` | `SmallVec::new()` | Extracted from `type_parameters` node |
| `class.decorators` | `mod.rs:400,418` | `Vec::new()` | Linked from parsed decorators |
| `import.specifiers` | `mod.rs:480` | `SmallVec::new()` | Individual imported names |
| `import.source` | `mod.rs:477-479` | Full statement text | Module path only |
| `import.is_type_only` | `mod.rs:481` | `false` | Detected from `type` keyword |
| `StringContext` | `mod.rs:592` | `Unknown` | Parent node analysis |
| `NumericContext` | `mod.rs:606` | `Unknown` | Parent node analysis |
| `doc_comments` (file) | N/A | Never populated | Comment node extraction |
| `error_handling.has_body` | `mod.rs:214` | Always `true` | Inspect catch block children |
| `error_handling.caught_type` | `mod.rs:213` | Always `None` | Extract from catch clause parameter |

### Detector Language Bias (verified)
| Detector | Current Bias | Languages Missing |
|----------|-------------|-------------------|
| Auth imports | JS/TS only | Python, Java, C#, Go, Ruby, PHP, Kotlin, Rust |
| Config imports | Node.js only | All 8 non-JS languages |
| Logging imports | Node.js only | All 8 non-JS languages |
| Data Access ORM | Sequelize/Prisma/TypeORM | Django, SQLAlchemy, ActiveRecord, Hibernate, EF Core, GORM, Diesel, Eloquent |
| Testing frameworks | Jest/Mocha/pytest | JUnit, NUnit/xUnit, Go testing, Rust #[test], RSpec, PHPUnit, kotest |
| Testing mocks | Jest/Sinon/unittest.mock | Mockito, Moq, gomock, mockk |
| Security cmd injection | JS/Python | Java Runtime.exec, C# Process.Start, Go exec.Command, Rust Command::new |
| API frameworks | Partial | Spring Boot, ASP.NET, Gin, Rails, Laravel, Ktor |

### Broken Detectors (due to empty fields)
| Detector | Broken Feature | Root Cause |
|----------|---------------|------------|
| Documentation | DOC-COMMENT-001 never fires | `doc_comments` never populated |
| Documentation | DOC-FUNC-002 never fires | `func.doc_comment` always None |
| Documentation | DOC-MISSING-003 never fires | `func.is_exported` always false |
| Contracts | CNTR-IMPL-002 never fires | `class.implements` always empty |
| Types | TYPE-GENERIC-003 never fires | `generic_params` always empty |
| Errors | ERR-EMPTY-CATCH-001 never fires | `has_body` always true |
| Errors | ERR-GENERIC-CATCH-001 fires on ALL try/catch | `caught_type` always None |

### Ruby Import Blindness (confirmed)
Ruby has no `import_statement` AST node. `require`/`require_relative` are `call` nodes. All Ruby imports invisible to every detector.

### Taint Sink Imbalance (confirmed)
| Language | Current Sinks | Target |
|----------|--------------|--------|
| TypeScript/JS | 6 | 6 (ok) |
| Python | 6 | 6 (ok) |
| Java | 3 | 6+ |
| C# | 2 | 5+ |
| Go | 2 | 5+ |
| Ruby | 3 | 5+ |
| PHP | 3 | 6+ |
| Rust | 2 | 3 (ok by design) |
| Kotlin | 1 | 5+ |

---

## Phase A: Parser Extraction Foundation

> **Goal:** Populate all 12+ empty/default `ParseResult` fields from the AST for all 10 languages. This is the highest-multiplier work — it instantly unlocks 3 broken detectors and improves all 16.
> **Estimated effort:** 1.5–2 days
> **File:** `crates/drift/drift-analysis/src/parsers/languages/mod.rs`
> **Rationale:** Every downstream detector, every structural analysis module, every graph system consumes `ParseResult`. Fixing extraction here cascades everywhere.
> **Performance target:** No regression in parse throughput (currently ~1ms per file).

### A1 — Import Extraction — `extract_import()` (L476-485)

- [ ] `DP-IMPORT-01` — Refactor `extract_import()` — Extract the **module path** (not full statement text) into `source`. For JS/TS: the string literal after `from`. For Python: the module name after `import`/`from`. For Java/Kotlin: the package path. For Go: the import path string. For Rust: the path after `use`. For C#: the namespace after `using`. For PHP: the namespace after `use`. For Ruby: see DP-IMPORT-07.
- [ ] `DP-IMPORT-02` — Populate `specifiers` — Extract individual imported names. JS/TS: `{ useState, useEffect }`. Python: `from X import a, b`. Java: class name from `import pkg.ClassName`. Rust: `use crate::{A, B}`.
- [ ] `DP-IMPORT-03` — Populate `is_type_only` — TS: detect `import type` keyword. Rust: not applicable (always false). Java: not applicable. All others: false.
- [ ] `DP-IMPORT-04` — Handle Go multi-import blocks — Go `import (...)` produces a single `import_declaration` node with multiple `import_spec` children. Extract each as a separate `ImportInfo`.
- [ ] `DP-IMPORT-05` — Handle Python `import X` vs `from X import Y` — `import_statement` (no specifiers, source=module) vs `import_from_statement` (specifiers=imported names, source=module).
- [ ] `DP-IMPORT-06` — Handle Rust `use` paths — `use std::collections::HashMap` → source=`std::collections::HashMap`. `use crate::{A, B}` → source=`crate`, specifiers=[A, B].
- [ ] `DP-IMPORT-07` — **Ruby `require` as imports** — In `extract_calls_recursive`, when a `call` node has callee `require` or `require_relative`, also push an `ImportInfo` with `source` = the string argument. This is the only way to capture Ruby imports.
- [ ] `DP-IMPORT-08` — **PHP `use` declarations** — Add `namespace_use_declaration` to the matched import node types in `extract_node_recursive`. Verify PHP's tree-sitter node type and extract the namespace path.

### A2 — Function Extraction — `extract_function()` (L270-306) & `extract_arrow_function()` (L308-346)

- [ ] `DP-FUNC-01` — Populate `is_exported` — **JS/TS:** Check if function node is child of `export_statement` or has `export` keyword. **Python:** All module-level functions without `_` prefix are effectively public (set `true` for module-level). **Java/Kotlin/C#:** Check for `public` visibility modifier. **Go:** Check if name starts with uppercase. **Rust:** Check for `pub` keyword via `visibility_modifier` child. **Ruby:** Module-level `def` is public. **PHP:** Check `visibility_modifier` for `public`.
- [ ] `DP-FUNC-02` — Populate `doc_comment` — For each function node, check the **previous sibling** (or previous named sibling). If it's a `comment` node matching doc-comment patterns (JS/TS: starts with `/**`, Python: next sibling `expression_statement` containing `string`, Rust: starts with `///` or `//!`, Java/Kotlin: `/**`, Go: `//` immediately preceding, C#: `///`, Ruby: `#`, PHP: `/**`), extract the text.
- [ ] `DP-FUNC-03` — Populate `generic_params` — Extract from `type_parameters` child node. JS/TS: `<T, U extends Foo>`. Java/Kotlin: `<T extends Comparable>`. Rust: `<T: Clone + Send>`. C#: `<T> where T : IFoo`. Go: `[T any]` (Go 1.18+ type params). Build `GenericParam { name, bounds }` for each.
- [ ] `DP-FUNC-04` — Link `decorators` — After extracting decorators in `extract_calls_recursive`, associate them with the next function/class node by line proximity. Populate `func.decorators` and `class.decorators`.
- [ ] `DP-FUNC-05` — Populate `visibility` — **Java/Kotlin/C#:** Parse `private`/`protected`/`public` modifier nodes. **Rust:** `pub` = Public, `pub(crate)` = Protected (mapped), no modifier = Private. **Go:** Uppercase first letter = Public, lowercase = Private. **Python/JS/TS/Ruby/PHP:** Use existing heuristics (underscore prefix = private for Python, `private` keyword for TS class methods).

### A3 — Class Extraction — `extract_class()` (L348-402), `extract_struct()`, `extract_interface()`, `extract_trait()`

- [ ] `DP-CLASS-01` — Populate `implements` — **Java/Kotlin:** Extract from `super_interfaces` or `implements` clause. **TypeScript:** Extract from `class_heritage` node filtering for `implements`. **C#:** Extract interfaces from base list (after class name, comma-separated). **Go:** Struct implementing interfaces is implicit (skip). **Rust:** Extract `impl Trait for Struct` as implements (may need separate pass). **PHP:** Extract from `class_interface_clause`.
- [ ] `DP-CLASS-02` — Populate `generic_params` on classes — Same logic as DP-FUNC-03 but on class/struct/interface nodes. Extract `type_parameters` child.
- [ ] `DP-CLASS-03` — Link `decorators` to classes — Same as DP-FUNC-04 but for class nodes. Java `@Entity`, Python `@dataclass`, TS `@Component`, etc.
- [ ] `DP-CLASS-04` — Populate `is_exported` on classes — Same visibility logic as DP-FUNC-01 applied to class/struct/enum/trait nodes.

### A4 — Doc Comment Extraction

- [ ] `DP-DOC-01` — Create doc comment extraction in `extract_calls_recursive` — When encountering `comment` nodes, classify them by `DocCommentStyle` and push to `result.doc_comments`. Patterns per language:
  - **JS/TS:** `/** ... */` → `DocCommentStyle::JsDoc`
  - **Rust:** `/// ...` or `//! ...` → `DocCommentStyle::TripleSlash`
  - **Python:** Triple-quoted strings as first statement in function/class → `DocCommentStyle::Docstring`
  - **Java/Kotlin:** `/** ... */` → `DocCommentStyle::KDoc` (Kotlin) or `DocCommentStyle::JsDoc` (Java — same format)
  - **Go:** `// Comment` immediately before declaration → `DocCommentStyle::GoDoc`
  - **C#:** `/// <summary>` → `DocCommentStyle::TripleSlash`
  - **Ruby:** `#` comments before method → `DocCommentStyle::Pound`
  - **PHP:** `/** ... */` → `DocCommentStyle::PhpDoc`

### A5 — Error Handling Accuracy

- [ ] `DP-ERR-01` — Fix `has_body` extraction — In the `try_statement` / `try_expression` handler (L206-216), find the `catch_clause` / `except_clause` / `rescue` child. Check if the handler body has >0 statement children. If empty, set `has_body: false`.
- [ ] `DP-ERR-02` — Fix `caught_type` extraction — In the catch/except clause, extract the type annotation. JS/TS: the parameter type in `catch (e: TypeError)`. Java/C#/Kotlin: the exception type `catch (IOException e)`. Python: `except ValueError as e`. Ruby: `rescue StandardError => e`.
- [ ] `DP-ERR-03` — Classify Python `try/except` correctly — When language is Python and node is `try_statement`, set `kind: ErrorHandlingKind::TryExcept` instead of `TryCatch`.

### A6 — Context Classification

- [ ] `DP-CTX-01` — Classify `StringContext` — Check parent node type of string literals: `arguments` → `FunctionArgument`, `variable_declarator` / `assignment` → `VariableAssignment`, `pair` / `property` → `ObjectProperty`, `decorator` / `attribute` → `Decorator`, `return_statement` → `ReturnValue`, `array` → `ArrayElement`.
- [ ] `DP-CTX-02` — Classify `NumericContext` — Check parent node: `const_item` / `const` declaration → `ConstDeclaration`, `variable_declarator` → `VariableAssignment`, `arguments` → `FunctionArgument`, `array` → `ArrayElement`, `binary_expression` with `==`/`<`/`>` → `Comparison`, `return_statement` → `ReturnValue`, `default_value` → `DefaultParameter`, `enum_assignment` → `EnumValue`.

### Phase A Tests

#### Import Extraction
- [ ] `DT-IMPORT-01` — TypeScript: `import { useState } from 'react'` → source=`react`, specifiers=[`useState`]
- [ ] `DT-IMPORT-02` — TypeScript: `import type { User } from './types'` → is_type_only=true
- [ ] `DT-IMPORT-03` — Python: `from flask import Flask, request` → source=`flask`, specifiers=[`Flask`, `request`]
- [ ] `DT-IMPORT-04` — Python: `import os` → source=`os`, specifiers=[]
- [ ] `DT-IMPORT-05` — Java: `import java.util.List` → source=`java.util.List`, specifiers=[`List`]
- [ ] `DT-IMPORT-06` — Go: `import "net/http"` → source=`net/http`
- [ ] `DT-IMPORT-07` — Go: multi-import `import (\n"fmt"\n"os"\n)` → 2 ImportInfo entries
- [ ] `DT-IMPORT-08` — Rust: `use std::collections::HashMap` → source=`std::collections::HashMap`
- [ ] `DT-IMPORT-09` — C#: `using System.Linq` → source=`System.Linq`
- [ ] `DT-IMPORT-10` — Ruby: `require 'sinatra'` → ImportInfo with source=`sinatra`
- [ ] `DT-IMPORT-11` — PHP: `use Illuminate\Http\Request` → source=`Illuminate\Http\Request`
- [ ] `DT-IMPORT-12` — Kotlin: `import java.io.File` → source=`java.io.File`

#### Function Extraction
- [ ] `DT-FUNC-01` — TypeScript: `export function getUser()` → is_exported=true
- [ ] `DT-FUNC-02` — Go: `func GetUser()` → is_exported=true, `func getUser()` → is_exported=false
- [ ] `DT-FUNC-03` — Rust: `pub fn get_user()` → is_exported=true, visibility=Public
- [ ] `DT-FUNC-04` — Java: `private void helper()` → visibility=Private, is_exported=false
- [ ] `DT-FUNC-05` — TypeScript: function with `/** JSDoc */` → doc_comment populated
- [ ] `DT-FUNC-06` — Python: function with triple-quote docstring → doc_comment populated
- [ ] `DT-FUNC-07` — Rust: function with `/// doc` → doc_comment populated
- [ ] `DT-FUNC-08` — TypeScript: `function foo<T>(x: T): T` → generic_params=[{name:"T", bounds:[]}]
- [ ] `DT-FUNC-09` — Java: `public <T extends Comparable> void sort(T item)` → generic_params populated
- [ ] `DT-FUNC-10` — Rust: `fn process<T: Clone + Send>(item: T)` → generic_params=[{name:"T", bounds:["Clone","Send"]}]

#### Class Extraction
- [ ] `DT-CLASS-01` — Java: `class Foo implements Bar, Baz` → implements=[`Bar`, `Baz`]
- [ ] `DT-CLASS-02` — TypeScript: `class UserService implements IService` → implements=[`IService`]
- [ ] `DT-CLASS-03` — C#: `class Foo : IBar, IBaz` → implements=[`IBar`, `IBaz`]
- [ ] `DT-CLASS-04` — Kotlin: `class Foo : Bar(), IBaz` → extends=`Bar`, implements=[`IBaz`]
- [ ] `DT-CLASS-05` — Java: `@Entity class User` → decorators=[{name:"Entity"}]
- [ ] `DT-CLASS-06` — TypeScript: `class Foo<T>` → generic_params=[{name:"T"}]

#### Error Handling
- [ ] `DT-ERR-01` — JS: `try { x() } catch (e) {}` → has_body=false (empty catch)
- [ ] `DT-ERR-02` — JS: `try { x() } catch (e) { log(e) }` → has_body=true
- [ ] `DT-ERR-03` — Java: `catch (IOException e)` → caught_type=Some("IOException")
- [ ] `DT-ERR-04` — Python: `except ValueError as e:` → caught_type=Some("ValueError"), kind=TryExcept

### Quality Gate A (QG-A)

```
MUST PASS before Phase B begins:
- [ ] All 10 reference test fixtures parse with specifiers populated (DT-IMPORT-01 through DT-IMPORT-12)
- [ ] is_exported is true for at least 1 function in every test fixture that has exported functions
- [ ] doc_comment is Some() for at least 1 function per language that has doc comments in fixtures
- [ ] class.implements is non-empty for Java/TS/C# test fixtures that implement interfaces
- [ ] error_handling.has_body correctly reports false for empty catch blocks
- [ ] error_handling.caught_type is Some() when catch clause has a type
- [ ] Ruby require produces ImportInfo entries
- [ ] cargo clippy --workspace -- -D warnings passes
- [ ] cargo test -p drift-analysis passes (all existing tests still green)
- [ ] Parse throughput: no more than 10% regression on 100-file benchmark
```

---

## Phase B: Detector Language Parity

> **Goal:** Expand every detector's hardcoded library/import/framework lists from JS-only to all 10 languages. Pure data addition — detection logic unchanged.
> **Estimated effort:** 1–1.5 days
> **Files:** `crates/drift/drift-analysis/src/detectors/*/mod.rs`
> **Depends on:** Phase A (import source must be module path, not full text)
> **Rationale:** Currently 6 of 16 detectors have JS-only library lists. Adding per-language entries makes them fire for all 10 languages instantly.

### B1 — Auth Detector — `detectors/auth/mod.rs`

- [ ] `DP-AUTH-01` — Expand `auth_imports` array to include all languages:
  - **Python:** `django.contrib.auth`, `flask-login`, `flask_login`, `authlib`, `python-jose`, `passlib`
  - **Java/Kotlin:** `spring-security`, `org.springframework.security`, `apache.shiro`, `io.jsonwebtoken`, `com.auth0`
  - **C#:** `Microsoft.AspNetCore.Identity`, `Microsoft.AspNetCore.Authentication`, `System.IdentityModel.Tokens.Jwt`
  - **Go:** `golang.org/x/oauth2`, `github.com/dgrijalva/jwt-go`, `github.com/golang-jwt/jwt`
  - **Ruby:** `devise`, `omniauth`, `warden`, `doorkeeper`, `jwt`
  - **PHP:** `laravel/sanctum`, `tymon/jwt-auth`, `laravel/passport`, `firebase/php-jwt`
  - **Rust:** `actix-identity`, `jsonwebtoken`, `oauth2`, `actix-web-httpauth`
- [ ] `DP-AUTH-02` — Expand `auth_receivers` to include language-specific patterns: `Spring Security` filter chains, `passport` (already there), `Devise`, `Auth::`, `auth.`

### B2 — API Detector — `detectors/api/mod.rs`

- [ ] `DP-API-01` — Expand `api_frameworks` array:
  - **Java/Kotlin:** `org.springframework.web`, `spring-boot`, `javax.ws.rs`, `io.ktor`
  - **C#:** `Microsoft.AspNetCore.Mvc`, `Microsoft.AspNetCore`
  - **Go:** `github.com/gin-gonic/gin`, `github.com/gorilla/mux`, `github.com/gofiber/fiber`, `net/http`
  - **Ruby:** `sinatra`, `rails`, `actionpack`, `grape`
  - **PHP:** `laravel`, `symfony`, `slim`
- [ ] `DP-API-02` — Reduce false positives on REST method detection — Only match `get`/`post`/`put`/`delete` when the receiver is a known router/app object (e.g., `app.get`, `router.post`, `server.get`). Do NOT match bare `get()` calls (too many false positives from Map.get, dict.get, etc.).

### B3 — Config Detector — `detectors/config/mod.rs`

- [ ] `DP-CFG-01` — Expand `config_imports` array:
  - **Python:** `python-dotenv`, `dotenv`, `pydantic-settings`, `pydantic`, `configparser`, `dynaconf`
  - **Java/Kotlin:** `spring-boot` (for `@Value`, `@ConfigurationProperties`), `com.typesafe.config`, `io.github.cdimascio.dotenv`
  - **Go:** `github.com/spf13/viper`, `github.com/kelseyhightower/envconfig`, `github.com/joho/godotenv`
  - **Ruby:** `dotenv`, `figaro`, `chamber`
  - **PHP:** `vlucas/phpdotenv`, `symfony/dotenv`
  - **Rust:** `config`, `dotenvy`, `figment`
  - **C#:** `Microsoft.Extensions.Configuration`
- [ ] `DP-CFG-02` — Expand env access patterns — Add: `System.getenv` (Java/Kotlin), `ENV[` and `ENV.fetch` (Ruby), `getenv(` (PHP), `os.Getenv` (Go)

### B4 — Logging Detector — `detectors/logging/mod.rs`

- [ ] `DP-LOG-01` — Expand `logging_imports` array:
  - **Python:** `logging`, `loguru`, `structlog`
  - **Java/Kotlin:** `org.slf4j`, `log4j`, `java.util.logging`, `ch.qos.logback`, `io.github.microutils.kotlin-logging`
  - **Go:** `log`, `go.uber.org/zap`, `github.com/sirupsen/logrus`, `github.com/rs/zerolog`
  - **Ruby:** `logger`, `logging`, `semantic_logger`
  - **PHP:** `monolog`, `psr/log`
  - **Rust:** `tracing`, `log`, `env_logger`, `slog`
  - **C#:** `Microsoft.Extensions.Logging`, `Serilog`, `NLog`
- [ ] `DP-LOG-02` — Expand `log_receivers` — Add `logger` (already there), `Logger` (Ruby/C#), `LOGGER` (Rust convention), `fmt` (Go — for `fmt.Println`)
- [ ] `DP-LOG-03` — Expand `bare_print_calls` — Add Rust macros handled as calls if possible: `println!`, `eprintln!`, `dbg!`. Also add Go's `fmt.Println`, `fmt.Printf` via receiver match on `fmt`.

### B5 — Data Access Detector — `detectors/data_access/mod.rs`

- [ ] `DP-DA-01` — Expand `orm_methods` array with per-framework methods:
  - **Django:** `objects.filter`, `objects.get`, `objects.all`, `objects.create`, `objects.exclude`
  - **SQLAlchemy:** `session.query`, `session.add`, `session.commit`, `session.execute`
  - **ActiveRecord:** `Model.where`, `Model.find`, `Model.find_by`, `Model.create`, `Model.update`
  - **Hibernate/JPA:** `entityManager.find`, `entityManager.persist`, `entityManager.merge`, `createQuery`, `createNativeQuery`
  - **EF Core:** `DbSet.Find`, `DbSet.FirstOrDefault`, `DbSet.Where`, `DbSet.Add`, `SaveChanges`, `SaveChangesAsync`
  - **GORM (Go):** `db.Find`, `db.First`, `db.Create`, `db.Where`, `db.Save`
  - **Diesel (Rust):** `diesel::insert_into`, `diesel::update`, `.load`, `.get_result`
  - **Eloquent (PHP):** `Model::find`, `Model::where`, `Model::create`, `Model::all`
- [ ] `DP-DA-02` — Expand raw SQL receiver patterns — Add: `cursor` (Python), `entityManager` (Java), `_context` (C#), `ActiveRecord::Base.connection` (Ruby), `DB::` (PHP), `sqlx` (Rust/Go)

### B6 — Testing Detector — `detectors/testing/mod.rs`

- [ ] `DP-TEST-01` — Expand `test_frameworks` array:
  - **Java:** `@Test`, `@BeforeEach`, `@AfterEach`, `@ParameterizedTest`, `assertThat`, `assertThrows`
  - **C#:** `[Fact]`, `[Theory]`, `[Test]`, `[SetUp]`, `[TearDown]`, `Assert.Equal`, `Assert.Throws`
  - **Go:** `testing.T`, `t.Run`, `t.Error`, `t.Fatal`, `t.Log`, `require.Equal`, `assert.Equal`
  - **Rust:** `#[test]`, `#[cfg(test)]`, `assert!`, `assert_eq!`, `assert_ne!`
  - **Ruby:** `describe`, `it`, `context`, `before`, `after`, `expect().to`, `RSpec.describe`
  - **PHP:** `@test`, `PHPUnit`, `assertEquals`, `assertSame`, `expectException`
  - **Kotlin:** `@Test`, `assertEquals`, `assertThat`, `shouldBe`, `kotest`
- [ ] `DP-TEST-02` — Expand `mock_patterns` array — Add: `Mockito` + `when` + `verify` (Java), `Moq` + `Setup` + `Verify` (C#), `gomock` + `NewMockController` (Go), `mockk` + `every` + `verify` (Kotlin), `double` + `allow` + `expect` (Ruby RSpec)
- [ ] `DP-TEST-03` — Expand `assertion_patterns` — Add: `t.Error`, `t.Fatal` (Go), `assert!`, `assert_eq!` (Rust), `expect().to` (Ruby), `assertEquals` (PHP), `shouldBe` (Kotlin kotest)

### B7 — Security Detector — `detectors/security/mod.rs`

- [ ] `DP-SEC-01` — Expand command injection patterns:
  - **Java:** `Runtime.getRuntime().exec`, `ProcessBuilder`
  - **C#:** `Process.Start`, `ProcessStartInfo`
  - **Go:** `exec.Command`
  - **Rust:** `Command::new`, `std::process::Command`
  - **Ruby:** `system`, `exec`, backtick operator (detect via string containing `` ` ``)
  - **PHP:** `shell_exec`, `passthru`, `proc_open`, `pcntl_exec`
- [ ] `DP-SEC-02` — Expand XSS patterns beyond innerHTML — Add: `document.write` (JS), `v-html` (Vue), `[innerHTML]` (Angular), `{!! !!}` (Laravel Blade), `|safe` (Django), `raw` (Jinja2/Twig)

### Phase B Tests

- [ ] `DT-AUTH-01` — Python `from flask_login import login_user` triggers AUTH-IMPORT-002
- [ ] `DT-AUTH-02` — Java `import org.springframework.security.core.Authentication` triggers AUTH-IMPORT-002
- [ ] `DT-AUTH-03` — Go `import "github.com/golang-jwt/jwt"` triggers AUTH-IMPORT-002
- [ ] `DT-CFG-01` — Python `import dotenv` triggers CFG-IMPORT-002
- [ ] `DT-CFG-02` — Go `import "github.com/spf13/viper"` triggers CFG-IMPORT-002
- [ ] `DT-LOG-01` — Python `import logging` triggers LOG-IMPORT-002
- [ ] `DT-LOG-02` — Java `import org.slf4j.Logger` triggers LOG-IMPORT-002
- [ ] `DT-LOG-03` — Rust `use tracing` triggers LOG-IMPORT-002
- [ ] `DT-DA-01` — Python `session.query(User)` triggers DA-ORM-001
- [ ] `DT-DA-02` — Java `entityManager.find(User.class, id)` triggers DA-ORM-001
- [ ] `DT-DA-03` — Ruby `User.where(active: true)` triggers DA-ORM-001
- [ ] `DT-TEST-01` — Java `@Test void testFoo()` triggers TEST-FRAMEWORK-001
- [ ] `DT-TEST-02` — Go `func TestGetUser(t *testing.T)` triggers TEST-FUNC-001
- [ ] `DT-TEST-03` — Rust function named `test_get_user` triggers TEST-FUNC-001
- [ ] `DT-SEC-01` — Java `Runtime.getRuntime().exec(input)` triggers SEC-CMDI-001
- [ ] `DT-SEC-02` — Go `exec.Command("sh", "-c", input)` triggers SEC-CMDI-001
- [ ] `DT-SEC-03` — PHP `shell_exec($input)` triggers SEC-CMDI-001
- [ ] `DT-SEC-04` — C# `Process.Start(input)` triggers SEC-CMDI-001
- [ ] `DT-API-01` — Verify bare `dict.get("key")` does NOT trigger API-REST-001 (false positive fix)
- [ ] `DT-API-02` — Java `import org.springframework.web.bind.annotation.*` triggers API-FRAMEWORK-003

### Quality Gate B (QG-B)

```
MUST PASS before Phase C begins:
- [ ] Auth detector fires on import patterns for all 10 languages
- [ ] Config detector fires on import patterns for at least 8 languages
- [ ] Logging detector fires on import patterns for at least 8 languages
- [ ] Data Access detector fires on ORM calls for at least 6 ORM frameworks
- [ ] Testing detector fires on test patterns for all 10 languages
- [ ] Security detector fires on command injection for at least 8 languages
- [ ] API detector false positive rate on clean code reduced (bare get/post gated)
- [ ] All DT-* tests in Phase B pass
- [ ] cargo clippy clean, cargo test green
```

---

## Phase C: Error Handling Accuracy

> **Goal:** Make error handling extraction produce correct, language-specific results so the Errors detector and graph-level error analysis work with real data.
> **Estimated effort:** 0.5–1 day
> **Files:** `parsers/languages/mod.rs`, `detectors/errors/mod.rs`
> **Depends on:** Phase A (DP-ERR-01 through DP-ERR-03)
> **Rationale:** The graph-level error handling system (`graph/error_handling/`) is fully implemented and tested with hand-constructed data. The parser just doesn't feed it real data.

### C1 — Rust Error Patterns

- [ ] `DP-RERR-01` — Detect `?` operator — When encountering `try_expression` node (Rust's `?`), emit `ErrorHandlingInfo` with `kind: ErrorHandlingKind::QuestionMark`.
- [ ] `DP-RERR-02` — Detect `.unwrap()` calls — When `call_expression` has callee `unwrap`/`unwrap_or`/`unwrap_or_else`/`expect`, emit `ErrorHandlingKind::Unwrap`.
- [ ] `DP-RERR-03` — Detect `match` on `Result`/`Option` — When `match_expression` arms match `Ok`/`Err` or `Some`/`None`, emit `ErrorHandlingKind::ResultMatch`.

### C2 — JS/TS Promise Patterns

- [ ] `DP-PERR-01` — Detect `.catch()` on promises — When `call_expression` has callee `catch` on a promise chain, emit `ErrorHandlingKind::PromiseCatch`.
- [ ] `DP-PERR-02` — Detect `Promise.allSettled`/`Promise.all` — Flag `Promise.all` without `.catch()` as potential unhandled rejection.

### C3 — Go Defer/Recover

- [ ] `DP-GERR-01` — Verify `defer_statement` produces `ErrorHandlingKind::Defer`.
- [ ] `DP-GERR-02` — Detect `recover()` inside `defer` block → `ErrorHandlingKind::DeferRecover`.

### C4 — Ruby Rescue

- [ ] `DP-RBERR-01` — Verify `rescue` extracts exception type into `caught_type` and body into `has_body`.
- [ ] `DP-RBERR-02` — Detect inline rescue (`x = dangerous rescue default`) via `rescue_modifier` nodes.

### C5 — Python Context Managers

- [ ] `DP-PYERR-01` — Detect `with` statement as resource management (analogous to Go `defer`).

### Phase C Tests

- [ ] `DT-RERR-01` — Rust: `let x = foo()?;` → QuestionMark detected
- [ ] `DT-RERR-02` — Rust: `foo().unwrap()` → Unwrap detected
- [ ] `DT-RERR-03` — Rust: `match result { Ok(v) => v, Err(e) => ... }` → ResultMatch
- [ ] `DT-PERR-01` — JS: `fetch(url).catch(e => log(e))` → PromiseCatch detected
- [ ] `DT-GERR-01` — Go: `defer func() { recover() }()` → DeferRecover detected
- [ ] `DT-RBERR-01` — Ruby: `begin...rescue StandardError => e...end` → Rescue with caught_type
- [ ] `DT-RBERR-02` — Ruby: `x = dangerous rescue nil` → Rescue (inline)
- [ ] `DT-PYERR-01` — Python: `except ValueError as e: pass` → TryExcept, caught_type="ValueError"
- [ ] `DT-ERR-INT-01` — Parse e2e TS source → empty catch in deleteUser has has_body=false
- [ ] `DT-ERR-INT-02` — Parse e2e Go source → `if err != nil` captured
- [ ] `DT-ERR-INT-03` — Parse e2e Rust source → `?` produces QuestionMark
- [ ] `DT-ERR-INT-04` — Run Errors detector on Python → TryExcept kind (not TryCatch)
- [ ] `DT-ERR-INT-05` — Run Errors detector on TS with empty catch → ERR-EMPTY-CATCH-001 fires
- [ ] `DT-ERR-INT-06` — Run Errors detector on Java with typed catch → ERR-GENERIC-CATCH does NOT fire

### Quality Gate C (QG-C)

```
MUST PASS before Phase D begins:
- [ ] Rust ?, unwrap, Result match all produce correct ErrorHandlingKind
- [ ] JS .catch() produces PromiseCatch
- [ ] Go defer+recover produces DeferRecover
- [ ] Ruby rescue produces Rescue with caught_type
- [ ] Python try/except produces TryExcept (not TryCatch)
- [ ] Empty catch blocks produce has_body=false
- [ ] ERR-EMPTY-CATCH-001 fires on real parsed code with empty catch
- [ ] ERR-GENERIC-CATCH-001 only fires when caught_type is genuinely None/generic
- [ ] All DT-* tests in Phase C pass
- [ ] cargo clippy clean, cargo test green
```
---
## Phase D: Taint Sink & Security Parity

> **Goal:** Expand taint sink definitions to competitive parity across all 10 languages.
> **Estimated effort:** 0.5 day
> **File:** `crates/drift/drift-analysis/src/language_provider/taint_sinks.rs`
> **Rationale:** Kotlin has 1 taint sink. C# and Go have 2 each. These languages deserve the same depth as JS/Python (6 each).

### D1 — Kotlin Taint Sinks (currently 1 → target 6)

- [ ] `DP-SINK-KT-01` — Add Kotlin sinks:
  - `Runtime.getRuntime().exec()` → CommandExecution, Critical
  - `ProcessBuilder` → CommandExecution, Critical
  - `readObject` on `ObjectInputStream` → Deserialization, Critical
  - `File().readText()` → FileRead, High
  - `URL().readText()` → NetworkRequest, Medium

### D2 — C# Taint Sinks (currently 2 → target 6)

- [ ] `DP-SINK-CS-01` — Add C# sinks:
  - `ExecuteReader`, `ExecuteScalar` on SqlCommand → SqlExecution, Critical
  - `HttpClient.GetAsync` / `PostAsync` → NetworkRequest, Medium
  - `BinaryFormatter.Deserialize` → Deserialization, Critical
  - `File.ReadAllText` / `File.WriteAllText` → FileRead/FileWrite, High
  - `Response.Redirect` → Redirect, Medium

### D3 — Go Taint Sinks (currently 2 → target 6)

- [ ] `DP-SINK-GO-01` — Add Go sinks:
  - `template.HTML()` → HtmlRendering, High
  - `http.Redirect` → Redirect, Medium
  - `os.Create` / `os.OpenFile` → FileWrite, High
  - `ioutil.ReadAll` / `io.ReadAll` → FileRead, Medium

### D4 — PHP Taint Sinks (currently 3 → target 7)

- [ ] `DP-SINK-PHP-01` — Add PHP sinks:
  - `include` / `require` with variable → FileRead (LFI), Critical
  - `file_get_contents` → FileRead, High
  - `unserialize` → Deserialization, Critical
  - `header("Location: ")` → Redirect, Medium
  - `echo` / `print` with unescaped input → HtmlRendering, High

### D5 — Ruby Taint Sinks (currently 3 → target 6)

- [ ] `DP-SINK-RB-01` — Add Ruby sinks:
  - `send` → Eval (arbitrary method dispatch), Critical
  - `constantize` → Eval (arbitrary class instantiation), Critical
  - `ERB.new(input).result` → HtmlRendering, High

### D6 — Java Taint Sinks (currently 3 → target 6)

- [ ] `DP-SINK-JV-01` — Add Java sinks:
  - `InitialContext.lookup` → JNDI injection, Critical
  - `URL.openConnection` → NetworkRequest (SSRF), High
  - `XMLInputFactory.createXMLStreamReader` → Deserialization (XXE), Critical

### Phase D Tests

- [ ] `DT-SINK-01` — `extract_sinks(Language::Kotlin)` returns >= 6 sinks
- [ ] `DT-SINK-02` — `extract_sinks(Language::CSharp)` returns >= 6 sinks
- [ ] `DT-SINK-03` — `extract_sinks(Language::Go)` returns >= 6 sinks
- [ ] `DT-SINK-04` — `extract_sinks(Language::Php)` returns >= 7 sinks
- [ ] `DT-SINK-05` — `extract_sinks(Language::Ruby)` returns >= 6 sinks
- [ ] `DT-SINK-06` — `extract_sinks(Language::Java)` returns >= 6 sinks
- [ ] `DT-SINK-07` — All sinks have valid `SinkCategory` and `SinkSeverity`
- [ ] `DT-SINK-08` — All sinks have non-empty `tainted_params` where applicable
- [ ] `DT-SINK-09` — Kotlin `executeQuery` sink still present (no regression)
- [ ] `DT-SINK-10` — Total sink count across all languages >= 50
- [ ] `DT-SINK-11` — Every `SinkCategory` variant is used by at least 2 languages
- [ ] `DT-SINK-12` — PHP `include` sink has `SinkSeverity::Critical`

### Quality Gate D (QG-D)

```
MUST PASS before Phase E begins:
- [ ] Every language has >= 3 taint sinks (Rust exempted at 2 by design)
- [ ] Kotlin, C#, Go, PHP, Ruby, Java all have >= 5 sinks
- [ ] All 10 SinkCategory variants are covered across the language set
- [ ] No duplicate sink entries within a language
- [ ] All DT-SINK-* tests pass
- [ ] cargo clippy clean, cargo test green
```

---

## Phase E: False Positive Reduction & Language Guards

> **Goal:** Gate language-specific detectors so they don't produce noise on irrelevant languages. Reduce false positives from overly-broad pattern matching.
> **Estimated effort:** 0.5 day
> **Files:** `detectors/performance/mod.rs`, `detectors/components/mod.rs`, `detectors/styling/mod.rs`, `detectors/accessibility/mod.rs`, `detectors/api/mod.rs`
> **Depends on:** Phases A-B (correct language detection and import extraction)
> **Rationale:** Currently the Performance detector flags `.clone()` in Java/JS as suspicious (it's normal there), and 3 frontend-only detectors fire uselessly on Go/Rust/Java/etc.

### E1 — Performance Detector Language Gating

- [ ] `DP-PERF-01` — Gate allocation patterns by language — `.clone()`, `.to_vec()`, `.to_string()`, `.to_owned()`, `.collect()` should only fire for Rust where unnecessary allocations are a real concern. For all other languages, these are normal idiomatic calls.
- [ ] `DP-PERF-02` — Add language-specific performance patterns:
  - **Python:** `time.sleep()` in async code, `+` string concatenation in loops (use join)
  - **Java:** Synchronized block in hot path, `String +=` in loop (use StringBuilder)
  - **Go:** Unbuffered channel in hot loop, `append` without pre-allocation hint
  - **JS/TS:** `JSON.parse(JSON.stringify())` for deep clone (use structuredClone)

### E2 — Frontend-Only Detector Guards

- [ ] `DP-FE-01` — Components detector — Add early return: if `ctx.language` is not TypeScript, JavaScript, or Python (for Django templates), return empty vec immediately. No point scanning Go/Rust/Java/C# for React components.
- [ ] `DP-FE-02` — Styling detector — Add early return: if `ctx.language` is not TypeScript or JavaScript, return empty vec. CSS-in-JS is exclusively a JS ecosystem concern.
- [ ] `DP-FE-03` — Accessibility detector — Add early return: if `ctx.language` is not TypeScript or JavaScript, return empty vec. ARIA attributes only exist in frontend code.
- [ ] `DP-FE-04` — Document the language guard pattern — Add a comment in each gated detector explaining why the guard exists, so future maintainers don't remove it.

### E3 — API Detector False Positive Fix

- [ ] `DP-API-FP-01` — Gate REST method detection — For API-REST-001 (REST method calls like `get`, `post`, `put`, `delete`): require the receiver to be a known router/app/server object. Current code fires on ANY function call named `get()`, which produces massive false positives on `Map.get()`, `dict.get()`, `Optional.get()`, etc.
- [ ] `DP-API-FP-02` — Add known router receivers: `app`, `router`, `server`, `route`, `api`, `express`, `fastify`, `koa`, `hapi`, `gin`, `mux`, `fiber`, `chi`, `echo`.

### Phase E Tests

- [ ] `DT-PERF-01` — Java: `list.clone()` does NOT trigger PERF-ALLOC-002
- [ ] `DT-PERF-02` — Rust: `vec.clone()` DOES trigger PERF-ALLOC-002
- [ ] `DT-PERF-03` — Python: `time.sleep(1)` in async function triggers new pattern
- [ ] `DT-FE-01` — Components detector on Go source → returns 0 matches
- [ ] `DT-FE-02` — Styling detector on Rust source → returns 0 matches
- [ ] `DT-FE-03` — Accessibility detector on Java source → returns 0 matches
- [ ] `DT-FE-04` — Components detector on TypeScript source → still returns matches (not broken)
- [ ] `DT-API-FP-01` — Python: `config.get("key")` does NOT trigger API-REST-001
- [ ] `DT-API-FP-02` — JS: `app.get("/users", handler)` DOES trigger API-REST-001
- [ ] `DT-API-FP-03` — Go: `http.Get(url)` does NOT trigger API-REST-001 (it's a client call, not route)

### Quality Gate E (QG-E)

```
MUST PASS before Phase F begins:
- [ ] Performance allocation patterns only fire for Rust
- [ ] Components/Styling/Accessibility return 0 matches for Go, Rust, Java, C#, Python, Ruby, PHP, Kotlin
- [ ] Components/Styling/Accessibility still fire correctly for TypeScript/JavaScript
- [ ] API REST method detection requires known router receiver
- [ ] False positive rate on clean Go/Java/Python code: 0 security false positives
- [ ] All DT-* tests in Phase E pass
- [ ] cargo clippy clean, cargo test green
```

---

## Phase F: Cross-Language Verification & Regression

> **Goal:** Build a comprehensive regression test suite that verifies every detector fires correctly across all 10 languages, using the reference test fixtures. Ensure no future change breaks parity.
> **Estimated effort:** 1 day
> **Files:** New test file `tests/detector_parity_test.rs`, updated reference fixtures
> **Depends on:** Phases A-E complete
> **Rationale:** The original test gap was: tests verified "something fires" but never "the right thing fires for each language." This phase closes that gap permanently.

### F1 — Enhanced Reference Test Fixtures

- [ ] `DP-FIX-01` — Update all 10 reference test fixtures to include patterns that should trigger EVERY applicable detector category. Each fixture should contain:
  - A function with a doc comment
  - An exported function
  - A function with generic type parameters (where language supports it)
  - A class/struct implementing an interface/trait (where language supports it)
  - An import of a known auth/config/logging/testing library
  - A try/catch (or equivalent) with both empty and non-empty catch
  - A call to a known ORM method
  - A known security-sensitive call (eval, exec, etc.)
  - A string literal containing an API route pattern
- [ ] `DP-FIX-02` — Add `EXPECT` comments to each fixture (like existing `// EXPECT: function_count=7`) but expanded:
  ```
  // EXPECT: function_count=7 class_count=2 import_count=3
  // EXPECT: exported_functions>=3 doc_comments>=2
  // EXPECT: generic_functions>=1 implements_count>=1
  // EXPECT: error_handling_count>=2 empty_catch=1
  ```

### F2 — Per-Language Detector Parity Test

- [ ] `DP-PARITY-01` — Create `tests/detector_parity_test.rs` — For each of the 10 languages, parse its reference fixture through the real parser, run all 16 detectors, and verify:
  - At least 5 detector categories produce matches
  - Security detector produces at least 1 match
  - Errors detector produces at least 1 match
  - Structural detector produces at least 1 match
  - Language-relevant detectors fire (e.g., Testing fires if fixture has test patterns)
- [ ] `DP-PARITY-02` — Create per-language assertion blocks within the parity test — Each language block asserts specific pattern IDs that MUST fire.
- [ ] `DP-PARITY-03` — Create negative assertion blocks — Verify frontend-only detectors do NOT fire for backend languages. Verify Rust allocation patterns do NOT fire for Java.

### F3 — Parser Extraction Completeness Test

- [ ] `DP-PARSE-01` — Create `tests/parser_extraction_completeness_test.rs` — For each of the 10 reference fixtures, assert:
  - `import.source` does NOT contain `import` or `from` keywords (it should be the module path only)
  - `import.specifiers` is non-empty for at least 1 import per file
  - At least 1 function has `is_exported = true`
  - At least 1 function has `doc_comment = Some(_)` (if fixture has doc comments)
  - `error_handling` entries have correct `kind` for the language
  - `error_handling` has at least 1 entry with `has_body = false` (if fixture has empty catch)
  - `error_handling` has at least 1 entry with `caught_type = Some(_)` (if fixture has typed catch)

### Phase F Tests

These ARE the tests — Phase F is a test-only phase.

- [ ] `DT-PARITY-TS` — TypeScript fixture: >= 6 detector categories produce matches
- [ ] `DT-PARITY-JS` — JavaScript fixture: >= 6 detector categories produce matches
- [ ] `DT-PARITY-PY` — Python fixture: >= 5 detector categories produce matches
- [ ] `DT-PARITY-JAVA` — Java fixture: >= 5 detector categories produce matches
- [ ] `DT-PARITY-CS` — C# fixture: >= 5 detector categories produce matches
- [ ] `DT-PARITY-GO` — Go fixture: >= 5 detector categories produce matches
- [ ] `DT-PARITY-RS` — Rust fixture: >= 4 detector categories produce matches
- [ ] `DT-PARITY-RB` — Ruby fixture: >= 4 detector categories produce matches
- [ ] `DT-PARITY-PHP` — PHP fixture: >= 4 detector categories produce matches
- [ ] `DT-PARITY-KT` — Kotlin fixture: >= 5 detector categories produce matches
- [ ] `DT-PARSE-TS` — TypeScript ParseResult: specifiers populated, is_exported correct, doc_comments present
- [ ] `DT-PARSE-JS` — JavaScript ParseResult: same assertions
- [ ] `DT-PARSE-PY` — Python ParseResult: same assertions + TryExcept kind
- [ ] `DT-PARSE-JAVA` — Java ParseResult: implements populated, visibility correct
- [ ] `DT-PARSE-CS` — C# ParseResult: implements populated, visibility correct
- [ ] `DT-PARSE-GO` — Go ParseResult: exported by case, multi-import parsed
- [ ] `DT-PARSE-RS` — Rust ParseResult: pub visibility, ? operator, generic_params
- [ ] `DT-PARSE-RB` — Ruby ParseResult: require as imports, rescue with caught_type
- [ ] `DT-PARSE-PHP` — PHP ParseResult: use declarations as imports
- [ ] `DT-PARSE-KT` — Kotlin ParseResult: imports, visibility, generic_params
- [ ] `DT-NEGATIVE-01` — Components detector on Go/Rust/Java/C#/PHP/Ruby/Kotlin → 0 matches each
- [ ] `DT-NEGATIVE-02` — Styling detector on Go/Rust/Java/C#/PHP/Ruby/Kotlin → 0 matches each
- [ ] `DT-NEGATIVE-03` — Accessibility detector on Go/Rust/Java/C#/PHP/Ruby/Kotlin → 0 matches each
- [ ] `DT-NEGATIVE-04` — Performance alloc patterns on Java/JS/Python → 0 matches each
- [ ] `DT-NEGATIVE-05` — API REST method on `dict.get("key")` in Python → 0 matches
- [ ] `DT-SINK-PARITY` — Every language has >= 3 taint sinks
- [ ] `DT-REGRESSION-01` — All existing 48 test files still pass (no regressions)
- [ ] `DT-REGRESSION-02` — E2E full pipeline test still passes
- [ ] `DT-REGRESSION-03` — Parse throughput benchmark: <= 10% slower than baseline
- [ ] `DT-REGRESSION-04` — Total pattern match count on e2e corpus INCREASES (more detections, not fewer)

### Quality Gate F (QG-F) — FINAL

```
ALL must pass — this is the completion gate:
- [ ] Every language achieves >= 4 active detector categories producing real matches
- [ ] TS/JS achieve >= 6 active categories (frontend detectors apply)
- [ ] Every ParseResult field that has data in the fixture is correctly populated
- [ ] Zero frontend detector matches on backend-only languages
- [ ] Taint sink count >= 50 across all languages
- [ ] All 48 existing test files pass (zero regressions)
- [ ] E2E full pipeline test passes
- [ ] New detector_parity_test.rs passes (30 assertions)
- [ ] New parser_extraction_completeness_test.rs passes (10 language blocks)
- [ ] cargo clippy --workspace -- -D warnings clean
- [ ] cargo test --workspace passes
- [ ] Total effort matches estimate: 3-5 days
```

---

## Dependency Graph

```
Phase A (Parser Foundation) ──→ Phase B (Detector Lists) ──→ Phase E (FP Reduction)
       │                                │                            │
       └──→ Phase C (Error Handling) ───┘                            │
                                        │                            │
                                  Phase D (Taint Sinks) ─────────────┘
                                                                     │
                                                               Phase F (Verification)
```

**Critical path:** A (1.5-2d) → B (1-1.5d) → E (0.5d) → F (1d) = **4-5 days**
**Parallel work:** C and D can run in parallel with B after A completes.
**Total calendar time:** 3-5 working days.

---

## Files Modified Summary

| File | Phase | Change Type |
|------|-------|-------------|
| `parsers/languages/mod.rs` | A, C | Extraction logic (largest change) |
| `detectors/auth/mod.rs` | B | Data addition (import lists) |
| `detectors/api/mod.rs` | B, E | Data addition + FP gating |
| `detectors/config/mod.rs` | B | Data addition (import lists) |
| `detectors/logging/mod.rs` | B | Data addition (import lists) |
| `detectors/data_access/mod.rs` | B | Data addition (ORM methods) |
| `detectors/testing/mod.rs` | B | Data addition (framework lists) |
| `detectors/security/mod.rs` | B | Data addition (cmd injection) |
| `detectors/performance/mod.rs` | E | Language gating |
| `detectors/components/mod.rs` | E | Language guard (early return) |
| `detectors/styling/mod.rs` | E | Language guard (early return) |
| `detectors/accessibility/mod.rs` | E | Language guard (early return) |
| `language_provider/taint_sinks.rs` | D | Data addition (sink entries) |
| `tests/detector_parity_test.rs` | F | New test file |
| `tests/parser_extraction_completeness_test.rs` | F | New test file |
| `test-fixtures/*/Reference.*` | F | Enhanced fixtures |
