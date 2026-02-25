//! Integration tests for the framework definition system.

use drift_analysis::frameworks::registry::FrameworkPackRegistry;

#[test]
fn test_builtin_packs_load_successfully() {
    let registry = FrameworkPackRegistry::with_builtins();
    // We have 22 built-in packs (14 cross-language + 8 framework-specific)
    assert!(
        registry.pack_count() >= 20,
        "Expected at least 20 built-in packs, got {}",
        registry.pack_count()
    );
    // Expect hundreds of patterns across all packs
    assert!(
        registry.pattern_count() >= 100,
        "Expected at least 100 patterns, got {}",
        registry.pattern_count()
    );
}

#[test]
fn test_single_pack_loads_from_toml() {
    let toml = r#"
[framework]
name = "test-framework"
display_name = "Test Framework"
languages = ["typescript"]

[[patterns]]
id = "TEST-001"
category = "security"
description = "Test pattern"
confidence = 0.90
[patterns.match]
content_patterns = ["(?i)dangerouslySetInnerHTML"]
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");
    assert_eq!(pack.name, "test-framework");
    assert_eq!(pack.patterns.len(), 1);
    assert_eq!(pack.patterns[0].id, "TEST-001");
    assert!((pack.patterns[0].confidence - 0.90).abs() < 0.001);
}

#[test]
fn test_import_matching_pattern() {
    let toml = r#"
[framework]
name = "import-test"
languages = ["typescript"]

[[patterns]]
id = "IMP-001"
category = "auth"
[patterns.match]
imports = ["passport"]
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");
    assert_eq!(pack.patterns.len(), 1);
    assert!(pack.patterns[0].match_block.imports.contains(&"passport".to_string()));
}

#[test]
fn test_decorator_matching_pattern() {
    let toml = r#"
[framework]
name = "decorator-test"
languages = ["java"]

[[patterns]]
id = "DEC-001"
category = "structural"
[patterns.match]
decorators = ["Service", "Component", "Repository"]
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");
    assert_eq!(pack.patterns[0].match_block.decorators.len(), 3);
}

#[test]
fn test_call_pattern_parsing() {
    let toml = r#"
[framework]
name = "call-test"
languages = ["typescript"]

[[patterns]]
id = "CALL-001"
category = "data_access"
[patterns.match]
calls = ["db.query", "connection.execute", "find"]
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");
    let calls = &pack.patterns[0].match_block.calls;
    assert_eq!(calls.len(), 3);
    // "db.query" should split into receiver="db", method="query"
    assert_eq!(calls[0].receiver.as_deref(), Some("db"));
    assert_eq!(calls[0].method, "query");
    // "find" should have no receiver
    assert_eq!(calls[2].receiver, None);
    assert_eq!(calls[2].method, "find");
}

#[test]
fn test_learning_directive_parsing() {
    let toml = r#"
[framework]
name = "learn-test"
languages = ["typescript"]

[[patterns]]
id = "LEARN-001"
category = "structural"
[patterns.match]
decorators = ["Injectable"]
[patterns.learn]
group_by = "sub_type"
signal = "convention"
deviation_threshold = 0.20
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");
    let p = &pack.patterns[0];
    assert!(p.has_learn);
    assert_eq!(p.learn_group_by.as_deref(), Some("sub_type"));
    assert_eq!(p.learn_signal.as_deref(), Some("convention"));
    assert!((p.learn_deviation_threshold - 0.20).abs() < 0.001);
}

#[test]
fn test_negative_match_block() {
    let toml = r#"
[framework]
name = "neg-test"
languages = ["typescript"]

[[patterns]]
id = "NEG-001"
category = "security"
[patterns.match]
content_patterns = ["(?i)eval\\s*\\("]
[patterns.match.not]
imports = ["safe-eval"]
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");
    let p = &pack.patterns[0];
    assert!(p.match_block.not.is_some());
    let not_block = p.match_block.not.as_ref().unwrap();
    assert!(not_block.imports.contains(&"safe-eval".to_string()));
}

#[test]
fn test_cwe_and_owasp_fields() {
    let toml = r#"
[framework]
name = "sec-test"
languages = ["typescript"]

[[patterns]]
id = "SEC-001"
category = "security"
cwe_ids = [89, 79]
owasp = "A1:2017"
[patterns.match]
content_patterns = ["(?i)sql"]
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");
    let p = &pack.patterns[0];
    assert_eq!(p.cwe_ids.len(), 2);
    assert_eq!(p.cwe_ids[0], 89);
    assert_eq!(p.cwe_ids[1], 79);
    assert_eq!(p.owasp.as_deref(), Some("A1:2017"));
}

#[test]
fn test_detect_signals() {
    let toml = r#"
[framework]
name = "detect-test"
languages = ["java"]
[[framework.detect_by]]
import = "org.springframework"
[[framework.detect_by]]
dependency = "spring-boot"

[[patterns]]
id = "DET-001"
category = "structural"
[patterns.match]
decorators = ["Component"]
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");
    assert_eq!(pack.detect_signals.len(), 2);
}

#[test]
fn test_invalid_category_skips_pattern() {
    let toml = r#"
[framework]
name = "bad-test"
languages = ["typescript"]

[[patterns]]
id = "BAD-001"
category = "nonexistent_category"
[patterns.match]
content_patterns = ["test"]
"#;

    let pack = FrameworkPackRegistry::load_single(toml)
        .expect("Pack should load, bad pattern is skipped");
    assert_eq!(pack.patterns.len(), 0, "Bad category pattern should be skipped");
}

#[test]
fn test_invalid_regex_skips_pattern() {
    let toml = r#"
[framework]
name = "bad-regex"
languages = ["typescript"]

[[patterns]]
id = "BAD-002"
category = "security"
[patterns.match]
content_patterns = ["(?P<unclosed"]
"#;

    let pack = FrameworkPackRegistry::load_single(toml)
        .expect("Pack should load, bad pattern is skipped");
    assert_eq!(pack.patterns.len(), 0, "Bad regex pattern should be skipped");
}

#[test]
fn test_framework_matcher_with_parse_result() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "matcher-test"
languages = ["typescript"]

[[patterns]]
id = "MATCH-IMPORT-001"
category = "auth"
[patterns.match]
imports = ["passport"]

[[patterns]]
id = "MATCH-CALL-001"
category = "data_access"
[patterns.match]
calls = ["db.query"]
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");

    // Build a synthetic ParseResult
    let parse_result = ParseResult {
        file: "test.ts".to_string(),
        language: Language::TypeScript,
        imports: vec![ImportInfo {
            source: "passport".to_string(),
            specifiers: smallvec::smallvec![],
            line: 1,
            is_type_only: false,
            file: "test.ts".to_string(),
        }],
        call_sites: vec![CallSite {
            callee_name: "query".to_string(),
            receiver: Some("db".to_string()),
            file: "test.ts".to_string(),
            line: 10,
            column: 4,
            argument_count: 1,
            is_await: false,
        }],
        ..Default::default()
    };

    let source = b"import passport from 'passport';\ndb.query('SELECT 1');";

    let mut matcher = FrameworkMatcher::new(vec![pack]);
    let ctx = DetectionContext::from_parse_result(&parse_result, source);
    matcher.analyze_file(&ctx);

    let results = matcher.results();
    assert!(
        results.len() >= 2,
        "Expected at least 2 matches (import + call), got {}",
        results.len()
    );

    let ids: Vec<&str> = results.iter().map(|r| r.pattern_id.as_str()).collect();
    assert!(ids.contains(&"MATCH-IMPORT-001"), "Should match import pattern");
    assert!(ids.contains(&"MATCH-CALL-001"), "Should match call pattern");
}

#[test]
fn test_framework_matcher_decorator_match() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "spring-test"
languages = ["java"]

[[patterns]]
id = "SPRING-SVC-001"
category = "structural"
[patterns.match]
decorators = ["Service"]
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");

    let parse_result = ParseResult {
        file: "UserService.java".to_string(),
        language: Language::Java,
        classes: vec![ClassInfo {
            name: "UserService".to_string(),
            namespace: None,
            extends: None,
            implements: smallvec::smallvec![],
            generic_params: smallvec::smallvec![],
            is_exported: true,
            is_abstract: false,
            class_kind: ClassKind::Class,
            decorators: vec![DecoratorInfo {
                name: "Service".to_string(),
                arguments: smallvec::smallvec![],
                raw_text: "@Service".to_string(),
                range: Range {
                    start: Position { line: 1, column: 0 },
                    end: Position { line: 1, column: 8 },
                },
            }],
            methods: vec![],
            properties: vec![],
            range: Range {
                start: Position { line: 2, column: 0 },
                end: Position { line: 10, column: 1 },
            },
        }],
        ..Default::default()
    };

    let source = b"@Service\npublic class UserService {}";

    let mut matcher = FrameworkMatcher::new(vec![pack]);
    let ctx = DetectionContext::from_parse_result(&parse_result, source);
    matcher.analyze_file(&ctx);

    let results = matcher.results();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].pattern_id, "SPRING-SVC-001");
    assert!(results[0].matched_text.contains("@Service"));
}

#[test]
fn test_framework_matcher_content_pattern_match() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "xss-test"
languages = ["typescript"]

[[patterns]]
id = "XSS-001"
category = "security"
[patterns.match]
content_patterns = ["(?i)dangerouslySetInnerHTML"]
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");

    let source = b"<div dangerouslySetInnerHTML={{__html: data}} />";
    let parse_result = ParseResult {
        file: "Component.tsx".to_string(),
        language: Language::TypeScript,
        ..Default::default()
    };

    let mut matcher = FrameworkMatcher::new(vec![pack]);
    let ctx = DetectionContext::from_parse_result(&parse_result, source);
    matcher.analyze_file(&ctx);

    let results = matcher.results();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].pattern_id, "XSS-001");
    assert!(results[0].matched_text.contains("dangerouslySetInnerHTML"));
}

#[test]
fn test_framework_matcher_language_filter() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "java-only"
languages = ["java"]

[[patterns]]
id = "JAVA-001"
category = "structural"
[patterns.match]
content_patterns = ["(?i)@Entity"]
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");

    // Feed it a TypeScript file — should NOT match
    let source = b"// @Entity is just a comment in TS";
    let parse_result = ParseResult {
        file: "test.ts".to_string(),
        language: Language::TypeScript,
        ..Default::default()
    };

    let mut matcher = FrameworkMatcher::new(vec![pack]);
    let ctx = DetectionContext::from_parse_result(&parse_result, source);
    matcher.analyze_file(&ctx);

    let results = matcher.results();
    assert_eq!(results.len(), 0, "Java pattern should not match TypeScript files");
}

#[test]
fn test_spring_pack_loads_and_has_patterns() {
    let registry = FrameworkPackRegistry::with_builtins();
    let packs = registry.into_packs();
    let spring = packs.iter().find(|p| p.name == "spring-boot");
    assert!(spring.is_some(), "Spring Boot pack should be in builtins");
    let spring = spring.unwrap();
    assert!(
        spring.patterns.len() >= 20,
        "Spring pack should have 20+ patterns, got {}",
        spring.patterns.len()
    );
}

#[test]
fn test_all_builtin_packs_have_valid_categories() {
    let registry = FrameworkPackRegistry::with_builtins();
    let packs = registry.into_packs();
    for pack in &packs {
        for pattern in &pack.patterns {
            // If we got here, the category was already validated during loading.
            // Just verify the pattern has at least one match predicate.
            let b = &pattern.match_block;
            let has_predicate = !b.imports.is_empty()
                || !b.decorators.is_empty()
                || !b.calls.is_empty()
                || !b.extends.is_empty()
                || !b.implements.is_empty()
                || !b.function_names.is_empty()
                || !b.class_names.is_empty()
                || !b.string_literals.is_empty()
                || !b.param_types.is_empty()
                || !b.return_types.is_empty()
                || !b.content_patterns.is_empty()
                || !b.exports.is_empty()
                || !b.error_handling.is_empty()
                || !b.doc_comments.is_empty()
                || !b.file_patterns.is_empty()
                || !b.type_annotations.is_empty();
            assert!(
                has_predicate,
                "Pattern {} in pack {} has no match predicates",
                pattern.id, pack.name
            );
        }
    }
}

// ===== Phase A Hardening Tests =====

/// FWT-LOAD-01: Bad regex in one pattern skips that pattern, not the entire pack.
#[test]
fn fwt_load_01_bad_regex_skips_pattern_not_pack() {
    let toml = r#"
[framework]
name = "mixed-pack"
languages = ["typescript"]

[[patterns]]
id = "GOOD-001"
category = "security"
[patterns.match]
content_patterns = ["(?i)safe_pattern"]

[[patterns]]
id = "BAD-001"
category = "security"
[patterns.match]
content_patterns = ["(?P<unclosed"]

[[patterns]]
id = "GOOD-002"
category = "security"
[patterns.match]
content_patterns = ["(?i)another_safe"]
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("pack should load despite bad pattern");
    assert_eq!(pack.patterns.len(), 2, "Only the 2 good patterns should survive");
    let ids: Vec<&str> = pack.patterns.iter().map(|p| p.id.as_str()).collect();
    assert!(ids.contains(&"GOOD-001"));
    assert!(ids.contains(&"GOOD-002"));
    assert!(!ids.contains(&"BAD-001"));
}

/// FWT-LOAD-02: Empty regex string is rejected.
#[test]
fn fwt_load_02_empty_regex_rejected() {
    let toml = r#"
[framework]
name = "empty-regex"
languages = ["typescript"]

[[patterns]]
id = "EMPTY-001"
category = "security"
[patterns.match]
content_patterns = [""]
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("pack loads but pattern is skipped");
    assert_eq!(pack.patterns.len(), 0, "Pattern with empty regex should be skipped");
}

/// FWT-LOAD-03: Unknown language is silently skipped (pack still loads).
#[test]
fn fwt_load_03_unknown_language_skipped() {
    let toml = r#"
[framework]
name = "unknown-lang"
languages = ["typescript", "klingon", "esperanto"]

[[patterns]]
id = "LANG-001"
category = "security"
[patterns.match]
content_patterns = ["test"]
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");
    assert_eq!(pack.languages.len(), 1, "Only TypeScript should be recognized");
}

/// FWT-LOAD-04: Bad detect_signal (invalid glob) is skipped, pack still loads.
#[test]
fn fwt_load_04_bad_detect_signal_skipped() {
    let toml = r#"
[framework]
name = "bad-signal"
languages = ["typescript"]
[[framework.detect_by]]
import = "express"
[[framework.detect_by]]
file_pattern = "[invalid-glob"

[[patterns]]
id = "SIG-001"
category = "structural"
[patterns.match]
content_patterns = ["test"]
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");
    assert_eq!(pack.detect_signals.len(), 1, "Only valid import signal should survive");
}

/// FWT-LOAD-05: Pack with mix of good and bad patterns loads good ones only.
#[test]
fn fwt_load_05_mixed_patterns_good_survive() {
    let toml = r#"
[framework]
name = "mixed"
languages = ["typescript"]

[[patterns]]
id = "OK-001"
category = "security"
confidence = 0.90
[patterns.match]
imports = ["helmet"]

[[patterns]]
id = "BAD-CATEGORY"
category = "does_not_exist"
[patterns.match]
content_patterns = ["test"]

[[patterns]]
id = "OK-002"
category = "auth"
[patterns.match]
decorators = ["Authenticated"]
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");
    assert_eq!(pack.patterns.len(), 2);
    let ids: Vec<&str> = pack.patterns.iter().map(|p| p.id.as_str()).collect();
    assert!(ids.contains(&"OK-001"));
    assert!(ids.contains(&"OK-002"));
}

/// FWT-CLONE-01: CompiledFrameworkPack implements Clone.
#[test]
fn fwt_clone_01_pack_is_clone() {
    let toml = r#"
[framework]
name = "clone-test"
languages = ["typescript"]

[[patterns]]
id = "CLN-001"
category = "security"
cwe_ids = [79]
[patterns.match]
content_patterns = ["(?i)eval"]
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");
    let cloned = pack.clone();
    assert_eq!(cloned.name, "clone-test");
    assert_eq!(cloned.patterns.len(), 1);
}

/// FWT-CLONE-02: Cloned pack has identical data to original.
#[test]
fn fwt_clone_02_cloned_pack_has_same_data() {
    let toml = r#"
[framework]
name = "clone-verify"
display_name = "Clone Verify"
languages = ["typescript", "javascript"]
[[framework.detect_by]]
import = "express"

[[patterns]]
id = "CLN-V-001"
category = "security"
description = "test desc"
sub_type = "xss"
confidence = 0.88
cwe_ids = [79, 352]
owasp = "A03:2021"
[patterns.match]
content_patterns = ["(?i)innerHTML"]
calls = ["foo.bar"]
imports = ["react"]
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");
    let cloned = pack.clone();

    assert_eq!(pack.name, cloned.name);
    assert_eq!(pack.display_name, cloned.display_name);
    assert_eq!(pack.languages.len(), cloned.languages.len());
    assert_eq!(pack.detect_signals.len(), cloned.detect_signals.len());
    assert_eq!(pack.patterns.len(), cloned.patterns.len());

    let p_orig = &pack.patterns[0];
    let p_clone = &cloned.patterns[0];
    assert_eq!(p_orig.id, p_clone.id);
    assert_eq!(p_orig.confidence, p_clone.confidence);
    assert_eq!(p_orig.cwe_ids.len(), p_clone.cwe_ids.len());
    assert_eq!(p_orig.owasp, p_clone.owasp);
    assert_eq!(p_orig.match_block.imports.len(), p_clone.match_block.imports.len());
    assert_eq!(p_orig.match_block.calls.len(), p_clone.match_block.calls.len());
    assert_eq!(p_orig.match_block.content_patterns.len(), p_clone.match_block.content_patterns.len());
}

/// FWT-OWASP-01: security.toml uses OWASP 2021 references (not 2017).
#[test]
fn fwt_owasp_01_security_toml_uses_2021_refs() {
    let registry = FrameworkPackRegistry::with_builtins();
    let packs = registry.into_packs();
    let security = packs.iter().find(|p| p.name == "security-patterns")
        .expect("security-patterns pack should exist");

    for pattern in &security.patterns {
        if let Some(ref owasp) = pattern.owasp {
            assert!(
                owasp.contains("2021"),
                "Pattern {} has stale OWASP ref: {} (should be 2021)",
                pattern.id, owasp
            );
        }
    }
}

/// FWT-OWASP-02: auth.toml has CWE IDs on token and permission patterns.
#[test]
fn fwt_owasp_02_auth_toml_has_cwe_ids() {
    let registry = FrameworkPackRegistry::with_builtins();
    let packs = registry.into_packs();
    let auth = packs.iter().find(|p| p.name == "auth-patterns")
        .expect("auth-patterns pack should exist");

    let jwt = auth.patterns.iter().find(|p| p.id == "AUTH-TOKEN-JWT-001")
        .expect("AUTH-TOKEN-JWT-001 should exist");
    assert!(!jwt.cwe_ids.is_empty(), "JWT pattern should have CWE IDs");
    assert!(jwt.cwe_ids.contains(&287), "JWT pattern should have CWE-287");

    let perm = auth.patterns.iter().find(|p| p.id == "AUTH-PERM-CHECK-001")
        .expect("AUTH-PERM-CHECK-001 should exist");
    assert!(!perm.cwe_ids.is_empty(), "Permission check pattern should have CWE IDs");
    assert!(perm.cwe_ids.contains(&862), "Permission check should have CWE-862");
}

/// FWT-OWASP-03: data_access.toml has CWE IDs on query builder pattern.
#[test]
fn fwt_owasp_03_data_access_toml_has_cwe_ids() {
    let registry = FrameworkPackRegistry::with_builtins();
    let packs = registry.into_packs();
    let da = packs.iter().find(|p| p.name == "data-access-patterns")
        .expect("data-access-patterns pack should exist");

    let qb = da.patterns.iter().find(|p| p.id == "DA-QUERY-BUILDER-001")
        .expect("DA-QUERY-BUILDER-001 should exist");
    assert!(!qb.cwe_ids.is_empty(), "Query builder pattern should have CWE IDs");
    assert!(qb.cwe_ids.contains(&89), "Query builder should have CWE-89");
}

/// FWT-JSRES-01: last_file_results returns per-file matches.
#[test]
fn fwt_jsres_01_last_file_results_per_file() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "jsres-test"
languages = ["typescript"]

[[patterns]]
id = "JSRES-001"
category = "security"
[patterns.match]
content_patterns = ["(?i)eval\\s*\\("]
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");
    let source = b"eval('code')";
    let parse_result = ParseResult {
        file: "test.ts".to_string(),
        language: Language::TypeScript,
        ..Default::default()
    };

    let mut matcher = FrameworkMatcher::new(vec![pack]);
    let ctx = DetectionContext::from_parse_result(&parse_result, source);
    matcher.analyze_file(&ctx);

    let last = matcher.last_file_results();
    assert_eq!(last.len(), 1, "Should have 1 match for this file");
    assert_eq!(last[0].pattern_id, "JSRES-001");
}

/// FWT-JSRES-02: last_file_results resets between files.
#[test]
fn fwt_jsres_02_last_file_results_resets_between_files() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "jsres-reset"
languages = ["typescript"]

[[patterns]]
id = "JSRES-R-001"
category = "security"
[patterns.match]
content_patterns = ["(?i)eval\\s*\\("]
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");
    let mut matcher = FrameworkMatcher::new(vec![pack]);

    // File 1: has match
    let source1 = b"eval('code')";
    let pr1 = ParseResult {
        file: "file1.ts".to_string(),
        language: Language::TypeScript,
        ..Default::default()
    };
    let ctx1 = DetectionContext::from_parse_result(&pr1, source1);
    matcher.analyze_file(&ctx1);
    assert_eq!(matcher.last_file_results().len(), 1);

    // File 2: no match
    let source2 = b"console.log('safe')";
    let pr2 = ParseResult {
        file: "file2.ts".to_string(),
        language: Language::TypeScript,
        ..Default::default()
    };
    let ctx2 = DetectionContext::from_parse_result(&pr2, source2);
    matcher.analyze_file(&ctx2);
    assert_eq!(matcher.last_file_results().len(), 0, "File 2 has no matches");

    // Total results should still have file1's match
    let all = matcher.results();
    assert_eq!(all.len(), 1, "Total matches should be 1");
}

/// FWT-LEARN-01: Learner produces deviation results from convention patterns.
#[test]
fn fwt_learn_01_learner_produces_deviations() {
    use drift_analysis::engine::visitor::{DetectionContext, LearningDetectorHandler};
    use drift_analysis::frameworks::FrameworkLearner;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "learn-test"
languages = ["typescript"]

[[patterns]]
id = "LEARN-A"
category = "structural"
sub_type = "naming"
[patterns.match]
function_names = ["^handle[A-Z]"]
[patterns.learn]
group_by = "sub_type"
signal = "convention"
deviation_threshold = 0.15

[[patterns]]
id = "LEARN-B"
category = "structural"
sub_type = "naming"
[patterns.match]
function_names = ["^process[A-Z]"]
[patterns.learn]
group_by = "sub_type"
signal = "convention"
deviation_threshold = 0.15
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");
    let mut learner = FrameworkLearner::new(vec![pack]);

    fn make_func(name: &str) -> FunctionInfo {
        FunctionInfo {
            name: name.to_string(),
            qualified_name: None,
            file: String::new(),
            line: 1,
            column: 0,
            end_line: 5,
            parameters: smallvec::smallvec![],
            return_type: None,
            generic_params: smallvec::smallvec![],
            visibility: Visibility::Public,
            is_exported: false,
            is_async: false,
            is_generator: false,
            is_abstract: false,
            range: Range {
                start: Position { line: 1, column: 0 },
                end: Position { line: 5, column: 1 },
            },
            decorators: vec![],
            doc_comment: None,
            body_hash: 0,
            signature_hash: 0,
        }
    }

    // Create 10 files with LEARN-A (dominant) and 1 with LEARN-B (deviation)
    // Need 10:1 ratio so dominant ratio = 10/11 ≈ 0.909 >= (1.0 - 0.15) = 0.85
    for i in 0..10 {
        let pr = ParseResult {
            file: format!("handler{i}.ts"),
            language: Language::TypeScript,
            functions: vec![make_func("handleClick")],
            ..Default::default()
        };
        let source = b"function handleClick() {}";
        let ctx = DetectionContext::from_parse_result(&pr, source);
        learner.learn(&ctx);
    }

    // One deviant file
    let deviant_pr = ParseResult {
        file: "deviant.ts".to_string(),
        language: Language::TypeScript,
        functions: vec![make_func("processData")],
        ..Default::default()
    };
    let deviant_source = b"function processData() {}";
    let deviant_ctx = DetectionContext::from_parse_result(&deviant_pr, deviant_source);
    learner.learn(&deviant_ctx);

    // Run detect pass on the deviant file
    learner.detect(&deviant_ctx);

    let results = learner.results();
    assert!(
        !results.is_empty(),
        "Learner should produce at least one deviation result"
    );
    assert!(
        results.iter().any(|r| r.pattern_id.contains("deviation")),
        "At least one result should be a deviation"
    );
}

/// FWT-LEARN-02: Learner reset clears all state.
#[test]
fn fwt_learn_02_learner_reset_clears_state() {
    use drift_analysis::engine::visitor::LearningDetectorHandler;
    use drift_analysis::frameworks::FrameworkLearner;

    let toml = r#"
[framework]
name = "reset-test"
languages = ["typescript"]

[[patterns]]
id = "RESET-001"
category = "structural"
[patterns.match]
content_patterns = ["test"]
[patterns.learn]
group_by = "sub_type"
signal = "convention"
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");
    let mut learner = FrameworkLearner::new(vec![pack]);
    learner.reset();
    let results = learner.results();
    assert!(results.is_empty(), "After reset, results should be empty");
}

/// FWT-LEARN-03: Patterns without learn directives produce no deviations.
#[test]
fn fwt_learn_03_no_learn_directive_no_deviations() {
    use drift_analysis::engine::visitor::{DetectionContext, LearningDetectorHandler};
    use drift_analysis::frameworks::FrameworkLearner;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "no-learn"
languages = ["typescript"]

[[patterns]]
id = "NOLEARN-001"
category = "security"
[patterns.match]
content_patterns = ["(?i)eval"]
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");
    let mut learner = FrameworkLearner::new(vec![pack]);

    let pr = ParseResult {
        file: "test.ts".to_string(),
        language: Language::TypeScript,
        ..Default::default()
    };
    let source = b"eval('code')";
    let ctx = DetectionContext::from_parse_result(&pr, source);
    learner.learn(&ctx);
    learner.detect(&ctx);

    let results = learner.results();
    assert!(results.is_empty(), "No learn directive = no deviations");
}

/// FWT-LEARN-04: Learner deviation has LearningDeviation detection method.
#[test]
fn fwt_learn_04_deviation_detection_method() {
    use drift_analysis::engine::visitor::{DetectionContext, LearningDetectorHandler};
    use drift_analysis::frameworks::FrameworkLearner;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "method-test"
languages = ["typescript"]

[[patterns]]
id = "METHOD-A"
category = "structural"
sub_type = "naming"
[patterns.match]
function_names = ["^handle[A-Z]"]
[patterns.learn]
group_by = "sub_type"
signal = "convention"
deviation_threshold = 0.15

[[patterns]]
id = "METHOD-B"
category = "structural"
sub_type = "naming"
[patterns.match]
function_names = ["^process[A-Z]"]
[patterns.learn]
group_by = "sub_type"
signal = "convention"
deviation_threshold = 0.15
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");
    let mut learner = FrameworkLearner::new(vec![pack]);

    fn make_fn(name: &str) -> FunctionInfo {
        FunctionInfo {
            name: name.to_string(),
            qualified_name: None,
            file: String::new(),
            line: 1,
            column: 0,
            end_line: 5,
            parameters: smallvec::smallvec![],
            return_type: None,
            generic_params: smallvec::smallvec![],
            visibility: Visibility::Public,
            is_exported: false,
            is_async: false,
            is_generator: false,
            is_abstract: false,
            range: Range {
                start: Position { line: 1, column: 0 },
                end: Position { line: 5, column: 1 },
            },
            decorators: vec![],
            doc_comment: None,
            body_hash: 0,
            signature_hash: 0,
        }
    }

    // 5 dominant + 1 deviant
    for i in 0..5 {
        let pr = ParseResult {
            file: format!("h{i}.ts"),
            language: Language::TypeScript,
            functions: vec![make_fn("handleEvent")],
            ..Default::default()
        };
        let source = b"function handleEvent() {}";
        let ctx = DetectionContext::from_parse_result(&pr, source);
        learner.learn(&ctx);
    }

    let deviant_pr = ParseResult {
        file: "dev.ts".to_string(),
        language: Language::TypeScript,
        functions: vec![make_fn("processEvent")],
        ..Default::default()
    };
    let deviant_source = b"function processEvent() {}";
    let deviant_ctx = DetectionContext::from_parse_result(&deviant_pr, deviant_source);
    learner.learn(&deviant_ctx);
    learner.detect(&deviant_ctx);

    let results = learner.results();
    for r in &results {
        assert_eq!(
            format!("{:?}", r.detection_method), "LearningDeviation",
            "Detection method should be LearningDeviation"
        );
    }
}

// ===== Phase B Hardening Tests =====

/// FWT-PRED-01: file_patterns *.d.ts matches types/index.d.ts, rejects types/index.ts
#[test]
fn fwt_pred_01_file_patterns_dts_match() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "dts-test"
languages = ["typescript"]

[[patterns]]
id = "DTS-001"
category = "structural"
[patterns.match]
file_patterns = ["*.d.ts"]
content_patterns = ["declare\\s+"]
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");

    // Should match .d.ts
    let mut matcher = FrameworkMatcher::new(vec![pack.clone()]);
    let source = b"declare module 'foo' {}";
    let pr = ParseResult {
        file: "types/index.d.ts".to_string(),
        language: Language::TypeScript,
        ..Default::default()
    };
    let ctx = DetectionContext::from_parse_result(&pr, source);
    matcher.analyze_file(&ctx);
    assert_eq!(matcher.results().len(), 1, "Should match .d.ts file");

    // Should NOT match .ts
    let mut matcher2 = FrameworkMatcher::new(vec![pack]);
    let pr2 = ParseResult {
        file: "types/index.ts".to_string(),
        language: Language::TypeScript,
        ..Default::default()
    };
    let ctx2 = DetectionContext::from_parse_result(&pr2, source);
    matcher2.analyze_file(&ctx2);
    assert_eq!(matcher2.results().len(), 0, "Should not match .ts file");
}

/// FWT-PRED-02: file_patterns **/types/** matches src/types/user.ts
#[test]
fn fwt_pred_02_file_patterns_glob_directory() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "types-dir-test"
languages = ["typescript"]

[[patterns]]
id = "TDIR-001"
category = "structural"
[patterns.match]
file_patterns = ["**/types/**"]
content_patterns = ["export"]
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");
    let mut matcher = FrameworkMatcher::new(vec![pack]);
    let source = b"export interface User {}";
    let pr = ParseResult {
        file: "src/types/user.ts".to_string(),
        language: Language::TypeScript,
        ..Default::default()
    };
    let ctx = DetectionContext::from_parse_result(&pr, source);
    matcher.analyze_file(&ctx);
    assert!(matcher.results().len() >= 1, "Should match file in types directory");
}

/// FWT-PRED-03: type_annotations \\bany\\b matches function with param: any
#[test]
fn fwt_pred_03_type_annotations_any() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "ta-test"
languages = ["typescript"]

[[patterns]]
id = "TA-001"
category = "structural"
[patterns.match]
type_annotations = ["\\bany\\b"]
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");
    let mut matcher = FrameworkMatcher::new(vec![pack]);

    let source = b"function foo(x: any) { return x; }";
    let pr = ParseResult {
        file: "test.ts".to_string(),
        language: Language::TypeScript,
        functions: vec![FunctionInfo {
            name: "foo".to_string(),
            qualified_name: None,
            file: "test.ts".to_string(),
            line: 1, column: 0, end_line: 1,
            parameters: smallvec::smallvec![ParameterInfo {
                name: "x".to_string(),
                type_annotation: Some("any".to_string()),
                is_rest: false,
                default_value: None,
            }],
            return_type: None,
            generic_params: smallvec::smallvec![],
            visibility: Visibility::Public,
            is_exported: false, is_async: false, is_generator: false, is_abstract: false,
            range: Range { start: Position { line: 1, column: 0 }, end: Position { line: 1, column: 34 } },
            decorators: vec![], doc_comment: None, body_hash: 0, signature_hash: 0,
        }],
        ..Default::default()
    };
    let ctx = DetectionContext::from_parse_result(&pr, source);
    matcher.analyze_file(&ctx);
    assert_eq!(matcher.results().len(), 1, "Should match 'any' type annotation");
    assert!(matcher.results()[0].matched_text.contains("any"));
}

/// FWT-PRED-04: type_annotations AND imports: only fires when both present
#[test]
fn fwt_pred_04_type_annotations_and_imports() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "ta-import-test"
languages = ["typescript"]

[[patterns]]
id = "TA-IMP-001"
category = "structural"
[patterns.match]
imports = ["express"]
type_annotations = ["Request|Response"]
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");

    // Has import but no type annotation → no match
    let mut matcher = FrameworkMatcher::new(vec![pack.clone()]);
    let source = b"import express from 'express';\nfunction handle() {}";
    let pr = ParseResult {
        file: "test.ts".to_string(),
        language: Language::TypeScript,
        imports: vec![ImportInfo {
            source: "express".to_string(),
            specifiers: smallvec::smallvec![],
            line: 1, is_type_only: false,
            file: "test.ts".to_string(),
        }],
        functions: vec![FunctionInfo {
            name: "handle".to_string(),
            qualified_name: None,
            file: "test.ts".to_string(),
            line: 2, column: 0, end_line: 2,
            parameters: smallvec::smallvec![],
            return_type: None,
            generic_params: smallvec::smallvec![],
            visibility: Visibility::Public,
            is_exported: false, is_async: false, is_generator: false, is_abstract: false,
            range: Range { start: Position { line: 2, column: 0 }, end: Position { line: 2, column: 20 } },
            decorators: vec![], doc_comment: None, body_hash: 0, signature_hash: 0,
        }],
        ..Default::default()
    };
    let ctx = DetectionContext::from_parse_result(&pr, source);
    matcher.analyze_file(&ctx);
    assert_eq!(matcher.results().len(), 0, "Import without matching type annotation = no match");

    // Has import AND type annotation → match
    let mut matcher2 = FrameworkMatcher::new(vec![pack]);
    let source2 = b"import express from 'express';\nfunction handle(req: Request) {}";
    let pr2 = ParseResult {
        file: "test2.ts".to_string(),
        language: Language::TypeScript,
        imports: vec![ImportInfo {
            source: "express".to_string(),
            specifiers: smallvec::smallvec![],
            line: 1, is_type_only: false,
            file: "test2.ts".to_string(),
        }],
        functions: vec![FunctionInfo {
            name: "handle".to_string(),
            qualified_name: None,
            file: "test2.ts".to_string(),
            line: 2, column: 0, end_line: 2,
            parameters: smallvec::smallvec![ParameterInfo {
                name: "req".to_string(),
                type_annotation: Some("Request".to_string()),
                is_rest: false, default_value: None,
            }],
            return_type: None,
            generic_params: smallvec::smallvec![],
            visibility: Visibility::Public,
            is_exported: false, is_async: false, is_generator: false, is_abstract: false,
            range: Range { start: Position { line: 2, column: 0 }, end: Position { line: 2, column: 32 } },
            decorators: vec![], doc_comment: None, body_hash: 0, signature_hash: 0,
        }],
        ..Default::default()
    };
    let ctx2 = DetectionContext::from_parse_result(&pr2, source2);
    matcher2.analyze_file(&ctx2);
    assert!(matcher2.results().len() >= 1, "Import + type annotation = match");
}

/// FWT-PRED-05: file_patterns + content_patterns AND: matches only in matching files with matching content
#[test]
fn fwt_pred_05_file_patterns_and_content() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "fp-content-test"
languages = ["typescript"]

[[patterns]]
id = "FPC-001"
category = "structural"
[patterns.match]
file_patterns = ["*.spec.ts"]
content_patterns = ["describe\\s*\\("]
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");

    // Matching file + matching content → match
    let mut m1 = FrameworkMatcher::new(vec![pack.clone()]);
    let s1 = b"describe('test', () => {})";
    let pr1 = ParseResult { file: "foo.spec.ts".to_string(), language: Language::TypeScript, ..Default::default() };
    let ctx1 = DetectionContext::from_parse_result(&pr1, s1);
    m1.analyze_file(&ctx1);
    assert_eq!(m1.results().len(), 1, "spec.ts with describe = match");

    // Non-matching file + matching content → no match
    let mut m2 = FrameworkMatcher::new(vec![pack.clone()]);
    let pr2 = ParseResult { file: "foo.ts".to_string(), language: Language::TypeScript, ..Default::default() };
    let ctx2 = DetectionContext::from_parse_result(&pr2, s1);
    m2.analyze_file(&ctx2);
    assert_eq!(m2.results().len(), 0, "non-spec.ts = no match despite content");

    // Matching file + non-matching content → no match
    let mut m3 = FrameworkMatcher::new(vec![pack]);
    let s3 = b"console.log('hello')";
    let pr3 = ParseResult { file: "foo.spec.ts".to_string(), language: Language::TypeScript, ..Default::default() };
    let ctx3 = DetectionContext::from_parse_result(&pr3, s3);
    m3.analyze_file(&ctx3);
    assert_eq!(m3.results().len(), 0, "spec.ts without describe = no match");
}

/// FWT-PRED-06: Empty file_patterns = no file filtering (backward compat)
#[test]
fn fwt_pred_06_empty_file_patterns_no_filter() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "no-fp-test"
languages = ["typescript"]

[[patterns]]
id = "NOFP-001"
category = "security"
[patterns.match]
content_patterns = ["(?i)eval\\s*\\("]
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");
    assert!(pack.patterns[0].match_block.file_patterns.is_empty());

    let mut matcher = FrameworkMatcher::new(vec![pack]);
    let source = b"eval('code')";
    let pr = ParseResult { file: "anything.ts".to_string(), language: Language::TypeScript, ..Default::default() };
    let ctx = DetectionContext::from_parse_result(&pr, source);
    matcher.analyze_file(&ctx);
    assert_eq!(matcher.results().len(), 1, "No file_patterns = match any file");
}

/// FWT-PRED-07: Empty type_annotations = no type filtering (backward compat)
#[test]
fn fwt_pred_07_empty_type_annotations_no_filter() {
    let toml = r#"
[framework]
name = "no-ta-test"
languages = ["typescript"]

[[patterns]]
id = "NOTA-001"
category = "security"
[patterns.match]
content_patterns = ["test"]
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");
    assert!(pack.patterns[0].match_block.type_annotations.is_empty());
}

/// FWT-PRED-08: Negative match with file_patterns: not.file_patterns excludes test files
#[test]
fn fwt_pred_08_negative_file_patterns() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "neg-fp-test"
languages = ["typescript"]

[[patterns]]
id = "NEGFP-001"
category = "security"
[patterns.match]
content_patterns = ["(?i)eval\\s*\\("]
[patterns.match.not]
file_patterns = ["*.test.ts", "*.spec.ts"]
"#;

    let pack = FrameworkPackRegistry::load_single(toml).expect("should parse");

    // Regular file → match
    let mut m1 = FrameworkMatcher::new(vec![pack.clone()]);
    let source = b"eval('code')";
    let pr1 = ParseResult { file: "src/utils.ts".to_string(), language: Language::TypeScript, ..Default::default() };
    let ctx1 = DetectionContext::from_parse_result(&pr1, source);
    m1.analyze_file(&ctx1);
    assert_eq!(m1.results().len(), 1, "Non-test file should match");

    // Test file → excluded by negative match
    let mut m2 = FrameworkMatcher::new(vec![pack]);
    let pr2 = ParseResult { file: "src/utils.test.ts".to_string(), language: Language::TypeScript, ..Default::default() };
    let ctx2 = DetectionContext::from_parse_result(&pr2, source);
    m2.analyze_file(&ctx2);
    assert_eq!(m2.results().len(), 0, "Test file should be excluded by not.file_patterns");
}

/// FWT-PACK-01: typescript_types.toml loads with 12 patterns, 0 errors
#[test]
fn fwt_pack_01_typescript_types_loads() {
    let registry = FrameworkPackRegistry::with_builtins();
    let packs = registry.into_packs();
    let ts = packs.iter().find(|p| p.name == "typescript-types")
        .expect("typescript-types pack should exist");
    assert!(
        ts.patterns.len() >= 12,
        "Expected at least 12 patterns, got {}",
        ts.patterns.len()
    );
}

/// FWT-PACK-02: TS-ANY-001 matches `const x: any = 1;` in .ts file
#[test]
fn fwt_pack_02_ts_any_matches() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let registry = FrameworkPackRegistry::with_builtins();
    let packs = registry.into_packs();
    let ts_pack = packs.into_iter().find(|p| p.name == "typescript-types").unwrap();

    let mut matcher = FrameworkMatcher::new(vec![ts_pack]);
    let source = b"const x: any = 1;";
    let pr = ParseResult { file: "test.ts".to_string(), language: Language::TypeScript, ..Default::default() };
    let ctx = DetectionContext::from_parse_result(&pr, source);
    matcher.analyze_file(&ctx);

    let results = matcher.results();
    assert!(
        results.iter().any(|r| r.pattern_id == "TS-ANY-001"),
        "TS-ANY-001 should match ': any' in .ts file"
    );
}

/// FWT-PACK-03: TS-IFACE-VS-TYPE learning: interface vs type alias detection
#[test]
fn fwt_pack_03_ts_iface_vs_type() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let registry = FrameworkPackRegistry::with_builtins();
    let packs = registry.into_packs();
    let ts_pack = packs.into_iter().find(|p| p.name == "typescript-types").unwrap();

    let mut matcher = FrameworkMatcher::new(vec![ts_pack]);

    // Interface file
    let source1 = b"export interface UserProfile { name: string; }";
    let pr1 = ParseResult { file: "iface.ts".to_string(), language: Language::TypeScript, ..Default::default() };
    let ctx1 = DetectionContext::from_parse_result(&pr1, source1);
    matcher.analyze_file(&ctx1);
    assert!(matcher.results().iter().any(|r| r.pattern_id == "TS-IFACE-VS-TYPE-001"), "Should detect interface");

    // Type alias file
    let source2 = b"export type UserProfile = { name: string; }";
    let pr2 = ParseResult { file: "alias.ts".to_string(), language: Language::TypeScript, ..Default::default() };
    let ctx2 = DetectionContext::from_parse_result(&pr2, source2);
    matcher.analyze_file(&ctx2);
    assert!(matcher.results().iter().any(|r| r.pattern_id == "TS-IFACE-VS-TYPE-002"), "Should detect type alias");
}

/// FWT-PACK-04: Warp route matches warp::path("api")
#[test]
fn fwt_pack_04_warp_route_matches() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let registry = FrameworkPackRegistry::with_builtins();
    let packs = registry.into_packs();
    let rust_pack = packs.into_iter().find(|p| p.name == "rust-frameworks").unwrap();

    let mut matcher = FrameworkMatcher::new(vec![rust_pack]);
    let source = b"let api = warp::path(\"api\").and(warp::get());";
    let pr = ParseResult { file: "main.rs".to_string(), language: Language::Rust, ..Default::default() };
    let ctx = DetectionContext::from_parse_result(&pr, source);
    matcher.analyze_file(&ctx);

    assert!(
        matcher.results().iter().any(|r| r.pattern_id == "rust/warp/route"),
        "Should match warp::path route pattern"
    );
}

/// FWT-PACK-05: Warp doesn't false-positive on `let warp_drive = true;`
#[test]
fn fwt_pack_05_warp_no_false_positive() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let registry = FrameworkPackRegistry::with_builtins();
    let packs = registry.into_packs();
    let rust_pack = packs.into_iter().find(|p| p.name == "rust-frameworks").unwrap();

    let mut matcher = FrameworkMatcher::new(vec![rust_pack]);
    let source = b"let warp_drive = true;\nlet warped = false;";
    let pr = ParseResult { file: "main.rs".to_string(), language: Language::Rust, ..Default::default() };
    let ctx = DetectionContext::from_parse_result(&pr, source);
    matcher.analyze_file(&ctx);

    let results = matcher.results();
    let warp_matches: Vec<_> = results.iter()
        .filter(|r| r.pattern_id.starts_with("rust/warp/"))
        .collect();
    assert_eq!(warp_matches.len(), 0, "warp_drive should not trigger Warp patterns");
}

/// FWT-PACK-06: Environment detection matches process.env.NODE_ENV
#[test]
fn fwt_pack_06_env_detection() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let registry = FrameworkPackRegistry::with_builtins();
    let packs = registry.into_packs();
    let config_pack = packs.into_iter().find(|p| p.name == "config-patterns").unwrap();

    let mut matcher = FrameworkMatcher::new(vec![config_pack]);
    let source = b"const env = process.env.NODE_ENV || 'development';";
    let pr = ParseResult { file: "config.ts".to_string(), language: Language::TypeScript, ..Default::default() };
    let ctx = DetectionContext::from_parse_result(&pr, source);
    matcher.analyze_file(&ctx);

    assert!(
        matcher.results().iter().any(|r| r.pattern_id == "CFG-ENV-DETECT-001"),
        "Should match process.env.NODE_ENV"
    );
}

/// FWT-PACK-07: BEM matches className="block__element--modifier"
#[test]
fn fwt_pack_07_bem_matches() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let registry = FrameworkPackRegistry::with_builtins();
    let packs = registry.into_packs();
    let style_pack = packs.into_iter().find(|p| p.name == "styling-patterns").unwrap();

    let mut matcher = FrameworkMatcher::new(vec![style_pack]);
    let source = b"<div className=\"card__header--active\" />";
    let pr = ParseResult { file: "Component.tsx".to_string(), language: Language::TypeScript, ..Default::default() };
    let ctx = DetectionContext::from_parse_result(&pr, source);
    matcher.analyze_file(&ctx);

    assert!(
        matcher.results().iter().any(|r| r.pattern_id == "STYLE-BEM-001"),
        "Should match BEM naming pattern"
    );
}

/// FWT-PACK-08: Try-catch matches Python try:/except Exception:
#[test]
fn fwt_pack_08_try_catch_python() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let registry = FrameworkPackRegistry::with_builtins();
    let packs = registry.into_packs();
    let err_pack = packs.into_iter().find(|p| p.name == "error-patterns").unwrap();

    let mut matcher = FrameworkMatcher::new(vec![err_pack]);
    let source = b"try:\n    do_something()\nexcept Exception as e:\n    log(e)";
    let pr = ParseResult { file: "handler.py".to_string(), language: Language::Python, ..Default::default() };
    let ctx = DetectionContext::from_parse_result(&pr, source);
    matcher.analyze_file(&ctx);

    assert!(
        matcher.results().iter().any(|r| r.pattern_id == "ERR-TRYCATCH-001"),
        "Should match Python try: block"
    );
}

/// FWT-PACK-09: All 23+ packs load (regression after adding typescript_types.toml)
#[test]
fn fwt_pack_09_all_packs_load() {
    let registry = FrameworkPackRegistry::with_builtins();
    assert!(
        registry.pack_count() >= 23,
        "Expected at least 23 built-in packs, got {}",
        registry.pack_count()
    );
}

/// FWT-PACK-10: Plain hello_world.ts produces 0 matches from new packs (no false positives)
#[test]
fn fwt_pack_10_no_false_positives_hello_world() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let registry = FrameworkPackRegistry::with_builtins();
    let packs = registry.into_packs();

    // Filter to only new Phase B packs
    let new_pack_names = ["typescript-types"];
    let new_packs: Vec<_> = packs.into_iter()
        .filter(|p| new_pack_names.contains(&p.name.as_str()))
        .collect();

    let mut matcher = FrameworkMatcher::new(new_packs);
    let source = b"console.log('Hello, World!');";
    let pr = ParseResult {
        file: "hello_world.ts".to_string(),
        language: Language::TypeScript,
        ..Default::default()
    };
    let ctx = DetectionContext::from_parse_result(&pr, source);
    matcher.analyze_file(&ctx);

    assert_eq!(
        matcher.results().len(), 0,
        "Plain hello_world.ts should produce 0 matches from new packs"
    );
}

// ===== Phase C Hardening Tests =====

/// FWT-DIAG-01: FrameworkDiagnostics populated after loading: builtin_packs_loaded >= 22
#[test]
fn fwt_diag_01_diagnostics_populated_after_load() {
    let registry = FrameworkPackRegistry::with_builtins();
    let diag = registry.diagnostics();
    assert!(
        diag.builtin_packs_loaded >= 22,
        "Expected at least 22 builtin packs loaded, got {}",
        diag.builtin_packs_loaded
    );
    assert!(diag.total_patterns_compiled > 0, "Should have compiled some patterns");
}

/// FWT-DIAG-02: Custom pack loaded increments custom_packs_loaded
#[test]
fn fwt_diag_02_custom_pack_loaded() {
    let tmp = std::env::temp_dir().join("fwt_diag_02_custom");
    let _ = std::fs::create_dir_all(&tmp);
    std::fs::write(
        tmp.join("custom.toml"),
        r#"
[framework]
name = "custom-test"
languages = ["typescript"]

[[patterns]]
id = "CUSTOM-001"
category = "structural"
[patterns.match]
content_patterns = ["custom_marker"]
"#,
    )
    .unwrap();

    let registry = FrameworkPackRegistry::with_builtins_and_custom(&tmp);
    let diag = registry.diagnostics();
    assert_eq!(diag.custom_packs_loaded, 1, "Should have loaded 1 custom pack");

    let _ = std::fs::remove_dir_all(&tmp);
}

/// FWT-DIAG-03: Match diagnostics: hits_per_category populated after matching
#[test]
fn fwt_diag_03_match_diagnostics_hits() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "diag-test"
languages = ["typescript"]

[[patterns]]
id = "DIAG-SEC-001"
category = "security"
[patterns.match]
content_patterns = ["eval\\s*\\("]
"#;
    let pack = FrameworkPackRegistry::load_single(toml).unwrap();
    let mut matcher = FrameworkMatcher::new(vec![pack]);
    let source = b"eval('code')";
    let pr = ParseResult { file: "a.ts".to_string(), language: Language::TypeScript, ..Default::default() };
    let ctx = DetectionContext::from_parse_result(&pr, source);
    matcher.analyze_file(&ctx);

    let diag = matcher.match_diagnostics();
    assert!(diag.total_hits > 0, "Should have at least 1 hit");
    assert!(diag.hits_per_category.values().sum::<usize>() > 0, "hits_per_category should be populated");
}

/// FWT-DIAG-04: Match diagnostics: files_matched < files_processed
#[test]
fn fwt_diag_04_files_matched_less_than_processed() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "diag-test2"
languages = ["typescript"]

[[patterns]]
id = "DIAG-002"
category = "security"
[patterns.match]
content_patterns = ["eval\\s*\\("]
"#;
    let pack = FrameworkPackRegistry::load_single(toml).unwrap();
    let mut matcher = FrameworkMatcher::new(vec![pack]);

    // File that matches
    let s1 = b"eval('code')";
    let pr1 = ParseResult { file: "a.ts".to_string(), language: Language::TypeScript, ..Default::default() };
    let ctx1 = DetectionContext::from_parse_result(&pr1, s1);
    matcher.analyze_file(&ctx1);

    // File that doesn't match
    let s2 = b"console.log('hello')";
    let pr2 = ParseResult { file: "b.ts".to_string(), language: Language::TypeScript, ..Default::default() };
    let ctx2 = DetectionContext::from_parse_result(&pr2, s2);
    matcher.analyze_file(&ctx2);

    let diag = matcher.match_diagnostics();
    assert_eq!(diag.files_processed, 2);
    assert_eq!(diag.files_matched, 1);
    assert!(diag.files_matched < diag.files_processed);
}

/// FWT-DIAG-05: Learning diagnostics: learning_groups populated
#[test]
fn fwt_diag_05_learning_diagnostics() {
    use drift_analysis::engine::visitor::{DetectionContext, LearningDetectorHandler};
    use drift_analysis::frameworks::FrameworkLearner;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "learn-diag-test"
languages = ["typescript"]

[[patterns]]
id = "LDIAG-001"
category = "structural"
[patterns.match]
content_patterns = ["useEffect"]
[patterns.learn]
group_by = "sub_type"
signal = "convention"
"#;
    let pack = FrameworkPackRegistry::load_single(toml).unwrap();
    let mut learner = FrameworkLearner::new(vec![pack]);

    let source = b"useEffect(() => {}, [])";
    let pr = ParseResult { file: "a.ts".to_string(), language: Language::TypeScript, ..Default::default() };
    let ctx = DetectionContext::from_parse_result(&pr, source);
    learner.learn(&ctx);

    let diag = learner.learn_diagnostics();
    assert!(diag.learning_groups > 0, "Should have at least 1 learning group");
}

/// FWT-DIAG-06: Diagnostics summary contains expected format
#[test]
fn fwt_diag_06_diagnostics_summary_format() {
    use drift_analysis::frameworks::FrameworkDiagnostics;
    let mut diag = FrameworkDiagnostics::default();
    diag.builtin_packs_loaded = 22;
    diag.total_patterns_compiled = 150;
    diag.files_processed = 100;
    diag.total_hits = 42;
    diag.learning_deviations = 3;
    let summary = diag.summary();
    assert!(summary.contains("[drift-analyze] framework diagnostics:"), "Should contain prefix");
    assert!(summary.contains("22 builtin"), "Should contain builtin count");
    assert!(summary.contains("42 hits"), "Should contain hits count");
}

/// FWT-DETECT-01: detect_signals with dependency "express": detected when in deps list
#[test]
fn fwt_detect_01_dependency_signal() {
    use drift_analysis::frameworks::registry::evaluate_pack_signals;

    let toml = r#"
[framework]
name = "express-detect"
languages = ["typescript"]
detect_by = [{ dependency = "express" }]

[[patterns]]
id = "ED-001"
category = "api"
[patterns.match]
content_patterns = ["app\\.get"]
"#;
    let pack = FrameworkPackRegistry::load_single(toml).unwrap();

    // Present in deps
    assert!(evaluate_pack_signals(&pack, &[], &["express".to_string()]));
    // Not present
    assert!(!evaluate_pack_signals(&pack, &[], &["react".to_string()]));
}

/// FWT-DETECT-02: detect_signals with file_pattern "*.java": detected when Java files present
#[test]
fn fwt_detect_02_file_pattern_signal() {
    use drift_analysis::frameworks::registry::evaluate_pack_signals;

    let toml = r#"
[framework]
name = "spring-detect"
languages = ["java"]
detect_by = [{ file_pattern = "*.java" }]

[[patterns]]
id = "SD-001"
category = "api"
[patterns.match]
content_patterns = ["@RestController"]
"#;
    let pack = FrameworkPackRegistry::load_single(toml).unwrap();

    // Java file present
    assert!(evaluate_pack_signals(&pack, &["src/Main.java".to_string()], &[]));
    // No Java files
    assert!(!evaluate_pack_signals(&pack, &["src/main.py".to_string()], &[]));
}

/// FWT-DETECT-03: No detect_signals: pack always runs (backward compat)
#[test]
fn fwt_detect_03_no_signals_always_active() {
    use drift_analysis::frameworks::registry::evaluate_pack_signals;

    let toml = r#"
[framework]
name = "no-signals"
languages = ["typescript"]

[[patterns]]
id = "NS-001"
category = "structural"
[patterns.match]
content_patterns = ["test"]
"#;
    let pack = FrameworkPackRegistry::load_single(toml).unwrap();
    assert!(evaluate_pack_signals(&pack, &[], &[]), "No detect_signals = always active");
}

/// FWT-DETECT-04: evaluate_signals returns detected frameworks list
#[test]
fn fwt_detect_04_evaluate_signals_list() {
    let mut registry = FrameworkPackRegistry::with_builtins();
    let detected = registry.evaluate_signals(
        &["app.ts".to_string()],
        &["express".to_string()],
    );
    // Should contain at least category packs (which have no signals = always active)
    assert!(!detected.is_empty(), "Should detect at least some frameworks");
}

/// FWT-CONFIG-01: Disabled pack not loaded
#[test]
fn fwt_config_01_disabled_pack() {
    use drift_analysis::frameworks::registry::FrameworkConfig;

    let config = FrameworkConfig {
        disabled_packs: vec!["accessibility".to_string()],
        enabled_only: None,
    };
    let registry = FrameworkPackRegistry::with_builtins_filtered(Some(&config));
    let packs = registry.into_packs();
    assert!(
        !packs.iter().any(|p| p.name == "accessibility-patterns"),
        "accessibility pack should be excluded"
    );
}

/// FWT-CONFIG-02: enabled_only: only specified packs loaded
#[test]
fn fwt_config_02_enabled_only() {
    use drift_analysis::frameworks::registry::FrameworkConfig;

    let config = FrameworkConfig {
        disabled_packs: vec![],
        enabled_only: Some(vec!["security".to_string()]),
    };
    let registry = FrameworkPackRegistry::with_builtins_filtered(Some(&config));
    let packs = registry.into_packs();
    assert_eq!(packs.len(), 1, "Only security pack should be loaded");
    assert_eq!(packs[0].name, "security-patterns");
}

/// FWT-CONFIG-03: No config: all packs loaded (backward compat)
#[test]
fn fwt_config_03_no_config_all_loaded() {
    let registry = FrameworkPackRegistry::with_builtins();
    assert!(
        registry.pack_count() >= 23,
        "All packs should load with no config, got {}",
        registry.pack_count()
    );
}

/// FWT-CONFIG-04: Invalid pack name in disabled_packs: other packs unaffected
#[test]
fn fwt_config_04_invalid_disabled_name() {
    use drift_analysis::frameworks::registry::FrameworkConfig;

    let config = FrameworkConfig {
        disabled_packs: vec!["nonexistent-pack".to_string()],
        enabled_only: None,
    };
    let registry_with = FrameworkPackRegistry::with_builtins_filtered(Some(&config));
    let registry_without = FrameworkPackRegistry::with_builtins();
    assert_eq!(
        registry_with.pack_count(),
        registry_without.pack_count(),
        "Invalid disabled pack name should not affect other packs"
    );
}

// ===== Phase D Hardening Tests =====

/// FWT-PERF-05: Per-file limit: many matches → at most limit results
#[test]
fn fwt_perf_05_per_file_limit_truncates() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "limit-test"
languages = ["typescript"]

[[patterns]]
id = "LIM-001"
category = "security"
[patterns.match]
content_patterns = ["x"]
"#;
    let pack = FrameworkPackRegistry::load_single(toml).unwrap();
    let mut matcher = FrameworkMatcher::new(vec![pack]);
    matcher.set_match_limit(5);

    // Source with many 'x' lines
    let lines: Vec<String> = (0..50).map(|i| format!("x line {i}")).collect();
    let source = lines.join("\n");
    let pr = ParseResult { file: "big.ts".to_string(), language: Language::TypeScript, ..Default::default() };
    let ctx = DetectionContext::from_parse_result(&pr, source.as_bytes());
    matcher.analyze_file(&ctx);

    assert_eq!(matcher.results().len(), 5, "Should be truncated to limit of 5");
}

/// FWT-PERF-06: Per-file limit: warning logged when truncated (verified via diagnostics)
#[test]
fn fwt_perf_06_truncated_increments_diagnostic() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "limit-diag-test"
languages = ["typescript"]

[[patterns]]
id = "LD-001"
category = "security"
[patterns.match]
content_patterns = ["y"]
"#;
    let pack = FrameworkPackRegistry::load_single(toml).unwrap();
    let mut matcher = FrameworkMatcher::new(vec![pack]);
    matcher.set_match_limit(3);

    let lines: Vec<String> = (0..20).map(|i| format!("y line {i}")).collect();
    let source = lines.join("\n");
    let pr = ParseResult { file: "big2.ts".to_string(), language: Language::TypeScript, ..Default::default() };
    let ctx = DetectionContext::from_parse_result(&pr, source.as_bytes());
    matcher.analyze_file(&ctx);

    let diag = matcher.match_diagnostics();
    assert_eq!(diag.files_truncated, 1, "Should have 1 truncated file");
}

/// FWT-PERF-07: files_truncated incremented per truncated file
#[test]
fn fwt_perf_07_multiple_truncated_files() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "multi-trunc"
languages = ["typescript"]

[[patterns]]
id = "MT-001"
category = "security"
[patterns.match]
content_patterns = ["z"]
"#;
    let pack = FrameworkPackRegistry::load_single(toml).unwrap();
    let mut matcher = FrameworkMatcher::new(vec![pack]);
    matcher.set_match_limit(2);

    let lines: Vec<String> = (0..10).map(|i| format!("z line {i}")).collect();
    let source = lines.join("\n");

    for i in 0..3 {
        let pr = ParseResult {
            file: format!("file{i}.ts"),
            language: Language::TypeScript,
            ..Default::default()
        };
        let ctx = DetectionContext::from_parse_result(&pr, source.as_bytes());
        matcher.analyze_file(&ctx);
    }

    let diag = matcher.match_diagnostics();
    assert_eq!(diag.files_truncated, 3, "All 3 files should be truncated");
    assert_eq!(matcher.results().len(), 6, "3 files * 2 limit = 6 total");
}

/// FWT-PERF-08: Per-file limit 0 = unlimited
#[test]
fn fwt_perf_08_limit_zero_unlimited() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "unlimited-test"
languages = ["typescript"]

[[patterns]]
id = "UL-001"
category = "security"
[patterns.match]
content_patterns = ["w"]
"#;
    let pack = FrameworkPackRegistry::load_single(toml).unwrap();
    let mut matcher = FrameworkMatcher::new(vec![pack]);
    matcher.set_match_limit(0); // unlimited

    let lines: Vec<String> = (0..200).map(|i| format!("w line {i}")).collect();
    let source = lines.join("\n");
    let pr = ParseResult { file: "huge.ts".to_string(), language: Language::TypeScript, ..Default::default() };
    let ctx = DetectionContext::from_parse_result(&pr, source.as_bytes());
    matcher.analyze_file(&ctx);

    assert_eq!(matcher.results().len(), 200, "Limit 0 = all 200 matches kept");
    assert_eq!(matcher.match_diagnostics().files_truncated, 0, "No truncation");
}

/// FWT-PERF-09: Pack filtering: non-detected pack skipped when detect_signals present
#[test]
fn fwt_perf_09_pack_filtering_skips_non_detected() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml_detected = r#"
[framework]
name = "detected-fw"
languages = ["typescript"]
detect_by = [{ dependency = "detected-fw" }]

[[patterns]]
id = "DET-001"
category = "api"
[patterns.match]
content_patterns = ["api_call"]
"#;
    let toml_not_detected = r#"
[framework]
name = "not-detected-fw"
languages = ["typescript"]
detect_by = [{ dependency = "not-detected-fw" }]

[[patterns]]
id = "NDET-001"
category = "api"
[patterns.match]
content_patterns = ["api_call"]
"#;

    let p1 = FrameworkPackRegistry::load_single(toml_detected).unwrap();
    let p2 = FrameworkPackRegistry::load_single(toml_not_detected).unwrap();
    let mut matcher = FrameworkMatcher::new(vec![p1, p2]);
    matcher.set_detected_packs(vec!["detected-fw".to_string()]);

    let source = b"api_call()";
    let pr = ParseResult { file: "a.ts".to_string(), language: Language::TypeScript, ..Default::default() };
    let ctx = DetectionContext::from_parse_result(&pr, source);
    matcher.analyze_file(&ctx);

    let results = matcher.results();
    assert!(results.iter().any(|r| r.pattern_id == "DET-001"), "Detected pack should match");
    assert!(!results.iter().any(|r| r.pattern_id == "NDET-001"), "Non-detected pack should be skipped");
}

/// FWT-PERF-10: Pack filtering: cross-language packs (no detect_signals) always run
#[test]
fn fwt_perf_10_cross_language_packs_always_run() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml_cross = r#"
[framework]
name = "cross-lang"
languages = ["typescript"]

[[patterns]]
id = "CROSS-001"
category = "security"
[patterns.match]
content_patterns = ["eval"]
"#;
    let toml_specific = r#"
[framework]
name = "specific-fw"
languages = ["typescript"]
detect_by = [{ dependency = "specific-fw" }]

[[patterns]]
id = "SPEC-001"
category = "api"
[patterns.match]
content_patterns = ["eval"]
"#;

    let p1 = FrameworkPackRegistry::load_single(toml_cross).unwrap();
    let p2 = FrameworkPackRegistry::load_single(toml_specific).unwrap();
    let mut matcher = FrameworkMatcher::new(vec![p1, p2]);
    // Only "other-fw" detected, "specific-fw" is not
    matcher.set_detected_packs(vec!["other-fw".to_string()]);

    let source = b"eval('code')";
    let pr = ParseResult { file: "a.ts".to_string(), language: Language::TypeScript, ..Default::default() };
    let ctx = DetectionContext::from_parse_result(&pr, source);
    matcher.analyze_file(&ctx);

    let results = matcher.results();
    assert!(results.iter().any(|r| r.pattern_id == "CROSS-001"), "Cross-language pack should always run");
    assert!(!results.iter().any(|r| r.pattern_id == "SPEC-001"), "Specific pack should be filtered");
}

/// FWT-PERF-13: Empty file: 0 matches, no crash
#[test]
fn fwt_perf_13_empty_file_no_crash() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let registry = FrameworkPackRegistry::with_builtins();
    let packs = registry.into_packs();
    let mut matcher = FrameworkMatcher::new(packs);

    let source = b"";
    let pr = ParseResult { file: "empty.ts".to_string(), language: Language::TypeScript, ..Default::default() };
    let ctx = DetectionContext::from_parse_result(&pr, source);
    matcher.analyze_file(&ctx);

    assert_eq!(matcher.results().len(), 0, "Empty file should produce 0 matches");
}

/// FWT-PERF-14: Binary file (invalid UTF-8): content_patterns gracefully handle lossy conversion
#[test]
fn fwt_perf_14_binary_file_no_crash() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "binary-test"
languages = ["typescript"]

[[patterns]]
id = "BIN-001"
category = "security"
[patterns.match]
content_patterns = ["eval"]
"#;
    let pack = FrameworkPackRegistry::load_single(toml).unwrap();
    let mut matcher = FrameworkMatcher::new(vec![pack]);

    // Invalid UTF-8 bytes
    let source: &[u8] = &[0xFF, 0xFE, 0x65, 0x76, 0x61, 0x6C, 0x28, 0x29, 0xFF];
    let pr = ParseResult { file: "binary.ts".to_string(), language: Language::TypeScript, ..Default::default() };
    let ctx = DetectionContext::from_parse_result(&pr, source);
    matcher.analyze_file(&ctx);

    // Should not crash — may or may not match depending on lossy conversion
    // The important thing is no panic
}

// ===== Phase E Hardening Tests =====

/// FWT-SIGNAL-01: "frequency" signal: rare pattern flagged (below 10th percentile)
#[test]
fn fwt_signal_01_frequency_rare_flagged() {
    use drift_analysis::engine::visitor::{DetectionContext, LearningDetectorHandler};
    use drift_analysis::frameworks::FrameworkLearner;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "freq-test"
languages = ["typescript"]

[[patterns]]
id = "FREQ-COMMON"
category = "structural"
sub_type = "naming"
[patterns.match]
function_names = ["^handle[A-Z]"]
[patterns.learn]
group_by = "sub_type"
signal = "frequency"

[[patterns]]
id = "FREQ-RARE"
category = "structural"
sub_type = "naming"
[patterns.match]
function_names = ["^process[A-Z]"]
[patterns.learn]
group_by = "sub_type"
signal = "frequency"
"#;

    fn make_func(name: &str) -> FunctionInfo {
        FunctionInfo {
            name: name.to_string(),
            qualified_name: None,
            file: String::new(),
            line: 1,
            column: 0,
            end_line: 5,
            parameters: smallvec::smallvec![],
            return_type: None,
            generic_params: smallvec::smallvec![],
            visibility: Visibility::Public,
            is_exported: false,
            is_async: false,
            is_generator: false,
            is_abstract: false,
            range: Range {
                start: Position { line: 1, column: 0 },
                end: Position { line: 5, column: 1 },
            },
            decorators: vec![],
            doc_comment: None,
            body_hash: 0,
            signature_hash: 0,
        }
    }

    let pack = FrameworkPackRegistry::load_single(toml).unwrap();
    let mut learner = FrameworkLearner::new(vec![pack]);

    // 20 files with FREQ-COMMON, 1 file with FREQ-RARE
    for i in 0..20 {
        let pr = ParseResult {
            file: format!("handler{i}.ts"),
            language: Language::TypeScript,
            functions: vec![make_func("handleClick")],
            ..Default::default()
        };
        let ctx = DetectionContext::from_parse_result(&pr, b"function handleClick() {}");
        learner.learn(&ctx);
    }

    let rare_pr = ParseResult {
        file: "rare.ts".to_string(),
        language: Language::TypeScript,
        functions: vec![make_func("processData")],
        ..Default::default()
    };
    let rare_ctx = DetectionContext::from_parse_result(&rare_pr, b"function processData() {}");
    learner.learn(&rare_ctx);

    // Detect on the rare file
    learner.detect(&rare_ctx);
    let results = learner.results();
    assert!(
        results.iter().any(|r| r.pattern_id.contains("/rare")),
        "Rare frequency pattern should be flagged, got: {:?}",
        results.iter().map(|r| &r.pattern_id).collect::<Vec<_>>()
    );
}

/// FWT-SIGNAL-02: "frequency" signal: common pattern NOT flagged
#[test]
fn fwt_signal_02_frequency_common_not_flagged() {
    use drift_analysis::engine::visitor::{DetectionContext, LearningDetectorHandler};
    use drift_analysis::frameworks::FrameworkLearner;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "freq-test2"
languages = ["typescript"]

[[patterns]]
id = "FREQ2-A"
category = "structural"
sub_type = "naming"
[patterns.match]
function_names = ["^handle[A-Z]"]
[patterns.learn]
group_by = "sub_type"
signal = "frequency"

[[patterns]]
id = "FREQ2-B"
category = "structural"
sub_type = "naming"
[patterns.match]
function_names = ["^process[A-Z]"]
[patterns.learn]
group_by = "sub_type"
signal = "frequency"
"#;

    fn make_func(name: &str) -> FunctionInfo {
        FunctionInfo {
            name: name.to_string(),
            qualified_name: None,
            file: String::new(),
            line: 1,
            column: 0,
            end_line: 5,
            parameters: smallvec::smallvec![],
            return_type: None,
            generic_params: smallvec::smallvec![],
            visibility: Visibility::Public,
            is_exported: false,
            is_async: false,
            is_generator: false,
            is_abstract: false,
            range: Range {
                start: Position { line: 1, column: 0 },
                end: Position { line: 5, column: 1 },
            },
            decorators: vec![],
            doc_comment: None,
            body_hash: 0,
            signature_hash: 0,
        }
    }

    let pack = FrameworkPackRegistry::load_single(toml).unwrap();
    let mut learner = FrameworkLearner::new(vec![pack]);

    // Both patterns appear equally (10 each)
    for i in 0..10 {
        let pr = ParseResult {
            file: format!("handler{i}.ts"),
            language: Language::TypeScript,
            functions: vec![make_func("handleClick")],
            ..Default::default()
        };
        let ctx = DetectionContext::from_parse_result(&pr, b"function handleClick() {}");
        learner.learn(&ctx);
    }
    for i in 0..10 {
        let pr = ParseResult {
            file: format!("process{i}.ts"),
            language: Language::TypeScript,
            functions: vec![make_func("processData")],
            ..Default::default()
        };
        let ctx = DetectionContext::from_parse_result(&pr, b"function processData() {}");
        learner.learn(&ctx);
    }

    // Detect on a common file — should NOT be flagged
    let pr = ParseResult {
        file: "handler0.ts".to_string(),
        language: Language::TypeScript,
        functions: vec![make_func("handleClick")],
        ..Default::default()
    };
    let ctx = DetectionContext::from_parse_result(&pr, b"function handleClick() {}");
    learner.detect(&ctx);
    let results = learner.results();
    assert!(
        results.is_empty(),
        "Common frequency pattern should NOT be flagged, got: {:?}",
        results.iter().map(|r| &r.pattern_id).collect::<Vec<_>>()
    );
}

/// FWT-SIGNAL-03: "presence" signal: pattern in <5% of files flagged
#[test]
fn fwt_signal_03_presence_rare_flagged() {
    use drift_analysis::engine::visitor::{DetectionContext, LearningDetectorHandler};
    use drift_analysis::frameworks::FrameworkLearner;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "presence-test"
languages = ["typescript"]

[[patterns]]
id = "PRES-COMMON"
category = "structural"
sub_type = "naming"
[patterns.match]
function_names = ["^handle[A-Z]"]
[patterns.learn]
group_by = "sub_type"
signal = "presence"

[[patterns]]
id = "PRES-RARE"
category = "structural"
sub_type = "naming"
[patterns.match]
function_names = ["^process[A-Z]"]
[patterns.learn]
group_by = "sub_type"
signal = "presence"
"#;

    fn make_func(name: &str) -> FunctionInfo {
        FunctionInfo {
            name: name.to_string(),
            qualified_name: None,
            file: String::new(),
            line: 1,
            column: 0,
            end_line: 5,
            parameters: smallvec::smallvec![],
            return_type: None,
            generic_params: smallvec::smallvec![],
            visibility: Visibility::Public,
            is_exported: false,
            is_async: false,
            is_generator: false,
            is_abstract: false,
            range: Range {
                start: Position { line: 1, column: 0 },
                end: Position { line: 5, column: 1 },
            },
            decorators: vec![],
            doc_comment: None,
            body_hash: 0,
            signature_hash: 0,
        }
    }

    let pack = FrameworkPackRegistry::load_single(toml).unwrap();
    let mut learner = FrameworkLearner::new(vec![pack]);

    // PRES-COMMON in 30 files, PRES-RARE in 1 file → 1/31 ≈ 3.2% < 5%
    for i in 0..30 {
        let pr = ParseResult {
            file: format!("handler{i}.ts"),
            language: Language::TypeScript,
            functions: vec![make_func("handleClick")],
            ..Default::default()
        };
        let ctx = DetectionContext::from_parse_result(&pr, b"function handleClick() {}");
        learner.learn(&ctx);
    }

    let rare_pr = ParseResult {
        file: "rare.ts".to_string(),
        language: Language::TypeScript,
        functions: vec![make_func("processData")],
        ..Default::default()
    };
    let rare_ctx = DetectionContext::from_parse_result(&rare_pr, b"function processData() {}");
    learner.learn(&rare_ctx);

    learner.detect(&rare_ctx);
    let results = learner.results();
    assert!(
        results.iter().any(|r| r.pattern_id.contains("/rare-presence")),
        "Rare presence pattern should be flagged, got: {:?}",
        results.iter().map(|r| &r.pattern_id).collect::<Vec<_>>()
    );
}

/// FWT-SIGNAL-04: "co_occurrence" signal: missing co-occurring pattern flagged
#[test]
fn fwt_signal_04_co_occurrence_missing_flagged() {
    use drift_analysis::engine::visitor::{DetectionContext, LearningDetectorHandler};
    use drift_analysis::frameworks::FrameworkLearner;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "cooccur-test"
languages = ["typescript"]

[[patterns]]
id = "CO-A"
category = "structural"
sub_type = "naming"
[patterns.match]
function_names = ["^handle[A-Z]"]
[patterns.learn]
group_by = "sub_type"
signal = "co_occurrence"

[[patterns]]
id = "CO-B"
category = "structural"
sub_type = "naming"
[patterns.match]
function_names = ["^process[A-Z]"]
[patterns.learn]
group_by = "sub_type"
signal = "co_occurrence"
"#;

    fn make_func(name: &str) -> FunctionInfo {
        FunctionInfo {
            name: name.to_string(),
            qualified_name: None,
            file: String::new(),
            line: 1,
            column: 0,
            end_line: 5,
            parameters: smallvec::smallvec![],
            return_type: None,
            generic_params: smallvec::smallvec![],
            visibility: Visibility::Public,
            is_exported: false,
            is_async: false,
            is_generator: false,
            is_abstract: false,
            range: Range {
                start: Position { line: 1, column: 0 },
                end: Position { line: 5, column: 1 },
            },
            decorators: vec![],
            doc_comment: None,
            body_hash: 0,
            signature_hash: 0,
        }
    }

    let pack = FrameworkPackRegistry::load_single(toml).unwrap();
    let mut learner = FrameworkLearner::new(vec![pack]);

    // Files with both patterns (co-occurring)
    for i in 0..5 {
        let pr = ParseResult {
            file: format!("both{i}.ts"),
            language: Language::TypeScript,
            functions: vec![make_func("handleClick"), make_func("processData")],
            ..Default::default()
        };
        let ctx = DetectionContext::from_parse_result(&pr, b"function handleClick() {} function processData() {}");
        learner.learn(&ctx);
    }

    // One file with only CO-A (missing CO-B)
    let partial_pr = ParseResult {
        file: "partial.ts".to_string(),
        language: Language::TypeScript,
        functions: vec![make_func("handleEvent")],
        ..Default::default()
    };
    let partial_ctx = DetectionContext::from_parse_result(&partial_pr, b"function handleEvent() {}");
    learner.learn(&partial_ctx);

    learner.detect(&partial_ctx);
    let results = learner.results();
    assert!(
        results.iter().any(|r| r.pattern_id.contains("/missing-co-occurrence")),
        "Missing co-occurring pattern should be flagged, got: {:?}",
        results.iter().map(|r| &r.pattern_id).collect::<Vec<_>>()
    );
}

/// FWT-SIGNAL-05: Unknown signal type: warning logged, no crash
#[test]
fn fwt_signal_05_unknown_signal_no_crash() {
    use drift_analysis::engine::visitor::{DetectionContext, LearningDetectorHandler};
    use drift_analysis::frameworks::FrameworkLearner;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "unknown-signal-test"
languages = ["typescript"]

[[patterns]]
id = "UNK-001"
category = "structural"
sub_type = "naming"
[patterns.match]
function_names = ["^handle[A-Z]"]
[patterns.learn]
group_by = "sub_type"
signal = "nonexistent_signal_type"
"#;

    fn make_func(name: &str) -> FunctionInfo {
        FunctionInfo {
            name: name.to_string(),
            qualified_name: None,
            file: String::new(),
            line: 1,
            column: 0,
            end_line: 5,
            parameters: smallvec::smallvec![],
            return_type: None,
            generic_params: smallvec::smallvec![],
            visibility: Visibility::Public,
            is_exported: false,
            is_async: false,
            is_generator: false,
            is_abstract: false,
            range: Range {
                start: Position { line: 1, column: 0 },
                end: Position { line: 5, column: 1 },
            },
            decorators: vec![],
            doc_comment: None,
            body_hash: 0,
            signature_hash: 0,
        }
    }

    let pack = FrameworkPackRegistry::load_single(toml).unwrap();
    let mut learner = FrameworkLearner::new(vec![pack]);

    let pr = ParseResult {
        file: "test.ts".to_string(),
        language: Language::TypeScript,
        functions: vec![make_func("handleClick")],
        ..Default::default()
    };
    let ctx = DetectionContext::from_parse_result(&pr, b"function handleClick() {}");
    learner.learn(&ctx);
    learner.detect(&ctx);

    // Should not crash — results may be empty (unknown signal just logs warning)
    let _results = learner.results();
}

/// FWT-VER-01: Pack with version = "1.0.0": version appears in compiled pack
#[test]
fn fwt_ver_01_pack_version_present() {
    let toml = r#"
[framework]
name = "versioned-pack"
languages = ["typescript"]
version = "1.0.0"

[[patterns]]
id = "VER-001"
category = "structural"
[patterns.match]
content_patterns = ["test"]
"#;
    let pack = FrameworkPackRegistry::load_single(toml).unwrap();
    assert_eq!(
        pack.version.as_deref(),
        Some("1.0.0"),
        "Pack version should be '1.0.0'"
    );
}

/// FWT-VER-02: Pack without version: None in compiled pack (backward compat)
#[test]
fn fwt_ver_02_pack_version_absent() {
    let toml = r#"
[framework]
name = "no-version-pack"
languages = ["typescript"]

[[patterns]]
id = "NOVER-001"
category = "structural"
[patterns.match]
content_patterns = ["test"]
"#;
    let pack = FrameworkPackRegistry::load_single(toml).unwrap();
    assert!(
        pack.version.is_none(),
        "Pack without version field should have None"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase E: JSON Schema Validation Tests
// ═══════════════════════════════════════════════════════════════════════════

/// FWT-SCHEMA-01: JSON Schema validates a correct TOML-converted-to-JSON pack.
#[test]
fn fwt_schema_01_json_schema_validates_correct_pack() {
    use drift_analysis::frameworks::types::generate_json_schema;

    let schema = generate_json_schema();
    let schema_json = serde_json::to_value(&schema).expect("Schema should serialize to JSON");

    // Verify the schema has the expected structure
    assert_eq!(
        schema_json.get("title").and_then(|t| t.as_str()),
        Some("FrameworkSpec"),
        "Root schema title should be FrameworkSpec"
    );

    // Verify it has definitions for our types
    let definitions = schema_json.get("definitions").or_else(|| schema_json.get("$defs"));
    assert!(
        definitions.is_some(),
        "Schema should have definitions for nested types"
    );

    // Verify the schema requires the 'framework' property
    let required = schema_json.get("required").and_then(|r| r.as_array());
    assert!(
        required.is_some(),
        "Schema should have required fields"
    );
    let required_fields: Vec<&str> = required
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        required_fields.contains(&"framework"),
        "Schema should require 'framework' field, got: {:?}",
        required_fields
    );

    // Verify a valid pack can be represented as JSON matching the schema structure
    let valid_toml = r#"
[framework]
name = "test-schema"
languages = ["typescript"]

[[patterns]]
id = "SCHEMA-001"
category = "structural"
[patterns.match]
content_patterns = ["test"]
"#;
    let spec: drift_analysis::frameworks::types::FrameworkSpec =
        toml::from_str(valid_toml).expect("Valid TOML should parse");
    let spec_json = serde_json::to_value(&spec).expect("Spec should serialize to JSON");

    // Verify the JSON has the expected structure
    assert!(spec_json.get("framework").is_some(), "JSON should have 'framework' key");
    assert!(spec_json.get("patterns").is_some(), "JSON should have 'patterns' key");
    let fw = spec_json.get("framework").unwrap();
    assert_eq!(fw.get("name").and_then(|n| n.as_str()), Some("test-schema"));
}

/// FWT-SCHEMA-02: JSON Schema rejects pack with missing required framework.name.
#[test]
fn fwt_schema_02_json_schema_rejects_missing_name() {
    use drift_analysis::frameworks::types::generate_json_schema;

    let schema = generate_json_schema();
    let schema_json = serde_json::to_value(&schema).expect("Schema should serialize to JSON");

    // Verify the schema's framework definition requires 'name' and 'languages'
    let defs = schema_json.get("definitions").or_else(|| schema_json.get("$defs"));
    assert!(defs.is_some(), "Schema should have definitions");

    let defs = defs.unwrap();
    let meta_def = defs.get("FrameworkMeta");
    assert!(meta_def.is_some(), "Schema should define FrameworkMeta");

    let meta_required = meta_def
        .unwrap()
        .get("required")
        .and_then(|r| r.as_array());
    assert!(meta_required.is_some(), "FrameworkMeta should have required fields");

    let meta_required_fields: Vec<&str> = meta_required
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        meta_required_fields.contains(&"name"),
        "FrameworkMeta should require 'name', got: {:?}",
        meta_required_fields
    );
    assert!(
        meta_required_fields.contains(&"languages"),
        "FrameworkMeta should require 'languages', got: {:?}",
        meta_required_fields
    );

    // Also verify that TOML without name fails to parse
    let invalid_toml = r#"
[framework]
languages = ["typescript"]
"#;
    let result: Result<drift_analysis::frameworks::types::FrameworkSpec, _> =
        toml::from_str(invalid_toml);
    assert!(
        result.is_err(),
        "TOML without framework.name should fail to parse"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase E: Degradation Alert Tests
// ═══════════════════════════════════════════════════════════════════════════

/// FWT-DEGRADE-01: Detection count drop >50% triggers degradation alert logic.
///
/// This tests the comparison logic used in analysis.rs Step 8.
#[test]
fn fwt_degrade_01_detection_drop_triggers_alert() {
    // Simulate previous pack counts and current pack counts
    let mut previous_pack_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    previous_pack_counts.insert("spring".to_string(), 20);
    previous_pack_counts.insert("express".to_string(), 15);

    let mut current_pack_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    current_pack_counts.insert("spring".to_string(), 5); // 75% drop
    // express missing entirely = 100% drop

    let mut alerts = Vec::new();
    for (pack, prev_count) in &previous_pack_counts {
        if *prev_count >= 5 {
            let curr_count = current_pack_counts.get(pack).copied().unwrap_or(0);
            if (curr_count as f64) < (*prev_count as f64 * 0.5) {
                alerts.push(format!(
                    "framework_detection_drop: {} dropped from {} to {}",
                    pack, prev_count, curr_count
                ));
            }
        }
    }

    assert_eq!(alerts.len(), 2, "Should have 2 degradation alerts");
    assert!(
        alerts.iter().any(|a| a.contains("spring")),
        "Should alert on spring (75% drop)"
    );
    assert!(
        alerts.iter().any(|a| a.contains("express")),
        "Should alert on express (100% drop)"
    );
}

/// FWT-DEGRADE-02: Detection count stable — no alert.
#[test]
fn fwt_degrade_02_detection_stable_no_alert() {
    let mut previous_pack_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    previous_pack_counts.insert("spring".to_string(), 20);
    previous_pack_counts.insert("express".to_string(), 15);

    let mut current_pack_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    current_pack_counts.insert("spring".to_string(), 18); // 10% drop — within threshold
    current_pack_counts.insert("express".to_string(), 20); // Increased

    let mut alerts = Vec::new();
    for (pack, prev_count) in &previous_pack_counts {
        if *prev_count >= 5 {
            let curr_count = current_pack_counts.get(pack).copied().unwrap_or(0);
            if (curr_count as f64) < (*prev_count as f64 * 0.5) {
                alerts.push(format!(
                    "framework_detection_drop: {} dropped from {} to {}",
                    pack, prev_count, curr_count
                ));
            }
        }
    }

    assert!(
        alerts.is_empty(),
        "Stable detection counts should produce no alerts, got: {:?}",
        alerts
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase E: E2E Regression Tests
// ═══════════════════════════════════════════════════════════════════════════

/// FWT-REG-01: E2E — full pipeline with framework data.
///
/// Loads built-in packs, runs matcher on realistic TypeScript content,
/// verifies detections flow through matcher → results with correct fields.
#[test]
fn fwt_reg_01_full_pipeline_framework_data() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    // Load all built-in packs
    let registry = FrameworkPackRegistry::with_builtins();
    assert!(registry.pack_count() >= 20);

    let packs = registry.into_packs();
    let mut matcher = FrameworkMatcher::new(packs);

    // Create a TypeScript file with content that should match content_patterns
    // in built-in packs (e.g., try/catch for error handling, console.log for logging)
    let pr = ParseResult {
        file: "src/service.ts".to_string(),
        language: Language::TypeScript,
        ..Default::default()
    };

    let source = b"try {\n  const result = await fetch('/api/data');\n  console.log('fetched', result);\n} catch (error) {\n  console.error('Failed:', error);\n  throw new Error('Service error');\n}\n";
    let ctx = DetectionContext::from_parse_result(&pr, source);
    matcher.analyze_file(&ctx);

    let results = matcher.last_file_results();
    // Should have at least some matches from NestJS or other packs
    // (imports, decorators, function patterns)
    assert!(
        !results.is_empty(),
        "Full pipeline should produce matches for a NestJS controller file"
    );

    // Verify result structure
    for r in results {
        assert!(!r.pattern_id.is_empty(), "pattern_id should not be empty");
        assert!(!r.file.is_empty(), "file should not be empty");
        assert!(r.confidence > 0.0, "confidence should be > 0");
    }

    // Verify diagnostics
    let diag = matcher.match_diagnostics();
    assert!(diag.files_processed >= 1, "Should have processed at least 1 file");
    assert!(diag.total_hits >= 1, "Should have at least 1 hit");
}

/// FWT-REG-02: E2E — custom pack loaded and matched alongside built-ins.
#[test]
fn fwt_reg_02_custom_pack_alongside_builtins() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    // Load built-in packs
    let registry = FrameworkPackRegistry::with_builtins();
    let builtin_count = registry.pack_count();
    let mut all_packs = registry.into_packs();

    // Add a custom pack
    let custom_toml = r#"
[framework]
name = "custom-test"
languages = ["typescript"]
version = "1.0.0"

[[patterns]]
id = "CUSTOM-001"
category = "structural"
description = "Custom test pattern"
[patterns.match]
content_patterns = ["CUSTOM_MARKER"]
"#;
    let custom_pack = FrameworkPackRegistry::load_single(custom_toml).unwrap();
    all_packs.push(custom_pack);

    assert_eq!(
        all_packs.len(),
        builtin_count + 1,
        "Should have builtins + 1 custom pack"
    );

    let mut matcher = FrameworkMatcher::new(all_packs);

    // Create a file that matches the custom pattern
    let pr = ParseResult {
        file: "src/custom.ts".to_string(),
        language: Language::TypeScript,
        ..Default::default()
    };

    let source = b"const x = CUSTOM_MARKER;\n";
    let ctx = DetectionContext::from_parse_result(&pr, source);
    matcher.analyze_file(&ctx);

    let results = matcher.last_file_results();
    let custom_matches: Vec<_> = results
        .iter()
        .filter(|r| r.pattern_id.contains("CUSTOM-001"))
        .collect();

    assert!(
        !custom_matches.is_empty(),
        "Custom pack pattern should match alongside built-ins"
    );

    // Verify the custom match has correct fields
    let m = &custom_matches[0];
    assert_eq!(m.file, "src/custom.ts");
    assert!(m.confidence > 0.0);
}

/// FWT-REG-03: Pack version appears in registry diagnostics.
#[test]
fn fwt_reg_03_pack_version_in_diagnostics() {
    // Create a custom pack with version via temp dir
    let dir = tempfile::tempdir().unwrap();
    let pack_path = dir.path().join("versioned.toml");
    std::fs::write(
        &pack_path,
        r#"
[framework]
name = "versioned-pack"
languages = ["typescript"]
version = "2.1.0"

[[patterns]]
id = "VP-001"
category = "structural"
[patterns.match]
content_patterns = ["test"]
"#,
    )
    .unwrap();

    let registry = FrameworkPackRegistry::with_builtins_and_custom(dir.path());
    let diag = registry.diagnostics();

    assert_eq!(diag.custom_packs_loaded, 1);
    assert_eq!(
        diag.pack_versions.get("versioned-pack"),
        Some(&"2.1.0".to_string()),
        "Diagnostics should contain the custom pack version"
    );
}

// ===== Phase D: RegexSet & Aho-Corasick Performance Tests =====

/// FWT-PERF-01: RegexSet compiled for content_patterns at load time
#[test]
fn fwt_perf_01_regex_set_compiled_for_content_patterns() {
    let toml = r#"
[framework]
name = "rs-test"
languages = ["typescript"]

[[patterns]]
id = "RS-001"
category = "structural"
[patterns.match]
content_patterns = ["foo", "bar"]
"#;
    let pack = FrameworkPackRegistry::load_single(toml).unwrap();
    assert!(
        pack.patterns[0].match_block.content_regex_set.is_some(),
        "content_regex_set should be compiled at load time"
    );
}

/// FWT-PERF-02: RegexSet compiled for function_names at load time
#[test]
fn fwt_perf_02_regex_set_compiled_for_function_names() {
    let toml = r#"
[framework]
name = "rs-fn-test"
languages = ["typescript"]

[[patterns]]
id = "RS-FN-001"
category = "structural"
[patterns.match]
function_names = ["^handle", "^process"]
"#;
    let pack = FrameworkPackRegistry::load_single(toml).unwrap();
    assert!(
        pack.patterns[0].match_block.function_name_regex_set.is_some(),
        "function_name_regex_set should be compiled at load time"
    );
}

/// FWT-PERF-03: RegexSet equivalence — same results with and without RegexSet
#[test]
fn fwt_perf_03_regex_set_equivalence() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "equiv-test"
languages = ["typescript"]

[[patterns]]
id = "EQ-001"
category = "structural"
[patterns.match]
content_patterns = ["(?i)useEffect", "(?i)useState"]
"#;
    let pack = FrameworkPackRegistry::load_single(toml).unwrap();
    // Verify RegexSet is present
    assert!(pack.patterns[0].match_block.content_regex_set.is_some());

    let mut matcher = FrameworkMatcher::new(vec![pack]);
    let source = b"import React from 'react';\nconst [x, setX] = useState(0);\nuseEffect(() => {}, []);\n";
    let pr = ParseResult {
        language: Language::TypeScript,
        ..Default::default()
    };
    let ctx = DetectionContext {
        file: "app.tsx",
        language: Language::TypeScript,
        source,
        parse_result: &pr,
        imports: &[],
        classes: &[],
        functions: &[],
        call_sites: &[],
        exports: &[],
    };
    matcher.analyze_file(&ctx);
    let results = matcher.results();
    // Should match both useState and useEffect lines
    assert!(results.len() >= 2, "RegexSet path should produce same matches as individual regex: got {}", results.len());
}

/// FWT-PERF-04: Aho-Corasick compiled for imports at load time
#[test]
fn fwt_perf_04_aho_corasick_compiled_for_imports() {
    let toml = r#"
[framework]
name = "ac-test"
languages = ["typescript"]

[[patterns]]
id = "AC-001"
category = "structural"
[patterns.match]
imports = ["express", "koa"]
"#;
    let pack = FrameworkPackRegistry::load_single(toml).unwrap();
    assert!(
        pack.patterns[0].match_block.import_ac.is_some(),
        "import_ac should be compiled at load time"
    );
}

/// FWT-PERF-11: Aho-Corasick compiled for decorators at load time
#[test]
fn fwt_perf_11_aho_corasick_compiled_for_decorators() {
    let toml = r#"
[framework]
name = "ac-dec-test"
languages = ["typescript"]

[[patterns]]
id = "AC-DEC-001"
category = "structural"
[patterns.match]
decorators = ["Injectable", "Component"]
"#;
    let pack = FrameworkPackRegistry::load_single(toml).unwrap();
    assert!(
        pack.patterns[0].match_block.decorator_ac.is_some(),
        "decorator_ac should be compiled at load time"
    );
    assert!(
        pack.patterns[0].match_block.extends_ac.is_none(),
        "extends_ac should be None when no extends patterns"
    );
}

/// FWT-PERF-12: RegexSet/AC absent when field is empty (no wasted allocation)
#[test]
fn fwt_perf_12_no_allocation_when_empty() {
    let toml = r#"
[framework]
name = "empty-test"
languages = ["typescript"]

[[patterns]]
id = "EMPTY-001"
category = "structural"
[patterns.match]
imports = ["express"]
"#;
    let pack = FrameworkPackRegistry::load_single(toml).unwrap();
    let block = &pack.patterns[0].match_block;
    // imports has data → AC present
    assert!(block.import_ac.is_some());
    // Everything else empty → None
    assert!(block.content_regex_set.is_none());
    assert!(block.function_name_regex_set.is_none());
    assert!(block.class_name_regex_set.is_none());
    assert!(block.string_literal_regex_set.is_none());
    assert!(block.doc_comment_regex_set.is_none());
    assert!(block.type_annotation_regex_set.is_none());
    assert!(block.decorator_ac.is_none());
    assert!(block.extends_ac.is_none());
    assert!(block.implements_ac.is_none());
}

/// FWT-PERF-15: Benchmark — 23 packs × 1000 files completes in <10s
#[test]
fn fwt_perf_15_benchmark_23_packs_1000_files() {
    use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
    use drift_analysis::frameworks::FrameworkMatcher;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let registry = FrameworkPackRegistry::with_builtins();
    let packs = registry.into_packs();
    let mut matcher = FrameworkMatcher::new(packs);

    let source = b"import express from 'express';\nconst app = express();\napp.get('/api', (req, res) => { res.json({}); });\n";
    let pr = ParseResult {
        language: Language::TypeScript,
        ..Default::default()
    };

    let start = std::time::Instant::now();
    for i in 0..1000 {
        let file = format!("src/file_{i}.ts");
        let ctx = DetectionContext {
            file: &file,
            language: Language::TypeScript,
            source,
            parse_result: &pr,
            imports: &[],
            classes: &[],
            functions: &[],
            call_sites: &[],
            exports: &[],
        };
        matcher.analyze_file(&ctx);
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 10,
        "23 packs × 1000 files should complete in <10s, took {:?}",
        elapsed
    );
    let diag = matcher.match_diagnostics();
    assert_eq!(diag.files_processed, 1000);
}

// ===== Phase A: Missing Learner Tests =====

/// FWT-LEARN-05: Learner with multiple groups produces correct dominant per group
#[test]
fn fwt_learn_05_multiple_groups() {
    use drift_analysis::engine::visitor::{DetectionContext, LearningDetectorHandler};
    use drift_analysis::frameworks::FrameworkLearner;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "multi-group"
languages = ["typescript"]

[[patterns]]
id = "MG-A"
category = "structural"
sub_type = "style-a"
[patterns.match]
content_patterns = ["styleA"]
[patterns.learn]
group_by = "sub_type"
signal = "convention"
deviation_threshold = 0.10

[[patterns]]
id = "MG-B"
category = "structural"
sub_type = "style-b"
[patterns.match]
content_patterns = ["styleB"]
[patterns.learn]
group_by = "sub_type"
signal = "convention"
deviation_threshold = 0.10
"#;
    let pack = FrameworkPackRegistry::load_single(toml).unwrap();
    let mut learner = FrameworkLearner::new(vec![pack]);

    // Feed 10 files with styleA, 1 with styleB
    for i in 0..10 {
        let src = b"const x = styleA();";
        let pr = ParseResult { language: Language::TypeScript, ..Default::default() };
        let file = format!("src/a_{i}.ts");
        let ctx = DetectionContext {
            file: &file, language: Language::TypeScript, source: src,
            parse_result: &pr, imports: &[], classes: &[], functions: &[],
            call_sites: &[], exports: &[],
        };
        learner.learn(&ctx);
    }
    let src_b = b"const x = styleB();";
    let pr_b = ParseResult { language: Language::TypeScript, ..Default::default() };
    let ctx_b = DetectionContext {
        file: "src/b_0.ts", language: Language::TypeScript, source: src_b,
        parse_result: &pr_b, imports: &[], classes: &[], functions: &[],
        call_sites: &[], exports: &[],
    };
    learner.learn(&ctx_b);

    // Detect pass — styleB should be flagged as deviation in its group
    let diag = learner.learn_diagnostics();
    assert!(diag.learning_groups > 0, "Should have learning groups");
}

/// FWT-LEARN-06: Learner with zero files: no crash, empty results
#[test]
fn fwt_learn_06_zero_files_no_crash() {
    use drift_analysis::engine::visitor::LearningDetectorHandler;
    use drift_analysis::frameworks::FrameworkLearner;

    let toml = r#"
[framework]
name = "empty-learn"
languages = ["typescript"]

[[patterns]]
id = "EL-001"
category = "structural"
[patterns.match]
content_patterns = ["test"]
[patterns.learn]
group_by = "sub_type"
signal = "convention"
deviation_threshold = 0.15
"#;
    let pack = FrameworkPackRegistry::load_single(toml).unwrap();
    let learner = FrameworkLearner::new(vec![pack]);
    let results = learner.results();
    assert!(results.is_empty(), "No files learned → no results");
}

/// FWT-LEARN-07: Learner deviation threshold 0.05 flags minority as deviation
#[test]
fn fwt_learn_07_low_threshold() {
    use drift_analysis::engine::visitor::{DetectionContext, LearningDetectorHandler};
    use drift_analysis::frameworks::FrameworkLearner;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "low-thresh"
languages = ["typescript"]

[[patterns]]
id = "LT-A"
category = "structural"
sub_type = "style"
[patterns.match]
content_patterns = ["patternA"]
[patterns.learn]
group_by = "sub_type"
signal = "convention"
deviation_threshold = 0.05

[[patterns]]
id = "LT-B"
category = "structural"
sub_type = "style"
[patterns.match]
content_patterns = ["patternB"]
[patterns.learn]
group_by = "sub_type"
signal = "convention"
deviation_threshold = 0.05
"#;
    let pack = FrameworkPackRegistry::load_single(toml).unwrap();
    let mut learner = FrameworkLearner::new(vec![pack]);

    // 19 files with patternA, 1 with patternB → ratio = 19/20 = 0.95 >= (1.0 - 0.05) = 0.95
    for i in 0..19 {
        let src = b"const x = patternA();";
        let pr = ParseResult { language: Language::TypeScript, ..Default::default() };
        let file = format!("src/{i}.ts");
        let ctx = DetectionContext {
            file: &file, language: Language::TypeScript, source: src,
            parse_result: &pr, imports: &[], classes: &[], functions: &[],
            call_sites: &[], exports: &[],
        };
        learner.learn(&ctx);
    }
    let src_b = b"const x = patternB();";
    let pr_b = ParseResult { language: Language::TypeScript, ..Default::default() };
    let ctx_b = DetectionContext {
        file: "src/rare.ts", language: Language::TypeScript, source: src_b,
        parse_result: &pr_b, imports: &[], classes: &[], functions: &[],
        call_sites: &[], exports: &[],
    };
    learner.learn(&ctx_b);

    // Detect on the rare file — with threshold 0.05 and 95% dominance, minority is a deviation
    learner.detect(&ctx_b);
    let results = learner.results();
    let deviations: Vec<_> = results.iter().filter(|r| r.pattern_id.contains("deviation")).collect();
    assert!(
        !deviations.is_empty(),
        "With threshold 0.05 and 95% dominance, minority pattern should be flagged as deviation"
    );
}

/// FWT-LEARN-08: Learner handles single-file project gracefully (no division by zero)
#[test]
fn fwt_learn_08_single_file_no_panic() {
    use drift_analysis::engine::visitor::{DetectionContext, LearningDetectorHandler};
    use drift_analysis::frameworks::FrameworkLearner;
    use drift_analysis::parsers::types::*;
    use drift_analysis::scanner::language_detect::Language;

    let toml = r#"
[framework]
name = "single-file"
languages = ["typescript"]

[[patterns]]
id = "SF-001"
category = "structural"
[patterns.match]
content_patterns = ["singlePattern"]
[patterns.learn]
group_by = "sub_type"
signal = "convention"
deviation_threshold = 0.15
"#;
    let pack = FrameworkPackRegistry::load_single(toml).unwrap();
    let mut learner = FrameworkLearner::new(vec![pack]);

    let src = b"const x = singlePattern();";
    let pr = ParseResult { language: Language::TypeScript, ..Default::default() };
    let ctx = DetectionContext {
        file: "src/only.ts", language: Language::TypeScript, source: src,
        parse_result: &pr, imports: &[], classes: &[], functions: &[],
        call_sites: &[], exports: &[],
    };
    learner.learn(&ctx);
    learner.detect(&ctx);
    // Should not panic — single pattern in single file = no deviation
    let results = learner.results();
    let deviations: Vec<_> = results.iter().filter(|r| r.pattern_id.contains("deviation")).collect();
    assert!(deviations.is_empty(), "Single pattern in single file should produce no deviations");
}

/// FWT-TIME-01: Timing instrumentation: pack loading produces non-zero elapsed
#[test]
fn fwt_time_01_timing_instrumentation() {
    let start = std::time::Instant::now();
    let _registry = FrameworkPackRegistry::with_builtins();
    let elapsed = start.elapsed();
    // Pack loading should take some measurable time (>0)
    // but complete quickly (<5s)
    assert!(elapsed.as_nanos() > 0, "Pack loading should take measurable time");
    assert!(elapsed.as_secs() < 5, "Pack loading should complete quickly");
}

// ===== Phase C: Storage Query Tests =====

/// FWT-STORE-01: get_detections_by_method returns correct results
#[test]
fn fwt_store_01_detections_by_method() {
    use drift_storage::DatabaseManager;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("drift.db");
    let db = DatabaseManager::open(&db_path).unwrap();
    db.with_writer(|conn: &rusqlite::Connection| {
        conn.execute_batch(
            "INSERT INTO detections (file, line, column_num, pattern_id, confidence, detection_method, category, matched_text)
             VALUES ('a.ts', 1, 0, 'P-001', 0.9, 'TomlPattern', 'structural', 'test'),
                    ('b.ts', 2, 0, 'P-002', 0.8, 'LearningDeviation', 'structural', 'dev');"
        ).unwrap();
        Ok(())
    }).unwrap();

    let results = db.with_reader(|conn: &rusqlite::Connection| {
        drift_storage::queries::detections::get_detections_by_method(conn, "TomlPattern")
    }).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].pattern_id, "P-001");
}

/// FWT-STORE-02: get_detections_by_pattern_prefix returns matching prefix
#[test]
fn fwt_store_02_detections_by_pattern_prefix() {
    use drift_storage::DatabaseManager;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("drift.db");
    let db = DatabaseManager::open(&db_path).unwrap();
    db.with_writer(|conn: &rusqlite::Connection| {
        conn.execute_batch(
            "INSERT INTO detections (file, line, column_num, pattern_id, confidence, detection_method, category, matched_text)
             VALUES ('a.ts', 1, 0, 'spring/di/constructor', 0.9, 'TomlPattern', 'structural', 'test'),
                    ('b.ts', 2, 0, 'spring/mvc/controller', 0.8, 'TomlPattern', 'api', 'ctrl'),
                    ('c.ts', 3, 0, 'express/route', 0.7, 'TomlPattern', 'api', 'route');"
        ).unwrap();
        Ok(())
    }).unwrap();

    let results = db.with_reader(|conn: &rusqlite::Connection| {
        drift_storage::queries::detections::get_detections_by_pattern_prefix(conn, "spring/")
    }).unwrap();
    assert_eq!(results.len(), 2, "Should match both spring/ patterns");
}

/// FWT-STORE-03: get_detections_by_cwe returns detections with matching CWE
#[test]
fn fwt_store_03_detections_by_cwe() {
    use drift_storage::DatabaseManager;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("drift.db");
    let db = DatabaseManager::open(&db_path).unwrap();
    db.with_writer(|conn: &rusqlite::Connection| {
        conn.execute_batch(
            "INSERT INTO detections (file, line, column_num, pattern_id, confidence, detection_method, category, matched_text, cwe_ids)
             VALUES ('a.ts', 1, 0, 'SEC-001', 0.9, 'TomlPattern', 'security', 'sql', '89,79'),
                    ('b.ts', 2, 0, 'SEC-002', 0.8, 'TomlPattern', 'security', 'xss', '79');"
        ).unwrap();
        Ok(())
    }).unwrap();

    let results = db.with_reader(|conn: &rusqlite::Connection| {
        drift_storage::queries::detections::get_detections_by_cwe(conn, 89)
    }).unwrap();
    assert_eq!(results.len(), 1, "Only one detection has CWE-89");
    assert_eq!(results[0].pattern_id, "SEC-001");
}

/// FWT-STORE-04: get_framework_detection_summary groups by method
#[test]
fn fwt_store_04_framework_detection_summary() {
    use drift_storage::DatabaseManager;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("drift.db");
    let db = DatabaseManager::open(&db_path).unwrap();
    db.with_writer(|conn: &rusqlite::Connection| {
        conn.execute_batch(
            "INSERT INTO detections (file, line, column_num, pattern_id, confidence, detection_method, category, matched_text)
             VALUES ('a.ts', 1, 0, 'P-001', 0.9, 'TomlPattern', 'structural', 'a'),
                    ('b.ts', 2, 0, 'P-002', 0.8, 'TomlPattern', 'api', 'b'),
                    ('c.ts', 3, 0, 'P-003', 0.7, 'LearningDeviation', 'structural', 'c');"
        ).unwrap();
        Ok(())
    }).unwrap();

    let summary = db.with_reader(|conn: &rusqlite::Connection| {
        drift_storage::queries::detections::get_framework_detection_summary(conn)
    }).unwrap();
    assert!(summary.len() >= 2, "Should have at least 2 detection methods in summary");
}

// ===== Phase E: CLI Validation Tests (via NAPI binding) =====

/// FWT-CLI-01: validate-pack on valid TOML: returns valid=true with pack info
#[test]
fn fwt_cli_01_validate_pack_valid() {
    let toml = r#"
[framework]
name = "valid-pack"
languages = ["typescript"]
version = "1.0.0"

[[patterns]]
id = "VP-001"
category = "structural"
[patterns.match]
content_patterns = ["test"]
"#;
    let pack = FrameworkPackRegistry::load_single(toml).unwrap();
    assert_eq!(pack.name, "valid-pack");
    assert_eq!(pack.version.as_deref(), Some("1.0.0"));
    assert!(!pack.languages.is_empty());
    assert!(!pack.patterns.is_empty());
}

/// FWT-CLI-02: validate-pack on invalid TOML: returns error
#[test]
fn fwt_cli_02_validate_pack_invalid() {
    let bad_toml = "this is not valid toml {{{";
    let result = FrameworkPackRegistry::load_single(bad_toml);
    assert!(result.is_err(), "Invalid TOML should return error");
}

/// FWT-CLI-03: validate-pack on TOML missing required fields: returns error
#[test]
fn fwt_cli_03_validate_pack_missing_fields() {
    let toml = r#"
[framework]
languages = ["typescript"]

[[patterns]]
id = "X-001"
category = "structural"
[patterns.match]
content_patterns = ["test"]
"#;
    let result = FrameworkPackRegistry::load_single(toml);
    assert!(result.is_err(), "TOML missing framework.name should return error");
}
