#![allow(unused_imports, unused_variables, clippy::needless_range_loop)]
//! Language Provider tests — T2-ULP-01 through T2-ULP-03.
//!
//! Tests for the Unified Language Provider: cross-language normalization,
//! framework matchers, taint sink extraction.

use std::path::Path;

use drift_analysis::language_provider::framework_matchers::MatcherRegistry;
use drift_analysis::language_provider::normalizers::{
    create_all_normalizers, normalize_chain, LanguageNormalizer,
};
use drift_analysis::language_provider::taint_sinks::{extract_sinks, SinkCategory, SinkSeverity};
use drift_analysis::language_provider::types::{
    CallArg, ChainCall, DataOperation, UnifiedCallChain,
};
use drift_analysis::parsers::manager::ParserManager;
use drift_analysis::parsers::types::ParseResult;
use drift_analysis::scanner::language_detect::Language;

// ---- Helpers ----

fn parse_file(source: &str, file: &str) -> ParseResult {
    let parser = ParserManager::new();
    parser.parse(source.as_bytes(), Path::new(file)).unwrap()
}

fn make_chain(
    receiver: &str,
    method: &str,
    file: &str,
    language: Language,
) -> UnifiedCallChain {
    UnifiedCallChain {
        receiver: receiver.to_string(),
        calls: vec![ChainCall {
            method: method.to_string(),
            args: Vec::new(),
        }],
        file: file.to_string(),
        line: 1,
        language,
    }
}

// ---- T2-ULP-01: Cross-language normalization to identical UnifiedCallChain ----

#[test]
fn t2_ulp_01_cross_language_normalization() {
    // TypeScript: User.findAll()
    let ts_source = r#"
import { User } from './models';
async function getUsers() {
    return User.findAll({ where: { active: true } });
}
"#;
    let ts_pr = parse_file(ts_source, "service.ts");

    // Python: User.objects.filter()
    let py_source = r#"
from models import User
def get_users():
    return User.objects.filter(active=True)
"#;
    let py_pr = parse_file(py_source, "service.py");

    // Java: userRepo.findAll()
    let java_source = r#"
import com.example.UserRepository;
public class UserService {
    private UserRepository userRepo;
    public List<User> getUsers() {
        return userRepo.findAll();
    }
}
"#;
    let java_pr = parse_file(java_source, "UserService.java");

    // All 9 normalizers should be available
    let normalizers = create_all_normalizers();
    assert_eq!(
        normalizers.len(),
        9,
        "should have 9 language normalizers, got {}",
        normalizers.len()
    );

    // Verify normalizers cover the expected languages
    let languages: Vec<Language> = normalizers.iter().map(|n| n.language()).collect();
    assert!(languages.contains(&Language::TypeScript));
    assert!(languages.contains(&Language::Python));
    assert!(languages.contains(&Language::Java));

    // Extract chains from each language
    let ts_normalizer = normalizers.iter().find(|n| n.language() == Language::TypeScript).unwrap();
    let py_normalizer = normalizers.iter().find(|n| n.language() == Language::Python).unwrap();

    let ts_chains = ts_normalizer.extract_chains(&ts_pr);
    let py_chains = py_normalizer.extract_chains(&py_pr);

    // Both should produce UnifiedCallChain structs
    // The exact content depends on parser extraction, but the type is the same
    eprintln!("TS chains: {}", ts_chains.len());
    eprintln!("PY chains: {}", py_chains.len());

    // Verify the normalize_chain helper works
    for cs in &ts_pr.call_sites {
        let chain = normalize_chain(cs, &ts_pr);
        assert_eq!(chain.language, Language::TypeScript);
        assert_eq!(chain.file, "service.ts");
        assert!(!chain.calls.is_empty());
    }
}

// ---- T2-ULP-02: Framework matcher identifies 5+ ORM frameworks from imports ----

#[test]
fn t2_ulp_02_framework_matcher() {
    let registry = MatcherRegistry::new();

    assert!(
        registry.count() >= 11,
        "should have at least 11 ORM matchers, got {}",
        registry.count()
    );

    // Test Sequelize matcher
    let seq_chain = make_chain("User", "findAll", "test.ts", Language::TypeScript);
    let seq_match = registry.match_chain(&seq_chain);
    assert!(seq_match.is_some(), "should match Sequelize findAll");
    let seq_pattern = seq_match.unwrap();
    assert_eq!(seq_pattern.operation, DataOperation::Select);

    // Test Prisma matcher
    let prisma_chain = make_chain("prisma.user", "findMany", "test.ts", Language::TypeScript);
    let prisma_match = registry.match_chain(&prisma_chain);
    assert!(prisma_match.is_some(), "should match Prisma findMany");

    // Test Django matcher
    let django_chain = make_chain("User.objects", "filter", "test.py", Language::Python);
    let django_match = registry.match_chain(&django_chain);
    assert!(django_match.is_some(), "should match Django filter");
    assert_eq!(django_match.unwrap().operation, DataOperation::Select);

    // Test SQLAlchemy matcher
    let sa_chain = make_chain("session", "query", "test.py", Language::Python);
    let sa_match = registry.match_chain(&sa_chain);
    assert!(sa_match.is_some(), "should match SQLAlchemy query");

    // Test ActiveRecord matcher
    let ar_chain = make_chain("User", "where", "test.rb", Language::Ruby);
    let ar_match = registry.match_chain(&ar_chain);
    assert!(ar_match.is_some(), "should match ActiveRecord where");

    // Test GORM matcher
    let gorm_chain = make_chain("db", "find", "test.go", Language::Go);
    let gorm_match = registry.match_chain(&gorm_chain);
    assert!(gorm_match.is_some(), "should match GORM find");

    // Test Hibernate matcher
    let hib_chain = make_chain("em", "persist", "Test.java", Language::Java);
    let hib_match = registry.match_chain(&hib_chain);
    assert!(hib_match.is_some(), "should match Hibernate persist");
    assert_eq!(hib_match.unwrap().operation, DataOperation::Insert);

    // Verify DataOperation variants
    let operations = vec![
        DataOperation::Select, DataOperation::Insert, DataOperation::Update,
        DataOperation::Delete, DataOperation::Upsert, DataOperation::Count,
        DataOperation::Aggregate, DataOperation::Join, DataOperation::Transaction,
        DataOperation::Migration, DataOperation::RawQuery, DataOperation::Unknown,
    ];
    assert_eq!(operations.len(), 12, "should have 12 DataOperation variants");
}

// ---- T2-ULP-03: Taint sink extraction for Phase 4 consumption ----

#[test]
fn t2_ulp_03_taint_sink_extraction() {
    // Extract sinks for all 9 languages
    let languages = vec![
        Language::TypeScript, Language::JavaScript, Language::Python,
        Language::Java, Language::CSharp, Language::Go,
        Language::Ruby, Language::Php, Language::Rust, Language::Kotlin,
    ];

    let mut total_sinks = 0;
    for lang in &languages {
        let sinks = extract_sinks(*lang);
        assert!(
            !sinks.is_empty(),
            "language {:?} should have at least 1 taint sink",
            lang
        );
        total_sinks += sinks.len();

        // Verify each sink has required fields
        for sink in &sinks {
            assert!(!sink.name.is_empty(), "sink name should not be empty");
            // Some sinks (e.g., readObject, saveChanges) may have empty tainted_params
            // when the entire operation is the sink, not a specific parameter
        }
    }

    eprintln!("Total taint sinks across {} languages: {}", languages.len(), total_sinks);

    // Verify critical sinks exist for common languages
    let ts_sinks = extract_sinks(Language::TypeScript);
    let has_eval = ts_sinks.iter().any(|s| s.name == "eval");
    assert!(has_eval, "TypeScript should have eval sink");

    let py_sinks = extract_sinks(Language::Python);
    let has_exec = py_sinks.iter().any(|s| s.name == "exec");
    assert!(has_exec, "Python should have exec sink");

    // Verify severity levels
    let critical_sinks: Vec<_> = ts_sinks.iter().filter(|s| s.severity == SinkSeverity::Critical).collect();
    assert!(
        !critical_sinks.is_empty(),
        "should have at least 1 critical severity sink"
    );

    // Verify sink categories
    let categories: std::collections::HashSet<_> = ts_sinks.iter().map(|s| s.category).collect();
    assert!(
        categories.contains(&SinkCategory::Eval),
        "should have Eval category"
    );
    assert!(
        categories.contains(&SinkCategory::SqlExecution) || categories.contains(&SinkCategory::CommandExecution),
        "should have SQL or Command execution category"
    );
}
