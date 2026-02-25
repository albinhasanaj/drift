//! Phase 7 Decision Mining tests — T7-DEC-01 through T7-DEC-05.

use drift_analysis::advanced::decisions::*;
use std::collections::HashSet;

fn make_commit(sha: &str, message: &str, files: Vec<&str>) -> CommitSummary {
    CommitSummary {
        sha: sha.to_string(),
        message: message.to_string(),
        author: "dev@example.com".to_string(),
        timestamp: 1700000000,
        files_changed: files.into_iter().map(String::from).collect(),
        insertions: 50,
        deletions: 10,
    }
}

// T7-DEC-01: Decision mining extracts decisions in at least 5 of 12 categories.
#[test]
fn t7_dec_01_extracts_at_least_5_categories() {
    let categorizer = DecisionCategorizer::new();

    let commits = vec![
        make_commit("aaa11111", "feat: adopt hexagonal architecture for user service", vec!["src/architecture/"]),
        make_commit("bbb22222", "feat: migrate from Express to Fastify framework", vec!["package.json"]),
        make_commit("ccc33333", "refactor: implement repository pattern for data access", vec!["src/patterns/"]),
        make_commit("ddd44444", "feat: add naming convention enforcement via eslint", vec![".eslintrc"]),
        make_commit("eee55555", "security: add CSRF protection and rate limiting", vec!["src/middleware/"]),
        make_commit("fff66666", "perf: add Redis cache layer for API responses", vec!["src/cache/"]),
        make_commit("ggg77777", "test: add integration test suite with Jest", vec!["tests/"]),
        make_commit("hhh88888", "feat: add Docker and Kubernetes deployment config", vec!["Dockerfile"]),
        make_commit("iii99999", "feat: add database migration for user schema", vec!["migrations/"]),
        make_commit("jjj00000", "feat: add REST API versioning for user endpoints", vec!["routes/"]),
        make_commit("kkk11111", "fix: improve error handling with circuit breaker", vec!["src/errors/"]),
        make_commit("lll22222", "docs: add API documentation with rustdoc", vec!["docs/"]),
    ];

    let mut categories_found = HashSet::new();
    for commit in &commits {
        if let Some(decision) = categorizer.categorize_commit(commit) {
            categories_found.insert(decision.category);
        }
    }

    assert!(
        categories_found.len() >= 5,
        "Only found {} categories: {:?}",
        categories_found.len(),
        categories_found
    );
}

// T7-DEC-02: ADR detection finds Architecture Decision Records in markdown.
#[test]
fn t7_dec_02_adr_detection_standard_format() {
    let detector = AdrDetector::new();

    let content = r#"# ADR-001: Use PostgreSQL for primary storage

## Status

Accepted

## Context

We need a reliable relational database for our application data.
The team has experience with PostgreSQL and it supports our scale requirements.

## Decision

We will use PostgreSQL as our primary database for all transactional data.

## Consequences

- Need to manage PostgreSQL infrastructure
- Team needs PostgreSQL expertise
- Good ecosystem support for ORMs
"#;

    let records = detector.detect("docs/adr/001-use-postgresql.md", content);
    assert_eq!(records.len(), 1);

    let adr = &records[0];
    assert!(adr.title.contains("PostgreSQL"));
    assert_eq!(adr.status, AdrStatus::Accepted);
    assert!(!adr.context.is_empty(), "Context should be populated");
    assert!(!adr.decision.is_empty(), "Decision should be populated");
    assert!(!adr.consequences.is_empty(), "Consequences should be populated");
}

// T7-DEC-03: Temporal correlation detected between decision and pattern change.
#[test]
fn t7_dec_03_temporal_correlation_detected() {
    use temporal::{PatternChangeEvent, PatternChangeType, TemporalCorrelator};

    let correlator = TemporalCorrelator::new();

    let decisions = vec![Decision {
        id: "d1".to_string(),
        category: DecisionCategory::Technology,
        description: "adopt Redis caching".to_string(),
        commit_sha: Some("abc123".to_string()),
        timestamp: 1000,
        confidence: 0.8,
        related_patterns: vec![],
        author: Some("dev".to_string()),
        files_changed: vec![],
    }];

    let changes = vec![PatternChangeEvent {
        id: "p1".to_string(),
        timestamp: 2000, // After decision
        pattern_name: "cache_pattern".to_string(),
        change_type: PatternChangeType::Introduced,
    }];

    let correlations = correlator.correlate(&decisions, &changes);
    assert!(!correlations.is_empty(), "Should detect temporal correlation");
    assert!(correlations[0].time_delta > 0, "Pattern change should be after decision");
    assert!(
        correlations[0].correlation_strength > 0.0,
        "Correlation strength should be positive"
    );
}

// T7-DEC-04: Decision reversal detection.
#[test]
fn t7_dec_04_reversal_detection() {
    use temporal::TemporalCorrelator;

    let correlator = TemporalCorrelator::new();

    let decisions = vec![
        Decision {
            id: "d1".to_string(),
            category: DecisionCategory::Technology,
            description: "add Redis caching layer".to_string(),
            commit_sha: Some("abc".to_string()),
            timestamp: 1000,
            confidence: 0.8,
            related_patterns: vec![],
            author: Some("dev".to_string()),
            files_changed: vec![],
        },
        Decision {
            id: "d2".to_string(),
            category: DecisionCategory::Technology,
            description: "remove Redis caching layer".to_string(),
            commit_sha: Some("def".to_string()),
            timestamp: 5000,
            confidence: 0.7,
            related_patterns: vec![],
            author: Some("dev".to_string()),
            files_changed: vec![],
        },
    ];

    let reversals = correlator.detect_reversals(&decisions);
    assert!(!reversals.is_empty(), "Should detect reversal (add → remove)");
    assert_eq!(reversals[0], ("d1".to_string(), "d2".to_string()));
}

// T7-DEC-05: Decision mining with no decisions found — empty set, not error.
#[test]
fn t7_dec_05_no_decisions_returns_empty() {
    let categorizer = DecisionCategorizer::new();

    let trivial_commits = vec![
        make_commit("aaa11111", "fix typo in comment", vec!["src/utils.ts"]),
        make_commit("bbb22222", "merge branch 'main' into feature", vec!["src/app.ts"]),
        make_commit("ccc33333", "wip save progress", vec!["src/temp.ts"]),
    ];

    let mut decisions = Vec::new();
    for commit in &trivial_commits {
        if let Some(d) = categorizer.categorize_commit(commit) {
            decisions.push(d);
        }
    }

    // Trivial/merge commits should not produce decisions
    assert!(
        decisions.is_empty(),
        "Trivial commits should not produce decisions, got {}",
        decisions.len()
    );
}

// Additional: 12 decision categories exist.
#[test]
fn test_12_decision_categories_exist() {
    assert_eq!(DecisionCategory::ALL.len(), 12);
}

// Additional: ADR status parsing.
#[test]
fn test_adr_status_parsing() {
    assert_eq!(AdrStatus::from_str_loose("accepted"), Some(AdrStatus::Accepted));
    assert_eq!(AdrStatus::from_str_loose("Proposed"), Some(AdrStatus::Proposed));
    assert_eq!(AdrStatus::from_str_loose("deprecated"), Some(AdrStatus::Deprecated));
    assert_eq!(AdrStatus::from_str_loose("superseded"), Some(AdrStatus::Superseded));
    assert_eq!(AdrStatus::from_str_loose("approved"), Some(AdrStatus::Accepted));
    assert_eq!(AdrStatus::from_str_loose("banana"), None);
}

// Additional: No ADR in regular markdown.
#[test]
fn test_no_adr_in_regular_markdown() {
    let detector = AdrDetector::new();
    let content = "# README\n\nThis is a regular readme.\n\n## Installation\n\nRun npm install.\n";
    let records = detector.detect("README.md", content);
    assert!(records.is_empty());
}

// Additional: Empty content returns empty.
#[test]
fn test_empty_content_returns_empty() {
    let detector = AdrDetector::new();
    let records = detector.detect("empty.md", "");
    assert!(records.is_empty());
}

// Additional: Temporal correlation outside window returns empty.
#[test]
fn test_no_correlation_outside_window() {
    use temporal::{PatternChangeEvent, PatternChangeType, TemporalCorrelator};

    let correlator = TemporalCorrelator::new().with_window(3600);
    let decisions = vec![Decision {
        id: "d1".into(),
        category: DecisionCategory::Technology,
        description: "adopt Redis".into(),
        commit_sha: Some("abc".into()),
        timestamp: 1000,
        confidence: 0.8,
        related_patterns: vec![],
        author: Some("dev".into()),
        files_changed: vec![],
    }];
    let changes = vec![PatternChangeEvent {
        id: "p1".into(),
        timestamp: 1_000_000,
        pattern_name: "cache".into(),
        change_type: PatternChangeType::Introduced,
    }];

    let correlations = correlator.correlate(&decisions, &changes);
    assert!(correlations.is_empty());
}
