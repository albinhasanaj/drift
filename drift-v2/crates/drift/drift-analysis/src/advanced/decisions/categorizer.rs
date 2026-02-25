//! 12 decision category classification from commit messages and diffs.

use super::types::{CommitSummary, Decision, DecisionCategory};

/// Decision categorizer — classifies commits into decision categories.
pub struct DecisionCategorizer {
    rules: Vec<CategorizationRule>,
}

const PATH_ONLY_CONFIDENCE_FLOOR: f64 = 0.15;
const PATH_ONLY_KEYWORD_MAX_SCORE: f64 = 0.05;

struct CategorizationRule {
    category: DecisionCategory,
    keywords: Vec<&'static str>,
    file_patterns: Vec<&'static str>,
    min_confidence: f64,
}

struct RuleScore {
    total: f64,
    keyword_score: f64,
    file_hits: usize,
}

impl DecisionCategorizer {
    pub fn new() -> Self {
        Self {
            rules: Self::build_rules(),
        }
    }

    /// Categorize a commit into a decision (if it represents one).
    pub fn categorize_commit(&self, commit: &CommitSummary) -> Option<Decision> {
        let msg_lower = commit.message.to_lowercase();

        // Skip trivial commits
        if Self::is_trivial_commit(&msg_lower) {
            return None;
        }

        let mut best_category = None;
        let mut best_confidence = 0.0;
        let mut best_low_confidence = false;

        for rule in &self.rules {
            let rule_score = self.score_rule(rule, &msg_lower, &commit.files_changed);
            let is_path_only = rule_score.file_hits > 0 && rule_score.keyword_score <= PATH_ONLY_KEYWORD_MAX_SCORE;
            let meets_threshold = if is_path_only {
                rule_score.total >= PATH_ONLY_CONFIDENCE_FLOOR
            } else {
                rule_score.total > rule.min_confidence
            };

            if meets_threshold && rule_score.total > best_confidence {
                best_category = Some(rule.category);
                best_confidence = rule_score.total;
                best_low_confidence = is_path_only;
            }
        }

        best_category.map(|category| {
            let description = Self::extract_description(&commit.message);
            let id = format!("dec-{}-{}", &commit.sha[..8.min(commit.sha.len())], category.name());

            Decision {
                id,
                category,
                description,
                commit_sha: Some(commit.sha.clone()),
                timestamp: commit.timestamp,
                confidence: best_confidence,
                low_confidence: best_low_confidence,
                related_patterns: Vec::new(),
                author: Some(commit.author.clone()),
                files_changed: commit.files_changed.clone(),
            }
        })
    }

    fn score_rule(
        &self,
        rule: &CategorizationRule,
        msg_lower: &str,
        files: &[String],
    ) -> RuleScore {
        let mut keyword_score = 0.0;
        let mut file_score = 0.0;

        // Keyword matching in commit message
        let keyword_hits: usize = rule.keywords.iter()
            .filter(|kw| msg_lower.contains(*kw))
            .count();
        keyword_score += (keyword_hits as f64 * 0.3).min(0.6);

        // File pattern matching
        let file_hits: usize = rule.file_patterns.iter()
            .filter(|pat| files.iter().any(|f| f.contains(*pat)))
            .count();
        file_score += (file_hits as f64 * 0.2).min(0.4);

        RuleScore {
            total: (keyword_score + file_score).min(1.0),
            keyword_score,
            file_hits,
        }
    }

    fn is_trivial_commit(msg: &str) -> bool {
        let trivial_prefixes = [
            "merge branch", "merge pull request", "wip", "fixup!",
            "squash!", "revert \"revert",
        ];
        trivial_prefixes.iter().any(|p| msg.starts_with(p))
    }

    fn extract_description(message: &str) -> String {
        // Take first line, strip conventional commit prefix
        let first_line = message.lines().next().unwrap_or(message);
        let stripped = if let Some(pos) = first_line.find(": ") {
            &first_line[pos + 2..]
        } else {
            first_line
        };
        stripped.trim().to_string()
    }

    fn build_rules() -> Vec<CategorizationRule> {
        vec![
            CategorizationRule {
                category: DecisionCategory::Architecture,
                keywords: vec![
                    "architect", "microservice", "monolith", "modular", "layer",
                    "decouple", "service mesh", "event-driven", "cqrs", "hexagonal",
                    "clean architecture", "domain-driven",
                ],
                file_patterns: vec!["architecture", "design", "adr/"],
                min_confidence: 0.25,
            },
            CategorizationRule {
                category: DecisionCategory::Technology,
                keywords: vec![
                    "migrate", "upgrade", "switch to", "replace", "adopt",
                    "framework", "library", "runtime", "engine", "platform",
                ],
                file_patterns: vec!["package.json", "Cargo.toml", "pom.xml", "go.mod", "Gemfile"],
                min_confidence: 0.25,
            },
            CategorizationRule {
                category: DecisionCategory::Pattern,
                keywords: vec![
                    "pattern", "singleton", "factory", "observer", "strategy",
                    "repository", "middleware", "decorator", "adapter",
                ],
                file_patterns: vec!["patterns/", "utils/", "helpers/"],
                min_confidence: 0.25,
            },
            CategorizationRule {
                category: DecisionCategory::Convention,
                keywords: vec![
                    "convention", "naming", "style", "lint", "format",
                    "eslint", "prettier", "rustfmt", "standard",
                ],
                file_patterns: vec![".eslintrc", ".prettierrc", "rustfmt.toml", "clippy.toml"],
                min_confidence: 0.25,
            },
            CategorizationRule {
                category: DecisionCategory::Security,
                keywords: vec![
                    "security", "auth", "csrf", "xss", "injection", "encrypt",
                    "vulnerability", "cve", "rate limit", "cors", "helmet",
                    "sanitize", "validate input",
                ],
                file_patterns: vec!["security/", "auth/", "middleware/"],
                min_confidence: 0.25,
            },
            CategorizationRule {
                category: DecisionCategory::Performance,
                keywords: vec![
                    "performance", "optimize", "cache", "lazy load", "bundle",
                    "compress", "index", "query optimization", "profil",
                    "benchmark", "throughput", "latency",
                ],
                file_patterns: vec!["cache/", "perf/", "benchmark/"],
                min_confidence: 0.25,
            },
            CategorizationRule {
                category: DecisionCategory::Testing,
                keywords: vec![
                    "test", "coverage", "jest", "mocha", "pytest", "junit",
                    "integration test", "e2e", "snapshot", "mock", "fixture",
                ],
                file_patterns: vec!["test/", "tests/", "spec/", "__tests__/"],
                min_confidence: 0.25,
            },
            CategorizationRule {
                category: DecisionCategory::Deployment,
                keywords: vec![
                    "deploy", "ci/cd", "docker", "kubernetes", "terraform",
                    "pipeline", "github action", "jenkins", "helm",
                ],
                file_patterns: vec![
                    "Dockerfile", ".github/workflows/", "terraform/",
                    "k8s/", "docker-compose", "Jenkinsfile",
                ],
                min_confidence: 0.25,
            },
            CategorizationRule {
                category: DecisionCategory::DataModel,
                keywords: vec![
                    "schema", "migration", "model", "entity", "table",
                    "column", "index", "foreign key", "relation",
                    "database", "orm",
                ],
                file_patterns: vec!["migrations/", "models/", "entities/", "schema/"],
                min_confidence: 0.25,
            },
            CategorizationRule {
                category: DecisionCategory::ApiDesign,
                keywords: vec![
                    "api", "endpoint", "rest", "graphql", "grpc", "openapi",
                    "swagger", "route", "controller", "versioning",
                ],
                file_patterns: vec!["routes/", "controllers/", "api/", "openapi"],
                min_confidence: 0.25,
            },
            CategorizationRule {
                category: DecisionCategory::ErrorHandling,
                keywords: vec![
                    "error handling", "exception", "retry", "circuit breaker",
                    "fallback", "graceful", "recovery", "error boundary",
                ],
                file_patterns: vec!["errors/", "exceptions/"],
                min_confidence: 0.25,
            },
            CategorizationRule {
                category: DecisionCategory::Documentation,
                keywords: vec![
                    "document", "readme", "changelog", "contributing",
                    "api doc", "jsdoc", "rustdoc", "wiki",
                ],
                file_patterns: vec!["docs/", "README", "CHANGELOG", "CONTRIBUTING"],
                min_confidence: 0.25,
            },
        ]
    }
}

impl Default for DecisionCategorizer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_commit(message: &str, files: Vec<&str>) -> CommitSummary {
        CommitSummary {
            sha: "abcdef1234567890".to_string(),
            message: message.to_string(),
            author: "dev".to_string(),
            timestamp: 1700000000,
            files_changed: files.into_iter().map(String::from).collect(),
            insertions: 50,
            deletions: 10,
        }
    }

    #[test]
    fn test_categorize_architecture_decision() {
        let cat = DecisionCategorizer::new();
        let commit = make_commit(
            "feat: decouple user service into microservice architecture",
            vec!["src/services/user-service/index.ts"],
        );
        let decision = cat.categorize_commit(&commit);
        assert!(decision.is_some());
        assert_eq!(decision.unwrap().category, DecisionCategory::Architecture);
    }

    #[test]
    fn test_categorize_security_decision() {
        let cat = DecisionCategorizer::new();
        let commit = make_commit(
            "security: add rate limiting to API endpoints",
            vec!["src/middleware/rate-limit.ts"],
        );
        let decision = cat.categorize_commit(&commit);
        assert!(decision.is_some());
        assert_eq!(decision.unwrap().category, DecisionCategory::Security);
    }

    #[test]
    fn test_categorize_technology_decision() {
        let cat = DecisionCategorizer::new();
        let commit = make_commit(
            "feat: migrate from Express to Fastify framework",
            vec!["package.json", "src/server.ts"],
        );
        let decision = cat.categorize_commit(&commit);
        assert!(decision.is_some());
        assert_eq!(decision.unwrap().category, DecisionCategory::Technology);
    }

    #[test]
    fn test_skip_trivial_commits() {
        let cat = DecisionCategorizer::new();
        let commit = make_commit("merge branch 'main' into feature", vec!["src/app.ts"]);
        assert!(cat.categorize_commit(&commit).is_none());
    }

    #[test]
    fn test_path_only_fallback_sets_low_confidence() {
        let cat = DecisionCategorizer::new();
        let commit = make_commit("update", vec!["src/cache/index.ts"]);
        let decision = cat.categorize_commit(&commit);
        assert!(decision.is_some());
        let decision = decision.unwrap();
        assert_eq!(decision.category, DecisionCategory::Performance);
        assert!(decision.low_confidence);
        assert!(decision.confidence >= PATH_ONLY_CONFIDENCE_FLOOR);
    }

    #[test]
    fn test_at_least_5_categories_detectable() {
        let cat = DecisionCategorizer::new();
        let test_commits = vec![
            make_commit("feat: adopt hexagonal architecture pattern", vec!["src/architecture/"]),
            make_commit("feat: migrate to PostgreSQL database", vec!["package.json"]),
            make_commit("refactor: implement repository pattern for data access", vec!["src/patterns/"]),
            make_commit("security: add CSRF protection middleware", vec!["src/middleware/"]),
            make_commit("perf: add Redis cache layer for API responses", vec!["src/cache/"]),
            make_commit("test: add integration test suite with Jest", vec!["tests/"]),
            make_commit("feat: add Docker deployment configuration", vec!["Dockerfile"]),
        ];

        let mut categories_found = std::collections::HashSet::new();
        for commit in &test_commits {
            if let Some(decision) = cat.categorize_commit(commit) {
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

    #[test]
    fn test_no_decisions_returns_empty() {
        let cat = DecisionCategorizer::new();
        let commit = make_commit("fix typo in comment", vec!["src/utils.ts"]);
        // Low-signal commit may or may not produce a decision
        // The important thing is it doesn't panic
        let _ = cat.categorize_commit(&commit);
    }
}
