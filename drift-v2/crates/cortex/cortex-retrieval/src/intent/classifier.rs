//! Intent classification from query context: keyword matching, file type heuristics,
//! recent action patterns.

use cortex_core::intent::Intent;
use cortex_core::models::RetrievalContext;

/// Keyword patterns mapped to intents.
const INTENT_KEYWORDS: &[(Intent, &[&str])] = &[
    (
        Intent::FixBug,
        &[
            "fix",
            "bug",
            "error",
            "crash",
            "broken",
            "issue",
            "debug",
            "failing",
            "exception",
        ],
    ),
    (
        Intent::AddFeature,
        &["add", "feature", "implement", "create", "build", "new"],
    ),
    (
        Intent::Refactor,
        &[
            "refactor",
            "clean",
            "restructure",
            "simplify",
            "extract",
            "rename",
            "move",
        ],
    ),
    (
        Intent::SecurityAudit,
        &[
            "security",
            "vulnerability",
            "audit",
            "cve",
            "injection",
            "xss",
            "csrf",
            "auth",
        ],
    ),
    (
        Intent::UnderstandCode,
        &[
            "understand",
            "explain",
            "how",
            "what",
            "why",
            "where",
            "trace",
            "flow",
        ],
    ),
    (
        Intent::AddTest,
        &["test", "coverage", "spec", "assert", "mock", "fixture"],
    ),
    (
        Intent::ReviewCode,
        &[
            "review",
            "pr",
            "pull request",
            "feedback",
            "approve",
            "comment",
        ],
    ),
    (
        Intent::DeployMigrate,
        &[
            "deploy", "migrate", "release", "rollback", "ci", "cd", "pipeline",
        ],
    ),
    (
        Intent::Create,
        &[
            "scaffold",
            "init",
            "bootstrap",
            "setup",
            "generate",
            "template",
        ],
    ),
    (
        Intent::Investigate,
        &["investigate", "analyze", "diagnose", "root cause", "bisect"],
    ),
    (
        Intent::Decide,
        &[
            "decide",
            "choose",
            "compare",
            "tradeoff",
            "pros",
            "cons",
            "alternative",
        ],
    ),
    (
        Intent::Recall,
        &["remember", "recall", "last time", "previously", "before"],
    ),
    (
        Intent::Learn,
        &["learn", "tutorial", "guide", "documentation", "example"],
    ),
    (
        Intent::Summarize,
        &["summarize", "summary", "overview", "tldr", "recap"],
    ),
    (
        Intent::Compare,
        &["compare", "diff", "versus", "vs", "difference"],
    ),
];

/// File extension heuristics for intent classification.
const FILE_INTENT_HINTS: &[(&str, Intent)] = &[
    (".test.", Intent::AddTest),
    (".spec.", Intent::AddTest),
    ("_test.", Intent::AddTest),
    ("test_", Intent::AddTest),
    (".config.", Intent::Create),
    ("Dockerfile", Intent::DeployMigrate),
    (".yml", Intent::DeployMigrate),
    (".yaml", Intent::DeployMigrate),
    ("migration", Intent::DeployMigrate),
];

/// Classify intent from a retrieval context.
///
/// Priority: explicit intent > keyword matching > file heuristics > default.
pub fn classify(context: &RetrievalContext) -> Intent {
    // If the context already has an intent, use it.
    if let Some(intent) = context.intent {
        return intent;
    }

    let query_lower = context.focus.to_lowercase();

    // Keyword matching: score each intent by keyword hits.
    let mut best_intent = Intent::Recall;
    let mut best_score = 0usize;

    for &(intent, keywords) in INTENT_KEYWORDS {
        let score = keywords
            .iter()
            .filter(|kw| query_lower.contains(**kw))
            .count();
        if score > best_score {
            best_score = score;
            best_intent = intent;
        }
    }

    if best_score > 0 {
        return best_intent;
    }

    // File type heuristics from active files.
    for file in &context.active_files {
        for &(pattern, intent) in FILE_INTENT_HINTS {
            if file.contains(pattern) {
                return intent;
            }
        }
    }

    // Default: Recall (general memory retrieval).
    Intent::Recall
}
