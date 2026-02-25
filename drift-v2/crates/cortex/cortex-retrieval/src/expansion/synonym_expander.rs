//! Synonym/related term expansion, code-aware.
//!
//! Expands queries with related terms to improve recall.
//! E.g., "auth" → "authentication middleware login session".

use std::collections::HashMap;

/// Code-aware synonym map. Maps common abbreviations and terms to related expansions.
fn synonym_map() -> HashMap<&'static str, &'static [&'static str]> {
    let mut m = HashMap::new();
    m.insert(
        "auth",
        &[
            "authentication",
            "authorization",
            "login",
            "session",
            "jwt",
            "oauth",
        ][..],
    );
    m.insert("db", &["database", "sql", "query", "migration", "schema"]);
    m.insert("api", &["endpoint", "route", "handler", "rest", "graphql"]);
    m.insert(
        "ui",
        &["frontend", "component", "render", "view", "template"],
    );
    m.insert(
        "test",
        &["spec", "assertion", "mock", "fixture", "coverage"],
    );
    m.insert("deploy", &["release", "ci", "cd", "pipeline", "rollback"]);
    m.insert(
        "perf",
        &[
            "performance",
            "latency",
            "throughput",
            "benchmark",
            "optimization",
        ],
    );
    m.insert("err", &["error", "exception", "failure", "panic", "crash"]);
    m.insert(
        "config",
        &["configuration", "settings", "env", "environment"],
    );
    m.insert("cache", &["caching", "memoize", "invalidation", "ttl"]);
    m.insert("log", &["logging", "trace", "debug", "observability"]);
    m.insert("sec", &["security", "vulnerability", "encryption", "tls"]);
    m.insert(
        "async",
        &["concurrent", "parallel", "future", "promise", "await"],
    );
    m.insert(
        "msg",
        &["message", "event", "queue", "pubsub", "notification"],
    );
    m
}

/// Expand a query with code-aware synonyms.
///
/// Returns the original query with additional related terms appended.
pub fn expand(query: &str) -> String {
    let map = synonym_map();
    let words: Vec<&str> = query.split_whitespace().collect();
    let mut expansions: Vec<&str> = Vec::new();

    for word in &words {
        let lower = word.to_lowercase();
        if let Some(synonyms) = map.get(lower.as_str()) {
            for syn in *synonyms {
                if !words.iter().any(|w| w.eq_ignore_ascii_case(syn)) {
                    expansions.push(syn);
                }
            }
        }
    }

    if expansions.is_empty() {
        return query.to_string();
    }

    // Limit expansion to avoid query bloat.
    expansions.truncate(5);
    format!("{} {}", query, expansions.join(" "))
}
