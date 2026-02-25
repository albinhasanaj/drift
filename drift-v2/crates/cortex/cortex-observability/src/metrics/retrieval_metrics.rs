//! Per-intent hit rate, token efficiency, most/least useful, query expansion effectiveness.

use std::collections::HashMap;

use cortex_core::intent::Intent;
use serde::{Deserialize, Serialize};

/// Tracks retrieval effectiveness metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RetrievalMetrics {
    /// Per-intent hit counts (queries that returned ≥1 result).
    pub hits_by_intent: HashMap<String, u64>,
    /// Per-intent total query counts.
    pub queries_by_intent: HashMap<String, u64>,
    /// Total tokens used across all retrievals.
    pub total_tokens_used: u64,
    /// Total tokens budgeted across all retrievals.
    pub total_tokens_budgeted: u64,
    /// Memory IDs ranked by how often they appear in results.
    pub most_useful: Vec<(String, u64)>,
    /// Number of queries where expansion improved results.
    pub expansion_improvements: u64,
    /// Total queries that used expansion.
    pub expansion_attempts: u64,
}

impl RetrievalMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a retrieval query result.
    pub fn record_query(
        &mut self,
        intent: Option<Intent>,
        hit: bool,
        tokens_used: u64,
        budget: u64,
    ) {
        let key = intent
            .map(|i| format!("{:?}", i))
            .unwrap_or_else(|| "unknown".into());
        *self.queries_by_intent.entry(key.clone()).or_default() += 1;
        if hit {
            *self.hits_by_intent.entry(key).or_default() += 1;
        }
        self.total_tokens_used += tokens_used;
        self.total_tokens_budgeted += budget;
    }

    /// Record that a memory was useful in a retrieval result.
    pub fn record_useful_memory(&mut self, memory_id: &str) {
        if let Some(entry) = self.most_useful.iter_mut().find(|(id, _)| id == memory_id) {
            entry.1 += 1;
        } else {
            self.most_useful.push((memory_id.to_string(), 1));
        }
        // Keep sorted descending by count.
        self.most_useful.sort_by(|a, b| b.1.cmp(&a.1));
        self.most_useful.truncate(100);
    }

    /// Record a query expansion attempt.
    pub fn record_expansion(&mut self, improved: bool) {
        self.expansion_attempts += 1;
        if improved {
            self.expansion_improvements += 1;
        }
    }

    /// Hit rate for a specific intent.
    pub fn hit_rate(&self, intent: Intent) -> f64 {
        let key = format!("{:?}", intent);
        let queries = self.queries_by_intent.get(&key).copied().unwrap_or(0);
        if queries == 0 {
            return 0.0;
        }
        let hits = self.hits_by_intent.get(&key).copied().unwrap_or(0);
        hits as f64 / queries as f64
    }

    /// Overall token efficiency (used / budgeted).
    pub fn token_efficiency(&self) -> f64 {
        if self.total_tokens_budgeted == 0 {
            return 0.0;
        }
        self.total_tokens_used as f64 / self.total_tokens_budgeted as f64
    }
}
