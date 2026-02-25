//! Bridge WeightProvider impl: adaptive weights from Cortex Skill memories.
//!
//! Formula: adjusted_weight = base_weight × (1 + failure_rate × boost_factor)
//! where boost_factor = 0.5
//! Minimum sample size of 15-20 enforced.
//! Weights stored as Skill memory with 365-day half-life.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::Utc;
use cortex_core::memory::base::{BaseMemory, TypedContent};
use cortex_core::memory::confidence::Confidence;
use cortex_core::memory::importance::Importance;
use cortex_core::memory::types::*;
use drift_core::traits::weight_provider::{AdaptiveWeightTable, MigrationPath, WeightProvider};
use tracing::{info, warn};

use crate::traits::IBridgeStorage;

/// Boost factor for weight adjustment formula.
const BOOST_FACTOR: f64 = 0.5;

/// Minimum sample size before adaptive weights are used.
const MIN_SAMPLE_SIZE: usize = 15;

/// Maximum allowed weight for any single section.
const MAX_WEIGHT: f64 = 5.0;

/// Bridge implementation of WeightProvider.
/// Reads Cortex Skill memories and computes adaptive weights.
pub struct BridgeWeightProvider {
    /// Bridge storage for reading Skill memories.
    bridge_store: Option<Arc<dyn IBridgeStorage>>,
    /// Cached weight tables per migration path.
    cache: Mutex<HashMap<String, AdaptiveWeightTable>>,
}

impl BridgeWeightProvider {
    pub fn new(bridge_store: Option<Arc<dyn IBridgeStorage>>) -> Self {
        Self {
            bridge_store,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Create a no-op provider for standalone mode.
    pub fn no_op() -> Self {
        Self {
            bridge_store: None,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Compute adaptive weights from verification feedback.
    ///
    /// Takes a list of (section_name, was_failure) pairs and computes adjusted weights.
    pub fn compute_adaptive_weights(
        feedback: &[(String, bool)],
    ) -> AdaptiveWeightTable {
        let defaults = AdaptiveWeightTable::static_defaults();

        if feedback.len() < MIN_SAMPLE_SIZE {
            info!(
                sample_size = feedback.len(),
                min = MIN_SAMPLE_SIZE,
                "Insufficient sample size for adaptive weights — using static defaults"
            );
            return defaults;
        }

        let _total = feedback.len() as f64;
        let mut failure_counts: HashMap<String, u32> = HashMap::new();
        let total_failures: u32 = feedback.iter().filter(|(_, f)| *f).count() as u32;

        for (section, is_failure) in feedback {
            if *is_failure {
                *failure_counts.entry(section.clone()).or_insert(0) += 1;
            }
        }

        let mut weights = defaults.weights.clone();
        let mut failure_distribution = HashMap::new();

        if total_failures == 0 {
            // All passes — return static defaults (no division by zero)
            return AdaptiveWeightTable {
                weights,
                failure_distribution,
                sample_size: feedback.len(),
                last_updated: chrono::Utc::now().timestamp(),
            };
        }

        for (section, count) in &failure_counts {
            let failure_rate = *count as f64 / total_failures as f64;
            failure_distribution.insert(section.clone(), failure_rate);

            if let Some(base_weight) = weights.get(section).copied() {
                let adjusted = base_weight * (1.0 + failure_rate * BOOST_FACTOR);
                let clamped = adjusted.min(MAX_WEIGHT);
                weights.insert(section.clone(), clamped);
            } else {
                // Section not in weight table — add with default base of 1.0
                let adjusted = 1.0 * (1.0 + failure_rate * BOOST_FACTOR);
                weights.insert(section.clone(), adjusted.min(MAX_WEIGHT));
            }
        }

        AdaptiveWeightTable {
            weights,
            failure_distribution,
            sample_size: feedback.len(),
            last_updated: chrono::Utc::now().timestamp(),
        }
    }

    /// Persist computed adaptive weights as a Skill memory in bridge_memories.
    /// This makes the weights retrievable by `get_weights()` on future runs.
    pub fn persist_weights(
        conn: &rusqlite::Connection,
        path: &MigrationPath,
        table: &AdaptiveWeightTable,
    ) -> Result<String, String> {
        let memory_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();

        let skill_name = format!("{}:{}", path.source_language, path.target_language);
        let evidence_json = serde_json::to_value(&table.weights)
            .map_err(|e| format!("Failed to serialize weights: {}", e))?;

        let content = TypedContent::Skill(SkillContent {
            domain: "adaptive_weights".to_string(),
            skill_name: skill_name.clone(),
            proficiency: format!("{:.2}", table.sample_size as f64 / 100.0),
            evidence: vec![evidence_json.to_string()],
        });

        let content_hash = BaseMemory::compute_content_hash(&content)
            .unwrap_or_else(|_| blake3::hash(b"fallback").to_hex().to_string());

        let memory = BaseMemory {
            id: memory_id.clone(),
            memory_type: cortex_core::MemoryType::Skill,
            content,
            summary: format!("Adaptive weights for {} (n={})", skill_name, table.sample_size),
            transaction_time: now,
            valid_time: now,
            valid_until: None,
            confidence: Confidence::new(0.8),
            importance: Importance::Normal,
            last_accessed: now,
            access_count: 0,
            linked_patterns: vec![],
            linked_constraints: vec![],
            linked_files: vec![],
            linked_functions: vec![],
            tags: vec![
                "drift_bridge".to_string(),
                "adaptive_weights".to_string(),
                format!("path:{}", skill_name),
            ],
            archived: false,
            superseded_by: None,
            supersedes: None,
            content_hash,
            namespace: Default::default(),
            source_agent: Default::default(),
        };

        crate::storage::store_memory(conn, &memory)
            .map_err(|e| format!("Failed to persist Skill memory: {}", e))?;

        info!(
            memory_id = %memory_id,
            skill_name = %skill_name,
            sample_size = table.sample_size,
            "Persisted adaptive weights as Skill memory"
        );

        Ok(memory_id)
    }

    /// Cache key for a migration path.
    fn cache_key(path: &MigrationPath) -> String {
        format!(
            "{}:{}:{}:{}",
            path.source_language,
            path.target_language,
            path.source_framework.as_deref().unwrap_or("none"),
            path.target_framework.as_deref().unwrap_or("none"),
        )
    }
}

impl WeightProvider for BridgeWeightProvider {
    fn get_weights(&self, path: &MigrationPath) -> AdaptiveWeightTable {
        // Check cache first
        let key = Self::cache_key(path);
        if let Ok(cache) = self.cache.lock() {
            if let Some(cached) = cache.get(&key) {
                return cached.clone();
            }
        }

        // If no bridge_store, return static defaults (graceful degradation)
        let Some(ref store) = self.bridge_store else {
            return AdaptiveWeightTable::static_defaults();
        };

        // Query for Skill memories containing weight tables for this migration path
        let memories = match store.query_memories_by_type("Skill", 100) {
            Ok(rows) => rows,
            Err(e) => {
                warn!(error = %e, "Failed to query adaptive weights — using static defaults");
                return AdaptiveWeightTable::static_defaults();
            }
        };

        let search_src = &path.source_language;
        let search_tgt = &path.target_language;

        for row in &memories {
            if let Ok(content) = serde_json::from_str::<serde_json::Value>(&row.content) {
                let is_adaptive = content
                    .get("data")
                    .and_then(|d| d.get("domain"))
                    .and_then(|d| d.as_str())
                    == Some("adaptive_weights");
                let skill_matches = content
                    .get("data")
                    .and_then(|d| d.get("skill_name"))
                    .and_then(|d| d.as_str())
                    .map(|s| s.contains(search_src) && s.contains(search_tgt))
                    .unwrap_or(false);

                if is_adaptive && skill_matches {
                    if let Some(weights_obj) = content.get("data").and_then(|d| d.get("evidence")) {
                        if let Ok(weights_map) = serde_json::from_value::<HashMap<String, f64>>(
                            weights_obj.clone(),
                        ) {
                            let table = AdaptiveWeightTable {
                                weights: weights_map,
                                failure_distribution: HashMap::new(),
                                sample_size: 0,
                                last_updated: chrono::Utc::now().timestamp(),
                            };
                            // Cache it
                            if let Ok(mut cache) = self.cache.lock() {
                                cache.insert(key, table.clone());
                            }
                            return table;
                        }
                    }
                }
            }
        }

        AdaptiveWeightTable::static_defaults()
    }
}
