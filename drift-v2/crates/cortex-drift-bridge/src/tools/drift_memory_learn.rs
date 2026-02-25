//! drift_memory_learn MCP tool: "Learn from this Drift correction."
//! Creates a Feedback memory from a user-provided correction.

use chrono::Utc;
use cortex_core::memory::base::{BaseMemory, TypedContent};
use cortex_core::memory::confidence::Confidence;
use cortex_core::memory::importance::Importance;
use cortex_core::memory::types::FeedbackContent;
use serde_json::json;

use crate::errors::BridgeResult;

/// Handle the drift_memory_learn MCP tool request.
///
/// Creates a Feedback memory from a user correction and returns the memory ID.
pub fn handle_drift_memory_learn(
    entity_type: &str,
    entity_id: &str,
    correction: &str,
    category: &str,
    bridge_db: Option<&rusqlite::Connection>,
) -> BridgeResult<serde_json::Value> {
    let memory_id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();

    let content = TypedContent::Feedback(FeedbackContent {
        feedback: format!(
            "User correction for {} '{}': {}",
            entity_type, entity_id, correction
        ),
        category: category.to_string(),
        source: "drift_memory_learn".to_string(),
    });

    let content_hash = BaseMemory::compute_content_hash(&content)
        .unwrap_or_else(|_| blake3::hash(b"fallback").to_hex().to_string());

    let memory = BaseMemory {
        id: memory_id.clone(),
        memory_type: cortex_core::MemoryType::Feedback,
        content,
        summary: format!("User correction: {} {} — {}", entity_type, entity_id, category),
        transaction_time: now,
        valid_time: now,
        valid_until: None,
        confidence: Confidence::new(0.9),
        importance: Importance::High,
        last_accessed: now,
        access_count: 0,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: vec![
            "drift_bridge".to_string(),
            "user_correction".to_string(),
            format!("entity_type:{}", entity_type),
            format!("entity_id:{}", entity_id),
            format!("category:{}", category),
        ],
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash,
        namespace: Default::default(),
        source_agent: Default::default(),
    };

    if let Some(db) = bridge_db {
        crate::storage::store_memory(db, &memory)?;
        crate::storage::log_event(
            db,
            "drift_memory_learn",
            Some("Feedback"),
            Some(&memory_id),
            Some(0.9),
        )?;
    }

    Ok(json!({
        "memory_id": memory_id,
        "status": "created",
        "entity_type": entity_type,
        "entity_id": entity_id,
        "category": category,
    }))
}
