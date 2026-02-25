//! drift_why MCP tool: "Why does this pattern/violation/constraint exist?"
//! Queries both Drift scan data and Cortex memories, generates causal narrative.

use serde_json::json;

use crate::errors::BridgeResult;

/// Handle the drift_why MCP tool request.
///
/// Returns a JSON response with:
/// - Drift data (pattern details, violation history, constraint info)
/// - Cortex memories (related memories, causal narrative)
/// - Combined explanation
pub fn handle_drift_why(
    entity_type: &str,
    entity_id: &str,
    bridge_db: Option<&rusqlite::Connection>,
    causal_engine: Option<&cortex_causal::CausalEngine>,
) -> BridgeResult<serde_json::Value> {
    let mut response = json!({
        "entity_type": entity_type,
        "entity_id": entity_id,
        "drift_data": {},
        "cortex_memories": [],
        "causal_narrative": null,
        "explanation": "",
    });

    // Query bridge_memories for related memories
    // Uses ESCAPE clause to prevent entity_id values containing % or _ from
    // being interpreted as LIKE wildcards (P2-9).
    if let Some(db) = bridge_db {
        let mut stmt = db.prepare(
            "SELECT id, memory_type, summary, confidence, created_at FROM bridge_memories
             WHERE summary LIKE ?1 ESCAPE '\\' OR tags LIKE ?1 ESCAPE '\\'
             ORDER BY confidence DESC LIMIT 10",
        )?;
        let escaped = crate::query::cortex_queries::escape_like(entity_id);
        let search = format!("%{}%", escaped);
        let rows = stmt.query_map(rusqlite::params![search], |row| {
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "memory_type": row.get::<_, String>(1)?,
                "summary": row.get::<_, String>(2)?,
                "confidence": row.get::<_, f64>(3)?,
                "created_at": row.get::<_, i64>(4)?,
            }))
        })?;

        let mut memories = Vec::new();
        for m in rows.flatten() {
            memories.push(m);
        }
        response["cortex_memories"] = json!(memories);

        // Query grounding history
        if let Ok(history) = crate::storage::tables::get_grounding_history(db, entity_id, 5) {
            let history_json: Vec<serde_json::Value> = history
                .iter()
                .map(|(score, classification, ts)| {
                    json!({
                        "grounding_score": score,
                        "classification": classification,
                        "timestamp": ts,
                    })
                })
                .collect();
            response["grounding_history"] = json!(history_json);
        }
    }

    // Generate causal narrative if engine is available
    if let Some(engine) = causal_engine {
        let explanation = crate::specification::narrative::explain_spec_section(entity_id, engine);
        response["causal_narrative"] = json!(explanation);
    }

    // Build combined explanation
    let memory_count = response["cortex_memories"]
        .as_array()
        .map_or(0, |a| a.len());
    let explanation = format!(
        "{} '{}': found {} related memories{}",
        entity_type,
        entity_id,
        memory_count,
        if response["causal_narrative"].is_string() {
            " with causal narrative"
        } else {
            ""
        },
    );
    response["explanation"] = json!(explanation);

    Ok(response)
}
