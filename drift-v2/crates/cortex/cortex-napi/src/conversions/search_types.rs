//! RetrievalContext, CompressedMemory ↔ serde_json::Value conversions.

use cortex_core::models::{CompressedMemory, RetrievalContext};

/// Serialize a RetrievalContext to JSON.
pub fn retrieval_context_to_json(ctx: &RetrievalContext) -> napi::Result<serde_json::Value> {
    serde_json::to_value(ctx)
        .map_err(|e| napi::Error::from_reason(format!("Failed to serialize RetrievalContext: {e}")))
}

/// Deserialize a RetrievalContext from JSON.
pub fn retrieval_context_from_json(value: serde_json::Value) -> napi::Result<RetrievalContext> {
    serde_json::from_value(value).map_err(|e| {
        napi::Error::from_reason(format!("Failed to deserialize RetrievalContext: {e}"))
    })
}

/// Serialize a CompressedMemory to JSON.
pub fn compressed_memory_to_json(cm: &CompressedMemory) -> napi::Result<serde_json::Value> {
    serde_json::to_value(cm)
        .map_err(|e| napi::Error::from_reason(format!("Failed to serialize CompressedMemory: {e}")))
}

/// Serialize a Vec<CompressedMemory> to JSON array.
pub fn compressed_memories_to_json(
    memories: &[CompressedMemory],
) -> napi::Result<serde_json::Value> {
    serde_json::to_value(memories).map_err(|e| {
        napi::Error::from_reason(format!("Failed to serialize CompressedMemory vec: {e}"))
    })
}
