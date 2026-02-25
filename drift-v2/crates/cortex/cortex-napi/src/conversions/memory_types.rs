//! BaseMemory ↔ serde_json::Value conversions for all 23 memory type variants.
//!
//! Since BaseMemory and all its nested types derive Serialize/Deserialize,
//! we leverage serde_json for zero-boilerplate roundtrip conversion.
//! napi's `serde-json` feature handles serde_json::Value ↔ JsObject automatically.

use cortex_core::memory::{BaseMemory, Importance, MemoryType, TypedContent};

/// Serialize a BaseMemory to a serde_json::Value for JS consumption.
pub fn memory_to_json(memory: &BaseMemory) -> napi::Result<serde_json::Value> {
    serde_json::to_value(memory)
        .map_err(|e| napi::Error::from_reason(format!("Failed to serialize BaseMemory: {e}")))
}

/// Deserialize a BaseMemory from a serde_json::Value received from JS.
pub fn memory_from_json(value: serde_json::Value) -> napi::Result<BaseMemory> {
    serde_json::from_value(value.clone()).map_err(|e| {
        let hint = if e.to_string().contains("missing field") {
            format!(
                "\nHint: The 'content' field must be {{\"type\":\"<memory_type>\",\"data\":{{...}}}}. \
                 Example: {{\"type\":\"episodic\",\"data\":{{\"interaction\":\"...\"}}}}"
            )
        } else {
            String::new()
        };
        napi::Error::from_reason(format!("Failed to deserialize BaseMemory: {e}{hint}"))
    })
}

/// Serialize a Vec<BaseMemory> to JSON array.
pub fn memories_to_json(memories: &[BaseMemory]) -> napi::Result<serde_json::Value> {
    serde_json::to_value(memories)
        .map_err(|e| napi::Error::from_reason(format!("Failed to serialize memories: {e}")))
}

/// Serialize a MemoryType to its string representation.
pub fn memory_type_to_string(mt: MemoryType) -> String {
    serde_json::to_value(mt)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| format!("{mt:?}"))
}

/// Parse a MemoryType from a string.
pub fn memory_type_from_string(s: &str) -> napi::Result<MemoryType> {
    // serde expects a JSON string value
    let json_str = format!("\"{s}\"");
    serde_json::from_str(&json_str)
        .map_err(|e| napi::Error::from_reason(format!("Invalid memory type '{s}': {e}")))
}

/// Parse an Importance from a string.
pub fn importance_from_string(s: &str) -> napi::Result<Importance> {
    let json_str = format!("\"{s}\"");
    serde_json::from_str(&json_str)
        .map_err(|e| napi::Error::from_reason(format!("Invalid importance '{s}': {e}")))
}

/// Serialize TypedContent to JSON.
pub fn typed_content_to_json(content: &TypedContent) -> napi::Result<serde_json::Value> {
    serde_json::to_value(content)
        .map_err(|e| napi::Error::from_reason(format!("Failed to serialize TypedContent: {e}")))
}

/// Deserialize TypedContent from JSON.
pub fn typed_content_from_json(value: serde_json::Value) -> napi::Result<TypedContent> {
    serde_json::from_value(value)
        .map_err(|e| napi::Error::from_reason(format!("Failed to deserialize TypedContent: {e}")))
}

/// Validate that a JSON value can roundtrip as a BaseMemory.
pub fn validate_memory_roundtrip(value: &serde_json::Value) -> napi::Result<()> {
    let memory: BaseMemory = serde_json::from_value(value.clone()).map_err(|e| {
        napi::Error::from_reason(format!(
            "Memory roundtrip validation failed (deserialize): {e}"
        ))
    })?;
    let _back = serde_json::to_value(&memory).map_err(|e| {
        napi::Error::from_reason(format!(
            "Memory roundtrip validation failed (serialize): {e}"
        ))
    })?;
    Ok(())
}
