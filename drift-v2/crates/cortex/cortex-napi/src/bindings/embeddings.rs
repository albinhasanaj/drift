//! Embedding NAPI bindings: re-embed memories.
//!
//! E-01: Provides `cortex_reembed` — iterates memories, regenerates embeddings
//! via the configured provider chain, and stores them in the embeddings table.

use napi_derive::napi;
use tracing::debug;

use cortex_core::traits::IMemoryStorage;

use crate::conversions::error_types;
use crate::runtime;

/// Re-embed all memories (or a specific type). Returns JSON with counts.
#[napi]
pub fn cortex_reembed(memory_type: Option<String>) -> napi::Result<serde_json::Value> {
    debug!(memory_type = ?memory_type, "NAPI: reembed");

    let rt = runtime::get()?;

    // Get all non-archived memories, optionally filtered by type.
    let all_memories = rt
        .storage
        .query_by_confidence_range(0.0, 1.0)
        .map_err(error_types::to_napi_error)?;

    let memories: Vec<_> = match &memory_type {
        Some(mt) => {
            let parsed: cortex_core::memory::MemoryType =
                serde_json::from_str(&format!("\"{mt}\""))
                    .map_err(|e| napi::Error::from_reason(format!("Invalid memory type: {e}")))?;
            all_memories
                .into_iter()
                .filter(|m| m.memory_type == parsed)
                .collect()
        }
        None => all_memories,
    };

    let mut embeddings = rt
        .embeddings
        .lock()
        .map_err(|e| napi::Error::from_reason(format!("Embedding lock poisoned: {e}")))?;

    let mut reembedded = 0u64;
    let mut failed = 0u64;

    for memory in &memories {
        match embeddings.embed_memory(memory) {
            Ok(embedding) => {
                // Store the embedding via the writer connection.
                let mem_id = memory.id.clone();
                let hash = memory.content_hash.clone();
                if let Err(e) = rt.storage.pool().writer.with_conn_sync(|conn| {
                    cortex_storage::queries::vector_search::store_embedding(
                        conn,
                        &mem_id,
                        &hash,
                        &embedding,
                        embeddings.active_provider(),
                    )
                }) {
                    debug!(memory_id = %memory.id, error = %e, "Failed to store embedding");
                    failed += 1;
                } else {
                    reembedded += 1;
                }
            }
            Err(e) => {
                debug!(memory_id = %memory.id, error = %e, "Failed to embed memory");
                failed += 1;
            }
        }
    }

    Ok(serde_json::json!({
        "total_memories": memories.len(),
        "reembedded": reembedded,
        "failed": failed,
        "status": "reembedding_complete",
    }))
}
