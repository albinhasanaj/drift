//! Decay NAPI bindings: run decay on all memories and update storage.
//!
//! C-07/C-08: Provides `cortex_decay_run` — processes all memories through the
//! 5-factor decay engine, updates confidence in storage, and archives memories
//! that fall below the archival threshold.

use napi_derive::napi;
use tracing::debug;

use cortex_core::traits::IMemoryStorage;
use cortex_decay::factors::DecayContext;

use crate::conversions::error_types;
use crate::runtime;

/// Run decay on all memories: compute new confidence, update storage, archive if needed.
/// Returns JSON with `{ processed: N, archived: N, updated: N }`.
#[napi]
pub fn cortex_decay_run() -> napi::Result<serde_json::Value> {
    debug!("NAPI: decay_run");

    let rt = runtime::get()?;

    // Get all memories by querying each type — or use a broad query.
    // Use confidence range 0.0..1.0 to get all non-archived memories.
    let memories = rt
        .storage
        .query_by_confidence_range(0.0, 1.0)
        .map_err(error_types::to_napi_error)?;

    let ctx = DecayContext::default();
    let results = rt.decay.process_batch(&memories, &ctx);

    let mut archived_count = 0u64;
    let mut updated_count = 0u64;

    for (i, (decayed_confidence, decision)) in results.iter().enumerate() {
        let memory = &memories[i];
        let old_confidence = memory.confidence.value();

        // Only update if confidence actually changed meaningfully.
        if (old_confidence - decayed_confidence).abs() > 1e-6 {
            let mut updated = memory.clone();
            updated.confidence = cortex_core::memory::Confidence::new(*decayed_confidence);

            if let Err(e) = rt.storage.update(&updated) {
                debug!(memory_id = %memory.id, error = %e, "Failed to update decayed memory");
                continue;
            }
            updated_count += 1;

            // Emit temporal event for the decay.
            let _ = rt.storage.pool().writer.with_conn_sync(|conn| {
                let delta = serde_json::json!({
                    "old_confidence": old_confidence,
                    "new_confidence": decayed_confidence,
                    "action": format!("{:?}", decision),
                });
                let _ = cortex_storage::temporal_events::emit_event(
                    conn,
                    &memory.id,
                    "decayed",
                    &delta,
                    "system",
                    "decay_engine",
                );
                Ok(())
            });
        }

        // Handle archival.
        if decision.should_archive {
            let mut archived = memory.clone();
            archived.archived = true;
            archived.confidence = cortex_core::memory::Confidence::new(*decayed_confidence);
            if rt.storage.update(&archived).is_ok() {
                archived_count += 1;
            }
        }
    }

    Ok(serde_json::json!({
        "processed": memories.len(),
        "archived": archived_count,
        "updated": updated_count,
    }))
}
