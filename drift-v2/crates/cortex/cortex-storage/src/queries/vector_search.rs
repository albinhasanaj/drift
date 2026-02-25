//! sqlite-vec similarity search queries.

use rusqlite::{params, Connection};

use cortex_core::errors::CortexResult;
use cortex_core::memory::BaseMemory;

use crate::to_storage_err;

/// Search memories by vector similarity using stored embeddings.
/// Returns (memory, cosine_similarity) pairs ordered by similarity descending.
///
/// This uses a brute-force scan over the embeddings table since sqlite-vec
/// virtual tables require the extension to be loaded. Falls back to a
/// manual cosine similarity calculation.
pub fn search_vector(
    conn: &Connection,
    query_embedding: &[f32],
    limit: usize,
) -> CortexResult<Vec<(BaseMemory, f64)>> {
    // Get all embeddings and compute cosine similarity in Rust.
    // This is the fallback path when sqlite-vec extension isn't loaded.
    let mut stmt = conn
        .prepare(
            "SELECT mel.memory_id, me.embedding, me.dimensions
             FROM memory_embedding_link mel
             JOIN memory_embeddings me ON me.id = mel.embedding_id",
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    let rows = stmt
        .query_map([], |row| {
            let memory_id: String = row.get(0)?;
            let embedding_blob: Vec<u8> = row.get(1)?;
            let dimensions: i32 = row.get(2)?;
            Ok((memory_id, embedding_blob, dimensions))
        })
        .map_err(|e| to_storage_err(e.to_string()))?;

    // D-06: Pre-compute query norm once for early-exit on zero-norm queries.
    let query_norm_sq: f64 = query_embedding.iter().map(|x| (*x as f64) * (*x as f64)).sum();
    if query_norm_sq == 0.0 {
        return Ok(vec![]);
    }
    let query_len = query_embedding.len();

    let mut scored: Vec<(String, f64)> = Vec::new();
    for row in rows {
        let (memory_id, blob, dims) = row.map_err(|e| to_storage_err(e.to_string()))?;
        // D-06: Skip dimension mismatches without deserializing full vector.
        if dims as usize != query_len {
            continue;
        }
        let stored = bytes_to_f32_vec(&blob, dims as usize);
        let sim = cosine_similarity(query_embedding, &stored);
        if sim > 0.0 {
            scored.push((memory_id, sim));
        }
    }

    // Sort by similarity descending.
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    scored.truncate(limit);

    // Fetch the full memories.
    let mut results = Vec::with_capacity(scored.len());
    for (memory_id, sim) in scored {
        if let Some(memory) = super::memory_crud::get_memory(conn, &memory_id)? {
            results.push((memory, sim));
        }
    }

    Ok(results)
}

/// Store an embedding for a memory, deduplicating by content hash.
/// Wrapped in a SAVEPOINT for atomicity: upsert + lookup + link are all-or-nothing.
pub fn store_embedding(
    conn: &Connection,
    memory_id: &str,
    content_hash: &str,
    embedding: &[f32],
    model_name: &str,
) -> CortexResult<()> {
    conn.execute_batch("SAVEPOINT store_emb")
        .map_err(|e| to_storage_err(format!("store_embedding savepoint: {e}")))?;

    match store_embedding_inner(conn, memory_id, content_hash, embedding, model_name) {
        Ok(()) => {
            conn.execute_batch("RELEASE store_emb")
                .map_err(|e| to_storage_err(format!("store_embedding release: {e}")))?;
            Ok(())
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK TO store_emb");
            let _ = conn.execute_batch("RELEASE store_emb");
            Err(e)
        }
    }
}

/// Inner store_embedding logic.
fn store_embedding_inner(
    conn: &Connection,
    memory_id: &str,
    content_hash: &str,
    embedding: &[f32],
    model_name: &str,
) -> CortexResult<()> {
    let blob = f32_vec_to_bytes(embedding);
    let dims = embedding.len() as i32;

    // Upsert the embedding by content hash (dedup).
    conn.execute(
        "INSERT INTO memory_embeddings (content_hash, embedding, dimensions, model_name)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(content_hash) DO UPDATE SET
            embedding = excluded.embedding,
            dimensions = excluded.dimensions,
            model_name = excluded.model_name",
        params![content_hash, blob, dims, model_name],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;

    // Get the embedding ID.
    let embedding_id: i64 = conn
        .query_row(
            "SELECT id FROM memory_embeddings WHERE content_hash = ?1",
            params![content_hash],
            |row| row.get(0),
        )
        .map_err(|e| to_storage_err(e.to_string()))?;

    // Link memory to embedding.
    conn.execute(
        "INSERT INTO memory_embedding_link (memory_id, embedding_id)
         VALUES (?1, ?2)
         ON CONFLICT(memory_id) DO UPDATE SET embedding_id = excluded.embedding_id",
        params![memory_id, embedding_id],
    )
    .map_err(|e| to_storage_err(e.to_string()))?;

    Ok(())
}

/// Convert f32 slice to bytes (little-endian).
fn f32_vec_to_bytes(v: &[f32]) -> Vec<u8> {
    v.iter().flat_map(|f| f.to_le_bytes()).collect()
}

/// Convert bytes back to f32 vec.
fn bytes_to_f32_vec(bytes: &[u8], expected_dims: usize) -> Vec<f32> {
    let mut result = Vec::with_capacity(expected_dims);
    for chunk in bytes.chunks_exact(4) {
        result.push(f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }
    result
}

/// Cosine similarity between two vectors.
fn cosine_similarity(a: &[f32], b: &[f32]) -> f64 {
    let dot: f64 = a
        .iter()
        .zip(b.iter())
        .map(|(x, y)| (*x as f64) * (*y as f64))
        .sum();
    let norm_a: f64 = a
        .iter()
        .map(|x| (*x as f64) * (*x as f64))
        .sum::<f64>()
        .sqrt();
    let norm_b: f64 = b
        .iter()
        .map(|x| (*x as f64) * (*x as f64))
        .sum::<f64>()
        .sqrt();
    if norm_a == 0.0 || norm_b == 0.0 {
        return 0.0;
    }
    dot / (norm_a * norm_b)
}
