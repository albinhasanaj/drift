//! Matryoshka dimension management.
//!
//! Store embeddings at full model dimensions (1024 for Jina, 2048 for Voyage).
//! Truncate to 384/256 for fast candidate search in sqlite-vec.
//! Use full dimensions for re-ranking.

use cortex_core::errors::{CortexResult, EmbeddingError};

/// Truncate an embedding to the target dimension count.
///
/// Matryoshka-trained models produce embeddings where the first N dimensions
/// capture the most important information, so simple prefix truncation works.
///
/// # Errors
/// Returns `DimensionMismatch` if `target_dims > embedding.len()`.
pub fn truncate(embedding: &[f32], target_dims: usize) -> CortexResult<Vec<f32>> {
    if target_dims > embedding.len() {
        return Err(EmbeddingError::DimensionMismatch {
            expected: target_dims,
            actual: embedding.len(),
        }
        .into());
    }

    let mut truncated = embedding[..target_dims].to_vec();

    // Re-normalize after truncation to maintain unit length.
    let norm: f32 = truncated.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > f32::EPSILON {
        for v in &mut truncated {
            *v /= norm;
        }
    }

    Ok(truncated)
}

/// Validate that an embedding has the expected dimensions.
///
/// # Errors
/// Returns `DimensionMismatch` if dimensions don't match.
pub fn validate_dimensions(embedding: &[f32], expected: usize) -> CortexResult<()> {
    if embedding.len() != expected {
        return Err(EmbeddingError::DimensionMismatch {
            expected,
            actual: embedding.len(),
        }
        .into());
    }
    Ok(())
}

/// Compute cosine similarity between two embeddings.
///
/// Assumes both vectors are already L2-normalized (returns dot product).
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    let min_len = a.len().min(b.len());
    a[..min_len]
        .iter()
        .zip(&b[..min_len])
        .map(|(x, y)| x * y)
        .sum()
}

/// Standard search dimensions for fast candidate retrieval.
pub const SEARCH_DIMS_SMALL: usize = 256;
/// Standard search dimensions for balanced speed/quality.
pub const SEARCH_DIMS_MEDIUM: usize = 384;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_reduces_dimensions() {
        let full = vec![1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];
        let truncated = truncate(&full, 4).unwrap();
        assert_eq!(truncated.len(), 4);
    }

    #[test]
    fn truncate_renormalizes() {
        let full: Vec<f32> = (0..8).map(|i| (i as f32) * 0.1).collect();
        let truncated = truncate(&full, 4).unwrap();
        let norm: f32 = truncated.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!(
            (norm - 1.0).abs() < 1e-5 || truncated.iter().all(|&x| x == 0.0),
            "truncated vector should be unit-normalized"
        );
    }

    #[test]
    fn truncate_errors_on_upscale() {
        let small = vec![1.0, 2.0];
        let result = truncate(&small, 10);
        assert!(result.is_err());
    }

    #[test]
    fn validate_dimensions_ok() {
        let v = vec![0.0; 1024];
        assert!(validate_dimensions(&v, 1024).is_ok());
    }

    #[test]
    fn validate_dimensions_mismatch() {
        let v = vec![0.0; 384];
        assert!(validate_dimensions(&v, 1024).is_err());
    }

    #[test]
    fn cosine_similarity_identical() {
        let v = vec![0.5, 0.5, 0.5, 0.5];
        let sim = cosine_similarity(&v, &v);
        // For a non-unit vector, dot product with itself = sum of squares.
        let expected: f32 = v.iter().map(|x| x * x).sum();
        assert!((sim - expected).abs() < 1e-5);
    }

    #[test]
    fn cosine_similarity_orthogonal() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![0.0, 1.0, 0.0];
        assert!((cosine_similarity(&a, &b)).abs() < 1e-5);
    }

    #[test]
    fn truncation_preserves_relative_similarity() {
        // Two similar vectors and one dissimilar.
        let a = vec![0.9, 0.1, 0.05, 0.02, 0.01, 0.01, 0.0, 0.0];
        let b = vec![0.85, 0.15, 0.04, 0.03, 0.01, 0.0, 0.0, 0.0];
        let c = vec![0.0, 0.0, 0.0, 0.0, 0.01, 0.01, 0.1, 0.9];

        let ta = truncate(&a, 4).unwrap();
        let tb = truncate(&b, 4).unwrap();
        let tc = truncate(&c, 4).unwrap();

        let sim_ab = cosine_similarity(&ta, &tb);
        let sim_ac = cosine_similarity(&ta, &tc);

        assert!(
            sim_ab > sim_ac,
            "truncation should preserve relative similarity ordering"
        );
    }
}
