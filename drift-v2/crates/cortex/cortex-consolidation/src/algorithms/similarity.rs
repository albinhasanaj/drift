//! Cosine similarity helpers, novelty threshold (0.85), overlap detection (0.9).

/// Novelty threshold — sentences below this similarity to the anchor are considered novel.
pub const NOVELTY_THRESHOLD: f64 = 0.85;

/// Overlap threshold — memories above this similarity are considered duplicates.
pub const OVERLAP_THRESHOLD: f64 = 0.90;

/// Cosine similarity between two vectors.
/// Returns 0.0 for zero-length or zero-magnitude vectors.
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f64 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let (mut dot, mut mag_a, mut mag_b) = (0.0f64, 0.0f64, 0.0f64);
    for (x, y) in a.iter().zip(b.iter()) {
        let (x, y) = (*x as f64, *y as f64);
        dot += x * y;
        mag_a += x * x;
        mag_b += y * y;
    }
    let denom = mag_a.sqrt() * mag_b.sqrt();
    if denom < f64::EPSILON {
        0.0
    } else {
        (dot / denom).clamp(-1.0, 1.0)
    }
}

/// Check if two texts are novel relative to each other (similarity < threshold).
pub fn is_novel(similarity: f64) -> bool {
    similarity < NOVELTY_THRESHOLD
}

/// Check if two texts overlap (similarity >= threshold).
pub fn is_overlap(similarity: f64) -> bool {
    similarity >= OVERLAP_THRESHOLD
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_vectors_have_similarity_one() {
        let v = vec![1.0, 2.0, 3.0];
        let sim = cosine_similarity(&v, &v);
        assert!((sim - 1.0).abs() < 1e-9);
    }

    #[test]
    fn orthogonal_vectors_have_similarity_zero() {
        let a = vec![1.0, 0.0];
        let b = vec![0.0, 1.0];
        let sim = cosine_similarity(&a, &b);
        assert!(sim.abs() < 1e-9);
    }

    #[test]
    fn empty_vectors_return_zero() {
        assert_eq!(cosine_similarity(&[], &[]), 0.0);
    }

    #[test]
    fn mismatched_lengths_return_zero() {
        assert_eq!(cosine_similarity(&[1.0], &[1.0, 2.0]), 0.0);
    }

    #[test]
    fn novelty_check() {
        assert!(is_novel(0.5));
        assert!(!is_novel(0.9));
    }

    #[test]
    fn overlap_check() {
        assert!(is_overlap(0.95));
        assert!(!is_overlap(0.8));
    }
}
