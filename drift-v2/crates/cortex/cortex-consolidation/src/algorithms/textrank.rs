//! TextRank: sentences as nodes, cosine similarity as edges, PageRank iteration.
//! Used to generate summaries of memory clusters.

use super::sentence_splitter::split_sentences;
use super::similarity::cosine_similarity;

/// Damping factor for PageRank iteration.
const DAMPING: f64 = 0.85;
/// Convergence threshold.
const CONVERGENCE: f64 = 1e-6;
/// Maximum iterations.
const MAX_ITERATIONS: usize = 100;

/// Generate a summary from text using TextRank.
/// Returns the top `num_sentences` ranked sentences joined together.
pub fn summarize(text: &str, num_sentences: usize) -> String {
    let sentences = split_sentences(text);
    if sentences.is_empty() {
        return String::new();
    }
    if sentences.len() <= num_sentences {
        return sentences.join(" ");
    }

    let ranked = rank_sentences(&sentences);
    let mut indexed: Vec<(usize, f64)> = ranked.into_iter().enumerate().collect();
    indexed.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    // Take top N, then re-sort by original position for coherent output.
    let mut top: Vec<usize> = indexed
        .iter()
        .take(num_sentences)
        .map(|(i, _)| *i)
        .collect();
    top.sort();

    top.iter()
        .map(|&i| sentences[i].as_str())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Rank sentences using TextRank (PageRank on sentence similarity graph).
/// Returns a score for each sentence.
fn rank_sentences(sentences: &[String]) -> Vec<f64> {
    let n = sentences.len();
    if n == 0 {
        return Vec::new();
    }
    if n == 1 {
        return vec![1.0];
    }

    // Build simple word-overlap vectors for sentence similarity.
    let vectors = build_word_vectors(sentences);

    // Build similarity matrix.
    let mut sim_matrix = vec![vec![0.0f64; n]; n];
    for i in 0..n {
        for j in (i + 1)..n {
            let s = cosine_similarity(&vectors[i], &vectors[j]);
            sim_matrix[i][j] = s;
            sim_matrix[j][i] = s;
        }
    }

    // PageRank iteration.
    let mut scores = vec![1.0 / n as f64; n];
    for _ in 0..MAX_ITERATIONS {
        let mut new_scores = vec![0.0f64; n];
        let mut max_diff = 0.0f64;

        for i in 0..n {
            let mut sum = 0.0f64;
            for j in 0..n {
                if i == j {
                    continue;
                }
                let out_sum: f64 = (0..n).filter(|&k| k != j).map(|k| sim_matrix[j][k]).sum();
                if out_sum > f64::EPSILON {
                    sum += sim_matrix[j][i] * scores[j] / out_sum;
                }
            }
            new_scores[i] = (1.0 - DAMPING) / n as f64 + DAMPING * sum;
            max_diff = max_diff.max((new_scores[i] - scores[i]).abs());
        }

        scores = new_scores;
        if max_diff < CONVERGENCE {
            break;
        }
    }

    scores
}

/// Build simple TF word vectors for cosine similarity.
fn build_word_vectors(sentences: &[String]) -> Vec<Vec<f32>> {
    // Collect vocabulary.
    let mut vocab: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for sentence in sentences {
        for word in sentence.split_whitespace() {
            let w = word.to_lowercase();
            let len = vocab.len();
            vocab.entry(w).or_insert(len);
        }
    }

    let dim = vocab.len();
    sentences
        .iter()
        .map(|s| {
            let mut vec = vec![0.0f32; dim];
            for word in s.split_whitespace() {
                if let Some(&idx) = vocab.get(&word.to_lowercase()) {
                    vec[idx] += 1.0;
                }
            }
            vec
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarize_returns_nonempty_for_valid_text() {
        let text = "Rust is a systems programming language. \
                     It focuses on safety and performance. \
                     Memory safety is guaranteed at compile time. \
                     The borrow checker prevents data races.";
        let summary = summarize(text, 2);
        assert!(!summary.is_empty());
    }

    #[test]
    fn summarize_returns_all_for_short_text() {
        let text = "One sentence.";
        let summary = summarize(text, 3);
        assert_eq!(summary, "One sentence.");
    }

    #[test]
    fn summarize_empty_returns_empty() {
        assert!(summarize("", 2).is_empty());
    }

    #[test]
    fn rank_sentences_produces_scores() {
        let sentences = vec![
            "Rust is great.".to_string(),
            "Rust is fast.".to_string(),
            "Python is slow.".to_string(),
        ];
        let scores = rank_sentences(&sentences);
        assert_eq!(scores.len(), 3);
        assert!(scores.iter().all(|&s| s > 0.0));
    }
}
