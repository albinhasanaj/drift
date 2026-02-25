//! TF-IDF across cluster for distinctive key phrases.

use std::collections::HashMap;

/// Compute TF-IDF scores for terms across a set of documents.
/// Returns the top `limit` key phrases sorted by score descending.
pub fn extract_key_phrases(documents: &[String], limit: usize) -> Vec<(String, f64)> {
    if documents.is_empty() {
        return Vec::new();
    }

    let n_docs = documents.len() as f64;
    let tokenized: Vec<Vec<String>> = documents.iter().map(|d| tokenize(d)).collect();

    // Document frequency: how many documents contain each term.
    let mut df: HashMap<String, usize> = HashMap::new();
    for tokens in &tokenized {
        let unique: std::collections::HashSet<&String> = tokens.iter().collect();
        for term in unique {
            *df.entry(term.clone()).or_insert(0) += 1;
        }
    }

    // Compute TF-IDF for each term across all documents combined.
    let mut tf: HashMap<String, usize> = HashMap::new();
    let mut total_terms = 0usize;
    for tokens in &tokenized {
        for token in tokens {
            *tf.entry(token.clone()).or_insert(0) += 1;
            total_terms += 1;
        }
    }

    if total_terms == 0 {
        return Vec::new();
    }

    let mut scores: Vec<(String, f64)> = tf
        .iter()
        .filter_map(|(term, &count)| {
            let doc_freq = *df.get(term)? as f64;
            let term_freq = count as f64 / total_terms as f64;
            let idf = (n_docs / doc_freq).ln() + 1.0;
            Some((term.clone(), term_freq * idf))
        })
        .collect();

    scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    scores.truncate(limit);
    scores
}

/// Simple whitespace + lowercase tokenizer with stop word removal.
fn tokenize(text: &str) -> Vec<String> {
    text.split_whitespace()
        .map(|w| {
            w.chars()
                .filter(|c| c.is_alphanumeric())
                .collect::<String>()
                .to_lowercase()
        })
        .filter(|w| w.len() > 2 && !is_stop_word(w))
        .collect()
}

fn is_stop_word(word: &str) -> bool {
    matches!(
        word,
        "the"
            | "and"
            | "for"
            | "are"
            | "but"
            | "not"
            | "you"
            | "all"
            | "can"
            | "had"
            | "her"
            | "was"
            | "one"
            | "our"
            | "out"
            | "has"
            | "have"
            | "been"
            | "from"
            | "this"
            | "that"
            | "with"
            | "they"
            | "will"
            | "each"
            | "which"
            | "their"
            | "said"
            | "what"
            | "its"
            | "into"
            | "more"
            | "other"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_key_phrases_from_documents() {
        let docs = vec![
            "Rust memory safety is important for systems programming".to_string(),
            "Memory management in Rust prevents common bugs".to_string(),
            "Systems programming requires careful memory handling".to_string(),
        ];
        let phrases = extract_key_phrases(&docs, 5);
        assert!(!phrases.is_empty());
        // "memory" should be a top phrase since it appears in all docs.
        let terms: Vec<&str> = phrases.iter().map(|(t, _)| t.as_str()).collect();
        assert!(terms.contains(&"memory"));
    }

    #[test]
    fn empty_documents_return_empty() {
        assert!(extract_key_phrases(&[], 5).is_empty());
    }

    #[test]
    fn respects_limit() {
        let docs = vec!["one two three four five six seven eight nine ten".to_string()];
        let phrases = extract_key_phrases(&docs, 3);
        assert!(phrases.len() <= 3);
    }
}
