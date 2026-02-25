//! Strategic content ordering — primacy-recency for transformer attention.
//!
//! Places the most important content at the beginning and end of the context
//! window, leveraging the primacy-recency effect in transformer attention.

/// Content orderer — arranges sections for optimal transformer attention.
pub struct ContentOrderer;

impl ContentOrderer {
    pub fn new() -> Self {
        Self
    }

    /// Order sections using primacy-recency strategy.
    ///
    /// Highest-weight sections go first (primacy) and last (recency).
    /// Medium-weight sections go in the middle.
    pub fn order(&self, mut sections: Vec<(String, String, f64)>) -> Vec<(String, String)> {
        if sections.len() <= 2 {
            return sections.into_iter().map(|(name, content, _)| (name, content)).collect();
        }

        // Sort by weight descending
        sections.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));

        let mut ordered = Vec::with_capacity(sections.len());
        let mut front = Vec::new();
        let mut middle = Vec::new();
        let mut back = Vec::new();

        for (i, (name, content, _weight)) in sections.into_iter().enumerate() {
            if i == 0 {
                // Highest weight → first (primacy)
                front.push((name, content));
            } else if i == 1 {
                // Second highest → last (recency)
                back.push((name, content));
            } else {
                // Rest → middle
                middle.push((name, content));
            }
        }

        ordered.extend(front);
        ordered.extend(middle);
        ordered.extend(back);

        ordered
    }
}

impl Default for ContentOrderer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ordering_primacy_recency() {
        let orderer = ContentOrderer::new();
        let sections = vec![
            ("low".to_string(), "low content".to_string(), 0.5),
            ("high".to_string(), "high content".to_string(), 2.0),
            ("medium".to_string(), "medium content".to_string(), 1.0),
            ("second".to_string(), "second content".to_string(), 1.5),
        ];

        let ordered = orderer.order(sections);
        assert_eq!(ordered[0].0, "high"); // Primacy
        assert_eq!(ordered.last().unwrap().0, "second"); // Recency
    }

    #[test]
    fn test_ordering_single_section() {
        let orderer = ContentOrderer::new();
        let sections = vec![("only".to_string(), "content".to_string(), 1.0)];
        let ordered = orderer.order(sections);
        assert_eq!(ordered.len(), 1);
    }

    #[test]
    fn test_ordering_empty() {
        let orderer = ContentOrderer::new();
        let ordered = orderer.order(vec![]);
        assert!(ordered.is_empty());
    }
}
