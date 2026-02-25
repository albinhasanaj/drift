//! Dirichlet-Multinomial extension for multi-value conventions.
//!
//! When a convention has >2 alternatives (e.g., 3 naming styles),
//! the Beta-Binomial model is insufficient. The Dirichlet-Multinomial
//! generalizes to K categories.

/// A multi-value convention distribution.
#[derive(Debug, Clone)]
pub struct DirichletMultinomial {
    /// Prior concentration parameters (one per category).
    /// Default: all 1.0 (uniform Dirichlet prior).
    alphas: Vec<f64>,
    /// Observed counts per category.
    counts: Vec<u64>,
    /// Category labels.
    labels: Vec<String>,
}

impl DirichletMultinomial {
    /// Create a new distribution with K categories.
    pub fn new(labels: Vec<String>) -> Self {
        let k = labels.len();
        Self {
            alphas: vec![1.0; k],
            counts: vec![0; k],
            labels,
        }
    }

    /// Record an observation for a category.
    pub fn observe(&mut self, category_index: usize) {
        if category_index < self.counts.len() {
            self.counts[category_index] += 1;
        }
    }

    /// Record multiple observations for a category.
    pub fn observe_n(&mut self, category_index: usize, count: u64) {
        if category_index < self.counts.len() {
            self.counts[category_index] += count;
        }
    }

    /// Compute posterior mean for each category.
    ///
    /// E[θ_k] = (α_k + n_k) / (Σα + N)
    pub fn posterior_means(&self) -> Vec<f64> {
        let alpha_sum: f64 = self.alphas.iter().sum();
        let n_total: f64 = self.counts.iter().sum::<u64>() as f64;
        let denom = alpha_sum + n_total;

        if denom <= 0.0 {
            return vec![1.0 / self.alphas.len() as f64; self.alphas.len()];
        }

        self.alphas
            .iter()
            .zip(self.counts.iter())
            .map(|(&a, &n)| (a + n as f64) / denom)
            .collect()
    }

    /// Find the dominant category (highest posterior mean).
    ///
    /// Returns (index, label, posterior_mean) or None if empty.
    pub fn dominant(&self) -> Option<(usize, &str, f64)> {
        let means = self.posterior_means();
        means
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(idx, &mean)| (idx, self.labels[idx].as_str(), mean))
    }

    /// Check if the distribution is contested (top two within threshold).
    pub fn is_contested(&self, threshold: f64) -> bool {
        let mut means = self.posterior_means();
        means.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
        if means.len() < 2 {
            return false;
        }
        (means[0] - means[1]).abs() <= threshold
    }

    /// Total observations.
    pub fn total_observations(&self) -> u64 {
        self.counts.iter().sum()
    }

    /// Number of categories.
    pub fn num_categories(&self) -> usize {
        self.labels.len()
    }

    /// Get counts per category.
    pub fn counts(&self) -> &[u64] {
        &self.counts
    }

    /// Get labels.
    pub fn labels(&self) -> &[String] {
        &self.labels
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uniform_prior() {
        let dist = DirichletMultinomial::new(vec!["a".into(), "b".into(), "c".into()]);
        let means = dist.posterior_means();
        for m in &means {
            assert!((m - 1.0 / 3.0).abs() < 1e-10);
        }
    }

    #[test]
    fn test_dominant_category() {
        let mut dist = DirichletMultinomial::new(vec!["camel".into(), "snake".into(), "pascal".into()]);
        dist.observe_n(0, 80); // camelCase dominant
        dist.observe_n(1, 15);
        dist.observe_n(2, 5);

        let (idx, label, mean) = dist.dominant().unwrap();
        assert_eq!(idx, 0);
        assert_eq!(label, "camel");
        assert!(mean > 0.5);
    }

    #[test]
    fn test_contested() {
        let mut dist = DirichletMultinomial::new(vec!["style_a".into(), "style_b".into()]);
        dist.observe_n(0, 45);
        dist.observe_n(1, 55);
        assert!(dist.is_contested(0.15));
    }

    #[test]
    fn test_not_contested() {
        let mut dist = DirichletMultinomial::new(vec!["style_a".into(), "style_b".into()]);
        dist.observe_n(0, 90);
        dist.observe_n(1, 10);
        assert!(!dist.is_contested(0.15));
    }
}
