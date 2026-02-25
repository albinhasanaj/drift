//! Token budgeting with model-aware limits.

use std::collections::HashMap;


/// Token budget configuration for context generation.
#[derive(Debug, Clone)]
pub struct TokenBudget {
    /// Total token budget.
    pub total: usize,
    /// Per-section allocations (section name → token count).
    pub allocations: HashMap<String, usize>,
    /// Reserved tokens for structural overhead (headers, separators).
    pub overhead_reserve: usize,
}

impl TokenBudget {
    /// Create a budget for the given depth level.
    pub fn for_depth(depth: ContextDepthBudget) -> Self {
        let total = depth.token_limit();
        let overhead = (total as f64 * 0.05) as usize; // 5% overhead
        Self {
            total,
            allocations: HashMap::new(),
            overhead_reserve: overhead,
        }
    }

    /// Available tokens after overhead.
    pub fn available(&self) -> usize {
        self.total.saturating_sub(self.overhead_reserve)
    }

    /// Allocate tokens to sections based on weights.
    pub fn allocate_by_weights(&mut self, weights: &HashMap<String, f64>) {
        let total_weight: f64 = weights.values().sum();
        if total_weight <= 0.0 {
            return;
        }

        let available = self.available();
        let allocated: usize = self.allocations.values().sum();
        let remaining = available.saturating_sub(allocated);

        for (section, weight) in weights {
            let proportion = weight / total_weight;
            let tokens = (remaining as f64 * proportion) as usize;
            self.allocations.insert(section.clone(), tokens);
        }
    }

    /// Get allocation for a section.
    pub fn get_allocation(&self, section: &str) -> usize {
        self.allocations.get(section).copied().unwrap_or(0)
    }

    /// Check if total allocations are within budget.
    pub fn is_within_budget(&self) -> bool {
        let total_allocated: usize = self.allocations.values().sum();
        total_allocated + self.overhead_reserve <= self.total
    }

    /// Remaining unallocated tokens.
    pub fn remaining(&self) -> usize {
        let total_allocated: usize = self.allocations.values().sum();
        self.available().saturating_sub(total_allocated)
    }
}

/// Depth levels with token limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextDepthBudget {
    /// ~2K tokens — high-level overview.
    Overview,
    /// ~6K tokens — standard detail.
    Standard,
    /// ~12K tokens — deep analysis.
    Deep,
}

impl ContextDepthBudget {
    pub fn token_limit(&self) -> usize {
        match self {
            Self::Overview => 2048,
            Self::Standard => 6144,
            Self::Deep => 12288,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_budget_overview() {
        let budget = TokenBudget::for_depth(ContextDepthBudget::Overview);
        assert_eq!(budget.total, 2048);
        assert!(budget.available() < budget.total);
    }

    #[test]
    fn test_budget_standard() {
        let budget = TokenBudget::for_depth(ContextDepthBudget::Standard);
        assert_eq!(budget.total, 6144);
    }

    #[test]
    fn test_budget_deep() {
        let budget = TokenBudget::for_depth(ContextDepthBudget::Deep);
        assert_eq!(budget.total, 12288);
    }

    #[test]
    fn test_allocate_by_weights() {
        let mut budget = TokenBudget::for_depth(ContextDepthBudget::Standard);
        let mut weights = HashMap::new();
        weights.insert("section_a".to_string(), 2.0);
        weights.insert("section_b".to_string(), 1.0);

        budget.allocate_by_weights(&weights);

        let a = budget.get_allocation("section_a");
        let b = budget.get_allocation("section_b");
        assert!(a > b, "Higher weight should get more tokens");
        assert!(budget.is_within_budget());
    }

    #[test]
    fn test_zero_weights_no_panic() {
        let mut budget = TokenBudget::for_depth(ContextDepthBudget::Overview);
        let weights = HashMap::new();
        budget.allocate_by_weights(&weights);
        assert!(budget.is_within_budget());
    }
}
