use super::counter::TokenCounter;

/// Token budget tracking and allocation.
pub struct TokenBudget<'a> {
    counter: &'a TokenCounter,
}

/// Result of allocating tokens across items.
#[derive(Debug, Clone)]
pub struct Allocation {
    /// Index of the item in the input slice.
    pub index: usize,
    /// Tokens allocated to this item.
    pub tokens: usize,
}

impl<'a> TokenBudget<'a> {
    pub fn new(counter: &'a TokenCounter) -> Self {
        Self { counter }
    }

    /// How many tokens remain from a total budget after using `used`.
    pub fn remaining(total: usize, used: usize) -> usize {
        total.saturating_sub(used)
    }

    /// Whether the given text fits within the budget.
    pub fn fits(&self, text: &str, budget: usize) -> bool {
        self.counter.count_cached(text) <= budget
    }

    /// Distribute a token budget across items (texts) greedily.
    /// Items are allocated in order until the budget is exhausted.
    /// Returns allocations for items that fit.
    pub fn allocate(&self, items: &[String], budget: usize) -> Vec<Allocation> {
        let mut remaining = budget;
        let mut allocations = Vec::new();

        for (index, item) in items.iter().enumerate() {
            let tokens = self.counter.count_cached(item);
            if tokens <= remaining {
                remaining -= tokens;
                allocations.push(Allocation { index, tokens });
            }
        }

        allocations
    }
}
