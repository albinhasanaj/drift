//! Context builder — 3 depth levels, intent-weighted selection, session-aware dedup.

use std::collections::HashMap;

use drift_core::errors::ContextError;
use drift_core::traits::WeightProvider;

use super::deduplication::ContextSession;
use super::intent::{ContextIntent, IntentWeights};
use super::ordering::ContentOrderer;
use crate::tokenization::budget::{ContextDepthBudget, TokenBudget};
use crate::tokenization::counter::TokenCounter;

/// Context depth levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextDepth {
    /// ~2K tokens — high-level overview.
    Overview,
    /// ~6K tokens — standard detail.
    Standard,
    /// ~12K tokens — deep analysis.
    Deep,
}

impl ContextDepth {
    pub fn to_budget(&self) -> ContextDepthBudget {
        match self {
            Self::Overview => ContextDepthBudget::Overview,
            Self::Standard => ContextDepthBudget::Standard,
            Self::Deep => ContextDepthBudget::Deep,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Overview => "overview",
            Self::Standard => "standard",
            Self::Deep => "deep",
        }
    }
}

/// Analysis data consumed by the context engine.
#[derive(Debug, Clone, Default)]
pub struct AnalysisData {
    /// Section name → content.
    pub sections: HashMap<String, String>,
}

impl AnalysisData {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_section(&mut self, name: impl Into<String>, content: impl Into<String>) {
        self.sections.insert(name.into(), content.into());
    }
}

/// Context output.
#[derive(Debug, Clone)]
pub struct ContextOutput {
    /// Ordered sections (name, content).
    pub sections: Vec<(String, String)>,
    /// Total token count.
    pub token_count: usize,
    /// Intent used.
    pub intent: ContextIntent,
    /// Depth used.
    pub depth: ContextDepth,
    /// Content hash for deduplication.
    pub content_hash: u64,
}

/// Main context engine — generates context at 3 depth levels with intent-weighted selection.
pub struct ContextEngine {
    weight_provider: Option<Box<dyn WeightProvider>>,
    token_counter: TokenCounter,
    session: Option<ContextSession>,
    orderer: ContentOrderer,
}

impl ContextEngine {
    pub fn new() -> Self {
        Self {
            weight_provider: None,
            token_counter: TokenCounter::default(),
            session: None,
            orderer: ContentOrderer::new(),
        }
    }

    pub fn with_weight_provider(mut self, provider: Box<dyn WeightProvider>) -> Self {
        self.weight_provider = Some(provider);
        self
    }

    pub fn with_session(mut self, session: ContextSession) -> Self {
        self.session = Some(session);
        self
    }

    pub fn with_model(mut self, model: &str) -> Self {
        self.token_counter = TokenCounter::new(model);
        self
    }

    /// Generate context for the given intent and depth.
    pub fn generate(
        &mut self,
        intent: ContextIntent,
        depth: ContextDepth,
        data: &AnalysisData,
    ) -> Result<ContextOutput, ContextError> {
        // Get intent weights
        let intent_weights = IntentWeights::for_intent(intent);

        // Create token budget
        let mut budget = TokenBudget::for_depth(depth.to_budget());
        budget.allocate_by_weights(&intent_weights.weights);

        // Select and truncate sections based on budget
        let mut weighted_sections = Vec::new();

        for (section_name, content) in &data.sections {
            let weight = intent_weights.weights.get(section_name).copied().unwrap_or(0.5);
            let allocation = budget.get_allocation(section_name);

            // Truncate content to fit allocation
            let truncated = self.truncate_to_tokens(content, allocation);
            if !truncated.is_empty() {
                weighted_sections.push((section_name.clone(), truncated, weight));
            }
        }

        // Handle empty data
        if weighted_sections.is_empty() {
            weighted_sections.push((
                "overview".to_string(),
                "No analysis data available.".to_string(),
                1.0,
            ));
        }

        // Order sections for optimal attention
        let ordered = self.orderer.order(weighted_sections);

        // Apply session deduplication
        let final_sections = if let Some(ref session) = self.session {
            session.deduplicate(ordered)
        } else {
            ordered
        };

        // Count total tokens
        let combined = final_sections
            .iter()
            .map(|(name, content)| format!("## {}\n\n{}", name, content))
            .collect::<Vec<_>>()
            .join("\n\n");

        let token_count = self.token_counter.count(&combined)
            .unwrap_or_else(|_| TokenCounter::count_approximate(&combined));

        let content_hash = ContextSession::hash_content(&combined);

        // Update session
        if let Some(ref mut session) = self.session {
            for (_, content) in &final_sections {
                let hash = ContextSession::hash_content(content);
                let tokens = self.token_counter.count(content)
                    .unwrap_or_else(|_| TokenCounter::count_approximate(content));
                session.mark_sent(hash, tokens);
            }
        }

        Ok(ContextOutput {
            sections: final_sections,
            token_count,
            intent,
            depth,
            content_hash,
        })
    }

    /// Truncate content to approximately fit within a token budget.
    fn truncate_to_tokens(&self, content: &str, max_tokens: usize) -> String {
        if max_tokens == 0 {
            return String::new();
        }

        let current_tokens = self.token_counter.count(content)
            .unwrap_or_else(|_| TokenCounter::count_approximate(content));

        if current_tokens <= max_tokens {
            return content.to_string();
        }

        // Approximate truncation: estimate chars per token
        let chars_per_token = content.len() as f64 / current_tokens.max(1) as f64;
        let target_chars = (max_tokens as f64 * chars_per_token) as usize;

        if target_chars >= content.len() {
            return content.to_string();
        }

        // Truncate at word boundary
        let truncated = &content[..target_chars.min(content.len())];
        match truncated.rfind(' ') {
            Some(pos) => format!("{}...", &truncated[..pos]),
            None => format!("{}...", truncated),
        }
    }
}

impl Default for ContextEngine {
    fn default() -> Self {
        Self::new()
    }
}
