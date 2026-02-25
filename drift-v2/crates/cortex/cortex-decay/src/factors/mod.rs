pub mod citation;
pub mod importance;
pub mod pattern;
pub mod temporal;
pub mod usage;

/// Context needed to compute all decay factors for a memory.
#[derive(Debug, Clone)]
pub struct DecayContext {
    /// Current timestamp.
    pub now: chrono::DateTime<chrono::Utc>,
    /// Ratio of stale citations (0.0 = all fresh, 1.0 = all stale).
    pub stale_citation_ratio: f64,
    /// Whether the memory's linked patterns are still active.
    pub has_active_patterns: bool,
}

impl Default for DecayContext {
    fn default() -> Self {
        Self {
            now: chrono::Utc::now(),
            stale_citation_ratio: 0.0,
            has_active_patterns: false,
        }
    }
}
