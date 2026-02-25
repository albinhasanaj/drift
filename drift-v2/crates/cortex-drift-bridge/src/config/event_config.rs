//! Per-event enable/disable toggles (21 events from §6.3).
//!
//! Allows operators to disable specific event→memory mappings
//! without changing license tier or recompiling.

use std::collections::HashSet;

/// Per-event toggle configuration.
/// Events not in the disabled set are enabled by default.
#[derive(Debug, Clone)]
pub struct EventConfig {
    /// Event types that are explicitly disabled.
    disabled_events: HashSet<String>,
}

impl EventConfig {
    /// Create a config with all events enabled.
    pub fn all_enabled() -> Self {
        Self {
            disabled_events: HashSet::new(),
        }
    }

    /// Create a config with specific events disabled.
    pub fn with_disabled(disabled: impl IntoIterator<Item = String>) -> Self {
        Self {
            disabled_events: disabled.into_iter().collect(),
        }
    }

    /// Check if a specific event type is enabled.
    pub fn is_enabled(&self, event_type: &str) -> bool {
        !self.disabled_events.contains(event_type)
    }

    /// Disable a specific event type.
    pub fn disable(&mut self, event_type: impl Into<String>) {
        self.disabled_events.insert(event_type.into());
    }

    /// Enable a specific event type (remove from disabled set).
    pub fn enable(&mut self, event_type: &str) {
        self.disabled_events.remove(event_type);
    }

    /// Get the set of disabled event types.
    pub fn disabled_events(&self) -> &HashSet<String> {
        &self.disabled_events
    }

    /// Number of disabled events.
    pub fn disabled_count(&self) -> usize {
        self.disabled_events.len()
    }
}

impl Default for EventConfig {
    fn default() -> Self {
        Self::all_enabled()
    }
}
