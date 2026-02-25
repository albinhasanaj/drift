//! Telemetry collector — opt-in anonymous usage metrics.
//! Buffers events locally and flushes to endpoint on interval.
//! All telemetry is strictly opt-in. No PII is ever collected.

use std::path::Path;
use std::sync::{Arc, Mutex};

use serde_json::json;

use crate::config::telemetry_config::TelemetryConfig;

use super::events::{TelemetryEvent, TelemetryEventType};

/// Telemetry collector — buffers and flushes anonymous usage events.
pub struct TelemetryCollector {
    config: TelemetryConfig,
    anonymous_id: String,
    buffer: Arc<Mutex<Vec<TelemetryEvent>>>,
    drift_version: String,
    platform: String,
    enabled: bool,
}

impl TelemetryCollector {
    /// Create a new collector. If telemetry is disabled, events are silently dropped.
    pub fn new(config: &TelemetryConfig, drift_path: Option<&Path>) -> Self {
        let enabled = config.effective_enabled();
        let anonymous_id = config
            .anonymous_id
            .clone()
            .unwrap_or_else(|| load_or_create_anonymous_id(drift_path));

        Self {
            config: config.clone(),
            anonymous_id,
            buffer: Arc::new(Mutex::new(Vec::new())),
            drift_version: env!("CARGO_PKG_VERSION").to_string(),
            platform: format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
            enabled,
        }
    }

    /// Record a telemetry event. No-op if telemetry is disabled.
    pub fn record(&self, event_type: TelemetryEventType, properties: serde_json::Value) {
        if !self.enabled {
            return;
        }

        let event = TelemetryEvent {
            anonymous_id: self.anonymous_id.clone(),
            event_type,
            drift_version: self.drift_version.clone(),
            platform: self.platform.clone(),
            timestamp: current_unix_time(),
            properties,
        };

        if let Ok(mut buf) = self.buffer.lock() {
            // Cap buffer at 1000 events to prevent unbounded memory growth
            if buf.len() < 1000 {
                buf.push(event);
            }
        }
    }

    /// Convenience: record a simple event with no properties.
    pub fn record_simple(&self, event_type: TelemetryEventType) {
        self.record(event_type, json!({}));
    }

    /// Get buffered events (for flushing to endpoint).
    pub fn drain(&self) -> Vec<TelemetryEvent> {
        if let Ok(mut buf) = self.buffer.lock() {
            std::mem::take(&mut *buf)
        } else {
            Vec::new()
        }
    }

    /// Get the number of buffered events.
    pub fn pending_count(&self) -> usize {
        self.buffer.lock().map(|b| b.len()).unwrap_or(0)
    }

    /// Check if telemetry is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get the anonymous ID.
    pub fn anonymous_id(&self) -> &str {
        &self.anonymous_id
    }

    /// Get the configured endpoint URL.
    pub fn endpoint(&self) -> Option<&str> {
        self.config.endpoint.as_deref()
    }

    /// Serialize buffered events to JSON (for HTTP POST to endpoint).
    pub fn serialize_batch(&self) -> Option<String> {
        let events = self.drain();
        if events.is_empty() {
            return None;
        }
        serde_json::to_string(&events).ok()
    }
}

/// Load or create a persistent anonymous ID.
/// Stored in .drift/anonymous_id to persist across sessions.
fn load_or_create_anonymous_id(drift_path: Option<&Path>) -> String {
    if let Some(path) = drift_path {
        let id_file = path.join("anonymous_id");
        if let Ok(id) = std::fs::read_to_string(&id_file) {
            let trimmed = id.trim().to_string();
            if !trimmed.is_empty() {
                return trimmed;
            }
        }
        // Generate new ID
        let id = generate_anonymous_id();
        let _ = std::fs::write(&id_file, &id);
        return id;
    }
    generate_anonymous_id()
}

/// Generate a UUID v4-like anonymous identifier.
fn generate_anonymous_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        (ts >> 32) as u32,
        (ts >> 16) as u16,
        ts as u16 & 0x0FFF,
        (pid as u16 & 0x3FFF) | 0x8000,
        ts as u64 & 0xFFFFFFFFFFFF,
    )
}

fn current_unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_collector_drops_events() {
        let config = TelemetryConfig {
            enabled: Some(false),
            ..Default::default()
        };
        let collector = TelemetryCollector::new(&config, None);
        collector.record_simple(TelemetryEventType::ScanCompleted);
        assert_eq!(collector.pending_count(), 0);
    }

    #[test]
    fn enabled_collector_buffers_events() {
        let config = TelemetryConfig {
            enabled: Some(true),
            ..Default::default()
        };
        let collector = TelemetryCollector::new(&config, None);
        collector.record_simple(TelemetryEventType::ScanCompleted);
        collector.record_simple(TelemetryEventType::CliCommand);
        assert_eq!(collector.pending_count(), 2);
    }

    #[test]
    fn drain_clears_buffer() {
        let config = TelemetryConfig {
            enabled: Some(true),
            ..Default::default()
        };
        let collector = TelemetryCollector::new(&config, None);
        collector.record_simple(TelemetryEventType::WorkspaceInit);
        let events = collector.drain();
        assert_eq!(events.len(), 1);
        assert_eq!(collector.pending_count(), 0);
    }

    #[test]
    fn anonymous_id_format() {
        let id = generate_anonymous_id();
        assert!(id.contains('-'));
        assert!(id.len() > 20);
    }

    #[test]
    fn persistent_anonymous_id() {
        let tmp = tempfile::tempdir().unwrap();
        let id1 = load_or_create_anonymous_id(Some(tmp.path()));
        let id2 = load_or_create_anonymous_id(Some(tmp.path()));
        assert_eq!(id1, id2, "Should return same ID on second call");
    }
}
