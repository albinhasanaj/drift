//! Telemetry event types — anonymous usage metrics.
//! All events are opt-in only and contain no PII.

use serde::{Deserialize, Serialize};

/// Telemetry event — a single anonymous usage data point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    /// Anonymous installation ID (UUID v4, generated once per workspace).
    pub anonymous_id: String,
    /// Event type.
    pub event_type: TelemetryEventType,
    /// Drift version.
    pub drift_version: String,
    /// Platform (os/arch).
    pub platform: String,
    /// Timestamp (Unix seconds).
    pub timestamp: u64,
    /// Event-specific properties.
    #[serde(default)]
    pub properties: serde_json::Value,
}

/// All telemetry event types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryEventType {
    /// Workspace initialized.
    WorkspaceInit,
    /// Scan completed.
    ScanCompleted,
    /// Quality gate check run.
    QualityGateCheck,
    /// MCP server started.
    McpServerStarted,
    /// CLI command executed.
    CliCommand,
    /// Error encountered (category only, no details).
    ErrorEncountered,
    /// License tier active.
    LicenseTierActive,
    /// CI environment detected.
    CiDetected,
}

impl TelemetryEventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::WorkspaceInit => "workspace_init",
            Self::ScanCompleted => "scan_completed",
            Self::QualityGateCheck => "quality_gate_check",
            Self::McpServerStarted => "mcp_server_started",
            Self::CliCommand => "cli_command",
            Self::ErrorEncountered => "error_encountered",
            Self::LicenseTierActive => "license_tier_active",
            Self::CiDetected => "ci_detected",
        }
    }
}
