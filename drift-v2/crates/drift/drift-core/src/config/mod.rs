//! Configuration system for Drift.
//! TOML-based, 4-layer resolution: CLI > env > project > user > defaults.

pub mod analysis_config;
pub mod backup_config;
pub mod drift_config;
pub mod gate_config;
pub mod license_config;
pub mod mcp_config;
pub mod scan_config;
pub mod telemetry_config;

pub use analysis_config::AnalysisConfig;
pub use backup_config::BackupConfig;
pub use drift_config::DriftConfig;
pub use gate_config::GateConfig;
pub use license_config::LicenseConfig;
pub use mcp_config::McpConfig;
pub use scan_config::ScanConfig;
pub use telemetry_config::TelemetryConfig;
