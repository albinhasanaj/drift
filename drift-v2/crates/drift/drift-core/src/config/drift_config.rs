//! Top-level Drift configuration with 4-layer resolution.

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::{
    AnalysisConfig, BackupConfig, GateConfig, LicenseConfig, McpConfig, ScanConfig,
    TelemetryConfig,
};
use crate::errors::ConfigError;

/// Top-level configuration aggregating all sub-configs.
///
/// Resolution order (highest priority first):
/// 1. CLI flags (applied via `apply_cli_overrides`)
/// 2. Environment variables (`DRIFT_*`)
/// 3. Project config (`drift.toml` in project root)
/// 4. User config (`~/.drift/config.toml`)
/// 5. Compiled defaults
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DriftConfig {
    pub scan: ScanConfig,
    pub analysis: AnalysisConfig,
    pub quality_gates: GateConfig,
    pub mcp: McpConfig,
    pub backup: BackupConfig,
    pub telemetry: TelemetryConfig,
    pub licensing: LicenseConfig,
}

/// CLI override arguments that can be applied to a config.
#[derive(Debug, Clone, Default)]
pub struct CliOverrides {
    pub scan_max_file_size: Option<u64>,
    pub scan_threads: Option<usize>,
    pub gate_fail_on: Option<String>,
    pub gate_min_score: Option<u32>,
}

impl DriftConfig {
    /// Load configuration with 4-layer resolution.
    ///
    /// Resolution order (highest priority first):
    /// 1. CLI flags
    /// 2. Environment variables (`DRIFT_*`)
    /// 3. Project config (`drift.toml` in `root`)
    /// 4. User config (`~/.drift/config.toml`)
    /// 5. Compiled defaults
    pub fn load(
        root: &Path,
        cli_overrides: Option<&CliOverrides>,
    ) -> Result<Self, ConfigError> {
        let mut config = Self::default();

        // Layer 4 (lowest priority): user config
        if let Some(user_config_path) = Self::user_config_path() {
            if user_config_path.exists() {
                match Self::merge_toml_file(&mut config, &user_config_path) {
                    Ok(()) => {}
                    Err(ConfigError::ParseError { .. }) => {
                        return Err(ConfigError::ParseError {
                            path: user_config_path.display().to_string(),
                            message: "invalid TOML in user config".to_string(),
                        });
                    }
                    Err(_) => {
                        // Non-parse errors from user config are warnings, not fatal.
                        // Continue with defaults.
                    }
                }
            }
        }

        // Layer 3: project config
        let project_config_path = root.join("drift.toml");
        if project_config_path.exists() {
            Self::merge_toml_file(&mut config, &project_config_path)?;
        }

        // Layer 2: environment variables
        Self::apply_env_overrides(&mut config);

        // Layer 1 (highest priority): CLI flags
        if let Some(cli) = cli_overrides {
            Self::apply_cli_overrides(&mut config, cli);
        }

        // Validate the final config
        Self::validate(&config)?;

        Ok(config)
    }

    /// Load configuration from a TOML string (for testing).
    pub fn from_toml(toml_str: &str) -> Result<Self, ConfigError> {
        toml::from_str(toml_str).map_err(|e| ConfigError::ParseError {
            path: "<string>".to_string(),
            message: e.to_string(),
        })
    }

    /// Validate the configuration values.
    pub fn validate(config: &DriftConfig) -> Result<(), ConfigError> {
        if let Some(threshold) = config.analysis.dominance_threshold {
            if !(0.0..=1.0).contains(&threshold) {
                return Err(ConfigError::ValidationFailed {
                    field: "analysis.dominance_threshold".to_string(),
                    message: "must be between 0.0 and 1.0".to_string(),
                });
            }
        }
        if let Some(score) = config.quality_gates.min_score {
            if score > 100 {
                return Err(ConfigError::ValidationFailed {
                    field: "quality_gates.min_score".to_string(),
                    message: "must be between 0 and 100".to_string(),
                });
            }
        }
        if let Some(ref max_file_size) = config.scan.max_file_size {
            if *max_file_size == 0 {
                return Err(ConfigError::ValidationFailed {
                    field: "scan.max_file_size".to_string(),
                    message: "must be greater than 0".to_string(),
                });
            }
        }
        Ok(())
    }

    /// Returns the user config path: `~/.drift/config.toml`.
    fn user_config_path() -> Option<std::path::PathBuf> {
        dirs_path().map(|d| d.join("config.toml"))
    }

    /// Merge a TOML file into the existing config.
    /// Unknown keys are silently ignored (forward-compatible).
    fn merge_toml_file(config: &mut DriftConfig, path: &Path) -> Result<(), ConfigError> {
        let content = std::fs::read_to_string(path).map_err(|_| {
            ConfigError::FileNotFound {
                path: path.display().to_string(),
            }
        })?;

        let file_config: DriftConfig =
            toml::from_str(&content).map_err(|e| ConfigError::ParseError {
                path: path.display().to_string(),
                message: e.to_string(),
            })?;

        Self::merge(config, &file_config);
        Ok(())
    }

    /// Merge `other` into `base`, where `other` values override `base` values
    /// only when `other` has a `Some` value.
    fn merge(base: &mut DriftConfig, other: &DriftConfig) {
        // Scan
        if other.scan.max_file_size.is_some() {
            base.scan.max_file_size = other.scan.max_file_size;
        }
        if other.scan.threads.is_some() {
            base.scan.threads = other.scan.threads;
        }
        if !other.scan.extra_ignore.is_empty() {
            base.scan.extra_ignore = other.scan.extra_ignore.clone();
        }
        if other.scan.follow_symlinks.is_some() {
            base.scan.follow_symlinks = other.scan.follow_symlinks;
        }
        if other.scan.compute_hashes.is_some() {
            base.scan.compute_hashes = other.scan.compute_hashes;
        }
        if other.scan.force_full_scan.is_some() {
            base.scan.force_full_scan = other.scan.force_full_scan;
        }
        if other.scan.skip_binary.is_some() {
            base.scan.skip_binary = other.scan.skip_binary;
        }
        if other.scan.hash_algorithm.is_some() {
            base.scan.hash_algorithm = other.scan.hash_algorithm.clone();
        }
        if other.scan.driftignore_path.is_some() {
            base.scan.driftignore_path = other.scan.driftignore_path.clone();
        }
        if other.scan.incremental.is_some() {
            base.scan.incremental = other.scan.incremental;
        }
        if other.scan.parallelism.is_some() {
            base.scan.parallelism = other.scan.parallelism;
        }

        // Analysis
        if other.analysis.min_occurrences.is_some() {
            base.analysis.min_occurrences = other.analysis.min_occurrences;
        }
        if other.analysis.dominance_threshold.is_some() {
            base.analysis.dominance_threshold = other.analysis.dominance_threshold;
        }
        if other.analysis.min_files.is_some() {
            base.analysis.min_files = other.analysis.min_files;
        }
        if other.analysis.relearn_threshold.is_some() {
            base.analysis.relearn_threshold = other.analysis.relearn_threshold;
        }
        if !other.analysis.enabled_categories.is_empty() {
            base.analysis.enabled_categories = other.analysis.enabled_categories.clone();
        }
        if !other.analysis.detector_thresholds.is_empty() {
            base.analysis.detector_thresholds =
                other.analysis.detector_thresholds.clone();
        }
        if !other.analysis.gast_languages.is_empty() {
            base.analysis.gast_languages = other.analysis.gast_languages.clone();
        }
        if other.analysis.incremental.is_some() {
            base.analysis.incremental = other.analysis.incremental;
        }

        // Quality gates
        if other.quality_gates.fail_on.is_some() {
            base.quality_gates.fail_on = other.quality_gates.fail_on.clone();
        }
        if !other.quality_gates.required_gates.is_empty() {
            base.quality_gates.required_gates =
                other.quality_gates.required_gates.clone();
        }
        if other.quality_gates.min_score.is_some() {
            base.quality_gates.min_score = other.quality_gates.min_score;
        }
        if !other.quality_gates.enabled_gates.is_empty() {
            base.quality_gates.enabled_gates =
                other.quality_gates.enabled_gates.clone();
        }
        if other.quality_gates.progressive_enforcement.is_some() {
            base.quality_gates.progressive_enforcement =
                other.quality_gates.progressive_enforcement;
        }
        if other.quality_gates.ramp_up_period.is_some() {
            base.quality_gates.ramp_up_period = other.quality_gates.ramp_up_period;
        }

        // MCP
        if other.mcp.cache_ttl_seconds.is_some() {
            base.mcp.cache_ttl_seconds = other.mcp.cache_ttl_seconds;
        }
        if other.mcp.max_response_tokens.is_some() {
            base.mcp.max_response_tokens = other.mcp.max_response_tokens;
        }
        if other.mcp.transport.is_some() {
            base.mcp.transport = other.mcp.transport.clone();
        }
        if !other.mcp.enabled_tools.is_empty() {
            base.mcp.enabled_tools = other.mcp.enabled_tools.clone();
        }

        // Backup
        if other.backup.max_operational.is_some() {
            base.backup.max_operational = other.backup.max_operational;
        }
        if other.backup.max_daily.is_some() {
            base.backup.max_daily = other.backup.max_daily;
        }
        if other.backup.backup_interval.is_some() {
            base.backup.backup_interval = other.backup.backup_interval;
        }
        if other.backup.max_backups.is_some() {
            base.backup.max_backups = other.backup.max_backups;
        }
        if other.backup.backup_path.is_some() {
            base.backup.backup_path = other.backup.backup_path.clone();
        }

        // Telemetry
        if other.telemetry.enabled.is_some() {
            base.telemetry.enabled = other.telemetry.enabled;
        }
        if other.telemetry.endpoint.is_some() {
            base.telemetry.endpoint = other.telemetry.endpoint.clone();
        }
        if other.telemetry.anonymous_id.is_some() {
            base.telemetry.anonymous_id = other.telemetry.anonymous_id.clone();
        }

        // Licensing
        if other.licensing.tier != LicenseConfig::default().tier {
            base.licensing.tier = other.licensing.tier.clone();
        }
        if other.licensing.key.is_some() {
            base.licensing.key = other.licensing.key.clone();
        }
        if other.licensing.jwt_path.is_some() {
            base.licensing.jwt_path = other.licensing.jwt_path.clone();
        }
        if other.licensing.upgrade_url.is_some() {
            base.licensing.upgrade_url = other.licensing.upgrade_url.clone();
        }
        if !other.licensing.feature_flags.is_empty() {
            base.licensing.feature_flags = other.licensing.feature_flags.clone();
        }
    }

    /// Apply environment variable overrides.
    /// Pattern: `DRIFT_SCAN_MAX_FILE_SIZE`, `DRIFT_ANALYSIS_MIN_OCCURRENCES`, etc.
    fn apply_env_overrides(config: &mut DriftConfig) {
        if let Ok(val) = std::env::var("DRIFT_SCAN_MAX_FILE_SIZE") {
            if let Ok(v) = val.parse::<u64>() {
                config.scan.max_file_size = Some(v);
            }
        }
        if let Ok(val) = std::env::var("DRIFT_SCAN_THREADS") {
            if let Ok(v) = val.parse::<usize>() {
                config.scan.threads = Some(v);
            }
        }
        if let Ok(val) = std::env::var("DRIFT_ANALYSIS_MIN_OCCURRENCES") {
            if let Ok(v) = val.parse::<u32>() {
                config.analysis.min_occurrences = Some(v);
            }
        }
        if let Ok(val) = std::env::var("DRIFT_ANALYSIS_DOMINANCE_THRESHOLD") {
            if let Ok(v) = val.parse::<f64>() {
                config.analysis.dominance_threshold = Some(v);
            }
        }
        if let Ok(val) = std::env::var("DRIFT_GATE_FAIL_ON") {
            config.quality_gates.fail_on = Some(val);
        }
        if let Ok(val) = std::env::var("DRIFT_GATE_MIN_SCORE") {
            if let Ok(v) = val.parse::<u32>() {
                config.quality_gates.min_score = Some(v);
            }
        }
        if let Ok(val) = std::env::var("DRIFT_MCP_MAX_RESPONSE_TOKENS") {
            if let Ok(v) = val.parse::<u32>() {
                config.mcp.max_response_tokens = Some(v);
            }
        }
        if let Ok(val) = std::env::var("DRIFT_TELEMETRY_ENABLED") {
            if let Ok(v) = val.parse::<bool>() {
                config.telemetry.enabled = Some(v);
            }
        }
    }

    /// Apply CLI overrides (highest priority).
    fn apply_cli_overrides(config: &mut DriftConfig, cli: &CliOverrides) {
        if let Some(v) = cli.scan_max_file_size {
            config.scan.max_file_size = Some(v);
        }
        if let Some(v) = cli.scan_threads {
            config.scan.threads = Some(v);
        }
        if let Some(ref v) = cli.gate_fail_on {
            config.quality_gates.fail_on = Some(v.clone());
        }
        if let Some(v) = cli.gate_min_score {
            config.quality_gates.min_score = Some(v);
        }
    }

    /// Serialize the config back to TOML.
    pub fn to_toml(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self).map_err(|e| ConfigError::ParseError {
            path: "<serialization>".to_string(),
            message: e.to_string(),
        })
    }
}

/// Returns the user-level drift config directory: `~/.drift/`.
fn dirs_path() -> Option<std::path::PathBuf> {
    home_dir().map(|h| h.join(".drift"))
}

/// Cross-platform home directory resolution.
fn home_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
}
