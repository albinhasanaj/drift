//! Production Category 14: Configuration & Initialization
//!
//! Tests: T14-01 through T14-03
//! Source: DriftConfig, ScanConfig in drift-core/src/config/

use std::sync::Mutex;

use drift_core::config::drift_config::DriftConfig;
use drift_core::config::ScanConfig;

/// Global mutex to serialize tests that modify environment variables.
static ENV_MUTEX: Mutex<()> = Mutex::new(());

/// Clear all DRIFT_ env vars to prevent cross-test contamination.
fn clear_drift_env_vars() {
    for key in [
        "DRIFT_SCAN_MAX_FILE_SIZE",
        "DRIFT_SCAN_THREADS",
        "DRIFT_ANALYSIS_MIN_OCCURRENCES",
        "DRIFT_ANALYSIS_DOMINANCE_THRESHOLD",
        "DRIFT_GATE_FAIL_ON",
        "DRIFT_GATE_MIN_SCORE",
        "DRIFT_MCP_MAX_RESPONSE_TOKENS",
        "DRIFT_TELEMETRY_ENABLED",
    ] {
        std::env::remove_var(key);
    }
}

/// T14-01: Default ScanConfig Values
///
/// Create `ScanConfig::default()`.
/// `max_file_size` effective = 1MB (1_048_576), `threads` effective = 0 (auto),
/// `incremental` effective = true.
/// Source: scan_config.rs:36-48
#[test]
fn t14_01_default_scan_config_values() {
    let config = ScanConfig::default();

    // Raw fields are None (Option-based defaults)
    assert!(config.max_file_size.is_none());
    assert!(config.threads.is_none());
    assert!(config.incremental.is_none());

    // Effective values match documented defaults
    assert_eq!(config.effective_max_file_size(), 1_048_576);
    assert_eq!(config.effective_threads(), 0);
    assert!(config.effective_incremental());

    // Other defaults
    assert!(config.extra_ignore.is_empty());
    assert!(config.follow_symlinks.is_none());
    assert!(config.compute_hashes.is_none());
    assert!(config.force_full_scan.is_none());
    assert!(config.skip_binary.is_none());
    assert!(config.hash_algorithm.is_none());
    assert!(config.driftignore_path.is_none());
    assert!(config.parallelism.is_none());
}

/// T14-02: Config TOML Round-Trip
///
/// Serialize and deserialize `DriftConfig`. All fields must survive
/// round-trip without data loss.
/// Source: DriftConfig::from_toml() + DriftConfig::to_toml() + serde
#[test]
fn t14_02_config_toml_round_trip() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_drift_env_vars();

    // Build a config with values set across all sub-configs
    let toml_input = r#"
[scan]
max_file_size = 2_097_152
threads = 8
extra_ignore = ["*.generated.ts", "vendor/**"]
follow_symlinks = true
compute_hashes = false
force_full_scan = true
skip_binary = false
hash_algorithm = "sha256"
driftignore_path = ".custom-driftignore"
incremental = false
parallelism = 4

[analysis]
min_occurrences = 5
dominance_threshold = 0.85
min_files = 10
relearn_threshold = 0.6
enabled_categories = ["security", "patterns"]
incremental = true

[quality_gates]
min_score = 90
fail_on = "error"

[mcp]
max_response_tokens = 16000

[telemetry]
enabled = false
"#;

    let config1 = DriftConfig::from_toml(toml_input).unwrap();

    // Serialize back to TOML
    let serialized = config1.to_toml().unwrap();

    // Deserialize again
    let config2 = DriftConfig::from_toml(&serialized).unwrap();

    // Scan fields
    assert_eq!(config1.scan.max_file_size, config2.scan.max_file_size);
    assert_eq!(config1.scan.threads, config2.scan.threads);
    assert_eq!(config1.scan.extra_ignore, config2.scan.extra_ignore);
    assert_eq!(config1.scan.follow_symlinks, config2.scan.follow_symlinks);
    assert_eq!(config1.scan.compute_hashes, config2.scan.compute_hashes);
    assert_eq!(config1.scan.force_full_scan, config2.scan.force_full_scan);
    assert_eq!(config1.scan.skip_binary, config2.scan.skip_binary);
    assert_eq!(config1.scan.hash_algorithm, config2.scan.hash_algorithm);
    assert_eq!(config1.scan.driftignore_path, config2.scan.driftignore_path);
    assert_eq!(config1.scan.incremental, config2.scan.incremental);
    assert_eq!(config1.scan.parallelism, config2.scan.parallelism);

    // Analysis fields
    assert_eq!(config1.analysis.min_occurrences, config2.analysis.min_occurrences);
    assert_eq!(config1.analysis.dominance_threshold, config2.analysis.dominance_threshold);
    assert_eq!(config1.analysis.min_files, config2.analysis.min_files);
    assert_eq!(config1.analysis.relearn_threshold, config2.analysis.relearn_threshold);
    assert_eq!(config1.analysis.enabled_categories, config2.analysis.enabled_categories);
    assert_eq!(config1.analysis.incremental, config2.analysis.incremental);

    // Quality gates fields
    assert_eq!(config1.quality_gates.min_score, config2.quality_gates.min_score);
    assert_eq!(config1.quality_gates.fail_on, config2.quality_gates.fail_on);

    // MCP fields
    assert_eq!(config1.mcp.max_response_tokens, config2.mcp.max_response_tokens);

    // Telemetry fields
    assert_eq!(config1.telemetry.enabled, config2.telemetry.enabled);

    // Verify actual values survived (not just equality of two empty configs)
    assert_eq!(config2.scan.max_file_size, Some(2_097_152));
    assert_eq!(config2.scan.threads, Some(8));
    assert_eq!(config2.scan.extra_ignore, vec!["*.generated.ts", "vendor/**"]);
    assert_eq!(config2.scan.incremental, Some(false));
    assert_eq!(config2.analysis.dominance_threshold, Some(0.85));
    assert_eq!(config2.quality_gates.min_score, Some(90));
    assert_eq!(config2.quality_gates.fail_on, Some("error".to_string()));
    assert_eq!(config2.mcp.max_response_tokens, Some(16000));
    assert_eq!(config2.telemetry.enabled, Some(false));
}

/// T14-03: Project Root Fallback
///
/// Initialize runtime with no explicit config. Must load from `project_root`
/// if available, then fall back to `DriftConfig::default()`.
/// Source: runtime.rs:56-61 — `DriftConfig::load(root, None).unwrap_or_default()`
#[test]
fn t14_03_project_root_fallback() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_drift_env_vars();

    let dir = tempfile::TempDir::new().unwrap();

    // Case 1: No drift.toml → falls back to defaults
    let config = DriftConfig::load(dir.path(), None).unwrap();
    assert_eq!(config.scan.effective_max_file_size(), 1_048_576);
    assert_eq!(config.scan.effective_threads(), 0);
    assert!(config.scan.effective_incremental());
    assert!(config.scan.extra_ignore.is_empty());
    assert!(config.quality_gates.min_score.is_none());

    // Case 2: drift.toml present → values loaded from file
    let project_toml = dir.path().join("drift.toml");
    std::fs::write(
        &project_toml,
        r#"
[scan]
max_file_size = 500_000
threads = 2
extra_ignore = ["*.bak"]

[quality_gates]
min_score = 75
"#,
    )
    .unwrap();

    let config2 = DriftConfig::load(dir.path(), None).unwrap();
    assert_eq!(config2.scan.max_file_size, Some(500_000));
    assert_eq!(config2.scan.threads, Some(2));
    assert_eq!(config2.scan.extra_ignore, vec!["*.bak"]);
    assert_eq!(config2.quality_gates.min_score, Some(75));

    // Case 3: unwrap_or_default pattern — invalid dir still gives usable config
    let fallback = DriftConfig::load(dir.path(), None)
        .unwrap_or_default();
    // Should succeed (valid dir with drift.toml), but if we simulate the
    // runtime pattern with a nonexistent path, unwrap_or_default gives defaults
    let nonexistent = std::path::Path::new("/nonexistent/path/that/does/not/exist");
    let default_config = DriftConfig::load(nonexistent, None)
        .unwrap_or_default();
    assert_eq!(default_config.scan.effective_max_file_size(), 1_048_576);
    assert_eq!(default_config.scan.effective_threads(), 0);
    assert!(default_config.scan.effective_incremental());

    drop(fallback);
}
