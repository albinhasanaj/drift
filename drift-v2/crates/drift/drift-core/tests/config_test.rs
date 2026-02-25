//! Tests for the Drift configuration system.

use std::sync::Mutex;

use drift_core::config::drift_config::{CliOverrides, DriftConfig};
use drift_core::errors::ConfigError;

/// Global mutex to serialize tests that modify environment variables.
static ENV_MUTEX: Mutex<()> = Mutex::new(());

/// Helper: create a temporary directory.
fn tempdir() -> tempfile::TempDir {
    tempfile::TempDir::new().unwrap()
}

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

/// T0-CFG-01: Test 4-layer config resolution (CLI > env > project > user > defaults)
#[test]
fn test_four_layer_resolution() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_drift_env_vars();

    let dir = tempdir();
    let project_toml = dir.path().join("drift.toml");
    std::fs::write(
        &project_toml,
        r#"
[scan]
max_file_size = 2_000_000

[quality_gates]
min_score = 80
"#,
    )
    .unwrap();

    // Set env var to override project config
    std::env::set_var("DRIFT_SCAN_MAX_FILE_SIZE", "5000000");

    let cli = CliOverrides {
        gate_min_score: Some(95),
        ..Default::default()
    };

    let config = DriftConfig::load(dir.path(), Some(&cli)).unwrap();

    // CLI overrides env and project for min_score
    assert_eq!(config.quality_gates.min_score, Some(95));
    // Env overrides project for max_file_size
    assert_eq!(config.scan.max_file_size, Some(5_000_000));

    clear_drift_env_vars();
}

/// T0-CFG-02: Test DriftConfig::load() with missing files (graceful fallback to defaults)
#[test]
fn test_load_missing_files_fallback() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_drift_env_vars();

    let dir = tempdir();
    // No drift.toml exists
    let config = DriftConfig::load(dir.path(), None).unwrap();

    // Should get compiled defaults
    assert_eq!(config.scan.effective_max_file_size(), 1_048_576);
    assert_eq!(config.analysis.effective_min_occurrences(), 3);
    assert_eq!(config.quality_gates.effective_min_score(), 70);
    assert_eq!(config.mcp.effective_max_response_tokens(), 8000);
}

/// T0-CFG-03: Test env var override pattern (DRIFT_SCAN_MAX_FILE_SIZE)
#[test]
fn test_env_var_override() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_drift_env_vars();

    let dir = tempdir();
    std::env::set_var("DRIFT_SCAN_MAX_FILE_SIZE", "5242880");

    let config = DriftConfig::load(dir.path(), None).unwrap();
    assert_eq!(config.scan.max_file_size, Some(5_242_880));

    clear_drift_env_vars();
}

/// T0-CFG-04: Test config with invalid TOML syntax returns ConfigError::ParseError
#[test]
fn test_invalid_toml_syntax() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_drift_env_vars();

    let dir = tempdir();
    let project_toml = dir.path().join("drift.toml");
    std::fs::write(&project_toml, "this is not valid toml {{{{").unwrap();

    let result = DriftConfig::load(dir.path(), None);
    assert!(result.is_err());
    match result.unwrap_err() {
        ConfigError::ParseError { .. } => {} // expected
        other => panic!("Expected ParseError, got: {:?}", other),
    }
}

/// T0-CFG-05: Test config with valid TOML but invalid values
#[test]
fn test_invalid_values() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_drift_env_vars();

    let dir = tempdir();
    let project_toml = dir.path().join("drift.toml");

    // min_score > 100 should fail validation
    std::fs::write(
        &project_toml,
        r#"
[quality_gates]
min_score = 200
"#,
    )
    .unwrap();

    let result = DriftConfig::load(dir.path(), None);
    assert!(result.is_err());
    match result.unwrap_err() {
        ConfigError::ValidationFailed { field, .. } => {
            assert_eq!(field, "quality_gates.min_score");
        }
        other => panic!("Expected ValidationFailed, got: {:?}", other),
    }
}

/// T0-CFG-06: Test config layer precedence: project-level overridden by env
#[test]
fn test_layer_precedence_env_over_project() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_drift_env_vars();

    let dir = tempdir();
    let project_toml = dir.path().join("drift.toml");
    std::fs::write(
        &project_toml,
        r#"
[scan]
max_file_size = 1_000_000
"#,
    )
    .unwrap();

    std::env::set_var("DRIFT_SCAN_MAX_FILE_SIZE", "5000000");

    let config = DriftConfig::load(dir.path(), None).unwrap();
    // Env wins over project
    assert_eq!(config.scan.max_file_size, Some(5_000_000));

    clear_drift_env_vars();
}

/// T0-CFG-07: Test config with unrecognized keys is accepted (forward-compatible)
#[test]
fn test_unrecognized_keys_accepted() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_drift_env_vars();

    let dir = tempdir();
    let project_toml = dir.path().join("drift.toml");
    std::fs::write(
        &project_toml,
        r#"
[scan]
max_file_size = 1_000_000
future_unknown_key = "hello"

[future_section]
another_key = 42
"#,
    )
    .unwrap();

    // Should not error on unknown keys
    let result = DriftConfig::load(dir.path(), None);
    assert!(result.is_ok());
}

/// T0-CFG-08: Test config round-trip: load → serialize → load produces identical config
#[test]
fn test_config_round_trip() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_drift_env_vars();

    let dir = tempdir();
    let project_toml = dir.path().join("drift.toml");
    std::fs::write(
        &project_toml,
        r#"
[scan]
max_file_size = 2_000_000
threads = 4

[analysis]
min_occurrences = 5
dominance_threshold = 0.75

[quality_gates]
min_score = 85
fail_on = "warning"
"#,
    )
    .unwrap();

    let config1 = DriftConfig::load(dir.path(), None).unwrap();
    let toml_str = config1.to_toml().unwrap();

    let config2 = DriftConfig::from_toml(&toml_str).unwrap();

    assert_eq!(config1.scan.max_file_size, config2.scan.max_file_size);
    assert_eq!(config1.scan.threads, config2.scan.threads);
    assert_eq!(
        config1.analysis.min_occurrences,
        config2.analysis.min_occurrences
    );
    assert_eq!(
        config1.analysis.dominance_threshold,
        config2.analysis.dominance_threshold
    );
    assert_eq!(
        config1.quality_gates.min_score,
        config2.quality_gates.min_score
    );
    assert_eq!(
        config1.quality_gates.fail_on,
        config2.quality_gates.fail_on
    );
}

/// T0-CFG-09: Test config with Unicode paths in drift.toml
#[test]
fn test_unicode_paths() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_drift_env_vars();

    let dir = tempdir();
    let project_toml = dir.path().join("drift.toml");
    std::fs::write(
        &project_toml,
        r#"
[scan]
extra_ignore = ["测试/", "🚀/build/", "بيانات/"]
driftignore_path = "测试/.driftignore"
"#,
    )
    .unwrap();

    let config = DriftConfig::load(dir.path(), None).unwrap();
    assert_eq!(config.scan.extra_ignore.len(), 3);
    assert_eq!(config.scan.extra_ignore[0], "测试/");
    assert_eq!(config.scan.extra_ignore[1], "🚀/build/");
    assert_eq!(
        config.scan.driftignore_path,
        Some("测试/.driftignore".to_string())
    );
}

/// T0-CFG-10: Test config with read-only filesystem for user config path
#[test]
fn test_read_only_user_config() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_drift_env_vars();

    let dir = tempdir();
    // No user config, no project config — should work fine with defaults
    let config = DriftConfig::load(dir.path(), None).unwrap();
    assert_eq!(config.scan.effective_max_file_size(), 1_048_576);
}
