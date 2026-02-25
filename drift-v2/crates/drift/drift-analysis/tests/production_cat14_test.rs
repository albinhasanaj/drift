//! Production Category 14: Configuration & Initialization (Walker)
//!
//! Test: T14-04
//! Source: walker.rs:73-76 — extra_ignore patterns applied to walk_directory

use std::sync::atomic::AtomicBool;

use drift_analysis::scanner::walker::walk_directory;
use drift_core::config::ScanConfig;

/// T14-04: extra_ignore Patterns
///
/// Set `extra_ignore = ["*.generated.ts"]`. Walker must skip matching files
/// in addition to DEFAULT_IGNORES and .driftignore.
/// Source: walker.rs:73-76 — iterates `config.extra_ignore`
#[test]
fn t14_04_extra_ignore_patterns() {
    let dir = tempfile::TempDir::new().unwrap();
    let root = dir.path();

    // Create a mix of files: some should be kept, some ignored
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();

    // Normal files (should appear in results)
    std::fs::write(src.join("app.ts"), "export const app = 1;").unwrap();
    std::fs::write(src.join("utils.ts"), "export function util() {}").unwrap();
    std::fs::write(src.join("index.ts"), "import { app } from './app';").unwrap();

    // Generated files (should be excluded by extra_ignore)
    std::fs::write(src.join("api.generated.ts"), "// auto-generated").unwrap();
    std::fs::write(src.join("types.generated.ts"), "// auto-generated").unwrap();

    let cancelled = AtomicBool::new(false);

    // First: scan WITHOUT extra_ignore — generated files should appear
    let config_no_ignore = ScanConfig::default();
    let files_all = walk_directory(root, &config_no_ignore, &cancelled).unwrap();
    let all_names: Vec<String> = files_all
        .iter()
        .map(|f| f.path.file_name().unwrap().to_string_lossy().to_string())
        .collect();
    assert!(
        all_names.contains(&"api.generated.ts".to_string()),
        "Without extra_ignore, generated files should appear. Got: {:?}",
        all_names
    );
    assert!(
        all_names.contains(&"types.generated.ts".to_string()),
        "Without extra_ignore, generated files should appear. Got: {:?}",
        all_names
    );

    // Second: scan WITH extra_ignore = ["*.generated.ts"] — generated files excluded
    let config_with_ignore = ScanConfig {
        extra_ignore: vec!["*.generated.ts".to_string()],
        ..Default::default()
    };
    let files_filtered = walk_directory(root, &config_with_ignore, &cancelled).unwrap();
    let filtered_names: Vec<String> = files_filtered
        .iter()
        .map(|f| f.path.file_name().unwrap().to_string_lossy().to_string())
        .collect();

    // Generated files must NOT appear
    assert!(
        !filtered_names.contains(&"api.generated.ts".to_string()),
        "extra_ignore should exclude *.generated.ts. Got: {:?}",
        filtered_names
    );
    assert!(
        !filtered_names.contains(&"types.generated.ts".to_string()),
        "extra_ignore should exclude *.generated.ts. Got: {:?}",
        filtered_names
    );

    // Normal files must still appear
    assert!(
        filtered_names.contains(&"app.ts".to_string()),
        "Normal .ts files should survive extra_ignore. Got: {:?}",
        filtered_names
    );
    assert!(
        filtered_names.contains(&"utils.ts".to_string()),
        "Normal .ts files should survive extra_ignore. Got: {:?}",
        filtered_names
    );
    assert!(
        filtered_names.contains(&"index.ts".to_string()),
        "Normal .ts files should survive extra_ignore. Got: {:?}",
        filtered_names
    );
}
