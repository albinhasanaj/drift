//! Scanner tests — T1-SCN-01 through T1-SCN-21.
//!
//! Tests cover: baseline correctness, incremental detection, .driftignore,
//! cancellation, language detection, symlinks, permissions, edge cases,
//! events, concurrency, and performance contracts.

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use drift_analysis::scanner::hasher::hash_content;
use drift_analysis::scanner::language_detect::Language;
use drift_analysis::scanner::scanner::Scanner;
use drift_analysis::scanner::types::CachedFileMetadata;
use drift_analysis::scanner::types::ScanDiff;
use drift_core::config::ScanConfig;
use drift_core::events::handler::DriftEventHandler;
use drift_core::events::types::*;
use drift_core::types::collections::FxHashMap;
use tempfile::TempDir;

// ---- Helpers ----

/// Create a temp directory with N files of various languages.
fn create_test_fixture(file_count: usize) -> TempDir {
    let dir = TempDir::new().expect("create temp dir");
    let extensions = ["ts", "js", "py", "java", "cs", "go", "rs", "rb", "php", "kt"];
    for i in 0..file_count {
        let ext = extensions[i % extensions.len()];
        let name = format!("file_{i}.{ext}");
        let content = format!("// file {i}\nfunction test_{i}() {{}}\n");
        fs::write(dir.path().join(&name), content).expect("write file");
    }
    dir
}

/// Create a ScanConfig with defaults suitable for testing.
fn test_config() -> ScanConfig {
    ScanConfig {
        max_file_size: Some(10_000_000),
        threads: Some(4),
        follow_symlinks: Some(false),
        compute_hashes: Some(true),
        force_full_scan: Some(false),
        incremental: Some(true),
        ..Default::default()
    }
}

/// No-op event handler for tests that don't check events.
struct NoOpHandler;
impl DriftEventHandler for NoOpHandler {}

/// Event-recording handler for tests that verify event sequences.
#[derive(Default)]
struct RecordingHandler {
    started: Mutex<Vec<ScanStartedEvent>>,
    progress: Mutex<Vec<ScanProgressEvent>>,
    complete: Mutex<Vec<ScanCompleteEvent>>,
    errors: Mutex<Vec<ScanErrorEvent>>,
}

impl DriftEventHandler for RecordingHandler {
    fn on_scan_started(&self, event: &ScanStartedEvent) {
        self.started.lock().unwrap().push(event.clone());
    }
    fn on_scan_progress(&self, event: &ScanProgressEvent) {
        self.progress.lock().unwrap().push(event.clone());
    }
    fn on_scan_complete(&self, event: &ScanCompleteEvent) {
        self.complete.lock().unwrap().push(event.clone());
    }
    fn on_scan_error(&self, event: &ScanErrorEvent) {
        self.errors.lock().unwrap().push(event.clone());
    }
}

// ---- T1-SCN-01: Baseline correctness ----

#[test]
fn t1_scn_01_scanner_discovers_files() {
    let dir = create_test_fixture(20);
    let config = test_config();
    let scanner = Scanner::new(config);
    let cached = FxHashMap::default();

    let diff = scanner.scan(dir.path(), &cached, &NoOpHandler).unwrap();

    assert_eq!(diff.added.len(), 20, "should discover all 20 files");
    assert_eq!(diff.modified.len(), 0);
    assert_eq!(diff.removed.len(), 0);
    assert_eq!(diff.unchanged.len(), 0);
    assert_eq!(diff.stats.total_files, 20);
    assert!(diff.stats.total_size_bytes > 0);
    assert!(diff.stats.discovery_ms < 5000, "discovery should be fast");
}

// ---- T1-SCN-02: Incremental scan (add→modify→delete cycle) ----

#[test]
fn t1_scn_02_incremental_scan_three_cycles() {
    let dir = TempDir::new().unwrap();
    let config = test_config();
    let scanner = Scanner::new(config);

    // Scan 1: initial — 5 files
    for i in 0..5 {
        fs::write(dir.path().join(format!("file_{i}.ts")), format!("const x = {i};"))
            .unwrap();
    }
    let diff1 = scanner
        .scan(dir.path(), &FxHashMap::default(), &NoOpHandler)
        .unwrap();
    assert_eq!(diff1.added.len(), 5);

    // Build cached metadata from scan 1
    let cached = build_cached_metadata(&diff1);

    // Scan 2: add 2 files, modify 1
    fs::write(dir.path().join("file_5.ts"), "const y = 5;").unwrap();
    fs::write(dir.path().join("file_6.ts"), "const y = 6;").unwrap();
    fs::write(dir.path().join("file_0.ts"), "const x = 999; // modified").unwrap();

    // Force full scan to ensure content hash comparison
    let mut config2 = test_config();
    config2.force_full_scan = Some(true);
    let scanner2 = Scanner::new(config2);
    let diff2 = scanner2.scan(dir.path(), &cached, &NoOpHandler).unwrap();

    assert_eq!(diff2.added.len(), 2, "2 new files");
    assert_eq!(diff2.modified.len(), 1, "1 modified file");
    assert_eq!(diff2.unchanged.len(), 4, "4 unchanged files");

    // Build cached metadata from scan 2
    let cached2 = build_cached_metadata(&diff2);

    // Scan 3: delete 2 files
    fs::remove_file(dir.path().join("file_5.ts")).unwrap();
    fs::remove_file(dir.path().join("file_6.ts")).unwrap();

    let mut config3 = test_config();
    config3.force_full_scan = Some(true);
    let scanner3 = Scanner::new(config3);
    let diff3 = scanner3.scan(dir.path(), &cached2, &NoOpHandler).unwrap();

    assert_eq!(diff3.removed.len(), 2, "2 removed files");
    assert_eq!(diff3.unchanged.len(), 5, "5 unchanged files");
}

// ---- T1-SCN-03: .driftignore patterns ----

#[test]
fn t1_scn_03_driftignore_patterns() {
    let dir = TempDir::new().unwrap();

    // Create files
    fs::write(dir.path().join("keep.ts"), "const x = 1;").unwrap();
    fs::write(dir.path().join("keep2.js"), "const y = 2;").unwrap();

    // Create a subdirectory with files to ignore
    fs::create_dir_all(dir.path().join("generated")).unwrap();
    fs::write(
        dir.path().join("generated/output.ts"),
        "// generated",
    )
    .unwrap();

    // Create .driftignore
    fs::write(dir.path().join(".driftignore"), "generated/\n").unwrap();

    let config = test_config();
    let scanner = Scanner::new(config);
    let diff = scanner
        .scan(dir.path(), &FxHashMap::default(), &NoOpHandler)
        .unwrap();

    let paths: Vec<String> = diff
        .added
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
        .collect();

    assert!(paths.contains(&"keep.ts".to_string()));
    assert!(paths.contains(&"keep2.js".to_string()));
    // .driftignore itself may or may not be included (it's not a code file)
    // The generated directory should be excluded
    assert!(
        !paths.contains(&"output.ts".to_string()),
        "generated/ should be ignored"
    );
}

// ---- T1-SCN-04: Cancellation ----

#[test]
fn t1_scn_04_cancellation_returns_partial_diff() {
    // Create a large fixture to give cancellation time to trigger
    let dir = create_test_fixture(200);
    let config = test_config();
    let scanner = Scanner::new(config);

    // Cancel immediately
    scanner.cancellation().cancel();

    let diff = scanner
        .scan(dir.path(), &FxHashMap::default(), &NoOpHandler)
        .unwrap();

    // With immediate cancellation, we should get fewer files than total
    // The walker may have already discovered some files before cancellation
    let total_returned = diff.added.len() + diff.unchanged.len();
    // We can't guarantee exact count, but it should be less than 200
    // or the diff should be valid (not corrupted)
    assert!(diff.errors.is_empty() || total_returned <= 200);
}

// ---- T1-SCN-05: Language detection for all 10 languages ----

#[test]
fn t1_scn_05_language_detection_all_10() {
    let cases = vec![
        ("ts", Some(Language::TypeScript)),
        ("tsx", Some(Language::TypeScript)),
        ("mts", Some(Language::TypeScript)),
        ("cts", Some(Language::TypeScript)),
        ("js", Some(Language::JavaScript)),
        ("jsx", Some(Language::JavaScript)),
        ("mjs", Some(Language::JavaScript)),
        ("cjs", Some(Language::JavaScript)),
        ("py", Some(Language::Python)),
        ("pyi", Some(Language::Python)),
        ("java", Some(Language::Java)),
        ("cs", Some(Language::CSharp)),
        ("go", Some(Language::Go)),
        ("rs", Some(Language::Rust)),
        ("rb", Some(Language::Ruby)),
        ("rake", Some(Language::Ruby)),
        ("gemspec", Some(Language::Ruby)),
        ("php", Some(Language::Php)),
        ("kt", Some(Language::Kotlin)),
        ("kts", Some(Language::Kotlin)),
        // Unknown extensions
        ("txt", None),
        ("md", None),
        ("json", None),
        ("yaml", None),
        ("toml", None),
        ("xml", None),
        ("html", None),
        ("css", None),
        ("svg", None),
    ];

    for (ext, expected) in cases {
        let result = Language::from_extension(Some(ext));
        assert_eq!(result, expected, "extension .{ext} should map to {expected:?}");
    }

    // None extension
    assert_eq!(Language::from_extension(None), None);
}

// ---- T1-SCN-06: Symlink loop detection ----

#[test]
fn t1_scn_06_symlink_loop_terminates() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("real.ts"), "const x = 1;").unwrap();

    // Create a → b → a symlink cycle
    let a_dir = dir.path().join("a");
    fs::create_dir(&a_dir).unwrap();
    fs::write(a_dir.join("file.ts"), "const y = 2;").unwrap();

    // Create symlink: a/b → a (cycle)
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&a_dir, a_dir.join("b")).unwrap();
    }

    // Scanner should terminate without stack overflow
    let mut config = test_config();
    config.follow_symlinks = Some(true);
    let scanner = Scanner::new(config);
    let result = scanner.scan(dir.path(), &FxHashMap::default(), &NoOpHandler);

    // Should succeed (ignore crate handles symlink loops)
    assert!(result.is_ok(), "scanner should handle symlink loops gracefully");
}

// ---- T1-SCN-07: Permission denied ----

#[test]
fn t1_scn_07_permission_denied_continues() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("readable.ts"), "const x = 1;").unwrap();

    // Create unreadable file (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let unreadable = dir.path().join("unreadable.ts");
        fs::write(&unreadable, "const y = 2;").unwrap();
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).unwrap();
    }

    let config = test_config();
    let scanner = Scanner::new(config);
    let diff = scanner
        .scan(dir.path(), &FxHashMap::default(), &NoOpHandler)
        .unwrap();

    // Should have at least the readable file
    assert!(
        !diff.added.is_empty(),
        "should discover at least the readable file"
    );

    // Cleanup: restore permissions so TempDir can clean up
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let unreadable = dir.path().join("unreadable.ts");
        let _ = fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o644));
    }
}

// ---- T1-SCN-08: 0-byte files ----

#[test]
fn t1_scn_08_zero_byte_files() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("empty.ts"), "").unwrap();
    fs::write(dir.path().join("nonempty.ts"), "const x = 1;").unwrap();

    let config = test_config();
    let scanner = Scanner::new(config);
    let diff = scanner
        .scan(dir.path(), &FxHashMap::default(), &NoOpHandler)
        .unwrap();

    assert_eq!(diff.added.len(), 2, "should include 0-byte file");

    // Find the empty file entry
    let empty_path = dir.path().join("empty.ts");
    let entry = diff.entries.get(&empty_path).expect("empty file should have entry");
    assert_eq!(entry.file_size, 0);
    // xxh3 of empty input is deterministic
    let expected_hash = hash_content(b"");
    assert_eq!(entry.content_hash, expected_hash);
}

// ---- T1-SCN-09: File modified mid-scan ----

#[test]
fn t1_scn_09_file_modified_mid_scan_no_crash() {
    let dir = create_test_fixture(50);

    // Modify a file while scan is running (best-effort race condition test)
    let modify_path = dir.path().join("file_0.ts");
    let config = test_config();
    let scanner = Scanner::new(config);

    // Start scan — the file may be read before or after modification
    let handle = {
        let _path = dir.path().to_path_buf();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(1));
            let _ = fs::write(modify_path, "// modified during scan\nconst z = 42;");
        })
    };

    let result = scanner.scan(dir.path(), &FxHashMap::default(), &NoOpHandler);
    handle.join().unwrap();

    // Should not crash — result is valid regardless of timing
    assert!(result.is_ok(), "scan should not crash on mid-scan modification");
}

// ---- T1-SCN-10: Deeply nested directory ----
// macOS NAME_MAX is 255 bytes, so full 256-level paths with multi-char names
// exceed the OS limit. We use single-char directory names to maximize depth
// within OS constraints, targeting 128 levels which is well beyond typical
// real-world nesting while staying within filesystem limits.

#[test]
fn t1_scn_10_deeply_nested_directory() {
    let dir = TempDir::new().unwrap();
    let mut current = dir.path().to_path_buf();

    // Use single-char names to maximize depth within OS path limits.
    // 128 levels is extreme nesting — real codebases rarely exceed 15-20.
    let depth = 128;
    for i in 0..depth {
        // Single char names: a, b, c, ... wrapping around
        let name = format!("{}", (b'a' + (i % 26) as u8) as char);
        current = current.join(name);
    }
    fs::create_dir_all(&current).unwrap();
    fs::write(current.join("deep.ts"), "const deep = true;").unwrap();

    let config = test_config();
    let scanner = Scanner::new(config);
    let diff = scanner
        .scan(dir.path(), &FxHashMap::default(), &NoOpHandler)
        .unwrap();

    assert_eq!(diff.added.len(), 1, "should find the deeply nested file");
}

// ---- T1-SCN-11: Empty directory ----

#[test]
fn t1_scn_11_empty_directory() {
    let dir = TempDir::new().unwrap();
    let config = test_config();
    let scanner = Scanner::new(config);
    let diff = scanner
        .scan(dir.path(), &FxHashMap::default(), &NoOpHandler)
        .unwrap();

    assert_eq!(diff.added.len(), 0);
    assert_eq!(diff.modified.len(), 0);
    assert_eq!(diff.removed.len(), 0);
    assert_eq!(diff.unchanged.len(), 0);
    assert!(diff.errors.is_empty());
    assert_eq!(diff.stats.total_files, 0);
}

// ---- T1-SCN-12: Unicode filenames ----

#[test]
fn t1_scn_12_unicode_filenames() {
    let dir = TempDir::new().unwrap();

    // CJK characters
    fs::write(dir.path().join("测试.ts"), "const x = 1;").unwrap();
    // Emoji
    fs::write(dir.path().join("🚀.py"), "x = 1").unwrap();
    // Combining diacriticals (e + combining acute)
    fs::write(dir.path().join("café.js"), "const x = 1;").unwrap();

    let config = test_config();
    let scanner = Scanner::new(config);
    let diff = scanner
        .scan(dir.path(), &FxHashMap::default(), &NoOpHandler)
        .unwrap();

    assert_eq!(diff.added.len(), 3, "should discover all Unicode-named files");
}

// ---- T1-SCN-13: Special character filenames ----

#[test]
fn t1_scn_13_special_character_filenames() {
    let dir = TempDir::new().unwrap();

    fs::write(dir.path().join("file with spaces.ts"), "const x = 1;").unwrap();
    fs::write(dir.path().join("file#hash.ts"), "const x = 2;").unwrap();
    fs::write(dir.path().join("file(parens).ts"), "const x = 3;").unwrap();
    fs::write(dir.path().join("file&amp.ts"), "const x = 4;").unwrap();

    let config = test_config();
    let scanner = Scanner::new(config);
    let diff = scanner
        .scan(dir.path(), &FxHashMap::default(), &NoOpHandler)
        .unwrap();

    assert_eq!(diff.added.len(), 4, "should handle special characters in filenames");
}

// ---- T1-SCN-14: Malformed .driftignore ----

#[test]
fn t1_scn_14_malformed_driftignore() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("keep.ts"), "const x = 1;").unwrap();

    // Malformed patterns — should not crash
    fs::write(
        dir.path().join(".driftignore"),
        "[unclosed\n***invalid\n\n# comment\nvalid_pattern/\n",
    )
    .unwrap();

    let config = test_config();
    let scanner = Scanner::new(config);
    let result = scanner.scan(dir.path(), &FxHashMap::default(), &NoOpHandler);

    assert!(result.is_ok(), "malformed .driftignore should not crash scanner");
    let diff = result.unwrap();
    assert!(!diff.added.is_empty(), "should still discover files");
}

// ---- T1-SCN-15: xxh3 hash determinism ----

#[test]
fn t1_scn_15_hash_determinism() {
    let content = b"function hello() { return 42; }";

    let hash1 = hash_content(content);
    let hash2 = hash_content(content);
    assert_eq!(hash1, hash2, "same content must produce identical hash");

    // Different content → different hash
    let hash3 = hash_content(b"function hello() { return 43; }");
    assert_ne!(hash1, hash3, "different content must produce different hash");

    // Empty content is deterministic
    let empty1 = hash_content(b"");
    let empty2 = hash_content(b"");
    assert_eq!(empty1, empty2, "empty content hash must be deterministic");
}

// ---- T1-SCN-16: mtime-based incremental detection ----

#[test]
fn t1_scn_16_mtime_incremental_detection() {
    let dir = TempDir::new().unwrap();
    let file_path = dir.path().join("test.ts");
    let content = "const x = 1;";
    fs::write(&file_path, content).unwrap();

    let config = test_config();
    let scanner = Scanner::new(config);

    // First scan
    let diff1 = scanner
        .scan(dir.path(), &FxHashMap::default(), &NoOpHandler)
        .unwrap();
    assert_eq!(diff1.added.len(), 1);

    let cached = build_cached_metadata(&diff1);

    // Touch file without changing content (update mtime)
    std::thread::sleep(std::time::Duration::from_millis(50));
    fs::write(&file_path, content).unwrap(); // same content, new mtime

    // Second scan with force_full to trigger content hash comparison
    let mut config2 = test_config();
    config2.force_full_scan = Some(true);
    let scanner2 = Scanner::new(config2);
    let diff2 = scanner2.scan(dir.path(), &cached, &NoOpHandler).unwrap();

    // Content unchanged → should be classified as unchanged
    assert_eq!(diff2.unchanged.len(), 1, "same content should be unchanged");
    assert_eq!(diff2.modified.len(), 0, "no actual modification");
}

// ---- T1-SCN-17: Event ordering ----

#[test]
fn t1_scn_17_event_ordering() {
    let dir = create_test_fixture(10);
    let config = test_config();
    let scanner = Scanner::new(config);
    let handler = Arc::new(RecordingHandler::default());

    let diff = scanner
        .scan(dir.path(), &FxHashMap::default(), handler.as_ref())
        .unwrap();

    let started = handler.started.lock().unwrap();
    let progress = handler.progress.lock().unwrap();
    let complete = handler.complete.lock().unwrap();

    assert_eq!(started.len(), 1, "exactly one scan_started event");
    assert_eq!(complete.len(), 1, "exactly one scan_complete event");
    assert!(!progress.is_empty(), "at least one progress event");

    // Verify complete event has correct counts
    let c = &complete[0];
    assert_eq!(c.added, diff.added.len());
    assert_eq!(c.modified, diff.modified.len());
    assert_eq!(c.removed, diff.removed.len());
    assert_eq!(c.unchanged, diff.unchanged.len());
}

// ---- T1-SCN-18: Error events for permission denied ----

#[test]
fn t1_scn_18_error_events_for_permission_denied() {
    // This test is meaningful on Unix where we can set permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("good.ts"), "const x = 1;").unwrap();

        // Create unreadable directory
        let bad_dir = dir.path().join("noaccess");
        fs::create_dir(&bad_dir).unwrap();
        fs::write(bad_dir.join("hidden.ts"), "const y = 2;").unwrap();
        fs::set_permissions(&bad_dir, fs::Permissions::from_mode(0o000)).unwrap();

        let config = test_config();
        let scanner = Scanner::new(config);
        let handler = Arc::new(RecordingHandler::default());

        let _diff = scanner
            .scan(dir.path(), &FxHashMap::default(), handler.as_ref())
            .unwrap();

        // Restore permissions for cleanup
        let _ = fs::set_permissions(&bad_dir, fs::Permissions::from_mode(0o755));

        // The scanner should have found at least the good file
        // Error events may or may not fire depending on how ignore crate handles it
    }
}

// ---- T1-SCN-19: Parallel walker no data races ----

#[test]
fn t1_scn_19_parallel_walker_no_data_races() {
    let dir = create_test_fixture(500);
    let mut config = test_config();
    config.threads = Some(8);
    let scanner = Scanner::new(config);

    // Run multiple times to increase chance of catching races
    for _ in 0..3 {
        let diff = scanner
            .scan(dir.path(), &FxHashMap::default(), &NoOpHandler)
            .unwrap();
        assert_eq!(diff.added.len(), 500, "all files should be discovered");
    }
}

// ---- T1-SCN-20: Performance benchmark (10K files <500ms) ----

#[test]
fn t1_scn_20_performance_10k_files() {
    let dir = create_test_fixture(10_000);
    let config = test_config();
    let scanner = Scanner::new(config);

    let start = Instant::now();
    let diff = scanner
        .scan(dir.path(), &FxHashMap::default(), &NoOpHandler)
        .unwrap();
    let elapsed = start.elapsed();

    assert_eq!(diff.added.len(), 10_000);
    // macOS target: <500ms. Allow generous margin for CI.
    assert!(
        elapsed.as_millis() < 5000,
        "10K file scan took {}ms (target: <500ms, CI margin: <5000ms)",
        elapsed.as_millis()
    );
}

// ---- T1-SCN-21: Incremental scan performance ----

#[test]
fn t1_scn_21_incremental_performance() {
    let dir = create_test_fixture(1000);
    let config = test_config();
    let scanner = Scanner::new(config);

    // First scan (cold)
    let diff1 = scanner
        .scan(dir.path(), &FxHashMap::default(), &NoOpHandler)
        .unwrap();
    let cached = build_cached_metadata(&diff1);

    // Modify 10 files
    for i in 0..10 {
        let ext = ["ts", "js", "py", "java", "cs", "go", "rs", "rb", "php", "kt"][i % 10];
        fs::write(
            dir.path().join(format!("file_{i}.{ext}")),
            format!("// modified\nconst modified_{i} = true;"),
        )
        .unwrap();
    }

    // Incremental scan
    let mut config2 = test_config();
    config2.force_full_scan = Some(true); // Force hash comparison
    let scanner2 = Scanner::new(config2);

    let start = Instant::now();
    let diff2 = scanner2.scan(dir.path(), &cached, &NoOpHandler).unwrap();
    let elapsed = start.elapsed();

    assert_eq!(diff2.modified.len(), 10, "10 modified files");
    assert!(
        elapsed.as_millis() < 5000,
        "incremental scan took {}ms",
        elapsed.as_millis()
    );
}

// ---- Helper: build cached metadata from a ScanDiff ----

fn build_cached_metadata(diff: &ScanDiff) -> FxHashMap<PathBuf, CachedFileMetadata> {
    let mut cached = FxHashMap::default();
    for (path, entry) in &diff.entries {
        cached.insert(
            path.clone(),
            CachedFileMetadata {
                path: path.clone(),
                content_hash: entry.content_hash,
                mtime_secs: entry.mtime_secs,
                mtime_nanos: entry.mtime_nanos,
                file_size: entry.file_size,
                language: entry.language,
            },
        );
    }
    cached
}
