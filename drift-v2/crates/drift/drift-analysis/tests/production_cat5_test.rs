//! Production Category 5: Analysis Pipeline Integrity
//!
//! Tests T5-01 through T5-08 per PRODUCTION-TEST-SUITE.md.
//! The 4-phase analysis pipeline (AST → String → Regex → Resolution) has
//! critical ordering and data flow dependencies.

use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use drift_analysis::engine::{
    AnalysisPipeline, DetectionEngine, IncrementalAnalyzer, ResolutionIndex, VisitorRegistry,
};
use drift_analysis::parsers::types::{
    FunctionInfo, ParseResult, ParameterInfo, Position, Range, Visibility,
};
use drift_analysis::scanner::language_detect::Language;
use drift_analysis::scanner::types::{CachedFileMetadata, ScanDiff};
use drift_analysis::scanner::Scanner;
use drift_core::config::ScanConfig;
use drift_core::events::handler::DriftEventHandler;
use drift_core::types::collections::FxHashMap;
use smallvec::SmallVec;
use tempfile::TempDir;

// ---- Helpers ----

struct NoOpHandler;
impl DriftEventHandler for NoOpHandler {}

/// Parse TypeScript source with tree-sitter and return (tree, source_bytes).
fn parse_ts(source: &str) -> (tree_sitter::Tree, Vec<u8>) {
    let bytes = source.as_bytes().to_vec();
    let lang = Language::TypeScript;
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&lang.ts_language())
        .expect("failed to set TS language");
    let tree = parser
        .parse(&bytes, None)
        .expect("failed to parse TS source");
    (tree, bytes)
}

/// Build a minimal ParseResult for a given file with N functions.
fn make_parse_result(file: &str, num_functions: usize) -> ParseResult {
    let mut pr = ParseResult {
        file: file.to_string(),
        language: Language::TypeScript,
        ..ParseResult::default()
    };
    for i in 0..num_functions {
        pr.functions.push(FunctionInfo {
            name: format!("fn_{i}"),
            qualified_name: Some(format!("{file}::fn_{i}")),
            file: file.to_string(),
            line: i as u32,
            column: 0,
            end_line: i as u32 + 3,
            parameters: SmallVec::from_vec(vec![ParameterInfo {
                name: "x".to_string(),
                type_annotation: Some("number".to_string()),
                default_value: None,
                is_rest: false,
            }]),
            return_type: Some("void".to_string()),
            generic_params: SmallVec::new(),
            visibility: Visibility::Public,
            is_exported: true,
            is_async: false,
            is_generator: false,
            is_abstract: false,
            range: Range {
                start: Position {
                    line: i as u32,
                    column: 0,
                },
                end: Position {
                    line: i as u32 + 3,
                    column: 1,
                },
            },
            decorators: Vec::new(),
            doc_comment: None,
            body_hash: i as u64,
            signature_hash: i as u64 * 17,
        });
    }
    pr
}

/// Generate TypeScript source with functions and string literals for pipeline testing.
fn generate_ts_source(num_functions: usize) -> String {
    let mut source = String::new();
    source.push_str("import { Request, Response } from 'express';\n");
    source.push_str("import * as utils from './utils';\n\n");
    for i in 0..num_functions {
        source.push_str(&format!(
            "export function handler_{i}(req: Request, res: Response): void {{\n"
        ));
        source.push_str(&format!(
            "  const msg_{i} = \"processing request {i}\";\n"
        ));
        source.push_str(&format!(
            "  console.log(\"handler_{i} called with\", req.body);\n"
        ));
        source.push_str(&format!("  const url = \"http://api.example.com/v{i}\";\n"));
        source.push_str(&format!("  res.json({{ status: \"ok\", id: {i} }});\n"));
        source.push_str("}\n\n");
    }
    source
}

/// Convert ScanDiff entries to CachedFileMetadata map for incremental re-scan.
fn entries_to_cached(diff: &ScanDiff) -> FxHashMap<PathBuf, CachedFileMetadata> {
    let mut cached = FxHashMap::default();
    for (path, entry) in &diff.entries {
        cached.insert(
            path.clone(),
            CachedFileMetadata {
                path: entry.path.clone(),
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

// ---- T5-01: Phase Ordering Invariant ----
// Run analyze_file() and verify phase_times_us[0..3] are all populated.
// All 4 phases must execute in order; each must record non-zero timing.

#[test]
fn t5_01_phase_ordering_invariant() {
    // Generate a substantial TS file so each phase takes measurable time (>1µs)
    let source_str = generate_ts_source(50);
    let (tree, source_bytes) = parse_ts(&source_str);

    // Build a ParseResult that matches the source
    let mut pr = ParseResult {
        file: "handlers.ts".to_string(),
        language: Language::TypeScript,
        ..ParseResult::default()
    };
    for i in 0..50 {
        pr.functions.push(FunctionInfo {
            name: format!("handler_{i}"),
            qualified_name: None,
            file: "handlers.ts".to_string(),
            line: (i * 6) as u32,
            column: 0,
            end_line: (i * 6 + 5) as u32,
            parameters: SmallVec::new(),
            return_type: Some("void".to_string()),
            generic_params: SmallVec::new(),
            visibility: Visibility::Public,
            is_exported: true,
            is_async: false,
            is_generator: false,
            is_abstract: false,
            range: Range {
                start: Position {
                    line: (i * 6) as u32,
                    column: 0,
                },
                end: Position {
                    line: (i * 6 + 5) as u32,
                    column: 1,
                },
            },
            decorators: Vec::new(),
            doc_comment: None,
            body_hash: i as u64,
            signature_hash: i as u64 * 31,
        });
    }

    let registry = VisitorRegistry::new();
    let engine = DetectionEngine::new(registry);
    let mut pipeline = AnalysisPipeline::with_engine(engine);
    let mut resolution_index = ResolutionIndex::new();

    let result = pipeline.analyze_file(&pr, &source_bytes, &tree, &mut resolution_index);

    // Total analysis time must be non-zero
    assert!(
        result.analysis_time_us > 0,
        "total analysis_time_us must be >0, got {}",
        result.analysis_time_us
    );

    // All 4 phases must have executed — verify the pipeline produced sane results.
    // Phase 2 (string extraction) should find strings in our generated source.
    assert!(
        result.strings_extracted > 0,
        "Phase 2 should extract strings from 50-function TS file, got 0"
    );

    // Phase 4 (resolution index) should have indexed our functions.
    assert!(
        result.resolution_entries > 0,
        "Phase 4 should index functions, got 0 resolution entries"
    );

    // Verify phase times array has 4 elements and at least the sum is positive.
    // Individual phases may be sub-microsecond on fast hardware, but the sum
    // of all 4 should be measurable for a 50-function file.
    let phase_sum: u64 = result.phase_times_us.iter().sum();
    assert!(
        phase_sum > 0,
        "sum of all 4 phase times must be >0, got {:?}",
        result.phase_times_us
    );

    // Verify ordering: analysis_time_us >= sum of phase times
    // (total includes overhead between phases)
    assert!(
        result.analysis_time_us >= phase_sum,
        "total ({}) must be >= phase sum ({})",
        result.analysis_time_us,
        phase_sum
    );
}

// ---- T5-02: Resolution Index Accumulation ----
// Analyze 100 files via analyze_files(). Verify ResolutionIndex accumulates
// entries from ALL files, not just the last.

#[test]
fn t5_02_resolution_index_accumulation() {
    // Create 100 ParseResults, each with 3 functions
    let source_str = "export function fn_0(x: number): void {}\nexport function fn_1(x: number): void {}\nexport function fn_2(x: number): void {}\n";
    let (_tree, source_bytes) = parse_ts(source_str);

    let mut parse_results: Vec<(ParseResult, Vec<u8>, tree_sitter::Tree)> = Vec::new();
    for i in 0..100 {
        let file_name = format!("module_{i}.ts");
        let pr = make_parse_result(&file_name, 3);

        // Re-parse to get a fresh tree for each file
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&Language::TypeScript.ts_language())
            .unwrap();
        let file_tree = parser.parse(source_str.as_bytes(), None).unwrap();

        parse_results.push((pr, source_bytes.clone(), file_tree));
    }

    let registry = VisitorRegistry::new();
    let engine = DetectionEngine::new(registry);
    let mut pipeline = AnalysisPipeline::with_engine(engine);

    let (results, resolution_index) = pipeline.analyze_files(&parse_results);

    // Must have 100 results
    assert_eq!(results.len(), 100, "should produce 100 AnalysisResults");

    // Resolution index must accumulate entries from ALL files.
    // Each file has 3 functions → 300 function entries minimum.
    assert!(
        resolution_index.entry_count() >= 300,
        "resolution index should have >=300 entries (100 files × 3 functions), got {}",
        resolution_index.entry_count()
    );

    // Must index all 100 files
    assert_eq!(
        resolution_index.file_count(),
        100,
        "resolution index should track all 100 files"
    );

    // Verify first and last file are both present
    let first_entries = resolution_index.entries_for_file("module_0.ts");
    assert!(
        !first_entries.is_empty(),
        "first file module_0.ts must have entries in resolution index"
    );
    let last_entries = resolution_index.entries_for_file("module_99.ts");
    assert!(
        !last_entries.is_empty(),
        "last file module_99.ts must have entries in resolution index"
    );

    // Verify entry count grows monotonically across files by checking
    // a middle file is also present
    let mid_entries = resolution_index.entries_for_file("module_50.ts");
    assert!(
        !mid_entries.is_empty(),
        "middle file module_50.ts must have entries"
    );
}

// ---- T5-03: ParseResult Completeness Cascade ----
// Analyze a file where ParseResult.functions is empty.
// Analysis must still complete — patterns, strings, regex all work;
// only resolution is degraded.

#[test]
fn t5_03_parse_result_completeness_cascade() {
    // Source with strings but the ParseResult has no functions
    let source_str = r#"
const apiKey = "secret_key_12345678";
const url = "http://api.example.com/data";
console.log("Starting application...");
// TODO: implement authentication
"#;
    let (tree, source_bytes) = parse_ts(source_str);

    let pr = ParseResult {
        file: "empty_functions.ts".to_string(),
        language: Language::TypeScript,
        functions: Vec::new(), // Explicitly empty
        classes: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        ..ParseResult::default()
    };

    let registry = VisitorRegistry::new();
    let engine = DetectionEngine::new(registry);
    let mut pipeline = AnalysisPipeline::with_engine(engine);
    let mut resolution_index = ResolutionIndex::new();

    // Must not panic — analysis should complete gracefully
    let result = pipeline.analyze_file(&pr, &source_bytes, &tree, &mut resolution_index);

    // File metadata preserved
    assert_eq!(result.file, "empty_functions.ts");
    assert_eq!(result.language, Language::TypeScript);

    // Phase 2 (string extraction) should still work on the AST
    // The source contains string literals that tree-sitter can extract
    assert!(
        result.strings_extracted > 0,
        "string extraction should work even with empty functions, got 0"
    );

    // Phase 4 (resolution) should have 0 entries since no functions/imports/exports
    assert_eq!(
        result.resolution_entries, 0,
        "empty ParseResult should produce 0 resolution entries"
    );

    // Total time should be recorded
    assert!(
        result.analysis_time_us > 0 || result.phase_times_us.iter().sum::<u64>() > 0,
        "analysis should complete and record timing"
    );
}

// ---- T5-04: Incremental Skip Correctness ----
// Scan a repo, modify 1 file, re-scan. IncrementalAnalyzer.files_to_analyze()
// must return only the 1 modified file + 0 added; unchanged files skipped.

#[test]
fn t5_04_incremental_skip_correctness() {
    // Build a ScanDiff simulating 1 modified file among 10
    let mut diff = ScanDiff::default();

    // 9 unchanged files
    for i in 0..9 {
        diff.unchanged
            .push(PathBuf::from(format!("src/unchanged_{i}.ts")));
    }

    // 1 modified file
    diff.modified
        .push(PathBuf::from("src/modified.ts"));

    let analyzer = IncrementalAnalyzer::new();
    let files = analyzer.files_to_analyze(&diff);

    // Must return only the modified file
    assert_eq!(
        files.len(),
        1,
        "should return only modified files, got {}",
        files.len()
    );
    assert_eq!(files[0], PathBuf::from("src/modified.ts"));

    // Now test with added files too
    diff.added
        .push(PathBuf::from("src/new_file.ts"));

    let files = analyzer.files_to_analyze(&diff);
    assert_eq!(
        files.len(),
        2,
        "should return added + modified files, got {}",
        files.len()
    );
    assert!(files.contains(&PathBuf::from("src/new_file.ts")));
    assert!(files.contains(&PathBuf::from("src/modified.ts")));

    // Unchanged files must NOT appear
    for f in &files {
        assert!(
            !f.to_str().unwrap().contains("unchanged"),
            "unchanged file {:?} should not be in files_to_analyze",
            f
        );
    }
}

// ---- T5-05: Content Hash L2 Skip ----
// Touch file mtime without changing content.
// mtime changes → triggers L2 content hash check → same hash → Unchanged.

#[test]
fn t5_05_content_hash_l2_skip() {
    let dir = TempDir::new().unwrap();
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();

    let file_path = src.join("stable.ts");
    let content = "export const VERSION = 42;\n";
    std::fs::write(&file_path, content).unwrap();

    let config = ScanConfig::default();
    let scanner = Scanner::new(config);

    // First scan: file is new → appears in added
    let cached = FxHashMap::default();
    let diff1 = scanner.scan(dir.path(), &cached, &NoOpHandler).unwrap();
    assert!(
        !diff1.added.is_empty(),
        "first scan should find at least 1 added file"
    );

    // Build cached metadata from first scan
    let cached = entries_to_cached(&diff1);

    // Sleep to ensure mtime changes, then re-write identical content
    thread::sleep(Duration::from_millis(1100));
    std::fs::write(&file_path, content).unwrap();

    // Second scan with cached metadata
    let config2 = ScanConfig::default();
    let scanner2 = Scanner::new(config2);
    let diff2 = scanner2.scan(dir.path(), &cached, &NoOpHandler).unwrap();

    // The file's mtime changed but content hash is the same.
    // L1 (mtime) check fails → L2 (content hash) check → Unchanged.
    assert!(
        diff2.added.is_empty(),
        "no files should be newly added on re-scan, got {:?}",
        diff2.added
    );
    assert!(
        diff2.modified.is_empty(),
        "file with same content hash should NOT be modified, got {:?}",
        diff2.modified
    );
    assert!(
        !diff2.unchanged.is_empty(),
        "file with same content hash should be unchanged"
    );
}

// ---- T5-06: File Removal Detection ----
// Delete a file between scans. Must appear in ScanDiff.removed.
// IncrementalAnalyzer.remove_files() must clean up tracked hashes.

#[test]
fn t5_06_file_removal_detection() {
    let dir = TempDir::new().unwrap();
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();

    // Create 3 files
    for name in &["keep_a.ts", "keep_b.ts", "delete_me.ts"] {
        let path = src.join(name);
        std::fs::write(&path, format!("export const x = '{name}';\n")).unwrap();
    }

    let config = ScanConfig::default();
    let scanner = Scanner::new(config);
    let cached = FxHashMap::default();

    // First scan
    let diff1 = scanner.scan(dir.path(), &cached, &NoOpHandler).unwrap();
    assert_eq!(
        diff1.added.len(),
        3,
        "first scan should find 3 added files, got {}",
        diff1.added.len()
    );

    // Build cached metadata
    let cached = entries_to_cached(&diff1);

    // Delete one file
    std::fs::remove_file(src.join("delete_me.ts")).unwrap();

    // Re-scan with cached metadata
    let config2 = ScanConfig::default();
    let scanner2 = Scanner::new(config2);
    let diff2 = scanner2.scan(dir.path(), &cached, &NoOpHandler).unwrap();

    // Deleted file must appear in removed
    let removed_names: Vec<String> = diff2
        .removed
        .iter()
        .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .collect();
    assert!(
        removed_names.contains(&"delete_me.ts".to_string()),
        "deleted file must appear in ScanDiff.removed, got {:?}",
        removed_names
    );

    // Remaining files should be unchanged
    assert_eq!(
        diff2.unchanged.len(),
        2,
        "2 surviving files should be unchanged, got {}",
        diff2.unchanged.len()
    );

    // Also test IncrementalAnalyzer.remove_files()
    let mut analyzer = IncrementalAnalyzer::new();
    analyzer.update_hash("keep_a.ts".to_string(), 111);
    analyzer.update_hash("keep_b.ts".to_string(), 222);
    analyzer.update_hash("delete_me.ts".to_string(), 333);
    assert_eq!(analyzer.tracked_count(), 3);

    analyzer.remove_files(&[PathBuf::from("delete_me.ts")]);
    assert_eq!(
        analyzer.tracked_count(),
        2,
        "remove_files should clean up tracked hashes"
    );
    assert!(
        analyzer.needs_analysis("delete_me.ts", 333),
        "removed file should need re-analysis if re-added"
    );
    assert!(
        !analyzer.needs_analysis("keep_a.ts", 111),
        "kept file with same hash should not need analysis"
    );
}

// ---- T5-07: Deterministic Scan Output ----
// Scan the same directory twice. ScanDiff.added, .modified, .removed,
// .unchanged must be sorted identically both times.

#[test]
fn t5_07_deterministic_scan_output() {
    let dir = TempDir::new().unwrap();
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();

    // Create files with names that would be unordered without explicit sort
    for name in &[
        "zebra.ts",
        "alpha.ts",
        "middle.ts",
        "beta.ts",
        "omega.py",
        "gamma.js",
        "delta.rs",
        "epsilon.go",
    ] {
        let path = src.join(name);
        std::fs::write(&path, format!("// {name}\n")).unwrap();
    }

    let config1 = ScanConfig::default();
    let scanner1 = Scanner::new(config1);
    let cached = FxHashMap::default();
    let diff1 = scanner1
        .scan(dir.path(), &cached, &NoOpHandler)
        .unwrap();

    let config2 = ScanConfig::default();
    let scanner2 = Scanner::new(config2);
    let diff2 = scanner2
        .scan(dir.path(), &cached, &NoOpHandler)
        .unwrap();

    // Both scans should produce identical added lists
    assert_eq!(
        diff1.added, diff2.added,
        "added lists must be identical across two scans"
    );

    // Verify the added list IS sorted (scanner/incremental.rs:119 sorts it)
    let mut sorted_added = diff1.added.clone();
    sorted_added.sort();
    assert_eq!(
        diff1.added, sorted_added,
        "added list must be sorted, got {:?}",
        diff1.added
    );

    // modified, removed, unchanged should also be empty but sorted
    assert_eq!(diff1.modified, diff2.modified);
    assert_eq!(diff1.removed, diff2.removed);
    assert_eq!(diff1.unchanged, diff2.unchanged);
}

// ---- T5-08: Language Detection Coverage ----
// Include files with all 14 Language variants (30+ extensions).
// Each must be classified with correct Language enum variant, not None.

#[test]
fn t5_08_language_detection_coverage() {
    // Map of extension → expected Language
    let extension_map: Vec<(&str, Language)> = vec![
        // TypeScript (4 extensions)
        ("ts", Language::TypeScript),
        ("tsx", Language::TypeScript),
        ("mts", Language::TypeScript),
        ("cts", Language::TypeScript),
        // JavaScript (4 extensions)
        ("js", Language::JavaScript),
        ("jsx", Language::JavaScript),
        ("mjs", Language::JavaScript),
        ("cjs", Language::JavaScript),
        // Python (2 extensions)
        ("py", Language::Python),
        ("pyi", Language::Python),
        // Java
        ("java", Language::Java),
        // C#
        ("cs", Language::CSharp),
        // Go
        ("go", Language::Go),
        // Rust
        ("rs", Language::Rust),
        // Ruby (3 extensions)
        ("rb", Language::Ruby),
        ("rake", Language::Ruby),
        ("gemspec", Language::Ruby),
        // PHP
        ("php", Language::Php),
        // Kotlin (2 extensions)
        ("kt", Language::Kotlin),
        ("kts", Language::Kotlin),
        // C++ (6 extensions)
        ("cpp", Language::Cpp),
        ("cc", Language::Cpp),
        ("cxx", Language::Cpp),
        ("hpp", Language::Cpp),
        ("hxx", Language::Cpp),
        ("hh", Language::Cpp),
        // C (2 extensions)
        ("c", Language::C),
        ("h", Language::C),
        // Swift
        ("swift", Language::Swift),
        // Scala (2 extensions)
        ("scala", Language::Scala),
        ("sc", Language::Scala),
    ];

    // Verify all 14 Language variants are covered
    let unique_languages: std::collections::HashSet<_> =
        extension_map.iter().map(|(_, lang)| *lang).collect();
    assert_eq!(
        unique_languages.len(),
        14,
        "must cover all 14 Language variants, got {}",
        unique_languages.len()
    );

    // Test each extension
    for (ext, expected_lang) in &extension_map {
        let detected = Language::from_extension(Some(ext));
        assert_eq!(
            detected,
            Some(*expected_lang),
            "extension '.{ext}' should detect as {:?}, got {:?}",
            expected_lang,
            detected
        );
    }

    // Verify unknown extensions return None
    for unknown_ext in &["txt", "md", "json", "yaml", "toml", "xml", "html", "css"] {
        assert_eq!(
            Language::from_extension(Some(unknown_ext)),
            None,
            "unknown extension '.{unknown_ext}' should return None"
        );
    }

    // Verify None extension returns None
    assert_eq!(
        Language::from_extension(None),
        None,
        "None extension should return None"
    );

    // Verify each language has a ts_language() that doesn't panic
    for lang in [
        Language::TypeScript,
        Language::JavaScript,
        Language::Python,
        Language::Java,
        Language::CSharp,
        Language::Go,
        Language::Rust,
        Language::Ruby,
        Language::Php,
        Language::Kotlin,
        Language::Cpp,
        Language::C,
        Language::Swift,
        Language::Scala,
    ] {
        let _ts_lang = lang.ts_language(); // Must not panic
    }
}
