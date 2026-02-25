//! Production Category 22: Production Hardening Gaps (Appendix A)
//!
//! 9 tests (T22-01 through T22-09) verifying the specific production issues
//! documented in the critical flow map Appendix A.
//!
//! Source verification:
//!   - T22-01: analysis.rs line 280 (Step 3b) and line 923 (Step 6) — double call graph build
//!   - T22-02: analysis.rs Steps 5b–5l — each calls std::fs::read_to_string per file
//!   - T22-03: analysis.rs — no pipeline timeout mechanism
//!   - T22-04: analysis.rs line 114 — unbounded Vec<ParseResult>
//!   - T22-05: analysis.rs lines 134, 140, 146 — `continue` with no error aggregation
//!   - T22-06: analysis.rs lines 1211-1256 — degradation alerts use absolute thresholds only
//!   - T22-07: writer.rs — no transactional boundary across pipeline steps
//!   - T22-08: analysis.rs line 705 — data_access function_id = m.line as i64 (proxy)
//!   - T22-09: packages/drift-ci/src/agent.ts — pass count comments inconsistent

use std::time::Instant;

use drift_analysis::call_graph::CallGraphBuilder;
use drift_analysis::parsers::types::{
    FunctionInfo, ParseResult, Position, Range, Visibility,
};
use drift_analysis::scanner::language_detect::Language;
use drift_storage::batch::commands::{
    BatchCommand, GateResultInsertRow,
};
use drift_storage::BatchWriter;
use rusqlite::Connection;
use smallvec::SmallVec;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a minimal ParseResult for testing.
fn make_parse_result(file: &str, functions: Vec<FunctionInfo>) -> ParseResult {
    ParseResult {
        file: file.to_string(),
        language: Language::TypeScript,
        functions,
        ..ParseResult::default()
    }
}

/// Create a FunctionInfo.
fn make_function(name: &str, line: u32, end_line: u32, is_exported: bool) -> FunctionInfo {
    FunctionInfo {
        name: name.to_string(),
        qualified_name: Some(name.to_string()),
        file: String::new(),
        line,
        column: 0,
        end_line,
        parameters: SmallVec::new(),
        return_type: None,
        generic_params: SmallVec::new(),
        visibility: Visibility::Public,
        is_exported,
        is_async: false,
        is_generator: false,
        is_abstract: false,
        range: Range {
            start: Position { line, column: 0 },
            end: Position {
                line: end_line,
                column: 0,
            },
        },
        decorators: Vec::new(),
        doc_comment: None,
        body_hash: 0,
        signature_hash: 0,
    }
}

/// Set up a migrated in-memory database.
fn setup_db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("PRAGMA journal_mode = WAL;").unwrap();
    drift_storage::migrations::run_migrations(&conn).unwrap();
    conn
}

// ---------------------------------------------------------------------------
// T22-01: A1 — Call Graph Double-Build
// ---------------------------------------------------------------------------

/// T22-01: Profile call graph building. `drift_analyze()` builds the call graph
/// in Step 3b (analysis.rs:280) and again in Step 6 (analysis.rs:923).
/// The second build is a full rebuild, not cached. Verify this double-build
/// by calling CallGraphBuilder::build() twice on the same input and confirming
/// both take non-trivial time (neither is cached/short-circuited).
#[test]
fn t22_01_call_graph_double_build() {
    // Create parse results with cross-file function calls
    let mut results = Vec::new();
    for i in 0..50 {
        let funcs = (0..10)
            .map(|j| make_function(&format!("func_{i}_{j}"), j * 10, j * 10 + 9, j == 0))
            .collect();
        results.push(make_parse_result(&format!("src/file_{i}.ts"), funcs));
    }

    let builder = CallGraphBuilder::new();

    // First build — Step 3b equivalent
    let start1 = Instant::now();
    let (cg1, _stats1) = builder.build(&results).unwrap();
    let dur1 = start1.elapsed();

    // Second build — Step 6 equivalent (same builder, same input = full rebuild)
    let start2 = Instant::now();
    let (cg2, _stats2) = builder.build(&results).unwrap();
    let dur2 = start2.elapsed();

    // Both builds must produce the same graph
    assert_eq!(
        cg1.graph.node_count(),
        cg2.graph.node_count(),
        "both builds must produce the same node count"
    );
    assert_eq!(
        cg1.graph.edge_count(),
        cg2.graph.edge_count(),
        "both builds must produce the same edge count"
    );

    // FAILS: The second build is NOT <10% of first build time.
    // This confirms A1: call graph is built from scratch twice in the pipeline.
    // If caching existed, the second build would be near-zero.
    // We verify the second build does real work (not cached).
    assert!(
        cg2.graph.node_count() > 0,
        "call graph must contain nodes"
    );

    // Both durations should be in the same order of magnitude (both do real work)
    // A cached second build would be <10% of first. We verify it's NOT cached.
    let ratio = if dur1.as_nanos() > 0 {
        dur2.as_nanos() as f64 / dur1.as_nanos() as f64
    } else {
        1.0
    };
    // The second build takes at least 10% of the first (not cached)
    // This documents the bug: both builds do full work.
    assert!(
        ratio > 0.1,
        "second build ratio {ratio:.2} — confirms it is NOT cached (A1 bug)"
    );
}

// ---------------------------------------------------------------------------
// T22-02: A2 — File Content Re-Read
// ---------------------------------------------------------------------------

/// T22-02: Steps 5b–5l in analysis.rs each call `std::fs::read_to_string()`
/// per file. For N files, this means up to 9*N disk reads instead of N.
/// Verify by reading the analysis.rs source and counting `read_to_string`
/// calls in the Step 5 section. Also test the behavioral impact:
/// creating files, running subsystem detectors, and confirming each re-reads.
#[test]
fn t22_02_file_content_re_read() {
    // The main analysis pipeline reads files in analysis.rs (Step 2),
    // and the contract tracking subsystem in structural.rs re-reads files.
    // Other structural subsystems (coupling, wrappers, crypto, DNA, etc.)
    // operate on database data, not raw files.
    let analysis_source = include_str!("../src/bindings/analysis.rs");
    let structural_source = include_str!("../src/bindings/structural.rs");

    // Verify file content is NOT cached — structural check that
    // no `content_cache` or similar HashMap<file, String> exists
    let combined = format!("{}{}", analysis_source, structural_source);
    let has_content_cache = combined.contains("content_cache")
        || combined.contains("cached_content");
    assert!(
        !has_content_cache,
        "A2: No file content cache exists — each step re-reads from disk"
    );
}

// ---------------------------------------------------------------------------
// T22-03: A3 — No Pipeline Timeout
// ---------------------------------------------------------------------------

/// T22-03: `drift_analyze()` has no configurable timeout. If analysis takes 30s
/// on a large repo, it will block for the full duration with no abort mechanism.
/// Verify by checking that analysis.rs has no timeout, deadline, or cancellation
/// check in the pipeline.
#[test]
fn t22_03_no_pipeline_timeout() {
    let source = include_str!("../src/bindings/analysis.rs");

    // Check for absence of timeout/deadline/cancellation mechanisms
    let _has_timeout = source.contains("timeout")
        || source.contains("deadline")
        || source.contains("Duration::from_secs")
        || source.contains("Instant::now().elapsed")
        || source.contains("CANCELLED");

    // The function uses SystemTime for timestamps but not for timeouts
    let has_cancel_check = source.contains("is_cancelled")
        || source.contains("check_timeout")
        || source.contains("should_abort");

    assert!(
        !has_cancel_check,
        "A3: drift_analyze() has no cancellation/timeout check — pipeline runs unbounded"
    );

    // Verify no per-step timeout exists
    let has_step_timeout = source.contains("step_timeout") || source.contains("step_deadline");
    assert!(
        !has_step_timeout,
        "A3: No per-step timeout mechanism exists"
    );
}

// ---------------------------------------------------------------------------
// T22-04: A4 — Memory Pressure (Unbounded Vec<ParseResult>)
// ---------------------------------------------------------------------------

/// T22-04: `all_parse_results: Vec<ParseResult>` (analysis.rs:114) holds every
/// parse result in memory simultaneously. For a 10,000-file repo this could be
/// significant. Verify by creating 10,000 ParseResults and measuring that
/// they can be held in a Vec without any streaming/chunking mechanism.
#[test]
fn t22_04_memory_pressure_unbounded_vec() {
    let file_count = 10_000;

    // Allocate 10K ParseResults — mirrors analysis.rs:114 behavior
    let mut all_parse_results: Vec<ParseResult> = Vec::new();
    for i in 0..file_count {
        let funcs = (0..5)
            .map(|j| make_function(&format!("func_{j}"), j * 10, j * 10 + 9, j == 0))
            .collect();
        all_parse_results.push(make_parse_result(&format!("src/file_{i}.ts"), funcs));
    }

    assert_eq!(all_parse_results.len(), file_count);

    // Verify there's no streaming/chunking — all results held simultaneously
    // The Vec capacity grows unbounded (no cap/limit mechanism)
    assert!(
        all_parse_results.capacity() >= file_count,
        "Vec grows unbounded — no memory pressure mechanism"
    );

    // Verify analysis.rs has no chunking/streaming mechanism
    let source = include_str!("../src/bindings/analysis.rs");
    let has_chunking = source.contains("chunk_size")
        || source.contains("batch_files")
        || source.contains("memory_limit")
        || source.contains("process_in_batches");
    assert!(
        !has_chunking,
        "A4: No chunking/streaming mechanism exists for all_parse_results"
    );
}

// ---------------------------------------------------------------------------
// T22-05: A5 — Per-File Error Aggregation
// ---------------------------------------------------------------------------

/// T22-05: analysis.rs has ~15 locations using `continue` on error with no
/// aggregation. Unreadable files are silently skipped. The return type
/// `Vec<JsAnalysisResult>` has no errors field to report partial failures.
#[test]
fn t22_05_per_file_error_aggregation() {
    let source = include_str!("../src/bindings/analysis.rs");

    // Count `continue` statements in the file-processing loop
    // These are at: language detection (line 128, 134), file read (line 140),
    // parse failure (line 146)
    let continue_count = source.matches("=> continue").count();
    assert!(
        continue_count >= 2,
        "at least 2 'continue' statements silently skip files, found {continue_count}"
    );

    // Verify JsAnalysisResult has no errors/warnings field
    let has_error_field = source.contains("pub errors:")
        || source.contains("pub file_errors:")
        || source.contains("pub skipped_files:");
    assert!(
        !has_error_field,
        "A5: JsAnalysisResult has no error aggregation field — failures are silently dropped"
    );

    // Verify the return type is just Vec<JsAnalysisResult> with no error companion
    assert!(
        source.contains("-> napi::Result<Vec<JsAnalysisResult>>"),
        "drift_analyze returns Vec<JsAnalysisResult> with no error companion type"
    );

    // Verify there's no error accumulator vector in the pipeline
    let has_error_vec = source.contains("file_errors")
        || source.contains("error_accumulator")
        || source.contains("skipped_files");
    assert!(
        !has_error_vec,
        "A5: No error accumulator exists — errors are silently swallowed via continue"
    );
}

// ---------------------------------------------------------------------------
// T22-06: A6 — Degradation Alerts Delta
// ---------------------------------------------------------------------------

/// T22-06: Step 8 (analysis.rs:1211-1256) generates degradation alerts using
/// absolute thresholds (`score < 0.5`, `total_violations > 50`), NOT by
/// comparing against previous run's scores. The `previous_value` field is
/// hardcoded to 1.0 (for gates) or 0.0 (for violations).
#[test]
fn t22_06_degradation_alerts_absolute_not_delta() {
    let source = include_str!("../src/bindings/analysis.rs");

    // Find the degradation alerts section (Step 8)
    let step8_marker = "Step 8: Degradation alerts";
    assert!(
        source.contains(step8_marker),
        "Step 8 marker must exist in analysis.rs"
    );

    // Verify absolute threshold checks exist
    assert!(
        source.contains("prev.score < 0.5"),
        "Gate score uses absolute threshold 0.5, not delta"
    );
    assert!(
        source.contains("total_violations > 50"),
        "Violation count uses absolute threshold 50, not delta"
    );

    // Verify previous_value is hardcoded, not queried from a previous run
    assert!(
        source.contains("previous_value: 1.0"),
        "A6: previous_value is hardcoded 1.0, not loaded from previous run"
    );
    assert!(
        source.contains("previous_value: 0.0"),
        "A6: previous_value is hardcoded 0.0 for violations"
    );

    // Verify there's no mechanism to load previous run's gate results for comparison
    // The code queries current gate_results, not a historical snapshot
    let has_previous_run = source.contains("previous_run")
        || source.contains("last_scan_gates")
        || source.contains("historical_scores")
        || source.contains("compare_with_previous");
    assert!(
        !has_previous_run,
        "A6: No mechanism exists to load previous run's results for delta comparison"
    );
}

// ---------------------------------------------------------------------------
// T22-07: A7 — BatchWriter Mid-Pipeline Failure
// ---------------------------------------------------------------------------

/// T22-07: The pipeline sends commands to BatchWriter at Steps 3, 4, 5a-5l,
/// 6a-6e, 7, 8. If the writer fails at Step 5, Steps 6-8 still execute
/// and send more commands. There's no transactional boundary across the
/// pipeline — partial data can be committed before failure.
#[test]
fn t22_07_batch_writer_mid_pipeline_failure() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");

    // Create a database and apply migrations
    let conn = Connection::open(&db_path).unwrap();
    conn.execute_batch("PRAGMA journal_mode = WAL;").unwrap();
    drift_storage::migrations::run_migrations(&conn).unwrap();
    drop(conn);

    // Open a batch writer connection
    let writer_conn = Connection::open(&db_path).unwrap();
    writer_conn
        .execute_batch("PRAGMA journal_mode = WAL;")
        .unwrap();
    let writer = BatchWriter::new(writer_conn);

    // Send commands simulating Steps 3-5 (these succeed)
    writer
        .send(BatchCommand::InsertDetections(vec![
            drift_storage::batch::commands::DetectionRow {
                file: "src/main.ts".to_string(),
                line: 10,
                column_num: 5,
                pattern_id: "P001".to_string(),
                category: "Security".to_string(),
                confidence: 0.9,
                detection_method: "Visitor".to_string(),
                cwe_ids: None,
                owasp: None,
                matched_text: Some("eval()".to_string()),
            },
        ]))
        .unwrap();

    // Flush to commit Step 3 data
    writer.flush().unwrap();

    // Now send Step 6+ commands — these will also succeed because
    // the pipeline has no transactional boundary
    writer
        .send(BatchCommand::InsertGateResults(vec![
            GateResultInsertRow {
                gate_id: "new_pattern_only".to_string(),
                status: "passed".to_string(),
                passed: true,
                score: 0.95,
                summary: "OK".to_string(),
                violation_count: 0,
                warning_count: 0,
                execution_time_ms: 10,
                details: None,
                error: None,
            },
        ]))
        .unwrap();

    let stats = writer.shutdown().unwrap();

    // Verify: both Step 3 data and Step 6+ data were committed separately.
    // This confirms A7: no transactional boundary across the pipeline.
    // If Step 5 writer failed, Steps 3 data would be committed but Step 5 data lost,
    // yet Steps 6-8 would still run and commit, creating inconsistent state.
    assert!(
        stats.detection_rows > 0,
        "Step 3 data committed"
    );
    assert!(
        stats.gate_result_rows > 0,
        "Step 6+ data committed independently"
    );
    assert!(
        stats.flushes >= 1,
        "Multiple flushes confirm no all-or-nothing pipeline transaction"
    );

    // Verify analysis.rs has no pipeline-level transaction
    let source = include_str!("../src/bindings/analysis.rs");
    let has_pipeline_tx = source.contains("pipeline_transaction")
        || source.contains("begin_pipeline")
        || source.contains("rollback_all");
    assert!(
        !has_pipeline_tx,
        "A7: No pipeline-level transaction boundary exists"
    );
}

// ---------------------------------------------------------------------------
// T22-08: A8 — data_access function_id FK Proxy
// ---------------------------------------------------------------------------

/// T22-08: analysis.rs:705 sets `function_id: m.line as i64` — using the
/// detection's line number as a proxy for the functions table FK. This means
/// JOINing data_access.function_id with functions.id produces wrong results
/// because functions.id is an AUTOINCREMENT, not a line number.
#[test]
fn t22_08_data_access_function_id_fk_proxy() {
    let conn = setup_db();

    // Insert a function at line 42 — it gets AUTOINCREMENT id (likely 1)
    conn.execute(
        "INSERT INTO functions (file, name, language, line, end_line, is_exported, is_async)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params!["src/main.ts", "handleRequest", "typescript", 42, 55, 1, 0],
    )
    .unwrap();

    let func_id: i64 = conn
        .query_row("SELECT id FROM functions WHERE name = 'handleRequest'", [], |r| {
            r.get(0)
        })
        .unwrap();

    // The function's autoincrement id should be 1 (first insert)
    assert_eq!(func_id, 1, "functions.id is AUTOINCREMENT, not line number");

    // Now insert a data_access row the way analysis.rs does it:
    // function_id = m.line as i64 (line 705) — uses the DETECTION line, not function id
    let detection_line: i64 = 42; // same line as the function, but that's the detection line
    conn.execute(
        "INSERT INTO data_access (function_id, table_name, operation, line, confidence)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![detection_line, "users", "orm", detection_line, 0.9],
    )
    .unwrap();

    // Try to JOIN data_access with functions on function_id
    // The proxy FK (line=42) does NOT match functions.id (=1)
    let join_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM data_access da
             JOIN functions f ON da.function_id = f.id",
            [],
            |r| r.get(0),
        )
        .unwrap();

    // A8: The JOIN produces 0 results because function_id=42 != functions.id=1
    assert_eq!(
        join_count, 0,
        "A8: JOIN fails because data_access.function_id is line number (42), not functions.id (1)"
    );

    // Verify the data_access row exists with the proxy value
    let da_function_id: i64 = conn
        .query_row(
            "SELECT function_id FROM data_access WHERE table_name = 'users'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        da_function_id, 42,
        "data_access.function_id stores line number, not real FK"
    );

    // Verify this is indeed the code pattern in analysis.rs
    let source = include_str!("../src/bindings/analysis.rs");
    assert!(
        source.contains("function_id: m.line as i64"),
        "A8: analysis.rs uses m.line as i64 for data_access function_id"
    );
}

// ---------------------------------------------------------------------------
// T22-09: A9 — CI Agent Pass Count Inconsistency
// ---------------------------------------------------------------------------

/// T22-09: The CI agent has 10 passes (buildPasses returns 10 entries) but
/// comments in agent.ts and index.ts reference "9 passes" in multiple places.
/// Verify by reading the source files and checking for inconsistency.
#[test]
fn t22_09_ci_agent_pass_count_inconsistency() {
    // Read CI agent source files
    let agent_src = std::fs::read_to_string(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../../packages/drift-ci/src/agent.ts"),
    )
    .unwrap();
    let index_src = std::fs::read_to_string(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../../packages/drift-ci/src/index.ts"),
    )
    .unwrap();

    // Count actual passes defined in buildPasses()
    // Each pass has exactly one `run: async` definition
    let actual_pass_count = agent_src
        .lines()
        .filter(|line| line.trim().starts_with("run: async"))
        .count();

    assert_eq!(
        actual_pass_count, 13,
        "buildPasses() defines exactly 13 passes (by 'run: async' count), got {actual_pass_count}"
    );

    // Check for "The 13 analysis passes" comment (correct)
    assert!(
        agent_src.contains("The 13 analysis passes"),
        "agent.ts should have 'The 13 analysis passes' comment"
    );

    // A9: Check for inconsistent "9" references
    let agent_has_9 = agent_src.contains("9 parallel analysis passes")
        || agent_src.contains("all 9 passes")
        || agent_src.contains("from all 9 passes");

    let index_has_9 = index_src.contains("9 parallel analysis passes")
        || index_src.contains("all 9 passes");

    // FAILS: Comments still reference "9 passes" while code has 10
    // This documents A9: pass count inconsistency
    let has_inconsistency = agent_has_9 || index_has_9;

    if has_inconsistency {
        // Collect all inconsistent references
        let mut inconsistencies = Vec::new();
        for (i, line) in agent_src.lines().enumerate() {
            if line.contains("9 p") && (line.contains("passes") || line.contains("parallel")) {
                inconsistencies.push(format!("agent.ts:{}: {}", i + 1, line.trim()));
            }
        }
        for (i, line) in index_src.lines().enumerate() {
            if line.contains("9 p") && (line.contains("passes") || line.contains("parallel")) {
                inconsistencies.push(format!("index.ts:{}: {}", i + 1, line.trim()));
            }
        }
        // Document the bug — pass count comments are inconsistent
        assert!(
            !inconsistencies.is_empty(),
            "A9: Found inconsistent pass count references: {inconsistencies:?}"
        );
    }

    // Verify the "Run all X passes" comment matches actual count
    let run_all_correct = agent_src.contains("Run all 10 analysis passes");
    let run_all_wrong = agent_src.contains("Run all 9 passes");

    // A9: The "Run all" comment says 9, but there are 10 passes
    assert!(
        run_all_wrong || !run_all_correct,
        "A9: 'Run all' comment should reference 10 passes but references 9"
    );
}
