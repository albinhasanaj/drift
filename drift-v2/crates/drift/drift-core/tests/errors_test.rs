//! Tests for the Drift error handling system.

use std::collections::HashSet;
use std::path::PathBuf;

use drift_core::errors::*;
use drift_core::errors::error_code::DriftErrorCode;

/// T0-ERR-01: Test every error enum has DriftErrorCode implementation
#[test]
fn test_all_errors_have_error_code() {
    let scan = ScanError::Cancelled;
    assert!(!scan.error_code().is_empty());

    let parse = ParseError::UnsupportedLanguage {
        extension: "xyz".into(),
    };
    assert!(!parse.error_code().is_empty());

    let storage = StorageError::DbBusy;
    assert!(!storage.error_code().is_empty());

    let detection = DetectionError::InvalidPattern("bad".into());
    assert!(!detection.error_code().is_empty());

    let call_graph = CallGraphError::MemoryExceeded;
    assert!(!call_graph.error_code().is_empty());

    let pipeline = PipelineError::Cancelled;
    assert!(!pipeline.error_code().is_empty());

    let taint = TaintError::InvalidSource("src".into());
    assert!(!taint.error_code().is_empty());

    let constraint = ConstraintError::InvalidInvariant("inv".into());
    assert!(!constraint.error_code().is_empty());

    let boundary = BoundaryError::UnknownOrm("orm".into());
    assert!(!boundary.error_code().is_empty());

    let gate = GateError::EvaluationFailed("fail".into());
    assert!(!gate.error_code().is_empty());

    let config = ConfigError::FileNotFound {
        path: "/tmp".into(),
    };
    assert!(!config.error_code().is_empty());

    let napi = NapiError::new("TEST", "test".into());
    assert!(!napi.error_code().is_empty());
}

/// T0-ERR-02: Test From conversions between sub-errors and top-level error
#[test]
fn test_from_conversions() {
    let scan = ScanError::Cancelled;
    let pipeline: PipelineError = scan.into();
    assert!(matches!(pipeline, PipelineError::Scan(ScanError::Cancelled)));

    let parse = ParseError::UnsupportedLanguage {
        extension: "xyz".into(),
    };
    let pipeline: PipelineError = parse.into();
    assert!(matches!(pipeline, PipelineError::Parse(_)));

    let storage = StorageError::DbBusy;
    let pipeline: PipelineError = storage.into();
    assert!(matches!(pipeline, PipelineError::Storage(_)));

    let detection = DetectionError::InvalidPattern("bad".into());
    let pipeline: PipelineError = detection.into();
    assert!(matches!(pipeline, PipelineError::Detection(_)));

    let call_graph = CallGraphError::MemoryExceeded;
    let pipeline: PipelineError = call_graph.into();
    assert!(matches!(pipeline, PipelineError::CallGraph(_)));

    let gate = GateError::EvaluationFailed("fail".into());
    let pipeline: PipelineError = gate.into();
    assert!(matches!(pipeline, PipelineError::Gate(_)));

    let config = ConfigError::FileNotFound {
        path: "/tmp".into(),
    };
    let pipeline: PipelineError = config.into();
    assert!(matches!(pipeline, PipelineError::Config(_)));
}

/// T0-ERR-03: Test NAPI error code string format [ERROR_CODE] message
#[test]
fn test_napi_error_code_format() {
    let scan = ScanError::Cancelled;
    let napi_str = scan.napi_string();
    assert!(napi_str.starts_with('['));
    assert!(napi_str.contains(']'));
    assert_eq!(napi_str, "[CANCELLED] Scan cancelled");

    let storage = StorageError::DbBusy;
    let napi_str = storage.napi_string();
    assert_eq!(
        napi_str,
        "[DB_BUSY] Database busy (another operation in progress)"
    );
}

/// T0-ERR-04: Test every error variant's Display impl produces human-readable message
#[test]
fn test_display_human_readable() {
    let errors: Vec<Box<dyn std::fmt::Display>> = vec![
        Box::new(ScanError::Cancelled),
        Box::new(ScanError::PermissionDenied {
            path: PathBuf::from("/tmp/test"),
        }),
        Box::new(ScanError::MaxFileSizeExceeded {
            path: PathBuf::from("/tmp/big"),
            size: 2_000_000,
            max: 1_000_000,
        }),
        Box::new(ParseError::UnsupportedLanguage {
            extension: "xyz".into(),
        }),
        Box::new(ParseError::GrammarNotFound {
            language: "brainfuck".into(),
        }),
        Box::new(StorageError::DbBusy),
        Box::new(StorageError::DiskFull),
        Box::new(StorageError::MigrationFailed {
            version: 3,
            message: "column missing".into(),
        }),
        Box::new(DetectionError::Timeout { timeout_ms: 5000 }),
        Box::new(CallGraphError::CycleDetected {
            path: vec!["a".into(), "b".into(), "a".into()],
        }),
        Box::new(TaintError::PathTooLong {
            length: 100,
            max: 50,
        }),
        Box::new(ConstraintError::ConflictingConstraints {
            a: "rule1".into(),
            b: "rule2".into(),
        }),
        Box::new(BoundaryError::SensitiveFieldConflict {
            field: "password".into(),
            model: "User".into(),
        }),
        Box::new(GateError::PolicyViolation("no tests".into())),
        Box::new(ConfigError::ValidationFailed {
            field: "score".into(),
            message: "too high".into(),
        }),
    ];

    for error in &errors {
        let msg = error.to_string();
        // Should not contain Debug formatting artifacts
        assert!(!msg.contains("{ "), "Debug leak in: {}", msg);
        // Should be non-empty
        assert!(!msg.is_empty());
    }
}

/// T0-ERR-05: Test PipelineResult accumulates multiple non-fatal errors
#[test]
fn test_pipeline_result_accumulates_errors() {
    let mut result = PipelineResult::<Vec<String>>::new(vec!["pattern1".into()]);
    assert!(result.is_clean());
    assert_eq!(result.error_count(), 0);

    result.add_error(PipelineError::Scan(ScanError::Cancelled));
    result.add_error(PipelineError::Parse(ParseError::UnsupportedLanguage {
        extension: "xyz".into(),
    }));

    assert!(!result.is_clean());
    assert_eq!(result.error_count(), 2);
    // Data is still accessible
    assert_eq!(result.data.len(), 1);
    assert_eq!(result.data[0], "pattern1");
}

/// T0-ERR-06: Test error chain preservation via source()
#[test]
fn test_error_chain_preservation() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file gone");
    let scan_err = ScanError::IoError {
        path: PathBuf::from("/tmp/test"),
        source: io_err,
    };

    // The source should be preserved
    use std::error::Error;
    let source = scan_err.source();
    assert!(source.is_some());
    assert!(source.unwrap().to_string().contains("file gone"));
}

/// T0-ERR-07: Test all 14 NAPI error codes are unique
#[test]
fn test_napi_error_codes_unique() {
    use drift_core::errors::error_code::*;

    let codes = vec![
        SCAN_ERROR,
        PARSE_ERROR,
        DB_BUSY,
        DB_CORRUPT,
        CANCELLED,
        UNSUPPORTED_LANGUAGE,
        DETECTION_ERROR,
        CALL_GRAPH_ERROR,
        CONFIG_ERROR,
        LICENSE_ERROR,
        GATE_FAILED,
        STORAGE_ERROR,
        DISK_FULL,
        MIGRATION_FAILED,
    ];

    let unique: HashSet<&str> = codes.iter().copied().collect();
    assert_eq!(
        codes.len(),
        unique.len(),
        "Duplicate error codes found"
    );
}

/// T0-ERR-08: Test NapiError conversion from every other error type
#[test]
fn test_napi_error_from_all_types() {
    let _: NapiError = ScanError::Cancelled.into();
    let _: NapiError = ParseError::UnsupportedLanguage {
        extension: "xyz".into(),
    }
    .into();
    let _: NapiError = StorageError::DbBusy.into();
    let _: NapiError = DetectionError::InvalidPattern("bad".into()).into();
    let _: NapiError = CallGraphError::MemoryExceeded.into();
    let _: NapiError = PipelineError::Cancelled.into();
    let _: NapiError = TaintError::InvalidSource("src".into()).into();
    let _: NapiError = ConstraintError::InvalidInvariant("inv".into()).into();
    let _: NapiError = BoundaryError::UnknownOrm("orm".into()).into();
    let _: NapiError = GateError::EvaluationFailed("fail".into()).into();
    let _: NapiError = ConfigError::FileNotFound {
        path: "/tmp".into(),
    }
    .into();
}
