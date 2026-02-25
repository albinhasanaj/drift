//! Production Category 24: Graceful Degradation — Parser Failure Recovery
//!
//! T24-04: Parser failure on one file must not crash the pipeline.
//! Binary files (.png) that the parser can't handle must return an error
//! for that file while all other files are still parsed successfully.
//!
//! Source verification:
//!   - ParserManager::parse: parsers/manager.rs:90-117
//!   - Language::from_extension: scanner/language_detect.rs
//!   - ParseError::UnsupportedLanguage: drift-core/src/errors.rs
//!   - Scanner error recovery: scanner/scanner.rs:107-118 (continue on error)

use std::path::Path;

use drift_analysis::parsers::manager::ParserManager;
use drift_analysis::parsers::types::ParseResult;
use drift_core::errors::ParseError;

// ═══════════════════════════════════════════════════════════════════════════
// T24-04: Parser Failure on One File
//
// Include a binary file (.png) that the parser can't handle.
// Parser must return an error for that file. All other files must still
// be parsed and analyzed. Pipeline continues.
// Source: parsers/manager.rs:90-99 — UnsupportedLanguage for unknown ext
// Source: scanner/scanner.rs:107-118 — continue on parse failure
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn t24_04_parser_failure_on_one_file() {
    let parser = ParserManager::new();

    // 1. Binary file (.png) must fail with UnsupportedLanguage
    let png_path = Path::new("image.png");
    let png_content = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
    let png_result = parser.parse(png_content, png_path);

    assert!(
        png_result.is_err(),
        "Parsing a .png file must return an error, not crash"
    );
    match png_result.unwrap_err() {
        ParseError::UnsupportedLanguage { extension } => {
            assert_eq!(extension, "png", "Extension should be reported as 'png'");
        }
        other => {
            panic!(
                "Expected UnsupportedLanguage for .png, got: {:?}",
                other
            );
        }
    }

    // 2. Other files must still parse successfully after the .png failure
    let ts_path = Path::new("src/main.ts");
    let ts_content = b"export function hello(): string { return 'world'; }";
    let ts_result = parser.parse(ts_content, ts_path);
    assert!(
        ts_result.is_ok(),
        "TypeScript file must parse successfully after .png failure"
    );
    let ts_parsed: ParseResult = ts_result.unwrap();
    assert_eq!(ts_parsed.functions.len(), 1, "Should extract 1 function");
    assert_eq!(ts_parsed.functions[0].name, "hello");

    // 3. Python file also works
    let py_path = Path::new("utils/helper.py");
    let py_content = b"def add(a, b):\n    return a + b\n";
    let py_result = parser.parse(py_content, py_path);
    assert!(
        py_result.is_ok(),
        "Python file must parse successfully after .png failure"
    );

    // 4. File with no extension must fail gracefully
    let no_ext_path = Path::new("Makefile");
    let no_ext_content = b"all:\n\techo hello\n";
    let no_ext_result = parser.parse(no_ext_content, no_ext_path);
    assert!(
        no_ext_result.is_err(),
        "File with no recognized extension must return error, not crash"
    );

    // 5. Random binary content in a .ts file — parser should handle gracefully
    //    (tree-sitter is error-tolerant; it produces a parse tree with errors)
    let bad_ts_path = Path::new("corrupt.ts");
    let bad_ts_content: &[u8] = &[0xFF, 0xFE, 0x00, 0x01, 0x89, 0xAB, 0xCD, 0xEF];
    let bad_ts_result = parser.parse(bad_ts_content, bad_ts_path);
    // tree-sitter is error-tolerant, so it should produce a result (with errors)
    // rather than crashing
    match bad_ts_result {
        Ok(result) => {
            assert!(
                result.has_errors,
                "Binary content in .ts should produce parse errors"
            );
        }
        Err(_) => {
            // An error is also acceptable — the key is no panic
        }
    }
}
