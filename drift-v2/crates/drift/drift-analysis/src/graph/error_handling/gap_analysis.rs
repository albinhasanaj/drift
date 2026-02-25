//! Phases 4-5: Unhandled path identification + gap analysis.

use crate::parsers::types::ParseResult;

use super::types::*;

/// Analyze error handling gaps from detected handlers and propagation chains.
pub fn analyze_gaps(
    handlers: &[ErrorHandler],
    chains: &[PropagationChain],
    parse_results: &[ParseResult],
) -> Vec<ErrorGap> {
    let mut gaps = Vec::new();

    // Phase 4: Detect empty catch blocks
    for handler in handlers {
        if handler.is_empty {
            gaps.push(ErrorGap {
                file: handler.file.clone(),
                function: handler.function.clone(),
                line: handler.line,
                gap_type: GapType::EmptyCatch,
                error_type: handler.caught_types.first().cloned(),
                framework: None,
                cwe_id: Some(390), // CWE-390: Detection of Error Condition Without Action
                severity: GapSeverity::High,
                remediation: Some("Add error logging or re-throw the error".to_string()),
            });
        }

        // Detect generic catch (catching base Exception/Error)
        for caught in &handler.caught_types {
            let is_generic = matches!(
                caught.as_str(),
                "Exception" | "Error" | "BaseException" | "Throwable"
                    | "System.Exception" | "std::exception" | "object"
            );
            if is_generic {
                gaps.push(ErrorGap {
                    file: handler.file.clone(),
                    function: handler.function.clone(),
                    line: handler.line,
                    gap_type: GapType::GenericCatch,
                    error_type: Some(caught.clone()),
                    framework: None,
                    cwe_id: Some(396), // CWE-396: Declaration of Catch for Generic Exception
                    severity: GapSeverity::Medium,
                    remediation: Some("Catch specific exception types instead of generic ones".to_string()),
                });
            }
        }
    }

    // Phase 5: Detect unhandled error paths from propagation chains
    for chain in chains {
        if !chain.is_handled {
            if let Some(source) = chain.functions.first() {
                gaps.push(ErrorGap {
                    file: source.file.clone(),
                    function: source.function.clone(),
                    line: source.line,
                    gap_type: GapType::Unhandled,
                    error_type: chain.error_type.clone(),
                    framework: None,
                    cwe_id: Some(248), // CWE-248: Uncaught Exception
                    severity: GapSeverity::High,
                    remediation: Some("Add error handling in a caller function".to_string()),
                });
            }
        }
    }

    // Detect swallowed errors (handler exists but doesn't log or re-throw)
    for handler in handlers {
        if !handler.is_empty && !handler.rethrows {
            // Heuristic: if the handler doesn't rethrow and has a very small body,
            // it might be swallowing the error
            let body_lines = handler.end_line.saturating_sub(handler.line);
            if body_lines <= 2 {
                gaps.push(ErrorGap {
                    file: handler.file.clone(),
                    function: handler.function.clone(),
                    line: handler.line,
                    gap_type: GapType::SwallowedError,
                    error_type: handler.caught_types.first().cloned(),
                    framework: None,
                    cwe_id: Some(390),
                    severity: GapSeverity::Medium,
                    remediation: Some("Log the error or re-throw it".to_string()),
                });
            }
        }
    }

    // Detect unhandled async patterns
    detect_unhandled_async(parse_results, &mut gaps);

    gaps
}

/// Detect unhandled async error patterns.
fn detect_unhandled_async(parse_results: &[ParseResult], gaps: &mut Vec<ErrorGap>) {
    for pr in parse_results {
        for func in &pr.functions {
            if func.is_async {
                // Check if async function has any error handling
                let has_handler = pr.error_handling.iter().any(|eh| {
                    eh.line >= func.line
                        && eh.line <= func.end_line
                        && matches!(
                            eh.kind,
                            crate::parsers::types::ErrorHandlingKind::TryCatch
                                | crate::parsers::types::ErrorHandlingKind::AsyncAwaitTry
                                | crate::parsers::types::ErrorHandlingKind::PromiseCatch
                        )
                });

                // Check if the function has any await calls
                let has_await = pr.call_sites.iter().any(|cs| {
                    cs.line >= func.line && cs.line <= func.end_line && cs.is_await
                });

                if has_await && !has_handler {
                    gaps.push(ErrorGap {
                        file: pr.file.clone(),
                        function: func.name.clone(),
                        line: func.line,
                        gap_type: GapType::UnhandledAsync,
                        error_type: None,
                        framework: None,
                        cwe_id: Some(248),
                        severity: GapSeverity::Medium,
                        remediation: Some(
                            "Wrap await calls in try/catch or add .catch() handler".to_string(),
                        ),
                    });
                }
            }
        }
    }
}
