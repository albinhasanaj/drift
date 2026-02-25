//! Phase 1: Error type profiling — categorize error types per language.

use crate::parsers::types::{ErrorHandlingKind, ParseResult};

use super::types::ErrorType;

/// Profile error types found in parse results.
pub fn profile_error_types(parse_results: &[ParseResult]) -> Vec<ErrorType> {
    let mut error_types = Vec::new();

    for pr in parse_results {
        for eh in &pr.error_handling {
            let language = pr.language.name().to_string();

            let (name, is_checked, parent) = match eh.kind {
                ErrorHandlingKind::TryCatch => {
                    let caught = eh.caught_type.clone().unwrap_or_else(|| "Error".to_string());
                    (caught, false, Some("Error".to_string()))
                }
                ErrorHandlingKind::TryExcept => {
                    let caught = eh.caught_type.clone().unwrap_or_else(|| "Exception".to_string());
                    (caught, false, Some("BaseException".to_string()))
                }
                ErrorHandlingKind::ResultMatch => {
                    ("Result".to_string(), true, None)
                }
                ErrorHandlingKind::QuestionMark => {
                    ("Result".to_string(), true, None)
                }
                ErrorHandlingKind::Throw => {
                    let thrown = eh.caught_type.clone().unwrap_or_else(|| "Error".to_string());
                    (thrown, false, Some("Error".to_string()))
                }
                ErrorHandlingKind::PromiseCatch => {
                    ("Promise".to_string(), false, None)
                }
                ErrorHandlingKind::AsyncAwaitTry => {
                    ("AsyncError".to_string(), false, Some("Error".to_string()))
                }
                ErrorHandlingKind::Rescue => {
                    let caught = eh.caught_type.clone().unwrap_or_else(|| "StandardError".to_string());
                    (caught, false, Some("Exception".to_string()))
                }
                ErrorHandlingKind::Defer => {
                    ("error".to_string(), false, None)
                }
                _ => {
                    ("Unknown".to_string(), false, None)
                }
            };

            error_types.push(ErrorType {
                name,
                language,
                is_checked,
                parent,
            });
        }
    }

    error_types
}
