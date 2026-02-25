//! Phase 2: Handler detection — try/catch, Result, error callbacks.

use crate::parsers::types::{ErrorHandlingKind, ParseResult};

use super::types::{ErrorHandler, HandlerType};

/// Detect all error handlers in parse results.
pub fn detect_handlers(parse_results: &[ParseResult]) -> Vec<ErrorHandler> {
    let mut handlers = Vec::new();

    for pr in parse_results {
        for eh in &pr.error_handling {
            let handler_type = match eh.kind {
                ErrorHandlingKind::TryCatch => HandlerType::TryCatch,
                ErrorHandlingKind::TryExcept => HandlerType::TryExcept,
                ErrorHandlingKind::ResultMatch => HandlerType::ResultMatch,
                ErrorHandlingKind::PromiseCatch => HandlerType::PromiseCatch,
                ErrorHandlingKind::AsyncAwaitTry => HandlerType::TryCatch,
                ErrorHandlingKind::Rescue => HandlerType::Rescue,
                ErrorHandlingKind::Defer => HandlerType::DeferRecover,
                ErrorHandlingKind::DeferRecover => HandlerType::DeferRecover,
                ErrorHandlingKind::WithStatement => HandlerType::TryCatch,
                // Throw/QuestionMark/Unwrap are not handlers
                ErrorHandlingKind::Throw
                | ErrorHandlingKind::QuestionMark
                | ErrorHandlingKind::Unwrap
                | ErrorHandlingKind::TryFinally => continue,
            };

            let caught_types = eh
                .caught_type
                .as_ref()
                .map(|t| vec![t.clone()])
                .unwrap_or_default();

            let is_empty = !eh.has_body;

            let function = eh
                .function_scope
                .clone()
                .unwrap_or_else(|| "<anonymous>".to_string());

            handlers.push(ErrorHandler {
                file: pr.file.clone(),
                line: eh.line,
                end_line: eh.end_line,
                function,
                handler_type,
                caught_types,
                is_empty,
                rethrows: false, // Would need deeper AST analysis
            });
        }
    }

    handlers
}

/// Detect error callback patterns (Node.js style: `function(err, data)`).
pub fn detect_error_callbacks(parse_results: &[ParseResult]) -> Vec<ErrorHandler> {
    let mut handlers = Vec::new();

    for pr in parse_results {
        for func in &pr.functions {
            // Check if first parameter is named "err" or "error"
            if let Some(first_param) = func.parameters.first() {
                let name_lower = first_param.name.to_lowercase();
                if name_lower == "err" || name_lower == "error" || name_lower == "e" {
                    handlers.push(ErrorHandler {
                        file: pr.file.clone(),
                        line: func.line,
                        end_line: func.end_line,
                        function: func.name.clone(),
                        handler_type: HandlerType::ErrorCallback,
                        caught_types: vec!["Error".to_string()],
                        is_empty: false,
                        rethrows: false,
                    });
                }
            }
        }
    }

    handlers
}
