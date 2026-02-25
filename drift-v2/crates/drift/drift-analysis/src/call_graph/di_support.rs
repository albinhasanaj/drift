//! DI injection framework support — FastAPI, Spring, NestJS, Laravel, ASP.NET.
//!
//! Detects dependency injection patterns and resolves them at confidence 0.80.

use drift_core::types::collections::FxHashMap;

use crate::parsers::types::{DecoratorInfo, ParseResult};

use super::types::Resolution;

/// A DI framework signature.
#[derive(Debug, Clone)]
pub struct DiFramework {
    pub name: &'static str,
    pub language: &'static str,
    /// Decorator/annotation names that indicate DI injection.
    pub injection_decorators: &'static [&'static str],
    /// Import sources that indicate this framework.
    pub import_sources: &'static [&'static str],
}

/// All supported DI frameworks.
pub const DI_FRAMEWORKS: &[DiFramework] = &[
    DiFramework {
        name: "NestJS",
        language: "TypeScript",
        injection_decorators: &["Injectable", "Inject", "Controller", "Module"],
        import_sources: &["@nestjs/common", "@nestjs/core"],
    },
    DiFramework {
        name: "Spring",
        language: "Java",
        injection_decorators: &["Autowired", "Inject", "Component", "Service", "Repository", "Bean"],
        import_sources: &["org.springframework"],
    },
    DiFramework {
        name: "FastAPI",
        language: "Python",
        injection_decorators: &["Depends"],
        import_sources: &["fastapi"],
    },
    DiFramework {
        name: "Laravel",
        language: "PHP",
        injection_decorators: &[],
        import_sources: &["Illuminate\\"],
    },
    DiFramework {
        name: "ASP.NET",
        language: "CSharp",
        injection_decorators: &["Inject", "FromServices"],
        import_sources: &["Microsoft.Extensions.DependencyInjection"],
    },
];

/// Detect which DI frameworks are used in the codebase.
pub fn detect_di_frameworks(parse_results: &[ParseResult]) -> Vec<&'static DiFramework> {
    let mut detected = Vec::new();

    for framework in DI_FRAMEWORKS {
        let is_used = parse_results.iter().any(|pr| {
            // Check imports
            pr.imports.iter().any(|imp| {
                framework.import_sources.iter().any(|src| imp.source.contains(src))
            })
            ||
            // Check decorators
            pr.functions.iter().any(|f| {
                f.decorators.iter().any(|d| {
                    framework.injection_decorators.contains(&d.name.as_str())
                })
            })
        });

        if is_used {
            detected.push(framework);
        }
    }

    detected
}

/// Check if a decorator indicates DI injection.
pub fn is_di_decorator(decorator: &DecoratorInfo) -> bool {
    DI_FRAMEWORKS.iter().any(|fw| {
        fw.injection_decorators.contains(&decorator.name.as_str())
    })
}

/// Resolve a DI-injected dependency to a provider function/class.
///
/// Returns the callee key and Resolution::DiInjection if found.
pub fn resolve_di_injection(
    injected_type: &str,
    name_index: &FxHashMap<String, Vec<String>>,
) -> Option<(String, Resolution)> {
    // Look for a class/function with the injected type name
    if let Some(keys) = name_index.get(injected_type) {
        if keys.len() == 1 {
            return Some((keys[0].clone(), Resolution::DiInjection));
        }
    }
    None
}
