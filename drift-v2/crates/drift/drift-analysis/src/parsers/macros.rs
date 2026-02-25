//! `define_parser!` macro for reducing boilerplate per language.

/// Macro to define a language parser with standard boilerplate.
///
/// Usage:
/// ```ignore
/// define_parser!(TypeScriptParser, Language::TypeScript, &["ts", "tsx", "mts", "cts"]);
/// ```
#[macro_export]
macro_rules! define_parser {
    ($name:ident, $language:expr, $extensions:expr, $ts_language_fn:expr) => {
        pub struct $name;

        impl $name {
            pub fn new() -> Self {
                Self
            }

            fn ts_language() -> tree_sitter::Language {
                $ts_language_fn
            }
        }

        impl $crate::parsers::traits::LanguageParser for $name {
            fn language(&self) -> $crate::scanner::language_detect::Language {
                $language
            }

            fn extensions(&self) -> &[&str] {
                $extensions
            }

            fn parse(
                &self,
                source: &[u8],
                path: &std::path::Path,
            ) -> Result<$crate::parsers::types::ParseResult, drift_core::errors::ParseError> {
                $crate::parsers::languages::parse_with_language(
                    source,
                    path,
                    $language,
                    Self::ts_language(),
                )
            }
        }
    };
}
