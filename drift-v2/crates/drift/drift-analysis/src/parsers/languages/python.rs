//! Python parser.

use std::path::Path;
use drift_core::errors::ParseError;
use crate::scanner::language_detect::Language;
use crate::parsers::traits::LanguageParser;
use crate::parsers::types::ParseResult;
use super::parse_with_language;

pub struct PythonParser;

impl Default for PythonParser {
    fn default() -> Self {
        Self::new()
    }
}

impl PythonParser {
    pub fn new() -> Self { Self }
}

impl LanguageParser for PythonParser {
    fn language(&self) -> Language { Language::Python }
    fn extensions(&self) -> &[&str] { &["py", "pyi"] }

    fn parse(&self, source: &[u8], path: &Path) -> Result<ParseResult, ParseError> {
        parse_with_language(source, path, Language::Python, tree_sitter_python::LANGUAGE.into())
    }
}
