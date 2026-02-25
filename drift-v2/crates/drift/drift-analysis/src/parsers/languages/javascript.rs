//! JavaScript parser.

use std::path::Path;
use drift_core::errors::ParseError;
use crate::scanner::language_detect::Language;
use crate::parsers::traits::LanguageParser;
use crate::parsers::types::ParseResult;
use super::parse_with_language;

pub struct JavaScriptParser;

impl Default for JavaScriptParser {
    fn default() -> Self {
        Self::new()
    }
}

impl JavaScriptParser {
    pub fn new() -> Self { Self }
}

impl LanguageParser for JavaScriptParser {
    fn language(&self) -> Language { Language::JavaScript }
    fn extensions(&self) -> &[&str] { &["js", "jsx", "mjs", "cjs"] }

    fn parse(&self, source: &[u8], path: &Path) -> Result<ParseResult, ParseError> {
        parse_with_language(source, path, Language::JavaScript, tree_sitter_javascript::LANGUAGE.into())
    }
}
