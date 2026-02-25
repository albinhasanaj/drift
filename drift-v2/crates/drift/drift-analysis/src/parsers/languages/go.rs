//! Go parser.

use std::path::Path;
use drift_core::errors::ParseError;
use crate::scanner::language_detect::Language;
use crate::parsers::traits::LanguageParser;
use crate::parsers::types::ParseResult;
use super::parse_with_language;

pub struct GoParser;

impl Default for GoParser {
    fn default() -> Self {
        Self::new()
    }
}

impl GoParser {
    pub fn new() -> Self { Self }
}

impl LanguageParser for GoParser {
    fn language(&self) -> Language { Language::Go }
    fn extensions(&self) -> &[&str] { &["go"] }

    fn parse(&self, source: &[u8], path: &Path) -> Result<ParseResult, ParseError> {
        parse_with_language(source, path, Language::Go, tree_sitter_go::LANGUAGE.into())
    }
}
