//! Rust parser.

use std::path::Path;
use drift_core::errors::ParseError;
use crate::scanner::language_detect::Language;
use crate::parsers::traits::LanguageParser;
use crate::parsers::types::ParseResult;
use super::parse_with_language;

pub struct RustParser;

impl Default for RustParser {
    fn default() -> Self {
        Self::new()
    }
}

impl RustParser {
    pub fn new() -> Self { Self }
}

impl LanguageParser for RustParser {
    fn language(&self) -> Language { Language::Rust }
    fn extensions(&self) -> &[&str] { &["rs"] }

    fn parse(&self, source: &[u8], path: &Path) -> Result<ParseResult, ParseError> {
        parse_with_language(source, path, Language::Rust, tree_sitter_rust::LANGUAGE.into())
    }
}
