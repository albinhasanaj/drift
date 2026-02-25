//! Kotlin parser.

use std::path::Path;
use drift_core::errors::ParseError;
use crate::scanner::language_detect::Language;
use crate::parsers::traits::LanguageParser;
use crate::parsers::types::ParseResult;
use super::parse_with_language;

pub struct KotlinParser;

impl Default for KotlinParser {
    fn default() -> Self {
        Self::new()
    }
}

impl KotlinParser {
    pub fn new() -> Self { Self }
}

impl LanguageParser for KotlinParser {
    fn language(&self) -> Language { Language::Kotlin }
    fn extensions(&self) -> &[&str] { &["kt", "kts"] }

    fn parse(&self, source: &[u8], path: &Path) -> Result<ParseResult, ParseError> {
        parse_with_language(source, path, Language::Kotlin, tree_sitter_kotlin_sg::LANGUAGE.into())
    }
}
