//! PHP parser.

use std::path::Path;
use drift_core::errors::ParseError;
use crate::scanner::language_detect::Language;
use crate::parsers::traits::LanguageParser;
use crate::parsers::types::ParseResult;
use super::parse_with_language;

pub struct PhpParser;

impl Default for PhpParser {
    fn default() -> Self {
        Self::new()
    }
}

impl PhpParser {
    pub fn new() -> Self { Self }
}

impl LanguageParser for PhpParser {
    fn language(&self) -> Language { Language::Php }
    fn extensions(&self) -> &[&str] { &["php"] }

    fn parse(&self, source: &[u8], path: &Path) -> Result<ParseResult, ParseError> {
        parse_with_language(source, path, Language::Php, tree_sitter_php::LANGUAGE_PHP.into())
    }
}
