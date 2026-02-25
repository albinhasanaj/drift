//! C# parser.

use std::path::Path;
use drift_core::errors::ParseError;
use crate::scanner::language_detect::Language;
use crate::parsers::traits::LanguageParser;
use crate::parsers::types::ParseResult;
use super::parse_with_language;

pub struct CSharpParser;

impl Default for CSharpParser {
    fn default() -> Self {
        Self::new()
    }
}

impl CSharpParser {
    pub fn new() -> Self { Self }
}

impl LanguageParser for CSharpParser {
    fn language(&self) -> Language { Language::CSharp }
    fn extensions(&self) -> &[&str] { &["cs"] }

    fn parse(&self, source: &[u8], path: &Path) -> Result<ParseResult, ParseError> {
        parse_with_language(source, path, Language::CSharp, tree_sitter_c_sharp::LANGUAGE.into())
    }
}
