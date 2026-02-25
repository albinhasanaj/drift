//! LanguageParser trait — the contract every language parser implements.

use std::path::Path;

use drift_core::errors::ParseError;

use super::types::ParseResult;
use crate::scanner::language_detect::Language;

/// Trait that every language parser must implement.
pub trait LanguageParser: Send + Sync {
    /// The language this parser handles.
    fn language(&self) -> Language;

    /// File extensions this parser handles.
    fn extensions(&self) -> &[&str];

    /// Parse source code and produce a ParseResult.
    fn parse(&self, source: &[u8], path: &Path) -> Result<ParseResult, ParseError>;
}
