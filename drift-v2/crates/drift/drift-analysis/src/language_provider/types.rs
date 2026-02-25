//! Unified Language Provider types — UnifiedCallChain, semantic categories.

use serde::{Deserialize, Serialize};

use crate::scanner::language_detect::Language;

/// A unified call chain representation, language-agnostic.
///
/// Examples:
/// - TS: `User.findAll({ where: { active: true } })` → receiver="User", calls=[findAll]
/// - Python: `User.objects.filter(active=True)` → receiver="User.objects", calls=[filter]
/// - Java: `userRepo.findByActiveTrue()` → receiver="userRepo", calls=[findByActiveTrue]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedCallChain {
    pub receiver: String,
    pub calls: Vec<ChainCall>,
    pub file: String,
    pub line: u32,
    pub language: Language,
}

/// A single method call in a chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainCall {
    pub method: String,
    pub args: Vec<CallArg>,
}

/// An argument in a method call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CallArg {
    /// A string literal argument.
    StringLiteral(String),
    /// A numeric literal argument.
    NumberLiteral(f64),
    /// A boolean literal argument.
    BoolLiteral(bool),
    /// An identifier reference.
    Identifier(String),
    /// A complex expression (not further analyzed).
    Expression(String),
}

/// A detected ORM data access pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrmPattern {
    pub framework: String,
    pub operation: DataOperation,
    pub table: Option<String>,
    pub fields: Vec<String>,
    pub file: String,
    pub line: u32,
    pub confidence: f32,
}

/// Data operation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataOperation {
    Select,
    Insert,
    Update,
    Delete,
    Upsert,
    Count,
    Aggregate,
    Join,
    Transaction,
    Migration,
    RawQuery,
    Unknown,
}

impl DataOperation {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Select => "select",
            Self::Insert => "insert",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Upsert => "upsert",
            Self::Count => "count",
            Self::Aggregate => "aggregate",
            Self::Join => "join",
            Self::Transaction => "transaction",
            Self::Migration => "migration",
            Self::RawQuery => "raw_query",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for DataOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Semantic categories for call chain classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SemanticCategory {
    DataRead,
    DataWrite,
    DataDelete,
    Authentication,
    Authorization,
    Validation,
    Serialization,
    Logging,
    ErrorHandling,
    Caching,
    Messaging,
    FileIO,
}
