//! Tree-sitter parser subsystem — 10 languages, thread_local instances, parse cache.

pub mod cache;
pub mod error_tolerant;
pub mod languages;
pub mod macros;
pub mod manager;
pub mod queries;
pub mod traits;
pub mod types;

pub use manager::ParserManager;
pub use types::ParseResult;
