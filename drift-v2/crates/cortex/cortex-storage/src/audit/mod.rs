//! AuditLogger — append-only mutation log.

pub mod logger;
pub mod rotation;

pub use logger::AuditLogger;
