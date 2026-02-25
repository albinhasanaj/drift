//! Query layer: parameterized reads against drift.db and cortex.db,
//! ATTACH lifecycle with RAII guard, cross-DB operations.

pub mod attach;
pub mod cortex_queries;
pub mod cross_db;
pub mod drift_queries;

pub use attach::AttachGuard;
pub use cortex_queries::MemoryRow;
pub use cross_db::with_drift_attached;
