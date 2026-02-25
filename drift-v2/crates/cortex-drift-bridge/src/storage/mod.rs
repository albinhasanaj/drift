//! Bridge-specific SQLite tables and storage operations.

pub mod engine;
pub mod migrations;
pub mod pool;
pub mod pragmas;
pub mod retention;
pub mod schema;
pub mod tables;

pub use migrations::migrate;
pub use pragmas::{configure_connection, configure_readonly_connection};
pub use retention::apply_retention;
pub use schema::BRIDGE_TABLE_NAMES;
pub use tables::{
    attach_cortex_db, create_bridge_tables, detach_cortex_db, get_grounding_history,
    get_previous_grounding_score, log_event, record_grounding_result,
    record_grounding_snapshot, record_metric, store_memory, update_memory_confidence,
};
