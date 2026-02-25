//! Log every memory mutation: create, update, archive, restore, link, unlink,
//! decay, validate, consolidate, reclassify.

use rusqlite::Connection;

use cortex_core::errors::CortexResult;
use cortex_core::models::{AuditActor, AuditEntry, AuditOperation};

use crate::queries::audit_ops;

/// Append-only audit logger. Wraps the audit_ops query functions
/// with a convenient API.
pub struct AuditLogger;

impl AuditLogger {
    /// Log a memory mutation.
    pub fn log(
        conn: &Connection,
        memory_id: &str,
        operation: AuditOperation,
        actor: AuditActor,
        details: serde_json::Value,
    ) -> CortexResult<()> {
        let entry = AuditEntry {
            memory_id: memory_id.to_string(),
            operation,
            details,
            actor,
            timestamp: chrono::Utc::now(),
        };
        audit_ops::insert_audit_entry(conn, &entry)
    }

    /// Log a create operation.
    pub fn log_create(conn: &Connection, memory_id: &str, actor: AuditActor) -> CortexResult<()> {
        Self::log(
            conn,
            memory_id,
            AuditOperation::Create,
            actor,
            serde_json::json!({}),
        )
    }

    /// Log an update operation with a reason.
    pub fn log_update(
        conn: &Connection,
        memory_id: &str,
        actor: AuditActor,
        reason: &str,
    ) -> CortexResult<()> {
        Self::log(
            conn,
            memory_id,
            AuditOperation::Update,
            actor,
            serde_json::json!({ "reason": reason }),
        )
    }
}
