//! ProjectionEngine — create, delete, get, list projections + filter evaluation.

use chrono::Utc;
use rusqlite::Connection;
use tracing::info;

use cortex_core::errors::{CortexResult, MultiAgentError};
use cortex_core::memory::BaseMemory;
use cortex_core::models::namespace::{MemoryProjection, NamespaceId, ProjectionFilter};

use cortex_storage::queries::multiagent_ops;

/// Manages memory projections between namespaces.
pub struct ProjectionEngine;

impl ProjectionEngine {
    /// Create a new projection. Validates source/target namespaces exist.
    pub fn create_projection(
        conn: &Connection,
        projection: &MemoryProjection,
    ) -> CortexResult<String> {
        let source_uri = projection.source.to_uri();
        let target_uri = projection.target.to_uri();

        // Validate source namespace exists.
        multiagent_ops::get_namespace(conn, &source_uri)?
            .ok_or_else(|| MultiAgentError::NamespaceNotFound(source_uri.clone()))?;

        // Validate target namespace exists.
        multiagent_ops::get_namespace(conn, &target_uri)?
            .ok_or_else(|| MultiAgentError::NamespaceNotFound(target_uri.clone()))?;

        let filter_json = serde_json::to_string(&projection.filter)
            .map_err(cortex_core::CortexError::SerializationError)?;

        multiagent_ops::insert_projection(
            conn,
            &multiagent_ops::InsertProjectionParams {
                projection_id: &projection.id,
                source_namespace: &source_uri,
                target_namespace: &target_uri,
                filter_json: &filter_json,
                compression_level: projection.compression_level as i32,
                live: projection.live,
                created_at: &projection.created_at.to_rfc3339(),
                created_by: &projection.created_by.0,
            },
        )?;

        info!(
            projection_id = %projection.id,
            source = %source_uri,
            target = %target_uri,
            live = projection.live,
            "projection created"
        );
        Ok(projection.id.clone())
    }

    /// Delete a projection.
    pub fn delete_projection(conn: &Connection, projection_id: &str) -> CortexResult<()> {
        multiagent_ops::get_projection(conn, projection_id)?
            .ok_or_else(|| MultiAgentError::ProjectionNotFound(projection_id.to_string()))?;

        multiagent_ops::delete_projection(conn, projection_id)?;
        info!(projection_id, "projection deleted");
        Ok(())
    }

    /// Get a projection by ID.
    pub fn get_projection(
        conn: &Connection,
        projection_id: &str,
    ) -> CortexResult<Option<MemoryProjection>> {
        let row = multiagent_ops::get_projection(conn, projection_id)?;
        match row {
            Some(r) => Ok(Some(row_to_projection(r)?)),
            None => Ok(None),
        }
    }

    /// List projections for a namespace.
    pub fn list_projections(
        conn: &Connection,
        namespace: &NamespaceId,
    ) -> CortexResult<Vec<MemoryProjection>> {
        let uri = namespace.to_uri();
        let rows = multiagent_ops::list_projections(conn, &uri)?;
        rows.into_iter().map(row_to_projection).collect()
    }

    /// Evaluate whether a memory matches a projection filter.
    /// All conditions are AND-ed: every specified filter must match.
    pub fn evaluate_filter(memory: &BaseMemory, filter: &ProjectionFilter) -> bool {
        // Memory types filter.
        if !filter.memory_types.is_empty()
            && !filter.memory_types.contains(&memory.memory_type)
        {
            return false;
        }

        // Minimum confidence.
        if let Some(min) = filter.min_confidence {
            if memory.confidence.value() < min {
                return false;
            }
        }

        // Minimum importance.
        if let Some(ref min) = filter.min_importance {
            if memory.importance < *min {
                return false;
            }
        }

        // Tags filter (any match).
        if !filter.tags.is_empty()
            && !filter.tags.iter().any(|t| memory.tags.contains(t))
        {
            return false;
        }

        // Linked files filter (any match).
        if !filter.linked_files.is_empty()
            && !filter.linked_files.iter().any(|f| {
                memory.linked_files.iter().any(|lf| lf.file_path == *f)
            })
        {
            return false;
        }

        // Max age in days.
        if let Some(days) = filter.max_age_days {
            let age = Utc::now()
                .signed_duration_since(memory.transaction_time)
                .num_days();
            if age > days as i64 {
                return false;
            }
        }

        true
    }
}

/// Convert a raw DB row to a `MemoryProjection`.
fn row_to_projection(row: multiagent_ops::ProjectionRow) -> CortexResult<MemoryProjection> {
    let source = cortex_core::models::namespace::NamespaceId::parse(&row.source_namespace)
        .map_err(MultiAgentError::InvalidNamespaceUri)?;
    let target = cortex_core::models::namespace::NamespaceId::parse(&row.target_namespace)
        .map_err(MultiAgentError::InvalidNamespaceUri)?;
    let filter: ProjectionFilter = serde_json::from_str(&row.filter_json)
        .map_err(cortex_core::CortexError::SerializationError)?;
    let created_at = chrono::DateTime::parse_from_rfc3339(&row.created_at)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|e| cortex_storage::to_storage_err(format!("parse created_at: {e}")))?;

    Ok(MemoryProjection {
        id: row.projection_id,
        source,
        target,
        filter,
        compression_level: row.compression_level as u8,
        live: row.live,
        created_at,
        created_by: cortex_core::models::agent::AgentId::from(row.created_by.as_str()),
    })
}
