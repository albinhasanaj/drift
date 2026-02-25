//! Project registry — resolve, switch, list, health indicators.
//! V1's 5-step resolution algorithm preserved exactly.

use std::path::{Path, PathBuf};

use rusqlite::Connection;

use serde::Serialize;

use super::errors::{WorkspaceError, WorkspaceResult};

/// Health status indicators — v1's 4-level system preserved exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum HealthStatus {
    Healthy,
    Warning,
    Critical,
    Unknown,
}

impl HealthStatus {
    pub fn emoji(&self) -> &'static str {
        match self {
            Self::Healthy => "🟢",
            Self::Warning => "🟡",
            Self::Critical => "🔴",
            Self::Unknown => "⚪",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Warning => "warning",
            Self::Critical => "critical",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "healthy" => Self::Healthy,
            "warning" => Self::Warning,
            "critical" => Self::Critical,
            _ => Self::Unknown,
        }
    }
}

/// Information about a registered project.
#[derive(Debug, Clone, Serialize)]
pub struct ProjectInfo {
    pub id: String,
    pub name: String,
    pub root_path: PathBuf,
    pub drift_path: PathBuf,
    pub health_status: HealthStatus,
    pub is_active: bool,
}

/// Resolve a project identifier to a registered project.
/// 5-step resolution algorithm (v1 pattern preserved exactly).
pub fn resolve_project(conn: &Connection, identifier: &str) -> WorkspaceResult<ProjectInfo> {
    // Step 1: Exact name match
    if let Some(project) = query_project_by_name(conn, identifier)? {
        return Ok(project);
    }

    // Step 2: Path match
    if let Some(project) = query_project_by_path(conn, identifier)? {
        return Ok(project);
    }

    // Step 3: ID match
    if let Some(project) = query_project_by_id(conn, identifier)? {
        return Ok(project);
    }

    // Step 4: Partial name match (substring)
    let partial_matches = query_projects_by_partial_name(conn, identifier)?;
    match partial_matches.len() {
        1 => return Ok(partial_matches.into_iter().next().unwrap()),
        n if n > 1 => {
            return Err(WorkspaceError::AmbiguousProject {
                identifier: identifier.to_string(),
                matches: partial_matches.iter().map(|p| p.name.clone()).collect(),
            });
        }
        _ => {}
    }

    // Step 5: Auto-detect from path (check for .drift/ directory)
    let path = Path::new(identifier);
    if path.join(".drift").exists() {
        return Ok(ProjectInfo {
            id: generate_project_id(),
            name: path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unnamed")
                .to_string(),
            root_path: path.to_path_buf(),
            drift_path: path.join(".drift"),
            health_status: HealthStatus::Unknown,
            is_active: false,
        });
    }

    Err(WorkspaceError::ProjectNotFound(identifier.to_string()))
}

/// Switch to a different project. Deactivates current, activates new.
pub fn switch_project(conn: &Connection, identifier: &str) -> WorkspaceResult<ProjectInfo> {
    let project = resolve_project(conn, identifier)?;

    conn.execute(
        "UPDATE project_registry SET is_active = 0 WHERE is_active = 1",
        [],
    )?;

    conn.execute(
        "UPDATE project_registry SET is_active = 1, last_accessed_at = datetime('now')
         WHERE id = ?1",
        [&project.id],
    )?;

    conn.execute(
        "INSERT INTO workspace_events (event_type, details) VALUES ('project_switch', ?1)",
        [format!(
            r#"{{"project_id":"{}","project_name":"{}"}}"#,
            project.id, project.name
        )],
    )?;

    Ok(project)
}

/// Get the currently active project.
pub fn get_active_project(conn: &Connection) -> WorkspaceResult<Option<ProjectInfo>> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, name, root_path, drift_path, health_status
         FROM project_registry WHERE is_active = 1",
    )?;
    let result = stmt.query_row([], |row| {
        Ok(ProjectInfo {
            id: row.get(0)?,
            name: row.get(1)?,
            root_path: PathBuf::from(row.get::<_, String>(2)?),
            drift_path: PathBuf::from(row.get::<_, String>(3)?),
            health_status: HealthStatus::parse(&row.get::<_, String>(4)?),
            is_active: true,
        })
    });

    match result {
        Ok(project) => Ok(Some(project)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(WorkspaceError::from(e)),
    }
}

/// List all registered projects.
pub fn list_projects(conn: &Connection) -> WorkspaceResult<Vec<ProjectInfo>> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, name, root_path, drift_path, health_status, is_active
         FROM project_registry ORDER BY last_accessed_at DESC",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok(ProjectInfo {
                id: row.get(0)?,
                name: row.get(1)?,
                root_path: PathBuf::from(row.get::<_, String>(2)?),
                drift_path: PathBuf::from(row.get::<_, String>(3)?),
                health_status: HealthStatus::parse(&row.get::<_, String>(4)?),
                is_active: row.get::<_, i32>(5)? != 0,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Format project indicator for CLI output.
pub fn format_project_indicator(project: &ProjectInfo) -> String {
    format!("[{}]", project.name)
}

/// Format full project header for CLI status output.
pub fn format_project_header(project: &ProjectInfo) -> String {
    format!(
        "{} {} — {}",
        project.health_status.emoji(),
        project.name,
        project.root_path.display(),
    )
}

// ---- Internal query helpers ----

fn query_project_by_name(conn: &Connection, name: &str) -> WorkspaceResult<Option<ProjectInfo>> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, name, root_path, drift_path, health_status, is_active
         FROM project_registry WHERE name = ?1",
    )?;
    match stmt.query_row([name], row_to_project) {
        Ok(p) => Ok(Some(p)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(WorkspaceError::from(e)),
    }
}

fn query_project_by_path(conn: &Connection, path: &str) -> WorkspaceResult<Option<ProjectInfo>> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, name, root_path, drift_path, health_status, is_active
         FROM project_registry WHERE root_path = ?1",
    )?;
    match stmt.query_row([path], row_to_project) {
        Ok(p) => Ok(Some(p)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(WorkspaceError::from(e)),
    }
}

fn query_project_by_id(conn: &Connection, id: &str) -> WorkspaceResult<Option<ProjectInfo>> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, name, root_path, drift_path, health_status, is_active
         FROM project_registry WHERE id = ?1",
    )?;
    match stmt.query_row([id], row_to_project) {
        Ok(p) => Ok(Some(p)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(WorkspaceError::from(e)),
    }
}

fn query_projects_by_partial_name(
    conn: &Connection,
    partial: &str,
) -> WorkspaceResult<Vec<ProjectInfo>> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, name, root_path, drift_path, health_status, is_active
         FROM project_registry WHERE name LIKE '%' || ?1 || '%'",
    )?;
    let rows = stmt
        .query_map([partial], row_to_project)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn row_to_project(row: &rusqlite::Row) -> rusqlite::Result<ProjectInfo> {
    Ok(ProjectInfo {
        id: row.get(0)?,
        name: row.get(1)?,
        root_path: PathBuf::from(row.get::<_, String>(2)?),
        drift_path: PathBuf::from(row.get::<_, String>(3)?),
        health_status: HealthStatus::parse(&row.get::<_, String>(4)?),
        is_active: row.get::<_, i32>(5)? != 0,
    })
}

/// Generate a unique project ID.
pub fn generate_project_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("proj-{:016x}", ts)
}
