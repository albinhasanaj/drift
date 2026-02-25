//! Event-driven context refresh — zero staleness.
//! Materialized workspace_context table refreshed after every scan.
//! Replaces v1's 2-tier cache (memory + JSON, 5min TTL) entirely.

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use super::errors::WorkspaceResult;

/// V2 workspace context — replaces v1's ContextLoader.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceContext {
    pub project: ProjectContext,
    pub analysis: AnalysisStatus,
    pub loaded_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectContext {
    pub name: String,
    pub root_path: String,
    pub schema_version: String,
    pub drift_version: String,
    pub last_scan_at: Option<String>,
    pub health_score: Option<String>,
    pub languages: Vec<String>,
    pub frameworks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnalysisStatus {
    pub call_graph_built: bool,
    pub test_topology_built: bool,
    pub coupling_built: bool,
    pub dna_profile_exists: bool,
    pub constants_extracted: bool,
    pub constraints_mined: bool,
    pub contracts_detected: bool,
    pub security_scanned: bool,
}

/// Agent-friendly context for MCP tools (v1 pattern preserved).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentProjectContext {
    pub summary: String,
    pub available_commands: Vec<String>,
    pub warnings: Vec<String>,
    pub readiness: Readiness,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Readiness {
    pub scanned: bool,
    pub call_graph_built: bool,
    pub memory_initialized: bool,
}

/// Refresh workspace context after scan completion.
/// This is the FINAL step of every scan pipeline.
/// Replaces v1's 2-tier cache entirely.
pub fn refresh_workspace_context(conn: &Connection) -> WorkspaceResult<()> {
    conn.execute("DELETE FROM workspace_context", [])?;

    // Store project metadata from workspace_config
    let keys = [
        "project_name",
        "root_path",
        "schema_version",
        "drift_version",
        "last_scan_at",
        "health_score",
        "detected_languages",
        "detected_frameworks",
    ];

    for key in &keys {
        let value: Option<String> = conn
            .query_row(
                "SELECT value FROM workspace_config WHERE key = ?1",
                [key],
                |row| row.get(0),
            )
            .ok();

        if let Some(val) = value {
            conn.execute(
                "INSERT INTO workspace_context (key, value) VALUES (?1, ?2)",
                rusqlite::params![key, val],
            )?;
        }
    }

    // Store analysis status flags — check if each table exists and has data.
    // These tables may not exist yet (they're created by drift-storage migrations).
    // We use a safe query pattern that returns 0 if the table doesn't exist.
    let analysis_keys = [
        ("call_graph_built", "functions"),
        ("test_topology_built", "test_mappings"),
        ("coupling_built", "coupling_metrics"),
        ("dna_profile_exists", "dna_profiles"),
        ("constants_extracted", "constants"),
        ("constraints_mined", "constraints"),
        ("contracts_detected", "contracts"),
        ("security_scanned", "security_findings"),
    ];

    for (key, table) in &analysis_keys {
        let has_data = table_has_data(conn, table);
        conn.execute(
            "INSERT INTO workspace_context (key, value) VALUES (?1, ?2)",
            rusqlite::params![key, if has_data { "true" } else { "false" }],
        )?;
    }

    Ok(())
}

/// Read workspace context from the materialized table.
pub fn get_workspace_context(conn: &Connection) -> WorkspaceResult<WorkspaceContext> {
    let mut stmt = conn.prepare_cached("SELECT key, value FROM workspace_context")?;
    let rows: Vec<(String, String)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;

    let get = |key: &str| -> String {
        rows.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };

    let get_bool = |key: &str| -> bool { get(key) == "true" };

    let languages: Vec<String> =
        serde_json::from_str(&get("detected_languages")).unwrap_or_default();
    let frameworks: Vec<String> =
        serde_json::from_str(&get("detected_frameworks")).unwrap_or_default();

    Ok(WorkspaceContext {
        project: ProjectContext {
            name: get("project_name"),
            root_path: get("root_path"),
            schema_version: get("schema_version"),
            drift_version: get("drift_version"),
            last_scan_at: {
                let v = get("last_scan_at");
                if v.is_empty() { None } else { Some(v) }
            },
            health_score: {
                let v = get("health_score");
                if v.is_empty() { None } else { Some(v) }
            },
            languages,
            frameworks,
        },
        analysis: AnalysisStatus {
            call_graph_built: get_bool("call_graph_built"),
            test_topology_built: get_bool("test_topology_built"),
            coupling_built: get_bool("coupling_built"),
            dna_profile_exists: get_bool("dna_profile_exists"),
            constants_extracted: get_bool("constants_extracted"),
            constraints_mined: get_bool("constraints_mined"),
            contracts_detected: get_bool("contracts_detected"),
            security_scanned: get_bool("security_scanned"),
        },
        loaded_at: now_iso(),
    })
}

/// Get agent-friendly context for MCP tools.
pub fn get_agent_context(conn: &Connection) -> WorkspaceResult<AgentProjectContext> {
    let ctx = get_workspace_context(conn)?;

    let mut warnings = Vec::new();
    if ctx.project.last_scan_at.is_none() {
        warnings.push("No scan has been run yet. Run `drift scan` first.".to_string());
    }

    Ok(AgentProjectContext {
        summary: format!("Project '{}' at {}", ctx.project.name, ctx.project.root_path),
        available_commands: vec![
            "drift scan".to_string(),
            "drift patterns".to_string(),
            "drift call-graph".to_string(),
            "drift boundaries".to_string(),
            "drift gates".to_string(),
            "drift status".to_string(),
        ],
        warnings,
        readiness: Readiness {
            scanned: ctx.project.last_scan_at.is_some(),
            call_graph_built: ctx.analysis.call_graph_built,
            memory_initialized: false,
        },
    })
}

/// Safely check if a table exists and has data.
/// Table name is validated to prevent SQL injection (only alphanumeric + underscore allowed).
fn table_has_data(conn: &Connection, table: &str) -> bool {
    if !table.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return false;
    }
    conn.query_row(
        &format!("SELECT COUNT(*) > 0 FROM {}", table),
        [],
        |row| row.get::<_, bool>(0),
    )
    .unwrap_or(false)
}

fn now_iso() -> String {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", duration.as_secs())
}
