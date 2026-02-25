//! Workspace initialization — creates .drift/, drift.db, drift.toml.
//! This is the entry point for every new workspace.

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use tracing::info;

use super::detect::{detect_frameworks, detect_languages, generate_config_template};
use super::errors::{WorkspaceError, WorkspaceResult};
use super::migration::{get_schema_version, initialize_workspace_db};
use super::monorepo::{detect_workspace, register_packages, WorkspaceLayout};
use super::project::generate_project_id;

/// Workspace initialization options.
#[derive(Debug, Clone, Default)]
pub struct InitOptions {
    /// Project root path. Defaults to current directory.
    pub root: Option<PathBuf>,
    /// Custom drift directory name. Defaults to ".drift".
    pub drift_dir: Option<String>,
    /// Configuration template name. Defaults to "default".
    pub template: Option<String>,
    /// Force re-initialization even if .drift/ exists.
    pub force: bool,
}

/// Result of workspace initialization.
#[derive(Debug)]
pub struct WorkspaceInfo {
    pub root_path: PathBuf,
    pub drift_path: PathBuf,
    pub schema_version: u32,
    pub is_new: bool,
    pub languages: Vec<String>,
    pub frameworks: Vec<String>,
}

/// Initialize a Drift workspace.
/// Creates .drift/ directory, drift.db, drift.toml, runs migrations.
pub fn workspace_init(opts: InitOptions) -> WorkspaceResult<WorkspaceInfo> {
    let root = opts
        .root
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let drift_dir = opts.drift_dir.unwrap_or_else(|| ".drift".to_string());
    let drift_path = root.join(&drift_dir);

    // Check if already initialized
    if drift_path.exists() && !opts.force {
        let db_path = drift_path.join("drift.db");
        if db_path.exists() {
            let conn = Connection::open(&db_path)?;
            initialize_workspace_db(&conn)?;
            let schema_version = get_schema_version(&conn)?;

            return Ok(WorkspaceInfo {
                root_path: root,
                drift_path,
                schema_version,
                is_new: false,
                languages: vec![],
                frameworks: vec![],
            });
        }
    }

    // Create .drift/ directory
    std::fs::create_dir_all(&drift_path)?;

    // Create .drift-backups/ directory
    let backup_dir = root.join(".drift-backups");
    std::fs::create_dir_all(&backup_dir)?;

    // Initialize drift.db with PRAGMAs and workspace tables
    let db_path = drift_path.join("drift.db");
    let conn = Connection::open(&db_path)?;
    initialize_workspace_db(&conn)?;

    // Auto-detect languages and frameworks
    let languages = detect_languages(&root);
    let frameworks = detect_frameworks(&root);

    // Store initial workspace config
    let project_name = root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unnamed")
        .to_string();

    let schema_version = get_schema_version(&conn)?;

    conn.execute(
        "INSERT OR REPLACE INTO workspace_config (key, value) VALUES (?1, ?2)",
        rusqlite::params!["project_name", &project_name],
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO workspace_config (key, value) VALUES (?1, ?2)",
        rusqlite::params!["root_path", root.display().to_string()],
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO workspace_config (key, value) VALUES (?1, ?2)",
        rusqlite::params!["drift_version", env!("CARGO_PKG_VERSION")],
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO workspace_config (key, value) VALUES (?1, ?2)",
        rusqlite::params![
            "schema_version",
            schema_version.to_string()
        ],
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO workspace_config (key, value) VALUES (?1, ?2)",
        rusqlite::params![
            "detected_languages",
            serde_json::to_string(&languages).unwrap_or_else(|_| "[]".to_string())
        ],
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO workspace_config (key, value) VALUES (?1, ?2)",
        rusqlite::params![
            "detected_frameworks",
            serde_json::to_string(&frameworks).unwrap_or_else(|_| "[]".to_string())
        ],
    )?;

    // Register project in registry
    let project_id = generate_project_id();
    conn.execute(
        "INSERT OR IGNORE INTO project_registry (id, name, root_path, drift_path, is_active)
         VALUES (?1, ?2, ?3, ?4, 1)",
        rusqlite::params![
            project_id,
            project_name,
            root.display().to_string(),
            drift_path.display().to_string()
        ],
    )?;

    // Detect monorepo and register packages
    if let Ok(WorkspaceLayout::Monorepo { packages, .. }) = detect_workspace(&root) {
        let _ = register_packages(&conn, &packages);
    }

    // Create default drift.toml if it doesn't exist
    let toml_path = root.join("drift.toml");
    if !toml_path.exists() {
        let template = opts.template.as_deref().unwrap_or("default");
        let toml_content = generate_config_template(template, &project_name);
        std::fs::write(&toml_path, toml_content)?;
    }

    // Log initialization event
    let event_details = serde_json::json!({
        "project_name": project_name,
        "languages": languages,
        "frameworks": frameworks,
    })
    .to_string();
    conn.execute(
        "INSERT INTO workspace_events (event_type, details) VALUES ('workspace_init', ?1)",
        [&event_details],
    )?;

    info!(
        project = project_name,
        languages = ?languages,
        frameworks = ?frameworks,
        "Workspace initialized"
    );

    Ok(WorkspaceInfo {
        root_path: root,
        drift_path,
        schema_version,
        is_new: true,
        languages,
        frameworks,
    })
}

/// Check if a workspace is initialized at the given path.
pub fn is_initialized(root: &Path) -> bool {
    root.join(".drift").join("drift.db").exists()
}

/// Open an existing workspace's drift.db connection.
pub fn open_workspace(root: &Path) -> WorkspaceResult<Connection> {
    let db_path = root.join(".drift").join("drift.db");
    if !db_path.exists() {
        return Err(WorkspaceError::NotInitialized);
    }
    let conn = Connection::open(&db_path)?;
    initialize_workspace_db(&conn)?;
    Ok(conn)
}
