//! Workspace error types.
//! One error enum covering all workspace operations.

#[derive(Debug, thiserror::Error)]
pub enum WorkspaceError {
    // Initialization
    #[error("Workspace already initialized at {0}")]
    AlreadyInitialized(String),

    #[error("Workspace not initialized. Run `drift init` first.")]
    NotInitialized,

    // Locking
    #[error("Workspace locked: {message} (operation: {operation})")]
    Locked { operation: String, message: String },

    // Migration
    #[error("Migration failed: {message}")]
    MigrationFailed { message: String },

    // Backup
    #[error("Backup not found: {0}")]
    BackupNotFound(String),

    #[error("Backup corrupted: {backup_id} — integrity check: {integrity_result}")]
    BackupCorrupted {
        backup_id: String,
        integrity_result: String,
    },

    #[error("No verified backup available for recovery")]
    NoVerifiedBackup,

    // Project
    #[error("Project not found: {0}")]
    ProjectNotFound(String),

    #[error("Ambiguous project identifier '{identifier}'. Matches: {matches:?}")]
    AmbiguousProject {
        identifier: String,
        matches: Vec<String>,
    },

    // Destructive operations
    #[error("Confirmation required for {operation}. Pass \"DELETE\" as confirmation token.")]
    ConfirmationRequired { operation: String },

    // Export/Import
    #[error("Export corrupted: {0}")]
    ExportCorrupted(String),

    #[error("Import corrupted: {0}")]
    ImportCorrupted(String),

    // Config
    #[error("Configuration error: {0}")]
    ConfigError(String),

    // Storage
    #[error("Storage error: {0}")]
    Storage(#[from] rusqlite::Error),

    // IO
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    // TOML
    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),
}

/// NAPI error code mapping for workspace errors.
impl WorkspaceError {
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::AlreadyInitialized(_) => "ALREADY_INITIALIZED",
            Self::NotInitialized => "NOT_INITIALIZED",
            Self::Locked { .. } => "WORKSPACE_LOCKED",
            Self::MigrationFailed { .. } => "MIGRATION_FAILED",
            Self::BackupNotFound(_) => "BACKUP_NOT_FOUND",
            Self::BackupCorrupted { .. } => "BACKUP_CORRUPTED",
            Self::NoVerifiedBackup => "NO_VERIFIED_BACKUP",
            Self::ProjectNotFound(_) => "PROJECT_NOT_FOUND",
            Self::AmbiguousProject { .. } => "AMBIGUOUS_PROJECT",
            Self::ConfirmationRequired { .. } => "CONFIRMATION_REQUIRED",
            Self::ExportCorrupted(_) => "EXPORT_CORRUPTED",
            Self::ImportCorrupted(_) => "IMPORT_CORRUPTED",
            Self::ConfigError(_) => "CONFIG_ERROR",
            Self::Storage(_) => "STORAGE_ERROR",
            Self::Io(_) => "IO_ERROR",
            Self::TomlParse(_) => "CONFIG_PARSE_ERROR",
        }
    }
}

pub type WorkspaceResult<T> = Result<T, WorkspaceError>;
