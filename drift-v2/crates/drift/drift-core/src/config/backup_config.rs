//! Backup configuration.

use serde::{Deserialize, Serialize};

/// Configuration for the backup subsystem.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct BackupConfig {
    /// Maximum operational backups. Default: 5.
    pub max_operational: Option<u32>,
    /// Maximum daily backups. Default: 7.
    pub max_daily: Option<u32>,
    /// Backup interval in seconds.
    pub backup_interval: Option<u64>,
    /// Maximum total backups to retain.
    pub max_backups: Option<u32>,
    /// Custom backup path.
    pub backup_path: Option<String>,
}

impl BackupConfig {
    /// Returns the effective max operational backups, defaulting to 5.
    pub fn effective_max_operational(&self) -> u32 {
        self.max_operational.unwrap_or(5)
    }

    /// Returns the effective max daily backups, defaulting to 7.
    pub fn effective_max_daily(&self) -> u32 {
        self.max_daily.unwrap_or(7)
    }
}
