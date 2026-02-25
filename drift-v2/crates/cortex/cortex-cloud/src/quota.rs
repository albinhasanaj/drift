//! Cloud quota management: memory count limits, storage size limits,
//! sync frequency limits, and graceful handling when limits are approached.

use cortex_core::errors::{CloudError, CortexResult};
use serde::{Deserialize, Serialize};

/// Quota limits for a cloud account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaLimits {
    /// Maximum number of memories allowed.
    pub max_memories: u64,
    /// Maximum total storage in bytes.
    pub max_storage_bytes: u64,
    /// Minimum interval between syncs in seconds.
    pub min_sync_interval_secs: u64,
}

impl Default for QuotaLimits {
    fn default() -> Self {
        Self {
            max_memories: 100_000,
            max_storage_bytes: 1_073_741_824, // 1 GB
            min_sync_interval_secs: 60,
        }
    }
}

/// Current usage against quota limits.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuotaUsage {
    /// Current number of memories.
    pub memory_count: u64,
    /// Current storage usage in bytes.
    pub storage_bytes: u64,
    /// Seconds since last sync.
    pub secs_since_last_sync: u64,
}

/// Quota enforcement result.
#[derive(Debug, Clone)]
pub enum QuotaCheck {
    /// Within limits, proceed.
    Ok,
    /// Approaching limits (>80% usage). Proceed but warn.
    Warning { resource: String, percent: f64 },
    /// Exceeded limits. Block the operation.
    Exceeded {
        resource: String,
        used: u64,
        limit: u64,
    },
}

/// Manages quota enforcement.
#[derive(Debug)]
pub struct QuotaManager {
    limits: QuotaLimits,
    usage: QuotaUsage,
}

impl QuotaManager {
    pub fn new(limits: QuotaLimits) -> Self {
        Self {
            limits,
            usage: QuotaUsage::default(),
        }
    }

    /// Update current usage.
    pub fn update_usage(&mut self, usage: QuotaUsage) {
        self.usage = usage;
    }

    /// Check whether a new memory can be created.
    pub fn check_memory_create(&self) -> QuotaCheck {
        self.check_resource(
            "memories",
            self.usage.memory_count,
            self.limits.max_memories,
        )
    }

    /// Check whether storage is within limits.
    pub fn check_storage(&self) -> QuotaCheck {
        self.check_resource(
            "storage_bytes",
            self.usage.storage_bytes,
            self.limits.max_storage_bytes,
        )
    }

    /// Check whether enough time has passed since the last sync.
    pub fn check_sync_frequency(&self) -> bool {
        self.usage.secs_since_last_sync >= self.limits.min_sync_interval_secs
    }

    /// Enforce quota — returns an error if any limit is exceeded.
    pub fn enforce(&self) -> CortexResult<()> {
        if let QuotaCheck::Exceeded {
            resource,
            used,
            limit,
        } = self.check_memory_create()
        {
            return Err(CloudError::QuotaExceeded {
                resource,
                used,
                limit,
            }
            .into());
        }
        if let QuotaCheck::Exceeded {
            resource,
            used,
            limit,
        } = self.check_storage()
        {
            return Err(CloudError::QuotaExceeded {
                resource,
                used,
                limit,
            }
            .into());
        }
        Ok(())
    }

    /// C-10: Record that a sync just completed — resets the sync interval timer.
    /// Must be called after every successful sync to prevent permanent throttling.
    pub fn record_sync_completed(&mut self) {
        self.usage.secs_since_last_sync = 0;
    }

    /// Get current usage.
    pub fn usage(&self) -> &QuotaUsage {
        &self.usage
    }

    /// Get current limits.
    pub fn limits(&self) -> &QuotaLimits {
        &self.limits
    }

    fn check_resource(&self, name: &str, used: u64, limit: u64) -> QuotaCheck {
        if used >= limit {
            QuotaCheck::Exceeded {
                resource: name.to_string(),
                used,
                limit,
            }
        } else {
            let percent = (used as f64 / limit as f64) * 100.0;
            if percent >= 80.0 {
                QuotaCheck::Warning {
                    resource: name.to_string(),
                    percent,
                }
            } else {
                QuotaCheck::Ok
            }
        }
    }
}

impl Default for QuotaManager {
    fn default() -> Self {
        Self::new(QuotaLimits::default())
    }
}
