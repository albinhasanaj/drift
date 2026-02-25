//! 6 trigger types for grounding loop scheduling.

use std::sync::atomic::{AtomicU32, Ordering};

/// The 6 trigger types for grounding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerType {
    /// Post-scan incremental: affected memories only, every scan.
    PostScanIncremental,
    /// Post-scan full: all groundable memories, every Nth scan.
    PostScanFull,
    /// Scheduled: all groundable memories, daily (configurable).
    Scheduled,
    /// On-demand: specified memories, user-triggered via MCP.
    OnDemand,
    /// Memory creation: new memory only, on creation.
    MemoryCreation,
    /// Memory update: updated memory only, on update.
    MemoryUpdate,
}

/// Grounding scheduler: determines when and what to ground.
pub struct GroundingScheduler {
    /// Number of scans since last full grounding.
    scan_count: AtomicU32,
    /// Full grounding every N scans.
    full_grounding_interval: u32,
}

impl GroundingScheduler {
    pub fn new(full_grounding_interval: u32) -> Self {
        Self {
            scan_count: AtomicU32::new(0),
            full_grounding_interval,
        }
    }

    /// Called after each scan. Returns the appropriate trigger type.
    pub fn on_scan_complete(&self) -> TriggerType {
        let count = self.scan_count.fetch_add(1, Ordering::SeqCst) + 1;
        if count.is_multiple_of(self.full_grounding_interval) {
            TriggerType::PostScanFull
        } else {
            TriggerType::PostScanIncremental
        }
    }

    /// Get the current scan count.
    pub fn scan_count(&self) -> u32 {
        self.scan_count.load(Ordering::SeqCst)
    }

    /// Reset the scan counter.
    pub fn reset(&self) {
        self.scan_count.store(0, Ordering::SeqCst);
    }

    /// Check if a trigger type should run a full grounding loop.
    pub fn is_full_grounding(trigger: TriggerType) -> bool {
        matches!(
            trigger,
            TriggerType::PostScanFull | TriggerType::Scheduled | TriggerType::OnDemand
        )
    }
}

impl Default for GroundingScheduler {
    fn default() -> Self {
        Self::new(10)
    }
}
