//! BridgeHealth: per-subsystem availability tracking.

use std::fmt;

/// Overall bridge health status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeHealth {
    /// All subsystems operational.
    Available,
    /// Some subsystems degraded — bridge functional but limited.
    Degraded(Vec<String>),
    /// Bridge entirely unavailable.
    Unavailable,
}

impl BridgeHealth {
    /// Whether the bridge can serve any requests.
    pub fn is_operational(&self) -> bool {
        !matches!(self, Self::Unavailable)
    }

    /// Whether the bridge is fully healthy.
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Available)
    }

    /// Get degradation reasons (empty if Available or Unavailable).
    pub fn degradation_reasons(&self) -> &[String] {
        match self {
            Self::Degraded(reasons) => reasons,
            _ => &[],
        }
    }
}

impl fmt::Display for BridgeHealth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Available => write!(f, "Available"),
            Self::Degraded(reasons) => write!(f, "Degraded: {}", reasons.join(", ")),
            Self::Unavailable => write!(f, "Unavailable"),
        }
    }
}
