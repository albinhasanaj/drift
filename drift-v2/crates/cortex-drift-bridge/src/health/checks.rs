//! Individual health checks for each bridge subsystem.

/// Result of a single subsystem health check.
#[derive(Debug, Clone)]
pub struct SubsystemCheck {
    /// Subsystem name.
    pub name: &'static str,
    /// Whether the subsystem is healthy.
    pub healthy: bool,
    /// Detail message (reason for unhealthy, or version/status info).
    pub detail: String,
}

impl SubsystemCheck {
    /// Create a healthy check result.
    pub fn ok(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            healthy: true,
            detail: detail.into(),
        }
    }

    /// Create an unhealthy check result.
    pub fn unhealthy(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            healthy: false,
            detail: detail.into(),
        }
    }
}

/// Check cortex.db availability.
pub fn check_cortex_db(conn: Option<&std::sync::Mutex<rusqlite::Connection>>) -> SubsystemCheck {
    match conn {
        Some(mutex) => match mutex.lock() {
            Ok(conn) => {
                match conn.execute_batch("SELECT 1") {
                    Ok(_) => SubsystemCheck::ok("cortex_db", "connected"),
                    Err(e) => SubsystemCheck::unhealthy("cortex_db", format!("query failed: {}", e)),
                }
            }
            Err(e) => SubsystemCheck::unhealthy("cortex_db", format!("lock poisoned: {}", e)),
        },
        None => SubsystemCheck::unhealthy("cortex_db", "not configured"),
    }
}

/// Check drift.db availability.
pub fn check_drift_db(conn: Option<&std::sync::Mutex<rusqlite::Connection>>) -> SubsystemCheck {
    match conn {
        Some(mutex) => match mutex.lock() {
            Ok(conn) => {
                match conn.execute_batch("SELECT 1") {
                    Ok(_) => SubsystemCheck::ok("drift_db", "connected (read-only)"),
                    Err(e) => SubsystemCheck::unhealthy("drift_db", format!("query failed: {}", e)),
                }
            }
            Err(e) => SubsystemCheck::unhealthy("drift_db", format!("lock poisoned: {}", e)),
        },
        None => SubsystemCheck::unhealthy("drift_db", "not configured — grounding unavailable"),
    }
}

/// Check bridge.db availability.
pub fn check_bridge_db(conn: Option<&std::sync::Mutex<rusqlite::Connection>>) -> SubsystemCheck {
    match conn {
        Some(mutex) => match mutex.lock() {
            Ok(conn) => {
                match conn.execute_batch("SELECT 1") {
                    Ok(_) => SubsystemCheck::ok("bridge_db", "connected"),
                    Err(e) => SubsystemCheck::unhealthy("bridge_db", format!("query failed: {}", e)),
                }
            }
            Err(e) => SubsystemCheck::unhealthy("bridge_db", format!("lock poisoned: {}", e)),
        },
        None => SubsystemCheck::unhealthy("bridge_db", "not configured"),
    }
}

/// Check causal engine availability.
pub fn check_causal_engine(engine: Option<&cortex_causal::CausalEngine>) -> SubsystemCheck {
    match engine {
        Some(_) => SubsystemCheck::ok("causal_engine", "available"),
        None => SubsystemCheck::unhealthy("causal_engine", "not configured — causal features unavailable"),
    }
}
