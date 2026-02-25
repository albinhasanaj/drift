//! Tracing initialization and configuration.

use std::sync::Once;

use tracing_subscriber::{fmt, prelude::*, EnvFilter};

static INIT: Once = Once::new();

/// Initialize the Drift tracing/logging system.
///
/// Reads `DRIFT_LOG` environment variable for per-subsystem log levels.
/// Format: `DRIFT_LOG=scanner=debug,parser=info,storage=warn`
///
/// Falls back to `drift=info` if `DRIFT_LOG` is not set or is invalid.
///
/// This function is idempotent — calling it multiple times is safe.
pub fn init_tracing() {
    INIT.call_once(|| {
        let filter = EnvFilter::try_from_env("DRIFT_LOG")
            .unwrap_or_else(|_| EnvFilter::new("drift=info"));

        tracing_subscriber::registry()
            .with(
                fmt::layer()
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_file(true)
                    .with_line_number(true),
            )
            .with(filter)
            .init();
    });
}
