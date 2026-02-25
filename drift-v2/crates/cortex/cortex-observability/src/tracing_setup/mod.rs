//! Tracing setup — structured logging with span definitions and event types.

pub mod events;
pub mod spans;

use tracing_subscriber::EnvFilter;

/// Initialize the tracing subscriber with structured JSON output.
///
/// Respects the `CORTEX_LOG` environment variable for filtering.
/// Defaults to `info` level if not set.
pub fn init_tracing() {
    let filter = EnvFilter::try_from_env("CORTEX_LOG").unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .json()
        .init();
}

/// Initialize tracing with a custom filter string (for testing or embedding).
pub fn init_tracing_with_filter(filter: &str) {
    let filter = EnvFilter::new(filter);

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .json()
        .init();
}
