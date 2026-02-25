//! # cortex-cloud
//!
//! Cloud sync engine with push/pull, conflict resolution (last-write-wins, local-wins,
//! remote-wins, manual), OAuth/API key auth, offline mode with mutation queuing, and
//! quota enforcement.
//!
//! Feature-gated behind the `cloud` feature flag. Local SQLite is always the source
//! of truth — cloud is optional push/pull. Offline-first design.

pub mod auth;
pub mod conflict;
pub mod engine;
pub mod quota;
pub mod sync;
pub mod transport;

pub use auth::{AuthManager, AuthState};
pub use conflict::ConflictResolver;
pub use engine::{CloudEngine, CloudStatus, SyncResult, SyncResultStatus};
pub use quota::{QuotaCheck, QuotaLimits, QuotaManager, QuotaUsage};
pub use sync::{SyncDelta, SyncManager};
pub use transport::{HttpClient, HttpClientConfig};
