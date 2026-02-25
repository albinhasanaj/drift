//! Storage trait module — re-exports all drift storage traits.
//!
//! These traits define the contract between drift business logic and
//! the underlying storage backend. The SQLite implementation lives in
//! `drift-storage`; a future Postgres implementation will live in a
//! cloud crate. All traits are object-safe, `Send + Sync`, and have
//! blanket `Arc<T>` impls.

pub mod drift_files;
pub mod drift_analysis;
pub mod drift_structural;
pub mod drift_enforcement;
pub mod drift_advanced;
pub mod drift_batch;
pub mod drift_reader;
pub mod workspace;
pub mod workspace_types;
pub mod test_helpers;

pub use drift_files::IDriftFiles;
pub use drift_analysis::IDriftAnalysis;
pub use drift_structural::IDriftStructural;
pub use drift_enforcement::IDriftEnforcement;
pub use drift_advanced::IDriftAdvanced;
pub use drift_batch::IDriftBatchWriter;
pub use drift_reader::IDriftReader;
pub use workspace::IWorkspaceStorage;
pub use workspace_types::*;
