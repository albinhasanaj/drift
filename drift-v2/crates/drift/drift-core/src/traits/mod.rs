//! Shared traits used across Drift crates.

pub mod cancellation;
pub mod decomposition;
pub mod storage;
pub mod weight_provider;

pub use cancellation::CancellationToken;
pub use decomposition::{DecompositionPriorProvider, NoOpPriorProvider};
pub use storage::{
    IDriftAdvanced, IDriftAnalysis, IDriftBatchWriter, IDriftEnforcement, IDriftFiles,
    IDriftReader, IDriftStructural, IWorkspaceStorage,
};
pub use weight_provider::{
    AdaptiveWeightTable, MigrationPath, StaticWeightProvider, WeightProvider,
};
