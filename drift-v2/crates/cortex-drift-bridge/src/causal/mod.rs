//! Causal intelligence bridge: typed edge creation, counterfactual/intervention
//! analysis, pruning, and unified narrative generation.

pub mod counterfactual;
pub mod edge_builder;
pub mod intervention;
pub mod narrative_builder;
pub mod pruning;

pub use counterfactual::{what_if_removed, CounterfactualResult};
pub use edge_builder::{add_correction_edge, add_grounding_edge};
pub use intervention::{what_if_changed, InterventionResult};
pub use narrative_builder::{build_narrative, render_markdown, UnifiedNarrative};
pub use pruning::{prune_weak_edges, PruningReport};
