//! Impact analysis — blast radius, dead code detection, path finding.

pub mod types;
pub mod blast_radius;
pub mod dead_code;
pub mod path_finding;

pub use types::*;
pub use blast_radius::{compute_blast_radius, compute_all_blast_radii};
pub use dead_code::{detect_dead_code, detect_dead_code_with_resolution_rate, detect_unreachable};
pub use path_finding::{shortest_path, k_shortest_paths};
