//! Constants & Environment (System 22) — secrets, magic numbers, env vars, dead constants.

pub mod types;
pub mod extractor;
pub mod magic_numbers;
pub mod secrets;
pub mod entropy;
pub mod inconsistency;
pub mod dead_constants;
pub mod env_extraction;
pub mod sensitivity;
pub mod health;

pub use types::*;
