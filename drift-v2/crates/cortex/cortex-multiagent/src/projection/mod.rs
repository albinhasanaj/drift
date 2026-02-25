//! Memory projections — filtered, compressed views between namespaces.

pub mod backpressure;
pub mod compression;
pub mod engine;
pub mod subscription;

pub use engine::ProjectionEngine;
