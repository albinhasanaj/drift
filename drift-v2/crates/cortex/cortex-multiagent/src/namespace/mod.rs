//! Namespace management — CRUD, permissions, URI addressing.

pub mod addressing;
pub mod manager;
pub mod permissions;

pub use manager::NamespaceManager;
pub use permissions::NamespacePermissionManager;
