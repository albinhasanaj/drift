//! Spur-based ID types for type-safe interned identifiers.
//!
//! Each ID type wraps a `lasso::Spur` to prevent cross-type confusion.
//! A `FileId` cannot be accidentally used where a `FunctionId` is expected.

use lasso::Spur;
use serde::{Deserialize, Serialize};

macro_rules! define_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(pub Spur);

        impl $name {
            /// Create a new ID from a `Spur`.
            pub fn new(spur: Spur) -> Self {
                Self(spur)
            }

            /// Get the inner `Spur`.
            pub fn inner(self) -> Spur {
                self.0
            }
        }

        impl From<Spur> for $name {
            fn from(spur: Spur) -> Self {
                Self(spur)
            }
        }

        impl From<$name> for Spur {
            fn from(id: $name) -> Self {
                id.0
            }
        }
    };
}

define_id!(
    /// Interned file path identifier.
    FileId
);

define_id!(
    /// Interned function name identifier.
    FunctionId
);

define_id!(
    /// Pattern identifier.
    PatternId
);

define_id!(
    /// Class name identifier.
    ClassId
);

define_id!(
    /// Module name identifier.
    ModuleId
);

define_id!(
    /// Detector identifier.
    DetectorId
);
