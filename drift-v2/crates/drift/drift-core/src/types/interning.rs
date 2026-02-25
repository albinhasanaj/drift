//! String interning for paths and function names.
//!
//! Uses `lasso::ThreadedRodeo` for thread-safe interning during build/scan phase,
//! and `lasso::RodeoReader` for contention-free reads during query phase.

use lasso::{RodeoReader, Spur, ThreadedRodeo};

/// Path interner that normalizes path separators before interning.
///
/// Converts all backslashes to forward slashes, removes trailing slashes,
/// and normalizes `..` segments for consistent cross-platform path handling.
pub struct PathInterner {
    inner: ThreadedRodeo,
}

impl PathInterner {
    /// Create a new path interner.
    pub fn new() -> Self {
        Self {
            inner: ThreadedRodeo::default(),
        }
    }

    /// Intern a path, normalizing separators first.
    pub fn intern(&self, path: &str) -> Spur {
        let normalized = Self::normalize(path);
        self.inner.get_or_intern(&normalized)
    }

    /// Look up a previously interned path without inserting.
    pub fn get(&self, path: &str) -> Option<Spur> {
        let normalized = Self::normalize(path);
        self.inner.get(&normalized)
    }

    /// Resolve a `Spur` back to its string.
    pub fn resolve(&self, key: &Spur) -> &str {
        self.inner.resolve(key)
    }

    /// Freeze the interner into a read-only `RodeoReader`.
    pub fn into_reader(self) -> RodeoReader {
        self.inner.into_reader()
    }

    /// Normalize a path: convert backslashes to forward slashes,
    /// remove trailing slashes, collapse `//` to `/`.
    fn normalize(path: &str) -> String {
        let mut result = path.replace('\\', "/");
        // Collapse double slashes
        while result.contains("//") {
            result = result.replace("//", "/");
        }
        // Remove trailing slash (unless it's the root "/")
        if result.len() > 1 && result.ends_with('/') {
            result.pop();
        }
        result
    }
}

impl Default for PathInterner {
    fn default() -> Self {
        Self::new()
    }
}

/// Function interner that supports qualified name interning (`Class.method`).
pub struct FunctionInterner {
    inner: ThreadedRodeo,
}

impl FunctionInterner {
    /// Create a new function interner.
    pub fn new() -> Self {
        Self {
            inner: ThreadedRodeo::default(),
        }
    }

    /// Intern a simple function name.
    pub fn intern(&self, name: &str) -> Spur {
        self.inner.get_or_intern(name)
    }

    /// Intern a qualified name (`Class.method`).
    pub fn intern_qualified(&self, class: &str, method: &str) -> Spur {
        let qualified = format!("{}.{}", class, method);
        self.inner.get_or_intern(&qualified)
    }

    /// Look up a previously interned name without inserting.
    pub fn get(&self, name: &str) -> Option<Spur> {
        self.inner.get(name)
    }

    /// Resolve a `Spur` back to its string.
    pub fn resolve(&self, key: &Spur) -> &str {
        self.inner.resolve(key)
    }

    /// Freeze the interner into a read-only `RodeoReader`.
    pub fn into_reader(self) -> RodeoReader {
        self.inner.into_reader()
    }
}

impl Default for FunctionInterner {
    fn default() -> Self {
        Self::new()
    }
}
