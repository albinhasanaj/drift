//! Module boundary detection and import graph construction.

use drift_core::types::collections::{FxHashMap, FxHashSet};

use super::types::ImportGraph;

/// Builds an import graph from file-level import data.
///
/// Groups files into modules (by top-level directory) and constructs
/// directed edges representing inter-module dependencies.
pub struct ImportGraphBuilder {
    /// File → list of imported file paths.
    file_imports: FxHashMap<String, Vec<String>>,
    /// File → number of abstract types (interfaces, abstract classes, traits).
    file_abstract_counts: FxHashMap<String, u32>,
    /// File → total type count.
    file_type_counts: FxHashMap<String, u32>,
    /// Module depth: how many path segments define a module boundary.
    module_depth: usize,
}

impl ImportGraphBuilder {
    /// Create a new builder with the given module depth.
    /// `module_depth = 1` means top-level directories are modules.
    pub fn new(module_depth: usize) -> Self {
        Self {
            file_imports: FxHashMap::default(),
            file_abstract_counts: FxHashMap::default(),
            file_type_counts: FxHashMap::default(),
            module_depth: module_depth.max(1),
        }
    }

    /// Add a file and its imports.
    pub fn add_file(&mut self, file: &str, imports: &[String]) {
        self.file_imports.insert(file.to_string(), imports.to_vec());
    }

    /// Set abstract/total type counts for a file.
    pub fn set_type_counts(&mut self, file: &str, abstract_count: u32, total_count: u32) {
        self.file_abstract_counts.insert(file.to_string(), abstract_count);
        self.file_type_counts.insert(file.to_string(), total_count);
    }

    /// Build the import graph.
    pub fn build(&self) -> ImportGraph {
        let mut module_set: FxHashSet<String> = FxHashSet::default();
        let mut edges: FxHashMap<String, FxHashSet<String>> = FxHashMap::default();
        let mut abstract_counts: FxHashMap<String, u32> = FxHashMap::default();
        let mut total_type_counts: FxHashMap<String, u32> = FxHashMap::default();

        // Collect all modules
        for file in self.file_imports.keys() {
            let module = self.file_to_module(file);
            module_set.insert(module);
        }

        // Build edges and aggregate type counts
        for (file, imports) in &self.file_imports {
            let src_module = self.file_to_module(file);

            // Aggregate type counts
            if let Some(&ac) = self.file_abstract_counts.get(file) {
                *abstract_counts.entry(src_module.clone()).or_default() += ac;
            }
            if let Some(&tc) = self.file_type_counts.get(file) {
                *total_type_counts.entry(src_module.clone()).or_default() += tc;
            }

            for import in imports {
                let dst_module = self.file_to_module(import);
                if src_module != dst_module {
                    edges.entry(src_module.clone()).or_default().insert(dst_module.clone());
                    module_set.insert(dst_module);
                }
            }
        }

        let modules: Vec<String> = module_set.into_iter().collect();
        let edge_map: FxHashMap<String, Vec<String>> = edges
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().collect()))
            .collect();

        ImportGraph {
            edges: edge_map,
            modules,
            abstract_counts,
            total_type_counts,
        }
    }

    /// Extract module name from a file path based on module_depth.
    ///
    /// Handles absolute paths by stripping the common prefix shared by all
    /// files in the graph, so that module grouping operates on the relative
    /// project-internal path segments rather than the OS-level prefix
    /// (e.g. `/Users/name/project/`).
    fn file_to_module(&self, file: &str) -> String {
        let normalized = file.replace('\\', "/");
        // Strip the common prefix so absolute paths don't collapse into one module.
        let relative = self.strip_common_prefix(&normalized);
        let parts: Vec<&str> = relative.split('/').filter(|s| !s.is_empty() && *s != ".").collect();
        if parts.len() <= self.module_depth {
            parts.join("/")
        } else {
            parts[..self.module_depth].join("/")
        }
    }

    /// Compute and cache the longest common directory prefix across all file paths.
    /// This strips the absolute project root so module grouping works on relative paths.
    fn strip_common_prefix<'a>(&self, path: &'a str) -> &'a str {
        // Fast path: if the path doesn't start with '/', it's already relative.
        if !path.starts_with('/') {
            return path;
        }
        // Find the common prefix from all registered file paths.
        // We compute it lazily from the first two files.
        let prefix = self.compute_common_prefix();
        path.strip_prefix(&prefix).unwrap_or(path)
    }

    /// Compute the longest common directory prefix of all file paths in the builder.
    fn compute_common_prefix(&self) -> String {
        let mut iter = self.file_imports.keys();
        let first = match iter.next() {
            Some(f) => f.replace('\\', "/"),
            None => return String::new(),
        };
        // Start with the directory of the first file
        let mut prefix = match first.rfind('/') {
            Some(pos) => first[..=pos].to_string(),
            None => return String::new(),
        };
        for file in iter {
            let normalized = file.replace('\\', "/");
            // Shrink prefix to match this file
            while !normalized.starts_with(&prefix) && !prefix.is_empty() {
                // Remove last path segment from prefix
                let trimmed = prefix.trim_end_matches('/');
                match trimmed.rfind('/') {
                    Some(pos) => prefix = trimmed[..=pos].to_string(),
                    None => { prefix.clear(); break; }
                }
            }
            if prefix.is_empty() {
                break;
            }
        }
        prefix
    }

    /// CG-COUP-01/02: Build from parse results using resolved import paths
    /// and populating abstract/total type counts from class info.
    pub fn from_parse_results(
        parse_results: &[crate::parsers::types::ParseResult],
        module_depth: usize,
    ) -> ImportGraph {
        let mut builder = Self::new(module_depth);

        for pr in parse_results {
            // CG-COUP-01: Use resolved import source paths, not raw text
            // Skip unresolvable imports (Rust module paths, bare packages)
            let resolved_imports: Vec<String> = pr.imports.iter()
                .filter_map(|imp| normalize_import_source(&imp.source, &pr.file))
                .collect();
            builder.add_file(&pr.file, &resolved_imports);

            // CG-COUP-02: Compute abstract and total type counts from classes
            let mut abstract_count = 0u32;
            let total_count = pr.classes.len() as u32;
            for class in &pr.classes {
                if class.is_abstract
                    || matches!(class.class_kind, crate::parsers::types::ClassKind::Interface)
                    || matches!(class.class_kind, crate::parsers::types::ClassKind::Trait)
                {
                    abstract_count += 1;
                }
            }
            if total_count > 0 {
                builder.set_type_counts(&pr.file, abstract_count, total_count);
            }
        }

        builder.build()
    }
}

/// Normalize an import source path to a file-system-like path.
/// Strips relative prefixes and adds extension if missing.
/// Returns None for imports that can't be resolved to file paths
/// (e.g., Rust module paths like `crate::models`, package imports).
fn normalize_import_source(source: &str, importer_file: &str) -> Option<String> {
    let mut path = source.to_string();

    // Skip Rust module paths (contain ::) — these are not file paths
    // and can't be resolved without full module resolution.
    if path.contains("::") {
        return None;
    }

    // Skip bare package imports (no path separator, no relative prefix)
    // e.g., "commander", "lodash", "serde" — these are external dependencies
    if !path.contains('/') && !path.starts_with("./") && !path.starts_with("../") && !path.starts_with('@') {
        return None;
    }

    // If it's a relative path, resolve relative to importer
    if path.starts_with("./") || path.starts_with("../") {
        // Get importer directory
        let importer_dir = if let Some(pos) = importer_file.rfind('/') {
            &importer_file[..pos]
        } else {
            ""
        };

        // Strip ./
        while path.starts_with("./") {
            path = path[2..].to_string();
        }

        // Handle ../ by going up directories
        while path.starts_with("../") {
            path = path[3..].to_string();
        }

        // Prepend importer directory for relative paths
        if !importer_dir.is_empty() {
            path = format!("{}/{}", importer_dir, path);
        }
    }

    // Add .ts extension if no extension present (for module resolution)
    if !path.contains('.') || path.starts_with('@') {
        // Package imports (e.g., @nestjs/common) stay as-is
        // Extensionless local imports get a .ts suffix for matching
        if !path.starts_with('@') && !path.contains("node_modules") {
            path = format!("{}.ts", path);
        }
    }

    Some(path)
}

impl Default for ImportGraphBuilder {
    fn default() -> Self {
        Self::new(1)
    }
}
