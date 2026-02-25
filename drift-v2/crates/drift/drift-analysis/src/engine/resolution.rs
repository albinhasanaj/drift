//! Resolution index — 6 strategies for cross-file symbol resolution (Phase 4 of the pipeline).

use std::collections::BTreeMap;

use drift_core::types::collections::FxHashMap;
use smallvec::SmallVec;

use crate::parsers::types::ParseResult;

/// Resolution strategy with associated confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResolutionStrategy {
    /// Same-file direct call. Confidence: 0.95.
    Direct,
    /// Method call on a known class. Confidence: 0.90.
    Method,
    /// Constructor/new call. Confidence: 0.85.
    Constructor,
    /// Callback/closure parameter. Confidence: 0.75.
    Callback,
    /// Dynamic/reflection-based. Confidence: 0.40-0.60.
    Dynamic,
    /// Cross-module via import/export. Confidence: 0.60-0.75.
    External,
}

impl ResolutionStrategy {
    /// Default confidence for this strategy.
    pub fn default_confidence(&self) -> f32 {
        match self {
            Self::Direct => 0.95,
            Self::Method => 0.90,
            Self::Constructor => 0.85,
            Self::Callback => 0.75,
            Self::Dynamic => 0.50,
            Self::External => 0.68,
        }
    }

    /// All strategies in resolution order (first match wins).
    pub fn all() -> &'static [ResolutionStrategy] {
        &[
            Self::Direct,
            Self::Method,
            Self::Constructor,
            Self::Callback,
            Self::Dynamic,
            Self::External,
        ]
    }
}

impl std::fmt::Display for ResolutionStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct => write!(f, "direct"),
            Self::Method => write!(f, "method"),
            Self::Constructor => write!(f, "constructor"),
            Self::Callback => write!(f, "callback"),
            Self::Dynamic => write!(f, "dynamic"),
            Self::External => write!(f, "external"),
        }
    }
}

/// An entry in the resolution index.
#[derive(Debug, Clone)]
pub struct ResolutionEntry {
    pub name: String,
    pub qualified_name: Option<String>,
    pub file: String,
    pub line: u32,
    pub kind: SymbolKind,
    pub is_exported: bool,
    pub strategies: SmallVec<[ResolutionStrategy; 2]>,
}

/// Kind of symbol in the resolution index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolKind {
    Function,
    Method,
    Class,
    Constructor,
    Variable,
    Import,
    Export,
}

/// The resolution index for cross-file symbol resolution.
///
/// Uses BTreeMap for ordered name lookups, FxHashMap for O(1) by-file lookups,
/// and SmallVec for compact strategy lists.
pub struct ResolutionIndex {
    /// Name → entries (BTreeMap for prefix search).
    name_index: BTreeMap<String, Vec<usize>>,
    /// All entries.
    entries: Vec<ResolutionEntry>,
    /// File → entry indices.
    file_index: FxHashMap<String, Vec<usize>>,
    /// Import source → importing files.
    import_index: FxHashMap<String, Vec<String>>,
    /// Class name → method names.
    class_hierarchy: FxHashMap<String, Vec<String>>,
}

impl ResolutionIndex {
    /// Create a new empty resolution index.
    pub fn new() -> Self {
        Self {
            name_index: BTreeMap::new(),
            entries: Vec::new(),
            file_index: FxHashMap::default(),
            import_index: FxHashMap::default(),
            class_hierarchy: FxHashMap::default(),
        }
    }

    /// Build the resolution index from a set of parse results.
    pub fn build(parse_results: &[ParseResult]) -> Self {
        let mut index = Self::new();

        for result in parse_results {
            index.index_parse_result(result);
        }

        index
    }

    /// Index a single parse result.
    pub fn index_parse_result(&mut self, result: &ParseResult) {
        // Index functions
        for func in &result.functions {
            self.add_entry(ResolutionEntry {
                name: func.name.clone(),
                qualified_name: func.qualified_name.clone(),
                file: result.file.clone(),
                line: func.line,
                kind: SymbolKind::Function,
                is_exported: func.is_exported,
                strategies: SmallVec::from_buf([ResolutionStrategy::Direct, ResolutionStrategy::External]),
            });
        }

        // Index classes and their methods
        for class in &result.classes {
            self.add_entry(ResolutionEntry {
                name: class.name.clone(),
                qualified_name: None,
                file: result.file.clone(),
                line: class.range.start.line,
                kind: SymbolKind::Class,
                is_exported: class.is_exported,
                strategies: SmallVec::from_buf([ResolutionStrategy::Constructor, ResolutionStrategy::External]),
            });

            let mut method_names = Vec::new();
            for method in &class.methods {
                let qualified = format!("{}.{}", class.name, method.name);
                method_names.push(method.name.clone());
                self.add_entry(ResolutionEntry {
                    name: method.name.clone(),
                    qualified_name: Some(qualified),
                    file: result.file.clone(),
                    line: method.line,
                    kind: SymbolKind::Method,
                    is_exported: class.is_exported,
                    strategies: SmallVec::from_buf([ResolutionStrategy::Method, ResolutionStrategy::External]),
                });
            }
            self.class_hierarchy.insert(class.name.clone(), method_names);
        }

        // Index imports
        for import in &result.imports {
            self.import_index
                .entry(import.source.clone())
                .or_default()
                .push(result.file.clone());

            for spec in &import.specifiers {
                self.add_entry(ResolutionEntry {
                    name: spec.alias.as_ref().unwrap_or(&spec.name).clone(),
                    qualified_name: Some(format!("{}::{}", import.source, spec.name)),
                    file: result.file.clone(),
                    line: import.line,
                    kind: SymbolKind::Import,
                    is_exported: false,
                    strategies: SmallVec::from_buf([ResolutionStrategy::External, ResolutionStrategy::Direct]),
                });
            }
        }

        // Index exports
        for export in &result.exports {
            if let Some(ref name) = export.name {
                self.add_entry(ResolutionEntry {
                    name: name.clone(),
                    qualified_name: None,
                    file: result.file.clone(),
                    line: export.line,
                    kind: SymbolKind::Export,
                    is_exported: true,
                    strategies: SmallVec::from_buf([ResolutionStrategy::External, ResolutionStrategy::Direct]),
                });
            }
        }
    }

    fn add_entry(&mut self, entry: ResolutionEntry) {
        let idx = self.entries.len();
        self.name_index
            .entry(entry.name.clone())
            .or_default()
            .push(idx);
        self.file_index
            .entry(entry.file.clone())
            .or_default()
            .push(idx);
        self.entries.push(entry);
    }

    /// Resolve a symbol name using the 6-strategy fallback chain.
    /// Returns the best match with its resolution strategy and confidence.
    pub fn resolve(
        &self,
        name: &str,
        from_file: &str,
    ) -> Option<(&ResolutionEntry, ResolutionStrategy, f32)> {
        let candidates = self.name_index.get(name)?;

        // Strategy 1: Direct — same file
        for &idx in candidates {
            let entry = &self.entries[idx];
            if entry.file == from_file && entry.kind == SymbolKind::Function {
                return Some((entry, ResolutionStrategy::Direct, 0.95));
            }
        }

        // Strategy 2: Method — qualified class.method
        for &idx in candidates {
            let entry = &self.entries[idx];
            if entry.kind == SymbolKind::Method {
                return Some((entry, ResolutionStrategy::Method, 0.90));
            }
        }

        // Strategy 3: Constructor
        for &idx in candidates {
            let entry = &self.entries[idx];
            if entry.kind == SymbolKind::Class {
                return Some((entry, ResolutionStrategy::Constructor, 0.85));
            }
        }

        // Strategy 4: Callback — imported symbol
        for &idx in candidates {
            let entry = &self.entries[idx];
            if entry.kind == SymbolKind::Import && entry.file == from_file {
                return Some((entry, ResolutionStrategy::Callback, 0.75));
            }
        }

        // Strategy 5: External — exported from another file
        for &idx in candidates {
            let entry = &self.entries[idx];
            if entry.is_exported && entry.file != from_file {
                return Some((entry, ResolutionStrategy::External, 0.68));
            }
        }

        // Strategy 6: Dynamic — any match at low confidence
        if let Some(&idx) = candidates.first() {
            let entry = &self.entries[idx];
            return Some((entry, ResolutionStrategy::Dynamic, 0.50));
        }

        None
    }

    /// Get all entries for a file.
    pub fn entries_for_file(&self, file: &str) -> Vec<&ResolutionEntry> {
        self.file_index
            .get(file)
            .map(|indices| indices.iter().map(|&i| &self.entries[i]).collect())
            .unwrap_or_default()
    }

    /// Total number of entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Number of unique names.
    pub fn name_count(&self) -> usize {
        self.name_index.len()
    }

    /// Number of indexed files.
    pub fn file_count(&self) -> usize {
        self.file_index.len()
    }

    /// Get class hierarchy.
    pub fn class_methods(&self, class_name: &str) -> Option<&Vec<String>> {
        self.class_hierarchy.get(class_name)
    }
}

impl Default for ResolutionIndex {
    fn default() -> Self {
        Self::new()
    }
}
