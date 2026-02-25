//! Single-pass visitor pattern (AD4) — the most important architectural decision in Phase 2.
//!
//! The engine walks the AST once per file, dispatching `on_enter`/`on_exit` to all
//! registered handlers per node type. Detectors MUST implement a visitor trait.


use drift_core::types::collections::FxHashMap;
use tree_sitter::Node;

use crate::parsers::types::{
    CallSite, ClassInfo, ExportInfo, FunctionInfo, ImportInfo, ParseResult,
};
use crate::scanner::language_detect::Language;

use super::types::PatternMatch;

/// Context passed to every detector handler during AST traversal.
#[derive(Debug)]
pub struct DetectionContext<'a> {
    pub file: &'a str,
    pub language: Language,
    pub source: &'a [u8],
    pub imports: &'a [ImportInfo],
    pub exports: &'a [ExportInfo],
    pub functions: &'a [FunctionInfo],
    pub classes: &'a [ClassInfo],
    pub call_sites: &'a [CallSite],
    pub parse_result: &'a ParseResult,
}

impl<'a> DetectionContext<'a> {
    /// Create a detection context from a ParseResult.
    pub fn from_parse_result(parse_result: &'a ParseResult, source: &'a [u8]) -> Self {
        Self {
            file: &parse_result.file,
            language: parse_result.language,
            source,
            imports: &parse_result.imports,
            exports: &parse_result.exports,
            functions: &parse_result.functions,
            classes: &parse_result.classes,
            call_sites: &parse_result.call_sites,
            parse_result,
        }
    }
}

/// Trait for AST-visitor-based detectors (AD4).
///
/// Detectors implement this to participate in the single-pass AST traversal.
/// The engine dispatches `on_enter`/`on_exit` only for node types the detector
/// declares interest in via `node_types()`.
pub trait DetectorHandler: Send + Sync {
    /// Unique identifier for this handler.
    fn id(&self) -> &str;

    /// Tree-sitter node types this handler wants to visit.
    /// Return an empty slice to visit all nodes.
    fn node_types(&self) -> &[&str];

    /// Languages this handler supports.
    fn languages(&self) -> &[Language];

    /// Called when entering a node during depth-first traversal.
    fn on_enter(&mut self, node: &Node, source: &[u8], ctx: &DetectionContext);

    /// Called when exiting a node during depth-first traversal.
    fn on_exit(&mut self, node: &Node, source: &[u8], ctx: &DetectionContext);

    /// Collect results after traversal completes.
    fn results(&self) -> Vec<PatternMatch>;

    /// Reset state for reuse on the next file.
    fn reset(&mut self);
}

/// Trait for detectors that need full-file context (not just per-node).
pub trait FileDetectorHandler: Send + Sync {
    /// Unique identifier.
    fn id(&self) -> &str;

    /// Languages this handler supports.
    fn languages(&self) -> &[Language];

    /// Analyze the full file after AST traversal.
    fn analyze_file(&mut self, ctx: &DetectionContext);

    /// Collect results.
    fn results(&self) -> Vec<PatternMatch>;

    /// Reset state.
    fn reset(&mut self);
}

/// Trait for two-pass learning detectors: learn conventions, then detect deviations.
pub trait LearningDetectorHandler: Send + Sync {
    /// Unique identifier.
    fn id(&self) -> &str;

    /// Languages this handler supports.
    fn languages(&self) -> &[Language];

    /// Learning pass: accumulate convention data from a file.
    fn learn(&mut self, ctx: &DetectionContext);

    /// Detection pass: find deviations from learned conventions.
    fn detect(&mut self, ctx: &DetectionContext);

    /// Collect results from the detection pass.
    fn results(&self) -> Vec<PatternMatch>;

    /// Reset state.
    fn reset(&mut self);
}

/// Registry of all detector handlers, indexed by node type for O(1) dispatch.
pub struct VisitorRegistry {
    /// AST visitor handlers.
    handlers: Vec<Box<dyn DetectorHandler>>,
    /// Map from node type → indices into `handlers`.
    node_handlers: FxHashMap<String, Vec<usize>>,
    /// Handlers that want all node types.
    wildcard_handlers: Vec<usize>,
    /// File-level handlers.
    file_handlers: Vec<Box<dyn FileDetectorHandler>>,
    /// Learning handlers.
    learning_handlers: Vec<Box<dyn LearningDetectorHandler>>,
}

impl VisitorRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
            node_handlers: FxHashMap::default(),
            wildcard_handlers: Vec::new(),
            file_handlers: Vec::new(),
            learning_handlers: Vec::new(),
        }
    }

    /// Register an AST visitor handler.
    pub fn register(&mut self, handler: Box<dyn DetectorHandler>) {
        let idx = self.handlers.len();
        let node_types = handler.node_types();
        if node_types.is_empty() {
            self.wildcard_handlers.push(idx);
        } else {
            for nt in node_types {
                self.node_handlers
                    .entry(nt.to_string())
                    .or_default()
                    .push(idx);
            }
        }
        self.handlers.push(handler);
    }

    /// Register a file-level handler.
    pub fn register_file_handler(&mut self, handler: Box<dyn FileDetectorHandler>) {
        self.file_handlers.push(handler);
    }

    /// Register a learning handler.
    pub fn register_learning_handler(&mut self, handler: Box<dyn LearningDetectorHandler>) {
        self.learning_handlers.push(handler);
    }

    /// Number of registered AST handlers.
    pub fn handler_count(&self) -> usize {
        self.handlers.len()
    }

    /// Number of registered file handlers.
    pub fn file_handler_count(&self) -> usize {
        self.file_handlers.len()
    }

    /// Number of registered learning handlers.
    pub fn learning_handler_count(&self) -> usize {
        self.learning_handlers.len()
    }
}

impl Default for VisitorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// The single-pass detection engine.
///
/// Walks the AST depth-first, dispatching to registered handlers per node type.
/// Each AST node is visited exactly once.
pub struct DetectionEngine {
    registry: VisitorRegistry,
}

impl DetectionEngine {
    /// Create a new detection engine with the given registry.
    pub fn new(registry: VisitorRegistry) -> Self {
        Self { registry }
    }

    /// Run single-pass AST traversal on a parsed file.
    ///
    /// Returns all pattern matches from all handlers.
    pub fn run(
        &mut self,
        tree: &tree_sitter::Tree,
        source: &[u8],
        ctx: &DetectionContext,
    ) -> Vec<PatternMatch> {
        // Reset all handlers for this file
        for handler in &mut self.registry.handlers {
            handler.reset();
        }
        for handler in &mut self.registry.file_handlers {
            handler.reset();
        }

        // Single-pass depth-first traversal
        let root = tree.root_node();
        self.visit_node(&root, source, ctx);

        // Run file-level handlers
        for handler in &mut self.registry.file_handlers {
            if handler.languages().contains(&ctx.language) || handler.languages().is_empty() {
                handler.analyze_file(ctx);
            }
        }

        // Collect all results
        let mut matches = Vec::new();
        for handler in &self.registry.handlers {
            matches.extend(handler.results());
        }
        for handler in &self.registry.file_handlers {
            matches.extend(handler.results());
        }
        matches
    }

    /// Run the learning pass across all files, then the detection pass.
    pub fn run_learning_pass(&mut self, contexts: &[DetectionContext]) -> Vec<PatternMatch> {
        // Learning pass
        for handler in &mut self.registry.learning_handlers {
            handler.reset();
            for ctx in contexts {
                if handler.languages().contains(&ctx.language) || handler.languages().is_empty() {
                    handler.learn(ctx);
                }
            }
        }

        // Detection pass
        let mut matches = Vec::new();
        for handler in &mut self.registry.learning_handlers {
            for ctx in contexts {
                if handler.languages().contains(&ctx.language) || handler.languages().is_empty() {
                    handler.detect(ctx);
                }
            }
            matches.extend(handler.results());
        }
        matches
    }

    /// Depth-first traversal dispatching to handlers.
    fn visit_node(&mut self, node: &Node, source: &[u8], ctx: &DetectionContext) {
        let kind = node.kind();

        // Dispatch on_enter to matching handlers
        self.dispatch_enter(kind, node, source, ctx);

        // Recurse into children
        let child_count = node.child_count();
        for i in 0..child_count {
            if let Some(child) = node.child(i) {
                self.visit_node(&child, source, ctx);
            }
        }

        // Dispatch on_exit to matching handlers
        self.dispatch_exit(kind, node, source, ctx);
    }

    fn dispatch_enter(&mut self, kind: &str, node: &Node, source: &[u8], ctx: &DetectionContext) {
        // Wildcard handlers
        for &idx in &self.registry.wildcard_handlers {
            let handler = &mut self.registry.handlers[idx];
            if handler.languages().contains(&ctx.language) || handler.languages().is_empty() {
                handler.on_enter(node, source, ctx);
            }
        }

        // Type-specific handlers
        if let Some(indices) = self.registry.node_handlers.get(kind) {
            for &idx in indices {
                let handler = &mut self.registry.handlers[idx];
                if handler.languages().contains(&ctx.language) || handler.languages().is_empty() {
                    handler.on_enter(node, source, ctx);
                }
            }
        }
    }

    fn dispatch_exit(&mut self, kind: &str, node: &Node, source: &[u8], ctx: &DetectionContext) {
        // Wildcard handlers
        for &idx in &self.registry.wildcard_handlers {
            let handler = &mut self.registry.handlers[idx];
            if handler.languages().contains(&ctx.language) || handler.languages().is_empty() {
                handler.on_exit(node, source, ctx);
            }
        }

        // Type-specific handlers
        if let Some(indices) = self.registry.node_handlers.get(kind) {
            for &idx in indices {
                let handler = &mut self.registry.handlers[idx];
                if handler.languages().contains(&ctx.language) || handler.languages().is_empty() {
                    handler.on_exit(node, source, ctx);
                }
            }
        }
    }

    /// Get a reference to the registry.
    pub fn registry(&self) -> &VisitorRegistry {
        &self.registry
    }

    /// Get a mutable reference to the registry.
    pub fn registry_mut(&mut self) -> &mut VisitorRegistry {
        &mut self.registry
    }
}
