//! Call graph types — nodes, edges, resolution strategies, stats.

use std::time::Duration;

use drift_core::types::collections::FxHashMap;
use petgraph::graph::NodeIndex;
use petgraph::stable_graph::StableGraph;
use petgraph::Directed;
use serde::{Deserialize, Serialize};

/// The call graph: a directed graph of function calls.
pub struct CallGraph {
    /// The underlying petgraph StableGraph.
    pub graph: StableGraph<FunctionNode, CallEdge, Directed>,
    /// Map from (file, function_name) → NodeIndex for O(1) lookup.
    pub node_index: FxHashMap<String, NodeIndex>,
    /// Map from file → list of NodeIndex for file-level operations.
    pub file_nodes: FxHashMap<String, Vec<NodeIndex>>,
}

impl CallGraph {
    /// Create an empty call graph.
    pub fn new() -> Self {
        Self {
            graph: StableGraph::new(),
            node_index: FxHashMap::default(),
            file_nodes: FxHashMap::default(),
        }
    }

    /// Number of functions (nodes) in the graph.
    pub fn function_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Number of call edges in the graph.
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Look up a node by its unique key (file::name).
    pub fn get_node(&self, key: &str) -> Option<NodeIndex> {
        self.node_index.get(key).copied()
    }

    /// Get all nodes for a given file.
    pub fn get_file_nodes(&self, file: &str) -> &[NodeIndex] {
        self.file_nodes.get(file).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Add a function node, returning its NodeIndex.
    pub fn add_function(&mut self, node: FunctionNode) -> NodeIndex {
        let key = format!("{}::{}", node.file, node.name);
        if let Some(&existing) = self.node_index.get(&key) {
            return existing;
        }
        let file = node.file.clone();
        let idx = self.graph.add_node(node);
        self.node_index.insert(key, idx);
        self.file_nodes.entry(file).or_default().push(idx);
        idx
    }

    /// Add a call edge between two functions.
    pub fn add_edge(&mut self, caller: NodeIndex, callee: NodeIndex, edge: CallEdge) {
        self.graph.add_edge(caller, callee, edge);
    }

    /// Remove all nodes and edges for a given file.
    pub fn remove_file(&mut self, file: &str) {
        if let Some(nodes) = self.file_nodes.remove(file) {
            for idx in &nodes {
                if let Some(node) = self.graph.node_weight(*idx) {
                    let key = format!("{}::{}", node.file, node.name);
                    self.node_index.remove(&key);
                }
                self.graph.remove_node(*idx);
            }
        }
    }
}

impl Default for CallGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// A function node in the call graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionNode {
    pub file: String,
    pub name: String,
    pub qualified_name: Option<String>,
    pub language: String,
    pub line: u32,
    pub end_line: u32,
    pub is_entry_point: bool,
    pub is_exported: bool,
    pub signature_hash: u64,
    pub body_hash: u64,
}

/// A call edge in the call graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallEdge {
    pub resolution: Resolution,
    pub confidence: f32,
    pub call_site_line: u32,
}

/// Resolution strategy used to resolve a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Resolution {
    /// Same-file direct call. Confidence: 0.95.
    SameFile,
    /// Method call on a known receiver type. Confidence: 0.90.
    MethodCall,
    /// DI injection resolution. Confidence: 0.80.
    DiInjection,
    /// Import-based resolution. Confidence: 0.75.
    ImportBased,
    /// Export-based cross-module resolution. Confidence: 0.60.
    ExportBased,
    /// Fuzzy name matching (string-based/reflection). Confidence: 0.40.
    Fuzzy,
}

impl Resolution {
    /// Default confidence for this resolution strategy.
    pub fn default_confidence(&self) -> f32 {
        match self {
            Self::SameFile => 0.95,
            Self::MethodCall => 0.90,
            Self::DiInjection => 0.80,
            Self::ImportBased => 0.75,
            Self::ExportBased => 0.60,
            Self::Fuzzy => 0.40,
        }
    }

    /// Name of the resolution strategy.
    pub fn name(&self) -> &'static str {
        match self {
            Self::SameFile => "same_file",
            Self::MethodCall => "method_call",
            Self::DiInjection => "di_injection",
            Self::ImportBased => "import_based",
            Self::ExportBased => "export_based",
            Self::Fuzzy => "fuzzy",
        }
    }

    /// All resolution strategies in fallback order.
    pub fn all_ordered() -> &'static [Resolution] {
        &[
            Self::SameFile,
            Self::MethodCall,
            Self::DiInjection,
            Self::ImportBased,
            Self::ExportBased,
            Self::Fuzzy,
        ]
    }
}

impl std::fmt::Display for Resolution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Statistics from a call graph build.
#[derive(Debug, Clone, Default)]
pub struct CallGraphStats {
    pub total_functions: usize,
    pub total_edges: usize,
    pub entry_points: usize,
    pub resolution_counts: FxHashMap<String, usize>,
    pub resolution_rate: f64,
    pub build_duration: Duration,
    pub cycles_detected: usize,
    /// CG-RES-12: Resolution diagnostics — per-strategy and per-language breakdown.
    pub diagnostics: super::resolution::ResolutionDiagnostics,
}
