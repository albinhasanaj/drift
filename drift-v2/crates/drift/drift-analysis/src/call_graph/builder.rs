//! CallGraphBuilder — parallel extraction via rayon, builds petgraph StableGraph.

use std::path::PathBuf;
use std::time::Instant;

use drift_core::errors::CallGraphError;
use drift_core::types::collections::FxHashMap;
use rayon::prelude::*;

use crate::parsers::types::{CallSite, ParseResult};

use super::di_support;
use super::resolution::{resolve_call, ResolutionDiagnostics};
use super::tsconfig::{AliasRule, TsConfigPaths};
use super::types::{CallEdge, CallGraph, CallGraphStats, FunctionNode};

/// Builder for constructing a call graph from parse results.
pub struct CallGraphBuilder {
    /// Maximum number of functions before switching to CTE fallback.
    pub in_memory_threshold: usize,
    /// Optional project root for tsconfig.json discovery.
    pub project_root: Option<PathBuf>,
    /// Pre-loaded tsconfig path alias configuration.
    pub tsconfig_paths: Option<TsConfigPaths>,
}

impl CallGraphBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self {
            in_memory_threshold: 500_000,
            project_root: None,
            tsconfig_paths: None,
        }
    }

    /// Create a builder with a custom in-memory threshold.
    pub fn with_threshold(threshold: usize) -> Self {
        Self {
            in_memory_threshold: threshold,
            project_root: None,
            tsconfig_paths: None,
        }
    }

    /// Set the project root for tsconfig.json discovery.
    pub fn with_project_root(mut self, root: PathBuf) -> Self {
        self.project_root = Some(root);
        self
    }

    /// Set pre-loaded tsconfig path aliases.
    pub fn with_tsconfig_paths(mut self, paths: TsConfigPaths) -> Self {
        self.tsconfig_paths = Some(paths);
        self
    }

    /// Build a call graph from a set of parse results.
    ///
    /// Phase 1: Extract all functions into nodes (parallel via rayon).
    /// Phase 2: Resolve all call sites into edges (parallel per file).
    pub fn build(&self, parse_results: &[ParseResult]) -> Result<(CallGraph, CallGraphStats), CallGraphError> {
        let start = Instant::now();
        let mut graph = CallGraph::new();

        // Phase 1: Add all function nodes
        // CG-RES-08: Build qualified names for module-level functions
        let all_nodes: Vec<FunctionNode> = parse_results
            .par_iter()
            .flat_map_iter(|pr| {
                let module_name = module_name_from_file(&pr.file);
                // Top-level functions
                let top_level = pr.functions.iter().map(move |f| {
                    let qn = f.qualified_name.clone().or_else(|| {
                        Some(format!("{}.{}", module_name, f.name))
                    });
                    FunctionNode {
                        file: pr.file.clone(),
                        name: f.name.clone(),
                        qualified_name: qn,
                        language: pr.language.name().to_string(),
                        line: f.line,
                        end_line: f.end_line,
                        is_entry_point: false, // Detected later
                        is_exported: f.is_exported,
                        signature_hash: f.signature_hash,
                        body_hash: f.body_hash,
                    }
                });
                top_level
            })
            .collect();

        // Also add class methods as graph nodes
        let class_method_nodes: Vec<FunctionNode> = parse_results
            .par_iter()
            .flat_map_iter(|pr| {
                pr.classes.iter().flat_map(move |class| {
                    class.methods.iter().map(move |m| {
                        let qn = m.qualified_name.clone().or_else(|| {
                            Some(format!("{}.{}", class.name, m.name))
                        });
                        FunctionNode {
                            file: pr.file.clone(),
                            name: format!("{}.{}", class.name, m.name),
                            qualified_name: qn,
                            language: pr.language.name().to_string(),
                            line: m.line,
                            end_line: m.end_line,
                            is_entry_point: false,
                            is_exported: m.is_exported || class.is_exported,
                            signature_hash: m.signature_hash,
                            body_hash: m.body_hash,
                        }
                    })
                })
            })
            .collect();

        for node in all_nodes {
            graph.add_function(node);
        }
        for node in class_method_nodes {
            graph.add_function(node);
        }

        // Build lookup indices for resolution
        let mut name_index: FxHashMap<String, Vec<String>> = FxHashMap::default();
        let mut qualified_index: FxHashMap<String, String> = FxHashMap::default();
        let mut export_index: FxHashMap<String, Vec<String>> = FxHashMap::default();
        let mut language_index: FxHashMap<String, String> = FxHashMap::default();

        for pr in parse_results {
            let lang = pr.language.name().to_string();
            for func in &pr.functions {
                let key = format!("{}::{}", pr.file, func.name);
                name_index.entry(func.name.clone()).or_default().push(key.clone());
                language_index.insert(key.clone(), lang.clone());
                if let Some(ref qn) = func.qualified_name {
                    qualified_index.insert(qn.clone(), key.clone());
                }
                // CG-RES-08: Also index module_name.function_name
                let module_qn = format!("{}.{}", module_name_from_file(&pr.file), func.name);
                qualified_index.entry(module_qn).or_insert_with(|| key.clone());
                if func.is_exported {
                    export_index.entry(func.name.clone()).or_default().push(key);
                }
            }
            // Index class methods (key includes class name to avoid collisions)
            for class in &pr.classes {
                for method in &class.methods {
                    let key = format!("{}::{}.{}", pr.file, class.name, method.name);
                    name_index.entry(method.name.clone()).or_default().push(key.clone());
                    language_index.insert(key.clone(), lang.clone());
                    // Qualified: ClassName.methodName
                    let class_qn = format!("{}.{}", class.name, method.name);
                    qualified_index.insert(class_qn, key.clone());
                    if let Some(ref qn) = method.qualified_name {
                        qualified_index.insert(qn.clone(), key.clone());
                    }
                    if method.is_exported || class.is_exported {
                        export_index.entry(method.name.clone()).or_default().push(key);
                    }
                }
            }
        }

        // Load tsconfig alias rules for import resolution
        let alias_rules: Vec<AliasRule> = if let Some(ref tc) = self.tsconfig_paths {
            tc.compile_rules()
        } else if let Some(ref root) = self.project_root {
            TsConfigPaths::load(root)
                .map(|tc| tc.compile_rules())
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        if !alias_rules.is_empty() {
            tracing::info!(
                "tsconfig alias rules loaded: {} rules (prefixes: {})",
                alias_rules.len(),
                alias_rules.iter().map(|r| r.prefix.as_str()).collect::<Vec<_>>().join(", ")
            );
        }

        // CG-RES-05: Detect DI frameworks for DI resolution
        let detected_frameworks = di_support::detect_di_frameworks(parse_results);

        // Phase 2: Resolve call sites into edges
        // Collect all (caller_key, call_site, file) tuples
        let call_entries: Vec<(String, &CallSite, &ParseResult)> = parse_results
            .iter()
            .flat_map(|pr| {
                pr.functions.iter().flat_map(move |func| {
                    let caller_key = format!("{}::{}", pr.file, func.name);
                    pr.call_sites
                        .iter()
                        .filter(move |cs| {
                            cs.line >= func.line && cs.line <= func.end_line
                        })
                        .map(move |cs| (caller_key.clone(), cs, pr))
                })
            })
            .collect();

        let mut resolution_counts: FxHashMap<String, usize> = FxHashMap::default();
        let mut diagnostics = ResolutionDiagnostics::new();
        let mut resolved = 0usize;

        for (caller_key, call_site, pr) in &call_entries {
            let caller_language = pr.language.name();
            if let Some(caller_idx) = graph.get_node(caller_key) {
                let resolution_result = resolve_call(
                    call_site,
                    &pr.file,
                    caller_language,
                    &pr.imports,
                    &name_index,
                    &qualified_index,
                    &export_index,
                    &language_index,
                    &alias_rules,
                );

                // CG-RES-05: If standard resolution fails, try DI resolution
                let resolution_result = resolution_result.or_else(|| {
                    if !detected_frameworks.is_empty() {
                        // Check if the callee name matches a DI-injected type
                        di_support::resolve_di_injection(
                            &call_site.callee_name,
                            &name_index,
                        )
                    } else {
                        None
                    }
                });

                // CG-RES-12: Record diagnostics
                diagnostics.record(
                    resolution_result.as_ref().map(|(_, r)| r),
                    caller_language,
                );

                if let Some((callee_key, resolution)) = resolution_result {
                    if let Some(callee_idx) = graph.get_node(&callee_key) {
                        let edge = CallEdge {
                            resolution,
                            confidence: resolution.default_confidence(),
                            call_site_line: call_site.line,
                        };
                        graph.add_edge(caller_idx, callee_idx, edge);
                        *resolution_counts.entry(resolution.name().to_string()).or_default() += 1;
                        resolved += 1;
                    }
                }
            }
        }

        // CG-RES-12: Emit warnings for low resolution rates
        for warning in diagnostics.low_resolution_warnings() {
            tracing::warn!("{}", warning);
        }

        // Detect entry points (with manifest support when project_root is available)
        super::traversal::mark_entry_points_with_root(
            &mut graph,
            parse_results,
            self.project_root.as_deref(),
        );

        let total_calls = call_entries.len();
        let stats = CallGraphStats {
            total_functions: graph.function_count(),
            total_edges: graph.edge_count(),
            entry_points: graph.graph.node_indices()
                .filter(|&idx| graph.graph[idx].is_entry_point)
                .count(),
            resolution_counts,
            resolution_rate: if total_calls > 0 {
                resolved as f64 / total_calls as f64
            } else {
                0.0
            },
            build_duration: start.elapsed(),
            cycles_detected: 0,
            diagnostics,
        };

        Ok((graph, stats))
    }
}

impl Default for CallGraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CallGraphBuilder {
    /// Create a builder that auto-discovers tsconfig from the project root.
    pub fn for_project(project_root: PathBuf) -> Self {
        let tsconfig = TsConfigPaths::load(&project_root);
        Self {
            in_memory_threshold: 500_000,
            project_root: Some(project_root),
            tsconfig_paths: tsconfig,
        }
    }
}

/// Extract a module name from a file path.
/// e.g., "src/utils/format.ts" → "format"
/// e.g., "controllers/user.controller.ts" → "user.controller"
fn module_name_from_file(file: &str) -> String {
    let normalized = file.replace('\\', "/");
    let filename = normalized.rsplit('/').next().unwrap_or(&normalized);
    // Strip extension
    for ext in &[".ts", ".tsx", ".js", ".jsx", ".py", ".java", ".go", ".rs", ".rb", ".php", ".cs", ".kt"] {
        if let Some(stripped) = filename.strip_suffix(ext) {
            return stripped.to_string();
        }
    }
    filename.to_string()
}
