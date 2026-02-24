//! Forward/inverse BFS on petgraph, entry point detection.
//!
//! Entry point sources (in priority order):
//! 1. package.json: bin, main, exports, scripts targets
//! 2. Python manifests: pyproject.toml, setup.py
//! 3. HTML script references
//! 4. Next.js app router patterns
//! 5. Decorator-based (route handlers, controllers)
//! 6. Code heuristics (exported, main/index, test, CLI)

use std::collections::VecDeque;
use std::path::Path;

use drift_core::types::collections::{FxHashMap, FxHashSet};
use petgraph::graph::NodeIndex;
use petgraph::Direction;

use crate::parsers::types::ParseResult;

use super::types::{CallGraph, FunctionNode};

/// Forward BFS from a starting node — find all functions reachable from `start`.
pub fn bfs_forward(graph: &CallGraph, start: NodeIndex, max_depth: Option<usize>) -> Vec<NodeIndex> {
    bfs_directed(graph, start, Direction::Outgoing, max_depth)
}

/// Inverse BFS from a starting node — find all callers that can reach `start`.
pub fn bfs_inverse(graph: &CallGraph, start: NodeIndex, max_depth: Option<usize>) -> Vec<NodeIndex> {
    bfs_directed(graph, start, Direction::Incoming, max_depth)
}

/// Generic BFS in a given direction.
fn bfs_directed(
    graph: &CallGraph,
    start: NodeIndex,
    direction: Direction,
    max_depth: Option<usize>,
) -> Vec<NodeIndex> {
    let mut visited = FxHashSet::default();
    let mut queue = VecDeque::new();
    let mut result = Vec::new();

    visited.insert(start);
    queue.push_back((start, 0usize));

    while let Some((node, depth)) = queue.pop_front() {
        if node != start {
            result.push(node);
        }

        if let Some(max) = max_depth {
            if depth >= max {
                continue;
            }
        }

        for neighbor in graph.graph.neighbors_directed(node, direction) {
            if visited.insert(neighbor) {
                queue.push_back((neighbor, depth + 1));
            }
        }
    }

    result
}

/// Detect and mark entry points in the call graph.
///
/// 5 heuristic categories:
/// 1. Exported functions
/// 2. Main/index file functions
/// 3. Route handlers
/// 4. Test functions
/// 5. CLI entry points
pub fn detect_entry_points(graph: &CallGraph) -> Vec<NodeIndex> {
    let mut entry_points = Vec::new();

    for idx in graph.graph.node_indices() {
        let node = &graph.graph[idx];
        if is_entry_point(node) {
            entry_points.push(idx);
        }
    }

    entry_points
}

/// Mark entry points directly on the graph (mutable).
///
/// Uses both code heuristics and manifest-based detection (package.json, etc.)
/// when a project_root is available. Call `mark_entry_points_with_root` for
/// full manifest support.
pub fn mark_entry_points(graph: &mut CallGraph, parse_results: &[ParseResult]) {
    mark_entry_points_with_root(graph, parse_results, None);
}

/// Mark entry points with optional project root for manifest-based detection.
pub fn mark_entry_points_with_root(
    graph: &mut CallGraph,
    parse_results: &[ParseResult],
    project_root: Option<&Path>,
) {
    // Build a set of route handler function names from decorators
    let mut route_handlers: FxHashSet<String> = FxHashSet::default();
    for pr in parse_results {
        for func in &pr.functions {
            if has_entry_point_decorator(&func.decorators) {
                route_handlers.insert(format!("{}::{}", pr.file, func.name));
            }
        }
        for class in &pr.classes {
            let is_controller = class.decorators.iter().any(|d| {
                let dl = d.name.to_lowercase();
                dl.contains("controller") || dl.contains("api") || dl.contains("resolver")
            });
            for method in &class.methods {
                if has_entry_point_decorator(&method.decorators) || is_controller {
                    route_handlers.insert(format!("{}::{}", pr.file, method.name));
                }
            }
        }
    }

    // Manifest-based entry point files (package.json, pyproject.toml, etc.)
    let manifest_entry_files = if let Some(root) = project_root {
        discover_manifest_entry_files(root)
    } else {
        FxHashMap::default()
    };

    // Next.js app router pattern files
    let nextjs_files: FxHashSet<String> = parse_results
        .iter()
        .filter(|pr| is_nextjs_entry_file(&pr.file))
        .map(|pr| pr.file.clone())
        .collect();

    let indices: Vec<NodeIndex> = graph.graph.node_indices().collect();
    for idx in indices {
        let node = &graph.graph[idx];
        let key = format!("{}::{}", node.file, node.name);
        let is_entry = is_entry_point(node)
            || route_handlers.contains(&key)
            || manifest_entry_files.contains_key(&node.file)
            || nextjs_files.contains(&node.file);
        if is_entry {
            if let Some(node_mut) = graph.graph.node_weight_mut(idx) {
                node_mut.is_entry_point = true;
            }
        }
    }
}

/// Discover entry point files from package.json, pyproject.toml, etc.
fn discover_manifest_entry_files(project_root: &Path) -> FxHashMap<String, String> {
    let mut entries = FxHashMap::default();

    // package.json
    let pkg_path = project_root.join("package.json");
    if let Ok(content) = std::fs::read_to_string(&pkg_path) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
            // "main" field
            if let Some(main) = json.get("main").and_then(|v| v.as_str()) {
                entries.insert(normalize_entry_path(main), "package.json:main".to_string());
            }
            // "bin" field (string or object)
            if let Some(bin) = json.get("bin") {
                if let Some(s) = bin.as_str() {
                    entries.insert(normalize_entry_path(s), "package.json:bin".to_string());
                } else if let Some(obj) = bin.as_object() {
                    for (_, v) in obj {
                        if let Some(s) = v.as_str() {
                            entries.insert(normalize_entry_path(s), "package.json:bin".to_string());
                        }
                    }
                }
            }
            // "exports" field
            if let Some(exports) = json.get("exports") {
                collect_exports_entries(exports, &mut entries);
            }
            // "scripts" — extract target files from build/start scripts
            if let Some(scripts) = json.get("scripts").and_then(|v| v.as_object()) {
                for (name, cmd) in scripts {
                    if matches!(name.as_str(), "start" | "dev" | "serve" | "build") {
                        if let Some(cmd_str) = cmd.as_str() {
                            for word in cmd_str.split_whitespace() {
                                if (word.ends_with(".ts") || word.ends_with(".js") || word.ends_with(".tsx"))
                                    && !word.starts_with('-')
                                {
                                    entries.insert(
                                        normalize_entry_path(word),
                                        format!("package.json:scripts.{}", name),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // pyproject.toml
    let pyproject_path = project_root.join("pyproject.toml");
    if let Ok(content) = std::fs::read_to_string(&pyproject_path) {
        if let Ok(toml_val) = content.parse::<toml::Value>() {
            // [tool.poetry.scripts] or [project.scripts]
            for key in &["tool.poetry.scripts", "project.scripts"] {
                let parts: Vec<&str> = key.split('.').collect();
                let mut val = Some(&toml_val);
                for part in &parts {
                    val = val.and_then(|v| v.get(part));
                }
                if let Some(scripts) = val.and_then(|v| v.as_table()) {
                    for (_, target) in scripts {
                        if let Some(s) = target.as_str() {
                            // "mypackage.cli:main" → mypackage/cli.py
                            if let Some(module) = s.split(':').next() {
                                let path = module.replace('.', "/") + ".py";
                                entries.insert(path, "pyproject.toml:scripts".to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    entries
}

/// Extract entry files from package.json "exports" field (handles nested objects).
fn collect_exports_entries(value: &serde_json::Value, entries: &mut FxHashMap<String, String>) {
    match value {
        serde_json::Value::String(s) => {
            entries.insert(normalize_entry_path(s), "package.json:exports".to_string());
        }
        serde_json::Value::Object(obj) => {
            for (_, v) in obj {
                collect_exports_entries(v, entries);
            }
        }
        _ => {}
    }
}

/// Normalize a manifest entry path: strip leading ./, normalize slashes.
fn normalize_entry_path(path: &str) -> String {
    let mut p = path.replace('\\', "/");
    while p.starts_with("./") {
        p = p[2..].to_string();
    }
    p
}

/// Check if a file path matches Next.js app router entry patterns.
fn is_nextjs_entry_file(file: &str) -> bool {
    let f = file.replace('\\', "/").to_lowercase();
    // App router: app/layout.tsx, app/page.tsx, app/**/layout.tsx, app/**/page.tsx
    if f.contains("/app/") || f.starts_with("app/") {
        let filename = f.rsplit('/').next().unwrap_or("");
        if filename.starts_with("layout.") || filename.starts_with("page.")
            || filename.starts_with("loading.") || filename.starts_with("error.")
            || filename.starts_with("not-found.") || filename.starts_with("route.")
        {
            return true;
        }
    }
    // Pages router: pages/_app.tsx, pages/_document.tsx, pages/index.tsx
    if f.contains("/pages/") || f.starts_with("pages/") {
        let filename = f.rsplit('/').next().unwrap_or("");
        if filename.starts_with("_app.") || filename.starts_with("_document.")
            || filename.starts_with("index.")
        {
            return true;
        }
    }
    false
}

/// CG-EP-01: Check if decorators indicate an entry point (route handler, API endpoint, etc.).
fn has_entry_point_decorator(decorators: &[crate::parsers::types::DecoratorInfo]) -> bool {
    decorators.iter().any(|d| {
        let dl = d.name.to_lowercase();
        // HTTP route decorators
        dl.contains("route") || dl.contains("get") || dl.contains("post")
            || dl.contains("put") || dl.contains("delete") || dl.contains("patch")
            || dl.contains("head") || dl.contains("options")
            // Spring
            || dl.contains("requestmapping") || dl.contains("getmapping")
            || dl.contains("postmapping") || dl.contains("putmapping")
            || dl.contains("deletemapping") || dl.contains("patchmapping")
            // NestJS / general
            || dl.contains("controller") || dl.contains("api")
            || dl.contains("endpoint")
            // DRF
            || dl.contains("api_view")
            // Scheduled / event
            || dl.contains("scheduled") || dl.contains("eventlistener")
            || dl.contains("subscribe") || dl.contains("cron")
            // GraphQL (CG-EP-04)
            || dl.contains("query") || dl.contains("mutation")
            || dl.contains("subscription") || dl.contains("resolvefield")
            || dl.contains("resolver")
    })
}

/// Check if a function node is an entry point based on heuristics.
fn is_entry_point(node: &FunctionNode) -> bool {
    // 1. Exported functions (CG-EP-02)
    if node.is_exported {
        return true;
    }

    // 2. Main/index file functions (CG-EP-03: expanded patterns)
    let file_lower = node.file.to_lowercase();
    let name_lower = node.name.to_lowercase();
    if (file_lower.contains("main.") || file_lower.contains("index.")
        || file_lower.contains("app.") || file_lower.contains("server.")
        || file_lower.contains("boot.") || file_lower.contains("startup."))
        && matches!(name_lower.as_str(), "main" | "run" | "start" | "init" | "bootstrap"
            | "app" | "createapp" | "createserver" | "application" | "default")
    {
        return true;
    }

    // CG-EP-03: Framework main function patterns (any file)
    if matches!(node.name.as_str(), "main" | "createApp" | "createServer"
        | "Application" | "WebApplication" | "gin.Default") {
        return true;
    }

    // 3. Test functions
    if name_lower.starts_with("test_") || name_lower.starts_with("test")
        || name_lower.starts_with("it_") || name_lower.starts_with("spec_")
    {
        return true;
    }

    // 4. CLI entry points
    if matches!(node.name.as_str(), "cli" | "run_cli" | "parse_args") {
        return true;
    }

    // CG-EP-02: Go uppercase-exported functions
    if node.language == "Go" {
        if let Some(first_char) = node.name.chars().next() {
            if first_char.is_uppercase() {
                return true;
            }
        }
    }

    // CG-EP-02: Rust pub fn (is_exported covers this via visibility)
    // CG-EP-04: GraphQL resolver patterns
    if name_lower.starts_with("query") || name_lower.starts_with("mutation")
        || name_lower.starts_with("subscription") || name_lower.starts_with("resolve")
    {
        if let Some(ref qn) = node.qualified_name {
            let qn_lower = qn.to_lowercase();
            if qn_lower.contains("resolver") || qn_lower.contains("query")
                || qn_lower.contains("mutation") {
                return true;
            }
        }
    }

    false
}
