//! Dead code detection with 10 false-positive exclusion categories.

use drift_core::types::collections::FxHashSet;
use petgraph::graph::NodeIndex;

use crate::call_graph::types::{CallGraph, FunctionNode};

use super::types::{DeadCodeExclusion, DeadCodeReason, DeadCodeResult};

/// Detect dead code in the call graph.
///
/// A function is considered dead if it has no callers AND is not excluded
/// by any of the 10 false-positive categories.
/// CG-DC-01: Results include confidence gated on resolution rate.
/// CG-DC-04: Results include confidence scoring.
pub fn detect_dead_code(graph: &CallGraph) -> Vec<DeadCodeResult> {
    detect_dead_code_with_resolution_rate(graph, None)
}

/// Detect dead code with optional resolution rate for confidence gating (CG-DC-01).
pub fn detect_dead_code_with_resolution_rate(
    graph: &CallGraph,
    resolution_rate: Option<f64>,
) -> Vec<DeadCodeResult> {
    let mut results = Vec::new();
    let low_resolution = resolution_rate.map(|r| r < 0.40).unwrap_or(false);

    for idx in graph.graph.node_indices() {
        let node = &graph.graph[idx];
        let incoming_count = graph
            .graph
            .neighbors_directed(idx, petgraph::Direction::Incoming)
            .count();

        if incoming_count == 0 {
            let exclusion = check_exclusions(node);
            let is_dead = exclusion.is_none();

            // CG-DC-04: Confidence scoring
            let confidence = if !is_dead {
                0.0 // Excluded — not dead
            } else if low_resolution {
                // CG-DC-01: Low confidence when resolution rate is poor
                0.3
            } else {
                compute_dead_code_confidence(node)
            };

            results.push(DeadCodeResult {
                function_id: idx,
                reason: DeadCodeReason::NoCallers,
                exclusion,
                is_dead,
                confidence,
            });
        }
    }

    results
}

/// CG-DC-04: Compute confidence that a function is truly dead.
fn compute_dead_code_confidence(node: &FunctionNode) -> f32 {
    let mut confidence = 0.9f32;

    // Common names are less likely to be truly dead (might be called dynamically)
    let common_names = ["handler", "callback", "listener", "hook", "middleware",
        "plugin", "factory", "provider", "service"];
    let name_lower = node.name.to_lowercase();
    if common_names.iter().any(|n| name_lower.contains(n)) {
        confidence -= 0.2;
    }

    // Short names are more likely false positives
    if node.name.len() <= 3 {
        confidence -= 0.15;
    }

    // Functions in test files less relevant for dead code detection
    if node.file.to_lowercase().contains("test") {
        confidence -= 0.1;
    }

    confidence.clamp(0.1, 1.0)
}

/// Detect functions with no path from any entry point.
pub fn detect_unreachable(graph: &CallGraph) -> Vec<DeadCodeResult> {
    let mut results = Vec::new();

    // Find all entry points
    let entry_points: Vec<NodeIndex> = graph
        .graph
        .node_indices()
        .filter(|&idx| graph.graph[idx].is_entry_point)
        .collect();

    // BFS from all entry points to find reachable set
    let mut reachable = FxHashSet::default();
    let mut queue = std::collections::VecDeque::new();

    for &entry in &entry_points {
        if reachable.insert(entry) {
            queue.push_back(entry);
        }
    }

    while let Some(node) = queue.pop_front() {
        for neighbor in graph.graph.neighbors_directed(node, petgraph::Direction::Outgoing) {
            if reachable.insert(neighbor) {
                queue.push_back(neighbor);
            }
        }
    }

    // Any node not in the reachable set is unreachable
    for idx in graph.graph.node_indices() {
        if !reachable.contains(&idx) {
            let node = &graph.graph[idx];
            let exclusion = check_exclusions(node);
            let is_dead = exclusion.is_none();
            let confidence = if is_dead { compute_dead_code_confidence(node) } else { 0.0 };

            results.push(DeadCodeResult {
                function_id: idx,
                reason: DeadCodeReason::NoEntryPath,
                exclusion,
                is_dead,
                confidence,
            });
        }
    }

    results
}

/// Check all 10 false-positive exclusion categories.
fn check_exclusions(node: &FunctionNode) -> Option<DeadCodeExclusion> {
    // 1. Entry points
    if is_entry_point(node) {
        return Some(DeadCodeExclusion::EntryPoint);
    }

    // 2. Event handlers
    if is_event_handler(node) {
        return Some(DeadCodeExclusion::EventHandler);
    }

    // 3. Reflection targets
    if is_reflection_target(node) {
        return Some(DeadCodeExclusion::ReflectionTarget);
    }

    // 4. Dependency injection
    if is_di_target(node) {
        return Some(DeadCodeExclusion::DependencyInjection);
    }

    // 5. Test utilities
    if is_test_utility(node) {
        return Some(DeadCodeExclusion::TestUtility);
    }

    // 6. Framework hooks
    if is_framework_hook(node) {
        return Some(DeadCodeExclusion::FrameworkHook);
    }

    // 7. Decorator targets
    if is_decorator_target(node) {
        return Some(DeadCodeExclusion::DecoratorTarget);
    }

    // 8. Interface implementations
    if is_interface_impl(node) {
        return Some(DeadCodeExclusion::InterfaceImpl);
    }

    // 9. Conditional compilation
    if is_conditional_compilation(node) {
        return Some(DeadCodeExclusion::ConditionalCompilation);
    }

    // 10. Dynamic imports
    if is_dynamic_import(node) {
        return Some(DeadCodeExclusion::DynamicImport);
    }

    None
}

fn is_entry_point(node: &FunctionNode) -> bool {
    node.is_entry_point
        || node.is_exported
        || matches!(node.name.as_str(), "main" | "index" | "default" | "run" | "start" | "init")
}

fn is_event_handler(node: &FunctionNode) -> bool {
    let name = &node.name.to_lowercase();
    name.starts_with("on_")
        || name.starts_with("on")
        || name.starts_with("handle_")
        || name.starts_with("handle")
        || name.contains("listener")
        || name.contains("callback")
        || name.contains("subscriber")
        || name.contains("observer")
}

fn is_reflection_target(node: &FunctionNode) -> bool {
    let name = &node.name.to_lowercase();
    name.contains("invoke")
        || name.contains("reflect")
        || name.contains("dynamic")
        || name.contains("proxy")
}

fn is_di_target(node: &FunctionNode) -> bool {
    let name = &node.name.to_lowercase();
    name.contains("inject")
        || name.contains("provide")
        || name.contains("factory")
        || name.contains("service")
        || name.contains("repository")
}

fn is_test_utility(node: &FunctionNode) -> bool {
    let name = &node.name.to_lowercase();
    let file = &node.file.to_lowercase();
    name.starts_with("test_")
        || name.starts_with("test")
        || name.starts_with("spec_")
        || name.starts_with("it_")
        || name.contains("mock")
        || name.contains("stub")
        || name.contains("fixture")
        || name.contains("helper")
        || file.contains("test")
        || file.contains("spec")
        || file.contains("__tests__")
}

fn is_framework_hook(node: &FunctionNode) -> bool {
    let name = &node.name;
    // React lifecycle
    matches!(
        name.as_str(),
        "componentDidMount"
            | "componentDidUpdate"
            | "componentWillUnmount"
            | "getDerivedStateFromProps"
            | "shouldComponentUpdate"
            | "getSnapshotBeforeUpdate"
            | "componentDidCatch"
            | "render"
    ) ||
    // Vue lifecycle
    matches!(
        name.as_str(),
        "created" | "mounted" | "updated" | "destroyed"
            | "beforeCreate" | "beforeMount" | "beforeUpdate" | "beforeDestroy"
            | "setup" | "onMounted" | "onUpdated" | "onUnmounted"
    ) ||
    // Angular lifecycle
    matches!(
        name.as_str(),
        "ngOnInit" | "ngOnDestroy" | "ngOnChanges" | "ngAfterViewInit"
            | "ngAfterContentInit" | "ngDoCheck"
    ) ||
    // Python
    matches!(name.as_str(), "__init__" | "__del__" | "__enter__" | "__exit__" | "__call__")
}

fn is_decorator_target(node: &FunctionNode) -> bool {
    // Functions with route decorators, API decorators, etc.
    let name = &node.name.to_lowercase();
    name.contains("route")
        || name.contains("api")
        || name.contains("endpoint")
        || name.contains("controller")
        || name.contains("middleware")
        || name.contains("plugin")
}

fn is_interface_impl(node: &FunctionNode) -> bool {
    // Functions that implement an interface method.
    // Match "ClassName.method" where ClassName starts with uppercase (class/interface).
    // Do NOT match "moduleName.funcName" which is set on all functions by the builder.
    node.qualified_name
        .as_ref()
        .map(|qn| {
            // Must have a dot separator
            if let Some(dot_pos) = qn.find('.') {
                let prefix = &qn[..dot_pos];
                // The prefix must start with uppercase (ClassName, not moduleName)
                // and must not contain path separators (which would indicate a file module)
                prefix.chars().next().map(|c| c.is_uppercase()).unwrap_or(false)
                    && !prefix.contains('/')
                    && !prefix.contains('\\')
            } else {
                // Rust-style Class::method
                qn.contains("::")
            }
        })
        .unwrap_or(false)
}

fn is_conditional_compilation(node: &FunctionNode) -> bool {
    let name = &node.name.to_lowercase();
    let file = &node.file.to_lowercase();
    name.contains("cfg")
        || name.contains("ifdef")
        || name.contains("platform")
        || file.contains("platform")
        || file.contains("arch")
}

fn is_dynamic_import(node: &FunctionNode) -> bool {
    let name = &node.name.to_lowercase();
    name.contains("lazy")
        || name.contains("dynamic")
        || name.contains("loadable")
        || name.contains("async_import")
}
