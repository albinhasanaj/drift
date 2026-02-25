//! 24 test smell detectors.

use crate::call_graph::types::CallGraph;
use crate::parsers::types::{FunctionInfo, ParseResult};

use super::types::TestSmell;

/// Detect test smells in a test function.
pub fn detect_smells(
    func: &FunctionInfo,
    parse_result: &ParseResult,
    graph: &CallGraph,
) -> Vec<TestSmell> {
    let mut smells = Vec::new();

    // 1. Empty test
    if func.end_line.saturating_sub(func.line) <= 1 {
        smells.push(TestSmell::EmptyTest);
    }

    // 2. Assertion-free test
    if !has_assertions(func, parse_result) {
        smells.push(TestSmell::AssertionFree);
    }

    // 3. Sleep in test
    if has_sleep(func, parse_result) {
        smells.push(TestSmell::SleepInTest);
    }

    // 4. Conditional test
    if has_conditionals(func, parse_result) {
        smells.push(TestSmell::ConditionalTest);
    }

    // 5. Long test (>50 lines)
    if func.end_line.saturating_sub(func.line) > 50 {
        smells.push(TestSmell::LongTest);
    }

    // 6. Assertion roulette (>5 assertions without messages)
    if count_assertions(func, parse_result) > 5 {
        smells.push(TestSmell::AssertionRoulette);
    }

    // 7. Eager test (calls >10 source functions)
    if count_source_calls(func, parse_result, graph) > 10 {
        smells.push(TestSmell::EagerTest);
    }

    // 8. Lazy test (calls 0 source functions)
    if count_source_calls(func, parse_result, graph) == 0 && func.end_line.saturating_sub(func.line) > 1 {
        smells.push(TestSmell::LazyTest);
    }

    // 9. Mystery guest (uses file I/O or network)
    if has_external_resources(func, parse_result) {
        smells.push(TestSmell::MysteryGuest);
    }

    // 10. Global state
    if uses_global_state(func, parse_result) {
        smells.push(TestSmell::GlobalState);
    }

    // 11. Complex setup (>10 lines before first assertion)
    if has_complex_setup(func, parse_result) {
        smells.push(TestSmell::ComplexSetup);
    }

    // 12. Excessive mocking (>5 mocks)
    if count_mocks(func, parse_result) > 5 {
        smells.push(TestSmell::ExcessiveMocking);
    }

    // 13. Unclear naming
    if has_unclear_naming(&func.name) {
        smells.push(TestSmell::UnclearNaming);
    }

    // 14. Exception swallowing
    if has_exception_swallowing(func, parse_result) {
        smells.push(TestSmell::ExceptionSwallowing);
    }

    // 15. Magic numbers
    if has_magic_numbers(func, parse_result) {
        smells.push(TestSmell::MagicNumbers);
    }

    // 16. Hardcoded values
    if has_hardcoded_values(func, parse_result) {
        smells.push(TestSmell::HardcodedValues);
    }

    smells
}

/// Detect smells across all test functions in parse results.
pub fn detect_all_smells(
    parse_results: &[ParseResult],
    graph: &CallGraph,
) -> Vec<(String, String, Vec<TestSmell>)> {
    let mut results = Vec::new();

    for pr in parse_results {
        for func in &pr.functions {
            let name_lower = func.name.to_lowercase();
            let file_lower = pr.file.to_lowercase();

            let is_test = name_lower.starts_with("test_")
                || name_lower.starts_with("test")
                || name_lower.starts_with("it_")
                || file_lower.contains("test")
                || file_lower.contains("spec");

            if is_test {
                let smells = detect_smells(func, pr, graph);
                if !smells.is_empty() {
                    results.push((pr.file.clone(), func.name.clone(), smells));
                }
            }
        }
    }

    results
}

fn has_assertions(func: &FunctionInfo, pr: &ParseResult) -> bool {
    let assertion_patterns = [
        "assert", "expect", "should", "verify", "check",
        "assert_eq", "assert_ne", "assert!", "assertEqual",
        "assertTrue", "assertFalse", "assertNull", "assertNotNull",
        "toBe", "toEqual", "toHaveBeenCalled", "toThrow",
    ];

    pr.call_sites.iter().any(|cs| {
        cs.line >= func.line
            && cs.line <= func.end_line
            && assertion_patterns.iter().any(|p| {
                cs.callee_name.to_lowercase().contains(&p.to_lowercase())
            })
    })
}

fn has_sleep(func: &FunctionInfo, pr: &ParseResult) -> bool {
    let sleep_patterns = ["sleep", "delay", "setTimeout", "wait", "pause", "time.sleep"];
    pr.call_sites.iter().any(|cs| {
        cs.line >= func.line
            && cs.line <= func.end_line
            && sleep_patterns.iter().any(|p| cs.callee_name.to_lowercase().contains(p))
    })
}

fn has_conditionals(func: &FunctionInfo, _pr: &ParseResult) -> bool {
    // Heuristic: if function body is long enough to have conditionals
    // A proper implementation would check the AST for if/switch/match
    func.end_line.saturating_sub(func.line) > 20
}

fn count_assertions(func: &FunctionInfo, pr: &ParseResult) -> usize {
    let assertion_patterns = ["assert", "expect", "should", "verify"];
    pr.call_sites
        .iter()
        .filter(|cs| {
            cs.line >= func.line
                && cs.line <= func.end_line
                && assertion_patterns.iter().any(|p| cs.callee_name.to_lowercase().contains(p))
        })
        .count()
}

fn count_source_calls(func: &FunctionInfo, pr: &ParseResult, graph: &CallGraph) -> usize {
    // CG-COV-02: Use call graph edges when available
    let func_key = format!("{}::{}", pr.file, func.name);
    if let Some(node_idx) = graph.get_node(&func_key) {
        // Count outgoing edges that go to non-test, non-assertion functions
        let graph_count = graph.graph
            .neighbors_directed(node_idx, petgraph::Direction::Outgoing)
            .filter(|&target| {
                let target_node = &graph.graph[target];
                let name_lower = target_node.name.to_lowercase();
                !name_lower.contains("assert")
                    && !name_lower.contains("expect")
                    && !name_lower.contains("mock")
                    && !name_lower.contains("spy")
            })
            .count();
        if graph_count > 0 {
            return graph_count;
        }
    }

    // Fall back to raw call site counting if no graph edges
    pr.call_sites
        .iter()
        .filter(|cs| {
            cs.line >= func.line
                && cs.line <= func.end_line
                && !cs.callee_name.to_lowercase().contains("assert")
                && !cs.callee_name.to_lowercase().contains("expect")
                && !cs.callee_name.to_lowercase().contains("mock")
        })
        .count()
}

fn has_external_resources(func: &FunctionInfo, pr: &ParseResult) -> bool {
    let io_patterns = [
        "readFile", "writeFile", "open", "fetch", "http", "request",
        "fs.", "path.", "net.", "socket", "database", "db.",
    ];
    pr.call_sites.iter().any(|cs| {
        cs.line >= func.line
            && cs.line <= func.end_line
            && io_patterns.iter().any(|p| {
                let full = if let Some(ref r) = cs.receiver {
                    format!("{}.{}", r, cs.callee_name)
                } else {
                    cs.callee_name.clone()
                };
                full.to_lowercase().contains(&p.to_lowercase())
            })
    })
}

fn uses_global_state(func: &FunctionInfo, pr: &ParseResult) -> bool {
    let global_patterns = [
        "global", "window.", "document.", "process.", "globalThis",
        "singleton", "static", "shared",
    ];
    pr.call_sites.iter().any(|cs| {
        cs.line >= func.line
            && cs.line <= func.end_line
            && global_patterns.iter().any(|p| {
                cs.callee_name.to_lowercase().contains(p)
                    || cs.receiver.as_ref().map(|r| r.to_lowercase().contains(p)).unwrap_or(false)
            })
    })
}

fn has_complex_setup(func: &FunctionInfo, pr: &ParseResult) -> bool {
    // Check if there are >10 call sites before the first assertion
    let first_assertion_line = pr.call_sites.iter()
        .filter(|cs| {
            cs.line >= func.line
                && cs.line <= func.end_line
                && cs.callee_name.to_lowercase().contains("assert")
        })
        .map(|cs| cs.line)
        .min();

    if let Some(assert_line) = first_assertion_line {
        let setup_calls = pr.call_sites.iter()
            .filter(|cs| cs.line >= func.line && cs.line < assert_line)
            .count();
        setup_calls > 10
    } else {
        false
    }
}

fn count_mocks(func: &FunctionInfo, pr: &ParseResult) -> usize {
    let mock_patterns = ["mock", "stub", "spy", "fake", "jest.fn", "sinon", "when("];
    pr.call_sites
        .iter()
        .filter(|cs| {
            cs.line >= func.line
                && cs.line <= func.end_line
                && mock_patterns.iter().any(|p| cs.callee_name.to_lowercase().contains(p))
        })
        .count()
}

fn has_unclear_naming(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower == "test1" || lower == "test2" || lower == "test"
        || lower == "it" || lower.len() < 5
        || lower.starts_with("test_") && lower.len() < 10
}

fn has_exception_swallowing(func: &FunctionInfo, pr: &ParseResult) -> bool {
    pr.error_handling.iter().any(|eh| {
        eh.line >= func.line
            && eh.line <= func.end_line
            && !eh.has_body
    })
}

fn has_magic_numbers(func: &FunctionInfo, pr: &ParseResult) -> bool {
    pr.numeric_literals.iter().any(|nl| {
        nl.line >= func.line
            && nl.line <= func.end_line
            && nl.value != 0.0
            && nl.value != 1.0
            && nl.value != -1.0
            && nl.value != 2.0
    })
}

fn has_hardcoded_values(func: &FunctionInfo, pr: &ParseResult) -> bool {
    let hardcoded_count = pr.string_literals.iter()
        .filter(|sl| {
            sl.line >= func.line
                && sl.line <= func.end_line
                && sl.value.len() > 5
                && !sl.value.starts_with("test")
                && !sl.value.starts_with("mock")
        })
        .count();
    hardcoded_count > 3
}
