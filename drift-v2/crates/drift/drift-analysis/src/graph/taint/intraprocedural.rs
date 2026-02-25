//! Intraprocedural taint analysis — within-function dataflow tracking.
//!
//! Phase 1 of taint analysis. Covers most common vulnerability patterns
//! by tracking taint within a single function body.
//! Performance target: <1ms per function.

use drift_core::types::collections::{FxHashMap, FxHashSet};

use crate::parsers::types::{CallSite, FunctionInfo, ParseResult};

use super::registry::TaintRegistry;
use super::types::*;

/// Analyze a single function for intraprocedural taint flows.
///
/// Tracks taint from sources through local variables to sinks,
/// applying sanitizers along the way.
pub fn analyze_intraprocedural(
    parse_result: &ParseResult,
    registry: &TaintRegistry,
) -> Vec<TaintFlow> {
    let mut flows = Vec::new();

    for func in &parse_result.functions {
        let func_flows = analyze_function(func, parse_result, registry);
        flows.extend(func_flows);
    }

    // Also analyze class methods
    for class in &parse_result.classes {
        for method in &class.methods {
            let method_flows = analyze_function(method, parse_result, registry);
            flows.extend(method_flows);
        }
    }

    flows
}

/// Analyze a single function for taint flows.
fn analyze_function(
    func: &FunctionInfo,
    parse_result: &ParseResult,
    registry: &TaintRegistry,
) -> Vec<TaintFlow> {
    let mut flows = Vec::new();
    let mut tainted_vars: FxHashMap<String, TaintLabel> = FxHashMap::default();
    let mut sanitized_vars: FxHashSet<String> = FxHashSet::default();
    let mut label_counter: u64 = 0;

    // Phase 1: Identify sources within this function's scope
    let func_sources = find_sources_in_function(func, parse_result, registry, &mut label_counter);

    // Mark source variables as tainted
    for source in &func_sources {
        tainted_vars.insert(source.expression.clone(), source.label.clone());
        // If the source is a dotted expression (e.g., "req.query"), also mark the
        // receiver prefix ("req") as tainted. This ensures that when tainted data
        // flows through the receiver to other sinks (e.g., res.send(req.body)),
        // the taint is properly tracked.
        if let Some(dot_pos) = source.expression.find('.') {
            let receiver = &source.expression[..dot_pos];
            tainted_vars.entry(receiver.to_string())
                .or_insert_with(|| source.label.clone());
        }
    }

    // Phase 2: Identify tainted parameters
    for param in &func.parameters {
        if let Some(source_pattern) = registry.match_source(&param.name) {
            let label = TaintLabel::new(label_counter, source_pattern.source_type);
            label_counter += 1;
            tainted_vars.insert(param.name.clone(), label);
        }
    }

    // Phase 3: Track taint through call sites within this function
    let func_calls = find_calls_in_function(func, parse_result);

    // Sort calls by line number for sequential analysis
    let mut sorted_calls: Vec<&CallSite> = func_calls.into_iter().collect();
    sorted_calls.sort_by_key(|c| c.line);

    let mut sanitizers_applied = Vec::new();

    for call in &sorted_calls {
        let callee_name = &call.callee_name;
        let full_name = if let Some(ref receiver) = call.receiver {
            format!("{}.{}", receiver, callee_name)
        } else {
            callee_name.clone()
        };

        // CG-TAINT-03: Track taint through assignments
        // If a call returns into a variable and its arguments are tainted,
        // propagate taint to the callee_name as a rough approximation
        if let Some(ref receiver) = call.receiver {
            if tainted_vars.contains_key(receiver) && !sanitized_vars.contains(receiver) {
                // Receiver is tainted, result of receiver.method() is also tainted
                let label = tainted_vars[receiver].clone();
                tainted_vars.insert(full_name.clone(), label);
            }
        }

        // Check if this call is a sanitizer
        if let Some(sanitizer_pattern) = registry.match_sanitizer(&full_name) {
            // Mark receiver/arguments as sanitized
            if let Some(ref receiver) = call.receiver {
                sanitized_vars.insert(receiver.clone());
            }
            sanitizers_applied.push(TaintSanitizer {
                file: parse_result.file.clone(),
                line: call.line,
                expression: full_name.clone(),
                sanitizer_type: sanitizer_pattern.sanitizer_type,
                labels_sanitized: sanitizer_pattern.protects_against.clone(),
            });
            continue;
        }

        // Check if this call is a sink
        if let Some(sink_pattern) = registry.match_sink(&full_name) {
            // CG-TAINT-01: Check if a tainted variable actually flows into this sink
            let is_tainted = check_taint_reaches_sink(
                &tainted_vars,
                &sanitized_vars,
                call,
                &func.parameters,
            );

            if is_tainted {
                let is_sanitized = check_sanitized_for_sink(
                    &sanitizers_applied,
                    &sink_pattern.sink_type,
                );

                // CG-TAINT-02: Find the source that originated the taint reaching this sink
                let source = find_taint_source_for_sink(
                    &tainted_vars, &sanitized_vars, call, &func_sources,
                ).unwrap_or_else(|| {
                    func_sources.first().cloned().unwrap_or_else(|| {
                        TaintSource {
                            file: parse_result.file.clone(),
                            line: func.line,
                            column: 0,
                            expression: "unknown_source".to_string(),
                            source_type: SourceType::UserInput,
                            label: TaintLabel::new(0, SourceType::UserInput),
                        }
                    })
                });

                let sink = TaintSink {
                    file: parse_result.file.clone(),
                    line: call.line,
                    column: call.column,
                    expression: full_name.clone(),
                    sink_type: sink_pattern.sink_type,
                    required_sanitizers: sink_pattern.required_sanitizers.clone(),
                };

                let path = build_intraprocedural_path(&source, &sink, func);

                flows.push(TaintFlow {
                    source,
                    sink,
                    path,
                    is_sanitized,
                    sanitizers_applied: if is_sanitized {
                        sanitizers_applied.clone()
                    } else {
                        Vec::new()
                    },
                    cwe_id: sink_pattern.sink_type.cwe_id(),
                    confidence: if is_sanitized { 0.3 } else { 0.85 },
                });
            }
        }
    }

    flows
}

/// Find taint sources within a function's scope.
fn find_sources_in_function(
    func: &FunctionInfo,
    parse_result: &ParseResult,
    registry: &TaintRegistry,
    label_counter: &mut u64,
) -> Vec<TaintSource> {
    let mut sources = Vec::new();

    // Check function parameters for source patterns
    for param in &func.parameters {
        if let Some(source_pattern) = registry.match_source(&param.name) {
            let label = TaintLabel::new(*label_counter, source_pattern.source_type);
            *label_counter += 1;
            sources.push(TaintSource {
                file: parse_result.file.clone(),
                line: func.line,
                column: 0,
                expression: param.name.clone(),
                source_type: source_pattern.source_type,
                label,
            });
        }
    }

    // Check call sites within function scope for source patterns
    for call in &parse_result.call_sites {
        if call.line >= func.line && call.line <= func.end_line {
            let full_name = if let Some(ref receiver) = call.receiver {
                format!("{}.{}", receiver, call.callee_name)
            } else {
                call.callee_name.clone()
            };

            if let Some(source_pattern) = registry.match_source(&full_name) {
                let label = TaintLabel::new(*label_counter, source_pattern.source_type);
                *label_counter += 1;
                sources.push(TaintSource {
                    file: parse_result.file.clone(),
                    line: call.line,
                    column: call.column,
                    expression: full_name,
                    source_type: source_pattern.source_type,
                    label,
                });
            }
        }
    }

    sources
}

/// Find call sites within a function's line range.
fn find_calls_in_function<'a>(
    func: &FunctionInfo,
    parse_result: &'a ParseResult,
) -> Vec<&'a CallSite> {
    parse_result
        .call_sites
        .iter()
        .filter(|c| c.line >= func.line && c.line <= func.end_line)
        .collect()
}

/// CG-TAINT-01: Check if tainted data reaches a sink call.
///
/// Uses a layered approach:
/// 1. Direct: receiver or full expression is tainted
/// 2. Bare calls: no receiver + callee name appears as a tainted var, OR
///    the function has only one tainted var and only one argument (high confidence)
/// 3. Receiver calls: receiver is a known parameter in the same function as a tainted
///    parameter (e.g., function(req, res) — "req" is tainted, "res.send" is the sink)
fn check_taint_reaches_sink(
    tainted_vars: &FxHashMap<String, TaintLabel>,
    sanitized_vars: &FxHashSet<String>,
    call: &CallSite,
    func_params: &smallvec::SmallVec<[crate::parsers::types::ParameterInfo; 4]>,
) -> bool {
    // Layer 1: Direct taint — receiver or full expression is tainted
    if let Some(ref receiver) = call.receiver {
        if tainted_vars.contains_key(receiver) && !sanitized_vars.contains(receiver) {
            return true;
        }
    }

    let full_name = if let Some(ref receiver) = call.receiver {
        format!("{}.{}", receiver, call.callee_name)
    } else {
        call.callee_name.clone()
    };
    if tainted_vars.contains_key(&full_name) && !sanitized_vars.contains(&full_name) {
        return true;
    }

    if tainted_vars.contains_key(&call.callee_name) && !sanitized_vars.contains(&call.callee_name) {
        return true;
    }

    // Layer 2: Bare function calls (no receiver) — require evidence that tainted
    // data actually flows as an argument. Without argument-level AST tracking,
    // we use a conservative heuristic: the call must have at least one argument,
    // and there must be unsanitized tainted variables in scope.
    // Previously this returned true for ANY bare call with ANY tainted var in scope,
    // which caused ~8,000 false positives (e.g., format!(), println!(), assert!()).
    if call.receiver.is_none() && call.argument_count > 0 {
        // Only flag if the number of distinct taint sources is small (high signal)
        // and the call takes arguments (data could flow through).
        // Count distinct taint labels rather than variable names, because a single
        // source like "req.query" may also taint the receiver "req" — both share
        // the same label and represent one logical taint source.
        let unsanitized_labels: FxHashSet<u64> = tainted_vars.iter()
            .filter(|(k, _)| !sanitized_vars.contains(*k))
            .map(|(_, label)| label.id)
            .collect();
        let unsanitized_taint_count = unsanitized_labels.len();
        // If there's exactly 1 tainted var and the call takes args, it's likely
        // the tainted data is being passed. If there are many tainted vars,
        // we can't be sure which (if any) flows to this call — skip it.
        if unsanitized_taint_count == 1 && call.argument_count <= 3 {
            return true;
        }
        // Also flag if a tainted var name is a substring of the callee
        // (e.g., tainted "query" → call "executeQuery")
        for var_name in tainted_vars.keys() {
            if sanitized_vars.contains(var_name) {
                continue;
            }
            let var_lower = var_name.to_lowercase();
            let callee_lower = call.callee_name.to_lowercase();
            if callee_lower.contains(&var_lower) || var_lower.contains(&callee_lower) {
                return true;
            }
        }
    }

    // Layer 3: For receiver calls — check if a tainted var's callee component
    // matches the sink's callee (e.g., tainted "req.query" → sink "db.query")
    // OR if the receiver is a sibling parameter of a tainted parameter
    // (e.g., function(req, res) — "req" is tainted, "res.send" is the sink)
    if call.receiver.is_some() {
        let has_unsanitized_taint = tainted_vars.keys().any(|k| !sanitized_vars.contains(k));
        if has_unsanitized_taint {
            for var_name in tainted_vars.keys() {
                if sanitized_vars.contains(var_name) {
                    continue;
                }
                let tainted_callee = var_name.rsplit('.').next().unwrap_or(var_name);
                if tainted_callee == call.callee_name {
                    return true;
                }
            }
            // If the receiver is itself a declared function parameter AND a different
            // parameter is tainted, the tainted data likely flows through the function
            // body to reach this sink. e.g., function(req, res) { res.send(req.body) }
            if let Some(ref receiver) = call.receiver {
                let receiver_is_param = func_params.iter().any(|p| p.name == *receiver);
                let has_tainted_param = func_params.iter().any(|p| {
                    tainted_vars.contains_key(&p.name) && !sanitized_vars.contains(&p.name)
                });
                if receiver_is_param && has_tainted_param {
                    return true;
                }
            }
        }
    }

    false
}

/// CG-TAINT-02: Find the taint source that flows to this specific sink call.
fn find_taint_source_for_sink(
    tainted_vars: &FxHashMap<String, TaintLabel>,
    sanitized_vars: &FxHashSet<String>,
    call: &CallSite,
    sources: &[TaintSource],
) -> Option<TaintSource> {
    // Check receiver first
    if let Some(ref receiver) = call.receiver {
        if let Some(label) = tainted_vars.get(receiver) {
            if !sanitized_vars.contains(receiver) {
                // Find the source with matching label
                return sources.iter()
                    .find(|s| s.label.id == label.id)
                    .cloned();
            }
        }
    }

    // Check callee name
    if let Some(label) = tainted_vars.get(&call.callee_name) {
        if !sanitized_vars.contains(&call.callee_name) {
            return sources.iter()
                .find(|s| s.label.id == label.id)
                .cloned();
        }
    }

    None
}

/// Check if the appropriate sanitizer has been applied for a given sink type.
fn check_sanitized_for_sink(
    sanitizers: &[TaintSanitizer],
    sink_type: &SinkType,
) -> bool {
    sanitizers.iter().any(|s| s.labels_sanitized.contains(sink_type))
}

/// Build an intraprocedural path from source to sink.
fn build_intraprocedural_path(
    source: &TaintSource,
    sink: &TaintSink,
    func: &FunctionInfo,
) -> Vec<TaintHop> {
    let mut path = Vec::new();

    // Source hop
    path.push(TaintHop {
        file: source.file.clone(),
        line: source.line,
        column: source.column,
        function: func.name.clone(),
        description: format!("Taint introduced from {}", source.source_type.name()),
    });

    // If source and sink are on different lines, add intermediate hop
    if source.line != sink.line {
        path.push(TaintHop {
            file: sink.file.clone(),
            line: sink.line,
            column: sink.column,
            function: func.name.clone(),
            description: format!("Taint flows to {} sink", sink.sink_type.name()),
        });
    }

    path
}
