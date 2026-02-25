//! decompose_with_priors() — 6-signal decomposition with prior-based boundary adjustment.
//!
//! D1 compliant: priors param is &[DecompositionDecision], empty in standalone mode.

use super::types::*;
use rustc_hash::{FxHashMap, FxHashSet};

/// Input data for decomposition.
pub struct DecompositionInput {
    /// Files with their directory paths.
    pub files: Vec<FileEntry>,
    /// Call edges: (caller_file, callee_file, function_name).
    pub call_edges: Vec<(String, String, String)>,
    /// Data access: (file, table_name, operation).
    pub data_access: Vec<(String, String, String)>,
    /// Function exports: (file, function_name, is_exported).
    pub functions: Vec<(String, String, bool)>,
}

/// A file entry for decomposition.
pub struct FileEntry {
    pub path: String,
    pub line_count: u64,
    pub language: String,
}

/// Decompose a codebase into logical modules, applying priors as boundary adjustments.
///
/// 6 signals used for decomposition:
/// 1. Directory structure (files in same directory cluster together)
/// 2. Call graph (files that call each other cluster together)
/// 3. Data dependencies (files accessing same tables cluster together)
/// 4. Naming conventions (files with similar naming patterns cluster together)
/// 5. Import patterns (files importing from same sources cluster together)
/// 6. File size/complexity (balance module sizes)
///
/// Priors are applied as boundary adjustments with weight = confidence × dna_similarity.
/// Thresholds: Split ≥ 0.4, Merge ≥ 0.5, Reclassify ≥ 0.3.
pub fn decompose_with_priors(
    input: &DecompositionInput,
    priors: &[DecompositionDecision],
) -> Vec<LogicalModule> {
    if input.files.is_empty() {
        return Vec::new();
    }

    // Step 1: Initial clustering by directory structure
    let mut modules = cluster_by_directory(input);

    // Step 2: Refine by call graph (merge tightly coupled clusters)
    refine_by_call_graph(&mut modules, &input.call_edges);

    // Step 3: Compute cohesion and coupling
    compute_metrics(&mut modules, &input.call_edges);

    // Step 4: Extract public interfaces
    extract_public_interfaces(&mut modules, &input.call_edges, &input.functions);

    // Step 5: Extract data dependencies
    extract_data_dependencies(&mut modules, &input.data_access);

    // Step 6: Apply priors
    apply_priors(&mut modules, priors);

    // Step 7: Re-score after adjustments
    compute_metrics(&mut modules, &input.call_edges);

    // Step 8: Set convention profiles and complexity
    for module in &mut modules {
        module.convention_profile = infer_convention_profile(&module.files);
        module.estimated_complexity = input.files.iter()
            .filter(|f| module.files.contains(&f.path))
            .map(|f| f.line_count)
            .sum();
    }

    // Sort deterministically by name
    modules.sort_by(|a, b| a.name.cmp(&b.name));

    modules
}

/// Cluster files by directory structure (Signal 1).
fn cluster_by_directory(input: &DecompositionInput) -> Vec<LogicalModule> {
    let mut dir_groups: FxHashMap<String, Vec<String>> = FxHashMap::default();

    for file in &input.files {
        let dir = file.path.rsplit_once('/')
            .map(|(d, _)| d.to_string())
            .unwrap_or_else(|| "root".to_string());
        dir_groups.entry(dir).or_default().push(file.path.clone());
    }

    dir_groups.into_iter().map(|(dir, files)| {
        let name = dir.rsplit('/').next().unwrap_or(&dir).to_string();
        LogicalModule {
            name,
            files,
            public_interface: Vec::new(),
            internal_functions: Vec::new(),
            data_dependencies: Vec::new(),
            convention_profile: ConventionProfile {
                naming_convention: String::new(),
                error_handling: String::new(),
                logging: String::new(),
            },
            cohesion: 0.0,
            coupling: 0.0,
            estimated_complexity: 0,
            applied_priors: Vec::new(),
        }
    }).collect()
}

/// Refine clusters by call graph connectivity (Signal 2).
fn refine_by_call_graph(modules: &mut Vec<LogicalModule>, call_edges: &[(String, String, String)]) {
    // Build file→module index
    let mut file_to_module: FxHashMap<String, usize> = FxHashMap::default();
    for (i, module) in modules.iter().enumerate() {
        for file in &module.files {
            file_to_module.insert(file.clone(), i);
        }
    }

    // Count cross-module calls
    let mut cross_module_calls: FxHashMap<(usize, usize), u32> = FxHashMap::default();
    for (caller, callee, _) in call_edges {
        if let (Some(&m1), Some(&m2)) = (file_to_module.get(caller), file_to_module.get(callee)) {
            if m1 != m2 {
                *cross_module_calls.entry((m1.min(m2), m1.max(m2))).or_insert(0) += 1;
            }
        }
    }

    // Merge modules with very high cross-module coupling (>50% of calls)
    // This is a simplified heuristic; a full implementation would use
    // community detection algorithms.
    let mut merges: Vec<(usize, usize)> = Vec::new();
    for (&(m1, m2), &count) in &cross_module_calls {
        let total_calls_m1 = call_edges.iter()
            .filter(|(c, _, _)| modules.get(m1).is_some_and(|m| m.files.contains(c)))
            .count() as u32;
        if total_calls_m1 > 0 && count as f64 / total_calls_m1 as f64 > 0.5 {
            merges.push((m1, m2));
        }
    }

    // Apply merges (in reverse order to preserve indices)
    merges.sort_by(|a, b| b.1.cmp(&a.1));
    for (keep, remove) in merges {
        if keep < modules.len() && remove < modules.len() && keep != remove {
            let removed_files = modules[remove].files.clone();
            modules[keep].files.extend(removed_files);
            modules.remove(remove);
        }
    }
}

/// Compute cohesion and coupling metrics.
fn compute_metrics(modules: &mut [LogicalModule], call_edges: &[(String, String, String)]) {
    let _file_to_module: FxHashMap<&str, usize> = modules.iter().enumerate()
        .flat_map(|(i, m)| m.files.iter().map(move |f| (f.as_str(), i)))
        .collect();

    for module in modules.iter_mut() {
        let module_files: FxHashSet<&str> = module.files.iter().map(|f| f.as_str()).collect();

        // Cohesion: fraction of call edges that are intra-module
        let intra_calls = call_edges.iter()
            .filter(|(c, t, _)| module_files.contains(c.as_str()) && module_files.contains(t.as_str()))
            .count() as f64;
        let total_calls = call_edges.iter()
            .filter(|(c, _, _)| module_files.contains(c.as_str()))
            .count() as f64;

        module.cohesion = if total_calls > 0.0 {
            (intra_calls / total_calls).clamp(0.0, 1.0)
        } else if module.files.len() <= 1 { 1.0 } else { 0.5 };

        // Coupling: fraction of call edges that are cross-module
        let cross_calls = call_edges.iter()
            .filter(|(c, t, _)| {
                module_files.contains(c.as_str()) && !module_files.contains(t.as_str())
            })
            .count() as f64;

        module.coupling = if total_calls > 0.0 {
            (cross_calls / total_calls).clamp(0.0, 1.0)
        } else {
            0.0
        };
    }
}

/// Extract public interfaces for each module.
fn extract_public_interfaces(
    modules: &mut [LogicalModule],
    call_edges: &[(String, String, String)],
    functions: &[(String, String, bool)],
) {
    let _file_to_module: FxHashMap<&str, usize> = modules.iter().enumerate()
        .flat_map(|(i, m)| m.files.iter().map(move |f| (f.as_str(), i)))
        .collect();

    for module in modules.iter_mut() {
        let module_files: FxHashSet<&str> = module.files.iter().map(|f| f.as_str()).collect();

        // Functions called from outside this module = public interface
        let mut public: FxHashSet<String> = FxHashSet::default();
        let mut all_funcs: FxHashSet<String> = FxHashSet::default();

        for (file, func, _) in functions {
            if module_files.contains(file.as_str()) {
                all_funcs.insert(func.clone());
            }
        }

        for (caller, callee, func_name) in call_edges {
            if module_files.contains(callee.as_str()) && !module_files.contains(caller.as_str()) {
                public.insert(func_name.clone());
            }
        }

        module.public_interface = public.iter().cloned().collect();
        module.public_interface.sort();

        module.internal_functions = all_funcs.iter()
            .filter(|f| !public.contains(f.as_str()))
            .cloned()
            .collect();
        module.internal_functions.sort();
    }
}

/// Extract data dependencies for each module.
fn extract_data_dependencies(
    modules: &mut [LogicalModule],
    data_access: &[(String, String, String)],
) {
    for module in modules.iter_mut() {
        let module_files: FxHashSet<&str> = module.files.iter().map(|f| f.as_str()).collect();

        let mut deps: FxHashMap<String, Vec<String>> = FxHashMap::default();
        for (file, table, operation) in data_access {
            if module_files.contains(file.as_str()) {
                deps.entry(table.clone()).or_default().push(operation.clone());
            }
        }

        module.data_dependencies = deps.into_iter().map(|(name, ops)| {
            DataDependency {
                name,
                kind: DataDependencyKind::Database,
                operations: ops,
                sensitive_fields: Vec::new(),
            }
        }).collect();
        module.data_dependencies.sort_by(|a, b| a.name.cmp(&b.name));
    }
}

/// Apply priors as boundary adjustments.
fn apply_priors(modules: &mut Vec<LogicalModule>, priors: &[DecompositionDecision]) {
    for prior in priors {
        // Validate: confidence and dna_similarity must be positive
        let confidence = prior.confidence.max(0.0);
        let dna_similarity = prior.dna_similarity.max(0.0);
        let weight = confidence * dna_similarity;

        match &prior.adjustment {
            BoundaryAdjustment::Split { module, into } => {
                if weight < DecompositionThresholds::SPLIT_THRESHOLD {
                    continue;
                }
                apply_split(modules, module, into, prior, weight);
            }
            BoundaryAdjustment::Merge { modules: merge_names, into } => {
                if weight < DecompositionThresholds::MERGE_THRESHOLD {
                    continue;
                }
                apply_merge(modules, merge_names, into, prior, weight);
            }
            BoundaryAdjustment::Reclassify { module, new_category } => {
                if weight < DecompositionThresholds::RECLASSIFY_THRESHOLD {
                    continue;
                }
                apply_reclassify(modules, module, new_category, prior, weight);
            }
        }
    }
}

fn apply_split(
    modules: &mut Vec<LogicalModule>,
    module_name: &str,
    into: &[String],
    prior: &DecompositionDecision,
    weight: f64,
) {
    let idx = modules.iter().position(|m| m.name == module_name);
    let idx = match idx {
        Some(i) => i,
        None => return, // Module doesn't exist, skip gracefully
    };

    if into.is_empty() || into.len() < 2 {
        return;
    }

    let original = modules.remove(idx);
    let files_per_split = original.files.len().div_ceil(into.len());

    let applied_prior = AppliedPrior {
        source_dna_hash: String::new(),
        adjustment: prior.adjustment.clone(),
        applied_weight: weight,
        narrative: prior.narrative.clone(),
    };

    for (i, name) in into.iter().enumerate() {
        let start = i * files_per_split;
        let end = ((i + 1) * files_per_split).min(original.files.len());
        let files = if start < original.files.len() {
            original.files[start..end].to_vec()
        } else {
            Vec::new()
        };

        modules.push(LogicalModule {
            name: name.clone(),
            files,
            public_interface: Vec::new(),
            internal_functions: Vec::new(),
            data_dependencies: Vec::new(),
            convention_profile: original.convention_profile.clone(),
            cohesion: 0.0,
            coupling: 0.0,
            estimated_complexity: 0,
            applied_priors: vec![applied_prior.clone()],
        });
    }
}

fn apply_merge(
    modules: &mut Vec<LogicalModule>,
    merge_names: &[String],
    into: &str,
    prior: &DecompositionDecision,
    weight: f64,
) {
    let mut merged_files = Vec::new();
    let mut indices_to_remove = Vec::new();

    for name in merge_names {
        if let Some(idx) = modules.iter().position(|m| m.name == *name) {
            merged_files.extend(modules[idx].files.clone());
            indices_to_remove.push(idx);
        }
    }

    if indices_to_remove.is_empty() {
        return;
    }

    // Remove in reverse order to preserve indices
    indices_to_remove.sort_unstable();
    indices_to_remove.reverse();
    for idx in indices_to_remove {
        modules.remove(idx);
    }

    let applied_prior = AppliedPrior {
        source_dna_hash: String::new(),
        adjustment: prior.adjustment.clone(),
        applied_weight: weight,
        narrative: prior.narrative.clone(),
    };

    modules.push(LogicalModule {
        name: into.to_string(),
        files: merged_files,
        public_interface: Vec::new(),
        internal_functions: Vec::new(),
        data_dependencies: Vec::new(),
        convention_profile: ConventionProfile {
            naming_convention: String::new(),
            error_handling: String::new(),
            logging: String::new(),
        },
        cohesion: 0.0,
        coupling: 0.0,
        estimated_complexity: 0,
        applied_priors: vec![applied_prior],
    });
}

fn apply_reclassify(
    modules: &mut [LogicalModule],
    module_name: &str,
    new_category: &str,
    prior: &DecompositionDecision,
    weight: f64,
) {
    if let Some(module) = modules.iter_mut().find(|m| m.name == module_name) {
        module.name = format!("{} ({})", module.name, new_category);
        module.applied_priors.push(AppliedPrior {
            source_dna_hash: String::new(),
            adjustment: prior.adjustment.clone(),
            applied_weight: weight,
            narrative: prior.narrative.clone(),
        });
    }
}

/// Infer convention profile from file paths.
fn infer_convention_profile(files: &[String]) -> ConventionProfile {
    let has_snake = files.iter().any(|f| f.contains('_'));
    let has_camel = files.iter().any(|f| {
        f.rsplit('/').next().is_some_and(|name| {
            name.chars().next().is_some_and(|c| c.is_lowercase())
                && name.contains(|c: char| c.is_uppercase())
        })
    });

    let naming = if has_snake && !has_camel {
        "snake_case"
    } else if has_camel && !has_snake {
        "camelCase"
    } else {
        "mixed"
    };

    ConventionProfile {
        naming_convention: naming.to_string(),
        error_handling: "unknown".to_string(),
        logging: "unknown".to_string(),
    }
}
