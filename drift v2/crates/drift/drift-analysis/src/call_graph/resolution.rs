//! 6 resolution strategies: SameFile, MethodCall, DiInjection, ImportBased, ExportBased, Fuzzy.
//! First match wins — strategies are tried in order of decreasing confidence.

use drift_core::types::collections::FxHashMap;

use crate::parsers::types::{CallSite, ImportInfo};

use super::tsconfig::AliasRule;
use super::types::Resolution;

/// Names too common for fuzzy resolution — matching these produces false positives.
const FUZZY_BLOCKLIST: &[&str] = &[
    "get", "set", "run", "init", "start", "stop", "open", "close",
    "read", "write", "create", "update", "delete", "find", "filter",
    "map", "reduce", "forEach", "push", "pop", "add", "remove",
    "send", "receive", "call", "apply", "bind", "new", "make",
    "build", "parse", "format", "render", "handle", "process",
    "execute", "dispatch", "emit", "on", "off", "then", "catch",
    "resolve", "reject", "next", "done", "log", "print", "debug",
    "error", "warn", "info", "toString", "valueOf", "clone",
    "equals", "compare", "sort", "merge", "split", "join", "trim",
    "replace", "match", "test", "check", "validate", "verify",
    "load", "save", "reset", "clear", "flush", "sync", "async",
    "wait", "sleep", "yield", "return", "throw", "raise",
];

/// Language family groupings for fuzzy resolution scoping.
fn language_family(lang: &str) -> u8 {
    let l = lang.to_lowercase();
    if l == "typescript" || l == "javascript" || l == "tsx" || l == "jsx" {
        1
    } else if l == "python" {
        2
    } else if l == "java" || l == "kotlin" {
        3
    } else if l == "go" {
        4
    } else if l == "rust" {
        5
    } else if l == "csharp" || l == "c#" {
        6
    } else if l == "ruby" {
        7
    } else if l == "php" {
        8
    } else {
        0
    }
}

/// Diagnostics for resolution tracking (CG-RES-12).
#[derive(Debug, Clone, Default)]
pub struct ResolutionDiagnostics {
    pub total_call_sites: usize,
    pub resolved: usize,
    pub unresolved: usize,
    pub by_strategy: FxHashMap<String, usize>,
    pub by_language: FxHashMap<String, (usize, usize)>, // (resolved, total)
}

impl ResolutionDiagnostics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, strategy: Option<&Resolution>, language: &str) {
        self.total_call_sites += 1;
        let lang_entry = self.by_language.entry(language.to_string()).or_insert((0, 0));
        lang_entry.1 += 1;

        if let Some(s) = strategy {
            self.resolved += 1;
            *self.by_strategy.entry(s.name().to_string()).or_default() += 1;
            lang_entry.0 += 1;
        } else {
            self.unresolved += 1;
        }
    }

    pub fn resolution_rate(&self) -> f64 {
        if self.total_call_sites == 0 {
            0.0
        } else {
            self.resolved as f64 / self.total_call_sites as f64
        }
    }

    pub fn low_resolution_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        for (lang, (resolved, total)) in &self.by_language {
            if *total > 0 {
                let rate = *resolved as f64 / *total as f64;
                if rate < 0.30 {
                    warnings.push(format!(
                        "Low resolution rate for {}: {:.1}% ({}/{})",
                        lang, rate * 100.0, resolved, total
                    ));
                }
            }
        }
        warnings
    }
}

/// Attempt to resolve a call site to a callee function key.
///
/// Tries strategies in order: SameFile → MethodCall → ImportBased → ExportBased → Fuzzy.
/// Returns the callee key and the resolution strategy used.
///
/// When `alias_rules` is non-empty, import sources are also resolved through
/// tsconfig path aliases (e.g. `@/components/Button` → `src/components/Button`).
#[allow(clippy::too_many_arguments)]
pub fn resolve_call(
    call_site: &CallSite,
    caller_file: &str,
    caller_language: &str,
    imports: &[ImportInfo],
    name_index: &FxHashMap<String, Vec<String>>,
    qualified_index: &FxHashMap<String, String>,
    export_index: &FxHashMap<String, Vec<String>>,
    language_index: &FxHashMap<String, String>,
    alias_rules: &[AliasRule],
) -> Option<(String, Resolution)> {
    // Strategy 1: Same-file direct call (confidence 0.95)
    if let Some(result) = resolve_same_file(call_site, caller_file, name_index) {
        return Some((result, Resolution::SameFile));
    }

    // Strategy 2: Method call on known receiver (confidence 0.90)
    if let Some(result) = resolve_method_call(call_site, caller_file, imports, qualified_index, name_index, alias_rules) {
        return Some((result, Resolution::MethodCall));
    }

    // Strategy 3: Import-based resolution (confidence 0.75)
    if let Some(result) = resolve_import_based(call_site, imports, name_index, alias_rules) {
        return Some((result, Resolution::ImportBased));
    }

    // Strategy 4: Export-based cross-module (confidence 0.60)
    if let Some(result) = resolve_export_based(call_site, caller_file, caller_language, imports, export_index, language_index, alias_rules) {
        return Some((result, Resolution::ExportBased));
    }

    // Strategy 5: Fuzzy name matching (confidence 0.40)
    if let Some(result) = resolve_fuzzy(call_site, caller_language, name_index, language_index) {
        return Some((result, Resolution::Fuzzy));
    }

    None
}

/// Same-file resolution: callee is in the same file as caller.
fn resolve_same_file(
    call_site: &CallSite,
    caller_file: &str,
    name_index: &FxHashMap<String, Vec<String>>,
) -> Option<String> {
    let callee_name = &call_site.callee_name;
    if let Some(keys) = name_index.get(callee_name) {
        let same_file_key = format!("{}::{}", caller_file, callee_name);
        if keys.contains(&same_file_key) {
            return Some(same_file_key);
        }
    }
    None
}

/// Method call resolution: receiver.method() → Class.method qualified name.
/// Enhanced (CG-RES-09): also resolves via import context when receiver is an import alias.
fn resolve_method_call(
    call_site: &CallSite,
    caller_file: &str,
    imports: &[ImportInfo],
    qualified_index: &FxHashMap<String, String>,
    name_index: &FxHashMap<String, Vec<String>>,
    alias_rules: &[AliasRule],
) -> Option<String> {
    let receiver = match call_site.receiver {
        Some(ref r) => r,
        None => return None,
    };

    // Try direct qualified name lookup: Receiver.method
    let qualified = format!("{}.{}", receiver, call_site.callee_name);
    if let Some(key) = qualified_index.get(&qualified) {
        return Some(key.clone());
    }

    // CG-RES-09: If receiver matches an import alias, resolve method from source module
    // e.g., `import * as utils from './utils'` → utils.foo() resolves foo from ./utils
    for import in imports {
        // Check namespace imports: receiver matches import alias or a specifier alias
        let is_namespace = import.specifiers.is_empty()
            || import.specifiers.iter().any(|s| {
                s.alias.as_deref() == Some(receiver) || s.name == *receiver
            });

        if is_namespace || import.specifiers.iter().any(|s| s.alias.as_deref() == Some(receiver)) {
            if let Some(keys) = name_index.get(&call_site.callee_name) {
                // Try original source first, then alias-resolved source
                let resolved = super::tsconfig::resolve_alias(&import.source, alias_rules);
                for key in keys {
                    if key.contains(&import.source) {
                        return Some(key.clone());
                    }
                    if let Some(ref resolved_src) = resolved {
                        if key.to_lowercase().contains(&resolved_src.to_lowercase()) {
                            return Some(key.clone());
                        }
                    }
                }
            }
        }
    }

    // Try same-file qualified: look for ClassName.method in current file
    if let Some(keys) = name_index.get(&call_site.callee_name) {
        let same_file_prefix = format!("{}::", caller_file);
        for key in keys {
            if key.starts_with(&same_file_prefix) {
                // Check if qualified_index has receiver.callee pointing to this
                return Some(key.clone());
            }
        }
    }

    None
}

/// Import-based resolution: callee is imported from another module.
/// CG-RES-01: improved module path matching
/// CG-RES-02: default import handling
/// CG-RES-03: namespace import handling
fn resolve_import_based(
    call_site: &CallSite,
    imports: &[ImportInfo],
    name_index: &FxHashMap<String, Vec<String>>,
    alias_rules: &[AliasRule],
) -> Option<String> {
    let callee_name = &call_site.callee_name;

    for import in imports {
        // CG-RES-03: Namespace import — import * as utils from './utils'
        // Call: utils.foo() → receiver=utils, callee_name=foo
        if let Some(ref receiver) = call_site.receiver {
            // Check if any specifier's alias matches the receiver
            let is_namespace_match = import.specifiers.iter().any(|s| {
                s.alias.as_deref() == Some(receiver.as_str())
            });
            if is_namespace_match {
                if let Some(keys) = name_index.get(callee_name) {
                    if let Some(key) = best_key_for_source(keys, &import.source, alias_rules) {
                        return Some(key);
                    }
                    if let Some(key) = keys.first() {
                        return Some(key.clone());
                    }
                }
            }
        }

        // Named specifiers: import { foo, bar as baz } from './module'
        for spec in &import.specifiers {
            let effective_name = spec.alias.as_deref().unwrap_or(&spec.name);
            if effective_name == callee_name {
                if let Some(keys) = name_index.get(&spec.name) {
                    if let Some(key) = best_key_for_source(keys, &import.source, alias_rules) {
                        return Some(key);
                    }
                    return keys.first().cloned();
                }
            }
        }

        // CG-RES-02: Default import — import React from 'react'
        if import.specifiers.is_empty() {
            if let Some(keys) = name_index.get(callee_name) {
                if let Some(key) = best_key_for_source(keys, &import.source, alias_rules) {
                    return Some(key);
                }
            }
        } else if import.specifiers.len() == 1 {
            let spec = &import.specifiers[0];
            let is_default = spec.name == "default"
                || (spec.alias.is_some() && spec.alias.as_deref() != Some(&spec.name));
            if is_default {
                let alias = spec.alias.as_deref().unwrap_or(&spec.name);
                if alias == callee_name {
                    if let Some(keys) = name_index.get(&spec.name) {
                        if let Some(key) = best_key_for_source(keys, &import.source, alias_rules) {
                            return Some(key);
                        }
                        return keys.first().cloned();
                    }
                    if let Some(keys) = name_index.get(callee_name) {
                        if let Some(key) = best_key_for_source(keys, &import.source, alias_rules) {
                            return Some(key);
                        }
                    }
                }
            }
        }
    }
    None
}

/// Find the best key matching a given import source module path.
/// Tries the original source first, then the alias-resolved source.
fn best_key_for_source(keys: &[String], source: &str, alias_rules: &[AliasRule]) -> Option<String> {
    if let Some(found) = best_key_for_normalized(keys, source) {
        return Some(found);
    }
    // Try alias-resolved source
    if let Some(resolved) = super::tsconfig::resolve_alias(source, alias_rules) {
        if let Some(found) = best_key_for_normalized(keys, &resolved) {
            return Some(found);
        }
    }
    None
}

/// Match a normalized source path against available keys.
fn best_key_for_normalized(keys: &[String], source: &str) -> Option<String> {
    let normalized = normalize_module_path(source);

    for key in keys {
        let key_lower = key.to_lowercase();
        let norm_lower = normalized.to_lowercase();
        if key_lower.contains(&norm_lower) {
            return Some(key.clone());
        }
    }

    if let Some(last) = normalized.rsplit('/').next() {
        let last_lower = last.to_lowercase();
        for key in keys {
            let key_lower = key.to_lowercase();
            if let Some(file_part) = key_lower.split("::").next() {
                if file_part.contains(&last_lower) {
                    return Some(key.clone());
                }
            }
        }
    }

    None
}

/// Normalize a module path by stripping relative prefixes and extensions.
fn normalize_module_path(source: &str) -> String {
    let mut s = source.to_string();
    // Strip relative prefixes
    while s.starts_with("./") {
        s = s[2..].to_string();
    }
    while s.starts_with("../") {
        s = s[3..].to_string();
    }
    // Strip common extensions
    for ext in &[".ts", ".tsx", ".js", ".jsx", ".py", ".java", ".go", ".rs", ".rb", ".php", ".cs", ".kt"] {
        if s.ends_with(ext) {
            s = s[..s.len() - ext.len()].to_string();
            break;
        }
    }
    s
}

/// Export-based resolution: callee is exported from some module.
/// CG-RES-04: Multi-match disambiguation by import, language, directory proximity.
fn resolve_export_based(
    call_site: &CallSite,
    caller_file: &str,
    caller_language: &str,
    imports: &[ImportInfo],
    export_index: &FxHashMap<String, Vec<String>>,
    language_index: &FxHashMap<String, String>,
    alias_rules: &[AliasRule],
) -> Option<String> {
    let keys = export_index.get(&call_site.callee_name)?;

    if keys.len() == 1 {
        return Some(keys[0].clone());
    }

    // CG-RES-04: Multi-match disambiguation
    for key in keys {
        let exporter_file = key.split("::").next().unwrap_or("");
        for import in imports {
            let normalized = normalize_module_path(&import.source);
            let exporter_lower = exporter_file.to_lowercase();
            let norm_lower = normalized.to_lowercase();
            if exporter_lower.contains(&norm_lower)
                || norm_lower.contains(
                    &exporter_lower.replace(".ts", "").replace(".js", "")
                ) {
                return Some(key.clone());
            }
            // Also try alias-resolved source
            if let Some(resolved) = super::tsconfig::resolve_alias(&import.source, alias_rules) {
                let resolved_norm = normalize_module_path(&resolved).to_lowercase();
                if exporter_lower.contains(&resolved_norm)
                    || resolved_norm.contains(
                        &exporter_lower.replace(".ts", "").replace(".js", "")
                    ) {
                    return Some(key.clone());
                }
            }
        }
    }

    // 2. Prefer same-language match
    let caller_family = language_family(caller_language);
    let same_lang: Vec<&String> = keys.iter().filter(|k| {
        language_index.get(*k)
            .map(|l| language_family(l) == caller_family)
            .unwrap_or(false)
    }).collect();
    if same_lang.len() == 1 {
        return Some(same_lang[0].clone());
    }

    // 3. Prefer closest directory match
    let caller_dir = caller_file.rsplit('/').skip(1).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("/");
    let mut best_key: Option<&String> = None;
    let mut best_prefix_len = 0;
    for key in keys {
        let key_file = key.split("::").next().unwrap_or("");
        let key_dir = key_file.rsplit('/').skip(1).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("/");
        let common = common_prefix_length(&caller_dir, &key_dir);
        if common > best_prefix_len {
            best_prefix_len = common;
            best_key = Some(key);
        }
    }
    if let Some(key) = best_key {
        return Some(key.clone());
    }

    None
}

/// Compute length of common path prefix.
fn common_prefix_length(a: &str, b: &str) -> usize {
    a.chars().zip(b.chars()).take_while(|(ca, cb)| ca == cb).count()
}

/// Fuzzy name matching: last resort, lowest confidence.
/// CG-RES-10: Language-scoped filtering.
/// CG-RES-11: Blocklist for common names.
fn resolve_fuzzy(
    call_site: &CallSite,
    caller_language: &str,
    name_index: &FxHashMap<String, Vec<String>>,
    language_index: &FxHashMap<String, String>,
) -> Option<String> {
    // CG-RES-11: Blocklist — never fuzzy-resolve common names
    if is_fuzzy_blocked(&call_site.callee_name) {
        return None;
    }

    let keys = name_index.get(&call_site.callee_name)?;

    // CG-RES-10: Filter by language family first
    let caller_family = language_family(caller_language);
    if caller_family != 0 {
        let same_lang: Vec<&String> = keys.iter().filter(|k| {
            language_index.get(*k)
                .map(|l| language_family(l) == caller_family)
                .unwrap_or(false)
        }).collect();

        if same_lang.len() == 1 {
            return Some(same_lang[0].clone());
        }
        // If language filtering narrows but not to 1, don't fuzzy-resolve
        if !same_lang.is_empty() {
            return None;
        }
    }

    // Fall back: only if exactly one match globally
    if keys.len() == 1 {
        return Some(keys[0].clone());
    }

    None
}

/// Check if a name is on the fuzzy blocklist.
pub fn is_fuzzy_blocked(name: &str) -> bool {
    let lower = name.to_lowercase();
    FUZZY_BLOCKLIST.iter().any(|b| b.to_lowercase() == lower)
}

/// Resolve a constructor call (new ClassName()).
pub fn resolve_constructor(
    class_name: &str,
    qualified_index: &FxHashMap<String, String>,
    name_index: &FxHashMap<String, Vec<String>>,
) -> Option<(String, Resolution)> {
    // Try qualified constructor name
    let constructor_names = [
        format!("{}.constructor", class_name),
        format!("{}.__init__", class_name),
        format!("{}.new", class_name),
        format!("{}.init", class_name),
    ];

    for qn in &constructor_names {
        if let Some(key) = qualified_index.get(qn) {
            return Some((key.clone(), Resolution::MethodCall));
        }
    }

    // Fall back to class name as function
    if let Some(keys) = name_index.get(class_name) {
        if keys.len() == 1 {
            return Some((keys[0].clone(), Resolution::Fuzzy));
        }
    }

    None
}
