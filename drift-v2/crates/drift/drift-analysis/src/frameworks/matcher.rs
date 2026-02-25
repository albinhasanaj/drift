//! Framework pattern matcher — implements FileDetectorHandler.
//!
//! Takes compiled framework packs and matches their patterns against each
//! file's ParseResult data. Emits PatternMatch results with framework-qualified IDs.

use std::collections::HashMap;

use crate::engine::types::{DetectionMethod, PatternMatch};
use crate::engine::visitor::{DetectionContext, FileDetectorHandler};
use crate::scanner::language_detect::Language;

use super::diagnostics::FrameworkDiagnostics;
use super::loader::{CompiledCall, CompiledFrameworkPack, CompiledMatchBlock, CompiledPattern};

/// FileDetectorHandler that matches framework patterns against ParseResult.
pub struct FrameworkMatcher {
    /// Compiled framework packs to match against.
    packs: Vec<CompiledFrameworkPack>,
    /// Accumulated results across all files.
    results: Vec<PatternMatch>,
    /// All languages across all packs (for handler dispatch).
    all_languages: Vec<Language>,
    /// Index into `results` where the current file's matches begin.
    file_result_start: usize,
    /// Match diagnostics counters.
    files_processed: usize,
    files_matched: usize,
    hits_per_category: HashMap<String, usize>,
    hits_per_pack: HashMap<String, usize>,
    /// Per-file match limit (0 = unlimited).
    match_limit: usize,
    files_truncated: usize,
    /// Optional set of detected pack names for filtering.
    detected_packs: Option<Vec<String>>,
}

impl FrameworkMatcher {
    /// Create a new matcher with the given framework packs.
    pub fn new(packs: Vec<CompiledFrameworkPack>) -> Self {
        let all_languages: Vec<Language> = packs
            .iter()
            .flat_map(|p| p.languages.iter().copied())
            .collect();
        // Dedup without requiring Ord — just keep unique languages
        let mut seen = Vec::new();
        for lang in all_languages {
            if !seen.contains(&lang) {
                seen.push(lang);
            }
        }
        let all_languages = seen;

        Self {
            packs,
            results: Vec::new(),
            all_languages,
            file_result_start: 0,
            files_processed: 0,
            files_matched: 0,
            hits_per_category: HashMap::new(),
            hits_per_pack: HashMap::new(),
            match_limit: 100,
            files_truncated: 0,
            detected_packs: None,
        }
    }

    /// Number of loaded framework packs.
    pub fn pack_count(&self) -> usize {
        self.packs.len()
    }

    /// Total number of patterns across all packs.
    pub fn pattern_count(&self) -> usize {
        self.packs.iter().map(|p| p.patterns.len()).sum()
    }

    /// Set per-file match limit (0 = unlimited).
    pub fn set_match_limit(&mut self, limit: usize) {
        self.match_limit = limit;
    }

    /// Set detected pack names for filtering. Only these packs (plus packs
    /// with no detect_signals) will be iterated during matching.
    pub fn set_detected_packs(&mut self, detected: Vec<String>) {
        self.detected_packs = Some(detected);
    }

    /// Get the matches produced by the most recent `analyze_file()` call.
    pub fn last_file_results(&self) -> &[PatternMatch] {
        &self.results[self.file_result_start..]
    }

    /// Get match-time diagnostics.
    pub fn match_diagnostics(&self) -> FrameworkDiagnostics {
        FrameworkDiagnostics {
            files_processed: self.files_processed,
            files_matched: self.files_matched,
            total_hits: self.results.len(),
            hits_per_category: self.hits_per_category.clone(),
            hits_per_pack: self.hits_per_pack.clone(),
            files_truncated: self.files_truncated,
            ..Default::default()
        }
    }
}

impl FileDetectorHandler for FrameworkMatcher {
    fn id(&self) -> &str {
        "framework-matcher"
    }

    fn languages(&self) -> &[Language] {
        &self.all_languages
    }

    fn analyze_file(&mut self, ctx: &DetectionContext) {
        self.file_result_start = self.results.len();
        self.files_processed += 1;
        let pre_count = self.results.len();
        for pack in &self.packs {
            // Skip packs that don't target this language
            if !pack.languages.contains(&ctx.language) {
                continue;
            }

            // Skip non-detected packs when filtering is enabled
            if let Some(ref detected) = self.detected_packs {
                if !pack.detect_signals.is_empty() && !detected.contains(&pack.name) {
                    continue;
                }
            }

            for pattern in &pack.patterns {
                // Check language narrowing
                if let Some(lang) = pattern.match_block.language {
                    if lang != ctx.language {
                        continue;
                    }
                }

                // Try to match this pattern against the file
                let matches = match_pattern(pattern, ctx);
                for m in &matches {
                    *self.hits_per_category.entry(format!("{:?}", m.category)).or_insert(0) += 1;
                    *self.hits_per_pack.entry(pack.name.clone()).or_insert(0) += 1;
                }
                self.results.extend(matches);
            }
        }
        if self.results.len() > pre_count {
            self.files_matched += 1;
        }
        // Check per-file limit
        let file_hits = self.results.len() - self.file_result_start;
        if self.match_limit > 0 && file_hits > self.match_limit {
            self.results.truncate(self.file_result_start + self.match_limit);
            self.files_truncated += 1;
            // Only emit warning when not in quiet mode (DRIFT_QUIET=1)
            if std::env::var("DRIFT_QUIET").as_deref() != Ok("1") {
                eprintln!(
                    "[drift] warning: match limit ({}) reached for file '{}', truncating",
                    self.match_limit, ctx.file
                );
            }
        }
    }

    fn results(&self) -> Vec<PatternMatch> {
        self.results.clone()
    }

    fn reset(&mut self) {
        self.results.clear();
    }
}

/// Public entry point for matching a pattern (used by learner).
pub fn match_pattern_pub(pattern: &CompiledPattern, ctx: &DetectionContext) -> Vec<PatternMatch> {
    match_pattern(pattern, ctx)
}

/// Match a compiled pattern against a detection context.
/// Returns all match locations found in the file.
fn match_pattern(pattern: &CompiledPattern, ctx: &DetectionContext) -> Vec<PatternMatch> {
    let block = &pattern.match_block;
    let mut matches = Vec::new();

    // Determine which predicate types are specified (non-empty).
    // For structural predicates (imports, decorators, calls, etc.),
    // we collect match locations. A pattern fires if ALL specified
    // predicate types have at least one match.
    let mut has_any_predicate = false;

    // --- File pattern matching (fail-fast AND) ---
    if !block.file_patterns.is_empty() {
        has_any_predicate = true;
        let file_matches = block.file_patterns.iter().any(|glob| glob.matches(ctx.file));
        if !file_matches {
            return Vec::new();
        }
        // file_patterns is a filter predicate — don't produce match locations.
        // Other predicates will produce the actual matches.
    }

    // --- Import matching (Aho-Corasick fast path) ---
    if !block.imports.is_empty() {
        has_any_predicate = true;
        let import_matches: Vec<(u32, String)> = ctx
            .imports
            .iter()
            .filter(|imp| {
                if let Some(ref ac) = block.import_ac {
                    ac.is_match(&imp.source)
                } else {
                    let src_lower = imp.source.to_lowercase();
                    block.imports.iter().any(|pat| src_lower.contains(&pat.to_lowercase()))
                }
            })
            .map(|imp| (imp.line, format!("import: {}", imp.source)))
            .collect();
        if import_matches.is_empty() {
            return Vec::new(); // AND: this predicate failed
        }
        for (line, text) in import_matches {
            matches.push(make_match(pattern, ctx, line, 0, &text));
        }
    }

    // --- Decorator matching (Aho-Corasick fast path) ---
    if !block.decorators.is_empty() {
        has_any_predicate = true;
        let mut dec_matches = Vec::new();

        let dec_matches_name = |name: &str| -> bool {
            if let Some(ref ac) = block.decorator_ac {
                ac.is_match(name)
            } else {
                block.decorators.contains(&name.to_string())
            }
        };

        // Check class decorators
        for class in ctx.classes {
            for dec in &class.decorators {
                if dec_matches_name(&dec.name) {
                    dec_matches.push((
                        dec.range.start.line,
                        dec.range.start.column,
                        format!("@{} on class {}", dec.name, class.name),
                    ));
                }
            }
            // Check method decorators
            for method in &class.methods {
                for dec in &method.decorators {
                    if dec_matches_name(&dec.name) {
                        dec_matches.push((
                            dec.range.start.line,
                            dec.range.start.column,
                            format!("@{} on {}.{}", dec.name, class.name, method.name),
                        ));
                    }
                }
            }
        }

        // Check function decorators
        for func in ctx.functions {
            for dec in &func.decorators {
                if dec_matches_name(&dec.name) {
                    dec_matches.push((
                        dec.range.start.line,
                        dec.range.start.column,
                        format!("@{} on {}", dec.name, func.name),
                    ));
                }
            }
        }

        if dec_matches.is_empty() {
            return Vec::new();
        }
        for (line, col, text) in dec_matches {
            matches.push(make_match(pattern, ctx, line, col, &text));
        }
    }

    // --- Call site matching ---
    if !block.calls.is_empty() {
        has_any_predicate = true;
        let call_matches: Vec<(u32, u32, String)> = ctx
            .call_sites
            .iter()
            .filter(|call| call_matches_any(call, &block.calls))
            .map(|call| {
                let text = if let Some(recv) = &call.receiver {
                    format!("{}.{}", recv, call.callee_name)
                } else {
                    call.callee_name.clone()
                };
                (call.line, call.column, text)
            })
            .collect();
        if call_matches.is_empty() {
            return Vec::new();
        }
        for (line, col, text) in call_matches {
            matches.push(make_match(pattern, ctx, line, col, &text));
        }
    }

    // --- Class extends matching (Aho-Corasick fast path) ---
    if !block.extends.is_empty() {
        has_any_predicate = true;
        let ext_matches: Vec<(u32, u32, String)> = ctx
            .classes
            .iter()
            .filter(|class| {
                class.extends.as_ref().is_some_and(|ext| {
                    if let Some(ref ac) = block.extends_ac {
                        ac.is_match(ext)
                    } else {
                        block.extends.iter().any(|pat| ext.contains(pat))
                    }
                })
            })
            .map(|class| {
                (
                    class.range.start.line,
                    class.range.start.column,
                    format!(
                        "{} extends {}",
                        class.name,
                        class.extends.as_deref().unwrap_or("?")
                    ),
                )
            })
            .collect();
        if ext_matches.is_empty() {
            return Vec::new();
        }
        for (line, col, text) in ext_matches {
            matches.push(make_match(pattern, ctx, line, col, &text));
        }
    }

    // --- Class implements matching (Aho-Corasick fast path) ---
    if !block.implements.is_empty() {
        has_any_predicate = true;
        let impl_matches: Vec<(u32, u32, String)> = ctx
            .classes
            .iter()
            .filter(|class| {
                class.implements.iter().any(|imp| {
                    if let Some(ref ac) = block.implements_ac {
                        ac.is_match(imp)
                    } else {
                        block.implements.iter().any(|pat| imp.contains(pat))
                    }
                })
            })
            .map(|class| {
                (
                    class.range.start.line,
                    class.range.start.column,
                    format!("{} implements {:?}", class.name, class.implements),
                )
            })
            .collect();
        if impl_matches.is_empty() {
            return Vec::new();
        }
        for (line, col, text) in impl_matches {
            matches.push(make_match(pattern, ctx, line, col, &text));
        }
    }

    // --- Function name matching (RegexSet fast path) ---
    if !block.function_names.is_empty() {
        has_any_predicate = true;
        let fn_matches: Vec<(u32, u32, String)> = ctx
            .functions
            .iter()
            .filter(|f| {
                if let Some(ref rs) = block.function_name_regex_set {
                    rs.is_match(&f.name)
                } else {
                    block.function_names.iter().any(|re| re.is_match(&f.name))
                }
            })
            .map(|f| (f.line, f.column, format!("function: {}", f.name)))
            .collect();
        if fn_matches.is_empty() {
            return Vec::new();
        }
        for (line, col, text) in fn_matches {
            matches.push(make_match(pattern, ctx, line, col, &text));
        }
    }

    // --- Class name matching (RegexSet fast path) ---
    if !block.class_names.is_empty() {
        has_any_predicate = true;
        let cls_matches: Vec<(u32, u32, String)> = ctx
            .classes
            .iter()
            .filter(|c| {
                if let Some(ref rs) = block.class_name_regex_set {
                    rs.is_match(&c.name)
                } else {
                    block.class_names.iter().any(|re| re.is_match(&c.name))
                }
            })
            .map(|c| {
                (
                    c.range.start.line,
                    c.range.start.column,
                    format!("class: {}", c.name),
                )
            })
            .collect();
        if cls_matches.is_empty() {
            return Vec::new();
        }
        for (line, col, text) in cls_matches {
            matches.push(make_match(pattern, ctx, line, col, &text));
        }
    }

    // --- String literal matching (RegexSet fast path) ---
    if !block.string_literals.is_empty() {
        has_any_predicate = true;
        let str_matches: Vec<(u32, u32, String)> = ctx
            .parse_result
            .string_literals
            .iter()
            .filter(|s| {
                if let Some(ref rs) = block.string_literal_regex_set {
                    rs.is_match(&s.value)
                } else {
                    block.string_literals.iter().any(|re| re.is_match(&s.value))
                }
            })
            .map(|s| (s.line, s.column, format!("string: {}", s.value)))
            .collect();
        if str_matches.is_empty() {
            return Vec::new();
        }
        for (line, col, text) in str_matches {
            matches.push(make_match(pattern, ctx, line, col, &text));
        }
    }

    // --- Parameter type matching ---
    if !block.param_types.is_empty() {
        has_any_predicate = true;
        let param_matches: Vec<(u32, u32, String)> = ctx
            .functions
            .iter()
            .filter(|f| {
                f.parameters.iter().any(|p| {
                    p.type_annotation.as_ref().is_some_and(|ta| {
                        block.param_types.iter().any(|pat| ta.contains(pat))
                    })
                })
            })
            .map(|f| (f.line, f.column, format!("param type in {}", f.name)))
            .collect();
        if param_matches.is_empty() {
            return Vec::new();
        }
        for (line, col, text) in param_matches {
            matches.push(make_match(pattern, ctx, line, col, &text));
        }
    }

    // --- Return type matching ---
    if !block.return_types.is_empty() {
        has_any_predicate = true;
        let ret_matches: Vec<(u32, u32, String)> = ctx
            .functions
            .iter()
            .filter(|f| {
                f.return_type.as_ref().is_some_and(|rt| {
                    block.return_types.iter().any(|pat| rt.contains(pat))
                })
            })
            .map(|f| (f.line, f.column, format!("return type in {}", f.name)))
            .collect();
        if ret_matches.is_empty() {
            return Vec::new();
        }
        for (line, col, text) in ret_matches {
            matches.push(make_match(pattern, ctx, line, col, &text));
        }
    }

    // --- Content pattern matching (RegexSet fast path + regex on source lines) ---
    if !block.content_patterns.is_empty() {
        has_any_predicate = true;
        let source_str = String::from_utf8_lossy(ctx.source);
        let mut content_matches = Vec::new();
        for (line_idx, line) in source_str.lines().enumerate() {
            // RegexSet fast-path: skip line if no pattern in the set matches
            if let Some(ref rs) = block.content_regex_set {
                if !rs.is_match(line) {
                    continue;
                }
            }
            for re in &block.content_patterns {
                if let Some(m) = re.find(line) {
                    content_matches.push((
                        (line_idx + 1) as u32,
                        m.start() as u32,
                        format!("content: {}", &line[m.start()..m.end()]),
                    ));
                }
            }
        }
        if content_matches.is_empty() {
            return Vec::new();
        }
        for (line, col, text) in content_matches {
            matches.push(make_match(pattern, ctx, line, col, &text));
        }
    }

    // --- Export matching ---
    if !block.exports.is_empty() {
        has_any_predicate = true;
        let exp_matches: Vec<(u32, String)> = ctx
            .exports
            .iter()
            .filter(|exp| {
                exp.name.as_ref().is_some_and(|n| {
                    block.exports.iter().any(|pat| n.contains(pat))
                })
            })
            .map(|exp| {
                (
                    exp.line,
                    format!("export: {}", exp.name.as_deref().unwrap_or("default")),
                )
            })
            .collect();
        if exp_matches.is_empty() {
            return Vec::new();
        }
        for (line, text) in exp_matches {
            matches.push(make_match(pattern, ctx, line, 0, &text));
        }
    }

    // --- Error handling matching ---
    if !block.error_handling.is_empty() {
        has_any_predicate = true;
        let err_matches: Vec<(u32, String)> = ctx
            .parse_result
            .error_handling
            .iter()
            .filter(|eh| {
                let kind_str = format!("{:?}", eh.kind);
                block
                    .error_handling
                    .iter()
                    .any(|pat| kind_str.eq_ignore_ascii_case(pat))
            })
            .map(|eh| (eh.line, format!("error handling: {:?}", eh.kind)))
            .collect();
        if err_matches.is_empty() {
            return Vec::new();
        }
        for (line, text) in err_matches {
            matches.push(make_match(pattern, ctx, line, 0, &text));
        }
    }

    // --- Type annotation matching (RegexSet fast path + regex on params + return types) ---
    if !block.type_annotations.is_empty() {
        has_any_predicate = true;
        let mut ta_matches = Vec::new();
        for f in ctx.functions {
            for p in &f.parameters {
                if let Some(ref ta) = p.type_annotation {
                    let matches_ta = if let Some(ref rs) = block.type_annotation_regex_set {
                        rs.is_match(ta)
                    } else {
                        block.type_annotations.iter().any(|re| re.is_match(ta))
                    };
                    if matches_ta {
                        ta_matches.push((f.line, f.column, format!("type annotation: {} in {}", ta, f.name)));
                    }
                }
            }
            if let Some(ref rt) = f.return_type {
                let matches_rt = if let Some(ref rs) = block.type_annotation_regex_set {
                    rs.is_match(rt)
                } else {
                    block.type_annotations.iter().any(|re| re.is_match(rt))
                };
                if matches_rt {
                    ta_matches.push((f.line, f.column, format!("return type: {} in {}", rt, f.name)));
                }
            }
        }
        if ta_matches.is_empty() {
            return Vec::new();
        }
        for (line, col, text) in ta_matches {
            matches.push(make_match(pattern, ctx, line, col, &text));
        }
    }

    // --- Doc comment matching (RegexSet fast path) ---
    if !block.doc_comments.is_empty() {
        has_any_predicate = true;
        let doc_matches: Vec<(u32, String)> = ctx
            .parse_result
            .doc_comments
            .iter()
            .filter(|dc| {
                if let Some(ref rs) = block.doc_comment_regex_set {
                    rs.is_match(&dc.text)
                } else {
                    block.doc_comments.iter().any(|re| re.is_match(&dc.text))
                }
            })
            .map(|dc| (dc.line, format!("doc: {}", dc.text.chars().take(60).collect::<String>())))
            .collect();
        if doc_matches.is_empty() {
            return Vec::new();
        }
        for (line, text) in doc_matches {
            matches.push(make_match(pattern, ctx, line, 0, &text));
        }
    }

    // --- Negative matching ---
    if let Some(not_block) = &block.not {
        if !matches.is_empty() && negative_block_matches(not_block, ctx) {
            return Vec::new();
        }
    }

    // If no predicates were specified, this is a malformed pattern — skip it
    if !has_any_predicate {
        return Vec::new();
    }

    matches
}

/// Check if a call site matches any of the compiled call patterns.
fn call_matches_any(
    call: &crate::parsers::types::CallSite,
    patterns: &[CompiledCall],
) -> bool {
    let callee_lower = call.callee_name.to_lowercase();
    let receiver_lower = call
        .receiver
        .as_deref()
        .unwrap_or("")
        .to_lowercase();

    patterns.iter().any(|pat| {
        let method_matches = callee_lower == pat.method.to_lowercase();
        let receiver_matches = match &pat.receiver {
            Some(recv) => receiver_lower == recv.to_lowercase(),
            None => true,
        };
        method_matches && receiver_matches
    })
}

/// Check if any predicate in a negative match block has matches.
fn negative_block_matches(block: &CompiledMatchBlock, ctx: &DetectionContext) -> bool {
    // Check imports
    if !block.imports.is_empty()
        && ctx.imports.iter().any(|imp| {
            let src_lower = imp.source.to_lowercase();
            block
                .imports
                .iter()
                .any(|pat| src_lower.contains(&pat.to_lowercase()))
        })
    {
        return true;
    }

    // Check decorators
    if !block.decorators.is_empty() {
        let has_dec = ctx.classes.iter().any(|c| {
            c.decorators
                .iter()
                .any(|d| block.decorators.contains(&d.name))
        }) || ctx.functions.iter().any(|f| {
            f.decorators
                .iter()
                .any(|d| block.decorators.contains(&d.name))
        });
        if has_dec {
            return true;
        }
    }

    // Check calls
    if !block.calls.is_empty()
        && ctx
            .call_sites
            .iter()
            .any(|call| call_matches_any(call, &block.calls))
    {
        return true;
    }

    // Check content patterns
    if !block.content_patterns.is_empty() {
        let source_str = String::from_utf8_lossy(ctx.source);
        for line in source_str.lines() {
            if block.content_patterns.iter().any(|re| re.is_match(line)) {
                return true;
            }
        }
    }

    // Check file_patterns
    if !block.file_patterns.is_empty()
        && block.file_patterns.iter().any(|glob| glob.matches(ctx.file))
    {
        return true;
    }

    false
}

/// Create a PatternMatch from a compiled pattern and match location.
fn make_match(
    pattern: &CompiledPattern,
    ctx: &DetectionContext,
    line: u32,
    column: u32,
    matched_text: &str,
) -> PatternMatch {
    PatternMatch {
        file: ctx.file.to_string(),
        line,
        column,
        pattern_id: pattern.id.clone(),
        confidence: pattern.confidence,
        cwe_ids: pattern.cwe_ids.clone(),
        owasp: pattern.owasp.clone(),
        detection_method: DetectionMethod::TomlPattern,
        category: pattern.category,
        matched_text: matched_text.to_string(),
    }
}

