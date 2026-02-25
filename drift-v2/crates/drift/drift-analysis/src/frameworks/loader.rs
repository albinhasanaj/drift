//! TOML framework pack loader — parses and compiles framework definitions.
//!
//! Compiles regex patterns at load time so matching is zero-allocation per file.

use aho_corasick::AhoCorasick;
use regex::{Regex, RegexSet};
use smallvec::SmallVec;

use drift_core::errors::DetectionError;

use crate::engine::types::PatternCategory;
use crate::scanner::language_detect::Language;

use super::types::{DetectSignal, FrameworkSpec, MatchBlock, PatternDef};

/// A compiled framework pack ready for matching.
#[derive(Debug, Clone)]
pub struct CompiledFrameworkPack {
    /// Framework name.
    pub name: String,
    /// Display name.
    pub display_name: String,
    /// Languages this framework targets.
    pub languages: Vec<Language>,
    /// Compiled detection signals.
    pub detect_signals: Vec<CompiledDetectSignal>,
    /// Compiled pattern definitions.
    pub patterns: Vec<CompiledPattern>,
    /// Pack version string.
    pub version: Option<String>,
}

/// Compiled detection signal.
#[derive(Debug, Clone)]
pub enum CompiledDetectSignal {
    Import(String),
    FilePattern(glob::Pattern),
    Decorator(String),
    Dependency(String),
}

/// A compiled pattern definition ready for matching.
#[derive(Debug, Clone)]
pub struct CompiledPattern {
    pub id: String,
    pub category: PatternCategory,
    pub description: Option<String>,
    pub sub_type: Option<String>,
    pub confidence: f32,
    pub cwe_ids: SmallVec<[u32; 2]>,
    pub owasp: Option<String>,
    pub match_block: CompiledMatchBlock,
    pub has_learn: bool,
    pub learn_group_by: Option<String>,
    pub learn_signal: Option<String>,
    pub learn_deviation_threshold: f64,
}

/// Compiled match block with pre-compiled regexes.
#[derive(Debug, Default, Clone)]
pub struct CompiledMatchBlock {
    pub imports: Vec<String>,
    pub decorators: Vec<String>,
    pub calls: Vec<CompiledCall>,
    pub extends: Vec<String>,
    pub implements: Vec<String>,
    pub function_names: Vec<Regex>,
    pub class_names: Vec<Regex>,
    pub string_literals: Vec<Regex>,
    pub param_types: Vec<String>,
    pub return_types: Vec<String>,
    pub content_patterns: Vec<Regex>,
    pub exports: Vec<String>,
    pub error_handling: Vec<String>,
    pub doc_comments: Vec<Regex>,
    pub file_patterns: Vec<glob::Pattern>,
    pub type_annotations: Vec<Regex>,
    pub language: Option<Language>,
    pub not: Option<Box<CompiledMatchBlock>>,
    /// Pre-compiled RegexSet for fast multi-pattern rejection on content_patterns.
    pub content_regex_set: Option<RegexSet>,
    /// Pre-compiled RegexSet for fast multi-pattern rejection on function_names.
    pub function_name_regex_set: Option<RegexSet>,
    /// Pre-compiled RegexSet for fast multi-pattern rejection on class_names.
    pub class_name_regex_set: Option<RegexSet>,
    /// Pre-compiled RegexSet for fast multi-pattern rejection on string_literals.
    pub string_literal_regex_set: Option<RegexSet>,
    /// Pre-compiled RegexSet for fast multi-pattern rejection on doc_comments.
    pub doc_comment_regex_set: Option<RegexSet>,
    /// Pre-compiled RegexSet for fast multi-pattern rejection on type_annotations.
    pub type_annotation_regex_set: Option<RegexSet>,
    /// Aho-Corasick automaton for fast import source matching.
    pub import_ac: Option<AhoCorasick>,
    /// Aho-Corasick automaton for fast decorator name matching.
    pub decorator_ac: Option<AhoCorasick>,
    /// Aho-Corasick automaton for fast extends matching.
    pub extends_ac: Option<AhoCorasick>,
    /// Aho-Corasick automaton for fast implements matching.
    pub implements_ac: Option<AhoCorasick>,
}

/// A compiled call pattern: optional receiver + method name.
#[derive(Debug, Clone)]
pub struct CompiledCall {
    pub receiver: Option<String>,
    pub method: String,
}

/// Load and compile a framework pack from a TOML string.
pub fn load_from_str(toml_str: &str) -> Result<CompiledFrameworkPack, DetectionError> {
    let spec: FrameworkSpec = toml::from_str(toml_str).map_err(|e| {
        DetectionError::InvalidPattern(format!("TOML parse error: {e}"))
    })?;
    compile_spec(spec)
}

/// Load and compile a framework pack from a file path.
pub fn load_from_file(path: &std::path::Path) -> Result<CompiledFrameworkPack, DetectionError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        DetectionError::InvalidPattern(format!("failed to read {}: {e}", path.display()))
    })?;
    load_from_str(&content)
}

fn compile_spec(spec: FrameworkSpec) -> Result<CompiledFrameworkPack, DetectionError> {
    let languages: Vec<Language> = spec
        .framework
        .languages
        .iter()
        .filter_map(|s| parse_language(s))
        .collect();

    let detect_signals = spec
        .framework
        .detect_by
        .into_iter()
        .filter_map(|s| match compile_detect_signal(s) {
            Ok(sig) => Some(sig),
            Err(e) => { eprintln!("[drift] warning: skipping detect_signal in pack '{}': {e}", spec.framework.name); None }
        })
        .collect();

    let mut patterns = Vec::with_capacity(spec.patterns.len());
    for def in spec.patterns {
        match compile_pattern(def) {
            Ok(p) => patterns.push(p),
            Err(e) => {
                eprintln!("[drift] warning: skipping pattern in pack '{}': {e}", spec.framework.name);
            }
        }
    }

    let display_name = spec
        .framework
        .display_name
        .unwrap_or_else(|| spec.framework.name.clone());

    Ok(CompiledFrameworkPack {
        name: spec.framework.name,
        display_name,
        languages,
        detect_signals,
        patterns,
        version: spec.framework.version,
    })
}

fn compile_detect_signal(signal: DetectSignal) -> Result<CompiledDetectSignal, DetectionError> {
    match signal {
        DetectSignal::Import { import } => Ok(CompiledDetectSignal::Import(import)),
        DetectSignal::FilePattern { file_pattern } => {
            let pat = glob::Pattern::new(&file_pattern).map_err(|e| {
                DetectionError::InvalidPattern(format!("invalid glob: {e}"))
            })?;
            Ok(CompiledDetectSignal::FilePattern(pat))
        }
        DetectSignal::Decorator { decorator } => Ok(CompiledDetectSignal::Decorator(decorator)),
        DetectSignal::Dependency { dependency } => Ok(CompiledDetectSignal::Dependency(dependency)),
    }
}

fn compile_pattern(def: PatternDef) -> Result<CompiledPattern, DetectionError> {
    let category = PatternCategory::parse_str(&def.category).ok_or_else(|| {
        DetectionError::InvalidPattern(format!(
            "unknown category '{}' in pattern '{}'",
            def.category, def.id
        ))
    })?;

    let mut cwe_ids = SmallVec::new();
    for id in &def.cwe_ids {
        cwe_ids.push(*id);
    }

    let match_block = compile_match_block(&def.match_predicates, &def.id)?;

    // FWT-LOAD-01/02: If the original TOML specified regex-based fields but
    // all regexes were invalid/empty and no other matchers survived, skip the
    // entire pattern so it doesn't produce false matches.
    let had_regex_input = !def.match_predicates.content_patterns.is_empty()
        || !def.match_predicates.function_names.is_empty()
        || !def.match_predicates.class_names.is_empty()
        || !def.match_predicates.string_literals.is_empty()
        || !def.match_predicates.doc_comments.is_empty()
        || !def.match_predicates.type_annotations.is_empty();

    let has_compiled_regex = !match_block.content_patterns.is_empty()
        || !match_block.function_names.is_empty()
        || !match_block.class_names.is_empty()
        || !match_block.string_literals.is_empty()
        || !match_block.doc_comments.is_empty()
        || !match_block.type_annotations.is_empty();

    let has_non_regex_matchers = !match_block.imports.is_empty()
        || !match_block.decorators.is_empty()
        || !match_block.calls.is_empty()
        || !match_block.extends.is_empty()
        || !match_block.implements.is_empty()
        || !match_block.param_types.is_empty()
        || !match_block.return_types.is_empty()
        || !match_block.exports.is_empty()
        || !match_block.error_handling.is_empty()
        || !match_block.file_patterns.is_empty();

    if had_regex_input && !has_compiled_regex && !has_non_regex_matchers {
        return Err(DetectionError::InvalidPattern(format!(
            "all regex patterns in '{}' were invalid or empty — skipping pattern",
            def.id
        )));
    }

    let (has_learn, learn_group_by, learn_signal, learn_deviation_threshold) =
        if let Some(learn) = &def.learn {
            (
                true,
                Some(learn.group_by.clone()),
                Some(learn.signal.clone()),
                learn.deviation_threshold,
            )
        } else {
            (false, None, None, 0.15)
        };

    Ok(CompiledPattern {
        id: def.id,
        category,
        description: def.description,
        sub_type: def.sub_type,
        confidence: def.confidence,
        cwe_ids,
        owasp: def.owasp,
        match_block,
        has_learn,
        learn_group_by,
        learn_signal,
        learn_deviation_threshold,
    })
}

fn compile_match_block(
    block: &MatchBlock,
    pattern_id: &str,
) -> Result<CompiledMatchBlock, DetectionError> {
    let function_names = compile_regexes(&block.function_names, pattern_id, "function_names")?;
    let class_names = compile_regexes(&block.class_names, pattern_id, "class_names")?;
    let string_literals = compile_regexes(&block.string_literals, pattern_id, "string_literals")?;
    let content_patterns =
        compile_regexes(&block.content_patterns, pattern_id, "content_patterns")?;
    let doc_comments = compile_regexes(&block.doc_comments, pattern_id, "doc_comments")?;

    let calls = block
        .calls
        .iter()
        .map(|c| {
            if let Some((recv, method)) = c.rsplit_once('.') {
                CompiledCall {
                    receiver: Some(recv.to_string()),
                    method: method.to_string(),
                }
            } else {
                CompiledCall {
                    receiver: None,
                    method: c.clone(),
                }
            }
        })
        .collect();

    let file_patterns: Vec<glob::Pattern> = block
        .file_patterns
        .iter()
        .filter_map(|p| match glob::Pattern::new(p) {
            Ok(pat) => Some(pat),
            Err(e) => {
                eprintln!("[drift] warning: invalid file_pattern glob in {pattern_id}: {e}");
                None
            }
        })
        .collect();

    let type_annotations = compile_regexes(&block.type_annotations, pattern_id, "type_annotations")?;

    let language = block.language.as_deref().and_then(parse_language);

    let not = if let Some(not_block) = &block.not {
        Some(Box::new(compile_match_block(not_block, pattern_id)?))
    } else {
        None
    };

    // Build RegexSets for fast multi-pattern rejection
    let content_regex_set = build_regex_set(&block.content_patterns);
    let function_name_regex_set = build_regex_set(&block.function_names);
    let class_name_regex_set = build_regex_set(&block.class_names);
    let string_literal_regex_set = build_regex_set(&block.string_literals);
    let doc_comment_regex_set = build_regex_set(&block.doc_comments);
    let type_annotation_regex_set = build_regex_set(&block.type_annotations);

    // Build Aho-Corasick automatons for fast literal matching
    let import_ac = build_aho_corasick(&block.imports);
    let decorator_ac = build_aho_corasick(&block.decorators);
    let extends_ac = build_aho_corasick(&block.extends);
    let implements_ac = build_aho_corasick(&block.implements);

    Ok(CompiledMatchBlock {
        imports: block.imports.clone(),
        decorators: block.decorators.clone(),
        calls,
        extends: block.extends.clone(),
        implements: block.implements.clone(),
        function_names,
        class_names,
        string_literals,
        param_types: block.param_types.clone(),
        return_types: block.return_types.clone(),
        content_patterns,
        exports: block.exports.clone(),
        error_handling: block.error_handling.clone(),
        doc_comments,
        file_patterns,
        type_annotations,
        language,
        not,
        content_regex_set,
        function_name_regex_set,
        class_name_regex_set,
        string_literal_regex_set,
        doc_comment_regex_set,
        type_annotation_regex_set,
        import_ac,
        decorator_ac,
        extends_ac,
        implements_ac,
    })
}

fn compile_regexes(
    patterns: &[String],
    pattern_id: &str,
    field_name: &str,
) -> Result<Vec<Regex>, DetectionError> {
    let mut compiled = Vec::new();
    for p in patterns {
        if p.is_empty() {
            continue;
        }
        match Regex::new(p) {
            Ok(re) => compiled.push(re),
            Err(e) => {
                // Gracefully skip unsupported patterns (e.g. lookahead/lookbehind)
                // instead of failing the entire pack. Log a warning for diagnostics.
                eprintln!(
                    "[drift] warning: skipping unsupported regex in {}.{}: {} ({})",
                    pattern_id, field_name, p, e
                );
            }
        }
    }
    Ok(compiled)
}

/// Build a RegexSet from pattern strings. Returns None if empty or if compilation fails.
fn build_regex_set(patterns: &[String]) -> Option<RegexSet> {
    if patterns.is_empty() {
        return None;
    }
    // Filter out empty patterns
    let non_empty: Vec<&str> = patterns.iter().map(|s| s.as_str()).filter(|s| !s.is_empty()).collect();
    if non_empty.is_empty() {
        return None;
    }
    RegexSet::new(&non_empty).ok()
}

/// Build an Aho-Corasick automaton from literal patterns. Returns None if empty.
fn build_aho_corasick(patterns: &[String]) -> Option<AhoCorasick> {
    if patterns.is_empty() {
        return None;
    }
    // Build case-insensitive AC automaton
    aho_corasick::AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .build(patterns)
        .ok()
}

fn parse_language(s: &str) -> Option<Language> {
    match s.to_lowercase().as_str() {
        "typescript" | "ts" => Some(Language::TypeScript),
        "javascript" | "js" => Some(Language::JavaScript),
        "python" | "py" => Some(Language::Python),
        "java" => Some(Language::Java),
        "csharp" | "c#" | "cs" => Some(Language::CSharp),
        "go" | "golang" => Some(Language::Go),
        "rust" | "rs" => Some(Language::Rust),
        "ruby" | "rb" => Some(Language::Ruby),
        "php" => Some(Language::Php),
        "kotlin" | "kt" => Some(Language::Kotlin),
        "cpp" | "c++" => Some(Language::Cpp),
        "c" => Some(Language::C),
        "swift" => Some(Language::Swift),
        "scala" => Some(Language::Scala),
        _ => { eprintln!("[drift] warning: unknown framework language '{s}'"); None }
    }
}
