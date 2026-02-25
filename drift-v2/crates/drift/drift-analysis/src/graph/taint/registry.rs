//! TOML-driven source/sink/sanitizer registry.
//!
//! Extensible without code changes — users can add custom sources, sinks,
//! and sanitizers via TOML configuration.

use serde::{Deserialize, Serialize};

use super::types::{SanitizerType, SinkType, SourceType};

/// TOML-driven taint registry.
///
/// Loaded from configuration, provides pattern matching for identifying
/// sources, sinks, and sanitizers in code.
#[derive(Debug, Clone, Default)]
pub struct TaintRegistry {
    /// Source patterns: function/expression → SourceType.
    pub sources: Vec<SourcePattern>,
    /// Sink patterns: function/expression → SinkType.
    pub sinks: Vec<SinkPattern>,
    /// Sanitizer patterns: function/expression → SanitizerType.
    pub sanitizers: Vec<SanitizerPattern>,
}

/// A pattern for identifying taint sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourcePattern {
    /// Pattern to match (function name, expression, etc.).
    pub pattern: String,
    /// Source type.
    pub source_type: SourceType,
    /// Optional framework restriction.
    pub framework: Option<String>,
}

/// A pattern for identifying taint sinks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkPattern {
    /// Pattern to match.
    pub pattern: String,
    /// Sink type (CWE-mapped).
    pub sink_type: SinkType,
    /// Required sanitizers to make this sink safe.
    pub required_sanitizers: Vec<SanitizerType>,
    /// Optional framework restriction.
    pub framework: Option<String>,
}

/// A pattern for identifying sanitizers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizerPattern {
    /// Pattern to match.
    pub pattern: String,
    /// Sanitizer type.
    pub sanitizer_type: SanitizerType,
    /// Which sink types this sanitizer protects against.
    pub protects_against: Vec<SinkType>,
    /// Optional framework restriction.
    pub framework: Option<String>,
}

impl TaintRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a registry with built-in defaults for common patterns.
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.add_default_sources();
        registry.add_default_sinks();
        registry.add_default_sanitizers();
        registry
    }

    /// Load additional patterns from TOML string.
    pub fn load_toml(&mut self, toml_str: &str) -> Result<(), toml::de::Error> {
        let config: RegistryConfig = toml::from_str(toml_str)?;

        if let Some(sources) = config.sources {
            self.sources.extend(sources);
        }
        if let Some(sinks) = config.sinks {
            self.sinks.extend(sinks);
        }
        if let Some(sanitizers) = config.sanitizers {
            self.sanitizers.extend(sanitizers);
        }

        Ok(())
    }

    /// Check if an expression matches a source pattern.
    /// CG-TAINT-04/05: Anchored matching — no bidirectional substring.
    pub fn match_source(&self, expression: &str) -> Option<&SourcePattern> {
        self.sources.iter().find(|p| pattern_matches(expression, &p.pattern))
    }

    /// Check if an expression matches a sink pattern.
    /// CG-TAINT-04/05: Anchored matching — no bidirectional substring.
    pub fn match_sink(&self, expression: &str) -> Option<&SinkPattern> {
        self.sinks.iter().find(|p| pattern_matches(expression, &p.pattern))
    }

    /// Check if an expression matches a sanitizer pattern.
    /// CG-TAINT-04/05: Anchored matching — no bidirectional substring.
    pub fn match_sanitizer(&self, expression: &str) -> Option<&SanitizerPattern> {
        self.sanitizers.iter().find(|p| pattern_matches(expression, &p.pattern))
    }

    /// Add a custom source pattern.
    pub fn add_source(&mut self, pattern: SourcePattern) {
        self.sources.push(pattern);
    }

    /// Add a custom sink pattern.
    pub fn add_sink(&mut self, pattern: SinkPattern) {
        self.sinks.push(pattern);
    }

    /// Add a custom sanitizer pattern.
    pub fn add_sanitizer(&mut self, pattern: SanitizerPattern) {
        self.sanitizers.push(pattern);
    }

    fn add_default_sources(&mut self) {
        let user_input_patterns = [
            "req.query", "req.body", "req.params", "req.headers",
            "request.GET", "request.POST", "request.data", "request.json",
            "request.args", "request.form", "request.files",
            "getParameter", "getQueryString", "getHeader",
            "HttpContext.Request", "Request.Query", "Request.Form",
            "params", "user_input", "stdin", "argv",
            "process.env", "os.environ", "System.getenv",
        ];

        for pattern in &user_input_patterns {
            self.sources.push(SourcePattern {
                pattern: pattern.to_string(),
                source_type: SourceType::UserInput,
                framework: None,
            });
        }
    }

    fn add_default_sinks(&mut self) {
        let sink_defs: &[(&str, SinkType, &[SanitizerType])] = &[
            ("db.query", SinkType::SqlQuery, &[SanitizerType::SqlParameterize]),
            ("db.execute", SinkType::SqlQuery, &[SanitizerType::SqlParameterize]),
            ("cursor.execute", SinkType::SqlQuery, &[SanitizerType::SqlParameterize]),
            ("connection.query", SinkType::SqlQuery, &[SanitizerType::SqlParameterize]),
            ("raw_sql", SinkType::SqlQuery, &[SanitizerType::SqlParameterize]),
            ("exec", SinkType::OsCommand, &[SanitizerType::ShellEscape]),
            ("execSync", SinkType::OsCommand, &[SanitizerType::ShellEscape]),
            ("spawn", SinkType::OsCommand, &[SanitizerType::ShellEscape]),
            ("system", SinkType::OsCommand, &[SanitizerType::ShellEscape]),
            ("popen", SinkType::OsCommand, &[SanitizerType::ShellEscape]),
            ("subprocess.run", SinkType::OsCommand, &[SanitizerType::ShellEscape]),
            ("subprocess.call", SinkType::OsCommand, &[SanitizerType::ShellEscape]),
            ("Runtime.exec", SinkType::OsCommand, &[SanitizerType::ShellEscape]),
            ("eval", SinkType::CodeExecution, &[SanitizerType::InputValidation]),
            ("Function", SinkType::CodeExecution, &[SanitizerType::InputValidation]),
            ("res.send", SinkType::HtmlOutput, &[SanitizerType::HtmlEscape]),
            ("res.write", SinkType::HtmlOutput, &[SanitizerType::HtmlEscape]),
            ("document.write", SinkType::HtmlOutput, &[SanitizerType::HtmlEscape]),
            ("innerHTML", SinkType::HtmlOutput, &[SanitizerType::HtmlEscape]),
            ("render", SinkType::TemplateRender, &[SanitizerType::HtmlEscape]),
            ("res.redirect", SinkType::HttpRedirect, &[SanitizerType::UrlEncode]),
            ("redirect", SinkType::HttpRedirect, &[SanitizerType::UrlEncode]),
            ("fetch", SinkType::HttpRequest, &[SanitizerType::UrlEncode]),
            ("http.get", SinkType::HttpRequest, &[SanitizerType::UrlEncode]),
            ("requests.get", SinkType::HttpRequest, &[SanitizerType::UrlEncode]),
            ("fs.readFile", SinkType::FileRead, &[SanitizerType::PathValidate]),
            ("fs.writeFile", SinkType::FileWrite, &[SanitizerType::PathValidate]),
            ("open", SinkType::FileRead, &[SanitizerType::PathValidate]),
            ("JSON.parse", SinkType::Deserialization, &[SanitizerType::InputValidation]),
            ("pickle.loads", SinkType::Deserialization, &[SanitizerType::InputValidation]),
            ("yaml.load", SinkType::Deserialization, &[SanitizerType::InputValidation]),
            ("console.log", SinkType::LogOutput, &[SanitizerType::InputValidation]),
            ("logger.info", SinkType::LogOutput, &[SanitizerType::InputValidation]),
            ("setHeader", SinkType::HeaderInjection, &[SanitizerType::InputValidation]),
            ("new RegExp", SinkType::RegexConstruction, &[SanitizerType::InputValidation]),
            ("xml.parse", SinkType::XmlParsing, &[SanitizerType::InputValidation]),
            ("upload", SinkType::FileUpload, &[SanitizerType::InputValidation]),
        ];

        for (pattern, sink_type, sanitizers) in sink_defs {
            self.sinks.push(SinkPattern {
                pattern: pattern.to_string(),
                sink_type: *sink_type,
                required_sanitizers: sanitizers.to_vec(),
                framework: None,
            });
        }
    }

    fn add_default_sanitizers(&mut self) {
        let sanitizer_defs: &[(&str, SanitizerType, &[SinkType])] = &[
            ("escapeHtml", SanitizerType::HtmlEscape, &[SinkType::HtmlOutput, SinkType::TemplateRender]),
            ("escape", SanitizerType::HtmlEscape, &[SinkType::HtmlOutput]),
            ("sanitize", SanitizerType::HtmlEscape, &[SinkType::HtmlOutput]),
            ("DOMPurify.sanitize", SanitizerType::HtmlEscape, &[SinkType::HtmlOutput]),
            ("xss", SanitizerType::HtmlEscape, &[SinkType::HtmlOutput]),
            ("parameterize", SanitizerType::SqlParameterize, &[SinkType::SqlQuery]),
            ("prepare", SanitizerType::SqlParameterize, &[SinkType::SqlQuery]),
            ("placeholder", SanitizerType::SqlParameterize, &[SinkType::SqlQuery]),
            ("shellescape", SanitizerType::ShellEscape, &[SinkType::OsCommand]),
            ("shlex.quote", SanitizerType::ShellEscape, &[SinkType::OsCommand]),
            ("escapeshellarg", SanitizerType::ShellEscape, &[SinkType::OsCommand]),
            ("path.resolve", SanitizerType::PathValidate, &[SinkType::FileRead, SinkType::FileWrite]),
            ("path.normalize", SanitizerType::PathValidate, &[SinkType::FileRead, SinkType::FileWrite]),
            ("realpath", SanitizerType::PathValidate, &[SinkType::FileRead, SinkType::FileWrite]),
            ("encodeURIComponent", SanitizerType::UrlEncode, &[SinkType::HttpRedirect, SinkType::HttpRequest]),
            ("encodeURI", SanitizerType::UrlEncode, &[SinkType::HttpRedirect]),
            ("parseInt", SanitizerType::TypeCast, &[SinkType::SqlQuery]),
            ("Number", SanitizerType::TypeCast, &[SinkType::SqlQuery]),
            ("validate", SanitizerType::InputValidation, &[SinkType::SqlQuery, SinkType::OsCommand, SinkType::HtmlOutput]),
        ];

        for (pattern, sanitizer_type, protects) in sanitizer_defs {
            self.sanitizers.push(SanitizerPattern {
                pattern: pattern.to_string(),
                sanitizer_type: *sanitizer_type,
                protects_against: protects.to_vec(),
                framework: None,
            });
        }
    }
}

/// CG-TAINT-04/05/06: Anchored pattern matching.
///
/// Matches if:
/// 1. Exact match (case-insensitive): `expression == pattern`
/// 2. Expression ends with `.pattern` (dotted suffix): `foo.req.body` matches `req.body`
/// 3. Expression starts with `pattern.` (dotted prefix): `req.body.name` matches `req.body`
/// 4. Pattern appears as a complete dotted segment: `a.open.b` matches `open`
///
/// Does NOT match if pattern is merely a substring of a longer identifier:
/// `openDialog` does NOT match `open`.
/// Does NOT do reverse matching (expression "query" no longer matches pattern "req.query")
/// because that caused massive false positives — a call to any function named "query"
/// would match the source pattern "req.query" and be treated as a taint source.
fn pattern_matches(expression: &str, pattern: &str) -> bool {
    let expr = expression.to_lowercase();
    let pat = pattern.to_lowercase();

    // 1. Exact match
    if expr == pat {
        return true;
    }

    // 2. Expression ends with the pattern after a dot separator
    //    e.g., expression "foo.req.body" matches pattern "req.body"
    let dotted = format!(".{}", pat);
    if expr.ends_with(&dotted) {
        return true;
    }

    // 3. Expression starts with the pattern followed by a dot (prefix match)
    //    e.g., expression "req.body.name" matches pattern "req.body"
    let prefix = format!("{}.", pat);
    if expr.starts_with(&prefix) {
        return true;
    }

    // 4. Pattern appears as a complete dotted segment in the expression
    //    e.g., expression "a.open.b" matches pattern "open"
    let segment = format!(".{}.", pat);
    if expr.contains(&segment) {
        return true;
    }

    false
}

/// TOML configuration structure for the registry.
#[derive(Debug, Deserialize)]
struct RegistryConfig {
    sources: Option<Vec<SourcePattern>>,
    sinks: Option<Vec<SinkPattern>>,
    sanitizers: Option<Vec<SanitizerPattern>>,
}
