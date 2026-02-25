//! Taint analysis types — sources, sinks, sanitizers, flows, labels.

use serde::{Deserialize, Serialize};

/// A taint source — where untrusted data enters the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSource {
    /// File containing the source.
    pub file: String,
    /// Line number.
    pub line: u32,
    /// Column number.
    pub column: u32,
    /// The expression that introduces taint (e.g., "req.query").
    pub expression: String,
    /// Type of source.
    pub source_type: SourceType,
    /// Taint label assigned to this source.
    pub label: TaintLabel,
}

/// Classification of taint sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SourceType {
    /// HTTP request parameters, body, headers.
    UserInput,
    /// Environment variables.
    Environment,
    /// Database query results.
    Database,
    /// Network responses.
    Network,
    /// File system reads.
    FileSystem,
    /// Command line arguments.
    CommandLine,
    /// Deserialized data.
    Deserialization,
}

impl SourceType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::UserInput => "user_input",
            Self::Environment => "environment",
            Self::Database => "database",
            Self::Network => "network",
            Self::FileSystem => "file_system",
            Self::CommandLine => "command_line",
            Self::Deserialization => "deserialization",
        }
    }
}

/// A taint sink — where tainted data could cause harm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSink {
    /// File containing the sink.
    pub file: String,
    /// Line number.
    pub line: u32,
    /// Column number.
    pub column: u32,
    /// The expression consuming tainted data (e.g., "db.query(sql)").
    pub expression: String,
    /// Type of sink (maps to CWE).
    pub sink_type: SinkType,
    /// Sanitizers required to make this sink safe.
    pub required_sanitizers: Vec<SanitizerType>,
}

/// 17 CWE-mapped sink types + Custom.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SinkType {
    /// SQL query execution — CWE-89.
    SqlQuery,
    /// OS command execution — CWE-78.
    OsCommand,
    /// Dynamic code execution — CWE-94.
    CodeExecution,
    /// File write operations — CWE-22.
    FileWrite,
    /// File read operations — CWE-22.
    FileRead,
    /// HTML output (XSS) — CWE-79.
    HtmlOutput,
    /// HTTP redirect — CWE-601.
    HttpRedirect,
    /// Server-side HTTP request (SSRF) — CWE-918.
    HttpRequest,
    /// Deserialization of untrusted data — CWE-502.
    Deserialization,
    /// LDAP query — CWE-90.
    LdapQuery,
    /// XPath query — CWE-643.
    XpathQuery,
    /// Template rendering — CWE-1336.
    TemplateRender,
    /// Log output (log injection) — CWE-117.
    LogOutput,
    /// HTTP header injection — CWE-113.
    HeaderInjection,
    /// Regex construction (ReDoS) — CWE-1333.
    RegexConstruction,
    /// XML parsing (XXE) — CWE-611.
    XmlParsing,
    /// File upload — CWE-434.
    FileUpload,
    /// Custom sink with user-defined CWE.
    Custom(u32),
}

impl SinkType {
    /// Get the CWE ID for this sink type.
    pub fn cwe_id(&self) -> Option<u32> {
        match self {
            Self::SqlQuery => Some(89),
            Self::OsCommand => Some(78),
            Self::CodeExecution => Some(94),
            Self::FileWrite => Some(22),
            Self::FileRead => Some(22),
            Self::HtmlOutput => Some(79),
            Self::HttpRedirect => Some(601),
            Self::HttpRequest => Some(918),
            Self::Deserialization => Some(502),
            Self::LdapQuery => Some(90),
            Self::XpathQuery => Some(643),
            Self::TemplateRender => Some(1336),
            Self::LogOutput => Some(117),
            Self::HeaderInjection => Some(113),
            Self::RegexConstruction => Some(1333),
            Self::XmlParsing => Some(611),
            Self::FileUpload => Some(434),
            Self::Custom(id) => Some(*id),
        }
    }

    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::SqlQuery => "sql_query",
            Self::OsCommand => "os_command",
            Self::CodeExecution => "code_execution",
            Self::FileWrite => "file_write",
            Self::FileRead => "file_read",
            Self::HtmlOutput => "html_output",
            Self::HttpRedirect => "http_redirect",
            Self::HttpRequest => "http_request",
            Self::Deserialization => "deserialization",
            Self::LdapQuery => "ldap_query",
            Self::XpathQuery => "xpath_query",
            Self::TemplateRender => "template_render",
            Self::LogOutput => "log_output",
            Self::HeaderInjection => "header_injection",
            Self::RegexConstruction => "regex_construction",
            Self::XmlParsing => "xml_parsing",
            Self::FileUpload => "file_upload",
            Self::Custom(_) => "custom",
        }
    }

    /// All built-in sink types.
    pub fn all_builtin() -> &'static [SinkType] {
        &[
            Self::SqlQuery, Self::OsCommand, Self::CodeExecution,
            Self::FileWrite, Self::FileRead, Self::HtmlOutput,
            Self::HttpRedirect, Self::HttpRequest, Self::Deserialization,
            Self::LdapQuery, Self::XpathQuery, Self::TemplateRender,
            Self::LogOutput, Self::HeaderInjection, Self::RegexConstruction,
            Self::XmlParsing, Self::FileUpload,
        ]
    }
}

impl std::fmt::Display for SinkType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// A taint sanitizer — neutralizes taint for specific sink types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSanitizer {
    /// File containing the sanitizer.
    pub file: String,
    /// Line number.
    pub line: u32,
    /// The sanitizer function/expression.
    pub expression: String,
    /// Type of sanitization performed.
    pub sanitizer_type: SanitizerType,
    /// Which taint labels this sanitizer neutralizes.
    pub labels_sanitized: Vec<SinkType>,
}

/// Types of sanitization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SanitizerType {
    /// HTML escaping (prevents XSS).
    HtmlEscape,
    /// SQL parameterization (prevents SQLi).
    SqlParameterize,
    /// Shell escaping (prevents command injection).
    ShellEscape,
    /// Path validation (prevents path traversal).
    PathValidate,
    /// URL encoding.
    UrlEncode,
    /// Input validation (regex, allowlist).
    InputValidation,
    /// Type casting/conversion.
    TypeCast,
    /// Custom sanitizer.
    Custom,
}

impl SanitizerType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::HtmlEscape => "html_escape",
            Self::SqlParameterize => "sql_parameterize",
            Self::ShellEscape => "shell_escape",
            Self::PathValidate => "path_validate",
            Self::UrlEncode => "url_encode",
            Self::InputValidation => "input_validation",
            Self::TypeCast => "type_cast",
            Self::Custom => "custom",
        }
    }
}

/// A taint label — tracks provenance through transformations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaintLabel {
    /// Unique identifier for this taint flow.
    pub id: u64,
    /// Source type that originated this taint.
    pub origin: SourceType,
    /// Whether this label has been sanitized.
    pub sanitized: bool,
    /// Sanitizers that have been applied.
    pub applied_sanitizers: Vec<SanitizerType>,
}

impl TaintLabel {
    /// Create a new unsanitized taint label.
    pub fn new(id: u64, origin: SourceType) -> Self {
        Self {
            id,
            origin,
            sanitized: false,
            applied_sanitizers: Vec::new(),
        }
    }

    /// Apply a sanitizer to this label.
    pub fn apply_sanitizer(&mut self, sanitizer: SanitizerType) {
        self.applied_sanitizers.push(sanitizer);
    }

    /// Mark as sanitized.
    pub fn mark_sanitized(&mut self) {
        self.sanitized = true;
    }

    /// Check if a specific sanitizer has been applied.
    pub fn has_sanitizer(&self, sanitizer: SanitizerType) -> bool {
        self.applied_sanitizers.contains(&sanitizer)
    }
}

/// A hop in a taint flow path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintHop {
    /// File at this hop.
    pub file: String,
    /// Line at this hop.
    pub line: u32,
    /// Column at this hop.
    pub column: u32,
    /// Function name at this hop.
    pub function: String,
    /// Description of what happens at this hop.
    pub description: String,
}

/// A complete taint flow from source to sink.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintFlow {
    /// The taint source.
    pub source: TaintSource,
    /// The taint sink.
    pub sink: TaintSink,
    /// Intermediate hops in the flow.
    pub path: Vec<TaintHop>,
    /// Whether the flow is sanitized (no vulnerability).
    pub is_sanitized: bool,
    /// Sanitizers applied along the path.
    pub sanitizers_applied: Vec<TaintSanitizer>,
    /// CWE ID if this is a vulnerability.
    pub cwe_id: Option<u32>,
    /// Confidence score (0.0-1.0).
    pub confidence: f32,
}

impl TaintFlow {
    /// Check if this flow represents an actual vulnerability (unsanitized).
    pub fn is_vulnerability(&self) -> bool {
        !self.is_sanitized
    }

    /// Get the total path length (source + hops + sink).
    pub fn path_length(&self) -> usize {
        self.path.len() + 2 // +2 for source and sink
    }
}

/// Summary of taint analysis results.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaintAnalysisResult {
    /// All discovered taint flows.
    pub flows: Vec<TaintFlow>,
    /// Number of sources found.
    pub source_count: usize,
    /// Number of sinks found.
    pub sink_count: usize,
    /// Number of sanitizers found.
    pub sanitizer_count: usize,
    /// Number of unsanitized flows (vulnerabilities).
    pub vulnerability_count: usize,
    /// Analysis duration in microseconds.
    pub duration_us: u64,
}
