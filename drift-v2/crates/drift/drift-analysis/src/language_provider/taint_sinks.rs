//! Taint sink extraction — feeds Phase 4 taint analysis.
//!
//! Identifies functions/methods that are security-sensitive sinks
//! (SQL execution, command execution, file I/O, etc.)

use serde::{Deserialize, Serialize};

use crate::scanner::language_detect::Language;

/// A taint sink definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSink {
    pub name: String,
    pub receiver: Option<String>,
    pub category: SinkCategory,
    pub language: Language,
    pub tainted_params: Vec<usize>,
    pub severity: SinkSeverity,
}

/// Categories of taint sinks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SinkCategory {
    SqlExecution,
    CommandExecution,
    FileWrite,
    FileRead,
    NetworkRequest,
    HtmlRendering,
    Deserialization,
    Logging,
    Redirect,
    Eval,
}

/// Severity of a taint sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SinkSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// Extract taint sink definitions for a given language.
pub fn extract_sinks(language: Language) -> Vec<TaintSink> {
    match language {
        Language::TypeScript | Language::JavaScript => typescript_sinks(),
        Language::Python => python_sinks(),
        Language::Java => java_sinks(),
        Language::CSharp => csharp_sinks(),
        Language::Go => go_sinks(),
        Language::Ruby => ruby_sinks(),
        Language::Php => php_sinks(),
        Language::Rust => rust_sinks(),
        Language::Kotlin => kotlin_sinks(),
        Language::Cpp | Language::C => csharp_sinks(),
        Language::Swift | Language::Scala => java_sinks(),
    }
}

fn typescript_sinks() -> Vec<TaintSink> {
    vec![
        TaintSink { name: "eval".into(), receiver: None, category: SinkCategory::Eval, language: Language::JavaScript, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "exec".into(), receiver: None, category: SinkCategory::CommandExecution, language: Language::JavaScript, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "query".into(), receiver: Some("connection".into()), category: SinkCategory::SqlExecution, language: Language::JavaScript, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "innerHTML".into(), receiver: None, category: SinkCategory::HtmlRendering, language: Language::JavaScript, tainted_params: vec![0], severity: SinkSeverity::High },
        TaintSink { name: "writeFile".into(), receiver: Some("fs".into()), category: SinkCategory::FileWrite, language: Language::JavaScript, tainted_params: vec![1], severity: SinkSeverity::High },
        TaintSink { name: "redirect".into(), receiver: Some("res".into()), category: SinkCategory::Redirect, language: Language::JavaScript, tainted_params: vec![0], severity: SinkSeverity::Medium },
    ]
}

fn python_sinks() -> Vec<TaintSink> {
    vec![
        TaintSink { name: "eval".into(), receiver: None, category: SinkCategory::Eval, language: Language::Python, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "exec".into(), receiver: None, category: SinkCategory::Eval, language: Language::Python, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "system".into(), receiver: Some("os".into()), category: SinkCategory::CommandExecution, language: Language::Python, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "execute".into(), receiver: Some("cursor".into()), category: SinkCategory::SqlExecution, language: Language::Python, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "open".into(), receiver: None, category: SinkCategory::FileRead, language: Language::Python, tainted_params: vec![0], severity: SinkSeverity::High },
        TaintSink { name: "loads".into(), receiver: Some("pickle".into()), category: SinkCategory::Deserialization, language: Language::Python, tainted_params: vec![0], severity: SinkSeverity::Critical },
    ]
}

fn java_sinks() -> Vec<TaintSink> {
    vec![
        TaintSink { name: "executeQuery".into(), receiver: Some("Statement".into()), category: SinkCategory::SqlExecution, language: Language::Java, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "executeUpdate".into(), receiver: Some("Statement".into()), category: SinkCategory::SqlExecution, language: Language::Java, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "exec".into(), receiver: Some("Runtime".into()), category: SinkCategory::CommandExecution, language: Language::Java, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "start".into(), receiver: Some("ProcessBuilder".into()), category: SinkCategory::CommandExecution, language: Language::Java, tainted_params: vec![], severity: SinkSeverity::Critical },
        TaintSink { name: "readObject".into(), receiver: Some("ObjectInputStream".into()), category: SinkCategory::Deserialization, language: Language::Java, tainted_params: vec![], severity: SinkSeverity::Critical },
        TaintSink { name: "write".into(), receiver: Some("FileOutputStream".into()), category: SinkCategory::FileWrite, language: Language::Java, tainted_params: vec![0], severity: SinkSeverity::High },
        TaintSink { name: "sendRedirect".into(), receiver: Some("HttpServletResponse".into()), category: SinkCategory::Redirect, language: Language::Java, tainted_params: vec![0], severity: SinkSeverity::Medium },
        TaintSink { name: "log".into(), receiver: Some("Logger".into()), category: SinkCategory::Logging, language: Language::Java, tainted_params: vec![0], severity: SinkSeverity::Low },
    ]
}

fn csharp_sinks() -> Vec<TaintSink> {
    vec![
        TaintSink { name: "ExecuteNonQuery".into(), receiver: Some("SqlCommand".into()), category: SinkCategory::SqlExecution, language: Language::CSharp, tainted_params: vec![], severity: SinkSeverity::Critical },
        TaintSink { name: "ExecuteReader".into(), receiver: Some("SqlCommand".into()), category: SinkCategory::SqlExecution, language: Language::CSharp, tainted_params: vec![], severity: SinkSeverity::Critical },
        TaintSink { name: "FromSqlRaw".into(), receiver: None, category: SinkCategory::SqlExecution, language: Language::CSharp, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "Start".into(), receiver: Some("Process".into()), category: SinkCategory::CommandExecution, language: Language::CSharp, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "Deserialize".into(), receiver: Some("JsonSerializer".into()), category: SinkCategory::Deserialization, language: Language::CSharp, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "WriteAllText".into(), receiver: Some("File".into()), category: SinkCategory::FileWrite, language: Language::CSharp, tainted_params: vec![1], severity: SinkSeverity::High },
        TaintSink { name: "Redirect".into(), receiver: None, category: SinkCategory::Redirect, language: Language::CSharp, tainted_params: vec![0], severity: SinkSeverity::Medium },
        TaintSink { name: "HtmlString".into(), receiver: None, category: SinkCategory::HtmlRendering, language: Language::CSharp, tainted_params: vec![0], severity: SinkSeverity::High },
    ]
}

fn go_sinks() -> Vec<TaintSink> {
    vec![
        TaintSink { name: "Exec".into(), receiver: Some("db".into()), category: SinkCategory::SqlExecution, language: Language::Go, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "Query".into(), receiver: Some("db".into()), category: SinkCategory::SqlExecution, language: Language::Go, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "QueryRow".into(), receiver: Some("db".into()), category: SinkCategory::SqlExecution, language: Language::Go, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "Command".into(), receiver: Some("exec".into()), category: SinkCategory::CommandExecution, language: Language::Go, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "WriteFile".into(), receiver: Some("os".into()), category: SinkCategory::FileWrite, language: Language::Go, tainted_params: vec![1], severity: SinkSeverity::High },
        TaintSink { name: "ReadFile".into(), receiver: Some("os".into()), category: SinkCategory::FileRead, language: Language::Go, tainted_params: vec![0], severity: SinkSeverity::High },
        TaintSink { name: "Unmarshal".into(), receiver: Some("json".into()), category: SinkCategory::Deserialization, language: Language::Go, tainted_params: vec![0], severity: SinkSeverity::High },
        TaintSink { name: "Redirect".into(), receiver: None, category: SinkCategory::Redirect, language: Language::Go, tainted_params: vec![1], severity: SinkSeverity::Medium },
    ]
}

fn ruby_sinks() -> Vec<TaintSink> {
    vec![
        TaintSink { name: "eval".into(), receiver: None, category: SinkCategory::Eval, language: Language::Ruby, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "system".into(), receiver: None, category: SinkCategory::CommandExecution, language: Language::Ruby, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "exec".into(), receiver: None, category: SinkCategory::CommandExecution, language: Language::Ruby, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "execute".into(), receiver: Some("ActiveRecord".into()), category: SinkCategory::SqlExecution, language: Language::Ruby, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "find_by_sql".into(), receiver: None, category: SinkCategory::SqlExecution, language: Language::Ruby, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "html_safe".into(), receiver: None, category: SinkCategory::HtmlRendering, language: Language::Ruby, tainted_params: vec![], severity: SinkSeverity::High },
        TaintSink { name: "write".into(), receiver: Some("File".into()), category: SinkCategory::FileWrite, language: Language::Ruby, tainted_params: vec![1], severity: SinkSeverity::High },
        TaintSink { name: "Marshal.load".into(), receiver: None, category: SinkCategory::Deserialization, language: Language::Ruby, tainted_params: vec![0], severity: SinkSeverity::Critical },
    ]
}

fn php_sinks() -> Vec<TaintSink> {
    vec![
        TaintSink { name: "eval".into(), receiver: None, category: SinkCategory::Eval, language: Language::Php, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "exec".into(), receiver: None, category: SinkCategory::CommandExecution, language: Language::Php, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "shell_exec".into(), receiver: None, category: SinkCategory::CommandExecution, language: Language::Php, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "system".into(), receiver: None, category: SinkCategory::CommandExecution, language: Language::Php, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "query".into(), receiver: Some("PDO".into()), category: SinkCategory::SqlExecution, language: Language::Php, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "query".into(), receiver: Some("mysqli".into()), category: SinkCategory::SqlExecution, language: Language::Php, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "file_put_contents".into(), receiver: None, category: SinkCategory::FileWrite, language: Language::Php, tainted_params: vec![1], severity: SinkSeverity::High },
        TaintSink { name: "unserialize".into(), receiver: None, category: SinkCategory::Deserialization, language: Language::Php, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "header".into(), receiver: None, category: SinkCategory::Redirect, language: Language::Php, tainted_params: vec![0], severity: SinkSeverity::Medium },
    ]
}

fn rust_sinks() -> Vec<TaintSink> {
    vec![
        TaintSink { name: "execute".into(), receiver: Some("Connection".into()), category: SinkCategory::SqlExecution, language: Language::Rust, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "query".into(), receiver: Some("sqlx".into()), category: SinkCategory::SqlExecution, language: Language::Rust, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "Command".into(), receiver: Some("std::process".into()), category: SinkCategory::CommandExecution, language: Language::Rust, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "write_all".into(), receiver: Some("File".into()), category: SinkCategory::FileWrite, language: Language::Rust, tainted_params: vec![0], severity: SinkSeverity::High },
        TaintSink { name: "from_slice".into(), receiver: Some("serde_json".into()), category: SinkCategory::Deserialization, language: Language::Rust, tainted_params: vec![0], severity: SinkSeverity::High },
        TaintSink { name: "get".into(), receiver: Some("reqwest".into()), category: SinkCategory::NetworkRequest, language: Language::Rust, tainted_params: vec![0], severity: SinkSeverity::Medium },
    ]
}

fn kotlin_sinks() -> Vec<TaintSink> {
    vec![
        TaintSink { name: "executeQuery".into(), receiver: Some("Statement".into()), category: SinkCategory::SqlExecution, language: Language::Kotlin, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "executeUpdate".into(), receiver: Some("Statement".into()), category: SinkCategory::SqlExecution, language: Language::Kotlin, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "exec".into(), receiver: Some("Runtime".into()), category: SinkCategory::CommandExecution, language: Language::Kotlin, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "ProcessBuilder".into(), receiver: None, category: SinkCategory::CommandExecution, language: Language::Kotlin, tainted_params: vec![0], severity: SinkSeverity::Critical },
        TaintSink { name: "writeText".into(), receiver: Some("File".into()), category: SinkCategory::FileWrite, language: Language::Kotlin, tainted_params: vec![0], severity: SinkSeverity::High },
        TaintSink { name: "readText".into(), receiver: Some("File".into()), category: SinkCategory::FileRead, language: Language::Kotlin, tainted_params: vec![], severity: SinkSeverity::High },
        TaintSink { name: "readObject".into(), receiver: Some("ObjectInputStream".into()), category: SinkCategory::Deserialization, language: Language::Kotlin, tainted_params: vec![], severity: SinkSeverity::Critical },
        TaintSink { name: "redirect".into(), receiver: None, category: SinkCategory::Redirect, language: Language::Kotlin, tainted_params: vec![0], severity: SinkSeverity::Medium },
    ]
}
