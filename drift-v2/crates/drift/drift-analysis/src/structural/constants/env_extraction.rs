//! Phases 6-9: Environment variable extraction, .env parsing, missing variable detection.

use drift_core::types::collections::FxHashSet;

use super::types::EnvVariable;

/// Extract environment variable references from source code.
pub fn extract_env_references(content: &str, file_path: &str, language: &str) -> Vec<EnvVariable> {
    let mut results = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        match language {
            "typescript" | "javascript" => {
                // process.env.VAR_NAME or process.env['VAR_NAME'] or process.env["VAR_NAME"]
                extract_js_env(trimmed, file_path, line_num as u32 + 1, &mut results);
                // import.meta.env.VITE_VAR (Vite)
                extract_vite_env(trimmed, file_path, line_num as u32 + 1, &mut results);
            }
            "python" => {
                // os.environ['VAR'] or os.environ.get('VAR') or os.getenv('VAR')
                extract_python_env(trimmed, file_path, line_num as u32 + 1, &mut results);
            }
            "java" | "kotlin" => {
                // System.getenv("VAR") or System.getProperty("VAR")
                extract_java_env(trimmed, file_path, line_num as u32 + 1, &mut results);
            }
            "rust" => {
                // std::env::var("VAR") or env::var("VAR") or env!("VAR")
                extract_rust_env(trimmed, file_path, line_num as u32 + 1, &mut results);
            }
            "go" => {
                // os.Getenv("VAR") or os.LookupEnv("VAR")
                extract_go_env(trimmed, file_path, line_num as u32 + 1, &mut results);
            }
            "csharp" => {
                // Environment.GetEnvironmentVariable("VAR")
                extract_csharp_env(trimmed, file_path, line_num as u32 + 1, &mut results);
            }
            "ruby" => {
                // ENV['VAR'] or ENV.fetch('VAR')
                extract_ruby_env(trimmed, file_path, line_num as u32 + 1, &mut results);
            }
            "php" => {
                // getenv('VAR') or $_ENV['VAR'] or env('VAR')
                extract_php_env(trimmed, file_path, line_num as u32 + 1, &mut results);
            }
            _ => {}
        }
    }

    // Detect framework-specific prefixes
    for env_var in &mut results {
        env_var.framework_prefix = detect_framework_prefix(&env_var.name);
    }

    results
}

/// Parse a .env file and return defined variable names.
pub fn parse_env_file(content: &str) -> FxHashSet<String> {
    let mut names = FxHashSet::default();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(eq_pos) = trimmed.find('=') {
            let name = trimmed[..eq_pos].trim();
            if !name.is_empty() {
                names.insert(name.to_string());
            }
        }
    }

    names
}

/// Detect missing environment variables: referenced in code but not in .env.
pub fn detect_missing_env_vars(
    references: &[EnvVariable],
    defined: &FxHashSet<String>,
) -> Vec<String> {
    let mut missing: Vec<String> = references
        .iter()
        .filter(|r| !r.has_default && !defined.contains(&r.name))
        .map(|r| r.name.clone())
        .collect();

    missing.sort();
    missing.dedup();
    missing
}

/// Detect framework-specific env var prefixes.
fn detect_framework_prefix(name: &str) -> Option<String> {
    let prefixes = [
        ("NEXT_PUBLIC_", "Next.js"),
        ("VITE_", "Vite"),
        ("REACT_APP_", "Create React App"),
        ("VUE_APP_", "Vue CLI"),
        ("NUXT_", "Nuxt"),
        ("GATSBY_", "Gatsby"),
        ("EXPO_PUBLIC_", "Expo"),
        ("DJANGO_", "Django"),
        ("FLASK_", "Flask"),
        ("SPRING_", "Spring"),
        ("RAILS_", "Rails"),
        ("LARAVEL_", "Laravel"),
    ];

    for (prefix, framework) in &prefixes {
        if name.starts_with(prefix) {
            return Some(framework.to_string());
        }
    }
    None
}

// --- Language-specific extractors ---

fn extract_js_env(line: &str, file: &str, line_num: u32, results: &mut Vec<EnvVariable>) {
    // process.env.VAR_NAME
    let marker = "process.env.";
    let mut search_from = 0;
    while let Some(pos) = line[search_from..].find(marker) {
        let abs_pos = search_from + pos + marker.len();
        let rest = &line[abs_pos..];
        let name: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
        if !name.is_empty() {
            results.push(EnvVariable {
                name,
                file: file.to_string(),
                line: line_num,
                access_method: "process.env".to_string(),
                has_default: line.contains("||") || line.contains("??"),
                defined_in_env: false,
                framework_prefix: None,
            });
        }
        search_from = abs_pos + 1;
    }

    // process.env['VAR'] or process.env["VAR"]
    for bracket_marker in &["process.env['", "process.env[\""] {
        if let Some(pos) = line.find(bracket_marker) {
            let start = pos + bracket_marker.len();
            let quote = if bracket_marker.contains('\'') { '\'' } else { '"' };
            if let Some(end) = line[start..].find(quote) {
                let name = &line[start..start + end];
                results.push(EnvVariable {
                    name: name.to_string(),
                    file: file.to_string(),
                    line: line_num,
                    access_method: "process.env".to_string(),
                    has_default: line.contains("||") || line.contains("??"),
                    defined_in_env: false,
                    framework_prefix: None,
                });
            }
        }
    }
}

fn extract_vite_env(line: &str, file: &str, line_num: u32, results: &mut Vec<EnvVariable>) {
    let marker = "import.meta.env.";
    if let Some(pos) = line.find(marker) {
        let start = pos + marker.len();
        let rest = &line[start..];
        let name: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
        if !name.is_empty() {
            results.push(EnvVariable {
                name,
                file: file.to_string(),
                line: line_num,
                access_method: "import.meta.env".to_string(),
                has_default: false,
                defined_in_env: false,
                framework_prefix: None,
            });
        }
    }
}

fn extract_python_env(line: &str, file: &str, line_num: u32, results: &mut Vec<EnvVariable>) {
    for marker in &["os.environ.get(", "os.environ[", "os.getenv("] {
        if let Some(pos) = line.find(marker) {
            let start = pos + marker.len();
            if let Some(name) = extract_quoted_arg(&line[start..]) {
                let has_default = marker.contains("get(") || marker.contains("getenv(");
                results.push(EnvVariable {
                    name,
                    file: file.to_string(),
                    line: line_num,
                    access_method: marker.trim_end_matches(&['(', '['][..]).to_string(),
                    has_default,
                    defined_in_env: false,
                    framework_prefix: None,
                });
            }
        }
    }
}

fn extract_java_env(line: &str, file: &str, line_num: u32, results: &mut Vec<EnvVariable>) {
    for marker in &["System.getenv(", "System.getProperty("] {
        if let Some(pos) = line.find(marker) {
            let start = pos + marker.len();
            if let Some(name) = extract_quoted_arg(&line[start..]) {
                results.push(EnvVariable {
                    name,
                    file: file.to_string(),
                    line: line_num,
                    access_method: marker.trim_end_matches('(').to_string(),
                    has_default: false,
                    defined_in_env: false,
                    framework_prefix: None,
                });
            }
        }
    }
}

fn extract_rust_env(line: &str, file: &str, line_num: u32, results: &mut Vec<EnvVariable>) {
    for marker in &["env::var(", "std::env::var(", "env!("] {
        if let Some(pos) = line.find(marker) {
            let start = pos + marker.len();
            if let Some(name) = extract_quoted_arg(&line[start..]) {
                results.push(EnvVariable {
                    name,
                    file: file.to_string(),
                    line: line_num,
                    access_method: marker.trim_end_matches('(').to_string(),
                    has_default: line.contains("unwrap_or"),
                    defined_in_env: false,
                    framework_prefix: None,
                });
            }
        }
    }
}

fn extract_go_env(line: &str, file: &str, line_num: u32, results: &mut Vec<EnvVariable>) {
    for marker in &["os.Getenv(", "os.LookupEnv("] {
        if let Some(pos) = line.find(marker) {
            let start = pos + marker.len();
            if let Some(name) = extract_quoted_arg(&line[start..]) {
                results.push(EnvVariable {
                    name,
                    file: file.to_string(),
                    line: line_num,
                    access_method: marker.trim_end_matches('(').to_string(),
                    has_default: marker.contains("Lookup"),
                    defined_in_env: false,
                    framework_prefix: None,
                });
            }
        }
    }
}

fn extract_csharp_env(line: &str, file: &str, line_num: u32, results: &mut Vec<EnvVariable>) {
    let marker = "Environment.GetEnvironmentVariable(";
    if let Some(pos) = line.find(marker) {
        let start = pos + marker.len();
        if let Some(name) = extract_quoted_arg(&line[start..]) {
            results.push(EnvVariable {
                name,
                file: file.to_string(),
                line: line_num,
                access_method: "Environment.GetEnvironmentVariable".to_string(),
                has_default: false,
                defined_in_env: false,
                framework_prefix: None,
            });
        }
    }
}

fn extract_ruby_env(line: &str, file: &str, line_num: u32, results: &mut Vec<EnvVariable>) {
    for marker in &["ENV['", "ENV[\"", "ENV.fetch('", "ENV.fetch(\""] {
        if let Some(pos) = line.find(marker) {
            let start = pos + marker.len();
            let quote = if marker.contains('\'') { '\'' } else { '"' };
            if let Some(end) = line[start..].find(quote) {
                let name = &line[start..start + end];
                results.push(EnvVariable {
                    name: name.to_string(),
                    file: file.to_string(),
                    line: line_num,
                    access_method: "ENV".to_string(),
                    has_default: marker.contains("fetch"),
                    defined_in_env: false,
                    framework_prefix: None,
                });
            }
        }
    }
}

fn extract_php_env(line: &str, file: &str, line_num: u32, results: &mut Vec<EnvVariable>) {
    for marker in &["getenv('", "getenv(\"", "$_ENV['", "$_ENV[\"", "env('", "env(\""] {
        if let Some(pos) = line.find(marker) {
            let start = pos + marker.len();
            let quote = if marker.contains('\'') { '\'' } else { '"' };
            if let Some(end) = line[start..].find(quote) {
                let name = &line[start..start + end];
                results.push(EnvVariable {
                    name: name.to_string(),
                    file: file.to_string(),
                    line: line_num,
                    access_method: if marker.starts_with('$') { "$_ENV" } else { "getenv" }.to_string(),
                    has_default: false,
                    defined_in_env: false,
                    framework_prefix: None,
                });
            }
        }
    }
}

/// Extract a quoted argument from a position.
fn extract_quoted_arg(s: &str) -> Option<String> {
    let trimmed = s.trim_start();
    let quote = trimmed.chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let after = &trimmed[1..];
    let end = after.find(quote)?;
    Some(after[..end].to_string())
}
