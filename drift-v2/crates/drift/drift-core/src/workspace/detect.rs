//! Language and framework auto-detection.
//! Expanded from v1's 7 languages to 11 ecosystems.

use std::path::Path;

/// Detect languages present in the project by checking for ecosystem marker files.
pub fn detect_languages(root: &Path) -> Vec<String> {
    let mut languages = Vec::new();

    let checks: &[(&str, &[&str])] = &[
        ("typescript", &["tsconfig.json"]),
        ("javascript", &["package.json"]),
        ("python", &["requirements.txt", "pyproject.toml", "setup.py", "Pipfile"]),
        ("java", &["pom.xml", "build.gradle", "build.gradle.kts"]),
        ("csharp", &[]),  // Glob-based detection below
        ("php", &["composer.json"]),
        ("go", &["go.mod"]),
        ("rust", &["Cargo.toml"]),
        ("ruby", &["Gemfile"]),
        ("swift", &["Package.swift"]),
        ("kotlin", &["build.gradle.kts"]),
    ];

    for (lang, markers) in checks {
        for marker in *markers {
            if root.join(marker).exists() {
                languages.push(lang.to_string());
                break;
            }
        }
    }

    // Glob-based detection for C# (.csproj, .sln)
    if (glob_exists(root, "*.csproj") || glob_exists(root, "*.sln"))
        && !languages.contains(&"csharp".to_string())
    {
        languages.push("csharp".to_string());
    }

    // Swift Xcode detection
    if glob_exists(root, "*.xcodeproj") && !languages.contains(&"swift".to_string()) {
        languages.push("swift".to_string());
    }

    // Deduplicate: if typescript detected, remove javascript
    if languages.contains(&"typescript".to_string()) {
        languages.retain(|l| l != "javascript");
    }

    // Remove duplicates while preserving order
    let mut seen = std::collections::HashSet::new();
    languages.retain(|l| seen.insert(l.clone()));

    languages
}

/// Detect frameworks from project dependency files.
pub fn detect_frameworks(root: &Path) -> Vec<String> {
    let mut frameworks = Vec::new();

    // Node.js frameworks (from package.json)
    if let Ok(content) = std::fs::read_to_string(root.join("package.json")) {
        let node_checks: &[(&str, &str)] = &[
            ("\"next\"", "Next.js"),
            ("\"react\"", "React"),
            ("\"vue\"", "Vue"),
            ("\"@angular/core\"", "Angular"),
            ("\"express\"", "Express"),
            ("\"fastify\"", "Fastify"),
            ("\"@nestjs/core\"", "NestJS"),
            ("\"svelte\"", "Svelte"),
            ("\"nuxt\"", "Nuxt"),
            ("\"remix\"", "Remix"),
            ("\"hono\"", "Hono"),
            ("\"koa\"", "Koa"),
        ];
        for (dep, name) in node_checks {
            if content.contains(dep) {
                frameworks.push(name.to_string());
            }
        }
    }

    // Python frameworks
    let python_files = ["requirements.txt", "pyproject.toml", "Pipfile"];
    for file in &python_files {
        if let Ok(content) = std::fs::read_to_string(root.join(file)) {
            let lower = content.to_lowercase();
            if lower.contains("django") && !frameworks.contains(&"Django".to_string()) {
                frameworks.push("Django".to_string());
            }
            if lower.contains("flask") && !frameworks.contains(&"Flask".to_string()) {
                frameworks.push("Flask".to_string());
            }
            if lower.contains("fastapi") && !frameworks.contains(&"FastAPI".to_string()) {
                frameworks.push("FastAPI".to_string());
            }
        }
    }

    // Java/Kotlin frameworks
    if root.join("pom.xml").exists() || root.join("build.gradle").exists() {
        for file in &["pom.xml", "build.gradle", "build.gradle.kts"] {
            if let Ok(content) = std::fs::read_to_string(root.join(file)) {
                if content.contains("spring-boot") {
                    frameworks.push("Spring Boot".to_string());
                    break;
                }
            }
        }
    }

    frameworks
}

/// Check if any file matching a glob pattern exists in a directory.
fn glob_exists(root: &Path, pattern: &str) -> bool {
    let full_pattern = root.join(pattern).display().to_string();
    glob::glob(&full_pattern)
        .map(|mut paths| paths.next().is_some())
        .unwrap_or(false)
}

/// Generate a drift.toml configuration template.
pub fn generate_config_template(template: &str, project_name: &str) -> String {
    match template {
        "strict" => format!(
            r#"# Drift Configuration — Strict Mode
[workspace]
name = "{project_name}"

[scan]
exclude = ["node_modules", "dist", ".git", "vendor"]

[quality_gates]
default_policy = "strict"
new_code_only = false
fail_on_violation = true
"#
        ),
        "ci" => format!(
            r#"# Drift Configuration — CI Mode
[workspace]
name = "{project_name}"

[scan]
exclude = ["node_modules", "dist", ".git", "vendor"]
parallelism = 0

[quality_gates]
default_policy = "default"
new_code_only = true
"#
        ),
        _ => format!(
            r#"# Drift Configuration
# Documentation: https://drift.dev/docs/configuration

[workspace]
name = "{project_name}"
# languages = ["typescript"]  # Override auto-detection if needed

[scan]
exclude = ["node_modules", "dist", ".git", "vendor", "build", "target", "__pycache__"]
# parallelism = 0  # 0 = auto (CPU cores - 1)
# max_file_size_kb = 1024  # Skip files larger than this

[backup]
auto_backup = true
max_operational = 5
max_daily = 7
max_weekly = 4
max_total_size_mb = 500

[quality_gates]
# default_policy = "default"
# new_code_only = true

# [packages.frontend]
# path = "apps/web"
# policy = "strict"
"#
        ),
    }
}
