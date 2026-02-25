//! Parse tsconfig.json (with `extends` chain) and resolve path aliases.
//!
//! Supports: `paths`, `baseUrl`, `extends` chains (up to 10 levels),
//! wildcard patterns (`@/*` → `src/*`), and exact-match patterns.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Resolved tsconfig path alias configuration.
#[derive(Debug, Clone, Default)]
pub struct TsConfigPaths {
    pub base_url: Option<String>,
    pub paths: HashMap<String, Vec<String>>,
}

/// A compiled alias rule ready for fast matching.
#[derive(Debug, Clone)]
pub struct AliasRule {
    pub prefix: String,
    pub wildcard: bool,
    pub targets: Vec<String>,
}

impl TsConfigPaths {
    /// Load tsconfig.json from the project root, following `extends` chains.
    pub fn load(project_root: &Path) -> Option<Self> {
        let candidates = ["tsconfig.json", "tsconfig.app.json", "tsconfig.build.json"];
        for name in &candidates {
            let path = project_root.join(name);
            if let Some(config) = Self::load_from_file(&path, 0) {
                if !config.paths.is_empty() {
                    return Some(config);
                }
            }
        }
        let path = project_root.join("tsconfig.json");
        Self::load_from_file(&path, 0)
    }

    fn load_from_file(path: &Path, depth: usize) -> Option<Self> {
        if depth > 10 || !path.exists() {
            return None;
        }

        let content = std::fs::read_to_string(path).ok()?;
        let content = strip_json_comments(&content);
        let json: serde_json::Value = serde_json::from_str(&content).ok()?;

        let mut base = if let Some(extends) = json.get("extends").and_then(|e| e.as_str()) {
            let extends_path = resolve_extends_path(path, extends)?;
            Self::load_from_file(&extends_path, depth + 1).unwrap_or_default()
        } else {
            Self::default()
        };

        if let Some(compiler_opts) = json.get("compilerOptions") {
            if let Some(base_url) = compiler_opts.get("baseUrl").and_then(|b| b.as_str()) {
                base.base_url = Some(base_url.to_string());
            }
            if let Some(paths) = compiler_opts.get("paths").and_then(|p| p.as_object()) {
                for (key, value) in paths {
                    if let Some(arr) = value.as_array() {
                        let targets: Vec<String> = arr
                            .iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect();
                        if !targets.is_empty() {
                            base.paths.insert(key.clone(), targets);
                        }
                    }
                }
            }
        }

        Some(base)
    }

    /// Compile the paths map into a list of alias rules for resolution.
    pub fn compile_rules(&self) -> Vec<AliasRule> {
        let mut rules = Vec::with_capacity(self.paths.len());
        for (pattern, targets) in &self.paths {
            if let Some(prefix) = pattern.strip_suffix("/*") {
                let resolved: Vec<String> = targets
                    .iter()
                    .map(|t| {
                        let t = t.strip_suffix("/*").unwrap_or(t);
                        apply_base_url(&self.base_url, t)
                    })
                    .collect();
                rules.push(AliasRule {
                    prefix: prefix.to_string(),
                    wildcard: true,
                    targets: resolved,
                });
            } else {
                let resolved: Vec<String> = targets
                    .iter()
                    .map(|t| apply_base_url(&self.base_url, t))
                    .collect();
                rules.push(AliasRule {
                    prefix: pattern.clone(),
                    wildcard: false,
                    targets: resolved,
                });
            }
        }
        rules
    }
}

fn apply_base_url(base_url: &Option<String>, target: &str) -> String {
    match base_url {
        Some(base) if base != "." && !base.is_empty() => format!("{}/{}", base, target),
        _ => target.to_string(),
    }
}

/// Resolve an import source using tsconfig path aliases.
/// Returns the resolved path (relative to project root, no extension) if matched.
pub fn resolve_alias(source: &str, rules: &[AliasRule]) -> Option<String> {
    for rule in rules {
        if rule.prefix.is_empty() {
            continue;
        }
        if rule.wildcard {
            if let Some(rest) = source.strip_prefix(&rule.prefix) {
                let rest = rest.strip_prefix('/').unwrap_or(rest);
                if let Some(target) = rule.targets.first() {
                    if target.is_empty() {
                        return Some(rest.to_string());
                    }
                    return Some(format!("{}/{}", target, rest));
                }
            }
        } else if source == rule.prefix {
            return rule.targets.first().cloned();
        }
    }
    None
}

/// Strip // and /* */ comments from JSON (tsconfig allows them).
fn strip_json_comments(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_string = false;
    let mut escape_next = false;

    while let Some(ch) = chars.next() {
        if escape_next {
            result.push(ch);
            escape_next = false;
            continue;
        }
        if in_string {
            result.push(ch);
            if ch == '\\' {
                escape_next = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        if ch == '"' {
            in_string = true;
            result.push(ch);
            continue;
        }
        if ch == '/' {
            match chars.peek() {
                Some('/') => {
                    chars.next();
                    for c in chars.by_ref() {
                        if c == '\n' {
                            result.push('\n');
                            break;
                        }
                    }
                }
                Some('*') => {
                    chars.next();
                    loop {
                        match chars.next() {
                            Some('*') if chars.peek() == Some(&'/') => {
                                chars.next();
                                break;
                            }
                            Some('\n') => result.push('\n'),
                            None => break,
                            _ => {}
                        }
                    }
                }
                _ => result.push(ch),
            }
        } else {
            result.push(ch);
        }
    }
    result
}

/// Resolve the file path for a tsconfig `extends` value.
fn resolve_extends_path(tsconfig_path: &Path, extends: &str) -> Option<PathBuf> {
    let parent = tsconfig_path.parent()?;

    if extends.starts_with('.') {
        let resolved = parent.join(extends);
        if resolved.exists() {
            return Some(resolved);
        }
        let with_json = parent.join(format!("{}.json", extends));
        if with_json.exists() {
            return Some(with_json);
        }
    } else {
        let mut dir = Some(parent.to_path_buf());
        while let Some(d) = dir {
            for candidate in &[
                d.join("node_modules").join(extends),
                d.join("node_modules").join(format!("{}.json", extends)),
                d.join("node_modules").join(extends).join("tsconfig.json"),
            ] {
                if candidate.exists() {
                    return Some(candidate.clone());
                }
            }
            dir = d.parent().map(|p| p.to_path_buf());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_wildcard_alias() {
        let rules = vec![AliasRule {
            prefix: "@".to_string(),
            wildcard: true,
            targets: vec!["src".to_string()],
        }];
        assert_eq!(
            resolve_alias("@/components/Button", &rules),
            Some("src/components/Button".to_string())
        );
        assert_eq!(
            resolve_alias("@/utils/format", &rules),
            Some("src/utils/format".to_string())
        );
    }

    #[test]
    fn test_resolve_scoped_alias() {
        let rules = vec![
            AliasRule {
                prefix: "@components".to_string(),
                wildcard: true,
                targets: vec!["src/components".to_string()],
            },
            AliasRule {
                prefix: "@utils".to_string(),
                wildcard: true,
                targets: vec!["src/utils".to_string()],
            },
        ];
        assert_eq!(
            resolve_alias("@components/Button", &rules),
            Some("src/components/Button".to_string())
        );
        assert_eq!(
            resolve_alias("@utils/format", &rules),
            Some("src/utils/format".to_string())
        );
    }

    #[test]
    fn test_resolve_exact_alias() {
        let rules = vec![AliasRule {
            prefix: "~config".to_string(),
            wildcard: false,
            targets: vec!["src/config/index".to_string()],
        }];
        assert_eq!(
            resolve_alias("~config", &rules),
            Some("src/config/index".to_string())
        );
        assert_eq!(resolve_alias("~config/sub", &rules), None);
    }

    #[test]
    fn test_no_match_returns_none() {
        let rules = vec![AliasRule {
            prefix: "@".to_string(),
            wildcard: true,
            targets: vec!["src".to_string()],
        }];
        assert_eq!(resolve_alias("./relative/path", &rules), None);
        assert_eq!(resolve_alias("react", &rules), None);
    }

    #[test]
    fn test_strip_json_comments() {
        let input = r#"{
  // This is a comment
  "compilerOptions": {
    "baseUrl": ".", /* inline comment */
    "paths": {
      "@/*": ["src/*"]
    }
  }
}"#;
        let stripped = strip_json_comments(input);
        let parsed: serde_json::Value = serde_json::from_str(&stripped).unwrap();
        assert_eq!(
            parsed["compilerOptions"]["baseUrl"].as_str(),
            Some(".")
        );
    }

    #[test]
    fn test_compile_rules_with_base_url() {
        let config = TsConfigPaths {
            base_url: Some("src".to_string()),
            paths: HashMap::from([("@/*".to_string(), vec!["*".to_string()])]),
        };
        let rules = config.compile_rules();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].prefix, "@");
        assert!(rules[0].wildcard);
        assert_eq!(rules[0].targets, vec!["src/*"]);
    }
}
