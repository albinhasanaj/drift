//! Monorepo workspace detection and package registration.
//! Supports: pnpm, npm/yarn, Cargo, Go, Maven, .NET, Lerna.

use std::path::{Path, PathBuf};

use rusqlite::Connection;

use super::errors::WorkspaceResult;

/// Workspace layout — single project or monorepo.
#[derive(Debug, Clone)]
pub enum WorkspaceLayout {
    SingleProject(PathBuf),
    Monorepo {
        root: PathBuf,
        packages: Vec<PackageInfo>,
    },
}

/// Information about a package within a monorepo.
#[derive(Debug, Clone)]
pub struct PackageInfo {
    pub name: String,
    pub path: PathBuf,
    pub language: Option<String>,
    pub framework: Option<String>,
    pub dependencies: Vec<String>,
}

/// Detect workspace layout. Cascading check for ecosystem-specific markers.
pub fn detect_workspace(root: &Path) -> WorkspaceResult<WorkspaceLayout> {
    // 1. pnpm workspaces
    if root.join("pnpm-workspace.yaml").exists() {
        return parse_pnpm_workspace(root);
    }

    // 2. npm/yarn workspaces (package.json with "workspaces" field)
    if let Ok(content) = std::fs::read_to_string(root.join("package.json")) {
        if content.contains("\"workspaces\"") {
            return parse_npm_workspace(root, &content);
        }
    }

    // 3. Cargo workspaces (Cargo.toml with [workspace] section)
    if let Ok(content) = std::fs::read_to_string(root.join("Cargo.toml")) {
        if content.contains("[workspace]") {
            return parse_cargo_workspace(root, &content);
        }
    }

    // 4. Go workspaces (go.work file)
    if root.join("go.work").exists() {
        return parse_go_workspace(root);
    }

    // 5. Lerna (lerna.json)
    if root.join("lerna.json").exists() {
        return parse_lerna_workspace(root);
    }

    // No workspace detected — single project
    Ok(WorkspaceLayout::SingleProject(root.to_path_buf()))
}

/// Register detected packages in drift.db.
pub fn register_packages(conn: &Connection, packages: &[PackageInfo]) -> WorkspaceResult<()> {
    conn.execute("DELETE FROM workspace_packages", [])?;

    for pkg in packages {
        let pkg_id = generate_package_id(&pkg.name);
        conn.execute(
            "INSERT INTO workspace_packages (id, name, path, language, framework, dependencies)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                pkg_id,
                pkg.name,
                pkg.path.display().to_string(),
                pkg.language,
                pkg.framework,
                serde_json::to_string(&pkg.dependencies).unwrap_or_else(|_| "[]".to_string()),
            ],
        )?;
    }

    Ok(())
}

/// Get registered packages from drift.db.
pub fn list_packages(conn: &Connection) -> WorkspaceResult<Vec<PackageInfo>> {
    let mut stmt = conn.prepare_cached(
        "SELECT name, path, language, framework, dependencies FROM workspace_packages",
    )?;
    let rows = stmt
        .query_map([], |row| {
            let deps_str: String = row.get(4)?;
            let deps: Vec<String> =
                serde_json::from_str(&deps_str).unwrap_or_default();
            Ok(PackageInfo {
                name: row.get(0)?,
                path: PathBuf::from(row.get::<_, String>(1)?),
                language: row.get(2)?,
                framework: row.get(3)?,
                dependencies: deps,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

// ---- Parser implementations ----

fn parse_pnpm_workspace(root: &Path) -> WorkspaceResult<WorkspaceLayout> {
    // pnpm-workspace.yaml contains patterns like:
    // packages:
    //   - 'packages/*'
    //   - 'apps/*'
    let content = std::fs::read_to_string(root.join("pnpm-workspace.yaml"))?;
    let mut packages = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim().trim_start_matches("- ").trim_matches('\'').trim_matches('"');
        if trimmed.ends_with("/*") || trimmed.ends_with("/**") {
            let base = trimmed.trim_end_matches("/**").trim_end_matches("/*");
            let base_path = root.join(base);
            if base_path.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&base_path) {
                    for entry in entries.flatten() {
                        let entry_path = entry.path();
                        if entry_path.is_dir() && entry_path.join("package.json").exists() {
                            packages.push(package_from_dir(&entry_path, root));
                        }
                    }
                }
            }
        }
    }

    Ok(WorkspaceLayout::Monorepo {
        root: root.to_path_buf(),
        packages,
    })
}

fn parse_npm_workspace(root: &Path, content: &str) -> WorkspaceResult<WorkspaceLayout> {
    // Extract workspace patterns from package.json "workspaces" array
    let mut packages = Vec::new();

    // Simple extraction: find patterns like "packages/*"
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
        if let Some(workspaces) = json.get("workspaces") {
            let patterns: Vec<String> = match workspaces {
                serde_json::Value::Array(arr) => {
                    arr.iter().filter_map(|v| v.as_str().map(String::from)).collect()
                }
                serde_json::Value::Object(obj) => {
                    if let Some(serde_json::Value::Array(arr)) = obj.get("packages") {
                        arr.iter().filter_map(|v| v.as_str().map(String::from)).collect()
                    } else {
                        vec![]
                    }
                }
                _ => vec![],
            };

            for pattern in patterns {
                if pattern.ends_with("/*") {
                    let base = pattern.trim_end_matches("/*");
                    let base_path = root.join(base);
                    if base_path.is_dir() {
                        if let Ok(entries) = std::fs::read_dir(&base_path) {
                            for entry in entries.flatten() {
                                let entry_path = entry.path();
                                if entry_path.is_dir()
                                    && entry_path.join("package.json").exists()
                                {
                                    packages.push(package_from_dir(&entry_path, root));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(WorkspaceLayout::Monorepo {
        root: root.to_path_buf(),
        packages,
    })
}

fn parse_cargo_workspace(root: &Path, content: &str) -> WorkspaceResult<WorkspaceLayout> {
    let mut packages = Vec::new();

    // Extract members from [workspace] section
    // Parse quoted strings from lines between `members = [` and `]`
    let mut in_members = false;
    let mut quoted_parts: Vec<String> = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("members") && trimmed.contains('[') {
            in_members = true;
        }
        if in_members {
            let parts: Vec<&str> = trimmed.split('"').collect();
            for (i, part) in parts.iter().enumerate() {
                if i % 2 == 1 && !part.is_empty() {
                    quoted_parts.push(part.to_string());
                }
            }
            if trimmed.contains(']') {
                in_members = false;
            }
        }
    }

    // Resolve each member pattern
    for member in &quoted_parts {
        if member.ends_with("/*") || member.ends_with("/**") {
            // Glob pattern — expand by listing directory
            let base = member.trim_end_matches("/**").trim_end_matches("/*");
            let base_path = root.join(base);
            if base_path.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&base_path) {
                    for entry in entries.flatten() {
                        let entry_path = entry.path();
                        if entry_path.is_dir() && entry_path.join("Cargo.toml").exists() {
                            let name = entry_path
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("unknown")
                                .to_string();
                            let relative = format!("{}/{}", base, name);
                            packages.push(PackageInfo {
                                name,
                                path: PathBuf::from(relative),
                                language: Some("rust".to_string()),
                                framework: None,
                                dependencies: vec![],
                            });
                        }
                    }
                }
            }
        } else {
            // Exact path
            let full = root.join(member);
            if full.is_dir() && full.join("Cargo.toml").exists() {
                let name = full
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(member)
                    .to_string();
                packages.push(PackageInfo {
                    name,
                    path: PathBuf::from(member),
                    language: Some("rust".to_string()),
                    framework: None,
                    dependencies: vec![],
                });
            }
        }
    }

    Ok(WorkspaceLayout::Monorepo {
        root: root.to_path_buf(),
        packages,
    })
}

fn parse_go_workspace(root: &Path) -> WorkspaceResult<WorkspaceLayout> {
    let content = std::fs::read_to_string(root.join("go.work"))?;
    let mut packages = Vec::new();

    // go.work contains `use` directives: use ./cmd/foo
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("use ") || trimmed.starts_with("./") || trimmed.starts_with("../") {
            let path_str = trimmed.trim_start_matches("use ").trim();
            let full = root.join(path_str);
            if full.is_dir() && full.join("go.mod").exists() {
                packages.push(PackageInfo {
                    name: full
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(path_str)
                        .to_string(),
                    path: PathBuf::from(path_str),
                    language: Some("go".to_string()),
                    framework: None,
                    dependencies: vec![],
                });
            }
        }
    }

    Ok(WorkspaceLayout::Monorepo {
        root: root.to_path_buf(),
        packages,
    })
}

fn parse_lerna_workspace(root: &Path) -> WorkspaceResult<WorkspaceLayout> {
    let content = std::fs::read_to_string(root.join("lerna.json"))?;
    let mut packages = Vec::new();

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
        if let Some(serde_json::Value::Array(patterns)) = json.get("packages") {
            for pattern in patterns {
                if let Some(pat) = pattern.as_str() {
                    if pat.ends_with("/*") {
                        let base = pat.trim_end_matches("/*");
                        let base_path = root.join(base);
                        if base_path.is_dir() {
                            if let Ok(entries) = std::fs::read_dir(&base_path) {
                                for entry in entries.flatten() {
                                    let entry_path = entry.path();
                                    if entry_path.is_dir()
                                        && entry_path.join("package.json").exists()
                                    {
                                        packages.push(package_from_dir(&entry_path, root));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(WorkspaceLayout::Monorepo {
        root: root.to_path_buf(),
        packages,
    })
}

fn package_from_dir(dir: &Path, root: &Path) -> PackageInfo {
    let name = dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();
    let relative = dir.strip_prefix(root).unwrap_or(dir);

    PackageInfo {
        name,
        path: relative.to_path_buf(),
        language: if dir.join("tsconfig.json").exists() {
            Some("typescript".to_string())
        } else if dir.join("package.json").exists() {
            Some("javascript".to_string())
        } else if dir.join("Cargo.toml").exists() {
            Some("rust".to_string())
        } else if dir.join("go.mod").exists() {
            Some("go".to_string())
        } else {
            None
        },
        framework: None,
        dependencies: vec![],
    }
}

fn generate_package_id(name: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    name.hash(&mut hasher);
    format!("pkg-{:016x}", hasher.finish())
}
