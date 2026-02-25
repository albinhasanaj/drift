//! Shared test fixtures and generators for benchmarks.
//! Deterministic: same seed → same output across runs.

use std::path::{Path, PathBuf};

/// A generated test project with deterministic file content.
pub struct TestFixture {
    pub root: PathBuf,
    pub files: Vec<FixtureFile>,
    pub total_lines: usize,
    pub total_bytes: usize,
}

/// A single generated file in a test fixture.
pub struct FixtureFile {
    pub path: PathBuf,
    pub language: &'static str,
    pub lines: usize,
    pub bytes: usize,
}

/// Fixture size presets.
#[derive(Debug, Clone, Copy)]
pub enum FixtureSize {
    /// ~10 files, ~500 lines — unit test scale
    Micro,
    /// ~100 files, ~10K lines — small project
    Small,
    /// ~1K files, ~100K lines — medium project
    Medium,
    /// ~10K files, ~1M lines — large monorepo
    Large,
}

impl FixtureSize {
    pub fn file_count(&self) -> usize {
        match self {
            Self::Micro => 10,
            Self::Small => 100,
            Self::Medium => 1_000,
            Self::Large => 10_000,
        }
    }

    pub fn lines_per_file(&self) -> usize {
        match self {
            Self::Micro => 50,
            Self::Small => 100,
            Self::Medium => 100,
            Self::Large => 100,
        }
    }
}

/// Language distribution for generated fixtures.
struct LangSpec {
    extension: &'static str,
    language: &'static str,
    weight: usize,
}

const LANG_DISTRIBUTION: &[LangSpec] = &[
    LangSpec { extension: "ts", language: "typescript", weight: 35 },
    LangSpec { extension: "js", language: "javascript", weight: 15 },
    LangSpec { extension: "py", language: "python", weight: 15 },
    LangSpec { extension: "rs", language: "rust", weight: 10 },
    LangSpec { extension: "go", language: "go", weight: 10 },
    LangSpec { extension: "java", language: "java", weight: 10 },
    LangSpec { extension: "rb", language: "ruby", weight: 5 },
];

/// Generate a deterministic test fixture on disk.
/// Uses a simple PRNG seeded from the given seed for reproducibility.
pub fn generate_fixture(root: &Path, size: FixtureSize, seed: u64) -> TestFixture {
    let file_count = size.file_count();
    let lines_per_file = size.lines_per_file();
    let mut rng = SimpleRng::new(seed);
    let mut files = Vec::with_capacity(file_count);
    let mut total_lines = 0;
    let mut total_bytes = 0;

    // Create directory structure: src/{module_N}/
    let module_count = (file_count / 10).max(1);
    for m in 0..module_count {
        let module_dir = root.join("src").join(format!("module_{}", m));
        let _ = std::fs::create_dir_all(&module_dir);
    }

    for i in 0..file_count {
        let module_idx = i % module_count;
        let lang = pick_language(&mut rng);
        let filename = format!("file_{}.{}", i, lang.extension);
        let file_path = root
            .join("src")
            .join(format!("module_{}", module_idx))
            .join(&filename);

        let content = generate_file_content(lang.language, lang.extension, lines_per_file, i, &mut rng);
        let bytes = content.len();
        let lines = content.lines().count();

        let _ = std::fs::write(&file_path, &content);

        files.push(FixtureFile {
            path: file_path,
            language: lang.language,
            lines,
            bytes,
        });

        total_lines += lines;
        total_bytes += bytes;
    }

    // Create marker files for detection
    let _ = std::fs::write(root.join("package.json"), r#"{"name":"test-fixture","version":"1.0.0"}"#);
    let _ = std::fs::write(root.join("tsconfig.json"), r#"{"compilerOptions":{"target":"es2020"}}"#);

    TestFixture {
        root: root.to_path_buf(),
        files,
        total_lines,
        total_bytes,
    }
}

fn pick_language(rng: &mut SimpleRng) -> &'static LangSpec {
    let total_weight: usize = LANG_DISTRIBUTION.iter().map(|l| l.weight).sum();
    let mut pick = (rng.next_u64() as usize) % total_weight;
    for spec in LANG_DISTRIBUTION {
        if pick < spec.weight {
            return spec;
        }
        pick -= spec.weight;
    }
    &LANG_DISTRIBUTION[0]
}

fn generate_file_content(
    language: &str,
    extension: &str,
    target_lines: usize,
    file_idx: usize,
    rng: &mut SimpleRng,
) -> String {
    let mut out = String::with_capacity(target_lines * 60);

    // File header
    match language {
        "typescript" | "javascript" => {
            out.push_str(&format!("// Generated fixture file_{}.{}\n", file_idx, extension));
            out.push_str("import { BaseService } from '../shared/base';\n\n");
        }
        "python" => {
            out.push_str(&format!("# Generated fixture file_{}.{}\n", file_idx, extension));
            out.push_str("from typing import Optional, List\n\n");
        }
        "rust" => {
            out.push_str(&format!("// Generated fixture file_{}.{}\n", file_idx, extension));
            out.push_str("use std::collections::HashMap;\n\n");
        }
        "go" => {
            out.push_str(&format!("// Generated fixture file_{}.{}\n", file_idx, extension));
            out.push_str(&format!("package module_{}\n\n", file_idx % 10));
            out.push_str("import \"fmt\"\n\n");
        }
        "java" => {
            out.push_str(&format!("// Generated fixture file_{}.{}\n", file_idx, extension));
            out.push_str(&format!("package com.test.module{};\n\n", file_idx % 10));
        }
        "ruby" => {
            out.push_str(&format!("# Generated fixture file_{}.{}\n", file_idx, extension));
            out.push_str("# frozen_string_literal: true\n\n");
        }
        _ => {}
    }

    // Generate functions/classes
    let func_count = (target_lines / 15).max(1);
    for f in 0..func_count {
        let complexity = (rng.next_u64() % 5) as usize + 1;
        out.push_str(&generate_function(language, f, file_idx, complexity, rng));
        out.push('\n');
    }

    out
}

fn generate_function(
    language: &str,
    func_idx: usize,
    file_idx: usize,
    complexity: usize,
    rng: &mut SimpleRng,
) -> String {
    let name = format!("process_item_{}_{}", file_idx, func_idx);
    let mut out = String::new();

    match language {
        "typescript" | "javascript" => {
            out.push_str(&format!("export function {}(input: string): string {{\n", name));
            for i in 0..complexity {
                out.push_str(&format!("  const step{} = input.trim();\n", i));
            }
            out.push_str(&format!("  if (input.length > {}) {{\n", rng.next_u64() % 100));
            out.push_str("    throw new Error('Input too long');\n");
            out.push_str("  }\n");
            out.push_str(&format!("  return step{};\n", complexity - 1));
            out.push_str("}\n");
        }
        "python" => {
            out.push_str(&format!("def {}(input: str) -> str:\n", name));
            out.push_str(&format!("    \"\"\"Process item {} from file {}.\"\"\"\n", func_idx, file_idx));
            for i in 0..complexity {
                out.push_str(&format!("    step{} = input.strip()\n", i));
            }
            out.push_str(&format!("    if len(input) > {}:\n", rng.next_u64() % 100));
            out.push_str("        raise ValueError('Input too long')\n");
            out.push_str(&format!("    return step{}\n", complexity - 1));
        }
        "rust" => {
            out.push_str(&format!("pub fn {}(input: &str) -> String {{\n", name));
            for i in 0..complexity {
                out.push_str(&format!("    let step{} = input.trim();\n", i));
            }
            out.push_str(&format!("    if input.len() > {} {{\n", rng.next_u64() % 100));
            out.push_str("        panic!(\"Input too long\");\n");
            out.push_str("    }\n");
            out.push_str(&format!("    step{}.to_string()\n", complexity - 1));
            out.push_str("}\n");
        }
        "go" => {
            out.push_str(&format!("func {}(input string) string {{\n", name));
            for i in 0..complexity {
                out.push_str(&format!("\tstep{} := strings.TrimSpace(input)\n", i));
            }
            out.push_str(&format!("\tif len(input) > {} {{\n", rng.next_u64() % 100));
            out.push_str("\t\tpanic(\"input too long\")\n");
            out.push_str("\t}\n");
            out.push_str(&format!("\treturn step{}\n", complexity - 1));
            out.push_str("}\n");
        }
        "java" => {
            out.push_str(&format!("    public static String {}(String input) {{\n", name));
            for i in 0..complexity {
                out.push_str(&format!("        String step{} = input.trim();\n", i));
            }
            out.push_str(&format!("        if (input.length() > {}) {{\n", rng.next_u64() % 100));
            out.push_str("            throw new IllegalArgumentException(\"Input too long\");\n");
            out.push_str("        }\n");
            out.push_str(&format!("        return step{};\n", complexity - 1));
            out.push_str("    }\n");
        }
        "ruby" => {
            out.push_str(&format!("  def self.{}(input)\n", name));
            for i in 0..complexity {
                out.push_str(&format!("    step{} = input.strip\n", i));
            }
            out.push_str(&format!("    raise 'Input too long' if input.length > {}\n", rng.next_u64() % 100));
            out.push_str(&format!("    step{}\n", complexity - 1));
            out.push_str("  end\n");
        }
        _ => {}
    }

    out
}

/// Simple deterministic PRNG (xorshift64) for reproducible fixtures.
pub struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 1 } else { seed },
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_deterministic() {
        let tmp1 = tempfile::tempdir().unwrap();
        let tmp2 = tempfile::tempdir().unwrap();

        let f1 = generate_fixture(tmp1.path(), FixtureSize::Micro, 42);
        let f2 = generate_fixture(tmp2.path(), FixtureSize::Micro, 42);

        assert_eq!(f1.files.len(), f2.files.len());
        assert_eq!(f1.total_lines, f2.total_lines);
        assert_eq!(f1.total_bytes, f2.total_bytes);

        // Same seed → same file content
        for (a, b) in f1.files.iter().zip(f2.files.iter()) {
            let content_a = std::fs::read_to_string(&a.path).unwrap();
            let content_b = std::fs::read_to_string(&b.path).unwrap();
            assert_eq!(content_a, content_b, "Files should be identical with same seed");
        }
    }

    #[test]
    fn fixture_different_seeds_differ() {
        let tmp1 = tempfile::tempdir().unwrap();
        let tmp2 = tempfile::tempdir().unwrap();

        let f1 = generate_fixture(tmp1.path(), FixtureSize::Micro, 42);
        let f2 = generate_fixture(tmp2.path(), FixtureSize::Micro, 99);

        // Different seeds should produce different content
        let content_a = std::fs::read_to_string(&f1.files[0].path).unwrap();
        let content_b = std::fs::read_to_string(&f2.files[0].path).unwrap();
        assert_ne!(content_a, content_b);
    }

    #[test]
    fn fixture_sizes_correct() {
        let tmp = tempfile::tempdir().unwrap();
        let f = generate_fixture(tmp.path(), FixtureSize::Small, 1);
        assert_eq!(f.files.len(), 100);
        assert!(f.total_lines > 0);
        assert!(f.total_bytes > 0);
    }

    #[test]
    fn rng_deterministic() {
        let mut r1 = SimpleRng::new(42);
        let mut r2 = SimpleRng::new(42);
        for _ in 0..100 {
            assert_eq!(r1.next_u64(), r2.next_u64());
        }
    }
}
