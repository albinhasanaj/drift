//! Parser benchmarks — T1-INT-04.
//!
//! Benchmarks: per-language parsing timing, 100 files each.
//! Run with: cargo bench -p drift-analysis --bench parser_bench

use std::path::PathBuf;

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use drift_analysis::parsers::manager::ParserManager;
use drift_analysis::scanner::language_detect::Language;

/// Generate sample source code for a given language.
fn sample_source(lang: Language, idx: usize) -> (String, String) {
    match lang {
        Language::TypeScript => (
            format!("file_{idx}.ts"),
            format!(
                r#"export interface Config_{idx} {{ name: string; value: number; }}
export function process_{idx}(config: Config_{idx}): string {{
    const result = config.name + String(config.value);
    return result.toUpperCase();
}}
export async function fetch_{idx}(url: string): Promise<Response> {{
    return await fetch(url);
}}
"#
            ),
        ),
        Language::JavaScript => (
            format!("file_{idx}.js"),
            format!(
                r#"function compute_{idx}(a, b) {{
    return a + b * {idx};
}}
module.exports = {{ compute_{idx} }};
"#
            ),
        ),
        Language::Python => (
            format!("file_{idx}.py"),
            format!(
                r#"def process_{idx}(data: list) -> dict:
    result = {{}}
    for item in data:
        result[item] = len(item) * {idx}
    return result

class Handler_{idx}:
    def __init__(self, config):
        self.config = config

    async def handle(self, request):
        return await self.process(request)
"#
            ),
        ),
        Language::Java => (
            format!("File_{idx}.java"),
            format!(
                r#"public class File_{idx} {{
    private int value = {idx};
    public int getValue() {{ return value; }}
    public void setValue(int v) {{ this.value = v; }}
}}
"#
            ),
        ),
        Language::Go => (
            format!("file_{idx}.go"),
            format!(
                r#"package main

func Process_{idx}(input string) string {{
    return input + "_{idx}"
}}
"#
            ),
        ),
        Language::Rust => (
            format!("file_{idx}.rs"),
            format!(
                r#"pub fn compute_{idx}(x: i32) -> i32 {{
    x * {idx}
}}
"#
            ),
        ),
        _ => (
            format!("file_{idx}.ts"),
            format!("export const x_{idx} = {idx};\n"),
        ),
    }
}

fn parser_per_language(c: &mut Criterion) {
    let mut group = c.benchmark_group("parser_per_language");
    group.sample_size(20);

    let parser = ParserManager::new();

    let languages = [
        Language::TypeScript,
        Language::JavaScript,
        Language::Python,
        Language::Java,
        Language::Go,
        Language::Rust,
    ];

    for lang in languages {
        // Pre-generate 100 source files
        let sources: Vec<(PathBuf, Vec<u8>)> = (0..100)
            .map(|i| {
                let (name, src) = sample_source(lang, i);
                (PathBuf::from(&name), src.into_bytes())
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::new("parse_100", format!("{lang:?}")),
            &sources,
            |b, sources| {
                b.iter(|| {
                    for (path, source) in sources {
                        let _ = parser.parse(source, path);
                    }
                });
            },
        );
    }

    group.finish();
}

fn parser_cache_effectiveness(c: &mut Criterion) {
    let mut group = c.benchmark_group("parser_cache");
    group.sample_size(20);

    let parser = ParserManager::new();
    let source = b"export function hello(name: string): string { return `Hello ${name}`; }\n";
    let path = PathBuf::from("cached.ts");

    // First parse (cold)
    group.bench_function("cold_parse", |b| {
        b.iter(|| {
            let p = ParserManager::new();
            p.parse(source, &path).unwrap();
        });
    });

    // Warm up cache
    parser.parse(source, &path).unwrap();

    // Cached parse (hot)
    group.bench_function("cached_parse", |b| {
        b.iter(|| {
            parser.parse(source, &path).unwrap();
        });
    });

    group.finish();
}

criterion_group!(benches, parser_per_language, parser_cache_effectiveness);
criterion_main!(benches);
