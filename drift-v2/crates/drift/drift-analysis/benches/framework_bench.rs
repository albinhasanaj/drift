//! Benchmark for framework pattern matching performance.
//!
//! Measures throughput of the framework matcher across all built-in packs
//! with realistic TypeScript content, validating that RegexSet and
//! Aho-Corasick optimizations provide measurable speedup.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use drift_analysis::engine::visitor::{DetectionContext, FileDetectorHandler};
use drift_analysis::frameworks::registry::FrameworkPackRegistry;
use drift_analysis::frameworks::FrameworkMatcher;
use drift_analysis::parsers::types::*;
use drift_analysis::scanner::language_detect::Language;

fn bench_framework_matching(c: &mut Criterion) {
    let registry = FrameworkPackRegistry::with_builtins();
    let packs = registry.into_packs();

    let source = b"import express from 'express';\n\
        import { Injectable } from '@angular/core';\n\
        const app = express();\n\
        app.get('/api/users', (req, res) => {\n\
            const token = req.headers.authorization;\n\
            const users = db.query('SELECT * FROM users');\n\
            res.json({ users });\n\
        });\n\
        app.post('/api/login', async (req, res) => {\n\
            try {\n\
                const { email, password } = req.body;\n\
                const user = await authenticate(email, password);\n\
                res.json({ token: generateJWT(user) });\n\
            } catch (err) {\n\
                res.status(500).json({ error: err.message });\n\
            }\n\
        });\n";

    let pr = ParseResult {
        language: Language::TypeScript,
        ..Default::default()
    };

    c.bench_function("framework_match_1000_files", |b| {
        b.iter(|| {
            let mut matcher = FrameworkMatcher::new(packs.clone());
            for i in 0..1000 {
                let file = format!("src/file_{i}.ts");
                let ctx = DetectionContext {
                    file: &file,
                    language: Language::TypeScript,
                    source: black_box(source),
                    parse_result: &pr,
                    imports: &[],
                    classes: &[],
                    functions: &[],
                    call_sites: &[],
                    exports: &[],
                };
                matcher.analyze_file(&ctx);
            }
            matcher.match_diagnostics()
        })
    });

    c.bench_function("framework_pack_loading", |b| {
        b.iter(|| {
            let registry = FrameworkPackRegistry::with_builtins();
            black_box(registry.into_packs())
        })
    });
}

criterion_group!(benches, bench_framework_matching);
criterion_main!(benches);
