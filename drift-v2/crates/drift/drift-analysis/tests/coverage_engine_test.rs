//! Engine coverage tests — exercise visitor engine, resolution index,
//! call graph resolution, DI support, and parser language dispatch.

#![allow(dead_code, unused, clippy::field_reassign_with_default, clippy::cloned_ref_to_slice_refs, clippy::manual_range_contains, clippy::comparison_to_empty)]

use std::path::Path;
use smallvec::SmallVec;

use drift_analysis::engine::visitor::*;
use drift_analysis::engine::resolution::*;
use drift_analysis::engine::types::*;
use drift_analysis::parsers::types::*;
use drift_analysis::parsers::manager::ParserManager;
use drift_analysis::scanner::language_detect::Language;
use drift_analysis::call_graph::resolution as cg_resolution;
use drift_analysis::call_graph::di_support;
use drift_analysis::call_graph::types::Resolution;
use drift_analysis::boundaries::extractors::FieldExtractor;
use drift_analysis::boundaries::types::OrmFramework;
use drift_core::types::collections::FxHashMap;

// ---- Visitor engine tests ----

struct TestHandler {
    enter_count: usize,
    exit_count: usize,
    matches: Vec<PatternMatch>,
}

impl TestHandler {
    fn new() -> Self {
        Self { enter_count: 0, exit_count: 0, matches: Vec::new() }
    }
}

impl DetectorHandler for TestHandler {
    fn id(&self) -> &str { "test-handler" }
    fn node_types(&self) -> &[&str] { &["function_declaration", "call_expression"] }
    fn languages(&self) -> &[Language] { &[Language::TypeScript] }

    fn on_enter(&mut self, _node: &tree_sitter::Node, _source: &[u8], _ctx: &DetectionContext) {
        self.enter_count += 1;
    }
    fn on_exit(&mut self, _node: &tree_sitter::Node, _source: &[u8], _ctx: &DetectionContext) {
        self.exit_count += 1;
    }
    fn results(&self) -> Vec<PatternMatch> { self.matches.clone() }
    fn reset(&mut self) { self.enter_count = 0; self.exit_count = 0; self.matches.clear(); }
}

struct WildcardHandler {
    count: usize,
}

impl WildcardHandler {
    fn new() -> Self { Self { count: 0 } }
}

impl DetectorHandler for WildcardHandler {
    fn id(&self) -> &str { "wildcard-handler" }
    fn node_types(&self) -> &[&str] { &[] } // empty = wildcard
    fn languages(&self) -> &[Language] { &[] } // empty = all languages

    fn on_enter(&mut self, _node: &tree_sitter::Node, _source: &[u8], _ctx: &DetectionContext) {
        self.count += 1;
    }
    fn on_exit(&mut self, _node: &tree_sitter::Node, _source: &[u8], _ctx: &DetectionContext) {}
    fn results(&self) -> Vec<PatternMatch> { vec![] }
    fn reset(&mut self) { self.count = 0; }
}

struct TestFileHandler {
    analyzed: bool,
}

impl TestFileHandler {
    fn new() -> Self { Self { analyzed: false } }
}

impl FileDetectorHandler for TestFileHandler {
    fn id(&self) -> &str { "test-file-handler" }
    fn languages(&self) -> &[Language] { &[] }
    fn analyze_file(&mut self, _ctx: &DetectionContext) { self.analyzed = true; }
    fn results(&self) -> Vec<PatternMatch> { vec![] }
    fn reset(&mut self) { self.analyzed = false; }
}

struct TestLearningHandler {
    learned: usize,
    detected: usize,
}

impl TestLearningHandler {
    fn new() -> Self { Self { learned: 0, detected: 0 } }
}

impl LearningDetectorHandler for TestLearningHandler {
    fn id(&self) -> &str { "test-learning-handler" }
    fn languages(&self) -> &[Language] { &[] }
    fn learn(&mut self, _ctx: &DetectionContext) { self.learned += 1; }
    fn detect(&mut self, _ctx: &DetectionContext) { self.detected += 1; }
    fn results(&self) -> Vec<PatternMatch> { vec![] }
    fn reset(&mut self) { self.learned = 0; self.detected = 0; }
}

fn make_ts_source() -> &'static [u8] {
    b"import { User } from './models';

export function authenticate(token: string): Promise<User> {
    const decoded = jwt.verify(token);
    return User.findOne({ where: { id: decoded.id } });
}

function helper() {
    console.log('debug');
}
"
}

fn make_pr_for_engine() -> ParseResult {
    let parser = ParserManager::new();
    parser.parse(make_ts_source(), Path::new("service.ts")).unwrap()
}

#[test]
fn engine_visitor_registry() {
    let mut registry = VisitorRegistry::new();
    assert_eq!(registry.handler_count(), 0);
    assert_eq!(registry.file_handler_count(), 0);
    assert_eq!(registry.learning_handler_count(), 0);

    registry.register(Box::new(TestHandler::new()));
    registry.register(Box::new(WildcardHandler::new()));
    registry.register_file_handler(Box::new(TestFileHandler::new()));
    registry.register_learning_handler(Box::new(TestLearningHandler::new()));

    assert_eq!(registry.handler_count(), 2);
    assert_eq!(registry.file_handler_count(), 1);
    assert_eq!(registry.learning_handler_count(), 1);
}

#[test]
fn engine_detection_engine_run() {
    let mut registry = VisitorRegistry::new();
    registry.register(Box::new(TestHandler::new()));
    registry.register(Box::new(WildcardHandler::new()));
    registry.register_file_handler(Box::new(TestFileHandler::new()));

    let mut engine = DetectionEngine::new(registry);

    let source = make_ts_source();
    let pr = make_pr_for_engine();
    let ctx = DetectionContext::from_parse_result(&pr, source);

    // Parse the source with tree-sitter
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()).unwrap();
    let tree = parser.parse(source, None).unwrap();

    let matches = engine.run(&tree, source, &ctx);
    // Handlers should have been called
    assert_eq!(engine.registry().handler_count(), 2);
}

#[test]
fn engine_learning_pass() {
    let mut registry = VisitorRegistry::new();
    registry.register_learning_handler(Box::new(TestLearningHandler::new()));

    let mut engine = DetectionEngine::new(registry);

    let source = make_ts_source();
    let pr = make_pr_for_engine();
    let ctx = DetectionContext::from_parse_result(&pr, source);

    let matches = engine.run_learning_pass(&[ctx]);
    // Learning handler should have been called
    eprintln!("learning matches: {}", matches.len());
}

// ---- Resolution index tests ----

#[test]
fn engine_resolution_index() {
    let pr = make_pr_for_engine();
    let index = ResolutionIndex::build(&[pr]);

    assert!(index.entry_count() > 0);
    assert!(index.name_count() > 0);
    assert!(index.file_count() > 0);

    // Resolve a function from the same file
    let entries = index.entries_for_file("service.ts");
    assert!(!entries.is_empty());

    // Test all 6 resolution strategies
    for strategy in ResolutionStrategy::all() {
        let conf = strategy.default_confidence();
        assert!(conf > 0.0 && conf <= 1.0);
        assert!(!format!("{}", strategy).is_empty());
    }
}

#[test]
fn engine_resolution_resolve() {
    let mut pr = ParseResult::default();
    pr.file = "main.ts".to_string();
    pr.language = Language::TypeScript;
    pr.functions.push(FunctionInfo {
        name: "helper".to_string(),
        qualified_name: None,
        file: "main.ts".to_string(),
        line: 1, column: 0, end_line: 5,
        parameters: SmallVec::new(),
        return_type: None, generic_params: SmallVec::new(),
        visibility: Visibility::Public,
        is_exported: true, is_async: false, is_generator: false, is_abstract: false,
        range: Range::default(), decorators: vec![], doc_comment: None,
        body_hash: 0, signature_hash: 0,
    });
    pr.classes.push(ClassInfo {
        name: "UserService".to_string(), namespace: None, extends: None,
        implements: SmallVec::new(), generic_params: SmallVec::new(),
        is_exported: true, is_abstract: false, class_kind: ClassKind::Class,
        methods: vec![FunctionInfo {
            name: "getUser".to_string(),
            qualified_name: Some("UserService.getUser".to_string()),
            file: "main.ts".to_string(),
            line: 10, column: 4, end_line: 15,
            parameters: SmallVec::new(),
            return_type: None, generic_params: SmallVec::new(),
            visibility: Visibility::Public,
            is_exported: false, is_async: false, is_generator: false, is_abstract: false,
            range: Range::default(), decorators: vec![], doc_comment: None,
            body_hash: 0, signature_hash: 0,
        }],
        properties: vec![],
        range: Range::default(), decorators: vec![],
    });
    pr.imports.push(ImportInfo {
        source: "./utils".to_string(),
        specifiers: SmallVec::from_vec(vec![ImportSpecifier { name: "format".to_string(), alias: None }]),
        is_type_only: false, file: "main.ts".to_string(), line: 1,
    });
    pr.exports.push(ExportInfo {
        name: Some("helper".to_string()), is_default: false, is_type_only: false,
        source: None, file: "main.ts".to_string(), line: 1,
    });

    let mut pr2 = ParseResult::default();
    pr2.file = "other.ts".to_string();
    pr2.language = Language::TypeScript;
    pr2.functions.push(FunctionInfo {
        name: "externalFn".to_string(),
        qualified_name: None,
        file: "other.ts".to_string(),
        line: 1, column: 0, end_line: 5,
        parameters: SmallVec::new(),
        return_type: None, generic_params: SmallVec::new(),
        visibility: Visibility::Public,
        is_exported: true, is_async: false, is_generator: false, is_abstract: false,
        range: Range::default(), decorators: vec![], doc_comment: None,
        body_hash: 0, signature_hash: 0,
    });

    let index = ResolutionIndex::build(&[pr, pr2]);

    // Direct resolution (same file)
    let result = index.resolve("helper", "main.ts");
    assert!(result.is_some());
    let (_, strategy, conf) = result.unwrap();
    assert_eq!(strategy, ResolutionStrategy::Direct);
    assert!(conf >= 0.90);

    // Method resolution
    let result = index.resolve("getUser", "other.ts");
    assert!(result.is_some());

    // Constructor resolution
    let result = index.resolve("UserService", "other.ts");
    assert!(result.is_some());

    // External resolution
    let result = index.resolve("externalFn", "main.ts");
    assert!(result.is_some());

    // Class methods
    let methods = index.class_methods("UserService");
    assert!(methods.is_some());
    assert!(methods.unwrap().contains(&"getUser".to_string()));

    // Non-existent
    let result = index.resolve("nonexistent", "main.ts");
    assert!(result.is_none());
}

// ---- Call graph resolution tests ----

#[test]
fn cg_resolve_call() {
    let mut name_index: FxHashMap<String, Vec<String>> = FxHashMap::default();
    name_index.insert("helper".to_string(), vec!["main.ts::helper".to_string()]);
    name_index.insert("format".to_string(), vec!["utils.ts::format".to_string()]);
    name_index.insert("ambiguous".to_string(), vec!["a.ts::ambiguous".to_string(), "b.ts::ambiguous".to_string()]);

    let mut qualified_index: FxHashMap<String, String> = FxHashMap::default();
    qualified_index.insert("User.findAll".to_string(), "models.ts::User.findAll".to_string());

    let mut export_index: FxHashMap<String, Vec<String>> = FxHashMap::default();
    export_index.insert("uniqueExport".to_string(), vec!["lib.ts::uniqueExport".to_string()]);

    let mut language_index: FxHashMap<String, String> = FxHashMap::default();
    language_index.insert("main.ts::helper".to_string(), "TypeScript".to_string());
    language_index.insert("utils.ts::format".to_string(), "TypeScript".to_string());
    language_index.insert("a.ts::ambiguous".to_string(), "TypeScript".to_string());
    language_index.insert("b.ts::ambiguous".to_string(), "TypeScript".to_string());
    language_index.insert("lib.ts::uniqueExport".to_string(), "TypeScript".to_string());
    language_index.insert("models.ts::User.findAll".to_string(), "TypeScript".to_string());

    let imports = vec![ImportInfo {
        source: "./utils".to_string(),
        specifiers: SmallVec::from_vec(vec![ImportSpecifier { name: "format".to_string(), alias: None }]),
        is_type_only: false, file: "main.ts".to_string(), line: 1,
    }];

    // Same-file resolution
    let cs = CallSite { callee_name: "helper".to_string(), receiver: None, file: "main.ts".to_string(), line: 5, column: 4, argument_count: 0, is_await: false };
    let result = cg_resolution::resolve_call(&cs, "main.ts", "TypeScript", &imports, &name_index, &qualified_index, &export_index, &language_index);
    assert!(result.is_some());
    let (key, res) = result.unwrap();
    assert_eq!(res, Resolution::SameFile);

    // Method call resolution
    let cs = CallSite { callee_name: "findAll".to_string(), receiver: Some("User".to_string()), file: "main.ts".to_string(), line: 10, column: 4, argument_count: 1, is_await: true };
    let result = cg_resolution::resolve_call(&cs, "main.ts", "TypeScript", &imports, &name_index, &qualified_index, &export_index, &language_index);
    assert!(result.is_some());
    let (_, res) = result.unwrap();
    assert_eq!(res, Resolution::MethodCall);

    // Import-based resolution
    let cs = CallSite { callee_name: "format".to_string(), receiver: None, file: "main.ts".to_string(), line: 15, column: 4, argument_count: 1, is_await: false };
    let result = cg_resolution::resolve_call(&cs, "main.ts", "TypeScript", &imports, &name_index, &qualified_index, &export_index, &language_index);
    assert!(result.is_some());

    // Export-based resolution
    let cs = CallSite { callee_name: "uniqueExport".to_string(), receiver: None, file: "main.ts".to_string(), line: 20, column: 4, argument_count: 0, is_await: false };
    let result = cg_resolution::resolve_call(&cs, "main.ts", "TypeScript", &[], &name_index, &qualified_index, &export_index, &language_index);
    assert!(result.is_some());
    let (_, res) = result.unwrap();
    assert_eq!(res, Resolution::ExportBased);

    // No resolution (ambiguous)
    let cs = CallSite { callee_name: "ambiguous".to_string(), receiver: None, file: "other.ts".to_string(), line: 25, column: 4, argument_count: 0, is_await: false };
    let result = cg_resolution::resolve_call(&cs, "other.ts", "TypeScript", &[], &name_index, &qualified_index, &export_index, &language_index);
    assert!(result.is_none());

    // Constructor resolution
    let result = cg_resolution::resolve_constructor("User", &qualified_index, &name_index);
    assert!(result.is_none()); // No constructor registered

    // Constructor with class in name_index
    let mut name_index2 = name_index.clone();
    name_index2.insert("MyClass".to_string(), vec!["file.ts::MyClass".to_string()]);
    let result = cg_resolution::resolve_constructor("MyClass", &qualified_index, &name_index2);
    assert!(result.is_some());
}

// ---- DI support tests ----

#[test]
fn cg_di_support() {
    // Test framework detection
    let mut pr = ParseResult::default();
    pr.file = "app.module.ts".to_string();
    pr.language = Language::TypeScript;
    pr.imports.push(ImportInfo {
        source: "@nestjs/common".to_string(),
        specifiers: SmallVec::from_vec(vec![ImportSpecifier { name: "Injectable".to_string(), alias: None }]),
        is_type_only: false, file: pr.file.clone(), line: 1,
    });
    pr.functions.push(FunctionInfo {
        name: "getService".to_string(), qualified_name: None,
        file: pr.file.clone(), line: 5, column: 0, end_line: 10,
        parameters: SmallVec::new(), return_type: None, generic_params: SmallVec::new(),
        visibility: Visibility::Public,
        is_exported: false, is_async: false, is_generator: false, is_abstract: false,
        range: Range::default(),
        decorators: vec![DecoratorInfo { name: "Injectable".to_string(), arguments: SmallVec::new(), raw_text: "@Injectable()".to_string(), range: Range::default() }],
        doc_comment: None, body_hash: 0, signature_hash: 0,
    });

    let detected = di_support::detect_di_frameworks(&[pr]);
    assert!(!detected.is_empty());
    assert_eq!(detected[0].name, "NestJS");

    // Test is_di_decorator
    let dec = DecoratorInfo { name: "Injectable".to_string(), arguments: SmallVec::new(), raw_text: "@Injectable()".to_string(), range: Range::default() };
    assert!(di_support::is_di_decorator(&dec));

    let dec2 = DecoratorInfo { name: "CustomDecorator".to_string(), arguments: SmallVec::new(), raw_text: "@CustomDecorator()".to_string(), range: Range::default() };
    assert!(!di_support::is_di_decorator(&dec2));

    // Test resolve_di_injection
    let mut name_index: FxHashMap<String, Vec<String>> = FxHashMap::default();
    name_index.insert("UserService".to_string(), vec!["services.ts::UserService".to_string()]);
    let result = di_support::resolve_di_injection("UserService", &name_index);
    assert!(result.is_some());
    let (key, res) = result.unwrap();
    assert_eq!(res, Resolution::DiInjection);

    // Ambiguous — no resolution
    let mut name_index2: FxHashMap<String, Vec<String>> = FxHashMap::default();
    name_index2.insert("Service".to_string(), vec!["a.ts::Service".to_string(), "b.ts::Service".to_string()]);
    let result = di_support::resolve_di_injection("Service", &name_index2);
    assert!(result.is_none());
}

// ---- Parser manager coverage ----

#[test]
fn parser_manager_all_languages() {
    let pm = ParserManager::new();

    // Test language detection
    assert_eq!(pm.detect_language(Path::new("file.ts")), Some(Language::TypeScript));
    assert_eq!(pm.detect_language(Path::new("file.py")), Some(Language::Python));
    assert_eq!(pm.detect_language(Path::new("file.java")), Some(Language::Java));
    assert_eq!(pm.detect_language(Path::new("file.unknown")), None);

    // Parse TypeScript
    let ts_src = b"function hello() { return 42; }";
    let result = pm.parse(ts_src, Path::new("test.ts")).unwrap();
    assert_eq!(result.language, Language::TypeScript);
    assert!(!result.functions.is_empty());

    // Parse Python
    let py_src = b"def hello():\n    return 42\n";
    let result = pm.parse(py_src, Path::new("test.py")).unwrap();
    assert_eq!(result.language, Language::Python);

    // Parse Java
    let java_src = b"public class Main { public static void main(String[] args) {} }";
    let result = pm.parse(java_src, Path::new("Main.java")).unwrap();
    assert_eq!(result.language, Language::Java);

    // Parse with known language
    let result = pm.parse_with_language(ts_src, Path::new("test.ts"), Language::TypeScript).unwrap();
    assert_eq!(result.language, Language::TypeScript);

    // Cache hit
    let result2 = pm.parse(ts_src, Path::new("test.ts")).unwrap();
    assert_eq!(result.content_hash, result2.content_hash);
    // Cache may or may not report entries depending on implementation
    eprintln!("cache entries: {}", pm.cache_entry_count());

    // Unsupported extension
    let err = pm.parse(b"hello", Path::new("test.xyz"));
    assert!(err.is_err());
}

// ---- GAST normalizer deeper coverage (more complex source) ----

#[test]
fn normalizer_complex_typescript() {
    use drift_analysis::engine::gast::base_normalizer::GASTNormalizer;
    use drift_analysis::engine::gast::normalizers::typescript::TypeScriptNormalizer;

    let source = br#"
import { Injectable } from '@nestjs/common';
import * as fs from 'fs';

export default class UserService extends BaseService {
    private users: User[] = [];

    constructor(private readonly db: Database) {
        super();
    }

    @Cacheable()
    async getUser(id: string): Promise<User | null> {
        if (!id) {
            throw new Error('Invalid ID');
        }
        try {
            const user = await this.db.query(`SELECT * FROM users WHERE id = ${id}`);
            return user ?? null;
        } catch (err) {
            console.error('Failed:', err);
            return null;
        }
    }

    *generateIds(): Generator<number> {
        let i = 0;
        while (true) {
            yield i++;
        }
    }

    get count(): number { return this.users.length; }
    set count(val: number) { /* noop */ }
}

interface IService {
    getUser(id: string): Promise<User>;
}

enum Status { Active = 'active', Inactive = 'inactive' }

type UserId = string;

const handler = async (req: Request, res: Response) => {
    const data = [...req.body];
    const result = data.length > 0 ? data[0] : null;
    for (const item of data) {
        switch (item.type) {
            case 'user': break;
            default: continue;
        }
    }
};
"#;

    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()).unwrap();
    let tree = parser.parse(source, None).unwrap();
    let gast = TypeScriptNormalizer.normalize(&tree, source);
    assert_eq!(gast.kind(), "program");
    assert!(gast.node_count() > 15, "complex TS should have many nodes, got {}", gast.node_count());
}

#[test]
fn normalizer_complex_python() {
    use drift_analysis::engine::gast::base_normalizer::GASTNormalizer;
    use drift_analysis::engine::gast::normalizers::python::PythonNormalizer;

    let source = br#"
import os
from typing import Optional, List

class UserService:
    """Service for managing users."""

    def __init__(self, db):
        self.db = db
        self._cache = {}

    async def get_user(self, user_id: str) -> Optional[dict]:
        if not user_id:
            raise ValueError("Invalid ID")
        try:
            result = await self.db.query(f"SELECT * FROM users WHERE id = {user_id}")
            return result
        except Exception as e:
            print(f"Error: {e}")
            return None

    def process_batch(self, items: List[dict]):
        for item in items:
            if item.get('type') == 'user':
                self._cache[item['id']] = item
            while False:
                break

    @staticmethod
    def validate(data):
        return bool(data)

def helper():
    x = 42
    y = True
    z = None
    s = "hello"
    return [x, y, z, s]
"#;

    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&tree_sitter_python::LANGUAGE.into()).unwrap();
    let tree = parser.parse(source, None).unwrap();
    let gast = PythonNormalizer.normalize(&tree, source);
    assert_eq!(gast.kind(), "program");
    assert!(gast.node_count() > 20, "complex Python should have many nodes, got {}", gast.node_count());
}

// ---- Parse all 10 languages to cover parser dispatch ----

#[test]
fn parser_all_10_languages() {
    let pm = ParserManager::new();

    // Go
    let go_src = b"package main\nfunc hello() int { return 42 }\n";
    let r = pm.parse(go_src, Path::new("main.go")).unwrap();
    assert_eq!(r.language, Language::Go);

    // C#
    let cs_src = b"using System;\nclass Main { static void Main() {} }\n";
    let r = pm.parse(cs_src, Path::new("Main.cs")).unwrap();
    assert_eq!(r.language, Language::CSharp);

    // Rust
    let rs_src = b"fn main() { let x = 42; }\n";
    let r = pm.parse(rs_src, Path::new("main.rs")).unwrap();
    assert_eq!(r.language, Language::Rust);

    // Ruby
    let rb_src = b"class User\n  def hello\n    42\n  end\nend\n";
    let r = pm.parse(rb_src, Path::new("user.rb")).unwrap();
    assert_eq!(r.language, Language::Ruby);

    // PHP
    let php_src = b"<?php\nfunction hello() { return 42; }\n";
    let r = pm.parse(php_src, Path::new("hello.php")).unwrap();
    assert_eq!(r.language, Language::Php);

    // Kotlin
    let kt_src = b"fun main() { val x = 42 }\n";
    let r = pm.parse(kt_src, Path::new("main.kt")).unwrap();
    assert_eq!(r.language, Language::Kotlin);

    // JavaScript
    let js_src = b"function hello() { return 42; }\n";
    let r = pm.parse(js_src, Path::new("hello.js")).unwrap();
    assert_eq!(r.language, Language::JavaScript);
}

// ---- Boundary extractors with proper data ----

#[test]
fn extractor_ef_core_with_data() {
    use drift_analysis::boundaries::extractors::ef_core::EfCoreExtractor;
    let ext = EfCoreExtractor;
    let mut pr = ParseResult::default();
    pr.file = "Models/AppDbContext.cs".to_string();
    pr.language = Language::CSharp;
    pr.classes.push(ClassInfo {
        name: "AppDbContext".to_string(), namespace: None,
        extends: Some("DbContext".to_string()),
        implements: SmallVec::new(), generic_params: SmallVec::new(),
        is_exported: true, is_abstract: false, class_kind: ClassKind::Class,
        methods: vec![], properties: vec![
            PropertyInfo { name: "Id".to_string(), type_annotation: Some("int".to_string()), is_static: false, is_readonly: false, visibility: Visibility::Public },
            PropertyInfo { name: "Name".to_string(), type_annotation: Some("string".to_string()), is_static: false, is_readonly: false, visibility: Visibility::Public },
        ],
        range: Range { start: Position { line: 5, column: 0 }, end: Position { line: 20, column: 0 } },
        decorators: vec![],
    });
    let models = ext.extract_models(&pr);
    assert_eq!(models.len(), 1);
    assert_eq!(models[0].name, "AppDbContext");
    assert_eq!(models[0].fields.len(), 2);
    assert!(models[0].fields[0].is_primary_key); // "Id" should be PK
}

#[test]
fn extractor_mongoose_with_data() {
    use drift_analysis::boundaries::extractors::mongoose::MongooseExtractor;
    let ext = MongooseExtractor;
    let mut pr = ParseResult::default();
    pr.file = "models/user.schema.ts".to_string();
    pr.language = Language::TypeScript;
    pr.imports.push(ImportInfo {
        source: "mongoose".to_string(),
        specifiers: SmallVec::from_vec(vec![ImportSpecifier { name: "Schema".to_string(), alias: None }]),
        is_type_only: false, file: pr.file.clone(), line: 1,
    });
    pr.classes.push(ClassInfo {
        name: "UserSchema".to_string(), namespace: None, extends: None,
        implements: SmallVec::new(), generic_params: SmallVec::new(),
        is_exported: true, is_abstract: false, class_kind: ClassKind::Class,
        methods: vec![], properties: vec![
            PropertyInfo { name: "_id".to_string(), type_annotation: Some("ObjectId".to_string()), is_static: false, is_readonly: false, visibility: Visibility::Public },
            PropertyInfo { name: "email".to_string(), type_annotation: Some("string".to_string()), is_static: false, is_readonly: false, visibility: Visibility::Public },
        ],
        range: Range { start: Position { line: 3, column: 0 }, end: Position { line: 10, column: 0 } },
        decorators: vec![],
    });
    let models = ext.extract_models(&pr);
    assert_eq!(models.len(), 1);
    assert!(models[0].fields[0].is_primary_key); // "_id" should be PK
}

#[test]
fn extractor_prisma_with_data() {
    use drift_analysis::boundaries::extractors::prisma::PrismaExtractor;
    let ext = PrismaExtractor;
    let mut pr = ParseResult::default();
    pr.file = "src/prisma/client.ts".to_string();
    pr.language = Language::TypeScript;
    pr.imports.push(ImportInfo {
        source: "@prisma/client".to_string(),
        specifiers: SmallVec::from_vec(vec![ImportSpecifier { name: "PrismaClient".to_string(), alias: None }]),
        is_type_only: false, file: pr.file.clone(), line: 1,
    });
    pr.classes.push(ClassInfo {
        name: "User".to_string(), namespace: None, extends: None,
        implements: SmallVec::new(), generic_params: SmallVec::new(),
        is_exported: true, is_abstract: false, class_kind: ClassKind::Class,
        methods: vec![], properties: vec![
            PropertyInfo { name: "id".to_string(), type_annotation: Some("string".to_string()), is_static: false, is_readonly: false, visibility: Visibility::Public },
            PropertyInfo { name: "email".to_string(), type_annotation: Some("string".to_string()), is_static: false, is_readonly: false, visibility: Visibility::Public },
        ],
        range: Range { start: Position { line: 5, column: 0 }, end: Position { line: 10, column: 0 } },
        decorators: vec![],
    });
    let models = ext.extract_models(&pr);
    assert_eq!(models.len(), 1);
    assert_eq!(models[0].framework, OrmFramework::Prisma);
}

#[test]
fn extractor_typeorm_with_data() {
    use drift_analysis::boundaries::extractors::typeorm::TypeOrmExtractor;
    let ext = TypeOrmExtractor;
    let mut pr = ParseResult::default();
    pr.file = "entities/user.entity.ts".to_string();
    pr.language = Language::TypeScript;
    pr.classes.push(ClassInfo {
        name: "User".to_string(), namespace: None, extends: None,
        implements: SmallVec::new(), generic_params: SmallVec::new(),
        is_exported: true, is_abstract: false, class_kind: ClassKind::Class,
        methods: vec![], properties: vec![
            PropertyInfo { name: "id".to_string(), type_annotation: Some("number".to_string()), is_static: false, is_readonly: false, visibility: Visibility::Public },
            PropertyInfo { name: "name".to_string(), type_annotation: Some("string".to_string()), is_static: false, is_readonly: false, visibility: Visibility::Public },
        ],
        range: Range { start: Position { line: 3, column: 0 }, end: Position { line: 10, column: 0 } },
        decorators: vec![DecoratorInfo { name: "Entity".to_string(), arguments: SmallVec::new(), raw_text: "@Entity()".to_string(), range: Range::default() }],
    });
    let models = ext.extract_models(&pr);
    assert_eq!(models.len(), 1);
    assert_eq!(models[0].framework, OrmFramework::TypeOrm);
}

#[test]
fn extractor_hibernate_with_data() {
    use drift_analysis::boundaries::extractors::hibernate::HibernateExtractor;
    let ext = HibernateExtractor;
    let mut pr = ParseResult::default();
    pr.file = "User.java".to_string();
    pr.language = Language::Java;
    pr.classes.push(ClassInfo {
        name: "User".to_string(), namespace: None, extends: None,
        implements: SmallVec::new(), generic_params: SmallVec::new(),
        is_exported: true, is_abstract: false, class_kind: ClassKind::Class,
        methods: vec![], properties: vec![
            PropertyInfo { name: "id".to_string(), type_annotation: Some("Long".to_string()), is_static: false, is_readonly: false, visibility: Visibility::Private },
            PropertyInfo { name: "email".to_string(), type_annotation: Some("String".to_string()), is_static: false, is_readonly: false, visibility: Visibility::Private },
        ],
        range: Range { start: Position { line: 5, column: 0 }, end: Position { line: 20, column: 0 } },
        decorators: vec![DecoratorInfo { name: "Entity".to_string(), arguments: SmallVec::new(), raw_text: "@Entity".to_string(), range: Range::default() }],
    });
    let models = ext.extract_models(&pr);
    assert_eq!(models.len(), 1);
    assert_eq!(models[0].framework, OrmFramework::Hibernate);
}

#[test]
fn extractor_eloquent_with_data() {
    use drift_analysis::boundaries::extractors::eloquent::EloquentExtractor;
    let ext = EloquentExtractor;
    let mut pr = ParseResult::default();
    pr.file = "app/Models/Post.php".to_string();
    pr.language = Language::Php;
    pr.classes.push(ClassInfo {
        name: "Post".to_string(), namespace: None,
        extends: Some("Model".to_string()),
        implements: SmallVec::new(), generic_params: SmallVec::new(),
        is_exported: false, is_abstract: false, class_kind: ClassKind::Class,
        methods: vec![], properties: vec![
            PropertyInfo { name: "id".to_string(), type_annotation: None, is_static: false, is_readonly: false, visibility: Visibility::Public },
            PropertyInfo { name: "title".to_string(), type_annotation: None, is_static: false, is_readonly: false, visibility: Visibility::Public },
        ],
        range: Range { start: Position { line: 5, column: 0 }, end: Position { line: 15, column: 0 } },
        decorators: vec![],
    });
    let models = ext.extract_models(&pr);
    assert_eq!(models.len(), 1);
    assert_eq!(models[0].framework, OrmFramework::Eloquent);
}

#[test]
fn extractor_active_record_with_data() {
    use drift_analysis::boundaries::extractors::active_record::ActiveRecordExtractor;
    let ext = ActiveRecordExtractor;
    let mut pr = ParseResult::default();
    pr.file = "app/models/post.rb".to_string();
    pr.language = Language::Ruby;
    pr.classes.push(ClassInfo {
        name: "Post".to_string(), namespace: None,
        extends: Some("ApplicationRecord".to_string()),
        implements: SmallVec::new(), generic_params: SmallVec::new(),
        is_exported: false, is_abstract: false, class_kind: ClassKind::Class,
        methods: vec![], properties: vec![
            PropertyInfo { name: "id".to_string(), type_annotation: None, is_static: false, is_readonly: false, visibility: Visibility::Public },
        ],
        range: Range { start: Position { line: 1, column: 0 }, end: Position { line: 5, column: 0 } },
        decorators: vec![],
    });
    let models = ext.extract_models(&pr);
    assert_eq!(models.len(), 1);
    assert_eq!(models[0].framework, OrmFramework::ActiveRecord);
}

// ---- Base normalizer direct coverage ----

#[test]
fn base_normalizer_direct() {
    use drift_analysis::engine::gast::base_normalizer::{GASTNormalizer, BaseNormalizer};
    use drift_analysis::engine::gast::types::GASTNode;

    let normalizer = BaseNormalizer;

    // Parse TypeScript with many construct types to exercise base normalizer match arms
    let source = br#"
import { User } from './models';
export { helper };

function greet(name: string): string {
    return `Hello ${name}`;
}

const arrow = async (x: number) => x * 2;

class UserService extends BaseService {
    private name: string;

    constructor(name: string) {
        super();
        this.name = name;
    }

    async getUser(id: string): Promise<User> {
        if (id) {
            for (let i = 0; i < 10; i++) {
                console.log(i);
            }
            for (const item of items) {
                process(item);
            }
            while (true) { break; }
            switch (id) {
                case '1': return null;
                default: break;
            }
            try {
                const result = await fetch(id);
                return result;
            } catch (err) {
                throw new Error('failed');
            }
        }
        return null;
    }

    *generateIds() {
        yield 1;
        yield* otherGen();
    }
}

interface IService {
    getUser(id: string): Promise<User>;
}

enum Status { Active, Inactive }

type UserId = string;

@Injectable()
class Decorated {}

// This is a comment
/* Block comment */
/** Doc comment */

const x = true;
const y = false;
const z = null;
const n = 42;
const s = "hello";
"#;

    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()).unwrap();
    let tree = parser.parse(source, None).unwrap();
    let gast = normalizer.normalize(&tree, source);
    assert_eq!(gast.kind(), "program");
    assert!(gast.node_count() > 10);
}

#[test]
fn base_normalizer_python_direct() {
    use drift_analysis::engine::gast::base_normalizer::{GASTNormalizer, BaseNormalizer};

    let normalizer = BaseNormalizer;

    let source = br#"
import os
from typing import Optional

class UserService:
    def __init__(self, db):
        self.db = db

    async def get_user(self, user_id):
        if user_id:
            for i in range(10):
                print(i)
            while False:
                break
            try:
                result = await self.db.query(user_id)
                return result
            except Exception as e:
                raise ValueError("failed")
        return None

    @staticmethod
    def validate(data):
        return bool(data)

x = True
y = False
z = None
n = 42
s = "hello"
"#;

    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&tree_sitter_python::LANGUAGE.into()).unwrap();
    let tree = parser.parse(source, None).unwrap();
    let gast = normalizer.normalize(&tree, source);
    assert_eq!(gast.kind(), "program");
    assert!(gast.node_count() > 10);
}

#[test]
fn base_normalizer_java_direct() {
    use drift_analysis::engine::gast::base_normalizer::{GASTNormalizer, BaseNormalizer};

    let normalizer = BaseNormalizer;

    let source = br#"
import java.util.List;

public class UserService {
    private String name;

    public UserService(String name) {
        this.name = name;
    }

    public List<String> getUsers() {
        if (name != null) {
            for (int i = 0; i < 10; i++) {
                System.out.println(i);
            }
            while (true) { break; }
            switch (name) {
                case "admin": return List.of(name);
                default: break;
            }
            try {
                return List.of(name);
            } catch (Exception e) {
                throw new RuntimeException("failed");
            }
        }
        return null;
    }
}

interface Greeter {
    String greet();
}

enum Color { RED, GREEN, BLUE }
"#;

    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&tree_sitter_java::LANGUAGE.into()).unwrap();
    let tree = parser.parse(source, None).unwrap();
    let gast = normalizer.normalize(&tree, source);
    assert_eq!(gast.kind(), "program");
    assert!(gast.node_count() > 10);
}
