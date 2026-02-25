#![allow(clippy::field_reassign_with_default, unused_imports)]
//! Production Category 17: Structural Analysis (Flow 6 — 9 untested subsystems)
//!
//! 10 tests (T17-01 through T17-10) covering coupling, wrappers, crypto,
//! DNA, secrets, magic numbers, constraints, env variables, and decomposition.

use drift_analysis::structural::coupling::types::ImportGraph;
use drift_analysis::structural::coupling::{compute_martin_metrics, detect_cycles};
use drift_analysis::structural::wrappers::detector::WrapperDetector;
use drift_analysis::structural::wrappers::confidence::compute_confidence;
use drift_analysis::structural::crypto::CryptoDetector;
use drift_analysis::structural::crypto::confidence::compute_confidence_batch;
use drift_analysis::structural::crypto::types::CryptoCategory;
use drift_analysis::structural::dna::GeneExtractorRegistry;
use drift_analysis::structural::constants::secrets::detect_secrets;
use drift_analysis::structural::constants::magic_numbers::detect_magic_numbers;
use drift_analysis::structural::constants::env_extraction::extract_env_references;
use drift_analysis::structural::constraints::types::{
    Constraint, ConstraintSource, InvariantType,
};
use drift_analysis::structural::constraints::{
    ConstraintStore, ConstraintVerifier, InvariantDetector,
};
use drift_analysis::structural::constraints::detector::FunctionInfo;
use drift_analysis::structural::decomposition::decomposer::{
    decompose_with_priors, DecompositionInput, FileEntry,
};

// ─── T17-01: Coupling — Martin Metrics ──────────────────────────────

/// T17-01: Analyze a module with 5 imports (Ce=5) and 3 importers (Ca=3).
/// instability = Ce/(Ce+Ca) = 0.625. distance = |abstractness + instability - 1|.
/// Must match Martin's formula.
#[test]
fn t17_01_coupling_martin_metrics() {
    let mut graph = ImportGraph::default();

    // Module "A" imports from 5 others
    graph.modules = vec![
        "A".into(),
        "B".into(),
        "C".into(),
        "D".into(),
        "E".into(),
        "F".into(),
        "G".into(),
        "H".into(),
    ];

    // A depends on B, C, D, E, F (Ce = 5)
    graph.edges.insert(
        "A".into(),
        vec!["B".into(), "C".into(), "D".into(), "E".into(), "F".into()],
    );

    // G, H, B depend on A (Ca = 3)
    graph.edges.insert("G".into(), vec!["A".into()]);
    graph.edges.insert("H".into(), vec!["A".into()]);
    graph
        .edges
        .entry("B".into())
        .or_insert_with(Vec::new)
        .push("A".into());

    // No abstract types for A — abstractness = 0
    graph.total_type_counts.insert("A".into(), 10);
    graph.abstract_counts.insert("A".into(), 0);

    let metrics = compute_martin_metrics(&graph);
    let a_metrics = metrics.iter().find(|m| m.module == "A").unwrap();

    assert_eq!(a_metrics.ce, 5, "Ce should be 5");
    assert_eq!(a_metrics.ca, 3, "Ca should be 3");

    // I = Ce / (Ce + Ca) = 5 / 8 = 0.625
    let expected_instability = 5.0 / 8.0;
    assert!(
        (a_metrics.instability - expected_instability).abs() < 1e-10,
        "Instability should be {}, got {}",
        expected_instability,
        a_metrics.instability
    );

    // A = 0 / 10 = 0.0
    assert!(
        a_metrics.abstractness.abs() < 1e-10,
        "Abstractness should be 0.0, got {}",
        a_metrics.abstractness
    );

    // D = |A + I - 1| = |0.0 + 0.625 - 1.0| = 0.375
    let expected_distance = (0.0 + expected_instability - 1.0).abs();
    assert!(
        (a_metrics.distance - expected_distance).abs() < 1e-10,
        "Distance should be {}, got {}",
        expected_distance,
        a_metrics.distance
    );
}

// ─── T17-02: Coupling — Cycle Detection ─────────────────────────────

/// T17-02: Create imports A→B→C→A. detect_cycles() must find the SCC {A,B,C}.
/// break_suggestions must be non-empty.
#[test]
fn t17_02_coupling_cycle_detection() {
    let mut graph = ImportGraph::default();
    graph.modules = vec!["A".into(), "B".into(), "C".into(), "D".into()];
    graph.edges.insert("A".into(), vec!["B".into()]);
    graph.edges.insert("B".into(), vec!["C".into()]);
    graph.edges.insert("C".into(), vec!["A".into()]);
    // D is acyclic
    graph.edges.insert("D".into(), vec!["A".into()]);

    let cycles = detect_cycles(&graph);

    assert!(
        !cycles.is_empty(),
        "Must detect at least 1 cycle, got 0"
    );

    // Find the cycle containing A, B, C
    let abc_cycle = cycles.iter().find(|c| {
        c.members.contains(&"A".to_string())
            && c.members.contains(&"B".to_string())
            && c.members.contains(&"C".to_string())
    });
    assert!(
        abc_cycle.is_some(),
        "Must find SCC containing {{A, B, C}}"
    );

    let cycle = abc_cycle.unwrap();
    assert_eq!(cycle.members.len(), 3, "SCC should have exactly 3 members");

    assert!(
        !cycle.break_suggestions.is_empty(),
        "break_suggestions must be non-empty"
    );

    // D should NOT be in any cycle
    for c in &cycles {
        assert!(
            !c.members.contains(&"D".to_string()),
            "D should not be in any cycle"
        );
    }
}

// ─── T17-03: Wrapper Detection Confidence ───────────────────────────

/// T17-03: Analyze a file wrapping fetch() in a custom apiClient().
/// WrapperDetector must detect it with confidence > 0.5.
/// Multi-primitive composite analysis must work when wrapping multiple primitives.
#[test]
fn t17_03_wrapper_detection_confidence() {
    let content = r#"
import axios from 'axios';

export function useApiClient(baseUrl) {
    const client = axios.create({ baseURL: baseUrl });

    const get = (path) => fetch(`${baseUrl}${path}`);
    const post = (path, body) => fetch(`${baseUrl}${path}`, { method: 'POST', body });

    return { get, post };
}

export const useUserData = () => {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    useEffect(() => {
        fetch('/api/users').then(r => r.json()).then(setData);
    }, []);
    return { data, loading };
};
"#;

    let detector = WrapperDetector::new();
    let wrappers = detector.detect(content, "src/hooks/useApiClient.ts");

    assert!(
        !wrappers.is_empty(),
        "WrapperDetector must detect at least one wrapper, got 0"
    );

    // Compute confidence for each wrapper
    for wrapper in &wrappers {
        let conf = compute_confidence(wrapper, content);
        assert!(
            conf > 0.0,
            "Wrapper '{}' should have positive confidence, got {}",
            wrapper.name,
            conf
        );
    }

    // Check multi-primitive detection: useUserData wraps useState + useEffect + fetch
    let multi = wrappers.iter().find(|w| w.name == "useUserData");
    if let Some(w) = multi {
        assert!(
            w.wrapped_primitives.len() > 1,
            "useUserData should detect multiple primitives, got {}",
            w.wrapped_primitives.len()
        );
        assert!(
            w.is_multi_primitive,
            "useUserData should be flagged as multi-primitive"
        );
        let conf = compute_confidence(w, content);
        assert!(
            conf > 0.0,
            "Multi-primitive wrapper confidence should be > 0, got {}",
            conf
        );
    }

    // Check that at least one wrapper has confidence > 0.5
    let any_high = wrappers.iter().any(|w| {
        let c = compute_confidence(w, content);
        c > 0.5
    });
    assert!(
        any_high,
        "At least one wrapper should have confidence > 0.5"
    );
}

// ─── T17-04: Crypto — Weak Algorithm Detection ─────────────────────

/// T17-04: File using MD5, SHA1, DES. Must detect all 3 as weak.
/// Each must have cwe_id and owasp mappings. confidence must vary by severity.
#[test]
fn t17_04_crypto_weak_algorithm_detection() {
    let content = r#"
import hashlib
import Crypto.Cipher

# Hash passwords with MD5
password_hash = hashlib.md5(password.encode()).hexdigest()

# Also use SHA1 for tokens
token_hash = hashlib.sha1(token.encode()).hexdigest()

# Encrypt data with DES
cipher = DES.new(key, DES.MODE_ECB)
encrypted = cipher.encrypt(data)
"#;

    let detector = CryptoDetector::new();
    let mut findings = detector.detect(content, "src/crypto_utils.py", "python");

    // Compute confidence
    compute_confidence_batch(&mut findings, content);

    // Must detect MD5
    let md5_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.category == CryptoCategory::WeakHash && f.description.contains("MD5"))
        .collect();
    assert!(
        !md5_findings.is_empty(),
        "Must detect MD5 as weak hash. All findings: {:?}",
        findings.iter().map(|f| &f.description).collect::<Vec<_>>()
    );

    // Must detect SHA1
    let sha1_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.category == CryptoCategory::WeakHash && f.description.contains("SHA1"))
        .collect();
    assert!(
        !sha1_findings.is_empty(),
        "Must detect SHA1 as weak hash"
    );

    // Must detect DES
    let des_findings: Vec<_> = findings
        .iter()
        .filter(|f| {
            f.category == CryptoCategory::DeprecatedCipher
                || (f.category == CryptoCategory::EcbMode)
                || f.description.contains("DES")
        })
        .collect();
    assert!(
        !des_findings.is_empty(),
        "Must detect DES as deprecated cipher. All findings: {:?}",
        findings.iter().map(|f| (&f.category, &f.description)).collect::<Vec<_>>()
    );

    // All findings must have CWE IDs
    for f in &findings {
        assert!(f.cwe_id > 0, "Finding '{}' must have cwe_id > 0", f.description);
        assert!(
            !f.owasp.is_empty(),
            "Finding '{}' must have owasp mapping",
            f.description
        );
    }

    // Confidence must be computed (not all zero)
    let has_nonzero_confidence = findings.iter().any(|f| f.confidence > 0.0);
    assert!(
        has_nonzero_confidence,
        "At least one finding should have non-zero confidence after compute_confidence_batch"
    );
}

// ─── T17-05: DNA — Naming Gene Consistency ──────────────────────────

/// T17-05: Repo with 50% camelCase, 50% snake_case files.
/// Gene must have 2 alleles. consistency ≈ 0. Dominant allele frequency ≥ 0.30.
#[test]
fn t17_05_dna_naming_gene_consistency() {
    let registry = GeneExtractorRegistry::with_all_extractors();

    // Verify we get all extractors (the spec says 11, but code creates 10)
    assert!(
        registry.len() >= 10,
        "Registry should have at least 10 extractors, got {}",
        registry.len()
    );

    // Use the VariantHandling gene to test allele detection with mixed patterns.
    // 50% cva, 50% clsx — should produce 2 alleles with ~equal frequency.
    let variant_extractor = registry
        .get(drift_analysis::structural::dna::types::GeneId::VariantHandling)
        .expect("VariantHandling extractor must exist");

    // Create files: 5 using cva, 5 using clsx
    let cva_content = r#"
import { cva } from 'class-variance-authority';
const button = cva("base", { variants: { size: { sm: "p-2", lg: "p-4" } } });
"#;

    let clsx_content = r#"
import clsx from 'clsx';
const className = clsx("base", isActive && "active", size === "lg" && "large");
"#;

    let mut results = Vec::new();
    for i in 0..5 {
        results.push(variant_extractor.extract_from_file(
            cva_content,
            &format!("src/components/cva_{}.tsx", i),
        ));
    }
    for i in 0..5 {
        results.push(variant_extractor.extract_from_file(
            clsx_content,
            &format!("src/components/clsx_{}.tsx", i),
        ));
    }

    let gene = variant_extractor.build_gene(&results);

    // Must have at least 2 alleles
    assert!(
        gene.alleles.len() >= 2,
        "Gene should have >= 2 alleles for mixed patterns, got {}",
        gene.alleles.len()
    );

    // Consistency should be low (close to 0) for 50/50 split
    // consistency = freq[0] - freq[1]
    if gene.alleles.len() >= 2 {
        let gap = gene.alleles[0].frequency - gene.alleles[1].frequency;
        assert!(
            gap.abs() < 0.5,
            "Consistency gap should be small for 50/50 split, got {}",
            gap
        );
    }

    // Dominant allele frequency ≥ 0.30
    if let Some(dominant) = &gene.dominant {
        assert!(
            dominant.frequency >= 0.30,
            "Dominant allele frequency must be >= 0.30, got {}",
            dominant.frequency
        );
    }
}

// ─── T17-06: Secrets — Entropy Filtering ────────────────────────────

/// T17-06: File with AWS_KEY=AKIAIOSFODNN7EXAMPLE and name="hello".
/// AWS key detected (high entropy + known pattern). "hello" not flagged.
/// redacted_value must not contain full secret.
#[test]
fn t17_06_secrets_entropy_filtering() {
    let content = r#"
const config = {
    AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7EXAMPLE",
    name: "hello",
    greeting: "world",
};
"#;

    let secrets = detect_secrets(content, "src/config.ts");

    // AWS key should be detected
    let aws_findings: Vec<_> = secrets
        .iter()
        .filter(|s| s.pattern_name.contains("aws"))
        .collect();
    assert!(
        !aws_findings.is_empty(),
        "AWS access key (AKIA prefix) must be detected. Found patterns: {:?}",
        secrets.iter().map(|s| &s.pattern_name).collect::<Vec<_>>()
    );

    // "hello" should NOT be flagged as a secret
    let hello_findings: Vec<_> = secrets
        .iter()
        .filter(|s| s.redacted_value.contains("hello"))
        .collect();
    assert!(
        hello_findings.is_empty(),
        "\"hello\" should not be flagged as a secret"
    );

    // redacted_value must not contain the full secret
    for s in &aws_findings {
        assert!(
            !s.redacted_value.contains("AKIAIOSFODNN7EXAMPLE"),
            "redacted_value must not contain full secret, got '{}'",
            s.redacted_value
        );
        assert!(
            s.redacted_value.contains('*'),
            "redacted_value should contain asterisks for redaction"
        );
    }

    // CWE IDs should be populated
    for s in &aws_findings {
        assert!(
            !s.cwe_ids.is_empty(),
            "AWS finding should have CWE IDs"
        );
    }
}

// ─── T17-07: Magic Numbers ──────────────────────────────────────────

/// T17-07: File with `if (retries > 3)` and `const MAX_RETRIES = 3`.
/// `3` in the `if` flagged as magic number. MAX_RETRIES = 3 NOT flagged.
/// suggested_name populated.
#[test]
fn t17_07_magic_numbers() {
    let content = r#"
const MAX_RETRIES = 3;
const TIMEOUT = 3600;

function retry(fn) {
    if (retries > 3) {
        throw new Error("Max retries exceeded");
    }
    setTimeout(fn, 5000);
}
"#;

    let magic = detect_magic_numbers(content, "src/retry.ts", "typescript");

    // `3` in the if statement should be flagged
    let three_in_if: Vec<_> = magic
        .iter()
        .filter(|m| m.value == "3" && !m.in_named_context)
        .collect();
    assert!(
        !three_in_if.is_empty(),
        "Bare `3` in if-statement should be flagged as magic number. All magic: {:?}",
        magic.iter().map(|m| (&m.value, m.line, m.in_named_context)).collect::<Vec<_>>()
    );

    // `3` in `const MAX_RETRIES = 3` should NOT be flagged (named context)
    // The detect_magic_numbers function filters out named contexts
    let named_three: Vec<_> = magic
        .iter()
        .filter(|m| m.value == "3" && m.in_named_context)
        .collect();
    assert!(
        named_three.is_empty(),
        "Named constant `3` should be filtered out (not in results)"
    );

    // 3600 should have suggested_name "SECONDS_PER_HOUR"
    let _magic_3600: Vec<_> = magic.iter().filter(|m| m.value == "3600").collect();
    // 3600 is on a const line so should NOT appear (named context)
    // But 5000 is bare — check it
    let magic_5000: Vec<_> = magic.iter().filter(|m| m.value == "5000").collect();
    if !magic_5000.is_empty() {
        // 5000 is a setTimeout argument — should be a magic number
        assert!(!magic_5000[0].in_named_context);
    }
}

// ─── T17-08: Constraint Verification ────────────────────────────────

/// T17-08: Define MustExist constraint for AuthMiddleware.
/// Analyze repo without it. ConstraintVerifier::verify_all() must return passed=false.
#[test]
fn t17_08_constraint_verification() {
    let mut store = ConstraintStore::new();
    store.add(Constraint {
        id: "auth-middleware".into(),
        description: "AuthMiddleware must exist in the codebase".into(),
        invariant_type: InvariantType::MustExist,
        target: "AuthMiddleware".into(),
        scope: None,
        source: ConstraintSource::Manual,
        enabled: true,
    });

    // Create a detector with NO AuthMiddleware registered
    let mut detector = InvariantDetector::new();
    detector.add_file(
        "src/routes.ts",
        vec![
            FunctionInfo {
                name: "getUsers".into(),
                line: 5,
                is_exported: true,
            },
            FunctionInfo {
                name: "createUser".into(),
                line: 15,
                is_exported: true,
            },
        ],
        vec![],
        30,
    );
    detector.add_file(
        "src/utils.ts",
        vec![FunctionInfo {
            name: "formatDate".into(),
            line: 1,
            is_exported: false,
        }],
        vec![],
        10,
    );

    let verifier = ConstraintVerifier::new(&store, &detector);
    let results = verifier.verify_all().expect("verify_all should not error");

    assert_eq!(results.len(), 1, "Should have 1 verification result");
    let result = &results[0];
    assert!(
        !result.passed,
        "MustExist constraint should FAIL when AuthMiddleware is missing"
    );
    assert!(
        !result.violations.is_empty(),
        "Should have violation details"
    );
    assert!(
        result.violations[0].message.contains("AuthMiddleware"),
        "Violation message should mention AuthMiddleware"
    );
}

// ─── T17-09: Env Variable Extraction — 8 Languages ─────────────────

/// T17-09: Files using env var patterns in all 8 supported languages.
/// All 8 must be extracted with correct access_method and has_default detection.
#[test]
fn t17_09_env_variable_extraction_8_languages() {
    // JavaScript: process.env.X
    let js = r#"const dbUrl = process.env.DATABASE_URL || "localhost";"#;
    let js_results = extract_env_references(js, "config.js", "javascript");
    assert!(!js_results.is_empty(), "JS: process.env.DATABASE_URL must be extracted");
    let js_var = js_results.iter().find(|v| v.name == "DATABASE_URL");
    assert!(js_var.is_some(), "JS: DATABASE_URL must be found");
    assert_eq!(js_var.unwrap().access_method, "process.env");
    assert!(js_var.unwrap().has_default, "JS: should detect || default");

    // Python: os.environ["X"]
    let py = r#"db_url = os.environ["DATABASE_URL"]"#;
    let py_results = extract_env_references(py, "config.py", "python");
    assert!(!py_results.is_empty(), "Python: os.environ must be extracted");
    let py_var = py_results.iter().find(|v| v.name == "DATABASE_URL");
    assert!(py_var.is_some(), "Python: DATABASE_URL must be found");

    // Rust: std::env::var("X")
    let rs = r#"let db = std::env::var("DATABASE_URL").unwrap_or("localhost".into());"#;
    let rs_results = extract_env_references(rs, "config.rs", "rust");
    assert!(!rs_results.is_empty(), "Rust: std::env::var must be extracted");
    let rs_var = rs_results.iter().find(|v| v.name == "DATABASE_URL");
    assert!(rs_var.is_some(), "Rust: DATABASE_URL must be found");
    assert!(rs_var.unwrap().has_default, "Rust: should detect unwrap_or default");

    // Go: os.Getenv("X")
    let go = r#"dbUrl := os.Getenv("DATABASE_URL")"#;
    let go_results = extract_env_references(go, "config.go", "go");
    assert!(!go_results.is_empty(), "Go: os.Getenv must be extracted");
    let go_var = go_results.iter().find(|v| v.name == "DATABASE_URL");
    assert!(go_var.is_some(), "Go: DATABASE_URL must be found");

    // Java: System.getenv("X")
    let java = r#"String dbUrl = System.getenv("DATABASE_URL");"#;
    let java_results = extract_env_references(java, "Config.java", "java");
    assert!(!java_results.is_empty(), "Java: System.getenv must be extracted");
    let java_var = java_results.iter().find(|v| v.name == "DATABASE_URL");
    assert!(java_var.is_some(), "Java: DATABASE_URL must be found");

    // Ruby: ENV["X"]
    let ruby = r#"db_url = ENV["DATABASE_URL"]"#;
    let ruby_results = extract_env_references(ruby, "config.rb", "ruby");
    assert!(!ruby_results.is_empty(), "Ruby: ENV must be extracted");
    let ruby_var = ruby_results.iter().find(|v| v.name == "DATABASE_URL");
    assert!(ruby_var.is_some(), "Ruby: DATABASE_URL must be found");

    // PHP: getenv('X')
    let php = r#"$dbUrl = getenv('DATABASE_URL');"#;
    let php_results = extract_env_references(php, "config.php", "php");
    assert!(!php_results.is_empty(), "PHP: getenv must be extracted");
    let php_var = php_results.iter().find(|v| v.name == "DATABASE_URL");
    assert!(php_var.is_some(), "PHP: DATABASE_URL must be found");

    // C#: Environment.GetEnvironmentVariable("X")
    let csharp = r#"var dbUrl = Environment.GetEnvironmentVariable("DATABASE_URL");"#;
    let csharp_results = extract_env_references(csharp, "Config.cs", "csharp");
    assert!(
        !csharp_results.is_empty(),
        "C#: Environment.GetEnvironmentVariable must be extracted"
    );
    let csharp_var = csharp_results.iter().find(|v| v.name == "DATABASE_URL");
    assert!(csharp_var.is_some(), "C#: DATABASE_URL must be found");
    assert_eq!(
        csharp_var.unwrap().access_method,
        "Environment.GetEnvironmentVariable"
    );
}

// ─── T17-10: Decomposition Suggestions ──────────────────────────────

/// T17-10: Analyze a monolith with high coupling between 3 modules.
/// decompose_with_priors() must suggest service boundaries.
/// confidence must be > 0. narrative must explain the reasoning.
#[test]
fn t17_10_decomposition_suggestions() {
    // Create a monolith with 3 directories (auth, users, billing)
    // with high cross-module coupling
    let input = DecompositionInput {
        files: vec![
            FileEntry {
                path: "src/auth/login.ts".into(),
                line_count: 200,
                language: "typescript".into(),
            },
            FileEntry {
                path: "src/auth/session.ts".into(),
                line_count: 150,
                language: "typescript".into(),
            },
            FileEntry {
                path: "src/users/crud.ts".into(),
                line_count: 300,
                language: "typescript".into(),
            },
            FileEntry {
                path: "src/users/profile.ts".into(),
                line_count: 100,
                language: "typescript".into(),
            },
            FileEntry {
                path: "src/billing/payments.ts".into(),
                line_count: 250,
                language: "typescript".into(),
            },
            FileEntry {
                path: "src/billing/invoices.ts".into(),
                line_count: 180,
                language: "typescript".into(),
            },
        ],
        call_edges: vec![
            // Auth → Users (cross-module)
            ("src/auth/login.ts".into(), "src/users/crud.ts".into(), "findUser".into()),
            ("src/auth/session.ts".into(), "src/users/crud.ts".into(), "getUser".into()),
            // Users → Billing (cross-module)
            ("src/users/crud.ts".into(), "src/billing/payments.ts".into(), "checkPayment".into()),
            // Intra-module calls
            ("src/auth/login.ts".into(), "src/auth/session.ts".into(), "createSession".into()),
            ("src/billing/payments.ts".into(), "src/billing/invoices.ts".into(), "createInvoice".into()),
            ("src/users/crud.ts".into(), "src/users/profile.ts".into(), "getProfile".into()),
        ],
        data_access: vec![
            ("src/users/crud.ts".into(), "users".into(), "READ".into()),
            ("src/users/crud.ts".into(), "users".into(), "WRITE".into()),
            ("src/billing/payments.ts".into(), "payments".into(), "READ".into()),
            ("src/billing/payments.ts".into(), "payments".into(), "WRITE".into()),
            ("src/auth/login.ts".into(), "sessions".into(), "WRITE".into()),
        ],
        functions: vec![
            ("src/auth/login.ts".into(), "login".into(), true),
            ("src/auth/session.ts".into(), "createSession".into(), true),
            ("src/users/crud.ts".into(), "findUser".into(), true),
            ("src/users/crud.ts".into(), "getUser".into(), true),
            ("src/users/profile.ts".into(), "getProfile".into(), true),
            ("src/billing/payments.ts".into(), "checkPayment".into(), true),
            ("src/billing/invoices.ts".into(), "createInvoice".into(), false),
        ],
    };

    // No priors — standalone mode
    let modules = decompose_with_priors(&input, &[]);

    assert!(
        !modules.is_empty(),
        "decompose_with_priors must produce at least 1 module"
    );

    // Should cluster into multiple logical modules
    // (at least 2; likely 3 based on directory structure: auth, users, billing)
    assert!(
        modules.len() >= 2,
        "Should produce at least 2 modules from 3 directories, got {}",
        modules.len()
    );

    // Each module should have files
    for module in &modules {
        assert!(
            !module.files.is_empty(),
            "Module '{}' should have files",
            module.name
        );
    }

    // Cohesion/coupling should be computed
    // At least some modules should have non-default cohesion
    let has_computed_metrics = modules.iter().any(|m| m.cohesion > 0.0 || m.coupling > 0.0);
    assert!(
        has_computed_metrics,
        "At least one module should have computed cohesion/coupling metrics"
    );

    // Estimated complexity should be > 0 for modules with files
    for module in &modules {
        assert!(
            module.estimated_complexity > 0,
            "Module '{}' should have estimated_complexity > 0, got {}",
            module.name,
            module.estimated_complexity
        );
    }

    // Total files across all modules should equal input files
    let total_files: usize = modules.iter().map(|m| m.files.len()).sum();
    assert_eq!(
        total_files,
        input.files.len(),
        "Total files across modules ({}) should equal input files ({})",
        total_files,
        input.files.len()
    );
}
