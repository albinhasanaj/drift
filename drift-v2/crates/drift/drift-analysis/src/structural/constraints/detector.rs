//! AST-based invariant detection (not regex).

use drift_core::types::collections::FxHashMap;

use super::types::{Constraint, ConstraintViolation, InvariantType, VerificationResult};

/// Detects invariant violations using AST-based analysis.
///
/// Unlike v1's regex approach, this uses parsed function/class/import data
/// from the analysis engine to verify constraints structurally.
pub struct InvariantDetector {
    /// Parsed function names per file.
    functions: FxHashMap<String, Vec<FunctionInfo>>,
    /// Parsed import relationships.
    imports: FxHashMap<String, Vec<String>>,
    /// File sizes (line counts).
    file_sizes: FxHashMap<String, u32>,
}

/// Minimal function info for constraint checking.
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub line: u32,
    pub is_exported: bool,
}

impl InvariantDetector {
    pub fn new() -> Self {
        Self {
            functions: FxHashMap::default(),
            imports: FxHashMap::default(),
            file_sizes: FxHashMap::default(),
        }
    }

    /// Register parsed data for a file.
    pub fn add_file(
        &mut self,
        file: &str,
        functions: Vec<FunctionInfo>,
        imports: Vec<String>,
        line_count: u32,
    ) {
        self.functions.insert(file.to_string(), functions);
        self.imports.insert(file.to_string(), imports);
        self.file_sizes.insert(file.to_string(), line_count);
    }

    /// Verify a constraint against the registered codebase data.
    pub fn verify(&self, constraint: &Constraint) -> VerificationResult {
        if !constraint.enabled {
            return VerificationResult {
                constraint_id: constraint.id.clone(),
                passed: true,
                violations: vec![],
            };
        }

        let violations = match constraint.invariant_type {
            InvariantType::MustExist => self.check_must_exist(constraint),
            InvariantType::MustNotExist => self.check_must_not_exist(constraint),
            InvariantType::MustPrecede => self.check_must_precede(constraint),
            InvariantType::NamingConvention => self.check_naming_convention(constraint),
            InvariantType::DependencyDirection => self.check_dependency_direction(constraint),
            InvariantType::LayerBoundary => self.check_layer_boundary(constraint),
            InvariantType::SizeLimit => self.check_size_limit(constraint),
            InvariantType::ComplexityLimit => self.check_complexity_limit(constraint),
            InvariantType::MustColocate => self.check_must_colocate(constraint),
            InvariantType::MustSeparate => self.check_must_separate(constraint),
            InvariantType::MustFollow => self.check_must_follow(constraint),
            InvariantType::DataFlow => vec![], // Requires call graph — deferred to Phase 6
        };

        VerificationResult {
            constraint_id: constraint.id.clone(),
            passed: violations.is_empty(),
            violations,
        }
    }

    fn check_must_exist(&self, constraint: &Constraint) -> Vec<ConstraintViolation> {
        let target = &constraint.target;
        let found = self.functions.values().any(|fns| {
            fns.iter().any(|f| f.name == *target)
        });
        if found {
            vec![]
        } else {
            vec![ConstraintViolation {
                file: String::new(),
                line: None,
                message: format!("Required symbol '{}' not found in codebase", target),
                expected: format!("Symbol '{}' exists", target),
                actual: "Not found".to_string(),
            }]
        }
    }

    fn check_must_not_exist(&self, constraint: &Constraint) -> Vec<ConstraintViolation> {
        let target = &constraint.target;
        let mut violations = Vec::new();
        for (file, fns) in &self.functions {
            for f in fns {
                if f.name == *target {
                    violations.push(ConstraintViolation {
                        file: file.clone(),
                        line: Some(f.line),
                        message: format!("Forbidden symbol '{}' found", target),
                        expected: format!("Symbol '{}' does not exist", target),
                        actual: format!("Found at {}:{}", file, f.line),
                    });
                }
            }
        }
        violations
    }

    fn check_must_precede(&self, constraint: &Constraint) -> Vec<ConstraintViolation> {
        // Target format: "symbolA:symbolB" — A must appear before B in the same file
        let parts: Vec<&str> = constraint.target.split(':').collect();
        if parts.len() != 2 {
            return vec![];
        }
        let (a, b) = (parts[0], parts[1]);
        let mut violations = Vec::new();

        for (file, fns) in &self.functions {
            let pos_a = fns.iter().find(|f| f.name == a).map(|f| f.line);
            let pos_b = fns.iter().find(|f| f.name == b).map(|f| f.line);
            if let (Some(la), Some(lb)) = (pos_a, pos_b) {
                if la >= lb {
                    violations.push(ConstraintViolation {
                        file: file.clone(),
                        line: Some(la),
                        message: format!("'{}' must appear before '{}'", a, b),
                        expected: format!("{} (line {}) before {} (line {})", a, la, b, lb),
                        actual: format!("{} at line {}, {} at line {}", a, la, b, lb),
                    });
                }
            }
        }
        violations
    }

    fn check_must_follow(&self, constraint: &Constraint) -> Vec<ConstraintViolation> {
        // Target format: "symbolA:symbolB" — A must appear after B
        let parts: Vec<&str> = constraint.target.split(':').collect();
        if parts.len() != 2 {
            return vec![];
        }
        let (a, b) = (parts[0], parts[1]);
        let mut violations = Vec::new();

        for (file, fns) in &self.functions {
            let pos_a = fns.iter().find(|f| f.name == a).map(|f| f.line);
            let pos_b = fns.iter().find(|f| f.name == b).map(|f| f.line);
            if let (Some(la), Some(lb)) = (pos_a, pos_b) {
                if la <= lb {
                    violations.push(ConstraintViolation {
                        file: file.clone(),
                        line: Some(la),
                        message: format!("'{}' must appear after '{}'", a, b),
                        expected: format!("{} after {}", a, b),
                        actual: format!("{} at line {}, {} at line {}", a, la, b, lb),
                    });
                }
            }
        }
        violations
    }

    fn check_naming_convention(&self, constraint: &Constraint) -> Vec<ConstraintViolation> {
        let convention = &constraint.target; // "camelCase", "snake_case", "PascalCase"
        let mut violations = Vec::new();

        let files = self.scoped_files(constraint.scope.as_deref());
        for file in files {
            if let Some(fns) = self.functions.get(file) {
                for f in fns {
                    if !matches_convention(&f.name, convention) {
                        violations.push(ConstraintViolation {
                            file: file.to_string(),
                            line: Some(f.line),
                            message: format!(
                                "Function '{}' does not follow {} convention",
                                f.name, convention
                            ),
                            expected: format!("{} naming", convention),
                            actual: f.name.clone(),
                        });
                    }
                }
            }
        }
        violations
    }

    fn check_dependency_direction(&self, constraint: &Constraint) -> Vec<ConstraintViolation> {
        // Target format: "moduleA->moduleB" — A may depend on B, but B must not depend on A
        let parts: Vec<&str> = constraint.target.split("->").collect();
        if parts.len() != 2 {
            return vec![];
        }
        let (allowed_src, allowed_dst) = (parts[0].trim(), parts[1].trim());
        let mut violations = Vec::new();

        // Check if the reverse dependency exists
        for (file, imports) in &self.imports {
            if file.starts_with(allowed_dst) {
                for import in imports {
                    if import.starts_with(allowed_src) {
                        violations.push(ConstraintViolation {
                            file: file.clone(),
                            line: None,
                            message: format!(
                                "Reverse dependency: '{}' imports from '{}' (only {} -> {} allowed)",
                                file, import, allowed_src, allowed_dst
                            ),
                            expected: format!("No imports from {} to {}", allowed_dst, allowed_src),
                            actual: format!("{} imports {}", file, import),
                        });
                    }
                }
            }
        }
        violations
    }

    fn check_layer_boundary(&self, constraint: &Constraint) -> Vec<ConstraintViolation> {
        // Target format: "ui!->db" — ui layer must not import from db layer
        let parts: Vec<&str> = constraint.target.split("!->").collect();
        if parts.len() != 2 {
            return vec![];
        }
        let (forbidden_src, forbidden_dst) = (parts[0].trim(), parts[1].trim());
        let mut violations = Vec::new();

        for (file, imports) in &self.imports {
            if file.contains(forbidden_src) {
                for import in imports {
                    if import.contains(forbidden_dst) {
                        violations.push(ConstraintViolation {
                            file: file.clone(),
                            line: None,
                            message: format!(
                                "Layer violation: '{}' imports from forbidden layer '{}'",
                                file, forbidden_dst
                            ),
                            expected: format!("No imports from {} to {}", forbidden_src, forbidden_dst),
                            actual: format!("{} imports {}", file, import),
                        });
                    }
                }
            }
        }
        violations
    }

    fn check_size_limit(&self, constraint: &Constraint) -> Vec<ConstraintViolation> {
        let limit: u32 = constraint.target.parse().unwrap_or(500);
        let mut violations = Vec::new();

        let files = self.scoped_files(constraint.scope.as_deref());
        for file in files {
            if let Some(&size) = self.file_sizes.get(file) {
                if size > limit {
                    violations.push(ConstraintViolation {
                        file: file.to_string(),
                        line: None,
                        message: format!("File exceeds size limit: {} lines (max {})", size, limit),
                        expected: format!("<= {} lines", limit),
                        actual: format!("{} lines", size),
                    });
                }
            }
        }
        violations
    }

    fn check_complexity_limit(&self, constraint: &Constraint) -> Vec<ConstraintViolation> {
        // Simplified: check function count per file as a proxy for complexity
        let limit: usize = constraint.target.parse().unwrap_or(20);
        let mut violations = Vec::new();

        let files = self.scoped_files(constraint.scope.as_deref());
        for file in files {
            if let Some(fns) = self.functions.get(file) {
                if fns.len() > limit {
                    violations.push(ConstraintViolation {
                        file: file.to_string(),
                        line: None,
                        message: format!(
                            "File has {} functions (max {})",
                            fns.len(),
                            limit
                        ),
                        expected: format!("<= {} functions", limit),
                        actual: format!("{} functions", fns.len()),
                    });
                }
            }
        }
        violations
    }

    fn check_must_colocate(&self, constraint: &Constraint) -> Vec<ConstraintViolation> {
        // Target: "symbolA:symbolB" — both must be in the same file
        let parts: Vec<&str> = constraint.target.split(':').collect();
        if parts.len() != 2 {
            return vec![];
        }
        let (a, b) = (parts[0], parts[1]);

        let file_a = self.find_symbol_file(a);
        let file_b = self.find_symbol_file(b);

        match (file_a, file_b) {
            (Some(fa), Some(fb)) if fa != fb => {
                vec![ConstraintViolation {
                    file: fa.clone(),
                    line: None,
                    message: format!("'{}' and '{}' must be colocated", a, b),
                    expected: "Both in same file".to_string(),
                    actual: format!("{} in {}, {} in {}", a, fa, b, fb),
                }]
            }
            _ => vec![],
        }
    }

    fn check_must_separate(&self, constraint: &Constraint) -> Vec<ConstraintViolation> {
        // Target: "symbolA:symbolB" — must be in different files
        let parts: Vec<&str> = constraint.target.split(':').collect();
        if parts.len() != 2 {
            return vec![];
        }
        let (a, b) = (parts[0], parts[1]);

        let file_a = self.find_symbol_file(a);
        let file_b = self.find_symbol_file(b);

        match (file_a, file_b) {
            (Some(fa), Some(fb)) if fa == fb => {
                vec![ConstraintViolation {
                    file: fa.clone(),
                    line: None,
                    message: format!("'{}' and '{}' must be in separate files", a, b),
                    expected: "Different files".to_string(),
                    actual: format!("Both in {}", fa),
                }]
            }
            _ => vec![],
        }
    }

    fn find_symbol_file(&self, symbol: &str) -> Option<String> {
        for (file, fns) in &self.functions {
            if fns.iter().any(|f| f.name == symbol) {
                return Some(file.clone());
            }
        }
        None
    }

    fn scoped_files<'a>(&'a self, scope: Option<&str>) -> Vec<&'a str> {
        match scope {
            Some(pattern) => self
                .functions
                .keys()
                .filter(|f| f.contains(pattern))
                .map(|s| s.as_str())
                .collect(),
            None => self.functions.keys().map(|s| s.as_str()).collect(),
        }
    }
}

impl Default for InvariantDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a name matches a naming convention.
fn matches_convention(name: &str, convention: &str) -> bool {
    if name.is_empty() {
        return true;
    }
    match convention {
        "camelCase" => {
            let first = name.chars().next().unwrap();
            first.is_lowercase() && !name.contains('_')
        }
        "snake_case" => {
            name.chars().all(|c| c.is_lowercase() || c.is_ascii_digit() || c == '_')
        }
        "PascalCase" => {
            let first = name.chars().next().unwrap();
            first.is_uppercase() && !name.contains('_')
        }
        "SCREAMING_SNAKE_CASE" => {
            name.chars().all(|c| c.is_uppercase() || c.is_ascii_digit() || c == '_')
        }
        _ => true, // Unknown convention — pass
    }
}
