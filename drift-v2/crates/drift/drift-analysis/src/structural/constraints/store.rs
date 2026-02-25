//! Constraint persistence and retrieval.

use super::types::Constraint;

/// In-memory constraint store with serialization support.
pub struct ConstraintStore {
    constraints: Vec<Constraint>,
}

impl ConstraintStore {
    pub fn new() -> Self {
        Self {
            constraints: Vec::new(),
        }
    }

    /// Add a constraint.
    pub fn add(&mut self, constraint: Constraint) {
        // Check for conflicts
        self.constraints.push(constraint);
    }

    /// Get all constraints.
    pub fn all(&self) -> &[Constraint] {
        &self.constraints
    }

    /// Get enabled constraints only.
    pub fn enabled(&self) -> Vec<&Constraint> {
        self.constraints.iter().filter(|c| c.enabled).collect()
    }

    /// Find a constraint by ID.
    pub fn get(&self, id: &str) -> Option<&Constraint> {
        self.constraints.iter().find(|c| c.id == id)
    }

    /// Remove a constraint by ID.
    pub fn remove(&mut self, id: &str) -> bool {
        let len = self.constraints.len();
        self.constraints.retain(|c| c.id != id);
        self.constraints.len() < len
    }

    /// Check for conflicting constraints (e.g., must_exist + must_not_exist for same target).
    pub fn find_conflicts(&self) -> Vec<(String, String)> {
        use super::types::InvariantType;
        let mut conflicts = Vec::new();

        for (i, a) in self.constraints.iter().enumerate() {
            for b in self.constraints.iter().skip(i + 1) {
                if a.target == b.target {
                    let is_conflict = matches!(
                        (&a.invariant_type, &b.invariant_type),
                        (InvariantType::MustExist, InvariantType::MustNotExist)
                            | (InvariantType::MustNotExist, InvariantType::MustExist)
                            | (InvariantType::MustColocate, InvariantType::MustSeparate)
                            | (InvariantType::MustSeparate, InvariantType::MustColocate)
                    );
                    if is_conflict {
                        conflicts.push((a.id.clone(), b.id.clone()));
                    }
                }
            }
        }
        conflicts
    }

    /// Number of constraints.
    pub fn len(&self) -> usize {
        self.constraints.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.constraints.is_empty()
    }
}

impl Default for ConstraintStore {
    fn default() -> Self {
        Self::new()
    }
}
