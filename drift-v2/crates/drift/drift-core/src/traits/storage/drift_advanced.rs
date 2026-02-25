//! `IDriftAdvanced` trait — simulations, decisions, context cache, migration projects.
//!
//! Maps to `drift-storage/src/queries/advanced.rs`.

use crate::errors::StorageError;
use std::sync::Arc;

// ─── Row Types ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SimulationRow {
    pub id: i64,
    pub task_category: String,
    pub task_description: String,
    pub approach_count: i32,
    pub recommended_approach: Option<String>,
    pub p10_effort: f64,
    pub p50_effort: f64,
    pub p90_effort: f64,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct CorrectionRow {
    pub id: i64,
    pub module_id: i64,
    pub section: String,
    pub original_text: String,
    pub corrected_text: String,
    pub reason: Option<String>,
    pub created_at: i64,
}

// ─── Trait ───────────────────────────────────────────────────────────

/// Advanced storage operations: simulations, decisions, context cache,
/// migration projects/modules/corrections.
pub trait IDriftAdvanced: Send + Sync {
    // ── simulations ──

    #[allow(clippy::too_many_arguments)]
    fn insert_simulation(
        &self,
        task_category: &str,
        task_description: &str,
        approach_count: i32,
        recommended_approach: Option<&str>,
        p10_effort: f64,
        p50_effort: f64,
        p90_effort: f64,
    ) -> Result<i64, StorageError>;

    fn get_simulations(&self, limit: usize) -> Result<Vec<SimulationRow>, StorageError>;

    // ── decisions ──

    #[allow(clippy::too_many_arguments)]
    fn insert_decision(
        &self,
        category: &str,
        description: &str,
        commit_sha: Option<&str>,
        confidence: f64,
        related_patterns: Option<&str>,
        author: Option<&str>,
        files_changed: Option<&str>,
    ) -> Result<i64, StorageError>;

    // ── context_cache ──

    fn insert_context_cache(
        &self,
        session_id: &str,
        intent: &str,
        depth: &str,
        token_count: i32,
        content_hash: &str,
    ) -> Result<i64, StorageError>;

    // ── migration_projects ──

    fn create_migration_project(
        &self,
        name: &str,
        source_language: &str,
        target_language: &str,
        source_framework: Option<&str>,
        target_framework: Option<&str>,
    ) -> Result<i64, StorageError>;

    fn create_migration_module(
        &self,
        project_id: i64,
        module_name: &str,
    ) -> Result<i64, StorageError>;

    fn update_module_status(
        &self,
        module_id: i64,
        status: &str,
    ) -> Result<(), StorageError>;

    fn insert_migration_correction(
        &self,
        module_id: i64,
        section: &str,
        original_text: &str,
        corrected_text: &str,
        reason: Option<&str>,
    ) -> Result<i64, StorageError>;

    fn get_migration_correction(
        &self,
        correction_id: i64,
    ) -> Result<Option<CorrectionRow>, StorageError>;
}

// ─── Arc blanket impl ───────────────────────────────────────────────

impl<T: IDriftAdvanced + ?Sized> IDriftAdvanced for Arc<T> {
    fn insert_simulation(&self, tc: &str, td: &str, ac: i32, ra: Option<&str>, p10: f64, p50: f64, p90: f64) -> Result<i64, StorageError> {
        (**self).insert_simulation(tc, td, ac, ra, p10, p50, p90)
    }
    fn get_simulations(&self, limit: usize) -> Result<Vec<SimulationRow>, StorageError> {
        (**self).get_simulations(limit)
    }
    fn insert_decision(&self, cat: &str, desc: &str, sha: Option<&str>, conf: f64, rp: Option<&str>, auth: Option<&str>, fc: Option<&str>) -> Result<i64, StorageError> {
        (**self).insert_decision(cat, desc, sha, conf, rp, auth, fc)
    }
    fn insert_context_cache(&self, sid: &str, intent: &str, depth: &str, tc: i32, ch: &str) -> Result<i64, StorageError> {
        (**self).insert_context_cache(sid, intent, depth, tc, ch)
    }
    fn create_migration_project(&self, name: &str, sl: &str, tl: &str, sf: Option<&str>, tf: Option<&str>) -> Result<i64, StorageError> {
        (**self).create_migration_project(name, sl, tl, sf, tf)
    }
    fn create_migration_module(&self, pid: i64, mn: &str) -> Result<i64, StorageError> {
        (**self).create_migration_module(pid, mn)
    }
    fn update_module_status(&self, mid: i64, status: &str) -> Result<(), StorageError> {
        (**self).update_module_status(mid, status)
    }
    fn insert_migration_correction(&self, mid: i64, sec: &str, ot: &str, ct: &str, reason: Option<&str>) -> Result<i64, StorageError> {
        (**self).insert_migration_correction(mid, sec, ot, ct, reason)
    }
    fn get_migration_correction(&self, cid: i64) -> Result<Option<CorrectionRow>, StorageError> {
        (**self).get_migration_correction(cid)
    }
}
