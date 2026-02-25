//! `IDriftFiles` trait — file metadata CRUD operations.
//!
//! Maps to `drift-storage/src/queries/files.rs` + `queries/parse_cache.rs`.

use crate::errors::StorageError;
use std::sync::Arc;

// ─── Row Types ──────────────────────────────────────────────────────

/// A file metadata record.
#[derive(Debug, Clone)]
pub struct FileMetadataRow {
    pub path: String,
    pub language: Option<String>,
    pub file_size: i64,
    pub content_hash: Vec<u8>,
    pub mtime_secs: i64,
    pub mtime_nanos: i64,
    pub last_scanned_at: i64,
    pub scan_duration_us: Option<i64>,
    pub pattern_count: i64,
    pub function_count: i64,
    pub error_count: i64,
    pub error: Option<String>,
}

/// A cached parse result record.
#[derive(Debug, Clone)]
pub struct ParseCacheRow {
    pub content_hash: Vec<u8>,
    pub language: String,
    pub parse_result_json: String,
    pub created_at: i64,
}

// ─── Trait ───────────────────────────────────────────────────────────

/// File metadata and parse cache storage operations.
///
/// Covers: `file_metadata` table + `parse_cache` table.
pub trait IDriftFiles: Send + Sync {
    // ── file_metadata ──

    /// Load all file metadata (for incremental scan comparison).
    fn load_all_file_metadata(&self) -> Result<Vec<FileMetadataRow>, StorageError>;

    /// Get file metadata for a specific path.
    fn get_file_metadata(&self, path: &str) -> Result<Option<FileMetadataRow>, StorageError>;

    /// Update the function_count counter cache for a file.
    fn update_function_count(&self, path: &str, count: i64) -> Result<(), StorageError>;

    /// Update the error fields for a file.
    fn update_file_error(
        &self,
        path: &str,
        error_count: i64,
        error_msg: Option<&str>,
    ) -> Result<(), StorageError>;

    /// Count total files in the database.
    fn count_files(&self) -> Result<i64, StorageError>;

    // ── parse_cache ──

    /// Get a cached parse result by content hash.
    fn get_parse_cache_by_hash(
        &self,
        content_hash: &[u8],
    ) -> Result<Option<ParseCacheRow>, StorageError>;

    /// Insert or replace a parse cache entry.
    fn insert_parse_cache(
        &self,
        content_hash: &[u8],
        language: &str,
        parse_result_json: &str,
        created_at: i64,
    ) -> Result<(), StorageError>;

    /// Invalidate a cache entry by content hash.
    fn invalidate_parse_cache(&self, content_hash: &[u8]) -> Result<(), StorageError>;

    /// Count entries in the parse cache.
    fn count_parse_cache(&self) -> Result<i64, StorageError>;
}

// ─── Arc blanket impl ───────────────────────────────────────────────

impl<T: IDriftFiles + ?Sized> IDriftFiles for Arc<T> {
    fn load_all_file_metadata(&self) -> Result<Vec<FileMetadataRow>, StorageError> {
        (**self).load_all_file_metadata()
    }
    fn get_file_metadata(&self, path: &str) -> Result<Option<FileMetadataRow>, StorageError> {
        (**self).get_file_metadata(path)
    }
    fn update_function_count(&self, path: &str, count: i64) -> Result<(), StorageError> {
        (**self).update_function_count(path, count)
    }
    fn update_file_error(
        &self,
        path: &str,
        error_count: i64,
        error_msg: Option<&str>,
    ) -> Result<(), StorageError> {
        (**self).update_file_error(path, error_count, error_msg)
    }
    fn count_files(&self) -> Result<i64, StorageError> {
        (**self).count_files()
    }
    fn get_parse_cache_by_hash(
        &self,
        content_hash: &[u8],
    ) -> Result<Option<ParseCacheRow>, StorageError> {
        (**self).get_parse_cache_by_hash(content_hash)
    }
    fn insert_parse_cache(
        &self,
        content_hash: &[u8],
        language: &str,
        parse_result_json: &str,
        created_at: i64,
    ) -> Result<(), StorageError> {
        (**self).insert_parse_cache(content_hash, language, parse_result_json, created_at)
    }
    fn invalidate_parse_cache(&self, content_hash: &[u8]) -> Result<(), StorageError> {
        (**self).invalidate_parse_cache(content_hash)
    }
    fn count_parse_cache(&self) -> Result<i64, StorageError> {
        (**self).count_parse_cache()
    }
}
