//! Scanner bindings: `drift_scan()` as `AsyncTask` with progress callbacks.
//!
//! The scan operation runs on libuv's thread pool (not the main JS thread)
//! via napi-rs `AsyncTask`. Progress is reported back to TypeScript via
//! v3's redesigned `ThreadsafeFunction`.
//!
//! Architecture:
//! 1. TS calls `driftScan(root, options, onProgress?)`
//! 2. Rust creates `ScanTask` → runs on libuv thread pool
//! 3. Scanner emits progress events → `NapiProgressHandler` forwards to ThreadsafeFunction
//! 4. Results are persisted to drift.db inside Rust (no NAPI crossing for bulk data)
//! 5. Lightweight `ScanSummary` is returned to TS

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use drift_analysis::scanner::Scanner;
use drift_analysis::scanner::language_detect::Language;
use drift_analysis::scanner::types::{CachedFileMetadata, ScanDiff};
use drift_core::config::ScanConfig;
use drift_core::events::handler::DriftEventHandler;
use drift_core::events::types::ScanProgressEvent;
use drift_core::types::collections::FxHashMap;
use drift_storage::batch::commands::{
    BatchCommand, FileMetadataRow as BatchFileMetadataRow,
};
use napi::bindgen_prelude::*;
use napi::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi_derive::napi;

use crate::conversions::error_codes;
use crate::conversions::types::{ProgressUpdate, ScanOptions, ScanSummary};
use crate::runtime;

/// Global cancellation flag for the current scan operation.
/// Set by `driftCancelScan()`, checked by rayon workers between files.
static SCAN_CANCELLED: AtomicBool = AtomicBool::new(false);

// ---- AsyncTask: ScanTask (no progress) ----

/// Async scan task that runs on libuv's thread pool.
pub struct ScanTask {
    root: PathBuf,
    options: ScanOptions,
}

#[napi]
impl Task for ScanTask {
    type Output = ScanSummary;
    type JsValue = ScanSummary;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let rt = runtime::get()?;
        let config = build_scan_config(&rt.config.scan, &self.options);
        let scanner = Scanner::new(config);

        // Wire global cancellation flag to scanner
        if SCAN_CANCELLED.load(Ordering::Relaxed) {
            SCAN_CANCELLED.store(false, Ordering::SeqCst);
        }

        let cached = load_cached_metadata(&rt)?;

        let diff = scanner
            .scan(&self.root, &cached, &NoOpHandler)
            .map_err(error_codes::scan_error)?;

        persist_scan_diff(&rt, &diff, &self.root.to_string_lossy())?;

        Ok(ScanSummary::from(&diff))
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(output)
    }
}

/// Scan a directory asynchronously. Returns a `ScanSummary` with counts and timing.
///
/// Full results are persisted to drift.db — query them via `driftQueryFiles()` etc.
/// Runs on libuv's thread pool, does not block the Node.js event loop.
///
/// @param root - Directory to scan.
/// @param options - Optional scan configuration overrides.
#[napi(js_name = "driftScan")]
pub fn drift_scan(root: String, options: Option<ScanOptions>) -> AsyncTask<ScanTask> {
    reset_cancellation();
    AsyncTask::new(ScanTask {
        root: PathBuf::from(root),
        options: options.unwrap_or_default(),
    })
}

// ---- AsyncTask: ScanWithProgressTask ----

/// Async scan task with progress reporting via ThreadsafeFunction.
pub struct ScanWithProgressTask {
    root: PathBuf,
    options: ScanOptions,
    on_progress: Arc<ThreadsafeFunction<ProgressUpdate, ()>>,
}

#[napi]
impl Task for ScanWithProgressTask {
    type Output = ScanSummary;
    type JsValue = ScanSummary;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let rt = runtime::get()?;
        let config = build_scan_config(&rt.config.scan, &self.options);
        let scanner = Scanner::new(config);

        // Create progress handler that bridges DriftEventHandler → ThreadsafeFunction
        let progress_handler = NapiProgressHandler::new(self.on_progress.clone());

        let cached = load_cached_metadata(&rt)?;

        let diff = scanner
            .scan(&self.root, &cached, &progress_handler)
            .map_err(error_codes::scan_error)?;

        persist_scan_diff(&rt, &diff, &self.root.to_string_lossy())?;

        Ok(ScanSummary::from(&diff))
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(output)
    }
}

/// Scan a directory with progress reporting.
///
/// The `on_progress` callback receives `ProgressUpdate` objects periodically
/// (every 100 files). Uses v3's ownership-based ThreadsafeFunction lifecycle.
///
/// @param root - Directory to scan.
/// @param options - Optional scan configuration overrides.
/// @param on_progress - Callback receiving progress updates.
#[napi(js_name = "driftScanWithProgress")]
pub fn drift_scan_with_progress(
    root: String,
    options: Option<ScanOptions>,
    on_progress: ThreadsafeFunction<ProgressUpdate, ()>,
) -> AsyncTask<ScanWithProgressTask> {
    reset_cancellation();
    AsyncTask::new(ScanWithProgressTask {
        root: PathBuf::from(root),
        options: options.unwrap_or_default(),
        on_progress: Arc::new(on_progress),
    })
}

// ---- Cancellation ----

/// Cancel a running scan operation.
///
/// Sets the global cancellation flag. Rayon workers check this between files.
/// Already-processed files are retained; in-progress files are discarded.
/// The scan returns with `status: "partial"`.
#[napi(js_name = "driftCancelScan")]
pub fn drift_cancel_scan() -> napi::Result<()> {
    SCAN_CANCELLED.store(true, Ordering::SeqCst);
    Ok(())
}

/// Reset the cancellation flag. Called at the start of each new scan.
fn reset_cancellation() {
    SCAN_CANCELLED.store(false, Ordering::SeqCst);
}

// ---- Progress Handler ----

/// Bridges `DriftEventHandler` → `ThreadsafeFunction` for progress reporting.
///
/// Reports every 100 files to keep NAPI callback overhead negligible (<0.1% of scan time).
/// Non-blocking: if the JS callback queue is full, the update is dropped rather than
/// blocking the Rust thread.
struct NapiProgressHandler {
    tsfn: Arc<ThreadsafeFunction<ProgressUpdate, ()>>,
}

impl NapiProgressHandler {
    fn new(tsfn: Arc<ThreadsafeFunction<ProgressUpdate, ()>>) -> Self {
        Self { tsfn }
    }
}

impl DriftEventHandler for NapiProgressHandler {
    fn on_scan_progress(&self, event: &ScanProgressEvent) {
        // Report every 100 files (from audit spec) or at completion
        if event.processed % 100 == 0 || event.processed == event.total {
            let update = ProgressUpdate {
                processed: event.processed as u32,
                total: event.total as u32,
                phase: "scanning".to_string(),
                current_file: None,
            };
            // Non-blocking call — drop update if JS queue is full
            let _ = self.tsfn.call(Ok(update), ThreadsafeFunctionCallMode::NonBlocking);
        }
    }
}

/// No-op event handler for scans without progress reporting.
struct NoOpHandler;
impl DriftEventHandler for NoOpHandler {}

// ---- Storage loading ----

/// Load cached file metadata from drift.db for incremental scan comparison.
fn load_cached_metadata(
    rt: &crate::runtime::DriftRuntime,
) -> napi::Result<FxHashMap<PathBuf, CachedFileMetadata>> {
    let records = rt.storage.with_reader(|conn| {
        drift_storage::queries::files::load_all_file_metadata(conn)
    }).map_err(|e| {
        napi::Error::from_reason(format!(
            "[{}] Failed to load cached metadata: {e}",
            error_codes::STORAGE_ERROR
        ))
    })?;

    let mut cached = FxHashMap::default();
    for record in records {
        let path = PathBuf::from(&record.path);
        let content_hash = if record.content_hash.len() == 8 {
            u64::from_le_bytes(record.content_hash.try_into().unwrap())
        } else {
            0
        };
        let language = record.language.as_deref().and_then(language_from_name);
        cached.insert(
            path.clone(),
            CachedFileMetadata {
                path,
                content_hash,
                mtime_secs: record.mtime_secs,
                mtime_nanos: record.mtime_nanos as u32,
                file_size: record.file_size as u64,
                language,
            },
        );
    }
    Ok(cached)
}

/// Convert a language display name back to a Language enum.
fn language_from_name(name: &str) -> Option<Language> {
    match name {
        "TypeScript" => Some(Language::TypeScript),
        "JavaScript" => Some(Language::JavaScript),
        "Python" => Some(Language::Python),
        "Java" => Some(Language::Java),
        "C#" => Some(Language::CSharp),
        "Go" => Some(Language::Go),
        "Rust" => Some(Language::Rust),
        "Ruby" => Some(Language::Ruby),
        "PHP" => Some(Language::Php),
        "Kotlin" => Some(Language::Kotlin),
        "C++" => Some(Language::Cpp),
        "C" => Some(Language::C),
        "Swift" => Some(Language::Swift),
        "Scala" => Some(Language::Scala),
        _ => None,
    }
}

// ---- Storage persistence ----

/// Persist scan results to drift.db via the batch writer.
/// Converts ScanEntry records to file_metadata rows and handles deletions.
fn persist_scan_diff(
    rt: &crate::runtime::DriftRuntime,
    diff: &ScanDiff,
    root_path: &str,
) -> napi::Result<()> {
    // Convert entries to batch rows
    let rows: Vec<BatchFileMetadataRow> = diff
        .entries
        .values()
        .map(|entry| BatchFileMetadataRow {
            path: entry.path.to_string_lossy().to_string(),
            language: entry.language.as_ref().map(|l| l.to_string()),
            file_size: entry.file_size as i64,
            content_hash: entry.content_hash.to_le_bytes().to_vec(),
            mtime_secs: entry.mtime_secs,
            mtime_nanos: entry.mtime_nanos as i64,
            last_scanned_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
            scan_duration_us: Some(entry.scan_duration_us as i64),
        })
        .collect();

    if !rows.is_empty() {
        rt.storage
            .send_batch(BatchCommand::UpsertFileMetadata(rows))
            .map_err(|e| {
                napi::Error::from_reason(format!(
                    "[{}] Failed to persist file metadata: {e}",
                    error_codes::STORAGE_ERROR
                ))
            })?;
    }

    // Delete removed files
    if !diff.removed.is_empty() {
        let paths: Vec<String> = diff
            .removed
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        rt.storage
            .send_batch(BatchCommand::DeleteFileMetadata(paths))
            .map_err(|e| {
                napi::Error::from_reason(format!(
                    "[{}] Failed to delete removed files: {e}",
                    error_codes::STORAGE_ERROR
                ))
            })?;
    }

    // PH7-01: Record completed scan in scan_history.
    // We insert + immediately update to 'completed' since persist_scan_diff runs
    // AFTER the scan finishes (the batch writer's InsertScanHistory only inserts
    // with status='running', which would leave it stuck forever).
    {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let root = root_path.to_string();
        let added = diff.added.len() as i64;
        let modified = diff.modified.len() as i64;
        let removed = diff.removed.len() as i64;
        let unchanged = diff.unchanged.len() as i64;
        let total = added + modified + removed + unchanged;
        let duration_ms = diff.stats.discovery_ms as i64
            + diff.stats.hashing_ms as i64
            + diff.stats.diff_ms as i64;

        rt.storage.with_writer(|conn| {
            let scan_id = drift_storage::queries::scan_history::insert_scan_start(conn, now, &root)?;
            drift_storage::queries::scan_history::update_scan_complete(
                conn, scan_id, now, total, added, modified, removed, unchanged,
                duration_ms, "completed", None,
            )
        }).map_err(|e| {
            napi::Error::from_reason(format!(
                "[{}] Failed to record scan history: {e}",
                error_codes::STORAGE_ERROR
            ))
        })?;
    }

    // Synchronous flush — block until batch writer confirms all file_metadata
    // rows are committed to SQLite. Without this, drift_analyze() may read an
    // empty file_metadata table if it runs immediately after scan.
    rt.storage.flush_batch_sync().map_err(|e| {
        napi::Error::from_reason(format!(
            "[{}] Failed to flush batch writer: {e}",
            error_codes::STORAGE_ERROR
        ))
    })?;

    Ok(())
}

// ---- Helpers ----

/// Build a `ScanConfig` by merging runtime config with per-call options.
fn build_scan_config(base: &ScanConfig, opts: &ScanOptions) -> ScanConfig {
    let mut config = base.clone();

    if let Some(force) = opts.force_full {
        config.force_full_scan = Some(force);
    }
    if let Some(max_size) = opts.max_file_size {
        config.max_file_size = Some(max_size as u64);
    }
    if let Some(ref include) = opts.include {
        config.include.extend(include.iter().cloned());
    }
    if let Some(ref extra) = opts.extra_ignore {
        config.extra_ignore.extend(extra.iter().cloned());
    }
    if let Some(follow) = opts.follow_symlinks {
        config.follow_symlinks = Some(follow);
    }

    config
}

// ---- PH7-02: Scan history NAPI binding ----

#[napi(object)]
#[derive(Debug, Clone)]
pub struct JsScanHistoryEntry {
    pub id: i64,
    pub started_at: i64,
    pub completed_at: Option<i64>,
    pub root_path: String,
    pub total_files: Option<i64>,
    pub added_files: Option<i64>,
    pub modified_files: Option<i64>,
    pub removed_files: Option<i64>,
    pub unchanged_files: Option<i64>,
    pub duration_ms: Option<i64>,
    pub status: String,
    pub error: Option<String>,
}

/// Query recent scan history entries.
#[napi(js_name = "driftScanHistory")]
pub fn drift_scan_history(limit: Option<u32>) -> napi::Result<Vec<JsScanHistoryEntry>> {
    let rt = runtime::get()?;
    let limit = limit.unwrap_or(20) as usize;

    let rows = rt.storage.with_reader(|conn| {
        drift_storage::queries::scan_history::query_recent(conn, limit)
    }).map_err(|e| {
        napi::Error::from_reason(format!(
            "[{}] Failed to query scan history: {e}",
            error_codes::STORAGE_ERROR
        ))
    })?;

    Ok(rows.into_iter().map(|r| JsScanHistoryEntry {
        id: r.id,
        started_at: r.started_at,
        completed_at: r.completed_at,
        root_path: r.root_path,
        total_files: r.total_files,
        added_files: r.added_files,
        modified_files: r.modified_files,
        removed_files: r.removed_files,
        unchanged_files: r.unchanged_files,
        duration_ms: r.duration_ms,
        status: r.status,
        error: r.error,
    }).collect())
}
