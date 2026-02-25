//! Framework pack registry — loads built-in packs + user custom packs.
//!
//! Built-in packs are embedded at compile time via `include_str!`.
//! User packs are loaded from `.drift/frameworks/` at runtime.

use std::path::Path;

use drift_core::errors::DetectionError;

use super::diagnostics::FrameworkDiagnostics;
use super::loader::{self, CompiledDetectSignal, CompiledFrameworkPack};

/// Configuration for framework pack filtering.
#[derive(Debug, Clone, Default)]
pub struct FrameworkConfig {
    /// Pack names to disable (excluded from loading).
    pub disabled_packs: Vec<String>,
    /// If set, only these pack names are loaded.
    pub enabled_only: Option<Vec<String>>,
}

/// Registry of all loaded framework packs.
pub struct FrameworkPackRegistry {
    packs: Vec<CompiledFrameworkPack>,
    diag: FrameworkDiagnostics,
}

impl FrameworkPackRegistry {
    /// Create registry with only built-in packs.
    pub fn with_builtins() -> Self {
        Self::with_builtins_filtered(None)
    }

    /// Create registry with built-in packs, applying optional config filter.
    pub fn with_builtins_filtered(config: Option<&FrameworkConfig>) -> Self {
        let mut packs = Vec::new();
        let mut diag = FrameworkDiagnostics::default();

        // Load each built-in pack. If any fails to parse, log and skip.
        for (name, toml_str) in builtin_packs() {
            if let Some(cfg) = config {
                if Self::is_pack_disabled(name, cfg) {
                    diag.builtin_packs_skipped += 1;
                    continue;
                }
            }
            match loader::load_from_str(toml_str) {
                Ok(pack) => {
                    diag.total_patterns_compiled += pack.patterns.len();
                    diag.builtin_packs_loaded += 1;
                    if let Some(ref ver) = pack.version {
                        diag.pack_versions.insert(pack.name.clone(), ver.clone());
                    }
                    packs.push(pack);
                }
                Err(e) => {
                    eprintln!("[drift] warning: failed to load built-in pack '{name}': {e}");
                    diag.builtin_packs_skipped += 1;
                }
            }
        }

        Self { packs, diag }
    }

    /// Create registry with built-in packs + user packs from a directory.
    pub fn with_builtins_and_custom(custom_dir: &Path) -> Self {
        Self::with_builtins_and_custom_filtered(custom_dir, None)
    }

    /// Create registry with built-in + custom packs, applying optional config filter.
    pub fn with_builtins_and_custom_filtered(custom_dir: &Path, config: Option<&FrameworkConfig>) -> Self {
        let mut registry = Self::with_builtins_filtered(config);

        if custom_dir.is_dir() {
            if let Ok(entries) = std::fs::read_dir(custom_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().is_some_and(|ext| ext == "toml") {
                        match loader::load_from_file(&path) {
                            Ok(pack) => {
                                registry.diag.total_patterns_compiled += pack.patterns.len();
                                registry.diag.custom_packs_loaded += 1;
                                if let Some(ref ver) = pack.version {
                                    registry.diag.pack_versions.insert(pack.name.clone(), ver.clone());
                                }
                                registry.packs.push(pack);
                            }
                            Err(e) => {
                                eprintln!(
                                    "[drift] warning: failed to load custom pack '{}': {e}",
                                    path.display()
                                );
                                registry.diag.custom_packs_skipped += 1;
                            }
                        }
                    }
                }
            }
        }

        registry
    }

    /// Load a single pack from a TOML string (for testing).
    pub fn load_single(toml_str: &str) -> Result<CompiledFrameworkPack, DetectionError> {
        loader::load_from_str(toml_str)
    }

    /// Consume the registry and return all packs.
    pub fn into_packs(self) -> Vec<CompiledFrameworkPack> {
        self.packs
    }

    /// Number of loaded packs.
    pub fn pack_count(&self) -> usize {
        self.packs.len()
    }

    /// Total pattern count across all packs.
    pub fn pattern_count(&self) -> usize {
        self.packs.iter().map(|p| p.patterns.len()).sum()
    }

    /// Get load-time diagnostics.
    pub fn diagnostics(&self) -> &FrameworkDiagnostics {
        &self.diag
    }

    /// Evaluate detect_signals for all packs against project files and dependencies.
    /// Returns names of packs whose signals matched.
    pub fn evaluate_signals(&mut self, files: &[String], dependencies: &[String]) -> Vec<String> {
        let mut detected = Vec::new();
        for pack in &self.packs {
            if pack.detect_signals.is_empty() || evaluate_pack_signals(pack, files, dependencies) {
                detected.push(pack.name.clone());
            }
        }
        self.diag.frameworks_detected = detected.clone();
        detected
    }

    /// Check if a pack should be disabled based on config.
    fn is_pack_disabled(name: &str, config: &FrameworkConfig) -> bool {
        if let Some(ref enabled) = config.enabled_only {
            return !enabled.iter().any(|e| e == name);
        }
        config.disabled_packs.iter().any(|d| d == name)
    }
}

/// Evaluate a single pack's detect_signals against project metadata.
pub fn evaluate_pack_signals(
    pack: &CompiledFrameworkPack,
    files: &[String],
    dependencies: &[String],
) -> bool {
    if pack.detect_signals.is_empty() {
        return true; // No signals = always active
    }
    pack.detect_signals.iter().any(|signal| match signal {
        CompiledDetectSignal::Import(src) => {
            // Import signals match if any tracked file would import this
            dependencies.iter().any(|d| d.contains(src.as_str()))
        }
        CompiledDetectSignal::FilePattern(glob) => {
            files.iter().any(|f| glob.matches(f))
        }
        CompiledDetectSignal::Decorator(name) => {
            // Decorator signals are structural — can't evaluate without parsing
            // Return false; they'll be evaluated at match time
            let _ = name;
            false
        }
        CompiledDetectSignal::Dependency(dep) => {
            dependencies.iter().any(|d| d == dep)
        }
    })
}

/// Built-in framework packs embedded at compile time.
fn builtin_packs() -> Vec<(&'static str, &'static str)> {
    vec![
        // --- Cross-language category packs ---
        ("security", include_str!("packs/security.toml")),
        ("auth", include_str!("packs/auth.toml")),
        ("data-access", include_str!("packs/data_access.toml")),
        ("errors", include_str!("packs/errors.toml")),
        ("logging", include_str!("packs/logging.toml")),
        ("testing", include_str!("packs/testing.toml")),
        ("performance", include_str!("packs/performance.toml")),
        ("config", include_str!("packs/config.toml")),
        ("api", include_str!("packs/api.toml")),
        ("components", include_str!("packs/components.toml")),
        ("structural", include_str!("packs/structural.toml")),
        ("documentation", include_str!("packs/documentation.toml")),
        ("styling", include_str!("packs/styling.toml")),
        ("accessibility", include_str!("packs/accessibility.toml")),
        // --- Framework-specific packs ---
        ("spring", include_str!("packs/spring.toml")),
        ("aspnet", include_str!("packs/aspnet.toml")),
        ("laravel", include_str!("packs/laravel.toml")),
        ("express", include_str!("packs/express.toml")),
        ("django", include_str!("packs/django.toml")),
        ("rails", include_str!("packs/rails.toml")),
        ("go-frameworks", include_str!("packs/go_frameworks.toml")),
        ("rust-frameworks", include_str!("packs/rust_frameworks.toml")),
        ("typescript-types", include_str!("packs/typescript_types.toml")),
    ]
}
