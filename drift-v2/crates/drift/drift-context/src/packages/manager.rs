//! 15 package manager support.

use serde::{Deserialize, Serialize};

/// Supported package managers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageManager {
    Npm,
    Yarn,
    Pnpm,
    Bun,
    Pip,
    Poetry,
    Pipenv,
    Cargo,
    Go,
    Maven,
    Gradle,
    NuGet,
    Composer,
    Bundler,
    CocoaPods,
}

impl PackageManager {
    pub const ALL: &'static [PackageManager] = &[
        Self::Npm, Self::Yarn, Self::Pnpm, Self::Bun,
        Self::Pip, Self::Poetry, Self::Pipenv,
        Self::Cargo, Self::Go,
        Self::Maven, Self::Gradle,
        Self::NuGet, Self::Composer, Self::Bundler, Self::CocoaPods,
    ];

    pub fn name(&self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Yarn => "yarn",
            Self::Pnpm => "pnpm",
            Self::Bun => "bun",
            Self::Pip => "pip",
            Self::Poetry => "poetry",
            Self::Pipenv => "pipenv",
            Self::Cargo => "cargo",
            Self::Go => "go",
            Self::Maven => "maven",
            Self::Gradle => "gradle",
            Self::NuGet => "nuget",
            Self::Composer => "composer",
            Self::Bundler => "bundler",
            Self::CocoaPods => "cocoapods",
        }
    }

    /// Manifest file name for this package manager.
    pub fn manifest_file(&self) -> &'static str {
        match self {
            Self::Npm | Self::Yarn | Self::Pnpm | Self::Bun => "package.json",
            Self::Pip => "requirements.txt",
            Self::Poetry => "pyproject.toml",
            Self::Pipenv => "Pipfile",
            Self::Cargo => "Cargo.toml",
            Self::Go => "go.mod",
            Self::Maven => "pom.xml",
            Self::Gradle => "build.gradle",
            Self::NuGet => "*.csproj",
            Self::Composer => "composer.json",
            Self::Bundler => "Gemfile",
            Self::CocoaPods => "Podfile",
        }
    }

    /// Lock file name for this package manager.
    pub fn lock_file(&self) -> Option<&'static str> {
        match self {
            Self::Npm => Some("package-lock.json"),
            Self::Yarn => Some("yarn.lock"),
            Self::Pnpm => Some("pnpm-lock.yaml"),
            Self::Bun => Some("bun.lockb"),
            Self::Poetry => Some("poetry.lock"),
            Self::Pipenv => Some("Pipfile.lock"),
            Self::Cargo => Some("Cargo.lock"),
            Self::Go => Some("go.sum"),
            Self::Gradle => Some("gradle.lockfile"),
            Self::Composer => Some("composer.lock"),
            Self::Bundler => Some("Gemfile.lock"),
            Self::CocoaPods => Some("Podfile.lock"),
            _ => None,
        }
    }

    /// Detect package manager from a file name.
    pub fn detect_from_file(filename: &str) -> Option<Self> {
        match filename {
            "package.json" | "package-lock.json" => Some(Self::Npm),
            "yarn.lock" => Some(Self::Yarn),
            "pnpm-lock.yaml" => Some(Self::Pnpm),
            "bun.lockb" => Some(Self::Bun),
            "requirements.txt" => Some(Self::Pip),
            "pyproject.toml" | "poetry.lock" => Some(Self::Poetry),
            "Pipfile" | "Pipfile.lock" => Some(Self::Pipenv),
            "Cargo.toml" | "Cargo.lock" => Some(Self::Cargo),
            "go.mod" | "go.sum" => Some(Self::Go),
            "pom.xml" => Some(Self::Maven),
            "build.gradle" | "build.gradle.kts" => Some(Self::Gradle),
            "composer.json" | "composer.lock" => Some(Self::Composer),
            "Gemfile" | "Gemfile.lock" => Some(Self::Bundler),
            "Podfile" | "Podfile.lock" => Some(Self::CocoaPods),
            f if f.ends_with(".csproj") => Some(Self::NuGet),
            _ => None,
        }
    }
}

impl std::fmt::Display for PackageManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_15_package_managers() {
        assert_eq!(PackageManager::ALL.len(), 15);
    }

    #[test]
    fn test_detect_from_file() {
        assert_eq!(PackageManager::detect_from_file("package.json"), Some(PackageManager::Npm));
        assert_eq!(PackageManager::detect_from_file("Cargo.toml"), Some(PackageManager::Cargo));
        assert_eq!(PackageManager::detect_from_file("go.mod"), Some(PackageManager::Go));
        assert_eq!(PackageManager::detect_from_file("unknown.txt"), None);
    }

    #[test]
    fn test_manifest_files() {
        for pm in PackageManager::ALL {
            assert!(!pm.manifest_file().is_empty());
        }
    }
}
