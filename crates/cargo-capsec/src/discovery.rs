//! Workspace and source file discovery.
//!
//! Uses `cargo metadata` to enumerate all crates in a workspace, then recursively
//! walks each crate's `src/` directory to find `.rs` source files. Also detects
//! `build.rs` files at the crate root.
//!
//! By default, only workspace-local crates are returned (`--no-deps` mode for speed).
//! With `include_deps = true`, all packages from `cargo metadata` are returned,
//! including registry dependencies whose source is cached in `~/.cargo/registry/src/`.

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Metadata about a crate discovered in the workspace.
#[derive(Debug, Clone)]
pub struct CrateInfo {
    /// Crate name (e.g., `"serde"`, `"my-app"`).
    pub name: String,
    /// Crate version (e.g., `"1.0.228"`).
    pub version: String,
    /// Path to the crate's `src/` directory.
    pub source_dir: PathBuf,
    /// `true` if this is a registry dependency (has a `source` field in cargo metadata),
    /// `false` if it's a local workspace member or path dependency.
    pub is_dependency: bool,
}

#[derive(Deserialize)]
struct CargoMetadata {
    packages: Vec<Package>,
    workspace_root: String,
}

#[derive(Deserialize)]
struct Package {
    name: String,
    version: String,
    manifest_path: String,
    source: Option<String>,
}

/// Result of workspace discovery: crates and the resolved workspace root.
pub struct DiscoveryResult {
    /// All discovered crates.
    pub crates: Vec<CrateInfo>,
    /// The Cargo workspace root (from `cargo metadata`).
    pub workspace_root: PathBuf,
}

/// Discovers all crates in a Cargo workspace by running `cargo metadata`.
///
/// When `include_deps` is `false` (default), passes `--no-deps` for speed — only
/// workspace members and path dependencies appear. When `true`, all transitive
/// dependencies with cached source are included.
///
/// Returns both the discovered crates and the resolved workspace root path.
pub fn discover_crates(
    workspace_root: &Path,
    include_deps: bool,
    spawn_cap: &impl capsec_core::has::Has<capsec_core::permission::Spawn>,
    _fs_cap: &impl capsec_core::has::Has<capsec_core::permission::FsRead>,
) -> Result<DiscoveryResult, String> {
    // Use --no-deps by default for speed (avoids resolving 300+ transitive deps).
    // Drop it when --include-deps is set so path dependencies and registry crates appear.
    let mut args = vec!["metadata", "--format-version=1"];
    if !include_deps {
        args.push("--no-deps");
    }

    let output = capsec_std::process::command("cargo", spawn_cap)
        .args(&args)
        .current_dir(workspace_root)
        .output()
        .map_err(|e| format!("Failed to run cargo metadata: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("cargo metadata failed: {stderr}"));
    }

    let metadata: CargoMetadata = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("Failed to parse cargo metadata: {e}"))?;

    let resolved_root = PathBuf::from(&metadata.workspace_root);

    let mut crates = Vec::new();

    for package in &metadata.packages {
        let manifest_dir = Path::new(&package.manifest_path)
            .parent()
            .unwrap_or(Path::new("."))
            .to_path_buf();

        let src_dir = manifest_dir.join("src");

        if src_dir.exists() {
            crates.push(CrateInfo {
                name: package.name.clone(),
                version: package.version.clone(),
                source_dir: src_dir,
                is_dependency: package.source.is_some(),
            });
        }
    }

    Ok(DiscoveryResult {
        crates,
        workspace_root: resolved_root,
    })
}

/// Recursively discovers all `.rs` source files in a directory.
///
/// Skips `target/` and hidden directories. Also checks for `build.rs` at the
/// crate root (the parent of the `src/` directory).
pub fn discover_source_files(
    dir: &Path,
    cap: &impl capsec_core::has::Has<capsec_core::permission::FsRead>,
) -> Vec<PathBuf> {
    let mut files = Vec::new();
    discover_recursive(dir, &mut files, cap);

    // Also check for build.rs at the crate root (parent of src/)
    if let Some(crate_root) = dir.parent() {
        let build_rs = crate_root.join("build.rs");
        if build_rs.exists() {
            files.push(build_rs);
        }
    }

    files
}

fn discover_recursive(
    dir: &Path,
    files: &mut Vec<PathBuf>,
    cap: &impl capsec_core::has::Has<capsec_core::permission::FsRead>,
) {
    let entries = match capsec_std::fs::read_dir(dir, cap) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().unwrap_or_default().to_str().unwrap_or("");
            if name != "target" && !name.starts_with('.') {
                discover_recursive(&path, files, cap);
            }
        } else if path.extension().is_some_and(|e| e == "rs") {
            files.push(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_source_files_finds_rs_files() {
        let root = capsec_core::root::test_root();
        let cap = root.grant::<capsec_core::permission::FsRead>();
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let files = discover_source_files(&dir, &cap);
        assert!(!files.is_empty());
        assert!(
            files
                .iter()
                .all(|f| f.extension().unwrap_or_default() == "rs")
        );
    }
}
