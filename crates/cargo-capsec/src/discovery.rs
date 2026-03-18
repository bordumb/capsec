use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct CrateInfo {
    pub name: String,
    pub version: String,
    pub source_dir: PathBuf,
    pub is_dependency: bool,
}

#[derive(Deserialize)]
struct CargoMetadata {
    packages: Vec<Package>,
}

#[derive(Deserialize)]
struct Package {
    name: String,
    version: String,
    manifest_path: String,
    source: Option<String>,
}

pub fn discover_crates(workspace_root: &Path, include_deps: bool) -> Result<Vec<CrateInfo>, String> {
    // Use --no-deps by default for speed (avoids resolving 300+ transitive deps).
    // Drop it when --include-deps is set so path dependencies and registry crates appear.
    let mut args = vec!["metadata", "--format-version=1"];
    if !include_deps {
        args.push("--no-deps");
    }

    let output = Command::new("cargo")
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

    Ok(crates)
}

pub fn discover_source_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    discover_recursive(dir, &mut files);

    // Also check for build.rs at the crate root (parent of src/)
    if let Some(crate_root) = dir.parent() {
        let build_rs = crate_root.join("build.rs");
        if build_rs.exists() {
            files.push(build_rs);
        }
    }

    files
}

fn discover_recursive(dir: &Path, files: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().unwrap_or_default().to_str().unwrap_or("");
            if name != "target" && !name.starts_with('.') {
                discover_recursive(&path, files);
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
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let files = discover_source_files(&dir);
        assert!(!files.is_empty());
        assert!(files.iter().all(|f| f.extension().unwrap_or_default() == "rs"));
    }
}
