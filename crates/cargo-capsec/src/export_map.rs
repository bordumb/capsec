//! Cross-crate export map construction.
//!
//! After scanning a dependency crate, this module extracts a summary of its
//! authority surface: which functions (directly or transitively) exercise ambient
//! authority. The export map is keyed by fully-qualified module path within the crate.

use crate::authorities::{Category, Risk};
use crate::detector::Finding;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// A dependency crate's authority surface — its functions that transitively
/// exercise ambient authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrateExportMap {
    /// Normalized crate name (underscores, not hyphens).
    pub crate_name: String,
    /// Crate version string.
    pub crate_version: String,
    /// Maps module-qualified function names to the authority categories they exercise.
    /// Key format: `"crate_name::module::function"` (e.g., `"reqwest::blocking::get"`).
    pub exports: HashMap<String, Vec<ExportedAuthority>>,
}

/// A single authority finding associated with an exported function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedAuthority {
    /// What kind of ambient authority this exercises.
    pub category: Category,
    /// How dangerous this call is.
    pub risk: Risk,
    /// The leaf authority call that this traces back to.
    pub leaf_call: String,
    /// Whether this is a direct call in the function or transitively propagated.
    pub is_transitive: bool,
}

/// Converts a source file path to a module path within the crate.
///
/// # Examples
///
/// - `"src/lib.rs"` → `[]`
/// - `"src/blocking/client.rs"` → `["blocking", "client"]`
/// - `"src/fs.rs"` → `["fs"]`
/// - `"src/fs/mod.rs"` → `["fs"]`
/// - `"src/main.rs"` → `[]`
#[must_use]
pub fn file_to_module_path(file_path: &str, src_dir: &Path) -> Vec<String> {
    let relative = Path::new(file_path)
        .strip_prefix(src_dir)
        .unwrap_or(Path::new(file_path));

    let stem = relative.file_stem().unwrap_or_default().to_string_lossy();

    let mut parts: Vec<String> = relative
        .parent()
        .unwrap_or(Path::new(""))
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();

    // "mod.rs" → module name is the parent directory (already captured)
    // "lib.rs" / "main.rs" → crate root, no additional segment
    // anything else → add the file stem as a module segment
    match stem.as_ref() {
        "mod" | "lib" | "main" => {}
        other => parts.push(other.to_string()),
    }

    parts
}

/// Builds an export map from a dependency crate's scan findings.
///
/// For each finding, derives the full module-qualified key from the file path
/// and function name. Build-script findings (`is_build_script: true`) are excluded
/// since they represent compile-time authority, not runtime authority.
#[must_use]
pub fn build_export_map(
    crate_name: &str,
    crate_version: &str,
    findings: &[Finding],
    src_dir: &Path,
) -> CrateExportMap {
    let mut exports: HashMap<String, Vec<ExportedAuthority>> = HashMap::new();

    for finding in findings {
        // Exclude build-script findings (compile-time only)
        if finding.is_build_script {
            continue;
        }

        let auth = ExportedAuthority {
            category: finding.category.clone(),
            risk: finding.risk,
            leaf_call: finding.call_text.clone(),
            is_transitive: finding.is_transitive,
        };

        // Entry 1: Full module-qualified path (e.g., "git2::repository::open")
        // Matches calls like `crate::module::function()`
        let module_path = file_to_module_path(&finding.file, src_dir);
        let mut full_path = vec![crate_name.to_string()];
        full_path.extend(module_path);
        full_path.push(finding.function.clone());
        let key = full_path.join("::");

        exports.entry(key.clone()).or_default().push(auth.clone());

        // Entry 2: Crate-scoped function name (e.g., "git2" + "open")
        // For type-qualified calls like `git2::Repository::open()`, strict suffix
        // matching fails ("Repository" ≠ "repository" from file path). This entry
        // enables crate-scoped matching: if the expanded call path contains the
        // crate name AND ends with the function name, it's a match.
        let scoped_key = format!("{crate_name}::{}", finding.function);
        if scoped_key != key {
            exports.entry(scoped_key).or_default().push(auth);
        }
    }

    CrateExportMap {
        crate_name: crate_name.to_string(),

        crate_version: crate_version.to_string(),
        exports,
    }
}

/// Adds extern function declarations from parsed files to an export map.
///
/// When a crate like `libgit2-sys` declares `extern "C" { fn git_repository_open(...); }`,
/// this creates an FFI export entry for `git_repository_open` so that other crates
/// calling `libgit2_sys::git_repository_open()` get a cross-crate FFI finding.
///
/// This is necessary because extern block findings have `function: "extern \"C\""` which
/// produces useless export map keys. The individual function names need to be exported.
pub fn add_extern_exports(
    export_map: &mut CrateExportMap,
    parsed_files: &[crate::parser::ParsedFile],
    src_dir: &Path,
) {
    let crate_name = &export_map.crate_name;

    for file in parsed_files {
        // Skip build.rs extern blocks (compile-time only)
        if file.path.ends_with("build.rs") {
            continue;
        }

        for ext in &file.extern_blocks {
            let module_path = file_to_module_path(&file.path, src_dir);

            for fn_name in &ext.functions {
                let auth = ExportedAuthority {
                    category: crate::authorities::Category::Ffi,
                    risk: crate::authorities::Risk::High,
                    leaf_call: format!("extern {fn_name}"),
                    is_transitive: false,
                };

                // Full path: crate::module::fn_name
                let mut full_path = vec![crate_name.clone()];
                full_path.extend(module_path.clone());
                full_path.push(fn_name.clone());
                let key = full_path.join("::");
                export_map
                    .exports
                    .entry(key.clone())
                    .or_default()
                    .push(auth.clone());

                // Short form: crate::fn_name (for crate-scoped matching)
                let short_key = format!("{crate_name}::{fn_name}");
                if short_key != key {
                    export_map.exports.entry(short_key).or_default().push(auth);
                }
            }
        }
    }
}

/// Cached export map format for disk persistence.
#[derive(Debug, Serialize, Deserialize)]
pub struct CachedExportMap {
    /// Schema version — bump when the export map format changes.
    pub schema_version: u32,
    /// The actual export map data.
    #[serde(flatten)]
    pub export_map: CrateExportMap,
}

/// Current schema version for cached export maps.
/// Bumped to 2: added extern function declaration exports.
pub const EXPORT_MAP_SCHEMA_VERSION: u32 = 2;

/// Attempts to load a cached export map for a dependency crate.
///
/// Returns `None` if the cache is missing, stale, or corrupt.
/// Only caches registry crates (path deps are always re-scanned).
pub fn load_cached_export_map(
    cache_dir: &Path,
    crate_name: &str,
    crate_version: &str,
    cap: &impl capsec_core::cap_provider::CapProvider<capsec_core::permission::FsRead>,
) -> Option<CrateExportMap> {
    let path = cache_dir
        .join("export-maps")
        .join(format!("{crate_name}-{crate_version}.json"));
    let content = capsec_std::fs::read_to_string(&path, cap).ok()?;
    let cached: CachedExportMap = serde_json::from_str(&content).ok()?;
    if cached.schema_version != EXPORT_MAP_SCHEMA_VERSION {
        return None; // Schema changed — re-scan
    }
    Some(cached.export_map)
}

/// Saves an export map to the cache directory.
///
/// Silently ignores write failures (caching is best-effort).
pub fn save_export_map_cache(
    cache_dir: &Path,
    export_map: &CrateExportMap,
    cap: &impl capsec_core::cap_provider::CapProvider<capsec_core::permission::FsWrite>,
) {
    let dir = cache_dir.join("export-maps");
    // Create directory if needed
    let _ = std::fs::create_dir_all(&dir);

    let cached = CachedExportMap {
        schema_version: EXPORT_MAP_SCHEMA_VERSION,
        export_map: export_map.clone(),
    };

    if let Ok(json) = serde_json::to_string_pretty(&cached) {
        let path = dir.join(format!(
            "{}-{}.json",
            export_map.crate_name, export_map.crate_version
        ));
        let _ = capsec_std::fs::write(path, json, cap);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorities::{Category, Risk};
    use crate::detector::Finding;

    fn make_finding(
        file: &str,
        function: &str,
        call_text: &str,
        category: Category,
        is_build_script: bool,
    ) -> Finding {
        Finding {
            file: file.to_string(),
            function: function.to_string(),
            function_line: 1,
            call_line: 2,
            call_col: 5,
            call_text: call_text.to_string(),
            category,
            subcategory: "test".to_string(),
            risk: Risk::Medium,
            description: "test".to_string(),
            is_build_script,
            crate_name: "test_crate".to_string(),
            crate_version: "1.0.0".to_string(),
            is_deny_violation: false,
            is_transitive: false,
        }
    }

    #[test]
    fn file_to_module_path_lib() {
        assert_eq!(
            file_to_module_path("src/lib.rs", Path::new("src")),
            Vec::<String>::new()
        );
    }

    #[test]
    fn file_to_module_path_main() {
        assert_eq!(
            file_to_module_path("src/main.rs", Path::new("src")),
            Vec::<String>::new()
        );
    }

    #[test]
    fn file_to_module_path_simple_module() {
        assert_eq!(
            file_to_module_path("src/fs.rs", Path::new("src")),
            vec!["fs"]
        );
    }

    #[test]
    fn file_to_module_path_nested() {
        assert_eq!(
            file_to_module_path("src/blocking/client.rs", Path::new("src")),
            vec!["blocking", "client"]
        );
    }

    #[test]
    fn file_to_module_path_mod_rs() {
        assert_eq!(
            file_to_module_path("src/fs/mod.rs", Path::new("src")),
            vec!["fs"]
        );
    }

    #[test]
    fn build_export_map_basic() {
        let findings = vec![make_finding(
            "src/lib.rs",
            "read_file",
            "std::fs::read",
            Category::Fs,
            false,
        )];
        let map = build_export_map("my_crate", "1.0.0", &findings, Path::new("src"));
        assert!(map.exports.contains_key("my_crate::read_file"));
        let auths = &map.exports["my_crate::read_file"];
        assert_eq!(auths.len(), 1);
        assert_eq!(auths[0].category, Category::Fs);
    }

    #[test]
    fn build_export_map_excludes_build_script() {
        let findings = vec![
            make_finding(
                "src/lib.rs",
                "read_file",
                "std::fs::read",
                Category::Fs,
                false,
            ),
            make_finding("build.rs", "main", "std::env::var", Category::Env, true),
        ];
        let map = build_export_map("my_crate", "1.0.0", &findings, Path::new("src"));
        assert_eq!(map.exports.len(), 1);
        assert!(map.exports.contains_key("my_crate::read_file"));
    }

    #[test]
    fn build_export_map_nested_module() {
        let findings = vec![make_finding(
            "src/blocking/client.rs",
            "get",
            "TcpStream::connect",
            Category::Net,
            false,
        )];
        let map = build_export_map("reqwest", "0.12.5", &findings, Path::new("src"));
        assert!(map.exports.contains_key("reqwest::blocking::client::get"));
    }

    #[test]
    fn build_export_map_multiple_findings_same_function() {
        let findings = vec![
            make_finding("src/lib.rs", "mixed", "std::fs::read", Category::Fs, false),
            make_finding(
                "src/lib.rs",
                "mixed",
                "TcpStream::connect",
                Category::Net,
                false,
            ),
        ];
        let map = build_export_map("my_crate", "1.0.0", &findings, Path::new("src"));
        let auths = &map.exports["my_crate::mixed"];
        assert_eq!(auths.len(), 2);
    }

    #[test]
    fn build_export_map_empty_findings() {
        let map = build_export_map("empty", "1.0.0", &[], Path::new("src"));
        assert!(map.exports.is_empty());
    }

    #[test]
    fn cached_export_map_round_trip() {
        let findings = vec![make_finding(
            "src/lib.rs",
            "read_file",
            "std::fs::read",
            Category::Fs,
            false,
        )];
        let export_map = build_export_map("my_crate", "1.0.0", &findings, Path::new("src"));
        let cached = CachedExportMap {
            schema_version: EXPORT_MAP_SCHEMA_VERSION,
            export_map,
        };
        let json = serde_json::to_string(&cached).unwrap();
        let loaded: CachedExportMap = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.schema_version, EXPORT_MAP_SCHEMA_VERSION);
        assert_eq!(loaded.export_map.crate_name, "my_crate");
        assert!(
            loaded
                .export_map
                .exports
                .contains_key("my_crate::read_file")
        );
    }
}
