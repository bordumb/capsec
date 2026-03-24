//! Workspace and source file discovery.
//!
//! Uses `cargo metadata` to enumerate all crates in a workspace, then recursively
//! walks each crate's `src/` directory to find `.rs` source files. Also detects
//! `build.rs` files at the crate root.
//!
//! By default, only workspace-local crates are returned (`--no-deps` mode for speed).
//! With `include_deps = true`, all packages from `cargo metadata` are returned,
//! including registry dependencies whose source is cached in `~/.cargo/registry/src/`.

use crate::config::Classification;
use serde::Deserialize;
use std::collections::{HashMap, VecDeque};
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
    /// Classification from `[package.metadata.capsec]` in the crate's Cargo.toml.
    /// `None` if not specified.
    pub classification: Option<Classification>,
    /// Opaque package ID from `cargo metadata` (for linking to the resolve graph).
    /// Only populated when `include_deps` is true.
    pub package_id: Option<String>,
}

#[derive(Deserialize)]
struct CargoMetadata {
    packages: Vec<Package>,
    workspace_root: String,
    /// The resolved dependency graph. Present when `cargo metadata` is run
    /// without `--no-deps`; `None` otherwise.
    resolve: Option<Resolve>,
}

#[derive(Deserialize)]
struct Package {
    name: String,
    version: String,
    id: String,
    manifest_path: String,
    source: Option<String>,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
    #[serde(default)]
    targets: Vec<Target>,
}

#[derive(Deserialize)]
struct Target {
    kind: Vec<String>,
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    src_path: String,
}

/// The resolved dependency graph from `cargo metadata`.
#[derive(Deserialize)]
struct Resolve {
    nodes: Vec<ResolveNode>,
}

/// A single node in the resolved dependency graph.
#[derive(Deserialize)]
struct ResolveNode {
    /// Opaque package ID (matches `Package::id`).
    id: String,
    /// Resolved dependencies with extern crate names and dependency kinds.
    #[serde(default)]
    deps: Vec<NodeDep>,
}

/// A resolved dependency edge — which package this node depends on and how.
#[derive(Deserialize)]
struct NodeDep {
    /// The extern crate name as seen in Rust source (underscored, handles renames).
    name: String,
    /// The package ID of the dependency (matches `Package::id`).
    pkg: String,
    /// Dependency kinds (normal, dev, build).
    #[serde(default)]
    dep_kinds: Vec<DepKindInfo>,
}

/// Metadata about the kind of a dependency edge.
#[derive(Deserialize)]
struct DepKindInfo {
    /// `null` = normal, `"dev"` = dev-dependency, `"build"` = build-dependency.
    kind: Option<String>,
}

/// Extracts `classification` from `package.metadata.capsec.classification` JSON value.
fn extract_classification(metadata: &Option<serde_json::Value>) -> Option<Classification> {
    let capsec = metadata.as_ref()?.get("capsec")?;
    let class_str = capsec.get("classification")?.as_str()?;
    match class_str {
        "pure" => Some(Classification::Pure),
        "resource" => Some(Classification::Resource),
        other => {
            eprintln!(
                "Warning: unknown classification '{other}' in [package.metadata.capsec], ignoring (valid: pure, resource)"
            );
            None
        }
    }
}

/// Normalizes a Cargo package name to its Rust crate name by replacing hyphens
/// with underscores. Cargo allows `serde-json` in `Cargo.toml`, but Rust source
/// always uses `serde_json`.
#[must_use]
pub fn normalize_crate_name(name: &str) -> String {
    name.replace('-', "_")
}

/// Returns true if a package is a proc-macro crate (compile-time code, not runtime).
fn is_proc_macro(pkg: &Package) -> bool {
    pkg.targets
        .iter()
        .any(|t| t.kind.contains(&"proc-macro".to_string()))
}

/// Information about a dependency edge in the resolved graph.
#[derive(Debug, Clone)]
pub struct DepEdge {
    /// Normalized extern crate name (underscored, handles renames).
    #[allow(dead_code)]
    pub extern_name: String,
    /// Package ID of the dependency.
    pub pkg_id: String,
}

/// Produces a topological ordering of package IDs from leaves (no dependencies)
/// to roots (workspace crates). Dev-dependencies are filtered out to avoid cycles.
///
/// Returns `Err` if a cycle is detected (should not happen in a valid Cargo graph
/// with dev-deps removed, but handled gracefully).
pub fn topological_order(resolve: &[(String, Vec<DepEdge>)]) -> Result<Vec<String>, String> {
    let num_nodes = resolve.len();

    // Build index: pkg_id -> index
    let id_to_idx: HashMap<&str, usize> = resolve
        .iter()
        .enumerate()
        .map(|(i, (id, _))| (id.as_str(), i))
        .collect();

    // Build adjacency list and in-degree counts.
    // Edge: node -> dependency (we want leaves first, so edges point from
    // dependents to dependencies).
    let mut in_degree = vec![0usize; num_nodes];
    let mut dependents: Vec<Vec<usize>> = vec![vec![]; num_nodes];

    for (idx, (_id, deps)) in resolve.iter().enumerate() {
        for dep in deps {
            if let Some(&dep_idx) = id_to_idx.get(dep.pkg_id.as_str()) {
                // idx depends on dep_idx.
                // In our topo sort, dep_idx must come before idx.
                // So dep_idx -> idx is a "dependent" edge.
                dependents[dep_idx].push(idx);
                in_degree[idx] += 1;
            }
            // Ignore deps not in the resolve set (e.g., filtered out proc-macros).
        }
    }

    // Kahn's algorithm: start with leaves (in_degree == 0).
    let mut queue: VecDeque<usize> = in_degree
        .iter()
        .enumerate()
        .filter(|&(_, &d)| d == 0)
        .map(|(i, _)| i)
        .collect();

    let mut order = Vec::with_capacity(num_nodes);

    while let Some(node) = queue.pop_front() {
        order.push(resolve[node].0.clone());
        for &dependent in &dependents[node] {
            in_degree[dependent] -= 1;
            if in_degree[dependent] == 0 {
                queue.push_back(dependent);
            }
        }
    }

    if order.len() == num_nodes {
        Ok(order)
    } else {
        Err(format!(
            "Cycle detected in dependency graph ({} of {} nodes processed)",
            order.len(),
            num_nodes
        ))
    }
}

/// Result of extracting the dependency graph: the graph itself and a name lookup map.
pub type DepGraphResult = (Vec<(String, Vec<DepEdge>)>, HashMap<String, String>);

/// Extracts the resolved dependency graph from `CargoMetadata`, filtering out
/// dev-dependencies and optionally proc-macro crates.
///
/// Returns a list of `(package_id, Vec<DepEdge>)` suitable for `topological_order()`.
pub fn extract_dep_graph(
    metadata_json: &[u8],
    exclude_proc_macros: bool,
) -> Result<DepGraphResult, String> {
    let metadata: CargoMetadata = serde_json::from_slice(metadata_json)
        .map_err(|e| format!("Failed to parse cargo metadata: {e}"))?;

    let resolve = metadata
        .resolve
        .ok_or("No resolve field in cargo metadata (was --no-deps used?)")?;

    // Build a set of proc-macro package IDs to exclude.
    let proc_macro_ids: std::collections::HashSet<&str> = if exclude_proc_macros {
        metadata
            .packages
            .iter()
            .filter(|p| is_proc_macro(p))
            .map(|p| p.id.as_str())
            .collect()
    } else {
        std::collections::HashSet::new()
    };

    // Map package ID -> normalized crate name for callers.
    let id_to_name: HashMap<String, String> = metadata
        .packages
        .iter()
        .map(|p| (p.id.clone(), normalize_crate_name(&p.name)))
        .collect();

    let mut graph = Vec::new();

    for node in &resolve.nodes {
        if proc_macro_ids.contains(node.id.as_str()) {
            continue;
        }

        let deps: Vec<DepEdge> = node
            .deps
            .iter()
            .filter(|d| {
                // Exclude dev-dependencies (can create cycles).
                !d.dep_kinds
                    .iter()
                    .all(|dk| dk.kind.as_deref() == Some("dev"))
            })
            .filter(|d| !proc_macro_ids.contains(d.pkg.as_str()))
            .map(|d| DepEdge {
                extern_name: normalize_crate_name(&d.name),
                pkg_id: d.pkg.clone(),
            })
            .collect();

        graph.push((node.id.clone(), deps));
    }

    Ok((graph, id_to_name))
}

/// Returns workspace member package IDs in topological order (leaves first).
///
/// Filters the resolve graph to only workspace-member nodes and edges,
/// then calls `topological_order()`. Crates with no intra-workspace
/// dependencies come first. Returns `None` if topo sort fails.
pub fn workspace_topological_order(
    workspace_crates: &[CrateInfo],
    resolve_graph: &[(String, Vec<DepEdge>)],
) -> Option<Vec<String>> {
    let ws_pkg_ids: std::collections::HashSet<String> = workspace_crates
        .iter()
        .filter_map(|c| c.package_id.clone())
        .collect();

    if ws_pkg_ids.is_empty() {
        return None;
    }

    // Filter resolve graph to workspace-member-only nodes and edges
    let ws_graph: Vec<(String, Vec<DepEdge>)> = resolve_graph
        .iter()
        .filter(|(id, _)| ws_pkg_ids.contains(id))
        .map(|(id, deps)| {
            let ws_deps: Vec<DepEdge> = deps
                .iter()
                .filter(|d| ws_pkg_ids.contains(&d.pkg_id))
                .cloned()
                .collect();
            (id.clone(), ws_deps)
        })
        .collect();

    topological_order(&ws_graph).ok()
}

/// Result of workspace discovery: crates and the resolved workspace root.
pub struct DiscoveryResult {
    /// All discovered crates.
    pub crates: Vec<CrateInfo>,
    /// The Cargo workspace root (from `cargo metadata`).
    pub workspace_root: PathBuf,
    /// Resolved dependency graph (only populated when `include_deps` is true).
    pub resolve_graph: Option<Vec<(String, Vec<DepEdge>)>>,
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
    spawn_cap: &impl capsec_core::cap_provider::CapProvider<capsec_core::permission::Spawn>,
    _fs_cap: &impl capsec_core::cap_provider::CapProvider<capsec_core::permission::FsRead>,
) -> Result<DiscoveryResult, String> {
    // Use --no-deps by default for speed (avoids resolving 300+ transitive deps).
    // Drop it when --include-deps is set so path dependencies and registry crates appear.
    let mut args = vec!["metadata", "--format-version=1"];
    if !include_deps {
        args.push("--no-deps");
    }

    let output = capsec_std::process::command("cargo", spawn_cap)
        .map_err(|e| format!("Failed to create command: {e}"))?
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
                classification: extract_classification(&package.metadata),
                package_id: if include_deps {
                    Some(package.id.clone())
                } else {
                    None
                },
            });
        }
    }

    // Extract the resolve graph when available (for topological ordering)
    let resolve_graph = if include_deps {
        extract_dep_graph(&output.stdout, true)
            .ok()
            .map(|(graph, _)| graph)
    } else {
        None
    };

    Ok(DiscoveryResult {
        crates,
        workspace_root: resolved_root,
        resolve_graph,
    })
}

/// Recursively discovers all `.rs` source files in a directory.
///
/// Skips `target/` and hidden directories. Also checks for `build.rs` at the
/// crate root (the parent of the `src/` directory).
pub fn discover_source_files(
    dir: &Path,
    cap: &impl capsec_core::cap_provider::CapProvider<capsec_core::permission::FsRead>,
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
    cap: &impl capsec_core::cap_provider::CapProvider<capsec_core::permission::FsRead>,
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

    #[test]
    fn normalize_crate_name_replaces_hyphens() {
        assert_eq!(normalize_crate_name("serde-json"), "serde_json");
        assert_eq!(normalize_crate_name("serde_json"), "serde_json");
        assert_eq!(normalize_crate_name("my-cool-crate"), "my_cool_crate");
        assert_eq!(normalize_crate_name("plain"), "plain");
    }

    fn make_graph(edges: &[(&str, &[&str])]) -> Vec<(String, Vec<DepEdge>)> {
        edges
            .iter()
            .map(|(id, deps)| {
                let dep_edges = deps
                    .iter()
                    .map(|d| DepEdge {
                        extern_name: d.to_string(),
                        pkg_id: d.to_string(),
                    })
                    .collect();
                (id.to_string(), dep_edges)
            })
            .collect()
    }

    #[test]
    fn topo_sort_single_node() {
        let graph = make_graph(&[("a", &[])]);
        let order = topological_order(&graph).unwrap();
        assert_eq!(order, vec!["a"]);
    }

    #[test]
    fn topo_sort_linear_chain() {
        // a -> b -> c (a depends on b, b depends on c)
        let graph = make_graph(&[("a", &["b"]), ("b", &["c"]), ("c", &[])]);
        let order = topological_order(&graph).unwrap();
        // c must come before b, b before a
        let pos = |id: &str| order.iter().position(|x| x == id).unwrap();
        assert!(pos("c") < pos("b"));
        assert!(pos("b") < pos("a"));
    }

    #[test]
    fn topo_sort_diamond() {
        //   a
        //  / \
        // b   c
        //  \ /
        //   d
        let graph = make_graph(&[("a", &["b", "c"]), ("b", &["d"]), ("c", &["d"]), ("d", &[])]);
        let order = topological_order(&graph).unwrap();
        let pos = |id: &str| order.iter().position(|x| x == id).unwrap();
        assert!(pos("d") < pos("b"));
        assert!(pos("d") < pos("c"));
        assert!(pos("b") < pos("a"));
        assert!(pos("c") < pos("a"));
    }

    #[test]
    fn topo_sort_cycle_detected() {
        // a -> b -> a (cycle)
        let graph = make_graph(&[("a", &["b"]), ("b", &["a"])]);
        let result = topological_order(&graph);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Cycle detected"));
    }

    #[test]
    fn topo_sort_ignores_unknown_deps() {
        // a depends on "missing" which is not in the graph — should be ignored
        let graph = make_graph(&[("a", &["missing"]), ("b", &[])]);
        let order = topological_order(&graph).unwrap();
        assert_eq!(order.len(), 2);
    }

    #[test]
    fn extract_dep_graph_filters_dev_deps() {
        let metadata_json = serde_json::json!({
            "packages": [
                {
                    "name": "app",
                    "version": "0.1.0",
                    "id": "app 0.1.0",
                    "manifest_path": "/fake/app/Cargo.toml",
                    "source": null,
                    "targets": [{"kind": ["lib"], "name": "app", "src_path": "/fake/app/src/lib.rs"}]
                },
                {
                    "name": "helper",
                    "version": "1.0.0",
                    "id": "helper 1.0.0",
                    "manifest_path": "/fake/helper/Cargo.toml",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                    "targets": [{"kind": ["lib"], "name": "helper", "src_path": "/fake/helper/src/lib.rs"}]
                },
                {
                    "name": "test-util",
                    "version": "0.1.0",
                    "id": "test-util 0.1.0",
                    "manifest_path": "/fake/test-util/Cargo.toml",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                    "targets": [{"kind": ["lib"], "name": "test_util", "src_path": "/fake/test-util/src/lib.rs"}]
                }
            ],
            "workspace_root": "/fake",
            "workspace_members": ["app 0.1.0"],
            "resolve": {
                "nodes": [
                    {
                        "id": "app 0.1.0",
                        "deps": [
                            {
                                "name": "helper",
                                "pkg": "helper 1.0.0",
                                "dep_kinds": [{"kind": null, "target": null}]
                            },
                            {
                                "name": "test_util",
                                "pkg": "test-util 0.1.0",
                                "dep_kinds": [{"kind": "dev", "target": null}]
                            }
                        ]
                    },
                    {
                        "id": "helper 1.0.0",
                        "deps": []
                    },
                    {
                        "id": "test-util 0.1.0",
                        "deps": []
                    }
                ],
                "root": "app 0.1.0"
            }
        });

        let json_bytes = serde_json::to_vec(&metadata_json).unwrap();
        let (graph, id_to_name) = extract_dep_graph(&json_bytes, false).unwrap();

        // app should have only "helper" as a dep (test-util is dev-only)
        let app_node = graph.iter().find(|(id, _)| id == "app 0.1.0").unwrap();
        assert_eq!(app_node.1.len(), 1);
        assert_eq!(app_node.1[0].extern_name, "helper");

        // id_to_name should normalize
        assert_eq!(id_to_name.get("test-util 0.1.0").unwrap(), "test_util");

        // topo sort should work
        let order = topological_order(&graph).unwrap();
        assert_eq!(order.len(), 3);
    }

    #[test]
    fn extract_dep_graph_excludes_proc_macros() {
        let metadata_json = serde_json::json!({
            "packages": [
                {
                    "name": "app",
                    "version": "0.1.0",
                    "id": "app 0.1.0",
                    "manifest_path": "/fake/app/Cargo.toml",
                    "source": null,
                    "targets": [{"kind": ["lib"], "name": "app", "src_path": "/fake/app/src/lib.rs"}]
                },
                {
                    "name": "my-derive",
                    "version": "1.0.0",
                    "id": "my-derive 1.0.0",
                    "manifest_path": "/fake/my-derive/Cargo.toml",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                    "targets": [{"kind": ["proc-macro"], "name": "my_derive", "src_path": "/fake/my-derive/src/lib.rs"}]
                }
            ],
            "workspace_root": "/fake",
            "workspace_members": ["app 0.1.0"],
            "resolve": {
                "nodes": [
                    {
                        "id": "app 0.1.0",
                        "deps": [
                            {
                                "name": "my_derive",
                                "pkg": "my-derive 1.0.0",
                                "dep_kinds": [{"kind": null, "target": null}]
                            }
                        ]
                    },
                    {
                        "id": "my-derive 1.0.0",
                        "deps": []
                    }
                ],
                "root": "app 0.1.0"
            }
        });

        let json_bytes = serde_json::to_vec(&metadata_json).unwrap();
        let (graph, _) = extract_dep_graph(&json_bytes, true).unwrap();

        // my-derive should be excluded as a proc-macro
        assert_eq!(graph.len(), 1); // only "app" remains
        let app_node = &graph[0];
        assert_eq!(app_node.0, "app 0.1.0");
        assert!(app_node.1.is_empty()); // dep on proc-macro filtered out
    }

    #[test]
    fn workspace_topo_order_basic() {
        let ws_crates = vec![
            CrateInfo {
                name: "app".to_string(),
                version: "0.1.0".to_string(),
                source_dir: PathBuf::from("/fake/app/src"),
                is_dependency: false,
                classification: None,
                package_id: Some("app 0.1.0".to_string()),
            },
            CrateInfo {
                name: "core-lib".to_string(),
                version: "0.1.0".to_string(),
                source_dir: PathBuf::from("/fake/core-lib/src"),
                is_dependency: false,
                classification: None,
                package_id: Some("core-lib 0.1.0".to_string()),
            },
        ];
        let graph = vec![
            (
                "app 0.1.0".to_string(),
                vec![DepEdge {
                    extern_name: "core_lib".to_string(),
                    pkg_id: "core-lib 0.1.0".to_string(),
                }],
            ),
            ("core-lib 0.1.0".to_string(), vec![]),
        ];
        let order = workspace_topological_order(&ws_crates, &graph).unwrap();
        let pos = |id: &str| order.iter().position(|x| x == id).unwrap();
        assert!(
            pos("core-lib 0.1.0") < pos("app 0.1.0"),
            "core-lib should come before app"
        );
    }

    #[test]
    fn workspace_topo_order_independent() {
        let ws_crates = vec![
            CrateInfo {
                name: "a".to_string(),
                version: "0.1.0".to_string(),
                source_dir: PathBuf::from("/fake/a/src"),
                is_dependency: false,
                classification: None,
                package_id: Some("a 0.1.0".to_string()),
            },
            CrateInfo {
                name: "b".to_string(),
                version: "0.1.0".to_string(),
                source_dir: PathBuf::from("/fake/b/src"),
                is_dependency: false,
                classification: None,
                package_id: Some("b 0.1.0".to_string()),
            },
        ];
        let graph = vec![
            ("a 0.1.0".to_string(), vec![]),
            ("b 0.1.0".to_string(), vec![]),
        ];
        let order = workspace_topological_order(&ws_crates, &graph).unwrap();
        assert_eq!(order.len(), 2);
    }
}
