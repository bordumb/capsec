//! Dependency version diffing and cross-crate comparison.
//!
//! `cargo capsec diff crate@v1 crate@v2` — what new authority did a version bump introduce?
//! `cargo capsec compare crate_a crate_b` — which crate has less ambient authority?

use crate::authorities::Category;
use crate::config::Config;
use crate::detector::Finding;
use crate::scanner;
use colored::Colorize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

// ── Types ──

/// Result of diffing findings between two crate versions.
pub struct DiffResult {
    pub added: Vec<Finding>,
    pub removed: Vec<Finding>,
    pub unchanged: usize,
}

/// Parsed crate specifier: name@version.
pub struct CrateSpec {
    pub name: String,
    pub version: String,
}

/// Options for `cargo capsec diff`.
pub struct DiffOptions {
    pub left: String,
    pub right: String,
    pub format: String,
    pub fail_on_new: bool,
}

/// Options for `cargo capsec compare`.
pub struct CompareOptions {
    pub left: String,
    pub right: String,
    pub format: String,
}

// ── Public entry points ──

/// Runs `cargo capsec diff crate@v1 crate@v2`.
pub fn run_diff(opts: DiffOptions) {
    let cap_root = capsec_core::root::root();
    let fs_read = cap_root.grant::<capsec_core::permission::FsRead>();
    let spawn_cap = cap_root.grant::<capsec_core::permission::Spawn>();

    let left = parse_crate_spec(&opts.left).unwrap_or_else(|e| {
        eprintln!("Error: {e}");
        std::process::exit(1);
    });
    let right = parse_crate_spec(&opts.right).unwrap_or_else(|e| {
        eprintln!("Error: {e}");
        std::process::exit(1);
    });

    eprintln!("Fetching {} v{}...", left.name, left.version);
    let left_dir = fetch_crate_source(&left.name, &left.version, &spawn_cap, &fs_read)
        .unwrap_or_else(|e| {
            eprintln!("Error fetching {} v{}: {e}", left.name, left.version);
            std::process::exit(1);
        });

    eprintln!("Fetching {} v{}...", right.name, right.version);
    let right_dir = fetch_crate_source(&right.name, &right.version, &spawn_cap, &fs_read)
        .unwrap_or_else(|e| {
            eprintln!("Error fetching {} v{}: {e}", right.name, right.version);
            std::process::exit(1);
        });

    eprintln!("Scanning...");
    let config = Config::default();
    let left_findings =
        scanner::scan_crate(&left_dir, &left.name, &left.version, &config, &fs_read);
    let right_findings =
        scanner::scan_crate(&right_dir, &right.name, &right.version, &config, &fs_read);

    let result = diff_findings(&left_findings, &right_findings);

    match opts.format.as_str() {
        "json" => print_diff_json(&left, &right, &result),
        _ => print_diff_text(&left, &right, &result),
    }

    if opts.fail_on_new && !result.added.is_empty() {
        std::process::exit(1);
    }
}

/// Runs `cargo capsec compare crate_a crate_b`.
pub fn run_compare(opts: CompareOptions) {
    let cap_root = capsec_core::root::root();
    let fs_read = cap_root.grant::<capsec_core::permission::FsRead>();
    let spawn_cap = cap_root.grant::<capsec_core::permission::Spawn>();

    let mut left = parse_crate_spec_or_latest(&opts.left);
    let mut right = parse_crate_spec_or_latest(&opts.right);

    eprintln!("Fetching {}...", left.name);
    let left_dir = fetch_crate_source(&left.name, &left.version, &spawn_cap, &fs_read)
        .unwrap_or_else(|e| {
            eprintln!("Error: {e}");
            std::process::exit(1);
        });
    resolve_version_from_path(&mut left, &left_dir);

    eprintln!("Fetching {}...", right.name);
    let right_dir = fetch_crate_source(&right.name, &right.version, &spawn_cap, &fs_read)
        .unwrap_or_else(|e| {
            eprintln!("Error: {e}");
            std::process::exit(1);
        });
    resolve_version_from_path(&mut right, &right_dir);

    eprintln!("Scanning...\n");
    let config = Config::default();
    let left_findings =
        scanner::scan_crate(&left_dir, &left.name, &left.version, &config, &fs_read);
    let right_findings =
        scanner::scan_crate(&right_dir, &right.name, &right.version, &config, &fs_read);

    match opts.format.as_str() {
        "json" => print_compare_json(&left, &right, &left_findings, &right_findings),
        _ => print_compare_text(&left, &right, &left_findings, &right_findings),
    }
}

// ── Registry source fetcher ──

/// Fetches the source directory for a crate@version.
/// Checks ~/.cargo/registry/src/ first, falls back to `cargo fetch` with a temp manifest.
fn fetch_crate_source(
    crate_name: &str,
    version: &str,
    spawn_cap: &impl capsec_core::cap_provider::CapProvider<capsec_core::permission::Spawn>,
    _fs_read: &impl capsec_core::cap_provider::CapProvider<capsec_core::permission::FsRead>,
) -> Result<PathBuf, String> {
    // Check registry cache first
    if let Some(cached) = find_registry_source(crate_name, version) {
        return Ok(cached);
    }

    // Not cached — create a temp project and cargo fetch
    let temp_dir = std::env::temp_dir().join(format!("capsec-fetch-{crate_name}-{version}"));
    let _ = std::fs::create_dir_all(&temp_dir);

    let version_spec = if version == "*" {
        format!("\"{version}\"")
    } else {
        format!("\"={version}\"")
    };
    let cargo_toml = format!(
        "[package]\nname = \"capsec-fetch-temp\"\nversion = \"0.0.1\"\nedition = \"2021\"\n\n[dependencies]\n{crate_name} = {version_spec}\n"
    );
    std::fs::write(temp_dir.join("Cargo.toml"), cargo_toml)
        .map_err(|e| format!("Failed to write temp Cargo.toml: {e}"))?;

    // Create a dummy src/lib.rs so cargo doesn't complain
    let _ = std::fs::create_dir_all(temp_dir.join("src"));
    std::fs::write(temp_dir.join("src/lib.rs"), "")
        .map_err(|e| format!("Failed to write temp lib.rs: {e}"))?;

    // Run cargo fetch to download the crate
    let output = capsec_std::process::command("cargo", spawn_cap)
        .map_err(|e| format!("Failed to create command: {e}"))?
        .arg("fetch")
        .current_dir(&temp_dir)
        .output()
        .map_err(|e| format!("Failed to run cargo fetch: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("cargo fetch failed: {stderr}"));
    }

    // Clean up temp dir
    let _ = std::fs::remove_dir_all(&temp_dir);

    // Now it should be in the registry cache
    find_registry_source(crate_name, version).ok_or_else(|| {
        format!("Crate {crate_name}@{version} not found in registry cache after fetch")
    })
}

/// Looks for a crate's source in ~/.cargo/registry/src/.
/// When version is "*", finds the latest version available in the cache.
fn find_registry_source(crate_name: &str, version: &str) -> Option<PathBuf> {
    let home = std::env::var("CARGO_HOME").unwrap_or_else(|_| {
        std::env::var("HOME")
            .map(|h| format!("{h}/.cargo"))
            .unwrap_or_default()
    });
    let registry_src = Path::new(&home).join("registry/src");

    if !registry_src.exists() {
        return None;
    }

    let entries = std::fs::read_dir(&registry_src).ok()?;
    for index_dir in entries.flatten() {
        if version == "*" {
            // Find any version of this crate — pick the latest by name sort
            let prefix = format!("{crate_name}-");
            if let Ok(crate_dirs) = std::fs::read_dir(index_dir.path()) {
                let mut matches: Vec<_> = crate_dirs
                    .flatten()
                    .filter(|e| {
                        e.file_name()
                            .to_str()
                            .is_some_and(|n| n.starts_with(&prefix))
                    })
                    .collect();
                matches.sort_by_key(|b| std::cmp::Reverse(b.file_name()));
                if let Some(best) = matches.first() {
                    let src_dir = best.path().join("src");
                    if src_dir.exists() {
                        return Some(src_dir);
                    }
                    return Some(best.path());
                }
            }
        } else {
            let crate_dir = index_dir.path().join(format!("{crate_name}-{version}"));
            if crate_dir.exists() {
                let src_dir = crate_dir.join("src");
                if src_dir.exists() {
                    return Some(src_dir);
                }
                return Some(crate_dir);
            }
        }
    }

    None
}

// ── Diff engine ──

/// Compares findings between two versions of a crate.
/// Matches by (function, call_text, category) — NOT by line number.
fn diff_findings(old: &[Finding], new: &[Finding]) -> DiffResult {
    type Key = (String, String, String);

    fn finding_key(f: &Finding) -> Key {
        (
            f.function.clone(),
            f.call_text.clone(),
            f.category.label().to_string(),
        )
    }

    let old_keys: HashSet<Key> = old.iter().map(finding_key).collect();
    let new_keys: HashSet<Key> = new.iter().map(finding_key).collect();

    let added: Vec<Finding> = new
        .iter()
        .filter(|f| !old_keys.contains(&finding_key(f)))
        .cloned()
        .collect();

    let removed: Vec<Finding> = old
        .iter()
        .filter(|f| !new_keys.contains(&finding_key(f)))
        .cloned()
        .collect();

    let unchanged = new_keys.intersection(&old_keys).count();

    DiffResult {
        added,
        removed,
        unchanged,
    }
}

// ── Parsers ──

/// If version is "*", resolves it from the fetched directory path.
/// e.g., path `.cargo/registry/src/.../ureq-2.12.1/src` → version "2.12.1"
fn resolve_version_from_path(spec: &mut CrateSpec, dir: &Path) {
    if spec.version != "*" {
        return;
    }
    // Walk up from src/ to the crate dir: ureq-2.12.1
    let crate_dir = if dir.ends_with("src") {
        dir.parent()
    } else {
        Some(dir)
    };
    if let Some(dir_name) = crate_dir
        .and_then(|d| d.file_name())
        .and_then(|n| n.to_str())
    {
        let prefix = format!("{}-", spec.name);
        if let Some(ver) = dir_name.strip_prefix(&prefix) {
            spec.version = ver.to_string();
        }
    }
}

/// Parses "serde_json@1.0.133" into CrateSpec.
fn parse_crate_spec(spec: &str) -> Result<CrateSpec, String> {
    let parts: Vec<&str> = spec.splitn(2, '@').collect();
    if parts.len() != 2 || parts[1].is_empty() {
        return Err(format!(
            "Invalid crate specifier '{spec}'. Expected format: crate_name@version"
        ));
    }
    Ok(CrateSpec {
        name: parts[0].to_string(),
        version: parts[1].to_string(),
    })
}

/// Parses "serde_json@1.0.133" or just "serde_json" (uses "latest" placeholder).
fn parse_crate_spec_or_latest(spec: &str) -> CrateSpec {
    if let Ok(parsed) = parse_crate_spec(spec) {
        parsed
    } else {
        // No version specified — use a wildcard that cargo fetch will resolve
        CrateSpec {
            name: spec.to_string(),
            version: "*".to_string(),
        }
    }
}

// ── Output formatters ──

fn print_diff_text(left: &CrateSpec, right: &CrateSpec, result: &DiffResult) {
    println!(
        "\n{} {} \u{2192} {}",
        left.name.bold(),
        left.version.dimmed(),
        right.version.bold()
    );
    let sep_len = left.name.len() + left.version.len() + right.version.len() + 4;
    println!("{}", "\u{2500}".repeat(sep_len));

    for f in &result.added {
        println!(
            "  {} {:<5} {}:{}:{}  {:<28} {}()",
            "+".green().bold(),
            colorize_category(&f.category),
            f.file.dimmed(),
            f.call_line,
            f.call_col,
            f.call_text.bold(),
            f.function,
        );
    }
    for f in &result.removed {
        println!(
            "  {} {:<5} {}:{}:{}  {:<28} {}()",
            "-".red().bold(),
            colorize_category(&f.category),
            f.file.dimmed(),
            f.call_line,
            f.call_col,
            f.call_text.bold(),
            f.function,
        );
    }

    println!(
        "\n{}: {} added, {} removed, {} unchanged",
        "Summary".bold(),
        result.added.len(),
        result.removed.len(),
        result.unchanged,
    );
}

fn print_diff_json(left: &CrateSpec, right: &CrateSpec, result: &DiffResult) {
    let json = serde_json::json!({
        "left": { "name": left.name, "version": left.version },
        "right": { "name": right.name, "version": right.version },
        "added": result.added.len(),
        "removed": result.removed.len(),
        "unchanged": result.unchanged,
        "findings_added": result.added,
        "findings_removed": result.removed,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&json).unwrap_or_default()
    );
}

fn print_compare_text(
    left: &CrateSpec,
    right: &CrateSpec,
    left_findings: &[Finding],
    right_findings: &[Finding],
) {
    fn count_by_cat(findings: &[Finding]) -> (usize, usize, usize, usize, usize) {
        let mut fs = 0;
        let mut net = 0;
        let mut env = 0;
        let mut proc_ = 0;
        let mut ffi = 0;
        for f in findings {
            match f.category {
                Category::Fs => fs += 1,
                Category::Net => net += 1,
                Category::Env => env += 1,
                Category::Process => proc_ += 1,
                Category::Ffi => ffi += 1,
            }
        }
        (fs, net, env, proc_, ffi)
    }

    let (lfs, lnet, lenv, lproc, lffi) = count_by_cat(left_findings);
    let (rfs, rnet, renv, rproc, rffi) = count_by_cat(right_findings);

    let left_header = format!("{} v{}", left.name, left.version);
    let right_header = format!("{} v{}", right.name, right.version);

    println!("\n{:<30} {}", left_header.bold(), right_header.bold());
    println!(
        "{:<30} {}",
        "\u{2500}".repeat(left_header.len()),
        "\u{2500}".repeat(right_header.len())
    );
    println!(
        "{:<30} {}",
        format!("FS:   {lfs}").blue(),
        format!("FS:   {rfs}").blue()
    );
    println!(
        "{:<30} {}",
        format!("NET:  {lnet}").red(),
        format!("NET:  {rnet}").red()
    );
    println!(
        "{:<30} {}",
        format!("ENV:  {lenv}").yellow(),
        format!("ENV:  {renv}").yellow()
    );
    println!(
        "{:<30} {}",
        format!("PROC: {lproc}").magenta(),
        format!("PROC: {rproc}").magenta()
    );
    println!(
        "{:<30} {}",
        format!("FFI:  {lffi}").cyan(),
        format!("FFI:  {rffi}").cyan()
    );
    println!(
        "{:<30} {}",
        format!("Total: {}", left_findings.len()).bold(),
        format!("Total: {}", right_findings.len()).bold()
    );
}

fn print_compare_json(
    left: &CrateSpec,
    right: &CrateSpec,
    left_findings: &[Finding],
    right_findings: &[Finding],
) {
    let json = serde_json::json!({
        "left": {
            "name": left.name,
            "version": left.version,
            "total": left_findings.len(),
            "findings": left_findings,
        },
        "right": {
            "name": right.name,
            "version": right.version,
            "total": right_findings.len(),
            "findings": right_findings,
        },
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&json).unwrap_or_default()
    );
}

fn colorize_category(cat: &Category) -> colored::ColoredString {
    let label = cat.label();
    match cat {
        Category::Fs => label.blue(),
        Category::Net => label.red(),
        Category::Env => label.yellow(),
        Category::Process => label.magenta(),
        Category::Ffi => label.cyan(),
    }
}
