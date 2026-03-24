//! Deep MIR analysis integration.
//!
//! Invokes `capsec-driver` as `RUSTC_WRAPPER` to analyze all crates via MIR,
//! then reads findings from JSONL and builds export maps for cross-crate propagation.

use crate::detector::Finding;
use crate::discovery::{self, CrateInfo};
use crate::export_map::{self, CrateExportMap};
use std::collections::HashMap;
use std::path::Path;

/// Pinned nightly date for capsec-driver. Must match `crates/capsec-deep/rust-toolchain.toml`.
const PINNED_NIGHTLY: &str = "nightly-2026-02-17";

/// Result of running deep MIR analysis.
pub struct DeepResult {
    /// Findings from the MIR driver, with crate names/versions patched to match Cargo metadata.
    pub findings: Vec<Finding>,
    /// Export maps built from MIR findings, ready to inject into Phase 2.
    pub export_maps: Vec<CrateExportMap>,
    /// Warnings encountered during analysis (driver missing, parse errors, etc.).
    pub warnings: Vec<String>,
}

/// Runs the MIR-based deep analysis driver on the target project.
///
/// Invokes `capsec-driver` via `RUSTC_WRAPPER` + `cargo check`, reads JSONL
/// findings, patches crate names/versions, and builds export maps.
///
/// Returns an empty `DeepResult` if the driver is not available or fails.
/// Warnings are collected in `DeepResult::warnings` rather than printed directly.
pub fn run_deep_analysis(
    path: &Path,
    workspace_root: &Path,
    workspace_crates: &[CrateInfo],
    dep_crates: &[CrateInfo],
    fs_read: &impl capsec_core::cap_provider::CapProvider<capsec_core::permission::FsRead>,
    spawn_cap: &impl capsec_core::cap_provider::CapProvider<capsec_core::permission::Spawn>,
) -> DeepResult {
    let mut warnings: Vec<String> = Vec::new();
    let output_path =
        std::env::temp_dir().join(format!("capsec-deep-{}.jsonl", std::process::id()));

    // Check if capsec-driver is available by trying to run it
    let driver_available = capsec_std::process::command("capsec-driver", spawn_cap)
        .ok()
        .and_then(|mut cmd| cmd.arg("--version").output().ok())
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !driver_available {
        warnings.push(
            "--deep requires capsec-driver. Install with: cd crates/capsec-deep && cargo install --path .".to_string()
        );
        return DeepResult {
            findings: Vec::new(),
            export_maps: Vec::new(),
            warnings,
        };
    }

    let deep_target_dir = workspace_root.join("target/capsec-deep");
    let toolchain = detect_nightly_toolchain(spawn_cap);

    // Clean to force full rebuild (incremental cache prevents driver from running)
    let _ = std::fs::remove_dir_all(&deep_target_dir);

    let deep_result = capsec_std::process::command("cargo", spawn_cap)
        .ok()
        .and_then(|mut cmd| {
            cmd.arg("check")
                .current_dir(path)
                .env("RUSTC_WRAPPER", "capsec-driver")
                .env("CAPSEC_DEEP_OUTPUT", &output_path)
                .env("CAPSEC_CRATE_VERSION", "0.0.0")
                .env("CARGO_TARGET_DIR", &deep_target_dir)
                .env("RUSTUP_TOOLCHAIN", toolchain)
                .output()
                .ok()
        });

    // Build name/version lookup for patching MIR findings
    let crate_lookup: HashMap<String, (String, String)> = workspace_crates
        .iter()
        .chain(dep_crates.iter())
        .map(|c| {
            (
                discovery::normalize_crate_name(&c.name),
                (c.name.clone(), c.version.clone()),
            )
        })
        .collect();

    let mir_findings = match deep_result {
        Some(output) if output.status.success() || output_path.exists() => {
            let findings =
                parse_findings_jsonl(&output_path, &crate_lookup, fs_read, &mut warnings);
            let _ = std::fs::remove_file(&output_path);
            findings
        }
        Some(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let mut msg = "Deep analysis failed (cargo check returned non-zero).".to_string();
            for line in stderr
                .lines()
                .filter(|l| l.contains("error") || l.contains("Error"))
                .take(5)
            {
                msg.push_str(&format!("\n  {line}"));
            }
            if stderr.contains("incompatible version of rustc") {
                msg.push_str("\n  Hint: try `rm -rf target/capsec-deep` to clear stale artifacts.");
            }
            warnings.push(msg);
            Vec::new()
        }
        None => {
            warnings.push("Could not invoke cargo check for deep analysis.".to_string());
            Vec::new()
        }
    };

    // Build export maps from MIR findings
    let export_maps = build_mir_export_maps(&mir_findings, workspace_crates, dep_crates);

    DeepResult {
        findings: mir_findings,
        export_maps,
        warnings,
    }
}

/// Parses JSONL findings from the MIR driver output file.
/// Patches crate names (rustc → Cargo) and versions (0.0.0 → real) using the lookup.
fn parse_findings_jsonl(
    output_path: &Path,
    crate_lookup: &HashMap<String, (String, String)>,
    fs_read: &impl capsec_core::cap_provider::CapProvider<capsec_core::permission::FsRead>,
    warnings: &mut Vec<String>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(contents) = capsec_std::fs::read_to_string(output_path, fs_read) else {
        return findings;
    };
    for line in contents.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Finding>(line) {
            Ok(mut finding) => {
                let normalized = discovery::normalize_crate_name(&finding.crate_name);
                if let Some((cargo_name, ver)) = crate_lookup.get(&normalized) {
                    finding.crate_name = cargo_name.clone();
                    if finding.crate_version == "0.0.0" {
                        finding.crate_version = ver.clone();
                    }
                }
                findings.push(finding);
            }
            Err(e) => {
                warnings.push(format!("Failed to parse deep finding: {e}"));
            }
        }
    }
    findings
}

/// Builds export maps from MIR findings, grouped by crate.
fn build_mir_export_maps(
    findings: &[Finding],
    workspace_crates: &[CrateInfo],
    dep_crates: &[CrateInfo],
) -> Vec<CrateExportMap> {
    if findings.is_empty() {
        return Vec::new();
    }

    // Group findings by crate name
    let mut by_crate: HashMap<String, Vec<&Finding>> = HashMap::new();
    for f in findings {
        by_crate.entry(f.crate_name.clone()).or_default().push(f);
    }

    let all_crates: Vec<&CrateInfo> = dep_crates.iter().chain(workspace_crates.iter()).collect();

    let mut export_maps = Vec::new();
    for (crate_name, crate_findings) in &by_crate {
        let normalized = discovery::normalize_crate_name(crate_name);
        let src_dir = all_crates
            .iter()
            .find(|c| discovery::normalize_crate_name(&c.name) == normalized)
            .map(|c| &c.source_dir);

        let Some(src_dir) = src_dir else {
            eprintln!(
                "Warning: MIR findings for unknown crate '{crate_name}', skipping export map"
            );
            continue;
        };

        // Collect owned findings for build_export_map (which takes &[Finding])
        let owned: Vec<Finding> = crate_findings.iter().map(|f| (*f).clone()).collect();
        let mir_emap =
            export_map::build_export_map(&normalized, &owned[0].crate_version, &owned, src_dir);
        export_maps.push(mir_emap);
    }
    export_maps
}

/// Detects the nightly toolchain to use for the MIR driver.
fn detect_nightly_toolchain(
    spawn_cap: &impl capsec_core::cap_provider::CapProvider<capsec_core::permission::Spawn>,
) -> &'static str {
    let has_pinned = capsec_std::process::command("rustup", spawn_cap)
        .ok()
        .and_then(|mut cmd| {
            cmd.arg("run")
                .arg(PINNED_NIGHTLY)
                .arg("rustc")
                .arg("--version")
                .output()
                .ok()
        })
        .map(|o| o.status.success())
        .unwrap_or(false);
    if has_pinned {
        PINNED_NIGHTLY
    } else {
        "nightly"
    }
}
