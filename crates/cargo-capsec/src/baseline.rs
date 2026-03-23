//! Baseline diffing — track capability changes across runs.
//!
//! The baseline system enables incremental adoption in CI. On the first run,
//! `--baseline` saves all findings to `.capsec-baseline.json`. On subsequent runs,
//! `--diff` compares current findings against the saved baseline and reports only
//! what's new or removed.
//!
//! This lets teams adopt `cargo capsec audit` on existing projects without fixing
//! every finding upfront — `--diff --fail-on high` only fails on *new* high-risk
//! findings introduced by a PR.

use crate::detector::Finding;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

const BASELINE_FILE: &str = ".capsec-baseline.json";

/// A single entry in the saved baseline file.
///
/// Baseline entries are compared by value equality — if a finding's crate, function,
/// call text, and category all match, it's considered the same finding across runs.
/// This means code movement (same call, different line) won't trigger a diff.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BaselineEntry {
    /// Name of the crate containing the finding.
    pub crate_name: String,
    /// Version of the crate.
    pub crate_version: String,
    /// Source file path.
    pub file: String,
    /// Function name containing the call.
    pub function: String,
    /// The expanded call path (e.g., `"std::fs::read"`).
    pub call_text: String,
    /// Category label (e.g., `"FS"`, `"NET"`).
    pub category: String,
}

impl PartialEq for BaselineEntry {
    fn eq(&self, other: &Self) -> bool {
        self.crate_name == other.crate_name
            && self.file == other.file
            && self.function == other.function
            && self.call_text == other.call_text
            && self.category == other.category
    }
}

impl Eq for BaselineEntry {}

impl std::hash::Hash for BaselineEntry {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.crate_name.hash(state);
        self.file.hash(state);
        self.function.hash(state);
        self.call_text.hash(state);
        self.category.hash(state);
    }
}

impl From<&Finding> for BaselineEntry {
    fn from(f: &Finding) -> Self {
        Self {
            crate_name: f.crate_name.clone(),
            crate_version: f.crate_version.clone(),
            file: f.file.clone(),
            function: f.function.clone(),
            call_text: f.call_text.clone(),
            category: f.category.label().to_string(),
        }
    }
}

/// The result of comparing current findings against a saved baseline.
pub struct DiffResult {
    /// Findings that exist now but weren't in the baseline (newly introduced).
    pub new_findings: Vec<BaselineEntry>,
    /// Findings that were in the baseline but no longer exist (resolved or removed).
    pub removed_findings: Vec<BaselineEntry>,
    /// Number of findings present in both current and baseline.
    pub unchanged_count: usize,
}

/// Loads a previously saved baseline from `.capsec-baseline.json` in the workspace root.
///
/// Returns `None` if the file doesn't exist or can't be parsed.
pub fn load_baseline(
    workspace_root: &Path,
    cap: &impl capsec_core::cap_provider::CapProvider<capsec_core::permission::FsRead>,
) -> Option<HashSet<BaselineEntry>> {
    let path = workspace_root.join(BASELINE_FILE);
    let data = capsec_std::fs::read_to_string(path, cap).ok()?;
    serde_json::from_str(&data).ok()
}

/// Saves current findings as the new baseline to `.capsec-baseline.json`.
pub fn save_baseline(
    workspace_root: &Path,
    findings: &[Finding],
    cap: &impl capsec_core::cap_provider::CapProvider<capsec_core::permission::FsWrite>,
) -> Result<(), String> {
    let entries: Vec<BaselineEntry> = findings.iter().map(BaselineEntry::from).collect();
    let json = serde_json::to_string_pretty(&entries)
        .map_err(|e| format!("Failed to serialize baseline: {e}"))?;
    capsec_std::fs::write(workspace_root.join(BASELINE_FILE), json, cap)
        .map_err(|e| format!("Failed to write baseline: {e}"))
}

/// Computes the difference between current findings and a saved baseline.
///
/// Returns which findings are new, which were removed, and how many are unchanged.
pub fn diff(current: &[Finding], baseline: &HashSet<BaselineEntry>) -> DiffResult {
    let current_set: HashSet<BaselineEntry> = current.iter().map(BaselineEntry::from).collect();

    let new_findings: Vec<BaselineEntry> = current_set.difference(baseline).cloned().collect();
    let removed_findings: Vec<BaselineEntry> = baseline.difference(&current_set).cloned().collect();
    let unchanged_count = current_set.intersection(baseline).count();

    DiffResult {
        new_findings,
        removed_findings,
        unchanged_count,
    }
}

/// Prints a human-readable diff summary to stderr.
pub fn print_diff(diff_result: &DiffResult) {
    if !diff_result.new_findings.is_empty() {
        eprintln!(
            "\n{} new finding(s) since last baseline:",
            diff_result.new_findings.len()
        );
        for entry in &diff_result.new_findings {
            eprintln!(
                "  + [{}] {}::{} — {}",
                entry.category, entry.crate_name, entry.function, entry.call_text
            );
        }
    }
    if !diff_result.removed_findings.is_empty() {
        eprintln!(
            "\n{} finding(s) removed since last baseline:",
            diff_result.removed_findings.len()
        );
        for entry in &diff_result.removed_findings {
            eprintln!(
                "  - [{}] {}::{} — {}",
                entry.category, entry.crate_name, entry.function, entry.call_text
            );
        }
    }
    eprintln!("\n{} finding(s) unchanged.", diff_result.unchanged_count);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorities::{Category, Risk};

    fn make_finding(call: &str, category: Category) -> Finding {
        Finding {
            file: "src/lib.rs".to_string(),
            function: "test".to_string(),
            function_line: 1,
            call_line: 2,
            call_col: 5,
            call_text: call.to_string(),
            category,
            subcategory: "test".to_string(),
            risk: Risk::Medium,
            description: "test".to_string(),
            is_build_script: false,
            crate_name: "test-crate".to_string(),
            crate_version: "0.1.0".to_string(),
            is_deny_violation: false,
            is_transitive: false,
        }
    }

    #[test]
    fn diff_detects_new_findings() {
        let baseline: HashSet<BaselineEntry> = HashSet::new();
        let current = vec![make_finding("std::fs::read", Category::Fs)];
        let result = diff(&current, &baseline);
        assert_eq!(result.new_findings.len(), 1);
        assert_eq!(result.removed_findings.len(), 0);
        assert_eq!(result.unchanged_count, 0);
    }

    #[test]
    fn diff_detects_removed_findings() {
        let entry = BaselineEntry {
            crate_name: "old-crate".to_string(),
            crate_version: "0.1.0".to_string(),
            file: "src/lib.rs".to_string(),
            function: "old_func".to_string(),
            call_text: "std::net::TcpStream::connect".to_string(),
            category: "NET".to_string(),
        };
        let baseline: HashSet<BaselineEntry> = [entry].into_iter().collect();
        let result = diff(&[], &baseline);
        assert_eq!(result.removed_findings.len(), 1);
        assert_eq!(result.new_findings.len(), 0);
    }

    #[test]
    fn version_bump_does_not_cause_spurious_diff() {
        let mut finding_v1 = make_finding("std::fs::read", Category::Fs);
        finding_v1.crate_version = "0.1.0".to_string();
        let baseline: HashSet<BaselineEntry> =
            [BaselineEntry::from(&finding_v1)].into_iter().collect();

        let mut finding_v2 = make_finding("std::fs::read", Category::Fs);
        finding_v2.crate_version = "0.2.0".to_string();
        let result = diff(&[finding_v2], &baseline);

        assert_eq!(
            result.new_findings.len(),
            0,
            "version bump should not create new findings"
        );
        assert_eq!(
            result.removed_findings.len(),
            0,
            "version bump should not remove findings"
        );
        assert_eq!(result.unchanged_count, 1);
    }

    #[test]
    fn diff_detects_unchanged() {
        let finding = make_finding("std::fs::read", Category::Fs);
        let baseline: HashSet<BaselineEntry> =
            [BaselineEntry::from(&finding)].into_iter().collect();
        let result = diff(&[finding], &baseline);
        assert_eq!(result.unchanged_count, 1);
        assert_eq!(result.new_findings.len(), 0);
        assert_eq!(result.removed_findings.len(), 0);
    }
}
