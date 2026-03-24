//! Standalone crate scanner — scans a single crate's source and returns raw findings.
//!
//! This is the shared scan logic used by `audit`, `check-deny`, `badge`, `init`, and `diff`.

use crate::config::{self, Config};
use crate::detector::{self, Finding};
use crate::{discovery, parser};
use std::path::Path;

/// Scans a single crate's source directory and returns raw findings.
///
/// No path normalization, no filtering, no reporting — just raw findings.
/// The caller decides what to do with them.
pub fn scan_crate(
    source_dir: &Path,
    crate_name: &str,
    crate_version: &str,
    config: &Config,
    fs_read: &impl capsec_core::cap_provider::CapProvider<capsec_core::permission::FsRead>,
) -> Vec<Finding> {
    let mut det = detector::Detector::new();
    let customs = config::custom_authorities(config);
    det.add_custom_authorities(&customs);
    let crate_deny = config.deny.normalized_categories();

    let source_files = discovery::discover_source_files(source_dir, fs_read);
    let mut findings = Vec::new();

    for file_path in source_files {
        if config::should_exclude(&file_path, &config.analysis.exclude) {
            continue;
        }

        match parser::parse_file(&file_path, fs_read) {
            Ok(parsed) => {
                let file_findings = det.analyse(&parsed, crate_name, crate_version, &crate_deny);
                findings.extend(file_findings);
            }
            Err(_) => {
                // Silently skip unparseable files
            }
        }
    }

    findings
}
