//! Output formatters — text, JSON, and SARIF.
//!
//! Three output modes, each targeting a different workflow:
//!
//! - **Text** ([`report_text`]) — color-coded terminal output grouped by crate, for humans.
//! - **JSON** ([`report_json`]) — structured output for scripts and CI pipelines.
//! - **SARIF** ([`report_sarif`]) — [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
//!   for GitHub Code Scanning and other SARIF-compatible tools.

use crate::authorities::{Category, Risk};
use crate::detector::Finding;
use colored::Colorize;
use serde::Serialize;
use std::collections::BTreeMap;

/// Prints findings to stdout as color-coded text grouped by crate.
///
/// Includes a summary with counts by category and risk level. Prints a green
/// "OK" message when no findings are present.
pub fn report_text(findings: &[Finding]) {
    let by_crate = group_by_crate(findings);

    if by_crate.is_empty() {
        println!("\n{}  No ambient authority detected.", "OK".green().bold());
        return;
    }

    for (crate_key, crate_findings) in &by_crate {
        println!();
        println!("{}", crate_key.bold());
        println!("{}", "─".repeat(crate_key.len()));

        for f in crate_findings {
            let colored_cat = colorize_category(&f.category);
            println!(
                "  {:<5} {}:{}:{}  {:<28} {}()",
                colored_cat,
                f.file.dimmed(),
                f.call_line,
                f.call_col,
                f.call_text.bold(),
                f.function,
            );
        }
    }

    print_summary(findings, &by_crate);
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

fn print_summary(findings: &[Finding], by_crate: &BTreeMap<String, Vec<&Finding>>) {
    let fs_count = findings
        .iter()
        .filter(|f| f.category == Category::Fs)
        .count();
    let net_count = findings
        .iter()
        .filter(|f| f.category == Category::Net)
        .count();
    let env_count = findings
        .iter()
        .filter(|f| f.category == Category::Env)
        .count();
    let proc_count = findings
        .iter()
        .filter(|f| f.category == Category::Process)
        .count();
    let ffi_count = findings
        .iter()
        .filter(|f| f.category == Category::Ffi)
        .count();

    println!();
    println!("{}", "Summary".bold());
    println!("───────");
    println!("  Crates with findings: {}", by_crate.len());
    println!("  Total findings:       {}", findings.len());
    println!(
        "  Categories:           {} {} {} {} {}",
        format!("FS: {fs_count}").blue(),
        format!("NET: {net_count}").red(),
        format!("ENV: {env_count}").yellow(),
        format!("PROC: {proc_count}").magenta(),
        format!("FFI: {ffi_count}").cyan(),
    );

    let critical = findings.iter().filter(|f| f.risk >= Risk::Critical).count();
    let high = findings.iter().filter(|f| f.risk == Risk::High).count();

    if critical > 0 {
        println!(
            "  {} critical-risk findings",
            format!("{critical}").red().bold()
        );
    }
    if high > 0 {
        println!("  {} high-risk findings", format!("{high}").yellow().bold());
    }
}

fn group_by_crate(findings: &[Finding]) -> BTreeMap<String, Vec<&Finding>> {
    let mut by_crate: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        let key = format!("{} v{}", f.crate_name, f.crate_version);
        by_crate.entry(key).or_default().push(f);
    }
    by_crate
}

//  JSON reporter

/// Top-level JSON report structure, output by [`report_json`].
#[derive(Serialize)]
pub struct JsonReport {
    /// Version of cargo-capsec that produced this report.
    pub version: String,
    /// Findings grouped by crate.
    pub crates: Vec<JsonCrate>,
    /// Aggregate statistics.
    pub summary: JsonSummary,
}

/// A crate and its findings in the JSON report.
#[derive(Serialize)]
pub struct JsonCrate {
    /// Crate name.
    pub name: String,
    /// Crate version.
    pub version: String,
    /// All ambient authority findings in this crate.
    pub findings: Vec<JsonFinding>,
}

/// A single finding in the JSON report.
#[derive(Serialize)]
pub struct JsonFinding {
    /// Source file path.
    pub file: String,
    /// Function containing the call.
    pub function: String,
    /// Line number of the call.
    pub line: usize,
    /// Column number of the call.
    pub col: usize,
    /// The expanded call path (e.g., `"std::fs::read"`).
    pub call: String,
    /// Category label (e.g., `"FS"`, `"NET"`).
    pub category: String,
    /// Subcategory (e.g., `"read"`, `"connect"`).
    pub subcategory: String,
    /// Risk level (e.g., `"high"`, `"critical"`).
    pub risk: String,
    /// Human-readable description.
    pub description: String,
    /// Whether this is inside a build.rs main() function.
    pub is_build_script: bool,
}

/// Aggregate statistics in the JSON report.
#[derive(Serialize)]
pub struct JsonSummary {
    /// Total number of findings.
    pub total_findings: usize,
    /// Number of crates with at least one finding.
    pub crates_with_findings: usize,
    /// Finding count by category (e.g., `{"FS": 3, "NET": 1}`).
    pub by_category: BTreeMap<String, usize>,
    /// Finding count by risk level (e.g., `{"high": 2, "critical": 1}`).
    pub by_risk: BTreeMap<String, usize>,
}

/// Formats findings as a pretty-printed JSON string.
///
/// The output conforms to the [`JsonReport`] schema and includes a summary
/// with counts by category and risk level.
pub fn report_json(findings: &[Finding]) -> String {
    let mut by_crate: BTreeMap<(String, String), Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        by_crate
            .entry((f.crate_name.clone(), f.crate_version.clone()))
            .or_default()
            .push(f);
    }

    let crates: Vec<JsonCrate> = by_crate
        .into_iter()
        .map(|((name, version), fs)| JsonCrate {
            name,
            version,
            findings: fs.into_iter().map(finding_to_json).collect(),
        })
        .collect();

    let mut by_category = BTreeMap::new();
    let mut by_risk = BTreeMap::new();
    for f in findings {
        *by_category
            .entry(f.category.label().to_string())
            .or_insert(0) += 1;
        *by_risk.entry(f.risk.label().to_string()).or_insert(0) += 1;
    }

    let report = JsonReport {
        version: env!("CARGO_PKG_VERSION").to_string(),
        summary: JsonSummary {
            total_findings: findings.len(),
            crates_with_findings: crates.iter().filter(|c| !c.findings.is_empty()).count(),
            by_category,
            by_risk,
        },
        crates,
    };

    serde_json::to_string_pretty(&report).unwrap_or_default()
}

fn finding_to_json(f: &Finding) -> JsonFinding {
    JsonFinding {
        file: f.file.clone(),
        function: f.function.clone(),
        line: f.call_line,
        col: f.call_col,
        call: f.call_text.clone(),
        category: f.category.label().to_string(),
        subcategory: f.subcategory.clone(),
        risk: f.risk.label().to_string(),
        description: f.description.clone(),
        is_build_script: f.is_build_script,
    }
}

//  SARIF reporter

/// Formats findings as a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
/// JSON string, suitable for upload to GitHub Code Scanning.
///
/// Risk levels map to SARIF severity: `Critical` → `"error"`, `High` → `"warning"`,
/// `Medium`/`Low` → `"note"`. Rule IDs follow the pattern `capsec/{category}/{subcategory}`.
pub fn report_sarif(findings: &[Finding]) -> String {
    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "ruleId": format!("capsec/{}/{}", f.category.label().to_lowercase(), f.subcategory),
                "level": match f.risk {
                    Risk::Critical => "error",
                    Risk::High => "warning",
                    _ => "note",
                },
                "message": {
                    "text": format!("{}: {} in {}()", f.description, f.call_text, f.function)
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.file },
                        "region": {
                            "startLine": f.call_line,
                            "startColumn": f.call_col
                        }
                    }
                }]
            })
        })
        .collect();

    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "capsec-cli",
                    "version": env!("CARGO_PKG_VERSION"),
                }
            },
            "results": results
        }]
    });

    serde_json::to_string_pretty(&sarif).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_findings() -> Vec<Finding> {
        vec![
            Finding {
                file: "src/main.rs".to_string(),
                function: "main".to_string(),
                function_line: 5,
                call_line: 8,
                call_col: 5,
                call_text: "std::fs::read".to_string(),
                category: Category::Fs,
                subcategory: "read".to_string(),
                risk: Risk::Medium,
                description: "Read arbitrary file".to_string(),
                is_build_script: false,
                crate_name: "my-app".to_string(),
                crate_version: "0.1.0".to_string(),
            },
            Finding {
                file: "src/net.rs".to_string(),
                function: "connect".to_string(),
                function_line: 10,
                call_line: 12,
                call_col: 9,
                call_text: "TcpStream::connect".to_string(),
                category: Category::Net,
                subcategory: "connect".to_string(),
                risk: Risk::High,
                description: "Open TCP connection".to_string(),
                is_build_script: false,
                crate_name: "my-app".to_string(),
                crate_version: "0.1.0".to_string(),
            },
        ]
    }

    #[test]
    fn json_report_is_valid() {
        let findings = sample_findings();
        let json_str = report_json(&findings);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["summary"]["total_findings"], 2);
        assert_eq!(parsed["crates"][0]["name"], "my-app");
    }

    #[test]
    fn sarif_report_is_valid() {
        let findings = sample_findings();
        let sarif_str = report_sarif(&findings);
        let parsed: serde_json::Value = serde_json::from_str(&sarif_str).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(parsed["runs"][0]["results"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn empty_findings_json() {
        let json_str = report_json(&[]);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["summary"]["total_findings"], 0);
    }
}
