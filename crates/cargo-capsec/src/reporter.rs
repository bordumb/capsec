//! Output formatters — text, JSON, and SARIF.
//!
//! Three output modes, each targeting a different workflow:
//!
//! - **Text** ([`report_text`]) — color-coded terminal output grouped by crate, for humans.
//! - **JSON** ([`report_json`]) — structured output for scripts and CI pipelines.
//! - **SARIF** ([`report_sarif`]) — [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
//!   for GitHub Code Scanning and other SARIF-compatible tools.

use crate::authorities::{Category, Risk};
use crate::config::{Classification, ClassificationResult};
use crate::detector::Finding;
use colored::Colorize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

/// Prints findings to stdout as color-coded text grouped by crate.
///
/// Includes a summary with counts by category and risk level. Prints a green
/// "OK" message when no findings are present.
pub fn report_text(findings: &[Finding], classifications: &[ClassificationResult]) {
    let by_crate = group_by_crate(findings);

    if by_crate.is_empty() && classifications.iter().all(|c| c.valid) {
        println!("\n{}  No ambient authority detected.", "OK".green().bold());
        // Show classification summary if any crates are classified
        for cr in classifications {
            if let Some(class) = cr.classification {
                let label = match class {
                    Classification::Pure => "pure".green(),
                    Classification::Resource => "resource".blue(),
                };
                println!("  {} v{} [{}]", cr.crate_name, cr.crate_version, label);
            }
        }
        return;
    }

    for (crate_key, crate_findings) in &by_crate {
        // Find classification for this crate
        let class_label = classifications
            .iter()
            .find(|cr| crate_key.starts_with(&cr.crate_name))
            .and_then(|cr| {
                cr.classification.map(|c| match (c, cr.valid) {
                    (Classification::Pure, true) => " [pure]".green().to_string(),
                    (Classification::Pure, false) => " [pure ✗]".red().to_string(),
                    (Classification::Resource, _) => " [resource]".blue().to_string(),
                })
            })
            .unwrap_or_default();

        println!();
        println!("{}{}", crate_key.bold(), class_label);
        let separator_len = crate_key.len() + if class_label.is_empty() { 0 } else { 12 };
        println!("{}", "─".repeat(separator_len));

        for f in crate_findings {
            if f.is_deny_violation {
                println!(
                    "  {} {}:{}:{}  {:<28} {}()",
                    "DENY".red().bold(),
                    f.file.dimmed(),
                    f.call_line,
                    f.call_col,
                    f.call_text.bold(),
                    f.function,
                );
            } else if f.description.starts_with("Cross-crate:") {
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
                // Show cross-crate chain detail
                println!("        {} {}", "\u{21b3}".dimmed(), f.description.dimmed(),);
            } else if f.is_transitive {
                println!(
                    "  {:<5} {}:{}:{}  {:<28} {}()",
                    "VIA".white().bold(),
                    f.file.dimmed(),
                    f.call_line,
                    f.call_col,
                    format!("{}()", f.call_text).bold(),
                    f.function,
                );
            } else {
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
    }

    // Print classification violations
    let violations: Vec<_> = classifications.iter().filter(|cr| !cr.valid).collect();
    if !violations.is_empty() {
        println!();
        println!("{}", "Classification Violations".red().bold());
        println!("────────────────────────");
        for cr in &violations {
            println!(
                "  {} v{}: classified as {} but has {} non-build.rs finding(s)",
                cr.crate_name.bold(),
                cr.crate_version,
                "pure".green(),
                cr.violation_count,
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

    let deny_violations = findings.iter().filter(|f| f.is_deny_violation).count();
    if deny_violations > 0 {
        println!(
            "  {} {} (ambient authority in #[deny] function)",
            format!("{deny_violations}").red().bold(),
            if deny_violations == 1 {
                "deny violation"
            } else {
                "deny violations"
            }
        );
    }

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
    /// Classification: `"pure"`, `"resource"`, or `null` if unclassified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
    /// Whether the classification is valid (no violations). `null` if unclassified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification_valid: Option<bool>,
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
    /// Whether this is a deny violation (ambient authority in a #[deny] function).
    pub is_deny_violation: bool,
    /// Whether this finding was propagated through the intra-file call graph.
    pub is_transitive: bool,
    /// Cross-crate chain description, if this finding was propagated from a dependency.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cross_crate_chain: Option<String>,
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
pub fn report_json(findings: &[Finding], classifications: &[ClassificationResult]) -> String {
    let mut by_crate: BTreeMap<(String, String), Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        by_crate
            .entry((f.crate_name.clone(), f.crate_version.clone()))
            .or_default()
            .push(f);
    }

    let crates: Vec<JsonCrate> = by_crate
        .into_iter()
        .map(|((name, version), fs)| {
            let cr = classifications
                .iter()
                .find(|cr| cr.crate_name == name && cr.crate_version == version);
            JsonCrate {
                name,
                version,
                classification: cr.and_then(|cr| {
                    cr.classification.map(|c| match c {
                        Classification::Pure => "pure".to_string(),
                        Classification::Resource => "resource".to_string(),
                    })
                }),
                classification_valid: cr.and_then(|cr| cr.classification.map(|_| cr.valid)),
                findings: fs.into_iter().map(finding_to_json).collect(),
            }
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
    let cross_crate_chain = if f.description.starts_with("Cross-crate:") {
        Some(f.description.clone())
    } else {
        None
    };

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
        is_deny_violation: f.is_deny_violation,
        is_transitive: f.is_transitive,
        cross_crate_chain,
    }
}

//  SARIF reporter

/// Formats findings as a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
/// JSON string, suitable for upload to GitHub Code Scanning.
///
/// Risk levels map to SARIF severity: `Critical` → `"error"`, `High` → `"warning"`,
/// `Medium`/`Low` → `"note"`. Rule IDs follow the pattern `capsec/{category}/{subcategory}`.
///
/// The output includes a `rules` array in `tool.driver` with descriptions and default
/// severity for each rule, and each result carries a `ruleIndex` pointing into that array.
/// This is required for GitHub Code Scanning to display rule metadata in the Security tab.
///
/// `workspace_root` is used to make `artifactLocation.uri` repo-relative. Paths that
/// start with the workspace root have that prefix stripped; other paths are left as-is.
///
/// Validated against GitHub Code Scanning SARIF requirements:
/// - `$schema`: json.schemastore.org URL (GitHub canonical)
/// - Rules: `shortDescription`, `fullDescription`, `help.text`, `properties.tags`,
///   `properties.security-severity` (string), `properties.precision`
/// - Results: `region` with all four bounds, `partialFingerprints.capsecFindingHash/v1`
/// - Run: `semanticVersion`, `runAutomationDetails.id`
pub fn report_sarif(
    findings: &[Finding],
    workspace_root: &Path,
    classifications: &[ClassificationResult],
) -> String {
    let mut rule_index_map: BTreeMap<String, usize> = BTreeMap::new();
    let mut rules: Vec<serde_json::Value> = Vec::new();

    for f in findings {
        let rule_id = format!(
            "capsec/{}/{}",
            f.category.label().to_lowercase(),
            f.subcategory
        );
        if !rule_index_map.contains_key(&rule_id) {
            let idx = rules.len();
            rule_index_map.insert(rule_id.clone(), idx);
            let category_tag = format!("ambient-authority/{}", f.category.label().to_lowercase());
            rules.push(serde_json::json!({
                "id": rule_id,
                "shortDescription": {
                    "text": f.description
                },
                "fullDescription": {
                    "text": format!("{}. Detected by capsec static analysis.", f.description)
                },
                "help": {
                    "text": format!("{}\n\nSee https://github.com/auths-dev/capsec for details on capability-based security in Rust.", f.description),
                    "markdown": format!("**{}**\n\n[capsec documentation](https://github.com/auths-dev/capsec)", f.description)
                },
                "defaultConfiguration": {
                    "level": risk_to_sarif_level(f.risk)
                },
                "properties": {
                    "security-severity": risk_to_security_severity(f.risk),
                    "precision": risk_to_precision(f.risk),
                    "tags": ["security", "ambient-authority", category_tag]
                }
            }));
        }
    }

    let mut results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let rule_id = format!(
                "capsec/{}/{}",
                f.category.label().to_lowercase(),
                f.subcategory
            );
            let rule_index = rule_index_map[&rule_id];
            let relative_path = make_relative(&f.file, workspace_root);
            let fingerprint = compute_fingerprint(f);
            serde_json::json!({
                "ruleId": rule_id,
                "ruleIndex": rule_index,
                "level": risk_to_sarif_level(f.risk),
                "message": {
                    "text": format!("{}: {} in {}()", f.description, f.call_text, f.function)
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": relative_path },
                        "region": {
                            "startLine": f.call_line,
                            "startColumn": f.call_col,
                            "endLine": f.call_line,
                            "endColumn": f.call_col
                        }
                    }
                }],
                "partialFingerprints": {
                    "capsecFindingHash/v1": fingerprint
                }
            })
        })
        .collect();

    // Add classification violation rules and results
    for cr in classifications {
        if !cr.valid {
            let rule_id = "capsec/classification/purity-violation";
            if !rule_index_map.contains_key(rule_id) {
                let idx = rules.len();
                rule_index_map.insert(rule_id.to_string(), idx);
                rules.push(serde_json::json!({
                    "id": rule_id,
                    "shortDescription": {
                        "text": "Crate classified as pure contains I/O operations"
                    },
                    "fullDescription": {
                        "text": "A crate declared as 'pure' in [package.metadata.capsec] has ambient authority findings. Pure crates must not perform I/O."
                    },
                    "help": {
                        "text": "Either remove the I/O operations or change the classification to 'resource'.\n\nSee https://github.com/auths-dev/capsec for details.",
                        "markdown": "**Purity violation**: either remove I/O or reclassify as `resource`.\n\n[capsec documentation](https://github.com/auths-dev/capsec)"
                    },
                    "defaultConfiguration": {
                        "level": "error"
                    },
                    "properties": {
                        "security-severity": "7.0",
                        "precision": "high",
                        "tags": ["security", "classification"]
                    }
                }));
            }
            let rule_index = rule_index_map[rule_id];
            results.push(serde_json::json!({
                "ruleId": rule_id,
                "ruleIndex": rule_index,
                "level": "error",
                "message": {
                    "text": format!(
                        "Crate '{}' v{} is classified as 'pure' but has {} non-build.rs finding(s)",
                        cr.crate_name, cr.crate_version, cr.violation_count
                    )
                }
            }));
        }
    }

    let sarif = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "capsec-cli",
                    "version": env!("CARGO_PKG_VERSION"),
                    "semanticVersion": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/auths-dev/capsec",
                    "rules": rules
                }
            },
            "results": results,
            "automationDetails": {
                "id": "capsec-audit/"
            }
        }]
    });

    serde_json::to_string_pretty(&sarif).unwrap_or_default()
}

/// Maps risk level to security-severity string (0.0–10.0) for GitHub Code Scanning.
/// GitHub's SARIF parser requires this as a string, not a number.
fn risk_to_security_severity(risk: Risk) -> String {
    match risk {
        Risk::Critical => "9.5".to_string(),
        Risk::High => "7.5".to_string(),
        Risk::Medium => "5.0".to_string(),
        Risk::Low => "2.0".to_string(),
    }
}

/// Strips `workspace_root` prefix from a file path to produce a repo-relative URI.
fn make_relative(file_path: &str, workspace_root: &Path) -> String {
    let root_str = workspace_root.to_string_lossy();
    let root_prefix = if root_str.ends_with('/') {
        root_str.to_string()
    } else {
        format!("{root_str}/")
    };
    if file_path.starts_with(&root_prefix) {
        file_path[root_prefix.len()..].to_string()
    } else {
        file_path.to_string()
    }
}

/// Maps risk to SARIF precision (how confident we are in the finding).
fn risk_to_precision(risk: Risk) -> &'static str {
    match risk {
        Risk::Critical | Risk::High => "high",
        Risk::Medium => "medium",
        Risk::Low => "low",
    }
}

/// Computes a stable fingerprint for GitHub Code Scanning deduplication.
/// Emitted as `partialFingerprints.capsecFindingHash/v1`.
fn compute_fingerprint(f: &Finding) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    f.file.hash(&mut hasher);
    f.function.hash(&mut hasher);
    f.call_text.hash(&mut hasher);
    f.category.label().hash(&mut hasher);
    f.subcategory.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn risk_to_sarif_level(risk: Risk) -> &'static str {
    match risk {
        Risk::Critical => "error",
        Risk::High => "warning",
        _ => "note",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_root() -> PathBuf {
        PathBuf::from("/workspace/project")
    }

    fn sample_findings() -> Vec<Finding> {
        vec![
            Finding {
                file: "/workspace/project/src/main.rs".to_string(),
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
                is_deny_violation: false,
                is_transitive: false,
            },
            Finding {
                file: "/workspace/project/src/net.rs".to_string(),
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
                is_deny_violation: false,
                is_transitive: false,
            },
        ]
    }

    #[test]
    fn json_report_is_valid() {
        let findings = sample_findings();
        let json_str = report_json(&findings, &[]);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["summary"]["total_findings"], 2);
        assert_eq!(parsed["crates"][0]["name"], "my-app");
    }

    #[test]
    fn sarif_report_is_valid() {
        let findings = sample_findings();
        let sarif_str = report_sarif(&findings, &test_root(), &[]);
        let parsed: serde_json::Value = serde_json::from_str(&sarif_str).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(parsed["runs"][0]["results"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn sarif_schema_is_canonical() {
        let sarif_str = report_sarif(&sample_findings(), &test_root(), &[]);
        let parsed: serde_json::Value = serde_json::from_str(&sarif_str).unwrap();
        assert_eq!(
            parsed["$schema"], "https://json.schemastore.org/sarif-2.1.0.json",
            "$schema must use the canonical json.schemastore.org URL"
        );
    }

    #[test]
    fn sarif_driver_has_semantic_version() {
        let sarif_str = report_sarif(&sample_findings(), &test_root(), &[]);
        let parsed: serde_json::Value = serde_json::from_str(&sarif_str).unwrap();
        let driver = &parsed["runs"][0]["tool"]["driver"];
        assert!(
            driver["semanticVersion"].is_string(),
            "driver must have semanticVersion"
        );
    }

    #[test]
    fn sarif_has_automation_details() {
        let sarif_str = report_sarif(&sample_findings(), &test_root(), &[]);
        let parsed: serde_json::Value = serde_json::from_str(&sarif_str).unwrap();
        assert!(
            parsed["runs"][0]["automationDetails"]["id"].is_string(),
            "run must have automationDetails.id"
        );
    }

    #[test]
    fn sarif_rules_have_all_required_fields() {
        let findings = sample_findings();
        let sarif_str = report_sarif(&findings, &test_root(), &[]);
        let parsed: serde_json::Value = serde_json::from_str(&sarif_str).unwrap();

        let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .expect("driver should have rules array");
        assert_eq!(rules.len(), 2, "two distinct rule IDs from sample findings");

        for rule in rules {
            assert!(rule["id"].is_string(), "rule must have id");
            assert!(
                rule["shortDescription"]["text"].is_string(),
                "rule must have shortDescription.text"
            );
            assert!(
                rule["fullDescription"]["text"].is_string(),
                "rule must have fullDescription.text (GitHub requires this)"
            );
            assert!(
                rule["help"]["text"].is_string(),
                "rule must have help.text (GitHub requires this)"
            );
            assert!(
                rule["defaultConfiguration"]["level"].is_string(),
                "rule must have defaultConfiguration.level"
            );

            let tags = rule["properties"]["tags"]
                .as_array()
                .expect("rule must have properties.tags");
            assert!(
                tags.iter().any(|t| t == "security"),
                "tags must include 'security' for GitHub severity to apply"
            );
            assert!(
                rule["properties"]["precision"].is_string(),
                "rule must have properties.precision"
            );
        }
    }

    #[test]
    fn sarif_results_have_valid_rule_index() {
        let findings = sample_findings();
        let sarif_str = report_sarif(&findings, &test_root(), &[]);
        let parsed: serde_json::Value = serde_json::from_str(&sarif_str).unwrap();

        let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        let results = parsed["runs"][0]["results"].as_array().unwrap();

        for result in results {
            let rule_index = result["ruleIndex"]
                .as_u64()
                .expect("each result must have ruleIndex") as usize;
            assert!(
                rule_index < rules.len(),
                "ruleIndex {rule_index} must be within rules array (len {})",
                rules.len()
            );

            // ruleId must match the rule at ruleIndex
            let rule_id = result["ruleId"].as_str().unwrap();
            let indexed_id = rules[rule_index]["id"].as_str().unwrap();
            assert_eq!(rule_id, indexed_id, "ruleId must match rules[ruleIndex].id");
        }
    }

    #[test]
    fn sarif_deduplicates_rules() {
        // Two findings with the same category+subcategory should produce one rule
        let findings = vec![
            Finding {
                file: "/workspace/project/src/a.rs".to_string(),
                function: "a".to_string(),
                function_line: 1,
                call_line: 2,
                call_col: 5,
                call_text: "std::fs::read".to_string(),
                category: Category::Fs,
                subcategory: "read".to_string(),
                risk: Risk::Medium,
                description: "Read arbitrary file".to_string(),
                is_build_script: false,
                crate_name: "app".to_string(),
                crate_version: "0.1.0".to_string(),
                is_deny_violation: false,
                is_transitive: false,
            },
            Finding {
                file: "/workspace/project/src/b.rs".to_string(),
                function: "b".to_string(),
                function_line: 10,
                call_line: 12,
                call_col: 9,
                call_text: "std::fs::read_to_string".to_string(),
                category: Category::Fs,
                subcategory: "read".to_string(),
                risk: Risk::Medium,
                description: "Read arbitrary file as string".to_string(),
                is_build_script: false,
                crate_name: "app".to_string(),
                crate_version: "0.1.0".to_string(),
                is_deny_violation: false,
                is_transitive: false,
            },
        ];

        let sarif_str = report_sarif(&findings, &test_root(), &[]);
        let parsed: serde_json::Value = serde_json::from_str(&sarif_str).unwrap();
        let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();

        assert_eq!(
            rules.len(),
            1,
            "two findings with same ruleId should produce one rule"
        );
        assert_eq!(rules[0]["id"], "capsec/fs/read");

        // Both results should point to rule index 0
        let results = parsed["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["ruleIndex"], 0);
        assert_eq!(results[1]["ruleIndex"], 0);
    }

    #[test]
    fn sarif_empty_findings_has_empty_rules() {
        let sarif_str = report_sarif(&[], &test_root(), &[]);
        let parsed: serde_json::Value = serde_json::from_str(&sarif_str).unwrap();
        let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert!(rules.is_empty(), "no findings should produce no rules");
    }

    #[test]
    fn empty_findings_json() {
        let json_str = report_json(&[], &[]);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["summary"]["total_findings"], 0);
    }

    #[test]
    fn sarif_results_have_partial_fingerprints() {
        let findings = sample_findings();
        let sarif_str = report_sarif(&findings, &test_root(), &[]);
        let parsed: serde_json::Value = serde_json::from_str(&sarif_str).unwrap();
        let results = parsed["runs"][0]["results"].as_array().unwrap();

        for result in results {
            let fingerprint = result["partialFingerprints"]["capsecFindingHash/v1"]
                .as_str()
                .expect("each result must have partialFingerprints.capsecFindingHash/v1");
            assert_eq!(fingerprint.len(), 16, "fingerprint should be 16 hex chars");
            assert!(
                fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
                "fingerprint should be hex"
            );
        }

        // Two different findings should have different fingerprints
        let fp0 = results[0]["partialFingerprints"]["capsecFindingHash/v1"]
            .as_str()
            .unwrap();
        let fp1 = results[1]["partialFingerprints"]["capsecFindingHash/v1"]
            .as_str()
            .unwrap();
        assert_ne!(
            fp0, fp1,
            "different findings should have different fingerprints"
        );
    }

    #[test]
    fn sarif_results_have_complete_region() {
        let findings = sample_findings();
        let sarif_str = report_sarif(&findings, &test_root(), &[]);
        let parsed: serde_json::Value = serde_json::from_str(&sarif_str).unwrap();
        let results = parsed["runs"][0]["results"].as_array().unwrap();

        for result in results {
            let region = &result["locations"][0]["physicalLocation"]["region"];
            assert!(region["startLine"].is_u64(), "must have startLine");
            assert!(region["startColumn"].is_u64(), "must have startColumn");
            assert!(
                region["endLine"].is_u64(),
                "must have endLine (GitHub requires this)"
            );
            assert!(
                region["endColumn"].is_u64(),
                "must have endColumn (GitHub requires this)"
            );
        }
    }

    #[test]
    fn sarif_rules_have_security_severity() {
        let findings = sample_findings();
        let sarif_str = report_sarif(&findings, &test_root(), &[]);
        let parsed: serde_json::Value = serde_json::from_str(&sarif_str).unwrap();
        let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();

        for rule in rules {
            let severity = rule["properties"]["security-severity"]
                .as_str()
                .expect("each rule must have properties.security-severity as string");
            let val: f64 = severity.parse().expect("must be parseable as f64");
            assert!(
                (0.0..=10.0).contains(&val),
                "security-severity must be 0.0-10.0, got {severity}"
            );
        }

        // fs/read is Medium → "5.0", net/connect is High → "7.5"
        assert_eq!(rules[0]["properties"]["security-severity"], "5.0");
        assert_eq!(rules[1]["properties"]["security-severity"], "7.5");
    }

    #[test]
    fn sarif_artifact_uris_are_relative() {
        let findings = sample_findings();
        let sarif_str = report_sarif(&findings, &test_root(), &[]);
        let parsed: serde_json::Value = serde_json::from_str(&sarif_str).unwrap();
        let results = parsed["runs"][0]["results"].as_array().unwrap();

        for result in results {
            let uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                .as_str()
                .unwrap();
            assert!(
                !uri.starts_with('/'),
                "artifactLocation.uri must be relative, got: {uri}"
            );
        }

        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/main.rs"
        );
        assert_eq!(
            results[1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/net.rs"
        );
    }

    #[test]
    fn make_relative_strips_prefix() {
        let root = PathBuf::from("/home/runner/work/repo");
        assert_eq!(
            make_relative("/home/runner/work/repo/src/main.rs", &root),
            "src/main.rs"
        );
    }

    #[test]
    fn make_relative_preserves_non_matching_path() {
        let root = PathBuf::from("/home/runner/work/repo");
        assert_eq!(
            make_relative("/other/path/src/main.rs", &root),
            "/other/path/src/main.rs"
        );
    }

    #[test]
    fn fingerprint_is_stable() {
        let f = Finding {
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
            is_deny_violation: false,
            is_transitive: false,
        };
        let fp1 = compute_fingerprint(&f);
        let fp2 = compute_fingerprint(&f);
        assert_eq!(fp1, fp2, "fingerprint must be stable across calls");
    }
}
