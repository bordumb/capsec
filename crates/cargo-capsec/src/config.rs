//! `.capsec.toml` configuration parsing.
//!
//! Users can place a `.capsec.toml` file in their workspace root to customize
//! the audit behavior:
//!
//! - **Custom authorities** — flag project-specific I/O functions (database queries,
//!   internal RPC, secret fetchers) that the built-in registry doesn't cover.
//! - **Allow rules** — suppress known-good findings by crate name and/or function name.
//! - **Exclude patterns** — skip files matching glob patterns (tests, benches, generated code).
//! - **Deny rules** — treat all ambient authority in matching categories as Critical deny violations.
//!
//! # Example
//!
//! ```toml
//! [deny]
//! categories = ["all"]
//!
//! [analysis]
//! exclude = ["tests/**", "benches/**"]
//!
//! [[authority]]
//! path = ["my_crate", "secrets", "fetch"]
//! category = "net"
//! risk = "critical"
//! description = "Fetches secrets from vault"
//!
//! [[allow]]
//! crate = "tracing"
//! ```

use crate::authorities::{Category, CustomAuthority, Risk};
use crate::detector::Finding;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Crate classification for capability-based security analysis.
///
/// Inspired by Wyvern's resource/pure module distinction (Melicher et al., ECOOP 2017).
/// A "pure" crate should contain no ambient authority (no I/O, no process spawning, etc.).
/// A "resource" crate is expected to have ambient authority findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Classification {
    /// No I/O, no state, no side effects — safe to import without capability grants.
    Pure,
    /// Contains I/O or ambient authority — requires explicit capability grants.
    Resource,
}

const CONFIG_FILE: &str = ".capsec.toml";

/// Top-level configuration loaded from `.capsec.toml`.
///
/// All fields are optional — a missing config file produces sensible defaults
/// (no excludes, no custom authorities, no allow rules, no deny rules).
#[derive(Debug, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub deny: DenyConfig,
    #[serde(default)]
    pub analysis: AnalysisConfig,
    #[serde(default)]
    pub authority: Vec<AuthorityEntry>,
    #[serde(default)]
    pub allow: Vec<AllowEntry>,
    #[serde(default)]
    pub classify: Vec<ClassifyEntry>,
}

/// A crate classification entry from `[[classify]]` in `.capsec.toml`.
///
/// Overrides any `[package.metadata.capsec]` classification in the crate's own Cargo.toml.
#[derive(Debug, Deserialize)]
pub struct ClassifyEntry {
    /// Crate name to classify (e.g., `"serde"`, `"my-app"`).
    #[serde(rename = "crate")]
    pub crate_name: String,
    /// Classification: `pure` or `resource`.
    pub classification: Classification,
}

/// Crate-level deny configuration from `[deny]` in `.capsec.toml`.
///
/// When categories are specified, any ambient authority matching those categories
/// is promoted to a Critical-risk deny violation — the same behavior as
/// `#[capsec::deny(...)]` on individual functions, but applied crate-wide.
///
/// Valid categories: `all`, `fs`, `net`, `env`, `process`, `ffi`.
#[derive(Debug, Deserialize, Default)]
pub struct DenyConfig {
    #[serde(default)]
    pub categories: Vec<String>,
}

/// Settings that control which files are scanned.
#[derive(Debug, Deserialize, Default)]
pub struct AnalysisConfig {
    #[serde(default)]
    pub exclude: Vec<String>,
}

/// A custom authority pattern from `[[authority]]` in `.capsec.toml`.
#[derive(Debug, Deserialize)]
pub struct AuthorityEntry {
    pub path: Vec<String>,
    pub category: String,
    #[serde(default = "default_risk")]
    pub risk: String,
    #[serde(default)]
    pub description: String,
}

fn default_risk() -> String {
    "medium".to_string()
}

/// A suppression rule from `[[allow]]` in `.capsec.toml`.
///
/// At least one of `crate`/`crate_name` or `function` must be set for the rule
/// to match anything. Both `crate` and `crate_name` keys are supported for ergonomics.
#[derive(Debug, Deserialize)]
pub struct AllowEntry {
    #[serde(default)]
    pub crate_name: Option<String>,
    // support both "crate" and "crate_name" keys
    #[serde(default, rename = "crate")]
    pub crate_key: Option<String>,
    #[serde(default)]
    pub function: Option<String>,
}

impl AllowEntry {
    /// Returns the crate name from either `crate` or `crate_name` key.
    pub fn effective_crate(&self) -> Option<&str> {
        self.crate_name.as_deref().or(self.crate_key.as_deref())
    }
}

const VALID_DENY_CATEGORIES: &[&str] = &["all", "fs", "net", "env", "process", "ffi"];

impl DenyConfig {
    /// Normalizes category names to lowercase and warns about unknown categories.
    pub fn normalized_categories(&self) -> Vec<String> {
        self.categories
            .iter()
            .filter_map(|cat| {
                let lower = cat.to_lowercase();
                if VALID_DENY_CATEGORIES.contains(&lower.as_str()) {
                    Some(lower)
                } else {
                    eprintln!("Warning: unknown deny category '{cat}', ignoring (valid: all, fs, net, env, process, ffi)");
                    None
                }
            })
            .collect()
    }
}

/// Loads configuration from `.capsec.toml` in the given workspace root.
///
/// Returns [`Config::default()`] if the file doesn't exist. Returns an error
/// if the file exists but contains invalid TOML.
pub fn load_config(
    workspace_root: &Path,
    cap: &impl capsec_core::has::Has<capsec_core::permission::FsRead>,
) -> Result<Config, String> {
    let config_path = workspace_root.join(CONFIG_FILE);

    if !config_path.exists() {
        return Ok(Config::default());
    }

    let content = capsec_std::fs::read_to_string(&config_path, cap)
        .map_err(|e| format!("Failed to read {}: {e}", config_path.display()))?;

    let config: Config = toml::from_str(&content)
        .map_err(|e| format!("Failed to parse {}: {e}", config_path.display()))?;

    Ok(config)
}

/// Converts `[[authority]]` config entries into [`CustomAuthority`] values
/// that can be added to the detector.
pub fn custom_authorities(config: &Config) -> Vec<CustomAuthority> {
    config
        .authority
        .iter()
        .map(|entry| CustomAuthority {
            path: entry.path.clone(),
            category: match entry.category.to_lowercase().as_str() {
                "fs" => Category::Fs,
                "net" => Category::Net,
                "env" => Category::Env,
                "process" | "proc" => Category::Process,
                "ffi" => Category::Ffi,
                _ => Category::Ffi,
            },
            risk: Risk::parse(&entry.risk),
            description: entry.description.clone(),
        })
        .collect()
}

/// Returns `true` if a finding should be suppressed by an `[[allow]]` rule.
pub fn should_allow(finding: &Finding, config: &Config) -> bool {
    config.allow.iter().any(|rule| {
        let crate_match = rule
            .effective_crate()
            .is_none_or(|c| c == finding.crate_name);
        let func_match = rule
            .function
            .as_ref()
            .is_none_or(|f| f == &finding.function);
        crate_match && func_match && (rule.effective_crate().is_some() || rule.function.is_some())
    })
}

/// Result of classification verification for a single crate.
#[derive(Debug, Clone, Serialize)]
pub struct ClassificationResult {
    /// Crate name.
    pub crate_name: String,
    /// Crate version.
    pub crate_version: String,
    /// Resolved classification (`None` if unclassified).
    pub classification: Option<Classification>,
    /// `true` if the classification is valid (no violations).
    pub valid: bool,
    /// Number of non-build.rs findings that violate a "pure" classification.
    pub violation_count: usize,
}

/// Verifies whether a crate's classification matches its audit findings.
///
/// A crate classified as `Pure` that has non-build.rs findings is a violation.
/// Build.rs findings are excluded (compile-time only, not runtime authority).
/// Resource and unclassified crates always pass.
pub fn verify_classification(
    classification: Option<Classification>,
    findings: &[Finding],
    crate_name: &str,
    crate_version: &str,
) -> ClassificationResult {
    let violation_count = match classification {
        Some(Classification::Pure) => findings
            .iter()
            .filter(|f| f.crate_name == crate_name && !f.is_build_script)
            .count(),
        _ => 0,
    };

    ClassificationResult {
        crate_name: crate_name.to_string(),
        crate_version: crate_version.to_string(),
        classification,
        valid: violation_count == 0,
        violation_count,
    }
}

/// Resolves the final classification for a crate by merging Cargo.toml metadata
/// with `.capsec.toml` `[[classify]]` overrides.
///
/// Precedence: `.capsec.toml` wins over `Cargo.toml` metadata (consumer > author).
pub fn resolve_classification(
    crate_name: &str,
    cargo_toml_classification: Option<Classification>,
    config: &Config,
) -> Option<Classification> {
    // Check .capsec.toml [[classify]] first (consumer override)
    for entry in &config.classify {
        if entry.crate_name == crate_name {
            return Some(entry.classification);
        }
    }
    // Fall back to Cargo.toml metadata
    cargo_toml_classification
}

/// Returns `true` if a file path matches any `[analysis].exclude` glob pattern.
///
/// Uses the [`globset`] crate for correct glob semantics (supports `**`, `*`,
/// `?`, and character classes).
pub fn should_exclude(path: &Path, excludes: &[String]) -> bool {
    let path_str = path.display().to_string();
    excludes.iter().any(|pattern| {
        match globset::Glob::new(pattern) {
            Ok(glob) => match glob.compile_matcher().is_match(&path_str) {
                true => true,
                false => {
                    // Also try matching against just the file name for simple patterns
                    path.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|name| glob.compile_matcher().is_match(name))
                }
            },
            Err(_) => path_str.contains(pattern),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_config() {
        let toml = r#"
            [analysis]
            exclude = ["tests/**", "benches/**"]

            [[authority]]
            path = ["my_crate", "secrets", "fetch"]
            category = "net"
            risk = "critical"
            description = "Fetches secrets"

            [[allow]]
            crate = "tracing"
            reason = "Logging framework"
        "#;

        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.analysis.exclude.len(), 2);
        assert_eq!(config.authority.len(), 1);
        assert_eq!(
            config.authority[0].path,
            vec!["my_crate", "secrets", "fetch"]
        );
        assert_eq!(config.allow.len(), 1);
        assert_eq!(config.allow[0].effective_crate(), Some("tracing"));
    }

    #[test]
    fn missing_config_returns_default() {
        let root = capsec_core::root::test_root();
        let cap = root.grant::<capsec_core::permission::FsRead>();
        let config = load_config(Path::new("/nonexistent/path"), &cap).unwrap();
        assert!(config.authority.is_empty());
        assert!(config.allow.is_empty());
    }

    #[test]
    fn parse_deny_config() {
        let toml = r#"
            [deny]
            categories = ["all"]
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.deny.categories, vec!["all"]);
    }

    #[test]
    fn parse_deny_selective_categories() {
        let toml = r#"
            [deny]
            categories = ["fs", "net"]
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.deny.categories, vec!["fs", "net"]);
    }

    #[test]
    fn missing_deny_section_defaults_to_empty() {
        let toml = r#"
            [[allow]]
            crate = "tracing"
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.deny.categories.is_empty());
    }

    #[test]
    fn normalized_categories_lowercases_and_filters() {
        let deny = DenyConfig {
            categories: vec!["FS".to_string(), "bogus".to_string(), "net".to_string()],
        };
        let normalized = deny.normalized_categories();
        assert_eq!(normalized, vec!["fs", "net"]);
    }

    #[test]
    fn parse_classify_entries() {
        let toml = r#"
            [[classify]]
            crate = "serde"
            classification = "pure"

            [[classify]]
            crate = "tokio"
            classification = "resource"
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.classify.len(), 2);
        assert_eq!(config.classify[0].crate_name, "serde");
        assert_eq!(config.classify[0].classification, Classification::Pure);
        assert_eq!(config.classify[1].crate_name, "tokio");
        assert_eq!(config.classify[1].classification, Classification::Resource);
    }

    #[test]
    fn missing_classify_defaults_to_empty() {
        let toml = r#"
            [[allow]]
            crate = "tracing"
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.classify.is_empty());
    }

    #[test]
    fn resolve_capsec_toml_overrides_cargo_metadata() {
        let config = Config {
            classify: vec![ClassifyEntry {
                crate_name: "my-lib".to_string(),
                classification: Classification::Resource,
            }],
            ..Config::default()
        };
        let result = resolve_classification("my-lib", Some(Classification::Pure), &config);
        assert_eq!(result, Some(Classification::Resource));
    }

    #[test]
    fn resolve_falls_back_to_cargo_metadata() {
        let config = Config::default();
        let result = resolve_classification("my-lib", Some(Classification::Pure), &config);
        assert_eq!(result, Some(Classification::Pure));
    }

    #[test]
    fn resolve_unclassified_returns_none() {
        let config = Config::default();
        let result = resolve_classification("my-lib", None, &config);
        assert_eq!(result, None);
    }

    #[test]
    fn verify_pure_crate_with_no_findings_passes() {
        let result = verify_classification(Some(Classification::Pure), &[], "my-lib", "0.1.0");
        assert!(result.valid);
        assert_eq!(result.violation_count, 0);
    }

    #[test]
    fn verify_pure_crate_with_findings_fails() {
        let findings = vec![Finding {
            file: "src/lib.rs".to_string(),
            function: "do_io".to_string(),
            function_line: 1,
            call_line: 2,
            call_col: 5,
            call_text: "std::fs::read".to_string(),
            category: crate::authorities::Category::Fs,
            subcategory: "read".to_string(),
            risk: crate::authorities::Risk::Medium,
            description: "Read file".to_string(),
            is_build_script: false,
            crate_name: "my-lib".to_string(),
            crate_version: "0.1.0".to_string(),
            is_deny_violation: false,
            is_transitive: false,
        }];
        let result =
            verify_classification(Some(Classification::Pure), &findings, "my-lib", "0.1.0");
        assert!(!result.valid);
        assert_eq!(result.violation_count, 1);
    }

    #[test]
    fn verify_pure_crate_excludes_build_script_findings() {
        let findings = vec![Finding {
            file: "build.rs".to_string(),
            function: "main".to_string(),
            function_line: 1,
            call_line: 2,
            call_col: 5,
            call_text: "std::env::var".to_string(),
            category: crate::authorities::Category::Env,
            subcategory: "read".to_string(),
            risk: crate::authorities::Risk::Low,
            description: "Read env var".to_string(),
            is_build_script: true,
            crate_name: "my-lib".to_string(),
            crate_version: "0.1.0".to_string(),
            is_deny_violation: false,
            is_transitive: false,
        }];
        let result =
            verify_classification(Some(Classification::Pure), &findings, "my-lib", "0.1.0");
        assert!(result.valid);
        assert_eq!(result.violation_count, 0);
    }

    #[test]
    fn verify_resource_crate_always_passes() {
        let findings = vec![Finding {
            file: "src/lib.rs".to_string(),
            function: "do_io".to_string(),
            function_line: 1,
            call_line: 2,
            call_col: 5,
            call_text: "std::fs::read".to_string(),
            category: crate::authorities::Category::Fs,
            subcategory: "read".to_string(),
            risk: crate::authorities::Risk::Medium,
            description: "Read file".to_string(),
            is_build_script: false,
            crate_name: "my-lib".to_string(),
            crate_version: "0.1.0".to_string(),
            is_deny_violation: false,
            is_transitive: false,
        }];
        let result =
            verify_classification(Some(Classification::Resource), &findings, "my-lib", "0.1.0");
        assert!(result.valid);
    }

    #[test]
    fn invalid_classification_value_errors() {
        let toml = r#"
            [[classify]]
            crate = "bad"
            classification = "unknown"
        "#;
        let result: Result<Config, _> = toml::from_str(toml);
        assert!(result.is_err());
    }

    #[test]
    fn exclude_pattern_matching() {
        assert!(should_exclude(
            Path::new("tests/integration.rs"),
            &["tests/**".to_string()]
        ));
        assert!(!should_exclude(
            Path::new("src/main.rs"),
            &["tests/**".to_string()]
        ));
    }
}
