//! `.capsec.toml` configuration parsing.
//!
//! Users can place a `.capsec.toml` file in their workspace root to customize
//! the audit behavior:
//!
//! - **Custom authorities** — flag project-specific I/O functions (database queries,
//!   internal RPC, secret fetchers) that the built-in registry doesn't cover.
//! - **Allow rules** — suppress known-good findings by crate name and/or function name.
//! - **Exclude patterns** — skip files matching glob patterns (tests, benches, generated code).
//!
//! # Example
//!
//! ```toml
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
use serde::Deserialize;
use std::path::Path;

const CONFIG_FILE: &str = ".capsec.toml";

/// Top-level configuration loaded from `.capsec.toml`.
///
/// All fields are optional — a missing config file produces sensible defaults
/// (no excludes, no custom authorities, no allow rules).
#[derive(Debug, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub analysis: AnalysisConfig,
    #[serde(default)]
    pub authority: Vec<AuthorityEntry>,
    #[serde(default)]
    pub allow: Vec<AllowEntry>,
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
        self.crate_name
            .as_deref()
            .or(self.crate_key.as_deref())
    }
}


/// Loads configuration from `.capsec.toml` in the given workspace root.
///
/// Returns [`Config::default()`] if the file doesn't exist. Returns an error
/// if the file exists but contains invalid TOML.
pub fn load_config(workspace_root: &Path) -> Result<Config, String> {
    let config_path = workspace_root.join(CONFIG_FILE);

    if !config_path.exists() {
        return Ok(Config::default());
    }

    let content = std::fs::read_to_string(&config_path)
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
            risk: Risk::from_str(&entry.risk),
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
        assert_eq!(config.authority[0].path, vec!["my_crate", "secrets", "fetch"]);
        assert_eq!(config.allow.len(), 1);
        assert_eq!(config.allow[0].effective_crate(), Some("tracing"));
    }

    #[test]
    fn missing_config_returns_default() {
        let config = load_config(Path::new("/nonexistent/path")).unwrap();
        assert!(config.authority.is_empty());
        assert!(config.allow.is_empty());
    }

    #[test]
    fn exclude_pattern_matching() {
        assert!(should_exclude(Path::new("tests/integration.rs"), &["tests/**".to_string()]));
        assert!(!should_exclude(Path::new("src/main.rs"), &["tests/**".to_string()]));
    }
}
