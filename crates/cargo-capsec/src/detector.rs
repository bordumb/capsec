//! The detection engine — matches parsed call sites against the authority registry.
//!
//! This is the core of `cargo-capsec`. It takes a [`ParsedFile`] from the parser,
//! expands call paths using import information, and matches them against the
//! [`authority registry`](crate::authorities::build_registry). The output is a
//! list of [`Finding`]s, each representing one instance of ambient authority usage.
//!
//! # Two-pass matching
//!
//! The detector uses a two-pass approach per function:
//!
//! 1. **Pass 1**: Match all [`AuthorityPattern::Path`] patterns and record which
//!    patterns were found (needed for contextual matching).
//! 2. **Pass 2**: Match [`AuthorityPattern::MethodWithContext`] patterns, which only
//!    fire if their required context path was found in pass 1.
//!
//! This eliminates false positives from common method names like `.status()` and `.output()`.

use crate::authorities::{
    Authority, AuthorityPattern, Category, CustomAuthority, Risk, build_registry,
};
use crate::parser::{CallKind, ImportPath, ParsedFile};
use serde::Serialize;
use std::collections::HashSet;

/// A single instance of ambient authority usage found in source code.
///
/// Each finding represents one call site where code exercises authority over the
/// filesystem, network, environment, or process table. Findings are the primary
/// output of the audit pipeline.
///
/// # Deduplication
///
/// The detector deduplicates findings by `(file, function, call_line, call_col)`,
/// so each unique call site appears at most once even if multiple import paths
/// could match it.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Source file path.
    pub file: String,
    /// Name of the function containing the call.
    pub function: String,
    /// Line where the containing function is defined.
    pub function_line: usize,
    /// Line of the call expression.
    pub call_line: usize,
    /// Column of the call expression.
    pub call_col: usize,
    /// The expanded call path (e.g., `"std::fs::read"`).
    pub call_text: String,
    /// What kind of ambient authority this exercises.
    pub category: Category,
    /// Finer-grained classification (e.g., `"read"`, `"connect"`, `"spawn"`).
    pub subcategory: String,
    /// How dangerous this call is.
    pub risk: Risk,
    /// Human-readable description.
    pub description: String,
    /// Whether this call is inside a `build.rs` `main()` function.
    pub is_build_script: bool,
    /// Name of the crate containing this call.
    pub crate_name: String,
    /// Version of the crate containing this call.
    pub crate_version: String,
    /// True if this finding is inside a `#[capsec::deny(...)]` function
    /// whose denied categories cover this finding's category.
    /// Deny violations are always promoted to `Critical` risk.
    pub is_deny_violation: bool,
}

/// The ambient authority detector.
///
/// Holds the built-in authority registry plus any user-defined custom authorities
/// from `.capsec.toml`. Create one with [`Detector::new`], optionally extend it
/// with [`add_custom_authorities`](Detector::add_custom_authorities), then call
/// [`analyse`](Detector::analyse) on each parsed file.
///
/// # Example
///
/// ```
/// use cargo_capsec::parser::parse_source;
/// use cargo_capsec::detector::Detector;
///
/// let source = r#"
///     use std::fs;
///     fn load() { let _ = fs::read("data.bin"); }
/// "#;
///
/// let parsed = parse_source(source, "example.rs").unwrap();
/// let detector = Detector::new();
/// let findings = detector.analyse(&parsed, "my-crate", "0.1.0");
/// assert_eq!(findings.len(), 1);
/// ```
pub struct Detector {
    authorities: Vec<Authority>,
    custom_paths: Vec<(Vec<String>, Category, Risk, String)>,
}

impl Default for Detector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector {
    /// Creates a new detector with the built-in authority registry.
    pub fn new() -> Self {
        Self {
            authorities: build_registry(),
            custom_paths: Vec::new(),
        }
    }

    /// Extends the detector with custom authority patterns from `.capsec.toml`.
    pub fn add_custom_authorities(&mut self, customs: &[CustomAuthority]) {
        for c in customs {
            self.custom_paths.push((
                c.path.clone(),
                c.category.clone(),
                c.risk,
                c.description.clone(),
            ));
        }
    }

    /// Analyses a parsed file and returns all ambient authority findings.
    ///
    /// Expands call paths using the file's `use` imports, matches against the
    /// authority registry (built-in + custom), and deduplicates by call site.
    pub fn analyse(
        &self,
        file: &ParsedFile,
        crate_name: &str,
        crate_version: &str,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let (import_map, glob_prefixes) = build_import_map(&file.use_imports);

        for func in &file.functions {
            // Expand all calls upfront for context lookups
            let expanded_calls: Vec<Vec<String>> = func
                .calls
                .iter()
                .map(|call| {
                    expand_call(
                        &call.segments,
                        &import_map,
                        &glob_prefixes,
                        &self.authorities,
                    )
                })
                .collect();

            // Pass 1: collect path-based findings and build a set of matched patterns.
            // We store the *pattern* (e.g. ["Command", "new"]), not the expanded call path.
            // This is correct: if someone writes `use std::process::Command; Command::new("sh")`,
            // import expansion produces `std::process::Command::new`, which suffix-matches
            // the pattern ["Command", "new"]. Pass 2 then checks for pattern co-occurrence,
            // so `.output()` fires only when the Command::new *pattern* was matched in pass 1.
            let mut matched_paths: HashSet<Vec<String>> = HashSet::new();

            for (call, expanded) in func.calls.iter().zip(expanded_calls.iter()) {
                for authority in &self.authorities {
                    if let AuthorityPattern::Path(pattern) = &authority.pattern
                        && matches_path(expanded, pattern)
                    {
                        matched_paths.insert(pattern.iter().map(|s| s.to_string()).collect());
                        findings.push(make_finding(
                            file,
                            func,
                            call,
                            expanded,
                            authority,
                            crate_name,
                            crate_version,
                        ));
                        break;
                    }
                }

                // Custom path authorities
                for (pattern, category, risk, description) in &self.custom_paths {
                    if matches_custom_path(expanded, pattern) {
                        let deny_violation = is_category_denied(&func.deny_categories, category);
                        findings.push(Finding {
                            file: file.path.clone(),
                            function: func.name.clone(),
                            function_line: func.line,
                            call_line: call.line,
                            call_col: call.col,
                            call_text: expanded.join("::"),
                            category: category.clone(),
                            subcategory: "custom".to_string(),
                            risk: if deny_violation {
                                Risk::Critical
                            } else {
                                *risk
                            },
                            description: if deny_violation {
                                format!("DENY VIOLATION: {} (in #[deny] function)", description)
                            } else {
                                description.clone()
                            },
                            is_build_script: func.is_build_script,
                            crate_name: crate_name.to_string(),
                            crate_version: crate_version.to_string(),
                            is_deny_violation: deny_violation,
                        });
                        break;
                    }
                }
            }

            // Pass 2: resolve MethodWithContext — only match if requires_path
            // was found in pass 1 (co-occurrence in same function)
            for (call, expanded) in func.calls.iter().zip(expanded_calls.iter()) {
                for authority in &self.authorities {
                    if let AuthorityPattern::MethodWithContext {
                        method,
                        requires_path,
                    } = &authority.pattern
                        && matches!(call.kind, CallKind::MethodCall { method: ref m } if m == method)
                    {
                        let required: Vec<String> =
                            requires_path.iter().map(|s| s.to_string()).collect();
                        if matched_paths.contains(&required) {
                            findings.push(make_finding(
                                file,
                                func,
                                call,
                                expanded,
                                authority,
                                crate_name,
                                crate_version,
                            ));
                            break;
                        }
                    }
                }
            }
        }

        // Extern blocks (not inside a function, so no deny context)
        for ext in &file.extern_blocks {
            findings.push(Finding {
                file: file.path.clone(),
                function: format!("extern \"{}\"", ext.abi.as_deref().unwrap_or("C")),
                function_line: ext.line,
                call_line: ext.line,
                call_col: 0,
                call_text: format!(
                    "extern block ({} functions: {})",
                    ext.functions.len(),
                    ext.functions.join(", ")
                ),
                category: Category::Ffi,
                subcategory: "extern".to_string(),
                risk: Risk::High,
                description: "Foreign function interface — bypasses Rust safety".to_string(),
                is_build_script: file.path.ends_with("build.rs"),
                crate_name: crate_name.to_string(),
                crate_version: crate_version.to_string(),
                is_deny_violation: false,
            });
        }

        // Fix #5: dedup by (file, function, call_line, call_col)
        let mut seen = HashSet::new();
        findings
            .retain(|f| seen.insert((f.file.clone(), f.function.clone(), f.call_line, f.call_col)));

        findings
    }
}

fn make_finding(
    file: &ParsedFile,
    func: &crate::parser::ParsedFunction,
    call: &crate::parser::CallSite,
    expanded: &[String],
    authority: &Authority,
    crate_name: &str,
    crate_version: &str,
) -> Finding {
    let is_deny_violation = is_category_denied(&func.deny_categories, &authority.category);
    Finding {
        file: file.path.clone(),
        function: func.name.clone(),
        function_line: func.line,
        call_line: call.line,
        call_col: call.col,
        call_text: expanded.join("::"),
        category: authority.category.clone(),
        subcategory: authority.subcategory.to_string(),
        risk: if is_deny_violation {
            Risk::Critical
        } else {
            authority.risk
        },
        description: if is_deny_violation {
            format!(
                "DENY VIOLATION: {} (in #[deny] function)",
                authority.description
            )
        } else {
            authority.description.to_string()
        },
        is_build_script: func.is_build_script,
        crate_name: crate_name.to_string(),
        crate_version: crate_version.to_string(),
        is_deny_violation,
    }
}

/// Checks if a finding's category is covered by the function's deny list.
fn is_category_denied(deny_categories: &[String], finding_category: &Category) -> bool {
    if deny_categories.is_empty() {
        return false;
    }
    for denied in deny_categories {
        match denied.as_str() {
            "all" => return true,
            "fs" if *finding_category == Category::Fs => return true,
            "net" if *finding_category == Category::Net => return true,
            "env" if *finding_category == Category::Env => return true,
            "process" if *finding_category == Category::Process => return true,
            "ffi" if *finding_category == Category::Ffi => return true,
            _ => {}
        }
    }
    false
}

type ImportMap = Vec<(String, Vec<String>)>;
type GlobPrefixes = Vec<Vec<String>>;

fn build_import_map(imports: &[ImportPath]) -> (ImportMap, GlobPrefixes) {
    let mut map = Vec::new();
    let mut glob_prefixes = Vec::new();

    for imp in imports {
        if imp.segments.last().map(|s| s.as_str()) == Some("*") {
            // Glob import: store the prefix (everything before "*")
            glob_prefixes.push(imp.segments[..imp.segments.len() - 1].to_vec());
        } else {
            let short_name = imp
                .alias
                .clone()
                .unwrap_or_else(|| imp.segments.last().cloned().unwrap_or_default());
            map.push((short_name, imp.segments.clone()));
        }
    }

    (map, glob_prefixes)
}

fn expand_call(
    segments: &[String],
    import_map: &[(String, Vec<String>)],
    glob_prefixes: &[Vec<String>],
    authorities: &[Authority],
) -> Vec<String> {
    if segments.is_empty() {
        return Vec::new();
    }

    // First: try explicit import expansion (takes priority per RFC 1560)
    for (short_name, full_path) in import_map {
        if segments[0] == *short_name {
            let mut expanded = full_path.clone();
            expanded.extend_from_slice(&segments[1..]);
            return expanded;
        }
    }

    // Fallback: try glob import expansion for single-segment bare calls
    if segments.len() == 1 {
        for prefix in glob_prefixes {
            let mut candidate = prefix.clone();
            candidate.push(segments[0].clone());
            // Only expand if the candidate matches a known authority pattern
            for authority in authorities {
                if let AuthorityPattern::Path(pattern) = &authority.pattern
                    && matches_path(&candidate, pattern)
                {
                    return candidate;
                }
            }
        }
    }

    segments.to_vec()
}

fn matches_path(expanded_path: &[String], pattern: &[&str]) -> bool {
    if expanded_path.len() < pattern.len() {
        return false;
    }
    let offset = expanded_path.len() - pattern.len();
    expanded_path[offset..]
        .iter()
        .zip(pattern.iter())
        .all(|(a, b)| a.as_str() == *b)
}

fn matches_custom_path(expanded_path: &[String], pattern: &[String]) -> bool {
    if expanded_path.len() < pattern.len() {
        return false;
    }
    let offset = expanded_path.len() - pattern.len();
    expanded_path[offset..]
        .iter()
        .zip(pattern.iter())
        .all(|(a, b)| a == b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_source;

    #[test]
    fn detect_fs_read() {
        let source = r#"
            use std::fs;
            fn load() {
                let _ = fs::read("test");
            }
        "#;
        let parsed = parse_source(source, "test.rs").unwrap();
        let detector = Detector::new();
        let findings = detector.analyse(&parsed, "test-crate", "0.1.0");
        assert!(!findings.is_empty());
        assert_eq!(findings[0].category, Category::Fs);
    }

    #[test]
    fn detect_import_expanded_call() {
        let source = r#"
            use std::fs::read_to_string;
            fn load() {
                let _ = read_to_string("/etc/passwd");
            }
        "#;
        let parsed = parse_source(source, "test.rs").unwrap();
        let detector = Detector::new();
        let findings = detector.analyse(&parsed, "test-crate", "0.1.0");
        assert!(!findings.is_empty());
        assert_eq!(findings[0].category, Category::Fs);
        assert!(findings[0].call_text.contains("read_to_string"));
    }

    #[test]
    fn method_with_context_fires_when_context_present() {
        let source = r#"
            use std::process::Command;
            fn run() {
                let cmd = Command::new("sh");
                cmd.output();
            }
        "#;
        let parsed = parse_source(source, "test.rs").unwrap();
        let detector = Detector::new();
        let findings = detector.analyse(&parsed, "test-crate", "0.1.0");
        let proc_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == Category::Process)
            .collect();
        // Should find Command::new AND .output() (context satisfied)
        assert!(
            proc_findings.len() >= 2,
            "Expected Command::new + .output(), got {proc_findings:?}"
        );
    }

    #[test]
    fn method_without_context_does_not_fire() {
        // .status() on something that is NOT Command — should not flag
        let source = r#"
            fn check() {
                let response = get_response();
                let s = response.status();
            }
        "#;
        let parsed = parse_source(source, "test.rs").unwrap();
        let detector = Detector::new();
        let findings = detector.analyse(&parsed, "test-crate", "0.1.0");
        let proc_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == Category::Process)
            .collect();
        assert!(
            proc_findings.is_empty(),
            "Should NOT flag .status() without Command::new context"
        );
    }

    #[test]
    fn detect_extern_block() {
        let source = r#"
            extern "C" {
                fn open(path: *const u8, flags: i32) -> i32;
            }
        "#;
        let parsed = parse_source(source, "test.rs").unwrap();
        let detector = Detector::new();
        let findings = detector.analyse(&parsed, "test-crate", "0.1.0");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, Category::Ffi);
    }

    #[test]
    fn clean_code_no_findings() {
        let source = r#"
            fn add(a: i32, b: i32) -> i32 { a + b }
        "#;
        let parsed = parse_source(source, "test.rs").unwrap();
        let detector = Detector::new();
        let findings = detector.analyse(&parsed, "test-crate", "0.1.0");
        assert!(findings.is_empty());
    }

    #[test]
    fn detect_command_new() {
        let source = r#"
            use std::process::Command;
            fn run() {
                let _ = Command::new("sh");
            }
        "#;
        let parsed = parse_source(source, "test.rs").unwrap();
        let detector = Detector::new();
        let findings = detector.analyse(&parsed, "test-crate", "0.1.0");
        assert!(!findings.is_empty());
        assert_eq!(findings[0].category, Category::Process);
        assert_eq!(findings[0].risk, Risk::Critical);
    }

    #[test]
    fn dedup_prevents_double_counting() {
        // Even if import expansion creates two matching paths, we only report once per call site
        let source = r#"
            use std::fs;
            use std::fs::read;
            fn load() {
                let _ = fs::read("test");
            }
        "#;
        let parsed = parse_source(source, "test.rs").unwrap();
        let detector = Detector::new();
        let findings = detector.analyse(&parsed, "test-crate", "0.1.0");
        // Each unique (file, function, line, col) should appear at most once
        let mut seen = std::collections::HashSet::new();
        for f in &findings {
            assert!(
                seen.insert((&f.file, &f.function, f.call_line, f.call_col)),
                "Duplicate finding at {}:{}",
                f.call_line,
                f.call_col
            );
        }
    }

    #[test]
    fn deny_violation_promotes_to_critical() {
        let source = r#"
            use std::fs;
            #[doc = "capsec::deny(all)"]
            fn pure_function() {
                let _ = fs::read("secret.key");
            }
        "#;
        let parsed = parse_source(source, "test.rs").unwrap();
        let detector = Detector::new();
        let findings = detector.analyse(&parsed, "test-crate", "0.1.0");
        assert!(!findings.is_empty());
        assert!(findings[0].is_deny_violation);
        assert_eq!(findings[0].risk, Risk::Critical);
        assert!(findings[0].description.contains("DENY VIOLATION"));
    }

    #[test]
    fn deny_fs_only_flags_fs_not_net() {
        let source = r#"
            use std::fs;
            use std::net::TcpStream;
            #[doc = "capsec::deny(fs)"]
            fn mostly_pure() {
                let _ = fs::read("data");
                let _ = TcpStream::connect("127.0.0.1:80");
            }
        "#;
        let parsed = parse_source(source, "test.rs").unwrap();
        let detector = Detector::new();
        let findings = detector.analyse(&parsed, "test-crate", "0.1.0");
        let fs_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == Category::Fs)
            .collect();
        let net_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == Category::Net)
            .collect();
        assert!(fs_findings[0].is_deny_violation);
        assert_eq!(fs_findings[0].risk, Risk::Critical);
        assert!(!net_findings[0].is_deny_violation);
    }

    #[test]
    fn no_deny_annotation_no_violation() {
        let source = r#"
            use std::fs;
            fn normal() {
                let _ = fs::read("data");
            }
        "#;
        let parsed = parse_source(source, "test.rs").unwrap();
        let detector = Detector::new();
        let findings = detector.analyse(&parsed, "test-crate", "0.1.0");
        assert!(!findings.is_empty());
        assert!(!findings[0].is_deny_violation);
    }

    #[test]
    fn detect_aliased_import() {
        let source = r#"
            use std::fs::read as load;
            fn fetch() {
                let _ = load("data.bin");
            }
        "#;
        let parsed = parse_source(source, "test.rs").unwrap();
        let detector = Detector::new();
        let findings = detector.analyse(&parsed, "test-crate", "0.1.0");
        assert!(
            !findings.is_empty(),
            "Should detect aliased import: use std::fs::read as load"
        );
        assert_eq!(findings[0].category, Category::Fs);
        assert!(findings[0].call_text.contains("std::fs::read"));
    }

    #[test]
    fn detect_impl_block_method() {
        let source = r#"
            use std::fs;
            struct Loader;
            impl Loader {
                fn load(&self) -> Vec<u8> {
                    fs::read("data.bin").unwrap()
                }
            }
        "#;
        let parsed = parse_source(source, "test.rs").unwrap();
        let detector = Detector::new();
        let findings = detector.analyse(&parsed, "test-crate", "0.1.0");
        assert!(
            !findings.is_empty(),
            "Should detect fs::read inside impl block"
        );
        assert_eq!(findings[0].function, "load");
    }
}
