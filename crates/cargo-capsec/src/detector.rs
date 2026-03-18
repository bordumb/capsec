use crate::authorities::{Authority, AuthorityPattern, Category, CustomAuthority, Risk, build_registry};
use crate::parser::{CallKind, ImportPath, ParsedFile};
use serde::Serialize;
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub file: String,
    pub function: String,
    pub function_line: usize,
    pub call_line: usize,
    pub call_col: usize,
    pub call_text: String,
    pub category: Category,
    pub subcategory: String,
    pub risk: Risk,
    pub description: String,
    pub is_build_script: bool,
    pub crate_name: String,
    pub crate_version: String,
}

pub struct Detector {
    authorities: Vec<Authority>,
    custom_paths: Vec<(Vec<String>, Category, Risk, String)>,
}

impl Detector {
    pub fn new() -> Self {
        Self {
            authorities: build_registry(),
            custom_paths: Vec::new(),
        }
    }

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

    pub fn analyse(&self, file: &ParsedFile, crate_name: &str, crate_version: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let import_map = build_import_map(&file.use_imports);

        for func in &file.functions {
            // Expand all calls upfront for context lookups
            let expanded_calls: Vec<Vec<String>> = func
                .calls
                .iter()
                .map(|call| expand_call(&call.segments, &import_map))
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
                    if let AuthorityPattern::Path(pattern) = &authority.pattern {
                        if matches_path(expanded, pattern) {
                            matched_paths.insert(pattern.iter().map(|s| s.to_string()).collect());
                            findings.push(make_finding(
                                file, func, call, expanded, authority, crate_name, crate_version,
                            ));
                            break;
                        }
                    }
                }

                // Custom path authorities
                for (pattern, category, risk, description) in &self.custom_paths {
                    if matches_custom_path(expanded, pattern) {
                        findings.push(Finding {
                            file: file.path.clone(),
                            function: func.name.clone(),
                            function_line: func.line,
                            call_line: call.line,
                            call_col: call.col,
                            call_text: expanded.join("::"),
                            category: category.clone(),
                            subcategory: "custom".to_string(),
                            risk: *risk,
                            description: description.clone(),
                            is_build_script: func.is_build_script,
                            crate_name: crate_name.to_string(),
                            crate_version: crate_version.to_string(),
                        });
                        break;
                    }
                }
            }

            // Pass 2: resolve MethodWithContext — only match if requires_path
            // was found in pass 1 (co-occurrence in same function)
            for (call, expanded) in func.calls.iter().zip(expanded_calls.iter()) {
                for authority in &self.authorities {
                    if let AuthorityPattern::MethodWithContext { method, requires_path } = &authority.pattern {
                        if matches!(call.kind, CallKind::MethodCall { method: ref m } if m == method) {
                            let required: Vec<String> = requires_path.iter().map(|s| s.to_string()).collect();
                            if matched_paths.contains(&required) {
                                findings.push(make_finding(
                                    file, func, call, expanded, authority, crate_name, crate_version,
                                ));
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Extern blocks
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
            });
        }

        // Fix #5: dedup by (file, function, call_line, call_col)
        let mut seen = HashSet::new();
        findings.retain(|f| seen.insert((f.file.clone(), f.function.clone(), f.call_line, f.call_col)));

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
    Finding {
        file: file.path.clone(),
        function: func.name.clone(),
        function_line: func.line,
        call_line: call.line,
        call_col: call.col,
        call_text: expanded.join("::"),
        category: authority.category.clone(),
        subcategory: authority.subcategory.to_string(),
        risk: authority.risk,
        description: authority.description.to_string(),
        is_build_script: func.is_build_script,
        crate_name: crate_name.to_string(),
        crate_version: crate_version.to_string(),
    }
}

fn build_import_map(imports: &[ImportPath]) -> Vec<(String, Vec<String>)> {
    imports
        .iter()
        .map(|imp| {
            let short_name = imp
                .alias
                .clone()
                .unwrap_or_else(|| imp.segments.last().cloned().unwrap_or_default());
            (short_name, imp.segments.clone())
        })
        .collect()
}

fn expand_call(segments: &[String], import_map: &[(String, Vec<String>)]) -> Vec<String> {
    if segments.is_empty() {
        return Vec::new();
    }

    for (short_name, full_path) in import_map {
        if segments[0] == *short_name {
            let mut expanded = full_path.clone();
            expanded.extend_from_slice(&segments[1..]);
            return expanded;
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
        let proc_findings: Vec<_> = findings.iter().filter(|f| f.category == Category::Process).collect();
        // Should find Command::new AND .output() (context satisfied)
        assert!(proc_findings.len() >= 2, "Expected Command::new + .output(), got {proc_findings:?}");
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
        let proc_findings: Vec<_> = findings.iter().filter(|f| f.category == Category::Process).collect();
        assert!(proc_findings.is_empty(), "Should NOT flag .status() without Command::new context");
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
                "Duplicate finding at {}:{}", f.call_line, f.call_col
            );
        }
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
        assert!(!findings.is_empty(), "Should detect aliased import: use std::fs::read as load");
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
        assert!(!findings.is_empty(), "Should detect fs::read inside impl block");
        assert_eq!(findings[0].function, "load");
    }
}
