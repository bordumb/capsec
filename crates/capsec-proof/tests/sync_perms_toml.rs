//! Sync tests: verify proofs/perms.toml matches capsec-core source code.
//!
//! These tests read capsec-core source files as plain text (no Cargo dependency)
//! and compare against the TOML source of truth.

use capsec_proof::runtime_mirror::PermKind;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // crates/capsec-proof -> workspace root (two levels up)
    manifest_dir
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_perms_toml() -> toml::Table {
    let path = workspace_root().join("proofs/perms.toml");
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {e}", path.display()));
    content
        .parse::<toml::Table>()
        .unwrap_or_else(|e| panic!("Failed to parse {}: {e}", path.display()))
}

fn toml_variants(table: &toml::Table) -> Vec<String> {
    table["permissions"]["variants"]
        .as_array()
        .expect("permissions.variants should be an array")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

fn toml_subsumes(table: &toml::Table) -> Vec<(String, Vec<String>)> {
    let sub_table = table["subsumes"]
        .as_table()
        .expect("subsumes should be a table");
    sub_table
        .iter()
        .map(|(super_perm, subs)| {
            let sub_list: Vec<String> = subs
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect();
            (super_perm.clone(), sub_list)
        })
        .collect()
}

fn read_source(relative_path: &str) -> String {
    let path = workspace_root().join(relative_path);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {e}", path.display()))
}

/// Extracts arguments from a macro invocation like `impl_ambient!(FsRead, FsWrite, ...)`.
fn extract_macro_args(source: &str, macro_name: &str) -> Vec<String> {
    let pattern = format!("{macro_name}!(");
    if let Some(start) = source.find(&pattern) {
        let after = &source[start + pattern.len()..];
        if let Some(end) = after.find(')') {
            let args_str = &after[..end];
            return args_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
    }
    vec![]
}

/// Extracts the first bracket list from the *invocation* of
/// `impl_tuple_has_first!([A, B, ...]; [...])`.
/// The invocation may span multiple lines.
fn extract_tuple_first_args(source: &str) -> Vec<String> {
    // Collect the full invocation text (multiline)
    let mut found = false;
    let mut content = String::new();
    for line in source.lines() {
        let trimmed = line.trim();
        if !found
            && trimmed.starts_with("impl_tuple_has_first!(")
            && !trimmed.contains("macro_rules")
        {
            found = true;
            content.push_str(trimmed);
            if trimmed.ends_with(");") {
                break;
            }
            continue;
        }
        if found {
            content.push_str(trimmed);
            if trimmed.contains(");") {
                break;
            }
        }
    }
    // Now extract first bracket list from the collected content
    if let Some(bracket_start) = content.find('[') {
        let inner = &content[bracket_start + 1..];
        if let Some(bracket_end) = inner.find(']') {
            let args_str = &inner[..bracket_end];
            return args_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
    }
    vec![]
}

/// Extracts arguments from the *invocation* of `impl_tuple_has_second!(A, B, C, ...)`.
/// Skips the macro definition by requiring the line NOT contain `$` (macro meta-variables).
fn extract_tuple_second_args(source: &str) -> Vec<String> {
    let mut found = false;
    let mut content = String::new();
    for line in source.lines() {
        let trimmed = line.trim();
        if !found && trimmed.starts_with("impl_tuple_has_second!(") {
            // Skip macro definition lines (they contain $)
            if trimmed.contains('$') {
                continue;
            }
            found = true;
            content.push_str(&trimmed["impl_tuple_has_second!(".len()..]);
            if trimmed.ends_with(");") {
                content = content.trim_end_matches(");").to_string();
                break;
            }
            continue;
        }
        if found {
            content.push_str(trimmed);
            if trimmed.contains(");") {
                content = content.trim_end_matches(");").to_string();
                break;
            }
        }
    }
    content
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

// ============================================================================
// Tests
// ============================================================================

#[test]
fn perms_toml_variants_match_runtime_mirror() {
    let toml = load_perms_toml();
    let toml_vars = toml_variants(&toml);
    let mirror_vars: Vec<String> = PermKind::ALL.iter().map(|p| p.name().to_string()).collect();
    assert_eq!(
        toml_vars, mirror_vars,
        "perms.toml variants must match PermKind::ALL in exact order"
    );
}

#[test]
fn perms_toml_subsumes_match_runtime_mirror() {
    let toml = load_perms_toml();
    let toml_subs = toml_subsumes(&toml);

    // For each TOML subsumption entry, verify the runtime mirror agrees
    for (super_name, sub_names) in &toml_subs {
        let super_perm = PermKind::ALL
            .iter()
            .find(|p| p.name() == super_name)
            .unwrap_or_else(|| panic!("Unknown permission in TOML subsumes: {super_name}"));

        for sub_name in sub_names {
            let sub_perm = PermKind::ALL
                .iter()
                .find(|p| p.name() == sub_name)
                .unwrap_or_else(|| panic!("Unknown permission in TOML subsumes: {sub_name}"));

            assert!(
                capsec_proof::runtime_mirror::subsumes(*super_perm, *sub_perm),
                "TOML says {super_name} subsumes {sub_name}, but runtime_mirror disagrees"
            );
        }
    }

    // Reverse: for each pair where runtime_mirror says subsumes (non-reflexive),
    // verify TOML has the entry
    for a in PermKind::ALL {
        for b in PermKind::ALL {
            if a != b && capsec_proof::runtime_mirror::subsumes(a, b) {
                let found = toml_subs
                    .iter()
                    .any(|(sup, subs)| sup == a.name() && subs.contains(&b.name().to_string()));
                assert!(
                    found,
                    "runtime_mirror says {:?} subsumes {:?}, but perms.toml doesn't have this entry",
                    a, b
                );
            }
        }
    }
}

#[test]
fn perms_toml_matches_has_rs_ambient_macro() {
    let toml = load_perms_toml();
    let toml_vars = toml_variants(&toml);
    // Ambient is not in impl_ambient! — it's covered by direct impl
    let expected_ambient_args: Vec<String> =
        toml_vars.into_iter().filter(|v| v != "Ambient").collect();

    let has_rs = read_source("crates/capsec-core/src/has.rs");
    let ambient_args = extract_macro_args(&has_rs, "impl_ambient");

    assert_eq!(
        ambient_args, expected_ambient_args,
        "impl_ambient! args must match perms.toml variants (minus Ambient)"
    );
}

#[test]
fn perms_toml_matches_has_rs_tuple_macros() {
    let toml = load_perms_toml();
    let toml_vars = toml_variants(&toml);

    let has_rs = read_source("crates/capsec-core/src/has.rs");
    let tuple_first_args = extract_tuple_first_args(&has_rs);
    let tuple_second_args = extract_tuple_second_args(&has_rs);

    assert_eq!(
        tuple_first_args, toml_vars,
        "impl_tuple_has_first! first bracket list must match perms.toml variants"
    );
    assert_eq!(
        tuple_second_args, toml_vars,
        "impl_tuple_has_second! args must match perms.toml variants"
    );
}

#[test]
fn perms_toml_matches_permission_rs_subsumes_impls() {
    let toml = load_perms_toml();
    let toml_subs = toml_subsumes(&toml);

    let perm_rs = read_source("crates/capsec-core/src/permission.rs");

    // Check concrete subsumption impls: `impl Subsumes<Sub> for Super {}`
    for (super_name, sub_names) in &toml_subs {
        if super_name == "Ambient" {
            // Ambient uses blanket impl: `impl<P: Permission> Subsumes<P> for Ambient {}`
            assert!(
                perm_rs.contains("impl<P: Permission> Subsumes<P> for Ambient"),
                "permission.rs must have blanket Subsumes impl for Ambient"
            );
        } else {
            for sub_name in sub_names {
                let pattern = format!("impl Subsumes<{sub_name}> for {super_name}");
                assert!(
                    perm_rs.contains(&pattern),
                    "permission.rs must contain: {pattern}"
                );
            }
        }
    }
}
