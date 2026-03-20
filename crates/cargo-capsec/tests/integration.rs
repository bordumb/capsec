use cargo_capsec::authorities::Category;
use cargo_capsec::detector::Detector;
use cargo_capsec::parser::parse_source;
use std::path::PathBuf;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
        .join("src/lib.rs")
}

fn fixture_source(name: &str) -> String {
    std::fs::read_to_string(fixture_path(name)).unwrap()
}

#[test]
fn clean_crate_zero_findings() {
    let source = fixture_source("clean_crate");
    let parsed = parse_source(&source, "clean_crate/src/lib.rs").unwrap();
    let detector = Detector::new();
    let findings = detector.analyse(&parsed, "clean_crate", "0.1.0");
    assert!(
        findings.is_empty(),
        "Clean crate should have zero findings, got: {findings:?}"
    );
}

#[test]
fn fs_crate_detects_filesystem_calls() {
    let source = fixture_source("fs_crate");
    let parsed = parse_source(&source, "fs_crate/src/lib.rs").unwrap();
    let detector = Detector::new();
    let findings = detector.analyse(&parsed, "fs_crate", "0.1.0");

    let fs_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.category == Category::Fs)
        .collect();
    assert!(
        fs_findings.len() >= 8,
        "Expected at least 8 FS findings, got {}",
        fs_findings.len()
    );

    // Check specific detections
    let calls: Vec<&str> = fs_findings.iter().map(|f| f.call_text.as_str()).collect();
    assert!(
        calls.iter().any(|c| c.contains("read_to_string")),
        "Should detect read_to_string"
    );
    assert!(
        calls.iter().any(|c| c.contains("write")),
        "Should detect write"
    );
    assert!(
        calls.iter().any(|c| c.ends_with("open")),
        "Should detect File::open"
    );
    assert!(
        calls.iter().any(|c| c.ends_with("create")),
        "Should detect File::create"
    );
    assert!(
        calls.iter().any(|c| c.contains("remove_file")),
        "Should detect remove_file"
    );
    assert!(
        calls.iter().any(|c| c.contains("remove_dir_all")),
        "Should detect remove_dir_all"
    );
}

#[test]
fn net_crate_detects_network_calls() {
    let source = fixture_source("net_crate");
    let parsed = parse_source(&source, "net_crate/src/lib.rs").unwrap();
    let detector = Detector::new();
    let findings = detector.analyse(&parsed, "net_crate", "0.1.0");

    let net_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.category == Category::Net)
        .collect();
    assert!(
        net_findings.len() >= 3,
        "Expected at least 3 NET findings, got {}",
        net_findings.len()
    );

    let calls: Vec<&str> = net_findings.iter().map(|f| f.call_text.as_str()).collect();
    assert!(
        calls.iter().any(|c| c.contains("connect")),
        "Should detect TcpStream::connect"
    );
    assert!(
        calls.iter().any(|c| c.contains("bind")),
        "Should detect bind"
    );
}

#[test]
fn sneaky_crate_detects_imported_calls() {
    let source = fixture_source("sneaky_crate");
    let parsed = parse_source(&source, "sneaky_crate/src/lib.rs").unwrap();
    let detector = Detector::new();
    let findings = detector.analyse(&parsed, "sneaky_crate", "0.1.0");

    // Should detect read_to_string via import expansion
    let fs_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.category == Category::Fs)
        .collect();
    assert!(!fs_findings.is_empty(), "Should detect imported fs calls");

    // Should detect env::var
    let env_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.category == Category::Env)
        .collect();
    assert!(!env_findings.is_empty(), "Should detect env::var calls");

    // Should detect Command::new
    let proc_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.category == Category::Process)
        .collect();
    assert!(!proc_findings.is_empty(), "Should detect Command::new");
}

#[test]
fn aliased_crate_detects_renamed_imports() {
    let source = fixture_source("aliased_crate");
    let parsed = parse_source(&source, "aliased_crate/src/lib.rs").unwrap();
    let detector = Detector::new();
    let findings = detector.analyse(&parsed, "aliased_crate", "0.1.0");

    // Import aliases ARE detected because we track use-statement aliases
    assert!(
        !findings.is_empty(),
        "Aliased imports should be detected via import expansion"
    );

    let fs_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.category == Category::Fs)
        .collect();
    assert!(
        !fs_findings.is_empty(),
        "Aliased fs::read should be detected"
    );
}

#[test]
fn json_output_is_valid() {
    let source = fixture_source("fs_crate");
    let parsed = parse_source(&source, "fs_crate/src/lib.rs").unwrap();
    let detector = Detector::new();
    let findings = detector.analyse(&parsed, "fs_crate", "0.1.0");

    let json = cargo_capsec::reporter::report_json(&findings);
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed["summary"]["total_findings"].as_u64().unwrap() > 0);
}

#[test]
fn sarif_output_is_valid() {
    let source = fixture_source("fs_crate");
    let parsed = parse_source(&source, "fs_crate/src/lib.rs").unwrap();
    let detector = Detector::new();
    let findings = detector.analyse(&parsed, "fs_crate", "0.1.0");

    let sarif = cargo_capsec::reporter::report_sarif(&findings, std::path::Path::new("."));
    let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
    assert_eq!(parsed["version"], "2.1.0");
    assert!(!parsed["runs"][0]["results"].as_array().unwrap().is_empty());
}

#[test]
fn config_allow_suppresses_findings() {
    let source = fixture_source("fs_crate");
    let parsed = parse_source(&source, "fs_crate/src/lib.rs").unwrap();
    let detector = Detector::new();
    let mut findings = detector.analyse(&parsed, "fs_crate", "0.1.0");

    let toml_str = r#"
        [[allow]]
        crate = "fs_crate"
        function = "read_config"
        reason = "Known safe"
    "#;
    let cfg: cargo_capsec::config::Config = toml::from_str(toml_str).unwrap();

    let before = findings.len();
    findings.retain(|f| !cargo_capsec::config::should_allow(f, &cfg));
    assert!(
        findings.len() < before,
        "Allow rule should suppress at least one finding"
    );
}

#[test]
fn baseline_round_trip() {
    let source = fixture_source("net_crate");
    let parsed = parse_source(&source, "net_crate/src/lib.rs").unwrap();
    let detector = Detector::new();
    let findings = detector.analyse(&parsed, "net_crate", "0.1.0");

    let root = capsec_core::root::test_root();
    let read_cap = root.grant::<capsec_core::permission::FsRead>();
    let write_cap = root.grant::<capsec_core::permission::FsWrite>();

    let dir = tempfile::tempdir().unwrap();
    cargo_capsec::baseline::save_baseline(dir.path(), &findings, &write_cap).unwrap();

    let loaded = cargo_capsec::baseline::load_baseline(dir.path(), &read_cap).unwrap();
    assert_eq!(loaded.len(), findings.len());

    let diff = cargo_capsec::baseline::diff(&findings, &loaded);
    assert_eq!(diff.new_findings.len(), 0);
    assert_eq!(diff.removed_findings.len(), 0);
    assert_eq!(diff.unchanged_count, findings.len());
}
