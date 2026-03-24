use cargo_capsec::authorities::Category;
use cargo_capsec::cross_crate::export_map_to_custom_authorities;
use cargo_capsec::detector::Detector;
use cargo_capsec::export_map::build_export_map;
use cargo_capsec::parser::parse_source;
use std::path::{Path, PathBuf};

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
    let findings = detector.analyse(&parsed, "clean_crate", "0.1.0", &[]);
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
    let findings = detector.analyse(&parsed, "fs_crate", "0.1.0", &[]);

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
    let findings = detector.analyse(&parsed, "net_crate", "0.1.0", &[]);

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
    let findings = detector.analyse(&parsed, "sneaky_crate", "0.1.0", &[]);

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
    let findings = detector.analyse(&parsed, "aliased_crate", "0.1.0", &[]);

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
    let findings = detector.analyse(&parsed, "fs_crate", "0.1.0", &[]);

    let json = cargo_capsec::reporter::report_json(&findings, &[]);
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed["summary"]["total_findings"].as_u64().unwrap() > 0);
}

#[test]
fn sarif_output_is_valid() {
    let source = fixture_source("fs_crate");
    let parsed = parse_source(&source, "fs_crate/src/lib.rs").unwrap();
    let detector = Detector::new();
    let findings = detector.analyse(&parsed, "fs_crate", "0.1.0", &[]);

    let sarif = cargo_capsec::reporter::report_sarif(&findings, std::path::Path::new("."), &[]);
    let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
    assert_eq!(parsed["version"], "2.1.0");
    assert!(!parsed["runs"][0]["results"].as_array().unwrap().is_empty());
}

#[test]
fn config_allow_suppresses_findings() {
    let source = fixture_source("fs_crate");
    let parsed = parse_source(&source, "fs_crate/src/lib.rs").unwrap();
    let detector = Detector::new();
    let mut findings = detector.analyse(&parsed, "fs_crate", "0.1.0", &[]);

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
    let findings = detector.analyse(&parsed, "net_crate", "0.1.0", &[]);

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

#[test]
fn transitive_crate_propagates_findings() {
    let source = fixture_source("transitive_crate");
    let parsed = parse_source(&source, "transitive_crate/src/lib.rs").unwrap();
    let detector = Detector::new();
    let findings = detector.analyse(&parsed, "transitive_crate", "0.1.0", &[]);

    // read_helper should have a direct FS finding
    let helper_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.function == "read_helper")
        .collect();
    assert!(
        !helper_findings.is_empty(),
        "read_helper should have direct FS finding"
    );
    assert!(!helper_findings[0].is_transitive);

    // public_api should have a transitive FS finding
    let api_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.function == "public_api")
        .collect();
    assert!(
        !api_findings.is_empty(),
        "public_api should have transitive FS finding from read_helper"
    );
    assert!(api_findings[0].is_transitive);
    assert_eq!(api_findings[0].category, Category::Fs);
    assert_eq!(api_findings[0].call_text, "read_helper");
}

// ── Cross-crate propagation tests ──

#[test]
fn cross_crate_type_qualified_method_call() {
    // Simulate: dependency "mydb" has `fn open() { std::fs::read(...) }`
    // living in src/connection.rs (so module path is "connection")
    // Workspace code calls `mydb::Connection::open()` (type-qualified)
    let dep_source = r#"
        use std::fs;
        pub fn open() -> Vec<u8> {
            fs::read("database.db").unwrap()
        }
    "#;
    // File is "src/connection.rs" so module path = ["connection"]
    let dep_parsed = parse_source(dep_source, "src/connection.rs").unwrap();
    let det = Detector::new();
    let dep_findings = det.analyse(&dep_parsed, "mydb", "1.0.0", &[]);
    assert!(!dep_findings.is_empty(), "mydb should have FS finding");

    // Export map should produce:
    //   "mydb::connection::open" (full path from file)
    //   "mydb::open" (short form for crate-scoped matching)
    let dep_map = build_export_map("mydb", "1.0.0", &dep_findings, Path::new("src"));
    assert!(
        dep_map.exports.contains_key("mydb::connection::open"),
        "Should have full-path entry"
    );
    assert!(
        dep_map.exports.contains_key("mydb::open"),
        "Should have short-form entry for crate-scoped matching"
    );

    // Workspace code calls mydb::Connection::open()
    // Parser produces segments: ["mydb", "Connection", "open"]
    // Crate-scoped matching: expanded[0]=="mydb" && expanded.last()=="open"
    //   matches pattern ["mydb", "open"]
    let app_source = r#"
        pub fn query() {
            mydb::Connection::open();
        }
    "#;
    let app_parsed = parse_source(app_source, "src/lib.rs").unwrap();

    let customs = export_map_to_custom_authorities(&[dep_map]);
    let mut det2 = Detector::new();
    det2.add_custom_authorities(&customs);
    let app_findings = det2.analyse(&app_parsed, "app", "0.1.0", &[]);

    let query_findings: Vec<_> = app_findings
        .iter()
        .filter(|f| f.function == "query")
        .collect();
    assert!(
        !query_findings.is_empty(),
        "app::query should get cross-crate finding via mydb::Connection::open(), got: {app_findings:?}"
    );
    assert!(query_findings[0].description.contains("Cross-crate"));
}

fn cross_crate_fixture_source(fixture: &str, crate_name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(fixture)
        .join(crate_name)
        .join("src/lib.rs");
    std::fs::read_to_string(path).unwrap()
}

#[test]
fn cross_crate_basic_fs_propagation() {
    // Phase 1: Scan the "helper" dependency crate
    let helper_source = cross_crate_fixture_source("cross_crate", "helper");
    let helper_parsed = parse_source(&helper_source, "src/lib.rs").unwrap();
    let det = Detector::new();
    let helper_findings = det.analyse(&helper_parsed, "helper", "0.1.0", &[]);

    // helper should have a direct FS finding
    assert!(
        !helper_findings.is_empty(),
        "helper should have FS findings"
    );
    assert_eq!(helper_findings[0].category, Category::Fs);

    // Build export map from helper's findings
    let export_map = build_export_map("helper", "0.1.0", &helper_findings, Path::new("src"));
    assert!(
        !export_map.exports.is_empty(),
        "export map should have entries"
    );

    // Phase 2: Scan the "app" workspace crate with helper's export map injected
    let app_source = cross_crate_fixture_source("cross_crate", "app");
    let app_parsed = parse_source(&app_source, "src/lib.rs").unwrap();

    let cross_crate_customs = export_map_to_custom_authorities(&[export_map]);
    let mut det2 = Detector::new();
    det2.add_custom_authorities(&cross_crate_customs);

    let app_findings = det2.analyse(&app_parsed, "app", "0.1.0", &[]);

    // app::load() should have a cross-crate FS finding via helper::read_file
    let load_findings: Vec<_> = app_findings
        .iter()
        .filter(|f| f.function == "load")
        .collect();
    assert!(
        !load_findings.is_empty(),
        "app::load should get cross-crate FS finding, got: {app_findings:?}"
    );
    assert!(load_findings[0].description.contains("Cross-crate"));
}

#[test]
fn cross_crate_chain_multi_hop() {
    // Phase 1a: Scan "leaf" (has direct NET finding)
    let leaf_source = cross_crate_fixture_source("cross_crate_chain", "leaf");
    let leaf_parsed = parse_source(&leaf_source, "src/lib.rs").unwrap();
    let det = Detector::new();
    let leaf_findings = det.analyse(&leaf_parsed, "leaf", "0.1.0", &[]);
    assert!(
        leaf_findings.iter().any(|f| f.category == Category::Net),
        "leaf should have NET finding"
    );

    let leaf_map = build_export_map("leaf", "0.1.0", &leaf_findings, Path::new("src"));

    // Phase 1b: Scan "mid" with leaf's export map injected
    let mid_source = cross_crate_fixture_source("cross_crate_chain", "mid");
    let mid_parsed = parse_source(&mid_source, "src/lib.rs").unwrap();
    let leaf_customs = export_map_to_custom_authorities(&[leaf_map.clone()]);
    let mut det_mid = Detector::new();
    det_mid.add_custom_authorities(&leaf_customs);
    let mid_findings = det_mid.analyse(&mid_parsed, "mid", "0.1.0", &[]);

    // mid::fetch() should have a cross-crate NET finding via leaf::connect
    let mid_fetch: Vec<_> = mid_findings
        .iter()
        .filter(|f| f.function == "fetch")
        .collect();
    assert!(
        !mid_fetch.is_empty(),
        "mid::fetch should get cross-crate NET finding"
    );

    let mid_map = build_export_map("mid", "0.1.0", &mid_findings, Path::new("src"));

    // Phase 2: Scan "app" with mid's export map
    let app_source = cross_crate_fixture_source("cross_crate_chain", "app");
    let app_parsed = parse_source(&app_source, "src/lib.rs").unwrap();
    let all_customs = export_map_to_custom_authorities(&[leaf_map, mid_map]);
    let mut det_app = Detector::new();
    det_app.add_custom_authorities(&all_customs);
    let app_findings = det_app.analyse(&app_parsed, "app", "0.1.0", &[]);

    // app::handler() should have a cross-crate finding via mid::fetch
    let handler_findings: Vec<_> = app_findings
        .iter()
        .filter(|f| f.function == "handler")
        .collect();
    assert!(
        !handler_findings.is_empty(),
        "app::handler should get cross-crate finding via mid::fetch"
    );
}

#[test]
fn cross_crate_clean_no_propagation() {
    // Phase 1: Scan "pure_lib" (no I/O)
    let pure_source = cross_crate_fixture_source("cross_crate_clean", "pure_lib");
    let pure_parsed = parse_source(&pure_source, "src/lib.rs").unwrap();
    let det = Detector::new();
    let pure_findings = det.analyse(&pure_parsed, "pure_lib", "0.1.0", &[]);
    assert!(
        pure_findings.is_empty(),
        "pure_lib should have zero findings"
    );

    let pure_map = build_export_map("pure_lib", "0.1.0", &pure_findings, Path::new("src"));
    assert!(
        pure_map.exports.is_empty(),
        "empty findings -> empty export map"
    );

    // Phase 2: Scan "app" with empty export map
    let app_source = cross_crate_fixture_source("cross_crate_clean", "app");
    let app_parsed = parse_source(&app_source, "src/lib.rs").unwrap();
    let customs = export_map_to_custom_authorities(&[pure_map]);
    let mut det2 = Detector::new();
    det2.add_custom_authorities(&customs);
    let app_findings = det2.analyse(&app_parsed, "app", "0.1.0", &[]);

    assert!(
        app_findings.is_empty(),
        "app calling pure_lib should have zero findings"
    );
}

#[test]
fn cross_crate_build_script_excluded() {
    // Phase 1: Scan "build_dep" — has build.rs with env::var, but lib.rs is clean
    let dep_source = cross_crate_fixture_source("cross_crate_build_script", "build_dep");
    let dep_parsed = parse_source(&dep_source, "src/lib.rs").unwrap();
    let det = Detector::new();
    let dep_findings = det.analyse(&dep_parsed, "build_dep", "0.1.0", &[]);

    // lib.rs has no authority calls
    assert!(dep_findings.is_empty(), "build_dep lib.rs should be clean");

    // Also scan build.rs
    let build_source = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/cross_crate_build_script/build_dep/build.rs"),
    )
    .unwrap();
    let build_parsed = parse_source(&build_source, "build.rs").unwrap();
    let build_findings = det.analyse(&build_parsed, "build_dep", "0.1.0", &[]);

    // build.rs has env::var — finding is marked as build_script
    assert!(
        build_findings.iter().any(|f| f.is_build_script),
        "build.rs findings should be marked as build_script"
    );

    // Build export map — build_script findings should be excluded
    let mut all_dep_findings = dep_findings;
    all_dep_findings.extend(build_findings);
    let dep_map = build_export_map("build_dep", "0.1.0", &all_dep_findings, Path::new("src"));

    assert!(
        dep_map.exports.is_empty(),
        "export map should exclude build.rs findings"
    );

    // Phase 2: Scan "app"
    let app_source = cross_crate_fixture_source("cross_crate_build_script", "app");
    let app_parsed = parse_source(&app_source, "src/lib.rs").unwrap();
    let customs = export_map_to_custom_authorities(&[dep_map]);
    let mut det2 = Detector::new();
    det2.add_custom_authorities(&customs);
    let app_findings = det2.analyse(&app_parsed, "app", "0.1.0", &[]);

    assert!(
        app_findings.is_empty(),
        "app should have no findings (build.rs excluded from export map)"
    );
}

#[test]
fn cross_crate_ffi_propagation() {
    // Phase 1: Scan ffi_dep — has extern block + function calling extern fn
    let dep_source = cross_crate_fixture_source("cross_crate_ffi", "ffi_dep");
    let dep_parsed = parse_source(&dep_source, "src/lib.rs").unwrap();
    let det = Detector::new();
    let dep_findings = det.analyse(&dep_parsed, "ffi_dep", "0.1.0", &[]);

    // open_db should have an ffi_call finding for calling sqlite3_open
    let open_db_ffi: Vec<_> = dep_findings
        .iter()
        .filter(|f| f.function == "open_db" && f.subcategory == "ffi_call")
        .collect();
    assert!(
        !open_db_ffi.is_empty(),
        "open_db should have FFI call-site finding, got: {dep_findings:?}"
    );

    // Build export map — open_db's FFI finding should appear
    let dep_map = build_export_map("ffi_dep", "0.1.0", &dep_findings, Path::new("src"));
    assert!(
        dep_map.exports.contains_key("ffi_dep::open_db"),
        "export map should have ffi_dep::open_db"
    );

    // Phase 2: Scan app with ffi_dep's export map
    let app_source = cross_crate_fixture_source("cross_crate_ffi", "app");
    let app_parsed = parse_source(&app_source, "src/lib.rs").unwrap();
    let customs = export_map_to_custom_authorities(&[dep_map]);
    let mut det2 = Detector::new();
    det2.add_custom_authorities(&customs);
    let app_findings = det2.analyse(&app_parsed, "app", "0.1.0", &[]);

    let init_findings: Vec<_> = app_findings
        .iter()
        .filter(|f| f.function == "init")
        .collect();
    assert!(
        !init_findings.is_empty(),
        "app::init should get cross-crate FFI finding via ffi_dep::open_db, got: {app_findings:?}"
    );
    assert!(init_findings[0].description.contains("Cross-crate"));
}

#[test]
fn workspace_to_workspace_propagation() {
    // Simulate workspace-to-workspace: core_lib scanned first, then app
    let core_source = cross_crate_fixture_source("workspace_to_workspace", "core_lib");
    let core_parsed = parse_source(&core_source, "src/lib.rs").unwrap();
    let det = Detector::new();
    let core_findings = det.analyse(&core_parsed, "core_lib", "0.1.0", &[]);
    assert!(
        core_findings.iter().any(|f| f.category == Category::Fs),
        "core_lib should have FS finding"
    );

    // Build export map for core_lib (as if scanned first in topo order)
    let core_map = build_export_map("core_lib", "0.1.0", &core_findings, Path::new("src"));

    // Scan app with core_lib's export map
    let app_source = cross_crate_fixture_source("workspace_to_workspace", "app");
    let app_parsed = parse_source(&app_source, "src/lib.rs").unwrap();
    let customs = export_map_to_custom_authorities(&[core_map]);
    let mut det2 = Detector::new();
    det2.add_custom_authorities(&customs);
    let app_findings = det2.analyse(&app_parsed, "app", "0.1.0", &[]);

    let init_findings: Vec<_> = app_findings
        .iter()
        .filter(|f| f.function == "init")
        .collect();
    assert!(
        !init_findings.is_empty(),
        "app::init should get ws-to-ws FS finding from core_lib::read_config"
    );
}
