mod authorities;
mod baseline;
mod cli;
mod config;
mod cross_crate;
mod deep;
mod detector;
mod discovery;
mod export_map;
mod parser;
mod reporter;

use authorities::Risk;
use clap::Parser;
use cli::{AuditArgs, BadgeArgs, CargoSubcommand, CheckDenyArgs, Cli, Commands};
use std::collections::HashMap;
use std::path::Path;

fn main() {
    let cli = Cli::parse();
    let CargoSubcommand::Capsec { command } = cli.command;

    match command {
        Commands::Audit(args) => run_audit(args),
        Commands::CheckDeny(args) => run_check_deny(args),
        Commands::Badge(args) => run_badge(args),
    }
}

fn run_audit(args: AuditArgs) {
    // Grant capabilities — this is the single point of ambient authority.
    // Every I/O operation below traces back to these grants.
    let cap_root = capsec_core::root::root();
    let fs_read = cap_root.grant::<capsec_core::permission::FsRead>();
    let fs_write = cap_root.grant::<capsec_core::permission::FsWrite>();
    let spawn_cap = cap_root.grant::<capsec_core::permission::Spawn>();

    let path_arg = args.path.canonicalize().unwrap_or(args.path.clone());

    let scan_deps = args.include_deps || args.deps_only;

    // Load config
    let cfg = match config::load_config(&path_arg, &fs_read) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Warning: {e}");
            config::Config::default()
        }
    };

    // Discover crates — always include deps when cross-crate scanning is active
    let discovery = match discovery::discover_crates(&path_arg, scan_deps, &spawn_cap, &fs_read) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!("Hint: Run from a directory containing Cargo.toml, or use --path");
            std::process::exit(2);
        }
    };
    let workspace_root = discovery.workspace_root;
    let resolve_graph = discovery.resolve_graph;
    let all_crates = discovery.crates;

    // Separate workspace crates from dependencies
    let (workspace_crates, dep_crates): (Vec<_>, Vec<_>) =
        all_crates.into_iter().partition(|c| !c.is_dependency);

    let crate_deny = cfg.deny.normalized_categories();
    let customs = config::custom_authorities(&cfg);

    let mut all_findings = Vec::new();

    if scan_deps {
        // ── Cross-crate two-phase scan ──

        // Phase 1: Scan dependency crates, build export maps.
        // Check cache first; only scan if cache miss.
        // At depth=1, all deps are independent and can be scanned in parallel.
        let cache_dir = workspace_root.join(".capsec-cache");

        let scan_one_dep =
            |krate: &discovery::CrateInfo| -> (export_map::CrateExportMap, Vec<detector::Finding>) {
                let normalized_name = discovery::normalize_crate_name(&krate.name);

                // Try loading from cache (only for registry deps)
                if krate.is_dependency
                    && let Some(cached) = export_map::load_cached_export_map(
                        &cache_dir,
                        &normalized_name,
                        &krate.version,
                        &fs_read,
                    )
                {
                    return (cached, Vec::new());
                }

                let mut det = detector::Detector::new();
                det.add_custom_authorities(&customs);

                let source_files = discovery::discover_source_files(&krate.source_dir, &fs_read);
                let mut dep_findings = Vec::new();
                let mut parsed_files = Vec::new();

                for file_path in source_files {
                    match parser::parse_file(&file_path, &fs_read) {
                        Ok(parsed) => {
                            let findings =
                                det.analyse(&parsed, &krate.name, &krate.version, &crate_deny);
                            dep_findings.extend(findings);
                            parsed_files.push(parsed);
                        }
                        Err(_e) => {
                            // Silently skip unparseable files in deps
                        }
                    }
                }

                let mut emap = export_map::build_export_map(
                    &normalized_name,
                    &krate.version,
                    &dep_findings,
                    &krate.source_dir,
                );

                // Also export extern function declarations (e.g., libgit2-sys, sqlite3-sys)
                // so callers like git2 get cross-crate FFI findings.
                export_map::add_extern_exports(&mut emap, &parsed_files, &krate.source_dir);

                // Cache for registry deps
                if krate.is_dependency {
                    export_map::save_export_map_cache(&cache_dir, &emap, &fs_write);
                }

                (emap, dep_findings)
            };

        // Scan deps — parallel at depth=1, sequential at depth>1 (needs prior maps)
        let mut export_maps = Vec::new();

        if args.dep_depth == 1 {
            // All deps are independent at depth 1 — scan sequentially
            // (capsec capabilities are !Send, so rayon can't parallelize I/O;
            //  parallelism will be added when capabilities support Sync)
            let results: Vec<_> = dep_crates.iter().map(scan_one_dep).collect();

            for (emap, dep_findings) in results {
                export_maps.push(emap);
                if args.deps_only {
                    all_findings.extend(dep_findings);
                }
            }
        } else {
            // Multi-hop: sequential, injecting prior maps at each step
            for krate in &dep_crates {
                let normalized_name = discovery::normalize_crate_name(&krate.name);

                // Try cache
                if krate.is_dependency
                    && let Some(cached) = export_map::load_cached_export_map(
                        &cache_dir,
                        &normalized_name,
                        &krate.version,
                        &fs_read,
                    )
                {
                    export_maps.push(cached);
                    continue;
                }

                let mut det = detector::Detector::new();
                det.add_custom_authorities(&customs);

                // Inject previously-scanned deps' export maps for multi-hop chains
                let cross_crate_customs =
                    cross_crate::export_map_to_custom_authorities(&export_maps);
                det.add_custom_authorities(&cross_crate_customs);

                let source_files = discovery::discover_source_files(&krate.source_dir, &fs_read);
                let mut dep_findings = Vec::new();
                let mut parsed_files = Vec::new();

                for file_path in source_files {
                    match parser::parse_file(&file_path, &fs_read) {
                        Ok(parsed) => {
                            let findings =
                                det.analyse(&parsed, &krate.name, &krate.version, &crate_deny);
                            dep_findings.extend(findings);
                            parsed_files.push(parsed);
                        }
                        Err(e) => {
                            eprintln!("  Warning: {e}");
                        }
                    }
                }

                let mut emap = export_map::build_export_map(
                    &normalized_name,
                    &krate.version,
                    &dep_findings,
                    &krate.source_dir,
                );
                export_map::add_extern_exports(&mut emap, &parsed_files, &krate.source_dir);

                if krate.is_dependency {
                    export_map::save_export_map_cache(&cache_dir, &emap, &fs_write);
                }

                export_maps.push(emap);

                if args.deps_only {
                    all_findings.extend(dep_findings);
                }
            }
        }

        // ── Deep MIR analysis (runs before Phase 2 so findings feed into export maps) ──
        if args.deep {
            let deep_result = deep::run_deep_analysis(
                &path_arg,
                &workspace_root,
                &workspace_crates,
                &dep_crates,
                &fs_read,
                &spawn_cap,
            );
            for warning in &deep_result.warnings {
                eprintln!("Warning: {warning}");
            }
            if !deep_result.findings.is_empty() {
                eprintln!(
                    "Deep analysis: {} MIR-level findings. Building export maps...",
                    deep_result.findings.len()
                );
            }
            export_maps.extend(deep_result.export_maps);
            all_findings.extend(deep_result.findings);
        }

        // Phase 2: Scan workspace crates with dependency export maps injected.
        // Process in topological order so workspace-to-workspace findings propagate
        // (e.g., radicle-cli depends on radicle → radicle scanned first).
        if !args.deps_only {
            let dep_customs = cross_crate::export_map_to_custom_authorities(&export_maps);

            // Determine scan order: topological if resolve graph available
            let ordered_ws_crates: Vec<&discovery::CrateInfo> =
                if let Some(ref graph) = resolve_graph {
                    if let Some(topo_ids) =
                        discovery::workspace_topological_order(&workspace_crates, graph)
                    {
                        let id_to_idx: HashMap<&str, usize> = workspace_crates
                            .iter()
                            .enumerate()
                            .filter_map(|(i, c)| c.package_id.as_deref().map(|id| (id, i)))
                            .collect();
                        let mut ordered: Vec<&discovery::CrateInfo> = Vec::new();
                        for id in &topo_ids {
                            if let Some(&idx) = id_to_idx.get(id.as_str()) {
                                ordered.push(&workspace_crates[idx]);
                            }
                        }
                        // Add any not in topo order (defensive fallback)
                        let seen: std::collections::HashSet<&str> =
                            topo_ids.iter().map(|s| s.as_str()).collect();
                        for c in &workspace_crates {
                            if !c
                                .package_id
                                .as_ref()
                                .is_some_and(|id| seen.contains(id.as_str()))
                            {
                                ordered.push(c);
                            }
                        }
                        ordered
                    } else {
                        workspace_crates.iter().collect()
                    }
                } else {
                    workspace_crates.iter().collect()
                };

            let mut workspace_export_maps: Vec<export_map::CrateExportMap> = Vec::new();

            for krate in &ordered_ws_crates {
                // Apply --only / --skip filtering to workspace crates
                if let Some(ref only) = args.only {
                    let allowed: Vec<&str> = only.split(',').collect();
                    if !allowed.contains(&krate.name.as_str()) {
                        continue;
                    }
                }
                if let Some(ref skip) = args.skip {
                    let skipped: Vec<&str> = skip.split(',').collect();
                    if skipped.contains(&krate.name.as_str()) {
                        continue;
                    }
                }

                let mut det = detector::Detector::new();
                det.add_custom_authorities(&customs);
                det.add_custom_authorities(&dep_customs);

                // Inject previously-scanned workspace member export maps
                let ws_customs =
                    cross_crate::export_map_to_custom_authorities(&workspace_export_maps);
                det.add_custom_authorities(&ws_customs);

                let source_files = discovery::discover_source_files(&krate.source_dir, &fs_read);
                let mut ws_crate_findings = Vec::new();
                let mut ws_parsed_files = Vec::new();

                for file_path in source_files {
                    if config::should_exclude(&file_path, &cfg.analysis.exclude) {
                        continue;
                    }

                    match parser::parse_file(&file_path, &fs_read) {
                        Ok(parsed) => {
                            let findings =
                                det.analyse(&parsed, &krate.name, &krate.version, &crate_deny);
                            ws_crate_findings.extend(findings);
                            ws_parsed_files.push(parsed);
                        }
                        Err(e) => {
                            eprintln!("  Warning: {e}");
                        }
                    }
                }

                // Build export map for this workspace crate (for downstream ws crates)
                let normalized_name = discovery::normalize_crate_name(&krate.name);
                let mut ws_emap = export_map::build_export_map(
                    &normalized_name,
                    &krate.version,
                    &ws_crate_findings,
                    &krate.source_dir,
                );
                export_map::add_extern_exports(&mut ws_emap, &ws_parsed_files, &krate.source_dir);
                workspace_export_maps.push(ws_emap);

                all_findings.extend(ws_crate_findings);
            }
        }
    } else {
        // ── Original single-pass scan (no deps) ──
        for krate in &workspace_crates {
            if let Some(ref only) = args.only {
                let allowed: Vec<&str> = only.split(',').collect();
                if !allowed.contains(&krate.name.as_str()) {
                    continue;
                }
            }
            if let Some(ref skip) = args.skip {
                let skipped: Vec<&str> = skip.split(',').collect();
                if skipped.contains(&krate.name.as_str()) {
                    continue;
                }
            }

            let mut det = detector::Detector::new();
            det.add_custom_authorities(&customs);

            let source_files = discovery::discover_source_files(&krate.source_dir, &fs_read);

            for file_path in source_files {
                if config::should_exclude(&file_path, &cfg.analysis.exclude) {
                    continue;
                }

                match parser::parse_file(&file_path, &fs_read) {
                    Ok(parsed) => {
                        let findings =
                            det.analyse(&parsed, &krate.name, &krate.version, &crate_deny);
                        all_findings.extend(findings);
                    }
                    Err(e) => {
                        eprintln!("  Warning: {e}");
                    }
                }
            }
        }
    }

    // Dedup: if both syntactic and MIR found the same call site, keep one
    {
        let mut seen = std::collections::HashSet::new();
        all_findings.retain(|f| {
            seen.insert((
                f.file.clone(),
                f.function.clone(),
                f.call_line,
                f.call_col,
                f.category.label().to_string(),
            ))
        });
    }

    // Normalize file paths to workspace-relative for portable baselines and output
    for f in &mut all_findings {
        f.file = make_relative(&f.file, &workspace_root);
    }

    // Filter by risk level (applied after all propagation)
    let min_risk = Risk::parse(&args.min_risk);
    all_findings.retain(|f| f.risk >= min_risk);

    // Apply allow rules
    all_findings.retain(|f| !config::should_allow(f, &cfg));

    // Use the appropriate crate list for classification
    let crates_for_classification = if args.deps_only {
        &dep_crates
    } else {
        &workspace_crates
    };

    // Classification verification
    let classification_results: Vec<config::ClassificationResult> = crates_for_classification
        .iter()
        .map(|krate| {
            let resolved = config::resolve_classification(&krate.name, krate.classification, &cfg);
            config::verify_classification(resolved, &all_findings, &krate.name, &krate.version)
        })
        .collect();

    let has_classification_violations = classification_results.iter().any(|r| !r.valid);

    // Load baseline once if needed for diff or fail-on
    let baseline_data = if args.diff || args.fail_on.is_some() {
        baseline::load_baseline(&workspace_root, &fs_read)
    } else {
        None
    };

    // Diff against baseline
    if args.diff {
        if let Some(ref bl) = baseline_data {
            let diff_result = baseline::diff(&all_findings, bl);
            baseline::print_diff(&diff_result);
        } else {
            eprintln!("No baseline found. Run with --baseline first.");
        }
    }

    // Report (suppress with --quiet)
    if !args.quiet {
        match args.format.as_str() {
            "json" => println!(
                "{}",
                reporter::report_json(&all_findings, &classification_results)
            ),
            "sarif" => println!(
                "{}",
                reporter::report_sarif(&all_findings, &workspace_root, &classification_results)
            ),
            _ => reporter::report_text(&all_findings, &classification_results),
        }
    }

    // Save baseline
    if args.baseline {
        match baseline::save_baseline(&workspace_root, &all_findings, &fs_write) {
            Ok(()) => eprintln!("Baseline saved to .capsec-baseline.json"),
            Err(e) => eprintln!("Warning: Failed to save baseline: {e}"),
        }
    }

    // Exit code — classification violations also trigger failure
    if has_classification_violations && args.fail_on.is_some() {
        std::process::exit(1);
    }

    if let Some(ref fail_level) = args.fail_on {
        let threshold = Risk::parse(fail_level);

        if args.diff {
            if let Some(ref bl) = baseline_data {
                let diff_result = baseline::diff(&all_findings, bl);
                let new_set: std::collections::HashSet<_> =
                    diff_result.new_findings.into_iter().collect();
                let has_new_high = all_findings.iter().any(|f| {
                    f.risk >= threshold && new_set.contains(&baseline::BaselineEntry::from(f))
                });
                if has_new_high {
                    std::process::exit(1);
                }
            }
        } else {
            let failing = all_findings.iter().any(|f| f.risk >= threshold);
            if failing {
                std::process::exit(1);
            }
        }
    }
}

fn run_check_deny(args: CheckDenyArgs) {
    let cap_root = capsec_core::root::root();
    let fs_read = cap_root.grant::<capsec_core::permission::FsRead>();
    let spawn_cap = cap_root.grant::<capsec_core::permission::Spawn>();

    let path_arg = args.path.canonicalize().unwrap_or(args.path.clone());

    // Load config
    let cfg = match config::load_config(&path_arg, &fs_read) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Warning: {e}");
            config::Config::default()
        }
    };

    // Discover crates
    let discovery = match discovery::discover_crates(&path_arg, false, &spawn_cap, &fs_read) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!("Hint: Run from a directory containing Cargo.toml, or use --path");
            std::process::exit(2);
        }
    };
    let workspace_root = discovery.workspace_root;
    let crates = discovery.crates;

    // Filter crates
    let crates: Vec<_> = crates
        .into_iter()
        .filter(|c| {
            if c.is_dependency {
                return false;
            }
            if let Some(ref only) = args.only {
                let allowed: Vec<&str> = only.split(',').collect();
                return allowed.contains(&c.name.as_str());
            }
            if let Some(ref skip) = args.skip {
                let skipped: Vec<&str> = skip.split(',').collect();
                return !skipped.contains(&c.name.as_str());
            }
            true
        })
        .collect();

    // Set up detector with custom authorities
    let mut det = detector::Detector::new();
    let customs = config::custom_authorities(&cfg);
    det.add_custom_authorities(&customs);
    let crate_deny = cfg.deny.normalized_categories();

    // Parse, detect, and filter to deny violations only
    let mut violations = Vec::new();

    for krate in &crates {
        let source_files = discovery::discover_source_files(&krate.source_dir, &fs_read);

        for file_path in source_files {
            match parser::parse_file(&file_path, &fs_read) {
                Ok(parsed) => {
                    let findings = det.analyse(&parsed, &krate.name, &krate.version, &crate_deny);
                    violations.extend(findings.into_iter().filter(|f| f.is_deny_violation).map(
                        |mut f| {
                            f.file = make_relative(&f.file, &workspace_root);
                            f
                        },
                    ));
                }
                Err(e) => {
                    eprintln!("  Warning: {e}");
                }
            }
        }
    }

    if violations.is_empty() {
        if crate_deny.is_empty() {
            println!("OK  All #[capsec::deny] annotations are respected.");
        } else {
            println!(
                "OK  All deny rules are respected (crate-level: [{}])",
                crate_deny.join(", ")
            );
        }
        return;
    }

    // Report violations
    match args.format.as_str() {
        "json" => println!("{}", reporter::report_json(&violations, &[])),
        "sarif" => println!(
            "{}",
            reporter::report_sarif(&violations, &workspace_root, &[])
        ),
        _ => {
            // Text output grouped by function
            use std::collections::BTreeMap;
            let mut by_func: BTreeMap<String, Vec<&detector::Finding>> = BTreeMap::new();
            for v in &violations {
                let key = format!("{}:{} fn {}", v.file, v.function_line, v.function);
                by_func.entry(key).or_default().push(v);
            }

            for (func_key, funcs) in &by_func {
                println!("\nDENY VIOLATION in {func_key}");
                for v in funcs {
                    println!(
                        "  - {} (line {}) [{}]",
                        v.call_text,
                        v.call_line,
                        v.category.label().to_lowercase()
                    );
                }
            }

            let func_count = by_func.len();
            println!(
                "\n{func_count} {} with violations, {} total violations",
                if func_count == 1 {
                    "function"
                } else {
                    "functions"
                },
                violations.len()
            );
        }
    }

    std::process::exit(1);
}

fn run_badge(args: BadgeArgs) {
    let cap_root = capsec_core::root::root();
    let fs_read = cap_root.grant::<capsec_core::permission::FsRead>();
    let spawn_cap = cap_root.grant::<capsec_core::permission::Spawn>();

    let path_arg = args.path.canonicalize().unwrap_or(args.path.clone());

    // Load config
    let cfg = match config::load_config(&path_arg, &fs_read) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Warning: {e}");
            config::Config::default()
        }
    };

    // Discover and audit
    let discovery = match discovery::discover_crates(&path_arg, false, &spawn_cap, &fs_read) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(2);
        }
    };
    let workspace_root = discovery.workspace_root;
    let crates = discovery.crates;

    let mut det = detector::Detector::new();
    let customs = config::custom_authorities(&cfg);
    det.add_custom_authorities(&customs);
    let crate_deny = cfg.deny.normalized_categories();

    let mut all_findings = Vec::new();
    for krate in &crates {
        if krate.is_dependency {
            continue;
        }
        let source_files = discovery::discover_source_files(&krate.source_dir, &fs_read);
        for file_path in source_files {
            if config::should_exclude(&file_path, &cfg.analysis.exclude) {
                continue;
            }
            if let Ok(parsed) = parser::parse_file(&file_path, &fs_read) {
                let findings = det.analyse(&parsed, &krate.name, &krate.version, &crate_deny);
                all_findings.extend(findings);
            }
        }
    }

    // Normalize paths and apply allow rules
    for f in &mut all_findings {
        f.file = make_relative(&f.file, &workspace_root);
    }
    all_findings.retain(|f| !config::should_allow(f, &cfg));

    // Determine badge color based on highest risk level
    let threshold = Risk::parse(&args.fail_on);
    let has_critical = all_findings.iter().any(|f| f.risk >= Risk::Critical);
    let has_high = all_findings.iter().any(|f| f.risk >= Risk::High);
    let has_medium = all_findings.iter().any(|f| f.risk >= Risk::Medium);
    let exceeds_threshold = all_findings.iter().any(|f| f.risk >= threshold);

    let (color, message) = if all_findings.is_empty() {
        ("brightgreen", "0 findings".to_string())
    } else if has_critical {
        ("red", format!("{} findings", all_findings.len()))
    } else if has_high {
        ("orange", format!("{} findings", all_findings.len()))
    } else if has_medium {
        ("yellowgreen", format!("{} findings", all_findings.len()))
    } else {
        ("green", format!("{} findings", all_findings.len()))
    };

    if args.json {
        // shields.io endpoint JSON format
        let badge = serde_json::json!({
            "schemaVersion": 1,
            "label": "capsec",
            "message": message,
            "color": color,
            "isError": exceeds_threshold
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&badge).unwrap_or_default()
        );
    } else {
        // Markdown badge
        let encoded_message = message.replace(' ', "%20");
        println!(
            "[![capsec](https://img.shields.io/badge/capsec-{encoded_message}-{color})](https://github.com/auths-dev/capsec)"
        );
    }
}

fn make_relative(file_path: &str, workspace_root: &Path) -> String {
    Path::new(file_path)
        .strip_prefix(workspace_root)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| file_path.to_string())
}
