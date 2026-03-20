mod authorities;
mod baseline;
mod cli;
mod config;
mod detector;
mod discovery;
mod parser;
mod reporter;

use authorities::Risk;
use clap::Parser;
use cli::{AuditArgs, BadgeArgs, CargoSubcommand, CheckDenyArgs, Cli, Commands};

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

    // Load config
    let cfg = match config::load_config(&path_arg, &fs_read) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Warning: {e}");
            config::Config::default()
        }
    };

    // Discover crates
    let discovery =
        match discovery::discover_crates(&path_arg, args.include_deps, &spawn_cap, &fs_read) {
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
            if !args.include_deps && c.is_dependency {
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

    // Parse and detect
    let mut all_findings = Vec::new();

    for krate in &crates {
        let source_files = discovery::discover_source_files(&krate.source_dir, &fs_read);

        for file_path in source_files {
            if config::should_exclude(&file_path, &cfg.analysis.exclude) {
                continue;
            }

            match parser::parse_file(&file_path, &fs_read) {
                Ok(parsed) => {
                    let findings = det.analyse(&parsed, &krate.name, &krate.version);
                    all_findings.extend(findings);
                }
                Err(e) => {
                    eprintln!("  Warning: {e}");
                }
            }
        }
    }

    // Filter by risk level
    let min_risk = Risk::parse(&args.min_risk);
    all_findings.retain(|f| f.risk >= min_risk);

    // Apply allow rules
    all_findings.retain(|f| !config::should_allow(f, &cfg));

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
            "json" => println!("{}", reporter::report_json(&all_findings)),
            "sarif" => println!("{}", reporter::report_sarif(&all_findings, &workspace_root)),
            _ => reporter::report_text(&all_findings),
        }
    }

    // Save baseline
    if args.baseline {
        match baseline::save_baseline(&workspace_root, &all_findings, &fs_write) {
            Ok(()) => eprintln!("Baseline saved to .capsec-baseline.json"),
            Err(e) => eprintln!("Warning: Failed to save baseline: {e}"),
        }
    }

    // Exit code
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

    // Set up detector
    let det = detector::Detector::new();

    // Parse, detect, and filter to deny violations only
    let mut violations = Vec::new();

    for krate in &crates {
        let source_files = discovery::discover_source_files(&krate.source_dir, &fs_read);

        for file_path in source_files {
            match parser::parse_file(&file_path, &fs_read) {
                Ok(parsed) => {
                    let findings = det.analyse(&parsed, &krate.name, &krate.version);
                    violations.extend(findings.into_iter().filter(|f| f.is_deny_violation));
                }
                Err(e) => {
                    eprintln!("  Warning: {e}");
                }
            }
        }
    }

    if violations.is_empty() {
        println!("OK  All #[capsec::deny] annotations are respected.");
        return;
    }

    // Report violations
    match args.format.as_str() {
        "json" => println!("{}", reporter::report_json(&violations)),
        "sarif" => println!("{}", reporter::report_sarif(&violations, &workspace_root)),
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
    let crates = discovery.crates;

    let mut det = detector::Detector::new();
    let customs = config::custom_authorities(&cfg);
    det.add_custom_authorities(&customs);

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
                let findings = det.analyse(&parsed, &krate.name, &krate.version);
                all_findings.extend(findings);
            }
        }
    }

    // Apply allow rules
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
            "[![capsec](https://img.shields.io/badge/capsec-{encoded_message}-{color})](https://github.com/bordumb/capsec)"
        );
    }
}
