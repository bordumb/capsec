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
use cli::{AuditArgs, CargoSubcommand, Cli, Commands};

fn main() {
    let cli = Cli::parse();
    let CargoSubcommand::Capsec { command } = cli.command;

    match command {
        Commands::Audit(args) => run_audit(args),
    }
}

fn run_audit(args: AuditArgs) {
    let workspace_root = args.path.canonicalize().unwrap_or(args.path.clone());

    // Load config
    let cfg = match config::load_config(&workspace_root) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Warning: {e}");
            config::Config::default()
        }
    };

    // Discover crates
    let crates = match discovery::discover_crates(&workspace_root, args.include_deps) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!("Hint: Run from a directory containing Cargo.toml, or use --path");
            std::process::exit(2);
        }
    };

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
        let source_files = discovery::discover_source_files(&krate.source_dir);

        for file_path in source_files {
            if config::should_exclude(&file_path, &cfg.analysis.exclude) {
                continue;
            }

            match parser::parse_file(&file_path) {
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
    let min_risk = Risk::from_str(&args.min_risk);
    all_findings.retain(|f| f.risk >= min_risk);

    // Apply allow rules
    all_findings.retain(|f| !config::should_allow(f, &cfg));

    // Load baseline once if needed for diff or fail-on
    let baseline_data = if args.diff || args.fail_on.is_some() {
        baseline::load_baseline(&workspace_root)
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
            "sarif" => println!("{}", reporter::report_sarif(&all_findings)),
            _ => reporter::report_text(&all_findings),
        }
    }

    // Save baseline
    if args.baseline {
        match baseline::save_baseline(&workspace_root, &all_findings) {
            Ok(()) => eprintln!("Baseline saved to .capsec-baseline.json"),
            Err(e) => eprintln!("Warning: Failed to save baseline: {e}"),
        }
    }

    // Exit code
    if let Some(ref fail_level) = args.fail_on {
        let threshold = Risk::from_str(fail_level);

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
