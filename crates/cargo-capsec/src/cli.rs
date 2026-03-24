use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "cargo-capsec",
    about = "Static capability audit for Rust — find out what your code can do to the outside world",
    version,
    after_help = "EXAMPLES:\n  \
        cargo capsec audit                    Audit workspace crates\n  \
        cargo capsec audit --include-deps     Audit workspace + dependencies\n  \
        cargo capsec audit --format json      JSON output for CI\n  \
        cargo capsec audit --format sarif     SARIF for GitHub Code Scanning\n  \
        cargo capsec audit --baseline         Save results as baseline\n  \
        cargo capsec audit --diff             Show changes since last baseline\n  \
        cargo capsec audit --min-risk high    Only show high and critical findings\n  \
        cargo capsec check-deny               Verify #[capsec::deny] annotations\n  \
        cargo capsec badge                    Generate shields.io badge\n  \
        cargo capsec badge --json             Output shields.io endpoint JSON"
)]
pub struct Cli {
    /// When invoked as `cargo capsec`, cargo passes "capsec" as the first arg.
    /// This hidden subcommand absorbs it.
    #[command(subcommand)]
    pub command: CargoSubcommand,
}

#[derive(Subcommand)]
pub enum CargoSubcommand {
    /// The capsec subcommand (absorbs "capsec" when run via cargo)
    #[command(name = "capsec")]
    Capsec {
        #[command(subcommand)]
        command: Commands,
    },
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan for ambient authority usage
    Audit(AuditArgs),
    /// Verify #[capsec::deny] annotations are respected
    CheckDeny(CheckDenyArgs),
    /// Generate a shields.io badge from audit results
    Badge(BadgeArgs),
    /// Bootstrap capsec for an existing codebase
    Init(InitArgs),
    /// Compare capability profiles between two crate versions
    Diff(DiffArgs),
    /// Compare capability profiles of two different crates
    Compare(CompareArgs),
}

#[derive(clap::Args)]
pub struct AuditArgs {
    /// Path to workspace root
    #[arg(short, long, default_value = ".")]
    pub path: PathBuf,

    /// Output format
    #[arg(short, long, default_value = "text", value_parser = ["text", "json", "sarif"])]
    pub format: String,

    /// Also scan dependency source code from cargo cache.
    /// With cross-crate propagation, findings from dependencies are
    /// transitively attributed to workspace functions that call them.
    #[arg(long)]
    pub include_deps: bool,

    /// Only scan dependencies, skip workspace crates (supply-chain view)
    #[arg(long, conflicts_with = "include_deps")]
    pub deps_only: bool,

    /// Maximum dependency depth to scan (0 = unlimited, default: 1 = direct deps only).
    /// Only meaningful with --include-deps or --deps-only.
    #[arg(long, default_value_t = 1)]
    pub dep_depth: usize,

    /// Use MIR-based deep analysis (requires nightly toolchain + capsec-driver).
    /// Catches macro-expanded FFI, trait dispatch, and generic instantiation
    /// that syntactic analysis misses.
    #[arg(long)]
    pub deep: bool,

    /// Minimum risk level to report
    #[arg(long, default_value = "low", value_parser = ["low", "medium", "high", "critical"])]
    pub min_risk: String,

    /// Save current results as baseline
    #[arg(long)]
    pub baseline: bool,

    /// Show diff against saved baseline
    #[arg(long)]
    pub diff: bool,

    /// Fail (exit 1) if any findings at or above this risk level
    #[arg(long, value_parser = ["low", "medium", "high", "critical"])]
    pub fail_on: Option<String>,

    /// Only scan these crates (comma-separated)
    #[arg(long)]
    pub only: Option<String>,

    /// Skip these crates (comma-separated)
    #[arg(long)]
    pub skip: Option<String>,

    /// Suppress output (exit code only, for CI)
    #[arg(short, long)]
    pub quiet: bool,
}

#[derive(clap::Args)]
pub struct CheckDenyArgs {
    /// Path to workspace root
    #[arg(short, long, default_value = ".")]
    pub path: PathBuf,

    /// Output format
    #[arg(short, long, default_value = "text", value_parser = ["text", "json", "sarif"])]
    pub format: String,

    /// Only scan these crates (comma-separated)
    #[arg(long)]
    pub only: Option<String>,

    /// Skip these crates (comma-separated)
    #[arg(long)]
    pub skip: Option<String>,
}

#[derive(clap::Args)]
pub struct BadgeArgs {
    /// Path to workspace root
    #[arg(short, long, default_value = ".")]
    pub path: PathBuf,

    /// Output shields.io endpoint JSON instead of markdown
    #[arg(long)]
    pub json: bool,

    /// Risk threshold for badge color (default: high)
    #[arg(long, default_value = "high", value_parser = ["low", "medium", "high", "critical"])]
    pub fail_on: String,
}

#[derive(clap::Args)]
pub struct InitArgs {
    /// Path to workspace root
    #[arg(short, long, default_value = ".")]
    pub path: PathBuf,

    /// Generate CI config (github, gitlab, generic)
    #[arg(long, value_parser = ["github", "gitlab", "generic"])]
    pub ci: Option<String>,

    /// Run interactively (prompt for each choice)
    #[arg(long)]
    pub interactive: bool,

    /// Show migration priority report after init
    #[arg(long)]
    pub report: bool,

    /// Exclude test/bench/example directories (default: true)
    #[arg(long, default_value_t = true)]
    pub exclude_tests: bool,

    /// Save baseline alongside config (default: true)
    #[arg(long, default_value_t = true)]
    pub baseline: bool,

    /// Overwrite existing .capsec.toml
    #[arg(long)]
    pub force: bool,
}

#[derive(clap::Args)]
pub struct DiffArgs {
    /// First crate specifier: name@version
    pub left: String,

    /// Second crate specifier: name@version
    pub right: String,

    /// Output format
    #[arg(short, long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Fail (exit 1) if new findings were added
    #[arg(long)]
    pub fail_on_new: bool,
}

#[derive(clap::Args)]
pub struct CompareArgs {
    /// First crate: name or name@version
    pub left: String,

    /// Second crate: name or name@version
    pub right: String,

    /// Output format
    #[arg(short, long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,
}
