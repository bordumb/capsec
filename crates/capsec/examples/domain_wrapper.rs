//! Example: Domain Wrapper pattern
//!
//! Demonstrates injecting capabilities at construction so that all
//! domain methods have clean, cap-free signatures.
//!
//! The capability is mentioned exactly once: in the constructor. Every
//! method after that is a pure domain API. Callers never see `Has<P>`
//! or `Cap<P>` in the method signatures.
//!
//! Key concepts:
//! - Store `Cap<P>` by value in the struct (not by reference — avoids lifetimes)
//! - Constructor takes a `Cap<P>` parameter — the only capability boundary
//! - All methods use `&self.cap` internally to call capsec-std functions
//! - Callers interact with a domain-typed API, not a security API
//!
//! See also: `context_struct.rs` for reducing parameter count, and
//! `layered_app.rs` for combining both patterns.

use capsec::prelude::*;

// ─── Domain Wrapper: ConfigService ───────────────────────────────

/// A file-based configuration service.
///
/// Capabilities are injected at construction. The methods expose a
/// pure domain API — no `Has<P>` bounds, no capsec types visible.
struct ConfigService {
    cap: Cap<FsRead>,
    base_dir: String,
}

#[allow(dead_code)] // all methods shown for completeness
impl ConfigService {
    /// The constructor is the ONLY place that mentions capabilities.
    fn new(base_dir: impl Into<String>, cap: Cap<FsRead>) -> Self {
        Self {
            cap,
            base_dir: base_dir.into(),
        }
    }

    /// Loads a config file by key name.
    ///
    /// Clean domain API — the caller doesn't know or care about capabilities.
    fn get(&self, key: &str) -> Option<String> {
        let path = format!("{}/{}.toml", self.base_dir, key);
        capsec::fs::read_to_string(&path, &self.cap).ok()
    }

    /// Checks if a config key exists on disk.
    fn exists(&self, key: &str) -> bool {
        let path = format!("{}/{}.toml", self.base_dir, key);
        capsec::fs::metadata(&path, &self.cap).is_ok()
    }

    /// Lists all available config keys (file stems in the base directory).
    fn list_keys(&self) -> Vec<String> {
        capsec::fs::read_dir(&self.base_dir, &self.cap)
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let path = e.path();
                if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                    path.file_stem().and_then(|s| s.to_str().map(String::from))
                } else {
                    None
                }
            })
            .collect()
    }
}

// ─── Domain Wrapper: OutputWriter ────────────────────────────────

/// Writes structured output to a directory.
///
/// Like ConfigService, capabilities are injected once at construction.
struct OutputWriter {
    cap: Cap<FsWrite>,
    output_dir: String,
}

impl OutputWriter {
    fn new(output_dir: impl Into<String>, cap: Cap<FsWrite>) -> Self {
        Self {
            cap,
            output_dir: output_dir.into(),
        }
    }

    /// Saves data to a named output file. No caps in the signature.
    fn save(&self, name: &str, data: &str) -> Result<(), CapSecError> {
        let path = format!("{}/{}", self.output_dir, name);
        capsec::fs::write(&path, data.as_bytes(), &self.cap)
    }

    /// Ensures the output directory exists.
    fn ensure_dir(&self) -> Result<(), CapSecError> {
        capsec::fs::create_dir_all(&self.output_dir, &self.cap)
    }
}

// ─── Application logic: no capsec imports needed ─────────────────

/// Processes configuration and writes output.
///
/// This function has ZERO capsec imports. It works entirely with
/// domain-typed wrappers. The capability boundary is invisible here.
fn process_and_save(config: &ConfigService, output: &OutputWriter) {
    // Load config (domain API — no caps)
    let db_config = config
        .get("database")
        .unwrap_or_else(|| "host=localhost port=5432".into());

    let app_config = config
        .get("app")
        .unwrap_or_else(|| "mode=development".into());

    // Process (pure computation)
    let report = format!(
        "Config Report\n=============\nDB: {}\nApp: {}\nKeys found: {:?}",
        db_config,
        app_config,
        config.list_keys()
    );

    // Write output (domain API — no caps)
    if let Err(e) = output.ensure_dir() {
        eprintln!("Warning: could not create output dir: {e}");
    }
    match output.save("report.txt", &report) {
        Ok(()) => println!("Report saved."),
        Err(e) => eprintln!("Warning: could not save report: {e}"),
    }

    println!("{report}");
}

// ─── Entry point ─────────────────────────────────────────────────

#[capsec::main]
fn main(root: CapRoot) {
    // Inject capabilities at the domain wrapper boundary.
    // After this point, no function sees Cap<P> or Has<P>.
    let config = ConfigService::new("/tmp/capsec-demo/config", root.grant::<FsRead>());
    let output = OutputWriter::new("/tmp/capsec-demo/output", root.grant::<FsWrite>());

    // Pure domain logic — capsec is invisible below this line.
    process_and_save(&config, &output);

    println!("\nDone. The domain wrapper pattern hid all capabilities from business logic.");
}
