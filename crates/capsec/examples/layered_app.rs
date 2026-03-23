//! Example: Layered Composition (recommended for large apps)
//!
//! Combines Context Structs at the boundary with Domain Wrappers in the core.
//! This is the recommended architecture for production applications.
//!
//! The three layers:
//!
//! 1. **Startup** — `main()` creates a `ServerCaps` context with `SendCap` fields
//!    (thread-safe). This is the single point of authority.
//!
//! 2. **Request boundary** — extracts caps from the shared context, constructs
//!    domain wrappers with minimum-needed capabilities. In a real app this would
//!    be an Axum handler, Actix route, or CLI subcommand dispatch.
//!
//! 3. **Core logic** — works exclusively with domain wrappers. No capsec types,
//!    no `Has<P>` bounds, no capability tokens visible at all.
//!
//! Key concepts:
//! - `SendCap<P>` for thread-safe shared state (implements Send + Sync)
//! - `.as_cap()` to recover thread-local `Cap<P>` per request
//! - Domain wrappers store `Cap<P>` by value (ZST, no lifetime noise)
//! - Core logic is completely decoupled from capsec
//!
//! See also: `context_struct.rs` and `domain_wrapper.rs` for the
//! individual patterns.

use capsec::SendCap;
use capsec::prelude::*;

// ═══════════════════════════════════════════════════════════════════
// Layer 1: Capability Boundary (startup)
// ═══════════════════════════════════════════════════════════════════

/// Thread-safe capability context for the entire server.
///
/// Uses `SendCap<P>` (Send + Sync) so it can be shared via Arc,
/// Axum State, or Actix Data. Clone is free — all fields are ZSTs.
#[derive(Clone)]
struct ServerCaps {
    fs_read: SendCap<FsRead>,
    fs_write: SendCap<FsWrite>,
    net: SendCap<NetConnect>,
    env: SendCap<EnvRead>,
}

// ═══════════════════════════════════════════════════════════════════
// Layer 2: Request Boundary (per-request wiring)
// ═══════════════════════════════════════════════════════════════════

/// Simulates a request handler.
///
/// In a real Axum app this would be:
/// ```ignore
/// async fn handle_sync(State(caps): State<ServerCaps>) -> impl IntoResponse { ... }
/// ```
///
/// This layer extracts thread-local caps from the shared context and
/// constructs domain wrappers with minimum needed capabilities.
fn handle_sync_request(caps: &ServerCaps) -> Result<String, CapSecError> {
    // Recover thread-local Cap<P> from SendCap<P>
    // (.as_cap() is free — both types are ZSTs)
    let config_svc = ConfigService::new("/tmp/capsec-demo/config", caps.fs_read.as_cap());
    let storage = FileStorage::new(caps.fs_read.as_cap(), caps.fs_write.as_cap());
    let api = ApiClient::new("api.example.com", caps.net.as_cap());

    // Hand off to core logic — no capsec types below this point
    sync_workflow(&config_svc, &storage, &api)
}

fn handle_status_request(caps: &ServerCaps) -> String {
    let config_svc = ConfigService::new("/tmp/capsec-demo/config", caps.fs_read.as_cap());
    let env_cap = caps.env.as_cap();

    // Only needs config + env — does NOT get fs_write, net, or spawn
    status_check(&config_svc, &env_cap)
}

// ═══════════════════════════════════════════════════════════════════
// Layer 3: Core Logic (no capsec imports)
// ═══════════════════════════════════════════════════════════════════

/// Business logic for the sync workflow.
///
/// This function has ZERO capsec imports. It works entirely with
/// domain-typed wrappers. The "coloring" stops at Layer 2.
fn sync_workflow(
    config: &ConfigService,
    storage: &FileStorage,
    api: &ApiClient,
) -> Result<String, CapSecError> {
    // Load configuration (domain API)
    let settings = config.get("sync").unwrap_or_else(|| "interval=60".into());

    // Fetch remote data (domain API)
    let remote_data = api.get("/data/latest");

    // Save locally (domain API)
    storage.save("/tmp/capsec-demo/synced.json", &remote_data)?;

    Ok(format!(
        "Synced {} bytes with settings: {settings}",
        remote_data.len()
    ))
}

/// Business logic for the status check.
///
/// Also zero capsec imports. Takes domain wrappers + a single cap
/// for env access (leaf-level, so `&impl CapProvider<P>` is appropriate).
fn status_check(config: &ConfigService, env_cap: &impl CapProvider<EnvRead>) -> String {
    let version = capsec::env::var("APP_VERSION", env_cap).unwrap_or_else(|_| "dev".into());

    let config_ok = config.get("app").is_some();
    let db_ok = config.get("database").is_some();

    format!(
        "Status: version={version} config={} database={}",
        if config_ok { "ok" } else { "missing" },
        if db_ok { "ok" } else { "missing" },
    )
}

// ═══════════════════════════════════════════════════════════════════
// Domain Wrappers
// ═══════════════════════════════════════════════════════════════════

/// File-based config service. Cap injected at construction.
struct ConfigService {
    cap: Cap<FsRead>,
    base_dir: String,
}

impl ConfigService {
    fn new(base_dir: impl Into<String>, cap: Cap<FsRead>) -> Self {
        Self {
            cap,
            base_dir: base_dir.into(),
        }
    }

    fn get(&self, key: &str) -> Option<String> {
        let path = format!("{}/{}.toml", self.base_dir, key);
        capsec::fs::read_to_string(&path, &self.cap).ok()
    }
}

/// File storage service. Needs both read and write.
#[allow(dead_code)] // fields/methods shown for completeness
struct FileStorage {
    read_cap: Cap<FsRead>,
    write_cap: Cap<FsWrite>,
}

#[allow(dead_code)]
impl FileStorage {
    fn new(read_cap: Cap<FsRead>, write_cap: Cap<FsWrite>) -> Self {
        Self {
            read_cap,
            write_cap,
        }
    }

    fn load(&self, name: &str) -> Result<Vec<u8>, CapSecError> {
        capsec::fs::read(name, &self.read_cap)
    }

    fn save(&self, name: &str, data: &str) -> Result<(), CapSecError> {
        capsec::fs::write(name, data.as_bytes(), &self.write_cap)
    }
}

/// HTTP API client. Only needs NetConnect.
#[allow(dead_code)] // cap field used in real impl, placeholder here
struct ApiClient {
    cap: Cap<NetConnect>,
    base_url: String,
}

impl ApiClient {
    fn new(base_url: impl Into<String>, cap: Cap<NetConnect>) -> Self {
        Self {
            cap,
            base_url: base_url.into(),
        }
    }

    /// In a real app, this would use capsec::net::tcp_connect or reqwest.
    fn get(&self, path: &str) -> String {
        // Placeholder: in reality you'd do:
        //   let stream = capsec::net::tcp_connect(&addr, &self.cap)?;
        //   ... HTTP over the stream ...
        format!(
            "{{\"source\":\"{}{}\",\"data\":\"...\"}}",
            self.base_url, path
        )
    }
}

// ═══════════════════════════════════════════════════════════════════
// Entry Point
// ═══════════════════════════════════════════════════════════════════

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Layer 1: single point of authority
    let root = capsec::root();
    let caps = ServerCaps {
        fs_read: root.grant::<FsRead>().make_send(),
        fs_write: root.grant::<FsWrite>().make_send(),
        net: root.grant::<NetConnect>().make_send(),
        env: root.grant::<EnvRead>().make_send(),
    };

    // Simulate two requests hitting the server:

    println!("── Sync Request ──");
    match handle_sync_request(&caps) {
        Ok(result) => println!("{result}"),
        Err(e) => println!("Sync failed (expected in demo): {e}"),
    }

    println!();

    println!("── Status Request ──");
    let status = handle_status_request(&caps);
    println!("{status}");

    println!();
    println!("The three layers:");
    println!("  1. main() created ServerCaps with SendCap fields (thread-safe)");
    println!("  2. Handlers extracted caps and built domain wrappers");
    println!("  3. Core logic used domain wrappers only — zero capsec imports");

    Ok(())
}
