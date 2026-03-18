//! The authority registry — a structured catalogue of every standard library and common
//! third-party function that exercises ambient authority.
//!
//! This is the core knowledge base of `cargo-capsec`. Each entry maps a call pattern
//! (like `std::fs::read` or `TcpStream::connect`) to a [`Category`], [`Risk`] level,
//! and human-readable description.
//!
//! The registry is compiled into the binary via [`build_registry`]. Users can extend it
//! at runtime with custom patterns loaded from `.capsec.toml` (see [`CustomAuthority`]).

use serde::Serialize;

/// The kind of ambient authority a call exercises.
///
/// Every finding is classified into exactly one category. The detector uses this
/// to group and color-code output, and users can filter by category in `.capsec.toml`.
///
/// # Variants
///
/// | Category | What it covers | Color in output |
/// |----------|---------------|-----------------|
/// | `Fs` | Filesystem reads, writes, deletes | Blue |
/// | `Net` | TCP/UDP connections, HTTP requests, listeners | Red |
/// | `Env` | Environment variable access | Yellow |
/// | `Process` | Subprocess spawning (`Command::new`) | Magenta |
/// | `Ffi` | Foreign function interface (`extern` blocks) | Cyan |
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum Category {
    /// Filesystem access: reads, writes, deletes, directory operations.
    Fs,
    /// Network access: TCP/UDP connections, listeners, HTTP clients.
    Net,
    /// Environment variable reads and writes.
    Env,
    /// Subprocess spawning and execution.
    Process,
    /// Foreign function interface — `extern` blocks that bypass Rust's safety model.
    Ffi,
}

impl Category {
    /// Returns the short uppercase label used in text output (e.g., `"FS"`, `"NET"`).
    pub fn label(&self) -> &'static str {
        match self {
            Self::Fs => "FS",
            Self::Net => "NET",
            Self::Env => "ENV",
            Self::Process => "PROC",
            Self::Ffi => "FFI",
        }
    }
}

/// How dangerous a particular ambient authority call is.
///
/// Risk levels are ordered: `Low < Medium < High < Critical`. The CLI's `--min-risk`
/// and `--fail-on` flags use this ordering to filter and gate findings.
///
/// # Assignment rationale
///
/// | Level | Meaning | Examples |
/// |-------|---------|----------|
/// | `Low` | Read-only metadata, unlikely to leak secrets | `fs::metadata`, `env::current_dir` |
/// | `Medium` | Can read data or create resources | `fs::read`, `env::var`, `File::open` |
/// | `High` | Can write, delete, or open network connections | `fs::write`, `TcpStream::connect` |
/// | `Critical` | Can destroy data or execute arbitrary code | `remove_dir_all`, `Command::new` |
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Risk {
    /// Read-only metadata or low-impact queries.
    Low,
    /// Can read sensitive data or create resources.
    Medium,
    /// Can write data, delete files, or open network connections.
    High,
    /// Can destroy data or execute arbitrary code.
    Critical,
}

impl Risk {
    /// Returns the lowercase label used in JSON output and CLI flags (e.g., `"high"`).
    pub fn label(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Parses a risk level from a string. Returns [`Risk::Low`] for unrecognized input.
    ///
    /// Accepts: `"low"`, `"medium"`, `"high"`, `"critical"`.
    pub fn parse(s: &str) -> Self {
        match s {
            "low" => Self::Low,
            "medium" => Self::Medium,
            "high" => Self::High,
            "critical" => Self::Critical,
            _ => Self::Low,
        }
    }
}

/// A single entry in the authority registry.
///
/// Each `Authority` describes one way that Rust code can exercise ambient authority
/// over the host system. The [`Detector`](crate::detector::Detector) matches parsed
/// call sites against these entries to produce [`Finding`](crate::detector::Finding)s.
#[derive(Debug, Clone)]
pub struct Authority {
    /// How to match this authority against a call site.
    pub pattern: AuthorityPattern,
    /// What kind of ambient authority this is.
    pub category: Category,
    /// Finer-grained classification within the category (e.g., `"read"`, `"write"`, `"connect"`).
    pub subcategory: &'static str,
    /// How dangerous this call is.
    pub risk: Risk,
    /// Human-readable description shown in audit output.
    pub description: &'static str,
}

/// How an [`Authority`] matches against parsed call sites.
///
/// There are two matching strategies, reflecting the two kinds of calls in Rust:
///
/// - **Path matching** catches qualified calls like `std::fs::read(...)` or `File::open(...)`
/// - **Contextual method matching** catches method calls like `.output()` or `.spawn()`,
///   but only when a related path call (like `Command::new`) appears in the same function.
///   This eliminates false positives from common method names.
#[derive(Debug, Clone)]
pub enum AuthorityPattern {
    /// Match a fully qualified path by suffix.
    ///
    /// The call's expanded path must *end with* these segments. For example,
    /// `&["std", "fs", "read"]` matches both `std::fs::read(...)` and a bare `read(...)`
    /// that was imported via `use std::fs::read`.
    Path(&'static [&'static str]),

    /// Match a method call, but only if the same function also contains a call
    /// matching `requires_path`.
    ///
    /// This is the co-occurrence heuristic that prevents `.status()` on an HTTP response
    /// from being flagged as subprocess execution. The method only fires when the
    /// required context (e.g., `Command::new`) is present in the same function body.
    MethodWithContext {
        /// The method name to match (e.g., `"output"`, `"spawn"`, `"send_to"`).
        method: &'static str,
        /// A path pattern that must also appear in the same function for this match to fire.
        requires_path: &'static [&'static str],
    },
}

/// A user-defined authority pattern loaded from `.capsec.toml`.
///
/// Custom authorities let teams flag project-specific I/O entry points that the
/// built-in registry doesn't cover — database query functions, internal RPC clients,
/// secret-fetching utilities, etc.
///
/// # Example `.capsec.toml`
///
/// ```toml
/// [[authority]]
/// path = ["my_crate", "secrets", "fetch"]
/// category = "net"
/// risk = "critical"
/// description = "Fetches secrets from vault"
/// ```
#[derive(Debug, Clone)]
pub struct CustomAuthority {
    /// Path segments to match by suffix (e.g., `["my_crate", "secrets", "fetch"]`).
    pub path: Vec<String>,
    /// What kind of ambient authority this is.
    pub category: Category,
    /// How dangerous this call is.
    pub risk: Risk,
    /// Human-readable description shown in audit output.
    pub description: String,
}

/// Builds the compiled-in authority registry.
///
/// Returns every known ambient authority pattern for the Rust standard library
/// and popular third-party crates (tokio, reqwest, hyper). The registry contains
/// 35+ entries covering filesystem, network, environment, process, and FFI patterns.
///
/// This is called once at startup by [`Detector::new`](crate::detector::Detector::new).
/// Users can extend it with [`CustomAuthority`] entries from `.capsec.toml`.
pub fn build_registry() -> Vec<Authority> {
    vec![
        //  Filesystem: std
        Authority {
            pattern: AuthorityPattern::Path(&["std", "fs", "read"]),
            category: Category::Fs,
            subcategory: "read",
            risk: Risk::Medium,
            description: "Read arbitrary file contents",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["std", "fs", "read_to_string"]),
            category: Category::Fs,
            subcategory: "read",
            risk: Risk::Medium,
            description: "Read arbitrary file contents as string",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["std", "fs", "read_dir"]),
            category: Category::Fs,
            subcategory: "read",
            risk: Risk::Low,
            description: "List directory contents",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["std", "fs", "metadata"]),
            category: Category::Fs,
            subcategory: "read",
            risk: Risk::Low,
            description: "Read file metadata",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["std", "fs", "write"]),
            category: Category::Fs,
            subcategory: "write",
            risk: Risk::High,
            description: "Write arbitrary file contents",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["std", "fs", "create_dir_all"]),
            category: Category::Fs,
            subcategory: "write",
            risk: Risk::Medium,
            description: "Create directory tree",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["std", "fs", "remove_file"]),
            category: Category::Fs,
            subcategory: "write",
            risk: Risk::High,
            description: "Delete a file",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["std", "fs", "remove_dir_all"]),
            category: Category::Fs,
            subcategory: "write",
            risk: Risk::Critical,
            description: "Recursively delete a directory tree",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["std", "fs", "rename"]),
            category: Category::Fs,
            subcategory: "write",
            risk: Risk::Medium,
            description: "Rename/move a file",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["std", "fs", "copy"]),
            category: Category::Fs,
            subcategory: "read+write",
            risk: Risk::Medium,
            description: "Copy a file",
        },
        //  Filesystem: File
        Authority {
            pattern: AuthorityPattern::Path(&["File", "open"]),
            category: Category::Fs,
            subcategory: "read",
            risk: Risk::Medium,
            description: "Open a file for reading",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["File", "create"]),
            category: Category::Fs,
            subcategory: "write",
            risk: Risk::High,
            description: "Create/truncate a file for writing",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["OpenOptions", "open"]),
            category: Category::Fs,
            subcategory: "read+write",
            risk: Risk::Medium,
            description: "Open file with custom options",
        },
        //  Filesystem: tokio
        Authority {
            pattern: AuthorityPattern::Path(&["tokio", "fs", "read"]),
            category: Category::Fs,
            subcategory: "read",
            risk: Risk::Medium,
            description: "Async read file contents",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["tokio", "fs", "read_to_string"]),
            category: Category::Fs,
            subcategory: "read",
            risk: Risk::Medium,
            description: "Async read file as string",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["tokio", "fs", "write"]),
            category: Category::Fs,
            subcategory: "write",
            risk: Risk::High,
            description: "Async write file contents",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["tokio", "fs", "remove_file"]),
            category: Category::Fs,
            subcategory: "write",
            risk: Risk::High,
            description: "Async delete a file",
        },
        //  Network: std
        Authority {
            pattern: AuthorityPattern::Path(&["TcpStream", "connect"]),
            category: Category::Net,
            subcategory: "connect",
            risk: Risk::High,
            description: "Open outbound TCP connection",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["TcpListener", "bind"]),
            category: Category::Net,
            subcategory: "bind",
            risk: Risk::High,
            description: "Bind a TCP listener to a port",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["UdpSocket", "bind"]),
            category: Category::Net,
            subcategory: "bind",
            risk: Risk::High,
            description: "Bind a UDP socket",
        },
        // send_to only flagged if UdpSocket::bind is in the same function
        Authority {
            pattern: AuthorityPattern::MethodWithContext {
                method: "send_to",
                requires_path: &["UdpSocket", "bind"],
            },
            category: Category::Net,
            subcategory: "connect",
            risk: Risk::High,
            description: "Send UDP datagram to address",
        },
        //  Network: tokio
        Authority {
            pattern: AuthorityPattern::Path(&["tokio", "net", "TcpStream", "connect"]),
            category: Category::Net,
            subcategory: "connect",
            risk: Risk::High,
            description: "Async outbound TCP connection",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["tokio", "net", "TcpListener", "bind"]),
            category: Category::Net,
            subcategory: "bind",
            risk: Risk::High,
            description: "Async bind TCP listener",
        },
        //  Network: reqwest
        Authority {
            pattern: AuthorityPattern::Path(&["reqwest", "get"]),
            category: Category::Net,
            subcategory: "connect",
            risk: Risk::High,
            description: "HTTP GET request",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["reqwest", "Client", "new"]),
            category: Category::Net,
            subcategory: "connect",
            risk: Risk::Medium,
            description: "Create HTTP client",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["reqwest", "Client", "get"]),
            category: Category::Net,
            subcategory: "connect",
            risk: Risk::High,
            description: "HTTP GET via client",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["reqwest", "Client", "post"]),
            category: Category::Net,
            subcategory: "connect",
            risk: Risk::High,
            description: "HTTP POST via client",
        },
        //  Network: hyper
        Authority {
            pattern: AuthorityPattern::Path(&["hyper", "Client", "request"]),
            category: Category::Net,
            subcategory: "connect",
            risk: Risk::High,
            description: "Hyper HTTP request",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["hyper", "Server", "bind"]),
            category: Category::Net,
            subcategory: "bind",
            risk: Risk::High,
            description: "Bind Hyper HTTP server",
        },
        //  Environment
        // (no duplicate ["env", "var"] — import expansion handles `use std::env`)
        Authority {
            pattern: AuthorityPattern::Path(&["std", "env", "var"]),
            category: Category::Env,
            subcategory: "read",
            risk: Risk::Medium,
            description: "Read environment variable",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["std", "env", "vars"]),
            category: Category::Env,
            subcategory: "read",
            risk: Risk::Medium,
            description: "Read all environment variables",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["std", "env", "set_var"]),
            category: Category::Env,
            subcategory: "write",
            risk: Risk::High,
            description: "Modify environment variable",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["std", "env", "remove_var"]),
            category: Category::Env,
            subcategory: "write",
            risk: Risk::Medium,
            description: "Remove environment variable",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["std", "env", "current_dir"]),
            category: Category::Env,
            subcategory: "read",
            risk: Risk::Low,
            description: "Read current working directory",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["std", "env", "set_current_dir"]),
            category: Category::Env,
            subcategory: "write",
            risk: Risk::High,
            description: "Change working directory",
        },
        //  Process
        Authority {
            pattern: AuthorityPattern::Path(&["Command", "new"]),
            category: Category::Process,
            subcategory: "spawn",
            risk: Risk::Critical,
            description: "Create command for subprocess execution",
        },
        // .output(), .spawn(), .status() only flagged if Command::new is in the same function
        Authority {
            pattern: AuthorityPattern::MethodWithContext {
                method: "output",
                requires_path: &["Command", "new"],
            },
            category: Category::Process,
            subcategory: "spawn",
            risk: Risk::Critical,
            description: "Execute subprocess and capture output",
        },
        Authority {
            pattern: AuthorityPattern::MethodWithContext {
                method: "spawn",
                requires_path: &["Command", "new"],
            },
            category: Category::Process,
            subcategory: "spawn",
            risk: Risk::Critical,
            description: "Spawn subprocess",
        },
        Authority {
            pattern: AuthorityPattern::MethodWithContext {
                method: "status",
                requires_path: &["Command", "new"],
            },
            category: Category::Process,
            subcategory: "spawn",
            risk: Risk::Critical,
            description: "Execute subprocess and get exit status",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_not_empty() {
        let reg = build_registry();
        assert!(reg.len() > 30);
    }

    #[test]
    fn all_categories_represented() {
        let reg = build_registry();
        let cats: std::collections::HashSet<_> = reg.iter().map(|a| &a.category).collect();
        assert!(cats.contains(&Category::Fs));
        assert!(cats.contains(&Category::Net));
        assert!(cats.contains(&Category::Env));
        assert!(cats.contains(&Category::Process));
    }

    #[test]
    fn risk_ordering() {
        assert!(Risk::Low < Risk::Medium);
        assert!(Risk::Medium < Risk::High);
        assert!(Risk::High < Risk::Critical);
    }
}
