//! capsec-driver — MIR-based deep analysis for capsec.
//!
//! This binary is used as `RUSTC_WRAPPER` to intercept compilation
//! of all crates (workspace + dependencies) and analyze their MIR for
//! ambient authority usage.
//!
//! It walks every function's MIR, extracts `TerminatorKind::Call` targets,
//! classifies them against known authority patterns (FS, NET, ENV, PROC, FFI),
//! and writes findings as JSONL to a file specified by `$CAPSEC_DEEP_OUTPUT`.
//!
//! Requires nightly Rust with the `rustc-dev` component installed.

#![feature(rustc_private)]

extern crate rustc_driver;
extern crate rustc_hir;
extern crate rustc_interface;
extern crate rustc_middle;
extern crate rustc_session;
extern crate rustc_span;

use rustc_driver::Compilation;
use rustc_hir::def::DefKind;
use rustc_hir::def_id::LOCAL_CRATE;
use rustc_interface::interface::Compiler;
use rustc_middle::mir::TerminatorKind;
use rustc_middle::ty::TyCtxt;
use serde::Serialize;
use std::io::Write;

/// A finding from MIR analysis — matches the capsec Finding JSON schema.
#[derive(Debug, Clone, Serialize)]
struct DeepFinding {
    file: String,
    function: String,
    function_line: usize,
    call_line: usize,
    call_col: usize,
    call_text: String,
    category: String,
    subcategory: String,
    risk: String,
    description: String,
    is_build_script: bool,
    crate_name: String,
    crate_version: String,
    is_deny_violation: bool,
    is_transitive: bool,
}

/// Authority category for a detected call.
#[derive(Debug, Clone)]
struct AuthorityMatch {
    category: &'static str,
    subcategory: &'static str,
    risk: &'static str,
    description: &'static str,
}

/// Classifies a resolved function path against known authority patterns.
/// Risk values use PascalCase to match the `Risk` enum serialization in cargo-capsec.
fn classify_authority(path: &str) -> Option<AuthorityMatch> {
    // Filesystem
    if path.starts_with("std::fs::") || path.starts_with("core::fs::") {
        let subcategory = if path.contains("write") || path.contains("create") || path.contains("remove") || path.contains("rename") {
            "write"
        } else {
            "read"
        };
        let risk = if path.contains("remove_dir_all") {
            "Critical"
        } else if path.contains("write") || path.contains("remove") || path.contains("create") {
            "High"
        } else {
            "Medium"
        };
        return Some(AuthorityMatch {
            category: "Fs",
            subcategory,
            risk,
            description: "Filesystem access",
        });
    }

    // File::open, File::create
    if (path.contains("::File::open") || path.contains("::File::create"))
        && (path.starts_with("std::") || path.contains("fs::"))
    {
        let (sub, risk) = if path.contains("create") {
            ("write", "High")
        } else {
            ("read", "Medium")
        };
        return Some(AuthorityMatch {
            category: "Fs",
            subcategory: sub,
            risk,
            description: "File access",
        });
    }

    // OpenOptions
    if path.contains("OpenOptions") && path.contains("open") {
        return Some(AuthorityMatch {
            category: "Fs",
            subcategory: "read+write",
            risk: "Medium",
            description: "File access with custom options",
        });
    }

    // Tokio filesystem
    if path.starts_with("tokio::fs::") {
        return Some(AuthorityMatch {
            category: "Fs",
            subcategory: "async",
            risk: "Medium",
            description: "Async filesystem access",
        });
    }

    // Network — std
    if path.starts_with("std::net::") {
        let risk = if path.contains("connect") || path.contains("bind") {
            "High"
        } else {
            "Medium"
        };
        return Some(AuthorityMatch {
            category: "Net",
            subcategory: "connect",
            risk,
            description: "Network access",
        });
    }

    // Network — tokio
    if path.starts_with("tokio::net::") {
        return Some(AuthorityMatch {
            category: "Net",
            subcategory: "async_connect",
            risk: "High",
            description: "Async network access",
        });
    }

    // Network — reqwest
    if path.starts_with("reqwest::") {
        return Some(AuthorityMatch {
            category: "Net",
            subcategory: "http",
            risk: "High",
            description: "HTTP request",
        });
    }

    // Network — hyper
    if path.starts_with("hyper::") && (path.contains("request") || path.contains("bind") || path.contains("connect")) {
        return Some(AuthorityMatch {
            category: "Net",
            subcategory: "http",
            risk: "High",
            description: "Hyper HTTP",
        });
    }

    // Environment
    if path.starts_with("std::env::") {
        let (sub, risk) = if path.contains("set_var") || path.contains("remove_var") || path.contains("set_current_dir") {
            ("write", "High")
        } else {
            ("read", "Medium")
        };
        return Some(AuthorityMatch {
            category: "Env",
            subcategory: sub,
            risk,
            description: "Environment access",
        });
    }

    // Process
    if path.starts_with("std::process::") {
        return Some(AuthorityMatch {
            category: "Process",
            subcategory: "spawn",
            risk: "Critical",
            description: "Process spawning",
        });
    }

    None
}

/// The capsec analysis callbacks — hooks into the compiler after type checking.
struct CapsecCallbacks;

impl rustc_driver::Callbacks for CapsecCallbacks {
    fn after_analysis<'tcx>(
        &mut self,
        _compiler: &Compiler,
        tcx: TyCtxt<'tcx>,
    ) -> Compilation {
        let crate_name = tcx.crate_name(LOCAL_CRATE).to_string();
        let crate_version = std::env::var("CAPSEC_CRATE_VERSION").unwrap_or_else(|_| "0.0.0".to_string());
        let debug = std::env::var("CAPSEC_DEEP_DEBUG").is_ok();

        if debug {
            eprintln!("[capsec-deep] Analyzing crate: {crate_name}");
        }

        // Skip std/core/alloc — not useful for authority analysis
        if matches!(
            crate_name.as_str(),
            "std" | "core" | "alloc" | "compiler_builtins"
                | "rustc_std_workspace_core" | "rustc_std_workspace_alloc"
                | "panic_unwind" | "panic_abort" | "unwind"
                | "hashbrown" | "std_detect" | "rustc_demangle"
                | "addr2line" | "gimli" | "miniz_oxide" | "adler2" | "object" | "memchr"
                | "cfg_if" | "libc"
        ) {
            if debug {
                eprintln!("[capsec-deep] Skipping stdlib/low-level crate: {crate_name}");
            }
            return Compilation::Continue;
        }

        // Skip proc-macro crates (compile-time only, not runtime authority)
        if tcx.crate_types().contains(&rustc_session::config::CrateType::ProcMacro) {
            if debug {
                eprintln!("[capsec-deep] Skipping proc-macro crate: {crate_name}");
            }
            return Compilation::Continue;
        }

        // Detect build scripts
        let is_build_script = crate_name == "build_script_build"
            || crate_name.starts_with("build_script_");

        let mut findings: Vec<DeepFinding> = Vec::new();
        let source_map = tcx.sess.source_map();

        // Walk all local function bodies
        for local_def_id in tcx.hir_body_owners() {
            let def_id = local_def_id.to_def_id();
            let def_kind = tcx.def_kind(def_id);

            // Only analyze functions and methods
            if !matches!(def_kind, DefKind::Fn | DefKind::AssocFn) {
                continue;
            }

            // Get the function path and span
            let fn_path = tcx.def_path_str(def_id);
            let fn_span = tcx.def_span(def_id);
            let fn_name = tcx.item_name(def_id).to_string();
            let fn_loc = source_map.lookup_char_pos(fn_span.lo());
            let fn_file = match &fn_loc.file.name {
                rustc_span::FileName::Real(real) => real
                    .local_path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| format!("{real:?}")),
                other => format!("{other:?}"),
            };
            let fn_line = fn_loc.line;

            // Get the optimized MIR for this function
            let mir = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                tcx.optimized_mir(def_id)
            })) {
                Ok(mir) => mir,
                Err(_) => {
                    if debug {
                        eprintln!("[capsec-deep] Skipping {fn_path}: MIR unavailable");
                    }
                    continue;
                }
            };

            // Walk all basic blocks looking for Call terminators
            for (_bb, bb_data) in mir.basic_blocks.iter_enumerated() {
                let Some(terminator) = &bb_data.terminator else {
                    continue;
                };

                if let TerminatorKind::Call { func, .. } = &terminator.kind {
                    // Extract the callee DefId from the function operand
                    let Some((callee_def_id, _generic_args)) = func.const_fn_def() else {
                        continue; // indirect call (fn pointer, vtable) — skip
                    };

                    let callee_path = tcx.def_path_str(callee_def_id);

                    // Get call site location
                    let call_span = terminator.source_info.span;
                    let call_loc = source_map.lookup_char_pos(call_span.lo());
                    let call_line = call_loc.line;
                    let call_col = call_loc.col_display;

                    // Check 1: Authority pattern match (FS, NET, ENV, PROC)
                    if let Some(auth) = classify_authority(&callee_path) {
                        findings.push(DeepFinding {
                            file: fn_file.clone(),
                            function: fn_name.clone(),
                            function_line: fn_line,
                            call_line,
                            call_col,
                            call_text: callee_path.clone(),
                            category: auth.category.to_string(),
                            subcategory: auth.subcategory.to_string(),
                            risk: auth.risk.to_string(),
                            description: format!("{}: {}", auth.description, callee_path),
                            is_build_script,
                            crate_name: crate_name.clone(),
                            crate_version: crate_version.clone(),
                            is_deny_violation: false,
                            is_transitive: false,
                        });
                    }

                    // Check 2: FFI — calls to foreign functions
                    if tcx.is_foreign_item(callee_def_id) {
                        findings.push(DeepFinding {
                            file: fn_file.clone(),
                            function: fn_name.clone(),
                            function_line: fn_line,
                            call_line,
                            call_col,
                            call_text: callee_path.clone(),
                            category: "Ffi".to_string(),
                            subcategory: "ffi_call".to_string(),
                            risk: "High".to_string(),
                            description: format!("Calls FFI function {callee_path}()"),
                            is_build_script,
                            crate_name: crate_name.clone(),
                            crate_version: crate_version.clone(),
                            is_deny_violation: false,
                            is_transitive: false,
                        });
                    }
                }
            }
        }

        if debug {
            eprintln!("[capsec-deep] Found {} findings in {crate_name}", findings.len());
        }

        // Write findings as JSONL — buffer all lines and write in a single batch
        // to avoid interleaving when cargo compiles multiple crates in parallel.
        if let Ok(output_path) = std::env::var("CAPSEC_DEEP_OUTPUT") {
            let mut batch = String::new();
            for finding in &findings {
                if let Ok(json) = serde_json::to_string(finding) {
                    batch.push_str(&json);
                    batch.push('\n');
                }
            }
            if !batch.is_empty() {
                if let Ok(mut file) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&output_path)
                {
                    let _ = file.write_all(batch.as_bytes());
                }
            }
        } else if debug {
            // Print to stderr in debug mode when no output file specified
            for finding in &findings {
                if let Ok(json) = serde_json::to_string_pretty(finding) {
                    eprintln!("{json}");
                }
            }
        }

        Compilation::Continue
    }
}

/// Checks if this invocation is a cargo probe (e.g., `--print=cfg`) rather than
/// an actual compilation. Cargo calls the wrapper with these flags to learn about
/// the target — we must delegate to real rustc for these.
fn is_target_info_query(args: &[String]) -> bool {
    args.iter().any(|a| {
        a.starts_with("--print")
            || a == "-vV"
            || a == "--version"
    })
}

fn main() {
    // Install the ICE hook for useful panic reports
    rustc_driver::install_ice_hook(
        "https://github.com/auths-dev/capsec/issues",
        |_| (),
    );

    let mut args: Vec<String> = std::env::args().collect();

    // When used as RUSTC_WORKSPACE_WRAPPER, cargo invokes us as:
    //   capsec-driver /path/to/real/rustc <rustc-args...>
    // The second arg is the real rustc path — we need to strip it since
    // run_compiler expects args[0] to be the binary name followed by rustc flags.
    if args.len() > 1 && (args[1].ends_with("rustc") || args[1].contains("/rustc")) {
        args.remove(1);
    }

    // For cargo probe calls (--print=cfg, --version, etc.), run as plain rustc
    // without our analysis callbacks. This is the pattern used by Miri and Clippy.
    if is_target_info_query(&args) {
        let mut callbacks = rustc_driver::TimePassesCallbacks::default();
        rustc_driver::run_compiler(&args, &mut callbacks);
        return;
    }

    // For actual compilations, run with our analysis callbacks
    let mut callbacks = CapsecCallbacks;
    rustc_driver::run_compiler(&args, &mut callbacks);
}
