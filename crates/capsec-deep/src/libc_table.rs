//! POSIX syscall classification table for `libc` foreign function calls.
//!
//! Maps common `libc` function names to ambient authority categories.
//! `libc` is on the driver's skip list, so the syntactic scanner never sees it —
//! this table is the only way these calls get classified beyond generic FFI.

use std::collections::HashMap;
use std::sync::LazyLock;

pub struct LibcClassification {
    pub category: &'static str,
    pub subcategory: &'static str,
    pub risk: &'static str,
}

static LIBC_TABLE: LazyLock<HashMap<&'static str, LibcClassification>> =
    LazyLock::new(build_table);

pub fn classify_libc_fn(fn_name: &str) -> Option<&'static LibcClassification> {
    LIBC_TABLE.get(fn_name)
}

fn build_table() -> HashMap<&'static str, LibcClassification> {
    let mut m = HashMap::with_capacity(80);

    // ── Filesystem read ──
    for name in [
        "open", "open64", "openat", "openat64", "creat", "creat64",
        "read", "pread", "pread64", "readv",
        "readlink", "readlinkat",
        "stat", "stat64", "fstat", "fstat64", "lstat", "lstat64",
        "fstatat", "fstatat64",
        "access", "faccessat",
        "readdir", "readdir_r", "fdopendir", "opendir",
        "getdents", "getdents64",
        "realpath",
    ] {
        m.insert(name, LibcClassification {
            category: "Fs",
            subcategory: "read",
            risk: "Medium",
        });
    }

    // ── Filesystem write ──
    for name in [
        "write", "pwrite", "pwrite64", "writev",
        "unlink", "unlinkat", "remove",
        "rename", "renameat", "renameat2",
        "mkdir", "mkdirat", "rmdir",
        "truncate", "ftruncate", "ftruncate64",
        "chmod", "fchmod", "fchmodat",
        "chown", "fchown", "lchown", "fchownat",
        "link", "linkat", "symlink", "symlinkat",
        "close", "fsync", "fdatasync",
    ] {
        m.insert(name, LibcClassification {
            category: "Fs",
            subcategory: "write",
            risk: "High",
        });
    }

    // ── Filesystem memory-mapped I/O ──
    for name in ["mmap", "mmap64", "munmap", "mprotect", "msync"] {
        m.insert(name, LibcClassification {
            category: "Fs",
            subcategory: "mmap",
            risk: "High",
        });
    }

    // ── Network ──
    for name in [
        "socket", "connect", "bind", "listen",
        "accept", "accept4",
        "recv", "recvfrom", "recvmsg",
        "send", "sendto", "sendmsg",
        "shutdown",
        "getaddrinfo", "freeaddrinfo", "getnameinfo",
        "getsockname", "getpeername",
        "setsockopt", "getsockopt",
        "poll", "ppoll",
        "select", "pselect",
        "epoll_create", "epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait",
        "kqueue", "kevent",
    ] {
        m.insert(name, LibcClassification {
            category: "Net",
            subcategory: "socket",
            risk: "High",
        });
    }

    // ── Environment read ──
    for name in ["getenv", "getcwd", "getuid", "geteuid", "getgid", "getegid", "getpid", "getppid"] {
        m.insert(name, LibcClassification {
            category: "Env",
            subcategory: "read",
            risk: "Medium",
        });
    }

    // ── Environment write ──
    for name in ["setenv", "unsetenv", "putenv", "chdir", "fchdir"] {
        m.insert(name, LibcClassification {
            category: "Env",
            subcategory: "write",
            risk: "High",
        });
    }

    // ── Process ──
    for name in [
        "fork", "vfork",
        "execve", "execvp", "execvpe", "fexecve", "execl", "execlp",
        "system",
        "posix_spawn", "posix_spawnp",
        "kill", "raise",
        "waitpid", "wait4", "wait",
        "ptrace",
        "exit", "_exit",
    ] {
        m.insert(name, LibcClassification {
            category: "Process",
            subcategory: "spawn",
            risk: "Critical",
        });
    }

    // ── Signal handling (process control) ──
    for name in ["signal", "sigaction", "sigprocmask", "sigsuspend"] {
        m.insert(name, LibcClassification {
            category: "Process",
            subcategory: "signal",
            risk: "High",
        });
    }

    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filesystem_calls_classified() {
        for name in ["open", "read", "stat", "readlink", "access"] {
            let c = classify_libc_fn(name)
                .unwrap_or_else(|| panic!("{name} should be classified"));
            assert_eq!(c.category, "Fs", "{name} should be Fs");
        }
    }

    #[test]
    fn network_calls_classified() {
        for name in ["socket", "connect", "bind", "accept", "send"] {
            let c = classify_libc_fn(name)
                .unwrap_or_else(|| panic!("{name} should be classified"));
            assert_eq!(c.category, "Net", "{name} should be Net");
        }
    }

    #[test]
    fn env_calls_classified() {
        for name in ["getenv", "getcwd", "setenv", "chdir"] {
            let c = classify_libc_fn(name)
                .unwrap_or_else(|| panic!("{name} should be classified"));
            assert_eq!(c.category, "Env", "{name} should be Env");
        }
    }

    #[test]
    fn process_calls_classified() {
        for name in ["fork", "execve", "kill", "waitpid", "system"] {
            let c = classify_libc_fn(name)
                .unwrap_or_else(|| panic!("{name} should be classified"));
            assert_eq!(c.category, "Process", "{name} should be Process");
        }
    }

    #[test]
    fn unknown_fn_returns_none() {
        assert!(classify_libc_fn("some_random_fn").is_none());
    }

    #[test]
    fn table_size_sanity() {
        let table = build_table();
        assert!(table.len() >= 60, "Table too small: {}", table.len());
        assert!(table.len() <= 120, "Table too large: {}", table.len());
    }
}
