# Contributing to capsec

## Project layout

```
capsec/
├── crates/
│   ├── capsec-core/       # Zero-cost capability tokens, permission traits, Has<P>
│   ├── capsec-macro/      # #[requires], #[deny], #[main], #[context] proc macros
│   ├── capsec-std/        # Capability-gated wrappers for std::fs, std::net, etc.
│   ├── capsec/            # Facade crate — re-exports everything, owns examples
│   ├── cargo-capsec/      # Static audit CLI tool
│   └── capsec-tests/      # Adversarial security tests
├── docs/                  # Additional documentation
├── .capsec.toml           # Default audit configuration
└── rust-toolchain.toml    # Pinned Rust version (compile-fail tests depend on this)
```

**Key files:**

| File | Purpose |
|------|---------|
| `capsec-core/src/permission.rs` | Permission types (`FsRead`, `NetConnect`, etc.) |
| `capsec-core/src/has.rs` | `Has<P>` trait + subsumption impls |
| `capsec-core/src/cap.rs` | `Cap<P>` zero-sized token |
| `capsec-std/src/fs.rs` | Gated filesystem operations |
| `cargo-capsec/src/authorities.rs` | Audit knowledge base — patterns, categories, risk levels |
| `cargo-capsec/src/detector.rs` | Matching engine that produces findings |
| `cargo-capsec/src/parser.rs` | Rust source parser (syn-based) |

## How to add an authority pattern

The audit tool's knowledge base lives in `crates/cargo-capsec/src/authorities.rs`. Each entry maps a call pattern to a category, risk level, and description.

### Step 1: Choose the pattern type

There are two matching strategies:

**`AuthorityPattern::Path`** — for qualified function calls like `std::fs::read` or `File::open`:

```rust
Authority {
    pattern: AuthorityPattern::Path(&["std", "fs", "read"]),
    category: Category::Fs,
    subcategory: "read",
    risk: Risk::Medium,
    description: "Read arbitrary file contents",
}
```

The detector matches by suffix — `&["fs", "read"]` will match `std::fs::read`, `use std::fs::read; read(...)`, and aliased imports.

**`AuthorityPattern::MethodWithContext`** — for method calls that are only meaningful in context (e.g., `.output()` is only a process call if `Command::new` is in the same function):

```rust
Authority {
    pattern: AuthorityPattern::MethodWithContext {
        method: "output",
        requires_path: &["Command", "new"],
    },
    category: Category::Process,
    subcategory: "spawn",
    risk: Risk::Critical,
    description: "Execute subprocess and capture output",
}
```

### Step 2: Add the entry to `build_registry()`

Add your `Authority` struct to the `vec![]` in `build_registry()`. Group it with related entries (filesystem patterns together, network patterns together, etc.).

### Step 3: Choose the right risk level

| Level | When to use |
|-------|-------------|
| `Low` | Read-only metadata, unlikely to leak secrets (`fs::metadata`, `env::current_dir`) |
| `Medium` | Can read data or create resources (`fs::read`, `env::var`, `File::open`) |
| `High` | Can write, delete, or open network connections (`fs::write`, `TcpStream::connect`) |
| `Critical` | Can destroy data or execute arbitrary code (`remove_dir_all`, `Command::new`) |

### Step 4: Add an integration test

Add a test fixture in `crates/capsec-tests/tests/audit_evasion.rs` that exercises your new pattern. The test should:

1. Create a temporary `.rs` file with the call you want to detect
2. Run the parser and detector against it
3. Assert the finding has the correct category, risk, and description

```rust
#[test]
fn detects_your_new_pattern() {
    let source = r#"
        fn example() {
            some_crate::dangerous_call();
        }
    "#;
    let findings = scan_source(source);
    assert!(findings.iter().any(|f| f.description == "Your description"));
}
```

### Step 5: Run the tests

```bash
cargo test -p cargo-capsec
cargo test -p capsec-tests
```

## Testing requirements

All PRs must pass:

```bash
cargo test --workspace          # All unit + integration tests
cargo clippy --workspace        # No warnings
cargo fmt --check               # Formatted
```

### Compile-fail tests

capsec uses [trybuild](https://github.com/dtolnay/trybuild) to prove security guarantees at the compiler level. These tests live in two places:

- `crates/capsec/tests/compile_fail/` — API-level guarantees (wrong cap rejected, cap is !Send, etc.)
- `crates/capsec-tests/tests/compile_fail/` — adversarial attacks (forgery, escalation, sealed traits)

Each test is a `.rs` file that **must fail to compile**, paired with a `.stderr` file containing the exact expected error output.

### How to add a compile-fail test

1. Create a `.rs` file in the appropriate `compile_fail/` directory:

```rust
/// Description of what this test proves.
use capsec::prelude::*;

fn main() {
    // Code that MUST NOT compile
}
```

2. Generate the `.stderr` snapshot:

```bash
TRYBUILD=overwrite cargo test -p capsec --test compile_tests
```

3. Review the `.stderr` — confirm it fails for the right reason.

4. Commit both the `.rs` and `.stderr` files.

**Important:** The `.stderr` snapshots are tied to the exact rustc version in `rust-toolchain.toml`. Bumping the toolchain will require regenerating them. See `docs/contributing/compile-fail-tests.md` for details.

## PR guidelines

- **One concern per PR.** A new authority pattern, a bug fix, or a refactor — not all three.
- **Include tests.** New authority patterns need integration tests. New type-system features need compile-fail tests.
- **Run `cargo capsec audit`** against the repo itself before submitting — capsec dogfoods its own tool.
- **Keep the security model intact.** `Cap<P>` must remain unforgeable and `!Send`. `Permission` must remain sealed. `Cap::new()` must remain `pub(crate)`. Any change that weakens these guarantees needs discussion in an issue first.
- **Update docs** if you change public API. The facade crate's `lib.rs` doc comments and crate READMEs should stay current.

## Context pattern and macros

capsec provides four macros that work together:

| Macro | Purpose |
|-------|---------|
| `#[capsec::context]` | Generates `Has<P>` impls on a struct, turning it into a capability context |
| `#[capsec::main]` | Injects `CapRoot` creation into a function entry point |
| `#[capsec::requires]` | Validates that a function's parameters satisfy declared permissions |
| `#[capsec::deny]` | Marks a function as capability-free; violations are promoted to critical by the audit tool |

When developing macros in `capsec-macro`:

- All generated code uses fully qualified `capsec_core::*` paths (not `capsec::*`)
- Permission type validation must stay in sync with `capsec-core/src/permission.rs`
- The `resolve.rs` module maps shorthand paths (`fs::read`) to full types
- Add compile-fail tests in `capsec/tests/compile_fail/` for error cases
- Add runtime tests in `capsec-tests/tests/type_system.rs` for happy paths
