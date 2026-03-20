# capsec-example-db

A real-world example of capsec's user-defined permissions, gating DuckDB operations at compile time.

## What this demonstrates

Library authors can define domain-specific permissions with `#[capsec::permission]` and enforce them through the type system — zero runtime cost, zero chance of forgetting a check.

```rust
#[capsec::permission]
pub struct DbRead;

#[capsec::permission]
pub struct DbWrite;

#[capsec::permission(subsumes = [DbRead, DbWrite])]
pub struct DbAll;
```

Functions declare what they need:

```rust
// This function literally cannot write to the database.
// The compiler rejects it — not a runtime check.
fn run_analytics(db: &CapDb, cap: &impl Has<DbRead>) {
    db.query("SELECT * FROM players", cap)?;

    // COMPILE ERROR: Has<DbWrite> is not implemented for impl Has<DbRead>
    // db.execute("DELETE FROM players", cap);
}
```

## Building and running

This crate is **excluded from the default workspace** because it depends on `duckdb` with the `bundled` feature, which compiles the entire DuckDB C++ engine from source (~500k lines of C++). This keeps `cargo build --workspace`, `cargo test --workspace`, and `cargo clippy --workspace` fast for day-to-day development.

To build, test, or run this crate, target it explicitly with `-p`:

```bash
# Run the example
cargo run -p capsec-example-db --example duck_db_app

# Run the tests
cargo test -p capsec-example-db
```

The first build will be slow (DuckDB compilation). Subsequent builds use the cached artifacts and are fast.

Output:

```
=== DuckDB + capsec: Compile-Time Capability Gating ===
Schema created.

--- Ingestion (write-only) ---
  inserted: Alice (score: 950)
  inserted: Bob (score: 870)
  ...

--- Analytics (read-only) ---
ID    Name            Score
----- --------------- ------
5     Eve             1100
3     Charlie         1020
...

--- Admin (full access) ---
Players below 900: 2
Removed 2 player(s) below threshold
Remaining players: 3
```

## Architecture

| Module | Capability | Can read? | Can write? |
|--------|-----------|-----------|------------|
| `ingest_scores` | `DbWrite` | No | Yes |
| `run_analytics` | `DbRead` | Yes | No |
| `admin_cleanup` | `DbAll` | Yes | Yes |

`DbAll` subsumes `DbRead` and `DbWrite` — extract a `Cap<DbAll>` and it satisfies both `Has<DbRead>` and `Has<DbWrite>` bounds.

## Key patterns shown

- **`#[capsec::permission]`** — define custom permissions in your own crate
- **`subsumes = [...]`** — build permission hierarchies
- **`Cap<DbAll>` subsumption** — extract the concrete token to use both read and write APIs
- **`#[capsec::context]`** — bundle custom permissions into a context struct
- **`#[capsec::requires]`** — annotate functions with custom permission requirements
- **Mixed built-in + custom** — combine `FsRead` and `DbRead` in one context

## Connection to auths

These compile-time permissions mirror the runtime capabilities used by [auths](https://github.com/bordumb/auths). The same vocabulary spans both layers:

| capsec (compile-time) | auths (runtime) |
|----------------------|-----------------|
| `Cap<DbRead>` | `HasCapability("db:read")` |
| Type system: compiles/doesn't | Policy evaluation: Allow/Deny |
| `Subsumes<DbRead> for DbAll` | Delegation narrowing |

capsec prevents the code from exceeding its authority. auths prevents unauthorized callers from reaching the code. Together: defense in depth.

## Tests

```bash
cargo test -p capsec-example-db
```

> **Note:** This crate is in the workspace `exclude` list, not `members`. Use `-p capsec-example-db` explicitly — `--workspace` will not include it.
