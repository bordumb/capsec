//! Capability-gated DuckDB wrapper.
//!
//! Demonstrates how library authors can define domain-specific permissions
//! using `#[capsec::permission]` and gate real database operations behind them.
//!
//! The core idea: if you only hold `Cap<DbRead>`, the compiler won't let you
//! call `db_execute` — you literally cannot write to the database without the
//! type system proving you have `DbWrite` permission.

use capsec::{Cap, Has};
use duckdb::Connection;

/// Permission to execute database read queries (SELECT).
#[capsec::permission]
pub struct DbRead;

/// Permission to execute database write statements (INSERT, UPDATE, DELETE, DDL).
#[capsec::permission]
pub struct DbWrite;

/// Full database access. Subsumes both [`DbRead`] and [`DbWrite`].
#[capsec::permission(subsumes = [DbRead, DbWrite])]
pub struct DbAll;

/// A capability-gated DuckDB connection.
///
/// Wraps a `duckdb::Connection` and gates all operations behind capsec
/// permission tokens. The connection itself has no capability — you must
/// pass a capability proof to every operation.
pub struct CapDb {
    conn: Connection,
}

impl CapDb {
    /// Open an in-memory DuckDB database.
    pub fn open_in_memory() -> Result<Self, duckdb::Error> {
        Ok(Self {
            conn: Connection::open_in_memory()?,
        })
    }

    /// Execute a read query and collect results as string rows.
    ///
    /// All columns are returned as strings (caller should CAST in SQL).
    /// Requires `DbRead` capability. Will not compile if you only hold `DbWrite`.
    pub fn query<C: Has<DbRead>>(
        &self,
        sql: &str,
        cap: &C,
    ) -> Result<Vec<Vec<String>>, duckdb::Error> {
        let _proof: Cap<DbRead> = cap.cap_ref();
        let mut stmt = self.conn.prepare(sql)?;
        let mut result_rows = Vec::new();
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let mut vals = Vec::new();
            let mut i = 0;
            loop {
                match row.get::<_, String>(i) {
                    Ok(val) => vals.push(val),
                    Err(_) => break,
                }
                i += 1;
            }
            result_rows.push(vals);
        }
        Ok(result_rows)
    }

    /// Execute a write statement (INSERT, UPDATE, DELETE, DDL).
    ///
    /// Requires `DbWrite` capability. Will not compile if you only hold `DbRead`.
    pub fn execute<C: Has<DbWrite>>(&self, sql: &str, cap: &C) -> Result<usize, duckdb::Error> {
        let _proof: Cap<DbWrite> = cap.cap_ref();
        self.conn.execute(sql, [])
    }

    /// Execute a batch of DDL/DML statements.
    ///
    /// Requires `DbWrite` capability.
    pub fn execute_batch<C: Has<DbWrite>>(&self, sql: &str, cap: &C) -> Result<(), duckdb::Error> {
        let _proof: Cap<DbWrite> = cap.cap_ref();
        self.conn.execute_batch(sql)
    }

    /// Run a migration: create schema then seed data.
    ///
    /// Requires `DbAll` — proves you can both read and write.
    pub fn migrate<C: Has<DbAll>>(&self, ddl: &str, cap: &C) -> Result<(), duckdb::Error> {
        let _proof: Cap<DbAll> = cap.cap_ref();
        self.conn.execute_batch(ddl)
    }

    /// Query a single scalar value.
    ///
    /// Requires `DbRead` capability.
    pub fn query_one<C: Has<DbRead>>(&self, sql: &str, cap: &C) -> Result<String, duckdb::Error> {
        let _proof: Cap<DbRead> = cap.cap_ref();
        self.conn.query_row(sql, [], |row| row.get(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use capsec_core::root::test_root;

    #[test]
    fn grant_custom_permission() {
        let root = test_root();
        let db = CapDb::open_in_memory().unwrap();
        let write_cap = root.grant::<DbWrite>();
        db.execute("CREATE TABLE t (x INTEGER)", &write_cap)
            .unwrap();
        db.execute("INSERT INTO t VALUES (42)", &write_cap).unwrap();

        let read_cap = root.grant::<DbRead>();
        let rows = db
            .query("SELECT CAST(x AS VARCHAR) FROM t", &read_cap)
            .unwrap();
        assert_eq!(rows, vec![vec!["42".to_string()]]);
    }

    #[test]
    fn db_all_subsumes_read_and_write() {
        let root = test_root();
        let db = CapDb::open_in_memory().unwrap();
        let cap = root.grant::<DbAll>();

        db.execute("CREATE TABLE t (x INTEGER)", &cap).unwrap();
        db.execute("INSERT INTO t VALUES (1)", &cap).unwrap();
        let rows = db.query("SELECT CAST(x AS VARCHAR) FROM t", &cap).unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn migrate_requires_db_all() {
        let root = test_root();
        let db = CapDb::open_in_memory().unwrap();
        let cap = root.grant::<DbAll>();
        db.migrate("CREATE TABLE users (id INTEGER, name VARCHAR)", &cap)
            .unwrap();
        let count = db
            .query_one("SELECT CAST(COUNT(*) AS VARCHAR) FROM users", &cap)
            .unwrap();
        assert_eq!(count, "0");
    }

    #[test]
    fn custom_permission_is_zst() {
        assert_eq!(std::mem::size_of::<Cap<DbRead>>(), 0);
        assert_eq!(std::mem::size_of::<Cap<DbWrite>>(), 0);
        assert_eq!(std::mem::size_of::<Cap<DbAll>>(), 0);
    }

    #[test]
    fn context_macro_with_custom_permissions() {
        #[capsec::context]
        struct DbCtx {
            read: DbRead,
            write: DbWrite,
        }

        let root = test_root();
        let db = CapDb::open_in_memory().unwrap();
        let ctx = DbCtx::new(&root);
        db.execute("CREATE TABLE t (x INTEGER)", &ctx).unwrap();
        db.execute("INSERT INTO t VALUES (1)", &ctx).unwrap();
        let rows = db.query("SELECT CAST(x AS VARCHAR) FROM t", &ctx).unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn requires_macro_with_custom_permissions() {
        #[capsec::context]
        struct QueryCtx {
            read: DbRead,
        }

        #[capsec::requires(DbRead, on = ctx)]
        fn checked_query(db: &CapDb, ctx: &QueryCtx) -> Vec<Vec<String>> {
            db.query("SELECT 'hello'", ctx).unwrap()
        }

        let root = test_root();
        let db = CapDb::open_in_memory().unwrap();
        let ctx = QueryCtx::new(&root);
        let results = checked_query(&db, &ctx);
        assert_eq!(results, vec![vec!["hello".to_string()]]);
    }

    #[test]
    fn context_with_mixed_builtin_and_custom() {
        use capsec::FsRead;

        #[capsec::context]
        struct MixedCtx {
            fs: FsRead,
            db: DbRead,
        }

        let root = test_root();
        let db = CapDb::open_in_memory().unwrap();
        let ctx = MixedCtx::new(&root);
        let rows = db.query("SELECT 'mixed'", &ctx).unwrap();
        assert_eq!(rows, vec![vec!["mixed".to_string()]]);

        fn needs_fs(_: &impl Has<FsRead>) {}
        needs_fs(&ctx);
    }
}
