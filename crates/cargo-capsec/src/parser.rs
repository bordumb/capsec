//! Rust source file parser built on [`syn`].
//!
//! Parses `.rs` files into a structured representation that captures the information
//! the [`Detector`](crate::detector::Detector) needs: function boundaries, call sites,
//! `use` imports, and `extern` blocks. Handles free functions, `impl` block methods,
//! and trait default methods.
//!
//! The parser uses [`syn::visit::Visit`] to walk the AST. It does **not** perform type
//! resolution — all matching is done on syntactic path segments. Import aliases are
//! tracked so the [`Detector`](crate::detector::Detector) can expand them.

use std::path::Path;
use syn::visit::Visit;

/// The parsed representation of a single `.rs` source file.
///
/// Contains every function body, `use` import, and `extern` block found in the file.
/// This is the input to [`Detector::analyse`](crate::detector::Detector::analyse).
#[derive(Debug, Clone)]
pub struct ParsedFile {
    /// File path (for reporting).
    pub path: String,
    /// All functions found: free functions, `impl` methods, and trait default methods.
    pub functions: Vec<ParsedFunction>,
    /// All `use` imports, with aliases tracked.
    pub use_imports: Vec<ImportPath>,
    /// All `extern` blocks (FFI declarations).
    pub extern_blocks: Vec<ExternBlock>,
}

/// A single function (free, `impl` method, or trait default method) and its call sites.
#[derive(Debug, Clone)]
pub struct ParsedFunction {
    /// The function name (e.g., `"load_config"`).
    pub name: String,
    /// Line number where the function is defined.
    pub line: usize,
    /// Every call expression found inside the function body.
    pub calls: Vec<CallSite>,
    /// True if this is the `main()` function inside a `build.rs` file.
    pub is_build_script: bool,
    /// Categories denied by `#[capsec::deny(...)]` on this function.
    /// Parsed from `#[doc = "capsec::deny(...)"]` attributes.
    pub deny_categories: Vec<String>,
}

/// A single call expression inside a function body.
///
/// Call sites are either qualified function calls (`fs::read(...)`) or method calls
/// (`stream.connect(...)`). The [`segments`](CallSite::segments) field holds the
/// raw path segments before import expansion.
#[derive(Debug, Clone)]
pub struct CallSite {
    /// Path segments of the call (e.g., `["fs", "read"]` or `["TcpStream", "connect"]`).
    pub segments: Vec<String>,
    /// Source line number.
    pub line: usize,
    /// Source column number.
    pub col: usize,
    /// Whether this is a function call or a method call.
    pub kind: CallKind,
}

/// Distinguishes qualified function calls from method calls.
#[derive(Debug, Clone)]
pub enum CallKind {
    /// A qualified path call like `fs::read(...)` or `Command::new(...)`.
    FunctionCall,
    /// A method call like `stream.connect(...)` or `cmd.output()`.
    MethodCall {
        /// The method name (e.g., `"connect"`, `"output"`).
        method: String,
    },
}

/// A `use` import statement, with optional alias.
///
/// For `use std::fs::read as load`, the segments are `["std", "fs", "read"]` and
/// the alias is `Some("load")`. The [`Detector`](crate::detector::Detector) uses
/// this to expand bare calls: when it sees `load(...)`, it looks up the alias and
/// expands it to `std::fs::read`.
#[derive(Debug, Clone)]
pub struct ImportPath {
    /// The full path segments (e.g., `["std", "fs", "read"]`).
    pub segments: Vec<String>,
    /// The `as` alias, if any (e.g., `Some("load")` for `use std::fs::read as load`).
    pub alias: Option<String>,
}

/// An `extern` block declaring foreign functions.
///
/// Any `extern` block is flagged as [`Category::Ffi`](crate::authorities::Category::Ffi)
/// by the detector, since FFI calls bypass Rust's safety model entirely.
#[derive(Debug, Clone)]
pub struct ExternBlock {
    /// The ABI string (e.g., `Some("C")` for `extern "C"`).
    pub abi: Option<String>,
    /// Names of functions declared in the block.
    pub functions: Vec<String>,
    /// Source line number.
    pub line: usize,
}

/// Parses a `.rs` file from disk into a [`ParsedFile`].
///
/// Requires an [`FsRead`](capsec_core::permission::FsRead) capability token,
/// proving the caller has permission to read files. This is the dogfood example —
/// `cargo capsec audit` flagged this function's `std::fs::read_to_string` call,
/// and now it's gated by the capsec type system.
///
/// # Example
///
/// ```rust,ignore
/// use capsec_core::root::test_root;
/// use capsec_core::permission::FsRead;
///
/// let root = test_root();
/// let cap = root.grant::<FsRead>();
/// let parsed = parse_file(Path::new("src/main.rs"), &cap).unwrap();
/// ```
pub fn parse_file(
    path: &Path,
    cap: &impl capsec_core::cap_provider::CapProvider<capsec_core::permission::FsRead>,
) -> Result<ParsedFile, String> {
    let source = capsec_std::fs::read_to_string(path, cap)
        .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    parse_source(&source, &path.display().to_string())
}

/// Parses Rust source code from a string into a [`ParsedFile`].
///
/// This is the primary entry point for programmatic usage and testing.
/// The `path` parameter is used only for error messages and the
/// [`ParsedFile::path`] field — it doesn't need to be a real file.
///
/// # Errors
///
/// Returns an error string if [`syn::parse_file`] fails (e.g., invalid Rust syntax).
pub fn parse_source(source: &str, path: &str) -> Result<ParsedFile, String> {
    let syntax = syn::parse_file(source).map_err(|e| format!("Failed to parse {path}: {e}"))?;

    let mut visitor = FileVisitor::new(path.to_string());
    visitor.visit_file(&syntax);

    Ok(ParsedFile {
        path: path.to_string(),
        functions: visitor.functions,
        use_imports: visitor.imports,
        extern_blocks: visitor.extern_blocks,
    })
}

struct FileVisitor {
    file_path: String,
    functions: Vec<ParsedFunction>,
    imports: Vec<ImportPath>,
    extern_blocks: Vec<ExternBlock>,
    current_function: Option<ParsedFunction>,
}

impl FileVisitor {
    fn new(file_path: String) -> Self {
        Self {
            file_path,
            functions: Vec::new(),
            imports: Vec::new(),
            extern_blocks: Vec::new(),
            current_function: None,
        }
    }
}

impl<'ast> Visit<'ast> for FileVisitor {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        let func = ParsedFunction {
            name: node.sig.ident.to_string(),
            line: node.sig.ident.span().start().line,
            calls: Vec::new(),
            is_build_script: self.file_path.ends_with("build.rs") && node.sig.ident == "main",
            deny_categories: extract_deny_categories(&node.attrs),
        };

        let prev = self.current_function.take();
        self.current_function = Some(func);

        syn::visit::visit_item_fn(self, node);

        if let Some(func) = self.current_function.take() {
            self.functions.push(func);
        }
        self.current_function = prev;
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        let func = ParsedFunction {
            name: node.sig.ident.to_string(),
            line: node.sig.ident.span().start().line,
            calls: Vec::new(),
            is_build_script: false,
            deny_categories: extract_deny_categories(&node.attrs),
        };

        let prev = self.current_function.take();
        self.current_function = Some(func);

        syn::visit::visit_impl_item_fn(self, node);

        if let Some(func) = self.current_function.take() {
            self.functions.push(func);
        }
        self.current_function = prev;
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        // Only visit if there's a default body
        if node.default.is_some() {
            let func = ParsedFunction {
                name: node.sig.ident.to_string(),
                line: node.sig.ident.span().start().line,
                calls: Vec::new(),
                is_build_script: false,
                deny_categories: extract_deny_categories(&node.attrs),
            };

            let prev = self.current_function.take();
            self.current_function = Some(func);

            syn::visit::visit_trait_item_fn(self, node);

            if let Some(func) = self.current_function.take() {
                self.functions.push(func);
            }
            self.current_function = prev;
        } else {
            syn::visit::visit_trait_item_fn(self, node);
        }
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Some(ref mut func) = self.current_function
            && let syn::Expr::Path(ref path) = *node.func
        {
            let segments: Vec<String> = path
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();

            if !segments.is_empty() {
                func.calls.push(CallSite {
                    segments,
                    line: path
                        .path
                        .segments
                        .first()
                        .map(|s| s.ident.span().start().line)
                        .unwrap_or(0),
                    col: path
                        .path
                        .segments
                        .first()
                        .map(|s| s.ident.span().start().column)
                        .unwrap_or(0),
                    kind: CallKind::FunctionCall,
                });
            }
        }

        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if let Some(ref mut func) = self.current_function {
            func.calls.push(CallSite {
                segments: vec![node.method.to_string()],
                line: node.method.span().start().line,
                col: node.method.span().start().column,
                kind: CallKind::MethodCall {
                    method: node.method.to_string(),
                },
            });
        }

        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        let mut paths = Vec::new();
        collect_use_paths(&node.tree, &mut Vec::new(), &mut paths);
        self.imports.extend(paths);

        syn::visit::visit_item_use(self, node);
    }

    fn visit_item_foreign_mod(&mut self, node: &'ast syn::ItemForeignMod) {
        let functions: Vec<String> = node
            .items
            .iter()
            .filter_map(|item| {
                if let syn::ForeignItem::Fn(f) = item {
                    Some(f.sig.ident.to_string())
                } else {
                    None
                }
            })
            .collect();

        self.extern_blocks.push(ExternBlock {
            abi: node.abi.name.as_ref().map(|n| n.value()),
            functions,
            line: node.abi.extern_token.span.start().line,
        });

        syn::visit::visit_item_foreign_mod(self, node);
    }
}

/// Extracts denied categories from `#[doc = "capsec::deny(...)"]` attributes.
///
/// The `#[capsec::deny(...)]` macro emits a doc attribute like
/// `#[doc = "capsec::deny(all, fs)"]`. This function parses that string
/// and returns the category names (e.g., `["all", "fs"]`).
fn extract_deny_categories(attrs: &[syn::Attribute]) -> Vec<String> {
    let mut categories = Vec::new();
    for attr in attrs {
        if !attr.path().is_ident("doc") {
            continue;
        }
        if let syn::Meta::NameValue(nv) = &attr.meta
            && let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(lit_str),
                ..
            }) = &nv.value
        {
            let value = lit_str.value();
            if let Some(inner) = value
                .strip_prefix("capsec::deny(")
                .and_then(|s| s.strip_suffix(')'))
            {
                for cat in inner.split(',') {
                    let trimmed = cat.trim();
                    if !trimmed.is_empty() {
                        categories.push(trimmed.to_string());
                    }
                }
            }
        }
    }
    categories
}

fn collect_use_paths(tree: &syn::UseTree, prefix: &mut Vec<String>, out: &mut Vec<ImportPath>) {
    match tree {
        syn::UseTree::Path(p) => {
            prefix.push(p.ident.to_string());
            collect_use_paths(&p.tree, prefix, out);
            prefix.pop();
        }
        syn::UseTree::Name(n) => {
            let mut segments = prefix.clone();
            segments.push(n.ident.to_string());
            out.push(ImportPath {
                segments,
                alias: None,
            });
        }
        syn::UseTree::Rename(r) => {
            let mut segments = prefix.clone();
            segments.push(r.ident.to_string());
            out.push(ImportPath {
                segments,
                alias: Some(r.rename.to_string()),
            });
        }
        syn::UseTree::Group(g) => {
            for item in &g.items {
                collect_use_paths(item, prefix, out);
            }
        }
        syn::UseTree::Glob(_) => {
            let mut segments = prefix.clone();
            segments.push("*".to_string());
            out.push(ImportPath {
                segments,
                alias: None,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_function_calls() {
        let source = r#"
            use std::fs;
            fn do_stuff() {
                let _ = fs::read("test");
            }
        "#;
        let parsed = parse_source(source, "test.rs").unwrap();
        assert_eq!(parsed.functions.len(), 1);
        assert_eq!(parsed.functions[0].name, "do_stuff");
        assert!(!parsed.functions[0].calls.is_empty());
    }

    #[test]
    fn parse_use_statements() {
        let source = r#"
            use std::fs::read;
            use std::net::{TcpStream, TcpListener};
            use std::env::var as get_env;
        "#;
        let parsed = parse_source(source, "test.rs").unwrap();
        assert_eq!(parsed.use_imports.len(), 4);

        let read_import = &parsed.use_imports[0];
        assert_eq!(read_import.segments, vec!["std", "fs", "read"]);
        assert!(read_import.alias.is_none());

        let alias_import = parsed
            .use_imports
            .iter()
            .find(|i| i.alias.is_some())
            .unwrap();
        assert_eq!(alias_import.segments, vec!["std", "env", "var"]);
        assert_eq!(alias_import.alias.as_deref(), Some("get_env"));
    }

    #[test]
    fn parse_method_calls() {
        let source = r#"
            fn network() {
                let stream = something();
                stream.connect("127.0.0.1:8080");
                stream.send_to(b"data", "addr");
            }
        "#;
        let parsed = parse_source(source, "test.rs").unwrap();
        let func = &parsed.functions[0];
        let method_calls: Vec<&CallSite> = func
            .calls
            .iter()
            .filter(|c| matches!(c.kind, CallKind::MethodCall { .. }))
            .collect();
        assert_eq!(method_calls.len(), 2);
    }

    #[test]
    fn parse_extern_blocks() {
        let source = r#"
            extern "C" {
                fn open(path: *const u8, flags: i32) -> i32;
                fn close(fd: i32) -> i32;
            }
        "#;
        let parsed = parse_source(source, "test.rs").unwrap();
        assert_eq!(parsed.extern_blocks.len(), 1);
        assert_eq!(parsed.extern_blocks[0].abi.as_deref(), Some("C"));
        assert_eq!(parsed.extern_blocks[0].functions, vec!["open", "close"]);
    }

    #[test]
    fn parse_error_returns_err() {
        let source = "this is not valid rust {{{";
        assert!(parse_source(source, "bad.rs").is_err());
    }

    #[test]
    fn parse_impl_block_methods() {
        let source = r#"
            use std::fs;
            struct Loader;
            impl Loader {
                fn load(&self) -> Vec<u8> {
                    fs::read("data.bin").unwrap()
                }
                fn name(&self) -> &str {
                    "loader"
                }
            }
        "#;
        let parsed = parse_source(source, "test.rs").unwrap();
        assert_eq!(parsed.functions.len(), 2);
        let load = parsed.functions.iter().find(|f| f.name == "load").unwrap();
        assert!(!load.calls.is_empty());
    }

    #[test]
    fn enum_variants_not_captured_as_calls() {
        let source = r#"
            enum Category { Fs, Net }
            fn classify() -> Category {
                let cat = Category::Fs;
                let none: Option<i32> = Option::None;
                cat
            }
        "#;
        let parsed = parse_source(source, "test.rs").unwrap();
        let func = parsed
            .functions
            .iter()
            .find(|f| f.name == "classify")
            .unwrap();
        let fn_calls: Vec<&CallSite> = func
            .calls
            .iter()
            .filter(|c| matches!(c.kind, CallKind::FunctionCall))
            .collect();
        assert!(
            fn_calls.is_empty(),
            "Enum variants should not be captured as function calls, got: {:?}",
            fn_calls
                .iter()
                .map(|c| c.segments.join("::"))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn parse_deny_annotation() {
        let source = r#"
            #[doc = "capsec::deny(all)"]
            fn pure_function() {
                let x = 1 + 2;
            }
        "#;
        let parsed = parse_source(source, "test.rs").unwrap();
        assert_eq!(parsed.functions.len(), 1);
        assert_eq!(parsed.functions[0].deny_categories, vec!["all"]);
    }

    #[test]
    fn parse_deny_specific_categories() {
        let source = r#"
            #[doc = "capsec::deny(fs, net)"]
            fn no_io() {}
        "#;
        let parsed = parse_source(source, "test.rs").unwrap();
        assert_eq!(parsed.functions[0].deny_categories, vec!["fs", "net"]);
    }

    #[test]
    fn parse_no_deny_annotation() {
        let source = r#"
            fn normal() {}
        "#;
        let parsed = parse_source(source, "test.rs").unwrap();
        assert!(parsed.functions[0].deny_categories.is_empty());
    }

    #[test]
    fn parse_trait_default_methods() {
        let source = r#"
            use std::fs;
            trait Readable {
                fn read_data(&self) -> Vec<u8> {
                    fs::read("default.dat").unwrap()
                }
                fn name(&self) -> &str;
            }
        "#;
        let parsed = parse_source(source, "test.rs").unwrap();
        // Only the default method with a body should be captured
        assert_eq!(parsed.functions.len(), 1);
        assert_eq!(parsed.functions[0].name, "read_data");
    }
}
