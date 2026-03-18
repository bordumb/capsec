//! # capsec-macro
//!
//! Procedural macros for the `capsec` capability-based security system.
//!
//! Provides two attribute macros:
//!
//! - [`requires`] — declares a function's capability requirements for tooling
//!   and documentation.
//! - [`deny`] — marks a function as capability-free for the lint tool.
//!
//! These macros are re-exported by the `capsec` facade crate. You don't need to
//! depend on `capsec-macro` directly.

mod resolve;

use proc_macro::TokenStream;
use quote::quote;
use syn::punctuated::Punctuated;
use syn::{ItemFn, Meta, Token, parse_macro_input};

/// Declares the capability requirements of a function.
///
/// **This macro is documentation-only.** It adds a `#[doc]` attribute for
/// tooling and human readers. It does **not** enforce anything at compile
/// time — no trait bound assertions are emitted.
///
/// Actual enforcement comes from the `Has<P>` trait bounds on the function's
/// capability parameter. If a function takes `cap: &impl Has<FsRead>`, the
/// compiler will reject callers that pass the wrong capability type regardless
/// of whether `#[requires]` is present. The macro exists to make the intent
/// explicit and machine-readable.
///
/// # Usage
///
/// ```rust,ignore
/// #[capsec::requires(fs::read, net::connect)]
/// fn sync_data(cap: &impl Has<FsRead> + Has<NetConnect>) -> Result<()> {
///     // ...
/// }
/// ```
///
/// # Supported permission paths
///
/// Both shorthand and explicit forms are accepted:
///
/// | Shorthand | Explicit | Permission type |
/// |-----------|----------|-----------------|
/// | `fs::read` | `FsRead` | `capsec_core::permission::FsRead` |
/// | `fs::write` | `FsWrite` | `capsec_core::permission::FsWrite` |
/// | `net::connect` | `NetConnect` | `capsec_core::permission::NetConnect` |
/// | `net::bind` | `NetBind` | `capsec_core::permission::NetBind` |
/// | `env::read` | `EnvRead` | `capsec_core::permission::EnvRead` |
/// | `env::write` | `EnvWrite` | `capsec_core::permission::EnvWrite` |
/// | `spawn` | `Spawn` | `capsec_core::permission::Spawn` |
/// | `all` | `Ambient` | `capsec_core::permission::Ambient` |
#[proc_macro_attribute]
pub fn requires(attr: TokenStream, item: TokenStream) -> TokenStream {
    let capabilities =
        parse_macro_input!(attr with Punctuated::<Meta, Token![,]>::parse_terminated);
    let func = parse_macro_input!(item as ItemFn);

    let cap_names: Vec<_> = capabilities
        .iter()
        .map(|meta| match resolve::meta_to_permission_type(meta) {
            Ok(tokens) => tokens,
            Err(e) => e.into_compile_error(),
        })
        .collect();

    let doc_string = format!(
        "capsec::requires({})",
        cap_names
            .iter()
            .map(|c| quote!(#c).to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let func_vis = &func.vis;
    let func_sig = &func.sig;
    let func_block = &func.block;
    let func_attrs = &func.attrs;

    let expanded = quote! {
        #(#func_attrs)*
        #[doc = #doc_string]
        #func_vis #func_sig
            #func_block
    };

    expanded.into()
}

/// Marks a function as capability-free.
///
/// This is a declaration for the `cargo capsec check` lint tool — any ambient
/// authority call found inside a `#[deny]` function will be flagged as a violation.
///
/// The macro itself does not enforce anything at compile time (there's no type-system
/// mechanism to prevent `std::fs` imports). Enforcement is in the lint tool.
///
/// # Usage
///
/// ```rust,ignore
/// // Deny all I/O
/// #[capsec::deny(all)]
/// fn pure_transform(input: &[u8]) -> Vec<u8> {
///     input.iter().map(|b| b.wrapping_add(1)).collect()
/// }
///
/// // Deny only network access
/// #[capsec::deny(net)]
/// fn local_only(cap: &impl Has<FsRead>) -> Vec<u8> {
///     capsec::fs::read("/tmp/data", cap).unwrap()
/// }
/// ```
///
/// # Supported categories
///
/// `all`, `fs`, `net`, `env`, `process`
#[proc_macro_attribute]
pub fn deny(attr: TokenStream, item: TokenStream) -> TokenStream {
    let denied = parse_macro_input!(attr with Punctuated::<Meta, Token![,]>::parse_terminated);

    let item_clone: proc_macro2::TokenStream = item.clone().into();
    let func = match syn::parse::<ItemFn>(item) {
        Ok(f) => f,
        Err(e) => {
            let err = e.into_compile_error();
            return quote! { #err #item_clone }.into();
        }
    };

    let deny_names: Vec<String> = denied
        .iter()
        .map(|meta| {
            meta.path()
                .get_ident()
                .map(|i| i.to_string())
                .unwrap_or_default()
        })
        .collect();

    let doc_string = format!("capsec::deny({})", deny_names.join(", "));

    let func_vis = &func.vis;
    let func_sig = &func.sig;
    let func_block = &func.block;
    let func_attrs = &func.attrs;

    let expanded = quote! {
        #(#func_attrs)*
        #[doc = #doc_string]
        #func_vis #func_sig
            #func_block
    };

    expanded.into()
}
