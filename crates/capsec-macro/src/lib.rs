//! # capsec-macro
//!
//! Procedural macros for the `capsec` capability-based security system.
//!
//! Provides attribute macros:
//!
//! - [`requires`] — declares and validates a function's capability requirements.
//! - [`deny`] — marks a function as capability-free for the lint tool.
//! - [`main`] — injects `CapRoot` creation into a function entry point.
//! - [`context`] — generates `Has<P>` impls and constructor for a capability context struct.
//!
//! These macros are re-exported by the `capsec` facade crate. You don't need to
//! depend on `capsec-macro` directly.

mod resolve;

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::punctuated::Punctuated;
use syn::{FnArg, ItemFn, ItemStruct, Meta, Pat, Token, Type, parse_macro_input};

/// The set of known permission type names (bare idents).
const KNOWN_PERMISSIONS: &[&str] = &[
    "FsRead",
    "FsWrite",
    "FsAll",
    "NetConnect",
    "NetBind",
    "NetAll",
    "EnvRead",
    "EnvWrite",
    "Spawn",
    "Ambient",
];

/// Declares the capability requirements of a function.
///
/// When all parameters use `impl Has<P>` bounds, the compiler already enforces
/// the trait bounds and this macro emits only a `#[doc]` attribute.
///
/// When concrete parameter types are used (e.g., context structs), use `on = param`
/// to identify the capability parameter. The macro emits a compile-time assertion
/// that the parameter type implements `Has<P>` for each declared permission.
///
/// # Usage
///
/// ```rust,ignore
/// // With impl bounds — no `on` needed
/// #[capsec::requires(fs::read, net::connect)]
/// fn sync_data(cap: &(impl Has<FsRead> + Has<NetConnect>)) -> Result<()> {
///     // ...
/// }
///
/// // With concrete context type — use `on = param`
/// #[capsec::requires(fs::read, net::connect, on = ctx)]
/// fn sync_data(config: &Config, ctx: &AppCtx) -> Result<()> {
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
    let attr2: proc_macro2::TokenStream = attr.into();
    let func = parse_macro_input!(item as ItemFn);

    match requires_inner(attr2, &func) {
        Ok(tokens) => tokens.into(),
        Err(e) => e.into_compile_error().into(),
    }
}

fn requires_inner(
    attr: proc_macro2::TokenStream,
    func: &ItemFn,
) -> syn::Result<proc_macro2::TokenStream> {
    let metas: Punctuated<Meta, Token![,]> =
        syn::parse::Parser::parse2(Punctuated::parse_terminated, attr)?;

    // Separate `on = param` from permission metas
    let mut on_param: Option<syn::Ident> = None;
    let mut perm_metas: Vec<&Meta> = Vec::new();

    for meta in &metas {
        if let Meta::NameValue(nv) = meta
            && nv.path.is_ident("on")
        {
            if let syn::Expr::Path(ep) = &nv.value
                && let Some(ident) = ep.path.get_ident()
            {
                on_param = Some(ident.clone());
                continue;
            }
            return Err(syn::Error::new_spanned(&nv.value, "expected an identifier"));
        }
        perm_metas.push(meta);
    }

    // Resolve permission types
    let mut cap_types = Vec::new();
    for meta in &perm_metas {
        cap_types.push(resolve::meta_to_permission_type(meta)?);
    }

    // Build doc string
    let doc_string = format!(
        "capsec::requires({})",
        cap_types
            .iter()
            .map(|c| quote!(#c).to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    // Check if any parameter uses `impl` trait bounds
    let has_impl_bounds = func.sig.inputs.iter().any(|arg| {
        if let FnArg::Typed(pat_type) = arg {
            contains_impl_trait(&pat_type.ty)
        } else {
            false
        }
    });

    // Build assertion block if needed
    let assertion = if let Some(ref param_name) = on_param {
        // Find the parameter and extract its type
        let param_type = find_param_type(&func.sig, param_name)?;
        let inner_type = unwrap_references(&param_type);

        let assert_fns: Vec<_> = cap_types
            .iter()
            .enumerate()
            .map(|(i, perm_ty)| {
                let fn_name = format_ident!("_assert_has_{}", i);
                quote! {
                    fn #fn_name<T: capsec_core::has::Has<#perm_ty>>() {}
                }
            })
            .collect();

        let assert_calls: Vec<_> = (0..cap_types.len())
            .map(|i| {
                let fn_name = format_ident!("_assert_has_{}", i);
                quote! { #fn_name::<#inner_type>(); }
            })
            .collect();

        Some(quote! {
            const _: () = {
                #(#assert_fns)*
                fn _check() {
                    #(#assert_calls)*
                }
            };
        })
    } else if !has_impl_bounds && !func.sig.inputs.is_empty() && !cap_types.is_empty() {
        // Concrete types present but no `on` keyword
        return Err(syn::Error::new_spanned(
            &func.sig,
            "#[capsec::requires] on a function with concrete parameter types requires \
             `on = <param>` to identify the capability parameter.\n\
             Example: #[capsec::requires(fs::read, on = ctx)]",
        ));
    } else {
        None
    };

    let func_vis = &func.vis;
    let func_sig = &func.sig;
    let func_block = &func.block;
    let func_attrs = &func.attrs;

    Ok(quote! {
        #(#func_attrs)*
        #[doc = #doc_string]
        #func_vis #func_sig {
            #assertion
            #func_block
        }
    })
}

fn contains_impl_trait(ty: &Type) -> bool {
    match ty {
        Type::ImplTrait(_) => true,
        Type::Reference(r) => contains_impl_trait(&r.elem),
        Type::Paren(p) => contains_impl_trait(&p.elem),
        _ => false,
    }
}

fn find_param_type(sig: &syn::Signature, name: &syn::Ident) -> syn::Result<Type> {
    for arg in &sig.inputs {
        if let FnArg::Typed(pat_type) = arg
            && let Pat::Ident(pi) = &*pat_type.pat
            && pi.ident == *name
        {
            return Ok((*pat_type.ty).clone());
        }
    }
    Err(syn::Error::new_spanned(
        name,
        format!("parameter '{}' not found in function signature", name),
    ))
}

fn unwrap_references(ty: &Type) -> &Type {
    match ty {
        Type::Reference(r) => unwrap_references(&r.elem),
        Type::Paren(p) => unwrap_references(&p.elem),
        _ => ty,
    }
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

/// Injects `CapRoot` creation into a function entry point.
///
/// Removes the first parameter (which must be typed as `CapRoot`) and prepends
/// `let {param_name} = capsec::root();` to the function body.
///
/// # Usage
///
/// ```rust,ignore
/// #[capsec::main]
/// fn main(root: CapRoot) {
///     let fs = root.fs_read();
///     // ...
/// }
/// ```
///
/// # With `#[tokio::main]`
///
/// Place `#[capsec::main]` above `#[tokio::main]`:
///
/// ```rust,ignore
/// #[capsec::main]
/// #[tokio::main]
/// async fn main(root: CapRoot) { ... }
/// ```
#[proc_macro_attribute]
pub fn main(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let func = parse_macro_input!(item as ItemFn);

    match main_inner(&func) {
        Ok(tokens) => tokens.into(),
        Err(e) => e.into_compile_error().into(),
    }
}

fn main_inner(func: &ItemFn) -> syn::Result<proc_macro2::TokenStream> {
    if func.sig.inputs.is_empty() {
        if func.sig.asyncness.is_some() {
            return Err(syn::Error::new_spanned(
                &func.sig,
                "#[capsec::main] found no CapRoot parameter. If combining with #[tokio::main], \
                 place #[capsec::main] above #[tokio::main]:\n\n  \
                 #[capsec::main]\n  \
                 #[tokio::main]\n  \
                 async fn main(root: CapRoot) { ... }",
            ));
        }
        return Err(syn::Error::new_spanned(
            &func.sig,
            "#[capsec::main] expected first parameter of type CapRoot",
        ));
    }

    // Extract first parameter
    let first_arg = &func.sig.inputs[0];
    let (param_name, param_type) = match first_arg {
        FnArg::Typed(pat_type) => {
            let name = if let Pat::Ident(pi) = &*pat_type.pat {
                pi.ident.clone()
            } else {
                return Err(syn::Error::new_spanned(
                    &pat_type.pat,
                    "#[capsec::main] expected a simple identifier for the CapRoot parameter",
                ));
            };
            (name, &*pat_type.ty)
        }
        FnArg::Receiver(r) => {
            return Err(syn::Error::new_spanned(
                r,
                "#[capsec::main] cannot be used on methods with self",
            ));
        }
    };

    // Validate type is CapRoot
    let type_str = quote!(#param_type).to_string().replace(' ', "");
    if type_str != "CapRoot" && type_str != "capsec::CapRoot" {
        return Err(syn::Error::new_spanned(
            param_type,
            "first parameter must be CapRoot",
        ));
    }

    // Build new signature without the first parameter
    let remaining_params: Vec<_> = func.sig.inputs.iter().skip(1).collect();
    let func_attrs = &func.attrs;
    let func_vis = &func.vis;
    let func_name = &func.sig.ident;
    let func_generics = &func.sig.generics;
    let func_output = &func.sig.output;
    let func_asyncness = &func.sig.asyncness;
    let func_block = &func.block;

    Ok(quote! {
        #(#func_attrs)*
        #func_vis #func_asyncness fn #func_name #func_generics(#(#remaining_params),*) #func_output {
            let #param_name = capsec::root();
            #func_block
        }
    })
}

/// Transforms a struct with permission-type fields into a capability context.
///
/// Generates:
/// - Field types rewritten from `PermType` to `Cap<PermType>` (or `SendCap<PermType>`)
/// - A `new(root: &CapRoot) -> Self` constructor
/// - `impl Has<P>` for each field's permission type
///
/// # Usage
///
/// ```rust,ignore
/// #[capsec::context]
/// struct AppCtx {
///     fs: FsRead,
///     net: NetConnect,
/// }
///
/// // Send variant for async/threaded code:
/// #[capsec::context(send)]
/// struct AsyncCtx {
///     fs: FsRead,
///     net: NetConnect,
/// }
/// ```
#[proc_macro_attribute]
pub fn context(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attr2: proc_macro2::TokenStream = attr.into();
    let input = parse_macro_input!(item as ItemStruct);

    match context_inner(attr2, &input) {
        Ok(tokens) => tokens.into(),
        Err(e) => e.into_compile_error().into(),
    }
}

fn context_inner(
    attr: proc_macro2::TokenStream,
    input: &ItemStruct,
) -> syn::Result<proc_macro2::TokenStream> {
    // Parse `send` flag
    let attr_str = attr.to_string();
    let is_send = match attr_str.trim() {
        "" => false,
        "send" => true,
        other => {
            return Err(syn::Error::new_spanned(
                &attr,
                format!("unexpected attribute '{}', expected empty or 'send'", other),
            ));
        }
    };

    // Reject generics
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            &input.generics,
            "#[capsec::context] does not support generic structs",
        ));
    }

    // Get named fields
    let fields = match &input.fields {
        syn::Fields::Named(f) => f,
        _ => {
            return Err(syn::Error::new_spanned(
                input,
                "#[capsec::context] requires a struct with named fields",
            ));
        }
    };

    // Validate fields and collect permission info
    let mut field_infos: Vec<(syn::Ident, syn::Ident)> = Vec::new(); // (field_name, perm_ident)
    let mut seen_perms: std::collections::HashSet<String> = std::collections::HashSet::new();

    for field in &fields.named {
        let field_name = field.ident.as_ref().unwrap().clone();
        let ty = &field.ty;

        // Check for tuple types
        if let Type::Tuple(_) = ty {
            return Err(syn::Error::new_spanned(
                ty,
                "tuple permission types are not supported in context structs — use separate fields instead",
            ));
        }

        // Extract type ident (last segment of path)
        let perm_ident = match ty {
            Type::Path(tp) => {
                if let Some(seg) = tp.path.segments.last() {
                    seg.ident.clone()
                } else {
                    return Err(syn::Error::new_spanned(
                        ty,
                        format!(
                            "field '{}' has type '{}', which is not a capsec permission type. \
                             Expected one of: {}",
                            field_name,
                            quote!(#ty),
                            KNOWN_PERMISSIONS.join(", ")
                        ),
                    ));
                }
            }
            _ => {
                return Err(syn::Error::new_spanned(
                    ty,
                    format!(
                        "field '{}' has type '{}', which is not a capsec permission type. \
                         Expected one of: {}",
                        field_name,
                        quote!(#ty),
                        KNOWN_PERMISSIONS.join(", ")
                    ),
                ));
            }
        };

        let perm_str = perm_ident.to_string();

        // Validate against known permissions
        if !KNOWN_PERMISSIONS.contains(&perm_str.as_str()) {
            return Err(syn::Error::new_spanned(
                ty,
                format!(
                    "field '{}' has type '{}', which is not a capsec permission type. \
                     Expected one of: {}",
                    field_name,
                    perm_str,
                    KNOWN_PERMISSIONS.join(", ")
                ),
            ));
        }

        // Check for duplicates
        if !seen_perms.insert(perm_str.clone()) {
            return Err(syn::Error::new_spanned(
                ty,
                format!(
                    "duplicate permission type '{}' — each permission can only appear once in a context struct",
                    perm_str
                ),
            ));
        }

        field_infos.push((field_name, perm_ident));
    }

    let struct_name = &input.ident;
    let struct_vis = &input.vis;
    let struct_attrs = &input.attrs;

    // Generate struct fields with rewritten types
    let struct_fields: Vec<_> = field_infos
        .iter()
        .map(|(name, perm)| {
            if is_send {
                quote! { #name: capsec_core::cap::SendCap<capsec_core::permission::#perm> }
            } else {
                quote! { #name: capsec_core::cap::Cap<capsec_core::permission::#perm> }
            }
        })
        .collect();

    // Generate constructor fields
    let constructor_fields: Vec<_> = field_infos
        .iter()
        .map(|(name, perm)| {
            if is_send {
                quote! { #name: root.grant::<capsec_core::permission::#perm>().make_send() }
            } else {
                quote! { #name: root.grant::<capsec_core::permission::#perm>() }
            }
        })
        .collect();

    // Generate Has<P> impls
    let has_impls: Vec<_> = field_infos
        .iter()
        .map(|(name, perm)| {
            quote! {
                impl capsec_core::has::Has<capsec_core::permission::#perm> for #struct_name {
                    fn cap_ref(&self) -> capsec_core::cap::Cap<capsec_core::permission::#perm> {
                        self.#name.cap_ref()
                    }
                }
            }
        })
        .collect();

    Ok(quote! {
        #(#struct_attrs)*
        #struct_vis struct #struct_name {
            #(#struct_fields,)*
        }

        impl #struct_name {
            /// Creates a new context by granting all capabilities from the root.
            pub fn new(root: &capsec_core::root::CapRoot) -> Self {
                Self {
                    #(#constructor_fields,)*
                }
            }
        }

        #(#has_impls)*
    })
}
