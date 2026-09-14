// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deliberately bounded extraction of the service's actual Rust registration
//! syntax. New composition forms require explicit support rather than silently
//! disappearing from the contract. This is an inventory, not a Rust interpreter.

use quote::ToTokens;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use syn::visit::{self, Visit};
use syn::{Attribute, Expr, ImplItem, Item, ItemFn, Lit, Meta, Pat, Stmt};

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct RestRoute {
    pub method: String,
    pub path: String,
    pub handler: String,
    pub feature: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct GrpcMethod {
    /// Actual Rust method identifier, without inferred casing conversion.
    pub name: String,
    pub crypto_feature: bool,
    pub body_sha256: String,
}

fn read_ast(path: &Path) -> Result<syn::File, String> {
    let source = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    syn::parse_file(&source).map_err(|e| format!("{}: {e}", path.display()))
}

fn source_files(directory: &Path, output: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = std::fs::read_dir(directory).map_err(|e| e.to_string())?;
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_symlink() {
            return Err(format!(
                "service source symlink requires review: {}",
                path.display()
            ));
        }
        if path.is_dir() {
            source_files(&path, output)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            output.push(path);
        }
    }
    Ok(())
}

fn path_text(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn called(expr: &Expr, name: &str) -> bool {
    matches!(expr, Expr::Path(value) if value.qself.is_none() && path_text(&value.path) == name)
}

fn ident(expr: &Expr, name: &str) -> bool {
    called(expr, name)
}

fn literal(expr: &Expr) -> Option<String> {
    if let Expr::Lit(value) = expr {
        if let Lit::Str(text) = &value.lit {
            return Some(text.value());
        }
    }
    None
}

fn cfg_meta(attr: &Attribute) -> Result<Option<Meta>, String> {
    if attr.path().is_ident("cfg_attr") {
        return Err("cfg_attr requires explicit surface extractor support".into());
    }
    if !attr.path().is_ident("cfg") {
        return Ok(None);
    }
    attr.parse_args()
        .map(Some)
        .map_err(|e| format!("invalid cfg: {e}"))
}

fn requires_test(meta: &Meta) -> bool {
    match meta {
        Meta::Path(path) => path.is_ident("test"),
        Meta::List(list) if list.path.is_ident("all") => list
            .parse_args_with(syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated)
            .is_ok_and(|items| items.iter().any(requires_test)),
        _ => false,
    }
}

fn test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || (attr.path().is_ident("cfg")
                && attr
                    .parse_args::<Meta>()
                    .is_ok_and(|meta| requires_test(&meta)))
    })
}

fn crypto_cfg(attrs: &[Attribute]) -> Result<Option<bool>, String> {
    let mut result = None;
    for attr in attrs {
        let Some(meta) = cfg_meta(attr)? else {
            continue;
        };
        let (enabled, candidate) = match meta {
            Meta::List(list) if list.path.is_ident("not") => {
                (false, list.parse_args::<Meta>().map_err(|e| e.to_string())?)
            }
            other => (true, other),
        };
        match candidate {
            Meta::NameValue(value)
                if value.path.is_ident("feature")
                    && literal(&value.value).as_deref() == Some("crypto-endpoints") => {}
            _ => return Err("unsupported surface cfg; expected crypto-endpoints".into()),
        }
        if result.replace(enabled).is_some() {
            return Err("multiple surface cfg attributes require review".into());
        }
    }
    Ok(result)
}

fn item_attrs(item: &Item) -> &[Attribute] {
    match item {
        Item::Fn(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Const(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Macro(item) => &item.attrs,
        _ => &[],
    }
}

#[derive(Default)]
struct SurfaceScan {
    in_router: bool,
    allowed_router_file: bool,
    routes: usize,
    registrations: usize,
    implementations: usize,
    errors: Vec<String>,
}

impl<'ast> Visit<'ast> for SurfaceScan {
    fn visit_item(&mut self, item: &'ast Item) {
        if !test_only(item_attrs(item)) {
            visit::visit_item(self, item);
        }
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if !test_only(&item.attrs) {
            visit::visit_impl_item_fn(self, item);
        }
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if item.trait_.as_ref().is_some_and(|(_, path, _)| {
            path.segments
                .last()
                .is_some_and(|segment| segment.ident == "KeyService")
        }) {
            self.implementations += 1;
        }
        visit::visit_item_impl(self, item);
    }

    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        let previous = self.in_router;
        self.in_router = self.allowed_router_file && item.sig.ident == "router";
        visit::visit_item_fn(self, item);
        self.in_router = previous;
    }

    fn visit_expr_method_call(&mut self, expr: &'ast syn::ExprMethodCall) {
        let method = expr.method.to_string();
        match method.as_str() {
            "route" => {
                self.routes += 1;
                if !self.in_router {
                    self.errors
                        .push("route registration outside rest::router requires review".into());
                }
            }
            "route_service"
            | "nest"
            | "nest_service"
            | "merge"
            | "fallback"
            | "fallback_service"
            | "method_not_allowed_fallback" => self
                .errors
                .push(format!("unsupported service router composition: {method}")),
            "add_service" | "add_optional_service" => self.registrations += 1,
            _ => {}
        }
        visit::visit_expr_method_call(self, expr);
    }
}

fn scan_service(root: &Path) -> Result<BTreeMap<PathBuf, syn::File>, String> {
    let source = root.join("crates/keyrack-service/src");
    let mut files = Vec::new();
    source_files(&source, &mut files)?;
    files.sort();
    let mut result = BTreeMap::new();
    let mut registrations = 0;
    let mut implementations = 0;
    for file in files {
        let ast = read_ast(&file)?;
        let mut scan = SurfaceScan {
            allowed_router_file: file == source.join("rest.rs"),
            ..SurfaceScan::default()
        };
        scan.visit_file(&ast);
        if !scan.errors.is_empty() {
            return Err(format!("{}: {}", file.display(), scan.errors.join("; ")));
        }
        registrations += scan.registrations;
        implementations += scan.implementations;
        result.insert(
            file.strip_prefix(&source)
                .map_err(|e| e.to_string())?
                .to_path_buf(),
            ast,
        );
    }
    if implementations != 1 {
        return Err(format!(
            "expected one production KeyService impl; found {implementations}"
        ));
    }
    if registrations != 1 {
        return Err(format!(
            "expected one gRPC service registration; found {registrations}"
        ));
    }
    verify_main(result.get(Path::new("main.rs")).ok_or("missing main.rs")?)?;
    Ok(result)
}

fn method_router(
    expr: &Expr,
    path: &str,
    feature: Option<&str>,
    routes: &mut Vec<RestRoute>,
) -> Result<(), String> {
    let (name, args) = match expr {
        Expr::Call(call) => {
            let Expr::Path(function) = call.func.as_ref() else {
                return Err("dynamic REST method factory requires review".into());
            };
            (path_text(&function.path), &call.args)
        }
        Expr::MethodCall(call) => {
            method_router(&call.receiver, path, feature, routes)?;
            (call.method.to_string(), &call.args)
        }
        _ => return Err("unsupported REST method-router syntax".into()),
    };
    if ![
        "get", "post", "put", "delete", "patch", "head", "options", "trace",
    ]
    .contains(&name.as_str())
        || args.len() != 1
    {
        return Err(format!(
            "unsupported REST method-router constructor: {name}"
        ));
    }
    let Expr::Path(handler) = &args[0] else {
        return Err("REST handler must be a named function, not a closure/dynamic value".into());
    };
    if handler.qself.is_some() || handler.path.segments.len() != 1 {
        return Err("qualified REST handler requires explicit extractor support".into());
    }
    routes.push(RestRoute {
        method: name.to_uppercase(),
        path: path.into(),
        handler: handler.path.segments[0].ident.to_string(),
        feature: feature.map(str::to_owned),
    });
    Ok(())
}

fn router_chain(
    expr: &Expr,
    initial: bool,
    feature: Option<&str>,
    routes: &mut Vec<RestRoute>,
) -> Result<(), String> {
    match expr {
        Expr::Call(call)
            if initial && called(&call.func, "Router::new") && call.args.is_empty() =>
        {
            Ok(())
        }
        Expr::Path(_) if !initial && ident(expr, "r") => Ok(()),
        Expr::MethodCall(call) => {
            router_chain(&call.receiver, initial, feature, routes)?;
            match call.method.to_string().as_str() {
                "route" if call.args.len() == 2 => {
                    let path =
                        literal(&call.args[0]).ok_or("REST paths must be string literals")?;
                    if !path.starts_with('/') {
                        return Err("REST path must be absolute".into());
                    }
                    method_router(&call.args[1], &path, feature, routes)
                }
                "layer" if call.args.len() == 1 => {
                    // Only the known transport-neutral request-ID layer is
                    // accepted. A new middleware may alter reachability.
                    let Expr::Call(layer) = &call.args[0] else {
                        return Err("unsupported router layer".into());
                    };
                    if called(&layer.func, "middleware::from_fn")
                        && layer.args.len() == 1
                        && ident(&layer.args[0], "echo_request_id")
                    {
                        Ok(())
                    } else {
                        Err("new router middleware requires surface review".into())
                    }
                }
                "with_state" if call.args.len() == 1 && ident(&call.args[0], "state") => Ok(()),
                other => Err(format!("unsupported router chain operation: {other}")),
            }
        }
        _ => Err(
            "unsupported router expression; dynamic/conditional composition requires review".into(),
        ),
    }
}

fn extract_router(function: &ItemFn) -> Result<Vec<RestRoute>, String> {
    if crypto_cfg(&function.attrs)?.is_some() {
        return Err("entire REST router cannot be conditionally hidden".into());
    }
    let mut routes = Vec::new();
    let mut initialized = false;
    let mut returned = false;
    for statement in &function.block.stmts {
        match statement {
            Stmt::Local(local) if !returned => {
                let Pat::Ident(pattern) = &local.pat else {
                    return Err("router binding must be r".into());
                };
                if pattern.ident != "r" || pattern.mutability.is_some() || pattern.subpat.is_some()
                {
                    return Err("unsupported router binding; expected immutable r".into());
                }
                let cfg = crypto_cfg(&local.attrs)?;
                if cfg == Some(false) || (!initialized && cfg.is_some()) {
                    return Err("unsupported conditional router initialization".into());
                }
                let binding = local
                    .init
                    .as_ref()
                    .ok_or("router binding has no initializer")?;
                if binding.diverge.is_some() {
                    return Err("router let-else requires review".into());
                }
                router_chain(
                    &binding.expr,
                    !initialized,
                    cfg.map(|_| "crypto-endpoints"),
                    &mut routes,
                )?;
                initialized = true;
            }
            Stmt::Expr(expr, None) if initialized && !returned => {
                router_chain(expr, false, None, &mut routes)?;
                returned = true;
            }
            _ => return Err("unsupported router statement or early return".into()),
        }
    }
    if !returned {
        return Err("REST router has no recognized return chain".into());
    }
    let mut unique = BTreeSet::new();
    for route in &routes {
        if !unique.insert((&route.method, &route.path)) {
            return Err(format!(
                "duplicate REST registration: {} {}",
                route.method, route.path
            ));
        }
    }
    routes.sort_by(|a, b| (&a.path, &a.method).cmp(&(&b.path, &b.method)));
    Ok(routes)
}

pub fn rest_routes(root: &Path) -> Result<Vec<RestRoute>, String> {
    let files = scan_service(root)?;
    let file = files.get(Path::new("rest.rs")).ok_or("missing rest.rs")?;
    let functions: Vec<_> = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Fn(function) if function.sig.ident == "router" && !test_only(&function.attrs) => {
                Some(function)
            }
            _ => None,
        })
        .collect();
    if functions.len() != 1 {
        return Err("expected exactly one rest::router function".into());
    }
    let routes = extract_router(functions[0])?;
    for route in &routes {
        let handlers: Vec<_> = file
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Fn(function)
                    if function.sig.ident == route.handler && !test_only(&function.attrs) =>
                {
                    Some(function)
                }
                _ => None,
            })
            .collect();
        if handlers.len() != 1 {
            return Err(format!(
                "missing or ambiguous REST handler: {}",
                route.handler
            ));
        }
        let expected = route.feature.as_ref().map(|_| true);
        if crypto_cfg(&handlers[0].attrs)? != expected {
            return Err(format!(
                "REST handler/route cfg mismatch: {}",
                route.handler
            ));
        }
    }
    Ok(routes)
}

#[derive(Default)]
struct DisabledCalls {
    calls: usize,
}
impl<'ast> Visit<'ast> for DisabledCalls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if called(&call.func, "crypto_disabled") {
            self.calls += 1;
        }
        visit::visit_expr_call(self, call);
    }
}

fn disabled_return(block: &syn::Block) -> bool {
    let Some(Stmt::Expr(Expr::Return(value), Some(_))) = block.stmts.last() else {
        return false;
    };
    let Some(Expr::Call(error)) = value.expr.as_deref() else {
        return false;
    };
    if !called(&error.func, "Err") || error.args.len() != 1 {
        return false;
    }
    let Expr::Call(disabled) = &error.args[0] else {
        return false;
    };
    called(&disabled.func, "crypto_disabled")
        && disabled.args.len() == 1
        && literal(&disabled.args[0]).is_some()
}

fn extract_grpc(method: &syn::ImplItemFn) -> Result<GrpcMethod, String> {
    if crypto_cfg(&method.attrs)?.is_some() {
        return Err("RPC itself must remain registered in both feature modes".into());
    }
    let mut visitor = DisabledCalls::default();
    visitor.visit_block(&method.block);
    let guards: Vec<_> = method
        .block
        .stmts
        .iter()
        .filter_map(|statement| {
            if let Stmt::Expr(Expr::Block(block), _) = statement {
                Some(block)
            } else {
                None
            }
        })
        .map(|block| crypto_cfg(&block.attrs).map(|cfg| (cfg, block)))
        .collect::<Result<_, _>>()?;
    let guarded: Vec<_> = guards.iter().filter(|(cfg, _)| cfg.is_some()).collect();
    let crypto_feature = if guarded.is_empty() && visitor.calls == 0 {
        false
    } else {
        if method.block.stmts.len() != 2
            || guarded.len() != 2
            || visitor.calls != 1
            || guarded[0].0 != Some(false)
            || guarded[1].0 != Some(true)
            || !disabled_return(&guarded[0].1.block)
        {
            return Err(format!(
                "RPC {} has unsupported or incomplete crypto feature guard",
                method.sig.ident
            ));
        }
        true
    };
    Ok(GrpcMethod {
        name: method.sig.ident.to_string(),
        crypto_feature,
        body_sha256: format!(
            "{:x}",
            Sha256::digest(method.block.to_token_stream().to_string().as_bytes())
        ),
    })
}

fn verify_disabled_helper(file: &syn::File) -> Result<(), String> {
    let helpers: Vec<_> = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Fn(function) if function.sig.ident == "crypto_disabled" => Some(function),
            _ => None,
        })
        .collect();
    if helpers.len() != 1 || crypto_cfg(&helpers[0].attrs)? != Some(false) {
        return Err("expected one crypto-disabled helper gated by not(feature)".into());
    }
    if helpers[0].block.stmts.len() != 1 {
        return Err("crypto-disabled helper behavior changed".into());
    }
    let Some(Stmt::Expr(expr, None)) = helpers[0].block.stmts.last() else {
        return Err("crypto-disabled helper has no recognized result".into());
    };
    if !call(expr, "Status::unimplemented", 1) {
        return Err("crypto-disabled RPCs must return UNIMPLEMENTED".into());
    }
    Ok(())
}

pub fn grpc_methods(root: &Path) -> Result<Vec<GrpcMethod>, String> {
    let files = scan_service(root)?;
    verify_disabled_helper(files.get(Path::new("grpc.rs")).ok_or("missing grpc.rs")?)?;
    let mut methods = Vec::new();
    let mut implementations = 0;
    for (path, file) in files {
        for item in file.items {
            let Item::Impl(implementation) = item else {
                continue;
            };
            if test_only(&implementation.attrs) {
                continue;
            }
            let Some((_, trait_path, _)) = &implementation.trait_ else {
                continue;
            };
            if trait_path
                .segments
                .last()
                .is_none_or(|segment| segment.ident != "KeyService")
            {
                continue;
            }
            implementations += 1;
            if path != Path::new("grpc.rs")
                || implementation.self_ty.to_token_stream().to_string() != "KeyServiceImpl"
            {
                return Err(
                    "KeyService implementation moved/changed; explicit surface review required"
                        .into(),
                );
            }
            for item in &implementation.items {
                match item {
                    ImplItem::Fn(method) if !test_only(&method.attrs) => {
                        methods.push(extract_grpc(method)?);
                    }
                    ImplItem::Fn(_) => {}
                    _ => return Err("unsupported non-method KeyService impl item".into()),
                }
            }
        }
    }
    if implementations != 1 {
        return Err("expected exactly one KeyService implementation".into());
    }
    methods.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(methods)
}

/// Verify the declared protobuf mapping against the actual Rust request and
/// response types. Descriptor names are supplied by the caller, not inferred
/// from RPC spelling.
pub fn verify_rpc_binding(
    root: &Path,
    grpc_handler: &str,
    request_type: &str,
    response_type: &str,
) -> Result<(), String> {
    let file = read_ast(&root.join("crates/keyrack-service/src/grpc.rs"))?;
    let mut matches = Vec::new();
    for item in &file.items {
        let Item::Impl(implementation) = item else {
            continue;
        };
        if test_only(&implementation.attrs) {
            continue;
        }
        if !implementation.trait_.as_ref().is_some_and(|(_, path, _)| {
            path.segments
                .last()
                .is_some_and(|segment| segment.ident == "KeyService")
        }) {
            continue;
        }
        for item in &implementation.items {
            if let ImplItem::Fn(method) = item {
                if method.sig.ident == grpc_handler && !test_only(&method.attrs) {
                    matches.push(method);
                }
            }
        }
    }
    if matches.len() != 1 {
        return Err(format!("missing/ambiguous gRPC handler {grpc_handler}"));
    }
    let method = matches[0];
    let inputs: Vec<_> = method
        .sig
        .inputs
        .iter()
        .filter_map(|input| match input {
            syn::FnArg::Typed(value) => Some(value.ty.as_ref()),
            syn::FnArg::Receiver(_) => None,
        })
        .collect();
    if inputs.len() != 1 {
        return Err(format!("unexpected request arity for {grpc_handler}"));
    }
    let request = generic_type(inputs[0], "Request", 0)?;
    if !proto_type(request, request_type) {
        return Err(format!(
            "gRPC {grpc_handler} request does not bind descriptor type {request_type}"
        ));
    }
    let syn::ReturnType::Type(_, output) = &method.sig.output else {
        return Err(format!("gRPC {grpc_handler} has no response type"));
    };
    let response = generic_type(generic_type(output, "Result", 0)?, "Response", 0)?;
    if !proto_type(response, response_type) {
        return Err(format!(
            "gRPC {grpc_handler} response does not bind descriptor type {response_type}"
        ));
    }
    Ok(())
}

fn generic_type<'a>(
    value: &'a syn::Type,
    wrapper: &str,
    index: usize,
) -> Result<&'a syn::Type, String> {
    let syn::Type::Path(path) = value else {
        return Err(format!("expected {wrapper} type"));
    };
    let segment = path.path.segments.last().ok_or("empty type path")?;
    if segment.ident != wrapper || path.qself.is_some() {
        return Err(format!("expected {wrapper} type wrapper"));
    }
    let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return Err(format!("expected generic arguments for {wrapper}"));
    };
    let Some(syn::GenericArgument::Type(value)) = arguments.args.iter().nth(index) else {
        return Err(format!("missing {wrapper} type argument"));
    };
    Ok(value)
}

fn proto_type(value: &syn::Type, name: &str) -> bool {
    matches!(value, syn::Type::Path(path) if path.qself.is_none()
        && path_text(&path.path) == format!("proto::{name}")
        && path.path.segments.iter().all(|segment| matches!(segment.arguments, syn::PathArguments::None)))
}

#[derive(Default)]
struct ConditionalWiring {
    found: bool,
}
impl<'ast> Visit<'ast> for ConditionalWiring {
    fn visit_attribute(&mut self, attribute: &'ast Attribute) {
        self.found |= attribute.path().is_ident("cfg") || attribute.path().is_ident("cfg_attr");
        visit::visit_attribute(self, attribute);
    }
}

fn local<'a>(function: &'a ItemFn, name: &str) -> Result<&'a Expr, String> {
    let values: Vec<_> = function
        .block
        .stmts
        .iter()
        .filter_map(|statement| {
            let Stmt::Local(local) = statement else {
                return None;
            };
            let Pat::Ident(pattern) = &local.pat else {
                return None;
            };
            if pattern.ident != name {
                return None;
            }
            Some((
                local.attrs.as_slice(),
                local.init.as_ref().map(|value| value.expr.as_ref()),
            ))
        })
        .collect();
    match values.as_slice() {
        [(attrs, Some(value))] => {
            if attrs
                .iter()
                .any(|attr| attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr"))
            {
                return Err(format!(
                    "conditional listener binding requires explicit support: {name}"
                ));
            }
            Ok(value)
        }
        _ => Err(format!("main must bind {name} exactly once")),
    }
}

fn call(expr: &Expr, name: &str, argc: usize) -> bool {
    matches!(expr, Expr::Call(value) if called(&value.func, name) && value.args.len() == argc)
}

fn spawned_tail(expr: &Expr) -> Result<&Expr, String> {
    let mut conditional = ConditionalWiring::default();
    conditional.visit_expr(expr);
    if conditional.found {
        return Err("conditional listener spawn requires explicit surface support".into());
    }
    let Expr::Call(spawn) = expr else {
        return Err("listener must use tokio::spawn".into());
    };
    if !called(&spawn.func, "tokio::spawn") || spawn.args.len() != 1 {
        return Err("unsupported listener spawn".into());
    }
    let Expr::Async(body) = &spawn.args[0] else {
        return Err("listener must be an async block".into());
    };
    let Some(Stmt::Expr(Expr::Await(tail), None)) = body.block.stmts.last() else {
        return Err("listener async block must await its serving future".into());
    };
    Ok(&tail.base)
}

#[derive(Default)]
struct WiringBindings {
    counts: BTreeMap<String, usize>,
    invalid: bool,
}
impl<'ast> Visit<'ast> for WiringBindings {
    fn visit_pat_ident(&mut self, pattern: &'ast syn::PatIdent) {
        let name = pattern.ident.to_string();
        if ["rest_router", "grpc_service", "rest_listener"].contains(&name.as_str()) {
            *self.counts.entry(name).or_default() += 1;
            self.invalid |= pattern.mutability.is_some() || pattern.subpat.is_some();
        }
        visit::visit_pat_ident(self, pattern);
    }
}

fn imported(file: &syn::File, expected: &str) -> bool {
    fn flatten(tree: &syn::UseTree, prefix: &str, output: &mut Vec<String>) {
        match tree {
            syn::UseTree::Path(path) => {
                flatten(&path.tree, &format!("{prefix}{}::", path.ident), output);
            }
            syn::UseTree::Name(name) => output.push(format!("{prefix}{}", name.ident)),
            syn::UseTree::Group(group) => {
                for item in &group.items {
                    flatten(item, prefix, output);
                }
            }
            syn::UseTree::Rename(_) | syn::UseTree::Glob(_) => {}
        }
    }
    let mut paths = Vec::new();
    for item in &file.items {
        if let Item::Use(item) = item {
            flatten(&item.tree, "", &mut paths);
        }
    }
    paths
        .iter()
        .filter(|path| path.as_str() == expected)
        .count()
        == 1
}

fn verify_main(file: &syn::File) -> Result<(), String> {
    let mains: Vec<_> = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Fn(function) if function.sig.ident == "main" => Some(function),
            _ => None,
        })
        .collect();
    if mains.len() != 1 {
        return Err("expected one service main".into());
    }
    let main = mains[0];
    for required in [
        "keyrack_service::grpc::KeyServiceImpl",
        "keyrack_service::proto::key_service_server::KeyServiceServer",
    ] {
        if !imported(file, required) {
            return Err(format!("listener type import changed: {required}"));
        }
    }
    let mut bindings = WiringBindings::default();
    bindings.visit_block(&main.block);
    if bindings.invalid
        || ["rest_router", "grpc_service", "rest_listener"]
            .iter()
            .any(|name| bindings.counts.get(*name) != Some(&1))
    {
        return Err("listener router/service bindings may not be mutable or shadowed".into());
    }
    let Expr::Try(listener) = local(main, "rest_listener")? else {
        return Err("unsupported REST listener binding".into());
    };
    let Expr::Await(listener) = listener.expr.as_ref() else {
        return Err("REST listener bind must be awaited".into());
    };
    if !call(&listener.base, "tokio::net::TcpListener::bind", 1) {
        return Err("REST listener is not bound".into());
    }

    if !call(
        local(main, "rest_router")?,
        "keyrack_service::rest::router",
        1,
    ) {
        return Err("main no longer constructs the inventoried rest::router".into());
    }
    let grpc = local(main, "grpc_service")?;
    if !call(grpc, "KeyServiceServer::new", 1) {
        return Err("main no longer constructs KeyServiceServer".into());
    }
    let Expr::Call(grpc) = grpc else {
        unreachable!()
    };
    if !call(&grpc.args[0], "KeyServiceImpl::new", 1) {
        return Err("main serves a different KeyService implementation".into());
    }
    let rest = spawned_tail(local(main, "rest_handle")?)?;
    let Expr::MethodCall(shutdown) = rest else {
        return Err("unsupported REST listener future".into());
    };
    if shutdown.method != "with_graceful_shutdown" || !call(&shutdown.receiver, "axum::serve", 2) {
        return Err("main no longer serves inventoried REST router".into());
    }
    let Expr::Call(serve) = shutdown.receiver.as_ref() else {
        unreachable!()
    };
    if !ident(&serve.args[0], "rest_listener") || !ident(&serve.args[1], "rest_router") {
        return Err("REST listener uses a different router".into());
    }
    let grpc = spawned_tail(local(main, "grpc_handle")?)?;
    let Expr::MethodCall(serve) = grpc else {
        return Err("unsupported gRPC listener future".into());
    };
    if serve.method != "serve_with_shutdown" {
        return Err("gRPC listener is not served".into());
    }
    let Expr::MethodCall(register) = serve.receiver.as_ref() else {
        return Err("missing gRPC service registration".into());
    };
    if register.method != "add_service"
        || register.args.len() != 1
        || !ident(&register.args[0], "grpc_service")
    {
        return Err("gRPC listener serves a different service".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn router(source: &str) -> Result<Vec<RestRoute>, String> {
        extract_router(&syn::parse_str::<ItemFn>(source).unwrap())
    }

    #[test]
    fn extracts_method_chains_and_feature_scopes() {
        let result = router(
            r#"fn router(state: State) -> Router {
            let r = Router::new().route("/items", get(list).post(create));
            #[cfg(feature = "crypto-endpoints")]
            let r = r.route("/crypto", post(encrypt));
            r.route("/healthz", get(health)).with_state(state)
        }"#,
        )
        .unwrap();
        assert_eq!(result.len(), 4);
        assert_eq!(result.iter().filter(|r| r.feature.is_some()).count(), 1);
        assert_eq!(
            result
                .iter()
                .find(|r| r.handler == "encrypt")
                .unwrap()
                .feature
                .as_deref(),
            Some("crypto-endpoints")
        );
    }

    #[test]
    fn rejects_dynamic_paths_closures_and_hidden_composition() {
        for source in [
            r"fn router(state: State) -> Router { let r = Router::new().route(PATH, get(list)); r }",
            r#"fn router(state: State) -> Router { let r = Router::new().route("/", get(|| async {})); r }"#,
            r"fn router(state: State) -> Router { let r = Router::new(); r.merge(other()) }",
            r"fn router(state: State) -> Router { let r = Router::new(); if true { r } else { other() } }",
        ] {
            assert!(router(source).is_err(), "{source}");
        }
    }

    #[test]
    fn scanner_excludes_test_modules_but_rejects_production_helper_routes() {
        let mut scanner = SurfaceScan::default();
        scanner.visit_file(&syn::parse_file(r#"#[cfg(test)] mod tests { fn helper() { Router::new().route("/test", get(test)); } }"#).unwrap());
        assert!(scanner.errors.is_empty());
        scanner.visit_file(
            &syn::parse_file(r#"fn helper() { Router::new().route("/hidden", get(handler)); }"#)
                .unwrap(),
        );
        assert!(!scanner.errors.is_empty());
    }

    #[test]
    fn grpc_feature_requires_both_compiled_branches_and_disabled_return() {
        let source = r#"async fn encrypt(&self, request: Request) -> Result<Response, Status> {
            #[cfg(not(feature = "crypto-endpoints"))] { let _ = request; return Err(crypto_disabled("Encrypt")); }
            #[cfg(feature = "crypto-endpoints")] { do_encrypt(request).await }
        }"#;
        assert!(
            extract_grpc(&syn::parse_str(source).unwrap())
                .unwrap()
                .crypto_feature
        );
        let missing = source.replace("#[cfg(not(feature = \"crypto-endpoints\"))]", "");
        assert!(extract_grpc(&syn::parse_str(&missing).unwrap()).is_err());
        let wrong = source.replace(
            "return Err(crypto_disabled(\"Encrypt\"));",
            "let ignored = crypto_disabled(\"Encrypt\"); return Ok(());",
        );
        assert!(extract_grpc(&syn::parse_str(&wrong).unwrap()).is_err());
    }

    #[test]
    fn body_hash_ignores_comments_but_tracks_stub_behavior() {
        let a = syn::parse_str("async fn list(&self) { vec![] }").unwrap();
        let b = syn::parse_str("async fn list(&self) { /* same semantics */ vec![] }").unwrap();
        let c = syn::parse_str("async fn list(&self) { vec![new_namespace()] }").unwrap();
        assert_eq!(
            extract_grpc(&a).unwrap().body_sha256,
            extract_grpc(&b).unwrap().body_sha256
        );
        assert_ne!(
            extract_grpc(&a).unwrap().body_sha256,
            extract_grpc(&c).unwrap().body_sha256
        );
    }
    #[test]
    fn descriptor_binding_uses_actual_types_instead_of_method_spelling() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("crates/keyrack-service/src");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("grpc.rs"), "impl KeyService for KeyServiceImpl { async fn get(&self, request: Request<proto::SharedInput>) -> Result<Response<proto::SharedOutput>, Status> { todo!() } }").unwrap();
        verify_rpc_binding(temp.path(), "get", "SharedInput", "SharedOutput").unwrap();
        assert!(verify_rpc_binding(temp.path(), "get", "GetRequest", "SharedOutput").is_err());
        assert!(verify_rpc_binding(temp.path(), "get", "SharedInput", "GetResponse").is_err());
    }

    #[test]
    fn listener_connection_rejects_shadowed_router_and_changed_import() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../keyrack-service/src/main.rs");
        let original = std::fs::read_to_string(path).unwrap();
        verify_main(&syn::parse_file(&original).unwrap()).unwrap();
        let shadowed = original.replace(
            "axum::serve(rest_listener, rest_router)",
            "{ let rest_router = Router::new(); axum::serve(rest_listener, rest_router) }",
        );
        assert!(verify_main(&syn::parse_file(&shadowed).unwrap()).is_err());
        let conditional = original.replace(
            "let rest_handle =",
            "#[cfg(feature = \"hidden-rest\")] let rest_handle =",
        );
        assert!(verify_main(&syn::parse_file(&conditional).unwrap()).is_err());
        let conditional_body = original.replace(
            "axum::serve(rest_listener, rest_router)",
            "#[cfg(feature = \"hidden-rest\")] axum::serve(rest_listener, rest_router)",
        );
        assert!(verify_main(&syn::parse_file(&conditional_body).unwrap()).is_err());
        let mutable = original.replace("let rest_router =", "let mut rest_router =");
        assert!(verify_main(&syn::parse_file(&mutable).unwrap()).is_err());
        let wrong_import = original.replace(
            "use keyrack_service::grpc::KeyServiceImpl;",
            "use other_service::grpc::KeyServiceImpl;",
        );
        assert!(verify_main(&syn::parse_file(&wrong_import).unwrap()).is_err());
    }

    #[test]
    fn disabled_helper_must_return_the_documented_status() {
        let source = r#"#[cfg(not(feature = "crypto-endpoints"))] fn crypto_disabled(name: &str) -> Status { Status::unimplemented(name) }"#;
        verify_disabled_helper(&syn::parse_file(source).unwrap()).unwrap();
        let changed = source.replace("Status::unimplemented", "Status::permission_denied");
        assert!(verify_disabled_helper(&syn::parse_file(&changed).unwrap()).is_err());
    }
}
