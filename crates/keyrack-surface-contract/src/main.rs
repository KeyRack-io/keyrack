// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Explicit API availability contract, checked against protoc and the Rust AST.
#![forbid(unsafe_code)]

mod extract;

use extract::RestRoute;
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

type Check<T> = Result<T, String>;
const CONTRACT: &str = "conformance/api-surface/contract.json";
const MARKDOWN: &str = "docs/generated/api-surface-parity.md";
const JSON: &str = "docs/generated/api-surface-parity.json";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Contract {
    schema: u32,
    services: BTreeMap<String, Service>,
    operations: Vec<Operation>,
    rest_only: Vec<RestOnly>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Service {
    role: String,
    reason: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Operation {
    rpc: String,
    grpc_handler: String,
    rest: Option<RestRoute>,
    gap: Option<Gap>,
    stub_body_sha256: Option<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Gap {
    kind: String,
    reason: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestOnly {
    route: RestRoute,
    reason: String,
}
#[derive(Serialize)]
struct Row {
    rpc: String,
    grpc_handler: String,
    grpc_status: String,
    rest: Option<RestRoute>,
    gap: Option<Gap>,
    crypto_feature: bool,
}
#[derive(Serialize)]
struct Surface {
    schema: u32,
    scope: &'static str,
    source_sha256: BTreeMap<String, String>,
    operations: Vec<Row>,
    rest_only: Vec<RestOnlyOutput>,
    external_services: BTreeMap<String, ExternalService>,
}
#[derive(Serialize)]
struct RestOnlyOutput {
    route: RestRoute,
    reason: String,
}
#[derive(Serialize)]
struct ExternalService {
    reason: String,
    rpcs: Vec<String>,
}

fn read(path: &Path) -> Check<Vec<u8>> {
    std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))
}
fn files_under(path: &Path, extension: &str) -> Check<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(path).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_dir() {
            files.extend(files_under(&path, extension)?);
        } else if path.extension().is_some_and(|ext| ext == extension) {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}
#[derive(Serialize)]
struct Rpc {
    name: String,
    input: String,
    output: String,
}
fn proto_services(root: &Path) -> Check<BTreeMap<String, Vec<Rpc>>> {
    let temporary = tempfile::tempdir().map_err(|e| e.to_string())?;
    let output = temporary.path().join("surface.pb");
    let protos = files_under(&root.join("proto"), "proto")?;
    if protos.is_empty() {
        return Err("PROTO_ENUMERATION: no proto files".into());
    }
    let result = std::process::Command::new("protoc")
        .arg(format!("--proto_path={}", root.join("proto").display()))
        .arg(format!("--descriptor_set_out={}", output.display()))
        .args(protos)
        .output()
        .map_err(|e| format!("PROTO_ENUMERATION: protoc: {e}"))?;
    if !result.status.success() {
        return Err(format!(
            "PROTO_ENUMERATION: {}",
            String::from_utf8_lossy(&result.stderr)
        ));
    }
    let descriptor = prost_types::FileDescriptorSet::decode(read(&output)?.as_slice())
        .map_err(|e| format!("PROTO_ENUMERATION: {e}"))?;
    let mut services = BTreeMap::new();
    for file in descriptor.file {
        for service in file.service {
            let name = format!(
                "{}.{}",
                file.package.as_deref().unwrap_or_default(),
                service.name()
            );
            let methods = service
                .method
                .iter()
                .map(|m| Rpc {
                    name: m.name().to_owned(),
                    input: m.input_type().to_owned(),
                    output: m.output_type().to_owned(),
                })
                .collect();
            if services.insert(name, methods).is_some() {
                return Err("PROTO_ENUMERATION: duplicate service".into());
            }
        }
    }
    Ok(services)
}
fn nonempty(text: &str, diagnostic: &str) -> Check<()> {
    if text.trim().is_empty() {
        Err(diagnostic.into())
    } else {
        Ok(())
    }
}
fn set_equal(
    actual: &BTreeSet<String>,
    expected: &BTreeSet<String>,
    diagnostic: &str,
) -> Check<()> {
    if actual == expected {
        return Ok(());
    }
    Err(format!(
        "{diagnostic}: unlisted={:?}; stale={:?}",
        actual.difference(expected).collect::<Vec<_>>(),
        expected.difference(actual).collect::<Vec<_>>()
    ))
}
fn route_key(route: &RestRoute) -> String {
    format!("{} {}", route.method, route.path)
}

fn enumerate(root: &Path) -> Check<Surface> {
    let contract: Contract = serde_json::from_slice(&read(&root.join(CONTRACT))?)
        .map_err(|e| format!("CONTRACT_SCHEMA: {e}"))?;
    if contract.schema != 1 {
        return Err("CONTRACT_SCHEMA: unsupported version".into());
    }
    let services = proto_services(root)?;
    set_equal(
        &services.keys().cloned().collect(),
        &contract.services.keys().cloned().collect(),
        "SERVICE_COVERAGE",
    )?;
    let mut external_services = BTreeMap::new();
    for (name, service) in &contract.services {
        nonempty(&service.reason, "SERVICE_REASON: empty reason")?;
        match (name.as_str(), service.role.as_str()) {
            ("keyrack.v1.KeyService", "northbound") => {}
            ("keyrack.v1.KeyService", _) => {
                return Err("SERVICE_ROLE: mounted KeyService must be northbound".into())
            }
            (_, "external_dependency") => {
                external_services.insert(
                    name.clone(),
                    ExternalService {
                        reason: service.reason.clone(),
                        rpcs: services[name].iter().map(|rpc| rpc.name.clone()).collect(),
                    },
                );
            }
            _ => return Err(format!("SERVICE_ROLE: unrecognized mounted service {name}")),
        }
    }
    let declared: BTreeSet<_> = services
        .get("keyrack.v1.KeyService")
        .ok_or("SERVICE_ROLE: KeyService missing")?
        .iter()
        .map(|rpc| rpc.name.clone())
        .collect();
    let actual_routes = extract::rest_routes(root)?;
    let actual_methods = extract::grpc_methods(root)?;
    let methods: BTreeMap<_, _> = actual_methods.iter().map(|m| (m.name.clone(), m)).collect();
    if methods.len() != actual_methods.len() {
        return Err("GRPC_DUPLICATE: duplicate handler".into());
    }
    let mut rpc_names = BTreeSet::new();
    let mut handler_names = BTreeSet::new();
    let mut expected_routes = BTreeMap::new();
    let mut rows = Vec::new();
    for operation in contract.operations {
        if !rpc_names.insert(operation.rpc.clone()) {
            return Err("RPC_DUPLICATE: repeated RPC".into());
        }
        if !handler_names.insert(operation.grpc_handler.clone()) {
            return Err("GRPC_DUPLICATE: handler reused".into());
        }
        let method = methods.get(&operation.grpc_handler).ok_or_else(|| {
            format!(
                "GRPC_BINDING: {} has no handler {}",
                operation.rpc, operation.grpc_handler
            )
        })?;
        // Exact compiler-generated message types bind this explicit RPC mapping
        // to the real Rust impl, independently of any snake_case convention.
        let rpc = services["keyrack.v1.KeyService"]
            .iter()
            .find(|rpc| rpc.name == operation.rpc)
            .ok_or_else(|| format!("RPC_COVERAGE: stale RPC {}", operation.rpc))?;
        extract::verify_rpc_binding(
            root,
            &operation.grpc_handler,
            rpc.input.rsplit('.').next().ok_or("missing input")?,
            rpc.output.rsplit('.').next().ok_or("missing output")?,
        )?;
        match (&operation.rest, &operation.gap) {
            (Some(route), None) => {
                if route.feature.as_deref() != method.crypto_feature.then_some("crypto-endpoints") {
                    return Err(format!(
                        "FEATURE_BINDING: {} differs between interfaces",
                        operation.rpc
                    ));
                }
                if expected_routes
                    .insert(route_key(route), route.clone())
                    .is_some()
                {
                    return Err("REST_DUPLICATE: route mapped twice".into());
                }
            }
            (None, Some(gap)) => {
                nonempty(&gap.reason, "GAP_REASON: empty reason")?;
                if !["intentional", "existing_gap", "stub"].contains(&gap.kind.as_str()) {
                    return Err("GAP_KIND: unknown classification".into());
                }
            }
            _ => {
                return Err(format!(
                    "GAP_REQUIRED: {} needs exactly one REST mapping or explicit gap",
                    operation.rpc
                ))
            }
        }
        let stub = operation.gap.as_ref().is_some_and(|gap| gap.kind == "stub");
        match (&operation.stub_body_sha256, stub) {
            (Some(hash), true) if hash == &method.body_sha256 => {}
            (None, false) => {}
            _ => {
                return Err(format!(
                    "STUB_DRIFT: {} implementation changed; review its availability claim",
                    operation.rpc
                ))
            }
        }
        rows.push(Row {
            rpc: operation.rpc,
            grpc_handler: operation.grpc_handler,
            grpc_status: if stub { "stub" } else { "handler" }.into(),
            rest: operation.rest,
            gap: operation.gap,
            crypto_feature: method.crypto_feature,
        });
    }
    set_equal(&declared, &rpc_names, "RPC_COVERAGE")?;
    set_equal(
        &methods.keys().cloned().collect(),
        &handler_names,
        "GRPC_COVERAGE",
    )?;
    let mut rest_only = Vec::new();
    for entry in contract.rest_only {
        nonempty(&entry.reason, "REST_ONLY_REASON: empty reason")?;
        if expected_routes
            .insert(route_key(&entry.route), entry.route.clone())
            .is_some()
        {
            return Err("REST_DUPLICATE: operational route mapped twice".into());
        }
        rest_only.push(RestOnlyOutput {
            route: entry.route,
            reason: entry.reason,
        });
    }
    let mut routes = BTreeMap::new();
    for route in actual_routes {
        if routes.insert(route_key(&route), route).is_some() {
            return Err("REST_DUPLICATE: duplicate registration".into());
        }
    }
    set_equal(
        &routes.keys().cloned().collect(),
        &expected_routes.keys().cloned().collect(),
        "REST_COVERAGE",
    )?;
    for (key, expected) in expected_routes {
        if routes[&key] != expected {
            return Err(format!(
                "REST_BINDING: {key} handler or feature differs from contract"
            ));
        }
    }
    rows.sort_by(|a, b| a.rpc.cmp(&b.rpc));
    rest_only.sort_by_key(|entry| route_key(&entry.route));
    let mut source_sha256 = BTreeMap::new();
    let mut inputs = files_under(&root.join("proto"), "proto")?;
    inputs.extend(files_under(&root.join("crates/keyrack-service/src"), "rs")?);
    inputs.push(root.join(CONTRACT));
    for path in inputs {
        let name = path
            .strip_prefix(root)
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .replace('\\', "/");
        source_sha256.insert(name, format!("{:x}", Sha256::digest(read(&path)?)));
    }
    Ok(Surface {schema: 1, scope: "KeyService operation availability in the default build; request/response shapes and behavioral equivalence are separate contracts", source_sha256, operations: rows, rest_only, external_services})
}
fn cell(text: &str) -> String {
    text.replace('|', "\\|").replace(['\n', '\r'], " ")
}
fn markdown(surface: &Surface) -> String {
    use std::fmt::Write as _;
    let mut out = String::from("<!-- Generated by keyrack-surface-contract; do not edit. -->\n\n## REST / gRPC surface availability\n\nThis table enumerates KeyService RPCs and registered REST routes in the default\nbuild. It describes availability, not identical request fields or behavior.\nExisting cross-interface lifecycle tests check semantics separately.\n\n`crypto-endpoints` is enabled by default. Rows marked **crypto feature** lose\nthe REST route and return gRPC `UNIMPLEMENTED` when that feature is disabled.\nExport and import are not controlled by that feature.\n\n| RPC | gRPC | REST method and path | Scope / gap reason |\n| --- | --- | --- | --- |\n");
    for row in &surface.operations {
        let grpc = if row.grpc_status == "stub" {
            "Declared stub; see limitation"
        } else {
            "Handler available"
        };
        let rest = row
            .rest
            .as_ref()
            .map_or_else(|| "—".into(), |r| format!("`{} {}`", r.method, r.path));
        let mut note = if row.crypto_feature {
            "**crypto feature**. ".to_owned()
        } else {
            String::new()
        };
        if let Some(gap) = &row.gap {
            let kind = match gap.kind.as_str() {
                "intentional" => "Intentional gap",
                "stub" => "Unimplemented namespace registry",
                _ => "Existing REST gap",
            };
            let _ = write!(note, "{kind}: {}", cell(&gap.reason));
        }
        let _ = writeln!(out, "| `{}` | {grpc} | {rest} | {note} |", row.rpc);
    }
    out.push_str("\n### REST-only operational endpoints\n\n| REST method and path | Reason |\n| --- | --- |\n");
    for entry in &surface.rest_only {
        let _ = writeln!(
            out,
            "| `{} {}` | {} |",
            entry.route.method,
            entry.route.path,
            cell(&entry.reason)
        );
    }
    out.push_str("\n### External protocol contracts\n\n");
    for (name, service) in &surface.external_services {
        let _ = writeln!(
            out,
            "`{name}` (`{}`): {}\n",
            service.rpcs.join("`, `"),
            cell(&service.reason)
        );
    }
    out.push_str("REST authentication also depends on deployment configuration. With the\npeer-certificate-only mTLS authenticator, authenticated REST operations return\n`501 AuthenticationTransportUnsupported`; the table does not claim that a\nregistered route supplies that identity transport.\n");
    out
}
fn run() -> Check<()> {
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut mode = "--check".to_owned();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--root" => root = PathBuf::from(args.next().ok_or("--root requires a directory")?),
            "--check" | "--write" | "--inspect" => mode = arg,
            _ => return Err(format!("unexpected argument {arg}")),
        }
    }
    let root = root.canonicalize().map_err(|e| e.to_string())?;
    if mode == "--inspect" {
        println!("{}",serde_json::to_string_pretty(&serde_json::json!({"services":proto_services(&root)?,"rest":extract::rest_routes(&root)?,"grpc":extract::grpc_methods(&root)?})).map_err(|e|e.to_string())?);
        return Ok(());
    }
    let surface = enumerate(&root)?;
    let outputs = [
        (MARKDOWN, markdown(&surface)),
        (
            JSON,
            serde_json::to_string_pretty(&surface).map_err(|e| e.to_string())? + "\n",
        ),
    ];
    for (path, expected) in outputs {
        let path = root.join(path);
        if mode == "--write" {
            std::fs::create_dir_all(path.parent().ok_or("output needs parent")?)
                .map_err(|e| e.to_string())?;
            std::fs::write(&path, expected).map_err(|e| e.to_string())?;
        } else if read(&path)? != expected.as_bytes() {
            return Err(format!(
                "GENERATED_DRIFT: {}; run --write and review",
                path.display()
            ));
        }
    }
    println!("PASS surface contract: {} RPCs, {} mapped REST operations, {} explicit gaps, {} REST-only endpoints",surface.operations.len(),surface.operations.iter().filter(|x|x.rest.is_some()).count(),surface.operations.iter().filter(|x|x.gap.is_some()).count(),surface.rest_only.len());
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("FAIL {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grpc_rest_surface_parity_matches_allowlist() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let surface =
            enumerate(&root).expect("proto/Rust surface must match the explicit contract");
        assert_eq!(
            read(&root.join(MARKDOWN)).unwrap(),
            markdown(&surface).as_bytes(),
            "generated Markdown surface table drifted"
        );
        assert_eq!(
            read(&root.join(JSON)).unwrap(),
            (serde_json::to_string_pretty(&surface).unwrap() + "\n").as_bytes(),
            "generated JSON surface inventory drifted"
        );
    }
}
