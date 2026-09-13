// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Static deployment constraints, checked against the shipped profile. The
//! Docker proof separately exercises runtime persistence and the writer lock.
use serde::Deserialize;
use serde_yaml::Value;

fn source(name: &str) -> String {
    if let Some(root) = std::env::var_os("KEYRACK_SOFTHSM_PROFILE_FIXTURE") {
        return std::fs::read_to_string(std::path::PathBuf::from(root).join(name)).unwrap();
    }
    match name {
        "deployment.yaml" => include_str!("../../../deploy/softhsm/deployment.yaml").into(),
        "keyrack.yaml" => include_str!("../../../deploy/softhsm/keyrack.yaml").into(),
        _ => unreachable!(),
    }
}

fn objects() -> Vec<Value> {
    serde_yaml::Deserializer::from_str(&source("deployment.yaml"))
        .map(|document| Value::deserialize(document).unwrap())
        .collect()
}

#[test]
fn persistent_token_has_one_replica_recreate_and_rwo() {
    let objects = objects();
    let deployment = objects.iter().find(|v| v["kind"] == "Deployment").unwrap();
    assert_eq!(
        deployment["spec"]["replicas"].as_u64(),
        Some(1),
        "token requires one replica"
    );
    assert_eq!(
        deployment["spec"]["strategy"]["type"], "Recreate",
        "token requires Recreate"
    );
    let pvc = objects
        .iter()
        .find(|v| v["kind"] == "PersistentVolumeClaim")
        .unwrap();
    let access = pvc["spec"]["accessModes"].as_sequence().unwrap();
    assert_eq!(
        access,
        &[Value::String("ReadWriteOnce".into())],
        "token requires RWO"
    );
    let pod = &deployment["spec"]["template"]["spec"];
    let data = pod["volumes"]
        .as_sequence()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "data")
        .unwrap();
    assert_eq!(
        data["persistentVolumeClaim"]["claimName"], pvc["metadata"]["name"],
        "token data must use the claimed PVC"
    );
    for kind in ["initContainers", "containers"] {
        let containers = pod[kind].as_sequence().unwrap();
        assert_eq!(
            containers.len(),
            1,
            "one initializer and one service container required"
        );
        let mounts = containers[0]["volumeMounts"].as_sequence().unwrap();
        let data = mounts.iter().find(|v| v["name"] == "data").unwrap();
        assert_eq!(
            data["mountPath"], "/var/lib/keyrack",
            "initializer and service must share the persistent data directory"
        );
    }
}

#[test]
fn initializer_and_service_are_nonroot_and_use_secret_files() {
    let objects = objects();
    let deployment = objects.iter().find(|v| v["kind"] == "Deployment").unwrap();
    let pod = &deployment["spec"]["template"]["spec"];
    assert_eq!(
        pod["securityContext"]["runAsNonRoot"], true,
        "pod must require nonroot"
    );
    assert_eq!(
        pod["securityContext"]["runAsUser"].as_u64(),
        Some(10001),
        "pod must use nonroot UID"
    );
    assert_eq!(
        pod["securityContext"]["runAsGroup"].as_u64(),
        Some(10001),
        "pod must use nonroot GID"
    );
    assert_eq!(
        pod["securityContext"]["fsGroup"].as_u64(),
        Some(10001),
        "PVC must use service file group"
    );
    for (kind, expected_args, secret_volume) in [
        ("initContainers", "init", "init-secrets"),
        ("containers", "serve", "service-secrets"),
    ] {
        let container = &pod[kind][0];
        for field in ["runAsUser", "runAsGroup"] {
            assert!(
                container["securityContext"][field].is_null()
                    || container["securityContext"][field].as_u64() == Some(10001),
                "container must not override nonroot identity"
            );
        }
        assert!(
            container["securityContext"]["runAsNonRoot"].is_null()
                || container["securityContext"]["runAsNonRoot"] == true,
            "container must not override nonroot requirement"
        );
        assert_eq!(
            container["securityContext"]["allowPrivilegeEscalation"], false,
            "privilege escalation must be disabled"
        );
        assert_eq!(
            container["securityContext"]["readOnlyRootFilesystem"], true,
            "image root filesystem must be read only"
        );
        assert_eq!(
            container["securityContext"]["capabilities"]["drop"],
            serde_yaml::to_value(["ALL"]).unwrap(),
            "all capabilities must be dropped"
        );
        assert!(
            container["command"].is_null(),
            "do not bypass the locked image entrypoint"
        );
        assert_eq!(
            container["args"],
            serde_yaml::to_value([expected_args]).unwrap(),
            "entrypoint mode must be exact"
        );
        assert!(
            container["env"].is_null() && container["envFrom"].is_null(),
            "secrets must enter only through files"
        );
        let mounts = container["volumeMounts"].as_sequence().unwrap();
        let secrets = mounts
            .iter()
            .find(|v| v["mountPath"] == "/run/secrets/keyrack");
        assert!(
            secrets.is_some(),
            "secret files must use the expected mount path"
        );
        let secrets = secrets.unwrap();
        assert_eq!(
            secrets["name"], secret_volume,
            "service must mount only its restricted secret projection"
        );
        assert_eq!(secrets["readOnly"], true, "secret files must be read only");
        for mount in mounts {
            let allowed = if kind == "initContainers" {
                ["data", "init-secrets", "tmp", "init-secrets"]
            } else {
                ["data", "service-secrets", "tmp", "config"]
            };
            assert!(
                allowed.contains(&mount["name"].as_str().unwrap()),
                "container must not mount extra secret sources"
            );
        }
    }
    let volumes = pod["volumes"].as_sequence().unwrap();
    for (name, keys) in [
        ("init-secrets", vec!["token-label", "user-pin", "so-pin"]),
        ("service-secrets", vec!["token-label", "user-pin"]),
    ] {
        let volume = volumes.iter().find(|v| v["name"] == name).unwrap();
        assert_eq!(
            volume["secret"]["secretName"], "keyrack-softhsm-secrets",
            "credentials must come from the declared Secret"
        );
        assert_eq!(
            volume["secret"]["defaultMode"].as_u64(),
            Some(0o440),
            "secret files must use restricted permissions"
        );
        let actual: Vec<_> = volume["secret"]["items"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|v| (v["key"].as_str().unwrap(), v["path"].as_str().unwrap()))
            .collect();
        let expected: Vec<_> = keys.iter().map(|key| (*key, *key)).collect();
        assert_eq!(
            actual, expected,
            "secret key and path projection must exclude SO PIN from service"
        );
    }
}

#[test]
fn readiness_uses_live_endpoint_with_sufficient_timeout() {
    let objects = objects();
    let deployment = objects.iter().find(|v| v["kind"] == "Deployment").unwrap();
    let probe = &deployment["spec"]["template"]["spec"]["containers"][0]["readinessProbe"];
    assert_eq!(
        probe["httpGet"]["path"], "/readyz",
        "readiness must use live readyz endpoint"
    );
    assert_eq!(
        probe["httpGet"]["port"], "rest",
        "readiness must probe the REST listener"
    );
    assert!(
        probe["timeoutSeconds"].as_u64().unwrap() >= 3,
        "readiness timeout must exceed provider probe budget"
    );
    assert_eq!(
        probe["failureThreshold"].as_u64(),
        Some(1),
        "readiness must withdraw on first failure"
    );
}

#[test]
fn shipped_config_has_persistent_pkcs11_and_no_inline_credentials() {
    let source = source("keyrack.yaml");
    let config: Value = serde_yaml::from_str(&source).unwrap();
    assert_eq!(
        config["storage"]["type"], "sqlite",
        "profile metadata must persist in SQLite"
    );
    assert_eq!(
        config["storage"]["path"], "/var/lib/keyrack/metadata/keyrack.db",
        "metadata must use the persistent directory"
    );
    assert_eq!(
        config["provider"]["type"], "pkcs11",
        "profile must use PKCS11 custody"
    );
    assert_eq!(
        config["provider"]["lib_path"], "/usr/lib/softhsm/libsofthsm2.so",
        "profile must use the stable module path"
    );
    assert_eq!(
        config["provider"]["pin_ref"], "file:user-pin",
        "user PIN must be a file reference"
    );
    assert_eq!(
        config["provider"]["token_label_ref"], "file:token-label",
        "token label must be a file reference"
    );
    assert!(
        config["provider"]["pin"].is_null() && config["provider"]["token_label"].is_null(),
        "inline token credentials are forbidden"
    );
    assert_eq!(
        config["pdp"]["type"], "always_deny",
        "shipped profile must deny until authorization is configured"
    );
    let config = keyrack_service::config::ServiceConfig::from_yaml(&source).unwrap();
    config.validate().unwrap();
}
