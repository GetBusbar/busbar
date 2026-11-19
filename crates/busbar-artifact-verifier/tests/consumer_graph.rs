// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Resolve an external consumer: workspace feature unification must not hide a loader/YAML edge.
use busbar_json::{self as json, JsonContainerTrait, JsonValueTrait};
use std::path::{Path, PathBuf};

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("remove this test's isolated resolver fixture");
    }
}

fn quoted(value: &str) -> String {
    json::to_string(value).unwrap()
}

#[test]
fn external_consumer_has_one_backend_and_no_loader_contract_or_yaml() {
    consumer_graph(false, false);
    consumer_graph(false, true);
}

#[test]
fn host_consumer_has_one_backend_without_tls_or_loader_contract_yaml() {
    consumer_graph(true, false);
    consumer_graph(true, true);
}

fn consumer_graph(host: bool, all_features: bool) {
    let owner = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = owner.parent().unwrap().parent().unwrap();
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "busbar-artifact-graph-{}-{unique}",
        std::process::id()
    )));
    std::fs::create_dir_all(scratch.0.join("src")).unwrap();
    std::fs::write(
        scratch.0.join("src/lib.rs"),
        "pub use busbar_artifact_verifier::verification::Verifier;\n",
    )
    .unwrap();
    let facade = std::fs::read_to_string(root.join("crates/busbar-crypto/Cargo.toml")).unwrap();
    let backend = facade
        .lines()
        .find(|line| line.starts_with("busbar-crypto-backend ="))
        .unwrap();
    let url = backend
        .split("git = \"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let workspace = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let patches = workspace
        .split("[patch.crates-io]")
        .nth(1)
        .unwrap()
        .lines()
        .filter(|line| line.starts_with("sonic-rs =") || line.starts_with("olpc-cjson ="))
        .collect::<Vec<_>>()
        .join("\n");
    // This fixture checks topology with the same selected backend source tree. The separate
    // backend_pin test and published-consumer lock prove the immutable source recipe.
    let host_dependency = if host {
        format!("busbar-plugin-abi = {{ path = {}, default-features = false, features = [\"host\"] }}\n",
            quoted(root.join("crates/busbar-plugin-abi").to_str().unwrap()))
    } else {
        String::new()
    };
    let manifest = format!(
        "[package]\nname = \"artifact-graph-witness\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[workspace]\n\n[dependencies]\nbusbar-artifact-verifier = {{ path = {}, default-features = false }}\n{host_dependency}\n[features]\nverifier-test-support = [\"busbar-artifact-verifier/test-support\"]\n\n[patch.{}]\nbusbar-crypto-backend = {{ path = {} }}\n\n[patch.crates-io]\n{patches}\n",
        quoted(owner.to_str().unwrap()), quoted(url), quoted(root.join("crates/busbar-crypto-backend").to_str().unwrap())
    );
    let manifest_path = scratch.0.join("Cargo.toml");
    std::fs::write(&manifest_path, manifest).unwrap();
    // The root's lock seeds the witness's resolve. Without one, cargo loads busbar-crypto-backend's
    // git source (core's URL at the pinned rev) before it applies the [patch] above, and offline that
    // revision is in no cargo home a fresh checkout has: the resolve failed before any topology was
    // judged. With the lock, the patched backend resolves to its path entry as it does in the root.
    // Locked versions are only a starting point: packages and features are resolved for this graph.
    std::fs::copy(root.join("Cargo.lock"), scratch.0.join("Cargo.lock"))
        .expect("seed the witness's resolve with the root's lock");
    let mut cargo = std::process::Command::new(env!("CARGO"));
    cargo
        .args([
            "metadata",
            "--offline",
            "--format-version",
            "1",
            "--manifest-path",
        ])
        .arg(&manifest_path);
    if all_features {
        cargo.arg("--all-features");
    }
    let output = cargo.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata = json::parse_value(&output.stdout).unwrap();
    let packages = metadata["packages"].as_array().unwrap();
    for forbidden in [
        "busbar-contract",
        "busbar-plugin-loader",
        "serde-saphyr",
        "saphyr",
        "unsafe-libyaml",
        "serde_yaml",
        "serde_yaml_ng",
        "serde_json",
    ] {
        assert!(
            !packages
                .iter()
                .any(|package| package["name"].as_str() == Some(forbidden)),
            "external verifier resolved {forbidden}"
        );
    }
    assert_eq!(
        packages
            .iter()
            .filter(|package| package["name"].as_str() == Some("busbar-crypto-backend"))
            .count(),
        1
    );
    for node in metadata["resolve"]["nodes"].as_array().unwrap() {
        let id = node["id"].as_str().unwrap();
        if id.contains("busbar-crypto") {
            assert!(
                !node["features"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|feature| matches!(feature.as_str(), Some("tls" | "test-support"))),
                "OEM consumer requested unsupported provider services: {id}"
            );
        }
        if id.contains("busbar-plugin-abi") || id.contains("busbar-ffi") {
            assert_eq!(
                node["features"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|feature| feature.as_str() == Some("host")),
                host,
                "consumer host feature selection differs: {id}"
            );
        }
    }
}
