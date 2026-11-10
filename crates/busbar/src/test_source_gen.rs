// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Test-source ownership is package metadata, never a production library API.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use serde_json::Value;

pub struct Owners(BTreeMap<String, Value>);

impl Owners {
    pub fn load(manifest: &str) -> Self {
        let names: BTreeSet<_> = [
            "root-test-sources",
            "test-common-sources",
            "test-source-contexts",
        ]
        .into_iter()
        .flat_map(|table| {
            crate::metadata_map(manifest, &format!("package.metadata.busbar.{table}"))
                .into_iter()
                .map(|(_, owner)| owner)
        })
        .collect();
        if names.is_empty() {
            return Self(BTreeMap::new());
        }

        // Dev-dependencies do not provide DEP_* metadata to a build script.
        // Ask Cargo for the resolved source locations instead of guessing its
        // checkout layout or exporting host test sources from plugin libraries.
        let manifest_path =
            PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("Cargo.toml");
        let mut command = std::process::Command::new(std::env::var_os("CARGO").unwrap());
        command.args([
            "metadata",
            "--format-version=1",
            "--locked",
            "--all-features",
            "--manifest-path",
        ]);
        command.arg(&manifest_path);
        // The roster includes sources from optional owners even when their runtime
        // features are disabled. Resolve their locations without compiling them.
        command
            .arg("--filter-platform")
            .arg(std::env::var("TARGET").unwrap());
        let output = command.output().expect("resolve test-source owners");
        assert!(
            output.status.success(),
            "resolve test-source owners with the locked Cargo graph: {}\n\
             Source discovery must share the build's Cargo configuration; \
             place overrides in Cargo config or CARGO_* environment variables.",
            String::from_utf8_lossy(&output.stderr)
        );
        let metadata: Value = serde_json::from_slice(&output.stdout).expect("Cargo metadata JSON");
        println!(
            "cargo:rerun-if-changed={}",
            Path::new(metadata["workspace_root"].as_str().unwrap())
                .join("Cargo.lock")
                .display()
        );
        let packages = metadata["packages"].as_array().expect("Cargo packages");
        let root = packages
            .iter()
            .find(|p| Path::new(p["manifest_path"].as_str().unwrap()) == manifest_path)
            .expect("assembly package in Cargo metadata");
        let node = metadata["resolve"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["id"] == root["id"])
            .expect("assembly resolution node");
        let direct = node["dependencies"].as_array().unwrap();
        let mut owners = BTreeMap::new();
        for name in names {
            let candidates: Vec<_> = packages
                .iter()
                .filter(|p| p["name"] == name && direct.contains(&p["id"]))
                .collect();
            assert_eq!(
                candidates.len(),
                1,
                "test-source owner {name} must resolve to one direct dependency"
            );
            let package = candidates[0];
            println!(
                "cargo:rerun-if-changed={}",
                package["manifest_path"].as_str().unwrap()
            );
            owners.insert(name, package.clone());
        }
        Self(owners)
    }

    pub fn module(&self, owner: &str, source: &str, module: &str) -> String {
        identifier(module);
        let package = &self.0[owner];
        let path = package["metadata"]["busbar"]["test-sources"][source]
            .as_str()
            .unwrap_or_else(|| panic!("{owner} does not declare test source {source}"));
        format!(
            "#[path = {:?}]\npub(crate) mod {module};\n",
            source_path(package, path)
        )
    }

    pub fn context(&self, owner: &str, context: &str) -> String {
        let package = &self.0[owner];
        let rows = package["metadata"]["busbar"]["test-contexts"][context]
            .as_array()
            .unwrap_or_else(|| panic!("{owner} does not declare test context {context}"));
        assert!(!rows.is_empty(), "{owner}: empty test context {context}");
        rows.iter()
            .map(|row| {
                let path = source_path(package, row["path"].as_str().expect("test context path"));
                match row.get("module") {
                    Some(module) => {
                        let module = module.as_str().expect("test context module");
                        identifier(module);
                        format!("#[path = {path:?}] mod {module};\n")
                    }
                    None => format!("include!({path:?});\n"),
                }
            })
            .collect()
    }
}

fn source_path(package: &Value, relative: &str) -> PathBuf {
    let relative = Path::new(relative);
    assert!(
        relative.starts_with("tests")
            && relative
                .extension()
                .is_some_and(|extension| extension == "rs")
            && relative
                .components()
                .all(|c| matches!(c, Component::Normal(_))),
        "test source must be an owner-relative Rust file under tests/: {relative:?}"
    );
    let root = Path::new(package["manifest_path"].as_str().unwrap())
        .parent()
        .unwrap()
        .canonicalize()
        .expect("test-source owner directory");
    let path = root
        .join(relative)
        .canonicalize()
        .expect("owner test source exists");
    assert!(
        path.starts_with(root.join("tests")),
        "test source escapes its owner's tests directory: {path:?}"
    );
    println!("cargo:rerun-if-changed={}", path.display());
    path
}

pub fn identifier(value: &str) {
    assert!(
        !value.is_empty()
            && value.bytes().enumerate().all(|(i, b)| b == b'_'
                || b.is_ascii_alphabetic()
                || (i > 0 && b.is_ascii_digit())),
        "invalid test source identifier: {value}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture(PathBuf);

    impl Fixture {
        fn new(label: &str) -> Self {
            let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
                .join(format!("owner-test-sources-{}-{label}", std::process::id()));
            std::fs::create_dir_all(path.join("tests")).unwrap();
            std::fs::write(path.join("tests/fixture.rs"), "fn fixture() {}\n").unwrap();
            Self(path)
        }

        fn package(&self) -> Value {
            serde_json::json!({
                "manifest_path": self.0.join("Cargo.toml"),
                "metadata": {"busbar": {
                    "test-sources": {"root": "tests/fixture.rs", "common": "tests/fixture.rs"},
                    "test-contexts": {"host": [
                        {"path": "tests/fixture.rs"},
                        {"path": "tests/fixture.rs", "module": "fixture"}
                    ]}
                }}
            })
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn metadata_mounts_owner_modules_and_inline_contexts_without_exports() {
        let fixture = Fixture::new("mount");
        let owners = Owners(BTreeMap::from([(
            "fixture-owner".into(),
            fixture.package(),
        )]));
        let path = fixture.0.join("tests/fixture.rs").canonicalize().unwrap();
        assert_eq!(
            owners.module("fixture-owner", "root", "root_fixture"),
            format!("#[path = {path:?}]\npub(crate) mod root_fixture;\n")
        );
        assert_eq!(
            owners.module("fixture-owner", "common", "common_fixture"),
            format!("#[path = {path:?}]\npub(crate) mod common_fixture;\n")
        );
        assert_eq!(
            owners.context("fixture-owner", "host"),
            format!("include!({path:?});\n#[path = {path:?}] mod fixture;\n")
        );
    }

    #[test]
    fn paths_cannot_escape_owner_tests() {
        let fixture = Fixture::new("paths");
        for invalid in [
            "../elsewhere.rs",
            "tests/../fixture.rs",
            "src/lib.rs",
            "/tests/fixture.rs",
        ] {
            assert!(
                std::panic::catch_unwind(|| source_path(&fixture.package(), invalid)).is_err(),
                "{invalid}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_cannot_escape_owner_tests() {
        let fixture = Fixture::new("symlinks");
        std::fs::write(fixture.0.join("outside.rs"), "fn outside() {}\n").unwrap();
        std::os::unix::fs::symlink("../outside.rs", fixture.0.join("tests/escape.rs")).unwrap();
        assert!(
            std::panic::catch_unwind(|| source_path(&fixture.package(), "tests/escape.rs"))
                .is_err()
        );
    }

    #[test]
    fn a_neutral_build_needs_no_source_owners() {
        assert!(Owners::load("[package]\nname = \"neutral\"\n").0.is_empty());
    }
}
