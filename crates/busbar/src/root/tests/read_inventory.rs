// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Actual read-owned archive admission, including a retained read after replacement/removal.

use super::*;
use busbar_kernel::config::{PluginPublisher, PluginPublisherKey, PluginsCfg, PluginsTrustCfg};
use busbar_plugin_loader::instance::{InstanceSpec, OpenPurpose, Registry};
use busbar_plugin_loader::test_host::{test_key, test_manifest, TEST_PUBLISHER};
use std::path::{Path, PathBuf};

const NAME: &str = "busbar-secret-c-fixture";

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn archive(dir: &Path, version: &str, error: u16) -> (Vec<u8>, [u8; 32]) {
    let source = include_str!("../../../../busbar-plugin-abi/tests/c_header/fixture.c")
        .replace(".version = \"1.6.0\"", &format!(".version = \"{version}\""))
        .replace("FIXTURE_ERROR 7071u", &format!("FIXTURE_ERROR {error}u"));
    let input = dir.join(format!("fixture-{version}.c"));
    let output = dir.join(format!("fixture-{version}.so"));
    std::fs::write(&input, source).unwrap();
    std::fs::write(
        dir.join("busbar_plugin.h"),
        include_str!("../../../../busbar-plugin-abi/include/busbar_plugin.h"),
    )
    .unwrap();
    let target = busbar_plugin_abi::stamp::target_now();
    let end = target.iter().position(|&b| b == 0).unwrap_or(target.len());
    let target = std::str::from_utf8(&target[..end]).unwrap();
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let compiled = std::process::Command::new(compiler)
        .args(["-std=c11", "-Wall", "-Werror", "-shared", "-fPIC", "-I"])
        .arg(dir)
        .arg(format!("-DBB_FIXTURE_TARGET=\"{target}\""))
        .arg(&input)
        .arg("-o")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let bytes = std::fs::read(output).unwrap();
    let digest = busbar_contract::crypto::sha256(&bytes);
    let manifest = test_manifest(&bytes, &["secret-c"]).unwrap();
    assert_eq!(manifest.version, version);
    (
        busbar_plugin_loader::tarball::package(&manifest, "fixture.so", &bytes).unwrap(),
        digest,
    )
}

fn plugins(dir: &Path) -> PluginsCfg {
    PluginsCfg {
        enabled: true,
        dir: dir.to_string_lossy().into_owned(),
        trust: PluginsTrustCfg {
            publishers: vec![PluginPublisher {
                name: TEST_PUBLISHER.into(),
                plugins: vec![NAME.into()],
                keys: vec![PluginPublisherKey {
                    public_key: hex::encode(test_key().verifying_key().as_bytes()),
                    revoked: false,
                }],
            }],
            allow_untrusted: false,
        },
        ..Default::default()
    }
}

fn read(process: &ProcessResources, plugins: &PluginsCfg) -> FileImages {
    prepare(
        process,
        &PhaseOneIn {
            plugins,
            dir: Path::new(&plugins.dir),
            pins: &BTreeMap::new(),
            fetch: busbar_kernel::config::grammar::Fetch::None,
        },
    )
    .unwrap_or_else(|error| panic!("the actual FileImages reader refused: {}", error.0))
}

fn assert_image(files: &FileImages, version: &str, digest: [u8; 32], error: u16) {
    assert_eq!(files.images.identity_of("secret-c").as_deref(), Some(NAME));
    assert_eq!(files.grammar.owners[NAME].version, version);
    assert_eq!(files.grammar.secret_sources["secret-c"].identity, NAME);
    assert_eq!(files.proofs[NAME].digest, Some(digest));
    let described = files.images.described(NAME).unwrap();
    assert_eq!(
        described
            .items
            .iter()
            .find(|(tag, _)| *tag == busbar_plugin_abi::records::tag::D_ERRORS)
            .unwrap()
            .1,
        error.to_le_bytes(),
    );
}

async fn check_retained(process: &ProcessResources, files: &FileImages) {
    let registry = Registry::new(
        files.images.clone(),
        Arc::new(busbar_kernel::plugin_config::Binder::new(
            Arc::default(),
            Vec::new(),
        )),
        Arc::clone(process.ids()),
    );
    registry
        .check(&InstanceSpec {
            store_migration: None,
            purpose: OpenPurpose::Canonical,
            identity: NAME,
            name: "read-owned-secret",
            config_json: b"{}",
            limits: Default::default(),
            public_url: None,
            caller_upstreams: &[],
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn actual_file_read_owns_replacement_directory_removal_and_disabled_inventory() {
    // Root sinks are process-owned. Isolate this real loader fixture rather than borrowing
    // whichever registry another parallel test happened to install.
    const CHILD: &str = "BUSBAR_READ_INVENTORY_CHILD";
    let test = format!(
        "{}::actual_file_read_owns_replacement_directory_removal_and_disabled_inventory",
        module_path!().split_once("::").unwrap().1
    );
    if std::env::var(CHILD).ok().as_deref() != Some(test.as_str()) {
        let output = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test, "--nocapture"])
            .env(CHILD, &test)
            .kill_on_drop(true)
            .output()
            .await
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("read inventory fixture ran"));
        return;
    }
    println!("read inventory fixture ran");
    let dir = Scratch(crate::root::test_plugins::scratch("native-read-inventory"));
    let first_dir = dir.0.join("first");
    let second_dir = dir.0.join("second");
    std::fs::create_dir_all(&first_dir).unwrap();
    std::fs::create_dir_all(&second_dir).unwrap();
    let (a, a_digest) = archive(&dir.0, "1.6.0", 7071);
    let (b, b_digest) = archive(&dir.0, "1.6.1", 7072);
    assert_ne!(a_digest, b_digest);
    let path = first_dir.join("fixture.tar.gz");
    std::fs::write(&path, &a).unwrap();
    std::fs::write(second_dir.join("fixture.tar.gz"), &a).unwrap();
    let process = ProcessResources::new().unwrap();
    let first = plugins(&first_dir);
    let held_a = read(&process, &first);
    assert_image(&held_a, "1.6.0", a_digest, 7071);

    std::fs::write(&path, &b).unwrap();
    let held_b = read(&process, &first);
    assert_image(&held_b, "1.6.1", b_digest, 7072);
    assert_image(&held_a, "1.6.0", a_digest, 7071);
    let other_directory = read(&process, &plugins(&second_dir));
    assert_image(&other_directory, "1.6.0", a_digest, 7071);

    std::fs::remove_file(&path).unwrap();
    let removed = read(&process, &first);
    assert!(removed.images.identity_of(NAME).is_none());
    assert!(!removed.grammar.owners.contains_key(NAME));
    assert!(!removed.grammar.secret_sources.contains_key("secret-c"));
    std::fs::write(&path, &b).unwrap();
    let mut disabled = first.clone();
    disabled.enabled = false;
    let disabled = read(&process, &disabled);
    assert!(disabled.images.identity_of(NAME).is_none());
    assert!(!disabled.grammar.owners.contains_key(NAME));
    assert!(!disabled.grammar.secret_sources.contains_key("secret-c"));

    // Retained image leases remain executable after replacement and removal from the read.
    check_retained(&process, &held_a).await;
    check_retained(&process, &held_b).await;
    assert_image(&held_a, "1.6.0", a_digest, 7071);
    assert_image(&held_b, "1.6.1", b_digest, 7072);
}
