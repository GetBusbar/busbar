// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn constructor_output(command: &mut std::process::Command) -> std::process::Output {
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let timed_out = loop {
        if child.try_wait().unwrap().is_some() {
            break false;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            break true;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let output = child.wait_with_output().unwrap();
    assert!(
        !timed_out,
        "constructor child exceeded its refusal bound: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    output
}

#[test]
fn early_plane_archive_pins_refuse_before_native_constructors() {
    const CHILD: &str = "BUSBAR_EARLY_PLANE_ARCHIVE_CHILD";
    if std::env::var_os(CHILD).is_some() {
        super::tests::constructor_child(false);
    }
    let dir = std::env::temp_dir().join(format!(
        "busbar-plane-bootstrap-{}-{}",
        std::process::id(),
        hex::encode(busbar_kernel::door::op_id().0),
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("constructor.c");
    let image = dir.join("constructor.so");
    std::fs::write(
        &source,
        r#"#include <stdio.h>
#include <stdlib.h>
__attribute__((constructor)) static void mark_loaded(void) {
    const char *path = getenv("BUSBAR_PLANE_CTOR_MARKER");
    if (path) { FILE *out = fopen(path, "wb"); if (out) { fputs("loaded", out); fclose(out); } }
}
"#,
    )
    .unwrap();
    let mut compiler = std::process::Command::new("cc");
    #[cfg(target_os = "macos")]
    compiler.arg("-dynamiclib");
    #[cfg(not(target_os = "macos"))]
    compiler.args(["-shared", "-fPIC"]);
    let compiled = compiler.arg(source).arg("-o").arg(&image).output().unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let library = std::fs::read(image).unwrap();
    let stated = crate::root::loader::dispatch::rendering_of(crate::LINKED.plane_doors[0]).unwrap();
    let head = busbar_contract::abi::mechanism::rendering::RENDERING_MAGIC.len() + 16;
    let len = |at: usize| u32::from_le_bytes(stated[at..at + 4].try_into().unwrap()) as usize;
    let version_at = head + 4 + len(head);
    let name = "constructor-plane-bootstrap";
    let version = "1.0.0";
    let mut rendering = stated[..head].to_vec();
    rendering.extend_from_slice(&(name.len() as u32).to_le_bytes());
    rendering.extend_from_slice(name.as_bytes());
    rendering.extend_from_slice(&(version.len() as u32).to_le_bytes());
    rendering.extend_from_slice(version.as_bytes());
    rendering.extend_from_slice(&stated[version_at + 4 + len(version_at)..]);
    let key = crate::root::loader::sign::SigningKey::from_bytes(&[0x37; 32]);
    let manifest = crate::root::loader::sign::sign(
        &key,
        crate::root::loader::sign::Manifest {
            name: name.into(),
            alias: "constructor-plane".into(),
            kind: "plane".into(),
            version: version.into(),
            publisher: "busbar".into(),
            abi_version: crate::root::loader::supported_abi("plane")[0],
            statement: Some(hex::encode(rendering)),
            ..Default::default()
        },
        &library,
    );
    let archive = crate::root::loader::tarball::package(&manifest, "lib.so", &library).unwrap();
    let hash = crate::root::loader::sign::sha256_hex(&archive);
    let plugins = dir.join("plugins");
    std::fs::create_dir_all(&plugins).unwrap();
    std::fs::write(plugins.join("plane.tar.gz"), archive).unwrap();
    let config = dir.join("config.yaml");
    let providers = dir.join("providers.yaml");
    std::fs::write(&providers, "{}\n").unwrap();
    for (tag, pin, constructor) in [
        ("missing", None, false),
        ("wrong", Some("00".repeat(32)), false),
        ("matching", Some(hash.clone()), true),
    ] {
        let fetch: Vec<_> = pin
            .into_iter()
            .map(|pin| {
                serde_json::json!({
                    "url":"http://127.0.0.1:9/plane.tar.gz", "sha256":pin,
                })
            })
            .collect();
        let document = serde_json::json!({
            "providers":{}, "models":{}, "store":{"module":"memory","settings":{}},
            "listen":"127.0.0.1:0", "admin_listen":"127.0.0.1:0",
            "advanced":{"worker_threads":1},
            "plugins":{"enabled":true,"dir":plugins,"fetch":fetch}
        });
        std::fs::write(&config, serde_yaml::to_string(&document).unwrap()).unwrap();
        let marker = dir.join(format!("{tag}.marker"));
        let output = constructor_output(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "root::boot::bootstrap_pin_tests::early_plane_archive_pins_refuse_before_native_constructors", "--nocapture"])
            .current_dir(&dir).env(CHILD, "1").env("BUSBAR_PLANE_CTOR_MARKER", &marker)
            .env("BUSBAR_TEST_HARNESS_FIRST_PARTY_KEY", hex::encode(key.verifying_key().to_bytes()))
            .env("BUSBAR_CONFIG", &config).env("BUSBAR_PROVIDERS", &providers)
            .env("BUSBAR_DATA_DIR", dir.join("state")));
        let logs = String::from_utf8_lossy(&output.stdout).into_owned()
            + &String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "the fixture exports no door: {logs}"
        );
        assert_eq!(marker.exists(), constructor, "{tag}: {logs}");
        if !constructor {
            assert!(logs.contains("exact archive SHA-256"), "{tag}: {logs}");
        }
        assert!(!dir.join("state/plugin-highwater.json").exists());
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn offline_secret_checker_archive_pins_refuse_before_native_constructors() {
    const CHILD: &str = "BUSBAR_OFFLINE_SECRET_ARCHIVE_CHILD";
    if std::env::var_os(CHILD).is_some() {
        super::tests::constructor_child(true);
    }
    let dir = std::env::temp_dir().join(format!(
        "busbar-secret-bootstrap-{}-{}",
        std::process::id(),
        hex::encode(busbar_kernel::door::op_id().0)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("constructor.c");
    let image = dir.join("constructor.so");
    std::fs::write(
        &source,
        r#"#include <stdio.h>
#include <stdlib.h>
__attribute__((constructor)) static void mark_loaded(void) {
    const char *path = getenv("BUSBAR_SECRET_CTOR_MARKER");
    if (path) { FILE *out = fopen(path, "wb"); if (out) { fputs("loaded", out); fclose(out); } }
}
"#,
    )
    .unwrap();
    let mut compiler = std::process::Command::new("cc");
    #[cfg(target_os = "macos")]
    compiler.arg("-dynamiclib");
    #[cfg(not(target_os = "macos"))]
    compiler.args(["-shared", "-fPIC"]);
    let compiled = compiler.arg(source).arg("-o").arg(&image).output().unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let library = std::fs::read(image).unwrap();
    let stated = crate::root::loader::dispatch::rendering_of(
        busbar_test_kit::root_door_fixtures::migrate_stub::door,
    )
    .unwrap();
    let key = crate::root::loader::sign::SigningKey::from_bytes(&[0x39; 32]);
    let manifest = crate::root::loader::sign::sign(
        &key,
        crate::root::loader::sign::Manifest {
            name: "busbar-secret-stub".into(),
            alias: "constructor-secret".into(),
            kind: "secret".into(),
            version: "1.6.0".into(),
            publisher: "busbar".into(),
            abi_version: crate::root::loader::supported_abi("secret")[0],
            statement: Some(hex::encode(stated)),
            ..Default::default()
        },
        &library,
    );
    let archive = crate::root::loader::tarball::package(&manifest, "lib.so", &library).unwrap();
    let hash = crate::root::loader::sign::sha256_hex(&archive);
    let plugins = dir.join("plugins");
    std::fs::create_dir_all(&plugins).unwrap();
    std::fs::write(plugins.join("secret.tar.gz"), archive).unwrap();
    let config = dir.join("config.yaml");
    let providers = dir.join("providers.yaml");
    std::fs::write(&providers, "{}\n").unwrap();
    for (tag, pin, constructor) in [
        ("missing", None, false),
        ("wrong", Some("00".repeat(32)), false),
        ("matching", Some(hash.clone()), true),
    ] {
        let fetch: Vec<_> = pin
            .into_iter()
            .map(|pin| serde_json::json!({"url":"http://127.0.0.1:9/secret.tar.gz","sha256":pin}))
            .collect();
        let secret = serde_json::json!({"module":"constructor-secret","settings":{}});
        let document = serde_json::json!({
            "providers":{},"models":{},"store":{"module":"memory","settings":{}},
            "listen":"127.0.0.1:0", "admin_listen":"127.0.0.1:0",
            "advanced":{"worker_threads":1},"tls":{"cert":secret,"key":secret},
            "plugins":{"enabled":true,"dir":plugins,"fetch":fetch}
        });
        std::fs::write(&config, serde_yaml::to_string(&document).unwrap()).unwrap();
        let marker = dir.join(format!("{tag}.marker"));
        let output = constructor_output(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact","root::boot::bootstrap_pin_tests::offline_secret_checker_archive_pins_refuse_before_native_constructors","--nocapture"])
            .current_dir(&dir).env(CHILD,"1").env("BUSBAR_SECRET_CTOR_MARKER",&marker)
            .env("BUSBAR_TEST_HARNESS_FIRST_PARTY_KEY",hex::encode(key.verifying_key().to_bytes()))
            .env("BUSBAR_CONFIG",&config).env("BUSBAR_PROVIDERS",&providers)
            .env("BUSBAR_DATA_DIR",dir.join("state")));
        let logs = String::from_utf8_lossy(&output.stdout).into_owned()
            + &String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "the fixture exports no door: {logs}"
        );
        assert_eq!(marker.exists(), constructor, "{tag}: {logs}");
        if !constructor {
            assert!(logs.contains("exact archive SHA-256"), "{tag}: {logs}");
        }
        assert!(!dir.join("state/plugin-highwater.json").exists());
    }
    std::fs::remove_dir_all(dir).unwrap();
}
