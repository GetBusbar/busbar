// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A provider credential that resolves to an empty or whitespace-only value is REFUSED by the
//! real binary, from the linked env and file sources, in `busbar --validate` and at boot
//! (D-blank-secrets). The refusal names the config field and the secret module, never the value.

#![cfg(linked_section_pools)]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const BLANK: &str = "EMPTY or whitespace-only (BLANK)";

fn workdir(tag: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "busbar-blank-secret-{}-{tag}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(
        d.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n",
    )
    .unwrap();
    d
}

fn write_config(dir: &Path, api_key: &str) {
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            "listen: \"127.0.0.1:0\"\nadmin_listen: \"127.0.0.1:0\"\nstore: {{module: memory}}\n\
             providers:\n  mock:\n    api_key: {api_key}\nmodels:\n  test-model:\n    provider: mock\n"
        ),
    )
    .unwrap();
}

fn command(dir: &Path, mock_key: &str) -> Command {
    let mut c = Command::new(common::boot::exe());
    c.env("MOCK_KEY", mock_key)
        .env(
            "BUSBAR_SIGNING_KEY",
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env_remove("BUSBAR_PROVIDERS");
    c
}

fn validate(dir: &Path, mock_key: &str) -> (bool, String) {
    let out = command(dir, mock_key)
        .arg("--validate")
        .output()
        .expect("run busbar --validate");
    (
        out.status.success(),
        format!(
            "stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn assert_blank_refusal(output: &str, module: &str, value: &str) {
    assert!(output.contains("api_key"), "names the field: {output}");
    assert!(
        output.contains(&format!("secret module '{module}'")),
        "names the secret module: {output}"
    );
    assert!(
        output.contains(BLANK),
        "the kernel's blank refusal: {output}"
    );
    assert!(
        !output.contains("is unset") && !output.contains("after trimming"),
        "refused as blank, not by another check: {output}"
    );
    for echoed in [
        format!("{value:?}"),
        format!("'{value}'"),
        format!("`{value}`"),
    ] {
        assert!(!output.contains(&echoed), "no value echoed: {output}");
    }
}

#[test]
fn validate_refuses_a_whitespace_only_env_secret() {
    let dir = workdir("env");
    write_config(&dir, "{ env: MOCK_KEY }");
    let (ok, output) = validate(&dir, "   ");
    assert!(
        !ok,
        "a whitespace-only env secret must not validate: {output}"
    );
    assert_blank_refusal(&output, "busbar-secret-env", "   ");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn validate_refuses_a_blank_file_secret() {
    for (tag, content) in [("newline", "\n"), ("space-newline", " \n")] {
        let dir = workdir(tag);
        let key = dir.join("api.key");
        std::fs::write(&key, content).unwrap();
        write_config(&dir, &format!("{{ file: {} }}", key.display()));
        let (ok, output) = validate(&dir, "unused");
        assert!(
            !ok,
            "a blank file secret ({content:?}) must not validate: {output}"
        );
        assert_blank_refusal(&output, "busbar-secret-file", content);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn validate_accepts_a_secret_with_content() {
    let dir = workdir("control");
    write_config(&dir, "{ env: MOCK_KEY }");
    let (ok, output) = validate(&dir, "  k\n");
    assert!(ok, "a secret with content validates: {output}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn boot_refuses_a_whitespace_only_env_secret_before_binding() {
    let dir = workdir("boot");
    write_config(&dir, "{ env: MOCK_KEY }");
    let mut child = command(&dir, "   ")
        .stdout(Stdio::from(
            std::fs::File::create(dir.join("stdout.log")).unwrap(),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(dir.join("stderr.log")).unwrap(),
        ))
        .spawn()
        .expect("start busbar");
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll busbar") {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("busbar kept running with a whitespace-only provider secret");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let stderr = std::fs::read_to_string(dir.join("stderr.log")).unwrap();
    let stdout = std::fs::read_to_string(dir.join("stdout.log")).unwrap();
    let all = format!("{stdout}{stderr}");
    assert!(!status.success(), "boot must refuse: {all}");
    assert!(
        !common::boot::log_shows_data_and_admin_listening(&all),
        "nothing binds: {all}"
    );
    assert!(
        stderr.contains(
            "provider 'mock' api_key (secret module 'busbar-secret-env') did not resolve"
        ),
        "names the provider and the module: {stderr}"
    );
    assert!(
        stderr.contains(BLANK),
        "the kernel's blank refusal: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
