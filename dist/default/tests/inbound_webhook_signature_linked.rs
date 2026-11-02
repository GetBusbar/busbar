// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(linked_every_auth)]

use std::path::PathBuf;
use std::process::Command;

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-webhook-signature-linked-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(d.join("plugins")).unwrap();
    d
}

#[test]
fn a_chain_naming_the_webhook_signature_plugin_resolves_to_the_linked_row() {
    const SECRET_ENV: &str = "BUSBAR_TEST_WEBHOOK_SIGNING_SECRET";
    let dir = fixture_dir();
    std::fs::write(dir.join("providers.yaml"), "").unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            "listen: \"127.0.0.1:0\"\nproviders: {{}}\nmodels: {{}}\nstore: {{module: memory}}\n\
             identity-providers:\n  twilio:\n    module: busbar-auth-webhook-signature\n    \
             settings: {{ variant: twilio, origin: \"wss://edge.example.com\", signing_secret: {{ env: {SECRET_ENV} }} }}\n\
             auth:\n  chain: [twilio]\n\
             plugins:\n  enabled: true\n  dir: '{}'\n  trust:\n    allow_unsigned: true\n",
            dir.join("plugins").display()
        ),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .arg("--validate")
        .env(
            "BUSBAR_SIGNING_KEY",
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env(SECRET_ENV, "test-webhook-linked-signing-secret")
        .output()
        .expect("run busbar");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success() && text.contains("ok: config valid"),
        "the linked webhook-signature row must validate this configured chain ({:?}): {text}",
        out.status
    );
    assert!(
        !text.contains("no plugin matching") && !text.contains("was not loaded"),
        "the linked webhook-signature row must answer the chain module: {text}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
