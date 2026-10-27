// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE WEBHOOK-SIGNATURE AUTH PLUGIN IS LINKED**, default-on: its inbound
//! verify is an auth-chain module, so linking it lists it in `GET /api/v1/admin/info`
//! `build.auth_modules` after 1.5.5's two (accepted difference `#64-class build.auth_modules lists
//! the webhook-signature module`). Driven through the real binary's `--validate`.
//!
//! An `auth.chain` module that no installed or linked plugin answers is refused with "no plugin
//! matching" / "was not loaded" (`cli_validate`'s `validate_fails_on_unresolvable_auth_chain_plugin`).
//! With the row linked, the same chain naming the webhook-signature module resolves to the linked
//! door, so that refusal is gone. RED without the link: the refusal is exactly what prints. The case
//! rides every linked auth row (`linked_every_auth`, build.rs) rather than spelling one row's feature.
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
    let dir = fixture_dir();
    std::fs::write(dir.join("providers.yaml"), "").unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            "listen: \"127.0.0.1:0\"\nproviders: {{}}\nmodels: {{}}\nstore: {{module: memory}}\n\
             identity-providers:\n  twilio:\n    module: busbar-auth-webhook-signature\n    \
             settings: {{ variant: twilio, origin: \"wss://edge.example.com\" }}\n\
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
        .output()
        .expect("run busbar");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !text.contains("no plugin matching") && !text.contains("was not loaded"),
        "the linked webhook-signature row must answer the chain module: {text}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
