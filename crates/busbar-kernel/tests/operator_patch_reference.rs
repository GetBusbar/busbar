// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OPERATOR-FROM-ADMITTED-AUTH r3.1 R24 (§000.1): the operator credential's reference is config.yaml
//! exactly as read from disk, before any stored `document_patch` is composed. The loader returns that
//! unpatched reference beside the patched document, so a patch can never become "the file", and a
//! disk rebuild takes that reference. A stored patch from an earlier binary that moves the
//! operator credential, or the plugin admission set, refuses boot naming its paths and both
//! remedies. The words are process-global: this test owns its binary.

use std::path::{Path, PathBuf};

use busbar_contract::auth_calls::OperatorClaim;
use busbar_kernel::appbuild::{
    load_config_from_disk_with_document_patches, AcceptAll, LoadedConfig,
};
use busbar_kernel::config::document_patch::DocumentPatch;
use busbar_kernel::config::operator_file::stored_document_patch;
use busbar_kernel::config::{EnvSubst, OperatorFileDefs};
use busbar_kernel_identity::operator::{install_operator, Judged, OperatorBinding};

const OP: &str = "dropped-op";
const DIGEST: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
const OTHER: &str = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752";

fn bind_operator() {
    install_operator(OperatorBinding::Bound(Judged {
        words: Ok(Some(OperatorClaim {
            provider: OP.to_owned(),
            canonical: "busbar-auth-dropped-op".to_owned(),
            principal: "admin".to_owned(),
            first_party: true,
            version: "1.6.0".to_owned(),
            signer: "busbar".to_owned(),
        })),
        inert: Vec::new(),
    }));
}

fn file() -> String {
    format!(
        "identity-providers:\n  {OP}:\n    module: {OP}\n    settings: {{ sha256: \"{DIGEST}\" }}\n"
    )
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "busbar-operator-patch-reference-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let config = dir.join("config.yaml");
    std::fs::write(&config, file()).expect("config.yaml");
    dir
}

fn patch(set: &str, value: &str) -> DocumentPatch {
    let mut edits = serde_json::Map::new();
    edits.insert(set.to_owned(), serde_json::Value::String(value.to_owned()));
    let mut body = serde_json::Map::new();
    body.insert("set".to_owned(), serde_json::Value::Object(edits));
    DocumentPatch::from_value(serde_json::Value::Object(body)).expect("a well-formed patch")
}

fn load(dir: &Path, stored: &DocumentPatch) -> LoadedConfig {
    load_config_from_disk_with_document_patches(
        &dir.join("config.yaml"),
        None,
        false,
        EnvSubst::Strict,
        &AcceptAll,
        Some(stored),
        None,
    )
    .expect("the file and its stored patch load")
}

#[test]
fn the_patch_loader_returns_the_unpatched_operator_reference() {
    bind_operator();
    let dir = scratch("reference");
    let stored = patch(&format!("/identity-providers/{OP}/settings/sha256"), OTHER);
    let loaded = load(&dir, &stored);
    let _ = std::fs::remove_dir_all(&dir);

    let file_reference = OperatorFileDefs::of(
        &busbar_kernel::config::deploy_from_yaml_str(
            &file(),
            &busbar_kernel::config::Grammar::empty(),
        )
        .expect("config.yaml parses")
        .identity_providers,
    );
    assert!(
        file_reference.get(OP).is_some(),
        "config.yaml's operator definition is the reference's"
    );
    assert_ne!(
        OperatorFileDefs::of(&loaded.deploy.identity_providers),
        file_reference,
        "the patched document carries the patch"
    );
    assert_eq!(
        loaded.operator_reference, file_reference,
        "the reference is config.yaml as read from disk, before the patch"
    );
}

#[test]
fn a_stored_patch_that_moves_the_operator_credential_refuses_boot_by_path() {
    bind_operator();
    let dir = scratch("refusal");
    let path = format!("/identity-providers/{OP}/settings/sha256");
    let stored = patch(&path, OTHER);
    let loaded = load(&dir, &stored);
    let refusal = stored_document_patch(&stored, &loaded)
        .expect_err("a stored patch re-keying the operator credential refuses boot");
    for needle in [
        format!("identity-providers.{OP}"),
        path,
        "reset_document_paths".to_owned(),
        "--ignore-overlay".to_owned(),
    ] {
        assert!(refusal.contains(&needle), "names {needle}: {refusal}");
    }

    let stored = patch("/plugins/dir", "/srv/elsewhere");
    let loaded = load(&dir, &stored);
    let refusal = stored_document_patch(&stored, &loaded)
        .expect_err("a stored patch moving the plugin admission set refuses boot");
    assert!(
        refusal.contains("/plugins/dir") && refusal.contains("reset_document_paths"),
        "{refusal}"
    );

    let stored = patch("/plugins/logs/level", "debug");
    let loaded = load(&dir, &stored);
    assert!(
        stored_document_patch(&stored, &loaded).is_ok(),
        "plugins.logs has no admission effect"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn reference_of(yaml: &str) -> OperatorFileDefs {
    OperatorFileDefs::of(
        &busbar_kernel::config::deploy_from_yaml_str(
            yaml,
            &busbar_kernel::config::Grammar::empty(),
        )
        .expect("config.yaml parses")
        .identity_providers,
    )
}

/// §3.6.1: a disk rebuild (`POST /config/reload`, `POST /plugins/reload`, `POST /plugins/rollback`)
/// re-reads config.yaml, so its candidate carries config.yaml's operator definitions as the
/// reference every later apply and validate is held to. Editing `settings` in config.yaml and
/// reloading is the 1.6.0 rotation path: the edited file becomes the reference.
#[test]
fn a_disk_rebuild_takes_config_yaml_as_its_operator_reference() {
    bind_operator();
    let dir = scratch("rebuild");
    let config = dir.join("config.yaml");
    let reload = || {
        load_config_from_disk_with_document_patches(
            &config,
            None,
            false,
            EnvSubst::Strict,
            &AcceptAll,
            None,
            None,
        )
        .expect("config.yaml loads")
        .disk_candidate()
        .expect("the candidate resolves")
        .operator_file_defs
    };

    assert_eq!(
        reload().as_deref(),
        Some(&reference_of(&file())),
        "the rebuild's reference is config.yaml's operator definition"
    );

    let rotated = file().replace(DIGEST, OTHER);
    std::fs::write(&config, &rotated).expect("config.yaml");
    assert_eq!(
        reload().as_deref(),
        Some(&reference_of(&rotated)),
        "the edited config.yaml is the new reference"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
