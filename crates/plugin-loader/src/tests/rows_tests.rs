// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `PluginRows::secret_slots` and `PluginRows::reference_slots` (security: they decide which settings
//! are treated as secret references and which may hold a reference at all): exactly the paths the signed
//! Statement of an ADMITTED dropped-in archive names; nothing for an archive whose Statement names none,
//! nothing for an archive the scan did not admit, nothing for a name no row answers to.

use std::path::{Path, PathBuf};

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, BLOB_OCTETS};
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::mechanism::extensions::{encode, EXT_REFERENCE_FIELDS};
use busbar_contract::abi::mechanism::rendering::render;
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::kinds::codes::KindCode;
use busbar_contract::plugin_rows::PluginRows;

use crate::sign::{Manifest, PublisherKey, PublisherTrust, SigningKey, TrustPolicy};
use crate::test_native::{test_key, TEST_PUBLISHER};

const SECRET_REFS: &[AbiStr] = &[abi_str("client_secret"), abi_str("hosts.*.password")];

/// The Statement rendering of a secret plugin `name` naming `secret_refs` and, when given, the
/// `reference_fields` extension (a JSON list of settings paths).
fn rendering(
    name: &'static str,
    secret_refs: &'static [AbiStr],
    reference_fields: Option<&[u8]>,
) -> Vec<u8> {
    let extensions = reference_fields.map(|fields| encode(&[(EXT_REFERENCE_FIELDS, fields)]));
    let mut st = Statement {
        kind: KindCode::Secret as u32,
        ..statement(name, "1.0.0", 1)
    };
    if !secret_refs.is_empty() {
        st.secret_refs = secret_refs.as_ptr();
        st.secret_refs_len = secret_refs.len();
    }
    if let Some(extensions) = &extensions {
        st.extensions = Blob {
            fmt: BLOB_OCTETS,
            flags: 0,
            len: extensions.len(),
            ptr: extensions.as_ptr(),
        };
    }
    // SAFETY: the secret_refs list is a `'static` array of its stated count and the extensions buffer
    // lives until `render` returns.
    unsafe { render(&st) }.expect("the Statement renders")
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "busbar-rows-{tag}-{}-{}",
        std::process::id(),
        crate::stage::next_seq()
    ));
    std::fs::create_dir_all(&dir).expect("create the scratch plugins directory");
    dir
}

/// Drop a signed archive `file` of the secret plugin `name` stating `stated` into `dir`.
fn drop_in(dir: &Path, key: &SigningKey, file: &str, name: &str, stated: Vec<u8>) {
    let lib = format!("{name}: library bytes this test never opens").into_bytes();
    let manifest = crate::sign::sign(
        key,
        Manifest {
            name: name.into(),
            alias: format!("{name}-alias"),
            kind: "secret".into(),
            version: "1.0.0".into(),
            publisher: TEST_PUBLISHER.into(),
            abi_version: crate::supported_abi("secret").expect("the engine loads secret plugins"),
            statement: Some(hex::encode(stated)),
            ..Manifest::default()
        },
        &lib,
    );
    let archive =
        crate::tarball::package(&manifest, "lib.so", &lib).expect("the archive packages");
    std::fs::write(dir.join(file), archive).expect("drop the archive in");
}

/// Trust [`TEST_PUBLISHER`]'s test key for exactly `names`.
fn trusting(names: &[&str]) -> TrustPolicy {
    let mut policy = TrustPolicy::default();
    policy.publishers.insert(
        TEST_PUBLISHER.to_string(),
        PublisherTrust {
            plugins: names.iter().map(|name| (*name).to_string()).collect(),
            keys: vec![PublisherKey {
                key: test_key().verifying_key(),
                revoked: false,
            }],
        },
    );
    policy
}

/// The admitted rows of `dir`, asserting which names were admitted and which skipped.
fn admitted(dir: &Path, admitted: &[&str], skipped: &[&str]) -> crate::PluginRegistry {
    let reg = crate::scan_and_validate(dir, &trusting(admitted))
        .expect("the plugins directory scans");
    for name in admitted {
        assert!(
            PluginRows::resolve(&reg, name).is_some(),
            "{name} is an admitted dropped-in row"
        );
    }
    for name in skipped {
        assert!(
            PluginRows::resolve(&reg, name).is_none()
                && PluginRows::unresolved_reason(&reg, name).is_some(),
            "{name} is skipped, not admitted"
        );
    }
    reg
}

#[test]
fn secret_slots_are_the_secret_refs_the_statement_names() {
    let dir = scratch("secret-slots");
    drop_in(
        &dir,
        &test_key(),
        "slotted.tar.gz",
        "slotted",
        rendering("slotted", SECRET_REFS, None),
    );
    drop_in(
        &dir,
        &test_key(),
        "unslotted.tar.gz",
        "unslotted",
        rendering("unslotted", &[], None),
    );
    drop_in(
        &dir,
        &SigningKey::from_bytes(&[0x36; 32]),
        "stranger.tar.gz",
        "stranger",
        rendering("stranger", SECRET_REFS, None),
    );
    let reg = admitted(&dir, &["slotted", "unslotted"], &["stranger"]);
    let rows: &dyn PluginRows = &reg;
    let stated = vec!["client_secret".to_string(), "hosts.*.password".to_string()];
    assert_eq!(rows.secret_slots("slotted"), stated, "exactly, in order");
    assert_eq!(
        rows.secret_slots("slotted-alias"),
        stated,
        "the row answers by its alias too"
    );
    assert!(
        rows.reference_slots("slotted").is_empty(),
        "a secret reference is not a reference field"
    );
    assert!(rows.secret_slots("unslotted").is_empty());
    assert!(
        rows.secret_slots("stranger").is_empty(),
        "an archive the scan did not admit states nothing"
    );
    assert!(rows.secret_slots("nope").is_empty());
    std::fs::remove_dir_all(dir).expect("remove the scratch directory");
}

#[test]
fn reference_slots_are_the_reference_fields_the_statement_names() {
    let dir = scratch("reference-slots");
    drop_in(
        &dir,
        &test_key(),
        "referencing.tar.gz",
        "referencing",
        rendering(
            "referencing",
            SECRET_REFS,
            Some(br#"["base_url","upstreams.*.host"]"#),
        ),
    );
    drop_in(
        &dir,
        &test_key(),
        "unslotted.tar.gz",
        "unslotted",
        rendering("unslotted", &[], None),
    );
    drop_in(
        &dir,
        &SigningKey::from_bytes(&[0x36; 32]),
        "stranger.tar.gz",
        "stranger",
        rendering("stranger", &[], Some(br#"["base_url"]"#)),
    );
    let reg = admitted(&dir, &["referencing", "unslotted"], &["stranger"]);
    let rows: &dyn PluginRows = &reg;
    let fields = vec!["base_url".to_string(), "upstreams.*.host".to_string()];
    assert_eq!(rows.reference_slots("referencing"), fields, "exactly, in order");
    assert_eq!(rows.reference_slots("referencing-alias"), fields);
    assert_eq!(
        rows.secret_slots("referencing"),
        vec!["client_secret".to_string(), "hosts.*.password".to_string()],
        "the secret slots stay the secret refs alone"
    );
    assert!(rows.reference_slots("unslotted").is_empty());
    assert!(
        rows.reference_slots("stranger").is_empty(),
        "an archive the scan did not admit states nothing"
    );
    assert!(rows.reference_slots("nope").is_empty());
    std::fs::remove_dir_all(dir).expect("remove the scratch directory");
}
