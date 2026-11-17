// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DES-NATIVE-FIRST-PARTY r3 §2.7, §5 L5: an `allow_untrusted` native admission is audited, one
//! `plugin.admitted.untrusted` row naming the identity, the evaluator's words for the publisher, the setting and
//! the sha256. A trusted admission writes none.

use crate::root::loader::sign::TrustPolicy;

fn bomb() -> (Vec<u8>, crate::root::loader::sign::Manifest) {
    let path = crate::root::test_plugins::native_schema_bomb_path().unwrap_or_else(|| {
        crate::root::test_plugins::missing(
            "native_schema_bomb",
            crate::root::test_plugins::BUILD_LOADER_EXAMPLES,
        )
    });
    let lib = std::fs::read(&path).expect("the bomb image reads");
    let manifest = crate::root::test_plugins::native_manifest("store", &path, "unknown-publisher");
    (lib, manifest)
}

#[test]
fn an_allow_untrusted_native_admission_is_audited() {
    let (lib, manifest) = bomb();
    let admitted = busbar_plugin_loader::admit::admit_bytes(
        &lib,
        &manifest,
        &TrustPolicy {
            allow_untrusted: true,
            ..TrustPolicy::default()
        },
    )
    .expect("allow_untrusted admits the unsigned image");
    let identity = admitted.identity().to_owned();
    let rows = super::untrusted_rows(&[(admitted, "alias".to_owned())]);
    assert_eq!(rows.len(), 1, "one row per untrusted admission");
    let row = &rows[0];
    assert_eq!(row.action, "plugin.admitted.untrusted");
    assert_eq!(row.resource, format!("plugin:{identity}"));
    let sha = busbar_contract::crypto::sha256(&lib);
    for want in [
        "setting=allow_untrusted".to_owned(),
        format!("sha256={}", hex::encode(sha)),
    ] {
        assert!(row.message.contains(&want), "{want} in {}", row.message);
    }
    assert!(busbar_kernel::audit::auditlog::AUDIT_ACTIONS.contains(&"plugin.admitted.untrusted"));
}
