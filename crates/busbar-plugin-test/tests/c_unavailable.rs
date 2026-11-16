// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-UNAVAILABLE (ABI-MIN3-INTERFACE §14): The facade's test-support stub backend: unsupported algs,
//! `EXTERNAL_PLUGINS`, stamp crypto; C-FIPS-GATE's admit arm (round 13). C-FIPS-GATE's facade build arm is
//! W0-H0B's contract test.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-A2"]
fn stub_backend_unsupported_algs_answer_unavailable() {
    todo!("owner: W1-A2 (C-UNAVAILABLE)")
}

/// W1-L1, C-FIPS-GATE's admit arm: admit's step 6 decides from the facade's two answers and nothing else. With a
/// deny-list stub backend stating `EXTERNAL_PLUGINS = false`, a `crypto = "external"` image is refused `Crypto`,
/// and a stamp naming a backend other than `BACKEND` is refused `Crypto`; on the linked facade, "external" admits
/// exactly when `busbar_crypto::EXTERNAL_PLUGINS` says so.
#[test]
fn admit_refuses_external_without_external_plugins_and_a_foreign_backend() {
    use busbar_plugin_loader::admit::{crypto_gate, CryptoFacts};
    use busbar_plugin_loader::refusal::RefusalCode;

    let stub = CryptoFacts {
        external_plugins: false,
        backend: "fips-stub",
        plugin_host: false,
    };
    let refused = crypto_gate("external", false, &stub).expect_err("EXTERNAL_PLUGINS = false");
    assert_eq!(
        (
            refused.code,
            refused.field,
            refused.have.as_str(),
            refused.want.as_str()
        ),
        (RefusalCode::Crypto, "crypto", "external", "fips-stub")
    );
    assert!(refused
        .named("busbar-secret-c")
        .to_string()
        .contains("is a non-Rust plugin (crypto: external)"));
    let with_host = CryptoFacts {
        plugin_host: true,
        ..stub
    };
    let foreign = crypto_gate("aws-lc", true, &with_host).expect_err("not BACKEND");
    assert_eq!(
        (foreign.code, foreign.have.as_str(), foreign.want.as_str()),
        (RefusalCode::Crypto, "aws-lc", "fips-stub")
    );
    assert!(crypto_gate("fips-stub", true, &with_host).is_ok());
    assert!(crypto_gate("host", false, &stub).is_ok());

    assert_eq!(
        (
            CryptoFacts::FACADE.external_plugins,
            CryptoFacts::FACADE.backend
        ),
        (
            busbar_contract::crypto::EXTERNAL_PLUGINS,
            busbar_contract::crypto::BACKEND
        )
    );
    assert_eq!(
        crypto_gate("external", false, &CryptoFacts::FACADE).is_ok(),
        busbar_contract::crypto::EXTERNAL_PLUGINS
    );
}
