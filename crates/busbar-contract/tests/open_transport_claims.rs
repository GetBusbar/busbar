// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Open-claim counterparts of the retired closed transport-axis enumeration tests.

use busbar_contract::abi::mechanism::extensions::encode;
use busbar_contract::abi::transport::listener_bindings::{
    read, resolve, ListenerBinding, EXT_LISTENER_BINDINGS,
};

#[test]
fn transport_identity_is_the_declared_key_without_a_central_name_table() {
    let bytes = encode(&[(
        EXT_LISTENER_BINDINGS,
        br#"[{"slot":"listen","claim":"foreign-wire-v7"}]"#,
    )]);
    let rows = read(&bytes, &["foreign-wire-v7"]).expect("a foreign claim is legal");
    assert_eq!(resolve("listen", rows.iter()).unwrap(), "foreign-wire-v7");
    assert!(
        read(&bytes, &["another-wire"]).is_err(),
        "an undeclared claim refuses"
    );
}

#[test]
fn selected_claim_has_one_supplier_without_enumerating_transport_variants() {
    let one = ListenerBinding {
        slot: "listen".into(),
        claim: "foreign-wire-v7".into(),
    };
    let two = ListenerBinding {
        slot: "listen".into(),
        claim: "other-wire-v9".into(),
    };
    assert!(resolve("listen", [&one, &two]).is_err());
    assert!(resolve("listen", [&one, &one]).is_err());
    assert!(resolve("unclaimed", [&one, &two]).is_err());
}
