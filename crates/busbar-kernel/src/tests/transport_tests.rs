// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::transport::listener_bindings::{resolve, ListenerBinding};

#[test]
fn names_are_stable_and_distinct() {
    let rows = [
        ListenerBinding {
            slot: "listen".into(),
            claim: "foreign-wire-v7".into(),
        },
        ListenerBinding {
            slot: "other".into(),
            claim: "another-wire-v9".into(),
        },
    ];
    assert_eq!(resolve("listen", &rows).unwrap(), "foreign-wire-v7");
    assert_eq!(resolve("other", &rows).unwrap(), "another-wire-v9");
    assert!(resolve("unknown", &rows).is_err());
    assert!(resolve("listen", [&rows[0], &rows[0]]).is_err());
    let ambiguous = ListenerBinding {
        slot: "listen".into(),
        claim: "another-wire-v9".into(),
    };
    assert!(resolve("listen", [&rows[0], &ambiguous]).is_err());
}
