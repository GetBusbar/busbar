// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SINGLE-PATH SP-R3: each upstream attempt builds its auth `FieldsRequest` once, at the far end;
//! the outbound auth borrows it on the spot or takes it whole on a ticket (the loader's half is
//! `plugin-loader`'s `auth_fields_request_copied_once`).

use super::*;
use busbar_contract::stage_probe::{Derive, Scope};

#[tokio::test]
async fn auth_fields_request_copied_once_per_attempt() {
    let r = rig(
        &[
            ("a.test", Script::Answer(503, None, vec![b"x"])),
            ("b.test", Script::Answer(200, None, vec![b"ok"])),
        ],
        OnExhausted::Status503,
        None,
    );
    let t = token();
    let far = r.egress.unit(route());
    for n in 1..=2 {
        let scope = Scope::open();
        let _ = far.member(&t, n).await;
        assert!(far.send(&t, request()).await);
        let _ = drain(&far, &t).await;
        assert_eq!(
            scope.count(Derive::AuthFieldsCopy),
            1,
            "attempt {n}: the auth fields request is built once"
        );
    }
    assert_eq!(
        r.auth.calls.load(Ordering::SeqCst),
        2,
        "one auth call per attempt"
    );
}
