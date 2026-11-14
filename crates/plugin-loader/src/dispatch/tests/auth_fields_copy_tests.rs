// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SINGLE-PATH SP-R3: the outbound auth `FieldsRequest` is built once per attempt, by the far end.
//! On a ticket the loader moves the request it was handed into what it lends the plugin and
//! copies it only for a grown resubmit, while the first lend is still out. On the spot it is
//! borrowed, so the lend, which owns what it lends, copies it once.

use super::*;
use busbar_contract::stage_probe::{Derive, Scope};

/// The test door's handle whose `FIELDS` crossings record where the caller credential was lent.
/// It answers 17 fields, so its first lend is short and is asked again, grown.
pub(super) const LENT: u64 = 14;

static LENDS: std::sync::Mutex<Vec<usize>> = std::sync::Mutex::new(Vec::new());

/// The test door records one `LENT` crossing's caller-credential pointer.
pub(super) fn lent(at: *const u8) {
    LENDS.lock().unwrap().push(at.addr());
}

/// The pointers the `LENT` crossings were lent so far, in order, taken.
fn lends() -> Vec<usize> {
    std::mem::take(&mut *LENDS.lock().unwrap())
}

#[test]
fn auth_fields_request_copied_once() {
    let a = opened();
    // Handle 1 answers within the first lend; handle 2 answers short and is asked again, grown.
    for (handle, answered, regrown) in [(1, 1, 0), (2, 17, 1)] {
        let wide = |f: Fields| match f {
            Fields::Ready(v) => v.len(),
            other => panic!("{other:?}"),
        };

        let scope = Scope::open();
        assert_eq!(a.fields_now(handle, &request()).map(wide), Some(answered));
        assert_eq!(
            scope.count(Derive::AuthFieldsCopy),
            1,
            "handle {handle}: on the spot the borrowed request is copied once into the lend"
        );
        drop(scope);

        let scope = Scope::open();
        assert_eq!(
            wide(futures_lite_block_on(a.fields(handle, request(), 0))),
            answered
        );
        assert_eq!(
            scope.count(Derive::AuthFieldsCopy),
            regrown,
            "handle {handle}: on a ticket the request moves in; only a grown resubmit copies it"
        );
    }
}

/// SINGLE-PATH SP-AU6: the plugin is lent the request's own caller-credential buffer on every
/// path, never a copy of it: on the spot and on its recall, and on a ticket's first submit and on
/// its grown resubmit.
#[test]
fn caller_secret_lent_to_plugin_without_copy() {
    let a = opened();
    let seal = busbar_contract::plugin::TestKernelSeal;
    let passthrough = || {
        let mut r = request();
        r.caller_credential = Some(b"sk-caller-secret".to_vec().into());
        r
    };
    let held = |r: &FieldsRequest| {
        r.caller_credential
            .as_ref()
            .map(|c| c.expose(&seal).as_ptr().addr())
    };
    let wide = |f: Fields| match f {
        Fields::Ready(v) => v.len(),
        other => panic!("{other:?}"),
    };

    let spot = passthrough();
    assert_eq!(a.fields_now(LENT, &spot).map(wide), Some(17));
    let lent = lends();
    assert_eq!(lent.len(), 2, "on the spot: the first lend and its recall");
    assert_eq!(
        lent[1], lent[0],
        "on the spot the recall resizes the same lend, so it lends the same buffer"
    );
    assert_eq!(
        Some(lent[0]),
        held(&spot),
        "on the spot the plugin is lent the request's own credential buffer, not a copy"
    );

    let ticketed = passthrough();
    let at = held(&ticketed);
    assert_eq!(wide(futures_lite_block_on(a.fields(LENT, ticketed, 0))), 17);
    let lent = lends();
    assert_eq!(
        lent.len(),
        2,
        "on a ticket: the first submit and its grown resubmit"
    );
    assert_eq!(
        Some(lent[0]),
        at,
        "on a ticket the first submit moves the request in and lends its own buffer"
    );
    assert_eq!(
        Some(lent[1]),
        at,
        "on a ticket the grown resubmit lends the same buffer, not a copy"
    );
}
