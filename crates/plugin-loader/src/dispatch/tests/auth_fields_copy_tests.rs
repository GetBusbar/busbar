// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SINGLE-PATH SP-R3: the outbound auth `FieldsRequest` is built once per attempt, by the far end.
//! On a ticket the loader moves the request it was handed into what it lends the plugin and
//! copies it only for a grown resubmit, while the first lend is still out. On the spot it is
//! borrowed, so the lend, which owns what it lends, copies it once.

use super::*;
use busbar_contract::stage_probe::{Derive, Scope};

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
