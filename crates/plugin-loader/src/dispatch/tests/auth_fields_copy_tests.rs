// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SINGLE-PATH SP-R3: the outbound auth `FieldsRequest` is copied once per attempt, by the far end
//! that builds it. The loader lends the plugin the request it was handed, on the spot and on a
//! ticket, including the ticket's grown resubmit, and copies none of it.

use super::*;
use busbar_contract::stage_probe::{Derive, Scope};

#[test]
fn auth_fields_request_copied_once() {
    let a = opened();
    // Handle 1 answers within the first lend; handle 2 answers short and is asked again, grown.
    for (handle, answered) in [(1, 1), (2, 17)] {
        let wide = |f: Fields| match f {
            Fields::Ready(v) => v.len(),
            other => panic!("{other:?}"),
        };

        let scope = Scope::open();
        assert_eq!(a.fields_now(handle, &request()).map(wide), Some(answered));
        assert_eq!(
            scope.count(Derive::AuthFieldsCopy),
            0,
            "handle {handle}: on the spot the loader lends the caller's request, copying none"
        );
        drop(scope);

        let scope = Scope::open();
        assert_eq!(
            wide(futures_lite_block_on(a.fields(handle, request(), 0))),
            answered
        );
        assert_eq!(
            scope.count(Derive::AuthFieldsCopy),
            0,
            "handle {handle}: on a ticket (and its grown resubmit) the request moves in once"
        );
    }
}
