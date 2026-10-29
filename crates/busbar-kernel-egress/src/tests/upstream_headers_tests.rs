// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The client headers that go upstream: `accept-encoding` is not one of them.

use crate::upstream::{re_derived, strip_re_derived};

/// 1.5.5 built every upstream request's headers itself and sent no `accept-encoding` (its HTTP
/// client had no content-coding feature, and no client header was copied across), so the far end
/// never compressed what busbar must read to meter. A client's `accept-encoding` is not forwarded,
/// in any spelling, and the headers around it are.
#[test]
fn a_clients_accept_encoding_never_goes_upstream() {
    assert!(re_derived("accept-encoding", std::iter::empty()));
    assert!(re_derived("Accept-Encoding", std::iter::empty()));
    assert!(!re_derived("x-trace", std::iter::empty()));

    let mut head = vec![
        (b"accept-encoding".to_vec(), b"gzip".to_vec()),
        (b"x-trace".to_vec(), b"t1".to_vec()),
    ];
    strip_re_derived(&mut head);
    assert_eq!(head, vec![(b"x-trace".to_vec(), b"t1".to_vec())]);
}
