// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The one upstream encoding choice.

use super::{apply_upstream_encoding, strip_re_derived, upstream_encoding, UpstreamEncoding};

/// Busbar asks a provider for identity, as 1.5.5 did: after the client's own field is stripped,
/// busbar's choice writes no `accept-encoding` back.
#[test]
fn busbar_asks_a_provider_for_identity_and_sends_no_accept_encoding() {
    assert_eq!(upstream_encoding(), UpstreamEncoding::Identity);
    assert_eq!(UpstreamEncoding::Identity.accept_encoding(), None);
    let mut head = vec![
        (b"accept-encoding".to_vec(), b"gzip, br".to_vec()),
        (b"x-trace".to_vec(), b"t1".to_vec()),
    ];
    strip_re_derived(&mut head);
    apply_upstream_encoding(&mut head);
    assert_eq!(head, vec![(b"x-trace".to_vec(), b"t1".to_vec())]);
}
