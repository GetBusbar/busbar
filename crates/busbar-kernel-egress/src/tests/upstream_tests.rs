// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What of a client's head reaches a provider.

use crate::upstream::{collect_client_headers, strip_re_derived};
use busbar_contract::http;

/// A client's `accept-encoding` never goes upstream, as in 1.5.5 (which sent a provider no
/// `accept-encoding` at all): busbar reads the answer to meter it and decodes no content coding.
/// The fields around it still go.
#[test]
fn a_clients_accept_encoding_never_reaches_the_provider_as_in_1_5_5() {
    let mut head = http::HeaderMap::new();
    head.insert(
        http::header::ACCEPT_ENCODING,
        http::HeaderValue::from_static("gzip, br"),
    );
    head.insert(
        http::header::USER_AGENT,
        http::HeaderValue::from_static("sdk/1"),
    );
    let collected = collect_client_headers(&head, |_| false);
    assert!(
        collected
            .iter()
            .all(|(name, _)| name != http::header::ACCEPT_ENCODING),
        "a client's accept-encoding went upstream: {collected:?}"
    );
    assert!(
        collected
            .iter()
            .any(|(name, _)| name == http::header::USER_AGENT),
        "the client's other fields still go upstream: {collected:?}"
    );

    let mut fields = vec![
        (b"Accept-Encoding".to_vec(), b"gzip".to_vec()),
        (b"accept".to_vec(), b"*/*".to_vec()),
    ];
    strip_re_derived(&mut fields);
    assert_eq!(
        fields,
        vec![(b"accept".to_vec(), b"*/*".to_vec())],
        "a plane-handed head keeps no accept-encoding in any spelling"
    );
}
