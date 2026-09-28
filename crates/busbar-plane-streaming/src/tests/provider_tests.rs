// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-plane-streaming/src/provider.rs`.

use super::*;

/// The redaction is narrow: a `key=` that is not a query parameter is ordinary text, and a message
/// with no credential in it survives byte-identical — an error line an operator reads is not worth
/// mangling to cover a secret that was never in it.
#[test]
fn redaction_leaves_a_message_that_carries_no_query_credential_alone() {
    let plain = "connecting to the pinned address failed: connection refused";
    assert_eq!(redact_url_credentials(plain), plain);
    let worded = "the monkey=business key=";
    assert_eq!(redact_url_credentials(worded), worded);
    assert_eq!(
        redact_url_credentials("wss://h/p?key=abc&alt=sse"),
        "wss://h/p?key=<redacted>&alt=sse"
    );
}
