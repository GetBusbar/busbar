// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The query-parameter auth fields: the framer's append and every shown target's redaction.

use super::{append_query, redact_query, REDACTED_VALUE};

#[test]
fn query_fields_append_to_the_target_and_redact_out_of_it() {
    assert_eq!(append_query("/v1/models", &[]), "/v1/models");
    assert_eq!(
        append_query("/v1/models", &[("key", "k1")]),
        "/v1/models?key=k1"
    );
    assert_eq!(
        append_query("/v1/x?alt=sse", &[("key", "a b&c")]),
        "/v1/x?alt=sse&key=a%20b%26c"
    );
    assert_eq!(append_query("/v1/x?", &[("key", "k")]), "/v1/x?key=k");
    assert_eq!(
        append_query("https://h.example/p#frag", &[("key", "k"), ("v", "2")]),
        "https://h.example/p?key=k&v=2#frag"
    );
    let sent = append_query("/v1/x?alt=sse", &[("key", "s3cr3t")]);
    let shown = redact_query(&sent, &["key"]);
    assert_eq!(shown, format!("/v1/x?alt=sse&key={REDACTED_VALUE}"));
    assert!(!shown.contains("s3cr3t"));
    assert_eq!(redact_query("/v1/x", &["key"]), "/v1/x");
    assert_eq!(redact_query("/v1/x?keys=1", &["key"]), "/v1/x?keys=1");
}
