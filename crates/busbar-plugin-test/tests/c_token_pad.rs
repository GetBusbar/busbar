// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-TOKEN-PAD (ABI-MIN3-INTERFACE §14 round 6): a session opener's answer begins with exactly one 16-byte TOKEN
//! record and the next record starts at offset 16. The codec arm is W1-A1's (merged; its crate test is
//! `busbar-plugin-abi` tests/records.rs); the opener arm needs the `kind!` shims and the host's answer parse.
//!
//! WBS rule 10: each ignored arm waits for the task that lands the last piece it needs; that task writes the
//! arm's body and un-ignores it in its own MR (red first, then green). Arms of tasks merged before W1-T1 run now.

use busbar_plugin_abi::records::{tag, Records, Reply, TokenRec, Writer};

#[test]
fn a_token_record_is_16_bytes_and_the_next_record_starts_at_16() {
    let mut reply = Reply::new();
    reply
        .put_pod(
            tag::TOKEN,
            &TokenRec {
                token: (1 << 32) | 1,
            },
        )
        .expect("token");
    reply.put_text(tag::TEXT, "after").expect("text");
    let bytes = reply.as_bytes();
    assert_eq!(bytes[16..18], tag::TEXT.to_ne_bytes());
    let tags: Vec<u16> = Records::new(bytes)
        .map(|rec| rec.expect("framing").tag)
        .collect();
    assert_eq!(tags, [tag::TOKEN, tag::TEXT]);
}

#[test]
#[ignore = "owner: W1-H1"]
fn plane_request_probe_and_transport_begin_answers_parse_with_no_unknown_tag_zero() {
    todo!("owner: W1-H1 (C-TOKEN-PAD)")
}
