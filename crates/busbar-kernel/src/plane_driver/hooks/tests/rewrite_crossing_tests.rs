// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A COMMITTED REWRITE CROSSES TO THE PLANE AS ONE, NEVER AS THE ABSENT BLOB, and an empty one is
//! applied as nothing, as 1.5.5 applied it. Hooks are frozen at 1.5.5's behaviour.
//!
//! 1.5.5 (tag `v1.5.5`) never committed an empty rewrite and never applied one:
//!
//! * `crates/busbar/src/hooks/wire.rs:496-510` (`parse_rewrite`): a reply whose `messages` is
//!   absent, not an array, or EMPTY is `None` — "proceed with the original body" — and
//!   `wire.rs:539-542` (`transform_outcome`) turns that `None` into `TransformOutcome::Abstain`;
//! * `crates/busbar/src/proxy/hooks.rs:56-63` (`apply_rewrite_to_body`): a rewrite with no
//!   messages returns `false` before it touches the body (the body is relayed untouched).
//!
//! The reply half is the contract's `hook_wire::reply::parse_rewrite`, pinned by
//! `policy`'s `wire_tests::transform_reply_reads_back_as_1_5_5_did`. This is the crossing half:
//! the kernel hands the plane a committed rewrite through `ProjectIn::rewrite`, and [`blob`] reads
//! EMPTY bytes as ABSENT ("no rewrite"). So a committed rewrite must never serialize to nothing:
//! if it did, the plane would proceed with the caller's original body while the hook stage
//! believed the rewrite applied — a fail-open. A rewrite constructed with no messages (a hook
//! implementation that skips the reply parser can return one) crosses as `{"messages": []}`, which
//! the plane applies as nothing: the body untouched, exactly 1.5.5's `false`.

use busbar_contract::abi::mechanism::call::BLOB_OCTETS;
use busbar_contract::hooks::RewriteReply;

use super::*;

#[test]
fn a_committed_rewrite_crosses_to_the_plane_as_one_and_never_as_absent() {
    let carried = RewriteReply {
        messages: vec![serde_json::json!({ "role": "user", "content": "[redacted]" })],
        tools: Vec::new(),
    };
    let empty = RewriteReply {
        messages: Vec::new(),
        tools: Vec::new(),
    };
    for (what, rw, expected) in [
        (
            "a rewrite carrying messages",
            &carried,
            serde_json::json!({
                "messages": [{ "role": "user", "content": "[redacted]" }],
                "tools": [],
            }),
        ),
        (
            "a rewrite naming no messages",
            &empty,
            serde_json::json!({ "messages": [], "tools": [] }),
        ),
    ] {
        let bytes = rewrite_bytes(rw);
        assert!(
            !bytes.is_empty(),
            "{what}: a committed rewrite that serialized to nothing would cross as ABSENT and the \
             plane would relay the caller's original body"
        );
        let crossed = blob(&bytes);
        assert!(
            !crossed.ptr.is_null() && crossed.len == bytes.len() && crossed.fmt == BLOB_OCTETS,
            "{what}: the plane is handed the rewrite, never the absent blob"
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).expect("JSON"),
            expected,
            "{what}: the plane reads the reply the hook committed, `messages` and all"
        );
    }
    // The control: empty bytes ARE the absent blob, which is why the crossing must never make them.
    assert!(blob(&[]).ptr.is_null(), "empty bytes cross as ABSENT");
}
