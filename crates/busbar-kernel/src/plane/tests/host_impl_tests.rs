// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-kernel/src/plane/host_impl.rs`.

use super::*;

/// THE REACHABILITY PIN for the invoke-family rewrite commit rule, stated at core's own function.
///
/// `apply_rewrite_to_invoke_args` is where a `prompt: rw` hook's reply becomes the `arguments` a
/// plane is handed back, and `transform_over_over` re-serialises that value with `serde_json::to_vec`.
/// Two facts about it decide whether a plane's apply site has a live hole or a dormant one, and both
/// are asserted here rather than read off the source by a plane's own test:
///
/// 1. It admits ANY JSON object as the replacement. It does not know, and cannot check, the TYPE the
///    receiving plane will decode into. For MCP and A2A the target is `serde_json::Value`, so bytes
///    core commits always parse and their "output I cannot read back" arms are unreachable through
///    this host. For `busbar-voice` the target is `SessionConfig`, which rejects `{"voice": 7}` as a
///    type mismatch — so THAT plane's arm is genuinely reachable through core's real host, and its
///    refusal (`busbar_voice::mount::committed_session_config`) is a live fix, not a dormant one.
/// 2. The commit is a WHOLESALE REPLACEMENT, not a merge. A hook that names one field produces
///    `arguments` carrying ONLY that field — every other key the caller (or the plane's own lock)
///    had is gone from the committed bytes. A plane whose target type defaults its absent fields
///    therefore silently blanks its own locked values unless it merges, which is the second half of
///    the voice rule.
#[test]
fn a_committed_invoke_rewrite_installs_any_json_object_verbatim() {
    // The arguments as the plane handed them to the seam: a locked field the hook never names, plus
    // the one it does. `persona` stands in for any string-typed field of a plane's typed config
    // (the doc above names the concrete one); core never learns which plane's type it is.
    let mut args = serde_json::json!({ "instructions": "locked by the plane", "persona": "alloy" });
    let rw = busbar_contract::hooks::RewriteReply {
        messages: vec![serde_json::json!({ "role": "user", "content": { "persona": 7 } })],
        tools: Vec::new(),
    };
    assert!(
        apply_rewrite_to_invoke_args(&mut args, &rw),
        "core COMMITS this rewrite (`applied: true`): the reply carries a JSON object, which is the \
         only thing this fn checks. It never consults the receiving plane's type."
    );
    assert_eq!(
        String::from_utf8(serde_json::to_vec(&args).expect("a Value always serializes"))
            .expect("json is utf-8"),
        r#"{"persona":7}"#,
        "these are the bytes `transform_over_over` hands back. (1) They are not a valid typed \
         config whose `persona` is a string — so a plane decoding into a typed \
         config CAN be handed a committed rewrite it cannot read. (2) `instructions` is GONE: the \
         commit replaced the arguments wholesale rather than patching the one named field."
    );
}
