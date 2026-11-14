// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SINGLE-PATH SP-P9: a hook's wire rewrite reply is moved out of its parsed value, never
//! deep-cloned from it. Counted by the dev-only stage probes (`busbar_contract::stage_probe`).

use busbar_contract::abi::hook::VERB_REWRITE;
use busbar_contract::hooks::TransformOutcome;
use busbar_contract::stage_probe::{Derive, Scope};

#[test]
fn a_wire_rewrite_reply_is_moved_out_of_its_parsed_value() {
    let scope = Scope::open();
    let outcome = super::policy::transformed(VERB_REWRITE, 0, String::new, || {
        br#"{"messages":[{"role":"user","content":"COMPRESSED"}],"tools":[{"name":"t"}]}"#.to_vec()
    });
    let TransformOutcome::Rewrite(rw) = outcome else {
        panic!("a well-formed rewrite reply is a rewrite");
    };
    assert_eq!(
        rw.messages,
        vec![serde_json::json!({"role": "user", "content": "COMPRESSED"})]
    );
    assert_eq!(rw.tools, vec![serde_json::json!({"name": "t"})]);
    assert_eq!(
        scope.count(Derive::ProjectCopy),
        0,
        "the reply's messages and tools are moved, not copied"
    );
}

#[test]
fn a_malformed_wire_rewrite_reply_still_abstains() {
    for reply in [
        br#"{}"#.as_slice(),
        br#"{"messages":[]}"#,
        br#"{"messages":"hi"}"#,
        br#"{"messages":[{}],"tools":"x"}"#,
        br#""hi""#,
        b"not json",
    ] {
        assert!(
            matches!(
                super::policy::transformed(VERB_REWRITE, 0, String::new, || reply.to_vec()),
                TransformOutcome::Abstain
            ),
            "{}",
            String::from_utf8_lossy(reply)
        );
    }
}
