// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A REQUEST-STAGE HOOK'S REWRITE IS SPLICED OVER THE CALLER'S BYTES (DIALECT FIDELITY, owner
//! 2026-10-02; Q128 arch u59): the members it changed are written in place and every other member
//! keeps the caller's key order, spacing and number spelling. RED: the body re-serialized (keys
//! sorted, `1.50` read back as `1.5`, the caller's spacing gone).

use busbar_plane_llm::exchange::arrive::arrive;
use busbar_plane_llm::exchange::project::apply_rewrite;

#[test]
fn an_unchanged_members_bytes_survive_a_rewrite() {
    let head: &[(&[u8], &[u8])] = &[(b"content-type", b"application/json")];
    let body = br#"{"temperature": 1.50,  "model":"m0","messages":[{"role":"user","content":"long"}],"zeta":{"b":2,"a":1}}"#;
    let mut arrived = arrive("POST", "/v1/chat/completions", head, body, &()).expect("arrives");
    let rewrite = br#"{"messages":[{"role":"user","content":"short"}],"tools":[]}"#;
    let out = apply_rewrite(&mut arrived, rewrite).expect("the rewrite applies");
    let text = String::from_utf8(out.clone()).expect("UTF-8");
    assert!(
        text.starts_with(r#"{"temperature": 1.50,  "model":"m0","messages":"#),
        "the members before the rewritten one keep their bytes: {text}"
    );
    assert!(
        text.ends_with(r#","zeta":{"b":2,"a":1}}"#),
        "the members after it keep their order and bytes: {text}"
    );
    let v: serde_json::Value = serde_json::from_slice(&out).expect("JSON");
    assert_eq!(
        v["messages"],
        serde_json::json!([{"role":"user","content":"short"}]),
        "the rewritten member carries the rewrite: {text}"
    );
    assert_eq!(arrived.body, out, "the arrival holds the spliced bytes");
}
