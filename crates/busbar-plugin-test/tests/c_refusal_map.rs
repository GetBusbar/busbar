// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-REFUSAL-MAP (ABI-MIN3-INTERFACE §14): Auth kind codes, hook MESSAGE and auth Fail text never reach a plane
//! REFUSAL by default; no client refusal carries a `BUSBAR-[a-z]` plugin code (round 34).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use busbar_kernel::refusal::{ClientRefusal, CoreRefusals, RefusalMap};
use busbar_plugin_abi::fail::failed::{F_INTERNAL, F_TIMEOUT};
use busbar_plugin_abi::fail::refused::{
    R_AUTH_REQUIRED, R_BAD_CREDENTIAL, R_POLICY, R_RATE_LIMITED,
};
use busbar_plugin_abi::fail::CallError;
use busbar_plugin_abi::kinds::auth::auth::{BAD_CREDENTIAL, NOT_MINE};
use busbar_ports::PluginCode;
use busbar_ports::PortError;

const WORDS: &str = "backend-said: token=abc BUSBAR-acme-auth-0042";

fn acme() -> Option<PluginCode> {
    Some(PluginCode {
        plugin: "acme-auth",
        number: 42,
    })
}

fn clean(r: &ClientRefusal) {
    assert!(r.code < 0x100, "{r:?}");
    assert!(!r.text.contains("BUSBAR-"), "{r:?}");
    assert!(!r.text.contains("backend-said"), "{r:?}");
}

#[test]
fn plugin_texts_never_reach_a_plane_refusal() {
    let map = CoreRefusals::new();

    // Auth kind codes become generic codes with core's own text.
    for (kind, code) in [
        (NOT_MINE, R_AUTH_REQUIRED),
        (BAD_CREDENTIAL, R_BAD_CREDENTIAL),
    ] {
        let r = map.for_auth(1, kind);
        assert_eq!((r.code, r.status), (code, 401));
        clean(&r);
    }

    // A hook's MESSAGE stays out unless the operator exposes it, and then never with a plugin code in it.
    let hidden = map.for_hook(1, "gate", Some(451), Some("blocked: reason 7"));
    assert_eq!((hidden.code, hidden.status), (R_POLICY, 451));
    assert!(!hidden.text.contains("reason 7"));
    let mut exposing = CoreRefusals::new();
    exposing.expose_hook_message("gate");
    let coded = exposing.for_hook(1, "gate", None, Some("BUSBAR-acme-hook-0003: no"));
    clean(&coded);
    assert!(exposing
        .for_hook(1, "gate", None, Some("blocked: reason 7"))
        .text
        .ends_with("blocked: reason 7"));

    // Every port error, with the plugin's text and code on it, crosses as generic code and core's text.
    let failed = PortError::Failed {
        code: F_TIMEOUT,
        text: WORDS.into(),
        retry_after_s: Some(3),
        backend_status: Some(503),
        error: acme(),
    };
    let r = map.for_port(1, &failed);
    assert_eq!((r.code, r.status), (F_TIMEOUT, 504));
    clean(&r);
    let refused = PortError::Refused {
        code: 0x104,
        text: WORDS.into(),
        error: acme(),
    };
    let r = map.for_port(1, &refused);
    assert_eq!((r.code, r.status), (F_INTERNAL, 502));
    clean(&r);
    assert_eq!(
        map.for_port(1, &PortError::Call(CallError::Deadline)).code,
        F_TIMEOUT
    );

    // The operator's per-route text replaces core's text for that route and code only.
    let mut texts = CoreRefusals::new();
    texts.set_text(7, R_RATE_LIMITED, "slow down");
    assert_eq!(texts.for_core(7, R_RATE_LIMITED).text, "slow down");
    assert_ne!(texts.for_core(8, R_RATE_LIMITED).text, "slow down");
}
