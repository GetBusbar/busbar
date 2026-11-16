// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SCRUB (ABI-MIN3-INTERFACE §14 rounds 4, 17, 18): a resolved secret, its encodings, URL userinfo and a
//! `?token=` parameter never survive. The scrub-set arm is W1-H0's (merged); the log, audit and `PortError` arm
//! and the template arm (K2 + H0) wait for their writers.
//!
//! WBS rule 10: each ignored arm waits for the task that lands the last piece it needs; that task writes the
//! arm's body and un-ignores it in its own MR (red first, then green). Arms of tasks merged before W1-T1 run now.

use busbar_plugin_abi::host_side::scrub::{needles, Scrub};

const SECRET: &[u8] = b"sk-live-4f9a2c7e1b8d";

#[test]
fn a_secret_its_encodings_userinfo_and_a_token_parameter_are_masked() {
    let scrub = Scrub::new();
    scrub.register(1, &[SECRET]);
    let forms = needles(SECRET);
    assert!(forms.len() > 1, "the raw value and its encodings");
    for form in &forms {
        let form = core::str::from_utf8(form).expect("every encoding is ASCII");
        let line = format!("upstream said {form} was rejected");
        let shown = scrub.text(&line);
        assert!(!shown.contains(form), "{form} survived: {shown}");
        assert!(shown.contains("***"), "{shown}");
    }
    let url = scrub.text("dial https://bob:hunter22@db.test/x?token=abc123&q=1");
    assert!(!url.contains("hunter22"), "{url}");
    assert!(!url.contains("abc123"), "{url}");
    assert!(url.contains("q=1"), "{url}");
}

#[test]
#[ignore = "owner: W1-K8D"]
fn none_survives_in_logs_audit_rows_or_port_error_text() {
    todo!("owner: W1-K8D (C-SCRUB)")
}

#[test]
#[ignore = "owner: W1-K2"]
fn template_fills_and_both_rotation_generations_are_masked_end_to_end() {
    todo!("owner: W1-K2 (C-SCRUB)")
}
