// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SCRUB-CUT (ABI-MIN3-INTERFACE §14 round 15): scrub first, cut after. A secret at bytes 500..540, its
//! encodings there, and one straddling the 3,072-byte wire cut leave no 4-byte run in the shown text; shown text
//! is at most 512 bytes. The `fail_text` arm is W1-H0's (merged); each adapter's `PortError`/log/audit arm is its
//! owner's (L3-L9), and the `bb_fail` arm is the C header's.
//!
//! WBS rule 10: each ignored arm waits for the task that lands the last piece it needs; that task writes the
//! arm's body and un-ignores it in its own MR (red first, then green). Arms of tasks merged before W1-T1 run now.

use busbar_plugin_abi::fail::FAIL_TEXT_WIRE_MAX;
use busbar_plugin_abi::host_side::scrub::{fail_text, needles, Scrub, FAIL_TEXT_SHOWN};

const SECRET: &str = "cut-secret-0123456789ABCDEFGHIJKLMNOPQRS";

/// Any 4-byte run of `form` in `shown`.
fn leaks(shown: &str, form: &[u8]) -> bool {
    form.windows(4)
        .any(|run| shown.as_bytes().windows(4).any(|have| have == run))
}

#[test]
fn a_secret_or_encoding_at_byte_500_is_masked_before_the_cut() {
    assert_eq!(SECRET.len(), 40);
    let scrub = Scrub::new();
    scrub.register(1, &[SECRET.as_bytes()]);
    for form in &needles(SECRET.as_bytes()) {
        let form = core::str::from_utf8(form).expect("ASCII");
        let text = format!("{}{form}{}", "a".repeat(500), "b".repeat(60));
        let shown = fail_text(&scrub, &text);
        assert!(shown.len() <= FAIL_TEXT_SHOWN);
        assert!(!leaks(&shown, form.as_bytes()), "{form}");
    }
}

#[test]
fn a_secret_split_by_the_wire_cut_is_masked_at_the_tail() {
    let scrub = Scrub::new();
    scrub.register(1, &[SECRET.as_bytes()]);
    let cut = format!("{}{}", "a".repeat(FAIL_TEXT_WIRE_MAX - 12), &SECRET[..12]);
    assert_eq!(cut.len(), FAIL_TEXT_WIRE_MAX);
    let tail = scrub.text_tail(&cut);
    assert!(tail.ends_with("***"), "{}", &tail[tail.len() - 20..]);
    assert!(!leaks(&tail, SECRET.as_bytes()));
    assert!(fail_text(&scrub, &cut).len() <= FAIL_TEXT_SHOWN);
}

#[test]
fn a_benign_600_byte_text_is_cut_to_512() {
    let text = "x".repeat(600);
    assert_eq!(fail_text(&Scrub::new(), &text), text[..FAIL_TEXT_SHOWN]);
}

#[test]
#[ignore = "owner: W1-L3 (blocked: the store adapter builder is `port_error(&Answer, &Instance)`, private and over a registry Instance; no public builder like hook/plane/transport have)"]
fn the_store_adapters_port_error_log_line_and_audit_row_hold() {
    todo!("owner: W1-L3 (C-SCRUB-CUT)")
}

/// The `PortError` arm; the secret adapter writes no log line or audit row of its own (custody audits, K8).
#[test]
fn the_secret_adapters_port_error_log_line_and_audit_row_hold() {
    use busbar_plugin_loader::adapters::secret::port_failure;
    use busbar_plugin_loader::ports::PortError;

    let scrub = Scrub::new();
    scrub.register(1, &[SECRET.as_bytes()]);
    for form in &needles(SECRET.as_bytes()) {
        let form = core::str::from_utf8(form).expect("ASCII");
        let text = format!("{}{form}{}", "a".repeat(500), "b".repeat(60));
        for failed in [true, false] {
            let (PortError::Failed { text: shown, .. } | PortError::Refused { text: shown, .. }) =
                port_failure(&scrub, failed, 1, &text, None, None, None)
            else {
                unreachable!()
            };
            assert!(shown.len() <= FAIL_TEXT_SHOWN);
            assert!(!leaks(&shown, form.as_bytes()), "{form}");
        }
    }
}

#[test]
fn the_auth_adapters_port_error_log_line_and_audit_row_hold() {
    use busbar_plugin_abi::auth::BAD_CREDENTIAL;
    use busbar_plugin_abi::types::Status;
    use busbar_plugin_loader::adapters::auth::{plugin_error, rejected};
    use busbar_plugin_loader::ports::auth::Verdict;
    use busbar_plugin_loader::ports::PortError;

    let scrub = Scrub::new();
    scrub.register(1, &[SECRET.as_bytes()]);
    for form in &needles(SECRET.as_bytes()) {
        let form = core::str::from_utf8(form).expect("ASCII");
        let text = format!("{}{form}{}", "a".repeat(500), "b".repeat(60));
        // A login/outbound/refresh/serve REFUSED or FAILED, and a verify rejection (the verdict text).
        for status in [Status::REFUSED, Status::FAILED] {
            let (PortError::Refused { text: shown, .. } | PortError::Failed { text: shown, .. }) =
                plugin_error(status, 1, &text, None, None, None, &scrub)
            else {
                panic!("not a plugin error")
            };
            assert!(shown.len() <= FAIL_TEXT_SHOWN);
            assert!(!leaks(&shown, form.as_bytes()), "{form}");
        }
        let Verdict::Rejected { text: shown, .. } = rejected(BAD_CREDENTIAL, &text, &scrub) else {
            panic!("not Rejected")
        };
        assert!(shown.len() <= FAIL_TEXT_SHOWN);
        assert!(!leaks(&shown, form.as_bytes()), "{form}");
    }
}

/// The shown text of a plugin-error `PortError`.
fn shown_text(e: &busbar_plugin_loader::ports::PortError) -> &str {
    use busbar_plugin_loader::ports::PortError;
    match e {
        PortError::Failed { text, .. } | PortError::Refused { text, .. } => &**text,
        other => panic!("not a plugin error: {other:?}"),
    }
}

/// Every encoding of the secret at byte 500 of a 560-byte text goes through `build(failed, text)`: the shown
/// text is at most 512 bytes and holds no 4-byte run of the encoding, for REFUSED and FAILED alike.
fn adapter_arm(build: impl Fn(bool, &str) -> busbar_plugin_loader::ports::PortError) {
    for form in &needles(SECRET.as_bytes()) {
        let form = core::str::from_utf8(form).expect("ASCII");
        let text = format!("{}{form}{}", "a".repeat(500), "b".repeat(60));
        for failed in [true, false] {
            let e = build(failed, &text);
            let shown = shown_text(&e);
            assert!(shown.len() <= FAIL_TEXT_SHOWN);
            assert!(!leaks(shown, form.as_bytes()), "{form}");
        }
    }
}

#[test]
fn the_hook_adapters_port_error_log_line_and_audit_row_hold() {
    use busbar_plugin_loader::adapters::hook::port_error;
    let scrub = Scrub::new();
    scrub.register(1, &[SECRET.as_bytes()]);
    adapter_arm(|failed, text| port_error(&scrub, failed, 1, text, None, None, None));
}

#[test]
fn the_plane_adapters_port_error_log_line_and_audit_row_hold() {
    use busbar_plugin_loader::adapters::plane::port_error;
    let scrub = Scrub::new();
    scrub.register(1, &[SECRET.as_bytes()]);
    adapter_arm(|failed, text| port_error(&scrub, failed, 1, text, (None, None), None));
}

#[test]
fn the_transport_adapters_port_error_log_line_and_audit_row_hold() {
    use busbar_plugin_abi::types::Status;
    use busbar_plugin_loader::adapters::transport::shown;
    let scrub = Scrub::new();
    scrub.register(1, &[SECRET.as_bytes()]);
    adapter_arm(|failed, text| {
        let status = if failed {
            Status::FAILED
        } else {
            Status::REFUSED
        };
        shown(status, Some((1, text)), None, None, None, &scrub)
    });
}

#[test]
#[ignore = "owner: W1-L7 (blocked: the export adapter's FAILED/REFUSED builder is `ExportAdapter::failed(&Answer)`, private; no public builder like hook/plane/transport have)"]
fn the_export_adapters_port_error_log_line_and_audit_row_hold() {
    todo!("owner: W1-L7 (C-SCRUB-CUT)")
}

#[test]
#[ignore = "owner: W1-A13 (blocked: a C fixture entry that calls bb_fail with a multibyte text across the 3,072-byte cut; busbar-plugin-abi/tests/c_header/fixture.c has none)"]
fn bb_fail_cuts_at_a_char_boundary_and_masks_the_same() {
    todo!("owner: W1-A13 (C-SCRUB-CUT)")
}
