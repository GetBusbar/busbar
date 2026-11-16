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

/// The texts a fixture fails with: every encoding of the secret at bytes 500..540+ of a 560+-byte text, and at
/// byte 3,060 of a 3,160+-byte text (straddling the 3,072-byte wire cut).
fn failing_texts() -> Vec<(String, String)> {
    let mut texts = Vec::new();
    for form in &needles(SECRET.as_bytes()) {
        let form = core::str::from_utf8(form).expect("ASCII").to_owned();
        for at in [500, FAIL_TEXT_WIRE_MAX - 12] {
            let text = format!("{}{form}{}", "a".repeat(at), "b".repeat(60));
            texts.push((form.clone(), text));
        }
    }
    texts
}

/// The planned failure member of a fixture config.
fn planned(failed: bool, text: &str) -> String {
    let (status, code) = if failed {
        ("failed", 7)
    } else {
        ("refused", 5)
    };
    format!(
        r#"{{"status":"{status}","code":{code},"text":{}}}"#,
        crate::min3_store::json_str(text)
    )
}

/// The store arm (W1-L3), booted: a `plugin!` store resolves the registered secret in `open` (custody registers
/// it in the instance's scrub set) and fails with each text, in `info` (the open's `OpenError` text, the store
/// adapter's builder) and in `read` (the `PortError` the adapter logs, "store call not answered OK"). The shown
/// text is at most 512 bytes and holds no 4-byte run of the encoding, for REFUSED and FAILED alike, and the log
/// line carries exactly that text. The store adapter writes no audit row of its own.
#[test]
fn the_store_adapters_port_error_log_line_and_audit_row_hold() {
    use busbar_plugin_loader::instance::OpenError;
    use busbar_plugin_test::fake_needs::FakeNeeds;
    use busbar_ports::PortError;

    use crate::min3_store::{booted, inline, read_one, Capture, NOT_ANSWERED_OK};

    let mut needs = FakeNeeds::new();
    needs.secret("/secret", SECRET.as_bytes());
    let h = booted(inline::PLUGIN.plugin(), needs);
    for (n, (form, text)) in failing_texts().iter().enumerate() {
        for failed in [true, false] {
            let fail = planned(failed, text);
            let name = format!("cut-info-{n}-{failed}");
            let config = format!(r#"{{"secret":"cut","info":{fail}}}"#);
            let shown = match h.open_store(&name, config.as_bytes()) {
                Err(OpenError::Failed { code: 7, text, .. }) if failed => text,
                Err(OpenError::Config { code: 5, text, .. }) if !failed => text,
                Err(other) => panic!("{name}: {other:?}"),
                Ok(_) => panic!("{name}: an `info` that failed opened"),
            };
            assert!(
                shown.len() <= FAIL_TEXT_SHOWN,
                "{name}: {} bytes",
                shown.len()
            );
            assert!(!leaks(&shown, form.as_bytes()), "{name}: {form}");

            let name = format!("cut-read-{n}-{failed}");
            let config = format!(r#"{{"secret":"cut","read":{fail}}}"#);
            let store = h
                .open_store(&name, config.as_bytes())
                .unwrap_or_else(|e| panic!("{name}: open failed: {e:?}"));
            let capture = Capture::default();
            {
                let _tap = capture.install();
                assert!(h.block_on(read_one(&*store.backend)).is_err(), "{name}");
            }
            let logged = capture.with_message(NOT_ANSWERED_OK);
            assert_eq!(logged.len(), 1, "{name}");
            let text: Box<str> = shown.clone().into();
            let want = if failed {
                PortError::Failed {
                    code: 7,
                    text,
                    retry_after_s: None,
                    backend_status: None,
                    error: None,
                }
            } else {
                PortError::Refused {
                    code: 5,
                    text,
                    error: None,
                }
            };
            let want = format!("{want:?}");
            assert_eq!(logged[0].field("error"), Some(want.as_str()), "{name}");
        }
    }
}

/// The `PortError` arm; the secret adapter writes no log line or audit row of its own (custody audits, K8).
#[test]
fn the_secret_adapters_port_error_log_line_and_audit_row_hold() {
    use busbar_plugin_loader::adapters::secret::port_failure;
    use busbar_ports::PortError;

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
    use busbar_ports::auth::Verdict;
    use busbar_ports::PortError;

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
fn shown_text(e: &busbar_ports::PortError) -> &str {
    use busbar_ports::PortError;
    match e {
        PortError::Failed { text, .. } | PortError::Refused { text, .. } => &**text,
        other => panic!("not a plugin error: {other:?}"),
    }
}

/// Every encoding of the secret at byte 500 of a 560-byte text goes through `build(failed, text)`: the shown
/// text is at most 512 bytes and holds no 4-byte run of the encoding, for REFUSED and FAILED alike.
fn adapter_arm(build: impl Fn(bool, &str) -> busbar_ports::PortError) {
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

/// The export arm (W1-L7), booted: a `plugin!` sink resolves the registered secret in `open` and its `deliver`
/// fails with each text; the `deliver` port call's `PortError` text (`ExportAdapter::failed`) is at most 512
/// bytes and holds no 4-byte run of the encoding, for REFUSED and FAILED alike. The adapter writes no log line
/// or audit row of its own for a failed delivery (the export pump does, K8C, from this same text).
#[test]
fn the_export_adapters_port_error_log_line_and_audit_row_hold() {
    use std::time::{Duration, Instant};

    use busbar_plugin_abi::export::STREAM_LOGS;
    use busbar_plugin_abi::host_side::caller::CallStack;
    use busbar_plugin_test::fake_needs::FakeNeeds;
    use busbar_ports::CallCx;

    use crate::min3_store::{booted, json_str};

    let mut needs = FakeNeeds::new();
    needs.secret("/secret", SECRET.as_bytes());
    let h = booted(crate::min3_export_fail::PLUGIN.plugin(), needs);
    let lines: [&[u8]; 1] = [b"one line"];
    for (n, (form, text)) in failing_texts().iter().enumerate() {
        for failed in [true, false] {
            let name = format!("cut-deliver-{n}-{failed}");
            let (status, code) = if failed {
                ("failed", 7)
            } else {
                ("refused", 5)
            };
            let config = format!(
                r#"{{"secret":"cut","status":"{status}","code":{code},"text":{}}}"#,
                json_str(text)
            );
            let port = h
                .open_export(&name, config.as_bytes())
                .unwrap_or_else(|e| panic!("{name}: open failed: {e:?}"));
            let cx = CallCx {
                deadline: Instant::now() + Duration::from_secs(30),
                request_id: 1,
                stack: CallStack::default(),
            };
            let e = h
                .block_on(port.deliver(cx, STREAM_LOGS, 1, 1, &lines))
                .err()
                .unwrap_or_else(|| panic!("{name}: a failing deliver was answered"));
            let shown = shown_text(&e);
            assert!(
                shown.len() <= FAIL_TEXT_SHOWN,
                "{name}: {} bytes",
                shown.len()
            );
            assert!(!leaks(shown, form.as_bytes()), "{name}: {form}");
        }
    }
}

/// The C header arm (W1-A13): a C host built from `busbar_plugin.h` alone (busbar-plugin-abi/tests/c_header/
/// fail_cut.c) answers `bb_fail(FAILED, F_INTERNAL, text)` for each text it is given and prints the answer. A
/// multibyte text across the 3,072-byte bound is cut at a char boundary, exactly as the Rust shim cuts it (the
/// same FAIL bytes); a secret straddling the cut is masked at the tail by `Scrub::text_tail`, and the shown text
/// (`fail_text`) is at most 512 bytes with no 4-byte run of the secret or any of its encodings.
#[test]
fn bb_fail_cuts_at_a_char_boundary_and_masks_the_same() {
    use busbar_plugin_abi::fail::failed;
    use busbar_plugin_abi::records::{tag, FailRec, Records, Reply, Writer};
    use busbar_plugin_abi::types::Status;

    let mut texts: Vec<(Option<String>, String)> = Vec::new();
    // One char of each UTF-8 width ending past the bound, and a text of only 2- and 3-byte chars.
    for (pad, ch) in [(3071, "é"), (3070, "€"), (3069, "😀"), (3071, "😀")] {
        texts.push((None, format!("{}{ch}{}", "a".repeat(pad), "z".repeat(10))));
    }
    texts.push((None, "€é".repeat(700)));
    // The secret and each encoding starting at byte 3,060 behind 2-byte chars (so the cut is a char boundary
    // inside the secret), and at byte 500.
    for form in &needles(SECRET.as_bytes()) {
        let form = core::str::from_utf8(form).expect("ASCII").to_owned();
        let straddle = format!("{}{form}{}", "é".repeat(1530), "ü".repeat(60));
        texts.push((Some(form.clone()), straddle));
        let early = format!("{}{form}{}", "a".repeat(500), "b".repeat(60));
        texts.push((Some(form), early));
    }

    let host = crate::c_header::cc::cc("c_fail_cut", &["fail_cut.c"], true);
    let run = std::process::Command::new(&host)
        .args(texts.iter().map(|(_, text)| text.as_str()))
        .output()
        .expect("the C host runs");
    assert!(run.status.success(), "C host exit {:?}", run.status);
    let seen = String::from_utf8(run.stdout).expect("UTF-8 lines");
    let lines: Vec<&str> = seen.lines().collect();
    assert_eq!(lines.len(), texts.len(), "one answer per text");

    let scrub = Scrub::new();
    scrub.register(1, &[SECRET.as_bytes()]);
    let unhex = |h: &str| -> Vec<u8> {
        (0..h.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&h[i..i + 2], 16).expect("hex"))
            .collect()
    };
    for ((secret, text), line) in texts.iter().zip(&lines) {
        let fields: Vec<&str> = line.split(' ').collect();
        assert_eq!(fields[..2], ["fail", "2"], "{line:.40}");
        let answer = unhex(fields[2]);

        // The Rust shim's FAIL for the same Fail: the detail cut to the bound at a char boundary.
        let mut cut = text.len().min(FAIL_TEXT_WIRE_MAX);
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        let mut shim = Reply::new();
        let head = FailRec {
            status: Status::FAILED.0,
            code: failed::F_INTERNAL,
        };
        shim.put_pod_tail(tag::FAIL, &head, text[..cut].as_bytes())
            .expect("fail");
        assert_eq!(answer, shim.as_bytes(), "the C cut is the Rust cut");

        let rec = Records::new(&answer)
            .next()
            .expect("one record")
            .expect("framing");
        assert_eq!(rec.tag, tag::FAIL);
        let (_, detail) = rec.pod_tail::<FailRec>().expect("FailRec");
        let detail = core::str::from_utf8(detail).expect("cut at a char boundary");
        assert!(detail.len() <= FAIL_TEXT_WIRE_MAX && text.starts_with(detail));
        assert!(
            text.len() <= FAIL_TEXT_WIRE_MAX || detail.len() > FAIL_TEXT_WIRE_MAX - 4,
            "cut no further than the char boundary"
        );

        let shown = fail_text(&scrub, detail);
        assert!(shown.len() <= FAIL_TEXT_SHOWN);
        if let Some(form) = secret {
            assert!(!leaks(&shown, form.as_bytes()), "{form}");
            if detail.len() < text.len() {
                let tail = scrub.text_tail(detail);
                assert!(tail.ends_with("***"), "{form}");
                assert!(!leaks(&tail, form.as_bytes()), "{form}");
            }
        }
    }
}
