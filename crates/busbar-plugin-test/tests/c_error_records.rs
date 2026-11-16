// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ERROR-RECORDS (ABI-MIN3-INTERFACE §14 round 34; PLUGIN-ERROR-CODES r4): FAIL, ERROR, FACTs in that order,
//! ERROR only when the number is not 0, and the longest such answer fits the first 4 KiB buffer. The record-order
//! arm is W1-A1's (merged); the other arms are the shim's, the C helpers', the answer parse's, the log sink's and
//! the render's. PLUGIN-ERROR-CODES §8 T1-T16 are owned per IF §50's owners paragraph.
//!
//! WBS rule 10: each ignored arm waits for the task that lands the last piece it needs; that task writes the
//! arm's body and un-ignores it in its own MR (red first, then green). Arms of tasks merged before W1-T1 run now.

use busbar_plugin_abi::fail::{fact, failed, Fail, FAIL_TEXT_WIRE_MAX};
use busbar_plugin_abi::host::level;
use busbar_plugin_abi::records::{tag, FailRec, Records, Reply, U32Rec, Writer};

#[test]
fn fail_error_and_two_facts_fit_the_first_4_kib_in_order() {
    let fail = Fail::failed_because(failed::F_UPSTREAM, "x".repeat(FAIL_TEXT_WIRE_MAX))
        .with_fact(fact::FACT_RETRY_AFTER_S, 30)
        .with_fact(fact::FACT_BACKEND_STATUS, 503)
        .with_error(7071);
    let mut reply = Reply::new();
    let head = FailRec {
        status: fail.status().0,
        code: fail.code(),
    };
    reply
        .put_pod_tail(tag::FAIL, &head, fail.text().as_bytes())
        .expect("fail");
    let error = U32Rec {
        value: u32::from(fail.error()),
        _r: 0,
    };
    reply.put_pod(tag::ERROR, &error).expect("error");
    for (key, value) in fail.facts() {
        reply.put_fact(key, value).expect("fact");
    }
    assert!(reply.len() <= 4096, "{} bytes", reply.len());
    let tags: Vec<u16> = Records::new(reply.as_bytes())
        .map(|rec| rec.expect("framing").tag)
        .collect();
    assert_eq!(tags, [tag::FAIL, tag::ERROR, tag::FACT, tag::FACT]);
    assert_eq!(Fail::failed(failed::F_UPSTREAM).with_error(0).error(), 0);
}

/// The shim arm (W1-A3, IF §6.4 step 2): a chain answering a Fail writes FAIL, then ERROR only when the number is not 0,
/// then the FAILED facts; REFUSED may carry ERROR and never facts.
#[test]
fn the_shim_writes_error_only_when_the_number_is_set() {
    use crate::bridge_fixture::{self as fx, Status};

    let instance = fx::instance();
    let cases: [(&[u8], Status, &[u16], Option<u32>); 4] = [
        (
            b"fail-error",
            Status::FAILED,
            &[tag::FAIL, tag::ERROR, tag::FACT, tag::FACT],
            Some(7071),
        ),
        (
            b"fail-facts",
            Status::FAILED,
            &[tag::FAIL, tag::FACT, tag::FACT],
            None,
        ),
        (
            b"refuse-error",
            Status::REFUSED,
            &[tag::FAIL, tag::ERROR],
            Some(7070),
        ),
        (b"refuse-plain", Status::REFUSED, &[tag::FAIL], None),
    ];
    for (scenario, status, tags, error) in cases {
        let mut lease = fx::lease();
        assert!(
            matches!(fx::start(&instance, scenario, &mut lease), fx::Started::Done(s) if s == status),
            "{scenario:?}"
        );
        assert_eq!(fx::tags(&lease), tags, "{scenario:?}");
        assert_eq!(fx::error_number(&lease), error, "{scenario:?}");
        assert!(lease.len() <= 4096);
    }
}

/// W1-A13: the C fixture, driven out of process by a C host (busbar-plugin-abi/tests/c_header/driver.c), writes
/// what the Rust shim writes for `Fail::failed_because(F_INTERNAL, text).with_error(7071)`: one FAIL, then one
/// ERROR, with everything written before wiped; `bb_log` passes error 0 and `bb_log_error` the number, both as
/// the raw `log` entry receives `Host::log` and `Host::log_error`; and describe declares that number.
#[test]
fn the_c_helpers_write_the_same_bytes_and_arguments_as_the_rust_shim() {
    let driver = crate::c_header::cc::cc("c_fixture_driver", &["fixture.c", "driver.c"], true);
    let run = std::process::Command::new(&driver)
        .output()
        .expect("the driver runs");
    assert!(run.status.success(), "driver exit {:?}", run.status);
    let seen = String::from_utf8(run.stdout).expect("UTF-8 lines");
    let lines: Vec<Vec<&str>> = seen.lines().map(|l| l.split(' ').collect()).collect();
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();

    let fail = Fail::failed_because(failed::F_INTERNAL, "numbered failure").with_error(7071);
    let mut shim = Reply::new();
    let head = FailRec {
        status: fail.status().0,
        code: fail.code(),
    };
    shim.put_pod_tail(tag::FAIL, &head, fail.text().as_bytes())
        .expect("fail");
    let error = U32Rec {
        value: u32::from(fail.error()),
        _r: 0,
    };
    shim.put_pod(tag::ERROR, &error).expect("error");
    let msg = hex(b"numbered".as_slice());
    let (info, warn) = (level::INFO.to_string(), level::WARN.to_string());
    let status = fail.status().0.to_string();
    let shim = hex(shim.as_bytes());
    assert_eq!(
        lines[1..],
        [
            vec!["log", info.as_str(), "0", msg.as_str()],
            vec!["log", warn.as_str(), "7071", msg.as_str()],
            vec!["numbered", status.as_str(), "zeroed", shim.as_str()],
        ]
    );

    assert_eq!(lines[0][..2], ["describe", "0"]);
    let describe: Vec<u8> = (0..lines[0][2].len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&lines[0][2][i..i + 2], 16).expect("hex"))
        .collect();
    let declared: Vec<&[u8]> = Records::new(&describe)
        .map(|rec| rec.expect("framing"))
        .filter(|rec| rec.tag == tag::D_ERRORS)
        .map(|rec| rec.body)
        .collect();
    assert_eq!(declared, [7071u16.to_le_bytes().as_slice()]);
}

/// The answer parse's position arm (round 34): the tail is FAIL, at most one ERROR directly after it (REFUSED or
/// FAILED), then the FAILED-only FACTs. A second ERROR, an ERROR after a FACT, a FACT on a REFUSED answer and an
/// ERROR in an OK answer FAULT; the accepted forms read back, the number raw (never narrowed).
#[test]
fn an_error_record_out_of_place_faults_and_the_accepted_forms_pass() {
    use busbar_plugin_abi::fail::{refused, FaultReason};
    use busbar_plugin_abi::host::Answer;
    use busbar_plugin_abi::records::RecErr;
    use busbar_plugin_abi::types::Status;

    let answer = |status: Status, tail: &[(u16, Vec<u8>)]| {
        let mut r = Reply::new();
        let head = FailRec {
            status: status.0,
            code: refused::R_DENIED,
        };
        r.put_pod_tail(tag::FAIL, &head, b"denied").expect("fail");
        for (t, body) in tail {
            r.put(*t, body).expect("tail");
        }
        r.as_bytes().to_vec()
    };
    let error = |n: u32| {
        let mut body = n.to_ne_bytes().to_vec();
        body.extend_from_slice(&0u32.to_ne_bytes());
        (tag::ERROR, body)
    };
    let fact = |key: u32, value: u64| {
        let mut body = key.to_ne_bytes().to_vec();
        body.extend_from_slice(&0u32.to_ne_bytes());
        body.extend_from_slice(&value.to_ne_bytes());
        (tag::FACT, body)
    };
    // Accepted.
    let bytes = answer(Status::REFUSED, &[error(7070)]);
    let a = Answer::parse(Status::REFUSED, &bytes).expect("FAIL, ERROR");
    assert_eq!(
        (a.fail_error(), a.fail().map(|(code, _)| code)),
        (7070, Some(refused::R_DENIED))
    );
    let bytes = answer(Status::FAILED, &[error(65_607), fact(1, 30), fact(2, 503)]);
    let a = Answer::parse(Status::FAILED, &bytes).expect("FAIL, ERROR, FACT, FACT");
    assert_eq!(a.fail_error(), 65_607, "raw, never narrowed to 16 bits");
    assert_eq!((a.fail_fact(1), a.fail_fact(2)), (Some(30), Some(503)));
    let bytes = answer(Status::REFUSED, &[]);
    assert_eq!(
        Answer::parse(Status::REFUSED, &bytes)
            .expect("FAIL")
            .fail_error(),
        0
    );
    // Out of place.
    let bad = FaultReason::BadRecords(RecErr::Unknown(tag::ERROR));
    let bytes = answer(Status::FAILED, &[error(1), error(2)]);
    assert_eq!(
        Answer::parse(Status::FAILED, &bytes).err(),
        Some(bad),
        "a second ERROR"
    );
    let bytes = answer(Status::FAILED, &[fact(1, 30), error(1)]);
    assert_eq!(
        Answer::parse(Status::FAILED, &bytes).err(),
        Some(bad),
        "ERROR after a FACT"
    );
    let bytes = answer(Status::REFUSED, &[error(1), fact(1, 30)]);
    assert_eq!(
        Answer::parse(Status::REFUSED, &bytes).err(),
        Some(FaultReason::BadRecords(RecErr::Unknown(tag::FACT))),
        "a FACT on REFUSED"
    );
    let mut ok = Reply::new();
    ok.put(tag::TEXT, b"x").expect("text");
    ok.put_pod(tag::ERROR, &U32Rec { value: 5, _r: 0 })
        .expect("error");
    assert_eq!(
        Answer::parse(Status::OK, ok.as_bytes()).err(),
        Some(FaultReason::UnknownTag(tag::ERROR)),
        "ERROR in an OK answer"
    );
}

/// The raw-`log` half of the arm below, over the probe image: two lines through the raw log entry numbered
/// 65,607 (= 65,536 + 71, so a host that truncated to `u16` would show 71) render no code, and the registry
/// writes the undeclared WARN once for the instance, carrying the whole number.
#[test]
fn a_raw_log_over_9999_renders_no_code_and_warns_once() {
    use std::time::{Duration, Instant};

    use busbar_plugin_abi::host_side::caller::CallStack;
    use busbar_plugin_loader::ports::CallCx;
    use busbar_plugin_test::fake_needs::FakeNeeds;
    use busbar_plugin_test::suites::harness::Harness;

    use crate::min3_second as fx;

    let h = Harness::admit(fx::probe::PLUGIN.plugin(), FakeNeeds::new())
        .unwrap_or_else(|r| panic!("{r:?}"));
    let port = h
        .open_secret("raw-log", br#"{"tag":"raw-log"}"#)
        .unwrap_or_else(|e| panic!("{e:?}"));
    let cx = CallCx {
        deadline: Instant::now() + Duration::from_secs(10),
        request_id: 1,
        stack: CallStack::default(),
    };
    assert!(h
        .block_on(port.resolve(cx, br#"{"name":"raw-log"}"#))
        .is_ok());

    let lines: Vec<_> = h
        .logs()
        .into_iter()
        .filter(|line| line.message == "a raw log line numbered over 9999")
        .collect();
    assert_eq!(lines.len(), 2, "both raw lines were logged: {lines:?}");
    for line in &lines {
        assert_eq!(line.code, "", "no code renders for {}", fx::RAW_LOG_ERROR);
        assert_eq!(line.level, level::WARN);
    }
    assert_eq!(
        h.undeclared(),
        vec![u64::from(fx::RAW_LOG_ERROR)],
        "one undeclared WARN for the instance, with the whole number (never 71)"
    );
}

#[test]
#[ignore = "owner: W1-L2; blocked (re-checked on dev 2026-11-16): the ERROR-record half needs a plugin that writes an ERROR record numbered 65,607 (over u16), and the SDK's `Fail::with_error` takes a u16 and the shim writes only what the SDK builds, so no safe fixture can emit it; the raw `log` half runs as a_raw_log_over_9999_renders_no_code_and_warns_once"]
fn a_raw_log_and_an_error_over_9999_render_no_code_and_warn_once() {
    todo!("owner: W1-L2 (C-ERROR-RECORDS)")
}

#[test]
#[ignore = "owner: W1-K8D; blocked (re-checked on dev 2026-11-16): the kernel admission path that reads error_codes_refused and the crypto self-test row is not on dev (OUTSTANDING row 5)"]
fn a_bad_d_errors_admits_without_codes_and_a_store_and_gate_hook_still_serve() {
    todo!("owner: W1-K8D (C-ERROR-RECORDS)")
}
