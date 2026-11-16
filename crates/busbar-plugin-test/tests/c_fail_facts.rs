// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-FAIL-FACTS (ABI-MIN3-INTERFACE §14): FAIL then exactly the stated FACTs, the bytes zeroed, and each adapter's
//! `PortError::Failed` facts (round 21).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

/// The shim arm (W1-A3): a FAILED Fail with both facts answers FAIL then exactly FACT(1, 30), FACT(2, 503).
#[test]
fn the_shim_writes_fail_then_its_facts() {
    use busbar_plugin_abi::fail::{fact, failed};
    use busbar_plugin_abi::records::{tag, FailRec};

    use crate::bridge_fixture::{self as fx, Status};

    let instance = fx::instance();
    let mut lease = fx::lease();
    assert!(matches!(
        fx::start(&instance, b"fail-facts", &mut lease),
        fx::Started::Done(Status::FAILED)
    ));
    assert_eq!(fx::tags(&lease), [tag::FAIL, tag::FACT, tag::FACT]);
    assert_eq!(
        fx::facts(&lease),
        [
            (fact::FACT_RETRY_AFTER_S, 30),
            (fact::FACT_BACKEND_STATUS, 503)
        ]
    );
    let answer = fx::answer(&lease);
    let fail = &answer[0].1;
    let head = core::mem::size_of::<FailRec>();
    assert_eq!(&fail[..4], &Status::FAILED.0.to_le_bytes());
    assert_eq!(&fail[4..8], &failed::F_UPSTREAM.to_le_bytes());
    assert_eq!(&fail[head..], b"the backend said 503");
}

/// The answer parse's arm: a hand-written FAILED answer whose facts break the round-21 rule (a key outside
/// `FAIL_FACT_KEYS`, a key twice, a third FACT, any record but ERROR/FACT after FAIL, a FACT on REFUSED) is FAULT
/// BadRecords; the stated facts read back through `fail_fact`, and only on FAILED.
#[test]
fn hand_written_bad_fact_answers_fault() {
    use busbar_plugin_abi::fail::{fact, failed, FaultReason};
    use busbar_plugin_abi::host::Answer;
    use busbar_plugin_abi::records::{tag, FailRec, RecErr, Reply, Writer};
    use busbar_plugin_abi::types::Status;

    let answer = |status: Status, facts: &[(u32, u64)], extra: Option<u16>| {
        let mut r = Reply::new();
        let head = FailRec {
            status: status.0,
            code: failed::F_UPSTREAM,
        };
        r.put_pod_tail(tag::FAIL, &head, b"503").expect("fail");
        for &(key, value) in facts {
            r.put_fact(key, value).expect("fact");
        }
        if let Some(t) = extra {
            r.put(t, b"x").expect("extra");
        }
        r.as_bytes().to_vec()
    };
    let (retry, backend) = (fact::FACT_RETRY_AFTER_S, fact::FACT_BACKEND_STATUS);
    let good = answer(Status::FAILED, &[(retry, 30), (backend, 503)], None);
    let a = Answer::parse(Status::FAILED, &good).expect("FAIL then the two facts");
    assert_eq!(
        (a.fail_fact(retry), a.fail_fact(backend)),
        (Some(30), Some(503))
    );
    let out_of_place = |t: u16| Some(FaultReason::BadRecords(RecErr::Unknown(t)));
    for (facts, extra, status, why) in [
        (
            &[(fact::FACT_TLS_PIN, 1)][..],
            None,
            Status::FAILED,
            "a key outside FAIL_FACT_KEYS",
        ),
        (
            &[(retry, 1), (retry, 2)][..],
            None,
            Status::FAILED,
            "a key twice",
        ),
        (
            &[(retry, 1), (backend, 2), (retry, 3)][..],
            None,
            Status::FAILED,
            "a third FACT",
        ),
        (
            &[(retry, 1)][..],
            Some(tag::TEXT),
            Status::FAILED,
            "a TEXT after the facts",
        ),
        (
            &[(retry, 1)][..],
            None,
            Status::REFUSED,
            "a FACT on REFUSED",
        ),
    ] {
        let bytes = answer(status, facts, extra);
        let got = Answer::parse(status, &bytes).err();
        let want = match extra {
            Some(t) => out_of_place(t),
            None => out_of_place(tag::FACT),
        };
        assert_eq!(got, want, "{why}");
    }
}

/// The store arm (W1-L3), booted: a `plugin!` store whose `read` answers
/// `Fail::failed_because(F_UPSTREAM, t).with_fact(FACT_RETRY_AFTER_S, 30).with_fact(FACT_BACKEND_STATUS, 503)`,
/// opened through `Registry::open_store` and read through its `PersistenceBackend`. The adapter's `PortError` is
/// what `exec` logs ("store call not answered OK", `error = ?e`): FAILED carries both facts, absent facts are
/// None, REFUSED carries none; the kernel sees `Failure::Unavailable` and `Failure::Refused`.
#[test]
fn store_adapter_maps_the_facts() {
    use busbar_contract::persistence::Failure;
    use busbar_plugin_abi::fail::failed;
    use busbar_plugin_test::fake_needs::FakeNeeds;
    use busbar_ports::PortError;

    use crate::min3_store::{booted, inline, read_one, Capture, NOT_ANSWERED_OK};

    let h = booted(inline::PLUGIN.plugin(), FakeNeeds::new());
    let cases: [(&str, &[u8], Failure, PortError); 3] = [
        (
            "facts-failed",
            br#"{"read":{"status":"failed","code":7,"text":"the backend said 503","retry_after_s":30,"backend_status":503}}"#,
            Failure::Unavailable,
            PortError::Failed {
                code: failed::F_UPSTREAM,
                text: "the backend said 503".into(),
                retry_after_s: Some(30),
                backend_status: Some(503),
                error: None,
            },
        ),
        (
            "facts-none",
            br#"{"read":{"status":"failed","code":2,"text":"slow"}}"#,
            Failure::Unavailable,
            PortError::Failed {
                code: failed::F_TIMEOUT,
                text: "slow".into(),
                retry_after_s: None,
                backend_status: None,
                error: None,
            },
        ),
        (
            "facts-refused",
            br#"{"read":{"status":"refused","code":5,"text":"no","retry_after_s":1,"backend_status":1}}"#,
            Failure::Refused,
            PortError::Refused {
                code: 5,
                text: "no".into(),
                error: None,
            },
        ),
    ];
    for (name, config, failure, want) in cases {
        let store = h
            .open_store(name, config)
            .unwrap_or_else(|e| panic!("{name}: open failed: {e:?}"));
        let capture = Capture::default();
        let seen = {
            let _tap = capture.install();
            h.block_on(read_one(&*store.backend))
        };
        assert_eq!(seen.err(), Some(failure), "{name}");
        let logged = capture.with_message(NOT_ANSWERED_OK);
        assert_eq!(logged.len(), 1, "{name}: one warning per answer");
        let want = format!("{want:?}");
        assert_eq!(logged[0].field("error"), Some(want.as_str()), "{name}");
    }
}

#[test]
fn secret_adapter_maps_the_facts() {
    use busbar_plugin_abi::host_side::scrub::Scrub;
    use busbar_plugin_loader::adapters::secret::port_failure;
    use busbar_ports::PortError;

    let scrub = Scrub::new();
    assert_eq!(
        port_failure(
            &scrub,
            true,
            3,
            "the backend said 503",
            Some(30),
            Some(503),
            None
        ),
        PortError::Failed {
            code: 3,
            text: "the backend said 503".into(),
            retry_after_s: Some(30),
            backend_status: Some(503),
            error: None,
        }
    );
    assert!(matches!(
        port_failure(&scrub, true, 3, "down", None, None, None),
        PortError::Failed {
            retry_after_s: None,
            backend_status: None,
            ..
        }
    ));
    // A refusal never carries facts.
    assert!(matches!(
        port_failure(&scrub, false, 5, "no", Some(1), Some(1), None),
        PortError::Refused { .. }
    ));
}

/// The auth arm (W1-L5): FAILED carries the stated Retry-After and backend status and the resolved ERROR, absent
/// facts are None, REFUSED carries no fact, and a status that is neither is a FAULT (IF §11.3 round 21, §8.3
/// login outcomes).
#[test]
fn auth_adapter_maps_the_facts() {
    use busbar_plugin_abi::auth::SECURITY_CHECK;
    use busbar_plugin_abi::fail::{failed, CallError, FaultReason};
    use busbar_plugin_abi::host_side::scrub::Scrub;
    use busbar_plugin_abi::types::Status;
    use busbar_plugin_loader::adapters::auth::plugin_error;
    use busbar_ports::PluginCode;
    use busbar_ports::PortError;

    let scrub = Scrub::new();
    let code = PluginCode {
        plugin: "auth-oidc",
        number: 12,
    };
    assert_eq!(
        plugin_error(
            Status::FAILED,
            failed::F_UNAVAILABLE,
            "the provider said 503",
            Some(30),
            Some(503),
            Some(code),
            &scrub
        ),
        PortError::Failed {
            code: failed::F_UNAVAILABLE,
            text: "the provider said 503".into(),
            retry_after_s: Some(30),
            backend_status: Some(503),
            error: Some(code),
        }
    );
    assert!(matches!(
        plugin_error(
            Status::FAILED,
            failed::F_TIMEOUT,
            "slow",
            None,
            None,
            None,
            &scrub
        ),
        PortError::Failed {
            retry_after_s: None,
            backend_status: None,
            ..
        }
    ));
    assert_eq!(
        plugin_error(
            Status::REFUSED,
            SECURITY_CHECK,
            "nonce",
            Some(30),
            Some(503),
            None,
            &scrub
        ),
        PortError::Refused {
            code: SECURITY_CHECK,
            text: "nonce".into(),
            error: None,
        }
    );
    assert_eq!(
        plugin_error(Status::OK, 0, "", Some(30), None, None, &scrub),
        PortError::Call(CallError::Fault(FaultReason::BadStatus(Status::OK.0)))
    );
}

/// The hook arm (W1-L6): FAILED carries the stated Retry-After and backend status, absent facts are None, and a
/// REFUSED answer carries no fact.
#[test]
fn hook_adapter_maps_the_facts() {
    use busbar_plugin_abi::fail::failed;
    use busbar_plugin_abi::host_side::scrub::Scrub;
    use busbar_plugin_loader::adapters::hook::port_error;
    use busbar_ports::PortError;

    let scrub = Scrub::new();
    assert_eq!(
        port_error(
            &scrub,
            true,
            failed::F_UPSTREAM,
            "the backend said 503",
            Some(30),
            Some(503),
            None
        ),
        PortError::Failed {
            code: failed::F_UPSTREAM,
            text: "the backend said 503".into(),
            retry_after_s: Some(30),
            backend_status: Some(503),
            error: None,
        }
    );
    assert!(matches!(
        port_error(&scrub, true, failed::F_TIMEOUT, "slow", None, None, None),
        PortError::Failed {
            retry_after_s: None,
            backend_status: None,
            ..
        }
    ));
    assert!(matches!(
        port_error(&scrub, false, 5, "no", Some(1), Some(1), None),
        PortError::Refused { .. }
    ));
}

/// The export arm (W1-L7), booted: a `plugin!` sink whose `deliver` answers the planned Fail, opened through
/// `Registry::open_export`; the `deliver` port call's `PortError` carries both facts on FAILED, None for absent
/// facts, and none on REFUSED.
#[test]
fn export_adapter_maps_the_facts() {
    use std::time::{Duration, Instant};

    use busbar_plugin_abi::export::STREAM_LOGS;
    use busbar_plugin_abi::fail::failed;
    use busbar_plugin_abi::host_side::caller::CallStack;
    use busbar_plugin_test::fake_needs::FakeNeeds;
    use busbar_ports::{CallCx, PortError};

    use crate::min3_store::booted;

    let h = booted(crate::min3_export_fail::PLUGIN.plugin(), FakeNeeds::new());
    let cases: [(&str, &[u8], PortError); 3] = [
        (
            "facts-failed",
            br#"{"status":"failed","code":7,"text":"the backend said 503","retry_after_s":30,"backend_status":503}"#,
            PortError::Failed {
                code: failed::F_UPSTREAM,
                text: "the backend said 503".into(),
                retry_after_s: Some(30),
                backend_status: Some(503),
                error: None,
            },
        ),
        (
            "facts-none",
            br#"{"status":"failed","code":2,"text":"slow"}"#,
            PortError::Failed {
                code: failed::F_TIMEOUT,
                text: "slow".into(),
                retry_after_s: None,
                backend_status: None,
                error: None,
            },
        ),
        (
            "facts-refused",
            br#"{"status":"refused","code":5,"text":"no","retry_after_s":1,"backend_status":1}"#,
            PortError::Refused {
                code: 5,
                text: "no".into(),
                error: None,
            },
        ),
    ];
    let lines: [&[u8]; 1] = [b"one line"];
    for (name, config, want) in cases {
        let port = h
            .open_export(name, config)
            .unwrap_or_else(|e| panic!("{name}: open failed: {e:?}"));
        let cx = CallCx {
            deadline: Instant::now() + Duration::from_secs(30),
            request_id: 1,
            stack: CallStack::default(),
        };
        let got = h
            .block_on(port.deliver(cx, STREAM_LOGS, 1, 1, &lines))
            .err();
        assert_eq!(got, Some(want), "{name}");
    }
}

/// The plane admin arm (W1-L8): the one `port_error` builder fills the facts on FAILED only.
#[test]
fn plane_admin_maps_the_facts() {
    use busbar_plugin_abi::fail::failed;
    use busbar_plugin_abi::host_side::scrub::Scrub;
    use busbar_plugin_loader::adapters::plane::port_error;
    use busbar_ports::PortError;

    let scrub = Scrub::new();
    assert_eq!(
        port_error(
            &scrub,
            true,
            failed::F_UPSTREAM,
            "the backend said 503",
            (Some(30), Some(503)),
            None
        ),
        PortError::Failed {
            code: failed::F_UPSTREAM,
            text: "the backend said 503".into(),
            retry_after_s: Some(30),
            backend_status: Some(503),
            error: None,
        }
    );
    assert!(matches!(
        port_error(&scrub, true, failed::F_TIMEOUT, "slow", (None, None), None),
        PortError::Failed {
            retry_after_s: None,
            backend_status: None,
            ..
        }
    ));
    assert!(matches!(
        port_error(&scrub, false, 5, "no", (Some(1), Some(1)), None),
        PortError::Refused { .. }
    ));
}

/// The retry arm (W1-K3): a Failed answer stating `retry_after_s = 30` is never rescheduled sooner than 30 s,
/// at the lowest jitter draw, on a store call and an export delivery.
#[test]
fn retry_policy_honours_retry_after() {
    use std::time::Duration;

    use busbar_kernel::retry::{Policy, Retry, RetryPolicy, RetrySite};
    use busbar_plugin_abi::fail::failed;
    use busbar_ports::PortError;

    let err = PortError::Failed {
        code: failed::F_UNAVAILABLE,
        text: "down".into(),
        retry_after_s: Some(30),
        backend_status: Some(503),
        error: None,
    };
    let policy = Policy::with_draw(|| 0.0);
    for site in [RetrySite::StoreRead, RetrySite::ExportDeliver(1)] {
        let Retry::After(wait) = policy.next(site, 1, &err) else {
            panic!("a Failed call at {site:?} waits");
        };
        assert!(wait >= Duration::from_secs(30), "{site:?} waited {wait:?}");
    }
}
