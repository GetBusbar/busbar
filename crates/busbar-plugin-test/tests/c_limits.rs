// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-LIMITS (ABI-MIN3-INTERFACE §14): Instance limits (§12.22). No `plaintext` arm (rule 14).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use busbar_kernel::port_call::PortGate;
use busbar_plugin_abi::fail::CallError;
use busbar_plugin_abi::host_side::caller::{CallStack, InstanceLimits};
use busbar_plugin_loader::ports::{CallCx, PortError};
use tokio::sync::Notify;

fn cx(within: Duration) -> CallCx {
    CallCx {
        deadline: Instant::now() + within,
        request_id: 1,
        stack: CallStack::default(),
    }
}

fn limits(timeout_ms: u32, max_inflight: u32) -> InstanceLimits {
    InstanceLimits {
        timeout_ms,
        max_inflight,
        ..InstanceLimits::default()
    }
}

/// The config arms (§12.22, W1-K7): `limits` beside `module` is parsed for an instance of every kind, bounded at
/// load (≤ 600,000 ms, ≤ 65,535 in flight, `stream_stall_ms` 0 or 1,000..=600,000, no `plaintext` row), and never
/// reaches the plugin: the bag it is bound from is `settings` alone.
#[test]
fn limits_config_arms() {
    use busbar_kernel::config::min3::{parse_min3, InstanceLimitsCfg};
    use busbar_kernel::config::{deploy_from_yaml_str, Grammar};
    let parse = |yaml: &str| {
        deploy_from_yaml_str(yaml, &Grammar::empty())
            .unwrap_or_else(|e| panic!("`limits` beside `module` is config grammar: {e}"))
    };
    let deploy = parse(
        r#"
providers: {}
models: {}
store:
  module: valkey
  settings: { url: "rediss://cache.internal:6380" }
  limits: { connect_timeout_ms: 1500 }
secrets:
  vault:
    limits: { timeout_ms: 2000 }
identity-providers:
  corp-ldap:
    module: ldap
    limits: { timeout_ms: 10000, connect_timeout_ms: 3000, max_inflight: 64 }
hooks:
  webrequest:
    module: webrequest
    limits: { timeout_ms: 750 }
export:
  siem:
    module: request-log-webhook
    limits: { max_inflight: 8, timeout_ms: 5000 }
"#,
    );
    let min3 = parse_min3(&deploy).expect("every value is in bounds");
    let at = |section: &str, name: &str| {
        let key: (Box<str>, Box<str>) = (section.into(), name.into());
        min3.limits.get(&key).copied()
    };
    assert_eq!(
        at("store", "store").map(|l| l.connect_timeout_ms),
        Some(1_500)
    );
    assert_eq!(at("secrets", "vault").map(|l| l.timeout_ms), Some(2_000));
    assert_eq!(
        at("identity-providers", "corp-ldap"),
        Some(InstanceLimitsCfg {
            timeout_ms: 10_000,
            connect_timeout_ms: 3_000,
            max_inflight: 64,
            stream_stall_ms: 0,
        })
    );
    assert_eq!(at("hooks", "webrequest").map(|l| l.timeout_ms), Some(750));
    assert_eq!(at("export", "siem").map(|l| l.max_inflight), Some(8));
    assert_eq!(
        deploy.store.as_ref().expect("store").settings.key_names(),
        ["url"],
        "limits is stripped before binding"
    );

    for (limits, key) in [
        ("{ timeout_ms: 600001 }", "timeout_ms"),
        ("{ connect_timeout_ms: 900000 }", "connect_timeout_ms"),
        ("{ max_inflight: 65536 }", "max_inflight"),
        ("{ stream_stall_ms: 10 }", "stream_stall_ms"),
        ("{ plaintext: deny }", "plaintext"),
    ] {
        let deploy = parse(&format!(
            "providers: {{}}\nmodels: {{}}\nstore:\n  module: valkey\n  limits: {limits}\n"
        ));
        let refused = parse_min3(&deploy).err().expect(limits);
        assert!(
            refused
                .iter()
                .any(|r| r.contains("store.limits") && r.contains(key)),
            "{limits}: {refused:?}"
        );
    }
}

/// `timeout_ms` and `max_inflight` at the port call sites (§12.22): the call is cut at min(caller deadline,
/// start + timeout_ms) and the port is handed that capped deadline; the call past the cap waits for a permit,
/// spends its own deadline waiting and answers `Deadline` without reaching the port; the held call finishes and
/// frees its permit.
#[tokio::test]
async fn timeout_ms_and_max_inflight_at_port_call_sites() {
    let gate = PortGate::new(limits(50, 0));
    let started = Instant::now();
    let seen = Arc::new(Mutex::new(None));
    let seen_in = Arc::clone(&seen);
    let out: Result<(), PortError> = gate
        .call(cx(Duration::from_secs(60)), |cx| async move {
            *seen_in.lock().expect("lock") = Some(cx.deadline);
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok(())
        })
        .await;
    assert_eq!(out, Err(PortError::Call(CallError::Deadline)));
    assert!(started.elapsed() < Duration::from_secs(10));
    let given = seen.lock().expect("lock").expect("the port ran");
    assert!(given <= started + Duration::from_millis(100));

    let gate = Arc::new(PortGate::new(limits(5_000, 1)));
    let release = Arc::new(Notify::new());
    let (held_gate, held_release) = (Arc::clone(&gate), Arc::clone(&release));
    let first = tokio::spawn(async move {
        let out: Result<u8, PortError> = held_gate
            .call(cx(Duration::from_secs(30)), |_cx| async move {
                held_release.notified().await;
                Ok(1)
            })
            .await;
        out
    });
    for _ in 0..400 {
        if gate.in_flight() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(gate.in_flight(), 1);
    let ran = Arc::new(Mutex::new(false));
    let ran_in = Arc::clone(&ran);
    let second: Result<u8, PortError> = gate
        .call(cx(Duration::from_millis(100)), |_cx| async move {
            *ran_in.lock().expect("lock") = true;
            Ok(2)
        })
        .await;
    assert_eq!(second, Err(PortError::Call(CallError::Deadline)));
    assert!(
        !*ran.lock().expect("lock"),
        "the refused call never reached the port"
    );
    release.notify_one();
    assert_eq!(first.await.expect("join"), Ok(1));
    assert_eq!(gate.in_flight(), 0);
}

#[test]
#[ignore = "re-checked 2026-11-16: the connect cap is implemented (crates/busbar-core-connector/src/need.rs:600 and :678 budget(), min of the class default, limits.connect_timeout_ms and the call deadline, passed as Dial.timeout; config parse is the live limits_config_arms arm and kernel appbuild.rs:1434 carries the value into Caller.limits), but nothing tests it: the dial seam (NeedIo, Dial) is connector-internal and busbar-plugin-test has no busbar-core-connector dependency, and the case names store-valkey's black-holed dial (plugin repo image). Needs a connector unit test over a scripted NeedIo (OUTSTANDING row 2 harness for HostNeeds, none exists) or the valkey image (W2-SW-STORE)"]
fn connect_timeout_ms_at_the_dial() {
    todo!("owner: W1-C1A (C-LIMITS)")
}
