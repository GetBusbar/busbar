// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-STASH-REOPEN (ABI-MIN3-INTERFACE §14): A stashed ChainBytes across FAULT, reopen and reconfigure onto the
//! same slot: every later `with` FAULTs StaleHandle.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_plugin_abi::fail::CallError;
use busbar_plugin_abi::host_side::caller::CallStack;
use busbar_plugin_abi::types::KindCode;
use busbar_plugin_loader::instance::{OpenedPort, Reconfigured};
use busbar_plugin_test::fake_needs::FakeNeeds;
use busbar_plugin_test::suites::harness::Harness;
use busbar_ports::secret::SecretPort;
use busbar_ports::{CallCx, PortError};

use crate::min3_second as fx;

const NAME: &str = "stash";
const CONFIG: &[u8] = br#"{"tag":"stash","stash":true}"#;

fn cx(id: u64) -> CallCx {
    CallCx {
        deadline: Instant::now() + Duration::from_secs(10),
        request_id: id,
        stack: CallStack::default(),
        mono_ns: 0,
    }
}

/// A fresh instance serves (`db` answers), then reads the stash: FAULT, and the instance is quarantined.
/// The host sees the stale read as the plugin's caught panic (`ChainBytes::with` panics "StaleHandle" outside
/// its chain), so the FAULT's reason is the panic's; the arm holds that it is a FAULT, as C-STALE does.
fn serves_then_faults(h: &Harness, port: &Arc<dyn SecretPort>, id: u64, when: &str) {
    let fresh = h.block_on(port.resolve(cx(id), br#"{"name":"db"}"#)).ok();
    assert_eq!(
        fresh.map(|a| a.value.as_slice().to_vec()).as_deref(),
        Some(&b"db"[..]),
        "{when}: the instance serves before the stale read"
    );
    let stale = h
        .block_on(port.resolve(cx(id + 1), br#"{"name":"stale"}"#))
        .err();
    assert!(
        matches!(stale, Some(PortError::Call(CallError::Fault(_)))),
        "{when}: the stashed ChainBytes read FAULTs: {stale:?}"
    );
    let after = h
        .block_on(port.resolve(cx(id + 2), br#"{"name":"db"}"#))
        .err();
    assert_eq!(
        after,
        Some(PortError::Call(CallError::Quarantined)),
        "{when}: the faulted instance is quarantined"
    );
}

/// The first `open` stashes its config `ChainBytes` in a `static Mutex<Option<ChainBytes>>`. The read FAULTs on
/// that instance; the instance is dropped (its slot goes back to the table) and the same configured instance is
/// reopened onto it again and again, then reconfigured: on every one of them the stashed read FAULTs.
#[test]
fn a_stash_across_reopen_and_reconfigure_faults_stale_handle() {
    let h = Harness::admit(fx::probe::PLUGIN.plugin(), FakeNeeds::new())
        .unwrap_or_else(|r| panic!("{r:?}"));
    let port = h
        .open_secret(NAME, CONFIG)
        .unwrap_or_else(|e| panic!("{e:?}"));
    serves_then_faults(&h, &port, 10, "the stashing instance");
    drop(port);

    for round in 1..=4u64 {
        let port = h
            .open_secret(NAME, CONFIG)
            .unwrap_or_else(|e| panic!("reopen {round}: {e:?}"));
        serves_then_faults(&h, &port, 10 * (round + 1), "a reopened instance");
        drop(port);
    }

    let port = h
        .open_secret(NAME, CONFIG)
        .unwrap_or_else(|e| panic!("{e:?}"));
    let reconfigured = h
        .block_on(
            h.registry()
                .reconfigure(KindCode::Secret, NAME, br#"{"note":"pushed"}"#, 1),
        )
        .unwrap_or_else(|e| panic!("reconfigure: {e:?}"));
    let Reconfigured::Opened(OpenedPort::Secret(next)) = reconfigured else {
        panic!("reconfigure opens a new secret instance");
    };
    drop(port);
    serves_then_faults(&h, &next, 100, "the reconfigured instance");
    drop(next);

    assert_eq!(
        fx::count("stash", "built"),
        7,
        "every open built its instance"
    );
    assert_eq!(fx::count("stash", "close"), 7, "every instance closed");
}
