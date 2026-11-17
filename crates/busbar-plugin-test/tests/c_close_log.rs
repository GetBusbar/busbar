// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-CLOSE-LOG (ABI-MIN3-INTERFACE §14): A secret logged in `close` is attributed to the closing instance and
//! scrubbed; its slot is not reused until the close returns.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use std::sync::mpsc;
use std::time::Duration;

use busbar_plugin_abi::host::level;
use busbar_plugin_abi::types::KindCode;
use busbar_plugin_test::fake_needs::FakeNeeds;

use crate::min3_second::{self as fx, CLOSE_LINE};

/// The value custody hands every instance here for its `password`.
const SECRET: &str = "pw-close-log-4417";

fn config(tag: &str) -> Vec<u8> {
    format!(r#"{{"tag":"{tag}","password":{{"env":"OPERATOR_REFERENCE"}},"close_log":true}}"#)
        .into_bytes()
}

/// The loud probe's `close` logs [`CLOSE_LINE`] and the password its `open` resolved, through the `Host` that open
/// was handed, then runs a hook that opens a second instance on another thread and waits for it. The close runs
/// inline on this thread (`Drop for Instance`), so the line reaches the log sink under the closing instance's
/// slot: attributed to its configured name and scrubbed with its own set (custody registered the password there
/// before the open held it). The instance opened during the close gets another slot; the closing slot comes free
/// only when the close has returned, and the next open takes it.
#[test]
fn a_close_log_line_is_attributed_and_scrubbed_and_the_slot_waits() {
    let mut needs = FakeNeeds::new();
    needs.secret("/password", SECRET.as_bytes());
    let (h, slots) = fx::scrubbed(fx::loud::PLUGIN.plugin(), needs);
    let me = std::thread::current().id();

    let closing = h
        .open_secret("close-a", &config("close-a"))
        .unwrap_or_else(|e| panic!("{e:?}"));
    let slot_a = slots.lock().expect("slots")[0];

    let (go, go_rx) = mpsc::channel::<()>();
    let (opened_tx, opened) = mpsc::channel::<()>();
    let harness = &*h;
    let during = std::thread::scope(|s| {
        let opener = s.spawn(move || {
            go_rx.recv_timeout(Duration::from_secs(10)).ok()?;
            let bag = config("close-b");
            let spec = harness.spec("close-b", &bag);
            let port = harness.block_on(harness.registry().open_secret(
                &spec,
                &harness.needs_arc(),
                &harness.refs_arc(),
            ));
            let _ = opened_tx.send(());
            Some(port)
        });
        fx::on_close(
            "close-a",
            Box::new(move || {
                let _ = go.send(());
                let _ = opened.recv_timeout(Duration::from_secs(10));
            }),
        );
        drop(closing);
        opener.join().expect("the opener thread")
    });
    let during = during
        .expect("the close ran its hook")
        .unwrap_or_else(|e| panic!("the open during the close: {e:?}"));
    assert_eq!(fx::threads("close-a", "close"), vec![me], "closed inline");

    let lines: Vec<_> = h
        .logs()
        .into_iter()
        .filter(|line| line.message.starts_with(CLOSE_LINE))
        .collect();
    assert_eq!(lines.len(), 1, "the close logged one line: {lines:?}");
    let line = &lines[0];
    assert_eq!(
        line.instance, "close-a",
        "attributed to the closing instance"
    );
    assert_eq!(line.kind, KindCode::Secret as u32);
    assert_eq!(line.level, level::WARN);
    assert!(
        !line.message.contains(SECRET),
        "scrubbed with the closing instance's set: {}",
        line.message
    );
    assert!(line.message.contains("***"), "{}", line.message);

    let after = h
        .open_secret("close-c", &config("close-c"))
        .unwrap_or_else(|e| panic!("{e:?}"));
    let seen = slots.lock().expect("slots").clone();
    assert_eq!(seen.len(), 3, "one SECRET per open: {seen:?}");
    assert_ne!(
        seen[1], slot_a,
        "the instance opened during the close got another slot"
    );
    assert_eq!(
        seen[2], slot_a,
        "the closing slot came free once the close had returned"
    );
    drop((during, after));
}
