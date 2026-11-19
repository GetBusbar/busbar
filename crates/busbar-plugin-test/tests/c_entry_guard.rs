// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ENTRY-GUARD (ABI-MIN3-INTERFACE §14): `grow` and `log` inside resume, describe and close, all inline under
//! `entry::guard` (round 10). H0 is not an owner here (W1-H0 handoff): the guard needs A2's `HOST` and H1's pool
//! and watch words. The source check (no `spawn_blocking`/`on_plugin_thread` around an entry) is ci/hop's
//! `the_tree_has_no_hop` (W1-H0) and is not repeated.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-H1 (blocked: entry::guard, GetBusbar/busbar#272)"]
fn grow_to_16_mib_and_the_arena_is_zero_when_the_open_step_returns() {
    todo!("owner: W1-H1 (C-ENTRY-GUARD)")
}

/// W1-L2, over the loud probe (min3_second.rs `loud`): its describe answers a D_SCHEMA of 64 KiB and logs a line;
/// its `open` (round 31: the migrate entry is the open chain) resolves the password, logs a line holding it and
/// answers a 64 KiB canonical CONFIG beside INSTANCE; its `close` logs a line holding the password. The image is
/// admitted, the open succeeds and core keeps the whole CONFIG; each line reaches the log sink attributed (the
/// open and close lines to the configured name, the describe line to the kind: §10.7 gives describe no
/// instance) and scrubbed with the slot's set (custody registered the password before the open held it); and
/// describe, open and close each ran on this thread, the one that called `add`, `open_secret` and dropped the port.
///
/// The thread book (`fx::threads`) is process-wide and the loud image's describe is recorded by every case of
/// this binary that admits it (c_close_log too), so "describe ran on this one thread" holds only in a process
/// of its own: the walk runs in a fresh child process of this binary (`own_process`).
#[test]
fn describe_open_and_close_log_lines_are_attributed_and_scrubbed_and_64_kib_answers_pass() {
    own_process(
        "c_entry_guard::describe_open_and_close_log_lines_are_attributed_and_scrubbed_and_64_kib_answers_pass",
        describe_open_and_close_arm,
    );
}

/// Names the one test a child process of this binary runs (the child runs `arm` itself).
const OWN_PROCESS: &str = "BUSBAR_C_ENTRY_GUARD_OWN_PROCESS";

/// Runs `arm` in a fresh process of this test binary that runs only the test `name`. The parent passes only
/// when that child ran exactly this one test and it passed.
fn own_process(name: &str, arm: impl FnOnce()) {
    if std::env::var_os(OWN_PROCESS).is_some_and(|child| child == name) {
        arm();
        return;
    }
    let out = std::process::Command::new(std::env::current_exe().expect("this test binary"))
        .args(["--exact", name, "--test-threads=1", "--nocapture"])
        .env(OWN_PROCESS, name)
        .output()
        .expect("run this test in its own process");
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        out.status.success() && stdout.contains("test result: ok. 1 passed; 0 failed"),
        "{name} in its own process: {}\n{stdout}\n{stderr}",
        out.status
    );
}

fn describe_open_and_close_arm() {
    use busbar_contract::json::{self as facade, JsonValueTrait};
    use busbar_plugin_abi::host::level;
    use busbar_plugin_abi::types::KindCode;
    use busbar_plugin_test::fake_needs::FakeNeeds;

    use crate::min3_second::{self as fx, CLOSE_LINE, DESCRIBE_LINE, OPEN_LINE};

    const SECRET: &str = "pw-entry-guard-2290";
    let me = std::thread::current().id();
    let mut needs = FakeNeeds::new();
    needs.secret("/password", SECRET.as_bytes());
    let h = fx::scrubbed(fx::loud::PLUGIN.plugin(), needs);

    let schema = h
        .registry()
        .described(fx::LOUD)
        .and_then(|d| d.schema)
        .expect("the loud image was admitted with its schema");
    assert!(schema.len() > fx::BIG, "a {} byte D_SCHEMA", schema.len());
    let described: Vec<_> = h
        .logs()
        .into_iter()
        .filter(|line| line.message == DESCRIBE_LINE)
        .collect();
    assert_eq!(
        described.len(),
        1,
        "describe logged one line: {described:?}"
    );
    assert_eq!(described[0].kind, KindCode::Secret as u32);
    assert_eq!(described[0].level, level::WARN);

    let config = format!(
        r#"{{"tag":"guard-a","password":{{"env":"OPERATOR_REFERENCE"}},"open_log":true,"close_log":true,"settle_pad":{}}}"#,
        fx::BIG
    );
    let port = h
        .open_secret("guard-a", config.as_bytes())
        .unwrap_or_else(|e| panic!("the open answering 64 KiB: {e:?}"));
    let settled = h
        .settled("guard-a")
        .expect("core kept the canonical CONFIG");
    let bag = facade::parse_typed(&settled.config_json).expect("JSON");
    assert_eq!(
        bag.get("pad").and_then(|p| p.as_str()).map(str::len),
        Some(fx::BIG),
        "the whole 64 KiB CONFIG came through"
    );
    drop(port);

    for (prefix, entry) in [(OPEN_LINE, "open"), (CLOSE_LINE, "close")] {
        let lines: Vec<_> = h
            .logs()
            .into_iter()
            .filter(|line| line.message.starts_with(prefix))
            .collect();
        assert_eq!(lines.len(), 1, "{entry} logged one line: {lines:?}");
        assert_eq!(
            lines[0].instance, "guard-a",
            "the {entry} line is attributed"
        );
        assert_eq!(lines[0].kind, KindCode::Secret as u32);
        assert!(
            !lines[0].message.contains(SECRET) && lines[0].message.contains("***"),
            "the {entry} line is scrubbed: {}",
            lines[0].message
        );
    }
    assert_eq!(
        fx::threads("describe", "describe"),
        vec![me],
        "describe inline"
    );
    assert_eq!(fx::threads("guard-a", "open"), vec![me], "open inline");
    assert_eq!(fx::threads("guard-a", "close"), vec![me], "close inline");
}
