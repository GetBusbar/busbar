// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-BLIND (ABI-MIN3-INTERFACE §14): No other plugin's identity reaches a plugin, and a stamp name appears only
//! inside `plugin_diag` (round 34). The fixtures fail and log with declared ERROR numbers.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use std::time::{Duration, Instant};

use busbar_plugin_abi::host_side::caller::CallStack;
use busbar_plugin_test::fake_needs::FakeNeeds;
use busbar_plugin_test::suites::harness::Harness;
use busbar_ports::{CallCx, PortError};

use crate::min3_second::{self as fx, ALIAS, ALIAS_WORDS, PROBE, PROBE_FORMER};

fn cx(id: u64) -> CallCx {
    CallCx {
        deadline: Instant::now() + Duration::from_secs(10),
        request_id: id,
        stack: CallStack::default(),
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Two images with second identities and former names in one registry, each opened (one by a former-name
/// `module:` word), checked, handed references, a SECRET result, a declared-number log line and a declared-number
/// failure: no input either received (bound config in `check` and `open`, reference, Need result) holds any
/// loaded image's stamp name or former name.
#[test]
fn no_stamp_name_reaches_a_config_view_or_need_result() {
    let mut needs = FakeNeeds::new();
    needs.secret("/password", b"pw-blind-5531");
    let h = Harness::admit_all(
        &[fx::probe::PLUGIN.plugin(), fx::alias::PLUGIN.plugin()],
        needs,
    )
    .unwrap_or_else(|r| panic!("both images are admitted: {r:?}"));
    let words = [ALIAS, ALIAS_WORDS[0], ALIAS_WORDS[1], PROBE, PROBE_FORMER];

    let opened = [
        (
            PROBE,
            "blind-b",
            br#"{"tag":"blind-b","password":"pw-blind-5531"}"#.as_slice(),
        ),
        (
            ALIAS_WORDS[0],
            "blind-a",
            br#"{"tag":"blind-a"}"#.as_slice(),
        ),
    ];
    for (at, (module, tag, config)) in opened.into_iter().enumerate() {
        let check = h.spec_for(module, tag, config);
        h.block_on(h.registry().check(&check))
            .unwrap_or_else(|e| panic!("{tag} checks: {e:?}"));
        let port = h
            .block_on(
                h.registry()
                    .open_secret(&check, &h.needs_arc(), &h.refs_arc()),
            )
            .unwrap_or_else(|e| panic!("{tag} opens: {e:?}"));
        let base = at as u64 * 10;
        let references: [&[u8]; 3] = [
            br#"{"name":"db"}"#,
            br#"{"name":"log"}"#,
            br#"{"name":"need"}"#,
        ];
        for (n, reference) in references.into_iter().enumerate() {
            let answer = h.block_on(port.resolve(cx(base + n as u64), reference));
            assert!(
                answer.is_ok(),
                "{tag} resolves {:?}",
                String::from_utf8_lossy(reference)
            );
        }
        let failed = h
            .block_on(port.resolve(cx(base + 9), br#"{"name":"fail"}"#))
            .err();
        // Only the probe image declares D_ERRORS: the alias image's number resolves to no code.
        let declared = (module == PROBE).then_some(fx::OPEN_ERROR);
        assert!(
            matches!(&failed, Some(PortError::Failed { error, .. }) if error.map(|c| c.number) == declared),
            "{tag}: {failed:?}"
        );
    }

    for tag in ["blind-a", "blind-b"] {
        let inputs = fx::inputs(tag);
        for what in [
            "check.config",
            "open.config",
            "resolve.reference",
            "resolve.need",
        ] {
            assert!(
                inputs.iter().any(|(w, _)| *w == what),
                "{tag} received a {what}: {inputs:?}"
            );
        }
        for (what, bytes) in &inputs {
            for word in words {
                assert!(
                    !contains(bytes, word.as_bytes()),
                    "{tag}'s {what} holds the stamp or former name {word}: {:?}",
                    String::from_utf8_lossy(bytes)
                );
            }
        }
    }
    let secret = fx::inputs("blind-b");
    assert!(
        secret
            .iter()
            .any(|(what, bytes)| *what == "open.need" && bytes.as_slice() == b"pw-blind-5531"),
        "the probe's open read its password through SECRET"
    );
    assert!(
        secret
            .iter()
            .filter(|(what, _)| *what == "open.config")
            .all(|(_, bytes)| !contains(bytes, b"pw-blind-5531")),
        "the bound config carries the handle, not the value"
    );
    let logged = h.logs();
    assert!(
        logged
            .iter()
            .any(|line| line.code == format!("BUSBAR-{PROBE}-{:04}", fx::LOG_ERROR)),
        "the declared log line carries its code: {logged:?}"
    );
}

#[test]
#[ignore = "owner: W1-K8C; blocked (re-checked on dev 2026-11-16): the kernel export pump, DiskSink and stream routing are not on dev (OUTSTANDING row 4)"]
fn no_stamp_name_reaches_a_deliver_batch_or_render_snapshot() {
    todo!("owner: W1-K8C (C-BLIND)")
}

/// Round 34: a stamp name appears only inside `plugin_diag` (the code core wrote beside the text); the plugin's
/// raw text member carries no stamp name, and a plugin that writes a `BUSBAR-...` itself is not rewritten.
#[test]
fn a_stamp_name_appears_only_inside_plugin_diag() {
    use busbar_kernel::plugin_text::PluginText;
    use busbar_ports::PluginCode;

    let code = PluginCode {
        plugin: "acme-auth",
        number: 42,
    };
    let shown = PluginText::new(Some(code), "the directory refused the bind");
    assert!(!shown.text().contains("acme-auth"));
    assert_eq!(
        shown.code.map(|c| c.to_string()).as_deref(),
        Some("BUSBAR-acme-auth-0042")
    );
    assert_eq!(
        shown.to_string(),
        "BUSBAR-acme-auth-0042: the directory refused the bind"
    );
    let own = PluginText::new(None, "BUSBAR-other-0001 is mine");
    assert_eq!(own.text(), "BUSBAR-other-0001 is mine");
    assert_eq!(own.to_string(), own.text());
}
