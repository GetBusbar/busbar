// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SCRUB (ABI-MIN3-INTERFACE §14 rounds 4, 17, 18): a resolved secret, its encodings, URL userinfo and a
//! `?token=` parameter never survive. The scrub-set arm is W1-H0's (merged); the log, audit and `PortError` arm
//! waits for W1-K8D; the template arm (K2 + H0) is W1-K2's, through custody.
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

/// The template arm (§12.2 step 5, §12.16; K2 + H0), through custody onto the instance's scrub set: the set its
/// log sink, its adapters' FAIL text and its audit rows scrub through. The sink legs (log line, audit row,
/// STREAM_LOGS) of the same set are `none_survives_in_logs_audit_rows_or_port_error_text` (W1-K8D).
#[tokio::test]
async fn template_fills_and_both_rotation_generations_are_masked_end_to_end() {
    use std::sync::Arc;

    use busbar_kernel::custody::{CustodyEvent, SecretCustody};
    use busbar_plugin_abi::host_side::scrub::fail_text;

    use crate::c_scrub_hit::fixture::{caller, source, template, Fixture, Vault};

    const FILLS: [&str; 3] = ["abc-fill-v1-7Kq2", "abc-fill-v2-9Wm4", "abc-fill-v3-3Tz8"];

    fn hidden(scrub: &Scrub, value: &str) -> bool {
        let lines = [
            scrub.text(&format!("token {value} rejected")).into_owned(),
            fail_text(scrub, &format!("upstream said {value}")).into_owned(),
        ];
        lines
            .iter()
            .all(|line| !line.contains(value) && line.contains("***"))
    }

    let fx = Fixture::new();
    let env = Vault::new(&[("TOKEN", FILLS[0]), ("SHORT", "ab")], Some(60));
    fx.source("env", 900, Arc::clone(&env));
    let scrub = fx.instance(1);
    fx.bind(1, 1, template("Bearer ${TOKEN}"));
    let rendered = fx.custody.resolve(&caller(1), 1).await.expect("renders");
    assert_eq!(
        rendered.as_slice(),
        format!("Bearer {}", FILLS[0]).as_bytes()
    );
    assert!(hidden(&scrub, FILLS[0]), "a fill alone is masked");
    for form in needles(FILLS[0].as_bytes()) {
        let form = core::str::from_utf8(&form).expect("every encoding is ASCII");
        let logged = scrub.text(&format!("plugin logged {form}")).into_owned();
        assert!(!logged.contains(form), "{form} survived: {logged}");
    }

    // A rotation keeps the value it replaced masked (a chain that resolved v1 fails after the renewal; v1 held in
    // instance state since `open` is logged after it); a second rotation drops v1 and keeps v2 and v3.
    env.set("TOKEN", FILLS[1]);
    fx.advance(61);
    fx.custody.resolve(&caller(1), 1).await.expect("v2");
    assert!(hidden(&scrub, FILLS[0]) && hidden(&scrub, FILLS[1]));
    env.set("TOKEN", FILLS[2]);
    fx.advance(61);
    fx.custody.resolve(&caller(1), 1).await.expect("v3");
    assert!(
        !hidden(&scrub, FILLS[0]),
        "two changes old is unmasked (§16.151)"
    );
    assert!(hidden(&scrub, FILLS[1]) && hidden(&scrub, FILLS[2]));

    // A reopened instance registers only its own resolves.
    let reopened = fx.instance(2);
    fx.bind(2, 1, template("Bearer ${TOKEN}"));
    fx.custody.resolve(&caller(2), 1).await.expect("reopened");
    assert!(hidden(&reopened, FILLS[2]));
    assert!(!hidden(&reopened, FILLS[1]) && !hidden(&reopened, FILLS[0]));

    // The same arms for a plain reference renewed under F_LEASE_S.
    let vault = Vault::new(&[("db", FILLS[0])], Some(60));
    fx.source("vault", 901, Arc::clone(&vault));
    let plain = fx.instance(3);
    fx.bind(3, 1, source("vault", "db"));
    fx.custody.resolve(&caller(3), 1).await.expect("v1");
    vault.set("db", FILLS[1]);
    fx.advance(61);
    fx.custody.resolve(&caller(3), 1).await.expect("v2");
    assert!(hidden(&plain, FILLS[0]) && hidden(&plain, FILLS[1]));
    vault.set("db", FILLS[2]);
    fx.advance(61);
    fx.custody.resolve(&caller(3), 1).await.expect("v3");
    assert!(!hidden(&plain, FILLS[0]));
    assert!(hidden(&plain, FILLS[1]) && hidden(&plain, FILLS[2]));

    // A fill shorter than MIN_NEEDLE is audited.
    fx.instance(4);
    fx.bind(4, 1, template("key ${SHORT}"));
    fx.custody.resolve(&caller(4), 1).await.expect("renders");
    assert_eq!(fx.audited(4, CustodyEvent::TooShortToScrub), 1);
    assert_eq!(fx.audited(1, CustodyEvent::TooShortToScrub), 0);
}
