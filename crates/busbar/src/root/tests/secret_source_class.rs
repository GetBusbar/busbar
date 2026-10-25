// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SCAN'S FIXED-CLASS HALF AND ITS KEPT RED ARM. The scan beside this file
//! proves a failing secret's source never reaches a door plane's caller; this file proves two more
//! things about the same renders:
//! * the refusal is a FIXED CLASS: two different sources failing (an unset variable, a missing file)
//!   hand the caller the same status and the same body, so nothing in it depends on which source
//!   failed or how;
//! * the scan SEES a leak: the operator's text spliced into a real door's caller render (what the
//!   retired `SetupRefusal::client_message` redaction stood in front of until #511) is found by the
//!   same detector and fails the same assertion every door's cell makes. A scan that could not fail
//!   would prove nothing; this arm stays in the tree so it cannot quietly go blind.

use axum::http::{HeaderMap, StatusCode};
use busbar_contract::secret_ref::SecretRef;

use super::{
    assert_clean, call, missing, program_section, refused_naming_its_source, rendered, source_in,
    unset,
};
use crate::root::door_steps::tests::tool_door::try_rig_tools;
use crate::root::serve::planes_tests::{Published, PUBLISHING};

/// One caller-facing answer: its status, its headers and its body.
type Answer = (StatusCode, HeaderMap, Vec<u8>);

/// The caller's answer to a call on a member program whose `env` reference is `secret`, which does
/// not resolve, served by the tool door as `instance`.
async fn refused_call(instance: &'static str, secret: &SecretRef) -> Answer {
    let _published = Published(instance);
    let rig = try_rig_tools(instance, 0, program_section(secret))
        .unwrap_or_else(|e| panic!("{instance}: a member's env is not resolved at compose: {e}"));
    call(&rig).await
}

/// THE REFUSAL IS ONE FIXED CLASS: an unset variable and a missing file, each the `env` reference of
/// a member program, reach the caller as the same status and the same body, both free of either
/// source.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_failing_sources_reach_the_caller_as_one_fixed_refusal() {
    let _one = PUBLISHING.lock().await;
    let cases = [
        ("tools-class-env", SecretRef::env(unset("TOOLS_CLASS_ENV"))),
        (
            "tools-class-file",
            SecretRef::file(missing("tools-class-file")),
        ),
    ];
    let mut answers = Vec::new();
    for (instance, secret) in &cases {
        refused_naming_its_source(secret);
        let (status, headers, body) = refused_call(instance, secret).await;
        for (_, other) in &cases {
            assert_clean(instance, status, &headers, &body, other);
        }
        answers.push((status, body));
    }
    let (first, second) = (&answers[0], &answers[1]);
    assert_eq!(
        first.0, second.0,
        "the refusal's status does not depend on the source that failed"
    );
    assert_eq!(
        String::from_utf8_lossy(&first.1),
        String::from_utf8_lossy(&second.1),
        "the refusal's body does not depend on the source that failed"
    );
}

/// THE KEPT RED ARM: the scan catches a leak. A real tool-door caller render for a reference that
/// does not resolve is first proven clean; the operator's text for the same reference is then
/// spliced into its body in place of the connector's fixed words (exactly the leak #511's redaction
/// stood in front of), and the same detector names the source and the same assertion fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_scan_catches_a_source_spliced_into_a_real_door_render() {
    let _one = PUBLISHING.lock().await;
    let fixed = busbar_contract::conn::ConnError::Refused.text();
    let cases = [
        ("tools-red-env", SecretRef::env(unset("TOOLS_RED_ENV"))),
        ("tools-red-file", SecretRef::file(missing("tools-red-file"))),
    ];
    for (instance, secret) in &cases {
        let operator = refused_naming_its_source(secret);
        let (status, headers, body) = refused_call(instance, secret).await;
        assert_clean(instance, status, &headers, &body, secret);
        let text = String::from_utf8_lossy(&body).into_owned();
        let leaked = if text.contains(fixed) {
            text.replace(fixed, &operator)
        } else {
            format!("{text}{operator}")
        };
        let found = source_in(&rendered(status, &headers, leaked.as_bytes()), secret);
        assert!(
            !found.is_empty(),
            "{instance}: the scan must find the spliced source in:\n{leaked}"
        );
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_clean(instance, status, &headers, leaked.as_bytes(), secret);
        }));
        assert!(
            caught.is_err(),
            "{instance}: the cell every door runs must fail on a render that carries {found:?}"
        );
    }
}
