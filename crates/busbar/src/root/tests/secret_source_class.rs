// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use axum::http::{HeaderMap, StatusCode};
use busbar_contract::secret_ref::SecretRef;

use super::{
    assert_clean, call, missing, program_section, refused_naming_its_source, rendered, source_in,
    unset,
};
use crate::root::door_steps::tests::tool_door::try_rig_tools;
use crate::root::serve::planes_tests::PUBLISHING;

type Answer = (StatusCode, HeaderMap, Vec<u8>);

async fn refused_call(instance: &'static str, secret: &SecretRef) -> Answer {
    let rig = try_rig_tools(instance, 0, program_section(secret))
        .unwrap_or_else(|e| panic!("{instance}: a member's env is not resolved at compose: {e}"));
    call(&rig).await
}

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
