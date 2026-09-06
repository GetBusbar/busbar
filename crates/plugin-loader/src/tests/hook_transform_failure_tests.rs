// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A `prompt: rw` gate that COULD NOT ANSWER is a failure, not an abstain.
//!
//! This is the rewrite-path twin of the distinction `HookReply::Failed` already carries on the
//! decide path. `TransformOutcome` had no failure arm, so a rewrite hook whose own dependency was
//! down — a compressor's model endpoint, a PII screen's classifier — produced the same
//! `TransformOutcome::Abstain` as a hook that looked at the body and had nothing to change. The
//! request then proceeded with its ORIGINAL body and the operator's `on_error` chain, whose terminal
//! can be `reject`, never fired. A gate deliberately configured to fail CLOSED failed OPEN, silently
//! and indistinguishably from working correctly.
//!
//! These drive the real cdylib over the real dlopen seam, so the assertion covers the SDK's
//! `transform_result` dispatch, the wire reply, and the loader's mapping — the whole path the arm
//! had to be threaded through.

use super::*;
use busbar_api::TransformOutcome;

/// The fixture reports it could not answer. The outcome must be `Failed` carrying the hook's own
/// message, NOT an abstain.
#[tokio::test]
async fn a_failing_rewrite_hook_is_a_failure_not_an_abstain() {
    let Some(_) = tests::hook_plugin_path() else {
        return;
    };
    let policy = tests::load(r#"{"fail_transform": "classifier unreachable"}"#);

    let outcome = policy
        .transform(&tests::req_with_prompt("screen me"), Duration::from_secs(5))
        .await;

    match outcome {
        TransformOutcome::Failed { message } => assert!(
            message.contains("classifier unreachable"),
            "the hook's own message must reach the operator: {message}"
        ),
        other => panic!(
            "a rewrite hook that could not answer must be Failed, not {other:?} — an abstain here \
             forwards the request the gate exists to screen"
        ),
    }
}

/// The control: a hook that genuinely has nothing to change still ABSTAINS. The new arm must not
/// turn every quiet rewrite hook into a failure, which would fail-CLOSE requests nothing objected to.
#[tokio::test]
async fn a_quiet_rewrite_hook_still_abstains() {
    let Some(_) = tests::hook_plugin_path() else {
        return;
    };
    let policy = tests::load(r#"{"raw_transform_reply": {}}"#);

    let outcome = policy
        .transform(
            &tests::req_with_prompt("nothing to do"),
            Duration::from_secs(5),
        )
        .await;

    assert_eq!(
        outcome,
        TransformOutcome::Abstain,
        "a hook with no changes to make must still abstain"
    );
}
