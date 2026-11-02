// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::hooks::TransformOutcome;

use super::{failed_rewrite, REQUIRED_HOOK_UNAVAILABLE_MESSAGE, REQUIRED_HOOK_UNAVAILABLE_STATUS};
use crate::config::PolicyOnError;

#[test]
fn a_hook_that_panics_is_the_seams_own_failed_verdict() {
    let failure = "the native hook crossing answered Fault";
    match failed_rewrite(&PolicyOnError::Weighted, failure.to_string()) {
        TransformOutcome::Failed { message } => assert_eq!(message, failure),
        other => panic!("an optional failed hook keeps the original body: {other:?}"),
    }
    match failed_rewrite(&PolicyOnError::Reject, failure.to_string()) {
        TransformOutcome::Reject { status, message } => {
            assert_eq!(status, REQUIRED_HOOK_UNAVAILABLE_STATUS);
            assert_eq!(status, 503);
            assert_eq!(message, REQUIRED_HOOK_UNAVAILABLE_MESSAGE);
            assert!(
                !message.contains(failure),
                "the refusal carries no native failure detail"
            );
        }
        other => panic!("a required failed hook refuses before dispatch: {other:?}"),
    }
}

#[test]
fn a_first_fallback_preserves_the_failed_rewrite_verdict() {
    let failure = "the hook was unavailable";
    match failed_rewrite(&PolicyOnError::First, failure.to_string()) {
        TransformOutcome::Failed { message } => assert_eq!(message, failure),
        other => panic!("the first fallback keeps the failed verdict: {other:?}"),
    }
}
