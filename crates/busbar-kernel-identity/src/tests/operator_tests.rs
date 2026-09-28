// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The operator credential: both carriers put to its module on every call, the answers folded.

use crate::operator::OperatorCredential;
use busbar_contract::auth::{AuthModule, AuthVerdict, Principal};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Counts its calls; identifies `ok`, refuses `bad`, defers on anything else.
struct Counting(Arc<AtomicUsize>);

impl AuthModule for Counting {
    fn name(&self) -> &'static str {
        "counting"
    }
    fn authenticate(&self, candidate: Option<&str>) -> AuthVerdict {
        self.0.fetch_add(1, Ordering::Relaxed);
        match candidate {
            Some("ok") => AuthVerdict::Identify(Principal::from_id("op")),
            Some("bad") => AuthVerdict::Reject,
            _ => AuthVerdict::Pass,
        }
    }
}

fn kind(v: Option<AuthVerdict>) -> &'static str {
    match v {
        None => "unanswered",
        Some(AuthVerdict::Identify(_)) => "identify",
        Some(AuthVerdict::Reject) => "reject",
        Some(AuthVerdict::Pass) => "pass",
    }
}

#[test]
fn both_carriers_are_judged_and_folded() {
    for (bearer, header, want) in [
        (Some("ok"), None, "identify"),
        (None, Some("ok"), "identify"),
        (Some("bad"), Some("ok"), "identify"),
        (Some("ok"), Some("bad"), "identify"),
        (Some("bad"), None, "reject"),
        (Some("x.y.z"), Some("bad"), "reject"),
        (Some("x.y.z"), None, "pass"),
        (None, None, "pass"),
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let credential = OperatorCredential::Module(Box::new(Counting(calls.clone())));
        assert_eq!(
            kind(credential.judge(bearer, header)),
            want,
            "bearer={bearer:?} header={header:?}"
        );
        assert_eq!(
            calls.load(Ordering::Relaxed),
            2,
            "both carriers are put to the module on every call"
        );
    }
}

#[test]
fn no_row_is_unanswered_and_no_token_defers() {
    assert_eq!(
        kind(OperatorCredential::Unanswered.judge(Some("ok"), Some("ok"))),
        "unanswered"
    );
    assert_eq!(
        kind(OperatorCredential::Unset.judge(Some("ok"), None)),
        "pass"
    );
}
