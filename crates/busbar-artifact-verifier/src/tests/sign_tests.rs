// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests of items the verifier keeps private or test-gated; moved unchanged from the loader.
use super::*;

#[test]
fn rejected_display_carries_the_reason() {
    let r = Rejected::new(
        RejectKind::Unsigned,
        "manifest carries no signature".to_string(),
    );
    assert_eq!(
        r.to_string(),
        "plugin rejected: manifest carries no signature"
    );
}

fn trusted_first_party() -> Verdict {
    Verdict::Trusted {
        publisher: FIRST_PARTY_PUBLISHER.to_string(),
        first_party: true,
    }
}

fn trusted_third_party() -> Verdict {
    Verdict::Trusted {
        publisher: "acme".to_string(),
        first_party: false,
    }
}

fn allowed_unsigned() -> Verdict {
    Verdict::Allowed {
        reason: "dev opt-in".to_string(),
        allow: AllowReason::Untrusted,
    }
}

#[test]
fn restart_override_to_true_is_always_honored() {
    for verdict in [
        trusted_first_party(),
        trusted_third_party(),
        allowed_unsigned(),
    ] {
        assert!(effective_restart_required("hook", Some(true), &verdict));
        assert!(effective_restart_required("auth", Some(true), &verdict));
    }
}

#[test]
fn restart_override_to_false_requires_trusted_first_party() {
    assert!(
        !effective_restart_required("store", Some(false), &trusted_first_party()),
        "trusted first-party clears the gate: the false override is honored"
    );
    assert!(
        effective_restart_required("store", Some(false), &trusted_third_party()),
        "trusted THIRD-PARTY does not clear the gate: kind default (true) is enforced"
    );
    assert!(
        effective_restart_required("secret", Some(false), &allowed_unsigned()),
        "an unsigned/allowed artifact does not clear the gate: kind default enforced"
    );
}

#[test]
fn restart_no_override_uses_kind_default_regardless_of_trust() {
    assert!(effective_restart_required(
        "store",
        None,
        &allowed_unsigned()
    ));
    assert!(!effective_restart_required(
        "hook",
        None,
        &allowed_unsigned()
    ));
}

#[test]
fn restart_override_to_false_against_hot_default_is_a_no_op_honored_unconditionally() {
    assert!(!effective_restart_required(
        "hook",
        Some(false),
        &allowed_unsigned()
    ));
}
