// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/plane_host/trust.rs`.

use super::*;
use crate::plane_host::{recover, with_dispatch_scope, DispatchScope, HostState};
use busbar_plugin::hot::host::{HostCtx, PlaneHostVtable};
use busbar_plugin::hot::Key;

/// Drive the trust slots through the REAL recovery path over a live `App` from the test-support
/// builder, exactly as the sibling `plane_host` tests do.
fn with_test_state<R>(f: impl FnOnce(HostCtx, &PlaneHostVtable, &DispatchScope) -> R) -> R {
    let app = crate::test_support::TestApp::new().build();
    with_dispatch_scope(&app, |host, vt| {
        // SAFETY: `host` is the live HostState minted by `with_dispatch_scope`.
        let state: &HostState = unsafe { recover(host) };
        let scope = state.scope;
        f(host, vt, scope)
    })
}

/// Build a borrowed `Key` over `bytes` for the duration of `f`.
fn with_key<R>(scope: u32, bytes: &[u8], f: impl FnOnce(*const Key) -> R) -> R {
    let key = Key {
        size: core::mem::size_of::<Key>() as u32,
        version: POD_VERSION,
        _reserved: 0,
        scope,
        _reserved2: 0,
        key_ptr: bytes.as_ptr(),
        key_len: bytes.len(),
        drift_state: 0,
    };
    f(&key as *const Key)
}

fn read_lookup(
    host: HostCtx,
    vt: &PlaneHostVtable,
    key: *const Key,
) -> (StatusClass, VerifyVerdict) {
    let mut out = MaybeUninit::<VerifyVerdict>::uninit();
    let status = (vt.verify_lookup.unwrap())(host, key, core::ptr::from_mut(&mut out));
    // SAFETY: on `Ok` the out-slot is initialized; the tests only read it on `Ok`.
    let verdict = if status == StatusClass::Ok {
        unsafe { out.assume_init() }
    } else {
        VerifyVerdict {
            size: 0,
            version: 0,
            outcome: VerifyOutcome::Follow,
            _reserved: 0,
            lease: VerifyLease::NONE,
            digest_ptr: core::ptr::null(),
            digest_len: 0,
        }
    };
    (status, verdict)
}

#[test]
fn store_then_lookup_returns_hit() {
    // A subject nobody has verified: the first lookup LEADS the fetch (not a Hit).
    let subject = b"trust-test/store-then-hit/counterparty-A";
    with_test_state(|host, vt, _scope| {
        let (lease_raw, status) = with_key(7, subject, |key| {
            let (status, verdict) = read_lookup(host, vt, key);
            (verdict.lease, status)
        });
        assert_eq!(status, StatusClass::Ok);
        // The leader stores a completed fetch with a long ttl.
        let stored = with_key(7, subject, |key| {
            (vt.verify_store.unwrap())(host, key, lease_raw, 3_600)
        });
        assert_eq!(stored, StatusClass::Ok);
        // Now the SAME subject reads back a fresh Hit.
        let (status, verdict) = with_key(7, subject, |key| read_lookup(host, vt, key));
        assert_eq!(status, StatusClass::Ok);
        assert_eq!(verdict.outcome, VerifyOutcome::Hit, "fresh subject → Hit");
    });
}

#[test]
fn first_lookup_leads_second_follows() {
    // Two lookups of an unseen subject WITHOUT a store between: one leads, the next follows
    // (single-flight — only one caller fetches).
    let subject = b"trust-test/lead-follow/counterparty-B";
    with_test_state(|host, vt, _scope| {
        let first = with_key(9, subject, |key| read_lookup(host, vt, key).1.outcome);
        let second = with_key(9, subject, |key| read_lookup(host, vt, key).1.outcome);
        assert_eq!(first, VerifyOutcome::Lead, "first caller leads the fetch");
        assert_eq!(
            second,
            VerifyOutcome::Follow,
            "a leader is fetching → follow"
        );
    });
}

#[test]
fn verify_lookup_is_fail_closed() {
    with_test_state(|host, vt, _scope| {
        // Null key → Refused (out not written), never a Hit.
        let mut out = MaybeUninit::<VerifyVerdict>::uninit();
        let status =
            (vt.verify_lookup.unwrap())(host, core::ptr::null(), core::ptr::from_mut(&mut out));
        assert_eq!(status, StatusClass::Refused);
        // Null out-slot with a valid key → Refused.
        let status = with_key(1, b"x", |key| {
            (vt.verify_lookup.unwrap())(host, key, core::ptr::null_mut())
        });
        assert_eq!(status, StatusClass::Refused);
    });
}

#[test]
fn verify_store_fail_closed_on_null_key() {
    with_test_state(|host, vt, _scope| {
        let status = (vt.verify_store.unwrap())(host, core::ptr::null(), VerifyLease::NONE, 60);
        assert_eq!(status, StatusClass::Refused);
    });
}

/// Build a borrowed `VerifyQuery` with the given freshness inputs (an absent `last_checked_ms`
/// marshals `last_checked_present = 0`) for `f`.
fn with_vquery<R>(
    last_checked_ms: Option<u64>,
    ttl_ms: u64,
    now_ms: u64,
    f: impl FnOnce(*const VerifyQuery) -> R,
) -> R {
    let q = VerifyQuery {
        size: core::mem::size_of::<VerifyQuery>() as u32,
        version: POD_VERSION,
        _reserved: 0,
        last_checked_present: u32::from(last_checked_ms.is_some()),
        _reserved2: 0,
        ttl_ms,
        now_ms,
        last_checked_ms: last_checked_ms.unwrap_or(0),
    };
    f(&q as *const VerifyQuery)
}

/// The boundary cases that pin `reverify::due`'s meaning: never-checked, just-checked/within-ttl
/// (fresh), the exact-ttl boundary (reaching it is due), ttl-elapsed (due), and clock-backwards
/// (due, never permanent freshness). `true` = due (re-verify).
const DUE_CASES: &[(Option<u64>, u64, u64, bool)] = &[
    (None, 1_000, 10_000, true),        // never checked → due
    (Some(5_000), 1_000, 5_000, false), // just checked → fresh
    (Some(5_000), 1_000, 5_999, false), // within ttl → fresh
    (Some(5_000), 1_000, 6_000, true),  // exactly ttl → due
    (Some(5_000), 1_000, 9_000, true),  // ttl elapsed → due
    (Some(5_000), 1_000, 4_000, true),  // clock went backwards → due
];

/// THE EXTERN-C SLOT marshals the FULL `reverify::Due` REASON onto its neutral `VerifyDecision`
/// mirror (`Fresh` for reuse; the specific `NeverChecked`/`TtlExpired`/`ClockWentBackwards` reason
/// when due), funneling to the SAME `verify_decide_due` body — so the dynamic-load veneer and the
/// compiled-in one cannot diverge, and the plane reconstructs the reason it audits, not a bool.
#[test]
fn verify_decide_q_marshals_the_full_due_reason() {
    use crate::trust::reverify::due;
    use crate::trust::reverify::{Ledger, Policy};
    with_test_state(|host, vt, _scope| {
        for &(last, ttl_ms, now, _want_due) in DUE_CASES {
            let got = with_vquery(last, ttl_ms, now, |q| (vt.verify_decide.unwrap())(host, q));
            // The reason the plane's own `reverify::due` (operator_sync = false) yields, marshalled.
            let ledger = Ledger {
                last_checked_ms: last,
                ..Ledger::default()
            };
            let policy = Policy {
                ttl_ms,
                recovery_backoff_ms: 0,
            };
            let want = due(&ledger, &policy, now, false).to_verify_decision();
            assert_eq!(
                got, want,
                "verify_decide_q reason for last={last:?} ttl={ttl_ms} now={now}"
            );
            // And it round-trips back to the SAME rich `Due` the a2a plane audits (the reconstruction
            // is the a2a-gated inbound half of the mapping).
            #[cfg(feature = "plane-a2a")]
            assert_eq!(
                crate::trust::reverify::Due::from_verify_decision(got),
                due(&ledger, &policy, now, false),
                "reconstructed Due for last={last:?} ttl={ttl_ms} now={now}"
            );
        }
    });
}

#[test]
fn verify_decide_q_fail_closed_on_null() {
    with_test_state(|host, vt, _scope| {
        // No query to decide over → Stale (re-verify), never a spurious Fresh.
        assert_eq!(
            (vt.verify_decide.unwrap())(host, core::ptr::null()),
            VerifyDecision::Stale
        );
    });
}

#[test]
fn approval_redeem_q_spends_against_the_marshalled_expiry() {
    with_test_state(|host, vt, _scope| {
        let nonce = b"verify-q/approval/one-time";
        let q = ApprovalQuery {
            size: core::mem::size_of::<ApprovalQuery>() as u32,
            version: POD_VERSION,
            _reserved: 0,
            scope: 0,
            _reserved2: 0,
            expires_at: crate::store::now().saturating_add(3_600),
            now: crate::store::now(),
            key_ptr: nonce.as_ptr(),
            key_len: nonce.len(),
        };
        let first = (vt.approval_redeem_q.unwrap())(host, &q as *const ApprovalQuery);
        let second = (vt.approval_redeem_q.unwrap())(host, &q as *const ApprovalQuery);
        assert_eq!(first, StatusClass::Ok, "first redemption is fresh");
        assert_eq!(second, StatusClass::Refused, "already spent → refused");
        // Null query → fail-closed.
        assert_eq!(
            (vt.approval_redeem_q.unwrap())(host, core::ptr::null()),
            StatusClass::Refused
        );
    });
}

#[test]
fn drift_quarantine_records_and_is_fail_closed() {
    with_test_state(|host, vt, _scope| {
        // A real subject: the demotion write is fire-and-forget (no sink in the test app), so a
        // clean call is Ok.
        let status = with_key(3, b"drifted-counterparty", |key| {
            (vt.drift_quarantine.unwrap())(host, key)
        });
        assert_eq!(status, StatusClass::Ok);
        // Null key → fail-closed.
        let status = (vt.drift_quarantine.unwrap())(host, core::ptr::null());
        assert_eq!(status, StatusClass::Refused);
    });
}

/// The neutral u8 mirror the drift path carries round-trips through
/// [`trust_state_u8`]/[`trust_state_from_u8`] for every state, and an ABSENT/unknown value fails
/// SAFE to `Quarantined` — the pre-extension demote-only disposition.
#[cfg(feature = "plane-mcp")]
#[test]
fn drift_state_mirror_round_trips_and_fails_safe() {
    use crate::trust::TrustState;
    for state in [
        TrustState::Pending,
        TrustState::Approved,
        TrustState::Quarantined,
        TrustState::Suspended,
        TrustState::Error,
    ] {
        assert_eq!(trust_state_from_u8(trust_state_u8(state)), state);
    }
    // 0 (a predating sender's zeroed field) and any unknown value → the demote-only fallback.
    assert_eq!(trust_state_from_u8(0), TrustState::Quarantined);
    assert_eq!(trust_state_from_u8(99), TrustState::Quarantined);
}

/// The slot RECORDS or CLEARS by the caller's `drift_state`, and a Key that predates the field
/// (the pre-extension `size`, so the sized guard hides `drift_state`) settles the demote-only
/// fallback. The test app has no durable sink, so the settle is a fire-and-forget `Ok`; the
/// disposition carried is asserted via the mirror above and the durable settle rule in
/// `plane::quarantine`'s own tests.
#[cfg(feature = "plane-mcp")]
#[test]
fn drift_quarantine_carries_the_caller_state() {
    use crate::trust::TrustState;
    with_test_state(|host, vt, _scope| {
        let subject = b"drift/carry/counterparty";
        // A full Key carrying an explicit disposition (CLEAR and DEMOTE both answer Ok).
        let with_state = |state: TrustState| {
            let key = Key {
                size: core::mem::size_of::<Key>() as u32,
                version: POD_VERSION,
                _reserved: 0,
                scope: 0,
                _reserved2: 0,
                key_ptr: subject.as_ptr(),
                key_len: subject.len(),
                drift_state: trust_state_u8(state),
            };
            (vt.drift_quarantine.unwrap())(host, &key as *const Key)
        };
        assert_eq!(with_state(TrustState::Approved), StatusClass::Ok);
        assert_eq!(with_state(TrustState::Quarantined), StatusClass::Ok);

        // A PREDATING sender advertises the pre-extension size, so the guard hides `drift_state`
        // and the slot still settles (the demote-only fallback) rather than refusing.
        let pre_ext_size = core::mem::offset_of!(Key, key_len) + core::mem::size_of::<usize>();
        let legacy = Key {
            size: pre_ext_size as u32,
            version: POD_VERSION,
            _reserved: 0,
            scope: 0,
            _reserved2: 0,
            key_ptr: subject.as_ptr(),
            key_len: subject.len(),
            drift_state: trust_state_u8(TrustState::Approved), // present in memory, hidden by size
        };
        assert_eq!(
            (vt.drift_quarantine.unwrap())(host, &legacy as *const Key),
            StatusClass::Ok
        );
    });
}

#[test]
fn approval_redeem_is_single_use_and_fail_closed() {
    with_test_state(|host, vt, _scope| {
        let nonce = b"trust-test/approval/one-time-nonce";
        // First redemption succeeds; the second is refused (single-use).
        let first = with_key(0, nonce, |key| (vt.approval_redeem.unwrap())(host, key));
        let second = with_key(0, nonce, |key| (vt.approval_redeem.unwrap())(host, key));
        assert_eq!(first, StatusClass::Ok, "first redemption is fresh");
        assert_eq!(second, StatusClass::Refused, "already spent → refused");
        // Null key → fail-closed.
        let status = (vt.approval_redeem.unwrap())(host, core::ptr::null());
        assert_eq!(status, StatusClass::Refused);
    });
}

/// The six per-step facts a plane marshals into the [`CounterpartyRef`] tail — the inverse of the
/// arms the plane's own `validate_request` refuses at. A `would_pass` value fills every step so a
/// single failing step can be isolated (exactly as the ordered validator short-circuits).
#[derive(Clone, Copy)]
struct Facts {
    identity_live: u8,
    grant_outcome: u8,
    registration_state: u8,
    artifact_outcome: u8,
    generation_admitted: u64,
    generation_live: u64,
}

impl Facts {
    /// Every step passes: live identity, all grants held, an Approved registration serving its
    /// artifact, and a still-live generation.
    fn would_pass() -> Self {
        Facts {
            identity_live: 1,
            grant_outcome: 0,
            registration_state: reg_state::APPROVED,
            artifact_outcome: 1,
            generation_admitted: 5,
            generation_live: 5,
        }
    }
}

/// The neutral u8 mirror of the plane's `TrustState`, as the plane marshals it.
fn state_u8(state: crate::trust::TrustState) -> u8 {
    match state {
        crate::trust::TrustState::Pending => reg_state::PENDING,
        crate::trust::TrustState::Approved => reg_state::APPROVED,
        crate::trust::TrustState::Quarantined => reg_state::QUARANTINED,
        crate::trust::TrustState::Suspended => reg_state::SUSPENDED,
        crate::trust::TrustState::Error => reg_state::FAILED,
    }
}

/// Build a `CounterpartyRef` carrying `facts` (fact tail written) over `id` for the duration of
/// `f`.
fn with_facts<R>(id: &[u8], facts: Facts, f: impl FnOnce(*const CounterpartyRef) -> R) -> R {
    let cp = CounterpartyRef {
        size: core::mem::size_of::<CounterpartyRef>() as u32,
        version: POD_VERSION,
        _reserved: 0,
        scope: 0,
        _reserved2: 0,
        ref_ptr: id.as_ptr(),
        ref_len: id.len(),
        identity_live: facts.identity_live,
        grant_outcome: facts.grant_outcome,
        registration_state: facts.registration_state,
        artifact_outcome: facts.artifact_outcome,
        fact_flags: 0x01, // the fact tail is authoritative.
        _reserved3: 0,
        _reserved4: 0,
        generation_admitted: facts.generation_admitted,
        generation_live: facts.generation_live,
    };
    f(&cp as *const CounterpartyRef)
}

/// THE FAITHFULNESS PROOF: the host `trust_evaluate` FOLD reproduces the plane's
/// `validate_request` disposition EXACTLY — every `Refusal` arm (and the passing case) marshalled
/// to its per-step facts folds to the verdict that names that arm, in the validator's order. This
/// is the trust analogue of `failure_signal_round_trips_through_classify`: the facts encode the
/// step outcome, the fold independently reconstructs the disposition, and the two must agree.
#[test]
fn trust_evaluate_folds_validate_request_order() {
    use crate::trust::TrustState;
    // (a description, the facts that produce it, the verdict the plane's Refusal maps to).
    let id = b"faithfulness/counterparty";
    let cases: &[(&str, Facts, TrustVerdict)] = &[
        ("all steps pass", Facts::would_pass(), TrustVerdict::Allow),
        (
            "identity not live",
            Facts {
                identity_live: 0,
                ..Facts::would_pass()
            },
            TrustVerdict::IdentityNotLive,
        ),
        (
            "not granted",
            Facts {
                grant_outcome: 1,
                ..Facts::would_pass()
            },
            TrustVerdict::NotGranted,
        ),
        (
            "egress denied",
            Facts {
                grant_outcome: 2,
                ..Facts::would_pass()
            },
            TrustVerdict::EgressDenied,
        ),
        (
            "not serving: quarantined",
            Facts {
                registration_state: state_u8(TrustState::Quarantined),
                ..Facts::would_pass()
            },
            TrustVerdict::Quarantined,
        ),
        (
            "not serving: error (last contact failed)",
            Facts {
                registration_state: state_u8(TrustState::Error),
                ..Facts::would_pass()
            },
            TrustVerdict::Quarantined,
        ),
        (
            "not serving: pending",
            Facts {
                registration_state: state_u8(TrustState::Pending),
                ..Facts::would_pass()
            },
            TrustVerdict::NeedsApproval,
        ),
        (
            "not serving: suspended",
            Facts {
                registration_state: state_u8(TrustState::Suspended),
                ..Facts::would_pass()
            },
            TrustVerdict::Denied,
        ),
        (
            "artifact drifted",
            Facts {
                artifact_outcome: 2,
                ..Facts::would_pass()
            },
            TrustVerdict::ArtifactDrifted,
        ),
        (
            "artifact unobservable",
            Facts {
                artifact_outcome: 3,
                ..Facts::would_pass()
            },
            TrustVerdict::ArtifactDrifted,
        ),
        (
            "generation moved",
            Facts {
                generation_admitted: 5,
                generation_live: 6,
                ..Facts::would_pass()
            },
            TrustVerdict::GenerationMoved,
        ),
    ];
    with_test_state(|host, vt, _scope| {
        for (desc, facts, expect) in cases {
            let got = with_facts(id, *facts, |cp| (vt.trust_evaluate.unwrap())(host, cp));
            assert_eq!(got, *expect, "fold disposition for `{desc}`");
        }
    });
}

/// THE ORDER IS THE CONTENT: when several steps would refuse at once, the EARLIER step wins,
/// exactly as `validate_request` short-circuits. Identity beats grant beats registration beats
/// artifact beats generation.
#[test]
fn trust_evaluate_short_circuits_in_step_order() {
    let id = b"faithfulness/order";
    // Every step fails simultaneously.
    let all_fail = Facts {
        identity_live: 0,
        grant_outcome: 1,
        registration_state: reg_state::QUARANTINED,
        artifact_outcome: 2,
        generation_admitted: 5,
        generation_live: 6,
    };
    with_test_state(|host, vt, _scope| {
        // Identity is step 1 — it wins over every later failure.
        assert_eq!(
            with_facts(id, all_fail, |cp| (vt.trust_evaluate.unwrap())(host, cp)),
            TrustVerdict::IdentityNotLive
        );
        // Fix identity → grant (step 2) wins over registration/artifact/generation.
        let grant_first = Facts {
            identity_live: 1,
            ..all_fail
        };
        assert_eq!(
            with_facts(id, grant_first, |cp| (vt.trust_evaluate.unwrap())(host, cp)),
            TrustVerdict::NotGranted
        );
        // Fix grant → registration (step 3a) wins over artifact/generation.
        let reg_first = Facts {
            grant_outcome: 0,
            ..grant_first
        };
        assert_eq!(
            with_facts(id, reg_first, |cp| (vt.trust_evaluate.unwrap())(host, cp)),
            TrustVerdict::Quarantined
        );
        // Fix registration → artifact (step 3b) wins over generation.
        let artifact_first = Facts {
            registration_state: reg_state::APPROVED,
            ..reg_first
        };
        assert_eq!(
            with_facts(id, artifact_first, |cp| (vt.trust_evaluate.unwrap())(
                host, cp
            )),
            TrustVerdict::ArtifactDrifted
        );
        // Fix artifact → generation (step 4) is the last refusal.
        let gen_first = Facts {
            artifact_outcome: 1,
            ..artifact_first
        };
        assert_eq!(
            with_facts(id, gen_first, |cp| (vt.trust_evaluate.unwrap())(host, cp)),
            TrustVerdict::GenerationMoved
        );
    });
}

/// FORWARD-COMPAT: a sender that predates the fact tail (fact flag clear) falls back to the
/// legacy drift map — an un-demoted counterparty is `Allow`, a null identity is `Denied` — so the
/// enrichment never changes the disposition an older plane would have received.
#[test]
fn trust_evaluate_falls_back_to_drift_map_without_facts() {
    with_test_state(|host, vt, _scope| {
        let id = b"faithfulness/legacy";
        // fact_flags = 0 → the tail is ignored even though present; legacy map → Allow (undemoted).
        let cp = CounterpartyRef {
            size: core::mem::size_of::<CounterpartyRef>() as u32,
            version: POD_VERSION,
            _reserved: 0,
            scope: 0,
            _reserved2: 0,
            ref_ptr: id.as_ptr(),
            ref_len: id.len(),
            identity_live: 0, // would be IdentityNotLive IF the tail were authoritative
            grant_outcome: 1,
            registration_state: reg_state::SUSPENDED,
            artifact_outcome: 2,
            fact_flags: 0, // NOT authoritative → legacy drift map.
            _reserved3: 0,
            _reserved4: 0,
            generation_admitted: 5,
            generation_live: 6,
        };
        assert_eq!(
            (vt.trust_evaluate.unwrap())(host, &cp as *const CounterpartyRef),
            TrustVerdict::Allow,
            "no fact tail → legacy drift map, not the folded refusal"
        );
    });
}

#[test]
fn trust_evaluate_allows_unknown_and_denies_null() {
    with_test_state(|host, vt, _scope| {
        let id = b"trust-test/eval/unknown-counterparty";
        let cp = CounterpartyRef {
            size: core::mem::size_of::<CounterpartyRef>() as u32,
            version: POD_VERSION,
            _reserved: 0,
            scope: 2,
            _reserved2: 0,
            ref_ptr: id.as_ptr(),
            ref_len: id.len(),
            // No fact tail → the legacy drift map governs (this test's subject).
            identity_live: 0,
            grant_outcome: 0,
            registration_state: 0,
            artifact_outcome: 0,
            fact_flags: 0,
            _reserved3: 0,
            _reserved4: 0,
            generation_admitted: 0,
            generation_live: 0,
        };
        // No demotion on record → Allow.
        assert_eq!(
            (vt.trust_evaluate.unwrap())(host, &cp as *const CounterpartyRef),
            TrustVerdict::Allow
        );
        // Null counterparty → Denied (fail-closed).
        assert_eq!(
            (vt.trust_evaluate.unwrap())(host, core::ptr::null()),
            TrustVerdict::Denied
        );
    });
}
