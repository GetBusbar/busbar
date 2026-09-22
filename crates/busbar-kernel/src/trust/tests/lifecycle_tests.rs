// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The trust LIFECYCLE, exercised through one concrete pinned artifact. Every assertion here is
//! about the plane-neutral machine; `genericity_tests` re-runs the same transitions over a second,
//! differently-shaped artifact to prove none of it is MCP-specific.

use super::*;
use std::collections::BTreeMap;

/// A cert-SPKI pin, the MCP shape: one mechanism, one opaque value.
#[derive(Clone, Debug, PartialEq)]
struct SpkiPin(&'static str);

impl PinnedArtifact for SpkiPin {
    fn mechanism(&self) -> &'static str {
        "cert_spki"
    }
    fn digest(&self) -> String {
        self.0.to_string()
    }
}

fn caps(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

fn seen(pin: Option<SpkiPin>, pairs: &[(&str, &str)]) -> Sighting<SpkiPin> {
    Sighting::Seen(Observation {
        pin,
        capabilities: caps(pairs),
    })
}

/// REGISTER: a fresh record is `pending` and serves nothing. This is the fail-closed floor the whole
/// machine rests on, so it is asserted before any transition exists to move off it.
#[test]
fn a_registered_record_is_pending_and_serves_nothing() {
    let a: Approval<SpkiPin> = Approval::registered();
    assert_eq!(a.state(&Sighting::Never), TrustState::Pending);
    assert!(!a.serves("read_file", "h1"));
}

/// CONNECT does not promote. Capturing a pin candidate and a capability set leaves the record
/// `pending`; only an operator approval moves it. The captured sighting is what distinguishes the
/// two pending sub-states the design names (`untrusted` vs `trusted-pending`), which is a question
/// about the SIGHTING and never a second stored state.
#[test]
fn capturing_a_sighting_does_not_promote_the_record() {
    let a: Approval<SpkiPin> = Approval::registered();
    let sighting = seen(Some(SpkiPin("PIN-A")), &[("read_file", "h1")]);
    assert_eq!(a.state(&sighting), TrustState::Pending);
    assert!(!a.serves("read_file", "h1"));
}

/// APPROVE locks the observed pin and adopts the observed hashes, and only then does the record
/// serve. Serving is gated on the hash MATCHING, not merely on the capability being named.
#[test]
fn approve_locks_the_pin_adopts_the_hashes_and_starts_serving() {
    let mut a = Approval::registered();
    let sighting = seen(
        Some(SpkiPin("PIN-A")),
        &[("read_file", "h1"), ("write", "h2")],
    );
    a.approve(&sighting, None).expect("approve");
    assert_eq!(a.state(&sighting), TrustState::Approved);
    assert!(a.serves("read_file", "h1"));
    assert!(a.serves("write", "h2"));
    assert!(
        !a.serves("read_file", "DRIFTED"),
        "serving is gated on the approved hash, not on the name"
    );
    assert!(!a.serves("never_seen", "h9"));
}

/// APPROVE with a PRE-DECLARED pin uses the operator's value, not the observed candidate. This is
/// the declarative path: a pin supplied out of band is the authenticity root, and a record carrying
/// one must never silently adopt whatever the endpoint presented instead.
#[test]
fn a_pre_declared_pin_wins_over_the_observed_candidate() {
    let mut a = Approval::registered();
    let sighting = seen(Some(SpkiPin("PRESENTED")), &[("read_file", "h1")]);
    a.approve(&sighting, Some(SpkiPin("OUT-OF-BAND")))
        .expect("approve with a pre-declared pin");
    assert_eq!(a.pin(), Some(&SpkiPin("OUT-OF-BAND")));
    assert_eq!(
        a.state(&sighting),
        TrustState::Quarantined,
        "the endpoint is presenting a pin that is not the operator's: that is drift, not trust"
    );
}

/// APPROVE with NEITHER a candidate nor a pre-declared pin is refused. Approving nothing would lock
/// an empty root and call it trust.
#[test]
fn approve_without_any_pin_is_refused() {
    let mut a: Approval<SpkiPin> = Approval::registered();
    assert!(a.approve(&Sighting::Never, None).is_err());
    assert!(a.approve(&seen(None, &[("t", "h")]), None).is_err());
    assert_eq!(a.state(&Sighting::Never), TrustState::Pending);
}

/// DRIFT on re-observation demotes to `quarantined`, and dispatch stops serving the drifted
/// capability WITHOUT the record being rewritten. The approval still says `h1`; the endpoint now
/// says `h2`; the gate is the comparison, so a stale-approved entry can never be dispatched against.
#[test]
fn a_changed_hash_quarantines_and_dispatch_refuses_the_new_hash() {
    let mut a = Approval::registered();
    a.approve(&seen(Some(SpkiPin("PIN-A")), &[("read_file", "h1")]), None)
        .expect("approve");
    let drifted = seen(Some(SpkiPin("PIN-A")), &[("read_file", "h2")]);
    assert_eq!(a.state(&drifted), TrustState::Quarantined);
    assert!(!a.serves("read_file", "h2"));
    assert!(
        a.serves("read_file", "h1"),
        "the approval itself is untouched by drift; only the comparison fails"
    );
}

/// A NEW capability is drift too. A server that grows a tool between refreshes has changed what the
/// operator approved, so it demotes rather than auto-adopting.
#[test]
fn a_new_capability_is_drift() {
    let mut a = Approval::registered();
    a.approve(&seen(Some(SpkiPin("P")), &[("read_file", "h1")]), None)
        .expect("approve");
    let grown = seen(
        Some(SpkiPin("P")),
        &[("read_file", "h1"), ("exfiltrate", "h9")],
    );
    assert_eq!(a.state(&grown), TrustState::Quarantined);
    assert_eq!(a.drift(&grown).added, vec!["exfiltrate".to_string()]);
    assert!(!a.serves("exfiltrate", "h9"));
}

/// A REMOVED capability is drift as well, and the drift report names all three kinds separately so
/// the operator sees what actually happened rather than one undifferentiated alarm.
#[test]
fn the_drift_report_separates_added_changed_and_removed() {
    let mut a = Approval::registered();
    a.approve(
        &seen(
            Some(SpkiPin("P")),
            &[("keep", "h1"), ("mutate", "h2"), ("vanish", "h3")],
        ),
        None,
    )
    .expect("approve");
    let now = seen(
        Some(SpkiPin("P")),
        &[("keep", "h1"), ("mutate", "CHANGED"), ("appear", "h4")],
    );
    let d = a.drift(&now);
    assert_eq!(d.added, vec!["appear".to_string()]);
    assert_eq!(d.changed, vec!["mutate".to_string()]);
    assert_eq!(d.removed, vec!["vanish".to_string()]);
    assert!(!d.pin_changed);
    assert!(!d.is_empty());
}

/// A CHANGED PIN is its own drift axis, and it is the one that must never be folded into a bulk
/// capability approval: adopting a new identity is a different act from adopting new content.
#[test]
fn a_changed_pin_is_its_own_drift_axis() {
    let mut a = Approval::registered();
    a.approve(&seen(Some(SpkiPin("PIN-A")), &[("t", "h1")]), None)
        .expect("approve");
    let moved = seen(Some(SpkiPin("PIN-B")), &[("t", "h1")]);
    let d = a.drift(&moved);
    assert!(d.pin_changed);
    assert!(d.added.is_empty() && d.changed.is_empty() && d.removed.is_empty());
    assert_eq!(a.state(&moved), TrustState::Quarantined);
}

/// RE-APPROVAL is per capability: approving the drifted one clears the drift for it alone and
/// leaves every sibling approval byte-identical. This is the changes queue worked one row at a time.
#[test]
fn approving_one_capability_clears_only_its_own_drift() {
    let mut a = Approval::registered();
    a.approve(&seen(Some(SpkiPin("P")), &[("a", "h1"), ("b", "h2")]), None)
        .expect("approve");
    let drifted = seen(Some(SpkiPin("P")), &[("a", "DRIFT-A"), ("b", "DRIFT-B")]);
    a.approve_capability("a", &drifted).expect("approve one");
    let d = a.drift(&drifted);
    assert_eq!(d.changed, vec!["b".to_string()]);
    assert!(a.serves("a", "DRIFT-A"));
    assert!(!a.serves("b", "DRIFT-B"));
    a.approve_capability("b", &drifted)
        .expect("approve the other");
    assert!(a.drift(&drifted).is_empty());
    assert_eq!(a.state(&drifted), TrustState::Approved);
}

/// REJECTING a capability drops it from the served set PERMANENTLY, and a rejected capability is
/// NOT drift: the operator has already ruled on it, so it must not keep re-raising an alarm.
#[test]
fn a_rejected_capability_is_never_served_and_never_drifts_again() {
    let mut a = Approval::registered();
    a.approve(
        &seen(Some(SpkiPin("P")), &[("ok", "h1"), ("bad", "h2")]),
        None,
    )
    .expect("approve");
    a.reject_capability("bad");
    let now = seen(Some(SpkiPin("P")), &[("ok", "h1"), ("bad", "h2")]);
    assert!(!a.serves("bad", "h2"));
    assert!(a.serves("ok", "h1"));
    assert!(
        a.drift(&now).is_empty(),
        "a rejected capability is settled, not drifting"
    );
    // It stays settled even when the rejected capability's own hash moves.
    let moved = seen(Some(SpkiPin("P")), &[("ok", "h1"), ("bad", "MOVED")]);
    assert!(a.drift(&moved).is_empty());
    assert!(!a.serves("bad", "MOVED"));
}

/// APPROVE-PIN adopts a changed identity as the new locked pin, and it is a SEPARATE act from
/// approving content: it clears the pin drift and touches no capability approval.
#[test]
fn approve_pin_adopts_the_new_identity_without_touching_capabilities() {
    let mut a = Approval::registered();
    a.approve(&seen(Some(SpkiPin("PIN-A")), &[("t", "h1")]), None)
        .expect("approve");
    let moved = seen(Some(SpkiPin("PIN-B")), &[("t", "CHANGED")]);
    a.approve_pin(&moved).expect("approve-pin");
    assert_eq!(a.pin(), Some(&SpkiPin("PIN-B")));
    let d = a.drift(&moved);
    assert!(!d.pin_changed, "the identity drift is settled");
    assert_eq!(d.changed, vec!["t".to_string()], "the CONTENT drift is not");
    assert_eq!(a.state(&moved), TrustState::Quarantined);
}

/// A CONNECT FAILURE parks the record in `error` and never in `approved`, from any prior state, and
/// an errored record serves nothing.
#[test]
fn a_failed_sighting_is_error_from_any_state() {
    let fresh: Approval<SpkiPin> = Approval::registered();
    let failed = Sighting::Failed("connection refused".to_string());
    assert_eq!(fresh.state(&failed), TrustState::Error);

    let mut approved = Approval::registered();
    approved
        .approve(&seen(Some(SpkiPin("P")), &[("t", "h1")]), None)
        .expect("approve");
    assert_eq!(approved.state(&failed), TrustState::Error);
    assert_eq!(
        approved.state(&Sighting::Never),
        TrustState::Approved,
        "an approved record that has simply not been re-observed is still approved"
    );
}

/// SUSPENSION outranks every other state and carries the operator-visible reason. It is a security
/// control, not a score, so it is not expressible as a demotion to some lesser trust state.
#[test]
fn suspension_outranks_every_other_state_and_names_its_reason() {
    let mut a = Approval::registered();
    let sighting = seen(Some(SpkiPin("P")), &[("t", "h1")]);
    a.approve(&sighting, None).expect("approve");
    a.suspend("response artifact tripped the anomaly breaker");
    assert_eq!(a.state(&sighting), TrustState::Suspended);
    assert_eq!(
        a.suspension(),
        Some("response artifact tripped the anomaly breaker")
    );
    assert!(!a.serves("t", "h1"), "a suspended upstream serves nothing");
    // Even a clean re-observation cannot lift it: only an operator resume can.
    assert_eq!(a.state(&sighting), TrustState::Suspended);
    a.resume();
    assert_eq!(a.state(&sighting), TrustState::Approved);
    assert!(a.serves("t", "h1"));
}

/// CHANGING THE ENDPOINT OR THE PIN forces re-approval: the locked pin AND every capability
/// approval are discarded, because they were assertions about a different upstream. An identity
/// change must never ride the old approval.
#[test]
fn unpinning_discards_the_pin_and_every_capability_approval() {
    let mut a = Approval::registered();
    let sighting = seen(Some(SpkiPin("PIN-A")), &[("t", "h1")]);
    a.approve(&sighting, None).expect("approve");
    a.unpin();
    assert_eq!(a.pin(), None);
    assert_eq!(a.state(&sighting), TrustState::Pending);
    assert!(
        !a.serves("t", "h1"),
        "the capability approvals went with the identity they described"
    );
}

/// A rejection SURVIVES an unpin. The operator said "never serve this capability"; that is a
/// standing instruction about the name, not a fact about the endpoint's current identity, and
/// silently reinstating it on a re-approval is exactly the way a rejected tool comes back.
#[test]
fn a_rejection_survives_an_unpin_and_a_re_approval() {
    let mut a = Approval::registered();
    let sighting = seen(Some(SpkiPin("PIN-A")), &[("ok", "h1"), ("bad", "h2")]);
    a.approve(&sighting, None).expect("approve");
    a.reject_capability("bad");
    a.unpin();
    a.approve(&sighting, None).expect("re-approve");
    assert!(a.serves("ok", "h1"));
    assert!(
        !a.serves("bad", "h2"),
        "a bulk re-approval must not quietly un-reject what the operator rejected"
    );
}

/// IDEMPOTENCE across the machine: re-running a transition that has already taken effect changes
/// nothing. Every one of these is reachable from an operator double-click or a retried request.
#[test]
fn every_transition_is_idempotent() {
    let sighting = seen(Some(SpkiPin("P")), &[("t", "h1")]);
    let mut a = Approval::registered();
    a.approve(&sighting, None).expect("approve");
    let once = a.clone();
    a.approve(&sighting, None).expect("approve again");
    assert_eq!(a, once);
    a.approve_pin(&sighting).expect("approve-pin again");
    assert_eq!(a, once);
    a.approve_capability("t", &sighting)
        .expect("approve one again");
    assert_eq!(a, once);

    a.reject_capability("t");
    let rejected = a.clone();
    a.reject_capability("t");
    assert_eq!(a, rejected);

    a.suspend("r");
    let suspended = a.clone();
    a.suspend("r");
    assert_eq!(a, suspended);
    a.resume();
    let resumed = a.clone();
    a.resume();
    assert_eq!(a, resumed);

    a.unpin();
    let unpinned = a.clone();
    a.unpin();
    assert_eq!(a, unpinned);
}

/// Approving a capability the endpoint is not currently offering is REFUSED. There is no hash to
/// adopt, so the alternative is inventing one.
#[test]
fn approving_an_unobserved_capability_is_refused() {
    let mut a = Approval::registered();
    let sighting = seen(Some(SpkiPin("P")), &[("t", "h1")]);
    a.approve(&sighting, None).expect("approve");
    assert!(a.approve_capability("ghost", &sighting).is_err());
    assert!(a.approve_capability("t", &Sighting::Never).is_err());
}
