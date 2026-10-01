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

/// APPROVE SETTLES THE `removed` AXIS. Approval adopts exactly the catalogue offered now, so a
/// capability the counterparty stopped offering leaves the approval with it, and the record is
/// `approved` again after the operator's one approval (`docs/design/BUSBAR-1.6.0.md` §11, trust
/// slot: re-sighting the pinned catalogue clears the quarantine). Merging the offered set into the
/// old one left the removed capability approved-and-absent: the approve verb answered applied and
/// the record stayed quarantined, permanently, with no verb left that could clear it.
#[test]
fn approve_after_a_capability_is_removed_clears_the_quarantine() {
    let mut a = Approval::registered();
    let before = seen(Some(SpkiPin("P")), &[("keep", "h1"), ("vanish", "h2")]);
    a.approve(&before, None).expect("approve");
    let shrunk = seen(Some(SpkiPin("P")), &[("keep", "h1")]);
    assert_eq!(a.state(&shrunk), TrustState::Quarantined);
    assert_eq!(a.drift(&shrunk).removed, vec!["vanish".to_string()]);

    a.approve(&shrunk, None)
        .expect("re-approve the offered catalogue");
    assert!(
        a.drift(&shrunk).is_empty(),
        "approve left the removed capability as drift"
    );
    assert_eq!(a.state(&shrunk), TrustState::Approved);
    assert!(a.serves("keep", "h1"));
    assert!(
        !a.serves("vanish", "h2"),
        "a capability no longer offered is no longer approved"
    );
    // Offered again later, it is a NEW capability for the operator to rule on, not a silent return.
    assert_eq!(a.drift(&before).added, vec!["vanish".to_string()]);
    assert_eq!(a.state(&before), TrustState::Quarantined);
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
