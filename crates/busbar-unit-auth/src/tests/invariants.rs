// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The security invariants of the authenticate step, stated over every shape rather than sampled.
//!
//! Each of these is a property the ported suite checks one instance of. One instance is what a
//! reader believes; every instance is what a change has to survive. They are written as exhaustive
//! walks over the chain shapes the configuration can produce, so a change that keeps the sampled
//! case working and breaks a neighbouring one has nowhere to land.

use super::{entry, test_digest, Canned, OneKey};
use crate::cache::CredentialCache;
use crate::chain::{AuthChain, ChainEntry, ChainVerdict, RevocationView};
use crate::module::{AuthModule, AuthOutcome};
use crate::principal::Principal;

/// A revocation set that records every credential it was asked about, so a test can assert on what
/// was NOT asked as easily as on what was.
struct Recording {
    revoked: Vec<String>,
    asked: std::sync::Mutex<Vec<String>>,
}

impl Recording {
    fn new(revoked: &[&str]) -> Self {
        Recording {
            revoked: revoked.iter().map(|s| (*s).to_string()).collect(),
            asked: std::sync::Mutex::new(Vec::new()),
        }
    }
    fn asked(&self) -> Vec<String> {
        self.asked.lock().expect("not poisoned").clone()
    }
}

impl RevocationView for Recording {
    fn is_revoked(&self, credential: &str) -> bool {
        self.asked
            .lock()
            .expect("not poisoned")
            .push(credential.to_string());
        self.revoked.iter().any(|r| r == credential)
    }
}

/// A module that identifies, for the positions after the rejecting one.
fn identifies(name: &'static str) -> Box<dyn AuthModule> {
    Box::new(Canned::new(
        name,
        AuthOutcome::Identify(Principal::from_id("alice")),
    ))
}

/// The three answers, as a chain position.
fn answering(name: &'static str, outcome: AuthOutcome) -> Box<dyn AuthModule> {
    Box::new(Canned::new(name, outcome))
}

// ---------------------------------------------------------------------------------------------
// A Reject is never a Pass.
// ---------------------------------------------------------------------------------------------

/// A `Reject` ANYWHERE in the chain denies, whatever is behind it.
///
/// The three answers are not interchangeable and only one of them is a refusal: `Reject` means this
/// module recognised the credential and refuses it, and `Pass` means it is not this module's
/// credential at all. Turning the first into the second is the whole failure mode this chain shape
/// exists to prevent — the module that KNOWS the credential is bad steps aside, and the next module,
/// or the keys arm, admits it. The suite checks one two-module chain. This checks every position in
/// chains of every length up to four, with something behind the rejection that would have admitted:
/// a module that identifies, the built-in keys arm holding a valid token, and both.
#[test]
fn a_reject_at_any_position_denies_whatever_would_have_admitted_behind_it() {
    const TOKEN: &str = "the-token";
    for len in 1..=4usize {
        for reject_at in 0..len {
            for keys_behind in [false, true] {
                let names = ["m0", "m1", "m2", "m3"];
                let mut chain: Vec<ChainEntry> = Vec::new();
                for (i, name) in names.iter().take(len).enumerate() {
                    let m = if i == reject_at {
                        answering(name, AuthOutcome::Reject)
                    } else if i > reject_at {
                        // Behind the rejection: a module that WOULD identify.
                        identifies(name)
                    } else {
                        answering(name, AuthOutcome::Pass)
                    };
                    chain.push(entry(name, m));
                }
                let c = AuthChain::new(chain, keys_behind);
                let keys = OneKey {
                    token: TOKEN,
                    aud: None,
                };
                let verdict = c.run_chain_cached(Some(TOKEN), None, Some(&keys), 1000, None);
                assert_eq!(
                    verdict,
                    ChainVerdict::Denied,
                    "len={len} reject_at={reject_at} keys_behind={keys_behind}: \
                     a recognised-and-refused credential was admitted by something behind it"
                );
            }
        }
    }
}

/// A `Reject` is never cached, so it can never later be served as anything — and a cached `Pass`
/// from an earlier run never masks a `Reject` the module gives now.
///
/// This is the deny path's instant-revocation property stated from the other side: an invalid
/// credential re-runs its module every single time, so the moment the module changes its mind the
/// chain does too. A cached `Pass` sitting in front of the rejecting module would be the one way a
/// refusal could be skipped without any module ever being asked.
#[test]
fn a_rejection_is_re_asked_every_time_and_no_cached_pass_can_stand_in_for_it() {
    let cache = CredentialCache::new(test_digest);
    let rejecting = Canned::cacheable("m", AuthOutcome::Reject);
    let calls = rejecting.calls.clone();
    let c = AuthChain::new(vec![entry("m", Box::new(rejecting))], false);

    for i in 1..=5 {
        assert_eq!(
            c.run_chain_cached(Some("bad"), Some(&cache), None, 1000, None),
            ChainVerdict::Denied
        );
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::Relaxed),
            i,
            "a rejection is never cached, so the module is asked every time"
        );
    }
    assert!(
        cache.get("m", "bad", 1000).is_none(),
        "no row exists for a rejected credential"
    );
    assert!(cache.is_empty());
}

/// A chain that only ever passes ends DENIED, never open.
///
/// The open door is one condition and one only: no boxed module and no keys arm. A chain that has
/// modules, all of which say "not mine", has not authenticated anybody — collapsing that into the
/// anonymous admit would turn "no module recognised this credential" into "no module was
/// configured", which is the operator's most consequential posture decided by accident.
#[test]
fn an_all_pass_chain_denies_and_only_an_unconfigured_chain_opens() {
    for len in 1..=4usize {
        let names = ["m0", "m1", "m2", "m3"];
        let chain: Vec<ChainEntry> = names
            .iter()
            .take(len)
            .map(|n| entry(n, answering(n, AuthOutcome::Pass)))
            .collect();
        let c = AuthChain::new(chain, false);
        assert!(!c.is_open(), "len={len}");
        assert_eq!(
            c.run_chain_cached(Some("cred"), None, None, 1000, None),
            ChainVerdict::Denied,
            "len={len}: every module said 'not mine', which is not an admission"
        );
    }
    // The keys arm alone keeps the door shut too: it runs, and with no verifier it denies.
    let arm_only = AuthChain::new(Vec::new(), true);
    assert!(!arm_only.is_open());
    assert_eq!(
        arm_only.run_chain_cached(Some("cred"), None, None, 1000, None),
        ChainVerdict::Denied
    );
    // And the one shape that opens.
    let unconfigured = AuthChain::new(Vec::new(), false);
    assert!(unconfigured.is_open());
    assert_eq!(
        unconfigured.run_chain_cached(Some("cred"), None, None, 1000, None),
        ChainVerdict::Open
    );
}

// ---------------------------------------------------------------------------------------------
// The revocation gate.
// ---------------------------------------------------------------------------------------------

/// A revoked credential's identification is WITHDRAWN at the arrival of a new unit, and a unit
/// already in flight is not asked.
///
/// The gate sits outside the walk on purpose: revoking mid-unit would tear down work already paid
/// for and observed, and the next unit is refused a fraction of a second later anyway.
#[test]
fn a_revoked_identification_is_withdrawn_for_a_new_unit_and_not_for_one_in_flight() {
    let c = AuthChain::new(
        vec![entry(
            "idp",
            Box::new(Canned::new(
                "idp",
                AuthOutcome::Identify(Principal::from_id("alice")),
            )),
        )],
        false,
    );
    let revocations = Recording::new(&["alice-cred"]);

    // In flight: the walk answers, and the gate is never consulted at all.
    assert!(matches!(
        c.run_chain_cached(Some("alice-cred"), None, None, 1000, None),
        ChainVerdict::Identified { .. }
    ));
    assert!(
        revocations.asked().is_empty(),
        "the walk itself never consults the revocation set"
    );

    // A NEW unit: the identification is withdrawn.
    assert_eq!(
        c.run_chain_for_new_unit(
            Some("alice-cred"),
            None,
            None,
            1000,
            None,
            Some(&revocations)
        ),
        ChainVerdict::Denied,
        "a revoked credential's identification is withdrawn at the door of a new unit"
    );
    assert_eq!(revocations.asked(), ["alice-cred"]);

    // A credential that is not revoked keeps its identification.
    let other = Recording::new(&["someone-else"]);
    assert!(matches!(
        c.run_chain_for_new_unit(Some("alice-cred"), None, None, 1000, None, Some(&other)),
        ChainVerdict::Identified { .. }
    ));
}

/// The revocation set is asked about a credential AT MOST ONCE per unit, and never when no
/// credential was presented at all.
///
/// The set is derived from the journal tail and is the kernel's, not this crate's; asking it more
/// than once per unit would let one unit's answer differ from itself between the two asks, and
/// asking with nothing presented is a lookup on a credential that does not exist.
#[test]
fn the_revocation_set_is_asked_once_per_unit_and_never_without_a_credential() {
    let c = AuthChain::new(
        vec![entry(
            "idp",
            Box::new(Canned::new(
                "idp",
                AuthOutcome::Identify(Principal::from_id("alice")),
            )),
        )],
        false,
    );

    let r = Recording::new(&[]);
    c.run_chain_for_new_unit(Some("cred"), None, None, 1000, None, Some(&r));
    assert_eq!(
        r.asked().len(),
        1,
        "one unit, one question — the answer cannot change under itself"
    );

    let none_presented = Recording::new(&[]);
    let verdict = c.run_chain_for_new_unit(None, None, None, 1000, None, Some(&none_presented));
    assert!(
        none_presented.asked().is_empty(),
        "no credential was presented, so there is nothing to look up"
    );
    // And the walk's own answer for that unit stands unchanged.
    assert!(matches!(verdict, ChainVerdict::Identified { .. }));
}

/// What the gate is asked about a string NOBODY identified, recorded as it currently stands.
///
/// The gate is keyed on the presented credential alone, not on the walk having identified anybody,
/// so it is consulted for every unit that presented a string — including the two where no
/// identification exists to withdraw:
///
/// - the open front door, where the admission is the anonymous principal and the string was never
///   looked at by anything;
/// - a chain that already denied, where the answer cannot change.
///
/// Neither can turn a refusal into an admission, which is why this is written down rather than
/// worked around here: the gate can only ever subtract, and the walk's own answer for both shapes is
/// already the safe one. What it does cost is a lookup against the revocation set on behalf of an
/// arbitrary unauthenticated string, on every such request. That makes the set answerable to a
/// caller who was never identified — a probe can learn whether a string it chose is in the
/// revocation set by presenting it against an open door and watching the admission disappear — and
/// it puts work on the deny path that scales with unauthenticated traffic.
///
/// This case pins the behaviour so a change to it is deliberate and shows up as this test failing,
/// rather than being made silently in either direction.
#[test]
fn the_gate_is_currently_consulted_even_for_a_string_nobody_identified() {
    // The open front door: admitted anonymously, and the string is still looked up.
    let open = AuthChain::new(Vec::new(), false);
    let r = Recording::new(&[]);
    assert_eq!(
        open.run_chain_for_new_unit(Some("chosen-by-caller"), None, None, 1000, None, Some(&r)),
        ChainVerdict::Open
    );
    assert_eq!(
        r.asked(),
        ["chosen-by-caller"],
        "the gate is keyed on the presented string, not on an identification having happened"
    );

    // And a revoked string turns the anonymous admission into a refusal, which is the observable
    // that makes the set answerable to an unidentified caller.
    let revoked = Recording::new(&["chosen-by-caller"]);
    assert_eq!(
        open.run_chain_for_new_unit(
            Some("chosen-by-caller"),
            None,
            None,
            1000,
            None,
            Some(&revoked)
        ),
        ChainVerdict::Denied
    );

    // A chain that already denied: asked too, and the answer cannot change either way.
    let denying = AuthChain::new(vec![entry("m", answering("m", AuthOutcome::Reject))], false);
    let r2 = Recording::new(&[]);
    assert_eq!(
        denying.run_chain_for_new_unit(Some("chosen-by-caller"), None, None, 1000, None, Some(&r2)),
        ChainVerdict::Denied
    );
    assert_eq!(r2.asked(), ["chosen-by-caller"]);
}

/// A chain that DENIED stays denied through the gate, whatever the revocation set says.
///
/// The two refusals are different reasons for the same answer and the gate must not be able to turn
/// either into an admission — a revocation view that answered "not revoked" for everything is the
/// shape a misconfigured or empty journal tail produces, and it must be incapable of promoting a
/// denial.
#[test]
fn the_revocation_gate_can_refuse_but_never_admit() {
    let denying = AuthChain::new(vec![entry("m", answering("m", AuthOutcome::Reject))], false);
    let r = Recording::new(&[]); // nothing is revoked
    assert_eq!(
        denying.run_chain_for_new_unit(Some("cred"), None, None, 1000, None, Some(&r)),
        ChainVerdict::Denied,
        "an empty revocation set cannot promote a denial into an admission"
    );
}
