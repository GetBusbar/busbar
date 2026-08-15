// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE GENERICITY PROOF: the lifecycle is driven twice, over two artifacts with genuinely different
//! SHAPES, by ONE table of transitions written once.
//!
//! This is not decoration. The registry is being written generic on its first build precisely
//! because there is no second use to extract a trait from later, so "is it actually generic?" has to
//! be a test rather than a claim. The two artifacts are deliberately not near-twins:
//!
//! - `SpkiPin` is ONE opaque value under one mechanism (a TLS certificate SPKI). It is what an MCP
//!   server offers, because MCP has no manifest signature at all.
//! - `CardPin` is TWO values under a different mechanism (a JWS issuer key AND a card fingerprint),
//!   and its equality is a conjunction. It is what an A2A Agent Card offers.
//!
//! A machine that had absorbed a single-value assumption anywhere would fail on the second, and a
//! machine that had absorbed anything MCP-shaped could not host the first at all.

use super::*;
use std::collections::BTreeMap;

/// The MCP shape: one mechanism, one opaque value.
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

/// The A2A shape: a signed card is authenticated by the OPERATOR-supplied issuer key, and the card
/// itself is identified by its fingerprint. Two values, and drift in EITHER is drift.
#[derive(Clone, Debug, PartialEq)]
struct CardPin {
    issuer_key: &'static str,
    card_fingerprint: &'static str,
}

impl PinnedArtifact for CardPin {
    fn mechanism(&self) -> &'static str {
        "jws_issuer"
    }
    fn digest(&self) -> String {
        format!("{}+{}", self.issuer_key, self.card_fingerprint)
    }
}

/// The whole lifecycle, written ONCE and parameterised by the artifact. Two pins that must differ,
/// and the capability names differ per plane too (tools vs skills) to keep the vocabulary out of
/// the machine.
fn run_the_lifecycle<A: PinnedArtifact>(pin_a: A, pin_b: A, cap: &str, other: &str) {
    let observed = |pin: &A, pairs: &[(&str, &str)]| -> Sighting<A> {
        Sighting::Seen(Observation {
            pin: Some(pin.clone()),
            capabilities: pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect::<BTreeMap<_, _>>(),
        })
    };

    // register -> pending, serving nothing.
    let mut a: Approval<A> = Approval::registered();
    assert_eq!(a.state(&Sighting::Never), TrustState::Pending);

    // connect captures, and does not promote.
    let first = observed(&pin_a, &[(cap, "h1"), (other, "h2")]);
    assert_eq!(a.state(&first), TrustState::Pending);
    assert!(!a.serves(cap, "h1"));

    // approve -> approved, and serving.
    a.approve(&first, None).expect("approve");
    assert_eq!(a.state(&first), TrustState::Approved);
    assert!(a.serves(cap, "h1"));
    assert!(a.serves(other, "h2"));

    // content drift -> quarantined, dispatch refuses the new hash.
    let content_drift = observed(&pin_a, &[(cap, "MOVED"), (other, "h2")]);
    assert_eq!(a.state(&content_drift), TrustState::Quarantined);
    assert!(!a.serves(cap, "MOVED"));
    assert_eq!(a.drift(&content_drift).changed, vec![cap.to_string()]);

    // per-capability re-approval settles exactly one row.
    a.approve_capability(cap, &content_drift)
        .expect("approve one");
    assert!(a.drift(&content_drift).is_empty());
    assert_eq!(a.state(&content_drift), TrustState::Approved);

    // IDENTITY drift is its own axis, and approve-pin settles it alone.
    let identity_drift = observed(&pin_b, &[(cap, "MOVED"), (other, "h2")]);
    let d = a.drift(&identity_drift);
    assert!(d.pin_changed);
    assert!(
        d.changed.is_empty(),
        "content is unchanged; only the identity moved"
    );
    assert_eq!(a.state(&identity_drift), TrustState::Quarantined);
    a.approve_pin(&identity_drift).expect("approve-pin");
    assert_eq!(a.state(&identity_drift), TrustState::Approved);

    // rejection is permanent and stops being drift.
    a.reject_capability(other);
    assert!(!a.serves(other, "h2"));
    assert!(a.drift(&identity_drift).is_empty());

    // suspension outranks, and only a resume lifts it.
    a.suspend("anomaly");
    assert_eq!(a.state(&identity_drift), TrustState::Suspended);
    assert!(!a.serves(cap, "MOVED"));
    a.resume();
    assert_eq!(a.state(&identity_drift), TrustState::Approved);

    // a failed sighting parks in error.
    assert_eq!(
        a.state(&Sighting::Failed("refused".to_string())),
        TrustState::Error
    );

    // an identity change forces re-approval; the rejection survives it.
    a.unpin();
    assert_eq!(a.state(&identity_drift), TrustState::Pending);
    a.approve(&identity_drift, None).expect("re-approve");
    assert!(a.serves(cap, "MOVED"));
    assert!(
        !a.serves(other, "h2"),
        "the rejection is a standing instruction"
    );
}

/// The MCP instantiation: a cert-SPKI pin over a tool list.
#[test]
fn the_lifecycle_runs_over_a_single_value_transport_pin() {
    run_the_lifecycle(
        SpkiPin("sha256/A"),
        SpkiPin("sha256/B"),
        "read_file",
        "write_file",
    );
}

/// The A2A instantiation: a two-part JWS-issuer-plus-card-fingerprint pin over a skill set. Same
/// machine, same transition table, no MCP anywhere in it.
#[test]
fn the_lifecycle_runs_over_a_two_value_signed_card_pin() {
    run_the_lifecycle(
        CardPin {
            issuer_key: "KEY-1",
            card_fingerprint: "FP-1",
        },
        CardPin {
            issuer_key: "KEY-1",
            card_fingerprint: "FP-2",
        },
        "plan",
        "summarize",
    );
}

/// The two-part artifact drifts when EITHER half moves. A machine that compared only a digest
/// prefix, or that assumed one value, would miss the issuer-key swap, which is the look-alike attack
/// the operator-pinned root exists to catch.
#[test]
fn either_half_of_a_two_value_artifact_is_identity_drift() {
    let approve_with = |pin: CardPin| {
        let mut a = Approval::registered();
        a.approve(
            &Sighting::Seen(Observation {
                pin: Some(pin),
                capabilities: BTreeMap::from([("plan".to_string(), "h1".to_string())]),
            }),
            None,
        )
        .expect("approve");
        a
    };
    let sight = |pin: CardPin| {
        Sighting::Seen(Observation {
            pin: Some(pin),
            capabilities: BTreeMap::from([("plan".to_string(), "h1".to_string())]),
        })
    };
    let base = CardPin {
        issuer_key: "KEY-1",
        card_fingerprint: "FP-1",
    };

    let a = approve_with(base.clone());
    // The card was re-signed by a DIFFERENT issuer: the look-alike case.
    assert!(
        a.drift(&sight(CardPin {
            issuer_key: "KEY-2",
            ..base
        }))
        .pin_changed
    );
    // The issuer is right but the card itself changed: the rug-pull case.
    assert!(
        a.drift(&sight(CardPin {
            card_fingerprint: "FP-2",
            ..base
        }))
        .pin_changed
    );
    // Both halves unchanged: no identity drift.
    assert!(!a.drift(&sight(base)).pin_changed);
}

/// THE RATCHET on the genericity claim, and the reason this file is more than two instantiations.
///
/// Two instantiations prove the machine COMPILES for two shapes today. They do not stop the next
/// change from writing a plane's vocabulary into a transition, and once one plane's noun is in a
/// state name or a branch, the second plane inherits a machine that is about somebody else. So the
/// module's own CODE is checked for plane vocabulary, and a violation is a failing test rather than
/// a review comment somebody has to remember to make.
///
/// PROSE is exempt and must be: the doc comments explain the parameter by naming exactly the two
/// planes it exists for, and that explanation is the most useful thing in the file. So whole-line
/// comments are stripped and only the remaining code is judged.
#[test]
fn the_lifecycle_names_no_plane_in_its_code() {
    const BANNED: &[&str] = &[
        "mcp", "Mcp", "MCP", "a2a", "A2a", "A2A", "tool", "Tool", "agent", "Agent", "skill",
        "Skill", "spki", "Spki", "SPKI", "card", "Card", "server", "Server", "jws", "Jws", "JWS",
    ];
    let source = include_str!("../mod.rs");
    let code: String = source
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for needle in BANNED {
        assert!(
            !code.contains(needle),
            "the plane-neutral lifecycle names `{needle}` in its CODE. A machine that knows one \
             plane's vocabulary is not a machine the other plane can parameterise: move the noun \
             out to the artifact, the capability name, or the caller."
        );
    }
}

/// The MECHANISM label travels with the artifact and is never inferred by the machine. It is what an
/// operator reads and what an audit row records, and the two planes spell it differently.
#[test]
fn the_mechanism_label_belongs_to_the_artifact_not_the_machine() {
    assert_eq!(SpkiPin("x").mechanism(), "cert_spki");
    assert_eq!(
        CardPin {
            issuer_key: "k",
            card_fingerprint: "f"
        }
        .mechanism(),
        "jws_issuer"
    );
}

/// The DIGEST is a rendering for operators and audit rows, and it is NOT the equality test. A
/// multi-part artifact must render every part it is compared on, or an audit row saying "pin
/// changed" cannot show WHICH half changed, and two genuinely different identities could print
/// identically.
#[test]
fn a_multi_part_artifact_renders_every_part_it_is_compared_on() {
    let a = CardPin {
        issuer_key: "KEY-1",
        card_fingerprint: "FP-1",
    };
    let rotated_key = CardPin {
        issuer_key: "KEY-2",
        ..a
    };
    let rotated_card = CardPin {
        card_fingerprint: "FP-2",
        ..a
    };
    assert_ne!(a.digest(), rotated_key.digest());
    assert_ne!(a.digest(), rotated_card.digest());
    assert_ne!(rotated_key.digest(), rotated_card.digest());
    // The single-value shape renders its one value, and equality and rendering agree there too.
    assert_eq!(SpkiPin("sha256/A").digest(), "sha256/A");
    assert_ne!(SpkiPin("sha256/A").digest(), SpkiPin("sha256/B").digest());
}
