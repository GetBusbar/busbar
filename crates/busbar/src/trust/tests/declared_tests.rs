// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DECLARED-PIN READER, driven by a plane busbar does not have.
//!
//! The claim this file exists to hold is `a_third_plane_costs_one_declares_impl_and_nothing_else`,
//! and it is only worth anything if the third plane is deliberately UNLIKE both real ones. `MeshPin`
//! is:
//!
//! - **not MCP-shaped**: it NAMES its unrooted state instead of spelling it `None`, so the reader's
//!   `NoRoot` arm has to be a real answer rather than a synonym for absence;
//! - **not A2A-shaped**: it binds NO fingerprint at all, and it carries the mechanism token INSIDE
//!   the value rather than in a field beside it;
//! - **shaped like neither**: it has a mechanism its own grammar treats as rooted-but-keyless-once-
//!   trimmed, which is what puts core's blank-key rule under load from a direction neither real
//!   plane exercises.
//!
//! Every other property below — the order of the questions, the blank-key refusal, the `Option`
//! contract — is asserted through that same impl, because if any of them had stayed on a plane the
//! third plane would have had to write it too.

use super::super::PinnedArtifact;
use super::{declared_pin, Declaration, Declares, Reading};

/// The third plane's mechanism vocabulary. Three variants, none of them spelled like either real
/// plane's, and TWO of them unrooted — so `is_a_root` cannot be a `!matches!(x, Unpinned)` that
/// happens to be right by luck.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MeshMechanism {
    /// A rendezvous key the operator holds out of band.
    RendezvousKey,
    /// A hardware attestation quote root.
    Attested,
    /// Anonymous mesh membership: joinable, never delegable.
    Anonymous,
    /// A member that has been explicitly de-rooted by the mesh operator.
    Revoked,
}

/// The third plane's artifact. It NAMES its unrooted states (unlike MCP) and binds NO fingerprint
/// (unlike A2A), and the mechanism token lives in the value (unlike both).
#[derive(Clone, Debug, PartialEq)]
enum MeshPin {
    Rooted { token: &'static str, key: String },
    NoRoot { token: &'static str },
}

impl PinnedArtifact for MeshPin {
    fn mechanism(&self) -> &'static str {
        match self {
            MeshPin::Rooted { token, .. } | MeshPin::NoRoot { token } => token,
        }
    }
    fn digest(&self) -> String {
        match self {
            MeshPin::Rooted { token, key } => format!("{token}:{key}"),
            MeshPin::NoRoot { token } => token.to_string(),
        }
    }
}

/// THE WHOLE OF WHAT THE THIRD PLANE WRITES. One impl, two answers, no sequence.
impl Declares for MeshPin {
    type Mechanism = MeshMechanism;

    fn is_a_root(mechanism: Self::Mechanism) -> bool {
        matches!(
            mechanism,
            MeshMechanism::RendezvousKey | MeshMechanism::Attested
        )
    }

    fn artifact(reading: Reading<'_, Self::Mechanism>) -> Option<Self> {
        let token = |m: MeshMechanism| match m {
            MeshMechanism::RendezvousKey => "rendezvous_key",
            MeshMechanism::Attested => "attested",
            MeshMechanism::Anonymous => "anonymous",
            MeshMechanism::Revoked => "revoked",
        };
        match reading {
            Reading::NoRoot { mechanism } => Some(MeshPin::NoRoot {
                token: token(mechanism),
            }),
            Reading::Rooted { mechanism, key, .. } => Some(MeshPin::Rooted {
                token: token(mechanism),
                key: key.to_string(),
            }),
        }
    }
}

fn declare(mechanism: MeshMechanism, key: Option<&str>) -> Option<MeshPin> {
    declared_pin::<MeshPin>(Declaration {
        mechanism,
        key,
        fingerprint: None,
    })
}

/// THE PROOF. A plane busbar does not have, deliberately unlike both it does, gets the entire
/// declared-pin reader for ONE `Declares` impl: it writes no sequence, no root/material ordering,
/// no blank-key rule and no `Option` contract, and all four hold for it anyway.
///
/// The analogue of `crate::audit`'s `a_fourth_stream_costs_a_record_type_and_nothing_else`. What
/// makes it a proof rather than a demonstration is that every assertion below is about behaviour
/// `MeshPin` never wrote a line for.
#[test]
fn a_third_plane_costs_one_declares_impl_and_nothing_else() {
    // (1) THE ROOT QUESTION IS ASKED FIRST, and it is asked of the PLANE. Both of this plane's
    // unrooted mechanisms reach `NoRoot` — with the mechanism intact, so a plane that renders it
    // still can — and neither is confused with "no material".
    assert_eq!(
        declare(MeshMechanism::Anonymous, None),
        Some(MeshPin::NoRoot { token: "anonymous" }),
        "an unrooted mechanism must reach the plane's NoRoot answer"
    );
    assert_eq!(
        declare(MeshMechanism::Revoked, None),
        Some(MeshPin::NoRoot { token: "revoked" }),
        "a SECOND unrooted mechanism proves the root question is the plane's, not a core guess"
    );

    // The root question is asked BEFORE the material question: an unrooted mechanism that somehow
    // carries material still reads as unrooted rather than as a pin.
    assert_eq!(
        declare(MeshMechanism::Anonymous, Some("leftover")),
        Some(MeshPin::NoRoot { token: "anonymous" }),
        "order: the root question is answered before the key is ever looked at"
    );

    // (2) THE MATERIAL QUESTION IS CORE'S, and the third plane wrote none of it. Absent, empty and
    // whitespace-only are ONE answer, and that answer is `None` — nothing to hand
    // `Approval::declared`, which is the fail-closed floor.
    for blank in [None, Some(""), Some("   "), Some("\t\n ")] {
        assert_eq!(
            declare(MeshMechanism::RendezvousKey, blank),
            None,
            "a rooted mechanism with no usable material must declare nothing (key: {blank:?})"
        );
    }

    // (3) MATERIAL REACHES THE PLANE VERBATIM. Core tested it for blankness and changed nothing —
    // an operator compares this string by eye against what their vendor published.
    assert_eq!(
        declare(MeshMechanism::Attested, Some("  QUOTE-ROOT  ")),
        Some(MeshPin::Rooted {
            token: "attested",
            key: "  QUOTE-ROOT  ".to_string()
        }),
        "the key must arrive untrimmed; core tests it and does not rewrite it"
    );

    // (4) AND THE ARTIFACT IS THE PLANE'S OWN, all the way out to `PinnedArtifact`, with no core
    // vocabulary anywhere in it.
    let pin = declare(MeshMechanism::RendezvousKey, Some("K")).expect("a complete declaration");
    assert_eq!(pin.mechanism(), "rendezvous_key");
    assert_eq!(pin.digest(), "rendezvous_key:K");
}

/// The `fingerprint` a plane does not bind is carried past it untouched, so a two-part plane and a
/// one-part plane share the reader without either learning the other's arity. Asserted on the third
/// plane, which ignores the field entirely: handing it one changes nothing about the answer.
#[test]
fn a_fingerprint_a_plane_does_not_bind_changes_nothing() {
    let without = declared_pin::<MeshPin>(Declaration {
        mechanism: MeshMechanism::Attested,
        key: Some("K"),
        fingerprint: None,
    });
    let with = declared_pin::<MeshPin>(Declaration {
        mechanism: MeshMechanism::Attested,
        key: Some("K"),
        fingerprint: Some("sha256/IGNORED"),
    });
    assert_eq!(
        without, with,
        "a plane that binds no fingerprint must be unaffected by one being present"
    );
}
