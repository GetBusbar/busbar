// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PIN AN OPERATOR DECLARED, read out of config ONCE. **Core owns the sequence; a plane
//! supplies its artifact.**
//!
//! ## What was measured before this existed
//!
//! `mcp/catalogue.rs::declared_pin` and `a2a/config.rs::declared_pin` were the same three questions
//! asked twice, and the ledger's `declared_pin` row is the bare-name collision they made. Tabulated:
//!
//! | # | question | MCP | A2A | whose |
//! |---|---|---|---|---|
//! | 1 | is the named mechanism an authenticity ROOT at all? | `!Unpinned` | `!Unpinned` | **CORE asks, plane answers** |
//! | 2 | what is this plane's artifact when it is NOT? | `None` | `Some(Unpinned)` | plane |
//! | 3 | is the operator's key material actually THERE? | `!k.trim().is_empty()` | (absent) | **CORE** |
//! | 4 | what is this plane's artifact when it IS? | `TransportPin::declared` | four-arm match on the mechanism | plane |
//!
//! Questions 1 and 3 are core's, and question 3 is the reason this is worth doing rather than a
//! tidy-up: MCP refused a present-but-blank `pin.key:` and **A2A did not**. A2A's parse-time
//! `is_a_root` rule refuses one at boot, so nothing reachable changed when the rule moved here —
//! but "one plane checks it at the reader and the other relies on a check somewhere else" is
//! exactly the shape `structure-lint`'s plane-coherence invariant exists to name. Now the reader
//! refuses it on BOTH planes, which is a NARROWING: after this, no plane's reader can be talked
//! into building an artifact out of `""`.
//!
//! ## The mechanism is the PLANE'S type, and core never reads its token
//!
//! [`Declares::Mechanism`] is an associated type, so a plane matches its own closed enum with no
//! `_` arm rather than matching a string core handed it. Core asks the mechanism exactly ONE
//! question ([`Declares::is_a_root`]) and never sees `token()` at all, which is the same rule
//! [`super::PinnedArtifact::mechanism`] states: the machine does not interpret the operator's word
//! for a mechanism, so it cannot acquire a per-mechanism special case by accident.
//!
//! ## What a plane still writes, and it is the honest list
//!
//! One [`Declares`] impl: which of its mechanisms is a root, and its artifact for each
//! [`Reading`]. It writes NO sequence, NO blank-key rule and NO `Option` contract.
//! `a_third_plane_costs_one_declares_impl_and_nothing_else` declares a pin for a plane busbar does
//! not have, deliberately unlike both real ones, and drives the whole reader through it.
//!
//! ## `None` is "nothing to hand [`super::Approval::declared`]", never "approved anyway"
//!
//! The return is an `Option` because that is the constructibility question
//! [`super::Approval::declared`] is built around: with no artifact there is nothing to declare, so
//! the registration can only be [`super::Approval::registered`] — pending, and serving nothing.
//! Every `None` below is therefore fail-CLOSED, and a plane cannot widen that by returning `Some`
//! from an arm core did not reach.

use super::PinnedArtifact;

/// THE OPERATOR'S `pin:` OBJECT, as the plane that owns the grammar read it.
///
/// Facts, never decisions. Both planes spell this object `{mechanism, key?}` with A2A adding
/// `fingerprint?`; a plane that binds no fingerprint passes `None` and its [`Declares`] impl never
/// looks at the field.
pub(crate) struct Declaration<'a, M> {
    /// Which root the operator named, in this plane's own spelling.
    pub(crate) mechanism: M,
    /// The out-of-band material, exactly as written. Core tests only whether it is THERE.
    pub(crate) key: Option<&'a str>,
    /// The artifact fingerprint the operator has already approved, where their plane has one.
    pub(crate) fingerprint: Option<&'a str>,
}

/// WHAT CORE CONCLUDED about one [`Declaration`]. A closed set, and deliberately not
/// `#[non_exhaustive]`: adding a variant must BREAK every plane until each has given it an artifact.
pub(crate) enum Reading<'a, M> {
    /// The operator named NO authenticity root. Whether that is an artifact at all is the plane's
    /// ruling: A2A names it out loud ([`crate::a2a::pin::CardPin::Unpinned`]) so a registration list
    /// shows which entries have no root, and MCP spells it `None` so an unrooted registration cannot
    /// be handed to [`super::Approval::declared`] at all. Both are fail-closed; they are not the
    /// same sentence, and core does not pick one.
    NoRoot {
        /// The mechanism as written, for a plane that renders it.
        mechanism: M,
    },
    /// A root, with the material core requires present: a `key` that is not absent and not blank.
    Rooted {
        /// The mechanism as written. The plane matches its own enum here.
        mechanism: M,
        /// The operator's material, VERBATIM — not trimmed. Core tested it for blankness and
        /// changed nothing: a key an operator can compare by eye against what their vendor
        /// published is worth more than one this reader silently re-rendered.
        key: &'a str,
        /// The approved fingerprint, or `None` for "capture it at `connect` and let me approve it",
        /// which is the normal first registration and is not an error.
        fingerprint: Option<&'a str>,
    },
}

/// WHAT A PLANE SUPPLIES TO HAVE ITS DECLARED PIN READ: one impl, two answers, no sequence.
pub(crate) trait Declares: PinnedArtifact + Sized {
    /// This plane's spelling of WHICH root. Its own closed enum, so [`Declares::artifact`] is a
    /// total match over it and a mechanism added later is a compile error until it has an artifact.
    type Mechanism: Copy;

    /// Is this mechanism an authenticity root at all? The ONE question core asks of a mechanism.
    ///
    /// Both planes answer it with the same predicate they already use at parse time to decide
    /// whether `pin.key:` is required, which is what keeps the reader and the boot-time refusal
    /// from disagreeing about what "rooted" means.
    fn is_a_root(mechanism: Self::Mechanism) -> bool;

    /// This plane's artifact for one reading, or `None` for "nothing is declared yet".
    ///
    /// There is no default and no `_` arm that stays right: the argument is a closed enum, so a
    /// reading core grows later is a compile error in every plane until it has been given an answer.
    fn artifact(reading: Reading<'_, Self::Mechanism>) -> Option<Self>;
}

/// THE SEQUENCE. Question 1, then question 3, then the plane.
///
/// ## Why the order is this order
///
/// The root question is first because an unrooted registration has nothing to say about material:
/// `unpinned` carrying a key is refused at boot, and asking about the key first would make this
/// reader's answer for a mechanism that needs none depend on a field that means nothing to it.
/// Blankness is second and is core's, because "a pin with nothing to verify with is not a pin" is
/// a statement about pinning rather than about either dialect.
pub(crate) fn declared_pin<A: Declares>(declaration: Declaration<'_, A::Mechanism>) -> Option<A> {
    let Declaration {
        mechanism,
        key,
        fingerprint,
    } = declaration;

    // (1) IS THERE A ROOT HERE AT ALL.
    if !A::is_a_root(mechanism) {
        return A::artifact(Reading::NoRoot { mechanism });
    }

    // (3) THE MATERIAL. Absent and present-but-whitespace are ONE answer on purpose: a `key: "  "`
    // reads to an operator as a pin and verifies against nothing, so treating it as material would
    // be the reader inventing a trust root out of a typo.
    let key = key.filter(|k| !k.trim().is_empty())?;

    // (2)(4) THE PLANE'S.
    A::artifact(Reading::Rooted {
        mechanism,
        key,
        fingerprint,
    })
}

#[cfg(test)]
#[path = "tests/declared_tests.rs"]
mod declared_tests;
