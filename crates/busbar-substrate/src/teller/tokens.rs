// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The Teller's capability types — sealed by TOKEN, not by visibility.
//!
//! - [`UnitToken<S>`] proves "the loop is running step `S` right now". Only the loop mints one.
//! - [`Decision<S>`] is a step's answer; it can only be built with the token for that same step, so
//!   a plane cannot answer Admit while it is being asked Verify, and cannot skip ahead.
//! - [`Hold`] is what Admit opens; it exists only between Admit and Audit and can only be built with
//!   an Admit token.
//! - [`Posted`] is the proof a unit was audited; only the loop mints it, from an Audit token.
//!
//! None of these is `Clone` or `Copy`: one token per step call, one decision per token, one hold
//! and one posting per unit.
//!
//! ## What a plane cannot do
//!
//! A token for one step cannot build a decision for another:
//!
//! ```compile_fail,E0308
//! use busbar_substrate::teller::{Admit, Decision, Meter, UnitToken};
//!
//! fn forge(token: &UnitToken<Meter>) -> Decision<Admit> {
//!     // The token is for Meter; the decision must be for Meter too.
//!     Decision::proceed(token, ())
//! }
//! ```
//!
//! A plane cannot skip a step by answering with an earlier step's decision:
//!
//! ```compile_fail,E0308
//! use busbar_substrate::teller::{Admit, Decision, Verify, UnitToken};
//!
//! fn skip_ahead(verify: &UnitToken<Verify>) -> Decision<Admit> {
//!     // Verify's decision is not Admit's decision, and no hold was opened.
//!     verify.proceed(())
//! }
//! ```
//!
//! A plane cannot mint a token of its own:
//!
//! ```compile_fail,E0624
//! use busbar_substrate::teller::{Admit, UnitToken};
//!
//! let token = UnitToken::<Admit>::mint();
//! ```
//!
//! A plane cannot construct a `Hold` without an Admit token:
//!
//! ```compile_fail,E0624
//! use busbar_substrate::teller::Hold;
//!
//! let hold = Hold::open(None, None, true);
//! ```
//!
//! A plane cannot mint a `Posted`, even holding an Audit token:
//!
//! ```compile_fail,E0624
//! use busbar_substrate::teller::{Audit, Posted, UnitEnd, UnitToken};
//!
//! fn fake_post(audit: &UnitToken<Audit>) -> Posted {
//!     Posted::mint(audit, UnitEnd::Completed)
//! }
//! ```
//!
//! A `Decision` cannot be duplicated: it is neither `Clone` nor `Copy` (and it is `#[must_use]`, so
//! it cannot be silently dropped either):
//!
//! ```compile_fail,E0599
//! use busbar_substrate::teller::{Decision, Verify};
//!
//! fn twice(d: Decision<Verify>) -> (Decision<Verify>, Decision<Verify>) {
//!     (d.clone(), d)
//! }
//! ```
//!
//! A `Hold` cannot be duplicated either:
//!
//! ```compile_fail,E0599
//! use busbar_substrate::teller::Hold;
//!
//! fn twice(h: Hold) -> (Hold, Hold) {
//!     (h.clone(), h)
//! }
//! ```
//!
//! And a plane cannot open a decision to read it — only the loop reads decisions:
//!
//! ```compile_fail,E0624
//! use busbar_substrate::teller::{Decision, Verify};
//!
//! fn peek(d: Decision<Verify>) {
//!     let _ = d.into_result();
//! }
//! ```

use super::steps::Refusal;
use super::unit::UnitEnd;
use super::{Admit, Audit, Step};
use crate::plane_host::AdmitHandle;
use std::marker::PhantomData;

/// The proof that the loop is running step `S` for the current unit. Handed by reference to the
/// plane's method for that step and dropped when the method returns; the plane never owns one and
/// never sees one for any other step.
#[repr(transparent)]
pub struct UnitToken<S: Step>(PhantomData<fn() -> S>);

impl<S: Step> UnitToken<S> {
    /// Mint the token for step `S`. Only the loop (this module's parent) may call this.
    pub(super) fn mint() -> Self {
        UnitToken(PhantomData)
    }

    /// Answer this step with "proceed", carrying the facts the next step reads.
    pub fn proceed(&self, facts: S::Facts) -> Decision<S> {
        Decision::proceed(self, facts)
    }

    /// Answer this step with a refusal: the plane's own already-shaped response.
    pub fn refuse(&self, resp: axum::response::Response) -> Decision<S> {
        Decision::refuse(self, Refusal::new(resp))
    }
}

impl UnitToken<Admit> {
    /// Open the unit's [`Hold`]. Only reachable while the loop is running Admit, because only then
    /// does the plane hold an Admit token.
    pub fn hold(
        &self,
        admit: Option<AdmitHandle>,
        downgraded: Option<String>,
        charged: bool,
    ) -> Hold {
        Hold::open(admit, downgraded, charged)
    }
}

impl<S: Step> std::fmt::Debug for UnitToken<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UnitToken<{}>", S::NAME)
    }
}

/// A step's answer: proceed with facts for the next step, or refuse with a finished response.
/// Built only with the [`UnitToken`] for the same step; read only by the loop.
#[repr(transparent)]
#[must_use = "a decision that is not returned to the loop silently skips the step"]
pub struct Decision<S: Step>(DecisionInner<S>);

enum DecisionInner<S: Step> {
    Proceed(S::Facts),
    Refuse(Refusal),
}

impl<S: Step> Decision<S> {
    /// Proceed past step `S`, carrying `facts` to the next step. Needs the token for `S`.
    pub fn proceed(_token: &UnitToken<S>, facts: S::Facts) -> Self {
        Decision(DecisionInner::Proceed(facts))
    }

    /// Refuse at step `S`. Needs the token for `S`; the refusal is stamped with `S` so Audit knows
    /// where the unit stopped.
    pub fn refuse(_token: &UnitToken<S>, refusal: Refusal) -> Self {
        Decision(DecisionInner::Refuse(refusal.at(S::NAME)))
    }

    /// Open the decision. Only the loop reads decisions. (`result_large_err`: the refusal carries
    /// the plane's finished `Response` by value, on purpose.)
    #[allow(clippy::result_large_err)]
    pub(super) fn into_result(self) -> Result<S::Facts, Refusal> {
        match self.0 {
            DecisionInner::Proceed(facts) => Ok(facts),
            DecisionInner::Refuse(refusal) => Err(refusal),
        }
    }
}

impl<S: Step> std::fmt::Debug for Decision<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            DecisionInner::Proceed(_) => write!(f, "Decision<{}>::Proceed", S::NAME),
            DecisionInner::Refuse(r) => write!(f, "Decision<{}>::Refuse({r:?})", S::NAME),
        }
    }
}

/// The unit's admission: what Admit opened and Audit must close. Lives from Admit to Audit and
/// nowhere else; has no `Drop` of its own (the admission grant inside releases itself when the last
/// holder lets go, exactly as before), is `#[must_use]`, and is neither `Clone` nor `Copy`, so a
/// unit has at most one.
#[repr(transparent)]
#[must_use = "a hold must reach Audit; dropping it here loses the unit's admission"]
pub struct Hold(HoldInner);

/// The admission facts a hold carries until the ledger takes over this role.
struct HoldInner {
    /// The admission grant (concurrency/budget) the plane opened, if governance is on.
    admit: Option<AdmitHandle>,
    /// The pool the request was downgraded to at the door, if any.
    downgraded: Option<String>,
    /// Whether the door charged the caller (a request counted against the key).
    charged: bool,
}

impl Hold {
    /// Open a hold. Reachable only through [`UnitToken::<Admit>::hold`], i.e. inside Admit.
    pub(super) fn open(
        admit: Option<AdmitHandle>,
        downgraded: Option<String>,
        charged: bool,
    ) -> Self {
        Hold(HoldInner {
            admit,
            downgraded,
            charged,
        })
    }

    /// Whether the door charged the caller for this unit.
    pub fn charged(&self) -> bool {
        self.0.charged
    }

    /// The pool the request was downgraded to at the door, if any.
    pub fn downgraded(&self) -> Option<&str> {
        self.0.downgraded.as_deref()
    }

    /// The admission grant, if one was opened.
    pub fn admit(&self) -> Option<&AdmitHandle> {
        self.0.admit.as_ref()
    }

    /// Take the hold apart — the one consuming read, for the plane's Audit step to finish the unit.
    pub fn into_parts(self) -> (Option<AdmitHandle>, Option<String>, bool) {
        (self.0.admit, self.0.downgraded, self.0.charged)
    }
}

impl std::fmt::Debug for Hold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hold")
            .field("admit", &self.0.admit.is_some())
            .field("downgraded", &self.0.downgraded)
            .field("charged", &self.0.charged)
            .finish()
    }
}

/// The proof that a unit was audited: the loop mints exactly one per unit, from the Audit token,
/// after the plane's Audit step returned. Carries how the unit ended.
#[repr(transparent)]
pub struct Posted(PostedInner);

struct PostedInner {
    end: UnitEnd,
}

impl Posted {
    /// Mint the posting. Only the loop may call this, and only with an Audit token.
    pub(super) fn mint(_audit: &UnitToken<Audit>, end: UnitEnd) -> Self {
        Posted(PostedInner { end })
    }

    /// How the unit ended.
    pub fn end(&self) -> UnitEnd {
        self.0.end
    }
}

impl std::fmt::Debug for Posted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Posted({:?})", self.0.end)
    }
}
