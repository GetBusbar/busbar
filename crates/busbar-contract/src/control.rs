//! The control kind: an unmetered served surface, and the four calls it answers.
//!
//! A control surface is not a quiet plane. It declares what it answers for the way a plane does —
//! as DATA, a table of rows rather than a decision inside a handler — and it owns the bodies it
//! renders. What it may not do is everything the metered path is made of: it reaches no upstream,
//! it opens no leg, it prices nothing, and it names no money, pool, failover or breaker vocabulary.
//! Those absences are why it is a kind of its own rather than a plane that happens to meter zero:
//! a plane's face has a `route` and a `meter` on it, and a face with a step on it is a face whose
//! implementers are asked the question — the honest answer for this kind is not an empty `RoutePlan`
//! but no method to return one from.
//!
//! So the shape is NARROWER than the plane's seven steps, not wider. Four calls:
//!
//! | call | what it says |
//! | --- | --- |
//! | [`Control::verify`] | where this unit goes — always one of the surface's own operations |
//! | [`Control::admit`] | what the door has to know; a control unit draws no priced dimension |
//! | [`Control::audit`] | what the unit was and how it ended |
//! | [`Control::answer`] | the bytes, whether the operation ran or the loop refused first |
//!
//! WHO IS CALLING is not among them: a control surface reads no credential and decides no identity,
//! because that is the auth kind's whole job and a second reading of one credential is a second
//! answer to one question. WHAT THE CALLER MAY DO is not among them either, for the same reason at
//! the scope unit.
//!
//! AND THE DECODE IS THE DECLARATION. A plane reads bytes to find out what arrived; a control
//! surface has already said, in [`ControlMeta::ROUTES`], every `(method, path)` pair it answers and
//! which operation each one is. The loop resolves the arriving request against that table, so there
//! is nothing left for a decode call to decide — and one table that every reader reads is the only
//! form in which a route matrix cannot drift from itself.

use crate::bounded::{ArenaBytes, Facts};
use crate::dest::DestinationFacts;
use crate::grammar::Claim;
use crate::ids::OpClassId;
use crate::plugin::Plugin;
use crate::unit::{AdmitFacts, AuditFacts, Ctx, Refusal, Unit, UnitEnd};
use crate::wire::Encode;

/// One row of a control surface's route table: an operation, as data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlRoute {
    /// The request method the row is claimed under.
    pub method: &'static str,
    /// The templated path, `{param}` segments and all.
    pub path: &'static str,
    /// The operation this row names.
    pub operation: &'static str,
    /// Which side of the surface's closed read-only/full split the operation falls on.
    pub read_only: bool,
}

/// Everything a control surface declares about itself.
///
/// All of it is a constant, for the reason every kind's declarations are: it is read once at
/// registration and sealed into policy, and a surface that could vary its own route table at run
/// time would be a surface whose claims a boot proved and whose rows nothing did.
pub trait ControlMeta {
    /// The surface's registry key.
    const KEY: &'static str;
    /// The claims this surface makes over arriving bytes.
    const CLAIMS: &'static [Claim];
    /// The route table this surface claims — the control kind's declared open vocabulary.
    const ROUTES: &'static [ControlRoute];
    /// The operation classes this surface's units can be.
    const OP_CLASSES: &'static [OpClassId];
    /// The schema of this surface's own configuration block.
    const CONFIG_SCHEMA: &'static str;
}

/// What one finished control unit has to be rendered from.
///
/// Two arms and no third: either the operation ran and produced bytes, or the loop ended the unit
/// before it did. The facts travel with the served arm because the surface that renders a body is
/// entitled to know which of its own operations produced it, and the executing side is what stamps
/// that back.
#[derive(Debug)]
pub enum Rendering<'u, 'r> {
    /// The operation ran; these are its bytes and the facts the execution stamped.
    Served {
        /// The operation's own bytes.
        body: ArenaBytes<'u>,
        /// The facts the execution stamped back.
        facts: &'r Facts<'u>,
    },
    /// The loop refused; nothing ran.
    Refused(&'r Refusal<'u>),
}

/// An unmetered served surface.
///
/// # Errors
/// [`Control::answer`] returns [`Encode`] when the reply cannot be expressed in this surface's own
/// shape; the kernel then falls back to its own minimal rendering.
pub trait Control: Plugin + Send + Sync + 'static {
    /// Say which of this surface's own operations the unit is for.
    fn verify<'u>(&self, u: &Unit<'u>, ctx: &Ctx<'u>) -> DestinationFacts;

    /// Say what the door has to know. A control unit draws no priced dimension.
    fn admit<'u>(&self, u: &Unit<'u>, ctx: &Ctx<'u>) -> AdmitFacts;

    /// Say what this unit was and how it ended.
    fn audit<'u>(&self, u: &Unit<'u>, out: &UnitEnd, ctx: &Ctx<'u>) -> AuditFacts;

    /// Write the answer, whichever way the unit ended.
    fn answer<'u>(
        &self,
        u: &Unit<'u>,
        rendering: Rendering<'u, '_>,
        ctx: &Ctx<'u>,
    ) -> Result<ArenaBytes<'u>, Encode>;
}
