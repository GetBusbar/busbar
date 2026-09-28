//! The decisions plane's answers to the kernel plane driver (`BUSBAR-1.6.0.md` Part 3, section 12,
//! "The plane driver"), in this plane's own vocabulary.
//!
//! The driver serves a unit in five crossings, and this module answers each one:
//!
//! | driver crossing | here |
//! |---|---|
//! | the Statement tail | [`tail`]: sections, dialects, scope kinds, op classes, billable classes, fee units, needs, claims |
//! | `arrive` | [`arrive`]: the op class, the principal need and the dialect of a claimed request |
//! | `on_piece`, from the caller | [`caller_piece`]: the caller's whole body arrives as one piece; the kernel keeps it |
//! | `on_piece`, ATTEMPT (from the kernel) | [`attempt`]: the request bound for the far end, verb and target explicit |
//! | `on_piece`, from the far end | [`FarEndReading`]: the bytes relayed unchanged, and the units the far end reported |
//! | `refusal` | [`refusal_body`]: the kernel's status and text, in this dialect's error shape |
//!
//! Every answer is plain data. Nothing here holds a byte across calls: [`FarEndReading`] is a value
//! the caller owns for the length of one unit, and it is the only accumulating thing in the module.
//! Writing these answers into the host buffers of the plane ABI (`busbar_contract::abi::plane`) is
//! the plane door's job, one generic adapter for every plane; it is not this plane's.
//!
//! WHAT THIS PLANE DOES NOT CLAIM: `GET /v1/models`. That path keeps its 1.5.5 bytes (the LLM
//! plane's model list), so [`tail::CLAIMS`] and [`tail::OP_CLASSES`] carry `systemone` alone and
//! [`arrive`] answers the models operation as unclaimed.
//!
//! Money-blind, like the rest of the crate: the plane reports how many decision units the far end
//! said it used, in its one billable class, and never what they are worth.

use busbar_contract::ids::{MeterClassId, OpClassId};

use crate::codec::{self, PTR_ERROR, PTR_USAGE_UNITS};
use crate::ops;
use crate::plane::{error_body, CONTENT_TYPE_JSON, EGRESS_SCHEME, FIELD_CONTENT_TYPE};

/// The plane's Statement tail, as data.
pub mod tail {
    use super::{MeterClassId, OpClassId};
    use crate::{claims, config, meta, ops};

    /// The top-level config section whose presence declares this plane.
    pub const SECTION_DECLARING: &str = "decisions";

    /// The sections this plane reads and does not own: every model names its provider there.
    pub const SECTIONS_CONSUMED: &[&str] = &["providers"];

    /// The one dialect this plane speaks. Dialect index 0 everywhere below.
    pub const DIALECTS: &[&str] = &[config::PROTOCOL];

    /// The resource granularity a grant names: a configured decision provider.
    pub const SCOPE_KINDS: &[&str] = &["decision_provider"];

    /// The op classes this plane serves, in index order. `systemone` alone (see the module doc).
    pub const OP_CLASSES: &[OpClassId] = &[ops::OP_SYSTEMONE];

    /// The billable classes, in index order, each with its family.
    pub const BILLABLE_CLASSES: &[(MeterClassId, &str)] = &[(meta::CLASS_DECISION, "decision")];

    /// The index of [`meta::CLASS_DECISION`] in [`BILLABLE_CLASSES`].
    pub const CLASS_DECISION_INDEX: u32 = 0;

    /// The fee units this plane counts. None: the only thing a jev unit reports is the far end's
    /// own decision count.
    pub const FEE_UNITS: &[&str] = &[];

    /// The connection needs, `(transport, auth)`, for the far-end direction. The plane names the
    /// auth scheme and never holds what is behind it.
    pub const NEEDS: &[(&str, &str)] = &[(claims::TRANSPORT, super::EGRESS_SCHEME)];

    /// The claims the generation snapshot publishes, `(verb, target)`.
    pub const CLAIMS: &[(&str, &str)] = &[("POST", ops::PATH_SYSTEMONE)];
}

/// Whether the kernel must verify a principal before the first piece.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrincipalNeed {
    /// No principal.
    None,
    /// A principal is verified before the first piece.
    Required,
    /// A principal is used when one is presented.
    Optional,
}

/// A claimed request, classified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arrived {
    /// The operation, by name.
    pub op: OpClassId,
    /// Its index in [`tail::OP_CLASSES`].
    pub op_class: u32,
    /// Whether a principal is verified first.
    pub principal: PrincipalNeed,
    /// Its index in [`tail::DIALECTS`].
    pub dialect: u32,
}

/// Classify an arriving request by its verb and target. `None` for anything this plane does not
/// claim, including `GET /v1/models`.
#[must_use]
pub fn arrive(verb: &str, target: &str) -> Option<Arrived> {
    let row = ops::row_for(verb, target)?;
    let op_class = tail::OP_CLASSES.iter().position(|op| *op == row.op)?;
    Some(Arrived {
        op: row.op,
        op_class: u32::try_from(op_class).ok()?,
        // A decision is billed to someone: the provider account is the deployment's, and the unit
        // is the caller's.
        principal: PrincipalNeed::Required,
        dialect: 0,
    })
}

/// What the plane says to a piece of the caller's body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallerAnswer {
    /// Nothing to emit. The kernel keeps the body and re-pushes it on every attempt.
    Keep,
    /// The body ended empty: a `systemone` request carries the caller's state, so there is nothing
    /// to forward. The kernel refuses the unit.
    Empty,
}

/// Answer a caller piece. The kernel gathers the whole body and pushes it as one piece.
#[must_use]
pub fn caller_piece(bytes: &[u8], last: bool) -> CallerAnswer {
    if last && bytes.is_empty() {
        CallerAnswer::Empty
    } else {
        CallerAnswer::Keep
    }
}

/// The request bound for the far end, answered to an ATTEMPT piece.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FarEndRequest<'a> {
    /// The verb, explicit.
    pub verb: &'static str,
    /// The target, explicit.
    pub target: &'static str,
    /// The dialect fields. The kernel adds the auth fields for [`FarEndRequest::auth`].
    pub fields: [(&'static str, &'static [u8]); 1],
    /// The auth scheme the kernel decorates the request under.
    pub auth: &'static str,
    /// The caller's body, unchanged: byte identity is the dialect.
    pub body: &'a [u8],
}

/// Answer an ATTEMPT piece: the same request on every attempt, whichever member the kernel picked.
/// jev names no provider on the wire, so the member changes nothing in the request.
#[must_use]
pub fn attempt(caller_body: &[u8]) -> FarEndRequest<'_> {
    FarEndRequest {
        verb: "POST",
        target: ops::PATH_SYSTEMONE,
        fields: [(FIELD_CONTENT_TYPE, CONTENT_TYPE_JSON)],
        auth: EGRESS_SCHEME,
        body: caller_body,
    }
}

/// One unit count, as the plane reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Units {
    /// Index into [`tail::BILLABLE_CLASSES`].
    pub class: u32,
    /// Reported by the far end. The plane never estimates a decision count.
    pub reported: bool,
    /// The cumulative count.
    pub amount: u64,
}

/// The far end's answer, read as it is relayed.
///
/// Every piece is relayed to the caller unchanged, as it arrives. The count lives inside the body
/// (`/usage/units`), so the bytes are also kept until the last piece, and the count is read once,
/// over the whole answer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FarEndReading {
    body: Vec<u8>,
}

impl FarEndReading {
    /// A reading with nothing received.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Take one far-end piece and return the bytes to relay to the caller: the piece itself.
    pub fn piece<'p>(&mut self, bytes: &'p [u8]) -> &'p [u8] {
        self.body.extend_from_slice(bytes);
        bytes
    }

    /// The units the far end reported, read at the last piece.
    ///
    /// A count is reported only for a successful answer (a 2xx status and no `/error` member)
    /// whose `/usage/units` is a whole number. An error answer, or a count that is missing,
    /// negative or fractional, reports nothing.
    #[must_use]
    pub fn units(&self, status: u16) -> Option<Units> {
        if !(200..300).contains(&status) || codec::has(&self.body, PTR_ERROR) {
            return None;
        }
        codec::read_u64(&self.body, PTR_USAGE_UNITS).map(|amount| Units {
            class: tail::CLASS_DECISION_INDEX,
            reported: true,
            amount,
        })
    }
}

/// Render a refusal the kernel decided, in this dialect's error shape: `{"error": {"code", "message"}}`.
/// The kernel chose the status and wrote the text; the plane chooses only the code word for the
/// status.
#[must_use]
pub fn refusal_body(status: u16, text: &str) -> Vec<u8> {
    let code = match status {
        403 | 429 => "unsupported_operation",
        404 => "invalid_params",
        400..=499 => "invalid_request",
        500 => "internal",
        _ => "unsupported_operation",
    };
    error_body(code, text)
}

#[cfg(test)]
#[path = "tests/driven.rs"]
mod tests;
