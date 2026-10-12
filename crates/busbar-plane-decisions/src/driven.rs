//! This plane's answers to the kernel plane driver (`BUSBAR-1.6.0.md` Part 3, section 12,
//! "The plane driver"), in this plane's own vocabulary.
//!
//! The driver serves a unit in five crossings, and this module answers each one:
//!
//! | driver crossing | here |
//! |---|---|
//! | the Statement tail | [`tail`]: declaring and consumed sections, dialects, scope kinds, op classes, billable classes, fee units, needs, claims |
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
//! MODEL RESOLUTION (THE DESIGN section 2, the decisions bullet; DECISIONS D8b): "a request routes
//! by its model; one configured model and none named is the default (byte-identical); more than one
//! and none named is 400; an unknown model is 404. `upstream_model` rewrites only the top-level model
//! value, by span splice, when it is set and differs; otherwise the body passes through."
//!
//! | config | `POST /v1/systemone` |
//! |---|---|
//! | `decisions.models: {}` | `404`, the kernel's unclaimed-route body (nothing is claimed) |
//! | one model, none named | routed over that model, the body byte for byte |
//! | several models, none named | `400` ([`Unrouted::Unnamed`]) |
//! | a model named | routed over it; a name no model has is `404` ([`Unrouted::Unknown`]) |
//!
//! With no model configured the snapshot publishes no claim ([`served_claims`]), so the request
//! falls through to the kernel's unclaimed-route body,
//! `{"error":{"code":null,"message":"the requested resource was not found","param":null,"type":"not_found_error"}}`,
//! byte for byte as before. The top-level `model` ([`codec::PTR_MODEL`]) is the one request member
//! this plane reads, and only to route ([`route_model`]) and splice ([`spliced`]).
//!
//! WHAT THIS PLANE DOES NOT CLAIM: `GET /v1/models`. That path keeps its 1.5.5 bytes (the model
//! list busbar already serves there), so [`tail::CLAIMS`] and [`tail::OP_CLASSES`] carry `systemone` alone and
//! [`arrive`] answers the models operation as unclaimed.
//!
//! Money-blind, like the rest of the crate: the plane reports how many decision units the far end
//! said it used, in its one billable class, and never what they are worth.

use busbar_contract::ids::{MeterClassId, OpClassId};

use crate::codec::{
    self, error_body, CONTENT_TYPE_JSON, EGRESS_SCHEME, FIELD_CONTENT_TYPE, PTR_ERROR,
    PTR_USAGE_UNITS,
};
use crate::ops;

/// The plane's Statement tail, as data.
pub mod tail {
    use super::{MeterClassId, OpClassId};
    use crate::{claims, config, meta, ops};

    /// The top-level config section whose presence declares this plane.
    pub const SECTION_DECLARING: &str = config::SECTION;

    /// The sections this plane reads and does not own: every model names its provider there.
    pub const SECTIONS_CONSUMED: &[&str] = &["providers"];

    /// The one dialect this plane speaks. Dialect index 0 everywhere below.
    pub const DIALECTS: &[&str] = &[config::PROTOCOL];

    /// The outbound auth style a jev far end is reached under: the operator's credential as a
    /// bearer (the signed design: "auth = core gateway credential, plane returns a
    /// CredentialLocator, never sees the secret").
    pub const OUTBOUND_STYLE: &str = "bearer";

    /// Each dialect's default outbound auth style, `(dialect index, style)` (the design, "Outbound auth", step 2:
    /// a provider entry's `auth:`, else this; ARCHITECT Q-L1-AUTH (A), 2026-10-03).
    pub const DIALECT_AUTH: &[(u32, &str)] = &[(0, OUTBOUND_STYLE)];

    /// The resource granularity a grant names: a configured decision provider.
    pub const SCOPE_KINDS: &[&str] = &["decision_provider"];

    /// What one registration on this plane is called.
    pub const SUBJECT_NOUN: &str = "decision provider";

    /// The singular noun for one registration in admin responses.
    pub const ADMIN_NOUN: &str = "decision-provider";

    /// The record resource kind a registration is audited under: the scope kind.
    pub const AUDIT_KIND: &str = SCOPE_KINDS[0];

    /// The op classes this plane serves, in index order. `systemone` alone (see the module doc).
    pub const OP_CLASSES: &[OpClassId] = &[ops::OP_SYSTEMONE];

    /// The billable classes, in index order, each with its family: the far end's decision count,
    /// and the fee unit (also a class: the tail check holds `fee_units ⊆ billable_classes`).
    pub const BILLABLE_CLASSES: &[(MeterClassId, &str)] = &[
        (meta::CLASS_DECISION, "decision"),
        (MeterClassId::new(FEE_PER_REQUEST), FEE_FAMILY),
    ];

    /// The index of [`meta::CLASS_DECISION`] in [`BILLABLE_CLASSES`].
    pub const CLASS_DECISION_INDEX: u32 = 0;

    /// THE FEE UNIT: the request fee (`decisions.fees.per_request`), counted `1` on a unit whose
    /// far end answered a success, so a refused or failed unit owes none (the signed design C-3,
    /// "billable-success fee gated kernel-side", the tool plane's twin; ARCHITECT Q-L5-FEE (C)). A
    /// fee unit is no priced class: the rate card never names it.
    pub const FEE_PER_REQUEST: &str = busbar_contract::plane::PER_REQUEST;

    /// The family of the fee unit's class: a count of 0 or 1.
    pub const FEE_FAMILY: &str = "count";

    /// The index of the fee unit's class in [`BILLABLE_CLASSES`].
    pub const CLASS_FEE_INDEX: u32 = 1;

    /// The fee units this plane counts.
    pub const FEE_UNITS: &[&str] = &[FEE_PER_REQUEST];

    /// The connection needs, `(transport, auth)`, for the far-end direction: its dialect's style, the
    /// one a member resolves to by default (a member is bound on the need its resolved style names).
    /// The plane names the style and never holds what is behind it.
    pub const NEEDS: &[(&str, &str)] = &[(claims::TRANSPORT, OUTBOUND_STYLE)];

    /// The claims the generation snapshot publishes, `(verb, target)`.
    pub const CLAIMS: &[(&str, &str)] = &[("POST", ops::PATH_SYSTEMONE)];
}

/// The claims a generation's snapshot publishes, given how many `decisions.models` it configures:
/// [`tail::CLAIMS`] for one or more, none for none (see the module doc's table).
#[must_use]
pub fn served_claims(models: usize) -> &'static [(&'static str, &'static str)] {
    if models == 0 {
        &[]
    } else {
        tail::CLAIMS
    }
}

/// Why a claimed request routes over no configured model (THE DESIGN section 2: "more than one and
/// none named is 400; an unknown model is 404").
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unrouted {
    /// The request names no model and the generation configures several.
    Unnamed,
    /// The request's `model` is not a string.
    NotAName,
    /// The request names a model the generation does not configure.
    Unknown(String),
}

impl Unrouted {
    /// The status the refusal wears.
    #[must_use]
    pub const fn status(&self) -> u16 {
        match self {
            Self::Unnamed | Self::NotAName => 400,
            Self::Unknown(_) => 404,
        }
    }

    /// The words the caller reads, in the dialect's error shape ([`refusal_body`]).
    #[must_use]
    pub fn text(&self) -> String {
        match self {
            Self::Unnamed => "the request names no model, and several decisions models are \
                              configured: name one in `model`"
                .to_string(),
            Self::NotAName => "`model` must be a string naming a decisions model".to_string(),
            Self::Unknown(model) => {
                format!("The model '{model}' does not exist or you do not have access to it.")
            }
        }
    }
}

/// The top-level `model` a request body names: `Ok(None)` when it names none, and
/// [`Unrouted::NotAName`] when the member is there but is not a string.
///
/// # Errors
///
/// [`Unrouted::NotAName`], as above.
pub fn requested_model(body: &[u8]) -> Result<Option<std::borrow::Cow<'_, str>>, Unrouted> {
    let Some(raw) = codec::read_raw(body, codec::PTR_MODEL) else {
        return Ok(None);
    };
    if let Ok(name) = serde_json::from_slice::<&str>(raw) {
        return Ok(Some(std::borrow::Cow::Borrowed(name)));
    }
    serde_json::from_slice::<String>(raw)
        .map(|name| Some(std::borrow::Cow::Owned(name)))
        .map_err(|_| Unrouted::NotAName)
}

/// THE MODEL A CLAIMED REQUEST ROUTES OVER among `models` (the generation's configured names, each
/// with what this plane keeps of it): the one it names, else the only one configured. Answers the
/// configured name and its entry.
///
/// # Errors
///
/// [`Unrouted`]: several configured and none named, a `model` that is not a string, or a name none
/// of `models` has.
pub fn route_model<'m, V>(
    body: &[u8],
    models: &'m std::collections::BTreeMap<String, V>,
) -> Result<(&'m str, &'m V), Unrouted> {
    match requested_model(body)? {
        Some(name) => models
            .get_key_value(name.as_ref())
            .map(|(k, v)| (k.as_str(), v))
            .ok_or_else(|| Unrouted::Unknown(name.into_owned())),
        None => {
            let mut all = models.iter();
            match (all.next(), all.next()) {
                (Some((k, v)), None) => Ok((k.as_str(), v)),
                _ => Err(Unrouted::Unnamed),
            }
        }
    }
}

/// THE `upstream_model` SPLICE: `body` with its top-level `model` value replaced by `upstream`, when
/// the body names a model and it differs from `upstream`; `None` when the body passes through
/// unchanged. Every byte outside the value's span is kept: member order, whitespace and the rest of
/// the document are the caller's.
#[must_use]
pub fn spliced(body: &[u8], upstream: &str) -> Option<Vec<u8>> {
    let busbar_contract::spans::Resolved::Found(span) =
        busbar_contract::spans::resolve_pointer(body, codec::PTR_MODEL)
    else {
        return None;
    };
    let named = requested_model(body).ok().flatten()?;
    if named == upstream {
        return None;
    }
    let value = serde_json::to_string(upstream).ok()?;
    let mut out = Vec::with_capacity(body.len() - (span.end - span.start) + value.len());
    out.extend_from_slice(body.get(..span.start)?);
    out.extend_from_slice(value.as_bytes());
    out.extend_from_slice(body.get(span.end..)?);
    Some(out)
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
/// jev names no provider on the wire, so the member changes nothing in the request. Named
/// `attempt_request`, not `attempt`, so it is not a cross-plane re-spelling of llm/a2a's `attempt`
/// (structure-lint plane-dup; ARCHITECT ruling 2b 2026-10-04).
#[must_use]
pub fn attempt_request(caller_body: &[u8]) -> FarEndRequest<'_> {
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

    /// The units the far end reported, read at the last piece, by the rule the plane's
    /// `decode_response` reads them (`plane.rs`): a count is reported only for an answer with no
    /// `/error` member, whose `/usage/units` is a whole number a signed 64-bit count holds. An
    /// error answer, or a count that is missing, negative, fractional or past `i64::MAX`, reports
    /// nothing. The status plays no part: `decode_response` judges success by the `/error` member
    /// alone.
    #[must_use]
    pub fn units(&self) -> Option<Units> {
        if codec::has(&self.body, PTR_ERROR) {
            return None;
        }
        codec::read_u64(&self.body, PTR_USAGE_UNITS)
            .filter(|amount| i64::try_from(*amount).is_ok())
            .map(|amount| Units {
                class: tail::CLASS_DECISION_INDEX,
                reported: true,
                amount,
            })
    }

    /// THE REQUEST FEE, read at the last piece: `1` of [`tail::FEE_PER_REQUEST`] for an answer the
    /// far end gave as a success — a `2xx` status and no `/error` member, the success rule
    /// [`Self::units`] reads — and nothing otherwise, so a refused or failed unit owes no fee
    /// (billable success only).
    #[must_use]
    pub fn fee(&self, status: Option<u32>) -> Option<Units> {
        let success = status.is_some_and(|s| (200..300).contains(&s));
        (success && !codec::has(&self.body, PTR_ERROR)).then_some(Units {
            class: tail::CLASS_FEE_INDEX,
            reported: true,
            amount: 1,
        })
    }
}

/// THE CALLER FIELDS THE FAR END NEVER RECEIVES: the ones the plane writes itself (the document
/// type), the ones naming the hop (`host`), and the credential carriers (the far end is presented
/// the member's credential by the kernel, never the caller's). Compared without case. Hop-by-hop
/// fields and the body framing never reach the plane (the framer drops them).
pub const NOT_RELAYED: &[&str] = &[
    FIELD_CONTENT_TYPE,
    "host",
    "authorization",
    "proxy-authorization",
];

/// THE CALLER'S FIELDS THE FAR END RECEIVES, in the order the caller sent them, a repeated name
/// keeping every value: every field the caller sent but [`NOT_RELAYED`]'s (a same-dialect relay
/// passes every header but the governed set; ARCHITECT DEC-SERVE Q2, the OWNER's DIALECT-FIDELITY
/// F2). Names are lowercased, as the wire compares them.
#[must_use]
pub fn relayed_fields<'f>(
    caller: impl IntoIterator<Item = (&'f [u8], &'f [u8])>,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    caller
        .into_iter()
        .filter(|(name, _)| {
            !NOT_RELAYED
                .iter()
                .any(|n| name.eq_ignore_ascii_case(n.as_bytes()))
        })
        .map(|(name, value)| (name.to_ascii_lowercase(), value.to_vec()))
        .collect()
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
