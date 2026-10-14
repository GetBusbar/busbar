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
//! the caller owns for the length of one unit, in fixed space, and it is the only accumulating
//! thing in the module.
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
//! THE SECOND DIALECT (THE DESIGN section 2): "NanoJev is the one, dialect `nanojev`: `/api/evaluate`
//! is its second exact claim; a model's dialect is its override or its provider's protocol; a model
//! of the wrong dialect gets that dialect's existing unknown-model refusal; it meters the upstream's
//! own billing unit, counted from the answer already read (`execution.states`; an answer with no
//! count refuses loudly ...), with no extra egress". Each dialect's claim is published when the
//! generation configures a model of that dialect ([`served_claims`]); a request routes among the
//! models of the dialect its claim is ([`route_model`]), so a model of the other dialect is that
//! dialect's unknown model (`404`). Its answer is read by its dialect's count
//! ([`FarEndReading::for_dialect`]): `/execution/states`, required.
//!
//! WHAT THIS PLANE DOES NOT CLAIM: `GET /v1/models`. That path keeps its 1.5.5 bytes (the model
//! list busbar already serves there), so [`tail::CLAIMS`] and [`tail::OP_CLASSES`] carry `systemone` alone and
//! [`arrive`] answers the models operation as unclaimed.
//!
//! Money-blind, like the rest of the crate: the plane reports what a successful answer bills, in its
//! billable classes, and never what it is worth (THE DESIGN section 7, the owner money rulings
//! 2026-09-28: "bills one `decision` per successful, settled answer from every provider; its card
//! prices `decision`, `input_tokens` and `output_tokens` (family `decision`, all three required, 0
//! = free); the hosted provider keeps 1.5.5's `/usage/units` as the decision count").

use busbar_contract::ids::{MeterClassId, OpClassId};

use crate::codec::{
    self, error_body, CONTENT_TYPE_JSON, EGRESS_SCHEME, FIELD_CONTENT_TYPE, PTR_EXECUTION_STATES,
    PTR_USAGE_INPUT_TOKENS, PTR_USAGE_OUTPUT_TOKENS, PTR_USAGE_UNITS,
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

    /// The dialects this plane speaks, in index order: `jev` ([`DIALECT_JEV`]) and `nanojev`
    /// ([`DIALECT_NANOJEV`]).
    pub const DIALECTS: &[&str] = config::PROTOCOLS;

    /// The index of `jev` in [`DIALECTS`].
    pub const DIALECT_JEV: u32 = 0;

    /// The index of `nanojev` in [`DIALECTS`].
    pub const DIALECT_NANOJEV: u32 = 1;

    /// The outbound auth style a jev far end is reached under: the operator's credential as a
    /// bearer (the signed design: "auth = core gateway credential, plane returns a
    /// CredentialLocator, never sees the secret").
    pub const OUTBOUND_STYLE: &str = "bearer";

    /// Each dialect's default outbound auth style, `(dialect index, style)` (the design, "Outbound auth", step 2:
    /// a provider entry's `auth:`, else this; ARCHITECT Q-L1-AUTH (A), 2026-10-03).
    pub const DIALECT_AUTH: &[(u32, &str)] = &[
        (DIALECT_JEV, OUTBOUND_STYLE),
        (DIALECT_NANOJEV, OUTBOUND_STYLE),
    ];

    /// The resource granularity a grant names: a configured decision provider.
    pub const SCOPE_KINDS: &[&str] = &["decision_provider"];

    /// What one registration on this plane is called.
    pub const SUBJECT_NOUN: &str = "decision provider";

    /// The singular noun for one registration in admin responses.
    pub const ADMIN_NOUN: &str = "decision-provider";

    /// The record resource kind a registration is audited under: the scope kind.
    pub const AUDIT_KIND: &str = SCOPE_KINDS[0];

    /// The op classes this plane serves, in index order: each dialect's decision call (see the
    /// module doc).
    pub const OP_CLASSES: &[OpClassId] = &[ops::OP_SYSTEMONE, ops::OP_EVALUATE];

    /// The billable classes, in index order, each with its family: the decision count, the fee
    /// unit (also a class: the tail check holds `fee_units ⊆ billable_classes`), and the far end's
    /// input and output tokens. THE DESIGN section 7 (owner money rulings 2026-09-28): the card
    /// "prices `decision`, `input_tokens` and `output_tokens` (family `decision`, all three
    /// required, 0 = free)".
    pub const BILLABLE_CLASSES: &[(MeterClassId, &str)] = &[
        (meta::CLASS_DECISION, DECISION_FAMILY),
        (MeterClassId::new(FEE_PER_REQUEST), FEE_FAMILY),
        (CLASS_INPUT_TOKENS, DECISION_FAMILY),
        (CLASS_OUTPUT_TOKENS, DECISION_FAMILY),
    ];

    /// The family every priced class of this plane is in.
    pub const DECISION_FAMILY: &str = "decision";

    /// The far end's input tokens, where its answer reports them (`/usage/input_tokens`).
    pub const CLASS_INPUT_TOKENS: MeterClassId = MeterClassId::new("input_tokens");

    /// The far end's output tokens, where its answer reports them (`/usage/output_tokens`).
    pub const CLASS_OUTPUT_TOKENS: MeterClassId = MeterClassId::new("output_tokens");

    /// The index of [`meta::CLASS_DECISION`] in [`BILLABLE_CLASSES`].
    pub const CLASS_DECISION_INDEX: u32 = 0;

    /// The index of [`CLASS_INPUT_TOKENS`] in [`BILLABLE_CLASSES`].
    pub const CLASS_INPUT_TOKENS_INDEX: u32 = 2;

    /// The index of [`CLASS_OUTPUT_TOKENS`] in [`BILLABLE_CLASSES`].
    pub const CLASS_OUTPUT_TOKENS_INDEX: u32 = 3;

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

    /// The claims a generation snapshot may publish, `(verb, target, dialect)`: each dialect's one
    /// exact claim.
    pub const CLAIMS: &[(&str, &str, u32)] = &[
        ("POST", ops::PATH_SYSTEMONE, DIALECT_JEV),
        ("POST", ops::PATH_EVALUATE, DIALECT_NANOJEV),
    ];
}

/// The claims a generation's snapshot publishes, given the dialect of each model it configures:
/// each dialect's claim when at least one model is of it, none for none (see the module doc).
#[must_use]
pub fn served_claims(dialects: &[u32]) -> Vec<(&'static str, &'static str, u32)> {
    tail::CLAIMS
        .iter()
        .filter(|(_, _, dialect)| dialects.contains(dialect))
        .copied()
        .collect()
}

/// A protocol's index in [`tail::DIALECTS`], where this plane speaks it.
#[must_use]
pub fn dialect_of(protocol: &str) -> Option<u32> {
    tail::DIALECTS
        .iter()
        .position(|d| *d == protocol)
        .and_then(|i| u32::try_from(i).ok())
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

/// THE MODEL A CLAIMED REQUEST ROUTES OVER among the `models` its claim's dialect `serves` (the
/// generation's configured names, each with what this plane keeps of it): the one it names, else
/// the only one of that dialect configured. Answers the configured name and its entry. A model of
/// another dialect is this dialect's unknown model (THE DESIGN section 2: "a model of the wrong
/// dialect gets that dialect's existing unknown-model refusal").
///
/// # Errors
///
/// [`Unrouted`]: several configured and none named, a `model` that is not a string, or a name none
/// of the dialect's models has.
pub fn route_model<'m, V>(
    body: &[u8],
    models: &'m std::collections::BTreeMap<String, V>,
    serves: impl Fn(&V) -> bool,
) -> Result<(&'m str, &'m V), Unrouted> {
    match requested_model(body)? {
        Some(name) => models
            .get_key_value(name.as_ref())
            .filter(|(_, v)| serves(v))
            .map(|(k, v)| (k.as_str(), v))
            .ok_or_else(|| Unrouted::Unknown(name.into_owned())),
        None => {
            let mut all = models.iter().filter(|(_, v)| serves(v));
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

/// Classify an arriving request by its verb and target: its operation, and the dialect its claim
/// is. `None` for anything this plane does not claim, including `GET /v1/models`.
#[must_use]
pub fn arrive(verb: &str, target: &str) -> Option<Arrived> {
    let row = ops::row_for(verb, target)?;
    let op_class = tail::OP_CLASSES.iter().position(|op| *op == row.op)?;
    let dialect = tail::CLAIMS
        .iter()
        .find(|(v, t, _)| *t == target && v.eq_ignore_ascii_case(verb))?
        .2;
    Some(Arrived {
        op: row.op,
        op_class: u32::try_from(op_class).ok()?,
        // A decision is billed to someone: the provider account is the deployment's, and the unit
        // is the caller's.
        principal: PrincipalNeed::Required,
        dialect,
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

/// Answer an ATTEMPT piece of a unit of `dialect`: the same request on every attempt, whichever
/// member the kernel picked, at the dialect's own path. Neither dialect names a provider on the
/// wire, so the member changes nothing in the request. Named `attempt_request`, not `attempt`, so
/// it is not a cross-plane re-spelling of llm/a2a's `attempt` (structure-lint plane-dup; ARCHITECT
/// ruling 2b 2026-10-04).
#[must_use]
pub fn attempt_request(dialect: u32, caller_body: &[u8]) -> FarEndRequest<'_> {
    let target = tail::CLAIMS
        .iter()
        .find(|(_, _, d)| *d == dialect)
        .map_or(ops::PATH_SYSTEMONE, |(_, t, _)| t);
    FarEndRequest {
        verb: "POST",
        target,
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

/// A usage member the far end's success answer carries but that is not a whole count: the money
/// rule's loud failure (finding 395, kept: "a usage member present but not a whole count is
/// LOCATED, never dropped"), never a silent 0. Names the member's pointer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unreadable(pub &'static str);

/// What one answer bills, in [`tail::BILLABLE_CLASSES`]' order of reading: the decision count,
/// the input and output tokens, and the request fee. `None` = nothing in that class.
pub type Counts = [Option<Units>; 4];

/// A usage member as the answer states it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Member {
    /// The answer has no such member.
    #[default]
    Absent,
    /// A whole count.
    Whole(u64),
    /// Present, and not a whole count.
    Unreadable,
}

/// What a member of the answer is to the reading: `/error`, `/usage`, one of the three usage
/// counts (by its index in its dialect's [`Usage::counted`]), or none of them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Slot {
    #[default]
    Other,
    Error,
    Usage,
    Count(usize),
}

/// Where a dialect's answer states its counts: the top-level member holding them, and the members
/// under it, `(name, pointer)`, in [`Counts`]' order (decision, input tokens, output tokens).
/// Usage pointers are dialect data (THE DESIGN section 2).
struct Usage {
    parent: &'static [u8],
    counted: &'static [(&'static [u8], &'static str)],
    /// The decision count is required: an answer with none refuses loudly.
    required: bool,
}

/// Each dialect's [`Usage`], in [`tail::DIALECTS`]' order: `jev` reads `/usage/units` (one decision
/// when absent) and its tokens; `nanojev` reads the upstream's own billing unit,
/// `/execution/states`, and an answer with no count refuses loudly.
const USAGE: [Usage; 2] = [
    Usage {
        parent: b"usage",
        counted: &[
            (b"units", PTR_USAGE_UNITS),
            (b"input_tokens", PTR_USAGE_INPUT_TOKENS),
            (b"output_tokens", PTR_USAGE_OUTPUT_TOKENS),
        ],
        required: false,
    },
    Usage {
        parent: b"execution",
        counted: &[(b"states", PTR_EXECUTION_STATES)],
        required: true,
    },
];

/// The longest member name compared ("output_tokens"), with room.
const KEY_CAP: usize = 16;
/// The longest scalar a whole count is spelled in (`u64::MAX` is 20 digits), with room.
const SCALAR_CAP: usize = 24;

/// The far end's answer, read as it is relayed.
///
/// Every piece is relayed to the caller unchanged, as it arrives, and read as it passes: a scan of
/// the JSON structure that keeps only what the money rule reads (whether `/error` is there and not
/// `null`, and the dialect's counts: `/usage/*`, or `/execution/states`), in fixed space. No byte of the answer is kept, so an
/// answer of any size is read in the same few bytes (THE DESIGN section 11.2: "no allocation and no
/// blocking on the hot path"), and the pieces may split the answer anywhere.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FarEndReading {
    /// The nesting depth: `1` inside the top-level value.
    depth: u32,
    /// Whether the container at depth 1 and at depth 2 is an object.
    object: [bool; 3],
    /// In an object at depth 1 or 2: the next string is a member name.
    want_key: bool,
    /// Inside a string; the string is a member name; the last byte was its escape.
    in_str: bool,
    str_key: bool,
    escaped: bool,
    /// The member name being read (cut at [`KEY_CAP`]: a longer one is none compared).
    key: [u8; KEY_CAP],
    key_len: usize,
    /// The member a value at depth 1, and at depth 2, belongs to.
    at: [Slot; 3],
    /// The scalar being read for `scalar_of` (cut at [`SCALAR_CAP`]: a longer one is no count).
    scalar: [u8; SCALAR_CAP],
    scalar_len: usize,
    scalar_of: Option<Slot>,
    /// `/error`: absent (`None`), `null` (`Some(false)`), or there (`Some(true)`).
    error: Option<bool>,
    /// The counts, in the dialect's [`Usage::counted`] order.
    members: [Member; 3],
    /// The dialect the answer is in ([`USAGE`]'s index).
    dialect: u32,
}

impl FarEndReading {
    /// A `jev` reading with nothing received.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A reading of an answer in `dialect` ([`tail::DIALECTS`]' index), nothing received.
    #[must_use]
    pub fn for_dialect(dialect: u32) -> Self {
        Self {
            dialect,
            ..Self::default()
        }
    }

    /// The dialect's [`Usage`].
    fn usage(&self) -> &'static Usage {
        USAGE.get(self.dialect as usize).unwrap_or(&USAGE[0])
    }

    /// Take one far-end piece and return the bytes to relay to the caller: the piece itself.
    pub fn piece<'p>(&mut self, bytes: &'p [u8]) -> &'p [u8] {
        for &b in bytes {
            self.byte(b);
        }
        bytes
    }

    /// The member at the current depth a value starting now belongs to.
    fn slot(&self) -> Slot {
        match self.depth {
            1 if self.object[1] => self.at[1],
            2 if self.object[2] && self.at[1] == Slot::Usage => self.at[2],
            _ => Slot::Other,
        }
    }

    /// Whether the container the reading is in is an object it reads member names of.
    fn in_object(&self) -> bool {
        matches!(self.depth, 1 | 2) && self.object[self.depth as usize]
    }

    /// A value starts: `scalar` = it is a bare scalar (a number, `true`, `false`, `null`).
    fn value(&mut self, scalar: Option<u8>) {
        let slot = self.slot();
        match (slot, scalar) {
            (Slot::Error, None) => self.error = Some(true),
            (Slot::Count(i), None) => self.members[i] = Member::Unreadable,
            (Slot::Error | Slot::Count(_), Some(b)) => {
                self.scalar[0] = b;
                self.scalar_len = 1;
                self.scalar_of = Some(slot);
            }
            _ => {}
        }
    }

    /// The scalar being read, ended.
    fn end_scalar(&mut self) {
        let Some(slot) = self.scalar_of.take() else {
            return;
        };
        let raw = &self.scalar[..self.scalar_len];
        match slot {
            Slot::Error => self.error = Some(raw != b"null"),
            Slot::Count(i) => {
                self.members[i] = if self.scalar_len > SCALAR_CAP - 1 {
                    Member::Unreadable
                } else {
                    whole(raw).map_or(Member::Unreadable, Member::Whole)
                };
            }
            _ => {}
        }
    }

    /// A member name, read whole.
    fn end_key(&mut self) {
        let key = &self.key[..self.key_len.min(KEY_CAP)];
        let named = if self.key_len > KEY_CAP {
            Slot::Other
        } else if self.depth == 1 {
            match key {
                b"error" => Slot::Error,
                k if k == self.usage().parent => Slot::Usage,
                _ => Slot::Other,
            }
        } else {
            self.usage()
                .counted
                .iter()
                .position(|(name, _)| *name == key)
                .map_or(Slot::Other, Slot::Count)
        };
        if let 1 | 2 = self.depth {
            self.at[self.depth as usize] = named;
        }
    }

    /// One byte of the answer.
    fn byte(&mut self, b: u8) {
        if self.in_str {
            if self.escaped {
                self.escaped = false;
            } else if b == b'"' {
                self.in_str = false;
                if self.str_key {
                    self.end_key();
                }
                return;
            } else if b == b'\\' {
                self.escaped = true;
            }
            if self.str_key {
                if self.key_len < KEY_CAP {
                    self.key[self.key_len] = b;
                }
                self.key_len = self.key_len.saturating_add(1);
            }
            return;
        }
        if self.scalar_of.is_some() {
            if !matches!(
                b,
                b' ' | b'\t' | b'\n' | b'\r' | b',' | b'}' | b']' | b':' | b'"' | b'{' | b'['
            ) {
                if self.scalar_len < SCALAR_CAP {
                    self.scalar[self.scalar_len] = b;
                    self.scalar_len += 1;
                }
                return;
            }
            self.end_scalar();
        }
        match b {
            b' ' | b'\t' | b'\n' | b'\r' | b':' => {}
            b'"' => {
                self.in_str = true;
                self.escaped = false;
                self.str_key = self.in_object() && self.want_key;
                if self.str_key {
                    self.key_len = 0;
                    self.want_key = false;
                } else {
                    self.value(None);
                }
            }
            b'{' | b'[' => {
                self.value(None);
                self.depth = self.depth.saturating_add(1);
                if let 1 | 2 = self.depth {
                    self.object[self.depth as usize] = b == b'{';
                    self.at[self.depth as usize] = Slot::Other;
                }
                self.want_key = b == b'{';
            }
            b'}' | b']' => {
                self.depth = self.depth.saturating_sub(1);
                self.want_key = false;
            }
            b',' => self.want_key = self.in_object(),
            _ => self.value(Some(b)),
        }
    }

    /// The reading as the answer stands: a scalar the answer ended in is read as it is.
    fn settled(&self) -> (Option<bool>, [Member; 3]) {
        let mut done = self.clone();
        done.end_scalar();
        (done.error, done.members)
    }

    /// Whether the answer, with the far end's `status`, is a SUCCESS: a `2xx` status and no
    /// `/error` member (a `null` one is none). The one success rule every count below reads.
    #[must_use]
    pub fn success(&self, status: Option<u32>) -> bool {
        status.is_some_and(|s| (200..300).contains(&s)) && self.settled().0 != Some(true)
    }

    /// WHAT THE ANSWER BILLS, read at the last piece (THE DESIGN section 7, the owner money rulings):
    /// a non-success bills nothing; a success bills one `decision`, or the whole count its
    /// `/usage/units` reports (the hosted provider's count, DECISIONS D9), its `/usage/input_tokens`
    /// and `/usage/output_tokens` where it reports them, and the request fee (`1` of
    /// [`tail::FEE_PER_REQUEST`]: a refused or failed unit owes none).
    ///
    /// # Errors
    ///
    /// [`Unreadable`]: a success whose usage member is present but is not a whole count a signed
    /// 64-bit count holds (negative, fractional, a string, `null`, past `i64::MAX`).
    pub fn counts(&self, status: Option<u32>) -> Result<Counts, Unreadable> {
        if !self.success(status) {
            return Ok([None; 4]);
        }
        let (_, members) = self.settled();
        let usage = self.usage();
        let mut whole = [None; 3];
        for (i, (_, pointer)) in usage.counted.iter().enumerate() {
            whole[i] = match members[i] {
                Member::Absent if i == 0 && usage.required => return Err(Unreadable(pointer)),
                Member::Absent => None,
                Member::Whole(n) => Some(n),
                Member::Unreadable => return Err(Unreadable(pointer)),
            };
        }
        let reported = |class: u32, amount: u64| Units {
            class,
            reported: true,
            amount,
        };
        Ok([
            Some(reported(tail::CLASS_DECISION_INDEX, whole[0].unwrap_or(1))),
            whole[1].map(|n| reported(tail::CLASS_INPUT_TOKENS_INDEX, n)),
            whole[2].map(|n| reported(tail::CLASS_OUTPUT_TOKENS_INDEX, n)),
            Some(reported(tail::CLASS_FEE_INDEX, 1)),
        ])
    }
}

/// A usage member's raw bytes read as a whole count a signed 64-bit count holds: ASCII digits
/// alone, at most `i64::MAX`.
#[must_use]
pub fn whole(raw: &[u8]) -> Option<u64> {
    if raw.is_empty() || !raw.iter().all(u8::is_ascii_digit) {
        return None;
    }
    core::str::from_utf8(raw)
        .ok()?
        .parse::<u64>()
        .ok()
        .filter(|n| i64::try_from(*n).is_ok())
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

/// The caller's fields the far end receives, held in one buffer per unit: each field's name
/// (lowercased) and value, back to back, and where each ends.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Relayed {
    bytes: Vec<u8>,
    /// Per field, `(end of its name, end of its value)` in `bytes`.
    ends: Vec<(usize, usize)>,
}

impl Relayed {
    /// Every field, `(name, value)`, in the caller's order.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &[u8])> + '_ {
        let mut from = 0;
        self.ends.iter().map(move |&(name, value)| {
            let field = (&self.bytes[from..name], &self.bytes[name..value]);
            from = value;
            field
        })
    }

    /// Whether no field is relayed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ends.is_empty()
    }
}

/// Whether the caller's field `name` reaches the far end.
fn relayed(name: &[u8]) -> bool {
    !NOT_RELAYED
        .iter()
        .any(|n| name.eq_ignore_ascii_case(n.as_bytes()))
}

/// THE CALLER'S FIELDS THE FAR END RECEIVES, in the order the caller sent them, a repeated name
/// keeping every value: every field the caller sent but [`NOT_RELAYED`]'s (a same-dialect relay
/// passes every header but the governed set; ARCHITECT DEC-SERVE Q2, the OWNER's DIALECT-FIDELITY
/// F2). Names are lowercased, as the wire compares them. Kept in one buffer sized once.
#[must_use]
pub fn relayed_fields<'f, I>(caller: I) -> Relayed
where
    I: IntoIterator<Item = (&'f [u8], &'f [u8])>,
    I::IntoIter: Clone,
{
    let fields = caller.into_iter();
    let (mut size, mut count) = (0, 0);
    for (name, value) in fields.clone().filter(|(name, _)| relayed(name)) {
        size += name.len() + value.len();
        count += 1;
    }
    let mut kept = Relayed {
        bytes: Vec::with_capacity(size),
        ends: Vec::with_capacity(count),
    };
    for (name, value) in fields.filter(|(name, _)| relayed(name)) {
        kept.bytes.extend(name.iter().map(u8::to_ascii_lowercase));
        let name_end = kept.bytes.len();
        kept.bytes.extend_from_slice(value);
        kept.ends.push((name_end, kept.bytes.len()));
    }
    kept
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
