// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH KIND'S ABI (v3; design B.3): its version, its table, its Statement tail, its cancel
//! dispositions and the `in`/`out` of each of its operations. ONE kind with two operation families:
//! INBOUND (`verify`, and the `begin_login`/`complete_login` pair) and OUTBOUND (`open_outbound`,
//! `outbound_ready`, `fields`). There is no separate egress kind.
//!
//! THE CACHE LIVES IN THE PLUGIN (owner ruling Q-INCACHE). The kernel makes one call per request
//! and keeps no verdict cache. The plugin caches internally: Identify TTL clamped to 3600 s
//! (default 300), Reject never cached, Pass never cached (Pass buffering, if any, is the
//! kernel's), 4096 entries. FLUSH THROUGH REFRESH: an auth plugin DROPS
//! its inbound cache on every `refresh`. `POST /admin/auth/cache/flush` (unchanged) is a `refresh`
//! with a NEW generation number and unchanged settings, so generations stay monotonic and memory
//! class (ii) holds. Only the INBOUND cache is dropped: the outbound token cache is keyed by
//! (style, credential, settings), never by handle, and survives `refresh` and re-opening, so a
//! reload never answers a fields call without a credential that 1.5.5 would have had.
//!
//! SERVICE CREDENTIALS (an LDAP bind password, an IdP client secret) are named by
//! [`Statement::secret_refs`](super::mechanism::door::Statement) (the settings keys holding a
//! secret-ref). The kernel resolves them into
//! [`OpenIn::secrets`](super::mechanism::lifecycle::OpenIn) in the same order, and again into
//! [`RefreshIn`](super::mechanism::lifecycle::RefreshIn). The auth tail carries nothing for them.
//!
//! VERDICTS ARE ALWAYS `READY`. `FAILED` on `verify` is a module failure: the chain's error path,
//! as 1.5.5's `STATUS_ERR`. `FAILED` on `complete_login` is a module failure too, and the host
//! declines the login fail-closed, as 1.5.5 refused a login plugin that failed: an identity
//! provider that could not answer is a READY [`LOGIN_OUTAGE`], never a `FAILED`. Both exclude the
//! short-buffer answer ([`IdentifyOut`]).
//!
//! `verify` ON THE SPOT. The host may call `verify` TICKET-LESS (`Ticket::NONE`, on its own
//! thread, which cannot wait): a plugin that can judge the credential without waiting answers as it
//! would on a ticket; one whose `verify` must wait on I/O answers `REFUSED` there, never `PENDING`
//! (a ticket-less `PENDING` is FAULT), and the host submits the same `verify` on a ticket.
//!
//! DEADLINES ARE HOST-OWNED. No op carries a timeout of its own: the host stamps
//! `InHead.deadline_ns`, bounds every read on a need's connection, and calls `cancel` at expiry.
//!
//! A slot for a capability the tail does not declare is never called. The plugin still fills it
//! (a NULL slot refuses the load) and answers `REFUSED`.
//!
//! The host side is `busbar_contract::auth_calls`: the kernel's identity chain calls `verify` through
//! it, the loader dispatching it through the one dispatcher.

use super::mechanism::call::{AbiStr, Op};
use super::mechanism::door::KindTailHead;
use super::mechanism::lifecycle::{OpsHead, LIFECYCLE_SLOTS};

mod check;
mod inbound;
mod outbound;
mod points;

pub use check::{
    check_begin_login, check_complete_login, check_fields, check_identify, check_inbound_points,
    check_points, check_style_decl, check_target, FIELDS_HARD_MAX, IDENTITY_GROUPS_HARD_MAX,
};

pub use inbound::{
    BeginLoginIn, BeginLoginOut, CompleteLoginIn, IdentifyOut, IdentityBuf, IdentityOut,
    LoginField, NamedValue, RequestFacts, StripName, VerifyIn,
};
pub use outbound::{
    FieldSpan, FieldsIn, FieldsOut, OpenOutboundIn, OpenOutboundOut, OutboundReadyIn,
    OutboundReadyOut, TargetIn, TargetOut,
};
pub use points::{AuthPoint, AuthPoints, POINT_FRAME, POINT_HEAD, POINT_HEAD_BODY, POINT_PEER};

/// The auth kind's ABI version: v1.5.5 shipped `2` (`AUTH_ABI_VERSION`), so 1.6.0 ships `3`.
pub const ABI_VERSION: u32 = 3;

/// The auth kind's layout fingerprint ([`crate::abi::mechanism::layout`]): the fold of
/// [`LAYOUT_SHAPES`], the size, alignment and field offsets of every `#[repr(C)]` struct crossing
/// the auth table. A door states it as built
/// ([`Door::layout`](crate::abi::mechanism::door::Door::layout)) and the loader refuses another;
/// `tests/layout_fingerprint.rs` holds it to its fold.
pub const LAYOUT_FINGERPRINT: u64 = 0x00c89280c6692621;

/// The auth kind's shapes, in fold order ([`crate::layout_shape!`]): every `#[repr(C)]` struct
/// crossing its table, each with every field. A struct `abi/auth/` gains is listed here (gate
/// `abi-location`).
pub const LAYOUT_SHAPES: &[&[u64]] = &[
    crate::layout_shape!(Ops =>
        head, verify, begin_login, complete_login, open_outbound, outbound_ready, fields, target
    ),
    crate::layout_shape!(StyleDecl => name, flags, points),
    crate::layout_shape!(AuthTail =>
        head, caps, facts, login_kind, inbound_points, styles, styles_len, operator_principal,
        credential_kinds, credential_kinds_len
    ),
    crate::layout_shape!(NamedValue => name, value),
    crate::layout_shape!(RequestFacts => method, authority, canonical_path, query, timestamp),
    crate::layout_shape!(IdentityBuf => buf, buf_cap, groups, groups_cap, _reserved),
    crate::layout_shape!(IdentityOut =>
        subject, key_id, key_name, user, provider, name, claims, claims_fmt, flags, ttl_secs,
        groups_len, _reserved, replay_key, replay_ttl_secs, credential
    ),
    crate::layout_shape!(StripName => name, place, _reserved),
    crate::layout_shape!(VerifyIn =>
        head, credential, lines, lines_len, request, out_buf, point, _reserved, conn, unit, peer,
        body, strip, strip_cap, _reserved2
    ),
    crate::layout_shape!(IdentifyOut =>
        head, verdict, needed_groups, needed_bytes, identity, decision, strip_len, needed_strip,
        _reserved
    ),
    crate::layout_shape!(BeginLoginIn =>
        head, redirect_uri, state, nonce, code_challenge, scopes, scopes_len
    ),
    crate::layout_shape!(LoginField => name, label, kind, required),
    crate::layout_shape!(BeginLoginOut => head, shape, _reserved, authorize_url, form, form_len),
    crate::layout_shape!(CompleteLoginIn =>
        head, code, state, redirect_uri, code_verifier, submitted, submitted_len, out_buf, nonce
    ),
    crate::layout_shape!(OpenOutboundIn => head, style, credential, settings),
    crate::layout_shape!(OpenOutboundOut => head, handle),
    crate::layout_shape!(OutboundReadyIn => head, handle),
    crate::layout_shape!(OutboundReadyOut => head, ready, _reserved),
    crate::layout_shape!(FieldSpan => name, value, flags, _reserved),
    crate::layout_shape!(FieldsIn =>
        head, handle, mode, point, request, caller_credential, field_buf, field_buf_cap, fields,
        fields_cap, _reserved, headers, headers_len, conn, unit, body
    ),
    crate::layout_shape!(FieldsOut => head, fields_len, needed_fields, needed_bytes),
    crate::layout_shape!(TargetIn => head, style, credential, settings, buf, buf_cap),
    crate::layout_shape!(TargetOut => head, target),
];

/// [`InHead::op`](super::mechanism::call::InHead) of each auth op: kind op `k` is at slot
/// [`LIFECYCLE_SLOTS`]` + k`, contiguous, in [`Ops`] field order.
///
/// ```
/// use busbar_contract::abi::auth::{slot, Ops, KIND_SLOTS, SLOTS};
/// use busbar_contract::abi::mechanism::lifecycle::LIFECYCLE_SLOTS;
/// use std::mem::{offset_of, size_of};
/// let order = [
///     (slot::VERIFY, offset_of!(Ops, verify)),
///     (slot::BEGIN_LOGIN, offset_of!(Ops, begin_login)),
///     (slot::COMPLETE_LOGIN, offset_of!(Ops, complete_login)),
///     (slot::OPEN_OUTBOUND, offset_of!(Ops, open_outbound)),
///     (slot::OUTBOUND_READY, offset_of!(Ops, outbound_ready)),
///     (slot::FIELDS, offset_of!(Ops, fields)),
///     (slot::TARGET, offset_of!(Ops, target)),
/// ];
/// assert_eq!(order.len() as u32, KIND_SLOTS);
/// for (k, (idx, off)) in order.into_iter().enumerate() {
///     assert_eq!(idx, LIFECYCLE_SLOTS + k as u32);
///     // OpsHead's `size` + `slots` (8 bytes), then one 8-byte slot per index.
///     assert_eq!(off, 8 + 8 * idx as usize);
/// }
/// assert_eq!(SLOTS, LIFECYCLE_SLOTS + KIND_SLOTS);
/// assert_eq!(size_of::<Ops>(), 8 + 8 * SLOTS as usize);
/// ```
pub mod slot {
    use super::LIFECYCLE_SLOTS;

    /// `verify`.
    pub const VERIFY: u32 = LIFECYCLE_SLOTS;
    /// `begin_login`.
    pub const BEGIN_LOGIN: u32 = LIFECYCLE_SLOTS + 1;
    /// `complete_login`.
    pub const COMPLETE_LOGIN: u32 = LIFECYCLE_SLOTS + 2;
    /// `open_outbound`.
    pub const OPEN_OUTBOUND: u32 = LIFECYCLE_SLOTS + 3;
    /// `outbound_ready`.
    pub const OUTBOUND_READY: u32 = LIFECYCLE_SLOTS + 4;
    /// `fields`.
    pub const FIELDS: u32 = LIFECYCLE_SLOTS + 5;
    /// `target`.
    pub const TARGET: u32 = LIFECYCLE_SLOTS + 6;
}

/// How many kind ops follow the lifecycle.
pub const KIND_SLOTS: u32 = 7;
/// [`OpsHead::slots`] for auth v3.
pub const SLOTS: u32 = LIFECYCLE_SLOTS + KIND_SLOTS;

/// The auth kind's ops table: the shared [`OpsHead`], then the kind's slots, contiguous.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ops {
    /// The lifecycle. `refresh` also drops the plugin's inbound cache (the admin flush).
    pub head: OpsHead,
    /// Judge an inbound request at one AUTH POINT ([`VerifyIn::point`]; THE DESIGN, "Auth
    /// points and guest lists": the inbound point call reuses this slot). REQUEST-PATH; may pend
    /// (a key-set fetch or a directory read over the plugin's need);
    /// [`DeadlineClass::Call`](super::mechanism::call::DeadlineClass). In [`VerifyIn`] (fixed
    /// 320 B, plus the line, peer and body bytes), out [`IdentifyOut`] (fixed 232 B; results in
    /// the host's [`IdentityBuf`], [`IDENTITY_BUF_BYTES`] and [`IDENTITY_GROUPS`] to start, and its
    /// strip array, [`FIELDS_MAX`] to start). The verdict is [`VERDICT_IDENTITY`],
    /// [`VERDICT_REJECT`] or [`VERDICT_PASS`]; the decision is [`DECISION_CONTINUE`] or
    /// [`DECISION_STOP`]; the credential lines to strip are named whatever the verdict. The
    /// transport receives only the decision and the strips; the verdict, the identity and the
    /// credential go to the kernel. OVERLOAD: when the instance's `max_inflight` is full, the host does not
    /// queue the call and answers the request 503 (an accepted difference from 1.5.5). The plugin
    /// never signals overload itself.
    pub verify: Option<Op>,
    /// Start a login. OFF-PATH; may pend through the plugin's own need; `Call`. In
    /// [`BeginLoginIn`] (fixed 168 B), out [`BeginLoginOut`] (fixed 136 B; URL and form held under
    /// `OutHead.lease`).
    pub begin_login: Option<Op>,
    /// Finish a login: the token exchange runs over the plugin's own need to its need-declared
    /// targets. OFF-PATH; may pend; `Call`. In [`CompleteLoginIn`] (fixed 232 B), out
    /// [`IdentifyOut`] (fixed 232 B; host [`IdentityBuf`]). The verdict is [`LOGIN_IDENTITY`],
    /// [`LOGIN_BAD_CREDENTIAL`], [`LOGIN_OUTAGE`] or [`LOGIN_SECURITY_CHECK_FAILED`].
    pub complete_login: Option<Op>,
    /// Bind one outbound style to its credential and answer a handle. OFF-PATH, at generation
    /// seal; never pends (the first mint runs in the background on `tick`); `Call`. In
    /// [`OpenOutboundIn`] (fixed 152 B), out [`OpenOutboundOut`] (fixed 104 B). A handle is
    /// GENERATION DATA: the kernel re-opens every handle at each generation, and a handle is valid
    /// until `retire` of the generation it was opened at. There is no close slot. The token cache
    /// behind a handle is keyed by (style, credential, settings) and outlives it.
    pub open_outbound: Option<Op>,
    /// The handle's `ready` fact, read by the health prober. OFF-PATH; never pends; `Call`. In
    /// [`OutboundReadyIn`] (fixed 96 B), out [`OutboundReadyOut`] (fixed 104 B).
    pub outbound_ready: Option<Op>,
    /// The per-attempt call the kernel makes before encode: the auth fields for this request.
    /// REQUEST-PATH; may pend only when the cached token has expired and its refresh failed
    /// (the design's expired-token rule, Q-EXPIRED), bounded by the attempt's deadline; `Call`.
    /// Called at the style's AUTH POINTS ([`FieldsIn::point`]; THE DESIGN, "Auth points and
    /// guest lists", step 5): the host REPLACES the plane's lines of the same name with the fields
    /// answered and adds nothing to the head after them; REFUSED or FAILED stops the request.
    /// In [`FieldsIn`] (fixed 288 B), out [`FieldsOut`] (fixed 112 B; fields in the host's
    /// buffer, [`FIELDS_BUF_BYTES`] and [`FIELDS_MAX`] to start; one re-call when short). READY
    /// with zero fields = no auth header, so the upstream answers 401: 1.5.5's answer before the
    /// first mint and for an un-encodable key.
    pub fields: Option<Op>,
    /// The destination one outbound style's credential sends to, for the kernel to judge (the
    /// need's target is the kernel's to judge, THE DESIGN's needs section): PURE (no I/O, never dials, reads
    /// only the credential and settings it is handed), called with NO instance (the `instance`
    /// argument is NULL) at config time and at the generation seal, never pends; `Call`. In
    /// [`TargetIn`] (fixed 168 B), out [`TargetOut`] (fixed 104 B). READY with a present
    /// [`TargetOut::target`]: the URL, in the host's buffer. READY with it absent: the style sends
    /// to no destination of its own. FAILED: why, one line in `head.error` (in the host's buffer),
    /// rendered verbatim. REFUSED: the plugin does not serve `target` (the SDK's answer for a door
    /// that wires none): the style names no destination.
    pub target: Option<Op>,
}

/// [`AuthTail::caps`]: the plugin serves `verify`.
pub const CAP_INBOUND: u32 = 1;
/// [`AuthTail::caps`]: the plugin serves `begin_login`/`complete_login`.
pub const CAP_LOGIN: u32 = 2;
/// [`AuthTail::caps`]: the plugin serves `open_outbound`/`outbound_ready`/`fields`.
pub const CAP_OUTBOUND: u32 = 4;

/// [`AuthTail::facts`]: the plugin's verdicts may be cached. INFORMATIONAL (status, operators):
/// the plugin caches them itself, and the kernel keeps no verdict cache.
pub const FACT_CACHEABLE: u32 = 1;
/// [`AuthTail::facts`]: `verify` reads the request body's hash. The body itself reaches `verify` as
/// [`VerifyIn::body`] when the tail's points hold [`POINT_HEAD_BODY`].
pub const FACT_INBOUND_NEEDS_BODY_HASH: u32 = 2;
/// [`AuthTail::facts`]: `verify` reads EVERY request header, not only its carriers (the Statement's
/// [`MARK_WORD_CARRIER`](crate::abi::mechanism::door::MARK_WORD_CARRIER) word marks); the
/// host passes them all in [`VerifyIn::lines`]. An inbound signature check needs it: the set of
/// signed headers varies per request.
pub const FACT_INBOUND_ALL_HEADERS: u32 = 4;
/// [`AuthTail::facts`]: this plugin's `verify` judges THE OPERATOR CREDENTIAL, the one admin
/// credential that is full by definition; [`AuthTail::operator_principal`] names the principal id
/// it identifies. Needs [`CAP_INBOUND`] and a non-empty principal; a tail stating it otherwise
/// refuses the load.
pub const FACT_OPERATOR: u32 = 8;
/// [`AuthTail::facts`]: this plugin's `verify` reads host-held credentials of the kinds
/// [`AuthTail::credential_kinds`] names, through the host's `records.secret` service; the host serves
/// that read for those kinds only. Needs [`CAP_INBOUND`] and a non-empty list; a tail stating it
/// otherwise refuses the load.
pub const FACT_READS_CREDENTIALS: u32 = 16;
/// [`AuthTail::facts`]: this plugin's carrier marks are the host's default inbound style: where a
/// caller's credential sits on every line the operator's config leaves without a style, in the
/// Statement's order (THE DESIGN, "Auth points and guest lists": the line's style names its
/// credential lines, and core's `keys` verifies what that style yields and names no line). Needs
/// at least one carrier mark; at most one loaded auth row states it, or boot is refused.
pub const FACT_DEFAULT_INBOUND_STYLE: u32 = 32;

/// THE CACHE-FLUSH COUNT's metric family name. An auth plugin that caches verdicts declares a
/// counter family of this name (no labels) in its Statement, and on `refresh` adds to it the number
/// of inbound cache entries it dropped. The host sums it across auth plugins into the admin cache
/// flush's `{"flushed": N}` (1.5.5's count). A plugin that caches nothing declares nothing.
pub const METRIC_CACHE_FLUSHED: &str = "busbar_auth_cache_flushed_total";

/// [`AuthTail::login_kind`]: no login ([`CAP_LOGIN`] not declared).
pub const LOGIN_KIND_NONE: u32 = 0;
/// [`AuthTail::login_kind`]: a redirect to an IdP.
pub const LOGIN_KIND_REDIRECT: u32 = 1;
/// [`AuthTail::login_kind`]: a credential form the core renders.
pub const LOGIN_KIND_CREDENTIAL: u32 = 2;

/// [`StyleDecl::flags`]: `fields` needs [`FieldsIn::headers`], the exact envelope, for this style.
pub const STYLE_NEEDS_HEADERS: u32 = 2;
/// [`StyleDecl::flags`]: this style serves [`MODE_PASSTHROUGH`] as well as [`MODE_OWN`] — the
/// per-request call may present the CALLER's verified credential, not only the plugin's own bound
/// one (ARCHITECT ruling 2026-09-29: caller-credential is not a mechanism, it is a credential
/// source a mechanism applies; a mechanism plugin declares this flag on a style instead of a
/// second plugin declaring a `caller-credential` style). The kernel maps a provider's
/// `caller-credential {as: X}` / `upstream_credentials: passthrough` config to style `X` in
/// [`MODE_PASSTHROUGH`] (KERNEL<>PLUGINS step 21 seam; not built here).
pub const STYLE_CALLER_CREDENTIAL: u32 = 4;
/// [`StyleDecl::flags`]: the style sends the credential to the provider entry's token endpoint.
///
/// The binding's settings carry it as `token_url`, which the HOST judges as a destination before
/// any binding is opened (its scheme and the cloud-metadata denylist, in the previous release's
/// words; ARCHITECT ruling 2026-09-28 Q2 (a): a need's target is the kernel's to judge), with the
/// entry's `scope` it is exchanged under. The credential is the `client_id:client_secret` pair the
/// exchange mints FROM, so an entry declaring none is refused. A style that does not state it has
/// any `token_url` left unjudged and unread, as the previous release ignored one on such a style.
pub const STYLE_ENDPOINT_TOKEN_URL: u32 = 32;
/// [`StyleDecl::flags`]: the style takes its token endpoint from the credential itself.
///
/// The credential is a document that names the endpoint (`token_uri`), inline or in the key file
/// the credential names, and the HOST reads it out and judges it as a destination before the
/// binding is opened (ARCHITECT ruling 2026-09-28 Q2 (a)), handing the plugin its judged copy as
/// the `token_uri` setting. The style signs its assertion WITH the credential, so an entry
/// declaring none is refused. A style takes its endpoint from one place: it never states this
/// beside [`STYLE_ENDPOINT_TOKEN_URL`].
pub const STYLE_ENDPOINT_FROM_CREDENTIAL: u32 = 64;
/// [`StyleDecl::flags`]: the lowest bit of the style's LIST RANK ([`STYLE_RANK_MASK`]).
pub const STYLE_RANK_SHIFT: u32 = 16;
/// [`StyleDecl::flags`]: the style's LIST RANK, `1..=255`, or `0` (unranked).
///
/// Where the style stands when the host lists the outbound styles a provider's `auth:` may name
/// (the refusal of an unknown one renders the list): ranked styles first, by rank, then the
/// unranked ones in plugin registration order. A rank orders a list and grants nothing; two
/// styles of one rank keep registration order. [`ranked`] spells one; [`style_rank`] reads it.
pub const STYLE_RANK_MASK: u32 = 0x00ff_0000;

/// The [`StyleDecl::flags`] bits stating list rank `rank` ([`STYLE_RANK_MASK`]).
#[must_use]
pub const fn ranked(rank: u8) -> u32 {
    (rank as u32) << STYLE_RANK_SHIFT
}

/// The list rank a [`StyleDecl::flags`] states (`0` = unranked; [`STYLE_RANK_MASK`]).
#[must_use]
pub const fn style_rank(flags: u32) -> u32 {
    (flags & STYLE_RANK_MASK) >> STYLE_RANK_SHIFT
}

/// One outbound style a plugin serves: an open string the provider's `auth:` resolves against.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StyleDecl {
    /// The style name.
    pub name: AbiStr,
    /// [`STYLE_NEEDS_HEADERS`] | [`STYLE_CALLER_CREDENTIAL`] | [`STYLE_ENDPOINT_TOKEN_URL`] |
    /// [`STYLE_ENDPOINT_FROM_CREDENTIAL`], and a list rank ([`STYLE_RANK_MASK`]).
    pub flags: u32,
    /// The [`AuthPoints`] the style needs: a valid, non-empty set ([`check_style_decl`]). A style
    /// that signs the body needs [`POINT_HEAD_BODY`] and reads [`FieldsIn::body`]; a style over
    /// the head alone needs [`POINT_HEAD`].
    pub points: u32,
}

impl StyleDecl {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `StyleDecl { …, ..StyleDecl::ZERO }` so a field appended later reads as
    /// not declared.
    pub const ZERO: Self = Self {
        name: AbiStr::ZERO,
        flags: 0,
        points: 0,
    };
}

/// THE AUTH STATEMENT TAIL: `Statement.kind_tail` of an auth plugin. Plain `'static` data.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AuthTail {
    /// The tail head (`size` = `size_of::<AuthTail>()`).
    pub head: KindTailHead,
    /// [`CAP_INBOUND`] | [`CAP_LOGIN`] | [`CAP_OUTBOUND`].
    pub caps: u32,
    /// [`FACT_CACHEABLE`] | [`FACT_INBOUND_NEEDS_BODY_HASH`] | [`FACT_INBOUND_ALL_HEADERS`] |
    /// [`FACT_OPERATOR`] | [`FACT_READS_CREDENTIALS`] | [`FACT_DEFAULT_INBOUND_STYLE`].
    pub facts: u32,
    /// [`LOGIN_KIND_NONE`] | [`LOGIN_KIND_REDIRECT`] | [`LOGIN_KIND_CREDENTIAL`]: the
    /// classification the login chooser reads without calling `begin_login`. It is `NONE` exactly
    /// when [`CAP_LOGIN`] is absent; a tail where the two disagree refuses the load.
    pub login_kind: u32,
    /// The [`AuthPoints`] `verify` needs inbound: with [`CAP_INBOUND`] a valid, non-empty set;
    /// without it `0` ([`check_inbound_points`]; the loader refuses any other tail). A mechanism
    /// that checks a signature over the body needs [`POINT_HEAD_BODY`] and reads
    /// [`VerifyIn::body`].
    pub inbound_points: u32,
    /// The outbound styles served ([`CAP_OUTBOUND`]).
    pub styles: *const StyleDecl,
    /// How many.
    pub styles_len: usize,
    /// With [`FACT_OPERATOR`]: the principal id the operator credential identifies; empty
    /// otherwise. APPENDED after the tail froze at [`AUTH_TAIL_FROZEN`] bytes: a tail of that size
    /// reads it empty.
    pub operator_principal: AbiStr,
    /// With [`FACT_READS_CREDENTIALS`]: the credential kinds `verify` reads through
    /// `records.secret`; none otherwise. APPENDED after [`AuthTail::operator_principal`]: an older
    /// tail reads none.
    pub credential_kinds: *const AbiStr,
    /// How many.
    pub credential_kinds_len: usize,
}

impl AuthTail {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `AuthTail { …, ..AuthTail::ZERO }` so a field appended later reads as
    /// not declared.
    pub const ZERO: Self = Self {
        head: KindTailHead::ZERO,
        caps: 0,
        facts: 0,
        login_kind: 0,
        inbound_points: 0,
        styles: std::ptr::null(),
        styles_len: 0,
        operator_principal: AbiStr::ZERO,
        credential_kinds: std::ptr::null(),
        credential_kinds_len: 0,
    };
}

/// HOW THE AUTH KIND TAIL IS MADE (status row 194): from [`AuthTail::EMPTY`], its plain fields set
/// directly and each list by its setter, to items that live for the program.
impl AuthTail {
    /// Nothing stated: every string absent, every list empty, every number zero; the head
    /// sized to the whole tail.
    pub const EMPTY: AuthTail = AuthTail {
        head: KindTailHead {
            size: core::mem::size_of::<AuthTail>() as u32,
            _reserved: 0,
        },
        caps: 0,
        facts: 0,
        login_kind: 0,
        inbound_points: 0,
        styles: std::ptr::null(),
        styles_len: 0,
        operator_principal: AbiStr::ABSENT,
        credential_kinds: std::ptr::null(),
        credential_kinds_len: 0,
    };

    abi_lists! {
        styles, styles_len: StyleDecl => styles_ptr, with_styles, with_raw_styles;
        credential_kinds, credential_kinds_len: AbiStr
            => credential_kinds_ptr, with_credential_kinds, with_raw_credential_kinds;
    }
}

/// The size [`AuthTail`] froze at before [`AuthTail::operator_principal`] was appended: the
/// smallest auth tail a host reads (THE KIND TAIL GROWTH RULE, `mechanism::door::tail_read_len`).
pub const AUTH_TAIL_FROZEN: usize = 40;

/// [`CancelOut::disposition`](super::mechanism::lifecycle::CancelOut) for an auth op: abandoned,
/// nothing kept.
pub const CANCEL_ABANDONED: u32 = 1;
/// [`CancelOut::disposition`](super::mechanism::lifecycle::CancelOut) for an auth op: the call is
/// dropped, but the work it started (a mint, a key-set fetch) completes in the background and fills
/// the plugin's cache. The ticket is never woken.
pub const CANCEL_CONTINUES: u32 = 2;

/// [`IdentifyOut::verdict`] for `verify`: identified; [`IdentifyOut::identity`] holds who.
pub const VERDICT_IDENTITY: u32 = 1;
/// [`IdentifyOut::verdict`] for `verify`: a credential was presented and is invalid. Fail-closed;
/// stops the chain.
pub const VERDICT_REJECT: u32 = 2;
/// [`IdentifyOut::verdict`] for `verify`: not this plugin's credential; try the next.
pub const VERDICT_PASS: u32 = 3;

/// [`IdentifyOut::decision`] for `verify`: the transport goes on with the request (the next
/// point, or hands it in). The SDK's default for [`VERDICT_IDENTITY`] and [`VERDICT_PASS`].
pub const DECISION_CONTINUE: u32 = 1;
/// [`IdentifyOut::decision`] for `verify`: the transport stops the request. The SDK's default
/// for [`VERDICT_REJECT`].
pub const DECISION_STOP: u32 = 2;

/// [`StripName::place`]: a field line of the request head, matched ASCII case-insensitively.
pub const STRIP_FIELD: u32 = 1;
/// [`StripName::place`]: a query key of the request target, matched case-sensitively.
pub const STRIP_QUERY: u32 = 2;

/// [`IdentifyOut::verdict`] for `complete_login`: identified.
pub const LOGIN_IDENTITY: u32 = 1;
/// [`IdentifyOut::verdict`] for `complete_login`: the directory or IdP answered, and the credential
/// is wrong.
pub const LOGIN_BAD_CREDENTIAL: u32 = 2;
/// [`IdentifyOut::verdict`] for `complete_login`: the directory or IdP could not answer (connect,
/// TLS, timeout, malformed reply). Distinct from a bad credential.
pub const LOGIN_OUTAGE: u32 = 3;
/// [`IdentifyOut::verdict`] for `complete_login`: the IdP answered, and its answer failed the
/// login's security check (an identity token whose `nonce` is not the one `begin_login` was
/// handed). No identity is trusted. Distinct from a declined credential: 1.5.5 rendered it as its
/// own page ("Sign-in couldn't be verified"). Appended.
pub const LOGIN_SECURITY_CHECK_FAILED: u32 = 4;

/// The identity buffer the host hands `verify`/`complete_login` to start: bytes.
pub const IDENTITY_BUF_BYTES: usize = 16 * 1024;
/// The identity buffer the host hands `verify`/`complete_login` to start: group spans.
pub const IDENTITY_GROUPS: u32 = 256;
/// The field buffer the host hands `fields` to start: bytes.
pub const FIELDS_BUF_BYTES: usize = 16 * 1024;
/// The field buffer the host hands `fields` to start: fields. Also the strip array the host
/// hands `verify` to start ([`VerifyIn::strip_cap`]); [`FIELDS_HARD_MAX`] bounds both.
pub const FIELDS_MAX: u32 = 16;

/// [`FieldsIn::mode`]: the plugin's own bound credential.
pub const MODE_OWN: u32 = 1;
/// [`FieldsIn::mode`]: pass the caller's verified credential ([`FieldsIn::caller_credential`]).
pub const MODE_PASSTHROUGH: u32 = 2;

/// `fields`' EXTENSIONS KEY ([`crate::abi::mechanism::extensions`], carried in
/// `FieldsIn::head.extensions`): the per-call scope the binding's credential is asked for, its
/// value the space-delimited scope text (ARCHITECT round 5 Q-L3B-EXCHANGE (B): the caller's
/// down-scope, which a token-exchange style requests as RFC 8693 `scope`). Absent = the call states
/// none; a style that asks no per-call scope never reads it.
pub const EXT_SCOPE: &str = "scope";

/// THE REQUEST FIELD BY WHICH A PLUGIN STATES ITS PER-CALL SCOPE to the host: a field of this name
/// in a request bound for the far end (a plane's attempt answer, a request it writes on its own
/// need) is the host's, never the far end's. The host takes it out of the request before anything is
/// encoded and carries its value into the member's auth call under [`EXT_SCOPE`]; no wire ever
/// carries it.
pub const SCOPE_REQUEST_FIELD: &str = "busbar-auth-scope";

/// Whether the request field `name` is [`SCOPE_REQUEST_FIELD`] (a field name compares
/// case-insensitively).
#[must_use]
pub fn is_scope_field(name: &[u8]) -> bool {
    name.eq_ignore_ascii_case(SCOPE_REQUEST_FIELD.as_bytes())
}

/// THE REQUEST FIELD BY WHICH A PLUGIN WAIVES ITS MEMBER'S BINDING FOR ONE REQUEST: a field of this
/// name in a request bound for the far end (a plane's attempt answer, a request it writes on its own
/// need) is the host's, never the far end's, exactly as [`SCOPE_REQUEST_FIELD`] is. The host takes
/// it out of the request before anything is encoded, and a request that carried it is opened with
/// NO member auth: the member's binding is not called and none of its fields are sent. Its value is
/// not read. A plugin can only waive a binding through it, never add or choose one, so it widens
/// nothing; no wire ever carries it.
pub const NO_MEMBER_AUTH_FIELD: &str = "busbar-no-member-auth";

/// Whether the request field `name` is [`NO_MEMBER_AUTH_FIELD`] (a field name compares
/// case-insensitively).
#[must_use]
pub fn is_no_member_auth_field(name: &[u8]) -> bool {
    name.eq_ignore_ascii_case(NO_MEMBER_AUTH_FIELD.as_bytes())
}

/// The extensions blob a request's stated `scope` is lent to its auth call in: one [`EXT_SCOPE`]
/// entry; empty (absent) when the request stated none.
#[must_use]
pub fn scope_extensions(scope: Option<&[u8]>) -> Vec<u8> {
    scope.map_or_else(Vec::new, |s| {
        crate::abi::mechanism::extensions::encode(&[(EXT_SCOPE, s)])
    })
}

/// [`FieldSpan::flags`]: when SET, an h2 encoder sends the field never-indexed. 1.5.5 sent its
/// credential headers indexable, so the 1.5.5 styles do NOT set it (ARCHITECT ruling 2026-09-28:
/// the 1.5.5 bytes win); marking them is a behaviour change taken only with the owner. Set or not,
/// the field is treated as sensitive everywhere else: the whole field buffer is never logged, no
/// value is printed, and it is zeroised after encode (an undeclared sensitivity is sensitive, owner
/// ruling 2026-10-27).
pub const FIELD_SENSITIVE: u32 = 1;
/// [`FieldSpan::flags`]: this field is a QUERY PARAMETER, not a header. The host's framer appends
/// it to the request target (`name=value`, each percent-encoded outside RFC 3986's unreserved set,
/// after any query the target already has, in the order written) and never sends it as a header.
/// The plane never sees it, and every target the host logs, reports in an error or labels a metric
/// with has its value redacted. Optional: a style that presents
/// only headers never sets it. For an upstream that takes its key as a query parameter (`?key=`).
pub const FIELD_QUERY: u32 = 2;

/// [`LoginField::kind`]: plain text.
pub const FORM_TEXT: u32 = 1;
/// [`LoginField::kind`]: a password; its submitted value arrives as a secret
/// [`Blob`](super::mechanism::call::Blob).
pub const FORM_PASSWORD: u32 = 2;

/// [`BeginLoginOut::shape`]: redirect to [`BeginLoginOut::authorize_url`].
pub const BEGIN_AUTHORIZE: u32 = 1;
/// [`BeginLoginOut::shape`]: render [`BeginLoginOut::form`].
pub const BEGIN_FORM: u32 = 2;

pub use super::mechanism::check::SPAN_ABSENT;

/// [`IdentityOut::flags`]: [`IdentityOut::ttl_secs`] is set.
pub const IDENTITY_HAS_TTL: u32 = 1;

// THE SDK's VIEW OF THE AUTH TABLE (`abi::sdk::door`): each kind op's `in`/`out`, stated next to
// the table, so `plugin_door!` refuses a kind op wired to any other structs. Every struct named
// here is plain data (integers, raw pointers, `AbiStr`/`Blob`, nested plain structs): every bit
// pattern is a valid value, which is what `AbiIn`/`AbiOut` promise.
//
// SAFETY (all below): `#[repr(C)]`, leading with `InHead`/`OutHead`, plain data only.
unsafe impl super::sdk::door::AbiIn for VerifyIn {}
unsafe impl super::sdk::door::AbiIn for BeginLoginIn {}
unsafe impl super::sdk::door::AbiIn for CompleteLoginIn {}
unsafe impl super::sdk::door::AbiIn for OpenOutboundIn {}
unsafe impl super::sdk::door::AbiIn for OutboundReadyIn {}
unsafe impl super::sdk::door::AbiIn for FieldsIn {}
unsafe impl super::sdk::door::AbiIn for TargetIn {}
unsafe impl super::sdk::door::AbiOut for IdentifyOut {}
unsafe impl super::sdk::door::AbiOut for BeginLoginOut {}
unsafe impl super::sdk::door::AbiOut for OpenOutboundOut {}
unsafe impl super::sdk::door::AbiOut for OutboundReadyOut {}
unsafe impl super::sdk::door::AbiOut for FieldsOut {}
unsafe impl super::sdk::door::AbiOut for TargetOut {}

super::sdk::door::slot_structs!(
    /// Each auth kind op's `in`/`out` for [`plugin_door!`](crate::plugin_door), per [`Ops`]' docs.
    /// A plugin wiring a slot to another op's structs does not compile:
    ///
    /// ```compile_fail,E0271
    /// use busbar_contract::abi::auth::{FieldsIn, FieldsOut, IdentifyOut, VerifyIn};
    /// use busbar_contract::abi::auth::{BeginLoginIn, BeginLoginOut, CompleteLoginIn};
    /// use busbar_contract::abi::auth::{OpenOutboundIn, OpenOutboundOut, OutboundReadyIn, OutboundReadyOut};
    /// use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
    /// use busbar_contract::abi::mechanism::lifecycle::*;
    /// use busbar_contract::abi::sdk::door::RawSlot;
    /// # use std::ffi::c_void;
    /// # macro_rules! ready { ($n:ident, $i:ty, $o:ty) => {
    /// #     struct $n;
    /// #     impl RawSlot for $n { type In = $i; type Out = $o;
    /// #         unsafe fn call(_: *mut c_void, _: &$i, _: &mut $o) -> Outcome { Outcome::Ready } }
    /// # } }
    /// # ready!(V, ValidateIn, OutHead); ready!(Op_, OpenIn, OpenOut); ready!(Rf, RefreshIn, OutHead);
    /// # ready!(Rt, GenIn, OutHead); ready!(Tk, TickIn, TickOut); ready!(Dr, DriveIn, OutHead);
    /// # ready!(Cn, CancelIn, CancelOut); ready!(Rl, ReleaseIn, OutHead); ready!(Cl, InHead, OutHead);
    /// # ready!(Begin, BeginLoginIn, BeginLoginOut); ready!(Complete, CompleteLoginIn, IdentifyOut);
    /// # ready!(OpenOb, OpenOutboundIn, OpenOutboundOut); ready!(Ready, OutboundReadyIn, OutboundReadyOut);
    /// # ready!(Fields, FieldsIn, FieldsOut);
    /// ready!(Verify, FieldsIn, FieldsOut); // `fields`' structs on `verify`: refused
    /// busbar_contract::plugin_door! {
    ///     ops: busbar_contract::abi::auth::Ops,
    ///     statement: busbar_contract::abi::sdk::door::statement("wrong", "0", 1),
    ///     lifecycle: { validate: V, open: Op_, refresh: Rf, retire: Rt, tick: Tk, drive: Dr,
    ///                  cancel: Cn, release: Rl, close: Cl },
    ///     kind_ops: { verify: Verify, begin_login: Begin, complete_login: Complete,
    ///                 open_outbound: OpenOb, outbound_ready: Ready, fields: Fields },
    /// }
    /// # fn main() { let _ = door(); }
    /// ```
    ///
    /// With `Verify` reading [`VerifyIn`] and writing [`IdentifyOut`] the same plugin compiles
    /// (`abi/sdk/tests/door_tests.rs`, `an_auth_plugin_wires_every_kind_op`).
    Ops {
        slot::VERIFY => VerifyIn, IdentifyOut;
        slot::BEGIN_LOGIN => BeginLoginIn, BeginLoginOut;
        slot::COMPLETE_LOGIN => CompleteLoginIn, IdentifyOut;
        slot::OPEN_OUTBOUND => OpenOutboundIn, OpenOutboundOut;
        slot::OUTBOUND_READY => OutboundReadyIn, OutboundReadyOut;
        slot::FIELDS => FieldsIn, FieldsOut;
        slot::TARGET => TargetIn, TargetOut;
    }
);
