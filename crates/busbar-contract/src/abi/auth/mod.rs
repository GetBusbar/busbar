// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH KIND'S ABI (v3; design B.3): its version, its table, its Statement tail, its cancel
//! dispositions and the `in`/`out` of each of its operations. ONE kind with two operation families:
//! INBOUND (`verify`, and the `begin_login`/`complete_login` pair) and OUTBOUND (`open_outbound`,
//! `outbound_ready`, `fields`). There is no separate egress kind.
//!
//! THE CACHE LIVES IN THE PLUGIN (owner ruling Q-INCACHE). The kernel makes one call per request
//! and keeps no verdict cache. The plugin caches internally: Identify TTL clamped to 3600 s
//! (default 300), Reject never cached, 4096 entries. FLUSH THROUGH REFRESH: an auth plugin DROPS
//! its inbound cache on every `refresh`. `POST /admin/auth/cache/flush` (unchanged) is a `refresh`
//! with a NEW generation number and unchanged settings, so generations stay monotonic and memory
//! class (ii) holds.
//!
//! SERVICE CREDENTIALS (an LDAP bind password, an IdP client secret) are named by the mechanism
//! Statement's `secret_refs` (the settings keys holding a secret-ref). The kernel resolves them
//! into [`OpenIn::secrets`](super::mechanism::lifecycle::OpenIn) in the same order. The auth tail
//! carries nothing for them.
//!
//! DEADLINES ARE HOST-OWNED. No op carries a timeout of its own: the host stamps
//! `InHead.deadline_ns`, bounds every read on a need's connection, and calls `cancel` at expiry.
//!
//! A slot for a capability the tail does not declare is never called. The plugin still fills it
//! (a NULL slot refuses the load) and answers `REFUSED`.
//!
//! NOTHING dispatches through these shapes yet (M3-wire).

use super::mechanism::call::{AbiStr, Op};
use super::mechanism::door::KindTailHead;
use super::mechanism::lifecycle::{OpsHead, LIFECYCLE_SLOTS};

mod inbound;
mod outbound;

pub use inbound::{
    BeginLoginIn, BeginLoginOut, CompleteLoginIn, IdentifyOut, IdentityBuf, IdentityOut,
    LoginField, NamedValue, RequestFacts, Span, VerifyIn,
};
pub use outbound::{
    FieldSpan, FieldsIn, FieldsOut, OpenOutboundIn, OpenOutboundOut, OutboundReadyIn,
    OutboundReadyOut,
};

/// The auth kind's ABI version: v1.5.5 shipped `2` (`AUTH_ABI_VERSION`), so 1.6.0 ships `3`.
pub const ABI_VERSION: u32 = 3;

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
}

/// How many kind ops follow the lifecycle.
pub const KIND_SLOTS: u32 = 6;
/// [`OpsHead::slots`] for auth v3.
pub const SLOTS: u32 = LIFECYCLE_SLOTS + KIND_SLOTS;

/// The auth kind's ops table: the shared [`OpsHead`], then the kind's slots, contiguous.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ops {
    /// The lifecycle. `refresh` also drops the plugin's inbound cache (the admin flush).
    pub head: OpsHead,
    /// Judge an inbound credential. REQUEST-PATH; may pend (a key-set fetch or a directory read
    /// over the plugin's need); [`DeadlineClass::Call`](super::mechanism::call::DeadlineClass).
    /// In [`VerifyIn`] (fixed 256 B, plus the credential and carrier bytes), out [`IdentifyOut`]
    /// (fixed 192 B; results in the host's [`IdentityBuf`], [`IDENTITY_BUF_BYTES`] and
    /// [`IDENTITY_GROUPS`] to start). The verdict is [`VERDICT_IDENTITY`], [`VERDICT_REJECT`] or
    /// [`VERDICT_PASS`]. OVERLOAD: when the instance's `max_inflight` is full, the host does not
    /// queue the call and answers the request 503 (an accepted difference from 1.5.5). The plugin
    /// never signals overload itself.
    pub verify: Option<Op>,
    /// Start a login. OFF-PATH; may pend through the plugin's own need; `Call`. In
    /// [`BeginLoginIn`] (fixed 152 B), out [`BeginLoginOut`] (fixed 136 B; URL and form held under
    /// `OutHead.lease`).
    pub begin_login: Option<Op>,
    /// Finish a login: the token exchange runs over the plugin's own need to its need-declared
    /// targets. OFF-PATH; may pend; `Call`. In [`CompleteLoginIn`] (fixed 184 B), out
    /// [`IdentifyOut`] (fixed 192 B; host [`IdentityBuf`]). The verdict is [`LOGIN_IDENTITY`],
    /// [`LOGIN_BAD_CREDENTIAL`] or [`LOGIN_OUTAGE`].
    pub complete_login: Option<Op>,
    /// Bind one outbound style to its credential and answer a handle. OFF-PATH, at generation
    /// seal; never pends (the first mint runs in the background on `tick`); `Call`. In
    /// [`OpenOutboundIn`] (fixed 136 B), out [`OpenOutboundOut`] (fixed 104 B). A handle is
    /// GENERATION DATA: the kernel re-opens every handle at each generation, and a handle is valid
    /// until `retire` of the generation it was opened at. There is no close slot.
    pub open_outbound: Option<Op>,
    /// The handle's `ready` fact, read by the health prober. OFF-PATH; never pends; `Call`. In
    /// [`OutboundReadyIn`] (fixed 80 B), out [`OutboundReadyOut`] (fixed 104 B).
    pub outbound_ready: Option<Op>,
    /// The per-attempt call the kernel makes before encode: the auth fields for this request.
    /// REQUEST-PATH; may pend only when the cached token has expired and its refresh failed
    /// (the design's expired-token rule, Q-EXPIRED), bounded by the attempt's deadline; `Call`.
    /// In [`FieldsIn`] (fixed 256 B), out [`FieldsOut`] (fixed 104 B; fields in the host's
    /// buffer, at most [`FIELDS_BUF_BYTES`] and [`FIELDS_MAX`]). READY with zero fields = no auth
    /// header, so the upstream answers 401: 1.5.5's answer before the first mint and for an
    /// un-encodable key.
    pub fields: Option<Op>,
}

/// [`AuthTail::caps`]: the plugin serves `verify`.
pub const CAP_INBOUND: u32 = 1;
/// [`AuthTail::caps`]: the plugin serves `begin_login`/`complete_login`.
pub const CAP_LOGIN: u32 = 2;
/// [`AuthTail::caps`]: the plugin serves `open_outbound`/`outbound_ready`/`fields`.
pub const CAP_OUTBOUND: u32 = 4;

/// [`AuthTail::facts`]: the plugin's verdicts may be cached. The plugin caches them itself; the
/// kernel keeps no verdict cache.
pub const FACT_CACHEABLE: u32 = 1;
/// [`AuthTail::facts`]: `verify` reads the request's body hash ([`RequestFacts::body_hash`]).
pub const FACT_INBOUND_NEEDS_BODY_HASH: u32 = 2;

/// [`AuthTail::login_kind`]: no login ([`CAP_LOGIN`] not declared).
pub const LOGIN_KIND_NONE: u32 = 0;
/// [`AuthTail::login_kind`]: a redirect to an IdP.
pub const LOGIN_KIND_REDIRECT: u32 = 1;
/// [`AuthTail::login_kind`]: a credential form the core renders.
pub const LOGIN_KIND_CREDENTIAL: u32 = 2;

/// [`StyleDecl::flags`]: `fields` needs [`RequestFacts::body_hash`] for this style.
pub const STYLE_NEEDS_BODY_HASH: u32 = 1;

/// One outbound style a plugin serves: an open string the provider's `auth:` resolves against.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StyleDecl {
    /// The style name.
    pub name: AbiStr,
    /// [`STYLE_NEEDS_BODY_HASH`].
    pub flags: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// THE AUTH STATEMENT TAIL: `Statement.kind_tail` of an auth plugin. Plain `'static` data.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AuthTail {
    /// The tail head (`size` = `size_of::<AuthTail>()`).
    pub head: KindTailHead,
    /// [`CAP_INBOUND`] | [`CAP_LOGIN`] | [`CAP_OUTBOUND`].
    pub caps: u32,
    /// [`FACT_CACHEABLE`] | [`FACT_INBOUND_NEEDS_BODY_HASH`].
    pub facts: u32,
    /// [`LOGIN_KIND_NONE`] | [`LOGIN_KIND_REDIRECT`] | [`LOGIN_KIND_CREDENTIAL`]: the
    /// classification the login chooser reads without calling `begin_login`.
    pub login_kind: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The outbound styles served ([`CAP_OUTBOUND`]).
    pub styles: *const StyleDecl,
    /// How many.
    pub styles_len: usize,
    /// Other names the plugin answers to in config.
    pub aliases: *const AbiStr,
    /// How many.
    pub aliases_len: usize,
    /// The inbound carrier field names `verify` reads as a credential. The kernel passes exactly
    /// these to `verify` and strips them from what a plane sees.
    pub carriers: *const AbiStr,
    /// How many.
    pub carriers_len: usize,
}

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

/// [`IdentifyOut::verdict`] for `complete_login`: identified.
pub const LOGIN_IDENTITY: u32 = 1;
/// [`IdentifyOut::verdict`] for `complete_login`: the directory or IdP answered, and the credential
/// is wrong.
pub const LOGIN_BAD_CREDENTIAL: u32 = 2;
/// [`IdentifyOut::verdict`] for `complete_login`: the directory or IdP could not answer (connect,
/// TLS, timeout, malformed reply). Distinct from a bad credential.
pub const LOGIN_OUTAGE: u32 = 3;

/// The identity buffer the host hands `verify`/`complete_login` to start: bytes.
pub const IDENTITY_BUF_BYTES: usize = 16 * 1024;
/// The identity buffer the host hands `verify`/`complete_login` to start: group spans.
pub const IDENTITY_GROUPS: u32 = 256;
/// The field buffer the host hands `fields`: bytes, the op's maximum out.
pub const FIELDS_BUF_BYTES: usize = 16 * 1024;
/// The field buffer the host hands `fields`: fields, the op's maximum out.
pub const FIELDS_MAX: u32 = 16;

/// [`FieldsIn::mode`]: the plugin's own bound credential.
pub const MODE_OWN: u32 = 1;
/// [`FieldsIn::mode`]: pass the caller's verified credential ([`FieldsIn::caller_credential`]).
pub const MODE_PASSTHROUGH: u32 = 2;

/// [`FieldSpan::flags`]: the value is credential material. An h2 encoder sends it never-indexed,
/// as 1.5.5 did.
pub const FIELD_SENSITIVE: u32 = 1;

/// [`LoginField::kind`]: plain text.
pub const FORM_TEXT: u32 = 1;
/// [`LoginField::kind`]: a password; its submitted value arrives as a secret
/// [`Blob`](super::mechanism::call::Blob).
pub const FORM_PASSWORD: u32 = 2;

/// [`BeginLoginOut::shape`]: redirect to [`BeginLoginOut::authorize_url`].
pub const BEGIN_AUTHORIZE: u32 = 1;
/// [`BeginLoginOut::shape`]: render [`BeginLoginOut::form`].
pub const BEGIN_FORM: u32 = 2;

/// [`Span::off`] of an absent value.
pub const SPAN_ABSENT: u32 = u32::MAX;

/// [`IdentityOut::flags`]: [`IdentityOut::ttl_secs`] is set.
pub const IDENTITY_HAS_TTL: u32 = 1;
