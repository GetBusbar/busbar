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
//! as 1.5.5's `STATUS_ERR`. `FAILED` on `complete_login` is [`LOGIN_OUTAGE`]. Both exclude the
//! short-buffer answer ([`IdentifyOut`]).
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

mod check;
mod inbound;
mod outbound;

pub use check::{
    check_begin_login, check_complete_login, check_fields, check_identify, FIELDS_HARD_MAX,
    IDENTITY_GROUPS_HARD_MAX,
};

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
    /// In [`VerifyIn`] (fixed 272 B, plus the credential and carrier bytes), out [`IdentifyOut`]
    /// (fixed 192 B; results in the host's [`IdentityBuf`], [`IDENTITY_BUF_BYTES`] and
    /// [`IDENTITY_GROUPS`] to start). The verdict is [`VERDICT_IDENTITY`], [`VERDICT_REJECT`] or
    /// [`VERDICT_PASS`]. OVERLOAD: when the instance's `max_inflight` is full, the host does not
    /// queue the call and answers the request 503 (an accepted difference from 1.5.5). The plugin
    /// never signals overload itself.
    pub verify: Option<Op>,
    /// Start a login. OFF-PATH; may pend through the plugin's own need; `Call`. In
    /// [`BeginLoginIn`] (fixed 168 B), out [`BeginLoginOut`] (fixed 136 B; URL and form held under
    /// `OutHead.lease`).
    pub begin_login: Option<Op>,
    /// Finish a login: the token exchange runs over the plugin's own need to its need-declared
    /// targets. OFF-PATH; may pend; `Call`. In [`CompleteLoginIn`] (fixed 216 B), out
    /// [`IdentifyOut`] (fixed 192 B; host [`IdentityBuf`]). The verdict is [`LOGIN_IDENTITY`],
    /// [`LOGIN_BAD_CREDENTIAL`] or [`LOGIN_OUTAGE`].
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
    /// In [`FieldsIn`] (fixed 288 B), out [`FieldsOut`] (fixed 112 B; fields in the host's
    /// buffer, [`FIELDS_BUF_BYTES`] and [`FIELDS_MAX`] to start; one re-call when short). READY
    /// with zero fields = no auth header, so the upstream answers 401: 1.5.5's answer before the
    /// first mint and for an un-encodable key.
    pub fields: Option<Op>,
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
/// [`AuthTail::facts`]: `verify` reads the request's body hash ([`RequestFacts::body_hash`]).
pub const FACT_INBOUND_NEEDS_BODY_HASH: u32 = 2;
/// [`AuthTail::facts`]: `verify` reads EVERY request header, not only [`AuthTail::carriers`]; the
/// kernel passes them all in [`VerifyIn::carrier`]. An inbound signature check needs it: the set of
/// signed headers varies per request.
pub const FACT_INBOUND_ALL_HEADERS: u32 = 4;

/// [`AuthTail::login_kind`]: no login ([`CAP_LOGIN`] not declared).
pub const LOGIN_KIND_NONE: u32 = 0;
/// [`AuthTail::login_kind`]: a redirect to an IdP.
pub const LOGIN_KIND_REDIRECT: u32 = 1;
/// [`AuthTail::login_kind`]: a credential form the core renders.
pub const LOGIN_KIND_CREDENTIAL: u32 = 2;

/// [`StyleDecl::flags`]: `fields` needs [`RequestFacts::body_hash`] for this style.
pub const STYLE_NEEDS_BODY_HASH: u32 = 1;
/// [`StyleDecl::flags`]: `fields` needs [`FieldsIn::headers`], the exact envelope, for this style.
pub const STYLE_NEEDS_HEADERS: u32 = 2;

/// One outbound style a plugin serves: an open string the provider's `auth:` resolves against.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StyleDecl {
    /// The style name.
    pub name: AbiStr,
    /// [`STYLE_NEEDS_BODY_HASH`] | [`STYLE_NEEDS_HEADERS`].
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
    /// [`FACT_CACHEABLE`] | [`FACT_INBOUND_NEEDS_BODY_HASH`] | [`FACT_INBOUND_ALL_HEADERS`].
    pub facts: u32,
    /// [`LOGIN_KIND_NONE`] | [`LOGIN_KIND_REDIRECT`] | [`LOGIN_KIND_CREDENTIAL`]: the
    /// classification the login chooser reads without calling `begin_login`. It is `NONE` exactly
    /// when [`CAP_LOGIN`] is absent; a tail where the two disagree refuses the load.
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
/// The field buffer the host hands `fields` to start: bytes.
pub const FIELDS_BUF_BYTES: usize = 16 * 1024;
/// The field buffer the host hands `fields` to start: fields.
pub const FIELDS_MAX: u32 = 16;

/// [`FieldsIn::mode`]: the plugin's own bound credential.
pub const MODE_OWN: u32 = 1;
/// [`FieldsIn::mode`]: pass the caller's verified credential ([`FieldsIn::caller_credential`]).
pub const MODE_PASSTHROUGH: u32 = 2;

/// [`FieldSpan::flags`]: the value is credential material. An h2 encoder sends it never-indexed,
/// as 1.5.5 did; like the whole field buffer it is never logged and is zeroised after encode.
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
unsafe impl super::sdk::door::AbiOut for IdentifyOut {}
unsafe impl super::sdk::door::AbiOut for BeginLoginOut {}
unsafe impl super::sdk::door::AbiOut for OpenOutboundOut {}
unsafe impl super::sdk::door::AbiOut for OutboundReadyOut {}
unsafe impl super::sdk::door::AbiOut for FieldsOut {}

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
    /// use busbar_contract::abi::sdk::door::Slot;
    /// # use std::ffi::c_void;
    /// # macro_rules! ready { ($n:ident, $i:ty, $o:ty) => {
    /// #     struct $n;
    /// #     impl Slot for $n { type In = $i; type Out = $o;
    /// #         fn call(_: *mut c_void, _: &$i, _: &mut $o) -> Outcome { Outcome::Ready } }
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
    }
);
