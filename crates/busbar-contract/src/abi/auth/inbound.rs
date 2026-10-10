// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE INBOUND FAMILY: `verify` and the `begin_login`/`complete_login` pair, plus the shapes the
//! outbound family shares with them ([`RequestFacts`], [`NamedValue`]).
//!
//! An identity is WHO the caller is, never what they may do: nothing here has a slot for a pool, a
//! scope or a policy decision. The kernel resolves `groups -> role_bindings -> policy` afterwards.

use crate::abi::mechanism::call::{AbiStr, Blob, InHead, OutHead, Span};

/// A named value the host hands in: an inbound carrier field, or a submitted login field. A
/// credential-bearing value carries [`BLOB_SECRET`](crate::abi::mechanism::call::BLOB_SECRET).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NamedValue {
    /// The name.
    pub name: AbiStr,
    /// The value.
    pub value: Blob,
}

/// The request's fixed facts, shared by `verify` (an inbound signature check) and `fields` (an
/// outbound signature).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RequestFacts {
    /// The method.
    pub method: AbiStr,
    /// The authority (host\[:port\]).
    pub authority: AbiStr,
    /// For `fields`: the path exactly as the framer will send it (already percent-encoded); a
    /// signing style derives its own canonical form from it. For `verify`: the raw RECEIVED bytes,
    /// never normalized.
    pub canonical_path: AbiStr,
    /// The query without `?`; absent = none. For `fields`: as it will be sent (a signing style
    /// sorts and encodes it). For `verify`: the raw RECEIVED bytes, never normalized.
    pub query: AbiStr,
    /// Wall-clock seconds since the Unix epoch, read once by the host for this call.
    pub timestamp: u64,
}

/// The HOST buffer an identity is written into (request-path results live in host memory).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IdentityBuf {
    /// The bytes every [`Span`] of the answer points into.
    pub buf: *mut u8,
    /// Their capacity.
    pub buf_cap: usize,
    /// The group spans.
    pub groups: *mut Span,
    /// Their capacity.
    pub groups_cap: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// An identity, as spans into the host's [`IdentityBuf`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IdentityOut {
    /// The stable subject (required).
    pub subject: Span,
    /// The governance virtual-key id, if any.
    pub key_id: Span,
    /// The governance virtual-key display name, if any.
    pub key_name: Span,
    /// The end-user identifier, if any.
    pub user: Span,
    /// The asserting provider, if any.
    pub provider: Span,
    /// The display name, if any.
    pub name: Span,
    /// The claims blob. The kernel never reads it on the request path.
    pub claims: Span,
    /// The claims' [`Blob::fmt`](crate::abi::mechanism::call::Blob).
    pub claims_fmt: u32,
    /// [`super::IDENTITY_HAS_TTL`]; any other bit is FAULT.
    pub flags: u32,
    /// The suggested cache TTL, seconds (the plugin's cache clamps it; 3600 max, 300 default).
    pub ttl_secs: u64,
    /// How many group spans the plugin wrote into [`IdentityBuf::groups`].
    pub groups_len: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// A key the kernel must see only ONCE within [`Self::replay_ttl_secs`] (a signed webhook's
    /// message id). After a `verify` identity carrying one, the kernel claims
    /// `<plugin name>/<replay_key>` in its record store for that long, and a key already claimed
    /// refuses the request (replay). Absent or empty = no claim. The plane never sees it. Appended
    /// last (a pre-tag layout edit).
    pub replay_key: Span,
    /// How long the replay claim stands, seconds. Read only when [`Self::replay_key`] is present
    /// and non-empty.
    pub replay_ttl_secs: u64,
    /// The credential the identity was verified from, as the kernel holds it on the unit for the
    /// `caller-credential` style (THE DESIGN, "Auth points and guest lists", step 4). SECRET:
    /// it goes to the kernel only, never to the transport, never logged, zeroised at the unit's
    /// exit. Only with [`super::VERDICT_IDENTITY`]; absent = `len == 0`. Appended last (a pre-tag
    /// layout edit).
    pub credential: Span,
}

/// One credential line or query key an auth names for the transport to strip: a NAME, never a
/// value, so the plane never sees a credential (THE DESIGN, "Auth points and guest lists",
/// step 4). The name is a [`Span`] into the host's [`IdentityBuf`] bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StripName {
    /// The name.
    pub name: Span,
    /// [`super::STRIP_FIELD`] (a field line, ASCII case-insensitive) | [`super::STRIP_QUERY`] (a
    /// query key, case-sensitive).
    pub place: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// `verify`'s `in`: the request at one AUTH POINT (THE DESIGN, "Auth points and guest lists").
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VerifyIn {
    /// The head.
    pub head: InHead,
    /// The candidate credential (secret); absent = none presented.
    pub credential: Blob,
    /// The request's neutral field lines, as presented: the lines the Statement's carrier word
    /// marks name, or every line when the tail states [`super::FACT_INBOUND_ALL_HEADERS`]. At
    /// [`super::POINT_PEER`] there are none.
    pub lines: *const NamedValue,
    /// How many.
    pub lines_len: usize,
    /// The request's fixed facts (an inbound signature check reads them).
    pub request: RequestFacts,
    /// Where the identity and the strip names' bytes go.
    pub out_buf: IdentityBuf,
    /// The [`AuthPoint`](super::AuthPoint) this call is made at: exactly one of
    /// [`super::POINT_PEER`] | [`super::POINT_HEAD`] | [`super::POINT_HEAD_BODY`], one the tail's
    /// [`AuthTail::inbound_points`](super::AuthTail) holds.
    pub point: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The connection the request arrived on, so an auth needing several points correlates them.
    pub conn: u64,
    /// The unit the kernel minted for the request; `0` at [`super::POINT_PEER`] (no request yet).
    pub unit: u64,
    /// The peer facts (the TLS peer certificate from the connector, a spawn environment); present
    /// only at [`super::POINT_PEER`], else absent.
    pub peer: Blob,
    /// The whole request body; present only at [`super::POINT_HEAD_BODY`], else absent. Bounded
    /// by the size gate: over its limit the request is refused (413) before any verdict.
    pub body: Blob,
    /// The host array the plugin names its credential lines and query keys in
    /// ([`StripName`]), whatever its verdict.
    pub strip: *mut StripName,
    /// Its capacity ([`super::FIELDS_MAX`] to start).
    pub strip_cap: u32,
    /// Alignment padding.
    pub _reserved2: u32,
}

/// `verify`'s and `complete_login`'s `out`.
///
/// SHORT BUFFER: when the identity or the strip names do not fit, the plugin answers `FAILED`
/// with `needed_bytes`, `needed_groups` or `needed_strip` above the capacity it was given and
/// writes nothing else. The host re-issues
/// the op once, as a fresh call (no `FLAG_RESUME`) on the SAME ticket, with buffers at least that
/// large; a second short answer is FAULT. The plugin keeps the identity it reached for that ticket
/// and serves the retry from it, never repeating the work (an authorization code redeems once).
/// `FAILED` with both at `0` is a real failure. A buffer is at most `u32::MAX` bytes ([`Span`]).
///
/// THE ANSWER RULES, enforced by [`super::check_identify`] and [`super::check_complete_login`]
/// in `u64` math (any violation is FAULT). On REFUSED or PENDING, every `needed_*` is `0`. On
/// READY, every `needed_*` is `0`; the verdict is in the op's vocabulary; for `verify` the
/// decision is in its vocabulary, `strip_len <= strip_cap`, every strip name is present and in
/// bounds with a known `place`, and a `credential` span is present only with an identity; for
/// `complete_login` the decision, `strip_len` and `credential` are `0`/absent;
/// for an identity, `subject` is present, every present [`Span`] has `off + len <= buf_cap`, an
/// absent one ([`super::SPAN_ABSENT`]) has `len == 0`, `groups_len <= groups_cap`, every group
/// span is present and in bounds, and `flags` holds only [`super::IDENTITY_HAS_TTL`]. On FAILED,
/// `needed_bytes <= u32::MAX`, `needed_groups <=` [`super::IDENTITY_GROUPS_HARD_MAX`] and
/// `needed_strip <=` [`super::FIELDS_HARD_MAX`]; all `0` is a real failure; otherwise each reports its FULL size and at least one exceeds its capacity
/// (a fitting dimension's full size is legal; none exceeding is FAULT, a wasted re-call).
///
/// The identity buffer is ALWAYS secret material to the host (claims may carry an identity token):
/// never logged, zeroised after use. No plugin flag says so.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IdentifyOut {
    /// The head.
    pub head: OutHead,
    /// `verify`: [`super::VERDICT_IDENTITY`] | [`super::VERDICT_REJECT`] | [`super::VERDICT_PASS`].
    /// `complete_login`: [`super::LOGIN_IDENTITY`] | [`super::LOGIN_BAD_CREDENTIAL`] |
    /// [`super::LOGIN_OUTAGE`] | [`super::LOGIN_SECURITY_CHECK_FAILED`]. `0` is FAULT.
    pub verdict: u32,
    /// Short buffer: the group spans needed.
    pub needed_groups: u32,
    /// Short buffer: the bytes needed.
    pub needed_bytes: u64,
    /// Who, for an identity verdict.
    pub identity: IdentityOut,
    /// `verify` on READY: [`super::DECISION_CONTINUE`] | [`super::DECISION_STOP`], what the
    /// transport does with the request. `complete_login`: `0`.
    pub decision: u32,
    /// `verify` on READY: how many [`StripName`]s the plugin wrote into [`VerifyIn::strip`],
    /// whatever the verdict. `complete_login`: `0`.
    pub strip_len: u32,
    /// Short buffer: the strip names needed.
    pub needed_strip: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// `begin_login`'s `in`. Every field is core-minted or public; there is no secret.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BeginLoginIn {
    /// The head.
    pub head: InHead,
    /// The callback URL.
    pub redirect_uri: AbiStr,
    /// The core's anti-CSRF state.
    pub state: AbiStr,
    /// The core's nonce; absent = none.
    pub nonce: AbiStr,
    /// The core's PKCE challenge.
    pub code_challenge: AbiStr,
    /// The requested scopes.
    pub scopes: *const AbiStr,
    /// How many.
    pub scopes_len: usize,
}

/// One declared credential field of a login form.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LoginField {
    /// The field name.
    pub name: AbiStr,
    /// Its label.
    pub label: AbiStr,
    /// [`super::FORM_TEXT`] | [`super::FORM_PASSWORD`].
    pub kind: u32,
    /// `1` = required.
    pub required: u32,
}

/// `begin_login`'s `out`: the URL and form are plugin memory held under `OutHead.lease`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BeginLoginOut {
    /// The head.
    pub head: OutHead,
    /// EXACTLY ONE of [`super::BEGIN_AUTHORIZE`] | [`super::BEGIN_FORM`]; no bit, two bits or an
    /// unknown bit is FAULT ([`super::check_begin_login`]). The one named must be present: a
    /// non-empty URL, or `form_len > 0`. Any `len > 0` with a NULL pointer is FAULT.
    pub shape: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The IdP authorize URL ([`super::BEGIN_AUTHORIZE`]).
    pub authorize_url: AbiStr,
    /// The form ([`super::BEGIN_FORM`]).
    pub form: *const LoginField,
    /// How many.
    pub form_len: usize,
}

/// `complete_login`'s `in`. Its `out` is [`IdentifyOut`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CompleteLoginIn {
    /// The head.
    pub head: InHead,
    /// The authorization code (redirect flow), a
    /// [`BLOB_SECRET`](crate::abi::mechanism::call::BLOB_SECRET) blob; absent = none.
    pub code: Blob,
    /// The callback's state.
    pub state: AbiStr,
    /// The callback URL; absent = none.
    pub redirect_uri: AbiStr,
    /// The PKCE verifier, a [`BLOB_SECRET`](crate::abi::mechanism::call::BLOB_SECRET) blob;
    /// absent = none.
    pub code_verifier: Blob,
    /// The submitted form fields (credential flow); a password value is a secret blob.
    pub submitted: *const NamedValue,
    /// How many.
    pub submitted_len: usize,
    /// Where the identity goes.
    pub out_buf: IdentityBuf,
    /// The nonce the login's `begin_login` was handed (the core's, carried in its login cookie),
    /// so the plugin binds the IdP's identity token to it; absent = none. Appended.
    pub nonce: AbiStr,
}
