// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH KIND'S CALLS, AS THE HOST'S TWO HALVES SHARE THEM (`BUSBAR-1.6.0.md` THE DESIGN,
//! sections 6, 11.4, 11.6 and 11.11): the [`AuthCalls`] trait the plugin loader implements over one loaded
//! auth instance, and the [`AuthAxis`] the composition root hands the kernel to open them. The
//! kernel's identity chain calls every auth plugin's `verify` through these, so a compiled-in and a
//! dropped-in auth plugin are reached through the same table. The kernel names this, the loader
//! names this, and neither names the other. Nothing here crosses the plugin boundary: the auth
//! kind's ABI is `abi::auth`.
//!
//! ONE CALL PER REQUEST PER CHAIN POSITION, and no verdict cache in the kernel: each auth plugin
//! caches inside itself, and drops that cache on `refresh` ([`AuthCalls::refresh`]).

use std::borrow::Cow;
use std::future::Future;

use crate::redacted::Redacted;
use std::sync::Arc;

use crate::abi::auth::AuthPoint;
use crate::auth::{BeginLogin, CompleteLogin, LoginKind, LoginOutcome};

/// One inbound request at one AUTH POINT, as the host hands it to `verify` (THE DESIGN, "Auth
/// points and guest lists"). Owned: the answer is awaited, so nothing here borrows the request.
pub struct VerifyRequest {
    /// The point the call is made at.
    pub point: AuthPoint,
    /// The connection the request arrived on.
    pub conn: u64,
    /// The unit the kernel minted for the request; `0` at [`AuthPoint::Peer`].
    pub unit: u64,
    /// The candidate credential the host extracted from the request (the data plane's client token,
    /// the admin plane's Bearer), lent as `verify`'s `credential` blob (`abi::auth::VerifyIn`);
    /// `None` = none presented. SECRET.
    pub credential: Option<Redacted<Vec<u8>>>,
    /// The neutral field lines, as presented (name, value). A value may be a credential: secret.
    pub lines: Vec<(String, Redacted<Vec<u8>>)>,
    /// The peer facts; `Some` only at [`AuthPoint::Peer`].
    pub peer: Option<Vec<u8>>,
    /// The whole body; `Some` only at [`AuthPoint::HeadBody`], bounded by the size gate.
    pub body: Option<Vec<u8>>,
    /// The method.
    pub method: String,
    /// The authority (host\[:port\]).
    pub authority: String,
    /// The path, raw as received.
    pub path: String,
    /// The query without `?`, raw as received; `None` = none.
    pub query: Option<String>,
    /// Wall-clock seconds since the Unix epoch, read once for this call.
    pub timestamp: u64,
}

impl Default for VerifyRequest {
    /// A request at [`AuthPoint::Head`] with nothing in it.
    fn default() -> Self {
        Self {
            point: AuthPoint::Head,
            conn: 0,
            unit: 0,
            credential: None,
            lines: Vec::new(),
            peer: None,
            body: None,
            method: String::new(),
            authority: String::new(),
            path: String::new(),
            query: None,
            timestamp: 0,
        }
    }
}

impl std::fmt::Debug for VerifyRequest {
    // Never the credential, a line value or the body: they carry the credential and the payload.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyRequest")
            .field("point", &self.point)
            .field("method", &self.method)
            .finish_non_exhaustive()
    }
}

/// WHO a `verify` identified, copied out of the host's identity buffer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifiedIdentity {
    /// The stable subject.
    pub subject: String,
    /// The governance virtual-key id, if any.
    pub key_id: Option<String>,
    /// The governance virtual-key display name, if any.
    pub key_name: Option<String>,
    /// The end-user identifier, if any.
    pub user: Option<String>,
    /// The asserting provider, if any.
    pub provider: Option<String>,
    /// The display name, if any.
    pub name: Option<String>,
    /// The asserted groups (roles), in the plugin's order.
    pub groups: Vec<String>,
    /// The suggested cache TTL, seconds.
    pub ttl_secs: Option<u64>,
    /// A key the kernel admits only once within its TTL, claimed in the record store under the
    /// verifying instance, the plugin's name and this key after this identity; `None` (or an empty
    /// key) = no claim. Never reaches a plane. Boxed: most identities carry none.
    pub replay: Option<Box<Replay>>,
    /// The credential the identity was verified from, for the kernel to hold on the unit for the
    /// `caller-credential` style (THE DESIGN, "Auth points and guest lists", step 4). SECRET:
    /// the kernel's only, never the transport's; `None` = the plugin named none.
    pub credential: Option<Redacted<String>>,
}

/// A replay claim an identity asks the kernel to make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replay {
    /// The key, unique per signed message (a webhook's message id).
    pub key: String,
    /// How long the claim stands, seconds.
    pub ttl_secs: u64,
}

/// One `verify`'s answer, as the kernel's chain reads it.
///
/// `large_enum_variant`: `Identity` carries the whole identity by value; the answer is built once
/// per call and consumed by the chain at once, never held in a collection, so a box would only add
/// an allocation per verify.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verified {
    /// Identified.
    Identity(VerifiedIdentity),
    /// A credential was presented and is invalid: the chain stops, denied.
    Reject,
    /// Not this plugin's credential: the chain tries the next.
    Pass,
    /// The call did not answer a verdict (FAILED, FAULT, REFUSED, a timeout or a second short
    /// answer): the chain's error path, fail-closed as 1.5.5's module failure.
    Failed,
    /// The instance's `max_inflight` is full: the call was not queued. The host answers the
    /// request 503 (THE DESIGN, section 11.11: an accepted difference from 1.5.5).
    Overloaded,
}

/// What the transport does with the request after a point call (THE DESIGN, "Auth points and
/// guest lists", step 3): the only verdict-derived thing it receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Go on: the next point, or hand the request in.
    Continue,
    /// Stop the request.
    Stop,
}

/// Where a credential name sits in the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StripPlace {
    /// A field line, matched ASCII case-insensitively.
    Field,
    /// A query key, matched case-sensitively.
    Query,
}

/// One credential line or query key an auth names for the transport to strip: a NAME, never a
/// value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Strip {
    /// The name.
    pub name: Cow<'static, str>,
    /// Where it sits.
    pub place: StripPlace,
}

impl Strip {
    /// The field line `name`.
    #[must_use]
    pub fn field(name: impl Into<Cow<'static, str>>) -> Self {
        Self {
            name: name.into(),
            place: StripPlace::Field,
        }
    }

    /// The query key `name`.
    #[must_use]
    pub fn query(name: impl Into<Cow<'static, str>>) -> Self {
        Self {
            name: name.into(),
            place: StripPlace::Query,
        }
    }
}

/// One `verify`'s whole answer as the host reads it: the verdict (the kernel's), the decision and
/// the lines to strip (the transport's).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyAnswer {
    /// The verdict, with the identity and its credential: the kernel's only.
    pub verified: Verified,
    /// Continue or stop.
    pub decision: Decision,
    /// The credential lines and query keys the auth named, whatever its verdict.
    pub strips: Vec<Strip>,
}

impl From<Verified> for VerifyAnswer {
    /// The verdict with no strips and its default decision: continue on an identity or a pass,
    /// stop otherwise (a reject, a failure, an overloaded verifier).
    fn from(verified: Verified) -> Self {
        let decision = match verified {
            Verified::Identity(_) | Verified::Pass => Decision::Continue,
            Verified::Reject | Verified::Failed | Verified::Overloaded => Decision::Stop,
        };
        Self {
            verified,
            decision,
            strips: Vec::new(),
        }
    }
}

/// One `verify` in flight. Dropping it before it answered is a client drop.
pub trait Verifying: Future<Output = VerifyAnswer> + Send + Unpin {
    /// The answer, if it has arrived; never waits. A SYNC caller polls this once and fails closed
    /// on `None` rather than block a thread.
    fn settled(&mut self) -> Option<VerifyAnswer>;

    /// Whether the verify's answer is a FAULT: the plugin broke its contract (a caught panic, a
    /// malformed answer), answered as a failed verify — so the host can tell a plugin that failed
    /// from one that refused. `false` until the verify has answered.
    fn faulted(&self) -> bool {
        false
    }
}

/// One `complete_login` as the kernel hands it: the callback's `state` and the login's `nonce` (the
/// core-minted values its login cookie carried, which the plugin binds the IdP's answer to), and the
/// callback's code / PKCE verifier or the submitted credential form.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LoginCallback {
    /// The callback's `state` (already checked against the login cookie by the kernel).
    pub state: String,
    /// The nonce `begin_login` was handed; `None` = none.
    pub nonce: Option<String>,
    /// The code, redirect URI and PKCE verifier (redirect flow) or the submitted fields (credential
    /// flow). `token_response` is never set: the plugin makes its own token exchange.
    pub login: CompleteLogin,
}

/// One `begin_login` or `complete_login` in flight. Dropping it before it answered abandons it.
///
/// `begin_login` answers [`LoginOutcome::Authorize`] or [`LoginOutcome::Prompt`];
/// `complete_login` answers [`LoginOutcome::Identify`] (`LOGIN_IDENTITY`),
/// [`LoginOutcome::Reject`] (`LOGIN_BAD_CREDENTIAL`) or [`LoginOutcome::Outage`] (`LOGIN_OUTAGE`).
/// A call that answered no verdict (FAILED, FAULT, REFUSED, a timeout, a second short answer, or
/// the instance at `max_inflight`) is [`LoginOutcome::Reject`], fail-closed, as 1.5.5 refused a
/// login plugin that failed or could not be started.
pub trait LoginCall: Future<Output = LoginOutcome> + Send + Unpin {
    /// The answer, if it has arrived; never waits.
    fn settled(&mut self) -> Option<LoginOutcome>;

    /// Whether the step's answer is a FAULT: the plugin broke its contract (a caught panic, a
    /// malformed answer), answered as [`LoginOutcome::Reject`] — so the host can tell a plugin
    /// that failed from one that declined. `false` until the step has answered.
    fn faulted(&self) -> bool {
        false
    }
}

/// A login step answered before anything crossed.
#[derive(Debug)]
pub struct LoginSettled(pub Option<LoginOutcome>);

impl Future for LoginSettled {
    type Output = LoginOutcome;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<LoginOutcome> {
        std::task::Poll::Ready(self.0.take().unwrap_or(LoginOutcome::Reject))
    }
}

impl LoginCall for LoginSettled {
    fn settled(&mut self) -> Option<LoginOutcome> {
        Some(self.0.take().unwrap_or(LoginOutcome::Reject))
    }
}

/// ONE AUTH INSTANCE'S CALLS, as the kernel's identity chain makes them.
pub trait AuthCalls: Send + Sync {
    /// The name the plugin's Statement states.
    fn name(&self) -> &str;

    /// The tail's facts (`abi::auth::FACT_*`).
    fn facts(&self) -> u32;

    /// With [`crate::abi::auth::FACT_READS_CREDENTIALS`]: the host-held credential kinds `verify`
    /// reads through `records.secret`, as the tail names them (opaque words to the kernel); none
    /// otherwise.
    fn credential_kinds(&self) -> Vec<String> {
        Vec::new()
    }

    /// The inbound carriers `verify` reads (field line names, lower-case), as the Statement's
    /// carrier word marks name them: where the plugin's credential sits. The host names no
    /// credential line itself (THE DESIGN, "Auth points and guest lists").
    fn carriers(&self) -> Vec<String> {
        Vec::new()
    }

    /// `verify` ON THE SPOT: one ticket-less crossing on the caller's thread, bounded by the
    /// dispatcher's watchdog (THE DESIGN, section 12: a crossing that cannot wait needs no ticket). A
    /// plugin whose `verify` must wait on I/O answers REFUSED there (`abi::auth`), and this answers
    /// `None`: the caller then [`AuthCalls::verify`]s, awaiting it. A short answer is re-called once.
    fn verify_now(&self, request: &VerifyRequest) -> Option<VerifyAnswer>;

    /// Submit `verify`; it crosses on a dispatcher worker and its answer is a future, so no thread
    /// is parked. A short answer is re-called once with the buffers it named; a second is
    /// [`Verified::Failed`]. The instance's `max_inflight` full is [`Verified::Overloaded`], never
    /// queued: the host answers the request 503 (THE DESIGN's accepted differences).
    fn verify(&self, request: VerifyRequest) -> Box<dyn Verifying>;

    /// `refresh` with a NEW generation and unchanged settings: the admin cache flush. The plugin
    /// drops its inbound cache. Answers how many entries it dropped, as the plugin reported them
    /// under [`crate::abi::auth::METRIC_CACHE_FLUSHED`] (`0` when it reported none).
    ///
    /// # Errors
    /// The refresh did not answer READY.
    fn refresh(&self) -> Result<u64, String>;

    /// How the plugin's login starts, as its tail states it (`abi::auth::LOGIN_KIND_*`); `None` =
    /// it serves no login (`CAP_LOGIN` not stated). Read without calling `begin_login`.
    fn login_kind(&self) -> Option<LoginKind> {
        None
    }

    /// Submit `begin_login`: the IdP authorize URL ([`LoginOutcome::Authorize`]) or the credential
    /// form ([`LoginOutcome::Prompt`]). Its answer is a future; no thread is parked.
    fn begin_login(&self, request: BeginLogin) -> Box<dyn LoginCall> {
        let _ = request;
        Box::new(LoginSettled(Some(LoginOutcome::Reject)))
    }

    /// Submit `complete_login`: the plugin runs the token exchange over its own need, holding its
    /// own client secret, and answers who ([`LoginOutcome::Identify`]), a declined credential
    /// ([`LoginOutcome::Reject`]) or an unreachable IdP ([`LoginOutcome::Outage`]). A short answer
    /// is re-called once.
    fn complete_login(&self, request: LoginCallback) -> Box<dyn LoginCall> {
        let _ = request;
        Box::new(LoginSettled(Some(LoginOutcome::Reject)))
    }
}

/// THE AUTH AXIS, as the composition root hands it to the kernel (the shape of the export kind's
/// `ExportAxis`): which auth modules a door answers, and opening one on the process's one
/// dispatcher. Installed once through the root's rows (`busbar_kernel::preflight::RootRows`).
pub trait AuthAxis: Send + Sync {
    /// The config keys of the auth rows this build LINKS, in registration order.
    fn linked_names(&self) -> Vec<String>;

    /// Whether a `kind: auth` row answers the module key `module` (linked or dropped in).
    fn answers(&self, module: &str) -> bool;

    /// Whether `module` names a row this build LINKS.
    fn linked(&self, module: &str) -> bool;

    /// THE OPERATOR CREDENTIAL'S ROW: the auth row whose Statement states
    /// [`FACT_OPERATOR`](crate::abi::auth::FACT_OPERATOR), as its module key and the principal id it
    /// names; linked rows first. `None` when no row states it.
    fn operator(&self) -> Option<(String, String)>;

    /// OPEN one instance of `module` over `settings` (the provider's settings, one JSON document,
    /// its secret-refs already resolved), under the host's instance `label` (unique per opened
    /// instance: the name every host service keys its caller by).
    ///
    /// # Errors
    /// Why it will not open, naming the module: no door answers it, the door refused the load, or
    /// `open` did not answer READY.
    fn open(
        &self,
        module: &str,
        label: &str,
        settings: &serde_json::Value,
    ) -> Result<Arc<dyn AuthCalls>, String>;

    /// The config keys of the auth rows whose Statement states
    /// [`FACT_READS_CREDENTIALS`](crate::abi::auth::FACT_READS_CREDENTIALS): the verifiers of the
    /// host-held credentials (core's `keys` verifies the credential such a style yields, THE
    /// DESIGN, "Auth points and guest lists"), linked rows first. None by default.
    fn credential_readers(&self) -> Vec<String> {
        Vec::new()
    }

    /// THE AUTH PLUGIN SERVING THE OUTBOUND `style` for a binding under `settings` (THE DESIGN
    /// section 6 step 3: the auth plugin that serves the style opens the binding), its instance
    /// opened for its outbound styles; `None` when no row this build reaches states the style.
    ///
    /// # Errors
    /// The serving plugin would not open for its outbound styles.
    fn serving(
        &self,
        style: &str,
        settings: &serde_json::Value,
    ) -> Result<Option<OutboundServing>, String> {
        let _ = (style, settings);
        Ok(None)
    }

    /// CHECK, NEVER DIAL (the `--validate` dry run): bind `credential` under `settings` on a fresh
    /// instance of the auth plugin serving `style`, one granted no need, and answer the refusals it
    /// names for the credential itself (its `credential:` lines, their text), in its own words.
    /// Empty when it accepts the credential, or when no plugin this build reaches serves the style.
    ///
    /// # Errors
    /// The serving plugin would not open for its outbound styles.
    fn check_outbound(
        &self,
        style: &str,
        credential: &[u8],
        settings: &serde_json::Value,
    ) -> Result<Vec<String>, String> {
        let _ = (style, credential, settings);
        Ok(Vec::new())
    }
}

/// ONE AUTH PLUGIN SERVING AN OUTBOUND STYLE ([`AuthAxis::serving`]): its instance, and the style
/// as its tail states it.
#[derive(Clone)]
pub struct OutboundServing {
    /// The instance, opened for its outbound styles.
    pub auth: Arc<dyn OutboundAuth>,
    /// The style's `abi::auth::StyleDecl::flags`.
    pub flags: u32,
    /// The style's `abi::auth::StyleDecl::points` (an `AuthPoints` bit set).
    pub points: u32,
}

impl std::fmt::Debug for OutboundServing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundServing")
            .field("flags", &self.flags)
            .field("points", &self.points)
            .finish_non_exhaustive()
    }
}

// THE OUTBOUND HALF (open_outbound/fields) ─────────────────────────────────────────────────────
//
// THE DESIGN, section 6 and section 11.6: for every attempt the kernel makes ONE uniform call to the provider's
// auth plugin, "give me the auth fields for this request", by the handle `open_outbound` answered
// when the generation was sealed. The plugin caches inside itself; the kernel keeps only the handle
// and no auth cache, and never branches per plugin or per style.

/// One attempt's fixed facts at one AUTH POINT, as the kernel hands them to `fields` (THE
/// DESIGN, "Auth points and guest lists", step 4: outbound sign is the same kind's other op, made
/// at the points the style states). Owned: the answer may be awaited, so nothing here borrows the
/// request.
pub struct FieldsRequest {
    /// The point the call is made at: one of the style's `StyleDecl::points`.
    pub point: AuthPoint,
    /// The connection the binding sends on; `0` while none is dialed yet.
    pub conn: u64,
    /// The unit the request belongs to; `0` = none.
    pub unit: u64,
    /// The whole body; `Some` only at [`AuthPoint::HeadBody`]. A style that signs the body hashes
    /// it itself.
    pub body: Option<Vec<u8>>,
    /// The method.
    pub method: Vec<u8>,
    /// The authority (host\[:port\]).
    pub authority: String,
    /// The path exactly as the framer will send it.
    pub path: Vec<u8>,
    /// The query without `?`, as it will be sent; `None` = none.
    pub query: Option<Vec<u8>>,
    /// Wall-clock seconds since the Unix epoch, read once by the kernel for this call.
    pub timestamp: u64,
    /// The exact head envelope the framer will send, in order, when the style declares
    /// `abi::auth::STYLE_NEEDS_HEADERS`; empty otherwise.
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    /// The caller's verified credential, for a passthrough binding (`abi::auth::MODE_PASSTHROUGH`).
    /// Secret: zeroised when it drops (every copy is its own [`Redacted`]).
    pub caller_credential: Option<Redacted<Vec<u8>>>,
    /// The call's extensions blob (`abi::mechanism::extensions`), lent as `FieldsIn::head.extensions`:
    /// the per-call scope under `abi::auth::EXT_SCOPE` when the request stated one. Empty = absent.
    pub extensions: Vec<u8>,
}

impl Default for FieldsRequest {
    /// A request at [`AuthPoint::Head`] with nothing in it.
    fn default() -> Self {
        Self {
            point: AuthPoint::Head,
            conn: 0,
            unit: 0,
            body: None,
            method: Vec::new(),
            authority: String::new(),
            path: Vec::new(),
            query: None,
            timestamp: 0,
            headers: Vec::new(),
            caller_credential: None,
            extensions: Vec::new(),
        }
    }
}

impl std::fmt::Debug for FieldsRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the caller's credential: it is secret material.
        f.debug_struct("FieldsRequest")
            .field("point", &self.point)
            .field("method", &String::from_utf8_lossy(&self.method))
            .field("authority", &self.authority)
            .field(
                "caller_credential",
                &self.caller_credential.as_ref().map(|_| "<redacted>"),
            )
            .finish_non_exhaustive()
    }
}

/// One auth field that joins the head before the framer encodes it.
#[derive(Clone)]
pub struct AuthField {
    /// The field name.
    pub name: Vec<u8>,
    /// The value: credential material, zeroised when it drops, whichever copy it is.
    pub value: Redacted<Vec<u8>>,
    /// `abi::auth::FIELD_SENSITIVE`: never logged, zeroised once the head is encoded.
    pub sensitive: bool,
}

impl std::fmt::Debug for AuthField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = if self.sensitive {
            "<redacted>".to_string()
        } else {
            String::from_utf8_lossy(self.value.expose_secret()).into_owned()
        };
        f.debug_struct("AuthField")
            .field("name", &String::from_utf8_lossy(&self.name))
            .field("value", &value)
            .finish()
    }
}

impl PartialEq for AuthField {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.value.expose_secret() == other.value.expose_secret()
            && self.sensitive == other.sensitive
    }
}

impl Eq for AuthField {}

/// One `fields`' answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fields {
    /// The fields, in order; none = no auth field (the upstream answers 401, as 1.5.5 did before
    /// the first mint).
    Ready(Vec<AuthField>),
    /// The handle refused the request (a passthrough on a style that does not pass the caller's
    /// credential, or a handle this generation does not hold).
    Refused,
    /// The call did not answer (FAILED, FAULT, a timeout or a second short answer): the attempt
    /// fails.
    Failed,
}

/// One `fields` in flight: PENDING while the plugin's cached token refreshes, bounded by the
/// attempt's deadline. Dropping it before it answered is a client drop.
pub trait Fielding: Future<Output = Fields> + Send + Unpin {
    /// The answer, if it has arrived; never waits.
    fn settled(&mut self) -> Option<Fields>;
}

/// ONE AUTH INSTANCE'S OUTBOUND CALLS, as the kernel's egress walk makes them.
pub trait OutboundAuth: Send + Sync {
    /// Bind `style` to its resolved `credential` (secret; empty for a passthrough-only binding)
    /// and the provider's auth `settings` (one JSON document); the handle the plugin answered.
    /// OFF-PATH: at generation seal.
    ///
    /// # Errors
    ///
    /// `open_outbound` did not answer READY.
    fn open_outbound(
        &self,
        style: &str,
        credential: &[u8],
        settings: &serde_json::Value,
    ) -> Result<u64, String>;

    /// `fields` ON THE SPOT: one ticket-less crossing on the caller's thread. `Some` only for a
    /// READY answer (a cached header: bearer, api-key, a fresh minted token, a SigV4 signature);
    /// `None` when the plugin cannot answer in place, and the caller then [`OutboundAuth::fields`]s.
    fn fields_now(&self, handle: u64, request: &FieldsRequest) -> Option<Fields>;

    /// Submit `fields` on a dispatcher worker; its answer is a future, so no thread is parked.
    /// `deadline_ns` (the dispatcher's clock; `0` = the op's own class) bounds a PENDING answer.
    fn fields(&self, handle: u64, request: FieldsRequest, deadline_ns: u64) -> Box<dyn Fielding>;

    /// `outbound_ready`: whether `fields` would answer with a credential now (`false` before a
    /// minting style's first mint, or expired with a failed refresh). The health prober reads it.
    /// ON THE SPOT, ticket-less. Default: ready.
    fn ready(&self, handle: u64) -> bool {
        let _ = handle;
        true
    }
}
