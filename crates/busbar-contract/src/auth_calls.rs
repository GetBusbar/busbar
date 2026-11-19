// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH KIND'S CALLS, AS THE HOST'S TWO HALVES SHARE THEM (`BUSBAR-1.6.0.md` THE DESIGN,

pub mod codes;
/// Inert provider-owned login presentation carried by the auth lifecycle.
pub mod presentation;
pub use presentation::{LoginIcon, LoginIconPath, LoginPresentation};

use std::borrow::Cow;
use std::future::Future;

use crate::redacted::Secret;
use std::sync::Arc;

use crate::auth::{BeginLogin, CompleteLogin, LoginKind, LoginOutcome};
use crate::route::AuthPoint;

/// One inbound request at one AUTH POINT, as the host hands it to `verify` (THE DESIGN, "Auth
pub struct VerifyRequest {
    /// The point the call is made at.
    pub point: AuthPoint,
    /// The connection the request arrived on.
    pub conn: u64,
    /// The unit the kernel minted for the request; `0` at [`AuthPoint::Peer`].
    pub unit: u64,
    /// The candidate credential the host extracted from the request (the data plane's client token,
    pub credential: Option<Secret<Vec<u8>>>,
    /// The neutral field lines, as presented (name, value). A value may be a credential: secret.
    pub lines: Vec<(String, Secret<Vec<u8>>)>,
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

impl Drop for VerifyRequest {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.peer.zeroize();
        self.body.zeroize();
        self.method.zeroize();
        self.authority.zeroize();
        self.path.zeroize();
        self.query.zeroize();
        for (name, _) in &mut self.lines {
            name.zeroize();
        }
    }
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
    pub credential: Option<Secret<String>>,
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
    /// WHY a [`Verified::Reject`] rejected, in the plugin's words (`abi::auth::IdentifyOut`, THE
    /// REASON): the operator's log only, never the client's answer. `None` = none given.
    pub reason: Option<String>,
}

impl From<Verified> for VerifyAnswer {
    /// The verdict with no strips and its default decision: continue on an identity or a pass,
    fn from(verified: Verified) -> Self {
        let decision = match verified {
            Verified::Identity(_) | Verified::Pass => Decision::Continue,
            Verified::Reject | Verified::Failed | Verified::Overloaded => Decision::Stop,
        };
        Self {
            verified,
            decision,
            strips: Vec::new(),
            reason: None,
        }
    }
}

/// One `verify` in flight. Dropping it before it answered is a client drop.
pub trait Verifying: Future<Output = VerifyAnswer> + Send + Unpin {
    /// The answer, if it has arrived; never waits. A SYNC caller polls this once and fails closed
    fn settled(&mut self) -> Option<VerifyAnswer>;

    /// Whether the verify's answer is a FAULT: the plugin broke its contract (a caught panic, a
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
pub trait LoginCall: Future<Output = LoginOutcome> + Send + Unpin {
    /// The answer, if it has arrived; never waits.
    fn settled(&mut self) -> Option<LoginOutcome>;

    /// Whether the step's answer is a FAULT: the plugin broke its contract (a caught panic, a
    fn faulted(&self) -> bool {
        false
    }

    /// Why a declined credential was declined, when the plugin said
    /// (`crate::abi::auth::EXT_REJECT_HINT` on a `LOGIN_BAD_CREDENTIAL` reply). The host acts on it
    /// (it stops forwarding attempts for the account) and never shows it to the client. `None`
    /// before the step answered, for any other answer, and when the plugin stated nothing.
    fn reject_hint(&self) -> Option<RejectHint> {
        None
    }
}

/// What a plugin may say about WHY it declined a credential (`complete_login`'s reply extension
/// `crate::abi::auth::EXT_REJECT_HINT`). Additive: a plugin that states nothing is a plain decline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectHint {
    /// The directory reports the account locked (for example Active Directory `data 775`).
    AccountLocked,
    /// The plugin's own attempt limiter refused the attempt.
    Throttled,
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

/// THE SHAPE OF THE CREDENTIAL THE HOST ISSUES for an auth row that reads host-held credentials,
/// as the row's Statement states it in its `MARK_WORD_ISSUED_*` word marks
/// (`crate::plugin_settings::sugar_words::MARK_WORD_ISSUED_ID_PREFIX` and its siblings), checked at load.
/// Kind-neutral: the host draws every symbol after the prefix from the OS CSPRNG over the stated
/// alphabets, each symbol with equal weight, and names no format of its own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IssuedShape {
    /// The public id's literal prefix (empty = none).
    pub id_prefix: String,
    /// The public id's total length in characters, the prefix included.
    pub id_len: usize,
    /// The public id's alphabet after the prefix: distinct ASCII graphic characters.
    pub id_alphabet: String,
    /// The secret's length in characters.
    pub secret_len: usize,
    /// The secret's alphabet: distinct ASCII graphic characters.
    pub secret_alphabet: String,
}

/// ONE AUTH INSTANCE'S CALLS, as the kernel's identity chain makes them.
pub trait AuthCalls: Send + Sync {
    /// The name the plugin's Statement states.
    fn name(&self) -> &str;

    /// The tail's facts (`abi::auth::FACT_*`).
    fn facts(&self) -> u32;

    /// With `crate::auth_calls::codes::FACT_READS_CREDENTIALS`: the host-held credential kinds `verify`
    fn credential_kinds(&self) -> Vec<String> {
        Vec::new()
    }

    /// With `crate::auth_calls::codes::FACT_READS_CREDENTIALS`: the shape of the credential the host issues
    fn issued_shape(&self) -> Option<IssuedShape> {
        None
    }

    /// The auth points `verify` is called at, as the tail states them
    fn inbound_points(&self) -> crate::route::AuthPoints {
        crate::route::AuthPoints::HEAD
    }

    /// The inbound carriers `verify` reads (field line names, lower-case), as the Statement's
    fn carriers(&self) -> Arc<[String]> {
        Arc::default()
    }

    /// `verify` ON THE SPOT: one ticket-less crossing on the caller's thread, bounded by the
    fn verify_now(&self, request: &VerifyRequest) -> Option<VerifyAnswer>;

    /// Submit `verify`; it crosses on a dispatcher worker and its answer is a future, so no thread
    fn verify(&self, request: VerifyRequest) -> Box<dyn Verifying>;

    /// `refresh` with a NEW generation and unchanged settings: the admin cache flush. The plugin
    fn refresh(&self) -> Result<u64, String>;

    /// Whether this instance answers `verify` itself right now: not quarantined, revoked or
    /// closed, and its metadata valid. Default `false`: an implementor that cannot tell is never
    /// trusted to be answering.
    fn answering(&self) -> bool {
        false
    }

    /// Whether core may carry this instance into the next config build unchanged (its inputs are
    /// unchanged and it is healthy: answering, and its refresh schedule did not fail). Default
    /// `false`: an implementor that cannot tell is opened again on every build, as before
    /// (WASTE-AUTH-SECRETS W2).
    fn reusable(&self) -> bool {
        false
    }

    /// RE-LEND: take `settings` (this instance's settings re-resolved from what it was opened
    /// over) and, when the secret material lent from them changed, hand it to the plugin's
    /// `refresh`. `NotRefreshed` asks the caller to open a new instance and swap it in. A refusal
    /// leaves the instance as it was.
    fn relend(
        &self,
        settings: &crate::plugin_settings::ResolvedSettings,
    ) -> Result<crate::secret::AuthRelent, String> {
        let _ = settings;
        Ok(crate::secret::AuthRelent::Unchanged)
    }

    /// Validated presentation from the current successful lifecycle generation.
    /// Absence uses the configured instance name and the host's generic icon.
    fn login_presentation(&self) -> Option<LoginPresentation> {
        None
    }

    /// How the plugin's login starts, as its tail states it (`abi::auth::LOGIN_KIND_*`); `None` =
    fn login_kind(&self) -> Option<LoginKind> {
        None
    }

    /// Submit `begin_login`: the IdP authorize URL ([`LoginOutcome::Authorize`]) or the credential
    fn begin_login(&self, request: BeginLogin) -> Box<dyn LoginCall> {
        let _ = request;
        Box::new(LoginSettled(Some(LoginOutcome::Reject)))
    }

    /// Submit `complete_login`: the plugin runs the token exchange over its own need, holding its
    fn complete_login(&self, request: LoginCallback) -> Box<dyn LoginCall> {
        let _ = request;
        Box::new(LoginSettled(Some(LoginOutcome::Reject)))
    }
}

/// One admitted `kind: auth` row whose Statement states the operator credential fact
/// (`FACT_OPERATOR` with its `operator_principal`), as process start and every build read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorClaim {
    /// The row's config key (its manifest alias), as `answers` matches it.
    pub provider: String,
    /// The plugin's canonical name: the key claims are de-duplicated on.
    pub canonical: String,
    /// The stated operator principal (never empty: the Statement decoder refuses an empty one).
    pub principal: String,
    /// Whether the row is first-party: linked, or verified against a busbar release key.
    pub first_party: bool,
    /// The row's version, for the audit row only; never part of a judged comparison.
    pub version: String,
    /// The row's signer (publisher or key label), for the audit row only.
    pub signer: String,
}

/// Every operator claim among the admitted auth rows, and every auth row whose Statement does not
/// read (`(row, error)`): such a row cannot be judged as or against the operator, so it is refused.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OperatorClaims {
    /// The rows stating the operator fact, de-duplicated on [`OperatorClaim::canonical`].
    pub claims: Vec<OperatorClaim>,
    /// The auth rows whose Statement did not decode, with the decoder's error.
    pub unreadable: Vec<(String, String)>,
}

/// ONE OUTBOUND STYLE an auth row declares ([`AuthAxis::outbound_styles`]): its name and its
/// `abi::auth::StyleDecl::flags` (the `STYLE_*` bits and its list rank).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredStyle {
    /// The style name: an open string a provider's `auth:` resolves against.
    pub name: String,
    /// Its declared flags.
    pub flags: u32,
}

/// One attempt's fixed facts at one AUTH POINT, as the kernel hands them to `fields` (THE
pub struct FieldsRequest {
    /// The point the call is made at: one of the style's `StyleDecl::points`.
    pub point: AuthPoint,
    /// The connection the binding sends on; `0` while none is dialed yet.
    pub conn: u64,
    /// The unit the request belongs to; `0` = none.
    pub unit: u64,
    /// The whole body; `Some` only at [`AuthPoint::HeadBody`]. A style that signs the body hashes
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
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    /// The caller's verified credential, for a passthrough binding (`abi::auth::MODE_PASSTHROUGH`):
    /// a handle on the unit's one shared buffer, lent to the plugin without a copy (SP-AU6).
    pub caller_credential: Option<crate::redacted::SharedSecret>,
    /// The call's extensions blob (`abi::mechanism::extensions`), lent as `FieldsIn::head.extensions`:
    pub extensions: Vec<u8>,
}

impl Drop for FieldsRequest {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.body.zeroize();
        self.method.zeroize();
        self.authority.zeroize();
        self.path.zeroize();
        self.query.zeroize();
        self.extensions.zeroize();
        for (name, value) in &mut self.headers {
            name.zeroize();
            value.zeroize();
        }
    }
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
    pub value: Secret<Vec<u8>>,
    /// `abi::auth::FIELD_SENSITIVE`, as the plugin stated it: the h2 encoding the field asks for.
    /// Logging never reads it: every auth field's value is withheld, marked or not.
    pub sensitive: bool,
    /// `abi::auth::FIELD_QUERY`: append to the request target, never a header.
    pub query: bool,
    /// The credential requires host-secured delivery; never discard this before opening.
    pub require_secure: bool,
}

/// Every auth field's value is withheld, whatever its `sensitive` bit says: a field whose
impl std::fmt::Debug for AuthField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthField")
            .field("name", &String::from_utf8_lossy(&self.name))
            .field("value", &"<redacted>")
            .field("sensitive", &self.sensitive)
            .field("query", &self.query)
            .field("require_secure", &self.require_secure)
            .finish()
    }
}

impl PartialEq for AuthField {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.value == other.value
            && self.sensitive == other.sensitive
            && self.query == other.query
            && self.require_secure == other.require_secure
    }
}

impl Eq for AuthField {}

impl AuthField {
    /// Encode a query pair for the host connector, retaining secret ownership until handed on.
    pub fn query_pair<S: crate::plugin::KernelSeal + ?Sized>(&self, seal: &S) -> Secret<Vec<u8>> {
        fn append(out: &mut Vec<u8>, bytes: &[u8]) {
            for piece in percent_encoding::percent_encode(bytes, crate::net::UNRESERVED_KEPT) {
                out.extend_from_slice(piece.as_bytes());
            }
        }
        let value = self.value.expose(seal);
        let mut pair = Vec::with_capacity(
            self.name
                .len()
                .saturating_add(value.len())
                .saturating_mul(3)
                .saturating_add(1),
        );
        append(&mut pair, &self.name);
        pair.push(b'=');
        append(&mut pair, value);
        Secret::new(pair)
    }
}

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
pub trait Fielding: Future<Output = Fields> + Send + Unpin {
    /// The answer, if it has arrived; never waits.
    fn settled(&mut self) -> Option<Fields>;
}

/// A BINDING WHOSE CREDENTIAL IS REFRESHED OFF THE REQUEST PATH (a registration's own credential):
pub trait PerRequestHandle: Send + Sync {
    /// The handle this request's auth call is made on, as the last refresh left it: a load, never a
    fn handle_now(&self) -> Option<u64>;
}

/// ONE AUTH INSTANCE'S OUTBOUND CALLS, as the kernel's egress walk makes them.
pub trait OutboundAuth: Send + Sync {
    /// Bind `style` to its resolved `credential` (secret; empty for a passthrough-only binding)
    fn open_outbound(
        &self,
        style: &str,
        credential: &[u8],
        settings: &serde_json::Value,
    ) -> Result<u64, String>;

    /// `fields` ON THE SPOT: one ticket-less crossing on the caller's thread. `Some` only for a
    fn fields_now(&self, handle: u64, request: &FieldsRequest) -> Option<Fields>;

    /// Submit `fields` on a dispatcher worker; its answer is a future, so no thread is parked.
    fn fields(&self, handle: u64, request: FieldsRequest, deadline_ns: u64) -> Box<dyn Fielding>;

    /// `outbound_ready`: whether `fields` would answer with a credential now (`false` before a
    fn ready(&self, handle: u64) -> bool {
        let _ = handle;
        true
    }
}

/// Admission of declared identity-domain configuration metadata.
pub mod domain;

/// Prepare authored auth settings and declared credential slots for the lifecycle ABI.
/// Resolution returns guarded values; exact credential positions are stripped from settings.
pub fn prepare_references(
    settings: &crate::plugin_settings::ResolvedSettings,
    references: &[String],
    sources: &crate::secret_ref::Sugars,
    owner: &str,
    field_base: &str,
    resolver: &dyn crate::secret::SecretResolve,
    scope: &crate::config_time::ConfigScope,
) -> Result<crate::plugin_settings::LentSettings, String> {
    settings.lend_references_with(
        references,
        sources,
        owner,
        &|reference| resolver.resolve_at_config(reference, scope),
        crate::plugin_settings::ReferenceDelivery::Strip(field_base),
    )
}

#[cfg(test)]
mod reuse_tests {
    use crate::redacted::Secret;

    /// A secret value refills its own allocation.
    #[test]
    fn a_secret_refills_in_place() {
        let mut value = Secret::new(b"longer-value".to_vec());
        value.refill(b"short");
        assert_eq!(value, Secret::new(b"short".to_vec()));
    }
}
