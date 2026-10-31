// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The AUTH contract: one module, one verdict.
//!
//! Moved here, module-path-only, from `busbar-api` (DECISIONS #83: contract = shapes; #84: nothing
//! on the plugin path may link a crate holding semantics; the per-kind capability trait is the
//! contract's, #35(a)). One name changed on the move and only to de-collide it (#35): the verdict is
//! [`AuthVerdict`] here because [`crate::kinds::AuthOutcome`] is a different type. `busbar-api`
//! re-exports it under its original spelling. `sha256_hex` followed later, beside the constant-time
//! compare it feeds ([`crate::redacted::sha256_hex`]), once the owner ruled the
//! `sha2 -> cpufeatures -> libc` edge tree-wide (2026-09-22).

use zeroize::Zeroize;

use crate::redacted::Secret;

/// The authenticated PRINCIPAL — who the caller IS, established at the auth stage and keyed to by
/// everything downstream (governance, audit attribution, the hook `send_user` projection, admin
/// scopes). IDENTITY ONLY: a module returns who; policy (allowed pools, group, admin scope) is
/// resolved by busbar from config (`auth.role_bindings:`, nested by module), never asserted by the
/// module. NEVER carries the credential itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// Stable identity handle (required): the virtual-key id for governance keys, a stable
    /// module-scoped handle otherwise (e.g. an AD UPN).
    pub id: String,
    /// Display name, if the module knows one.
    pub name: Option<String>,
    /// ROLES the identifying module asserts for this principal (1.5.0: `roles`, was `groups`).
    /// Mapped to policy through `auth.role_bindings.<module>` (nested by module, so a role from
    /// one module never rides another's binding). Empty = no roles (grants nothing).
    pub roles: Vec<String>,
    /// Module-suggested cache TTL for this identification, seconds (clamped by the engine's hard
    /// cap when the credential cache lands). `None` = engine default.
    pub ttl_secs: Option<u64>,
}

impl Principal {
    /// A principal with only a stable id — the common built-in-module shape.
    pub fn from_id(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: None,
            roles: Vec::new(),
            ttl_secs: None,
        }
    }
}

/// Request-extension carrier for the authenticated [`Principal`]. ALWAYS inserted by the auth
/// middleware on admitted requests (`None` = the empty-chain anonymous front door), so downstream
/// consumers (audit attribution, the hook `send_user` projection, admin scopes) can extract it
/// without an is-it-there dance. Never carries the credential.
#[derive(Debug, Clone)]
pub struct AuthPrincipal(pub Option<Principal>);

impl AuthPrincipal {
    /// The attribution handle for audit records: the principal id, or `anonymous` for the
    /// explicit open-front-door postures.
    pub fn actor_id(&self) -> &str {
        self.0
            .as_ref()
            .map(|p| p.id.as_str())
            .unwrap_or("anonymous")
    }
}

/// The caller's bearer token, threaded into request extensions by the auth middleware so handlers
/// can forward it upstream in passthrough mode. `None` when no usable bearer token was presented.
///
/// Beside [`AuthPrincipal`] because it is the same KIND of thing — a request-extension carrier the
/// auth middleware inserts — and because it carries nothing of the engine: one `Option<String>` and
/// a redacting `Debug`. It lives here so a plane naming it (a test assembling the extension map an
/// ingress handler extracts from) names the neutral ABI rather than reaching into the engine.
#[derive(Clone, Default)]
pub struct CallerToken(pub Option<String>);

// MANUAL Debug that NEVER prints the token contents. `CallerToken` wraps a caller credential and is
// threaded into request extensions, so it can be reached by any future code that debug-formats the
// extension map (or a struct that holds it). A derived `Debug` would print the plaintext token — a
// latent credential leak the moment anything debug-logs it. Redact to presence only ("present" /
// "absent"); never the length and never the value, since even the length is a (small) oracle.
impl std::fmt::Debug for CallerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("CallerToken")
            .field(&if self.0.is_some() {
                "<present>"
            } else {
                "<absent>"
            })
            .finish()
    }
}

/// The verdict of one auth module. The PAM-style trichotomy the 1.3 auth-plugin layer is built on:
/// `Identify` = this module authenticated the caller and this is WHO —
/// carries the [`Principal`]; `Reject` = a credential was presented but is invalid (fail-closed,
/// stop the chain); `Pass` = "not mine" — no usable credential for this module, defer to the next
/// module / the mode default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthVerdict {
    Identify(Principal),
    Reject,
    Pass,
}

/// One authentication module — a swappable implementation of the fixed `auth` engine stage. The
/// built-in `tokens` module implements it (the `auth/tokens/` crate); SAML/AD/OIDC modules
/// implement the same trait. Extraction of the credential carriers (Bearer /
/// x-api-key / x-goog-api-key) stays in the engine's middleware, so a module never re-parses
/// headers — it receives the already-extracted candidate and returns a verdict.
pub trait AuthModule: Send + Sync {
    /// Stable module name for config references, metrics, and audit (e.g. `"tokens"`).
    fn name(&self) -> &'static str;
    /// Judge the presented candidate credential. Constant-time and side-effect-free.
    fn authenticate(&self, candidate: Option<&str>) -> AuthVerdict;
    /// Whether the engine may CACHE this module's verdicts (the credential cache). Default
    /// `false`: an in-process module is microseconds and caching its verdicts would only widen
    /// the revocation window. A module that does real I/O per call (a directory lookup over a
    /// socket) overrides to `true`.
    fn cacheable(&self) -> bool {
        false
    }
}

// ── Browser-login primitives (auth ABI v2, 1.5.2 token-exchange) ────────────────────────────────
//
// These are the ENGINE-side (api-level) mirrors of the plugin-abi login wire types (the same
// Identity↔Principal split: the wire types are serde-serializable, these carry no serde and stay in
// the engine vocabulary). A verify-only auth module needs none of this. A login-capable module (an OIDC IdP)
// serves `begin_login` and `complete_login`; the CORE, never the module, holds the confidential-client
// secret.

/// `begin_login` input — everything is CORE-generated or public; there is NO secret
/// field, structurally keeping the confidential-client secret off the begin path.
#[derive(Debug, Clone, PartialEq)]
pub struct BeginLogin {
    /// Callback URL the IdP returns the browser to (busbar's `/auth/token`).
    pub redirect_uri: String,
    /// CORE-generated anti-CSRF `state` (echoed on the callback, checked against the cookie).
    pub state: String,
    /// CORE-generated PKCE `code_challenge` (S256 of the core-held verifier).
    pub code_challenge: String,
    /// CORE-generated OIDC `nonce`, if wanted on the authorize URL.
    pub nonce: Option<String>,
    /// Operator-requested extra scopes (the module adds its own, e.g. `openid`).
    pub scopes: Vec<String>,
}

/// How a login METHOD starts — a pure, declarative classification the chooser reads BEFORE the user
/// picks (so it never has to call `begin_login`, which mints PKCE state/nonce — side
/// effects). `Redirect` = OAuth-family (send the browser to an external authorize URL); `Credential` =
/// collect fields directly from the user and let the plugin verify them (LDAP/AD-bind, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginKind {
    Redirect,
    Credential,
}

/// The input type of one credential field the plugin DECLARES in a [`LoginForm`]. `Password` is
/// masked in the UI and carried [`Secret`] on the wire; `Text` is a plain field (username, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    Text,
    Password,
}

/// One field the core renders in a credential-login form, exactly as the plugin declared it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginField {
    /// The key the submitted value is returned under in [`CompleteLogin::submitted`].
    pub name: String,
    /// The human label shown next to the field.
    pub label: String,
    /// Text or Password (masking + redaction).
    pub kind: FieldKind,
    /// Whether the field must be non-empty to submit.
    pub required: bool,
}

/// A declarative form spec a `Credential`-kind method returns from `begin_login`. The
/// core renders WHATEVER fields the plugin declares (username+password, or +totp, …) — generic, not
/// LDAP-shaped. The submitted values come back keyed by [`LoginField::name`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginForm {
    pub fields: Vec<LoginField>,
}

/// `complete_login` input — an OAuth authorization-code shape OR the generic submitted
/// credential map, plus the response of a prior core-executed [`LoginHop`] fed back for verification.
///
/// Its `Debug` withholds the code, the PKCE verifier and every token response: each is a credential.
#[derive(Clone, PartialEq, Default)]
pub struct CompleteLogin {
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    /// Credential-flow: the submitted form values, keyed by the [`LoginField::name`] the plugin
    /// declared in its [`LoginForm`]. Every value is [`Secret`] (Debug/Display never print it). This
    /// SUBSUMES the old ad-hoc `username`/`password` pair — one generic credential transport, so a
    /// method declaring `[username, password, totp]` just works.
    pub submitted: Vec<(String, Secret<String>)>,
    pub token_response: Option<LoginHttpResponse>,
}

/// An HTTP hop the module DESCRIBES and the CORE EXECUTES. `secret_form_field` names the form key the
/// core fills with the `client_secret` VALUE — the module writes only the KEY, never the secret.
///
/// Its `Debug` names the form and header KEYS only: a value may be a credential (a bearer token).
#[derive(Clone, PartialEq)]
pub struct LoginHop {
    pub method: String,
    pub url: String,
    pub form: Vec<(String, String)>,
    pub secret_form_field: Option<String>,
    /// Extra request headers the module wants on this hop (e.g. `Authorization: Bearer <token>` for a
    /// userinfo GET). The CORE SANITIZES them before sending (rejects CR/LF/NUL and the hop-control
    /// headers `Host`/`Content-Length`/`Transfer-Encoding`) and only sends the hop to an
    /// operator-allowlisted host over https.
    pub headers: Vec<(String, String)>,
}

/// The result of a core-executed [`LoginHop`], fed back to the module.
///
/// Its `Debug` withholds the body: a token response carries the tokens.
#[derive(Clone, PartialEq)]
pub struct LoginHttpResponse {
    pub status: u16,
    pub body: String,
}

/// What a withheld value prints as, the [`Secret`] redaction.
const WITHHELD: &str = "[REDACTED]";

/// `Some` as the redaction, `None` as itself.
fn withheld<T>(v: &Option<T>) -> Option<&'static str> {
    v.as_ref().map(|_| WITHHELD)
}

/// The keys of `pairs`, never their values.
fn keys(pairs: &[(String, String)]) -> Vec<&str> {
    pairs.iter().map(|(k, _)| k.as_str()).collect()
}

impl std::fmt::Debug for CompleteLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompleteLogin")
            .field("code", &withheld(&self.code))
            .field("redirect_uri", &self.redirect_uri)
            .field("code_verifier", &withheld(&self.code_verifier))
            .field("submitted", &self.submitted)
            .field("token_response", &self.token_response)
            .finish()
    }
}

impl std::fmt::Debug for LoginHop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginHop")
            .field("method", &self.method)
            .field("url", &WITHHELD)
            .field("form", &keys(&self.form))
            .field("secret_form_field", &self.secret_form_field)
            .field("headers", &keys(&self.headers))
            .finish()
    }
}

impl std::fmt::Debug for LoginHttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginHttpResponse")
            .field("status", &self.status)
            .field("body", &WITHHELD)
            .finish()
    }
}

// THE LOGIN HOP AND ITS RESPONSE WIPE ON DROP (open160 A2): a hop's form and header values (a
// bearer token, a client credential) and a token response's body (the tokens) are overwritten with
// zeroes when the value is dropped, wherever it was built. The fields stay `String` so a plugin
// built against the earlier contract still compiles; `CompleteLogin`'s code and PKCE verifier stay
// as they are for the same reason (a plugin builds it with `..Default::default()`, which a `Drop`
// type refuses), and its token response wipes through this.

impl Drop for LoginHop {
    fn drop(&mut self) {
        for (_, value) in self.form.iter_mut().chain(self.headers.iter_mut()) {
            value.zeroize();
        }
    }
}

impl zeroize::ZeroizeOnDrop for LoginHop {}

impl Drop for LoginHttpResponse {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for LoginHttpResponse {}

/// The verdict of one login step (begin or complete). `Authorize` = redirect the browser here;
/// `Exchange` = the core must run this hop then call complete_login again with the response;
/// `Identify` = identity established; `Reject` = fail closed; `Outage` = the identity provider
/// could not be reached (the auth ABI's `LOGIN_OUTAGE`), fail closed too, but told apart from a
/// declined credential.
#[derive(Debug, Clone, PartialEq)]
pub enum LoginOutcome {
    Authorize(String),
    /// The credential-flow START: render this form, collect the fields, POST them back. The honest
    /// PEER of `Authorize` (the two login start-shapes).
    Prompt(LoginForm),
    Exchange(LoginHop),
    Identify(Principal),
    Reject,
    /// The identity provider could not be reached: nothing was verified, and the credential was
    /// not declined either.
    Outage,
    /// The identity provider answered, and its answer failed the login's security check (its
    /// identity token's nonce is not the login's): no identity is trusted.
    SecurityCheckFailed,
}

/// WHY a chain verdict did not resolve to an admitted identity. The DECISION is closed here; the
/// WORDS are the caller's — the HTTP middleware renders an RFC 6750 challenge or a native envelope,
/// and a headerless serve mode a boot-time stderr sentence and a nonzero exit — which is the same
/// decision/vocabulary split `crate::ingress::protocol::CoreRefusal` documents for the ingress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityRefusal {
    /// The chain denied the credential: a `Reject`, an all-`Pass` on a configured chain, or a
    /// signed key that stopped verifying.
    Denied,
    /// The principal authenticated but its roles earned NO enforcement key while this module has a
    /// `role_bindings` table. Admitting it `key: None` would hand it UNRESTRICTED access, so it is
    /// refused — the same fail-closed rule stated at length below.
    NoGrant,
}

#[cfg(test)]
#[path = "tests/auth_tests.rs"]
mod tests;
