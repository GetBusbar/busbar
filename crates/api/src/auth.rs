// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The AUTH contract: one module, one verdict.

use sha2::{Digest, Sha256};

use crate::redacted::Redacted;

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

/// The verdict of one auth module. The PAM-style trichotomy the 1.3 auth-plugin layer is built on:
/// `Identify` = this module authenticated the caller and this is WHO —
/// carries the [`Principal`]; `Reject` = a credential was presented but is invalid (fail-closed,
/// stop the chain); `Pass` = "not mine" — no usable credential for this module, defer to the next
/// module / the mode default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
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
    fn authenticate(&self, candidate: Option<&str>) -> AuthOutcome;
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
// the engine vocabulary). A verify-only auth module needs none of this — [`LoginModule`]'s defaults
// are fail-closed, so an existing module compiles and behaves unchanged. A login-capable module (an
// OIDC IdP) overrides them; the CORE, never the module, holds the confidential-client secret.

/// [`LoginModule::begin_login`] input — everything is CORE-generated or public; there is NO secret
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
/// picks (so it never has to call [`LoginModule::begin_login`], which mints PKCE state/nonce — side
/// effects). `Redirect` = OAuth-family (send the browser to an external authorize URL); `Credential` =
/// collect fields directly from the user and let the plugin verify them (LDAP/AD-bind, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginKind {
    Redirect,
    Credential,
}

/// The input type of one credential field the plugin DECLARES in a [`LoginForm`]. `Password` is
/// masked in the UI and carried [`Redacted`] on the wire; `Text` is a plain field (username, …).
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

/// A declarative form spec a `Credential`-kind method returns from [`LoginModule::begin_login`]. The
/// core renders WHATEVER fields the plugin declares (username+password, or +totp, …) — generic, not
/// LDAP-shaped. The submitted values come back keyed by [`LoginField::name`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginForm {
    pub fields: Vec<LoginField>,
}

/// [`LoginModule::complete_login`] input — an OAuth authorization-code shape OR the generic submitted
/// credential map, plus the response of a prior core-executed [`LoginHop`] fed back for verification.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CompleteLogin {
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    /// Credential-flow: the submitted form values, keyed by the [`LoginField::name`] the plugin
    /// declared in its [`LoginForm`]. Every value is [`Redacted`] (Debug/Display never print it). This
    /// SUBSUMES the old ad-hoc `username`/`password` pair — one generic credential transport, so a
    /// method declaring `[username, password, totp]` just works.
    pub submitted: Vec<(String, Redacted<String>)>,
    pub token_response: Option<LoginHttpResponse>,
}

/// An HTTP hop the module DESCRIBES and the CORE EXECUTES. `secret_form_field` names the form key the
/// core fills with the `client_secret` VALUE — the module writes only the KEY, never the secret.
#[derive(Debug, Clone, PartialEq)]
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
#[derive(Debug, Clone, PartialEq)]
pub struct LoginHttpResponse {
    pub status: u16,
    pub body: String,
}

/// The verdict of one login step (begin or complete). `Authorize` = redirect the browser here;
/// `Exchange` = the core must run this hop then call complete_login again with the response;
/// `Identify` = identity established; `Reject` = fail closed.
#[derive(Debug, Clone, PartialEq)]
pub enum LoginOutcome {
    Authorize(String),
    /// The credential-flow START: render this form, collect the fields, POST them back. The honest
    /// PEER of `Authorize` (the two login start-shapes).
    Prompt(LoginForm),
    Exchange(LoginHop),
    Identify(Principal),
    Reject,
}

/// The OPT-IN browser-login capability of an auth module (auth ABI v2). SEPARATE from [`AuthModule`]
/// (never modify the verify trait): a module that only verifies bearer credentials leaves both
/// methods at their FAIL-CLOSED defaults and is unaffected. An IdP module overrides them to drive the
/// hosted-login / headless code→token flow. The CORE holds the confidential-client secret and
/// executes every [`LoginOutcome::Exchange`] hop; the module never opens a socket and never sees the
/// secret value.
pub trait LoginModule: Send + Sync {
    /// Pure, side-effect-free classification the chooser reads BEFORE the user picks (no `begin_login`
    /// call, which would mint PKCE state/nonce). Default [`LoginKind::Redirect`] keeps every existing
    /// OAuth plugin unchanged; a credential/directory module overrides to [`LoginKind::Credential`].
    fn login_kind(&self) -> LoginKind {
        LoginKind::Redirect
    }
    /// Start browser login: given the core-minted PKCE/state/nonce, return the IdP authorize URL to
    /// redirect to (redirect flow) or a [`LoginOutcome::Prompt`] form (credential flow). Default:
    /// `Reject` (this module has no browser login).
    fn begin_login(&self, _req: &BeginLogin) -> LoginOutcome {
        LoginOutcome::Reject
    }
    /// Handle the callback: return a token-exchange hop for the core to run, or — once a token
    /// response is fed back — an established `Identify`. Default: `Reject`.
    fn complete_login(&self, _req: &CompleteLogin) -> LoginOutcome {
        LoginOutcome::Reject
    }
}

/// The unified auth-plugin handle: an auth module that is BOTH a verifier ([`AuthModule`]) and a
/// login provider ([`LoginModule`], possibly by fail-closed default). The blanket impl means any
/// type that is both is automatically an `AuthPlugin`, so `Box<dyn AuthPlugin>` is the single boxed
/// handle the SDK exports and the loader boxes. Verify-only modules reach it through the SDK's
/// fail-closed login adapter.
pub trait AuthPlugin: AuthModule + LoginModule {}
impl<T: AuthModule + LoginModule + ?Sized> AuthPlugin for T {}

/// Constant-time comparison of the CONTENTS once lengths already match, to avoid leaking how much
/// of a token matches via timing. `#[inline(never)]` + `black_box` keep the optimizer from turning
/// the accumulation loop into an early-exit branch (which would reintroduce a timing signal for the
/// contents). The length check IS an early exit, and is only safe to apply to raw secret material
/// when the material's length is not itself sensitive — which a raw token generally is NOT expected
/// to be, but a caller comparing genuinely secret raw bytes directly (rather than through
/// [`sha256_hex`] below) still leaks whether the two lengths matched. Prefer hashing both sides
/// first (see `sha256_hex`'s doc) so length never enters the comparison at all; this primitive alone
/// does not guarantee that for its caller.
#[inline(never)]
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();

    if a_bytes.len() != b_bytes.len() {
        return false;
    }

    // XOR all bytes and OR the results together. If any bit differs, result > 0.
    let mut result: u8 = 0;
    for (x, y) in a_bytes.iter().zip(b_bytes.iter()) {
        result |= x ^ y;
    }

    std::hint::black_box(result) == 0
}

/// Lowercase hex SHA-256 of `data` — THE digest facility credentials are compared under (a module
/// hashes both sides before [`constant_time_eq`]: every digest is 64 hex chars, so
/// `constant_time_eq`'s length early-exit never fires on a length difference driven by the raw
/// candidate, and candidate length leaks nothing). This is the pattern every auth module SHOULD
/// follow when comparing a caller-supplied credential against configured secret material — compare
/// raw only when the material's length is not itself sensitive.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[cfg(test)]
#[path = "tests/auth_tests.rs"]
mod tests;

/// The UPSTREAM-credential mode (`upstream_credentials:`) — whose credential reaches the provider.
/// DISTINCT from authentication (which auth module, if any, ran at the front door — that's the
/// `auth.chain`): `Own` (default) signs the upstream call with busbar's configured lane key;
/// `Passthrough` forwards the CALLER's credential upstream. A proto writer uses THIS to resolve an
/// otherwise-ambiguous credential scheme to the single native header the caller's real client
/// produces. (Split out of the old `AuthMode`, now its own config key — `AuthMode` is gone.)
// `Serialize` is additive and is what lets a config section carrying this field be projected back
// to a raw definition document — the base half of the config overlay's per-entry MERGE
// (`NamedMapSection::entry_as_document`). A section whose entry cannot round-trip to a document
// cannot be patched per field, only replaced wholesale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamCreds {
    #[default]
    Own,
    Passthrough,
}

/// WHY a chain verdict did not resolve to an admitted identity. The DECISION is closed here; the
/// WORDS are the caller's — the HTTP middleware renders an RFC 6750 challenge or a native envelope,
/// and the stdio serve mode a boot-time stderr sentence and a nonzero exit — which is the same
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
