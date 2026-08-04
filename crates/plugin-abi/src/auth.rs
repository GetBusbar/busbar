// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **auth** payload schema (kind = [`crate::kind::AUTH`]) that rides the kind-neutral `call`.
//!
//! ## Identity-only — STRUCTURAL, not merely conventional
//!
//! An auth plugin asserts WHO the caller is, NEVER what they may do. The only data-carrying success
//! payload it can produce is [`Identity`] — `sub` + `groups` + `name` + `ttl_secs` — and NOTHING in
//! its transitive type graph has a slot for pools, scope, permissions, roles-as-policy, or a policy
//! decision. `#[serde(deny_unknown_fields)]` makes a rogue plugin's extra keys a REJECT, not a
//! silently-ignored field, so the identity-only guarantee is structural. The engine resolves
//! `groups → role_bindings → policy` AFTER, from [`Identity`] alone. A plugin
//! CANNOT serialize an authorization decision — the type it must produce has no place to put one.
//!
//! `Identity.groups` is the frozen WIRE name for the caller's asserted memberships; it maps to the
//! engine's [`busbar_api::Principal::roles`] (the field the auth chain consumes and resolves through
//! `auth.role_bindings`). The wire name stays `groups` (the operator-facing membership vocabulary).
//!
//! ## What crosses the boundary
//!
//! IN: the already-extracted OPAQUE candidate credential (the bearer token the engine's middleware
//! pulled off the request) via [`AuthRequest::Authenticate`]. The plugin never sees raw headers, the
//! path, or the peer. OUT: an [`AuthResponse`] — `Identity` (this is WHO), `Reject` (a credential was
//! presented and is invalid — fail-closed, stop the chain), or `Pass` ("not mine", defer to the next
//! chain module). `Reject`/`Pass` are control-flow, not policy; the ONLY shape carrying data OUT is
//! the identity-only [`Identity`].

use busbar_api::{
    AuthOutcome, BeginLogin, CompleteLogin, FieldKind as EngineFieldKind,
    LoginField as EngineLoginField, LoginForm as EngineLoginForm, LoginHop, LoginHttpResponse,
    LoginKind as EngineLoginKind, LoginOutcome, Principal, Redacted,
};
use serde::{Deserialize, Serialize};

/// The identity-only success payload an auth plugin returns: WHO the caller is, and nothing about
/// what they may do. `#[serde(deny_unknown_fields)]` rejects any extra key a plugin tries to smuggle
/// (a policy/scope field), so the identity-only guarantee is structural. Converts to/from the
/// engine's [`busbar_api::Principal`] (the seam the auth chain consumes; `groups` ↔ `roles`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    /// Stable subject handle (required): a module-scoped identity (e.g. an OIDC subject / UPN).
    pub sub: String,
    /// Asserted group/role memberships. Mapped to policy via the operator's `auth.role_bindings:`
    /// AFTER the plugin returns — the plugin asserts membership, never the grant. Empty = none.
    #[serde(default)]
    pub groups: Vec<String>,
    /// Display name, if the plugin knows one.
    #[serde(default)]
    pub name: Option<String>,
    /// Plugin-suggested cache TTL for this identification, seconds (clamped by the engine's hard cap).
    /// `None` = engine default.
    #[serde(default)]
    pub ttl_secs: Option<u64>,
}

impl From<Principal> for Identity {
    fn from(p: Principal) -> Self {
        Identity {
            sub: p.id,
            groups: p.roles,
            name: p.name,
            ttl_secs: p.ttl_secs,
        }
    }
}

impl From<Identity> for Principal {
    fn from(i: Identity) -> Self {
        Principal {
            id: i.sub,
            name: i.name,
            roles: i.groups,
            ttl_secs: i.ttl_secs,
        }
    }
}

/// An auth operation, serialized as the `call` request payload. Mirrors the `busbar_api::AuthModule`
/// trait; the variant is the op-code.
#[derive(Debug, Serialize, Deserialize)]
pub enum AuthRequest {
    /// `name()` — the module's stable name (config/metrics/audit identifier). Resolved once at load.
    Name,
    /// `cacheable()` — whether the engine may cache this module's verdicts.
    Cacheable,
    /// `login_kind()` — the pure redirect-vs-credential classification, resolved ONCE at load so the
    /// chooser reads it without side effects. ABI v2+. An older plugin that doesn't know this op
    /// returns a transport error, which the loader fail-closes to `Redirect` (the trait default).
    LoginKind,
    /// `authenticate(candidate)` — judge the OPAQUE already-extracted candidate credential. An empty
    /// string means no usable credential was presented on any carrier the engine supports.
    Authenticate { credential: String },
    /// `begin_login(req)` — the browser-login START. The CORE has already minted the PKCE
    /// `code_challenge`, `state`, and `nonce`; the module returns the IdP authorize URL to redirect
    /// to. Carries NO secret (the confidential-client secret is the core's alone). ABI v2+.
    BeginLogin(BeginLoginRequest),
    /// `complete_login(req)` — the browser-login CALLBACK. Given the authorization `code` (or a
    /// username/password credential), the module either returns a [`AuthResponse::TokenExchange`] hop
    /// for the CORE to execute (injecting `client_secret`), or — once it has a verifiable token
    /// response fed back in — an [`AuthResponse::Identity`]. ABI v2+.
    CompleteLogin(CompleteLoginRequest),
}

/// Input to [`AuthRequest::BeginLogin`]. Every field is core-generated or public; there is NO secret
/// slot in this type's transitive graph — the confidential-client secret never crosses to the plugin
/// on the begin path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginLoginRequest {
    /// The redirect/callback URL the IdP will send the browser back to (busbar's `/auth/token`).
    pub redirect_uri: String,
    /// The CORE-generated anti-CSRF `state` (echoed back on the callback, checked against the cookie).
    pub state: String,
    /// The CORE-generated PKCE `code_challenge` (S256 of the core-held `code_verifier`).
    pub code_challenge: String,
    /// The CORE-generated OIDC `nonce`, if the module wants it on the authorize URL.
    #[serde(default)]
    pub nonce: Option<String>,
    /// Extra scopes the operator asked for (module adds its own defaults, e.g. `openid`).
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// Input to [`AuthRequest::CompleteLogin`]. Carries EITHER an OAuth authorization-code shape
/// (`code`+`redirect_uri`+`code_verifier`) OR the generic `submitted` credential map (subsuming the
/// old ad-hoc username/password), plus — after the core has executed a module-described
/// [`AuthResponse::TokenExchange`] hop — the resulting `token_response` fed back so the module can
/// verify it and produce an [`Identity`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CompleteLoginRequest {
    /// OAuth authorization code returned to the callback.
    #[serde(default)]
    pub code: Option<String>,
    /// The redirect_uri used at begin (some IdPs require it echoed at the token endpoint).
    #[serde(default)]
    pub redirect_uri: Option<String>,
    /// The CORE-held PKCE `code_verifier` (paired with the begin-time `code_challenge`).
    #[serde(default)]
    pub code_verifier: Option<String>,
    /// Credential-flow: the submitted form values, keyed by the [`LoginField::name`] the plugin
    /// declared in its [`LoginForm`]. This is THE single, deliberate, documented plaintext
    /// credential-delivery boundary: the values must reach the plugin that verifies them (an LDAP
    /// bind, …), so they cross as plain `String` here (the engine holds them
    /// [`busbar_api::Redacted`] on its side of the seam and converts via `expose_secret` only for
    /// this call). Absent for the OAuth-code shape.
    #[serde(default)]
    pub submitted: Vec<(String, String)>,
    /// The response body+status of a prior core-executed token-exchange hop, fed back so the module
    /// can verify it. Absent on the first call.
    #[serde(default)]
    pub token_response: Option<HttpResponse>,
}

/// A single outbound HTTP hop the module DESCRIBES and the CORE EXECUTES (the plugin never opens a
/// socket, and never holds the confidential-client secret). `secret_form_field` names the form key
/// the CORE fills with the `client_secret` value — the plugin writes the KEY, never the VALUE, so the
/// secret is structurally core-only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRequest {
    /// HTTP method (`POST` for a token exchange, `GET` for a userinfo hop).
    pub method: String,
    /// Absolute URL of the hop (the IdP token/userinfo endpoint).
    pub url: String,
    /// x-www-form-urlencoded body fields, in order. The value for the key named by
    /// `secret_form_field` (if any) is a placeholder the CORE overwrites with the real secret.
    #[serde(default)]
    pub form: Vec<(String, String)>,
    /// The `form` key whose value the CORE must replace with the confidential-client secret. `None`
    /// ⇒ no secret is injected (e.g. a public-client or userinfo hop).
    #[serde(default)]
    pub secret_form_field: Option<String>,
    /// Extra request headers the module wants on this hop (e.g. a userinfo `Authorization: Bearer`).
    /// `#[serde(default)]` so a plugin that never sets them (and an older plugin whose ABI predates
    /// this field) round-trips unchanged. The CORE sanitizes them (CR/LF/NUL + hop-control headers)
    /// and only sends the hop to an operator-allowlisted host.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
}

/// The result of a core-executed [`HttpRequest`] hop, fed back to the module via
/// [`CompleteLoginRequest::token_response`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpResponse {
    /// HTTP status code of the hop.
    pub status: u16,
    /// Response body (the token endpoint's JSON, verbatim).
    pub body: String,
}

// ── credential-flow wire types (auth ABI v2, 1.5.2) ─────────────────────────────────────────────

/// Wire mirror of [`busbar_api::LoginKind`] — the pure method classification the chooser reads at
/// load (via [`AuthRequest::LoginKind`]) to decide redirect-button vs credential-form, WITHOUT
/// calling `begin_login` (no PKCE side effects).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoginKind {
    Redirect,
    Credential,
}

impl From<EngineLoginKind> for LoginKind {
    fn from(k: EngineLoginKind) -> Self {
        match k {
            EngineLoginKind::Redirect => LoginKind::Redirect,
            EngineLoginKind::Credential => LoginKind::Credential,
        }
    }
}
impl From<LoginKind> for EngineLoginKind {
    fn from(k: LoginKind) -> Self {
        match k {
            LoginKind::Redirect => EngineLoginKind::Redirect,
            LoginKind::Credential => EngineLoginKind::Credential,
        }
    }
}

/// Wire mirror of [`busbar_api::FieldKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldKind {
    Text,
    Password,
}

impl From<EngineFieldKind> for FieldKind {
    fn from(k: EngineFieldKind) -> Self {
        match k {
            EngineFieldKind::Text => FieldKind::Text,
            EngineFieldKind::Password => FieldKind::Password,
        }
    }
}
impl From<FieldKind> for EngineFieldKind {
    fn from(k: FieldKind) -> Self {
        match k {
            FieldKind::Text => EngineFieldKind::Text,
            FieldKind::Password => EngineFieldKind::Password,
        }
    }
}

/// Wire mirror of [`busbar_api::LoginField`] — one declared credential field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginField {
    pub name: String,
    pub label: String,
    pub kind: FieldKind,
    pub required: bool,
}

impl From<EngineLoginField> for LoginField {
    fn from(f: EngineLoginField) -> Self {
        LoginField {
            name: f.name,
            label: f.label,
            kind: f.kind.into(),
            required: f.required,
        }
    }
}
impl From<LoginField> for EngineLoginField {
    fn from(f: LoginField) -> Self {
        EngineLoginField {
            name: f.name,
            label: f.label,
            kind: f.kind.into(),
            required: f.required,
        }
    }
}

/// Wire mirror of [`busbar_api::LoginForm`] — the declarative form spec a credential method returns
/// from `begin_login` for the core to render.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginForm {
    #[serde(default)]
    pub fields: Vec<LoginField>,
}

impl From<EngineLoginForm> for LoginForm {
    fn from(form: EngineLoginForm) -> Self {
        LoginForm {
            fields: form.fields.into_iter().map(Into::into).collect(),
        }
    }
}
impl From<LoginForm> for EngineLoginForm {
    fn from(form: LoginForm) -> Self {
        EngineLoginForm {
            fields: form.fields.into_iter().map(Into::into).collect(),
        }
    }
}

/// The success payload for an auth `call`. Module-level FAILURES (e.g. an unreachable JWKS endpoint)
/// ride `STATUS_ERR` with a UTF-8 message, NOT here. The ONLY data-carrying success shape is
/// [`AuthResponse::Identity`] — the identity-only [`Identity`]. `Reject`/`Pass` are the fail-closed
/// and defer control-flow verdicts (a denied credential is NOT an error; it is a successful call).
#[derive(Debug, Serialize, Deserialize)]
pub enum AuthResponse {
    /// `name()` — the module's stable name.
    Name(String),
    /// `cacheable()` — whether verdicts may be cached.
    Cacheable(bool),
    /// `login_kind()` — the pure redirect-vs-credential classification.
    LoginKind(LoginKind),
    /// `authenticate()` identified the caller — the ONLY shape carrying identity data out.
    Identity(Identity),
    /// `authenticate()` rejects: a credential was presented and is invalid (fail-closed, stop chain).
    Reject,
    /// `authenticate()` defers: not this module's credential shape — try the next chain module.
    Pass,
    /// `begin_login()` result: the IdP authorize URL the browser is redirected to. Carries no secret.
    AuthorizeUrl(String),
    /// `begin_login()` result (credential flow): the declarative form the core renders and POSTs back.
    Prompt(LoginForm),
    /// `complete_login()` result: a token-exchange (or userinfo) hop the CORE must execute — the
    /// module describes it (URL + form + which field is the secret); the core injects the secret,
    /// runs it, and feeds the [`HttpResponse`] back via `complete_login` again.
    TokenExchange(HttpRequest),
}

impl AuthResponse {
    /// Build the `authenticate` response from an engine [`AuthOutcome`]. The identity-only `Identify`
    /// projects to [`AuthResponse::Identity`]; the control-flow verdicts map straight across.
    pub fn from_outcome(outcome: AuthOutcome) -> Self {
        match outcome {
            AuthOutcome::Identify(p) => AuthResponse::Identity(p.into()),
            AuthOutcome::Reject => AuthResponse::Reject,
            AuthOutcome::Pass => AuthResponse::Pass,
        }
    }

    /// Build a login response from an engine [`LoginOutcome`] (the SDK dispatch side). `Exchange` is
    /// the module-described hop the core will execute; the secret is never present here.
    pub fn from_login_outcome(outcome: LoginOutcome) -> Self {
        match outcome {
            LoginOutcome::Authorize(url) => AuthResponse::AuthorizeUrl(url),
            LoginOutcome::Prompt(form) => AuthResponse::Prompt(form.into()),
            LoginOutcome::Exchange(hop) => AuthResponse::TokenExchange(hop.into()),
            LoginOutcome::Identify(p) => AuthResponse::Identity(p.into()),
            LoginOutcome::Reject => AuthResponse::Reject,
        }
    }

    /// Decode a login response into an engine [`LoginOutcome`] (the loader/`DynAuth` side). Any
    /// non-login variant (or a verify-only `Pass`) is FAIL-CLOSED to `Reject` — a misbehaving plugin
    /// must never drive a login forward on an unexpected shape.
    pub fn into_login_outcome(self) -> LoginOutcome {
        match self {
            AuthResponse::AuthorizeUrl(url) => LoginOutcome::Authorize(url),
            AuthResponse::Prompt(form) => LoginOutcome::Prompt(form.into()),
            AuthResponse::TokenExchange(hop) => LoginOutcome::Exchange(hop.into()),
            AuthResponse::Identity(id) => LoginOutcome::Identify(id.into()),
            _ => LoginOutcome::Reject,
        }
    }
}

// ── wire ↔ engine login conversions (mirror Identity↔Principal) ─────────────────────────────────

impl From<BeginLogin> for BeginLoginRequest {
    fn from(b: BeginLogin) -> Self {
        BeginLoginRequest {
            redirect_uri: b.redirect_uri,
            state: b.state,
            code_challenge: b.code_challenge,
            nonce: b.nonce,
            scopes: b.scopes,
        }
    }
}
impl From<BeginLoginRequest> for BeginLogin {
    fn from(b: BeginLoginRequest) -> Self {
        BeginLogin {
            redirect_uri: b.redirect_uri,
            state: b.state,
            code_challenge: b.code_challenge,
            nonce: b.nonce,
            scopes: b.scopes,
        }
    }
}

impl From<CompleteLogin> for CompleteLoginRequest {
    fn from(c: CompleteLogin) -> Self {
        CompleteLoginRequest {
            code: c.code,
            redirect_uri: c.redirect_uri,
            code_verifier: c.code_verifier,
            // Cross the ONE plaintext credential boundary: expose the Redacted values for the plugin
            // that will verify them (see `CompleteLoginRequest::submitted`).
            submitted: c
                .submitted
                .into_iter()
                .map(|(k, v)| (k, v.expose_secret().clone()))
                .collect(),
            token_response: c.token_response.map(Into::into),
        }
    }
}
impl From<CompleteLoginRequest> for CompleteLogin {
    fn from(c: CompleteLoginRequest) -> Self {
        CompleteLogin {
            code: c.code,
            redirect_uri: c.redirect_uri,
            code_verifier: c.code_verifier,
            // Re-wrap the submitted values as Redacted the moment they enter the engine vocabulary.
            submitted: c
                .submitted
                .into_iter()
                .map(|(k, v)| (k, Redacted::new(v)))
                .collect(),
            token_response: c.token_response.map(Into::into),
        }
    }
}

impl From<LoginHop> for HttpRequest {
    fn from(h: LoginHop) -> Self {
        HttpRequest {
            method: h.method,
            url: h.url,
            form: h.form,
            secret_form_field: h.secret_form_field,
            headers: h.headers,
        }
    }
}
impl From<HttpRequest> for LoginHop {
    fn from(h: HttpRequest) -> Self {
        LoginHop {
            method: h.method,
            url: h.url,
            form: h.form,
            secret_form_field: h.secret_form_field,
            headers: h.headers,
        }
    }
}

impl From<LoginHttpResponse> for HttpResponse {
    fn from(r: LoginHttpResponse) -> Self {
        HttpResponse {
            status: r.status,
            body: r.body,
        }
    }
}
impl From<HttpResponse> for LoginHttpResponse {
    fn from(r: HttpResponse) -> Self {
        LoginHttpResponse {
            status: r.status,
            body: r.body,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_identity() -> Identity {
        Identity {
            sub: "oidc:alice@contoso.com".into(),
            groups: vec!["engineering".into(), "sre".into()],
            name: Some("Alice".into()),
            ttl_secs: Some(300),
        }
    }

    #[test]
    fn request_response_json_roundtrip() {
        let reqs = vec![
            AuthRequest::Name,
            AuthRequest::Cacheable,
            AuthRequest::Authenticate {
                credential: String::new(),
            },
            AuthRequest::Authenticate {
                credential: "ey.jwt.token".into(),
            },
        ];
        for r in reqs {
            let j = serde_json::to_vec(&r).unwrap();
            let back: AuthRequest = serde_json::from_slice(&j).unwrap();
            assert_eq!(serde_json::to_vec(&back).unwrap(), j);
        }

        let resp = AuthResponse::Identity(sample_identity());
        let j = serde_json::to_vec(&resp).unwrap();
        match serde_json::from_slice::<AuthResponse>(&j).unwrap() {
            AuthResponse::Identity(i) => assert_eq!(i, sample_identity()),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// The identity-only guarantee is STRUCTURAL: an extra field (a smuggled policy/scope) is
    /// REJECTED by `deny_unknown_fields`, never ignored.
    #[test]
    fn identity_rejects_unknown_fields() {
        let rogue = r#"{"sub":"x","groups":[],"name":null,"ttl_secs":null,"admin_scope":"full"}"#;
        assert!(
            serde_json::from_str::<Identity>(rogue).is_err(),
            "a plugin smuggling a policy field must be rejected, not silently accepted"
        );
    }

    /// Identity <-> Principal is lossless (the seam the auth chain consumes; groups ↔ roles).
    #[test]
    fn identity_principal_roundtrip() {
        let id = sample_identity();
        let p: Principal = id.clone().into();
        assert_eq!(p.id, id.sub);
        assert_eq!(p.roles, id.groups);
        let back: Identity = p.into();
        assert_eq!(back, id);
    }

    /// `BeginLoginRequest`/`AuthorizeUrl` round-trip, and the begin request STRUCTURALLY carries no
    /// secret field (the confidential-client secret never crosses on the begin path).
    #[test]
    fn begin_login_roundtrip_no_client_secret() {
        let req = AuthRequest::BeginLogin(BeginLoginRequest {
            redirect_uri: "https://busbar.example/auth/token".into(),
            state: "state-123".into(),
            code_challenge: "chal".into(),
            nonce: Some("nonce".into()),
            scopes: vec!["openid".into(), "email".into()],
        });
        let j = serde_json::to_vec(&req).unwrap();
        let back: AuthRequest = serde_json::from_slice(&j).unwrap();
        assert_eq!(serde_json::to_vec(&back).unwrap(), j);

        // No secret field anywhere in the serialized begin request.
        let s = String::from_utf8(j).unwrap();
        assert!(
            !s.contains("client_secret") && !s.contains("secret"),
            "begin request must carry no secret: {s}"
        );

        let resp = AuthResponse::AuthorizeUrl("https://idp/authorize?state=state-123".into());
        let j = serde_json::to_vec(&resp).unwrap();
        assert!(matches!(
            serde_json::from_slice::<AuthResponse>(&j).unwrap(),
            AuthResponse::AuthorizeUrl(_)
        ));
    }

    /// `CompleteLoginRequest` round-trips for both the OAuth-code shape and the generic `submitted`
    /// credential map (which subsumed the old ad-hoc username/password), with `token_response`
    /// present and absent.
    #[test]
    fn complete_login_oauth_and_credential_shapes() {
        let oauth = CompleteLoginRequest {
            code: Some("authcode".into()),
            redirect_uri: Some("https://busbar.example/auth/token".into()),
            code_verifier: Some("verifier".into()),
            ..Default::default()
        };
        let cred = CompleteLoginRequest {
            submitted: vec![
                ("username".into(), "alice".into()),
                ("password".into(), "pw".into()),
            ],
            ..Default::default()
        };
        let with_resp = CompleteLoginRequest {
            code: Some("authcode".into()),
            token_response: Some(HttpResponse {
                status: 200,
                body: r#"{"id_token":"ey.."}"#.into(),
            }),
            ..Default::default()
        };
        for c in [oauth, cred, with_resp] {
            let req = AuthRequest::CompleteLogin(c.clone());
            let j = serde_json::to_vec(&req).unwrap();
            match serde_json::from_slice::<AuthRequest>(&j).unwrap() {
                AuthRequest::CompleteLogin(back) => assert_eq!(back, c),
                other => panic!("wrong variant: {other:?}"),
            }
        }
    }

    /// The credential-flow wire additions round-trip: `LoginKind` (the load-time classification), a
    /// `Prompt(LoginForm)` begin result, and the `submitted` map crossing engine↔wire with Redaction
    /// re-applied on the engine side.
    #[test]
    fn credential_flow_wire_roundtrips() {
        // LoginKind op + response.
        let j = serde_json::to_vec(&AuthRequest::LoginKind).unwrap();
        assert!(matches!(
            serde_json::from_slice::<AuthRequest>(&j).unwrap(),
            AuthRequest::LoginKind
        ));
        for k in [LoginKind::Redirect, LoginKind::Credential] {
            let j = serde_json::to_vec(&AuthResponse::LoginKind(k)).unwrap();
            match serde_json::from_slice::<AuthResponse>(&j).unwrap() {
                AuthResponse::LoginKind(back) => assert_eq!(back, k),
                other => panic!("wrong variant: {other:?}"),
            }
        }

        // Prompt(LoginForm) begin result.
        let form = LoginForm {
            fields: vec![
                LoginField {
                    name: "username".into(),
                    label: "Username".into(),
                    kind: FieldKind::Text,
                    required: true,
                },
                LoginField {
                    name: "password".into(),
                    label: "Password".into(),
                    kind: FieldKind::Password,
                    required: true,
                },
            ],
        };
        let j = serde_json::to_vec(&AuthResponse::Prompt(form.clone())).unwrap();
        match serde_json::from_slice::<AuthResponse>(&j).unwrap() {
            AuthResponse::Prompt(back) => assert_eq!(back, form),
            other => panic!("wrong variant: {other:?}"),
        }
        // Prompt survives the engine LoginOutcome round-trip both directions.
        let outcome = AuthResponse::Prompt(form.clone()).into_login_outcome();
        assert!(matches!(outcome, LoginOutcome::Prompt(_)));
        assert!(matches!(
            AuthResponse::from_login_outcome(outcome),
            AuthResponse::Prompt(_)
        ));

        // The submitted map: engine (Redacted) → wire (plain) → engine (Redacted) is lossless, and
        // the Redacted values never reveal themselves in Debug.
        let eng = CompleteLogin {
            submitted: vec![
                ("username".into(), Redacted::new("alice".to_string())),
                ("password".into(), Redacted::new("s3cr3t".to_string())),
            ],
            ..Default::default()
        };
        let wire: CompleteLoginRequest = eng.clone().into();
        assert_eq!(wire.submitted[1].1, "s3cr3t"); // plaintext crosses at this documented boundary
        let back: CompleteLogin = wire.into();
        assert_eq!(back.submitted[0].1.expose_secret(), "alice");
        assert_eq!(back.submitted[1].1.expose_secret(), "s3cr3t");
        assert!(
            !format!("{back:?}").contains("s3cr3t"),
            "engine side must redact"
        );
    }

    /// `TokenExchange(HttpRequest)` / `HttpResponse` round-trip; the secret field names a KEY, not a
    /// value.
    #[test]
    fn token_exchange_and_http_response_roundtrip() {
        let hop = HttpRequest {
            method: "POST".into(),
            url: "https://idp/token".into(),
            form: vec![
                ("grant_type".into(), "authorization_code".into()),
                ("code".into(), "authcode".into()),
                ("code_verifier".into(), "verifier".into()),
                ("client_secret".into(), String::new()),
            ],
            secret_form_field: Some("client_secret".into()),
            headers: vec![("X-Trace".into(), "1".into())],
        };
        let resp = AuthResponse::TokenExchange(hop.clone());
        let j = serde_json::to_vec(&resp).unwrap();
        match serde_json::from_slice::<AuthResponse>(&j).unwrap() {
            AuthResponse::TokenExchange(back) => assert_eq!(back, hop),
            other => panic!("wrong variant: {other:?}"),
        }

        let hr = HttpResponse {
            status: 200,
            body: "{}".into(),
        };
        let j = serde_json::to_vec(&hr).unwrap();
        assert_eq!(serde_json::from_slice::<HttpResponse>(&j).unwrap(), hr);
    }

    #[test]
    fn from_outcome_maps_verdicts() {
        let mut p = Principal::from_id("oidc:bob");
        p.roles = vec!["g".into()];
        match AuthResponse::from_outcome(AuthOutcome::Identify(p)) {
            AuthResponse::Identity(i) => assert_eq!(i.sub, "oidc:bob"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            AuthResponse::from_outcome(AuthOutcome::Reject),
            AuthResponse::Reject
        ));
        assert!(matches!(
            AuthResponse::from_outcome(AuthOutcome::Pass),
            AuthResponse::Pass
        ));
    }
}
