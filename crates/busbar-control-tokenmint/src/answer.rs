// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BODIES behind the declared route table — what each row of [`crate::claims::ROUTES`] answers
//! with, written over the `http` vocabulary and nothing else.
//!
//! ## What is here and what is NOT
//!
//! No router, no extractor, no engine handle. The composition builds a [`Request`] from whatever
//! arrived, hands it to [`TokenIssuer::answer`] with the row's [`Handler`], and sends the
//! [`Response`] back. `oauth-as` also ships an `axum` feature that hands back a ready-made router,
//! and busbar does not use it: that router is a single `fallback`, so its paths would enter the
//! tree with NO entry in the composition's route table.
//!
//! ## The bar, and why NO body here checks a credential
//!
//! `Bar::Open` is authentication that belongs to a different protocol and is performed by the
//! library that implements it — so [`forward`] never reads busbar's governance state. `Bar::Operator`
//! means the operator has ALREADY been identified by the node's operator chain before the consent
//! bodies run, so there is no credential check in them and there must not be.
//!
//! ## Refusals
//!
//! Every refusal this crate makes is a [`PluginError`] from [`crate::catalog`]; [`render`] turns it
//! into the SAME bytes the legacy handler answered (the two HTML pages, the statuses), because the
//! byte-identity judge in the composition's tests pins those bytes and a "better" page is a
//! divergence.

use busbar_contract::error::{ErrorClass, PluginError};
use bytes::Bytes;
use http::header::{CACHE_CONTROL, CONTENT_TYPE, LOCATION, SET_COOKIE};
use http::{HeaderValue, StatusCode};

use crate::catalog;
use crate::claims::Handler;
use crate::surface::TokenIssuer;

/// A parsed request with its body already buffered. The composition's body-size cap has fired
/// before this is built.
pub type Request = http::Request<Bytes>;
/// A complete response; the composition frames it.
pub type Response = http::Response<Bytes>;

impl TokenIssuer {
    /// Answer ONE request on the row whose handler is `handler`.
    pub async fn answer(&self, handler: Handler, request: Request) -> Response {
        match handler {
            Handler::Forward => forward(self, request).await,
            Handler::ConsentScreen => consent_screen(self, &request),
            Handler::ConsentSubmit => consent_submit(self, &request),
        }
    }
}

/// Hand one request to `oauth-as` and return what it answers, unchanged.
///
/// The whole of busbar's OAuth wire surface is this function. Nothing is inspected, rewritten or
/// re-decided on the way through: the RFCs define these responses down to the header, and a gateway
/// that "improves" one of them fails a conformance suite for a reason nobody can find.
pub async fn forward(surface: &TokenIssuer, request: Request) -> Response {
    // Box::pin: the whole `oauth-as` dispatch future (~56 KB monomorphized), boxed at its one call
    // site — cold relative to the data planes, and boxing keeps the caller's future small.
    Box::pin(
        surface
            .service()
            .handle(request.map(oauth_as::http::Body::from)),
    )
    .await
    .map(oauth_as::http::Body::into_bytes)
}

/// `GET {issuer}/consent` — the screen that names the client and the scopes and asks the operator.
pub fn consent_screen(surface: &TokenIssuer, request: &Request) -> Response {
    // The SAME decode the framework's `Query` extractor performed, and the same rejection when it
    // fails, so a query this deployment used to accept is one it still accepts.
    let query =
        match serde_urlencoded::from_str::<ConsentQuery>(request.uri().query().unwrap_or("")) {
            Ok(q) => q,
            Err(e) => {
                return text(
                    StatusCode::BAD_REQUEST,
                    format!("Failed to deserialize query string: {e}"),
                )
            }
        };
    let Some(target) = query.return_to.as_deref().filter(|t| is_local_path(t)) else {
        return render(&catalog::refuse(
            ErrorClass::NotFound,
            catalog::CONSENT_NO_REQUEST,
            "consent screen reached with no pending authorization request",
        ));
    };
    // The session is opened HERE, not at the POST: the operator has already been authenticated by
    // the operator chain to get this far, so this is the moment the fact is true.
    //
    // NO SESSION WITHOUT ENTROPY. `new_session_id` answers `None` when the platform RNG failed, and
    // the refusal is the point: an EMPTY id is one every caller already knows.
    let Some(id) = new_session_id() else {
        return render(&catalog::refuse(
            ErrorClass::Unavailable,
            catalog::CONSENT_NO_ENTROPY,
            "the platform RNG failed; no session was opened",
        ));
    };
    surface.sessions().open(OPERATOR_SUBJECT, id.clone());
    let mut response = html(StatusCode::OK, consent_page(target));
    for cookie in session_cookies(surface.identity(), &id) {
        // `HeaderValue::from_str` rather than an unwrap: the `Path` is derived from the operator's
        // `issuer`, whose path component is not character-checked at boot, so a control character
        // there would be a response-splitting vector. Refused whole.
        let Ok(value) = HeaderValue::from_str(&cookie) else {
            return render(&catalog::refuse(
                ErrorClass::Internal,
                catalog::CONSENT_NOT_REPRESENTABLE,
                "the issuer path cannot be carried in a Set-Cookie header value",
            ));
        };
        // APPEND, not insert: there is more than one cookie. See `session_cookies`.
        response.headers_mut().append(SET_COOKIE, value);
    }
    // A page naming a client and a scope set is a per-request answer.
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// EVERY `Set-Cookie` that opens one consent session, and why there is more than one of them.
///
/// A cookie is only sent to the paths RFC 6265 §5.1.4 path-matches (a prefix match at a `/`
/// boundary), and the session is read at BOTH `{issuer}/authorize` (the subject and approval
/// resolvers `oauth-as` calls) and `{issuer}/consent` (the submission). `Path=/` would send an
/// operator's credential to the token endpoint and every data-plane path on the origin; two
/// cookies of one name at two disjoint paths is unambiguous by construction.
pub fn session_cookies(identity: &crate::config::Identity, id: &str) -> [String; 2] {
    // `Secure` follows the ISSUER'S SCHEME: unconditional would break the `http://` loopback
    // deployment outright, because a browser discards a `Secure` cookie arriving over plain HTTP.
    let secure = if identity.issuer().starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    // `SameSite=Lax`, NOT `Strict`: the browser arrives at `/authorize` by a cross-site top-level
    // navigation, which `Strict` withholds the cookie on. `Max-Age` is `SESSION_TTL`.
    let attrs = format!(
        "HttpOnly{secure}; SameSite=Lax; Max-Age={}",
        crate::consent::SESSION_TTL.as_secs()
    );
    let name = crate::consent::SESSION_COOKIE;
    [
        format!("{name}={id}; Path={}; {attrs}", identity.authorize_path()),
        format!("{name}={id}; Path={}; {attrs}", identity.consent_path()),
    ]
}

/// `POST {issuer}/consent` — the operator approved. Stake ONE approval and hand the browser back to
/// `/authorize`, which will spend it.
///
/// The approval is staked against the exact client and scope set the pending request carries,
/// read out of the `return` URL rather than from the form: a form field naming the scope would be a
/// value the browser could change between being shown one thing and approving another.
pub fn consent_submit(surface: &TokenIssuer, request: &Request) -> Response {
    // THE SAME `Form` READ the framework extractor performed, rejection for rejection: a wrong
    // content type is a `415` and a malformed body a `400`, each with the extractor's own text.
    if !is_form_content_type(request) {
        return text(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Form requests must have `Content-Type: application/x-www-form-urlencoded`".to_string(),
        );
    }
    let form = match serde_urlencoded::from_bytes::<ConsentForm>(request.body()) {
        Ok(f) => f,
        Err(e) => {
            return text(
                StatusCode::BAD_REQUEST,
                format!("Failed to deserialize form body: {e}"),
            )
        }
    };
    let Some(target) = form.return_to.as_deref().filter(|t| is_local_path(t)) else {
        return render(&catalog::refuse(
            ErrorClass::NotFound,
            catalog::CONSENT_NO_REQUEST,
            "approval submitted with no local return path",
        ));
    };
    // The session comes from the COOKIE, never from the form.
    let Some(session) = crate::consent::session_id(request.headers()) else {
        return render(&catalog::refuse(
            ErrorClass::Denied,
            catalog::CONSENT_NO_SESSION,
            "approval submitted without a consent session cookie",
        ));
    };
    // The redirect host is rendered on the screen but deliberately NOT part of the stake key: the
    // key has to match what the authorization endpoint compares when it spends the approval.
    if let Some((client_id, scope, _redirect_host)) = client_and_scope_of(target) {
        surface
            .sessions()
            .stake(&session, format!("{client_id}\u{1f}{scope}"));
    }
    let mut response = http::Response::new(Bytes::new());
    *response.status_mut() = StatusCode::FOUND;
    if let Ok(value) = HeaderValue::from_str(target) {
        response.headers_mut().insert(LOCATION, value);
    }
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// The refusal's bytes on the wire: the legacy pages and statuses, code by code.
///
/// [`catalog::CONSENT_NO_REQUEST`] and [`catalog::CONSENT_NO_SESSION`] answer the "no request"
/// page at `400`; [`catalog::CONSENT_NO_ENTROPY`] the "no session" page at `503`;
/// [`catalog::CONSENT_NOT_REPRESENTABLE`] the same page at `500` — it names no cause, because
/// neither a failed RNG nor a malformed issuer is something a browser should be told about.
pub fn render(refusal: &PluginError) -> Response {
    match refusal.code.as_str() {
        catalog::CONSENT_NO_ENTROPY => {
            html(StatusCode::SERVICE_UNAVAILABLE, PAGE_NO_SESSION.to_string())
        }
        catalog::CONSENT_NOT_REPRESENTABLE => html(
            StatusCode::INTERNAL_SERVER_ERROR,
            PAGE_NO_SESSION.to_string(),
        ),
        _ => html(StatusCode::BAD_REQUEST, PAGE_NO_REQUEST.to_string()),
    }
}

/// The subject an approval on this plane is granted BY. One value, because there is one party this
/// deployment can authenticate without an identity provider; see [`crate::consent`].
const OPERATOR_SUBJECT: &str = "busbar-operator";

/// `?return=` on the consent screen.
#[derive(serde::Deserialize)]
struct ConsentQuery {
    #[serde(rename = "return")]
    return_to: Option<String>,
}

/// The consent form's one field.
#[derive(serde::Deserialize)]
struct ConsentForm {
    #[serde(rename = "return")]
    return_to: Option<String>,
}

/// `Content-Type: application/x-www-form-urlencoded`, with or without parameters — the same test
/// the framework extractor applied.
fn is_form_content_type(request: &Request) -> bool {
    request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
        .unwrap_or(false)
}

/// Is this a path on THIS server rather than a URL somewhere else? An unchecked one is an open
/// redirect on an OAuth server's own origin. Accepted: a single leading `/` followed by something
/// that is not another `/` and not a `\`.
fn is_local_path(value: &str) -> bool {
    value.starts_with('/')
        && !value.starts_with("//")
        && !value.starts_with("/\\")
        && !value.contains('\\')
}

/// The `client_id` and `scope` of a pending authorization request, read out of its query string.
/// Returns the RAW values: the approval key is compared against what `oauth-as` reports.
fn client_and_scope_of(target: &str) -> Option<(String, String, String)> {
    let query = target.split_once('?')?.1;
    let mut client_id = None;
    let mut scope = String::new();
    let mut redirect_uri = String::new();
    for (name, value) in form_urlencoded_pairs(query) {
        match name.as_str() {
            "client_id" => client_id = Some(value),
            "scope" => scope = value,
            "redirect_uri" => redirect_uri = value,
            _ => {}
        }
    }
    Some((client_id?, scope, host_of(&redirect_uri)))
}

/// The host authority of an absolute `redirect_uri` — the part of it an operator can judge.
fn host_of(redirect_uri: &str) -> String {
    let after_scheme = redirect_uri
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(redirect_uri);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority)
        .to_string()
}

/// `a=b&c=d` with `+` and `%xx` decoded. Hand-written because the one caller reads two names out
/// of a query this server itself produced.
fn form_urlencoded_pairs(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (percent_decode(k), percent_decode(v)))
        .collect()
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                Ok(b) => {
                    out.push(b);
                    i += 3;
                }
                // A stray `%` is kept verbatim: dropping it would let two query strings decode
                // to one value.
                Err(_) => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// An unguessable session id: 256 bits from the platform RNG, hex — or `None`. A session id is a
/// bearer credential, and the only safe answer to "I could not generate a secret" is to not issue one.
fn new_session_id() -> Option<String> {
    let mut bytes = [0u8; 32];
    match ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes) {
        Ok(()) => Some(bytes.iter().map(|b| format!("{b:02x}")).collect()),
        Err(_) => None,
    }
}

/// An HTML answer, exactly as the framework's `Html` wrapper spelled its content type.
fn html(status: StatusCode, page: String) -> Response {
    let mut response = http::Response::new(Bytes::from(page));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
}

/// A plain-text answer, exactly as the framework's rejections spelled theirs.
fn text(status: StatusCode, body: String) -> Response {
    let mut response = http::Response::new(Bytes::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

/// What the operator sees when they land on the consent screen with no pending request.
const PAGE_NO_REQUEST: &str = "<!doctype html><meta charset=utf-8><title>busbar</title>\
    <p>There is no authorization request waiting. Start the login from your agent.</p>";

/// What the operator sees when this server could not open a session at all. It names no cause.
const PAGE_NO_SESSION: &str = "<!doctype html><meta charset=utf-8><title>busbar</title>\
    <p>This server could not start a session. Try again, and tell your operator if it persists.</p>";

/// The consent screen. Everything interpolated is HTML-escaped, and the client's NAME is not among
/// the interpolations: the screen names the `client_id`, because a `client_name` is a string the
/// client chose.
fn consent_page(return_to: &str) -> String {
    let (client_id, scope, redirect_host) = client_and_scope_of(return_to)
        .unwrap_or_else(|| ("(unnamed)".to_string(), String::new(), String::new()));
    let scope = if scope.is_empty() {
        "no scopes".to_string()
    } else {
        scope
    };
    let redirect_host = if redirect_host.is_empty() {
        "(unnamed)".to_string()
    } else {
        redirect_host
    };
    format!(
        "<!doctype html><meta charset=utf-8><title>busbar — authorize</title>\
         <h1>Authorize this client?</h1>\
         <p>Client: <code>{client}</code></p>\
         <p>Requesting: <code>{scope}</code></p>\
         <p>Sends the credential to: <code>{host}</code></p>\
         <form method=post>\
         <input type=hidden name=return value=\"{ret}\">\
         <button type=submit>Approve</button>\
         </form>",
        client = escape(&client_id),
        scope = escape(&scope),
        host = escape(&redirect_host),
        ret = escape(return_to),
    )
}

/// The five characters that change the meaning of surrounding markup.
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
