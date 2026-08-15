// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FLOW ITSELF: `/authorize` → consent → code → token, driven over a real socket through a
//! cookie jar that enforces RFC 6265 path scoping.
//!
//! ## Why a jar, and why this jar
//!
//! The consent session is carried in a cookie, and a cookie is only useful at the paths the
//! browser will send it to. Every test that drives this flow by copying a `Set-Cookie` value into
//! the next request's `Cookie` header is testing a browser that does not exist: such a test passes
//! against a session cookie scoped to a path the reader will never be reached at, which is exactly
//! the defect this file exists to keep out. So the flow below goes through [`Jar`], which
//! implements RFC 6265 §5.1.4 default-path and path-match and NOTHING else, and which has its own
//! proof ([`the_jar_refuses_to_send_a_cookie_to_a_sibling_path`]) that it would have failed the
//! broken code — a jar that ignored `Path` would make this whole file worthless.
//!
//! The issuer is `http://127.0.0.1:{port}` of the listener the router is actually served on, so
//! every absolute URL the server hands back (the consent redirect, the metadata document) points
//! at the socket under test and can be followed literally rather than rewritten by the test.

use std::sync::Arc;

use oauth_as::client::{Client, ClientAuth, ClientId};
use oauth_as::grant::GrantType;
use oauth_as::scope::ScopeSet;

use crate::oauth_as::config::OauthAsCfg;
use crate::test_support::TestApp;

/// The client's redirect URI. Never fetched — the flow ends at the 302 that carries the code.
const REDIRECT_URI: &str = "http://127.0.0.1:9999/cb";
/// RFC 7636 appendix B's verifier and the challenge it hashes to, so PKCE is exercised against a
/// published vector rather than against a challenge this test computed with the same code the
/// server verifies it with.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
/// The one scope this deployment's ceiling allows, so the approval is staked and spent for a
/// NON-EMPTY scope set: an empty one would let a key-building bug on either side pass unnoticed.
const SCOPE: &str = "read";
const CLIENT_ID: &str = "flow-test-client";

// ── the cookie jar ───────────────────────────────────────────────────────────────────────────────

/// One stored cookie: the three attributes that decide whether it is sent, and the value.
#[derive(Clone, Debug)]
struct Cookie {
    name: String,
    value: String,
    path: String,
    secure: bool,
}

/// A cookie store that applies RFC 6265 §5.1.4 and refuses to guess.
///
/// Deliberately hand-written and deliberately small. A general-purpose jar would be a dependency,
/// and — more to the point — this file's whole claim is that the cookie reaches the paths that read
/// it, so the code deciding that has to be visible in the test rather than three crates away.
#[derive(Default)]
struct Jar {
    cookies: Vec<Cookie>,
    /// `true` when the connection this jar is used over is a secure one. `Secure` cookies are
    /// stored only when it is (RFC 6265bis §5.5), which is what makes a `Secure` attribute on a
    /// plain-HTTP deployment show up here as a missing cookie rather than as nothing at all.
    secure_connection: bool,
}

impl Jar {
    fn new(secure_connection: bool) -> Self {
        Self {
            cookies: Vec::new(),
            secure_connection,
        }
    }

    /// Store one `Set-Cookie`, as received on a request to `request_path`.
    ///
    /// `Max-Age=0` deletes, which is how a clearing header is honoured rather than stored as a
    /// cookie with an empty value.
    fn store(&mut self, set_cookie: &str, request_path: &str) {
        let mut parts = set_cookie.split(';');
        let (name, value) = parts
            .next()
            .and_then(|nv| nv.split_once('='))
            .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
            .expect("a Set-Cookie header has a name=value pair");
        let mut path: Option<String> = None;
        let mut secure = false;
        let mut max_age: Option<i64> = None;
        for attr in parts {
            let (k, v) = match attr.split_once('=') {
                Some((k, v)) => (k.trim(), v.trim()),
                None => (attr.trim(), ""),
            };
            match k.to_ascii_lowercase().as_str() {
                "path" => path = Some(v.to_string()),
                "secure" => secure = true,
                "max-age" => max_age = v.parse().ok(),
                _ => {}
            }
        }
        // RFC 6265 §5.1.4: an absent or non-`/`-prefixed Path defaults to the request path with its
        // last segment removed.
        let path = match path {
            Some(p) if p.starts_with('/') => p,
            _ => default_path(request_path),
        };
        self.cookies.retain(|c| !(c.name == name && c.path == path));
        if max_age == Some(0) {
            return;
        }
        if secure && !self.secure_connection {
            return;
        }
        self.cookies.push(Cookie {
            name,
            value,
            path,
            secure,
        });
    }

    /// The `Cookie` header to send to `request_path`, or `None` when nothing matches — which is the
    /// answer this whole file is about.
    fn header_for(&self, request_path: &str) -> Option<String> {
        let sent: Vec<String> = self
            .cookies
            .iter()
            .filter(|c| path_matches(request_path, &c.path))
            .filter(|c| self.secure_connection || !c.secure)
            .map(|c| format!("{}={}", c.name, c.value))
            .collect();
        (!sent.is_empty()).then(|| sent.join("; "))
    }
}

/// RFC 6265 §5.1.4 default-path.
fn default_path(request_path: &str) -> String {
    if !request_path.starts_with('/') {
        return "/".to_string();
    }
    match request_path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => request_path[..i].to_string(),
    }
}

/// RFC 6265 §5.1.4 path-match. Prefix matching only at a `/` boundary, which is what makes
/// `/authorize` and `/consent` disjoint and `/consent` a match for `/consent/anything`.
fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    if request_path == cookie_path {
        return true;
    }
    if !request_path.starts_with(cookie_path) {
        return false;
    }
    cookie_path.ends_with('/') || request_path[cookie_path.len()..].starts_with('/')
}

// ── the wire ─────────────────────────────────────────────────────────────────────────────────────

/// One request through the jar: cookies in, `Set-Cookie`s out, redirects NOT followed.
///
/// Redirects are followed by hand below so every hop's status, `Location` and cookie header can be
/// asserted on — a client that followed them would hide the exact hop this file is about.
async fn send(
    client: &reqwest::Client,
    jar: &mut Jar,
    method: reqwest::Method,
    url: &str,
    form: Option<&[(&str, &str)]>,
) -> (reqwest::StatusCode, reqwest::header::HeaderMap, String) {
    let path = path_of(url);
    let mut req = client.request(method, url);
    if let Some(cookie) = jar.header_for(&path) {
        req = req.header(reqwest::header::COOKIE, cookie);
    }
    if let Some(form) = form {
        req = req.form(form);
    }
    let resp = req.send().await.expect("request");
    let status = resp.status();
    let headers = resp.headers().clone();
    for value in headers.get_all(reqwest::header::SET_COOKIE) {
        jar.store(value.to_str().expect("ASCII Set-Cookie"), &path);
    }
    let body = resp.text().await.expect("body");
    (status, headers, body)
}

/// The path component of an absolute URL, or of a path that is already one.
fn path_of(url: &str) -> String {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"));
    let with_query = match rest {
        Some(rest) => match rest.find('/') {
            Some(i) => &rest[i..],
            None => "/",
        },
        None => url,
    };
    with_query
        .split_once('?')
        .map_or(with_query, |(p, _)| p)
        .to_string()
}

/// One query parameter of a URL, percent-decoded exactly as far as this test needs.
fn query_param(url: &str, name: &str) -> Option<String> {
    url.split(['?', '&'])
        .skip(1)
        .filter_map(|p| p.split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

/// The `Location` of a redirect, as an absolute URL against `origin`.
fn location(headers: &reqwest::header::HeaderMap, origin: &str) -> String {
    let raw = headers
        .get(reqwest::header::LOCATION)
        .expect("a redirect carries Location")
        .to_str()
        .expect("ASCII Location")
        .to_string();
    if raw.starts_with('/') {
        format!("{origin}{raw}")
    } else {
        raw
    }
}

// ── the fixture ──────────────────────────────────────────────────────────────────────────────────

/// A served deployment: an authorization server on a real socket, with one registered client and an
/// OPEN admin posture so the consent screen is reachable without a credential.
///
/// The admin chain is what the consent route's `RouteAuth::Admin` consults, and it is emptied here
/// deliberately: the property under test is the cookie's reach, and an operator credential in the
/// middle of it would only add a second way for the test to fail.
async fn serve() -> (String, Arc<crate::state::App>) {
    crate::metrics::init();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let origin = format!("http://{addr}");

    let cfg = OauthAsCfg {
        issuer: origin.clone(),
        signing_key: None,
        key_id: None,
        dynamic_registration: None,
        default_grant: vec![SCOPE.to_string()],
        access_token_ttl_secs: None,
    };
    let app = TestApp::new().admin_chain(vec![]).oauth_as(&cfg).build();

    let scopes = ScopeSet::from_tokens([SCOPE]).expect("scope");
    app.oauth_as
        .as_ref()
        .expect("configured")
        .server()
        .register_client(Client {
            client_id: ClientId::new(CLIENT_ID),
            auth: ClientAuth::Public,
            grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            redirect_uris: vec![REDIRECT_URI.to_string()],
            allowed_scopes: scopes.clone(),
            default_scopes: scopes,
            name: Some("Flow Test".to_string()),
            registration: None,
        })
        .await
        .expect("register client");

    let router = crate::build_router(Arc::clone(&app));
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    (origin, app)
}

// ── the tests ────────────────────────────────────────────────────────────────────────────────────

/// THE JAR'S OWN PROOF, and the reason the test below means anything.
///
/// A jar that ignored `Path` would have passed against the broken code — the session cookie was
/// scoped to `/consent` and read at `/authorize`, and a jar that replayed every cookie everywhere
/// would have papered over exactly that. This test is what stops that from happening silently.
#[test]
fn the_jar_refuses_to_send_a_cookie_to_a_sibling_path() {
    let mut jar = Jar::new(false);
    jar.store("s=abc; Path=/consent; HttpOnly", "/consent");
    assert_eq!(jar.header_for("/consent").as_deref(), Some("s=abc"));
    assert_eq!(
        jar.header_for("/consent/sub").as_deref(),
        Some("s=abc"),
        "path-match is a prefix match at a `/` boundary"
    );
    assert_eq!(
        jar.header_for("/authorize"),
        None,
        "`/consent` and `/authorize` are SIBLINGS: a cookie scoped to one is never sent to the other"
    );
    assert_eq!(
        jar.header_for("/consentious"),
        None,
        "a prefix that does not end at a `/` boundary is not a path-match"
    );

    // Two cookies of the same name at two disjoint paths are two cookies, and each is sent to its
    // own path only. This is the shape the fix relies on.
    let mut jar = Jar::new(false);
    jar.store("s=one; Path=/authorize", "/authorize");
    jar.store("s=two; Path=/consent", "/consent");
    assert_eq!(jar.header_for("/authorize").as_deref(), Some("s=one"));
    assert_eq!(jar.header_for("/consent").as_deref(), Some("s=two"));
    assert_eq!(jar.header_for("/token"), None);
    assert_eq!(jar.header_for("/"), None);

    // A `Secure` cookie is not stored over a plain connection, so a `Secure` attribute that a
    // deployment cannot honour reads here as an absent cookie.
    let mut jar = Jar::new(false);
    jar.store("s=abc; Path=/consent; Secure", "/consent");
    assert_eq!(jar.header_for("/consent"), None);
    let mut jar = Jar::new(true);
    jar.store("s=abc; Path=/consent; Secure", "/consent");
    assert_eq!(jar.header_for("/consent").as_deref(), Some("s=abc"));

    // Max-Age=0 is a deletion, not a cookie with an empty value.
    let mut jar = Jar::new(false);
    jar.store("s=abc; Path=/consent", "/consent");
    jar.store("s=; Path=/consent; Max-Age=0", "/consent");
    assert_eq!(jar.header_for("/consent"), None);
}

/// EVERY ATTRIBUTE of the session cookie, pinned where it is written rather than inferred from a
/// response — so a change to any one of them is a change somebody has to make here too.
///
/// The scope is asserted as a SET of exact paths: the point of the fix is that this cookie reaches
/// the two endpoints that read it and NOT the token endpoint, and a test that only checked
/// "`/authorize` gets it" would pass just as happily against `Path=/`.
#[test]
fn the_session_cookie_carries_exactly_the_attributes_it_should() {
    use crate::oauth_as::config::AsIdentity;
    use crate::oauth_as::routes::session_cookies;

    for (issuer, secure_expected) in [
        ("https://as.example.com", true),
        // A loopback developer deployment. `Secure` here would be a cookie the browser discards.
        ("http://127.0.0.1:8080", false),
        // A tenant-prefixed issuer: the two paths carry the prefix, and neither one is the bare
        // `/authorize` or `/consent` of the origin.
        ("https://gw.example.com/tenant-a", true),
    ] {
        let cfg = OauthAsCfg {
            issuer: issuer.to_string(),
            signing_key: None,
            key_id: None,
            dynamic_registration: None,
            default_grant: Vec::new(),
            access_token_ttl_secs: None,
        };
        let id = AsIdentity::from_cfg(&cfg).expect("valid issuer");
        let cookies = session_cookies(&id, "deadbeef");

        // The jar decides reachability, exactly as the browser does.
        let mut jar = Jar::new(secure_expected);
        for c in &cookies {
            jar.store(c, id.consent_path());
        }
        assert!(
            jar.header_for(id.authorize_path()).is_some(),
            "the approval resolver reads this cookie at {}: {cookies:?}",
            id.authorize_path()
        );
        assert!(
            jar.header_for(id.consent_path()).is_some(),
            "the consent POST reads this cookie at {}: {cookies:?}",
            id.consent_path()
        );
        // AND NOWHERE ELSE. The token endpoint is the one that matters — it is spoken to by the
        // CLIENT, so an operator session cookie arriving there is a credential handed to the party
        // the consent step exists to keep it from.
        assert_eq!(
            jar.header_for(id.token_path()),
            None,
            "the token endpoint must never see the operator's session: {cookies:?}"
        );
        assert_eq!(jar.header_for(id.jwks_path()), None);
        assert_eq!(jar.header_for(id.metadata_path()), None);
        assert_eq!(
            jar.header_for("/v1/chat/completions"),
            None,
            "a data-plane path on the same origin must never see it either"
        );
        assert_eq!(jar.header_for("/"), None);

        for c in &cookies {
            assert!(c.contains("; HttpOnly"), "script must not read it: {c}");
            assert!(
                c.contains("; SameSite=Lax"),
                "Strict would withhold the cookie on the cross-site top-level navigation that \
                 STARTS this flow: {c}"
            );
            assert_eq!(
                c.contains("; Secure"),
                secure_expected,
                "`Secure` follows the issuer's scheme ({issuer}): {c}"
            );
            assert!(
                c.contains(&format!(
                    "; Max-Age={}",
                    crate::oauth_as::consent::SESSION_TTL.as_secs()
                )),
                "the cookie's lifetime is the SESSION's lifetime, from the same constant: {c}"
            );
            assert!(
                !c.contains("Path=/;") && !c.ends_with("Path=/"),
                "`Path=/` is the widening this fix exists to avoid: {c}"
            );
        }
    }
}

/// THE FLOW, end to end: an authorization request that has never been seen mints a code, and that
/// code is exchanged for a usable access token.
///
/// Every hop is asserted, because the failure this test was written for delivered a cookie and
/// still could not mint a code — the browser bounced between `/authorize` and `/consent` forever,
/// with each hop individually looking correct.
#[tokio::test]
async fn the_authorization_code_flow_mints_and_exchanges_a_code() {
    let (origin, app) = serve().await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");
    // The issuer is `http://`, so the jar is a plain-connection one: a `Secure` cookie would be
    // DROPPED here, which is what makes the attribute's derivation from the issuer scheme a thing
    // this test can see rather than a comment.
    let mut jar = Jar::new(false);

    let authorize = format!(
        "{origin}/authorize?response_type=code&client_id={CLIENT_ID}\
         &redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb&state=s1&scope={SCOPE}\
         &code_challenge={CHALLENGE}&code_challenge_method=S256"
    );

    // 1. The unauthenticated authorization request is sent to the consent screen.
    let (status, headers, body) =
        send(&client, &mut jar, reqwest::Method::GET, &authorize, None).await;
    assert_eq!(status, 302, "authorize must redirect to consent: {body}");
    let consent = location(&headers, &origin);
    assert!(
        consent.starts_with(&format!("{origin}/consent?return=")),
        "the redirect must name this deployment's consent screen: {consent}"
    );

    // 2. The consent screen opens the session and sets the cookie.
    let (status, headers, body) =
        send(&client, &mut jar, reqwest::Method::GET, &consent, None).await;
    assert_eq!(status, 200, "the consent screen must render: {body}");
    let set_cookie = headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().expect("ASCII").to_string())
        .collect::<Vec<_>>();
    assert!(
        !set_cookie.is_empty(),
        "the consent screen must open a session"
    );

    // THE CLAIM THE DEFECT BROKE: the session cookie is sent BOTH to the screen that submits the
    // approval and to the endpoint that spends it. Asserted before the flow continues, so a
    // regression names the cookie rather than showing up as a redirect loop twenty lines later.
    assert!(
        jar.header_for("/consent").is_some(),
        "the consent POST reads the session cookie; Set-Cookie was {set_cookie:?}"
    );
    assert!(
        jar.header_for("/authorize").is_some(),
        "`/authorize` is where the approval resolver reads the session cookie, and it is a SIBLING \
         of `/consent`, not a child: a cookie the browser will not send here cannot mint a code. \
         Set-Cookie was {set_cookie:?}"
    );

    // 3. The operator approves. The form carries only the return URL; the session comes from the
    //    cookie the jar decided to send.
    let return_to =
        query_param(&consent, "return").expect("the screen carries the pending request");
    let return_to = percent_decode(&return_to);
    let (status, headers, body) = send(
        &client,
        &mut jar,
        reqwest::Method::POST,
        &format!("{origin}/consent"),
        Some(&[("return", return_to.as_str())]),
    )
    .await;
    assert_eq!(status, 302, "an approval must redirect back: {body}");
    let back = location(&headers, &origin);
    assert!(
        path_of(&back) == "/authorize",
        "the approval hands the browser back to the authorization endpoint: {back}"
    );

    // 4. The authorization request is replayed, the staked approval is spent, and a code is minted.
    let (status, headers, body) = send(&client, &mut jar, reqwest::Method::GET, &back, None).await;
    assert_eq!(status, 302, "the approved request must redirect: {body}");
    let redirect = location(&headers, &origin);
    assert!(
        redirect.starts_with(REDIRECT_URI),
        "an approved request goes to the CLIENT's redirect URI, not back to the consent screen. \
         Got: {redirect}"
    );
    let code = query_param(&redirect, "code").unwrap_or_else(|| {
        panic!("the approved authorization request must carry a code: {redirect}")
    });
    assert!(!code.is_empty(), "an empty code is not a code");
    assert_eq!(
        query_param(&redirect, "state").as_deref(),
        Some("s1"),
        "RFC 6749 §4.1.2: the client's `state` is returned verbatim"
    );

    // 5. The code is exchanged at the token endpoint.
    let (status, _headers, body) = send(
        &client,
        &mut jar,
        reqwest::Method::POST,
        &format!("{origin}/token"),
        Some(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("client_id", CLIENT_ID),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", VERIFIER),
        ]),
    )
    .await;
    assert_eq!(status, 200, "the code must be exchangeable: {body}");
    let token: serde_json::Value = serde_json::from_str(&body).expect("a token response is JSON");
    let access = token["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("no access_token: {body}"))
        .to_string();

    // 6. The token is USABLE: the server that minted it knows it, for the client and the subject
    //    and the scope the operator actually approved. A token the AS cannot introspect is a string.
    let record = app
        .oauth_as
        .as_ref()
        .expect("configured")
        .server()
        .introspect(&access)
        .await
        .expect("introspection must not fail")
        .expect("the freshly minted token must be live");
    assert_eq!(record.client_id.as_str(), CLIENT_ID);
    assert_eq!(
        record.subject.as_deref(),
        Some("busbar-operator"),
        "the code was minted for the operator, who is this plane's only resource owner"
    );
    assert_eq!(record.scope.to_string(), SCOPE);

    // And the audience binding busbar's own resource half reads off a bearer holds, which is what
    // makes the token usable at a busbar plane rather than merely well-formed.
    assert_eq!(
        crate::auth::audience::inspect_bearer(&access, &origin),
        crate::auth::audience::Binding::Bound,
        "the access token must carry this deployment's audience"
    );

    // 7. The approval was ONE-SHOT: replaying the same authorization request goes back to the
    //    consent screen rather than minting a second code from a decision made once.
    let (status, headers, body) =
        send(&client, &mut jar, reqwest::Method::GET, &authorize, None).await;
    assert_eq!(status, 302, "{body}");
    assert_eq!(
        path_of(&location(&headers, &origin)),
        "/consent",
        "a spent approval must not authorise a second request"
    );
}

// ── all three registration mechanisms, end to end ───────────────────────────────────────────────
//
// The ruling this plane ships under is ALL THREE ON, NO TOGGLES, and a mounted endpoint is not an
// admitted client. So each mechanism is driven over the same real socket to the same end state — an
// access token the server introspects for that client — with the flow itself shared, because three
// hand-rolled copies of the hops would let one mechanism's proof drift from another's.
//
// * pre-registered: `the_authorization_code_flow_mints_and_exchanges_a_code` above (the fixture's
//   client is provisioned by `register_client`, which IS pre-registration).
// * DCR:  `dynamic_client_registration_admits_a_client_end_to_end`.
// * CIMD: `a_client_id_metadata_document_admits_a_client_end_to_end`, over a stub document host —
//   the fetch seam exists so the SSRF guard's loopback refusal does not sit between this test and
//   the property under test. The guard has its own suites; the document VALIDATION has `cimd_tests`.

/// Drive authorize → consent → approval → code → token for `client_id`, asserting every hop, and
/// hand back the access token.
async fn mint_access_token(origin: &str, client_id: &str) -> String {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");
    let mut jar = Jar::new(false);

    let authorize = format!(
        "{origin}/authorize?response_type=code&client_id={}\
         &redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb&state=s1&scope={SCOPE}\
         &code_challenge={CHALLENGE}&code_challenge_method=S256",
        encode_component(client_id)
    );

    let (status, headers, body) =
        send(&client, &mut jar, reqwest::Method::GET, &authorize, None).await;
    assert_eq!(status, 302, "authorize must redirect to consent: {body}");
    let consent = location(&headers, origin);

    let (status, _headers, body) =
        send(&client, &mut jar, reqwest::Method::GET, &consent, None).await;
    assert_eq!(status, 200, "the consent screen must render: {body}");

    let return_to =
        query_param(&consent, "return").expect("the screen carries the pending request");
    let return_to = percent_decode(&return_to);
    let (status, headers, body) = send(
        &client,
        &mut jar,
        reqwest::Method::POST,
        &format!("{origin}/consent"),
        Some(&[("return", return_to.as_str())]),
    )
    .await;
    assert_eq!(status, 302, "an approval must redirect back: {body}");
    let back = location(&headers, origin);

    let (status, headers, body) = send(&client, &mut jar, reqwest::Method::GET, &back, None).await;
    assert_eq!(status, 302, "the approved request must redirect: {body}");
    let redirect = location(&headers, origin);
    assert!(
        redirect.starts_with(REDIRECT_URI),
        "an approved request goes to the client's redirect URI: {redirect}"
    );
    let code = query_param(&redirect, "code")
        .unwrap_or_else(|| panic!("the approved request must carry a code: {redirect}"));

    let (status, _headers, body) = send(
        &client,
        &mut jar,
        reqwest::Method::POST,
        &format!("{origin}/token"),
        Some(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("client_id", client_id),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", VERIFIER),
        ]),
    )
    .await;
    assert_eq!(status, 200, "the code must be exchangeable: {body}");
    let token: serde_json::Value = serde_json::from_str(&body).expect("a token response is JSON");
    token["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("no access_token: {body}"))
        .to_string()
}

/// RFC 3986 percent-encoding for one query VALUE, so a `client_id` that is itself a URL survives
/// the trip through the authorization request's query string byte-for-byte.
fn encode_component(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                char::from(b).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

/// DCR, END TO END: an anonymous POST to the always-mounted `/register` mints a `client_id`, and
/// that client completes the whole flow to a token the server knows.
#[tokio::test]
async fn dynamic_client_registration_admits_a_client_end_to_end() {
    let (origin, app) = serve().await;

    let resp = reqwest::Client::new()
        .post(format!("{origin}/register"))
        .json(&serde_json::json!({
            "redirect_uris": [REDIRECT_URI],
            "token_endpoint_auth_method": "none",
            "response_types": ["code"],
            "grant_types": ["authorization_code", "refresh_token"],
            "client_name": "an agent",
            "scope": SCOPE,
        }))
        .send()
        .await
        .expect("register");
    assert_eq!(
        resp.status(),
        201,
        "RFC 7591 §3.2.1: a registration is 201 Created; the endpoint mounts with the plane, \
         unconditionally"
    );
    let registration: serde_json::Value = resp.json().await.expect("a registration response");
    let client_id = registration["client_id"]
        .as_str()
        .unwrap_or_else(|| panic!("no client_id in {registration}"))
        .to_string();

    let access = mint_access_token(&origin, &client_id).await;
    let record = app
        .oauth_as
        .as_ref()
        .expect("configured")
        .server()
        .introspect(&access)
        .await
        .expect("introspection must not fail")
        .expect("the freshly minted token must be live");
    assert_eq!(record.client_id.as_str(), client_id);
    assert_eq!(record.scope.to_string(), SCOPE);
}

/// The metadata document URL that IS the client id on the CIMD path.
const CIMD_CLIENT_ID: &str = "https://client.example/oauth-client";

/// The stub document host behind the fetch seam: answers the one URL with the document, and
/// anything else with a refusal — so the test also shows the fallback is keyed to the exact
/// `client_id` and not to "any HTTPS URL fetches something".
struct StubDocumentHost(serde_json::Value);

impl crate::oauth_as::cimd::CimdFetch for StubDocumentHost {
    fn fetch<'a>(
        &'a self,
        url: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send + 'a>>
    {
        Box::pin(async move {
            if url == CIMD_CLIENT_ID {
                Ok(serde_json::to_vec(&self.0).expect("the stub document serialises"))
            } else {
                Err(format!("no document at `{url}`"))
            }
        })
    }
}

/// CIMD, END TO END: a `client_id` that is an HTTPS URL, never registered anywhere, completes the
/// whole flow to a token the server introspects FOR THAT URL. The client exists only as its
/// document — nothing was written to the store before, during or after.
#[tokio::test]
async fn a_client_id_metadata_document_admits_a_client_end_to_end() {
    let (origin, app) = serve().await;
    app.oauth_as
        .as_ref()
        .expect("configured")
        .server()
        .store()
        .set_fetcher(Arc::new(StubDocumentHost(serde_json::json!({
            "client_id": CIMD_CLIENT_ID,
            "redirect_uris": [REDIRECT_URI],
            "token_endpoint_auth_method": "none",
            "client_name": "an agent",
            "scope": SCOPE,
        }))));

    let access = mint_access_token(&origin, CIMD_CLIENT_ID).await;
    let record = app
        .oauth_as
        .as_ref()
        .expect("configured")
        .server()
        .introspect(&access)
        .await
        .expect("introspection must not fail")
        .expect("the freshly minted token must be live");
    assert_eq!(
        record.client_id.as_str(),
        CIMD_CLIENT_ID,
        "the URL is the client's identity, verbatim"
    );
    assert_eq!(record.scope.to_string(), SCOPE);
}

/// Percent-decoding for the one value this file reads back out of a URL it was handed.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                Ok(b) => {
                    out.push(b);
                    i += 3;
                }
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
    String::from_utf8(out).expect("the server produced UTF-8")
}
