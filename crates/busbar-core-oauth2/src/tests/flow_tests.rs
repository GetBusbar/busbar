// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{MeteringDelta, PlaneRecordRef, PlaneSelector, UsageDelta};
use busbar_contract::store_calls::{StoreCall, StoreCalls, StoreDoor, StoreFailure};

use oauth_as::client::{Client, ClientAuth, ClientId};
use oauth_as::grant::GrantType;
use oauth_as::scope::ScopeSet;

use crate::config::OauthAsCfg;
use busbar_kernel_testkit::test_support::TestApp;

use crate::testkit::{oauth_as_plane, TestAppOauthExt};

const REDIRECT_URI: &str = "http://127.0.0.1:9999/cb";

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

const SCOPE: &str = "read";
const CLIENT_ID: &str = "flow-test-client";

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
pub(crate) struct Jar {
    cookies: Vec<Cookie>,
    /// `true` when the connection this jar is used over is a secure one. `Secure` cookies are
    /// stored only when it is (RFC 6265bis §5.5), which is what makes a `Secure` attribute on a
    /// plain-HTTP deployment show up here as a missing cookie rather than as nothing at all.
    secure_connection: bool,
}

impl Jar {
    pub(crate) fn new(secure_connection: bool) -> Self {
        Self {
            cookies: Vec::new(),
            secure_connection,
        }
    }

    pub(crate) fn store(&mut self, set_cookie: &str, request_path: &str) {
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

    pub(crate) fn header_for(&self, request_path: &str) -> Option<String> {
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

fn default_path(request_path: &str) -> String {
    if !request_path.starts_with('/') {
        return "/".to_string();
    }
    match request_path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => request_path[..i].to_string(),
    }
}

fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    if request_path == cookie_path {
        return true;
    }
    if !request_path.starts_with(cookie_path) {
        return false;
    }
    cookie_path.ends_with('/') || request_path[cookie_path.len()..].starts_with('/')
}

pub(crate) async fn send(
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

pub(crate) fn path_of(url: &str) -> String {
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

pub(crate) fn query_param(url: &str, name: &str) -> Option<String> {
    url.split(['?', '&'])
        .skip(1)
        .filter_map(|p| p.split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

pub(crate) fn location(headers: &reqwest::header::HeaderMap, origin: &str) -> String {
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

async fn serve() -> (String, Arc<busbar_kernel::state::App>) {
    serve_with_admin_chain(Vec::new()).await
}

pub(crate) async fn serve_with_admin_chain(
    admin_chain: Vec<String>,
) -> (String, Arc<busbar_kernel::state::App>) {
    serve_with_store(admin_chain, None).await
}

async fn serve_with_store(
    admin_chain: Vec<String>,
    store: Option<Arc<dyn StoreCalls>>,
) -> (String, Arc<busbar_kernel::state::App>) {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let origin = format!("http://{addr}");

    let cfg = OauthAsCfg {
        issuer: origin.clone(),
        signing_key: None,
        key_id: None,
        default_grant: vec![SCOPE.to_string()],
        access_token_ttl_secs: None,
        refresh_token_ttl_secs: None,
        fapi2: false,
        clients: Vec::new(),
    };
    let builder = TestApp::new().admin_chain(admin_chain);
    let app = match store {
        None => builder.oauth_as(&cfg).build(),
        Some(store) => {
            crate::testkit::install_test_seam();
            let identity = crate::config::AsIdentity::from_cfg(&cfg).expect("valid config");
            let plane = crate::plane::AsPlane::build_carrying(
                identity,
                None,
                Vec::new(),
                crate::cimd::unconnected(),
                Arc::new(crate::plane::Carried::over(Some(store))),
            )
            .expect("shared-store plane");
            builder.oauth_as_plane(Arc::new(plane)).build()
        }
    };

    let scopes = ScopeSet::from_tokens([SCOPE]).expect("scope");
    oauth_as_plane(&app)
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

    let router = busbar_kernel::build_router(Arc::clone(&app));
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    (origin, app)
}

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

    let mut jar = Jar::new(false);
    jar.store("s=one; Path=/authorize", "/authorize");
    jar.store("s=two; Path=/consent", "/consent");
    assert_eq!(jar.header_for("/authorize").as_deref(), Some("s=one"));
    assert_eq!(jar.header_for("/consent").as_deref(), Some("s=two"));
    assert_eq!(jar.header_for("/token"), None);
    assert_eq!(jar.header_for("/"), None);

    let mut jar = Jar::new(false);
    jar.store("s=abc; Path=/consent; Secure", "/consent");
    assert_eq!(jar.header_for("/consent"), None);
    let mut jar = Jar::new(true);
    jar.store("s=abc; Path=/consent; Secure", "/consent");
    assert_eq!(jar.header_for("/consent").as_deref(), Some("s=abc"));

    let mut jar = Jar::new(false);
    jar.store("s=abc; Path=/consent", "/consent");
    jar.store("s=; Path=/consent; Max-Age=0", "/consent");
    assert_eq!(jar.header_for("/consent"), None);
}

#[test]
fn the_session_cookie_carries_exactly_the_attributes_it_should() {
    use crate::config::AsIdentity;
    use crate::routes::session_cookies;

    for (issuer, secure_expected) in [
        ("https://as.example.com", true),
        ("http://127.0.0.1:8080", false),
        ("https://gw.example.com/tenant-a", true),
    ] {
        let cfg = OauthAsCfg {
            issuer: issuer.to_string(),
            signing_key: None,
            key_id: None,
            default_grant: Vec::new(),
            access_token_ttl_secs: None,
            refresh_token_ttl_secs: None,
            fapi2: false,
            clients: Vec::new(),
        };
        let id = AsIdentity::from_cfg(&cfg).expect("valid issuer");
        let cookies = session_cookies(&id, "deadbeef");

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
                    crate::consent::SESSION_TTL.as_secs()
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

#[tokio::test]
async fn the_authorization_code_flow_mints_and_exchanges_a_code() {
    let (origin, app) = serve().await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");

    let mut jar = Jar::new(false);

    let authorize = format!(
        "{origin}/authorize?response_type=code&client_id={CLIENT_ID}\
         &redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb&state=s1&scope={SCOPE}\
         &code_challenge={CHALLENGE}&code_challenge_method=S256"
    );

    let (status, headers, body) =
        send(&client, &mut jar, reqwest::Method::GET, &authorize, None).await;
    assert_eq!(status, 302, "authorize must redirect to consent: {body}");
    let consent = location(&headers, &origin);
    assert!(
        consent.starts_with(&format!("{origin}/consent?return=")),
        "the redirect must name this deployment's consent screen: {consent}"
    );

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

    let record = oauth_as_plane(&app)
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

    assert_eq!(
        busbar_kernel::auth::audience::inspect_bearer(&access, &origin),
        busbar_kernel::auth::audience::Binding::Bound,
        "the access token must carry this deployment's audience"
    );

    let (status, headers, body) =
        send(&client, &mut jar, reqwest::Method::GET, &authorize, None).await;
    assert_eq!(status, 302, "{body}");
    assert_eq!(
        path_of(&location(&headers, &origin)),
        "/consent",
        "a spent approval must not authorise a second request"
    );
}

#[tokio::test]
async fn a_multi_scope_or_default_scope_request_is_approved_on_its_first_consent() {
    const MULTI: &str = "flow-test-multi-scope";
    let (origin, app) = serve().await;
    let scopes = ScopeSet::from_tokens(["read", "write"]).expect("scope");
    oauth_as_plane(&app)
        .expect("configured")
        .server()
        .register_client(Client {
            client_id: ClientId::new(MULTI),
            auth: ClientAuth::Public,
            grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            redirect_uris: vec![REDIRECT_URI.to_string()],
            allowed_scopes: scopes.clone(),
            default_scopes: scopes,
            name: Some("Multi Scope".to_string()),
            registration: None,
        })
        .await
        .expect("register client");
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");

    for scope in ["&scope=write%20read", "&scope=read%20read%20write", ""] {
        let mut jar = Jar::new(false);
        let authorize = format!(
            "{origin}/authorize?response_type=code&client_id={MULTI}\
             &redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb&state=s1{scope}\
             &code_challenge={CHALLENGE}&code_challenge_method=S256"
        );
        let (status, headers, body) =
            send(&client, &mut jar, reqwest::Method::GET, &authorize, None).await;
        assert_eq!(
            status, 302,
            "{scope:?}: authorize must redirect to consent: {body}"
        );
        let consent = location(&headers, &origin);
        let (status, _headers, body) =
            send(&client, &mut jar, reqwest::Method::GET, &consent, None).await;
        assert_eq!(
            status, 200,
            "{scope:?}: the consent screen must render: {body}"
        );
        let return_to = percent_decode(
            &query_param(&consent, "return").expect("the screen carries the pending request"),
        );
        let (status, headers, body) = send(
            &client,
            &mut jar,
            reqwest::Method::POST,
            &format!("{origin}/consent"),
            Some(&[("return", return_to.as_str())]),
        )
        .await;
        assert_eq!(
            status, 302,
            "{scope:?}: an approval must redirect back: {body}"
        );
        let back = location(&headers, &origin);
        let (status, headers, body) =
            send(&client, &mut jar, reqwest::Method::GET, &back, None).await;
        assert_eq!(status, 302, "{scope:?}: {body}");
        let redirect = location(&headers, &origin);
        assert!(
            redirect.starts_with(REDIRECT_URI),
            "{scope:?}: an approved request goes to the client's redirect URI on its FIRST \
             approval, not back to the consent screen. Got: {redirect}"
        );
        assert!(
            query_param(&redirect, "code").is_some_and(|c| !c.is_empty()),
            "{scope:?}: the approved request carries a code: {redirect}"
        );
    }
}

fn requesting(page: &str) -> String {
    page.split_once("<p>Requesting: <code>")
        .and_then(|(_, rest)| rest.split_once("</code>"))
        .map(|(scope, _)| scope.to_string())
        .unwrap_or_else(|| panic!("the screen names what it is asking for: {page}"))
}

async fn shown_and_granted(
    origin: &str,
    app: &busbar_kernel::state::App,
    client_id: &str,
    scope_param: &str,
) -> (String, String) {
    shown_and_granted_after_lookup_failure(origin, app, client_id, scope_param, None).await
}

async fn shown_and_granted_after_lookup_failure(
    origin: &str,
    app: &busbar_kernel::state::App,
    client_id: &str,
    scope_param: &str,
    fault: Option<&FailClientRead>,
) -> (String, String) {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");
    let mut jar = Jar::new(false);
    let authorize = format!(
        "{origin}/authorize?response_type=code&client_id={}\
         &redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb&state=s1{scope_param}\
         &code_challenge={CHALLENGE}&code_challenge_method=S256",
        encode_component(client_id)
    );
    let (status, headers, body) =
        send(&client, &mut jar, reqwest::Method::GET, &authorize, None).await;
    assert_eq!(status, 302, "authorize must redirect to consent: {body}");
    let consent = location(&headers, origin);
    if let Some(fault) = fault {
        fault.fail_next.store(true, Ordering::SeqCst);
        let (status, headers, page) =
            send(&client, &mut jar, reqwest::Method::GET, &consent, None).await;
        assert_eq!(
            status, 503,
            "an unresolved grant cannot be approved: {page}"
        );
        assert!(
            !page.contains("<form"),
            "no approval form on lookup failure: {page}"
        );
        assert_eq!(headers[reqwest::header::CACHE_CONTROL], "no-store");
    }
    let (status, _headers, page) =
        send(&client, &mut jar, reqwest::Method::GET, &consent, None).await;
    assert_eq!(status, 200, "the consent screen must render: {page}");
    let shown = requesting(&page);

    let return_to = percent_decode(
        &query_param(&consent, "return").expect("the screen carries the pending request"),
    );
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
    let access = token["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("no access_token: {body}"));
    let record = oauth_as_plane(app)
        .expect("configured")
        .server()
        .introspect(access)
        .await
        .expect("introspection must not fail")
        .expect("the freshly minted token must be live");
    (shown, record.scope.to_string())
}

async fn register_defaulting_to(
    app: &busbar_kernel::state::App,
    client_id: &str,
    default: &[&str],
) {
    let scopes = ScopeSet::from_tokens(default.iter().copied()).expect("scope");
    oauth_as_plane(app)
        .expect("configured")
        .server()
        .register_client(Client {
            client_id: ClientId::new(client_id),
            auth: ClientAuth::Public,
            grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            redirect_uris: vec![REDIRECT_URI.to_string()],
            allowed_scopes: scopes.clone(),
            default_scopes: scopes,
            name: None,
            registration: None,
        })
        .await
        .expect("register client");
}

#[tokio::test]
async fn a_request_naming_no_scope_is_shown_the_default_it_is_granted() {
    const DEFAULTED: &str = "flow-test-defaulted";
    let (origin, app) = serve().await;
    register_defaulting_to(&app, DEFAULTED, &["read", "write"]).await;
    let (shown, granted) = shown_and_granted(&origin, &app, DEFAULTED, "").await;
    assert_eq!(granted, "read write", "the registered default is granted");
    assert_eq!(
        shown, granted,
        "the consent screen must name the scope the approval grants"
    );
}

#[tokio::test]
async fn a_metadata_document_client_naming_no_scope_is_shown_the_default_it_is_granted() {
    let (origin, app) = serve().await;
    oauth_as_plane(&app)
        .expect("configured")
        .server()
        .store()
        .set_fetcher(Arc::new(StubDocumentHost(serde_json::json!({
            "client_id": CIMD_CLIENT_ID,
            "redirect_uris": [REDIRECT_URI],
            "token_endpoint_auth_method": "none",
            "client_name": "an agent",
        }))));
    let (shown, granted) = shown_and_granted(&origin, &app, CIMD_CLIENT_ID, "").await;
    assert_eq!(granted, SCOPE, "the operator's default_grant is granted");
    assert_eq!(
        shown, granted,
        "the consent screen must name the scope the approval grants"
    );
}

#[tokio::test]
async fn the_consent_screen_names_a_requested_scope_and_an_empty_grant() {
    const EMPTY: &str = "flow-test-empty-default";
    let (origin, app) = serve().await;
    let (shown, granted) = shown_and_granted(&origin, &app, CLIENT_ID, "&scope=read").await;
    assert_eq!((shown.as_str(), granted.as_str()), (SCOPE, SCOPE));

    register_defaulting_to(&app, EMPTY, &[]).await;
    let (shown, granted) = shown_and_granted(&origin, &app, EMPTY, "").await;
    assert_eq!(granted, "", "an empty default grants nothing");
    assert_eq!(shown, "no scopes", "and the screen says so");
}

#[tokio::test]
async fn a_failed_default_scope_lookup_refuses_consent_and_recovers() {
    let calls = busbar_kernel_testkit::test_support::store_axis_stand_in()
        .open(
            StoreDoor::Linked(busbar_kernel_testkit::test_support::store_double::door),
            "consent-lookup",
            b"{}",
        )
        .expect("open store")
        .calls
        .expect("typed store calls");
    let fault = Arc::new(FailClientRead {
        inner: calls,
        fail_next: AtomicBool::new(false),
    });
    let (origin, app) = serve_with_store(Vec::new(), Some(fault.clone())).await;
    let (shown, granted) =
        shown_and_granted_after_lookup_failure(&origin, &app, CLIENT_ID, "", Some(&fault)).await;
    assert_eq!(
        granted, SCOPE,
        "the recovered request grants its registered default"
    );
    assert_eq!(shown, granted, "the recovered screen names the grant");

    const EMPTY: &str = "flow-test-shared-empty-default";
    register_defaulting_to(&app, EMPTY, &[]).await;
    let (shown, granted) = shown_and_granted(&origin, &app, EMPTY, "").await;
    assert_eq!(
        granted, "",
        "a successfully resolved empty default remains valid"
    );
    assert_eq!(shown, "no scopes");
}

struct FailClientRead {
    inner: Arc<dyn StoreCalls>,
    fail_next: AtomicBool,
}

impl StoreCalls for FailClientRead {
    fn supports_record_transaction(&self) -> bool {
        self.inner.supports_record_transaction()
    }

    fn record_transaction<'a>(
        &'a self,
        request: &'a busbar_contract::abi::sdk::store::conditional::Request,
    ) -> StoreCall<'a, busbar_contract::abi::sdk::store::conditional::Decision> {
        self.inner.record_transaction(request)
    }

    fn add_usage_batch<'a>(
        &'a self,
        op: OpId,
        cells: &'a [(&'a str, u64, UsageDelta)],
    ) -> StoreCall<'a, ()> {
        self.inner.add_usage_batch(op, cells)
    }

    fn add_metering_batch<'a>(
        &'a self,
        op: OpId,
        deltas: &'a [MeteringDelta],
    ) -> StoreCall<'a, ()> {
        self.inner.add_metering_batch(op, deltas)
    }

    fn record_put<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
        value: &'a RecordBytes,
    ) -> StoreCall<'a, ()> {
        self.inner.record_put(schema, key, value)
    }

    fn record_get<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
    ) -> StoreCall<'a, Option<RecordBytes>> {
        if schema == format!("{}bucket.atomic.v1", crate::shared::LABEL)
            && self.fail_next.swap(false, Ordering::SeqCst)
        {
            return Box::pin(async {
                Err(StoreFailure::Failed(
                    "client lookup unavailable".to_string(),
                ))
            });
        }
        self.inner.record_get(schema, key)
    }

    fn record_scan<'a>(
        &'a self,
        schema: &'a str,
        prefix: &'a [u8],
        limit: u32,
    ) -> StoreCall<'a, Vec<(Vec<u8>, RecordBytes)>> {
        self.inner.record_scan(schema, prefix, limit)
    }

    fn upsert_plane_record<'a>(&'a self, record: PlaneRecordRef<'a>) -> StoreCall<'a, ()> {
        self.inner.upsert_plane_record(record)
    }

    fn get_plane_record<'a>(
        &'a self,
        kind: &'a str,
        id: &'a str,
    ) -> StoreCall<'a, Option<Vec<u8>>> {
        if kind == format!("{}bucket", crate::shared::LABEL)
            && self.fail_next.swap(false, Ordering::SeqCst)
        {
            return Box::pin(async {
                Err(StoreFailure::Failed(
                    "client lookup unavailable".to_string(),
                ))
            });
        }
        self.inner.get_plane_record(kind, id)
    }

    fn append_plane_record<'a>(
        &'a self,
        op: OpId,
        record: PlaneRecordRef<'a>,
    ) -> StoreCall<'a, ()> {
        self.inner.append_plane_record(op, record)
    }

    fn list_plane_records<'a>(
        &'a self,
        kind: &'a str,
        selector: &'a PlaneSelector<'a>,
    ) -> StoreCall<'a, Vec<Vec<u8>>> {
        self.inner.list_plane_records(kind, selector)
    }

    fn delete_plane_record<'a>(&'a self, kind: &'a str, id: &'a str) -> StoreCall<'a, ()> {
        self.inner.delete_plane_record(kind, id)
    }

    fn redeem_plane_token<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> StoreCall<'a, bool> {
        self.inner.redeem_plane_token(kind, token, expires_at, now)
    }

    fn plane_token_live<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> StoreCall<'a, bool> {
        self.inner.plane_token_live(kind, token, expires_at, now)
    }
}

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

pub(crate) fn encode_component(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                char::from(b).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

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
    let record = oauth_as_plane(&app)
        .expect("configured")
        .server()
        .introspect(&access)
        .await
        .expect("introspection must not fail")
        .expect("the freshly minted token must be live");
    assert_eq!(record.client_id.as_str(), client_id);
    assert_eq!(record.scope.to_string(), SCOPE);
}

async fn register(origin: &str, body: &str) -> u16 {
    reqwest::Client::new()
        .post(format!("{origin}/register"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.to_string())
        .send()
        .await
        .expect("register")
        .status()
        .as_u16()
}

fn registration(name: &str) -> String {
    serde_json::json!({
        "redirect_uris": [REDIRECT_URI],
        "token_endpoint_auth_method": "none",
        "response_types": ["code"],
        "grant_types": ["authorization_code", "refresh_token"],
        "client_name": name,
        "scope": SCOPE,
    })
    .to_string()
}

#[tokio::test]
async fn refused_registrations_do_not_close_registration_for_everyone() {
    let (origin, _app) = serve().await;
    for i in 0..10 {
        let status = register(&origin, &registration(&format!("busbar {i}"))).await;
        assert_ne!(
            status, 201,
            "a name impersonating the deployment is refused"
        );
    }
    for _ in 0..10 {
        let status = register(&origin, "{ not a registration").await;
        assert_ne!(status, 201, "a body that does not parse is refused");
    }
    assert_eq!(
        register(&origin, &registration("an agent")).await,
        201,
        "a legitimate registration is admitted after another caller's refusals"
    );
}

#[tokio::test]
async fn admitted_registrations_keep_the_ceiling() {
    let (origin, _app) = serve().await;
    for i in 0..60 {
        assert_eq!(
            register(&origin, &registration(&format!("agent {i}"))).await,
            201,
            "registration {i} is inside the ceiling"
        );
    }
    assert_ne!(
        register(&origin, &registration("one too many")).await,
        201,
        "the sixty-first registration in a minute is refused"
    );
}

const CIMD_CLIENT_ID: &str = "https://client.example/oauth-client";

struct StubDocumentHost(serde_json::Value);

impl crate::cimd::CimdFetch for StubDocumentHost {
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

#[tokio::test]
async fn a_client_id_metadata_document_admits_a_client_end_to_end() {
    let (origin, app) = serve().await;
    oauth_as_plane(&app)
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
    let record = oauth_as_plane(&app)
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

pub(crate) fn percent_decode(s: &str) -> String {
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

const OFFSITE_CLIENT_ID: &str = "offsite-callback-client";
const OFFSITE_REDIRECT_URI: &str = "https://client.example/cb";

#[tokio::test]
async fn the_consent_screen_names_the_client_and_the_redirect_host() {
    let (origin, app) = serve().await;
    let scopes = ScopeSet::from_tokens([SCOPE]).expect("scope");
    oauth_as_plane(&app)
        .expect("configured")
        .server()
        .register_client(Client {
            client_id: ClientId::new(OFFSITE_CLIENT_ID),
            auth: ClientAuth::Public,
            grant_types: vec![GrantType::AuthorizationCode],
            redirect_uris: vec![OFFSITE_REDIRECT_URI.to_string()],
            allowed_scopes: scopes.clone(),
            default_scopes: scopes,
            name: None,
            registration: None,
        })
        .await
        .expect("register the offsite client");

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");
    let mut jar = Jar::new(false);

    let authorize = format!(
        "{origin}/authorize?response_type=code&client_id={OFFSITE_CLIENT_ID}\
         &redirect_uri=https%3A%2F%2Fclient.example%2Fcb&state=s1&scope={SCOPE}\
         &code_challenge={CHALLENGE}&code_challenge_method=S256"
    );
    let (status, headers, body) =
        send(&client, &mut jar, reqwest::Method::GET, &authorize, None).await;
    assert_eq!(status, 302, "authorize must redirect to consent: {body}");
    let consent = location(&headers, &origin);
    let (status, _headers, page) =
        send(&client, &mut jar, reqwest::Method::GET, &consent, None).await;
    assert_eq!(status, 200, "the consent screen must render: {page}");

    assert!(
        page.contains(OFFSITE_CLIENT_ID),
        "the screen must NAME the client asking for authorization: {page}"
    );
    assert!(
        page.contains(SCOPE),
        "the screen must name the scopes being requested: {page}"
    );

    let visible = strip_hidden_return(&page);
    assert!(
        visible.contains("client.example"),
        "the consent screen must name the HOST the approval sends the credential to \
         (client.example, from redirect_uri {OFFSITE_REDIRECT_URI}) somewhere the operator can READ \
         it. Without it, an operator approving \"{OFFSITE_CLIENT_ID} for scope {SCOPE}\" cannot tell \
         a legitimate registration from one pointing at an attacker's callback. Visible page, with \
         the hidden `return` field removed:\n{visible}"
    );
}

fn strip_hidden_return(page: &str) -> String {
    let marker = "name=return value=\"";
    let Some(start) = page.find(marker) else {
        return page.to_string();
    };
    let after = start + marker.len();
    let Some(end) = page[after..].find('"') else {
        return page.to_string();
    };
    format!("{}{}", &page[..after], &page[after + end..])
}

#[tokio::test]
async fn an_unauthenticated_visitor_is_never_shown_the_consent_screen() {
    let (origin, _app) = serve_with_admin_chain(vec!["test-scope-module".to_string()]).await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");
    let mut jar = Jar::new(false);

    let authorize = format!(
        "{origin}/authorize?response_type=code&client_id={CLIENT_ID}\
         &redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb&state=s1&scope={SCOPE}\
         &code_challenge={CHALLENGE}&code_challenge_method=S256"
    );
    let (status, headers, body) =
        send(&client, &mut jar, reqwest::Method::GET, &authorize, None).await;
    assert_eq!(
        status, 302,
        "the authorization endpoint must answer with a redirect, not with a page describing the \
         request: {body}"
    );
    assert!(
        !body.contains(CLIENT_ID),
        "the redirect away from /authorize must not itself carry a body naming the client: {body}"
    );

    let consent = location(&headers, &origin);
    let (status, _headers, page) =
        send(&client, &mut jar, reqwest::Method::GET, &consent, None).await;
    assert!(
        status == 401 || status == 403,
        "the consent screen is `RouteAuth::Admin`: an anonymous visitor must be refused, got \
         {status}: {page}"
    );
    assert!(
        !page.contains(CLIENT_ID),
        "an anonymous visitor must NOT be told which client is asking — that page is the phishing \
         surface: {page}"
    );
}

#[tokio::test]
async fn an_unencodable_login_redirect_fails_closed_rather_than_proceeding() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let real_origin = format!("http://{addr}");

    let bad_issuer = "http://bad\rhost/defect2".to_string();
    let cfg = OauthAsCfg {
        issuer: bad_issuer,
        signing_key: None,
        key_id: None,
        default_grant: vec![SCOPE.to_string()],
        access_token_ttl_secs: None,
        refresh_token_ttl_secs: None,
        fapi2: false,
        clients: Vec::new(),
    };
    let app = TestApp::new().oauth_as(&cfg).build();

    let scopes = ScopeSet::from_tokens([SCOPE]).expect("scope");
    oauth_as_plane(&app)
        .expect("configured")
        .server()
        .register_client(Client {
            client_id: ClientId::new(CLIENT_ID),
            auth: ClientAuth::Public,
            grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            redirect_uris: vec![REDIRECT_URI.to_string()],
            allowed_scopes: scopes.clone(),
            default_scopes: scopes,
            name: Some("Defect 2".to_string()),
            registration: None,
        })
        .await
        .expect("register client");

    let router = busbar_kernel::build_router(Arc::clone(&app));
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");
    let authorize = format!(
        "{real_origin}/defect2/authorize?response_type=code&client_id={CLIENT_ID}\
         &redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb&state=s1&scope={SCOPE}\
         &code_challenge={CHALLENGE}&code_challenge_method=S256"
    );
    let resp = client.get(&authorize).send().await.expect("request");
    let status = resp.status();
    let body = resp.text().await.expect("body");

    assert_eq!(
        status, 502,
        "an unencodable login redirect must fail closed with a 502, not proceed as though the \
         resource owner had answered: got {status} {body}"
    );
}

#[tokio::test]
async fn a_return_target_a_browser_reads_as_off_site_is_refused_on_approve_and_deny() {
    let (origin, _app) = serve().await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");
    let mut jar = Jar::new(false);
    let authorize = format!(
        "{origin}/authorize?response_type=code&client_id={CLIENT_ID}\
         &redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb&state=s1&scope={SCOPE}\
         &code_challenge={CHALLENGE}&code_challenge_method=S256"
    );
    let (_, headers, _) = send(&client, &mut jar, reqwest::Method::GET, &authorize, None).await;
    let consent = location(&headers, &origin);
    let (status, _, body) = send(&client, &mut jar, reqwest::Method::GET, &consent, None).await;
    assert_eq!(
        status, 200,
        "the consent screen renders and opens a session: {body}"
    );
    assert!(
        jar.header_for("/consent").is_some(),
        "the session cookie is live"
    );

    for answer in ["approve", "deny"] {
        for bypass in ["/\t/evil.example", "/\n/evil.example", "/\\evil.example"] {
            let (status, headers, _) = send(
                &client,
                &mut jar,
                reqwest::Method::POST,
                &format!("{origin}/consent"),
                Some(&[("return", bypass), ("answer", answer)]),
            )
            .await;
            assert_eq!(
                status, 400,
                "{answer} with return {bypass:?} must be refused"
            );
            assert!(
                headers.get(reqwest::header::LOCATION).is_none(),
                "{answer} with return {bypass:?} redirected the browser"
            );
        }
    }

    let (status, _, _) = send(
        &client,
        &mut jar,
        reqwest::Method::GET,
        &format!("{origin}/consent?return=%2F%09%2Fevil.example"),
        None,
    )
    .await;
    assert_eq!(
        status, 400,
        "the consent screen renders for an off-site return target"
    );
}
